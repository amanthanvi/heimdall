//! ⟨M06 W5 `w5f`⟩ The world of the journeys that pair **through the product CLI**
//! (`environment add`, `invite`, `join`, `revoke-client`, `remove`): a controller whose
//! catalog holds a verified M03 enrollment of the runner account, a runner installation
//! that exists only as the bootstrap creates it, and more controller devices that join by
//! invitation.
//!
//! **The first controller is M03's exit world** (`exit_m03/world.rs`, shared as `exit_m05`
//! shares it, not copied): the real CLI-started runtime and its real issuer child; the
//! catalog built with the product's commands (`identity adopt`, `destination add`,
//! `destination prefer`, `setup apply`, `time confirm`). As in that world, the CA and the
//! enrollment **record** are written while the runtime is stopped (`enroll <destination>`
//! and the issuer ceremony have their own suites); [`CliWorld::start`] then runs the
//! product's `enroll verify` against the runner account's sshd, so the enrollment
//! `environment add` reads is one the product itself verified in this run.
//!
//! **The runner side of the bootstrap.** `environment add` runs `<runner-program> remote
//! init …` in a session of the runner account's sshd. That session's environment is
//! sshd's, so the debug build's test variables cannot come from this test's process. The
//! native journeys give them with the fixture sshd's `SetEnv`; `heimdall_testkit`'s sshd
//! has no such option, so here `--runner-program` is a **launcher** in the scratch
//! directory: a two-line `sh` script that sets `HEIMDALL_TEST_SSH_HOME` (the runner's
//! scratch account home: the management line goes to its `.ssh/authorized_keys`, never
//! the account's own), `HEIMDALL_TEST_TIME_SYNC`, `HEIMDALL_TEST_RUNNER_SSHD_CONFIG` (the
//! fixture policy file of the limited-role check, as A25's journey) and both fixture key
//! stores, and `exec`s
//! the real binary with its arguments unchanged. `--runner-sha256` is the real binary's,
//! which the runner checks on itself.
//!
//! **The runner account's sshd** is one `heimdall_testkit` fixture on 127.0.0.1 with a
//! per-run host key. Its `AuthorizedKeysFile` is a link to the runner's scratch
//! `.ssh/authorized_keys`, which starts with the owner's existing access (a per-run key,
//! with a terminal allowed) and the CA line M03's world enrolls; the bootstrap appends the
//! management lines.
//!
//! **Isolation**: both worlds' rules. Every `heimdall` gets scratch `HOME`,
//! `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME`, and both fixture key stores
//! (`HEIMDALL_TEST_MGMT_STORE`, `HEIMDALL_TEST_IROH_KEY_STORE`); no `SSH_AUTH_SOCK`.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use heimdall_testkit::agent::FixtureKey;
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::console::TerminalCommand;
use heimdall_testkit::home::Scratch;
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;

use super::m03world::{World, WorldOptions};
use super::world::{Runner, bin, envelope};

/// The end of every typed confirmation of the M06 commands (`remote init`'s at the runner,
/// shown on the controller's terminal by the bootstrap session; `invite`'s and `join`'s).
pub(crate) const CONFIRMATION: &str = "Type yes to continue";
/// The end of the bootstrap's offer to start the runner's runtime.
pub(crate) const RUNTIME_OFFER: &str = "Type yes to start it";

/// What one command on a pseudo-terminal did.
pub(crate) struct Typed {
    pub(crate) code: Option<i32>,
    pub(crate) text: String,
    /// How many of the dialog's prompts were shown (and answered).
    pub(crate) answered: usize,
}

impl Typed {
    /// The envelope (`--json`).
    pub(crate) fn json(&self) -> Value {
        envelope(&self.text)
    }
}

/// `program args…` on a pseudo-terminal in exactly `env`, typing each `(prompt, answer)`
/// of `dialog` in order when its prompt appears after the previous answer. A command that
/// exits, or shows nothing more for 90 s, before a prompt ends the dialog there.
pub(crate) fn typed(
    program: &Path,
    args: &[String],
    env: &[(String, String)],
    dialog: &[(&str, &str)],
) -> Typed {
    let mut cmd = TerminalCommand::new(program).args(args).size(400, 50);
    for (k, v) in env {
        cmd = cmd.env(k, v);
    }
    let mut t = cmd
        .spawn()
        .expect("blocked: a pseudo-terminal (script(1)) is needed");
    let mut answered = 0;
    for (prompt, answer) in dialog {
        if t.expect(prompt, Duration::from_secs(90)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
        t.send(format!("{answer}\r").as_bytes()).unwrap();
        answered += 1;
    }
    let code = t.wait(Duration::from_secs(180));
    let text = t.text();
    assert_no_canary(&text);
    assert!(!text.contains("panicked"), "{args:?}: {text}");
    Typed {
        code,
        text,
        answered,
    }
}

fn owner_only_dir(scratch: &Scratch, name: &str) -> PathBuf {
    let dir = scratch.subdir(name).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// ⟨M06 W5 `w5r`⟩ The length of [`Device::with_long_home`]'s Heimdall home, in bytes.
pub(crate) const LONG_HOME_BYTES: usize = 84;

/// A controller **device** that is not the first controller: a scratch installation with
/// its own fixture K_mgmt store. It joins a runner by invitation.
pub(crate) struct Device {
    pub(crate) home: PathBuf,
    pub(crate) account: PathBuf,
    mgmt: PathBuf,
    iroh: PathBuf,
}

impl Device {
    pub(crate) fn new(scratch: &Scratch, tag: &str) -> Device {
        Device {
            home: scratch.subdir(&format!("{tag}h")).unwrap(),
            account: owner_only_dir(scratch, &format!("{tag}a")),
            mgmt: scratch
                .subdir(&format!("{tag}m"))
                .unwrap()
                .join("k_mgmt.fixture"),
            iroh: owner_only_dir(scratch, &format!("{tag}i")),
        }
    }

    /// ⟨M06 W5 `w5r`⟩ A device whose Heimdall home is [`LONG_HOME_BYTES`] long: a
    /// management session's agent socket under it (`<home>/run/mgmt/<12 hex>/a.sock`, 29
    /// bytes more) would pass every platform's `sun_path` limit, while its own runtime
    /// socket (`<home>/run/signing.sock`, 17 more) still fits. Its sessions open only
    /// because their agent sockets are not under the home.
    pub(crate) fn with_long_home(scratch: &Scratch, tag: &str) -> Device {
        let mut device = Device::new(scratch, tag);
        let base = device.home.as_os_str().len();
        assert!(base + 2 <= LONG_HOME_BYTES, "the scratch root is too long");
        let home = device.home.join("l".repeat(LONG_HOME_BYTES - base - 1));
        std::fs::create_dir(&home).unwrap();
        assert_eq!(home.as_os_str().len(), LONG_HOME_BYTES);
        assert!(home.as_os_str().len() + 29 > 107 && home.as_os_str().len() + 17 <= 103);
        device.home = home;
        device
    }

    pub(crate) fn env(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("HOME".to_owned(), text(&self.account)),
            ("HEIMDALL_HOME".to_owned(), text(&self.home)),
            ("HEIMDALL_TEST_SSH_HOME".to_owned(), text(&self.account)),
            (
                "HEIMDALL_TEST_SECRET_STORE".to_owned(),
                "scratch".to_owned(),
            ),
            (
                "HEIMDALL_TEST_TIME_SYNC".to_owned(),
                "synchronized".to_owned(),
            ),
            (
                "HEIMDALL_TEST_MGMT_STORE".to_owned(),
                format!("fixture-file:{}", self.mgmt.display()),
            ),
            ("HEIMDALL_TEST_IROH_KEY_STORE".to_owned(), text(&self.iroh)),
        ]
    }

    /// `heimdall --json <args…>` without a terminal: the exit code and the envelope.
    pub(crate) fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(bin())
            .env_clear()
            .envs(self.env())
            .arg("--json")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_no_canary(&stdout);
        assert_no_canary(&stderr);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        let value = stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l.trim()).ok())
            .unwrap_or_else(|| panic!("{args:?}: no envelope: {stdout} {stderr}"));
        (out.status.code().unwrap_or(-1), value)
    }

    /// `heimdall --json <args…>` on a pseudo-terminal.
    pub(crate) fn typed(&self, args: &[&str], dialog: &[(&str, &str)]) -> Typed {
        let mut argv = vec!["--json".to_owned()];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        typed(Path::new(&bin()), &argv, &self.env(), dialog)
    }
}

/// The world (module docs). Fields drop in order: the runner's runtime, the controller
/// (its runtime and projection), then the sshd and the scratch directories.
pub(crate) struct CliWorld {
    pub(crate) runner: Runner,
    /// The first controller: M03's exit world, with both fixture key stores.
    pub(crate) controller: World,
    /// The runner account (the fixture sshd's).
    pub(crate) account: String,
    /// The catalog destination of the runner account on the controller.
    pub(crate) destination: String,
    /// The launcher `environment add` names as the runner program (module docs).
    pub(crate) runner_program: PathBuf,
    /// The real binary's SHA-256.
    pub(crate) runner_sha256: String,
    /// The runner account's `authorized_keys` (scratch).
    pub(crate) runner_keys: PathBuf,
    /// The existing access's public key line (no comment).
    pub(crate) existing_access: String,
    pub(crate) scratch: Scratch,
}

impl CliWorld {
    /// Build the world up to, and not including, `environment add`. `Err`: blocked, with
    /// the reason (no fixture sshd on this host).
    pub(crate) fn start() -> Result<CliWorld, String> {
        let scratch = Scratch::new().unwrap();
        let existing = FixtureKey::generate();
        let sshd = LoopbackSshd::start(
            &scratch,
            SshdConfig {
                registry_seed: Some(Vec::new()),
                authorized: vec![existing.public().clone()],
                allow_pty: true,
                ..SshdConfig::default()
            },
        )
        .map_err(|e| format!("no fixture sshd: {e}"))?;
        let account = sshd
            .login_account()
            .ok_or("the fixture account is unknown")?;
        let registry = sshd
            .registry_path()
            .map(Path::to_path_buf)
            .ok_or("the fixture sshd has no local registry")?;

        // The runner installation: only its directories and the account's existing
        // authorized_keys exist before the bootstrap.
        let mut runner = Runner::named(&scratch, "r");
        std::fs::set_permissions(&runner.account, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ssh_dir = runner.account.join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner_keys = ssh_dir.join("authorized_keys");
        std::fs::copy(&registry, &runner_keys).unwrap();
        std::fs::set_permissions(&runner_keys, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&registry).unwrap();
        std::os::unix::fs::symlink(&runner_keys, &registry).unwrap();
        runner.with_iroh_fixture_store(&scratch, "ri");
        let runner_mgmt = scratch.subdir("rm").unwrap().join("k_mgmt.fixture");
        let launcher_dir = scratch.subdir("rp").unwrap();
        // The runner's effective sshd policy for its limited-role check (`sshd -T -f`,
        // nothing listens on it): the debug build's fixture file, as A25's journey gives it.
        let sshd_policy = launcher_dir.join("sshd_policy");
        std::fs::write(
            &sshd_policy,
            format!(
                "AuthorizedKeysFile .ssh/authorized_keys\n{}",
                super::a25::RESTRICTED
            ),
        )
        .unwrap();
        let runner_program = launcher_dir.join("heimdall-runner");
        let quoted = |p: &Path| heimdall_testkit::home::sh_quote(p.as_os_str());
        std::fs::write(
            &runner_program,
            format!(
                "#!/bin/sh\nHOME={account} HEIMDALL_HOME={home} HEIMDALL_TEST_SSH_HOME={account} \
                 HEIMDALL_TEST_SECRET_STORE=scratch HEIMDALL_TEST_TIME_SYNC=synchronized \
                 HEIMDALL_TEST_RUNNER_SSHD_CONFIG={} HEIMDALL_TEST_MGMT_STORE={} \
                 HEIMDALL_TEST_IROH_KEY_STORE={} exec {} \"$@\"\n",
                quoted(&sshd_policy),
                heimdall_testkit::home::sh_quote(std::ffi::OsStr::new(&format!(
                    "fixture-file:{}",
                    runner_mgmt.display()
                ))),
                quoted(runner.iroh_store.as_deref().unwrap()),
                quoted(Path::new(&bin())),
                account = quoted(&runner.account),
                home = quoted(&runner.home),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&runner_program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner_sha256 =
            heimdall_domain::projection::Sha256Hex::of(&std::fs::read(bin()).unwrap())
                .as_str()
                .to_owned();

        // The first controller: M03's exit world over that sshd, with the fixture key
        // stores every M06 command needs.
        let mgmt = scratch.subdir("cm").unwrap().join("k_mgmt.fixture");
        let iroh = owner_only_dir(&scratch, "ci");
        let (controller, ca) = World::start(WorldOptions {
            pairs: 1,
            servers: vec![sshd],
            extra_env: vec![
                (
                    "HEIMDALL_TEST_MGMT_STORE".to_owned(),
                    format!("fixture-file:{}", mgmt.display()),
                ),
                ("HEIMDALL_TEST_IROH_KEY_STORE".to_owned(), text(&iroh)),
            ],
            ..WorldOptions::default()
        });
        drop(ca);
        let destination = controller.pairs[0].destination.clone();

        // The owner's existing access to the runner account, as their own configuration
        // names it for the catalog alias (before Heimdall's include: the first value wins).
        let key_file = controller.home.ssh_dir.join("existing_access");
        existing.write_private(&key_file).unwrap();
        let original = std::fs::read_to_string(&controller.home.user_config).unwrap();
        std::fs::write(
            &controller.home.user_config,
            format!(
                "Host {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  IdentityAgent none\n  \
                 CertificateFile none\n  BatchMode no\n{original}",
                controller.pairs[0].alias,
                heimdall_testkit::home::ssh_option_path(&key_file),
            ),
        )
        .unwrap();
        Ok(CliWorld {
            runner,
            account,
            destination,
            runner_program,
            runner_sha256,
            runner_keys,
            existing_access: existing.public_line_without_comment(),
            controller,
            scratch,
        })
    }

    /// The first controller's environment, as (name, value) text.
    pub(crate) fn controller_env(&self) -> Vec<(String, String)> {
        self.controller
            .env()
            .into_iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }

    /// `heimdall --json <args…>` on a pseudo-terminal as the first controller's owner.
    pub(crate) fn controller_typed(&self, args: &[&str], dialog: &[(&str, &str)]) -> Typed {
        let mut argv = vec!["--json".to_owned()];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        typed(Path::new(&bin()), &argv, &self.controller_env(), dialog)
    }

    /// `heimdall --json <args…>` as the first controller's owner, without a terminal.
    pub(crate) fn controller_json(&self, args: &[&str]) -> (i32, Value) {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(args);
        let out = self.controller.cli(&argv);
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        (out.code, out.json())
    }

    /// The product's `enroll verify` of the runner account's enrollment: its state after.
    pub(crate) fn verify_enrollment(&self) -> String {
        let (code, status) = self.controller_json(&["--non-interactive", "enroll", "status"]);
        assert_eq!(code, 0, "{status}");
        let listed = status["data"]["enrollments"].as_array().unwrap().clone();
        assert_eq!(listed.len(), 1, "{status}");
        let id = listed[0]["enrollment_id"].as_str().unwrap().to_owned();
        let (code, verified) =
            self.controller_json(&["--non-interactive", "enroll", "verify", &id]);
        assert_eq!(code, 0, "{verified}");
        verified["data"]["state"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// `environment add` on a pseudo-terminal, typing `confirm` at the runner's
    /// confirmation and `start` at the offer to start the runner's runtime.
    pub(crate) fn environment_add(&self, confirm: &str, start: &str) -> Typed {
        self.environment_add_from(&self.controller_env(), confirm, start)
    }

    pub(crate) fn environment_add_from(
        &self,
        env: &[(String, String)],
        confirm: &str,
        start: &str,
    ) -> Typed {
        let args = [
            "--json",
            "environment",
            "add",
            "--destination",
            &self.destination,
            "--account",
            &self.account,
            "--runner-program",
            &text(&self.runner_program),
            "--runner-home",
            &text(&self.runner.home),
            "--runner-sha256",
            &self.runner_sha256,
        ]
        .map(str::to_owned);
        typed(
            Path::new(&bin()),
            &args,
            env,
            &[(CONFIRMATION, confirm), (RUNTIME_OFFER, start)],
        )
    }

    /// As the runner's local owner on a pseudo-terminal: `heimdall --json --home <runner
    /// home> <args…>`, in the launcher's test configuration.
    pub(crate) fn runner_typed(&self, args: &[&str], dialog: &[(&str, &str)]) -> Typed {
        let mut argv = vec![
            "--json".to_owned(),
            "--home".to_owned(),
            text(&self.runner.home),
        ];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        typed(&self.runner_program, &argv, &self.runner_env(), dialog)
    }

    /// The environment of a runner-side command started through the launcher (which adds
    /// the test configuration itself).
    fn runner_env(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("HOME".to_owned(), text(&self.runner.account)),
            ("HEIMDALL_HOME".to_owned(), text(&self.runner.home)),
        ]
    }

    /// `heimdall --json --home <runner home> <args…>` as the runner's local owner, without
    /// a terminal (through the launcher): the exit code and the envelope, `Null` when the
    /// command printed none.
    pub(crate) fn runner_json(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(&self.runner_program)
            .env_clear()
            .envs(self.runner_env())
            .arg("--json")
            .arg("--home")
            .arg(&self.runner.home)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_no_canary(&stdout);
        assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        let value = stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l.trim()).ok())
            .unwrap_or(Value::Null);
        (out.status.code().unwrap_or(-1), value)
    }

    /// Whether the runner's runtime serves (`service status`, which starts nothing).
    pub(crate) fn runner_serves(&self) -> bool {
        self.runner_json(&["service", "status"]).0 == 0
    }

    /// Stop the runner's runtime the bootstrap started (`service stop` on its own scratch
    /// home), and wait until it no longer serves.
    pub(crate) fn runner_stop(&self) -> bool {
        let _ = self.runner_json(&["service", "stop"]);
        let start = std::time::Instant::now();
        while self.runner_serves() {
            if start.elapsed() > Duration::from_secs(30) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }

    /// The lines of the runner account's `authorized_keys`.
    pub(crate) fn runner_key_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.runner_keys)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for CliWorld {
    /// The runner's runtime, when the bootstrap started it detached, is stopped through
    /// `service stop` on its own scratch home (never by a name or pattern), before the
    /// scratch directories go.
    fn drop(&mut self) {
        if self.runner_program.exists() && self.runner_serves() && !self.runner_stop() {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "m06 cli world: the runner runtime under {} did not stop",
                    self.runner.home.display()
                );
            }
        }
    }
}
