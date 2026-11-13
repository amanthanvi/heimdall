//! M03 wave 5 (U12): `e2e_cli_m03` submodule `issuer` (owner: worker I, `.m03-wave5-api.md`
//! R1): `heimdall issuer …` through the **real binary** against this test's **in-process
//! runtime** (`Service::start_with`), whose issuer child is the real binary's
//! `internal issuer` on the scratch store (`HEIMDALL_TEST_SECRET_STORE=scratch`). A
//! runtime the CLI started would wire the account's real `~/.ssh`, so effectful commands
//! run only while the in-process runtime serves.
//!
//! **Terminal.** The ceremony and prompt cases re-execute this test binary as the leader
//! of a new session ([`issuer_cli_pty_child`]): with a pty slave it acquires the pty as
//! its controlling terminal, then execs `heimdall` with stdout and stderr on separate
//! files (stdin and stderr on the pty when a case says so), so the test can show what
//! reaches the terminal only. Without a slave the session has no controlling terminal.
//!
//! **S3 (`.m03-wave5-questions.md` Q-IS1).** The scratch store is a test-configuration
//! kind: `issuer init|rotate begin|restore` stop at the registration with
//! `issuer_store_unavailable` (nothing written), and the R2B deletion of `issuer retire`
//! stops at `unloaded` unless `S3_TEST_STORE_DELETION` (mirrored here) is switched on.
//! The assertions that need the ruling are named in each test.
//!
//! **Isolation.** Cleared environments (`PATH`, a scratch `HOME`, the scratch
//! `HEIMDALL_HOME`, the scratch store); fixture keys are generated per run; no owner key,
//! agent or keychain is touched; every output byte is scanned for canaries. Only
//! processes this test started are stopped, by their own handles.

#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_credential::cert::SecretCaKey;
use heimdall_issuer::store::{SecretStore, StoreItemRef};
use heimdall_store::{IssuerRecord, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::scratch_store::ScratchSecretStore;
use serde_json::Value;

use super::{Out, bin, run};

/// Mirrors `issuer_cmd::S3_TEST_STORE_DELETION` (the binary's switch): with it on, the
/// R2B retire case asserts the whole chain to `retired`.
const S3_TEST_STORE_DELETION: bool = false;

const SLAVE: &str = "HM_I_PTY_SLAVE";
const ARGV: &str = "HM_I_ARGV";
const ENVS: &str = "HM_I_ENV";
const STDIN_TTY: &str = "HM_I_STDIN_TTY";
const STDERR_TTY: &str = "HM_I_STDERR_TTY";
const LIMIT: Duration = Duration::from_secs(120);

/// The scratch store's directory under the state directory (`m03_cmd::SCRATCH_STORE_DIR`).
const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

// --- the in-process runtime ---------------------------------------------------------------

struct Running {
    store: Arc<Store>,
    token: tokio_util::sync::CancellationToken,
    thread: std::thread::JoinHandle<()>,
    issuer: Option<heimdall_issuer::client::ChildIssuer>,
}

/// A scratch installation: its home, an account directory, the in-process runtime.
struct Rig {
    tmp: tempfile::TempDir,
    home: PathBuf,
    account: PathBuf,
    service: Option<Running>,
}

/// A directory created owner-only (the devbox's umask is 002).
fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Rig {
    /// A started runtime with no CA.
    fn new() -> Rig {
        let tmp = tempfile::Builder::new().prefix("hm-i-").tempdir().unwrap();
        private_dir(tmp.path());
        let home = tmp.path().join("hh");
        heimdall_runtime::Paths::under(&home).ensure().unwrap();
        let account = tmp.path().join("account");
        private_dir(&account);
        let mut rig = Rig {
            tmp,
            home,
            account,
            service: None,
        };
        rig.start();
        rig
    }

    fn state_dir(&self) -> PathBuf {
        heimdall_runtime::Paths::under(&self.home).state_dir
    }

    /// The scratch store the CLI and the issuer child select (created owner-only).
    fn scratch_store(&self) -> ScratchSecretStore {
        let dir = self.state_dir().join(SCRATCH_STORE_DIR);
        private_dir(&dir);
        ScratchSecretStore::new(dir)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    /// The environment every CLI process of this rig gets.
    fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), self.account.clone().into()),
            ("HEIMDALL_HOME".into(), self.home.clone().into()),
            ("HEIMDALL_TEST_SECRET_STORE".into(), "scratch".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("TERM".into(), "dumb".into()),
        ]
    }

    fn start(&mut self) {
        use heimdall_runtime::service::{ManagedOptions, ServiceOptions, SessionLockWiring};
        let paths = heimdall_runtime::Paths::under(&self.home);
        let child = heimdall_issuer::client::ChildCommand {
            program: PathBuf::from(bin()),
            args: vec!["internal".into(), "issuer".into()],
            env: vec![
                ("HEIMDALL_HOME".into(), self.home.clone().into()),
                ("HEIMDALL_TEST_SECRET_STORE".into(), "scratch".into()),
            ],
        };
        let token = tokio_util::sync::CancellationToken::new();
        let service_token = token.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let clock = Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap());
                let mut o = ServiceOptions::with_clock(
                    clock,
                    heimdall_testkit::ScriptedTimeSync::new(
                        heimdall_domain::time::SyncStatus::Synchronized,
                    ),
                );
                o.endpoint_prefix = "hmi-".to_owned();
                o.managed = Some(ManagedOptions {
                    session_lock: SessionLockWiring::Source(Arc::new(
                        heimdall_testkit::session_lock::FakeSessionLockSource::default(),
                    )),
                    issuer_command: Some(child),
                    ..ManagedOptions::default()
                });
                let service = heimdall_runtime::Service::start_with(
                    paths,
                    heimdall_runtime::Config::default(),
                    o,
                    service_token,
                )
                .await
                .unwrap();
                let _ = tx.send((Arc::clone(service.store()), service.issuer()));
                let _ = service.run().await;
            });
        });
        let (store, issuer) = rx.recv().expect("the service started");
        self.service = Some(Running {
            store,
            token,
            thread,
            issuer,
        });
    }

    /// Stop the runtime and wait until its issuer child (by its own PID and start
    /// token) is gone.
    fn stop(&mut self) {
        let Some(s) = self.service.take() else {
            return;
        };
        let child = s.issuer.as_ref().and_then(|i| i.identity());
        s.token.cancel();
        let _ = s.thread.join();
        if let Some(id) = child {
            let deadline = Instant::now() + Duration::from_secs(20);
            while heimdall_runtime::platform::process_start_time(id.pid) == id.start_token
                && id.start_token.is_some()
            {
                assert!(Instant::now() < deadline, "the issuer child survived");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn store(&self) -> Arc<Store> {
        Arc::clone(&self.service.as_ref().unwrap().store)
    }

    /// Register a CA directly (state `active`), its K_ca in the scratch store and its
    /// locator recorded, then restart so the issuer child loads it.
    fn seed_ca(&mut self) -> (CaFingerprint, StoreItemRef) {
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        let public = key.public_openssh().unwrap();
        let item = self.scratch_store().put(&fp, &key).unwrap();
        drop(key);
        let now = Timestamp::now();
        let locator = item.locator.clone();
        self.store()
            .transaction(|tx| {
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })?;
                tx.set_issuer_store_locator(&fp, &locator)
            })
            .unwrap();
        self.stop();
        self.start();
        (fp, item)
    }

    /// A K_ca in the scratch store that no registration names (an orphan).
    fn seed_orphan(&self) -> StoreItemRef {
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        self.scratch_store().put(&fp, &key).unwrap()
    }

    fn ca_state(&self, fp: &CaFingerprint) -> Option<CaState> {
        self.store()
            .transaction(|tx| tx.issuer(fp))
            .unwrap()
            .map(|r| r.state)
    }

    fn pending(&self) -> Vec<heimdall_domain::decision::DecisionRecord> {
        self.store()
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
    }

    /// The CLI with stdin closed, no terminal involved.
    fn cli(&self, args: &[&str]) -> Out {
        let extra: Vec<(&str, &str)> = vec![("HEIMDALL_TEST_SECRET_STORE", "scratch")];
        run(&self.home, &self.account, args, &extra)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.stop();
    }
}

// --- the terminal -------------------------------------------------------------------------

/// Child-mode entry: a new session (with the pty as its controlling terminal when a slave
/// is given), then `exec` of the argv from the parent (never holding a passphrase).
#[cfg(unix)]
#[test]
#[ignore = "child-mode entry of the issuer pty cases, started by them"]
fn issuer_cli_pty_child() {
    use std::os::unix::process::CommandExt as _;
    let (Some(argv), Some(envs)) = (std::env::var(ARGV).ok(), std::env::var(ENVS).ok()) else {
        return;
    };
    rustix::process::setsid().unwrap();
    if let Some(slave) = std::env::var_os(SLAVE) {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        if std::env::var_os(STDIN_TTY).is_some() {
            rustix::stdio::dup2_stdin(&tty).unwrap();
        }
        if std::env::var_os(STDERR_TTY).is_some() {
            rustix::stdio::dup2_stderr(&tty).unwrap();
        }
    }
    let argv: Vec<String> = serde_json::from_str(&argv).unwrap();
    let envs: Vec<(String, String)> = serde_json::from_str(&envs).unwrap();
    heimdall_testkit::term::default_terminal_signals_for_exec().unwrap();
    let err = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(envs)
        .stdin(if std::env::var_os(STDIN_TTY).is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .exec();
    panic!("exec failed: {err}");
}

#[cfg(unix)]
mod term {
    use std::io::{Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;

    /// A pseudo-terminal whose output is drained into an in-memory transcript.
    pub(super) struct Pty {
        master: OwnedFd,
        pub(super) slave: PathBuf,
        _slave_fd: OwnedFd,
        output: Arc<Mutex<Vec<u8>>>,
        stop: Arc<AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    impl Pty {
        pub(super) fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes()));
            let slave_fd = rustix::fs::open(
                &slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let reader = master.try_clone().unwrap();
            let sink = Arc::clone(&output);
            let done = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Pty {
                master,
                slave,
                _slave_fd: slave_fd,
                output,
                stop,
            }
        }

        pub(super) fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        /// Wait until the transcript contains `needle`; `false` when `child` exited first.
        pub(super) fn wait_for(&self, needle: &str, child: &mut Child) -> bool {
            let deadline = Instant::now() + LIMIT;
            loop {
                if self.transcript().contains(needle) {
                    return true;
                }
                if child.try_wait().unwrap().is_some() {
                    std::thread::sleep(Duration::from_millis(100));
                    return self.transcript().contains(needle);
                }
                assert!(Instant::now() < deadline, "no {needle:?} on the terminal");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Type raw bytes at the terminal.
        pub(super) fn type_bytes(&self, bytes: &[u8]) {
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            let _ = f.write_all(bytes);
        }

        /// Type `text` and a newline.
        pub(super) fn type_line(&self, text: &str) {
            self.type_bytes(format!("{text}\n").as_bytes());
        }
    }
}

#[cfg(unix)]
use term::Pty;

/// One started CLI case: its process, what the test gave it, its output files.
struct Started {
    child: Child,
    given: Vec<OsString>,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Drop for Started {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Where a case's stdin and stderr go (stdout is always its own file).
#[derive(Clone, Copy)]
struct Wiring {
    /// The pty is the controlling terminal.
    tty: bool,
    stdin_tty: bool,
    stderr_tty: bool,
}

const CEREMONY: Wiring = Wiring {
    tty: true,
    stdin_tty: false,
    stderr_tty: false,
};
const PROMPT: Wiring = Wiring {
    tty: true,
    stdin_tty: true,
    stderr_tty: true,
};
const NO_TTY: Wiring = Wiring {
    tty: false,
    stdin_tty: false,
    stderr_tty: false,
};

#[cfg(unix)]
fn start_cli(rig: &Rig, case: &str, args: &[&str], pty: Option<&Pty>, wiring: Wiring) -> Started {
    let exe = std::env::current_exe().unwrap();
    let mut argv = vec![bin()];
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let envs: Vec<(String, String)> = rig
        .env()
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let stdout = rig.file(&format!("{case}.stdout"));
    let stderr = rig.file(&format!("{case}.stderr"));
    let mut cmd = Command::new(&exe);
    let entry = [
        "--exact",
        "issuer::issuer_cli_pty_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ];
    cmd.args(entry)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(ARGV, serde_json::to_string(&argv).unwrap())
        .env(ENVS, serde_json::to_string(&envs).unwrap())
        .current_dir(rig.tmp.path());
    if let (Some(p), true) = (pty, wiring.tty) {
        cmd.env(SLAVE, &p.slave);
        if wiring.stdin_tty {
            cmd.env(STDIN_TTY, "1");
        }
        if wiring.stderr_tty {
            cmd.env(STDERR_TTY, "1");
        }
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let mut given: Vec<OsString> = vec![exe.into_os_string()];
    given.extend(entry.iter().map(OsString::from));
    given.extend(argv.into_iter().map(OsString::from));
    given.extend(envs.into_iter().flat_map(|(k, v)| [k.into(), v.into()]));
    Started {
        child,
        given,
        stdout,
        stderr,
    }
}

/// Wait for the case to exit; its exit code and its stdout/stderr (scanned).
fn finish(started: &mut Started) -> Out {
    let deadline = Instant::now() + LIMIT;
    let code = loop {
        if let Some(s) = started.child.try_wait().unwrap() {
            break s.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "the CLI case did not finish");
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = std::fs::read_to_string(&started.stdout).unwrap_or_default();
    let stderr = std::fs::read_to_string(&started.stderr).unwrap_or_default();
    assert_no_canary(&stdout);
    assert_no_canary(&stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    Out {
        code,
        stdout,
        stderr,
    }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// A run of 26 base32 symbols in groups of five (a shown passphrase) in `text`.
fn has_passphrase_shape(text: &str) -> bool {
    heimdall_testkit::ca::ceremony::find_passphrase(text.as_bytes()).is_some()
}

fn reason(env: &Value) -> &str {
    env["data"]["error"]["reason"].as_str().unwrap_or_default()
}

// --- the tests ----------------------------------------------------------------------------

/// The JSON envelope of every issuer command where no terminal or runtime is involved
/// (all platforms): the ceremonies refuse `--non-interactive` first (exit 3, effect
/// `none`); `restore` without `--not-stolen` and a malformed fingerprint are usage
/// errors (exit 2); the read-only `status` and `bundle` never start a runtime (exit 5).
/// Nothing creates the Heimdall home, and none answers "not available".
#[test]
fn issuer_commands_json_envelopes_without_a_runtime_or_terminal() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    private_dir(&account);
    let cases: &[(&[&str], i32, &str)] = &[
        (
            &["issuer", "init", "--backup-out", "b.enc"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &[
                "issuer",
                "init",
                "--backup-out",
                "b",
                "--replace-orphan",
                "fp",
                "--no-bundle-available",
            ],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (
            &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
            3,
            "INTERACTION_REQUIRED",
        ),
        (&["issuer", "unlock"], 3, "INTERACTION_REQUIRED"),
        (&["issuer", "status"], 5, "SERVICE_UNAVAILABLE"),
        (
            &["issuer", "bundle", "--out", "o.json"],
            5,
            "SERVICE_UNAVAILABLE",
        ),
        (&["issuer", "retire", "SHA256:abc"], 2, "USAGE_ERROR"),
    ];
    for (i, (line, exit, code)) in cases.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let mut argv = vec!["--json", "--non-interactive"];
        argv.extend_from_slice(line);
        let out = run(&home, &account, &argv, &[]);
        assert_eq!(out.code, *exit, "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], *code, "{line:?}: {out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        assert!(
            !out.message().contains("not available in this build"),
            "{line:?}"
        );
        assert!(!home.exists(), "{line:?} created the Heimdall home");
    }
    // Without --non-interactive and without --not-stolen: the ADR-0005 §5.3 guidance,
    // a usage error before any runtime contact.
    let home = scratch.path().join("home-restore");
    let out = run(
        &home,
        &account,
        &["--json", "issuer", "restore", "--backup", "b.enc"],
        &[],
    );
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.message().contains("--not-stolen"), "{out:?}");
    assert!(out.message().contains("rotate"), "{out:?}");
    assert!(!home.exists());
}

/// `issuer_init_prints_passphrase_only_to_tty` (m03-plan U12): `issuer init` on a real
/// pty (the controlling terminal; stdin, stdout and stderr are not the terminal), with
/// `--json`.
///
/// * Without a controlling terminal, refused (exit 3) before the runtime is contacted.
/// * On the pty, the ceremony runs on the terminal against the in-process runtime; on the
///   scratch store it stops at the registration (S3): exit 4 `CAPABILITY_UNAVAILABLE`,
///   reason `issuer_store_unavailable`, no decision, no backup file, no store item, no
///   passphrase anywhere (the transcript, stdout, stderr, the files, the arguments).
///
/// **Blocked on the S3 ruling (Q-IS1):** that the passphrase is shown on the transcript
/// (26 base32 symbols in groups of five) and on no other output, that `written` clears
/// it, and that it decrypts the backup — the passphrase step follows the registration.
#[cfg(unix)]
#[test]
fn issuer_init_prints_passphrase_only_to_tty() {
    let rig = Rig::new();
    let _ = rig.scratch_store();
    let backup = rig.file("ca-backup.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];

    // No controlling terminal: refused first.
    let mut started = start_cli(&rig, "no-tty", &args, None, NO_TTY);
    let out = finish(&mut started);
    assert_eq!(out.code, 3, "{out:?}");
    assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{out:?}");
    assert!(out.message().contains("terminal"), "{out:?}");

    // On the pty.
    let pty = Pty::open();
    let mut started = start_cli(&rig, "init", &args, Some(&pty), CEREMONY);
    let out = finish(&mut started);
    let transcript = pty.transcript();
    assert_eq!(out.code, 4, "{out:?}\n{transcript}");
    let env = out.json();
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
    assert_eq!(reason(&env), "issuer_store_unavailable", "{out:?}");
    assert!(
        out.message().contains("test-configuration store"),
        "{out:?}"
    );
    assert_eq!(env["data"]["error"]["effect_status"], "none");
    // Nothing was registered, written or stored.
    assert!(rig.pending().is_empty(), "no RegisterIssuer decision");
    assert!(!backup.exists(), "no backup file");
    assert!(files_under(&rig.state_dir().join(SCRATCH_STORE_DIR)).is_empty());
    // No passphrase on any output, file or argument.
    assert!(!transcript.contains("Backup passphrase"), "{transcript}");
    assert!(!has_passphrase_shape(&transcript));
    assert!(!has_passphrase_shape(&out.stdout) && !has_passphrase_shape(&out.stderr));
    for f in files_under(rig.tmp.path()) {
        let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap_or_default()).into_owned();
        assert!(!text.contains("Backup passphrase"), "{}", f.display());
    }
    for g in &started.given {
        assert!(!has_passphrase_shape(&g.to_string_lossy()));
    }
    assert_no_canary(&transcript);
    // A second init on the same installation answers the same: nothing was left behind.
    let pty = Pty::open();
    let mut again = start_cli(&rig, "init-again", &args, Some(&pty), CEREMONY);
    assert_eq!(finish(&mut again).code, 4);
}

/// `replace_orphan_cli_warns_and_cross_checks_bundle` (m03-plan U12; ADR-0008 D4 item 1,
/// F08), on a pty against the in-process runtime with an orphan K_ca in the scratch
/// store (no registration names it):
///
/// * plain `init` refuses (`CONFIG_CONFLICT`), naming restore and `--replace-orphan`;
/// * with a bundle listing a live enrollment trusting the orphan: the irreversibility
///   warning, the refusal, and the restore offer; the item stays (exit 6);
/// * with a bundle that does not list the CA: a note, then the typed confirmation;
/// * with `--no-bundle-available`: the "remote lines may still trust" warning; anything
///   but `delete` keeps the item (exit 3); `delete` deletes exactly that item, then the
///   init ceremony goes on to the registration, which the scratch store stops (S3).
#[cfg(unix)]
#[test]
fn replace_orphan_cli_warns_and_cross_checks_bundle() {
    let rig = Rig::new();
    let orphan = rig.seed_orphan();
    let fp = orphan.fingerprint.to_string();
    let backup = rig.file("new-backup.key");
    let backup_arg = backup.to_string_lossy().into_owned();
    let store = rig.scratch_store();

    // Plain init: the orphan is reported first.
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "plain", &args, Some(&pty), CEREMONY);
    let out = finish(&mut s);
    assert_eq!(out.code, 6, "{out:?}");
    assert_eq!(out.json()["code"], "CONFIG_CONFLICT");
    let t = pty.transcript();
    assert!(t.contains("heimdall issuer restore"), "{t}");
    assert!(t.contains("--replace-orphan"), "{t}");

    // A bundle listing a live enrollment under the orphan's CA.
    let bundle = |name: &str, live: bool, list_ca: bool| -> PathBuf {
        let path = rig.file(name);
        let ca_line = format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture {fp}");
        let mut b = serde_json::json!({
            "schema": "heimdall-recovery-bundle/1",
            "created_at": "2026-11-01T00:00:00Z",
            "redacted": false,
            "cas": [],
            "enrollments": [{
                "marker": "heimdall:enr_fixture",
                "destination_id": "dst-lab",
                "alias": "lab",
                "hostname": "lab.example.invalid",
                "port": 22,
                "account": "deploy",
                "registry": {"path": null, "resolved_by": "remote_home"},
                "registry_path_display": "~/.ssh/authorized_keys",
                "form": "account",
                "state": if live { "verified" } else { "removed" },
                "ca_fingerprint": fp,
                "ca_public_key": ca_line,
                "line_sha256": "ab".repeat(32),
            }],
            "instructions": [],
        });
        if list_ca {
            b["cas"] = serde_json::json!([{
                "fingerprint": fp,
                "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture",
                "backup_sha256": "ab".repeat(32),
                "backup_created_at": "2026-11-01T00:00:00Z",
                "state": "active",
            }]);
        }
        std::fs::write(&path, serde_json::to_vec(&b).unwrap()).unwrap();
        path
    };
    let live = bundle("live.json", true, true);
    let live_arg = live.to_string_lossy().into_owned();
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--bundle",
        live_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "live", &args, Some(&pty), CEREMONY);
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 6, "{out:?}\n{t}");
    assert_eq!(out.json()["code"], "CONFIG_CONFLICT");
    assert!(t.contains("irreversible"), "{t}");
    assert!(
        t.contains("1 enrollment(s) that still trust this CA"),
        "{t}"
    );
    assert!(t.contains("Restore it instead"), "{t}");
    assert!(t.contains("heimdall issuer restore --backup"), "{t}");
    assert!(!t.contains("Type 'delete'"), "no deletion offered: {t}");
    assert_eq!(
        store.list().unwrap(),
        vec![orphan.clone()],
        "the item stays"
    );

    // A bundle that does not list this CA and only a final enrollment: a note, then the
    // typed confirmation; `no` keeps the item.
    let other = bundle("other.json", false, false);
    let other_arg = other.to_string_lossy().into_owned();
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--bundle",
        other_arg.as_str(),
    ];
    let mut s = start_cli(&rig, "other", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Type 'delete'", &mut s.child));
    pty.type_line("no");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert_eq!(out.code, 3, "{out:?}\n{t}");
    assert_eq!(out.json()["code"], "INTERACTION_REQUIRED");
    assert!(t.contains("does not list this CA"), "{t}");
    assert!(t.contains("irreversible"), "{t}");
    assert_eq!(store.list().unwrap(), vec![orphan.clone()]);

    // No bundle: the warning, then `delete` deletes exactly the orphan; the ceremony
    // then reaches the registration, which the scratch store stops (S3).
    let pty = Pty::open();
    let args = [
        "--json",
        "issuer",
        "init",
        "--backup-out",
        backup_arg.as_str(),
        "--replace-orphan",
        fp.as_str(),
        "--no-bundle-available",
    ];
    let mut s = start_cli(&rig, "none", &args, Some(&pty), CEREMONY);
    assert!(pty.wait_for("Type 'delete'", &mut s.child));
    let t = pty.transcript();
    assert!(t.contains("remote lines may still trust this CA"), "{t}");
    pty.type_line("delete");
    let out = finish(&mut s);
    let t = pty.transcript();
    assert!(t.contains("Deleted."), "{t}");
    assert!(
        store.list().unwrap().is_empty(),
        "exactly the orphan was deleted"
    );
    assert_eq!(out.code, 4, "{out:?}\n{t}");
    assert_eq!(reason(&out.json()), "issuer_store_unavailable");
    assert!(!backup.exists());
    assert!(rig.pending().is_empty());
    assert_no_canary(&t);
}

/// The `retire_issuer` typed confirmation and the R2B deletion end to end (m03-plan
/// U12; ADR-0008 §17.22 item 12), against the in-process runtime with a registered CA
/// whose K_ca is in the scratch store and whose locator is recorded:
///
/// * `--non-interactive` and a non-TTY stdin send `issuer.retire` only: exit 3
///   `INTERACTION_REQUIRED` with `next.decision_ref`, the CA still `active`;
/// * on a pty, EOF, `no` and Ctrl-C at the prompt send nothing more (exit 3), and the
///   decision stays pending;
/// * `yes`: `Decide approve`, the issuer unloads the CA (`unloaded`), then this process
///   deletes exactly the recorded locator and confirms it (`deleted_locator`): with the
///   S3 switch off the scratch store's item is **not** deleted (exit 4,
///   `issuer_store_unavailable`; the CA waits at `unloaded`, the item stays). **Blocked
///   on the S3 ruling:** the deletion, the confirmation and `retired` on the scratch
///   store (asserted when `S3_TEST_STORE_DELETION` is on).
#[cfg(unix)]
#[test]
fn issuer_retire_typed_yes_and_r2b_deletion_on_scratch_store() {
    let mut rig = Rig::new();
    let (fp, item) = rig.seed_ca();
    let store = rig.scratch_store();
    let fp_arg = fp.to_string();

    for (label, args) in [
        (
            "--non-interactive",
            vec![
                "--json",
                "--non-interactive",
                "issuer",
                "retire",
                fp_arg.as_str(),
            ],
        ),
        (
            "non-TTY stdin",
            vec!["--json", "issuer", "retire", fp_arg.as_str()],
        ),
    ] {
        let out = rig.cli(&args);
        assert_eq!(out.code, 3, "{label}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "INTERACTION_REQUIRED", "{label}");
        assert!(env["next"]["decision_ref"].is_string(), "{label}: {out:?}");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Active), "{label}");
    }
    let pending = rig.pending();
    assert_eq!(pending.len(), 1, "one RetireIssuer decision, joined");

    let args = ["--json", "issuer", "retire", fp_arg.as_str()];
    for (label, answer) in [
        ("EOF", &b"\x04"[..]),
        ("no", &b"no\n"[..]),
        ("Ctrl-C", &b"\x03"[..]),
    ] {
        let pty = Pty::open();
        let mut s = start_cli(&rig, &format!("retire-{label}"), &args, Some(&pty), PROMPT);
        assert!(pty.wait_for("[y/N]: ", &mut s.child), "{label}");
        std::thread::sleep(Duration::from_millis(200));
        pty.type_bytes(answer);
        let out = finish(&mut s);
        assert_eq!(out.code, 3, "{label}: {out:?}\n{}", pty.transcript());
        assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{label}");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Active), "{label}");
        assert_eq!(rig.pending().len(), 1, "{label}: still pending");
    }

    // `yes`: approve, unload, then the owner-present deletion.
    let pty = Pty::open();
    let mut s = start_cli(&rig, "retire-yes", &args, Some(&pty), PROMPT);
    assert!(pty.wait_for("[y/N]: ", &mut s.child));
    let shown = pty.transcript();
    assert!(shown.contains("retire_issuer"), "{shown}");
    assert!(shown.contains(fp.as_str()), "{shown}");
    pty.type_line("yes");
    let out = finish(&mut s);
    let env = out.json();
    assert!(rig.pending().is_empty(), "the decision was used");
    if S3_TEST_STORE_DELETION {
        assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
        assert_eq!(env["code"], "OK");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Retired));
        assert!(store.list().unwrap().is_empty(), "exactly L was deleted");
        let ca = &env["data"]["cas"][0];
        assert_eq!(ca["state"], "retired", "{env}");
    } else {
        assert_eq!(out.code, 4, "{out:?}\n{}", pty.transcript());
        assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
        assert_eq!(reason(&env), "issuer_store_unavailable", "{out:?}");
        assert!(out.message().contains("test-configuration"), "{out:?}");
        assert_eq!(
            rig.ca_state(&fp),
            Some(CaState::Unloaded),
            "waits at unloaded"
        );
        assert_eq!(
            store.list().unwrap(),
            vec![item.clone()],
            "nothing was deleted"
        );
        // The status names the item awaiting deletion; a second retire answers the same.
        let st = rig.cli(&["--json", "issuer", "status"]);
        assert_eq!(st.code, 0, "{st:?}");
        let ca = &st.json()["data"]["cas"][0];
        assert_eq!(ca["state"], "unloaded");
        assert_eq!(ca["store_locator"], item.locator.as_str());
        let pty = Pty::open();
        let mut s = start_cli(&rig, "retire-again", &args, Some(&pty), PROMPT);
        let out = finish(&mut s);
        assert_eq!(out.code, 4, "{out:?}");
        assert_eq!(rig.ca_state(&fp), Some(CaState::Unloaded));
    }
}

/// `issuer status`, `issuer bundle` and `issuer unlock` JSON envelopes against the
/// in-process runtime (m03-plan U12 "the JSON envelope for each command"):
///
/// * `status`: `OK`, the `issuer.status` data (the CA, its recorded store item); the
///   human form names the store item the CLI found that no registration names;
/// * `bundle --out`: `OK`, the bundle data; the file is written owner-only (0600 on
///   Unix, also under umask 002), equals the data, and is never overwritten (exit 2);
///   `--redact hostnames` writes a redacted bundle;
/// * `unlock` (pty): `OK` with the status while the store is available; a missing store
///   reports what to do (exit 4) and sends no `issuer.unlock`.
#[cfg(unix)]
#[test]
fn issuer_status_bundle_unlock_json_envelopes() {
    let mut rig = Rig::new();
    let (fp, item) = rig.seed_ca();
    let _orphan = rig.seed_orphan();

    let out = rig.cli(&["--json", "issuer", "status"]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["cas"][0]["fingerprint"], fp.as_str());
    assert_eq!(env["data"]["cas"][0]["state"], "active");
    assert_eq!(
        env["data"]["cas"][0]["store_locator"],
        item.locator.as_str()
    );
    assert_eq!(env["data"]["issuer_isolation"], "same_user_process");
    let human = rig.cli(&["issuer", "status"]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(human.stdout.contains(fp.as_str()), "{human:?}");
    assert!(
        human.stdout.contains("test-configuration store"),
        "{human:?}"
    );

    // bundle
    let out_path = rig.file("bundle.json");
    let out_arg = out_path.to_string_lossy().into_owned();
    let out = rig.cli(&["--json", "issuer", "bundle", "--out", out_arg.as_str()]);
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["schema"], "heimdall-recovery-bundle/1");
    assert_eq!(env["data"]["cas"][0]["fingerprint"], fp.as_str());
    let written: Value = serde_json::from_slice(&std::fs::read(&out_path).unwrap()).unwrap();
    assert_eq!(written, env["data"]);
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "owner-only");
    }
    let before = std::fs::read(&out_path).unwrap();
    let again = rig.cli(&["--json", "issuer", "bundle", "--out", out_arg.as_str()]);
    assert_eq!(again.code, 2, "{again:?}");
    assert!(again.message().contains("never overwrites"), "{again:?}");
    assert_eq!(std::fs::read(&out_path).unwrap(), before);
    let redacted = rig.file("redacted.json");
    let redacted_arg = redacted.to_string_lossy().into_owned();
    let out = rig.cli(&[
        "issuer",
        "bundle",
        "--out",
        redacted_arg.as_str(),
        "--redact",
        "hostnames",
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stdout.contains("bundle_redacted"), "{out:?}");
    let r: Value = serde_json::from_slice(&std::fs::read(&redacted).unwrap()).unwrap();
    assert_eq!(r["redacted"], true);

    // unlock on the pty: the store is available, the issuer reloads.
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    assert_eq!(out.code, 0, "{out:?}\n{}", pty.transcript());
    assert_eq!(out.json()["code"], "OK");
    assert!(
        pty.transcript().contains("reloaded"),
        "{}",
        pty.transcript()
    );

    // The store is missing: reported with what to do; nothing is sent.
    let dir = rig.state_dir().join(SCRATCH_STORE_DIR);
    let aside = rig.state_dir().join("scratch-aside");
    std::fs::rename(&dir, &aside).unwrap();
    let pty = Pty::open();
    let mut s = start_cli(
        &rig,
        "unlock-missing",
        &["--json", "issuer", "unlock"],
        Some(&pty),
        CEREMONY,
    );
    let out = finish(&mut s);
    std::fs::rename(&aside, &dir).unwrap();
    assert_eq!(out.code, 4, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(reason(&env), "issuer_store_unavailable");
    assert!(
        pty.transcript().contains("heimdall issuer unlock"),
        "{}",
        pty.transcript()
    );
    rig.stop();
}
