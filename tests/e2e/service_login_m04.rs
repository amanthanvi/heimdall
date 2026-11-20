//! M04 U1 through the **real binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`):
//! the login entry's command line (ADR-0010 §1 item 2, §6 item 1; m04-plan U1).
//!
//! * `login_mode_yields_to_running_instance`: `service run --login` exits 0 with no output
//!   and no change under the home while another runtime holds the lock, leaving that one
//!   instance running; and, as the control, with no runtime it runs like `service run`.
//! * `uninstall_removes_only_the_owned_login_entry`: uninstall removes Heimdall's own entry
//!   by its exact data, leaves an entry of a similar name alone, and leaves a non-owned entry
//!   at Heimdall's own name alone and reported.
//! * `service_autostart_commands_report_refuse_and_touch_only_their_own_entry`: one table
//!   over the new commands' refusals and reports: `status`, `disable`, `enable` without a
//!   terminal, a foreign entry at the name, a relocated home without a scratch root, a bad
//!   scratch root.
//!
//! Every entry is written under a scratch root (`HEIMDALL_TEST_LOGIN_ROOT`: a directory, on
//! Windows a `HKCU\Software\HeimdallTest\<unique>` subkey that is deleted at the end); the
//! account's Run key, LaunchAgents and systemd units are never named. On macOS run with
//! `TMPDIR=/tmp` (the runtime's socket path limit).
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heimdall_runtime::autostart::render::LoginCommand;
use heimdall_runtime::autostart::{LoginHost, installation_token, system_host};
use heimdall_testkit::assert_no_canary;
use serde_json::Value;

fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("hmtest-{tag}-{}-{nanos:x}", std::process::id())
}

/// The scratch root: a directory, or a registry subkey on Windows (deleted when dropped).
struct Root {
    path: PathBuf,
    _dir: Option<tempfile::TempDir>,
}

impl Root {
    fn new() -> Self {
        if cfg!(windows) {
            Self {
                path: PathBuf::from(format!(r"Software\HeimdallTest\{}", unique("e2e"))),
                _dir: None,
            }
        } else {
            let dir = tempfile::Builder::new().prefix("hlr").tempdir().unwrap();
            Self {
                path: dir.path().to_owned(),
                _dir: Some(dir),
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Root {
    fn drop(&mut self) {
        let key = self.path.to_string_lossy().into_owned();
        let _ = Command::new("reg")
            .args(["delete", &format!(r"HKCU\{key}"), "/f"])
            .output();
        let _ = heimdall_runtime::autostart::windows::delete_scratch_key(&key);
    }
}

/// A temporary Heimdall home and its scratch login root.
struct World {
    home: tempfile::TempDir,
    root: Root,
}

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .find_map(|l| l.find('{').and_then(|i| serde_json::from_str(&l[i..]).ok()))
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }
}

impl World {
    fn new() -> Self {
        Self {
            home: tempfile::Builder::new().prefix("hdm").tempdir().unwrap(),
            root: Root::new(),
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.home.path().join("state")
    }

    fn token(&self) -> String {
        installation_token(&self.state_dir())
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.arg("--json").args(args);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("HEIMDALL_TEST_") {
                cmd.env_remove(k);
            }
        }
        cmd.env("HEIMDALL_HOME", self.home.path())
            .env("HEIMDALL_TEST_LOGIN_ROOT", &self.root.path)
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Out {
        self.finish(self.command(args))
    }

    fn finish(&self, mut cmd: Command) -> Out {
        let out = cmd.output().expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        out
    }

    /// The host of this world's entry (scratch root, no activation).
    fn host(&self) -> std::sync::Arc<dyn LoginHost> {
        system_host(&self.token(), Some(&self.root.path))
    }

    fn instance_pid(&self) -> Option<u32> {
        let text =
            std::fs::read_to_string(self.home.path().join("run").join("instance.json")).ok()?;
        let v: Value = serde_json::from_str(&text).ok()?;
        v["pid"].as_u64().and_then(|p| u32::try_from(p).ok())
    }

    /// Start `args` as this test's child and wait until a runtime answers `service status`.
    fn start(&self, args: &[&str]) -> Child {
        let mut cmd = self.command(args);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn service");
        let start = Instant::now();
        loop {
            if self.run(&["service", "status"]).code == 0 {
                return child;
            }
            if let Some(code) = child.try_wait().unwrap() {
                panic!("the service exited early ({code})");
            }
            assert!(start.elapsed() < Duration::from_secs(30), "no start");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `service stop`, then the child must exit 0.
    fn stop(&self, mut child: Child) {
        let out = self.run(&["service", "stop"]);
        assert_eq!(out.code, 0, "{out:?}");
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(0), "exit status after stop");
                return;
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the service did not stop");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = self
            .command(&["service", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output();
    }
}

/// Every path under `dir`, relative and sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            out.push(
                e.path()
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
            if e.path().is_dir() {
                walk(&e.path(), base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn login_mode_yields_to_running_instance() {
    let w = World::new();
    let first = w.start(&["service", "run"]);
    let pid = w.instance_pid().expect("an advertised instance");
    assert_eq!(pid, first.id());
    // Windows: the runtime started on a state directory Heimdall created fresh, whose
    // protected owner-only DACL the check at start accepted (ADR-0010 §1 item 7).
    #[cfg(windows)]
    assert!(heimdall_testkit::win::is_owner_only(&w.state_dir()).unwrap());
    let advertisement = std::fs::read(w.home.path().join("run").join("instance.json")).unwrap();
    let before = tree(w.home.path());

    // The login entry's command: exit 0, nothing printed, nothing changed, one instance.
    let out = w.run(&["service", "run", "--login"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(
        (out.stdout.as_str(), out.stderr.as_str()),
        ("", ""),
        "{out:?}"
    );
    assert_eq!(tree(w.home.path()), before, "no side effect under the home");
    assert_eq!(
        w.instance_pid(),
        Some(pid),
        "the first instance still serves"
    );
    assert_eq!(
        std::fs::read(w.home.path().join("run").join("instance.json")).unwrap(),
        advertisement
    );
    let status = w.run(&["service", "status"]);
    assert_eq!(status.code, 0, "{status:?}");
    assert_eq!(status.json()["data"]["pid"], pid);
    w.stop(first);

    // The control: with no instance it is `service run` (it serves, until stopped).
    let second = w.start(&["service", "run", "--login"]);
    assert_eq!(w.instance_pid(), Some(second.id()), "it became the runtime");
    w.stop(second);
}

#[cfg(windows)]
fn write_foreign(w: &World, name: &str, data: &str) {
    let added = Command::new("reg")
        .args([
            "add",
            &format!(r"HKCU\{}", w.root.path.display()),
            "/v",
            name,
            "/t",
            "REG_SZ",
            "/d",
            data,
            "/f",
        ])
        .output()
        .unwrap();
    assert!(added.status.success());
}

#[cfg(windows)]
fn foreign_intact(w: &World, name: &str, data: &str) -> bool {
    let out = Command::new("reg")
        .args([
            "query",
            &format!(r"HKCU\{}", w.root.path.display()),
            "/v",
            name,
        ])
        .output()
        .unwrap();
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains(data)
}

#[cfg(not(windows))]
fn write_foreign(w: &World, name: &str, data: &str) {
    std::fs::write(w.root.path.join(name), data).unwrap();
}

#[cfg(not(windows))]
fn foreign_intact(w: &World, name: &str, data: &str) -> bool {
    std::fs::read_to_string(w.root.path.join(name)).is_ok_and(|t| t == data)
}

/// The names of (a) an entry that looks like Heimdall's, and (b) Heimdall's own, in this
/// host's namespace.
fn names(w: &World) -> (String, String) {
    let token = w.token();
    if cfg!(windows) {
        (format!("Heimdall-{token}x"), format!("Heimdall-{token}"))
    } else if cfg!(target_os = "macos") {
        (
            format!("io.github.amanthanvi.heimdall.{token}x.plist"),
            format!("io.github.amanthanvi.heimdall.{token}.plist"),
        )
    } else {
        (
            "heimdall-other.service".to_owned(),
            "heimdall.service".to_owned(),
        )
    }
}

fn own_command() -> LoginCommand {
    let exe = if cfg!(windows) {
        r"C:\Program Files\Heimdall\heimdall.exe"
    } else {
        "/opt/heimdall/bin/heimdall"
    };
    LoginCommand::new(Path::new(exe)).unwrap()
}

#[test]
fn uninstall_removes_only_the_owned_login_entry() {
    use heimdall_runtime::autostart::{EntryState, RemoveOutcome};
    let w = World::new();
    let host = w.host();
    let (similar, own) = names(&w);
    // Heimdall's own entry, written the way setup writes it, and a foreign entry of a
    // similar name.
    host.install(&own_command()).unwrap();
    write_foreign(&w, &similar, "foreign similar entry");
    assert!(matches!(host.observe().unwrap(), EntryState::Owned(_)));

    // No state store: uninstall has nothing to roll back and starts nothing, and it still
    // removes the entry.
    let out = w.run(&["uninstall", "--non-interactive"]);
    assert_eq!(out.code, 0, "{out:?}");
    let login = &out.json()["data"]["login_entry"];
    assert_eq!(login["removed"], true, "{out:?}");
    assert_eq!(login["conflict"], false);
    assert_eq!(host.observe().unwrap(), EntryState::Absent);
    assert!(
        foreign_intact(&w, &similar, "foreign similar entry"),
        "an entry of a similar name is untouched"
    );

    // Nothing left to remove: a second uninstall removes nothing.
    let out = w.run(&["uninstall", "--non-interactive"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(out.json()["data"]["login_entry"]["removed"], false);

    // A non-owned entry at Heimdall's own name is never touched, and is reported.
    write_foreign(&w, &own, "not heimdall's data");
    assert_eq!(host.observe().unwrap(), EntryState::Foreign);
    let out = w.run(&["uninstall", "--non-interactive"]);
    assert_eq!(out.code, 0, "{out:?}");
    let login = &out.json()["data"]["login_entry"];
    assert_eq!(
        (login["removed"].clone(), login["conflict"].clone()),
        (false.into(), true.into())
    );
    assert!(foreign_intact(&w, &own, "not heimdall's data"));
    assert!(matches!(
        host.remove(),
        Err(heimdall_runtime::autostart::LoginError::Conflict)
    ));
    let _ = RemoveOutcome::Absent;
}

/// One row of the autostart table.
struct Row {
    /// The scenario's name.
    name: &'static str,
    args: &'static [&'static str],
    /// What is at Heimdall's name before: `none`, `owned` or `foreign`.
    before: &'static str,
    /// `HEIMDALL_TEST_LOGIN_ROOT`: `root` (the scratch root), `unset` or a literal.
    root: &'static str,
    exit: i32,
    /// `data.error.reason`, or a `data` key and value for a success.
    reason: Option<&'static str>,
    /// What is at Heimdall's name after: `none`, `owned` or `foreign`.
    after: &'static str,
    /// `data.<key> == value` checks.
    data: Vec<(&'static str, &'static str)>,
}

fn kind_word() -> &'static str {
    if cfg!(windows) {
        "run_value"
    } else if cfg!(target_os = "macos") {
        "launch_agent"
    } else {
        "systemd_user"
    }
}

#[test]
fn service_autostart_commands_report_refuse_and_touch_only_their_own_entry() {
    use heimdall_runtime::autostart::EntryState;
    let kind = kind_word();
    let rows = [
        Row {
            name: "status of nothing",
            args: &["service", "autostart", "status"],
            before: "none",
            root: "root",
            exit: 0,
            reason: None,
            after: "none",
            data: vec![("state", "absent"), ("installed", "false"), ("kind", kind)],
        },
        Row {
            name: "status of Heimdall's own entry",
            args: &["service", "autostart", "status"],
            before: "owned",
            root: "root",
            exit: 0,
            reason: None,
            after: "owned",
            data: vec![("state", "owned"), ("installed", "true")],
        },
        Row {
            name: "status of a foreign entry at the name",
            args: &["service", "autostart", "status"],
            before: "foreign",
            root: "root",
            exit: 0,
            reason: None,
            after: "foreign",
            data: vec![("state", "conflict"), ("installed", "false")],
        },
        Row {
            name: "disable of nothing",
            args: &["service", "autostart", "disable"],
            before: "none",
            root: "root",
            exit: 0,
            reason: None,
            after: "none",
            data: vec![("removed", "false")],
        },
        Row {
            name: "disable removes Heimdall's own entry",
            args: &["service", "autostart", "disable"],
            before: "owned",
            root: "root",
            exit: 0,
            reason: None,
            after: "none",
            data: vec![("removed", "true")],
        },
        Row {
            name: "disable refuses a foreign entry at the name",
            args: &["service", "autostart", "disable"],
            before: "foreign",
            root: "root",
            exit: 6,
            reason: Some("login_entry_conflict"),
            after: "foreign",
            data: vec![],
        },
        Row {
            name: "enable without a terminal writes nothing",
            args: &["service", "autostart", "enable"],
            before: "none",
            root: "root",
            exit: 3,
            reason: None,
            after: "none",
            data: vec![],
        },
        Row {
            name: "enable refuses a foreign entry at the name",
            args: &["service", "autostart", "enable"],
            before: "foreign",
            root: "root",
            exit: 6,
            reason: Some("login_entry_conflict"),
            after: "foreign",
            data: vec![],
        },
        Row {
            name: "enable in a relocated home never reaches the account",
            args: &["service", "autostart", "enable"],
            before: "none",
            root: "unset",
            exit: 2,
            reason: None,
            after: "none",
            data: vec![],
        },
        Row {
            name: "a relative scratch root is a usage error",
            args: &["service", "autostart", "status"],
            before: "none",
            root: "relative/root",
            exit: 2,
            reason: None,
            after: "none",
            data: vec![],
        },
    ];
    for row in rows {
        let w = World::new();
        let host = w.host();
        let (_, own) = names(&w);
        match row.before {
            "owned" => {
                host.install(&own_command()).unwrap();
            }
            "foreign" => write_foreign(&w, &own, "foreign data at the name"),
            _ => {}
        }
        let mut cmd = w.command(row.args);
        match row.root {
            "root" => {}
            "unset" => {
                cmd.env_remove("HEIMDALL_TEST_LOGIN_ROOT");
            }
            literal => {
                cmd.env("HEIMDALL_TEST_LOGIN_ROOT", literal);
            }
        }
        let out = w.finish(cmd);
        assert_eq!(out.code, row.exit, "{}: {out:?}", row.name);
        let env = out.json();
        if let Some(reason) = row.reason {
            assert_eq!(env["data"]["error"]["reason"], reason, "{}", row.name);
        }
        for (key, value) in &row.data {
            assert_eq!(
                env["data"][key].to_string().trim_matches('"'),
                *value,
                "{}: {key}",
                row.name
            );
        }
        let state = match host.observe().unwrap() {
            EntryState::Absent => "none",
            EntryState::Owned(_) => "owned",
            EntryState::Foreign => "foreign",
        };
        assert_eq!(state, row.after, "{}", row.name);
        if row.after == "foreign" {
            assert!(
                foreign_intact(&w, &own, "foreign data at the name"),
                "{}",
                row.name
            );
        }
    }
}

// =================================================================================
// WSL: the systemd user unit starts the runtime at the next login (Windows-hosted)
// =================================================================================

/// `linux_login_entry_starts_runtime_at_next_login` (m04-plan U1 → A31, A08): in a
/// **disposable** WSL distribution with systemd, `service autostart enable` installs the
/// systemd user unit, `wsl --terminate` stops the distribution, and a **new login** finds
/// the runtime serving. Driven from the Windows PC through `wsl.exe`; it never runs in or
/// touches the owner's distributions.
///
/// **Gate.** `#[ignore]`, and `HM_FIXTURE_WSL_DISTRO` must name the run's disposable
/// distribution (the variable `tests/native/m02/run-wsl-distro.sh`'s harness already sets
/// for its scenarios; its name must match `hm-m0<N>-<hex>` and be registered). Also:
/// * `HM_WSL_LOGIN_HEIMDALL`: the absolute in-distribution path of the Linux `heimdall`
///   binary (a copy the harness staged, e.g. under the disposable user's scratch home);
/// * `HM_WSL_LOGIN_USER`: the disposable non-root user (not `root`).
///
/// The distribution must run systemd (`/etc/wsl.conf` `[boot] systemd=true`; the M02
///   harness writes `systemd=false`, so this run needs the harness's systemd variant).
///
/// **The login session, defined explicitly.** `wsl --exec` alone creates no PAM or systemd
/// user session. A "login" here is `wsl.exe -d <name> -u root --exec su -l <user> -c
/// <script>`: `su -l` runs the distribution's PAM `su-l` stack, whose `common-session`
/// includes `pam_systemd`, so logind opens a session for the user and starts the user's
/// manager (`user@<uid>.service`) and its `default.target`. The script runs inside that
/// session; when it ends the session ends and, with no lingering, the manager stops again.
/// Lingering is never enabled (asserted, before and after). The runtime is looked for only
/// **inside** a login session, with `heimdall service status`, which never starts one.
///
/// Run: `cargo test -p heimdall --test e2e_platform_m04 -- --ignored
/// linux_login_entry_starts_runtime_at_next_login` on the PC.
#[cfg(windows)]
mod wsl_login {
    use std::process::Command;
    use std::time::Duration;

    struct Run {
        distro: String,
        user: String,
        heimdall: String,
    }

    #[derive(Debug)]
    struct Done {
        code: i32,
        stdout: String,
    }

    fn wsl(args: &[&str]) -> Done {
        let out = Command::new("wsl.exe")
            .args(args)
            .output()
            .expect("wsl.exe");
        Done {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        }
    }

    /// `wsl.exe` lists in UTF-16LE.
    fn listed(args: &[&str]) -> Vec<String> {
        let out = Command::new("wsl.exe")
            .args(args)
            .output()
            .expect("wsl.exe");
        let units: Vec<u16> = out
            .stdout
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
            .lines()
            .map(|l| l.trim().trim_start_matches('\u{feff}').to_owned())
            .filter(|l| !l.is_empty())
            .collect()
    }

    impl Run {
        /// As root inside the disposable distribution.
        fn root(&self, script: &str) -> Done {
            wsl(&[
                "-d",
                &self.distro,
                "-u",
                "root",
                "--exec",
                "/bin/sh",
                "-c",
                script,
            ])
        }

        /// One login of the user (module docs): `su -l` through PAM.
        fn login(&self, script: &str) -> Done {
            wsl(&[
                "-d",
                &self.distro,
                "-u",
                "root",
                "--exec",
                "/usr/bin/su",
                "-l",
                &self.user,
                "-c",
                script,
            ])
        }
    }

    fn setup() -> Option<Run> {
        let distro = std::env::var("HM_FIXTURE_WSL_DISTRO").ok()?;
        let user = std::env::var("HM_WSL_LOGIN_USER").ok()?;
        let heimdall = std::env::var("HM_WSL_LOGIN_HEIMDALL").ok()?;
        // Only the harness's disposable distribution: `hm-m0<N>-<hex>`, or ⟨M04 U7⟩ the M04
        // runner's `hm-m04-<hex>-<1|2>`, registered, and never an owner's.
        let well_formed = distro.strip_prefix("hm-m0").is_some_and(|rest| {
            let mut parts = rest.splitn(2, '-');
            let hex_ok = |h: &str| h.len() >= 6 && h.chars().all(|c| c.is_ascii_hexdigit());
            matches!(
                (parts.next(), parts.next()),
                (Some(n), Some(tail)) if n.len() == 1
                    && n.chars().all(|c| c.is_ascii_digit())
                    && (hex_ok(tail)
                        || tail
                            .rsplit_once('-')
                            .is_some_and(|(h, k)| hex_ok(h) && (k == "1" || k == "2")))
            )
        });
        assert!(
            well_formed,
            "HM_FIXTURE_WSL_DISTRO is not a disposable name"
        );
        assert!(
            user != "root"
                && !user.is_empty()
                && user
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "HM_WSL_LOGIN_USER must be a disposable non-root user"
        );
        assert!(
            heimdall.starts_with('/') && !heimdall.contains(['\'', '"', ' ', '\n']),
            "HM_WSL_LOGIN_HEIMDALL must be a plain absolute path"
        );
        assert!(
            listed(&["--list", "--quiet"]).contains(&distro),
            "the distribution is not registered"
        );
        Some(Run {
            distro,
            user,
            heimdall,
        })
    }

    #[test]
    #[ignore = "needs HM_FIXTURE_WSL_DISTRO (a disposable systemd distribution), HM_WSL_LOGIN_USER and HM_WSL_LOGIN_HEIMDALL; run with --ignored on the PC"]
    fn linux_login_entry_starts_runtime_at_next_login() {
        let Some(run) = setup() else {
            panic!(
                "set HM_FIXTURE_WSL_DISTRO, HM_WSL_LOGIN_USER and HM_WSL_LOGIN_HEIMDALL (module docs)"
            );
        };
        let h = &run.heimdall;

        // Preconditions: systemd is init, the user exists, the binary runs, no lingering.
        let init = run.root("cat /proc/1/comm");
        assert_eq!(init.stdout.trim(), "systemd", "{init:?}");
        let ready = run.root("systemctl is-system-running --wait");
        assert!(
            ["running", "degraded"].contains(&ready.stdout.trim()),
            "{ready:?}"
        );
        let linger = |run: &Run| {
            run.root(&format!("loginctl show-user {} -p Linger", run.user))
                .stdout
                .trim()
                .to_owned()
        };
        assert!(!linger(&run).contains("yes"), "lingering is never enabled");
        assert_eq!(
            run.root(&format!("test -x {h}")).code,
            0,
            "the binary is staged"
        );

        // Session 1: install the entry (the attended setup step, on a pty: `script` gives
        // the prompt its terminal and the typed `yes` comes from stdin), look at it, and
        // stop the runtime that `enable` started on demand, so that what is found later is
        // not left over.
        let install = format!(
            "set -e; {h} --json service autostart status | grep -q '\"installed\":false'; \
             printf 'yes\\n' | script -q -e -c '{h} service autostart enable' /dev/null >/dev/null; \
             {h} --json service autostart status | grep -q '\"installed\":true'; \
             systemctl --user is-enabled heimdall.service; \
             test -f \"$HOME/.config/systemd/user/heimdall.service\"; \
             {h} service stop >/dev/null 2>&1 || true; \
             if {h} service status >/dev/null 2>&1; then echo runtime-still-up; exit 1; fi"
        );
        let first = run.login(&install);
        assert_eq!(first.code, 0, "{first:?}");

        // The distribution stops: only this one.
        let stopped = wsl(&["--terminate", &run.distro]);
        assert_eq!(stopped.code, 0, "{stopped:?}");
        assert!(
            !listed(&["--list", "--running", "--quiet"]).contains(&run.distro),
            "the distribution is still running"
        );
        std::thread::sleep(Duration::from_secs(2));

        // Session 2, a new login: the user manager starts `default.target`, which starts the
        // entry, which starts the runtime. `service status` never starts one, so a runtime
        // seen here was started by the entry.
        let again = format!(
            "for i in $(seq 1 60); do \
               if {h} --json service status 2>/dev/null | grep -q '\"running\":true'; then \
                 systemctl --user is-active heimdall.service; \
                 test \"$({h} --json service status | grep -o '\"pid\":[0-9]*' | sort -u | wc -l)\" = 1; \
                 exit 0; \
               fi; sleep 1; done; echo no-runtime-at-login; exit 1"
        );
        let second = run.login(&again);
        assert_eq!(second.code, 0, "no runtime at the next login: {second:?}");
        assert!(second.stdout.contains("active"), "{second:?}");

        // Clean up inside the disposable distribution (the harness unregisters it anyway),
        // and lingering was never turned on.
        let cleanup = run.login(&format!(
            "{h} service stop >/dev/null 2>&1; {h} --json service autostart disable | grep -q '\"removed\":true'; \
             ! systemctl --user is-enabled heimdall.service >/dev/null 2>&1; \
             test ! -e \"$HOME/.config/systemd/user/heimdall.service\""
        ));
        assert_eq!(cleanup.code, 0, "{cleanup:?}");
        assert!(!linger(&run).contains("yes"), "lingering is never enabled");
    }
}
