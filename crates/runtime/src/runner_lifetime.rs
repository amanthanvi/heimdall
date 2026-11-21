//! ⟨M06 U3⟩ The runner runtime's lifetime (ADR-0012 §4.3; the ruling on Q7, R09).
//!
//! * **Preferred:** a verified `systemd --user` unit where the owner has enabled linger. The
//!   unit is verified when systemd reports it loaded and active, its main PID is this process,
//!   and its `ExecStart` runs this executable's `service run`. Linger is read
//!   (`loginctl show-user <uid> --property=Linger`), **never enabled**: this module only runs
//!   read-only `show` queries ([`READ_ONLY_QUERIES`]).
//! * **Otherwise** the narrower lifetime is reported: `session_scope`, which survives logout
//!   only while logind's `KillUserProcesses=no` (read and reported beside it when available).
//! * Off Linux there is no `systemd --user`: `unknown`.
//!
//! The probes run through [`LifetimeProbe`] so tests use fixture outputs; the product probe
//! ([`SystemProbe`]) runs `loginctl` and `systemctl --user` as bounded, windowless children
//! with a cleared environment, and kills only the exact child it started when one overruns.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heimdall_contract::remote::RunnerLifetime;

/// The unit name the runner's user service uses.
pub const RUNNER_UNIT: &str = "heimdall-runner.service";

/// The only subcommands the probes run (all read-only).
pub const READ_ONLY_QUERIES: [&str; 3] = ["show-user", "show-session", "show"];

/// How long one probe may run.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs one read-only query and returns its standard output, or `None` when it could not run
/// or failed.
pub trait LifetimeProbe {
    /// `program` with `args`; `None` on any failure.
    fn query(&self, program: &str, args: &[&str]) -> Option<String>;
}

/// What the unit check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitVerdict {
    /// Loaded, active, this process its main PID, `ExecStart` this executable's `service run`.
    Verified,
    /// The unit could not be read (no user manager, no unit).
    Unreadable,
    /// The unit exists but does not run this process as described; why.
    Mismatch(&'static str),
}

/// The lifetime report (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeReport {
    /// The reported lifetime.
    pub lifetime: RunnerLifetime,
    /// Whether linger is enabled for the account (`None`: not readable).
    pub linger: Option<bool>,
    /// logind's `KillUserProcesses` (`None`: not readable).
    pub kill_user_processes: Option<bool>,
    /// The unit check.
    pub unit: UnitVerdict,
}

fn yes_no(s: Option<String>) -> Option<bool> {
    match s?.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// One `KEY=value` property of `systemctl show` output.
fn property<'a>(show: &'a str, key: &str) -> Option<&'a str> {
    show.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Whether `systemctl show`'s `ExecStart` value runs `exec` with `service run`: its `path=` is
/// `exec` and its `argv[]=` continues `service run`.
fn exec_start_matches(exec_start: &str, exec: &Path) -> bool {
    let Some(exec) = exec.to_str() else {
        return false;
    };
    let path_ok = exec_start
        .split(';')
        .filter_map(|f| {
            f.trim()
                .trim_start_matches('{')
                .trim()
                .strip_prefix("path=")
        })
        .any(|p| p.trim() == exec);
    let argv_ok = exec_start
        .split(';')
        .filter_map(|f| f.trim().strip_prefix("argv[]="))
        .any(|a| {
            let mut words = a.split_whitespace();
            words.next() == Some(exec)
                && words.next() == Some("service")
                && words.next() == Some("run")
        });
    path_ok && argv_ok
}

/// Verify the unit from `systemctl --user show` output.
fn verify_unit(show: Option<String>, exec: &Path, own_pid: u32) -> UnitVerdict {
    let Some(show) = show else {
        return UnitVerdict::Unreadable;
    };
    if property(&show, "LoadState") != Some("loaded") {
        return UnitVerdict::Mismatch("not_loaded");
    }
    if property(&show, "ActiveState") != Some("active") {
        return UnitVerdict::Mismatch("not_active");
    }
    if property(&show, "MainPID").and_then(|p| p.trim().parse::<u32>().ok()) != Some(own_pid) {
        return UnitVerdict::Mismatch("main_pid_is_not_this_process");
    }
    if !property(&show, "ExecStart").is_some_and(|e| exec_start_matches(e, exec)) {
        return UnitVerdict::Mismatch("exec_start_is_not_this_executable");
    }
    UnitVerdict::Verified
}

/// Detect the lifetime through `probe` (module docs) for the account `uid`, the unit `unit`,
/// this executable `exec` and this process `own_pid`. The Linux rule; [`detect`] answers
/// `unknown` elsewhere.
#[must_use]
pub fn detect_with(
    probe: &dyn LifetimeProbe,
    uid: u32,
    unit: &str,
    exec: &Path,
    own_pid: u32,
) -> LifetimeReport {
    let uid = uid.to_string();
    let linger = yes_no(probe.query(
        "loginctl",
        &["show-user", &uid, "--property=Linger", "--value"],
    ));
    let kill_user_processes = yes_no(probe.query(
        "loginctl",
        &["show-session", "--property=KillUserProcesses", "--value"],
    ));
    let unit = verify_unit(
        probe.query(
            "systemctl",
            &[
                "--user",
                "show",
                unit,
                "--property=LoadState,ActiveState,MainPID,ExecStart",
                "--no-pager",
            ],
        ),
        exec,
        own_pid,
    );
    let lifetime = if linger == Some(true) && unit == UnitVerdict::Verified {
        RunnerLifetime::UserService
    } else {
        RunnerLifetime::SessionScope
    };
    LifetimeReport {
        lifetime,
        linger,
        kill_user_processes,
        unit,
    }
}

/// The product probe: `loginctl` and `systemctl` from the system directories, cleared
/// environment (with `XDG_RUNTIME_DIR` kept so `systemctl --user` finds the user manager), no
/// stdin, no console window, at most [`PROBE_TIMEOUT`] each.
#[derive(Debug, Clone, Default)]
pub struct SystemProbe {
    /// `XDG_RUNTIME_DIR` for `systemctl --user` (the process's own, when set).
    pub runtime_dir: Option<PathBuf>,
}

impl LifetimeProbe for SystemProbe {
    fn query(&self, program: &str, args: &[&str]) -> Option<String> {
        if !matches!(program, "loginctl" | "systemctl")
            || !args.iter().any(|a| READ_ONLY_QUERIES.contains(a))
        {
            return None;
        }
        let path = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(program))
            .find(|p| p.is_file())?;
        let mut command = heimdall_app::no_window!(std::process::Command::new(path));
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        if let Some(dir) = &self.runtime_dir {
            command.env("XDG_RUNTIME_DIR", dir);
        }
        let mut child = command.spawn().ok()?;
        let deadline = Instant::now() + PROBE_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return None;
                    }
                    let mut out = String::new();
                    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
                    return Some(out);
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    // Only the exact child started above.
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }
}

/// The lifetime of this runner process (module docs): the Linux rule over [`SystemProbe`];
/// `unknown` off Linux.
#[must_use]
pub fn detect(uid: u32, exec: &Path) -> LifetimeReport {
    if cfg!(target_os = "linux") {
        let probe = SystemProbe {
            runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        };
        detect_with(&probe, uid, RUNNER_UNIT, exec, std::process::id())
    } else {
        LifetimeReport {
            lifetime: RunnerLifetime::Unknown,
            linger: None,
            kill_user_processes: None,
            unit: UnitVerdict::Unreadable,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Fixture outputs by program and first query word; records every call.
    struct Fixture {
        linger: Option<&'static str>,
        kill: Option<&'static str>,
        show: Option<String>,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl LifetimeProbe for Fixture {
        fn query(&self, program: &str, args: &[&str]) -> Option<String> {
            let mut call = vec![program.to_owned()];
            call.extend(args.iter().map(|a| (*a).to_owned()));
            self.calls.borrow_mut().push(call);
            match (program, args.first().copied()) {
                ("loginctl", Some("show-user")) => self.linger.map(str::to_owned),
                ("loginctl", Some("show-session")) => self.kill.map(str::to_owned),
                ("systemctl", Some("--user")) => self.show.clone(),
                _ => None,
            }
        }
    }

    const EXEC: &str = "/home/runner/.local/bin/heimdall";

    fn show(state: &str, pid: u32, exec: &str) -> String {
        format!(
            "LoadState=loaded\nActiveState={state}\nMainPID={pid}\nExecStart={{ path={exec} ; argv[]={exec} service run --home /home/runner/.local/share/heimdall ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\n"
        )
    }

    fn fixture(linger: Option<&'static str>, show: Option<String>) -> Fixture {
        Fixture {
            linger,
            kill: Some("no\n"),
            show,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn detect_fixture(f: &Fixture) -> LifetimeReport {
        detect_with(f, 1000, RUNNER_UNIT, Path::new(EXEC), 4242)
    }

    #[test]
    fn a_verified_user_service_with_linger_is_the_user_service_lifetime() {
        let f = fixture(Some("yes\n"), Some(show("active", 4242, EXEC)));
        let r = detect_fixture(&f);
        assert_eq!(r.lifetime, RunnerLifetime::UserService);
        assert_eq!(r.linger, Some(true));
        assert_eq!(r.kill_user_processes, Some(false));
        assert_eq!(r.unit, UnitVerdict::Verified);
    }

    #[test]
    fn anything_less_is_session_scope() {
        let cases = [
            (
                fixture(Some("no\n"), Some(show("active", 4242, EXEC))),
                UnitVerdict::Verified,
            ),
            (
                fixture(Some("yes\n"), Some(show("active", 7, EXEC))),
                UnitVerdict::Mismatch("main_pid_is_not_this_process"),
            ),
            (
                fixture(Some("yes\n"), Some(show("inactive", 4242, EXEC))),
                UnitVerdict::Mismatch("not_active"),
            ),
            (
                fixture(Some("yes\n"), Some(show("active", 4242, "/tmp/other"))),
                UnitVerdict::Mismatch("exec_start_is_not_this_executable"),
            ),
            (fixture(Some("yes\n"), None), UnitVerdict::Unreadable),
            (fixture(None, None), UnitVerdict::Unreadable),
        ];
        for (f, unit) in cases {
            let r = detect_fixture(&f);
            assert_eq!(r.lifetime, RunnerLifetime::SessionScope, "{unit:?}");
            assert_eq!(r.unit, unit);
        }
    }

    /// Linger is read, never enabled: every query is a read-only `show`.
    #[test]
    fn linger_is_never_enabled() {
        let f = fixture(Some("no\n"), Some(show("active", 4242, EXEC)));
        let _ = detect_fixture(&f);
        let calls = f.calls.borrow();
        assert_eq!(calls.len(), 3);
        for call in calls.iter() {
            assert!(
                call.iter().any(|a| READ_ONLY_QUERIES.contains(&a.as_str())),
                "{call:?}"
            );
            assert!(
                !call
                    .iter()
                    .any(|a| a.contains("linger") && !a.contains("Linger")),
                "{call:?}"
            );
            assert!(!call.iter().any(|a| a == "enable" || a == "enable-linger"));
        }
        // The product probe refuses anything but a read-only query outright.
        let p = SystemProbe::default();
        assert_eq!(p.query("loginctl", &["enable-linger", "1000"]), None);
        assert_eq!(p.query("rm", &["show"]), None);
    }
}
