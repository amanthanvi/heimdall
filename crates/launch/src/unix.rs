//! Unix `run`: Heimdall replaces itself with the child (m02-plan U8; ADR-0007 §8).
//!
//! Writes `launching` before `execve` (through `CommandExt::exec`), and
//! `prelaunch_failed` (best effort) after an exec failure. The process becomes the
//! child, so exit status, signals, job control, terminal ownership and stdio are
//! exactly the platform's.
//!
//! Sequence: the pre-flight checks (a refusal writes `prelaunch_failed` with its
//! reason and exit status and returns [`LaunchFailure::Refused`]); the command is
//! built; `launching` is written in full (a failure returns
//! [`LaunchFailure::MetaUnavailable`]: no child); `exec`. If `exec` returns, the
//! failure is recorded as `prelaunch_failed` (`LAUNCH_FAILED`, 127, `exec_error`)
//! and [`LaunchFailure::ExecError`] is returned.
//!
//! **SIGPIPE after a failed exec.** Rust ignores SIGPIPE, but std's `exec` resets it
//! to the default disposition in *this* process just before `execvp` (so the child
//! starts with the default), and nothing restores it when `execvp` fails. A
//! `prelaunch_failed` write to a pipe whose reader has gone would then kill
//! Heimdall instead of failing with `EPIPE` (ADR-0007 §8 assumes the latter). After
//! a failed exec this module therefore installs a SIGPIPE handler (tokio's, which
//! stays for the life of the process) before any further write; if that cannot be
//! done, the fd protocol writes nothing more and `launching` stays last
//! (`indeterminate`, which the reader table allows). The caller's own writes after
//! the return (stderr) get the same protection.

use std::ffi::OsString;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use heimdall_contract::envelope::reason;

use crate::LaunchFailure;
use crate::env::{EnvDelta, child_command};
use crate::meta::SideChannel;
use crate::resolve::{ResolvedProgram, preflight};

/// The exit status of a launch call that failed after `launching` (`exec_error`).
const EXEC_ERROR_EXIT: i32 = 127;

/// Exec `program` with `args` and `delta`. Returns only on failure.
///
/// `args` are the arguments after the program (argv[1..]); argv[0] is the resolved
/// path. The working directory, the rest of the environment and stdio are the
/// caller's.
#[must_use]
pub fn exec_replace(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
) -> LaunchFailure {
    match attempt(program, args, delta, meta) {
        Ok((mut command, meta)) => {
            let _ = command.exec();
            after_exec_failure(meta)
        }
        Err(failure) => failure,
    }
}

/// The test-only hooks of m02-plan U8 (`HEIMDALL_TEST_PRE_EXEC_PAUSE`,
/// `HEIMDALL_TEST_FORCE_EXEC_FAILURE`), applied after `launching`. Debug builds
/// only: release builds contain neither this type nor
/// [`exec_replace_with_test_hooks`]; the CLI fills it from its `testcfg`.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestHooks {
    /// After `launching`, open this path for reading before exec. A FIFO blocks
    /// until the test opens it for writing (or kills the process by exact PID).
    pub pre_exec_pause: Option<std::path::PathBuf>,
    /// Make the exec fail after `launching`: the same command is aimed at `/`, which
    /// `execve` always refuses, so the failure takes std's real exec path.
    pub force_exec_failure: bool,
}

/// [`exec_replace`] with [`TestHooks`] (debug builds only).
#[cfg(debug_assertions)]
#[must_use]
pub fn exec_replace_with_test_hooks(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
    hooks: &TestHooks,
) -> LaunchFailure {
    match attempt(program, args, delta, meta) {
        Ok((mut command, meta)) => {
            if let Some(path) = &hooks.pre_exec_pause {
                let _ = std::fs::File::open(path);
            }
            if hooks.force_exec_failure {
                let forced = ResolvedProgram {
                    path: std::path::PathBuf::from("/"),
                    ..program.clone()
                };
                command = child_command(&forced, args, delta);
            }
            let _ = command.exec();
            after_exec_failure(meta)
        }
        Err(failure) => failure,
    }
}

/// Everything before `exec`: the checks, the command, `launching`.
fn attempt(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    mut meta: Option<SideChannel>,
) -> Result<(Command, Option<SideChannel>), LaunchFailure> {
    let executable = match preflight(program, args) {
        Ok(executable) => executable,
        Err(refusal) => {
            if let Some(channel) = meta.as_mut() {
                let _ = channel.write_launch_failed(refusal.exit_code(), refusal.reason());
            }
            return Err(LaunchFailure::Refused(refusal));
        }
    };
    let command = child_command(program, args, delta);
    if let Some(channel) = meta.as_mut()
        && channel
            .write_launching(executable, &delta.overrides)
            .is_err()
    {
        return Err(LaunchFailure::MetaUnavailable);
    }
    Ok((command, meta))
}

/// Record a failed exec (module docs, "SIGPIPE after a failed exec").
fn after_exec_failure(meta: Option<SideChannel>) -> LaunchFailure {
    let sigpipe_handled = keep_signals_handled(&[tokio::signal::unix::SignalKind::pipe()]);
    if let Some(mut channel) = meta
        && (sigpipe_handled || !channel.is_fd())
    {
        let _ = channel.write_launch_failed(EXEC_ERROR_EXIT, reason::EXEC_ERROR);
    }
    LaunchFailure::ExecError
}

/// Install tokio's handler for each of `kinds`, so none of them takes its default
/// action in this process any more (tokio never unregisters a handler). A handler,
/// unlike `SIG_IGN`, does not survive `execve`, so a child started later gets the
/// default disposition. The registration runs on its own thread with its own
/// current-thread runtime, so it works whether or not the caller is inside a
/// runtime. Returns whether every handler is installed.
pub(crate) fn keep_signals_handled(kinds: &[tokio::signal::unix::SignalKind]) -> bool {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                else {
                    return false;
                };
                let _entered = runtime.enter();
                kinds
                    .iter()
                    .all(|kind| tokio::signal::unix::signal(*kind).is_ok())
            })
            .join()
            .unwrap_or(false)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests {
    use std::ffi::OsStr;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    use heimdall_contract::Code;
    use heimdall_contract::doctor::GitScope;
    use heimdall_contract::ids::{BindingId, OperationId};
    use heimdall_contract::request::{ConsumerKind, ConsumerOverride, OverrideSource};
    use heimdall_contract::run_record::{LaunchClassification, RunPlatform, RunRecord, classify};
    use heimdall_contract::version::SchemaVersion;
    use heimdall_localenv::env::{Env, Platform};

    use super::*;
    use crate::meta::encode_line;
    use crate::meta::scratch::Scratch;
    use crate::resolve::{LaunchRefusal, ProgramKind, Via, resolve_program};

    const SCENARIO: &str = "HM_U8_SCENARIO";
    const DIR: &str = "HM_U8_DIR";

    /// What the child-mode process exits with when `exec_replace` returns.
    fn failure_code(failure: &LaunchFailure) -> i32 {
        match failure {
            LaunchFailure::Refused(_) => 90,
            LaunchFailure::MetaUnavailable => 91,
            LaunchFailure::ExecError => 92,
        }
    }

    /// Run a scenario in a fresh copy of this test binary (an `exec` replaces the
    /// process, so it never runs inside the harness). The child is killed by its
    /// own handle if the test fails first.
    pub(crate) struct ChildRun {
        child: Option<Child>,
    }

    impl ChildRun {
        pub(crate) fn start(entry: &str, scenario: &str, dir: &Path) -> ChildRun {
            // Through the fork gate: a descriptor another test thread holds open
            // while this spawn runs is copied into the child until its `exec`
            // (`meta::scratch::fork_gate`).
            let child = crate::meta::scratch::spawn(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        entry,
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                        "-q",
                    ])
                    .env(SCENARIO, scenario)
                    .env(DIR, dir)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
            )
            .unwrap();
            ChildRun { child: Some(child) }
        }

        pub(crate) fn pid(&self) -> u32 {
            self.child.as_ref().unwrap().id()
        }

        pub(crate) fn kill(&mut self) {
            let _ = self.child.as_mut().unwrap().kill();
        }

        pub(crate) fn wait(mut self) -> std::process::ExitStatus {
            let mut child = self.child.take().unwrap();
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    return status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child-mode process did not finish");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for ChildRun {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// The scenario named by the environment, when this binary was started by
    /// [`ChildRun`].
    pub(crate) fn scenario() -> Option<(String, PathBuf)> {
        let scenario = std::env::var(SCENARIO).ok()?;
        let dir = PathBuf::from(std::env::var_os(DIR)?);
        Some((scenario, dir))
    }

    pub(crate) fn sh() -> ResolvedProgram {
        let env = Env::from_vars([("PATH", "/bin:/usr/bin")]);
        resolve_program(OsStr::new("sh"), &env, Path::new("/"), Platform::current()).unwrap()
    }

    pub(crate) fn args(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn op() -> OperationId {
        OperationId::parse("op_00112233445566778899aabbccddeeff").unwrap()
    }

    fn binding() -> BindingId {
        BindingId::parse("binding_0123456789abcdef0123456789abcdef").unwrap()
    }

    fn git_local() -> ConsumerOverride {
        ConsumerOverride {
            consumer: ConsumerKind::Git,
            setting: "core.sshCommand".to_owned(),
            source: OverrideSource::GitScope {
                scope: GitScope::Local,
            },
        }
    }

    const METACHARACTERS: [&str; 10] = [
        "$(touch pwned)",
        "`touch pwned`",
        "a;b",
        "a|b",
        "a&&b",
        "'\"",
        "*",
        "$HOME",
        "",
        "two words",
    ];

    const SCRIPT: &str = "out=$1; shift; printf '%s\\0' \"$@\" > \"$out.args\"; \
         printf '%s' \"$HM_U8_ADDED\" > \"$out.env\"; printf '%s' \"$$\" > \"$out.pid\"; exit 42";

    fn meta_file(dir: &Path) -> SideChannel {
        SideChannel::create_exclusive(&dir.join("meta"))
            .unwrap()
            .with_ids(Some(op()), Some(binding()))
    }

    /// Entry point of the re-executed test binary; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of the exec tests, started by them"]
    fn exec_child() {
        let Some((scenario, dir)) = scenario() else {
            return;
        };
        let delta = EnvDelta {
            set: vec![(OsString::from("HM_U8_ADDED"), OsString::from("added-value"))],
            overrides: vec![git_local()],
        };
        let marker = dir.join("marker").into_os_string().into_string().unwrap();
        let touch = args(&["-c", "touch \"$1\"", "sh", &marker]);
        let failure = match scenario.as_str() {
            s if s.strip_prefix("code:").is_some() => {
                let code = s.trim_start_matches("code:");
                exec_replace(
                    &sh(),
                    &args(&["-c", "exit \"$1\"", "sh", code]),
                    &EnvDelta::default(),
                    None,
                )
            }
            "ok" => {
                let mut a = args(&["-c", SCRIPT, "sh"]);
                a.push(dir.join("out").into_os_string());
                a.extend(args(&METACHARACTERS));
                exec_replace(&sh(), &a, &delta, Some(meta_file(&dir)))
            }
            "signal" => exec_replace(
                &sh(),
                &args(&["-c", "kill -TERM $$"]),
                &EnvDelta::default(),
                None,
            ),
            "exec_error" => {
                let missing = ResolvedProgram {
                    path: dir.join("missing"),
                    kind: ProgramKind::Native,
                    via: Via::Explicit,
                };
                exec_replace(&missing, &touch, &delta, Some(meta_file(&dir)))
            }
            "refused_argument" => {
                let mut a = touch.clone();
                a.push(OsString::from("n\0ul"));
                exec_replace(&sh(), &a, &delta, Some(meta_file(&dir)))
            }
            "meta_unavailable" => {
                let (reader, writer) = std::io::pipe().unwrap();
                drop(reader);
                let channel = SideChannel::over_fd(std::os::fd::OwnedFd::from(writer));
                exec_replace(&sh(), &touch, &delta, Some(channel))
            }
            "force_failure" => exec_replace_with_test_hooks(
                &sh(),
                &touch,
                &delta,
                Some(meta_file(&dir)),
                &TestHooks {
                    pre_exec_pause: None,
                    force_exec_failure: true,
                },
            ),
            "pause" => exec_replace_with_test_hooks(
                &sh(),
                &touch,
                &delta,
                Some(meta_file(&dir)),
                &TestHooks {
                    pre_exec_pause: Some(dir.join("fifo")),
                    force_exec_failure: false,
                },
            ),
            "exec_error_reader_closed" => {
                // The reader takes `launching`, closes its end, then releases the
                // pre-exec pause; the exec then fails for real.
                let (reader, writer) = std::io::pipe().unwrap();
                let fifo = dir.join("fifo");
                let seen = dir.join("seen");
                let thread = std::thread::spawn(move || {
                    use std::io::BufRead as _;
                    let mut line = String::new();
                    std::io::BufReader::new(reader)
                        .read_line(&mut line)
                        .unwrap();
                    std::fs::write(seen, line).unwrap();
                    let _ = std::fs::OpenOptions::new().write(true).open(fifo);
                });
                let missing = ResolvedProgram {
                    path: dir.join("missing"),
                    kind: ProgramKind::Native,
                    via: Via::Explicit,
                };
                let channel = SideChannel::over_fd(std::os::fd::OwnedFd::from(writer))
                    .with_ids(Some(op()), Some(binding()));
                let failure = exec_replace_with_test_hooks(
                    &missing,
                    &touch,
                    &delta,
                    Some(channel),
                    &TestHooks {
                        pre_exec_pause: Some(dir.join("fifo")),
                        force_exec_failure: false,
                    },
                );
                thread.join().unwrap();
                failure
            }
            other => panic!("unknown scenario {other}"),
        };
        std::process::exit(failure_code(&failure));
    }

    fn failed_record(exit_code: i32, reason: &str) -> RunRecord {
        RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion::current(),
            code: Code::LaunchFailed,
            exit_code,
            reason: Some(reason.to_owned()),
            operation_id: Some(op()),
            binding_id: Some(binding()),
        }
    }

    fn line(record: &RunRecord) -> String {
        String::from_utf8(encode_line(record).unwrap()).unwrap()
    }

    fn launching_record(executable: &Path, pid: u32) -> RunRecord {
        RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: executable.to_str().unwrap().to_owned(),
            operation_id: Some(op()),
            binding_id: Some(binding()),
            pid,
            consumer_overrides: vec![git_local()],
        }
    }

    const ENTRY: &str = "unix::tests::exec_child";

    #[test]
    fn exec_replaces_the_process_after_launching_and_preserves_args_env_and_status() {
        let s = Scratch::new();
        let run = ChildRun::start(ENTRY, "ok", s.path());
        let pid = run.pid();
        let status = run.wait();
        assert_eq!(status.code(), Some(42), "{status:?}");
        // Same PID: the child replaced the process.
        let out = s.path().join("out");
        let shell_pid = std::fs::read_to_string(out.with_extension("pid")).unwrap();
        assert_eq!(shell_pid, pid.to_string());
        // Exactly one record, `launching`, written before exec.
        let meta = std::fs::read_to_string(s.path().join("meta")).unwrap();
        assert_eq!(meta, line(&launching_record(&sh().path, pid)));
        assert_eq!(
            classify(&[launching_record(&sh().path, pid)], RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
        // Arguments verbatim (no shell interpreted them), the documented addition.
        let got = std::fs::read(out.with_extension("args")).unwrap();
        let mut expected = Vec::new();
        for a in METACHARACTERS {
            expected.extend_from_slice(a.as_bytes());
            expected.push(0);
        }
        assert_eq!(got, expected);
        assert_eq!(
            std::fs::read_to_string(out.with_extension("env")).unwrap(),
            "added-value"
        );
        assert!(!s.path().join("pwned").exists());
    }

    #[test]
    fn exec_exit_codes_and_signal_death_are_the_childs() {
        let s = Scratch::new();
        for code in [0, 1, 2, 3, 42, 125, 126, 127, 128, 255] {
            let status = ChildRun::start(ENTRY, &format!("code:{code}"), s.path()).wait();
            assert_eq!(status.code(), Some(code), "{status:?}");
        }
        let status = ChildRun::start(ENTRY, "signal", s.path()).wait();
        assert_eq!(status.signal(), Some(15), "{status:?}");
    }

    #[test]
    fn exec_failure_after_launching_writes_prelaunch_failed_exec_error() {
        let s = Scratch::new();
        let run = ChildRun::start(ENTRY, "exec_error", s.path());
        let pid = run.pid();
        let status = run.wait();
        assert_eq!(status.code(), Some(92), "{status:?}");
        let meta = std::fs::read_to_string(s.path().join("meta")).unwrap();
        let missing = s.path().join("missing");
        let records = [
            launching_record(&missing, pid),
            failed_record(127, "exec_error"),
        ];
        assert_eq!(meta, format!("{}{}", line(&records[0]), line(&records[1])));
        assert_eq!(
            classify(&records, RunPlatform::Unix),
            LaunchClassification::NotLaunched {
                code: Some(Code::LaunchFailed),
                reason: Some("exec_error".to_owned())
            }
        );
        assert!(!s.path().join("marker").exists());
    }

    #[test]
    fn refusal_before_launching_names_the_reason_and_never_runs_the_child() {
        let s = Scratch::new();
        let status = ChildRun::start(ENTRY, "refused_argument", s.path()).wait();
        assert_eq!(status.code(), Some(90), "{status:?}");
        let meta = std::fs::read_to_string(s.path().join("meta")).unwrap();
        let refusal = LaunchRefusal::ArgumentUnescapable { index: 5 };
        assert_eq!(meta, line(&failed_record(127, refusal.reason())));
        assert!(!meta.contains("n\\u0000ul") && !meta.contains("ul\""));
        assert!(!s.path().join("marker").exists());
    }

    #[test]
    fn meta_unavailable_aborts_launch_no_child() {
        let s = Scratch::new();
        let status = ChildRun::start(ENTRY, "meta_unavailable", s.path()).wait();
        // Not killed by SIGPIPE; the launch was abandoned before exec.
        assert_eq!(status.signal(), None, "{status:?}");
        assert_eq!(status.code(), Some(91), "{status:?}");
        assert!(!s.path().join("marker").exists());
    }

    #[test]
    fn forced_exec_failure_hook_fails_after_launching() {
        let s = Scratch::new();
        let run = ChildRun::start(ENTRY, "force_failure", s.path());
        let pid = run.pid();
        let status = run.wait();
        assert_eq!(status.code(), Some(92), "{status:?}");
        let meta = std::fs::read_to_string(s.path().join("meta")).unwrap();
        assert_eq!(
            meta,
            format!(
                "{}{}",
                line(&launching_record(&sh().path, pid)),
                line(&failed_record(127, "exec_error"))
            )
        );
        assert!(!s.path().join("marker").exists());
    }

    fn mkfifo(path: &Path) {
        // Through the fork gate, like `ChildRun::start`.
        let status = crate::meta::scratch::spawn(Command::new("mkfifo").arg(path))
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn kill_between_launching_and_exec_is_indeterminate_never_launched() {
        let s = Scratch::new();
        mkfifo(&s.path().join("fifo"));
        let mut run = ChildRun::start(ENTRY, "pause", s.path());
        let pid = run.pid();
        let meta_path = s.path().join("meta");
        let expected = line(&launching_record(&sh().path, pid));
        let deadline = Instant::now() + Duration::from_secs(30);
        while std::fs::read_to_string(&meta_path).unwrap_or_default() != expected {
            assert!(Instant::now() < deadline, "launching never written");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Stopped by its own handle (exact PID) while held after `launching`.
        run.kill();
        let status = run.wait();
        assert_eq!(status.signal(), Some(9), "{status:?}");
        let records = [launching_record(&sh().path, pid)];
        assert_eq!(std::fs::read_to_string(&meta_path).unwrap(), expected);
        assert_eq!(
            classify(&records, RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
        assert!(!s.path().join("marker").exists());
    }

    #[test]
    fn pause_released_then_exec_runs_the_child() {
        let s = Scratch::new();
        let fifo = s.path().join("fifo");
        mkfifo(&fifo);
        let run = ChildRun::start(ENTRY, "pause", s.path());
        let opened = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        drop(opened);
        let status = run.wait();
        assert_eq!(status.code(), Some(0), "{status:?}");
        assert!(s.path().join("marker").exists());
    }

    #[test]
    fn exec_failure_with_failed_meta_write_exits_without_sigpipe_and_is_indeterminate() {
        let s = Scratch::new();
        mkfifo(&s.path().join("fifo"));
        let run = ChildRun::start(ENTRY, "exec_error_reader_closed", s.path());
        let pid = run.pid();
        let status = run.wait();
        // std reset SIGPIPE before the failed execvp; the write after it must still
        // fail with EPIPE instead of killing the process.
        assert_eq!(status.signal(), None, "{status:?}");
        assert_eq!(status.code(), Some(92), "{status:?}");
        let seen = std::fs::read_to_string(s.path().join("seen")).unwrap();
        let launching = launching_record(&s.path().join("missing"), pid);
        assert_eq!(seen, line(&launching));
        assert_eq!(
            classify(&[launching], RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
    }
}
