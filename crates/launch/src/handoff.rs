//! The TUI's foreground handoff, `system(3)` model (m02-plan U8, U10; ADR-0007 §8).
//!
//! Restore cooked mode and leave the alternate screen; keep the child in the TUI's
//! process group; keep SIGINT and SIGQUIT handlers registered while waiting; leave
//! SIGTSTP at its default; wait; re-enter. Windows uses the console control guard.
//!
//! Division of work: the terminal steps (cooked mode and the alternate screen
//! before, re-entering after) belong to the TUI, which owns the terminal and its
//! library; [`run_foreground`] does the process steps between them:
//!
//! * the child is spawned in the caller's process group (no `setpgid`), with the
//!   caller's terminal, stdio, working directory and environment plus the delta;
//! * Unix: SIGINT and SIGQUIT get handlers (tokio's) before the spawn. A Ctrl-C at
//!   the terminal reaches the whole foreground group: the child takes its default
//!   action, because handlers do not survive `execve` (unlike `SIG_IGN`, which
//!   would), and the TUI survives. tokio keeps a handler for the life of the
//!   process, which suits a TUI that reads keys in raw mode. SIGTSTP is not
//!   touched, so the shell stops and continues the TUI and the child as one job,
//!   and the wait (which does not report stops) simply continues;
//! * Windows: the console control guard of [`crate::windows`] for the duration of
//!   the wait.
//!
//! No run record is written (the TUI has no side channel). If the handlers cannot
//! be installed the child still runs, and a Ctrl-C may then end the TUI too.

use std::ffi::OsString;

use crate::LaunchFailure;
use crate::env::{EnvDelta, child_command};
use crate::resolve::{ResolvedProgram, preflight};

/// How a foreground child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildOutcome {
    /// Exited with this status.
    Exited(i64),
    /// Killed by this signal (Unix).
    Signaled(i32),
}

/// Run `program` in the foreground and wait.
///
/// `args` are the arguments after the program (argv[1..]).
///
/// # Errors
/// [`LaunchFailure::Refused`] from the pre-flight checks; [`LaunchFailure::ExecError`]
/// when the spawn or the wait fails.
pub fn run_foreground(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
) -> Result<ChildOutcome, LaunchFailure> {
    preflight(program, args).map_err(LaunchFailure::Refused)?;
    let mut command = child_command(program, args, delta);
    #[cfg(unix)]
    let _ = crate::unix::keep_signals_handled(&[
        tokio::signal::unix::SignalKind::interrupt(),
        tokio::signal::unix::SignalKind::quit(),
    ]);
    #[cfg(windows)]
    let guard = crate::windows::console_guard();
    let mut child = command.spawn().map_err(|_| LaunchFailure::ExecError)?;
    let status = child.wait().map_err(|_| LaunchFailure::ExecError)?;
    #[cfg(windows)]
    drop(guard);
    Ok(outcome(status))
}

/// A wait status as an outcome. `wait` reports only exits and (Unix) deaths by
/// signal; the `Exited(-1)` fallback is unreachable.
fn outcome(status: std::process::ExitStatus) -> ChildOutcome {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return ChildOutcome::Signaled(signal);
        }
        status.code().map_or(ChildOutcome::Exited(-1), |c| {
            ChildOutcome::Exited(i64::from(c))
        })
    }
    #[cfg(windows)]
    {
        ChildOutcome::Exited(i64::from(crate::windows::exit_code(status)))
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::meta::scratch::Scratch;
    use crate::unix::tests::{ChildRun, args, scenario, sh};

    const ENTRY: &str = "handoff::tests::handoff_child";

    /// Entry point of the re-executed test binary; writes the outcome to `outcome`.
    #[test]
    #[ignore = "child-mode entry of the handoff tests, started by them"]
    fn handoff_child() {
        let Some((scenario, dir)) = scenario() else {
            return;
        };
        let out = dir.join("out").into_os_string().into_string().unwrap();
        let script = match scenario.as_str() {
            "exit" => "exit 5",
            "signal" => "kill -TERM $$",
            // Both signals at the caller, which must survive them.
            "interrupt_caller" => "kill -INT $PPID; kill -QUIT $PPID; exit 3",
            // The child itself still dies of SIGINT: its disposition is the default.
            "interrupt_child" => "kill -INT $$; exit 7",
            "env" => {
                "printf '%s' \"$HM_U8_ADDED\" > \"$1\"; \
                      ps -o pgid= -p $$ > \"$1.child\"; ps -o pgid= -p $PPID > \"$1.parent\""
            }
            other => panic!("unknown scenario {other}"),
        };
        let delta = EnvDelta {
            set: vec![(OsString::from("HM_U8_ADDED"), OsString::from("handoff"))],
            overrides: Vec::new(),
        };
        let outcome = run_foreground(&sh(), &args(&["-c", script, "sh", &out]), &delta).unwrap();
        std::fs::write(dir.join("outcome"), format!("{outcome:?}")).unwrap();
        std::process::exit(0);
    }

    fn run(scenario: &str, dir: &Path) -> String {
        let status = ChildRun::start(ENTRY, scenario, dir).wait();
        assert_eq!(status.code(), Some(0), "{scenario}: {status:?}");
        std::fs::read_to_string(dir.join("outcome")).unwrap()
    }

    #[test]
    fn foreground_child_status_and_signal_death_are_reported() {
        let s = Scratch::new();
        assert_eq!(run("exit", s.path()), "Exited(5)");
        assert_eq!(run("signal", s.path()), "Signaled(15)");
    }

    #[test]
    fn caller_survives_sigint_and_sigquit_while_the_child_gets_the_default() {
        let s = Scratch::new();
        assert_eq!(run("interrupt_caller", s.path()), "Exited(3)");
        assert_eq!(run("interrupt_child", s.path()), "Signaled(2)");
    }

    #[test]
    fn child_shares_the_callers_process_group_and_gets_the_delta() {
        let s = Scratch::new();
        assert_eq!(run("env", s.path()), "Exited(0)");
        let out = s.path().join("out");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "handoff");
        let child = std::fs::read_to_string(out.with_extension("child")).unwrap();
        let parent = std::fs::read_to_string(out.with_extension("parent")).unwrap();
        assert!(!child.trim().is_empty());
        assert_eq!(child.trim(), parent.trim());
    }

    #[test]
    fn refused_arguments_never_spawn() {
        let mut a = args(&["-c", "exit 0"]);
        a.push(OsString::from("x\0y"));
        assert_eq!(
            run_foreground(&sh(), &a, &EnvDelta::default()),
            Err(LaunchFailure::Refused(
                crate::resolve::LaunchRefusal::ArgumentUnescapable { index: 3 }
            ))
        );
    }
}
