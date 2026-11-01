//! Windows `run`: spawn the child and wait (m02-plan U8; ADR-0007 §8).
//!
//! The child inherits the console and stdio directly (no relaying). While waiting,
//! a console control guard consumes CTRL_C and CTRL_BREAK so the child, sharing the
//! console, handles them. No job object. Writes `launching`, `spawned` and `exited`.
//!
//! Sequence: the pre-flight checks (a refusal writes `prelaunch_failed` with its
//! reason and exit status and returns [`LaunchFailure::Refused`]); the guard; the
//! command; `launching` in full (a failure returns [`LaunchFailure::MetaUnavailable`]:
//! no child); `CreateProcessW` through std (a failure writes `prelaunch_failed`,
//! `LAUNCH_FAILED`, 127, `exec_error`, and returns [`LaunchFailure::ExecError`]);
//! `spawned` with the child's PID; wait; `exited` with the exact 32-bit code. The
//! `spawned` and `exited` writes are best effort: the child runs either way.
//!
//! The guard is tokio's console control handler: while a CTRL_C or CTRL_BREAK
//! listener exists the handler reports the event handled, so the launcher survives
//! and the child, in the same console process group (no
//! `CREATE_NEW_PROCESS_GROUP`), handles the event itself. It needs no runtime. If it
//! cannot be installed the launch proceeds, and a console event may then end the
//! launcher while the child runs (as a forced launcher termination does; disclosed,
//! ADR-0007 §8). A failure of the wait itself (an invalid handle; not expected)
//! returns [`LaunchFailure::ExecError`] without a `prelaunch_failed`: `spawned` is
//! already written and stays the truthful last record.

use std::ffi::OsString;

use heimdall_contract::envelope::reason;

use crate::LaunchFailure;
use crate::env::{EnvDelta, child_command};
use crate::meta::SideChannel;
use crate::resolve::{ResolvedProgram, preflight};

/// The exit status of a launch call that failed after `launching` (`exec_error`).
const EXEC_ERROR_EXIT: i32 = 127;

/// Spawn `program` and wait; the child's exact 32-bit exit code.
///
/// `args` are the arguments after the program (argv[1..]); std builds the command
/// line, with its batch-file escaping for a [`crate::resolve::ProgramKind::Batch`]
/// target.
///
/// # Errors
/// [`LaunchFailure`].
pub fn spawn_and_wait(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    mut meta: Option<SideChannel>,
) -> Result<u32, LaunchFailure> {
    let executable = match preflight(program, args) {
        Ok(executable) => executable,
        Err(refusal) => {
            if let Some(channel) = meta.as_mut() {
                let _ = channel.write_launch_failed(refusal.exit_code(), refusal.reason());
            }
            return Err(LaunchFailure::Refused(refusal));
        }
    };
    let guard = console_guard();
    let mut command = child_command(program, args, delta);
    if let Some(channel) = meta.as_mut()
        && channel
            .write_launching(executable, &delta.overrides)
            .is_err()
    {
        return Err(LaunchFailure::MetaUnavailable);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            if let Some(channel) = meta.as_mut() {
                let _ = channel.write_launch_failed(EXEC_ERROR_EXIT, reason::EXEC_ERROR);
            }
            return Err(LaunchFailure::ExecError);
        }
    };
    if let Some(channel) = meta.as_mut() {
        let _ = channel.write_spawned(child.id());
    }
    let status = child.wait().map_err(|_| LaunchFailure::ExecError)?;
    drop(guard);
    let code = exit_code(status);
    if let Some(channel) = meta.as_mut() {
        let _ = channel.write_exited(code);
    }
    Ok(code)
}

/// The child's exit code as Windows reports it: std's `code()` is the `DWORD`
/// reinterpreted as `i32`, so the reverse reinterpretation is exact (for example
/// `0xC000013A` after CTRL_C stays 3221225786).
pub(crate) fn exit_code(status: std::process::ExitStatus) -> u32 {
    status.code().map_or(1, i32::cast_unsigned)
}

/// The console control guard (module docs). Dropping it removes the listeners.
#[derive(Debug)]
pub(crate) struct ConsoleGuard {
    _ctrl_c: tokio::signal::windows::CtrlC,
    _ctrl_break: tokio::signal::windows::CtrlBreak,
}

/// Install the console control guard, or `None` when the handler cannot be
/// registered.
pub(crate) fn console_guard() -> Option<ConsoleGuard> {
    Some(ConsoleGuard {
        _ctrl_c: tokio::signal::windows::ctrl_c().ok()?,
        _ctrl_break: tokio::signal::windows::ctrl_break().ok()?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::ffi::OsStr;
    use std::os::windows::process::ExitStatusExt as _;
    use std::path::Path;

    use heimdall_localenv::env::{Env, Platform};

    use super::*;
    use crate::meta::scratch::Scratch;
    use crate::resolve::{LaunchRefusal, ProgramKind, Via, resolve_program};

    fn cmd_exe() -> ResolvedProgram {
        let system_root = std::env::var_os("SystemRoot").unwrap();
        let env = Env::from_vars([(
            OsString::from("PATH"),
            Path::new(&system_root).join("System32").into_os_string(),
        )]);
        resolve_program(
            OsStr::new("cmd"),
            &env,
            Path::new("C:\\"),
            Platform::Windows,
        )
        .unwrap()
    }

    #[test]
    fn full_32bit_exit_code_is_preserved() {
        let status = std::process::ExitStatus::from_raw(0xC000_013A);
        assert_eq!(exit_code(status), 3_221_225_786);
        assert_eq!(exit_code(std::process::ExitStatus::from_raw(0)), 0);
        assert_eq!(
            exit_code(std::process::ExitStatus::from_raw(u32::MAX)),
            u32::MAX
        );
    }

    #[test]
    fn spawned_record_follows_launching_and_exited_carries_the_code() {
        let s = Scratch::new();
        let meta = SideChannel::create_exclusive(&s.path().join("meta")).unwrap();
        // 0xC000013A as cmd's signed 32-bit errorlevel.
        let args: Vec<OsString> = ["/d", "/c", "exit -1073741510"]
            .into_iter()
            .map(OsString::from)
            .collect();
        let code = spawn_and_wait(&cmd_exe(), &args, &EnvDelta::default(), Some(meta)).unwrap();
        assert_eq!(code, 3_221_225_786);
        let text = std::fs::read_to_string(s.path().join("meta")).unwrap();
        let types: Vec<&str> = text
            .lines()
            .map(|l| l.split('"').nth(3).unwrap_or(""))
            .collect();
        assert_eq!(types, ["launching", "spawned", "exited"]);
        assert!(text.contains("\"exit_code\":3221225786"));
    }

    #[test]
    fn spawn_failure_after_launching_is_exec_error() {
        let s = Scratch::new();
        let meta = SideChannel::create_exclusive(&s.path().join("meta")).unwrap();
        let missing = ResolvedProgram {
            path: s.path().join("missing.exe"),
            kind: ProgramKind::Native,
            via: Via::Explicit,
        };
        let err = spawn_and_wait(&missing, &[], &EnvDelta::default(), Some(meta)).unwrap_err();
        assert_eq!(err, LaunchFailure::ExecError);
        let text = std::fs::read_to_string(s.path().join("meta")).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("\"reason\":\"exec_error\""));
    }

    #[test]
    fn batch_argument_with_line_break_refused_before_launching() {
        let s = Scratch::new();
        let script = s.path().join("t.cmd");
        std::fs::write(&script, "@exit /b 0\r\n").unwrap();
        let program = ResolvedProgram {
            path: script,
            kind: ProgramKind::Batch,
            via: Via::Explicit,
        };
        let meta = SideChannel::create_exclusive(&s.path().join("meta")).unwrap();
        let args = vec![OsString::from("ok"), OsString::from("a\nb")];
        let err = spawn_and_wait(&program, &args, &EnvDelta::default(), Some(meta)).unwrap_err();
        assert_eq!(
            err,
            LaunchFailure::Refused(LaunchRefusal::ArgumentUnescapable { index: 2 })
        );
        let text = std::fs::read_to_string(s.path().join("meta")).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"reason\":\"refused_argument\""));
    }
}
