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
//!
//! ⟨M03⟩ **The one exception to "no job object"** (ADR-0008 D8 item 2; §17.3 item 1,
//! Q18): a managed launch whose program is the verified `ssh`
//! ([`launch_uses_kill_on_close_job`]) goes through [`spawn_contained_and_wait`]: the
//! child is created suspended in a kill-on-close job without breakaway, registered
//! while suspended through the caller's registrar, and resumed only after a successful
//! registration. The disclosed residual: ssh's own `ProxyCommand` or `LocalCommand`
//! helpers end with it. Every other `run` keeps [`spawn_and_wait`].

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

// --- ⟨M03⟩ the contained launch of the verified ssh (ADR-0008 D8 item 2; §17.3 item 1,
// §17.4 item 8; m03-plan U7) -----------------------------------------------------------

/// Q18 as ruled (§17.3 item 1): a launch gets the kill-on-close job **only** when it is
/// the launch of a managed binding (a binding with a `managed_certificate` pair) whose
/// program is the verified `ssh` client. `run` of any other program keeps M02's
/// semantics: no job object (ADR-0007 §8), `existing_connections: not_controlled`.
#[must_use]
pub fn launch_uses_kill_on_close_job(managed_binding: bool, program_is_verified_ssh: bool) -> bool {
    managed_binding && program_is_verified_ssh
}

/// The answer to a registration while the child is suspended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// Registered: the child may run.
    Registered,
    /// Refused by the runtime for the grant (`connection_registration_refused`).
    Refused,
    /// Any other failure (`connection_registration_failed`), including a runtime that
    /// does not accept the request yet.
    Failed,
}

/// Why a contained launch did not run its child to completion.
#[derive(Debug)]
pub enum ContainedFailure {
    /// The launch itself (pre-flight, record, `CreateProcessW`), as
    /// [`spawn_and_wait`]; the record is already written.
    Launch(LaunchFailure),
    /// The registration (or the resume after it) failed: the job was closed, so the
    /// still-suspended child died without running. `launching` was written; the caller
    /// writes `prelaunch_failed` with [`ContainedFailure::reason`] on the returned side
    /// channel.
    Registration {
        /// The runtime refused the grant (else: any other failure).
        refused: bool,
        /// The side channel, for the `prelaunch_failed` record.
        meta: Option<SideChannel>,
    },
}

impl ContainedFailure {
    /// The `LAUNCH_FAILED` reason of a registration failure (m03-plan §5 item 14).
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            ContainedFailure::Launch(_) => None,
            ContainedFailure::Registration { refused: true, .. } => {
                Some(reason::CONNECTION_REGISTRATION_REFUSED)
            }
            ContainedFailure::Registration { refused: false, .. } => {
                Some(reason::CONNECTION_REGISTRATION_FAILED)
            }
        }
    }
}

/// The contained launch (ADR-0008 D8 item 2, Windows): as [`spawn_and_wait`], except
/// that the child is created **suspended** in a kill-on-close job without breakaway
/// (`heimdall_localenv::sys::JobObject::spawn_suspended`), `register` is called with its
/// PID, creation time and image **while it is still suspended**, and it is resumed only
/// after [`Registration::Registered`]. Any other answer, or a failed resume, closes the
/// job (the child dies never having run) and returns [`ContainedFailure::Registration`].
/// The job stays open until the child has exited, so the launcher's death ends the
/// client (and any child it started) too.
///
/// # Errors
/// [`ContainedFailure`].
pub fn spawn_contained_and_wait(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    mut meta: Option<SideChannel>,
    register: &mut dyn FnMut(u32, heimdall_contract::Timestamp, &std::path::Path) -> Registration,
) -> Result<u32, ContainedFailure> {
    let executable = match preflight(program, args) {
        Ok(executable) => executable,
        Err(refusal) => {
            if let Some(channel) = meta.as_mut() {
                let _ = channel.write_launch_failed(refusal.exit_code(), refusal.reason());
            }
            return Err(ContainedFailure::Launch(LaunchFailure::Refused(refusal)));
        }
    };
    let guard = console_guard();
    let command = child_command(program, args, delta);
    if let Some(channel) = meta.as_mut()
        && channel
            .write_launching(executable, &delta.overrides)
            .is_err()
    {
        return Err(ContainedFailure::Launch(LaunchFailure::MetaUnavailable));
    }
    let suspended = match heimdall_localenv::sys::JobObject::spawn_suspended(command) {
        Ok(s) => s,
        Err(_) => {
            if let Some(channel) = meta.as_mut() {
                let _ = channel.write_launch_failed(EXEC_ERROR_EXIT, reason::EXEC_ERROR);
            }
            return Err(ContainedFailure::Launch(LaunchFailure::ExecError));
        }
    };
    let answer = register(suspended.pid, suspended.created_at, &program.path);
    if answer != Registration::Registered {
        suspended.close();
        return Err(ContainedFailure::Registration {
            refused: answer == Registration::Refused,
            meta,
        });
    }
    let pid = suspended.pid;
    let Ok(mut contained) = suspended.resume() else {
        return Err(ContainedFailure::Registration {
            refused: false,
            meta,
        });
    };
    if let Some(channel) = meta.as_mut() {
        let _ = channel.write_spawned(pid);
    }
    let status = contained
        .child
        .wait()
        .map_err(|_| ContainedFailure::Launch(LaunchFailure::ExecError))?;
    drop(guard);
    // The job closes only now, after the client has exited (anything it left behind
    // in the job ends with it: the disclosed Q18 residual).
    drop(contained);
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
