//! The TUI's foreground handoff, `system(3)` model (m02-plan U8, U10; ADR-0007 §8).
//!
//! Restore cooked mode and leave the alternate screen; keep the child in the TUI's
//! process group; keep SIGINT and SIGQUIT handlers registered while waiting; leave
//! SIGTSTP at its default; wait; re-enter. Windows uses the console control guard.

use std::ffi::OsString;

use crate::LaunchFailure;
use crate::env::EnvDelta;
use crate::resolve::ResolvedProgram;

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
/// # Errors
/// [`LaunchFailure`].
pub fn run_foreground(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
) -> Result<ChildOutcome, LaunchFailure> {
    let _ = (program, args, delta);
    todo!("M02-U8 handoff::run_foreground")
}
