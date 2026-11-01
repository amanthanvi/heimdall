//! Unix `run`: Heimdall replaces itself with the child (m02-plan U8; ADR-0007 §8).
//!
//! Writes `launching` before `execve` (through `CommandExt::exec`), and
//! `prelaunch_failed` (best effort) after an exec failure. The process becomes the
//! child, so exit status, signals, job control, terminal ownership and stdio are
//! exactly the platform's.

use std::ffi::OsString;

use crate::LaunchFailure;
use crate::env::EnvDelta;
use crate::meta::SideChannel;
use crate::resolve::ResolvedProgram;

/// Exec `program` with `args` and `delta`. Returns only on failure.
#[must_use]
pub fn exec_replace(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
) -> LaunchFailure {
    let _ = (program, args, delta, meta);
    todo!("M02-U8 unix::exec_replace")
}
