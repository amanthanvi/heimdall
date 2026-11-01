//! Windows `run`: spawn the child and wait (m02-plan U8; ADR-0007 §8).
//!
//! The child inherits the console and stdio directly (no relaying). While waiting,
//! a console control guard consumes CTRL_C and CTRL_BREAK so the child, sharing the
//! console, handles them. No job object. Writes `launching`, `spawned` and `exited`.

use std::ffi::OsString;

use crate::LaunchFailure;
use crate::env::EnvDelta;
use crate::meta::SideChannel;
use crate::resolve::ResolvedProgram;

/// Spawn `program` and wait; the child's exact 32-bit exit code.
///
/// # Errors
/// [`LaunchFailure`].
pub fn spawn_and_wait(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
) -> Result<u32, LaunchFailure> {
    let _ = (program, args, delta, meta);
    todo!("M02-U8 windows::spawn_and_wait")
}
