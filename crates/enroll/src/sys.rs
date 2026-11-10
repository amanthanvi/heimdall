//! The enrollment crate's only `unsafe` module (overview §9 item 7; ADR-0008 D5 §6.3,
//! §17.4 item 2, §17.17 item 5; m03-plan U5 `SshStepRunner`): on Linux, a step's `ssh`
//! child receives `SIGKILL` when the thread of the CLI that spawned it dies
//! (`PR_SET_PDEATHSIG`), so a CLI killed by `SIGKILL` cannot leave a step running.
//!
//! It holds exactly one `CommandExt::pre_exec` closure. The closure runs in the forked
//! child before `execve`, where only async-signal-safe calls are allowed; it makes two
//! raw system calls through rustix's safe wrappers and allocates nothing.
//!
//! | Function | Platform | Call | Invariant |
//! |---|---|---|---|
//! | [`kill_with_parent`] | Linux | `CommandExt::pre_exec` with a closure that calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` (rustix `set_parent_process_death_signal(Some(Signal::KILL))`), then `getppid()` | The closure runs in the child between `fork` and `execve`. Both calls are single system calls (async-signal-safe), the closure captures only a `Pid` (`Copy`) and allocates nothing (an error is `io::Error::from_raw_os_error`, no heap). The death signal is tied to the spawning **thread**: `SshStepRunner::run` spawns and then waits on the calling thread until the step has ended and its group is killed, so the thread outlives the child. The `getppid()` check closes the race in which the CLI dies between `fork` and the `prctl`: the child then fails the spawn (`ESRCH`) instead of running unparented. `execve` keeps the death signal (the step's `ssh` is not set-ID) |

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
use std::process::Command;

/// Arrange for `cmd`'s child to receive `SIGKILL` when the calling thread dies
/// (`PR_SET_PDEATHSIG`), and to fail its spawn if the caller is already gone.
///
/// Call it on the thread that spawns and then waits for the child.
#[cfg(target_os = "linux")]
pub(crate) fn kill_with_parent(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    use rustix::process::{Signal, getpid, getppid, set_parent_process_death_signal};

    let parent = getpid();
    // SAFETY: the closure runs in the forked child before `execve` and only makes two
    // async-signal-safe system calls (`prctl`, `getppid`) through rustix; it captures a
    // `Copy` value and never allocates (module table).
    unsafe {
        cmd.pre_exec(move || {
            set_parent_process_death_signal(Some(Signal::KILL)).map_err(std::io::Error::from)?;
            if getppid() != Some(parent) {
                return Err(std::io::Error::from(rustix::io::Errno::SRCH));
            }
            Ok(())
        });
    }
}
