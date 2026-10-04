//! Signal dispositions and the startup signal mask (Unix; round 2).
//!
//! * [`block_early`] runs as the first statement of `main`: the signals heimdall-proto
//!   handles are blocked until the selected command has installed its handling, then
//!   [`restore_mask`] puts the inherited mask back. A signal that arrives in between
//!   stays pending instead of killing the process by default action (round-1 review:
//!   SIGINT within ~1 ms of start killed `agent list` without a CANCELLED result). The
//!   window between `execve` and `main` (loader and runtime start-up) cannot be closed
//!   by any user-space code.
//! * [`inherited_ignored`] reports whether a signal's disposition is `SIG_IGN`. `run`
//!   leaves such signals alone so `execve` keeps them ignored in the child and they are
//!   not forwarded (contract §9.1 K6a: exec semantics).
//!
//! The query needs `sigaction(sig, NULL, &old)`, which no safe wrapper in the
//! dependency graph exposes. It is the only `unsafe` in the crate. It is a public POSIX
//! call, query-only (the disposition is never changed).

use std::sync::OnceLock;

use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};

/// Signals any command may handle: the `run` forwarding set (contract §4).
pub const HANDLED: [Signal; 5] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGWINCH,
];

static SAVED: OnceLock<SigSet> = OnceLock::new();

/// Block [`HANDLED`] in the calling (main) thread and remember the previous mask.
/// Must run before any thread is spawned, so every later thread inherits the block.
pub fn block_early() {
    let mut set = SigSet::empty();
    for s in HANDLED {
        set.add(s);
    }
    let mut old = SigSet::empty();
    if pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut old)).is_ok() {
        let _ = SAVED.set(old);
    }
}

/// Restore the mask saved by [`block_early`] in the calling thread. Pending signals are
/// delivered now, to whatever handling the command installed (or the default action).
/// Idempotent.
pub fn restore_mask() {
    if let Some(old) = SAVED.get() {
        let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(old), None);
    }
}

/// True if `sig`'s current disposition is `SIG_IGN`. Called before heimdall-proto
/// installs any handler for `sig`, so this is the disposition inherited through
/// `execve` (Rust std itself only changes SIGPIPE before `main`).
#[allow(unsafe_code)]
pub fn inherited_ignored(sig: Signal) -> bool {
    let mut old = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
    // SAFETY: query-only call (`act` is NULL, so nothing is installed); `old` points to
    // writable, properly aligned storage for one `struct sigaction`.
    let rc = unsafe { libc::sigaction(sig as libc::c_int, std::ptr::null(), old.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: sigaction returned 0, so it filled `old`; a zeroed sigaction is also valid.
    let old = unsafe { old.assume_init() };
    old.sa_sigaction == libc::SIG_IGN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_disposition_is_not_ignored() {
        // SIGUSR2 is not touched by shells, nohup, or the test harness. (The ignored
        // case is covered end to end by tests/cli.rs k6a_* through `trap ''`.)
        assert!(!inherited_ignored(Signal::SIGUSR2));
    }
}
