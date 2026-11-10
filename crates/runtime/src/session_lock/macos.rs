//! The macOS session-lock source (ADR-0008 D9 item 3): a dedicated thread reading
//! `CGSessionCopyCurrentDictionary` (`CGSSessionScreenIsLocked`, `kCGSessionOnConsoleKey`)
//! every [`MACOS_POLL_INTERVAL`]. FFI in `sys.rs`.
//!
//! **Why polling, not the distributed notifications** (questions file U9-Q4). ADR-0008
//! D9 item 3 names `com.apple.screenIsLocked` / `com.apple.screenIsUnlocked` on a
//! dedicated run-loop thread. Observed on this host (macOS 27.2, arm64; a throwaway
//! `swiftc` probe with `dev.heimdall.test.*` names, never a system name):
//! `CFNotificationCenterGetDistributedCenter` delivers its callbacks **only on the main
//! thread's run loop**. An observer registered on a background thread whose own run loop
//! ran in the default mode received nothing, whether the center was first touched there
//! or not and whether the post came from the same process or another one; the same
//! cross-process post was delivered, on the main thread, while the main thread ran its
//! run loop. The runtime's main thread is tokio's and never runs a CF run loop, so that
//! observer could never fire. The dedicated thread therefore polls the session
//! dictionary, which is the ADR's own query and needs no run loop.
//!
//! The reading: no dictionary (no GUI session for this process) is `unavailable` at
//! start (the thread then ends) and `unknown` later; `CGSSessionScreenIsLocked` true, or
//! the session off the console (fast user switching), is `locked`; otherwise `unlocked`.
//! A lock is seen within one poll interval (the native row
//! `macos_lock_signal_observed` records the latency); an unlock needs authentication,
//! which takes far longer than the interval, so a lock is not missed between two polls,
//! and the latch keeps it until the pass acknowledges it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::sys::{self, CgSession};
use super::{LockSignal, LockState, STOP_SLICE, Shared, SourceOptions};

/// This platform's signal.
pub(super) const SIGNAL: LockSignal = LockSignal::MacosScreenLock;

/// How often the thread reads the session dictionary (the macOS signal itself).
pub const MACOS_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The source thread's name.
const THREAD_NAME: &str = "heimdall-session-lock";

/// One reading of the session dictionary (`None`: no session).
fn reading() -> Option<LockState> {
    match sys::cg_session() {
        CgSession::None => None,
        CgSession::Present { locked, on_console } => Some(if locked || !on_console {
            LockState::Locked
        } else {
            LockState::Unlocked
        }),
    }
}

/// Spawn the polling thread. `options.poll_interval` replaces
/// [`MACOS_POLL_INTERVAL`] only when it is shorter (tests).
pub(super) fn spawn(
    shared: Arc<Shared>,
    options: &SourceOptions,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let every = options.poll_interval.min(MACOS_POLL_INTERVAL);
    std::thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || run(&shared, every))
}

/// Nothing to wake: the thread sleeps in [`STOP_SLICE`] slices at most and checks the
/// stop flag between them.
pub(super) fn wake(_shared: &Shared) {}

fn run(shared: &Arc<Shared>, every: Duration) {
    shared.bind_thread();
    let Some(first) = reading() else {
        shared.record(LockState::Unavailable);
        return;
    };
    shared.record(first);
    let slice = every.min(STOP_SLICE);
    let mut last = Instant::now();
    while !shared.stopping() {
        std::thread::sleep(slice);
        if last.elapsed() >= every {
            last = Instant::now();
            shared.event_delivered();
            shared.record(reading().unwrap_or(LockState::Unknown));
        }
    }
}
