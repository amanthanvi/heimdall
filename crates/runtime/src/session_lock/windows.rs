//! The Windows session-lock source (ADR-0008 D9 item 3): a hidden message-only window
//! on its own thread, registered with `WTSRegisterSessionNotification` for this
//! session, with `WTSQuerySessionInformationW(WTSSessionInfoEx)` for the initial state,
//! for every other session change (re-read) and for the backstop tick. FFI in `sys.rs`.
//!
//! `WTS_SESSION_LOCK` records `locked` directly; `WTS_SESSION_UNLOCK` and every other
//! session change re-read the session flags (a failed read is `unknown`). A window or
//! registration that cannot be created reads `unavailable`.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use windows_sys::Win32::UI::WindowsAndMessaging::WTS_SESSION_LOCK;

use super::sys;
use super::{LockSignal, LockState, Shared, SourceOptions};

/// This platform's signal.
pub(super) const SIGNAL: LockSignal = LockSignal::WindowsSession;

/// The source thread's name.
const THREAD_NAME: &str = "heimdall-session-lock";

thread_local! {
    /// The source the window procedure records into (set on the window thread only).
    static SHARED: RefCell<Option<Arc<Shared>>> = const { RefCell::new(None) };
}

fn with_shared(f: impl FnOnce(&Shared)) {
    let shared = SHARED
        .try_with(|c| c.try_borrow().ok().and_then(|s| s.clone()))
        .ok()
        .flatten();
    if let Some(s) = shared {
        f(&s);
    }
}

fn state_of(locked: Option<bool>) -> LockState {
    match locked {
        Some(true) => LockState::Locked,
        Some(false) => LockState::Unlocked,
        None => LockState::Unknown,
    }
}

/// `WM_WTSSESSION_CHANGE` (called by the window procedure, on the window thread).
pub(super) fn on_session_change(code: u32) {
    with_shared(|s| {
        s.event_delivered();
        if code == WTS_SESSION_LOCK {
            s.record(LockState::Locked);
        } else {
            s.record(state_of(sys::session_locked()));
        }
    });
}

/// `WM_TIMER`: the backstop re-query (definite readings only).
pub(super) fn on_tick() {
    with_shared(|s| {
        s.record_definite(sys::session_locked().map(|l| state_of(Some(l))));
    });
}

/// Spawn the window thread.
pub(super) fn spawn(
    shared: Arc<Shared>,
    options: &SourceOptions,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let tick_ms = u32::try_from(options.poll_interval.as_millis())
        .unwrap_or(u32::MAX)
        .max(100);
    std::thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || run(&shared, tick_ms))
}

/// Post `WM_QUIT` to the window thread (retried briefly; the tick bounds the stop
/// anyway, because the pump checks the stop flag after every message).
pub(super) fn wake(shared: &Shared) {
    for _ in 0..50 {
        let tid = shared.thread_id.load(Ordering::SeqCst);
        if tid != 0 && sys::post_quit(tid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run(shared: &Arc<Shared>, tick_ms: u32) {
    shared.bind_thread();
    let window = match sys::MessageWindow::create(tick_ms) {
        Ok(w) => w,
        Err(code) => {
            tracing::warn!(
                code,
                "the session-lock window could not be registered; unavailable"
            );
            shared.record(LockState::Unavailable);
            return;
        }
    };
    let _ = SHARED.try_with(|c| {
        if let Ok(mut slot) = c.try_borrow_mut() {
            *slot = Some(Arc::clone(shared));
        }
    });
    // The queue exists (the window was created), so `WM_QUIT` can be posted now.
    shared
        .thread_id
        .store(sys::current_thread_id(), Ordering::SeqCst);
    shared.record(state_of(sys::session_locked()));
    if !sys::pump(&shared.stop) {
        tracing::warn!("the session-lock message loop failed; unknown");
        shared.record(LockState::Unknown);
    }
    let _ = SHARED.try_with(|c| {
        if let Ok(mut slot) = c.try_borrow_mut() {
            *slot = None;
        }
    });
    drop(window);
}
