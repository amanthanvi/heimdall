//! The session-lock sources (ADR-0008 D9 item 3; §17.1 item 9, §17.4 item 9; m03-plan
//! U9): one `app::ports::SessionLockSource` per platform, behind
//! [`PlatformSessionLockSource`].
//!
//! | Platform | Initial state | Events | Thread |
//! |---|---|---|---|
//! | macOS | `CGSessionCopyCurrentDictionary` (`CGSSessionScreenIsLocked`, `kCGSessionOnConsoleKey`) | the same query, every [`MACOS_POLL_INTERVAL`] (the distributed `com.apple.screenIsLocked` notifications reach only a main-thread run loop, which the runtime has not; `macos.rs`, questions file U9-Q4) | a dedicated polling thread |
//! | Windows | `WTSQuerySessionInformationW(WTSSessionInfoEx)` for the current session | `WTSRegisterSessionNotification` (`WTS_SESSION_LOCK` / `WTS_SESSION_UNLOCK`) | a hidden message-only window thread |
//! | Linux desktop | logind `LockedHint` of the caller's graphical session (system bus) | the session's `Lock` / `Unlock` signals and `PropertiesChanged(LockedHint)` | a dedicated thread running a current-thread tokio runtime for `zbus` |
//! | Linux headless, WSL, containers, other systems | — | — | none: `unavailable` |
//!
//! **The port, exactly** (m03-plan §5 item 19): [`SessionLockSource::state`] is the
//! current state; [`SessionLockSource::lock_epoch`] is the latched epoch, which moves on
//! every transition into `locked` and keeps `observed` set until
//! [`SessionLockSource::acknowledge`] clears it for that epoch only;
//! [`SessionLockSource::changed`] is a wake-up that carries no value. All four are
//! in-memory reads and never block. So a lock followed by an unlock before the consumer
//! looks still revokes (`lock_then_unlock_while_consumer_paused_still_revokes`).
//!
//! **Fail closed.**
//! * `unknown` counts as a lock ([`heimdall_app::lock::UNKNOWN_IS_LOCK`]; ADR-0008 D9
//!   item 3: "whenever the source reports `unknown`, every `revoke_on_lock` grant is
//!   treated as locked"): a transition into `unknown` latches the epoch as a transition
//!   into `locked` does, and so does an initial reading of `locked` or `unknown` ("at
//!   start"). An initial `unlocked` or `unavailable` latches nothing.
//! * A platform query that fails at an event reads `unknown`. On Windows and Linux the
//!   periodic backstop re-query ([`POLL_INTERVAL`]) only applies a definite reading
//!   (`locked` or `unlocked`); it catches a transition whose event was lost. On macOS the
//!   poll is the signal itself, and a failed read is `unknown`.
//! * A source whose first reading does not arrive within [`INITIAL_STATE_WAIT`] reads
//!   `unknown` (latched). A platform with no signal, or a session without one, reads
//!   `unavailable`, and `revoke_on_lock` is refused there (`lock_signal_unavailable`,
//!   `app::operations` row 11).
//!
//! **Threads.** Each source spawns its one platform thread once, in
//! [`PlatformSessionLockSource::start`], and joins it in
//! [`PlatformSessionLockSource::shutdown`] (also on drop). The thread only records
//! readings into this module's latch and wakes [`SessionLockSource::changed`]; it never
//! calls into the store or the application. The lock pass itself is
//! `heimdall_app::lock::run_lock_passes` (U10 runs it from the supervisor).
//!
//! **FFI** lives only in `sys.rs` (macOS and Windows, with its invariant table). Linux
//! uses `zbus` and needs none.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

pub use heimdall_app::lock::LockSignal;
pub use heimdall_app::ports::{LockState, SessionLockSource};
use heimdall_contract::managed::LockBehavior;
use heimdall_domain::managed::LockEpoch;
use tokio::sync::Notify;

use crate::config::{self, SessionConfig};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", windows))]
mod sys;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use self::linux as platform;
#[cfg(target_os = "macos")]
use self::macos as platform;
#[cfg(windows)]
use self::windows as platform;

/// How long [`PlatformSessionLockSource::start`] waits for the platform thread's first
/// reading before it records `unknown` (latched, fail closed).
pub const INITIAL_STATE_WAIT: Duration = Duration::from_secs(3);

/// The interval of the backstop re-query on the platform thread (definite readings
/// only).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The longest a platform thread takes to notice [`PlatformSessionLockSource::shutdown`]
/// when it cannot be woken directly (the macOS polling slice).
pub const STOP_SLICE: Duration = Duration::from_millis(250);

#[cfg(target_os = "macos")]
pub use self::macos::MACOS_POLL_INTERVAL;

/// The ADR-0008 §17.15 item 12 (R3) floor from the M01 `[session] lock_behavior` key:
/// `revoke` is the floor `revoke_on_lock`, merged fail closed into every grant's
/// effective behaviour (`Operations::set_session_lock_floor`); `continue` adds nothing.
#[must_use]
pub fn lock_floor(session: &SessionConfig) -> LockBehavior {
    match session.lock_behavior {
        config::LockBehavior::Continue => LockBehavior::Continue,
        config::LockBehavior::Revoke => LockBehavior::RevokeOnLock,
    }
}

/// Options of a source (tests only; production uses [`SourceOptions::default`]).
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct SourceOptions {
    /// How long `start` waits for the first reading.
    pub initial_wait: Duration,
    /// The backstop re-query interval (on macOS, the poll interval when shorter than
    /// `MACOS_POLL_INTERVAL`).
    pub poll_interval: Duration,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            initial_wait: INITIAL_STATE_WAIT,
            poll_interval: POLL_INTERVAL,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Latch {
    state: LockState,
    epoch: LockEpoch,
    initialized: bool,
    transitions: u64,
    last_change: Option<Instant>,
    /// Readings that entered `locked` itself (never `unknown`): the native evidence
    /// rows' proof of a real lock (wave-1 review W1-R03). Latched: an unlock after it
    /// does not lower it.
    locked_entries: u64,
    /// When the last of those arrived.
    last_locked: Option<Instant>,
    /// Readings that entered `unknown` (they advance the epoch, fail closed, but are
    /// never evidence of a lock).
    unknown_entries: u64,
}

impl Latch {
    /// Count an entry into `next` for the evidence counters.
    fn count_entry(&mut self, next: LockState) {
        match next {
            LockState::Locked => {
                self.locked_entries = self.locked_entries.saturating_add(1);
                self.last_locked = Some(Instant::now());
            }
            LockState::Unknown => self.unknown_entries = self.unknown_entries.saturating_add(1),
            _ => {}
        }
    }
}

/// The state a platform thread records into, read by the port (in memory only).
#[derive(Debug)]
pub(crate) struct Shared {
    latch: Mutex<Latch>,
    notify: Notify,
    ready: Condvar,
    stop: AtomicBool,
    /// Wakes an async platform worker at shutdown (Linux).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    stop_wake: Notify,
    /// The Windows window thread's ID, for its `WM_QUIT` at shutdown (0 until known).
    #[cfg(windows)]
    pub(crate) thread_id: std::sync::atomic::AtomicU32,
    /// The platform thread (set once when it starts).
    thread: OnceLock<ThreadId>,
    /// Platform events delivered (notifications, window messages, signals).
    events: AtomicU64,
    /// Of those, delivered on a thread other than the platform thread.
    events_off_thread: AtomicU64,
}

/// Whether entering `s` counts as a lock (fail closed: `unknown` does).
fn counts_as_lock(s: LockState) -> bool {
    s == LockState::Locked || (heimdall_app::lock::UNKNOWN_IS_LOCK && s == LockState::Unknown)
}

impl Shared {
    fn new() -> Self {
        Self {
            latch: Mutex::new(Latch {
                state: LockState::Unknown,
                epoch: LockEpoch::default(),
                initialized: false,
                transitions: 0,
                last_change: None,
                locked_entries: 0,
                last_locked: None,
                unknown_entries: 0,
            }),
            notify: Notify::new(),
            ready: Condvar::new(),
            stop: AtomicBool::new(false),
            stop_wake: Notify::new(),
            #[cfg(windows)]
            thread_id: std::sync::atomic::AtomicU32::new(0),
            thread: OnceLock::new(),
            events: AtomicU64::new(0),
            events_off_thread: AtomicU64::new(0),
        }
    }

    /// Called first on the platform thread.
    #[cfg_attr(
        not(any(target_os = "macos", windows, target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn bind_thread(&self) {
        let _ = self.thread.set(std::thread::current().id());
    }

    /// Count one platform event (and whether it arrived off the platform thread).
    #[cfg_attr(
        not(any(target_os = "macos", windows, target_os = "linux")),
        allow(dead_code)
    )]
    pub(crate) fn event_delivered(&self) {
        self.events.fetch_add(1, Ordering::SeqCst);
        if self.thread.get() != Some(&std::thread::current().id()) {
            self.events_off_thread.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn latch(&self) -> std::sync::MutexGuard<'_, Latch> {
        self.latch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a reading. The first reading initializes the source (an initial `locked`
    /// or `unknown` latches the epoch); later readings latch on every transition into a
    /// state that counts as a lock. A reading equal to the current state changes
    /// nothing and wakes nobody.
    pub(crate) fn record(&self, next: LockState) {
        let woke = {
            let mut l = self.latch();
            if l.initialized {
                if l.state == next {
                    false
                } else {
                    if counts_as_lock(next) {
                        l.epoch = l.epoch.observe_lock();
                    }
                    l.count_entry(next);
                    l.state = next;
                    l.transitions = l.transitions.saturating_add(1);
                    l.last_change = Some(Instant::now());
                    true
                }
            } else {
                l.initialized = true;
                if counts_as_lock(next) {
                    l.epoch = l.epoch.observe_lock();
                }
                l.count_entry(next);
                l.state = next;
                l.last_change = Some(Instant::now());
                true
            }
        };
        self.ready.notify_all();
        if woke {
            // Wake every current waiter and leave one permit, so a waiter created just
            // after this call is not missed (a spurious wake-up is harmless).
            self.notify.notify_waiters();
            self.notify.notify_one();
        }
    }

    /// Record a definite reading only (the backstop re-query; Windows, Linux).
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    pub(crate) fn record_definite(&self, reading: Option<LockState>) {
        if let Some(s @ (LockState::Locked | LockState::Unlocked)) = reading {
            self.record(s);
        }
    }

    pub(crate) fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Resolves once shutdown was requested (Linux worker).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) async fn stopped(&self) {
        loop {
            let n = self.stop_wake.notified();
            if self.stopping() {
                return;
            }
            n.await;
        }
    }

    /// Wait (blocking, bounded) until the first reading arrived.
    fn wait_initialized(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut l = self.latch();
        while !l.initialized {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            l = self
                .ready
                .wait_timeout(l, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// The platform session-lock source (module docs).
#[derive(Debug)]
pub struct PlatformSessionLockSource {
    shared: Arc<Shared>,
    signal: LockSignal,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// A diagnostic snapshot of a source (nonsecret; for the native evidence records and
/// `heimdall internal session-lock-state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceSnapshot {
    /// The current state.
    pub state: LockState,
    /// The latched epoch.
    pub epoch: LockEpoch,
    /// Transitions recorded after the first reading.
    pub transitions: u64,
    /// When the state last changed (the first reading included).
    pub last_change: Option<Instant>,
    /// The platform signal.
    pub signal: LockSignal,
    /// Platform events delivered so far.
    pub events: u64,
    /// Of those, delivered on a thread other than the source's own (expected 0).
    pub events_off_thread: u64,
    /// Readings that entered `locked` itself, latched (an unlock does not lower it).
    /// The only evidence of a real lock: entering `unknown` advances the epoch (fail
    /// closed) but never this count (wave-1 review W1-R03).
    pub locked_entries: u64,
    /// When the last `locked` reading arrived.
    pub last_locked: Option<Instant>,
    /// Readings that entered `unknown`.
    pub unknown_entries: u64,
}

impl SourceSnapshot {
    /// Whether a real `locked` reading arrived after `earlier` was taken (W1-R03): the
    /// native lock rows' evidence. An epoch advanced only by `unknown` (a lost signal,
    /// an unreadable session) never satisfies it; a lock followed by an unlock still
    /// does (latched).
    #[must_use]
    pub fn locked_since(&self, earlier: &SourceSnapshot) -> bool {
        self.locked_entries > earlier.locked_entries
    }
}

impl PlatformSessionLockSource {
    /// Start this platform's source: spawn its one thread and wait (blocking, at most
    /// [`INITIAL_STATE_WAIT`]) for the first reading. Never panics: a thread that cannot
    /// be spawned reads `unavailable` on a platform without a signal and `unknown`
    /// otherwise. Call it from a blocking context (it may wait).
    #[must_use]
    pub fn start() -> Arc<Self> {
        Self::start_with(&SourceOptions::default())
    }

    /// [`Self::start`] with explicit options (tests).
    #[doc(hidden)]
    #[must_use]
    pub fn start_with(options: &SourceOptions) -> Arc<Self> {
        let shared = Arc::new(Shared::new());
        #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
        {
            let worker = match platform::spawn(Arc::clone(&shared), options) {
                Ok(handle) => Some(handle),
                Err(e) => {
                    tracing::warn!(error = %e, "session-lock thread could not start");
                    shared.record(LockState::Unknown);
                    None
                }
            };
            if !shared.wait_initialized(options.initial_wait) {
                tracing::warn!("session-lock source gave no first reading in time; unknown");
                shared.record(LockState::Unknown);
            }
            Arc::new(Self {
                shared,
                signal: platform::SIGNAL,
                worker: Mutex::new(worker),
            })
        }
        #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
        {
            let _ = options;
            shared.record(LockState::Unavailable);
            Arc::new(Self {
                shared,
                signal: LockSignal::None,
                worker: Mutex::new(None),
            })
        }
    }

    /// A source with no signal (`unavailable`), and no thread.
    #[must_use]
    pub fn unavailable() -> Arc<Self> {
        let shared = Arc::new(Shared::new());
        shared.record(LockState::Unavailable);
        Arc::new(Self {
            shared,
            signal: LockSignal::None,
            worker: Mutex::new(None),
        })
    }

    /// The platform signal this source uses (`None` when it reads `unavailable`).
    #[must_use]
    pub fn signal(&self) -> LockSignal {
        if self.state() == LockState::Unavailable {
            LockSignal::None
        } else {
            self.signal
        }
    }

    /// A diagnostic snapshot.
    #[must_use]
    pub fn snapshot(&self) -> SourceSnapshot {
        let l = *self.shared.latch();
        SourceSnapshot {
            state: l.state,
            epoch: l.epoch,
            transitions: l.transitions,
            last_change: l.last_change,
            signal: self.signal(),
            events: self.shared.events.load(Ordering::SeqCst),
            events_off_thread: self.shared.events_off_thread.load(Ordering::SeqCst),
            locked_entries: l.locked_entries,
            last_locked: l.last_locked,
            unknown_entries: l.unknown_entries,
        }
    }

    /// Whether the platform thread is still running.
    #[must_use]
    pub fn thread_running(&self) -> bool {
        self.worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    /// Stop and join the platform thread (idempotent; bounded by the platform's wake-up,
    /// at most about [`STOP_SLICE`] on macOS). The state stays as last read.
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.stop_wake.notify_waiters();
        self.shared.stop_wake.notify_one();
        let handle = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        #[cfg(any(target_os = "macos", windows, target_os = "linux"))]
        if handle.as_ref().is_some_and(|h| !h.is_finished()) {
            platform::wake(&self.shared);
        }
        if let Some(h) = handle
            && h.join().is_err()
        {
            tracing::warn!("session-lock thread ended with a panic");
        }
    }
}

impl Drop for PlatformSessionLockSource {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl SessionLockSource for PlatformSessionLockSource {
    fn state(&self) -> LockState {
        self.shared.latch().state
    }

    fn lock_epoch(&self) -> LockEpoch {
        self.shared.latch().epoch
    }

    fn acknowledge(&self, epoch: u64) {
        let mut l = self.shared.latch();
        l.epoch = l.epoch.acknowledge(epoch);
    }

    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.shared.notify.notified()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn source_over(shared: Arc<Shared>) -> PlatformSessionLockSource {
        PlatformSessionLockSource {
            shared,
            signal: LockSignal::None,
            worker: Mutex::new(None),
        }
    }

    /// W1-R03: entering `unknown` advances the epoch (fail closed: the revocation pass
    /// runs) but is never evidence of a real lock; only a `locked` reading is, and it
    /// stays counted after an unlock.
    #[test]
    fn unknown_never_counts_as_a_real_lock_observation() {
        let s = Arc::new(Shared::new());
        s.record(LockState::Unlocked);
        let src = source_over(Arc::clone(&s));
        let before = src.snapshot();
        s.record(LockState::Unknown);
        let lost = src.snapshot();
        assert_eq!(lost.epoch.epoch, before.epoch.epoch + 1, "unknown latches");
        assert!(lost.epoch.observed);
        assert_eq!(lost.unknown_entries, 1);
        assert!(!lost.locked_since(&before), "a lost signal is no lock");
        s.record(LockState::Unlocked);
        s.record(LockState::Locked);
        s.record(LockState::Unlocked);
        let after = src.snapshot();
        assert_eq!(after.state, LockState::Unlocked);
        assert!(after.locked_since(&before), "latched after the unlock");
        assert!(after.locked_since(&lost));
        assert_eq!(after.locked_entries, 1);
        assert!(after.last_locked.is_some());
    }

    #[test]
    fn initial_unlocked_latches_nothing() {
        let s = Arc::new(Shared::new());
        s.record(LockState::Unlocked);
        let src = source_over(s);
        assert_eq!(src.state(), LockState::Unlocked);
        assert_eq!(src.lock_epoch(), LockEpoch::default());
    }

    #[test]
    fn initial_locked_or_unknown_latches_once() {
        for initial in [LockState::Locked, LockState::Unknown] {
            let s = Arc::new(Shared::new());
            s.record(initial);
            let src = source_over(s);
            assert_eq!(
                src.lock_epoch(),
                LockEpoch {
                    epoch: 1,
                    observed: true
                },
                "{initial:?} at start is treated as a lock"
            );
        }
        let s = Arc::new(Shared::new());
        s.record(LockState::Unavailable);
        assert_eq!(source_over(s).lock_epoch(), LockEpoch::default());
    }

    #[test]
    fn every_transition_into_locked_or_unknown_latches_and_ack_clears_only_its_epoch() {
        let s = Arc::new(Shared::new());
        s.record(LockState::Unlocked);
        let src = source_over(Arc::clone(&s));
        s.record(LockState::Locked);
        s.record(LockState::Locked); // not a transition
        assert_eq!(src.lock_epoch().epoch, 1);
        s.record(LockState::Unlocked);
        assert!(
            src.lock_epoch().observed,
            "an unlock never clears the latch"
        );
        s.record(LockState::Unknown);
        assert_eq!(src.lock_epoch().epoch, 2, "unknown counts as a lock");
        s.record(LockState::Locked);
        assert_eq!(src.lock_epoch().epoch, 3, "unknown -> locked latches again");
        src.acknowledge(2);
        assert!(src.lock_epoch().observed, "an older epoch clears nothing");
        src.acknowledge(3);
        assert!(!src.lock_epoch().observed);
        assert_eq!(src.snapshot().transitions, 4);
    }

    #[test]
    fn definite_readings_only_from_the_backstop() {
        let s = Arc::new(Shared::new());
        s.record(LockState::Unlocked);
        s.record_definite(None);
        s.record_definite(Some(LockState::Unknown));
        s.record_definite(Some(LockState::Unavailable));
        assert_eq!(s.latch().state, LockState::Unlocked);
        s.record_definite(Some(LockState::Locked));
        assert_eq!(s.latch().state, LockState::Locked);
    }

    #[test]
    fn changed_wakes_a_waiter_and_a_late_one() {
        let s = Arc::new(Shared::new());
        s.record(LockState::Unlocked);
        let src = source_over(Arc::clone(&s));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let waiter = src.changed();
            s.record(LockState::Locked);
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("woken");
            tokio::time::timeout(Duration::from_secs(5), src.changed())
                .await
                .expect("the stored permit wakes a late waiter");
        });
    }

    #[test]
    fn floor_maps_the_m01_key() {
        let mut c = SessionConfig::default();
        assert_eq!(lock_floor(&c), LockBehavior::Continue);
        c.lock_behavior = config::LockBehavior::Revoke;
        assert_eq!(lock_floor(&c), LockBehavior::RevokeOnLock);
    }

    #[test]
    fn unavailable_source_has_no_thread_and_no_signal() {
        let src = PlatformSessionLockSource::unavailable();
        assert_eq!(src.state(), LockState::Unavailable);
        assert_eq!(src.signal(), LockSignal::None);
        assert!(!src.thread_running());
        src.shutdown();
        src.shutdown();
    }
}
