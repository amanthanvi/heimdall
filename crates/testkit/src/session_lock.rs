//! `FakeSessionLockSource`: the test-configuration session-lock source (ADR-0008 D9
//! item 3, §17.1 item 9; m03-plan U0 "Frozen in wave 0", §5 item 19). Feature
//! `managed`.
//!
//! It implements `app::ports::SessionLockSource` with the **latched epoch**: every
//! transition into `locked` increments the epoch and sets `observed`
//! ([`LockEpoch::observe_lock`]); [`SessionLockSource::acknowledge`] clears `observed`
//! for that epoch only; [`SessionLockSource::changed`] wakes every waiter. So a lock
//! followed by an unlock while the consumer was paused is still seen.
//!
//! Tests drive it with [`FakeSessionLockSource::set_state`]. Under the test
//! configuration the binary selects it through [`ENV`] (`HEIMDALL_TEST_SESSION_LOCK`,
//! the absolute path of a state file); the wiring then calls
//! [`FakeSessionLockSource::refresh_from_file`] on its own interval. The file holds
//! one word: `locked`, `unlocked`, `unknown` or `unavailable`.
//!
//! ⟨M03 wave 1, U11⟩ **The consumer-pause control** (ADR-0008 D13 item 7, §17.1 item 9;
//! m03-plan U11 `lock::FakeSessionLockSource`): [`FakeSessionLockSource::pause_consumer`]
//! withholds the [`SessionLockSource::changed`] wake-ups, as if the consumer (the
//! revocation pass) were paused, while transitions still latch;
//! [`FakeSessionLockSource::resume_consumer`] delivers one wake-up when anything changed
//! meanwhile. It lives here, not in `lock.rs`, because it gates the wake-up inside
//! [`FakeSessionLockSource::set_state`] of this one type (`lock` re-exports it).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use heimdall_app::ports::{LockState, SessionLockSource};
use heimdall_domain::managed::LockEpoch;
use tokio::sync::Notify;

/// The test-configuration variable naming the state file (debug builds only; a
/// release build that sees it exits 2, m03-plan U0b row 16).
pub const ENV: &str = "HEIMDALL_TEST_SESSION_LOCK";

#[derive(Debug, Clone, Copy)]
struct Inner {
    state: LockState,
    epoch: LockEpoch,
    /// The consumer is paused: wake-ups are withheld.
    paused: bool,
    /// A change happened while paused.
    pending: bool,
}

/// A scripted session-lock source.
#[derive(Debug)]
pub struct FakeSessionLockSource {
    inner: Mutex<Inner>,
    notify: Notify,
    state_file: Option<PathBuf>,
}

impl Default for FakeSessionLockSource {
    fn default() -> Self {
        Self::new(LockState::Unlocked)
    }
}

impl FakeSessionLockSource {
    /// A source in `initial` state, epoch 0, nothing observed. Starting `locked` is
    /// not a transition and latches nothing.
    #[must_use]
    pub fn new(initial: LockState) -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: initial,
                epoch: LockEpoch::default(),
                paused: false,
                pending: false,
            }),
            notify: Notify::new(),
            state_file: None,
        }
    }

    /// A source that reads `path` on [`Self::refresh_from_file`], starting from the
    /// file's current contents.
    #[must_use]
    pub fn from_state_file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let initial = read_state_file(&path);
        Self {
            state_file: Some(path),
            ..Self::new(initial)
        }
    }

    /// The state file, when there is one.
    #[must_use]
    pub fn state_file(&self) -> Option<&Path> {
        self.state_file.as_deref()
    }

    /// Move to `state`. A transition into `locked` (from any other state) increments
    /// the epoch and latches `observed`. Every call wakes the waiters of
    /// [`SessionLockSource::changed`].
    pub fn set_state(&self, state: LockState) {
        let wake = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if state == LockState::Locked && inner.state != LockState::Locked {
                inner.epoch = inner.epoch.observe_lock();
            }
            inner.state = state;
            if inner.paused {
                inner.pending = true;
            }
            !inner.paused
        };
        if wake {
            self.wake();
        }
    }

    /// Wake every current waiter, and leave one permit so a waiter created just after
    /// this call cannot miss it (a spurious wake-up is harmless; `changed` carries no
    /// value).
    fn wake(&self) {
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    /// ⟨M03⟩ Pause the consumer: from now on [`Self::set_state`] still latches every
    /// transition, but wakes nobody (ADR-0008 §17.1 item 9). Idempotent.
    pub fn pause_consumer(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).paused = true;
    }

    /// ⟨M03⟩ Resume the consumer: one wake-up if anything changed while it was paused.
    pub fn resume_consumer(&self) {
        let wake = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let wake = inner.paused && inner.pending;
            inner.paused = false;
            inner.pending = false;
            wake
        };
        if wake {
            self.wake();
        }
    }

    /// ⟨M03⟩ Whether the consumer is paused.
    #[must_use]
    pub fn consumer_paused(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).paused
    }

    /// Re-read the state file and apply it through [`Self::set_state`] when it
    /// changed. A missing file reads `unavailable`; an unreadable or unrecognized one
    /// reads `unknown`. Without a state file this does nothing.
    pub fn refresh_from_file(&self) {
        let Some(path) = &self.state_file else {
            return;
        };
        let next = read_state_file(path);
        if next != self.state() {
            self.set_state(next);
        }
    }
}

/// The state a state file names.
fn read_state_file(path: &Path) -> LockState {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_state(text.trim()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LockState::Unavailable,
        Err(_) => LockState::Unknown,
    }
}

/// The state a word names (`unknown` for anything else).
fn parse_state(word: &str) -> LockState {
    match word {
        "locked" => LockState::Locked,
        "unlocked" => LockState::Unlocked,
        "unavailable" => LockState::Unavailable,
        _ => LockState::Unknown,
    }
}

impl SessionLockSource for FakeSessionLockSource {
    fn state(&self) -> LockState {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state
    }

    fn lock_epoch(&self) -> LockEpoch {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).epoch
    }

    fn acknowledge(&self, epoch: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.epoch = inner.epoch.acknowledge(epoch);
    }

    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn lock_then_unlock_while_consumer_paused_still_latches() {
        let src = FakeSessionLockSource::default();
        let before = src.lock_epoch();
        assert_eq!(before, LockEpoch::default());
        // The consumer is paused: it reads nothing while the session locks and unlocks.
        src.set_state(LockState::Locked);
        src.set_state(LockState::Unlocked);
        // On resuming it sees the unlocked state but the latched lock.
        assert_eq!(src.state(), LockState::Unlocked);
        let seen = src.lock_epoch();
        assert_eq!(seen.epoch, 1);
        assert!(seen.observed, "a lock while paused must stay observed");
        src.acknowledge(seen.epoch);
        assert!(!src.lock_epoch().observed);
        assert_eq!(src.lock_epoch().epoch, 1);
    }

    #[test]
    fn every_transition_into_locked_increments_and_ack_clears_only_its_epoch() {
        let src = FakeSessionLockSource::default();
        src.set_state(LockState::Locked);
        src.set_state(LockState::Locked); // not a transition
        assert_eq!(src.lock_epoch().epoch, 1);
        let first = src.lock_epoch().epoch;
        src.set_state(LockState::Unknown);
        src.set_state(LockState::Locked); // unknown -> locked is a transition
        assert_eq!(src.lock_epoch().epoch, 2);
        src.acknowledge(first);
        assert!(src.lock_epoch().observed, "an older epoch clears nothing");
        src.acknowledge(2);
        assert!(!src.lock_epoch().observed);
        src.acknowledge(2);
        assert!(!src.lock_epoch().observed);
    }

    #[test]
    fn starting_locked_latches_nothing() {
        let src = FakeSessionLockSource::new(LockState::Locked);
        assert_eq!(src.lock_epoch(), LockEpoch::default());
    }

    #[test]
    fn changed_wakes_a_waiter() {
        let src = FakeSessionLockSource::default();
        block_on(async {
            let waiter = src.changed();
            src.set_state(LockState::Locked);
            tokio::time::timeout(Duration::from_secs(5), waiter)
                .await
                .expect("the waiter was woken");
            // A waiter created after the change is not left waiting forever either.
            tokio::time::timeout(Duration::from_secs(5), src.changed())
                .await
                .expect("the stored permit wakes a late waiter");
        });
    }

    #[test]
    fn state_file_drives_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock-state");
        let src = FakeSessionLockSource::from_state_file(&path);
        assert_eq!(src.state(), LockState::Unavailable);
        std::fs::write(&path, "locked\n").unwrap();
        src.refresh_from_file();
        assert_eq!(src.state(), LockState::Locked);
        assert_eq!(src.lock_epoch().epoch, 1);
        std::fs::write(&path, "unlocked").unwrap();
        src.refresh_from_file();
        assert_eq!(src.state(), LockState::Unlocked);
        assert!(src.lock_epoch().observed);
        std::fs::write(&path, "garbage").unwrap();
        src.refresh_from_file();
        assert_eq!(src.state(), LockState::Unknown);
        assert_eq!(src.state_file(), Some(path.as_path()));
    }
}
