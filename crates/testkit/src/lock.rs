//! The test-configuration session-lock source with the consumer-pause control
//! (m03-plan U11 `lock::FakeSessionLockSource`; ADR-0008 D9 item 3, D13 item 7, §17.1
//! item 9). Feature `managed`.
//!
//! This re-exports wave 0's [`FakeSessionLockSource`] (`crate::session_lock`): the
//! latched epoch (`LockEpoch { epoch, observed }`, acknowledged per epoch), the
//! state-file wiring ([`ENV`]), and the consumer-pause control
//! [`FakeSessionLockSource::pause_consumer`] / [`FakeSessionLockSource::resume_consumer`],
//! which withholds the `changed()` wake-ups while transitions still latch, so a lock
//! followed by an unlock while the consumer is paused is still seen (U9's
//! `lock_then_unlock_while_consumer_paused_still_revokes`).

pub use crate::session_lock::{ENV, FakeSessionLockSource};
