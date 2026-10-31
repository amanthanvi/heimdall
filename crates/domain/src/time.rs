//! Time model (spec §6.2, §6.4; ADR-0006 §10; overview §6).
//!
//! Two clocks, both injectable so virtual-clock tests drive production code:
//! wall time ([`jiff::Timestamp`], UTC) for persisted absolute deadlines, and a
//! monotonic clock for in-process intervals. Deadlines are resolved once at creation
//! and persisted as absolute UTC instants together with the caller's original
//! intent. Restarts, sleep and clock changes never extend authority: the check is
//! always `now >= deadline` against the persisted instant, and implausible rollback
//! stops issuance with `TIME_UNCERTAIN`.

use std::time::Duration;

use heimdall_contract::request::DeadlineIntent;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Source of wall and monotonic time. Production uses [`SystemClock`]; tests use
/// `heimdall_testkit::VirtualClock`.
pub trait Clock: Send + Sync {
    /// Current wall time (UTC instant).
    fn wall(&self) -> Timestamp;
    /// Monotonic elapsed time since an arbitrary fixed origin of this process.
    fn monotonic(&self) -> Duration;
}

/// The operating system clocks.
#[derive(Debug)]
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    /// Create a system clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn wall(&self) -> Timestamp {
        Timestamp::now()
    }

    fn monotonic(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A resolved deadline: the intent as given, when it was resolved, and the
/// absolute UTC instant that is enforced (spec §6.2 "retain the original intended
/// deadline").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadline {
    /// Original caller intent, verbatim.
    pub intent: DeadlineIntent,
    /// Wall time at resolution.
    pub resolved_at: Timestamp,
    /// Enforced absolute instant (UTC).
    pub effective: Timestamp,
}

/// Why a deadline intent could not be resolved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeadlineError {
    /// Not RFC 3339 with an explicit offset, or not a supported duration.
    #[error("deadline intent is malformed: {0}")]
    Malformed(String),
    /// A local time that is ambiguous or nonexistent in the given zone; machine
    /// requests must be unambiguous (spec §6.2).
    #[error("local time is ambiguous or does not exist; disambiguate at the input boundary")]
    Ambiguous,
    /// The resolved instant is not after `now`.
    #[error("deadline is not in the future")]
    NotInFuture,
    /// The resolved instant exceeds the permitted maximum window.
    #[error("deadline exceeds the maximum window")]
    ExceedsMaximum,
}

/// Resolve an intent against `now`, bounded by `max_window` (spec P04 default 12 h).
/// Absolute intents must carry an explicit offset; durations are added once to `now`.
pub fn resolve_deadline(
    _intent: &DeadlineIntent,
    _now: Timestamp,
    _max_window: Duration,
) -> Result<Deadline, DeadlineError> {
    todo!("M01-T02: parse RFC 3339 with offset or duration, add once, bound by max_window")
}

/// Earliest of several absolute bounds (grant deadline, parent deadline, policy
/// cutoff). Credentials never outlive this (spec §6.5).
#[must_use]
pub fn narrowest(bounds: impl IntoIterator<Item = Timestamp>) -> Option<Timestamp> {
    bounds.into_iter().min()
}

/// Last persisted observation of both clocks (spec §6.4 "persisted absolute
/// deadlines", rollback detection across restarts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnchor {
    /// Wall time observed.
    pub wall: Timestamp,
    /// Monotonic reading at the same moment.
    pub monotonic: Duration,
    /// Monotonic origin generation; differs after every process start so readings
    /// from different processes are never subtracted.
    pub process_generation: u64,
}

/// Tolerances for time plausibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimePolicy {
    /// Wall time may run behind the previous anchor by at most this much.
    pub max_tolerated_rollback: Duration,
    /// Within one process, wall progress may differ from monotonic progress by at
    /// most this much before time is uncertain.
    pub max_tolerated_skew: Duration,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            max_tolerated_rollback: Duration::from_secs(5),
            max_tolerated_skew: Duration::from_secs(60),
        }
    }
}

/// Why safe time could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUncertainty {
    /// Wall clock is earlier than a persisted anchor by more than the tolerance.
    Rollback {
        /// Last persisted wall time.
        anchor: Timestamp,
        /// Observed wall time.
        observed: Timestamp,
    },
    /// Within one process, wall and monotonic progress disagree beyond tolerance.
    Skew {
        /// Wall progress since the anchor.
        wall_delta: Duration,
        /// Monotonic progress since the anchor.
        monotonic_delta: Duration,
    },
}

/// Result of a plausibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStatus {
    /// Safe to issue and to compare against deadlines.
    Safe,
    /// Issuance must stop; passive reads continue with a warning (spec §6.4).
    Uncertain(TimeUncertainty),
}

/// Assess the current anchor against the previous one. Forward jumps are
/// plausible (sleep, suspend) and only make deadlines expire sooner; rollback
/// beyond tolerance and intra-process skew are uncertain.
#[must_use]
pub fn assess_time(
    _previous: Option<&TimeAnchor>,
    _now: &TimeAnchor,
    _policy: &TimePolicy,
) -> TimeStatus {
    todo!("M01-T02: rollback and skew detection per ADR-0006 §10")
}

/// `true` when `deadline` has passed at `now`. No grace, no extension.
#[must_use]
pub fn is_expired(now: Timestamp, deadline: Timestamp) -> bool {
    now >= deadline
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn narrowest_picks_min() {
        let a: Timestamp = "2026-10-02T06:00:00Z".parse().unwrap();
        let b: Timestamp = "2026-10-02T02:00:00Z".parse().unwrap();
        assert_eq!(narrowest([a, b]), Some(b));
        assert_eq!(narrowest(std::iter::empty()), None);
    }

    #[test]
    fn expiry_is_inclusive_at_the_instant() {
        let t: Timestamp = "2026-10-02T06:00:00Z".parse().unwrap();
        assert!(is_expired(t, t));
    }
}
