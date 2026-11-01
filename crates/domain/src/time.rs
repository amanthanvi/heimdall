//! Time model (spec §6.2, §6.4; ADR-0006 §10; ADR-0005 §3.6; overview §5).
//!
//! Two clocks, both injectable so virtual-clock tests drive production code:
//! wall time ([`jiff::Timestamp`], UTC) for persisted absolute deadlines, and a
//! monotonic clock for in-process intervals. Deadlines are resolved once at creation
//! and persisted as absolute UTC instants together with the caller's original
//! intent. Restarts, sleep and clock changes never extend authority: the check is
//! always `now >= deadline` against the persisted instant, and implausible rollback
//! stops issuance with `TIME_UNCERTAIN`.
//!
//! ADR-0005 §3.6 pieces expressed here: the high-water mark ([`next_anchor`]),
//! rollback and two-sided skew detection ([`assess_time`]), and the grant budget on
//! the monotonic clock ([`budget_end`], [`admission`]). The ADR's boot-wide
//! continuous clock, boot ID and "OS reports synchronized time" inputs are not part
//! of [`Clock`]/[`TimeAnchor`] yet; until they are, a `process_generation` is the
//! domain in which monotonic readings may be compared, and [`SystemClock`] uses
//! `std::time::Instant`, whose counting of system sleep std leaves platform-dependent
//! (Linux `CLOCK_MONOTONIC` excludes suspend).

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

/// Longest intent string the parser looks at (A29: parsers are bounded). Every
/// valid RFC 3339 timestamp or duration is far shorter.
const MAX_INTENT_LEN: usize = 128;

/// Resolve an intent against `now`, bounded by `max_window` (spec P04 default 12 h).
/// Absolute intents must carry an explicit offset; durations are added once to `now`.
///
/// Rules (spec §6.2, ADR-0006 §10):
/// * `Absolute` must be an RFC 3339 timestamp with an explicit offset (`Z`,
///   `±hh:mm`). A civil time without an offset is `Malformed`, except that a civil
///   time naming a zone (`…[Area/City]`) in which it is ambiguous (DST fold) or does
///   not exist (DST gap) is reported as `Ambiguous`, so the human input boundary can
///   ask for disambiguation. A zone annotation next to an explicit offset is not
///   RFC 3339 and is `Malformed`.
/// * `Duration` is an ISO 8601 (`PT2H`) or friendly (`2h`, `1h 30m`) duration of
///   exact units, added once to `now`. Calendar units with variable length are
///   rejected by the parser.
/// * The effective instant must be strictly after `now` (`NotInFuture`) and at
///   most `max_window` after it (`ExceedsMaximum`; equality is allowed).
///
/// The result is computed once at creation and persisted; retries and restarts
/// reuse the persisted [`Deadline`] and never call this again for the same grant.
pub fn resolve_deadline(
    intent: &DeadlineIntent,
    now: Timestamp,
    max_window: Duration,
) -> Result<Deadline, DeadlineError> {
    let max = jiff::SignedDuration::try_from(max_window).unwrap_or(jiff::SignedDuration::MAX);
    let effective = match intent {
        DeadlineIntent::Absolute(text) => parse_absolute(bounded(text)?)?,
        DeadlineIntent::Duration(text) => {
            let span = parse_duration(bounded(text)?)?;
            if span <= jiff::SignedDuration::ZERO {
                return Err(DeadlineError::NotInFuture);
            }
            if span > max {
                return Err(DeadlineError::ExceedsMaximum);
            }
            now.checked_add(span)
                .map_err(|_| DeadlineError::ExceedsMaximum)?
        }
    };
    if effective <= now {
        return Err(DeadlineError::NotInFuture);
    }
    if effective.duration_since(now) > max {
        return Err(DeadlineError::ExceedsMaximum);
    }
    Ok(Deadline {
        intent: intent.clone(),
        resolved_at: now,
        effective,
    })
}

fn bounded(text: &str) -> Result<&str, DeadlineError> {
    if text.len() > MAX_INTENT_LEN {
        return Err(DeadlineError::Malformed("intent is too long".into()));
    }
    Ok(text.trim())
}

fn parse_duration(text: &str) -> Result<jiff::SignedDuration, DeadlineError> {
    text.parse::<jiff::SignedDuration>().map_err(|_| {
        DeadlineError::Malformed("not an ISO 8601 or friendly duration of exact units".into())
    })
}

fn parse_absolute(text: &str) -> Result<Timestamp, DeadlineError> {
    use jiff::fmt::temporal::Pieces;

    let malformed = |why: &str| DeadlineError::Malformed(why.to_owned());
    let pieces = Pieces::parse(text).map_err(|_| malformed("not an RFC 3339 timestamp"))?;
    let time = pieces
        .time()
        .ok_or_else(|| malformed("timestamp has no time of day"))?;
    let civil = pieces.date().to_datetime(time);
    match (pieces.offset(), pieces.time_zone_annotation()) {
        (Some(offset), None) => offset
            .to_numeric_offset()
            .to_timestamp(civil)
            .map_err(|_| malformed("timestamp is out of range")),
        (Some(_), Some(_)) => Err(malformed(
            "a time zone annotation is not part of RFC 3339; send the offset only",
        )),
        (None, Some(annotation)) => {
            // Named zones need a time zone database; where none is available the
            // input is still refused, only without the more specific diagnosis.
            let zone = annotation
                .to_time_zone()
                .map_err(|_| malformed("unknown time zone"))?;
            Err(reject_local_time(&zone, civil))
        }
        (None, None) => Err(malformed("timestamp needs an explicit UTC offset")),
    }
}

/// Why a civil time without an offset is refused in `zone`: `Ambiguous` when the
/// zone repeats (fold) or skips (gap) it, else `Malformed` (offset required).
fn reject_local_time(zone: &jiff::tz::TimeZone, civil: jiff::civil::DateTime) -> DeadlineError {
    use jiff::tz::AmbiguousOffset;
    match zone.to_ambiguous_timestamp(civil).offset() {
        AmbiguousOffset::Gap { .. } | AmbiguousOffset::Fold { .. } => DeadlineError::Ambiguous,
        AmbiguousOffset::Unambiguous { .. } => {
            DeadlineError::Malformed("timestamp needs an explicit UTC offset".to_owned())
        }
    }
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
///
/// Rules (overview §5; ADR-0005 §3.6 "`TIME_UNCERTAIN` applies when"):
/// 1. `previous` is the persisted anchor whose `wall` is the high-water mark (see
///    [`next_anchor`]). `now.wall` below it by more than `max_tolerated_rollback`
///    is `Rollback`, whatever the process generation.
/// 2. Within one monotonic domain (`process_generation` equal), the wall clock must
///    follow the monotonic prediction `previous.wall + (now.monotonic −
///    previous.monotonic)` within `max_tolerated_skew` **in either direction**: a
///    step back hidden inside the rollback tolerance and an implausible forward
///    jump are both `Skew`. Sleep is plausible only because the monotonic clock is
///    expected to count it (ADR-0005 "continuous clock"); a forward wall jump
///    matched by monotonic progress is `Safe`. A monotonic reading that went
///    backwards inside one generation is impossible for a real clock and fails
///    closed as `Skew`.
/// 3. Across generations no monotonic comparison is possible; a forward jump (or a
///    step back within tolerance) is `Safe`.
/// 4. No previous anchor (first start): `Safe`; nothing to compare against.
///
/// Boundaries are inclusive on the safe side: a difference equal to a tolerance is
/// `Safe`, one nanosecond more is `Uncertain`.
#[must_use]
pub fn assess_time(
    previous: Option<&TimeAnchor>,
    now: &TimeAnchor,
    policy: &TimePolicy,
) -> TimeStatus {
    let Some(previous) = previous else {
        return TimeStatus::Safe;
    };
    let rollback_tolerance = signed(policy.max_tolerated_rollback);
    // Positive when the observed wall time is earlier than the high-water mark.
    let behind = previous.wall.duration_since(now.wall);
    if behind > rollback_tolerance {
        return TimeStatus::Uncertain(TimeUncertainty::Rollback {
            anchor: previous.wall,
            observed: now.wall,
        });
    }
    if previous.process_generation != now.process_generation {
        return TimeStatus::Safe;
    }
    let wall_progress = now.wall.duration_since(previous.wall);
    let wall_delta = Duration::try_from(wall_progress).unwrap_or(Duration::ZERO);
    let Some(monotonic_delta) = now.monotonic.checked_sub(previous.monotonic) else {
        return TimeStatus::Uncertain(TimeUncertainty::Skew {
            wall_delta,
            monotonic_delta: Duration::ZERO,
        });
    };
    // Overflow means a disagreement far beyond any tolerance: fail closed.
    let disagreement = wall_progress
        .checked_sub(signed(monotonic_delta))
        .map_or(Duration::MAX, jiff::SignedDuration::unsigned_abs);
    if disagreement > policy.max_tolerated_skew {
        return TimeStatus::Uncertain(TimeUncertainty::Skew {
            wall_delta,
            monotonic_delta,
        });
    }
    TimeStatus::Safe
}

/// The anchor to persist after `observed` was assessed [`TimeStatus::Safe`]
/// against `previous` (ADR-0005 §3.6 "high-water mark": the latest wall-clock time
/// accepted). The persisted wall time never moves backwards, so tolerated small
/// step-backs cannot accumulate across anchors into an undetected rollback.
///
/// * `observed.wall >= previous.wall`: `observed` itself.
/// * Same generation, small step back: `previous` is kept (it is a real, paired
///   observation in the same monotonic domain, so later skew checks stay exact).
/// * New generation, small step back: the mark `previous.wall` paired with the new
///   generation's reading; later skew checks in that generation carry at most the
///   rollback tolerance of error, far below the skew tolerance.
///
/// Never call this with an anchor assessed `Uncertain`: persisting it would accept
/// the rollback.
#[must_use]
pub fn next_anchor(previous: Option<&TimeAnchor>, observed: TimeAnchor) -> TimeAnchor {
    match previous {
        Some(prev) if observed.wall < prev.wall => {
            if prev.process_generation == observed.process_generation {
                *prev
            } else {
                TimeAnchor {
                    wall: prev.wall,
                    ..observed
                }
            }
        }
        _ => observed,
    }
}

/// Monotonic reading at which a grant's budget ends (ADR-0005 §3.6 "grant
/// anchor"): `anchor.monotonic + (bound − anchor.wall)`, where `bound` is the
/// absolute `min(deadline, cutoff, parent deadline)` and `anchor` is the paired
/// observation taken when the grant was activated or first validated in this
/// monotonic domain. A bound at or before the anchor ends the budget at the anchor.
/// An earlier bound set later yields an earlier end; nothing here can lengthen it.
#[must_use]
pub fn budget_end(anchor: &TimeAnchor, bound: Timestamp) -> Duration {
    let remaining = Duration::try_from(bound.duration_since(anchor.wall)).unwrap_or(Duration::ZERO);
    anchor.monotonic.saturating_add(remaining)
}

/// Result of the ADR-0005 §3.6 admission-deadline check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Neither deadline branch has passed. Admission still also needs
    /// [`TimeStatus::Safe`] and the grant/generation checks.
    Open,
    /// The admission deadline passed: the wall clock reached the bound, or the
    /// monotonic budget ran out. The grant expires (`DeadlineReached`).
    Expired,
    /// The budget anchor belongs to another monotonic domain (`process_generation`
    /// differs), so branch (b) cannot be evaluated. Refuse admission (fail closed)
    /// until the runtime re-anchors the grant from a wall time assessed
    /// [`TimeStatus::Safe`]; this is not an expiry and must not emit
    /// `DeadlineReached`. Only the wall branch has been checked.
    NeedsAnchor,
}

/// ADR-0005 §3.6 admission deadline: expired once **either** (a) the wall clock
/// reaches the absolute `bound`, or (b) the monotonic clock reaches the grant's
/// [`budget_end`]. Because (b) counts elapsed monotonic time, a frozen or
/// stepped-back wall clock cannot extend authority, and sleep counts against the
/// budget when the monotonic clock includes it. The budget is never rebuilt
/// implicitly; see [`Admission::NeedsAnchor`]. Callers must separately refuse while
/// time is `Uncertain`.
#[must_use]
pub fn admission(bound: Timestamp, budget_anchor: &TimeAnchor, now: &TimeAnchor) -> Admission {
    if is_expired(now.wall, bound) {
        return Admission::Expired;
    }
    if budget_anchor.process_generation != now.process_generation {
        return Admission::NeedsAnchor;
    }
    if now.monotonic >= budget_end(budget_anchor, bound) {
        return Admission::Expired;
    }
    Admission::Open
}

fn signed(d: Duration) -> jiff::SignedDuration {
    jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::MAX)
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

    // ---- resolve_deadline -------------------------------------------------------

    const H12: Duration = Duration::from_secs(12 * 3600);

    fn now() -> Timestamp {
        "2026-10-02T00:00:00Z".parse().unwrap()
    }

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn abs(s: &str) -> DeadlineIntent {
        DeadlineIntent::Absolute(s.to_owned())
    }

    fn dur(s: &str) -> DeadlineIntent {
        DeadlineIntent::Duration(s.to_owned())
    }

    fn resolve(intent: &DeadlineIntent) -> Result<Deadline, DeadlineError> {
        resolve_deadline(intent, now(), H12)
    }

    fn malformed(r: Result<Deadline, DeadlineError>) -> bool {
        matches!(r, Err(DeadlineError::Malformed(_)))
    }

    #[test]
    fn absolute_with_offset_resolves_to_utc_and_keeps_intent() {
        let intent = abs("2026-10-02T08:00:00+02:00");
        let d = resolve(&intent).unwrap();
        assert_eq!(d.effective, ts("2026-10-02T06:00:00Z"));
        assert_eq!(d.intent, intent);
        assert_eq!(d.resolved_at, now());
        let z = resolve(&abs("2026-10-02T06:00:00Z")).unwrap();
        assert_eq!(z.effective, d.effective);
        let neg = resolve(&abs("2026-10-01T23:30:00-04:00")).unwrap();
        assert_eq!(neg.effective, ts("2026-10-02T03:30:00Z"));
    }

    #[test]
    fn absolute_without_offset_is_malformed() {
        assert!(malformed(resolve(&abs("2026-10-02T06:00:00"))));
        assert!(malformed(resolve(&abs("2026-10-02"))));
        assert!(malformed(resolve(&abs("2026-10-02Z"))));
        assert!(malformed(resolve(&abs("tomorrow"))));
        assert!(malformed(resolve(&abs(""))));
        assert!(malformed(resolve(&abs(
            "2026-10-02T06:00:00+02:00 trailing"
        ))));
    }

    #[test]
    fn zone_annotations_are_not_rfc3339() {
        // Offset and annotation together: not RFC 3339, refused.
        assert!(malformed(resolve(&abs(
            "2026-10-02T02:00:00-04:00[America/New_York]"
        ))));
        assert!(malformed(resolve(&abs("2026-10-02T06:00:00Z[UTC]"))));
        // Unambiguous local time in a zone, no offset: still needs the offset.
        assert!(malformed(resolve(&abs(
            "2026-10-02T02:00:00[America/New_York]"
        ))));
        // Unknown zone.
        assert!(malformed(resolve(&abs(
            "2026-10-02T02:00:00[Nowhere/Nothing]"
        ))));
    }

    #[test]
    fn ambiguous_or_nonexistent_local_time_is_ambiguous() {
        // POSIX rule equal to US Eastern since 2007; needs no time zone database.
        let zone = jiff::tz::TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        let civil = |s: &str| s.parse::<jiff::civil::DateTime>().unwrap();
        // DST fold: 01:30 happens twice on 2026-11-01.
        assert_eq!(
            reject_local_time(&zone, civil("2026-11-01T01:30:00")),
            DeadlineError::Ambiguous
        );
        // DST gap: 02:30 does not exist on 2026-03-08.
        assert_eq!(
            reject_local_time(&zone, civil("2026-03-08T02:30:00")),
            DeadlineError::Ambiguous
        );
        // Unambiguous: still refused, an explicit offset is required.
        assert!(matches!(
            reject_local_time(&zone, civil("2026-10-02T02:00:00")),
            DeadlineError::Malformed(_)
        ));
    }

    #[test]
    fn named_zone_without_offset_is_always_refused() {
        // With a time zone database the fold is diagnosed as Ambiguous; without one
        // (the pinned jiff features carry no database on Unix) it is Malformed.
        // Either way the deadline is never resolved.
        let got = resolve_deadline(
            &abs("2026-11-01T01:30:00[America/New_York]"),
            ts("2026-11-01T00:00:00Z"),
            H12,
        );
        let has_db = jiff::tz::TimeZone::get("America/New_York").is_ok();
        if has_db {
            assert_eq!(got, Err(DeadlineError::Ambiguous));
        } else {
            assert!(malformed(got));
        }
    }

    #[test]
    fn absolute_must_be_in_future_and_within_window() {
        assert_eq!(
            resolve(&abs("2026-10-02T00:00:00Z")),
            Err(DeadlineError::NotInFuture)
        );
        assert_eq!(
            resolve(&abs("2026-10-01T23:00:00Z")),
            Err(DeadlineError::NotInFuture)
        );
        assert!(
            resolve(&abs("2026-10-02T12:00:00Z")).is_ok(),
            "window is inclusive"
        );
        assert_eq!(
            resolve(&abs("2026-10-02T12:00:00.000000001Z")),
            Err(DeadlineError::ExceedsMaximum)
        );
        assert_eq!(
            resolve(&abs("9000-01-01T00:00:00Z")),
            Err(DeadlineError::ExceedsMaximum)
        );
        // Outside jiff's representable range: refused as malformed.
        assert!(malformed(resolve(&abs("9999-12-31T23:59:59-23:59"))));
    }

    #[test]
    fn durations_iso_and_friendly_agree() {
        let iso = resolve(&dur("PT2H")).unwrap();
        let friendly = resolve(&dur("2h")).unwrap();
        assert_eq!(iso.effective, ts("2026-10-02T02:00:00Z"));
        assert_eq!(iso.effective, friendly.effective);
        assert_eq!(iso.intent, dur("PT2H"), "intent kept verbatim");
        assert_eq!(
            resolve(&dur("1h 30m")).unwrap().effective,
            ts("2026-10-02T01:30:00Z")
        );
        assert_eq!(
            resolve(&dur(" 90m ")).unwrap().effective,
            ts("2026-10-02T01:30:00Z")
        );
    }

    #[test]
    fn duration_bounds_and_malformed() {
        assert_eq!(resolve(&dur("0s")), Err(DeadlineError::NotInFuture));
        assert_eq!(resolve(&dur("-2h")), Err(DeadlineError::NotInFuture));
        assert_eq!(resolve(&dur("PT0S")), Err(DeadlineError::NotInFuture));
        assert!(resolve(&dur("12h")).is_ok(), "window is inclusive");
        assert_eq!(resolve(&dur("12h 1s")), Err(DeadlineError::ExceedsMaximum));
        assert_eq!(
            resolve(&dur("2562047788015215h")),
            Err(DeadlineError::ExceedsMaximum)
        );
        assert!(malformed(resolve(&dur("two hours"))));
        assert!(malformed(resolve(&dur(""))));
        // Variable-length calendar units are not exact durations.
        assert!(malformed(resolve(&dur("P1M"))));
        assert!(malformed(resolve(&dur("1 month"))));
        assert!(malformed(resolve(&dur("P1Y"))));
        // An absolute timestamp is not a duration and vice versa.
        assert!(malformed(resolve(&dur("2026-10-02T06:00:00Z"))));
        assert!(malformed(resolve(&abs("2h"))));
    }

    #[test]
    fn oversized_intent_is_rejected_before_parsing() {
        let long = format!("{}h", "1".repeat(MAX_INTENT_LEN));
        assert!(malformed(resolve(&dur(&long))));
        let long_abs = format!("2026-10-02T06:00:00Z{}", " ".repeat(MAX_INTENT_LEN));
        assert!(malformed(resolve(&abs(&long_abs))));
    }

    // ---- assess_time ------------------------------------------------------------

    fn anchor(wall: Timestamp, mono_secs: u64, generation: u64) -> TimeAnchor {
        TimeAnchor {
            wall,
            monotonic: Duration::from_secs(mono_secs),
            process_generation: generation,
        }
    }

    fn plus(t: Timestamp, secs: i64) -> Timestamp {
        t.checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn first_start_is_safe() {
        let p = TimePolicy::default();
        assert_eq!(
            assess_time(None, &anchor(now(), 0, 1), &p),
            TimeStatus::Safe
        );
    }

    #[test]
    fn rollback_boundary_is_inclusive_on_the_safe_side() {
        let p = TimePolicy::default();
        let prev = anchor(now(), 100, 1);
        // Other generation (restart): 5 s back is tolerated, 5 s + 1 ns is not.
        assert_eq!(
            assess_time(Some(&prev), &anchor(plus(now(), -5), 0, 2), &p),
            TimeStatus::Safe
        );
        let just_over = now().checked_sub(jiff::SignedDuration::new(5, 1)).unwrap();
        assert_eq!(
            assess_time(Some(&prev), &anchor(just_over, 0, 2), &p),
            TimeStatus::Uncertain(TimeUncertainty::Rollback {
                anchor: now(),
                observed: just_over
            })
        );
    }

    #[test]
    fn same_process_forward_jump_without_monotonic_progress_is_skew() {
        let p = TimePolicy::default();
        let prev = anchor(now(), 100, 1);
        let jumped = anchor(plus(now(), 3600), 110, 1);
        assert_eq!(
            assess_time(Some(&prev), &jumped, &p),
            TimeStatus::Uncertain(TimeUncertainty::Skew {
                wall_delta: Duration::from_secs(3600),
                monotonic_delta: Duration::from_secs(10),
            })
        );
        // Exactly at the skew tolerance: safe.
        let at_tol = anchor(plus(now(), 70), 110, 1);
        assert_eq!(assess_time(Some(&prev), &at_tol, &p), TimeStatus::Safe);
        // Sleep counted by the monotonic clock: safe.
        let slept = anchor(plus(now(), 3600), 3700, 1);
        assert_eq!(assess_time(Some(&prev), &slept, &p), TimeStatus::Safe);
    }

    #[test]
    fn same_process_hidden_step_back_is_skew() {
        let p = TimePolicy::default();
        let prev = anchor(now(), 0, 1);
        // Wall 3 s behind the anchor (inside rollback tolerance) after 120 s of
        // monotonic progress: the wall clock was stepped back ~123 s.
        let obs = anchor(plus(now(), -3), 120, 1);
        assert_eq!(
            assess_time(Some(&prev), &obs, &p),
            TimeStatus::Uncertain(TimeUncertainty::Skew {
                wall_delta: Duration::ZERO,
                monotonic_delta: Duration::from_secs(120),
            })
        );
    }

    #[test]
    fn monotonic_going_backwards_in_one_generation_fails_closed() {
        let p = TimePolicy::default();
        let prev = anchor(now(), 100, 1);
        let obs = anchor(plus(now(), 1), 50, 1);
        assert!(matches!(
            assess_time(Some(&prev), &obs, &p),
            TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
        ));
    }

    #[test]
    fn restart_forward_jump_is_safe() {
        let p = TimePolicy::default();
        let prev = anchor(now(), 5000, 1);
        let obs = anchor(plus(now(), 86_400), 0, 2);
        assert_eq!(assess_time(Some(&prev), &obs, &p), TimeStatus::Safe);
    }

    // ---- high-water mark and budgets -------------------------------------------

    #[test]
    fn next_anchor_never_lowers_the_mark() {
        let prev = anchor(now(), 100, 1);
        let fwd = anchor(plus(now(), 10), 110, 1);
        assert_eq!(next_anchor(Some(&prev), fwd), fwd);
        assert_eq!(next_anchor(None, fwd), fwd);
        let back_same = anchor(plus(now(), -2), 110, 1);
        assert_eq!(next_anchor(Some(&prev), back_same), prev);
        let back_new = anchor(plus(now(), -2), 3, 2);
        assert_eq!(
            next_anchor(Some(&prev), back_new),
            TimeAnchor {
                wall: now(),
                monotonic: Duration::from_secs(3),
                process_generation: 2
            }
        );
    }

    #[test]
    fn budget_runs_out_on_the_monotonic_clock() {
        let bound = plus(now(), 3600);
        let a = anchor(now(), 1000, 7);
        assert_eq!(budget_end(&a, bound), Duration::from_secs(4600));
        assert_eq!(budget_end(&a, plus(now(), -10)), Duration::from_secs(1000));
        let at = |wall: Timestamp, mono: u64, generation: u64| {
            admission(bound, &a, &anchor(wall, mono, generation))
        };
        // Wall frozen, monotonic past the budget: expired.
        assert_eq!(at(now(), 4600, 7), Admission::Expired);
        assert_eq!(at(now(), 4599, 7), Admission::Open);
        // Wall stepped back an hour, monotonic past the budget: still expired.
        assert_eq!(at(plus(now(), -3600), 4600, 7), Admission::Expired);
        // Wall reached the bound first: expired.
        assert_eq!(at(bound, 1001, 7), Admission::Expired);
        // Anchor from another monotonic domain: refuse, but it is not an expiry.
        assert_eq!(at(now(), 0, 8), Admission::NeedsAnchor);
        // ...unless the wall branch alone already passed.
        assert_eq!(at(bound, 0, 8), Admission::Expired);
        // An earlier bound set later shortens the budget.
        let cutoff = plus(now(), 600);
        assert_eq!(
            admission(cutoff, &a, &anchor(now(), 1600, 7)),
            Admission::Expired
        );
    }

    // ---- properties (plan §6.3 #5) ---------------------------------------------

    mod props {
        use super::*;
        use proptest::prelude::*;

        const DAY: i64 = 86_400;

        fn config() -> ProptestConfig {
            ProptestConfig {
                cases: 512,
                ..ProptestConfig::default()
            }
        }

        fn base() -> impl Strategy<Value = Timestamp> {
            (0i64..(365 * DAY)).prop_map(|s| plus(ts("2026-01-01T00:00:00Z"), s))
        }

        proptest! {
            #![proptest_config(config())]

            /// Monotone wall with matching monotonic progress (within skew) is Safe.
            #[test]
            fn monotone_matching_progress_is_safe(
                t in base(),
                mono0 in 0u64..1_000_000,
                step in 0u64..(30 * DAY as u64),
                jitter in -60i64..=60,
                generation in any::<u64>(),
            ) {
                let p = TimePolicy::default();
                let wall_step = (step as i64 + jitter).max(0);
                let prev = anchor(t, mono0, generation);
                let obs = anchor(plus(t, wall_step), mono0 + step, generation);
                prop_assert_eq!(assess_time(Some(&prev), &obs, &p), TimeStatus::Safe);
            }

            /// Any rollback beyond tolerance is Uncertain(Rollback), in any generation.
            #[test]
            fn rollback_beyond_tolerance_is_uncertain(
                t in base(),
                back_ms in 5_001i64..(30 * DAY * 1000),
                mono0 in 0u64..1_000_000,
                mono_step in 0u64..1_000_000,
                same_generation in any::<bool>(),
                tolerance_s in 0u64..120,
            ) {
                let p = TimePolicy {
                    max_tolerated_rollback: Duration::from_secs(tolerance_s),
                    ..TimePolicy::default()
                };
                let back = jiff::SignedDuration::from_millis(back_ms)
                    + jiff::SignedDuration::from_secs(tolerance_s as i64)
                    - jiff::SignedDuration::from_secs(5);
                let observed = t.checked_sub(back).unwrap();
                let prev = anchor(t, mono0, 1);
                let obs = anchor(observed, mono0 + mono_step, if same_generation { 1 } else { 2 });
                prop_assert_eq!(
                    assess_time(Some(&prev), &obs, &p),
                    TimeStatus::Uncertain(TimeUncertainty::Rollback { anchor: t, observed })
                );
            }

            /// Forward jumps are Safe across a restart (no monotonic comparison
            /// possible) and within a process when the monotonic clock counted the
            /// same interval (sleep on a continuous clock).
            #[test]
            fn forward_jumps_are_safe(
                t in base(),
                jump in 0i64..(400 * DAY),
                mono0 in 0u64..1_000_000,
                mono_after_restart in 0u64..1_000_000,
            ) {
                let p = TimePolicy::default();
                let prev = anchor(t, mono0, 1);
                let restarted = anchor(plus(t, jump), mono_after_restart, 2);
                prop_assert_eq!(assess_time(Some(&prev), &restarted, &p), TimeStatus::Safe);
                let slept = anchor(plus(t, jump), mono0 + jump as u64, 1);
                prop_assert_eq!(assess_time(Some(&prev), &slept, &p), TimeStatus::Safe);
            }

            /// Within one process, disagreement beyond the skew tolerance in either
            /// direction is Uncertain (ADR-0005 §3.6, forward jumps included).
            #[test]
            fn intra_process_disagreement_is_uncertain(
                t in base(),
                mono0 in 0u64..1_000_000,
                mono_step in 0u64..(30 * DAY as u64),
                excess in 1i64..(30 * DAY),
                forward in any::<bool>(),
            ) {
                let p = TimePolicy::default();
                let skew = p.max_tolerated_skew.as_secs() as i64;
                let wall_step = if forward {
                    mono_step as i64 + skew + excess
                } else {
                    mono_step as i64 - skew - excess
                };
                let prev = anchor(t, mono0, 9);
                let obs = anchor(plus(t, wall_step), mono0 + mono_step, 9);
                let status = assess_time(Some(&prev), &obs, &p);
                prop_assert!(matches!(status, TimeStatus::Uncertain(_)), "{status:?}");
            }

            /// Pure: same input, same output.
            #[test]
            fn assess_is_pure(
                t in base(),
                d in -DAY..DAY,
                m0 in 0u64..1_000_000,
                m1 in 0u64..1_000_000,
                g0 in 0u64..3,
                g1 in 0u64..3,
            ) {
                let p = TimePolicy::default();
                let prev = anchor(t, m0, g0);
                let obs = anchor(plus(t, d), m1, g1);
                prop_assert_eq!(assess_time(Some(&prev), &obs, &p), assess_time(Some(&prev), &obs, &p));
            }

            /// A persisted mark never decreases, whatever Safe readings arrive.
            #[test]
            fn high_water_mark_is_monotone(
                t in base(),
                steps in prop::collection::vec((-5i64..=120, 0u64..120, any::<bool>()), 1..40),
            ) {
                let p = TimePolicy::default();
                let mut current = anchor(t, 0, 0);
                let mut wall = t;
                let mut mono = 0u64;
                let mut generation = 0u64;
                for (dw, dm, restart) in steps {
                    wall = plus(wall, dw);
                    if restart { generation += 1; mono = 0; } else { mono += dm; }
                    let obs = anchor(wall, mono, generation);
                    if assess_time(Some(&current), &obs, &p) == TimeStatus::Safe {
                        let next = next_anchor(Some(&current), obs);
                        prop_assert!(next.wall >= current.wall);
                        current = next;
                    }
                }
            }

            /// Durations are added exactly once to `now`.
            #[test]
            fn duration_is_added_once(t in base(), secs in 1u64..=(12 * 3600)) {
                let d = resolve_deadline(&dur(&format!("{secs}s")), t, H12).unwrap();
                prop_assert_eq!(d.effective, plus(t, secs as i64));
                prop_assert_eq!(d.resolved_at, t);
                let iso = resolve_deadline(&dur(&format!("PT{secs}S")), t, H12).unwrap();
                prop_assert_eq!(iso.effective, d.effective);
            }

            /// The same instant written with any offset resolves identically.
            #[test]
            fn offset_spelling_does_not_change_the_instant(
                t in base(),
                ahead in 1i64..(12 * 3600),
                offset_min in -(14i32 * 60)..=(14 * 60),
            ) {
                let target = plus(t, ahead);
                let offset = jiff::tz::Offset::from_seconds(offset_min * 60).unwrap();
                let text = target.display_with_offset(offset).to_string();
                let d = resolve_deadline(&abs(&text), t, H12).unwrap();
                prop_assert_eq!(d.effective, target);
            }

            /// Effective deadline is always in (now, now + max_window].
            #[test]
            fn accepted_deadlines_are_within_window(
                t in base(),
                secs in -DAY..DAY,
                window_s in 1u64..(2 * DAY as u64),
            ) {
                let window = Duration::from_secs(window_s);
                if let Ok(d) = resolve_deadline(&dur(&format!("{secs}s")), t, window) {
                    prop_assert!(d.effective > t);
                    prop_assert!(d.effective.duration_since(t) <= signed(window));
                }
            }
        }
    }
}
