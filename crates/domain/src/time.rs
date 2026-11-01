//! Time model (spec §6.2, §6.4; ADR-0005 §3.6 revision 3; ADR-0006 §10; overview §5).
//!
//! Three time sources, all injected so virtual-clock tests drive production code:
//!
//! * the **wall clock** (`jiff::Timestamp`, UTC) for persisted absolute deadlines;
//! * a **boot-scoped continuous clock** that keeps counting through sleep (Linux
//!   `CLOCK_BOOTTIME`, macOS `mach_continuous_time`, Windows interrupt time including
//!   suspend) together with the platform **boot ID** that names the boot the reading
//!   belongs to; readings from different boots are never compared;
//! * a **synchronization report** ([`TimeSync`]) saying whether the OS believes its
//!   wall clock is synchronized.
//!
//! Rules (ADR-0005 §3.6), all pure functions here:
//!
//! * Deadlines are resolved once ([`resolve_deadline`]) and persisted as absolute UTC
//!   instants together with the caller's verbatim intent. Nothing moves them later.
//! * Each grant gets a persisted [`GrantAnchor`] (boot ID, continuous reading, wall
//!   time) when it is activated or first validated in a boot; its budget end on the
//!   continuous clock is `anchor.continuous + (bound − anchor.wall)`. Budgets only
//!   shorten ([`shorten`]); they are never rebuilt from the current wall clock.
//! * Admission ([`admission`]) is refused once **either** the wall clock reaches the
//!   bound or the continuous budget runs out; an anchor from another boot is void
//!   (`NeedsAnchor`, fail closed) until a time assessed `Safe` re-anchors it.
//! * One shared gate ([`gate`]) is consulted before admission, signing and issuance:
//!   the wall clock must not be below the persisted high-water mark (within a boot by
//!   more than the rollback tolerance; after a reboot not at all); within a boot
//!   it must agree with the continuous clock's prediction in **either** direction
//!   (an implausible forward jump is as uncertain as a step back); after a reboot
//!   (or at first start) it is accepted only at or above the high-water mark **and**
//!   with synchronized time, or through an attended owner confirmation for this
//!   boot. Otherwise `TIME_UNCERTAIN`: no issuance, no signature, no admission.
//! * The high-water mark ([`next_high_water`]) is the latest wall time ever accepted;
//!   it never decreases.
//!
//! Platform clock sources live in `heimdall_runtime::platform`; this crate holds
//! only the trait and the rules.

use std::time::Duration;

use heimdall_contract::ids::{DecisionId, GrantId};
use heimdall_contract::request::DeadlineIntent;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Opaque per-boot identifier (Linux `/proc/sys/kernel/random/boot_id`, macOS
/// `kern.bootsessionuuid`, Windows the Session Manager `BootId` counter; see
/// `heimdall_runtime::platform`). Compared for equality only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootId(pub String);

/// Source of wall time, boot-scoped continuous time and the boot ID. Production:
/// `heimdall_runtime::platform::SystemClock`; tests: `heimdall_testkit::VirtualClock`.
pub trait Clock: Send + Sync {
    /// Current wall time (UTC instant).
    fn wall(&self) -> Timestamp;
    /// Continuous time since an arbitrary origin of the **current boot**; counts
    /// sleep and suspend; never decreases within a boot.
    fn continuous(&self) -> Duration;
    /// Identifier of the current boot.
    fn boot_id(&self) -> BootId;

    /// Paired reading of all three (one logical observation).
    fn observe(&self) -> TimeAnchor {
        TimeAnchor {
            boot_id: self.boot_id(),
            continuous: self.continuous(),
            wall: self.wall(),
        }
    }
}

/// Whether the operating system reports synchronized wall time (ADR-0005 §3.6
/// "the OS reports synchronized time"). `Unknown` fails closed exactly like
/// `NotSynchronized`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// The platform time service reports a successful synchronization.
    Synchronized,
    /// The platform reports no synchronization.
    NotSynchronized,
    /// No trustworthy signal is available (also used by stubs marked [I]).
    Unknown,
}

/// Port reporting [`SyncStatus`]. Platform implementations are stubs returning
/// `Unknown` until M03/M04 evidence selects the trustworthy signal per platform;
/// the fail-closed rule in [`gate`] exists now.
pub trait TimeSync: Send + Sync {
    /// Current synchronization status.
    fn status(&self) -> SyncStatus;
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

/// One paired observation of the three clocks (ADR-0005 §3.6 "grant anchor" and the
/// runtime's own anchor). Persisted in the transactional store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnchor {
    /// Boot the continuous reading belongs to.
    pub boot_id: BootId,
    /// Continuous-clock reading.
    pub continuous: Duration,
    /// Wall time at the same moment.
    pub wall: Timestamp,
}

/// Tolerances for time plausibility. The exact values are set by G09; these are
/// the M01 defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimePolicy {
    /// Wall time may be below the high-water mark by at most this much.
    pub max_tolerated_rollback: Duration,
    /// Within one boot, wall progress may differ from continuous progress by at
    /// most this much, in either direction.
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

/// An owner-present confirmation of the current time (ADR-0005 §3.6 "resolved
/// interactively by an explicit owner confirmation ... never `--non-interactive`").
/// It accepts the wall clock for **this boot** as a synthetic anchor; it never moves
/// a deadline and never rebuilds a budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendedTimeConfirmation {
    /// Boot the confirmation applies to.
    pub boot_id: BootId,
    /// Paired observation at confirmation.
    pub continuous: Duration,
    /// Wall time the owner confirmed.
    pub wall: Timestamp,
    /// Decision record that carried the confirmation (consume-once).
    pub decision: DecisionId,
}

impl AttendedTimeConfirmation {
    /// The anchor this confirmation stands in for.
    #[must_use]
    pub fn as_anchor(&self) -> TimeAnchor {
        TimeAnchor {
            boot_id: self.boot_id.clone(),
            continuous: self.continuous,
            wall: self.wall,
        }
    }
}

/// Why safe time could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimeUncertainty {
    /// Wall clock is below the persisted high-water mark by more than the tolerance.
    BelowHighWater {
        /// Persisted mark.
        mark: Timestamp,
        /// Observed wall time.
        observed: Timestamp,
    },
    /// Within one boot, wall and continuous progress disagree beyond tolerance.
    Skew {
        /// Wall progress since the reference anchor (negative when it went back).
        wall_delta: jiff::SignedDuration,
        /// Continuous progress since the reference anchor.
        continuous_delta: Duration,
    },
    /// The continuous clock went backwards within one boot: impossible for a real
    /// clock, fails closed.
    ContinuousWentBackwards,
    /// New boot (or first start): the wall clock is not reported synchronized and no
    /// attended confirmation covers this boot.
    Unsynchronized {
        /// What the platform reported.
        sync: SyncStatus,
    },
}

/// Result of the shared time gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeStatus {
    /// Safe to admit, sign, issue and to persist as the new anchor / high-water.
    Safe,
    /// Issuance, signing and admission must stop; passive reads continue with a
    /// warning (spec §6.4); owned masters are closed (ADR-0005 §3.6).
    Uncertain(TimeUncertainty),
}

/// Everything the gate may look at. Built by the runtime from the store and the
/// ports; the gate itself reads nothing else.
#[derive(Debug, Clone)]
pub struct GateInput<'a> {
    /// The runtime's last accepted anchor, if any (same boot ⇒ prediction check;
    /// other boot ⇒ reboot rules).
    pub previous: Option<&'a TimeAnchor>,
    /// Persisted high-water mark (latest accepted wall time).
    pub high_water: Option<Timestamp>,
    /// Current observation.
    pub now: &'a TimeAnchor,
    /// Platform synchronization report.
    pub sync: SyncStatus,
    /// Attended confirmation on record, if any.
    pub confirmation: Option<&'a AttendedTimeConfirmation>,
    /// Tolerances.
    pub policy: &'a TimePolicy,
}

/// The shared time gate (ADR-0005 §3.6 "`TIME_UNCERTAIN` applies when"). Pure.
///
/// 1. `now.wall` below `high_water` ⇒ `BelowHighWater`. **Within a boot** (a
///    same-boot runtime anchor or attended confirmation exists) a deficit up to
///    `max_tolerated_rollback` is tolerated; **after a reboot or at first start** (no
///    same-boot reference) no deficit is tolerated: ADR-0005 §3.6 requires wall time
///    at or above the mark there (ADR-0006 §13.4 N05).
/// 2. A same-boot reference: the continuous clock must not have gone backwards
///    (`ContinuousWentBackwards`) and `now.wall` must lie within
///    `max_tolerated_skew` of `previous.wall + (now.continuous − previous.continuous)`
///    in either direction (`Skew`). Sleep passes because the continuous clock counts
///    it; a frozen wall clock, a step back and an implausible forward jump all fail.
/// 3. No `previous` in this boot (reboot or first start): accepted only when
///    `sync == Synchronized` **and** `now.wall >= high_water` (rule 1). An attended
///    confirmation for this boot is a same-boot reference (rule 2). Otherwise
///    `Unsynchronized`. A rolled-back clock after downtime is therefore refused when
///    above the mark but unsynchronized, and refused by the mark when below it,
///    whatever the synchronization report.
///
/// Boundaries are inclusive on the safe side: a difference equal to a tolerance is
/// `Safe`, one nanosecond more is `Uncertain`.
#[must_use]
pub fn gate(input: &GateInput<'_>) -> TimeStatus {
    let now = input.now;
    let policy = input.policy;
    let reference = prediction_reference(input);
    if let Some(mark) = input.high_water {
        // The rollback tolerance is a within-boot allowance only (N05).
        let allowed = if reference.is_some() {
            signed(policy.max_tolerated_rollback)
        } else {
            jiff::SignedDuration::ZERO
        };
        if mark.duration_since(now.wall) > allowed {
            return TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
                mark,
                observed: now.wall,
            });
        }
    }
    if let Some(reference) = reference {
        return check_prediction(&reference, now, policy);
    }
    if input.sync == SyncStatus::Synchronized {
        return TimeStatus::Safe;
    }
    TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { sync: input.sync })
}

/// The same-boot anchor the prediction is measured against: the **later** (by
/// continuous reading) of the runtime anchor and an attended confirmation for this
/// boot. A confirmation accepted after a same-boot `Skew` therefore becomes the
/// reference and clears the skew (ADR-0005 §3.6; design-fix second round R3).
fn prediction_reference(input: &GateInput<'_>) -> Option<TimeAnchor> {
    let now = input.now;
    let prev = input.previous.filter(|p| p.boot_id == now.boot_id).cloned();
    let conf = input
        .confirmation
        .filter(|c| c.boot_id == now.boot_id)
        .map(AttendedTimeConfirmation::as_anchor);
    match (prev, conf) {
        (Some(p), Some(c)) => Some(if c.continuous >= p.continuous { c } else { p }),
        (Some(p), None) => Some(p),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

/// The runtime anchor to persist after `accepted` passed the gate (design-fix second
/// round R2). Within a boot the anchor is **re-based only on synchronized time**;
/// otherwise the previous reference is kept, so drift against it accumulates and a
/// slowly wrong or frozen wall clock is detected instead of being re-accepted every
/// pass. A new boot's first acceptance (by synchronization) installs `accepted`; a
/// confirmation installs its own anchor through `AttendedTimeConfirmation::as_anchor`.
#[must_use]
pub fn next_runtime_anchor(
    previous: Option<&TimeAnchor>,
    accepted: &TimeAnchor,
    sync: SyncStatus,
) -> TimeAnchor {
    match previous {
        Some(p) if p.boot_id == accepted.boot_id && sync != SyncStatus::Synchronized => p.clone(),
        _ => accepted.clone(),
    }
}

/// How far the accepted wall time may lag the truth, given the tolerances the gate
/// used to accept it (design-fix second round R4): the rollback tolerance when the
/// observation sits below the high-water mark **within a boot** (after a reboot the
/// gate accepts nothing below the mark, so there is no rollback share; N05), plus
/// the skew tolerance when it was accepted through a same-boot prediction (runtime
/// anchor or confirmation) on unsynchronized time. Zero for an observation accepted
/// at or above the mark on synchronized time with no same-boot reference. Only
/// meaningful when [`gate`] returned `Safe`.
#[must_use]
pub fn accepted_tolerance(input: &GateInput<'_>) -> Duration {
    let same_boot = prediction_reference(input).is_some();
    let mut tolerance = Duration::ZERO;
    if same_boot && input.high_water.is_some_and(|mark| input.now.wall < mark) {
        tolerance = tolerance.saturating_add(input.policy.max_tolerated_rollback);
    }
    // A prediction-based acceptance (runtime anchor or confirmation) can hide up to
    // the skew tolerance; synchronized time is an ASSUMPTION needing native evidence
    // (ADR-0006 §13.3 item 4), taken as-is, so the skew share applies only when the
    // platform did not report synchronization.
    if same_boot && input.sync != SyncStatus::Synchronized {
        tolerance = tolerance.saturating_add(input.policy.max_tolerated_skew);
    }
    tolerance
}

fn check_prediction(reference: &TimeAnchor, now: &TimeAnchor, policy: &TimePolicy) -> TimeStatus {
    let Some(continuous_delta) = now.continuous.checked_sub(reference.continuous) else {
        return TimeStatus::Uncertain(TimeUncertainty::ContinuousWentBackwards);
    };
    let wall_delta = now.wall.duration_since(reference.wall);
    // Overflow means a disagreement far beyond any tolerance: fail closed.
    let disagreement = wall_delta
        .checked_sub(signed(continuous_delta))
        .map_or(Duration::MAX, jiff::SignedDuration::unsigned_abs);
    if disagreement > policy.max_tolerated_skew {
        return TimeStatus::Uncertain(TimeUncertainty::Skew {
            wall_delta,
            continuous_delta,
        });
    }
    TimeStatus::Safe
}

/// The high-water mark to persist after `accepted` was assessed `Safe`: the later of
/// the previous mark and the accepted wall time. Never decreases.
#[must_use]
pub fn next_high_water(previous: Option<Timestamp>, accepted: Timestamp) -> Timestamp {
    match previous {
        Some(p) if p > accepted => p,
        _ => accepted,
    }
}

/// A grant's persisted budget anchor (ADR-0005 §3.6 "grant anchor").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAnchor {
    /// Grant.
    pub grant: GrantId,
    /// Paired observation when activated or first validated in this boot.
    pub anchor: TimeAnchor,
    /// Absolute bound `min(deadline, cutoff, parent deadline)` the budget was cut from.
    pub bound: Timestamp,
    /// Continuous reading at which the budget ends in `anchor.boot_id`.
    pub budget_end: Duration,
}

/// Build a grant anchor from an observation assessed `Safe` and the absolute bound:
/// `budget_end = anchor.continuous + (bound − anchor.wall)`; a bound at or before
/// the anchor ends the budget at the anchor.
#[must_use]
pub fn anchor_grant(grant: GrantId, anchor: TimeAnchor, bound: Timestamp) -> GrantAnchor {
    let remaining = Duration::try_from(bound.duration_since(anchor.wall)).unwrap_or(Duration::ZERO);
    let budget_end = anchor.continuous.saturating_add(remaining);
    GrantAnchor {
        grant,
        anchor,
        bound,
        budget_end,
    }
}

/// Like [`anchor_grant`] for an observation accepted **within a tolerance**
/// (design-fix second round R4): the wall clock may lag the truth by up to
/// `tolerance`, so the budget is cut as if the observation were that much later:
/// `budget_end = continuous + (bound − (wall + tolerance))`. The grant may end up to
/// `tolerance` early, never late. Callers `min()` the result with any existing
/// same-boot budget (the store's `set_grant_anchor` refuses to lengthen).
#[must_use]
pub fn anchor_grant_with_tolerance(
    grant: GrantId,
    anchor: TimeAnchor,
    bound: Timestamp,
    tolerance: Duration,
) -> GrantAnchor {
    let pessimistic_wall = anchor
        .wall
        .checked_add(signed(tolerance))
        .unwrap_or(Timestamp::MAX);
    let remaining =
        Duration::try_from(bound.duration_since(pessimistic_wall)).unwrap_or(Duration::ZERO);
    let budget_end = anchor.continuous.saturating_add(remaining);
    GrantAnchor {
        grant,
        anchor,
        bound,
        budget_end,
    }
}

/// Apply a later-set earlier bound (cutoff, parent narrowing; ADR-0005 §3.6 "an
/// earlier cutoff set later shortens it").
///
/// The **existing** budget is reduced by the bound reduction:
/// `budget_end = current.budget_end − (current.bound − new_bound)`, saturating at
/// zero. It is never recomputed from the raw anchor, so a tolerance deduction made
/// when the grant was anchored ([`anchor_grant_with_tolerance`]) is kept (ADR-0006
/// §13.4 N01: recomputing lost that margin and admitted up to the tolerance past
/// the new bound). The result never has a later bound or a longer budget than
/// `current`; a later or equal `new_bound` returns `current` unchanged.
#[must_use]
pub fn shorten(current: &GrantAnchor, new_bound: Timestamp) -> GrantAnchor {
    if new_bound >= current.bound {
        return current.clone();
    }
    // `new_bound < current.bound`, so the reduction is positive; a reduction too
    // large for `Duration` ends the budget (saturating, fail closed).
    let reduction =
        Duration::try_from(current.bound.duration_since(new_bound)).unwrap_or(Duration::MAX);
    GrantAnchor {
        grant: current.grant.clone(),
        anchor: current.anchor.clone(),
        bound: new_bound,
        budget_end: current.budget_end.saturating_sub(reduction),
    }
}

/// Result of the ADR-0005 §3.6 admission-deadline check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Neither deadline branch has passed. Admission still also needs
    /// [`TimeStatus::Safe`] and the grant/generation checks.
    Open,
    /// The admission deadline passed: the wall clock reached the bound, or the
    /// continuous budget ran out. The grant expires (`DeadlineReached`).
    Expired,
    /// The anchor belongs to another boot, so the budget branch cannot be
    /// evaluated. Refuse admission (fail closed) until the runtime re-anchors the
    /// grant from a time assessed `Safe`; this is not an expiry and must not emit
    /// `DeadlineReached`. Only the wall branch has been checked.
    NeedsAnchor,
}

/// ADR-0005 §3.6 admission deadline: expired once **either** (a) the wall clock
/// reaches `anchor.bound`, or (b) the continuous clock reaches `budget_end` in the
/// anchor's boot. Because (b) counts elapsed continuous time, a frozen or
/// stepped-back wall clock cannot extend authority, and sleep counts against the
/// budget. Callers must separately refuse while time is `Uncertain`.
#[must_use]
pub fn admission(grant: &GrantAnchor, now: &TimeAnchor) -> Admission {
    if is_expired(now.wall, grant.bound) {
        return Admission::Expired;
    }
    if grant.anchor.boot_id != now.boot_id {
        return Admission::NeedsAnchor;
    }
    if now.continuous >= grant.budget_end {
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

    // ---- gate / anchors ----------------------------------------------------------

    fn boot(n: u8) -> BootId {
        BootId(format!("boot-{n}"))
    }

    fn at(boot_n: u8, cont_secs: u64, wall: Timestamp) -> TimeAnchor {
        TimeAnchor {
            boot_id: boot(boot_n),
            continuous: Duration::from_secs(cont_secs),
            wall,
        }
    }

    fn plus(t: Timestamp, secs: i64) -> Timestamp {
        t.checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    fn run(
        previous: Option<&TimeAnchor>,
        hw: Option<Timestamp>,
        now: &TimeAnchor,
        sync: SyncStatus,
    ) -> TimeStatus {
        gate(&GateInput {
            previous,
            high_water: hw,
            now,
            sync,
            confirmation: None,
            policy: &TimePolicy::default(),
        })
    }

    #[test]
    fn first_start_needs_synchronized_time() {
        let n = at(1, 10, now());
        assert_eq!(
            run(None, None, &n, SyncStatus::Synchronized),
            TimeStatus::Safe
        );
        assert!(matches!(
            run(None, None, &n, SyncStatus::Unknown),
            TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
        ));
    }

    #[test]
    fn same_boot_prediction_both_directions() {
        let prev = at(1, 100, now());
        let ok = at(1, 160, plus(now(), 60));
        assert_eq!(
            run(Some(&prev), Some(now()), &ok, SyncStatus::Unknown),
            TimeStatus::Safe
        );
        let frozen = at(1, 400, now());
        assert!(matches!(
            run(Some(&prev), Some(now()), &frozen, SyncStatus::Synchronized),
            TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
        ));
        let jumped = at(1, 160, plus(now(), 3600));
        assert!(matches!(
            run(Some(&prev), Some(now()), &jumped, SyncStatus::Synchronized),
            TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
        ));
        let backwards = at(1, 50, plus(now(), 1));
        assert_eq!(
            run(Some(&prev), None, &backwards, SyncStatus::Synchronized),
            TimeStatus::Uncertain(TimeUncertainty::ContinuousWentBackwards)
        );
    }

    #[test]
    fn reboot_needs_mark_and_sync_or_confirmation() {
        let prev = at(1, 100, now());
        let hw = Some(plus(now(), 7200));
        // Above the mark but unsynchronized: refused (stopped 10:00, real 12:00, clock 10:01).
        let rolled = at(2, 5, plus(now(), 7260));
        assert!(matches!(
            run(Some(&prev), hw, &rolled, SyncStatus::NotSynchronized),
            TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
        ));
        // Below the mark: refused even when synchronized.
        let below = at(2, 5, plus(now(), 60));
        assert!(matches!(
            run(Some(&prev), hw, &below, SyncStatus::Synchronized),
            TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
        ));
        // Above the mark and synchronized: accepted.
        let good = at(2, 5, plus(now(), 10_000));
        assert_eq!(
            run(Some(&prev), hw, &good, SyncStatus::Synchronized),
            TimeStatus::Safe
        );
        // Attended confirmation for this boot replaces synchronization.
        let conf = AttendedTimeConfirmation {
            boot_id: boot(2),
            continuous: Duration::from_secs(5),
            wall: plus(now(), 10_000),
            decision: DecisionId::from_random_bytes([1; 16]),
        };
        let later = at(2, 65, plus(now(), 10_060));
        let st = gate(&GateInput {
            previous: Some(&prev),
            high_water: hw,
            now: &later,
            sync: SyncStatus::Unknown,
            confirmation: Some(&conf),
            policy: &TimePolicy::default(),
        });
        assert_eq!(st, TimeStatus::Safe);
    }

    #[test]
    fn high_water_never_decreases() {
        let a = now();
        let b = plus(now(), 10);
        assert_eq!(next_high_water(Some(b), a), b);
        assert_eq!(next_high_water(Some(a), b), b);
        assert_eq!(next_high_water(None, a), a);
    }

    #[test]
    fn budget_only_shortens_and_survives_restart_in_the_same_boot() {
        let g = GrantId::from_random_bytes([2; 16]);
        let anchor = at(1, 1000, now());
        let ga = anchor_grant(g.clone(), anchor, plus(now(), 3600));
        assert_eq!(ga.budget_end, Duration::from_secs(4600));
        let shorter = shorten(&ga, plus(now(), 1800));
        assert_eq!(shorter.budget_end, Duration::from_secs(2800));
        let not_longer = shorten(&shorter, plus(now(), 7200));
        assert_eq!(not_longer, shorter);
        // Same boot, later process: wall stuck, continuous ran past the budget.
        let stuck = at(1, 4600, plus(now(), 5));
        assert_eq!(admission(&ga, &stuck), Admission::Expired);
        let open = at(1, 2000, plus(now(), 1000));
        assert_eq!(admission(&ga, &open), Admission::Open);
        // Other boot: void, fail closed, not an expiry.
        let other = at(2, 0, plus(now(), 1000));
        assert_eq!(admission(&ga, &other), Admission::NeedsAnchor);
        // Wall branch still expires regardless of boot.
        let late = at(2, 0, plus(now(), 3600));
        assert_eq!(admission(&ga, &late), Admission::Expired);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests_rev2 {
    use super::*;

    fn boot(n: u8) -> BootId {
        BootId(format!("boot-{n}"))
    }

    fn at(boot_n: u8, cont_secs: u64, wall: Timestamp) -> TimeAnchor {
        TimeAnchor {
            boot_id: boot(boot_n),
            continuous: Duration::from_secs(cont_secs),
            wall,
        }
    }

    fn t0() -> Timestamp {
        "2026-10-02T00:00:00Z".parse().unwrap()
    }

    fn plus(t: Timestamp, secs: i64) -> Timestamp {
        t.checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn runtime_anchor_rebases_only_on_synchronized_time_within_a_boot() {
        let prev = at(1, 100, t0());
        let later = at(1, 160, plus(t0(), 60));
        assert_eq!(
            next_runtime_anchor(Some(&prev), &later, SyncStatus::Unknown),
            prev
        );
        assert_eq!(
            next_runtime_anchor(Some(&prev), &later, SyncStatus::NotSynchronized),
            prev
        );
        assert_eq!(
            next_runtime_anchor(Some(&prev), &later, SyncStatus::Synchronized),
            later
        );
        let other_boot = at(2, 5, plus(t0(), 7200));
        assert_eq!(
            next_runtime_anchor(Some(&prev), &other_boot, SyncStatus::Unknown),
            other_boot
        );
        assert_eq!(
            next_runtime_anchor(None, &later, SyncStatus::Unknown),
            later
        );
    }

    #[test]
    fn later_same_boot_confirmation_becomes_the_prediction_reference() {
        let policy = TimePolicy::default();
        let prev = at(1, 100, t0());
        // Wall jumped an hour: skew against `prev`.
        let jumped = at(1, 160, plus(t0(), 3660));
        let before = gate(&GateInput {
            previous: Some(&prev),
            high_water: Some(t0()),
            now: &jumped,
            sync: SyncStatus::Unknown,
            confirmation: None,
            policy: &policy,
        });
        assert!(matches!(
            before,
            TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
        ));
        // The owner confirms the jumped time; it is later than `prev`, so it wins.
        let conf = AttendedTimeConfirmation {
            boot_id: boot(1),
            continuous: Duration::from_secs(160),
            wall: plus(t0(), 3660),
            decision: DecisionId::from_random_bytes([3; 16]),
        };
        let after = at(1, 190, plus(t0(), 3690));
        let status = gate(&GateInput {
            previous: Some(&prev),
            high_water: Some(t0()),
            now: &after,
            sync: SyncStatus::Unknown,
            confirmation: Some(&conf),
            policy: &policy,
        });
        assert_eq!(status, TimeStatus::Safe);
        assert_eq!(
            accepted_tolerance(&GateInput {
                previous: Some(&prev),
                high_water: Some(t0()),
                now: &after,
                sync: SyncStatus::Unknown,
                confirmation: Some(&conf),
                policy: &policy,
            }),
            policy.max_tolerated_skew
        );
    }

    #[test]
    fn tolerance_anchor_ends_early_never_late() {
        let g = GrantId::from_random_bytes([4; 16]);
        let anchor = at(1, 1000, t0());
        let exact = anchor_grant(g.clone(), anchor.clone(), plus(t0(), 3600));
        let tolerant =
            anchor_grant_with_tolerance(g, anchor, plus(t0(), 3600), Duration::from_secs(60));
        assert_eq!(exact.budget_end, Duration::from_secs(4600));
        assert_eq!(tolerant.budget_end, Duration::from_secs(4540));
        assert!(tolerant.budget_end <= exact.budget_end);
    }

    #[test]
    fn accepted_tolerance_is_zero_for_clean_synchronized_acceptance() {
        let policy = TimePolicy::default();
        let now = at(2, 5, plus(t0(), 10_000));
        let input = GateInput {
            previous: None,
            high_water: Some(plus(t0(), 7200)),
            now: &now,
            sync: SyncStatus::Synchronized,
            confirmation: None,
            policy: &policy,
        };
        assert_eq!(gate(&input), TimeStatus::Safe);
        assert_eq!(accepted_tolerance(&input), Duration::ZERO);
        // N05: after a reboot (no same-boot reference) 3 s below the mark is refused
        // even when synchronized, and carries no rollback share.
        let below = at(2, 5, plus(t0(), 7197));
        let input = GateInput {
            now: &below,
            ..input
        };
        assert!(matches!(
            gate(&input),
            TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
        ));
        assert_eq!(accepted_tolerance(&input), Duration::ZERO);
        // Within a boot (same-boot runtime anchor) the same deficit is tolerated and
        // the rollback share counts.
        let prev = at(2, 1, plus(t0(), 7193));
        let input = GateInput {
            previous: Some(&prev),
            ..input
        };
        assert_eq!(gate(&input), TimeStatus::Safe);
        assert_eq!(accepted_tolerance(&input), policy.max_tolerated_rollback);
    }

    /// N05: a synchronized reboot slightly below the mark is `Uncertain`; an attended
    /// confirmation for this boot resolves it (rollback tolerance then applies within
    /// the boot).
    #[test]
    fn reboot_below_mark_is_uncertain_until_confirmed() {
        let policy = TimePolicy::default();
        let prev = at(1, 100, t0());
        let mark = plus(t0(), 7200);
        let now = at(2, 10, plus(t0(), 7196));
        let input = GateInput {
            previous: Some(&prev),
            high_water: Some(mark),
            now: &now,
            sync: SyncStatus::Synchronized,
            confirmation: None,
            policy: &policy,
        };
        assert!(matches!(
            gate(&input),
            TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
        ));
        let conf = AttendedTimeConfirmation {
            boot_id: boot(2),
            continuous: Duration::from_secs(10),
            wall: plus(t0(), 7196),
            decision: DecisionId::from_random_bytes([5; 16]),
        };
        let input = GateInput {
            confirmation: Some(&conf),
            ..input
        };
        assert_eq!(gate(&input), TimeStatus::Safe);
        assert_eq!(accepted_tolerance(&input), policy.max_tolerated_rollback);
    }

    /// N01 regression (reviewer's counterexample): a tolerance-adjusted budget keeps
    /// its margin when shortened.
    #[test]
    fn shorten_keeps_the_tolerance_margin() {
        let g = GrantId::from_random_bytes([6; 16]);
        let anchor = at(1, 0, t0());
        let ga = anchor_grant_with_tolerance(g, anchor, plus(t0(), 3600), Duration::from_secs(60));
        assert_eq!(ga.budget_end, Duration::from_secs(3540));
        let narrowed = shorten(&ga, plus(t0(), 3570));
        assert_eq!(narrowed.bound, plus(t0(), 3570));
        assert_eq!(narrowed.budget_end, Duration::from_secs(3510));
        // Saturates at zero, never wraps.
        let gone = shorten(&ga, plus(t0(), -100_000));
        assert_eq!(gone.budget_end, Duration::ZERO);
        // Later bound: unchanged.
        assert_eq!(shorten(&ga, plus(t0(), 9999)), ga);
    }
}
