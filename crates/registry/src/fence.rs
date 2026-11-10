//! The reconcile classification and fencing view (ADR-0008 D5 §6.3, §6.7; m03-plan
//! U5): [`classify_reconcile`], [`not_after_remote`] and [`late_write_cleared`].
//!
//! **Fencing first** (D5 §6.7). The reconcile reads the lock in the latest `inspect`
//! before it reads the marker:
//! * no lock, or another enrollment's lock (or a record that is not a holder record):
//!   classify directly; that lock is never touched;
//! * a lock carrying **this** step's token: [`ReconcileClass::Fence`] until `fence` has
//!   run. Its result ([`FenceView`]) decides: `gone` (the link was removed) → classify
//!   the next inspect; `alive` before the step's not-after → wait (nothing decided, no
//!   attempt counted); `alive` after it → [`ReconcileClass::Terminate`]; still `alive`
//!   after `--terminate`, or `unproven` → the attempt counts, and after
//!   [`HOLDER_TERMINATION_ATTEMPTS`] reconciles the record is `held`
//!   (`lock_holder_unresolved`). **`unproven` (exit 44) never unlocks, never signals
//!   again and never redispatches**; the signals it already sent stay in its
//!   [`FenceSignals`].
//!
//! **The observation table** (after fencing; for a removal or rollback "marker absent"
//! means applied; §17.15 X-Q2: §6.7's "damaged" applies to a removal too):
//!
//! | Observation | Append | Removal / rollback |
//! |---|---|---|
//! | exactly one marker line, equal to the line | `Applied` | redispatch when proven gone |
//! | no marker line | redispatch only when proven gone, approval valid, attended, route unchanged; `ApprovalLapsed` when the approval lapsed | `Applied` |
//! | a marker line differs, or more than one | `Damaged` | `Damaged` |
//! | no usable reading | `Unresolved` | `Unresolved` |
//!
//! **Proven gone** means: `fence` removed this step's lock, or the latest inspect
//! shows no lock of this step **and** its remote clock reading is past the step's
//! not-after (the script can no longer pass its own checks). An absence read alone
//! never authorizes a redispatch. `--after-manual-recovery` classifies only (one exact
//! line, or none), never fences and never redispatches.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_domain::enrollment::LateWrite;

use crate::classify::{FileKind, HolderRecord, Inspection, LockReading, ReadingError, token_ok};
use crate::hm1::{ExitCode, Hm1Key, Hm1Record};
use crate::line::{lines, marker_lines, marker_of};

/// Reconciles that try to prove a holder gone before the record is `held`
/// (`holder_termination_attempts`; m03-plan §5 item 17).
pub const HOLDER_TERMINATION_ATTEMPTS: u32 = 3;

/// A mutating step needs a remote reading younger than this
/// (`enrollment_inspect_max_age`).
pub const INSPECT_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Added to the step timeout for the remote not-after
/// (`enrollment_not_after_allowance`).
pub const NOT_AFTER_ALLOWANCE: Duration = Duration::from_secs(60);

/// Added to timeout + allowance for the hard deadline
/// (`enrollment_step_hard_deadline`).
pub const HARD_DEADLINE_MARGIN: Duration = Duration::from_secs(30);

// --- the fence's own reading ----------------------------------------------------------

/// One `fence=` decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FenceDecision {
    /// The holder's process group is proven gone.
    Gone,
    /// The holder's group is live by agreement.
    Alive,
    /// Not proven either way.
    Unproven,
    /// No lock.
    None,
}

/// The signals a `fence --terminate` already sent (`fence_signals`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FenceSignals {
    /// None.
    #[default]
    None,
    /// `TERM`.
    Term,
    /// `TERM,KILL`.
    TermKill,
}

impl FenceSignals {
    /// The wire value (``, `TERM`, `TERM,KILL`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FenceSignals::None => "",
            FenceSignals::Term => "TERM",
            FenceSignals::TermKill => "TERM,KILL",
        }
    }

    /// Whether any signal was sent.
    #[must_use]
    pub fn any(self) -> bool {
        self != FenceSignals::None
    }
}

/// A `fence` result: the decisions in order (the last is final), the signals sent,
/// the holder record, the remote clock and the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceReading {
    /// Every `fence=` decision, in order.
    pub decisions: Vec<FenceDecision>,
    /// The signals sent (kept in the step result and the `enrollment.fence` audit
    /// event, whatever the decision).
    pub signals: FenceSignals,
    /// The holder record the fence read.
    pub holder: Option<HolderRecord>,
    /// The remote clock reading.
    pub remote_now: Option<i64>,
    /// The exit code (`None`: not one of the protocol's).
    pub exit: Option<ExitCode>,
}

impl FenceReading {
    /// Read a `fence` record and its exit status.
    ///
    /// # Errors
    /// [`ReadingError`] for a repeated `fence_signals`, `lock_holder` or `remote_now`,
    /// or a value that does not parse.
    pub fn from_record(rec: &Hm1Record, exit_status: i32) -> Result<FenceReading, ReadingError> {
        let once = |key| rec.single(key).map_err(|_| ReadingError::Repeated(key));
        let decisions = rec
            .all(Hm1Key::Fence)
            .map(|v| match v {
                "gone" => FenceDecision::Gone,
                "alive" => FenceDecision::Alive,
                "none" => FenceDecision::None,
                _ => FenceDecision::Unproven,
            })
            .collect();
        let signals = match once(Hm1Key::FenceSignals)? {
            None | Some("") => FenceSignals::None,
            Some("TERM") => FenceSignals::Term,
            Some(_) => FenceSignals::TermKill,
        };
        let holder = match once(Hm1Key::LockHolder)? {
            Some(text) => Some(
                HolderRecord::parse(text).ok_or(ReadingError::Inconsistent(Hm1Key::LockHolder))?,
            ),
            None => None,
        };
        let remote_now = match once(Hm1Key::RemoteNow)? {
            Some(v) => Some(
                v.parse::<i64>()
                    .map_err(|_| ReadingError::Inconsistent(Hm1Key::RemoteNow))?,
            ),
            None => None,
        };
        Ok(FenceReading {
            decisions,
            signals,
            holder,
            remote_now,
            exit: ExitCode::from_status(exit_status),
        })
    }

    /// The final decision.
    #[must_use]
    pub fn decision(&self) -> Option<FenceDecision> {
        self.decisions.last().copied()
    }

    /// What the reconcile knows about this step's lock after this fence run.
    /// `terminate` says whether the run was `--terminate`. Fail closed: an exit code
    /// that does not match its decision is [`OurLock::Unproven`].
    #[must_use]
    pub fn lock_view(&self, terminate: bool) -> LockView {
        let not_after_passed = match (&self.holder, self.remote_now) {
            (Some(h), Some(now)) => now > h.not_after,
            _ => false,
        };
        match (self.exit, self.decision()) {
            (Some(ExitCode::Ok), Some(FenceDecision::Gone)) => LockView::Ours(OurLock::Gone),
            (Some(ExitCode::Ok), Some(FenceDecision::None)) => LockView::None,
            (Some(ExitCode::Busy), _) if !self.signals.any() => LockView::Other,
            (Some(ExitCode::HolderAlive), Some(FenceDecision::Alive)) => {
                LockView::Ours(OurLock::Alive {
                    not_after_passed,
                    terminated: terminate && self.signals.any(),
                })
            }
            _ => LockView::Ours(OurLock::Unproven {
                signals: self.signals,
            }),
        }
    }
}

// --- the fencing view -----------------------------------------------------------------

/// This step's lock, as the fence runs of this reconcile left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OurLock {
    /// `fence` has not run on it yet.
    Unfenced,
    /// `fence` proved the holder gone and removed the link.
    Gone,
    /// The holder is alive.
    Alive {
        /// The holder's not-after has passed on the remote clock.
        not_after_passed: bool,
        /// `--terminate` already sent its signals in this reconcile.
        terminated: bool,
    },
    /// The proof failed (exit 44): no unlock, no further signal.
    Unproven {
        /// What was already sent.
        signals: FenceSignals,
    },
}

/// The lock as the reconcile knows it (m03-plan U5 `FenceView.lock`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockView {
    /// No lock.
    #[default]
    None,
    /// Another enrollment's lock (or a record that is not a holder record).
    Other,
    /// This step's lock.
    Ours(OurLock),
}

/// The fencing facts of one reconcile (m03-plan U5 `FenceView { lock, attempts }`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FenceView {
    /// The lock.
    pub lock: LockView,
    /// Earlier reconciles of this operation that ended without a proof.
    pub attempts: u32,
}

impl FenceView {
    /// The lock an inspect shows, before any fence run: this step's (by token),
    /// another's, or none.
    #[must_use]
    pub fn shown(inspection: &Inspection, step_token: &str) -> LockView {
        match &inspection.lock {
            LockReading::None => LockView::None,
            LockReading::Held(h) if h.token == step_token => LockView::Ours(OurLock::Unfenced),
            _ => LockView::Other,
        }
    }
}

// --- the classification ---------------------------------------------------------------

/// Which step is being reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReconcilePurpose {
    /// An append (`outcome_unknown`).
    Append,
    /// A failed verification's rollback (`rollback_unknown`).
    Rollback,
    /// An explicit removal (`remove_unknown`), own or foreign.
    Removal,
    /// An uncertain bootstrap (D5 §6.4 E2b): present and checked continues at E3;
    /// absent may run again.
    Bootstrap,
}

/// What the reconcile expects, and the redispatch conditions (Q7 as amended).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileExpected<'a> {
    /// The step's purpose.
    pub purpose: ReconcilePurpose,
    /// The exact registry line (its last field is the marker).
    pub line: &'a str,
    /// The uncertain step's token.
    pub step_token: &'a str,
    /// The uncertain step's remote not-after (`None`: no lock was taken, bootstrap).
    pub not_after_remote: Option<i64>,
    /// The approval is within its validity (24 h, safe time).
    pub approval_valid: bool,
    /// The session is attended (F20).
    pub attended: bool,
    /// The route re-evaluation found the same approved target, endpoint and effect.
    pub route_unchanged: bool,
    /// `--after-manual-recovery`: classify only.
    pub after_manual_recovery: bool,
}

/// What reconcile observed (the latest `inspect`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Observation {
    /// Unreachable, authentication failed, the provider locked, or no usable reading.
    Unavailable,
    /// An `inspect` reading.
    Inspected(Box<Inspection>),
}

/// Why nothing was decided (the state stays).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnresolvedReason {
    /// No usable reading.
    Unreachable,
    /// The registry cannot be read (a symlink, another kind, an inconsistent count).
    Unreadable,
    /// The fence view and the reading disagree; inspect and fence again.
    Inconsistent,
    /// This step's holder is alive and its not-after has not passed: next reconcile
    /// after the hard deadline.
    HolderAlive,
    /// The holder is still alive after `--terminate` (counted).
    StillAlive,
    /// The proof failed (counted).
    Unproven,
    /// The marker shows not applied, but the holder is not proven gone yet.
    HolderNotProvenGone,
    /// The route, endpoint or effect changed (`route_changed`).
    RouteChanged,
    /// A redispatch of an append needs an attended session.
    NotAttended,
    /// After manual recovery, this step's lock is still there.
    LockStillHeld,
    /// The bootstrap's directory exists but is not private or not ours.
    NotManageable,
}

/// The reconcile class (D5 §6.7; m03-plan U5 `ReconcileClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReconcileClass {
    /// Applied (event `ReconcileApplied`).
    Applied,
    /// A redispatch is authorized (event `ReconcileRedispatch`).
    Redispatch,
    /// Damaged: `held`, `registry_line_damaged` (event `ReconcileDamaged`).
    Damaged,
    /// Append not applied after fencing and the approval lapsed: `withdrawn` with the
    /// `late_write` residual (`DECISION_STALE`, `approval_lapsed`).
    ApprovalLapsed,
    /// Run `fence` on this step's lock.
    Fence,
    /// Run `fence --terminate` (alive past its not-after).
    Terminate,
    /// `lock_holder_unresolved` after the attempts: `held` (event `HolderUnresolved`).
    HolderUnresolved,
    /// Manual recovery found one exact line.
    ManualRecoveryLinePresent,
    /// Manual recovery found no marker line.
    ManualRecoveryLineAbsent,
    /// Nothing decided; the state stays (event `ReconcileUnresolved`).
    Unresolved(UnresolvedReason),
}

impl ReconcileClass {
    /// Whether this class authorizes a redispatch.
    #[must_use]
    pub fn redispatches(self) -> bool {
        self == ReconcileClass::Redispatch
    }

    /// Whether this reconcile counts toward [`HOLDER_TERMINATION_ATTEMPTS`].
    #[must_use]
    pub fn counts_attempt(self) -> bool {
        matches!(
            self,
            ReconcileClass::Unresolved(UnresolvedReason::Unproven | UnresolvedReason::StillAlive)
                | ReconcileClass::HolderUnresolved
        )
    }
}

/// The marker state of a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineState {
    Exact,
    Absent,
    Damaged,
    Unreadable,
}

fn line_state(inspection: &Inspection, line: &str) -> LineState {
    let Some(marker) = marker_of(line) else {
        return LineState::Unreadable;
    };
    let Some(content) = inspection.preimage() else {
        return LineState::Unreadable;
    };
    let count = marker_lines(content, marker);
    if u64::try_from(count).ok() != Some(inspection.marker_lines) {
        return LineState::Unreadable;
    }
    let exact = lines(content).filter(|l| *l == line.as_bytes()).count();
    match (count, exact) {
        (0, _) => LineState::Absent,
        (1, 1) => LineState::Exact,
        _ => LineState::Damaged,
    }
}

fn failed_attempt(view: FenceView, reason: UnresolvedReason) -> ReconcileClass {
    if view.attempts.saturating_add(1) >= HOLDER_TERMINATION_ATTEMPTS {
        ReconcileClass::HolderUnresolved
    } else {
        ReconcileClass::Unresolved(reason)
    }
}

/// Classify a reconcile (module docs: fencing first, then the D5 §6.7 table).
#[must_use]
pub fn classify_reconcile(
    observation: &Observation,
    expected: &ReconcileExpected<'_>,
    fence: FenceView,
) -> ReconcileClass {
    use ReconcileClass as C;
    use UnresolvedReason as U;
    let Observation::Inspected(inspection) = observation else {
        return C::Unresolved(U::Unreachable);
    };
    if !token_ok(expected.step_token) {
        return C::Unresolved(U::Inconsistent);
    }
    let shown = FenceView::shown(inspection, expected.step_token);
    let ours_shown = matches!(shown, LockView::Ours(_));

    if expected.after_manual_recovery {
        if ours_shown {
            return C::Unresolved(U::LockStillHeld);
        }
        return match (expected.purpose, line_state(inspection, expected.line)) {
            (ReconcilePurpose::Bootstrap, _) => C::Unresolved(U::Inconsistent),
            (_, LineState::Exact) => C::ManualRecoveryLinePresent,
            (_, LineState::Absent) => C::ManualRecoveryLineAbsent,
            (_, LineState::Damaged) => C::Damaged,
            (_, LineState::Unreadable) => C::Unresolved(U::Unreadable),
        };
    }

    // Fencing first.
    let proven_gone = if ours_shown {
        return match fence.lock {
            LockView::None | LockView::Other | LockView::Ours(OurLock::Unfenced) => C::Fence,
            LockView::Ours(OurLock::Gone) => C::Unresolved(U::Inconsistent),
            LockView::Ours(OurLock::Alive {
                not_after_passed: false,
                terminated: false,
            }) => C::Unresolved(U::HolderAlive),
            LockView::Ours(OurLock::Alive {
                not_after_passed: true,
                terminated: false,
            }) => C::Terminate,
            LockView::Ours(OurLock::Alive {
                terminated: true, ..
            }) => failed_attempt(fence, U::StillAlive),
            LockView::Ours(OurLock::Unproven { .. }) => failed_attempt(fence, U::Unproven),
        };
    } else {
        match fence.lock {
            LockView::Ours(OurLock::Gone) => true,
            // The fence saw this step's holder alive or unproven, and the lock has
            // since gone: never read as proof.
            LockView::Ours(OurLock::Alive { .. } | OurLock::Unproven { .. }) => {
                return C::Unresolved(U::Inconsistent);
            }
            // ⟨integrator, wave-1 review finding 3⟩ A held lock whose record cannot be
            // read (`HeldForeign`) may be this step's, rendered differently: its holder
            // could be paused past its final re-check, so the not-after alone never
            // proves it gone (as in `late_write_cleared`).
            LockView::None | LockView::Other | LockView::Ours(OurLock::Unfenced) => {
                !matches!(inspection.lock, LockReading::HeldForeign)
                    && expected
                        .not_after_remote
                        .is_some_and(|na| inspection.remote_now > na)
            }
        }
    };

    if expected.purpose == ReconcilePurpose::Bootstrap {
        let checked = inspection.dir_mode.as_deref() == Some("drwx------")
            && inspection.dir_owner_self == Some(true);
        return match inspection.dir {
            crate::classify::DirState::Present if checked => C::Applied,
            crate::classify::DirState::Present => C::Unresolved(U::NotManageable),
            _ if !expected.approval_valid => C::ApprovalLapsed,
            _ if !expected.route_unchanged => C::Unresolved(U::RouteChanged),
            _ if !expected.attended => C::Unresolved(U::NotAttended),
            _ => C::Redispatch,
        };
    }

    let state = line_state(inspection, expected.line);
    match (expected.purpose, state) {
        (_, LineState::Unreadable) => C::Unresolved(U::Unreadable),
        (_, LineState::Damaged) => C::Damaged,
        (ReconcilePurpose::Append, LineState::Exact) => C::Applied,
        (ReconcilePurpose::Append, LineState::Absent) => {
            if !expected.approval_valid {
                C::ApprovalLapsed
            } else if !proven_gone {
                C::Unresolved(U::HolderNotProvenGone)
            } else if !expected.route_unchanged {
                C::Unresolved(U::RouteChanged)
            } else if !expected.attended {
                C::Unresolved(U::NotAttended)
            } else {
                C::Redispatch
            }
        }
        (_, LineState::Absent) => C::Applied,
        (_, LineState::Exact) => {
            if !proven_gone {
                C::Unresolved(U::HolderNotProvenGone)
            } else if !expected.route_unchanged {
                C::Unresolved(U::RouteChanged)
            } else {
                C::Redispatch
            }
        }
    }
}

// --- the not-after and the late-write residual ----------------------------------------

/// Why no not-after was computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum NotAfterError {
    /// The reading arrived after the issue instant (the inputs are swapped).
    #[error("the remote reading arrived after the step was issued")]
    ReadingAfterIssue,
    /// The reading is older than [`INSPECT_MAX_AGE`]: inspect first.
    #[error("the remote reading is older than the inspect maximum age")]
    StaleReading,
    /// The reading is negative, or the sum overflows.
    #[error("the remote not-after is out of range")]
    OutOfRange,
}

/// The step's remote not-after (D5 §6.3): `T + (c_issue − c_read) + timeout + 60 s`,
/// with `T` the latest inspect's remote reading (epoch seconds), `c_read` the local
/// continuous time its reading arrived and `c_issue` the step's issue time. The
/// elapsed time and the timeout are rounded **down** to seconds, so the not-after is
/// never later than the formula; the remote clock passes it by the hard deadline
/// ([`step_hard_deadline`]) with at least 30 s to spare.
///
/// # Errors
/// [`NotAfterError`].
pub fn not_after_remote(
    inspect_reading: i64,
    c_read: Duration,
    c_issue: Duration,
    timeout: Duration,
) -> Result<i64, NotAfterError> {
    let age = c_issue
        .checked_sub(c_read)
        .ok_or(NotAfterError::ReadingAfterIssue)?;
    if age > INSPECT_MAX_AGE {
        return Err(NotAfterError::StaleReading);
    }
    if inspect_reading < 0 {
        return Err(NotAfterError::OutOfRange);
    }
    let add = age
        .as_secs()
        .checked_add(timeout.as_secs())
        .and_then(|s| s.checked_add(NOT_AFTER_ALLOWANCE.as_secs()))
        .and_then(|s| i64::try_from(s).ok())
        .ok_or(NotAfterError::OutOfRange)?;
    inspect_reading
        .checked_add(add)
        .ok_or(NotAfterError::OutOfRange)
}

/// The step's hard deadline on the continuous clock: issue + timeout + 60 s + 30 s
/// (`None` on overflow).
#[must_use]
pub fn step_hard_deadline(c_issue: Duration, timeout: Duration) -> Option<Duration> {
    c_issue
        .checked_add(timeout)?
        .checked_add(NOT_AFTER_ALLOWANCE)?
        .checked_add(HARD_DEADLINE_MARGIN)
}

/// A step's hard deadline as persisted (D5 §6.3 "Bounds"; B R2-11): the continuous
/// value, the wall-clock deadline and the boot it was taken in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HardDeadline {
    /// The deadline on the runtime's continuous clock.
    pub continuous: Duration,
    /// The wall-clock deadline.
    pub wall: Timestamp,
    /// The local boot ID the continuous value belongs to.
    pub boot_id: String,
}

/// The local clocks now, for [`hard_deadline_passed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineNow<'a> {
    /// The local boot ID.
    pub boot_id: &'a str,
    /// The continuous clock.
    pub continuous: Duration,
    /// **Safe** wall time (`None` until `time confirm` after a reboot; Q13).
    pub safe_wall: Option<Timestamp>,
}

/// Whether a hard deadline has passed (D5 §6.3): in the same boot, on the continuous
/// clock; after a reboot the continuous value is void, and the deadline passes only
/// once **safe** wall time is past the wall deadline. Without safe time it has not
/// passed.
#[must_use]
pub fn hard_deadline_passed(deadline: &HardDeadline, now: &DeadlineNow<'_>) -> bool {
    if !deadline.boot_id.is_empty() && now.boot_id == deadline.boot_id {
        now.continuous > deadline.continuous
    } else {
        now.safe_wall.is_some_and(|wall| wall > deadline.wall)
    }
}

/// Whether `inspect` clears the `late_write` residual (D5 §6.7): its remote clock
/// reading is past the residual's not-after, the registry is readable and no line
/// contains `marker`, and no lock with the residual's token (nor an unreadable lock
/// record, which could be it) is present.
#[must_use]
pub fn late_write_cleared(inspect: &Inspection, residual: &LateWrite, marker: &str) -> bool {
    if inspect.remote_now <= residual.not_after_remote {
        return false;
    }
    let lock_clear = match &inspect.lock {
        LockReading::None => true,
        LockReading::Held(h) => h.token != residual.step_token,
        LockReading::HeldForeign => false,
    };
    let readable = matches!(inspect.file, FileKind::Regular | FileKind::Absent);
    let absent = inspect
        .preimage()
        .is_some_and(|c| marker_lines(c, marker) == 0)
        && inspect.marker_lines == 0;
    lock_clear && readable && absent
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn not_after_and_hard_deadline() {
        let t = 1_700_000_000;
        let na = not_after_remote(
            t,
            Duration::from_millis(1_000),
            Duration::from_millis(3_999),
            Duration::from_secs(120),
        )
        .unwrap();
        assert_eq!(na, t + 2 + 120 + 60);
        assert_eq!(
            not_after_remote(
                t,
                Duration::from_secs(5),
                Duration::from_secs(1),
                Duration::ZERO
            ),
            Err(NotAfterError::ReadingAfterIssue)
        );
        assert_eq!(
            not_after_remote(
                t,
                Duration::ZERO,
                INSPECT_MAX_AGE + Duration::from_secs(1),
                Duration::ZERO
            ),
            Err(NotAfterError::StaleReading)
        );
        assert_eq!(
            step_hard_deadline(Duration::from_secs(10), Duration::from_secs(120)),
            Some(Duration::from_secs(220))
        );
    }
}
