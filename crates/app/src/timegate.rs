//! The one shared time gate (ADR-0005 §3.6; review F01; overview §5).
//!
//! Every admission, signature and issuance passes through [`TimeGate::check`]. It
//! reads the persisted runtime anchor, the high-water mark and any attended
//! confirmation from the store, observes the injected [`Clock`] and [`TimeSync`],
//! runs the pure `heimdall_domain::time::gate`, and on `Safe` persists, in the same
//! transaction, the high-water mark (`next_high_water`) and the runtime anchor
//! chosen by `next_runtime_anchor` (design-fix second round R2: within a boot the
//! anchor is re-based only on synchronized time; otherwise the previous reference
//! is kept so drift accumulates and a frozen or slowly wrong wall clock becomes
//! `TIME_UNCERTAIN` even when checked often; with the M01 platform stubs reporting
//! `Unknown` a long uptime may reach that state, and an attended `ConfirmTime`
//! resolves it). On `Uncertain` it persists nothing and the caller returns
//! `TIME_UNCERTAIN`.
//!
//! An accepted attended confirmation installs a new runtime anchor for this boot
//! ([`TimeGate::confirm_attended`]; R3), so a same-boot skew is cleared by it; it
//! never moves a deadline or rebuilds a budget.
//!
//! Grant budgets are re-anchored only from a `Safe` observation
//! ([`TimeGate::anchor_grant`]), cut by the tolerance the gate used to accept it
//! (`SafeNow::tolerance_used`, `anchor_grant_with_tolerance`; R4: up to the
//! tolerance early, never late) and `min()`'d with any existing same-boot budget,
//! then only shortened afterwards ([`TimeGate::shorten_grant`]); `admission` is
//! evaluated against the persisted `GrantAnchor`, never against a budget rebuilt
//! from the wall clock.
//!
//! Wiring choices (M01-U5t):
//!
//! * Every store access runs on the blocking pool (overview §4) inside one store
//!   transaction, and the clock is observed **inside** that transaction, so two
//!   concurrent passes are serialized by the store and never assess an older
//!   observation against an anchor written by a newer one.
//! * The store returns the latest confirmation without knowing the current boot
//!   (R7); the gate compares its `boot_id` with the observation's boot before using
//!   it.
//! * [`TimeGate::confirm_attended`] refuses (persisting nothing) when the owner's
//!   value disagrees with the clock by more than `max_tolerated_skew`, and when the
//!   clock is below the high-water mark by more than `max_tolerated_rollback`: the
//!   gate's rule 1 refuses such a clock whatever the confirmation, so recording one
//!   could not make time `Safe`.
//! * [`TimeGate::admission`] also evaluates the persisted anchor at a fresh clock
//!   reading and returns the more restrictive verdict, so a stale [`SafeNow`] can
//!   never admit past the budget or the bound.
//! * The same gate also runs **inside a caller's store transaction**
//!   (`TimeGate::in_txn`, crate-private; code review A01/A02): the application's
//!   transactions that reserve, publish, authorize an effect attempt, activate,
//!   bind, or create or complete a decision record assess a fresh observation in
//!   that very transaction instead of carrying a [`SafeNow`] across asynchronous
//!   work. `check`, `peek`, `anchor_grant` and `admission` are thin wrappers over
//!   it.

use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Code;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DecisionId, GrantId};
use heimdall_domain::time::{
    self as dtime, Admission, AttendedTimeConfirmation, Clock, GateInput, GrantAnchor, SyncStatus,
    TimeAnchor, TimePolicy, TimeStatus, TimeSync, TimeUncertainty,
};
use heimdall_store::{Store, Txn};

use crate::error::OpError;

/// A `Safe` observation accepted by the gate; the only way to obtain a `now` for
/// admission, issuance or signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeNow {
    /// The accepted observation.
    pub anchor: TimeAnchor,
    /// Sync report at the time of acceptance (for evidence).
    pub sync: SyncStatus,
    /// How far the accepted wall time may lag the truth
    /// (`heimdall_domain::time::accepted_tolerance`); budgets cut from this
    /// observation subtract it (R4).
    pub tolerance_used: Duration,
}

impl SafeNow {
    /// Wall time of the accepted observation.
    #[must_use]
    pub fn wall(&self) -> Timestamp {
        self.anchor.wall
    }
}

/// The shared gate.
pub struct TimeGate {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    sync: Arc<dyn TimeSync>,
    policy: TimePolicy,
}

impl std::fmt::Debug for TimeGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeGate")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Everything one gate pass looked at, and its verdict.
struct Assessment {
    now: TimeAnchor,
    sync: SyncStatus,
    previous: Option<TimeAnchor>,
    status: TimeStatus,
    tolerance: Duration,
}

/// Owned handles moved onto the blocking pool.
struct Parts {
    store: Arc<Store>,
    gate: TxnGate,
}

/// The gate run **inside a caller's store transaction** (code review A01/A02):
/// the transaction that reserves, publishes, authorizes an effect attempt,
/// activates, binds or records a decision observes the clock and assesses it in
/// that same transaction, so no accepted time is carried across asynchronous work
/// into the transaction that acts on it. Same rules and persistence as
/// [`TimeGate::check`]: on `Safe` the high-water mark and the runtime anchor are
/// written in the caller's transaction (they commit or roll back with it); on
/// `Uncertain` nothing is written. Cloneable so it moves into store closures.
#[derive(Clone)]
pub(crate) struct TxnGate {
    clock: Arc<dyn Clock>,
    sync: Arc<dyn TimeSync>,
    policy: TimePolicy,
}

impl std::fmt::Debug for TxnGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxnGate")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl TxnGate {
    /// The clock this gate observes.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Observe and assess inside `txn` (reads only).
    fn assess(&self, txn: &mut Txn<'_>) -> heimdall_store::Result<Assessment> {
        let previous = txn.runtime_anchor()?;
        let high_water = txn.high_water_mark()?;
        let now = self.clock.observe();
        let sync = self.sync.status();
        // R7: the store does not know the current boot; a confirmation from another
        // boot never covers this one.
        let confirmation = txn
            .time_confirmation()?
            .filter(|c| c.boot_id == now.boot_id);
        let input = GateInput {
            previous: previous.as_ref(),
            high_water,
            now: &now,
            sync,
            confirmation: confirmation.as_ref(),
            policy: &self.policy,
        };
        let status = dtime::gate(&input);
        let tolerance = dtime::accepted_tolerance(&input);
        Ok(Assessment {
            now,
            sync,
            previous,
            status,
            tolerance,
        })
    }

    /// [`TimeGate::check`] inside `txn`: a fresh observation, assessed; on `Safe`
    /// the mark and the runtime anchor are persisted in `txn`.
    pub(crate) fn check(
        &self,
        txn: &mut Txn<'_>,
    ) -> heimdall_store::Result<Result<SafeNow, TimeUncertainty>> {
        let a = self.assess(txn)?;
        match a.status {
            TimeStatus::Safe => {
                // R2: the mark advances on every Safe pass; the anchor is re-based
                // only as next_runtime_anchor says.
                txn.raise_high_water_mark(a.now.wall)?;
                let next = dtime::next_runtime_anchor(a.previous.as_ref(), &a.now, a.sync);
                if a.previous.as_ref() != Some(&next) {
                    txn.set_runtime_anchor(&next)?;
                }
                Ok(Ok(SafeNow {
                    anchor: a.now,
                    sync: a.sync,
                    tolerance_used: a.tolerance,
                }))
            }
            TimeStatus::Uncertain(u) => Ok(Err(u)),
        }
    }

    /// [`TimeGate::anchor_grant`] inside `txn`. `None` when `now` belongs to
    /// another boot (it cannot anchor a budget here).
    pub(crate) fn anchor_grant(
        &self,
        txn: &mut Txn<'_>,
        grant: &GrantId,
        now: &SafeNow,
        bound: Timestamp,
    ) -> heimdall_store::Result<Option<GrantAnchor>> {
        if self.clock.boot_id() != now.anchor.boot_id {
            return Ok(None);
        }
        // R4: cut from the accepted observation minus the tolerance used.
        let fresh = dtime::anchor_grant_with_tolerance(
            grant.clone(),
            now.anchor.clone(),
            bound,
            now.tolerance_used,
        );
        // Within the anchor's boot the result is the min() of both budgets and
        // both bounds, so the store's never-lengthen check always accepts it;
        // another boot's anchor is void and replaced.
        let candidate = match txn.grant_anchor(grant)? {
            Some(stored) if stored.anchor.boot_id == fresh.anchor.boot_id => {
                let narrowed = dtime::shorten(&stored, bound);
                GrantAnchor {
                    budget_end: narrowed.budget_end.min(fresh.budget_end),
                    ..narrowed
                }
            }
            _ => fresh,
        };
        Ok(Some(txn.set_grant_anchor(&candidate)?))
    }

    /// [`TimeGate::admission`] inside `txn`: the persisted anchor at `now` and at a
    /// fresh reading, the stricter verdict.
    pub(crate) fn admission(
        &self,
        txn: &mut Txn<'_>,
        grant: &GrantId,
        now: &SafeNow,
    ) -> heimdall_store::Result<Admission> {
        let Some(anchor) = txn.grant_anchor(grant)? else {
            return Ok(Admission::NeedsAnchor);
        };
        let at_safe = dtime::admission(&anchor, &now.anchor);
        let at_fresh = dtime::admission(&anchor, &self.clock.observe());
        Ok(stricter(at_safe, at_fresh))
    }

    /// ⟨r2.6⟩ ADR-0006 §13.9 item 1: whether `grant` must **end** by expiry, judged
    /// on trusted evidence only: the wall branch at the accepted observation `now`,
    /// and the continuous branch at `now` and at a fresh reading (the continuous
    /// clock counts sleep and is trusted within a boot). Unlike
    /// [`TxnGate::admission`], which refuses a use on any reading, a fresh wall
    /// reading that the gate has not assessed (it may have jumped forward) never
    /// ends anything here. `false` without a persisted anchor.
    pub(crate) fn expired(
        &self,
        txn: &mut Txn<'_>,
        grant: &GrantId,
        now: &SafeNow,
    ) -> heimdall_store::Result<bool> {
        let Some(anchor) = txn.grant_anchor(grant)? else {
            return Ok(false);
        };
        Ok(dtime::admission(&anchor, &now.anchor) == Admission::Expired
            || dtime::budget_exhausted(&anchor, &self.clock.observe()))
    }

    /// ⟨r2.6⟩ ADR-0006 §13.9 item 1: while time is uncertain, the only evidence
    /// that ends `grant`: its persisted continuous budget has run out at a fresh
    /// reading in the anchor's boot (`heimdall_domain::time::budget_exhausted`).
    /// The wall clock is not looked at. `false` without a persisted anchor.
    pub(crate) fn budget_exhausted(
        &self,
        txn: &mut Txn<'_>,
        grant: &GrantId,
    ) -> heimdall_store::Result<bool> {
        let Some(anchor) = txn.grant_anchor(grant)? else {
            return Ok(false);
        };
        Ok(dtime::budget_exhausted(&anchor, &self.clock.observe()))
    }
}

fn signed(d: Duration) -> jiff::SignedDuration {
    jiff::SignedDuration::try_from(d).unwrap_or(jiff::SignedDuration::MAX)
}

/// `TIME_UNCERTAIN` with the kind of uncertainty in the message. Only fixed text:
/// no observed values, no caller input.
pub(crate) fn uncertain(u: &TimeUncertainty) -> OpError {
    let why = match u {
        TimeUncertainty::BelowHighWater { .. } => {
            "the wall clock is below the latest accepted time by more than the rollback tolerance"
        }
        TimeUncertainty::Skew { .. } => {
            "the wall clock disagrees with the continuous clock by more than the skew tolerance"
        }
        TimeUncertainty::ContinuousWentBackwards => "the continuous clock went backwards",
        TimeUncertainty::Unsynchronized { sync } => match sync {
            SyncStatus::NotSynchronized => {
                "after a reboot or first start the system clock reports no synchronization and no attended confirmation covers this boot"
            }
            _ => {
                "after a reboot or first start the system clock synchronization is unknown and no attended confirmation covers this boot"
            }
        },
    };
    OpError::new(Code::TimeUncertain, format!("time uncertain: {why}")).with_resource("clock", None)
}

fn refused(why: &str) -> OpError {
    OpError::new(
        Code::TimeUncertain,
        format!("time confirmation refused: {why}"),
    )
    .with_resource("clock", None)
}

fn join_error(_: tokio::task::JoinError) -> OpError {
    OpError::new(Code::InternalError, "time gate task failed")
}

impl TimeGate {
    /// New gate.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        sync: Arc<dyn TimeSync>,
        policy: TimePolicy,
    ) -> Self {
        Self {
            store,
            clock,
            sync,
            policy,
        }
    }

    /// Tolerances in force.
    #[must_use]
    pub fn policy(&self) -> &TimePolicy {
        &self.policy
    }

    fn parts(&self) -> Parts {
        Parts {
            store: Arc::clone(&self.store),
            gate: self.in_txn(),
        }
    }

    /// The same gate for use inside a caller's store transaction (A01/A02).
    pub(crate) fn in_txn(&self) -> TxnGate {
        TxnGate {
            clock: Arc::clone(&self.clock),
            sync: Arc::clone(&self.sync),
            policy: self.policy,
        }
    }

    /// Run `f` on the blocking pool (SQLite and clock reads; overview §4).
    async fn blocking<R, F>(&self, f: F) -> Result<R, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&Parts) -> Result<R, OpError> + Send + 'static,
    {
        let parts = self.parts();
        tokio::task::spawn_blocking(move || f(&parts))
            .await
            .map_err(join_error)?
    }

    /// Observe, assess, and on `Safe` persist anchor + high-water mark. Returns the
    /// accepted observation or the `TIME_UNCERTAIN` error (with the uncertainty in
    /// the message, never in a secret-bearing field).
    pub async fn check(&self) -> Result<SafeNow, OpError> {
        // Mark and anchor persist in this transaction: together or not at all.
        self.blocking(|p| Ok(p.store.transaction(|txn| p.gate.check(txn))?))
            .await?
            .map_err(|u| uncertain(&u))
    }

    /// Last assessment without persisting anything (for `inspect` and warnings).
    pub async fn peek(&self) -> Result<TimeStatus, OpError> {
        self.blocking(|p| Ok(p.store.transaction(|txn| p.gate.assess(txn))?.status))
            .await
    }

    /// Record an attended confirmation (ADR-0005 §3.6): accepts the current
    /// observation as this boot's anchor if `confirmed_wall` agrees with the clock
    /// within tolerance. Never moves deadlines; never rebuilds budgets. The caller
    /// has already verified attendance and consumed the decision.
    pub async fn confirm_attended(
        &self,
        confirmed_wall: Timestamp,
        decision: DecisionId,
    ) -> Result<AttendedTimeConfirmation, OpError> {
        self.blocking(move |p| {
            p.store.transaction(|txn| {
                let mark = txn.high_water_mark()?;
                let now = p.gate.clock.observe();
                let disagreement = confirmed_wall.duration_since(now.wall).unsigned_abs();
                if disagreement > p.gate.policy.max_tolerated_skew {
                    return Ok(Err(refused(
                        "the confirmed time disagrees with the system clock by more than the skew tolerance",
                    )));
                }
                if mark.is_some_and(|m| m.duration_since(now.wall) > signed(p.gate.policy.max_tolerated_rollback)) {
                    return Ok(Err(refused(
                        "the system clock is below the latest accepted time by more than the rollback tolerance",
                    )));
                }
                // R3: the accepted observation becomes this boot's runtime anchor; no
                // grant anchor, bound or deadline is read or written here.
                let confirmation = AttendedTimeConfirmation {
                    boot_id: now.boot_id.clone(),
                    continuous: now.continuous,
                    wall: now.wall,
                    decision,
                };
                txn.set_time_confirmation(&confirmation)?;
                txn.set_runtime_anchor(&confirmation.as_anchor())?;
                txn.raise_high_water_mark(now.wall)?;
                Ok(Ok(confirmation))
            })?
        })
        .await
    }

    /// Create (or re-create in a new boot) a grant's budget anchor from a `Safe`
    /// observation and its absolute bound; persisted.
    pub async fn anchor_grant(
        &self,
        grant: &GrantId,
        now: &SafeNow,
        bound: Timestamp,
    ) -> Result<GrantAnchor, OpError> {
        let grant = grant.clone();
        let now = now.clone();
        self.blocking(move |p| {
            p.store.transaction(|txn| {
                Ok(p.gate
                    .anchor_grant(txn, &grant, &now, bound)?
                    .ok_or_else(|| {
                        // An observation from another boot cannot anchor a budget here.
                        OpError::new(
                            Code::TimeUncertain,
                            "time uncertain: the accepted observation belongs to another boot",
                        )
                        .with_resource("clock", None)
                    }))
            })?
        })
        .await
    }

    /// Shorten a grant's bound (cutoff, parent narrowing); never lengthens.
    pub async fn shorten_grant(
        &self,
        grant: &GrantId,
        new_bound: Timestamp,
    ) -> Result<Option<GrantAnchor>, OpError> {
        let grant = grant.clone();
        self.blocking(move |p| {
            Ok(p.store.transaction(|txn| {
                let Some(current) = txn.grant_anchor(&grant)? else {
                    return Ok(None);
                };
                let shortened = dtime::shorten(&current, new_bound);
                if shortened == current {
                    return Ok(Some(current));
                }
                Ok(Some(txn.set_grant_anchor(&shortened)?))
            })?)
        })
        .await
    }

    /// [`TxnGate::expired`] in its own transaction (the scheduler pass, ADR-0006
    /// §13.9 item 1).
    pub(crate) async fn expired(&self, grant: &GrantId, now: &SafeNow) -> Result<bool, OpError> {
        let grant = grant.clone();
        let now = now.clone();
        self.blocking(move |p| {
            Ok(p.store
                .transaction(|txn| p.gate.expired(txn, &grant, &now))?)
        })
        .await
    }

    /// [`TxnGate::budget_exhausted`] in its own transaction (the scheduler pass
    /// while time is uncertain, ADR-0006 §13.9 item 1).
    pub(crate) async fn budget_exhausted(&self, grant: &GrantId) -> Result<bool, OpError> {
        let grant = grant.clone();
        self.blocking(move |p| {
            Ok(p.store
                .transaction(|txn| p.gate.budget_exhausted(txn, &grant))?)
        })
        .await
    }

    /// ⟨M03⟩ The read-only time assessment (m03-plan U3; ADR-0008 D2 item 3, D3 item
    /// 4; F21): the same gate over `store` (which may be opened read-only), persisting
    /// **nothing**: no high-water mark, no runtime anchor. Synchronous store reads;
    /// call it on the blocking pool.
    ///
    /// **Wave 0:** the body is U3's. Until it lands it answers `Uncertain`
    /// (`Unsynchronized`, sync `Unknown`), so nothing it gates is admitted.
    #[must_use]
    pub fn assess_read_only(&self, _store: &Store) -> TimeStatus {
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
            sync: SyncStatus::Unknown,
        })
    }

    /// Admission check for a grant against a `Safe` observation: wall bound and
    /// continuous budget. `NeedsAnchor` means re-anchor from `now` before use.
    pub async fn admission(&self, grant: &GrantId, now: &SafeNow) -> Result<Admission, OpError> {
        let grant = grant.clone();
        let now = now.clone();
        // No persisted anchor: nothing to admit against (fail closed). A fresh
        // reading can only make the verdict stricter: the budget keeps running
        // after `now` was accepted, and the wall branch only denies.
        self.blocking(move |p| {
            Ok(p.store
                .transaction(|txn| p.gate.admission(txn, &grant, &now))?)
        })
        .await
    }
}

/// The more restrictive of two admission verdicts: `Expired` > `NeedsAnchor` > `Open`.
fn stricter(a: Admission, b: Admission) -> Admission {
    match (a, b) {
        (Admission::Expired, _) | (_, Admission::Expired) => Admission::Expired,
        (Admission::NeedsAnchor, _) | (_, Admission::NeedsAnchor) => Admission::NeedsAnchor,
        (Admission::Open, Admission::Open) => Admission::Open,
    }
}
