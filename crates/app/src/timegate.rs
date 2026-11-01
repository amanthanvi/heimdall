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

use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DecisionId, GrantId};
use heimdall_domain::time::{
    Admission, AttendedTimeConfirmation, Clock, GrantAnchor, SyncStatus, TimeAnchor, TimePolicy,
    TimeStatus, TimeSync,
};
use heimdall_store::Store;

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

    /// Observe, assess, and on `Safe` persist anchor + high-water mark. Returns the
    /// accepted observation or the `TIME_UNCERTAIN` error (with the uncertainty in
    /// the message, never in a secret-bearing field).
    pub async fn check(&self) -> Result<SafeNow, OpError> {
        let _ = (&self.store, &self.clock, &self.sync, &self.policy);
        todo!(
            "M01-U5t: observe clock+sync, read anchor/high-water/confirmation, gate(), persist on Safe"
        )
    }

    /// Last assessment without persisting anything (for `inspect` and warnings).
    pub async fn peek(&self) -> Result<TimeStatus, OpError> {
        todo!("M01-U5t")
    }

    /// Record an attended confirmation (ADR-0005 §3.6): accepts the current
    /// observation as this boot's anchor if `confirmed_wall` agrees with the clock
    /// within tolerance. Never moves deadlines; never rebuilds budgets. The caller
    /// has already verified attendance and consumed the decision.
    pub async fn confirm_attended(
        &self,
        _confirmed_wall: Timestamp,
        _decision: DecisionId,
    ) -> Result<AttendedTimeConfirmation, OpError> {
        todo!("M01-U5t")
    }

    /// Create (or re-create in a new boot) a grant's budget anchor from a `Safe`
    /// observation and its absolute bound; persisted.
    pub async fn anchor_grant(
        &self,
        _grant: &GrantId,
        _now: &SafeNow,
        _bound: Timestamp,
    ) -> Result<GrantAnchor, OpError> {
        todo!("M01-U5t: domain::time::anchor_grant + Txn::set_grant_anchor")
    }

    /// Shorten a grant's bound (cutoff, parent narrowing); never lengthens.
    pub async fn shorten_grant(
        &self,
        _grant: &GrantId,
        _new_bound: Timestamp,
    ) -> Result<Option<GrantAnchor>, OpError> {
        todo!("M01-U5t: domain::time::shorten + Txn::set_grant_anchor")
    }

    /// Admission check for a grant against a `Safe` observation: wall bound and
    /// continuous budget. `NeedsAnchor` means re-anchor from `now` before use.
    pub async fn admission(&self, _grant: &GrantId, _now: &SafeNow) -> Result<Admission, OpError> {
        todo!("M01-U5t: Txn::grant_anchor + domain::time::admission")
    }
}
