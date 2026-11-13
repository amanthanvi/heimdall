//! ⟨M03⟩ wave 4 (U0b row 14, phase 2): completion of the M03 decision kinds inside
//! `Operations::decide`'s transaction. Each kind's body is its driver's:
//! `RegisterIssuer` and `RetireIssuer` are `issuer_m03`'s; `EnrollAccount`,
//! `EnrollSystemForm`, `RemoveEnrollment` and `ApproveTargetChange` are
//! `enrollment_m03`'s.
//!
//! **Order** (as for the M02 kinds): [`precheck`] runs before the record is completed
//! and may refuse with nothing written (the record stays `pending`, not consumed);
//! [`apply`] runs after the store completed the record, in the same transaction, and
//! a store error there rolls the whole transaction back (nothing consumed); then,
//! after the commit, [`super::Operations::m03_after_decision`] does any non-store
//! work (an issuer start, a waiting operation's continuation).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::OperationId;
use heimdall_contract::request::Verdict;
use heimdall_domain::decision::{DecisionKind, DecisionRecord};
use heimdall_domain::operation::OperationRecord;
use heimdall_store::Txn;

use super::{Emit, Operations};
use crate::error::OpError;

/// Before completion: refuse (nothing written) or name the operation the record
/// waits on (`None`: the record waits on no operation).
pub(super) fn precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
    now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    match &d.kind {
        DecisionKind::RegisterIssuer { .. } | DecisionKind::RetireIssuer { .. } => {
            super::issuer_m03::decision_precheck(tx, d, verdict, now)
        }
        DecisionKind::EnrollAccount { .. }
        | DecisionKind::EnrollSystemForm { .. }
        | DecisionKind::RemoveEnrollment { .. }
        | DecisionKind::ApproveTargetChange { .. } => {
            super::enrollment_m03::decision_precheck(tx, d, verdict, now)
        }
        _ => Ok(Err(OpError::driver_unavailable(
            "this decision kind is not available in this build",
        ))),
    }
}

/// After the store completed `record` (same transaction): the kind's effect. Returns
/// the operations to resume through the M01 pipeline (none for the M03 kinds unless
/// a driver says otherwise).
#[allow(clippy::too_many_arguments)]
pub(super) fn apply(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    waiting: Option<OperationRecord>,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    match &record.kind {
        DecisionKind::RegisterIssuer { .. } | DecisionKind::RetireIssuer { .. } => {
            super::issuer_m03::decision_apply(tx, emit, record, verdict, waiting, now, retention)
        }
        DecisionKind::EnrollAccount { .. }
        | DecisionKind::EnrollSystemForm { .. }
        | DecisionKind::RemoveEnrollment { .. }
        | DecisionKind::ApproveTargetChange { .. } => super::enrollment_m03::decision_apply(
            tx, emit, record, verdict, waiting, now, retention,
        ),
        _ => Ok(Ok(Vec::new())),
    }
}

impl Operations {
    /// After the decide transaction committed an M03 record: the kind's non-store work.
    /// Never fails the decide request (the record is already durable); a failure is
    /// logged and left to the kind's own recovery.
    pub(super) async fn m03_after_decision(&self, record: &DecisionRecord, verdict: Verdict) {
        match &record.kind {
            DecisionKind::RegisterIssuer { .. } | DecisionKind::RetireIssuer { .. } => {
                self.issuer_after_decision(record, verdict).await;
            }
            DecisionKind::EnrollAccount { .. }
            | DecisionKind::EnrollSystemForm { .. }
            | DecisionKind::RemoveEnrollment { .. }
            | DecisionKind::ApproveTargetChange { .. } => {
                self.enrollment_after_decision(record, verdict).await;
            }
            _ => {}
        }
    }
}
