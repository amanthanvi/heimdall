//! ⟨M03⟩ Wave-0 escalation E10 (m03-plan §5 item 11; ADR-0008 D5 §6.4): `cancel` of
//! an `enrollment.apply`, `enrollment.verify` or `enrollment.remove` operation that is
//! still open.
//! * Once a remote mutation's `Attempted` receipt exists
//!   (`heimdall_domain::operation::enrollment_cancel_allowed`) it is refused and
//!   writes nothing: `CAPABILITY_UNAVAILABLE`, reason `remote_step_in_progress`,
//!   `next: reconcile`.
//! * ⟨wave 4, U10⟩ Before that, [`cancel_in`] cancels it in the caller's transaction:
//!   a `planned` record is `withdrawn` (nothing written), an `applying` one whose
//!   append was never attempted is `failed_unwritten`, and the operation's pending
//!   decision is withdrawn. An approved removal (`removing`) is not cancelled (the
//!   table has no exit back; it continues with `enroll step`), nor is a step in
//!   flight (`step_outstanding`).

use heimdall_contract::enrollment::EnrollmentState;
use heimdall_contract::envelope::{EffectStatus, NextAction, reason};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::enrollment::EnrollmentEventKind;
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{
    CancelRefusal, CancellationRecord, OperationRecord, enrollment_cancel_allowed,
};
use heimdall_store::Txn;

use super::{Cancelled, Emit, op_to};
use crate::error::OpError;

fn in_progress(op: &OperationRecord) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "a remote enrollment step may have run; reconcile or remove instead of cancelling",
    )
    .with_reason(reason::REMOTE_STEP_IN_PROGRESS)
    .with_next(NextAction {
        action: "reconcile".to_owned(),
        operation_id: Some(op.id.clone()),
        ..NextAction::default()
    })
    .with_operation(op.id.clone())
}

/// ⟨wave 4⟩ Cancel the open enrollment operation `op` in the caller's transaction
/// (module docs), as `cancel_local_in` does for setup: `Ok(Ok((op, None)))` once
/// cancelled, `Ok(Err(e))` refused with nothing written.
pub(super) fn cancel_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    mut op: OperationRecord,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<Cancelled> {
    let receipts = tx.stage_receipts(&op.id)?;
    if let Err(CancelRefusal::RemoteStepInProgress) = enrollment_cancel_allowed(op.kind, &receipts)
    {
        return Ok(Err(in_progress(&op)));
    }
    let journal = super::enrollment_m03::journal_of(&receipts);
    if journal.as_ref().is_some_and(|j| j.outstanding.is_some()) {
        return Ok(Err(OpError::new(
            Code::RequestConflict,
            "a step of this enrollment is outstanding; send its result first",
        )
        .with_reason(reason::STEP_OUTSTANDING)
        .with_operation(op.id.clone())));
    }
    // A foreign manual removal (§17.10 item 2): cancel back to its origin, or keep it
    // in `manual_removal_pending` once a `ca_not_held` result exists.
    if let Some(fid) = journal.as_ref().and_then(|j| j.foreign.clone())
        && let Some(f) = tx.foreign_removal(&fid)?
        && f.state == EnrollmentState::ManualRemovalPending
        && let Some(origin) = f.removal_origin.clone()
    {
        let mut updated = f.clone();
        if !origin.ca_not_held_seen {
            updated.removal_origin = None;
        }
        let kind = EnrollmentEventKind::OwnerCancelsManualRemoval {
            origin: origin.state,
            ca_not_held_seen: origin.ca_not_held_seen,
        };
        if tx
            .transition_foreign_removal(f.state, kind, &updated)?
            .is_err()
        {
            return Ok(Err(OpError::new(
                Code::ConfigConflict,
                "this manual removal cannot be cancelled",
            )
            .with_operation(op.id.clone())));
        }
    }
    let record = match journal.as_ref().and_then(|j| j.enrollment.clone()) {
        Some(id) => tx.enrollment(&id)?,
        None => None,
    };
    // An own manual removal (§17.4 item 5): back to the origin, with its evidence.
    if let Some(r) = record
        .as_ref()
        .filter(|r| r.state == EnrollmentState::ManualRemovalPending)
        && let Some(origin) = r.removal_origin.clone()
    {
        let mut updated = r.clone();
        updated.updated_at = now;
        updated.removal_origin = None;
        updated.evidence = origin.evidence.clone();
        updated.verified_at = origin.evidence.as_ref().map(|e| e.verified_at);
        updated.hold = origin.hold;
        let kind = EnrollmentEventKind::OwnerCancelsManualRemoval {
            origin: origin.state,
            ca_not_held_seen: origin.ca_not_held_seen,
        };
        if tx.transition_enrollment(r.state, kind, &updated)?.is_err() {
            return Ok(Err(OpError::new(
                Code::ConfigConflict,
                "this manual removal cannot be cancelled",
            )
            .with_operation(op.id.clone())));
        }
    }
    let event = match record.as_ref().map(|r| r.state) {
        Some(EnrollmentState::Planned) => Some(EnrollmentEventKind::DecisionWithdrawn),
        Some(EnrollmentState::Applying) => Some(EnrollmentEventKind::RefusedBeforeWrite),
        Some(EnrollmentState::Removing | EnrollmentState::RollbackPending) => {
            return Ok(Err(OpError::new(
                Code::ConfigConflict,
                "an approved removal is not cancelled; it continues with `enroll step`",
            )
            .with_effect(EffectStatus::None)
            .with_operation(op.id.clone())));
        }
        _ => None,
    };
    if let (Some(r), Some(event)) = (record, event) {
        let mut updated = r.clone();
        updated.updated_at = now;
        super::enrollment_m03::move_record(tx, emit, r.state, event, &updated, Some(&op.id))?;
    }
    for d in tx.pending_decisions()? {
        if super::enrollment_m03::decision_operation(&d.kind) == Some(&op.id) {
            let withdrawn = tx.withdraw_decision(&d.id)?;
            emit.decision(tx, &withdrawn, Some(&op.id))?;
        }
    }
    op_to(&mut op, OperationEvent::Cancel, now)?;
    op.cancellation = Some(CancellationRecord {
        requested_at: now,
        may_have_external_effect: false,
    });
    let err = OpError::new(Code::OperationCancelled, "the operation was cancelled")
        .with_effect(EffectStatus::None)
        .with_operation(op.id.clone());
    op.code = Some(Code::OperationCancelled);
    op.effect_status = err.effect_status;
    op.result = Some(serde_json::json!({ "error": err.detail() }));
    tx.update_operation(&op)?;
    tx.settle_idempotency(
        &op.key,
        heimdall_domain::idempotency::retention_expiry(now, retention),
    )?;
    emit.op(tx, &op)?;
    Ok(Ok((op, None)))
}
