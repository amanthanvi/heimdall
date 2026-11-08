//! ⟨M03⟩ Wave-0 escalation E10 (m03-plan §5 item 11; ADR-0008 D5 §6.4): `cancel` of
//! an `enrollment.apply`, `enrollment.verify` or `enrollment.remove` operation that is
//! still open. It is refused and writes nothing:
//! * once a remote mutation's `Attempted` receipt exists
//!   (`heimdall_domain::operation::enrollment_cancel_allowed`):
//!   `CAPABILITY_UNAVAILABLE`, reason `remote_step_in_progress`, `next: reconcile`;
//! * before that, in wave 0: `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`
//!   (cancelling is allowed then, but its driver is U10's).

use heimdall_contract::Code;
use heimdall_contract::envelope::{NextAction, reason};
use heimdall_domain::operation::{CancelRefusal, OperationRecord, enrollment_cancel_allowed};
use heimdall_store::Txn;

use crate::error::OpError;

/// The refusal of cancelling the open enrollment operation `op` (module docs).
pub(super) fn refusal(tx: &mut Txn<'_>, op: &OperationRecord) -> heimdall_store::Result<OpError> {
    let receipts = tx.stage_receipts(&op.id)?;
    Ok(match enrollment_cancel_allowed(op.kind, &receipts) {
        Err(CancelRefusal::RemoteStepInProgress) => OpError::new(
            Code::CapabilityUnavailable,
            "a remote enrollment step may have run; reconcile or remove instead of cancelling",
        )
        .with_reason(reason::REMOTE_STEP_IN_PROGRESS)
        .with_next(NextAction {
            action: "reconcile".to_owned(),
            operation_id: Some(op.id.clone()),
            ..NextAction::default()
        })
        .with_operation(op.id.clone()),
        // Allowed by the rule, but the enrollment driver is not in this build; a
        // refusal this build does not know refuses the same way (fail closed).
        _ => OpError::driver_unavailable(
            "cancelling an enrollment operation is not available in this build",
        )
        .with_operation(op.id.clone()),
    })
}
