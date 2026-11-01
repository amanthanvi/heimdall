//! Execution and recovery of a setup intent (m02-plan U4; ADR-0007 §5.3–§5.7).
//!
//! Every staged byte comes from `content::materialize` over the intent's content and
//! the bytes validated in the same run. Each receipt is appended through the sink
//! before the next step; each item is committed through `StageSink::commit_item`
//! before anything of it is settled. `reconcile` runs `observe_step`, `decide` and
//! the action until every step is final or held, and never calls `apply`.

use heimdall_app::ports::{ProjectionReceipt, ProjectionReconcile, ReconcileError, StageSink};
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::SetupIntent;

use super::ProjectionConfig;

/// Execute `intent`.
///
/// # Errors
/// [`ReconcileError`].
pub fn apply(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    sink: &mut dyn StageSink,
) -> Result<ProjectionReceipt, ReconcileError> {
    let _ = (config, intent, sink);
    todo!("M02-U4 projection::apply::apply")
}

/// Recover `intent` from `receipts`.
///
/// # Errors
/// [`ReconcileError`].
pub fn reconcile(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
    sink: &mut dyn StageSink,
) -> Result<ProjectionReconcile, ReconcileError> {
    let _ = (config, intent, receipts, sink);
    todo!("M02-U4 projection::apply::reconcile")
}
