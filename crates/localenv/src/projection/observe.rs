//! Passive observation (m02-plan U4): aliases against the projection record, and the
//! held steps of an intent. Moves nothing and writes nothing.

use heimdall_app::ports::{HeldStep, ReconcileError};
use heimdall_contract::doctor::AliasObservation;
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{ProjectionRecord, SetupIntent};

use super::ProjectionConfig;

/// Re-evaluate `aliases` statically against `record`.
#[must_use]
pub fn observe(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
) -> Vec<AliasObservation> {
    let _ = (config, record, aliases);
    todo!("M02-U4 projection::observe::observe")
}

/// The held steps of `intent`, with their classification and fingerprints.
///
/// # Errors
/// [`ReconcileError`].
pub fn observe_held(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
) -> Result<Vec<HeldStep>, ReconcileError> {
    let _ = (config, intent, receipts);
    todo!("M02-U4 projection::observe::observe_held")
}
