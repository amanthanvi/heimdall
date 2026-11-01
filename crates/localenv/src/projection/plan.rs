//! The read-only preview (m02-plan U4; ADR-0007 §5.1).
//!
//! The plan carries each step's `StepContent`, built through `Rendered`; staged
//! names are random and fixed in the plan. A plan beyond the content bounds is
//! refused (`PreviewError::TooLarge`, `projection_too_large`).

use heimdall_app::ports::PreviewError;
use heimdall_contract::setup::PreviewIntent;
use heimdall_domain::projection::{ProjectionPlan, ProjectionSpec};

use super::ProjectionConfig;

/// Build the plan for `intent` over `spec`, reading the files as they are.
///
/// # Errors
/// [`PreviewError`].
pub fn preview(
    config: &ProjectionConfig,
    spec: &ProjectionSpec,
    intent: &PreviewIntent,
) -> Result<ProjectionPlan, PreviewError> {
    let _ = (config, spec, intent);
    todo!("M02-U4 projection::plan::preview")
}
