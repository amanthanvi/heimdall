//! `heimdall setup [preview|apply|rollback|repair|status]` (m02-plan U9; ADR-0007 §5).
//!
//! Skeleton (m02-plan U0): until U9 lands, every action answers M01's "not
//! available in this build" envelope and contacts nothing. U9 replaces [`run`]:
//! preview first, show the exact plan with its restore column, follow the
//! ADR-0006 §3.1 confirmation contract, then submit the plan digest.

use crate::cli::{SetupArgs, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `setup`. Wave 0: `USAGE_ERROR` "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx, args: SetupArgs) -> ExitCode {
    let SetupArgs { action: _ } = args;
    not_available(ctx)
}
