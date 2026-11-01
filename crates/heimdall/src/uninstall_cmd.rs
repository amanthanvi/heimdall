//! `heimdall uninstall [--purge-state]` (m02-plan U9; Q6).
//!
//! Skeleton (m02-plan U0): until U9 lands, [`run`] answers M01's "not available in
//! this build" envelope and changes nothing.

use crate::cli::{UninstallArgs, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `uninstall`. Wave 0: "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx, args: UninstallArgs) -> ExitCode {
    let UninstallArgs { purge_state: _ } = args;
    not_available(ctx)
}
