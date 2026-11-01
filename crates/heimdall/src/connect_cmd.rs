//! `heimdall connect <alias>` (m02-plan U8; ADR-0007 §8).
//!
//! Skeleton (m02-plan U0): until U8 lands, [`run`] answers M01's "not available in
//! this build" envelope and contacts nothing. U8 replaces it with
//! `connect_cmd::connect(alias)`: `inspect destinations`, the verified client,
//! the pre-launch eligibility check under `--non-interactive`, then launch.

use crate::cli::{ConnectArgs, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `connect`. Wave 0: `USAGE_ERROR` "not available in this build", exit 2.
pub(crate) fn run(ctx: &Ctx, args: ConnectArgs) -> ExitCode {
    let ConnectArgs {
        destination: _,
        launch: _,
    } = args;
    not_available(ctx)
}
