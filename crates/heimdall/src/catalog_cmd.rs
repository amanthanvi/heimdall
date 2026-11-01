//! `heimdall destination|identity|profile …` (m02-plan U9; §5 item 3).
//!
//! Skeleton (m02-plan U0): until U9 lands, every subcommand answers M01's "not
//! available in this build" envelope and contacts nothing. U9 replaces these with
//! `Request::Catalog` clients (and `inspect` for the read-only ones).

use crate::cli::{DestinationCommand, IdentityCommand, ProfileCommand, not_available};
use crate::client::Ctx;
use heimdall_contract::ExitCode;

/// Handle `destination`. Wave 0: "not available in this build", exit 2.
pub(crate) fn destination(ctx: &Ctx, command: DestinationCommand) -> ExitCode {
    drop(command);
    not_available(ctx)
}

/// Handle `identity`. Wave 0: "not available in this build", exit 2. No agent is
/// listed and no file is read.
pub(crate) fn identity(ctx: &Ctx, command: IdentityCommand) -> ExitCode {
    drop(command);
    not_available(ctx)
}

/// Handle `profile`. Wave 0: "not available in this build", exit 2.
pub(crate) fn profile(ctx: &Ctx, command: ProfileCommand) -> ExitCode {
    drop(command);
    not_available(ctx)
}
