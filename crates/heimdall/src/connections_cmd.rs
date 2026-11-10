//! `heimdall connections [--json]` and `heimdall connections close <id>` (m03-plan
//! §5 items 4a and 24; ADR-0008 D8).
//!
//! Wave 0: the argument tree is in `cli.rs`; both forms answer the wave-0 envelope of
//! [`crate::m03_cmd`] before any runtime contact (U12 fills the bodies).

use heimdall_contract::ExitCode;

use crate::cli::{ConnectionsArgs, ConnectionsCommand};
use crate::client::Ctx;
use crate::m03_cmd;

/// Handle `connections`: no subcommand lists, `close <id>` closes.
pub(crate) fn run(ctx: &Ctx, args: ConnectionsArgs) -> ExitCode {
    match args.command {
        None | Some(ConnectionsCommand::Close { .. }) => m03_cmd::not_available(ctx),
    }
}
