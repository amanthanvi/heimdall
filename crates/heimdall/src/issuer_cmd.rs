//! `heimdall issuer init|status|unlock|rotate begin|retire|restore|bundle` (m03-plan
//! §5 item 24; ADR-0008 D3, D4).
//!
//! Wave 0: the argument tree is in `cli.rs`; every subcommand answers the wave-0
//! envelope of [`crate::m03_cmd`] before any runtime contact (U12 fills the bodies).

use heimdall_contract::ExitCode;

use crate::cli::IssuerCommand;
use crate::client::Ctx;
use crate::m03_cmd;

/// Handle `issuer`.
pub(crate) fn run(ctx: &Ctx, command: IssuerCommand) -> ExitCode {
    match command {
        IssuerCommand::Init { .. }
        | IssuerCommand::Status
        | IssuerCommand::Unlock
        | IssuerCommand::Rotate(_)
        | IssuerCommand::Retire { .. }
        | IssuerCommand::Restore { .. }
        | IssuerCommand::Bundle { .. } => m03_cmd::not_available(ctx),
    }
}
