//! `container add|remove|mount-args` (M04 U5; ADR-0010 §4; m04-plan U5).
//!
//! Wave 0: every command answers M04's refusal (`wsl_cmd::refuse`) before any
//! runtime contact. The M04 track replaces it with the handlers.

use heimdall_contract::ExitCode;

use crate::client::Ctx;
use crate::wsl_cmd;

/// Refuse `container *` (wave 0).
pub(crate) fn refuse(ctx: &Ctx) -> ExitCode {
    wsl_cmd::refuse(ctx)
}
