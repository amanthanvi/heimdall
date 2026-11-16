//! `activate --hook --cwd <PATH>` and `shell init <zsh|bash>` (M05 U4; ADR-0011 §3.2, §10
//! item 3; m05-plan U4).
//!
//! Wave 0: both answer M05's refusal (`m05_cmd::refuse`) before any runtime contact.
//! The M05 track replaces it with the handlers.

use heimdall_contract::ExitCode;

use crate::client::Ctx;
use crate::m05_cmd;

/// Refuse `activate` and `shell init` (wave 0).
pub(crate) fn refuse(ctx: &Ctx) -> ExitCode {
    m05_cmd::refuse(ctx)
}
