//! `export [--redact]` and `import <BUNDLE>` (M05 U7; ADR-0011 §2.4; m05-plan U7).
//!
//! Wave 0: both answer M05's refusal (`m05_cmd::refuse`) before any runtime contact.
//! The M05 track replaces it with the handlers.

use heimdall_contract::ExitCode;

use crate::client::Ctx;
use crate::m05_cmd;

/// Refuse `export` and `import` (wave 0).
pub(crate) fn refuse(ctx: &Ctx) -> ExitCode {
    m05_cmd::refuse(ctx)
}
