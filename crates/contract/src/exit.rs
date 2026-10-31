//! CLI exit codes for non-child commands (spec §11.6; ADR-0006 §6).
//!
//! `heimdall run -- <argv>` is different: after launch the exit status is the
//! child's (spec §10.4). Pre-launch failures use this table.

use serde::{Deserialize, Serialize};

/// Process exit classes. Values are the wire numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[repr(u8)]
pub enum ExitCode {
    /// Success, or accepted-pending when the caller selected asynchronous behaviour.
    Success = 0,
    /// Unexpected internal failure.
    Internal = 1,
    /// Usage, argument, or schema error.
    Usage = 2,
    /// Required human or provider interaction.
    InteractionRequired = 3,
    /// Denied, paused, cut off, or otherwise refused on authority grounds.
    Denied = 4,
    /// Unavailable or transient dependency.
    Unavailable = 5,
    /// Conflict with existing state or a different request under the same key.
    Conflict = 6,
    /// Uncertain external outcome.
    OutcomeUnknown = 7,
}

impl ExitCode {
    /// Numeric process status.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        i32::from(self as u8)
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code as u8)
    }
}
