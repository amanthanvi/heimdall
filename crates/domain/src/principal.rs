//! Authenticated caller context (spec §13.2; primitives-draft §2).
//!
//! Same-user IPC credentials identify an OS principal, not an application.
//! Caller-supplied names, PIDs and paths are metadata and never appear here.

use serde::{Deserialize, Serialize};

/// The OS principal established by the transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrincipalRef {
    /// Unix user by numeric ID.
    UnixUser {
        /// uid.
        uid: u32,
    },
    /// Windows user by SID string.
    WindowsUser {
        /// SID.
        sid: String,
    },
}

/// Role of a paired remote client (G07); local callers are always `Owner` because
/// Q1 was decided as "accept and disclose" (primitives-draft §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    /// Full owner authority on this runtime.
    Owner,
    /// May view status and request allowed work only.
    LimitedConsumer,
}

/// What authorization is evaluated against. Part of the idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallerContext {
    /// Authenticated principal.
    pub principal: PrincipalRef,
    /// Role.
    pub role: ClientRole,
}

impl CallerContext {
    /// Whether owner-channel actions (approve, pause, cutoff, unenroll) are allowed.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.role == ClientRole::Owner
    }
}
