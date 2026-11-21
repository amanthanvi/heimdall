//! Authenticated caller context (spec §13.2; primitives-draft §2).
//!
//! Same-user IPC credentials identify an OS principal, not an application.
//! Caller-supplied names, PIDs and paths are metadata and never appear here.

use heimdall_contract::ids::ClientId;
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

/// What authorization is evaluated against. Part of the idempotency key, the operation
/// owner and visibility, and the event cursor's reader tag (ADR-0006 §7.1, §8;
/// ⟨rev6⟩ §18: every namespace keyed by caller includes `remote_client`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallerContext {
    /// Authenticated principal.
    pub principal: PrincipalRef,
    /// Role.
    pub role: ClientRole,
    /// ⟨M06⟩ Revision 6 (ADR-0012 §3.6, §3.7, §9 item 1): the paired client a runner
    /// runtime's bridge declared for this session. Set only by a runner runtime, from the
    /// bridge's hello on a same-uid connection, and never from request fields; nothing
    /// sets it in wave 0. `None` is omitted from the serialized form, so every stored
    /// key, hash and cursor of an earlier caller is byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_client: Option<ClientId>,
}

impl CallerContext {
    /// The local caller the transport authenticated: `principal` in `role`, with no paired
    /// client.
    #[must_use]
    pub fn local(principal: PrincipalRef, role: ClientRole) -> Self {
        Self {
            principal,
            role,
            remote_client: None,
        }
    }

    /// Whether owner-channel actions (approve, pause, cutoff, unenroll) are allowed.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.role == ClientRole::Owner
    }

    /// ⟨M06⟩ Whether `other` is the same caller for ownership and visibility (ADR-0012
    /// §3.7): the same principal **and** the same paired client (two clients of one
    /// runner account are different callers).
    #[must_use]
    pub fn same_caller(&self, other: &CallerContext) -> bool {
        self.principal == other.principal && self.remote_client == other.remote_client
    }
}
