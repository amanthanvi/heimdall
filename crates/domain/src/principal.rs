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

    /// ⟨M06-W0-R03; ADR-0006 §18.2 item 17, the orchestrator's ruling⟩ The **local** owner's
    /// global access to every caller's objects: the owner role with no paired client. A
    /// paired caller, owner role included, never has it.
    #[must_use]
    pub fn has_global_access(&self) -> bool {
        self.is_owner() && self.remote_client.is_none()
    }

    /// ⟨M06-W0-R03⟩ Whether this caller may see or act on an object `owner` created (an
    /// operation, a binding): the same caller (principal and paired client), or the local
    /// owner's global access. A paired owner is scoped to its own client: no role bypass
    /// for observe, cancel or binding ownership (ADR-0012 §3.7).
    #[must_use]
    pub fn may_access(&self, owner: &CallerContext) -> bool {
        owner.same_caller(self) || self.has_global_access()
    }

    /// ⟨M06-W0-R03⟩ The named cross-caller narrowing powers (ADR-0012 §7.2, §8: either owner
    /// may deliver a narrowing effect, and revoke a client or a grant it does not own):
    /// any owner, local or paired. Narrowing only: it never grants access to another
    /// caller's objects for anything else.
    #[must_use]
    pub fn may_narrow_across_callers(&self) -> bool {
        self.is_owner()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ⟨M06-W0-R03⟩ The local owner keeps its global access; a paired owner is scoped to
    /// its own client but keeps the named narrowing powers; a limited caller has neither.
    #[test]
    fn paired_owner_is_client_scoped_and_local_owner_global() {
        let p = PrincipalRef::UnixUser { uid: 501 };
        let local = CallerContext::local(p.clone(), ClientRole::Owner);
        let paired = |n: u8, role| CallerContext {
            principal: p.clone(),
            role,
            remote_client: Some(ClientId::from_random_bytes([n; 16])),
        };
        let a = paired(1, ClientRole::Owner);
        let b = paired(2, ClientRole::LimitedConsumer);
        assert!(local.has_global_access());
        assert!(
            !a.has_global_access(),
            "a paired owner has no global access"
        );
        assert!(local.may_access(&a) && local.may_access(&b));
        assert!(a.may_access(&a));
        assert!(!a.may_access(&b), "paired owner, another client's object");
        assert!(
            !a.may_access(&local),
            "paired owner, the local caller's object"
        );
        assert!(!b.may_access(&a));
        assert!(a.may_narrow_across_callers() && local.may_narrow_across_callers());
        assert!(!b.may_narrow_across_callers());
    }
}
