//! Work bindings (spec §4.1 "Work binding", §8.2 "stable bindings"; review F04).
//!
//! A binding pins environment, profile revision, resolved scope, mechanism and
//! grant, and records the **owning caller**: `release`, `bind` and `delegate` are
//! authorized by binding ownership (same principal) or owner role, never by the
//! binding ID alone (spec §4.2 "IDs are opaque references, not bearer
//! credentials"). Release is idempotent; releasing a shared grant's last reference
//! never revokes credentials (ADR-0006 §13.2 baseline: release ≠ revoke).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, EnvironmentId, GrantId, ProfileId, WorkId};
use serde::{Deserialize, Serialize};

use crate::principal::CallerContext;
use crate::scope::Scope;

/// Lifecycle of a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    /// Holding a reference to its grant.
    Active,
    /// Reference dropped (idempotent terminal state).
    Released,
}

/// The durable binding record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRecord {
    /// ID.
    pub id: BindingId,
    /// Environment pinned.
    pub environment: EnvironmentId,
    /// Grant realizing it.
    pub grant: GrantId,
    /// Work ID (spec §6.1: a continuing binding cannot reset expiry by changing it).
    pub work_id: WorkId,
    /// Caller that created it; authorizes release/bind/delegate on it.
    pub owner: CallerContext,
    /// Profile pinned.
    pub profile: ProfileId,
    /// Profile revision pinned at activation.
    pub profile_revision: u64,
    /// Resolved scope pinned at activation.
    pub scope: Scope,
    /// Mechanism name pinned at activation.
    pub mechanism: String,
    /// Parent binding for delegation.
    pub parent: Option<BindingId>,
    /// Created.
    pub created_at: Timestamp,
    /// Released.
    pub released_at: Option<Timestamp>,
    /// State.
    pub state: BindingState,
}

/// Result of a release (store `Txn::release_binding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReleaseOutcome {
    /// Reference dropped now.
    Released {
        /// References other bindings still hold on the same grant.
        remaining_references: u64,
    },
    /// Already released earlier: idempotent success, nothing changed.
    AlreadyReleased,
    /// Caller neither owns the binding nor has the owner role.
    NotOwner,
}

/// Pure ownership rule shared by release/bind/delegate: the same caller (principal and
/// ⟨rev6⟩ paired client, ADR-0012 §3.7) or ⟨M06-W0-R03⟩ the **local** owner's global
/// access. A paired owner acts only on its own client's bindings
/// ([`CallerContext::may_access`]).
#[must_use]
pub fn may_act_on(binding: &BindingRecord, caller: &CallerContext) -> bool {
    caller.may_access(&binding.owner)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::principal::{ClientRole, PrincipalRef};

    #[test]
    fn foreign_limited_caller_may_not_act() {
        let owner = CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        );
        let other = CallerContext::local(
            PrincipalRef::UnixUser { uid: 502 },
            ClientRole::LimitedConsumer,
        );
        let b = BindingRecord {
            id: BindingId::from_random_bytes([1; 16]),
            environment: EnvironmentId::from_random_bytes([2; 16]),
            grant: GrantId::from_random_bytes([3; 16]),
            work_id: WorkId::parse("w").unwrap(),
            owner: owner.clone(),
            profile: ProfileId::parse("p").unwrap(),
            profile_revision: 1,
            scope: Scope::empty(),
            mechanism: "fake".into(),
            parent: None,
            created_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            released_at: None,
            state: BindingState::Active,
        };
        assert!(may_act_on(&b, &owner));
        assert!(!may_act_on(&b, &other));
        let admin = CallerContext::local(PrincipalRef::UnixUser { uid: 502 }, ClientRole::Owner);
        assert!(may_act_on(&b, &admin));
        // ⟨rev6⟩ ADR-0012 §3.7: another paired client of the same runner account is another
        // caller, and so is the account's own local caller.
        let client = |n: u8| CallerContext {
            remote_client: Some(heimdall_contract::ids::ClientId::from_random_bytes([n; 16])),
            ..owner.clone()
        };
        let mut paired = b.clone();
        paired.owner = client(1);
        assert!(may_act_on(&paired, &client(1)));
        assert!(!may_act_on(&paired, &client(2)));
        assert!(!may_act_on(&paired, &owner));
        // ⟨M06-W0-R03⟩ A paired owner has no role bypass: not another client's binding,
        // not the local caller's; the local owner keeps its global access.
        let paired_owner = CallerContext {
            role: ClientRole::Owner,
            ..client(3)
        };
        assert!(!may_act_on(&paired, &paired_owner));
        assert!(!may_act_on(&b, &paired_owner));
        let local_owner =
            CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner);
        assert!(may_act_on(&paired, &local_owner));
    }
}
