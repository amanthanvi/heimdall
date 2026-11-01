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

/// Pure ownership rule shared by release/bind/delegate.
#[must_use]
pub fn may_act_on(binding: &BindingRecord, caller: &CallerContext) -> bool {
    binding.owner.principal == caller.principal || caller.is_owner()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::principal::{ClientRole, PrincipalRef};

    #[test]
    fn foreign_limited_caller_may_not_act() {
        let owner = CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::LimitedConsumer,
        };
        let other = CallerContext {
            principal: PrincipalRef::UnixUser { uid: 502 },
            role: ClientRole::LimitedConsumer,
        };
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
        let admin = CallerContext {
            principal: PrincipalRef::UnixUser { uid: 502 },
            role: ClientRole::Owner,
        };
        assert!(may_act_on(&b, &admin));
    }
}
