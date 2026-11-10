//! Standing policy (spec §4.1, §6.1; plan §4.3 "mutable versioned standing
//! policies"). Pause and cutoff outrank standing automatic permission.

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{EnvironmentId, PolicyId, ProfileId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// ⟨M03⟩ The lock behaviour and connection policy types are wire-visible (policy
/// actions carry them), so they live in the contract and are re-exported here.
pub use heimdall_contract::managed::{
    ConnectionPolicy, ExistingConnectionsMode, LockBehavior, MultiplexingMode,
};

use crate::scope::Scope;

/// Monotonic revision of a policy definition. Grants pin the revision they were
/// authorized under (spec §4.1 "Grant ... policy revision").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRevision(pub u64);

/// Monotonic authority generation. Bumped on revocation, pause, cutoff and policy
/// narrowing; stale approvals, renewals and retries against an older generation
/// are invalid (spec §6.7, R-SE-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityGeneration(pub u64);

impl AuthorityGeneration {
    /// Next generation.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Where a policy decision came from (spec §13.4 "owner's verified decision").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySource {
    /// Owner decision recorded on the owner channel at `decided_at`.
    OwnerDecision {
        /// When.
        decided_at: Timestamp,
    },
    /// Personal default profile created at setup.
    SetupDefault,
}

/// Pause state (spec §5.6, §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PauseState {
    /// Automatic activation allowed.
    Active,
    /// Paused since `since`; blocks new automatic activation, not existing work.
    Paused {
        /// When.
        since: Timestamp,
    },
}

/// A saved user decision permitting automatic creation of bounded access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPolicy {
    /// Policy ID.
    pub id: PolicyId,
    /// Revision.
    pub revision: PolicyRevision,
    /// Profile this policy authorizes (resolved to a snapshot at activation).
    pub profile: ProfileId,
    /// Optional workspace the policy is bound to (trust lives here, not in the repo).
    pub workspace: Option<WorkspaceId>,
    /// Maximum scope automatic work may receive.
    pub scope: Scope,
    /// Environments in which the policy applies.
    pub environments: BTreeSet<EnvironmentId>,
    /// Maximum window for a new work binding (spec P04 default 12 h).
    pub max_window: Duration,
    /// Pause state.
    pub pause: PauseState,
    /// Hard cutoff; after it no new work activates until deliberately cleared.
    pub cutoff_at: Option<Timestamp>,
    /// Provenance.
    pub source: PolicySource,
    /// ⟨M03⟩ What a session lock does to grants under this policy (ADR-0008 D9; §5
    /// item 6). Serde default `continue`, omitted when `continue`, so every M01/M02
    /// policy record decodes and re-encodes unchanged.
    #[serde(default, skip_serializing_if = "is_continue")]
    pub lock_behavior: LockBehavior,
    /// ⟨M03⟩ The connection policy (ADR-0008 D8 item 1). Serde default `graceful`,
    /// `disabled`, omitted when default.
    #[serde(default, skip_serializing_if = "ConnectionPolicy::is_default")]
    pub connection: ConnectionPolicy,
}

fn is_continue(b: &LockBehavior) -> bool {
    *b == LockBehavior::Continue
}

/// ⟨M03⟩ The stricter of two lock behaviours: `revoke_on_lock` wins (fail closed;
/// U0b row 11). Any value this build does not know counts as `revoke_on_lock`.
#[must_use]
pub fn strictest_lock_behavior(a: LockBehavior, b: LockBehavior) -> LockBehavior {
    match (a, b) {
        (LockBehavior::Continue, LockBehavior::Continue) => LockBehavior::Continue,
        _ => LockBehavior::RevokeOnLock,
    }
}

/// ⟨M03⟩ The stricter of two connection policies, field by field (ADR-0008 D8
/// item 1: the effective policy is the strictest of every source): `strict` beats
/// `graceful`, `disabled` beats `owned_masters`.
#[must_use]
pub fn strictest_connection_policy(a: ConnectionPolicy, b: ConnectionPolicy) -> ConnectionPolicy {
    let existing = match (a.existing, b.existing) {
        (ExistingConnectionsMode::Graceful, ExistingConnectionsMode::Graceful) => {
            ExistingConnectionsMode::Graceful
        }
        _ => ExistingConnectionsMode::Strict,
    };
    let multiplexing = match (a.multiplexing, b.multiplexing) {
        (MultiplexingMode::OwnedMasters, MultiplexingMode::OwnedMasters) => {
            MultiplexingMode::OwnedMasters
        }
        _ => MultiplexingMode::Disabled,
    };
    ConnectionPolicy {
        existing,
        multiplexing,
    }
}

/// ⟨M03⟩ U0b row 11: extend a merged policy view (the application's
/// `merged_policy`) fail closed for the two M03 fields: the strictest lock
/// behaviour and connection policy of `merged` and every applicable policy.
pub fn merge_lock_and_connection(merged: &mut StandingPolicy, policies: &[StandingPolicy]) {
    for p in policies {
        merged.lock_behavior = strictest_lock_behavior(merged.lock_behavior, p.lock_behavior);
        merged.connection = strictest_connection_policy(merged.connection, p.connection);
    }
}

impl StandingPolicy {
    /// Whether automatic activation is blocked at `now` by pause or cutoff. Pure.
    #[must_use]
    pub fn blocks_activation_at(&self, now: Timestamp) -> Option<ActivationBlock> {
        if let PauseState::Paused { since } = self.pause {
            return Some(ActivationBlock::Paused { since });
        }
        if let Some(cutoff) = self.cutoff_at
            && now >= cutoff
        {
            return Some(ActivationBlock::Cutoff { at: cutoff });
        }
        None
    }
}

/// Why a policy refuses activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationBlock {
    /// Paused.
    Paused {
        /// Since.
        since: Timestamp,
    },
    /// Cutoff passed.
    Cutoff {
        /// At.
        at: Timestamp,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn m02_policy_record_reads_defaults_and_reencodes_unchanged() {
        let old = serde_json::json!({
            "id": "default", "revision": 1, "profile": "personal", "workspace": null,
            "scope": {"pairs": [], "capabilities": []}, "environments": [],
            "max_window": {"secs": 43200, "nanos": 0}, "pause": {"state": "active"},
            "cutoff_at": null, "source": {"kind": "setup_default"}
        });
        let p: StandingPolicy = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(p.lock_behavior, LockBehavior::Continue);
        assert!(p.connection.is_default());
        assert_eq!(serde_json::to_value(&p).unwrap(), old);
    }

    #[test]
    fn strictest_is_fail_closed() {
        use ExistingConnectionsMode as E;
        use MultiplexingMode as M;
        assert_eq!(
            strictest_lock_behavior(LockBehavior::Continue, LockBehavior::RevokeOnLock),
            LockBehavior::RevokeOnLock
        );
        let wide = ConnectionPolicy {
            existing: E::Graceful,
            multiplexing: M::OwnedMasters,
        };
        let narrow = ConnectionPolicy {
            existing: E::Strict,
            multiplexing: M::Disabled,
        };
        assert_eq!(strictest_connection_policy(wide, narrow), narrow);
        assert_eq!(strictest_connection_policy(wide, wide), wide);
    }
}
