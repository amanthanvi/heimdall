//! Standing policy (spec §4.1, §6.1; plan §4.3 "mutable versioned standing
//! policies"). Pause and cutoff outrank standing automatic permission.

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{EnvironmentId, PolicyId, ProfileId, WorkspaceId};
use serde::{Deserialize, Serialize};

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
