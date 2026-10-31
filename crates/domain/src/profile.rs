//! Profiles: mutable definition, immutable resolved snapshot for active work
//! (spec §4.1 "Profile", §6.2 "Resolve a profile ... at activation").

use heimdall_contract::ids::ProfileId;
use serde::{Deserialize, Serialize};

use crate::scope::Scope;

/// Mutable profile definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDefinition {
    /// Name.
    pub id: ProfileId,
    /// Current revision; bumped on every change.
    pub revision: u64,
    /// Intended scope.
    pub scope: Scope,
    /// Human label.
    pub label: Option<String>,
}

/// Immutable resolved snapshot pinned by a binding. Adding a host to the profile
/// later does not widen an existing grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSnapshot {
    /// Name.
    pub id: ProfileId,
    /// Revision resolved.
    pub revision: u64,
    /// Resolved scope at that revision.
    pub scope: Scope,
}

impl ProfileDefinition {
    /// Snapshot the current revision.
    #[must_use]
    pub fn snapshot(&self) -> ProfileSnapshot {
        ProfileSnapshot {
            id: self.id.clone(),
            revision: self.revision,
            scope: self.scope.clone(),
        }
    }
}
