//! Grants: immutable scope/deadline snapshots (spec §4.1 "Grant", §6.1, §6.7;
//! plan §4.3).

use heimdall_contract::ids::{BindingId, EnvironmentId, GrantId, OperationId};
use heimdall_contract::{GrantState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::evidence::EnforcementEvidence;
use crate::policy::{AuthorityGeneration, PolicyRevision};
use crate::scope::Scope;
use crate::time::Deadline;

/// Where the grant's authorization came from (spec §4.1 "source of authorization").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorizationSource {
    /// Standing policy at a revision.
    StandingPolicy {
        /// Revision.
        revision: PolicyRevision,
    },
    /// Owner decision recorded for this operation.
    OwnerDecision {
        /// Operation carrying the decision.
        operation_id: OperationId,
    },
    /// Delegated from a parent grant.
    Delegation {
        /// Parent.
        parent: GrantId,
    },
}

/// Immutable grant snapshot. Renewal maintains it; nothing extends `deadline` or
/// adds pairs (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSnapshot {
    /// Grant ID.
    pub id: GrantId,
    /// Environment pinned.
    pub environment: EnvironmentId,
    /// Effective scope at authorization.
    pub scope: Scope,
    /// Start.
    pub starts_at: Timestamp,
    /// Immutable maximum deadline.
    pub deadline: Deadline,
    /// Parent for delegation; cascades expiry/revocation/cutoff.
    pub parent: Option<GrantId>,
    /// Authorization provenance.
    pub source: AuthorizationSource,
    /// Authority generation at authorization; rechecked before activation and
    /// before every issuance (R-SE-07).
    pub generation: AuthorityGeneration,
    /// Current state.
    pub state: GrantState,
    /// Enforcement evidence recorded with the grant.
    pub enforcement: EnforcementEvidence,
}

/// A consumer reference to a grant (spec §6.3 "ownership-aware reference counts").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReference {
    /// Binding holding the reference.
    pub binding: BindingId,
    /// Grant referenced.
    pub grant: GrantId,
    /// When acquired.
    pub acquired_at: Timestamp,
}

impl GrantSnapshot {
    /// Whether `child_scope`/`child_deadline` would be a valid delegation from this
    /// grant (plan §6.3 property 2). Pure.
    #[must_use]
    pub fn permits_child(&self, child_scope: &Scope, child_deadline: Timestamp) -> bool {
        child_scope.is_subset_of(&self.scope) && child_deadline <= self.deadline.effective
    }
}
