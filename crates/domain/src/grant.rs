//! Grants: immutable scope/deadline snapshots (spec §4.1 "Grant", §6.1, §6.7;
//! plan §4.3).

use heimdall_contract::ids::{BindingId, EnvironmentId, GrantId, OperationId, ProfileId};
use heimdall_contract::{GrantState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::evidence::EnforcementEvidence;
use crate::operation::CoveredBasis;
use crate::policy::{AuthorityGeneration, PolicyRevision};
use crate::principal::CallerContext;
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

/// ⟨r2.6⟩ Where a grant's authority was resolved, persisted **with the grant**
/// (ADR-0006 §13.9 item 2; `heimdall_store::Txn::{set_grant_origin, grant_origin}`).
///
/// Together with the snapshot (scope, deadline, environment, parent, source) and
/// the approval basis persisted with the grant, it is the whole context
/// re-validation needs (§13.5 ruling 2): no consumer binding and no operation
/// record plays a part, so a parent kept alive only by its delegated child's
/// reference (§13.5 ruling 1) re-validates like any other grant. Written once when
/// the grant is created; operation retention never touches it. A grant without a
/// recorded origin is the only case whose re-validation is undetermined (refuse
/// the use, end nothing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantOrigin {
    /// Profile pinned at resolution.
    pub profile: ProfileId,
    /// Profile revision pinned at resolution.
    pub profile_revision: u64,
    /// Applicable standing-policy revision at resolution, if any.
    pub policy_revision: Option<PolicyRevision>,
    /// The caller the authority was resolved for (its role bounds what
    /// re-resolution may accept).
    pub caller: CallerContext,
    /// Credential mechanism selected at resolution.
    pub mechanism: String,
    /// ADR-0006 §13.7 item 2: the standing policy this waiting owner-decision grant
    /// came to rest on when the saved policy covered it entirely. Absent otherwise;
    /// add-only (recorded once, never replaced or cleared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<CoveredBasis>,
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
