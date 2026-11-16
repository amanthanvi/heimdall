//! ⟨M05⟩ Workspace identity and the M05 authority records (ADR-0011 §2.1, §2.3, §4.2–§4.4,
//! §5.2, §7.2; ADR-0006 revision 5, §17). Types only, landed by joint wave 0: the match
//! function is `heimdall_project::match_workspace` (M05 U1), the policy actions that write
//! these records are M05 U2/U3, and the store accessors are `heimdall_store::ext_m05`.
//!
//! Identity is a local observation recorded at the owner's decision (ADR-0011 I3): the Git
//! remote URL, `.git` contents and the manifest's `project` label are never identity.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, BindingId, DecisionId, DestinationId, EnvironmentId, PolicyId, WorkId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::policy::{PolicyRevision, StandingPolicy};
use crate::projection::FileIdentity;

/// A trusted workspace's local identity record (ADR-0011 §2.1 option A). Lives only in the
/// local state store (`workspaces` table, migration 0008); never exported (I4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    /// Workspace ID.
    pub id: WorkspaceId,
    /// The environment whose path namespace `root` is in (ADR-0011 §2.3 last paragraph).
    pub environment: EnvironmentId,
    /// The canonical root path, as observed at the decision.
    pub root: String,
    /// The root directory's file identity. A filesystem without one is refused
    /// (`workspace_identity_unavailable`), never approximated (R6).
    pub root_identity: FileIdentity,
    /// The Git common directory's identity, when the root is a Git checkout (the
    /// linked-worktree back-link check of §2.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_common_identity: Option<FileIdentity>,
    /// The decision that created (or last reconciled) the record.
    pub decision: DecisionId,
    /// When it was created.
    pub created_at: Timestamp,
    /// Whether the record is current or listed as stale (a move across filesystems).
    #[serde(default)]
    pub state: WorkspaceState,
}

/// Whether a workspace record still matches anything (ADR-0011 §2.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceState {
    /// Current.
    #[default]
    Active,
    /// No observation matches it any more (listed as stale; never matched).
    Stale,
}

/// Why an observation is ambiguous against a record (ADR-0011 §2.3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AmbiguityReason {
    /// Same canonical path, different root identity: a re-clone at the same path or a
    /// restore from backup.
    SamePathOtherIdentity,
    /// Same root identity, different path: a move within one filesystem.
    SameIdentityOtherPath,
}

/// The result of matching an observation against the workspace records
/// (`heimdall_project::match_workspace`, M05 U1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceMatch {
    /// Equal canonical path and equal root identity.
    Trusted {
        /// The record.
        workspace: WorkspaceId,
    },
    /// A verified linked worktree of the trusted checkout (owner question Q1).
    Member {
        /// The record.
        workspace: WorkspaceId,
    },
    /// No record matches (a copy, a clone, a cross-filesystem move, a submodule).
    Untrusted,
    /// One record matches partly: one `ReconcileWorkspace` decision, and no workspace grant
    /// until it is applied (ADR-0011 §10 item 1).
    Ambiguous {
        /// The record it partly matches.
        workspace: WorkspaceId,
        /// Why.
        why: AmbiguityReason,
    },
}

/// One applied policy change (`policy_history`, ADR-0011 §4.4): the revision and the whole
/// record as applied, with its cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHistoryEntry {
    /// Policy.
    pub policy: PolicyId,
    /// The revision this entry wrote.
    pub revision: PolicyRevision,
    /// The policy record as applied.
    pub record: StandingPolicy,
    /// What applied it.
    pub cause: PolicyChangeCause,
    /// When.
    pub at: Timestamp,
}

/// What applied a policy change (ADR-0011 §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyChangeCause {
    /// An attended owner decision (every widening, ADR-0011 I1).
    Decision {
        /// The decision.
        decision: DecisionId,
    },
    /// An immediate narrowing on the owner channel (pause, stop, earlier cutoff, narrow).
    Narrowing,
}

/// A denied decision's cooldown (ADR-0011 §4.3): requesters asking for the same key get
/// `decision_cooldown` until `until`, or until the policy revision or the delta changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionCooldown {
    /// The coalescing key's digest (policy, revision, environment, canonical delta;
    /// ADR-0011 §4.2), lowercase hex SHA-256.
    pub key: String,
    /// Policy.
    pub policy: PolicyId,
    /// Policy revision the denied decision was raised against.
    pub revision: PolicyRevision,
    /// Environment.
    pub environment: EnvironmentId,
    /// The denied decision.
    pub decision: DecisionId,
    /// When the cooldown ends (the policy's saved window after the denial, P04).
    pub until: Timestamp,
}

/// A stopped work ID (ADR-0011 §7.2 "Stop (work)"): never reactivated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkStop {
    /// Environment.
    pub environment: EnvironmentId,
    /// Work ID.
    pub work_id: WorkId,
    /// When it was stopped.
    pub stopped_at: Timestamp,
}

/// A binding's reference to a shared ordinary-alias slot (ADR-0011 §5.2, as ruled in §10
/// item 6): the slot's materializer is one of these; the rest wait for handover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotReference {
    /// Environment.
    pub environment: EnvironmentId,
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// The referencing binding.
    pub binding: BindingId,
    /// Its grant's deadline (handover goes to the latest one).
    pub deadline: Timestamp,
    /// When it joined.
    pub joined_at: Timestamp,
}

/// What a binding pins as its context (ADR-0011 §5.1): a workspace, or personal work
/// (`bindings.context_json`, migration 0008; absent means personal).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum BindingContext {
    /// Repository-free work, ordinary `ssh`, an untrusted workspace covered by personal
    /// policy.
    Personal,
    /// A trusted (or member) workspace.
    Workspace {
        /// The workspace.
        workspace: WorkspaceId,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The match wire form is the tagged shape the result types and the model use.
    #[test]
    fn match_wire_forms() {
        let ws = WorkspaceId::from_random_bytes([7; 16]);
        let m = WorkspaceMatch::Ambiguous {
            workspace: ws.clone(),
            why: AmbiguityReason::SamePathOtherIdentity,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["match"], "ambiguous");
        assert_eq!(v["why"], "same_path_other_identity");
        assert_eq!(serde_json::from_value::<WorkspaceMatch>(v).unwrap(), m);
        let u = serde_json::to_value(WorkspaceMatch::Untrusted).unwrap();
        assert_eq!(u, serde_json::json!({ "match": "untrusted" }));
    }
}
