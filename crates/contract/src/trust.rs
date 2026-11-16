//! ⟨M05⟩ ADR-0006 revision 5 (§17; m05-plan §4): the trusted-work vocabulary of the
//! requests and results (ADR-0011 §2–§7). Types and wire forms only; joint wave 0 lands
//! them fail closed (every new request form answers `CAPABILITY_UNAVAILABLE` /
//! `driver_unavailable` before any record is written) and the capability
//! [`crate::ipc::capability::TRUSTED_WORK_V1`] is declared and not offered.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{EnvironmentId, PolicyId, ProfileId, WorkId, WorkspaceId};
use crate::request::{AccessPairRef, Capability};

/// Maximum size of a request's working directory, in bytes (m05-plan §4 item 1).
pub const MAX_CWD_BYTES: usize = 4096;

/// `EnsureRequest.context` (m05-plan §4 item 1): the caller's working directory, metadata
/// only. The runtime discovers, observes and reads the workspace itself (ADR-0011 §2.2
/// "Who reads it"); the client never sends a manifest. A same-user claim (ADR-0011 R2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkContext {
    /// Absolute path, 1 to 4096 bytes, no NUL.
    pub cwd: String,
}

/// A [`WorkContext`] outside its bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the working directory is an absolute path of 1 to 4096 bytes without NUL")]
pub struct WorkContextError;

impl WorkContext {
    /// Check the bounds. "Absolute" is this platform's rule ([`std::path::Path::is_absolute`]).
    ///
    /// # Errors
    /// [`WorkContextError`].
    pub fn validate(&self) -> Result<(), WorkContextError> {
        let c = &self.cwd;
        if c.is_empty()
            || c.len() > MAX_CWD_BYTES
            || c.contains('\0')
            || !std::path::Path::new(c).is_absolute()
        {
            return Err(WorkContextError);
        }
        Ok(())
    }
}

/// What a narrowing or block action applies to (ADR-0011 §7.3 "Targets"; m05-plan §4
/// item 2), tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyTarget {
    /// One policy.
    Policy {
        /// Policy.
        policy_id: PolicyId,
    },
    /// Every policy for a profile.
    Profile {
        /// Profile.
        profile: ProfileId,
    },
    /// Every policy of a workspace.
    Workspace {
        /// Workspace.
        workspace: WorkspaceId,
    },
    /// Every policy.
    All,
}

/// What the owner approves in a `TrustWorkspace` decision (ADR-0011 §2.1): the request
/// the workspace makes (its manifest ∩ the latest profile snapshot, or the trust record's
/// own scope when there is no manifest), fixed at decision creation (I5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustProposal {
    /// Profile.
    pub profile: ProfileId,
    /// Pairs (a subset of the profile; empty means the whole profile).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pairs: BTreeSet<AccessPairRef>,
    /// Environments.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub environments: BTreeSet<EnvironmentId>,
    /// Capabilities.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub capabilities: BTreeSet<Capability>,
    /// Lock behaviour requested by `preferences.background_work`, shown at review.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub background_work: bool,
}

/// What a `revoke` revokes (m05-plan §4 item 3), tagged by `kind`. Absent means the
/// request's `grant_id`, as in M01–M03.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevokeTarget {
    /// Stop one piece of work (ADR-0011 §7.2 "Stop (work)"): its unshared grants are
    /// revoked, its references on shared grants dropped, and the work ID never
    /// reactivates (`work_stopped`).
    Work {
        /// Environment; default the caller's.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        environment: Option<EnvironmentId>,
        /// Work ID.
        work_id: WorkId,
    },
}

/// Where a result's authority came from (m05-plan §4 item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContextKind {
    /// A trusted (or member) workspace's policy.
    Workspace,
    /// The personal policy.
    Personal,
    /// A parent binding (`delegate`).
    Delegation,
    /// An explicit request beyond policy, approved once.
    Explicit,
}

/// How much a context claim is worth (ADR-0011 R2): the working directory is a same-user
/// claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContextProvenance {
    /// Any same-user process can name any workspace.
    SameUserContext,
}

/// `EnsureData.context` (m05-plan §4 item 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContextReport {
    /// Kind.
    pub kind: ContextKind,
    /// The workspace, for `workspace`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    /// The policy the authority rests on, when one covered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    /// Its revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    /// Provenance.
    pub provenance: ContextProvenance,
}

/// `Enforcement.ordinary_aliases` (ADR-0011 §5.2 as ruled in §10 item 6).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OrdinaryAliases {
    /// Not known.
    #[default]
    Unknown,
    /// Ordinary aliases are environment-level: a sibling's shorter deadline is enforced
    /// on its bound contexts, not on the shared alias (R3).
    SharedEnvironmentDefault,
}

/// `Enforcement.owner_functions` (ADR-0011 §6.2–§6.3).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OwnerFunctions {
    /// Not known.
    #[default]
    Unknown,
    /// Nothing delegates them, but a same-user child can reach the control endpoint.
    NotDelegated,
    /// The child cannot reach them (only an M04 container row that mounts only the child
    /// endpoint).
    Unreachable,
}

/// `EventType::Activation` payload kinds (m05-plan §4 item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActivationEventKind {
    /// A background trigger activated covered access.
    Activated,
    /// A pause, cutoff, stop or cooldown blocked it (at most one per policy and reason per
    /// hour).
    Blocked,
    /// The request was not covered; no decision was created.
    NotCovered,
}

/// `EventType::Activation` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActivationEventPayload {
    /// Kind.
    pub kind: ActivationEventKind,
    /// Environment.
    pub environment_id: EnvironmentId,
    /// The policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    /// The workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    /// The stable reason (for `blocked` and `not_covered`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// How an observation matched the workspace records, as `inspect workspace` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WorkspaceMatchView {
    /// Equal path and identity.
    Trusted,
    /// A verified linked worktree.
    Member,
    /// No record matches.
    Untrusted,
    /// One `ReconcileWorkspace` decision away.
    Ambiguous,
    /// No workspace root above the working directory: personal context.
    None,
}

/// `inspect workspace` data (m05-plan §4 items 5, 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WorkspaceView {
    /// The working directory asked about.
    pub cwd: String,
    /// The discovered workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// The match.
    #[serde(rename = "match")]
    pub matched: WorkspaceMatchView,
    /// The workspace record, for `trusted`, `member` and `ambiguous`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    /// The workspace policy, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    /// The manifest's access digest (lowercase hex), when a manifest was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_digest: Option<String>,
    /// Provenance.
    pub provenance: ContextProvenance,
}

/// One applied revision in `inspect policies` (ADR-0011 §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyRevisionView {
    /// Revision.
    pub revision: u64,
    /// `decision` or `narrowing`.
    pub cause: String,
    /// The decision, for `decision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<crate::ids::DecisionId>,
    /// When.
    pub at: Timestamp,
}

/// One standing policy in `inspect policies`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyView {
    /// Policy.
    pub policy_id: PolicyId,
    /// Current revision.
    pub revision: u64,
    /// Profile.
    pub profile: ProfileId,
    /// The workspace, for a workspace policy; absent for a personal one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    /// Environments.
    pub environments: Vec<EnvironmentId>,
    /// The personal default for its environments (at most one per environment).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default: bool,
    /// Paused since.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_since: Option<Timestamp>,
    /// Hard cutoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_at: Option<Timestamp>,
    /// Applied revisions, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<PolicyRevisionView>,
}

/// `inspect policies` data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PoliciesView {
    /// Every standing policy.
    pub items: Vec<PolicyView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The working directory is metadata with hard bounds, checked before anything is
    /// read or written.
    #[test]
    fn work_context_bounds() {
        let abs = if cfg!(windows) { r"C:\w" } else { "/w" };
        assert!(WorkContext { cwd: abs.into() }.validate().is_ok());
        for bad in [
            String::new(),
            "relative/dir".to_owned(),
            format!("{abs}\0x"),
            format!("{abs}{}", "a".repeat(MAX_CWD_BYTES)),
        ] {
            assert!(
                WorkContext { cwd: bad.clone() }.validate().is_err(),
                "{bad:?}"
            );
        }
    }
}
