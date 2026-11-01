//! `Request::Setup`: previewing, applying, rolling back and repairing the managed
//! OpenSSH (and optional Git) projection (ADR-0007 §5; m02-plan §5 item 2).
//!
//! `Preview` is read-only and never journaled. `Apply`, `Rollback` and `Repair`
//! carry the `plan_digest` of a preview the caller saw; the plan fixes the intent,
//! its options and the files, so the digest is their whole idempotency input
//! besides the environment (m02-plan §5 item 16). The application creates an
//! `ApplyProjection` decision when ADR-0007 §5.2 requires one; these types carry no
//! approval.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::doctor::{DirectiveObservation, Finding, GitSshSelection, GitValueObservation};
use crate::ids::{OperationId, RequestId};
use crate::provider::IdentitySelectionReport;

/// Maximum size of one rendered diff in a plan or decision summary (64 KiB).
pub const MAX_DIFF_BYTES: usize = 64 << 10;

/// A plan digest: lowercase hex SHA-256 (64 characters), transparent on the wire.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct PlanDigest(String);

/// A malformed [`PlanDigest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a plan digest is 64 lowercase hexadecimal characters")]
pub struct PlanDigestError;

impl PlanDigest {
    /// Parse a wire string: exactly 64 lowercase hex characters.
    pub fn parse(s: &str) -> Result<Self, PlanDigestError> {
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(s.to_owned()))
        } else {
            Err(PlanDigestError)
        }
    }

    /// From a raw SHA-256 output.
    #[must_use]
    pub fn from_sha256(bytes: [u8; 32]) -> Self {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        Self(s)
    }

    /// The wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PlanDigest {
    type Error = PlanDigestError;
    fn try_from(s: String) -> Result<Self, PlanDigestError> {
        Self::parse(&s)
    }
}

impl From<PlanDigest> for String {
    fn from(d: PlanDigest) -> String {
        d.0
    }
}

impl std::fmt::Display for PlanDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A projection item: the OpenSSH projection or the Git include (ADR-0007 §5.4).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProjectionItem {
    /// The OpenSSH include block B and the managed file P (with key files).
    Ssh,
    /// The Git include block B_git and the managed file P_git.
    Git,
}

/// A conflict a repair addresses (ADR-0007 §5.5, §5.7). Also a stable error reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConflictKind {
    /// The user file changed since the plan.
    UserConfigChanged,
    /// The managed file was edited.
    ManagedFileEdited,
    /// A marker line was edited.
    MarkerEdited,
    /// A marker appears more than once.
    MarkerDuplicated,
    /// The include block is conditional.
    IncludeConditional,
    /// A target file cannot be managed (manual mode).
    UnmanageableFile,
    /// A managed alias collides with a user alias.
    AliasCollision,
    /// Another writer changed a file during the transaction.
    ConcurrentWriter,
    /// Git's configuration lock is held.
    GitConfigLocked,
    /// A setup operation is held for the owner (ADR-0007 §5.7 outcome H).
    ProjectionHeld,
}

/// How a repair resolves its conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RepairResolution {
    /// Render the projection again.
    Rerender,
    /// Remove duplicated markers.
    RemoveDuplicateMarkers,
    /// Move the include block to the top.
    MoveIncludeToTop,
    /// Switch to manual mode.
    ManualMode,
    /// Retry a held operation's recovery (only with `projection_held`).
    RetryHeld,
    /// Close a held operation, keeping what is there (only with `projection_held`).
    KeepHeld,
}

impl RepairResolution {
    /// Whether this resolution acts on a held operation (ADR-0007 QR12).
    #[must_use]
    pub fn is_held_resolution(self) -> bool {
        matches!(
            self,
            RepairResolution::RetryHeld | RepairResolution::KeepHeld
        )
    }
}

fn all_items() -> BTreeSet<ProjectionItem> {
    [ProjectionItem::Ssh, ProjectionItem::Git]
        .into_iter()
        .collect()
}

/// What a preview plans (ADR-0007 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviewIntent {
    /// Install or re-render the projection.
    Apply {
        /// Also install the Git include (ADR-0007 §5.6).
        #[serde(default)]
        include_git: bool,
    },
    /// Remove the projection.
    Rollback {
        /// Keep the materialized public key files.
        #[serde(default)]
        keep_key_files: bool,
        /// The items to roll back; default both.
        #[serde(default = "all_items")]
        items: BTreeSet<ProjectionItem>,
    },
    /// Repair a conflict.
    Repair {
        /// The conflict.
        conflict: ConflictKind,
        /// The resolution.
        resolution: RepairResolution,
        /// The held operation, required for `retry_held` and `keep_held` and
        /// refused otherwise. Their plan's digest covers the held operation's
        /// canonical observation and each held step's content fingerprint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation: Option<OperationId>,
    },
}

/// A [`PreviewIntent`] that breaks a rule the wire types cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PreviewIntentError {
    /// A rollback names no item.
    #[error("a rollback names at least one item")]
    NoItems,
    /// `retry_held`/`keep_held` without `projection_held`, or `projection_held`
    /// with another resolution.
    #[error(
        "retry_held and keep_held go only with projection_held, and projection_held only with them"
    )]
    HeldResolutionMismatch,
    /// `retry_held`/`keep_held` without the held operation.
    #[error("retry_held and keep_held name the held operation")]
    OperationRequired,
    /// An operation named for any other resolution.
    #[error("only retry_held and keep_held name an operation")]
    OperationNotAllowed,
}

impl PreviewIntent {
    /// Check the rules of m02-plan §5 item 2 that the wire types cannot express.
    pub fn validate(&self) -> Result<(), PreviewIntentError> {
        match self {
            PreviewIntent::Apply { .. } => Ok(()),
            PreviewIntent::Rollback { items, .. } => {
                if items.is_empty() {
                    Err(PreviewIntentError::NoItems)
                } else {
                    Ok(())
                }
            }
            PreviewIntent::Repair {
                conflict,
                resolution,
                operation,
            } => {
                let held = resolution.is_held_resolution();
                if held != (*conflict == ConflictKind::ProjectionHeld) {
                    return Err(PreviewIntentError::HeldResolutionMismatch);
                }
                match (held, operation.is_some()) {
                    (true, false) => Err(PreviewIntentError::OperationRequired),
                    (false, true) => Err(PreviewIntentError::OperationNotAllowed),
                    _ => Ok(()),
                }
            }
        }
    }
}

/// `Request::Setup`, tagged by `action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SetupRequest {
    /// Read-only plan; not journaled, no operation ID. Answered with [`SetupPlan`].
    Preview {
        /// What to plan.
        intent: PreviewIntent,
    },
    /// Apply a previewed `apply` plan.
    Apply {
        /// The digest of the plan the caller saw.
        plan_digest: PlanDigest,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Apply a previewed `rollback` plan.
    Rollback {
        /// The digest of the plan the caller saw.
        plan_digest: PlanDigest,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Apply a previewed `repair` plan.
    Repair {
        /// The digest of the plan the caller saw.
        plan_digest: PlanDigest,
        /// Idempotency request ID.
        request_id: RequestId,
    },
}

impl SetupRequest {
    /// The operation-kind name (`setup.preview`, `setup.apply`, `setup.rollback`,
    /// `setup.repair`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            SetupRequest::Preview { .. } => "setup.preview",
            SetupRequest::Apply { .. } => "setup.apply",
            SetupRequest::Rollback { .. } => "setup.rollback",
            SetupRequest::Repair { .. } => "setup.repair",
        }
    }

    /// The plan digest of an effectful action.
    #[must_use]
    pub fn plan_digest(&self) -> Option<&PlanDigest> {
        match self {
            SetupRequest::Preview { .. } => None,
            SetupRequest::Apply { plan_digest, .. }
            | SetupRequest::Rollback { plan_digest, .. }
            | SetupRequest::Repair { plan_digest, .. } => Some(plan_digest),
        }
    }

    /// The idempotency request ID of an effectful action.
    #[must_use]
    pub fn request_id(&self) -> Option<&RequestId> {
        match self {
            SetupRequest::Preview { .. } => None,
            SetupRequest::Apply { request_id, .. }
            | SetupRequest::Rollback { request_id, .. }
            | SetupRequest::Repair { request_id, .. } => Some(request_id),
        }
    }
}

/// Whether Heimdall edits the user file or only writes P (ADR-0007 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SetupMode {
    /// Heimdall inserts the include block.
    Automatic,
    /// The owner inserts it; see `manual_reasons`.
    Manual,
}

/// Stable manual-mode reasons (also error reasons).
pub mod manual_reason {
    /// A target file cannot be managed.
    pub const UNMANAGEABLE_FILE: &str = "unmanageable_file";
    /// The filesystem cannot exchange atomically.
    pub const ATOMIC_EXCHANGE_UNSUPPORTED: &str = "atomic_exchange_unsupported";
    /// A file's encoding is not supported.
    pub const UNSUPPORTED_ENCODING: &str = "unsupported_encoding";
    /// `GIT_CONFIG_GLOBAL` redirects the global Git file.
    pub const GIT_GLOBAL_REDIRECTED: &str = "git_global_redirected";
    /// Every value.
    pub const ALL: &[&str] = &[
        UNMANAGEABLE_FILE,
        ATOMIC_EXCHANGE_UNSUPPORTED,
        UNSUPPORTED_ENCODING,
        GIT_GLOBAL_REDIRECTED,
    ];
}

/// The role of a file in a projection plan or result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProjectionFileRole {
    /// The user's OpenSSH configuration (holds B).
    UserSsh,
    /// The managed OpenSSH file P.
    ManagedSsh,
    /// A materialized public key file.
    KeyFile,
    /// The global Git file (holds B_git).
    GitInclude,
    /// The managed Git file P_git.
    GitManaged,
}

/// One file a plan changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileChange {
    /// Role.
    pub role: ProjectionFileRole,
    /// Display path.
    pub path_display: String,
    /// SHA-256 before, lowercase hex; absent when the file does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_sha256: Option<String>,
    /// SHA-256 after, lowercase hex; absent when the file is removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sha256: Option<String>,
    /// Unified diff, at most [`MAX_DIFF_BYTES`].
    pub diff: String,
}

/// How an alias is defined in a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AliasKind {
    /// Rendered into P.
    Managed,
    /// Defined by the user; observed only.
    Observed,
}

/// A behaviour digest and the directives behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BehaviorSummary {
    /// Behaviour digest (provenance reduced to its source role; ADR-0007 §5.2).
    pub digest: String,
    /// The relevant directives.
    #[serde(default)]
    pub directives: Vec<DirectiveObservation>,
}

/// One directive whose relevant behaviour differs between two states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BehaviorChange {
    /// Directive keyword.
    pub directive: String,
    /// Before (`certainty: unset` when absent).
    pub before: DirectiveObservation,
    /// After (`certainty: unset` when absent).
    pub after: DirectiveObservation,
}

/// One alias in a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AliasPreview {
    /// The alias.
    pub alias: String,
    /// Managed or observed.
    pub kind: AliasKind,
    /// Behaviour now.
    pub before: BehaviorSummary,
    /// Behaviour after the plan.
    pub after: BehaviorSummary,
    /// The consented restore state (rollback and repair; ADR-0007 §5.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<BehaviorSummary>,
    /// What changes.
    #[serde(default)]
    pub changes: Vec<BehaviorChange>,
    /// Directives the alias inherits from user configuration.
    #[serde(default)]
    pub inherited: Vec<DirectiveObservation>,
    /// The identity selection after the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_selection: Option<IdentitySelectionReport>,
}

/// Why a plan needs an owner decision (ADR-0007 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConsentReasonKind {
    /// The item reaches a state the owner has not consented to.
    NewState,
    /// The item exposes inherited behaviour.
    ExposesInherited,
    /// The item's current or after state is undetermined.
    UndeterminedState,
    /// Git's SSH selection changes.
    GitSelectionChanged,
}

/// One consent reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsentReason {
    /// The affected item (an alias or `git`).
    pub item: String,
    /// Why.
    pub kind: ConsentReasonKind,
}

/// Whether applying the plan needs an `ApplyProjection` decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsentNeed {
    /// A decision is required.
    pub decision_required: bool,
    /// Why.
    #[serde(default)]
    pub reasons: Vec<ConsentReason>,
}

/// Whether the Git include can be applied (ADR-0007 §5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitApplicability {
    /// No `core.sshCommand` at the system or global scopes (including every file
    /// they include).
    Applicable,
    /// See `reason`.
    NotApplicable,
}

/// Which global Git file holds B_git.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitGlobalFileKind {
    /// `~/.gitconfig`.
    HomeGitconfig,
    /// `$XDG_CONFIG_HOME/git/config`.
    XdgConfig,
}

/// How the global Git file was chosen (ADR-0007 §5.6 first-read rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitFileResolution {
    /// The first existing file in Git's read order.
    FirstReadExisting,
    /// None existed; `~/.gitconfig` is created.
    Created,
}

/// The chosen global Git file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GitGlobalFile {
    /// Display path.
    pub path_display: String,
    /// Which file.
    pub file: GitGlobalFileKind,
    /// How it was chosen.
    pub resolution: GitFileResolution,
}

/// The Git part of a plan (ADR-0007 §5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GitConfigChange {
    /// Whether it can be applied.
    pub applicability: GitApplicability,
    /// Why not, when not applicable (for example `git_config_unreadable`,
    /// `git_global_redirected`, `git_ssh_command_present`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The global file B_git goes into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_file: Option<GitGlobalFile>,
    /// The values that make it not applicable; empty when applicable.
    #[serde(default)]
    pub previous_values: Vec<GitValueObservation>,
    /// The change to the global file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_block: Option<FileChange>,
    /// The change to P_git.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_file: Option<FileChange>,
    /// Git's effective selection now.
    pub effective_before: GitSshSelection,
    /// Git's effective selection after the plan.
    pub effective_after: GitSshSelection,
}

/// A preview result (`Request::Setup(Preview)` data; schema `setup-plan`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SetupPlan {
    /// The digest an effectful request must carry.
    pub plan_digest: PlanDigest,
    /// What was planned.
    pub intent: PreviewIntent,
    /// Automatic or manual.
    pub mode: SetupMode,
    /// Why manual: [`manual_reason`]'s values.
    #[serde(default)]
    pub manual_reasons: Vec<String>,
    /// File changes.
    #[serde(default)]
    pub files: Vec<FileChange>,
    /// The Git part, when planned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitConfigChange>,
    /// Affected aliases.
    #[serde(default)]
    pub aliases: Vec<AliasPreview>,
    /// Consent.
    pub consent: ConsentNeed,
    /// How many unaffected names were checked to keep their behaviour.
    pub unaffected_names_checked: u32,
    /// Findings.
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// An item's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ItemOutcomeKind {
    /// Applied.
    Applied,
    /// Not applied; nothing changed.
    NotApplied,
    /// Applied, then restored after a failed check.
    Restored,
    /// Closed by the owner with `keep_held`.
    ConflictPreserved,
    /// Held for the owner (ADR-0007 §5.7 outcome H).
    Held,
}

/// A file's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileOutcomeState {
    /// Written and active.
    Applied,
    /// Not written.
    NotApplied,
    /// Restored.
    Restored,
    /// Written but not referenced (the item did not commit).
    WrittenInactive,
    /// Removed.
    Removed,
    /// Kept as found (`keep_held`).
    ConflictPreserved,
    /// Held for the owner.
    Held,
}

/// One file of an item's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileOutcome {
    /// Role.
    pub role: ProjectionFileRole,
    /// Display path.
    pub path_display: String,
    /// State.
    pub state: FileOutcomeState,
}

/// One item's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ItemOutcome {
    /// The item.
    pub item: ProjectionItem,
    /// Its outcome.
    pub outcome: ItemOutcomeKind,
    /// Its files.
    #[serde(default)]
    pub files: Vec<FileOutcome>,
}

/// The kind of an artifact left for the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemainingArtifactKind {
    /// A backup copy.
    Backup,
    /// A conflict file.
    ConflictFile,
    /// A manual-mode block the owner inserted.
    ManualBlock,
    /// The Heimdall state store.
    StateStore,
    /// A recovery record.
    RecoveryRecord,
    /// The quarantine directory.
    Quarantine,
}

/// An artifact left for the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemainingArtifact {
    /// Kind.
    pub kind: RemainingArtifactKind,
    /// Display path.
    pub path_display: String,
}

/// An apply, rollback or repair result (schema `setup-result`). A held operation's
/// error envelope (`OUTCOME_UNKNOWN`, reason `projection_held`) carries it in
/// `data.setup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SetupResult {
    /// The projection generation.
    pub generation: u64,
    /// One outcome per item.
    #[serde(default)]
    pub items: Vec<ItemOutcome>,
    /// Artifacts left for the owner.
    #[serde(default)]
    pub remaining: Vec<RemainingArtifact>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plan_digest_is_strict_lowercase_hex() {
        let ok = "0123456789abcdef".repeat(4);
        assert_eq!(PlanDigest::parse(&ok).unwrap().as_str(), ok);
        for bad in [
            String::new(),
            ok.to_uppercase(),
            ok[..63].to_owned(),
            format!("{ok}0"),
            format!("{}g", &ok[..63]),
        ] {
            assert_eq!(PlanDigest::parse(&bad), Err(PlanDigestError), "{bad}");
        }
        assert_eq!(
            PlanDigest::from_sha256([0xab; 32]).as_str(),
            "ab".repeat(32)
        );
        let wire = serde_json::to_string(&PlanDigest::parse(&ok).unwrap()).unwrap();
        assert_eq!(wire, format!("\"{ok}\""));
        assert!(serde_json::from_str::<PlanDigest>("\"ABC\"").is_err());
    }

    #[test]
    fn preview_intent_defaults_and_rules() {
        let apply: PreviewIntent = serde_json::from_str(r#"{"kind":"apply"}"#).unwrap();
        assert_eq!(apply, PreviewIntent::Apply { include_git: false });
        let rollback: PreviewIntent = serde_json::from_str(r#"{"kind":"rollback"}"#).unwrap();
        assert_eq!(
            rollback,
            PreviewIntent::Rollback {
                keep_key_files: false,
                items: all_items()
            }
        );
        assert_eq!(rollback.validate(), Ok(()));
        let empty = PreviewIntent::Rollback {
            keep_key_files: false,
            items: BTreeSet::new(),
        };
        assert_eq!(empty.validate(), Err(PreviewIntentError::NoItems));
    }
}
