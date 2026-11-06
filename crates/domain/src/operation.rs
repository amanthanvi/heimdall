//! Durable operations (spec §4.1 "Operation", §11.4).

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_contract::setup::{ConflictKind, ProjectionItem};
use heimdall_contract::{Code, OperationState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::catalog::CatalogIntent;
use crate::idempotency::IdempotencyKey;
use crate::projection::{ContentState, FileIdentity, RecordedRole, SetupIntent, Sha256Hex};

/// Operation kinds; the string form is the idempotency namespace
/// (`heimdall_contract::request::Request::kind`).
///
/// The serde form equals [`OperationKind::as_str`] for every kind, so the store's
/// `kind` columns, `record_json`, events, `inspect operations` and the
/// idempotency-key hash all use one name. The M02 kinds carry the dotted request
/// names (`setup.apply`, …) on the wire too (wave-0 verifier escalation E4).
///
/// Not `#[non_exhaustive]`: the application's restart driver matches it without a
/// wildcard (m02-plan U0b row 10), so a new kind fails to compile until it has a
/// driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// `ensure`.
    Ensure,
    /// `bind`.
    Bind,
    /// `delegate`.
    Delegate,
    /// `cancel`. Declared, never journaled.
    Cancel,
    /// `release`. Declared, never journaled.
    Release,
    /// `revoke`.
    Revoke,
    /// Owner policy action. Declared, never journaled.
    Policy,
    /// Reserved for explicit active probes. No request has this kind and it is never
    /// journaled in M02: explicit probes run in the doctor or CLI process (ADR-0007
    /// §6).
    Probe,
    /// ⟨M02⟩ `setup.apply` (m02-plan §5 item 17; U0b row 13). Effect class
    /// `local_resources`.
    #[serde(rename = "setup.apply")]
    SetupApply,
    /// ⟨M02⟩ `setup.rollback`. Effect class `local_resources`.
    #[serde(rename = "setup.rollback")]
    SetupRollback,
    /// ⟨M02⟩ `setup.repair`. Effect class `local_resources`.
    #[serde(rename = "setup.repair")]
    SetupRepair,
    /// ⟨M02⟩ `catalog`, every action (the action enters the hash extras). Effect
    /// class `local`.
    Catalog,
}

impl OperationKind {
    /// Every kind, in declaration order.
    pub const ALL: [OperationKind; 12] = [
        OperationKind::Ensure,
        OperationKind::Bind,
        OperationKind::Delegate,
        OperationKind::Cancel,
        OperationKind::Release,
        OperationKind::Revoke,
        OperationKind::Policy,
        OperationKind::Probe,
        OperationKind::SetupApply,
        OperationKind::SetupRollback,
        OperationKind::SetupRepair,
        OperationKind::Catalog,
    ];

    /// The setup kinds, serialized per environment (`setup_in_progress`, ADR-0007
    /// §5.7 "One setup operation at a time").
    pub const SETUP: [OperationKind; 3] = [
        OperationKind::SetupApply,
        OperationKind::SetupRollback,
        OperationKind::SetupRepair,
    ];

    /// Stable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OperationKind::Ensure => "ensure",
            OperationKind::Bind => "bind",
            OperationKind::Delegate => "delegate",
            OperationKind::Cancel => "cancel",
            OperationKind::Release => "release",
            OperationKind::Revoke => "revoke",
            OperationKind::Policy => "policy",
            OperationKind::Probe => "probe",
            OperationKind::SetupApply => "setup.apply",
            OperationKind::SetupRollback => "setup.rollback",
            OperationKind::SetupRepair => "setup.repair",
            OperationKind::Catalog => "catalog",
        }
    }

    /// Whether this is a setup kind (`setup.apply`, `setup.rollback`, `setup.repair`).
    #[must_use]
    pub fn is_setup(self) -> bool {
        matches!(
            self,
            OperationKind::SetupApply | OperationKind::SetupRollback | OperationKind::SetupRepair
        )
    }

    /// The effect class of an M02 kind (U0b row 13): `local_resources` for setup,
    /// `local` for catalog; `None` for the M01 kinds, whose class the pipeline
    /// assigns.
    #[must_use]
    pub fn m02_effect_class(self) -> Option<EffectClass> {
        match self {
            OperationKind::SetupApply
            | OperationKind::SetupRollback
            | OperationKind::SetupRepair => Some(EffectClass::LocalResources),
            OperationKind::Catalog => Some(EffectClass::Local),
            OperationKind::Ensure
            | OperationKind::Bind
            | OperationKind::Delegate
            | OperationKind::Cancel
            | OperationKind::Release
            | OperationKind::Revoke
            | OperationKind::Policy
            | OperationKind::Probe => None,
        }
    }
}

/// Effect classification recorded at creation (spec §4.1 "effect classification").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// Local state only.
    Local,
    /// Local plus owned endpoints/processes/config projections.
    LocalResources,
    /// May mutate a remote destination (enrollment); never auto-replayed.
    RemoteMutation,
}

/// Cancellation record (spec §11.4: reports whether an irreversible or uncertain
/// step may have occurred).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    /// When requested.
    pub requested_at: Timestamp,
    /// Whether an irreversible or uncertain external step may have happened.
    pub may_have_external_effect: bool,
}

/// Recovery metadata (spec §4.1 "recovery metadata"; plan §4.2 "interruptible
/// between each stage").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMetadata {
    /// Last durable stage reached (pipeline stage name).
    pub last_stage: Option<String>,
    /// Attempts so far.
    pub attempts: u32,
    /// Original operation when this is a recovery attempt (spec §6.3 `failed`).
    pub recovers: Option<OperationId>,
}

/// Durable operation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    /// ID.
    pub id: OperationId,
    /// Kind.
    pub kind: OperationKind,
    /// Environment.
    pub environment: EnvironmentId,
    /// Idempotency key.
    pub key: IdempotencyKey,
    /// Canonical request hash.
    pub request_hash: RequestHash,
    /// Effect class.
    pub effect_class: EffectClass,
    /// State.
    pub state: OperationState,
    /// Result code once terminal.
    pub code: Option<Code>,
    /// Effect status once known.
    pub effect_status: EffectStatus,
    /// Result payload (redacted JSON) once terminal.
    pub result: Option<serde_json::Value>,
    /// Created.
    pub created_at: Timestamp,
    /// Updated.
    pub updated_at: Timestamp,
    /// Cancellation, if any.
    pub cancellation: Option<CancellationRecord>,
    /// Recovery metadata.
    pub recovery: RecoveryMetadata,
}

// --- durable recovery intent and stage receipts (review F05; plan §4.2, §4.3) ------

/// Stable identity of the adapter instance that performs an effect, so recovery
/// asks the same adapter to reconcile (ADR-0006 §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdapterIdentity {
    /// Mechanism name (`credential_mechanism`).
    pub mechanism: String,
    /// Instance identifier within the mechanism (e.g. endpoint path hash).
    pub instance: String,
}

/// What `LoadAuthority`/`ResolveMechanism` established, persisted before any effect
/// so a retry or restart resumes the **same** intent and never re-resolves the
/// deadline or snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedIntent {
    /// Profile pinned.
    pub profile: heimdall_contract::ids::ProfileId,
    /// Profile revision pinned.
    pub profile_revision: u64,
    /// Resolved scope.
    pub scope: crate::scope::Scope,
    /// Resolved deadline (intent verbatim + effective instant).
    pub deadline: crate::time::Deadline,
    /// Policy revision the authority rests on.
    pub policy_revision: Option<crate::policy::PolicyRevision>,
    /// Authority generation at resolution.
    pub generation: crate::policy::AuthorityGeneration,
    /// Grant created for this operation, once created.
    pub grant: Option<heimdall_contract::ids::GrantId>,
    /// Binding created for this operation, once created.
    pub binding: Option<heimdall_contract::ids::BindingId>,
    /// Adapter selected.
    pub adapter: Option<AdapterIdentity>,
    /// The owner approval this added-authority intent rests on, recorded once when
    /// the owner approves (code review A06; ADR-0006 §3.1, §13.6 items 2 and 10).
    /// Absent for authority the standing policy covers. Add-only: never replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalBasis>,
    /// ⟨r2.4⟩ ADR-0006 §13.7 item 2: the standing policy this waiting added-authority
    /// intent came to rest on when the owner's saved policy covered it entirely
    /// (its recomputed delta was empty), recorded once when it left
    /// `awaiting_approval` without a decision. Absent otherwise. Add-only: never
    /// replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered: Option<CoveredBasis>,
}

/// ⟨r2.4⟩ What re-based a waiting added-authority intent when the owner's saved
/// standing policy came to cover it entirely (ADR-0006 §13.7 item 2; spec §5.5 "no
/// prompt for authority the owner already saved").
///
/// The request then proceeds as a standing-policy activation, with its unchanged
/// scope and deadline, through the normal time, pause and cutoff checks; no
/// decision record is issued. Like [`ApprovalBasis`], it re-bases the pinned
/// generation and policy revision without rewriting them: activation re-validates
/// against `generation` and requires the applicable policy at `policy_revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoveredBasis {
    /// Authority generation at which the standing policy covered the request.
    pub generation: crate::policy::AuthorityGeneration,
    /// Applicable standing-policy revision at that generation, if any.
    pub policy_revision: Option<crate::policy::PolicyRevision>,
}

/// What an attended approval of added authority established (code review A06).
///
/// A replacement decision is recomputed against the policy current at its own
/// generation (ADR-0006 §13.6 item 2), so the approval rests on that generation and
/// that applicable policy revision, not on the ones pinned at resolution. Before
/// preparation and activation the application re-validates the grant and refuses
/// when the authority it needs is no longer within `delta`, or the applicable
/// policy moved past `policy_revision`.
///
/// ⟨r2.4⟩ ADR-0006 §13.7 item 3: the basis is also persisted **with the grant**
/// (`heimdall_store::Txn::set_grant_approval`), so operation retention cannot
/// remove it; re-validation of an owner-approved grant then requires the grant's
/// scope ⊆ (current applicable standing policy ∪ `delta`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBasis {
    /// The approved decision record.
    pub decision: heimdall_contract::ids::DecisionId,
    /// Exactly the delta the owner approved.
    pub delta: crate::authority::AuthorityDelta,
    /// Authority generation the approval was made at (the record's generation).
    pub generation: crate::policy::AuthorityGeneration,
    /// Applicable standing-policy revision at that generation, if any.
    pub policy_revision: Option<crate::policy::PolicyRevision>,
}

/// Durable, redacted recovery intent for an operation (review F05 fix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryIntent {
    /// The original request as submitted, minus secrets (the `Request` JSON with
    /// no credential material; requests never carry secrets by contract).
    pub request: serde_json::Value,
    /// Resolved intent once the pipeline reached `ResolveMechanism`.
    pub resolved: Option<ResolvedIntent>,
    /// ⟨M02⟩ The local intent of a setup or catalog operation (m02-plan §5 item 17;
    /// frozen). Serde default, omitted when absent, so an M01 intent decodes with
    /// `None` and re-encodes byte-identically. Add-only (U0b row 16): `None → Some`
    /// once; then only its approval may go `None → Some` once. Never set together
    /// with `resolved`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalIntent>,
}

/// ⟨M02⟩ The local intent of a setup or catalog operation, tagged `kind`:
/// `{"kind":"setup",…}` wraps a [`SetupIntent`], `{"kind":"catalog",…}` a
/// [`CatalogIntent`] (m02-plan §5 item 17; frozen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalIntent {
    /// A setup operation's intent.
    Setup(SetupIntent),
    /// A catalog operation's intent.
    Catalog(CatalogIntent),
}

/// Why a local intent is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LocalIntentError {
    /// The setup intent breaks a content, binding or bound rule.
    #[error("setup intent: {0}")]
    Setup(#[from] crate::projection::IntentError),
    /// The catalog intent's approval does not fit its action.
    #[error("catalog intent: {0}")]
    Catalog(#[from] crate::catalog::CatalogIntentError),
}

impl LocalIntent {
    /// Validate on build and on every read (ADR-0007 §5.7; escalation E9).
    pub fn validate(&self) -> Result<(), LocalIntentError> {
        match self {
            LocalIntent::Setup(i) => Ok(i.validate()?),
            LocalIntent::Catalog(i) => Ok(i.validate()?),
        }
    }

    /// The intent with its approval removed: the part that never changes once
    /// stored.
    #[must_use]
    pub fn without_approval(&self) -> LocalIntent {
        match self {
            LocalIntent::Setup(i) => LocalIntent::Setup(i.without_approval()),
            LocalIntent::Catalog(i) => LocalIntent::Catalog(i.without_approval()),
        }
    }

    /// Whether the approval is set.
    #[must_use]
    pub fn has_approval(&self) -> bool {
        match self {
            LocalIntent::Setup(i) => i.approval.is_some(),
            LocalIntent::Catalog(i) => i.approval.is_some(),
        }
    }
}

/// Whether and how an external effect happened. **A hash or a stage marker is
/// never an effect receipt**; only these values are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectReceipt {
    /// The stage performed no external effect.
    NotAttempted,
    /// The effect was started with this token; outcome not yet confirmed. On
    /// recovery the same adapter is asked to `reconcile(token)`.
    Attempted {
        /// Adapter asked.
        adapter: AdapterIdentity,
        /// Idempotency token minted before the call.
        effect_token: String,
    },
    /// The adapter confirmed the effect (and returned a credential reference).
    Confirmed {
        /// Adapter.
        adapter: AdapterIdentity,
        /// Opaque credential reference (never material).
        credential_ref: String,
    },
    /// The adapter could not say (lost acknowledgment); stays uncertain until
    /// reconciliation.
    Uncertain {
        /// Adapter.
        adapter: AdapterIdentity,
        /// Token to reconcile with.
        effect_token: String,
    },
}

/// A receipt written when a pipeline stage durably completes (plan §4.2 "journal
/// intent, perform the scoped action, record outcome").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReceipt {
    /// Stage name (`heimdall_app::ensure::EnsureStage::as_str`; `setup.file` or
    /// `setup.item` for a local receipt).
    pub stage: String,
    /// When recorded.
    pub recorded_at: Timestamp,
    /// Effect status of the stage. For a local receipt it is fixed by the phase:
    /// `Confirmed` for `item.committed` and `item.finished{applied}`, `Attempted`
    /// otherwise (m02-plan §5 item 17a).
    pub effect: EffectReceipt,
    /// ⟨M02⟩ The typed local receipt payload (m02-plan §5 item 17a; frozen). Serde
    /// default, omitted when absent: every M01 receipt decodes with `None` and
    /// re-encodes byte-identically. Only the setup driver reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalReceipt>,
}

// --- ⟨M02⟩ typed local receipt payload (m02-plan §5 item 17a; ADR-0007 §5.7; frozen) -
//
// These enums are exhaustive: an unknown scope, phase or value fails to decode, and
// the setup driver then leaves its operation unresolved (`unreadable_receipts`) and
// infers nothing. Adding a phase needs an ADR-0007 revision with a migration note.

/// Stage name of a file-level local receipt.
pub const STAGE_SETUP_FILE: &str = "setup.file";
/// Stage name of an item-level local receipt.
pub const STAGE_SETUP_ITEM: &str = "setup.item";

/// A local receipt, tagged `scope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum LocalReceipt {
    /// A file step's phase.
    File {
        /// Index into `SetupIntent.files`.
        step: u16,
        /// The phase.
        phase: FilePhase,
    },
    /// An item's phase.
    Item {
        /// The item.
        item: ProjectionItem,
        /// The phase.
        phase: ItemPhase,
    },
}

impl LocalReceipt {
    /// The `StageReceipt.stage` name this receipt is written under.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        match self {
            LocalReceipt::File { .. } => STAGE_SETUP_FILE,
            LocalReceipt::Item { .. } => STAGE_SETUP_ITEM,
        }
    }

    /// Whether the phase fixes the receipt's effect at `Confirmed`
    /// (`item.committed`, `item.finished{applied}`); every other phase is
    /// `Attempted`.
    #[must_use]
    pub fn effect_is_confirmed(&self) -> bool {
        matches!(
            self,
            LocalReceipt::Item {
                phase: ItemPhase::Committed { .. }
                    | ItemPhase::Finished {
                        outcome: ItemFinish::Applied,
                        ..
                    },
                ..
            }
        )
    }
}

/// A file step's phase, tagged `kind` (ADR-0007 §5.7 "Receipts").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilePhase {
    /// S was created and fsync'd (K for the `git_lock` step, before the claim).
    Staged {
        /// S's identity.
        identity: FileIdentity,
    },
    /// The boundary recheck passed, before the exchange.
    Validated {
        /// V, or `None` for an absent base.
        base: Option<FileIdentity>,
    },
    /// The exchange (or the no-replace create) returned.
    Exchanged,
    /// Post-validation.
    PostValidated {
        /// Valid or mismatch.
        verdict: PostVerdict,
        /// On a mismatch, the identity observed at the displaced name.
        observed: Option<FileIdentity>,
    },
    /// Before a restore exchange, after the path was checked to hold S with the
    /// target digest.
    RestoreStarted {
        /// Why.
        cause: RestoreCause,
    },
    /// After the restore exchange (for a create, after the path's settlement).
    Restored,
    /// ⟨r4⟩ The step reached outcome H. Identities only, never content. A record
    /// for the owner and the repair preview: never a recovery phase.
    Held {
        /// Why.
        reason: HoldReason,
        /// What each observed name held.
        observed: Vec<ObservedName>,
    },
    /// Before the move into the quarantine.
    Settling {
        /// Which name is moved.
        source: SettleSource,
        /// ⟨r4⟩ That name.
        name: String,
        /// Its expected identity.
        expected: FileIdentity,
        /// ⟨r4⟩ Its expected digest.
        expected_sha256: Sha256Hex,
        /// The quarantine slot.
        slot: String,
    },
    /// After the moved entry's identity and digest were verified, before removal.
    Settled {
        /// Disposition.
        disposition: SettledDisposition,
    },
    /// The source was missing or foreign, or the moved entry's content changed.
    SettleConflict {
        /// What was found.
        found: SettleConflictFound,
        /// Where it was kept.
        kept: Vec<PreservedEntry>,
    },
}

/// A post-validation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostVerdict {
    /// The path is S and the displaced name is V.
    Valid,
    /// The displaced entry is not the validated base.
    Mismatch,
}

/// Why a restore runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreCause {
    /// `post_validated{mismatch}`.
    FileMismatch,
    /// The item's transaction check failed (`item.rolling_back`).
    TransactionCheck,
}

/// ⟨r4⟩ Why a step is held (ADR-0007 §5.7 "Outcome H").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    /// After an exchange, before the outcome is recorded, the path is not S.
    ActiveEntryReplaced,
    /// The path holds S′ when a restore is due (QR13).
    ActiveEntryModified,
    /// D is gone.
    DisplacedMissing,
    /// Another entry is at D's name.
    DisplacedReplaced,
    /// A third writer.
    ThirdWriter,
    /// Neither receipts nor entries show whether the exchange happened.
    AmbiguousExchange,
    /// The observation failed.
    Unobservable,
    /// No row lists the combination.
    Unmatched,
    /// ⟨r5⟩ The history breaks the phase order, or the item's receipts contradict
    /// each other.
    ContradictoryReceipts,
}

/// Which name a held receipt's observation is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedNameRole {
    /// The path.
    Path,
    /// The aside name (staged or displaced).
    Aside,
    /// The quarantine slot.
    Slot,
}

/// What an observed name held, by identity, never content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservedEntry {
    /// ∅.
    Absent,
    /// A recorded entry (S, V, D or Q), with or without its expected content.
    Recorded {
        /// Which.
        which: RecordedRole,
        /// Content.
        content: ContentState,
    },
    /// X, with its identity when one could be read.
    Foreign {
        /// Identity.
        identity: Option<FileIdentity>,
    },
    /// ?.
    Unobservable,
}

/// One observed name of a held receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedName {
    /// Which name.
    pub name: ObservedNameRole,
    /// What it held.
    pub entry: ObservedEntry,
}

/// Which name a settlement moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettleSource {
    /// The displaced entry (D, after an exchange).
    Displaced,
    /// The staged entry (S, before an exchange or after a restore).
    Staged,
    /// The path entry (a create's restore; K's release from the lock name).
    Path,
}

/// How a settlement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettledDisposition {
    /// Moved into the quarantine and verified.
    Quarantined,
    /// A create: nothing was displaced.
    NothingDisplaced,
}

/// What a settlement conflict found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettleConflictFound {
    /// The source was missing.
    Missing,
    /// A foreign entry was at the source or in the slot.
    Foreign,
    /// ⟨r4⟩ The moved entry's content had changed.
    Modified,
}

/// An entry a settlement conflict kept in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreservedEntry {
    /// Where it was kept.
    pub name: String,
    /// Its identity, when one could be read.
    pub identity: Option<FileIdentity>,
}

/// An item's phase, tagged `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ItemPhase {
    /// Written with the item's resources, record and consent in one transaction.
    Committed {
        /// The generation committed.
        generation: u64,
    },
    /// Before a transaction-level restore.
    RollingBack {
        /// Why.
        reason: ConflictKind,
    },
    /// After the item's last settlement.
    Finished {
        /// The outcome.
        outcome: ItemFinish,
        /// ⟨ADR-0007 §12.20 item 2⟩ Why, when a conflict caused a `not_applied` or
        /// `restored` outcome: the reason the run reported (the live path's, or the
        /// one the §5.7 row names when recovery decided the abort), so a restart
        /// reports the same one. Serde default, omitted when absent: a stored receipt
        /// without it decodes with `None` and re-encodes byte-identically.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<ConflictKind>,
    },
}

/// An item's recorded outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemFinish {
    /// Applied.
    Applied,
    /// Not applied; nothing of the item is active.
    NotApplied,
    /// Restored.
    Restored,
    /// Closed by `keep_held` with the files preserved.
    ConflictPreserved,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::projection::{ConsentRecord, Sha256Hex};

    fn round_trip<T>(value: &T, golden: &str)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_string(value).unwrap(), golden);
        let back: T = serde_json::from_str(golden).unwrap();
        assert_eq!(&back, value);
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            golden,
            "re-encodes byte-identically"
        );
    }

    fn unix(ino: u64, birth: Option<i128>) -> FileIdentity {
        FileIdentity::Unix { dev: 7, ino, birth }
    }

    const ID_B: &str = r#"{"platform":"unix","dev":7,"ino":2,"birth":"5"}"#;
    const ID_N: &str = r#"{"platform":"unix","dev":7,"ino":3}"#;

    fn receipt(local: LocalReceipt) -> StageReceipt {
        let adapter = AdapterIdentity {
            mechanism: "config_projection".into(),
            instance: "env_04040404040404040404040404040404".into(),
        };
        let effect = if local.effect_is_confirmed() {
            EffectReceipt::Confirmed {
                adapter,
                credential_ref: "projection/ssh/4".into(),
            }
        } else {
            EffectReceipt::Attempted {
                adapter,
                effect_token: "eff_fixture".into(),
            }
        };
        StageReceipt {
            stage: local.stage().into(),
            recorded_at: "2026-11-01T00:00:00Z".parse().unwrap(),
            effect,
            local: Some(local),
        }
    }

    #[test]
    fn local_receipt_wire_forms() {
        let digest = Sha256Hex::of(b"fixture");
        let file = |phase: FilePhase| LocalReceipt::File { step: 1, phase };
        // One golden per FilePhase variant (inside the `file` scope).
        let file_cases: Vec<(FilePhase, String)> = vec![
            (
                FilePhase::Staged {
                    identity: unix(2, Some(5)),
                },
                format!(r#"{{"kind":"staged","identity":{ID_B}}}"#),
            ),
            (
                FilePhase::Validated {
                    base: Some(unix(3, None)),
                },
                format!(r#"{{"kind":"validated","base":{ID_N}}}"#),
            ),
            (
                FilePhase::Validated { base: None },
                r#"{"kind":"validated","base":null}"#.to_owned(),
            ),
            (FilePhase::Exchanged, r#"{"kind":"exchanged"}"#.to_owned()),
            (
                FilePhase::PostValidated {
                    verdict: PostVerdict::Valid,
                    observed: None,
                },
                r#"{"kind":"post_validated","verdict":"valid","observed":null}"#.to_owned(),
            ),
            (
                FilePhase::PostValidated {
                    verdict: PostVerdict::Mismatch,
                    observed: Some(unix(3, None)),
                },
                format!(r#"{{"kind":"post_validated","verdict":"mismatch","observed":{ID_N}}}"#),
            ),
            (
                FilePhase::RestoreStarted {
                    cause: RestoreCause::FileMismatch,
                },
                r#"{"kind":"restore_started","cause":"file_mismatch"}"#.to_owned(),
            ),
            (
                FilePhase::RestoreStarted {
                    cause: RestoreCause::TransactionCheck,
                },
                r#"{"kind":"restore_started","cause":"transaction_check"}"#.to_owned(),
            ),
            (FilePhase::Restored, r#"{"kind":"restored"}"#.to_owned()),
            (
                FilePhase::Held {
                    reason: HoldReason::ContradictoryReceipts,
                    observed: vec![
                        ObservedName {
                            name: ObservedNameRole::Path,
                            entry: ObservedEntry::Recorded {
                                which: RecordedRole::S,
                                content: ContentState::Modified,
                            },
                        },
                        ObservedName {
                            name: ObservedNameRole::Aside,
                            entry: ObservedEntry::Foreign {
                                identity: Some(unix(3, None)),
                            },
                        },
                        ObservedName {
                            name: ObservedNameRole::Slot,
                            entry: ObservedEntry::Absent,
                        },
                    ],
                },
                format!(
                    concat!(
                        r#"{{"kind":"held","reason":"contradictory_receipts","observed":["#,
                        r#"{{"name":"path","entry":{{"kind":"recorded","which":"s","content":"modified"}}}},"#,
                        r#"{{"name":"aside","entry":{{"kind":"foreign","identity":{}}}}},"#,
                        r#"{{"name":"slot","entry":{{"kind":"absent"}}}}]}}"#
                    ),
                    ID_N
                ),
            ),
            (
                FilePhase::Held {
                    reason: HoldReason::Unobservable,
                    observed: vec![ObservedName {
                        name: ObservedNameRole::Path,
                        entry: ObservedEntry::Unobservable,
                    }],
                },
                r#"{"kind":"held","reason":"unobservable","observed":[{"name":"path","entry":{"kind":"unobservable"}}]}"#
                    .to_owned(),
            ),
            (
                FilePhase::Settling {
                    source: SettleSource::Path,
                    name: "gitconfig.lock".into(),
                    expected: unix(2, Some(5)),
                    expected_sha256: digest.clone(),
                    slot: "git_lock-4-0123456789abcdef".into(),
                },
                format!(
                    r#"{{"kind":"settling","source":"path","name":"gitconfig.lock","expected":{ID_B},"expected_sha256":"{digest}","slot":"git_lock-4-0123456789abcdef"}}"#
                ),
            ),
            (
                FilePhase::Settled {
                    disposition: SettledDisposition::Quarantined,
                },
                r#"{"kind":"settled","disposition":"quarantined"}"#.to_owned(),
            ),
            (
                FilePhase::Settled {
                    disposition: SettledDisposition::NothingDisplaced,
                },
                r#"{"kind":"settled","disposition":"nothing_displaced"}"#.to_owned(),
            ),
            (
                FilePhase::SettleConflict {
                    found: SettleConflictFound::Modified,
                    kept: vec![PreservedEntry {
                        name: ".hm-quarantine/managed_ssh-4-0123456789abcdef".into(),
                        identity: Some(unix(3, None)),
                    }],
                },
                format!(
                    r#"{{"kind":"settle_conflict","found":"modified","kept":[{{"name":".hm-quarantine/managed_ssh-4-0123456789abcdef","identity":{ID_N}}}]}}"#
                ),
            ),
            (
                FilePhase::SettleConflict {
                    found: SettleConflictFound::Missing,
                    kept: Vec::new(),
                },
                r#"{"kind":"settle_conflict","found":"missing","kept":[]}"#.to_owned(),
            ),
        ];
        for (phase, golden) in &file_cases {
            round_trip(phase, golden);
            round_trip(
                &file(phase.clone()),
                &format!(r#"{{"scope":"file","step":1,"phase":{golden}}}"#),
            );
        }
        // One golden per ItemPhase variant (inside the `item` scope).
        let item_cases = [
            (
                ItemPhase::Committed { generation: 4 },
                r#"{"kind":"committed","generation":4}"#,
            ),
            (
                ItemPhase::RollingBack {
                    reason: ConflictKind::UserConfigChanged,
                },
                r#"{"kind":"rolling_back","reason":"user_config_changed"}"#,
            ),
            (
                ItemPhase::Finished {
                    outcome: ItemFinish::Applied,
                    reason: None,
                },
                r#"{"kind":"finished","outcome":"applied"}"#,
            ),
            (
                ItemPhase::Finished {
                    outcome: ItemFinish::ConflictPreserved,
                    reason: None,
                },
                r#"{"kind":"finished","outcome":"conflict_preserved"}"#,
            ),
            // ADR-0007 §12.20 item 2: the reason is optional, omitted when absent (the
            // goldens above are the stored form of a receipt without one).
            (
                ItemPhase::Finished {
                    outcome: ItemFinish::NotApplied,
                    reason: Some(ConflictKind::ConcurrentWriter),
                },
                r#"{"kind":"finished","outcome":"not_applied","reason":"concurrent_writer"}"#,
            ),
            (
                ItemPhase::Finished {
                    outcome: ItemFinish::NotApplied,
                    reason: Some(ConflictKind::VerifiedClientUnavailable),
                },
                r#"{"kind":"finished","outcome":"not_applied","reason":"verified_client_unavailable"}"#,
            ),
        ];
        for (phase, golden) in &item_cases {
            round_trip(phase, golden);
            round_trip(
                &LocalReceipt::Item {
                    item: ProjectionItem::Git,
                    phase: phase.clone(),
                },
                &format!(r#"{{"scope":"item","item":"git","phase":{golden}}}"#),
            );
        }
        // The m02-plan §5 item 17a example, as a whole receipt.
        round_trip(
            &receipt(file(FilePhase::Exchanged)),
            concat!(
                r#"{"stage":"setup.file","recorded_at":"2026-11-01T00:00:00Z","effect":{"kind":"attempted","#,
                r#""adapter":{"mechanism":"config_projection","instance":"env_04040404040404040404040404040404"},"#,
                r#""effect_token":"eff_fixture"},"local":{"scope":"file","step":1,"phase":{"kind":"exchanged"}}}"#
            ),
        );
        // Effect fixed by phase: Confirmed for item.committed and finished{applied}.
        for (local, confirmed) in [
            (
                LocalReceipt::Item {
                    item: ProjectionItem::Ssh,
                    phase: ItemPhase::Committed { generation: 4 },
                },
                true,
            ),
            (
                LocalReceipt::Item {
                    item: ProjectionItem::Ssh,
                    phase: ItemPhase::Finished {
                        outcome: ItemFinish::Applied,
                        reason: None,
                    },
                },
                true,
            ),
            (
                LocalReceipt::Item {
                    item: ProjectionItem::Ssh,
                    phase: ItemPhase::Finished {
                        outcome: ItemFinish::Restored,
                        reason: Some(ConflictKind::ManagedFileEdited),
                    },
                },
                false,
            ),
            (file(FilePhase::Restored), false),
        ] {
            assert_eq!(local.effect_is_confirmed(), confirmed, "{local:?}");
            assert_eq!(
                matches!(receipt(local).effect, EffectReceipt::Confirmed { .. }),
                confirmed
            );
        }

        // An M01 receipt has no `local`: it decodes to None and re-encodes exactly.
        for m01 in [
            r#"{"stage":"authenticate","recorded_at":"2026-10-01T00:00:00Z","effect":{"kind":"not_attempted"}}"#,
            r#"{"stage":"prepare","recorded_at":"2026-10-01T00:00:00.5Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake","instance":"i"},"credential_ref":"c"}}"#,
        ] {
            let r: StageReceipt = serde_json::from_str(m01).unwrap();
            assert_eq!(r.local, None);
            assert_eq!(serde_json::to_string(&r).unwrap(), m01);
        }

        // Unknown content fails to decode: an unknown phase or scope, and the
        // withdrawn `restore_conflict` phase.
        for bad in [
            r#"{"scope":"file","step":1,"phase":{"kind":"restore_conflict","observed":null}}"#,
            r#"{"scope":"file","step":1,"phase":{"kind":"bogus"}}"#,
            r#"{"scope":"file","step":70000,"phase":{"kind":"exchanged"}}"#,
            r#"{"scope":"directory","step":1,"phase":{"kind":"exchanged"}}"#,
            r#"{"scope":"item","item":"ssh","phase":{"kind":"aborted"}}"#,
            r#"{"scope":"item","item":"svn","phase":{"kind":"committed","generation":1}}"#,
            r#"{"scope":"file","step":1,"phase":{"kind":"held","reason":"bogus","observed":[]}}"#,
            r#"{"scope":"file","step":1,"phase":{"kind":"settle_conflict","found":"stolen","kept":[]}}"#,
        ] {
            assert!(serde_json::from_str::<LocalReceipt>(bad).is_err(), "{bad}");
        }
        let with_bad_local = r#"{"stage":"setup.file","recorded_at":"2026-11-01T00:00:00Z","effect":{"kind":"not_attempted"},"local":{"scope":"file","step":1,"phase":{"kind":"restore_conflict"}}}"#;
        assert!(serde_json::from_str::<StageReceipt>(with_bad_local).is_err());
    }

    #[test]
    fn recovery_intent_local_is_additive_on_the_wire() {
        // An M01 intent decodes with `local: None` and re-encodes byte-identically.
        for m01 in [
            r#"{"request":{"kind":"ensure"},"resolved":null}"#,
            r#"{"request":{"x":[1,2]},"resolved":null}"#,
        ] {
            let i: RecoveryIntent = serde_json::from_str(m01).unwrap();
            assert_eq!(i.local, None);
            assert_eq!(serde_json::to_string(&i).unwrap(), m01);
        }
        let catalog = RecoveryIntent {
            request: serde_json::json!({"action": "remove_identity"}),
            resolved: None,
            local: Some(LocalIntent::Catalog(CatalogIntent {
                action: crate::catalog::CatalogAction::RemoveIdentity {
                    id: heimdall_contract::ids::IdentityId::from_random_bytes([3; 16]),
                },
                approval: None,
            })),
        };
        round_trip(
            &catalog,
            concat!(
                r#"{"request":{"action":"remove_identity"},"resolved":null,"local":{"kind":"catalog","#,
                r#""action":{"action":"remove_identity","id":"idn_03030303030303030303030303030303"}}}"#
            ),
        );
        let setup = LocalIntent::Setup(SetupIntent {
            plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([1; 32]),
            intent: heimdall_contract::setup::PreviewIntent::Apply { include_git: false },
            generation: 1,
            approval: None,
            consent: ConsentRecord::default(),
            files: Vec::new(),
        });
        let json = serde_json::to_string(&setup).unwrap();
        assert!(
            json.starts_with(r#"{"kind":"setup","plan_digest":"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<LocalIntent>(&json).unwrap(), setup);
        assert!(serde_json::from_str::<LocalIntent>(r#"{"kind":"probe"}"#).is_err());
    }

    /// E4: the serde form equals `as_str` for every kind, so store columns, events,
    /// `record_json` and the idempotency-key hash agree.
    #[test]
    fn operation_kind_serde_form_equals_as_str_for_every_kind() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in OperationKind::ALL {
            let wire = serde_json::to_string(&kind).unwrap();
            assert_eq!(wire, format!("\"{}\"", kind.as_str()));
            assert_eq!(serde_json::from_str::<OperationKind>(&wire).unwrap(), kind);
            assert!(
                seen.insert(kind.as_str()),
                "duplicate name {}",
                kind.as_str()
            );
        }
        assert_eq!(OperationKind::SetupApply.as_str(), "setup.apply");
        assert_eq!(OperationKind::SetupRollback.as_str(), "setup.rollback");
        assert_eq!(OperationKind::SetupRepair.as_str(), "setup.repair");
        assert_eq!(OperationKind::Catalog.as_str(), "catalog");
        assert_eq!(OperationKind::Probe.as_str(), "probe");
        assert!(serde_json::from_str::<OperationKind>("\"setup_apply\"").is_err());
        let setup: Vec<_> = OperationKind::ALL
            .into_iter()
            .filter(|k| k.is_setup())
            .collect();
        assert_eq!(setup, OperationKind::SETUP);
        assert_eq!(
            OperationKind::SetupRepair.m02_effect_class(),
            Some(EffectClass::LocalResources)
        );
        assert_eq!(
            OperationKind::Catalog.m02_effect_class(),
            Some(EffectClass::Local)
        );
        assert_eq!(OperationKind::Ensure.m02_effect_class(), None);
    }

    /// The domain half of `journaled_operation_kinds_match_their_request_kind`
    /// (m02-plan U0 tests; the contract half is in `tests/contracts/m02.rs`). Both
    /// read `tests/contracts/golden/journaled-kinds.golden.json`: every
    /// `OperationKind` is exactly one of journaled, declared-never-constructed or
    /// reserved, and its `as_str` and serde form are the golden's name. The
    /// declared-only kinds and `Probe` are never constructed outside this file: a
    /// source scan allows them only as match-pattern lines (`X` or `| X`, ending in
    /// `|` or `=>`).
    #[test]
    fn journaled_kinds_golden_matches_operation_kind_names() {
        use std::collections::BTreeMap;
        // The repository through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
        let root = heimdall_testkit::repo::repo_root();
        let text = std::fs::read_to_string(
            root.join("tests/contracts/golden/journaled-kinds.golden.json"),
        )
        .expect("journaled-kinds golden present");
        let golden: serde_json::Value = serde_json::from_str(&text).unwrap();
        let map = |k: &str| -> BTreeMap<String, String> {
            serde_json::from_value(golden[k].clone()).unwrap()
        };
        let journaled = map("journaled");
        let never = map("declared_never_constructed");
        let reserved = map("reserved");
        assert_eq!(
            journaled.len() + never.len() + reserved.len(),
            OperationKind::ALL.len(),
            "every OperationKind is classified exactly once"
        );
        for kind in OperationKind::ALL {
            let variant = format!("{kind:?}");
            let classes: Vec<&String> = [&journaled, &never, &reserved]
                .into_iter()
                .filter_map(|m| m.get(&variant))
                .collect();
            assert_eq!(classes.len(), 1, "{variant} classified once");
            assert_eq!(kind.as_str(), classes[0], "{variant}: as_str");
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", classes[0]),
                "{variant}: serde"
            );
        }
        assert_eq!(reserved.get("Probe").map(String::as_str), Some("probe"));

        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
            panic!("workspace crates directory not found");
        };
        for c in crates.flatten() {
            walk(&c.path().join("src"), &mut files);
        }
        assert!(!files.is_empty());
        let names: Vec<String> = never
            .keys()
            .chain(reserved.keys())
            .map(|v| format!("OperationKind::{v}"))
            .collect();
        let mut offenders = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "crates/domain/src/operation.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                let t = line.trim();
                for name in &names {
                    let Some(at) = t.find(name.as_str()) else {
                        continue;
                    };
                    let rest = t[at + name.len()..].trim();
                    let head = t[..at].trim();
                    let pattern = (head.is_empty() || head == "|")
                        && (rest.is_empty() || rest.starts_with('|') || rest.starts_with("=>"));
                    if !pattern {
                        offenders.push(format!("{rel}:{}: {t}", n + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "declared-only or reserved kinds constructed: {offenders:?}"
        );
    }
}
