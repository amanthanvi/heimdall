//! Durable operations (spec §4.1 "Operation", §11.4).

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_contract::{Code, OperationState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::idempotency::IdempotencyKey;

/// Operation kinds; the string form is the idempotency namespace
/// (`heimdall_contract::request::Request::kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// `ensure`.
    Ensure,
    /// `bind`.
    Bind,
    /// `delegate`.
    Delegate,
    /// `cancel`.
    Cancel,
    /// `release`.
    Release,
    /// `revoke`.
    Revoke,
    /// Owner policy action.
    Policy,
    /// Explicit active probe (`inspect --probe-level`).
    Probe,
}

impl OperationKind {
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
}

/// Durable, redacted recovery intent for an operation (review F05 fix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryIntent {
    /// The original request as submitted, minus secrets (the `Request` JSON with
    /// no credential material; requests never carry secrets by contract).
    pub request: serde_json::Value,
    /// Resolved intent once the pipeline reached `ResolveMechanism`.
    pub resolved: Option<ResolvedIntent>,
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
    /// Stage name (`heimdall_app::ensure::EnsureStage::as_str`).
    pub stage: String,
    /// When recorded.
    pub recorded_at: Timestamp,
    /// Effect status of the stage.
    pub effect: EffectReceipt,
}
