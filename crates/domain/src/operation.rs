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
