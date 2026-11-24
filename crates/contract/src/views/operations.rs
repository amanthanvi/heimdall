//! ⟨rev7⟩ The operation view (`operation show`, `operation wait`) and `inspect operations`
//! (ADR-0013 §11 D1, D9).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::PreviewView;
use crate::Timestamp;
use crate::code::Code;
use crate::envelope::EffectStatus;
use crate::ids::OperationId;
use crate::state::OperationState;

/// One durable operation as `observe` (`operation show`, `operation wait`) and `inspect
/// operations` show it. Its envelope carries the same `operation_id` and `state`, and
/// `next: {action: "observe"}` while the state is not quiescent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationView {
    /// The operation.
    pub operation_id: OperationId,
    /// Its kind.
    pub kind: OperationKindView,
    /// Its state.
    pub state: OperationState,
    /// Its result code once terminal. Omitted before (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// Its effect status.
    pub effect_status: EffectStatus,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// Its cancellation. Omitted when none was requested (today: `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation: Option<CancellationView>,
    /// Its result payload (redacted JSON) once terminal: an `ensure`, `bind` or `delegate`
    /// result as a current response shows it. Omitted before it is terminal, and where
    /// `observe` withholds it: a succeeded binding result that does not read as one, of a
    /// binding outside the runtime's own environment (today: `null` in both cases). `state`
    /// says whether the operation is terminal, so a terminal operation with no `result`
    /// reads as withheld (ruled 2026-11-24, PC3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// An operation's kind, with the dotted names of the setup and enrollment kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OperationKindView {
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
    /// An owner policy action.
    Policy,
    /// An explicit active probe.
    Probe,
    /// ⟨M02⟩ `setup.apply`.
    #[serde(rename = "setup.apply")]
    SetupApply,
    /// ⟨M02⟩ `setup.rollback`.
    #[serde(rename = "setup.rollback")]
    SetupRollback,
    /// ⟨M02⟩ `setup.repair`.
    #[serde(rename = "setup.repair")]
    SetupRepair,
    /// ⟨M02⟩ `catalog`.
    Catalog,
    /// ⟨M03⟩ `enrollment.apply`.
    #[serde(rename = "enrollment.apply")]
    EnrollmentApply,
    /// ⟨M03⟩ `enrollment.verify`.
    #[serde(rename = "enrollment.verify")]
    EnrollmentVerify,
    /// ⟨M03⟩ `enrollment.remove`.
    #[serde(rename = "enrollment.remove")]
    EnrollmentRemove,
}

/// A requested cancellation (spec §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CancellationView {
    /// When it was requested.
    pub requested_at: Timestamp,
    /// Whether an irreversible or uncertain external step may have happened.
    pub may_have_external_effect: bool,
}

/// `inspect operations` data: the open and unresolved operations the caller may see, and
/// the store's count of every operation by state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationListView {
    /// The open operations, then the unresolved (`outcome_unknown`) ones.
    pub operations: Vec<OperationView>,
    /// Every stored operation counted by state (subject metadata, kept: D1). Only states
    /// with at least one operation appear, ordered by state name. Not filtered by the
    /// caller's visibility.
    pub counts: Vec<OperationCountView>,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// The number of stored operations in one state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationCountView {
    /// The state.
    pub state: OperationState,
    /// How many operations are in it.
    pub count: u64,
}
