//! The common machine envelope (spec §11.2; ADR-0006 §3).

use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::ids::{BindingId, OperationId};
use crate::state::OperationState;
use crate::version::SchemaVersion;

/// Every ordinary structured result. `T` is the per-primitive `data` payload; errors
/// use [`ErrorData`]. Field order is the spec example's order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Envelope<T> {
    /// Major schema version of this document.
    pub schema_version: SchemaVersion,
    /// Present for effectful or long-running work; absent for pure reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Operation state; synchronous reads report `succeeded` or `failed`.
    pub state: OperationState,
    /// Stable semantic code.
    pub code: Code,
    /// Per-primitive payload; never contains private keys or reusable secrets.
    pub data: T,
    /// Non-fatal findings.
    #[serde(default)]
    pub warnings: Vec<Warning>,
    /// Machine next action, or `null` when nothing is expected of the caller.
    #[serde(default)]
    pub next: Option<NextAction>,
}

impl<T> Envelope<T> {
    /// A synchronous successful read (`state = succeeded`, `code = OK`).
    #[must_use]
    pub fn ok(data: T) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            operation_id: None,
            state: OperationState::Succeeded,
            code: Code::Ok,
            data,
            warnings: Vec::new(),
            next: None,
        }
    }

    /// Map the payload type while keeping every other field.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Envelope<U> {
        Envelope {
            schema_version: self.schema_version,
            operation_id: self.operation_id,
            state: self.state,
            code: self.code,
            data: f(self.data),
            warnings: self.warnings,
            next: self.next,
        }
    }
}

/// A non-fatal finding attached to a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Warning {
    /// Stable warning code (SCREAMING_SNAKE_CASE, not localized).
    pub code: String,
    /// Human text; may change without breaking callers.
    pub message: String,
}

/// Machine next action (spec §11.2 `next`, §11.6 "machine-readable next action").
/// `action` names are stable; parameters are present only when relevant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NextAction {
    /// Stable action name; defaults come from [`Code::default_next_action`].
    pub action: String,
    /// Operation to observe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Binding to use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<BindingId>,
    /// Nonsecret reference to a pending owner decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_ref: Option<String>,
    /// Suggested minimum delay before a retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Cursor to resume from after a resync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<crate::event::Cursor>,
}

impl NextAction {
    /// The default next action for a code, with no parameters.
    #[must_use]
    pub fn for_code(code: Code) -> Self {
        Self {
            action: code.default_next_action().to_owned(),
            ..Self::default()
        }
    }
}

/// Whether an operation's external effect happened (spec §11.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    /// Nothing external was changed.
    None,
    /// The effect was applied and verified.
    Applied,
    /// Some steps applied; the result says which.
    Partial,
    /// The effect may or may not have applied; reconcile before retrying.
    Unknown,
}

/// A reference to the resource an error concerns. Opaque IDs only; never a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResourceRef {
    /// Resource kind (`operation`, `binding`, `grant`, `policy`, `destination`,
    /// `environment`, `endpoint`, `config`, `store`, `clock`).
    pub kind: String,
    /// Opaque identifier, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Error detail (`data.error`, primitives-draft §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ErrorDetail {
    /// Same code as the envelope.
    pub code: Code,
    /// Whether any external effect happened.
    pub effect_status: EffectStatus,
    /// Whether an unchanged retry may succeed later.
    pub retryable: bool,
    /// Resource the error concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
    /// Machine next action.
    pub next: NextAction,
    /// Human text; may change without breaking callers; never contains secrets.
    pub message: String,
}

/// The `data` payload of an error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ErrorData {
    /// The error.
    pub error: ErrorDetail,
}

impl Envelope<ErrorData> {
    /// Build a failed envelope from an error detail.
    #[must_use]
    pub fn failed(operation_id: Option<OperationId>, error: ErrorDetail) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            operation_id,
            state: OperationState::Failed,
            code: error.code,
            data: ErrorData { error },
            warnings: Vec::new(),
            next: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_noncritical_fields_are_tolerated() {
        let json = r#"{"schema_version":"1","state":"succeeded","code":"OK","data":{"x":1},
            "warnings":[],"next":null,"future_field":{"a":[1,2,3]}}"#;
        let env: Envelope<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(env.code, Code::Ok);
        assert!(env.next.is_none());
    }

    #[test]
    fn omitted_and_null_differ_for_next() {
        let omitted: Envelope<serde_json::Value> = serde_json::from_str(
            r#"{"schema_version":"1","state":"succeeded","code":"OK","data":{}}"#,
        )
        .unwrap();
        assert!(omitted.next.is_none());
        let serialized = serde_json::to_value(&omitted).unwrap();
        // The emitted form always materializes `next`, so machine readers see the
        // explicit null rather than an omission (ADR-0006 §9).
        assert!(serialized.get("next").is_some());
    }
}
