//! The common machine envelope (spec §11.2; ADR-0006 §3).

use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::ids::{BindingId, OperationId};
use crate::state::OperationState;
use crate::version::SchemaVersion;

/// Every ordinary structured result. `T` is the per-primitive `data` payload; errors
/// use [`ErrorData`]. Field order is the spec example's order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(transform = require_warnings_and_next)]
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
    /// Non-fatal findings. Always emitted (listed in the schema's `required`); a
    /// lenient reader still accepts omission as empty.
    #[serde(default)]
    pub warnings: Vec<Warning>,
    /// Machine next action, or `null` when nothing is expected of the caller.
    /// Always emitted, `null` when absent (required-nullable in the schema:
    /// `NextAction | null`).
    #[serde(default)]
    pub next: Option<NextAction>,
}

/// Schema transform (design-fix second round R1): `warnings` and `next` are always
/// emitted, so they are `required` in the generated envelope schemas while `next`
/// keeps its `null` alternative. `#[schemars(required)]` would instead drop the
/// null alternative (schemars 1.x reads it as "must be `Some`").
fn require_warnings_and_next(schema: &mut schemars::Schema) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    let required = obj
        .entry("required")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if let serde_json::Value::Array(list) = required {
        for field in ["warnings", "next"] {
            if !list.iter().any(|v| v == field) {
                list.push(serde_json::Value::String(field.to_owned()));
            }
        }
    }
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
    /// The provider-owned interaction, with action `interact`, for
    /// `PROVIDER_LOCKED` and provider-owned `INTERACTION_REQUIRED` (ADR-0007 §7).
    /// Never combined with `decision_ref`: provider dialogs are not Heimdall
    /// decisions (spec §5.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_interaction: Option<crate::provider::ProviderInteractionRef>,
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

    /// Whether the action respects spec §5.5: a provider interaction is never
    /// combined with a Heimdall decision reference.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !(self.provider_interaction.is_some() && self.decision_ref.is_some())
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
    /// `environment`, `endpoint`, `config`, `store`, `clock`, `decision`, and
    /// since M02 `projection`, `identity`, `provider`, `executable`).
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
    /// Stable `snake_case` sub-reason refining the code (m02-plan §5 item 14; the
    /// values are in [`reason`]). Readers tolerate unknown values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// ⟨M02⟩ ADR-0007 §12.24 item 4: the configuration entries the refusal concerns,
    /// each as its file's display path and 1-based line (a pre-launch fallback
    /// refusal names the refused `IdentityFile` entries). Display paths and line
    /// numbers only, never file content. Additive: omitted when empty, and a reader
    /// that predates it reads an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<crate::doctor::ConfigProvenance>,
}

/// The `data` payload of an error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ErrorData {
    /// The error.
    pub error: ErrorDetail,
    /// A setup operation's partial result: a held operation's envelope
    /// (`OUTCOME_UNKNOWN`, reason `projection_held`) lists every item and held
    /// step here (m02-plan §5 item 2). Boxed so the common error stays small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<Box<crate::setup::SetupResult>>,
}

/// Stable values of [`ErrorDetail::reason`] (m02-plan §5 item 14). The conflict
/// kinds ([`crate::setup::ConflictKind`]) and the manual reasons
/// ([`crate::setup::manual_reason`]) are reasons too, with the same spelling.
pub mod reason {
    /// Launch: the program was not found.
    pub const NOT_FOUND: &str = "not_found";
    /// Launch: the program would resolve from the current directory.
    pub const CURRENT_DIRECTORY: &str = "current_directory";
    /// Launch: a batch script path with a refused character (Q-B).
    pub const REFUSED_BATCH_PATH: &str = "refused_batch_path";
    /// Launch: an argument std refuses to escape (named by index only).
    pub const REFUSED_ARGUMENT: &str = "refused_argument";
    /// Launch: found but not executable (exit 126).
    pub const NOT_EXECUTABLE: &str = "not_executable";
    /// Launch: exec or spawn returned an error.
    pub const EXEC_ERROR: &str = "exec_error";
    /// Launch: the resolved path is not valid Unicode.
    pub const REFUSED_PATH: &str = "refused_path";
    /// Launch: the side-channel `launching` record could not be written.
    pub const META_UNAVAILABLE: &str = "meta_unavailable";
    /// Provider: the agent endpoint is absent.
    pub const ENDPOINT_ABSENT: &str = "endpoint_absent";
    /// Provider: the identity is not listed by its agent.
    pub const IDENTITY_NOT_LISTED: &str = "identity_not_listed";
    /// Provider: the provider owns an interaction.
    pub const PROVIDER_INTERACTION: &str = "provider_interaction";
    /// Provider: the identity's interaction is unknown.
    pub const INTERACTION_UNKNOWN: &str = "interaction_unknown";
    /// One grant's pairs name identities of different mechanisms (P6).
    pub const MIXED_MECHANISMS: &str = "mixed_mechanisms";
    /// A real-tree probe level without `--allow-config-commands`.
    pub const CONFIG_COMMANDS_NOT_AUTHORIZED: &str = "config_commands_not_authorized";
    /// A `core.sshCommand` value is present.
    pub const GIT_SSH_COMMAND_PRESENT: &str = "git_ssh_command_present";
    /// The request's driver is not in this build or runtime (wave-0 landing; a
    /// runtime without a projection writer).
    pub const DRIVER_UNAVAILABLE: &str = "driver_unavailable";
    /// An uncleared fallback identity may prompt (ADR-0007 §7, M2-R05).
    pub const FALLBACK_IDENTITY_INTERACTION: &str = "fallback_identity_interaction";
    /// The static pass could not fully read the configuration tree.
    pub const CONFIG_NOT_FULLY_READABLE: &str = "config_not_fully_readable";
    /// A Git configuration file is unreadable.
    pub const GIT_CONFIG_UNREADABLE: &str = "git_config_unreadable";
    /// Another setup operation of this environment is open or unresolved.
    pub const SETUP_IN_PROGRESS: &str = "setup_in_progress";
    /// A setup operation is held for the owner (with `OUTCOME_UNKNOWN`).
    pub const PROJECTION_HELD: &str = "projection_held";
    /// A plan exceeds the setup intent's content bounds.
    pub const PROJECTION_TOO_LARGE: &str = "projection_too_large";
    /// ⟨ADR-0007 §12.32 item 5⟩ A preview's full diff exceeds
    /// [`MAX_DIFF_BYTES`](crate::setup::MAX_DIFF_BYTES) (`CAPABILITY_UNAVAILABLE`,
    /// effect `none`). The plan is refused before anything is journaled; no client is
    /// ever sent a truncated diff.
    pub const PLAN_TOO_LARGE: &str = "plan_too_large";
    /// ⟨ADR-0007 §12.17 item 11⟩ The Git item is not applicable: Git's default SSH is
    /// not its bundled MSYS client (ADR-0007 §5.6), so the Git include would change
    /// nothing Heimdall can verify.
    pub const GIT_DEFAULT_NOT_BUNDLED_MSYS: &str = "git_default_not_bundled_msys";
    /// ⟨ADR-0007 §12.17 item 11⟩ A check needs a verified client that is not
    /// available (no verified Git client, or local queries disabled).
    pub const VERIFIED_CLIENT_UNAVAILABLE: &str = "verified_client_unavailable";
    /// ⟨ADR-0007 §12.25 item 4⟩ Launch: the binding already has a live holder that is
    /// not this process (`REQUEST_CONFLICT`, `next: new_request_id`); nothing was
    /// launched and the existing holder is kept.
    pub const BINDING_IN_USE: &str = "binding_in_use";
    /// ⟨ADR-0007 §12.26 item 3(a)⟩ Launch: the binding was released (its holder exited)
    /// before this launch (`CREDENTIAL_EXPIRED`, `next: new_work`, resource `binding`).
    pub const BINDING_RELEASED: &str = "binding_released";

    /// The reasons defined here, in documentation order. Together with the conflict
    /// kinds and the manual reasons they are every reason this build writes.
    pub const ALL: &[&str] = &[
        NOT_FOUND,
        CURRENT_DIRECTORY,
        REFUSED_BATCH_PATH,
        REFUSED_ARGUMENT,
        NOT_EXECUTABLE,
        EXEC_ERROR,
        REFUSED_PATH,
        META_UNAVAILABLE,
        ENDPOINT_ABSENT,
        IDENTITY_NOT_LISTED,
        PROVIDER_INTERACTION,
        INTERACTION_UNKNOWN,
        MIXED_MECHANISMS,
        CONFIG_COMMANDS_NOT_AUTHORIZED,
        GIT_SSH_COMMAND_PRESENT,
        DRIVER_UNAVAILABLE,
        FALLBACK_IDENTITY_INTERACTION,
        CONFIG_NOT_FULLY_READABLE,
        GIT_CONFIG_UNREADABLE,
        SETUP_IN_PROGRESS,
        PROJECTION_HELD,
        PROJECTION_TOO_LARGE,
        PLAN_TOO_LARGE,
        GIT_DEFAULT_NOT_BUNDLED_MSYS,
        VERIFIED_CLIENT_UNAVAILABLE,
        BINDING_IN_USE,
        BINDING_RELEASED,
    ];
}

impl Envelope<ErrorData> {
    /// Build a failed envelope from an error detail.
    #[must_use]
    pub fn failed(operation_id: Option<OperationId>, error: ErrorDetail) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            operation_id,
            state: OperationState::Failed,
            code: error.code.clone(),
            data: ErrorData { error, setup: None },
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

    /// ADR-0007 §12.24 item 4: `entries` is additive. A detail without it reads as
    /// empty, an empty list is not emitted, and a filled one round-trips.
    #[test]
    fn error_entries_are_additive() {
        let old = r#"{"code":"INTERACTION_REQUIRED","effect_status":"none","retryable":false,
            "next":{"action":"interact"},"message":"m","reason":"fallback_identity_interaction"}"#;
        let mut detail: ErrorDetail = serde_json::from_str(old).unwrap();
        assert!(detail.entries.is_empty());
        let v = serde_json::to_value(&detail).unwrap();
        assert!(v.get("entries").is_none(), "{v}");
        detail.entries = vec![crate::doctor::ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line: 7,
        }];
        let v = serde_json::to_value(&detail).unwrap();
        assert_eq!(
            v["entries"],
            serde_json::json!([{ "path_display": "~/.ssh/config", "line": 7 }])
        );
        let back: ErrorDetail = serde_json::from_value(v).unwrap();
        assert_eq!(back, detail);
    }
}
