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
    /// ⟨M03; ADR-0008 §17.25 item 15⟩ Stable `snake_case` sub-reason refining the
    /// code (the values are in [`m03_warning::REASONS`], with the code each refines).
    /// Readers tolerate unknown values. Additive: omitted when absent, so every
    /// earlier warning is byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    use crate::code::Code;

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

    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: No CA is registered.
    pub const ISSUER_NOT_INITIALIZED: &str = "issuer_not_initialized";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The issuer child is unavailable.
    pub const ISSUER_UNAVAILABLE: &str = "issuer_unavailable";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The issuer's platform store is locked (`issuer unlock`).
    pub const ISSUER_STORE_LOCKED: &str = "issuer_store_locked";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The issuer's platform store is unavailable.
    pub const ISSUER_STORE_UNAVAILABLE: &str = "issuer_store_unavailable";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A CA's retirement stops at `unloaded`: this
    /// installation recorded no store locator for its key item, so nothing is deleted
    /// (ADR-0008 §17.21 item 3, §17.17 item 3).
    pub const ISSUER_STORE_LOCATOR_UNRECORDED: &str = "issuer_store_locator_unrecorded";
    /// ⟨M03; ADR-0008 §17.28 item 6⟩ `CAPABILITY_UNAVAILABLE` (exit 4): the store is
    /// unlocked, but its access list denied this executable a read of the CA key (on
    /// macOS `errSecAuthFailed` from an unlocked keychain: an ad-hoc-signed build's
    /// identity changes with every update). Next: `heimdall issuer restore --backup
    /// <file>` (the log-intact restore). Never reported as `issuer_store_locked`.
    pub const ISSUER_STORE_ACCESS_DENIED: &str = "issuer_store_access_denied";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The pair has no `verified` enrollment.
    pub const PAIR_NOT_ENROLLED: &str = "pair_not_enrolled";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The pair is not in the catalog.
    pub const PAIR_NOT_ADOPTED: &str = "pair_not_adopted";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The enrollment has not passed verification.
    pub const ENROLLMENT_UNVERIFIED: &str = "enrollment_unverified";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A managed-only request while the managed projection is not applied.
    pub const PROJECTION_PENDING: &str = "projection_pending";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: An observed (user-defined) alias cannot be enrolled.
    pub const OBSERVED_ALIAS_UNMANAGED: &str = "observed_alias_unmanaged";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The destination's route is not direct (M03 has no proxy routes).
    pub const ROUTE_UNSUPPORTED: &str = "route_unsupported";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The registry path breaks the ADR-0008 D5 §6.1 rule.
    pub const REGISTRY_UNSUPPORTED: &str = "registry_unsupported";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The destination or account cannot form a principal.
    pub const PRINCIPAL_CHARSET: &str = "principal_charset";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: No single approved host key could be determined.
    pub const HOST_TRUST_UNDETERMINED: &str = "host_trust_undetermined";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The positive verification was refused.
    pub const VERIFICATION_FAILED: &str = "verification_failed";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The negative verification was accepted.
    pub const PRINCIPALS_NOT_ENFORCED: &str = "principals_not_enforced";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The verification could not classify the result.
    pub const VERIFICATION_INCONCLUSIVE: &str = "verification_inconclusive";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A request needs verified lock continuity.
    pub const LOCK_CONTINUITY_UNVERIFIED: &str = "lock_continuity_unverified";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The grant's lock behaviour revokes on lock.
    pub const LOCK_REVOKES_CHOSEN: &str = "lock_revokes_chosen";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: No session-lock source is available.
    pub const LOCK_SIGNAL_UNAVAILABLE: &str = "lock_signal_unavailable";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: Owned masters are not supported here (Windows).
    pub const MULTIPLEXING_UNSUPPORTED: &str = "multiplexing_unsupported";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The endpoint would list more than its identity bound.
    pub const TOO_MANY_IDENTITIES: &str = "too_many_identities";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The grant's key was lost; re-issue is pending.
    pub const CREDENTIAL_REISSUE_PENDING: &str = "credential_reissue_pending";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: Cancel after the remote mutation's `Attempted` receipt.
    pub const REMOTE_STEP_IN_PROGRESS: &str = "remote_step_in_progress";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The re-evaluated route differs from the approved target.
    pub const ROUTE_CHANGED: &str = "route_changed";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The route could not be evaluated statically.
    pub const ROUTE_UNDETERMINED: &str = "route_undetermined";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The existing access cannot enroll in M03 (password only).
    pub const EXISTING_ACCESS_KIND_UNSUPPORTED: &str = "existing_access_kind_unsupported";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: `connect`: no profile of the environment covers the destination.
    pub const NO_PROFILE_COVERS_DESTINATION: &str = "no_profile_covers_destination";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The slot's mux path exceeds the socket-path limit.
    pub const MUX_PATH_TOO_LONG: &str = "mux_path_too_long";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The CA is retiring; no new reservation.
    pub const CA_RETIRING: &str = "ca_retiring";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: Foreign removal from a redacted bundle.
    pub const BUNDLE_REDACTED: &str = "bundle_redacted";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A purge that keeps enrollments needs a fresh bundle.
    pub const BUNDLE_REQUIRED: &str = "bundle_required";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The client's effective configuration does not show every host-trust pin.
    pub const HOST_TRUST_UNPINNABLE: &str = "host_trust_unpinnable";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The existing-access endpoint cannot be resolved.
    pub const EXISTING_ACCESS_ENDPOINT_UNRECORDED: &str = "existing_access_endpoint_unrecorded";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The existing-access endpoint is a Heimdall endpoint.
    pub const EXISTING_ACCESS_ENDPOINT_IS_HEIMDALL: &str = "existing_access_endpoint_is_heimdall";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The existing-access endpoint changed since approval.
    pub const EXISTING_ACCESS_CHANGED: &str = "existing_access_changed";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The bundle's host and port differ from the alias's evaluated ones.
    pub const BUNDLE_HOST_MISMATCH: &str = "bundle_host_mismatch";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A held foreign removal names another descriptor
    /// than the request's (ADR-0008 §17.22 item 1).
    pub const DESCRIPTOR_MISMATCH: &str = "descriptor_mismatch";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The registry directory's parent is absent.
    pub const REGISTRY_PARENT_ABSENT: &str = "registry_parent_absent";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The target cannot report a process start identity.
    pub const START_IDENTITY_UNAVAILABLE: &str = "start_identity_unavailable";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: The remote shell has no process group of its own.
    pub const NO_PROCESS_GROUP: &str = "no_process_group";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A refusal a destination clock skew could explain (with `verification_inconclusive`).
    pub const DESTINATION_CLOCK_SKEW: &str = "destination_clock_skew";
    /// ⟨M03⟩ `CAPABILITY_UNAVAILABLE`: A foreign system-form absence check: this device holds no key of the CA.
    pub const CA_NOT_HELD: &str = "ca_not_held";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: The pair already has a live enrollment under that CA.
    pub const ALREADY_ENROLLED: &str = "already_enrolled";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: The registry changed during removal three times.
    pub const REGISTRY_CHANGED: &str = "registry_changed";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: The registry cannot be rewritten safely; manual instructions.
    pub const REGISTRY_NOT_REWRITABLE: &str = "registry_not_rewritable";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: The registry exceeds `registry_max_bytes`.
    pub const REGISTRY_TOO_LARGE: &str = "registry_too_large";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: Our marker line differs, or appears more than once.
    pub const REGISTRY_LINE_DAMAGED: &str = "registry_line_damaged";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: Another binding holds the pair's slot.
    pub const MANAGED_SLOT_HELD: &str = "managed_slot_held";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: Another step holds the registry lock.
    pub const REGISTRY_BUSY: &str = "registry_busy";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: An argument would move an owned connection out of its process.
    pub const OWNED_CONNECTION_OPTION_CONFLICT: &str = "owned_connection_option_conflict";
    /// ⟨M03⟩ `CONFIG_CONFLICT`: A stale lock's holder could not be proven gone.
    pub const LOCK_HOLDER_UNRESOLVED: &str = "lock_holder_unresolved";
    /// ⟨M03⟩ `USAGE_ERROR`: An enrollment account that differs from the catalog's.
    pub const ACCOUNT_OVERRIDE_REFUSED: &str = "account_override_refused";
    /// ⟨M03⟩ `USAGE_ERROR`: An invalid `--registry-path` (D5 §6.1; U5P-Q3, ruled by ADR-0008
    /// §17.20 item 13 and registered by wave 5).
    pub const REGISTRY_PATH_INVALID: &str = "registry_path_invalid";
    /// ⟨M03⟩ `LAUNCH_FAILED`: Windows: the contained `ssh.exe` could not be registered.
    pub const CONNECTION_REGISTRATION_FAILED: &str = "connection_registration_failed";
    /// ⟨M03⟩ `LAUNCH_FAILED`: Windows: the grant ended or is unsafe; the child never resumed.
    pub const CONNECTION_REGISTRATION_REFUSED: &str = "connection_registration_refused";
    /// ⟨M03⟩ `REQUEST_CONFLICT`: A step result for another step token.
    pub const STEP_TOKEN_MISMATCH: &str = "step_token_mismatch";
    /// ⟨M03⟩ `REQUEST_CONFLICT`: A step is already outstanding for the operation.
    pub const STEP_OUTSTANDING: &str = "step_outstanding";
    /// ⟨M03⟩ `OUTCOME_UNKNOWN`: An append's result was lost.
    pub const REGISTRY_OUTCOME_UNKNOWN: &str = "registry_outcome_unknown";
    /// ⟨M03⟩ `OUTCOME_UNKNOWN`: A removal's result was lost.
    pub const REMOVE_OUTCOME_UNKNOWN: &str = "remove_outcome_unknown";
    /// ⟨M03⟩ `DECISION_STALE`: The enrollment approval's 24 h validity lapsed.
    pub const APPROVAL_LAPSED: &str = "approval_lapsed";
    /// ⟨M03⟩ `HOST_TRUST_CHANGED`: The host key differs from the approved one.
    pub const ENROLLMENT_HOST_KEY_MISMATCH: &str = "enrollment_host_key_mismatch";
    /// ⟨M03⟩ `SERVICE_UNAVAILABLE`: The issuer child is restarting.
    pub const ISSUER_RESTARTING: &str = "issuer_restarting";
    /// ⟨M03; ADR-0008 §17.28 item 5⟩ `SERVICE_UNAVAILABLE` (exit 5, retryable): the
    /// running executable no longer matches the identity a new store item's access list
    /// would trust (its file was replaced, an update or a rebuild), so nothing was
    /// written. Next: finish installing or updating Heimdall, then run the command again.
    pub const ISSUER_EXECUTABLE_CHANGED: &str = "issuer_executable_changed";
    /// ⟨M03⟩ `BACKPRESSURE`: The issuer's signature rate limit was reached.
    pub const ISSUER_RATE_LIMITED: &str = "issuer_rate_limited";
    /// ⟨M03⟩ `CREDENTIAL_EXPIRED`: Use after a lock revocation.
    pub const GRANT_ENDED_SESSION_LOCKED: &str = "grant_ended_session_locked";
    /// ⟨M03; ADR-0008 §17.27 item 2⟩ `SERVICE_UNAVAILABLE`: an uninstall holds the
    /// fence, so new enrollment, CA and issuance work is not admitted.
    pub const UNINSTALL_IN_PROGRESS: &str = "uninstall_in_progress";
    /// ⟨M03; ADR-0008 §17.27 item 2⟩ `CAPABILITY_UNAVAILABLE` (exit 4): the
    /// outstanding-obligation inventory read under the fence differs from the one the
    /// owner confirmed; nothing was deleted (next: `heimdall uninstall` again).
    pub const UNINSTALL_INVENTORY_CHANGED: &str = "uninstall_inventory_changed";
    /// ⟨M03; ADR-0008 §17.28 item 1⟩ `CAPABILITY_UNAVAILABLE` (exit 4): under the
    /// fence, an enrollment operation still has a dispatched step without its result
    /// (its remote effect is unknown), so the purge is refused; nothing was deleted.
    pub const UNINSTALL_REMOTE_STEP_UNRESOLVED: &str = "uninstall_remote_step_unresolved";

    /// ⟨M03⟩ Every new stable sub-reason of m03-plan §5 item 14, with the code it is
    /// used with, in the table's order. `driver_unavailable` (M02, in [`ALL`]) is
    /// used by M03 too and is not repeated. [`ALL`] stays M01/M02's list; the code
    /// table itself is unchanged (no new code).
    pub const M03: &[(&str, Code)] = &[
        (ISSUER_NOT_INITIALIZED, Code::CapabilityUnavailable),
        (ISSUER_UNAVAILABLE, Code::CapabilityUnavailable),
        (ISSUER_STORE_LOCKED, Code::CapabilityUnavailable),
        (ISSUER_STORE_UNAVAILABLE, Code::CapabilityUnavailable),
        (ISSUER_STORE_LOCATOR_UNRECORDED, Code::CapabilityUnavailable),
        (ISSUER_STORE_ACCESS_DENIED, Code::CapabilityUnavailable),
        (PAIR_NOT_ENROLLED, Code::CapabilityUnavailable),
        (PAIR_NOT_ADOPTED, Code::CapabilityUnavailable),
        (ENROLLMENT_UNVERIFIED, Code::CapabilityUnavailable),
        (PROJECTION_PENDING, Code::CapabilityUnavailable),
        (OBSERVED_ALIAS_UNMANAGED, Code::CapabilityUnavailable),
        (ROUTE_UNSUPPORTED, Code::CapabilityUnavailable),
        (REGISTRY_UNSUPPORTED, Code::CapabilityUnavailable),
        (PRINCIPAL_CHARSET, Code::CapabilityUnavailable),
        (HOST_TRUST_UNDETERMINED, Code::CapabilityUnavailable),
        (VERIFICATION_FAILED, Code::CapabilityUnavailable),
        (PRINCIPALS_NOT_ENFORCED, Code::CapabilityUnavailable),
        (VERIFICATION_INCONCLUSIVE, Code::CapabilityUnavailable),
        (LOCK_CONTINUITY_UNVERIFIED, Code::CapabilityUnavailable),
        (LOCK_REVOKES_CHOSEN, Code::CapabilityUnavailable),
        (LOCK_SIGNAL_UNAVAILABLE, Code::CapabilityUnavailable),
        (MULTIPLEXING_UNSUPPORTED, Code::CapabilityUnavailable),
        (TOO_MANY_IDENTITIES, Code::CapabilityUnavailable),
        (CREDENTIAL_REISSUE_PENDING, Code::CapabilityUnavailable),
        (REMOTE_STEP_IN_PROGRESS, Code::CapabilityUnavailable),
        (ROUTE_CHANGED, Code::CapabilityUnavailable),
        (ROUTE_UNDETERMINED, Code::CapabilityUnavailable),
        (
            EXISTING_ACCESS_KIND_UNSUPPORTED,
            Code::CapabilityUnavailable,
        ),
        (NO_PROFILE_COVERS_DESTINATION, Code::CapabilityUnavailable),
        (MUX_PATH_TOO_LONG, Code::CapabilityUnavailable),
        (CA_RETIRING, Code::CapabilityUnavailable),
        (BUNDLE_REDACTED, Code::CapabilityUnavailable),
        (BUNDLE_REQUIRED, Code::CapabilityUnavailable),
        (HOST_TRUST_UNPINNABLE, Code::CapabilityUnavailable),
        (
            EXISTING_ACCESS_ENDPOINT_UNRECORDED,
            Code::CapabilityUnavailable,
        ),
        (
            EXISTING_ACCESS_ENDPOINT_IS_HEIMDALL,
            Code::CapabilityUnavailable,
        ),
        (EXISTING_ACCESS_CHANGED, Code::CapabilityUnavailable),
        (BUNDLE_HOST_MISMATCH, Code::CapabilityUnavailable),
        (DESCRIPTOR_MISMATCH, Code::CapabilityUnavailable),
        (REGISTRY_PARENT_ABSENT, Code::CapabilityUnavailable),
        (START_IDENTITY_UNAVAILABLE, Code::CapabilityUnavailable),
        (NO_PROCESS_GROUP, Code::CapabilityUnavailable),
        (DESTINATION_CLOCK_SKEW, Code::CapabilityUnavailable),
        (CA_NOT_HELD, Code::CapabilityUnavailable),
        (ALREADY_ENROLLED, Code::ConfigConflict),
        (REGISTRY_CHANGED, Code::ConfigConflict),
        (REGISTRY_NOT_REWRITABLE, Code::ConfigConflict),
        (REGISTRY_TOO_LARGE, Code::ConfigConflict),
        (REGISTRY_LINE_DAMAGED, Code::ConfigConflict),
        (MANAGED_SLOT_HELD, Code::ConfigConflict),
        (REGISTRY_BUSY, Code::ConfigConflict),
        (OWNED_CONNECTION_OPTION_CONFLICT, Code::ConfigConflict),
        (LOCK_HOLDER_UNRESOLVED, Code::ConfigConflict),
        (ACCOUNT_OVERRIDE_REFUSED, Code::UsageError),
        (REGISTRY_PATH_INVALID, Code::UsageError),
        (CONNECTION_REGISTRATION_FAILED, Code::LaunchFailed),
        (CONNECTION_REGISTRATION_REFUSED, Code::LaunchFailed),
        (STEP_TOKEN_MISMATCH, Code::RequestConflict),
        (STEP_OUTSTANDING, Code::RequestConflict),
        (REGISTRY_OUTCOME_UNKNOWN, Code::OutcomeUnknown),
        (REMOVE_OUTCOME_UNKNOWN, Code::OutcomeUnknown),
        (APPROVAL_LAPSED, Code::DecisionStale),
        (ENROLLMENT_HOST_KEY_MISMATCH, Code::HostTrustChanged),
        (ISSUER_RESTARTING, Code::ServiceUnavailable),
        (ISSUER_EXECUTABLE_CHANGED, Code::ServiceUnavailable),
        (ISSUER_RATE_LIMITED, Code::Backpressure),
        (GRANT_ENDED_SESSION_LOCKED, Code::CredentialExpired),
        (UNINSTALL_IN_PROGRESS, Code::ServiceUnavailable),
        (UNINSTALL_INVENTORY_CHANGED, Code::CapabilityUnavailable),
        (
            UNINSTALL_REMOTE_STEP_UNRESOLVED,
            Code::CapabilityUnavailable,
        ),
    ];
}

/// ⟨M03⟩ Warning codes M03 adds (m03-plan §5 item 14: warnings, not error reasons).
pub mod m03_warning {
    /// The pair resolved to its existing mechanism while the managed projection is
    /// pending (`next: setup_apply`; F04).
    pub const MANAGED_PROJECTION_PENDING: &str = "managed_projection_pending";
    /// Linux `revoke_on_lock` is unverified until B11 (F19).
    pub const SIGNAL_UNVERIFIED: &str = "signal_unverified";
    /// Ordinary `ssh <alias>` needs a held slot.
    pub const ORDINARY_SSH_NEEDS_HELD_SLOT: &str = "ordinary_ssh_needs_held_slot";
    /// An uncertain append may still land.
    pub const POSSIBLE_LATE_WRITE: &str = "possible_late_write";
    /// Every M03 warning code.
    pub const ALL: &[&str] = &[
        MANAGED_PROJECTION_PENDING,
        SIGNAL_UNVERIFIED,
        ORDINARY_SSH_NEEDS_HELD_SLOT,
        POSSIBLE_LATE_WRITE,
    ];

    /// ⟨ADR-0008 §17.25 item 15⟩ `Warning.reason` on `TIME_UNCERTAIN` when the cause
    /// is no time reference for this boot: managed issuance waits for one attended
    /// `heimdall time confirm`. The TUI keys on this reason, not on the code.
    pub const TIME_CONFIRMATION_AFTER_REBOOT: &str = "time_confirmation_after_reboot";

    /// ⟨ADR-0008 §17.25 item 15⟩ Every `Warning.reason` value, with the warning code
    /// (`Warning.code`) it refines. The reason is a refinement, never a new code.
    pub const REASONS: &[(&str, &str)] = &[(TIME_CONFIRMATION_AFTER_REBOOT, "TIME_UNCERTAIN")];
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
