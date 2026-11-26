//! The common machine envelope (spec §11.2; ADR-0006 §3).

use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::ids::{BindingId, OperationId, RequestId};
use crate::lifecycle::RestoreEpoch;
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
    /// ⟨rev7; M08 U2b-2; U0-Q5⟩ The request ID a mutating answer's request carried. With
    /// `request_epoch` it is the pair a caller keeps to retry the request (`--request-id`
    /// with `--request-epoch`). Omitted on reads, and on a mutating request that carries no
    /// request ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// ⟨rev7; M08 U2b-2; ADR-0014 H13; U0-Q5⟩ The restore epoch a mutating answer's request
    /// was bound to: the one its frame carried, or the current one at receipt. Present on
    /// every mutating answer of a runtime that checks the epoch, beside `request_id`; omitted
    /// on reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_epoch: Option<RestoreEpoch>,
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
            request_id: None,
            request_epoch: None,
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
            request_id: self.request_id,
            request_epoch: self.request_epoch,
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
    /// ⟨M05⟩ Revision 5 (m05-plan §4 item 9): with reason `mixed_mechanisms`, the
    /// mechanism groups to re-request under one work ID (ADR-0011 §5.3). Omitted when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<MechanismGroup>,
}

/// ⟨M05⟩ One mechanism group of a mixed profile (`next.groups`; ADR-0011 §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MechanismGroup {
    /// The mechanism (`managed_certificate`, `native_agent`, ...).
    pub mechanism: String,
    /// Its pairs.
    pub pairs: Vec<crate::request::AccessPairRef>,
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
    /// ⟨rev7⟩ A `USAGE_ERROR` / `item_too_large` refusal's [`ItemTooLarge`] detail (ADR-0013
    /// §6.4, D20; m07-plan U3, PC11): the field over its bound (`pairs`, `routes`, `relays`,
    /// `label`, the whole `item`). The item itself, when it has an ID, is `resource`.
    /// Additive: set only on that refusal, omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// ⟨rev7⟩ The [`ItemTooLarge`] bound `field` is over, counted in `unit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<u64>,
    /// ⟨rev7⟩ Whether `bound` counts bytes or entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<BoundUnit>,
}

impl ErrorDetail {
    /// ⟨rev7⟩ The typed [`ItemTooLarge`] detail of an `item_too_large` refusal, when the
    /// detail carries one (its `field`, `bound` and `unit`, with [`Self::resource`]).
    #[must_use]
    pub fn item_too_large(&self) -> Option<ItemTooLarge> {
        Some(ItemTooLarge {
            field: self.field.clone()?,
            bound: self.bound?,
            unit: self.unit?,
            resource: self.resource.clone(),
        })
    }
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

/// ⟨rev7⟩ The typed detail of a `USAGE_ERROR` / `response_too_large` refusal (ADR-0013 §4,
/// D19). **Standalone, not attached:** `ErrorDetail` gains these fields in the change that
/// emits them (U3, PC4), with the CLI and the wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResponseTooLarge {
    /// The frame or budget limit the answer would exceed, in bytes.
    pub limit_bytes: u64,
    /// The section that is over its cap (a snapshot's `operations`, `pending_decisions`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// The narrowing to use (`filter.operation_id`, `filter.types`, `select`, `page`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrow: Option<String>,
    /// A legacy over-limit item met by a page or a point `inspect`, by ID, with its
    /// remediation through the existing catalog command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
}

/// ⟨rev7⟩ The typed detail of a `USAGE_ERROR` / `item_too_large` refusal (ADR-0013 §6.4,
/// D20). **Attached** (U3, PC11): [`ErrorDetail`] carries `field`, `bound` and `unit`, and its
/// `resource` is the item ([`ErrorDetail::item_too_large`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ItemTooLarge {
    /// The field over its bound (`pairs`, `routes`, `relays`, `label`, the whole `item`).
    pub field: String,
    /// The bound: bytes for a byte bound, entries for a count bound.
    pub bound: u64,
    /// Whether the bound counts bytes or entries.
    pub unit: BoundUnit,
    /// The item, by kind and ID, when it has one yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
}

/// ⟨rev7⟩ What an [`ItemTooLarge`] bound counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BoundUnit {
    /// Serialized bytes.
    Bytes,
    /// List entries.
    Entries,
}

/// ⟨rev7⟩ The most live-access entries a `destination_has_live_access` refusal lists
/// (ADR-0013 D13).
pub const LIVE_ACCESS_LISTED_MAX: usize = 32;

/// ⟨rev7⟩ The typed detail of a `CONFIG_CONFLICT` / `destination_has_live_access` refusal
/// (ADR-0013 D13). **Standalone, not attached** (U3 with U8b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveAccessRefusal {
    /// Up to [`LIVE_ACCESS_LISTED_MAX`] live or unresolved entries.
    pub live: Vec<LiveAccessEntry>,
    /// How many there are in all.
    pub total: u64,
}

/// ⟨rev7⟩ One live or unresolved entry of a [`LiveAccessRefusal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiveAccessEntry {
    /// The grant, binding or operation, by kind and opaque ID.
    pub resource: ResourceRef,
    /// The work it belongs to, when it has an actual work reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_id: Option<crate::ids::WorkId>,
    /// `heimdall access stop --work <work_id>`, only for an entry with a work reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
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
    /// ⟨M03; ADR-0008 §17.31 items 1 and 6⟩ `SERVICE_UNAVAILABLE` (exit 5, retryable): the
    /// runtime's stop before a purge was not confirmed (the shutdown failed or its
    /// connection was lost), so the purge read and deleted nothing (next: stop the runtime
    /// with `heimdall service stop` or wait for it to stop, then `heimdall uninstall` again).
    pub const UNINSTALL_SHUTDOWN_UNCONFIRMED: &str = "uninstall_shutdown_unconfirmed";
    /// ⟨M03; ADR-0008 §17.33 items 1 and 9⟩ `SERVICE_UNAVAILABLE` (exit 5, retryable): an
    /// uninstall's fence release has waited past its bound for work the uninstall
    /// started, so the fence stays releasing and fenced work is refused until that work
    /// ends or the runtime restarts (next: stop the runtime with `heimdall service
    /// stop`, then start it again with `heimdall service run --detach`).
    pub const UNINSTALL_FENCE_RELEASE_STUCK: &str = "uninstall_fence_release_stuck";
    /// ⟨M03; ADR-0008 §17.35 item 7 (audit D1, D2)⟩ `SERVICE_UNAVAILABLE` (exit 5): the
    /// runtime did not start (it opened no state store) because `<state>` holds an
    /// interrupted uninstall's quarantine (a `.hm-purge-*` entry) or a `-wal`, `-shm` or
    /// `-journal` without its database: opening the store would create a new database
    /// and discard commits that exist only in that log. The message names the exact
    /// paths. Next: `heimdall uninstall`, which restores the quarantined database family
    /// (or reports what it cannot restore).
    pub const UNINSTALL_QUARANTINE_PRESENT: &str = "uninstall_quarantine_present";
    /// ⟨M03; ADR-0008 §17.29 item 2⟩ `CONFIG_CONFLICT` (exit 6): an attended
    /// `enroll verify <enrollment> --absence` run after the `late_write` residual's
    /// not-after observed the enrollment's marker line present: the uncertain append
    /// landed and trust of ours remains, whatever the record's state says. The residual
    /// is kept. Next: `heimdall enroll remove <enrollment>`.
    pub const LATE_WRITE_PRESENT: &str = "late_write_present";

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
        (UNINSTALL_SHUTDOWN_UNCONFIRMED, Code::ServiceUnavailable),
        (UNINSTALL_FENCE_RELEASE_STUCK, Code::ServiceUnavailable),
        (UNINSTALL_QUARANTINE_PRESENT, Code::ServiceUnavailable),
        (LATE_WRITE_PRESENT, Code::ConfigConflict),
    ];

    // --- ⟨M03⟩ revision 5 (the M03 exit suite, wave 6 question I-8(2)) -----------------

    /// ⟨M03; revision 5⟩ `CAPABILITY_UNAVAILABLE` (exit 4, not retryable): the issuer child
    /// was running and **refused** to sign the entry (an independent predicate or
    /// ceiling failed: `ceiling_exceeded`, `subject_mismatch`, `entry_stale`, …; the
    /// refusal's name is in the message). Distinct from [`ISSUER_UNAVAILABLE`] (not
    /// running, locked, restarting, no answer); a rate limit stays
    /// [`ISSUER_RATE_LIMITED`].
    pub const ISSUER_REFUSED: &str = "issuer_refused";

    /// ⟨M03⟩ The M03 reasons revision 5 adds, kept separate from [`M03`] (its golden is
    /// M03's record): `golden/rev5-reasons.golden.json` key `m03`.
    pub const M03_REV5: &[(&str, Code)] = &[(ISSUER_REFUSED, Code::CapabilityUnavailable)];

    // --- ⟨M04⟩ revision 5 (m04-plan §5 item 8; ADR-0010) ---------------------------

    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: WSL is not installed or not usable.
    pub const WSL_UNAVAILABLE: &str = "wsl_unavailable";
    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: the distribution's Windows interop is disabled.
    pub const WSL_INTEROP_DISABLED: &str = "wsl_interop_disabled";
    /// ⟨M04⟩ `NOT_FOUND`: no registered distribution has this GUID.
    pub const WSL_DISTRIBUTION_UNKNOWN: &str = "wsl_distribution_unknown";
    /// ⟨M04⟩ `SERVICE_UNAVAILABLE` (retryable): the distribution is not running and
    /// background repair never starts it (ADR-0010 §3 items 9–10).
    pub const WSL_DISTRIBUTION_NOT_RUNNING: &str = "wsl_distribution_not_running";
    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: no Linux-visible helper path resolves.
    pub const WSL_HELPER_UNAVAILABLE: &str = "wsl_helper_unavailable";
    /// ⟨M04⟩ `CONFIG_CONFLICT`: a container environment already has a distinct active
    /// binding (ADR-0010 §4 item 3).
    pub const ENVIRONMENT_BUSY: &str = "environment_busy";
    /// ⟨M04⟩ `NOT_FOUND`: the target environment was removed (or its distribution
    /// unregistered); a removed identity is never a target again (ADR-0010 §9 item 1).
    pub const ENVIRONMENT_REMOVED: &str = "environment_removed";
    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: a jump destination has a route of its own.
    pub const ROUTE_CHAIN_UNSUPPORTED: &str = "route_chain_unsupported";
    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: the jump hop's access is neither a managed pair in
    /// the same grant's scope nor existing access (ADR-0010 §5 item 2).
    pub const ROUTE_DEPENDENCY_OUT_OF_SCOPE: &str = "route_dependency_out_of_scope";
    /// ⟨M04⟩ `CAPABILITY_UNAVAILABLE`: Git's effective SSH client is Git for Windows'
    /// bundled MSYS `ssh`, which cannot reach named pipes (ADR-0010 §1 item 5; also a
    /// doctor finding).
    pub const GIT_CLIENT_CANNOT_REACH_PIPE: &str = "git_client_cannot_reach_pipe";
    /// ⟨M04⟩ `STATE_UNAVAILABLE`: the Windows state directory is not protected
    /// owner-only; refused, never repaired (ADR-0010 §1 item 7).
    pub const STATE_DIR_UNSAFE: &str = "state_dir_unsafe";
    /// ⟨M04⟩ `CONFIG_CONFLICT`: a login entry of Heimdall's name exists with other data.
    pub const LOGIN_ENTRY_CONFLICT: &str = "login_entry_conflict";

    /// ⟨M04⟩ Revision 5's M04 reasons with their codes, kept separate from [`ALL`] and
    /// [`M03`] (the code table is unchanged).
    pub const M04: &[(&str, Code)] = &[
        (WSL_UNAVAILABLE, Code::CapabilityUnavailable),
        (WSL_INTEROP_DISABLED, Code::CapabilityUnavailable),
        (WSL_DISTRIBUTION_UNKNOWN, Code::NotFound),
        (WSL_DISTRIBUTION_NOT_RUNNING, Code::ServiceUnavailable),
        (WSL_HELPER_UNAVAILABLE, Code::CapabilityUnavailable),
        (ENVIRONMENT_BUSY, Code::ConfigConflict),
        (ENVIRONMENT_REMOVED, Code::NotFound),
        (ROUTE_CHAIN_UNSUPPORTED, Code::CapabilityUnavailable),
        (ROUTE_DEPENDENCY_OUT_OF_SCOPE, Code::CapabilityUnavailable),
        (GIT_CLIENT_CANNOT_REACH_PIPE, Code::CapabilityUnavailable),
        (STATE_DIR_UNSAFE, Code::StateUnavailable),
        (LOGIN_ENTRY_CONFLICT, Code::ConfigConflict),
    ];

    // --- ⟨M05⟩ revision 5 (m05-plan §4 item 9; ADR-0011) ---------------------------

    /// ⟨M05⟩ `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED`, with a decision
    /// reference: the workspace is not trusted and its request exceeds personal policy.
    pub const WORKSPACE_UNTRUSTED: &str = "workspace_untrusted";
    /// ⟨M05⟩ `APPROVAL_REQUIRED` or `INTERACTION_REQUIRED`, with a `ReconcileWorkspace`
    /// decision reference: a move or re-clone of a trusted checkout.
    pub const WORKSPACE_AMBIGUOUS: &str = "workspace_ambiguous";
    /// ⟨M05⟩ `CAPABILITY_UNAVAILABLE`: the filesystem has no stable file identity, so
    /// trust is refused there (ADR-0011 R6).
    pub const WORKSPACE_IDENTITY_UNAVAILABLE: &str = "workspace_identity_unavailable";
    /// ⟨M05⟩ `USAGE_ERROR`: the manifest breaks its closed schema or bounds.
    pub const MANIFEST_INVALID: &str = "manifest_invalid";
    /// ⟨M05⟩ `USAGE_ERROR`: the manifest uses authority vocabulary (any depth).
    pub const MANIFEST_AUTHORITY_KEY: &str = "manifest_authority_key";
    /// ⟨M05⟩ `NOT_FOUND`: the manifest names a profile the local catalog does not have.
    pub const MANIFEST_PROFILE_UNKNOWN: &str = "manifest_profile_unknown";
    /// ⟨M05⟩ `NOT_FOUND`: a policy target matches no policy.
    pub const POLICY_TARGET_EMPTY: &str = "policy_target_empty";
    /// ⟨M05⟩ `APPROVAL_REQUIRED` or `INTERACTION_REQUIRED`, with `retry_after` and the
    /// denied decision's reference, and no new decision (ADR-0011 §4.3).
    pub const DECISION_COOLDOWN: &str = "decision_cooldown";
    /// ⟨M05⟩ `INTERACTION_REQUIRED`, with no decision reference: a `covered_only`
    /// request found nothing covered (ADR-0011 §3.2; the shell hook never prompts).
    pub const NOT_COVERED: &str = "not_covered";
    /// ⟨M05⟩ `CREDENTIAL_EXPIRED`: the work ID was stopped and never reactivates.
    pub const WORK_STOPPED: &str = "work_stopped";

    /// ⟨M05⟩ Revision 5's M05 reasons with their codes (a reason used with either of two
    /// codes, by session attendance, appears once per code), kept separate from [`ALL`],
    /// [`M03`] and [`M04`] (the code table is unchanged).
    pub const M05: &[(&str, Code)] = &[
        (WORKSPACE_UNTRUSTED, Code::ApprovalRequired),
        (WORKSPACE_UNTRUSTED, Code::InteractionRequired),
        (WORKSPACE_AMBIGUOUS, Code::ApprovalRequired),
        (WORKSPACE_AMBIGUOUS, Code::InteractionRequired),
        (WORKSPACE_IDENTITY_UNAVAILABLE, Code::CapabilityUnavailable),
        (MANIFEST_INVALID, Code::UsageError),
        (MANIFEST_AUTHORITY_KEY, Code::UsageError),
        (MANIFEST_PROFILE_UNKNOWN, Code::NotFound),
        (POLICY_TARGET_EMPTY, Code::NotFound),
        (DECISION_COOLDOWN, Code::ApprovalRequired),
        (DECISION_COOLDOWN, Code::InteractionRequired),
        (NOT_COVERED, Code::InteractionRequired),
        (WORK_STOPPED, Code::CredentialExpired),
    ];

    // --- ⟨M06⟩ revision 6 (ADR-0012 §9 item 7; ADR-0006 §18) ----------------------------
    // Every one is `CAPABILITY_UNAVAILABLE` (exit 4, not retryable). The existing
    // [`ROUTE_DEPENDENCY_OUT_OF_SCOPE`] (M04) is reused, not repeated.

    /// ⟨M06⟩ The caller's role lacks the permission or capability (ADR-0012 §3.8, §6.2).
    pub const ROLE_INSUFFICIENT: &str = "role_insufficient";
    /// ⟨M06⟩ The client was revoked; its sessions and subscriptions are closed (§3.7).
    pub const CLIENT_REVOKED: &str = "client_revoked";
    /// ⟨M06⟩ The invitation is not live: time uncertain, its boot anchor lost, or its wall
    /// deadline or elapsed bound passed (§3.9 item 4).
    pub const INVITATION_EXPIRED: &str = "invitation_expired";
    /// ⟨M06⟩ The invitation was already consumed (§3.9 items 5, 7).
    pub const INVITATION_CONSUMED: &str = "invitation_consumed";
    /// ⟨M06⟩ A pending client's session sent something other than the activation probe or
    /// `join`, refused before dispatch (§3.9 item 3).
    pub const INVITATION_PENDING: &str = "invitation_pending";
    /// ⟨M06⟩ A decision does not match the action and canonical parameters it was bound to
    /// (§3.10 item 2).
    pub const DECISION_BINDING_MISMATCH: &str = "decision_binding_mismatch";
    /// ⟨M06⟩ A limited role on a runner whose effective sshd policy is not verified (§3.2).
    pub const MANAGEMENT_SSHD_UNVERIFIED: &str = "management_sshd_unverified";
    /// ⟨M06⟩ A confirming activation probe disagrees with the verified sshd policy (§3.2).
    pub const MANAGEMENT_SSHD_UNSUPPORTED: &str = "management_sshd_unsupported";
    /// ⟨M06⟩ K_mgmt's store is locked: management connections are unavailable (§3.4).
    pub const MGMT_KEY_STORE_LOCKED: &str = "mgmt_key_store_locked";
    /// ⟨M06, rev6.2⟩ No verified persistent store holds (or can hold) K_mgmt on this device:
    /// absent, unsupported (desktop controllers only), corrupt, or its access list does not
    /// trust this executable. Unlocking cannot help (contrast [`MGMT_KEY_STORE_LOCKED`]);
    /// management connections are unavailable and the runners' work continues (§3.4).
    pub const MGMT_KEY_STORE_UNAVAILABLE: &str = "mgmt_key_store_unavailable";
    /// ⟨M06⟩ No verified platform store for K_iroh: no persistent Iroh endpoint (§2.4).
    pub const TRANSPORT_KEY_STORE_UNAVAILABLE: &str = "transport_key_store_unavailable";
    /// ⟨M06⟩ Runner work would depend on an inherited controller socket (§4.5).
    pub const CONTROLLER_DEPENDENCY: &str = "controller_dependency";
    /// ⟨M06⟩ A source of unknown provenance: no unattended readiness claim (§4.5).
    pub const DEPENDENCY_PROVENANCE_UNKNOWN: &str = "dependency_provenance_unknown";
    /// ⟨M06⟩ The certificate's issuer is not in the runner's `issuer_trust` (§4.2).
    pub const ISSUER_UNTRUSTED: &str = "issuer_untrusted";
    /// ⟨M06⟩ A changed host key, or an environment ID that does not match the pin: `held`
    /// (§7.5).
    pub const ENVIRONMENT_IDENTITY_MISMATCH: &str = "environment_identity_mismatch";
    /// ⟨M06⟩ An effective client setting defeats the catalog host pin (§5.2).
    pub const HOST_PIN_DEFEATED: &str = "host_pin_defeated";
    /// ⟨M06⟩ The route helper found zero or several bindings at its endpoint (§5.4).
    pub const ROUTE_BINDING_AMBIGUOUS: &str = "route_binding_ambiguous";
    /// ⟨M06⟩ A route, address or hint outside the approved routes (§2.1, §5.5).
    pub const ROUTE_UNAPPROVED: &str = "route_unapproved";
    /// ⟨M06⟩ A relay outside the effective exposure policy (§2.1).
    pub const RELAY_UNAPPROVED: &str = "relay_unapproved";
    /// ⟨M06⟩ Exposure not covered by a recorded consent (§2.1).
    pub const EXPOSURE_UNCONSENTED: &str = "exposure_unconsented";
    /// ⟨M06⟩ The transport is unavailable, or the endpoint cannot apply its policy (§2.1).
    pub const TRANSPORT_UNAVAILABLE: &str = "transport_unavailable";
    /// ⟨M06⟩ The transport refused the connection.
    pub const TRANSPORT_REFUSED: &str = "transport_refused";
    /// ⟨M06⟩ Admission authority cannot be read: the serve child is not started (§2.3
    /// item 5).
    pub const TRANSPORT_AUTHORITY_LOST: &str = "transport_authority_lost";
    /// ⟨M06⟩ The key is already authorized under another line (§3.5).
    pub const KEY_ALREADY_AUTHORIZED: &str = "key_already_authorized";
    /// ⟨M06, rev6.3⟩ A local-only form (`runner_local.*`, `controller_record.*`, `decide`)
    /// sent from a paired session (`INTERACTION_REQUIRED`): only the owner at this machine
    /// can do it, so retrying from the paired session can never succeed (ADR-0006 §18.7).
    pub const LOCAL_OWNER_REQUIRED: &str = "local_owner_required";
    /// ⟨M06, rev6.3⟩ Issuance is gated until the session has completed the authority report
    /// and resynchronization (ADR-0012 §7.4): the controller's barrier and the runner's
    /// per-session gate both answer it.
    pub const RESYNC_PENDING: &str = "resync_pending";
    /// ⟨M06, rev6.5⟩ `CAPABILITY_UNAVAILABLE`: this controller's management key agent could
    /// not start because its socket path would be longer than the platform allows (ADR-0006
    /// §18.9). A fault on this controller, not on the runner, that an unchanged retry
    /// cannot fix (a shorter runtime or temporary directory does).
    pub const MGMT_AGENT_PATH_TOO_LONG: &str = "mgmt_agent_path_too_long";
    /// ⟨M06, rev6.5⟩ `CAPABILITY_UNAVAILABLE`: the operating system denied this controller's
    /// management key agent its owner-only directory, socket or pipe (ADR-0006 §18.9); an
    /// unchanged retry cannot fix it (that directory's ownership or permissions can).
    pub const MGMT_AGENT_PERMISSION_DENIED: &str = "mgmt_agent_permission_denied";
    /// ⟨M06, rev6.5⟩ `STATE_UNAVAILABLE`: the name of this controller's management key
    /// agent was already taken under every fresh random name it tried; what is there is
    /// never reused or removed (ADR-0006 §18.9). Retryable.
    pub const MGMT_AGENT_ADDRESS_IN_USE: &str = "mgmt_agent_address_in_use";
    /// ⟨M06, rev6.5⟩ `STATE_UNAVAILABLE`: this controller's management key agent could not
    /// start for any other reason (ADR-0006 §18.9). Retryable.
    pub const MGMT_AGENT_UNAVAILABLE: &str = "mgmt_agent_unavailable";

    // ⟨M06, rev6.5; ADR-0006 §18.9 item 13⟩ Why an `ssh` the controller ran (the
    // bootstrap's host-key preflight, a management session) did not reach the runner, read
    // from what that `ssh` actually did. The two the client itself caused, which an
    // unchanged retry cannot fix, are `CAPABILITY_UNAVAILABLE`; the network outcomes stay
    // `DESTINATION_UNREACHABLE`. No message carries a path or an address.

    /// ⟨M06, rev6.5⟩ `CAPABILITY_UNAVAILABLE`: this controller's OpenSSH client did not start
    /// (it could not be spawned, or it ended with a status no OpenSSH client uses and said
    /// nothing).
    pub const SSH_CLIENT_NOT_STARTED: &str = "ssh_client_not_started";
    /// ⟨M06, rev6.5⟩ `CAPABILITY_UNAVAILABLE`: this controller's OpenSSH client refused its
    /// own options or configuration before connecting (a bad option, a configuration file
    /// it could not open, or one with a bad owner or permissions).
    pub const SSH_CLIENT_CONFIG_REJECTED: &str = "ssh_client_config_rejected";
    /// ⟨M06, rev6.5⟩ `DESTINATION_UNREACHABLE`: the runner's address refused the connection.
    pub const SSH_CONNECTION_REFUSED: &str = "ssh_connection_refused";
    /// ⟨M06, rev6.5⟩ `DESTINATION_UNREACHABLE`: the connection (or its banner exchange)
    /// timed out.
    pub const SSH_CONNECTION_TIMED_OUT: &str = "ssh_connection_timed_out";
    /// ⟨M06, rev6.5⟩ `DESTINATION_UNREACHABLE`: the runner's host name did not resolve.
    pub const SSH_NAME_NOT_RESOLVED: &str = "ssh_name_not_resolved";
    /// ⟨M06, rev6.5⟩ `DESTINATION_UNREACHABLE`: the runner was not reached for any other
    /// reason the client stated (or it stated none).
    pub const SSH_UNREACHABLE_OTHER: &str = "ssh_unreachable_other";

    /// ⟨M06, rev6.5⟩ The reasons of a management session that failed on this controller
    /// before anything reached the runner: its management key agent's, and its K_mgmt
    /// store's.
    pub const MGMT_CONTROLLER_SIDE: &[&str] = &[
        MGMT_AGENT_PATH_TOO_LONG,
        MGMT_AGENT_PERMISSION_DENIED,
        MGMT_AGENT_ADDRESS_IN_USE,
        MGMT_AGENT_UNAVAILABLE,
        MGMT_KEY_STORE_LOCKED,
        MGMT_KEY_STORE_UNAVAILABLE,
    ];

    /// ⟨M06⟩ Revision 6's reasons with their codes, kept separate from [`ALL`], [`M03`],
    /// [`M04`] and [`M05`] (the code table is unchanged): golden
    /// `rev6-reasons.golden.json` key `m06`.
    pub const M06: &[(&str, Code)] = &[
        (ROLE_INSUFFICIENT, Code::CapabilityUnavailable),
        (CLIENT_REVOKED, Code::CapabilityUnavailable),
        (INVITATION_EXPIRED, Code::CapabilityUnavailable),
        (INVITATION_CONSUMED, Code::CapabilityUnavailable),
        (INVITATION_PENDING, Code::CapabilityUnavailable),
        (DECISION_BINDING_MISMATCH, Code::CapabilityUnavailable),
        (MANAGEMENT_SSHD_UNVERIFIED, Code::CapabilityUnavailable),
        (MANAGEMENT_SSHD_UNSUPPORTED, Code::CapabilityUnavailable),
        (MGMT_KEY_STORE_LOCKED, Code::CapabilityUnavailable),
        (MGMT_KEY_STORE_UNAVAILABLE, Code::CapabilityUnavailable),
        (TRANSPORT_KEY_STORE_UNAVAILABLE, Code::CapabilityUnavailable),
        (CONTROLLER_DEPENDENCY, Code::CapabilityUnavailable),
        (DEPENDENCY_PROVENANCE_UNKNOWN, Code::CapabilityUnavailable),
        (ISSUER_UNTRUSTED, Code::CapabilityUnavailable),
        (ENVIRONMENT_IDENTITY_MISMATCH, Code::CapabilityUnavailable),
        (HOST_PIN_DEFEATED, Code::CapabilityUnavailable),
        (ROUTE_BINDING_AMBIGUOUS, Code::CapabilityUnavailable),
        (ROUTE_UNAPPROVED, Code::CapabilityUnavailable),
        (RELAY_UNAPPROVED, Code::CapabilityUnavailable),
        (EXPOSURE_UNCONSENTED, Code::CapabilityUnavailable),
        (TRANSPORT_UNAVAILABLE, Code::CapabilityUnavailable),
        (TRANSPORT_REFUSED, Code::CapabilityUnavailable),
        (TRANSPORT_AUTHORITY_LOST, Code::CapabilityUnavailable),
        (KEY_ALREADY_AUTHORIZED, Code::CapabilityUnavailable),
        (LOCAL_OWNER_REQUIRED, Code::InteractionRequired),
        (RESYNC_PENDING, Code::CapabilityUnavailable),
        (MGMT_AGENT_PATH_TOO_LONG, Code::CapabilityUnavailable),
        (MGMT_AGENT_PERMISSION_DENIED, Code::CapabilityUnavailable),
        (MGMT_AGENT_ADDRESS_IN_USE, Code::StateUnavailable),
        (MGMT_AGENT_UNAVAILABLE, Code::StateUnavailable),
        (SSH_CLIENT_NOT_STARTED, Code::CapabilityUnavailable),
        (SSH_CLIENT_CONFIG_REJECTED, Code::CapabilityUnavailable),
        (SSH_CONNECTION_REFUSED, Code::DestinationUnreachable),
        (SSH_CONNECTION_TIMED_OUT, Code::DestinationUnreachable),
        (SSH_NAME_NOT_RESOLVED, Code::DestinationUnreachable),
        (SSH_UNREACHABLE_OTHER, Code::DestinationUnreachable),
    ];

    /// ⟨M06⟩ A `remote_pending` reason, not an error reason: an Iroh revocation is
    /// reported pending until the serve child acknowledged suspending admission (or was
    /// stopped) (ADR-0012 §2.3 item 4).
    pub const IROH_ADMISSION_CLOSING: &str = "iroh_admission_closing";

    /// ⟨M06⟩ Every `remote_pending` reason (no code: a pending state, never an error).
    pub const M06_PENDING: &[&str] = &[IROH_ADMISSION_CLOSING];

    // --- ⟨rev7⟩ revision 7 (ADR-0013 D2, D6, D8, D12, D13, D19, D20, D21; ADR-0014 H4, H10,
    // H13, H14; the contract owner's rulings on U0-Q3, Q5, Q6, Q8 and D20) -----------------
    // **Declared, not emitted:** each joins an emitter in its own later change (U3, U2b).
    // `route_undetermined` (M03) and `controller_dependency` / `dependency_provenance_unknown`
    // (M06, the unattended launch refusal of U0-Q4) already exist and are not repeated.

    /// ⟨rev7⟩ `USAGE_ERROR`: a page token that is malformed, tampered with, or issued for
    /// another reader, environment, query or sort (ADR-0013 §6.2, D21).
    pub const PAGE_TOKEN_INVALID: &str = "page_token_invalid";
    /// ⟨rev7⟩ `USAGE_ERROR`: an empty selector, one over 64 entries, or `select` together
    /// with `page` (ADR-0013 §6.1, D21).
    pub const SELECTOR_INVALID: &str = "selector_invalid";
    /// ⟨rev7⟩ `USAGE_ERROR`: a response that would not fit one frame (ADR-0013 §4, D19). A read
    /// is refused before anything is sent (`effect_status: none`, next `narrow_request`); a
    /// reply after dispatch keeps its operation's true effect and reference (next `observe`).
    pub const RESPONSE_TOO_LARGE: &str = "response_too_large";
    /// ⟨rev7⟩ `USAGE_ERROR`: a catalog or import write whose item exceeds a revision-7 bound,
    /// a byte bound or a count bound (ADR-0013 §6.4, D20; the ruling on ASK-D20); the detail
    /// ([`super::ItemTooLarge`]) names the field and the bound. A store that already exceeds a
    /// bound is reported, never truncated.
    pub const ITEM_TOO_LARGE: &str = "item_too_large";
    /// ⟨rev7⟩ `RESYNC_REQUIRED` (page mode) and a `resync_required` event or subscribe
    /// `resync_reason`: retention removed events the reader had not received (ADR-0013 §5.4).
    pub const HISTORY_TRIMMED: &str = "history_trimmed";
    /// ⟨rev7⟩ `RESYNC_REQUIRED` (page mode), a `resync_required` event or `resync_reason`: an
    /// event that does not fit one frame (ADR-0013 §5.4, §5.6).
    pub const EVENT_TOO_LARGE: &str = "event_too_large";
    /// ⟨rev7⟩ `RESYNC_REQUIRED` (page mode) or `resync_reason`: a cursor beyond the head,
    /// malformed, of an unknown version, or another reader's or environment's (ADR-0013 §5.3).
    pub const CURSOR_INVALID: &str = "cursor_invalid";
    /// ⟨rev7⟩ `SERVICE_UNAVAILABLE`: no runtime is advertised (ADR-0013 §8, D12; H14).
    pub const RUNTIME_NOT_RUNNING: &str = "runtime_not_running";
    /// ⟨rev7⟩ `SERVICE_UNAVAILABLE`: an advertised runtime whose process is live with its
    /// recorded start time but whose endpoint does not answer (ADR-0014 H14).
    pub const RUNTIME_UNREACHABLE: &str = "runtime_unreachable";
    /// ⟨rev7⟩ `SERVICE_UNAVAILABLE`: the endpoint, its owner, its peer or the hello did not
    /// verify (ADR-0013 §8 "Discovery", D12).
    pub const ENDPOINT_UNTRUSTED: &str = "endpoint_untrusted";
    /// ⟨rev7⟩ `CONFIG_CONFLICT`: `destination remove` while access to the destination is live
    /// or unresolved (ADR-0013 D13; `data.error.live` lists up to 32 entries plus `total`).
    pub const DESTINATION_HAS_LIVE_ACCESS: &str = "destination_has_live_access";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: the mechanism cannot meet the request's minimum
    /// (U0-Q3: "ask for less").
    pub const MECHANISM_MINIMUM_UNMET: &str = "mechanism_minimum_unmet";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: the person denied the approval (U0-Q3: stop, do not
    /// ask again).
    pub const DECISION_DENIED: &str = "decision_denied";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: M06's confirming probe could not run here (a limited
    /// role's join, or a policy recheck; on Windows today). Named from its emission site,
    /// `heimdall_app::remote_env::probes_unavailable` (U0-Q3).
    pub const PROBES_UNAVAILABLE: &str = "probes_unavailable";
    /// ⟨rev7⟩ `DESTINATION_UNREACHABLE`: M06's confirming probe ran and could not decide
    /// (`heimdall_app::remote_env`, the join's and the recheck's inconclusive probe; ruled
    /// 2026-11-24).
    pub const PROBE_INCONCLUSIVE: &str = "probe_inconclusive";
    /// ⟨rev7⟩ `STATE_UNAVAILABLE`: the state store, or its generation pointer or record, is
    /// damaged (ADR-0014 H4, §3.6); unsafe operations stop and the choices are named.
    pub const STATE_CORRUPT: &str = "state_corrupt";
    /// ⟨rev7⟩ `STATE_UNAVAILABLE`: the state store is newer than this build (ADR-0014 H4).
    pub const STATE_NEWER_THAN_BUILD: &str = "state_newer_than_build";
    /// ⟨rev7⟩ `STATE_UNAVAILABLE`: the request ledger is damaged, so every append is refused
    /// until the attended `state repair` (U0-Q8).
    pub const LEDGER_DAMAGED: &str = "ledger_damaged";
    /// ⟨rev7⟩ `CREDENTIAL_EXPIRED`: the authority was ended by a restore (ADR-0014 H4, §3.6).
    pub const STATE_RESTORED_AUTHORITY_ENDED: &str = "state_restored_authority_ended";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: a management client quarantined by a restore, until
    /// reauthorized (ADR-0014 H10).
    pub const CLIENT_QUARANTINED_AFTER_RESTORE: &str = "client_quarantined_after_restore";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: an invitation voided by a restore (ADR-0014 H10).
    pub const INVITATION_VOID_AFTER_RESTORE: &str = "invitation_void_after_restore";
    /// ⟨rev7⟩ `CAPABILITY_UNAVAILABLE`: exposure or admission state disabled by a restore
    /// (ADR-0014 H10).
    pub const EXPOSURE_DISABLED_AFTER_RESTORE: &str = "exposure_disabled_after_restore";
    /// ⟨rev7⟩ `INTERACTION_REQUIRED` (next `interact`): a local widening (`route add`,
    /// `transport enable`, `transport adopt-roost`) asked for without an attended owner, which
    /// it needs (ADR-0006 §18.9 item 10, deferred there to revision 7; ruled 2026-11-24).
    pub const LOCAL_WIDENING_NEEDS_ATTENDED_OWNER: &str = "local_widening_needs_attended_owner";
    /// ⟨rev7⟩ `REQUEST_STALE`: a mutating request whose epoch is not the current one
    /// (ADR-0014 H13, §3.6 step 3; U0-Q5); and `DECISION_STALE` (`fix_request`): a decision
    /// reference minted under an older epoch (§3.6 step 2).
    pub const RESTORE_EPOCH_STALE: &str = "restore_epoch_stale";
    /// ⟨rev7⟩ `REQUEST_STALE`: a request ID the ledger fenced at a restore or a repair; it is
    /// never executed again (ADR-0014 §3.6 step 4; U0-Q5, Q8).
    pub const RESTORED_BEFORE_COMPLETION: &str = "restored_before_completion";

    /// ⟨rev7⟩ Revision 7's reasons under the codes of the table, each `(reason, code)`.
    pub const REV7: &[(&str, Code)] = &[
        (PAGE_TOKEN_INVALID, Code::UsageError),
        (SELECTOR_INVALID, Code::UsageError),
        (RESPONSE_TOO_LARGE, Code::UsageError),
        (ITEM_TOO_LARGE, Code::UsageError),
        (HISTORY_TRIMMED, Code::ResyncRequired),
        (EVENT_TOO_LARGE, Code::ResyncRequired),
        (CURSOR_INVALID, Code::ResyncRequired),
        (RUNTIME_NOT_RUNNING, Code::ServiceUnavailable),
        (RUNTIME_UNREACHABLE, Code::ServiceUnavailable),
        (ENDPOINT_UNTRUSTED, Code::ServiceUnavailable),
        (DESTINATION_HAS_LIVE_ACCESS, Code::ConfigConflict),
        (MECHANISM_MINIMUM_UNMET, Code::CapabilityUnavailable),
        (DECISION_DENIED, Code::CapabilityUnavailable),
        (PROBES_UNAVAILABLE, Code::CapabilityUnavailable),
        (PROBE_INCONCLUSIVE, Code::DestinationUnreachable),
        (
            LOCAL_WIDENING_NEEDS_ATTENDED_OWNER,
            Code::InteractionRequired,
        ),
        (STATE_CORRUPT, Code::StateUnavailable),
        (STATE_NEWER_THAN_BUILD, Code::StateUnavailable),
        (LEDGER_DAMAGED, Code::StateUnavailable),
        (STATE_RESTORED_AUTHORITY_ENDED, Code::CredentialExpired),
        (
            CLIENT_QUARANTINED_AFTER_RESTORE,
            Code::CapabilityUnavailable,
        ),
        (INVITATION_VOID_AFTER_RESTORE, Code::CapabilityUnavailable),
        (EXPOSURE_DISABLED_AFTER_RESTORE, Code::CapabilityUnavailable),
        // A decision reference minted under an older epoch (ADR-0014 §3.6 step 2).
        (RESTORE_EPOCH_STALE, Code::DecisionStale),
        // ⟨M08 U2b-2; ADR-0014 H13⟩ A request (ADR-0014 §3.6 steps 3 and 4). `REQUEST_STALE`
        // joined the code table with its emitter (the ruling on ASK-CODE).
        (RESTORE_EPOCH_STALE, Code::RequestStale),
        (RESTORED_BEFORE_COMPLETION, Code::RequestStale),
    ];

    /// ⟨rev7⟩ The two resync reasons that are not error reasons: `subscriber_lagged` (a live
    /// `resync_required` event when the 256-event buffer overran; it ends the stream) and
    /// `backlog_too_long` (a subscribe `resync_reason` when the missed backlog is over 500
    /// events). With [`HISTORY_TRIMMED`], [`EVENT_TOO_LARGE`] and [`CURSOR_INVALID`] they are
    /// every resync reason (ADR-0013 §5.3, §5.4).
    pub const SUBSCRIBER_LAGGED: &str = "subscriber_lagged";
    /// ⟨rev7⟩ See [`SUBSCRIBER_LAGGED`].
    pub const BACKLOG_TOO_LONG: &str = "backlog_too_long";
}

/// ⟨M05⟩ Warning codes revision 5 adds for M05 (m05-plan §4 item 9).
pub mod m05_warning {
    /// A bind joined a slot another binding materializes (ADR-0011 §5.2): ordinary aliases
    /// are environment-level (`ordinary_aliases: shared_environment_default`).
    pub const SLOT_SHARED: &str = "slot_shared";
    /// Every M05 warning code.
    pub const ALL: &[&str] = &[SLOT_SHARED];
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
            request_id: None,
            request_epoch: None,
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

    /// ⟨rev7; D20, PC11⟩ An `item_too_large` refusal carries [`ItemTooLarge`] in the detail
    /// (`field`, `bound`, `unit`, the item in `resource`); every other detail omits them, and a
    /// detail that predates them reads as none.
    #[test]
    fn item_too_large_is_attached_and_additive() {
        let old = r#"{"code":"USAGE_ERROR","effect_status":"none","retryable":false,
            "next":{"action":"fix_request"},"message":"m"}"#;
        let mut detail: ErrorDetail = serde_json::from_str(old).unwrap();
        assert_eq!(detail.item_too_large(), None);
        let v = serde_json::to_value(&detail).unwrap();
        for k in ["field", "bound", "unit"] {
            assert!(v.get(k).is_none(), "{k}: {v}");
        }
        detail.reason = Some(reason::ITEM_TOO_LARGE.to_owned());
        detail.resource = Some(ResourceRef {
            kind: "profile".to_owned(),
            id: Some("work".to_owned()),
        });
        detail.field = Some("pairs".to_owned());
        detail.bound = Some(200);
        detail.unit = Some(BoundUnit::Entries);
        let v = serde_json::to_value(&detail).unwrap();
        assert_eq!(v["field"], "pairs");
        assert_eq!(v["bound"], 200);
        assert_eq!(v["unit"], "entries");
        assert_eq!(
            v["resource"],
            serde_json::json!({"kind": "profile", "id": "work"})
        );
        let back: ErrorDetail = serde_json::from_value(v).unwrap();
        assert_eq!(back, detail);
        assert_eq!(
            back.item_too_large(),
            Some(ItemTooLarge {
                field: "pairs".to_owned(),
                bound: 200,
                unit: BoundUnit::Entries,
                resource: detail.resource.clone(),
            })
        );
    }
}
