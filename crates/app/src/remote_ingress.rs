//! ⟨M08 W4 SEC-5; spec §14; ADR-0013⟩ Remote-ingress screening of runner success data and
//! unknown error codes.
//!
//! A paired runner is an untrusted peer from the perspective of this controller's own
//! records, human output, logs and agent-facing JSON (spec §14). SEC-1 added
//! [`crate::remote_env::peer_refusal`] for runner refusals and canonicalized report/ack
//! `scope_key`s. This module extends that boundary to:
//!
//! 1. **Bounded unknown error codes** (ruling 8): [`screen_peer_code`] keeps
//!    [`Code::Unknown`] only when it matches `[A-Z][A-Z0-9_]*` and is at most
//!    [`MAX_PEER_CODE_BYTES`] (64 bytes), and maps any other spelling to
//!    [`PEER_UNKNOWN_CODE`] (`"UNKNOWN_CODE"`).
//! 2. **Runner success payloads** (item 1): every relayed success answer
//!    (`revoke-client`, `update`, `recheck`, `transport rotate` accepted announcements,
//!    a limited role's `runner_view`, and forwarded/submitted `EnsureData`) is parsed from
//!    the wire into freshly constructed typed values, dropping unknown keys and screening
//!    every field to the grammar guaranteed by its local producer:
//!    * enumerations and tokens to their grammar (unknown values map to the contract's
//!      existing unknown/undetermined/not-verified/absent representation where one exists,
//!      else refuse as `OUTCOME_UNKNOWN`);
//!    * IDs to their ID grammar (generated `<prefix>_<32 lowercase hex>` for
//!      runtime-generated IDs, contract token grammar for caller-chosen IDs, exact 64
//!      lowercase hex for Iroh endpoints, `SHA256:<43 base64>` for fingerprints);
//!    * runner-local paths and endpoints bounded (<= 4096 bytes), with no control
//!      characters and a valid path or named-pipe prefix, kept as runner-reported values;
//!    * genuine free text (`EnsureData.connection_policy.wording`, `runner_view` record
//!      `label`) replaced with fixed local text.
//!
//! Values only change — no contract shape is altered (ADR-0013). Any reply that fails its
//! grammar where the field has no existing unknown representation is refused as
//! `OUTCOME_UNKNOWN` with the message `"the runner's response could not be read"`.

use heimdall_contract::doctor::{ConfigProvenance, GitScope};
use heimdall_contract::environment::{
    EnvironmentKindView, MountSpec, RealizationDescriptor, RouteView,
};
use heimdall_contract::ids::{
    AccountName, BindingId, ClientId, DestinationId, DeviceId, EnvironmentId, GrantId, IdentityId,
    IrohEndpointId, KeyFingerprint, OperationId, PolicyId, WorkspaceId,
};
use heimdall_contract::managed::{
    AuthenticationResidual, BindingEndpointKind, ClockMeasurement, ComponentResidual,
    ConnectionPolicyReport, DestinationClock, EvidenceEntry, EvidenceSource,
    ExistingConnectionsMode, IdentitySelectionEnforcement, IssuerIsolation, LocalRevocation,
    LockContinuityReport, MultiplexingMode, NewSigningExpiry, OwnedMultiplexing,
    ReadinessCondition, RefreshCondition, RefreshTrigger, RemoteProcesses, RemoteRevocation,
    RevocationResiduals, RevocationSemantics, UnmanagedConnections, WithheldReason,
};
use heimdall_contract::provider::{
    Certainty, CredentialAvailability, DeclarationRef, EndpointKind, EndpointRef, EvidenceBasis,
    IdentitiesOnly, IdentityBacking, IdentityEntry, IdentityEntryKind, IdentityEntrySource,
    IdentitySelection, IdentitySelectionReport, InteractionKind, NoninteractiveEligibility,
    ProbeLevel, ProviderAvailability, ProviderKind, ProviderStatus, noninteractive_reason,
};
use heimdall_contract::remote::ManagementPolicy;
use heimdall_contract::request::{
    AccessPairRef, ConsumerExecutable, ConsumerIntegration, ConsumerKind, ConsumerOverride,
    DestinationScopeEnforcement, Enforcement, EnsureData, ExistingConnectionsPolicy,
    MAX_EXECUTABLE_BYTES, NewAuthenticationExpiry, OverrideSource, PairIntegration,
    RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_contract::trust::{
    ContextKind, ContextProvenance, ContextReport, OrdinaryAliases, OwnerFunctions,
};
use heimdall_contract::views::environment::{
    EnvironmentListView, EnvironmentPermissionsView, EnvironmentRecordView,
};
use heimdall_contract::{Code, Timestamp};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::OpError;
use crate::remote_env::is_reason_token;

/// ⟨M08 W4 SEC-5, ruling 8⟩ Longest `Code::Unknown` accepted from a peer.
pub const MAX_PEER_CODE_BYTES: usize = 64;

/// ⟨M08 W4 SEC-5, ruling 8⟩ Fixed spelling substituted for any peer `Code::Unknown` that
/// fails `[A-Z][A-Z0-9_]*` or exceeds [`MAX_PEER_CODE_BYTES`].
pub const PEER_UNKNOWN_CODE: &str = "UNKNOWN_CODE";

/// Fixed local text substituted for a runner's free-text environment label in
/// `runner_view` (spec §14).
const RUNNER_LABEL_OMITTED: &str = "runner label omitted";

const MAX_ALIAS_BYTES: usize = 64;
const MAX_FIELD_BYTES: usize = 64;
const MAX_RECORD_PATH_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 64;
const MAX_OPENSSH_VERSION_BYTES: usize = 32;
const MAX_ENV_VARS: usize = 32;
const MAX_EXECUTABLES: usize = 16;
const MAX_OVERRIDES: usize = 64;
const MAX_PAIRS: usize = 256;
const MAX_SELECTION_ENTRIES: usize = 64;
const MAX_CONDITIONS: usize = 32;
const MAX_EVIDENCE: usize = 128;
const MAX_UNCOVERED: usize = 256;
const MAX_RUNNER_VIEW_RECORDS: usize = 16;

/// Exact refusal returned whenever a runner's success reply fails its grammar and the
/// offending field has no existing unknown representation.
#[must_use]
pub fn unreadable_runner_response() -> OpError {
    OpError::new(
        Code::OutcomeUnknown,
        "the runner's response could not be read",
    )
}

/// ⟨M08 W4 SEC-5, ruling 8⟩ Whether `code` matches `[A-Z][A-Z0-9_]*` and is at most
/// [`MAX_PEER_CODE_BYTES`] bytes.
#[must_use]
pub fn is_peer_code_token(code: &str) -> bool {
    let bytes = code.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_PEER_CODE_BYTES
        && bytes[0].is_ascii_uppercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

/// ⟨M08 W4 SEC-5, ruling 8⟩ Screen a peer's `Code`: known variants pass unchanged;
/// `Code::Unknown(s)` passes only if [`is_peer_code_token`], else maps to
/// `Code::Unknown(PEER_UNKNOWN_CODE)`.
#[must_use]
pub fn screen_peer_code(code: Code) -> Code {
    match code {
        Code::Unknown(ref s) if !is_peer_code_token(s) => {
            Code::Unknown(PEER_UNKNOWN_CODE.to_owned())
        }
        other => other,
    }
}

// --- primitive grammar helpers -----------------------------------------------------------

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `text` matches `<prefix>_<32 lowercase hex>`, the wire grammar of every
/// runtime-generated ID (`heimdall_contract::ids`).
#[must_use]
pub fn is_generated_id(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|hex| is_lower_hex(hex, 32))
}

fn is_alias_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_ALIAS_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_dotted_field_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_FIELD_BYTES && s.split('.').all(is_reason_token)
}

fn is_evidence_record_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_RECORD_PATH_BYTES
        && !s.starts_with('/')
        && !s.contains("//")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && s.split('/').all(|seg| !seg.is_empty() && seg != "..")
}

fn is_version_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_VERSION_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// OpenSSH version token: `[OpenSSH_]<digits>.<digits>[p<digits>]`, <= 32 bytes.
fn is_openssh_version(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_OPENSSH_VERSION_BYTES {
        return false;
    }
    let rest = s.strip_prefix("OpenSSH_").unwrap_or(s);
    let Some((major, tail)) = rest.split_once('.') else {
        return false;
    };
    if major.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    match tail.split_once('p') {
        Some((minor, patch)) => {
            !minor.is_empty()
                && minor.bytes().all(|b| b.is_ascii_digit())
                && !patch.is_empty()
                && patch.bytes().all(|b| b.is_ascii_digit())
        }
        None => !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn is_named_pipe(s: &str) -> bool {
    if s.len() > MAX_EXECUTABLE_BYTES || s.chars().any(char::is_control) {
        return false;
    }
    let rest = s
        .strip_prefix(r"\\.\pipe\")
        .or_else(|| s.strip_prefix("//./pipe/"));
    rest.is_some_and(|name| !name.is_empty() && !name.contains(['\\', '/']))
}

fn is_windows_abs_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/')
}

/// Runner-local absolute path or named-pipe endpoint: bounded, no control chars, valid root.
fn is_runner_path(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_EXECUTABLE_BYTES || s.chars().any(char::is_control) {
        return false;
    }
    s.starts_with('/') || is_named_pipe(s) || is_windows_abs_path(s)
}

fn is_mount_source(s: &str) -> bool {
    is_runner_path(s)
        || s.strip_prefix("c/")
            .is_some_and(|hex| is_lower_hex(hex, 16))
}

fn is_config_path_display(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_EXECUTABLE_BYTES || s.chars().any(char::is_control) {
        return false;
    }
    s == "~" || s == "?" || s.starts_with("~/") || s.starts_with("$HOME/") || is_runner_path(s)
}

fn is_sh_word_runner_path(word: &str) -> bool {
    if word.is_empty() || word.len() > MAX_EXECUTABLE_BYTES * 4 {
        return false;
    }
    if let Some(inner) = word.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        // Reconstruct `container_m04::sh_word`'s single-quoting (`'` encoded as `'\''`).
        let mut unquoted = String::with_capacity(inner.len());
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                if inner[i..].starts_with(r"'\''") {
                    unquoted.push('\'');
                    i += 4;
                } else {
                    return false;
                }
            } else {
                let ch = inner[i..].chars().next().unwrap_or('\0');
                unquoted.push(ch);
                i += ch.len_utf8();
            }
        }
        return is_runner_path(&unquoted);
    }
    word.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        && is_runner_path(word)
}

fn is_consumer_env_pair(name: &str, value: &str) -> bool {
    match name {
        "SSH_AUTH_SOCK" => is_runner_path(value),
        "GIT_SSH_COMMAND" => value
            .strip_prefix("ssh -F ")
            .is_some_and(is_sh_word_runner_path),
        _ => false,
    }
}

fn is_override_setting(s: &str) -> bool {
    matches!(
        s,
        "IdentityAgent"
            | "SSH_AUTH_SOCK"
            | "core.sshCommand"
            | "GIT_SSH_COMMAND"
            | "GIT_SSH"
            | "GIT_SSH_VARIANT"
    )
}

// --- JSON reading helpers ----------------------------------------------------------------

fn as_obj(v: &Value) -> Result<&Map<String, Value>, OpError> {
    v.as_object().ok_or_else(unreadable_runner_response)
}

fn req<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Value, OpError> {
    obj.get(key).ok_or_else(unreadable_runner_response)
}

fn opt<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn req_str<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str, OpError> {
    req(obj, key)?
        .as_str()
        .ok_or_else(unreadable_runner_response)
}

fn req_bool(obj: &Map<String, Value>, key: &str) -> Result<bool, OpError> {
    req(obj, key)?
        .as_bool()
        .ok_or_else(unreadable_runner_response)
}

fn req_u64(obj: &Map<String, Value>, key: &str) -> Result<u64, OpError> {
    req(obj, key)?
        .as_u64()
        .ok_or_else(unreadable_runner_response)
}

fn req_u32(obj: &Map<String, Value>, key: &str) -> Result<u32, OpError> {
    req_u64(obj, key)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(unreadable_runner_response)
}

fn parse_strict<T: DeserializeOwned>(v: &Value) -> Result<T, OpError> {
    serde_json::from_value(v.clone()).map_err(|_| unreadable_runner_response())
}

fn parse_ts(v: &Value) -> Result<Timestamp, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    serde_json::from_value(Value::String(s.to_owned())).map_err(|_| unreadable_runner_response())
}

fn parse_enum_or_unknown<T: DeserializeOwned>(v: &Value, unknown: T) -> Result<T, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    Ok(serde_json::from_value(Value::String(s.to_owned())).unwrap_or(unknown))
}

fn parse_opt_enum_or_unknown<T: DeserializeOwned>(
    obj: &Map<String, Value>,
    key: &str,
    unknown: T,
) -> Result<Option<T>, OpError> {
    opt(obj, key)
        .map(|v| parse_enum_or_unknown(v, unknown))
        .transpose()
}

fn screen_admission_report(v: &Value) -> Result<Value, OpError> {
    let obj = as_obj(v)?;
    match req_str(obj, "state")? {
        "applied" => Ok(serde_json::json!({ "state": "applied" })),
        "not_serving" => Ok(serde_json::json!({ "state": "not_serving" })),
        "pending" => {
            let reason = req_str(obj, "reason")?;
            if reason == heimdall_contract::envelope::reason::IROH_ADMISSION_CLOSING {
                Ok(serde_json::json!({ "state": "pending", "reason": reason }))
            } else {
                Err(unreadable_runner_response())
            }
        }
        _ => Err(unreadable_runner_response()),
    }
}

fn screen_env_id(v: &Value) -> Result<EnvironmentId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, EnvironmentId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    EnvironmentId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_client_id(v: &Value) -> Result<ClientId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, ClientId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    ClientId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_grant_id(v: &Value) -> Result<GrantId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, GrantId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    GrantId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_binding_id(v: &Value) -> Result<BindingId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, BindingId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    BindingId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_device_id(v: &Value) -> Result<DeviceId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, DeviceId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    DeviceId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_operation_id(v: &Value) -> Result<OperationId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, OperationId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    OperationId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_identity_id(v: &Value) -> Result<IdentityId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, IdentityId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    IdentityId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_workspace_id(v: &Value) -> Result<WorkspaceId, OpError> {
    let s = v.as_str().ok_or_else(unreadable_runner_response)?;
    if !is_generated_id(s, WorkspaceId::PREFIX) {
        return Err(unreadable_runner_response());
    }
    WorkspaceId::parse(s).map_err(|_| unreadable_runner_response())
}

fn screen_pair_ref(v: &Value) -> Result<AccessPairRef, OpError> {
    let obj = as_obj(v)?;
    let destination = DestinationId::parse(req_str(obj, "destination")?)
        .map_err(|_| unreadable_runner_response())?;
    let account =
        AccountName::parse(req_str(obj, "account")?).map_err(|_| unreadable_runner_response())?;
    Ok(AccessPairRef {
        destination,
        account,
    })
}

fn screen_endpoint_ref(v: &Value) -> Result<EndpointRef, OpError> {
    let obj = as_obj(v)?;
    let kind: EndpointKind = parse_strict(req(obj, "kind")?)?;
    let locator = req_str(obj, "locator")?;
    let ok = match kind {
        EndpointKind::UnixSocket => {
            locator.len() <= MAX_EXECUTABLE_BYTES
                && locator.starts_with('/')
                && !locator.chars().any(char::is_control)
        }
        EndpointKind::NamedPipe => is_named_pipe(locator),
        _ => false,
    };
    if !ok {
        return Err(unreadable_runner_response());
    }
    Ok(EndpointRef {
        kind,
        locator: locator.to_owned(),
    })
}

fn screen_provenance(v: &Value) -> Result<ConfigProvenance, OpError> {
    let obj = as_obj(v)?;
    let path_display = req_str(obj, "path_display")?;
    if !is_config_path_display(path_display) {
        return Err(unreadable_runner_response());
    }
    let line = req_u32(obj, "line")?;
    Ok(ConfigProvenance {
        path_display: path_display.to_owned(),
        line,
    })
}

fn screen_destination_clock(v: &Value) -> Result<DestinationClock, OpError> {
    match v {
        Value::String(s) if s == "unmeasured" => Ok(DestinationClock::Unmeasured),
        Value::Object(map) => {
            let inner = map
                .get("measured")
                .and_then(Value::as_object)
                .ok_or_else(unreadable_runner_response)?;
            Ok(DestinationClock::Measured(ClockMeasurement {
                behind_upper_ms: req_u64(inner, "behind_upper_ms")?,
                rtt_ms: req_u64(inner, "rtt_ms")?,
                measured_at: parse_ts(req(inner, "measured_at")?)?,
            }))
        }
        _ => Err(unreadable_runner_response()),
    }
}

fn screen_env_pairs(v: &Value) -> Result<Vec<(String, String)>, OpError> {
    let arr = v.as_array().ok_or_else(unreadable_runner_response)?;
    if arr.len() > MAX_ENV_VARS {
        return Err(unreadable_runner_response());
    }
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let pair = entry.as_array().ok_or_else(unreadable_runner_response)?;
        if pair.len() != 2 {
            return Err(unreadable_runner_response());
        }
        let k = pair[0].as_str().ok_or_else(unreadable_runner_response)?;
        let val = pair[1].as_str().ok_or_else(unreadable_runner_response)?;
        if !is_consumer_env_pair(k, val) {
            return Err(unreadable_runner_response());
        }
        out.push((k.to_owned(), val.to_owned()));
    }
    Ok(out)
}

// --- controller management success payloads ----------------------------------------------

/// Screen the runner's `remote_environment.revoke_client` success payload.
///
/// Expected wire shape (`PairedRunner::revoke_client`):
/// `{environment, client, state: "revoked", iroh_admission, line_removed}`.
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_revoke_client_answer(
    raw: Value,
    expected_env: &EnvironmentId,
    expected_client: &ClientId,
) -> Result<Value, OpError> {
    let obj = as_obj(&raw)?;
    let environment = screen_env_id(req(obj, "environment")?)?;
    let client = screen_client_id(req(obj, "client")?)?;
    if environment != *expected_env || client != *expected_client {
        return Err(unreadable_runner_response());
    }
    if req_str(obj, "state")? != "revoked" {
        return Err(unreadable_runner_response());
    }
    let iroh_admission = screen_admission_report(req(obj, "iroh_admission")?)?;
    let line_removed = req_bool(obj, "line_removed")?;
    Ok(serde_json::json!({
        "environment": environment,
        "client": client,
        "state": "revoked",
        "iroh_admission": iroh_admission,
        "line_removed": line_removed,
    }))
}

/// Screen the runner's `remote_environment.update` success payload.
///
/// Accepts a JSON object whose optional known fields (`environment`, `status`, `version`,
/// `sha256`, `updated`) match their grammars; drops any unknown key.
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_update_answer(raw: Value, expected_env: &EnvironmentId) -> Result<Value, OpError> {
    let obj = as_obj(&raw)?;
    let mut out = Map::new();
    if let Some(v) = opt(obj, "environment") {
        let env = screen_env_id(v)?;
        if env != *expected_env {
            return Err(unreadable_runner_response());
        }
        out.insert(
            "environment".to_owned(),
            Value::String(env.as_str().to_owned()),
        );
    }
    if let Some(v) = opt(obj, "status") {
        let s = v.as_str().ok_or_else(unreadable_runner_response)?;
        if !is_reason_token(s) {
            return Err(unreadable_runner_response());
        }
        out.insert("status".to_owned(), Value::String(s.to_owned()));
    }
    if let Some(v) = opt(obj, "version") {
        let s = v.as_str().ok_or_else(unreadable_runner_response)?;
        if !is_version_token(s) {
            return Err(unreadable_runner_response());
        }
        out.insert("version".to_owned(), Value::String(s.to_owned()));
    }
    if let Some(v) = opt(obj, "sha256") {
        let s = v.as_str().ok_or_else(unreadable_runner_response)?;
        if !is_lower_hex(s, 64) {
            return Err(unreadable_runner_response());
        }
        out.insert("sha256".to_owned(), Value::String(s.to_owned()));
    }
    if let Some(v) = opt(obj, "updated") {
        let b = v.as_bool().ok_or_else(unreadable_runner_response)?;
        out.insert("updated".to_owned(), Value::Bool(b));
    }
    Ok(Value::Object(out))
}

/// Screen the runner's `remote_environment.runner_policy_recheck` success payload.
///
/// Expected wire shapes (`PairedRunner::policy_recheck`):
/// * not downgraded: `{environment, downgraded: false, recorded: false, management_policy}`;
/// * downgraded and recorded: `{environment, downgraded: true, recorded: true, cause, epoch,
///   controller, recorded_at, valid_for_seconds}` (an unknown `cause` string maps to the
///   existing unknown spelling `"unreadable"`).
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_recheck_answer(raw: Value, expected_env: &EnvironmentId) -> Result<Value, OpError> {
    let obj = as_obj(&raw)?;
    let environment = screen_env_id(req(obj, "environment")?)?;
    if environment != *expected_env {
        return Err(unreadable_runner_response());
    }
    let downgraded = req_bool(obj, "downgraded")?;
    let recorded = req_bool(obj, "recorded")?;
    match (downgraded, recorded) {
        (false, false) => {
            let policy: ManagementPolicy = parse_strict(req(obj, "management_policy")?)?;
            Ok(serde_json::json!({
                "environment": environment,
                "downgraded": false,
                "recorded": false,
                "management_policy": policy,
            }))
        }
        (true, true) => {
            let raw_cause = req_str(obj, "cause")?;
            let cause = match raw_cause {
                "probe_disagreed" | "session_pty" | "session_agent_forwarded" | "unreadable" => {
                    raw_cause
                }
                _ => "unreadable",
            };
            let epoch = req_u64(obj, "epoch")?;
            let controller = screen_client_id(req(obj, "controller")?)?;
            let recorded_at = parse_ts(req(obj, "recorded_at")?)?;
            let valid_for_seconds = req_u64(obj, "valid_for_seconds")?;
            Ok(serde_json::json!({
                "environment": environment,
                "downgraded": true,
                "recorded": true,
                "cause": cause,
                "epoch": epoch,
                "controller": controller,
                "recorded_at": recorded_at,
                "valid_for_seconds": valid_for_seconds,
            }))
        }
        _ => Err(unreadable_runner_response()),
    }
}

/// Screen the runner's `remote_environment.rotate_endpoint` success payload
/// (`transport rotate`'s accepted announcements).
///
/// Expected wire shape (`PairedRunner::rotate_endpoint`):
/// `{environment, client, endpoint, change: "recorded"|"unchanged"|"replaced", iroh_admission?}`.
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_rotate_endpoint_answer(
    raw: Value,
    expected_env: &EnvironmentId,
    expected_client: &ClientId,
    expected_endpoint: &IrohEndpointId,
) -> Result<Value, OpError> {
    let obj = as_obj(&raw)?;
    let environment = screen_env_id(req(obj, "environment")?)?;
    let client = screen_client_id(req(obj, "client")?)?;
    let endpoint = IrohEndpointId::parse(req_str(obj, "endpoint")?)
        .map_err(|_| unreadable_runner_response())?;
    if environment != *expected_env || client != *expected_client || endpoint != *expected_endpoint
    {
        return Err(unreadable_runner_response());
    }
    let change = req_str(obj, "change")?;
    if !matches!(change, "recorded" | "unchanged" | "replaced") {
        return Err(unreadable_runner_response());
    }
    let mut out = serde_json::json!({
        "environment": environment,
        "client": client,
        "endpoint": endpoint,
        "change": change,
    });
    if let Some(iroh) = opt(obj, "iroh_admission") {
        let screened = screen_admission_report(iroh)?;
        if let Some(map) = out.as_object_mut() {
            map.insert("iroh_admission".to_owned(), screened);
        }
    }
    Ok(out)
}

/// Screen a limited role's `inspect environments` answer (`RemoteEnvController::runner_view`).
///
/// Reconstructs [`EnvironmentListView`] with `items: None` and `preview: None`, replacing any
/// free-text environment `label` with fixed local text ([`RUNNER_LABEL_OMITTED`]).
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_runner_view_answer(
    raw: Value,
    expected_env: &EnvironmentId,
) -> Result<Value, OpError> {
    let obj = as_obj(&raw)?;
    let environment_id = screen_env_id(req(obj, "environment_id")?)?;
    if environment_id != *expected_env {
        return Err(unreadable_runner_response());
    }
    let enrolled = req_bool(obj, "enrolled")?;
    let raw_records = req(obj, "environments")?
        .as_array()
        .ok_or_else(unreadable_runner_response)?;
    if raw_records.len() > MAX_RUNNER_VIEW_RECORDS {
        return Err(unreadable_runner_response());
    }
    let mut environments = Vec::with_capacity(raw_records.len());
    for item in raw_records {
        let rec = as_obj(item)?;
        let id = screen_env_id(req(rec, "id")?)?;
        let device = screen_device_id(req(rec, "device")?)?;
        let kind: EnvironmentKindView = parse_strict(req(rec, "kind")?)?;
        let label = match opt(rec, "label") {
            None => None,
            Some(v) => {
                // Must be a string; genuine free text is replaced with fixed local text.
                let _ = v.as_str().ok_or_else(unreadable_runner_response)?;
                Some(RUNNER_LABEL_OMITTED.to_owned())
            }
        };
        let perms = as_obj(req(rec, "permissions")?)?;
        let permissions = EnvironmentPermissionsView {
            automatic_activation: req_bool(perms, "automatic_activation")?,
            managed_signing: req_bool(perms, "managed_signing")?,
            issuer_access: req_bool(perms, "issuer_access")?,
        };
        environments.push(EnvironmentRecordView {
            id,
            device,
            kind,
            label,
            permissions,
        });
    }
    let view = EnvironmentListView {
        environment_id,
        enrolled,
        environments,
        items: None,
        preview: None,
    };
    serde_json::to_value(&view).map_err(|_| unreadable_runner_response())
}

// --- EnsureData screening (forwarded and submitted ensure) -------------------------------

fn connection_policy_local_wording(
    existing: ExistingConnectionsMode,
    multiplexing: MultiplexingMode,
) -> String {
    let existing_name = match existing {
        ExistingConnectionsMode::Graceful => "graceful",
        ExistingConnectionsMode::Strict => "strict",
        _ => "unknown",
    };
    let mux_name = match multiplexing {
        MultiplexingMode::Disabled => "disabled",
        MultiplexingMode::OwnedMasters => "owned_masters",
        _ => "unknown",
    };
    format!(
        "runner connection policy (existing: {existing_name}, multiplexing: {mux_name}); \
         the runner's own wording is not shown"
    )
}

fn screen_enforcement(v: &Value) -> Result<Enforcement, OpError> {
    let obj = as_obj(v)?;
    Ok(Enforcement {
        destination_scope: parse_enum_or_unknown(
            req(obj, "destination_scope")?,
            DestinationScopeEnforcement::Unknown,
        )?,
        new_authentication_expiry: parse_enum_or_unknown(
            req(obj, "new_authentication_expiry")?,
            NewAuthenticationExpiry::Unknown,
        )?,
        workload_isolation: parse_enum_or_unknown(
            req(obj, "workload_isolation")?,
            WorkloadIsolation::Unknown,
        )?,
        existing_connections: parse_enum_or_unknown(
            req(obj, "existing_connections")?,
            ExistingConnectionsPolicy::Unknown,
        )?,
        revocation: parse_enum_or_unknown(req(obj, "revocation")?, RevocationStatus::Unknown)?,
        identity_selection: parse_opt_enum_or_unknown(
            obj,
            "identity_selection",
            IdentitySelectionEnforcement::Unknown,
        )?,
        new_signing_expiry: parse_opt_enum_or_unknown(
            obj,
            "new_signing_expiry",
            NewSigningExpiry::Unknown,
        )?,
        owned_multiplexing: parse_opt_enum_or_unknown(
            obj,
            "owned_multiplexing",
            OwnedMultiplexing::Unknown,
        )?,
        remote_processes: parse_opt_enum_or_unknown(
            obj,
            "remote_processes",
            RemoteProcesses::Unknown,
        )?,
        unmanaged_connections: parse_opt_enum_or_unknown(
            obj,
            "unmanaged_connections",
            UnmanagedConnections::Unknown,
        )?,
        issuer_isolation: parse_opt_enum_or_unknown(
            obj,
            "issuer_isolation",
            IssuerIsolation::Unknown,
        )?,
        ordinary_aliases: parse_opt_enum_or_unknown(
            obj,
            "ordinary_aliases",
            OrdinaryAliases::Unknown,
        )?,
        owner_functions: parse_opt_enum_or_unknown(
            obj,
            "owner_functions",
            OwnerFunctions::Unknown,
        )?,
    })
}

fn screen_provider(v: &Value) -> Result<ProviderStatus, OpError> {
    let obj = as_obj(v)?;
    Ok(ProviderStatus {
        provider: parse_enum_or_unknown(req(obj, "provider")?, ProviderKind::Unknown)?,
        availability: parse_enum_or_unknown(
            req(obj, "availability")?,
            ProviderAvailability::Unknown,
        )?,
        interaction: parse_enum_or_unknown(req(obj, "interaction")?, InteractionKind::Unknown)?,
        observed_level: parse_strict::<ProbeLevel>(req(obj, "observed_level")?)?,
        observed_at: parse_ts(req(obj, "observed_at")?)?,
        basis: parse_strict::<EvidenceBasis>(req(obj, "basis")?)?,
    })
}

fn screen_revocation(v: &Value) -> Result<RevocationSemantics, OpError> {
    let obj = as_obj(v)?;
    Ok(RevocationSemantics {
        local: parse_strict::<LocalRevocation>(req(obj, "local")?)?,
        remote: parse_enum_or_unknown(req(obj, "remote")?, RemoteRevocation::Unknown)?,
        latest_possible_credential_expiry: opt(obj, "latest_possible_credential_expiry")
            .map(parse_ts)
            .transpose()?,
        destination_clock: screen_destination_clock(req(obj, "destination_clock")?)?,
    })
}

fn screen_residuals(v: &Value) -> Result<RevocationResiduals, OpError> {
    let obj = as_obj(v)?;
    let new_authentication = opt(obj, "new_authentication")
        .map(|na| -> Result<AuthenticationResidual, OpError> {
            let na_obj = as_obj(na)?;
            Ok(AuthenticationResidual {
                latest_possible_credential_expiry: opt(na_obj, "latest_possible_credential_expiry")
                    .map(parse_ts)
                    .transpose()?,
                destination_clock_error: screen_destination_clock(req(
                    na_obj,
                    "destination_clock_error",
                )?)?,
            })
        })
        .transpose()?;
    Ok(RevocationResiduals {
        new_authentication,
        owned_dedicated_sessions: parse_opt_enum_or_unknown(
            obj,
            "owned_dedicated_sessions",
            ComponentResidual::Unknown,
        )?,
        owned_admissions: parse_opt_enum_or_unknown(
            obj,
            "owned_admissions",
            ComponentResidual::Unknown,
        )?,
        other_live_sessions: parse_opt_enum_or_unknown(
            obj,
            "other_live_sessions",
            ComponentResidual::Unknown,
        )?,
        detached_remote_processes: parse_opt_enum_or_unknown(
            obj,
            "detached_remote_processes",
            ComponentResidual::Unknown,
        )?,
    })
}

fn screen_evidence(v: &Value) -> Result<Vec<EvidenceEntry>, OpError> {
    let arr = v.as_array().ok_or_else(unreadable_runner_response)?;
    if arr.len() > MAX_EVIDENCE {
        return Err(unreadable_runner_response());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = as_obj(item)?;
        let field = req_str(obj, "field")?;
        if !is_dotted_field_name(field) {
            return Err(unreadable_runner_response());
        }
        let source: EvidenceSource = parse_strict(req(obj, "source")?)?;
        let pair = opt(obj, "pair").map(screen_pair_ref).transpose()?;
        let record = match opt(obj, "record") {
            None => None,
            Some(r) => {
                let s = r.as_str().ok_or_else(unreadable_runner_response)?;
                if !is_evidence_record_path(s) {
                    return Err(unreadable_runner_response());
                }
                Some(s.to_owned())
            }
        };
        let operation_id = opt(obj, "operation_id")
            .map(screen_operation_id)
            .transpose()?;
        let opt_openssh = |key: &str| -> Result<Option<String>, OpError> {
            match opt(obj, key) {
                None => Ok(None),
                Some(val) => {
                    let s = val.as_str().ok_or_else(unreadable_runner_response)?;
                    // Absent (`None`) is the contract's unobserved representation; any banner
                    // that does not match the strict OpenSSH version token (including empty
                    // strings or hostile text) becomes `None`.
                    Ok(is_openssh_version(s).then(|| s.to_owned()))
                }
            }
        };
        let client = opt_openssh("client")?;
        let server = opt_openssh("server")?;
        let observed_at = parse_ts(req(obj, "observed_at")?)?;
        let fresh_until = opt(obj, "fresh_until").map(parse_ts).transpose()?;
        let endpoint_kind =
            parse_opt_enum_or_unknown(obj, "endpoint_kind", BindingEndpointKind::Unknown)?;
        let withheld_reason = opt(obj, "withheld_reason")
            .map(parse_strict::<WithheldReason>)
            .transpose()?;
        out.push(EvidenceEntry {
            field: field.to_owned(),
            source,
            pair,
            record,
            operation_id,
            client,
            server,
            observed_at,
            fresh_until,
            endpoint_kind,
            withheld_reason,
        });
    }
    Ok(out)
}

fn screen_context(v: &Value) -> Result<ContextReport, OpError> {
    let obj = as_obj(v)?;
    let kind: ContextKind = parse_strict(req(obj, "kind")?)?;
    let workspace_id = opt(obj, "workspace_id")
        .map(screen_workspace_id)
        .transpose()?;
    let policy_id = match opt(obj, "policy_id") {
        None => None,
        Some(p) => {
            let s = p.as_str().ok_or_else(unreadable_runner_response)?;
            Some(PolicyId::parse(s).map_err(|_| unreadable_runner_response())?)
        }
    };
    let policy_revision = match opt(obj, "policy_revision") {
        None => None,
        Some(r) => Some(r.as_u64().ok_or_else(unreadable_runner_response)?),
    };
    let provenance: ContextProvenance = parse_strict(req(obj, "provenance")?)?;
    Ok(ContextReport {
        kind,
        workspace_id,
        policy_id,
        policy_revision,
        provenance,
    })
}

fn screen_executables(v: &Value) -> Result<Vec<ConsumerExecutable>, OpError> {
    let arr = v.as_array().ok_or_else(unreadable_runner_response)?;
    if arr.len() > MAX_EXECUTABLES {
        return Err(unreadable_runner_response());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = as_obj(item)?;
        let consumer: ConsumerKind = parse_strict(req(obj, "consumer")?)?;
        let path = req_str(obj, "path")?;
        if !is_runner_path(path) {
            return Err(unreadable_runner_response());
        }
        let version = match opt(obj, "version") {
            None => None,
            Some(ver) => {
                let s = ver.as_str().ok_or_else(unreadable_runner_response)?;
                if !is_openssh_version(s) {
                    return Err(unreadable_runner_response());
                }
                Some(s.to_owned())
            }
        };
        let sha256 = match opt(obj, "sha256") {
            None => None,
            Some(h) => {
                let s = h.as_str().ok_or_else(unreadable_runner_response)?;
                if !is_lower_hex(s, 64) {
                    return Err(unreadable_runner_response());
                }
                Some(s.to_owned())
            }
        };
        let basis: EvidenceBasis = parse_strict(req(obj, "basis")?)?;
        out.push(ConsumerExecutable {
            consumer,
            path: path.to_owned(),
            version,
            sha256,
            basis,
        });
    }
    Ok(out)
}

fn screen_overrides(v: &Value) -> Result<Vec<ConsumerOverride>, OpError> {
    let arr = v.as_array().ok_or_else(unreadable_runner_response)?;
    if arr.len() > MAX_OVERRIDES {
        return Err(unreadable_runner_response());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = as_obj(item)?;
        let consumer: ConsumerKind = parse_strict(req(obj, "consumer")?)?;
        let setting = req_str(obj, "setting")?;
        if !is_override_setting(setting) {
            return Err(unreadable_runner_response());
        }
        let src_obj = as_obj(req(obj, "source")?)?;
        let source = match req_str(src_obj, "kind")? {
            "ssh_config" => OverrideSource::SshConfig(screen_provenance(req(obj, "source")?)?),
            "git_scope" => OverrideSource::GitScope {
                scope: parse_strict::<GitScope>(req(src_obj, "scope")?)?,
            },
            "environment" => OverrideSource::Environment,
            _ => return Err(unreadable_runner_response()),
        };
        out.push(ConsumerOverride {
            consumer,
            setting: setting.to_owned(),
            source,
        });
    }
    Ok(out)
}

fn screen_selection_report(v: &Value) -> Result<IdentitySelectionReport, OpError> {
    let obj = as_obj(v)?;
    let selection = parse_enum_or_unknown(req(obj, "selection")?, IdentitySelection::Undetermined)?;
    let identities_only =
        parse_enum_or_unknown(req(obj, "identities_only")?, IdentitiesOnly::Undetermined)?;
    let entries = match opt(obj, "entries") {
        None => Vec::new(),
        Some(list) => {
            let arr = list.as_array().ok_or_else(unreadable_runner_response)?;
            if arr.len() > MAX_SELECTION_ENTRIES {
                return Err(unreadable_runner_response());
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let e = as_obj(item)?;
                let kind: IdentityEntryKind = parse_strict(req(e, "kind")?)?;
                let source: IdentityEntrySource = parse_strict(req(e, "source")?)?;
                let provenance = opt(e, "provenance").map(screen_provenance).transpose()?;
                let certainty =
                    parse_enum_or_unknown(req(e, "certainty")?, Certainty::Undetermined)?;
                let fingerprint = match opt(e, "fingerprint") {
                    None => None,
                    Some(fp) => {
                        let s = fp.as_str().ok_or_else(unreadable_runner_response)?;
                        KeyFingerprint::parse(s).map_err(|_| unreadable_runner_response())?;
                        Some(s.to_owned())
                    }
                };
                let backing = parse_enum_or_unknown(req(e, "backing")?, IdentityBacking::Unknown)?;
                let cleared = match opt(e, "cleared") {
                    None => None,
                    Some(c) => Some(c.as_bool().ok_or_else(unreadable_runner_response)?),
                };
                out.push(IdentityEntry {
                    kind,
                    source,
                    provenance,
                    certainty,
                    fingerprint,
                    backing,
                    cleared,
                });
            }
            out
        }
    };
    Ok(IdentitySelectionReport {
        selection,
        entries,
        identities_only,
    })
}

fn screen_pairs(v: &Value) -> Result<Vec<PairIntegration>, OpError> {
    let arr = v.as_array().ok_or_else(unreadable_runner_response)?;
    if arr.len() > MAX_PAIRS {
        return Err(unreadable_runner_response());
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = as_obj(item)?;
        let destination = DestinationId::parse(req_str(obj, "destination")?)
            .map_err(|_| unreadable_runner_response())?;
        let account = AccountName::parse(req_str(obj, "account")?)
            .map_err(|_| unreadable_runner_response())?;
        let identity = screen_identity_id(req(obj, "identity")?)?;
        let mechanism = req_str(obj, "mechanism")?;
        if !is_reason_token(mechanism) {
            return Err(unreadable_runner_response());
        }
        let endpoint = opt(obj, "endpoint").map(screen_endpoint_ref).transpose()?;
        let alias = match opt(obj, "alias") {
            None => None,
            Some(a) => {
                let s = a.as_str().ok_or_else(unreadable_runner_response)?;
                if !is_alias_name(s) {
                    return Err(unreadable_runner_response());
                }
                Some(s.to_owned())
            }
        };
        let interaction =
            parse_enum_or_unknown(req(obj, "interaction")?, InteractionKind::Unknown)?;
        let interaction_basis: EvidenceBasis = parse_strict(req(obj, "interaction_basis")?)?;
        let declared_at = opt(obj, "declared_at").map(parse_ts).transpose()?;
        let identity_selection = parse_enum_or_unknown(
            req(obj, "identity_selection")?,
            IdentitySelection::Undetermined,
        )?;
        let selection_observed_at = parse_ts(req(obj, "selection_observed_at")?)?;
        let declaration = match opt(obj, "declaration") {
            None => None,
            Some(d) => {
                let dobj = as_obj(d)?;
                Some(DeclarationRef {
                    revision: req_u64(dobj, "revision")?,
                    endpoint: screen_endpoint_ref(req(dobj, "endpoint")?)?,
                    expires_at: parse_ts(req(dobj, "expires_at")?)?,
                })
            }
        };
        let noninteractive = {
            let nobj = as_obj(req(obj, "noninteractive")?)?;
            let eligible = req_bool(nobj, "eligible")?;
            let reason = match opt(nobj, "reason") {
                None => None,
                Some(r) => {
                    let s = r.as_str().ok_or_else(unreadable_runner_response)?;
                    if !noninteractive_reason::ALL.contains(&s) {
                        return Err(unreadable_runner_response());
                    }
                    Some(s.to_owned())
                }
            };
            NoninteractiveEligibility { eligible, reason }
        };
        let eligibility_checked_at = parse_ts(req(obj, "eligibility_checked_at")?)?;
        let identity_selection_report = opt(obj, "identity_selection_report")
            .map(screen_selection_report)
            .transpose()?;
        let route = match opt(obj, "route") {
            None => None,
            Some(rt) => {
                let robj = as_obj(rt)?;
                let jump = DestinationId::parse(req_str(robj, "jump")?)
                    .map_err(|_| unreadable_runner_response())?;
                let jump_alias = req_str(robj, "jump_alias")?;
                if !is_alias_name(jump_alias) {
                    return Err(unreadable_runner_response());
                }
                let jump_access = parse_strict(req(robj, "jump_access")?)?;
                Some(RouteView {
                    jump,
                    jump_alias: jump_alias.to_owned(),
                    jump_access,
                })
            }
        };
        let agent_forwarding = match opt(obj, "agent_forwarding") {
            None => false,
            Some(b) => b.as_bool().ok_or_else(unreadable_runner_response)?,
        };
        out.push(PairIntegration {
            destination,
            account,
            identity,
            mechanism: mechanism.to_owned(),
            endpoint,
            alias,
            interaction,
            interaction_basis,
            declared_at,
            identity_selection,
            selection_observed_at,
            declaration,
            noninteractive,
            eligibility_checked_at,
            identity_selection_report,
            route,
            agent_forwarding,
        });
    }
    Ok(out)
}

fn screen_realization(v: &Value) -> Result<RealizationDescriptor, OpError> {
    let obj = as_obj(v)?;
    let environment_kind: EnvironmentKindView = parse_strict(req(obj, "environment_kind")?)?;
    let endpoint = match opt(obj, "endpoint") {
        None => None,
        Some(ep) => {
            let s = ep.as_str().ok_or_else(unreadable_runner_response)?;
            if !is_runner_path(s) {
                return Err(unreadable_runner_response());
            }
            Some(s.to_owned())
        }
    };
    let config = match opt(obj, "config") {
        None => None,
        Some(cfg) => {
            let s = cfg.as_str().ok_or_else(unreadable_runner_response)?;
            if !is_runner_path(s) {
                return Err(unreadable_runner_response());
            }
            Some(s.to_owned())
        }
    };
    let mount = match opt(obj, "mount") {
        None => None,
        Some(m) => {
            let mobj = as_obj(m)?;
            let source = req_str(mobj, "source")?;
            let target = req_str(mobj, "target")?;
            if !is_mount_source(source) || !is_runner_path(target) {
                return Err(unreadable_runner_response());
            }
            let read_only = req_bool(mobj, "read_only")?;
            Some(MountSpec {
                source: source.to_owned(),
                target: target.to_owned(),
                read_only,
            })
        }
    };
    let environment = match opt(obj, "environment") {
        None => Vec::new(),
        Some(e) => screen_env_pairs(e)?,
    };
    Ok(RealizationDescriptor {
        environment_kind,
        endpoint,
        config,
        mount,
        environment,
    })
}

fn screen_consumer(v: &Value) -> Result<ConsumerIntegration, OpError> {
    let obj = as_obj(v)?;
    let signing_endpoint = match opt(obj, "signing_endpoint") {
        None => None,
        Some(ep) => {
            let s = ep.as_str().ok_or_else(unreadable_runner_response)?;
            if !is_runner_path(s) {
                return Err(unreadable_runner_response());
            }
            Some(s.to_owned())
        }
    };
    let ssh_config_include = match opt(obj, "ssh_config_include") {
        None => None,
        Some(cfg) => {
            let s = cfg.as_str().ok_or_else(unreadable_runner_response)?;
            if !is_runner_path(s) {
                return Err(unreadable_runner_response());
            }
            Some(s.to_owned())
        }
    };
    let environment = match opt(obj, "environment") {
        None => Vec::new(),
        Some(e) => screen_env_pairs(e)?,
    };
    let executables = match opt(obj, "executables") {
        None => Vec::new(),
        Some(e) => screen_executables(e)?,
    };
    let overrides = match opt(obj, "overrides") {
        None => Vec::new(),
        Some(o) => screen_overrides(o)?,
    };
    let pairs = match opt(obj, "pairs") {
        None => Vec::new(),
        Some(p) => screen_pairs(p)?,
    };
    let realization = opt(obj, "realization")
        .map(screen_realization)
        .transpose()?;
    Ok(ConsumerIntegration {
        signing_endpoint,
        ssh_config_include,
        environment,
        executables,
        overrides,
        pairs,
        realization,
    })
}

/// Screen a runner's `EnsureData` success payload (forwarded or submitted `ensure`) at the
/// remote ingress. Verifies `environment_id == expected_env`, drops all unknown keys,
/// screens every field to its grammar, maps unrecognized open-enum values to their existing
/// unknown representation, and replaces `connection_policy.wording` with fixed local text.
///
/// # Errors
/// [`unreadable_runner_response`] (`OUTCOME_UNKNOWN`).
pub fn screen_ensure_data(
    raw: Value,
    expected_env: &EnvironmentId,
) -> Result<(GrantId, Value), OpError> {
    let obj = as_obj(&raw)?;
    let binding_id = screen_binding_id(req(obj, "binding_id")?)?;
    let environment_id = screen_env_id(req(obj, "environment_id")?)?;
    if environment_id != *expected_env {
        return Err(unreadable_runner_response());
    }
    let profile_revision = req_u64(obj, "profile_revision")?;
    let grant_id = screen_grant_id(req(obj, "grant_id")?)?;
    let expires_at = parse_ts(req(obj, "expires_at")?)?;
    let usable_until = parse_ts(req(obj, "usable_until")?)?;
    let offline_until = parse_ts(req(obj, "offline_until")?)?;
    let refresh_dependency: RefreshDependency = parse_strict(req(obj, "refresh_dependency")?)?;
    let credential_mechanism = req_str(obj, "credential_mechanism")?;
    if !is_reason_token(credential_mechanism) {
        return Err(unreadable_runner_response());
    }
    let enforcement = screen_enforcement(req(obj, "enforcement")?)?;
    let consumer = screen_consumer(req(obj, "consumer")?)?;
    let credential_availability = match opt(obj, "credential_availability") {
        None => CredentialAvailability::Unknown,
        Some(v) => parse_enum_or_unknown(v, CredentialAvailability::Unknown)?,
    };
    let provider = opt(obj, "provider").map(screen_provider).transpose()?;
    let lock_continuity =
        parse_opt_enum_or_unknown(obj, "lock_continuity", LockContinuityReport::NotVerified)?;
    let conditions = match opt(obj, "conditions") {
        None => Vec::new(),
        Some(list) => {
            let arr = list.as_array().ok_or_else(unreadable_runner_response)?;
            if arr.len() > MAX_CONDITIONS {
                return Err(unreadable_runner_response());
            }
            arr.iter()
                .map(parse_strict::<ReadinessCondition>)
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    let refresh_condition = match opt(obj, "refresh_condition") {
        None => None,
        Some(rc) => {
            let rc_obj = as_obj(rc)?;
            Some(RefreshCondition {
                needed_only_after: parse_strict::<RefreshTrigger>(req(
                    rc_obj,
                    "needed_only_after",
                )?)?,
                source: parse_strict::<RefreshDependency>(req(rc_obj, "source")?)?,
            })
        }
    };
    let revocation = opt(obj, "revocation").map(screen_revocation).transpose()?;
    let evidence = match opt(obj, "evidence") {
        None => Vec::new(),
        Some(e) => screen_evidence(e)?,
    };
    let connection_policy = match opt(obj, "connection_policy") {
        None => None,
        Some(cp) => {
            let cp_obj = as_obj(cp)?;
            let existing: ExistingConnectionsMode = parse_strict(req(cp_obj, "existing")?)?;
            let multiplexing: MultiplexingMode = parse_strict(req(cp_obj, "multiplexing")?)?;
            // Must be a string; genuine free text is replaced with fixed local text.
            let _ = req_str(cp_obj, "wording")?;
            Some(ConnectionPolicyReport {
                existing,
                multiplexing,
                wording: connection_policy_local_wording(existing, multiplexing),
            })
        }
    };
    let context = opt(obj, "context").map(screen_context).transpose()?;
    let uncovered = match opt(obj, "uncovered") {
        None => Vec::new(),
        Some(list) => {
            let arr = list.as_array().ok_or_else(unreadable_runner_response)?;
            if arr.len() > MAX_UNCOVERED {
                return Err(unreadable_runner_response());
            }
            arr.iter()
                .map(screen_pair_ref)
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    let residuals = opt(obj, "residuals").map(screen_residuals).transpose()?;

    let screened = EnsureData {
        binding_id,
        environment_id,
        profile_revision,
        grant_id: grant_id.clone(),
        expires_at,
        usable_until,
        offline_until,
        refresh_dependency,
        credential_mechanism: credential_mechanism.to_owned(),
        enforcement,
        consumer,
        credential_availability,
        provider,
        lock_continuity,
        conditions,
        refresh_condition,
        revocation,
        evidence,
        connection_policy,
        context,
        uncovered,
        residuals,
    };
    let json = serde_json::to_value(&screened).map_err(|_| unreadable_runner_response())?;
    Ok((grant_id, json))
}
