//! ⟨M03⟩ Managed-credential report and control types (ADR-0006 revision 4; m03-plan
//! §5 items 4, 4a, 4b, 5–9 and 13; ADR-0008 D7, D8, D9, D12).
//!
//! Everything here is additive on the wire. Fields added to M01/M02 documents
//! (`EnsureData`, `Enforcement`, `RevokeData`, `EnsureRequest`) are optional and
//! omitted when absent, so every M01/M02 document decodes and re-encodes unchanged
//! and every M01/M02 request hash is unchanged. Every new enum is
//! `#[non_exhaustive]` and `snake_case`.
//!
//! No type here carries a secret, a PID or a socket path that is not already public
//! (ADR-0008 D2 item 2: endpoint paths are references, never secrets).

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{
    AccountName, BindingId, ConnectionId, DestinationId, EnrollmentId, GrantId, OperationId,
};
use crate::request::{AccessPairRef, RefreshDependency};

// --- policies: lock behaviour and connection policy (§5 items 5, 6; D8 item 1, D9) ---

/// What a desktop/session lock does to a grant (ADR-0008 D9; spec §6.4). The default
/// is `continue`; `revoke_on_lock` is narrowing, `continue` is widening (§5 item 6).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
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
pub enum LockBehavior {
    /// A lock does not end managed grants (the default, spec §6.4).
    #[default]
    Continue,
    /// A lock revokes the grant (cause `session_locked`).
    RevokeOnLock,
}

/// What happens to owned dedicated connections at the admission deadline (ADR-0008
/// D8 item 1). `strict` is narrowing; `graceful` (the default) is widening.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
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
pub enum ExistingConnectionsMode {
    /// Existing dedicated sessions may stay connected (spec §6.6 default).
    #[default]
    Graceful,
    /// Owned connections are closed at the deadline.
    Strict,
}

/// Owned multiplex masters (ADR-0008 D8 item 3). `disabled` is the default and
/// narrowing; `owned_masters` is widening.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
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
pub enum MultiplexingMode {
    /// No master; P renders `ControlPath none`.
    #[default]
    Disabled,
    /// The supervisor runs one owned master per pair slot.
    OwnedMasters,
}

/// A connection policy (ADR-0008 D8 item 1). The default is `graceful`, `disabled`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ConnectionPolicy {
    /// Existing dedicated connections at the deadline.
    #[serde(default)]
    pub existing: ExistingConnectionsMode,
    /// Owned multiplexing.
    #[serde(default)]
    pub multiplexing: MultiplexingMode,
}

impl ConnectionPolicy {
    /// Whether this is the default policy (`graceful`, `disabled`).
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// `EnsureRequest.connection` (§5 item 5): a request may only **narrow** `existing`
/// to `strict`; `graceful` in a request is `USAGE_ERROR` (checked by the
/// application). It enters the canonical hash only when present.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ConnectionRequest {
    /// The requested existing-connections mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing: Option<ExistingConnectionsMode>,
}

// --- EnsureData additions (§5 item 7; ADR-0008 D12) ---------------------------------

/// Whether credentials survive a desktop lock (`lock_continuity`; R-UX-03). Reads
/// `not_verified` when absent: only a claim-table entry makes it `verified`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LockContinuityReport {
    /// A verified claim-table entry covers this platform and store.
    Verified,
    /// Not verified (the default).
    #[default]
    NotVerified,
    /// The grant's lock behaviour is `revoke_on_lock`.
    LockRevokes,
}

/// A condition the result's readiness depends on (§5 item 7; F03, F14).
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
pub enum ReadinessCondition {
    /// The in-process signer must be running.
    SignerRunning,
    /// After a reboot an attended time confirmation is needed.
    TimeConfirmationAfterReboot,
    /// The issuer store must be unlocked at start (macOS keychain).
    IssuerStoreUnlockedAtStart,
}

/// What would trigger a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RefreshTrigger {
    /// Only a signer restart (the K_env is lost) needs a re-issue.
    SignerRestart,
}

/// `refresh_condition` (§5 item 7): `{needed_only_after: signer_restart, source:
/// local_issuer}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RefreshCondition {
    /// When a refresh is needed.
    pub needed_only_after: RefreshTrigger,
    /// What the refresh depends on.
    pub source: RefreshDependency,
}

/// The local part of revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LocalRevocation {
    /// Local denial is immediate.
    Immediate,
}

/// The remote part of revocation (`revocation.remote`), gated by the claim table
/// exactly like `enforcement.revocation`: `unknown` until a claim exists (F11).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteRevocation {
    /// Bounded by the issued certificates' expiry.
    BoundedByCredentialExpiry,
    /// No remote credential exists.
    NotApplicable,
    /// Trust may remain until the registry line is removed.
    PendingUntilLineRemoved,
    /// No bound is known (a key-only restore, ADR-0008 D4 item 4).
    UnboundedUnknown,
    /// Not known (the default).
    #[default]
    Unknown,
}

/// A destination clock measurement (ADR-0008 D5 §6.5 item 4): the destination's
/// clock lags local time by at most `behind_upper_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClockMeasurement {
    /// Upper bound of the destination clock's lag, in milliseconds.
    pub behind_upper_ms: u64,
    /// Round trip of the measurement, in milliseconds.
    pub rtt_ms: u64,
    /// When measured (local wall time).
    pub measured_at: Timestamp,
}

/// A pair's destination clock (ADR-0008 D7 item 3). Wire forms:
/// `{"measured":{…}}` or `"unmeasured"`. Per pair the weakest is shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(transform = open_tagged_object)]
#[non_exhaustive]
pub enum DestinationClock {
    /// A fresh measurement exists.
    Measured(ClockMeasurement),
    /// No (fresh) measurement.
    #[default]
    Unmeasured,
}

/// Deserialization is hand-written so a reader tolerates unknown sibling keys next to
/// `measured` (ADR-0006 §9, spec §11.2): serde's externally tagged form refuses an
/// object with more than one key. An unknown variant is still refused, as for every
/// other contract enum.
impl<'de> Deserialize<'de> for DestinationClock {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) if s == "unmeasured" => Ok(Self::Unmeasured),
            serde_json::Value::Object(mut map) => match map.remove("measured") {
                Some(inner) => serde_json::from_value(inner)
                    .map(Self::Measured)
                    .map_err(D::Error::custom),
                None => Err(D::Error::custom(
                    "destination_clock: expected \"unmeasured\" or {\"measured\": {…}}",
                )),
            },
            _ => Err(D::Error::custom(
                "destination_clock: expected \"unmeasured\" or {\"measured\": {…}}",
            )),
        }
    }
}

/// The `{"measured": {…}}` alternative is an externally tagged object; readers
/// tolerate unknown fields (ADR-0006 §9), so the schema does not close it
/// (`additionalProperties` is outside the contract's schema keyword set).
fn open_tagged_object(schema: &mut schemars::Schema) {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                map.remove("additionalProperties");
                map.values_mut().for_each(strip);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    if let Some(obj) = schema.as_object_mut() {
        obj.values_mut().for_each(strip);
    }
}

/// `EnsureData.revocation` (§5 item 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevocationSemantics {
    /// Local part.
    pub local: LocalRevocation,
    /// Remote part (claim-gated).
    pub remote: RemoteRevocation,
    /// Latest instant an issued credential could be accepted; absent = unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_possible_credential_expiry: Option<Timestamp>,
    /// The weakest destination clock of the grant's pairs.
    pub destination_clock: DestinationClock,
}

/// Where an evidence entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceSource {
    /// This pair's own runtime verification (ADR-0008 §17.1 item 13).
    RuntimeVerification,
    /// A claim-table entry (ADR-0008 D12).
    ClaimTable,
}

/// One piece of evidence behind a reported value (§5 item 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceEntry {
    /// The reported field (`destination_scope`, `lock_continuity`, …).
    pub field: String,
    /// Source.
    pub source: EvidenceSource,
    /// The pair, for runtime verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<AccessPairRef>,
    /// The claim-table record path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// The verifying operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Client version line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Server version line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// When observed.
    pub observed_at: Timestamp,
    /// Fresh until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_until: Option<Timestamp>,
}

/// `EnsureData.connection_policy` (§5 item 7; ADR-0008 D8 item 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectionPolicyReport {
    /// Effective existing-connections mode.
    pub existing: ExistingConnectionsMode,
    /// Effective multiplexing.
    pub multiplexing: MultiplexingMode,
    /// The exact D8 disclosure sentence(s): human text, not a code.
    pub wording: String,
}

// --- Enforcement additions (§5 item 8). Each reads `unknown` when absent. ---------

/// `enforcement.identity_selection`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentitySelectionEnforcement {
    /// Exclusive client configuration plus signer filtering (runtime evidence).
    ClientConfigurationAndSigner,
    /// Only the signer filters.
    SignerFiltering,
    /// Only the client configuration selects.
    ClientConfiguration,
    /// Not known.
    #[default]
    Unknown,
}

/// `enforcement.new_signing_expiry` (claim-gated).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NewSigningExpiry {
    /// The signer stops signing at the deadline.
    Signer,
    /// No signer is involved.
    NotApplicable,
    /// Not known.
    #[default]
    Unknown,
}

/// `enforcement.owned_multiplexing`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OwnedMultiplexing {
    /// Masters disabled.
    Disabled,
    /// Owned masters are closed at the deadline (claim-gated).
    ClosedAtDeadline,
    /// Not available on this platform (Windows).
    Unavailable,
    /// Not known.
    #[default]
    Unknown,
}

/// `enforcement.remote_processes`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteProcesses {
    /// Remote processes are never claimed to stop (ADR-0008 D8 item 5).
    NotTerminated,
    /// Not known.
    #[default]
    Unknown,
}

/// `enforcement.unmanaged_connections`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnmanagedConnections {
    /// Connections Heimdall did not start are not controlled.
    NotControlled,
    /// Not known.
    #[default]
    Unknown,
}

/// `enforcement.issuer_isolation` and `IssuerStatus.issuer_isolation`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuerIsolation {
    /// The issuer is a same-user child process.
    SameUserProcess,
    /// No issuer is involved.
    NotApplicable,
    /// Not known.
    #[default]
    Unknown,
}

// --- RevokeData additions (§5 item 9; ADR-0008 D7 items 2–3) ------------------------

/// A remote residual's status (ADR-0008 D7 item 3; §17.1 item 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResidualStatus {
    /// Before the completion bound (or, unmeasured, before `latest_valid_before`).
    PendingUntil,
    /// Measured, and the bound passed on safe time: closed.
    BoundedComplete,
    /// Unmeasured, and `latest_valid_before` passed on safe time. Never shown as
    /// cleared.
    NominallyExpired,
    /// No bound exists (a key-only restore).
    UnboundedUnknown,
}

/// One (destination, account) residual of a revoke (§5 item 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteEffectReport {
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// The latest `valid_before` of a reserved or published entry for the pair.
    pub latest_valid_before: Timestamp,
    /// The pair's clock measurement.
    pub destination_clock: DestinationClock,
    /// Status.
    pub status: ResidualStatus,
    /// The completion bound, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
}

/// An owned connection's kind (ADR-0008 D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionKind {
    /// An owned multiplex master.
    Master,
    /// An owned dedicated connection (`connect`, `run ssh`).
    Dedicated,
}

/// An owned connection's state in a revoke result (F15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OwnedConnectionReportState {
    /// Being closed.
    Closing,
    /// Closed.
    Closed,
    /// Its identity could not be verified; never signalled, treated as unmanaged.
    Unverified,
}

/// One owned connection of a revoke's cascade (§5 item 9; F15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnedConnectionReport {
    /// Connection ID.
    pub id: ConnectionId,
    /// Kind.
    pub kind: ConnectionKind,
    /// State.
    pub state: OwnedConnectionReportState,
}

/// A fixed note in a revoke result (F15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevokeNote {
    /// Connections ordinary `ssh` opened through P, and unmanaged ones, are not
    /// closed (always present for a managed revoke).
    OrdinaryConnectionsNotClosed,
}

// --- connections (§5 items 4, 4a) -----------------------------------------------------

/// `Request::Connections` (capability `connections/1`). Both actions are
/// synchronous, effectful, and accepted from the owner role only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionsRequest {
    /// Close one owned connection (narrowing; no decision). kind
    /// `"connections.close"`.
    Close {
        /// The connection.
        connection_id: ConnectionId,
    },
    /// The Windows launcher's durable registration of the contained, still
    /// suspended `ssh.exe` (ADR-0008 D8 item 2). kind `"connections.register"`.
    Register {
        /// The launch binding.
        binding_id: BindingId,
        /// The child's PID.
        pid: u32,
        /// The child's creation time.
        created_at: Timestamp,
        /// The child's image path (ADR-0008 D8 item 2, revision 3); the runtime
        /// checks it is the verified client.
        image: String,
    },
}

impl ConnectionsRequest {
    /// The request kind (`connections.close`, `connections.register`).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            ConnectionsRequest::Close { .. } => "connections.close",
            ConnectionsRequest::Register { .. } => "connections.register",
        }
    }
}

/// An owned connection's live state in `inspect connections`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionState {
    /// Running.
    Up,
    /// Being closed.
    Closing,
}

/// One `owned_connections` row in `inspect connections` (§5 item 4). PIDs are not
/// exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectionEntry {
    /// Connection ID.
    pub id: ConnectionId,
    /// Kind.
    pub kind: ConnectionKind,
    /// Binding.
    pub binding_id: BindingId,
    /// Grant.
    pub grant_id: GrantId,
    /// Destination.
    pub destination_id: DestinationId,
    /// Started.
    pub started_at: Timestamp,
    /// Effective policy.
    pub policy: ConnectionPolicy,
    /// When it will be closed, or `null`.
    pub closes_at: Option<Timestamp>,
    /// State.
    pub state: ConnectionState,
}

/// `inspect connections` data (§5 item 4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectionsView {
    /// One entry per owned connection.
    pub connections: Vec<ConnectionEntry>,
}

// --- catalog preference (§5 item 4b) --------------------------------------------------

/// The pair mechanism a `SetPreference` catalog action selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreferredMechanism {
    /// Managed certificates (needs a verified enrollment: `pair_not_enrolled`).
    ManagedCertificate,
    /// The adopted existing identity.
    Existing,
}

// --- events (§5 item 13) --------------------------------------------------------------

/// `CredentialLifecycle` payload `event` values: M01's, plus M03's `installed`,
/// `destroyed`, `lost` and `reissued`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialLifecycleEvent {
    /// An issuance entry was reserved.
    Reserved,
    /// An issuance entry was published.
    Published,
    /// An issuance entry was voided.
    Voided,
    /// The grant expired (M01).
    Expired,
    /// The grant was revoked locally (M01).
    RevokedLocally,
    /// The grant's authority was withdrawn (M01).
    AuthorityWithdrawn,
    /// A credential instance was installed in the signer.
    Installed,
    /// A credential instance's key was destroyed.
    Destroyed,
    /// A credential instance was lost (no vault slot at restart).
    Lost,
    /// A credential was re-issued.
    Reissued,
}

/// The `Enrollment` event payload: `{enrollment_id, state, operation_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnrollmentEventPayload {
    /// Enrollment.
    pub enrollment_id: EnrollmentId,
    /// New state.
    pub state: crate::enrollment::EnrollmentState,
    /// The operation that moved it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
}

/// Whether a connection started or closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionEventKind {
    /// Started (or registered).
    Started,
    /// Closed.
    Closed,
}

/// Why an owned connection was closed (ADR-0008 D8 item 2 table and item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CloseReason {
    /// The admission deadline passed.
    AdmissionDeadline,
    /// A cutoff passed.
    Cutoff,
    /// The grant was revoked.
    Revocation,
    /// `revoke_on_lock` after a session lock.
    SessionLocked,
    /// The last reference was released.
    Release,
    /// Time became uncertain.
    TimeUncertain,
    /// The owner asked (`Connections::Close`).
    OwnerRequest,
    /// The process exited by itself.
    ProcessExited,
    /// The slot passed to another binding (masters).
    SlotReplaced,
}

/// The `Connection` event payload: `{connection_id, kind, event, reason}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectionEventPayload {
    /// Connection.
    pub connection_id: ConnectionId,
    /// Kind.
    pub kind: ConnectionKind,
    /// Started or closed.
    pub event: ConnectionEventKind,
    /// Why closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<CloseReason>,
}

/// The session-lock source's state (ADR-0008 D9; `SessionLockSource::state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SessionLockState {
    /// The session is unlocked.
    Unlocked,
    /// The session is locked.
    Locked,
    /// The source cannot tell.
    Unknown,
    /// No lock source on this platform or session.
    Unavailable,
}

/// The `SessionLock` event payload: `{state, revoked: [grant_id]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SessionLockEventPayload {
    /// The observed state.
    pub state: SessionLockState,
    /// Grants revoked because of it.
    #[serde(default)]
    pub revoked: Vec<GrantId>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn destination_clock_wire_forms() {
        let m = DestinationClock::Measured(ClockMeasurement {
            behind_upper_ms: 1400,
            rtt_ms: 38,
            measured_at: "2026-11-10T13:50:00Z".parse().unwrap(),
        });
        assert_eq!(
            serde_json::to_value(m).unwrap(),
            serde_json::json!({"measured": {"behind_upper_ms": 1400, "rtt_ms": 38,
                "measured_at": "2026-11-10T13:50:00Z"}})
        );
        assert_eq!(
            serde_json::to_value(DestinationClock::Unmeasured).unwrap(),
            serde_json::json!("unmeasured")
        );
    }

    #[test]
    fn connection_policy_defaults_graceful_disabled() {
        let p: ConnectionPolicy = serde_json::from_str("{}").unwrap();
        assert!(p.is_default());
        assert_eq!(
            serde_json::to_value(p).unwrap(),
            serde_json::json!({"existing": "graceful", "multiplexing": "disabled"})
        );
        assert_eq!(LockBehavior::default(), LockBehavior::Continue);
    }
}
