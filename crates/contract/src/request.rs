//! Request and response payloads of the six primitives
//! (docs/contracts/primitives-draft.md §4; spec §11.3, §4.3).
//!
//! Names are a baseline, not frozen (spec §11.1, ADR-0006 §1). Everything here is
//! data; authorization happens in `heimdall-app` on the authenticated caller
//! context, never on these fields.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::event::{Cursor, EventFilter};
use crate::ids::{
    AccountName, BindingId, DestinationId, EnvironmentId, GrantId, OperationId, PolicyId,
    ProfileId, RequestId, WorkId,
};

/// Maximum number of destination/account pairs one request may name.
pub const MAX_SCOPE_PAIRS: usize = 1024;
/// Maximum argv length accepted by `bind(launch)` (bytes, summed).
pub const MAX_ARGV_BYTES: usize = 1 << 20;

/// Deadline intent as given by the caller, kept verbatim so that a retry of
/// `--for 2h` hashes equal (spec §6.2, primitives-draft §5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DeadlineIntent {
    /// RFC 3339 timestamp with explicit offset (machine requests must be unambiguous).
    Absolute(String),
    /// ISO 8601 / friendly duration string (`PT2H`, `2h`), converted once at creation.
    Duration(String),
}

/// A destination/account pair.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct AccessPairRef {
    /// Logical destination.
    pub destination: DestinationId,
    /// Remote account.
    pub account: AccountName,
}

/// Credential capabilities a caller may request (spec §7.2).
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
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Capability {
    /// SSH user authentication.
    SshAuthentication,
    /// Git commit/tag signing (never implied by authentication; spec §7.2).
    GitSigning,
    /// Agent forwarding (explicit, disabled by default; spec §8.5).
    AgentForwarding,
}

/// Destination-scope enforcement levels (spec §4.3), ordered weakest to strongest.
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
pub enum DestinationScopeEnforcement {
    /// Not known.
    Unknown,
    /// Intent only; nothing enforces it.
    UnenforcedIntent,
    /// Client configuration routes to the destination.
    ClientRouting,
    /// Agent restriction authenticated to the destination (spec S03).
    AuthenticatedAgentRestriction,
    /// Server-side principal mapping verified by test.
    VerifiedServerPrincipals,
    /// A separately tested isolated execution boundary.
    IsolatedExecutionBoundary,
}

/// What ends new authentication at expiry (spec §4.3 "Expiry").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NewAuthenticationExpiry {
    /// Not known.
    Unknown,
    /// Only the local signer stops.
    SignerOnly,
    /// Certificate validity and the signer both stop.
    CredentialAndSigner,
    /// Nothing stops new authentication (existing fixed credentials).
    None,
}

/// Workload isolation label (spec §4.3 "Isolation"; R-SE-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIsolation {
    /// Not known.
    Unknown,
    /// Shared OS-user environment; same-user convenience only.
    SharedOsUser,
    /// Separately authenticated service boundary.
    SeparateServiceBoundary,
    /// A specifically tested isolated workload.
    TestedIsolatedWorkload,
}

/// Effect on existing connections at expiry (spec §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExistingConnectionsPolicy {
    /// Not known.
    Unknown,
    /// Dedicated connections may stay; owned masters are closed.
    GracefulDedicatedConnections,
    /// Owned connections are closed at expiry.
    StrictDisconnect,
}

/// Revocation propagation status (spec §4.3 "Revocation", §6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Not known.
    Unknown,
    /// Applied locally.
    LocalApplied,
    /// Acknowledged remotely.
    RemoteAcknowledged,
    /// Remote effect pending.
    RemotePending,
    /// Bounded only by an already-issued credential's expiry.
    BoundedByCredentialExpiry,
}

/// Structured guarantee report (spec §4.3, §11.3 `enforcement`). Every claim
/// references evidence held by the runtime; `Unknown` is a valid value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Enforcement {
    /// Destination/account restriction mechanism.
    pub destination_scope: DestinationScopeEnforcement,
    /// What stops new authentication at expiry.
    pub new_authentication_expiry: NewAuthenticationExpiry,
    /// Isolation label.
    pub workload_isolation: WorkloadIsolation,
    /// Existing-connection policy.
    pub existing_connections: ExistingConnectionsPolicy,
    /// Revocation propagation.
    pub revocation: RevocationStatus,
}

/// Minimum capability a non-interactive caller requires (spec §4.3); unmet
/// minimums yield `CAPABILITY_UNAVAILABLE`, never silently weaker access.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct RequiredCapabilities {
    /// Credential capabilities needed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub capabilities: BTreeSet<Capability>,
    /// Minimum destination-scope enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_scope_at_least: Option<DestinationScopeEnforcement>,
    /// Credentials must remain usable offline until this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_until: Option<Timestamp>,
}

/// Whether Heimdall may open prompts (spec §11.3; R-AP-06).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    /// Heimdall may present decisions on the owner channel.
    Interactive,
    /// Heimdall opens no browser, dialog, or terminal prompt.
    #[default]
    NonInteractive,
}

/// Delivery preference; not part of the idempotency hash (ADR-0006 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WaitMode {
    /// Wait up to `timeout_ms`; on timeout return the current state (timeout is
    /// not cancellation).
    Sync {
        /// Bounded wait.
        timeout_ms: u64,
    },
    /// Return `ACCEPTED` immediately with the operation to observe.
    Async,
}

impl Default for WaitMode {
    fn default() -> Self {
        WaitMode::Sync { timeout_ms: 30_000 }
    }
}

/// `inspect` subjects (primitives-draft §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InspectSubject {
    /// Capability and schema discovery (R-AP-08).
    Capabilities,
    /// Known environments.
    Environments,
    /// Profiles.
    Profiles,
    /// Destinations.
    Destinations,
    /// Bindings.
    Bindings,
    /// Grants.
    Grants,
    /// Operations.
    Operations,
    /// Pending owner decisions.
    Decisions,
}

/// `inspect` request (read-only; never contacts agents, network, or executable
/// configuration; spec §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InspectRequest {
    /// What to inspect.
    pub subject: InspectSubject,
    /// Dry-run authority preview: resolved snapshot plus authority delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<EnsurePreview>,
}

/// Preview parameters for `inspect --preview` (no side effects).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnsurePreview {
    /// Profile to resolve.
    pub profile: ProfileId,
    /// Environment, default the caller's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentId>,
    /// Deadline intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DeadlineIntent>,
    /// Minimum capabilities.
    #[serde(default)]
    pub required_capabilities: RequiredCapabilities,
}

/// `ensure` request (spec §11.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnsureRequest {
    /// Profile, or a subset of it via `scope`.
    pub profile: ProfileId,
    /// Explicit profile revision; default latest at creation (pinned afterwards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_revision: Option<u64>,
    /// Optional subset of the profile's destination/account pairs.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub scope: BTreeSet<AccessPairRef>,
    /// Environment, default the caller's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentId>,
    /// Work ID (spec §6.1).
    pub work_id: WorkId,
    /// Deadline intent; default the policy's saved window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DeadlineIntent>,
    /// Minimum capabilities.
    #[serde(default)]
    pub required_capabilities: RequiredCapabilities,
    /// Idempotency request ID.
    pub request_id: RequestId,
    /// Interaction mode.
    #[serde(default)]
    pub interaction: InteractionMode,
    /// Wait mode.
    #[serde(default)]
    pub wait: WaitMode,
}

/// `ensure`/`bind` success payload (spec §11.3 example, primitives-draft §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnsureData {
    /// Binding produced or reused.
    pub binding_id: BindingId,
    /// Environment the binding is pinned to.
    pub environment_id: EnvironmentId,
    /// Profile revision pinned at activation.
    pub profile_revision: u64,
    /// Grant realizing the binding.
    pub grant_id: GrantId,
    /// Immutable grant deadline.
    pub expires_at: Timestamp,
    /// Credentials usable without refresh until.
    pub usable_until: Timestamp,
    /// Usable with no controller/issuer contact until.
    pub offline_until: Timestamp,
    /// What ongoing readiness depends on.
    pub refresh_dependency: RefreshDependency,
    /// Mechanism name (`managed_certificate`, `native_agent`, `external_signer`, ...).
    pub credential_mechanism: String,
    /// Structured guarantees.
    pub enforcement: Enforcement,
    /// Consumer integration descriptor; contains endpoints and config references,
    /// never secrets.
    pub consumer: ConsumerIntegration,
}

/// Dependency of continued readiness (spec §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefreshDependency {
    /// No refresh needed before `expires_at`.
    None,
    /// Needs the local issuer.
    LocalIssuer,
    /// Needs the controller device.
    Controller,
    /// Needs provider interaction.
    ProviderInteraction,
}

/// How a consumer reaches the binding (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsumerIntegration {
    /// Signing endpoint path or pipe name, if one is materialized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_endpoint: Option<String>,
    /// Generated OpenSSH include path, if one is materialized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_config_include: Option<String>,
    /// Environment variables a launcher should set (names and values; never secrets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment: Vec<(String, String)>,
}

/// `bind` forms (primitives-draft §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum BindForm {
    /// Launch `argv` without a shell under the binding (spec §10.4). The runtime
    /// never launches; the CLI does, after `ensure` returns the integration.
    Launch {
        /// Argument vector, bounded by [`MAX_ARGV_BYTES`]. Non-UTF-8 arguments are
        /// carried by the CLI process, not over IPC.
        argv: Vec<String>,
    },
    /// Produce a bound consumer configuration for a consumer Heimdall cannot launch.
    Materialize,
}

/// `bind` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BindRequest {
    /// Binding to attach to.
    pub binding_id: BindingId,
    /// Form.
    pub form: BindForm,
    /// Idempotency request ID.
    pub request_id: RequestId,
}

/// `delegate` request (primitives-draft §4.4; spec §6.7, §8.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DelegateRequest {
    /// Parent binding.
    pub parent_binding_id: BindingId,
    /// Scope subset (must be within the parent).
    pub scope: BTreeSet<AccessPairRef>,
    /// Deadline intent (effective deadline must not exceed the parent's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DeadlineIntent>,
    /// Work ID of the child.
    pub work_id: WorkId,
    /// Idempotency request ID.
    pub request_id: RequestId,
    /// Minimum enforcement the child requires.
    #[serde(default)]
    pub required_capabilities: RequiredCapabilities,
}

/// `observe` request (primitives-draft §4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObserveRequest {
    /// Get an operation, optionally waiting (timeout is not cancel).
    Operation {
        /// Operation ID.
        operation_id: OperationId,
        /// Bounded wait for a terminal state.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wait_ms: Option<u64>,
    },
    /// Fetch events after a cursor (or a snapshot when no cursor is given).
    Events {
        /// Resume point.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<Cursor>,
        /// Filter.
        #[serde(default)]
        filter: EventFilter,
        /// Maximum events to return (bounded by the runtime).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
    },
}

/// `cancel` request (spec §11.4: explicit, idempotent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CancelRequest {
    /// Operation to cancel.
    pub operation_id: OperationId,
}

/// `release` request (drops this consumer's reference; primitives-draft §4.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReleaseRequest {
    /// Binding reference to release.
    pub binding_id: BindingId,
}

/// `revoke` request (spec §6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevokeRequest {
    /// Grant to revoke; descendants cascade.
    pub grant_id: GrantId,
    /// Idempotency request ID.
    pub request_id: RequestId,
}

/// `revoke` result (spec §6.7 `local_applied`, `remote_pending`,
/// `latest_possible_credential_expiry`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevokeData {
    /// Local denial persisted before acknowledgment.
    pub local_applied: bool,
    /// Grants (self and descendants) whose remote effects are pending.
    pub remote_pending: Vec<GrantId>,
    /// Latest instant an already-issued credential could still be accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_possible_credential_expiry: Option<Timestamp>,
}

/// Owner-channel policy actions (primitives-draft §4.6; spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PolicyAction {
    /// Pause future automatic activation.
    Pause {
        /// Policy.
        policy_id: PolicyId,
    },
    /// Resume automatic activation.
    Resume {
        /// Policy.
        policy_id: PolicyId,
    },
    /// Schedule a hard cutoff (RFC 3339 with offset).
    Cutoff {
        /// Policy.
        policy_id: PolicyId,
        /// Instant after which no new work activates until cleared.
        at: Timestamp,
    },
    /// Clear a cutoff deliberately.
    ClearCutoff {
        /// Policy.
        policy_id: PolicyId,
    },
}

/// A request sent over the control endpoint. The variant is the operation kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Request {
    /// Read-only inspection.
    Inspect(InspectRequest),
    /// Idempotent access preparation.
    Ensure(EnsureRequest),
    /// Attach a running context.
    Bind(BindRequest),
    /// Narrower child binding.
    Delegate(DelegateRequest),
    /// Status, events, resumption.
    Observe(ObserveRequest),
    /// Explicit cancellation.
    Cancel(CancelRequest),
    /// Drop a consumer reference.
    Release(ReleaseRequest),
    /// Revoke a grant and descendants.
    Revoke(RevokeRequest),
    /// Owner-channel policy action.
    Policy(PolicyAction),
}

impl Request {
    /// Stable operation-kind name used in the idempotency key (spec §11.4).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Request::Inspect(_) => "inspect",
            Request::Ensure(_) => "ensure",
            Request::Bind(_) => "bind",
            Request::Delegate(_) => "delegate",
            Request::Observe(_) => "observe",
            Request::Cancel(_) => "cancel",
            Request::Release(_) => "release",
            Request::Revoke(_) => "revoke",
            Request::Policy(_) => "policy",
        }
    }

    /// Whether the request can have external effects (and therefore gets an
    /// operation ID and journal entry).
    #[must_use]
    pub fn is_effectful(&self) -> bool {
        !matches!(self, Request::Inspect(_) | Request::Observe(_))
    }
}
