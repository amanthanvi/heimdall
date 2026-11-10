//! Request and response payloads of the six primitives
//! (docs/contracts/primitives-draft.md §4; spec §11.3, §4.3).
//!
//! Names are a baseline, not frozen (spec §11.1, ADR-0006 §1). Everything here is
//! data; authorization happens in `heimdall-app` on the authenticated caller
//! context, never on these fields.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::catalog::CatalogRequest;
use crate::doctor::{ConfigProvenance, GitScope};
use crate::enrollment::EnrollmentRequest;
use crate::event::{Cursor, EventFilter};
use crate::ids::{
    AccountName, BindingId, DestinationId, EnvironmentId, GrantId, IdentityId, OperationId,
    PolicyId, ProfileId, RequestId, WorkId,
};
use crate::issuer::IssuerRequest;
use crate::managed::{
    ConnectionRequest, ConnectionsRequest, ExistingConnectionsMode, IdentitySelectionEnforcement,
    IssuerIsolation, LockBehavior, LockContinuityReport, MultiplexingMode, NewSigningExpiry,
    OwnedConnectionReport, OwnedMultiplexing, ReadinessCondition, RefreshCondition,
    RemoteEffectReport, RemoteProcesses, RevocationSemantics, RevokeNote, UnmanagedConnections,
};
use crate::provider::{
    CredentialAvailability, DeclarationRef, EndpointRef, EvidenceBasis, IdentitySelection,
    IdentitySelectionReport, InteractionKind, NoninteractiveEligibility, ProviderStatus,
};
use crate::setup::SetupRequest;

/// Maximum number of destination/account pairs one request may name.
pub const MAX_SCOPE_PAIRS: usize = 1024;
/// Maximum size of `bind(launch)`'s resolved executable path, in bytes. (M02 Q8:
/// `argv` no longer crosses IPC, so its old bound left the contract for
/// `heimdall-launch`.)
pub const MAX_EXECUTABLE_BYTES: usize = 4096;
/// Maximum size of a holder process's opaque start-time token, in bytes.
pub const MAX_STARTED_AT_BYTES: usize = 64;

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
    /// ⟨M03⟩ A `run` of a program other than the verified `ssh`: its connections
    /// are not owned, so nothing closes them (ADR-0008 D8 item 2).
    NotControlled,
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
    /// ⟨M03⟩ How identities are selected (§5 item 8). Omitted when absent, so every
    /// M01/M02 report (and every grant record that stores one) is unchanged; reads
    /// `unknown` when absent ([`Self::identity_selection`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_selection: Option<IdentitySelectionEnforcement>,
    /// ⟨M03⟩ What stops new signatures at expiry (claim-gated); `unknown` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_signing_expiry: Option<NewSigningExpiry>,
    /// ⟨M03⟩ Owned multiplexing; `unknown` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_multiplexing: Option<OwnedMultiplexing>,
    /// ⟨M03⟩ Remote processes; `unknown` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_processes: Option<RemoteProcesses>,
    /// ⟨M03⟩ Unmanaged connections; `unknown` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmanaged_connections: Option<UnmanagedConnections>,
    /// ⟨M03⟩ The issuer boundary; `unknown` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_isolation: Option<IssuerIsolation>,
}

impl Enforcement {
    /// An M01/M02-shaped report: the five original fields, every M03 field absent.
    #[must_use]
    pub fn new(
        destination_scope: DestinationScopeEnforcement,
        new_authentication_expiry: NewAuthenticationExpiry,
        workload_isolation: WorkloadIsolation,
        existing_connections: ExistingConnectionsPolicy,
        revocation: RevocationStatus,
    ) -> Self {
        Self {
            destination_scope,
            new_authentication_expiry,
            workload_isolation,
            existing_connections,
            revocation,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
        }
    }

    /// `identity_selection`, `unknown` when absent.
    #[must_use]
    pub fn identity_selection(&self) -> IdentitySelectionEnforcement {
        self.identity_selection.unwrap_or_default()
    }

    /// `new_signing_expiry`, `unknown` when absent.
    #[must_use]
    pub fn new_signing_expiry(&self) -> NewSigningExpiry {
        self.new_signing_expiry.unwrap_or_default()
    }

    /// `owned_multiplexing`, `unknown` when absent.
    #[must_use]
    pub fn owned_multiplexing(&self) -> OwnedMultiplexing {
        self.owned_multiplexing.unwrap_or_default()
    }

    /// `remote_processes`, `unknown` when absent.
    #[must_use]
    pub fn remote_processes(&self) -> RemoteProcesses {
        self.remote_processes.unwrap_or_default()
    }

    /// `unmanaged_connections`, `unknown` when absent.
    #[must_use]
    pub fn unmanaged_connections(&self) -> UnmanagedConnections {
        self.unmanaged_connections.unwrap_or_default()
    }

    /// `issuer_isolation`, `unknown` when absent.
    #[must_use]
    pub fn issuer_isolation(&self) -> IssuerIsolation {
        self.issuer_isolation.unwrap_or_default()
    }
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
    /// New authentications must need no human interaction until the deadline,
    /// including through desktop and vault lock (m02-plan §5 item 6). `unknown`
    /// never satisfies it. Omitted when false, so M01 request hashes are unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unattended: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
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
    /// Catalog identities with fresh eligibility and each live declaration's
    /// reference (M02).
    Identities,
    /// Projection resources, read-only (M02).
    Projections,
    /// ⟨M03⟩ Enrollment records (`EnrollmentsView`).
    Enrollments,
    /// ⟨M03⟩ The issuer status (`IssuerStatus`).
    Issuer,
    /// ⟨M03⟩ Owned connections (`ConnectionsView`).
    Connections,
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
    /// ⟨M03⟩ Narrow the existing-connections mode to `strict` (§5 item 5). Enters
    /// the canonical hash only when present, so M01/M02 hashes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionRequest>,
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
    /// Credential availability (spec §4.3), computed fresh for every result. Always
    /// written; a document that omits it reads as `unknown`.
    #[serde(default)]
    pub credential_availability: CredentialAvailability,
    /// The provider's observed state, for existing-access mechanisms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderStatus>,
    /// ⟨M03⟩ Lock continuity (§5 item 7). Omitted when absent, so every M02 result
    /// is unchanged; reads `not_verified` when absent ([`Self::lock_continuity`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_continuity: Option<LockContinuityReport>,
    /// ⟨M03⟩ Conditions readiness depends on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<ReadinessCondition>,
    /// ⟨M03⟩ When a refresh is needed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_condition: Option<RefreshCondition>,
    /// ⟨M03⟩ Revocation semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationSemantics>,
    /// ⟨M03⟩ Evidence behind reported values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::managed::EvidenceEntry>,
    /// ⟨M03⟩ The effective connection policy and its wording.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_policy: Option<crate::managed::ConnectionPolicyReport>,
}

impl EnsureData {
    /// `lock_continuity`, `not_verified` when absent.
    #[must_use]
    pub fn lock_continuity(&self) -> LockContinuityReport {
        self.lock_continuity.unwrap_or_default()
    }
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// Client executables the integration relies on (R-SS-03).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executables: Vec<ConsumerExecutable>,
    /// Consumer settings another source keeps in force.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<ConsumerOverride>,
    /// One entry per destination/account pair of the grant (ADR-0007 §7).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pairs: Vec<PairIntegration>,
}

/// A consumer program.
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
pub enum ConsumerKind {
    /// `ssh`.
    Ssh,
    /// `scp`.
    Scp,
    /// `sftp`.
    Sftp,
    /// `git`.
    Git,
    /// `ssh-keygen`.
    SshKeygen,
}

/// A client executable an integration relies on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsumerExecutable {
    /// Which consumer.
    pub consumer: ConsumerKind,
    /// Absolute path.
    pub path: String,
    /// Reported version, when a local query ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SHA-256, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// How it was established.
    pub basis: EvidenceBasis,
}

/// Where an overriding consumer setting comes from (tagged by `kind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OverrideSource {
    /// An OpenSSH configuration directive (for example an effective
    /// `IdentityAgent`).
    SshConfig(ConfigProvenance),
    /// A Git configuration scope.
    GitScope {
        /// The scope.
        scope: GitScope,
    },
    /// The process environment.
    Environment,
}

/// A consumer setting another source keeps in force (ADR-0007 §8 "Git under
/// `run`"). Names the setting, never its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsumerOverride {
    /// Which consumer.
    pub consumer: ConsumerKind,
    /// The setting (`core.sshCommand`, `GIT_SSH_COMMAND`, `GIT_SSH`,
    /// `IdentityAgent`, `SSH_AUTH_SOCK`).
    pub setting: String,
    /// Where it comes from.
    pub source: OverrideSource,
}

/// One destination/account pair's integration (ADR-0007 §7). `endpoint`, `alias`,
/// `mechanism`, `identity_selection` and `selection_observed_at` are history
/// (prepared facts); the interaction and eligibility fields are computed fresh in
/// the transaction that builds each result (M2-R04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PairIntegration {
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// The adopted identity.
    pub identity: IdentityId,
    /// Mechanism (`native_agent`, `onepassword`).
    pub mechanism: String,
    /// The agent endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointRef>,
    /// The managed alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Fresh interaction.
    pub interaction: InteractionKind,
    /// How the interaction was established.
    pub interaction_basis: EvidenceBasis,
    /// When the owner declared it (`basis: declared` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_at: Option<Timestamp>,
    /// The recorded identity selection.
    pub identity_selection: IdentitySelection,
    /// When the selection was observed.
    pub selection_observed_at: Timestamp,
    /// The live declaration the eligibility relied on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<DeclarationRef>,
    /// Fresh non-interactive eligibility.
    pub noninteractive: NoninteractiveEligibility,
    /// When the eligibility was computed.
    pub eligibility_checked_at: Timestamp,
    /// ⟨M02⟩ The full static identity selection behind `identity_selection`: its
    /// entries (each alternative's `cleared` filled by the one clearance rule) and
    /// `IdentitiesOnly` (ADR-0007 §12.14 item 6, §12.15 item 3(c)). History, like the
    /// verdict: the runtime stores it in the prepared facts. Serde default, omitted
    /// when absent, so an older document decodes with `None`; a missing report never
    /// clears a fallback (ADR-0007 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_selection_report: Option<IdentitySelectionReport>,
}

/// `bind` forms (primitives-draft §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum BindForm {
    /// Launch a program without a shell under the binding (spec §10.4). The runtime
    /// never launches; the CLI does. `argv` never crosses IPC (Q8, ADR-0007 §8):
    /// the request names the resolved executable and the holder process.
    Launch(LaunchBinding),
    /// Produce a bound consumer configuration for a consumer Heimdall cannot launch.
    Materialize,
}

/// The process holding a binding reference: its PID and an opaque OS start-time
/// token, so a reused PID never counts (ADR-0007 §8). Lifecycle metadata, never
/// authorization; excluded from the request hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProcessHolder {
    /// PID (> 0).
    pub pid: u32,
    /// Opaque OS start-time token: 1 to 64 bytes of `[A-Za-z0-9._:-]`.
    pub started_at: String,
}

/// `bind(launch)` (m02-plan §5 item 5). Wire form:
/// `{"form":"launch","executable":…,"holder":{…}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LaunchBinding {
    /// The resolved executable: absolute, 1 to 4096 bytes, no NUL. A resolved path
    /// that is not Unicode is refused locally (`LAUNCH_FAILED`, `refused_path`).
    pub executable: String,
    /// The holder process (delivery metadata; not hashed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<ProcessHolder>,
}

/// A [`LaunchBinding`] that breaks m02-plan §5 item 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchBindingError {
    /// Empty, longer than [`MAX_EXECUTABLE_BYTES`], or containing NUL.
    #[error("the executable is 1 to 4096 bytes without NUL")]
    ExecutableLength,
    /// Not an absolute path on this platform.
    #[error("the executable must be an absolute path")]
    ExecutableNotAbsolute,
    /// `holder.pid` is 0.
    #[error("the holder PID must be positive")]
    HolderPid,
    /// `holder.started_at` is empty, longer than [`MAX_STARTED_AT_BYTES`], or
    /// outside `[A-Za-z0-9._:-]`.
    #[error("the holder start time is 1 to 64 bytes of [A-Za-z0-9._:-]")]
    HolderStartedAt,
}

impl LaunchBinding {
    /// Check m02-plan §5 item 5's rules. "Absolute" is this platform's rule
    /// ([`std::path::Path::is_absolute`]); the runtime and the CLI share a machine.
    pub fn validate(&self) -> Result<(), LaunchBindingError> {
        let exe = &self.executable;
        if exe.is_empty() || exe.len() > MAX_EXECUTABLE_BYTES || exe.contains('\0') {
            return Err(LaunchBindingError::ExecutableLength);
        }
        if !std::path::Path::new(exe).is_absolute() {
            return Err(LaunchBindingError::ExecutableNotAbsolute);
        }
        if let Some(holder) = &self.holder {
            if holder.pid == 0 {
                return Err(LaunchBindingError::HolderPid);
            }
            let t = &holder.started_at;
            if t.is_empty()
                || t.len() > MAX_STARTED_AT_BYTES
                || !t
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
            {
                return Err(LaunchBindingError::HolderStartedAt);
            }
        }
        Ok(())
    }
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
    /// ⟨M03⟩ One row per (destination, account) with an unexpired entry (ADR-0008
    /// D7 items 2–3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_effects: Vec<RemoteEffectReport>,
    /// ⟨M03⟩ The cascade's owned connections (F15).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_connections: Vec<OwnedConnectionReport>,
    /// ⟨M03⟩ Fixed notes (`ordinary_connections_not_closed` for a managed revoke).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<RevokeNote>,
    /// ⟨M03⟩ The runtime's wall clock when the revoke was first admitted, before any
    /// gate wait (§5 item 9; ADR-0008 §17.10 item 3). Optional on the wire so M01/M02
    /// documents decode; M03 always fills it; a replay returns the stored value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<Timestamp>,
    /// ⟨M03⟩ Read inside the tombstone transaction; a replay returns the stored
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<Timestamp>,
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
    /// ⟨M03⟩ Set the lock behaviour (§5 item 6): `continue` is widening,
    /// `revoke_on_lock` narrowing.
    SetLockBehavior {
        /// Policy.
        policy_id: PolicyId,
        /// Behaviour.
        behavior: LockBehavior,
    },
    /// ⟨M03⟩ Set the connection policy (§5 item 6): `existing: graceful` and
    /// `multiplexing: owned_masters` are widening; the others narrowing.
    SetConnectionPolicy {
        /// Policy.
        policy_id: PolicyId,
        /// Existing connections.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        existing: Option<ExistingConnectionsMode>,
        /// Multiplexing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        multiplexing: Option<MultiplexingMode>,
    },
}

impl PolicyAction {
    /// Whether this action widens authority and so needs a `WidenPolicy` decision
    /// (ADR-0006 §3.1; m03-plan §5 item 6): `resume`, `clear_cutoff`,
    /// `set_lock_behavior{continue}`, and `set_connection_policy` with `existing:
    /// graceful` or `multiplexing: owned_masters`. Looks only at the request, not at
    /// the stored policy.
    #[must_use]
    pub fn is_widening(&self) -> bool {
        match self {
            PolicyAction::Resume { .. } | PolicyAction::ClearCutoff { .. } => true,
            PolicyAction::Pause { .. } | PolicyAction::Cutoff { .. } => false,
            PolicyAction::SetLockBehavior { behavior, .. } => *behavior == LockBehavior::Continue,
            PolicyAction::SetConnectionPolicy {
                existing,
                multiplexing,
                ..
            } => {
                *existing == Some(ExistingConnectionsMode::Graceful)
                    || *multiplexing == Some(MultiplexingMode::OwnedMasters)
            }
        }
    }
}

/// Verdict on a server-issued decision record (ADR-0006 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Grant exactly the recorded delta / action.
    Approve,
    /// Refuse it.
    Deny,
}

/// Complete a pending decision (approval of added authority, a widening policy
/// action, or a time confirmation). Only accepted on an **attended** control
/// session; refused with `INTERACTION_REQUIRED` otherwise, and with
/// `DECISION_STALE` when the record was consumed, expired, or issued under an older
/// authority generation (ADR-0006 §3.1). Consume-once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecideRequest {
    /// Decision record to complete.
    pub decision_id: crate::ids::DecisionId,
    /// Verdict.
    pub verdict: Verdict,
}

/// Attended owner confirmation of the current wall time to resolve
/// `TIME_UNCERTAIN` after a reboot or sync loss (ADR-0005 §3.6). Never moves a
/// deadline; never rebuilds a budget. Attended sessions only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfirmTimeRequest {
    /// The wall time the owner confirms as correct now (RFC 3339 with offset). It
    /// must agree with the runtime's own wall clock within tolerance; the owner
    /// cannot set time, only vouch for it.
    pub observed_wall: Timestamp,
}

/// Ask the runtime to stop (ADR-0006 §13.6 item 8; capability
/// [`crate::ipc::capability::SERVICE_CONTROL_V1`]).
///
/// Accepted only from the owner principal on the control endpoint (never from a
/// limited consumer), on any session (attended or not: stopping the service is an
/// availability action, not a widening of authority; a same-user process could end
/// the process anyway). Idempotent: a repeated request while the runtime is
/// draining answers `OK` again. The runtime answers `OK {"stopping": true, ...}`
/// first, then drains gracefully: it stops accepting, lets in-flight operations
/// reach a durable stage (bounded; anything still running resumes through restart
/// recovery), persists, removes its advertisement and endpoints, and exits 0.
/// Not an operation: no operation ID, no idempotency record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShutdownRequest {}

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
    /// Complete a server-issued decision (attended sessions only).
    Decide(DecideRequest),
    /// Attended confirmation of the current time (attended sessions only).
    ConfirmTime(ConfirmTimeRequest),
    /// Graceful runtime stop (owner principal, control endpoint, any session;
    /// needs the negotiated `service-control/1` capability).
    Shutdown(ShutdownRequest),
    /// Projection setup (M02; needs `setup/1`, offered since the activation change
    /// set).
    Setup(SetupRequest),
    /// Catalog change (M02; needs `setup/1`).
    Catalog(CatalogRequest),
    /// ⟨M03⟩ Issuer status, registration, unlock, retirement and the recovery bundle
    /// (needs `issuer/1`, not offered until the activation change set).
    Issuer(IssuerRequest),
    /// ⟨M03⟩ Enrollment (needs `enrollment/1`, not offered until the activation
    /// change set).
    Enrollment(EnrollmentRequest),
    /// ⟨M03⟩ Owned connections (needs `connections/1`, not offered until the
    /// activation change set).
    Connections(ConnectionsRequest),
}

/// How the application admits a request (m02-plan U0 "journaled kinds"; ADR-0006
/// §7). [`Request::admission`] matches every variant without a wildcard, so a new
/// variant does not compile until it is classified here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Admission {
    /// Admitted as a journaled operation row whose `OperationKind::as_str()` is
    /// this string (equal to [`Request::kind`]).
    Journaled(&'static str),
    /// Effectful, but settled synchronously under ADR-0006 §7 idempotency with no
    /// operation row (`cancel`, `release`, `policy`, `decide`, `confirm_time`).
    Synchronous,
    /// Not effectful: no operation ID and no journal entry.
    ReadOnly,
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
            Request::Decide(_) => "decide",
            Request::ConfirmTime(_) => "confirm_time",
            Request::Shutdown(_) => "shutdown",
            Request::Setup(r) => r.kind(),
            Request::Catalog(_) => "catalog",
            Request::Issuer(r) => r.kind(),
            Request::Enrollment(r) => r.kind(),
            Request::Connections(r) => r.kind(),
        }
    }

    /// How the application admits this request. Exhaustive by construction.
    #[must_use]
    pub fn admission(&self) -> Admission {
        match self {
            Request::Inspect(_) | Request::Observe(_) | Request::Shutdown(_) => Admission::ReadOnly,
            Request::Ensure(_) => Admission::Journaled("ensure"),
            Request::Delegate(_) => Admission::Journaled("delegate"),
            Request::Bind(_) => Admission::Journaled("bind"),
            Request::Revoke(_) => Admission::Journaled("revoke"),
            Request::Cancel(_)
            | Request::Release(_)
            | Request::Policy(_)
            | Request::Decide(_)
            | Request::ConfirmTime(_) => Admission::Synchronous,
            Request::Setup(SetupRequest::Preview { .. }) => Admission::ReadOnly,
            Request::Setup(SetupRequest::Apply { .. }) => Admission::Journaled("setup.apply"),
            Request::Setup(SetupRequest::Rollback { .. }) => Admission::Journaled("setup.rollback"),
            Request::Setup(SetupRequest::Repair { .. }) => Admission::Journaled("setup.repair"),
            Request::Catalog(_) => Admission::Journaled("catalog"),
            // ⟨M03⟩ m03-plan §5 items 2, 3, 4a, 11, 12.
            Request::Issuer(IssuerRequest::Status | IssuerRequest::Bundle { .. }) => {
                Admission::ReadOnly
            }
            Request::Issuer(
                IssuerRequest::Register { .. }
                | IssuerRequest::Unlock
                | IssuerRequest::Retire { .. },
            ) => Admission::Synchronous,
            Request::Enrollment(EnrollmentRequest::Preview { .. }) => Admission::ReadOnly,
            Request::Enrollment(EnrollmentRequest::Apply { .. }) => {
                Admission::Journaled("enrollment.apply")
            }
            Request::Enrollment(EnrollmentRequest::Verify { .. }) => {
                Admission::Journaled("enrollment.verify")
            }
            Request::Enrollment(EnrollmentRequest::Remove { .. }) => {
                Admission::Journaled("enrollment.remove")
            }
            Request::Enrollment(
                EnrollmentRequest::Reconcile { .. }
                | EnrollmentRequest::Abandon { .. }
                | EnrollmentRequest::Step { .. }
                | EnrollmentRequest::StepResult { .. },
            ) => Admission::Synchronous,
            Request::Connections(
                ConnectionsRequest::Close { .. } | ConnectionsRequest::Register { .. },
            ) => Admission::Synchronous,
        }
    }

    /// The capability a session must have negotiated to send this request, when it
    /// needs one beyond `operations/1` (ADR-0006 §2.4): `Shutdown` needs
    /// `service-control/1`; `Setup` and `Catalog` need `setup/1` (m02-plan §5
    /// item 4). A session without it gets `SCHEMA_UNSUPPORTED` and the request is
    /// never dispatched. Exhaustive, so a new variant must state its capability.
    #[must_use]
    pub fn required_capability(&self) -> Option<&'static str> {
        match self {
            Request::Shutdown(_) => Some(crate::ipc::capability::SERVICE_CONTROL_V1),
            Request::Setup(_) | Request::Catalog(_) => Some(crate::ipc::capability::SETUP_V1),
            Request::Issuer(_) => Some(crate::ipc::capability::ISSUER_V1),
            Request::Enrollment(_) => Some(crate::ipc::capability::ENROLLMENT_V1),
            Request::Connections(_) => Some(crate::ipc::capability::CONNECTIONS_V1),
            Request::Inspect(_)
            | Request::Ensure(_)
            | Request::Bind(_)
            | Request::Delegate(_)
            | Request::Observe(_)
            | Request::Cancel(_)
            | Request::Release(_)
            | Request::Revoke(_)
            | Request::Policy(_)
            | Request::Decide(_)
            | Request::ConfirmTime(_) => None,
        }
    }

    /// Whether the request may only be served on an attended session and is
    /// refused **before dispatch** otherwise, with `INTERACTION_REQUIRED` and no
    /// decision record (ADR-0006 §2.3, §3.1; design-fix second round R5): completing
    /// a decision and confirming time. `Attend` itself is a frame, not a request;
    /// its precondition is a session that declared `interactive`. ⟨M03⟩ Also
    /// `Issuer::Unlock` (m03-plan §5 item 2: attended sessions only).
    #[must_use]
    pub fn requires_attended_session(&self) -> bool {
        matches!(
            self,
            Request::Decide(_) | Request::ConfirmTime(_) | Request::Issuer(IssuerRequest::Unlock)
        )
    }

    /// Whether the request is a widening policy action (`resume`, `clear_cutoff`;
    /// ⟨M03⟩ `set_lock_behavior{continue}`, `set_connection_policy` with `existing:
    /// graceful` or `multiplexing: owned_masters`; [`PolicyAction::is_widening`]).
    /// These **are** dispatched on any session, and the application always creates a
    /// `WidenPolicy` decision record and never executes on dispatch: it returns
    /// `APPROVAL_REQUIRED` on an attended session and `INTERACTION_REQUIRED` on an
    /// unattended one, both with `next.decision_ref`, which only an attended
    /// `decide` completes (ADR-0006 §3.1; R5 as superseded by ⟨r2.1⟩ N04). The
    /// application also treats a `cutoff` later than the current one as widening;
    /// this predicate looks only at the request, not at the stored cutoff.
    #[must_use]
    pub fn is_widening_policy_action(&self) -> bool {
        match self {
            Request::Policy(action) => action.is_widening(),
            _ => false,
        }
    }

    /// Whether the request can have external effects. `Shutdown` is a runtime
    /// lifecycle request, not a journaled operation, and `Setup(Preview)` is
    /// read-only. Which effectful requests get an operation row is
    /// [`Self::admission`].
    #[must_use]
    pub fn is_effectful(&self) -> bool {
        self.admission() != Admission::ReadOnly
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use crate::ipc::{ClientMessage, ServerMessage, capability};

    /// ADR-0006 §13.6 item 8: `{"op":"shutdown"}` is the whole wire form, it needs
    /// `service-control/1`, it is not attended-only, not a widening action and not
    /// a journaled operation.
    #[test]
    fn shutdown_wire_form_and_predicates() {
        let r: Request = serde_json::from_str(r#"{"op":"shutdown"}"#).unwrap();
        assert_eq!(r, Request::Shutdown(ShutdownRequest {}));
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"op":"shutdown"}"#);
        assert_eq!(r.kind(), "shutdown");
        assert_eq!(
            r.required_capability(),
            Some(capability::SERVICE_CONTROL_V1)
        );
        assert_eq!(capability::SERVICE_CONTROL_V1, "service-control/1");
        assert!(!r.requires_attended_session());
        assert!(!r.is_widening_policy_action());
        assert!(!r.is_effectful());
        // Unknown fields are tolerated (ADR-0006 §9).
        let extra: Request = serde_json::from_str(r#"{"op":"shutdown","later":1}"#).unwrap();
        assert_eq!(extra, r);
        // No other request needs a capability beyond operations/1.
        let decide = Request::Decide(DecideRequest {
            decision_id: crate::ids::DecisionId::from_random_bytes([1; 16]),
            verdict: Verdict::Deny,
        });
        assert_eq!(decide.required_capability(), None);
    }

    /// The checked-in examples (`schemas/examples/*shutdown*.json`) round-trip
    /// exactly through the typed model.
    #[test]
    fn shutdown_examples_round_trip() {
        fn exact<T: serde::Serialize + serde::de::DeserializeOwned>(text: &str) -> T {
            let v: serde_json::Value = serde_json::from_str(text).unwrap();
            let typed: T = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(serde_json::to_value(&typed).unwrap(), v);
            typed
        }
        let r: Request = exact(include_str!(
            "../../../schemas/examples/request.shutdown.json"
        ));
        assert_eq!(r, Request::Shutdown(ShutdownRequest {}));
        let m: ClientMessage = exact(include_str!(
            "../../../schemas/examples/ipc.client-message.request-shutdown.json"
        ));
        assert!(matches!(
            m,
            ClientMessage::Request {
                request: Request::Shutdown(_),
                ..
            }
        ));
        let s: ServerMessage = exact(include_str!(
            "../../../schemas/examples/ipc.server-message.response-shutdown.json"
        ));
        let ServerMessage::Response { envelope, .. } = s else {
            panic!("a response");
        };
        let envelope: Envelope<serde_json::Value> = envelope;
        assert_eq!(envelope.code, crate::Code::Ok);
        assert_eq!(envelope.data["stopping"], true);
    }

    /// The generated request schema lists `shutdown` as an `op`.
    #[test]
    fn request_schema_names_shutdown() {
        let schema = schemars::schema_for!(Request);
        let text = serde_json::to_string(&schema).unwrap();
        assert!(text.contains("\"shutdown\""), "{text}");
        assert!(text.contains("ShutdownRequest"), "{text}");
    }
}
