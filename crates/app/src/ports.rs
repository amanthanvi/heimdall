//! Adapter ports (spec §13.1 "Adapters declare supported operations, side effects,
//! interaction requirements, and enforcement capability").
//!
//! M01 has one implementation, `heimdall_testkit::FakeCredentialAdapter`; M02 adds
//! the native-agent and 1Password adapters, M03 the managed signer. Adapters never
//! start their own retry loops (spec §11.5) and never prompt.

use std::collections::BTreeSet;

use async_trait::async_trait;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId};
use heimdall_contract::request::{Capability, RequiredCapabilities};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::scope::Scope;

/// Interaction an adapter may need (spec §7.2, §11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InteractionRequirement {
    /// Never needs a human.
    None,
    /// Provider may show its own dialog (described as a provider interaction).
    ProviderDialog,
    /// Hardware presence (touch/PIN).
    HardwarePresence,
    /// Terminal prompt (passphrase).
    TerminalPrompt,
}

/// Static declaration of what an adapter can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDescriptor {
    /// Mechanism name reported as `credential_mechanism`.
    pub mechanism: &'static str,
    /// Capabilities it can realize.
    pub capabilities: BTreeSet<Capability>,
    /// Whether it has external side effects beyond local process/state.
    pub external_side_effects: bool,
    /// Interaction it may require.
    pub interaction: InteractionRequirement,
    /// Strongest enforcement it can claim, with evidence.
    pub enforcement: EnforcementEvidence,
    /// Whether it can sign while the desktop/vault is locked (verified, not assumed).
    pub lock_continuity: LockContinuity,
}

/// Lock-continuity claim (spec §6.4, R-CR-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockContinuity {
    /// Not known.
    Unknown,
    /// Verified by a native test.
    Verified,
    /// Known not to continue.
    StopsOnLock,
}

/// Adapter failure. Classified; the application maps it to a code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// Provider locked.
    #[error("provider locked")]
    ProviderLocked,
    /// Interaction required but not permitted.
    #[error("interaction required: {0:?}")]
    InteractionRequired(InteractionRequirement),
    /// Dependency unavailable (socket, pipe, service).
    #[error("adapter dependency unavailable: {0}")]
    Unavailable(String),
    /// Minimum capability cannot be met.
    #[error("capability unavailable")]
    CapabilityUnavailable,
    /// External effect uncertain.
    #[error("outcome unknown: {0}")]
    OutcomeUnknown(String),
    /// Protocol or parse failure from the dependency (bounded, redacted).
    #[error("adapter protocol error: {0}")]
    Protocol(String),
}

/// Request to prepare credentials for a grant.
#[derive(Debug, Clone)]
pub struct PrepareRequest<'a> {
    /// The grant.
    pub grant: &'a GrantSnapshot,
    /// Scope to prepare (subset of the grant).
    pub scope: &'a Scope,
    /// Minimums.
    pub required: &'a RequiredCapabilities,
    /// Whether prompts are permitted.
    pub interactive: bool,
    /// Now.
    pub now: Timestamp,
}

/// Prepared credential facts (spec §6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareOutcome {
    /// Credentials usable without refresh until.
    pub usable_until: Timestamp,
    /// Usable with no controller/issuer contact until.
    pub offline_until: Timestamp,
    /// Dependency of continued readiness.
    pub refresh_dependency: heimdall_contract::request::RefreshDependency,
    /// Enforcement achieved, with evidence.
    pub enforcement: EnforcementEvidence,
    /// Opaque credential handle reference stored in the grant (never the material).
    pub credential_ref: String,
}

/// Result of a local revocation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// Destinations whose remote effect is pending.
    pub remote_pending: Vec<DestinationId>,
    /// Latest instant an issued credential may still be accepted.
    pub latest_possible_credential_expiry: Option<Timestamp>,
}

/// A credential adapter.
#[async_trait]
pub trait CredentialAdapter: Send + Sync {
    /// Static declaration.
    fn descriptor(&self) -> &AdapterDescriptor;

    /// Prepare credentials for a grant. Must be idempotent for the same grant and
    /// must not extend `grant.deadline`.
    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError>;

    /// Renew within the grant (never past its deadline or cutoff).
    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError>;

    /// Apply local revocation for a grant; remote effects are reported, not assumed.
    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError>;
}

/// Owner-decision port (primitives-draft §2: approval is not a primitive; it
/// happens on an owner channel). M01 records decisions in the store; the TUI/CLI
/// decision flow arrives with G05.
#[async_trait]
pub trait DecisionChannel: Send + Sync {
    /// Register a pending decision and return its nonsecret reference.
    async fn request_decision(
        &self,
        delta: &heimdall_domain::authority::AuthorityDelta,
    ) -> Result<String, AdapterError>;
}
