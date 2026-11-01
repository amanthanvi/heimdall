//! Adapter ports (spec §13.1 "Adapters declare supported operations, side effects,
//! interaction requirements, and enforcement capability"; review F05).
//!
//! M01 has one implementation, `heimdall_testkit::FakeCredentialAdapter`; M02 adds
//! the native-agent and 1Password adapters, M03 the managed signer and issuer.
//! Adapters never start their own retry loops (spec §11.5) and never prompt.
//!
//! Effects are idempotent per `effect_token`: the application mints the token,
//! writes an `Attempted` stage receipt, then calls `prepare`. After a crash or a
//! lost reply it asks the **same** adapter to `reconcile(token)` instead of calling
//! `prepare` again; a stage marker or request hash is never treated as a receipt.
//! Owner decisions are not a port any more: they are server-issued
//! `heimdall_domain::decision::DecisionRecord`s completed on attended sessions.

use std::collections::BTreeSet;

use async_trait::async_trait;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId};
use heimdall_contract::request::{Capability, RequiredCapabilities};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::operation::AdapterIdentity;
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
    /// Stable identity (mechanism + instance) recorded in receipts.
    pub identity: AdapterIdentity,
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

impl AdapterDescriptor {
    /// Mechanism name reported as `credential_mechanism`.
    #[must_use]
    pub fn mechanism(&self) -> &str {
        &self.identity.mechanism
    }
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
    /// External effect uncertain (lost acknowledgment); reconcile with the token.
    #[error("outcome unknown: {0}")]
    OutcomeUnknown(String),
    /// Protocol or parse failure from the dependency (bounded, redacted).
    #[error("adapter protocol error: {0}")]
    Protocol(String),
}

/// Request to prepare credentials for a grant.
#[derive(Debug, Clone)]
pub struct PrepareRequest<'a> {
    /// The grant, with `deadline.effective` narrowed to the bound recorded when the
    /// attempt was authorized: `min(deadline, every ancestor deadline, cutoff)`
    /// (code review A03). Nothing the adapter creates may outlive it.
    pub grant: &'a GrantSnapshot,
    /// Scope to prepare (subset of the grant).
    pub scope: &'a Scope,
    /// Minimums.
    pub required: &'a RequiredCapabilities,
    /// Whether prompts are permitted.
    pub interactive: bool,
    /// Idempotency token for this effect, already recorded in an `Attempted`
    /// receipt. A repeated call with the same token must not produce a second
    /// effect.
    pub effect_token: &'a str,
    /// Now: the wall time the gate accepted in the transaction that authorized
    /// this attempt.
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

/// What reconciliation established about an earlier `effect_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The effect happened; here is what it produced.
    Applied(PrepareOutcome),
    /// The effect did not happen; a fresh `prepare` is safe.
    NotApplied,
    /// Still unknown; the operation stays `outcome_unknown`.
    Unknown,
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

    /// Prepare credentials for a grant. Idempotent per `effect_token`; must not
    /// extend `grant.deadline`.
    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError>;

    /// Renew within the grant (never past its deadline or cutoff).
    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError>;

    /// Establish what happened to an earlier effect (recovery after a crash or a
    /// lost reply). Must not perform the effect.
    async fn reconcile(
        &self,
        grant: &GrantId,
        effect_token: &str,
    ) -> Result<ReconcileOutcome, AdapterError>;

    /// Apply local revocation for a grant; remote effects are reported, not assumed.
    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError>;
}

/// Removes runtime-owned resources (spec §13.5; R-RT-04; m01-plan U8 ⟨r2.1⟩ N06):
/// endpoints, supervised processes, generated projections. Called **only** by the
/// runtime's single supervisor-owned cleanup executor, which plans the cleanup
/// (`reconcile::plan`), re-checks the generation (`reconcile::guard_cleanup`)
/// right before the call, and owns every retry; an implementation never retries
/// and never prompts.
///
/// `delete` is **generation-bound**: it removes the instance that
/// `resource.locator` names at `resource.generation` and nothing else (a socket
/// path is unlinked only if it is still that generation's inode, a process is
/// stopped only by exact PID and start time). A replacement that already took the
/// locator over is left untouched and reported as success (`Ok`, nothing of that
/// generation remains). M01 has no production implementation (the M02 adapters
/// add them); tests use a fake through this port.
#[async_trait]
pub trait ResourceCleaner: Send + Sync {
    /// Remove the instance of `resource` at its generation. Idempotent.
    async fn delete(
        &self,
        resource: &heimdall_domain::resource::ManagedResource,
    ) -> Result<(), AdapterError>;
}
