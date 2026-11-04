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
//!
//! **M02 additions** (m02-plan §5 item 15; ADR-0007 §5.7, §7, §8):
//! * [`PrepareRequest::pairs`] and the [`PrepareOutcome`] fields `availability`,
//!   `provider` and `integration`;
//! * the **drop contract** of [`CredentialAdapter`] and the bound on every adapter
//!   call ([`DEFAULT_ADAPTER_CALL_TIMEOUT`], [`MIN_ADAPTER_CALL_TIMEOUT`]; U0b row 24);
//! * [`ProjectionWriter`] (stateless, with `observe_held`) and [`StageSink`], frozen
//!   in wave 0, implemented by `heimdall_localenv::projection::LocalProjection` (U4)
//!   and over the store by U5;
//! * [`ProviderProbe`] (the existing-access adapters, U6) and [`ProcessLiveness`]
//!   (holder release, U8).
//!
//! The recovery and fingerprint types a [`HeldStep`] carries live in
//! `heimdall_domain::projection` (wave-0 verifier escalation E8): `heimdall-localenv`
//! implements these ports, so the app cannot name its types.
//!
//! ⟨M02⟩ **Nothing that can block runs inside the bound** (ADR-0007 §12.23 item 2,
//! U02). An adapter that reads the store or the file system for `prepare` reads it
//! in [`CredentialAdapter::read_sources`], which the runtime calls on the blocking
//! pool **before** `bounded_adapter_call`, in the same operation step. The result,
//! an in-memory [`IntegrationSnapshot`], is handed to the bounded
//! [`CredentialAdapter::prepare_from`], which only evaluates over it. Both have
//! defaults (no sources; `prepare`), so an adapter that reads nothing is unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::Timestamp;
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::ids::{AccountName, DestinationId, GrantId, IdentityId};
use heimdall_contract::provider::{
    CredentialAvailability, EndpointRef, ProviderKind, ProviderStatus,
};
use heimdall_contract::request::{
    Capability, ConsumerExecutable, ConsumerIntegration, RequiredCapabilities,
};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::catalog::{IdentityRecord, InteractionDeclaration};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::holder::{HolderState, ProcessHolder};
use heimdall_domain::operation::{AdapterIdentity, HoldReason, LocalReceipt, StageReceipt};
use heimdall_domain::projection::{
    FileRole, ItemCommit, ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent,
    StepFingerprint, StepObservation,
};
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
    /// ⟨M02⟩ The catalog's pairs for the scope (U0b row 8): destination, account,
    /// identity record and managed alias. Empty for adapters that use no catalog
    /// identity (the M01 fake).
    pub pairs: &'a [PreparePair],
}

/// ⟨M02⟩ One access pair as the catalog names it (m02-plan §5 item 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparePair {
    /// Destination.
    pub destination: DestinationId,
    /// Remote account.
    pub account: AccountName,
    /// The adopted identity the catalog names for the pair.
    pub identity: IdentityRecord,
    /// The managed alias, when the destination is managed (a literal `Host` name,
    /// validated by the renderer).
    pub alias: Option<String>,
}

/// ⟨M02⟩ ADR-0007 §12.23 item 2 (U02): everything an adapter's `prepare` reads
/// besides its request, as an in-memory value. [`CredentialAdapter::read_sources`]
/// builds it before the bound (store reads: catalog identities, declaration rows,
/// executables; file reads: the static observation of the managed aliases), and
/// [`CredentialAdapter::prepare_from`] evaluates over it inside the bound. Nothing in
/// it is secret: public identity records, declarations, configuration observations
/// and client paths. Empty claims nothing, which fails closed (no observation leaves
/// a selection `undetermined`, no declaration leaves a native key `unknown`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrationSnapshot {
    /// The static observation of the request's managed aliases.
    pub observations: Vec<AliasObservation>,
    /// Every catalog identity (fallback clearance looks alternatives up here).
    pub identities: Vec<IdentityRecord>,
    /// The declaration row of each identity that has one (the pairs' and the
    /// catalog's).
    pub declarations: BTreeMap<IdentityId, InteractionDeclaration>,
    /// The verified client executables the integration relies on.
    pub executables: Vec<ConsumerExecutable>,
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
    /// ⟨M02⟩ Credential availability through the deadline (spec §4.3); `unknown`
    /// unless the adapter established it.
    pub availability: CredentialAvailability,
    /// ⟨M02⟩ The provider's status, when the adapter fronts one.
    pub provider: Option<ProviderStatus>,
    /// ⟨M02⟩ The consumer integration the adapter materialized (executables,
    /// overrides, per-pair endpoints and selections). The runtime keeps only its
    /// history (`PreparedFacts`) and recomputes interaction and eligibility for every
    /// result (U0b row 5).
    pub integration: ConsumerIntegration,
}

/// What reconciliation established about an earlier `effect_token`.
// ⟨M02⟩ `PrepareOutcome` grew with its integration (U0b row 5). It is returned once
// per reconcile call and never stored in bulk; boxing `Applied` would change every
// adapter and test that builds it, so the size difference is accepted.
#[allow(clippy::large_enum_variant)]
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

/// Default bound on one adapter call (m02-plan §6 P12; U0b row 24). An application
/// limit, not a user configuration key in M02.
pub const DEFAULT_ADAPTER_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest production value of the adapter-call bound (P12). Tests may set a lower
/// one (row 24's tests use 200 ms), so `Operations::start` does not enforce it
/// (wave-0 verify E14 reading).
pub const MIN_ADAPTER_CALL_TIMEOUT: Duration = Duration::from_secs(1);

/// A credential adapter.
///
/// **Drop contract** (m02-plan §5 item 15; ADR-0007 §7 "Every call is bounded";
/// M2-T06). The runtime awaits every `prepare`, `renew`, `reconcile` and `revoke`
/// future under a bound (`Limits.adapter_call_timeout`, default
/// [`DEFAULT_ADAPTER_CALL_TIMEOUT`]) applied to the adapter future alone, never to a
/// slot wait or a caller's wait. When the bound elapses the runtime **drops** the
/// future and treats the call as [`AdapterError::OutcomeUnknown`]. An implementation
/// must therefore:
/// * do no further work once its future is dropped: no detached task, no thread, no
///   timer, and no blocking call outside a bound of its own;
/// * leave nothing running that could apply an effect later, killing any child
///   process it started when the future is dropped;
/// * keep its effects idempotent per `effect_token`, because the runtime then asks
///   `reconcile` what happened.
///
/// No signature changes for this contract; adapters whose effect can land after the
/// drop are handed to M03 (m02-plan §8).
///
/// ⟨M02⟩ ADR-0007 §12.23 item 2 (U02): the runtime's one preparation call is
/// [`Self::read_sources`] on the blocking pool, outside the bound, then
/// [`Self::prepare_from`] inside it. An implementation keeps every store and file
/// read in `read_sources`; inside the bound it evaluates over the snapshot and makes
/// at most its own bounded, passive checks (the existing-access adapters: one
/// endpoint `stat`).
#[async_trait]
pub trait CredentialAdapter: Send + Sync {
    /// Static declaration.
    fn descriptor(&self) -> &AdapterDescriptor;

    /// Prepare credentials for a grant. Idempotent per `effect_token`; must not
    /// extend `grant.deadline`.
    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError>;

    /// ⟨M02⟩ ADR-0007 §12.23 item 2: read what `prepare` needs besides its request
    /// for `pairs` (store and file reads), **before** the bound. Synchronous: it may
    /// wait on the store or a slow file system, which delays the operation's own step
    /// as any store wait does and never the bounded call. The runtime calls it on the
    /// blocking pool, never inside `bounded_adapter_call`. Default: nothing (an
    /// adapter that reads no source).
    fn read_sources(&self, pairs: &[PreparePair]) -> IntegrationSnapshot {
        let _ = pairs;
        IntegrationSnapshot::default()
    }

    /// ⟨M02⟩ ADR-0007 §12.23 item 2: `prepare` over `sources`, the snapshot
    /// [`Self::read_sources`] returned for `req.pairs` in the same step. This is the
    /// call the runtime bounds; it reads nothing that can block. Same contract as
    /// `prepare` otherwise. Default: `prepare` (an adapter that reads no source).
    async fn prepare_from(
        &self,
        req: PrepareRequest<'_>,
        sources: &IntegrationSnapshot,
    ) -> Result<PrepareOutcome, AdapterError> {
        let _ = sources;
        self.prepare(req).await
    }

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

// --- ⟨M02⟩ existing-access providers (m02-plan §5 item 15; ADR-0007 §6, §7) ----------

/// What passive detection may look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectContext {
    /// The wall time of the observation.
    pub now: Timestamp,
    /// The endpoint the catalog or configuration names for the provider, when one
    /// is known (`SSH_AUTH_SOCK` or an `IdentityAgent` reference; ADR-0007 §7).
    pub endpoint: Option<EndpointRef>,
}

/// Bounds of one explicit agent listing (m02-plan U6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeBounds {
    /// Whole-call timeout.
    pub timeout: Duration,
    /// Largest reply accepted, in bytes.
    pub max_reply_bytes: usize,
    /// Most identities accepted in one reply.
    pub max_identities: usize,
}

impl Default for ProbeBounds {
    /// 2 s, 256 KiB, 1024 identities (m02-plan U6).
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            max_reply_bytes: 256 * 1024,
            max_identities: 1024,
        }
    }
}

/// One identity an agent listed. Comments are discarded; nothing secret is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedIdentity {
    /// Key type (`ssh-ed25519`, `sk-ssh-ed25519@openssh.com` …).
    pub key_type: String,
    /// SHA-256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
}

/// The result of an explicit `agent` probe: exactly one
/// `SSH_AGENTC_REQUEST_IDENTITIES` (ADR-0007 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityListing {
    /// The endpoint listed.
    pub endpoint: EndpointRef,
    /// What it listed.
    pub identities: Vec<ListedIdentity>,
    /// When.
    pub observed_at: Timestamp,
}

/// A provider an existing-access adapter fronts (the native agent, 1Password).
///
/// `detect` is passive: it opens nothing and contacts nothing. Only
/// `list_identities` contacts the provider, and only as the explicit `agent` probe.
#[async_trait]
pub trait ProviderProbe: Send + Sync {
    /// Which provider.
    fn provider(&self) -> ProviderKind;

    /// Passive status (presence, documented interaction), never a contact.
    fn detect(&self, ctx: &DetectContext) -> ProviderStatus;

    /// The explicit `agent` probe, bounded by `bounds`. Same drop contract as
    /// [`CredentialAdapter`].
    async fn list_identities(&self, bounds: &ProbeBounds) -> Result<IdentityListing, AdapterError>;
}

/// Liveness of a launch binding's holder process (ADR-0007 §8; Q5 as qualified).
/// Only an observed exit of that exact process (PID **and** start-time token)
/// releases the binding; [`HolderState::Unknown`] never does.
pub trait ProcessLiveness: Send + Sync {
    /// Observe `holder`.
    fn state(&self, holder: &ProcessHolder) -> HolderState;
}

// --- ⟨M02⟩ the projection writer (frozen in wave 0; ADR-0007 §5.7; U4, U5) ----------

/// A failed append or commit through a [`StageSink`]. Nonsecret, bounded text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("stage sink failed: {0}")]
pub struct SinkError(pub String);

/// Where the writer records its progress. U5 implements it over the store.
///
/// * [`append`](StageSink::append) writes one `StageReceipt` carrying the local
///   receipt, in its own store transaction, with `effect` fixed by the phase
///   (`Confirmed` for `item.committed` and `item.finished{applied}`, `Attempted`
///   otherwise), and returns only once it is durable. The writer never begins the
///   next step before that.
/// * [`commit_item`](StageSink::commit_item) writes `item.committed` together with
///   the item's resources at the new generation, the projection record and the
///   consented states in **one** transaction (`Txn::commit_projection_item`;
///   M2-R01). The writer settles nothing of the item before it returns `Ok`.
///
/// An error leaves everything unsettled for `reconcile` (ADR-0007 §5.7 row T1).
pub trait StageSink: Send {
    /// Durably append one local receipt.
    ///
    /// # Errors
    /// [`SinkError`] when the receipt is not durable.
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError>;

    /// Durably commit an item.
    ///
    /// # Errors
    /// [`SinkError`] when the commit transaction did not commit.
    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError>;
}

/// A step that reached outcome H (ADR-0007 §5.7 "Outcome H"), as `observe_held` and
/// `reconcile` report it. Identities, digests and metadata only: never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldStep {
    /// Index into `SetupIntent.files`.
    pub step: u16,
    /// The step's role.
    pub role: FileRole,
    /// The step's path, for display.
    pub path_display: String,
    /// Why it is held.
    pub reason: HoldReason,
    /// The recovery classification of path, aside and slot.
    pub observed: StepObservation,
    /// ⟨r5⟩ Content fingerprints of the observed names (M2-T03), which a held
    /// repair's plan digest covers.
    pub fingerprint: StepFingerprint,
}

/// The outcome of one projection item (`ssh` or `git`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemOutcome {
    /// `item.committed` at `generation`, settled or settling forward.
    Applied {
        /// The item.
        item: ProjectionItem,
        /// The committed generation.
        generation: u64,
    },
    /// The commit step was never exchanged; nothing of the item is active.
    NotApplied {
        /// The item.
        item: ProjectionItem,
        /// Why, when a conflict caused it.
        reason: Option<ConflictKind>,
    },
    /// Every exchanged step was restored.
    Restored {
        /// The item.
        item: ProjectionItem,
        /// Why, when a conflict caused it.
        reason: Option<ConflictKind>,
    },
    /// Finished with preserved conflict entries (after a `keep_held` repair).
    ConflictPreserved {
        /// The item.
        item: ProjectionItem,
    },
    /// ⟨r4⟩ Held for the owner: nothing moved, the operation stays
    /// `outcome_unknown` (reason `projection_held`).
    Held {
        /// The item.
        item: ProjectionItem,
        /// Every held step.
        steps: Vec<HeldStep>,
    },
}

/// What `apply` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionReceipt {
    /// One outcome per item of the intent.
    pub items: Vec<ItemOutcome>,
}

/// What `reconcile` established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionReconcile {
    /// One outcome per item of the intent.
    pub items: Vec<ItemOutcome>,
}

/// Why `apply`, `reconcile` or `observe_held` did not run. Every variant writes
/// nothing and leaves the operation unresolved and untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReconcileError {
    /// A receipt this build cannot decode or place (`runtime_lifecycle`,
    /// `unreadable_receipts`; §5 item 17a). Nothing is inferred from it.
    #[error("unreadable receipt: {0}")]
    UnreadableReceipt(String),
    /// The intent's content fails its digest binding or bounds
    /// (`SetupIntent::validate`, `content::materialize`), refused before any write.
    #[error("setup intent invalid: {0}")]
    IntentInvalid(String),
    /// A receipt could not be made durable. Whatever was written stays for the next
    /// `reconcile` (row T1).
    #[error(transparent)]
    Sink(#[from] SinkError),
    /// The writer cannot act in this build or on this filesystem
    /// (`CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`).
    #[error("projection writer unavailable: {0}")]
    Unavailable(String),
}

/// Why `preview` produced no plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PreviewError {
    /// The plan exceeds the content bounds of §5 item 17
    /// (`CAPABILITY_UNAVAILABLE`, reason `projection_too_large`); nothing is admitted.
    #[error("projection too large")]
    TooLarge,
    /// The writer cannot preview in this build (`driver_unavailable`), or a file it
    /// must read could not be read (bounded, nonsecret text).
    #[error("projection preview unavailable: {0}")]
    Unavailable(String),
}

/// The managed-projection writer (ADR-0007 §5; implemented by
/// `heimdall_localenv::projection::LocalProjection`, U4).
///
/// **Stateless contract** (frozen; M2-S05). An implementation keeps no state between
/// calls: no preview, `ProjectionSpec`, plan or bytes are cached. `apply` and
/// `reconcile` take every byte they write from `SetupIntent.files[].content` and the
/// base bytes they validate in the same call, so a fresh instance in a fresh process
/// executes or recovers any intent. Its only state is its configuration (paths and
/// test configuration).
///
/// The methods are synchronous file work; the runtime calls them on the blocking
/// pool. On restart the runtime calls `reconcile`, never a second `apply`.
pub trait ProjectionWriter: Send + Sync {
    /// Read-only preview of `intent` over `spec`. The plan carries each step's
    /// content, built through `Rendered`; `ProjectionPlan::intent()` is what
    /// admission stores.
    ///
    /// # Errors
    /// [`PreviewError`]; a manual-mode plan is a plan, not an error.
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError>;

    /// Execute `intent` (apply, rollback or repair), appending every receipt through
    /// `sink` before the next step and committing each item through
    /// [`StageSink::commit_item`] before settling it.
    ///
    /// # Errors
    /// [`ReconcileError`]; `IntentInvalid` before any write.
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError>;

    /// Recover from the receipts by identity, never by content alone: ADR-0007 §5.7's
    /// table, row by row, writing the receipts it completes through `sink`.
    ///
    /// # Errors
    /// [`ReconcileError`]: the operation stays unresolved and nothing is written.
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError>;

    /// Passive static re-evaluation of `aliases` against `record` (behaviour digest,
    /// identity selection, block placement), for doctor, the adapters and
    /// `setup status`. `aliases` are managed or observed alias names.
    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation>;

    /// ⟨r4⟩ The held steps of an intent, observed passively; moves nothing. A held
    /// repair's preview is built from it.
    ///
    /// # Errors
    /// [`ReconcileError`], as for `reconcile`.
    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError>;
}
