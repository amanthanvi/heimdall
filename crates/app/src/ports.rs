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
//! **M03 additions** (m03-plan §5 item 19; frozen in wave 0): [`SignatureAuthority`]
//! (returning [`crate::managed::SignPermit`]), [`IssuerPort`], [`VerificationRunner`],
//! [`VerificationEndpoints`] and [`VerificationSession`], [`TargetEvaluator`],
//! [`ManagedEffects`], [`SessionLockSource`] (with the latched epoch) and
//! [`ConnectionControl`], each under the M02 drop contract; and the fields
//! [`AdapterDescriptor::remote_credential_effect`], [`RevokeOutcome::remote_effects`]
//! and [`IntegrationSnapshot::managed`].
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
//! [`CredentialAdapter::prepare_from`], which only evaluates over it. ⟨M02⟩ ADR-0007
//! §12.26 item 2: neither has a default body, so every adapter states both (one that
//! reads no source returns an empty snapshot and prepares from its request alone).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::Timestamp;
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::enrollment::EnrollmentPlan;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, CredentialInstanceId, DestinationId, EnvironmentId,
    GrantId, IdentityId, IssuanceId, OperationId,
};
use heimdall_contract::issuer::IssuerStatus;
use heimdall_contract::managed::{CloseReason, RemoteEffectReport};
use heimdall_contract::provider::{
    CredentialAvailability, EndpointRef, ProviderKind, ProviderStatus,
};
use heimdall_contract::request::{
    Capability, ConsumerExecutable, ConsumerIntegration, RequiredCapabilities,
};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::catalog::{IdentityRecord, InteractionDeclaration};
use heimdall_domain::claims::Claim;
use heimdall_domain::enrollment::{EnrollmentRecord, TargetEvaluation};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::holder::{HolderState, ProcessHolder};
use heimdall_domain::issuance::{IssuanceEntry, IssuanceRefusal};
use heimdall_domain::managed::{LockEpoch, OwnedConnection, SlotState};
use heimdall_domain::operation::{AdapterIdentity, HoldReason, LocalReceipt, StageReceipt};
use heimdall_domain::projection::{
    FileRole, ItemCommit, ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent,
    StepFingerprint, StepObservation,
};
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::verification::{AttemptResult, VerificationRefusal};

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
    /// ⟨M03⟩ U0b row 7 (ADR-0008 D7 item 5; ADR-0007 §12.13, QR17): whether the
    /// adapter's credentials are authority usable **remotely** (the managed adapter's
    /// published certificates). When true, a timed-out immediate `revoke` keeps its
    /// cleanup intent and the supervisor retries it with bounded, jittered backoff;
    /// it never counts as made. `false` for every M01/M02 adapter.
    pub remote_credential_effect: bool,
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
    /// ⟨M03⟩ U0b row 21 (ADR-0008 D6 item 0): the managed sources of a
    /// `managed_certificate` preparation, filled by the managed adapter's
    /// `read_sources`. `None` for every existing-access adapter, whose contract is
    /// unchanged.
    pub managed: Option<ManagedSources>,
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
    /// ⟨M03⟩ U0b row 6 (m03-plan §5 item 19; ADR-0008 D7 items 3–4): the per-pair
    /// remote residuals of a managed revocation (`latest_valid_before`,
    /// `destination_clock`, `status`). Empty for every M01/M02 adapter.
    pub remote_effects: Vec<RemoteEffectReport>,
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
    /// blocking pool, never inside `bounded_adapter_call`. ⟨M02⟩ ADR-0007 §12.26
    /// item 2: no default; an adapter that reads no source returns
    /// `IntegrationSnapshot::default()`.
    fn read_sources(&self, pairs: &[PreparePair]) -> IntegrationSnapshot;

    /// ⟨M02⟩ ADR-0007 §12.23 item 2: `prepare` over `sources`, the snapshot
    /// [`Self::read_sources`] returned for `req.pairs` in the same step. This is the
    /// call the runtime bounds; it reads nothing that can block: no store, no file and
    /// no live source, only `req` and `sources` (and an adapter's own bounded, passive
    /// checks). Same contract as `prepare` otherwise. ⟨M02⟩ ADR-0007 §12.26 item 2: no
    /// default.
    async fn prepare_from(
        &self,
        req: PrepareRequest<'_>,
        sources: &IntegrationSnapshot,
    ) -> Result<PrepareOutcome, AdapterError>;

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

// --- ⟨M03⟩ the managed-credential ports (m03-plan §5 item 19; ADR-0008) -------------
//
// Frozen in wave 0 (m03-plan U0 "Frozen in wave 0"). Every one follows the M02 drop
// contract of [`CredentialAdapter`]: no detached work once a future is dropped (no
// task, thread or timer left behind), every blocking call under a bound of its own,
// and nothing left running that could apply an effect later. Asynchronous calls are
// awaited by the application under their stated bound; synchronous file work runs on
// the blocking pool. No port carries or returns secret material: public keys,
// certificate lines, fingerprints, opaque slot references and nonsecret reasons only.
//
// Remote enrollment steps are client-executed, so they have no port (ADR-0008 D5
// §6.3): the pure step classification is
// `heimdall_registry::classify::classify_step`, the plan builder
// `heimdall_registry::plan::build`, and the CLI-side runner
// `heimdall_enroll::remote::SshStepRunner`.

/// The session-lock state a [`SessionLockSource`] reports (`unlocked | locked |
/// unknown | unavailable`; ADR-0008 D9 item 3). The contract's wire type, reused.
pub use heimdall_contract::managed::SessionLockState as LockState;

/// Where a sign request arrived (ADR-0008 D2 item 2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignerEndpoint {
    /// The environment endpoint (`signing.sock` or the stable pipe).
    Environment,
    /// A per-binding endpoint.
    Binding(BindingId),
    /// An enrollment operation's verification endpoint.
    Verification(OperationId),
}

/// Whose key a sign request names, as the signer's vault knows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureSubject {
    /// A grant's K_env.
    Grant(GrantId),
    /// An enrollment operation's K_verify.
    Verification(OperationId),
}

/// The facts a parsed, purpose-checked sign request carries into
/// [`SignatureAuthority`] (ADR-0008 D2 items 3–4). Nonsecret: no signed data, no
/// key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRequestFacts {
    /// The endpoint the request arrived on.
    pub endpoint: SignerEndpoint,
    /// The key's owner.
    pub subject: SignatureSubject,
    /// The access pair whose principal the presented certificate names (D2 item 4).
    pub pair: AccessPair,
    /// SHA-256 fingerprint (`SHA256:…`) of the presented key or certificate's
    /// subject key.
    pub key_fingerprint: String,
}

/// Why a signature was refused (ADR-0008 D2 item 3). The client only ever sees
/// `SSH_AGENT_FAILURE`; [`SignRefusal::code`] is the nonsecret code the audit event
/// records.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignRefusal {
    /// The key belongs to no grant (or operation) this endpoint serves.
    #[error("key not served by this endpoint")]
    KeyNotServed,
    /// The grant is not `active`, or `degraded` for a reason that permits signing.
    #[error("grant state does not permit signing")]
    GrantNotUsable,
    /// The grant's validated generation is stale and re-validation did not restore
    /// it.
    #[error("stale authority generation")]
    StaleGeneration,
    /// A tombstone on the grant or an ancestor.
    #[error("grant or ancestor tombstoned")]
    Tombstoned,
    /// The admission deadline passed (wall bound or continuous budget).
    #[error("admission deadline passed")]
    DeadlinePassed,
    /// Time is not `Safe`.
    #[error("time uncertain")]
    TimeUncertain,
    /// The grant's mechanism is not configured.
    #[error("mechanism not configured")]
    MechanismNotConfigured,
    /// `revoke_on_lock` and the session-lock source does not report `unlocked`.
    #[error("session not unlocked")]
    SessionNotUnlocked,
    /// The grant or an ancestor is marked `narrowing_pending` (D2 item 3a).
    #[error("narrowing pending")]
    NarrowingPending,
    /// The grant's gate was not obtained within `signing_gate_wait`.
    #[error("signing gate not obtained in time")]
    GateTimeout,
    /// Authorization exceeded `signature_authorization_timeout`.
    #[error("authorization timed out")]
    AuthorizationTimeout,
    /// The D5 §6.5 verification predicate refused.
    #[error("verification predicate refused: {0}")]
    Verification(VerificationRefusal),
    /// No authority is wired in this build or for this endpoint (wave 0: every
    /// request; fail closed).
    #[error("signature authority unavailable")]
    Unavailable,
}

impl SignRefusal {
    /// The nonsecret audit code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SignRefusal::KeyNotServed => "key_not_served",
            SignRefusal::GrantNotUsable => "grant_not_usable",
            SignRefusal::StaleGeneration => "stale_generation",
            SignRefusal::Tombstoned => "tombstoned",
            SignRefusal::DeadlinePassed => "deadline_passed",
            SignRefusal::TimeUncertain => "time_uncertain",
            SignRefusal::MechanismNotConfigured => "mechanism_not_configured",
            SignRefusal::SessionNotUnlocked => "session_not_unlocked",
            SignRefusal::NarrowingPending => "narrowing_pending",
            SignRefusal::GateTimeout => "gate_timeout",
            SignRefusal::AuthorizationTimeout => "authorization_timeout",
            SignRefusal::Verification(_) => "verification_refused",
            SignRefusal::Unavailable => "authority_unavailable",
        }
    }
}

/// Per-signature authorization (ADR-0008 D2 items 3 and 3a), implemented by
/// `Operations` (U0b row 5) and called by `heimdall-credential`'s signer.
///
/// Drop contract: dropping either future releases everything it took (a gate guard
/// included); neither leaves work behind. `admit` is bounded by
/// `Limits.signing_gate_wait` for the gate and `signature_authorization_timeout`
/// overall.
#[async_trait]
pub trait SignatureAuthority: Send + Sync {
    /// ⟨r2⟩ The unlocked early refusal (step 2). An optimization only: it never
    /// admits and passing it proves nothing. Refuses at once when the grant or an
    /// ancestor is marked `narrowing_pending`.
    ///
    /// # Errors
    /// [`SignRefusal`].
    async fn precheck(&self, facts: &SignatureRequestFacts) -> Result<(), SignRefusal>;

    /// ⟨r2⟩ Takes the grant's gate shared (`signing_gate_wait`), checks the pending
    /// mark first, then reads fresh under it (steps 3–4). The permit is held until
    /// the response is enqueued (ADR-0008 D2 item 3a).
    ///
    /// # Errors
    /// [`SignRefusal`]; the gate is released before the error returns.
    async fn admit(
        &self,
        facts: &SignatureRequestFacts,
    ) -> Result<crate::managed::SignPermit, SignRefusal>;
}

/// Which issuance table an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuanceTable {
    /// The grant issuance log (`issuance_log`).
    Grant,
    /// The verification issuance table (`verification_issuance`; ADR-0008 D5 §6.5).
    Verification,
}

/// A reserved issuance entry the issuer is asked to sign (ADR-0008 D3 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IssuanceRef {
    /// The table.
    pub table: IssuanceTable,
    /// The entry.
    pub id: IssuanceId,
}

/// Why the issuer refused an entry (`heimdall-issuer/1`, m03-plan §5 item 20): the
/// [`IssuanceRefusal`] and [`VerificationRefusal`] sets plus six issuer-side
/// refusals. The wire golden is U3's (`tests/contracts/golden/issuer-protocol.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssuerRefusal {
    /// A grant-entry predicate failed in the read-only snapshot.
    #[error("issuance refused: {0}")]
    Issuance(IssuanceRefusal),
    /// A verification-entry predicate failed in the read-only snapshot.
    #[error("verification issuance refused: {0}")]
    Verification(VerificationRefusal),
    /// The entry is not `reserved` (published, voided or missing).
    #[error("entry not reserved")]
    EntryNotReserved,
    /// The reservation is older than the issuer accepts (60 s).
    #[error("entry stale")]
    EntryStale,
    /// The subject key is not the one the entry was reserved for.
    #[error("subject mismatch")]
    SubjectMismatch,
    /// The entry exceeds an issuer ceiling (principals, extensions, validity).
    #[error("ceiling exceeded")]
    CeilingExceeded,
    /// The entry's CA is not loaded in the child.
    #[error("CA not loaded")]
    CaNotLoaded,
    /// More than `issuer_signatures_per_minute` (or the per-grant cap).
    #[error("rate limited")]
    RateLimited,
}

/// An [`IssuerPort`] failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// The issuer refused the entry.
    #[error(transparent)]
    Refused(#[from] IssuerRefusal),
    /// The issuer is not running, not initialized, locked or restarting (nonsecret
    /// reason, one of the `issuer_*` sub-reasons).
    #[error("issuer unavailable: {0}")]
    Unavailable(String),
    /// No reply within `issuer_request_timeout`; a late reply is discarded.
    #[error("issuer request timed out")]
    Timeout,
    /// A malformed or unexpected frame (bounded, redacted).
    #[error("issuer protocol error: {0}")]
    Protocol(String),
}

/// The issuer's supervised status as the runtime last observed it (no I/O to read
/// it; ADR-0008 D3 item 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerStatusSnapshot {
    /// The `issuer.status` view.
    pub status: IssuerStatus,
}

/// The issuer child's client (ADR-0008 D3; implemented by
/// `heimdall_issuer::client::ChildIssuer`, U3).
///
/// Drop contract: a dropped `sign` or `unload` future leaves nothing pending in the
/// client; a reply that arrives later is discarded (and a certificate zeroized)
/// by `request_id` matching. Each request is bounded by `issuer_request_timeout`
/// (10 s), inside the 30 s adapter-call bound.
#[async_trait]
pub trait IssuerPort: Send + Sync {
    /// The last observed status; never blocks.
    fn status(&self) -> IssuerStatusSnapshot;

    /// Sign the reserved `entry` for `subject` (an OpenSSH public-key line). Returns
    /// the OpenSSH certificate line.
    ///
    /// # Errors
    /// [`IssuerError`].
    async fn sign(&self, entry: IssuanceRef, subject: &str) -> Result<String, IssuerError>;

    /// ⟨r2⟩ Retirement: zeroize and unload `ca` in the child (ADR-0008 D4 item 3),
    /// sent only once the CA is `retiring` in the store.
    ///
    /// # Errors
    /// [`IssuerError`].
    async fn unload(&self, ca: &CaFingerprint) -> Result<(), IssuerError>;
}

/// The two verification attempts' observable results (ADR-0008 D5 §6.5), which the
/// application classifies with `heimdall_domain::verification::classify`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationOutcome {
    /// The positive attempt.
    pub positive: AttemptResult,
    /// The negative attempt.
    pub negative: AttemptResult,
    /// The verified client that ran them (path and version, for evidence), when it
    /// started.
    pub client: Option<String>,
    /// ⟨M03 wave 4, ADR-0008 §17.17 item 14 (U5IO-Q4)⟩ The client's trace family or
    /// version is unrecorded, so no attempt ran: the classification is inconclusive
    /// (`unrecorded_client_family`) and the doctor names the client.
    pub unrecorded: bool,
}

/// Runs the production verification's fresh logins (ADR-0008 D5 §6.5; U5).
///
/// Drop contract: a dropped `run` kills every client it started and leaves no
/// generated file behind. Bounded by the verification limits of §5 item 17.
#[async_trait]
pub trait VerificationRunner: Send + Sync {
    /// Run the positive and negative attempts of `plan` with the certificate lines
    /// `positive` and `negative`, through `session`'s endpoint.
    async fn run(
        &self,
        plan: &EnrollmentPlan,
        positive: &str,
        negative: &str,
        session: &dyn VerificationSession,
    ) -> VerificationOutcome;
}

/// ⟨r3⟩ The verification lifecycle factory (§17.4 item 9; A R2-09). Implemented by
/// `heimdall-credential`.
///
/// Drop contract: a dropped `create` leaves no endpoint and no key.
#[async_trait]
pub trait VerificationEndpoints: Send + Sync {
    /// Create `operation`'s verification endpoint with a fresh K_verify, whose public
    /// key is registered at creation. ⟨M03 wave 4, ADR-0008 §17.19 item 5 (INT-Q13)⟩
    /// The factory receives the `plan`: every certificate the session installs must be
    /// signed by the plan's CA, and the positive one must name the plan's pair. The
    /// implementation also opens `operation`'s verification signing gate
    /// (`app::managed::SigningGates::open_verification`), which closes when the
    /// session is dropped.
    ///
    /// # Errors
    /// [`AdapterError`].
    async fn create(
        &self,
        operation: &OperationId,
        plan: &EnrollmentPlan,
    ) -> Result<Box<dyn VerificationSession>, AdapterError>;
}

/// ⟨r3⟩ One operation's verification endpoint. Dropping it zeroizes K_verify and
/// removes the endpoint.
pub trait VerificationSession: Send + Sync {
    /// K_verify's OpenSSH public-key line, registered at creation.
    fn public_key(&self) -> &str;

    /// Install a published verification certificate (the signer's check, D2 item 6).
    ///
    /// # Errors
    /// [`AdapterError`]; a refused certificate is discarded.
    fn install(&self, certificate_line: &str) -> Result<(), AdapterError>;

    /// The endpoint's locator.
    fn locator(&self) -> &EndpointRef;

    /// Signatures recorded for `key_fingerprint`.
    fn signatures(&self, key_fingerprint: &str) -> u32;

    /// `session-bind@openssh.com` extensions received.
    fn session_binds(&self) -> u32;
}

/// ⟨r2⟩ The passive target evaluation of a managed alias (`ssh -G`-equivalent,
/// static; §17.1 items 2, 12). Implemented by `heimdall-localenv` (`target.rs`).
/// Contacts nothing.
pub trait TargetEvaluator: Send + Sync {
    /// Evaluate `alias`.
    fn evaluate(&self, alias: &str) -> TargetEvaluation;
}

/// What the signer registered for a freshly generated K_env (credential instance
/// `pending`, ADR-0008 D2). No secret: the key stays in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRegistration {
    /// The OpenSSH public-key line.
    pub public_key: String,
    /// Its SHA-256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// The opaque vault slot reference persisted with the instance.
    pub slot: String,
}

/// One certificate a binding's files carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedCertificate {
    /// The pair.
    pub pair: AccessPair,
    /// The OpenSSH certificate line.
    pub certificate: String,
}

/// The per-binding files to write (ADR-0008 D6 item 1 step 6; D10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeSpec {
    /// The resource generation the files carry.
    pub generation: u64,
    /// K_env's OpenSSH public-key line (`key.pub`).
    pub public_key: String,
    /// One `cert-<destination-id>.pub` per pair.
    pub certificates: Vec<MaterializedCertificate>,
    /// Also fill the environment slots (a materialized binding holding them).
    pub environment_slots: bool,
}

/// What `materialize` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFiles {
    /// The binding's directory (`<runtime_dir>/b/<16 hex>`).
    pub directory: PathBuf,
    /// Every file written, at `generation`.
    pub files: Vec<PathBuf>,
    /// The generation.
    pub generation: u64,
}

/// ⟨r2⟩ The managed credential adapter's effects (ADR-0008 D6 item 0), implemented by
/// `heimdall_adapters::managed` (U6) and driven only by
/// [`crate::managed::drive_preparation`].
///
/// Drop contract: as [`CredentialAdapter`]. `generate_key`, `install` and `destroy`
/// are each bounded by `adapter_call_timeout`; `materialize` and `clear` are
/// synchronous file work the caller runs on the blocking pool, like
/// [`ProjectionWriter`].
#[async_trait]
pub trait ManagedEffects: Send + Sync {
    /// Generate K_env for `grant` in the vault, idempotent per `token`.
    ///
    /// # Errors
    /// [`AdapterError`].
    async fn generate_key(
        &self,
        grant: &GrantId,
        token: &str,
    ) -> Result<KeyRegistration, AdapterError>;

    /// Install a published certificate after the signer's own check (D2 item 6).
    ///
    /// # Errors
    /// [`AdapterError`]; a refused certificate is discarded.
    async fn install(
        &self,
        grant: &GrantId,
        entry: &IssuanceEntry,
        cert: &str,
    ) -> Result<(), AdapterError>;

    /// Unlist the identities and zeroize K_env of every grant in `grants`.
    ///
    /// # Errors
    /// [`AdapterError`].
    async fn destroy(&self, grants: &[GrantId]) -> Result<(), AdapterError>;

    /// Write a binding's files at `files.generation` (blocking pool).
    ///
    /// # Errors
    /// [`AdapterError`].
    fn materialize(
        &self,
        binding: &BindingId,
        files: &MaterializeSpec,
    ) -> Result<MaterializedFiles, AdapterError>;

    /// Remove a binding's files of `generation` only (blocking pool).
    ///
    /// # Errors
    /// [`AdapterError`].
    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError>;
}

/// ⟨r2⟩ The session-lock source (ADR-0008 D9 item 3; implemented by
/// `heimdall_runtime::session_lock`, U9, and testkit's `FakeSessionLockSource`).
///
/// Lock events **latch**: every transition into `locked` increments the epoch and
/// sets `observed`, which clears only through [`Self::acknowledge`] for that epoch,
/// after the revocation pass's revocations have committed. All methods are
/// in-memory and never block.
pub trait SessionLockSource: Send + Sync {
    /// The current state.
    fn state(&self) -> LockState;

    /// The latched epoch `{ epoch, observed }`.
    fn lock_epoch(&self) -> LockEpoch;

    /// Clear `observed` for `epoch` only (a later epoch stays latched).
    fn acknowledge(&self, epoch: u64);

    /// A wake-up on any change; no value is carried (read [`Self::state`] and
    /// [`Self::lock_epoch`] after it fires).
    fn changed(&self) -> tokio::sync::futures::Notified<'_>;
}

/// Why a connection-control call failed (ADR-0008 D8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConnError {
    /// ⟨r3⟩ The registration was refused under the gate (`LAUNCH_FAILED`, reason
    /// `connection_registration_refused`): the grant ended, is tombstoned (or an
    /// ancestor), its deadline passed, time is not `Safe`, the generation moved, or
    /// it is marked `narrowing_pending`. The reason is a fixed nonsecret word.
    #[error("connection registration refused: {0}")]
    RegistrationRefused(String),
    /// The process could not be verified as the expected client (PID, start token,
    /// image): never signalled, treated as unmanaged.
    #[error("connection identity unverified")]
    Unverified,
    /// The mechanism is not available here (no multiplexing support, path too long,
    /// or not wired in this build).
    #[error("connection control unavailable: {0}")]
    Unavailable(String),
    /// The call's bound elapsed.
    #[error("connection control timed out")]
    Timeout,
    /// An operating-system failure (bounded, nonsecret text).
    #[error("connection control failed: {0}")]
    Failed(String),
}

/// ⟨r2⟩ Owned masters and owned dedicated connections (ADR-0008 D8; U7).
///
/// Drop contract: as [`CredentialAdapter`]; a dropped `start_master` leaves no
/// master running, and `close` is bounded by the close graces of §5 item 17.
#[async_trait]
pub trait ConnectionControl: Send + Sync {
    /// Start an owned master for `pair` under `binding`.
    ///
    /// # Errors
    /// [`ConnError`].
    async fn start_master(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
    ) -> Result<OwnedConnection, ConnError>;

    /// Close `c` (re-verifying its identity before any signal).
    ///
    /// # Errors
    /// [`ConnError`].
    async fn close(&self, c: &OwnedConnection, reason: CloseReason) -> Result<(), ConnError>;

    /// ⟨r2⟩ Windows: register the still-suspended contained `ssh.exe` (U0b row 26: under
    /// the grant's gate taken shared, its transaction bounded by
    /// `connection_registration_txn_max`).
    ///
    /// # Errors
    /// [`ConnError`].
    async fn register(
        &self,
        binding: &BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &str,
    ) -> Result<OwnedConnection, ConnError>;
}

/// One managed slot (ADR-0008 D10 item 2) as `read_sources` found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSlot {
    /// The environment.
    pub environment: EnvironmentId,
    /// The pair.
    pub pair: AccessPair,
    /// Its state.
    pub state: SlotState,
}

/// One pair's prepared certificate, as the effect driver left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCertificate {
    /// The pair.
    pub pair: AccessPair,
    /// The published entry.
    pub issuance: IssuanceId,
    /// The issuing CA.
    pub ca: CaFingerprint,
    /// The certificate's `valid_before`.
    pub valid_before: Timestamp,
}

/// ⟨r2⟩ The managed effect driver's own results (ADR-0008 D6 item 0), which
/// `prepare_from` for `managed_certificate` only computes a `PrepareOutcome` from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPrepared {
    /// The credential instance.
    pub instance: CredentialInstanceId,
    /// K_env's registration.
    pub key: KeyRegistration,
    /// One certificate per pair.
    pub certificates: Vec<PreparedCertificate>,
    /// The binding's files, once materialized.
    pub materialized: Option<MaterializedFiles>,
}

/// ⟨r2⟩ The managed sources of a preparation (ADR-0008 D6 item 0; U0b row 21).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagedSources {
    /// The pairs' `verified` enrollments.
    pub enrollments: Vec<EnrollmentRecord>,
    /// Each pair's issuing-CA set (`pair_preferences.issuing_cas`).
    pub issuing_cas: BTreeMap<AccessPair, BTreeSet<CaFingerprint>>,
    /// The pairs' slots.
    pub slots: Vec<ManagedSlot>,
    /// The applicable claim-table entries (ADR-0008 D12).
    pub claims: Vec<Claim>,
    /// The issuer's status.
    pub issuer: Option<IssuerStatusSnapshot>,
    /// The effect driver's results. `None`: `prepare_from` refuses with
    /// [`crate::managed::MANAGED_PREPARE_WITHOUT_DRIVER`].
    pub prepared: Option<ManagedPrepared>,
}
