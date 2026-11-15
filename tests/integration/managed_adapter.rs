//! M03 wave 3, U6: the managed credential adapter (m03-plan U6 "Tests"; ADR-0008 D6,
//! D7, D10, D12; rulings §17.3 item 3 (Q20), §17.4, §17.17–§17.19; readings R1–R7).
//!
//! **Harness.** A state database in a scratch directory, seeded through the production
//! store and driven by the production `heimdall_app::Operations` (the
//! `tests/integration/issuer_child.rs` pattern: `VirtualClock`, `ScriptedTimeSync`). The
//! Operations' one adapter is [`Wrapped`]: its `descriptor`, `reconcile` and `revoke`
//! are the **real** `ManagedCertificateAdapter`'s; its `prepare_from` answers a fixture
//! outcome so that `ensure` can create a `managed_certificate` grant at all (in
//! production the managed adapter is not registered until U10, and `ensure` refuses
//! `driver_unavailable`; reading R5). The adapter reads the store through
//! [`StoreSources`], a test implementation of U6's source trait over the real
//! `heimdall_store::Store` (reading R6: U10 implements it in production).
//!
//! **The fixture driver** (reading R5). The stage sequence key → reserve → sign →
//! publish → install → materialize is `app::managed::drive_preparation`, U10's, which
//! fails closed. [`World::drive`] is a **test-local fixture driver**: it calls U6's real
//! `ManagedEffectsImpl` and the real `Operations::{reserve_issuance, publish_issuance}`
//! transactions in the documented order. Certificates are signed by a per-run K_ca,
//! in process (`heimdall_credential::cert::build_and_sign`, the "fixture issuer"), except
//! in `revoke_during_each_issuance_step`, which signs through a **real issuer child**
//! (`heimdall_issuer::client::ChildIssuer`, this test binary re-executed; Unix only).
//! The signer table's D2 item 6 store view (U2-Q2) is a fixture ([`StoreInstallView`],
//! over the same store; U10 wires the production one). Key destruction under the gates
//! (D7 item 2 step 2) is wired by the test's narrowing hook, calling the real adapter's
//! `revoke` at `UnderGates` (U10 wires it in production).
//!
//! Every key and CA is generated per run; nothing of the owner's is touched; no
//! listener is opened (binding endpoints are named, never bound: [`FixtureEndpoints`]).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_adapters::managed::effects::{
    BindingEndpoints, GrantScopes, ManagedEffectsImpl, ManagedSlotTable, SlotClaimError, SlotStore,
};
use heimdall_adapters::managed::files::{self, ClearOutcome, SlotRoot};
use heimdall_adapters::managed::prepare::{self, GrantTerms, ManagedSourceRead};
use heimdall_adapters::managed::reissue::{self, GrantSource, ReissueRefusal, StoreRead};
use heimdall_adapters::managed::report::{
    self, PairEvidence, ReportContext, SelectionClass, current_platform,
};
use heimdall_adapters::managed::{ManagedCertificateAdapter, RENEW_THROUGH_DRIVER, ReissueInput};
use heimdall_app::ensure::NoStageHook;
use heimdall_app::managed::MANAGED_PREPARE_WITHOUT_DRIVER;
use heimdall_app::operations::narrowing::{
    HookFuture as NarrowingFuture, NarrowingHook, NarrowingKind, NarrowingPoint,
};
use heimdall_app::operations::{
    IssuanceFacts, IssuanceRequest, Limits, MANAGED_CERTIFICATE, Publication,
};
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot, IssuerStatusSnapshot,
    KeyRegistration, ManagedEffects, ManagedPrepared, ManagedSlot, MaterializeSource,
    MaterializeSpec, MaterializedCertificate, PrepareOutcome, PreparePair, PrepareRequest,
    PreparedCertificate, ReconcileOutcome, RevokeOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, ConnectionId, CredentialInstanceId, DestinationId,
    DeviceId, EnrollmentId, EnvironmentId, GrantId, IdentityId, OperationId, PolicyId, ProfileId,
    RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
use heimdall_contract::managed::{
    ClockMeasurement, ConnectionKind, ConnectionPolicy, DestinationClock, EvidenceSource,
    ExistingConnectionsMode, IdentitySelectionEnforcement, IssuerIsolation, LockBehavior,
    LockContinuityReport, MultiplexingMode, NewSigningExpiry, OwnedConnectionReportState,
    OwnedMultiplexing, PreferredMechanism, ReadinessCondition, RemoteProcesses, RemoteRevocation,
    ResidualStatus, RevokeNote, UnmanagedConnections,
};
use heimdall_contract::provider::{CredentialAvailability, EndpointKind, EndpointRef};
use heimdall_contract::request::{
    AccessPairRef, DelegateRequest, DestinationScopeEnforcement, EnsureData, EnsureRequest,
    ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry, RefreshDependency,
    ReleaseRequest, RequiredCapabilities, RevocationStatus, RevokeData, RevokeRequest, WaitMode,
    WorkloadIsolation,
};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_credential::cert::{self, CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::endpoints::{EndpointLayout, EndpointTag};
use heimdall_credential::table::{InstallRefusal, InstallView, SignerTable};
use heimdall_credential::vault::KeyVault;
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource,
};
use heimdall_domain::claims::{BuildProfile, Claim, Platform, VersionRange};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, Determinism, EnrollmentEvidence, EnrollmentForm,
    EnrollmentRecord, EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference,
    ProjectionStatus, ProxyRoute, RawHostKey, RegistryCanonical, RegistryRef, RegistryResolvedBy,
    TargetEvaluation, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{GrantOrigin, GrantSnapshot};
use heimdall_domain::issuance::{EXTENSION_PTY, IssuanceEntry, IssuanceState, principal_for};
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState, SlotRefusal, SlotState};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Admission, Clock, SyncStatus, TimePolicy, TimeStatus};
use heimdall_issuer::store::SecretStore;
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::scratch_store::ScratchSecretStore;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};
use proptest::prelude::*;

// =================================================================================
// Time, ids, catalog
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-02T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    Timestamp::from_second(t.as_second() + secs).unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn owner() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    })
}

fn attended() -> Caller {
    Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        attendance: heimdall_app::Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn h1() -> AccessPair {
    pair("h1", "deploy")
}

fn h2() -> AccessPair {
    pair("h2", "ops")
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn facts(new_activation: bool) -> IssuanceFacts {
    IssuanceFacts {
        new_activation,
        subject_registered: true,
        critical_option: false,
    }
}

fn fixture_enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: heimdall_adapters::managed::baseline_enforcement(),
        evidence: Vec::new(),
    }
}

fn policy(pairs: &[AccessPair], lock: LockBehavior, revision: u64) -> StandingPolicy {
    StandingPolicy {
        id: policy_id(),
        revision: PolicyRevision(revision),
        profile: ProfileId::parse("dev").unwrap(),
        workspace: None,
        scope: Scope {
            pairs: pairs.iter().cloned().collect(),
            capabilities: ssh_only(),
        },
        environments: [env_id()].into_iter().collect(),
        max_window: 2 * HOUR,
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::SetupDefault,
        lock_behavior: lock,
        connection: ConnectionPolicy::default(),
    }
}

fn environment_record() -> EnvironmentRecord {
    EnvironmentRecord {
        id: env_id(),
        device: DeviceId::from_random_bytes([8; 16]),
        kind: EnvironmentKind::NativeSession,
        label: None,
        permissions: EnvironmentPermissions {
            automatic_activation: true,
            managed_signing: true,
            issuer_access: true,
        },
    }
}

fn measured() -> ClockMeasurement {
    ClockMeasurement {
        behind_upper_ms: 1400,
        rtt_ms: 38,
        measured_at: t0(),
    }
}

fn enrollment(
    seed: u8,
    ca: &CaFingerprint,
    p: &AccessPair,
    clock: Option<ClockMeasurement>,
) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([seed; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: ca.clone(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "ab".repeat(32),
        target: ApprovedTarget {
            hostname: format!("{}.example.invalid", p.destination.as_str()),
            port: 22,
            user: p.account.clone(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([1; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Verified,
        verified_at: Some(t0()),
        evidence: Some(EnrollmentEvidence {
            client: "OpenSSH_10.5p1".into(),
            server: "OpenSSH_10.0p2 Debian-7+deb13u4".into(),
            operation: OperationId::from_random_bytes([seed; 16]),
            verified_at: t0(),
            fresh_until: shift(t0(), 90 * 86_400),
            clock,
        }),
        created_at: t0(),
        updated_at: t0(),
    }
}

fn issuer_record(ca: &CaFingerprint, public: &str, created_at: Timestamp) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca.clone(),
        public_key: public.to_owned(),
        state: CaState::Active,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: "ab".repeat(32),
        backup_created_at: created_at,
        restored_without_log: false,
        created_at,
        retired_at: None,
    }
}

fn ready_issuer() -> IssuerStatusSnapshot {
    issuer_in(IssuerState::Ready)
}

fn issuer_in(state: IssuerState) -> IssuerStatusSnapshot {
    IssuerStatusSnapshot {
        status: IssuerStatus {
            state,
            reason: None,
            cas: Vec::new(),
            orphan_store_items: Vec::new(),
            issuer_isolation: IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        },
    }
}

fn identity_record() -> IdentityRecord {
    IdentityRecord {
        id: IdentityId::from_random_bytes([1; 16]),
        revision: 1,
        source: IdentitySource::PublicKeyFile {
            path: "/nonexistent/fixture.pub".into(),
        },
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".into(),
        fingerprint: "SHA256:fixture".into(),
        interaction: heimdall_domain::catalog::InteractionProfile {
            interaction: heimdall_contract::provider::InteractionKind::Unknown,
            basis: heimdall_contract::provider::EvidenceBasis::Inferred,
        },
        label: None,
        adopted_at: t0(),
        updated_at: t0(),
    }
}

/// Set a directory's permission bits (Unix; Windows has none, so it is a no-op there:
/// the Windows refusals are the DACL's, `managed_dir_windows_*`).
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn prepare_pairs(pairs: &[AccessPair]) -> Vec<PreparePair> {
    pairs
        .iter()
        .map(|p| PreparePair {
            destination: p.destination.clone(),
            account: p.account.clone(),
            identity: identity_record(),
            alias: Some(p.destination.as_str().to_owned()),
        })
        .collect()
}

// =================================================================================
// The sources (U6's source trait over the real store; U10's in production)
// =================================================================================

/// `ManagedSourceRead` + `GrantScopes` + `SlotStore` over the real store. The claim
/// table, the issuer status, the driver's results, the terms and the cascade are set
/// by the test (fixture values; U10 reads them from the runtime).
struct StoreSources {
    store: Arc<Store>,
    claims: Mutex<Vec<Claim>>,
    issuer: Mutex<Option<IssuerStatusSnapshot>>,
    prepared: Mutex<Option<ManagedPrepared>>,
    terms: Mutex<HashMap<GrantId, GrantTerms>>,
    children: Mutex<HashMap<GrantId, Vec<GrantId>>>,
    recorded: Mutex<HashMap<(GrantId, String), PrepareOutcome>>,
    key_only: AtomicBool,
    /// ⟨§17.22 item 7⟩ The evidence comparison's evaluation per alias (by default the
    /// fixture enrollment's approved target, so the evidence holds).
    targets: Mutex<HashMap<String, TargetEvaluation>>,
    /// ⟨§17.22 item 7⟩ The current verifying client's version line (by default the
    /// fixture evidence's client).
    client: Mutex<Option<String>>,
}

/// The evaluation that is exactly [`enrollment`]'s approved target for `p`.
fn approved_eval(p: &AccessPair) -> TargetEvaluation {
    TargetEvaluation {
        hostname: format!("{}.example.invalid", p.destination.as_str()),
        port: 22,
        user: p.account.as_str().to_owned(),
        proxy: ProxyRoute::None,
        determinism: Determinism::Determined,
        host_keys: vec![RawHostKey {
            key_type: "ssh-ed25519".into(),
            key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
            fingerprint: "SHA256:hostfixture".into(),
            origin_display: "fixture".into(),
            revoked: false,
        }],
    }
}

impl StoreSources {
    fn new(store: Arc<Store>) -> Arc<Self> {
        Arc::new(Self {
            store,
            claims: Mutex::new(Vec::new()),
            issuer: Mutex::new(Some(ready_issuer())),
            prepared: Mutex::new(None),
            terms: Mutex::new(HashMap::new()),
            children: Mutex::new(HashMap::new()),
            recorded: Mutex::new(HashMap::new()),
            key_only: AtomicBool::new(false),
            targets: Mutex::new(
                [h1(), h2()]
                    .iter()
                    .map(|p| (p.destination.as_str().to_owned(), approved_eval(p)))
                    .collect(),
            ),
            client: Mutex::new(Some("OpenSSH_10.5p1, LibreSSL 3.3.6".to_owned())),
        })
    }
}

impl ManagedSourceRead for StoreSources {
    fn enrollments(&self, pairs: &[AccessPair]) -> Vec<EnrollmentRecord> {
        self.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for p in pairs {
                    out.extend(tx.enrollments_for_pair(p)?);
                }
                Ok(out)
            })
            .unwrap()
    }
    fn issuing_cas(&self, pairs: &[AccessPair]) -> BTreeMap<AccessPair, BTreeSet<CaFingerprint>> {
        self.store
            .transaction(|tx| {
                let mut out = BTreeMap::new();
                for p in pairs {
                    out.insert(p.clone(), tx.verified_cas_for_pair(p)?);
                }
                Ok(out)
            })
            .unwrap()
    }
    fn slots(&self, pairs: &[AccessPair]) -> Vec<ManagedSlot> {
        self.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for p in pairs {
                    out.push(ManagedSlot {
                        environment: env_id(),
                        pair: p.clone(),
                        state: tx.slot(&env_id(), p)?,
                    });
                }
                Ok(out)
            })
            .unwrap()
    }
    fn claims(&self) -> Vec<Claim> {
        self.claims.lock().unwrap().clone()
    }
    fn issuer(&self) -> Option<IssuerStatusSnapshot> {
        self.issuer.lock().unwrap().clone()
    }
    fn prepared(&self, _pairs: &[AccessPair]) -> Option<ManagedPrepared> {
        self.prepared.lock().unwrap().clone()
    }
    fn terms(&self, grant: &GrantId) -> Option<GrantTerms> {
        self.terms.lock().unwrap().get(grant).copied()
    }
    fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
        let children = self.children.lock().unwrap();
        let mut out = vec![grant.clone()];
        let mut i = 0;
        while i < out.len() {
            if let Some(c) = children.get(&out[i]) {
                out.extend(c.iter().cloned());
            }
            i += 1;
        }
        out
    }
    fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
        self.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for g in grants {
                    out.extend(tx.issuance_entries(g)?);
                }
                Ok(out)
            })
            .unwrap()
    }
    fn key_only_restore(&self) -> bool {
        self.key_only.load(Ordering::SeqCst)
    }
    fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
        self.targets.lock().unwrap().get(alias).cloned()
    }
    fn client_version(&self) -> Option<String> {
        self.client.lock().unwrap().clone()
    }
    fn owned_connections(&self, grants: &[GrantId]) -> Vec<OwnedConnection> {
        self.store
            .transaction(|tx| {
                let mut out = Vec::new();
                for g in grants {
                    out.extend(tx.owned_connections_for_grant(g)?);
                }
                Ok(out)
            })
            .unwrap()
    }
    fn recorded_outcome(&self, grant: &GrantId, token: &str) -> Option<PrepareOutcome> {
        self.recorded
            .lock()
            .unwrap()
            .get(&(grant.clone(), token.to_owned()))
            .cloned()
    }
}

impl GrantScopes for StoreSources {
    fn pairs(&self, grant: &GrantId) -> Option<Vec<AccessPair>> {
        self.store
            .transaction(|tx| tx.grant(grant))
            .unwrap()
            .map(|g| g.scope.pairs.into_iter().collect())
    }
}

/// The slot table's store side over the real store (U10's in production).
struct StoreSlots(Arc<Store>);

impl SlotStore for StoreSlots {
    fn slot(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
    ) -> Result<SlotState, AdapterError> {
        self.0
            .transaction(|tx| tx.slot(environment, pair))
            .map_err(|e| AdapterError::Unavailable(e.to_string()))
    }
    fn claim(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
    ) -> Result<Result<SlotState, SlotRefusal>, AdapterError> {
        self.0
            .transaction(|tx| tx.claim_slot(environment, pair, binding, t0()))
            .map_err(|e| AdapterError::Unavailable(e.to_string()))
    }
}

/// Binding endpoints by name only (no listener): `EndpointLayout::binding(tag)`.
#[derive(Default)]
struct FixtureEndpoints(Mutex<HashMap<BindingId, EndpointRef>>);

impl BindingEndpoints for FixtureEndpoints {
    fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
        self.0.lock().unwrap().get(binding).cloned()
    }
}

/// The fixture D2 item 6 view (U2-Q2; U10 wires the production one): the grant usable
/// (`active`/`degraded`, no tombstone), time `Safe`, the wall before its deadline and
/// any cutoff; optionally paused (for the drop test).
struct StoreInstallView {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    timegate: heimdall_app::timegate::TimeGate,
    pause: Mutex<Option<Arc<tokio::sync::Notify>>>,
    reached: tokio::sync::Notify,
}

#[async_trait]
impl InstallView for StoreInstallView {
    async fn check(&self, grant: &GrantId, entry: &IssuanceEntry) -> Result<(), InstallRefusal> {
        let pause = self.pause.lock().unwrap().clone();
        if let Some(p) = pause {
            self.reached.notify_one();
            p.notified().await;
        }
        let now = self.clock.wall();
        let (g, tomb, cutoff) = self
            .store
            .transaction(|tx| {
                let g = tx.grant(grant)?;
                let tomb = tx.tombstone(grant)?;
                let cutoff = tx
                    .policies_for(&ProfileId::parse("dev").unwrap(), &env_id())?
                    .into_iter()
                    .filter_map(|p| p.cutoff_at)
                    .min();
                Ok((g, tomb, cutoff))
            })
            .map_err(|_| InstallRefusal::View("store"))?;
        let Some(g) = g else {
            return Err(InstallRefusal::View("no_grant"));
        };
        if !matches!(g.state, GrantState::Active | GrantState::Degraded) || tomb.is_some() {
            return Err(InstallRefusal::View("grant_not_usable"));
        }
        if self.timegate.assess_read_only(&self.store) != TimeStatus::Safe {
            return Err(InstallRefusal::View("time_uncertain"));
        }
        if now >= g.deadline.effective || cutoff.is_some_and(|c| now >= c) {
            return Err(InstallRefusal::View("deadline_passed"));
        }
        if entry.grant != *grant {
            return Err(InstallRefusal::View("entry"));
        }
        Ok(())
    }
}

// =================================================================================
// The Operations adapter: the real managed adapter, with a fixture activation
// =================================================================================

/// `descriptor`, `reconcile` and `revoke` are the real `ManagedCertificateAdapter`'s.
/// `prepare`/`prepare_from` answer a fixture outcome bounded by the grant's deadline,
/// so `ensure` creates a `managed_certificate` grant (U10's driver is not wired).
struct Wrapped {
    managed: Arc<ManagedCertificateAdapter>,
    revoke_delay: Mutex<Option<Duration>>,
    revokes: AtomicUsize,
}

fn fixture_outcome(req: &PrepareRequest<'_>) -> PrepareOutcome {
    PrepareOutcome {
        usable_until: req.grant.deadline.effective,
        offline_until: req.grant.deadline.effective,
        refresh_dependency: RefreshDependency::LocalIssuer,
        enforcement: fixture_enforcement(),
        credential_ref: "fixture-activation".into(),
        availability: CredentialAvailability::ThroughDeadline,
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

#[async_trait]
impl CredentialAdapter for Wrapped {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.managed.descriptor()
    }
    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        Ok(fixture_outcome(&req))
    }
    fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
        IntegrationSnapshot::default()
    }
    async fn prepare_from(
        &self,
        req: PrepareRequest<'_>,
        _sources: &IntegrationSnapshot,
    ) -> Result<PrepareOutcome, AdapterError> {
        Ok(fixture_outcome(&req))
    }
    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.managed.renew(req).await
    }
    async fn reconcile(
        &self,
        grant: &GrantId,
        token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        self.managed.reconcile(grant, token).await
    }
    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError> {
        self.revokes.fetch_add(1, Ordering::SeqCst);
        let delay = *self.revoke_delay.lock().unwrap();
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        self.managed.revoke(grant, now).await
    }
}

// =================================================================================
// The narrowing hook: key destruction under the gates through the real adapter
// =================================================================================

#[derive(Default)]
struct Hook {
    adapter: Mutex<Option<Arc<ManagedCertificateAdapter>>>,
    gates: Mutex<Option<heimdall_app::managed::SigningGates>>,
    clock: Mutex<Option<Arc<VirtualClock>>>,
    /// Per destroyed grant: whether its gate was held exclusively (a shared
    /// acquisition with no wait timed out) when its key was destroyed.
    exclusive_at_destroy: Mutex<Vec<(GrantId, bool, bool)>>,
}

impl NarrowingHook for Hook {
    fn at<'a>(&'a self, _kind: NarrowingKind, point: NarrowingPoint) -> NarrowingFuture<'a> {
        Box::pin(async move {
            if let NarrowingPoint::UnderGates { destroy, .. } = &point {
                let adapter = self.adapter.lock().unwrap().clone();
                let gates = self.gates.lock().unwrap().clone();
                let now = self.clock.lock().unwrap().as_ref().map(|c| c.wall());
                if let (Some(a), Some(now)) = (adapter, now) {
                    for g in destroy {
                        let exclusive = match &gates {
                            Some(gs) => gs.acquire_shared(g, Duration::ZERO).await.is_err(),
                            None => false,
                        };
                        let had_key = a
                            .effects()
                            .is_some_and(|e| e.table().public_key(g).is_some());
                        a.revoke(g, now).await.unwrap();
                        self.exclusive_at_destroy.lock().unwrap().push((
                            g.clone(),
                            exclusive,
                            had_key,
                        ));
                    }
                }
            }
        })
    }
}

// =================================================================================
// The world and the fixture driver
// =================================================================================

struct Opts {
    pairs: Vec<AccessPair>,
    clock: Option<ClockMeasurement>,
    enroll: bool,
    limits: Limits,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            pairs: vec![h1(), h2()],
            clock: Some(measured()),
            enroll: true,
            limits: Limits::default(),
        }
    }
}

struct World {
    dir: tempfile::TempDir,
    // Read by the Unix issuer-child cases only.
    #[cfg_attr(not(unix), allow(dead_code))]
    db: PathBuf,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    ops: Operations,
    sources: Arc<StoreSources>,
    endpoints: Arc<FixtureEndpoints>,
    layout: EndpointLayout,
    view: Arc<StoreInstallView>,
    effects: ManagedEffectsImpl,
    adapter: Arc<ManagedCertificateAdapter>,
    wrapped: Arc<Wrapped>,
    hook: Arc<Hook>,
    ca: SecretCaKey,
    ca_fp: CaFingerprint,
    /// CAs registered later (rotation), by fingerprint.
    extra_cas: Mutex<Vec<(CaFingerprint, Arc<SecretCaKey>)>>,
}

/// How far the fixture driver goes (the stages of ADR-0008 D6 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Key,
    Reserve,
    Sign,
    Publish,
    Install,
    Materialize,
}

const STAGES: [Stage; 6] = [
    Stage::Key,
    Stage::Reserve,
    Stage::Sign,
    Stage::Publish,
    Stage::Install,
    Stage::Materialize,
];

/// What the fixture driver did.
#[derive(Debug, Clone, Default)]
struct Driven {
    key: Option<KeyRegistration>,
    reserved: Vec<IssuanceEntry>,
    certs: Vec<(AccessPair, String)>,
    published: Vec<IssuanceEntry>,
    binding: Option<BindingId>,
    prepared: Option<ManagedPrepared>,
}

impl World {
    async fn new() -> Self {
        Self::with(Opts::default()).await
    }

    async fn with(o: Opts) -> Self {
        let dir = tempfile::tempdir().unwrap();
        owner_only_anchor(&dir.path().join("state"));
        owner_only_anchor(&dir.path().join("run"));
        let db = dir.path().join("state").join("state.db");
        let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
        let ca = SecretCaKey::generate().unwrap();
        let ca_fp = ca.fingerprint().unwrap();
        let ca_public = ca.public_openssh().unwrap();
        std::fs::create_dir(dir.path().join("store")).unwrap();
        ScratchSecretStore::new(dir.path().join("store"))
            .put(&ca_fp, &ca)
            .unwrap();
        let profile_pairs = [h1(), h2()];
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&environment_record())?;
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: Scope {
                        pairs: profile_pairs.iter().cloned().collect(),
                        capabilities: ssh_only(),
                    },
                    label: None,
                })?;
                tx.upsert_policy(&policy(&profile_pairs, LockBehavior::Continue, 1), false)?;
                for p in &profile_pairs {
                    tx.upsert_destination(&DestinationRecord {
                        id: p.destination.clone(),
                        alias: p.destination.as_str().into(),
                        revision: 1,
                        definition: DestinationDefinition::Observed,
                        label: None,
                        updated_at: t0(),
                    })?;
                }
                tx.insert_issuer(&issuer_record(&ca_fp, &ca_public, t0()))?;
                if o.enroll {
                    for (i, p) in o.pairs.iter().enumerate() {
                        let seed = u8::try_from(i + 1).unwrap();
                        tx.seed_enrollment(&enrollment(seed, &ca_fp, p, o.clock))?;
                    }
                }
                Ok(())
            })
            .unwrap();
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let sources = StoreSources::new(store.clone());
        let view = Arc::new(StoreInstallView {
            store: store.clone(),
            clock: clock.clone(),
            timegate: heimdall_app::timegate::TimeGate::new(
                store.clone(),
                clock.clone(),
                sync.clone(),
                TimePolicy::default(),
            ),
            pause: Mutex::new(None),
            reached: tokio::sync::Notify::new(),
        });
        let table = SignerTable::new(Arc::new(KeyVault::new()));
        table.set_install_view(view.clone());
        let endpoints = Arc::new(FixtureEndpoints::default());
        let runtime_dir = dir.path().join("run");
        let layout = EndpointLayout::unix(&runtime_dir).unwrap();
        let effects = ManagedEffectsImpl::new(
            table,
            endpoints.clone(),
            sources.clone(),
            runtime_dir,
            SlotRoot {
                data_dir: dir.path().join("state"),
                environment: env_id(),
            },
        )
        .with_slot_store(Arc::new(StoreSlots(store.clone())));
        let adapter = Arc::new(ManagedCertificateAdapter::new(
            "fixture-1",
            sources.clone(),
            Some(effects.clone()),
            Some(layout.clone()),
        ));
        let wrapped = Arc::new(Wrapped {
            managed: adapter.clone(),
            revoke_delay: Mutex::new(None),
            revokes: AtomicUsize::new(0),
        });
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: sync.clone(),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: vec![wrapped.clone() as Arc<dyn CredentialAdapter>],
            stage_hook: Arc::new(NoStageHook),
            limits: o.limits,
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        let hook = Arc::new(Hook::default());
        *hook.adapter.lock().unwrap() = Some(adapter.clone());
        *hook.gates.lock().unwrap() = Some(ops.signing_gates().clone());
        *hook.clock.lock().unwrap() = Some(clock.clone());
        ops.set_narrowing_hook(hook.clone());
        Self {
            dir,
            db,
            store,
            clock,
            sync,
            ops,
            sources,
            endpoints,
            layout,
            view,
            effects,
            adapter,
            wrapped,
            hook,
            ca,
            ca_fp,
            extra_cas: Mutex::new(Vec::new()),
        }
    }

    fn wall(&self) -> Timestamp {
        Clock::wall(self.clock.as_ref())
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    fn table(&self) -> &SignerTable {
        self.effects.table()
    }

    fn grant(&self, id: &GrantId) -> GrantSnapshot {
        self.store.transaction(|tx| tx.grant(id)).unwrap().unwrap()
    }

    fn entries(&self, id: &GrantId) -> Vec<IssuanceEntry> {
        self.store
            .transaction(|tx| tx.issuance_entries(id))
            .unwrap()
    }

    fn origin(&self, id: &GrantId) -> GrantOrigin {
        self.store
            .transaction(|tx| tx.grant_origin(id))
            .unwrap()
            .unwrap()
    }

    async fn ensure(&self, tag: &str, pairs: &[AccessPair]) -> EnsureData {
        self.try_ensure(tag, pairs, RequiredCapabilities::default())
            .await
            .unwrap_or_else(|e| panic!("ensure {tag}: {} {}", e.code, e.message))
    }

    async fn try_ensure(
        &self,
        tag: &str,
        pairs: &[AccessPair],
        required: RequiredCapabilities,
    ) -> Result<EnsureData, heimdall_app::error::OpError> {
        self.ops
            .ensure(
                &owner(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: pairs.iter().cloned().collect(),
                    environment: None,
                    work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                    until: None,
                    required_capabilities: required,
                    request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            )
            .await
            .map(|c| c.data)
    }

    async fn revoke(&self, grant: &GrantId, rid: &str) -> RevokeData {
        match self
            .ops
            .revoke(
                &owner(),
                RevokeRequest {
                    grant_id: grant.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await
        {
            Ok(c) => c.data,
            Err(e) => panic!("revoke {rid}: {} {}", e.code, e.message),
        }
    }

    /// The reservation request of the fixture driver (ADR-0005 §3.4 bounds:
    /// `valid_after` = now − 60 s, `valid_before` = the grant's effective deadline).
    fn request(
        &self,
        grant: &GrantSnapshot,
        p: &AccessPair,
        fp: &str,
        new_activation: bool,
    ) -> IssuanceRequest {
        IssuanceRequest {
            grant: grant.id.clone(),
            pair: p.clone(),
            principal: principal_for(p),
            key_id: cert::key_id(&env_id(), &grant.id, 1),
            valid_after: shift(self.wall(), -60),
            valid_before: grant.deadline.effective,
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: fp.to_owned(),
            facts: facts(new_activation),
        }
    }

    /// The fixture issuer: K_ca signs exactly the reserved bounds, in process.
    fn sign(&self, grant: &GrantId, entry: &IssuanceEntry) -> String {
        let key = self.table().public_key(grant).expect("a live key");
        let extra = self
            .extra_cas
            .lock()
            .unwrap()
            .iter()
            .find(|(fp, _)| entry.bounds.ca_fingerprint.as_ref() == Some(fp))
            .map(|(_, k)| k.clone());
        let ca: &SecretCaKey = match &extra {
            Some(k) => k,
            None => &self.ca,
        };
        build_and_sign(
            &CertificateProfile::from_bounds(&entry.bounds),
            &key.public_key().unwrap(),
            ca,
        )
        .unwrap()
        .to_openssh()
        .unwrap()
    }

    /// Publish (with the re-reservation round trips of ADR-0006 §13.8 item 1).
    async fn publish(
        &self,
        grant: &GrantId,
        mut entry: IssuanceEntry,
        new_activation: bool,
    ) -> Result<(IssuanceEntry, String), heimdall_app::error::OpError> {
        let mut cert = self.sign(grant, &entry);
        for _ in 0..3 {
            match self
                .ops
                .publish_issuance(&entry.id, &facts(new_activation))
                .await?
            {
                Publication::Published(e) => return Ok((e, cert)),
                Publication::Rereserved { reservation } => {
                    entry = reservation;
                    cert = self.sign(grant, &entry);
                }
            }
        }
        panic!("too many re-reservations");
    }

    /// **The test-local fixture driver** (reading R5): D6 item 1's stages through
    /// U6's real effects and the real `Operations` transactions, up to `until`
    /// inclusive. The gate is retained with the key (U10 wires it: §17.15).
    async fn drive(&self, data: &EnsureData, token: &str, until: Stage) -> Driven {
        self.drive_with(data, token, until, true, &[]).await
    }

    async fn drive_with(
        &self,
        data: &EnsureData,
        token: &str,
        until: Stage,
        new_activation: bool,
        ancestors: &[GrantId],
    ) -> Driven {
        let gid = &data.grant_id;
        let grant = self.grant(gid);
        let mut d = Driven::default();
        // 0. the grant's terms, as U10 records them at activation (U6-Q5; a test that
        // set them first keeps its own).
        self.sources
            .terms
            .lock()
            .unwrap()
            .entry(gid.clone())
            .or_default();
        // 1. key
        let key = self.effects.generate_key(gid, token).await.unwrap();
        self.ops.signing_gates().retain(gid, ancestors);
        d.key = Some(key.clone());
        if until == Stage::Key {
            return d;
        }
        // 2. reserve
        for p in &grant.scope.pairs {
            let e = self
                .ops
                .reserve_issuance(self.request(&grant, p, &key.fingerprint, new_activation))
                .await
                .unwrap_or_else(|e| panic!("reserve: {} {}", e.code, e.message));
            d.reserved.push(e);
        }
        if until == Stage::Reserve {
            return d;
        }
        // 3. sign
        for e in &d.reserved {
            d.certs.push((e.pair.clone(), self.sign(gid, e)));
        }
        if until == Stage::Sign {
            return d;
        }
        // 4. publish
        let mut certs = Vec::new();
        for e in d.reserved.clone() {
            let (published, cert) = self.publish(gid, e, new_activation).await.unwrap();
            certs.push((published.pair.clone(), cert));
            d.published.push(published);
        }
        d.certs = certs;
        if until == Stage::Publish {
            return d;
        }
        // 5. install
        for (e, (_, c)) in d.published.iter().zip(&d.certs) {
            self.effects.install(gid, e, c).await.unwrap();
        }
        if until == Stage::Install {
            return d;
        }
        // 6. materialize (the binding's files; no environment slot)
        let tag = EndpointTag::generate().unwrap();
        self.endpoints
            .0
            .lock()
            .unwrap()
            .insert(data.binding_id.clone(), self.layout.binding(&tag));
        self.table().attach_binding(&data.binding_id, gid);
        let files = self
            .effects
            .materialize(
                &data.binding_id,
                &MaterializeSpec {
                    generation: 1,
                    source: MaterializeSource::Fresh {
                        public_key: key.public_key.clone(),
                        certificates: d
                            .certs
                            .iter()
                            .map(|(p, c)| MaterializedCertificate {
                                pair: p.clone(),
                                certificate: c.clone(),
                            })
                            .collect(),
                    },
                    environment_slots: false,
                },
            )
            .unwrap();
        d.binding = Some(data.binding_id.clone());
        let prepared = ManagedPrepared {
            instance: CredentialInstanceId::from_random_bytes([9; 16]),
            key,
            certificates: d
                .published
                .iter()
                .map(|e| PreparedCertificate {
                    pair: e.pair.clone(),
                    issuance: e.id.clone(),
                    ca: e.bounds.ca_fingerprint.clone().unwrap(),
                    valid_before: e.bounds.valid_before,
                })
                .collect(),
            materialized: Some(files),
        };
        *self.sources.prepared.lock().unwrap() = Some(prepared.clone());
        d.prepared = Some(prepared);
        d
    }

    /// `prepare_from` through the real adapter, over a fresh `read_sources`.
    async fn prepare_from(
        &self,
        grant: &GrantSnapshot,
        pairs: &[AccessPair],
        required: &RequiredCapabilities,
    ) -> Result<PrepareOutcome, AdapterError> {
        let pp = prepare_pairs(pairs);
        let scope = grant.scope.clone();
        let snap = self.adapter.read_sources(&pp);
        self.adapter
            .prepare_from(
                PrepareRequest {
                    grant,
                    scope: &scope,
                    required,
                    interactive: false,
                    effect_token: "tok",
                    now: self.wall(),
                    pairs: &pp,
                },
                &snap,
            )
            .await
    }

    /// No leftover vault slot (the vault-slot counter: `KeyVault::len`, a public
    /// accessor, read only by tests): every key this world generated is destroyed.
    async fn finish(self, grants: &[GrantId]) {
        self.effects.destroy(grants).await.unwrap();
        assert_eq!(self.table().vault().len(), 0, "leftover vault slots");
    }
}

// =================================================================================
// Files (R1–R3): agreement with `connect_cmd::binding_files`, atomic, by generation
// =================================================================================

/// R2: `binding_files_for_endpoint` derives the paths `heimdall::connect_cmd::
/// binding_files` derives (its test's expectations, byte for byte), and refuses what
/// it refuses.
#[test]
fn binding_files_for_endpoint_agrees_with_connect_cmd() {
    let rd = Path::new("/run/user/1000/heimdall");
    let dest = DestinationId::parse("dst-w").unwrap();
    let unix = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: "/run/user/1000/heimdall/b/0123456789abcdef/agent.sock".into(),
    };
    let f = files::binding_files_for_endpoint(rd, &unix, std::slice::from_ref(&dest)).unwrap();
    // connect_cmd: `socket.parent()` joined with the file names.
    let dir = Path::new("/run/user/1000/heimdall/b/0123456789abcdef");
    assert_eq!(f.directory, dir);
    assert_eq!(f.key_pub, dir.join("key.pub"));
    assert_eq!(f.certificate(&dest).unwrap(), dir.join("cert-dst-w.pub"));
    if cfg!(unix) {
        assert_eq!(
            f.key_pub.to_str().unwrap(),
            "/run/user/1000/heimdall/b/0123456789abcdef/key.pub"
        );
        assert_eq!(
            f.certificate(&dest).unwrap().to_str().unwrap(),
            "/run/user/1000/heimdall/b/0123456789abcdef/cert-dst-w.pub"
        );
    }
    // The producer's own path function agrees.
    let tag = EndpointTag::parse("0123456789abcdef").unwrap();
    assert_eq!(
        files::binding_files(rd, &tag, std::slice::from_ref(&dest)).unwrap(),
        f
    );
    for bad in [
        "/run/user/1000/heimdall/signing.sock",
        "/run/user/1000/heimdall/b/0123456789ABCDEF/agent.sock",
        "/elsewhere/b/0123456789abcdef/agent.sock",
        "/run/user/1000/heimdall/b/0123456789abcdef/other.sock",
        "/run/user/1000/heimdall/v/0123456789abcdef/agent.sock",
    ] {
        let e = EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: bad.into(),
        };
        assert!(
            files::binding_files_for_endpoint(rd, &e, std::slice::from_ref(&dest)).is_none(),
            "{bad}"
        );
    }
    let unsafe_dest = DestinationId::parse("a:b").unwrap();
    assert!(files::binding_files_for_endpoint(rd, &unix, &[unsafe_dest]).is_none());
    // Windows: `<runtime_dir>/b/<tag>` from the pipe name.
    let wrd = Path::new(r"C:\Users\fx\AppData\Local\heimdall\run");
    let pipe = EndpointRef {
        kind: EndpointKind::NamedPipe,
        locator: r"\\.\pipe\heimdall-tok-b0123456789abcdef".into(),
    };
    let w = files::binding_files_for_endpoint(wrd, &pipe, std::slice::from_ref(&dest)).unwrap();
    assert_eq!(w.directory, wrd.join("b").join("0123456789abcdef"));
    assert_eq!(
        w.key_pub,
        wrd.join("b").join("0123456789abcdef").join("key.pub")
    );
    assert_eq!(
        w.certificate(&dest).unwrap(),
        wrd.join("b")
            .join("0123456789abcdef")
            .join("cert-dst-w.pub")
    );
    let env_pipe = EndpointRef {
        kind: EndpointKind::NamedPipe,
        locator: r"\\.\pipe\heimdall-tok-signing".into(),
    };
    assert!(files::binding_files_for_endpoint(wrd, &env_pipe, &[dest]).is_none());
}

/// The binding and slot files: exactly one line each (R3), atomic, generation-bound
/// (a clear of g never touches g + 1), refusing unsafe destination IDs.
#[test]
fn slot_and_binding_files_are_generation_bound() {
    let dir = tempfile::tempdir().unwrap();
    // The anchors exist (the state and runtime directories); every level below them is
    // created owner-only (§17.20 item 7).
    owner_only_anchor(&dir.path().join("state"));
    owner_only_anchor(&dir.path().join("run"));
    let root = SlotRoot {
        data_dir: dir.path().join("state"),
        environment: env_id(),
    };
    let b1 = BindingId::from_random_bytes([1; 16]);
    let b2 = BindingId::from_random_bytes([2; 16]);
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkey heimdall:x";
    let cert = "ssh-ed25519-cert-v01@openssh.com AAAAIGNlcnQ= heimdall:x";
    let written = files::write_slot(&root, &env_id(), &h1(), &b1, 1, key, cert).unwrap();
    let paths = files::slot_paths(&root.data_dir, &h1()).unwrap();
    assert_eq!(written, vec![paths.key_pub.clone(), paths.cert_pub.clone()]);
    assert_eq!(
        std::fs::read_to_string(&paths.cert_pub).unwrap(),
        format!("{cert}\n")
    );
    assert_eq!(
        std::fs::read_to_string(&paths.key_pub).unwrap(),
        format!("{key}\n")
    );
    assert_eq!(files::slot_generation(&root, &h1()).unwrap(), Some(1));
    // g + 1 (another holder) replaces it; a late clear of g touches nothing.
    files::write_slot(&root, &env_id(), &h1(), &b2, 2, key, cert).unwrap();
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 1).unwrap(),
        ClearOutcome::OtherGeneration(2)
    );
    assert!(paths.cert_pub.exists() && paths.key_pub.exists());
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 2).unwrap(),
        ClearOutcome::Removed
    );
    assert!(!paths.cert_pub.exists() && !paths.key_pub.exists());
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 2).unwrap(),
        ClearOutcome::Absent
    );
    // Files without a marker are not provably ours: left untouched.
    std::fs::write(&paths.cert_pub, "foreign\n").unwrap();
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 3).unwrap(),
        ClearOutcome::Unmarked
    );
    assert!(paths.cert_pub.exists());
    // Never a key line as the certificate (R3), never two lines, never another
    // environment's slot, never an unsafe destination ID.
    assert!(files::write_slot(&root, &env_id(), &h2(), &b1, 1, key, key).is_err());
    assert!(
        files::write_slot(
            &root,
            &env_id(),
            &h2(),
            &b1,
            1,
            key,
            &format!("{cert}\n{cert}")
        )
        .is_err()
    );
    let other = EnvironmentId::from_random_bytes([9; 16]);
    assert!(files::write_slot(&root, &other, &h2(), &b1, 1, key, cert).is_err());
    assert!(
        files::write_slot(&root, &env_id(), &pair("a:b", "deploy"), &b1, 1, key, cert).is_err()
    );
    // No temporary file is left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&paths.dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());

    // Binding files, by generation and holder.
    let rd = dir.path().join("run");
    let tag = EndpointTag::parse("00112233aabbccdd").unwrap();
    let bf = files::binding_files(&rd, &tag, &[h1().destination, h2().destination]).unwrap();
    let certs = vec![
        (h1().destination, cert.to_owned()),
        (h2().destination, cert.to_owned()),
    ];
    let w = files::write_binding_files(&bf, &b1, 4, key, &certs).unwrap();
    assert_eq!(w.len(), 3);
    assert_eq!(
        std::fs::read_to_string(bf.certificate(&h2().destination).unwrap()).unwrap(),
        format!("{cert}\n")
    );
    assert_eq!(
        files::binding_directories_of(&rd, &b1).unwrap(),
        vec![(bf.directory.clone(), 4)]
    );
    assert_eq!(
        files::clear_binding_files(&bf, &b1, 3).unwrap(),
        ClearOutcome::OtherGeneration(4)
    );
    assert_eq!(
        files::clear_binding_files(&bf, &b2, 4).unwrap(),
        ClearOutcome::OtherGeneration(4),
        "another holder's clear of the same number touches nothing"
    );
    assert!(bf.key_pub.exists());
    assert_eq!(
        files::clear_binding_files(&bf, &b1, 4).unwrap(),
        ClearOutcome::Removed
    );
    assert!(!bf.key_pub.exists());
    assert!(!bf.certificate(&h1().destination).unwrap().exists());
}

// =================================================================================
// Positive
// =================================================================================

#[tokio::test]
async fn activation_issues_one_certificate_per_pair_covering_grant() {
    let w = World::new().await;
    let data = w.ensure("act", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    let d = w.drive(&data, "tok-act", Stage::Materialize).await;
    let grant = w.grant(&gid);
    let entries = w.entries(&gid);
    assert_eq!(entries.len(), 2, "one certificate per pair: {entries:?}");
    for p in [h1(), h2()] {
        let mine: Vec<&IssuanceEntry> = entries.iter().filter(|e| e.pair == p).collect();
        assert_eq!(mine.len(), 1);
        let e = mine[0];
        assert_eq!(e.state, IssuanceState::Published);
        assert_eq!(e.bounds.principal, principal_for(&p));
        assert_eq!(e.bounds.ca_fingerprint.as_ref(), Some(&w.ca_fp));
        assert_eq!(
            e.bounds.valid_before, grant.deadline.effective,
            "the one certificate covers the whole grant (D6 item 3)"
        );
    }
    assert_eq!(w.table().installed_entries(&gid).len(), 2);
    assert_eq!(
        w.table().instance_state(&gid),
        Some(heimdall_domain::issuance::CredentialState::Installed)
    );
    // The binding files hold exactly the certificate the alias names (R3).
    let prepared = d.prepared.clone().unwrap();
    let mat = prepared.materialized.clone().unwrap();
    let key = d.key.clone().unwrap();
    let bf = files::binding_files_for_endpoint(
        &w.runtime_dir(),
        &w.endpoints.binding_endpoint(&data.binding_id).unwrap(),
        &[h1().destination, h2().destination],
    )
    .unwrap();
    assert_eq!(bf.directory, mat.directory);
    assert_eq!(
        std::fs::read_to_string(&bf.key_pub).unwrap(),
        format!("{}\n", key.public_key.trim_end())
    );
    for (p, c) in &d.certs {
        assert_eq!(
            std::fs::read_to_string(bf.certificate(&p.destination).unwrap()).unwrap(),
            format!("{c}\n")
        );
    }
    // prepare_from computes the outcome only from the snapshot and the driver results.
    let o = w
        .prepare_from(&grant, &[h1(), h2()], &RequiredCapabilities::default())
        .await
        .unwrap();
    assert_eq!(o.usable_until, grant.deadline.effective);
    assert_eq!(o.offline_until, grant.deadline.effective);
    assert_eq!(o.availability, CredentialAvailability::ThroughDeadline);
    assert_eq!(o.refresh_dependency, RefreshDependency::LocalIssuer);
    // The wave-2 request: the consumer integration names the **binding** endpoint.
    let endpoint = w.endpoints.binding_endpoint(&data.binding_id).unwrap();
    assert_eq!(
        o.integration.signing_endpoint.as_deref(),
        Some(endpoint.locator.as_str())
    );
    assert!(
        o.integration
            .pairs
            .iter()
            .all(|p| p.mechanism == MANAGED_CERTIFICATE && p.endpoint.as_ref() == Some(&endpoint))
    );
    w.finish(&[gid]).await;
}

/// The golden of §5 item 7 (ADR-0005 §7.2), computed with an **empty** claim table.
#[tokio::test]
async fn report_for_local_managed_binding_with_empty_claim_table() {
    let golden = include_str!("../../schemas/examples/ensure-data.managed.json");
    let w = World::new().await;
    let data = w.ensure("golden", &[h1()]).await;
    let mut g = w.grant(&data.grant_id);
    let dest_lab = pair("dest-lab", "deploy");
    g.scope.pairs = [dest_lab.clone()].into_iter().collect();
    g.deadline.effective = "2026-11-10T22:00:00Z".parse().unwrap();
    let measured_at: Timestamp = "2026-11-10T13:50:00Z".parse().unwrap();
    let evidence = EnrollmentEvidence {
        client: "OpenSSH_10.5p1".into(),
        server: "OpenSSH_10.0p2 Debian-7+deb13u4".into(),
        operation: OperationId::parse("op_00112233445566778899aabbccddeeff").unwrap(),
        verified_at: measured_at,
        fresh_until: "2027-02-08T13:50:00Z".parse().unwrap(),
        clock: Some(ClockMeasurement {
            behind_upper_ms: 1400,
            rtt_ms: 38,
            measured_at,
        }),
    };
    let prepared = ManagedPrepared {
        instance: CredentialInstanceId::from_random_bytes([3; 16]),
        key: KeyRegistration {
            public_key: "ssh-ed25519 AAAA".into(),
            fingerprint: "SHA256:x".into(),
            slot: "00".into(),
        },
        certificates: vec![PreparedCertificate {
            pair: dest_lab.clone(),
            issuance: heimdall_contract::ids::IssuanceId::from_random_bytes([4; 16]),
            ca: w.ca_fp.clone(),
            valid_before: g.deadline.effective,
        }],
        materialized: None,
    };
    let windows = Platform {
        os: "windows",
        arch: "x86_64",
    };
    let ctx = ReportContext {
        platform: windows,
        lock_behavior: LockBehavior::Continue,
        policy: ConnectionPolicy::default(),
        issuer_ready: true,
        reissue_pending: false,
        now: measured_at,
        selection: SelectionClass::Exclusive,
    };
    let ev: Vec<PairEvidence<'_>> = vec![(&dest_lab, &evidence)];
    let r = report::compute(&g, &prepared, &[], &ctx, &ev);
    let deadline = g.deadline.effective;
    assert_eq!((r.usable_until, r.offline_until), (deadline, deadline));
    assert_eq!(r.refresh_dependency, RefreshDependency::LocalIssuer);
    assert_eq!(
        r.conditions,
        vec![
            ReadinessCondition::SignerRunning,
            ReadinessCondition::TimeConfirmationAfterReboot
        ]
    );
    assert_eq!(r.availability, CredentialAvailability::ThroughDeadline);
    assert_eq!(r.lock_continuity, LockContinuityReport::NotVerified);
    let e = &r.enforcement;
    assert_eq!(
        e.destination_scope,
        DestinationScopeEnforcement::VerifiedServerPrincipals
    );
    assert_eq!(
        e.new_authentication_expiry,
        NewAuthenticationExpiry::Unknown
    );
    assert_eq!(e.workload_isolation, WorkloadIsolation::SharedOsUser);
    assert_eq!(e.existing_connections, ExistingConnectionsPolicy::Unknown);
    assert_eq!(e.revocation, RevocationStatus::Unknown);
    assert_eq!(
        e.identity_selection(),
        IdentitySelectionEnforcement::ClientConfigurationAndSigner
    );
    assert_eq!(e.new_signing_expiry(), NewSigningExpiry::Unknown);
    assert_eq!(e.owned_multiplexing(), OwnedMultiplexing::Disabled);
    assert_eq!(e.remote_processes(), RemoteProcesses::NotTerminated);
    assert_eq!(
        e.unmanaged_connections(),
        UnmanagedConnections::NotControlled
    );
    assert_eq!(e.issuer_isolation(), IssuerIsolation::SameUserProcess);
    assert_eq!(r.revocation.remote, RemoteRevocation::Unknown);
    assert_eq!(
        r.revocation.latest_possible_credential_expiry,
        Some(deadline)
    );
    assert_eq!(
        r.revocation.destination_clock,
        DestinationClock::Measured(ClockMeasurement {
            behind_upper_ms: 1400,
            rtt_ms: 38,
            measured_at
        })
    );
    assert_eq!(r.evidence.len(), 1);
    let ev0 = &r.evidence[0];
    assert_eq!(ev0.field, "destination_scope");
    assert_eq!(ev0.source, EvidenceSource::RuntimeVerification);
    assert_eq!(
        ev0.pair,
        Some(AccessPairRef {
            destination: dest_lab.destination.clone(),
            account: dest_lab.account.clone()
        })
    );
    assert_eq!(ev0.observed_at, measured_at);
    assert_eq!(ev0.fresh_until, Some(evidence.fresh_until));
    assert_eq!(
        r.connection_policy.existing,
        ExistingConnectionsMode::Graceful
    );
    assert_eq!(r.connection_policy.multiplexing, MultiplexingMode::Disabled);
    // The golden carries exactly these values (every report field; `consumer` below).
    for fragment in [
        "\"usable_until\": \"2026-11-10T22:00:00Z\"",
        "\"offline_until\": \"2026-11-10T22:00:00Z\"",
        "\"refresh_dependency\": \"local_issuer\"",
        "\"needed_only_after\": \"signer_restart\"",
        "\"signer_running\",\n    \"time_confirmation_after_reboot\"\n  ]",
        "\"credential_availability\": \"through_deadline\"",
        "\"lock_continuity\": \"not_verified\"",
        "\"destination_scope\": \"verified_server_principals\"",
        "\"new_authentication_expiry\": \"unknown\"",
        "\"workload_isolation\": \"shared_os_user\"",
        "\"existing_connections\": \"unknown\"",
        "\"revocation\": \"unknown\"",
        "\"identity_selection\": \"client_configuration_and_signer\"",
        "\"new_signing_expiry\": \"unknown\"",
        "\"owned_multiplexing\": \"disabled\"",
        "\"remote_processes\": \"not_terminated\"",
        "\"unmanaged_connections\": \"not_controlled\"",
        "\"issuer_isolation\": \"same_user_process\"",
        "\"local\": \"immediate\"",
        "\"remote\": \"unknown\"",
        "\"latest_possible_credential_expiry\": \"2026-11-10T22:00:00Z\"",
        "\"behind_upper_ms\": 1400",
        "\"rtt_ms\": 38",
        "\"measured_at\": \"2026-11-10T13:50:00Z\"",
        "\"source\": \"runtime_verification\"",
        "\"destination\": \"dest-lab\"",
        "\"operation_id\": \"op_00112233445566778899aabbccddeeff\"",
        "\"client\": \"OpenSSH_10.5p1\"",
        "\"server\": \"OpenSSH_10.0p2 Debian-7+deb13u4\"",
        "\"fresh_until\": \"2027-02-08T13:50:00Z\"",
        "\"existing\": \"graceful\"",
        "\"multiplexing\": \"disabled\"",
    ] {
        assert!(golden.contains(fragment), "golden lacks {fragment}");
    }
    assert!(golden.contains(&format!("\"wording\": \"{}\"", r.connection_policy.wording)));
    // §17.20 item 9 (W3-R07): the wording is U8's `deadline_wording` for the selection
    // and the policy, never retyped; D8 item 3's disclosure follows when owned masters
    // are applied (never on Windows, where they are unavailable).
    use heimdall_contract::provider::IdentitySelection;
    use heimdall_localenv::projection::plan::deadline_wording;
    assert_eq!(
        r.connection_policy.wording,
        deadline_wording(
            IdentitySelection::Exclusive,
            ExistingConnectionsMode::Graceful
        )
    );
    let masters = ConnectionPolicy {
        existing: ExistingConnectionsMode::Graceful,
        multiplexing: MultiplexingMode::OwnedMasters,
    };
    let strict = ConnectionPolicy {
        existing: ExistingConnectionsMode::Strict,
        multiplexing: MultiplexingMode::Disabled,
    };
    let mac = Platform {
        os: "macos",
        arch: "aarch64",
    };
    for (selection, policy, platform, expected) in [
        (
            SelectionClass::Undetermined,
            ConnectionPolicy::default(),
            windows,
            deadline_wording(
                IdentitySelection::Undetermined,
                ExistingConnectionsMode::Graceful,
            )
            .to_owned(),
        ),
        (
            SelectionClass::NotExclusive,
            strict,
            windows,
            deadline_wording(
                IdentitySelection::NotExclusive,
                ExistingConnectionsMode::Strict,
            )
            .to_owned(),
        ),
        (
            SelectionClass::Undetermined,
            masters,
            mac,
            format!(
                "{} {}",
                deadline_wording(
                    IdentitySelection::Undetermined,
                    ExistingConnectionsMode::Graceful
                ),
                report::OWNED_MASTERS_DISCLOSURE
            ),
        ),
        (
            SelectionClass::Exclusive,
            masters,
            windows,
            deadline_wording(
                IdentitySelection::Exclusive,
                ExistingConnectionsMode::Graceful,
            )
            .to_owned(),
        ),
    ] {
        let c = ReportContext {
            selection,
            policy,
            platform,
            ..ctx
        };
        assert_eq!(
            report::compute(&g, &prepared, &[], &c, &ev)
                .connection_policy
                .wording,
            expected
        );
    }
    // `undetermined` (today's selection) gets the qualified D8 item 6 text.
    assert_ne!(
        report::connection_wording(
            SelectionClass::Undetermined,
            &ConnectionPolicy::default(),
            &windows
        ),
        r.connection_policy.wording
    );
    // `consumer` (§17.20 item 14, U6-Q6): the **binding** endpoint of the materialized
    // files, as `prepare_from` fills it, for the golden's Windows token and tag. The
    // golden carries the locator the product emits, `\\.\pipe\…`, which `connect`
    // derives the files from (§17.20 item 15, W3-R2-Q1), JSON-escaped.
    let layout = EndpointLayout::windows("0011223344556677").unwrap();
    let with_files = ManagedPrepared {
        materialized: Some(heimdall_app::ports::MaterializedFiles {
            directory: w.runtime_dir().join("b").join("0123456789abcdef"),
            files: Vec::new(),
            generation: 1,
            endpoint: None,
        }),
        ..prepared.clone()
    };
    let issuer = ready_issuer();
    let mut enrolled = enrollment(0x61, &w.ca_fp, &dest_lab, None);
    enrolled.evidence = Some(evidence.clone());
    let snap = IntegrationSnapshot {
        managed: Some(heimdall_app::ports::ManagedSources {
            enrollments: vec![enrolled],
            issuing_cas: [(dest_lab.clone(), [w.ca_fp.clone()].into_iter().collect())]
                .into_iter()
                .collect(),
            slots: Vec::new(),
            claims: Vec::new(),
            issuer: Some(issuer),
            prepared: Some(with_files),
        }),
        ..IntegrationSnapshot::default()
    };
    let pp = prepare_pairs(std::slice::from_ref(&dest_lab));
    let required = RequiredCapabilities::default();
    let (outcome, _) = prepare::outcome(
        &PrepareRequest {
            grant: &g,
            scope: &g.scope,
            required: &required,
            interactive: false,
            effect_token: "tok",
            now: measured_at,
            pairs: &pp,
        },
        &snap,
        Some(&GrantTerms::default()),
        Some(&layout),
        windows,
        &heimdall_adapters::managed::managed_capabilities(),
        &|_| Some(measured_at),
    )
    .unwrap();
    let locator = outcome.integration.signing_endpoint.clone().unwrap();
    assert_eq!(
        locator,
        r"\\.\pipe\heimdall-0011223344556677-b0123456789abcdef"
    );
    let escaped = locator.replace('\\', "\\\\");
    assert!(
        golden.contains(&format!(
            "\"consumer\": {{\n    \"signing_endpoint\": \"{escaped}\"\n  }}"
        )),
        "the golden's consumer is exactly the binding endpoint {locator}"
    );
    // ⟨wave 4⟩ The selection is classified (U6-Q3, U0b phase 2); an `Undetermined`
    // selection still reports `unknown`, never the claim.
    const { assert!(report::MANAGED_SELECTION_CLASSIFIED) };
    let undetermined = ReportContext {
        selection: SelectionClass::Undetermined,
        ..ctx
    };
    let r2 = report::compute(&g, &prepared, &[], &undetermined, &ev);
    assert_eq!(
        r2.enforcement.identity_selection(),
        IdentitySelectionEnforcement::Unknown
    );
    // On macOS the conditions also carry the issuer store's unlock (F03).
    let mac = ReportContext {
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        ..ctx
    };
    let r3 = report::compute(&g, &prepared, &[], &mac, &ev);
    assert!(
        r3.conditions
            .contains(&ReadinessCondition::IssuerStoreUnlockedAtStart)
    );
    // A pair without its own fresh verification reads `unknown`.
    let r4 = report::compute(&g, &prepared, &[], &ctx, &[]);
    assert_eq!(
        r4.enforcement.destination_scope,
        DestinationScopeEnforcement::Unknown
    );
    assert!(r4.evidence.is_empty());
    assert_eq!(
        r4.revocation.destination_clock,
        DestinationClock::Unmeasured
    );
}

fn fixture_claim(platform: Platform, field: &'static str, value: &'static str) -> Claim {
    Claim {
        field,
        value,
        platform,
        os_floor: "0",
        client_versions: VersionRange {
            min: "9.5",
            max: "",
        },
        signer_builds: VersionRange { min: "0", max: "" },
        build_profile: BuildProfile::Release,
        store_kind: None,
        record: "tests/evidence/fixture-claim.json",
        record_commit: "0000000",
    }
}

fn fixture_claims(platform: Platform) -> Vec<Claim> {
    vec![
        fixture_claim(platform, "lock_continuity", "verified"),
        fixture_claim(platform, "new_signing_expiry", "signer"),
        fixture_claim(platform, "owned_multiplexing", "closed_at_deadline"),
        fixture_claim(
            platform,
            "existing_connections",
            "graceful_dedicated_connections",
        ),
        fixture_claim(
            platform,
            "new_authentication_expiry",
            "credential_and_signer",
        ),
        fixture_claim(
            platform,
            "enforcement.revocation",
            "bounded_by_credential_expiry",
        ),
        fixture_claim(
            platform,
            "revocation.remote",
            "bounded_by_credential_expiry",
        ),
    ]
}

#[tokio::test]
async fn report_with_fixture_claim_table_reports_verified_with_record() {
    let w = World::new().await;
    let data = w.ensure("claims", &[h1()]).await;
    let d = w.drive(&data, "tok-claims", Stage::Materialize).await;
    let g = w.grant(&data.grant_id);
    let platform = current_platform();
    let claims = fixture_claims(platform);
    let masters = ConnectionPolicy {
        existing: ExistingConnectionsMode::Graceful,
        multiplexing: MultiplexingMode::OwnedMasters,
    };
    let ctx = ReportContext {
        platform,
        lock_behavior: LockBehavior::Continue,
        policy: masters,
        issuer_ready: true,
        reissue_pending: false,
        now: w.wall(),
        selection: SelectionClass::Undetermined,
    };
    let r = report::compute(&g, d.prepared.as_ref().unwrap(), &claims, &ctx, &[]);
    assert_eq!(r.lock_continuity, LockContinuityReport::Verified);
    let e = &r.enforcement;
    assert_eq!(e.new_signing_expiry(), NewSigningExpiry::Signer);
    assert_eq!(
        e.new_authentication_expiry,
        NewAuthenticationExpiry::CredentialAndSigner
    );
    assert_eq!(
        e.existing_connections,
        ExistingConnectionsPolicy::GracefulDedicatedConnections
    );
    assert_eq!(e.revocation, RevocationStatus::BoundedByCredentialExpiry);
    assert_eq!(
        r.revocation.remote,
        RemoteRevocation::BoundedByCredentialExpiry
    );
    if platform.os == "windows" {
        assert_eq!(e.owned_multiplexing(), OwnedMultiplexing::Unavailable);
    } else {
        assert_eq!(e.owned_multiplexing(), OwnedMultiplexing::ClosedAtDeadline);
    }
    let claimed: Vec<&str> = r
        .evidence
        .iter()
        .filter(|x| x.source == EvidenceSource::ClaimTable)
        .map(|x| {
            assert_eq!(
                x.record.as_deref(),
                Some("tests/evidence/fixture-claim.json")
            );
            x.field.as_str()
        })
        .collect();
    assert!(claimed.contains(&"lock_continuity") && claimed.contains(&"revocation.remote"));
    // Another platform's claims never apply here.
    let other = Platform {
        os: if platform.os == "linux" {
            "macos"
        } else {
            "linux"
        },
        arch: platform.arch,
    };
    let r2 = report::compute(
        &g,
        d.prepared.as_ref().unwrap(),
        &fixture_claims(other),
        &ctx,
        &[],
    );
    assert_eq!(r2.lock_continuity, LockContinuityReport::NotVerified);
    assert_eq!(r2.revocation.remote, RemoteRevocation::Unknown);
    // The descriptor's lock continuity follows the claim table too.
    *w.sources.claims.lock().unwrap() = claims.clone();
    let a = ManagedCertificateAdapter::new("claims", w.sources.clone(), None, None);
    assert_eq!(
        a.descriptor().lock_continuity,
        heimdall_app::ports::LockContinuity::Verified
    );
    assert_eq!(
        w.adapter.descriptor().lock_continuity,
        heimdall_app::ports::LockContinuity::Unknown,
        "the baseline table is empty"
    );
    let desc = w.adapter.descriptor();
    assert_eq!(desc.mechanism(), MANAGED_CERTIFICATE);
    assert!(desc.external_side_effects && desc.remote_credential_effect);
    assert_eq!(
        desc.interaction,
        heimdall_app::ports::InteractionRequirement::None
    );
    w.finish(&[data.grant_id]).await;
}

/// D6 item 5: the child gets its own K_env on its own binding endpoint, and
/// certificates for its subset of pairs, none valid after the parent's deadline (the
/// predicate refuses more).
#[tokio::test]
async fn child_gets_own_key_endpoint_and_subset_certificates_bounded_by_parent() {
    let w = World::new().await;
    let parent = w.ensure("parent", &[h1(), h2()]).await;
    let pd = w.drive(&parent, "tok-parent", Stage::Materialize).await;
    let child = w
        .ops
        .delegate(
            &owner(),
            DelegateRequest {
                parent_binding_id: parent.binding_id.clone(),
                scope: [AccessPairRef {
                    destination: h1().destination,
                    account: h1().account,
                }]
                .into_iter()
                .collect(),
                until: None,
                work_id: WorkId::parse("w-child").unwrap(),
                request_id: RequestId::parse("r-child").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {}", e.code, e.message))
        .data;
    w.sources
        .children
        .lock()
        .unwrap()
        .insert(parent.grant_id.clone(), vec![child.grant_id.clone()]);
    let cd = w
        .drive_with(
            &child,
            "tok-child",
            Stage::Materialize,
            true,
            std::slice::from_ref(&parent.grant_id),
        )
        .await;
    let (pk, ck) = (pd.key.clone().unwrap(), cd.key.clone().unwrap());
    assert_ne!(pk.fingerprint, ck.fingerprint, "the child's own K_env");
    let pe = w.endpoints.binding_endpoint(&parent.binding_id).unwrap();
    let ce = w.endpoints.binding_endpoint(&child.binding_id).unwrap();
    assert_ne!(pe, ce, "its own binding endpoint");
    let pg = w.grant(&parent.grant_id);
    let cg = w.grant(&child.grant_id);
    assert!(cg.scope.pairs.is_subset(&pg.scope.pairs));
    let ce_entries = w.entries(&child.grant_id);
    assert_eq!(ce_entries.len(), 1);
    assert_eq!(ce_entries[0].pair, h1());
    assert!(ce_entries[0].bounds.valid_before <= pg.deadline.effective);
    assert_eq!(ce_entries[0].bounds.subject_fingerprint, ck.fingerprint);
    // A reservation past the parent's deadline is refused by the predicate.
    let mut wider = w.request(&cg, &h1(), &ck.fingerprint, true);
    wider.valid_before = shift(pg.deadline.effective, 3600);
    assert!(w.ops.reserve_issuance(wider).await.is_err());
    // A pair outside the child's subset too.
    assert!(
        w.ops
            .reserve_issuance(w.request(&cg, &h2(), &ck.fingerprint, true))
            .await
            .is_err()
    );
    // The child's report is bounded by the child's (≤ parent's) deadline.
    let o = w
        .prepare_from(&cg, &[h1()], &RequiredCapabilities::default())
        .await
        .unwrap();
    assert!(o.usable_until <= pg.deadline.effective);
    w.finish(&[parent.grant_id, child.grant_id]).await;
}

/// ADR-0005 §3.7, lifecycle row 1: a process restart in the same boot loses K_env;
/// the stored grant re-issues under the rule (continuing work), and is usable again
/// with the same pairs and the same D.
#[tokio::test]
async fn reissue_after_process_restart_same_boot_restores_usability() {
    let w = World::new().await;
    let data = w.ensure("restart", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok-before", Stage::Materialize).await;
    // The restart: the in-memory key is gone (the vault does not survive).
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    assert!(w.table().public_key(&gid).is_none());
    let stored = w.grant(&gid);
    let origin = w.origin(&gid);
    let time = w.ops.timegate().assess_read_only(&w.store);
    assert_eq!(
        time,
        TimeStatus::Safe,
        "same boot: the persisted anchor resumes"
    );
    let read = StoreRead {
        source: GrantSource::Store,
        tombstoned: false,
        cutoff_at: None,
        now: w.wall(),
    };
    reissue::eligible(
        &stored,
        &origin,
        &time,
        &Admission::Open,
        LockBehavior::Continue,
        &read,
    )
    .unwrap();
    // The driver re-issues (continuing work: no new activation).
    w.drive_with(&data, "tok-after", Stage::Materialize, false, &[])
        .await;
    let snapshot = w.adapter.read_sources(&prepare_pairs(&[h1(), h2()]));
    let scope = stored.scope.clone();
    let pp = prepare_pairs(&[h1(), h2()]);
    let required = RequiredCapabilities::default();
    let o = w
        .adapter
        .reissue_from(
            PrepareRequest {
                grant: &stored,
                scope: &scope,
                required: &required,
                interactive: false,
                effect_token: "tok-after",
                now: w.wall(),
                pairs: &pp,
            },
            &snapshot,
            &ReissueInput {
                stored: &stored,
                origin: &origin,
                time: &time,
                admission: &Admission::Open,
                lock_behavior: LockBehavior::Continue,
                read: &read,
            },
        )
        .unwrap();
    assert_eq!(o.usable_until, stored.deadline.effective);
    assert_eq!(o.availability, CredentialAvailability::ThroughDeadline);
    assert_eq!(w.table().installed_entries(&gid).len(), 2, "usable again");
    // The re-issued entries are continuing work, under the same D.
    let fresh: Vec<IssuanceEntry> = w
        .entries(&gid)
        .into_iter()
        .filter(|e| e.continuing)
        .collect();
    assert_eq!(fresh.len(), 2);
    assert!(
        fresh
            .iter()
            .all(|e| e.bounds.valid_before == stored.deadline.effective)
    );
    w.finish(&[gid]).await;
}

// =================================================================================
// Negative
// =================================================================================

fn set_preference(w: &World, p: &AccessPair, mechanism: PreferredMechanism, applied: bool) {
    let cas = w
        .store
        .transaction(|tx| tx.verified_cas_for_pair(p))
        .unwrap();
    w.store
        .transaction(|tx| {
            tx.set_pair_preference(
                &PairPreference {
                    destination: p.destination.clone(),
                    account: p.account.clone(),
                    mechanism,
                    projection: if applied {
                        ProjectionStatus::Applied { generation: 1 }
                    } else {
                        ProjectionStatus::Pending
                    },
                    issuing_cas: cas.clone(),
                },
                t0(),
            )
        })
        .unwrap();
}

#[tokio::test]
async fn pair_not_enrolled_refused() {
    let w = World::with(Opts {
        enroll: false,
        ..Opts::default()
    })
    .await;
    let data = w.ensure("unenrolled", &[h1()]).await;
    let gid = data.grant_id.clone();
    let g = w.grant(&gid);
    // The reserve transaction refuses a pair with no verified enrollment.
    let key = w.effects.generate_key(&gid, "tok").await.unwrap();
    let e = w
        .ops
        .reserve_issuance(w.request(&g, &h1(), &key.fingerprint, true))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
    // prepare_from refuses even with (forged) driver results: `pair_not_enrolled`.
    *w.sources.prepared.lock().unwrap() = Some(ManagedPrepared {
        instance: CredentialInstanceId::from_random_bytes([5; 16]),
        key,
        certificates: vec![PreparedCertificate {
            pair: h1(),
            issuance: heimdall_contract::ids::IssuanceId::from_random_bytes([6; 16]),
            ca: w.ca_fp.clone(),
            valid_before: g.deadline.effective,
        }],
        materialized: None,
    });
    let r = w
        .prepare_from(&g, &[h1()], &RequiredCapabilities::default())
        .await;
    assert_eq!(r.unwrap_err(), AdapterError::CapabilityUnavailable);
    let snap = w.adapter.read_sources(&prepare_pairs(&[h1()]));
    let m = snap.managed.as_ref().unwrap();
    assert_eq!(
        prepare::check_enrolled(m, &[h1()]).unwrap_err().reason,
        heimdall_contract::envelope::reason::PAIR_NOT_ENROLLED
    );
    // Through `ensure`: a pair preferring managed certificates with no verified
    // enrollment is refused `pair_not_enrolled` before anything is written.
    set_preference(&w, &h2(), PreferredMechanism::ManagedCertificate, true);
    let e = w
        .try_ensure("pref-unenrolled", &[h2()], RequiredCapabilities::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some(heimdall_contract::envelope::reason::PAIR_NOT_ENROLLED)
    );
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn mixed_mechanisms_refused() {
    let w = World::new().await;
    set_preference(&w, &h1(), PreferredMechanism::ManagedCertificate, true);
    let e = w
        .try_ensure("mixed", &[h1(), h2()], RequiredCapabilities::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some(heimdall_contract::envelope::reason::MIXED_MECHANISMS)
    );
    // The managed pair alone resolves to `managed_certificate`, which this build
    // refuses `driver_unavailable` until U10 registers the adapter (fail closed).
    let e = w
        .try_ensure("managed-only", &[h1()], RequiredCapabilities::default())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some(heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE)
    );
    // And the adapter itself never computes an outcome across mechanisms: a scope with
    // an unenrolled pair is refused as a whole.
    let w2 = World::with(Opts {
        pairs: vec![h1()],
        ..Opts::default()
    })
    .await;
    let data = w2.ensure("mixed-adapter", &[h1(), h2()]).await;
    let g = w2.grant(&data.grant_id);
    let snap = w2.adapter.read_sources(&prepare_pairs(&[h1(), h2()]));
    assert!(prepare::check_enrolled(snap.managed.as_ref().unwrap(), &[h1(), h2()]).is_err());
    let _ = g;
}

#[tokio::test]
async fn issuer_unavailable_no_fallback_to_existing_identity() {
    let w = World::new().await;
    let data = w.ensure("issuer-down", &[h1()]).await;
    let gid = data.grant_id.clone();
    let g = w.grant(&gid);
    *w.sources.issuer.lock().unwrap() = Some(issuer_in(IssuerState::Unavailable));
    // No issuer, so no driver results: refused, never an outcome naming the
    // existing identity.
    let r = w
        .prepare_from(&g, &[h1()], &RequiredCapabilities::default())
        .await;
    assert_eq!(
        r.unwrap_err(),
        AdapterError::Protocol(MANAGED_PREPARE_WITHOUT_DRIVER.to_owned())
    );
    // The issuer port itself answers unavailable (a client with no child started).
    let issuer =
        heimdall_issuer::client::ChildIssuer::new(heimdall_issuer::client::ClientConfig::new(
            heimdall_issuer::client::ChildCommand {
                program: w.dir.path().join("no-such-issuer"),
                args: Vec::new(),
                env: Vec::new(),
            },
            Arc::new(|_| None),
        ));
    let key = w.effects.generate_key(&gid, "tok").await.unwrap();
    let entry = w
        .ops
        .reserve_issuance(w.request(&g, &h1(), &key.fingerprint, true))
        .await
        .unwrap();
    let signed = heimdall_app::ports::IssuerPort::sign(
        &issuer,
        heimdall_app::ports::IssuanceRef {
            table: heimdall_app::ports::IssuanceTable::Grant,
            id: entry.id.clone(),
        },
        &key.public_key,
    )
    .await;
    assert!(
        matches!(
            signed,
            Err(heimdall_app::ports::IssuerError::Unavailable(_))
        ),
        "{signed:?}"
    );
    // A preparation the driver completed while the issuer was ready, observed now
    // with the issuer down: still the managed mechanism only, refresh-dependent,
    // through the binding endpoint; never the catalog identity.
    *w.sources.issuer.lock().unwrap() = Some(ready_issuer());
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    let data2 = w.ensure("issuer-down-2", &[h1()]).await;
    w.drive(&data2, "tok-2", Stage::Materialize).await;
    *w.sources.issuer.lock().unwrap() = Some(issuer_in(IssuerState::Unavailable));
    let g2 = w.grant(&data2.grant_id);
    let o = w
        .prepare_from(&g2, &[h1()], &RequiredCapabilities::default())
        .await
        .unwrap();
    assert_eq!(o.availability, CredentialAvailability::RefreshDependent);
    assert!(
        o.integration
            .pairs
            .iter()
            .all(|p| p.mechanism == MANAGED_CERTIFICATE)
    );
    let ident = identity_record();
    assert!(o.integration.pairs.iter().all(|p| p.endpoint
        != match &ident.source {
            IdentitySource::NativeAgent { endpoint } => Some(endpoint.clone()),
            _ => None,
        }
        && p.endpoint.is_some()));
    w.finish(&[gid, data2.grant_id]).await;
}

#[tokio::test]
async fn offline_until_beyond_bound_capability_unavailable() {
    let w = World::new().await;
    let data = w.ensure("offline", &[h1()]).await;
    w.drive(&data, "tok", Stage::Materialize).await;
    let g = w.grant(&data.grant_id);
    let at = |t: Timestamp| RequiredCapabilities {
        offline_until: Some(t),
        ..RequiredCapabilities::default()
    };
    let beyond = w
        .prepare_from(&g, &[h1()], &at(shift(g.deadline.effective, 1)))
        .await;
    assert_eq!(beyond.unwrap_err(), AdapterError::CapabilityUnavailable);
    let exact = w
        .prepare_from(&g, &[h1()], &at(g.deadline.effective))
        .await
        .unwrap();
    assert_eq!(exact.offline_until, g.deadline.effective);
    w.finish(&[data.grant_id]).await;
}

#[tokio::test]
async fn unattended_minimum_requires_claim_continue_and_no_interaction() {
    let w = World::new().await;
    let data = w.ensure("unattended", &[h1()]).await;
    let d = w.drive(&data, "tok", Stage::Materialize).await;
    let g = w.grant(&data.grant_id);
    let unattended = RequiredCapabilities {
        unattended: true,
        ..RequiredCapabilities::default()
    };
    // Empty claim table: refused (`lock_continuity_unverified`).
    assert_eq!(
        w.prepare_from(&g, &[h1()], &unattended).await.unwrap_err(),
        AdapterError::CapabilityUnavailable
    );
    let platform = current_platform();
    let reason_with = |claims: &[Claim], lock: LockBehavior| {
        let ctx = ReportContext {
            platform,
            lock_behavior: lock,
            policy: ConnectionPolicy::default(),
            issuer_ready: true,
            reissue_pending: false,
            now: w.wall(),
            selection: SelectionClass::Undetermined,
        };
        let r = report::compute(&g, d.prepared.as_ref().unwrap(), claims, &ctx, &[]);
        let scope = g.scope.clone();
        let pp = prepare_pairs(&[h1()]);
        let req = PrepareRequest {
            grant: &g,
            scope: &scope,
            required: &unattended,
            interactive: false,
            effect_token: "tok",
            now: w.wall(),
            pairs: &pp,
        };
        prepare::check_minimums(
            &req,
            &r,
            &GrantTerms {
                lock_behavior: lock,
                policy: ConnectionPolicy::default(),
            },
            &heimdall_adapters::managed::managed_capabilities(),
        )
        .err()
        .map(|e| e.reason)
    };
    assert_eq!(
        reason_with(&[], LockBehavior::Continue),
        Some(heimdall_contract::envelope::reason::LOCK_CONTINUITY_UNVERIFIED)
    );
    let claims = fixture_claims(platform);
    assert_eq!(reason_with(&claims, LockBehavior::Continue), None);
    assert_eq!(
        reason_with(&claims, LockBehavior::RevokeOnLock),
        Some(heimdall_contract::envelope::reason::LOCK_REVOKES_CHOSEN)
    );
    // The third condition: a managed binding never needs interaction.
    assert_eq!(
        w.adapter.descriptor().interaction,
        heimdall_app::ports::InteractionRequirement::None
    );
    // With the fixture claim and `continue`, the whole preparation passes.
    *w.sources.claims.lock().unwrap() = claims;
    w.prepare_from(&g, &[h1()], &unattended).await.unwrap();
    w.finish(&[data.grant_id]).await;
}

impl World {
    /// A fresh process over the same store and directories: a new vault and signer
    /// table (every K_env of the old process is lost), new effects and adapter.
    fn fresh_process(&self) -> (ManagedEffectsImpl, ManagedCertificateAdapter) {
        let table = SignerTable::new(Arc::new(KeyVault::new()));
        table.set_install_view(self.view.clone());
        let effects = ManagedEffectsImpl::new(
            table,
            self.endpoints.clone(),
            self.sources.clone(),
            self.runtime_dir(),
            SlotRoot {
                data_dir: self.data_dir(),
                environment: env_id(),
            },
        );
        let adapter = ManagedCertificateAdapter::new(
            "fresh",
            self.sources.clone(),
            Some(effects.clone()),
            Some(self.layout.clone()),
        );
        (effects, adapter)
    }

    fn store_read(&self) -> StoreRead {
        StoreRead {
            source: GrantSource::Store,
            tombstoned: false,
            cutoff_at: None,
            now: self.wall(),
        }
    }

    fn residual(&self, grants: &[GrantId]) -> Option<Timestamp> {
        self.store
            .transaction(|tx| tx.issuance_residual(grants))
            .unwrap()
    }
}

/// The exit claim "an expired grant cannot renew itself".
#[tokio::test]
async fn expired_grant_never_reissued() {
    let w = World::new().await;
    let data = w.ensure("expired", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    let live = w.grant(&gid);
    // The adapter's `renew` never runs the re-issue itself (R5): fail closed.
    let scope = live.scope.clone();
    let pp = prepare_pairs(&[h1()]);
    let required = RequiredCapabilities::default();
    fn req<'a>(
        g: &'a GrantSnapshot,
        scope: &'a Scope,
        required: &'a RequiredCapabilities,
        pairs: &'a [PreparePair],
        now: Timestamp,
    ) -> PrepareRequest<'a> {
        PrepareRequest {
            grant: g,
            scope,
            required,
            interactive: false,
            effect_token: "tok-renew",
            now,
            pairs,
        }
    }
    assert_eq!(
        w.adapter
            .renew(req(&live, &scope, &required, &pp, w.wall()))
            .await
            .unwrap_err(),
        AdapterError::Protocol(RENEW_THROUGH_DRIVER.to_owned())
    );
    // K_env's public key, read while the grant is live (⟨§17.22 item 4, W4-R01⟩ expiry
    // destroys K_env, so it is gone afterwards).
    let key = w.table().public_key(&gid).unwrap();
    // Past the deadline: the grant expires, and nothing re-issues for it.
    w.clock.advance(3 * HOUR);
    w.ops.tick().await.unwrap();
    let expired = w.grant(&gid);
    assert_eq!(expired.state, GrantState::Expired);
    assert!(
        w.table().public_key(&gid).is_none(),
        "expiry destroyed K_env (§17.22 item 4)"
    );
    let origin = w.origin(&gid);
    let read = w.store_read();
    assert_eq!(
        reissue::eligible(
            &expired,
            &origin,
            &TimeStatus::Safe,
            &Admission::Expired,
            LockBehavior::Continue,
            &read
        ),
        Err(ReissueRefusal::GrantEnded(GrantState::Expired))
    );
    // Even a snapshot that still says `active` (stale) is refused at its deadline.
    assert_eq!(
        reissue::eligible(
            &live,
            &origin,
            &TimeStatus::Safe,
            &Admission::Expired,
            LockBehavior::Continue,
            &read
        ),
        Err(ReissueRefusal::DeadlinePassed)
    );
    assert_eq!(
        w.adapter
            .renew(req(&expired, &scope, &required, &pp, w.wall()))
            .await
            .unwrap_err(),
        AdapterError::CapabilityUnavailable
    );
    assert_eq!(
        w.adapter
            .renew(req(&live, &scope, &required, &pp, w.wall()))
            .await
            .unwrap_err(),
        AdapterError::CapabilityUnavailable
    );
    // The reserve transaction refuses a new certificate for it.
    assert!(
        w.ops
            .reserve_issuance(w.request(&live, &h1(), &key.fingerprint, false))
            .await
            .is_err()
    );
    for (state, refusal) in [
        (
            GrantState::Revoked,
            ReissueRefusal::GrantEnded(GrantState::Revoked),
        ),
        (
            GrantState::Released,
            ReissueRefusal::GrantEnded(GrantState::Released),
        ),
        (
            GrantState::Revoking,
            ReissueRefusal::GrantEnded(GrantState::Revoking),
        ),
    ] {
        let mut g = live.clone();
        g.state = state;
        let read = StoreRead {
            now: w.wall(),
            ..w.store_read()
        };
        let mut r = read;
        r.now = live.starts_at;
        assert_eq!(
            reissue::eligible(
                &g,
                &origin,
                &TimeStatus::Safe,
                &Admission::Open,
                LockBehavior::Continue,
                &r
            ),
            Err(refusal)
        );
    }
    w.finish(&[gid]).await;
}

/// Property (fixed seed, 256 cases): a re-issue outcome never has a later deadline or
/// other pairs than the stored grant, whatever the request says.
#[tokio::test]
async fn renew_never_extends_deadline_or_pairs() {
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let w = World::new().await;
    let data = w.ensure("prop", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok-prop", Stage::Materialize).await;
    let stored = w.grant(&gid);
    let origin = w.origin(&gid);
    let base = w.adapter.read_sources(&prepare_pairs(&[h1(), h2()]));
    let d = stored.deadline.effective;
    let now = w.wall();
    let adapter = w.adapter.clone();
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 256,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &[0x56; 32]),
    );
    let strategy = (
        -7200i64..7200,
        any::<bool>(),
        any::<bool>(),
        0u8..4,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    );
    let accepted = AtomicUsize::new(0);
    runner
        .run(
            &strategy,
            |(delta, add, drop, state, safe, revokes, from_store, wider)| {
                let mut requested = stored.clone();
                if delta % 3 != 0 {
                    requested.deadline.effective = shift(d, delta);
                }
                if add {
                    requested.scope.pairs.insert(h2());
                }
                if drop {
                    requested.scope.pairs.remove(&h1());
                }
                let mut stored_now = stored.clone();
                stored_now.state = [
                    GrantState::Active,
                    GrantState::Degraded,
                    GrantState::Expired,
                    GrantState::Revoked,
                ][usize::from(state)];
                let mut snap = base.clone();
                if let Some(m) = snap.managed.as_mut()
                    && let Some(p) = m.prepared.as_mut()
                {
                    let vb = if wider {
                        requested.deadline.effective
                    } else {
                        d
                    };
                    let installed = p.certificates.clone();
                    p.certificates = requested
                        .scope
                        .pairs
                        .iter()
                        .map(|pr| PreparedCertificate {
                            pair: pr.clone(),
                            // The installed entry for a pair the driver prepared (its
                            // validity is checked, §17.20 item 8); a forged one else.
                            issuance: installed.iter().find(|c| &c.pair == pr).map_or_else(
                                || heimdall_contract::ids::IssuanceId::from_random_bytes([7; 16]),
                                |c| c.issuance.clone(),
                            ),
                            ca: w.ca_fp.clone(),
                            valid_before: vb,
                        })
                        .collect();
                }
                let pairs: Vec<AccessPair> = requested.scope.pairs.iter().cloned().collect();
                let pp = prepare_pairs(&pairs);
                let scope = requested.scope.clone();
                let required = RequiredCapabilities::default();
                let time = if safe {
                    TimeStatus::Safe
                } else {
                    TimeStatus::Uncertain(heimdall_domain::time::TimeUncertainty::Unsynchronized {
                        sync: SyncStatus::Unknown,
                    })
                };
                let read = StoreRead {
                    source: if from_store {
                        GrantSource::Store
                    } else {
                        GrantSource::ProcessFile
                    },
                    tombstoned: false,
                    cutoff_at: None,
                    now,
                };
                let r = adapter.reissue_from(
                    PrepareRequest {
                        grant: &requested,
                        scope: &scope,
                        required: &required,
                        interactive: false,
                        effect_token: "tok-prop",
                        now,
                        pairs: &pp,
                    },
                    &snap,
                    &ReissueInput {
                        stored: &stored_now,
                        origin: &origin,
                        time: &time,
                        admission: &Admission::Open,
                        lock_behavior: if revokes {
                            LockBehavior::RevokeOnLock
                        } else {
                            LockBehavior::Continue
                        },
                        read: &read,
                    },
                );
                let same = requested.deadline.effective == d
                    && requested.scope.pairs == stored.scope.pairs;
                if let Ok(o) = r {
                    prop_assert!(same, "accepted a changed grant");
                    prop_assert!(o.usable_until <= d && o.offline_until <= d);
                    let got: BTreeSet<AccessPair> = o
                        .integration
                        .pairs
                        .iter()
                        .map(|p| AccessPair {
                            destination: p.destination.clone(),
                            account: p.account.clone(),
                        })
                        .collect();
                    prop_assert_eq!(got, stored.scope.pairs.clone());
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            },
        )
        .unwrap();
    assert!(
        accepted.load(Ordering::SeqCst) > 0,
        "some re-issues are eligible (the property is not vacuous)"
    );
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn reissue_refused_for_revoke_on_lock() {
    let w = World::new().await;
    let data = w.ensure("lockrevokes", &[h1()]).await;
    let g = w.grant(&data.grant_id);
    let origin = w.origin(&data.grant_id);
    let read = w.store_read();
    assert_eq!(
        reissue::eligible(
            &g,
            &origin,
            &TimeStatus::Safe,
            &Admission::Open,
            LockBehavior::RevokeOnLock,
            &read
        ),
        Err(ReissueRefusal::RevokeOnLock)
    );
    // The origin recorded at creation wins over a later `continue` (§17.17 item 4).
    let mut recorded = origin.clone();
    recorded.lock_behavior = Some(LockBehavior::RevokeOnLock);
    assert_eq!(
        reissue::eligible(
            &g,
            &recorded,
            &TimeStatus::Safe,
            &Admission::Open,
            LockBehavior::Continue,
            &read
        ),
        Err(ReissueRefusal::RevokeOnLock)
    );
    assert_eq!(
        reissue::eligible(
            &g,
            &origin,
            &TimeStatus::Safe,
            &Admission::Open,
            LockBehavior::Continue,
            &read
        ),
        Ok(())
    );
}

/// ADR-0005 §3.7 rule 3 with lifecycle row 3: after a reboot, time is not accepted
/// (synchronized time is not trusted in M03), so no re-issue, until an attended
/// confirmation.
#[tokio::test]
async fn reissue_waits_on_time_uncertain_until_confirmed() {
    let w = World::new().await;
    let data = w.ensure("reboot", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    // The reboot loses the key; the platform reports nothing trustworthy.
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    w.clock.reboot(shift(w.wall(), 120));
    w.sync.set(SyncStatus::Unknown);
    let g = w.grant(&gid);
    let origin = w.origin(&gid);
    let time = w.ops.timegate().assess_read_only(&w.store);
    assert!(matches!(time, TimeStatus::Uncertain(_)), "{time:?}");
    assert_eq!(
        reissue::eligible(
            &g,
            &origin,
            &time,
            &Admission::NeedsAnchor,
            LockBehavior::Continue,
            &w.store_read()
        ),
        Err(ReissueRefusal::TimeNotAccepted)
    );
    // The reserve transaction agrees: nothing is issued while time is uncertain.
    let key = w
        .effects
        .generate_key(&gid, "tok-after-reboot")
        .await
        .unwrap();
    assert!(
        w.ops
            .reserve_issuance(w.request(&g, &h1(), &key.fingerprint, false))
            .await
            .is_err()
    );
    // An attended confirmation accepts time for this boot.
    w.ops
        .confirm_time(
            &attended(),
            heimdall_contract::request::ConfirmTimeRequest {
                observed_wall: w.wall(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("confirm: {} {}", e.code, e.message));
    let time = w.ops.timegate().assess_read_only(&w.store);
    assert_eq!(time, TimeStatus::Safe);
    assert_eq!(
        reissue::eligible(
            &g,
            &origin,
            &time,
            &Admission::Open,
            LockBehavior::Continue,
            &w.store_read()
        ),
        Ok(())
    );
    w.finish(&[gid]).await;
}

/// Rule 4: a planted stale socket or PID file never counts as a grant or a key.
#[tokio::test]
async fn reissue_never_from_process_files() {
    let w = World::new().await;
    let data = w.ensure("planted", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    // Planted process files: a stale socket path and a PID file naming the grant.
    let planted = w.runtime_dir().join("b").join("ffffffffffffffff");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::write(planted.join("agent.sock"), b"").unwrap();
    std::fs::write(planted.join("key.pub"), b"ssh-ed25519 AAAAplanted\n").unwrap();
    std::fs::write(w.runtime_dir().join("heimdall.pid"), gid.as_str()).unwrap();
    let g = w.grant(&gid);
    let origin = w.origin(&gid);
    let read = StoreRead {
        source: GrantSource::ProcessFile,
        ..w.store_read()
    };
    assert_eq!(
        reissue::eligible(
            &g,
            &origin,
            &TimeStatus::Safe,
            &Admission::Open,
            LockBehavior::Continue,
            &read
        ),
        Err(ReissueRefusal::NotFromStore)
    );
    // A fresh process finds no key in them and never reconciles them as applied.
    let (effects, adapter) = w.fresh_process();
    assert!(effects.table().public_key(&gid).is_none());
    assert_ne!(
        adapter.reconcile(&gid, "tok").await.unwrap(),
        ReconcileOutcome::NotApplied,
        "published entries exist"
    );
    assert!(!matches!(
        adapter.reconcile(&gid, "tok").await.unwrap(),
        ReconcileOutcome::Applied(_)
    ));
    // The planted directory is not owner-only (§17.20 item 7): the restart enumeration
    // refuses it with `managed_dir_unsafe`, never repairs it, and no clear touches it.
    let fake = BindingId::from_random_bytes([0xff; 16]);
    assert!(matches!(
        files::binding_directories_of(&w.runtime_dir(), &fake),
        Err(files::FilesError::Unsafe(_))
    ));
    assert_eq!(
        effects.clear(&fake, 1).unwrap_err(),
        AdapterError::Unavailable(files::MANAGED_DIR_UNSAFE.to_owned())
    );
    assert!(planted.join("key.pub").exists());
    // Owner-only (Unix: mode 0700; Windows keeps the inherited DACL, refused above), it
    // holds no marker: no binding owns it, no clear touches it.
    if cfg!(unix) {
        set_mode(&planted, 0o700);
        assert!(
            files::binding_directories_of(&w.runtime_dir(), &fake)
                .unwrap()
                .is_empty()
        );
        effects.clear(&fake, 1).unwrap();
        assert!(planted.join("key.pub").exists());
    }
    w.finish(&[gid]).await;
}

// =================================================================================
// Interrupted
// =================================================================================

/// D6 item 8's table: after a crash at each stage, `reconcile(token)` in the new
/// process answers `NotApplied` when nothing is published and `Unknown` otherwise
/// (the old key is gone); in the same process a lost reply after install answers
/// `Applied`. Reservations stay counted; a fresh preparation starts over.
#[tokio::test]
async fn crash_at_each_prepare_step_recovers_per_table() {
    for stage in STAGES {
        let w = World::new().await;
        let data = w
            .ensure(&format!("crash-{stage:?}").to_lowercase(), &[h1()])
            .await;
        let gid = data.grant_id.clone();
        let token = "tok-crash";
        let d = w.drive(&data, token, stage).await;
        let published = stage >= Stage::Publish;
        let installed = stage >= Stage::Install;
        // Same process, lost reply.
        if installed {
            let o = PrepareOutcome {
                credential_ref: "recorded".into(),
                ..fixture_outcome(&PrepareRequest {
                    grant: &w.grant(&gid),
                    scope: &w.grant(&gid).scope,
                    required: &RequiredCapabilities::default(),
                    interactive: false,
                    effect_token: token,
                    now: w.wall(),
                    pairs: &[],
                })
            };
            w.sources
                .recorded
                .lock()
                .unwrap()
                .insert((gid.clone(), token.to_owned()), o.clone());
            assert_eq!(
                w.adapter.reconcile(&gid, token).await.unwrap(),
                ReconcileOutcome::Applied(o),
                "{stage:?}"
            );
            assert_eq!(
                w.adapter.reconcile(&gid, "another-token").await.unwrap(),
                ReconcileOutcome::Unknown,
                "{stage:?}: another token's effect is not this one"
            );
        }
        // The crash: a new process.
        let (fresh_effects, fresh) = w.fresh_process();
        let r = fresh.reconcile(&gid, token).await.unwrap();
        if published {
            assert_eq!(r, ReconcileOutcome::Unknown, "{stage:?}");
        } else {
            assert_eq!(r, ReconcileOutcome::NotApplied, "{stage:?}");
        }
        // Reservations made before the crash stay counted in the residual.
        if stage >= Stage::Reserve {
            assert_eq!(
                w.residual(std::slice::from_ref(&gid)),
                Some(w.grant(&gid).deadline.effective),
                "{stage:?}"
            );
        }
        // The cleanup intent destroys whatever is installed; a fresh prepare starts
        // over in the new process and completes.
        w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
        let key = fresh_effects.generate_key(&gid, "tok-again").await.unwrap();
        let g = w.grant(&gid);
        let e = w
            .ops
            .reserve_issuance(w.request(&g, &h1(), &key.fingerprint, true))
            .await
            .unwrap();
        let cert = build_and_sign(
            &CertificateProfile::from_bounds(&e.bounds),
            &fresh_effects
                .table()
                .public_key(&gid)
                .unwrap()
                .public_key()
                .unwrap(),
            &w.ca,
        )
        .unwrap()
        .to_openssh()
        .unwrap();
        let Publication::Published(p) = w.ops.publish_issuance(&e.id, &facts(true)).await.unwrap()
        else {
            panic!("re-reserved")
        };
        fresh_effects.install(&gid, &p, &cert).await.unwrap();
        assert_eq!(
            fresh_effects.table().installed_entries(&gid),
            vec![p.id.clone()]
        );
        let _ = d;
        fresh_effects
            .destroy(std::slice::from_ref(&gid))
            .await
            .unwrap();
        assert_eq!(fresh_effects.table().vault().len(), 0);
        w.finish(&[gid]).await;
    }
}

/// D6 item 8: a dropped install step installs nothing, then or later.
#[tokio::test]
async fn dropped_prepare_installs_nothing_after_drop() {
    let w = World::new().await;
    let data = w.ensure("drop", &[h1()]).await;
    let gid = data.grant_id.clone();
    let d = w.drive(&data, "tok", Stage::Publish).await;
    let release = Arc::new(tokio::sync::Notify::new());
    *w.view.pause.lock().unwrap() = Some(release.clone());
    let (e, c) = (&d.published[0], &d.certs[0].1);
    tokio::select! {
        biased;
        r = w.effects.install(&gid, e, c) => panic!("not dropped: {r:?}"),
        () = w.view.reached.notified() => {}
    }
    // The future is dropped while its store view was being read.
    *w.view.pause.lock().unwrap() = None;
    release.notify_waiters();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(w.table().installed_entries(&gid).is_empty());
    assert_eq!(
        w.table().instance_state(&gid),
        Some(heimdall_domain::issuance::CredentialState::Pending)
    );
    // After the cleanup destroyed the key, the published certificate can never be
    // installed: installation needs the live preparation's matching key.
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    assert!(w.effects.install(&gid, e, c).await.is_err());
    assert!(w.table().installed_entries(&gid).is_empty());
    // A bounded install: a view that never answers times out as `OutcomeUnknown`.
    let w2 = World::new().await;
    let data2 = w2.ensure("drop-bound", &[h1()]).await;
    let d2 = w2.drive(&data2, "tok", Stage::Publish).await;
    *w2.view.pause.lock().unwrap() = Some(Arc::new(tokio::sync::Notify::new()));
    let bounded = w2
        .effects
        .clone()
        .with_call_timeout(Duration::from_millis(50));
    assert!(matches!(
        bounded
            .install(&data2.grant_id, &d2.published[0], &d2.certs[0].1)
            .await,
        Err(AdapterError::OutcomeUnknown(_))
    ));
    assert!(w2.table().installed_entries(&data2.grant_id).is_empty());
    w2.finish(&[data2.grant_id]).await;
    w.finish(&[gid]).await;
}

/// D7 item 5 (QR17): the managed adapter declares a remote credential effect, so a
/// timed-out immediate revoke keeps its cleanup intent (it never counts as made),
/// and the next processing retries it.
#[tokio::test]
async fn timed_out_immediate_revoke_keeps_intent_and_retries() {
    let w = World::with(Opts {
        limits: Limits {
            adapter_call_timeout: Duration::from_millis(50),
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    assert!(w.adapter.descriptor().remote_credential_effect);
    let data = w.ensure("qr17", &[h1()]).await;
    let g = data.grant_id.clone();
    let op = OperationId::from_random_bytes([0x17; 16]);
    let intent = heimdall_domain::revocation::CleanupIntent {
        grant: g.clone(),
        operation: op.clone(),
        adapter: Some(w.adapter.descriptor().identity.clone()),
        effect_token: "tok-qr17".into(),
        confirmed: false,
        in_flight: false,
        version: 0,
        recorded_at: t0(),
    };
    w.store
        .transaction(|tx| tx.record_cleanup_intent(&intent))
        .unwrap();
    *w.wrapped.revoke_delay.lock().unwrap() = Some(Duration::from_millis(500));
    w.ops.process_cleanup_intents().await.unwrap();
    assert!(
        w.wrapped.revokes.load(Ordering::SeqCst) >= 1,
        "the immediate call was made"
    );
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_some(),
        "a timed-out call keeps the intent"
    );
    // The retry, answered: the intent clears.
    *w.wrapped.revoke_delay.lock().unwrap() = None;
    let before = w.wrapped.revokes.load(Ordering::SeqCst);
    w.ops.process_cleanup_intents().await.unwrap();
    assert!(w.wrapped.revokes.load(Ordering::SeqCst) > before, "retried");
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&g, &op))
            .unwrap()
            .is_none(),
        "cleared once answered"
    );
}

// =================================================================================
// Rotation and removal (§17.1 item 15; §17.3 item 3, Q20; R7)
// =================================================================================

impl World {
    /// Register K_ca′ (newer than every CA so far) and verify it for `pairs`.
    fn rotate_to_new_ca(
        &self,
        seed: u8,
        pairs: &[AccessPair],
        created_at: Timestamp,
    ) -> CaFingerprint {
        let k = Arc::new(SecretCaKey::generate().unwrap());
        let fp = k.fingerprint().unwrap();
        let public = k.public_openssh().unwrap();
        self.store
            .transaction(|tx| {
                tx.insert_issuer(&issuer_record(&fp, &public, created_at))?;
                for (i, p) in pairs.iter().enumerate() {
                    let s = seed.wrapping_add(u8::try_from(i).unwrap());
                    tx.seed_enrollment(&enrollment(s, &fp, p, Some(measured())))?;
                }
                Ok(())
            })
            .unwrap();
        self.extra_cas.lock().unwrap().push((fp.clone(), k));
        fp
    }

    fn ca_of(&self, grant: &GrantId, p: &AccessPair) -> CaFingerprint {
        self.entries(grant)
            .into_iter()
            .find(|e| &e.pair == p && e.state == IssuanceState::Published)
            .and_then(|e| e.bounds.ca_fingerprint)
            .unwrap()
    }

    fn all_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
        grants.iter().flat_map(|g| self.entries(g)).collect()
    }
}

/// Two accounts verify K_ca′ in turn; `ensure` (and the managed preparation) keeps
/// working throughout, from the newest verified CA per pair; the projection status is
/// not reset by the rotation.
#[tokio::test]
async fn rotation_keeps_ensure_working_per_account() {
    let w = World::new().await;
    let required = RequiredCapabilities::default();
    // Before: both accounts under K_ca.
    let a = w.ensure("rot-a", &[h1(), h2()]).await;
    let prepared_a = w
        .drive(&a, "tok-a", Stage::Materialize)
        .await
        .prepared
        .unwrap();
    assert_eq!(w.ca_of(&a.grant_id, &h1()), w.ca_fp);
    assert_eq!(w.ca_of(&a.grant_id, &h2()), w.ca_fp);
    w.prepare_from(&w.grant(&a.grant_id), &[h1(), h2()], &required)
        .await
        .unwrap();
    // h1's account verifies K_ca′ first.
    let ca2 = w.rotate_to_new_ca(0x40, &[h1()], shift(t0(), 60));
    let b = w.ensure("rot-b", &[h1(), h2()]).await;
    w.drive(&b, "tok-b", Stage::Materialize).await;
    assert_eq!(
        w.ca_of(&b.grant_id, &h1()),
        ca2,
        "the newest verified CA for h1"
    );
    assert_eq!(
        w.ca_of(&b.grant_id, &h2()),
        w.ca_fp,
        "h2 keeps K_ca until it verifies"
    );
    w.prepare_from(&w.grant(&b.grant_id), &[h1(), h2()], &required)
        .await
        .unwrap();
    // Then h2's account.
    w.store
        .transaction(|tx| tx.seed_enrollment(&enrollment(0x50, &ca2, &h2(), Some(measured()))))
        .unwrap();
    let c = w.ensure("rot-c", &[h1(), h2()]).await;
    w.drive(&c, "tok-c", Stage::Materialize).await;
    assert_eq!(w.ca_of(&c.grant_id, &h1()), ca2);
    assert_eq!(w.ca_of(&c.grant_id, &h2()), ca2);
    w.prepare_from(&w.grant(&c.grant_id), &[h1(), h2()], &required)
        .await
        .unwrap();
    // The earlier grants keep working (their certificates are still valid), each with
    // its own driver results (the installed entries' validity is checked: §17.20 item 8).
    *w.sources.prepared.lock().unwrap() = Some(prepared_a.clone());
    w.prepare_from(&w.grant(&a.grant_id), &[h1(), h2()], &required)
        .await
        .unwrap();
    // The projection status survives the issuing-CA set's growth.
    set_preference(&w, &h1(), PreferredMechanism::ManagedCertificate, true);
    w.store
        .transaction(|tx| tx.add_issuing_ca(&h1(), &ca2, t0()))
        .unwrap();
    let pref = w
        .store
        .transaction(|tx| tx.pair_preference(&h1()))
        .unwrap()
        .unwrap();
    assert_eq!(pref.projection, ProjectionStatus::Applied { generation: 1 });
    assert_eq!(pref.mechanism, PreferredMechanism::ManagedCertificate);
    w.finish(&[a.grant_id, b.grant_id, c.grant_id]).await;
}

/// Grants under K_ca and under K_ca′ for the same pair, both CAs verified for it.
async fn two_ca_world() -> (World, CaFingerprint, GrantId, GrantId) {
    let w = World::with(Opts {
        pairs: vec![h1()],
        ..Opts::default()
    })
    .await;
    let old = w.ensure("under-old", &[h1()]).await;
    w.drive(&old, "tok-old", Stage::Materialize).await;
    let ca2 = w.rotate_to_new_ca(0x60, &[h1()], shift(t0(), 60));
    let new = w.ensure("under-new", &[h1()]).await;
    w.drive(&new, "tok-new", Stage::Materialize).await;
    assert_eq!(w.ca_of(&old.grant_id, &h1()), w.ca_fp);
    assert_eq!(w.ca_of(&new.grant_id, &h1()), ca2);
    (w, ca2, old.grant_id, new.grant_id)
}

#[tokio::test]
async fn early_removal_preview_names_grants_under_removed_ca() {
    let (w, ca2, old, new) = two_ca_world().await;
    let entries = w.all_entries(&[old.clone(), new.clone()]);
    assert_eq!(
        report::grants_under_ca(&w.ca_fp, &entries),
        [old.clone()].into_iter().collect()
    );
    assert_eq!(
        report::grants_under_ca(&ca2, &entries),
        [new.clone()].into_iter().collect()
    );
    w.finish(&[old, new]).await;
}

/// Q20 (§17.3 item 3; R7): removing a CA degrades **every** grant whose certificate is
/// under it, even though another verified CA remains for the pair; grants under the
/// other CA are untouched.
#[tokio::test]
async fn removal_degrades_only_grants_under_removed_ca() {
    let (w, ca2, old, new) = two_ca_world().await;
    let remaining: BTreeSet<CaFingerprint> = w
        .store
        .transaction(|tx| tx.verified_cas_for_pair(&h1()))
        .unwrap()
        .into_iter()
        .filter(|c| *c != w.ca_fp)
        .collect();
    assert_eq!(
        remaining,
        [ca2.clone()].into_iter().collect(),
        "another CA remains"
    );
    let degrade = report::grants_under_ca(&w.ca_fp, &w.all_entries(&[old.clone(), new.clone()]));
    assert!(
        degrade.contains(&old),
        "the grant under the removed CA degrades"
    );
    assert!(
        !degrade.contains(&new),
        "a grant under the remaining CA does not"
    );
    // A voided entry names no certificate.
    let mut voided = w.entries(&new)[0].clone();
    voided.state = IssuanceState::Voided;
    voided.bounds.ca_fingerprint = Some(w.ca_fp.clone());
    assert!(report::grants_under_ca(&w.ca_fp, &[voided]).is_empty());
    w.finish(&[old, new]).await;
}

#[tokio::test]
async fn preference_stays_managed_while_another_verified_ca_remains() {
    let (w, ca2, old, new) = two_ca_world().await;
    let verified = w
        .store
        .transaction(|tx| tx.verified_cas_for_pair(&h1()))
        .unwrap();
    let without_old: BTreeSet<CaFingerprint> = verified
        .iter()
        .filter(|c| **c != w.ca_fp)
        .cloned()
        .collect();
    assert_eq!(
        report::preference_after_removal(&without_old),
        PreferredMechanism::ManagedCertificate
    );
    let none: BTreeSet<CaFingerprint> = without_old.into_iter().filter(|c| *c != ca2).collect();
    assert_eq!(
        report::preference_after_removal(&none),
        PreferredMechanism::Existing
    );
    w.finish(&[old, new]).await;
}

// =================================================================================
// A07: revocation
// =================================================================================

#[tokio::test]
async fn revoke_destroys_keys_under_exclusive_gate() {
    let w = World::new().await;
    let data = w.ensure("gate", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    let r = w.revoke(&gid, "rv-gate").await;
    assert!(r.local_applied);
    let log = w.hook.exclusive_at_destroy.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|(g, exclusive, had_key)| *g == gid && *exclusive && *had_key),
        "the key was destroyed while the gate was held exclusively: {log:?}"
    );
    assert!(w.table().public_key(&gid).is_none());
    assert_eq!(w.table().vault().len(), 0);
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn revoke_cascades_to_children_destroying_their_keys() {
    let w = World::new().await;
    let parent = w.ensure("casc-parent", &[h1(), h2()]).await;
    w.drive(&parent, "tok-p", Stage::Materialize).await;
    let child = w
        .ops
        .delegate(
            &owner(),
            DelegateRequest {
                parent_binding_id: parent.binding_id.clone(),
                scope: [AccessPairRef {
                    destination: h2().destination,
                    account: h2().account,
                }]
                .into_iter()
                .collect(),
                until: None,
                work_id: WorkId::parse("w-casc-child").unwrap(),
                request_id: RequestId::parse("r-casc-child").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .unwrap()
        .data;
    w.sources
        .children
        .lock()
        .unwrap()
        .insert(parent.grant_id.clone(), vec![child.grant_id.clone()]);
    w.drive_with(
        &child,
        "tok-c",
        Stage::Materialize,
        true,
        std::slice::from_ref(&parent.grant_id),
    )
    .await;
    assert_eq!(w.table().vault().len(), 2);
    w.revoke(&parent.grant_id, "rv-casc").await;
    assert!(w.table().public_key(&parent.grant_id).is_none());
    assert!(
        w.table().public_key(&child.grant_id).is_none(),
        "the child's key too"
    );
    assert_eq!(w.table().vault().len(), 0);
    assert!(
        w.grant(&child.grant_id).state.is_terminal()
            || w.grant(&child.grant_id).state == GrantState::Revoking
    );
    // The adapter's own revoke cascades through its source as well (idempotent).
    let o = w.adapter.revoke(&parent.grant_id, w.wall()).await.unwrap();
    assert_eq!(
        o.latest_possible_credential_expiry,
        Some(w.grant(&parent.grant_id).deadline.effective)
    );
    w.finish(&[parent.grant_id, child.grant_id]).await;
}

/// R-SE-07, through the real adapter: after the revocation, a stale published
/// certificate of the revoked grant can never be installed, and nothing reserves anew.
#[tokio::test]
async fn stale_approval_cannot_reactivate_after_revoke() {
    let w = World::new().await;
    let data = w.ensure("stale", &[h1()]).await;
    let gid = data.grant_id.clone();
    let d = w.drive(&data, "tok-stale", Stage::Publish).await;
    w.revoke(&gid, "rv-stale").await;
    assert!(w.table().public_key(&gid).is_none());
    // The stale certificate: no key, never installed.
    assert!(
        w.effects
            .install(&gid, &d.published[0], &d.certs[0].1)
            .await
            .is_err()
    );
    // The same effect token never regenerates the destroyed key.
    assert_eq!(
        w.effects.generate_key(&gid, "tok-stale").await.unwrap_err(),
        AdapterError::Protocol("key_destroyed".into())
    );
    // A new key cannot be certified: the reserve transaction refuses the grant.
    let key = w.effects.generate_key(&gid, "tok-new").await.unwrap();
    let g = w.grant(&gid);
    assert!(
        w.ops
            .reserve_issuance(w.request(&g, &h1(), &key.fingerprint, true))
            .await
            .is_err()
    );
    // Even a forged install of the stale certificate for the new key is refused (its
    // subject is the destroyed key), and the view refuses the revoked grant.
    assert!(
        w.effects
            .install(&gid, &d.published[0], &d.certs[0].1)
            .await
            .is_err()
    );
    assert!(w.table().installed_entries(&gid).is_empty());
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn revoke_with_unreachable_destination_reports_bounded_remote_effect() {
    let w = World::new().await;
    let data = w.ensure("unreach", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    let d = w.grant(&gid).deadline.effective;
    let data_rv = w.revoke(&gid, "rv-unreach").await;
    assert_eq!(data_rv.latest_possible_credential_expiry, Some(d));
    // The managed adapter's residual: no remote action exists (no KRL), so nothing
    // contacts the destination; each pair's residual is bounded by the measurement.
    let now = w.wall();
    let o = w.adapter.revoke(&gid, now).await.unwrap();
    assert_eq!(o.latest_possible_credential_expiry, Some(d));
    assert_eq!(o.remote_effects.len(), 2);
    for r in &o.remote_effects {
        assert_eq!(r.latest_valid_before, d);
        assert_eq!(r.destination_clock, DestinationClock::Measured(measured()));
        assert_eq!(r.status, ResidualStatus::PendingUntil);
        assert_eq!(r.until, report::completion_bound(d, &measured(), now));
        assert!(r.until.unwrap() > d);
    }
    let mut pending = o.remote_pending.clone();
    pending.sort();
    assert_eq!(pending, vec![h1().destination, h2().destination]);
    w.finish(&[gid]).await;
}

/// §17.1 item 10: with a measurement the completion bound is `latest_valid_before +
/// behind_upper + rtt + 100 ppm × (now − measured_at)`, and the residual closes only
/// after it on safe time. (Fixture measurement: U11's lagging sshd would produce it
/// at enrollment; U6 computes from the recorded value.)
#[tokio::test]
async fn slow_server_clock_residual_bounded_by_measurement() {
    let lag = ClockMeasurement {
        behind_upper_ms: 5_000,
        rtt_ms: 200,
        measured_at: t0(),
    };
    let w = World::with(Opts {
        pairs: vec![h1()],
        clock: Some(lag),
        ..Opts::default()
    })
    .await;
    let data = w.ensure("slow", &[h1()]).await;
    let data_pair = h1();
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    w.revoke(&gid, "rv-slow").await;
    let d = w.grant(&gid).deadline.effective;
    let now = w.wall();
    let o = w.adapter.revoke(&gid, now).await.unwrap();
    let elapsed_ms = u64::try_from(now.duration_since(t0()).as_millis()).unwrap();
    let expected = d
        .checked_add(Duration::from_millis(
            5_000 + 200 + elapsed_ms * 100 / 1_000_000,
        ))
        .unwrap();
    assert_eq!(o.remote_effects[0].until, Some(expected));
    assert_eq!(o.remote_effects[0].status, ResidualStatus::PendingUntil);
    // The revoke result moves nothing on the caller's (unvouched) time, however late.
    let o = w.adapter.revoke(&gid, shift(d, 3600)).await.unwrap();
    assert_eq!(o.remote_effects[0].status, ResidualStatus::PendingUntil);
    // On safe time (the supervisor's pass): just after D still pending, since the
    // server may lag by up to the bound; past the bound complete, with the
    // measurement it relied on.
    let entries = w.entries(&gid);
    let clocks: Vec<report::PairClock<'_>> = vec![(&data_pair, Some(lag))];
    let after_d = shift(d, 1);
    let fx = report::remote_effects(&entries, &clocks, after_d, Some(after_d), false);
    assert_eq!(fx[0].status, ResidualStatus::PendingUntil);
    assert!(fx[0].until.unwrap() > after_d);
    let late = shift(d, 3600);
    let fx = report::remote_effects(&entries, &clocks, late, Some(late), false);
    assert_eq!(fx[0].status, ResidualStatus::BoundedComplete);
    assert_eq!(fx[0].destination_clock, DestinationClock::Measured(lag));
    // Time not safe: nothing moves.
    let fx = report::remote_effects(&entries, &clocks, late, None, false);
    assert_eq!(fx[0].status, ResidualStatus::PendingUntil);
    let o = w.adapter.revoke(&gid, late).await.unwrap();
    assert_eq!(
        o.remote_pending,
        vec![h1().destination],
        "pending as at revocation"
    );
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn unmeasured_residual_reported_nominally_expired_never_cleared() {
    let w = World::with(Opts {
        pairs: vec![h1()],
        clock: None,
        ..Opts::default()
    })
    .await;
    let data = w.ensure("unmeasured", &[h1()]).await;
    let data_pair = h1();
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    w.revoke(&gid, "rv-unmeasured").await;
    let d = w.grant(&gid).deadline.effective;
    let o = w.adapter.revoke(&gid, w.wall()).await.unwrap();
    assert_eq!(
        o.remote_effects[0].destination_clock,
        DestinationClock::Unmeasured
    );
    assert_eq!(o.remote_effects[0].status, ResidualStatus::PendingUntil);
    assert_eq!(
        o.remote_effects[0].until, None,
        "no bound without a measurement"
    );
    let entries = w.entries(&gid);
    let clocks: Vec<report::PairClock<'_>> = vec![(&data_pair, None)];
    for later in [shift(d, 0), shift(d, 1), shift(d, 365 * 86_400)] {
        // On safe time: nominally expired, never cleared, and kept in the list.
        let fx = report::remote_effects(&entries, &clocks, later, Some(later), false);
        assert_eq!(fx.len(), 1, "the record is kept and listed");
        assert_eq!(fx[0].status, ResidualStatus::NominallyExpired);
        assert_ne!(fx[0].status, ResidualStatus::BoundedComplete);
        assert_eq!(fx[0].destination_clock, DestinationClock::Unmeasured);
        assert_eq!(fx[0].until, None);
        // The revoke result never shows it cleared either.
        let o = w.adapter.revoke(&gid, later).await.unwrap();
        assert_eq!(o.remote_effects.len(), 1);
        assert_ne!(o.remote_effects[0].status, ResidualStatus::BoundedComplete);
    }
    // A key-only restore: no bound at all.
    w.sources.key_only.store(true, Ordering::SeqCst);
    let o = w.adapter.revoke(&gid, w.wall()).await.unwrap();
    assert_eq!(o.remote_effects[0].status, ResidualStatus::UnboundedUnknown);
    w.finish(&[gid]).await;
}

#[tokio::test]
async fn revoke_result_lists_owned_connections_and_ordinary_note() {
    let w = World::new().await;
    let data = w.ensure("owned", &[h1()]).await;
    let gid = data.grant_id.clone();
    let row = |n: u8, kind| OwnedConnection {
        id: ConnectionId::from_random_bytes([n; 16]),
        kind,
        binding: data.binding_id.clone(),
        grant: gid.clone(),
        pid: 4242 + u32::from(n),
        start_token: format!("tok-{n}"),
        image: "/usr/bin/ssh".into(),
        control_path: None,
        generation: 1,
        state: OwnedConnectionState::Up,
        started_at: t0(),
    };
    let (a, b, c) = (
        row(1, ConnectionKind::Master),
        row(2, ConnectionKind::Dedicated),
        row(3, ConnectionKind::Dedicated),
    );
    w.store
        .transaction(|tx| {
            // A dedicated row belongs to a launch binding with a recorded holder (U7-Q4,
            // §17.20 item 14: the store refuses it otherwise).
            tx.set_binding_holder(
                &data.binding_id,
                &heimdall_domain::holder::ProcessHolder {
                    pid: 4200,
                    started_at: "1730419200.5".into(),
                },
            )?;
            tx.insert_owned_connection(&a)?;
            tx.insert_owned_connection(&b)?;
            tx.insert_owned_connection(&c)?;
            tx.close_owned_connection(&b.id, 1, OwnedConnectionState::Closed)?;
            tx.close_owned_connection(&c.id, 1, OwnedConnectionState::Unverified)?;
            Ok(())
        })
        .unwrap();
    let rows = w.sources.owned_connections(&w.sources.cascade(&gid));
    let mut reports = report::owned_connection_reports(&rows);
    reports.sort_by(|x, y| x.id.cmp(&y.id));
    let states: Vec<(ConnectionKind, OwnedConnectionReportState)> =
        reports.iter().map(|r| (r.kind, r.state)).collect();
    assert_eq!(
        states,
        vec![
            (ConnectionKind::Master, OwnedConnectionReportState::Closing),
            (
                ConnectionKind::Dedicated,
                OwnedConnectionReportState::Closed
            ),
            (
                ConnectionKind::Dedicated,
                OwnedConnectionReportState::Unverified
            ),
        ]
    );
    assert_eq!(
        report::revoke_notes(),
        vec![RevokeNote::OrdinaryConnectionsNotClosed]
    );
}

// =================================================================================
// Cleanup
// =================================================================================

#[tokio::test]
async fn release_destroys_key_without_tombstone() {
    let w = World::new().await;
    let data = w.ensure("release", &[h1()]).await;
    let gid = data.grant_id.clone();
    let d = w.drive(&data, "tok", Stage::Materialize).await;
    let files = d.prepared.unwrap().materialized.unwrap();
    w.ops
        .release(
            &owner(),
            ReleaseRequest {
                binding_id: data.binding_id.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("release: {} {}", e.code, e.message));
    // D7 item 7 (the cleanup U10 runs after release; fixture here): K_env destroyed,
    // the binding files removed, no tombstone, no cascade.
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    w.effects.clear(&data.binding_id, files.generation).unwrap();
    assert!(w.table().public_key(&gid).is_none());
    assert!(
        files.files.iter().all(|f| !f.exists()),
        "binding files removed"
    );
    assert!(
        w.store
            .transaction(|tx| tx.tombstone(&gid))
            .unwrap()
            .is_none(),
        "release writes no tombstone"
    );
    // Issued certificates stay in the residual until their valid_before.
    assert_eq!(
        w.residual(std::slice::from_ref(&gid)),
        Some(w.grant(&gid).deadline.effective)
    );
    w.finish(&[gid]).await;
}

/// At expiry the slot (held through the slot table, D10 item 2) and the binding
/// files are cleared by generation; a newer generation is never touched.
#[tokio::test]
async fn expiry_clears_slot_and_binding_files() {
    let w = World::new().await;
    let data = w.ensure("expiry", &[h1()]).await;
    let gid = data.grant_id.clone();
    let d = w.drive(&data, "tok", Stage::Materialize).await;
    let bfiles = d.prepared.unwrap().materialized.unwrap();
    // `run`'s auto-materialize: the slot table claims the free slot, writes it.
    let slots = ManagedSlotTable::new(StoreSlots(w.store.clone()), w.effects.clone());
    assert_eq!(
        slots.state(&h1()).unwrap(),
        SlotState::Free { generation: 0 }
    );
    let held = slots.claim(&data.binding_id, &h1()).unwrap();
    assert_eq!(
        held,
        SlotState::Held {
            binding: data.binding_id.clone(),
            generation: 1
        }
    );
    let paths = files::slot_paths(&w.data_dir(), &h1()).unwrap();
    assert!(paths.cert_pub.exists() && paths.key_pub.exists());
    assert_eq!(w.table().materialized_pairs(&data.binding_id), vec![h1()]);
    // Another binding asking is refused before any write.
    let other = w.ensure("expiry-other", &[h1()]).await;
    assert_eq!(
        slots.claim(&other.binding_id, &h1()).unwrap_err(),
        SlotClaimError::Refused(SlotRefusal::ManagedSlotHeld)
    );
    // The deadline passes: the grant expires; the cleanup clears by generation.
    w.clock.advance(3 * HOUR);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&gid).state, GrantState::Expired);
    w.store
        .transaction(|tx| tx.release_slot(&env_id(), &h1(), &data.binding_id, 1, t0()))
        .unwrap()
        .unwrap();
    assert_eq!(
        w.effects.clear_slot(&data.binding_id, &h1(), 1).unwrap(),
        ClearOutcome::Removed
    );
    w.effects
        .clear(&data.binding_id, bfiles.generation)
        .unwrap();
    w.effects.destroy(std::slice::from_ref(&gid)).await.unwrap();
    assert!(!paths.cert_pub.exists() && !paths.key_pub.exists());
    assert!(bfiles.files.iter().all(|f| !f.exists()));
    assert!(w.table().materialized_pairs(&data.binding_id).is_empty());
    assert_eq!(
        w.store
            .transaction(|tx| tx.slot_files_removed(&env_id(), &h1(), 1, t0()))
            .unwrap()
            .unwrap(),
        SlotState::Free { generation: 1 }
    );
    // g + 1 for the next holder; a late clear of g leaves it.
    let next = w.ensure("expiry-next", &[h1()]).await;
    w.drive(&next, "tok-next", Stage::Materialize).await;
    let held2 = slots.claim(&next.binding_id, &h1()).unwrap();
    assert_eq!(
        held2,
        SlotState::Held {
            binding: next.binding_id.clone(),
            generation: 2
        }
    );
    assert_eq!(
        w.effects.clear_slot(&data.binding_id, &h1(), 1).unwrap(),
        ClearOutcome::OtherGeneration(2)
    );
    w.effects.clear(&data.binding_id, 1).unwrap();
    assert!(
        paths.cert_pub.exists(),
        "the newer generation's files are untouched"
    );
    assert_eq!(
        files::slot_generation(w.effects.slot_root(), &h1()).unwrap(),
        Some(2)
    );
    w.finish(&[gid, other.grant_id, next.grant_id]).await;
}

#[tokio::test]
async fn residual_counts_reserved_and_published_excludes_voided() {
    let w = World::new().await;
    let data = w.ensure("residual", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    // h1 published, h2 only reserved.
    let d = w.drive(&data, "tok", Stage::Reserve).await;
    let (e1, e2) = (d.reserved[0].clone(), d.reserved[1].clone());
    let (published, _) = w.publish(&gid, e1, true).await.unwrap();
    let deadline = w.grant(&gid).deadline.effective;
    let mut entries = w.entries(&gid);
    assert!(entries.iter().any(|e| e.state == IssuanceState::Published));
    assert!(
        entries
            .iter()
            .any(|e| e.state == IssuanceState::Reserved && e.id == e2.id)
    );
    // A voided entry with a later bound is excluded.
    let mut voided = published.clone();
    voided.state = IssuanceState::Voided;
    voided.bounds.valid_before = shift(deadline, 3600);
    entries.push(voided);
    assert_eq!(
        report::latest_possible_credential_expiry(&entries),
        Some(deadline)
    );
    let fx = report::remote_effects(&entries, &[], w.wall(), Some(w.wall()), false);
    assert_eq!(fx.len(), 2, "one row per pair with a counted entry");
    assert!(fx.iter().all(|r| r.latest_valid_before == deadline));
    // And through the adapter's revoke, over the store's entries.
    let o = w.adapter.revoke(&gid, w.wall()).await.unwrap();
    assert_eq!(o.latest_possible_credential_expiry, Some(deadline));
    assert_eq!(o.remote_effects.len(), 2);
    w.finish(&[gid]).await;
}

/// The vault-slot counter (`KeyVault::len`, read in test configuration only): after a
/// full activation, revocation and cleanup, no slot is left; every test above ends
/// with the same check (`World::finish`).
#[tokio::test]
async fn no_leftover_vault_slots_after_every_test() {
    let w = World::new().await;
    let a = w.ensure("vault-a", &[h1(), h2()]).await;
    let b = w.ensure("vault-b", &[h1()]).await;
    w.drive(&a, "tok-a", Stage::Materialize).await;
    w.drive(&b, "tok-b", Stage::Install).await;
    assert_eq!(w.table().vault().len(), 2);
    w.revoke(&a.grant_id, "rv-vault").await;
    assert_eq!(
        w.table().vault().len(),
        1,
        "the revoked grant's slot is gone"
    );
    w.finish(&[a.grant_id, b.grant_id]).await;
}

// =================================================================================
// A07 with a real issuer child (Unix: this test binary, re-executed)
// =================================================================================

#[cfg(unix)]
mod issuer_child {
    //! The issuer child as a real process: this test binary re-executed through
    //! `/bin/sh` with `HM_U6_CHILD_*` set runs `child_process_entry`, whose protocol
    //! output goes to descriptor 3 (libtest's own stdout goes to `/dev/null`); the
    //! U3 pattern. Processes are ended only through the client's own `stop`.

    use super::*;
    use heimdall_issuer::client::{ChildCommand, ChildIssuer, ClientConfig};

    const DB_ENV: &str = "HM_U6_CHILD_DB";
    const STORE_ENV: &str = "HM_U6_CHILD_STORE";
    const WALL_ENV: &str = "HM_U6_CHILD_WALL";

    /// The child entry (a no-op unless re-executed by [`client`]).
    #[test]
    fn child_process_entry() {
        let (Some(db), Some(store), Some(wall)) = (
            std::env::var_os(DB_ENV),
            std::env::var_os(STORE_ENV),
            std::env::var_os(WALL_ENV),
        ) else {
            return;
        };
        let clock = VirtualClock::at(wall.to_str().unwrap().parse().unwrap());
        let out = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/fd/3")
            .unwrap();
        let store = Box::new(ScratchSecretStore::new(PathBuf::from(store)));
        let status =
            heimdall_issuer::child::run(std::io::stdin(), out, store, Path::new(&db), clock);
        std::process::exit(status);
    }

    fn start_token(pid: u32) -> Option<String> {
        let out = std::process::Command::new("ps")
            .args(["-o", "lstart=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
        (!s.is_empty()).then_some(s)
    }

    /// A client whose child reads the world's state database with its clock at the
    /// world's current wall time.
    pub(super) fn client(w: &World) -> ChildIssuer {
        let exe = std::env::current_exe().unwrap();
        let env = vec![
            (DB_ENV.into(), w.db.clone().into_os_string()),
            (
                STORE_ENV.into(),
                w.dir.path().join("store").into_os_string(),
            ),
            (WALL_ENV.into(), w.wall().to_string().into()),
        ];
        ChildIssuer::new(ClientConfig::new(
            ChildCommand {
                program: PathBuf::from("/bin/sh"),
                args: vec![
                    "-c".into(),
                    "exec 3>&1 1>/dev/null 2>/dev/null; exec \"$0\" --exact issuer_child::child_process_entry --nocapture --test-threads=1 -q".into(),
                    exe.into_os_string(),
                ],
                env,
            },
            Arc::new(start_token),
        ))
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum A07Event {
    Revoke,
    Cutoff,
    Deadline,
    TimeUncertain,
}

#[cfg(unix)]
async fn inject(w: &World, gid: &GrantId, event: A07Event, tag: &str) {
    match event {
        A07Event::Revoke => {
            w.revoke(gid, &format!("rv-{tag}")).await;
        }
        A07Event::Cutoff => {
            w.ops
                .policy(
                    &owner(),
                    heimdall_contract::request::PolicyAction::Cutoff {
                        policy_id: policy_id(),
                        at: shift(w.wall(), 1),
                    },
                )
                .await
                .unwrap_or_else(|e| panic!("cutoff: {} {}", e.code, e.message));
            w.clock.advance(Duration::from_secs(2));
            w.ops.tick().await.unwrap();
        }
        A07Event::Deadline => {
            w.clock.advance(3 * HOUR);
            w.ops.tick().await.unwrap();
        }
        A07Event::TimeUncertain => {
            w.clock.set_wall(shift(w.wall(), -7200));
        }
    }
}

/// A07: with a real issuer child, a revocation, a cutoff, the deadline's passage and
/// `TIME_UNCERTAIN`, each injected at reserve, sign, publish and install: the result
/// is always refused (or the entry voided), and every reservation made stays counted.
#[cfg(unix)]
#[tokio::test]
async fn revoke_during_each_issuance_step() {
    use heimdall_app::ports::{IssuanceRef, IssuanceTable, IssuerPort};
    let mut refused = 0usize;
    for step in [Stage::Reserve, Stage::Sign, Stage::Publish, Stage::Install] {
        for event in [
            A07Event::Revoke,
            A07Event::Cutoff,
            A07Event::Deadline,
            A07Event::TimeUncertain,
        ] {
            let tag = format!("{step:?}-{event:?}").to_lowercase();
            let w = World::with(Opts {
                pairs: vec![h1()],
                ..Opts::default()
            })
            .await;
            let data = w.ensure(&tag, &[h1()]).await;
            let gid = data.grant_id.clone();
            let g = w.grant(&gid);
            let key = w.effects.generate_key(&gid, "tok").await.unwrap();
            w.ops.signing_gates().retain(&gid, &[]);
            let request = w.request(&g, &h1(), &key.fingerprint, true);
            if step == Stage::Reserve {
                inject(&w, &gid, event, &tag).await;
                assert!(w.ops.reserve_issuance(request).await.is_err(), "{tag}");
                refused += 1;
                w.finish(&[gid]).await;
                continue;
            }
            let entry = w.ops.reserve_issuance(request).await.unwrap();
            let entry_ref = IssuanceRef {
                table: IssuanceTable::Grant,
                id: entry.id.clone(),
            };
            if step == Stage::Sign {
                inject(&w, &gid, event, &tag).await;
                let issuer = issuer_child::client(&w);
                issuer
                    .start()
                    .await
                    .unwrap_or_else(|e| panic!("{tag}: start {e}"));
                let r = issuer.sign(entry_ref, &key.public_key).await;
                issuer.stop().await;
                assert!(r.is_err(), "{tag}: the child's re-check refuses: {r:?}");
                refused += 1;
            } else {
                let issuer = issuer_child::client(&w);
                issuer
                    .start()
                    .await
                    .unwrap_or_else(|e| panic!("{tag}: start {e}"));
                let cert = issuer
                    .sign(entry_ref, &key.public_key)
                    .await
                    .unwrap_or_else(|e| panic!("{tag}: sign {e}"));
                issuer.stop().await;
                if step == Stage::Publish {
                    inject(&w, &gid, event, &tag).await;
                    let r = w.ops.publish_issuance(&entry.id, &facts(true)).await;
                    assert!(r.is_err(), "{tag}: publication refused");
                    refused += 1;
                } else {
                    let Publication::Published(published) = w
                        .ops
                        .publish_issuance(&entry.id, &facts(true))
                        .await
                        .unwrap()
                    else {
                        panic!("{tag}: re-reserved");
                    };
                    inject(&w, &gid, event, &tag).await;
                    let r = w.effects.install(&gid, &published, &cert).await;
                    assert!(r.is_err(), "{tag}: installation refused: {r:?}");
                    assert!(w.table().installed_entries(&gid).is_empty());
                    refused += 1;
                }
            }
            // Counted: the reservation is still `reserved` or `published` (in the
            // residual), or `voided` by the refusing publication.
            let e = w
                .entries(&gid)
                .into_iter()
                .find(|x| x.id == entry.id)
                .unwrap();
            match e.state {
                IssuanceState::Reserved | IssuanceState::Published => assert_eq!(
                    w.residual(std::slice::from_ref(&gid)),
                    Some(e.bounds.valid_before),
                    "{tag}"
                ),
                IssuanceState::Voided => assert_eq!(step, Stage::Publish, "{tag}"),
            }
            w.finish(&[gid]).await;
        }
    }
    assert_eq!(refused, 16, "every injection refused");
}

/// F04 (U0b row 9's resolution, observed with the managed adapter's descriptor
/// configured): while a pair's managed projection is `pending`, an ordinary request
/// resolves to the existing path with the warning `managed_projection_pending`; only a
/// request whose minimums need the managed mechanism is refused `projection_pending`.
#[tokio::test]
async fn projection_pending_refused_only_for_managed_only_minimums() {
    let w = World::new().await;
    set_preference(&w, &h1(), PreferredMechanism::ManagedCertificate, false);
    let ordinary = w
        .ops
        .ensure(
            &owner(),
            EnsureRequest {
                profile: ProfileId::parse("dev").unwrap(),
                profile_revision: None,
                scope: [h1()].into_iter().collect(),
                environment: None,
                work_id: WorkId::parse("w-pending").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-pending").unwrap(),
                interaction: InteractionMode::NonInteractive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("ordinary: {} {}", e.code, e.message));
    assert!(
        ordinary
            .warnings
            .iter()
            .any(|x| x.code == heimdall_contract::envelope::m03_warning::MANAGED_PROJECTION_PENDING),
        "{:?}",
        ordinary.warnings
    );
    let managed_only = RequiredCapabilities {
        destination_scope_at_least: Some(DestinationScopeEnforcement::VerifiedServerPrincipals),
        ..RequiredCapabilities::default()
    };
    let e = w
        .try_ensure("pending-min", &[h1()], managed_only)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some(heimdall_contract::envelope::reason::PROJECTION_PENDING)
    );
}

// =================================================================================
// Wave 3 round 2 (ADR-0008 §17.20): the review fixes' regressions
// =================================================================================

/// The fixture certificate line every file-level case writes (public format only).
const FIX_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkey heimdall:x";

fn fix_cert(n: u8) -> String {
    format!("ssh-ed25519-cert-v01@openssh.com AAAAIGNlcnQ{n}= heimdall:x")
}

/// A scratch state and runtime directory (the anchors exist, as in production).
/// The state or runtime directory a managed root is opened at, created owner-only as
/// `Paths::ensure` creates it in production (mode 0700, explicitly, whatever the umask:
/// the devbox's umask 002 would leave a plain `create_dir` at 0775, which the anchor
/// check refuses; ADR-0008 §17.20 item 7, round 3).
fn owner_only_anchor(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::create_dir(path).unwrap();
}

fn anchors() -> (tempfile::TempDir, SlotRoot, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    owner_only_anchor(&dir.path().join("state"));
    owner_only_anchor(&dir.path().join("run"));
    let root = SlotRoot {
        data_dir: dir.path().join("state"),
        environment: env_id(),
    };
    let rd = dir.path().join("run");
    (dir, root, rd)
}

fn free_slot(w: &World, binding: &BindingId, pair: &AccessPair, generation: u64) {
    w.store
        .transaction(|tx| tx.release_slot(&env_id(), pair, binding, generation, t0()))
        .unwrap()
        .unwrap();
    w.store
        .transaction(|tx| tx.slot_files_removed(&env_id(), pair, generation, t0()))
        .unwrap()
        .unwrap();
}

/// §17.20 item 1 (W3-R01 = W3-S05; the security review's `LATE_WRITE` probe, ported):
/// a generation-1 write delayed past a release and a generation-2 claim leaves
/// generation 2's marker and bytes unchanged; a write the store no longer backs
/// publishes nothing.
#[tokio::test]
async fn stale_generation_write_never_rolls_back_the_slot() {
    // The probe: generation 2 written, then the delayed generation-1 write.
    let (_dir, root, _rd) = anchors();
    let (b1, b2) = (
        BindingId::from_random_bytes([1; 16]),
        BindingId::from_random_bytes([2; 16]),
    );
    let paths = files::slot_paths(&root.data_dir, &h1()).unwrap();
    files::write_slot(&root, &env_id(), &h1(), &b2, 2, FIX_KEY, &fix_cert(2)).unwrap();
    let late = files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1));
    assert!(
        matches!(late, Err(files::FilesError::StaleGeneration(2))),
        "{late:?}"
    );
    assert_eq!(files::slot_generation(&root, &h1()).unwrap(), Some(2));
    let marker = std::fs::read_to_string(paths.dir.join(files::GENERATION_FILE)).unwrap();
    assert_eq!(marker, format!("2 {}\n", b2.as_str()));
    assert_eq!(
        std::fs::read_to_string(&paths.cert_pub).unwrap(),
        format!("{}\n", fix_cert(2))
    );
    // Another holder at the same generation is refused too.
    assert!(matches!(
        files::write_slot(&root, &env_id(), &h1(), &b1, 2, FIX_KEY, &fix_cert(1)),
        Err(files::FilesError::OtherHolder)
    ));
    assert_eq!(
        std::fs::read_to_string(&paths.cert_pub).unwrap(),
        format!("{}\n", fix_cert(2))
    );
    // A clear of generation 2 still finds generation 2 (never `OtherGeneration(1)`).
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 2).unwrap(),
        ClearOutcome::Removed
    );

    // Through the effects: the store's holder and generation are re-validated first.
    let w = World::new().await;
    let a = w.ensure("late-a", &[h1()]).await;
    w.drive(&a, "tok-a", Stage::Materialize).await;
    let b = w.ensure("late-b", &[h1()]).await;
    w.drive(&b, "tok-b", Stage::Materialize).await;
    let slots = ManagedSlotTable::new(StoreSlots(w.store.clone()), w.effects.clone());
    slots.claim(&a.binding_id, &h1()).unwrap();
    // A's generation 1 is released and cleared; the store frees it.
    w.store
        .transaction(|tx| tx.release_slot(&env_id(), &h1(), &a.binding_id, 1, t0()))
        .unwrap()
        .unwrap();
    assert_eq!(
        w.effects.clear_slot(&a.binding_id, &h1(), 1).unwrap(),
        ClearOutcome::Removed
    );
    w.store
        .transaction(|tx| tx.slot_files_removed(&env_id(), &h1(), 1, t0()))
        .unwrap()
        .unwrap();
    let wpaths = files::slot_paths(&w.data_dir(), &h1()).unwrap();
    // A delayed generation-1 write after the clear (no marker left to fence it): the
    // store shows the slot free, so nothing is published.
    assert_eq!(
        w.effects
            .materialize_slot(&a.binding_id, &h1(), 1)
            .unwrap_err(),
        AdapterError::Protocol(heimdall_adapters::managed::effects::SLOT_HOLDER_CHANGED.into())
    );
    assert!(!wpaths.cert_pub.exists() && !wpaths.key_pub.exists());
    assert!(w.table().materialized_pairs(&a.binding_id).is_empty());
    // B claims generation 2; A's delayed generation-1 write then changes nothing.
    slots.claim(&b.binding_id, &h1()).unwrap();
    let marker2 = std::fs::read_to_string(wpaths.dir.join(files::GENERATION_FILE)).unwrap();
    let cert2 = std::fs::read_to_string(&wpaths.cert_pub).unwrap();
    assert_eq!(marker2, format!("2 {}\n", b.binding_id.as_str()));
    assert!(w.effects.materialize_slot(&a.binding_id, &h1(), 1).is_err());
    assert_eq!(
        std::fs::read_to_string(wpaths.dir.join(files::GENERATION_FILE)).unwrap(),
        marker2
    );
    assert_eq!(std::fs::read_to_string(&wpaths.cert_pub).unwrap(), cert2);
    assert_eq!(
        w.table().materialized_generation(&b.binding_id, &h1()),
        Some(2)
    );
    w.finish(&[a.grant_id, b.grant_id]).await;
}

/// A [`SlotStore`] whose `claim` stops until released (the serialization regression).
struct GatedSlots {
    inner: StoreSlots,
    entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl SlotStore for GatedSlots {
    fn slot(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
    ) -> Result<SlotState, AdapterError> {
        self.inner.slot(environment, pair)
    }
    fn claim(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
    ) -> Result<Result<SlotState, SlotRefusal>, AdapterError> {
        let r = self.inner.claim(environment, pair, binding);
        if let Some(tx) = self.entered.lock().unwrap().take() {
            tx.send(()).unwrap();
        }
        if let Some(rx) = self.release.lock().unwrap().take() {
            rx.recv().unwrap();
        }
        r
    }
}

/// §17.20 item 1: a slot's claim, its materialization and a clear of it are
/// serialized. A clear issued while the claim is between its store CAS and its files
/// waits for the claim's publication, so it can never run before the write it clears.
#[tokio::test]
async fn slot_claim_and_clear_are_serialized() {
    let w = World::new().await;
    let a = w.ensure("serial", &[h1()]).await;
    w.drive(&a, "tok", Stage::Materialize).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let slots = ManagedSlotTable::new(
        GatedSlots {
            inner: StoreSlots(w.store.clone()),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
        },
        w.effects.clone(),
    );
    let order = Mutex::new(Vec::new());
    let cleared = AtomicBool::new(false);
    let raced = std::thread::scope(|s| {
        s.spawn(|| {
            slots.claim(&a.binding_id, &h1()).unwrap();
            order.lock().unwrap().push("claim");
        });
        entered_rx.recv().unwrap();
        s.spawn(|| {
            let _ = w.effects.clear_slot(&a.binding_id, &h1(), 1);
            cleared.store(true, Ordering::SeqCst);
            order.lock().unwrap().push("clear");
        });
        std::thread::sleep(Duration::from_millis(300));
        let raced = cleared.load(Ordering::SeqCst);
        // Released before any assertion, so a failure never leaves the claim waiting.
        release_tx.send(()).unwrap();
        raced
    });
    assert!(
        !raced,
        "the clear ran while the claim was between its CAS and its files"
    );
    assert_eq!(*order.lock().unwrap(), vec!["claim", "clear"]);
    // The clear came after the claim's files: generation 1 is gone, not resurrected.
    let paths = files::slot_paths(&w.data_dir(), &h1()).unwrap();
    assert!(!paths.cert_pub.exists());
    w.finish(&[a.grant_id]).await;
}

/// §17.20 item 2 (W3-R02): a binding re-materialized at generation N+1 keeps its
/// listing after a clear for N (in the signer and on disk).
#[tokio::test]
async fn stale_clear_never_unlists_the_current_binding() {
    let w = World::new().await;
    let a = w.ensure("relist", &[h1()]).await;
    let d = w.drive(&a, "tok", Stage::Materialize).await;
    let slots = ManagedSlotTable::new(StoreSlots(w.store.clone()), w.effects.clone());
    slots.claim(&a.binding_id, &h1()).unwrap();
    // Generation 1 ends; its first clear ran; the store frees it; the same binding
    // claims again: generation 2.
    w.store
        .transaction(|tx| tx.release_slot(&env_id(), &h1(), &a.binding_id, 1, t0()))
        .unwrap()
        .unwrap();
    w.effects.clear_slot(&a.binding_id, &h1(), 1).unwrap();
    w.store
        .transaction(|tx| tx.slot_files_removed(&env_id(), &h1(), 1, t0()))
        .unwrap()
        .unwrap();
    slots.claim(&a.binding_id, &h1()).unwrap();
    // The binding files are re-materialized at resource generation 2 (a re-issue).
    let key = d.key.clone().unwrap();
    let bfiles = w
        .effects
        .materialize(
            &a.binding_id,
            &MaterializeSpec {
                generation: 2,
                source: MaterializeSource::Fresh {
                    public_key: key.public_key.clone(),
                    certificates: d
                        .certs
                        .iter()
                        .map(|(p, c)| MaterializedCertificate {
                            pair: p.clone(),
                            certificate: c.clone(),
                        })
                        .collect(),
                },
                environment_slots: false,
            },
        )
        .unwrap();
    let env = heimdall_app::ports::SignerEndpoint::Environment;
    assert_eq!(w.table().list(&env).len(), 1);
    // The stale clears of generation 1, of the slot and of the binding.
    assert_eq!(
        w.effects.clear_slot(&a.binding_id, &h1(), 1).unwrap(),
        ClearOutcome::OtherGeneration(2)
    );
    w.effects.clear(&a.binding_id, 1).unwrap();
    assert_eq!(
        w.table().materialized_generation(&a.binding_id, &h1()),
        Some(2),
        "the current listing survives a clear for an older generation"
    );
    assert_eq!(w.table().list(&env).len(), 1);
    let paths = files::slot_paths(&w.data_dir(), &h1()).unwrap();
    assert!(paths.cert_pub.exists());
    assert!(bfiles.files.iter().all(|f| f.exists()));
    // The current generation's clear withdraws it.
    assert_eq!(
        w.effects.clear_slot(&a.binding_id, &h1(), 2).unwrap(),
        ClearOutcome::Removed
    );
    assert!(w.table().list(&env).is_empty());
    w.finish(&[a.grant_id]).await;
}

/// §17.20 item 2 (W3-R02): clearing one pair withdraws only that pair; a second pair
/// keeps its listing and files.
#[tokio::test]
async fn clearing_one_pair_keeps_the_other_pairs_listing() {
    let w = World::new().await;
    let a = w.ensure("twopairs", &[h1(), h2()]).await;
    w.drive(&a, "tok", Stage::Materialize).await;
    let slots = ManagedSlotTable::new(StoreSlots(w.store.clone()), w.effects.clone());
    slots.claim(&a.binding_id, &h1()).unwrap();
    slots.claim(&a.binding_id, &h2()).unwrap();
    let env = heimdall_app::ports::SignerEndpoint::Environment;
    assert_eq!(w.table().list(&env).len(), 2);
    free_slot(&w, &a.binding_id, &h1(), 1);
    assert_eq!(
        w.effects.clear_slot(&a.binding_id, &h1(), 1).unwrap(),
        ClearOutcome::Removed
    );
    assert_eq!(w.table().materialized_pairs(&a.binding_id), vec![h2()]);
    assert_eq!(w.table().list(&env).len(), 1);
    let p2 = files::slot_paths(&w.data_dir(), &h2()).unwrap();
    assert!(p2.cert_pub.exists() && p2.key_pub.exists());
    w.finish(&[a.grant_id]).await;
}

/// §17.20 item 7 (W3-S04; the security review's three probe cases, ported, plus the
/// restart enumeration over a planted entry): managed files never follow a planted
/// directory, an open directory is refused and never repaired, nothing is removed
/// through an unverified directory.
#[cfg(unix)]
#[test]
fn managed_files_never_follow_a_planted_directory() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
    let unsafe_dir = |r: Result<Vec<PathBuf>, files::FilesError>| {
        assert!(matches!(r, Err(files::FilesError::Unsafe(_))), "{r:?}");
    };
    // W3-C02: only the no-follow refusal may fire. Every planted target is an
    // **acceptable** directory (owned, mode 0700, set explicitly whatever the umask), so
    // the permission check cannot mask a followed link; the refusal must name the link.
    let link_refused = |r: Result<(), files::FilesError>, what: &str| match r {
        Err(files::FilesError::Unsafe(why)) => {
            assert!(
                why.contains("symlink"),
                "{what}: refused for {why}, not the link"
            )
        }
        other => panic!("{what}: a planted symlink was followed: {other:?}"),
    };
    let owner_only_victim = |p: &Path| {
        std::fs::create_dir(p).unwrap();
        set_mode(p, 0o700);
        assert_eq!(mode(p), 0o700, "the victim is an acceptable directory");
    };
    let b1 = BindingId::from_random_bytes([1; 16]);

    // 1. A parent symlink: `<state_dir>/managed` → an unrelated owner-only directory.
    let (dir, root, _rd) = anchors();
    let victim = dir.path().join("victim");
    owner_only_victim(&victim);
    symlink(&victim, root.data_dir.join("managed")).unwrap();
    link_refused(
        files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1)).map(|_| ()),
        "parent write",
    );
    assert_eq!(
        std::fs::read_dir(&victim).unwrap().count(),
        0,
        "nothing written there"
    );
    link_refused(
        files::slots_written_by(&root.data_dir, &b1).map(|_| ()),
        "parent enumeration",
    );

    // 2. A leaf symlink on clear: `<state_dir>/managed/h1` → a directory holding a
    // matching plaintext marker and the slot's file names.
    let (dir, root, rd) = anchors();
    let victim = dir.path().join("victim");
    owner_only_victim(&victim);
    for (n, c) in [
        (files::GENERATION_FILE, format!("1 {}\n", b1.as_str())),
        ("key.pub", "unrelated\n".to_owned()),
        ("cert.pub", "unrelated\n".to_owned()),
    ] {
        std::fs::write(victim.join(n), c).unwrap();
    }
    let managed = root.data_dir.join("managed");
    std::fs::create_dir(&managed).unwrap();
    set_mode(&managed, 0o700);
    symlink(&victim, managed.join("h1")).unwrap();
    let victim_names = || {
        let mut n: Vec<String> = std::fs::read_dir(&victim)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    };
    let before = victim_names();
    link_refused(
        files::clear_slot(&root, &env_id(), &h1(), 1).map(|_| ()),
        "leaf clear",
    );
    link_refused(
        files::slot_generation(&root, &h1()).map(|_| ()),
        "leaf read",
    );
    link_refused(
        files::clear_slot_dir(&managed.join("h1"), &b1, 1).map(|_| ()),
        "leaf clear by directory",
    );
    link_refused(
        files::write_slot(&root, &env_id(), &h1(), &b1, 2, FIX_KEY, &fix_cert(2)).map(|_| ()),
        "leaf write",
    );
    assert_eq!(
        victim_names(),
        before,
        "nothing written into or removed from it"
    );
    // Restart enumeration over the planted entry: never followed, never listed.
    assert!(
        files::slots_written_by(&root.data_dir, &b1)
            .unwrap()
            .is_empty()
    );
    // The same at a binding directory `<runtime_dir>/b/<tag>`.
    let tag = EndpointTag::parse("00112233aabbccdd").unwrap();
    std::fs::create_dir(rd.join("b")).unwrap();
    set_mode(&rd.join("b"), 0o700);
    symlink(&victim, rd.join("b").join(tag.as_str())).unwrap();
    let bf = files::binding_files(&rd, &tag, &[h1().destination]).unwrap();
    link_refused(
        files::clear_binding_files(&bf, &b1, 1).map(|_| ()),
        "binding clear",
    );
    link_refused(
        files::write_binding_files(&bf, &b1, 1, FIX_KEY, &[]).map(|_| ()),
        "binding write",
    );
    assert!(files::binding_directories_of(&rd, &b1).unwrap().is_empty());
    assert_eq!(
        victim_names(),
        before,
        "nothing written into or removed from it"
    );
    for n in [files::GENERATION_FILE, "key.pub", "cert.pub"] {
        assert!(
            victim.join(n).exists(),
            "{n} deleted through a planted link"
        );
    }
    // A planted `b` itself: refused.
    let (_d3, _root3, rd3) = anchors();
    symlink(&victim, rd3.join("b")).unwrap();
    link_refused(
        files::binding_directories_of(&rd3, &b1).map(|_| ()),
        "planted b",
    );
    assert_eq!(victim_names(), before);

    // 3. A pre-existing 0777 directory: refused, `managed_dir_unsafe`, never repaired.
    let (_d4, root, _rd) = anchors();
    let leaf = files::slot_paths(&root.data_dir, &h1()).unwrap().dir;
    std::fs::create_dir_all(&leaf).unwrap();
    set_mode(&root.data_dir.join("managed"), 0o700);
    set_mode(&leaf, 0o777);
    unsafe_dir(files::write_slot(
        &root,
        &env_id(),
        &h1(),
        &b1,
        1,
        FIX_KEY,
        &fix_cert(1),
    ));
    assert_eq!(mode(&leaf), 0o777, "never repaired silently");
    assert_eq!(std::fs::read_dir(&leaf).unwrap().count(), 0);
    let e = files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1)).unwrap_err();
    assert!(e.to_string().starts_with(files::MANAGED_DIR_UNSAFE), "{e}");
    set_mode(&root.data_dir.join("managed"), 0o777);
    set_mode(&leaf, 0o700);
    unsafe_dir(files::write_slot(
        &root,
        &env_id(),
        &h1(),
        &b1,
        1,
        FIX_KEY,
        &fix_cert(1),
    ));

    // A symlink planted at a file's name inside a verified slot directory: the clear
    // refuses it and removes nothing (every removal is the quarantine's verified one).
    let (d6, root, _rd) = anchors();
    files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1)).unwrap();
    let leaf = files::slot_paths(&root.data_dir, &h1()).unwrap().dir;
    let outside = d6.path().join("outside.pub");
    std::fs::write(&outside, "unrelated\n").unwrap();
    std::fs::remove_file(leaf.join("key.pub")).unwrap();
    symlink(&outside, leaf.join("key.pub")).unwrap();
    assert!(matches!(
        files::clear_slot(&root, &env_id(), &h1(), 1),
        Err(files::FilesError::Unsafe(_))
    ));
    assert!(outside.exists() && leaf.join("key.pub").symlink_metadata().is_ok());
    assert_eq!(files::slot_generation(&root, &h1()).unwrap(), Some(1));
    // Without the planted entry the clear removes the generation and leaves no
    // quarantine behind.
    std::fs::remove_file(leaf.join("key.pub")).unwrap();
    assert_eq!(
        files::clear_slot(&root, &env_id(), &h1(), 1).unwrap(),
        ClearOutcome::Removed
    );
    assert_eq!(std::fs::read_dir(&leaf).unwrap().count(), 0);

    // The positive case: levels created 0700, the files public 0644.
    let (_d5, root, _rd) = anchors();
    let written =
        files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1)).unwrap();
    let leaf = files::slot_paths(&root.data_dir, &h1()).unwrap().dir;
    assert_eq!(mode(&root.data_dir.join("managed")), 0o700);
    assert_eq!(mode(&leaf), 0o700);
    assert!(written.iter().all(|f| mode(f) == 0o644));
    assert_eq!(
        files::slots_written_by(&root.data_dir, &b1).unwrap(),
        vec![(leaf, 1)]
    );
}

/// §17.20 item 7 on Windows (needs the Windows-native run): an existing managed
/// directory without Heimdall's owner-only DACL (here, one with the inherited DACL of
/// a scratch directory) and a junction at a level are refused, `managed_dir_unsafe`,
/// and nothing is written through them.
#[cfg(windows)]
#[test]
fn managed_dir_windows_refuses_inherited_dacl_and_junction() {
    let b1 = BindingId::from_random_bytes([1; 16]);
    let (dir, root, _rd) = anchors();
    std::fs::create_dir(root.data_dir.join("managed")).unwrap();
    let r = files::write_slot(&root, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1));
    assert!(matches!(r, Err(files::FilesError::Unsafe(_))), "{r:?}");
    // A junction (no privilege needed) at `managed`.
    let (dir2, root2, _rd2) = anchors();
    // W3-C02: the victim gets Heimdall's owner-only DACL (created through `ManagedDir`,
    // which then verifies it), so only the reparse-point refusal can fire.
    let victim = dir2.path().join("victim");
    heimdall_localenv::sys::ManagedDir::open_root(dir2.path())
        .unwrap()
        .unwrap()
        .child("victim", true)
        .unwrap()
        .unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root2.data_dir.join("managed"))
        .arg(&victim)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");
    let r = files::write_slot(&root2, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1));
    assert!(
        matches!(&r, Err(files::FilesError::Unsafe(why)) if why.contains("reparse point")),
        "{r:?}"
    );
    assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0);
    // The positive case: created levels pass their own check.
    let (_d3, root3, _rd3) = anchors();
    files::write_slot(&root3, &env_id(), &h1(), &b1, 1, FIX_KEY, &fix_cert(1)).unwrap();
    assert_eq!(files::slot_generation(&root3, &h1()).unwrap(), Some(1));
    drop(dir);
}

/// §17.20 item 8 (W3-R06): coverage never exceeds the shortest certificate; an
/// expired or not-yet-valid certificate is refused; an offline minimum beyond the
/// shortest certificate is `capability_unavailable`.
#[tokio::test]
async fn coverage_never_exceeds_the_shortest_certificate() {
    let w = World::new().await;
    let data = w.ensure("short", &[h1(), h2()]).await;
    let mut grant = w.grant(&data.grant_id);
    let now: Timestamp = "2026-11-10T10:00:00Z".parse().unwrap();
    let deadline = shift(now, 12 * 3600);
    let short = shift(now, 15 * 60);
    grant.deadline.effective = deadline;
    grant.scope.pairs = [h1(), h2()].into_iter().collect();
    let cert = |p: AccessPair, vb: Timestamp, n: u8| PreparedCertificate {
        pair: p,
        issuance: heimdall_contract::ids::IssuanceId::from_random_bytes([n; 16]),
        ca: w.ca_fp.clone(),
        valid_before: vb,
    };
    let prepared = ManagedPrepared {
        instance: CredentialInstanceId::from_random_bytes([3; 16]),
        key: KeyRegistration {
            public_key: "ssh-ed25519 AAAA".into(),
            fingerprint: "SHA256:x".into(),
            slot: "00".into(),
        },
        certificates: vec![cert(h1(), deadline, 1), cert(h2(), short, 2)],
        materialized: None,
    };
    let ctx = ReportContext {
        platform: current_platform(),
        lock_behavior: LockBehavior::Continue,
        policy: ConnectionPolicy::default(),
        issuer_ready: true,
        reissue_pending: false,
        now,
        selection: SelectionClass::Undetermined,
    };
    let r = report::compute(&grant, &prepared, &[], &ctx, &[]);
    assert_eq!((r.usable_until, r.offline_until), (short, short));
    assert_eq!(r.availability, CredentialAvailability::RefreshDependent);
    // An offline minimum beyond the shortest certificate: capability_unavailable.
    let pp = prepare_pairs(&[h1(), h2()]);
    let required = RequiredCapabilities {
        offline_until: Some(shift(short, 1)),
        ..RequiredCapabilities::default()
    };
    let req = PrepareRequest {
        grant: &grant,
        scope: &grant.scope,
        required: &required,
        interactive: false,
        effect_token: "tok",
        now,
        pairs: &pp,
    };
    let refusal = prepare::check_minimums(
        &req,
        &r,
        &GrantTerms::default(),
        &heimdall_adapters::managed::managed_capabilities(),
    )
    .unwrap_err();
    assert_eq!(refusal.reason, prepare::OFFLINE_UNTIL_BEYOND_BOUND);
    assert_eq!(
        refusal.into_adapter_error(),
        AdapterError::CapabilityUnavailable
    );
    // check_prepared: valid now passes; expired, not yet valid, unknown refuse.
    let pairs = [h1(), h2()];
    let started = |_: &PreparedCertificate| Some(shift(now, -60));
    prepare::check_prepared(&prepared, &pairs, deadline, now, &started).unwrap();
    assert_eq!(
        prepare::check_prepared(&prepared, &pairs, deadline, short, &started).unwrap_err(),
        AdapterError::Protocol(prepare::PREPARED_CERTIFICATE_EXPIRED.into())
    );
    assert_eq!(
        prepare::check_prepared(&prepared, &pairs, deadline, now, &|_| Some(shift(now, 1)))
            .unwrap_err(),
        AdapterError::Protocol(prepare::PREPARED_CERTIFICATE_NOT_YET_VALID.into())
    );
    assert_eq!(
        prepare::check_prepared(&prepared, &pairs, deadline, now, &|_| None).unwrap_err(),
        AdapterError::Protocol(prepare::PREPARED_CERTIFICATE_NOT_YET_VALID.into())
    );
}

/// §17.20 item 10 (W3-R08; the review's counterexample): the aggregate clock is the
/// pair with the largest completion allowance at the report's observation time; an
/// unknown measurement or an overflow is the weakest.
#[test]
fn aggregate_clock_is_the_weakest_now() {
    let now: Timestamp = "2026-11-10T12:00:00Z".parse().unwrap();
    let a = ClockMeasurement {
        behind_upper_ms: 1362,
        rtt_ms: 38,
        measured_at: now,
    };
    // 1000 ms measured 10 000 s ago: + 1000 ms of drift = 2000 ms now.
    let b = ClockMeasurement {
        behind_upper_ms: 962,
        rtt_ms: 38,
        measured_at: shift(now, -10_000),
    };
    assert_eq!(report::completion_allowance_ms(&a, now), Some(1400));
    assert_eq!(report::completion_allowance_ms(&b, now), Some(2000));
    for clocks in [[Some(a), Some(b)], [Some(b), Some(a)]] {
        assert_eq!(
            report::weakest_clock(&clocks, now),
            DestinationClock::Measured(b)
        );
    }
    // At B's measurement time, A (measured "later") adds no drift and B none: A wins.
    assert_eq!(
        report::weakest_clock(&[Some(a), Some(b)], shift(now, -10_000)),
        DestinationClock::Measured(a)
    );
    let overflow = ClockMeasurement {
        behind_upper_ms: u64::MAX,
        rtt_ms: 1,
        measured_at: now,
    };
    assert_eq!(report::completion_allowance_ms(&overflow, now), None);
    assert_eq!(
        report::weakest_clock(&[Some(b), Some(overflow)], now),
        DestinationClock::Measured(overflow)
    );
    assert_eq!(
        report::weakest_clock(&[Some(b), None], now),
        DestinationClock::Unmeasured
    );
}

/// §17.20 item 14 (U6-Q5 amended): a `revoke_on_lock` grant whose terms are absent
/// never reports `verified`, even with a matching lock-continuity claim: the report is
/// not computed (`grant_terms_unavailable`).
#[tokio::test]
async fn revoke_on_lock_grant_without_terms_never_reports_verified() {
    let w = World::new().await;
    let data = w.ensure("noterms", &[h1()]).await;
    let gid = data.grant_id.clone();
    w.drive(&data, "tok", Stage::Materialize).await;
    *w.sources.claims.lock().unwrap() = fixture_claims(current_platform());
    let g = w.grant(&gid);
    let unattended = RequiredCapabilities {
        unattended: true,
        ..RequiredCapabilities::default()
    };
    // The terms (revoke_on_lock) were never recorded.
    w.sources.terms.lock().unwrap().remove(&gid);
    for required in [RequiredCapabilities::default(), unattended.clone()] {
        assert_eq!(
            w.prepare_from(&g, &[h1()], &required).await.unwrap_err(),
            AdapterError::Unavailable(prepare::GRANT_TERMS_UNAVAILABLE.into())
        );
    }
    // Recorded as revoke_on_lock: refused for the unattended minimum (lock revokes).
    w.sources.terms.lock().unwrap().insert(
        gid.clone(),
        GrantTerms {
            lock_behavior: LockBehavior::RevokeOnLock,
            policy: ConnectionPolicy::default(),
        },
    );
    assert_eq!(
        w.prepare_from(&g, &[h1()], &unattended).await.unwrap_err(),
        AdapterError::CapabilityUnavailable
    );
    // The control: recorded as `continue`, the claim makes the unattended minimum pass.
    w.sources
        .terms
        .lock()
        .unwrap()
        .insert(gid.clone(), GrantTerms::default());
    w.prepare_from(&g, &[h1()], &unattended).await.unwrap();
    w.finish(&[gid]).await;
}

// =================================================================================
// Wave 4 round 3 (R3-A): ADR-0008 §17.22 item 7, evidence invalidated at the comparison
// =================================================================================

/// The minimum that needs the destination scope.
fn scope_minimum() -> RequiredCapabilities {
    RequiredCapabilities {
        destination_scope_at_least: Some(DestinationScopeEnforcement::VerifiedServerPrincipals),
        ..RequiredCapabilities::default()
    }
}

/// ADR-0008 §17.22 item 7 (W4-R04, R2A-Q1; D5 §6.5): the evidence is invalid **at the
/// comparison** the managed preparation's `read_sources` runs: when the evaluated host
/// key, the route or the client differs from what the evidence was taken against (or
/// is not known), the report's `destination_scope` is `unknown` and a minimum that
/// needs it fails, before any re-verification pass, while the record is still
/// `verified` with its evidence (nothing written); restoring the evaluation restores
/// the claim (the record never changed).
#[tokio::test]
async fn evidence_invalidated_at_the_comparison_before_any_pass() {
    let w = World::new().await;
    let data = w.ensure("cmp", &[h1()]).await;
    w.drive(&data, "tok-cmp", Stage::Materialize).await;
    let g = w.grant(&data.grant_id);
    let min = scope_minimum();
    let scope_of = |o: &PrepareOutcome| o.enforcement.report.destination_scope;
    let stored = || {
        w.store
            .transaction(|tx| tx.enrollments_for_pair(&h1()))
            .unwrap()
    };
    let before = stored();
    // Control: the approved target and the verifying client.
    let ok = w.prepare_from(&g, &[h1()], &min).await.unwrap();
    assert_eq!(
        scope_of(&ok),
        DestinationScopeEnforcement::VerifiedServerPrincipals
    );
    let alias = h1().destination.as_str().to_owned();
    let approved = approved_eval(&h1());
    let mut other_key = approved.clone();
    other_key.host_keys[0].key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIotherhost".into();
    let mut moved = approved.clone();
    moved.port = 2222;
    let mut undetermined = approved.clone();
    undetermined.determinism = Determinism::Undetermined {
        reason: "match exec".into(),
    };
    type Change = Box<dyn Fn(&StoreSources)>;
    let set_eval = |e: TargetEvaluation| -> Change {
        let alias = alias.clone();
        Box::new(move |s: &StoreSources| {
            s.targets.lock().unwrap().insert(alias.clone(), e.clone());
        })
    };
    let set_client = |c: Option<&'static str>| -> Change {
        Box::new(move |s: &StoreSources| {
            *s.client.lock().unwrap() = c.map(str::to_owned);
        })
    };
    let cases: Vec<(&str, Change)> = vec![
        ("host key changed", set_eval(other_key)),
        ("route changed", set_eval(moved)),
        ("route undetermined", set_eval(undetermined)),
        ("no evaluation", {
            let alias = alias.clone();
            Box::new(move |s: &StoreSources| {
                s.targets.lock().unwrap().remove(&alias);
            })
        }),
        (
            "client changed",
            set_client(Some("OpenSSH_10.6p1, LibreSSL 3.3.6")),
        ),
        ("client unknown", set_client(None)),
    ];
    for (what, change) in &cases {
        change(&w.sources);
        let e = w.prepare_from(&g, &[h1()], &min).await.unwrap_err();
        assert_eq!(e, AdapterError::CapabilityUnavailable, "{what}");
        let plain = w
            .prepare_from(&g, &[h1()], &RequiredCapabilities::default())
            .await
            .unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(
            scope_of(&plain),
            DestinationScopeEnforcement::Unknown,
            "{what}"
        );
        assert!(
            plain.enforcement.report.destination_scope
                != DestinationScopeEnforcement::VerifiedServerPrincipals
        );
        assert_eq!(
            stored(),
            before,
            "{what}: nothing written, the record still verified"
        );
        // Restore: the claim comes back (the record never changed).
        set_eval(approved.clone())(&w.sources);
        set_client(Some("OpenSSH_10.5p1, LibreSSL 3.3.6"))(&w.sources);
        let again = w.prepare_from(&g, &[h1()], &min).await.unwrap();
        assert_eq!(
            scope_of(&again),
            DestinationScopeEnforcement::VerifiedServerPrincipals,
            "{what}"
        );
    }
    assert_eq!(before[0].state, EnrollmentState::Verified);
}

/// ADR-0008 §17.22 item 7: `pair_evidence` selects the evidence for the CA of the
/// certificate being prepared. After a rotation whose new CA's enrollment is
/// `verified` without evidence of its own, the certificate is issued under the new
/// CA, and the old CA's fresh evidence never makes its scope
/// `verified_server_principals`: a minimum that needs it fails.
#[tokio::test]
async fn pair_evidence_is_for_the_prepared_certificates_ca() {
    let w = World::new().await;
    let k = Arc::new(SecretCaKey::generate().unwrap());
    let ca2 = k.fingerprint().unwrap();
    let public = k.public_openssh().unwrap();
    w.store
        .transaction(|tx| {
            tx.insert_issuer(&issuer_record(&ca2, &public, shift(t0(), 60)))?;
            let mut e = enrollment(0x51, &ca2, &h1(), Some(measured()));
            e.evidence = None;
            tx.seed_enrollment(&e)
        })
        .unwrap();
    w.extra_cas.lock().unwrap().push((ca2.clone(), k));
    let data = w.ensure("ca2", &[h1()]).await;
    let driven = w.drive(&data, "tok-ca2", Stage::Materialize).await;
    assert_eq!(
        w.ca_of(&data.grant_id, &h1()),
        ca2,
        "issued under the new CA"
    );
    let g = w.grant(&data.grant_id);
    let e = w
        .prepare_from(&g, &[h1()], &scope_minimum())
        .await
        .unwrap_err();
    assert_eq!(e, AdapterError::CapabilityUnavailable);
    let plain = w
        .prepare_from(&g, &[h1()], &RequiredCapabilities::default())
        .await
        .unwrap();
    assert_eq!(
        plain.enforcement.report.destination_scope,
        DestinationScopeEnforcement::Unknown
    );
    // `pair_evidence` itself: the old CA's evidence is not this certificate's.
    let snap = w.adapter.read_sources(&prepare_pairs(&[h1()]));
    let managed = snap.managed.as_ref().unwrap();
    let prepared = driven.prepared.unwrap();
    let pairs = [h1()];
    assert!(prepare::pair_evidence(managed, &pairs, &prepared).is_empty());
    let mut under_old = prepared.clone();
    under_old.certificates[0].ca = w.ca_fp.clone();
    assert_eq!(prepare::pair_evidence(managed, &pairs, &under_old).len(), 1);
}
