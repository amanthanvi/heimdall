//! ⟨M03⟩ wave 4 (U10-C): the managed effect driver, the credential instances, the
//! install view, the re-issue pass and the revoke result, end to end through the real
//! `heimdall_app::Operations` and the real state store (m03-plan U10 "Tests", U0b rows
//! 8, 9, 21 and 27; ADR-0008 D2 items 3a/6, D6 items 0–4, D7 item 2).
//!
//! **Harness.** A scratch state database (owner-only directories, created explicitly),
//! a `VirtualClock` and a `ScriptedTimeSync`. The managed ports are **port-level
//! fixtures**, labelled so in every result: [`FixtureEffects`] (`ManagedEffects`: an
//! in-memory key per grant, fingerprints unique per key), [`FixtureIssuer`]
//! (`IssuerPort`: a fixed certificate line per entry; no CA key, no child) and
//! [`FixtureManaged`] (a `CredentialAdapter` whose mechanism is `managed_certificate`
//! and whose `prepare_from` computes only from the driver's results, as the real
//! adapter does). The real adapter, signer table and store sources are exercised by the
//! runtime's `managed_store` unit tests (this host crate has no `adapters`/`credential`
//! edge). Store transactions are observed through the store's `FaultHook` (begin and
//! commit) on one [`Timeline`] with every effect and the bounded call, so the order is
//! asserted, never inferred. No listener, no process, no owner material.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    missing_docs
)]

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait_shim::*;
use heimdall_app::ensure::NoStageHook;
use heimdall_app::managed::{MANAGED_PREPARE_WITHOUT_DRIVER, ManagedWiring};
use heimdall_app::operations::{Limits, MANAGED_CERTIFICATE};
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot,
    InteractionRequirement, IssuanceRef, IssuerError, IssuerPort, IssuerStatusSnapshot,
    KeyRegistration, LockContinuity, ManagedEffects, ManagedSources, MaterializeSource,
    MaterializeSpec, MaterializedFiles, PrepareOutcome, PreparePair, PrepareRequest,
    ReconcileOutcome, RevokeOutcome,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, DestinationId, DeviceId, EnrollmentId, EnvironmentId,
    GrantId, IdentityId, OperationId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
use heimdall_contract::managed::{
    ClockMeasurement, ConnectionPolicy, DestinationClock, IssuerIsolation, LockBehavior,
    PreferredMechanism, RemoteEffectReport, ResidualStatus, RevokeNote,
};
use heimdall_contract::provider::CredentialAvailability;
use heimdall_contract::request::{
    ConfirmTimeRequest, EnsureData, EnsureRequest, InteractionMode, RefreshDependency,
    RequiredCapabilities, RevokeData, RevokeRequest, WaitMode,
};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus,
    RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::DegradedReason;
use heimdall_domain::issuance::{CredentialState, IssuanceEntry, IssuanceState};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, IssuerRecord, Store};
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

/// `async_trait` is not a dependency of this host crate: the port traits are
/// implemented with the expansion the macro produces (boxed `Send` futures).
mod async_trait_shim {
    pub use std::future::Future;
    pub use std::pin::Pin;
    pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
}

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

/// A syntactically valid CA fingerprint (no key behind it: the fixture issuer signs
/// nothing real, and the fixture effects install what they are given).
fn ca_fp() -> CaFingerprint {
    CaFingerprint::parse(&format!("SHA256:{}A", "c".repeat(42))).unwrap()
}

// =================================================================================
// The timeline: store transactions (through the store's fault hook) and effects
// =================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Begin,
    Commit,
    Effect(&'static str),
    BoundStart,
    BoundEnd,
}

#[derive(Default)]
struct Timeline(Mutex<Vec<Ev>>);

impl Timeline {
    fn push(&self, e: Ev) {
        self.0.lock().unwrap().push(e);
    }
    fn take(&self) -> Vec<Ev> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

struct TimelineFaults(Arc<Timeline>);

impl FaultHook for TimelineFaults {
    fn at(&self, point: FaultPoint) -> FaultAction {
        match point {
            FaultPoint::BeforeTransaction => self.0.push(Ev::Begin),
            FaultPoint::AfterCommit => self.0.push(Ev::Commit),
            _ => {}
        }
        FaultAction::Continue
    }
}

/// The open store transactions just before each event of `t`.
fn depth_before(t: &[Ev]) -> Vec<(Ev, i64)> {
    let mut depth = 0i64;
    let mut out = Vec::new();
    for e in t {
        out.push((e.clone(), depth));
        match e {
            Ev::Begin => depth += 1,
            Ev::Commit => depth -= 1,
            _ => {}
        }
    }
    out
}

// =================================================================================
// Port-level fixtures (labelled "fixture" in the report)
// =================================================================================

static KEY_SEQ: AtomicU64 = AtomicU64::new(1);

/// `ManagedEffects` fixture: one in-memory key per grant, idempotent per token.
struct FixtureEffects {
    timeline: Arc<Timeline>,
    keys: Mutex<HashMap<GrantId, (String, KeyRegistration)>>,
    installed: Mutex<Vec<(GrantId, IssuanceEntry)>>,
    destroyed: Mutex<Vec<GrantId>>,
    /// ⟨§17.21 item 1⟩ Every `materialize` call (binding, spec), in order.
    materialized: Mutex<Vec<(BindingId, MaterializeSpec)>>,
    /// Every `clear` call (binding, generation), in order.
    cleared: Mutex<Vec<(BindingId, u64)>>,
}

impl FixtureEffects {
    fn new(timeline: Arc<Timeline>) -> Arc<Self> {
        Arc::new(Self {
            timeline,
            keys: Mutex::new(HashMap::new()),
            installed: Mutex::new(Vec::new()),
            destroyed: Mutex::new(Vec::new()),
            materialized: Mutex::new(Vec::new()),
            cleared: Mutex::new(Vec::new()),
        })
    }
    fn live(&self, g: &GrantId) -> bool {
        self.keys.lock().unwrap().contains_key(g)
    }
}

impl ManagedEffects for FixtureEffects {
    fn generate_key<'a, 'b, 'c, 'd>(
        &'a self,
        grant: &'b GrantId,
        token: &'c str,
    ) -> BoxFut<'d, Result<KeyRegistration, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move {
            self.timeline.push(Ev::Effect("generate_key"));
            let mut keys = self.keys.lock().unwrap();
            if let Some((t, k)) = keys.get(grant) {
                return if t == token {
                    Ok(k.clone())
                } else {
                    Err(AdapterError::Protocol("already_registered".into()))
                };
            }
            let n = KEY_SEQ.fetch_add(1, Ordering::SeqCst);
            let k = KeyRegistration {
                public_key: format!("ssh-ed25519 AAAAfixture{n}"),
                // 42 base64 digits (the counter, least significant digit first, so
                // the digest's leading bytes differ per key) then `A` (zero low
                // bits): a canonical 32-byte digest.
                fingerprint: format!(
                    "SHA256:{}A",
                    format!("{n:042}").chars().rev().collect::<String>()
                ),
                slot: format!("fixture-slot-{n}"),
            };
            keys.insert(grant.clone(), (token.to_owned(), k.clone()));
            Ok(k)
        })
    }

    fn install<'a, 'b, 'c, 'd, 'e>(
        &'a self,
        grant: &'b GrantId,
        entry: &'c IssuanceEntry,
        _cert: &'d str,
    ) -> BoxFut<'e, Result<(), AdapterError>>
    where
        'a: 'e,
        'b: 'e,
        'c: 'e,
        'd: 'e,
        Self: 'e,
    {
        Box::pin(async move {
            self.timeline.push(Ev::Effect("install"));
            if !self.live(grant) {
                return Err(AdapterError::Protocol("no_key".into()));
            }
            self.installed
                .lock()
                .unwrap()
                .push((grant.clone(), entry.clone()));
            Ok(())
        })
    }

    fn destroy<'a, 'b, 'c>(&'a self, grants: &'b [GrantId]) -> BoxFut<'c, Result<(), AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            self.timeline.push(Ev::Effect("destroy"));
            let mut keys = self.keys.lock().unwrap();
            for g in grants {
                if keys.remove(g).is_some() {
                    self.destroyed.lock().unwrap().push(g.clone());
                }
            }
            Ok(())
        })
    }

    fn materialize(
        &self,
        binding: &BindingId,
        files: &MaterializeSpec,
    ) -> Result<MaterializedFiles, AdapterError> {
        self.timeline.push(Ev::Effect("materialize"));
        self.materialized
            .lock()
            .unwrap()
            .push((binding.clone(), files.clone()));
        // Named, never written (the real files are the managed adapter suite's).
        let directory = std::path::PathBuf::from(format!("fixture-run/b/{binding}"));
        Ok(MaterializedFiles {
            files: vec![directory.join("key.pub")],
            directory,
            generation: files.generation,
            endpoint: None,
        })
    }

    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError> {
        self.cleared
            .lock()
            .unwrap()
            .push((binding.clone(), generation));
        Ok(())
    }
}

/// `IssuerPort` fixture: `ready`; signs every entry with a fixed certificate line.
struct FixtureIssuer {
    timeline: Arc<Timeline>,
    signed: Mutex<Vec<IssuanceRef>>,
}

impl FixtureIssuer {
    fn new(timeline: Arc<Timeline>) -> Arc<Self> {
        Arc::new(Self {
            timeline,
            signed: Mutex::new(Vec::new()),
        })
    }
}

fn ready_status() -> IssuerStatusSnapshot {
    IssuerStatusSnapshot {
        status: IssuerStatus {
            state: IssuerState::Ready,
            reason: None,
            cas: Vec::new(),
            orphan_store_items: Vec::new(),
            issuer_isolation: IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        },
    }
}

impl IssuerPort for FixtureIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        ready_status()
    }

    fn sign<'a, 'b, 'c>(
        &'a self,
        entry: IssuanceRef,
        _subject: &'b str,
    ) -> BoxFut<'c, Result<String, IssuerError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            self.timeline.push(Ev::Effect("sign"));
            let line = format!("ssh-ed25519-cert-v01@openssh.com AAAAfixture-{}", entry.id);
            self.signed.lock().unwrap().push(entry);
            Ok(line)
        })
    }

    fn unload<'a, 'b, 'c>(&'a self, _ca: &'b CaFingerprint) -> BoxFut<'c, Result<(), IssuerError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { Ok(()) })
    }
}

/// The adapter fixture: mechanism `managed_certificate` (or another, for the
/// existing-access contract); `prepare_from` computes only from the driver's
/// results, inside the bound (timeline `BoundStart`/`BoundEnd`).
struct FixtureManaged {
    descriptor: AdapterDescriptor,
    timeline: Arc<Timeline>,
    seen_managed: Mutex<Vec<bool>>,
    revoke_rows: Mutex<Vec<RemoteEffectReport>>,
    /// ⟨§17.21 item 1⟩ `prepare_from` refuses (after the driver ran) while set.
    fail_prepare: std::sync::atomic::AtomicBool,
}

impl FixtureManaged {
    fn new(mechanism: &str, timeline: Arc<Timeline>) -> Arc<Self> {
        Arc::new(Self {
            descriptor: AdapterDescriptor {
                identity: heimdall_domain::operation::AdapterIdentity {
                    mechanism: mechanism.to_owned(),
                    instance: "fixture-1".to_owned(),
                },
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
                external_side_effects: true,
                interaction: InteractionRequirement::None,
                enforcement: evidence(),
                lock_continuity: LockContinuity::Unknown,
                remote_credential_effect: mechanism == MANAGED_CERTIFICATE,
            },
            timeline,
            seen_managed: Mutex::new(Vec::new()),
            revoke_rows: Mutex::new(Vec::new()),
            fail_prepare: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

fn evidence() -> EnforcementEvidence {
    use heimdall_contract::request::{
        DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
        NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
    };
    EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::Unknown,
            new_authentication_expiry: NewAuthenticationExpiry::Unknown,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::Unknown,
            revocation: RevocationStatus::Unknown,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
        },
        evidence: Vec::new(),
    }
}

fn outcome_for(req: &PrepareRequest<'_>) -> PrepareOutcome {
    PrepareOutcome {
        usable_until: req.grant.deadline.effective,
        offline_until: req.grant.deadline.effective,
        refresh_dependency: RefreshDependency::LocalIssuer,
        enforcement: evidence(),
        credential_ref: "fixture".into(),
        availability: CredentialAvailability::ThroughDeadline,
        provider: None,
        integration: Default::default(),
    }
}

impl CredentialAdapter for FixtureManaged {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn prepare<'a, 'b, 'c>(
        &'a self,
        _req: PrepareRequest<'b>,
    ) -> BoxFut<'c, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            Err(AdapterError::Protocol(
                MANAGED_PREPARE_WITHOUT_DRIVER.into(),
            ))
        })
    }

    fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
        IntegrationSnapshot {
            managed: (self.descriptor.identity.mechanism == MANAGED_CERTIFICATE)
                .then(ManagedSources::default),
            ..IntegrationSnapshot::default()
        }
    }

    fn prepare_from<'a, 'b, 'c, 'd>(
        &'a self,
        req: PrepareRequest<'b>,
        sources: &'c IntegrationSnapshot,
    ) -> BoxFut<'d, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move {
            self.timeline.push(Ev::BoundStart);
            let prepared = sources.managed.as_ref().and_then(|m| m.prepared.as_ref());
            self.seen_managed
                .lock()
                .unwrap()
                .push(sources.managed.is_some());
            let r = if self.descriptor.identity.mechanism != MANAGED_CERTIFICATE {
                Ok(outcome_for(&req))
            } else if self.fail_prepare.load(Ordering::SeqCst) {
                Err(AdapterError::CapabilityUnavailable)
            } else {
                match prepared {
                    Some(p) if p.certificates.len() == req.scope.pairs.len() => {
                        Ok(PrepareOutcome {
                            credential_ref: p.instance.to_string(),
                            ..outcome_for(&req)
                        })
                    }
                    _ => Err(AdapterError::Protocol(
                        MANAGED_PREPARE_WITHOUT_DRIVER.into(),
                    )),
                }
            };
            self.timeline.push(Ev::BoundEnd);
            r
        })
    }

    fn renew<'a, 'b, 'c>(
        &'a self,
        _req: PrepareRequest<'b>,
    ) -> BoxFut<'c, Result<PrepareOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move { Err(AdapterError::CapabilityUnavailable) })
    }

    fn reconcile<'a, 'b, 'c, 'd>(
        &'a self,
        _grant: &'b GrantId,
        _effect_token: &'c str,
    ) -> BoxFut<'d, Result<ReconcileOutcome, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        Box::pin(async move { Ok(ReconcileOutcome::Unknown) })
    }

    fn revoke<'a, 'b, 'c>(
        &'a self,
        _grant: &'b GrantId,
        _now: Timestamp,
    ) -> BoxFut<'c, Result<RevokeOutcome, AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        Box::pin(async move {
            Ok(RevokeOutcome {
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
                remote_effects: self.revoke_rows.lock().unwrap().clone(),
            })
        })
    }
}

// =================================================================================
// The world
// =================================================================================

fn owner_only_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn enrollment(seed: u8, p: &AccessPair) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([seed; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: ca_fp(),
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
            server: "OpenSSH_10.0p2".into(),
            operation: OperationId::from_random_bytes([seed; 16]),
            verified_at: t0(),
            fresh_until: shift(t0(), 90 * 86_400),
            clock: Some(ClockMeasurement {
                behind_upper_ms: 1400,
                rtt_ms: 38,
                measured_at: t0(),
            }),
        }),
        created_at: t0(),
        updated_at: t0(),
    }
}

fn seed(store: &Store) {
    let pairs = [h1(), h2()];
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            let scope = Scope {
                pairs: pairs.iter().cloned().collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope,
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                },
                false,
            )?;
            for p in &pairs {
                tx.upsert_destination(&DestinationRecord {
                    id: p.destination.clone(),
                    alias: p.destination.as_str().into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: t0(),
                })?;
            }
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: ca_fp(),
                public_key: "ssh-ed25519 AAAAfixtureca".into(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: t0(),
                restored_without_log: false,
                created_at: t0(),
                retired_at: None,
            })?;
            for (i, p) in pairs.iter().enumerate() {
                tx.seed_enrollment(&enrollment(u8::try_from(i + 1).unwrap(), p))?;
            }
            Ok(())
        })
        .unwrap();
}

struct World {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    timeline: Arc<Timeline>,
    adapter: Arc<FixtureManaged>,
    effects: Arc<FixtureEffects>,
    issuer: Arc<FixtureIssuer>,
    ops: Operations,
}

impl World {
    async fn new() -> Self {
        Self::with(MANAGED_CERTIFICATE, true).await
    }

    async fn with(mechanism: &str, wired: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        owner_only_dir(&dir.path().join("state"));
        let timeline = Arc::new(Timeline::default());
        let store = Arc::new(
            Store::open(
                &dir.path().join("state").join("state.db"),
                Arc::new(TimelineFaults(timeline.clone())),
            )
            .unwrap(),
        );
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let adapter = FixtureManaged::new(mechanism, timeline.clone());
        let ops = start(&store, &clock, &sync, &adapter).await;
        let effects = FixtureEffects::new(timeline.clone());
        let issuer = FixtureIssuer::new(timeline.clone());
        if wired {
            wire(&ops, &effects, &issuer);
        }
        Self {
            _dir: dir,
            store,
            clock,
            sync,
            timeline,
            adapter,
            effects,
            issuer,
            ops,
        }
    }

    fn wall(&self) -> Timestamp {
        Clock::wall(self.clock.as_ref())
    }

    async fn try_ensure(
        &self,
        tag: &str,
        pairs: &[AccessPair],
    ) -> Result<EnsureData, heimdall_app::OpError> {
        ensure_on(&self.ops, tag, pairs).await.map(|c| c.data)
    }

    async fn ensure(&self, tag: &str, pairs: &[AccessPair]) -> (EnsureData, OperationId) {
        let c = ensure_on(&self.ops, tag, pairs)
            .await
            .unwrap_or_else(|e| panic!("ensure {tag}: {} {}", e.code, e.message));
        (c.data, c.operation_id.expect("an operation"))
    }

    async fn revoke(&self, grant: &GrantId, rid: &str) -> RevokeData {
        self.ops
            .revoke(
                &owner(),
                RevokeRequest {
                    grant_id: grant.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("revoke {rid}: {} {}", e.code, e.message))
            .data
    }

    fn grant_state(&self, g: &GrantId) -> GrantState {
        self.store
            .transaction(|tx| tx.grant(g))
            .unwrap()
            .unwrap()
            .state
    }

    fn entries(&self, g: &GrantId) -> Vec<IssuanceEntry> {
        self.store.transaction(|tx| tx.issuance_entries(g)).unwrap()
    }

    fn instance_state(&self, fingerprint: &str) -> Option<CredentialState> {
        let id = heimdall_app::managed::driver::instance_id_for(fingerprint).unwrap();
        self.store
            .transaction(|tx| tx.credential_instance(&id))
            .unwrap()
            .map(|i| i.state)
    }
}

async fn start(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    adapter: &Arc<FixtureManaged>,
) -> Operations {
    Operations::start(OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![adapter.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap()
}

fn wire(ops: &Operations, effects: &Arc<FixtureEffects>, issuer: &Arc<FixtureIssuer>) {
    ops.set_managed_wiring(ManagedWiring {
        effects: Some(effects.clone() as Arc<dyn ManagedEffects>),
        issuer: Some(issuer.clone() as Arc<dyn IssuerPort>),
        ..ManagedWiring::default()
    });
}

async fn ensure_on(
    ops: &Operations,
    tag: &str,
    pairs: &[AccessPair],
) -> Result<heimdall_app::error::Completed<EnsureData>, heimdall_app::OpError> {
    ops.ensure(
        &owner(),
        EnsureRequest {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: None,
            scope: pairs.iter().cloned().collect(),
            environment: None,
            work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::Sync { timeout_ms: 30_000 },
            connection: None,
        },
    )
    .await
}

// =================================================================================
// Row 21: the stage sequence, outside every store transaction and the bound
// =================================================================================

/// U10 "Tests" (row 21): every effect of the stage sequence (key, sign per pair,
/// install per pair, ⟨§17.21 item 1⟩ materialize) runs with no store transaction open, each separated from the next
/// by at least one committed store transaction (a reservation, a publication, or a
/// stage receipt), and the operation carries the stage receipts in order.
#[tokio::test]
async fn managed_effect_steps_run_outside_store_transactions() {
    let w = World::new().await;
    w.timeline.clear();
    let (data, op) = w.ensure("steps", &[h1(), h2()]).await;
    let t = w.timeline.take();
    let effects: Vec<(Ev, i64)> = depth_before(&t)
        .into_iter()
        .filter(|(e, _)| matches!(e, Ev::Effect(_)))
        .collect();
    let names: Vec<&str> = effects
        .iter()
        .map(|(e, _)| match e {
            Ev::Effect(n) => *n,
            _ => "",
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "generate_key",
            "sign",
            "sign",
            "install",
            "install",
            "materialize"
        ],
        "the fixture driver's effects, in D6 item 1's order"
    );
    for (e, depth) in &effects {
        assert_eq!(*depth, 0, "{e:?} ran inside a store transaction");
    }
    // Between two consecutive effects at least one transaction committed.
    let idx: Vec<usize> = t
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Ev::Effect(_)))
        .map(|(i, _)| i)
        .collect();
    for w2 in idx.windows(2) {
        assert!(
            t[w2[0]..w2[1]].contains(&Ev::Commit),
            "no stage receipt between effects at {w2:?}"
        );
    }
    let stages: Vec<String> = w
        .store
        .transaction(|tx| tx.stage_receipts(&op))
        .unwrap()
        .into_iter()
        .map(|r| r.stage)
        .filter(|s| s.starts_with("managed."))
        .collect();
    assert_eq!(
        stages,
        vec![
            "managed.key",
            "managed.reserve",
            "managed.sign",
            "managed.publish",
            "managed.reserve",
            "managed.sign",
            "managed.publish",
            "managed.install",
            "managed.install",
            "managed.materialize",
            "managed.prepared",
        ]
    );
    assert_eq!(w.grant_state(&data.grant_id), GrantState::Active);
    let published = w
        .entries(&data.grant_id)
        .into_iter()
        .filter(|e| e.state == IssuanceState::Published)
        .count();
    assert_eq!(published, 2, "one published certificate per pair");
}

/// U0b row 21: the bounded `prepare_from` runs no store transaction, and computes from
/// the driver's results (which the driver produced before the bound).
#[tokio::test]
async fn driver_never_runs_store_work_inside_adapter_bound() {
    let w = World::new().await;
    w.timeline.clear();
    w.ensure("bound", &[h1()]).await;
    let t = w.timeline.take();
    let start = t
        .iter()
        .position(|e| *e == Ev::BoundStart)
        .expect("bound entered");
    let end = t
        .iter()
        .position(|e| *e == Ev::BoundEnd)
        .expect("bound left");
    assert!(
        !t[start..end].contains(&Ev::Begin),
        "a store transaction ran inside the bound: {:?}",
        &t[start..end]
    );
    assert!(
        !t[start..end].iter().any(|e| matches!(e, Ev::Effect(_))),
        "an effect ran inside the bound"
    );
    assert!(
        t[..start].contains(&Ev::Effect("install")),
        "the driver installed before the bound"
    );
}

/// U0b row 21: an existing-access adapter's preparation is M02's (no driver, no
/// `managed` sources), even with the managed wiring present.
#[tokio::test]
async fn existing_access_prepare_contract_unchanged() {
    let w = World::with("fake_agent", true).await;
    w.ensure("existing", &[h1()]).await;
    assert_eq!(*w.adapter.seen_managed.lock().unwrap(), vec![false]);
    assert!(
        w.effects.keys.lock().unwrap().is_empty(),
        "no key generated"
    );
    assert!(w.issuer.signed.lock().unwrap().is_empty(), "nothing signed");
}

/// Without the driver's results the managed `prepare_from` refuses (the fixture
/// computes as the real adapter does); unwired, `ensure` fails closed before any
/// effect: nothing generated, nothing reserved.
#[tokio::test]
async fn managed_prepare_unwired_fails_closed_before_any_effect() {
    let w = World::with(MANAGED_CERTIFICATE, false).await;
    let e = w.try_ensure("unwired", &[h1()]).await.unwrap_err();
    assert_ne!(e.code, Code::Ok);
    assert!(w.effects.keys.lock().unwrap().is_empty());
    let none = w
        .store
        .transaction(|tx| {
            let mut n = 0;
            for g in tx.grants_due(Timestamp::MAX)? {
                n += tx.issuance_entries(&g.id)?.len();
            }
            Ok(n)
        })
        .unwrap();
    assert_eq!(none, 0, "nothing reserved");
}

// =================================================================================
// U2-Q1: credential instances
// =================================================================================

/// U2-Q1: the instance is persisted `pending` then `installed` with its entries, its
/// creation retains the grant's gate; a revoke destroys it and releases the gate.
#[tokio::test]
async fn credential_instance_persisted_installed_then_destroyed_with_gate() {
    let w = World::new().await;
    let (data, _) = w.ensure("instance", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    let fp = w
        .effects
        .keys
        .lock()
        .unwrap()
        .get(&gid)
        .unwrap()
        .1
        .fingerprint
        .clone();
    assert_eq!(w.instance_state(&fp), Some(CredentialState::Installed));
    let id = heimdall_app::managed::driver::instance_id_for(&fp).unwrap();
    let i = w
        .store
        .transaction(|tx| tx.credential_instance(&id))
        .unwrap()
        .unwrap();
    let published: BTreeSet<_> = w
        .entries(&gid)
        .into_iter()
        .filter(|e| e.state == IssuanceState::Published)
        .map(|e| e.id)
        .collect();
    assert_eq!(
        i.certificates.iter().cloned().collect::<BTreeSet<_>>(),
        published
    );
    assert_eq!(
        i.key_handle_ref,
        w.effects.keys.lock().unwrap().get(&gid).unwrap().1.slot
    );
    assert_eq!(
        w.ops.signing_gates().instances(&gid),
        1,
        "the gate is retained"
    );
    w.revoke(&gid, "rv-instance").await;
    assert_eq!(w.instance_state(&fp), Some(CredentialState::Destroyed));
    assert!(
        !w.ops.signing_gates().contains(&gid),
        "the last instance's gate is gone"
    );
    assert!(!w.effects.live(&gid), "K_env destroyed");
}

// =================================================================================
// U2-Q2: the install view
// =================================================================================

/// D2 item 6: the install view admits the published entry of a usable grant, and
/// refuses a mismatched (stale) entry, an expired grant and a revoked one.
#[tokio::test]
async fn install_view_refuses_tombstoned_stale_or_expired_grant() {
    let w = World::new().await;
    let (data, _) = w.ensure("view", &[h1()]).await;
    let gid = data.grant_id.clone();
    let entry = w
        .entries(&gid)
        .into_iter()
        .find(|e| e.state == IssuanceState::Published)
        .unwrap();
    assert_eq!(w.ops.managed_install_check(&gid, &entry).await, Ok(()));
    let mut stale = entry.clone();
    stale.bounds.serial = stale.bounds.serial.wrapping_add(1);
    assert_eq!(
        w.ops.managed_install_check(&gid, &stale).await,
        Err("entry_mismatch")
    );
    let reserved_only = IssuanceEntry {
        state: IssuanceState::Reserved,
        ..entry.clone()
    };
    assert_eq!(
        w.ops.managed_install_check(&gid, &reserved_only).await,
        Ok(()),
        "the stored entry is what counts, never the caller's copy of its state"
    );
    let (other, _) = w.ensure("view-revoked", &[h2()]).await;
    let other_entry = w
        .entries(&other.grant_id)
        .into_iter()
        .find(|e| e.state == IssuanceState::Published)
        .unwrap();
    w.revoke(&other.grant_id, "rv-view").await;
    let r = w
        .ops
        .managed_install_check(&other.grant_id, &other_entry)
        .await;
    assert!(matches!(r, Err("grant_not_usable" | "tombstoned")), "{r:?}");
    w.clock.advance(3 * HOUR);
    let r = w.ops.managed_install_check(&gid, &entry).await;
    assert!(
        matches!(r, Err("deadline_passed" | "grant_not_usable")),
        "{r:?}"
    );
}

// =================================================================================
// U0b row 27 (e2e side): revoke timestamps and the managed result
// =================================================================================

/// §17.10 item 3: the revoke result carries `requested_at ≤ committed_at`, a replay of
/// the same request returns the stored originals, and a managed cascade's result
/// carries the adapter's per-pair rows and the fixed note (F15).
#[tokio::test]
async fn revoke_result_reports_requested_and_committed_at() {
    let w = World::new().await;
    let (data, _) = w.ensure("rv", &[h1()]).await;
    let gid = data.grant_id.clone();
    let row = RemoteEffectReport {
        destination: h1().destination,
        account: h1().account,
        latest_valid_before: shift(t0(), 7200),
        destination_clock: DestinationClock::Unmeasured,
        status: ResidualStatus::PendingUntil,
        until: None,
    };
    *w.adapter.revoke_rows.lock().unwrap() = vec![row.clone()];
    let first = w.revoke(&gid, "rv-ts").await;
    let (req, com) = (first.requested_at.unwrap(), first.committed_at.unwrap());
    assert!(req <= com, "{req} > {com}");
    assert_eq!(first.notes, vec![RevokeNote::OrdinaryConnectionsNotClosed]);
    assert_eq!(first.remote_effects, vec![row]);
    assert!(first.local_applied);
    w.clock.advance(Duration::from_secs(30));
    let replay = w.revoke(&gid, "rv-ts").await;
    assert_eq!(replay.requested_at, first.requested_at);
    assert_eq!(replay.committed_at, first.committed_at);
}

// =================================================================================
// Re-issue (U0b row 8; D6 item 4)
// =================================================================================

/// A runtime restart in the same boot: the installed instance is `lost`, its grant
/// degraded `credential_reissue_pending`; the new runtime's `managed_reissue_pass`
/// re-issues it as continuing work (same pairs, same D), restoring `active`.
#[tokio::test]
async fn reissue_after_runtime_process_restart_same_boot() {
    let w = World::new().await;
    let (data, _) = w.ensure("restart", &[h1(), h2()]).await;
    let gid = data.grant_id.clone();
    let d = w
        .store
        .transaction(|tx| tx.grant(&gid))
        .unwrap()
        .unwrap()
        .deadline
        .effective;
    let fp = w
        .effects
        .keys
        .lock()
        .unwrap()
        .get(&gid)
        .unwrap()
        .1
        .fingerprint
        .clone();
    // The old runtime stops serving (its `Operations` is idle from here on).
    // The new process: no vault slot; recovery marks the instance lost.
    let ops2 = start(&w.store, &w.clock, &w.sync, &w.adapter).await;
    assert_eq!(w.instance_state(&fp), Some(CredentialState::Lost));
    assert_eq!(w.grant_state(&gid), GrantState::Degraded);
    // Unwired, the pass is a no-op.
    assert_eq!(
        ops2.managed_reissue_pass().await.unwrap(),
        Vec::<GrantId>::new()
    );
    let effects2 = FixtureEffects::new(w.timeline.clone());
    wire(&ops2, &effects2, &w.issuer);
    assert_eq!(
        ops2.managed_reissue_pass().await.unwrap(),
        vec![gid.clone()]
    );
    assert_eq!(w.grant_state(&gid), GrantState::Active);
    assert_eq!(w.instance_state(&fp), Some(CredentialState::Destroyed));
    let fp2 = effects2
        .keys
        .lock()
        .unwrap()
        .get(&gid)
        .unwrap()
        .1
        .fingerprint
        .clone();
    assert_ne!(fp, fp2, "a new K_env");
    assert_eq!(w.instance_state(&fp2), Some(CredentialState::Installed));
    let continuing: Vec<IssuanceEntry> = w
        .entries(&gid)
        .into_iter()
        .filter(|e| e.continuing && e.state == IssuanceState::Published)
        .collect();
    assert_eq!(continuing.len(), 2, "one continuing certificate per pair");
    assert!(
        continuing.iter().all(|e| e.bounds.valid_before == d),
        "same D"
    );
    assert_eq!(
        ops2.managed_reissue_pass().await.unwrap(),
        Vec::<GrantId>::new(),
        "nothing left to re-issue"
    );
}

/// After a reboot time is not accepted: the pass re-issues nothing and the grant stays
/// `credential_reissue_pending`, until an attended `time confirm`.
#[tokio::test]
async fn reissue_after_reboot_waits_for_time_confirm() {
    let w = World::new().await;
    let (data, _) = w.ensure("reboot", &[h1()]).await;
    let gid = data.grant_id.clone();
    // The old runtime stops serving (its `Operations` is idle from here on).
    w.clock.reboot(shift(w.wall(), 120));
    w.sync.set(SyncStatus::Unknown);
    let ops2 = start(&w.store, &w.clock, &w.sync, &w.adapter).await;
    let effects2 = FixtureEffects::new(w.timeline.clone());
    wire(&ops2, &effects2, &w.issuer);
    w.timeline.clear();
    assert_eq!(
        ops2.managed_reissue_pass().await.unwrap(),
        Vec::<GrantId>::new()
    );
    assert_eq!(w.grant_state(&gid), GrantState::Degraded);
    let reason = w
        .store
        .transaction(|tx| tx.grant_degradation(&gid))
        .unwrap();
    assert_eq!(reason, Some(DegradedReason::CredentialReissuePending));
    assert!(
        !w.timeline.take().contains(&Ev::Effect("generate_key")),
        "no key generated before time is accepted"
    );
    assert!(effects2.keys.lock().unwrap().is_empty());
    ops2.confirm_time(
        &attended(),
        ConfirmTimeRequest {
            observed_wall: Clock::wall(w.clock.as_ref()),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("confirm: {} {}", e.code, e.message));
    assert_eq!(
        ops2.managed_reissue_pass().await.unwrap(),
        vec![gid.clone()]
    );
    assert_eq!(w.grant_state(&gid), GrantState::Active);
}

// =================================================================================
// U0b row 9: the managed refusal opens only with the wiring
// =================================================================================

/// A pair preferring managed certificates (verified, projection applied) is refused
/// `driver_unavailable` before any record while the driver is unwired, and activates
/// once the runtime wired the effects and the issuer.
#[tokio::test]
async fn managed_preference_refused_unwired_activates_when_wired() {
    let w = World::with(MANAGED_CERTIFICATE, false).await;
    w.store
        .transaction(|tx| {
            let cas = tx.verified_cas_for_pair(&h1())?;
            tx.set_pair_preference(
                &PairPreference {
                    destination: h1().destination,
                    account: h1().account,
                    mechanism: PreferredMechanism::ManagedCertificate,
                    projection: ProjectionStatus::Applied { generation: 1 },
                    issuing_cas: cas,
                },
                t0(),
            )
        })
        .unwrap();
    let e = w.try_ensure("pref-unwired", &[h1()]).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
    assert_eq!(e.reason.as_deref(), Some("driver_unavailable"));
    let ops_written = w.store.transaction(|tx| tx.open_operations()).unwrap();
    assert!(ops_written.is_empty(), "nothing written");
    wire(&w.ops, &w.effects, &w.issuer);
    let data = w.try_ensure("pref-wired", &[h1()]).await.unwrap();
    assert_eq!(w.grant_state(&data.grant_id), GrantState::Active);
}

// =================================================================================
// Integrator regression (U10C-Q3; ADR-0008 D7 item 2 step 2, U0b row 20 (10))
// =================================================================================

/// Records, at the narrowing's `UnderGates` point (the commit done, every gate still
/// held), whether each destroyed grant's K_env was already gone from the effects.
struct UnderGatesProbe {
    effects: Arc<FixtureEffects>,
    seen: Mutex<Vec<(GrantId, bool, usize)>>,
}

impl heimdall_app::operations::narrowing::NarrowingHook for UnderGatesProbe {
    fn at<'a>(
        &'a self,
        _kind: heimdall_app::operations::narrowing::NarrowingKind,
        point: heimdall_app::operations::narrowing::NarrowingPoint,
    ) -> heimdall_app::operations::narrowing::HookFuture<'a> {
        Box::pin(async move {
            if let heimdall_app::operations::narrowing::NarrowingPoint::UnderGates {
                destroy,
                held,
            } = point
            {
                for g in destroy {
                    let live = self.effects.live(&g);
                    self.seen.lock().unwrap().push((g, live, held.len()));
                }
            }
        })
    }
}

/// A managed grant's revocation zeroizes and unlists K_env **under** the signing
/// gates (the in-memory step of D7 item 2 step 2), not only after their release.
#[tokio::test]
async fn revoke_destroys_k_env_under_the_gates() {
    let w = World::new().await;
    let (data, _) = w.ensure("under-gates", &[h1()]).await;
    let gid = data.grant_id.clone();
    assert!(w.effects.live(&gid), "K_env generated by the driver");
    let probe = Arc::new(UnderGatesProbe {
        effects: Arc::clone(&w.effects),
        seen: Mutex::new(Vec::new()),
    });
    w.ops.set_narrowing_hook(probe.clone());
    let _ = w.revoke(&gid, "under-gates-rv").await;
    let seen = probe.seen.lock().unwrap().clone();
    let mine: Vec<_> = seen.iter().filter(|(g, _, _)| *g == gid).collect();
    assert!(
        !mine.is_empty(),
        "the narrowing reached UnderGates for the grant: {seen:?}"
    );
    for (_, live, held) in mine {
        assert!(*held >= 1, "the grant's gate is held at UnderGates");
        assert!(!live, "K_env destroyed before the gates are released");
    }
}

// =================================================================================
// ⟨M03 wave 4, round 2⟩ ADR-0008 §17.21 item 1: the binding minted at resolve
// =================================================================================

fn stored_intent(w: &World, op: &OperationId) -> heimdall_domain::operation::RecoveryIntent {
    w.store
        .transaction(|tx| tx.recovery_intent(op))
        .unwrap()
        .expect("a recovery intent")
}

/// §17.21 item 1: a managed `ensure` mints the binding ID at resolve (recorded in the
/// intent as `binding_id`), the driver materializes exactly that binding at step 6
/// (generation 1, K_env's public key, one certificate per pair, no slots), and the
/// commit creates the binding under the same ID.
#[tokio::test]
async fn managed_binding_minted_at_resolve_materialized_then_committed_under_it() {
    let w = World::new().await;
    let (data, op) = w.ensure("minted", &[h1(), h2()]).await;
    let resolved = stored_intent(&w, &op).resolved.expect("resolved");
    assert_eq!(resolved.binding_id.as_ref(), Some(&data.binding_id));
    assert_eq!(resolved.binding.as_ref(), Some(&data.binding_id));
    let calls = w.effects.materialized.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "one materialization");
    let (b, spec) = &calls[0];
    assert_eq!(b, &data.binding_id, "materialized under the minted ID");
    assert_eq!(spec.generation, 1);
    assert!(!spec.environment_slots, "no slot at preparation");
    let key = w
        .effects
        .keys
        .lock()
        .unwrap()
        .get(&data.grant_id)
        .unwrap()
        .1
        .public_key
        .clone();
    let MaterializeSource::Fresh {
        public_key,
        certificates,
    } = &spec.source
    else {
        panic!("a new activation materializes fresh key material: {spec:?}");
    };
    assert_eq!(public_key, &key);
    let pairs: BTreeSet<AccessPair> = certificates.iter().map(|c| c.pair.clone()).collect();
    assert_eq!(pairs, [h1(), h2()].into_iter().collect());
    let stored = w
        .store
        .transaction(|tx| tx.binding(&data.binding_id))
        .unwrap()
        .expect("the binding committed under the minted ID");
    assert_eq!(stored.grant, data.grant_id);
    assert!(
        w.effects.cleared.lock().unwrap().is_empty(),
        "nothing cleared"
    );
}

/// §17.21 item 1: a replay of the same `request_id` returns the same binding, and the
/// driver does not run again (one materialization).
#[tokio::test]
async fn managed_replay_of_request_returns_same_binding() {
    let w = World::new().await;
    let (first, op1) = w.ensure("replay", &[h1()]).await;
    let (again, op2) = w.ensure("replay", &[h1()]).await;
    assert_eq!(op1, op2, "the same operation");
    assert_eq!(again.binding_id, first.binding_id);
    assert_eq!(again.grant_id, first.grant_id);
    let calls = w.effects.materialized.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "the driver ran once");
    assert_eq!(
        calls[0].0, first.binding_id,
        "the replayed binding is the materialized one"
    );
}

/// §17.21 item 1: a failure after the driver materialized (here `prepare_from`
/// refuses) is cleaned up by the operation's cleanup intent before the call returns:
/// K_env destroyed, the instance `destroyed` with its gate released, the minted
/// binding cleared at generation 1, no binding committed, no intent left.
#[tokio::test]
async fn managed_failure_before_commit_cleans_binding_key_and_instance() {
    let w = World::new().await;
    w.adapter.fail_prepare.store(true, Ordering::SeqCst);
    let e = w.try_ensure("fails", &[h1()]).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    let calls = w.effects.materialized.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "the driver materialized");
    let binding = calls[0].0.clone();
    assert_eq!(
        *w.effects.cleared.lock().unwrap(),
        vec![(binding.clone(), 1)],
        "the minted binding's endpoint and files cleared"
    );
    let gid = w
        .effects
        .destroyed
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("K_env destroyed");
    assert!(!w.effects.live(&gid));
    let instances = w
        .store
        .transaction(|tx| tx.credential_instances_for_grant(&gid))
        .unwrap();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].state, CredentialState::Destroyed);
    assert!(!w.ops.signing_gates().contains(&gid), "the gate released");
    assert_eq!(w.grant_state(&gid), GrantState::Failed);
    let (committed, intents) = w
        .store
        .transaction(|tx| Ok((tx.binding(&binding)?, tx.cleanup_intents()?)))
        .unwrap();
    assert!(committed.is_none(), "no binding committed");
    assert!(intents.is_empty(), "the cleanup intent was processed");
}

/// The M02 shape of a resolved intent's JSON keys (ADR-0006; `approval`/`covered`
/// omitted when absent).
const M02_RESOLVED_KEYS: [&str; 9] = [
    "adapter",
    "binding",
    "deadline",
    "generation",
    "grant",
    "policy_revision",
    "profile",
    "profile_revision",
    "scope",
];

/// §17.21 item 1: an existing-access `ensure` is byte-identical to M02. Its stored
/// intent has exactly the M02 keys (no `binding_id`), and those bytes (the shape an
/// M02 build wrote) decode with no `binding_id` and re-encode byte-identically; the
/// driver never runs (no key, no materialization) and the result names no managed
/// endpoint.
#[tokio::test]
async fn existing_access_ensure_intent_and_result_byte_identical_to_m02() {
    let w = World::with("fake_agent", true).await;
    let (data, op) = w.ensure("m02-shape", &[h1()]).await;
    let intent = stored_intent(&w, &op);
    let resolved = intent.resolved.clone().unwrap();
    assert_eq!(resolved.binding_id, None);
    let value = serde_json::to_value(&resolved).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, M02_RESOLVED_KEYS, "the M02 key set");
    let bytes = serde_json::to_string(&intent).unwrap();
    assert!(!bytes.contains("binding_id"));
    let decoded: heimdall_domain::operation::RecoveryIntent = serde_json::from_str(&bytes).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), bytes);
    // The result names no managed endpoint, and the binding is the intent's.
    assert_eq!(data.consumer.signing_endpoint, None);
    assert_eq!(resolved.binding.as_ref(), Some(&data.binding_id));
    assert!(w.effects.keys.lock().unwrap().is_empty());
    assert!(w.effects.materialized.lock().unwrap().is_empty());
    // A managed intent carries the key; removing it gives the M02 bytes, which decode
    // to no `binding_id` and re-encode byte-identically.
    let mw = World::new().await;
    let (mdata, mop) = mw.ensure("m02-managed", &[h1()]).await;
    let managed = serde_json::to_string(&stored_intent(&mw, &mop)).unwrap();
    let field = format!(",\"binding_id\":\"{}\"", mdata.binding_id);
    assert!(
        managed.contains(&field),
        "the managed intent records the minted ID"
    );
    let m02_bytes = managed.replace(&field, "");
    let read: heimdall_domain::operation::RecoveryIntent =
        serde_json::from_str(&m02_bytes).unwrap();
    assert_eq!(read.resolved.as_ref().unwrap().binding_id, None);
    assert_eq!(serde_json::to_string(&read).unwrap(), m02_bytes);
}

// =================================================================================
// §17.21 item 7: the credential instances of a grant, by store query
// =================================================================================

/// §17.21 item 7: `Txn::credential_instances_for_grant` lists every instance of the
/// grant (any state, any ID scheme) and no other grant's; the revoke's cleanup finds an
/// instance whose ID is not derived from any key fingerprint through it, destroys it
/// and releases its gate.
#[tokio::test]
async fn credential_instances_found_by_grant_query_not_fingerprint() {
    use heimdall_domain::issuance::CredentialInstance;
    let w = World::new().await;
    let (a, _) = w.ensure("inst-a", &[h1()]).await;
    let (b, _) = w.ensure("inst-b", &[h2()]).await;
    let extra = CredentialInstance {
        id: heimdall_contract::ids::CredentialInstanceId::from_random_bytes([0xAB; 16]),
        grant: a.grant_id.clone(),
        key_handle_ref: "fixture-extra".into(),
        certificates: Vec::new(),
        state: CredentialState::Installed,
    };
    w.store
        .transaction(|tx| tx.insert_credential_instance(&extra))
        .unwrap();
    w.ops.signing_gates().retain(&a.grant_id, &[]);
    let of = |g: &GrantId| {
        w.store
            .transaction(|tx| tx.credential_instances_for_grant(g))
            .unwrap()
    };
    let listed = of(&a.grant_id);
    assert_eq!(listed.len(), 2, "the driver's instance and the extra one");
    assert!(listed.iter().all(|i| i.grant == a.grant_id));
    assert!(listed.iter().any(|i| i.id == extra.id));
    assert_eq!(
        of(&b.grant_id).len(),
        1,
        "the other grant's own instance only"
    );
    assert!(of(&GrantId::from_random_bytes([0xEE; 16])).is_empty());
    w.revoke(&a.grant_id, "rv-inst-a").await;
    assert!(
        of(&a.grant_id)
            .iter()
            .all(|i| i.state == CredentialState::Destroyed),
        "every instance of the grant destroyed, found by the query"
    );
    assert!(
        !w.ops.signing_gates().contains(&a.grant_id),
        "both gate holds released"
    );
    assert_eq!(of(&b.grant_id)[0].state, CredentialState::Installed);
}
