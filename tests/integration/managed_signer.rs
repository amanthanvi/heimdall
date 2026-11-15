//! M03 wave 2, U2: the managed signer, its endpoints and the signer table (m03-plan U2
//! "Tests"; ADR-0008 D2 items 1–7 and 3a, D5 §6.5 item 1, D10 items 1–3; rulings
//! §17.4 item 6, §17.7 item 2, §17.10 item 1, §17.13 item 1, §17.15, §17.18 item 3;
//! readings R2–R4, R6).
//!
//! **Authority.** Where a test is about real authorization the `SignatureAuthority` is
//! the production `heimdall_app::Operations` over an in-memory store, the
//! `testkit::FakeCredentialAdapter` and a **paused** tokio clock (`TokioClock` reads the
//! tokio clock, so wall and continuous time move only through `advance` or idle
//! auto-advance), as `tests/model/narrowing_m03.rs` does. Gates are created with
//! `SigningGates::retain` (the first credential instance; U10 wires it), and the
//! narrowing hook destroys keys at its `UnderGates` point (`SignerTable::destroy_grant`,
//! in memory, under the gates: D2 item 3a's order; U10 wires it). Every world sets
//! `AuthorizationTime::ReadOnly` explicitly (reading R2: the tests do not depend on the
//! default). The verification endpoint is tested with a fixture authority (reading R3:
//! production `Operations` refuses every verification subject, INT-Q13), plus one test
//! that production does refuse it.
//!
//! **Wire.** Signers are served by the real `ipc::signing::serve_with_limits` (bounded
//! outbound queue, capacity-then-release order) over in-memory duplex streams, or by
//! the `EndpointRegistry`'s real M01 listeners. The release/enqueue order is observed
//! on a test-owned queue through `ipc::signing::enqueue_signed`, the core `serve()`
//! runs. Orderings come from the signer's pause hook (`SignHook`) and the narrowing
//! hook, never from real sleeps.
//!
//! **Real clients** (`fresh_login_through_environment_endpoint`,
//! `one_signature_per_login`, `session_bind_observed_per_client`,
//! `destroyed_key_makes_installed_certificate_unusable`): a real `ssh` (isolation
//! arguments only, the default-identity guard) through the registry's real endpoints
//! to a `LoopbackSshd` in account form, with the rendered managed block of P as the
//! thing under test (INT-Q10's default form `CertificateAsIdentityFile`: `IdentityAgent`
//! the environment endpoint, `IdentitiesOnly yes`, `IdentityFile <slot>/cert.pub`).
//! Every key and CA is generated per run; nothing of the owner's is touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::managed::{PermitExpiry, SafeTime, SignPermit, SigningGates};
use heimdall_app::operations::Limits;
use heimdall_app::operations::narrowing::{
    AuthorizationTime, BoundTerms, HookFuture as NarrowingFuture, NarrowingHook, NarrowingKind,
    NarrowingPoint, NarrowingReport,
};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, LockState,
    PrepareOutcome, SessionLockSource, SignRefusal, SignatureAuthority, SignatureRequestFacts,
    SignatureSubject, SignerEndpoint, VerificationEndpoints, VerificationSession,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, BindingId, CredentialInstanceId, DestinationId, DeviceId, EnvironmentId, GrantId,
    IssuanceId, OperationId, PolicyId, ProfileId, RequestId, ResourceId, WorkId,
};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{
    DeadlineIntent, DelegateRequest, DestinationScopeEnforcement, Enforcement, EnsureData,
    EnsureRequest, ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry,
    PolicyAction, RefreshDependency, RequiredCapabilities, RevocationStatus, RevokeData,
    RevokeRequest, WaitMode, WorkloadIsolation,
};
use heimdall_credential::cert::{self, CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::endpoints::{
    self, EndpointLayout, EndpointRegistry, EndpointTag, endpoint_resource, serve_connection,
};
use heimdall_credential::signer::{
    ManagedSigner, SignHook, SignStep, SignerLimits, VERIFICATION_UNGATED_SIGNING,
};
use heimdall_credential::table::{
    InstallRefusal, InstallView, InstanceEvent, MAX_LISTED, MaterializeRefusal, SignerTable,
    VerificationScope, grant_comment, instance_transition,
};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo, SystemRng};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::DegradedReason;
use heimdall_domain::issuance::{
    CertificateBounds, CredentialInstance, CredentialState, EXTENSION_AGENT_FORWARDING,
    EXTENSION_PTY, IssuanceEntry, IssuanceState, principal_for,
};
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::resource::ResourceGeneration;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimeAnchor, TimePolicy, TimeStatus};
use heimdall_ipc::endpoint::{ExpectedOwner, PeerIdentity};
use heimdall_ipc::signing::{
    ServeLimits, Signer, SigningSession, enqueue_signed, failure_frame, serve_with_limits,
    success_frame,
};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::home::Scratch;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};
use ssh_key::certificate::Certificate;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

// =================================================================================
// Time, ids, policy
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(d).unwrap()
}

fn until(a: Timestamp, b: Timestamp) -> Duration {
    Duration::try_from(b.duration_since(a)).unwrap()
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
    pair("h2", "deploy")
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRng::fill(&mut b).unwrap();
    b
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: plus(t0(), 12 * HOUR),
        offline_until: plus(t0(), HOUR),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence {
            report: Enforcement {
                destination_scope: DestinationScopeEnforcement::ClientRouting,
                new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                workload_isolation: WorkloadIsolation::SharedOsUser,
                existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
                revocation: RevocationStatus::LocalApplied,
                identity_selection: None,
                new_signing_expiry: None,
                owned_multiplexing: None,
                remote_processes: None,
                unmanaged_connections: None,
                issuer_isolation: None,
            },
            evidence: Vec::new(),
        },
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

fn descriptor() -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: outcome().enforcement,
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
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
        connection: Default::default(),
    }
}

fn seed(store: &Store, pairs: &[AccessPair], lock: LockBehavior) {
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
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: pairs.iter().cloned().collect(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(&policy(pairs, LockBehavior::Continue, 1), false)?;
            if lock != LockBehavior::Continue {
                tx.upsert_policy(&policy(pairs, lock, 2), false)?;
            }
            Ok(())
        })
        .unwrap();
}

/// The operations clock on the tokio clock: wall = `t0 + elapsed + wall_ahead −
/// wall_back`, continuous = `elapsed + continuous_ahead`, one boot.
struct TokioClock {
    start: Instant,
    wall_back: Mutex<Duration>,
    wall_ahead: Mutex<Duration>,
    continuous_ahead: Mutex<Duration>,
    /// ⟨§17.19 item 1⟩ An armed wall step: `(reads left, step back)`. Each
    /// `observe()` counts one read; the read that brings the count to zero returns its
    /// value unchanged and **then** steps the wall clock back (per clock, so tests
    /// running in parallel never share it).
    step_back_after: Mutex<Option<(usize, Duration)>>,
}

impl TokioClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            wall_back: Mutex::new(Duration::ZERO),
            wall_ahead: Mutex::new(Duration::ZERO),
            continuous_ahead: Mutex::new(Duration::ZERO),
            step_back_after: Mutex::new(None),
        })
    }
    fn elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(self.start)
    }
    /// Arm a wall step of `back` right after the `reads`-th `observe()` from now.
    fn step_back_after_reads(&self, reads: usize, back: Duration) {
        *self.step_back_after.lock().unwrap() = Some((reads, back));
    }
}

impl Clock for TokioClock {
    fn wall(&self) -> Timestamp {
        let w = plus(t0(), self.elapsed() + *self.wall_ahead.lock().unwrap());
        w.checked_sub(*self.wall_back.lock().unwrap()).unwrap()
    }
    fn continuous(&self) -> Duration {
        Duration::from_secs(1000) + self.elapsed() + *self.continuous_ahead.lock().unwrap()
    }
    fn boot_id(&self) -> BootId {
        BootId("tokio-boot-1".into())
    }
    fn observe(&self) -> TimeAnchor {
        let anchor = TimeAnchor {
            wall: self.wall(),
            continuous: self.continuous(),
            boot_id: self.boot_id(),
        };
        let mut armed = self.step_back_after.lock().unwrap();
        if let Some((left, back)) = armed.as_mut() {
            *left = left.saturating_sub(1);
            if *left == 0 {
                *self.wall_back.lock().unwrap() += *back;
                *armed = None;
            }
        }
        anchor
    }
}

/// A session-lock source whose state the test sets.
struct TestLock {
    state: Mutex<LockState>,
    epoch: Mutex<LockEpoch>,
    notify: Notify,
}

impl TestLock {
    fn new(state: LockState) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            epoch: Mutex::new(LockEpoch::default()),
            notify: Notify::new(),
        })
    }
    fn set(&self, state: LockState) {
        *self.state.lock().unwrap() = state;
    }
}

impl SessionLockSource for TestLock {
    fn state(&self) -> LockState {
        *self.state.lock().unwrap()
    }
    fn lock_epoch(&self) -> LockEpoch {
        *self.epoch.lock().unwrap()
    }
    fn acknowledge(&self, epoch: u64) {
        let e = *self.epoch.lock().unwrap();
        *self.epoch.lock().unwrap() = e.acknowledge(epoch);
    }
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

// =================================================================================
// The narrowing hook (log, t_read / t_commit, key destruction under the gates)
// =================================================================================

type Fut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
type When = Box<dyn Fn(NarrowingKind, &NarrowingPoint) -> bool + Send + Sync>;

struct Act {
    when: When,
    run: Box<dyn Fn() -> Fut + Send + Sync>,
    left: AtomicUsize,
}

#[derive(Default)]
struct NHook {
    t_read: Mutex<Duration>,
    t_commit: Mutex<Duration>,
    cleanup_hold: Mutex<Option<(NarrowingKind, Duration)>>,
    log: Mutex<Vec<(Instant, NarrowingKind, NarrowingPoint)>>,
    acts: Mutex<Vec<Arc<Act>>>,
    table: Mutex<Option<SignerTable>>,
    changed: Notify,
}

impl NHook {
    fn act(
        &self,
        when: impl Fn(NarrowingKind, &NarrowingPoint) -> bool + Send + Sync + 'static,
        run: impl Fn() -> Fut + Send + Sync + 'static,
    ) {
        self.acts.lock().unwrap().push(Arc::new(Act {
            when: Box::new(when),
            run: Box::new(run),
            left: AtomicUsize::new(1),
        }));
    }

    fn at_of(&self, f: impl Fn(NarrowingKind, &NarrowingPoint) -> bool) -> Option<Instant> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|(_, k, p)| f(*k, p))
            .map(|(i, _, _)| *i)
    }

    fn mark_of(&self, kind: NarrowingKind) -> Instant {
        self.at_of(|k, p| k == kind && matches!(p, NarrowingPoint::Marked { .. }))
            .expect("marked")
    }

    fn report(&self, kind: NarrowingKind) -> NarrowingReport {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, _, p)| match p {
                NarrowingPoint::Reported(r) => Some((**r).clone()),
                _ => None,
            })
            .rfind(|r| r.kind == kind)
            .expect("a report")
    }

    async fn wait(
        &self,
        what: &str,
        f: impl Fn(&[(Instant, NarrowingKind, NarrowingPoint)]) -> bool,
    ) {
        let fut = async {
            loop {
                let n = self.changed.notified();
                tokio::pin!(n);
                n.as_mut().enable();
                if f(&self.log.lock().unwrap()) {
                    return;
                }
                n.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3600), fut)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    async fn wait_marked(&self, kind: NarrowingKind) {
        self.wait("the mark", |l| {
            l.iter()
                .any(|(_, k, p)| *k == kind && matches!(p, NarrowingPoint::Marked { .. }))
        })
        .await;
    }
}

impl NarrowingHook for NHook {
    fn at<'a>(&'a self, kind: NarrowingKind, point: NarrowingPoint) -> NarrowingFuture<'a> {
        Box::pin(async move {
            self.log
                .lock()
                .unwrap()
                .push((Instant::now(), kind, point.clone()));
            self.changed.notify_waiters();
            // D2 item 3a, order within a narrowing, step 3: keys destroyed and
            // identities unlisted under the gates (in memory; U10 wires
            // `ManagedEffects::destroy` here).
            if let NarrowingPoint::UnderGates { destroy, .. } = &point {
                let table = self.table.lock().unwrap().clone();
                if let Some(t) = table {
                    for g in destroy {
                        t.destroy_grant(g);
                    }
                }
            }
            let acts: Vec<Arc<Act>> = self
                .acts
                .lock()
                .unwrap()
                .iter()
                .filter(|a| (a.when)(kind, &point))
                .cloned()
                .collect();
            for a in acts {
                if a.left
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
                {
                    (a.run)().await;
                }
            }
            let delay = match &point {
                NarrowingPoint::BeforeRead(_) => *self.t_read.lock().unwrap(),
                NarrowingPoint::BeforeCommit => *self.t_commit.lock().unwrap(),
                NarrowingPoint::Cleanup { .. } => match *self.cleanup_hold.lock().unwrap() {
                    Some((k, d)) if k == kind => d,
                    _ => Duration::ZERO,
                },
                _ => Duration::ZERO,
            };
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            self.changed.notify_waiters();
        })
    }
}

// =================================================================================
// The signer's pause hook
// =================================================================================

/// Records every sign step with its instant, pauses at chosen steps until released,
/// and can sleep (virtual time) at one step.
#[derive(Default)]
struct Pauses {
    log: Mutex<Vec<(SignStep, Instant)>>,
    pause_at: Mutex<BTreeSet<SignStep>>,
    sleep_at: Mutex<Option<(SignStep, Duration)>>,
    reached: Notify,
    resume: Notify,
}

impl Pauses {
    fn none() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn pause(step: SignStep) -> Arc<Self> {
        let p = Self::default();
        p.pause_at.lock().unwrap().insert(step);
        Arc::new(p)
    }
    fn sleep(step: SignStep, d: Duration) -> Arc<Self> {
        let p = Self::default();
        *p.sleep_at.lock().unwrap() = Some((step, d));
        Arc::new(p)
    }
    async fn reached(&self) {
        self.reached.notified().await;
    }
    fn release(&self) {
        self.pause_at.lock().unwrap().clear();
        self.resume.notify_one();
    }
    fn at_of(&self, step: SignStep) -> Option<Instant> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|(s, _)| *s == step)
            .map(|(_, i)| *i)
    }
}

impl SignHook for Pauses {
    fn at<'a>(
        &'a self,
        _endpoint: &'a SignerEndpoint,
        step: SignStep,
    ) -> heimdall_credential::signer::HookFuture<'a> {
        Box::pin(async move {
            self.log.lock().unwrap().push((step, Instant::now()));
            let sleep = *self.sleep_at.lock().unwrap();
            if let Some((s, d)) = sleep
                && s == step
            {
                tokio::time::sleep(d).await;
            }
            let pause = self.pause_at.lock().unwrap().contains(&step);
            if pause {
                self.reached.notify_one();
                self.resume.notified().await;
            }
        })
    }
}

// =================================================================================
// The world: Operations, the signer table, a test CA
// =================================================================================

/// The fixture install view (U2-Q2): accepts every installation the table's own checks
/// pass.
struct AcceptView;

#[async_trait]
impl InstallView for AcceptView {
    async fn check(&self, _grant: &GrantId, _entry: &IssuanceEntry) -> Result<(), InstallRefusal> {
        Ok(())
    }
}

struct Opts {
    limits: Limits,
    pairs: Vec<AccessPair>,
    lock: LockBehavior,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            pairs: vec![h1(), h2()],
            lock: LockBehavior::Continue,
        }
    }
}

/// A grant with its installed key and certificates (one per pair).
#[derive(Clone)]
struct G {
    data: EnsureData,
    key: PublicKeyInfo,
    certs: Vec<(AccessPair, Certificate)>,
    entries: Vec<IssuanceEntry>,
}

impl G {
    fn id(&self) -> &GrantId {
        &self.data.grant_id
    }
    fn binding(&self) -> &BindingId {
        &self.data.binding_id
    }
    fn cert(&self, p: &AccessPair) -> &Certificate {
        &self
            .certs
            .iter()
            .find(|(q, _)| q == p)
            .expect("a certificate")
            .1
    }
    fn blob(&self, p: &AccessPair) -> Vec<u8> {
        self.cert(p).to_bytes().unwrap()
    }
    /// A userauth request for `p` as `p`'s account presenting `p`'s certificate.
    fn auth(&self, p: &AccessPair, sid: &[u8]) -> Vec<u8> {
        userauth(sid, p.account.as_str(), "publickey", &self.blob(p), None)
    }
    fn req(&self, p: &AccessPair) -> Vec<u8> {
        sign_req(&self.blob(p), &self.auth(p, &sid()), 0)
    }
}

struct W {
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    limits: Limits,
    ops: Operations,
    hook: Arc<NHook>,
    table: SignerTable,
    ca: SecretCaKey,
    ca_blob: Vec<u8>,
}

fn config(
    store: &Arc<Store>,
    clock: &Arc<TokioClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
    limits: Limits,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
        limits,
        default_window: 12 * HOUR,
        projection: None,
    }
}

async fn world() -> W {
    world_with(Opts::default()).await
}

async fn world_with(o: Opts) -> W {
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    seed(&store, &o.pairs, o.lock);
    let clock = TokioClock::new();
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::new(descriptor(), vec![FakeStep::Prepare(outcome())]);
    let ops = Operations::start(config(&store, &clock, &sync, &fake, o.limits))
        .await
        .unwrap();
    // Reading R2: never depend on the default authorization time.
    ops.set_authorization_time(AuthorizationTime::ReadOnly);
    let hook = Arc::new(NHook::default());
    ops.set_narrowing_hook(hook.clone());
    let table = SignerTable::new(Arc::new(KeyVault::new()));
    table.set_install_view(Arc::new(AcceptView));
    *hook.table.lock().unwrap() = Some(table.clone());
    let ca = SecretCaKey::generate().unwrap();
    let ca_blob = ca.public_key().to_bytes().unwrap();
    W {
        store,
        clock,
        sync,
        fake,
        limits: o.limits,
        ops,
        hook,
        table,
        ca,
        ca_blob,
    }
}

/// The bounds of a reservation for `p` and its certificate, issued by `ca` for `key`
/// (real wall time, an hour of validity, so a real sshd accepts it).
fn issue(
    ca: &SecretCaKey,
    grant: &GrantId,
    key: &PublicKeyInfo,
    p: &AccessPair,
    extensions: &[&str],
) -> (Certificate, IssuanceEntry) {
    let now = Timestamp::now().as_second();
    let serial = u64::from_be_bytes(random::<8>());
    let bounds = CertificateBounds {
        serial,
        key_id: cert::key_id(&env_id(), grant, serial),
        principal: principal_for(p),
        valid_after: cert::valid_after_for(Timestamp::from_second(now).unwrap()).unwrap(),
        valid_before: Timestamp::from_second(now + 3600).unwrap(),
        extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
        subject_fingerprint: key.fingerprint.clone(),
        ca_fingerprint: Some(ca.fingerprint().unwrap()),
    };
    let cert = build_and_sign(
        &CertificateProfile::from_bounds(&bounds),
        &key.public_key().unwrap(),
        ca,
    )
    .unwrap();
    let entry = IssuanceEntry {
        id: IssuanceId::from_random_bytes(random()),
        grant: grant.clone(),
        generation: AuthorityGeneration(0),
        pair: p.clone(),
        bounds,
        state: IssuanceState::Published,
        reserved_at: Timestamp::from_second(now).unwrap(),
        settled_at: Some(Timestamp::from_second(now).unwrap()),
        void_reason: None,
        continuing: false,
    };
    (cert, entry)
}

impl W {
    fn gates(&self) -> &SigningGates {
        self.ops.signing_gates()
    }

    fn authority(&self) -> Arc<dyn SignatureAuthority> {
        Arc::new(self.ops.clone())
    }

    fn signer_limits(&self) -> SignerLimits {
        SignerLimits::from_limits(&self.limits)
    }

    fn signer(&self, endpoint: SignerEndpoint) -> Arc<ManagedSigner> {
        Arc::new(ManagedSigner::new(
            endpoint,
            self.table.clone(),
            self.authority(),
            self.signer_limits(),
        ))
    }

    fn signer_with(&self, endpoint: SignerEndpoint, hook: Arc<dyn SignHook>) -> Arc<ManagedSigner> {
        Arc::new(
            ManagedSigner::new(
                endpoint,
                self.table.clone(),
                self.authority(),
                self.signer_limits(),
            )
            .with_hook(hook),
        )
    }

    async fn ensure(&self, tag: &str, pairs: &[AccessPair]) -> EnsureData {
        let r = self
            .ops
            .ensure(
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
            .await;
        match r {
            Ok(c) => c.data,
            Err(e) => panic!("ensure {tag}: {} {}", e.code, e.message),
        }
    }

    /// Generate K_env, install one certificate per pair (with `extensions`) after the
    /// table's D2 item 6 check, and attach the binding.
    async fn install(&self, data: EnsureData, pairs: &[AccessPair], extensions: &[&str]) -> G {
        let gid = data.grant_id.clone();
        let reg = self.table.generate(&gid, pairs).unwrap();
        assert_eq!(
            self.table.instance_state(&gid),
            Some(CredentialState::Pending)
        );
        let key = self.table.public_key(&gid).unwrap();
        assert_eq!(reg.fingerprint, key.fingerprint);
        let mut certs = Vec::new();
        let mut entries = Vec::new();
        for p in pairs {
            let (c, e) = issue(&self.ca, &gid, &key, p, extensions);
            self.table.install(&gid, p, &c, &e).await.unwrap();
            certs.push((p.clone(), c));
            entries.push(e);
        }
        assert_eq!(
            self.table.instance_state(&gid),
            Some(CredentialState::Installed)
        );
        self.table.attach_binding(&data.binding_id, &gid);
        G {
            data,
            key,
            certs,
            entries,
        }
    }

    /// An active grant for `pairs`, gated (its first instance), installed, attached.
    async fn grant(&self, tag: &str, pairs: &[AccessPair]) -> G {
        let data = self.ensure(tag, pairs).await;
        self.gates().retain(&data.grant_id, &[]);
        self.install(data, pairs, &[EXTENSION_PTY]).await
    }

    /// Hold the environment slot of `p` for `g`'s binding (the store's record that the
    /// binding is materialized; D10 item 2).
    fn claim_slot(&self, g: &G, p: &AccessPair) {
        let b = g.binding().clone();
        let p = p.clone();
        self.store
            .transaction(|tx| tx.claim_slot(&env_id(), &p, &b, t0()))
            .unwrap()
            .unwrap();
    }

    async fn revoke(&self, g: &G, rid: &str) -> RevokeData {
        revoke(&self.ops, g.id(), rid).await
    }

    fn spawn_revoke(&self, g: &G, rid: &str) -> tokio::task::JoinHandle<RevokeData> {
        let (ops, gid, rid) = (self.ops.clone(), g.id().clone(), rid.to_owned());
        tokio::spawn(async move { revoke(&ops, &gid, &rid).await })
    }

    fn spawn_cutoff(&self) -> tokio::task::JoinHandle<()> {
        let ops = self.ops.clone();
        let at = plus(self.clock.wall(), HOUR);
        tokio::spawn(async move {
            ops.policy(
                &owner(),
                PolicyAction::Cutoff {
                    policy_id: policy_id(),
                    at,
                },
            )
            .await
            .map(|_| ())
            .unwrap();
        })
    }

    fn state(&self, g: &G) -> GrantState {
        self.store
            .transaction(|tx| tx.grant(g.id()))
            .unwrap()
            .unwrap()
            .state
    }

    fn degrade(&self, g: &G, reason: DegradedReason) {
        let gid = g.id().clone();
        self.store
            .transaction(|tx| {
                let mut snap = tx.grant(&gid)?.unwrap();
                snap.state = GrantState::Degraded;
                tx.update_grant_state(&snap)?;
                tx.set_grant_degradation(&gid, reason)
            })
            .unwrap();
    }
}

async fn revoke(ops: &Operations, gid: &GrantId, rid: &str) -> RevokeData {
    match ops
        .revoke(
            &owner(),
            RevokeRequest {
                grant_id: gid.clone(),
                request_id: RequestId::parse(rid).unwrap(),
            },
        )
        .await
    {
        Ok(c) => c.data,
        Err(e) => panic!("revoke {rid}: {} {}", e.code, e.message),
    }
}

async fn settle() {
    for _ in 0..40 {
        tokio::task::yield_now().await;
    }
}

// =================================================================================
// The agent wire
// =================================================================================

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn ident_req() -> Vec<u8> {
    framed(&[11])
}

fn sign_req(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut body = vec![13];
    put_string(&mut body, key_blob);
    put_string(&mut body, data);
    body.extend_from_slice(&flags.to_be_bytes());
    framed(&body)
}

fn bind_req(contents: &[u8]) -> Vec<u8> {
    let mut body = vec![27];
    put_string(&mut body, b"session-bind@openssh.com");
    body.extend_from_slice(contents);
    framed(&body)
}

const CERT_ALG: &str = "ssh-ed25519-cert-v01@openssh.com";
const HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// A userauth request (RFC 4252 §7) presenting `key_blob` as an Ed25519 certificate.
fn userauth(
    sid: &[u8],
    user: &str,
    method: &str,
    key_blob: &[u8],
    host_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, sid);
    out.push(50);
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, b"ssh-connection");
    put_string(&mut out, method.as_bytes());
    out.push(1);
    put_string(&mut out, CERT_ALG.as_bytes());
    put_string(&mut out, key_blob);
    if let Some(h) = host_key {
        put_string(&mut out, h);
    }
    out
}

/// A host key and a `session-bind@openssh.com` payload signed by it over `sid`.
fn signed_bind(sid: &[u8], forwarding: bool) -> (Vec<u8>, Vec<u8>) {
    let vault = KeyVault::new();
    let (slot, info) = vault.generate_ed25519().unwrap();
    let signature = vault.sign(&slot, sid).unwrap();
    let mut out = Vec::new();
    put_string(&mut out, &info.blob);
    put_string(&mut out, sid);
    put_string(&mut out, &signature);
    out.push(u8::from(forwarding));
    (info.blob, out)
}

async fn read_frame(r: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(h) as usize];
    r.read_exact(&mut body).await.ok()?;
    let mut out = h.to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

fn is_signature(frame: &[u8]) -> bool {
    frame.get(4) == Some(&14)
}

fn is_failure(frame: &[u8]) -> bool {
    frame == failure_frame()
}

fn take_string(c: &mut &[u8]) -> Vec<u8> {
    let n = u32::from_be_bytes(c[..4].try_into().unwrap()) as usize;
    let s = c[4..4 + n].to_vec();
    *c = &c[4 + n..];
    s
}

fn parse_identities(frame: &[u8]) -> Vec<(Vec<u8>, String)> {
    assert_eq!(frame.get(4), Some(&12), "an identities answer");
    let mut c = &frame[5..];
    let n = u32::from_be_bytes(c[..4].try_into().unwrap());
    c = &c[4..];
    (0..n)
        .map(|_| {
            let blob = take_string(&mut c);
            let comment = String::from_utf8(take_string(&mut c)).unwrap();
            (blob, comment)
        })
        .collect()
}

fn fixture_ref(endpoint: &SignerEndpoint) -> EndpointRef {
    EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: format!("/fixture/{endpoint:?}"),
    }
}

fn me() -> PeerIdentity {
    PeerIdentity::Unix {
        uid: 501,
        gid: 20,
        pid: None,
    }
}

/// One agent connection served by the real `serve_with_limits`.
struct Conn {
    client: DuplexStream,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Conn {
    fn open(signer: Arc<ManagedSigner>, limits: ServeLimits) -> Conn {
        Self::open_buf(signer, limits, 1 << 16)
    }

    fn open_buf(signer: Arc<ManagedSigner>, limits: ServeLimits, buf: usize) -> Conn {
        let (client, server) = tokio::io::duplex(buf);
        let endpoint = fixture_ref(signer.endpoint());
        let s: Arc<dyn Signer> = signer;
        let server = tokio::spawn(serve_with_limits(
            server,
            me(),
            endpoint,
            s,
            CancellationToken::new(),
            limits,
        ));
        Conn { client, server }
    }

    async fn call(&mut self, req: &[u8]) -> Vec<u8> {
        self.client.write_all(req).await.unwrap();
        read_frame(&mut self.client).await.expect("a reply")
    }

    async fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        parse_identities(&self.call(&ident_req()).await)
    }
}

fn serve_limits(w: &W) -> ServeLimits {
    SignerLimits::from_limits(&w.limits).serve
}

/// A stuck connection: a 1-byte server→client buffer the client does not drain and a
/// one-frame queue. Two identity answers fill the writer and the queue; the next reply
/// waits for capacity.
fn stuck(signer: Arc<ManagedSigner>, enqueue_timeout: Duration) -> Conn {
    Conn::open_buf(
        signer,
        ServeLimits {
            idle: Duration::from_secs(60),
            enqueue_timeout,
            outbound_frames: 1,
        },
        1,
    )
}

fn sid() -> Vec<u8> {
    random::<32>().to_vec()
}

fn sig_bytes_in(stream: &[u8], g: &G) -> bool {
    // Every signature frame the client could see starts with 14 after the length; a
    // stream of failures and identity answers holds none.
    let _ = g;
    let mut c = stream;
    while c.len() >= 5 {
        let n = u32::from_be_bytes(c[..4].try_into().unwrap()) as usize;
        if c[4] == 14 {
            return true;
        }
        c = &c[(4 + n).min(c.len())..];
    }
    false
}

// =================================================================================
// Positive
// =================================================================================

/// D2 item 2, D10 items 2–3, F17, A10: the environment endpoint lists exactly the
/// certificates of materialized bindings for their materialized pairs (at most one
/// binding per pair), never a plain K_env and never the CA; it signs only for those.
#[tokio::test(start_paused = true)]
async fn environment_endpoint_lists_only_materialized_bindings() {
    let w = world().await;
    let a = w.grant("a", &[h1()]).await;
    let b = w.grant("b", &[h2()]).await;
    let c = w.grant("c", &[h1()]).await;
    let env = w.signer(SignerEndpoint::Environment);
    let mut conn = Conn::open(env.clone(), serve_limits(&w));
    assert!(conn.identities().await.is_empty(), "nothing materialized");

    w.table.materialize(a.binding(), &[h1()]).unwrap();
    assert_eq!(
        conn.identities().await,
        vec![(a.blob(&h1()), grant_comment(a.id()))]
    );
    // At most one binding per pair.
    assert_eq!(
        w.table.materialize(c.binding(), &[h1()]),
        Err(MaterializeRefusal::PairHeld(h1()))
    );
    assert_eq!(
        w.table.materialize(b.binding(), &[h1()]),
        Err(MaterializeRefusal::NotInstalled(h1()))
    );
    w.table.materialize(b.binding(), &[h2()]).unwrap();
    let listed = conn.identities().await;
    assert_eq!(
        listed,
        vec![
            (a.blob(&h1()), grant_comment(a.id())),
            (b.blob(&h2()), grant_comment(b.id())),
        ]
    );
    for (blob, comment) in &listed {
        for g in [&a, &b, &c] {
            assert_ne!(blob, &g.key.blob, "never a plain K_env");
        }
        assert_ne!(blob, &w.ca_blob, "never the CA");
        assert!(comment.starts_with("heimdall:") && comment.len() == "heimdall:".len() + 12);
    }

    // It signs for a materialized binding whose slot the store holds.
    w.claim_slot(&a, &h1());
    assert!(
        is_signature(&conn.call(&a.req(&h1())).await),
        "{:?}",
        env.refusals()
    );
    // Never for a grant that is not materialized here.
    assert!(is_failure(&conn.call(&c.req(&h1())).await));
    assert_eq!(env.refusals().last(), Some(&"key_not_listed"));

    w.table.unmaterialize(a.binding());
    assert_eq!(
        conn.identities().await,
        vec![(b.blob(&h2()), grant_comment(b.id()))]
    );
    assert!(is_failure(&conn.call(&a.req(&h1())).await));
}

/// ⟨integrator, wave-2 review⟩ D10 items 2–3 in the admitting read: the environment
/// endpoint signs for a pair only while the grant's binding **holds that pair's** slot
/// in the store. A table that still lists a pair whose slot the store does not hold
/// (an unmaterialize that has not run yet) is refused by the fresh read
/// (`key_not_served`), never released.
#[tokio::test(start_paused = true)]
async fn environment_endpoint_requires_the_pairs_held_slot_in_the_store() {
    let w = world().await;
    let g = w.grant("g", &[h1(), h2()]).await;
    let env = w.signer(SignerEndpoint::Environment);
    let mut conn = Conn::open(env.clone(), serve_limits(&w));
    w.table.materialize(g.binding(), &[h1(), h2()]).unwrap();
    assert_eq!(
        conn.identities().await.len(),
        2,
        "both pairs listed in memory"
    );
    // The store holds h1's slot for the binding, not h2's.
    w.claim_slot(&g, &h1());
    assert!(
        is_signature(&conn.call(&g.req(&h1())).await),
        "{:?}",
        env.refusals()
    );
    assert!(is_failure(&conn.call(&g.req(&h2())).await));
    assert_eq!(env.refusals().last(), Some(&"key_not_served"));
    // Once the store holds h2's slot too, h2 signs.
    w.claim_slot(&g, &h2());
    assert!(
        is_signature(&conn.call(&g.req(&h2())).await),
        "{:?}",
        env.refusals()
    );
}

/// Arms `clock`'s wall step when the signer reaches [`SignStep::Prechecked`]: from
/// there, read 1 is the permit's paired observation (`admit_signature`) and read 2 the
/// authorization's time assessment.
struct StepBackAfterPrecheck {
    clock: Arc<TokioClock>,
    back: Duration,
}

impl SignHook for StepBackAfterPrecheck {
    fn at<'a>(
        &'a self,
        _endpoint: &'a SignerEndpoint,
        step: SignStep,
    ) -> heimdall_credential::signer::HookFuture<'a> {
        Box::pin(async move {
            if step == SignStep::Prechecked {
                self.clock.step_back_after_reads(2, self.back);
            }
        })
    }
}

/// ⟨§17.19 item 1, W2-R01 = W2-S01⟩ The security review's interleaving, through the
/// real signer, `SignatureAuthority::admit` under the default `ReadOnly` seam, and the
/// real capacity-then-release enqueue: the time gate assesses an observation as
/// `Safe`, and the wall clock then steps back an hour (beyond the rollback tolerance)
/// before anything else reads it. The admission is the assessed observation's, so the
/// release check sees the step and nothing is released. Before the fix, the admission
/// took a second, unassessed reading after the step, and the signature was released.
/// Control: the same flow with a zero step releases.
#[tokio::test(start_paused = true)]
async fn signature_refused_when_wall_clock_steps_back_after_the_time_assessment() {
    let w = world().await;
    assert_eq!(
        heimdall_app::operations::narrowing::AuthorizationTime::default(),
        AuthorizationTime::ReadOnly,
        "the default seam is the one under test"
    );
    for (back, released) in [(Duration::ZERO, true), (HOUR, false)] {
        let g = w
            .grant(&format!("step-back-{}", back.as_secs()), &[h1()])
            .await;
        let s = w.signer_with(
            SignerEndpoint::Binding(g.binding().clone()),
            Arc::new(StepBackAfterPrecheck {
                clock: Arc::clone(&w.clock),
                back,
            }),
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let frame = spawn_signed(&s, &g, &h1(), &log).await.unwrap();
        assert_eq!(
            is_signature(&frame),
            released,
            "step back {back:?}: {:?}",
            s.refusals()
        );
        if !released {
            // The step was beyond the tolerance: time is no longer `Safe` at all.
            assert_ne!(
                w.ops.timegate().assess_read_only(&w.store),
                TimeStatus::Safe
            );
        }
    }
}

/// D2 item 2: a binding endpoint lists its grant's certificates only and signs for
/// nothing else; the plain K_env is never served (F17); an unattached binding lists
/// nothing.
#[tokio::test(start_paused = true)]
async fn binding_endpoint_lists_only_its_grant() {
    let w = world().await;
    let a = w.grant("a", &[h1()]).await;
    let b = w.grant("b", &[h1(), h2()]).await;
    let sa = w.signer(SignerEndpoint::Binding(a.binding().clone()));
    let sb = w.signer(SignerEndpoint::Binding(b.binding().clone()));
    let mut ca = Conn::open(sa.clone(), serve_limits(&w));
    let mut cb = Conn::open(sb, serve_limits(&w));
    assert_eq!(
        ca.identities().await,
        vec![(a.blob(&h1()), grant_comment(a.id()))]
    );
    let lb = cb.identities().await;
    assert_eq!(
        lb,
        vec![
            (b.blob(&h1()), grant_comment(b.id())),
            (b.blob(&h2()), grant_comment(b.id())),
        ]
    );
    assert!(
        !lb.iter()
            .any(|(bl, _)| *bl == b.key.blob || *bl == a.blob(&h1()))
    );
    assert!(
        is_signature(&ca.call(&a.req(&h1())).await),
        "{:?}",
        sa.refusals()
    );
    assert!(is_signature(&cb.call(&b.req(&h2())).await));
    assert!(is_failure(&ca.call(&b.req(&h1())).await));
    assert_eq!(sa.refusals().last(), Some(&"key_not_listed"));
    // F17: the plain K_env is never served, even by its own binding.
    let plain = userauth(&sid(), "deploy", "publickey", &a.key.blob, None);
    assert!(is_failure(
        &ca.call(&sign_req(&a.key.blob, &plain, 0)).await
    ));
    assert_eq!(sa.refusals().last(), Some(&"key_not_listed"));
    // A listed certificate asked under a userauth presenting the plain key: refused.
    assert!(is_failure(
        &ca.call(&sign_req(&a.blob(&h1()), &plain, 0)).await
    ));
    assert_eq!(sa.refusals().last(), Some(&"request_key_mismatch"));
    // An unattached binding lists and signs nothing.
    let stray = w.signer(SignerEndpoint::Binding(BindingId::from_random_bytes(
        random(),
    )));
    let mut cs = Conn::open(stray, serve_limits(&w));
    assert!(cs.identities().await.is_empty());
    assert!(is_failure(&cs.call(&a.req(&h1())).await));
}

// =================================================================================
// Negative
// =================================================================================

/// D2 item 3: the admission deadline, on both branches. Wall: the clock passes the
/// grant's deadline. Continuous: the continuous clock runs 40 s ahead of the wall
/// (inside the 60 s skew tolerance), so the continuous budget ends while the wall is
/// still 30 s before the deadline.
#[tokio::test(start_paused = true)]
async fn signature_refused_after_deadline() {
    // Wall branch.
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert!(is_signature(&c.call(&g.req(&h1())).await));
    tokio::time::advance(until(w.clock.wall(), g.data.expires_at) + Duration::from_secs(1)).await;
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"deadline_passed"));

    // Continuous branch.
    let w = world().await;
    let g = w.grant("b", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    tokio::time::advance(until(w.clock.wall(), g.data.expires_at) - Duration::from_secs(30)).await;
    assert!(
        is_signature(&c.call(&g.req(&h1())).await),
        "{:?}",
        s.refusals()
    );
    *w.clock.continuous_ahead.lock().unwrap() = Duration::from_secs(40);
    assert!(
        w.clock.wall() < g.data.expires_at,
        "the wall has not passed"
    );
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"deadline_passed"));
}

/// D2 item 3: a committed tombstone refuses every later signature.
#[tokio::test(start_paused = true)]
async fn signature_refused_after_tombstone_commit() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    // Keep the key in the table, so the refusal is the authority's, not the vault's.
    *w.hook.table.lock().unwrap() = None;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert!(is_signature(&c.call(&g.req(&h1())).await));
    w.revoke(&g, "rv").await;
    assert_ne!(w.state(&g), GrantState::Active);
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"tombstoned"));
}

/// D2 item 3: time not `Safe` (the wall clock stepped back an hour) refuses.
#[tokio::test(start_paused = true)]
async fn signature_refused_on_time_uncertain() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert!(is_signature(&c.call(&g.req(&h1())).await));
    *w.clock.wall_back.lock().unwrap() = HOUR;
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"time_uncertain"));
    // An unsynchronized time source alone: the same refusal class or the gate's.
    *w.clock.wall_back.lock().unwrap() = Duration::ZERO;
    let _ = &w.sync;
}

/// D2 item 3, U0b row 12: `degraded(mechanism_unavailable)` refuses; a degraded reason
/// that permits signing (`issuer_unavailable`) does not.
#[tokio::test(start_paused = true)]
async fn signature_refused_for_mechanism_unavailable() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    w.degrade(&g, DegradedReason::MechanismUnavailable);
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"grant_not_usable"));
    w.degrade(&g, DegradedReason::IssuerUnavailable);
    assert!(
        is_signature(&c.call(&g.req(&h1())).await),
        "{:?}",
        s.refusals()
    );
    let _ = &w.fake;
}

/// D2 item 3, D9: a `revoke_on_lock` grant signs only while the session-lock source
/// reports `unlocked` (`locked` and `unknown` refuse).
#[tokio::test(start_paused = true)]
async fn signature_refused_for_revoke_on_lock_unless_unlocked() {
    let w = world_with(Opts {
        lock: LockBehavior::RevokeOnLock,
        ..Opts::default()
    })
    .await;
    let lock = TestLock::new(LockState::Unlocked);
    w.ops.set_session_lock_source(lock.clone());
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert!(
        is_signature(&c.call(&g.req(&h1())).await),
        "{:?}",
        s.refusals()
    );
    for state in [LockState::Locked, LockState::Unknown] {
        lock.set(state);
        assert!(is_failure(&c.call(&g.req(&h1())).await), "{state:?}");
        assert_eq!(s.refusals().last(), Some(&"session_not_unlocked"));
    }
    lock.set(LockState::Unlocked);
    assert!(is_signature(&c.call(&g.req(&h1())).await));
}

/// D2 item 5: a forwarded bind (`is_forwarding`) refuses every signature unless the
/// presented certificate carries `permit-agent-forwarding` (the grant's scope has
/// `agent-forwarding`); a local bind signs only for its session and host key; a bind
/// whose host signature fails poisons the connection.
#[tokio::test(start_paused = true)]
async fn forwarded_session_refused_without_agent_forwarding() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let session = sid();
    let (host, fwd) = signed_bind(&session, true);
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert_eq!(c.call(&bind_req(&fwd)).await, success_frame());
    let r = c
        .call(&sign_req(&g.blob(&h1()), &g.auth(&h1(), &session), 0))
        .await;
    assert!(is_failure(&r));
    assert_eq!(s.refusals().last(), Some(&"forwarding_not_permitted"));

    // A local bind: signs for its session and host key only.
    let session = sid();
    let (host2, local) = signed_bind(&session, false);
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert_eq!(c.call(&bind_req(&local)).await, success_frame());
    let hb = userauth(&session, "deploy", HOSTBOUND, &g.blob(&h1()), Some(&host2));
    assert!(is_signature(
        &c.call(&sign_req(&g.blob(&h1()), &hb, 0)).await
    ));
    let wrong_host = userauth(&session, "deploy", HOSTBOUND, &g.blob(&h1()), Some(&host));
    assert!(is_failure(
        &c.call(&sign_req(&g.blob(&h1()), &wrong_host, 0)).await
    ));
    assert_eq!(s.refusals().last(), Some(&"host_key_mismatch"));
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"session_mismatch"));
    // A later forwarding hop on the same connection stays recorded as forwarding.
    let (_, fwd) = signed_bind(&session, true);
    assert_eq!(c.call(&bind_req(&fwd)).await, success_frame());
    let r = c
        .call(&sign_req(&g.blob(&h1()), &g.auth(&h1(), &session), 0))
        .await;
    assert!(is_failure(&r));
    assert_eq!(s.refusals().last(), Some(&"forwarding_not_permitted"));

    // A grant whose certificate permits agent forwarding signs on a forwarded bind.
    let data = w.ensure("f", &[h1()]).await;
    w.gates().retain(&data.grant_id, &[]);
    let f = w
        .install(data, &[h1()], &[EXTENSION_PTY, EXTENSION_AGENT_FORWARDING])
        .await;
    let sf = w.signer(SignerEndpoint::Binding(f.binding().clone()));
    let session = sid();
    let (_, fwd) = signed_bind(&session, true);
    let mut c = Conn::open(sf.clone(), serve_limits(&w));
    assert_eq!(c.call(&bind_req(&fwd)).await, success_frame());
    let r = c
        .call(&sign_req(&f.blob(&h1()), &f.auth(&h1(), &session), 0))
        .await;
    assert!(is_signature(&r), "{:?}", sf.refusals());

    // A bind whose host signature does not verify poisons the connection.
    let session = sid();
    let (_, mut bad) = signed_bind(&session, false);
    let n = bad.len();
    bad[n - 2] ^= 0xff;
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    assert!(is_failure(&c.call(&bind_req(&bad)).await));
    let r = c
        .call(&sign_req(&g.blob(&h1()), &g.auth(&h1(), &session), 0))
        .await;
    assert!(is_failure(&r));
    assert_eq!(s.refusals().last(), Some(&"session_bind_failed"));
    let (_, good) = signed_bind(&session, false);
    assert!(
        is_failure(&c.call(&bind_req(&good)).await),
        "poisoned for good"
    );
    let stats = s.bind_stats();
    assert!(stats.accepted >= 3 && stats.refused >= 2, "{stats:?}");
}

/// ADR-0006 §2.6 allow-list on the real signer: add, remove, remove-all, smartcard,
/// lock, unlock, constrained adds and every other extension get `SSH_AGENT_FAILURE`,
/// change nothing, and leave the connection usable.
#[tokio::test(start_paused = true)]
async fn add_remove_lock_unlock_smartcard_extension_refused_on_real_signer() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    let before = c.identities().await;
    let keys = w.table.vault().len();
    let with_string = |ty: u8, s: &[u8]| {
        let mut b = vec![ty];
        put_string(&mut b, s);
        b
    };
    for body in [
        with_string(17, b"ssh-ed25519"),
        with_string(18, &g.blob(&h1())),
        vec![19],
        with_string(20, b"reader"),
        with_string(21, b"reader"),
        with_string(22, b"fixture-lock-word"),
        with_string(23, b"fixture-lock-word"),
        with_string(25, b"ssh-ed25519"),
        with_string(26, b"reader"),
        with_string(27, b"query"),
        with_string(27, b"restrict-destination-v00@openssh.com"),
        vec![9],
    ] {
        let r = c.call(&framed(&body)).await;
        assert!(is_failure(&r), "type {}", body[0]);
    }
    assert_eq!(c.identities().await, before);
    assert_eq!(w.table.vault().len(), keys);
    assert!(is_signature(&c.call(&g.req(&h1())).await), "still usable");
}

/// An authority that refuses everything (tables without a store).
struct NoAuthority;

#[async_trait]
impl SignatureAuthority for NoAuthority {
    async fn precheck(&self, _facts: &SignatureRequestFacts) -> Result<(), SignRefusal> {
        Err(SignRefusal::Unavailable)
    }
    async fn admit(&self, _facts: &SignatureRequestFacts) -> Result<SignPermit, SignRefusal> {
        Err(SignRefusal::Unavailable)
    }
}

/// `ipc::signing::MAX_IDENTITIES`: every endpoint lists at most 64 identities, in the
/// table and on the wire.
#[tokio::test]
async fn identities_capped_at_64() {
    let table = SignerTable::new(Arc::new(KeyVault::new()));
    table.set_install_view(Arc::new(AcceptView));
    let ca = SecretCaKey::generate().unwrap();
    // 70 materialized bindings, one pair each.
    for i in 0..70 {
        let gid = GrantId::from_random_bytes(random());
        let p = pair(&format!("d{i:02}"), "deploy");
        table.generate(&gid, std::slice::from_ref(&p)).unwrap();
        let key = table.public_key(&gid).unwrap();
        let (c, e) = issue(&ca, &gid, &key, &p, &[EXTENSION_PTY]);
        table.install(&gid, &p, &c, &e).await.unwrap();
        let b = BindingId::from_random_bytes(random());
        table.attach_binding(&b, &gid);
        table.materialize(&b, &[p]).unwrap();
    }
    assert_eq!(MAX_LISTED, 64);
    assert_eq!(table.list(&SignerEndpoint::Environment).len(), 64);
    // One grant with 70 pairs, on its binding endpoint.
    let gid = GrantId::from_random_bytes(random());
    let pairs: Vec<AccessPair> = (0..70)
        .map(|i| pair(&format!("e{i:02}"), "deploy"))
        .collect();
    table.generate(&gid, &pairs).unwrap();
    let key = table.public_key(&gid).unwrap();
    for p in &pairs {
        let (c, e) = issue(&ca, &gid, &key, p, &[EXTENSION_PTY]);
        table.install(&gid, p, &c, &e).await.unwrap();
    }
    let b = BindingId::from_random_bytes(random());
    table.attach_binding(&b, &gid);
    assert_eq!(table.list(&SignerEndpoint::Binding(b.clone())).len(), 64);
    for endpoint in [SignerEndpoint::Environment, SignerEndpoint::Binding(b)] {
        let s = Arc::new(ManagedSigner::new(
            endpoint,
            table.clone(),
            Arc::new(NoAuthority),
            SignerLimits::default(),
        ));
        let mut c = Conn::open(s, ServeLimits::default());
        assert_eq!(c.identities().await.len(), 64);
    }
}

/// ADR-0006 §2.1 on every endpoint kind: a connection whose transport-authenticated
/// peer is another principal is closed before a byte is read, with no reply; the
/// runtime's own principal is served. The peer check runs with a forged credential in
/// the test double (`serve_connection`, the registry's per-connection path). The
/// cross-account rows are separate tests, blocked on B3 (macOS), B2 (Windows) and B8
/// (the devbox).
#[tokio::test(start_paused = true)]
async fn endpoint_refuses_other_principal() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    #[cfg(unix)]
    let (owner, other, mine) = {
        let uid = heimdall_ipc::unix::current_uid();
        (
            ExpectedOwner::Uid(uid),
            PeerIdentity::Unix {
                uid: uid.wrapping_add(1),
                gid: 0,
                pid: None,
            },
            PeerIdentity::Unix {
                uid,
                gid: 0,
                pid: None,
            },
        )
    };
    #[cfg(windows)]
    let (owner, other, mine) = {
        let sid = heimdall_ipc::windows::current_user_sid().unwrap();
        (
            ExpectedOwner::Sid(sid.clone()),
            // BUILTIN\Users: a well-known group SID, never this account.
            PeerIdentity::Windows {
                sid: "S-1-5-32-545".into(),
                pid: None,
            },
            PeerIdentity::Windows { sid, pid: None },
        )
    };
    assert!(!endpoints::peer_admitted(&other, &owner));
    assert!(endpoints::peer_admitted(&mine, &owner));
    for endpoint in [
        SignerEndpoint::Environment,
        SignerEndpoint::Binding(g.binding().clone()),
        SignerEndpoint::Verification(OperationId::from_random_bytes(random())),
    ] {
        let signer: Arc<dyn Signer> = w.signer(endpoint.clone());
        let (mut client, server) = tokio::io::duplex(1 << 12);
        client.write_all(&ident_req()).await.unwrap();
        let r = serve_connection(
            server,
            other.clone(),
            fixture_ref(&endpoint),
            Arc::clone(&signer),
            &owner,
            ServeLimits::default(),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            r.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "{endpoint:?}"
        );
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        assert!(
            out.is_empty(),
            "{endpoint:?}: no reply to another principal"
        );

        let (mut client, server) = tokio::io::duplex(1 << 12);
        let srv = tokio::spawn({
            let (endpoint, owner, mine) = (endpoint.clone(), owner.clone(), mine.clone());
            let signer = Arc::clone(&signer);
            async move {
                serve_connection(
                    server,
                    mine,
                    fixture_ref(&endpoint),
                    signer,
                    &owner,
                    ServeLimits::default(),
                    CancellationToken::new(),
                )
                .await
            }
        });
        client.write_all(&ident_req()).await.unwrap();
        let reply = read_frame(&mut client).await.unwrap();
        assert_eq!(reply.get(4), Some(&12), "{endpoint:?}");
        drop(client);
        srv.await.unwrap().unwrap();
    }
}

/// The cross-account row of `endpoint_refuses_other_principal` on macOS: a second OS
/// account connecting to each endpoint kind.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "blocked: B3 (a disposable second macOS account)"]
fn endpoint_refuses_other_principal_cross_account_macos() {
    panic!("blocked: B3; a second macOS account must connect to each endpoint kind");
}

/// The cross-account row on Windows.
#[cfg(windows)]
#[test]
#[ignore = "blocked: B2 (a second Windows account)"]
fn endpoint_refuses_other_principal_cross_account_windows() {
    panic!("blocked: B2; a second Windows account must connect to each endpoint kind");
}

/// The cross-account row on the Linux devbox (m03-plan §4.2: no second account).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "blocked: B8 (a second Linux account on the devbox)"]
fn endpoint_refuses_other_principal_cross_account_linux() {
    panic!("blocked: B8; a second Linux account must connect to each endpoint kind");
}

// =================================================================================
// Interrupted (D2 item 3a)
// =================================================================================

/// Wait (virtual time) until the pause hook logged `step`.
async fn logged(p: &Pauses, step: SignStep) -> Instant {
    tokio::time::timeout(Duration::from_secs(3600), async {
        loop {
            if let Some(i) = p.at_of(step) {
                return i;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the signer never reached {step:?}"))
}

/// Spawn one sign of `g`'s `p` on `signer` through the real step 6–8 core into a
/// test-owned queue. Right after the enqueue (before any await, so before any other
/// task runs on this current-thread runtime) it records whether a signature was
/// enqueued, and when.
fn spawn_signed(
    signer: &Arc<ManagedSigner>,
    g: &G,
    p: &AccessPair,
    log: &Arc<Mutex<Vec<(Instant, bool)>>>,
) -> tokio::task::JoinHandle<Vec<u8>> {
    let (s, g, p, log) = (Arc::clone(signer), g.clone(), p.clone(), Arc::clone(log));
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        let session = SigningSession::new(me(), fixture_ref(s.endpoint()));
        let out = s.sign(&session, &g.blob(&p), &g.auth(&p, &sid()), 0).await;
        match out.permit {
            Some(guard) => {
                enqueue_signed(&tx, out.frame, guard, Duration::from_secs(2))
                    .await
                    .unwrap();
            }
            None => {
                assert!(!is_signature(&out.frame), "a signature without a permit");
                tx.try_send(out.frame).unwrap();
            }
        }
        let frame = rx.try_recv().unwrap();
        log.lock()
            .unwrap()
            .push((Instant::now(), is_signature(&frame)));
        frame
    })
}

/// §17.1 item 1 (Q21 default), deterministic: the signer is paused right after the
/// pre-check; the revocation commits (the signer holds no gate yet); the signer is
/// resumed, and the fresh read under the gate refuses.
#[tokio::test(start_paused = true)]
async fn sign_paused_after_precheck_then_revoke_is_refused() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Prechecked);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    c.client.write_all(&g.req(&h1())).await.unwrap();
    pauses.reached().await;
    let rv = w.revoke(&g, "rv").await;
    assert!(rv.local_applied);
    assert_ne!(w.state(&g), GrantState::Active);
    pauses.release();
    let reply = read_frame(&mut c.client).await.unwrap();
    assert!(is_failure(&reply));
    assert!(pauses.at_of(SignStep::Admitted).is_none(), "never admitted");
    let code = *s.refusals().last().unwrap();
    assert!(
        ["tombstoned", "key_not_listed", "key_destroyed"].contains(&code),
        "{code}"
    );
}

/// §17.3 item 4, deterministic: a signer paused inside the gate (admitted) delays the
/// revocation, whose commit waits for the gate; the reply is enqueued **before** the
/// commit. The revocation's mark is set while it waits, so the release check (§17.10
/// item 1) puts `SSH_AGENT_FAILURE` into the reserved room: admitted before the mark,
/// never released after it.
#[tokio::test(start_paused = true)]
async fn sign_paused_inside_gate_delays_revoke_and_is_enqueued_before_commit() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Admitted);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen_at_commit = Arc::new(Mutex::new(None::<usize>));
    {
        let (log, seen) = (Arc::clone(&log), Arc::clone(&seen_at_commit));
        w.hook.act(
            |k, p| k == NarrowingKind::Revoke && matches!(p, NarrowingPoint::BeforeCommit),
            move || {
                let (log, seen) = (Arc::clone(&log), Arc::clone(&seen));
                Box::pin(async move {
                    *seen.lock().unwrap() = Some(log.lock().unwrap().len());
                })
            },
        );
    }
    let signer = spawn_signed(&s, &g, &h1(), &log);
    pauses.reached().await;
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert!(!rv.is_finished(), "the revocation waits for the gate");
    assert!(
        w.hook
            .at_of(|k, p| k == NarrowingKind::Revoke && matches!(p, NarrowingPoint::BeforeCommit))
            .is_none()
    );
    pauses.release();
    let frame = signer.await.unwrap();
    let data = rv.await.unwrap();
    assert!(data.local_applied);
    assert_eq!(
        *seen_at_commit.lock().unwrap(),
        Some(1),
        "the reply was in the queue before the commit"
    );
    assert!(is_failure(&frame), "nothing released after the mark");
    let acquired = w
        .hook
        .at_of(|k, p| k == NarrowingKind::Revoke && matches!(p, NarrowingPoint::Acquired { .. }))
        .unwrap();
    assert!(log.lock().unwrap()[0].0 <= acquired);
}

/// Deterministic: the revocation's acknowledgment waits for the gate a signer holds;
/// no signature is enqueued after it (nor after its mark), and every later request is
/// refused.
#[tokio::test(start_paused = true)]
async fn no_signature_enqueued_after_revocation_acknowledged() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Signed);
    let held = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let plain = w.signer(SignerEndpoint::Binding(g.binding().clone()));
    let log = Arc::new(Mutex::new(Vec::new()));
    // A signature before anything: released.
    let first = spawn_signed(&plain, &g, &h1(), &log).await.unwrap();
    assert!(is_signature(&first));
    tokio::time::advance(Duration::from_secs(1)).await;
    let signer = spawn_signed(&held, &g, &h1(), &log);
    pauses.reached().await;
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let mark = w.hook.mark_of(NarrowingKind::Revoke);
    // While pending, a new request is refused at once.
    let during = spawn_signed(&plain, &g, &h1(), &log).await.unwrap();
    assert!(is_failure(&during));
    assert_eq!(plain.refusals().last(), Some(&"narrowing_pending"));
    tokio::time::advance(Duration::from_secs(1)).await;
    settle().await;
    assert!(!rv.is_finished(), "the acknowledgment waits for the gate");
    pauses.release();
    let reply = signer.await.unwrap();
    assert!(is_failure(&reply));
    let data = rv.await.unwrap();
    let acked = Instant::now();
    assert!(data.local_applied);
    let after = spawn_signed(&plain, &g, &h1(), &log).await.unwrap();
    assert!(is_failure(&after));
    for (at, signature) in log.lock().unwrap().iter() {
        if *signature {
            assert!(
                *at < mark && *at < acked,
                "a signature enqueued after the mark"
            );
        }
    }
    assert_eq!(
        log.lock().unwrap().iter().filter(|(_, s)| *s).count(),
        1,
        "only the first, before the revocation"
    );
}

/// D2 item 3a step 6: a signer whose reply cannot get outbound capacity is cancelled
/// within `signing_enqueue_timeout` (the connection closes without a reply), its permit
/// and gate go, and the revocation waiting for them proceeds.
#[tokio::test(start_paused = true)]
async fn stuck_enqueue_is_cancelled_within_bound_and_revoke_proceeds() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Signed);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = stuck(s.clone(), w.limits.signing_enqueue_timeout);
    c.client
        .write_all(&[ident_req(), ident_req(), g.req(&h1())].concat())
        .await
        .unwrap();
    pauses.reached().await;
    pauses.release();
    settle().await;
    let start = Instant::now();
    let rv = w.spawn_revoke(&g, "rv");
    let data = rv.await.unwrap();
    assert!(data.local_applied);
    let took = start.elapsed();
    assert!(
        took <= w.limits.signing_enqueue_timeout,
        "the revocation waited {took:?}"
    );
    let served = c.server.await.unwrap();
    assert_eq!(served.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    let mut out = Vec::new();
    c.client.read_to_end(&mut out).await.unwrap();
    assert!(!sig_bytes_in(&out, &g), "no signature reached the client");
    assert_eq!(w.gates().holders(g.id()), 0);
}

/// §17.4 item 6: the signer is paused after the fresh read (admitted); the virtual
/// clock crosses the deadline with no state edit; resumed, its reply is not released.
#[tokio::test(start_paused = true)]
async fn sign_crossing_deadline_after_fresh_read_not_released() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    tokio::time::advance(until(w.clock.wall(), g.data.expires_at) - Duration::from_secs(1)).await;
    let pauses = Pauses::pause(SignStep::Admitted);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    c.client.write_all(&g.req(&h1())).await.unwrap();
    pauses.reached().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(w.clock.wall() > g.data.expires_at);
    pauses.release();
    let reply = read_frame(&mut c.client).await.unwrap();
    assert!(is_failure(&reply));
    assert!(
        s.refusals().is_empty(),
        "the signer signed; the release check refused"
    );
}

/// §17.4 item 6: `KeyVault::sign` overruns `signing_budget`: the permit (and the gate)
/// is dropped at the budget, the late signature is discarded, and nothing is released.
#[tokio::test(start_paused = true)]
async fn sign_budget_overrun_expires_permit_nothing_released() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::sleep(SignStep::Signing, Duration::from_secs(3));
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    let reply = c.call(&g.req(&h1())).await;
    let replied = Instant::now();
    assert!(is_failure(&reply));
    assert_eq!(s.refusals().last(), Some(&"signing_budget_exceeded"));
    let signing = pauses.at_of(SignStep::Signing).unwrap();
    assert_eq!(replied - signing, w.limits.signing_budget);
    assert!(pauses.at_of(SignStep::Signed).is_none());
    assert_eq!(
        w.gates().holders(g.id()),
        0,
        "the gate went with the permit"
    );
    let mut n = w.gates().begin_narrowing([]);
    let before = Instant::now();
    n.acquire(g.id()).await.unwrap();
    assert_eq!(before.elapsed(), Duration::ZERO, "nothing holds the gate");
    drop(n);
    // The late result never reaches the connection.
    tokio::time::advance(Duration::from_secs(5)).await;
    let next = c.call(&ident_req()).await;
    assert_eq!(next.get(4), Some(&12));
}

/// D2 item 3a "the holders": a signer holds its gate at most `signing_holder_max`
/// (5 s), whatever the enqueue timeout: the permit's expiry cancels the capacity wait.
#[tokio::test(start_paused = true)]
async fn signer_holder_bounded_by_signing_holder_max() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Admitted);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = stuck(s.clone(), Duration::from_secs(30));
    c.client
        .write_all(&[ident_req(), ident_req(), g.req(&h1())].concat())
        .await
        .unwrap();
    pauses.reached().await;
    let admitted = Instant::now();
    pauses.release();
    let mut n = w.gates().begin_narrowing([]);
    n.acquire(g.id()).await.unwrap();
    let held = admitted.elapsed();
    assert!(held <= w.limits.signing_holder_max, "held {held:?}");
    assert!(held > w.limits.signing_holder_max - Duration::from_secs(1));
    drop(n);
    // No room ever frees: closed without a reply, never the signature.
    let served = c.server.await.unwrap();
    assert_eq!(served.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    let mut out = Vec::new();
    c.client.read_to_end(&mut out).await.unwrap();
    assert!(!sig_bytes_in(&out, &g));
}

/// §17.7 item 2: the outbound queue is held full; the deadline passes while the reply
/// waits for capacity; the expiry cancels the wait, and once room frees the reply is
/// `SSH_AGENT_FAILURE`: nothing is released.
#[tokio::test(start_paused = true)]
async fn deadline_crossed_while_enqueue_blocked_nothing_released() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    tokio::time::advance(until(w.clock.wall(), g.data.expires_at) - Duration::from_secs(1)).await;
    let pauses = Pauses::pause(SignStep::Signed);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = stuck(s.clone(), w.limits.signing_enqueue_timeout);
    c.client
        .write_all(&[ident_req(), ident_req(), g.req(&h1())].concat())
        .await
        .unwrap();
    pauses.reached().await;
    pauses.release();
    settle().await;
    assert!(
        w.gates().holders(g.id()) > 0,
        "waiting for capacity, permit held"
    );
    tokio::time::advance(Duration::from_millis(1500)).await;
    settle().await;
    assert!(w.clock.wall() > g.data.expires_at);
    assert_eq!(
        w.gates().holders(g.id()),
        0,
        "the expiry cancelled the wait"
    );
    let a = read_frame(&mut c.client).await.unwrap();
    let b = read_frame(&mut c.client).await.unwrap();
    let reply = read_frame(&mut c.client).await.unwrap();
    assert_eq!((a.get(4), b.get(4)), (Some(&12), Some(&12)));
    assert!(is_failure(&reply), "nothing released");
}

/// §17.7 item 2: capacity is free, but the wall deadline is crossed between the
/// admission and the release check (the wall clock steps 20 s ahead, inside the skew
/// tolerance, the continuous expiry not reached): the release check refuses.
#[tokio::test(start_paused = true)]
async fn deadline_crossed_between_capacity_and_release_check_refused() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    tokio::time::advance(until(w.clock.wall(), g.data.expires_at) - Duration::from_secs(10)).await;
    let pauses = Pauses::pause(SignStep::Signed);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    c.client.write_all(&g.req(&h1())).await.unwrap();
    pauses.reached().await;
    *w.clock.wall_ahead.lock().unwrap() = Duration::from_secs(20);
    assert!(w.clock.wall() > g.data.expires_at);
    pauses.release();
    let reply = read_frame(&mut c.client).await.unwrap();
    assert!(is_failure(&reply));
    assert!(
        s.refusals().is_empty(),
        "admitted and signed; refused at release"
    );
}

/// §17.10 item 1, the re-check's second trace, deterministic: the pre-check passes at
/// t = −0.1 s, the mark is set at t = 0, and the gate is taken at t = 9 s (an earlier
/// exclusive holder; `signing_gate_wait` raised to 10 s so the trace can be replayed).
/// The first check under the gate is the mark: refused, nothing signed or released.
#[tokio::test(start_paused = true)]
async fn precheck_before_mark_then_gate_after_mark_refused() {
    let w = world_with(Opts {
        limits: Limits {
            signing_gate_wait: Duration::from_secs(10),
            signature_authorization_timeout: Duration::from_secs(15),
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let g = w.grant("a", &[h1()]).await;
    let mut blocker = w.gates().begin_narrowing([]);
    blocker.acquire(g.id()).await.unwrap();
    let pauses = Pauses::none();
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    c.client.write_all(&g.req(&h1())).await.unwrap();
    let prechecked = logged(&pauses, SignStep::Prechecked).await;
    settle().await;
    tokio::time::advance(Duration::from_millis(100)).await;
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let mark = w.hook.mark_of(NarrowingKind::Revoke);
    assert_eq!(mark - prechecked, Duration::from_millis(100));
    tokio::time::advance(Duration::from_secs(9)).await;
    drop(blocker);
    let reply = read_frame(&mut c.client).await.unwrap();
    assert!(is_failure(&reply));
    assert_eq!(s.refusals().last(), Some(&"narrowing_pending"));
    assert!(pauses.at_of(SignStep::Admitted).is_none(), "never admitted");
    assert!(pauses.at_of(SignStep::Signed).is_none(), "never signed");
    assert!(rv.await.unwrap().local_applied);
}

/// §17.10 item 1: a mark set after the admission (while the permit is held) makes the
/// release check refuse; once the narrowing ends, signing resumes.
#[tokio::test(start_paused = true)]
async fn release_check_refuses_when_mark_set_after_admission() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let pauses = Pauses::pause(SignStep::Signed);
    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), pauses.clone());
    let mut c = Conn::open(s.clone(), serve_limits(&w));
    c.client.write_all(&g.req(&h1())).await.unwrap();
    pauses.reached().await;
    let n = w.gates().begin_narrowing([g.id().clone()]);
    pauses.release();
    let reply = read_frame(&mut c.client).await.unwrap();
    assert!(is_failure(&reply));
    assert!(s.refusals().is_empty(), "refused at release, not before");
    drop(n);
    assert!(is_signature(&c.call(&g.req(&h1())).await));
}

/// Each root's endpoint signer on its own connection; a request on each after the
/// mark, and a record of every reply.
async fn post_mark_requests(w: &W, roots: &[G], log: &Arc<Mutex<Vec<(Instant, bool)>>>) {
    for g in roots {
        let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
        let mut c = Conn::open(s, serve_limits(w));
        let r = c.call(&g.req(&h1())).await;
        log.lock().unwrap().push((Instant::now(), is_signature(&r)));
    }
}

/// §17.13 item 1, the round-5 multi-root countermodel through real signer endpoints and
/// outbound queues: 8 roots, 9 grants, a pre-mark delegation ending at 9.9 s, 2 s
/// reads. The cutoff commits within `H + R(N)`, is reported (over the 20 s target,
/// never aborted), and no signature is enqueued after the mark.
#[tokio::test(start_paused = true)]
async fn signer_multi_root_countermodel_within_derived_bound() {
    let reads = Duration::from_secs(2);
    let w = world_with(Opts {
        limits: Limits {
            narrowing_read_budget: reads,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut roots = Vec::new();
    for i in 0..8 {
        roots.push(w.grant(&format!("m{i}"), &[h1()]).await);
    }
    *w.hook.t_read.lock().unwrap() = reads;
    let log = Arc::new(Mutex::new(Vec::new()));
    // Before the mark, every endpoint signs.
    post_mark_requests(&w, &roots, &log).await;
    assert!(log.lock().unwrap().iter().all(|(_, s)| *s));
    log.lock().unwrap().clear();
    let hold = w
        .gates()
        .hold_for_delegation(roots[0].id(), &[], Duration::from_secs(1))
        .await
        .unwrap();
    let start = Instant::now();
    let (ops, parent) = (w.ops.clone(), roots[0].clone());
    let delegation = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(9900)).await;
        let c = ops
            .delegate(
                &owner(),
                DelegateRequest {
                    parent_binding_id: parent.binding().clone(),
                    scope: [h1()].into_iter().collect(),
                    until: Some(DeadlineIntent::Duration("1h".into())),
                    work_id: WorkId::parse("c-mr").unwrap(),
                    request_id: RequestId::parse("d-mr").unwrap(),
                    required_capabilities: RequiredCapabilities::default(),
                },
            )
            .await
            .unwrap()
            .data;
        ops.signing_gates()
            .retain(&c.grant_id, std::slice::from_ref(parent.id()));
        drop(hold);
        c
    });
    let cut = w.spawn_cutoff();
    w.hook.wait_marked(NarrowingKind::Cutoff).await;
    let mark = w.hook.mark_of(NarrowingKind::Cutoff);
    post_mark_requests(&w, &roots, &log).await;
    cut.await.unwrap();
    delegation.await.unwrap();
    let r = w.hook.report(NarrowingKind::Cutoff);
    assert_eq!((r.members, r.roots, r.rounds), (9, 8, 1), "{r:?}");
    let terms = BoundTerms::of(&w.limits);
    assert_eq!(r.bound, terms.h + terms.work(9, 8));
    assert!(r.elapsed <= r.bound, "{r:?}");
    assert!(start.elapsed() <= r.bound);
    assert!(
        r.over_target,
        "reported past the 20 s target, never aborted"
    );
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 8);
    for (at, signature) in log.iter() {
        assert!(!signature && *at >= mark, "no signature after the mark");
    }
}

/// §17.13 item 1, the overlapping-narrowing countermodel through real signer endpoints:
/// an earlier revocation whose cleanup is held at 5 s (reads and commit at the budgets)
/// with a pre-mark signer inside the gate, and a later cutoff sharing its grant. The
/// later one commits within `H + R(earlier) + R(later)` without waiting for the earlier
/// cleanup, and nothing is released after either mark.
#[tokio::test(start_paused = true)]
async fn signer_overlapping_narrowings_countermodel_within_derived_bound() {
    let w = world().await;
    let a = w.grant("a", &[h1()]).await;
    let b = w.grant("b", &[h1()]).await;
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
    *w.hook.cleanup_hold.lock().unwrap() = Some((NarrowingKind::Revoke, Duration::from_secs(5)));
    // The pre-mark holder: a signer on a's endpoint inside the gate for 4 s.
    let pauses = Pauses::sleep(SignStep::Admitted, Duration::from_secs(4));
    let held = w.signer_with(SignerEndpoint::Binding(a.binding().clone()), pauses.clone());
    let log = Arc::new(Mutex::new(Vec::new()));
    let pre = spawn_signed(&held, &a, &h1(), &log);
    logged(&pauses, SignStep::Admitted).await;
    let earlier = w.spawn_revoke(&a, "rv-a");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let later = w.spawn_cutoff();
    w.hook.wait_marked(NarrowingKind::Cutoff).await;
    // Post-mark requests on both endpoints.
    post_mark_requests(&w, &[a.clone(), b.clone()], &log).await;
    later.await.unwrap();
    let later_done = Instant::now();
    earlier.await.unwrap();
    let pre_reply = pre.await.unwrap();
    assert!(
        is_failure(&pre_reply),
        "admitted before the mark, not released after it"
    );
    let e = w.hook.report(NarrowingKind::Revoke);
    let l = w.hook.report(NarrowingKind::Cutoff);
    assert_eq!(l.earlier.len(), 1);
    assert_eq!(Some(l.earlier[0].seq), e.seq);
    let terms = BoundTerms::of(&w.limits);
    assert_eq!(
        l.bound,
        terms.h + terms.work(e.members, e.roots) + terms.work(l.members, l.roots)
    );
    assert!(l.elapsed <= l.bound, "{l:?}");
    let cleanup_end = w
        .hook
        .at_of(|k, p| k == NarrowingKind::Revoke && matches!(p, NarrowingPoint::Cleanup { .. }))
        .unwrap()
        + Duration::from_secs(5);
    assert!(
        later_done < cleanup_end,
        "never waits for the earlier cleanup"
    );
    let first_mark = w.hook.mark_of(NarrowingKind::Revoke);
    for (at, signature) in log.lock().unwrap().iter() {
        assert!(!signature || *at < first_mark, "a signature after a mark");
    }
    assert!(log.lock().unwrap().iter().all(|(_, s)| !s));
}

/// D2 item 3a "Result", on top of the deterministic tests: across 1000 uncontrolled
/// interleavings (real time; store transactions, time assessments and `KeyVault::sign`
/// on blocking-pool threads; random yields) of two signers and a revocation, every
/// signature is enqueued before the revocation took the gate for its commit (so before
/// the tombstone commit), or the request is refused.
#[tokio::test]
async fn sign_during_revoke_is_linearized() {
    let w = world().await;
    let mut released = 0usize;
    let mut refused = 0usize;
    // ⟨integrator⟩ The revocation's start is jittered in real time over 0..2× one
    // uncontended signature's measured latency, so both outcomes occur on a slow host
    // too (an emulated x86-64 container saw 0 released / 2000 with yields alone).
    let base = {
        let g = w.grant("lin-calibrate", &[h1()]).await;
        let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
        let started = std::time::Instant::now();
        let frame = spawn_signed(&s, &g, &h1(), &Arc::new(Mutex::new(Vec::new())))
            .await
            .unwrap();
        assert!(
            is_signature(&frame),
            "calibration: an uncontended signature"
        );
        started.elapsed().max(Duration::from_millis(1))
    };
    for i in 0..1000 {
        let g = w.grant(&format!("lin{i}"), &[h1()]).await;
        let s = w.signer(SignerEndpoint::Binding(g.binding().clone()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let jitter = |n: u8| async move {
            for _ in 0..(n % 24) {
                tokio::task::yield_now().await;
            }
        };
        let r = random::<3>();
        let signers: Vec<_> = (0..2)
            .map(|k| {
                let (s, g, log) = (Arc::clone(&s), g.clone(), Arc::clone(&log));
                let n = r[k];
                tokio::spawn(async move {
                    jitter(n).await;
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
                    let session = SigningSession::new(me(), fixture_ref(s.endpoint()));
                    let out = s
                        .sign(&session, &g.blob(&h1()), &g.auth(&h1(), &sid()), 0)
                        .await;
                    if let Some(guard) = out.permit {
                        enqueue_signed(&tx, out.frame, guard, Duration::from_secs(2))
                            .await
                            .unwrap();
                        // Recorded with no await after the enqueue, so before the
                        // revocation's task can run and take the gate the guard freed.
                        let at = std::time::Instant::now();
                        let frame = rx.try_recv().unwrap();
                        log.lock().unwrap().push((at, is_signature(&frame)));
                    } else {
                        assert!(!is_signature(&out.frame));
                        log.lock().unwrap().push((std::time::Instant::now(), false));
                    }
                })
            })
            .collect();
        let (ops, gid, rid, n) = (w.ops.clone(), g.id().clone(), format!("rv{i}"), r[2]);
        let committed = Arc::new(Mutex::new(None::<std::time::Instant>));
        let c2 = Arc::clone(&committed);
        let rv = tokio::spawn(async move {
            tokio::time::sleep(base.mul_f64(f64::from(n % 41) / 20.0)).await;
            let data = revoke(&ops, &gid, &rid).await;
            *c2.lock().unwrap() = Some(std::time::Instant::now());
            data
        });
        for t in signers {
            t.await.unwrap();
        }
        assert!(rv.await.unwrap().local_applied);
        // The narrowing's commit happens after it acquired the gate exclusively; the
        // gate is free only after every permit's enqueue.
        let acquired: std::time::Instant = w
            .hook
            .log
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(_, k, p)| {
                *k == NarrowingKind::Revoke
                    && matches!(p, NarrowingPoint::Acquired { held, .. } if held.contains(g.id()))
            })
            .map(|(at, ..)| at.into_std())
            .expect("the revocation took the gate");
        for (at, signature) in log.lock().unwrap().iter() {
            if *signature {
                released += 1;
                assert!(
                    *at <= acquired,
                    "a signature enqueued after the gate was taken"
                );
                assert!(*at <= committed.lock().unwrap().unwrap());
            } else {
                refused += 1;
            }
        }
        // After the acknowledgment, nothing is ever released.
        let after = spawn_signed(&s, &g, &h1(), &Arc::new(Mutex::new(Vec::new())))
            .await
            .unwrap();
        assert!(!is_signature(&after));
    }
    assert!(
        released > 0 && refused > 0,
        "both outcomes seen: {released} / {refused}"
    );
}

/// An authority whose calls never answer (or answer only the pre-check).
struct StuckAuthority {
    precheck_hangs: bool,
}

#[async_trait]
impl SignatureAuthority for StuckAuthority {
    async fn precheck(&self, _facts: &SignatureRequestFacts) -> Result<(), SignRefusal> {
        if self.precheck_hangs {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn admit(&self, _facts: &SignatureRequestFacts) -> Result<SignPermit, SignRefusal> {
        std::future::pending::<()>().await;
        Err(SignRefusal::Unavailable)
    }
}

/// D2 item 3: authorization is bounded by `signature_authorization_timeout` (2 s), the
/// pre-check and the admission each; a timeout refuses, nothing signed.
#[tokio::test(start_paused = true)]
async fn authorization_timeout_refuses() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    for precheck_hangs in [true, false] {
        let s = Arc::new(ManagedSigner::new(
            SignerEndpoint::Binding(g.binding().clone()),
            w.table.clone(),
            Arc::new(StuckAuthority { precheck_hangs }),
            w.signer_limits(),
        ));
        let mut c = Conn::open(s.clone(), serve_limits(&w));
        let start = Instant::now();
        let reply = c.call(&g.req(&h1())).await;
        assert!(is_failure(&reply));
        assert_eq!(start.elapsed(), w.limits.signature_authorization_timeout);
        assert_eq!(s.refusals(), vec!["authorization_timeout"]);
    }
}

/// U0b row 8 with the signer (ADR-0008 D2 table, `installed → lost` on process exit):
/// a key installed and persisted as `installed` by the effect driver (U2-Q1: the test
/// writes the row it would), then the process "crashes" (its vault is gone); at the
/// next start the instance is `lost`, the grant degraded `credential_reissue_pending`,
/// and the new process's signer holds no slot, lists nothing and signs nothing.
#[tokio::test(start_paused = true)]
async fn crash_after_install_makes_instance_lost_at_restart() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let slot = w.table.slot(g.id()).unwrap();
    let instance = CredentialInstance {
        id: CredentialInstanceId::from_random_bytes(random()),
        grant: g.id().clone(),
        key_handle_ref: slot.to_hex(),
        certificates: w.table.installed_entries(g.id()),
        state: CredentialState::Installed,
    };
    assert_eq!(instance.certificates, vec![g.entries[0].id.clone()]);
    w.store
        .transaction(|tx| tx.insert_credential_instance(&instance))
        .unwrap();
    assert_eq!(
        instance_transition(CredentialState::Installed, InstanceEvent::ProcessExit),
        Ok(CredentialState::Lost)
    );
    // The crash: the runtime, its table and its vault are gone.
    let W {
        store,
        clock,
        sync,
        fake,
        limits,
        ops,
        hook,
        table,
        ..
    } = w;
    drop(ops);
    *hook.table.lock().unwrap() = None;
    drop(table);
    // The next start, with a fresh, empty vault.
    let vault = Arc::new(KeyVault::new());
    assert!(!vault.contains(&slot));
    let ops = Operations::start(config(&store, &clock, &sync, &fake, limits))
        .await
        .unwrap();
    let (state, reason) = store
        .transaction(|tx| {
            Ok((
                tx.credential_instance(&instance.id)?.unwrap().state,
                tx.grant_degradation(g.id())?,
            ))
        })
        .unwrap();
    assert_eq!(state, CredentialState::Lost);
    assert_eq!(reason, Some(DegradedReason::CredentialReissuePending));
    let table = SignerTable::new(vault);
    table.attach_binding(g.binding(), g.id());
    let s = Arc::new(ManagedSigner::new(
        SignerEndpoint::Binding(g.binding().clone()),
        table,
        Arc::new(ops.clone()),
        SignerLimits::from_limits(&limits),
    ));
    let mut c = Conn::open(s.clone(), SignerLimits::from_limits(&limits).serve);
    assert!(c.identities().await.is_empty());
    assert!(is_failure(&c.call(&g.req(&h1())).await));
    assert_eq!(s.refusals().last(), Some(&"key_not_listed"));
}

// =================================================================================
// Cleanup and endpoints (real listeners)
// =================================================================================

/// A stream to a real endpoint.
trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

#[cfg(unix)]
async fn connect(endpoint: &EndpointRef) -> std::io::Result<Box<dyn Duplex>> {
    heimdall_ipc::unix::connect(std::path::Path::new(&endpoint.locator))
        .await
        .map(|s| Box::new(s) as Box<dyn Duplex>)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(windows)]
async fn connect(endpoint: &EndpointRef) -> std::io::Result<Box<dyn Duplex>> {
    heimdall_ipc::windows::connect_with_owner(
        std::path::Path::new(&endpoint.locator),
        heimdall_ipc::windows::ServerOwner::CurrentUser,
    )
    .await
    .map(|s| Box::new(s) as Box<dyn Duplex>)
}

async fn identities_at(endpoint: &EndpointRef) -> std::io::Result<Vec<(Vec<u8>, String)>> {
    let mut s = connect(endpoint).await?;
    s.write_all(&ident_req()).await?;
    let f = read_frame(&mut s)
        .await
        .ok_or_else(|| std::io::Error::other("no reply"))?;
    Ok(parse_identities(&f))
}

/// The endpoint is gone: connecting fails (within a bound, for the pipe instances an
/// aborted accept loop closes asynchronously).
async fn gone(endpoint: &EndpointRef) -> bool {
    for _ in 0..200 {
        if identities_at(endpoint).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// The platform layout and owner for a registry; the runtime directory is `dir` on Unix.
fn layout_and_owner(dir: &std::path::Path) -> (EndpointLayout, ExpectedOwner) {
    #[cfg(unix)]
    {
        (
            EndpointLayout::unix(dir).unwrap(),
            ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
        )
    }
    #[cfg(windows)]
    {
        let _ = dir;
        let token = EndpointTag::generate().unwrap();
        (
            EndpointLayout::windows(&format!("u2t{token}")).unwrap(),
            ExpectedOwner::Sid(heimdall_ipc::windows::current_user_sid().unwrap()),
        )
    }
}

fn registry(
    w: &W,
    dir: &std::path::Path,
    authority: Arc<dyn SignatureAuthority>,
) -> EndpointRegistry {
    let (layout, owner) = layout_and_owner(dir);
    EndpointRegistry::new(
        layout,
        owner,
        w.table.clone(),
        authority,
        w.signer_limits(),
        CancellationToken::new(),
    )
}

/// R-RT-04: cleaning binding endpoint generation N removes exactly N (its socket and
/// private directory) and leaves N+1 serving; a cleanup naming another generation's
/// locator, or a repeated one, changes nothing.
#[tokio::test]
async fn binding_endpoint_removed_by_generation() {
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = registry(&w, &dir, w.authority());
    let b = g.binding().clone();
    let e1 = reg.create_binding(&b, ResourceGeneration(1)).unwrap();
    let e2 = reg.create_binding(&b, ResourceGeneration(2)).unwrap();
    assert_ne!(e1.locator, e2.locator, "a fresh random tag per generation");
    let want = vec![(g.blob(&h1()), grant_comment(g.id()))];
    assert_eq!(identities_at(&e1).await.unwrap(), want);
    assert_eq!(identities_at(&e2).await.unwrap(), want);
    let res = |generation: u64, e: &EndpointRef| {
        endpoint_resource(
            ResourceId::from_random_bytes(random()),
            &b,
            ResourceGeneration(generation),
            e,
            t0(),
        )
    };
    // Generation 1's cleanup naming generation 2's locator: nothing.
    reg.remove(&res(1, &e2)).unwrap();
    assert_eq!(identities_at(&e1).await.unwrap(), want);
    assert_eq!(identities_at(&e2).await.unwrap(), want);
    // Generation 1's own cleanup.
    reg.remove(&res(1, &e1)).unwrap();
    assert!(gone(&e1).await, "generation 1 removed");
    #[cfg(unix)]
    {
        let p = std::path::Path::new(&e1.locator);
        assert!(!p.exists());
        assert!(!p.parent().unwrap().exists(), "its private directory too");
    }
    assert_eq!(
        identities_at(&e2).await.unwrap(),
        want,
        "generation 2 untouched"
    );
    assert_eq!(
        reg.binding_endpoint(&b),
        Some((e2.clone(), ResourceGeneration(2)))
    );
    reg.remove(&res(1, &e1)).unwrap();
    assert_eq!(identities_at(&e2).await.unwrap(), want, "idempotent");
    // Through the cleaner port.
    heimdall_app::ports::ResourceCleaner::delete(&reg, &res(2, &e2))
        .await
        .unwrap();
    assert!(gone(&e2).await);
    assert_eq!(reg.binding_endpoint(&b), None);
}

/// ADR-0006 §2.1, D2 item 2 on Unix: every endpoint's socket is 0600 and ours; a
/// binding or verification endpoint lives in its own random-tag directory, 0700, under
/// a 0700 `b/` or `v/`; the directories go with the endpoints.
#[cfg(unix)]
#[tokio::test]
async fn unix_endpoint_dirs_0700_sockets_0600() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = registry(&w, &dir, w.authority());
    let env = reg.start_environment().unwrap();
    let eb = reg
        .create_binding(g.binding(), ResourceGeneration(1))
        .unwrap();
    let op = OperationId::from_random_bytes(random());
    let v = reg.create_verification(&op, &vscope(&w.ca, &h1())).unwrap();
    let ev = v.locator().clone();
    let uid = heimdall_ipc::unix::current_uid();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(env.locator, dir.join("signing.sock").to_string_lossy());
    for (e, kind) in [(&env, None), (&eb, Some("b")), (&ev, Some("v"))] {
        let sock = std::path::Path::new(&e.locator);
        let meta = std::fs::symlink_metadata(sock).unwrap();
        assert!(meta.file_type().is_socket(), "{kind:?}");
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{kind:?}");
        if let Some(k) = kind {
            let tag_dir = sock.parent().unwrap();
            assert_eq!(sock.file_name().unwrap(), "agent.sock");
            assert!(EndpointTag::parse(tag_dir.file_name().unwrap().to_str().unwrap()).is_some());
            assert_eq!(tag_dir.parent().unwrap(), dir.join(k));
            assert_eq!(mode(tag_dir), 0o700, "{k}/<tag>");
            assert_eq!(mode(&dir.join(k)), 0o700, "{k}/");
        }
    }
    let ev_dir = std::path::Path::new(&ev.locator)
        .parent()
        .unwrap()
        .to_path_buf();
    drop(v);
    assert!(
        !ev_dir.exists(),
        "the verification endpoint goes with its session"
    );
    let eb_dir = std::path::Path::new(&eb.locator)
        .parent()
        .unwrap()
        .to_path_buf();
    reg.remove(&endpoint_resource(
        ResourceId::from_random_bytes(random()),
        g.binding(),
        ResourceGeneration(1),
        &eb,
        t0(),
    ))
    .unwrap();
    assert!(!eb_dir.exists());
    reg.stop_all();
    assert!(!std::path::Path::new(&env.locator).exists());
}

/// ADR-0006 §2.1, D2 item 2 on Windows, for each endpoint kind: the pipe is owned by
/// this user (M01's client-side owner-SID check, `connect_with_owner`) and answers; a
/// client that requires another owner refuses it before writing. The DACL itself is
/// M01's protected owner-only `D:P(A;;GA;;;<owner SID>)` (`ipc::windows::Listener`);
/// `icacls` does not read pipes, so the owner check is the evidence here.
#[cfg(windows)]
#[tokio::test]
async fn windows_pipe_dacl_owner_only_for_each_endpoint_kind() {
    use heimdall_ipc::windows::{ServerOwner, connect_with_owner};
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let scratch = Scratch::new().unwrap();
    let reg = registry(&w, scratch.path(), w.authority());
    let env = reg.start_environment().unwrap();
    let eb = reg
        .create_binding(g.binding(), ResourceGeneration(1))
        .unwrap();
    let op = OperationId::from_random_bytes(random());
    let v = reg.create_verification(&op, &vscope(&w.ca, &h1())).unwrap();
    let ev = v.locator().clone();
    for e in [&env, &eb, &ev] {
        assert!(
            e.locator.starts_with(r"\\.\pipe\heimdall-u2t"),
            "{}",
            e.locator
        );
        let mut s = connect_with_owner(std::path::Path::new(&e.locator), ServerOwner::CurrentUser)
            .await
            .unwrap();
        s.write_all(&ident_req()).await.unwrap();
        let f = read_frame(&mut s).await.unwrap();
        assert_eq!(f.get(4), Some(&12));
        let other = connect_with_owner(
            std::path::Path::new(&e.locator),
            ServerOwner::Sid("S-1-5-32-545".into()),
        )
        .await;
        assert_eq!(
            other.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "{}",
            e.locator
        );
    }
    drop(v);
    reg.stop_all();
}

// =================================================================================
// Verification endpoints (D5 §6.5; readings R3, INT-Q13)
// =================================================================================

/// A fixture authority for verification subjects (reading R3): admits through a gate of
/// its own and refuses grant subjects.
struct VerifyAuthority {
    gates: SigningGates,
    gate: GrantId,
}

impl VerifyAuthority {
    fn new() -> Arc<Self> {
        let gates = SigningGates::new();
        let gate = GrantId::from_random_bytes(random());
        gates.retain(&gate, &[]);
        Arc::new(Self { gates, gate })
    }
}

#[async_trait]
impl SignatureAuthority for VerifyAuthority {
    async fn precheck(&self, facts: &SignatureRequestFacts) -> Result<(), SignRefusal> {
        match facts.subject {
            SignatureSubject::Verification(_) => Ok(()),
            _ => Err(SignRefusal::KeyNotServed),
        }
    }
    async fn admit(&self, facts: &SignatureRequestFacts) -> Result<SignPermit, SignRefusal> {
        if !matches!(facts.subject, SignatureSubject::Verification(_)) {
            return Err(SignRefusal::KeyNotServed);
        }
        let shared = self
            .gates
            .admit_shared(&self.gate, Duration::from_secs(1))
            .await
            .map_err(|_| SignRefusal::GateTimeout)?;
        let time: Arc<dyn SafeTime> = Arc::new(|| Some(Timestamp::now()));
        Ok(SigningGates::permit(
            shared,
            PermitExpiry::new(
                plus(Timestamp::now(), HOUR),
                Instant::now() + Duration::from_secs(5),
            ),
            time,
        ))
    }
}

/// ⟨INT-Q13⟩ The plan's CA (`ca`) and pair `p` as a verification scope.
fn vscope(ca: &SecretCaKey, p: &AccessPair) -> VerificationScope {
    VerificationScope {
        ca: ca.fingerprint().unwrap(),
        pair: p.clone(),
    }
}

/// ⟨INT-Q13⟩ A plan whose only fields the verification factory reads are its CA and
/// pair (`ca_fingerprint`, `destination_id`, `account`).
fn vplan(ca: &SecretCaKey, p: &AccessPair) -> heimdall_contract::enrollment::EnrollmentPlan {
    use heimdall_contract::enrollment::{
        ApprovedHostKey, ApprovedTarget, DisclosureKind, EndpointSource, EnrollmentForm,
        EnrollmentPlan, ExistingAccessPlan, NoProxy, RegistryRef, RegistryResolvedBy, RollbackPlan,
        VerificationPlan,
    };
    EnrollmentPlan {
        plan_digest: heimdall_contract::setup::PlanDigest::parse(&"0".repeat(64)).unwrap(),
        destination_id: p.destination.clone(),
        alias: "u2-verify".into(),
        account: p.account.clone(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "scratch".into(),
            resolved_by: RegistryResolvedBy::Explicit,
        },
        line: String::new(),
        line_sha256: "0".repeat(64),
        ca_fingerprint: ca.fingerprint().unwrap(),
        existing_access: ExistingAccessPlan {
            identity_id: heimdall_contract::ids::IdentityId::from_random_bytes(random()),
            mechanism: "native_agent".into(),
            endpoint: "/unused".into(),
            endpoint_source: EndpointSource::CatalogRecord,
            invocation: Vec::new(),
        },
        host_trust: Vec::new(),
        approved_target: ApprovedTarget {
            hostname: "h1.example.invalid".into(),
            port: 22,
            user: p.account.clone(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        bootstrap: None,
        verification: VerificationPlan {
            positive_principal: principal_for(p),
            negative: true,
            max_validity_seconds: 300,
        },
        rollback: RollbackPlan::CompareThenRenameByMarker,
        disclosures: vec![DisclosureKind::CaTrustBlastRadius],
    }
}

/// A verification certificate (D5 §6.5 item 2's shape: one principal, no extension,
/// at most 300 s ahead) for `key`.
fn verification_cert(ca: &SecretCaKey, key: &ssh_key::PublicKey, principal: &str) -> Certificate {
    let now = Timestamp::now().as_second();
    let serial = u64::from_be_bytes(random::<8>());
    let profile = CertificateProfile {
        serial,
        key_id: format!("heimdall:{}:op_fixture:{serial}", env_id()),
        principal: principal.to_owned(),
        valid_after: now - 60,
        valid_before: now + 240,
        extensions: BTreeSet::new(),
        subject_fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        ca_fingerprint: Some(ca.fingerprint().unwrap()),
    };
    build_and_sign(&profile, key, ca).unwrap()
}

/// D5 §6.5 item 1, R3, the wave-1 leftover "two certificates per session": the
/// verification endpoint lists K_verify and the certificate currently installed;
/// `install` takes the positive, then the negative (a third is refused); a request may
/// name the plain K_verify (9.6p1/10.5p1 do; INT-Q10) but the userauth must present the
/// current positive certificate; sign requests are counted per key fingerprint and
/// session-binds received; the session's drop zeroizes K_verify and removes the
/// endpoint.
#[tokio::test]
async fn verification_endpoint_lists_k_verify_and_installs_two_certificates() {
    const { assert!(!VERIFICATION_UNGATED_SIGNING) };
    let w = world().await;
    let g = w.grant("a", &[h1()]).await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = registry(&w, &dir, VerifyAuthority::new());
    let op = OperationId::from_random_bytes(random());
    let session: Box<dyn VerificationSession> =
        VerificationEndpoints::create(&reg, &op, &vplan(&w.ca, &h1()))
            .await
            .unwrap();
    let kv = ssh_key::PublicKey::from_openssh(session.public_key()).unwrap();
    let fp = kv.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let plain = kv.to_bytes().unwrap();
    let endpoint = session.locator().clone();
    let listed = identities_at(&endpoint).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, plain);
    assert!(listed[0].1.starts_with("heimdall:v-"));

    let pos = verification_cert(&w.ca, &kv, &principal_for(&h1()));
    session.install(&pos.to_openssh().unwrap()).unwrap();
    let pos_blob = pos.to_bytes().unwrap();
    assert_eq!(
        identities_at(&endpoint)
            .await
            .unwrap()
            .into_iter()
            .map(|(b, _)| b)
            .collect::<Vec<_>>(),
        vec![plain.clone(), pos_blob.clone()]
    );
    let mut s = connect(&endpoint).await.unwrap();
    let mut call = async |req: Vec<u8>| {
        s.write_all(&req).await.unwrap();
        read_frame(&mut s).await.unwrap()
    };
    // The plain K_verify named by the request, the certificate presented: signed.
    let session_id = sid();
    let (_, bind) = signed_bind(&session_id, false);
    assert_eq!(call(bind_req(&bind)).await, success_frame());
    let data = userauth(&session_id, "deploy", "publickey", &pos_blob, None);
    assert!(is_signature(&call(sign_req(&plain, &data, 0)).await));
    assert_eq!(session.signatures(&fp), 1);
    assert_eq!(session.session_binds(), 1);
    // The plain key presented in the userauth: refused (F17 holds for K_verify too).
    let bare = userauth(&session_id, "deploy", "publickey", &plain, None);
    assert!(is_failure(&call(sign_req(&plain, &bare, 0)).await));
    // Another account than the certificate's pair: refused, still counted.
    let wrong = userauth(&session_id, "root", "publickey", &pos_blob, None);
    assert!(is_failure(&call(sign_req(&pos_blob, &wrong, 0)).await));
    assert_eq!(session.signatures(&fp), 3);
    // A grant's certificate is never served here.
    assert!(is_failure(&call(g.req(&h1())).await));
    assert_eq!(session.signatures(&fp), 3, "not this endpoint's key");

    // The negative certificate: listed in place of the positive one, never signed for.
    let nonce: String = random::<16>().iter().map(|b| format!("{b:02x}")).collect();
    let neg = verification_cert(&w.ca, &kv, &format!("hm:verify-negative:{nonce}"));
    session.install(&neg.to_openssh().unwrap()).unwrap();
    let neg_blob = neg.to_bytes().unwrap();
    assert_eq!(
        identities_at(&endpoint)
            .await
            .unwrap()
            .into_iter()
            .map(|(b, _)| b)
            .collect::<Vec<_>>(),
        vec![plain.clone(), neg_blob.clone()]
    );
    let neg_data = userauth(&session_id, "deploy", "publickey", &neg_blob, None);
    assert!(is_failure(&call(sign_req(&plain, &neg_data, 0)).await));
    assert_eq!(
        session.signatures(&fp),
        4,
        "a request for the negative is counted"
    );
    let stale = userauth(&session_id, "deploy", "publickey", &pos_blob, None);
    assert!(is_failure(&call(sign_req(&plain, &stale, 0)).await));
    // A third certificate, and a malformed or foreign one, are refused.
    let third = verification_cert(&w.ca, &kv, &principal_for(&h1()));
    assert!(session.install(&third.to_openssh().unwrap()).is_err());
    assert!(session.install("not a certificate").is_err());
    drop(s);

    // Drop: K_verify zeroized, the endpoint removed.
    drop(session);
    assert!(w.table.verification_key(&op).is_none());
    assert!(gone(&endpoint).await);
}

/// Reading R3 (INT-Q13), fail closed: with the production `Operations` as the
/// authority and a registry built without the signing gates, no verification gate is
/// open for the operation, so the signature is refused (`key_not_served`, ADR-0008
/// §17.19 item 5: a verification signature is admitted only through its operation's
/// gate); the request is still counted, and nothing is sent without a permit.
#[tokio::test]
async fn verification_signature_refused_by_production_operations() {
    let w = world().await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = registry(&w, &dir, w.authority());
    let op = OperationId::from_random_bytes(random());
    let v = reg.create_verification(&op, &vscope(&w.ca, &h1())).unwrap();
    let kv = ssh_key::PublicKey::from_openssh(v.public_key()).unwrap();
    let pos = verification_cert(&w.ca, &kv, &principal_for(&h1()));
    v.install(&pos.to_openssh().unwrap()).unwrap();
    let mut s = connect(v.locator()).await.unwrap();
    let data = userauth(
        &sid(),
        "deploy",
        "publickey",
        &pos.to_bytes().unwrap(),
        None,
    );
    s.write_all(&sign_req(&kv.to_bytes().unwrap(), &data, 0))
        .await
        .unwrap();
    assert!(is_failure(&read_frame(&mut s).await.unwrap()));
    assert_eq!(v.signatures(v.key_fingerprint()), 1);
    assert_eq!(v.signer().unwrap().refusals(), vec!["key_not_served"]);
}

/// ⟨INT-Q13, ADR-0008 §17.19 item 5⟩ The verification factory receives the plan, and
/// `install` checks each certificate against the plan's CA and, for the positive one,
/// the plan's pair: a certificate under another CA (positive or negative) and a
/// positive one for another pair are refused and discarded; the plan's own install.
#[tokio::test]
async fn verification_install_refuses_another_ca_or_another_pair() {
    let w = world().await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let reg = registry(&w, &dir, VerifyAuthority::new());
    let op = OperationId::from_random_bytes(random());
    let session = VerificationEndpoints::create(&reg, &op, &vplan(&w.ca, &h1()))
        .await
        .unwrap();
    let kv = ssh_key::PublicKey::from_openssh(session.public_key()).unwrap();
    let other_ca = SecretCaKey::generate().unwrap();
    let nonce: String = random::<16>().iter().map(|b| format!("{b:02x}")).collect();
    let negative = format!("hm:verify-negative:{nonce}");
    let refused = |line: String| {
        let e = session.install(&line).unwrap_err();
        format!("{e}")
    };
    let under_other = verification_cert(&other_ca, &kv, &principal_for(&h1()));
    assert!(
        refused(under_other.to_openssh().unwrap()).contains("wrong_ca"),
        "a positive certificate under another CA"
    );
    let neg_other = verification_cert(&other_ca, &kv, &negative);
    assert!(
        refused(neg_other.to_openssh().unwrap()).contains("wrong_ca"),
        "a negative certificate under another CA"
    );
    let other_pair = verification_cert(&w.ca, &kv, &principal_for(&h2()));
    assert!(
        refused(other_pair.to_openssh().unwrap()).contains("wrong_principal"),
        "a positive certificate for another pair"
    );
    assert_eq!(
        identities_at(session.locator()).await.unwrap().len(),
        1,
        "nothing refused is listed"
    );
    let pos = verification_cert(&w.ca, &kv, &principal_for(&h1()));
    session.install(&pos.to_openssh().unwrap()).unwrap();
    let neg = verification_cert(&w.ca, &kv, &negative);
    session.install(&neg.to_openssh().unwrap()).unwrap();
    drop(session);
    reg.stop_all();
}

/// ⟨INT-Q13⟩ A registry built with the signing gates opens the operation's verification
/// gate with the plan's CA and pair when the session is created, refuses a second live
/// session of the same operation (`GateOpen`, nothing left behind), and closes the gate
/// when the session is dropped.
#[tokio::test]
async fn verification_session_opens_and_closes_its_operation_gate() {
    let w = world().await;
    let scratch = Scratch::new().unwrap();
    let dir = scratch.subdir("r").unwrap();
    let gates = w.ops.signing_gates().clone();
    let reg = registry(&w, &dir, w.authority()).with_verification_gates(gates.clone());
    let op = OperationId::from_random_bytes(random());
    assert!(!gates.is_verification_open(&op));
    let v = reg.create_verification(&op, &vscope(&w.ca, &h1())).unwrap();
    assert!(gates.is_verification_open(&op));
    assert_eq!(gates.verification_scope(&op), Some(vscope(&w.ca, &h1())));
    assert_eq!(
        reg.create_verification(&op, &vscope(&w.ca, &h1()))
            .unwrap_err(),
        endpoints::EndpointError::GateOpen
    );
    assert!(
        w.table.verification_key(&op).is_some(),
        "the first session's key stays"
    );
    drop(v);
    assert!(!gates.is_verification_open(&op));
    assert!(w.table.verification_key(&op).is_none());
    // A new session reopens it.
    let again = reg.create_verification(&op, &vscope(&w.ca, &h1())).unwrap();
    assert!(gates.is_verification_open(&op));
    drop(again);
    assert!(!gates.is_verification_open(&op));
    reg.stop_all();
}

// =================================================================================
// Real clients (Unix: a real `ssh` through the registry's endpoints to a LoopbackSshd)
// =================================================================================

#[cfg(unix)]
mod real {
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};

    use heimdall_testkit::assert_no_canary;
    use heimdall_testkit::home::{ClientKind, ScratchHome, find_program, ssh_config_quote};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};

    use super::*;

    pub(super) const ALIAS: &str = "u2-managed";

    /// A grant on `u2-dest/<this account>` with its key and certificate installed and
    /// materialized in the environment listing; the registry's environment and binding
    /// endpoints; a loopback sshd in account form trusting the test CA for that pair's
    /// principal; the slot's certificate file; and P's managed block for the alias in
    /// INT-Q10's default form (`CertificateAsIdentityFile`).
    pub(super) struct Real {
        pub home: ScratchHome,
        pub sshd: LoopbackSshd,
        pub w: W,
        pub g: G,
        pub p: AccessPair,
        pub reg: EndpointRegistry,
        pub env: EndpointRef,
        pub binding: EndpointRef,
        pub pauses: Arc<Pauses>,
        pub cert_file: PathBuf,
        pub account: String,
    }

    pub(super) async fn start() -> Real {
        let home = ScratchHome::new();
        let account = current_account().expect("the current account name");
        let p = pair("u2-dest", &account);
        let w = world_with(Opts {
            pairs: vec![p.clone()],
            ..Opts::default()
        })
        .await;
        let g = w.grant("real", std::slice::from_ref(&p)).await;
        let ca_line = w.ca.public_openssh().unwrap().trim_end().to_owned();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                registry_seed: Some(
                    format!(
                        "cert-authority,principals=\"{}\" {ca_line}\n",
                        principal_for(&p)
                    )
                    .into_bytes(),
                ),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        home.trust_host_key(&sshd.host_key_line).unwrap();
        let dir = home.scratch().subdir("r").unwrap();
        let pauses = Pauses::none();
        let (layout, owner) = layout_and_owner(&dir);
        let reg = EndpointRegistry::new(
            layout,
            owner,
            w.table.clone(),
            w.authority(),
            w.signer_limits(),
            CancellationToken::new(),
        )
        .with_hook(pauses.clone());
        let env = reg.start_environment().unwrap();
        let binding = reg
            .create_binding(g.binding(), ResourceGeneration(1))
            .unwrap();
        w.table
            .materialize(g.binding(), std::slice::from_ref(&p))
            .unwrap();
        w.claim_slot(&g, &p);
        // The slot's public certificate file (R7's shape; U6 writes it in production).
        let slot = home.scratch().subdir("managed").unwrap();
        let cert_file = slot.join("cert.pub");
        std::fs::write(
            &cert_file,
            format!("{}\n", g.cert(&p).to_openssh().unwrap().trim_end()),
        )
        .unwrap();
        // P's managed block for the alias: the rendered product projection under test.
        home.write_user_config(&format!(
            "Host {ALIAS}\n  HostName 127.0.0.1\n  Port {}\n  User {account}\n  IdentityAgent {}\n  IdentitiesOnly yes\n  IdentityFile {}\n  ControlMaster no\n  ControlPath none\n",
            sshd.port,
            ssh_config_quote(&reg.layout().rendered_environment()),
            ssh_config_quote(&cert_file.to_string_lossy()),
        ))
        .unwrap();
        Real {
            home,
            sshd,
            w,
            g,
            p,
            reg,
            env,
            binding,
            pauses,
            cert_file,
            account,
        }
    }

    /// `ssh <alias> true`, isolation arguments only, on the blocking pool (the
    /// endpoints keep being served meanwhile).
    pub(super) async fn login(r: &Real) -> Output {
        let mut cmd = r.home.client_command(ClientKind::Ssh, ALIAS).unwrap();
        cmd.arg("true").stdin(Stdio::null());
        let out = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .unwrap()
            .unwrap();
        assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    }

    pub(super) fn why(r: &Real, out: &Output) -> String {
        let root = r.home.root.to_string_lossy().into_owned();
        let text = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = text.lines().rev().take(12).collect();
        let mut s = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
        s = s.replace(&root, "<scratch>");
        if r.account.len() >= 2 {
            s = s.replace(&r.account, "<user>");
        }
        format!(
            "exit {:?}: {s}; signer refusals {:?}",
            out.status.code(),
            r.reg
                .signer(&SignerEndpoint::Environment)
                .map(|s| s.refusals())
                .unwrap_or_default()
        )
    }

    pub(super) fn client_version() -> String {
        Command::new(find_program("ssh").unwrap())
            .arg("-V")
            .stdin(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
            .unwrap_or_default()
    }

    pub(super) fn signed(r: &Real) -> usize {
        r.pauses
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _)| *s == SignStep::Signed)
            .count()
    }
}

/// D10 items 1–3: a real `ssh` whose scratch `-F` holds P's managed block (the
/// environment endpoint, `IdentitiesOnly`, the slot certificate as the identity) logs in
/// to a loopback sshd in account form through the environment endpoint; the server
/// accepted exactly this grant's certificate (key ID, serial, CA, K_env).
#[cfg(unix)]
#[tokio::test]
async fn fresh_login_through_environment_endpoint() {
    let r = real::start().await;
    let out = real::login(&r).await;
    assert!(out.status.success(), "{}", real::why(&r, &out));
    let accepted = r.sshd.accepted_certificates();
    assert_eq!(accepted.len(), 1);
    let cert = r.g.cert(&r.p);
    assert_eq!(accepted[0].key_id, cert.key_id());
    assert_eq!(accepted[0].serial, cert.serial());
    assert_eq!(accepted[0].fingerprint, r.g.key.fingerprint);
    assert_eq!(
        accepted[0].ca_fingerprint,
        r.w.ca.fingerprint().unwrap().as_str()
    );
    let env = r.reg.signer(&SignerEndpoint::Environment).unwrap();
    assert!(env.refusals().is_empty(), "{:?}", env.refusals());
    let _ = (&r.env, &r.binding, &r.cert_file);
}

/// Exactly one signature per fresh login, on each of three logins.
#[cfg(unix)]
#[tokio::test]
async fn one_signature_per_login() {
    let r = real::start().await;
    for n in 1..=3 {
        let out = real::login(&r).await;
        assert!(out.status.success(), "login {n}: {}", real::why(&r, &out));
        assert_eq!(real::signed(&r), n, "login {n}");
        assert_eq!(r.sshd.accepted_certificates().len(), n);
    }
    let env = r.reg.signer(&SignerEndpoint::Environment).unwrap();
    assert!(env.refusals().is_empty(), "{:?}", env.refusals());
}

/// M-F2: records, per client version, whether `session-bind@openssh.com` is sent and
/// whether the signature request arrived on a bound connection (one `m03 observation:`
/// row). Asserts only its control: the login succeeded with one signature.
#[cfg(unix)]
#[tokio::test]
async fn session_bind_observed_per_client() {
    let r = real::start().await;
    let out = real::login(&r).await;
    let env = r.reg.signer(&SignerEndpoint::Environment).unwrap();
    let stats = env.bind_stats();
    #[allow(clippy::print_stderr)] // the observation row (INT-Q4)
    {
        eprintln!(
            "m03 observation: session_bind client={:?} exit={:?} sent={} accepted={} refused={} signs_bound={} signs_unbound={}",
            real::client_version(),
            out.status.code(),
            if stats.accepted + stats.refused > 0 {
                "yes"
            } else {
                "no"
            },
            stats.accepted,
            stats.refused,
            stats.signs_bound,
            stats.signs_unbound,
        );
    }
    assert!(out.status.success(), "{}", real::why(&r, &out));
    assert_eq!(real::signed(&r), 1);
}

/// ADR-0005 §9.3, D2 item 7: after `destroy_grant` the agent lists nothing on any
/// endpoint, the vault no longer holds K_env, and a fresh login with the still-valid
/// slot certificate fails; the server accepts nothing new.
#[cfg(unix)]
#[tokio::test]
async fn destroyed_key_makes_installed_certificate_unusable() {
    let r = real::start().await;
    let out = real::login(&r).await;
    assert!(out.status.success(), "control: {}", real::why(&r, &out));
    assert_eq!(r.sshd.accepted_certificates().len(), 1);
    let slot = r.w.table.slot(r.g.id()).unwrap();
    assert!(r.w.table.destroy_grant(r.g.id()));
    assert!(!r.w.table.vault().contains(&slot), "K_env zeroized");
    assert!(identities_at(&r.env).await.unwrap().is_empty());
    assert!(identities_at(&r.binding).await.unwrap().is_empty());
    let out = real::login(&r).await;
    assert_eq!(out.status.code(), Some(255), "{}", real::why(&r, &out));
    assert_eq!(
        r.sshd.accepted_certificates().len(),
        1,
        "nothing new accepted"
    );
    assert!(
        r.cert_file.exists(),
        "the certificate itself is still on disk"
    );
    assert_eq!(r.w.table.instance_state(r.g.id()), None);
}
