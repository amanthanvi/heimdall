//! M03 wave 0 (G): U0b rows 5, 7, 20, 25, 26 and 27: signature authorization, the
//! narrowing protocol, the lock revocation, the owned-connection registration and the
//! revocation timestamps (ADR-0008 D2 items 3 and 3a, D7 items 2 and 5, D8 item 2, D9
//! item 2; rulings §17.4 item 6, §17.7 item 3, §17.10 items 1 and 3, §17.13 item 1,
//! §17.14 item 2).
//!
//! Everything runs in process over the production `heimdall_app::Operations`, an
//! in-memory store and `testkit::FakeCredentialAdapter`, on a **paused** tokio clock:
//! the operations clock below (`TokioClock`) reads the tokio clock, so wall and
//! continuous time move only when the runtime is idle (or `advance` is called), and
//! every duration below is virtual and deterministic. Orderings come from the
//! production narrowing hook (`Operations::set_narrowing_hook`, the M01 `StageHook`
//! pattern), never from real sleeps.
//!
//! **Wave 0 has no credential instance**, so no grant has a gate in production and
//! every narrowing takes the zero-gate path. The tests create gates through
//! `SigningGates::retain`, as the first instance will (U10). A "signer" is a task that
//! takes a real permit through `SignatureAuthority::admit`, holds it, and records an
//! enqueue only when the permit's release check passes ("nothing enqueued after the
//! mark" = no permit passes its release check after the mark). A "delegation" holds its
//! chain through the real `SigningGates::hold_for_delegation` and creates the child
//! through the real `Operations::delegate`. Slot files and owned processes do not exist
//! in wave 0: their ordering is asserted at the hook's `Cleanup` point (U7/U10 wire the
//! effects there).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::managed::{GateError, SignPermit, SigningGates};
use heimdall_app::operations::narrowing::{
    AuthorizationTime, BoundTerms, HookFuture, NarrowingHook, NarrowingKind, NarrowingPoint,
    NarrowingRead, NarrowingReport,
};
use heimdall_app::operations::{IntentOutcome, Limits};
use heimdall_app::ports::{
    AdapterDescriptor, ConnError, CredentialAdapter, InteractionRequirement, LockContinuity,
    LockState, PrepareOutcome, SessionLockSource, SignRefusal, SignatureAuthority,
    SignatureRequestFacts, SignatureSubject, SignerEndpoint,
};
use heimdall_app::{Caller, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, DeviceId, EnvironmentId, GrantId, OperationId, PolicyId,
    ProfileId, RequestId, WorkId,
};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::request::{
    DeadlineIntent, DelegateRequest, DestinationScopeEnforcement, Enforcement, EnsureData,
    EnsureRequest, ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry,
    PolicyAction, RefreshDependency, RequiredCapabilities, RevocationStatus, RevokeData,
    RevokeRequest, WaitMode, WorkloadIsolation,
};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::revocation::{CleanupIntent, RevocationCause};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};
use tokio::sync::Notify;
use tokio::time::Instant;

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
        .unwrap()
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
    }
}

fn descriptor(remote_effect: bool) -> AdapterDescriptor {
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
        remote_credential_effect: remote_effect,
    }
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn policy(lock: LockBehavior) -> StandingPolicy {
    policy_rev(lock, 1)
}

fn policy_rev(lock: LockBehavior, revision: u64) -> StandingPolicy {
    StandingPolicy {
        id: policy_id(),
        revision: PolicyRevision(revision),
        profile: ProfileId::parse("dev").unwrap(),
        workspace: None,
        scope: Scope {
            pairs: [pair("h1", "deploy"), pair("h2", "deploy")]
                .into_iter()
                .collect(),
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

fn seed(store: &Store) {
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
                    pairs: [pair("h1", "deploy"), pair("h2", "deploy")]
                        .into_iter()
                        .collect(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(&policy(LockBehavior::Continue), false)?;
            Ok(())
        })
        .unwrap();
}

/// The operations clock on the tokio clock (paused in every test): wall =
/// `t0 + elapsed (+ wall skew)`, continuous = `elapsed (+ continuous skew)`, one boot.
struct TokioClock {
    start: Instant,
    wall_back: Mutex<Duration>,
    continuous_ahead: Mutex<Duration>,
}

impl TokioClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            wall_back: Mutex::new(Duration::ZERO),
            continuous_ahead: Mutex::new(Duration::ZERO),
        })
    }
    fn elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(self.start)
    }
}

impl Clock for TokioClock {
    fn wall(&self) -> Timestamp {
        let w = plus(t0(), self.elapsed());
        w.checked_sub(jiff::SignedDuration::try_from(*self.wall_back.lock().unwrap()).unwrap())
            .unwrap()
    }
    fn continuous(&self) -> Duration {
        Duration::from_secs(1000) + self.elapsed() + *self.continuous_ahead.lock().unwrap()
    }
    fn boot_id(&self) -> BootId {
        BootId("tokio-boot-1".into())
    }
}

type Fut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

type When = Box<dyn Fn(NarrowingKind, &NarrowingPoint) -> bool + Send + Sync>;

struct Act {
    when: When,
    run: Box<dyn Fn() -> Fut + Send + Sync>,
    left: AtomicUsize,
}

/// The narrowing hook: logs every point with its instant, imposes `t_read` before
/// each read and `t_commit` before each slow-path commit, and runs scripted actions.
#[derive(Default)]
struct Hook {
    t_read: Mutex<Duration>,
    t_commit: Mutex<Duration>,
    /// Extra hold at the cleanup point of a kind (the countermodel's 5 s cleanup).
    cleanup_hold: Mutex<Option<(NarrowingKind, Duration)>>,
    log: Mutex<Vec<(Instant, NarrowingKind, NarrowingPoint)>>,
    acts: Mutex<Vec<Arc<Act>>>,
    changed: Notify,
}

impl Hook {
    fn act(
        &self,
        times: usize,
        when: impl Fn(NarrowingKind, &NarrowingPoint) -> bool + Send + Sync + 'static,
        run: impl Fn() -> Fut + Send + Sync + 'static,
    ) {
        self.acts.lock().unwrap().push(Arc::new(Act {
            when: Box::new(when),
            run: Box::new(run),
            left: AtomicUsize::new(times),
        }));
    }

    fn log(&self) -> Vec<(Instant, NarrowingKind, NarrowingPoint)> {
        self.log.lock().unwrap().clone()
    }

    fn at_of(&self, f: impl Fn(NarrowingKind, &NarrowingPoint) -> bool) -> Option<Instant> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|(_, k, p)| f(*k, p))
            .map(|(i, _, _)| *i)
    }

    fn reports(&self) -> Vec<NarrowingReport> {
        self.log()
            .into_iter()
            .filter_map(|(_, _, p)| match p {
                NarrowingPoint::Reported(r) => Some(*r),
                _ => None,
            })
            .collect()
    }

    /// Wait (in virtual time) until the log satisfies `f`.
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

fn marked(_: NarrowingKind, p: &NarrowingPoint) -> bool {
    matches!(p, NarrowingPoint::Marked { .. })
}

impl NarrowingHook for Hook {
    fn at<'a>(&'a self, kind: NarrowingKind, point: NarrowingPoint) -> HookFuture<'a> {
        Box::pin(async move {
            self.log
                .lock()
                .unwrap()
                .push((Instant::now(), kind, point.clone()));
            self.changed.notify_waiters();
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

/// A store fault hook that counts transactions and can fail the next commit.
#[derive(Default)]
struct Faults {
    transactions: AtomicUsize,
    fail_commit: AtomicBool,
}

impl FaultHook for Faults {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == FaultPoint::BeforeTransaction {
            self.transactions.fetch_add(1, Ordering::SeqCst);
        }
        if point == FaultPoint::BeforeCommit && self.fail_commit.swap(false, Ordering::SeqCst) {
            return FaultAction::Fail;
        }
        FaultAction::Continue
    }
}

/// A session-lock source that records each `acknowledge`, with its instant.
struct TestLock {
    state: Mutex<LockState>,
    epoch: Mutex<LockEpoch>,
    acked: Mutex<Vec<(u64, Instant)>>,
    notify: Notify,
}

impl TestLock {
    fn new(state: LockState) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(state),
            epoch: Mutex::new(LockEpoch::default()),
            acked: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }
    fn lock(&self) {
        *self.state.lock().unwrap() = LockState::Locked;
        let e = *self.epoch.lock().unwrap();
        *self.epoch.lock().unwrap() = e.observe_lock();
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
        self.acked.lock().unwrap().push((epoch, Instant::now()));
        let e = *self.epoch.lock().unwrap();
        *self.epoch.lock().unwrap() = e.acknowledge(epoch);
    }
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

struct W {
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    faults: Arc<Faults>,
    limits: Limits,
    ops: Operations,
    hook: Arc<Hook>,
}

struct Opts {
    limits: Limits,
    remote_effect: bool,
    lock: LockBehavior,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            remote_effect: false,
            lock: LockBehavior::Continue,
        }
    }
}

async fn world() -> W {
    world_with(Opts::default()).await
}

async fn world_with(o: Opts) -> W {
    let faults = Arc::new(Faults::default());
    let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
    seed(&store);
    if o.lock != LockBehavior::Continue {
        store
            .transaction(|tx| tx.upsert_policy(&policy_rev(o.lock, 2), false))
            .unwrap();
    }
    let clock = TokioClock::new();
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::new(
        descriptor(o.remote_effect),
        vec![FakeStep::Prepare(outcome())],
    );
    let ops = Operations::start(config(&store, &clock, &sync, &fake, o.limits))
        .await
        .unwrap();
    let hook = Arc::new(Hook::default());
    ops.set_narrowing_hook(hook.clone());
    W {
        store,
        clock,
        sync,
        fake,
        faults,
        limits: o.limits,
        ops,
        hook,
    }
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

impl W {
    fn gates(&self) -> &SigningGates {
        self.ops.signing_gates()
    }

    async fn root(&self, tag: &str) -> EnsureData {
        let r = self
            .ops
            .ensure(
                &owner(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: [pair("h1", "deploy")].into_iter().collect(),
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

    async fn child(&self, parent: &EnsureData, tag: &str) -> EnsureData {
        let r = self
            .ops
            .delegate(
                &owner(),
                DelegateRequest {
                    parent_binding_id: parent.binding_id.clone(),
                    scope: [pair("h1", "deploy")].into_iter().collect(),
                    until: Some(DeadlineIntent::Duration("1h".into())),
                    work_id: WorkId::parse(&format!("c-{tag}")).unwrap(),
                    request_id: RequestId::parse(&format!("d-{tag}")).unwrap(),
                    required_capabilities: RequiredCapabilities::default(),
                },
            )
            .await;
        match r {
            Ok(c) => c.data,
            Err(e) => panic!("delegate {tag}: {} {}", e.code, e.message),
        }
    }

    /// Create the gate (the first credential instance; U10).
    fn gate(&self, g: &EnsureData, ancestors: &[&EnsureData]) {
        let chain: Vec<GrantId> = ancestors.iter().map(|a| a.grant_id.clone()).collect();
        self.gates().retain(&g.grant_id, &chain);
    }

    async fn admit(&self, g: &EnsureData) -> Result<SignPermit, SignRefusal> {
        self.ops.admit(&facts(g)).await
    }

    async fn revoke(&self, g: &EnsureData, rid: &str) -> RevokeData {
        let r = self
            .ops
            .revoke(
                &owner(),
                RevokeRequest {
                    grant_id: g.grant_id.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await;
        match r {
            Ok(c) => c.data,
            Err(e) => panic!("revoke {rid}: {} {}", e.code, e.message),
        }
    }

    fn spawn_revoke(&self, g: &EnsureData, rid: &str) -> tokio::task::JoinHandle<RevokeData> {
        let (ops, g, rid) = (self.ops.clone(), g.clone(), rid.to_owned());
        tokio::spawn(async move {
            match ops
                .revoke(
                    &owner(),
                    RevokeRequest {
                        grant_id: g.grant_id,
                        request_id: RequestId::parse(&rid).unwrap(),
                    },
                )
                .await
            {
                Ok(c) => c.data,
                Err(e) => panic!("revoke {rid}: {} {}", e.code, e.message),
            }
        })
    }

    fn tombstone(&self, g: &EnsureData) -> Option<heimdall_domain::revocation::Tombstone> {
        self.store
            .transaction(|tx| tx.tombstone(&g.grant_id))
            .unwrap()
    }

    fn state(&self, g: &EnsureData) -> GrantState {
        self.store
            .transaction(|tx| tx.grant(&g.grant_id))
            .unwrap()
            .unwrap()
            .state
    }

    fn report(&self, kind: NarrowingKind) -> NarrowingReport {
        self.hook
            .reports()
            .into_iter()
            .rfind(|r| r.kind == kind)
            .expect("a report")
    }
}

fn facts(g: &EnsureData) -> SignatureRequestFacts {
    SignatureRequestFacts {
        endpoint: SignerEndpoint::Binding(g.binding_id.clone()),
        subject: SignatureSubject::Grant(g.grant_id.clone()),
        pair: pair("h1", "deploy"),
        key_fingerprint: "SHA256:fixture".into(),
    }
}

/// A test signer: admits, holds the permit for `hold`, then "enqueues" (records the
/// instant) only when the release check passes.
#[derive(Default)]
struct Signers {
    enqueued: Mutex<Vec<Instant>>,
    refused_at_release: AtomicUsize,
    refused_at_admit: Mutex<Vec<SignRefusal>>,
}

impl Signers {
    fn spawn(
        self: &Arc<Self>,
        ops: &Operations,
        g: &EnsureData,
        hold: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let (me, ops, f) = (Arc::clone(self), ops.clone(), facts(g));
        tokio::spawn(async move {
            match ops.admit(&f).await {
                Ok(p) => {
                    tokio::time::sleep(hold).await;
                    if p.may_release() {
                        me.enqueued.lock().unwrap().push(Instant::now());
                    } else {
                        me.refused_at_release.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(e) => me.refused_at_admit.lock().unwrap().push(e),
            }
        })
    }

    fn none_enqueued_after(&self, mark: Instant) {
        for e in self.enqueued.lock().unwrap().iter() {
            assert!(*e < mark, "a signature was enqueued after the mark");
        }
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

fn mark_of(w: &W, kind: NarrowingKind) -> Instant {
    w.hook
        .at_of(|k, p| k == kind && matches!(p, NarrowingPoint::Marked { .. }))
        .expect("marked")
}

// =================================================================================
// Row 5: authorization
// =================================================================================

/// Each D2 item 3 predicate refuses on its own (the key's endpoint, a missing gate,
/// a tombstone, the grant state, the deadline, time, the mechanism, the generation,
/// the session lock, the pending mark, the gate wait). `AuthorizationTimeout` needs a
/// store slower than 2 s inside one transaction and is not exercised in wave 0.
#[tokio::test(start_paused = true)]
async fn authorize_refuses_each_predicate() {
    let w = world().await;
    let g = w.root("p1").await;
    // No gate: nothing can sign.
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::KeyNotServed);
    w.gate(&g, &[]);
    assert!(w.admit(&g).await.is_ok(), "the baseline admits");
    // Another binding's endpoint does not serve this key.
    let mut other = facts(&g);
    other.endpoint = SignerEndpoint::Binding(BindingId::from_random_bytes([9; 16]));
    assert_eq!(
        w.ops.admit(&other).await.unwrap_err(),
        SignRefusal::KeyNotServed
    );
    // Verification subjects are U5's (fail closed).
    let mut verification = facts(&g);
    verification.subject = SignatureSubject::Verification(OperationId::from_random_bytes([3; 16]));
    assert_eq!(
        w.ops.admit(&verification).await.unwrap_err(),
        SignRefusal::Unavailable
    );
    // The pending mark.
    let n = w.gates().begin_narrowing([g.grant_id.clone()]);
    assert_eq!(
        w.admit(&g).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    drop(n);
    // The gate wait: held exclusively by a narrowing that marks nothing.
    let mut n = w.gates().begin_narrowing([]);
    n.acquire(&g.grant_id).await.unwrap();
    let before = Instant::now();
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::GateTimeout);
    assert_eq!(before.elapsed(), w.limits.signing_gate_wait);
    drop(n);
    // Time: the read-only assessment (U3) fails closed in wave 0; a wall clock pulled
    // back beyond the rollback tolerance is uncertain under `Peek`.
    w.ops.set_authorization_time(AuthorizationTime::ReadOnly);
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::TimeUncertain);
    w.ops.set_authorization_time(AuthorizationTime::Peek);
    *w.clock.wall_back.lock().unwrap() = Duration::from_secs(3600);
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::TimeUncertain);
    *w.clock.wall_back.lock().unwrap() = Duration::ZERO;
    assert!(w.admit(&g).await.is_ok());
    // The session lock: `revoke_on_lock` needs `unlocked` (no source = unknown).
    w.store
        .transaction(|tx| tx.upsert_policy(&policy_rev(LockBehavior::RevokeOnLock, 2), true))
        .unwrap();
    assert_eq!(
        w.admit(&g).await.unwrap_err(),
        SignRefusal::SessionNotUnlocked
    );
    let lock = TestLock::new(LockState::Locked);
    w.ops.set_session_lock_source(lock.clone());
    assert_eq!(
        w.admit(&g).await.unwrap_err(),
        SignRefusal::SessionNotUnlocked
    );
    *lock.state.lock().unwrap() = LockState::Unlocked;
    assert!(w.admit(&g).await.is_ok(), "unlocked admits");
    // A stale generation that re-validation cannot restore (the policy no longer
    // covers h1).
    let mut narrowed = policy(LockBehavior::Continue);
    narrowed.scope.pairs = [pair("h2", "deploy")].into_iter().collect();
    narrowed.revision = PolicyRevision(3);
    w.store
        .transaction(|tx| tx.upsert_policy(&narrowed, true))
        .unwrap();
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::StaleGeneration);
    // The mechanism: an `Operations` with no adapter configured.
    let w2 = world().await;
    let g2 = w2.root("p2").await;
    let bare = Operations::start(OperationsConfig {
        adapters: Vec::new(),
        ..config(&w2.store, &w2.clock, &w2.sync, &w2.fake, w2.limits)
    })
    .await
    .unwrap();
    bare.signing_gates().retain(&g2.grant_id, &[]);
    assert_eq!(
        bare.admit(&facts(&g2)).await.unwrap_err(),
        SignRefusal::MechanismNotConfigured
    );
    // The deadline (2 h window), then the state once the grant has ended.
    w2.gate(&g2, &[]);
    tokio::time::advance(2 * HOUR + Duration::from_secs(1)).await;
    assert_eq!(
        w2.admit(&g2).await.unwrap_err(),
        SignRefusal::DeadlinePassed
    );
    w2.ops.tick().await.unwrap();
    assert_eq!(w2.state(&g2), GrantState::Expired);
    assert_eq!(
        w2.admit(&g2).await.unwrap_err(),
        SignRefusal::GrantNotUsable
    );
    // A tombstone.
    let w3 = world().await;
    let g3 = w3.root("p3").await;
    w3.gate(&g3, &[]);
    w3.revoke(&g3, "rv-p3").await;
    assert_eq!(w3.admit(&g3).await.unwrap_err(), SignRefusal::Tombstoned);
}

/// ADR-0006 §13.5 ruling 2: an unrelated generation move (another grant revoked)
/// re-validates automatically and admits; the new validation is recorded.
#[tokio::test(start_paused = true)]
async fn authorize_revalidates_after_unrelated_generation_move() {
    let w = world().await;
    let g = w.root("a").await;
    let other = w.root("b").await;
    w.gate(&g, &[]);
    w.revoke(&other, "rv-b").await;
    let current = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    assert!(w.admit(&g).await.is_ok());
    let validated = w
        .store
        .transaction(|tx| tx.grant_validation(&g.grant_id))
        .unwrap();
    assert_eq!(validated, Some(current));
}

/// A permit admitted before a revoke is never released after its mark, the commit
/// waits for the permit to drop, and after the commit nothing is admitted.
#[tokio::test(start_paused = true)]
async fn authorize_linearizes_with_revoke_commit() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    assert!(p.may_release());
    let rv = w.spawn_revoke(&g, "rv-a");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    assert!(!p.may_release(), "never released after the mark");
    assert!(
        w.tombstone(&g).is_none(),
        "no commit while the permit holds the gate"
    );
    let dropped = Instant::now();
    drop(p);
    rv.await.unwrap();
    let acquired = w
        .hook
        .at_of(|_, p| matches!(p, NarrowingPoint::Acquired { round: 0, .. }))
        .unwrap();
    assert!(acquired >= dropped);
    assert!(w.tombstone(&g).is_some());
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::Tombstoned);
}

/// The admitting read is the one taken after the gate: a tombstone written while the
/// signer waited (no mark involved) refuses.
#[tokio::test(start_paused = true)]
async fn admit_reads_fresh_after_taking_gate() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let mut n = w.gates().begin_narrowing([]);
    n.acquire(&g.grant_id).await.unwrap();
    let (ops, f) = (w.ops.clone(), facts(&g));
    let signer = tokio::spawn(async move { ops.admit(&f).await.map(|_| ()) });
    settle().await;
    let gid = g.grant_id.clone();
    w.store
        .transaction(|tx| {
            let generation = tx.authority_generation()?;
            tx.insert_tombstone(&heimdall_domain::revocation::Tombstone {
                grant: gid.clone(),
                cascade: Vec::new(),
                generation,
                revoked_at: t0(),
                remote_pending: Vec::new(),
                cause: RevocationCause::Revoke,
            })
            .map(|_| ())
        })
        .unwrap();
    drop(n);
    assert_eq!(signer.await.unwrap().unwrap_err(), SignRefusal::Tombstoned);
}

/// `signing_gate_wait` bounds the shared wait; the refusal comes at exactly the bound.
#[tokio::test(start_paused = true)]
async fn admit_refuses_when_gate_not_obtained_in_time() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let mut n = w.gates().begin_narrowing([]);
    n.acquire(&g.grant_id).await.unwrap();
    let start = Instant::now();
    assert_eq!(w.admit(&g).await.unwrap_err(), SignRefusal::GateTimeout);
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    drop(n);
    assert!(w.admit(&g).await.is_ok());
}

/// The permit's expiry is the earliest of the holder bound, the wall deadline, an
/// admission limit (a cutoff) and the continuous budget's end.
#[tokio::test(start_paused = true)]
async fn permit_expiry_is_earliest_of_every_bound() {
    // Holder bound: deadline 2 h away, so `signing_holder_max` (5 s) wins.
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    assert_eq!(p.expires_at() - Instant::now(), w.limits.signing_holder_max);
    assert_eq!(
        p.expires_wall(),
        plus(w.clock.wall(), w.limits.signing_holder_max)
    );
    drop(p);
    // Wall deadline: 2 s before the 2 h bound.
    tokio::time::advance(2 * HOUR - Duration::from_secs(2)).await;
    let p = w.admit(&g).await.unwrap();
    assert_eq!(p.expires_wall(), g.expires_at);
    assert_eq!(p.expires_at() - Instant::now(), Duration::from_secs(2));
    drop(p);
    // Continuous budget: the continuous clock 1 s ahead of the wall (within the
    // skew tolerance) leaves 1 s of budget against 2 s of wall.
    *w.clock.continuous_ahead.lock().unwrap() = Duration::from_secs(1);
    let p = w.admit(&g).await.unwrap();
    assert_eq!(p.expires_at() - Instant::now(), Duration::from_secs(1));
    drop(p);
    // An admission limit: a cutoff 3 s ahead on a fresh grant.
    let w = world().await;
    let g = w.root("b").await;
    w.gate(&g, &[]);
    let at = plus(w.clock.wall(), Duration::from_secs(3));
    w.ops
        .policy(
            &owner(),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await
        .unwrap();
    let p = w.admit(&g).await.unwrap();
    assert_eq!(p.expires_wall(), at);
    assert_eq!(p.expires_at() - Instant::now(), Duration::from_secs(3));
}

/// `expires_at()` is the continuous expiry, and the release check refuses at it.
#[tokio::test(start_paused = true)]
async fn permit_expires_at_matches_expiry() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    assert_eq!(p.expires_at(), p.expiry().continuous);
    let wall = w.clock.wall();
    assert!(p.may_release_at(Some(wall), p.expires_at() - Duration::from_millis(1)));
    assert!(!p.may_release_at(Some(wall), p.expires_at()));
    tokio::time::advance(w.limits.signing_holder_max).await;
    assert!(!p.may_release(), "expired on the continuous clock");
}

/// The pre-check refuses a marked grant, and a grant whose ancestor is marked.
#[tokio::test(start_paused = true)]
async fn precheck_refuses_pending_narrowing() {
    let w = world().await;
    let g = w.root("a").await;
    let c = w.child(&g, "c").await;
    w.gate(&g, &[]);
    w.gate(&c, &[&g]);
    assert!(w.ops.precheck(&facts(&g)).await.is_ok());
    let n = w.gates().begin_narrowing([g.grant_id.clone()]);
    assert_eq!(
        w.ops.precheck(&facts(&g)).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    assert_eq!(
        w.ops.precheck(&facts(&c)).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    drop(n);
    assert!(w.ops.precheck(&facts(&c)).await.is_ok());
}

/// A signer that waited for the gate and finds the mark when it gets it refuses
/// before any store read (no transaction runs), and releases the gate at once.
#[tokio::test(start_paused = true)]
async fn admit_checks_pending_first_after_awaited_acquisition() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let mut holder = w.gates().begin_narrowing([]);
    holder.acquire(&g.grant_id).await.unwrap();
    let (ops, f) = (w.ops.clone(), facts(&g));
    let signer = tokio::spawn(async move { ops.admit(&f).await.map(|_| ()) });
    settle().await;
    let mark = w.gates().begin_narrowing([g.grant_id.clone()]);
    let before = w.faults.transactions.load(Ordering::SeqCst);
    drop(holder);
    assert_eq!(
        signer.await.unwrap().unwrap_err(),
        SignRefusal::NarrowingPending
    );
    assert_eq!(
        w.faults.transactions.load(Ordering::SeqCst),
        before,
        "no store read after the pending refusal"
    );
    // Released at once: an exclusive acquisition succeeds immediately.
    assert!(
        w.gates()
            .acquire_shared(&g.grant_id, Duration::from_millis(1))
            .await
            .is_ok(),
        "the gate was released"
    );
    drop(mark);
}

/// A child's admission refuses while its ancestor is marked, whether the mark comes
/// before the request or while it waits for the gate.
#[tokio::test(start_paused = true)]
async fn admit_refuses_when_ancestor_marked() {
    let w = world().await;
    let g = w.root("a").await;
    let c = w.child(&g, "c").await;
    w.gate(&g, &[]);
    w.gate(&c, &[&g]);
    let n = w.gates().begin_narrowing([g.grant_id.clone()]);
    assert_eq!(
        w.admit(&c).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    drop(n);
    let mut holder = w.gates().begin_narrowing([]);
    holder.acquire(&c.grant_id).await.unwrap();
    let (ops, f) = (w.ops.clone(), facts(&c));
    let signer = tokio::spawn(async move { ops.admit(&f).await.map(|_| ()) });
    settle().await;
    let n = w.gates().begin_narrowing([g.grant_id.clone()]);
    drop(holder);
    assert_eq!(
        signer.await.unwrap().unwrap_err(),
        SignRefusal::NarrowingPending
    );
    drop(n);
    assert!(w.admit(&c).await.is_ok());
}

// =================================================================================
// Row 7: QR17 for adapters with a remote credential effect
// =================================================================================

fn seed_intent(w: &W) -> CleanupIntent {
    let intent = CleanupIntent {
        grant: GrantId::from_random_bytes([0x5a; 16]),
        operation: OperationId::from_random_bytes([0x5b; 16]),
        adapter: Some(descriptor(false).identity),
        effect_token: "eff_g_row7".into(),
        confirmed: true,
        in_flight: false,
        version: 0,
        recorded_at: t0(),
    };
    w.store
        .transaction(|tx| tx.record_cleanup_intent(&intent))
        .unwrap()
}

fn bounded() -> Limits {
    Limits {
        adapter_call_timeout: Duration::from_millis(200),
        ..Limits::default()
    }
}

/// A remote-effect adapter's timed-out immediate call keeps the intent (never counted
/// as made); the next processing makes the call again and clears it once answered.
/// The bounded, jittered schedule of those retries is the supervisor's (agent R's
/// `runtime_m03` tests; `Operations::process_cleanup_intent_reporting` answers `Kept`).
#[tokio::test(start_paused = true)]
async fn timed_out_immediate_revoke_with_remote_effect_keeps_intent_and_retries() {
    let w = world_with(Opts {
        limits: bounded(),
        remote_effect: true,
        ..Opts::default()
    })
    .await;
    let intent = seed_intent(&w);
    w.fake.arm(FakeStep::HangRevoke);
    assert_eq!(
        w.ops.process_cleanup_intent_reporting(intent.clone()).await,
        IntentOutcome::Kept
    );
    assert!(
        w.store
            .transaction(|tx| tx.cleanup_intent(&intent.grant, &intent.operation))
            .unwrap()
            .is_some()
    );
    assert_eq!(w.fake.hangs_dropped(), 1);
    // The retry answers: the intent clears.
    assert_eq!(
        w.ops.process_cleanup_intent_reporting(intent.clone()).await,
        IntentOutcome::Cleared
    );
}

/// M02 adapters (no remote credential effect) keep QR17: the timed-out immediate call
/// counts as made and the intent is removed.
#[tokio::test(start_paused = true)]
async fn m02_adapters_unchanged_timed_out_immediate_counts_as_made() {
    let w = world_with(Opts {
        limits: bounded(),
        ..Opts::default()
    })
    .await;
    let intent = seed_intent(&w);
    w.fake.arm(FakeStep::HangRevoke);
    assert_eq!(
        w.ops.process_cleanup_intent_reporting(intent.clone()).await,
        IntentOutcome::Cleared
    );
    assert_eq!(w.fake.hangs_dropped(), 1);
}

// =================================================================================
// Row 20: the narrowing protocol
// =================================================================================

/// The revoke's commit waits for the gate: marked first, no tombstone while a
/// pre-mark permit holds the gate, the commit after it drops.
#[tokio::test(start_paused = true)]
async fn revoke_takes_gate_before_commit() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(w.tombstone(&g).is_none());
    drop(p);
    let data = rv.await.unwrap();
    assert!(data.local_applied);
    let r = w.report(NarrowingKind::Revoke);
    assert_eq!(r.gates_held, 1);
    assert!(r.seq.is_some());
    assert!(w.tombstone(&g).is_some());
}

/// A cutoff moved earlier is a narrowing commit: the policy is not written while a
/// permit holds an affected grant's gate.
#[tokio::test(start_paused = true)]
async fn cutoff_earlier_takes_gate() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    let ops = w.ops.clone();
    let at = plus(w.clock.wall(), Duration::from_secs(1800));
    let cut = tokio::spawn(async move {
        ops.policy(
            &owner(),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await
        .map(|_| ())
    });
    w.hook.wait_marked(NarrowingKind::Cutoff).await;
    let stored = |w: &W| {
        w.store
            .transaction(|tx| tx.policy(&policy_id()))
            .unwrap()
            .unwrap()
            .cutoff_at
    };
    assert_eq!(stored(&w), None, "not committed under a held gate");
    assert!(!p.may_release());
    drop(p);
    cut.await.unwrap().unwrap();
    assert_eq!(stored(&w), Some(at));
    assert_eq!(w.report(NarrowingKind::Cutoff).gates_held, 1);
}

/// Reading E6b (and E6a): an environment-permission removal withdraws the grant at
/// re-validation; the withdrawal is detected, then committed only under the gate.
#[tokio::test(start_paused = true)]
async fn revalidation_withdrawal_takes_gate() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    w.store
        .transaction(|tx| {
            let mut e = tx.environment(&env_id())?.expect("environment");
            e.permissions.automatic_activation = false;
            tx.upsert_environment(&e)
        })
        .unwrap();
    let ops = w.ops.clone();
    let tick = tokio::spawn(async move { ops.tick().await.map(|_| ()) });
    w.hook.wait_marked(NarrowingKind::Withdrawal).await;
    assert!(w.tombstone(&g).is_none());
    assert!(!p.may_release());
    drop(p);
    tick.await.unwrap().unwrap();
    let t = w.tombstone(&g).expect("withdrawn");
    assert_eq!(t.cause, RevocationCause::AuthorityWithdrawn);
    assert_eq!(w.report(NarrowingKind::Withdrawal).gates_held, 1);
}

/// Keys are destroyed (in memory) while the gates are held; the gates are released
/// only after.
#[tokio::test(start_paused = true)]
async fn gate_released_after_keys_destroyed() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let held_at_destroy = Arc::new(AtomicBool::new(false));
    let (gates, gid, flag) = (
        w.gates().clone(),
        g.grant_id.clone(),
        held_at_destroy.clone(),
    );
    w.hook.act(
        1,
        |_, p| matches!(p, NarrowingPoint::UnderGates { .. }),
        move || {
            let (gates, gid, flag) = (gates.clone(), gid.clone(), flag.clone());
            Box::pin(async move {
                let busy = gates.acquire_shared(&gid, Duration::from_millis(1)).await;
                flag.store(matches!(busy, Err(GateError::Timeout)), Ordering::SeqCst);
            })
        },
    );
    w.revoke(&g, "rv").await;
    assert!(
        held_at_destroy.load(Ordering::SeqCst),
        "held while keys are destroyed"
    );
    let log = w.hook.log();
    let under = log
        .iter()
        .position(|(_, _, p)| matches!(p, NarrowingPoint::UnderGates { destroy, .. } if destroy.contains(&g.grant_id)))
        .unwrap();
    let released = log
        .iter()
        .position(|(_, _, p)| matches!(p, NarrowingPoint::Released))
        .unwrap();
    assert!(under < released);
    assert!(
        w.gates()
            .acquire_shared(&g.grant_id, Duration::from_millis(1))
            .await
            .is_ok()
    );
}

/// A delegation in flight when the revoke starts holds the parent's gate; the child
/// it creates after the mark is covered (its ancestor is marked), its install aborts
/// fail closed, and no signature from it is ever released.
#[tokio::test(start_paused = true)]
async fn delegation_during_revocation_child_never_signs_after_ack() {
    let w = world().await;
    let parent = w.root("p").await;
    w.gate(&parent, &[]);
    let hold = w
        .gates()
        .hold_for_delegation(&parent.grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let rv = w.spawn_revoke(&parent, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    // The delegation goes on: the child exists, its first instance is created...
    let child = w.child(&parent, "c").await;
    w.gate(&child, &[&parent]);
    assert_eq!(
        w.admit(&child).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    // ... and the re-check before install finds the mark: abort fail closed.
    assert!(hold.is_pending());
    w.gates().release(&child.grant_id);
    drop(hold);
    let data = rv.await.unwrap();
    assert!(data.local_applied);
    assert!(
        w.tombstone(&parent)
            .unwrap()
            .cascade
            .contains(&child.grant_id)
    );
    assert!(
        w.admit(&child).await.is_err(),
        "never admitted after the acknowledgment"
    );
}

/// Two cascades over one tree (A and its child B), each with pre-mark signers: both
/// commit, no deadlock, and no signature is released after either mark.
#[tokio::test(start_paused = true)]
async fn two_concurrent_cascades_no_deadlock_no_late_signature() {
    let w = world().await;
    let a = w.root("a").await;
    let b = w.child(&a, "b").await;
    w.gate(&a, &[]);
    w.gate(&b, &[&a]);
    let signers = Arc::new(Signers::default());
    let s1 = signers.spawn(&w.ops, &a, Duration::from_secs(3));
    let s2 = signers.spawn(&w.ops, &b, Duration::from_secs(3));
    settle().await;
    let r1 = w.spawn_revoke(&a, "rv-a");
    let r2 = w.spawn_revoke(&b, "rv-b");
    tokio::time::timeout(Duration::from_secs(60), async {
        r1.await.unwrap();
        r2.await.unwrap();
    })
    .await
    .expect("no deadlock");
    s1.await.unwrap();
    s2.await.unwrap();
    let first_mark = w
        .hook
        .log()
        .iter()
        .filter(|(_, _, p)| matches!(p, NarrowingPoint::Marked { .. }))
        .map(|(i, _, _)| *i)
        .min()
        .unwrap();
    signers.none_enqueued_after(first_mark);
    assert_eq!(signers.refused_at_release.load(Ordering::SeqCst), 2);
    assert_eq!(w.state(&a), GrantState::Revoked);
    assert_eq!(w.state(&b), GrantState::Revoked);
}

fn cleanup_after_release(w: &W, g: &EnsureData) {
    let log = w.hook.log();
    let released = log
        .iter()
        .position(|(_, k, p)| *k == NarrowingKind::Revoke && matches!(p, NarrowingPoint::Released))
        .unwrap();
    let cleanup = log
        .iter()
        .position(|(_, k, p)| {
            *k == NarrowingKind::Revoke
                && matches!(p, NarrowingPoint::Cleanup { grants } if grants.contains(&g.grant_id))
        })
        .unwrap();
    assert!(
        released < cleanup,
        "cleanup only after the gates are released"
    );
}

fn probe_free_at_cleanup(w: &W, g: &EnsureData) -> Arc<AtomicBool> {
    let free = Arc::new(AtomicBool::new(false));
    let (gates, gid, flag) = (w.gates().clone(), g.grant_id.clone(), free.clone());
    w.hook.act(
        1,
        |_, p| matches!(p, NarrowingPoint::Cleanup { .. }),
        move || {
            let (gates, gid, flag) = (gates.clone(), gid.clone(), flag.clone());
            Box::pin(async move {
                let mut probe = gates.begin_narrowing([]);
                let got = tokio::time::timeout(Duration::from_millis(1), probe.acquire(&gid)).await;
                flag.store(matches!(got, Ok(Ok(_))), Ordering::SeqCst);
            })
        },
    );
    free
}

/// Owned processes are closed only after the gates are released. Wave 0 has no
/// owned process: the ordering is asserted at the cleanup point, where the gate is
/// already free (U7 wires the closing there).
#[tokio::test(start_paused = true)]
async fn revoke_closes_processes_only_after_gates_released() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let free = probe_free_at_cleanup(&w, &g);
    w.revoke(&g, "rv").await;
    cleanup_after_release(&w, &g);
    assert!(
        free.load(Ordering::SeqCst),
        "the gate is free at the cleanup"
    );
}

/// A delegation that overruns `delegation_gate_hold_max` aborts fail closed and the
/// waiting narrowing proceeds. Wave 0 has no delegation driver (U10) and no issuance
/// entries, so the abort is played through `DelegationHold::held_for` and "entries
/// counted" cannot be checked yet.
#[tokio::test(start_paused = true)]
async fn delegation_overrun_aborts_fail_closed_entries_counted() {
    let w = world().await;
    let parent = w.root("p").await;
    w.gate(&parent, &[]);
    let hold = w
        .gates()
        .hold_for_delegation(&parent.grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let rv = w.spawn_revoke(&parent, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::sleep(w.limits.delegation_gate_hold_max + Duration::from_millis(1)).await;
    assert!(hold.held_for(Instant::now()) > w.limits.delegation_gate_hold_max);
    drop(hold); // the overrun aborts fail closed
    rv.await.unwrap();
    assert!(w.tombstone(&parent).is_some());
}

/// The re-check's H/L interleaving: the cascade on R holds R and H, then finds L
/// (delegated before R was taken). Another narrowing wants L and H; it defers to the
/// cascade's earlier mark instead of taking L during the cascade's release, and both
/// complete.
#[tokio::test(start_paused = true)]
async fn gate_set_growth_hl_interleaving_releases_and_reacquires_no_deadlock() {
    let w = world().await;
    let r = w.root("r").await;
    let x = w.child(&r, "x").await;
    w.gate(&r, &[]);
    w.gate(&x, &[&r]);
    // L appears after the cascade's first read, before round 0's gates are taken.
    let (ops, rr) = (w.ops.clone(), r.clone());
    let made: Arc<Mutex<Option<EnsureData>>> = Arc::new(Mutex::new(None));
    let m2 = made.clone();
    w.hook.act(1, marked, move || {
        let (ops, rr, m2) = (ops.clone(), rr.clone(), m2.clone());
        Box::pin(async move {
            let c = ops
                .delegate(
                    &owner(),
                    DelegateRequest {
                        parent_binding_id: rr.binding_id.clone(),
                        scope: [pair("h1", "deploy")].into_iter().collect(),
                        until: Some(DeadlineIntent::Duration("1h".into())),
                        work_id: WorkId::parse("c-l").unwrap(),
                        request_id: RequestId::parse("d-l").unwrap(),
                        required_capabilities: RequiredCapabilities::default(),
                    },
                )
                .await
                .unwrap()
                .data;
            ops.signing_gates()
                .retain(&c.grant_id, std::slice::from_ref(&rr.grant_id));
            *m2.lock().unwrap() = Some(c);
        })
    });
    let other_done = Arc::new(AtomicBool::new(false));
    let (gates, xid, m3, done) = (
        w.gates().clone(),
        x.grant_id.clone(),
        made.clone(),
        other_done.clone(),
    );
    // At the cascade's round-1 release, the other narrowing starts.
    w.hook.act(
        1,
        |_, p| {
            matches!(
                p,
                NarrowingPoint::BeforeRead(NarrowingRead::Subtree { round: 1, .. })
            )
        },
        move || {
            let (gates, xid, m3, done) = (gates.clone(), xid.clone(), m3.clone(), done.clone());
            Box::pin(async move {
                let l = m3.lock().unwrap().clone().unwrap().grant_id;
                tokio::spawn(async move {
                    let mut n = gates.begin_narrowing([l.clone(), xid.clone()]);
                    n.acquire_all([&l, &xid]).await.unwrap();
                    done.store(true, Ordering::SeqCst);
                });
            })
        },
    );
    tokio::time::timeout(Duration::from_secs(60), w.revoke(&r, "rv"))
        .await
        .expect("no deadlock");
    let report = w.report(NarrowingKind::Revoke);
    assert_eq!(report.rounds, 1, "one release-and-reacquire round");
    assert!(!report.set_grew);
    tokio::time::timeout(Duration::from_secs(60), async {
        while !other_done.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the other narrowing completes");
}

/// Round 1 reacquires while delegations at every depth try to start: each is refused
/// by the mark, so the round's re-validation never grows the set.
#[tokio::test(start_paused = true)]
async fn reacquisition_round_never_grows_set() {
    let w = world().await;
    let r = w.root("r").await;
    let a = w.child(&r, "a").await;
    w.gate(&r, &[]);
    w.gate(&a, &[&r]);
    let (ops, aa) = (w.ops.clone(), a.clone());
    w.hook.act(1, marked, move || {
        let (ops, aa) = (ops.clone(), aa.clone());
        Box::pin(async move {
            // Growth before round 0's re-read forces round 1.
            let _ = ops
                .delegate(
                    &owner(),
                    DelegateRequest {
                        parent_binding_id: aa.binding_id.clone(),
                        scope: [pair("h1", "deploy")].into_iter().collect(),
                        until: Some(DeadlineIntent::Duration("1h".into())),
                        work_id: WorkId::parse("c-grow").unwrap(),
                        request_id: RequestId::parse("d-grow").unwrap(),
                        required_capabilities: RequiredCapabilities::default(),
                    },
                )
                .await
                .unwrap();
        })
    });
    let refused = Arc::new(AtomicUsize::new(0));
    let (gates, rid, aid, n) = (
        w.gates().clone(),
        r.grant_id.clone(),
        a.grant_id.clone(),
        refused.clone(),
    );
    w.hook.act(
        1,
        |_, p| {
            matches!(
                p,
                NarrowingPoint::BeforeRead(NarrowingRead::Subtree { round: 1, .. })
            )
        },
        move || {
            let (gates, rid, aid, n) = (gates.clone(), rid.clone(), aid.clone(), n.clone());
            Box::pin(async move {
                for (parent, chain) in [(rid.clone(), vec![]), (aid.clone(), vec![rid.clone()])] {
                    if matches!(
                        gates
                            .hold_for_delegation(&parent, &chain, Duration::from_millis(1))
                            .await,
                        Err(GateError::Pending)
                    ) {
                        n.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        },
    );
    w.revoke(&r, "rv").await;
    assert_eq!(
        refused.load(Ordering::SeqCst),
        2,
        "every delegation refused"
    );
    let report = w.report(NarrowingKind::Revoke);
    assert_eq!(report.rounds, 1);
    assert!(!report.set_grew);
    assert_eq!(report.members, 3);
}

/// Revision 4's bound, superseded by `narrowing_commit_within_derived_bound_and_reported`
/// (§17.13 item 1). At the budgets with one round it still holds: `(rounds + 1) × H`.
#[tokio::test(start_paused = true)]
async fn narrowing_wait_bounded_by_rounds_plus_one_times_gate_max_wait() {
    let w = world().await;
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let signers = Arc::new(Signers::default());
    let s = signers.spawn(&w.ops, &g, w.limits.signing_holder_max);
    settle().await;
    w.revoke(&g, "rv").await;
    s.await.unwrap();
    let r = w.report(NarrowingKind::Revoke);
    assert!(r.elapsed <= (r.rounds + 1) * w.limits.signing_gate_max_wait);
}

/// While a narrowing waits, every new signer, pre-check, delegation and connection
/// registration under its grants is refused at its first check.
#[tokio::test(start_paused = true)]
async fn pending_mark_refuses_new_signers_and_delegations() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    assert_eq!(
        w.admit(&g).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    assert_eq!(
        w.ops.precheck(&facts(&g)).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    assert!(matches!(
        w.gates()
            .hold_for_delegation(&g.grant_id, &[], Duration::from_secs(1))
            .await,
        Err(GateError::Pending)
    ));
    assert_eq!(
        w.ops
            .register_owned_connection(&g.binding_id, 4242, t0(), "/usr/bin/ssh")
            .await
            .unwrap_err(),
        ConnError::RegistrationRefused("narrowing_pending".into())
    );
    drop(p);
    rv.await.unwrap();
}

/// A delegation holds its whole chain shared, root first, and a narrowing on the root
/// waits for the hold.
#[tokio::test(start_paused = true)]
async fn delegation_holds_ancestor_chain_in_global_order() {
    let w = world().await;
    let r = w.root("r").await;
    let a = w.child(&r, "a").await;
    w.gate(&r, &[]);
    w.gate(&a, &[&r]);
    let hold = w
        .gates()
        .hold_for_delegation(
            &a.grant_id,
            std::slice::from_ref(&r.grant_id),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_eq!(hold.held(), vec![r.grant_id.clone(), a.grant_id.clone()]);
    let rv = w.spawn_revoke(&r, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(w.tombstone(&r).is_none(), "the root is frozen by the hold");
    drop(hold);
    rv.await.unwrap();
    assert!(w.tombstone(&r).is_some());
}

async fn delegate_child(ops: &Operations, parent: &EnsureData, tag: &str) -> EnsureData {
    ops.delegate(
        &owner(),
        DelegateRequest {
            parent_binding_id: parent.binding_id.clone(),
            scope: [pair("h1", "deploy")].into_iter().collect(),
            until: Some(DeadlineIntent::Duration("1h".into())),
            work_id: WorkId::parse(&format!("c-{tag}")).unwrap(),
            request_id: RequestId::parse(&format!("d-{tag}")).unwrap(),
            required_capabilities: RequiredCapabilities::default(),
        },
    )
    .await
    .unwrap()
    .data
}

/// The re-check's first trace (24.6 s under revision 4): pre-mark holders, a flood of
/// post-mark signers, and a pre-mark delegation whose child round 0's re-read finds.
/// The commit comes within `narrowing_gate_wait_max` and within the derived bound, and
/// nothing is released after the mark.
#[tokio::test(start_paused = true)]
async fn post_mark_flood_and_round_one_descendants_commit_within_bound() {
    let w = world().await;
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
    let r = w.root("r").await;
    w.gate(&r, &[]);
    let signers = Arc::new(Signers::default());
    let pre = signers.spawn(&w.ops, &r, w.limits.signing_holder_max);
    settle().await;
    let hold = w
        .gates()
        .hold_for_delegation(&r.grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let ops = w.ops.clone();
    let rr = r.clone();
    let delegation = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(9)).await;
        let c = delegate_child(&ops, &rr, "flood").await;
        ops.signing_gates()
            .retain(&c.grant_id, std::slice::from_ref(&rr.grant_id));
        drop(hold);
    });
    let rv = w.spawn_revoke(&r, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let mut flood = Vec::new();
    for _ in 0..50 {
        flood.push(signers.spawn(&w.ops, &r, Duration::ZERO));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    rv.await.unwrap();
    delegation.await.unwrap();
    pre.await.unwrap();
    for f in flood {
        f.await.unwrap();
    }
    let report = w.report(NarrowingKind::Revoke);
    assert_eq!(report.rounds, 1);
    assert!(
        report.elapsed <= w.limits.narrowing_gate_wait_max,
        "{report:?}"
    );
    assert!(report.elapsed <= report.bound);
    signers.none_enqueued_after(mark_of(&w, NarrowingKind::Revoke));
    assert!(
        signers
            .refused_at_admit
            .lock()
            .unwrap()
            .iter()
            .all(|e| *e == SignRefusal::NarrowingPending || *e == SignRefusal::Tombstoned)
    );
}

/// A descendant created after the mark is pending from the moment its gate exists,
/// through the ancestor check alone.
#[tokio::test(start_paused = true)]
async fn ancestor_pending_covers_descendant_created_after_mark() {
    let w = world().await;
    let r = w.root("r").await;
    w.gate(&r, &[]);
    let p = w.admit(&r).await.unwrap();
    let rv = w.spawn_revoke(&r, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let c = w.child(&r, "late").await;
    w.gate(&c, &[&r]);
    assert_eq!(w.gates().mark_count(&c.grant_id), 0, "not marked itself");
    assert!(w.gates().is_pending(&c.grant_id));
    assert_eq!(
        w.admit(&c).await.unwrap_err(),
        SignRefusal::NarrowingPending
    );
    drop(p);
    rv.await.unwrap();
}

/// Round 1 marks every new descendant before it releases any gate.
#[tokio::test(start_paused = true)]
async fn round_one_marks_new_descendants_before_releasing_gates() {
    let w = world().await;
    let r = w.root("r").await;
    w.gate(&r, &[]);
    let found: Arc<Mutex<Option<GrantId>>> = Arc::new(Mutex::new(None));
    let (ops, rr, f2) = (w.ops.clone(), r.clone(), found.clone());
    w.hook.act(1, marked, move || {
        let (ops, rr, f2) = (ops.clone(), rr.clone(), f2.clone());
        Box::pin(async move {
            let c = delegate_child(&ops, &rr, "new").await;
            // Its chain recorded without the root: only an explicit mark covers it.
            ops.signing_gates().retain(&c.grant_id, &[]);
            *f2.lock().unwrap() = Some(c.grant_id);
        })
    });
    let marked_while_released = Arc::new(AtomicBool::new(false));
    let (gates, f3, flag) = (
        w.gates().clone(),
        found.clone(),
        marked_while_released.clone(),
    );
    // The first point after round 1's release.
    w.hook.act(
        1,
        |_, p| {
            matches!(
                p,
                NarrowingPoint::BeforeRead(NarrowingRead::Subtree { round: 1, .. })
            )
        },
        move || {
            let (gates, f3, flag) = (gates.clone(), f3.clone(), flag.clone());
            Box::pin(async move {
                let c = f3.lock().unwrap().clone().unwrap();
                flag.store(
                    gates.mark_count(&c) == 1 && gates.is_pending(&c),
                    Ordering::SeqCst,
                );
            })
        },
    );
    w.revoke(&r, "rv").await;
    assert!(marked_while_released.load(Ordering::SeqCst));
    assert_eq!(w.report(NarrowingKind::Revoke).rounds, 1);
}

/// A delegation re-checks the mark after each awaited acquisition and once more before
/// the child's first install.
#[tokio::test(start_paused = true)]
async fn delegation_rechecks_pending_after_each_awaited_acquisition_and_before_install() {
    let w = world().await;
    let r = w.root("r").await;
    let a = w.child(&r, "a").await;
    w.gate(&r, &[]);
    w.gate(&a, &[&r]);
    // Awaited acquisition: A is held exclusively; the mark comes while it waits.
    let mut holder = w.gates().begin_narrowing([]);
    holder.acquire(&a.grant_id).await.unwrap();
    let (gates, aid, rid) = (w.gates().clone(), a.grant_id.clone(), r.grant_id.clone());
    let d = tokio::spawn(async move {
        gates
            .hold_for_delegation(&aid, std::slice::from_ref(&rid), Duration::from_secs(5))
            .await
            .map(|_| ())
    });
    settle().await;
    let mark = w.gates().begin_narrowing([r.grant_id.clone()]);
    drop(holder);
    assert_eq!(d.await.unwrap().unwrap_err(), GateError::Pending);
    drop(mark);
    // Before install: obtained, then the mark appears.
    let hold = w
        .gates()
        .hold_for_delegation(
            &a.grant_id,
            std::slice::from_ref(&r.grant_id),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(!hold.is_pending());
    let mark = w.gates().begin_narrowing([r.grant_id.clone()]);
    assert!(hold.is_pending(), "the install aborts fail closed");
    drop(hold);
    drop(mark);
}

/// Spawn a delegation that holds `parent`'s chain until `until` (virtual, from now),
/// then creates a child (gated) and releases.
fn pre_mark_delegation(
    w: &W,
    hold: heimdall_app::managed::DelegationHold,
    parent: &EnsureData,
    until: Duration,
    tag: &'static str,
) -> tokio::task::JoinHandle<EnsureData> {
    let (ops, p) = (w.ops.clone(), parent.clone());
    tokio::spawn(async move {
        tokio::time::sleep(until).await;
        let c = delegate_child(&ops, &p, tag).await;
        ops.signing_gates()
            .retain(&c.grant_id, std::slice::from_ref(&p.grant_id));
        drop(hold);
        c
    })
}

/// §17.13 item 1, the round-5 multi-root countermodel: 8 roots, 9 grants, a pre-mark
/// delegation ending at 9.9 s, 2 s reads, no post-mark holder. It commits at about
/// 29.9 s, within `H + R(N)` (about 32 s), is reported over the 20 s target and never
/// aborted, and nothing is released after the mark.
#[tokio::test(start_paused = true)]
async fn multi_root_countermodel_within_derived_bound() {
    let reads = Duration::from_secs(2);
    let w = world_with(Opts {
        limits: Limits {
            narrowing_read_budget: reads,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    *w.hook.t_read.lock().unwrap() = reads;
    let mut roots = Vec::new();
    for i in 0..8 {
        let g = w.root(&format!("m{i}")).await;
        w.gate(&g, &[]);
        roots.push(g);
    }
    let hold = w
        .gates()
        .hold_for_delegation(&roots[0].grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let start = Instant::now();
    let d = pre_mark_delegation(&w, hold, &roots[0], Duration::from_millis(9900), "mr");
    let ops = w.ops.clone();
    let at = plus(w.clock.wall(), HOUR);
    let cut = tokio::spawn(async move {
        ops.policy(
            &owner(),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await
        .map(|_| ())
    });
    w.hook.wait_marked(NarrowingKind::Cutoff).await;
    let signers = Arc::new(Signers::default());
    let late = signers.spawn(&w.ops, &roots[3], Duration::ZERO);
    cut.await.unwrap().unwrap();
    let child = d.await.unwrap();
    late.await.unwrap();
    let r = w.report(NarrowingKind::Cutoff);
    assert_eq!((r.members, r.roots, r.rounds), (9, 8, 1), "{r:?}");
    assert_eq!(start.elapsed(), Duration::from_millis(29_900));
    assert_eq!(r.elapsed, Duration::from_millis(29_900));
    let terms = BoundTerms::of(&w.limits);
    assert_eq!(r.bound, terms.h + terms.work(9, 8));
    assert!(r.elapsed <= r.bound);
    assert!(
        r.over_target,
        "reported past the 20 s target, never aborted"
    );
    signers.none_enqueued_after(mark_of(&w, NarrowingKind::Cutoff));
    assert_eq!(
        signers.refused_at_admit.lock().unwrap().as_slice(),
        &[SignRefusal::NarrowingPending]
    );
    let _ = child;
}

/// §17.13 item 1, the overlapping-narrowing countermodel: an earlier narrowing whose
/// cleanup is held at 5 s and whose reads are at the budget, and a later one sharing a
/// grant. The later commits within `H + R(earlier) + R(later)` without waiting for the
/// earlier one's cleanup, and nothing is released after either mark.
#[tokio::test(start_paused = true)]
async fn overlapping_narrowings_countermodel_within_derived_bound() {
    let w = world().await;
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
    *w.hook.cleanup_hold.lock().unwrap() = Some((NarrowingKind::Revoke, Duration::from_secs(5)));
    let a = w.root("a").await;
    let b = w.root("b").await;
    w.gate(&a, &[]);
    w.gate(&b, &[]);
    let signers = Arc::new(Signers::default());
    let pre = signers.spawn(&w.ops, &a, w.limits.signing_holder_max);
    settle().await;
    let earlier = w.spawn_revoke(&a, "rv-a");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let ops = w.ops.clone();
    let at = plus(w.clock.wall(), HOUR);
    let later = tokio::spawn(async move {
        ops.policy(
            &owner(),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await
        .map(|_| ())
    });
    later.await.unwrap().unwrap();
    let later_done = Instant::now();
    earlier.await.unwrap();
    pre.await.unwrap();
    let e = w.report(NarrowingKind::Revoke);
    let l = w.report(NarrowingKind::Cutoff);
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
    signers.none_enqueued_after(mark_of(&w, NarrowingKind::Revoke));
}

/// The 20 s target at the §5 item 17 budgets, with a pre-mark holder at `H`, 16 roots
/// and round 1: within `H + R ≈ 14.1 s` with no earlier overlap, and within
/// `H + 2R ≈ 18.2 s` behind one earlier overlapping narrowing.
#[tokio::test(start_paused = true)]
async fn narrowing_commit_target_20s_at_budgets() {
    for overlap in [false, true] {
        let w = world().await;
        *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
        *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
        let mut roots = Vec::new();
        for i in 0..16 {
            let g = w.root(&format!("t{i}")).await;
            w.gate(&g, &[]);
            roots.push(g);
        }
        let hold = w
            .gates()
            .hold_for_delegation(&roots[0].grant_id, &[], Duration::from_secs(1))
            .await
            .unwrap();
        let d = pre_mark_delegation(&w, hold, &roots[0], w.limits.signing_gate_max_wait, "tg");
        let earlier = overlap.then(|| w.spawn_revoke(&roots[0], "rv-e"));
        if overlap {
            w.hook.wait_marked(NarrowingKind::Revoke).await;
        }
        let ops = w.ops.clone();
        let at = plus(w.clock.wall(), HOUR);
        ops.policy(
            &owner(),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await
        .unwrap();
        d.await.unwrap();
        if let Some(e) = earlier {
            e.await.unwrap();
        }
        let r = w.report(NarrowingKind::Cutoff);
        let terms = BoundTerms::of(&w.limits);
        let budget_r = terms.work(
            w.limits.narrowing_set_budget,
            w.limits.narrowing_root_budget,
        );
        let target = if overlap {
            terms.h + budget_r * 2
        } else {
            terms.h + budget_r
        };
        assert_eq!(r.earlier.len(), usize::from(overlap), "{r:?}");
        assert!(r.elapsed <= target, "overlap {overlap}: {r:?}");
        assert!(r.elapsed <= w.limits.narrowing_gate_wait_max);
        assert!(!r.over_target);
    }
}

/// A holder that keeps the gate past every bound (a 25 s delegation overrun): the
/// narrowing waits, commits, and reports `narrowing_over_target`. It is never aborted.
#[tokio::test(start_paused = true)]
async fn narrowing_never_aborts_for_time_reports_over_target() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let hold = w
        .gates()
        .hold_for_delegation(&g.grant_id, &[], Duration::from_secs(1))
        .await
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(25)).await;
        drop(hold);
    });
    let data = w.revoke(&g, "rv").await;
    release.await.unwrap();
    assert!(data.local_applied);
    let r = w.report(NarrowingKind::Revoke);
    assert!(r.elapsed >= Duration::from_secs(25));
    assert!(r.over_target);
    assert!(w.ops.narrowing_reports().iter().any(|x| x.over_target));
}

/// §17.14 item 2: a re-validation that finds members no round held (injected twice: at
/// round 1's re-validation, and at the commit's re-read) is the `narrowing_set_grew`
/// defect: reported, another round runs, and the narrowing commits; nothing is
/// released after the mark.
#[tokio::test(start_paused = true)]
async fn injected_set_growth_runs_another_round_and_commits() {
    let w = world().await;
    let r = w.root("r").await;
    w.gate(&r, &[]);
    let signers = Arc::new(Signers::default());
    let pre = signers.spawn(&w.ops, &r, Duration::from_secs(2));
    settle().await;
    let inject = |w: &W,
                  times: usize,
                  tag: &'static str,
                  when: fn(NarrowingKind, &NarrowingPoint) -> bool| {
        let (ops, rr) = (w.ops.clone(), r.clone());
        w.hook.act(times, when, move || {
            let (ops, rr) = (ops.clone(), rr.clone());
            Box::pin(async move {
                let c = delegate_child(&ops, &rr, tag).await;
                ops.signing_gates()
                    .retain(&c.grant_id, std::slice::from_ref(&rr.grant_id));
            })
        });
    };
    inject(&w, 1, "g0", marked);
    inject(&w, 1, "g1", |_, p| {
        matches!(
            p,
            NarrowingPoint::BeforeRead(NarrowingRead::Revalidate { round: 1 })
        )
    });
    inject(&w, 1, "g2", |_, p| {
        matches!(p, NarrowingPoint::BeforeCommit)
    });
    let data = w.revoke(&r, "rv").await;
    pre.await.unwrap();
    assert!(data.local_applied);
    let report = w.report(NarrowingKind::Revoke);
    assert!(report.set_grew);
    assert!(report.rounds >= 3, "{report:?}");
    assert_eq!(report.members, 4);
    assert_eq!(w.tombstone(&r).unwrap().cascade.len(), 3);
    signers.none_enqueued_after(mark_of(&w, NarrowingKind::Revoke));
}

/// "Earlier marks go first": a later narrowing that needs a gate covered by an earlier
/// one's mark waits for it to finish instead of queuing; both complete.
#[tokio::test(start_paused = true)]
async fn later_narrowing_defers_to_earlier_mark_no_deadlock() {
    let w = world().await;
    let p = w.root("p").await;
    let a = w.child(&p, "a").await;
    w.gate(&p, &[]);
    w.gate(&a, &[&p]);
    let permit = w.admit(&a).await.unwrap();
    let earlier = w.spawn_revoke(&a, "rv-a");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    let later = w.spawn_revoke(&p, "rv-p");
    w.hook
        .wait("the later mark", |l| {
            l.iter()
                .filter(|(_, _, p)| matches!(p, NarrowingPoint::Marked { .. }))
                .count()
                == 2
        })
        .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(permit);
    tokio::time::timeout(Duration::from_secs(60), async {
        earlier.await.unwrap();
        later.await.unwrap();
    })
    .await
    .expect("no deadlock");
    let log = w.hook.log();
    let reports: Vec<NarrowingReport> = w.hook.reports();
    let (e, l) = (&reports[0], &reports[1]);
    assert!(e.seq < l.seq);
    assert_eq!(l.earlier.len(), 1);
    let earlier_released = log
        .iter()
        .position(|(_, _, pt)| matches!(pt, NarrowingPoint::Released))
        .unwrap();
    let later_acquired_a = log
        .iter()
        .rposition(|(_, _, pt)| matches!(pt, NarrowingPoint::Acquired { held, .. } if held.contains(&a.grant_id)))
        .unwrap();
    assert!(earlier_released < later_acquired_a);
}

/// Slot and binding files are removed only after the gates are released. Wave 0 has
/// no slot files: the ordering is asserted at the cleanup point, where the gate is
/// already free and the narrowing's marks are cleared (U10 wires the removal there).
#[tokio::test(start_paused = true)]
async fn slot_files_removed_only_after_gates_released() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let free = probe_free_at_cleanup(&w, &g);
    w.revoke(&g, "rv").await;
    cleanup_after_release(&w, &g);
    assert!(free.load(Ordering::SeqCst));
    assert_eq!(w.gates().mark_count(&g.grant_id), 0);
}

/// The commit comes within the derived bound and is reported: in the result's
/// timestamps, in `narrowing_reports`, and at the hook, with the terms it used.
#[tokio::test(start_paused = true)]
async fn narrowing_commit_within_derived_bound_and_reported() {
    let w = world().await;
    *w.hook.t_read.lock().unwrap() = w.limits.narrowing_read_budget;
    *w.hook.t_commit.lock().unwrap() = w.limits.narrowing_commit_budget;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let signers = Arc::new(Signers::default());
    let s = signers.spawn(&w.ops, &g, w.limits.signing_holder_max);
    settle().await;
    let data = w.revoke(&g, "rv").await;
    s.await.unwrap();
    let r = w.report(NarrowingKind::Revoke);
    assert_eq!(r.terms, BoundTerms::of(&w.limits));
    assert_eq!(r.bound, r.terms.h + r.terms.work(1, 1));
    assert!(r.elapsed <= r.bound);
    assert!(!r.over_target);
    assert_eq!(data.requested_at, Some(r.requested_at));
    assert_eq!(data.committed_at, Some(r.committed_at));
    assert_eq!(w.ops.narrowing_reports().last(), Some(&r));
    signers.none_enqueued_after(mark_of(&w, NarrowingKind::Revoke));
}

// =================================================================================
// Row 25: the lock revocation
// =================================================================================

/// One pass revokes every `revoke_on_lock` grant (cascade included, cause
/// `session_locked`) and then acknowledges the epoch.
#[tokio::test(start_paused = true)]
async fn on_session_lock_revokes_then_acknowledges() {
    let w = world_with(Opts {
        lock: LockBehavior::RevokeOnLock,
        ..Opts::default()
    })
    .await;
    let a = w.root("a").await;
    let b = w.root("b").await;
    let c = w.child(&a, "c").await;
    let lock = TestLock::new(LockState::Unlocked);
    lock.lock();
    let done = w
        .ops
        .on_session_lock(lock.lock_epoch(), lock.as_ref())
        .await
        .unwrap();
    assert_eq!(done.epoch, 1);
    assert_eq!(
        done.revoked.len(),
        2,
        "two roots; the child is in a cascade"
    );
    for g in [&a, &b] {
        assert_eq!(
            w.tombstone(g).unwrap().cause,
            RevocationCause::SessionLocked
        );
    }
    assert!(w.tombstone(&a).unwrap().cascade.contains(&c.grant_id));
    for g in [&a, &b, &c] {
        assert!(matches!(
            w.state(g),
            GrantState::Revoked | GrantState::Revoking
        ));
    }
    assert_eq!(lock.acked.lock().unwrap().len(), 1);
    assert!(!lock.lock_epoch().observed);
    assert_eq!(
        w.store
            .transaction(|tx| tx.acknowledged_lock_epoch())
            .unwrap(),
        Some(1)
    );
    // Nothing latched: nothing done, nothing acknowledged.
    let again = w
        .ops
        .on_session_lock(lock.lock_epoch(), lock.as_ref())
        .await
        .unwrap();
    assert!(again.revoked.is_empty());
    assert_eq!(lock.acked.lock().unwrap().len(), 1);
}

/// The epoch is acknowledged only after the revocations commit: not while a permit
/// holds the gate, and not at all when the commit fails (the lock stays latched).
#[tokio::test(start_paused = true)]
async fn epoch_acknowledged_only_after_revocations_commit() {
    let w = world_with(Opts {
        lock: LockBehavior::RevokeOnLock,
        ..Opts::default()
    })
    .await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let lock = TestLock::new(LockState::Unlocked);
    w.ops.set_session_lock_source(lock.clone());
    let p = w.admit(&g).await.unwrap();
    lock.lock();
    // A failing commit first: nothing acknowledged.
    let faults = w.faults.clone();
    w.hook.act(
        1,
        |_, p| matches!(p, NarrowingPoint::BeforeCommit),
        move || {
            faults.fail_commit.store(true, Ordering::SeqCst);
            Box::pin(async {})
        },
    );
    let (ops, l2) = (w.ops.clone(), lock.clone());
    let pass = tokio::spawn(async move {
        ops.on_session_lock(l2.lock_epoch(), l2.as_ref())
            .await
            .map(|_| ())
    });
    w.hook.wait_marked(NarrowingKind::SessionLock).await;
    assert!(lock.acked.lock().unwrap().is_empty());
    drop(p);
    assert!(pass.await.unwrap().is_err());
    assert!(lock.acked.lock().unwrap().is_empty());
    assert!(lock.lock_epoch().observed, "still latched");
    assert!(w.tombstone(&g).is_none());
    // The next pass commits, then acknowledges.
    let done = w
        .ops
        .on_session_lock(lock.lock_epoch(), lock.as_ref())
        .await
        .unwrap();
    assert_eq!(done.revoked, vec![g.grant_id.clone()]);
    let committed = w
        .hook
        .log()
        .iter()
        .rev()
        .find(|(_, k, p)| {
            *k == NarrowingKind::SessionLock && matches!(p, NarrowingPoint::UnderGates { .. })
        })
        .map(|(i, _, _)| *i)
        .unwrap();
    let acked = lock.acked.lock().unwrap()[0];
    assert_eq!(acked.0, 1);
    assert!(acked.1 >= committed);
    assert!(w.tombstone(&g).is_some());
}

// =================================================================================
// Row 26: owned-connection registration
// =================================================================================

/// Registration re-checks the grant in its transaction: an unknown binding, a
/// tombstoned grant and an ended grant are refused, and no row is written.
#[tokio::test(start_paused = true)]
async fn register_refused_for_ended_or_tombstoned_grant() {
    let w = world().await;
    let refused = |e: ConnError| match e {
        ConnError::RegistrationRefused(r) => r,
        other => panic!("{other:?}"),
    };
    let e = w
        .ops
        .register_owned_connection(
            &BindingId::from_random_bytes([4; 16]),
            1,
            t0(),
            "/usr/bin/ssh",
        )
        .await
        .unwrap_err();
    assert_eq!(refused(e), "binding_unknown");
    let g = w.root("a").await;
    w.revoke(&g, "rv").await;
    let e = w
        .ops
        .register_owned_connection(&g.binding_id, 1, t0(), "/usr/bin/ssh")
        .await
        .unwrap_err();
    assert_eq!(refused(e), "tombstoned");
    let h = w.root("b").await;
    tokio::time::advance(2 * HOUR + Duration::from_secs(1)).await;
    let e = w
        .ops
        .register_owned_connection(&h.binding_id, 1, t0(), "/usr/bin/ssh")
        .await
        .unwrap_err();
    assert_eq!(refused(e), "deadline_passed");
    w.ops.tick().await.unwrap();
    let e = w
        .ops
        .register_owned_connection(&h.binding_id, 1, t0(), "/usr/bin/ssh")
        .await
        .unwrap_err();
    assert_eq!(refused(e), "grant_ended");
    for x in [&g, &h] {
        assert!(
            w.store
                .transaction(|tx| tx.owned_connections_for_grant(&x.grant_id))
                .unwrap()
                .is_empty()
        );
    }
}

/// Registration and revocation are ordered by the gate: a registration before the
/// narrowing's mark writes its row, which the revocation then finds; one while it
/// waits is refused; one after its commit is refused by the re-check. Pausing a
/// registration inside its own transaction needs a store pause point that wave 0 does
/// not have (U7's Windows tests do it with the launcher).
#[tokio::test(start_paused = true)]
async fn register_ordered_with_revocation_by_gate() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let row = w
        .ops
        .register_owned_connection(&g.binding_id, 4242, t0(), "/usr/bin/ssh")
        .await
        .unwrap();
    assert_eq!(row.grant, g.grant_id);
    let p = w.admit(&g).await.unwrap();
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    assert!(
        w.ops
            .register_owned_connection(&g.binding_id, 4243, t0(), "/usr/bin/ssh")
            .await
            .is_err()
    );
    drop(p);
    rv.await.unwrap();
    let rows = w
        .store
        .transaction(|tx| tx.owned_connections_for_grant(&g.grant_id))
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the pre-mark row exists for the revocation to close"
    );
    assert_eq!(
        w.ops
            .register_owned_connection(&g.binding_id, 4244, t0(), "/usr/bin/ssh")
            .await
            .unwrap_err(),
        ConnError::RegistrationRefused("tombstoned".into())
    );
}

/// While a narrowing is pending on the grant, registration refuses with
/// `narrowing_pending` (the launcher kills the suspended child) and writes nothing.
#[tokio::test(start_paused = true)]
async fn registration_refused_while_pending() {
    let w = world().await;
    let g = w.root("a").await;
    let c = w.child(&g, "c").await;
    w.gate(&g, &[]);
    let n = w.gates().begin_narrowing([g.grant_id.clone()]);
    for b in [&g, &c] {
        assert_eq!(
            w.ops
                .register_owned_connection(&b.binding_id, 7, t0(), "/usr/bin/ssh")
                .await
                .unwrap_err(),
            ConnError::RegistrationRefused("narrowing_pending".into())
        );
    }
    drop(n);
    assert!(
        w.store
            .transaction(|tx| tx.owned_connections_for_grant(&g.grant_id))
            .unwrap()
            .is_empty()
    );
    assert!(
        w.ops
            .register_owned_connection(&g.binding_id, 7, t0(), "/usr/bin/ssh")
            .await
            .is_ok()
    );
}

// =================================================================================
// Row 27: revocation timestamps
// =================================================================================

/// `requested_at` is the wall time at admission, before the gate wait; it is the
/// operation's stored `created_at`.
#[tokio::test(start_paused = true)]
async fn revoke_requested_at_captured_at_admission_before_gate_wait() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    let asked = w.clock.wall();
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    drop(p);
    let data = rv.await.unwrap();
    assert_eq!(data.requested_at, Some(asked));
    assert!(data.committed_at.unwrap() >= plus(asked, Duration::from_secs(4)));
    assert_eq!(w.report(NarrowingKind::Revoke).requested_at, asked);
}

/// `committed_at` is read inside the tombstone transaction: it equals the tombstone's
/// `revoked_at` and comes after the gate was taken, not at the request.
#[tokio::test(start_paused = true)]
async fn revoke_committed_at_read_inside_tombstone_transaction() {
    let w = world().await;
    *w.hook.t_commit.lock().unwrap() = Duration::from_secs(1);
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let p = w.admit(&g).await.unwrap();
    let rv = w.spawn_revoke(&g, "rv");
    w.hook.wait_marked(NarrowingKind::Revoke).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(p);
    let data = rv.await.unwrap();
    let t = w.tombstone(&g).unwrap();
    assert_eq!(data.committed_at, Some(t.revoked_at));
    let before_commit = w
        .hook
        .at_of(|_, p| matches!(p, NarrowingPoint::BeforeCommit))
        .unwrap();
    let wall_before_commit = plus(t0(), before_commit - w.clock.start);
    assert!(
        t.revoked_at >= plus(wall_before_commit, Duration::from_secs(1)),
        "read in the commit"
    );
    assert!(data.requested_at.unwrap() < t.revoked_at);
}

/// A replay of the same `request_id` returns the stored originals.
#[tokio::test(start_paused = true)]
async fn revoke_replay_returns_original_timestamps() {
    let w = world().await;
    let g = w.root("a").await;
    w.gate(&g, &[]);
    let first = w.revoke(&g, "rv").await;
    assert!(first.requested_at.is_some() && first.committed_at.is_some());
    tokio::time::advance(Duration::from_secs(600)).await;
    let replay = w.revoke(&g, "rv").await;
    assert_eq!(replay.requested_at, first.requested_at);
    assert_eq!(replay.committed_at, first.committed_at);
}

/// Later cleanup (the supervisor's remote-revocation retries) never changes
/// `committed_at`, in the tombstone or in a replayed result.
#[tokio::test(start_paused = true)]
async fn committed_at_unaffected_by_cleanup_retries() {
    let w = world_with(Opts {
        limits: bounded(),
        ..Opts::default()
    })
    .await;
    let g = w.root("a").await;
    w.fake.arm(FakeStep::HangRevoke);
    let first = w.revoke(&g, "rv").await;
    assert_eq!(first.remote_pending, vec![g.grant_id.clone()]);
    let committed = first.committed_at.unwrap();
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(120)).await;
        w.fake.arm(FakeStep::HangRevoke);
        w.ops.retry_remote_revocation(&g.grant_id, 8).await.unwrap();
    }
    w.ops.retry_remote_revocation(&g.grant_id, 8).await.unwrap();
    assert_eq!(w.tombstone(&g).unwrap().revoked_at, committed);
    let replay = w.revoke(&g, "rv").await;
    assert_eq!(replay.committed_at, Some(committed));
    assert_eq!(replay.requested_at, first.requested_at);
}

// =================================================================================
// G-Q1, ruled: one gated member puts the whole set under the full protocol
// =================================================================================

/// The marks held by each member while every gate of round 0 is held.
fn marks_at_round0(w: &W, ids: Vec<GrantId>) -> Arc<Mutex<Vec<usize>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (gates, out) = (w.gates().clone(), seen.clone());
    w.hook.act(
        1,
        |_, p| matches!(p, NarrowingPoint::Acquired { round: 0, .. }),
        move || {
            let (gates, out, ids) = (gates.clone(), out.clone(), ids.clone());
            Box::pin(async move {
                *out.lock().unwrap() = ids.iter().map(|g| gates.mark_count(g)).collect();
            })
        },
    );
    seen
}

fn round0_held(w: &W) -> Vec<GrantId> {
    w.hook
        .log()
        .into_iter()
        .find_map(|(_, _, p)| match p {
            NarrowingPoint::Acquired { round: 0, held } => Some(held),
            _ => None,
        })
        .expect("round 0 ran")
}

fn marked_set(w: &W, kind: NarrowingKind) -> BTreeSet<GrantId> {
    w.hook
        .log()
        .into_iter()
        .find_map(|(_, k, p)| match p {
            NarrowingPoint::Marked { set, .. } if k == kind => Some(set.into_iter().collect()),
            _ => None,
        })
        .expect("marked")
}

/// A cascade R → {A, B} where only B has a gate: the whole cascade is marked, B's gate is
/// taken before the commit, keys are destroyed under it, and cleanup follows release.
#[tokio::test(start_paused = true)]
async fn gated_member_of_cascade_takes_full_protocol() {
    let w = world().await;
    let r = w.root("r").await;
    let a = w.child(&r, "a").await;
    let b = w.child(&r, "b").await;
    w.gate(&b, &[&r]);
    let all = vec![r.grant_id.clone(), a.grant_id.clone(), b.grant_id.clone()];
    let marks = marks_at_round0(&w, all.clone());
    let held_at_commit = Arc::new(AtomicBool::new(false));
    let (gates, bid, flag) = (
        w.gates().clone(),
        b.grant_id.clone(),
        held_at_commit.clone(),
    );
    w.hook.act(
        1,
        |_, p| matches!(p, NarrowingPoint::BeforeCommit),
        move || {
            let (gates, bid, flag) = (gates.clone(), bid.clone(), flag.clone());
            Box::pin(async move {
                let busy = gates.acquire_shared(&bid, Duration::from_millis(1)).await;
                flag.store(matches!(busy, Err(GateError::Timeout)), Ordering::SeqCst);
            })
        },
    );
    w.revoke(&r, "rv").await;
    let report = w.report(NarrowingKind::Revoke);
    assert!(
        report.seq.is_some(),
        "the full protocol, not the zero-gate commit"
    );
    assert_eq!(report.members, 3);
    assert_eq!(report.gates_held, 1);
    assert_eq!(
        marked_set(&w, NarrowingKind::Revoke),
        all.iter().cloned().collect::<BTreeSet<_>>()
    );
    assert_eq!(*marks.lock().unwrap(), vec![1, 1, 1], "every member marked");
    assert_eq!(round0_held(&w), vec![b.grant_id.clone()]);
    assert!(
        held_at_commit.load(Ordering::SeqCst),
        "the commit waits under B's gate"
    );
    let log = w.hook.log();
    let pos = |f: &dyn Fn(&NarrowingPoint) -> bool| log.iter().position(|(_, _, p)| f(p)).unwrap();
    let under = pos(&|p| {
        matches!(p, NarrowingPoint::UnderGates { destroy, held }
            if destroy.len() == 3 && held == &vec![b.grant_id.clone()])
    });
    let released = pos(&|p| matches!(p, NarrowingPoint::Released));
    let cleanup = pos(&|p| matches!(p, NarrowingPoint::Cleanup { .. }));
    assert!(under < released && released < cleanup);
    for g in &all {
        assert_eq!(w.gates().mark_count(g), 0, "marks cleared at the end");
    }
    assert_eq!(w.tombstone(&r).unwrap().cascade.len(), 2);
}

/// A lock pass over two roots and their children, only some gated (R1 and its child C
/// gated, R2 and its child D not): every member, ungated ones included, is marked;
/// the gated ones are acquired in global order (depth, then ID); every member's key is
/// destroyed under the gates; release precedes cleanup.
#[tokio::test(start_paused = true)]
async fn mixed_gated_and_ungated_set_takes_full_protocol_for_whole_set() {
    let w = world_with(Opts {
        lock: LockBehavior::RevokeOnLock,
        ..Opts::default()
    })
    .await;
    let r1 = w.root("r1").await;
    let r2 = w.root("r2").await;
    let c = w.child(&r1, "c").await;
    let d = w.child(&r2, "d").await;
    w.gate(&r1, &[]);
    w.gate(&c, &[&r1]);
    let all = vec![
        r1.grant_id.clone(),
        r2.grant_id.clone(),
        c.grant_id.clone(),
        d.grant_id.clone(),
    ];
    let marks = marks_at_round0(&w, all.clone());
    let lock = TestLock::new(LockState::Unlocked);
    lock.lock();
    let done = w
        .ops
        .on_session_lock(lock.lock_epoch(), lock.as_ref())
        .await
        .unwrap();
    assert_eq!(done.revoked.len(), 2);
    let report = done.report.unwrap();
    assert!(report.seq.is_some(), "the full protocol for the whole set");
    assert_eq!((report.members, report.roots, report.gates_held), (4, 2, 2));
    assert_eq!(
        marked_set(&w, NarrowingKind::SessionLock),
        all.iter().cloned().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        *marks.lock().unwrap(),
        vec![1, 1, 1, 1],
        "ungated members marked too"
    );
    assert_eq!(
        round0_held(&w),
        vec![r1.grant_id.clone(), c.grant_id.clone()],
        "gated members in global order; ungated ones have nothing to acquire"
    );
    let log = w.hook.log();
    let under = log
        .iter()
        .position(|(_, _, p)| {
            matches!(p, NarrowingPoint::UnderGates { destroy, .. }
                if all.iter().all(|g| destroy.contains(g)))
        })
        .expect("every member's key destroyed under the gates");
    let released = log
        .iter()
        .position(|(_, _, p)| matches!(p, NarrowingPoint::Released))
        .unwrap();
    let cleanup = log
        .iter()
        .position(|(_, _, p)| matches!(p, NarrowingPoint::Cleanup { grants } if grants.len() == 4))
        .unwrap();
    assert!(under < released && released < cleanup);
    for g in [&r1, &r2] {
        assert_eq!(
            w.tombstone(g).unwrap().cause,
            RevocationCause::SessionLocked
        );
    }
    assert_eq!(lock.acked.lock().unwrap().len(), 1);
}
