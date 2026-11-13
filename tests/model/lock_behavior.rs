//! M03 U9: lock behaviour through the production `heimdall_app::Operations`
//! (ADR-0008 D9; §17.1 items 9 and 18, §17.15 item 12, §17.16 items 1 and 6; m03-plan
//! U9). Hosted by heimdall-app (target `model_lock_behavior`).
//!
//! Harness as `tests/model/narrowing_m03.rs`: an in-memory store,
//! `testkit::FakeCredentialAdapter`, and a **paused** tokio clock that the operations
//! clock (`TokioClock`) reads, so every duration is virtual and deterministic. The lock
//! source is testkit's `FakeSessionLockSource` (the latched epoch); the lock passes run
//! through `heimdall_app::lock::run_lock_passes`, the driver U10 runs from the
//! supervisor. **The consumer pause** is U11's `FakeSessionLockSource::pause_consumer` /
//! `resume_consumer` (`testkit::lock`): it withholds the source's wake-ups from the
//! driver while transitions still latch.
//!
//! Two profiles: `dev` under policy `pol` (`continue`) and `ops` under `pol-ops`
//! (`revoke_on_lock`), so a `continue` grant and a `revoke_on_lock` grant coexist.
//! Every value is synthetic; no owner key, agent or keychain is touched, and nothing
//! locks a screen.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::lock::{
    self, LockPassConfig, LockPassReport, LockSignal, label_completed, lock_warnings,
    run_lock_passes,
};
use heimdall_app::operations::narrowing::{
    HookFuture, NarrowingHook, NarrowingKind, NarrowingPoint, NarrowingRead,
};
use heimdall_app::operations::{IssuanceFacts, IssuanceRequest, Limits, MANAGED_CERTIFICATE};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, LockState,
    PrepareOutcome, SessionLockSource, SignRefusal, SignatureAuthority, SignatureRequestFacts,
    SignatureSubject, SignerEndpoint,
};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::envelope::m03_warning;
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, DeviceId, EnrollmentId, EnvironmentId, GrantId,
    IdentityId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::request::{
    DeadlineIntent, DecideRequest, DelegateRequest, DestinationScopeEnforcement, Enforcement,
    EnsureData, EnsureRequest, ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry,
    PolicyAction, RefreshDependency, RequiredCapabilities, RevocationStatus, Verdict, WaitMode,
    WorkloadIsolation,
};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{EXTENSION_PTY, IssuanceState};
use heimdall_domain::managed::LockEpoch;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::revocation::RevocationCause;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, IssuerRecord, Store};
use heimdall_testkit::lock::FakeSessionLockSource;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync};
use tokio::sync::Notify;
use tokio::time::Instant;

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-03T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn owner_ctx() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    }
}

fn owner() -> Caller {
    Caller::unattended(owner_ctx())
}

fn attended() -> Caller {
    Caller {
        context: owner_ctx(),
        attendance: Attendance::Attended { since: t0() },
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

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
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
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: plus(t0(), 12 * HOUR),
        offline_until: plus(t0(), HOUR),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
    }
}

fn descriptor(mechanism: &str) -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: mechanism.into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

fn dev() -> ProfileId {
    ProfileId::parse("dev").unwrap()
}

fn ops_profile() -> ProfileId {
    ProfileId::parse("ops").unwrap()
}

fn pol() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn pol_ops() -> PolicyId {
    PolicyId::parse("pol-ops").unwrap()
}

fn standing(id: PolicyId, profile: ProfileId, lock: LockBehavior) -> StandingPolicy {
    StandingPolicy {
        id,
        revision: PolicyRevision(1),
        profile,
        workspace: None,
        scope: Scope {
            pairs: [h1(), pair("h2", "deploy")].into_iter().collect(),
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
            for p in [dev(), ops_profile()] {
                tx.upsert_profile(&ProfileDefinition {
                    id: p,
                    revision: 1,
                    scope: Scope {
                        pairs: [h1(), pair("h2", "deploy")].into_iter().collect(),
                        capabilities: ssh_only(),
                    },
                    label: None,
                })?;
            }
            tx.upsert_policy(&standing(pol(), dev(), LockBehavior::Continue), false)?;
            tx.upsert_policy(
                &standing(pol_ops(), ops_profile(), LockBehavior::RevokeOnLock),
                false,
            )?;
            for d in ["h1", "h2"] {
                tx.upsert_destination(&DestinationRecord {
                    id: DestinationId::parse(d).unwrap(),
                    alias: d.into(),
                    revision: 1,
                    definition: DestinationDefinition::Observed,
                    label: None,
                    updated_at: t0(),
                })?;
            }
            Ok(())
        })
        .unwrap();
}

/// The operations clock on the (paused) tokio clock: wall = `t0 + elapsed`, one boot.
struct TokioClock {
    start: Instant,
}

impl Clock for TokioClock {
    fn wall(&self) -> Timestamp {
        plus(t0(), Instant::now().saturating_duration_since(self.start))
    }
    fn continuous(&self) -> Duration {
        Duration::from_secs(1000) + Instant::now().saturating_duration_since(self.start)
    }
    fn boot_id(&self) -> BootId {
        BootId("tokio-boot-1".into())
    }
}

/// A store fault hook that can fail the next commit.
#[derive(Default)]
struct Faults {
    fail_commit: AtomicBool,
}

impl FaultHook for Faults {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == FaultPoint::BeforeCommit && self.fail_commit.swap(false, Ordering::SeqCst) {
            return FaultAction::Fail;
        }
        FaultAction::Continue
    }
}

type HookLog = Vec<(Instant, NarrowingKind, NarrowingPoint)>;

/// The narrowing hook: logs every point with its instant; optionally arms a store
/// commit failure at the first lock pass's initial read (in the zero-gate path that
/// read's transaction is the commit).
#[derive(Default)]
struct Hook {
    log: Mutex<HookLog>,
    fail_first_lock_commit: Mutex<Option<Arc<Faults>>>,
}

impl NarrowingHook for Hook {
    fn at<'a>(&'a self, kind: NarrowingKind, point: NarrowingPoint) -> HookFuture<'a> {
        Box::pin(async move {
            if kind == NarrowingKind::SessionLock
                && point == NarrowingPoint::BeforeRead(NarrowingRead::Initial)
                && let Some(f) = self.fail_first_lock_commit.lock().unwrap().take()
            {
                f.fail_commit.store(true, Ordering::SeqCst);
            }
            self.log.lock().unwrap().push((Instant::now(), kind, point));
        })
    }
}

struct W {
    store: Arc<Store>,
    clock: Arc<TokioClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    faults: Arc<Faults>,
    ops: Operations,
    hook: Arc<Hook>,
    lock: Arc<FakeSessionLockSource>,
}

fn config(w: &W) -> OperationsConfig {
    config_of(&w.store, &w.clock, &w.sync, &w.fake)
}

fn config_of(
    store: &Arc<Store>,
    clock: &Arc<TokioClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    }
}

async fn world_with(mechanism: &str) -> W {
    let faults = Arc::new(Faults::default());
    let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
    seed(&store);
    let clock = Arc::new(TokioClock {
        start: Instant::now(),
    });
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let script: Vec<FakeStep> = (0..32).map(|_| FakeStep::Prepare(outcome())).collect();
    let fake = FakeCredentialAdapter::new(descriptor(mechanism), script);
    let ops = Operations::start(config_of(&store, &clock, &sync, &fake))
        .await
        .unwrap();
    let hook = Arc::new(Hook::default());
    ops.set_narrowing_hook(hook.clone());
    let lock = Arc::new(FakeSessionLockSource::new(LockState::Unlocked));
    ops.set_session_lock_source(lock.clone());
    W {
        store,
        clock,
        sync,
        fake,
        faults,
        ops,
        hook,
        lock,
    }
}

async fn world() -> W {
    world_with("fake_agent").await
}

impl W {
    async fn grant(&self, profile: ProfileId, tag: &str) -> EnsureData {
        let r = self
            .ops
            .ensure(
                &owner(),
                EnsureRequest {
                    profile,
                    profile_revision: None,
                    scope: [h1()].into_iter().collect(),
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
                    scope: [h1()].into_iter().collect(),
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

    /// Create the grant's signing gate (its first credential instance; U10).
    fn gate(&self, g: &EnsureData) {
        self.ops.signing_gates().retain(&g.grant_id, &[]);
    }

    async fn admit_on(ops: &Operations, g: &EnsureData) -> Result<(), SignRefusal> {
        ops.admit(&SignatureRequestFacts {
            endpoint: SignerEndpoint::Binding(g.binding_id.clone()),
            subject: SignatureSubject::Grant(g.grant_id.clone()),
            pair: h1(),
            key_fingerprint: "SHA256:fixture".into(),
        })
        .await
        .map(drop)
    }

    async fn admit(&self, g: &EnsureData) -> Result<(), SignRefusal> {
        Self::admit_on(&self.ops, g).await
    }

    fn state(&self, g: &EnsureData) -> GrantState {
        self.store
            .transaction(|tx| tx.grant(&g.grant_id))
            .unwrap()
            .unwrap()
            .state
    }

    fn revoked(&self, g: &EnsureData) -> bool {
        matches!(self.state(g), GrantState::Revoked | GrantState::Revoking)
    }

    fn tombstone_cause(&self, g: &EnsureData) -> Option<RevocationCause> {
        self.store
            .transaction(|tx| tx.tombstone(&g.grant_id))
            .unwrap()
            .map(|t| t.cause)
    }

    fn events(&self, ty: EventType) -> Vec<serde_json::Value> {
        self.store
            .transaction(|tx| {
                tx.stored_events_after(
                    &env_id(),
                    0,
                    &EventFilter {
                        operation_id: None,
                        types: vec![ty],
                    },
                    10_000,
                )
            })
            .unwrap()
            .events
            .into_iter()
            .map(|e| e.event.payload)
            .collect()
    }

    /// `revoked_locally` lifecycle events with cause `session_locked`.
    fn lock_revocation_events(&self) -> usize {
        self.events(EventType::CredentialLifecycle)
            .iter()
            .filter(|p| p["event"] == "revoked_locally" && p["cause"] == "session_locked")
            .count()
    }

    fn policy(&self, id: &PolicyId) -> StandingPolicy {
        self.store.transaction(|tx| tx.policy(id)).unwrap().unwrap()
    }

    fn generation(&self) -> u64 {
        self.store
            .transaction(|tx| tx.authority_generation())
            .unwrap()
            .0
    }

    /// Run the driver over `source` until the returned stop is notified.
    fn drive(&self, source: Arc<dyn SessionLockSource>, cfg: LockPassConfig) -> Driver {
        let stop = Arc::new(Notify::new());
        let s2 = stop.clone();
        let ops = self.ops.clone();
        let task = tokio::spawn(async move {
            run_lock_passes(ops, source, cfg, async move { s2.notified().await }).await
        });
        Driver { stop, task }
    }
}

struct Driver {
    stop: Arc<Notify>,
    task: tokio::task::JoinHandle<LockPassReport>,
}

impl Driver {
    async fn stop(self) -> LockPassReport {
        self.stop.notify_one();
        self.task.await.unwrap()
    }
}

/// Wait (virtual time) until `f` holds.
async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..20_000 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn settle_for(d: Duration) {
    tokio::time::sleep(d).await;
}

fn fast() -> LockPassConfig {
    LockPassConfig {
        min_interval: Duration::from_millis(50),
        retry_after: Duration::from_millis(100),
    }
}

/// Records each acknowledgement with its instant, delegating everything to the fake.
struct Recording {
    inner: Arc<FakeSessionLockSource>,
    acks: Mutex<Vec<(u64, Instant)>>,
}

impl Recording {
    fn new(inner: Arc<FakeSessionLockSource>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            acks: Mutex::new(Vec::new()),
        })
    }
}

impl SessionLockSource for Recording {
    fn state(&self) -> LockState {
        self.inner.state()
    }
    fn lock_epoch(&self) -> LockEpoch {
        self.inner.lock_epoch()
    }
    fn acknowledge(&self, epoch: u64) {
        self.acks.lock().unwrap().push((epoch, Instant::now()));
        self.inner.acknowledge(epoch);
    }
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.inner.changed()
    }
}

// =================================================================================
// Positive
// =================================================================================

/// ADR-0008 D9 item 3, §17.1 item 9 (M03-R09): a lock that is over before the consumer
/// looks still revokes. The driver is paused (it receives no wake-up) while the session
/// locks and unlocks; on resuming it reads `unlocked` but the latched epoch, and its
/// one pass revokes the `revoke_on_lock` grant and acknowledges that epoch.
#[tokio::test(start_paused = true)]
async fn lock_then_unlock_while_consumer_paused_still_revokes() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let c = w.grant(dev(), "c").await;
    let src = Recording::new(w.lock.clone());
    let driver = w.drive(src.clone(), fast());
    settle_for(Duration::from_millis(200)).await;
    w.lock.pause_consumer();
    w.lock.set_state(LockState::Locked);
    w.lock.set_state(LockState::Unlocked);
    settle_for(Duration::from_secs(5)).await;
    assert!(!w.revoked(&r), "the paused consumer has done nothing yet");
    assert_eq!(src.state(), LockState::Unlocked);
    assert_eq!(
        src.lock_epoch(),
        LockEpoch {
            epoch: 1,
            observed: true
        },
        "the lock stays latched across the unlock"
    );
    w.lock.resume_consumer();
    until("the lock pass", || w.revoked(&r)).await;
    until("the acknowledgement", || !src.lock_epoch().observed).await;
    assert_eq!(w.tombstone_cause(&r), Some(RevocationCause::SessionLocked));
    assert_eq!(w.state(&c), GrantState::Active, "`continue` is untouched");
    let acked: Vec<u64> = src.acks.lock().unwrap().iter().map(|a| a.0).collect();
    assert_eq!(acked, vec![1]);
    let report = driver.stop().await;
    assert_eq!(report.passes, 1);
    assert_eq!(report.revoked, vec![r.grant_id.clone()]);
}

/// G-Q12 (confirmed as built): the epoch is acknowledged only after the pass's
/// revocations commit. The first lock pass's commit fails (a store fault): nothing is
/// acknowledged and the lock stays latched; the driver retries, the retry commits, and
/// only then is the epoch acknowledged (at or after the commit's `UnderGates` point).
#[tokio::test(start_paused = true)]
async fn epoch_acknowledged_only_after_revocations_commit() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    *w.hook.fail_first_lock_commit.lock().unwrap() = Some(w.faults.clone());
    let src = Recording::new(w.lock.clone());
    let driver = w.drive(src.clone(), fast());
    w.lock.set_state(LockState::Locked);
    until("the lock pass", || w.revoked(&r)).await;
    until("the acknowledgement", || !src.lock_epoch().observed).await;
    let report = driver.stop().await;
    assert_eq!(report.failures, 1, "the first commit failed");
    assert_eq!(report.passes, 1, "the retry committed");
    let acks = src.acks.lock().unwrap().clone();
    assert_eq!(
        acks.len(),
        1,
        "acknowledged once, after the committed pass only"
    );
    assert_eq!(acks[0].0, 1);
    let committed = w
        .hook
        .log
        .lock()
        .unwrap()
        .iter()
        .find(|(_, k, p)| {
            *k == NarrowingKind::SessionLock && matches!(p, NarrowingPoint::UnderGates { .. })
        })
        .map(|(i, _, _)| *i)
        .expect("a committed lock narrowing");
    assert!(acks[0].1 >= committed);
    assert_eq!(
        w.store
            .transaction(|tx| tx.acknowledged_lock_epoch())
            .unwrap(),
        Some(1),
        "the epoch is stored in the revocation's commit"
    );
}

/// F19 (§17.1 item 18): the disclosure is conditional and states the saved limits:
/// each `continue` policy's window and cutoff, the verified/not-yet clause, the
/// `revoke_on_lock` policies and the floor, and the hint only where a signal exists.
#[tokio::test(start_paused = true)]
async fn disclosure_is_conditional_and_states_saved_limits() {
    use LockBehavior::{Continue, RevokeOnLock};
    let mac = LockSignal::MacosScreenLock;
    let p = standing(pol(), dev(), Continue);
    let d = lock::disclosure(std::slice::from_ref(&p), Continue, false, mac);
    assert_eq!(d.behavior, Continue);
    assert!(
        d.text
            .contains("keep working while your screen or password manager is locked")
    );
    assert!(
        d.text
            .contains("at most 2h after approval, under your saved policy \"pol\""),
        "{}",
        d.text
    );
    assert!(
        d.text
            .contains("On this computer that has not been verified yet."),
        "{}",
        d.text
    );
    assert!(d.text.contains("set lock behaviour to \"revoke on lock\""));
    assert_eq!(d.limits.len(), 1);
    assert_eq!(d.limits[0].max_window, 2 * HOUR);
    assert!(d.warnings.is_empty());

    // Verified (the claim table), and a cutoff.
    let cutoff = plus(t0(), 3 * HOUR);
    let mut pc = p.clone();
    pc.cutoff_at = Some(cutoff);
    let d = lock::disclosure(std::slice::from_ref(&pc), Continue, true, mac);
    assert!(d.text.contains("has been verified."), "{}", d.text);
    assert!(!d.text.contains("not been verified"));
    assert!(
        d.text.contains(&format!("(no new work after {cutoff})")),
        "{}",
        d.text
    );

    // Two continue policies with their own limits; a revoke_on_lock one says so instead.
    let mut long = standing(PolicyId::parse("pol-long").unwrap(), dev(), Continue);
    long.max_window = 12 * HOUR;
    let ro = standing(pol_ops(), ops_profile(), RevokeOnLock);
    let d = lock::disclosure(&[ro.clone(), long, p.clone()], Continue, false, mac);
    assert_eq!(d.behavior, RevokeOnLock, "the strictest over the policies");
    assert!(
        d.text
            .contains("at most 2h after approval, under your saved policy \"pol\"")
    );
    assert!(
        d.text
            .contains("at most 12h after approval, under your saved policy \"pol-long\"")
    );
    assert!(
        d.text
            .contains("Work under your saved policy \"pol-ops\" ends when you lock the screen")
    );
    assert!(
        !d.text
            .contains("after approval, under your saved policy \"pol-ops\"")
    );

    // Only revoke_on_lock: no continuity sentence, no hint.
    let d = lock::disclosure(std::slice::from_ref(&ro), Continue, false, mac);
    assert!(!d.text.contains("keep working"), "{}", d.text);
    assert!(!d.text.contains("set lock behaviour"));

    // The R3 floor ends all approved work at a lock.
    let d = lock::disclosure(std::slice::from_ref(&p), RevokeOnLock, false, mac);
    assert_eq!(d.behavior, RevokeOnLock);
    assert!(
        d.text.contains("[session] lock_behavior = \"revoke\""),
        "{}",
        d.text
    );
    assert!(!d.text.contains("keep working"));

    // No signal here: the hint says revoke on lock is unavailable.
    let d = lock::disclosure(std::slice::from_ref(&p), Continue, false, LockSignal::None);
    assert!(
        d.text
            .contains("Revoke on lock is not available on this computer"),
        "{}",
        d.text
    );
    assert!(!d.text.contains("set lock behaviour"));

    // No saved policy at all.
    let d = lock::disclosure(&[], Continue, false, mac);
    assert!(
        d.text.contains("until the end time you approve"),
        "{}",
        d.text
    );

    // Through the operations: the saved limits are the stored policies'.
    let w = world().await;
    let d = w.ops.lock_disclosure(false, mac).await.unwrap();
    let ids: Vec<&str> = d.limits.iter().map(|l| l.policy.as_str()).collect();
    assert_eq!(ids, vec!["pol", "pol-ops"]);
    assert!(d.text.contains("under your saved policy \"pol\""));
    assert!(
        d.text
            .contains("Work under your saved policy \"pol-ops\" ends when you lock the screen")
    );
    w.ops.set_session_lock_floor(RevokeOnLock);
    let d = w.ops.lock_disclosure(false, mac).await.unwrap();
    assert_eq!(d.floor, RevokeOnLock);
    assert!(d.text.contains("[session] lock_behavior"));
}

/// F19: Linux `revoke_on_lock` is accepted but carries `signal_unverified` in its
/// results and in the disclosure until B11 (`lock::LINUX_LOGIND_SIGNAL_VERIFIED`);
/// macOS, Windows and `continue` carry nothing.
#[tokio::test(start_paused = true)]
async fn linux_revoke_on_lock_labelled_signal_unverified() {
    use LockBehavior::{Continue, RevokeOnLock};
    const { assert!(!lock::LINUX_LOGIND_SIGNAL_VERIFIED, "B11 has not run") };
    let linux = LockSignal::LinuxLogind;
    let warnings = lock_warnings(RevokeOnLock, linux);
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, m03_warning::SIGNAL_UNVERIFIED);
    assert_eq!(warnings[0].code, "signal_unverified");
    assert!(lock_warnings(Continue, linux).is_empty());
    for s in [
        LockSignal::MacosScreenLock,
        LockSignal::WindowsSession,
        LockSignal::None,
    ] {
        assert!(lock_warnings(RevokeOnLock, s).is_empty(), "{s:?}");
    }
    // In the disclosure.
    let d = lock::disclosure(
        &[standing(pol_ops(), ops_profile(), RevokeOnLock)],
        Continue,
        false,
        linux,
    );
    assert_eq!(d.warnings.len(), 1);
    assert!(d.text.contains("has not been verified yet"), "{}", d.text);
    let d = lock::disclosure(&[], RevokeOnLock, false, linux);
    assert_eq!(d.warnings[0].code, "signal_unverified", "the floor too");
    // On a policy result: accepted (Linux has a signal) and labelled once.
    let w = world().await;
    let mut done = w
        .ops
        .policy(
            &attended(),
            PolicyAction::SetLockBehavior {
                policy_id: pol(),
                behavior: RevokeOnLock,
            },
        )
        .await
        .unwrap();
    assert_eq!(w.policy(&pol()).lock_behavior, RevokeOnLock);
    label_completed(&mut done, RevokeOnLock, linux);
    label_completed(&mut done, RevokeOnLock, linux);
    let codes: Vec<&str> = done.warnings.iter().map(|x| x.code.as_str()).collect();
    assert_eq!(codes, vec!["signal_unverified"]);
    let env = serde_json::to_value(done.into_envelope()).unwrap();
    assert_eq!(env["warnings"][0]["code"], "signal_unverified");

    // ⟨M03 wave 5⟩ U9-Q3 (a): the operations label their own results, with no caller
    // help: the `SetLockBehavior`, `ensure` (and `delegate`) and `inspect
    // capabilities` results. The fake source stands in for logind through
    // `set_session_lock_signal`, so this runs on every host.
    let codes = |w: &[heimdall_contract::envelope::Warning]| -> Vec<String> {
        w.iter().map(|x| x.code.clone()).collect()
    };
    let unverified = vec!["signal_unverified".to_owned()];
    let w = world().await;
    w.ops.set_session_lock_signal(linux);
    assert_eq!(w.ops.session_lock_signal(), linux);
    let ensure = |profile: ProfileId, tag: &str| EnsureRequest {
        profile,
        profile_revision: None,
        scope: [h1()].into_iter().collect(),
        environment: None,
        work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
    };
    let capabilities = heimdall_contract::request::InspectRequest {
        subject: heimdall_contract::request::InspectSubject::Capabilities,
        preview: None,
    };
    // A `continue` grant carries nothing; a `revoke_on_lock` one is labelled, once.
    let c = w
        .ops
        .ensure(&owner(), ensure(dev(), "lbl-c"))
        .await
        .unwrap();
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    let r = w
        .ops
        .ensure(&owner(), ensure(ops_profile(), "lbl-r"))
        .await
        .unwrap();
    assert_eq!(codes(&r.warnings), unverified);
    let child = w
        .ops
        .delegate(
            &owner(),
            DelegateRequest {
                parent_binding_id: r.data.binding_id.clone(),
                scope: [h1()].into_iter().collect(),
                until: Some(DeadlineIntent::Duration("1h".into())),
                work_id: WorkId::parse("c-lbl").unwrap(),
                request_id: RequestId::parse("d-lbl").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        codes(&child.warnings),
        unverified,
        "the delegated child too"
    );
    // The capabilities: `pol-ops` is `revoke_on_lock`, so the current behaviour is.
    let caps = w.ops.inspect(&owner(), capabilities.clone()).await.unwrap();
    assert_eq!(codes(&caps.warnings), unverified);
    // The policy result, from the operations alone; `continue` carries nothing.
    let set = |behavior| PolicyAction::SetLockBehavior {
        policy_id: pol_ops(),
        behavior,
    };
    let done = w.ops.policy(&attended(), set(RevokeOnLock)).await.unwrap();
    assert_eq!(
        codes(&done.warnings),
        unverified,
        "unchanged, still labelled"
    );
    // Another signal (macOS, Windows) labels nothing.
    w.ops.set_session_lock_signal(LockSignal::MacosScreenLock);
    let r2 = w
        .ops
        .ensure(&owner(), ensure(ops_profile(), "lbl-m"))
        .await
        .unwrap();
    assert!(r2.warnings.is_empty(), "{:?}", r2.warnings);
    let caps = w.ops.inspect(&owner(), capabilities.clone()).await.unwrap();
    assert!(caps.warnings.is_empty(), "{:?}", caps.warnings);
    let done = w.ops.policy(&attended(), set(RevokeOnLock)).await.unwrap();
    assert!(done.warnings.is_empty(), "{:?}", done.warnings);
    // A source that reads `unavailable` has no signal (and no label).
    w.ops.set_session_lock_signal(linux);
    w.lock.set_state(LockState::Unavailable);
    assert_eq!(w.ops.session_lock_signal(), LockSignal::None);
    let caps = w.ops.inspect(&owner(), capabilities).await.unwrap();
    assert!(caps.warnings.is_empty(), "{:?}", caps.warnings);
}

/// ADR-0008 D9 item 2: a lock revokes every `revoke_on_lock` grant, with tombstone and
/// cascade and cause `session_locked`; one `session_lock` event records the pass, and
/// the grant refuses signatures afterwards.
#[tokio::test(start_paused = true)]
async fn lock_event_revokes_revoke_on_lock_grants_with_cause_session_locked() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let child = w.child(&r, "rc").await;
    let r2 = w.grant(ops_profile(), "r2").await;
    let driver = w.drive(w.lock.clone(), fast());
    settle_for(Duration::from_millis(100)).await;
    w.lock.set_state(LockState::Locked);
    until("the lock pass", || w.revoked(&r) && w.revoked(&r2)).await;
    until("the acknowledgement", || !w.lock.lock_epoch().observed).await;
    let report = driver.stop().await;
    for g in [&r, &r2] {
        assert_eq!(w.tombstone_cause(g), Some(RevocationCause::SessionLocked));
    }
    assert!(w.revoked(&child), "the cascade");
    let tomb = w
        .store
        .transaction(|tx| tx.tombstone(&r.grant_id))
        .unwrap()
        .unwrap();
    assert!(tomb.cascade.contains(&child.grant_id));
    assert_eq!(w.lock_revocation_events(), 3);
    let lock_events = w.events(EventType::SessionLock);
    assert_eq!(lock_events.len(), 1, "one event for the pass");
    assert_eq!(lock_events[0]["state"], "locked");
    let revoked: BTreeSet<String> = lock_events[0]["revoked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let want: BTreeSet<String> = [&r, &child, &r2]
        .iter()
        .map(|g| g.grant_id.to_string())
        .collect();
    assert_eq!(revoked, want);
    assert_eq!(report.passes, 1);
    assert_eq!(
        report.revoked.iter().cloned().collect::<BTreeSet<_>>(),
        [r.grant_id.clone(), r2.grant_id.clone()]
            .into_iter()
            .collect()
    );
    // Use after the lock: refused, even unlocked.
    w.gate(&r);
    w.lock.set_state(LockState::Unlocked);
    assert!(w.admit(&r).await.is_err());
}

/// The default `continue` (spec §6.4): a lock ends nothing, and a `continue` grant
/// keeps signing while locked; the `revoke_on_lock` grant beside it is revoked.
#[tokio::test(start_paused = true)]
async fn continue_grants_unaffected_by_lock() {
    let w = world().await;
    let c = w.grant(dev(), "c").await;
    let r = w.grant(ops_profile(), "r").await;
    w.gate(&c);
    let driver = w.drive(w.lock.clone(), fast());
    w.lock.set_state(LockState::Locked);
    until("the lock pass", || w.revoked(&r)).await;
    settle_for(Duration::from_secs(2)).await;
    assert_eq!(w.state(&c), GrantState::Active);
    assert_eq!(w.tombstone_cause(&c), None);
    assert!(w.admit(&c).await.is_ok(), "`continue` signs while locked");
    assert_eq!(
        w.ops.effective_lock_behavior_of(&c.grant_id).await.unwrap(),
        Some(LockBehavior::Continue)
    );
    let report = driver.stop().await;
    assert_eq!(report.revoked, vec![r.grant_id.clone()]);
}

/// ADR-0008 D9 item 2: an unlock reactivates nothing. The revoked grant stays terminal
/// through the unlock and a later lock; new work needs a new activation (a new grant).
#[tokio::test(start_paused = true)]
async fn unlock_restores_nothing() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let driver = w.drive(w.lock.clone(), fast());
    w.lock.set_state(LockState::Locked);
    until("the lock pass", || w.revoked(&r)).await;
    let before = w.state(&r);
    w.lock.set_state(LockState::Unlocked);
    settle_for(Duration::from_secs(2)).await;
    assert_eq!(w.state(&r), before, "nothing reactivated it");
    assert!(w.revoked(&r));
    w.gate(&r);
    assert!(w.admit(&r).await.is_err(), "it never signs again");
    // A second lock and unlock: still terminal, revoked once.
    w.lock.set_state(LockState::Locked);
    settle_for(Duration::from_secs(2)).await;
    w.lock.set_state(LockState::Unlocked);
    settle_for(Duration::from_secs(2)).await;
    assert!(w.revoked(&r));
    assert_eq!(w.lock_revocation_events(), 1, "revoked exactly once");
    // New work is a new activation.
    let again = w.grant(ops_profile(), "r-again").await;
    assert_ne!(again.grant_id, r.grant_id);
    assert_eq!(w.state(&again), GrantState::Active);
    let report = driver.stop().await;
    assert_eq!(report.revoked, vec![r.grant_id.clone()]);
}

/// R-UX-03: the disclosure is shown once (pending until acknowledged), the
/// acknowledgement is recorded once in `meta.lock_disclosure_acknowledged_at` and not
/// repeated, and the current behaviour stays readable afterwards.
#[tokio::test(start_paused = true)]
async fn disclosure_shown_once_then_recorded() {
    let w = world().await;
    let mac = LockSignal::MacosScreenLock;
    let first = w.ops.pending_lock_disclosure(false, mac).await.unwrap();
    assert!(first.is_some(), "shown before any acknowledgement");
    assert_eq!(
        w.store.transaction(|tx| tx.lock_disclosure_ack()).unwrap(),
        None
    );
    let at = w.ops.acknowledge_lock_disclosure().await.unwrap();
    assert_eq!(at, w.clock.wall());
    assert_eq!(
        w.store.transaction(|tx| tx.lock_disclosure_ack()).unwrap(),
        Some(at)
    );
    assert!(
        w.ops
            .pending_lock_disclosure(false, mac)
            .await
            .unwrap()
            .is_none(),
        "not shown again"
    );
    settle_for(Duration::from_secs(60)).await;
    assert_eq!(
        w.ops.acknowledge_lock_disclosure().await.unwrap(),
        at,
        "the first acknowledgement is kept"
    );
    // The help text and the TUI detail always show the current behaviour.
    let current = w.ops.lock_disclosure(false, mac).await.unwrap();
    assert_eq!(current.acknowledged_at, Some(at));
    assert!(!current.text.is_empty());
    // A restart keeps it.
    let ops2 = Operations::start(config(&w)).await.unwrap();
    assert!(
        ops2.pending_lock_disclosure(false, mac)
            .await
            .unwrap()
            .is_none()
    );
}

// =================================================================================
// Negative
// =================================================================================

/// ADR-0008 D9 item 3: setting `revoke_on_lock` where the source is `unavailable` (or
/// absent) is refused `CAPABILITY_UNAVAILABLE`, `lock_signal_unavailable`, with nothing
/// written; the R3 floor is refused the same way (`lock::floor_refusal`). The native
/// rows (devbox, WSL) run the runtime's real source in `integration_session_lock`.
#[tokio::test(start_paused = true)]
async fn revoke_on_lock_refused_where_signal_unavailable() {
    let w = world().await;
    let set = PolicyAction::SetLockBehavior {
        policy_id: pol(),
        behavior: LockBehavior::RevokeOnLock,
    };
    let before = (w.policy(&pol()), w.generation());
    w.ops
        .set_session_lock_source(Arc::new(FakeSessionLockSource::new(LockState::Unavailable)));
    let e = w.ops.policy(&attended(), set.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    assert_eq!(
        (w.policy(&pol()), w.generation()),
        before,
        "nothing written"
    );
    // An unattended owner is refused the same way.
    let e = w.ops.policy(&owner(), set.clone()).await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    // `continue` is never refused for want of a signal.
    let ok = w
        .ops
        .policy(
            &attended(),
            PolicyAction::SetLockBehavior {
                policy_id: pol(),
                behavior: LockBehavior::Continue,
            },
        )
        .await
        .unwrap();
    assert_eq!(ok.data["changed"], false);
    // No source at all (a fresh operations instance): refused too.
    let fresh = Operations::start(config(&w)).await.unwrap();
    let e = fresh.policy(&attended(), set.clone()).await.unwrap_err();
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    // The configured floor where the signal is unavailable.
    let e = lock::floor_refusal(LockBehavior::RevokeOnLock, LockState::Unavailable).unwrap();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    assert!(lock::floor_refusal(LockBehavior::Continue, LockState::Unavailable).is_none());
    assert!(lock::floor_refusal(LockBehavior::RevokeOnLock, LockState::Unlocked).is_none());
    // A source that becomes available accepts it.
    w.ops.set_session_lock_source(w.lock.clone());
    w.ops.policy(&attended(), set).await.unwrap();
    assert_eq!(w.policy(&pol()).lock_behavior, LockBehavior::RevokeOnLock);
}

/// ADR-0008 D9 item 2, §17.16 item 1: `continue → revoke_on_lock` narrows at once;
/// back to `continue` widens: a decision record and an attended `Decide`, nothing
/// applied before it, and effective for later locks only (a grant created under
/// `revoke_on_lock` keeps it; one created after the widening continues).
#[tokio::test(start_paused = true)]
async fn widening_to_continue_needs_attended_decision() {
    let w = world().await;
    let to = |b| PolicyAction::SetLockBehavior {
        policy_id: pol(),
        behavior: b,
    };
    let g0 = w.generation();
    w.ops
        .policy(&attended(), to(LockBehavior::RevokeOnLock))
        .await
        .unwrap();
    assert_eq!(w.policy(&pol()).lock_behavior, LockBehavior::RevokeOnLock);
    assert!(
        w.generation() > g0,
        "narrowing is immediate and moves the generation"
    );
    let before = w.grant(dev(), "before").await;
    // Widening, attended: APPROVAL_REQUIRED with a decision; unattended:
    // INTERACTION_REQUIRED with the same record; nothing applied.
    let e = w
        .ops
        .policy(&attended(), to(LockBehavior::Continue))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired);
    let decision = e.next.decision_ref.clone().unwrap();
    let e = w
        .ops
        .policy(&owner(), to(LockBehavior::Continue))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(e.next.decision_ref.as_deref(), Some(decision.as_str()));
    assert_eq!(w.policy(&pol()).lock_behavior, LockBehavior::RevokeOnLock);
    // An unattended Decide is refused; the attended one applies it.
    let decide = |caller: Caller| {
        let ops = w.ops.clone();
        let id = heimdall_contract::ids::DecisionId::parse(&decision).unwrap();
        async move {
            ops.decide(
                &caller,
                DecideRequest {
                    decision_id: id,
                    verdict: Verdict::Approve,
                },
            )
            .await
        }
    };
    assert!(decide(owner()).await.is_err());
    assert_eq!(w.policy(&pol()).lock_behavior, LockBehavior::RevokeOnLock);
    decide(attended()).await.unwrap();
    assert_eq!(w.policy(&pol()).lock_behavior, LockBehavior::Continue);
    // Effective for later locks only.
    let after = w.grant(dev(), "after").await;
    assert_eq!(
        w.ops
            .effective_lock_behavior_of(&before.grant_id)
            .await
            .unwrap(),
        Some(LockBehavior::RevokeOnLock),
        "recorded at creation"
    );
    assert_eq!(
        w.ops
            .effective_lock_behavior_of(&after.grant_id)
            .await
            .unwrap(),
        Some(LockBehavior::Continue)
    );
    let driver = w.drive(w.lock.clone(), fast());
    w.lock.set_state(LockState::Locked);
    until("the lock pass", || w.revoked(&before)).await;
    settle_for(Duration::from_secs(1)).await;
    assert_eq!(w.state(&after), GrantState::Active);
    driver.stop().await;
}

/// ADR-0008 D9 item 3: `unknown` is treated as locked. A `revoke_on_lock` grant
/// refuses signatures unless the state is `unlocked` (`unknown` and `unavailable`
/// included, and no source at all); entering `unknown` runs a revocation pass even
/// though the source latched no lock (`lock::UNKNOWN_IS_LOCK`); a `continue` grant is
/// unaffected.
#[tokio::test(start_paused = true)]
async fn unknown_state_treated_as_locked() {
    const { assert!(lock::UNKNOWN_IS_LOCK) };
    assert!(lock::treated_as_locked(LockState::Unknown));
    assert!(lock::treated_as_locked(LockState::Unavailable));
    assert!(!lock::treated_as_locked(LockState::Unlocked));
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let c = w.grant(dev(), "c").await;
    w.gate(&r);
    w.gate(&c);
    assert!(w.admit(&r).await.is_ok(), "unlocked: signs");
    w.lock.set_state(LockState::Unknown);
    assert_eq!(
        w.lock.lock_epoch(),
        LockEpoch::default(),
        "the fake latches nothing"
    );
    assert_eq!(w.admit(&r).await, Err(SignRefusal::SessionNotUnlocked));
    assert!(w.admit(&c).await.is_ok(), "`continue` signs");
    w.lock.set_state(LockState::Unavailable);
    assert_eq!(w.admit(&r).await, Err(SignRefusal::SessionNotUnlocked));
    // No source at all (a fresh instance over the same store and gates): unknown.
    let fresh = Operations::start(config(&w)).await.unwrap();
    fresh.signing_gates().retain(&r.grant_id, &[]);
    assert_eq!(
        W::admit_on(&fresh, &r).await,
        Err(SignRefusal::SessionNotUnlocked)
    );
    // Entering unknown runs the pass.
    w.lock.set_state(LockState::Unlocked);
    let driver = w.drive(w.lock.clone(), fast());
    settle_for(Duration::from_millis(200)).await;
    assert!(!w.revoked(&r));
    w.lock.set_state(LockState::Unknown);
    until("the pass for unknown", || w.revoked(&r)).await;
    assert_eq!(w.tombstone_cause(&r), Some(RevocationCause::SessionLocked));
    assert_eq!(w.state(&c), GrantState::Active);
    let ev = w.events(EventType::SessionLock);
    assert_eq!(ev.last().unwrap()["state"], "unknown");
    let report = driver.stop().await;
    assert_eq!(report.revoked, vec![r.grant_id.clone()]);
}

// =================================================================================
// Interrupted
// =================================================================================

/// ADR-0008 D9 item 2 (ADR-0005 §3.7 rule 5): after a restart, re-issue never runs for
/// a `revoke_on_lock` grant, so a lock missed while the runtime was down cannot leave
/// it alive. Checked through the predicate U6/U10's `managed_reissue_pass` consults
/// (`Operations::lock_blocks_reissue`) on a restarted instance: blocked for the
/// `revoke_on_lock` grant and its child, allowed for a `continue` one, blocked for every
/// grant under the R3 floor and for an unknown grant. The re-issue pass itself (key
/// regeneration, issuance) is U6/U10's: not exercised here.
#[tokio::test(start_paused = true)]
async fn restart_never_reissues_revoke_on_lock_grant() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let rc = w.child(&r, "rc").await;
    let c = w.grant(dev(), "c").await;
    // The restart: a new instance over the same store; it observed no lock.
    let restarted = Operations::start(config(&w)).await.unwrap();
    assert!(restarted.lock_blocks_reissue(&r.grant_id).await.unwrap());
    assert!(
        restarted.lock_blocks_reissue(&rc.grant_id).await.unwrap(),
        "the child recorded it too"
    );
    assert!(!restarted.lock_blocks_reissue(&c.grant_id).await.unwrap());
    let unknown = GrantId::from_random_bytes([0x5a; 16]);
    assert!(
        restarted.lock_blocks_reissue(&unknown).await.unwrap(),
        "fail closed"
    );
    // The floor makes every grant revoke_on_lock while it is set.
    restarted.set_session_lock_floor(LockBehavior::RevokeOnLock);
    assert!(restarted.lock_blocks_reissue(&c.grant_id).await.unwrap());
    assert!(!lock::reissue_allowed(LockBehavior::RevokeOnLock));
    assert!(lock::reissue_allowed(LockBehavior::Continue));
}

// --- the managed issuance fixtures (as tests/model/operations_m03.rs) -------------------

fn ca(n: u8) -> CaFingerprint {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let hi = char::from(B64[usize::from(n / 64)]);
    let lo = char::from(B64[usize::from(n % 64)]);
    CaFingerprint::parse(&format!("SHA256:{hi}{}", lo.to_string().repeat(42))).unwrap()
}

fn issuer(n: u8) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: ca(n),
        public_key: format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture{n}"),
        state: CaState::Active,
        store_kind: StoreKind::LinuxSecretService,
        backup_sha256: format!("{n:02x}").repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: t0(),
        retired_at: None,
    }
}

fn enrollment(n: u8, p: &AccessPair) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: p.destination.clone(),
        account: p.account.clone(),
        ca_fingerprint: ca(n),
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
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Verified,
        verified_at: Some(t0()),
        evidence: None,
        created_at: t0(),
        updated_at: t0(),
    }
}

fn issuance_facts() -> IssuanceFacts {
    IssuanceFacts {
        new_activation: false,
        subject_registered: true,
        critical_option: false,
    }
}

/// D3 / U0b row 3: a lock revocation that lands between an issuance's reserve and its
/// publish voids the reservation. The certificate the issuer signed over the reserved
/// bounds is never released: publish re-runs every predicate in its own transaction,
/// finds the grant revoked (cause `session_locked`), voids the entry and refuses.
#[tokio::test(start_paused = true)]
async fn lock_revocation_between_reserve_and_publish_voids() {
    let w = world_with(MANAGED_CERTIFICATE).await;
    w.store
        .transaction(|tx| {
            tx.insert_issuer(&issuer(1))?;
            tx.seed_enrollment(&enrollment(1, &h1()))
        })
        .unwrap();
    let r = w.grant(ops_profile(), "r").await;
    let now = w.clock.wall();
    let entry = w
        .ops
        .reserve_issuance(IssuanceRequest {
            grant: r.grant_id.clone(),
            pair: h1(),
            principal: "hm:h1:deploy".into(),
            key_id: "fixture-key".into(),
            valid_after: now,
            valid_before: plus(now, Duration::from_secs(1800)),
            extensions: [EXTENSION_PTY.to_owned()].into_iter().collect(),
            subject_fingerprint: "fixture-fingerprint".into(),
            facts: issuance_facts(),
        })
        .await
        .unwrap();
    assert_eq!(entry.state, IssuanceState::Reserved);
    assert_eq!(entry.bounds.ca_fingerprint, Some(ca(1)));
    // The lock lands while the issuer signs.
    w.lock.set_state(LockState::Locked);
    lock::lock_pass_now(&w.ops, w.lock.as_ref()).await.unwrap();
    assert_eq!(w.tombstone_cause(&r), Some(RevocationCause::SessionLocked));
    let e = w
        .ops
        .publish_issuance(&entry.id, &issuance_facts())
        .await
        .unwrap_err();
    assert_ne!(e.code, Code::Ok);
    let stored = w
        .store
        .transaction(|tx| tx.issuance_entries(&r.grant_id))
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].state, IssuanceState::Voided, "never published");
    assert!(stored[0].void_reason.is_some());
}

/// 100 lock events in 1 s cause one revocation pass, and no notification storm: the
/// events latch into the epoch, the driver starts at most one pass per `min_interval`
/// (1 s, the default), only the first pass revokes anything, each grant is revoked
/// (and announced) once, there is one `session_lock` event per pass (never one per lock
/// event), and at the end the latest epoch is acknowledged.
#[tokio::test(start_paused = true)]
async fn lock_event_storm_coalesced_bounded() {
    let w = world().await;
    let r = w.grant(ops_profile(), "r").await;
    let rc = w.child(&r, "rc").await;
    let r2 = w.grant(ops_profile(), "r2").await;
    let c = w.grant(dev(), "c").await;
    let driver = w.drive(w.lock.clone(), LockPassConfig::default());
    settle_for(Duration::from_millis(100)).await;
    let start = Instant::now();
    for _ in 0..100 {
        w.lock.set_state(LockState::Locked);
        tokio::time::sleep(Duration::from_millis(5)).await;
        w.lock.set_state(LockState::Unlocked);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let storm = start.elapsed();
    assert!(storm <= Duration::from_millis(1100), "{storm:?}");
    assert_eq!(w.lock.lock_epoch().epoch, 100, "100 lock events");
    until("the latch to clear", || !w.lock.lock_epoch().observed).await;
    settle_for(Duration::from_secs(3)).await;
    let report = driver.stop().await;
    assert!(
        (1..=2).contains(&report.passes),
        "at most one pass per second of storm, plus the first: {}",
        report.passes
    );
    assert_eq!(report.failures, 0);
    assert_eq!(
        report.epochs.last().copied(),
        Some(100),
        "the latest epoch acknowledged"
    );
    assert!(!w.lock.lock_epoch().observed);
    let lock_events = w.events(EventType::SessionLock);
    let revoking_passes = lock_events
        .iter()
        .filter(|e| !e["revoked"].as_array().unwrap().is_empty())
        .count();
    assert_eq!(revoking_passes, 1, "one revocation pass");
    assert_eq!(
        lock_events.len(),
        report.passes as usize,
        "one session_lock event per pass, none per lock event"
    );
    assert_eq!(
        w.lock_revocation_events(),
        3,
        "r, its child and r2, once each"
    );
    assert!(w.revoked(&r) && w.revoked(&rc) && w.revoked(&r2));
    assert_eq!(w.state(&c), GrantState::Active);
    assert_eq!(
        report.revoked.iter().cloned().collect::<BTreeSet<_>>(),
        [r.grant_id.clone(), r2.grant_id.clone()]
            .into_iter()
            .collect()
    );
}

/// The R3 floor (ADR-0008 §17.15 item 12): the M01 `[session] lock_behavior = "revoke"`
/// key is merged fail closed with the standing policy: with the floor set, a lock
/// revokes a grant whose policy and origin say `continue`, and its signatures need
/// `unlocked`; `continue` adds nothing.
#[tokio::test(start_paused = true)]
async fn r3_floor_merged_fail_closed() {
    use LockBehavior::{Continue, RevokeOnLock};
    // The pure merge: revoke from either side wins.
    let p_cont = standing(pol(), dev(), Continue);
    let p_rev = standing(pol_ops(), ops_profile(), RevokeOnLock);
    assert_eq!(
        lock::effective_behavior_with_floor(None, std::slice::from_ref(&p_cont), Continue),
        Continue
    );
    assert_eq!(
        lock::effective_behavior_with_floor(None, std::slice::from_ref(&p_cont), RevokeOnLock),
        RevokeOnLock
    );
    assert_eq!(
        lock::effective_behavior_with_floor(None, &[p_rev], Continue),
        RevokeOnLock
    );
    assert_eq!(
        lock::origin_behavior(std::slice::from_ref(&p_cont), Continue),
        None
    );
    assert_eq!(
        lock::origin_behavior(&[p_cont], RevokeOnLock),
        Some(RevokeOnLock)
    );
    // Through the operations.
    let w = world().await;
    let c = w.grant(dev(), "c").await;
    w.gate(&c);
    let origin = w
        .store
        .transaction(|tx| tx.grant_origin(&c.grant_id))
        .unwrap()
        .unwrap();
    assert_eq!(lock::effective_behavior(&origin, &[]), Continue);
    w.lock.set_state(LockState::Locked);
    assert!(
        w.admit(&c).await.is_ok(),
        "no floor: `continue` signs while locked"
    );
    w.ops.set_session_lock_floor(RevokeOnLock);
    assert_eq!(w.ops.session_lock_floor(), RevokeOnLock);
    assert_eq!(w.admit(&c).await, Err(SignRefusal::SessionNotUnlocked));
    let done = lock::lock_pass_now(&w.ops, w.lock.as_ref()).await.unwrap();
    assert_eq!(done.revoked, vec![c.grant_id.clone()]);
    assert_eq!(w.tombstone_cause(&c), Some(RevocationCause::SessionLocked));
    // `continue` adds nothing.
    let w2 = world().await;
    let c2 = w2.grant(dev(), "c2").await;
    w2.ops.set_session_lock_floor(Continue);
    w2.lock.set_state(LockState::Locked);
    let done = lock::lock_pass_now(&w2.ops, w2.lock.as_ref())
        .await
        .unwrap();
    assert!(done.revoked.is_empty());
    assert_eq!(w2.state(&c2), GrantState::Active);
}

/// ADR-0008 §17.17 item 4 (U9-Q2): a grant created while the R3 floor is `revoke`
/// records `revoke_on_lock` in its origin. After the configuration changes to
/// `continue` and the runtime restarts (a new instance over the same store, floor
/// `continue`), it is still `revoke_on_lock`: a lock revokes it and it is never
/// re-issued. A grant created after the change, the control, stays `continue`.
#[tokio::test(start_paused = true)]
async fn grant_created_under_revoke_floor_stays_revoke_on_lock_after_config_change_and_restart() {
    use LockBehavior::{Continue, RevokeOnLock};
    let w = world().await;
    w.ops.set_session_lock_floor(RevokeOnLock);
    let g = w.grant(dev(), "floor").await;
    let origin = |id: &GrantId| {
        w.store
            .transaction(|tx| tx.grant_origin(id))
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        origin(&g.grant_id).lock_behavior,
        Some(RevokeOnLock),
        "the floor is recorded at creation"
    );
    // The configuration changes to `continue`.
    w.ops.set_session_lock_floor(Continue);
    let c = w.grant(dev(), "after").await;
    assert_eq!(
        origin(&c.grant_id).lock_behavior,
        None,
        "the control is `continue`"
    );
    // The restart: a new instance over the same store, with the `continue` floor.
    let restarted = Operations::start(config(&w)).await.unwrap();
    restarted.set_session_lock_floor(Continue);
    assert_eq!(restarted.session_lock_floor(), Continue);
    assert!(
        restarted.lock_blocks_reissue(&g.grant_id).await.unwrap(),
        "still revoke_on_lock after the restart"
    );
    assert!(!restarted.lock_blocks_reissue(&c.grant_id).await.unwrap());
    w.lock.set_state(LockState::Locked);
    let done = lock::lock_pass_now(&restarted, w.lock.as_ref())
        .await
        .unwrap();
    assert_eq!(done.revoked, vec![g.grant_id.clone()]);
    assert_eq!(w.tombstone_cause(&g), Some(RevocationCause::SessionLocked));
    assert_eq!(w.state(&c), GrantState::Active);
}
