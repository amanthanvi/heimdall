//! M01-U5 model suite for the application operations (spec §17 A06, A19, A29
//! local variants; plan §6.4 fault schedule; m01-plan U5).
//!
//! Everything runs in process over the production `heimdall_app::Operations`,
//! `heimdall_store::Store::open_in_memory`, `testkit::VirtualClock`,
//! `testkit::ScriptedTimeSync` and `testkit::FakeCredentialAdapter`. Faults are
//! injected only through production hooks: the store `FaultHook`, the pipeline
//! `StageHook` (`testkit::ScriptedStageHook` or a hook implementing the same
//! trait) and the fake adapter's script.
//!
//! **Restart label.** Every "restart" here is an **in-process** reconstruction: a
//! new `Operations::start` over the same store and the same fake adapter instance
//! (its effect ledger lives in memory). It exercises the recovery code paths; it is
//! not process-crash evidence (that is U9/U10's, ADR-0006 §13.4 N06).
//!
//! Canary rule: the fake adapter's credential reference and error texts carry a
//! synthetic `HEIMDALL_CANARY_*` value built at runtime; every envelope, event and
//! error message produced here is scanned with `assert_no_canary`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use heimdall_app::ensure::{EnsureStage, NoStageHook, StageHook};
use heimdall_app::error::Completed;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, DeviceId, EnvironmentId, OperationId, PolicyId,
    ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    BindForm, BindRequest, CancelRequest, ConfirmTimeRequest, DeadlineIntent, DecideRequest,
    DelegateRequest, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
    ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry, ObserveRequest,
    PolicyAction, RefreshDependency, ReleaseRequest, RequiredCapabilities, RevocationStatus,
    RevokeRequest, Verdict, WaitMode, WorkloadIsolation,
};
use heimdall_contract::{Code, ExitCode, GrantState, OperationState, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedStageHook, ScriptedTimeSync,
    VirtualClock, assert_no_canary,
};

// =================================================================================
// Harness
// =================================================================================

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

/// Synthetic canary built at runtime (never a literal in source).
fn canary() -> String {
    format!("{CANARY_PREFIX}u5_fixture")
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn ctx(uid: u32, role: ClientRole) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role,
    }
}

fn unattended(uid: u32) -> Caller {
    Caller::unattended(ctx(uid, ClientRole::Owner))
}

fn attended(uid: u32) -> Caller {
    Caller {
        context: ctx(uid, ClientRole::Owner),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn limited(uid: u32) -> Caller {
    Caller::unattended(ctx(uid, ClientRole::LimitedConsumer))
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

/// Profile `dev`: h1, h2, h3. Policy `pol` covers h1 and h2 only (h3 is added
/// authority), window 2 h.
fn profile_pairs() -> BTreeSet<AccessPair> {
    [
        pair("h1", "deploy"),
        pair("h2", "deploy"),
        pair("h3", "deploy"),
    ]
    .into_iter()
    .collect()
}

fn policy_pairs() -> BTreeSet<AccessPair> {
    [pair("h1", "deploy"), pair("h2", "deploy")]
        .into_iter()
        .collect()
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: shift(t0(), 12 * 3600),
        offline_until: shift(t0(), 3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        // The opaque reference carries a canary: it must never reach an envelope
        // or an event.
        credential_ref: canary(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
    }
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::ClientRouting,
            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
            revocation: RevocationStatus::LocalApplied,
        },
        evidence: Vec::new(),
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
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
    }
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
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
                    pairs: profile_pairs(),
                    capabilities: ssh_only(),
                },
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: policy_id(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: policy_pairs(),
                        capabilities: ssh_only(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
}

/// Store fault hook armed on demand (production `FaultHook`). While armed it
/// fails the next `point` once, optionally only after the fake adapter applied an
/// effect ("after the effect, before the receipt").
struct Armed {
    point: FaultPoint,
    armed: AtomicBool,
    after_effect_of: std::sync::Mutex<Option<Arc<FakeCredentialAdapter>>>,
    fired: AtomicUsize,
}

impl Armed {
    fn new(point: FaultPoint) -> Arc<Self> {
        Arc::new(Self {
            point,
            armed: AtomicBool::new(false),
            after_effect_of: std::sync::Mutex::new(None),
            fired: AtomicUsize::new(0),
        })
    }
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn arm_after_effect(&self, fake: Arc<FakeCredentialAdapter>) {
        *self.after_effect_of.lock().unwrap() = Some(fake);
        self.arm();
    }
}

impl FaultHook for Armed {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point != self.point || !self.armed.load(Ordering::SeqCst) {
            return FaultAction::Continue;
        }
        if let Some(fake) = self.after_effect_of.lock().unwrap().as_ref()
            && fake.effect_count() == 0
        {
            return FaultAction::Continue;
        }
        self.armed.store(false, Ordering::SeqCst);
        self.fired.fetch_add(1, Ordering::SeqCst);
        FaultAction::Fail
    }
}

/// Pipeline hook that arms a store fault when a stage starts (production
/// `StageHook` trait).
struct ArmAt {
    stage: EnsureStage,
    faults: Arc<Armed>,
    used: AtomicBool,
}

impl ArmAt {
    fn new(stage: EnsureStage, faults: Arc<Armed>) -> Arc<Self> {
        Arc::new(Self {
            stage,
            faults,
            used: AtomicBool::new(false),
        })
    }
}

impl StageHook for ArmAt {
    fn before(&self, stage: EnsureStage) -> Result<(), Code> {
        // Arms once: the retry runs the stage again without a fault.
        if stage == self.stage && !self.used.swap(true, Ordering::SeqCst) {
            self.faults.arm();
        }
        Ok(())
    }
    fn after(&self, _stage: EnsureStage) -> Result<(), Code> {
        Ok(())
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    hook: Arc<dyn StageHook>,
    limits: Limits,
    ops: Operations,
}

struct Setup {
    script: Vec<FakeStep>,
    hook: Arc<dyn StageHook>,
    faults: Arc<dyn FaultHook>,
    limits: Limits,
    /// Durable effect ledger for the fake adapter (ADR-0006 §13.4 N06).
    ledger: Option<std::path::PathBuf>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            script: vec![FakeStep::Prepare(outcome())],
            hook: Arc::new(NoStageHook),
            faults: Arc::new(heimdall_store::NoFaults),
            limits: Limits::default(),
            ledger: None,
        }
    }
}

impl World {
    async fn new() -> Self {
        Self::with(Setup::default()).await
    }

    async fn with(setup: Setup) -> Self {
        let store = Arc::new(Store::open_in_memory(setup.faults).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let fake = match &setup.ledger {
            Some(path) => {
                FakeCredentialAdapter::with_ledger(descriptor(), setup.script, path).unwrap()
            }
            None => FakeCredentialAdapter::new(descriptor(), setup.script),
        };
        let config = config_of(&store, &clock, &sync, &fake, &setup.hook, setup.limits);
        let ops = Operations::start(config).await.unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            hook: setup.hook,
            limits: setup.limits,
            ops,
        }
    }

    fn config(&self) -> OperationsConfig {
        config_of(
            &self.store,
            &self.clock,
            &self.sync,
            &self.fake,
            &self.hook,
            self.limits,
        )
    }

    /// In-process restart: a new `Operations` over the same store and adapter.
    async fn restart(&mut self) {
        self.ops = Operations::start(self.config()).await.unwrap();
    }

    async fn restart_with_hook(&mut self, hook: Arc<dyn StageHook>) {
        self.hook = hook;
        self.restart().await;
    }

    fn effects(&self) -> usize {
        self.fake.effect_count()
    }

    fn op(&self, id: &OperationId) -> heimdall_domain::operation::OperationRecord {
        self.store
            .transaction(|tx| tx.operation(id))
            .unwrap()
            .unwrap()
    }

    fn grant(&self, id: &heimdall_contract::ids::GrantId) -> heimdall_domain::grant::GrantSnapshot {
        self.store.transaction(|tx| tx.grant(id)).unwrap().unwrap()
    }

    fn bindings_for(&self, work: &str) -> Vec<heimdall_domain::binding::BindingRecord> {
        self.store
            .transaction(|tx| tx.bindings_for_work(&env_id(), &WorkId::parse(work).unwrap()))
            .unwrap()
    }

    /// Every stored event, scanned for canaries.
    fn events(&self) -> Vec<heimdall_store::StoredEvent> {
        let page = self
            .store
            .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 10_000))
            .unwrap();
        for e in &page.events {
            assert_no_canary(&serde_json::to_string(&e.event).unwrap());
        }
        page.events
    }
}

fn config_of(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
    hook: &Arc<dyn StageHook>,
    limits: Limits,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: hook.clone(),
        limits,
        default_window: 12 * HOUR,
        projection: None,
    }
}

fn ensure_req(request_id: &str, work: &str, pairs: &[(&str, &str)]) -> EnsureRequest {
    EnsureRequest {
        profile: ProfileId::parse("dev").unwrap(),
        profile_revision: None,
        scope: pairs.iter().map(|(d, a)| pair(d, a)).collect(),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(request_id).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
    }
}

/// Render a result as its envelope JSON, scanning it for canaries.
fn rendered<T: serde::Serialize + Clone>(r: &OpResult<T>) -> serde_json::Value {
    let v = match r {
        Ok(c) => serde_json::to_value(c.clone_envelope()).unwrap(),
        Err(e) => serde_json::to_value(e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&v.to_string());
    v
}

trait CloneEnvelope<T> {
    fn clone_envelope(&self) -> heimdall_contract::Envelope<T>;
}

impl<T: Clone> CloneEnvelope<T> for Completed<T> {
    fn clone_envelope(&self) -> heimdall_contract::Envelope<T> {
        self.clone().into_envelope()
    }
}

fn ok<T: serde::Serialize + Clone>(r: OpResult<T>) -> Completed<T> {
    rendered(&r);
    match r {
        Ok(c) => c,
        Err(e) => panic!("expected success, got {}: {}", e.code, e.message),
    }
}

fn err<T: serde::Serialize + Clone + std::fmt::Debug>(r: OpResult<T>) -> OpError {
    rendered(&r);
    match r {
        Ok(c) => panic!("expected an error, got {:?}", c.code),
        Err(e) => {
            assert_no_canary(&e.message);
            e
        }
    }
}

fn decision_ref(e: &OpError) -> DecisionId {
    DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
}

// =================================================================================
// A19 — success, approval, timeout, cancel, uncertainty
// =================================================================================

#[tokio::test]
async fn a19_success_is_access_ready_with_binding_and_bounded_facts() {
    let w = World::new().await;
    let r = w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-1", "work-1", &[("h1", "deploy")]),
        )
        .await;
    let env = rendered(&r);
    let done = ok(r);
    assert_eq!(done.code, Code::AccessReady);
    assert_eq!(done.state, OperationState::Succeeded);
    assert_eq!(env["next"]["action"], "use_binding");
    let data: EnsureData = done.data;
    assert_eq!(data.environment_id, env_id());
    assert_eq!(data.profile_revision, 1);
    assert_eq!(data.credential_mechanism, "fake_agent");
    // Default deadline = the policy window (2 h), credentials never exceed it.
    assert_eq!(data.expires_at, shift(t0(), 2 * 3600));
    assert!(data.usable_until <= data.expires_at);
    assert!(data.offline_until <= data.expires_at);
    assert_eq!(w.effects(), 1);
    let g = w.grant(&data.grant_id);
    assert_eq!(g.state, GrantState::Active);
    assert_eq!(w.bindings_for("work-1").len(), 1);
    w.events();
}

fn approval_req(request_id: &str, work: &str) -> EnsureRequest {
    // h3 is in the profile but not in the policy: added authority.
    ensure_req(request_id, work, &[("h1", "deploy"), ("h3", "deploy")])
}

async fn decide(
    w: &World,
    caller: &Caller,
    d: &DecisionId,
    verdict: Verdict,
) -> OpResult<serde_json::Value> {
    w.ops
        .decide(
            caller,
            DecideRequest {
                decision_id: d.clone(),
                verdict,
            },
        )
        .await
}

async fn observe(
    w: &World,
    caller: &Caller,
    id: &OperationId,
    wait_ms: Option<u64>,
) -> Completed<serde_json::Value> {
    ok(w.ops
        .observe(
            caller,
            ObserveRequest::Operation {
                operation_id: id.clone(),
                wait_ms,
            },
        )
        .await)
}

#[tokio::test]
async fn a19_added_authority_unattended_is_interaction_required_with_a_decision_ref() {
    let w = World::new().await;
    let r = w
        .ops
        .ensure(&unattended(501), approval_req("req-a", "work-a"))
        .await;
    let env = rendered(&r);
    let e = err(r);
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(e.code.exit_code(), ExitCode::InteractionRequired);
    assert_eq!(e.state(), OperationState::AwaitingApproval);
    assert_eq!(env["state"], "awaiting_approval");
    let dec = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::AwaitingApproval);
    // Nothing executed on dispatch.
    assert_eq!(w.effects(), 0);
    // A duplicate retry coalesces onto the same decision (one logical decision).
    let again = err(w
        .ops
        .ensure(&unattended(501), approval_req("req-a", "work-a"))
        .await);
    assert_eq!(decision_ref(&again), dec);
    assert_eq!(again.operation_id, Some(op));
}

#[tokio::test]
async fn a19_added_authority_attended_waits_for_decide_then_applies_exactly_the_delta() {
    let w = World::new().await;
    let e = err(w
        .ops
        .ensure(&attended(501), approval_req("req-b", "work-b"))
        .await);
    assert_eq!(e.code, Code::ApprovalRequired);
    let dec = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(
        w.effects(),
        0,
        "an attended session never executes on dispatch"
    );
    // `decide` from an unattended session is refused, with no record change.
    let refused = err(decide(&w, &unattended(501), &dec, Verdict::Approve).await);
    assert_eq!(refused.code, Code::InteractionRequired);
    assert!(refused.next.decision_ref.is_none());
    assert_eq!(w.op(&op).state, OperationState::AwaitingApproval);
    // Attended approval resumes the waiting operation.
    let done = ok(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    assert_eq!(done.data["state"], "approved");
    assert_eq!(done.data["operation_state"], "succeeded");
    assert_eq!(w.effects(), 1);
    let ready = ok(w
        .ops
        .ensure(&attended(501), approval_req("req-b", "work-b"))
        .await);
    assert_eq!(ready.code, Code::AccessReady);
    let g = w.grant(&ready.data.grant_id);
    assert_eq!(
        g.scope.pairs,
        [pair("h1", "deploy"), pair("h3", "deploy")]
            .into_iter()
            .collect()
    );
    // Consume-once: a second verdict is stale.
    let again = err(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    assert_eq!(again.code, Code::DecisionStale);
    assert_eq!(again.code.exit_code(), ExitCode::Conflict);
}

#[tokio::test]
async fn a19_denied_decision_fails_the_operation_and_its_grant() {
    let w = World::new().await;
    let e = err(w
        .ops
        .ensure(&attended(501), approval_req("req-c", "work-c"))
        .await);
    let dec = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    ok(decide(&w, &attended(501), &dec, Verdict::Deny).await);
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Failed);
    assert_eq!(rec.code, Some(Code::CapabilityUnavailable));
    let replay = err(w
        .ops
        .ensure(&attended(501), approval_req("req-c", "work-c"))
        .await);
    assert_eq!(replay.code, Code::CapabilityUnavailable);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn a19_decision_issued_under_an_older_generation_is_stale() {
    let w = World::new().await;
    let e = err(w
        .ops
        .ensure(&attended(501), approval_req("req-d", "work-d"))
        .await);
    let dec = decision_ref(&e);
    // Pause narrows and bumps the authority generation.
    ok(w.ops
        .policy(
            &attended(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    let stale = err(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    assert_eq!(stale.code, Code::DecisionStale);
    // Even a denial of a stale record is refused (generation-checked).
    let stale_deny = err(decide(&w, &attended(501), &dec, Verdict::Deny).await);
    assert_eq!(stale_deny.code, Code::DecisionStale);
    assert_eq!(w.effects(), 0);
    // The waiting operation can never complete under the old generation. ADR-0006
    // §13.6 items 1–2: the pause is not an expiry; the operation keeps waiting and
    // a same-key retry is refused as a new grant under the pause.
    let replay = err(w
        .ops
        .ensure(&attended(501), approval_req("req-d", "work-d"))
        .await);
    assert_eq!(replay.code, Code::PolicyPaused);
    assert_eq!(
        w.op(replay.operation_id.as_ref().unwrap()).state,
        OperationState::AwaitingApproval
    );
}

#[tokio::test]
async fn a19_expired_decision_is_stale_operation_keeps_waiting_and_retry_gets_a_fresh_ref() {
    let w = World::new().await;
    let e = err(w
        .ops
        .ensure(&attended(501), approval_req("req-e", "work-e"))
        .await);
    let first = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    w.clock.advance(16 * MINUTE);
    let stale = err(decide(&w, &attended(501), &first, Verdict::Approve).await);
    assert_eq!(stale.code, Code::DecisionStale);
    // ADR-0006 §13.3: the expired decision does not fail the operation.
    let seen = observe(&w, &attended(501), &op, None).await;
    assert_eq!(seen.state, OperationState::AwaitingApproval);
    let retry = err(w
        .ops
        .ensure(&attended(501), approval_req("req-e", "work-e"))
        .await);
    assert_eq!(retry.code, Code::ApprovalRequired);
    let fresh = decision_ref(&retry);
    assert_ne!(
        fresh, first,
        "a same-key retry returns a fresh decision_ref"
    );
    assert_eq!(retry.operation_id, Some(op.clone()));
    let done = ok(decide(&w, &attended(501), &fresh, Verdict::Approve).await);
    assert_eq!(done.data["operation_state"], "succeeded");
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a19_pending_approval_whose_grant_deadline_passes_fails_with_credential_expired() {
    let w = World::new().await;
    let mut req = approval_req("req-f", "work-f");
    req.until = Some(DeadlineIntent::Duration("10m".into()));
    let e = err(w.ops.ensure(&attended(501), req.clone()).await);
    let dec = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    let resolved = w
        .store
        .transaction(|tx| tx.recovery_intent(&op))
        .unwrap()
        .unwrap()
        .resolved
        .unwrap();
    let grant = resolved.grant.unwrap();
    assert_eq!(w.grant(&grant).state, GrantState::AwaitingApproval);
    // The decision (15 min) outlives the grant deadline (10 min): nothing waits
    // past its deadline.
    w.clock.advance(11 * MINUTE);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&grant).state, GrantState::Expired);
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Failed);
    assert_eq!(rec.code, Some(Code::CredentialExpired));
    let replay = err(w.ops.ensure(&attended(501), req).await);
    assert_eq!(replay.code, Code::CredentialExpired);
    let late = err(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    assert_eq!(late.code, Code::DecisionStale);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn a19_caller_timeout_is_not_cancellation() {
    let w = World::new().await;
    let mut req = ensure_req("req-g", "work-g", &[("h1", "deploy")]);
    req.wait = WaitMode::Sync { timeout_ms: 0 };
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::Accepted);
    assert_eq!(e.next.action, "observe");
    let op = e.operation_id.clone().unwrap();
    // The work continues after the caller's wait ended.
    let seen = observe(&w, &unattended(501), &op, Some(5_000)).await;
    assert_eq!(seen.state, OperationState::Succeeded);
    assert!(w.op(&op).cancellation.is_none());
    let mut async_req = ensure_req("req-g2", "work-g2", &[("h1", "deploy")]);
    async_req.wait = WaitMode::Async;
    let accepted = err(w.ops.ensure(&unattended(501), async_req).await);
    assert_eq!(accepted.code, Code::Accepted);
    // A bounded observe of a waiting operation times out without changing it.
    let pending = err(w
        .ops
        .ensure(&unattended(501), approval_req("req-g3", "work-g3"))
        .await);
    let pop = pending.operation_id.clone().unwrap();
    let timed = observe(&w, &unattended(501), &pop, Some(20)).await;
    assert_eq!(timed.state, OperationState::AwaitingApproval);
    assert_eq!(w.op(&pop).state, OperationState::AwaitingApproval);
    assert!(w.op(&pop).cancellation.is_none());
}

#[tokio::test]
async fn a19_explicit_cancel_reports_possible_external_effect() {
    // Interrupt after the effect was confirmed, before activation.
    let hook = ScriptedStageHook::new([(EnsureStage::Probe, Code::ServiceUnavailable)], []);
    let w = World::with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-h", "work-h", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::ServiceUnavailable);
    assert_eq!(e.effect_status, EffectStatus::Partial);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Running);
    let c = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(c.data["state"], "cancelled");
    assert_eq!(c.data["may_have_external_effect"], true);
    // The prepared credential is cleaned up locally.
    assert_eq!(w.fake.revocations.lock().unwrap().len(), 1);
    let replay = err(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(replay.code, Code::OperationCancelled);
    assert_eq!(replay.effect_status, EffectStatus::Partial);
    // Cancel is idempotent on a settled operation.
    let again = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(again.data["state"], "cancelled");
    // Cancelling before any effect reports none.
    let pending = err(w
        .ops
        .ensure(&unattended(501), approval_req("req-h2", "work-h2"))
        .await);
    let none = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: pending.operation_id.clone().unwrap(),
            },
        )
        .await);
    assert_eq!(none.data["may_have_external_effect"], false);
}

#[tokio::test]
async fn a19_outcome_unknown_from_the_adapter_is_never_reported_as_no_effect() {
    let w = World::with(Setup {
        script: vec![
            FakeStep::ApplyButLoseReply(outcome()),
            FakeStep::Prepare(outcome()),
        ],
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-i", "work-i", &[("h1", "deploy")]);
    let r = w.ops.ensure(&unattended(501), req.clone()).await;
    let env = rendered(&r);
    let e = err(r);
    assert_eq!(e.code, Code::OutcomeUnknown);
    assert_eq!(e.code.exit_code(), ExitCode::OutcomeUnknown);
    assert_eq!(e.effect_status, EffectStatus::Unknown);
    assert!(!e.code.retryable());
    assert_eq!(env["state"], "outcome_unknown");
    assert_eq!(env["data"]["error"]["effect_status"], "unknown");
    let op = e.operation_id.clone().unwrap();
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::OutcomeUnknown);
    assert_eq!(rec.effect_status, EffectStatus::Unknown);
    // Cancel cannot turn an uncertain effect into "not applied".
    let c = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(c.data["state"], "outcome_unknown");
    assert_eq!(c.data["may_have_external_effect"], true);
    // A same-key retry reconciles through the recorded adapter, never re-prepares.
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.code, Code::AccessReady);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a19_widening_policy_actions_always_create_a_decision_record() {
    let w = World::new().await;
    let paused = ok(w
        .ops
        .policy(
            &unattended(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(paused.data["paused"], true);
    let blocked = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-j", "work-j", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(blocked.code, Code::PolicyPaused);
    assert_eq!(blocked.code.exit_code(), ExitCode::Denied);
    // Unattended resume: INTERACTION_REQUIRED + decision_ref, nothing executed.
    let u = err(w
        .ops
        .policy(
            &unattended(501),
            PolicyAction::Resume {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(u.code, Code::InteractionRequired);
    let dec = decision_ref(&u);
    // Attended resume: APPROVAL_REQUIRED + the same coalesced record; still paused.
    let a = err(w
        .ops
        .policy(
            &attended(501),
            PolicyAction::Resume {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(a.code, Code::ApprovalRequired);
    assert_eq!(decision_ref(&a), dec);
    let still = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-j2", "work-j2", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(still.code, Code::PolicyPaused);
    ok(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    let ready = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-j3", "work-j3", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(ready.code, Code::AccessReady);
    // A cutoff narrows at once; clearing it is a decision.
    let at = shift(t0(), 3600);
    ok(w.ops
        .policy(
            &unattended(501),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at,
            },
        )
        .await);
    let clear = err(w
        .ops
        .policy(
            &attended(501),
            PolicyAction::ClearCutoff {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(clear.code, Code::ApprovalRequired);
    // Moving a cutoff later widens too.
    let later = err(w
        .ops
        .policy(
            &attended(501),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at: shift(t0(), 7200),
            },
        )
        .await);
    assert_eq!(later.code, Code::ApprovalRequired);
    ok(decide(&w, &attended(501), &decision_ref(&clear), Verdict::Approve).await);
    let p = w
        .store
        .transaction(|tx| tx.policy(&policy_id()))
        .unwrap()
        .unwrap();
    assert_eq!(p.cutoff_at, None);
    // Only the owner role may act on the owner channel.
    let lim = err(w
        .ops
        .policy(
            &limited(502),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(lim.code, Code::CapabilityUnavailable);
}

#[tokio::test]
async fn a19_time_confirmation_needs_attendance_and_never_moves_a_deadline() {
    let w = World::new().await;
    let ready = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-k", "work-k", &[("h1", "deploy")]),
        )
        .await);
    let before = w.grant(&ready.data.grant_id).deadline;
    let u = err(w
        .ops
        .confirm_time(
            &unattended(501),
            ConfirmTimeRequest {
                observed_wall: w.clock.wall(),
            },
        )
        .await);
    assert_eq!(u.code, Code::InteractionRequired);
    let far = err(w
        .ops
        .confirm_time(
            &attended(501),
            ConfirmTimeRequest {
                observed_wall: shift(w.clock.wall(), 3600),
            },
        )
        .await);
    assert_eq!(far.code, Code::TimeUncertain);
    let c = ok(w
        .ops
        .confirm_time(
            &attended(501),
            ConfirmTimeRequest {
                observed_wall: w.clock.wall(),
            },
        )
        .await);
    assert_eq!(c.data["deadlines_moved"], false);
    assert_eq!(w.grant(&ready.data.grant_id).deadline, before);
}

#[tokio::test]
async fn a19_running_limit_gives_backpressure_and_persists_nothing() {
    let w = World::with(Setup {
        limits: Limits {
            max_running_operations: 0,
            ..Limits::default()
        },
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-l", "work-l", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.code, Code::Backpressure);
    assert!(e.next.retry_after_ms.is_some());
    let key = heimdall_domain::idempotency::IdempotencyKey {
        caller: ctx(501, ClientRole::Owner),
        kind: heimdall_domain::operation::OperationKind::Ensure,
        request_id: RequestId::parse("req-l").unwrap(),
    };
    assert!(
        w.store
            .transaction(|tx| tx.idempotency_record(&key))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a19_uncertain_time_stops_activation_but_passive_reads_continue_with_a_warning() {
    let w = World::new().await;
    // Reboot with the wall clock behind the mark and no synchronization.
    w.clock.reboot(shift(t0(), -600));
    w.sync.set(SyncStatus::Unknown);
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-m", "work-m", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.code, Code::TimeUncertain);
    assert_eq!(w.effects(), 0);
    let r = ok(w
        .ops
        .inspect(
            &unattended(501),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Operations,
                preview: None,
            },
        )
        .await);
    assert!(r.warnings.iter().any(|w| w.code == "TIME_UNCERTAIN"));
}

#[tokio::test]
async fn a19_inspect_reports_capabilities_decisions_and_previews_without_effects() {
    let w = World::new().await;
    let caps = ok(w
        .ops
        .inspect(
            &unattended(501),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Capabilities,
                preview: Some(heimdall_contract::request::EnsurePreview {
                    profile: ProfileId::parse("dev").unwrap(),
                    environment: None,
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                }),
            },
        )
        .await);
    assert!(
        caps.data["codes"]
            .as_array()
            .is_some_and(|c| c.len() == Code::all().len())
    );
    // The whole profile includes h3: the preview says approval, and nothing happened.
    assert_eq!(caps.data["preview"]["outcome"], "approval_required");
    assert_eq!(w.effects(), 0);
    let e = err(w
        .ops
        .ensure(&unattended(501), approval_req("req-n", "work-n"))
        .await);
    let decisions = ok(w
        .ops
        .inspect(
            &unattended(501),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Decisions,
                preview: None,
            },
        )
        .await);
    let listed = decisions.data["decisions"].as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0]["decision_id"],
        e.next.decision_ref.clone().unwrap()
    );
    assert_eq!(listed[0]["expired"], false);
}

// =================================================================================
// A06 — idempotency and interrupted requests
// =================================================================================

#[tokio::test]
async fn a06_duplicate_concurrent_requests_make_one_operation_and_one_effect() {
    let w = World::new().await;
    let req = ensure_req("req-dup", "work-dup", &[("h1", "deploy")]);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let ops = w.ops.clone();
        let req = req.clone();
        tasks.push(tokio::spawn(async move {
            ops.ensure(&unattended(501), req).await
        }));
    }
    let mut ops = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for t in tasks {
        let done = ok(t.await.unwrap());
        ops.insert(done.operation_id.unwrap());
        bindings.insert(done.data.binding_id);
    }
    assert_eq!(ops.len(), 1);
    assert_eq!(bindings.len(), 1);
    assert_eq!(w.effects(), 1);
    assert_eq!(w.bindings_for("work-dup").len(), 1);
}

#[tokio::test]
async fn a06_a_dropped_caller_and_a_retry_converge_on_one_result() {
    let w = World::new().await;
    let req = ensure_req("req-drop", "work-drop", &[("h1", "deploy")]);
    // The caller goes away before any answer (its future is dropped).
    let _ = tokio::time::timeout(Duration::ZERO, w.ops.ensure(&unattended(501), req.clone())).await;
    let first = ok(w.ops.ensure(&unattended(501), req.clone()).await);
    let second = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(first.data, second.data);
    assert_eq!(w.effects(), 1);
    assert_eq!(w.bindings_for("work-drop").len(), 1);
}

#[tokio::test]
async fn a06_same_key_with_altered_parameters_conflicts() {
    let w = World::new().await;
    let done = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-c1", "work-c1", &[("h1", "deploy")]),
        )
        .await);
    let mut altered = ensure_req("req-c1", "work-c1", &[("h1", "deploy")]);
    altered.until = Some(DeadlineIntent::Duration("30m".into()));
    let e = err(w.ops.ensure(&unattended(501), altered).await);
    assert_eq!(e.code, Code::RequestConflict);
    assert_eq!(e.code.exit_code(), ExitCode::Conflict);
    assert_eq!(e.operation_id, done.operation_id);
    // Delivery preferences are not part of the hash: a different wait replays.
    let mut waited = ensure_req("req-c1", "work-c1", &[("h1", "deploy")]);
    waited.wait = WaitMode::Sync { timeout_ms: 5 };
    waited.interaction = InteractionMode::Interactive;
    let replay = ok(w.ops.ensure(&unattended(501), waited).await);
    assert_eq!(replay.operation_id, done.operation_id);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a06_purged_key_is_request_expired_inside_the_marker_window() {
    let w = World::new().await;
    let req = ensure_req("req-p", "work-p", &[("h1", "deploy")]);
    let first = ok(w.ops.ensure(&unattended(501), req.clone()).await);
    // Past retention (7 d after settlement): purge leaves a marker.
    w.clock.advance(8 * DAY);
    w.ops.tick().await.unwrap();
    assert!(
        w.store
            .transaction(|tx| tx.operation(first.operation_id.as_ref().unwrap()))
            .unwrap()
            .is_none()
    );
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::RequestExpired);
    assert_eq!(e.code.exit_code(), ExitCode::Conflict);
    // Beyond the marker window the key is no longer known: it is new work, which
    // for the same work ID cannot reset the ended binding (spec §6.1).
    w.clock.advance(31 * DAY);
    w.ops.tick().await.unwrap();
    let late = err(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(late.code, Code::CredentialExpired);
    assert_ne!(late.operation_id, first.operation_id);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a06_crash_before_the_effect_then_restart_completes_with_one_effect() {
    let hook = ScriptedStageHook::new([(EnsureStage::Reconcile, Code::ServiceUnavailable)], []);
    let mut w = World::with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-cb", "work-cb", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::ServiceUnavailable);
    assert_eq!(e.effect_status, EffectStatus::None);
    assert_eq!(w.effects(), 0);
    // In-process restart: recovery re-drives the operation from its receipts.
    w.restart_with_hook(Arc::new(NoStageHook)).await;
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a06_lost_reply_then_restart_reconciles_without_a_second_effect() {
    let mut w = World::with(Setup {
        script: vec![
            FakeStep::ApplyButLoseReply(outcome()),
            FakeStep::Prepare(outcome()),
        ],
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-lr", "work-lr", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::OutcomeUnknown);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.effects(), 1);
    // In-process restart (same fake adapter instance and ledger): recovery asks
    // the recorded adapter to reconcile the recorded effect token.
    w.restart().await;
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Succeeded);
    let receipts = w.store.transaction(|tx| tx.stage_receipts(&op)).unwrap();
    assert!(receipts.iter().any(|r| matches!(
        r.effect,
        heimdall_domain::operation::EffectReceipt::Uncertain { .. }
    )));
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(
        w.effects(),
        1,
        "reconciliation never performs a second effect"
    );
}

#[tokio::test]
async fn a06_lost_reply_then_restart_with_a_new_adapter_over_the_same_ledger_settles_once() {
    // A **new** `FakeCredentialAdapter` instance after the restart sees the effect
    // only through the durable ledger file (`with_ledger`). In-process
    // reconstruction: process-crash evidence is U9/U10's.
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("effects.ledger");
    let mut w = World::with(Setup {
        script: vec![FakeStep::ApplyButLoseReply(outcome())],
        ledger: Some(ledger.clone()),
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-led", "work-led", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::OutcomeUnknown);
    assert_eq!(
        FakeCredentialAdapter::ledger_entries(&ledger)
            .unwrap()
            .len(),
        1
    );
    // Replace the adapter instance (same identity, same ledger) and restart.
    w.fake =
        FakeCredentialAdapter::with_ledger(descriptor(), [FakeStep::Prepare(outcome())], &ledger)
            .unwrap();
    w.restart().await;
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(
        FakeCredentialAdapter::ledger_entries(&ledger)
            .unwrap()
            .len(),
        1,
        "exactly one ledger entry: reconciled, never re-prepared"
    );
}

#[tokio::test]
async fn a06_crash_after_the_effect_before_its_receipt_reconciles_on_restart() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let mut w = World::with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    // Fail the first commit after the adapter applied its effect: the
    // `Confirmed` receipt never becomes durable.
    faults.arm_after_effect(w.fake.clone());
    let req = ensure_req("req-ae", "work-ae", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::StateUnavailable);
    assert_eq!(faults.fired.load(Ordering::SeqCst), 1);
    assert_eq!(w.effects(), 1);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Running);
    let receipts = w.store.transaction(|tx| tx.stage_receipts(&op)).unwrap();
    assert!(matches!(
        receipts.last().map(|r| &r.effect),
        Some(heimdall_domain::operation::EffectReceipt::Attempted { .. })
    ));
    w.restart().await;
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a06_crash_after_the_receipt_completes_on_restart_with_one_effect() {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let mut w = World::with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-ar", "work-ar", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.effect_status, EffectStatus::Partial);
    w.restart_with_hook(Arc::new(NoStageHook)).await;
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, e.operation_id);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a06_restart_never_resets_a_resolved_deadline() {
    let hook = ScriptedStageHook::new([(EnsureStage::Commit, Code::ServiceUnavailable)], []);
    let mut w = World::with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let mut req = ensure_req("req-dl", "work-dl", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    err(w.ops.ensure(&unattended(501), req.clone()).await);
    w.clock.advance(10 * MINUTE);
    w.restart_with_hook(Arc::new(NoStageHook)).await;
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    // Resolved once at t0: a retry or restart never re-resolves "1h".
    assert_eq!(ready.data.expires_at, shift(t0(), 3600));
    assert_eq!(w.effects(), 1);
}

// =================================================================================
// Fault points (plan §6.4): before/after every pipeline stage; commit faults
// =================================================================================

#[tokio::test]
async fn fault_points_before_and_after_every_stage_recover_with_one_effect() {
    for stage in EnsureStage::ALL {
        for after in [false, true] {
            let script = [(stage, Code::ServiceUnavailable)];
            let hook = if after {
                ScriptedStageHook::new([], script)
            } else {
                ScriptedStageHook::new(script, [])
            };
            let mut w = World::with(Setup {
                hook: hook.clone(),
                ..Setup::default()
            })
            .await;
            let req = ensure_req("req-fp", "work-fp", &[("h1", "deploy")]);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            assert_eq!(e.code, Code::ServiceUnavailable, "{stage:?} after={after}");
            assert!(
                hook.visited
                    .lock()
                    .unwrap()
                    .contains(&(stage, if after { "after" } else { "before" })),
                "{stage:?} after={after}"
            );
            // Half the cases resume through restart recovery, half through a
            // same-key retry in the same process.
            if after {
                w.restart().await;
            }
            let ready = ok(w.ops.ensure(&unattended(501), req).await);
            if let Some(op) = &e.operation_id {
                assert_eq!(
                    ready.operation_id.as_ref(),
                    Some(op),
                    "{stage:?} after={after}"
                );
            }
            assert_eq!(w.effects(), 1, "{stage:?} after={after}");
            assert_eq!(
                w.bindings_for("work-fp").len(),
                1,
                "{stage:?} after={after}"
            );
        }
    }
}

#[tokio::test]
async fn fault_commit_failing_before_commit_leaves_no_binding_and_no_event() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let w = World::with(Setup {
        faults: faults.clone(),
        hook: ArmAt::new(EnsureStage::Commit, faults.clone()),
        ..Setup::default()
    })
    .await;
    let mut live = w.ops.events().live_receiver();
    let req = ensure_req("req-bc", "work-bc", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::StateUnavailable);
    assert_eq!(faults.fired.load(Ordering::SeqCst), 1);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Running);
    assert!(w.bindings_for("work-bc").is_empty(), "no active binding");
    let stored = w.events();
    assert!(
        !stored
            .iter()
            .any(|e| e.event.event_type == EventType::OperationStateChanged
                && e.event.payload["state"] == "succeeded")
    );
    // Nothing about a success was announced live either.
    while let Ok(ev) = live.try_recv() {
        assert!(
            !(ev.event.event_type == EventType::OperationStateChanged
                && ev.event.payload["state"] == "succeeded")
        );
    }
    // The retry completes it exactly once.
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(w.bindings_for("work-bc").len(), 1);
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn fault_commit_failing_after_commit_is_replayed_by_the_retry() {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let w = World::with(Setup {
        faults: faults.clone(),
        hook: ArmAt::new(EnsureStage::Commit, faults.clone()),
        ..Setup::default()
    })
    .await;
    let req = ensure_req("req-acf", "work-acf", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::StateUnavailable);
    let op = e.operation_id.clone().unwrap();
    // Durable despite the error the caller saw.
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    assert_eq!(w.bindings_for("work-acf").len(), 1);
    let ready = ok(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(ready.data.binding_id, w.bindings_for("work-acf")[0].id);
    assert_eq!(w.effects(), 1);
}

// =================================================================================
// A29 local — hostile input and authorization forgery
// =================================================================================

#[tokio::test]
async fn a29_the_same_request_id_from_another_owner_is_a_distinct_key() {
    let w = World::new().await;
    let a = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("shared", "work-501", &[("h1", "deploy")]),
        )
        .await);
    // Different parameters, same request ID, different principal: no conflict.
    let b = ok(w
        .ops
        .ensure(
            &unattended(502),
            ensure_req("shared", "work-502", &[("h2", "deploy")]),
        )
        .await);
    assert_ne!(a.operation_id, b.operation_id);
    assert_eq!(w.effects(), 2);
}

#[tokio::test]
async fn a29_another_principals_binding_is_not_found_or_not_owner() {
    let w = World::new().await;
    let done = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-o", "work-o", &[("h1", "deploy")]),
        )
        .await);
    let op = done.operation_id.clone().unwrap();
    let foreign = limited(777);
    let rel = err(w
        .ops
        .release(
            &foreign,
            ReleaseRequest {
                binding_id: done.data.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(rel.code, Code::CapabilityUnavailable);
    let bind = err(w
        .ops
        .bind(
            &foreign,
            BindRequest {
                binding_id: done.data.binding_id.clone(),
                form: BindForm::Materialize,
                request_id: RequestId::parse("bind-x").unwrap(),
            },
        )
        .await);
    assert_eq!(bind.code, Code::NotFound);
    let del = err(w
        .ops
        .delegate(
            &foreign,
            DelegateRequest {
                parent_binding_id: done.data.binding_id.clone(),
                scope: BTreeSet::new(),
                until: None,
                work_id: WorkId::parse("child").unwrap(),
                request_id: RequestId::parse("del-x").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await);
    assert_eq!(del.code, Code::NotFound);
    let obs = err(w
        .ops
        .observe(
            &foreign,
            ObserveRequest::Operation {
                operation_id: op.clone(),
                wait_ms: None,
            },
        )
        .await);
    assert_eq!(obs.code, Code::NotFound);
    let can = err(w
        .ops
        .cancel(&foreign, CancelRequest { operation_id: op })
        .await);
    assert_eq!(can.code, Code::NotFound);
    let rev = err(w
        .ops
        .revoke(
            &foreign,
            RevokeRequest {
                grant_id: done.data.grant_id.clone(),
                request_id: RequestId::parse("rev-x").unwrap(),
            },
        )
        .await);
    assert_eq!(rev.code, Code::NotFound);
    // The binding is untouched.
    assert_eq!(
        w.bindings_for("work-o")[0].state,
        heimdall_domain::binding::BindingState::Active
    );
}

#[tokio::test]
async fn a29_request_fields_never_widen_the_resolved_scope() {
    let w = World::new().await;
    // A pair outside the profile.
    let outside = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-w1", "work-w1", &[("evil", "root")]),
        )
        .await);
    assert_eq!(outside.code, Code::UsageError);
    // A capability the profile does not carry.
    let mut caps = ensure_req("req-w2", "work-w2", &[("h1", "deploy")]);
    caps.required_capabilities.capabilities = [Capability::AgentForwarding].into_iter().collect();
    let refused = err(w.ops.ensure(&unattended(501), caps).await);
    assert_eq!(refused.code, Code::CapabilityUnavailable);
    // Another environment named in the request.
    let mut other = ensure_req("req-w3", "work-w3", &[("h1", "deploy")]);
    other.environment = Some(EnvironmentId::from_random_bytes([9; 16]));
    assert_eq!(
        err(w.ops.ensure(&unattended(501), other).await).code,
        Code::NotFound
    );
    // A deadline request beyond the policy window is added authority, not a grant.
    let mut long = ensure_req("req-w4", "work-w4", &[("h1", "deploy")]);
    long.until = Some(DeadlineIntent::Duration("6h".into()));
    assert_eq!(
        err(w.ops.ensure(&unattended(501), long).await).code,
        Code::InteractionRequired
    );
    // What is granted is within policy ∩ profile ∩ request.
    let ok_req = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-w5", "work-w5", &[("h1", "deploy")]),
        )
        .await);
    let g = w.grant(&ok_req.data.grant_id);
    assert!(g.scope.pairs.is_subset(&policy_pairs()));
    assert_eq!(g.scope.capabilities, ssh_only());
    assert_eq!(w.effects(), 1);
}

#[tokio::test]
async fn a29_metadata_is_ignored_and_attendance_is_never_a_request_field() {
    let w = World::new().await;
    let plain = ensure_req(
        "req-meta",
        "work-meta",
        &[("h1", "deploy"), ("h3", "deploy")],
    );
    let mut doc = serde_json::to_value(&plain).unwrap();
    // Forged metadata and a forged "attended"/"approved" flag in the body.
    doc["agent_name"] = serde_json::json!("owner-approved-agent");
    doc["attended"] = serde_json::json!(true);
    doc["approved"] = serde_json::json!(true);
    doc["decision"] = serde_json::json!({ "verdict": "approve" });
    let forged: EnsureRequest = serde_json::from_value(doc).unwrap();
    assert_eq!(forged, plain);
    let first = err(w.ops.ensure(&unattended(501), forged).await);
    assert_eq!(
        first.code,
        Code::InteractionRequired,
        "request content never becomes consent"
    );
    let replay = err(w.ops.ensure(&unattended(501), plain).await);
    assert_eq!(replay.operation_id, first.operation_id);
    // A decide body with an "attended" field is still refused on an unattended
    // session.
    let decide_doc = serde_json::json!({
        "decision_id": first.next.decision_ref.clone().unwrap(),
        "verdict": "approve",
        "attended": true,
    });
    let req: DecideRequest = serde_json::from_value(decide_doc).unwrap();
    let refused = err(w.ops.decide(&unattended(501), req).await);
    assert_eq!(refused.code, Code::InteractionRequired);
    assert_eq!(w.effects(), 0);
}

#[tokio::test]
async fn a29_only_an_interactive_session_may_attend() {
    let w = World::new().await;
    let e = w.ops.attend(&unattended(501)).await.unwrap_err();
    assert_no_canary(&serde_json::to_string(&e.clone().into_envelope()).unwrap());
    assert_eq!(e.code, Code::InteractionRequired);
    let mut interactive = unattended(501);
    interactive.interaction = InteractionMode::Interactive;
    let a = w.ops.attend(&interactive).await.unwrap();
    assert_eq!(a.code, Code::Ok);
    assert!(matches!(a.data, Attendance::Attended { .. }));
    // Attending says nothing about any action: the caller's own copy of the
    // session is what the runtime marks; a decision still needs `decide`.
    assert!(!unattended(501).is_attended());
}

// =================================================================================
// Bind, release, delegate
// =================================================================================

#[tokio::test]
async fn bind_materializes_an_existing_binding_without_a_new_effect() {
    let w = World::new().await;
    let done = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-bd", "work-bd", &[("h1", "deploy")]),
        )
        .await);
    let req = BindRequest {
        binding_id: done.data.binding_id.clone(),
        form: BindForm::Materialize,
        request_id: RequestId::parse("bind-1").unwrap(),
    };
    let b = ok(w.ops.bind(&unattended(501), req.clone()).await);
    assert_eq!(b.code, Code::AccessReady);
    assert_eq!(b.data.binding_id, done.data.binding_id);
    assert_eq!(b.data.grant_id, done.data.grant_id);
    assert!(b.data.usable_until <= b.data.expires_at);
    let again = ok(w.ops.bind(&unattended(501), req).await);
    assert_eq!(again.operation_id, b.operation_id);
    assert_eq!(w.effects(), 1);
    let launch = err(w
        .ops
        .bind(
            &unattended(501),
            BindRequest {
                binding_id: done.data.binding_id.clone(),
                // ⟨M02⟩ m02-plan §5 item 5 (Q8): `argv` left the contract; an
                // invalid launch binding (empty executable) is still refused.
                form: BindForm::Launch(heimdall_contract::request::LaunchBinding {
                    executable: String::new(),
                    holder: None,
                }),
                request_id: RequestId::parse("bind-2").unwrap(),
            },
        )
        .await);
    assert_eq!(launch.code, Code::UsageError);
}

#[tokio::test]
async fn release_is_idempotent_and_the_last_reference_releases_without_revoking() {
    let w = World::new().await;
    let done = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-rl", "work-rl", &[("h1", "deploy")]),
        )
        .await);
    let first = ok(w
        .ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: done.data.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(first.data["outcome"]["outcome"], "released");
    assert_eq!(first.data["grant_state"], "released");
    let second = ok(w
        .ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: done.data.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(second.data["outcome"]["outcome"], "already_released");
    // Release is never revoke: no tombstone, no adapter revocation.
    let tomb = w
        .store
        .transaction(|tx| tx.tombstone(&done.data.grant_id))
        .unwrap();
    assert!(tomb.is_none());
    assert!(w.fake.revocations.lock().unwrap().is_empty());
    let unknown = err(w
        .ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: heimdall_contract::ids::BindingId::from_random_bytes([3; 16]),
            },
        )
        .await);
    assert_eq!(unknown.code, Code::NotFound);
}

#[tokio::test]
async fn delegate_creates_a_narrower_child_and_refuses_a_wider_or_longer_one() {
    let w = World::new().await;
    let parent = ok(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-par", "work-par", &[("h1", "deploy"), ("h2", "deploy")]),
        )
        .await);
    let child = |scope: &[(&str, &str)], until: Option<&str>, rid: &str| DelegateRequest {
        parent_binding_id: parent.data.binding_id.clone(),
        scope: scope.iter().map(|(d, a)| pair(d, a)).collect(),
        until: until.map(|u| DeadlineIntent::Duration(u.into())),
        work_id: WorkId::parse(&format!("child-{rid}")).unwrap(),
        request_id: RequestId::parse(rid).unwrap(),
        required_capabilities: RequiredCapabilities::default(),
    };
    let c = ok(w
        .ops
        .delegate(
            &unattended(501),
            child(&[("h1", "deploy")], Some("30m"), "d1"),
        )
        .await);
    let cg = w.grant(&c.data.grant_id);
    assert_eq!(cg.parent, Some(parent.data.grant_id.clone()));
    assert!(cg.deadline.effective <= w.grant(&parent.data.grant_id).deadline.effective);
    let wider = err(w
        .ops
        .delegate(&unattended(501), child(&[("h3", "deploy")], None, "d2"))
        .await);
    assert_eq!(wider.code, Code::DelegationExceedsParent);
    let longer = err(w
        .ops
        .delegate(
            &unattended(501),
            child(&[("h1", "deploy")], Some("3h"), "d3"),
        )
        .await);
    assert_eq!(longer.code, Code::DelegationExceedsParent);
    // Default deadline = the parent's.
    let dflt = ok(w
        .ops
        .delegate(&unattended(501), child(&[("h2", "deploy")], None, "d4"))
        .await);
    assert_eq!(dflt.data.expires_at, parent.data.expires_at);
    assert_eq!(w.effects(), 3);
}

// =================================================================================
// Restart recovery invariants (R-RT-07): identity and pause survive a restart
// =================================================================================

#[tokio::test]
async fn restart_never_changes_environment_identity_or_revives_a_pause() {
    let mut w = World::new().await;
    ok(w.ops
        .policy(
            &unattended(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    w.restart().await;
    let blocked = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("req-rs", "work-rs", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(
        blocked.code,
        Code::PolicyPaused,
        "a restart never revives a pause"
    );
    // A runtime started over this store with another environment ID is refused.
    let mut other = w.config();
    other.environment = EnvironmentId::from_random_bytes([9; 16]);
    let refused = Operations::start(other).await.unwrap_err();
    assert_eq!(refused.code, Code::StateUnavailable);
    assert_eq!(
        w.store.transaction(|tx| tx.self_environment()).unwrap(),
        Some(env_id())
    );
}

#[tokio::test]
async fn tick_reanchors_after_a_synchronized_reboot_and_expires_at_the_persisted_bound() {
    let mut w = World::new().await;
    let mut req = ensure_req("req-rb", "work-rb", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    let done = ok(w.ops.ensure(&unattended(501), req).await);
    let before = w
        .store
        .transaction(|tx| tx.grant_anchor(&done.data.grant_id))
        .unwrap()
        .unwrap();
    // Reboot 10 minutes later, synchronized, at or above the mark.
    w.clock.reboot(shift(t0(), 600));
    w.restart().await;
    w.ops.tick().await.unwrap();
    let after = w
        .store
        .transaction(|tx| tx.grant_anchor(&done.data.grant_id))
        .unwrap()
        .unwrap();
    assert_ne!(after.anchor.boot_id, before.anchor.boot_id);
    assert_eq!(
        after.bound, before.bound,
        "re-anchored with the persisted bound"
    );
    assert_eq!(w.grant(&done.data.grant_id).state, GrantState::Active);
    // The re-anchored budget ends at the same instant; the grant expires there.
    w.clock.advance(50 * MINUTE);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&done.data.grant_id).state, GrantState::Expired);
    let bind = err(w
        .ops
        .bind(
            &unattended(501),
            BindRequest {
                binding_id: done.data.binding_id.clone(),
                form: BindForm::Materialize,
                request_id: RequestId::parse("bind-rb").unwrap(),
            },
        )
        .await);
    assert_eq!(bind.code, Code::CredentialExpired);
}

// =================================================================================
// M01-U10 glue: cases the m01-plan §3 exit mapping needs and no unit suite held
// (ADR-0006 §13.5 ⟨r2.2⟩ rulings 1–2; A17-local N06; the process-crash variant of
// "crash recovery cannot reset a deadline, revive a pause, or change environment
// identity"). Same harness and production hooks as the U5 cases above.
// =================================================================================

fn u10_issuance(
    grant: &heimdall_contract::ids::GrantId,
    valid_before: Timestamp,
) -> heimdall_app::operations::IssuanceRequest {
    heimdall_app::operations::IssuanceRequest {
        grant: grant.clone(),
        pair: pair("h1", "deploy"),
        principal: "hm:h1:deploy".into(),
        key_id: "fixture-key".into(),
        valid_after: t0(),
        valid_before,
        extensions: BTreeSet::new(),
        subject_fingerprint: "fixture-fingerprint".into(),
        facts: heimdall_app::operations::IssuanceFacts {
            new_activation: false,
            subject_registered: true,
            critical_option: false,
        },
    }
}

/// The issuer's side of publication (ADR-0005 §3.5 with its 2026-11-01 amendment;
/// ADR-0006 §13.8 item 1): publish; on `Rereserved`, sign exactly the returned
/// bounds (nothing to sign in M01) and publish that reservation, until it is
/// published or refused. Bounded.
async fn issue(
    w: &World,
    first: &heimdall_contract::ids::IssuanceId,
    facts: &heimdall_app::operations::IssuanceFacts,
) -> Result<heimdall_domain::issuance::IssuanceEntry, OpError> {
    let mut id = first.clone();
    for _ in 0..8 {
        match w.ops.publish_issuance(&id, facts).await? {
            heimdall_app::operations::Publication::Published(e) => return Ok(e),
            heimdall_app::operations::Publication::Rereserved { reservation } => {
                assert_eq!(
                    reservation.state,
                    heimdall_domain::issuance::IssuanceState::Reserved
                );
                id = reservation.id;
            }
        }
    }
    panic!("publication did not converge within 8 round trips");
}

fn u10_delegate(parent: &EnsureData, rid: &str, until: &str) -> DelegateRequest {
    DelegateRequest {
        parent_binding_id: parent.binding_id.clone(),
        scope: [pair("h1", "deploy")].into_iter().collect(),
        until: Some(DeadlineIntent::Duration(until.into())),
        work_id: WorkId::parse(&format!("child-{rid}")).unwrap(),
        request_id: RequestId::parse(rid).unwrap(),
        required_capabilities: RequiredCapabilities::default(),
    }
}

async fn u10_revoke(w: &World, grant: &heimdall_contract::ids::GrantId, rid: &str) {
    let r = w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: grant.clone(),
                request_id: RequestId::parse(rid).unwrap(),
            },
        )
        .await;
    let done = ok(r);
    assert!(done.data.local_applied, "the tombstone is applied locally");
}

/// ADR-0006 §13.5 ruling 2 (A07): the authority generation is global, so a
/// revoke elsewhere moves it; the next issuance for a healthy chain re-validates
/// silently and succeeds, while a revoke of this grant's ancestor fails it.
#[tokio::test]
async fn u10_a07_unrelated_revoke_never_fails_healthy_issuance_but_an_ancestor_revoke_does() {
    let w = World::new().await;
    let mut req = ensure_req("u10-p", "u10-parent", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    let parent = ok(w.ops.ensure(&unattended(501), req).await).data;
    let mut other = ensure_req("u10-o", "u10-other", &[("h2", "deploy")]);
    other.until = Some(DeadlineIntent::Duration("1h".into()));
    let unrelated = ok(w.ops.ensure(&unattended(501), other).await).data;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "u10-c", "30m"))
        .await)
    .data;
    assert_eq!(
        w.grant(&child.grant_id).parent,
        Some(parent.grant_id.clone())
    );
    let gen_before = w.store.transaction(|tx| tx.authority_generation()).unwrap();

    // Unrelated revoke: the global generation moves, healthy work keeps issuing.
    u10_revoke(&w, &unrelated.grant_id, "u10-rv-o").await;
    let gen_after = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    assert_ne!(
        gen_before, gen_after,
        "the revoke moved the global generation"
    );
    let reserved = w
        .ops
        .reserve_issuance(u10_issuance(&child.grant_id, shift(t0(), 600)))
        .await
        .unwrap_or_else(|e| panic!("healthy child issuance refused: {} {}", e.code, e.message));
    let published = issue(&w, &reserved.id, &u10_issuance(&child.grant_id, t0()).facts)
        .await
        .unwrap_or_else(|e| panic!("healthy child publish refused: {} {}", e.code, e.message));
    assert_eq!(
        published.state,
        heimdall_domain::issuance::IssuanceState::Published
    );
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Active);

    // A revoke of the child's ancestor fails the next issuance at reserve.
    u10_revoke(&w, &parent.grant_id, "u10-rv-p").await;
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&child.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&refused.message);
    assert!(
        matches!(
            refused.code,
            Code::CredentialExpired | Code::NotFound | Code::CapabilityUnavailable
        ),
        "ancestor revoke refuses issuance, got {}",
        refused.code
    );
    let ended = w.grant(&child.grant_id).state;
    assert!(
        !matches!(ended, GrantState::Active | GrantState::Degraded),
        "the child of a revoked parent is never usable again: {ended:?}"
    );
    w.events();
}

/// ADR-0006 §13.5 ruling 1 (A07): `delegate` holds an ownership-aware reference
/// on the parent owned by the child, so releasing every consumer reference of the
/// parent leaves it `active` while the child lives; the child still issues. Once
/// the child ends, the parent may become `released`.
#[tokio::test]
async fn u10_a07_releasing_a_parent_with_a_live_child_keeps_it_active_until_the_child_ends() {
    let w = World::new().await;
    let mut req = ensure_req("u10-rp", "u10-rparent", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    let parent = ok(w.ops.ensure(&unattended(501), req).await).data;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "u10-rc", "30m"))
        .await)
    .data;
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: parent.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(
        w.grant(&parent.grant_id).state,
        GrantState::Active,
        "a live child keeps its parent active"
    );
    let reserved = w
        .ops
        .reserve_issuance(u10_issuance(&child.grant_id, shift(t0(), 600)))
        .await
        .unwrap_or_else(|e| panic!("child issuance refused: {} {}", e.code, e.message));
    assert_eq!(
        reserved.state,
        heimdall_domain::issuance::IssuanceState::Reserved
    );
    // End the child: its reference on the parent goes with it.
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: child.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Released);
    assert_eq!(
        w.grant(&parent.grant_id).state,
        GrantState::Released,
        "with the child ended and no consumer left, the parent is released"
    );
    w.events();
}

type U10Fut<'a, T> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<T, heimdall_app::ports::AdapterError>> + Send + 'a>,
>;

/// Wraps the fake through the production `CredentialAdapter` port: counts every
/// `prepare`, and optionally never returns from the `hang_on`-th call (0-based)
/// after the fake applied its effect, writing `marker` first (the process is
/// killed there: after the effect, before its receipt). `heimdall-runtime` has
/// no `async-trait` dependency, so the impl is the trait's expanded form.
struct U10Adapter {
    inner: Arc<FakeCredentialAdapter>,
    prepares: AtomicUsize,
    hang_on: Option<(usize, std::path::PathBuf)>,
}

impl U10Adapter {
    fn new(inner: Arc<FakeCredentialAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            prepares: AtomicUsize::new(0),
            hang_on: None,
        })
    }
}

impl CredentialAdapter for U10Adapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.inner.descriptor()
    }
    fn prepare<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let n = self.prepares.fetch_add(1, Ordering::SeqCst);
            let out = self.inner.prepare(req).await;
            if let Some((at, marker)) = &self.hang_on
                && *at == n
            {
                std::fs::write(marker, b"hung").unwrap();
                std::future::pending::<()>().await;
            }
            out
        })
    }
    fn renew<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.prepare(req)
    }
    fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        effect_token: &'life2 str,
    ) -> U10Fut<'async_trait, heimdall_app::ports::ReconcileOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.reconcile(grant, effect_token)
    }
    fn revoke<'life0, 'life1, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        now: Timestamp,
    ) -> U10Fut<'async_trait, heimdall_app::ports::RevokeOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.revoke(grant, now)
    }
}

/// A17 local (N06 b, fail-closed reading): repeated `AdapterError::Unavailable`
/// produces one adapter call per request, a stable `SERVICE_UNAVAILABLE` code,
/// no decision records (no prompt storm) and no retry loop of its own: neither
/// the operation, nor `tick` (the supervisor's scheduler pass), nor a restart
/// prepares again for the failed request.
#[tokio::test]
async fn u10_a17_repeated_unavailable_errors_get_a_stable_code_and_no_retry_storm() {
    let mut w = World::with(Setup {
        script: vec![FakeStep::Fail(
            heimdall_app::ports::AdapterError::Unavailable(format!("dependency {}", canary())),
        )],
        ..Setup::default()
    })
    .await;
    let counting = U10Adapter::new(w.fake.clone());
    let adapters = vec![counting.clone() as Arc<dyn CredentialAdapter>];
    let config = |w: &World| OperationsConfig {
        adapters: adapters.clone(),
        ..w.config()
    };
    w.ops = Operations::start(config(&w)).await.unwrap();

    let mut codes = Vec::new();
    for i in 0..5 {
        let req = ensure_req(&format!("u10-un-{i}"), "u10-unavail", &[("h1", "deploy")]);
        let e = err(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(
            counting.prepares.load(Ordering::SeqCst),
            i + 1,
            "exactly one adapter call per request, no hidden retry loop"
        );
        codes.push(e.code.clone());
    }
    assert!(
        codes.iter().all(|c| *c == Code::ServiceUnavailable),
        "stable failure code: {codes:?}"
    );
    // Same-key retry replays the settled failure without calling the adapter.
    let replay = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("u10-un-0", "u10-unavail", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(replay.code, Code::ServiceUnavailable);
    assert_eq!(counting.prepares.load(Ordering::SeqCst), 5);
    // Scheduler passes and a restart never re-drive the failed requests.
    for _ in 0..10 {
        w.clock.advance(MINUTE);
        w.ops.tick().await.unwrap();
    }
    w.ops = Operations::start(config(&w)).await.unwrap();
    w.ops.tick().await.unwrap();
    assert_eq!(
        counting.prepares.load(Ordering::SeqCst),
        5,
        "no supervisor or restart retry storm"
    );
    assert_eq!(w.effects(), 0);
    let decisions = w.store.transaction(|tx| tx.pending_decisions()).unwrap();
    assert!(
        decisions.is_empty(),
        "an unavailable dependency never prompts"
    );
    assert!(w.bindings_for("u10-unavail").is_empty());
    w.events();
}

/// A17 local (N06 a) at the substrate level: a cleanup planned for generation N
/// (`reconcile::plan`) races its replacement N+1 created at the deletion boundary
/// (between the decision and the delete). The delete is the generation-CAS write
/// `Txn::upsert_resource(.., Some(N))`; it is refused and N+1 survives, and
/// `reconcile::guard_cleanup` reports `Superseded`. M01 has no production
/// executor that deletes resources (U8b escalation); this case exercises the
/// production planner, guard and store CAS that such an executor must use.
#[tokio::test]
async fn u10_a17_cleanup_of_generation_n_never_deletes_its_replacement_n_plus_1() {
    use heimdall_app::reconcile::{Action, guard_cleanup, plan};
    use heimdall_domain::resource::{
        CleanupDecision, ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
    };
    let w = World::new().await;
    let id = heimdall_contract::ids::ResourceId::from_random_bytes([3; 16]);
    let gen_n = ManagedResource {
        id: id.clone(),
        kind: ResourceKind::Endpoint,
        owner: OwnerRef::Runtime,
        generation: ResourceGeneration(1),
        desired: ResourceState::Present,
        observed: ResourceState::Present,
        last_operation: None,
        locator: "fixture-endpoint".into(),
        updated_at: t0(),
    };
    w.store
        .transaction(|tx| tx.upsert_resource(&gen_n, None))
        .unwrap();
    // Generation N's owner ends: desired becomes absent; the planner decides.
    let mut ending = gen_n.clone();
    ending.desired = ResourceState::Absent;
    w.store
        .transaction(|tx| tx.upsert_resource(&ending, Some(ResourceGeneration(1))))
        .unwrap();
    let planned = w
        .store
        .transaction(|tx| tx.resources_needing_reconcile())
        .unwrap();
    assert_eq!(planned.len(), 1);
    let Action::Cleanup { generation } = plan(&planned[0]) else {
        panic!("cleanup expected, got {:?}", plan(&planned[0]));
    };
    assert_eq!(generation, ResourceGeneration(1));
    // Deletion boundary: the replacement N+1 is created now.
    let replacement = ManagedResource {
        generation: ResourceGeneration(2),
        desired: ResourceState::Present,
        observed: ResourceState::Present,
        locator: "fixture-endpoint-2".into(),
        updated_at: shift(t0(), 1),
        ..gen_n.clone()
    };
    w.store
        .transaction(|tx| tx.upsert_resource(&replacement, Some(ResourceGeneration(1))))
        .unwrap();
    // The delayed delete of N, bound to its generation, is refused.
    let deleted = ManagedResource {
        observed: ResourceState::Absent,
        updated_at: shift(t0(), 2),
        ..ending.clone()
    };
    let refused = w
        .store
        .transaction(|tx| tx.upsert_resource(&deleted, Some(generation)));
    assert!(
        matches!(
            refused,
            Err(heimdall_store::StoreError::GenerationConflict(_))
        ),
        "stale cleanup refused: {refused:?}"
    );
    let current = w.store.transaction(|tx| tx.resource(&id)).unwrap().unwrap();
    assert_eq!(current, replacement, "N+1 survives untouched");
    assert_eq!(
        guard_cleanup(generation, &current),
        CleanupDecision::Superseded
    );
    assert_eq!(plan(&current), Action::None);
}

// ---------------------------------------------------------------------------------
// Process-crash variant (core in a child process, killed by exact handle)
// ---------------------------------------------------------------------------------

const U10_CRASH_DIR: &str = "HEIMDALL_U10_CRASH_DIR";

fn u10_crash_config(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    adapter: Arc<dyn CredentialAdapter>,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![adapter],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    }
}

/// Child entry for the process-crash case: does nothing unless the parent set
/// `HEIMDALL_U10_CRASH_DIR`. In the child: an on-disk store, the fake adapter
/// over a durable ledger, ensure A to completion (1 h), ensure B left hanging
/// after its effect, then the policy paused; the parent kills the process.
#[tokio::test]
async fn u10_crash_child_entry() {
    let Some(dir) = std::env::var_os(U10_CRASH_DIR).map(std::path::PathBuf::from) else {
        return;
    };
    let store =
        Arc::new(Store::open(&dir.join("state.db"), Arc::new(heimdall_store::NoFaults)).unwrap());
    seed(&store);
    let clock = VirtualClock::at(t0());
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::with_ledger(
        descriptor(),
        vec![FakeStep::Prepare(outcome())],
        dir.join("ledger"),
    )
    .unwrap();
    let adapter = Arc::new(U10Adapter {
        inner: fake,
        prepares: AtomicUsize::new(0),
        hang_on: Some((1, dir.join("hung"))),
    });
    let ops = Operations::start(u10_crash_config(&store, &clock, &sync, adapter))
        .await
        .unwrap();
    let mut a = ensure_req("u10-crash-a", "u10-crash-a", &[("h1", "deploy")]);
    a.until = Some(DeadlineIntent::Duration("1h".into()));
    let done = ok(ops.ensure(&unattended(501), a).await);
    std::fs::write(dir.join("a.json"), serde_json::to_vec(&done.data).unwrap()).unwrap();
    let ops = Arc::new(ops);
    let b_ops = ops.clone();
    tokio::spawn(async move {
        let mut b = ensure_req("u10-crash-b", "u10-crash-b", &[("h2", "deploy")]);
        b.until = Some(DeadlineIntent::Duration("1h".into()));
        let _ = b_ops.ensure(&unattended(501), b).await;
    });
    while !dir.join("hung").exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ok(ops
        .policy(
            &unattended(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    std::fs::write(dir.join("paused"), b"paused").unwrap();
    std::future::pending::<()>().await;
}

fn u10_wait_for(path: &std::path::Path, child: &mut std::process::Child) {
    let start = std::time::Instant::now();
    while !path.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("crash child exited early: {status}");
        }
        if start.elapsed() > Duration::from_secs(60) {
            // Only the exact child this test spawned.
            child.kill().ok();
            child.wait().ok();
            panic!("crash child did not reach {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// **Process-crash** (plan §5 M01 exit; m01-plan §3; spec A06/A17 local): the
/// operations core runs in a child process over an on-disk store and a durable
/// fake ledger; the child is killed (SIGKILL / TerminateProcess through the exact
/// `Child` handle) after ensure A settled, after ensure B's effect but before its
/// receipt, and after a pause committed. A new process reopens the store: the
/// environment identity, A's deadline and anchor bound are unchanged, the pause is
/// still in force (B's activation is never completed after it and B's effect is
/// never applied twice), and A expires at its original instant.
#[tokio::test]
async fn u10_process_crash_never_resets_a_deadline_revives_a_pause_or_changes_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "u10_crash_child_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(U10_CRASH_DIR, dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    u10_wait_for(&dir.path().join("paused"), &mut child);
    let ledger = dir.path().join("ledger");
    assert_eq!(
        FakeCredentialAdapter::ledger_entries(&ledger)
            .unwrap()
            .len(),
        2,
        "A's and B's effects are durably applied before the kill"
    );
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "the child was killed, not finished: {status}"
    );
    let mut child_out = String::new();
    let mut child_err = String::new();
    use std::io::Read as _;
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut child_out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut child_err)
        .unwrap();
    assert_no_canary(&child_out);
    assert_no_canary(&child_err);
    let a: EnsureData =
        serde_json::from_slice(&std::fs::read(dir.path().join("a.json")).unwrap()).unwrap();
    assert_eq!(a.expires_at, shift(t0(), 3600));

    // New process image of the runtime: reopen from disk, new adapter instance
    // over the same ledger, same boot five minutes later.
    let store = Arc::new(
        Store::open(
            &dir.path().join("state.db"),
            Arc::new(heimdall_store::NoFaults),
        )
        .unwrap(),
    );
    assert_eq!(
        store.transaction(|tx| tx.self_environment()).unwrap(),
        Some(env_id()),
        "environment identity survives the crash"
    );
    let anchor_before = store
        .transaction(|tx| tx.grant_anchor(&a.grant_id))
        .unwrap()
        .unwrap();
    let clock = VirtualClock::at(t0());
    clock.advance(5 * MINUTE);
    let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
    let fake = FakeCredentialAdapter::with_ledger(
        descriptor(),
        vec![FakeStep::Prepare(outcome())],
        &ledger,
    )
    .unwrap();
    let ops = Operations::start(u10_crash_config(
        &store,
        &clock,
        &sync,
        fake.clone() as Arc<dyn CredentialAdapter>,
    ))
    .await
    .unwrap();
    assert_eq!(
        FakeCredentialAdapter::ledger_entries(&ledger)
            .unwrap()
            .len(),
        2,
        "recovery reconciles, never prepares B a second time"
    );
    let b_bindings = store
        .transaction(|tx| tx.bindings_for_work(&env_id(), &WorkId::parse("u10-crash-b").unwrap()))
        .unwrap();
    assert!(
        b_bindings.is_empty(),
        "an activation interrupted by the crash is never completed after the pause"
    );
    let b_retry = err(ops
        .ensure(&unattended(501), {
            let mut b = ensure_req("u10-crash-b", "u10-crash-b", &[("h2", "deploy")]);
            b.until = Some(DeadlineIntent::Duration("1h".into()));
            b
        })
        .await);
    assert_ne!(b_retry.code, Code::AccessReady);
    assert_eq!(
        FakeCredentialAdapter::ledger_entries(&ledger)
            .unwrap()
            .len(),
        2
    );
    // The pause is still in force for new work.
    let blocked = err(ops
        .ensure(
            &unattended(501),
            ensure_req("u10-crash-c", "u10-crash-c", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(
        blocked.code,
        Code::PolicyPaused,
        "a crash never revives a pause"
    );
    // A's deadline is unchanged, its anchor bound never lengthened.
    let g = store
        .transaction(|tx| tx.grant(&a.grant_id))
        .unwrap()
        .unwrap();
    assert_eq!(g.deadline.effective, a.expires_at, "deadline not reset");
    ops.tick().await.unwrap();
    let anchor_after = store
        .transaction(|tx| tx.grant_anchor(&a.grant_id))
        .unwrap()
        .unwrap();
    assert!(anchor_after.bound <= anchor_before.bound);
    assert!(anchor_after.budget_end <= anchor_before.budget_end);
    // A started before the pause; whatever its state, it never outlives 1 h.
    clock.advance(55 * MINUTE);
    ops.tick().await.unwrap();
    let ended = store
        .transaction(|tx| tx.grant(&a.grant_id))
        .unwrap()
        .unwrap()
        .state;
    assert!(
        !matches!(ended, GrantState::Active | GrantState::Degraded),
        "A ends at its original instant: {ended:?}"
    );
    // A runtime with another environment ID is refused over this store.
    let mut other = u10_crash_config(&store, &clock, &sync, fake as Arc<dyn CredentialAdapter>);
    other.environment = EnvironmentId::from_random_bytes([9; 16]);
    assert_eq!(
        Operations::start(other).await.unwrap_err().code,
        Code::StateUnavailable
    );
    let page = store
        .transaction(|tx| tx.stored_events_after(&env_id(), 0, &EventFilter::default(), 10_000))
        .unwrap();
    for e in &page.events {
        assert_no_canary(&serde_json::to_string(&e.event).unwrap());
    }
}

// =================================================================================
// Gap fixes G08 and G10 (M01-wave2-gapfix)
// =================================================================================

/// Gap G08 (plan §6.3 #2; spec §6.2 "explicit deny and pause override allow"):
/// with two applicable policies, a future cutoff on the one resolution did not
/// choose (the second by ID) still bounds the grant: the activation anchor, the
/// reported usability and every certificate's `valid_before` end at that cutoff.
#[tokio::test]
async fn g08_a_future_cutoff_on_any_applicable_policy_bounds_the_grant() {
    let w = World::new().await;
    let cutoff = shift(t0(), 30 * 60);
    w.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol-z").unwrap(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: policy_pairs(),
                        capabilities: ssh_only(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: Some(cutoff),
                    source: PolicySource::SetupDefault,
                },
                false,
            )
        })
        .unwrap();
    let mut req = ensure_req("g08", "work-g08", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    let ready = ok(w.ops.ensure(&unattended(501), req).await).data;
    assert!(ready.usable_until <= cutoff, "usable_until past the cutoff");
    assert!(
        ready.offline_until <= cutoff,
        "offline_until past the cutoff"
    );
    let anchor = w
        .store
        .transaction(|tx| tx.grant_anchor(&ready.grant_id))
        .unwrap()
        .expect("activation anchor");
    assert!(
        anchor.bound <= cutoff,
        "anchor bound {} is later than the other policy's cutoff {cutoff}",
        anchor.bound
    );
    // valid_before one second past the cutoff is refused; at the cutoff it is not.
    let late = w
        .ops
        .reserve_issuance(u10_issuance(&ready.grant_id, shift(cutoff, 1)))
        .await
        .unwrap_err();
    assert_no_canary(&late.message);
    assert_eq!(late.code, Code::CapabilityUnavailable);
    let at_cutoff = w
        .ops
        .reserve_issuance(u10_issuance(&ready.grant_id, cutoff))
        .await
        .unwrap_or_else(|e| panic!("valid_before at the cutoff refused: {}", e.code));
    assert!(at_cutoff.bounds.valid_before <= cutoff);
    // Once the cutoff passes, issuance stops although the chosen policy has none.
    // ADR-0006 §13.6 item 1: renewal within the existing grant past its bound is
    // CREDENTIAL_EXPIRED (POLICY_CUTOFF is for new activations).
    w.clock.advance(31 * MINUTE);
    let after = w
        .ops
        .reserve_issuance(u10_issuance(&ready.grant_id, shift(cutoff, 60)))
        .await
        .unwrap_err();
    assert_eq!(after.code, Code::CredentialExpired);
    w.events();
}

/// Gap G10: a widening policy action under `TIME_UNCERTAIN` (forward skew past
/// the tolerance) creates no decision record, so no record can stay approvable
/// past `decision_lifetime` once time is safe again; narrowing still applies.
#[tokio::test]
async fn g10_widening_under_uncertain_time_creates_no_decision() {
    let w = World::new().await;
    ok(w.ops
        .policy(
            &attended(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await);
    // The wall jumps forward far beyond the 60 s skew tolerance.
    w.clock.set_wall(shift(t0(), 6 * 3600));
    let e = err(w
        .ops
        .policy(
            &attended(501),
            PolicyAction::Resume {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(e.code, Code::TimeUncertain);
    assert!(e.next.decision_ref.is_none());
    let pending = w.store.transaction(|tx| tx.pending_decisions()).unwrap();
    assert!(
        pending.is_empty(),
        "no widening record under uncertain time"
    );
    // Narrowing still applies while uncertain.
    ok(w.ops
        .policy(
            &attended(501),
            PolicyAction::Cutoff {
                policy_id: policy_id(),
                at: shift(t0(), 3600),
            },
        )
        .await);
    // Back to safe time: the widening creates a record whose lifetime is
    // measured from accepted time.
    w.clock.set_wall(t0());
    let e = err(w
        .ops
        .policy(
            &attended(501),
            PolicyAction::Resume {
                policy_id: policy_id(),
            },
        )
        .await);
    assert_eq!(e.code, Code::ApprovalRequired);
    let rec = w
        .store
        .transaction(|tx| tx.decision(&decision_ref(&e)))
        .unwrap()
        .unwrap();
    assert!(rec.created_at <= shift(t0(), 60));
    assert!(rec.expires_at <= shift(t0(), 60 + 15 * 60));
    w.events();
}

// =================================================================================
// Gap fixes G03 and G04: the supervisor-owned cleanup executor (m01-plan U8
// ⟨r2.1⟩ N06 (a) and (b)), through the production `Supervisor::cleanup_pass`,
// the `ResourceCleaner` port and the `CleanupHook` deletion-boundary hook.
// =================================================================================

/// The external world the fake cleaner acts on: one slot per locator holding the
/// generation currently installed there (a socket path's inode, a PID with start
/// time). The delete is generation-bound: it empties the slot only if it still
/// holds the generation being cleaned up.
#[derive(Default)]
struct FakeCleaner {
    slots: std::sync::Mutex<BTreeMap<String, u64>>,
    calls: std::sync::Mutex<Vec<(u64, Duration)>>,
    unavailable: AtomicBool,
    clock: std::sync::Mutex<Option<Arc<VirtualClock>>>,
}

impl FakeCleaner {
    fn install(&self, locator: &str, generation: u64) {
        self.slots
            .lock()
            .unwrap()
            .insert(locator.to_owned(), generation);
    }
    fn slot(&self, locator: &str) -> Option<u64> {
        self.slots.lock().unwrap().get(locator).copied()
    }
    fn calls(&self) -> Vec<(u64, Duration)> {
        self.calls.lock().unwrap().clone()
    }
}

impl heimdall_app::ports::ResourceCleaner for FakeCleaner {
    fn delete<'life0, 'life1, 'async_trait>(
        &'life0 self,
        resource: &'life1 heimdall_domain::resource::ManagedResource,
    ) -> U10Fut<'async_trait, ()>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let at = self
                .clock
                .lock()
                .unwrap()
                .as_ref()
                .map_or(Duration::ZERO, |c| c.continuous());
            self.calls.lock().unwrap().push((resource.generation.0, at));
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(heimdall_app::ports::AdapterError::Unavailable(
                    "fixture dependency down".into(),
                ));
            }
            let mut slots = self.slots.lock().unwrap();
            if slots.get(&resource.locator) == Some(&resource.generation.0) {
                slots.remove(&resource.locator);
            }
            Ok(())
        })
    }
}

/// At `point`, installs generation N+1 at the same locator (store record by
/// generation CAS, and the external slot): the replacement races the cleanup of
/// N at the deletion boundary.
struct ReplaceAt {
    point: heimdall_app::reconcile::CleanupPoint,
    store: Arc<Store>,
    cleaner: Arc<FakeCleaner>,
    fired: AtomicUsize,
}

impl heimdall_app::reconcile::CleanupHook for ReplaceAt {
    fn at(
        &self,
        point: heimdall_app::reconcile::CleanupPoint,
        resource: &heimdall_domain::resource::ManagedResource,
    ) {
        use heimdall_domain::resource::{ResourceGeneration, ResourceState};
        if point != self.point || self.fired.fetch_add(1, Ordering::SeqCst) > 0 {
            return;
        }
        let next = heimdall_domain::resource::ManagedResource {
            generation: ResourceGeneration(resource.generation.0 + 1),
            desired: ResourceState::Present,
            observed: ResourceState::Present,
            updated_at: shift(t0(), 1),
            ..resource.clone()
        };
        self.store
            .transaction(|tx| tx.upsert_resource(&next, Some(resource.generation)))
            .unwrap();
        self.cleaner.install(&resource.locator, next.generation.0);
    }
}

/// Generation N of an endpoint whose owner ended (desired absent, observed
/// present), installed in the store and in the fake world.
fn ending_endpoint(w: &World, cleaner: &FakeCleaner) -> heimdall_domain::resource::ManagedResource {
    use heimdall_domain::resource::{
        ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
    };
    let r = ManagedResource {
        id: heimdall_contract::ids::ResourceId::from_random_bytes([5; 16]),
        kind: ResourceKind::Endpoint,
        owner: OwnerRef::Runtime,
        generation: ResourceGeneration(1),
        desired: ResourceState::Absent,
        observed: ResourceState::Present,
        last_operation: None,
        locator: "fixture-endpoint".into(),
        updated_at: t0(),
    };
    w.store
        .transaction(|tx| tx.upsert_resource(&r, None))
        .unwrap();
    cleaner.install(&r.locator, 1);
    r
}

fn supervisor_with(
    w: &World,
    cleaner: &Arc<FakeCleaner>,
    hook: Arc<dyn heimdall_app::reconcile::CleanupHook>,
) -> heimdall_runtime::supervisor::Supervisor {
    *cleaner.clock.lock().unwrap() = Some(w.clock.clone());
    heimdall_runtime::supervisor::Supervisor::new(
        w.ops.clone(),
        heimdall_runtime::supervisor::SupervisorConfig::default(),
    )
    .with_state(w.store.clone(), w.clock.clone())
    .with_cleaner(
        cleaner.clone(),
        hook,
        heimdall_app::reconcile::Backoff::default(),
    )
    // ADR-0006 §13.6 item 4: production retries are jittered; a unit of 1.0 pins
    // the unjittered schedule so these cases can assert exact offsets (the jitter
    // bounds are covered by integration_runtime::jitter_props).
    .with_jitter(Arc::new(heimdall_runtime::supervisor::FixedJitter(1.0)))
}

/// N06 (a) control: with no race the executor deletes generation N exactly once
/// and records it absent at that generation.
#[tokio::test]
async fn g03_cleanup_executor_deletes_generation_n_once() {
    let w = World::new().await;
    let cleaner = Arc::new(FakeCleaner::default());
    let r = ending_endpoint(&w, &cleaner);
    let sup = supervisor_with(
        &w,
        &cleaner,
        Arc::new(heimdall_app::reconcile::NoCleanupHook),
    );
    let report = sup.cleanup_pass().await.unwrap();
    assert_eq!(report.deleted, vec![r.id.clone()]);
    assert_eq!(cleaner.calls().len(), 1);
    assert_eq!(cleaner.slot(&r.locator), None, "N is gone");
    let stored = w
        .store
        .transaction(|tx| tx.resource(&r.id))
        .unwrap()
        .unwrap();
    assert_eq!(stored.generation, r.generation);
    assert_eq!(
        stored.observed,
        heimdall_domain::resource::ResourceState::Absent
    );
    // Nothing left to do: a second pass deletes nothing.
    let again = sup.cleanup_pass().await.unwrap();
    assert!(again.deleted.is_empty());
    assert_eq!(cleaner.calls().len(), 1);
    w.events();
}

/// N06 (a) at the deletion boundary: the replacement N+1 is created between the
/// decision to delete N and the delete, at either hook point. N+1 survives in the
/// store and in the world; N is gone (its slot was taken over); the executor never
/// overwrites N+1's record.
#[tokio::test]
async fn g03_cleanup_of_generation_n_never_deletes_its_replacement_created_at_the_deletion_boundary()
 {
    use heimdall_app::reconcile::CleanupPoint;
    use heimdall_domain::resource::{ResourceGeneration, ResourceState};
    for point in [CleanupPoint::Decided, CleanupPoint::Guarded] {
        let w = World::new().await;
        let cleaner = Arc::new(FakeCleaner::default());
        let r = ending_endpoint(&w, &cleaner);
        let hook = Arc::new(ReplaceAt {
            point,
            store: w.store.clone(),
            cleaner: cleaner.clone(),
            fired: AtomicUsize::new(0),
        });
        let sup = supervisor_with(&w, &cleaner, hook.clone());
        let report = sup.cleanup_pass().await.unwrap();
        assert_eq!(hook.fired.load(Ordering::SeqCst), 1, "{point:?}");
        assert!(report.deleted.is_empty(), "{point:?}: {report:?}");
        assert_eq!(report.superseded, vec![r.id.clone()], "{point:?}");
        assert_eq!(cleaner.slot(&r.locator), Some(2), "{point:?}: N+1 survives");
        let stored = w
            .store
            .transaction(|tx| tx.resource(&r.id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.generation, ResourceGeneration(2), "{point:?}");
        assert_eq!(stored.desired, ResourceState::Present, "{point:?}");
        assert_eq!(stored.observed, ResourceState::Present, "{point:?}");
        // Guarded: the generation-bound delete of N ran and touched nothing of
        // N+1; Decided: the guard stopped it before any delete.
        let expected_calls = usize::from(point == CleanupPoint::Guarded);
        assert_eq!(cleaner.calls().len(), expected_calls, "{point:?}");
        assert!(cleaner.calls().iter().all(|(g, _)| *g == 1), "{point:?}");
        // Later passes leave N+1 alone (desired = observed = present).
        sup.cleanup_pass().await.unwrap();
        assert_eq!(cleaner.slot(&r.locator), Some(2), "{point:?}");
        w.events();
    }
}

/// N06 (b): repeated `AdapterError::Unavailable` is retried only by the single
/// supervisor executor, with `Backoff` spacing on the continuous clock (0.5 s,
/// 1 s, 2 s, ... ), capped at `max_attempts` (8) calls, then a stable
/// `SERVICE_UNAVAILABLE` code; no operation, decision record or prompt results,
/// and `tick` (the operations path) never retries a resource.
#[tokio::test]
async fn g04_unavailable_cleanup_is_retried_by_the_single_supervisor_with_bounded_backoff() {
    let w = World::new().await;
    let cleaner = Arc::new(FakeCleaner::default());
    cleaner.unavailable.store(true, Ordering::SeqCst);
    let r = ending_endpoint(&w, &cleaner);
    let sup = supervisor_with(
        &w,
        &cleaner,
        Arc::new(heimdall_app::reconcile::NoCleanupHook),
    );
    let start = w.clock.continuous();
    let mut failed = Vec::new();
    let step = Duration::from_millis(250);
    for _ in 0..(4 * 120) {
        let report = sup.cleanup_pass().await.unwrap();
        failed.extend(report.failed);
        // The operations path never touches resources.
        w.ops.tick().await.unwrap();
        w.clock.advance(step);
    }
    let offsets: Vec<Duration> = cleaner
        .calls()
        .iter()
        .map(|(_, at)| at.saturating_sub(start))
        .collect();
    let ms = |v: u64| Duration::from_millis(v);
    assert_eq!(
        offsets,
        vec![
            ms(0),
            ms(500),
            ms(1_500),
            ms(3_500),
            ms(7_500),
            ms(15_500),
            ms(31_500),
            ms(63_500),
        ],
        "attempts follow the backoff schedule and stop at the cap"
    );
    assert_eq!(failed, vec![(r.id.clone(), Code::ServiceUnavailable)]);
    // After the cap nothing retries, whatever the clock does.
    w.clock.advance(Duration::from_secs(3600));
    let after = sup.cleanup_pass().await.unwrap();
    assert!(after.retry_scheduled.is_empty() && after.failed.is_empty());
    assert_eq!(cleaner.calls().len(), 8);
    // No decision record, no operation, no prompt.
    assert!(
        w.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .is_empty()
    );
    assert!(
        w.store
            .transaction(|tx| tx.operation_counts())
            .unwrap()
            .iter()
            .all(|(_, n)| *n == 0)
    );
    // The stable code is published once, redacted (no locator).
    let failures: Vec<serde_json::Value> = w
        .events()
        .into_iter()
        .filter(|e| e.event.event_type == EventType::ResourceChanged)
        .map(|e| e.event.payload)
        .collect();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0]["outcome"], "cleanup_failed");
    assert_eq!(failures[0]["code"], "SERVICE_UNAVAILABLE");
    assert_eq!(failures[0]["attempts"], 8);
    assert!(!failures[0].to_string().contains("fixture-endpoint"));
    // The resource is still recorded present (truthful), generation unchanged.
    let stored = w
        .store
        .transaction(|tx| tx.resource(&r.id))
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.observed,
        heimdall_domain::resource::ResourceState::Present
    );
}

/// ADR-0006 §13.5 ruling 1 (gap G02), the other ends of a child: revoking only
/// the child drops its reference on the parent at once (`revoking` never returns
/// to live); a parent whose consumers already released becomes `released` then,
/// with no tombstone and no cascade (release is never revoke, §13.1 item 2).
#[tokio::test]
async fn g02_a_revoked_child_frees_its_parent_without_revoking_it() {
    let w = World::new().await;
    let mut req = ensure_req("g02-p", "g02-parent", &[("h1", "deploy")]);
    req.until = Some(DeadlineIntent::Duration("1h".into()));
    let parent = ok(w.ops.ensure(&unattended(501), req).await).data;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "g02-c", "30m"))
        .await)
    .data;
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: parent.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Active);
    // Revoke the child alone (its tombstone, not the parent's).
    u10_revoke(&w, &child.grant_id, "g02-rv-c").await;
    let c = w.grant(&child.grant_id).state;
    assert!(
        matches!(c, GrantState::Revoked | GrantState::Revoking),
        "{c:?}"
    );
    assert_eq!(
        w.grant(&parent.grant_id).state,
        GrantState::Released,
        "no consumer and no live child left"
    );
    let parent_tombstone = w
        .store
        .transaction(|tx| tx.tombstone(&parent.grant_id))
        .unwrap();
    assert!(parent_tombstone.is_none(), "release is never revoke");
    assert!(
        w.store
            .transaction(|tx| tx.grant_references(&parent.grant_id))
            .unwrap()
            .is_empty()
    );
    w.events();
}

// =================================================================================
// ADR-0006 §13.6 rulings (2026-11-01), unit M01-rulings-13-6-F1: pause versus
// cutoff versus revoke for existing work (item 1), the child-owned parent
// reference (item 3), several applicable policies (item 5), cutoff direction and
// time (item 6).
// =================================================================================

fn r136_issuance(
    grant: &heimdall_contract::ids::GrantId,
    valid_before: Timestamp,
    new_activation: bool,
) -> heimdall_app::operations::IssuanceRequest {
    let mut r = u10_issuance(grant, valid_before);
    r.facts.new_activation = new_activation;
    r
}

async fn r136_ready(w: &World, rid: &str, work: &str, host: &str, until: &str) -> EnsureData {
    let mut req = ensure_req(rid, work, &[(host, "deploy")]);
    req.until = Some(DeadlineIntent::Duration(until.into()));
    ok(w.ops.ensure(&unattended(501), req).await).data
}

async fn r136_bind(
    w: &World,
    binding: &heimdall_contract::ids::BindingId,
    rid: &str,
) -> OpResult<EnsureData> {
    w.ops
        .bind(
            &unattended(501),
            BindRequest {
                binding_id: binding.clone(),
                form: BindForm::Materialize,
                request_id: RequestId::parse(rid).unwrap(),
            },
        )
        .await
}

async fn r136_policy(
    w: &World,
    caller: &Caller,
    action: PolicyAction,
) -> OpResult<serde_json::Value> {
    w.ops.policy(caller, action).await
}

/// A second policy for the same profile and environment (spec §13.4: separate
/// policy records are legitimate), sorted after `pol`.
fn r136_second_policy(w: &World, id: &str) -> PolicyId {
    let pid = PolicyId::parse(id).unwrap();
    w.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: pid.clone(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: policy_pairs(),
                        capabilities: ssh_only(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                },
                false,
            )
        })
        .unwrap();
    pid
}

/// §13.6 item 1: after a pause, a running grant and its existing binding continue
/// until their deadline: the binding materializes again (fresh bind request), and
/// issuance within the grant (renewal, `new_activation: false`) reserves and
/// publishes. Re-validation under the pause never maps it to
/// `CREDENTIAL_EXPIRED`. Only the deadline ends the grant.
#[tokio::test]
async fn r136_1_pause_lets_an_existing_binding_bind_and_issue_until_its_deadline() {
    let w = World::new().await;
    let a = r136_ready(&w, "r1-a", "r1-work-a", "h1", "1h").await;
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Pause {
            policy_id: policy_id(),
        },
    )
    .await);
    let bound = r136_bind(&w, &a.binding_id, "r1-bind-1").await;
    let bound = ok(bound);
    assert_eq!(
        bound.code,
        Code::AccessReady,
        "an existing binding continues under a pause"
    );
    assert_eq!(bound.data.grant_id, a.grant_id);
    let reserved = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), false))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "renewal within the grant refused under a pause: {} {}",
                e.code, e.message
            )
        });
    let published = issue(
        &w,
        &reserved.id,
        &r136_issuance(&a.grant_id, t0(), false).facts,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "publish within the grant refused under a pause: {} {}",
            e.code, e.message
        )
    });
    assert_eq!(
        published.state,
        heimdall_domain::issuance::IssuanceState::Published
    );
    // An issuance that would activate a new grant is the pause's business.
    let fresh = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), true))
        .await
        .unwrap_err();
    assert_no_canary(&fresh.message);
    assert_eq!(fresh.code, Code::PolicyPaused);
    assert_eq!(fresh.code.exit_code(), ExitCode::Denied);
    // The grant stays live across scheduler passes until its deadline.
    w.clock.advance(30 * MINUTE);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&a.grant_id).state, GrantState::Active);
    let later = ok(r136_bind(&w, &a.binding_id, "r1-bind-2").await);
    assert_eq!(later.code, Code::AccessReady);
    // At the deadline it ends: CREDENTIAL_EXPIRED, never a pause code.
    w.clock.advance(31 * MINUTE);
    let past = err(r136_bind(&w, &a.binding_id, "r1-bind-3").await);
    assert_eq!(past.code, Code::CredentialExpired);
    w.ops.tick().await.unwrap();
    assert!(!w.grant(&a.grant_id).state.permits_use());
    assert_eq!(
        w.effects(),
        1,
        "nothing under the pause prepared a new credential"
    );
    w.events();
}

/// §13.6 item 1: a pause refuses new grants and new work bindings with
/// `POLICY_PAUSED` (exit 4), including fresh request and work identifiers and a
/// delegation; a same-key replay returns the recorded result.
#[tokio::test]
async fn r136_1_pause_refuses_new_grants_and_bindings_and_replays_recorded_results() {
    let w = World::new().await;
    let a = r136_ready(&w, "r1b-a", "r1b-work-a", "h1", "1h").await;
    let bind_before = ok(r136_bind(&w, &a.binding_id, "r1b-bind").await);
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Pause {
            policy_id: policy_id(),
        },
    )
    .await);
    let effects = w.effects();
    for (rid, work) in [
        ("r1b-fresh-rid", "r1b-work-a"),
        ("r1b-fresh-both", "r1b-work-new"),
    ] {
        let mut req = ensure_req(rid, work, &[("h1", "deploy")]);
        req.until = Some(DeadlineIntent::Duration("1h".into()));
        let e = err(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(e.code, Code::PolicyPaused, "{rid}/{work}");
        assert_eq!(e.code.exit_code(), ExitCode::Denied);
    }
    let child = err(w
        .ops
        .delegate(&unattended(501), u10_delegate(&a, "r1b-child", "10m"))
        .await);
    assert_eq!(
        child.code,
        Code::PolicyPaused,
        "a delegation is a new grant"
    );
    assert_eq!(
        w.bindings_for("r1b-work-a").len(),
        1,
        "no new binding under the pause"
    );
    assert!(w.bindings_for("r1b-work-new").is_empty());
    // Same-key replays return the recorded results.
    let mut again = ensure_req("r1b-a", "r1b-work-a", &[("h1", "deploy")]);
    again.until = Some(DeadlineIntent::Duration("1h".into()));
    let replay = ok(w.ops.ensure(&unattended(501), again).await);
    assert_eq!(replay.code, Code::AccessReady);
    assert_eq!(replay.data.binding_id, a.binding_id);
    let bind_replay = ok(r136_bind(&w, &a.binding_id, "r1b-bind").await);
    assert_eq!(bind_replay.operation_id, bind_before.operation_id);
    assert_eq!(bind_replay.code, Code::AccessReady);
    assert_eq!(w.effects(), effects);
    w.events();
}

/// §13.6 items 1 and 2: a request waiting for added authority when the policy is
/// paused: its decision is stale (strict), the operation keeps waiting, and a
/// same-key retry answers `POLICY_PAUSED` (a new grant under the pause) with no
/// fresh record and no effect; never `CREDENTIAL_EXPIRED`.
#[tokio::test]
async fn r136_1_a_waiting_request_under_a_pause_answers_policy_paused_and_keeps_waiting() {
    let w = World::new().await;
    let e = err(w
        .ops
        .ensure(&attended(501), approval_req("r1c", "r1c-work"))
        .await);
    let dec = decision_ref(&e);
    let op = e.operation_id.clone().unwrap();
    ok(r136_policy(
        &w,
        &attended(501),
        PolicyAction::Pause {
            policy_id: policy_id(),
        },
    )
    .await);
    let stale = err(decide(&w, &attended(501), &dec, Verdict::Approve).await);
    assert_eq!(stale.code, Code::DecisionStale);
    let retry = err(w
        .ops
        .ensure(&attended(501), approval_req("r1c", "r1c-work"))
        .await);
    assert_eq!(retry.code, Code::PolicyPaused);
    assert_eq!(retry.operation_id, Some(op.clone()));
    assert_eq!(w.op(&op).state, OperationState::AwaitingApproval);
    let pending = w.store.transaction(|tx| tx.pending_decisions()).unwrap();
    assert!(
        pending.iter().all(|d| d.id == dec
            || !matches!(
                d.kind,
                heimdall_domain::decision::DecisionKind::ApproveAuthority { .. }
            )),
        "no fresh approval record while paused"
    );
    assert_eq!(w.effects(), 0);
}

/// §13.6 item 1: a cutoff bounds every applicable grant at `min(deadline,
/// cutoff)`. Before it, existing work continues (bind, issuance up to the
/// cutoff) and new work activates bounded by it; at or after it, using the
/// existing grant is `CREDENTIAL_EXPIRED` and new work (fresh request, fresh
/// work, delegation, new-activation issuance) is `POLICY_CUTOFF`.
#[tokio::test]
async fn r136_1_cutoff_bounds_existing_work_and_refuses_new_work_after_it() {
    let w = World::new().await;
    let a = r136_ready(&w, "r1d-a", "r1d-work-a", "h1", "1h").await;
    let cutoff = shift(t0(), 20 * 60);
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: cutoff,
        },
    )
    .await);
    // Future cutoff: existing work continues until it.
    w.clock.advance(5 * MINUTE);
    ok(r136_bind(&w, &a.binding_id, "r1d-bind-1").await);
    let r = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, cutoff, false))
        .await
        .unwrap_or_else(|e| panic!("issuance before the cutoff refused: {}", e.code));
    assert!(r.bounds.valid_before <= cutoff);
    let late = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(cutoff, 1), false))
        .await
        .unwrap_err();
    assert_eq!(
        late.code,
        Code::CapabilityUnavailable,
        "valid_before past the cutoff"
    );
    let b = r136_ready(&w, "r1d-b", "r1d-work-b", "h2", "1h").await;
    assert!(b.expires_at <= cutoff || b.usable_until <= cutoff);
    // Past the cutoff. A new activation answers POLICY_CUTOFF; ⟨r2.5⟩ ADR-0006
    // §13.8 item 4: that use finds the grant past its bound and ends it
    // (`expired`), so every later use of it is CREDENTIAL_EXPIRED.
    w.clock.advance(16 * MINUTE);
    let activation = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(cutoff, 600), true))
        .await
        .unwrap_err();
    assert_eq!(
        activation.code,
        Code::PolicyCutoff,
        "new activation past the cutoff"
    );
    assert_eq!(w.grant(&a.grant_id).state, GrantState::Expired);
    let used = err(r136_bind(&w, &a.binding_id, "r1d-bind-2").await);
    assert_eq!(
        used.code,
        Code::CredentialExpired,
        "existing use past the cutoff"
    );
    let issued = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(cutoff, 600), false))
        .await
        .unwrap_err();
    assert_eq!(
        issued.code,
        Code::CredentialExpired,
        "renewal past the cutoff"
    );
    for (rid, work) in [("r1d-fresh-rid", "r1d-work-a"), ("r1d-fresh", "r1d-work-c")] {
        let mut req = ensure_req(rid, work, &[("h1", "deploy")]);
        req.until = Some(DeadlineIntent::Duration("1h".into()));
        let e = err(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(e.code, Code::PolicyCutoff, "{rid}/{work}");
        assert_eq!(e.code.exit_code(), ExitCode::Denied);
    }
    let child = err(w
        .ops
        .delegate(&unattended(501), u10_delegate(&a, "r1d-child", "10m"))
        .await);
    assert_eq!(child.code, Code::PolicyCutoff);
    w.ops.tick().await.unwrap();
    assert!(!w.grant(&a.grant_id).state.permits_use());
    w.events();
}

/// §13.6 item 5: with two applicable policies, a pause on the second between
/// reserve and publish voids the reservation (the generation moved) and blocks new
/// activations; the continuing grant reserves and publishes afresh. Since §13.6
/// item 11 the same publish call re-validates and re-reserves (the pause does not
/// apply to continuing issuance) and publishes the fresh reservation.
#[tokio::test]
async fn r136_5_pause_on_a_second_policy_between_reserve_and_publish_voids_the_publish() {
    let w = World::new().await;
    let z = r136_second_policy(&w, "pol-z");
    let a = r136_ready(&w, "r5-a", "r5-work-a", "h1", "1h").await;
    let gen_before = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    let e1 = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), false))
        .await
        .unwrap();
    ok(r136_policy(&w, &unattended(501), PolicyAction::Pause { policy_id: z }).await);
    assert_ne!(
        w.store.transaction(|tx| tx.authority_generation()).unwrap(),
        gen_before,
        "a pause on an applicable policy moves the generation"
    );
    let republished = issue(&w, &e1.id, &r136_issuance(&a.grant_id, t0(), false).facts)
        .await
        .unwrap_or_else(|e| panic!("item 11 re-reservation refused: {} {}", e.code, e.message));
    assert_ne!(republished.id, e1.id, "a fresh reservation was published");
    assert_eq!(
        republished.state,
        heimdall_domain::issuance::IssuanceState::Published
    );
    let entries = w
        .store
        .transaction(|tx| tx.issuance_entries(&a.grant_id))
        .unwrap();
    let original = entries.iter().find(|e| e.id == e1.id).unwrap();
    assert_eq!(
        original.state,
        heimdall_domain::issuance::IssuanceState::Voided
    );
    assert_eq!(
        original.void_reason,
        Some(heimdall_domain::issuance::IssuanceRefusal::StaleGeneration)
    );
    let blocked = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r5-new", "r5-work-new", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(blocked.code, Code::PolicyPaused);
    let new_activation = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), true))
        .await
        .unwrap_err();
    assert_eq!(new_activation.code, Code::PolicyPaused);
    let e2 = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), false))
        .await
        .unwrap_or_else(|e| panic!("continuing issuance refused: {} {}", e.code, e.message));
    let p2 = issue(&w, &e2.id, &r136_issuance(&a.grant_id, t0(), false).facts)
        .await
        .unwrap_or_else(|e| panic!("continuing publish refused: {} {}", e.code, e.message));
    assert_eq!(
        p2.state,
        heimdall_domain::issuance::IssuanceState::Published
    );
    w.events();
}

/// §13.6 item 5: a cutoff on the second policy between reserve and publish voids
/// the publish and bounds the grant; at the cutoff new activations are
/// `POLICY_CUTOFF`. A widening revision of an applicable policy (an approved
/// `clear_cutoff`) moves the generation too and voids a reservation made before it.
#[tokio::test]
async fn r136_5_cutoff_or_revision_on_a_second_policy_between_reserve_and_publish_voids_the_publish()
 {
    let w = World::new().await;
    let z = r136_second_policy(&w, "pol-z");
    let a = r136_ready(&w, "r5c-a", "r5c-work-a", "h1", "1h").await;
    let e1 = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), false))
        .await
        .unwrap();
    let cutoff = shift(t0(), 30 * 60);
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: z.clone(),
            at: cutoff,
        },
    )
    .await);
    // The cutoff voids the reservation; the reservation's bounds stay before the
    // cutoff, so publication re-reserves (§13.6 item 11) and hands the fresh
    // reservation back to the issuer, whose next round trip publishes it (§13.8
    // item 1).
    let republished = issue(&w, &e1.id, &r136_issuance(&a.grant_id, t0(), false).facts)
        .await
        .unwrap();
    assert_ne!(republished.id, e1.id);
    assert_eq!(
        w.store
            .transaction(|tx| tx.issuance_entries(&a.grant_id))
            .unwrap()
            .iter()
            .find(|e| e.id == e1.id)
            .unwrap()
            .state,
        heimdall_domain::issuance::IssuanceState::Voided,
        "the cutoff voided the reservation made before it"
    );
    // A widening revision (approved clear_cutoff) also moves the generation.
    let e2 = w
        .ops
        .reserve_issuance(r136_issuance(&a.grant_id, shift(t0(), 600), false))
        .await
        .unwrap();
    let gen_before = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    let clear = err(r136_policy(
        &w,
        &attended(501),
        PolicyAction::ClearCutoff {
            policy_id: z.clone(),
        },
    )
    .await);
    ok(decide(&w, &attended(501), &decision_ref(&clear), Verdict::Approve).await);
    assert_ne!(
        w.store.transaction(|tx| tx.authority_generation()).unwrap(),
        gen_before,
        "a widening revision of an applicable policy moves the generation"
    );
    let again = issue(&w, &e2.id, &r136_issuance(&a.grant_id, t0(), false).facts)
        .await
        .unwrap();
    assert_ne!(again.id, e2.id);
    assert_eq!(
        w.store
            .transaction(|tx| tx.issuance_entries(&a.grant_id))
            .unwrap()
            .iter()
            .find(|e| e.id == e2.id)
            .unwrap()
            .state,
        heimdall_domain::issuance::IssuanceState::Voided,
        "a reservation made before the revision is voided"
    );
    // Set the cutoff again and pass it: new activations are refused.
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: z,
            at: cutoff,
        },
    )
    .await);
    w.clock.advance(31 * MINUTE);
    let blocked = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r5c-new", "r5c-work-new", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(blocked.code, Code::PolicyCutoff);
    let used = err(r136_bind(&w, &a.binding_id, "r5c-bind").await);
    assert_eq!(used.code, Code::CredentialExpired);
    w.events();
}

/// Delegates to the fake, except that `revoke` leaves a remote effect pending,
/// so a revoked grant stays in `revoking`.
struct PendingRevoke {
    inner: Arc<FakeCredentialAdapter>,
}

impl CredentialAdapter for PendingRevoke {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.inner.descriptor()
    }
    fn prepare<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.prepare(req)
    }
    fn renew<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.renew(req)
    }
    fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        effect_token: &'life2 str,
    ) -> U10Fut<'async_trait, heimdall_app::ports::ReconcileOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.reconcile(grant, effect_token)
    }
    fn revoke<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _grant: &'life1 heimdall_contract::ids::GrantId,
        _now: Timestamp,
    ) -> U10Fut<'async_trait, heimdall_app::ports::RevokeOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            Ok(heimdall_app::ports::RevokeOutcome {
                remote_pending: vec![DestinationId::parse("h1").unwrap()],
                latest_possible_credential_expiry: None,
            })
        })
    }
}

/// §13.6 item 3: the child-owned reference on the parent is released when the
/// child **enters** `revoking` (here the remote effect stays pending, so the child
/// never reaches `revoked`): a parent without consumers becomes `released`, with
/// no tombstone and no cascade.
#[tokio::test]
async fn r136_3_a_child_entering_revoking_releases_its_parent_reference() {
    let mut w = World::new().await;
    let adapter = Arc::new(PendingRevoke {
        inner: w.fake.clone(),
    });
    w.ops = Operations::start(OperationsConfig {
        adapters: vec![adapter as Arc<dyn CredentialAdapter>],
        ..w.config()
    })
    .await
    .unwrap();
    let parent = r136_ready(&w, "r3-p", "r3-parent", "h1", "1h").await;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "r3-c", "30m"))
        .await)
    .data;
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: parent.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Active);
    let rv = ok(w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: child.grant_id.clone(),
                request_id: RequestId::parse("r3-rv").unwrap(),
            },
        )
        .await);
    assert!(!rv.data.remote_pending.is_empty());
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Revoking);
    assert_eq!(
        w.grant(&parent.grant_id).state,
        GrantState::Released,
        "a dying child never keeps its parent alive"
    );
    assert!(
        w.store
            .transaction(|tx| tx.grant_references(&parent.grant_id))
            .unwrap()
            .is_empty()
    );
    assert!(
        w.store
            .transaction(|tx| tx.tombstone(&parent.grant_id))
            .unwrap()
            .is_none(),
        "release is never revoke"
    );
    w.events();
}

/// §13.6 item 3 / §13.5 ruling 1: the reference also goes when the child reaches
/// a terminal state by expiry; the parent, still within its own deadline and
/// without consumers, becomes `released`.
#[tokio::test]
async fn r136_3_an_expired_child_releases_its_parent_reference() {
    let w = World::new().await;
    let parent = r136_ready(&w, "r3e-p", "r3e-parent", "h1", "1h").await;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "r3e-c", "10m"))
        .await)
    .data;
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: parent.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Active);
    w.clock.advance(11 * MINUTE);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Expired);
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Released);
    assert!(
        w.store
            .transaction(|tx| tx.grant_references(&parent.grant_id))
            .unwrap()
            .is_empty()
    );
    w.events();
}

/// §13.6 item 6: a later or cleared cutoff widens (decision record, attended
/// `Decide`); an equal one changes nothing and an earlier one narrows at once.
/// While time is uncertain every widening (later cutoff, clear, resume, and the
/// attended approval of a pending widening) is `TIME_UNCERTAIN`, and every
/// narrowing (pause, earlier cutoff, revoke, release, deny) still applies.
#[tokio::test]
async fn r136_6_cutoff_direction_and_narrowing_under_uncertain_time() {
    let w = World::new().await;
    let a = r136_ready(&w, "r6-a", "r6-work-a", "h1", "1h").await;
    let b = r136_ready(&w, "r6-b", "r6-work-b", "h2", "1h").await;
    let c2h = shift(t0(), 2 * 3600);
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: c2h,
        },
    )
    .await);
    // Later: a decision record, nothing applied.
    let later = err(r136_policy(
        &w,
        &attended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: shift(c2h, 3600),
        },
    )
    .await);
    assert_eq!(later.code, Code::ApprovalRequired);
    let later_ref = decision_ref(&later);
    let rec = w
        .store
        .transaction(|tx| tx.decision(&later_ref))
        .unwrap()
        .unwrap();
    assert!(matches!(
        rec.kind,
        heimdall_domain::decision::DecisionKind::WidenPolicy { .. }
    ));
    let pol = |w: &World| {
        w.store
            .transaction(|tx| tx.policy(&policy_id()))
            .unwrap()
            .unwrap()
    };
    assert_eq!(pol(&w).cutoff_at, Some(c2h));
    // Equal: unchanged; no record.
    let same = ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: c2h,
        },
    )
    .await);
    assert_eq!(same.data["changed"], false);
    // Clear: a decision record.
    let clear = err(r136_policy(
        &w,
        &attended(501),
        PolicyAction::ClearCutoff {
            policy_id: policy_id(),
        },
    )
    .await);
    assert_eq!(clear.code, Code::ApprovalRequired);
    let clear_ref = decision_ref(&clear);
    // Time becomes uncertain: the wall clock rolls back within this boot, below
    // the high-water mark by more than the rollback tolerance.
    w.clock.set_wall(shift(t0(), -3600));
    let later_u = err(r136_policy(
        &w,
        &attended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: shift(c2h, 7200),
        },
    )
    .await);
    assert_eq!(later_u.code, Code::TimeUncertain);
    assert!(later_u.next.decision_ref.is_none());
    let clear_u = err(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::ClearCutoff {
            policy_id: policy_id(),
        },
    )
    .await);
    assert_eq!(clear_u.code, Code::TimeUncertain);
    let approve_u = err(decide(&w, &attended(501), &clear_ref, Verdict::Approve).await);
    assert_eq!(
        approve_u.code,
        Code::TimeUncertain,
        "approving a widening needs safe time"
    );
    assert_eq!(
        pol(&w).cutoff_at,
        Some(c2h),
        "nothing widened under uncertain time"
    );
    // Narrowing is never blocked by time.
    ok(decide(&w, &attended(501), &later_ref, Verdict::Deny).await);
    let earlier = ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: shift(t0(), 3600),
        },
    )
    .await);
    assert_eq!(earlier.data["changed"], true);
    assert_eq!(pol(&w).cutoff_at, Some(shift(t0(), 3600)));
    let paused = ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Pause {
            policy_id: policy_id(),
        },
    )
    .await);
    assert_eq!(paused.data["paused"], true);
    let resume_u = err(r136_policy(
        &w,
        &attended(501),
        PolicyAction::Resume {
            policy_id: policy_id(),
        },
    )
    .await);
    assert_eq!(resume_u.code, Code::TimeUncertain);
    let rv = ok(w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: a.grant_id.clone(),
                request_id: RequestId::parse("r6-rv").unwrap(),
            },
        )
        .await);
    assert!(rv.data.local_applied);
    assert!(!w.grant(&a.grant_id).state.permits_use());
    let rl = ok(w
        .ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: b.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(rl.data["grant_state"], "released");
    w.events();
}

// =================================================================================
// ADR-0006 §13.8 item 4 (M01-rulings-13-8-H1): what "ends the grant" means. When
// re-validation of an active or degraded grant fails, the grant moves to a terminal
// state on detection, at use and in the supervisor's scheduler pass: a passed
// deadline or cutoff ⇒ `expired`; withdrawn authority (a revoke on the chain, a
// narrowing outside the approval, a removed environment permission) ⇒ `revoking`
// with a tombstone whose cause is `authority_withdrawn`, then `revoked` once local
// denial is applied, the residual reported as for any revocation. A pause and
// uncertain time never end a grant. The cases marked red were first run against the
// base commit and failed there.
// =================================================================================

/// The standing policy `pol` covers exactly `hosts` at its next revision (a
/// setup-level write; it moves the authority generation).
fn r138_set_policy_hosts(w: &World, hosts: &[&str]) {
    w.store
        .transaction(|tx| {
            let mut p = tx.policy(&policy_id())?.expect("policy");
            p.scope.pairs = hosts.iter().map(|h| pair(h, "deploy")).collect();
            p.revision = PolicyRevision(p.revision.0 + 1);
            tx.upsert_policy(&p, true).map(|_| ())
        })
        .unwrap();
}

/// The environment's automatic activation on or off (an environment write; it
/// moves the authority generation, ADR-0006 §13.7 item 5).
fn r138_set_automatic_activation(w: &World, on: bool) {
    w.store
        .transaction(|tx| {
            let mut e = tx.environment(&env_id())?.expect("environment");
            e.permissions.automatic_activation = on;
            tx.upsert_environment(&e)
        })
        .unwrap();
}

/// A revocation recorded for `grant` alone (a tombstone on it, no cascade, the
/// grant row untouched): what a grant below it sees as "a revoke on the chain".
/// Built from its wire form so it names no field this suite does not own.
fn r138_tombstone_only(w: &World, grant: &heimdall_contract::ids::GrantId) {
    let t: heimdall_domain::revocation::Tombstone = serde_json::from_value(serde_json::json!({
        "grant": grant,
        "cascade": [],
        "generation": 0,
        "revoked_at": w.clock.wall(),
        "remote_pending": [],
    }))
    .unwrap();
    w.store
        .transaction(|tx| tx.insert_tombstone(&t).map(|_| ()))
        .unwrap();
}

/// The stored tombstone of `grant` as JSON, if any.
fn r138_tombstone(w: &World, grant: &heimdall_contract::ids::GrantId) -> Option<serde_json::Value> {
    w.store
        .transaction(|tx| tx.tombstone(grant))
        .unwrap()
        .map(|t| serde_json::to_value(t).unwrap())
}

/// The `authority_withdrawn` credential-lifecycle event of `grant`, if any.
fn r138_withdrawal(
    w: &World,
    grant: &heimdall_contract::ids::GrantId,
) -> Option<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event.event_type == EventType::CredentialLifecycle)
        .map(|e| e.event.payload)
        .find(|p| p["grant_id"] == serde_json::json!(grant) && p["event"] == "authority_withdrawn")
}

/// Withdrawn authority: `revoked` (local denial applied through the fake adapter,
/// which reports nothing pending), a tombstone whose cause is
/// `authority_withdrawn`, and the residual in the event.
fn r138_assert_withdrawn(
    w: &World,
    grant: &heimdall_contract::ids::GrantId,
    residual: Option<Timestamp>,
) {
    assert_eq!(
        w.grant(grant).state,
        GrantState::Revoked,
        "withdrawn ⇒ revoked"
    );
    let t = r138_tombstone(w, grant).expect("a tombstone");
    assert_eq!(t["cause"], "authority_withdrawn");
    let ev = r138_withdrawal(w, grant).expect("the withdrawal is reported");
    assert_eq!(ev["local_applied"], true);
    assert_eq!(ev["remote_pending"], serde_json::json!([]));
    assert_eq!(
        ev["latest_possible_credential_expiry"],
        serde_json::json!(residual),
        "the residual is reported as for any revocation"
    );
}

/// An owner-approved h1+h3 grant (policy h1,h2; approved delta h3), active.
async fn r138_approved(w: &World, rid: &str, work: &str) -> EnsureData {
    let pending = err(w
        .ops
        .ensure(&unattended(501), approval_req(rid, work))
        .await);
    ok(decide(w, &attended(501), &decision_ref(&pending), Verdict::Approve).await);
    ok(w.ops
        .ensure(&unattended(501), approval_req(rid, work))
        .await)
    .data
}

/// A delegated child (h1, 30 min) of an h1 parent (1 h).
async fn r138_parent_and_child(w: &World, tag: &str) -> (EnsureData, EnsureData) {
    let parent = r136_ready(w, &format!("{tag}-p"), &format!("{tag}-work"), "h1", "1h").await;
    let child = ok(w
        .ops
        .delegate(
            &unattended(501),
            u10_delegate(&parent, &format!("{tag}-c"), "30m"),
        )
        .await)
    .data;
    (parent, child)
}

/// The supervisor over this world (deadline scheduler only; no cleaner).
fn r138_supervisor(w: &World) -> heimdall_runtime::supervisor::Supervisor {
    heimdall_runtime::supervisor::Supervisor::new(
        w.ops.clone(),
        heimdall_runtime::supervisor::SupervisorConfig::default(),
    )
    .with_state(w.store.clone(), w.clock.clone())
}

/// Red. Withdrawn authority detected at use (bind): a narrowing that removes h1,
/// which the owner's approval (h3) did not cover, ends the owner-approved grant:
/// `revoked` with an `authority_withdrawn` tombstone; the reservation made before
/// counts in the reported residual; every later use is refused.
#[tokio::test]
async fn r138_4_a_narrowing_outside_the_approval_ends_the_grant_at_use() {
    let w = World::new().await;
    let g = r138_approved(&w, "r138-4a", "r138-4a-work").await;
    w.ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 1800)))
        .await
        .unwrap();
    r138_set_policy_hosts(&w, &["h2"]);
    let e = err(r136_bind(&w, &g.binding_id, "r138-4a-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
    r138_assert_withdrawn(&w, &g.grant_id, Some(shift(t0(), 1800)));
    let again = err(r136_bind(&w, &g.binding_id, "r138-4a-b2").await);
    assert_eq!(again.code, Code::CredentialExpired);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::CredentialExpired);
}

/// Red. Withdrawn authority detected at use (issuance reserve): the environment no
/// longer permits automatic activation, so a standing-policy grant ends.
#[tokio::test]
async fn r138_4_a_removed_environment_permission_ends_the_grant_at_use() {
    let w = World::new().await;
    let g = r136_ready(&w, "r138-4b", "r138-4b-work", "h1", "1h").await;
    r138_set_automatic_activation(&w, false);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&refused.message);
    assert_eq!(refused.code, Code::CredentialExpired);
    r138_assert_withdrawn(&w, &g.grant_id, None);
    let e = err(r136_bind(&w, &g.binding_id, "r138-4b-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
}

/// Red. A revoke on the chain detected at use: a tombstone on the parent (the
/// child's row untouched) ends the child when it is next used.
#[tokio::test]
async fn r138_4_a_revoke_on_the_chain_ends_the_grant_at_use() {
    let w = World::new().await;
    let (parent, child) = r138_parent_and_child(&w, "r138-4c").await;
    r138_tombstone_only(&w, &parent.grant_id);
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Active);
    let e = err(r136_bind(&w, &child.binding_id, "r138-4c-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
    r138_assert_withdrawn(&w, &child.grant_id, None);
}

/// Red. A passed deadline, or a passed cutoff, detected at use: `expired` (no
/// tombstone: nothing was withdrawn).
#[tokio::test]
async fn r138_4_a_passed_deadline_or_cutoff_expires_the_grant_at_use() {
    let w = World::new().await;
    let g = r136_ready(&w, "r138-4d", "r138-4d-work", "h1", "1h").await;
    w.clock.advance(61 * MINUTE);
    let e = err(r136_bind(&w, &g.binding_id, "r138-4d-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Expired);
    assert!(r138_tombstone(&w, &g.grant_id).is_none());

    let w = World::new().await;
    let g = r136_ready(&w, "r138-4e", "r138-4e-work", "h1", "1h").await;
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: shift(t0(), 600),
        },
    )
    .await);
    w.clock.advance(11 * MINUTE);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 1800)))
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::CredentialExpired);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Expired);
    assert!(r138_tombstone(&w, &g.grant_id).is_none());
}

/// Red. Withdrawn authority detected by the supervisor's scheduler pass, with no
/// use at all: a narrowing outside the approval, a removed environment permission,
/// and a revoke on the chain each end their grant (`revoked`, `authority_withdrawn`).
#[tokio::test]
async fn r138_4_the_scheduler_pass_ends_grants_whose_authority_was_withdrawn() {
    // A narrowing outside the owner's approval.
    let w = World::new().await;
    let g = r138_approved(&w, "r138-4f", "r138-4f-work").await;
    r138_set_policy_hosts(&w, &["h2"]);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r138_assert_withdrawn(&w, &g.grant_id, None);
    // A removed environment permission.
    let w = World::new().await;
    let g = r136_ready(&w, "r138-4g", "r138-4g-work", "h1", "1h").await;
    r138_set_automatic_activation(&w, false);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r138_assert_withdrawn(&w, &g.grant_id, None);
    // A revoke on the chain.
    let w = World::new().await;
    let (parent, child) = r138_parent_and_child(&w, "r138-4h").await;
    r138_tombstone_only(&w, &parent.grant_id);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r138_assert_withdrawn(&w, &child.grant_id, None);
}

/// A passed deadline and a passed cutoff are detected by the scheduler pass as
/// `expired` (already so at the base commit; kept as the item's scheduler-pass
/// evidence for these causes).
#[tokio::test]
async fn r138_4_the_scheduler_pass_expires_grants_past_their_deadline_or_cutoff() {
    let w = World::new().await;
    let g = r136_ready(&w, "r138-4i", "r138-4i-work", "h1", "1h").await;
    w.clock.advance(61 * MINUTE);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Expired);
    assert!(r138_tombstone(&w, &g.grant_id).is_none());

    let w = World::new().await;
    let g = r136_ready(&w, "r138-4j", "r138-4j-work", "h1", "1h").await;
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Cutoff {
            policy_id: policy_id(),
            at: shift(t0(), 600),
        },
    )
    .await);
    w.clock.advance(11 * MINUTE);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Expired);
}

/// A pause and uncertain time never end a grant, neither at use nor in the
/// scheduler pass: under a pause the binding still binds; with authority
/// withdrawn while time is uncertain, every use answers `TIME_UNCERTAIN` and the
/// grant stays `active` (with no tombstone) until time is safe again; then the
/// next pass ends it.
#[tokio::test]
async fn r138_4_a_pause_or_uncertain_time_never_ends_a_grant() {
    let w = World::new().await;
    let g = r136_ready(&w, "r138-4k", "r138-4k-work", "h1", "1h").await;
    let sup = r138_supervisor(&w);
    ok(r136_policy(
        &w,
        &unattended(501),
        PolicyAction::Pause {
            policy_id: policy_id(),
        },
    )
    .await);
    let bound = ok(r136_bind(&w, &g.binding_id, "r138-4k-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Active,
        "a pause never ends a grant"
    );

    // Authority withdrawn, then the wall clock steps back: time is uncertain.
    r138_set_policy_hosts(&w, &["h2"]);
    w.clock.set_wall(
        w.clock
            .wall()
            .checked_sub(jiff::SignedDuration::from_mins(2))
            .unwrap(),
    );
    let e = err(r136_bind(&w, &g.binding_id, "r138-4k-b2").await);
    assert_eq!(e.code, Code::TimeUncertain);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::TimeUncertain);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Active,
        "uncertain time never ends a grant"
    );
    assert!(r138_tombstone(&w, &g.grant_id).is_none());
    // Once the wall clock is back where the continuous clock says it should be,
    // time is safe again and the next scheduler pass detects the withdrawal.
    w.clock.set_wall(
        w.clock
            .wall()
            .checked_add(jiff::SignedDuration::from_mins(2))
            .unwrap(),
    );
    sup.scheduler_pass().await.unwrap();
    r138_assert_withdrawn(&w, &g.grant_id, None);
}

/// Re-validation that cannot be determined is no withdrawal. ⟨r2.6⟩ ADR-0006
/// §13.9 item 2 leaves "undetermined" only for a record that truly lacks the data:
/// here a grant recorded without its origin (as a grant that predates schema
/// version 4 with nothing to backfill from is). After an unrelated generation move
/// its use is refused, and neither that refusal nor a scheduler pass ends or
/// tombstones it; a healthy grant beside it re-validates and stays usable. (A
/// parent kept alive only by its delegated child re-validates normally:
/// `r139_2_a_parent_kept_alive_by_its_child_revalidates_after_an_unrelated_generation_move`.)
#[tokio::test]
async fn r138_4_an_undetermined_revalidation_ends_nothing() {
    let w = World::new().await;
    let live = r136_ready(&w, "r138-4l", "r138-4l-work", "h1", "1h").await;
    let bare = heimdall_domain::grant::GrantSnapshot {
        id: heimdall_contract::ids::GrantId::from_random_bytes([0x5c; 16]),
        ..w.grant(&live.grant_id)
    };
    w.store.transaction(|tx| tx.insert_grant(&bare)).unwrap();
    assert_eq!(
        w.store.transaction(|tx| tx.grant_origin(&bare.id)).unwrap(),
        None,
        "a record without its origin"
    );
    r139_unrelated_policy(&w, 1);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&bare.id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&refused.message);
    assert_eq!(refused.code, Code::CredentialExpired, "the use is refused");
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&bare.id).state, GrantState::Active);
    assert!(r138_tombstone(&w, &bare.id).is_none());
    assert_eq!(w.grant(&live.grant_id).state, GrantState::Active);
    let bound = ok(r136_bind(&w, &live.binding_id, "r138-4l-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
}

// =================================================================================
// ⟨r2.6⟩ ADR-0006 §13.9 rulings (M01-rulings-13-9-J1): item 1 (uncertain time and
// expiry), item 2 (re-validation context from the grant's own record) and item 3
// (interrupted withdrawals complete). Each case was first run against the base
// commit 01747a6b and failed there (red); it passes with the change. Only
// production hooks and public APIs are used; restarts are in-process.
// =================================================================================

/// The `authority_withdrawn` credential-lifecycle events reported for `grant`.
fn r139_withdrawals(w: &World, grant: &heimdall_contract::ids::GrantId) -> Vec<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event.event_type == EventType::CredentialLifecycle)
        .map(|e| e.event.payload)
        .filter(|p| {
            p["grant_id"] == serde_json::json!(grant) && p["event"] == "authority_withdrawn"
        })
        .collect()
}

/// A policy for another profile: moves the global authority generation without
/// touching anything the `dev` grants rest on.
fn r139_unrelated_policy(w: &World, revision: u64) {
    w.store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol-other").unwrap(),
                    revision: PolicyRevision(revision),
                    profile: ProfileId::parse("other").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: [pair("h9", "deploy")].into_iter().collect(),
                        capabilities: ssh_only(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                },
                false,
            )
            .map(|_| ())
        })
        .unwrap();
}

/// Red. §13.9 item 1: a wall clock that jumps forward past the grant's bound while
/// the continuous clock says only 10 minutes passed is untrusted (`TIME_UNCERTAIN`,
/// skew). The scheduler pass ends nothing on that reading, a use answers
/// `TIME_UNCERTAIN`, and the grant stays `active` with no tombstone. Once the wall
/// clock agrees again, time is safe and the grant is judged: its continuous budget
/// is not spent, so it binds.
#[tokio::test]
async fn r139_1_a_forward_wall_jump_under_uncertainty_leaves_the_grant_non_terminal() {
    let w = World::new().await;
    let g = r136_ready(&w, "r139-1a", "r139-1a-work", "h1", "1h").await;
    let sup = r138_supervisor(&w);
    w.clock.advance(10 * MINUTE);
    w.clock.set_wall(shift(w.clock.wall(), 2 * 3600));
    sup.scheduler_pass().await.unwrap();
    w.ops.tick().await.unwrap();
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Active,
        "a wall bound that appears passed only on an uncertain reading ends nothing"
    );
    let e = err(r136_bind(&w, &g.binding_id, "r139-1a-b1").await);
    assert_eq!(e.code, Code::TimeUncertain);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Active);
    assert!(r138_tombstone(&w, &g.grant_id).is_none());
    // The wall clock is back where the continuous clock predicts it: safe again.
    w.clock.set_wall(shift(w.clock.wall(), -2 * 3600));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Active);
    let bound = ok(r136_bind(&w, &g.binding_id, "r139-1a-b2").await);
    assert_eq!(bound.code, Code::AccessReady);
    w.events();
}

/// Red. §13.9 item 1: the boot-scoped continuous clock counts sleep and is trusted
/// within a boot, so a budget that runs out while time is uncertain (here the wall
/// clock lags 30 minutes behind the continuous prediction) still expires the grant
/// in the scheduler pass: `expired`, no tombstone, and later use is refused.
#[tokio::test]
async fn r139_1_a_continuous_budget_running_out_under_uncertainty_expires_the_grant() {
    let w = World::new().await;
    let g = r136_ready(&w, "r139-1b", "r139-1b-work", "h1", "1h").await;
    w.clock.advance(61 * MINUTE);
    w.clock.set_wall(shift(w.clock.wall(), -30 * 60));
    assert!(
        dtime_uncertain(&w).await,
        "the lagging wall clock makes time uncertain"
    );
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Expired,
        "the continuous budget ran out"
    );
    assert!(r138_tombstone(&w, &g.grant_id).is_none());
    let e = err(r136_bind(&w, &g.binding_id, "r139-1b-b1").await);
    assert!(
        matches!(e.code, Code::CredentialExpired | Code::TimeUncertain),
        "no use of an expired grant: {}",
        e.code
    );
    w.events();
}

/// Whether the shared gate currently assesses time as uncertain.
async fn dtime_uncertain(w: &World) -> bool {
    matches!(
        w.ops.timegate().peek().await.unwrap(),
        heimdall_domain::time::TimeStatus::Uncertain(_)
    )
}

/// A clock over the virtual clock whose wall reading, while armed, is `jump`
/// seconds ahead on every reading after the first: the gate assesses the first
/// reading of a pass; a later one in the same pass is unassessed.
struct JumpAfterFirst {
    inner: Arc<VirtualClock>,
    armed: AtomicBool,
    reads: AtomicUsize,
    jump: i64,
}

impl Clock for JumpAfterFirst {
    fn wall(&self) -> Timestamp {
        let w = self.inner.wall();
        if self.armed.load(Ordering::SeqCst) && self.reads.fetch_add(1, Ordering::SeqCst) > 0 {
            shift(w, self.jump)
        } else {
            w
        }
    }
    fn continuous(&self) -> Duration {
        self.inner.continuous()
    }
    fn boot_id(&self) -> heimdall_domain::time::BootId {
        self.inner.boot_id()
    }
}

/// Red. §13.9 item 1 on safe time: the scheduler pass judges expiry on the
/// observation the gate accepted and on the continuous budget only. A wall reading
/// taken after that acceptance in the same pass (here 2 h ahead, past the grant's
/// 1 h bound, with 10 minutes on the continuous clock) is unassessed and ends
/// nothing; the grant stays usable.
#[tokio::test]
async fn r139_1_an_unassessed_wall_reading_after_the_gate_accepted_time_ends_nothing() {
    let mut w = World::new().await;
    let clock = Arc::new(JumpAfterFirst {
        inner: w.clock.clone(),
        armed: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
        jump: 2 * 3600,
    });
    w.ops = Operations::start(OperationsConfig {
        clock: clock.clone(),
        ..w.config()
    })
    .await
    .unwrap();
    let g = r136_ready(&w, "r139-1c", "r139-1c-work", "h1", "1h").await;
    w.clock.advance(10 * MINUTE);
    clock.armed.store(true, Ordering::SeqCst);
    w.ops.tick().await.unwrap();
    clock.armed.store(false, Ordering::SeqCst);
    assert!(
        clock.reads.load(Ordering::SeqCst) >= 2,
        "the pass read the wall clock again after the gate"
    );
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Active,
        "an unassessed wall reading ends nothing"
    );
    let bound = ok(r136_bind(&w, &g.binding_id, "r139-1c-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
}

/// Red. §13.9 item 1 at use: a use that finds the grant's authority withdrawn
/// classifies its end on trusted evidence only. A wall reading taken after the gate
/// accepted the use's observation (2 h ahead, past the 1 h bound; the continuous
/// clock says 10 minutes) does not turn the withdrawal into an expiry: the grant is
/// `revoked` with an `authority_withdrawn` tombstone and report, never `expired`.
#[tokio::test]
async fn r139_1_an_unassessed_wall_reading_never_turns_a_withdrawal_into_an_expiry() {
    let mut w = World::new().await;
    let clock = Arc::new(JumpAfterFirst {
        inner: w.clock.clone(),
        armed: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
        jump: 2 * 3600,
    });
    w.ops = Operations::start(OperationsConfig {
        clock: clock.clone(),
        ..w.config()
    })
    .await
    .unwrap();
    let g = r136_ready(&w, "r139-1d", "r139-1d-work", "h1", "1h").await;
    w.clock.advance(10 * MINUTE);
    r138_set_automatic_activation(&w, false);
    clock.armed.store(true, Ordering::SeqCst);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 1800)))
        .await
        .unwrap_err();
    clock.armed.store(false, Ordering::SeqCst);
    assert_no_canary(&refused.message);
    assert_eq!(refused.code, Code::CredentialExpired);
    r138_assert_withdrawn(&w, &g.grant_id, None);
}

/// Red. §13.9 item 2: a parent kept alive only by its delegated child's reference
/// (its consumer released its binding) re-validates from its own persisted record
/// after an unrelated generation move, like any other grant: the child's issuance
/// reserves and publishes, the child's binding binds, the parent's re-validation is
/// recorded at the current generation, and the scheduler pass ends nothing.
#[tokio::test]
async fn r139_2_a_parent_kept_alive_by_its_child_revalidates_after_an_unrelated_generation_move() {
    let w = World::new().await;
    let (parent, child) = r138_parent_and_child(&w, "r139-2").await;
    ok(w.ops
        .release(
            &unattended(501),
            ReleaseRequest {
                binding_id: parent.binding_id.clone(),
            },
        )
        .await);
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Active);
    r139_unrelated_policy(&w, 1);
    let reserved = w
        .ops
        .reserve_issuance(u10_issuance(&child.grant_id, shift(t0(), 600)))
        .await
        .unwrap_or_else(|e| panic!("child issuance refused: {} {}", e.code, e.message));
    let published = issue(&w, &reserved.id, &u10_issuance(&child.grant_id, t0()).facts)
        .await
        .unwrap_or_else(|e| panic!("child publish refused: {} {}", e.code, e.message));
    assert_eq!(
        published.state,
        heimdall_domain::issuance::IssuanceState::Published
    );
    let current = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    assert_eq!(
        w.store
            .transaction(|tx| tx.grant_validation(&parent.grant_id))
            .unwrap(),
        Some(current),
        "the parent re-validated at the current generation"
    );
    // Another unrelated move: the child's binding binds (its chain re-validates).
    r139_unrelated_policy(&w, 2);
    let bound = ok(r136_bind(&w, &child.binding_id, "r139-2-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&parent.grant_id).state, GrantState::Active);
    assert_eq!(w.grant(&child.grant_id).state, GrantState::Active);
    assert!(r138_tombstone(&w, &parent.grant_id).is_none());
    assert!(r138_tombstone(&w, &child.grant_id).is_none());
    w.events();
}

/// Red. §13.9 item 3: a crash between the withdrawal tombstone and its completion.
/// A use detects withdrawn authority (the environment no longer permits automatic
/// activation); its transaction writes the `authority_withdrawn` tombstone and
/// moves the grant to `revoking`, and the store fails right after that commit, so
/// the completion never runs. The in-process restart completes it: local denial,
/// `revoked`, exactly one `authority_withdrawn` event whose residual counts the
/// certificate published before the withdrawal. Further passes and restarts add
/// nothing.
#[tokio::test]
async fn r139_3_a_crash_between_the_withdrawal_tombstone_and_its_completion_completes_on_restart() {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let mut w = World::with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let g = r136_ready(&w, "r139-3a", "r139-3a-work", "h1", "1h").await;
    let reserved = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 1800)))
        .await
        .unwrap();
    issue(&w, &reserved.id, &u10_issuance(&g.grant_id, t0()).facts)
        .await
        .unwrap();
    r138_set_automatic_activation(&w, false);
    faults.arm();
    let crashed = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&crashed.message);
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the crash point fired"
    );
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    assert_eq!(
        r138_tombstone(&w, &g.grant_id).expect("tombstone")["cause"],
        "authority_withdrawn"
    );
    assert!(
        r139_withdrawals(&w, &g.grant_id).is_empty(),
        "not completed yet"
    );
    w.restart().await;
    r138_assert_withdrawn(&w, &g.grant_id, Some(shift(t0(), 1800)));
    assert_eq!(
        r139_withdrawals(&w, &g.grant_id).len(),
        1,
        "exactly one event"
    );
    w.ops.tick().await.unwrap();
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    w.restart().await;
    assert_eq!(
        r139_withdrawals(&w, &g.grant_id).len(),
        1,
        "completion is idempotent"
    );
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
}

/// Red. §13.9 item 3 in the scheduler pass (no restart): the same interrupted
/// withdrawal is completed by the next pass, once.
#[tokio::test]
async fn r139_3_the_scheduler_pass_completes_an_interrupted_withdrawal_once() {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let w = World::with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let g = r136_ready(&w, "r139-3b", "r139-3b-work", "h1", "1h").await;
    r138_set_policy_hosts(&w, &["h2"]);
    // The use is an issuance reservation: one transaction detects the withdrawal,
    // writes the tombstone and moves the grant to `revoking`; the crash point is
    // right after its commit.
    faults.arm();
    let crashed = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&crashed.message);
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the crash point fired"
    );
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    assert!(r139_withdrawals(&w, &g.grant_id).is_empty());
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    r138_assert_withdrawn(&w, &g.grant_id, None);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1);
}

/// Delegates to the fake, except that while `pending` is set `revoke` leaves a
/// remote effect pending (the grant stays `revoking`).
struct TogglePending {
    inner: Arc<FakeCredentialAdapter>,
    pending: AtomicBool,
}

impl CredentialAdapter for TogglePending {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.inner.descriptor()
    }
    fn prepare<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.prepare(req)
    }
    fn renew<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.renew(req)
    }
    fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        effect_token: &'life2 str,
    ) -> U10Fut<'async_trait, heimdall_app::ports::ReconcileOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.reconcile(grant, effect_token)
    }
    fn revoke<'life0, 'life1, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        now: Timestamp,
    ) -> U10Fut<'async_trait, heimdall_app::ports::RevokeOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let pending = self.pending.load(Ordering::SeqCst);
        Box::pin(async move {
            let mut out = self.inner.revoke(grant, now).await?;
            if pending {
                out.remote_pending = vec![DestinationId::parse("h1").unwrap()];
            }
            Ok(out)
        })
    }
}

/// Red. §13.9 item 3: a withdrawal whose remote effect is still pending is
/// reported once (`remote_pending` names the grant) and the grant stays
/// `revoking`; once nothing is pending remotely, the next retry round moves it to
/// `revoked` without a second report. ⟨r2.7⟩ §13.10 item 3: that round is due on
/// the supervisor's bounded, jittered schedule (default backoff: at most 500 ms
/// after the pass that first saw the pending record), not in every pass.
#[tokio::test]
async fn r139_3_a_pending_remote_effect_completes_in_a_later_pass_without_a_second_report() {
    let mut w = World::new().await;
    let adapter = Arc::new(TogglePending {
        inner: w.fake.clone(),
        pending: AtomicBool::new(true),
    });
    w.ops = Operations::start(OperationsConfig {
        adapters: vec![adapter.clone() as Arc<dyn CredentialAdapter>],
        ..w.config()
    })
    .await
    .unwrap();
    let g = r136_ready(&w, "r139-3c", "r139-3c-work", "h1", "1h").await;
    r138_set_automatic_activation(&w, false);
    let e = err(r136_bind(&w, &g.binding_id, "r139-3c-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    let reported = r139_withdrawals(&w, &g.grant_id);
    assert_eq!(reported.len(), 1);
    assert_eq!(
        reported[0]["remote_pending"],
        serde_json::json!([g.grant_id.clone()])
    );
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        w.grant(&g.grant_id).state,
        GrantState::Revoking,
        "still pending remotely"
    );
    adapter.pending.store(false, Ordering::SeqCst);
    w.clock.advance(Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1, "reported once");
}

/// ⟨r2.6⟩ ADR-0006 §13.9 item 1 as a property (proptest, 256 cases, fixed seed
/// unless `PROPTEST_RNG_SEED` is set; failures persist to
/// `tests/model/operations.proptest-regressions`).
mod r139_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    fn config(seed: u64) -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(seed);
        }
        c
    }

    fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
        f: F,
    ) -> Result<(), TestCaseError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    proptest! {
        #![proptest_config(config(0x0139_0001))]

        /// While time is uncertain (the wall clock disagrees with the continuous
        /// prediction by more than the skew tolerance, ahead or behind), the
        /// scheduler pass ends a 1 h grant exactly when its persisted continuous
        /// budget has run out, whether or not the wall reading is past the bound;
        /// an expiry writes no tombstone.
        #[test]
        fn r139_1_under_uncertain_time_only_the_continuous_budget_ends_a_grant(
            elapsed_s in 0u64..7200,
            skew_s in prop_oneof![-5400i64..-61, 61i64..10_800],
        ) {
            block(async move {
                let w = World::new().await;
                let g = r136_ready(&w, "r139-p", "r139-p-work", "h1", "1h").await;
                let anchor = w
                    .store
                    .transaction(|tx| tx.grant_anchor(&g.grant_id))
                    .unwrap()
                    .unwrap();
                w.clock.advance(Duration::from_secs(elapsed_s));
                w.clock.set_wall(shift(w.clock.wall(), skew_s));
                prop_assert!(dtime_uncertain(&w).await, "time is uncertain");
                r138_supervisor(&w).scheduler_pass().await.unwrap();
                let exhausted = w.clock.continuous() >= anchor.budget_end;
                let expected = if exhausted {
                    GrantState::Expired
                } else {
                    GrantState::Active
                };
                prop_assert_eq!(w.grant(&g.grant_id).state, expected);
                prop_assert!(r138_tombstone(&w, &g.grant_id).is_none());
                Ok(())
            })?;
        }
    }
}

// =================================================================================
// ⟨r2.7⟩ ADR-0006 §13.10 item 2 (M01-rulings-13-10-K1): a grant whose credential
// mechanism is no longer configured. Every use is refused and nothing ends; the
// grant moves `active → degraded` with reason `mechanism_unavailable` (at use and in
// the scheduler pass), returns to `active` when the mechanism is configured again
// and re-validation passes, and still expires (or is withdrawn) as usual while
// degraded. Only public APIs are used, so each case also runs against the base
// commit 2142c81a (red there). "Restart" is in-process: a new `Operations` over the
// same store with another adapter set.
// =================================================================================

/// A fake adapter for another mechanism (`fake_other`): with only it configured,
/// the fixture grants' mechanism (`fake_agent`) is no longer configured.
fn r1310_other_adapter() -> Arc<dyn CredentialAdapter> {
    let mut d = descriptor();
    d.identity = AdapterIdentity {
        mechanism: "fake_other".into(),
        instance: "fixture-2".into(),
    };
    FakeCredentialAdapter::new(d, vec![FakeStep::Prepare(outcome())])
}

/// In-process restart with only `fake_other` configured.
async fn r1310_restart_without_mechanism(w: &mut World) {
    w.ops = Operations::start(OperationsConfig {
        adapters: vec![r1310_other_adapter()],
        ..w.config()
    })
    .await
    .unwrap();
}

/// The `grant_state_changed` payloads of `grant` in order.
fn r1310_states(w: &World, grant: &heimdall_contract::ids::GrantId) -> Vec<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event.event_type == EventType::GrantStateChanged)
        .map(|e| e.event.payload)
        .filter(|p| p["grant_id"] == serde_json::json!(grant))
        .collect()
}

/// The `degraded` state changes of `grant`.
fn r1310_degraded(w: &World, grant: &heimdall_contract::ids::GrantId) -> Vec<serde_json::Value> {
    r1310_states(w, grant)
        .into_iter()
        .filter(|p| p["state"] == "degraded")
        .collect()
}

/// The owner's inspect view of `grant` (listed while it is not terminal).
async fn r1310_view(w: &World, grant: &heimdall_contract::ids::GrantId) -> serde_json::Value {
    let r = ok(w
        .ops
        .inspect(
            &unattended(501),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Grants,
                preview: None,
            },
        )
        .await);
    r.data["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["grant_id"] == serde_json::json!(grant))
        .cloned()
        .expect("the grant is listed")
}

/// `degraded` with reason `mechanism_unavailable` (one state change carrying it,
/// the inspect view showing it), no tombstone, and its binding still active.
async fn r1310_assert_degraded(w: &World, g: &EnsureData, work: &str) {
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Degraded);
    let degraded = r1310_degraded(w, &g.grant_id);
    assert_eq!(degraded.len(), 1, "one degraded state change: {degraded:?}");
    assert_eq!(degraded[0]["reason"], "mechanism_unavailable");
    assert_eq!(
        r1310_view(w, &g.grant_id).await["degraded_reason"],
        "mechanism_unavailable"
    );
    assert!(r138_tombstone(w, &g.grant_id).is_none(), "nothing ends");
    assert!(
        w.bindings_for(work)
            .iter()
            .all(|b| b.state == heimdall_domain::binding::BindingState::Active),
        "its binding is untouched"
    );
}

/// Red. Detected at use: with the grant's mechanism no longer configured, a bind
/// is refused (`CAPABILITY_UNAVAILABLE`, exit 4) and moves the grant to `degraded`
/// with reason `mechanism_unavailable`; nothing ends. Every further use (bind,
/// issuance reserve, delegation from it) is refused the same way, and a scheduler
/// pass neither ends it nor reports it again.
#[tokio::test]
async fn r1310_2_a_use_with_the_mechanism_gone_is_refused_and_degrades_the_grant() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2a", "r1310-2a-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    let e = err(r136_bind(&w, &g.binding_id, "r1310-2a-b1").await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.code.exit_code(), ExitCode::Denied);
    r1310_assert_degraded(&w, &g, "r1310-2a-work").await;
    let again = err(r136_bind(&w, &g.binding_id, "r1310-2a-b2").await);
    assert_eq!(again.code, Code::CapabilityUnavailable);
    let refused = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_err();
    assert_no_canary(&refused.message);
    assert_eq!(refused.code, Code::CapabilityUnavailable);
    let child = err(w
        .ops
        .delegate(&unattended(501), u10_delegate(&g, "r1310-2a-c", "30m"))
        .await);
    assert_eq!(child.code, Code::CapabilityUnavailable);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2a-work").await;
}

/// Red. Detected by the scheduler pass with no use at all: the grant whose
/// mechanism is gone moves to `degraded` (once; later passes add nothing).
#[tokio::test]
async fn r1310_2_the_scheduler_pass_degrades_a_grant_whose_mechanism_is_gone() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2b", "r1310-2b-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2b-work").await;
    sup.scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2b-work").await;
}

/// Red. Back at use: once the mechanism is configured again (restart with the
/// fixture adapter), the next use re-validates the degraded grant, moves it to
/// `active` (the reason is gone) and succeeds.
#[tokio::test]
async fn r1310_2_a_use_repairs_a_degraded_grant_once_its_mechanism_is_configured_again() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2c", "r1310-2c-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2c-work").await;
    w.restart().await;
    let bound = ok(r136_bind(&w, &g.binding_id, "r1310-2c-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Active);
    let states = r1310_states(&w, &g.grant_id);
    assert_eq!(states.last().unwrap()["state"], "active", "{states:?}");
    assert!(
        r1310_view(&w, &g.grant_id)
            .await
            .get("degraded_reason")
            .is_none()
    );
    let reserved = w
        .ops
        .reserve_issuance(u10_issuance(&g.grant_id, shift(t0(), 600)))
        .await
        .unwrap_or_else(|e| panic!("issuance refused: {} {}", e.code, e.message));
    assert_eq!(reserved.grant, g.grant_id);
}

/// Red. Back in the scheduler pass: with the mechanism configured again, the pass
/// re-validates the degraded grant and moves it to `active`; it binds.
#[tokio::test]
async fn r1310_2_the_scheduler_pass_repairs_a_degraded_grant_once_its_mechanism_is_back() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2d", "r1310-2d-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2d-work").await;
    w.restart().await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Active);
    let bound = ok(r136_bind(&w, &g.binding_id, "r1310-2d-b1").await);
    assert_eq!(bound.code, Code::AccessReady);
    w.events();
}

/// Red. A restart while degraded (the mechanism still missing): the grant stays
/// `degraded` with its reason (persisted), every use is still refused, a pass adds
/// no second report; after a restart with the mechanism configured again the pass
/// returns it to `active`.
#[tokio::test]
async fn r1310_2_a_restart_while_degraded_keeps_the_grant_degraded_and_refused() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2e", "r1310-2e-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    let e = err(r136_bind(&w, &g.binding_id, "r1310-2e-b1").await);
    assert_eq!(e.code, Code::CapabilityUnavailable);
    r1310_assert_degraded(&w, &g, "r1310-2e-work").await;
    r1310_restart_without_mechanism(&mut w).await;
    r1310_assert_degraded(&w, &g, "r1310-2e-work").await;
    let again = err(r136_bind(&w, &g.binding_id, "r1310-2e-b2").await);
    assert_eq!(again.code, Code::CapabilityUnavailable);
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2e-work").await;
    w.restart().await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Active);
    let bound = ok(r136_bind(&w, &g.binding_id, "r1310-2e-b3").await);
    assert_eq!(bound.code, Code::AccessReady);
}

/// Red. A deadline passing while degraded expires the grant as usual (`expired`,
/// no tombstone), even though its mechanism is still missing.
#[tokio::test]
async fn r1310_2_a_deadline_passing_while_degraded_expires_the_grant() {
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2f", "r1310-2f-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2f-work").await;
    w.clock.advance(61 * MINUTE);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Expired);
    assert!(r138_tombstone(&w, &g.grant_id).is_none());
    let e = err(r136_bind(&w, &g.binding_id, "r1310-2f-b1").await);
    assert_eq!(e.code, Code::CredentialExpired);
}

/// Red. Authority is judged apart from the mechanism: a narrowing that removes the
/// degraded grant's pair is still a withdrawal (`authority_withdrawn`), and with
/// the mechanism configured again the grant is not repaired, because its
/// re-validation fails.
///
/// ⟨r2.9⟩ ADR-0006 §13.12 item 2: while the grant's responsible adapter is not
/// configured, its local denial and remote obligation cannot be confirmed, so the
/// withdrawn grant stays `revoking` (`adapter_unavailable`) until that adapter is
/// configured again and confirms; then it is `revoked`. (Before §13.12 the other
/// mechanism's adapter answered and the grant was `revoked` at once: the false
/// completion of review round 4 T02.)
#[tokio::test]
async fn r1310_2_a_degraded_grant_returns_only_when_revalidation_passes() {
    // Withdrawn while degraded (the mechanism still missing).
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2g", "r1310-2g-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2g-work").await;
    r138_set_policy_hosts(&w, &["h2"]);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    assert_eq!(
        r138_tombstone(&w, &g.grant_id).expect("a tombstone")["cause"],
        "authority_withdrawn"
    );
    assert_eq!(
        r1310_view(&w, &g.grant_id).await["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"])
    );
    w.restart().await;
    let sup = r138_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(MINUTE);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    let ev = r138_withdrawal(&w, &g.grant_id).expect("the withdrawal is reported");
    assert_eq!(ev["local_applied"], true);
    assert_eq!(
        ev["remote_pending"],
        serde_json::json!([g.grant_id.clone()]),
        "reported pending: its adapter could not be asked"
    );
    // The mechanism comes back together with a narrowing: no return to `active`.
    let mut w = World::new().await;
    let g = r136_ready(&w, "r1310-2h", "r1310-2h-work", "h1", "1h").await;
    r1310_restart_without_mechanism(&mut w).await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1310-2h-work").await;
    r138_set_policy_hosts(&w, &["h2"]);
    w.restart().await;
    r138_supervisor(&w).scheduler_pass().await.unwrap();
    let states: Vec<String> = r1310_states(&w, &g.grant_id)
        .iter()
        .map(|p| p["state"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        !states
            .iter()
            .skip_while(|s| *s != "degraded")
            .any(|s| s == "active"),
        "never active again: {states:?}"
    );
    r138_assert_withdrawn(&w, &g.grant_id, None);
}

// =================================================================================
// ⟨r2.7⟩ ADR-0006 §13.10 item 3 (M01-rulings-13-10-K1): repeated adapter `revoke()`
// calls for a pending remote effect follow the supervisor's bounded, jittered
// backoff (the default `Backoff`: 500 ms doubling to at most 60 s, 8 rounds; the
// jitter injected as `FixedJitter(0.5)`, i.e. 75 % of each delay); attempts are
// capped, after which the grant stays `revoking` with its remote part visible and
// nothing calls or reports again until an explicit owner action or a round that
// finds nothing pending. Only public APIs are used (red at the base commit).
// =================================================================================

/// Delegates to the fake; counts `revoke` calls, and while `pending` is set every
/// `revoke` leaves a remote effect pending.
///
/// ⟨r2.9⟩ ADR-0006 §13.12 additions: it counts its confirmations (a `revoke` answer
/// with nothing pending); while `faults` holds a store fault hook, every `revoke`
/// arms it, so the next commit (the round's completion) fails; while `hang` is set,
/// the next `revoke` is counted, signals `entered` and never returns (the in-process
/// crash point after the adapter call and before its completion).
///
/// ⟨r2.10⟩ ADR-0006 §13.13 item 4: while `stall` is set, the next `revoke` signals
/// `entered` and never returns **without** being counted or reaching the fake (the
/// in-process crash point after the round's claim committed and before the adapter
/// acted on the call).
///
/// ⟨r2.14⟩ ADR-0006 §13.17: while `hold_prepare` is set, the next `prepare` signals
/// `prepare_entered` and waits for `prepare_release` before the fake applies its
/// effect (a preparation still in flight while the grant is revoked and its
/// operation cancelled).
///
/// ⟨r2.15⟩ ADR-0006 §13.18 item 2: while `hold_revoke` is set, the next `revoke` is
/// counted and reaches the fake at once (the call goes out), then signals
/// `revoke_entered` and holds its answer until `revoke_release` (a round's call in
/// flight while a credential is applied).
///
/// ⟨r2.16⟩ ADR-0006 §13.19: `log` records, in order, every applied effect
/// (`(grant, None)`, written when the fake applied it) and every `revoke` call
/// (`(grant, Some(pending))`, the answer fixed when the call goes out). While
/// `hold_queued` is set, the next `revoke` goes out at once (counted, logged, the
/// fake reached) and then parks on its own release, appended to `held` in call
/// order and signalled by `held_entered`: several answers can be held at once and
/// released in any order. A held call whose release is dropped never answers (a
/// crash). While `hang_after_prepare` is set, the next `prepare` applies its effect
/// and never returns (the in-process crash point after the effect, before its
/// receipt).
struct PendingCounter {
    inner: Arc<FakeCredentialAdapter>,
    pending: AtomicBool,
    revokes: AtomicUsize,
    confirms: AtomicUsize,
    faults: std::sync::Mutex<Option<Arc<Armed>>>,
    hang: AtomicBool,
    stall: AtomicBool,
    entered: tokio::sync::Notify,
    hold_prepare: AtomicBool,
    prepare_entered: tokio::sync::Notify,
    prepare_release: tokio::sync::Notify,
    hold_revoke: AtomicBool,
    revoke_entered: tokio::sync::Notify,
    revoke_release: tokio::sync::Notify,
    log: std::sync::Mutex<Vec<(heimdall_contract::ids::GrantId, Option<bool>)>>,
    hold_queued: AtomicBool,
    held: std::sync::Mutex<Vec<tokio::sync::oneshot::Sender<()>>>,
    held_entered: tokio::sync::Notify,
    hang_after_prepare: AtomicBool,
}

impl PendingCounter {
    fn new(inner: Arc<FakeCredentialAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            pending: AtomicBool::new(true),
            revokes: AtomicUsize::new(0),
            confirms: AtomicUsize::new(0),
            faults: std::sync::Mutex::new(None),
            hang: AtomicBool::new(false),
            stall: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            hold_prepare: AtomicBool::new(false),
            prepare_entered: tokio::sync::Notify::new(),
            prepare_release: tokio::sync::Notify::new(),
            hold_revoke: AtomicBool::new(false),
            revoke_entered: tokio::sync::Notify::new(),
            revoke_release: tokio::sync::Notify::new(),
            log: std::sync::Mutex::new(Vec::new()),
            hold_queued: AtomicBool::new(false),
            held: std::sync::Mutex::new(Vec::new()),
            held_entered: tokio::sync::Notify::new(),
            hang_after_prepare: AtomicBool::new(false),
        })
    }
    fn calls(&self) -> usize {
        self.revokes.load(Ordering::SeqCst)
    }
    fn confirmations(&self) -> usize {
        self.confirms.load(Ordering::SeqCst)
    }
    /// ⟨r2.16⟩ The `revoke` calls for `grant` made after its latest applied effect
    /// (`None` when no effect was applied for it).
    fn calls_after_effect(&self, grant: &heimdall_contract::ids::GrantId) -> Option<usize> {
        let log = self.log.lock().unwrap();
        let at = log
            .iter()
            .rposition(|(g, call)| g == grant && call.is_none())?;
        Some(
            log[at + 1..]
                .iter()
                .filter(|(g, call)| g == grant && call.is_some())
                .count(),
        )
    }
    /// ⟨r2.16⟩ Release the held answer at `index` (call order); `false` when none.
    fn release_held(&self, index: usize) -> bool {
        let mut held = self.held.lock().unwrap();
        if index >= held.len() {
            return false;
        }
        let _ = held.remove(index).send(());
        true
    }
}

impl CredentialAdapter for PendingCounter {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.inner.descriptor()
    }
    fn prepare<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let hold = self.hold_prepare.swap(false, Ordering::SeqCst);
        let grant = req.grant.id.clone();
        let applied = self.inner.prepare(req);
        Box::pin(async move {
            if hold {
                self.prepare_entered.notify_one();
                self.prepare_release.notified().await;
            }
            let before = self.inner.effect_count();
            let out = applied.await;
            if self.inner.effect_count() > before {
                self.log.lock().unwrap().push((grant, None));
                if self.hang_after_prepare.swap(false, Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
            }
            out
        })
    }
    fn renew<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: heimdall_app::ports::PrepareRequest<'life1>,
    ) -> U10Fut<'async_trait, PrepareOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.renew(req)
    }
    fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        effect_token: &'life2 str,
    ) -> U10Fut<'async_trait, heimdall_app::ports::ReconcileOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.reconcile(grant, effect_token)
    }
    fn revoke<'life0, 'life1, 'async_trait>(
        &'life0 self,
        grant: &'life1 heimdall_contract::ids::GrantId,
        now: Timestamp,
    ) -> U10Fut<'async_trait, heimdall_app::ports::RevokeOutcome>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        if self.stall.swap(false, Ordering::SeqCst) {
            return Box::pin(async move {
                self.entered.notify_one();
                std::future::pending().await
            });
        }
        self.revokes.fetch_add(1, Ordering::SeqCst);
        let pending = self.pending.load(Ordering::SeqCst);
        self.log
            .lock()
            .unwrap()
            .push((grant.clone(), Some(pending)));
        if let Some(f) = self.faults.lock().unwrap().as_ref() {
            f.arm();
        }
        let hang = self.hang.swap(false, Ordering::SeqCst);
        let hold = self.hold_revoke.swap(false, Ordering::SeqCst);
        let queued = self.hold_queued.swap(false, Ordering::SeqCst).then(|| {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            self.held.lock().unwrap().push(tx);
            rx
        });
        Box::pin(async move {
            if hang {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            let mut out = self.inner.revoke(grant, now).await?;
            if let Some(rx) = queued {
                self.held_entered.notify_one();
                if rx.await.is_err() {
                    // Its release was dropped: a crash, so this answer never arrives.
                    std::future::pending::<()>().await;
                }
            }
            if hold {
                self.revoke_entered.notify_one();
                self.revoke_release.notified().await;
            }
            if pending {
                out.remote_pending = vec![DestinationId::parse("h1").unwrap()];
            } else {
                self.confirms.fetch_add(1, Ordering::SeqCst);
            }
            Ok(out)
        })
    }
}

/// A world whose only adapter is a [`PendingCounter`] (pending on).
async fn r1310_pending_world() -> (World, Arc<PendingCounter>) {
    r1312_pending_world_with(Setup::default()).await
}

/// [`r1310_pending_world`] over a world built from `setup` (⟨r2.9⟩: a store fault
/// hook for the §13.12 cases).
async fn r1312_pending_world_with(setup: Setup) -> (World, Arc<PendingCounter>) {
    let mut w = World::with(setup).await;
    let adapter = PendingCounter::new(w.fake.clone());
    w.ops = Operations::start(OperationsConfig {
        adapters: vec![adapter.clone() as Arc<dyn CredentialAdapter>],
        ..w.config()
    })
    .await
    .unwrap();
    (w, adapter)
}

/// In-process restart keeping the [`PendingCounter`] as the only adapter.
async fn r1310_restart_pending(w: &mut World, adapter: &Arc<PendingCounter>) {
    w.ops = Operations::start(OperationsConfig {
        adapters: vec![adapter.clone() as Arc<dyn CredentialAdapter>],
        ..w.config()
    })
    .await
    .unwrap();
}

/// The supervisor over this world with the deterministic jitter unit 0.5 (each
/// retry delay is 75 % of the bounded backoff delay).
fn r1310_supervisor(w: &World) -> heimdall_runtime::supervisor::Supervisor {
    r138_supervisor(w).with_jitter(Arc::new(heimdall_runtime::supervisor::FixedJitter(0.5)))
}

/// The jittered delay before round `n + 1` after round `n` (default backoff,
/// unit 0.5), computed independently of the production helper.
fn r1310_delay(n: u32) -> Duration {
    let base = Duration::from_millis(500) * (1u32 << (n - 1));
    base.min(Duration::from_secs(60)).mul_f64(0.75)
}

/// A grant withdrawn at use (the environment no longer permits automatic
/// activation) whose local denial leaves a remote effect pending: round 1.
async fn r1310_withdrawn_pending(w: &World, adapter: &PendingCounter, tag: &str) -> EnsureData {
    let g = r136_ready(w, tag, &format!("{tag}-work"), "h1", "1h").await;
    r138_set_automatic_activation(w, false);
    let e = err(r136_bind(w, &g.binding_id, &format!("{tag}-b1")).await);
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    assert_eq!(adapter.calls(), 1, "local denial is round 1");
    let reported = r139_withdrawals(w, &g.grant_id);
    assert_eq!(reported.len(), 1);
    assert_eq!(
        reported[0]["remote_pending"],
        serde_json::json!([g.grant_id.clone()])
    );
    g
}

/// Red. A pending remote effect gets its `revoke()` rounds exactly at the jittered
/// bounded schedule: never in the pass that first sees it, never before a round is
/// due, one round when it is due; it stops at the cap (8 rounds, the first local
/// denial included), after which no pass and no restart calls the adapter again,
/// and no round adds an event. The grant stays `revoking` with its remote part
/// visible. An explicit owner `revoke` then calls again (here the adapter reports
/// done) and completes it.
#[tokio::test]
async fn r1310_3_a_pending_remote_effect_is_retried_on_the_jittered_schedule_up_to_the_cap() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1310-3a").await;
    let events_after_report = w.events().len();
    let sup = r1310_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "the first pass only schedules round 2");
    for n in 1..8u32 {
        let delay = r1310_delay(n);
        w.clock.advance(delay - Duration::from_millis(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(
            adapter.calls(),
            n as usize,
            "round {} is not due yet",
            n + 1
        );
        w.clock.advance(Duration::from_millis(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(adapter.calls(), n as usize + 1, "round {} is due", n + 1);
        sup.scheduler_pass().await.unwrap();
        assert_eq!(adapter.calls(), n as usize + 1, "one round per due instant");
    }
    for _ in 0..4 {
        w.clock.advance(10 * MINUTE);
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(adapter.calls(), 8, "capped at 8 rounds");
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    let view = r1310_view(&w, &g.grant_id).await;
    assert_eq!(view["state"], "revoking");
    assert_eq!(
        view["remote_pending"], true,
        "the pending remote part stays visible"
    );
    assert_eq!(view["remote_retries"]["attempts"], 8);
    assert_eq!(view["remote_retries"]["stopped"], true);
    assert_eq!(
        w.events().len(),
        events_after_report,
        "no round, cap or pass emitted a notification"
    );
    // A restart is no owner action: startup and later passes call nothing.
    r1310_restart_pending(&mut w, &adapter).await;
    let sup = r1310_supervisor(&w);
    for _ in 0..3 {
        w.clock.advance(10 * MINUTE);
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(adapter.calls(), 8, "a restart never resets the cap");
    // An explicit owner action calls again; the adapter now reports done.
    adapter.pending.store(false, Ordering::SeqCst);
    let done = ok(w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: g.grant_id.clone(),
                request_id: RequestId::parse("r1310-3a-revoke").unwrap(),
            },
        )
        .await);
    assert!(done.data.remote_pending.is_empty());
    assert_eq!(adapter.calls(), 9);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1, "reported once");
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 9);
}

/// Red. Completion when the adapter later reports done: the round that is due
/// after the remote effect cleared moves the grant to `revoked` (one state change,
/// no second report), and nothing is called afterwards.
#[tokio::test]
async fn r1310_3_a_pending_remote_effect_completes_when_the_adapter_later_reports_done() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1310-3b").await;
    let sup = r1310_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(r1310_delay(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "round 2, still pending");
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    adapter.pending.store(false, Ordering::SeqCst);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "round 3 is not due yet");
    w.clock.advance(r1310_delay(2));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 3);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1, "reported once");
    let revoked: Vec<_> = r1310_states(&w, &g.grant_id)
        .into_iter()
        .filter(|p| p["state"] == "revoked")
        .collect();
    assert_eq!(revoked.len(), 1);
    for _ in 0..3 {
        w.clock.advance(10 * MINUTE);
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(adapter.calls(), 3);
}

/// Red. An explicit revoke whose operation settled with a remote effect pending
/// (its result names it) is retried on the same bounded schedule: an immediate
/// pass calls nothing; the due round does.
#[tokio::test]
async fn r1310_3_a_settled_explicit_revoke_left_pending_is_retried_only_when_due() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1310-3c", "r1310-3c-work", "h1", "1h").await;
    let done = ok(w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: g.grant_id.clone(),
                request_id: RequestId::parse("r1310-3c-revoke").unwrap(),
            },
        )
        .await);
    assert_eq!(done.data.remote_pending, vec![g.grant_id.clone()]);
    assert_eq!(adapter.calls(), 1);
    let sup = r1310_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "no round in every pass");
    w.clock.advance(r1310_delay(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
}

/// The revocation backoff is injectable (`Supervisor::with_revocation_backoff`):
/// with base 10 s, cap 15 s and 3 rounds (unit 0.5), round 2 is scheduled 7.5 s
/// after the pass that first saw round 1 (and the scheduler pass's next wake is
/// that instant), round 3 11.25 s after round 2, and the record then stops: no
/// further round is scheduled or run. (Uses the new API, so it cannot run at the
/// base commit; its red evidence is the mutation check recorded with the task.)
#[tokio::test]
async fn r1310_3_the_revocation_backoff_is_injectable_and_caps_the_rounds() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1310-3d").await;
    let sup = r1310_supervisor(&w).with_revocation_backoff(heimdall_app::reconcile::Backoff {
        base: Duration::from_secs(10),
        max: Duration::from_secs(15),
        max_attempts: 3,
    });
    let at = |d: Duration| {
        w.clock
            .wall()
            .checked_add(jiff::SignedDuration::try_from(d).unwrap())
            .unwrap()
    };
    let expected_wake = at(Duration::from_millis(7_500));
    assert_eq!(
        sup.scheduler_pass().await.unwrap(),
        Some(expected_wake),
        "the next wake is the scheduled round"
    );
    assert_eq!(adapter.calls(), 1);
    w.clock.advance(Duration::from_millis(7_500));
    let report = sup.revocation_pass().await.unwrap();
    assert_eq!(report.retried, vec![(g.grant_id.clone(), 2)]);
    assert_eq!(
        report.scheduled,
        vec![(g.grant_id.clone(), 2, Duration::from_millis(11_250))]
    );
    assert_eq!(report.next_due_in, Some(Duration::from_millis(11_250)));
    w.clock.advance(Duration::from_millis(11_250));
    let report = sup.revocation_pass().await.unwrap();
    assert_eq!(report.retried, vec![(g.grant_id.clone(), 3)]);
    assert_eq!(report.stopped, vec![g.grant_id.clone()]);
    assert!(report.scheduled.is_empty());
    assert_eq!(report.next_due_in, None);
    assert_eq!(adapter.calls(), 3);
    for _ in 0..3 {
        w.clock.advance(10 * MINUTE);
        let r = sup.revocation_pass().await.unwrap();
        assert!(r.retried.is_empty() && r.scheduled.is_empty());
    }
    assert_eq!(adapter.calls(), 3);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
}

/// ⟨r2.7⟩ ADR-0006 §13.10 item 3 as a property (proptest, 256 cases, fixed seed
/// unless `PROPTEST_RNG_SEED` is set; failures persist to
/// `tests/model/operations.proptest-regressions`).
mod r1310_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    fn config(seed: u64) -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(seed);
        }
        c
    }

    fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
        f: F,
    ) -> Result<(), TestCaseError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    proptest! {
        #![proptest_config(config(0x1310_0003))]

        /// For any jitter unit, base delay and cap, a pending remote effect gets
        /// round `n + 1` exactly `min(base·2^(n-1), max)·(0.5 + 0.5·unit)` after
        /// round `n` was scheduled (never a millisecond earlier), exactly `cap`
        /// rounds in all (the first local denial included), and no round or pass
        /// adds an event.
        #[test]
        fn r1310_3_rounds_follow_the_jittered_capped_schedule(
            unit in 0.0f64..=1.0,
            base_ms in 10u64..20_000,
            cap in 1u32..6,
        ) {
            block(async move {
                let (w, adapter) = r1310_pending_world().await;
                let _g = r1310_withdrawn_pending(&w, &adapter, "r1310-p").await;
                let events = w.events().len();
                let base = Duration::from_millis(base_ms);
                let max = base * 8;
                let sup = r138_supervisor(&w)
                    .with_jitter(Arc::new(heimdall_runtime::supervisor::FixedJitter(unit)))
                    .with_revocation_backoff(heimdall_app::reconcile::Backoff {
                        base,
                        max,
                        max_attempts: cap,
                    });
                sup.scheduler_pass().await.unwrap();
                prop_assert_eq!(adapter.calls(), 1);
                for n in 1..cap {
                    let full = (base * (1u32 << (n - 1))).min(max);
                    let delay = full.mul_f64(0.5 + 0.5 * unit);
                    w.clock.advance(delay - Duration::from_millis(1));
                    sup.scheduler_pass().await.unwrap();
                    prop_assert_eq!(adapter.calls(), n as usize, "early");
                    w.clock.advance(Duration::from_millis(1));
                    sup.scheduler_pass().await.unwrap();
                    prop_assert_eq!(adapter.calls(), n as usize + 1, "due");
                }
                for _ in 0..3 {
                    w.clock.advance(5 * MINUTE);
                    sup.scheduler_pass().await.unwrap();
                }
                prop_assert_eq!(adapter.calls(), cap as usize, "capped");
                prop_assert_eq!(w.events().len(), events, "no notification");
                Ok(())
            })?;
        }
    }
}

// =================================================================================
// ⟨r2.9⟩ ADR-0006 §13.12 (M01-review4-T01-T02; review round 4 T01 and T02).
//
// T01: a remote-revocation round is claimed durably, in its own committed
// transaction, before any adapter is called (the attempt is counted and
// `claimed_at` recorded). A claimed round that never completed (a failed completion
// commit, or a crash between the adapter call and the completion) counts, so no
// sequence of failures yields more adapter calls than the cap.
//
// T02: the pending record keeps each unresolved obligation per responsible adapter
// (its `AdapterIdentity` from the recovery intent and receipts). A round calls only
// that adapter and only its confirmation clears the obligation. With it not
// configured the obligation stays pending and visible (`adapter_unavailable`), the
// round consumes no attempt and the schedule still backs off; once it is configured
// again rounds resume, and the grant leaves `revoking` only when every obligation
// has cleared. Another adapter's answer, or an empty adapter list, never clears one.
//
// Only public APIs are used, so every case also runs against the base commit
// ca21d621 (red there). "Crash" and "restart" are in-process (module docs).
// =================================================================================

/// The pending remote record of `root`, if any.
fn r1312_record(
    w: &World,
    root: &heimdall_contract::ids::GrantId,
) -> Option<heimdall_domain::revocation::PendingRemoteRevocation> {
    w.store
        .transaction(|tx| tx.remote_revocation(root))
        .unwrap()
}

/// The supervisor over this world with a revocation cap of `cap` rounds (the first
/// local denial included; base 1 s, at most 8 s, unjittered).
fn r1312_supervisor(w: &World, cap: u32) -> heimdall_runtime::supervisor::Supervisor {
    r138_supervisor(w)
        .with_jitter(Arc::new(heimdall_runtime::supervisor::FixedJitter(1.0)))
        .with_revocation_backoff(heimdall_app::reconcile::Backoff {
            base: Duration::from_secs(1),
            max: Duration::from_secs(8),
            max_attempts: cap,
        })
}

/// A fake for another mechanism whose `revoke` calls stay inspectable: with only it
/// configured, the fixture grants' responsible adapter is gone.
fn r1312_other_adapter() -> Arc<FakeCredentialAdapter> {
    let mut d = descriptor();
    d.identity = AdapterIdentity {
        mechanism: "fake_other".into(),
        instance: "fixture-2".into(),
    };
    FakeCredentialAdapter::new(d, vec![FakeStep::Prepare(outcome())])
}

/// In-process restart with exactly `adapters` configured.
async fn r1312_restart_with(w: &mut World, adapters: Vec<Arc<dyn CredentialAdapter>>) {
    w.ops = Operations::start(OperationsConfig {
        adapters,
        ..w.config()
    })
    .await
    .unwrap();
}

/// Drive `fut` until it finishes (`false`) or `adapter` enters a hanging `revoke`
/// (`true`): the future is then dropped there, after the adapter call and before
/// its completion, as a crash would leave it.
async fn r1312_until_crash<F: std::future::Future>(adapter: &PendingCounter, fut: F) -> bool {
    tokio::select! {
        biased;
        () = adapter.entered.notified() => true,
        _ = fut => false,
    }
}

/// `revoking` with its remote part visible and pending on the original adapter
/// with reason `adapter_unavailable`, `attempts` rounds counted.
async fn r1312_assert_waiting_for_adapter(
    w: &World,
    grant: &heimdall_contract::ids::GrantId,
    attempts: u32,
) {
    assert_eq!(
        w.grant(grant).state,
        GrantState::Revoking,
        "no state change"
    );
    let rec = r1312_record(w, grant).expect("the pending record is kept");
    assert_eq!(rec.grants, vec![grant.clone()]);
    assert_eq!(
        rec.attempts, attempts,
        "a round with no call consumes no attempt"
    );
    assert!(!rec.stopped);
    let view = r1310_view(w, grant).await;
    assert_eq!(view["state"], "revoking");
    assert_eq!(view["remote_pending"], true);
    assert_eq!(
        view["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"]),
        "the obligation stays visible with its reason: {view}"
    );
    assert_eq!(view["remote_retries"]["attempts"], attempts);
    assert!(
        r1310_states(w, grant)
            .iter()
            .all(|p| p["state"] != "revoked"),
        "never revoked"
    );
}

/// Red (T01, the reviewer's probe). Every round's completion commit fails (the
/// adapter arms a `BeforeCommit` store fault inside each `revoke`). With a cap of 2
/// rounds (the first local denial is round 1), the production supervisor calls the
/// adapter at most twice however many passes run; the durable count reaches the
/// cap and the record is then stopped, still visible; the grant stays `revoking`.
#[tokio::test]
async fn r1312_1_failed_completion_commits_never_allow_more_adapter_calls_than_the_cap() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1312-1a").await;
    assert_eq!(r1312_record(&w, &g.grant_id).unwrap().attempts, 1);
    *adapter.faults.lock().unwrap() = Some(faults.clone());
    let cap = 2;
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..8 {
        let _ = sup.scheduler_pass().await;
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let _ = sup.scheduler_pass().await;
    *adapter.faults.lock().unwrap() = None;
    faults.armed.store(false, Ordering::SeqCst);
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert!(
        adapter.calls() <= cap as usize,
        "calls={} durable_attempts={} cap={cap} faults={}",
        adapter.calls(),
        rec.attempts,
        faults.fired.load(Ordering::SeqCst)
    );
    assert_eq!(rec.attempts, cap, "the claimed round counts");
    assert!(rec.stopped, "stopped at the cap");
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    assert_eq!(r1310_view(&w, &g.grant_id).await["remote_pending"], true);
    // Nothing calls again afterwards, faults or not.
    for _ in 0..3 {
        w.clock.advance(MINUTE);
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(adapter.calls(), cap as usize);
}

/// Red (T01, interruption). A crash between the adapter call and its completion,
/// repeated after every restart: with a cap of 2 rounds the adapter is called at
/// most twice in all; the interrupted round counted durably.
#[tokio::test]
async fn r1312_1_a_crash_between_the_adapter_call_and_its_completion_counts_the_round() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1312-1b").await;
    let cap = 2;
    let mut crashes = 0;
    for _ in 0..4 {
        let sup = r1312_supervisor(&w, cap);
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
        adapter.hang.store(true, Ordering::SeqCst);
        if r1312_until_crash(&adapter, sup.scheduler_pass()).await {
            crashes += 1;
        }
        adapter.hang.store(false, Ordering::SeqCst);
        r1310_restart_pending(&mut w, &adapter).await;
    }
    assert!(crashes >= 1, "the crash point was reached");
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert!(
        adapter.calls() <= cap as usize,
        "calls={} durable_attempts={} cap={cap} crashes={crashes}",
        adapter.calls(),
        rec.attempts
    );
    assert_eq!(rec.attempts, cap);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
}

/// Red (T01, an explicit revoke). The revoke's first local denial is interrupted
/// after the adapter call; restart recovery settles the operation without calling
/// the adapter again (the claimed round counts) and reports the grant as pending;
/// later rounds come only from the supervisor (⟨r2.10⟩ §13.13 item 4: the first
/// pass after the restart runs the interrupted round's successor at once).
#[tokio::test]
async fn r1312_1_an_interrupted_explicit_revoke_is_not_called_again_by_recovery() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1312-1c", "r1312-1c-work", "h1", "1h").await;
    adapter.hang.store(true, Ordering::SeqCst);
    let owner = unattended(501);
    let revoke = w.ops.revoke(
        &owner,
        RevokeRequest {
            grant_id: g.grant_id.clone(),
            request_id: RequestId::parse("r1312-1c-revoke").unwrap(),
        },
    );
    assert!(
        r1312_until_crash(&adapter, revoke).await,
        "crashed after the call"
    );
    assert_eq!(adapter.calls(), 1);
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(
        adapter.calls(),
        1,
        "recovery does not call the adapter again"
    );
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    let rec = r1312_record(&w, &g.grant_id).expect("pending");
    assert_eq!(rec.attempts, 1, "the interrupted round counted");
    let done = ok(w
        .ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: g.grant_id.clone(),
                request_id: RequestId::parse("r1312-1c-revoke").unwrap(),
            },
        )
        .await);
    assert_eq!(done.data.remote_pending, vec![g.grant_id.clone()]);
    assert_eq!(adapter.calls(), 1, "a same-key replay calls nothing");
    adapter.pending.store(false, Ordering::SeqCst);
    // ⟨r2.10⟩ ADR-0006 §13.13 item 4: the claimed round never completed, so the
    // first supervisor pass after the restart runs the next round at once (it was
    // "only schedules" before §13.13); the interrupted round still counted.
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "the interrupted round is due at once");
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "nothing is called again");
}

/// Red (T02, the reviewer's probe). A pending withdrawal on the fixture adapter; a
/// restart with only another mechanism's adapter configured; later rounds never
/// ask that other adapter and never complete the revocation: the obligation stays
/// pending and visible (`adapter_unavailable`), no attempt is consumed, no state
/// changes. Restoring the original adapter resumes the rounds; its confirmation
/// clears the obligation and only then is the grant `revoked`.
#[tokio::test]
async fn r1312_2_removing_the_original_adapter_never_completes_its_pending_revocation() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1312-2a").await;
    let other = r1312_other_adapter();
    r1312_restart_with(&mut w, vec![other.clone() as Arc<dyn CredentialAdapter>]).await;
    let sup = r1312_supervisor(&w, 8);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "original_adapter_calls");
    assert!(
        !other.revocations.lock().unwrap().contains(&g.grant_id),
        "another adapter is never asked about this obligation"
    );
    r1312_assert_waiting_for_adapter(&w, &g.grant_id, 1).await;
    // A restart with the original adapter (now reporting done) resumes the rounds.
    adapter.pending.store(false, Ordering::SeqCst);
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "the original adapter is asked again");
    assert_eq!(adapter.confirmations(), 1);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1, "reported once");
}

/// Red (T02). The same with no adapter configured at all: an empty adapter list
/// never clears the obligation.
#[tokio::test]
async fn r1312_2_an_empty_adapter_list_never_completes_a_pending_revocation() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1312-2b").await;
    r1312_restart_with(&mut w, Vec::new()).await;
    let sup = r1312_supervisor(&w, 8);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(adapter.calls(), 1);
    r1312_assert_waiting_for_adapter(&w, &g.grant_id, 1).await;
    adapter.pending.store(false, Ordering::SeqCst);
    r1310_restart_pending(&mut w, &adapter).await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
}

/// Red (T02). A withdrawal found while the grant's own adapter is not configured
/// (the grant is `degraded` for `mechanism_unavailable`): local denial could not
/// reach that adapter, so the obligation is pending from the start (another
/// adapter is not asked) and the grant stays `revoking` with
/// `adapter_unavailable`; once the adapter is configured again its confirmation
/// completes the revocation.
#[tokio::test]
async fn r1312_2_a_withdrawal_while_the_responsible_adapter_is_missing_waits_for_it() {
    let (mut w, adapter) = r1310_pending_world().await;
    adapter.pending.store(false, Ordering::SeqCst);
    let g = r136_ready(&w, "r1312-2c", "r1312-2c-work", "h1", "1h").await;
    let other = r1312_other_adapter();
    r1312_restart_with(&mut w, vec![other.clone() as Arc<dyn CredentialAdapter>]).await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    r1310_assert_degraded(&w, &g, "r1312-2c-work").await;
    r138_set_policy_hosts(&w, &["h2"]);
    sup.scheduler_pass().await.unwrap();
    for _ in 0..4 {
        w.clock.advance(10 * Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
    }
    assert!(!other.revocations.lock().unwrap().contains(&g.grant_id));
    assert_eq!(adapter.calls(), 0);
    let t = r138_tombstone(&w, &g.grant_id).expect("a tombstone");
    assert_eq!(t["cause"], "authority_withdrawn");
    let reported = r139_withdrawals(&w, &g.grant_id);
    assert_eq!(reported.len(), 1, "the withdrawal is reported once");
    assert_eq!(
        reported[0]["remote_pending"],
        serde_json::json!([g.grant_id.clone()])
    );
    r1312_assert_waiting_for_adapter(&w, &g.grant_id, 0).await;
    r1310_restart_pending(&mut w, &adapter).await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert_eq!(r139_withdrawals(&w, &g.grant_id).len(), 1);
}

/// Red (T02, a record written before obligations existed). A record with only its
/// grant list (the pre-§13.12 shape) is read with the grant's responsible adapter
/// from its recovery intent: another adapter's answer does not clear it, the
/// original adapter's does.
#[tokio::test]
async fn r1312_2_a_record_written_before_obligations_keeps_its_responsible_adapter() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1312-2d").await;
    let legacy: heimdall_domain::revocation::PendingRemoteRevocation =
        serde_json::from_value(serde_json::json!({
            "root": g.grant_id,
            "grants": [g.grant_id],
            "attempts": 1,
            "last_attempt_at": t0(),
            "stopped": false,
        }))
        .unwrap();
    w.store
        .transaction(|tx| tx.set_remote_revocation(&legacy))
        .unwrap();
    let other = r1312_other_adapter();
    r1312_restart_with(&mut w, vec![other.clone() as Arc<dyn CredentialAdapter>]).await;
    let sup = r1312_supervisor(&w, 8);
    for _ in 0..4 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert!(!other.revocations.lock().unwrap().contains(&g.grant_id));
    r1312_assert_waiting_for_adapter(&w, &g.grant_id, 1).await;
    adapter.pending.store(false, Ordering::SeqCst);
    r1310_restart_pending(&mut w, &adapter).await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
}

/// ⟨r2.9⟩ ADR-0006 §13.12 as a property (proptest, 256 cases, fixed seed unless
/// `PROPTEST_RNG_SEED` is set; failures persist to
/// `tests/model/operations.proptest-regressions`).
mod r1312_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    fn config(seed: u64) -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(seed);
        }
        c
    }

    fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
        f: F,
    ) -> Result<(), TestCaseError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// One step of a sequence. Every round-driving step runs a pass (which may only
    /// schedule), advances past the longest delay and runs the pass that is due.
    ///
    /// ⟨r2.10⟩ ADR-0006 §13.13: the tree has two obligations, the parent's on the
    /// original adapter A and its delegated child's on adapter B, so the adapter
    /// steps add and remove each of them; `Stall` interrupts a round after its
    /// claim and before the call.
    #[derive(Debug, Clone, Copy)]
    enum Step {
        /// A due round.
        Round,
        /// A due round whose completion commit fails.
        FailCompletion,
        /// A due round interrupted after the adapter call; then a restart.
        Crash,
        /// ⟨r2.10⟩ A due round interrupted after its claim, before the call; then a
        /// restart.
        Stall,
        /// Restart with only another mechanism's adapter.
        RemoveAdapter,
        /// Restart with no adapter.
        NoAdapters,
        /// Restart with the original adapter A only.
        RestoreAdapter,
        /// ⟨r2.10⟩ Restart with adapter B only.
        OnlyB,
        /// ⟨r2.10⟩ Restart with both A and B.
        Both,
        /// The original adapter now reports done (`true`) or pending (`false`).
        Done(bool),
        /// ⟨r2.10⟩ Adapter B now reports done (`true`) or pending (`false`).
        DoneB(bool),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            3 => Just(Step::Round),
            2 => Just(Step::FailCompletion),
            2 => Just(Step::Crash),
            2 => Just(Step::Stall),
            1 => Just(Step::RemoveAdapter),
            1 => Just(Step::NoAdapters),
            2 => Just(Step::RestoreAdapter),
            2 => Just(Step::OnlyB),
            2 => Just(Step::Both),
            2 => any::<bool>().prop_map(Step::Done),
            2 => any::<bool>().prop_map(Step::DoneB),
        ]
    }

    /// Drive `fut` until it finishes (`false`) or `a` or `b` enters a hanging or
    /// stalled `revoke` (`true`; the future is dropped there).
    async fn until_either<F: std::future::Future>(
        a: &PendingCounter,
        b: &PendingCounter,
        fut: F,
    ) -> bool {
        tokio::select! {
            biased;
            () = a.entered.notified() => true,
            () = b.entered.notified() => true,
            _ = fut => false,
        }
    }

    /// The obligation of `grant` in `record`, with its counted attempts.
    fn owed(
        record: &heimdall_domain::revocation::PendingRemoteRevocation,
        grant: &heimdall_contract::ids::GrantId,
    ) -> Option<u32> {
        record
            .obligations
            .iter()
            .find(|o| &o.grant == grant)
            .map(|o| record.obligation_attempts(o))
    }

    proptest! {
        #![proptest_config(config(0x1312_0001))]

        /// For any sequence of rounds, completion faults, crashes before and after
        /// the call and adapter removal or restoration (cap 2 to 4 rounds per
        /// obligation, the first local denial included), over a withdrawn parent
        /// whose obligation is the original adapter A's and its delegated child
        /// whose obligation is adapter B's:
        /// * each adapter is called at most `cap` times (⟨r2.10⟩ the cap is per
        ///   obligation, §13.13 item 3), and an obligation's counted attempts never
        ///   exceed the cap nor fall below its adapter's calls;
        /// * an obligation is never cleared (the grant `revoked`) unless its own
        ///   adapter confirmed; another mechanism's adapter is never asked;
        /// * while a grant is `revoking` its obligation stays in the record, and the
        ///   record is stopped only when every obligation reached its cap;
        /// * finally, with both adapters configured again and reporting done, every
        ///   obligation either clears or had reached its own cap: one adapter's
        ///   rounds never exhausted the other's obligation.
        #[test]
        fn r1312_calls_stay_within_the_cap_and_only_the_adapter_clears_its_obligation(
            cap in 2u32..5,
            steps in proptest::collection::vec(step(), 1..14),
        ) {
            block(async move {
                let faults = Armed::new(FaultPoint::BeforeCommit);
                let (mut w, a) = r1312_pending_world_with(Setup {
                    faults: faults.clone(),
                    ..Setup::default()
                })
                .await;
                let b = r1313_instance("fixture-2");
                let (parent, child) = r1313_tree(&mut w, &a, &b, "r1312-p").await;
                let (pg, cg) = (parent.grant_id.clone(), child.grant_id.clone());
                // Withdrawal of the parent (its child in the cascade): round 1
                // reaches both adapters.
                r138_set_automatic_activation(&w, false);
                let e = err(r136_bind(&w, &parent.binding_id, "r1312-p-b1").await);
                prop_assert_eq!(e.code, Code::CredentialExpired);
                prop_assert_eq!(w.grant(&pg).state, GrantState::Revoking);
                prop_assert_eq!(w.grant(&cg).state, GrantState::Revoking);
                prop_assert_eq!((a.calls(), b.calls()), (1, 1));
                let other = r1312_other_adapter();
                let (ad, bd) = (
                    a.clone() as Arc<dyn CredentialAdapter>,
                    b.clone() as Arc<dyn CredentialAdapter>,
                );
                let mut current = vec![bd.clone(), ad.clone()];
                let mut sup = r1312_supervisor(&w, cap);
                for s in steps {
                    let restart_with = match s {
                        Step::RemoveAdapter => Some(vec![other.clone() as Arc<dyn CredentialAdapter>]),
                        Step::NoAdapters => Some(Vec::new()),
                        Step::RestoreAdapter => Some(vec![ad.clone()]),
                        Step::OnlyB => Some(vec![bd.clone()]),
                        Step::Both => Some(vec![ad.clone(), bd.clone()]),
                        _ => None,
                    };
                    match s {
                        Step::Round | Step::FailCompletion | Step::Crash | Step::Stall => {
                            let _ = sup.scheduler_pass().await;
                            w.clock.advance(10 * Duration::from_secs(1));
                            for x in [&a, &b] {
                                match s {
                                    Step::FailCompletion => {
                                        *x.faults.lock().unwrap() = Some(faults.clone());
                                    }
                                    Step::Crash => x.hang.store(true, Ordering::SeqCst),
                                    Step::Stall => x.stall.store(true, Ordering::SeqCst),
                                    _ => {}
                                }
                            }
                            let crashed = until_either(&a, &b, sup.scheduler_pass()).await;
                            for x in [&a, &b] {
                                *x.faults.lock().unwrap() = None;
                                x.hang.store(false, Ordering::SeqCst);
                                x.stall.store(false, Ordering::SeqCst);
                            }
                            faults.armed.store(false, Ordering::SeqCst);
                            if crashed {
                                r1312_restart_with(&mut w, current.clone()).await;
                                sup = r1312_supervisor(&w, cap);
                            }
                        }
                        Step::Done(done) => a.pending.store(!done, Ordering::SeqCst),
                        Step::DoneB(done) => b.pending.store(!done, Ordering::SeqCst),
                        _ => {}
                    }
                    if let Some(adapters) = restart_with {
                        current = adapters;
                        r1312_restart_with(&mut w, current.clone()).await;
                        sup = r1312_supervisor(&w, cap);
                    }
                    let record = r1312_record(&w, &pg);
                    prop_assert!(
                        a.calls() <= cap as usize && b.calls() <= cap as usize,
                        "calls a={} b={} > cap {cap} (record {:?})", a.calls(), b.calls(), record
                    );
                    let asked = other.revocations.lock().unwrap().clone();
                    prop_assert!(
                        !asked.contains(&pg) && !asked.contains(&cg),
                        "another mechanism's adapter was asked"
                    );
                    for (g, x) in [(&pg, &a), (&cg, &b)] {
                        match w.grant(g).state {
                            GrantState::Revoked => prop_assert!(
                                x.confirmations() > 0,
                                "cleared without its adapter's confirmation"
                            ),
                            state => {
                                prop_assert_eq!(state, GrantState::Revoking);
                                let r = record.as_ref().expect("a revoking grant keeps its record");
                                let n = owed(r, g).expect("a revoking grant keeps its obligation");
                                prop_assert!(n <= cap, "attempts {n} > cap {cap}");
                                prop_assert!(n as usize >= x.calls(), "attempts {n} < calls {}", x.calls());
                            }
                        }
                    }
                    if let Some(r) = &record {
                        prop_assert!(!r.stopped || r.capped(cap), "stopped before every cap: {r:?}");
                    }
                }
                // Both adapters configured again and done: every obligation clears
                // unless it had reached its own cap.
                a.pending.store(false, Ordering::SeqCst);
                b.pending.store(false, Ordering::SeqCst);
                r1312_restart_with(&mut w, vec![ad.clone(), bd.clone()]).await;
                let sup = r1312_supervisor(&w, cap);
                for _ in 0..(cap + 3) {
                    sup.scheduler_pass().await.unwrap();
                    w.clock.advance(10 * Duration::from_secs(1));
                }
                let record = r1312_record(&w, &pg);
                for (g, x) in [(&pg, &a), (&cg, &b)] {
                    if w.grant(g).state != GrantState::Revoked {
                        let r = record.as_ref().expect("still pending");
                        prop_assert_eq!(
                            owed(r, g),
                            Some(cap),
                            "an obligation neither cleared nor capped by its own rounds: {:?}", r
                        );
                        prop_assert!(x.calls() <= cap as usize);
                    }
                }
                Ok(())
            })?;
        }
    }
}

// =================================================================================
// ⟨r2.10⟩ ADR-0006 §13.13 (M01-rulings-13-13).
//
// Item 1: the adapter that prepared a grant (mechanism and instance) is persisted
// with the grant when its first `Attempted` receipt is recorded, so operation
// retention cannot remove it; the mechanism-only fallback is for grants written
// before the field existed.
// Item 2: every pending answer of a responsible adapter is tracked as an obligation,
// whatever the grant's state (a grant revoked while `preparing` included); no
// untracked one-off call.
// Item 3: attempts and the cap are counted per (grant, adapter) obligation; one
// adapter's rounds never exhaust another's obligation; the record stops only when
// every obligation has cleared or reached its cap.
// Item 4: at startup a claimed but uncompleted round is due at once (it still
// counts as attempted).
//
// The standalone cases use only public APIs that exist at the base commit d64503f5,
// so they run (red) there. "Crash" and "restart" are in-process (module docs).
// =================================================================================

/// A [`PendingCounter`] over a fresh fake whose identity is `fake_agent/<instance>`:
/// the fixture adapter's mechanism, another instance.
fn r1313_instance(instance: &str) -> Arc<PendingCounter> {
    let mut d = descriptor();
    d.identity.instance = instance.into();
    PendingCounter::new(FakeCredentialAdapter::new(
        d,
        vec![FakeStep::Prepare(outcome())],
    ))
}

/// An explicit owner revoke of `grant`; its result data.
async fn r1313_revoke(
    w: &World,
    grant: &heimdall_contract::ids::GrantId,
    rid: &str,
) -> heimdall_contract::request::RevokeData {
    ok(w.ops
        .revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: grant.clone(),
                request_id: RequestId::parse(rid).unwrap(),
            },
        )
        .await)
    .data
}

/// The grant `op` pinned in its recovery intent.
fn r1313_grant_of(w: &World, op: &OperationId) -> heimdall_contract::ids::GrantId {
    w.store
        .transaction(|tx| tx.recovery_intent(op))
        .unwrap()
        .unwrap()
        .resolved
        .unwrap()
        .grant
        .unwrap()
}

/// A parent prepared by `a` (the world's only adapter), then, after a restart with
/// `b` first and `a`, a delegated child prepared by `b`: two grants of one tree
/// whose responsible adapters differ.
async fn r1313_tree(
    w: &mut World,
    a: &Arc<PendingCounter>,
    b: &Arc<PendingCounter>,
    tag: &str,
) -> (EnsureData, EnsureData) {
    let parent = r136_ready(w, tag, &format!("{tag}-work"), "h1", "1h").await;
    r1312_restart_with(
        w,
        vec![
            b.clone() as Arc<dyn CredentialAdapter>,
            a.clone() as Arc<dyn CredentialAdapter>,
        ],
    )
    .await;
    let child = ok(w
        .ops
        .delegate(
            &unattended(501),
            u10_delegate(&parent, &format!("{tag}-c"), "30m"),
        )
        .await)
    .data;
    let adapters = |g: &heimdall_contract::ids::GrantId| {
        w.store.transaction(|tx| tx.grant_adapters(g)).unwrap()
    };
    assert_eq!(
        adapters(&parent.grant_id),
        vec![a.descriptor().identity.clone()]
    );
    assert_eq!(
        adapters(&child.grant_id),
        vec![b.descriptor().identity.clone()]
    );
    (parent, child)
}

/// Red (§13.13 item 1). After operation retention purged every recovery intent and
/// stage receipt that named the grant's adapter, an explicit revoke still owes its
/// confirmation to exactly the adapter that prepared the grant (mechanism **and**
/// instance): another instance of the same mechanism is never asked and clears
/// nothing, the obligation waits (`adapter_unavailable`, no attempt consumed), and
/// the original instance's confirmation completes the revocation.
#[tokio::test]
async fn r1313_1_the_preparing_adapter_stays_responsible_after_operation_retention() {
    let (mut w, adapter) = r1310_pending_world().await;
    adapter.pending.store(false, Ordering::SeqCst);
    let g = r136_ready(&w, "r1313-1", "r1313-1-work", "h1", "1h").await;
    let purged = w
        .store
        .transaction(|tx| tx.purge_operations_before(shift(t0(), 60 * 86_400)))
        .unwrap();
    assert!(purged >= 1, "the settled ensure was purged");
    assert!(
        w.store
            .transaction(|tx| tx.grant_adapters(&g.grant_id))
            .unwrap()
            .is_empty(),
        "no intent or receipt names the adapter any more"
    );
    let sibling = r1313_instance("fixture-9");
    sibling.pending.store(false, Ordering::SeqCst);
    r1312_restart_with(&mut w, vec![sibling.clone() as Arc<dyn CredentialAdapter>]).await;
    let done = r1313_revoke(&w, &g.grant_id, "r1313-1-revoke").await;
    assert_eq!(sibling.calls(), 0, "another instance is never asked");
    assert_eq!(done.remote_pending, vec![g.grant_id.clone()]);
    let rec = r1312_record(&w, &g.grant_id).expect("pending on the preparing adapter");
    assert_eq!(rec.obligations.len(), 1);
    assert_eq!(rec.obligations[0].adapter, descriptor().identity);
    r1312_assert_waiting_for_adapter(&w, &g.grant_id, 0).await;
    // The preparing instance is configured again (next to the sibling): its
    // confirmation, and only its, completes the revocation.
    r1312_restart_with(
        &mut w,
        vec![
            sibling.clone() as Arc<dyn CredentialAdapter>,
            adapter.clone() as Arc<dyn CredentialAdapter>,
        ],
    )
    .await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!((adapter.calls(), sibling.calls()), (1, 0));
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
}

/// Red (§13.13 item 2). A grant revoked while `preparing` (its preparation's
/// `Attempted` receipt is on record, the operation still running) goes `preparing →
/// revoked`; its adapter's local denial reports a remote effect pending. That answer
/// is tracked: the record holds the obligation, the revoke's result and the inspect
/// view (the grant stays listed although terminal) name it pending, and the
/// supervisor retries it on its bounded schedule until the adapter confirms; then
/// the record is gone and nothing is called again.
#[tokio::test]
async fn r1313_2_a_grant_revoked_while_preparing_is_tracked_until_its_adapter_confirms() {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let (w, adapter) = r1312_pending_world_with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1313-2", "r1313-2-work", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.effect_status, EffectStatus::Partial);
    let gid = r1313_grant_of(&w, e.operation_id.as_ref().unwrap());
    assert_eq!(w.grant(&gid).state, GrantState::Preparing);
    let done = r1313_revoke(&w, &gid, "r1313-2-revoke").await;
    assert_eq!(
        w.grant(&gid).state,
        GrantState::Revoked,
        "preparing → revoked"
    );
    assert_eq!(
        adapter.calls(),
        1,
        "local denial asked the responsible adapter"
    );
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    let rec = r1312_record(&w, &gid).expect("the pending answer is tracked");
    assert_eq!(rec.grants, vec![gid.clone()]);
    assert_eq!(rec.obligations.len(), 1);
    assert_eq!(rec.obligations[0].adapter, descriptor().identity);
    let view = r1310_view(&w, &gid).await;
    assert_eq!(view["state"], "revoked");
    assert_eq!(
        view["remote_pending"], true,
        "the pending remote part is visible"
    );
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "the first pass only schedules");
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "retried when due");
    assert!(r1312_record(&w, &gid).is_some(), "still pending");
    adapter.pending.store(false, Ordering::SeqCst);
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 3);
    assert_eq!(adapter.confirmations(), 1);
    assert!(
        r1312_record(&w, &gid).is_none(),
        "cleared by the confirmation"
    );
    assert_eq!(w.grant(&gid).state, GrantState::Revoked);
    for _ in 0..3 {
        w.clock.advance(MINUTE);
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(adapter.calls(), 3, "nothing is called again");
}

/// Red (§13.13 item 3). A parent prepared by adapter A and its delegated child
/// prepared by adapter B; A is not configured when the parent is revoked. B's
/// rounds reach their cap (3, the first local denial included) while A's
/// obligation waits: B's obligation is capped, A's has consumed nothing and the
/// record is not stopped. When A is configured again it is served for its own full
/// cap (B is not called again), and only then is the record stopped.
#[tokio::test]
async fn r1313_3_one_adapters_rounds_never_exhaust_another_adapters_obligation() {
    let (mut w, a) = r1310_pending_world().await;
    let b = r1313_instance("fixture-2");
    let (parent, child) = r1313_tree(&mut w, &a, &b, "r1313-3").await;
    r1312_restart_with(&mut w, vec![b.clone() as Arc<dyn CredentialAdapter>]).await;
    let done = r1313_revoke(&w, &parent.grant_id, "r1313-3-revoke").await;
    let pending: BTreeSet<_> = done.remote_pending.into_iter().collect();
    assert_eq!(
        pending,
        [parent.grant_id.clone(), child.grant_id.clone()]
            .into_iter()
            .collect()
    );
    assert_eq!((a.calls(), b.calls()), (0, 1), "round 1 reaches B only");
    let cap = 3u32;
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..8 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    sup.scheduler_pass().await.unwrap();
    assert_eq!(b.calls(), cap as usize, "B's obligation reached its cap");
    assert_eq!(a.calls(), 0);
    let rec = r1312_record(&w, &parent.grant_id).expect("still pending");
    assert!(
        !rec.stopped,
        "A's obligation has neither cleared nor reached its cap"
    );
    let pv = r1310_view(&w, &parent.grant_id).await;
    assert_eq!(
        pv["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"])
    );
    assert_eq!(
        pv["remote_retries"]["attempts"], 0,
        "B's rounds consumed none of A's attempts: {pv}"
    );
    assert_eq!(pv["remote_retries"]["stopped"], false);
    let cv = r1310_view(&w, &child.grant_id).await;
    assert_eq!(cv["remote_retries"]["attempts"], cap);
    assert_eq!(cv["remote_retries"]["stopped"], true, "{cv}");
    // A returns: its obligation continues within its own, full cap.
    r1312_restart_with(
        &mut w,
        vec![
            a.clone() as Arc<dyn CredentialAdapter>,
            b.clone() as Arc<dyn CredentialAdapter>,
        ],
    )
    .await;
    // Its rounds still follow the bounded back-off (the record's own round count is
    // past the cap, which caps nothing): never in the pass that first sees the
    // record, one round per due instant, never one in every pass.
    let sup = r1312_supervisor(&w, cap);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        a.calls(),
        0,
        "the first pass after the restart only schedules"
    );
    for n in 1..=cap as usize {
        w.clock.advance(10 * Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(a.calls(), n, "A's round {n} is due");
        sup.scheduler_pass().await.unwrap();
        assert_eq!(a.calls(), n, "one round per due instant");
    }
    for _ in 0..4 {
        w.clock.advance(10 * Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
    }
    assert_eq!(a.calls(), cap as usize, "A is served for its full cap");
    assert_eq!(b.calls(), cap as usize, "B is not called again");
    let rec = r1312_record(&w, &parent.grant_id).expect("still pending");
    assert!(rec.stopped, "every obligation reached its cap");
    for g in [&parent.grant_id, &child.grant_id] {
        assert_eq!(w.grant(g).state, GrantState::Revoking);
        let v = r1310_view(&w, g).await;
        assert_eq!(v["remote_retries"]["attempts"], cap);
        assert_eq!(v["remote_retries"]["stopped"], true);
    }
}

/// Red (§13.13 item 4). An explicit revoke interrupted after its round's claim
/// committed and before the adapter acted on the call; restart recovery settles the
/// operation from the record without calling. The first supervisor pass after the
/// restart calls the adapter (the round is due at once, not after a back-off), and
/// the attempt count includes the interrupted round. Later rounds follow the
/// bounded schedule again.
#[tokio::test]
async fn r1313_4_an_explicit_revoke_interrupted_before_its_call_is_due_at_once_after_restart() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1313-4a", "r1313-4a-work", "h1", "1h").await;
    adapter.stall.store(true, Ordering::SeqCst);
    let owner = unattended(501);
    let revoke = w.ops.revoke(
        &owner,
        RevokeRequest {
            grant_id: g.grant_id.clone(),
            request_id: RequestId::parse("r1313-4a-revoke").unwrap(),
        },
    );
    assert!(
        r1312_until_crash(&adapter, revoke).await,
        "crashed after the claim, before the call"
    );
    assert_eq!(adapter.calls(), 0, "the adapter never acted on the call");
    let rec = r1312_record(&w, &g.grant_id).expect("the round was claimed");
    assert_eq!(rec.attempts, 1);
    assert!(rec.claimed_at.is_some());
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(adapter.calls(), 0, "recovery settles from the record");
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        adapter.calls(),
        1,
        "the first pass after the restart calls the adapter"
    );
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert_eq!(rec.attempts, 2, "the interrupted round counts");
    assert_eq!(rec.claimed_at, None);
    assert_eq!(
        r1310_view(&w, &g.grant_id).await["remote_retries"]["attempts"],
        2
    );
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "the next round waits for its back-off");
    adapter.pending.store(false, Ordering::SeqCst);
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
}

/// Red (§13.13 item 4). The same for a supervisor retry round interrupted between
/// its claim and its call: after the restart the first pass calls at once and the
/// count includes the interrupted round.
#[tokio::test]
async fn r1313_4_a_retry_round_interrupted_before_its_call_is_due_at_once_after_restart() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1313-4b").await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    adapter.stall.store(true, Ordering::SeqCst);
    assert!(r1312_until_crash(&adapter, sup.scheduler_pass()).await);
    assert_eq!(adapter.calls(), 1, "only the first local denial acted");
    let rec = r1312_record(&w, &g.grant_id).expect("claimed");
    assert_eq!(rec.attempts, 2);
    assert!(rec.claimed_at.is_some());
    r1310_restart_pending(&mut w, &adapter).await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2, "due at once after the restart");
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert_eq!(rec.attempts, 3, "the interrupted round counts");
    assert_eq!(rec.claimed_at, None);
}

/// §13.13 item 4, the boundary: a round claimed **in this process** and still in
/// flight (its adapter call has not returned) is not an interrupted round. A
/// supervisor pass that sees its claim schedules the next round on the back-off and
/// calls nothing at once. (Green at the base commit; it guards the startup
/// condition against a reading that treats every open claim as due.)
#[tokio::test]
async fn r1313_4_a_round_in_flight_in_this_process_is_not_called_again_at_once() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1313-4c", "r1313-4c-work", "h1", "1h").await;
    adapter.hang.store(true, Ordering::SeqCst);
    let owner = unattended(501);
    let revoke = w.ops.revoke(
        &owner,
        RevokeRequest {
            grant_id: g.grant_id.clone(),
            request_id: RequestId::parse("r1313-4c-revoke").unwrap(),
        },
    );
    tokio::pin!(revoke);
    tokio::select! {
        biased;
        () = adapter.entered.notified() => {}
        _ = &mut revoke => panic!("the revoke's adapter call hangs"),
    }
    assert_eq!(adapter.calls(), 1);
    let rec = r1312_record(&w, &g.grant_id).expect("claimed");
    assert!(rec.claimed_at.is_some());
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        adapter.calls(),
        1,
        "nothing is called at once for a round in flight"
    );
    assert_eq!(r1312_record(&w, &g.grant_id).unwrap().attempts, 1);
}

/// §13.13 item 4, the boundary after the restart: once this process claimed the
/// successor of an interrupted round, that claim is its own. When the successor's
/// completion commit fails, the next pass does not treat the record as interrupted
/// again: the following round waits for its back-off.
#[tokio::test]
async fn r1313_4_a_round_claimed_after_the_restart_follows_the_back_off_again() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1313-4d").await;
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    adapter.stall.store(true, Ordering::SeqCst);
    assert!(r1312_until_crash(&adapter, sup.scheduler_pass()).await);
    r1310_restart_pending(&mut w, &adapter).await;
    // The successor runs at once; its completion commit fails.
    *adapter.faults.lock().unwrap() = Some(faults.clone());
    let sup = r1312_supervisor(&w, 8);
    let _ = sup.scheduler_pass().await;
    *adapter.faults.lock().unwrap() = None;
    faults.armed.store(false, Ordering::SeqCst);
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the completion failed"
    );
    assert_eq!(
        adapter.calls(),
        2,
        "the successor of the interrupted round ran"
    );
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert_eq!(rec.attempts, 3);
    assert!(
        rec.claimed_at.is_some(),
        "this process's claim, uncompleted"
    );
    sup.scheduler_pass().await.unwrap();
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        adapter.calls(),
        2,
        "no round at once for this process's own claim"
    );
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 3, "the next round when due");
}

/// §13.13 item 3, backward compatibility: a record written before per-obligation
/// counts existed (its obligations without their own `attempts`) keeps its record
/// count, mapped onto each obligation conservatively: with 2 of a cap of 3 rounds
/// already used, the obligation gets exactly one more call and the record then
/// stops. (The base commit, where the count was the record's, behaves the same;
/// this case reads the new per-obligation field, so it does not compile there and
/// its evidence is the mutation check that maps the count to 0.)
#[tokio::test]
async fn r1313_3_a_record_count_from_before_per_obligation_counts_still_caps_its_obligations() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r1310_withdrawn_pending(&w, &adapter, "r1313-3b").await;
    let legacy: heimdall_domain::revocation::PendingRemoteRevocation =
        serde_json::from_value(serde_json::json!({
            "root": g.grant_id,
            "grants": [g.grant_id],
            "attempts": 2,
            "last_attempt_at": t0(),
            "stopped": false,
            "obligations": [{"grant": g.grant_id, "adapter": descriptor().identity}],
        }))
        .unwrap();
    w.store
        .transaction(|tx| tx.set_remote_revocation(&legacy))
        .unwrap();
    let sup = r1312_supervisor(&w, 3);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(
        adapter.calls(),
        2,
        "the first local denial, then exactly one more"
    );
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert_eq!(rec.attempts, 3);
    assert_eq!(rec.obligations[0].attempts, Some(3));
    assert!(rec.stopped);
}

// =================================================================================
// ⟨r2.11⟩ ADR-0006 §13.14 item 2: unknown remote state counts as pending
// =================================================================================

/// In-process restart with only [`r1312_other_adapter`] configured (the fixture
/// grants' responsible adapter is removed) while recovery's drive of the still
/// running ensure fails once before `next` (production `StageHook` seam), so the
/// grant stays `preparing` until the revoke denies it.
async fn r1314_remove_adapter(w: &mut World, next: EnsureStage) -> Arc<FakeCredentialAdapter> {
    w.hook = ScriptedStageHook::new([(next, Code::ServiceUnavailable)], []);
    let other = r1312_other_adapter();
    r1312_restart_with(w, vec![other.clone() as Arc<dyn CredentialAdapter>]).await;
    other
}

/// The ensure's effect receipts for `op` (`NotAttempted` excluded).
fn r1314_effects(w: &World, op: &OperationId) -> Vec<heimdall_domain::operation::EffectReceipt> {
    w.store
        .transaction(|tx| tx.stage_receipts(op))
        .unwrap()
        .into_iter()
        .map(|r| r.effect)
        .filter(|e| !matches!(e, heimdall_domain::operation::EffectReceipt::NotAttempted))
        .collect()
}

/// Red (§13.14 item 2). A grant revoked while `preparing`, with an `Attempted`
/// effect receipt on record (its `Reconcile` stage recorded the effect, then the
/// ensure failed; the operation still runs), whose responsible adapter was removed
/// before the revoke: no call can be made and nothing is reported, yet the remote
/// state is unknown, so the first local denial records an obligation on the
/// preparing adapter with reason `adapter_unavailable`. It consumes no attempt,
/// stays visible in `inspect grants` (the terminal grant stays listed), is never
/// served by another adapter, and rounds keep backing off without a call. Once the
/// adapter is configured again, its confirmation clears the obligation.
#[tokio::test]
async fn r1314_2_a_revoked_preparing_grant_with_an_effect_and_no_adapter_waits_for_it() {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1314-2a", "r1314-2a-work", &[("h1", "deploy")]),
        )
        .await);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    assert!(
        r1314_effects(&w, &op).iter().any(|r| matches!(
            r,
            heimdall_domain::operation::EffectReceipt::Attempted { .. }
        )),
        "an `Attempted` effect receipt is on record"
    );
    let other = r1314_remove_adapter(&mut w, EnsureStage::Probe).await;
    assert_eq!(w.grant(&gid).state, GrantState::Preparing);
    let done = r1313_revoke(&w, &gid, "r1314-2a-revoke").await;
    assert_eq!(
        w.grant(&gid).state,
        GrantState::Revoked,
        "preparing → revoked"
    );
    assert_eq!(adapter.calls(), 0, "no call can be made");
    assert_eq!(
        done.remote_pending,
        vec![gid.clone()],
        "the unknown remote state is pending"
    );
    let rec = r1312_record(&w, &gid).expect("an obligation is recorded");
    assert_eq!(rec.grants, vec![gid.clone()]);
    assert_eq!(rec.obligations.len(), 1);
    assert_eq!(rec.obligations[0].adapter, descriptor().identity);
    assert_eq!(
        rec.obligations[0].reason,
        Some(heimdall_domain::revocation::RemotePendingReason::AdapterUnavailable)
    );
    assert_eq!(rec.attempts, 0, "no attempt is consumed");
    assert_eq!(rec.obligations[0].attempts, Some(0));
    assert!(!rec.stopped);
    let view = r1310_view(&w, &gid).await;
    assert_eq!(view["state"], "revoked");
    assert_eq!(view["remote_pending"], true, "visible: {view}");
    assert_eq!(
        view["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"])
    );
    assert_eq!(view["remote_retries"]["attempts"], 0);
    let sup = r1312_supervisor(&w, 3);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(adapter.calls(), 0);
    assert!(
        !other.revocations.lock().unwrap().contains(&gid),
        "another adapter is never asked about this obligation"
    );
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert_eq!(rec.attempts, 0, "rounds without a call consume nothing");
    assert!(!rec.stopped);
    // The responsible adapter is configured again and confirms. Recovery settles
    // the still-running ensure first (its grant is revoked) without its
    // best-effort cleanup call (⟨r2.12⟩ §13.15 item 3: the record's rounds own
    // the calls). The obligation's own round then serves it.
    adapter.pending.store(false, Ordering::SeqCst);
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(w.op(&op).state, OperationState::Failed);
    assert_eq!(adapter.calls(), 0, "recovery makes no call for the grant");
    assert!(r1312_record(&w, &gid).is_some(), "still pending");
    let sup = r1312_supervisor(&w, 3);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "served once the adapter returns");
    assert_eq!(adapter.confirmations(), 1);
    assert!(
        r1312_record(&w, &gid).is_none(),
        "cleared by the confirmation"
    );
    assert_eq!(w.grant(&gid).state, GrantState::Revoked);
}

/// Store fault hook and pipeline hook in one: armed when `Reconcile` starts, it
/// lets the next commit (the grant's creation, `requested → preparing`) through
/// and fails the one after it (the `Attempted` receipt's), once: the grant is left
/// `preparing` with no effect receipt and no effect.
struct R1314FailAttemptCommit {
    armed: AtomicBool,
    passed: AtomicUsize,
}

impl FaultHook for R1314FailAttemptCommit {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point != FaultPoint::BeforeCommit || !self.armed.load(Ordering::SeqCst) {
            return FaultAction::Continue;
        }
        if self.passed.fetch_add(1, Ordering::SeqCst) == 0 {
            return FaultAction::Continue;
        }
        self.armed.store(false, Ordering::SeqCst);
        FaultAction::Fail
    }
}

impl StageHook for R1314FailAttemptCommit {
    fn before(&self, stage: EnsureStage) -> Result<(), Code> {
        if stage == EnsureStage::Reconcile && self.passed.load(Ordering::SeqCst) == 0 {
            self.armed.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
    fn after(&self, _stage: EnsureStage) -> Result<(), Code> {
        Ok(())
    }
}

/// Guard (§13.14 item 2). The same, but the grant's preparation never recorded an
/// effect (the commit of its `Attempted` receipt failed; no effect was applied):
/// with no effect receipt nothing can exist remotely, so the revoke records no
/// obligation and reports nothing pending.
#[tokio::test]
async fn r1314_2_a_revoked_preparing_grant_without_an_effect_receipt_owes_nothing() {
    let fault = Arc::new(R1314FailAttemptCommit {
        armed: AtomicBool::new(false),
        passed: AtomicUsize::new(0),
    });
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        hook: fault.clone(),
        faults: fault.clone(),
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1314-2b", "r1314-2b-work", &[("h1", "deploy")]),
        )
        .await);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    assert!(r1314_effects(&w, &op).is_empty(), "no effect receipt");
    assert_eq!(w.effects(), 0, "no effect was applied");
    let other = r1314_remove_adapter(&mut w, EnsureStage::Reconcile).await;
    assert_eq!(w.grant(&gid).state, GrantState::Preparing);
    let done = r1313_revoke(&w, &gid, "r1314-2b-revoke").await;
    assert_eq!(w.grant(&gid).state, GrantState::Revoked);
    assert_eq!(adapter.calls(), 0);
    assert!(!other.revocations.lock().unwrap().contains(&gid));
    assert!(done.remote_pending.is_empty(), "nothing is pending");
    assert!(
        r1312_record(&w, &gid).is_none(),
        "no obligation is recorded"
    );
}

// =================================================================================
// ⟨r2.12⟩ ADR-0006 §13.15 items 1–3 (review round 5 U01, U02; one call owner)
// =================================================================================

/// Red at b933d3eb (§13.15 item 1; review round 5 U02, the reviewer's exact path).
/// Preparation records its `Attempted` receipt and the ensure returns a partial
/// result, leaving the grant `preparing`; the runtime restarts with no adapter at
/// all (the preparing adapter is gone), and restart recovery fails the operation,
/// moving the grant to `failed`; then the owner revokes it explicitly. The remote
/// state is unknown, so the revoke records an `adapter_unavailable` obligation on
/// the preparing adapter (no call, no attempt consumed) that stays visible in the
/// revoke result and in `inspect grants` across supervisor passes; once that
/// adapter is configured again, its confirmation clears it.
#[tokio::test]
async fn r1315_1_an_attempted_grant_failed_by_recovery_without_its_adapter_stays_pending_after_revoke()
 {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1315-1", "r1315-1-work", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.effect_status, EffectStatus::Partial, "a partial result");
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    assert_eq!(w.grant(&gid).state, GrantState::Preparing);
    assert!(
        r1314_effects(&w, &op).iter().any(|r| matches!(
            r,
            heimdall_domain::operation::EffectReceipt::Attempted { .. }
        )),
        "an `Attempted` effect receipt is on record"
    );
    assert_eq!(
        w.store
            .transaction(|tx| tx.grant_origin(&gid))
            .unwrap()
            .and_then(|o| o.adapter),
        Some(descriptor().identity),
        "the preparing adapter is persisted with the grant"
    );
    let calls_before = adapter.calls();
    r1312_restart_with(&mut w, vec![]).await;
    assert_eq!(
        w.grant(&gid).state,
        GrantState::Failed,
        "recovery without the adapter fails the grant"
    );
    let done = r1313_revoke(&w, &gid, "r1315-1-revoke").await;
    assert_eq!(adapter.calls(), calls_before, "no call can be made");
    assert_eq!(
        done.remote_pending,
        vec![gid.clone()],
        "the revoke result names the unknown remote state pending"
    );
    let rec = r1312_record(&w, &gid).expect("an obligation is recorded");
    assert_eq!(rec.grants, vec![gid.clone()]);
    assert_eq!(rec.obligations.len(), 1);
    assert_eq!(rec.obligations[0].adapter, descriptor().identity);
    assert_eq!(
        rec.obligations[0].reason,
        Some(heimdall_domain::revocation::RemotePendingReason::AdapterUnavailable)
    );
    assert_eq!(rec.attempts, 0, "no attempt is consumed");
    let sup = r1312_supervisor(&w, 3);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let view = r1310_view(&w, &gid).await;
    assert_eq!(view["state"], "failed");
    assert_eq!(view["remote_pending"], true, "still visible: {view}");
    assert_eq!(
        view["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"])
    );
    assert_eq!(view["remote_retries"]["attempts"], 0);
    assert_eq!(view["remote_retries"]["stopped"], false);
    assert_eq!(adapter.calls(), calls_before);
    // The preparing adapter returns and confirms: only its own round clears it.
    adapter.pending.store(false, Ordering::SeqCst);
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(
        adapter.calls(),
        calls_before,
        "restart recovery makes no call"
    );
    let sup = r1312_supervisor(&w, 3);
    sup.scheduler_pass().await.unwrap();
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), calls_before + 1, "served once it returns");
    assert!(
        r1312_record(&w, &gid).is_none(),
        "cleared by the confirmation"
    );
}

/// Red (§13.15 item 2; review round 5 U01, the reviewer's overlapping roots). A
/// parent and its delegated child, both with pending remote effects. The greater
/// of the two IDs is revoked first and its record is run to its cap (3); then the
/// other is revoked with a new request. Both records hold an obligation for the
/// child, one stopped and one retryable. The child's inspect view combines both:
/// not stopped (one obligation remains retryable), `attempts` the maximum and
/// `last_attempt_at` the latest across them, whatever the records' root order.
/// After a restart with no adapter, only the retryable record's round can mark its
/// obligation `adapter_unavailable`; the reason is shown whichever record carries
/// it.
#[tokio::test]
async fn r1315_2_inspect_combines_every_pending_record_that_covers_a_grant() {
    let (mut w, _adapter) = r1310_pending_world().await;
    let parent = r136_ready(&w, "r1315-2", "r1315-2-work", "h1", "1h").await;
    let child = ok(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "r1315-2-c", "30m"))
        .await)
    .data;
    let (first, second) = if parent.grant_id.as_str() > child.grant_id.as_str() {
        (parent.grant_id.clone(), child.grant_id.clone())
    } else {
        (child.grant_id.clone(), parent.grant_id.clone())
    };
    let cap = 3u32;
    r1313_revoke(&w, &first, "r1315-2-revoke-1").await;
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..8 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    sup.scheduler_pass().await.unwrap();
    assert!(
        r1312_record(&w, &first).expect("first record").stopped,
        "the first record ran to its cap"
    );
    w.clock.advance(MINUTE);
    r1313_revoke(&w, &second, "r1315-2-revoke-2").await;
    let recs = [
        r1312_record(&w, &first).expect("first record"),
        r1312_record(&w, &second).expect("second record"),
    ];
    let cg = &child.grant_id;
    for r in &recs {
        assert!(
            r.obligations.iter().any(|o| &o.grant == cg),
            "both records owe the child: {r:?}"
        );
    }
    let own = |r: &heimdall_domain::revocation::PendingRemoteRevocation| {
        r.obligations
            .iter()
            .filter(|o| &o.grant == cg)
            .map(|o| (r.obligation_attempts(o), o.stopped || r.stopped))
            .collect::<Vec<_>>()
    };
    assert!(own(&recs[0]).iter().all(|(_, s)| *s), "first: stopped");
    assert!(own(&recs[1]).iter().all(|(_, s)| !*s), "second: retryable");
    let max_attempts = recs.iter().flat_map(own).map(|(a, _)| a).max().unwrap();
    assert_eq!(max_attempts, cap);
    let latest = recs.iter().map(|r| r.last_attempt_at).max().unwrap();
    assert!(recs[0].last_attempt_at < latest);
    let v = r1310_view(&w, cg).await;
    assert_eq!(v["remote_pending"], true);
    assert_eq!(
        v["remote_retries"]["stopped"], false,
        "one obligation remains retryable: {v}"
    );
    assert_eq!(v["remote_retries"]["attempts"], max_attempts);
    assert_eq!(
        v["remote_retries"]["last_attempt_at"],
        serde_json::json!(latest)
    );
    assert!(
        v.get("remote_pending_reasons").is_none(),
        "no reason yet: {v}"
    );
    // No adapter: the retryable record's next round finds its adapter missing.
    r1312_restart_with(&mut w, vec![]).await;
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..3 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let second_rec = r1312_record(&w, &second).expect("second record");
    assert!(
        second_rec.obligations.iter().any(|o| &o.grant == cg
            && o.reason
                == Some(heimdall_domain::revocation::RemotePendingReason::AdapterUnavailable)),
        "the retryable record marks the child's obligation: {second_rec:?}"
    );
    assert!(
        r1312_record(&w, &first)
            .expect("first record")
            .obligations
            .iter()
            .all(|o| o.reason.is_none()),
        "the stopped record has no round, so no reason"
    );
    let v = r1310_view(&w, cg).await;
    assert_eq!(
        v["remote_pending_reasons"],
        serde_json::json!(["adapter_unavailable"]),
        "every reason present is shown: {v}"
    );
    assert_eq!(v["remote_retries"]["stopped"], false);
}

/// Red (§13.15 item 3). A grant revoked while `preparing` whose adapter reports
/// its remote effect pending has a pending record; its ensure is still running.
/// Restart recovery settles that ensure (its grant is revoked) without the
/// best-effort cleanup call: the record's rounds own the calls. Counted through
/// recovery and the following passes, the adapter is called only by the first
/// local denial and by scheduled rounds, one per due instant.
#[tokio::test]
async fn r1315_3_recovery_cleanup_never_calls_for_a_grant_with_a_pending_record() {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1315-3", "r1315-3-work", &[("h1", "deploy")]),
        )
        .await);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    r1313_revoke(&w, &gid, "r1315-3-revoke").await;
    assert_eq!(adapter.calls(), 1, "the first local denial");
    assert!(r1312_record(&w, &gid).is_some(), "a pending record");
    assert_eq!(w.op(&op).state, OperationState::Running);
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(
        w.op(&op).state,
        OperationState::Failed,
        "recovery settled the ensure"
    );
    assert_eq!(adapter.calls(), 1, "recovery made no call for the grant");
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "the first pass only schedules");
    for n in 2..=4 {
        w.clock.advance(10 * Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(adapter.calls(), n, "one scheduled round per due instant");
        sup.scheduler_pass().await.unwrap();
        assert_eq!(adapter.calls(), n);
    }
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert_eq!(rec.attempts, 4, "every call is a counted round");
}

/// Guard (§13.15 item 3: unchanged without a record). The same, but the adapter
/// confirms the first local denial, so no record is left: restart recovery's
/// best-effort cleanup still calls the adapter for the revoked grant.
#[tokio::test]
async fn r1315_3_recovery_cleanup_still_calls_for_a_grant_without_a_record() {
    let hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        hook: hook.clone(),
        ..Setup::default()
    })
    .await;
    adapter.pending.store(false, Ordering::SeqCst);
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1315-3b", "r1315-3b-work", &[("h1", "deploy")]),
        )
        .await);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    r1313_revoke(&w, &gid, "r1315-3b-revoke").await;
    assert_eq!(adapter.calls(), 1);
    assert!(r1312_record(&w, &gid).is_none(), "confirmed: no record");
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(w.op(&op).state, OperationState::Failed);
    assert_eq!(adapter.calls(), 2, "the best-effort cleanup call");
    assert!(r1312_record(&w, &gid).is_none());
}

/// Red (§13.15 item 3, a grant covered by another root's record). A delegated
/// child is revoked through its parent while its own preparation is still running
/// (`Attempted` receipt, partial result); the parent's record covers it. Restart
/// recovery settles the child's operation without a cleanup call for it: the
/// parent's record owns its calls.
#[tokio::test]
async fn r1315_3_recovery_cleanup_never_calls_for_a_child_covered_by_its_parents_record() {
    let (mut w, adapter) = r1310_pending_world().await;
    let parent = r136_ready(&w, "r1315-3c", "r1315-3c-work", "h1", "1h").await;
    w.hook = ScriptedStageHook::new([], [(EnsureStage::Reconcile, Code::ServiceUnavailable)]);
    r1310_restart_pending(&mut w, &adapter).await;
    let e = err(w
        .ops
        .delegate(&unattended(501), u10_delegate(&parent, "r1315-3c-c", "30m"))
        .await);
    assert_eq!(e.effect_status, EffectStatus::Partial);
    let op = e.operation_id.clone().unwrap();
    let child = r1313_grant_of(&w, &op);
    assert_eq!(w.grant(&child).state, GrantState::Preparing);
    r1313_revoke(&w, &parent.grant_id, "r1315-3c-revoke").await;
    let rec = r1312_record(&w, &parent.grant_id).expect("the parent's record");
    assert!(rec.grants.contains(&child), "it covers the child: {rec:?}");
    assert!(
        r1312_record(&w, &child).is_none(),
        "the child has no own record"
    );
    assert_eq!(w.op(&op).state, OperationState::Running);
    let calls = adapter.calls();
    r1310_restart_pending(&mut w, &adapter).await;
    assert_ne!(
        w.op(&op).state,
        OperationState::Running,
        "recovery settled it"
    );
    assert_eq!(
        adapter.calls(),
        calls,
        "recovery made no call for the child"
    );
}

// =================================================================================
// ⟨r2.14⟩ ADR-0006 §13.17 (automated security review of 6230acf9, "fail-open
// revocation"). A credential effect applied for a grant that a pending remote record
// covers is skipped by `cleanup` only while a covering record holds a live
// obligation for (that grant, the applying adapter); otherwise the record's
// obligation is re-armed, or one is added, in the cleanup decision's transaction,
// and the supervisor's rounds make the call. A grant no record covers is cleaned up
// with the immediate call as before (`r1315_3_recovery_cleanup_still_calls_for_a_grant_without_a_record`).
//
// The late confirmation used throughout: the preparation applied its effect but the
// commit of its `Confirmed` receipt failed, so the ensure still runs with only the
// `Attempted` receipt; the owner revokes the grant; a later in-process restart's
// recovery reconciles the effect token (`Applied`), records `Confirmed` and refuses
// activation of the revoked grant at `Recheck`, which reaches `cleanup`. Only public
// APIs are used, so every case also runs against the base commit d0c8cb7c.
// =================================================================================

/// The grant's obligation to the fixture adapter (its preparing adapter) in `record`.
fn r1317_owed(
    record: &heimdall_domain::revocation::PendingRemoteRevocation,
    grant: &heimdall_contract::ids::GrantId,
) -> Option<heimdall_domain::revocation::RemoteObligation> {
    record
        .obligations
        .iter()
        .find(|o| &o.grant == grant && o.adapter == descriptor().identity)
        .cloned()
}

/// A grant revoked after its preparation applied its credential effect and before
/// that effect's confirmation became durable (see the section comment). The first
/// local denial calls the preparing adapter, which reports the remote effect
/// pending: the record holds one live obligation, round 1.
async fn r1317_revoked_before_its_confirmation(
    tag: &str,
) -> (
    World,
    Arc<PendingCounter>,
    OperationId,
    heimdall_contract::ids::GrantId,
) {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    faults.arm_after_effect(w.fake.clone());
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req(tag, &format!("{tag}-work"), &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.code, Code::StateUnavailable);
    assert_eq!(faults.fired.load(Ordering::SeqCst), 1);
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Running);
    assert!(
        matches!(
            r1314_effects(&w, &op).last(),
            Some(heimdall_domain::operation::EffectReceipt::Attempted { .. })
        ),
        "only the `Attempted` receipt is durable"
    );
    let gid = r1313_grant_of(&w, &op);
    assert_eq!(w.grant(&gid).state, GrantState::Preparing);
    let done = r1313_revoke(&w, &gid, &format!("{tag}-revoke")).await;
    assert_eq!(w.grant(&gid).state, GrantState::Revoked);
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    assert_eq!(adapter.calls(), 1, "the first local denial");
    let rec = r1312_record(&w, &gid).expect("the pending record");
    let owed = r1317_owed(&rec, &gid).expect("the preparing adapter's obligation");
    assert_eq!(owed.attempts, Some(1));
    assert!(!owed.stopped && !rec.stopped);
    (w, adapter, op, gid)
}

/// Run the supervisor (revocation cap `cap`) until the record of `grant` is stopped
/// at its cap: the adapter was called `cap` times in all.
async fn r1317_run_to_cap(
    w: &World,
    adapter: &PendingCounter,
    grant: &heimdall_contract::ids::GrantId,
    cap: u32,
) {
    let sup = r1312_supervisor(w, cap);
    for _ in 0..(cap + 3) {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let rec = r1312_record(w, grant).expect("still pending");
    assert!(rec.stopped, "capped: {rec:?}");
    assert!(rec.obligations.iter().all(|o| o.stopped), "{rec:?}");
    assert_eq!(adapter.calls(), cap as usize, "every round of the cap ran");
}

/// The late confirmation of the effect (restart recovery; section comment): the
/// ensure settles failed with its `Confirmed` receipt recorded, and `cleanup` makes
/// no immediate call for a grant a record covers.
async fn r1317_late_confirmation(w: &mut World, adapter: &Arc<PendingCounter>, op: &OperationId) {
    let calls = adapter.calls();
    r1310_restart_pending(w, adapter).await;
    assert_eq!(
        w.op(op).state,
        OperationState::Failed,
        "recovery settled it"
    );
    assert!(
        r1314_effects(w, op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
    assert_eq!(
        adapter.calls(),
        calls,
        "no immediate call: the record's rounds own it"
    );
}

/// The next due round of `grant`'s record calls the adapter once: the first pass
/// schedules it (no call), the pass after its delay runs it.
async fn r1317_next_round_calls(
    w: &World,
    adapter: &PendingCounter,
    grant: &heimdall_contract::ids::GrantId,
    cap: u32,
) {
    let calls = adapter.calls();
    let sup = r1312_supervisor(w, cap);
    let report = sup.revocation_pass().await.unwrap();
    assert!(
        report.scheduled.iter().any(|(r, ..)| r == grant),
        "the record is scheduled: {report:?}"
    );
    assert_eq!(adapter.calls(), calls, "the first pass only schedules");
    w.clock.advance(10 * Duration::from_secs(1));
    let report = sup.revocation_pass().await.unwrap();
    assert!(
        report.retried.iter().any(|(r, _)| r == grant),
        "the due round ran: {report:?}"
    );
    assert_eq!(
        adapter.calls(),
        calls + 1,
        "the next round calls the adapter"
    );
}

/// Red at d0c8cb7c (§13.17 items 1, 2). The covering record ran to its cap (3
/// rounds, stopped) before the effect's late confirmation. `cleanup` re-arms the
/// stopped obligation of the applying adapter (attempts reset, `stopped` cleared, the
/// record no longer stopped) in its decision's transaction, with no immediate call,
/// and the next round calls the adapter. The re-armed obligation gets its own cap of
/// rounds again, and no more.
#[tokio::test]
async fn r1317_1_a_late_effect_on_a_capped_record_rearms_it_for_the_next_round() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-1").await;
    r1317_run_to_cap(&w, &adapter, &gid, cap).await;
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert!(!rec.stopped, "re-armed: {rec:?}");
    let owed = r1317_owed(&rec, &gid).expect("the obligation");
    assert_eq!(owed.attempts, Some(0), "attempts reset");
    assert!(!owed.stopped, "stopped cleared");
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..(cap + 3) {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(
        adapter.calls(),
        2 * cap as usize,
        "one more cap of rounds, and no more"
    );
    assert!(r1312_record(&w, &gid).expect("still pending").stopped);
}

/// Red at d0c8cb7c (§13.17 items 1, 2). The covering record owes the grant's remote
/// effect to another adapter only (here rewritten to name another mechanism's
/// adapter, which is not configured). `cleanup` adds an obligation for the applying
/// adapter in its decision's transaction, with no immediate call; the next round
/// calls it. The other obligation stays as it was.
#[tokio::test]
async fn r1317_2_a_late_effect_with_no_obligation_for_its_adapter_adds_one() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-2").await;
    let other = AdapterIdentity {
        mechanism: "fake_other".into(),
        instance: "fixture-2".into(),
    };
    w.store
        .transaction(|tx| {
            let mut r = tx.remote_revocation(&gid)?.unwrap();
            for o in &mut r.obligations {
                o.adapter = other.clone();
            }
            tx.set_remote_revocation(&r)
        })
        .unwrap();
    let before = r1312_record(&w, &gid).unwrap();
    assert!(r1317_owed(&before, &gid).is_none(), "nothing owed to it");
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    let rec = r1312_record(&w, &gid).expect("still pending");
    let owed = r1317_owed(&rec, &gid).expect("an obligation was added");
    assert_eq!(owed.attempts, Some(0));
    assert!(!owed.stopped && !rec.stopped);
    assert!(
        rec.obligations
            .iter()
            .any(|o| o.grant == gid && o.adapter == other),
        "the other adapter's obligation is kept: {rec:?}"
    );
    assert_eq!(rec.grants, vec![gid.clone()]);
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
}

/// Guard (§13.17 item 1; green at d0c8cb7c). The covering record's obligation for
/// the applying adapter is live (round 1 of 3, not stopped) when the effect's late
/// confirmation arrives: `cleanup` skips, the record is unchanged, and the rounds
/// continue on their schedule within the cap: no extra call. ⟨r2.15⟩ ADR-0006
/// §13.18 item 2 amends "unchanged": the skip records the effect on the live
/// obligation, at the record's round count (1), and nothing else changes.
#[tokio::test]
async fn r1317_3_a_late_effect_with_a_live_obligation_is_skipped_without_an_extra_call() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-3").await;
    let before = r1312_record(&w, &gid).unwrap();
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    assert_eq!(
        r1312_record(&w, &gid).unwrap(),
        r1318_with_effect_at(&before, 1),
        "a live obligation owns the call: only the effect is recorded on it"
    );
    r1317_run_to_cap(&w, &adapter, &gid, cap).await;
}

/// ⟨r2.15⟩ `record` with the effect recorded at `round` on every obligation
/// (ADR-0006 §13.18 item 2). Written through the record's stored form, so the module
/// also compiles at the base commit, where the field does not exist and this is
/// the record unchanged. ⟨r2.16⟩ ADR-0006 §13.19 item 1: the effect is recorded as
/// the record's claim sequence (`effect_seq`); in these cases the round's claim is
/// the record's first, so its sequence equals the round.
fn r1318_with_effect_at(
    record: &heimdall_domain::revocation::PendingRemoteRevocation,
    round: u32,
) -> heimdall_domain::revocation::PendingRemoteRevocation {
    let mut v = serde_json::to_value(record).unwrap();
    for o in v["obligations"].as_array_mut().unwrap() {
        o["effect_seq"] = round.into();
    }
    serde_json::from_value(v).unwrap()
}

/// Red at d0c8cb7c (§13.17 items 1, 2; restart). As in
/// [`r1317_1_a_late_effect_on_a_capped_record_rearms_it_for_the_next_round`], then
/// another in-process restart: the re-armed obligation is durable, the restart makes
/// no call and does not re-arm it again, and the supervisor schedules it and calls.
#[tokio::test]
async fn r1317_1_a_restart_keeps_the_rearmed_obligation_and_schedules_it() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-1r").await;
    r1317_run_to_cap(&w, &adapter, &gid, cap).await;
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    let rearmed = r1312_record(&w, &gid).expect("still pending");
    assert!(!rearmed.stopped);
    let calls = adapter.calls();
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(adapter.calls(), calls, "the restart makes no call");
    assert_eq!(
        r1312_record(&w, &gid).unwrap(),
        rearmed,
        "the re-armed obligation survives the restart unchanged"
    );
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
}

/// Red at d0c8cb7c (§13.17 items 1, 2; restart). As in
/// [`r1317_2_a_late_effect_with_no_obligation_for_its_adapter_adds_one`], then another
/// in-process restart: the added obligation is durable and the supervisor schedules
/// it and calls.
#[tokio::test]
async fn r1317_2_a_restart_keeps_the_added_obligation_and_schedules_it() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-2r").await;
    w.store
        .transaction(|tx| {
            let mut r = tx.remote_revocation(&gid)?.unwrap();
            for o in &mut r.obligations {
                o.adapter = AdapterIdentity {
                    mechanism: "fake_other".into(),
                    instance: "fixture-2".into(),
                };
            }
            tx.set_remote_revocation(&r)
        })
        .unwrap();
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    let added = r1312_record(&w, &gid).expect("still pending");
    assert!(
        r1317_owed(&added, &gid).is_some(),
        "an obligation was added"
    );
    let calls = adapter.calls();
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(adapter.calls(), calls, "the restart makes no call");
    assert_eq!(
        r1312_record(&w, &gid).unwrap(),
        added,
        "the added obligation survives the restart unchanged"
    );
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
}

/// Guard (§13.17 item 1; restart; green at d0c8cb7c). As in
/// [`r1317_3_a_late_effect_with_a_live_obligation_is_skipped_without_an_extra_call`],
/// then another in-process restart: the live obligation is unchanged (⟨r2.15⟩ but for
/// the effect recorded on it, §13.18 item 2) and is scheduled and called by its next
/// round.
#[tokio::test]
async fn r1317_3_a_restart_keeps_the_live_obligation_and_schedules_it() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1317-3r").await;
    let before = r1312_record(&w, &gid).unwrap();
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(adapter.calls(), 1, "neither restart made a call");
    assert_eq!(
        r1312_record(&w, &gid).unwrap(),
        r1318_with_effect_at(&before, 1),
        "unchanged but for the recorded effect"
    );
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
}

/// Red at d0c8cb7c (§13.17 item 1: "below its cap"). The covering obligation
/// reached its cap (3) in a round whose completion commit failed, so it is not yet
/// marked `stopped`. The effect's late confirmation then arrives in the same
/// process, through a same-key retry of the ensure, after the supervisor gave the
/// operations its cap. At its cap the obligation is not live, so `cleanup`
/// re-arms it and the next round calls the adapter. If it were judged live, the
/// next pass would stop the record without a call.
#[tokio::test]
async fn r1317_4_an_obligation_at_its_cap_but_not_yet_stopped_is_rearmed() {
    let cap = 3u32;
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    faults.arm_after_effect(w.fake.clone());
    let req = ensure_req("r1317-4", "r1317-4-work", &[("h1", "deploy")]);
    let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
    assert_eq!(e.code, Code::StateUnavailable);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    *faults.after_effect_of.lock().unwrap() = None;
    r1313_revoke(&w, &gid, "r1317-4-revoke").await;
    assert_eq!(adapter.calls(), 1);
    let sup = r1312_supervisor(&w, cap);
    while adapter.calls() < cap as usize - 1 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    // The round that reaches the cap: its completion commit fails.
    *adapter.faults.lock().unwrap() = Some(faults.clone());
    while adapter.calls() < cap as usize {
        let _ = sup.scheduler_pass().await;
        w.clock.advance(10 * Duration::from_secs(1));
    }
    *adapter.faults.lock().unwrap() = None;
    faults.armed.store(false, Ordering::SeqCst);
    let rec = r1312_record(&w, &gid).expect("still pending");
    let owed = r1317_owed(&rec, &gid).expect("the obligation");
    assert_eq!(owed.attempts, Some(cap), "at its cap");
    assert!(
        !owed.stopped && !rec.stopped,
        "not yet marked stopped: {rec:?}"
    );
    // The late confirmation, in this process.
    let _ = w.ops.ensure(&unattended(501), req).await;
    assert_eq!(w.op(&op).state, OperationState::Failed);
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
    assert_eq!(adapter.calls(), cap as usize, "no immediate call");
    let rec = r1312_record(&w, &gid).expect("still pending");
    let owed = r1317_owed(&rec, &gid).expect("the obligation");
    assert_eq!(owed.attempts, Some(0), "re-armed: {rec:?}");
    let calls = adapter.calls();
    for _ in 0..2 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(
        adapter.calls(),
        calls + 1,
        "the next round calls the adapter"
    );
}

/// Red at d0c8cb7c (§13.17 items 2, 4; the finding's own path). The grant is revoked
/// while its preparation is still in flight, and its record runs to its cap (3).
/// The ensure is then cancelled: its receipts show an attempted, possibly applied
/// effect, so `cleanup` re-arms the stopped obligation (the effect's first state),
/// and the re-armed rounds run to the cap again before the effect is applied.
/// Then the preparation applies its credential and the late confirmation reaches
/// `cleanup` again. The same effect token, now confirmed, is a new state of the
/// effect: it re-arms once more, and the next round, after the credential exists,
/// calls the adapter. Neither state re-arms twice, and nothing is called
/// immediately.
#[tokio::test]
async fn r1317_5_a_cancel_then_a_late_confirmation_each_rearm_once() {
    let cap = 3u32;
    let (w, adapter) = r1310_pending_world().await;
    adapter.hold_prepare.store(true, Ordering::SeqCst);
    let ops = w.ops.clone();
    let req = ensure_req("r1317-5", "r1317-5-work", &[("h1", "deploy")]);
    let ensure = tokio::spawn(async move { ops.ensure(&unattended(501), req).await });
    adapter.prepare_entered.notified().await;
    assert_eq!(w.effects(), 0, "the preparation is still in flight");
    let op = w
        .store
        .transaction(|tx| tx.open_operations())
        .unwrap()
        .into_iter()
        .find(|o| o.state == OperationState::Running)
        .expect("the running ensure")
        .id;
    let gid = r1313_grant_of(&w, &op);
    r1313_revoke(&w, &gid, "r1317-5-revoke").await;
    assert_eq!(w.grant(&gid).state, GrantState::Revoked);
    r1317_run_to_cap(&w, &adapter, &gid, cap).await;
    // Cancelled while the preparation is in flight: a possibly applied effect.
    let c = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(c.data["may_have_external_effect"], true);
    assert_eq!(adapter.calls(), cap as usize, "no immediate call");
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert!(!rec.stopped, "re-armed by the possible effect: {rec:?}");
    assert_eq!(r1317_owed(&rec, &gid).unwrap().attempts, Some(0));
    // Its rounds run to the cap again, all before the credential exists.
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..(cap + 3) {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(adapter.calls(), 2 * cap as usize);
    assert!(r1312_record(&w, &gid).expect("still pending").stopped);
    assert_eq!(w.effects(), 0, "every call so far preceded the effect");
    // The preparation applies its credential; the late confirmation follows.
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
    assert_eq!(adapter.calls(), 2 * cap as usize, "no immediate call");
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert!(!rec.stopped, "re-armed by the confirmed effect: {rec:?}");
    assert_eq!(r1317_owed(&rec, &gid).unwrap().attempts, Some(0));
    // Read through the record's stored form, so the case also compiles (red) at
    // the base commit, before the field existed.
    let rearmed = serde_json::to_value(&rec).unwrap()["rearmed_effects"]
        .as_array()
        .map_or(0, Vec::len);
    assert_eq!(rearmed, 2, "one re-arm per state: {rec:?}");
    r1317_next_round_calls(&w, &adapter, &gid, cap).await;
}

// =================================================================================
// ⟨r2.15⟩ ADR-0006 §13.18 (rulings on the §13.17 implementation, and the automated
// security review of 8d17ace9).
//
// * Item 2: when `cleanup` skips because a covering obligation is live, it records
//   the effect on that obligation as the record's claimed-round count at that
//   moment. Only a round claimed after it may clear the obligation. A confirmation
//   means "revoked as of the call", never "revoked as of now".
// * Item 3: each record carries the cap in force when it was created or re-armed.
//   Restart recovery, before any supervisor exists, and the supervisor judge it by
//   the lower of that cap and the configured one.
// * Item 4: the re-arm bound limits re-arms only, never the call.
//
// The race used below: a grant is revoked while its preparation is still in flight
// (held in `prepare`, no credential yet). A round's call then goes out with its
// answer held, the preparation applies its credential, and the late confirmation
// reaches `cleanup` while that round is in flight. Only public APIs are used, so
// every case also runs against the base commit 8d17ace9.
// =================================================================================

/// An ensure whose preparation is held in flight (no credential applied yet), and
/// its grant. The ensure resumes once `prepare_release` is notified.
async fn r1318_held_ensure(
    w: &World,
    adapter: &Arc<PendingCounter>,
    tag: &str,
) -> (
    OperationId,
    heimdall_contract::ids::GrantId,
    tokio::task::JoinHandle<impl Sized + use<>>,
) {
    adapter.hold_prepare.store(true, Ordering::SeqCst);
    let ops = w.ops.clone();
    let req = ensure_req(tag, &format!("{tag}-work"), &[("h1", "deploy")]);
    let ensure = tokio::spawn(async move { ops.ensure(&unattended(501), req).await });
    adapter.prepare_entered.notified().await;
    assert_eq!(w.effects(), 0, "the preparation is still in flight");
    let op = w
        .store
        .transaction(|tx| tx.open_operations())
        .unwrap()
        .into_iter()
        .find(|o| o.state == OperationState::Running)
        .expect("the running ensure")
        .id;
    let gid = r1313_grant_of(w, &op);
    (op, gid, ensure)
}

/// Release the held preparation: it applies its credential, and the ensure's late
/// confirmation reaches `cleanup` (its grant is revoked, so activation is refused).
async fn r1318_apply_late(
    w: &World,
    adapter: &PendingCounter,
    op: &OperationId,
    ensure: tokio::task::JoinHandle<impl Sized>,
) {
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    assert_eq!(w.op(op).state, OperationState::Failed);
    assert!(
        r1314_effects(w, op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
}

/// The next due round of `grant`'s record calls the adapter once and, the adapter
/// now confirming, clears the record: the first pass schedules it (no call), and the
/// pass after its delay runs it.
async fn r1318_next_round_clears(
    w: &World,
    adapter: &PendingCounter,
    grant: &heimdall_contract::ids::GrantId,
    cap: u32,
) {
    assert!(r1312_record(w, grant).is_some(), "still pending");
    let calls = adapter.calls();
    let sup = r1312_supervisor(w, cap);
    let report = sup.revocation_pass().await.unwrap();
    assert!(
        report.scheduled.iter().any(|(r, ..)| r == grant),
        "the record is scheduled: {report:?}"
    );
    assert_eq!(adapter.calls(), calls, "the first pass only schedules");
    w.clock.advance(10 * Duration::from_secs(1));
    let report = sup.revocation_pass().await.unwrap();
    assert_eq!(
        adapter.calls(),
        calls + 1,
        "the next round calls the adapter"
    );
    assert!(
        report.completed.contains(grant),
        "its confirmation clears the record: {report:?}"
    );
    assert!(r1312_record(w, grant).is_none());
}

/// The race of §13.18 item 2 through a supervisor round. The first local denial
/// leaves the remote effect pending (round 1 of `cap`). Round 2 is claimed and its
/// call goes out before any credential exists, and its answer, a confirmation, is
/// held. Then the credential is applied and its late confirmation reaches `cleanup`,
/// which makes no immediate call: the obligation is live. Then round 2's answer
/// arrives. Returns what that round left: the record, if any.
async fn r1318_round_in_flight_when_the_effect_lands(
    tag: &str,
    cap: u32,
) -> (
    World,
    Arc<PendingCounter>,
    heimdall_contract::ids::GrantId,
    Option<heimdall_domain::revocation::PendingRemoteRevocation>,
) {
    let (w, adapter) = r1310_pending_world().await;
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, tag).await;
    let done = r1313_revoke(&w, &gid, &format!("{tag}-revoke")).await;
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    assert_eq!(adapter.calls(), 1, "the first local denial");
    // Round 2: claimed, its call goes out, its confirmation is held.
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_revoke.store(true, Ordering::SeqCst);
    let ops = w.ops.clone();
    let g = gid.clone();
    let round = tokio::spawn(async move { ops.retry_remote_revocation(&g, cap).await });
    adapter.revoke_entered.notified().await;
    assert_eq!(adapter.calls(), 2, "round 2's call went out");
    assert_eq!(w.effects(), 0, "before the credential existed");
    assert_eq!(r1312_record(&w, &gid).unwrap().attempts, 2, "claimed");
    // The credential is applied after the call; `cleanup` skips (live obligation).
    r1318_apply_late(&w, &adapter, &op, ensure).await;
    assert_eq!(
        adapter.calls(),
        2,
        "no immediate call: the live obligation owns it"
    );
    let owed = r1317_owed(&r1312_record(&w, &gid).unwrap(), &gid).expect("the obligation");
    assert!(!owed.stopped, "live: round 2 of {cap}");
    // Round 2's confirmation arrives.
    adapter.revoke_release.notify_one();
    let left = round.await.unwrap().unwrap();
    (w, adapter, gid, left)
}

/// Red at 8d17ace9 (§13.18 items 2 and 4, [HIGH]). A supervisor round claimed
/// before a late credential effect confirms after it. Its confirmation answers a
/// call made before the credential existed, so it must not clear the obligation.
/// The obligation stays, and the next round calls the adapter and clears it.
#[tokio::test]
async fn r1318_2_a_round_in_flight_when_a_late_effect_lands_does_not_clear_it() {
    let cap = 3u32;
    let (w, adapter, gid, left) =
        r1318_round_in_flight_when_the_effect_lands("r1318-2a", cap).await;
    let rec = left.expect("still pending: that round's call preceded the effect");
    let owed = r1317_owed(&rec, &gid).expect("the obligation stays");
    assert!(!owed.stopped && !rec.stopped, "{rec:?}");
    assert_eq!(rec.claimed_at, None, "the round completed");
    r1318_next_round_clears(&w, &adapter, &gid, cap).await;
}

/// Red at 8d17ace9 (§13.18 item 2; restart). As in
/// [`r1318_2_a_round_in_flight_when_a_late_effect_lands_does_not_clear_it`], then an
/// in-process restart between that round and the next one: the kept obligation is
/// durable, the restart makes no call, and the next round calls and clears it.
#[tokio::test]
async fn r1318_2_a_restart_after_the_racing_round_keeps_the_obligation_for_the_next_round() {
    let cap = 3u32;
    let (mut w, adapter, gid, left) =
        r1318_round_in_flight_when_the_effect_lands("r1318-2r", cap).await;
    let kept = left.expect("still pending: that round's call preceded the effect");
    let calls = adapter.calls();
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(adapter.calls(), calls, "the restart makes no call");
    assert_eq!(
        r1312_record(&w, &gid).expect("durable"),
        kept,
        "the kept obligation survives the restart unchanged"
    );
    r1318_next_round_clears(&w, &adapter, &gid, cap).await;
}

/// Red at 8d17ace9 (§13.18 items 2 and 4, [HIGH]; the explicit revoke's own first
/// round). The revoke claims its first round in its tombstone's transaction and
/// calls the preparing adapter. While that call is in flight (answer held), the
/// preparation applies its credential and the late confirmation reaches `cleanup`,
/// which skips: the obligation is live. The revoke's confirmation then arrives: it
/// must not clear the obligation, and the revoke reports the grant as still pending.
/// The next round calls the adapter and clears it.
#[tokio::test]
async fn r1318_2_an_explicit_revokes_first_round_in_flight_does_not_clear_a_late_effect() {
    let cap = 3u32;
    let (w, adapter) = r1310_pending_world().await;
    // The supervisor gives the operations its cap before anything is revoked.
    let _sup = r1312_supervisor(&w, cap);
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1318-2e").await;
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_revoke.store(true, Ordering::SeqCst);
    let ops = w.ops.clone();
    let g = gid.clone();
    let revoke = tokio::spawn(async move {
        ops.revoke(
            &unattended(501),
            RevokeRequest {
                grant_id: g,
                request_id: RequestId::parse("r1318-2e-revoke").unwrap(),
            },
        )
        .await
    });
    adapter.revoke_entered.notified().await;
    assert_eq!(adapter.calls(), 1, "the first local denial's call went out");
    assert_eq!(w.effects(), 0, "before the credential existed");
    r1318_apply_late(&w, &adapter, &op, ensure).await;
    assert_eq!(
        adapter.calls(),
        1,
        "no immediate call: the live obligation owns it"
    );
    adapter.revoke_release.notify_one();
    let done = ok(revoke.await.unwrap()).data;
    assert_eq!(
        done.remote_pending,
        vec![gid.clone()],
        "the revoke's call preceded the effect: still pending"
    );
    let rec = r1312_record(&w, &gid).expect("still pending");
    assert!(
        r1317_owed(&rec, &gid).is_some(),
        "the obligation stays: {rec:?}"
    );
    r1318_next_round_clears(&w, &adapter, &gid, cap).await;
}

/// Guard (§13.18 item 2; green at 8d17ace9). The late confirmation reaches
/// `cleanup` while the covering obligation is live and no round is in flight. The
/// effect is recorded at round 1, and round 2 is claimed after it, so round 2's
/// confirmation clears the obligation as before.
#[tokio::test]
async fn r1318_2_a_round_claimed_after_the_late_effect_clears_it() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1318-2g").await;
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    adapter.pending.store(false, Ordering::SeqCst);
    r1318_next_round_clears(&w, &adapter, &gid, cap).await;
}

/// Red at 8d17ace9 (§13.18 item 3). The supervisor's cap (3) is in force when the
/// grant is revoked, so the record is created with it. Its obligation reaches that
/// cap in a round whose completion commit fails, so it is not yet marked `stopped`.
/// Then an in-process restart: recovery confirms the effect late and reaches
/// `cleanup` before any supervisor exists. Judged by its own cap, the obligation is
/// not live, so it is re-armed and the next round calls the adapter. Judged by the
/// default cap (8), it would be skipped as live, and the supervisor's next pass would
/// stop the record without a call.
#[tokio::test]
async fn r1318_3_restart_recovery_judges_a_record_by_the_lower_cap_it_was_created_with() {
    let cap = 3u32;
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    faults.arm_after_effect(w.fake.clone());
    let e = err(w
        .ops
        .ensure(
            &unattended(501),
            ensure_req("r1318-3", "r1318-3-work", &[("h1", "deploy")]),
        )
        .await);
    assert_eq!(e.code, Code::StateUnavailable);
    let op = e.operation_id.clone().unwrap();
    let gid = r1313_grant_of(&w, &op);
    *faults.after_effect_of.lock().unwrap() = None;
    let sup = r1312_supervisor(&w, cap);
    r1313_revoke(&w, &gid, "r1318-3-revoke").await;
    assert_eq!(adapter.calls(), 1);
    while adapter.calls() < cap as usize - 1 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    // The round that reaches the cap: its completion commit fails.
    *adapter.faults.lock().unwrap() = Some(faults.clone());
    while adapter.calls() < cap as usize {
        let _ = sup.scheduler_pass().await;
        w.clock.advance(10 * Duration::from_secs(1));
    }
    *adapter.faults.lock().unwrap() = None;
    faults.armed.store(false, Ordering::SeqCst);
    drop(sup);
    let rec = r1312_record(&w, &gid).expect("still pending");
    let owed = r1317_owed(&rec, &gid).expect("the obligation");
    assert_eq!(owed.attempts, Some(cap), "at its cap");
    assert!(
        !owed.stopped && !rec.stopped,
        "not yet marked stopped: {rec:?}"
    );
    // Restart: the late confirmation, in recovery, before any supervisor exists.
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(
        w.op(&op).state,
        OperationState::Failed,
        "recovery settled it"
    );
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
    assert_eq!(adapter.calls(), cap as usize, "no immediate call");
    let rec = r1312_record(&w, &gid).expect("still pending");
    let owed = r1317_owed(&rec, &gid).expect("the obligation");
    assert_eq!(
        owed.attempts,
        Some(0),
        "not live at its own cap: re-armed: {rec:?}"
    );
    assert!(!owed.stopped && !rec.stopped);
    // The next round (due at once: the restart found the failed completion's claim
    // uncompleted, §13.13 item 4) calls the adapter.
    let calls = adapter.calls();
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..3 {
        if adapter.calls() > calls {
            break;
        }
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(
        adapter.calls(),
        calls + 1,
        "the next round calls the adapter"
    );
}

/// Red at 8d17ace9 (§13.18 item 4, [MEDIUM] "the bound skips a real late effect").
/// The covering record ran to its cap (stopped), and the bound is reached: the very
/// effect whose late confirmation arrives next already re-armed this record once
/// (written here as the record would hold it). The bound allows no second re-arm,
/// but it never suppresses the call: `cleanup` makes exactly one immediate call
/// after the late effect. Its pending answer stays tracked as the grant's
/// obligation (stopped, still visible), and nothing else calls.
#[tokio::test]
async fn r1318_4_a_bounded_late_effect_with_every_obligation_stopped_makes_one_immediate_call() {
    let cap = 3u32;
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1318-4c").await;
    r1317_run_to_cap(&w, &adapter, &gid, cap).await;
    let (effect_adapter, token) = match r1314_effects(&w, &op).last() {
        Some(heimdall_domain::operation::EffectReceipt::Attempted {
            adapter,
            effect_token,
        }) => (adapter.clone(), effect_token.clone()),
        other => panic!("the attempt: {other:?}"),
    };
    w.store
        .transaction(|tx| {
            let r = tx.remote_revocation(&gid)?.unwrap();
            let mut v = serde_json::to_value(&r).unwrap();
            v["rearmed_effects"] = serde_json::json!([{
                "grant": gid,
                "adapter": effect_adapter,
                "effect_token": token,
                "confirmed": true,
            }]);
            tx.set_remote_revocation(&serde_json::from_value(v).unwrap())
        })
        .unwrap();
    let bounded = r1312_record(&w, &gid).unwrap();
    assert!(bounded.stopped && bounded.obligations.iter().all(|o| o.stopped));
    // The late confirmation (restart recovery).
    r1310_restart_pending(&mut w, &adapter).await;
    assert_eq!(
        w.op(&op).state,
        OperationState::Failed,
        "recovery settled it"
    );
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect was confirmed late"
    );
    assert_eq!(
        adapter.calls(),
        cap as usize + 1,
        "exactly one immediate call after the late effect"
    );
    let rec = r1312_record(&w, &gid).expect("its pending answer stays tracked");
    let owed = r1317_owed(&rec, &gid).expect("the grant's obligation");
    assert!(
        owed.stopped && rec.stopped,
        "the bound allows no re-arm: {rec:?}"
    );
    let sup = r1312_supervisor(&w, cap);
    for _ in 0..4 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(adapter.calls(), cap as usize + 1, "and nothing else calls");
}

/// Guard (§13.18 item 2; green at 8d17ace9). The effect is recorded at round 1 by
/// the late confirmation's skip. Then the owner revokes the grant again, which
/// re-arms the record and restarts its round count. The effect now precedes every
/// round claimed after that, so the re-armed first round (round 1 again) clears
/// the obligation with its confirmation. If the recorded round were kept, the
/// restarted count would not pass it for several rounds.
#[tokio::test]
async fn r1318_2_an_explicit_revoke_after_a_recorded_effect_clears_it_with_its_own_round() {
    let (mut w, adapter, op, gid) = r1317_revoked_before_its_confirmation("r1318-2x").await;
    r1317_late_confirmation(&mut w, &adapter, &op).await;
    adapter.pending.store(false, Ordering::SeqCst);
    let done = r1313_revoke(&w, &gid, "r1318-2x-again").await;
    assert_eq!(adapter.calls(), 2, "the re-armed first round");
    assert!(done.remote_pending.is_empty(), "{done:?}");
    assert!(r1312_record(&w, &gid).is_none(), "cleared");
}

/// Red at 8d17ace9 (§13.18 item 2; a round superseded by an explicit revoke). A
/// supervisor round is in flight (answer held: a confirmation) when the late
/// credential effect lands; `cleanup` skips and records it. The owner then revokes
/// the grant again: the record is re-armed, its count restarts, and its first round
/// calls the adapter after the effect and gets a pending answer. The superseded
/// round's confirmation then arrives. It answers a call made before the credential
/// existed, and its claim is no longer the record's, so it is not ordered against
/// the effect: it must not clear the obligation.
#[tokio::test]
async fn r1318_2_a_round_superseded_by_an_explicit_revoke_does_not_clear_a_late_effect() {
    let cap = 3u32;
    let (w, adapter) = r1310_pending_world().await;
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1318-2s").await;
    r1313_revoke(&w, &gid, "r1318-2s-revoke").await;
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_revoke.store(true, Ordering::SeqCst);
    let ops = w.ops.clone();
    let g = gid.clone();
    let round = tokio::spawn(async move { ops.retry_remote_revocation(&g, cap).await });
    adapter.revoke_entered.notified().await;
    assert_eq!(adapter.calls(), 2, "round 2's call went out");
    r1318_apply_late(&w, &adapter, &op, ensure).await;
    assert_eq!(adapter.calls(), 2, "no immediate call");
    // The owner revokes again: a re-armed first round, after the effect, pending.
    adapter.pending.store(true, Ordering::SeqCst);
    let done = r1313_revoke(&w, &gid, "r1318-2s-again").await;
    assert_eq!(adapter.calls(), 3);
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    assert_eq!(
        r1312_record(&w, &gid).unwrap().attempts,
        1,
        "the count restarted"
    );
    // The superseded round's confirmation arrives.
    adapter.revoke_release.notify_one();
    let left = round.await.unwrap().unwrap();
    let rec = left.expect("still pending: the superseded round preceded the effect");
    assert!(
        r1317_owed(&rec, &gid).is_some(),
        "the obligation stays: {rec:?}"
    );
    adapter.pending.store(false, Ordering::SeqCst);
    r1318_next_round_clears(&w, &adapter, &gid, cap).await;
}

/// Red at 8d17ace9 (§13.18 item 3; the supervisor). The supervisor's cap (3) is in
/// force when the grant is revoked, so the record is created with it. A later
/// supervisor configured with a higher cap (5) judges the record by the lower of
/// the two: rounds stop at 3 in all, the first local denial included, as restart
/// recovery would judge it.
#[tokio::test]
async fn r1318_3_the_supervisor_judges_a_record_by_the_lower_cap_it_was_created_with() {
    let (w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1318-3s", "r1318-3s-work", "h1", "1h").await;
    let _created_with = r1312_supervisor(&w, 3);
    let done = r1313_revoke(&w, &g.grant_id, "r1318-3s-revoke").await;
    assert_eq!(done.remote_pending, vec![g.grant_id.clone()]);
    assert_eq!(adapter.calls(), 1);
    let sup = r1312_supervisor(&w, 5);
    for _ in 0..10 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert!(rec.stopped, "stopped at its own cap: {rec:?}");
    assert_eq!(adapter.calls(), 3, "3 rounds in all, not 5");
}

/// Red at 8d17ace9 (§13.18 item 3; a withdrawal's record). The supervisor's cap (3)
/// is in force when the grant's authority is withdrawn at use, so the withdrawal's
/// record is created with it. A later supervisor configured with a higher cap (5)
/// judges it by the lower of the two: 3 rounds in all, the local denial included.
#[tokio::test]
async fn r1318_3_a_withdrawals_record_keeps_the_cap_it_was_created_with() {
    let (w, adapter) = r1310_pending_world().await;
    let _created_with = r1312_supervisor(&w, 3);
    let g = r1310_withdrawn_pending(&w, &adapter, "r1318-3w").await;
    assert!(
        r1312_record(&w, &g.grant_id).is_some(),
        "the withdrawal's record"
    );
    let sup = r1312_supervisor(&w, 5);
    for _ in 0..10 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    assert!(rec.stopped, "stopped at its own cap: {rec:?}");
    assert_eq!(adapter.calls(), 3, "3 rounds in all, not 5");
}

/// Red at 8d17ace9 (§13.18 item 3; a claim after a failed completion). The record
/// is created with the supervisor's cap (3). The round that reaches that cap has
/// its completion commit fail, so its obligation is not marked stopped. A
/// supervisor configured with a higher cap (5) then judges the record by the lower
/// of the two and stops it without another call.
#[tokio::test]
async fn r1318_3_a_record_at_its_own_cap_after_a_failed_completion_is_stopped_without_a_call() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let g = r136_ready(&w, "r1318-3f", "r1318-3f-work", "h1", "1h").await;
    let sup = r1312_supervisor(&w, 3);
    r1313_revoke(&w, &g.grant_id, "r1318-3f-revoke").await;
    assert_eq!(adapter.calls(), 1);
    while adapter.calls() < 2 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    // The round that reaches the cap: its completion commit fails.
    *adapter.faults.lock().unwrap() = Some(faults.clone());
    while adapter.calls() < 3 {
        let _ = sup.scheduler_pass().await;
        w.clock.advance(10 * Duration::from_secs(1));
    }
    *adapter.faults.lock().unwrap() = None;
    faults.armed.store(false, Ordering::SeqCst);
    drop(sup);
    let rec = r1312_record(&w, &g.grant_id).expect("still pending");
    let owed = r1317_owed(&rec, &g.grant_id).expect("the obligation");
    assert_eq!(owed.attempts, Some(3), "at its own cap");
    assert!(
        !owed.stopped && !rec.stopped,
        "not yet marked stopped: {rec:?}"
    );
    let sup = r1312_supervisor(&w, 5);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(10 * Duration::from_secs(1));
    }
    assert_eq!(adapter.calls(), 3, "no call past its own cap");
    assert!(
        r1312_record(&w, &g.grant_id)
            .expect("still pending")
            .stopped
    );
}

// =================================================================================
// ⟨r2.16⟩ ADR-0006 §13.19 (code review round 7, W01 and W02).
//
// * Item 1 (W01): every claim of a pending remote record is identified by a
//   persisted `claim_seq` that is never reset, not even by an explicit revoke's
//   re-arm. A completion clears an obligation only when its claim is still the
//   record's current claim and was made after the obligation's recorded effect.
// * Item 2 (W02): the transaction that settles an operation with an applied (or
//   possibly applied) credential effect also records who makes the call after it: a
//   covering obligation, registered or re-armed there, or a recoverable cleanup
//   intent that restart recovery and the supervisor process even once the
//   operation has settled.
//
// Only public APIs are used, so every case also runs against the base commit
// 8263ee6c (red there). "Crash" and "restart" are in-process (module docs).
// =================================================================================

/// ⟨r2.16⟩ Store fault hook (production `FaultHook`): fails the `n`-th next `point`
/// (0 = the next one) once, then is disarmed. Transactions run while `paused` is set
/// (the test's own reads) neither fire nor count.
#[derive(Default)]
struct R1319Countdown {
    at: std::sync::Mutex<Option<(FaultPoint, u32)>>,
    paused: AtomicBool,
    fired: AtomicUsize,
}

impl R1319Countdown {
    fn arm(&self, point: FaultPoint, n: u32) {
        *self.at.lock().unwrap() = Some((point, n));
    }
    fn disarm(&self) {
        *self.at.lock().unwrap() = None;
    }
}

impl FaultHook for R1319Countdown {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if self.paused.load(Ordering::SeqCst) {
            return FaultAction::Continue;
        }
        let mut at = self.at.lock().unwrap();
        match *at {
            Some((p, 0)) if p == point => {
                *at = None;
                self.fired.fetch_add(1, Ordering::SeqCst);
                FaultAction::Fail
            }
            Some((p, n)) if p == point => {
                *at = Some((p, n - 1));
                FaultAction::Continue
            }
            _ => FaultAction::Continue,
        }
    }
}

/// An explicit owner revoke of `grant` in its own task (its first round's call may
/// be held).
fn r1319_spawn_revoke(
    w: &World,
    grant: &heimdall_contract::ids::GrantId,
    rid: &str,
) -> tokio::task::JoinHandle<OpResult<heimdall_contract::request::RevokeData>> {
    let ops = w.ops.clone();
    let req = RevokeRequest {
        grant_id: grant.clone(),
        request_id: RequestId::parse(rid).unwrap(),
    };
    tokio::spawn(async move { ops.revoke(&unattended(501), req).await })
}

/// Whether `grant`'s record holds a live obligation for the fixture adapter: neither
/// it nor the record stopped, and below `cap` rounds.
fn r1319_live(w: &World, grant: &heimdall_contract::ids::GrantId, cap: u32) -> bool {
    r1312_record(w, grant).is_some_and(|r| {
        !r.stopped
            && r1317_owed(&r, grant)
                .is_some_and(|o| !o.stopped && r.obligation_attempts(&o) < r.round_cap(cap))
    })
}

/// Run the production supervisor (default back-off, cap 8) until `grant`'s record is
/// stopped at its cap: every round answered pending, all before any credential
/// existed.
async fn r1319_run_to_production_cap(
    w: &World,
    adapter: &PendingCounter,
    grant: &heimdall_contract::ids::GrantId,
) {
    let sup = r1310_supervisor(w);
    for _ in 0..40 {
        if r1312_record(w, grant).is_some_and(|r| r.stopped) {
            break;
        }
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(MINUTE);
    }
    let rec = r1312_record(w, grant).expect("still pending");
    assert!(rec.stopped, "capped: {rec:?}");
    assert_eq!(adapter.calls(), 8, "the production cap of 8 rounds");
    assert_eq!(w.effects(), 0, "every call preceded the effect");
    assert_eq!(adapter.calls_after_effect(grant), None);
}

/// After an in-process restart: the applied effect has a live owning obligation or a
/// call made after it, and six supervisor passes (production back-off) make that
/// call.
async fn r1319_restart_then_a_call_follows_the_effect(
    w: &mut World,
    adapter: &Arc<PendingCounter>,
    grant: &heimdall_contract::ids::GrantId,
) {
    r1310_restart_pending(w, adapter).await;
    assert!(
        r1319_live(w, grant, 8) || adapter.calls_after_effect(grant) > Some(0),
        "the applied effect has neither a live owning obligation nor a call after it: {:?}",
        r1312_record(w, grant)
    );
    let sup = r1310_supervisor(w);
    for _ in 0..6 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(MINUTE);
    }
    assert!(
        adapter.calls_after_effect(grant) > Some(0),
        "no call was made after the effect: {:?}",
        r1312_record(w, grant)
    );
}

/// Red at 8263ee6c (§13.19 item 1, W01; the reviewer's ABA on a frozen clock). Revoke
/// A's first round calls before the credential exists and its confirmation is held.
/// The late effect is recorded on the live obligation. Revoke B, at the same
/// timestamp, re-arms the record (its count restarts) and its first round's pending
/// answer is held: B's claim carries A's timestamp and count. A's confirmation is
/// superseded and must not clear the obligation; B's pending answer keeps it; it
/// survives a restart.
#[tokio::test]
async fn r1319_1_a_superseded_first_round_confirmation_never_erases_a_newer_pending_obligation() {
    let (mut w, adapter) = r1310_pending_world().await;
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-1").await;
    // Revoke A: its call confirms the state before the effect; the answer is held.
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let a = r1319_spawn_revoke(&w, &gid, "r1319-1-a");
    adapter.held_entered.notified().await;
    let claimed = r1312_record(&w, &gid).expect("A's record");
    assert_eq!(claimed.attempts, 1, "A's first round");
    assert!(claimed.claimed_at.is_some());
    // The late effect lands while A's round is in flight: the live obligation owns it.
    r1318_apply_late(&w, &adapter, &op, ensure).await;
    assert_eq!(adapter.calls(), 1, "no immediate call");
    assert!(r1319_live(&w, &gid, 8));
    // Revoke B at the same instant: a re-armed first round whose answer is pending.
    adapter.pending.store(true, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let b = r1319_spawn_revoke(&w, &gid, "r1319-1-b");
    adapter.held_entered.notified().await;
    assert_eq!(adapter.calls(), 2, "B's call went out after the effect");
    let rearmed = r1312_record(&w, &gid).expect("B's record");
    assert_eq!(
        (rearmed.claimed_at, rearmed.attempts),
        (claimed.claimed_at, claimed.attempts),
        "a frozen clock: B's claim has A's timestamp and count"
    );
    // A's superseded confirmation arrives.
    assert!(adapter.release_held(0));
    let _ = a.await.unwrap();
    let rec = r1312_record(&w, &gid).expect("the obligation survives A's confirmation");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
    // B's pending answer arrives.
    assert!(adapter.release_held(0));
    let done = ok(b.await.unwrap()).data;
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    let rec = r1312_record(&w, &gid).expect("B's pending answer keeps the obligation");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
    r1310_restart_pending(&mut w, &adapter).await;
    let rec = r1312_record(&w, &gid).expect("the obligation survives a restart");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
}

/// Red at 8263ee6c (§13.19 item 1, W01 without any late effect; the claim identity
/// alone). An active grant is revoked: revoke A's first round calls and its
/// confirmation is held. Revoke B, at the same instant, re-arms the record and its
/// first round's pending answer is held: B's claim has A's timestamp and count. A's
/// superseded confirmation must clear nothing, since B's later call answered
/// pending; B's answer keeps the obligation, and it survives a restart. (A re-arm
/// that reset the sequence would give B A's identity again.)
#[tokio::test]
async fn r1319_1_a_superseded_confirmation_never_erases_a_newer_pending_obligation_without_an_effect()
 {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1319-1n", "r1319-1n-work", "h1", "1h").await;
    let gid = g.grant_id.clone();
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let a = r1319_spawn_revoke(&w, &gid, "r1319-1n-a");
    adapter.held_entered.notified().await;
    let claimed = r1312_record(&w, &gid).expect("A's record");
    adapter.pending.store(true, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let b = r1319_spawn_revoke(&w, &gid, "r1319-1n-b");
    adapter.held_entered.notified().await;
    assert_eq!(adapter.calls(), 2);
    let rearmed = r1312_record(&w, &gid).expect("B's record");
    assert_eq!(
        (rearmed.claimed_at, rearmed.attempts),
        (claimed.claimed_at, claimed.attempts),
        "a frozen clock: B's claim has A's timestamp and count"
    );
    assert!(adapter.release_held(0));
    let _ = a.await.unwrap();
    let rec = r1312_record(&w, &gid).expect("A's superseded confirmation clears nothing");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
    assert!(adapter.release_held(0));
    let done = ok(b.await.unwrap()).data;
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    assert_eq!(w.grant(&gid).state, GrantState::Revoking);
    r1310_restart_pending(&mut w, &adapter).await;
    let rec = r1312_record(&w, &gid).expect("the obligation survives a restart");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
}

/// Red at 8263ee6c (§13.19 item 1; a claim that outlives its record, found by
/// [`r1319_props`]). Revoke A's first round calls and its confirmation is held. A
/// supervisor round then confirms and completes, and the record is removed. Revoke B
/// creates a new record for the same root, and its first round's pending answer is
/// held. A's confirmation arrives last: its claim's sequence was never assigned
/// again, so it is superseded and clears nothing; B's pending answer keeps the new
/// obligation, also across a restart.
#[tokio::test]
async fn r1319_1_a_claim_that_outlives_its_records_removal_never_erases_a_new_records_obligation() {
    let (mut w, adapter) = r1310_pending_world().await;
    let g = r136_ready(&w, "r1319-1x", "r1319-1x-work", "h1", "1h").await;
    let gid = g.grant_id.clone();
    adapter.pending.store(false, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let a = r1319_spawn_revoke(&w, &gid, "r1319-1x-a");
    adapter.held_entered.notified().await;
    let rounds = w.ops.retry_remote_revocation(&gid, 3).await.unwrap();
    assert!(
        rounds.is_none(),
        "the round confirmed: the record is removed"
    );
    assert!(r1312_record(&w, &gid).is_none());
    assert_eq!(adapter.calls(), 2);
    adapter.pending.store(true, Ordering::SeqCst);
    adapter.hold_queued.store(true, Ordering::SeqCst);
    let b = r1319_spawn_revoke(&w, &gid, "r1319-1x-b");
    adapter.held_entered.notified().await;
    assert_eq!(adapter.calls(), 3, "B's call went out last");
    assert!(r1312_record(&w, &gid).is_some(), "B's new record");
    assert!(adapter.release_held(0));
    let _ = a.await.unwrap();
    let rec = r1312_record(&w, &gid).expect("A's confirmation clears nothing of B's record");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
    assert!(adapter.release_held(0));
    let done = ok(b.await.unwrap()).data;
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    r1310_restart_pending(&mut w, &adapter).await;
    let rec = r1312_record(&w, &gid).expect("the obligation survives a restart");
    assert!(r1317_owed(&rec, &gid).is_some(), "{rec:?}");
}

/// Red at 8263ee6c (§13.19 item 2, W02; the reviewer's scenario). The preparation is
/// held, the grant revoked and the ensure cancelled, and the covering record runs to
/// the production cap of 8, all before the credential exists. The preparation then
/// applies it, and the commit of its late `Confirmed` receipt fails after it
/// committed (`AfterCommit`, armed only once the effect applied). After a restart
/// the applied effect still has a live owning obligation, and a call follows it.
#[tokio::test]
async fn r1319_2_a_restart_after_the_late_confirmation_commit_keeps_the_capped_records_cleanup() {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let _cap = r1310_supervisor(&w);
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-2a").await;
    let done = r1313_revoke(&w, &gid, "r1319-2a-revoke").await;
    assert_eq!(done.remote_pending, vec![gid.clone()]);
    let c = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(c.data["may_have_external_effect"], true);
    r1319_run_to_production_cap(&w, &adapter, &gid).await;
    faults.arm_after_effect(w.fake.clone());
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the post-commit fault"
    );
    assert_eq!(w.op(&op).state, OperationState::Cancelled);
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the late `Confirmed` receipt is durable"
    );
    r1319_restart_then_a_call_follows_the_effect(&mut w, &adapter, &gid).await;
}

/// Red at 8263ee6c (§13.19 item 2; the recheck refusal boundary). As in
/// [`r1319_2_a_restart_after_the_late_confirmation_commit_keeps_the_capped_records_cleanup`],
/// but the ensure is not cancelled: the late confirmation continues to `Recheck`,
/// which refuses the revoked grant, and that refusal's commit fails after it
/// committed. After a restart a call follows the effect.
#[tokio::test]
async fn r1319_2_a_restart_after_a_recheck_refusal_commit_keeps_the_capped_records_cleanup() {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        hook: ArmAt::new(EnsureStage::Recheck, faults.clone()),
        ..Setup::default()
    })
    .await;
    let _cap = r1310_supervisor(&w);
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-2r").await;
    r1313_revoke(&w, &gid, "r1319-2r-revoke").await;
    r1319_run_to_production_cap(&w, &adapter, &gid).await;
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the refusal's fault"
    );
    assert_eq!(
        w.op(&op).state,
        OperationState::Failed,
        "refused at recheck"
    );
    r1319_restart_then_a_call_follows_the_effect(&mut w, &adapter, &gid).await;
}

/// Red at 8263ee6c (§13.19 item 2; the cancellation boundary). The preparation is
/// held, the grant revoked, and the record runs to the production cap before the
/// credential exists. The preparation then applies and confirms it, and the drive
/// stops before `Probe` (the operation still runs). The ensure is then cancelled,
/// and the cancellation's commit fails after it committed. After a restart (the
/// operation is settled, so recovery never drives it) a call follows the effect.
#[tokio::test]
async fn r1319_2_a_restart_after_a_cancellation_commit_keeps_the_capped_records_cleanup() {
    let faults = Arc::new(R1319Countdown::default());
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        hook: ScriptedStageHook::new([(EnsureStage::Probe, Code::ServiceUnavailable)], []),
        ..Setup::default()
    })
    .await;
    let _cap = r1310_supervisor(&w);
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-2c").await;
    r1313_revoke(&w, &gid, "r1319-2c-revoke").await;
    r1319_run_to_production_cap(&w, &adapter, &gid).await;
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1);
    assert_eq!(
        w.op(&op).state,
        OperationState::Running,
        "stopped before Probe"
    );
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "the effect is confirmed"
    );
    // The cancellation's own transaction is the second commit: the first is the
    // time gate's assessment of `now`.
    faults.arm(FaultPoint::AfterCommit, 1);
    let e = err(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(e.code, Code::StateUnavailable, "the cancellation's fault");
    assert_eq!(faults.fired.load(Ordering::SeqCst), 1);
    assert_eq!(w.op(&op).state, OperationState::Cancelled);
    r1319_restart_then_a_call_follows_the_effect(&mut w, &adapter, &gid).await;
}

/// An ensure whose prepared facts miss the caller's offline minimum (the fixture
/// credential covers 1 h offline, 1.5 h is required), so `Commit` refuses it after
/// the effect applied and was confirmed. No record covers the grant: its cleanup is
/// the immediate call. The refusal's commit fails after it committed (`AfterCommit`
/// armed when `Commit` starts).
async fn r1319_commit_refused_after_commit(tag: &str) -> (World, Arc<PendingCounter>, OperationId) {
    let faults = Armed::new(FaultPoint::AfterCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        hook: ArmAt::new(EnsureStage::Commit, faults.clone()),
        ..Setup::default()
    })
    .await;
    let mut req = ensure_req(tag, &format!("{tag}-work"), &[("h1", "deploy")]);
    req.required_capabilities.offline_until = Some(shift(t0(), 5400));
    let e = err(w.ops.ensure(&unattended(501), req).await);
    assert_eq!(
        e.code,
        Code::StateUnavailable,
        "the refusal's post-commit fault"
    );
    assert_eq!(faults.fired.load(Ordering::SeqCst), 1);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::Failed, "refused at commit");
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    (w, adapter, op)
}

/// Red at 8263ee6c (§13.19 item 2; the commit refusal boundary, an uncovered grant).
/// The immediate call the refusal owes is a cleanup intent written in the refusal's
/// transaction: restart recovery makes it, although the operation is settled.
#[tokio::test]
async fn r1319_2_a_restart_after_a_commit_refusal_commit_makes_the_owed_immediate_call() {
    let (mut w, adapter, op) = r1319_commit_refused_after_commit("r1319-2m").await;
    let gid = r1313_grant_of(&w, &op);
    r1310_restart_pending(&mut w, &adapter).await;
    assert!(
        adapter.calls_after_effect(&gid) > Some(0),
        "restart recovery made the owed call after the effect"
    );
    assert!(
        r1312_record(&w, &gid).is_none(),
        "no record covers the grant"
    );
}

/// Red at 8263ee6c (§13.19 item 2; the commit refusal boundary, without a restart).
/// As in [`r1319_2_a_restart_after_a_commit_refusal_commit_makes_the_owed_immediate_call`],
/// but the process keeps running: the supervisor's next pass makes the owed call,
/// once, and later passes make no other.
#[tokio::test]
async fn r1319_2_the_supervisor_makes_the_immediate_call_a_failed_refusal_commit_owes() {
    let (w, adapter, op) = r1319_commit_refused_after_commit("r1319-2s").await;
    let gid = r1313_grant_of(&w, &op);
    let sup = r1310_supervisor(&w);
    for _ in 0..3 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(MINUTE);
    }
    assert_eq!(
        adapter.calls_after_effect(&gid),
        Some(1),
        "the supervisor made the owed call once"
    );
}

/// ADR-0006 §13.20 item 1 (spec §12.3). While a cleanup intent still owes the applied
/// credential a call, `inspect grants` lists the grant, ended or not, with
/// `cleanup_pending: true`. Once the supervisor has made the owed call and removed
/// the intent, the field is gone.
#[tokio::test]
async fn r1320_1_a_pending_cleanup_intent_is_visible_until_its_call_is_made() {
    let (w, adapter, op) = r1319_commit_refused_after_commit("r1320-1").await;
    let gid = r1313_grant_of(&w, &op);
    let before = r1310_view(&w, &gid).await;
    assert_eq!(
        before["cleanup_pending"],
        serde_json::json!(true),
        "an owed cleanup call is visible: {before}"
    );
    let sup = r1310_supervisor(&w);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(
        adapter.calls_after_effect(&gid),
        Some(1),
        "the supervisor made the owed call"
    );
    let r = ok(w
        .ops
        .inspect(
            &unattended(501),
            heimdall_contract::request::InspectRequest {
                subject: heimdall_contract::request::InspectSubject::Grants,
                preview: None,
            },
        )
        .await);
    let after = r.data["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["grant_id"] == serde_json::json!(gid))
        .cloned();
    assert!(
        after
            .as_ref()
            .is_none_or(|v| v.get("cleanup_pending").is_none()),
        "no cleanup is pending once the call was made: {after:?}"
    );
}

/// Red at 8263ee6c (§13.19 item 2; a late `Uncertain` receipt). The ensure is
/// cancelled while its preparation is in flight and no record covers the grant. The
/// preparation then applies the credential but loses its reply (`OutcomeUnknown`),
/// so the cancelled operation records an `Uncertain` receipt: that transaction owes
/// the possibly applied credential a call after it, and the call is made.
#[tokio::test]
async fn r1319_2_a_late_uncertain_receipt_after_a_cancellation_gets_a_call_after_the_effect() {
    let (mut w, adapter) = r1312_pending_world_with(Setup {
        script: vec![FakeStep::ApplyButLoseReply(outcome())],
        ..Setup::default()
    })
    .await;
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-2u").await;
    let c = ok(w
        .ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    assert_eq!(c.data["may_have_external_effect"], true);
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "applied, its reply lost");
    assert!(
        r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Uncertain { .. }
        )),
        "the late `Uncertain` receipt"
    );
    r1319_restart_then_a_call_follows_the_effect(&mut w, &adapter, &gid).await;
}

/// Red at 8263ee6c (§13.19 item 2; a late confirmation that never becomes durable).
/// The ensure is cancelled while its preparation is in flight (no record covers the
/// grant). The preparation applies the credential, and the commit of its late
/// `Confirmed` receipt fails before it committed, so no receipt records the
/// confirmation. The cancellation's transaction already owed the possibly applied
/// effect a call made after it: that call follows the effect in this process.
#[tokio::test]
async fn r1319_2_a_late_confirmation_that_fails_to_commit_still_gets_a_call_after_the_effect() {
    let faults = Armed::new(FaultPoint::BeforeCommit);
    let (w, adapter) = r1312_pending_world_with(Setup {
        faults: faults.clone(),
        ..Setup::default()
    })
    .await;
    let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, "r1319-2b").await;
    ok(w.ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    faults.arm_after_effect(w.fake.clone());
    adapter.prepare_release.notify_one();
    let _ = ensure.await.unwrap();
    assert_eq!(w.effects(), 1, "the credential effect was applied");
    assert_eq!(
        faults.fired.load(Ordering::SeqCst),
        1,
        "the failed late commit"
    );
    assert!(
        !r1314_effects(&w, &op).iter().any(|e| matches!(
            e,
            heimdall_domain::operation::EffectReceipt::Confirmed { .. }
        )),
        "no `Confirmed` receipt became durable"
    );
    assert!(
        adapter.calls_after_effect(&gid) > Some(0),
        "a call followed the effect"
    );
}

/// Red at 8263ee6c (§13.19 item 2; a crash after the effect of a cancelled
/// preparation). The ensure is cancelled while its preparation is in flight (no
/// record covers the grant); the preparation applies the credential and never
/// returns. Supervisor passes leave the call to the preparation while it is in
/// flight. After an in-process restart, recovery makes the call the cancellation
/// owed, although the operation is settled.
#[tokio::test]
async fn r1319_2_a_restart_after_a_cancelled_preparation_applied_its_effect_makes_the_owed_call() {
    let (mut w, adapter) = r1310_pending_world().await;
    adapter.hang_after_prepare.store(true, Ordering::SeqCst);
    let (op, gid, _ensure) = r1318_held_ensure(&w, &adapter, "r1319-2h").await;
    ok(w.ops
        .cancel(
            &unattended(501),
            CancelRequest {
                operation_id: op.clone(),
            },
        )
        .await);
    adapter.prepare_release.notify_one();
    for _ in 0..1000 {
        if w.effects() > 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(w.effects(), 1, "applied; the preparation never returns");
    let sup = r1310_supervisor(&w);
    for _ in 0..3 {
        sup.scheduler_pass().await.unwrap();
        w.clock.advance(MINUTE);
    }
    assert_eq!(
        adapter.calls_after_effect(&gid),
        Some(0),
        "left to the preparation while it is in flight"
    );
    drop(sup);
    r1310_restart_pending(&mut w, &adapter).await;
    assert!(
        adapter.calls_after_effect(&gid) > Some(0),
        "restart recovery made the owed call after the effect"
    );
}

/// ⟨r2.16⟩ ADR-0006 §13.19 item 3: the cleanup invariant over real transitions
/// (proptest, 1024 cases, fixed seed unless `PROPTEST_RNG_SEED` is set; failures
/// persist to `tests/model/operations.proptest-regressions`). 1024 rather than 256
/// cases: the shortest sequences that defeat a claim sequence reset by a re-arm
/// first appear after several hundred cases at this seed.
///
/// One grant is prepared by an ensure whose preparation is held (no credential
/// yet), with a [`PendingCounter`] as the only adapter and the supervisor's cap of
/// [`r1319_props::CAP`] rounds. The generated steps drive the production
/// `Operations` and `Supervisor`: explicit revokes (a re-arm once a record exists)
/// and claimed supervisor rounds, each with its call's answer (pending or a
/// confirmation) held or not; supervisor passes; the late effect (the preparation
/// released) and the cleanup it reaches; a cancellation; the release of any held
/// answer, in any order; a store fault (`BeforeCommit` or `AfterCommit`) at one of
/// the next commits; and an in-process restart, a crash for everything in flight
/// (held answers never arrive, a held preparation never applies). Every call and
/// effect is logged in order by the adapter.
///
/// * After every step: an obligation disappears only when the latest call to its
///   adapter for its grant was answered with a confirmation (no obligation is lost
///   while its adapter's last answer was pending).
/// * At the end (a final restart, then supervisor passes): the applied effect of a
///   grant that is not in use has a live owning obligation or a call made after it,
///   and a call follows it.
mod r1319_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// The supervisor's cap of rounds per obligation.
    pub(super) const CAP: u32 = 3;

    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 1024,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x1319_0003);
        }
        c
    }

    fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
        f: F,
    ) -> Result<(), TestCaseError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[derive(Debug, Clone)]
    enum Step {
        /// An explicit revoke; its first round's call answers `pending`, held if
        /// `hold`.
        Revoke { hold: bool, pending: bool },
        /// A supervisor round claimed now (`retry_remote_revocation`), likewise.
        Round { hold: bool, pending: bool },
        /// A supervisor pass (its calls answer `pending`), then 10 s.
        Pass { pending: bool },
        /// The held preparation applies its credential: the late effect.
        Effect,
        /// The ensure is cancelled.
        Cancel,
        /// The held answer at this index (modulo those held) arrives.
        Release(usize),
        /// A store fault at the `n`-th next `AfterCommit` (or `BeforeCommit`).
        Fault { after: bool, n: u32 },
        /// An in-process restart: a crash for everything in flight.
        Restart,
    }

    fn step_s() -> impl Strategy<Value = Step> {
        prop_oneof![
            3 => (any::<bool>(), any::<bool>())
                .prop_map(|(hold, pending)| Step::Revoke { hold, pending }),
            3 => (any::<bool>(), any::<bool>())
                .prop_map(|(hold, pending)| Step::Round { hold, pending }),
            2 => any::<bool>().prop_map(|pending| Step::Pass { pending }),
            2 => Just(Step::Effect),
            2 => Just(Step::Cancel),
            3 => (0..3usize).prop_map(Step::Release),
            1 => (any::<bool>(), 0..3u32).prop_map(|(after, n)| Step::Fault { after, n }),
            1 => Just(Step::Restart),
        ]
    }

    struct Run {
        w: World,
        adapter: Arc<PendingCounter>,
        faults: Arc<R1319Countdown>,
        sup: heimdall_runtime::supervisor::Supervisor,
        op: OperationId,
        gid: heimdall_contract::ids::GrantId,
        /// The ensure while its preparation is held (alive, not yet applied).
        ensure: Option<tokio::task::JoinHandle<()>>,
        /// Tasks parked on a held answer, in the adapter's `held` order.
        parked: Vec<tokio::task::JoinHandle<()>>,
        revokes: usize,
    }

    impl Run {
        async fn new() -> Self {
            let faults = Arc::new(R1319Countdown::default());
            let (w, adapter) = r1312_pending_world_with(Setup {
                faults: faults.clone(),
                ..Setup::default()
            })
            .await;
            let sup = r1312_supervisor(&w, CAP);
            adapter.hold_prepare.store(true, Ordering::SeqCst);
            let ops = w.ops.clone();
            let req = ensure_req("r1319-p", "r1319-p-work", &[("h1", "deploy")]);
            let ensure = tokio::spawn(async move {
                let _ = ops.ensure(&unattended(501), req).await;
            });
            adapter.prepare_entered.notified().await;
            let op = w
                .store
                .transaction(|tx| tx.open_operations())
                .unwrap()
                .into_iter()
                .find(|o| o.state == OperationState::Running)
                .expect("the running ensure")
                .id;
            let gid = r1313_grant_of(&w, &op);
            Self {
                w,
                adapter,
                faults,
                sup,
                op,
                gid,
                ensure: Some(ensure),
                parked: Vec::new(),
                revokes: 0,
            }
        }

        /// Run `fut` in its own task. With `hold`, its next call's answer is held:
        /// the task parks there (or finishes without a call).
        async fn spawn(
            &mut self,
            hold: bool,
            fut: impl std::future::Future<Output = ()> + Send + 'static,
        ) {
            self.adapter.hold_queued.store(hold, Ordering::SeqCst);
            let mut task = tokio::spawn(fut);
            if !hold {
                let _ = task.await;
                return;
            }
            tokio::select! {
                biased;
                () = self.adapter.held_entered.notified() => self.parked.push(task),
                _ = &mut task => self.adapter.hold_queued.store(false, Ordering::SeqCst),
            }
        }

        async fn step(&mut self, step: &Step) {
            match *step {
                Step::Revoke { hold, pending } => {
                    self.adapter.pending.store(pending, Ordering::SeqCst);
                    self.revokes += 1;
                    let ops = self.w.ops.clone();
                    let req = RevokeRequest {
                        grant_id: self.gid.clone(),
                        request_id: RequestId::parse(&format!("r1319-p-{}", self.revokes)).unwrap(),
                    };
                    self.spawn(hold, async move {
                        let _ = ops.revoke(&unattended(501), req).await;
                    })
                    .await;
                }
                Step::Round { hold, pending } => {
                    self.adapter.pending.store(pending, Ordering::SeqCst);
                    let ops = self.w.ops.clone();
                    let g = self.gid.clone();
                    self.spawn(hold, async move {
                        let _ = ops.retry_remote_revocation(&g, CAP).await;
                    })
                    .await;
                }
                Step::Pass { pending } => {
                    self.adapter.pending.store(pending, Ordering::SeqCst);
                    let _ = self.sup.scheduler_pass().await;
                    self.w.clock.advance(10 * Duration::from_secs(1));
                }
                Step::Effect => {
                    if let Some(ensure) = self.ensure.take() {
                        self.adapter.prepare_release.notify_one();
                        let _ = ensure.await;
                    }
                }
                Step::Cancel => {
                    let _ = self
                        .w
                        .ops
                        .cancel(
                            &unattended(501),
                            CancelRequest {
                                operation_id: self.op.clone(),
                            },
                        )
                        .await;
                }
                Step::Release(i) => {
                    if !self.parked.is_empty() {
                        let i = i % self.parked.len();
                        assert!(self.adapter.release_held(i));
                        let _ = self.parked.remove(i).await;
                    }
                }
                Step::Fault { after, n } => {
                    let point = if after {
                        FaultPoint::AfterCommit
                    } else {
                        FaultPoint::BeforeCommit
                    };
                    self.faults.arm(point, n);
                }
                Step::Restart => self.restart().await,
            }
        }

        async fn restart(&mut self) {
            self.faults.disarm();
            // A crash: no held answer ever arrives and a held preparation never
            // applies (its task stays parked; nothing releases it again).
            self.adapter.held.lock().unwrap().clear();
            for t in self.parked.drain(..) {
                t.abort();
            }
            if let Some(t) = self.ensure.take() {
                t.abort();
            }
            self.adapter.hold_queued.store(false, Ordering::SeqCst);
            r1310_restart_pending(&mut self.w, &self.adapter).await;
            self.sup = r1312_supervisor(&self.w, CAP);
        }

        /// The grants that have an obligation in some record.
        fn owed(&self) -> BTreeSet<heimdall_contract::ids::GrantId> {
            self.faults.paused.store(true, Ordering::SeqCst);
            let records = self.w.store.transaction(|tx| tx.remote_revocations());
            self.faults.paused.store(false, Ordering::SeqCst);
            records
                .unwrap()
                .into_iter()
                .flat_map(|r| r.obligations.into_iter().map(|o| o.grant))
                .collect()
        }

        /// The answer of the latest call for `grant`: `Some(true)` pending,
        /// `Some(false)` a confirmation, `None` no call.
        fn last_answer(&self, grant: &heimdall_contract::ids::GrantId) -> Option<bool> {
            self.adapter
                .log
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find_map(|(g, call)| if g == grant { *call } else { None })
        }

        fn check_none_lost(
            &self,
            before: &BTreeSet<heimdall_contract::ids::GrantId>,
            step: &Step,
        ) -> Result<(), TestCaseError> {
            let after = self.owed();
            for g in before.difference(&after) {
                prop_assert_eq!(
                    self.last_answer(g),
                    Some(false),
                    "an obligation was lost while its adapter's last answer was pending ({:?})",
                    step
                );
            }
            Ok(())
        }
    }

    async fn trace(steps: Vec<Step>) -> Result<(), TestCaseError> {
        let mut run = Run::new().await;
        for step in &steps {
            let before = run.owed();
            run.step(step).await;
            run.check_none_lost(&before, step)?;
        }
        let before = run.owed();
        run.restart().await;
        run.check_none_lost(&before, &Step::Restart)?;
        let gid = run.gid.clone();
        let Some(after) = run.adapter.calls_after_effect(&gid) else {
            return Ok(()); // no credential was ever applied
        };
        if run.w.grant(&gid).state.permits_use() {
            return Ok(()); // the effect is the grant's own, in use
        }
        prop_assert!(
            r1319_live(&run.w, &gid, CAP) || after > 0,
            "after the restart the applied effect has neither a live owning obligation \
             nor a call after it: {:?}",
            r1312_record(&run.w, &gid)
        );
        for _ in 0..(2 * CAP + 2) {
            let before = run.owed();
            let pass = Step::Pass { pending: true };
            run.step(&pass).await;
            run.check_none_lost(&before, &pass)?;
        }
        prop_assert!(
            run.adapter.calls_after_effect(&gid) > Some(0),
            "no call followed the applied effect: {:?}",
            r1312_record(&run.w, &gid)
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn r1319_every_applied_effect_ends_owned_or_called_and_no_pending_obligation_is_lost(
            steps in proptest::collection::vec(step_s(), 1..=14),
        ) {
            block(trace(steps))?;
        }
    }
}

// =================================================================================
// ⟨M02⟩ U0b phase 1: M01 integration (m02-plan U0b rows 1 to 23, "Tests, phase 1")
// =================================================================================

/// ⟨M02⟩ m02-plan U0b phase 1, through the real `Operations` and a real scratch
/// `Store` (in memory). The plan names `tests/model/m02_integration.rs` as a target
/// hosted by `heimdall-runtime`; adding a `[[test]]` entry needs that crate's
/// manifest, which this unit does not own, so the suite is a module of this
/// existing target (escalated). Catalog rows, declarations and setup operations are
/// seeded through the store; no file is read or written.
mod m02_integration {
    use super::*;
    use heimdall_app::SetupAdmission;
    use heimdall_app::ports::{AdapterError, PreparePair, PrepareRequest};
    use heimdall_contract::canonical::RequestHash;
    use heimdall_contract::catalog::DeclaredInteraction;
    use heimdall_contract::ids::IdentityId;
    use heimdall_contract::provider::{
        CredentialAvailability, DeclarationRef, EndpointKind, EndpointRef, EvidenceBasis,
        IdentitiesOnly, IdentitySelection, IdentitySelectionReport, InteractionKind,
        NoninteractiveEligibility, ProbeLevel, ProviderAvailability, ProviderKind, ProviderStatus,
    };
    use heimdall_contract::request::{
        ConsumerIntegration, InspectRequest, InspectSubject, LaunchBinding, PairIntegration,
        ProcessHolder, Request,
    };
    use heimdall_contract::setup::{PlanDigest, PreviewIntent};
    use heimdall_domain::catalog::{
        DeclarationEndReason, DestinationDefinition, DestinationRecord, IdentityRecord,
        IdentitySource, InteractionDeclaration, InteractionProfile, PreparedFacts, PreparedPair,
    };
    use heimdall_domain::idempotency::{
        HashInput, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, compute_hash,
    };
    use heimdall_domain::operation::{
        EffectClass, EffectReceipt, LocalIntent, OperationKind, OperationRecord, RecoveryIntent,
        RecoveryMetadata, StageReceipt,
    };
    use heimdall_domain::projection::{
        Base, ConsentRecord, FileRole, FileStep, Rendered, SetupIntent, Sha256Hex, Target,
    };

    /// The agent endpoint the catalog names: a locator string, never opened.
    const AGENT: &str = "/scratch/u0b/agent.sock";
    /// Another endpoint (the identity moved).
    const OTHER_AGENT: &str = "/scratch/u0b/other.sock";
    /// The adopted identity's fingerprint (synthetic).
    const FINGERPRINT: &str = "SHA256:u0bfixtureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub(super) fn endpoint(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.into(),
        }
    }

    pub(super) fn identity_id() -> IdentityId {
        IdentityId::from_random_bytes([21; 16])
    }

    /// The adopted identity: a public ed25519 key line (synthetic, public material
    /// only) held by the agent at `at`, at `revision`.
    pub(super) fn identity(at: &str, revision: u64) -> IdentityRecord {
        let source = IdentitySource::NativeAgent {
            endpoint: endpoint(at),
        };
        let public_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUwYmZpeHR1cmUAAAAAAAAAAAAAAAAAAAAAAAAA u0b"
                .to_owned();
        IdentityRecord {
            id: identity_id(),
            revision,
            interaction: InteractionProfile::default_for(&source, &public_key),
            source,
            public_key,
            fingerprint: FINGERPRINT.into(),
            label: None,
            adopted_at: shift(t0(), -86_400),
            updated_at: shift(t0(), -86_400),
        }
    }

    fn destination(d: &str, identity: &IdentityId) -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::parse(d).unwrap(),
            alias: d.into(),
            revision: 1,
            definition: DestinationDefinition::Managed {
                hostname: format!("{d}.example.invalid"),
                port: None,
                account: AccountName::parse("deploy").unwrap(),
                identity: identity.clone(),
            },
            label: None,
            updated_at: t0(),
        }
    }

    pub(super) fn declaration(
        revision: u64,
        at: &str,
        expires_at: Timestamp,
    ) -> InteractionDeclaration {
        InteractionDeclaration {
            revision,
            state: heimdall_domain::catalog::DeclarationState::Live,
            interaction: DeclaredInteraction::None,
            fingerprint: FINGERPRINT.into(),
            endpoint: endpoint(at),
            declared_at: shift(t0(), -3600),
            expires_at,
            decision: DecisionId::from_random_bytes([31; 16]),
            ended_at: None,
            end_reason: None,
        }
    }

    /// The identity, managed destinations h1 and h2 naming it, and (when `declared`)
    /// a live `none` declaration at its endpoint that expires 30 minutes after t0.
    pub(super) fn seed_catalog(w: &World, declared: bool) {
        w.store
            .transaction(|tx| {
                tx.upsert_identity(&identity(AGENT, 1))?;
                for d in ["h1", "h2"] {
                    tx.upsert_destination(&destination(d, &identity_id()))?;
                }
                if declared {
                    tx.put_interaction_declaration(
                        &identity_id(),
                        0,
                        &declaration(1, AGENT, shift(t0(), 30 * 60)),
                    )?;
                }
                Ok(())
            })
            .unwrap();
    }

    pub(super) fn provider_status() -> ProviderStatus {
        ProviderStatus {
            provider: ProviderKind::NativeAgent,
            availability: ProviderAvailability::Available,
            interaction: InteractionKind::Unknown,
            observed_level: ProbeLevel::Static,
            observed_at: shift(t0(), -60),
            basis: EvidenceBasis::Observed,
        }
    }

    /// What the adapter reports for one pair. Its fresh fields claim `none`
    /// (declared, eligible) with a declaration that does not exist: the runtime must
    /// recompute them and never take them from the adapter or from stored facts.
    fn reported_pair(d: &str) -> PairIntegration {
        PairIntegration {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
            identity: identity_id(),
            mechanism: "native_agent".into(),
            endpoint: Some(endpoint(AGENT)),
            alias: Some(d.into()),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Declared,
            declared_at: Some(t0()),
            identity_selection: IdentitySelection::Exclusive,
            selection_observed_at: shift(t0(), -120),
            declaration: Some(DeclarationRef {
                revision: 99,
                endpoint: endpoint(AGENT),
                expires_at: shift(t0(), 365 * 86_400),
            }),
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: t0(),
            identity_selection_report: None,
        }
    }

    /// The native fake's outcome: two pairs, a provider status, an environment
    /// value, and an availability claim the runtime must not repeat.
    pub(super) fn pairs_outcome() -> PrepareOutcome {
        PrepareOutcome {
            availability: CredentialAvailability::ThroughDeadline,
            provider: Some(provider_status()),
            integration: ConsumerIntegration {
                environment: vec![("SSH_AUTH_SOCK".into(), AGENT.into())],
                pairs: vec![reported_pair("h1"), reported_pair("h2")],
                ..ConsumerIntegration::default()
            },
            ..outcome()
        }
    }

    fn native_descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "native_agent".into(),
                instance: "u0b-fixture".into(),
            },
            ..descriptor()
        }
    }

    /// A `native_agent` fake that records the catalog pairs of every `prepare` and
    /// can hold one preparation until released.
    pub(super) struct Native {
        pub(super) inner: Arc<FakeCredentialAdapter>,
        pub(super) hold: AtomicBool,
        pub(super) entered: tokio::sync::Notify,
        pub(super) release: tokio::sync::Notify,
        pub(super) seen: std::sync::Mutex<Vec<Vec<PreparePair>>>,
    }

    impl Native {
        pub(super) fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCredentialAdapter::new(
                    native_descriptor(),
                    vec![FakeStep::Prepare(pairs_outcome())],
                ),
                hold: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                seen: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    impl CredentialAdapter for Native {
        fn descriptor(&self) -> &AdapterDescriptor {
            self.inner.descriptor()
        }
        fn prepare<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: PrepareRequest<'life1>,
        ) -> U10Fut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.seen.lock().unwrap().push(req.pairs.to_vec());
            let hold = self.hold.swap(false, Ordering::SeqCst);
            let applied = self.inner.prepare(req);
            Box::pin(async move {
                if hold {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                applied.await
            })
        }
        fn renew<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: PrepareRequest<'life1>,
        ) -> U10Fut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.renew(req)
        }
        fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            effect_token: &'life2 str,
        ) -> U10Fut<'async_trait, heimdall_app::ports::ReconcileOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.reconcile(grant, effect_token)
        }
        fn revoke<'life0, 'life1, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            now: Timestamp,
        ) -> U10Fut<'async_trait, heimdall_app::ports::RevokeOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.revoke(grant, now)
        }
    }

    /// In-process restart with the M01 fake first and the native fake second, so the
    /// M01 selection would pick the M01 fake: only the catalog's mechanism picks the
    /// native one (U0b row 7).
    pub(super) async fn restart_native(w: &mut World, native: &Arc<Native>) {
        w.ops = Operations::start(OperationsConfig {
            adapters: vec![
                w.fake.clone() as Arc<dyn CredentialAdapter>,
                native.clone() as Arc<dyn CredentialAdapter>,
            ],
            ..w.config()
        })
        .await
        .unwrap();
    }

    pub(super) async fn native_world(declared: bool) -> (World, Arc<Native>) {
        let mut w = World::new().await;
        seed_catalog(&w, declared);
        let native = Native::new();
        restart_native(&mut w, &native).await;
        (w, native)
    }

    fn both_pairs() -> [(&'static str, &'static str); 2] {
        [("h1", "deploy"), ("h2", "deploy")]
    }

    async fn bind_materialize(w: &World, binding: &BindingIdOf, rid: &str) -> EnsureData {
        ok(w.ops
            .bind(
                &unattended(501),
                BindRequest {
                    binding_id: binding.clone(),
                    form: BindForm::Materialize,
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await)
        .data
    }

    type BindingIdOf = heimdall_contract::ids::BindingId;

    /// The history part of a result (U0b row 5): provider, environment,
    /// executables, overrides, and each pair's endpoint, alias, mechanism, selection
    /// and its observation time.
    pub(super) fn history(d: &EnsureData) -> serde_json::Value {
        serde_json::json!({
            "provider": d.provider,
            "environment": d.consumer.environment,
            "executables": d.consumer.executables,
            "overrides": d.consumer.overrides,
            "pairs": d.consumer.pairs.iter().map(|p| serde_json::json!({
                "destination": p.destination,
                "account": p.account,
                "identity": p.identity,
                "mechanism": p.mechanism,
                "endpoint": p.endpoint,
                "alias": p.alias,
                "identity_selection": p.identity_selection,
                "selection_observed_at": p.selection_observed_at,
            })).collect::<Vec<_>>(),
        })
    }

    /// The fresh part of a result (U0b row 5): availability and each pair's
    /// interaction, basis, declaration and eligibility.
    pub(super) fn fresh(d: &EnsureData) -> serde_json::Value {
        serde_json::json!({
            "availability": d.credential_availability,
            "pairs": d.consumer.pairs.iter().map(|p| serde_json::json!({
                "interaction": p.interaction,
                "interaction_basis": p.interaction_basis,
                "declared_at": p.declared_at,
                "declaration": p.declaration,
                "noninteractive": p.noninteractive,
            })).collect::<Vec<_>>(),
        })
    }

    fn assert_declared_none(d: &EnsureData, revision: u64) {
        assert_eq!(d.consumer.pairs.len(), 2, "{d:?}");
        for p in &d.consumer.pairs {
            assert_eq!(p.interaction, InteractionKind::None, "{p:?}");
            assert_eq!(p.interaction_basis, EvidenceBasis::Declared);
            assert_eq!(
                p.declaration.as_ref().map(|r| r.revision),
                Some(revision),
                "{p:?}"
            );
            assert!(p.noninteractive.eligible);
            assert!(p.declared_at.is_some());
        }
        assert_eq!(
            d.credential_availability,
            CredentialAvailability::CurrentOnly
        );
    }

    fn assert_unknown(d: &EnsureData) {
        assert_eq!(d.consumer.pairs.len(), 2, "{d:?}");
        for p in &d.consumer.pairs {
            assert_eq!(p.interaction, InteractionKind::Unknown, "{p:?}");
            assert_eq!(p.interaction_basis, EvidenceBasis::Inferred);
            assert!(!p.noninteractive.eligible, "{p:?}");
            assert_eq!(
                p.noninteractive.reason.as_deref(),
                Some("interaction_unknown")
            );
            assert_eq!(p.declaration, None, "{p:?}");
            assert_eq!(p.declared_at, None);
        }
        assert_eq!(
            d.credential_availability,
            CredentialAvailability::InteractionRequired
        );
    }

    fn open_ops_of(w: &World, uid: u32) -> Vec<OperationRecord> {
        w.store
            .transaction(|tx| tx.open_operations())
            .unwrap()
            .into_iter()
            .filter(|o| o.key.caller.principal == PrincipalRef::UnixUser { uid })
            .collect()
    }

    /// U0b row 3: a launch binding validates its executable and holder; the holder
    /// is delivery metadata, so the same request ID with another holder replays and
    /// another executable conflicts. Materialize still hashes exactly as in M01.
    #[tokio::test]
    async fn u0b_bind_launch_validates_executable_and_excludes_holder_from_hash() {
        let w = World::new().await;
        let done = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-bl", "u0b-bl-work", &[("h1", "deploy")]),
            )
            .await)
        .data;
        let (exe, other_exe) = if cfg!(windows) {
            (r"C:\fixture\bin\tool.exe", r"C:\fixture\bin\other.exe")
        } else {
            ("/opt/fixture/bin/tool", "/opt/fixture/bin/other")
        };
        let holder = |pid: u32, started: &str| ProcessHolder {
            pid,
            started_at: started.into(),
        };
        let launch = |exe: &str, holder: Option<ProcessHolder>, rid: &str| BindRequest {
            binding_id: done.binding_id.clone(),
            form: BindForm::Launch(LaunchBinding {
                executable: exe.into(),
                holder,
            }),
            request_id: RequestId::parse(rid).unwrap(),
        };
        let first_holder = holder(4242, "1700000000.250");
        let first = ok(w
            .ops
            .bind(
                &unattended(501),
                launch(exe, Some(first_holder.clone()), "u0b-bl-1"),
            )
            .await);
        assert_eq!(first.code, Code::AccessReady);
        let stored_holder = |w: &World| {
            w.store
                .transaction(|tx| tx.binding_holder(&done.binding_id))
                .unwrap()
        };
        assert_eq!(stored_holder(&w), Some(first_holder.clone()));
        // Another holder, the same request ID: a replay of the same operation.
        let replay = ok(w
            .ops
            .bind(
                &unattended(501),
                launch(exe, Some(holder(4343, "1700000001.000")), "u0b-bl-1"),
            )
            .await);
        assert_eq!(replay.operation_id, first.operation_id);
        let replay_without = ok(w
            .ops
            .bind(&unattended(501), launch(exe, None, "u0b-bl-1"))
            .await);
        assert_eq!(replay_without.operation_id, first.operation_id);
        assert_eq!(
            stored_holder(&w),
            Some(first_holder.clone()),
            "a replay writes nothing"
        );
        // Another executable, the same request ID: a conflict.
        let conflict = err(w
            .ops
            .bind(
                &unattended(501),
                launch(other_exe, Some(first_holder.clone()), "u0b-bl-1"),
            )
            .await);
        assert_eq!(conflict.code, Code::RequestConflict);
        // Invalid launch bindings are refused before any record exists.
        let ops_before = w.store.transaction(|tx| tx.operation_counts()).unwrap();
        let long = format!("{exe}{}", "x".repeat(4097));
        let invalid: Vec<(String, Option<ProcessHolder>)> = vec![
            (String::new(), None),
            ("relative/tool".into(), None),
            (format!("{exe}\0"), None),
            (long, None),
            (exe.into(), Some(holder(0, "1700000000"))),
            (exe.into(), Some(holder(1, ""))),
            (exe.into(), Some(holder(1, "has space"))),
            (exe.into(), Some(holder(1, &"9".repeat(65)))),
        ];
        for (i, (e, h)) in invalid.into_iter().enumerate() {
            let refused = err(w
                .ops
                .bind(&unattended(501), launch(&e, h, &format!("u0b-bl-bad-{i}")))
                .await);
            assert_eq!(refused.code, Code::UsageError, "case {i}");
        }
        assert_eq!(
            w.store.transaction(|tx| tx.operation_counts()).unwrap(),
            ops_before,
            "no operation was admitted for an invalid launch binding"
        );
        // Materialize: the M01 hash input, byte for byte.
        let m = ok(w
            .ops
            .bind(
                &unattended(501),
                BindRequest {
                    binding_id: done.binding_id.clone(),
                    form: BindForm::Materialize,
                    request_id: RequestId::parse("u0b-bl-m").unwrap(),
                },
            )
            .await);
        let m01 = compute_hash(
            OperationKind::Bind,
            &HashInput {
                environment: &env_id(),
                profile: None,
                profile_revision: None,
                scope: &BTreeSet::new(),
                deadline_intent: None,
                work_id: None,
                required_capabilities: &RequiredCapabilities::default(),
                parent_binding: None,
                extra: serde_json::json!({
                    "binding_id": done.binding_id,
                    "form": { "form": "materialize" },
                }),
            },
        )
        .unwrap();
        assert_eq!(w.op(m.operation_id.as_ref().unwrap()).request_hash, m01);
        w.events();
    }

    /// U0b rows 4 to 8, rescoped for M2-R04: the history survives ensure, an
    /// attached (coalesced) result, bind, replay and a restart; with nothing
    /// changed the fresh eligibility is equal too. The catalog's mechanism selects
    /// the adapter and the adapter receives the catalog's pairs.
    #[tokio::test]
    async fn u0b_integration_provider_and_pairs_survive_ensure_attach_bind_replay_restart() {
        let (mut w, native) = native_world(true).await;
        // `ensure` by 501, its preparation held.
        native.hold.store(true, Ordering::SeqCst);
        let ops = w.ops.clone();
        let req_a = ensure_req("u0b-int-a", "u0b-int-wa", &both_pairs());
        let a = tokio::spawn(async move { ops.ensure(&unattended(501), req_a).await });
        native.entered.notified().await;
        // A second caller's equivalent request coalesces onto it.
        let ops = w.ops.clone();
        let req_b = ensure_req("u0b-int-b", "u0b-int-wb", &both_pairs());
        let b = tokio::spawn(async move { ops.ensure(&unattended(502), req_b).await });
        let resolved = EnsureStage::ResolveMechanism.as_str();
        for _ in 0..500 {
            let at_coalesce = open_ops_of(&w, 502).iter().any(|o| {
                w.store
                    .transaction(|tx| tx.stage_receipts(&o.id))
                    .unwrap()
                    .iter()
                    .any(|r| r.stage == resolved)
            });
            if at_coalesce {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Let the follower reach the shared flight before the leader finishes.
        tokio::time::sleep(Duration::from_millis(100)).await;
        native.release.notify_one();
        let ra = ok(a.await.unwrap());
        let rb = ok(b.await.unwrap());
        assert_eq!(native.inner.effect_count(), 1, "one preparation for both");
        assert_eq!(w.effects(), 0, "the M01 fake was never selected");
        assert_eq!(ra.data.credential_mechanism, "native_agent");
        assert_eq!(rb.data.grant_id, ra.data.grant_id, "attached to one grant");
        assert_ne!(rb.data.binding_id, ra.data.binding_id);
        // U0b row 8: the adapter got the catalog's pairs.
        let seen = native.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let aliases: Vec<_> = seen[0].iter().map(|p| p.alias.clone()).collect();
        assert_eq!(aliases, vec![Some("h1".to_owned()), Some("h2".to_owned())]);
        assert!(seen[0].iter().all(|p| p.identity.id == identity_id()));
        // bind, then replays of every request.
        let rbind = bind_materialize(&w, &ra.data.binding_id, "u0b-int-bind").await;
        let replay_a = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-int-a", "u0b-int-wa", &both_pairs()),
            )
            .await)
        .data;
        let replay_b = ok(w
            .ops
            .ensure(
                &unattended(502),
                ensure_req("u0b-int-b", "u0b-int-wb", &both_pairs()),
            )
            .await)
        .data;
        let replay_bind = bind_materialize(&w, &ra.data.binding_id, "u0b-int-bind").await;
        // A restart from the same store, then bind again.
        restart_native(&mut w, &native).await;
        let rbind2 = bind_materialize(&w, &ra.data.binding_id, "u0b-int-bind-2").await;
        let replay_after = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-int-a", "u0b-int-wa", &both_pairs()),
            )
            .await)
        .data;
        let expected = history(&ra.data);
        assert!(ra.data.provider.is_some(), "a provider status is reported");
        assert_eq!(ra.data.consumer.pairs.len(), 2);
        assert!(
            ra.data
                .consumer
                .pairs
                .iter()
                .all(|p| p.endpoint.is_some() && p.alias.is_some())
        );
        assert!(!ra.data.consumer.environment.is_empty());
        let results = [
            ("attached", &rb.data),
            ("bind", &rbind),
            ("ensure replay", &replay_a),
            ("attached replay", &replay_b),
            ("bind replay", &replay_bind),
            ("bind after restart", &rbind2),
            ("replay after restart", &replay_after),
        ];
        for (label, d) in results {
            assert_eq!(history(d), expected, "history of the {label} result");
        }
        // Nothing changed: the fresh eligibility is equal in every result, and it is
        // the runtime's (`none` from the live declaration, revision 1), not the
        // adapter's claim (revision 99, `through_deadline`).
        assert_declared_none(&ra.data, 1);
        for (label, d) in results {
            assert_eq!(
                fresh(d),
                fresh(&ra.data),
                "eligibility of the {label} result"
            );
        }
        w.events();
    }

    #[derive(Debug, Clone, Copy)]
    enum Lapse {
        Withdrawn,
        Expired,
        ListingMissing,
        EndpointChanged,
    }

    async fn eligibility_after(lapse: Lapse, restart: bool) {
        let label = format!("{lapse:?}, restart {restart}");
        let (mut w, native) = native_world(true).await;
        let ensured = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-el", "u0b-el-work", &both_pairs()),
            )
            .await)
        .data;
        assert_declared_none(&ensured, 1);
        let now = w.clock.wall();
        match lapse {
            Lapse::Withdrawn | Lapse::ListingMissing => {
                let reason = if matches!(lapse, Lapse::Withdrawn) {
                    DeclarationEndReason::OwnerWithdrawn
                } else {
                    DeclarationEndReason::ListingMissing
                };
                let ended = w
                    .store
                    .transaction(|tx| {
                        tx.end_interaction_declaration(&identity_id(), Some(1), reason, now)
                    })
                    .unwrap();
                assert!(ended.ended, "{label}");
            }
            // The fake clock passes `expires_at` (30 minutes after t0).
            Lapse::Expired => w.clock.advance(31 * MINUTE),
            Lapse::EndpointChanged => w
                .store
                .transaction(|tx| tx.upsert_identity(&identity(OTHER_AGENT, 2)))
                .unwrap(),
        }
        if restart {
            restart_native(&mut w, &native).await;
        }
        let bound = bind_materialize(&w, &ensured.binding_id, "u0b-el-bind").await;
        assert_unknown(&bound);
        assert_eq!(history(&bound), history(&ensured), "{label}: history kept");
        // A re-declaration at the identity's current endpoint shows a new revision.
        let (row, at) = w
            .store
            .transaction(|tx| {
                Ok((
                    tx.interaction_declaration(&identity_id())?
                        .unwrap()
                        .revision,
                    tx.identity(&identity_id())?.unwrap(),
                ))
            })
            .unwrap();
        let at = at.source.endpoint().unwrap().locator.clone();
        let later = shift(w.clock.wall(), 86_400);
        w.store
            .transaction(|tx| {
                tx.put_interaction_declaration(
                    &identity_id(),
                    row,
                    &declaration(row + 1, &at, later),
                )
            })
            .unwrap();
        let again = bind_materialize(&w, &ensured.binding_id, "u0b-el-bind-2").await;
        assert_declared_none(&again, row + 1);
        assert!(row + 1 > 1, "{label}: a new revision");
        w.events();
    }

    /// U0b row 5 (M2-R04): after an `ensure` that reported `interaction: none`
    /// (declared), a withdrawal, an expiry on the fake clock, a recorded
    /// `listing_missing` lapse or an endpoint change before `bind` makes the `bind`
    /// result `unknown`, not eligible, with no declaration, in-process and after a
    /// restart. A re-declaration then shows a new revision.
    #[tokio::test]
    async fn u0b_eligibility_is_recomputed_per_result_never_taken_from_prepared_facts() {
        for lapse in [
            Lapse::Withdrawn,
            Lapse::Expired,
            Lapse::ListingMissing,
            Lapse::EndpointChanged,
        ] {
            for restart in [false, true] {
                eligibility_after(lapse, restart).await;
            }
        }
    }

    /// Every key of an object, and of each object in its `pairs` array.
    fn top_and_pair_keys(v: &serde_json::Value) -> BTreeSet<String> {
        let mut keys: BTreeSet<String> = v.as_object().unwrap().keys().cloned().collect();
        for p in v["pairs"].as_array().unwrap() {
            keys.extend(p.as_object().unwrap().keys().cloned());
        }
        keys
    }

    const FRESH_KEYS: [&str; 9] = [
        "interaction",
        "interaction_basis",
        "declared_at",
        "declaration",
        "noninteractive",
        "eligibility_checked_at",
        "availability",
        "credential_availability",
        "eligible",
    ];

    /// U0b row 6 (M2-R04): `PreparedFacts` is history only. A serde golden, and the
    /// facts an `ensure` stored from an outcome that claimed `none` and
    /// `through_deadline` hold neither.
    #[tokio::test]
    async fn u0b_prepared_facts_have_no_interaction_field() {
        let facts = PreparedFacts {
            provider: Some(provider_status()),
            executables: Vec::new(),
            overrides: Vec::new(),
            environment: vec![("SSH_AUTH_SOCK".into(), AGENT.into())],
            pairs: vec![PreparedPair {
                destination: DestinationId::parse("h1").unwrap(),
                account: AccountName::parse("deploy").unwrap(),
                identity: identity_id(),
                mechanism: "native_agent".into(),
                endpoint: Some(endpoint(AGENT)),
                alias: Some("h1".into()),
                identity_selection: IdentitySelectionReport {
                    selection: IdentitySelection::Exclusive,
                    entries: Vec::new(),
                    identities_only: IdentitiesOnly::DeterminedYes,
                },
                selection_observed_at: shift(t0(), -120),
            }],
            recorded_at: t0(),
        };
        let golden = serde_json::json!({
            "provider": {
                "provider": "native_agent",
                "availability": "available",
                "interaction": "unknown",
                "observed_level": "static",
                "observed_at": "2026-10-02T08:59:00Z",
                "basis": "observed",
            },
            "executables": [],
            "overrides": [],
            "environment": [["SSH_AUTH_SOCK", AGENT]],
            "pairs": [{
                "destination": "h1",
                "account": "deploy",
                "identity": identity_id(),
                "mechanism": "native_agent",
                "endpoint": { "kind": "unix_socket", "locator": AGENT },
                "alias": "h1",
                "identity_selection": {
                    "selection": "exclusive",
                    "entries": [],
                    "identities_only": "determined_yes",
                },
                "selection_observed_at": "2026-10-02T08:58:00Z",
            }],
            "recorded_at": "2026-10-02T09:00:00Z",
        });
        let v = serde_json::to_value(&facts).unwrap();
        assert_eq!(v, golden);
        assert_eq!(
            serde_json::from_value::<PreparedFacts>(golden).unwrap(),
            facts
        );
        for k in FRESH_KEYS {
            assert!(!top_and_pair_keys(&v).contains(k), "{k} in {v}");
        }
        // What an `ensure` stored from the native fake's outcome.
        let (w, _native) = native_world(true).await;
        let done = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-pf", "u0b-pf-work", &both_pairs()),
            )
            .await)
        .data;
        let stored = w
            .store
            .transaction(|tx| tx.grant_prepared_facts(&done.grant_id))
            .unwrap()
            .expect("prepared facts in the transaction of the Confirmed receipt");
        let sv = serde_json::to_value(&stored).unwrap();
        for k in FRESH_KEYS {
            assert!(!top_and_pair_keys(&sv).contains(k), "{k} in {sv}");
        }
        assert_eq!(stored.pairs.len(), 2);
        assert_eq!(stored.provider, Some(provider_status()));
    }

    /// U0b rows 10 and 11, phase-1 form: one journaled operation of each M01 kind,
    /// left `queued` as a crash right after admission leaves it, is driven to its
    /// result by restart recovery. (The setup and catalog kinds: the full form,
    /// `u0b_phase2::u0b_restart_dispatches_every_operation_kind`.)
    #[tokio::test]
    async fn u0b_restart_dispatches_every_operation_kind() {
        let mut w = World::new().await;
        let parent = r136_ready(&w, "u0b-rk-p", "u0b-rk-pw", "h1", "1h").await;
        let target = r136_ready(&w, "u0b-rk-t", "u0b-rk-tw", "h2", "1h").await;
        let seeds = [
            (
                OperationKind::Ensure,
                Request::Ensure(ensure_req("u0b-rk-e", "u0b-rk-ew", &[("h1", "deploy")])),
            ),
            (
                OperationKind::Delegate,
                Request::Delegate(u10_delegate(&parent, "u0b-rk-d", "30m")),
            ),
            (
                OperationKind::Bind,
                Request::Bind(BindRequest {
                    binding_id: parent.binding_id.clone(),
                    form: BindForm::Materialize,
                    request_id: RequestId::parse("u0b-rk-b").unwrap(),
                }),
            ),
            (
                OperationKind::Revoke,
                Request::Revoke(RevokeRequest {
                    grant_id: target.grant_id.clone(),
                    request_id: RequestId::parse("u0b-rk-v").unwrap(),
                }),
            ),
        ];
        let mut seeded = Vec::new();
        for (i, (kind, request)) in seeds.into_iter().enumerate() {
            let n = u8::try_from(i).unwrap() + 1;
            let id = OperationId::from_random_bytes([0x60 + n; 16]);
            let rid = match &request {
                Request::Ensure(r) => r.request_id.clone(),
                Request::Delegate(r) => r.request_id.clone(),
                Request::Bind(r) => r.request_id.clone(),
                Request::Revoke(r) => r.request_id.clone(),
                _ => unreachable!("only M01 journaled kinds are seeded"),
            };
            let op = queued(&id, kind, &rid, 0x60 + n);
            let pipeline = matches!(kind, OperationKind::Ensure | OperationKind::Delegate);
            w.store
                .transaction(|tx| {
                    tx.insert_operation(&op, &idem_of(&op))?;
                    tx.set_recovery_intent(
                        &id,
                        &RecoveryIntent {
                            request: serde_json::to_value(&request).unwrap(),
                            resolved: None,
                            local: None,
                        },
                    )?;
                    if pipeline {
                        tx.append_stage_receipt(
                            &id,
                            &StageReceipt {
                                stage: EnsureStage::Authenticate.as_str().into(),
                                recorded_at: t0(),
                                effect: EffectReceipt::NotAttempted,
                                local: None,
                            },
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            seeded.push((kind, id));
        }
        w.restart().await;
        for (kind, id) in &seeded {
            let op = w.op(id);
            assert_eq!(
                op.state,
                OperationState::Succeeded,
                "{kind:?} was driven to its result: {:?} {:?}",
                op.code,
                op.result
            );
        }
        w.events();
    }

    /// A `queued` operation record of `kind` for caller 501.
    pub(super) fn queued(
        id: &OperationId,
        kind: OperationKind,
        rid: &RequestId,
        hash: u8,
    ) -> OperationRecord {
        OperationRecord {
            id: id.clone(),
            kind,
            environment: env_id(),
            key: IdempotencyKey {
                caller: ctx(501, ClientRole::Owner),
                kind,
                request_id: rid.clone(),
            },
            request_hash: RequestHash([hash; 32]),
            effect_class: kind
                .m02_effect_class()
                .unwrap_or(EffectClass::LocalResources),
            state: OperationState::Queued,
            code: None,
            effect_status: EffectStatus::None,
            result: None,
            created_at: t0(),
            updated_at: t0(),
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        }
    }

    pub(super) fn idem_of(op: &OperationRecord) -> IdempotencyRecord {
        IdempotencyRecord {
            key: op.key.clone(),
            request_hash: op.request_hash,
            operation_id: op.id.clone(),
            created_at: op.created_at,
            expires_at: None,
        }
    }

    /// U0b row 7 (P6): pairs whose catalog identities name two mechanisms are
    /// refused `CAPABILITY_UNAVAILABLE`, reason `mixed_mechanisms`, with no effect;
    /// each mechanism alone resolves.
    #[tokio::test]
    async fn u0b_mixed_mechanisms_refused_capability_unavailable() {
        let (w, native) = native_world(false).await;
        let vault = IdentityId::from_random_bytes([22; 16]);
        w.store
            .transaction(|tx| {
                let source = IdentitySource::OnePassword { endpoint: None };
                let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUwYnZhdWx0AAAAAAAAAAAAAAAAAAAAAAAAAAAA u0b".to_owned();
                tx.upsert_identity(&IdentityRecord {
                    id: vault.clone(),
                    revision: 1,
                    interaction: InteractionProfile::default_for(&source, &public_key),
                    source,
                    public_key,
                    fingerprint: "SHA256:u0bvaultAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    label: None,
                    adopted_at: t0(),
                    updated_at: t0(),
                })?;
                let mut h2 = destination("h2", &vault);
                h2.revision = 2;
                tx.upsert_destination(&h2)
            })
            .unwrap();
        let mixed = err(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-mm", "u0b-mm-work", &both_pairs()),
            )
            .await);
        assert_eq!(mixed.code, Code::CapabilityUnavailable);
        assert_eq!(mixed.reason.as_deref(), Some("mixed_mechanisms"));
        assert_eq!(mixed.effect_status, EffectStatus::None);
        let env = mixed.clone().into_envelope();
        assert_eq!(
            serde_json::to_value(&env).unwrap()["data"]["error"]["reason"],
            "mixed_mechanisms"
        );
        assert_eq!(native.inner.effect_count() + w.effects(), 0, "no effect");
        // One mechanism alone resolves (h1 names the native identity).
        let one = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-mm-1", "u0b-mm-1-work", &[("h1", "deploy")]),
            )
            .await);
        assert_eq!(one.data.credential_mechanism, "native_agent");
        w.events();
    }

    /// U0b row 9: `unattended` is met only by an adapter whose lock continuity is
    /// `Verified` and that needs no interaction; `Unknown` never meets it.
    #[tokio::test]
    async fn u0b_unattended_minimum_unknown_is_capability_unavailable() {
        let mut w = World::new().await;
        let mut req = ensure_req("u0b-un", "u0b-un-work", &[("h1", "deploy")]);
        req.required_capabilities.unattended = true;
        let refused = err(w.ops.ensure(&unattended(501), req.clone()).await);
        assert_eq!(refused.code, Code::CapabilityUnavailable);
        assert_eq!(w.effects(), 0);
        assert!(w.bindings_for("u0b-un-work").is_empty());
        // Control: an adapter that can meet it (never configured in M02).
        let mut d = descriptor();
        d.identity.mechanism = "fake_verified".into();
        d.lock_continuity = LockContinuity::Verified;
        d.interaction = InteractionRequirement::None;
        let verified = FakeCredentialAdapter::new(d, vec![FakeStep::Prepare(outcome())]);
        w.ops = Operations::start(OperationsConfig {
            adapters: vec![verified.clone() as Arc<dyn CredentialAdapter>],
            ..w.config()
        })
        .await
        .unwrap();
        req.request_id = RequestId::parse("u0b-un-2").unwrap();
        let met = ok(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(met.data.credential_mechanism, "fake_verified");
        assert_eq!(verified.effect_count(), 1);
    }

    pub(super) fn setup_intent(generation: u64, intent: PreviewIntent) -> SetupIntent {
        const P: &[u8] = b"Host h1\n  HostName h1.example.invalid\n  IdentitiesOnly yes\n";
        SetupIntent {
            plan_digest: PlanDigest::from_sha256([u8::try_from(generation % 251).unwrap(); 32]),
            intent,
            generation,
            approval: None,
            consent: ConsentRecord::default(),
            files: vec![FileStep {
                role: FileRole::ManagedSsh,
                path: "/scratch/u0b/ssh/heimdall.conf".into(),
                base: Base::Absent,
                target: Target::Present {
                    sha256: Sha256Hex::of(P),
                },
                content: Rendered::from_renderer(P.to_vec()).into_whole(),
                commit: true,
                staged_name: Some(
                    ".heimdall.conf.hm-stage-00112233445566778899aabbccddeeff".into(),
                ),
                displaced_name: None,
            }],
        }
    }

    pub(super) fn apply_intent() -> PreviewIntent {
        PreviewIntent::Apply { include_git: false }
    }

    /// U0b row 16: `RecoveryIntent.local` is add-only. `None → Some` is allowed;
    /// once set, its variant and every field but `approval` never change; `approval`
    /// goes `None → Some` once; `local` beside `resolved` is refused.
    #[tokio::test]
    async fn u0b_recovery_intent_local_is_add_only() {
        let w = World::new().await;
        let id = OperationId::from_random_bytes([0x71; 16]);
        let rid = RequestId::parse("u0b-ao").unwrap();
        let op = queued(&id, OperationKind::SetupApply, &rid, 0x71);
        let base = RecoveryIntent {
            request: serde_json::json!({ "op": "setup", "action": "apply" }),
            resolved: None,
            local: None,
        };
        let set = |intent: &RecoveryIntent| {
            w.store
                .transaction(|tx| tx.set_recovery_intent(&id, intent))
        };
        w.store
            .transaction(|tx| tx.insert_operation(&op, &idem_of(&op)))
            .unwrap();
        set(&base).unwrap();
        let mut with_local = base.clone();
        with_local.local = Some(LocalIntent::Setup(setup_intent(1, apply_intent())));
        set(&with_local).expect("None → Some");
        let refused = |intent: &RecoveryIntent, kept: &RecoveryIntent, what: &str| {
            let e = set(intent).expect_err(what);
            assert!(
                matches!(e, heimdall_store::StoreError::GenerationConflict(_)),
                "{what}: {e:?}"
            );
            assert_eq!(&current(&w, &id), kept, "{what}: nothing changed");
        };
        let mut gone = with_local.clone();
        gone.local = None;
        refused(&gone, &with_local, "Some → None");
        let mut changed = with_local.clone();
        changed.local = Some(LocalIntent::Setup(setup_intent(2, apply_intent())));
        refused(&changed, &with_local, "another generation and digest");
        let mut other_variant = with_local.clone();
        other_variant.local = Some(LocalIntent::Catalog(
            heimdall_domain::catalog::CatalogIntent {
                action: heimdall_domain::catalog::CatalogAction::RemoveIdentity {
                    id: identity_id(),
                },
                approval: None,
            },
        ));
        refused(&other_variant, &with_local, "another variant");
        // `approval` goes None → Some once and is never replaced.
        let approval = |n: u8| heimdall_domain::projection::ProjectionApproval {
            decision: DecisionId::from_random_bytes([n; 16]),
            plan_digest: PlanDigest::from_sha256([1; 32]),
        };
        let mut approved = with_local.clone();
        if let Some(LocalIntent::Setup(s)) = approved.local.as_mut() {
            s.approval = Some(approval(1));
        }
        set(&approved).expect("approval None → Some");
        let mut replaced = approved.clone();
        if let Some(LocalIntent::Setup(s)) = replaced.local.as_mut() {
            s.approval = Some(approval(2));
        }
        refused(&replaced, &approved, "approval replaced");
        let mut dropped = approved.clone();
        if let Some(LocalIntent::Setup(s)) = dropped.local.as_mut() {
            s.approval = None;
        }
        refused(&dropped, &approved, "approval removed");
        // `local` beside `resolved` is refused.
        let mut both = approved.clone();
        both.resolved = Some(heimdall_domain::operation::ResolvedIntent {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope: Scope::empty(),
            deadline: heimdall_domain::time::Deadline {
                intent: DeadlineIntent::Duration("1h".into()),
                resolved_at: t0(),
                effective: shift(t0(), 3600),
            },
            policy_revision: None,
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            grant: None,
            binding: None,
            adapter: None,
            approval: None,
            covered: None,
        });
        refused(&both, &approved, "local beside resolved");
    }

    fn current(w: &World, id: &OperationId) -> RecoveryIntent {
        w.store
            .transaction(|tx| tx.recovery_intent(id))
            .unwrap()
            .unwrap()
    }

    /// The idempotency key of a caller-501 request.
    fn key_of(kind: OperationKind, rid: &str) -> IdempotencyKey {
        IdempotencyKey {
            caller: ctx(501, ClientRole::Owner),
            kind,
            request_id: RequestId::parse(rid).unwrap(),
        }
    }

    fn admission() -> SetupAdmission {
        SetupAdmission {
            environment: env_id(),
            intent: LocalIntent::Setup(setup_intent(1, apply_intent())),
            repair_target: None,
        }
    }

    /// U0b row 23 and the preserve list: `allow_new` is captured before the
    /// transaction and tested after `classify`. At the running limit a replay still
    /// returns its operation and a new request is `BACKPRESSURE`, not
    /// `setup_in_progress`, even with a setup blocker, writing nothing. Below the
    /// limit the blocker answers `setup_in_progress`. `pipeline: false` writes no
    /// `Authenticate` receipt.
    #[tokio::test]
    async fn u0b_admit_keeps_backpressure_order() {
        let mut w = World::new().await;
        let caller = unattended(501);
        let body = serde_json::json!({ "op": "setup", "action": "apply" });
        let admit = |w: &World, rid: &str, hash: u8, exclusive: Option<SetupAdmission>| {
            let ops = w.ops.clone();
            let caller = caller.clone();
            let body = body.clone();
            let rid = RequestId::parse(rid).unwrap();
            async move {
                ops.admit_for_test(
                    &caller,
                    OperationKind::SetupApply,
                    rid,
                    RequestHash([hash; 32]),
                    body,
                    false,
                    exclusive,
                )
                .await
            }
        };
        let blocker = match admit(&w, "u0b-bp-1", 1, Some(admission())).await.unwrap() {
            IdempotencyOutcome::Replay(id) => id,
            other => panic!("admitted: {other:?}"),
        };
        assert!(
            w.store
                .transaction(|tx| tx.stage_receipts(&blocker))
                .unwrap()
                .is_empty(),
            "pipeline false: no Authenticate receipt"
        );
        assert!(
            w.store
                .transaction(|tx| tx.recovery_intent(&blocker))
                .unwrap()
                .unwrap()
                .local
                .is_some()
        );
        // At the running limit.
        w.limits.max_running_operations = 0;
        w.restart().await;
        let replay = admit(&w, "u0b-bp-1", 1, Some(admission())).await.unwrap();
        assert_eq!(replay, IdempotencyOutcome::Replay(blocker.clone()));
        let counts = w.store.transaction(|tx| tx.operation_counts()).unwrap();
        let busy = admit(&w, "u0b-bp-2", 2, Some(admission()))
            .await
            .unwrap_err();
        assert_eq!(busy.code, Code::Backpressure, "{busy:?}");
        assert_eq!(busy.reason, None, "not setup_in_progress");
        assert!(busy.next.retry_after_ms.is_some());
        let unchanged = |w: &World| {
            assert_eq!(
                w.store.transaction(|tx| tx.operation_counts()).unwrap(),
                counts
            );
            assert!(
                w.store
                    .transaction(
                        |tx| tx.idempotency_record(&key_of(OperationKind::SetupApply, "u0b-bp-2"))
                    )
                    .unwrap()
                    .is_none(),
                "no idempotency record"
            );
        };
        unchanged(&w);
        // Below the limit: the blocker refuses.
        w.limits = Limits::default();
        w.restart().await;
        let blocked = admit(&w, "u0b-bp-2", 2, Some(admission()))
            .await
            .unwrap_err();
        assert_eq!(blocked.code, Code::ConfigConflict);
        assert_eq!(blocked.reason.as_deref(), Some("setup_in_progress"));
        assert_eq!(blocked.next.operation_id.as_ref(), Some(&blocker));
        assert_eq!(
            blocked.resource.as_ref().and_then(|r| r.id.clone()),
            Some(blocker.to_string())
        );
        unchanged(&w);
        // A replay is classified first and never sees the check.
        let again = admit(&w, "u0b-bp-1", 1, Some(admission())).await.unwrap();
        assert_eq!(again, IdempotencyOutcome::Replay(blocker.clone()));
        // Control: `pipeline: true` writes the `Authenticate` receipt.
        let ensure = serde_json::to_value(Request::Ensure(ensure_req(
            "u0b-bp-e",
            "u0b-bp-ew",
            &[("h1", "deploy")],
        )))
        .unwrap();
        let control = match w
            .ops
            .admit_for_test(
                &caller,
                OperationKind::Ensure,
                RequestId::parse("u0b-bp-e").unwrap(),
                RequestHash([3; 32]),
                ensure,
                true,
                None,
            )
            .await
            .unwrap()
        {
            IdempotencyOutcome::Replay(id) => id,
            other => panic!("admitted: {other:?}"),
        };
        let receipts = w
            .store
            .transaction(|tx| tx.stage_receipts(&control))
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].stage, EnsureStage::Authenticate.as_str());
    }

    /// U0b row 6 and the preserve list (`settle_effect_in`): an operation cancelled
    /// while its preparation is in flight gets a late `Confirmed`. The receipt, the
    /// prepared facts and the cleanup decision are written in one transaction; with
    /// the store `FaultHook` failing it, none of the three is written and the
    /// cancellation's in-flight intent is kept for the preparation's return path.
    #[tokio::test]
    async fn u0b_confirm_with_prepared_facts_keeps_cleanup_ownership() {
        for fail in [false, true] {
            let faults = Armed::new(FaultPoint::BeforeCommit);
            let (w, adapter) = r1312_pending_world_with(Setup {
                script: vec![FakeStep::Prepare(pairs_outcome())],
                faults: faults.clone(),
                ..Setup::default()
            })
            .await;
            let tag = if fail { "u0b-cf-f" } else { "u0b-cf-s" };
            let (op, gid, ensure) = r1318_held_ensure(&w, &adapter, tag).await;
            ok(w.ops
                .cancel(
                    &unattended(501),
                    CancelRequest {
                        operation_id: op.clone(),
                    },
                )
                .await);
            let in_flight = w
                .store
                .transaction(|tx| tx.cleanup_intent(&gid, &op))
                .unwrap()
                .expect("the cancellation's cleanup intent");
            assert!(
                in_flight.in_flight,
                "written while the attempt is in flight"
            );
            if fail {
                faults.arm_after_effect(w.fake.clone());
            }
            adapter.prepare_release.notify_one();
            let _ = ensure.await.unwrap();
            assert_eq!(w.effects(), 1, "the credential effect was applied");
            let confirmed = r1314_effects(&w, &op)
                .iter()
                .any(|e| matches!(e, EffectReceipt::Confirmed { .. }));
            let facts = w
                .store
                .transaction(|tx| tx.grant_prepared_facts(&gid))
                .unwrap();
            if fail {
                assert_eq!(faults.fired.load(Ordering::SeqCst), 1, "the failed commit");
                assert!(!confirmed, "no Confirmed receipt");
                assert_eq!(facts, None, "no prepared facts");
            } else {
                assert!(confirmed, "the Confirmed receipt");
                let facts = facts.expect("prepared facts with the receipt");
                assert_eq!(facts.pairs.len(), 2);
            }
            // Either way the effect ends with a cleanup call after it: the
            // decision written with the receipt, or the kept in-flight intent
            // processed by the preparation's return path.
            assert!(
                adapter.calls_after_effect(&gid) > Some(0),
                "a call followed the effect (fail {fail})"
            );
            assert!(
                w.store
                    .transaction(|tx| tx.cleanup_intent(&gid, &op))
                    .unwrap()
                    .is_none(),
                "the intent was processed and removed (fail {fail})"
            );
        }
    }

    fn inspect_req(subject: InspectSubject) -> InspectRequest {
        InspectRequest {
            subject,
            preview: None,
        }
    }

    /// U0b row 21 and the preserve list (`cleanup_pending`): the M01 regression
    /// `r1320_1_a_pending_cleanup_intent_is_visible_until_its_call_is_made` with the
    /// two new subjects added. `inspect identities` and `inspect projections` list
    /// no grant and are empty while the catalog and the projection are.
    #[tokio::test]
    async fn u0b_inspect_grants_keeps_cleanup_pending() {
        let (w, adapter, op) = r1319_commit_refused_after_commit("u0b-cp").await;
        let gid = r1313_grant_of(&w, &op);
        assert_eq!(
            r1310_view(&w, &gid).await["cleanup_pending"],
            serde_json::json!(true)
        );
        for subject in [InspectSubject::Identities, InspectSubject::Projections] {
            let r = ok(w.ops.inspect(&unattended(501), inspect_req(subject)).await);
            assert!(r.data.get("grants").is_none(), "{subject:?}: {}", r.data);
            assert!(!r.data.to_string().contains(gid.as_str()), "{subject:?}");
        }
        let ids = ok(w
            .ops
            .inspect(&unattended(501), inspect_req(InspectSubject::Identities))
            .await);
        assert_eq!(ids.data["identities"], serde_json::json!([]));
        let projections = ok(w
            .ops
            .inspect(&unattended(501), inspect_req(InspectSubject::Projections))
            .await);
        assert_eq!(projections.data["projections"], serde_json::json!([]));
        assert_eq!(projections.data["record"], serde_json::Value::Null);
        let sup = r1310_supervisor(&w);
        sup.scheduler_pass().await.unwrap();
        assert_eq!(adapter.calls_after_effect(&gid), Some(1));
        let after = ok(w
            .ops
            .inspect(&unattended(501), inspect_req(InspectSubject::Grants))
            .await);
        let listed = after.data["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["grant_id"] == serde_json::json!(gid))
            .cloned();
        assert!(
            listed
                .as_ref()
                .is_none_or(|v| v.get("cleanup_pending").is_none()),
            "{listed:?}"
        );
    }

    /// U0b row 21: `inspect identities` reports each catalog identity with its fresh
    /// eligibility and its live declaration's reference; owner role only.
    #[tokio::test]
    async fn u0b_inspect_identities_reports_fresh_eligibility_and_live_declaration() {
        let (w, _native) = native_world(true).await;
        let r = ok(w
            .ops
            .inspect(&unattended(501), inspect_req(InspectSubject::Identities))
            .await);
        let items = r.data["identities"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{}", r.data);
        let item = &items[0];
        assert_eq!(item["identity_id"], serde_json::json!(identity_id()));
        assert_eq!(item["interaction"], "none");
        assert_eq!(item["interaction_basis"], "declared");
        assert_eq!(item["noninteractive"]["eligible"], true);
        assert_eq!(item["declaration"]["revision"], 1);
        assert_eq!(item["declaration"]["endpoint"]["locator"], AGENT);
        // Past `expires_at`: still the live row, but no longer eligible.
        w.clock.advance(31 * MINUTE);
        let r = ok(w
            .ops
            .inspect(&unattended(501), inspect_req(InspectSubject::Identities))
            .await);
        let item = &r.data["identities"][0];
        assert_eq!(item["interaction"], "unknown");
        assert_eq!(item["noninteractive"]["eligible"], false);
        assert_eq!(item["declaration"]["revision"], 1);
        // A limited consumer sees none.
        let limited_view = ok(w
            .ops
            .inspect(&limited(501), inspect_req(InspectSubject::Identities))
            .await);
        assert_eq!(limited_view.data["identities"], serde_json::json!([]));
    }

    /// The setup operation of [`u0b_restart_keeps_withdrawal_and_cleanup_intent_recovery`],
    /// seeded as admission leaves it (queued, its `SetupIntent` stored), with one
    /// local receipt.
    pub(super) fn seed_setup_operation(w: &World, n: u8, kind: OperationKind) -> OperationId {
        let id = OperationId::from_random_bytes([n; 16]);
        let rid = RequestId::parse(&format!("u0b-setup-{n}")).unwrap();
        let op = queued(&id, kind, &rid, n);
        let intent = RecoveryIntent {
            request: serde_json::json!({ "op": "setup", "action": "apply" }),
            resolved: None,
            local: Some(LocalIntent::Setup(setup_intent(
                u64::from(n),
                apply_intent(),
            ))),
        };
        w.store
            .transaction(|tx| {
                tx.insert_operation(&op, &idem_of(&op))?;
                tx.set_recovery_intent(&id, &intent)?;
                tx.append_stage_receipt(&id, &local_receipt())
            })
            .unwrap();
        id
    }

    pub(super) fn local_receipt() -> StageReceipt {
        StageReceipt {
            stage: heimdall_domain::operation::STAGE_SETUP_FILE.into(),
            recorded_at: t0(),
            effect: EffectReceipt::Attempted {
                adapter: AdapterIdentity {
                    mechanism: "config_projection".into(),
                    instance: env_id().to_string(),
                },
                effect_token: "eff_u0b_setup".into(),
            },
            local: Some(heimdall_domain::operation::LocalReceipt::File {
                step: 0,
                phase: heimdall_domain::operation::FilePhase::Staged {
                    identity: heimdall_domain::projection::FileIdentity::Unix {
                        dev: 1,
                        ino: 2,
                        birth: None,
                    },
                },
            }),
        }
    }

    /// The `runtime_lifecycle` events that name `id` as unresolved, `driver_unavailable`.
    pub(super) fn unresolved_events(w: &World, id: &OperationId) -> Vec<serde_json::Value> {
        w.events()
            .into_iter()
            .filter(|e| e.event.event_type == EventType::RuntimeLifecycle)
            .map(|e| e.event.payload)
            .filter(|p| p["operation_id"] == serde_json::json!(id))
            .collect()
    }

    /// U0b row 11 and the preserve list. One store holds an open setup operation, an
    /// interrupted withdrawal, a pending remote record whose round was claimed and
    /// never completed, and a cleanup intent whose operation is settled. After a
    /// restart: the setup operation stays unresolved with `driver_unavailable`
    /// (this runtime has no projection writer), the withdrawal completes, the
    /// interrupted round is due at once, and the cleanup intent's call is made and
    /// the intent removed.
    #[tokio::test]
    async fn u0b_restart_keeps_withdrawal_and_cleanup_intent_recovery() {
        // A cleanup intent whose operation is settled: the commit refusal's
        // post-commit processing fails (as `r1319_commit_refused_after_commit`).
        let faults = Armed::new(FaultPoint::AfterCommit);
        let (mut w, adapter) = r1312_pending_world_with(Setup {
            faults: faults.clone(),
            hook: ArmAt::new(EnsureStage::Commit, faults.clone()),
            ..Setup::default()
        })
        .await;
        let mut req = ensure_req("u0b-rr", "u0b-rr-work", &[("h1", "deploy")]);
        req.required_capabilities.offline_until = Some(shift(t0(), 5400));
        let e = err(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(e.code, Code::StateUnavailable, "the post-commit fault");
        let refused = e.operation_id.clone().unwrap();
        assert_eq!(w.op(&refused).state, OperationState::Failed);
        let cleanup_grant = r1313_grant_of(&w, &refused);
        assert!(
            w.store
                .transaction(|tx| tx.cleanup_intent(&cleanup_grant, &refused))
                .unwrap()
                .is_some(),
            "the intent waits"
        );
        // A pending remote record with a claimed, uncompleted round (as r1313_4).
        let claimed = r136_ready(&w, "u0b-rr-c", "u0b-rr-cw", "h2", "1h").await;
        adapter.stall.store(true, Ordering::SeqCst);
        let owner = unattended(501);
        let revoke = w.ops.revoke(
            &owner,
            RevokeRequest {
                grant_id: claimed.grant_id.clone(),
                request_id: RequestId::parse("u0b-rr-revoke").unwrap(),
            },
        );
        assert!(
            r1312_until_crash(&adapter, revoke).await,
            "crashed after the claim"
        );
        let rec = r1312_record(&w, &claimed.grant_id).expect("claimed");
        assert_eq!((rec.attempts, rec.claimed_at.is_some()), (1, true));
        // An interrupted withdrawal (as r139_3): the use's transaction wrote the
        // tombstone and committed, and its completion never ran.
        let withdrawn = r136_ready(&w, "u0b-rr-w", "u0b-rr-ww", "h1", "1h").await;
        let reserved = w
            .ops
            .reserve_issuance(u10_issuance(&withdrawn.grant_id, shift(t0(), 1800)))
            .await
            .unwrap();
        issue(
            &w,
            &reserved.id,
            &u10_issuance(&withdrawn.grant_id, t0()).facts,
        )
        .await
        .unwrap();
        r138_set_automatic_activation(&w, false);
        faults.arm();
        let crashed = w
            .ops
            .reserve_issuance(u10_issuance(&withdrawn.grant_id, shift(t0(), 600)))
            .await
            .unwrap_err();
        assert_no_canary(&crashed.message);
        assert_eq!(
            faults.fired.load(Ordering::SeqCst),
            2,
            "both crash points fired"
        );
        assert_eq!(w.grant(&withdrawn.grant_id).state, GrantState::Revoking);
        assert!(r139_withdrawals(&w, &withdrawn.grant_id).is_empty());
        // The open setup operation.
        let setup = seed_setup_operation(&w, 0x81, OperationKind::SetupApply);
        let setup_before = (
            w.op(&setup),
            w.store.transaction(|tx| tx.stage_receipts(&setup)).unwrap(),
        );
        r1310_restart_pending(&mut w, &adapter).await;
        // The setup operation: untouched, reported.
        assert_eq!(w.op(&setup), setup_before.0);
        assert_eq!(
            w.store.transaction(|tx| tx.stage_receipts(&setup)).unwrap(),
            setup_before.1
        );
        let reported = unresolved_events(&w, &setup);
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert_eq!(reported[0]["reason"], "driver_unavailable");
        // The withdrawal completed.
        assert_eq!(r139_withdrawals(&w, &withdrawn.grant_id).len(), 1);
        // The cleanup intent's call was made and the intent removed.
        assert!(adapter.calls_after_effect(&cleanup_grant) > Some(0));
        assert!(
            w.store
                .transaction(|tx| tx.cleanup_intent(&cleanup_grant, &refused))
                .unwrap()
                .is_none()
        );
        // The interrupted round is due at once.
        let sup = r1312_supervisor(&w, 8);
        sup.scheduler_pass().await.unwrap();
        let rec = r1312_record(&w, &claimed.grant_id).expect("still pending");
        assert_eq!(
            rec.attempts, 2,
            "called at once; the interrupted round counts"
        );
        assert_eq!(rec.claimed_at, None);
        assert_eq!(w.op(&setup).state, OperationState::Queued);
    }

    /// A world with the catalog seeded (`declared` as in [`seed_catalog`]) whose
    /// adapters are the M01 fake and a `native_agent` fake with `script`.
    async fn native_script_world(
        declared: bool,
        script: Vec<FakeStep>,
        hook: Arc<dyn StageHook>,
    ) -> (World, Arc<FakeCredentialAdapter>) {
        let mut w = World::with(Setup {
            hook,
            ..Setup::default()
        })
        .await;
        seed_catalog(&w, declared);
        let native = FakeCredentialAdapter::new(native_descriptor(), script);
        w.ops = Operations::start(OperationsConfig {
            adapters: vec![
                w.fake.clone() as Arc<dyn CredentialAdapter>,
                native.clone() as Arc<dyn CredentialAdapter>,
            ],
            ..w.config()
        })
        .await
        .unwrap();
        (w, native)
    }

    /// ADR-0007 §12.15 item 7 (E-U6-4). An existing-access adapter's `prepare` error
    /// names the provider (`OpError::from_adapter_for(&e, "provider")`): an absent
    /// endpoint is `SERVICE_UNAVAILABLE` with reason `endpoint_absent`;
    /// `INTERACTION_REQUIRED` carries the reason and `next.provider_interaction` of
    /// the pair eligibility the runtime computes (an undeclared native key:
    /// `interaction_unknown`/`unknown`; every pair declared, so the adapter's refusal
    /// was its fallback clearance: `fallback_identity_interaction`), never a
    /// `decision_ref`; `PROVIDER_LOCKED` asks for `provider_unlock`. The M01 fake
    /// keeps the M01 mapping.
    #[tokio::test]
    async fn u0b_existing_access_prepare_errors_name_the_provider() {
        let script = vec![
            FakeStep::Fail(AdapterError::Unavailable("agent socket absent".into())),
            FakeStep::Fail(AdapterError::InteractionRequired(
                InteractionRequirement::ProviderDialog,
            )),
            FakeStep::Fail(AdapterError::ProviderLocked),
            FakeStep::Prepare(pairs_outcome()),
        ];
        let (w, native) = native_script_world(false, script, Arc::new(NoStageHook)).await;
        let run = |rid: &str| {
            let ops = w.ops.clone();
            let req = ensure_req(rid, &format!("{rid}-w"), &both_pairs());
            async move { ops.ensure(&unattended(501), req).await }
        };
        let absent = err(run("u0b-e4-1").await);
        assert_eq!(absent.code, Code::ServiceUnavailable);
        assert_eq!(absent.reason.as_deref(), Some("endpoint_absent"));
        let resource = absent.resource.as_deref().unwrap();
        assert_eq!(
            (resource.kind.as_str(), resource.id.as_deref()),
            ("provider", Some("native_agent"))
        );
        assert_eq!(absent.effect_status, EffectStatus::None);
        let needs = err(run("u0b-e4-2").await);
        assert_eq!(needs.code, Code::InteractionRequired);
        assert_eq!(needs.reason.as_deref(), Some("interaction_unknown"));
        assert_eq!(needs.next.action, "interact");
        assert_eq!(needs.next.decision_ref, None, "never a decision_ref");
        assert_eq!(
            needs.next.provider_interaction,
            Some(heimdall_contract::provider::ProviderInteractionRef {
                provider: ProviderKind::NativeAgent,
                kind: InteractionKind::Unknown,
            })
        );
        assert_eq!(needs.resource.as_deref().unwrap().kind, "provider");
        let env = serde_json::to_value(needs.clone().into_envelope()).unwrap();
        assert_eq!(env["data"]["error"]["reason"], "interaction_unknown");
        assert_eq!(
            env["data"]["error"]["next"]["provider_interaction"]["provider"],
            "native_agent"
        );
        let locked = err(run("u0b-e4-3").await);
        assert_eq!(locked.code, Code::ProviderLocked);
        assert_eq!(
            locked.next.provider_interaction.map(|p| p.kind),
            Some(InteractionKind::ProviderUnlock)
        );
        assert_eq!(native.effect_count(), 0);
        // Every pair declared `none`: the refusal is the fallback clearance's.
        let (w2, _native) = native_script_world(
            true,
            vec![FakeStep::Fail(AdapterError::InteractionRequired(
                InteractionRequirement::ProviderDialog,
            ))],
            Arc::new(NoStageHook),
        )
        .await;
        let fallback = err(w2
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-e4-4", "u0b-e4-4-w", &both_pairs()),
            )
            .await);
        assert_eq!(fallback.code, Code::InteractionRequired);
        assert_eq!(
            fallback.reason.as_deref(),
            Some("fallback_identity_interaction")
        );
        assert_eq!(
            fallback.next.provider_interaction.map(|p| p.provider),
            Some(ProviderKind::NativeAgent)
        );
        // The M01 fake (no catalog pair names it) keeps the M01 mapping.
        let m01 = World::with(Setup {
            script: vec![FakeStep::Fail(AdapterError::Unavailable("socket".into()))],
            ..Setup::default()
        })
        .await;
        let e = err(m01
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-e4-5", "u0b-e4-5-w", &[("h1", "deploy")]),
            )
            .await);
        assert_eq!(e.code, Code::ServiceUnavailable);
        assert_eq!(e.reason, None);
        assert_eq!(e.resource.as_deref().unwrap().kind, "adapter");
        w.events();
    }

    /// ADR-0007 §12.15 item 7 (E-U6-6). After a restart, an adapter with no
    /// external effect has forgotten what it returned, so its `reconcile` of the
    /// confirmed effect says `not_applied`. The runtime answers from the
    /// `PreparedFacts` recorded with the `Confirmed` receipt instead: the operation
    /// commits, with the same history, and no second `prepare` is made. An adapter
    /// with external effects keeps the M01 answer (`not_applied` fails closed).
    #[tokio::test]
    async fn u0b_reconcile_after_restart_answers_from_prepared_facts() {
        for external in [false, true] {
            let hook: Arc<dyn StageHook> =
                ScriptedStageHook::new([(EnsureStage::Commit, Code::ServiceUnavailable)], []);
            let mut descriptor = native_descriptor();
            descriptor.external_side_effects = external;
            let mut w = World::with(Setup {
                hook,
                ..Setup::default()
            })
            .await;
            seed_catalog(&w, true);
            let first = FakeCredentialAdapter::new(
                descriptor.clone(),
                vec![FakeStep::Prepare(pairs_outcome())],
            );
            w.ops = Operations::start(OperationsConfig {
                adapters: vec![first.clone() as Arc<dyn CredentialAdapter>],
                ..w.config()
            })
            .await
            .unwrap();
            let req = ensure_req("u0b-e6", "u0b-e6-w", &both_pairs());
            let stopped = err(w.ops.ensure(&unattended(501), req.clone()).await);
            let op = stopped.operation_id.clone().unwrap();
            let gid = r1313_grant_of(&w, &op);
            let stored = w
                .store
                .transaction(|tx| tx.grant_prepared_facts(&gid))
                .unwrap()
                .expect("facts recorded with the confirmation");
            // Restart: a fresh adapter instance with an empty memory.
            let fresh =
                FakeCredentialAdapter::new(descriptor, vec![FakeStep::Prepare(pairs_outcome())]);
            w.ops = Operations::start(OperationsConfig {
                adapters: vec![fresh.clone() as Arc<dyn CredentialAdapter>],
                ..w.config()
            })
            .await
            .unwrap();
            let r = w.ops.ensure(&unattended(501), req).await;
            assert_eq!(
                fresh.effect_count(),
                0,
                "external {external}: never prepared again"
            );
            if external {
                let e = err(r);
                assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
                assert_eq!(w.op(&op).state, OperationState::Failed);
                continue;
            }
            let done = ok(r);
            assert_eq!(done.code, Code::AccessReady);
            assert_eq!(done.operation_id.as_ref(), Some(&op));
            // The history is the recorded one; the fresh part is recomputed.
            assert_eq!(done.data.provider, stored.provider);
            assert_eq!(done.data.consumer.environment, stored.environment);
            assert_eq!(done.data.consumer.pairs.len(), 2);
            for (p, s) in done.data.consumer.pairs.iter().zip(&stored.pairs) {
                assert_eq!(p.destination, s.destination);
                assert_eq!(p.endpoint, s.endpoint);
                assert_eq!(p.alias, s.alias);
                assert_eq!(p.identity_selection, s.identity_selection.selection);
                assert_eq!(p.interaction, InteractionKind::None, "declared, fresh");
            }
            // Conservative beyond the history: no claim past the commit's time.
            assert!(done.data.usable_until <= w.clock.wall());
            assert_eq!(
                done.data.refresh_dependency,
                RefreshDependency::ProviderInteraction
            );
            w.events();
        }
    }

    /// ADR-0007 §12.15 item 3(c). A pair's full `identity_selection_report` crosses
    /// the port and is what the runtime stores as the pair's history (entries,
    /// `IdentitiesOnly`, `cleared` marks), and results report it back. A pair
    /// without one, or whose report contradicts its verdict, keeps the verdict
    /// alone (no entries, `IdentitiesOnly` undetermined), which never clears a
    /// fallback.
    #[tokio::test]
    async fn u0b_prepared_facts_keep_the_full_identity_selection_report() {
        use heimdall_contract::doctor::ConfigProvenance;
        use heimdall_contract::provider::{
            Certainty, IdentityBacking, IdentityEntry, IdentityEntryKind, IdentityEntrySource,
        };
        let report = IdentitySelectionReport {
            selection: IdentitySelection::NotExclusive,
            entries: vec![
                IdentityEntry {
                    kind: IdentityEntryKind::IdentityFile,
                    source: IdentityEntrySource::Managed,
                    provenance: Some(ConfigProvenance {
                        path_display: "~/.config/heimdall/ssh/heimdall.conf".into(),
                        line: 4,
                    }),
                    certainty: Certainty::Determined,
                    fingerprint: Some(FINGERPRINT.into()),
                    backing: IdentityBacking::Agent,
                    cleared: None,
                },
                IdentityEntry {
                    kind: IdentityEntryKind::IdentityFile,
                    source: IdentityEntrySource::User,
                    provenance: Some(ConfigProvenance {
                        path_display: "~/.ssh/config".into(),
                        line: 9,
                    }),
                    certainty: Certainty::Determined,
                    fingerprint: None,
                    backing: IdentityBacking::File,
                    cleared: Some(false),
                },
            ],
            identities_only: IdentitiesOnly::DeterminedYes,
        };
        let mut outcome = pairs_outcome();
        // h1 carries the full report; h2 one that contradicts its verdict.
        outcome.integration.pairs[0].identity_selection = IdentitySelection::NotExclusive;
        outcome.integration.pairs[0].identity_selection_report = Some(report.clone());
        outcome.integration.pairs[1].identity_selection_report = Some(report.clone());
        let (w, _native) = native_script_world(
            true,
            vec![FakeStep::Prepare(outcome)],
            Arc::new(NoStageHook),
        )
        .await;
        let done = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-3c", "u0b-3c-w", &both_pairs()),
            )
            .await);
        let facts = w
            .store
            .transaction(|tx| tx.grant_prepared_facts(&done.data.grant_id))
            .unwrap()
            .unwrap();
        assert_eq!(facts.pairs[0].identity_selection, report, "the full report");
        let verdict_only = IdentitySelectionReport {
            selection: IdentitySelection::Exclusive,
            entries: Vec::new(),
            identities_only: IdentitiesOnly::Undetermined,
        };
        assert_eq!(
            facts.pairs[1].identity_selection, verdict_only,
            "contradicting"
        );
        // Reported back as history.
        assert_eq!(
            done.data.consumer.pairs[0]
                .identity_selection_report
                .as_ref(),
            Some(&report)
        );
        assert_eq!(
            done.data.consumer.pairs[1]
                .identity_selection_report
                .as_ref(),
            Some(&verdict_only)
        );
        // An older document without the field decodes; `None` is not serialized.
        let mut plain = serde_json::to_value(&done.data.consumer.pairs[0]).unwrap();
        plain
            .as_object_mut()
            .unwrap()
            .remove("identity_selection_report");
        let back: PairIntegration = serde_json::from_value(plain).unwrap();
        assert_eq!(back.identity_selection_report, None);
        assert!(
            !serde_json::to_string(&back)
                .unwrap()
                .contains("identity_selection_report")
        );
        w.events();
    }
}

// =================================================================================
// ⟨M02⟩ U0b phase 2, row 24: every real adapter call is bounded (m02-plan U0b row
// 24; M2-T06; ADR-0006 §13.20 item 3; ADR-0007 §7 "Every call is bounded", §12.13
// QR17)
// =================================================================================

/// `adapter_call_timeout` is 200 ms (m02-plan U0b "Tests, phase 2"). The fake's hang
/// steps (`testkit::FakeStep::{ApplyThenHang, HangBeforeEffect, HangReconcile,
/// HangRevoke}`) wait until released; a hang released while its future is still
/// awaited counts as work after the drop (`FakeCredentialAdapter::work_after_drop`),
/// which a bounded runtime keeps at 0. Timing: every wait below is bounded by
/// [`until`] (10 s); the bound itself is asserted only from below (a call is never
/// answered before it), so a loaded host cannot make a case pass wrongly.
mod u0b_adapter_bound {
    use super::*;
    use heimdall_app::operations::{ADAPTER_CALL_TIMED_OUT, bounded_adapter_call};
    use heimdall_app::ports::{AdapterError, ReconcileOutcome};
    use heimdall_domain::operation::{EffectReceipt, StageReceipt};
    use heimdall_store::NoFaults;
    use heimdall_testkit::FakeEvent;

    pub(super) const BOUND: Duration = Duration::from_millis(200);

    pub(super) fn bounded_limits() -> Limits {
        Limits {
            adapter_call_timeout: BOUND,
            ..Limits::default()
        }
    }

    pub(super) async fn bounded_world(script: Vec<FakeStep>, faults: Arc<dyn FaultHook>) -> World {
        World::with(Setup {
            script,
            faults,
            limits: bounded_limits(),
            ..Setup::default()
        })
        .await
    }

    /// Poll `f` every 5 ms until it holds; fails after 10 s.
    pub(super) async fn until(what: &str, f: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn receipts_of(w: &World, op: &OperationId) -> Vec<StageReceipt> {
        w.store.transaction(|tx| tx.stage_receipts(op)).unwrap()
    }

    /// The last effect receipt (`NotAttempted` excluded).
    fn last_effect(w: &World, op: &OperationId) -> Option<EffectReceipt> {
        r1314_effects(w, op).pop()
    }

    fn async_req(rid: &str, work: &str) -> EnsureRequest {
        EnsureRequest {
            wait: WaitMode::Async,
            ..ensure_req(rid, work, &[("h1", "deploy")])
        }
    }

    /// Start an ensure whose preparation hangs, and return its operation once the
    /// fake's hang was entered (the effect, for `ApplyThenHang`, already applied).
    async fn hung_ensure(w: &World, rid: &str) -> OperationId {
        let e = err(w
            .ops
            .ensure(&unattended(501), async_req(rid, &format!("{rid}-w")))
            .await);
        assert_eq!(e.code, Code::Accepted, "{}", e.message);
        let op = e.operation_id.clone().unwrap();
        until("the hang", || w.fake.hangs_entered() == 1).await;
        op
    }

    fn intent_of(
        w: &World,
        op: &OperationId,
    ) -> Option<heimdall_domain::revocation::CleanupIntent> {
        let gid = r1313_grant_of(w, op);
        w.store
            .transaction(|tx| tx.cleanup_intent(&gid, op))
            .unwrap()
    }

    fn revocations(w: &World) -> usize {
        w.fake.revocations.lock().unwrap().len()
    }

    /// `u0b_prepare_timeout_after_effect_settles_uncertain_and_releases_marker`. The
    /// operation is cancelled while `ApplyThenHang` runs, which writes a cleanup
    /// intent with `in_flight`. A supervisor pass during the hang skips it, with no
    /// `revoke`. After the bound, the receipts end in `Uncertain`, the preparing
    /// marker is released, `settle_effect_in` ran in the receipt's transaction (the
    /// intent re-recorded with `in_flight: false`, then processed by its origin: a
    /// call after the effect, and the intent removed), and the adapter slot is free.
    #[tokio::test]
    async fn u0b_prepare_timeout_after_effect_settles_uncertain_and_releases_marker() {
        let w = bounded_world(vec![FakeStep::ApplyThenHang(outcome())], Arc::new(NoFaults)).await;
        let started = std::time::Instant::now();
        let op = hung_ensure(&w, "u0b-pt").await;
        assert_eq!(w.effects(), 1, "the effect applied before the hang");
        assert_eq!(w.ops.preparing_operations(), vec![op.clone()]);
        assert_eq!(
            w.ops.available_adapter_slots(),
            Limits::default().max_concurrent_adapter_calls - 1
        );
        let c = ok(w
            .ops
            .cancel(
                &unattended(501),
                CancelRequest {
                    operation_id: op.clone(),
                },
            )
            .await);
        assert_eq!(c.data["may_have_external_effect"], true);
        let intent = intent_of(&w, &op).expect("the cancellation's cleanup intent");
        assert!(intent.in_flight, "written while the attempt is in flight");
        // The cancellation's own origin processing calls now (it may precede the
        // effect, so the intent is kept); a supervisor pass during the hang skips it.
        let before_pass = revocations(&w);
        r1310_supervisor(&w).revocation_pass().await.unwrap();
        assert_eq!(
            revocations(&w),
            before_pass,
            "the pass skipped the in-flight intent"
        );
        assert!(intent_of(&w, &op).is_some_and(|i| i.in_flight));
        // The bound elapses.
        until("the marker's release", || {
            w.ops.preparing_operations().is_empty()
        })
        .await;
        until("the origin processing", || intent_of(&w, &op).is_none()).await;
        assert!(
            started.elapsed() >= BOUND,
            "never answered before the bound"
        );
        assert!(
            matches!(last_effect(&w, &op), Some(EffectReceipt::Uncertain { .. })),
            "{:?}",
            r1314_effects(&w, &op)
        );
        assert_eq!(w.op(&op).state, OperationState::Cancelled);
        assert_eq!(
            w.ops.available_adapter_slots(),
            Limits::default().max_concurrent_adapter_calls,
            "the adapter slot is free"
        );
        assert_eq!(revocations(&w), before_pass + 1, "one call after the bound");
        // The future was dropped at the bound: released now, it does no more work.
        assert_eq!(w.fake.hangs_dropped(), 1);
        w.fake.release_hangs();
        tokio::task::yield_now().await;
        assert_eq!(w.fake.work_after_drop(), 0);
        assert_eq!(w.effects(), 1);
        w.events();
    }

    /// A store fault hook that, once armed, lets `skip` transactions commit and then
    /// fails the next `fail` ones at `BeforeCommit`.
    struct FailNext {
        skip: AtomicUsize,
        fail: AtomicUsize,
        armed: AtomicBool,
        fired: AtomicUsize,
    }

    impl FailNext {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                skip: AtomicUsize::new(0),
                fail: AtomicUsize::new(0),
                armed: AtomicBool::new(false),
                fired: AtomicUsize::new(0),
            })
        }
        fn arm(&self, skip: usize, fail: usize) {
            self.skip.store(skip, Ordering::SeqCst);
            self.fail.store(fail, Ordering::SeqCst);
            self.armed.store(true, Ordering::SeqCst);
        }
    }

    impl FaultHook for FailNext {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point != FaultPoint::BeforeCommit || !self.armed.load(Ordering::SeqCst) {
                return FaultAction::Continue;
            }
            if self
                .skip
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return FaultAction::Continue;
            }
            if self
                .fail
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                self.fired.fetch_add(1, Ordering::SeqCst);
                return FaultAction::Fail;
            }
            self.armed.store(false, Ordering::SeqCst);
            FaultAction::Continue
        }
    }

    /// `u0b_timed_out_preparation_cleanup_processed_by_supervisor_without_restart`.
    /// As above, but the origin processing fails (the store `FaultHook` fails its
    /// transactions: the cleanup decision and the return path's read). The next
    /// `revocation_pass`, in the same process and with no restart, makes the
    /// `revoke` call and removes the intent; the call follows the effect in the
    /// fake's journal. Variant: `mark_uncertain`'s own transaction fails too, so the
    /// original `in_flight` intent is what remains; the pass processes it, because
    /// the marker was released.
    #[tokio::test]
    async fn u0b_timed_out_preparation_cleanup_processed_by_supervisor_without_restart() {
        // (skip, fail): mark_uncertain commits, then the origin's decision and the
        // return path's read fail; or mark_uncertain fails as well.
        for (skip, fail, uncertain) in [(1, 2, true), (0, 2, false)] {
            let faults = FailNext::new();
            let w = bounded_world(vec![FakeStep::ApplyThenHang(outcome())], faults.clone()).await;
            let rid = format!("u0b-ts-{skip}");
            let op = hung_ensure(&w, &rid).await;
            ok(w.ops
                .cancel(
                    &unattended(501),
                    CancelRequest {
                        operation_id: op.clone(),
                    },
                )
                .await);
            let gid = r1313_grant_of(&w, &op);
            faults.arm(skip, fail);
            until("the marker's release", || {
                w.ops.preparing_operations().is_empty()
            })
            .await;
            until("the injected failures", || {
                faults.fired.load(Ordering::SeqCst) == fail
            })
            .await;
            // Let the drive finish its return path.
            until("the slot", || {
                w.ops.available_adapter_slots() == Limits::default().max_concurrent_adapter_calls
            })
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let kept =
                intent_of(&w, &op).expect("the origin processing failed: the intent is kept");
            assert_eq!(
                matches!(last_effect(&w, &op), Some(EffectReceipt::Uncertain { .. })),
                uncertain,
                "skip {skip}"
            );
            assert_eq!(
                kept.in_flight, !uncertain,
                "skip {skip}: the intent on record"
            );
            let calls_before = revocations(&w);
            // The next pass of the supervisor, same process, no restart.
            r1310_supervisor(&w).revocation_pass().await.unwrap();
            assert_eq!(
                revocations(&w),
                calls_before + 1,
                "skip {skip}: the pass made the call"
            );
            assert!(
                intent_of(&w, &op).is_none(),
                "skip {skip}: and removed the intent"
            );
            let journal = w.fake.journal();
            let effect = journal
                .iter()
                .position(|e| matches!(e, FakeEvent::Effect(_)))
                .unwrap();
            assert!(
                matches!(journal.last(), Some(FakeEvent::Revoke(g)) if *g == gid)
                    && journal.len() - 1 > effect,
                "skip {skip}: the call follows the effect: {journal:?}"
            );
            w.fake.release_hangs();
            tokio::task::yield_now().await;
            assert_eq!(w.fake.work_after_drop(), 0);
        }
    }

    /// `u0b_prepare_timeout_while_running_is_outcome_unknown`. Without a
    /// cancellation the operation moves to `outcome_unknown` (`OUTCOME_UNKNOWN`,
    /// effect `unknown`); the marker and the slot are released; it stays unresolved
    /// until `reconcile` settles it (the same request ID: one effect, no second
    /// `prepare`).
    #[tokio::test]
    async fn u0b_prepare_timeout_while_running_is_outcome_unknown() {
        let w = bounded_world(vec![FakeStep::ApplyThenHang(outcome())], Arc::new(NoFaults)).await;
        let started = std::time::Instant::now();
        let e = err(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-pr", "u0b-pr-w", &[("h1", "deploy")]),
            )
            .await);
        assert!(started.elapsed() >= BOUND);
        assert_eq!(e.code, Code::OutcomeUnknown, "{}", e.message);
        assert_eq!(e.effect_status, EffectStatus::Unknown);
        let op = e.operation_id.clone().unwrap();
        assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
        assert!(w.ops.preparing_operations().is_empty());
        assert_eq!(
            w.ops.available_adapter_slots(),
            Limits::default().max_concurrent_adapter_calls
        );
        assert!(matches!(
            last_effect(&w, &op),
            Some(EffectReceipt::Uncertain { .. })
        ));
        assert!(
            intent_of(&w, &op).is_none(),
            "nothing to clean up while unresolved"
        );
        // Still unresolved after a wait; the same request ID reconciles it.
        tokio::time::sleep(BOUND).await;
        assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
        let done = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-pr", "u0b-pr-w", &[("h1", "deploy")]),
            )
            .await);
        assert_eq!(done.code, Code::AccessReady);
        assert_eq!(done.operation_id.as_ref(), Some(&op));
        assert_eq!(w.effects(), 1, "reconciled, never prepared again");
        assert_eq!(w.fake.hangs_entered(), 1);
        w.fake.release_hangs();
        tokio::task::yield_now().await;
        assert_eq!(w.fake.work_after_drop(), 0);
        w.events();
    }

    /// Pipeline hook (production `StageHook`): while armed, every drive stops
    /// right before `Probe` (after `Reconcile` confirmed the effect).
    #[derive(Default)]
    struct StopBeforeProbe {
        armed: AtomicBool,
    }

    impl StageHook for StopBeforeProbe {
        fn before(&self, stage: EnsureStage) -> Result<(), Code> {
            if stage == EnsureStage::Probe && self.armed.load(Ordering::SeqCst) {
                return Err(Code::ServiceUnavailable);
            }
            Ok(())
        }
        fn after(&self, _stage: EnsureStage) -> Result<(), Code> {
            Ok(())
        }
    }

    fn shared_req(i: usize) -> EnsureRequest {
        EnsureRequest {
            until: Some(DeadlineIntent::Absolute(shift(t0(), 3600).to_string())),
            wait: WaitMode::Sync { timeout_ms: 2_000 },
            ..ensure_req(
                &format!("u0b-rc-sh-{i}"),
                "u0b-rc-sh-w",
                &[("h1", "deploy"), ("h3", "deploy")],
            )
        }
    }

    /// Retry `i`'s shared request (same key) until its operation settles; bounded.
    async fn shared_settled(w: &World, i: usize) -> OpResult<EnsureData> {
        for _ in 0..200 {
            let r = w.ops.ensure(&unattended(501), shared_req(i)).await;
            match &r {
                Err(e) if matches!(e.code, Code::Accepted | Code::ServiceUnavailable) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                _ => return r,
            }
        }
        panic!("shared request {i} did not settle");
    }

    /// `u0b_reconcile_timeout_matches_each_call_sites_error_arm`. `HangReconcile`
    /// at each of the four `reconcile` sites gives that site's existing `Err` arm,
    /// and no slot or marker is kept:
    /// * `stage_reconcile` (an earlier attempt): the attempt is marked `Uncertain`
    ///   and the operation is `outcome_unknown`;
    /// * `reconcile_unresolved`: the operation stays unresolved, no receipt added;
    /// * `stage_commit` (no facts in this drive): `SERVICE_UNAVAILABLE` with effect
    ///   `partial`, the operation still running;
    /// * `continued_preparation`: no facts, so the attached request is answered as
    ///   still in progress (`SERVICE_UNAVAILABLE`) and keeps running.
    ///
    /// Each recovers once the hang is gone, with one effect.
    #[tokio::test]
    async fn u0b_reconcile_timeout_matches_each_call_sites_error_arm() {
        let free = Limits::default().max_concurrent_adapter_calls;
        // 1. stage_reconcile: the confirmation's transaction fails after the
        // effect, leaving `Attempted` as the last receipt of a running operation.
        {
            let faults = Armed::new(FaultPoint::BeforeCommit);
            let w = bounded_world(vec![FakeStep::Prepare(outcome())], faults.clone()).await;
            faults.arm_after_effect(w.fake.clone());
            let req = ensure_req("u0b-rc-1", "u0b-rc-1-w", &[("h1", "deploy")]);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            let op = e.operation_id.clone().unwrap();
            assert!(matches!(
                last_effect(&w, &op),
                Some(EffectReceipt::Attempted { .. })
            ));
            w.fake.arm(FakeStep::HangReconcile);
            let e = err(w.ops.ensure(&unattended(501), req).await);
            assert_eq!(e.code, Code::OutcomeUnknown, "{}", e.message);
            assert_eq!(w.op(&op).state, OperationState::OutcomeUnknown);
            assert!(matches!(
                last_effect(&w, &op),
                Some(EffectReceipt::Uncertain { .. })
            ));
            assert_eq!(w.ops.available_adapter_slots(), free);
            assert!(w.ops.preparing_operations().is_empty());
            assert_eq!((w.fake.hangs_entered(), w.fake.hangs_dropped()), (1, 1));
        }
        // 2. reconcile_unresolved: an uncertain attempt, reconciled by a retry.
        {
            let w = bounded_world(
                vec![FakeStep::ApplyButLoseReply(outcome())],
                Arc::new(NoFaults),
            )
            .await;
            let req = ensure_req("u0b-rc-2", "u0b-rc-2-w", &[("h1", "deploy")]);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            assert_eq!(e.code, Code::OutcomeUnknown);
            let op = e.operation_id.clone().unwrap();
            let receipts = receipts_of(&w, &op).len();
            w.fake.arm(FakeStep::HangReconcile);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            assert_eq!(e.code, Code::OutcomeUnknown);
            assert_eq!(
                w.op(&op).state,
                OperationState::OutcomeUnknown,
                "stays unresolved"
            );
            assert_eq!(receipts_of(&w, &op).len(), receipts, "nothing recorded");
            assert_eq!(w.ops.available_adapter_slots(), free);
            assert_eq!(w.fake.hangs_dropped(), 1);
            let done = ok(w.ops.ensure(&unattended(501), req).await);
            assert_eq!(done.code, Code::AccessReady);
            assert_eq!(w.effects(), 1);
        }
        // 3. stage_commit: the drive stops before `Commit` once; a retry is a new
        // drive with no facts of its own, so it reconciles.
        {
            let mut w = World::with(Setup {
                hook: ScriptedStageHook::new([(EnsureStage::Commit, Code::ServiceUnavailable)], []),
                limits: bounded_limits(),
                ..Setup::default()
            })
            .await;
            let req = ensure_req("u0b-rc-3", "u0b-rc-3-w", &[("h1", "deploy")]);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            let op = e.operation_id.clone().unwrap();
            assert!(matches!(
                last_effect(&w, &op),
                Some(EffectReceipt::Confirmed { .. })
            ));
            w.fake.arm(FakeStep::HangReconcile);
            let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
            assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
            assert_eq!(e.effect_status, EffectStatus::Partial);
            assert_eq!(w.op(&op).state, OperationState::Running);
            assert_eq!(w.ops.available_adapter_slots(), free);
            assert_eq!(w.fake.hangs_dropped(), 1);
            // The same holds for the restart path.
            w.fake.arm(FakeStep::HangReconcile);
            w.restart().await;
            assert_eq!(w.op(&op).state, OperationState::Running);
            assert_eq!(w.fake.hangs_dropped(), 2);
            let done = ok(w.ops.ensure(&unattended(501), req).await);
            assert_eq!(done.code, Code::AccessReady);
            assert_eq!(w.effects(), 1);
        }
        // 4. continued_preparation: a shared grant whose creator was cancelled after
        // approval (ADR-0006 §13.8 item 5).
        {
            let stop = Arc::new(StopBeforeProbe::default());
            let w = World::with(Setup {
                hook: stop.clone(),
                limits: bounded_limits(),
                ..Setup::default()
            })
            .await;
            let mut ops = Vec::new();
            let mut decision = None;
            for i in 1..=3 {
                w.clock.advance(Duration::from_secs(1));
                let e = err(w.ops.ensure(&unattended(501), shared_req(i)).await);
                let d = decision_ref(&e);
                assert_eq!(decision.get_or_insert(d.clone()), &d, "one shared decision");
                ops.push(e.operation_id.clone().unwrap());
            }
            stop.armed.store(true, Ordering::SeqCst);
            ok(decide(&w, &attended(501), &decision.unwrap(), Verdict::Approve).await);
            until("the creator's confirmed effect", || w.effects() == 1).await;
            let c = ok(w
                .ops
                .cancel(
                    &unattended(501),
                    CancelRequest {
                        operation_id: ops[0].clone(),
                    },
                )
                .await);
            assert_eq!(c.data["may_have_external_effect"], true);
            stop.armed.store(false, Ordering::SeqCst);
            // The second waiter completes the shared preparation and attaches.
            let b = shared_settled(&w, 2)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"));
            let gid = b.data.grant_id.clone();
            assert_eq!(w.grant(&gid).state, GrantState::Active);
            // The third reconciles the creator's token: hung, so no facts yet.
            w.fake.arm(FakeStep::HangReconcile);
            let e = err(w.ops.ensure(&unattended(501), shared_req(3)).await);
            assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
            assert_eq!(w.op(&ops[2]).state, OperationState::Running);
            assert_eq!(w.fake.hangs_dropped(), 1);
            assert_eq!(w.ops.available_adapter_slots(), free);
            let c3 = shared_settled(&w, 3)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(c3.data.grant_id, gid);
            assert_eq!(w.effects(), 1, "one effect");
        }
    }

    /// ADR-0007 §12.15 item 7 (E-U6-6) on the `continued_preparation` path, required
    /// by §12.22 item 10 (W3b-gaps). A shared grant's creator is cancelled after
    /// approval and its preparation continues for the requests attached to it
    /// (ADR-0006 §13.8 item 5). After a restart, a fresh instance of an adapter with
    /// no external effect has forgotten the integration it returned, so its
    /// `reconcile` of the creator's token says `not_applied`: the attached request is
    /// answered from the `PreparedFacts` recorded with the creator's confirmation, and
    /// commits with that history and no new effect. An adapter with external effects
    /// keeps the M01 answer: no facts, so the request stays running
    /// (`SERVICE_UNAVAILABLE`) and nothing is prepared again.
    #[tokio::test]
    async fn u0b_continued_preparation_after_restart_answers_from_prepared_facts() {
        for external in [false, true] {
            let stop = Arc::new(StopBeforeProbe::default());
            let mut fixture = descriptor();
            fixture.external_side_effects = external;
            let mut w = World::with(Setup {
                hook: stop.clone(),
                limits: bounded_limits(),
                ..Setup::default()
            })
            .await;
            let first =
                FakeCredentialAdapter::new(fixture.clone(), vec![FakeStep::Prepare(outcome())]);
            w.ops = Operations::start(OperationsConfig {
                adapters: vec![first.clone() as Arc<dyn CredentialAdapter>],
                ..w.config()
            })
            .await
            .unwrap();
            let mut ops = Vec::new();
            let mut decision = None;
            for i in 1..=3 {
                w.clock.advance(Duration::from_secs(1));
                let e = err(w.ops.ensure(&unattended(501), shared_req(i)).await);
                let d = decision_ref(&e);
                assert_eq!(decision.get_or_insert(d.clone()), &d, "one shared decision");
                ops.push(e.operation_id.clone().unwrap());
            }
            stop.armed.store(true, Ordering::SeqCst);
            ok(decide(&w, &attended(501), &decision.unwrap(), Verdict::Approve).await);
            until("the creator's confirmed effect", || {
                first.effect_count() == 1
            })
            .await;
            let c = ok(w
                .ops
                .cancel(
                    &unattended(501),
                    CancelRequest {
                        operation_id: ops[0].clone(),
                    },
                )
                .await);
            assert_eq!(c.data["may_have_external_effect"], true);
            stop.armed.store(false, Ordering::SeqCst);
            // The second waiter completes the creator's continued preparation.
            let b = shared_settled(&w, 2)
                .await
                .unwrap_or_else(|e| panic!("external {external}: {e:?}"));
            let gid = b.data.grant_id.clone();
            assert_eq!(w.grant(&gid).state, GrantState::Active);
            let stored = w
                .store
                .transaction(|tx| tx.grant_prepared_facts(&gid))
                .unwrap()
                .expect("facts recorded with the creator's confirmation");
            assert_eq!(w.op(&ops[0]).state, OperationState::Cancelled);
            assert_eq!(w.op(&ops[2]).state, OperationState::Running);
            // Restart: a fresh adapter instance (same identity) with an empty memory.
            let fresh = FakeCredentialAdapter::new(fixture, vec![FakeStep::Prepare(outcome())]);
            w.ops = Operations::start(OperationsConfig {
                adapters: vec![fresh.clone() as Arc<dyn CredentialAdapter>],
                ..w.config()
            })
            .await
            .unwrap();
            if external {
                let e = err(w.ops.ensure(&unattended(501), shared_req(3)).await);
                assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
                assert_eq!(w.op(&ops[2]).state, OperationState::Running, "fails closed");
                assert_eq!(fresh.effect_count(), 0, "never prepared again");
                assert_eq!(first.effect_count(), 1);
                continue;
            }
            let c3 = shared_settled(&w, 3)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(c3.code, Code::AccessReady);
            assert_eq!(c3.operation_id.as_ref(), Some(&ops[2]));
            assert_eq!(c3.data.grant_id, gid, "attached to the creator's grant");
            assert_eq!(fresh.effect_count(), 0, "no new effect");
            assert_eq!(first.effect_count(), 1, "one effect in all");
            // The history is the recorded one; nothing is claimed past the commit.
            assert_eq!(c3.data.provider, stored.provider);
            assert_eq!(c3.data.consumer.environment, stored.environment);
            assert!(c3.data.usable_until <= w.clock.wall());
            assert_eq!(
                c3.data.refresh_dependency,
                RefreshDependency::ProviderInteraction
            );
            assert_eq!(w.op(&ops[2]).state, OperationState::Succeeded);
            w.events();
        }
    }

    /// `u0b_revoke_timeout_counts_as_unconfirmed_in_rounds_and_bounded_cleanup`.
    /// `HangRevoke` in a round keeps the obligation and the claimed round counts;
    /// in a bounded cleanup call the answer is tracked as an obligation; in an
    /// uncovered grant's immediate call the intent is removed (QR17: counted as
    /// made). A supervisor pass is never blocked beyond the bound per call.
    #[tokio::test]
    async fn u0b_revoke_timeout_counts_as_unconfirmed_in_rounds_and_bounded_cleanup() {
        // Rounds: the explicit revoke's first round, then a supervisor round.
        let w = bounded_world(vec![FakeStep::Prepare(outcome())], Arc::new(NoFaults)).await;
        let ready = ok(w
            .ops
            .ensure(
                &unattended(501),
                ensure_req("u0b-rv", "u0b-rv-w", &[("h1", "deploy")]),
            )
            .await)
        .data;
        w.fake.arm(FakeStep::HangRevoke);
        let started = std::time::Instant::now();
        let r = w
            .ops
            .revoke(
                &unattended(501),
                RevokeRequest {
                    grant_id: ready.grant_id.clone(),
                    request_id: RequestId::parse("u0b-rv-revoke").unwrap(),
                },
            )
            .await;
        assert!(started.elapsed() >= BOUND);
        rendered(&r);
        let rec = r1312_record(&w, &ready.grant_id).expect("the timed-out call is unconfirmed");
        assert_eq!(rec.attempts, 1, "the claimed round counts");
        assert_eq!(rec.obligations.len(), 1);
        assert_eq!(w.grant(&ready.grant_id).state, GrantState::Revoking);
        // A supervisor round whose call times out: the obligation stays, the round
        // counts, and the pass ends after the call's bound (the hang never ends by
        // itself; the upper limit only leaves room for a loaded host).
        w.fake.arm(FakeStep::HangRevoke);
        let sup = r1312_supervisor(&w, 8);
        sup.revocation_pass().await.unwrap();
        w.clock.advance_continuous_only(Duration::from_secs(60));
        let started = std::time::Instant::now();
        sup.revocation_pass().await.unwrap();
        let took = started.elapsed();
        assert!(
            took >= BOUND && took < BOUND * 25,
            "one bound per call: {took:?}"
        );
        let rec = r1312_record(&w, &ready.grant_id).expect("still pending");
        assert_eq!(rec.attempts, 2);
        assert_eq!(rec.obligations.len(), 1, "the obligation stays");
        assert_eq!(w.fake.hangs_dropped(), 2);
        // The next round confirms and clears it.
        w.clock.advance_continuous_only(Duration::from_secs(60));
        sup.revocation_pass().await.unwrap();
        assert!(
            r1312_record(&w, &ready.grant_id).is_none(),
            "confirmed by a later round"
        );
        assert_eq!(w.grant(&ready.grant_id).state, GrantState::Revoked);

        // A bounded cleanup call (ADR-0006 §13.18 item 4): a covering record already
        // re-armed for this effect, with no obligation for the applying adapter.
        let w = bounded_world(vec![FakeStep::Prepare(outcome())], Arc::new(NoFaults)).await;
        let g = heimdall_contract::ids::GrantId::from_random_bytes([0x5a; 16]);
        let op = OperationId::from_random_bytes([0x5b; 16]);
        let applying = descriptor().identity;
        let record: heimdall_domain::revocation::PendingRemoteRevocation =
            serde_json::from_value(serde_json::json!({
                "root": g,
                "grants": [g],
                "attempts": 1,
                "last_attempt_at": t0(),
                "stopped": true,
                "rearmed_effects": [{
                    "grant": g,
                    "adapter": applying,
                    "effect_token": "eff_u0b_bounded",
                    "confirmed": true,
                }],
            }))
            .unwrap();
        let tombstone: heimdall_domain::revocation::Tombstone =
            serde_json::from_value(serde_json::json!({
                "grant": g,
                "cascade": [],
                "generation": 0,
                "revoked_at": t0(),
                "remote_pending": [],
            }))
            .unwrap();
        w.store
            .transaction(|tx| {
                tx.insert_tombstone(&tombstone)?;
                tx.set_remote_revocation(&record)?;
                tx.record_cleanup_intent(&heimdall_domain::revocation::CleanupIntent {
                    grant: g.clone(),
                    operation: op.clone(),
                    adapter: Some(applying.clone()),
                    effect_token: "eff_u0b_bounded".into(),
                    confirmed: true,
                    in_flight: false,
                    version: 0,
                    recorded_at: t0(),
                })
            })
            .unwrap();
        w.fake.arm(FakeStep::HangRevoke);
        let started = std::time::Instant::now();
        w.ops.process_cleanup_intents().await.unwrap();
        assert!(started.elapsed() >= BOUND);
        let rec = r1312_record(&w, &g).unwrap();
        let tracked = rec
            .obligations
            .iter()
            .find(|o| o.adapter == applying)
            .expect("the timed-out bounded call is tracked as an obligation");
        assert!(!tracked.stopped);
        assert!(!rec.stopped);
        assert!(
            w.store
                .transaction(|tx| tx.cleanup_intent(&g, &op))
                .unwrap()
                .is_none(),
            "an obligation owns it now"
        );
        assert_eq!(w.fake.hangs_dropped(), 1);

        // An uncovered grant's immediate call times out: counted as made (QR17).
        let w = bounded_world(vec![FakeStep::ApplyThenHang(outcome())], Arc::new(NoFaults)).await;
        let op = hung_ensure(&w, "u0b-rv-imm").await;
        // Both immediate calls hang: the cancellation's (the attempt in flight),
        // and the one after the preparation's own bound.
        w.fake.arm(FakeStep::HangRevoke);
        w.fake.arm(FakeStep::HangRevoke);
        ok(w.ops
            .cancel(
                &unattended(501),
                CancelRequest {
                    operation_id: op.clone(),
                },
            )
            .await);
        until("the marker's release", || {
            w.ops.preparing_operations().is_empty()
        })
        .await;
        until("the intent's removal", || intent_of(&w, &op).is_none()).await;
        assert_eq!(w.fake.hangs_dropped(), 3, "the preparation and both calls");
        assert!(
            w.fake.revocations.lock().unwrap().is_empty(),
            "no call answered"
        );
        w.fake.release_hangs();
        tokio::task::yield_now().await;
        assert_eq!(w.fake.work_after_drop(), 0);
    }

    /// `u0b_adapter_bound_covers_only_the_adapter_call`. One adapter slot. Two
    /// preparations hang in turn, each until its bound; the last one to get the slot
    /// waited for it for longer than one bound and is not timed out: it prepares and
    /// succeeds. The third caller's own wait ends first with the bounded-wait answer
    /// (`ACCEPTED`) while the work continues. Which of the second and third requests
    /// gets the slot first is the scheduler's choice; the assertions hold for both.
    #[tokio::test]
    async fn u0b_adapter_bound_covers_only_the_adapter_call() {
        let w = World::with(Setup {
            script: vec![
                FakeStep::ApplyThenHang(outcome()),
                FakeStep::ApplyThenHang(outcome()),
                FakeStep::Prepare(outcome()),
            ],
            limits: Limits {
                max_concurrent_adapter_calls: 1,
                ..bounded_limits()
            },
            ..Setup::default()
        })
        .await;
        let a = err(w
            .ops
            .ensure(&unattended(501), async_req("u0b-sl-a", "u0b-sl-a-w"))
            .await)
        .operation_id
        .unwrap();
        until("the first hang", || w.fake.hangs_entered() == 1).await;
        let b = err(w
            .ops
            .ensure(&unattended(501), async_req("u0b-sl-b", "u0b-sl-b-w"))
            .await)
        .operation_id
        .unwrap();
        let started = std::time::Instant::now();
        let mut req = ensure_req("u0b-sl-c", "u0b-sl-c-w", &[("h1", "deploy")]);
        req.wait = WaitMode::Sync { timeout_ms: 50 };
        let waited = err(w.ops.ensure(&unattended(501), req.clone()).await);
        assert_eq!(waited.code, Code::Accepted, "the caller's wait ended first");
        let c = waited.operation_id.clone().unwrap();
        assert!(!w.op(&c).state.is_settled(), "the work continues");
        until("the last preparation", || {
            [&b, &c]
                .into_iter()
                .any(|o| w.op(o).state == OperationState::Succeeded)
        })
        .await;
        assert!(
            started.elapsed() >= BOUND,
            "it waited for the slot past one bound: {:?}",
            started.elapsed()
        );
        let (last, hung) = if w.op(&c).state == OperationState::Succeeded {
            (&c, &b)
        } else {
            (&b, &c)
        };
        assert!(
            !r1314_effects(&w, last)
                .iter()
                .any(|e| matches!(e, EffectReceipt::Uncertain { .. })),
            "the slot wait was never timed out"
        );
        until("the second hang's bound", || {
            w.op(hung).state == OperationState::OutcomeUnknown
        })
        .await;
        assert_eq!(w.op(&a).state, OperationState::OutcomeUnknown);
        assert_eq!(w.fake.hangs_dropped(), 2);
        let done = ok(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(done.code, Code::AccessReady);
    }

    /// `u0b_dropped_adapter_future_does_no_later_work`. After each timeout, the
    /// fake's after-drop counter stays 0 once its hangs are released: an effect
    /// applied before a hang is the only one, a hang before the effect applies none,
    /// and the cleanup call follows the effect.
    #[tokio::test]
    async fn u0b_dropped_adapter_future_does_no_later_work() {
        // A hang before any effect: the attempt is uncertain, and reconcile later
        // establishes that nothing applied.
        let w = bounded_world(
            vec![FakeStep::HangBeforeEffect(outcome())],
            Arc::new(NoFaults),
        )
        .await;
        let req = ensure_req("u0b-dd-1", "u0b-dd-1-w", &[("h1", "deploy")]);
        let e = err(w.ops.ensure(&unattended(501), req.clone()).await);
        assert_eq!(e.code, Code::OutcomeUnknown);
        w.fake.release_hangs();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            w.fake.work_after_drop(),
            0,
            "the dropped future did nothing more"
        );
        assert_eq!(w.effects(), 0, "no effect after the drop");
        let e = err(w.ops.ensure(&unattended(501), req).await);
        assert_eq!(e.effect_status, EffectStatus::None, "{}", e.message);
        // An effect before the hang, then a cancellation: one effect, and every
        // cleanup call follows it.
        let w = bounded_world(vec![FakeStep::ApplyThenHang(outcome())], Arc::new(NoFaults)).await;
        let op = hung_ensure(&w, "u0b-dd-2").await;
        ok(w.ops
            .cancel(
                &unattended(501),
                CancelRequest {
                    operation_id: op.clone(),
                },
            )
            .await);
        until("the intent's removal", || intent_of(&w, &op).is_none()).await;
        w.fake.release_hangs();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(w.fake.work_after_drop(), 0);
        let journal = w.fake.journal();
        assert!(
            matches!(journal.first(), Some(FakeEvent::Effect(_))),
            "{journal:?}"
        );
        assert_eq!(
            journal
                .iter()
                .filter(|e| matches!(e, FakeEvent::Effect(_)))
                .count(),
            1,
            "the only effect: {journal:?}"
        );
        assert!(
            journal
                .iter()
                .skip(1)
                .all(|e| matches!(e, FakeEvent::Revoke(_)))
        );
        assert!(journal.len() >= 2, "a cleanup call follows the effect");
    }

    /// The helper itself: the inner future is dropped at the bound and the answer
    /// is `OutcomeUnknown` with fixed text; a timely answer passes through.
    #[tokio::test]
    async fn u0b_bounded_adapter_call_drops_the_call_at_the_bound() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let started = std::time::Instant::now();
        let answer: Result<(), AdapterError> = bounded_adapter_call(BOUND, async move {
            let _guard = guard;
            std::future::pending::<()>().await;
            Ok(())
        })
        .await;
        assert!(started.elapsed() >= BOUND);
        assert_eq!(
            answer,
            Err(AdapterError::OutcomeUnknown(ADAPTER_CALL_TIMED_OUT.into()))
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the call's future was dropped"
        );
        let fast: Result<ReconcileOutcome, AdapterError> =
            bounded_adapter_call(BOUND, async { Ok(ReconcileOutcome::NotApplied) }).await;
        assert_eq!(fast, Ok(ReconcileOutcome::NotApplied));
        assert_eq!(
            Limits::default().adapter_call_timeout,
            heimdall_app::ports::DEFAULT_ADAPTER_CALL_TIMEOUT
        );
        assert_eq!(
            Limits::default().adapter_call_timeout,
            Duration::from_secs(30)
        );
    }

    /// `u0b_every_adapter_call_is_bounded`: a source check over
    /// `crates/app/src/operations.rs` outside `#[cfg(test)]`. Every `.prepare(`,
    /// `.renew(`, `.reconcile(` and `.revoke(` call on an adapter is the argument of
    /// a `bounded_adapter_call`, and there is at least one of each of the three the
    /// runtime makes.
    #[test]
    fn u0b_every_adapter_call_is_bounded() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../app/src/operations.rs");
        let source = std::fs::read_to_string(path).unwrap();
        let production = source
            .split("\n#[cfg(test)]")
            .next()
            .expect("production part");
        let lines: Vec<&str> = production.lines().collect();
        let mut found: BTreeMap<&str, usize> = BTreeMap::new();
        for (n, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for call in [".prepare(", ".renew(", ".reconcile(", ".revoke("] {
                if !code.contains(call) {
                    continue;
                }
                // The call and the bound are on one line, or the bound opens at
                // most two lines before (a call spread over several lines, with
                // the limit as the first argument).
                let window = lines[n.saturating_sub(2)..=n].join("\n");
                assert!(
                    window.contains("bounded_adapter_call("),
                    "line {}: `{}` is not inside bounded_adapter_call",
                    n + 1,
                    line.trim()
                );
                *found.entry(call).or_default() += 1;
            }
        }
        for call in [".prepare(", ".reconcile(", ".revoke("] {
            assert!(
                found.get(call).copied().unwrap_or(0) > 0,
                "{call} found: {found:?}"
            );
        }
        assert_eq!(found.get(".reconcile(").copied(), Some(4), "{found:?}");
        assert_eq!(found.get(".revoke(").copied(), Some(3), "{found:?}");
        assert_eq!(found.get(".prepare(").copied(), Some(1), "{found:?}");
    }
}

// =================================================================================
// ⟨M02⟩ U0b phase 2: the activation change set (m02-plan U0b rows 1, 10, 18, 19, 23;
// ADR-0007 §12.14 item 3 E1). The setup and catalog drivers are U5's; these tests
// drive them through a counting `ProjectionWriter` fake and check what U0b decides:
// the decision arms, the drive arms, the capability, the writer-less refusal, the
// admission's single store call and the cancel rule.
// =================================================================================

mod u0b_phase2 {
    use super::m02_integration::{
        apply_intent, endpoint, idem_of, identity_id, local_receipt, queued, setup_intent,
    };
    use super::*;
    use heimdall_app::ports::{
        HeldStep, PreviewError, ProjectionReceipt, ProjectionReconcile, ProjectionWriter,
        ReconcileError, StageSink,
    };
    use heimdall_contract::catalog::DeclaredInteraction;
    use heimdall_contract::doctor::AliasObservation;
    use heimdall_contract::ids::IdentityId;
    use heimdall_contract::ipc::{PeerInfo, PrincipalInfo, capability};
    use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
    use heimdall_contract::setup::{
        ConflictKind, PlanDigest, PreviewIntent, RepairResolution, SetupPlan, SetupRequest,
    };
    use heimdall_domain::catalog::{CatalogAction, CatalogIntent, DeclarationState};
    use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
    use heimdall_domain::operation::{
        EffectReceipt, FilePhase, LocalIntent, LocalReceipt, OperationKind, RecoveryIntent,
        StageReceipt,
    };
    use heimdall_domain::projection::{
        ConsentRecord, ProjectionPlan, ProjectionRecord, ProjectionSpec, ProjectionSummary,
        SetupIntent, SummaryIntent,
    };
    use heimdall_ipc::session::{
        ConnectionLimits, ControlClient, ControlConnection, server_capabilities,
    };
    use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
    use tokio_util::sync::CancellationToken;

    /// A projection writer that counts every call. `preview` returns a plan whose
    /// digest is `digest` (the committed `setup-plan.apply.json` example, with that
    /// digest and the requested intent), needing a decision when `decision` is set;
    /// without a digest it refuses. `apply` records the intent it was given and
    /// `reconcile` the intent it reconciles; both then stop with `Unavailable`, which
    /// writes nothing, so the driver leaves no file and no receipt behind.
    #[derive(Default)]
    pub(super) struct CountingWriter {
        pub(super) digest: std::sync::Mutex<Option<PlanDigest>>,
        pub(super) decision: AtomicBool,
        pub(super) previews: AtomicUsize,
        pub(super) applies: std::sync::Mutex<Vec<SetupIntent>>,
        pub(super) reconciles: std::sync::Mutex<Vec<SetupIntent>>,
    }

    impl CountingWriter {
        pub(super) fn new(digest: Option<PlanDigest>, decision: bool) -> Arc<Self> {
            let w = Self::default();
            *w.digest.lock().unwrap() = digest;
            w.decision.store(decision, Ordering::SeqCst);
            Arc::new(w)
        }
        fn applies(&self) -> usize {
            self.applies.lock().unwrap().len()
        }
        fn reconciles(&self) -> usize {
            self.reconciles.lock().unwrap().len()
        }
    }

    impl ProjectionWriter for CountingWriter {
        fn preview(
            &self,
            _spec: &ProjectionSpec,
            intent: &PreviewIntent,
        ) -> Result<ProjectionPlan, PreviewError> {
            self.previews.fetch_add(1, Ordering::SeqCst);
            let Some(digest) = self.digest.lock().unwrap().clone() else {
                return Err(PreviewError::Unavailable("counting writer".into()));
            };
            let mut view: SetupPlan =
                serde_json::from_str(include_str!("../../schemas/examples/setup-plan.apply.json"))
                    .unwrap();
            view.plan_digest = digest;
            view.intent = intent.clone();
            view.consent.decision_required = self.decision.load(Ordering::SeqCst);
            view.consent.reasons.clear();
            let base = setup_intent(1, intent.clone());
            Ok(ProjectionPlan {
                view,
                generation: base.generation,
                consent: ConsentRecord::default(),
                files: base.files,
                summary: Some(summary()),
            })
        }

        fn apply(
            &self,
            intent: &SetupIntent,
            _sink: &mut dyn StageSink,
        ) -> Result<ProjectionReceipt, ReconcileError> {
            self.applies.lock().unwrap().push(intent.clone());
            Err(ReconcileError::Unavailable("counting writer".into()))
        }

        fn reconcile(
            &self,
            intent: &SetupIntent,
            _receipts: &[StageReceipt],
            _sink: &mut dyn StageSink,
        ) -> Result<ProjectionReconcile, ReconcileError> {
            self.reconciles.lock().unwrap().push(intent.clone());
            Err(ReconcileError::Unavailable("counting writer".into()))
        }

        fn observe(
            &self,
            _record: &ProjectionRecord,
            _aliases: &[String],
        ) -> Vec<AliasObservation> {
            Vec::new()
        }

        fn observe_held(
            &self,
            _intent: &SetupIntent,
            _receipts: &[StageReceipt],
        ) -> Result<Vec<HeldStep>, ReconcileError> {
            Ok(Vec::new())
        }
    }

    fn summary() -> ProjectionSummary {
        ProjectionSummary {
            intent: SummaryIntent::Apply,
            added_aliases: vec!["h1".into()],
            changed_aliases: Vec::new(),
            removed_aliases: Vec::new(),
            files: vec!["/scratch/u0b/ssh/config".into()],
            git: false,
            restore: Vec::new(),
            diff_text: "+Include heimdall.conf\n".into(),
        }
    }

    /// Restart `w` with `writer` as its projection writer (the M01 fake stays).
    pub(super) async fn with_writer(w: &mut World, writer: &Arc<CountingWriter>) {
        w.ops = Operations::start(OperationsConfig {
            projection: Some(writer.clone() as Arc<dyn ProjectionWriter>),
            ..w.config()
        })
        .await
        .unwrap();
    }

    /// An operation of `kind` in `state` with `local`, inserted through the store
    /// (as admission leaves it, with no receipt).
    fn seed_local(
        w: &World,
        n: u8,
        kind: OperationKind,
        state: OperationState,
        local: LocalIntent,
    ) -> OperationId {
        let id = OperationId::from_random_bytes([n; 16]);
        let rid = RequestId::parse(&format!("u0b-p2-{n}")).unwrap();
        let mut op = queued(&id, kind, &rid, n);
        op.state = state;
        w.store
            .transaction(|tx| {
                tx.insert_operation(&op, &idem_of(&op))?;
                tx.set_recovery_intent(
                    &id,
                    &RecoveryIntent {
                        request: serde_json::json!({ "op": kind.as_str() }),
                        resolved: None,
                        local: Some(local),
                    },
                )
            })
            .unwrap();
        id
    }

    fn insert_decision(w: &World, n: u8, kind: DecisionKind) -> DecisionId {
        let id = DecisionId::from_random_bytes([n; 16]);
        w.store
            .transaction(|tx| {
                let generation = tx.authority_generation()?;
                tx.insert_decision(&DecisionRecord {
                    id: id.clone(),
                    kind,
                    generation,
                    created_at: t0(),
                    expires_at: shift(t0(), 3600),
                    state: DecisionState::Pending,
                    decided_at: None,
                })
            })
            .unwrap();
        id
    }

    fn apply_projection(op: &OperationId, digest: &PlanDigest) -> DecisionKind {
        DecisionKind::ApplyProjection {
            operation: op.clone(),
            plan_digest: digest.clone(),
            summary: summary(),
        }
    }

    fn declare_interaction(op: &OperationId, identity: &IdentityId) -> DecisionKind {
        DecisionKind::DeclareInteraction {
            operation: op.clone(),
            identity: identity.clone(),
            fingerprint: super::m02_integration::identity("/scratch/u0b/agent.sock", 1).fingerprint,
            endpoint: endpoint("/scratch/u0b/agent.sock"),
            interaction: DeclaredInteraction::None,
            valid_until: shift(t0(), 30 * 86_400),
        }
    }

    fn declare_intent(identity: &IdentityId) -> LocalIntent {
        LocalIntent::Catalog(CatalogIntent {
            action: CatalogAction::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
            },
            approval: None,
        })
    }

    fn intent_of(w: &World, op: &OperationId) -> RecoveryIntent {
        w.store
            .transaction(|tx| tx.recovery_intent(op))
            .unwrap()
            .unwrap()
    }

    fn record(w: &World, d: &DecisionId) -> DecisionRecord {
        w.store.transaction(|tx| tx.decision(d)).unwrap().unwrap()
    }

    /// A waiting setup operation with its pending `ApplyProjection` record.
    fn waiting_setup(w: &World, n: u8) -> (OperationId, DecisionId, SetupIntent) {
        let intent = setup_intent(u64::from(n), apply_intent());
        let op = seed_local(
            w,
            n,
            OperationKind::SetupApply,
            OperationState::AwaitingApproval,
            LocalIntent::Setup(intent.clone()),
        );
        let d = insert_decision(w, n + 1, apply_projection(&op, &intent.plan_digest));
        (op, d, intent)
    }

    /// `u0b_apply_projection_decision_resumes_exact_waiting_operation`, with deny,
    /// stale-generation, unattended-decide and `plan_digest`-mismatch variants
    /// (m02-plan U0b row 1, phase 2). Approval writes `ProjectionApproval {
    /// decision, plan_digest }` into exactly the waiting operation's `SetupIntent`,
    /// moves it out of `awaiting_approval` and resumes it: the driver runs `apply`
    /// once, with that approval (and nothing for another waiting operation). Deny
    /// fails the operation, `CAPABILITY_UNAVAILABLE`, with no writer call. Each
    /// refusal is `DECISION_STALE` or `INTERACTION_REQUIRED` with nothing applied.
    #[tokio::test]
    async fn u0b_apply_projection_decision_resumes_exact_waiting_operation() {
        let mut w = World::new().await;
        let (op, d, intent) = waiting_setup(&w, 0x31);
        let (other, other_d, _) = waiting_setup(&w, 0x41);
        let writer = CountingWriter::new(Some(intent.plan_digest.clone()), true);
        with_writer(&mut w, &writer).await;
        // Unattended: refused, nothing consumed.
        let e = err(decide(&w, &unattended(501), &d, Verdict::Approve).await);
        assert_eq!(e.code, Code::InteractionRequired);
        assert_eq!(record(&w, &d).state, DecisionState::Pending);
        // Approve.
        let done = ok(decide(&w, &attended(501), &d, Verdict::Approve).await);
        assert_eq!(done.data["state"], "approved");
        assert_eq!(done.operation_id.as_ref(), Some(&op));
        let Some(LocalIntent::Setup(stored)) = intent_of(&w, &op).local else {
            panic!("setup intent");
        };
        let approval = stored.approval.clone().expect("the projection approval");
        assert_eq!(approval.decision, d);
        assert_eq!(approval.plan_digest, intent.plan_digest);
        assert_eq!(stored.without_approval(), intent, "nothing else changed");
        until_settled(&w, &op).await;
        assert_eq!(writer.applies(), 1, "resumed and applied once");
        assert_eq!(
            writer.applies.lock().unwrap()[0].approval.as_ref(),
            Some(&approval),
            "the exact decided plan"
        );
        assert_eq!(writer.reconciles(), 0);
        // The other waiting operation is untouched.
        assert_eq!(w.op(&other).state, OperationState::AwaitingApproval);
        assert_eq!(record(&w, &other_d).state, DecisionState::Pending);
        let Some(LocalIntent::Setup(untouched)) = intent_of(&w, &other).local else {
            panic!("setup intent");
        };
        assert_eq!(untouched.approval, None);
        // Deny: failed, CAPABILITY_UNAVAILABLE, no writer call.
        let applies = writer.applies();
        let previews = writer.previews.load(Ordering::SeqCst);
        ok(decide(&w, &attended(501), &other_d, Verdict::Deny).await);
        let denied = w.op(&other);
        assert_eq!(denied.state, OperationState::Failed);
        assert_eq!(denied.code, Some(Code::CapabilityUnavailable));
        assert_eq!(denied.effect_status, EffectStatus::None);
        assert_eq!(record(&w, &other_d).state, DecisionState::Denied);
        assert_eq!(writer.applies(), applies);
        assert_eq!(writer.previews.load(Ordering::SeqCst), previews);
        // Stale generation: the authority generation moved after issuance.
        let (stale_op, stale_d, _) = waiting_setup(&w, 0x51);
        r138_set_automatic_activation(&w, true);
        let e = err(decide(&w, &attended(501), &stale_d, Verdict::Approve).await);
        assert_eq!(e.code, Code::DecisionStale);
        assert_eq!(w.op(&stale_op).state, OperationState::AwaitingApproval);
        assert!(
            matches!(intent_of(&w, &stale_op).local, Some(LocalIntent::Setup(i)) if i.approval.is_none())
        );
        // A plan-digest mismatch: DECISION_STALE, nothing applied or consumed.
        let (mis_op, _, _) = waiting_setup(&w, 0x61);
        let mismatch = insert_decision(
            &w,
            0x63,
            apply_projection(&mis_op, &PlanDigest::from_sha256([0xee; 32])),
        );
        for verdict in [Verdict::Approve, Verdict::Deny] {
            let e = err(decide(&w, &attended(501), &mismatch, verdict).await);
            assert_eq!(e.code, Code::DecisionStale, "{verdict:?}");
            assert_eq!(record(&w, &mismatch).state, DecisionState::Pending);
            assert_eq!(w.op(&mis_op).state, OperationState::AwaitingApproval);
            assert!(
                matches!(intent_of(&w, &mis_op).local, Some(LocalIntent::Setup(i)) if i.approval.is_none())
            );
        }
        assert_eq!(writer.applies(), 1);
        w.events();
    }

    /// Wait (bounded) until `op` settles.
    async fn until_settled(w: &World, op: &OperationId) {
        super::u0b_adapter_bound::until("the operation's settlement", || {
            w.op(op).state.is_settled()
        })
        .await;
    }

    /// `u0b_declare_interaction_decision_requires_attended_decide` (QR1), extended.
    /// Only an attended `Decide` completes it. Approval copies the record's fields
    /// into the waiting catalog intent's `DeclarationApproval`, and the catalog
    /// driver stores a declaration equal to them. When the identity's endpoint
    /// changed after the decision was created, the driver answers
    /// `DECISION_STALE` and writes no declaration.
    #[tokio::test]
    async fn u0b_declare_interaction_decision_requires_attended_decide() {
        let w = World::new().await;
        super::m02_integration::seed_catalog(&w, false);
        let op = seed_local(
            &w,
            0x71,
            OperationKind::Catalog,
            OperationState::AwaitingApproval,
            declare_intent(&identity_id()),
        );
        let kind = declare_interaction(&op, &identity_id());
        let d = insert_decision(&w, 0x72, kind.clone());
        let e = err(decide(&w, &unattended(501), &d, Verdict::Approve).await);
        assert_eq!(e.code, Code::InteractionRequired);
        assert_eq!(record(&w, &d).state, DecisionState::Pending);
        ok(decide(&w, &attended(501), &d, Verdict::Approve).await);
        let Some(LocalIntent::Catalog(stored)) = intent_of(&w, &op).local else {
            panic!("catalog intent");
        };
        let approval = stored.approval.expect("the declaration approval");
        let DecisionKind::DeclareInteraction {
            identity,
            fingerprint,
            endpoint: at,
            interaction,
            valid_until,
            ..
        } = kind
        else {
            unreachable!()
        };
        assert_eq!(approval.decision, d);
        assert_eq!(
            (
                &approval.identity,
                &approval.fingerprint,
                &approval.endpoint,
                approval.interaction,
                approval.valid_until
            ),
            (&identity, &fingerprint, &at, interaction, valid_until),
            "copied from the record"
        );
        until_settled(&w, &op).await;
        let declared = w
            .store
            .transaction(|tx| tx.interaction_declaration(&identity))
            .unwrap()
            .expect("the declaration written from the approval");
        assert_eq!(declared.state, DeclarationState::Live);
        assert_eq!(declared.fingerprint, fingerprint);
        assert_eq!(declared.endpoint, at);
        assert_eq!(declared.expires_at, valid_until);
        assert_eq!(declared.decision, d);
        // The identity's endpoint changes after the decision was created.
        let w = World::new().await;
        super::m02_integration::seed_catalog(&w, false);
        let op = seed_local(
            &w,
            0x75,
            OperationKind::Catalog,
            OperationState::AwaitingApproval,
            declare_intent(&identity_id()),
        );
        let d = insert_decision(&w, 0x76, declare_interaction(&op, &identity_id()));
        w.store
            .transaction(|tx| {
                tx.upsert_identity(&super::m02_integration::identity(
                    "/scratch/u0b/moved.sock",
                    2,
                ))
            })
            .unwrap();
        ok(decide(&w, &attended(501), &d, Verdict::Approve).await);
        until_settled(&w, &op).await;
        let settled = w.op(&op);
        assert_eq!(settled.state, OperationState::Failed);
        assert_eq!(settled.code, Some(Code::DecisionStale));
        assert_eq!(
            w.store
                .transaction(|tx| tx.interaction_declaration(&identity_id()))
                .unwrap(),
            None,
            "nothing written"
        );
        w.events();
    }

    /// `u0b_decision_kind_must_match_its_waiting_intent`: an `ApplyProjection`
    /// record naming a catalog operation and a `DeclareInteraction` record naming a
    /// setup operation are both `DECISION_STALE`, approve and deny alike; the
    /// records stay pending and the operations untouched.
    #[tokio::test]
    async fn u0b_decision_kind_must_match_its_waiting_intent() {
        let w = World::new().await;
        let catalog_op = seed_local(
            &w,
            0x81,
            OperationKind::Catalog,
            OperationState::AwaitingApproval,
            declare_intent(&identity_id()),
        );
        let setup = setup_intent(0x82, apply_intent());
        let setup_op = seed_local(
            &w,
            0x82,
            OperationKind::SetupApply,
            OperationState::AwaitingApproval,
            LocalIntent::Setup(setup.clone()),
        );
        let wrong = [
            insert_decision(&w, 0x83, apply_projection(&catalog_op, &setup.plan_digest)),
            insert_decision(&w, 0x84, declare_interaction(&setup_op, &identity_id())),
        ];
        let before = (intent_of(&w, &catalog_op), intent_of(&w, &setup_op));
        for d in &wrong {
            for verdict in [Verdict::Approve, Verdict::Deny] {
                let e = err(decide(&w, &attended(501), d, verdict).await);
                assert_eq!(e.code, Code::DecisionStale, "{d} {verdict:?}");
                assert_eq!(record(&w, d).state, DecisionState::Pending);
            }
        }
        assert_eq!(w.op(&catalog_op).state, OperationState::AwaitingApproval);
        assert_eq!(w.op(&setup_op).state, OperationState::AwaitingApproval);
        assert_eq!(
            (intent_of(&w, &catalog_op), intent_of(&w, &setup_op)),
            before
        );
    }

    /// The idempotency key's `setup.attempt` receipt and a local receipt of a
    /// running setup operation whose writer has started.
    fn started(w: &World, op: &OperationId) {
        w.store
            .transaction(|tx| {
                tx.append_stage_receipt(
                    op,
                    &StageReceipt {
                        stage: heimdall_app::setup::STAGE_SETUP_ATTEMPT.into(),
                        recorded_at: t0(),
                        effect: EffectReceipt::Attempted {
                            adapter: AdapterIdentity {
                                mechanism: heimdall_app::setup::PROJECTION_MECHANISM.into(),
                                instance: env_id().to_string(),
                            },
                            effect_token: "eff_u0b_setup".into(),
                        },
                        local: None,
                    },
                )?;
                tx.append_stage_receipt(op, &local_receipt())
            })
            .unwrap();
    }

    /// `u0b_restart_dispatches_every_operation_kind`, full form (m02-plan U0b row
    /// 10, phase 2). Setup operations of each kind whose writer had started, and a
    /// catalog operation, are open when the runtime restarts with a projection
    /// writer: each setup operation is reconciled through
    /// `ProjectionWriter::reconcile` and `apply` is never called; the catalog
    /// operation is driven by the catalog driver to a result. Without a writer the
    /// setup operations stay unresolved and untouched (`driver_unavailable`). The
    /// M01 kinds are the phase-1 test's (`m02_integration`).
    #[tokio::test]
    async fn u0b_restart_dispatches_every_operation_kind() {
        let mut w = World::new().await;
        let kinds = [
            (OperationKind::SetupApply, apply_intent()),
            (
                OperationKind::SetupRollback,
                PreviewIntent::Rollback {
                    keep_key_files: false,
                    items: [heimdall_contract::setup::ProjectionItem::Ssh]
                        .into_iter()
                        .collect(),
                },
            ),
            (
                OperationKind::SetupRepair,
                PreviewIntent::Repair {
                    conflict: ConflictKind::MarkerDuplicated,
                    resolution: RepairResolution::RemoveDuplicateMarkers,
                    operation: None,
                },
            ),
        ];
        let mut setups = Vec::new();
        for (i, (kind, intent)) in kinds.into_iter().enumerate() {
            let n = 0x91 + u8::try_from(i).unwrap();
            let op = seed_local(
                &w,
                n,
                kind,
                OperationState::Running,
                LocalIntent::Setup(setup_intent(u64::from(n), intent)),
            );
            started(&w, &op);
            setups.push(op);
        }
        let catalog = seed_local(
            &w,
            0x9a,
            OperationKind::Catalog,
            OperationState::Queued,
            LocalIntent::Catalog(CatalogIntent {
                action: CatalogAction::RemoveIdentity {
                    id: IdentityId::from_random_bytes([0x9b; 16]),
                },
                approval: None,
            }),
        );
        // Without a writer: untouched.
        let before: Vec<_> = setups
            .iter()
            .map(|id| {
                (
                    w.op(id),
                    w.store.transaction(|tx| tx.stage_receipts(id)).unwrap(),
                )
            })
            .collect();
        w.restart().await;
        let after: Vec<_> = setups
            .iter()
            .map(|id| {
                (
                    w.op(id),
                    w.store.transaction(|tx| tx.stage_receipts(id)).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            after, before,
            "no writer: the setup operations are untouched"
        );
        for id in &setups {
            let reported = super::m02_integration::unresolved_events(&w, id);
            assert_eq!(reported.len(), 1, "{id}: reported once");
            assert_eq!(reported[0]["reason"], "driver_unavailable");
        }
        // With one: reconcile each, never apply.
        let writer = CountingWriter::new(None, false);
        with_writer(&mut w, &writer).await;
        assert_eq!(writer.applies(), 0, "never apply at restart");
        let reconciled: BTreeSet<PlanDigest> = writer
            .reconciles
            .lock()
            .unwrap()
            .iter()
            .map(|i| i.plan_digest.clone())
            .collect();
        assert_eq!(
            reconciled.len(),
            setups.len(),
            "each setup operation reconciled"
        );
        assert!(w.op(&catalog).state.is_settled(), "the catalog driver ran");
        w.events();
    }

    /// `u0b_setup_1_offered_after_activation` (row 19, phase 2; retires
    /// `w0_setup_1_is_not_offered`). `server_capabilities()` and `inspect
    /// capabilities` list `setup/1` and agree; a hello that requires it is accepted;
    /// a session that negotiated it dispatches a Setup request, and one that did not
    /// is still answered `SCHEMA_UNSUPPORTED` without dispatch.
    #[tokio::test]
    async fn u0b_setup_1_offered_after_activation() {
        assert!(server_capabilities().contains(capability::SETUP_V1));
        let w = World::new().await;
        let r = ok(w
            .ops
            .inspect(
                &unattended(501),
                InspectRequest {
                    subject: InspectSubject::Capabilities,
                    preview: None,
                },
            )
            .await);
        let listed: BTreeSet<String> = r.data["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert!(listed.contains(capability::SETUP_V1));
        assert_eq!(listed, server_capabilities(), "the two lists agree");
        let preview = Request::Setup(SetupRequest::Preview {
            intent: apply_intent(),
        });
        // A hello that requires `setup/1` is accepted (the production client).
        let (server, stream) = tokio::io::duplex(1 << 16);
        let calls = Arc::new(AtomicUsize::new(0));
        let served = serve(&w, server, calls.clone());
        let mut client = match ControlClient::handshake(
            stream,
            PeerInfo {
                name: "heimdall-u0b-test".into(),
                version: "0".into(),
            },
            [capability::SETUP_V1.to_owned()].into_iter().collect(),
            InteractionMode::NonInteractive,
        )
        .await
        {
            Ok(c) => c,
            Err(_) => panic!("a hello requiring setup/1 must be accepted"),
        };
        assert!(client.server().capabilities.contains(capability::SETUP_V1));
        let env = client.request(preview.clone()).await.unwrap();
        // Dispatched; this runtime has no projection writer.
        assert_eq!(env.code, Code::CapabilityUnavailable);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(client);
        let _ = served.await;
        // A hello that does not offer it: the gate answers, nothing is dispatched.
        for offered in [false, true] {
            let (server, stream) = tokio::io::duplex(1 << 16);
            let calls = Arc::new(AtomicUsize::new(0));
            let served = serve(&w, server, calls.clone());
            let mut caps = super::wave0_fail_closed::without_setup();
            if offered {
                caps.insert(capability::SETUP_V1.to_owned());
            }
            let mut raw = super::wave0_fail_closed::RawClient::handshake(stream, caps)
                .await
                .unwrap_or_else(|e| panic!("hello refused: {:?}", e.code));
            assert_eq!(raw.negotiated.contains(capability::SETUP_V1), offered);
            let env = raw.request(preview.clone()).await;
            let expected = if offered {
                Code::CapabilityUnavailable
            } else {
                Code::SchemaUnsupported
            };
            assert_eq!(env.code, expected, "offered {offered}");
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(offered));
            drop(raw);
            let _ = served.await;
        }
    }

    /// Serve one control connection over `server`, counting dispatched requests.
    fn serve(
        w: &World,
        server: tokio::io::DuplexStream,
        calls: Arc<AtomicUsize>,
    ) -> tokio::task::JoinHandle<()> {
        let relay = EventRelay::spawn(&w.ops, CancellationToken::new());
        let dispatcher = CountingDispatcher {
            inner: OperationsDispatcher::new(w.ops.clone(), relay, w.clock.clone()),
            calls,
        };
        tokio::spawn(async move {
            let _ = ControlConnection::new(server, ConnectionLimits::default())
                .with_server_identity(
                    env_id(),
                    PeerInfo {
                        name: "heimdall".into(),
                        version: "test".into(),
                    },
                )
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                )
                .await;
        })
    }

    #[derive(Clone)]
    struct CountingDispatcher {
        inner: OperationsDispatcher,
        calls: Arc<AtomicUsize>,
    }

    impl heimdall_ipc::session::Dispatcher for CountingDispatcher {
        fn dispatch<'life0, 'life1, 'async_trait>(
            &'life0 self,
            session: &'life1 heimdall_ipc::session::SessionInfo,
            request: Request,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = heimdall_contract::Envelope<serde_json::Value>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.dispatch(session, request)
        }

        fn subscribe<'life0, 'life1, 'async_trait>(
            &'life0 self,
            session: &'life1 heimdall_ipc::session::SessionInfo,
            filter: EventFilter,
            from: Option<heimdall_contract::event::Cursor>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            heimdall_ipc::session::SubscriptionStart,
                            Box<heimdall_contract::Envelope<heimdall_contract::ErrorData>>,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.subscribe(session, filter, from)
        }
    }

    /// Every Setup request of the committed examples.
    fn setup_requests() -> Vec<Request> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("request.setup."))
            .collect();
        names.sort();
        let requests: Vec<Request> = names
            .iter()
            .map(|n| serde_json::from_str(&std::fs::read_to_string(dir.join(n)).unwrap()).unwrap())
            .collect();
        let kinds: BTreeSet<&str> = requests.iter().map(Request::kind).collect();
        assert_eq!(
            kinds,
            [
                "setup.apply",
                "setup.preview",
                "setup.repair",
                "setup.rollback"
            ]
            .into_iter()
            .collect()
        );
        requests
    }

    /// `u0b_setup_without_projection_writer_is_capability_unavailable`, the permanent
    /// form of the dispatch-level wave-0 test (rows 17, 18). With no projection
    /// writer, every Setup request, through `OperationsDispatcher::handle_as` and
    /// `Operations::setup`, for every caller, is `CAPABILITY_UNAVAILABLE`, reason
    /// `driver_unavailable`, effect `none`, never the dispatcher's wildcard; nothing
    /// is admitted or written and no file is touched.
    #[tokio::test]
    async fn u0b_setup_without_projection_writer_is_capability_unavailable() {
        let w = World::new().await;
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("config"), b"Host lab\n").unwrap();
        let tree_before = std::fs::read(tree.path().join("config")).unwrap();
        let requests = setup_requests();
        let snapshot = |w: &World| {
            w.store
                .transaction(|tx| {
                    Ok(serde_json::json!({
                        "operations": tx.operation_counts()?,
                        "decisions": tx.pending_decisions()?.len(),
                        "intents": tx.raw_documents(heimdall_store::RawDocuments::RecoveryIntents)?,
                        "receipts": tx.raw_documents(heimdall_store::RawDocuments::StageReceipts)?,
                    }))
                })
                .unwrap()
        };
        let before = snapshot(&w);
        let relay = EventRelay::spawn(&w.ops, CancellationToken::new());
        let dispatcher = OperationsDispatcher::new(w.ops.clone(), relay, w.clock.clone());
        for caller in [unattended(501), attended(501), limited(501)] {
            // A caller without the owner role is refused for its role first (U5);
            // the owner gets the writer-less refusal.
            let owner = caller.context.is_owner();
            for request in &requests {
                let label = format!("{} ({:?})", request.kind(), caller.context.role);
                let env =
                    serde_json::to_value(dispatcher.handle_as(&caller, request.clone()).await)
                        .unwrap();
                assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{label}: {env}");
                if owner {
                    assert_eq!(
                        env["data"]["error"]["reason"], "driver_unavailable",
                        "{label}"
                    );
                }
                assert_eq!(env["data"]["error"]["effect_status"], "none", "{label}");
                assert!(env["operation_id"].is_null(), "{label}");
                let Request::Setup(r) = request.clone() else {
                    unreachable!()
                };
                let e = w.ops.setup(&caller, r).await.expect_err("refused");
                assert_eq!(e.code, Code::CapabilityUnavailable, "{label}");
                if owner {
                    assert_eq!(e.reason.as_deref(), Some("driver_unavailable"), "{label}");
                }
                assert_eq!(e.operation_id, None, "{label}");
            }
        }
        assert_eq!(snapshot(&w), before, "nothing admitted or written");
        assert_eq!(w.ops.setup_insert_calls(), 0);
        assert_eq!(
            std::fs::read(tree.path().join("config")).unwrap(),
            tree_before
        );
    }

    /// `u0b_setup_admission_goes_through_insert_setup_operation` (row 23, phase 2).
    /// Every effectful setup request calls `Txn::insert_setup_operation` exactly once
    /// (counted at the admission call site). Replaying an admitted request's ID calls
    /// it zero times and returns that same operation while it is open, so the request
    /// is never refused because of itself. A refused request leaves no record, so
    /// its retry is checked again and admitted once the blocker settled.
    #[tokio::test]
    async fn u0b_setup_admission_goes_through_insert_setup_operation() {
        let mut w = World::new().await;
        let digest = PlanDigest::from_sha256([0x5d; 32]);
        let writer = CountingWriter::new(Some(digest.clone()), true);
        with_writer(&mut w, &writer).await;
        let caller = unattended(501);
        let apply = |rid: &str| SetupRequest::Apply {
            plan_digest: digest.clone(),
            request_id: RequestId::parse(rid).unwrap(),
        };
        let open = |w: &World| {
            w.store
                .transaction(|tx| tx.open_setup_operations(&env_id()))
                .unwrap()
        };
        // Admitted: one call; the operation waits for its decision.
        let first = w.ops.setup(&caller, apply("u0b-ad-1")).await;
        rendered(&first);
        assert_eq!(w.ops.setup_insert_calls(), 1);
        let blocker = open(&w);
        assert_eq!(blocker.len(), 1, "one operation admitted");
        let op1 = blocker[0].clone();
        // A replay: zero calls, the same operation, never `setup_in_progress`.
        for _ in 0..2 {
            let replay = w.ops.setup(&caller, apply("u0b-ad-1")).await;
            let v = rendered(&replay);
            assert_eq!(
                w.ops.setup_insert_calls(),
                1,
                "a replay never reaches the store call"
            );
            assert_ne!(v["data"]["error"]["reason"], "setup_in_progress", "{v}");
            assert_eq!(v["operation_id"], serde_json::json!(op1));
        }
        // Another request: one call, refused naming the blocker, nothing written.
        let counts = w.store.transaction(|tx| tx.operation_counts()).unwrap();
        for (n, req) in [
            (2, apply("u0b-ad-2")),
            (
                3,
                SetupRequest::Rollback {
                    plan_digest: digest.clone(),
                    request_id: RequestId::parse("u0b-ad-3").unwrap(),
                },
            ),
        ] {
            let e = err(w.ops.setup(&caller, req).await);
            assert_eq!(e.code, Code::ConfigConflict, "{}", e.message);
            assert_eq!(e.reason.as_deref(), Some("setup_in_progress"));
            assert_eq!(e.next.operation_id.as_ref(), Some(&op1));
            assert_eq!(
                w.ops.setup_insert_calls(),
                n,
                "exactly one call per request"
            );
        }
        assert_eq!(
            w.store.transaction(|tx| tx.operation_counts()).unwrap(),
            counts
        );
        assert_eq!(open(&w), vec![op1.clone()]);
        // The blocker settles (denied); the refused request's retry is checked again.
        let d = w
            .store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .into_iter()
            .find(|d| matches!(&d.kind, DecisionKind::ApplyProjection { operation, .. } if *operation == op1))
            .expect("the decision");
        ok(decide(&w, &attended(501), &d.id, Verdict::Deny).await);
        assert_eq!(w.op(&op1).state, OperationState::Failed);
        let retry = w.ops.setup(&caller, apply("u0b-ad-2")).await;
        rendered(&retry);
        assert_eq!(w.ops.setup_insert_calls(), 4);
        let now_open = open(&w);
        assert_eq!(now_open.len(), 1);
        assert_ne!(now_open[0], op1);
        assert_eq!(writer.applies(), 0);
        w.events();
    }

    /// ADR-0007 §12.14 item 3 (E1), phase 2: a setup cancellation is honoured only
    /// before the first commit point. Before the driver started (queued, or waiting
    /// for its decision), it settles `cancelled` with effect `none`, withdraws the
    /// pending decision and releases `setup_in_progress`. Once the driver started (its
    /// `setup.attempt` receipt, or a commit step exchanged), the answer is
    /// `OUTCOME_UNKNOWN` (effect `unknown`) with `next: reconcile` naming the
    /// operation, and nothing is written. The same rule holds for a catalog
    /// operation, and a settled operation's cancellation stays idempotent.
    #[tokio::test]
    async fn u0b_setup_cancel_only_before_the_first_commit_point() {
        let w = World::new().await;
        let cancel = |id: &OperationId| {
            let ops = w.ops.clone();
            let req = CancelRequest {
                operation_id: id.clone(),
            };
            async move { ops.cancel(&unattended(501), req).await }
        };
        // Waiting for its decision.
        let (waiting, d, _) = waiting_setup(&w, 0xa1);
        let done = ok(cancel(&waiting).await);
        assert_eq!(done.data["state"], "cancelled");
        assert_eq!(done.data["may_have_external_effect"], false);
        let op = w.op(&waiting);
        assert_eq!(op.state, OperationState::Cancelled);
        assert_eq!(op.effect_status, EffectStatus::None);
        assert_eq!(record(&w, &d).state, DecisionState::Withdrawn);
        assert!(
            w.store
                .transaction(|tx| tx.open_setup_operations(&env_id()))
                .unwrap()
                .is_empty(),
            "setup_in_progress is released"
        );
        // Idempotent once settled.
        let again = ok(cancel(&waiting).await);
        assert_eq!(again.data["state"], "cancelled");
        // Queued, nothing started.
        let queued_op = seed_local(
            &w,
            0xa3,
            OperationKind::SetupRollback,
            OperationState::Queued,
            LocalIntent::Setup(setup_intent(0xa3, apply_intent())),
        );
        assert_eq!(ok(cancel(&queued_op).await).data["state"], "cancelled");
        // Started: past (or possibly past) the first commit point.
        let snapshot = |id: &OperationId| {
            (
                w.op(id),
                w.store.transaction(|tx| tx.stage_receipts(id)).unwrap(),
                intent_of(&w, id),
            )
        };
        let running = seed_local(
            &w,
            0xa5,
            OperationKind::SetupApply,
            OperationState::Running,
            LocalIntent::Setup(setup_intent(0xa5, apply_intent())),
        );
        started(&w, &running);
        let exchanged = seed_local(
            &w,
            0xa7,
            OperationKind::SetupApply,
            OperationState::Running,
            LocalIntent::Setup(setup_intent(0xa7, apply_intent())),
        );
        started(&w, &exchanged);
        w.store
            .transaction(|tx| {
                tx.append_stage_receipt(
                    &exchanged,
                    &StageReceipt {
                        local: Some(LocalReceipt::File {
                            step: 0,
                            phase: FilePhase::Exchanged,
                        }),
                        ..local_receipt()
                    },
                )
            })
            .unwrap();
        for id in [&running, &exchanged] {
            let before = snapshot(id);
            let e = err(cancel(id).await);
            assert_eq!(e.code, Code::OutcomeUnknown, "{}", e.message);
            assert_eq!(e.effect_status, EffectStatus::Unknown);
            assert_eq!(e.next.action, "reconcile");
            assert_eq!(e.next.operation_id.as_ref(), Some(id));
            assert_eq!(snapshot(id), before, "nothing written");
        }
        // A catalog operation waiting for its declaration decision.
        let catalog = seed_local(
            &w,
            0xa9,
            OperationKind::Catalog,
            OperationState::AwaitingApproval,
            declare_intent(&identity_id()),
        );
        let cd = insert_decision(&w, 0xaa, declare_interaction(&catalog, &identity_id()));
        assert_eq!(ok(cancel(&catalog).await).data["state"], "cancelled");
        assert_eq!(record(&w, &cd).state, DecisionState::Withdrawn);
        w.events();
    }
}

// =================================================================================
// ⟨M02⟩ Wave-0 acceptance: the fail-closed landing (m02-plan §5 item 4, U0b), after
// the activation change set
// =================================================================================

/// ⟨M02⟩ m02-plan U0b "wave-0 acceptance tests" (M2-R07; ADR-0007 §12.5 item 7,
/// §12.7 QR7), as phase 2 leaves them. The one that still holds stays here: a
/// session that did not negotiate `setup/1` gets `SCHEMA_UNSUPPORTED` for every
/// Setup and Catalog request, never dispatched. Phase 2 replaced the others (m02-plan
/// U0b "Tests, phase 2"):
/// * `w0_setup_1_is_not_offered` is retired by
///   `u0b_phase2::u0b_setup_1_offered_after_activation`;
/// * `w0_setup_and_catalog_at_dispatch_are_capability_unavailable` by
///   `u0b_phase2::u0b_setup_without_projection_writer_is_capability_unavailable` (its
///   permanent form; the catalog part by U5's end-to-end tests);
/// * `w0_open_setup_and_catalog_operations_stay_unresolved_at_restart` by
///   `u0b_phase2::u0b_restart_dispatches_every_operation_kind`
///   (untouched without a writer, reconciled with one) and
///   `u0b_phase2::u0b_setup_cancel_only_before_the_first_commit_point` (E1);
/// * `w0_decide_on_projection_or_declaration_decision_is_refused_unconsumed` by the
///   three phase-2 decision tests.
///
/// The plan names `tests/e2e/wave0_fail_closed.rs` hosted by `heimdall-runtime`;
/// that needs a `[[test]]` entry in a manifest this unit does not own, so the suite
/// is a module of this target, which `heimdall-runtime` already hosts (escalated in
/// wave 0). The CLI case is in `tests/e2e/cli_m01.rs` (a `heimdall` package target,
/// wave-0 verify E6). Sessions run over an in-memory duplex stream, so the suite is
/// the same on every platform.
mod wave0_fail_closed {
    use super::*;
    use heimdall_contract::ipc::{
        ClientHello, ClientMessage, PeerInfo, PrincipalInfo, ServerMessage, capability,
    };
    use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
    use heimdall_domain::operation::OperationKind;
    use heimdall_ipc::frame::{CONTROL_LIMIT, decode_frame, encode_frame};
    use heimdall_ipc::session::{
        ConnectionLimits, ControlConnection, Dispatcher, SessionInfo, SubscriptionStart,
        server_capabilities,
    };
    use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
    use tokio_util::sync::CancellationToken;

    /// Every Setup and Catalog request: each committed example under
    /// `schemas/examples/request.{setup,catalog}.*.json`, decoded as a `Request`
    /// (every action of both, U0's examples).
    fn new_requests() -> Vec<Request> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("request.setup.") || n.starts_with("request.catalog."))
            .collect();
        names.sort();
        let requests: Vec<Request> = names
            .iter()
            .map(|n| {
                let text = std::fs::read_to_string(dir.join(n)).unwrap();
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{n}: {e}"))
            })
            .collect();
        let actions: BTreeSet<String> = requests
            .iter()
            .map(|r| {
                let v = serde_json::to_value(r).unwrap();
                format!(
                    "{}.{}",
                    v["op"].as_str().unwrap(),
                    v["action"].as_str().unwrap()
                )
            })
            .collect();
        let expected: BTreeSet<String> = [
            "setup.preview",
            "setup.apply",
            "setup.rollback",
            "setup.repair",
            "catalog.upsert_destination",
            "catalog.remove_destination",
            "catalog.adopt_identity",
            "catalog.remove_identity",
            "catalog.upsert_profile",
            "catalog.remove_profile",
            "catalog.declare_interaction",
            "catalog.withdraw_declaration",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            actions, expected,
            "every Setup and Catalog action is covered"
        );
        assert!(
            requests
                .iter()
                .all(|r| matches!(r, Request::Setup(_) | Request::Catalog(_)))
        );
        requests
    }

    /// Everything a request could have written: operation counts, stored events,
    /// pending decisions, receipts, intents and meta rows, and the idempotency
    /// records of the given keys.
    fn rows(w: &World, keys: &[IdempotencyKeyOf]) -> serde_json::Value {
        w.store
            .transaction(|tx| {
                let events = tx
                    .stored_events_after(&env_id(), 0, &EventFilter::default(), 10_000)?
                    .events
                    .into_iter()
                    .map(|e| serde_json::to_value(e.event).unwrap())
                    .collect::<Vec<_>>();
                let mut idem = Vec::new();
                for k in keys {
                    idem.push(tx.idempotency_record(k)?.is_some());
                }
                Ok(serde_json::json!({
                    "operations": tx.operation_counts()?,
                    "open": tx.open_operations()?.len(),
                    "events": events,
                    "decisions": tx.pending_decisions()?.len(),
                    "receipts": tx.raw_documents(heimdall_store::RawDocuments::StageReceipts)?,
                    "intents": tx.raw_documents(heimdall_store::RawDocuments::RecoveryIntents)?,
                    "meta": tx.raw_documents(heimdall_store::RawDocuments::Meta)?,
                    "idempotency": idem,
                    "identities": tx.identities()?.len(),
                    "destinations": tx.destinations()?.len(),
                    "projections": tx.projection_resources(&env_id())?.len(),
                }))
            })
            .unwrap()
    }

    type IdempotencyKeyOf = heimdall_domain::idempotency::IdempotencyKey;

    /// The idempotency key each request would have had (its kind's namespace).
    fn keys_of(requests: &[Request]) -> Vec<IdempotencyKeyOf> {
        requests
            .iter()
            .filter_map(|r| {
                let v = serde_json::to_value(r).unwrap();
                let rid = v["request_id"].as_str()?;
                let kind = match r.kind() {
                    "setup.apply" => OperationKind::SetupApply,
                    "setup.rollback" => OperationKind::SetupRollback,
                    "setup.repair" => OperationKind::SetupRepair,
                    _ => OperationKind::Catalog,
                };
                Some(IdempotencyKeyOf {
                    caller: ctx(501, ClientRole::Owner),
                    kind,
                    request_id: RequestId::parse(rid).unwrap(),
                })
            })
            .collect()
    }

    fn client_info() -> PeerInfo {
        PeerInfo {
            name: "heimdall-u0b-test".into(),
            version: "0".into(),
        }
    }

    /// Counts every request the session hands to the dispatcher, then delegates to
    /// the real [`OperationsDispatcher`].
    #[derive(Clone)]
    struct Counting {
        inner: OperationsDispatcher,
        calls: Arc<AtomicUsize>,
    }

    impl Dispatcher for Counting {
        fn dispatch<'life0, 'life1, 'async_trait>(
            &'life0 self,
            session: &'life1 SessionInfo,
            request: Request,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = heimdall_contract::Envelope<serde_json::Value>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.dispatch(session, request)
        }

        fn subscribe<'life0, 'life1, 'async_trait>(
            &'life0 self,
            session: &'life1 SessionInfo,
            filter: EventFilter,
            from: Option<heimdall_contract::event::Cursor>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            SubscriptionStart,
                            Box<heimdall_contract::Envelope<heimdall_contract::ErrorData>>,
                        >,
                    > + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.subscribe(session, filter, from)
        }
    }

    fn counting(w: &World) -> (Counting, Arc<AtomicUsize>) {
        let relay = EventRelay::spawn(&w.ops, CancellationToken::new());
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Counting {
                inner: OperationsDispatcher::new(w.ops.clone(), relay, w.clock.clone()),
                calls: calls.clone(),
            },
            calls,
        )
    }

    fn serve(
        w: &World,
        server: tokio::io::DuplexStream,
        dispatcher: Counting,
    ) -> tokio::task::JoinHandle<()> {
        let _ = w;
        tokio::spawn(async move {
            let _ = ControlConnection::new(server, ConnectionLimits::default())
                .with_server_identity(
                    env_id(),
                    PeerInfo {
                        name: "heimdall".into(),
                        version: "test".into(),
                    },
                )
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                )
                .await;
        })
    }

    /// A control client whose hello offers exactly the capabilities it is given.
    /// (The production `ControlClient` offers every capability the server serves,
    /// `setup/1` included since the activation change set.) Frames are the
    /// production codec's (`heimdall_ipc::frame`).
    pub(super) struct RawClient {
        stream: tokio::io::DuplexStream,
        buf: Vec<u8>,
        seq: u64,
        /// The capabilities the server's hello negotiated.
        pub(super) negotiated: BTreeSet<String>,
    }

    impl RawClient {
        /// Send a hello offering `capabilities` and requiring none; `Err` is the
        /// server's rejection.
        pub(super) async fn handshake(
            mut stream: tokio::io::DuplexStream,
            capabilities: BTreeSet<String>,
        ) -> Result<Self, Box<heimdall_contract::Envelope<heimdall_contract::ErrorData>>> {
            use tokio::io::AsyncWriteExt;
            let hello = ClientMessage::Hello(ClientHello {
                protocol: heimdall_contract::PROTOCOL_VERSION,
                schema_version: heimdall_contract::SchemaVersion::current(),
                client: client_info(),
                capabilities,
                required: BTreeSet::new(),
                interaction: InteractionMode::NonInteractive,
            });
            stream
                .write_all(&encode_frame(&hello, CONTROL_LIMIT).unwrap())
                .await
                .unwrap();
            let mut me = Self {
                stream,
                buf: Vec::new(),
                seq: 0,
                negotiated: BTreeSet::new(),
            };
            match me.next().await {
                ServerMessage::Hello(h) => {
                    me.negotiated = h.capabilities;
                    Ok(me)
                }
                ServerMessage::Reject(env) => Err(Box::new(env)),
                _ => panic!("unexpected first server frame"),
            }
        }

        async fn next(&mut self) -> ServerMessage {
            use tokio::io::AsyncReadExt;
            loop {
                if let Some((msg, used)) =
                    decode_frame::<ServerMessage>(&self.buf, CONTROL_LIMIT).unwrap()
                {
                    self.buf.drain(..used);
                    return msg;
                }
                let mut chunk = [0u8; 8192];
                let n = self.stream.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the server closed the connection");
                self.buf.extend_from_slice(&chunk[..n]);
            }
        }

        /// Send `request` and return its response.
        pub(super) async fn request(
            &mut self,
            request: Request,
        ) -> heimdall_contract::Envelope<serde_json::Value> {
            use tokio::io::AsyncWriteExt;
            self.seq += 1;
            let seq = self.seq;
            let frame =
                encode_frame(&ClientMessage::Request { seq, request }, CONTROL_LIMIT).unwrap();
            self.stream.write_all(&frame).await.unwrap();
            loop {
                if let ServerMessage::Response {
                    in_reply_to,
                    envelope,
                } = self.next().await
                    && in_reply_to == seq
                {
                    return envelope;
                }
            }
        }
    }

    /// Every capability the server serves except `setup/1`.
    pub(super) fn without_setup() -> BTreeSet<String> {
        let mut c = server_capabilities();
        c.remove(capability::SETUP_V1);
        c
    }

    /// A real session over a duplex stream whose hello did not offer `setup/1` (it
    /// offers every other capability the server serves), its dispatcher counting.
    async fn session(w: &World) -> ((tokio::task::JoinHandle<()>, Arc<AtomicUsize>), RawClient) {
        let (server, client_stream) = tokio::io::duplex(1 << 16);
        let (dispatcher, calls) = counting(w);
        let served = serve(w, server, dispatcher);
        let client = RawClient::handshake(client_stream, without_setup())
            .await
            .unwrap_or_else(|e| panic!("hello refused: {:?}", e.code));
        assert!(!client.negotiated.contains(capability::SETUP_V1));
        assert_eq!(client.negotiated, without_setup());
        ((served, calls), client)
    }

    /// `w0_setup_and_catalog_on_a_session_are_never_dispatched`, as it holds after
    /// activation: over a real session whose hello did not offer `setup/1`, every
    /// Setup and Catalog request is answered `SCHEMA_UNSUPPORTED` by the session
    /// gate. The dispatcher is never called, and nothing is written.
    #[tokio::test]
    async fn w0_setup_and_catalog_on_a_session_are_never_dispatched() {
        let w = World::new().await;
        let requests = new_requests();
        let keys = keys_of(&requests);
        let before = rows(&w, &keys);
        let ((served, calls), mut client) = session(&w).await;
        for request in &requests {
            let env = client.request(request.clone()).await;
            let v = serde_json::to_value(&env).unwrap();
            assert_eq!(env.code, Code::SchemaUnsupported, "{}: {v}", request.kind());
            assert_no_canary(&v.to_string());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "never dispatched");
        // The session still dispatches a request it negotiated.
        let inspect = client
            .request(Request::Inspect(InspectRequest {
                subject: InspectSubject::Operations,
                preview: None,
            }))
            .await;
        assert_eq!(inspect.code, Code::Ok);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(client);
        let _ = served.await;
        assert_eq!(rows(&w, &keys), before, "no row of any kind");
    }
}
