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
                form: BindForm::Launch { argv: Vec::new() },
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
        r1310_view(&w, &g.grant_id).await["remote_pending_reason"],
        "adapter_unavailable"
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
struct PendingCounter {
    inner: Arc<FakeCredentialAdapter>,
    pending: AtomicBool,
    revokes: AtomicUsize,
    confirms: AtomicUsize,
    faults: std::sync::Mutex<Option<Arc<Armed>>>,
    hang: AtomicBool,
    entered: tokio::sync::Notify,
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
            entered: tokio::sync::Notify::new(),
        })
    }
    fn calls(&self) -> usize {
        self.revokes.load(Ordering::SeqCst)
    }
    fn confirmations(&self) -> usize {
        self.confirms.load(Ordering::SeqCst)
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
        self.revokes.fetch_add(1, Ordering::SeqCst);
        let pending = self.pending.load(Ordering::SeqCst);
        if let Some(f) = self.faults.lock().unwrap().as_ref() {
            f.arm();
        }
        let hang = self.hang.swap(false, Ordering::SeqCst);
        Box::pin(async move {
            if hang {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            let mut out = self.inner.revoke(grant, now).await?;
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
        view["remote_pending_reason"], "adapter_unavailable",
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
/// later rounds come only from the supervisor's schedule.
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
    let sup = r1312_supervisor(&w, 8);
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 1, "the first pass only schedules");
    w.clock.advance(10 * Duration::from_secs(1));
    sup.scheduler_pass().await.unwrap();
    assert_eq!(adapter.calls(), 2);
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoked);
    assert!(r1312_record(&w, &g.grant_id).is_none());
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
    #[derive(Debug, Clone, Copy)]
    enum Step {
        /// A due round.
        Round,
        /// A due round whose completion commit fails.
        FailCompletion,
        /// A due round interrupted after the adapter call; then a restart.
        Crash,
        /// Restart with only another mechanism's adapter.
        RemoveAdapter,
        /// Restart with no adapter.
        NoAdapters,
        /// Restart with the original adapter.
        RestoreAdapter,
        /// The original adapter now reports done (`true`) or pending (`false`).
        Done(bool),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            3 => Just(Step::Round),
            2 => Just(Step::FailCompletion),
            2 => Just(Step::Crash),
            1 => Just(Step::RemoveAdapter),
            1 => Just(Step::NoAdapters),
            2 => Just(Step::RestoreAdapter),
            2 => any::<bool>().prop_map(Step::Done),
        ]
    }

    proptest! {
        #![proptest_config(config(0x1312_0001))]

        /// For any sequence of rounds, completion faults, crashes and adapter
        /// removal or restoration (cap 2 to 4 rounds, the first local denial
        /// included): the original adapter is called at most `cap` times; the
        /// obligation is never cleared (record gone, grant `revoked`) unless that
        /// adapter confirmed; another adapter is never asked; while the grant is
        /// `revoking` its record stays visible.
        #[test]
        fn r1312_calls_stay_within_the_cap_and_only_the_adapter_clears_its_obligation(
            cap in 2u32..5,
            steps in proptest::collection::vec(step(), 1..12),
        ) {
            block(async move {
                let faults = Armed::new(FaultPoint::BeforeCommit);
                let (mut w, adapter) = r1312_pending_world_with(Setup {
                    faults: faults.clone(),
                    ..Setup::default()
                })
                .await;
                let g = r1310_withdrawn_pending(&w, &adapter, "r1312-p").await;
                let other = r1312_other_adapter();
                let original = adapter.clone() as Arc<dyn CredentialAdapter>;
                let mut sup = r1312_supervisor(&w, cap);
                for s in steps {
                    match s {
                        Step::Round | Step::FailCompletion | Step::Crash => {
                            let _ = sup.scheduler_pass().await;
                            w.clock.advance(10 * Duration::from_secs(1));
                            match s {
                                Step::FailCompletion => {
                                    *adapter.faults.lock().unwrap() = Some(faults.clone());
                                }
                                Step::Crash => adapter.hang.store(true, Ordering::SeqCst),
                                _ => {}
                            }
                            let crashed = r1312_until_crash(&adapter, sup.scheduler_pass()).await;
                            *adapter.faults.lock().unwrap() = None;
                            faults.armed.store(false, Ordering::SeqCst);
                            adapter.hang.store(false, Ordering::SeqCst);
                            if crashed {
                                r1312_restart_with(&mut w, vec![original.clone()]).await;
                                sup = r1312_supervisor(&w, cap);
                            }
                        }
                        Step::RemoveAdapter => {
                            r1312_restart_with(
                                &mut w,
                                vec![other.clone() as Arc<dyn CredentialAdapter>],
                            )
                            .await;
                            sup = r1312_supervisor(&w, cap);
                        }
                        Step::NoAdapters => {
                            r1312_restart_with(&mut w, Vec::new()).await;
                            sup = r1312_supervisor(&w, cap);
                        }
                        Step::RestoreAdapter => {
                            r1312_restart_with(&mut w, vec![original.clone()]).await;
                            sup = r1312_supervisor(&w, cap);
                        }
                        Step::Done(done) => adapter.pending.store(!done, Ordering::SeqCst),
                    }
                    let state = w.grant(&g.grant_id).state;
                    let record = r1312_record(&w, &g.grant_id);
                    prop_assert!(
                        adapter.calls() <= cap as usize,
                        "calls {} > cap {cap} (record {:?})", adapter.calls(), record
                    );
                    prop_assert!(
                        !other.revocations.lock().unwrap().contains(&g.grant_id),
                        "another adapter was asked"
                    );
                    match record {
                        Some(r) if state != GrantState::Revoked => {
                            prop_assert_eq!(state, GrantState::Revoking);
                            prop_assert!(r.attempts <= cap);
                        }
                        record => {
                            prop_assert_eq!(state, GrantState::Revoked);
                            prop_assert!(record.is_none());
                            prop_assert!(
                                adapter.confirmations() > 0,
                                "cleared without the adapter's confirmation"
                            );
                        }
                    }
                }
                Ok(())
            })?;
        }
    }
}
