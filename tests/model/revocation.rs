//! M01-U5 revocation, issuance and sharing suite (spec §6.7, §8.2, §17 A07;
//! ADR-0005 §3.5–§3.6; ADR-0006 §13.4 N02; plan §6.3 #3, #5, #8).
//!
//! * **A07** (model variant): a revoke during a scripted slow `prepare` denies the
//!   child and the parent, and the late `Prepared` is ignored by the generation and
//!   tombstone checks; a pending approval cannot be completed after a revoke; the
//!   production `issuance::check` at publish voids a reservation after a revoke, a
//!   cutoff, a policy-revision change, a continuous-budget expiry and
//!   `TIME_UNCERTAIN` (each between reserve and publish), and the residual then
//!   counts nothing published; a `reserved` entry found after a restart stays
//!   counted and is never published; `remote_pending` and
//!   `latest_possible_credential_expiry` are truthful.
//! * **Sharing** (spec §8.2): equivalent work is single-flight with separate
//!   references; unrelated scopes never share a grant.
//! * **Properties** (proptest, 256 cases, fixed seed unless `PROPTEST_RNG_SEED`):
//!   #3 a tombstone or cutoff is never defeated by stale callbacks or new request
//!   IDs; #5 expired/revoked grants never return to active and a restart never
//!   resets a deadline; #8 sharing never merges unrelated authority nor retains a
//!   grant past its deadline.
//!
//! The slow `prepare` is a test adapter **wrapping** `testkit::FakeCredentialAdapter`
//! through the production `CredentialAdapter` port (it delays one call; effects
//! and reconciliation are the fake's). Restarts are **in-process**.
//!
//! Hosting: `heimdall-app` (it has the `proptest` and `async-trait` edges).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::ensure::{EnsureStage, NoStageHook, StageHook};
use heimdall_app::operations::{IssuanceFacts, IssuanceRequest, Limits};
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, InteractionRequirement, LockContinuity,
    PrepareOutcome, PrepareRequest, ReconcileOutcome, RevokeOutcome,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, BindingId, DecisionId, DestinationId, DeviceId, EnvironmentId, GrantId,
    OperationId, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    BindForm, BindRequest, DeadlineIntent, DecideRequest, DelegateRequest,
    DestinationScopeEnforcement, EnsureData, EnsureRequest, InteractionMode, PolicyAction,
    RefreshDependency, ReleaseRequest, RequiredCapabilities, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::authority::AuthorityDelta;
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{IssuanceRefusal, IssuanceState};
use heimdall_domain::operation::{AdapterIdentity, EffectReceipt};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store, Txn};
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};
use tokio::sync::{Notify, Semaphore};

// =================================================================================
// Harness
// =================================================================================

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn at(secs: i64) -> Timestamp {
    t0().checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn owner(uid: u32) -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid },
        role: ClientRole::Owner,
    })
}

fn attended(uid: u32) -> Caller {
    Caller {
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
        ..owner(uid)
    }
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn ssh() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn policy_id() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: at(12 * 3600),
        offline_until: at(3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        credential_ref: format!("{CANARY_PREFIX}revocation_fixture"),
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
                    pairs: [
                        pair("h1", "deploy"),
                        pair("h2", "deploy"),
                        pair("h3", "deploy"),
                    ]
                    .into_iter()
                    .collect(),
                    capabilities: ssh(),
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
                        pairs: [pair("h1", "deploy"), pair("h2", "deploy")]
                            .into_iter()
                            .collect(),
                        capabilities: ssh(),
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

/// The fake adapter behind the production port, with one optionally delayed
/// `prepare` call and an optionally failing `revoke` (unreachable remote).
struct Gated {
    inner: Arc<FakeCredentialAdapter>,
    calls: AtomicUsize,
    hold_call: AtomicUsize,
    entered: Notify,
    release: Semaphore,
    revoke_fails: AtomicBool,
}

impl Gated {
    fn new(inner: Arc<FakeCredentialAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            calls: AtomicUsize::new(0),
            hold_call: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Semaphore::new(0),
            revoke_fails: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl CredentialAdapter for Gated {
    fn descriptor(&self) -> &AdapterDescriptor {
        self.inner.descriptor()
    }

    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.hold_call.load(Ordering::SeqCst) {
            self.entered.notify_one();
            let _permit = self.release.acquire().await.unwrap();
        }
        self.inner.prepare(req).await
    }

    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.inner.renew(req).await
    }

    async fn reconcile(
        &self,
        grant: &GrantId,
        token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        self.inner.reconcile(grant, token).await
    }

    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError> {
        if self.revoke_fails.load(Ordering::SeqCst) {
            return Err(AdapterError::Unavailable(format!(
                "{CANARY_PREFIX}unreachable"
            )));
        }
        self.inner.revoke(grant, now).await
    }
}

/// Counts pipeline entries into `Coalesce` (production `StageHook` trait); the
/// hook runs synchronously right before `SingleFlight::join_or_lead`.
#[derive(Default)]
struct CountCoalesce {
    entries: AtomicUsize,
    changed: Notify,
}

impl StageHook for CountCoalesce {
    fn before(&self, stage: EnsureStage) -> Result<(), Code> {
        if stage == EnsureStage::Coalesce {
            self.entries.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_one();
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
    gated: Arc<Gated>,
    hook: Arc<dyn StageHook>,
    limits: Limits,
    ops: Operations,
}

/// Harness options (production hooks only: the pipeline `StageHook`, the store
/// `FaultHook`, the limits, the fake adapter's declared enforcement and script).
struct Opts {
    hook: Arc<dyn StageHook>,
    faults: Arc<dyn FaultHook>,
    limits: Limits,
    enforcement: EnforcementEvidence,
    script: Vec<FakeStep>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            hook: Arc::new(NoStageHook),
            faults: Arc::new(heimdall_store::NoFaults),
            limits: Limits::default(),
            enforcement: EnforcementEvidence::unknown(),
            script: vec![FakeStep::Prepare(outcome())],
        }
    }
}

impl World {
    async fn new() -> Self {
        Self::with_hook(Arc::new(NoStageHook)).await
    }

    async fn with_hook(hook: Arc<dyn StageHook>) -> Self {
        Self::with_opts(Opts {
            hook,
            ..Opts::default()
        })
        .await
    }

    async fn with_opts(o: Opts) -> Self {
        let store = Arc::new(Store::open_in_memory(o.faults).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let descriptor = AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            capabilities: ssh(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: o.enforcement,
            lock_continuity: LockContinuity::Unknown,
        };
        let fake = FakeCredentialAdapter::new(descriptor, o.script);
        let gated = Gated::new(fake.clone());
        let hook = o.hook;
        let limits = o.limits;
        let ops = Operations::start(config(&store, &clock, &sync, &gated, &hook, limits))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            gated,
            hook,
            limits,
            ops,
        }
    }

    /// In-process restart over the same store and adapter.
    async fn restart(&mut self) {
        self.ops = Operations::start(config(
            &self.store,
            &self.clock,
            &self.sync,
            &self.gated,
            &self.hook,
            self.limits,
        ))
        .await
        .unwrap();
    }

    fn grant(&self, id: &GrantId) -> heimdall_domain::grant::GrantSnapshot {
        self.store.transaction(|tx| tx.grant(id)).unwrap().unwrap()
    }

    async fn ensure(
        &self,
        rid: &str,
        work: &str,
        hosts: &[&str],
        until: Option<DeadlineIntent>,
    ) -> OpResult<EnsureData> {
        let r = self
            .ops
            .ensure(
                &owner(501),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: hosts.iter().map(|h| pair(h, "deploy")).collect(),
                    environment: None,
                    work_id: WorkId::parse(work).unwrap(),
                    until,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                },
            )
            .await;
        scan(&r);
        r
    }

    async fn ready(
        &self,
        rid: &str,
        work: &str,
        hosts: &[&str],
        until: Option<DeadlineIntent>,
    ) -> EnsureData {
        match self.ensure(rid, work, hosts, until).await {
            Ok(c) => c.data,
            Err(e) => panic!("ensure {rid}: {}: {}", e.code, e.message),
        }
    }

    async fn revoke(
        &self,
        grant: &GrantId,
        rid: &str,
    ) -> OpResult<heimdall_contract::request::RevokeData> {
        let r = self
            .ops
            .revoke(
                &owner(501),
                RevokeRequest {
                    grant_id: grant.clone(),
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await;
        scan(&r);
        r
    }

    async fn bind(&self, binding: &BindingId, rid: &str) -> OpResult<EnsureData> {
        let r = self
            .ops
            .bind(
                &owner(501),
                BindRequest {
                    binding_id: binding.clone(),
                    form: BindForm::Materialize,
                    request_id: RequestId::parse(rid).unwrap(),
                },
            )
            .await;
        scan(&r);
        r
    }
}

fn config(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    gated: &Arc<Gated>,
    hook: &Arc<dyn StageHook>,
    limits: Limits,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![gated.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: hook.clone(),
        limits,
        default_window: 12 * HOUR,
    }
}

fn scan<T: serde::Serialize + Clone>(r: &OpResult<T>) {
    let s = match r {
        Ok(c) => serde_json::to_string(&c.clone().into_envelope()).unwrap(),
        Err(e) => serde_json::to_string(&e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&s);
}

fn code_of<T>(r: &OpResult<T>) -> Code {
    match r {
        Ok(c) => c.code.clone(),
        Err(e) => e.code.clone(),
    }
}

fn issuance(grant: &GrantId, valid_before: Timestamp) -> IssuanceRequest {
    IssuanceRequest {
        grant: grant.clone(),
        pair: pair("h1", "deploy"),
        principal: "hm:h1:deploy".into(),
        key_id: "fixture-key".into(),
        valid_after: t0(),
        valid_before,
        extensions: BTreeSet::new(),
        subject_fingerprint: "fixture-fingerprint".into(),
        facts: facts(),
    }
}

fn facts() -> IssuanceFacts {
    IssuanceFacts {
        new_activation: false,
        subject_registered: true,
        critical_option: false,
    }
}

fn entry(w: &World, grant: &GrantId) -> heimdall_domain::issuance::IssuanceEntry {
    w.store
        .transaction(|tx| tx.issuance_entries(grant))
        .unwrap()
        .pop()
        .unwrap()
}

fn residual(w: &World, grant: &GrantId) -> Option<Timestamp> {
    w.store
        .transaction(|tx| tx.issuance_residual(std::slice::from_ref(grant)))
        .unwrap()
}

// =================================================================================
// A07 — revoke races
// =================================================================================

#[tokio::test]
async fn a07_revoke_during_a_slow_prepare_denies_child_and_parent_and_ignores_the_late_prepared() {
    let w = World::new().await;
    let parent = w.ready("req-par", "work-par", &["h1", "h2"], None).await;
    // The child's prepare (the adapter's second call) is held open.
    w.gated.hold_call.store(2, Ordering::SeqCst);
    let ops = w.ops.clone();
    let parent_binding = parent.binding_id.clone();
    let child = tokio::spawn(async move {
        ops.delegate(
            &owner(501),
            DelegateRequest {
                parent_binding_id: parent_binding,
                scope: [pair("h1", "deploy")].into_iter().collect(),
                until: Some(DeadlineIntent::Duration("30m".into())),
                work_id: WorkId::parse("child").unwrap(),
                request_id: RequestId::parse("req-child").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
    });
    w.gated.entered.notified().await;
    // Revoke the parent while the child is inside `prepare`.
    let revoked = w.revoke(&parent.grant_id, "req-rv").await.unwrap();
    assert!(revoked.data.local_applied);
    let tomb = w
        .store
        .transaction(|tx| tx.tombstone(&parent.grant_id))
        .unwrap()
        .expect("tombstone persisted before acknowledgment");
    assert_eq!(tomb.cascade.len(), 1);
    let child_grant = tomb.cascade[0].clone();
    assert_eq!(w.grant(&child_grant).state, GrantState::Revoked);
    // The late `Prepared` arrives after the tombstone.
    w.gated.release.add_permits(1);
    let r = child.await.unwrap();
    scan(&r);
    let e = r.unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(
        w.grant(&child_grant).state,
        GrantState::Revoked,
        "never reactivated"
    );
    assert!(matches!(
        w.grant(&parent.grant_id).state,
        GrantState::Revoked | GrantState::Revoking
    ));
    // The late credential was cleaned up locally (revoke op + cleanup).
    let revs = w.fake.revocations.lock().unwrap().clone();
    assert!(revs.iter().filter(|g| **g == child_grant).count() >= 2);
    // New local use fails immediately.
    assert_eq!(
        code_of(&w.bind(&parent.binding_id, "bind-after").await),
        Code::CredentialExpired
    );
    let reserve = w
        .ops
        .reserve_issuance(issuance(&parent.grant_id, at(600)))
        .await;
    assert_eq!(reserve.unwrap_err().code, Code::CredentialExpired);
    let again = w
        .ops
        .delegate(
            &owner(501),
            DelegateRequest {
                parent_binding_id: parent.binding_id.clone(),
                scope: [pair("h1", "deploy")].into_iter().collect(),
                until: None,
                work_id: WorkId::parse("child-2").unwrap(),
                request_id: RequestId::parse("req-child-2").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await;
    scan(&again);
    assert_eq!(code_of(&again), Code::CredentialExpired);
}

/// An unrelated revoke moves the global generation: the pending decision record
/// is stale (`DECISION_STALE`, consume-once on its generation), but the waiting
/// operation is re-validated silently and stays waiting (ADR-0006 §13.5 ruling 2,
/// §13.3): a same-key retry returns a fresh `decision_ref`, and approving that one
/// completes it. (A revoke that touches the waiting grant ends it:
/// `a07_revoking_an_awaiting_grant_ends_its_operation_at_once`.)
#[tokio::test]
async fn a07_a_pending_approval_cannot_complete_after_a_revoke() {
    let w = World::new().await;
    let base = w.ready("req-base", "work-base", &["h1"], None).await;
    let pending = w
        .ensure("req-ap", "work-ap", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(pending.code, Code::InteractionRequired);
    let dec = DecisionId::parse(pending.next.decision_ref.as_deref().unwrap()).unwrap();
    w.revoke(&base.grant_id, "req-rv2").await.unwrap();
    let stale = w
        .ops
        .decide(
            &attended(501),
            DecideRequest {
                decision_id: dec.clone(),
                verdict: Verdict::Approve,
            },
        )
        .await;
    scan(&stale);
    assert_eq!(code_of(&stale), Code::DecisionStale);
    assert_eq!(
        w.fake.effect_count(),
        1,
        "the stale approval applied nothing"
    );
    let replay = w
        .ensure("req-ap", "work-ap", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(replay.code, Code::InteractionRequired);
    assert_eq!(replay.operation_id, pending.operation_id, "same operation");
    let fresh = DecisionId::parse(replay.next.decision_ref.as_deref().unwrap()).unwrap();
    assert_ne!(fresh, dec, "a fresh decision record");
    let done = w
        .ops
        .decide(
            &attended(501),
            DecideRequest {
                decision_id: fresh,
                verdict: Verdict::Approve,
            },
        )
        .await;
    scan(&done);
    assert_eq!(code_of(&done), Code::Ok);
    let finished = w.ensure("req-ap", "work-ap", &["h1", "h3"], None).await;
    scan(&finished);
    assert_eq!(code_of(&finished), Code::AccessReady);
    assert_eq!(w.fake.effect_count(), 2);
}

#[tokio::test]
async fn a07_revoking_an_awaiting_grant_ends_its_operation_at_once() {
    let w = World::new().await;
    let pending = w
        .ensure("req-aw", "work-aw", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let op = pending.operation_id.clone().unwrap();
    let grant = w
        .store
        .transaction(|tx| tx.recovery_intent(&op))
        .unwrap()
        .unwrap()
        .resolved
        .unwrap()
        .grant
        .unwrap();
    w.revoke(&grant, "req-rv3").await.unwrap();
    assert_eq!(w.grant(&grant).state, GrantState::Denied);
    let rec = w
        .store
        .transaction(|tx| tx.operation(&op))
        .unwrap()
        .unwrap();
    assert_eq!(rec.state, heimdall_contract::OperationState::Failed);
}

/// What happens between reserve and publish.
#[derive(Debug, Clone, Copy)]
enum Between {
    Nothing,
    Revoke,
    Cutoff,
    PolicyRevision,
    BudgetExpiry,
    /// The wall clock passes the grant's absolute deadline while the continuous
    /// budget still has time left (gap G12).
    WallDeadline,
    TimeUncertain,
}

async fn reserve_then(between: Between) -> (World, GrantId, Result<(), OpError>) {
    let w = World::new().await;
    if matches!(between, Between::PolicyRevision) {
        // A cutoff far ahead, set before the grant (narrowing bumps the generation
        // now, not between reserve and publish).
        w.ops
            .policy(
                &owner(501),
                PolicyAction::Cutoff {
                    policy_id: policy_id(),
                    at: at(24 * 3600),
                },
            )
            .await
            .unwrap();
    }
    let until = match between {
        Between::BudgetExpiry => Some(DeadlineIntent::Duration("30s".into())),
        Between::WallDeadline => Some(DeadlineIntent::Duration("30m".into())),
        _ => None,
    };
    let g = w.ready("req-is", "work-is", &["h1"], until).await;
    let valid_before = match between {
        Between::BudgetExpiry => at(20),
        Between::WallDeadline => at(600),
        _ => at(1800),
    };
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, valid_before))
        .await
        .unwrap();
    assert_eq!(reserved.state, IssuanceState::Reserved);
    assert_eq!(
        residual(&w, &g.grant_id),
        Some(valid_before),
        "a reservation counts"
    );
    match between {
        Between::Nothing => {}
        Between::Revoke => {
            let r = w.revoke(&g.grant_id, "req-rv-is").await.unwrap();
            // A reservation is possibly issued: the revoke reports it.
            assert_eq!(r.data.latest_possible_credential_expiry, Some(valid_before));
        }
        Between::Cutoff => {
            w.ops
                .policy(
                    &owner(501),
                    PolicyAction::Cutoff {
                        policy_id: policy_id(),
                        at: w.clock.wall(),
                    },
                )
                .await
                .unwrap();
        }
        Between::PolicyRevision => {
            // A widening approved by the owner moves the revision and, since
            // ADR-0006 §13.6 item 5, the generation.
            let e = w
                .ops
                .policy(
                    &attended(501),
                    PolicyAction::ClearCutoff {
                        policy_id: policy_id(),
                    },
                )
                .await
                .unwrap_err();
            let dec = DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
            w.ops
                .decide(
                    &attended(501),
                    DecideRequest {
                        decision_id: dec,
                        verdict: Verdict::Approve,
                    },
                )
                .await
                .unwrap();
        }
        Between::BudgetExpiry => {
            // The wall clock stalls (within the skew tolerance) while the
            // continuous budget runs out.
            w.clock.advance_continuous_only(31 * Duration::from_secs(1));
        }
        Between::WallDeadline => {
            // Continuous time runs 29m59s, the wall shows 30m10s: 11 s of forward
            // skew (inside the 60 s tolerance), so time stays safe, the 30-minute
            // continuous budget is still open and only the wall deadline passed.
            w.clock
                .advance_continuous_only(30 * MINUTE - Duration::from_secs(1));
            w.clock.set_wall(at(30 * 60 + 10));
        }
        Between::TimeUncertain => {
            w.clock.set_wall(at(-600));
        }
    }
    let published = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .map(|_| ());
    (w, g.grant_id, published)
}

#[tokio::test]
async fn a07_publish_rechecks_every_predicate_and_voids_after_each_change() {
    // Control: nothing in between publishes and stays counted.
    let (w, g, r) = reserve_then(Between::Nothing).await;
    r.unwrap();
    assert_eq!(entry(&w, &g).state, IssuanceState::Published);
    assert_eq!(residual(&w, &g), Some(at(1800)));
    // ADR-0006 §13.6 item 5: a revision of an applicable policy moves the
    // generation too, so the reservation made before it is voided because reserve
    // and publish saw different generations. The chain re-validates against the
    // new revision, so since §13.6 item 11 the same call re-reserves and publishes.
    let (w, g, r) = reserve_then(Between::PolicyRevision).await;
    r.unwrap();
    let entries = w.store.transaction(|tx| tx.issuance_entries(&g)).unwrap();
    assert_eq!(entries.len(), 2);
    let voided: Vec<_> = entries
        .iter()
        .filter(|e| e.state == IssuanceState::Voided)
        .collect();
    assert_eq!(voided.len(), 1);
    assert_eq!(
        voided[0].void_reason,
        Some(IssuanceRefusal::StaleGeneration)
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.state == IssuanceState::Published)
            .count(),
        1
    );
    assert_eq!(residual(&w, &g), Some(at(1800)));
    for (between, expect) in [
        (
            Between::Revoke,
            IssuanceRefusal::GrantNotIssuable(GrantState::Revoked),
        ),
        // A cutoff is a policy change: the first failing predicate is the moved
        // revision (the cutoff itself would refuse next).
        (Between::Cutoff, IssuanceRefusal::StalePolicyRevision),
        (Between::BudgetExpiry, IssuanceRefusal::BudgetExpired),
        (Between::WallDeadline, IssuanceRefusal::BoundPassed),
        (Between::TimeUncertain, IssuanceRefusal::TimeUncertain),
    ] {
        let (w, g, r) = reserve_then(between).await;
        let e = r.unwrap_err();
        assert_no_canary(&e.message);
        let voided = entry(&w, &g);
        assert_eq!(voided.state, IssuanceState::Voided, "{between:?}");
        assert_eq!(voided.void_reason, Some(expect), "{between:?}");
        // Nothing was released: the residual counts nothing.
        assert_eq!(residual(&w, &g), None, "{between:?}");
    }
}

#[tokio::test]
async fn a07_reserve_refuses_on_the_same_predicates() {
    let w = World::new().await;
    let g = w.ready("req-rr", "work-rr", &["h1"], None).await;
    let mut wrong = issuance(&g.grant_id, at(600));
    wrong.principal = "hm:h1:root".into();
    assert_eq!(
        w.ops.reserve_issuance(wrong).await.unwrap_err().code,
        Code::CapabilityUnavailable
    );
    let too_late = issuance(&g.grant_id, at(3 * 3600));
    assert_eq!(
        w.ops.reserve_issuance(too_late).await.unwrap_err().code,
        Code::CapabilityUnavailable
    );
    let mut x11 = issuance(&g.grant_id, at(600));
    x11.extensions.insert("permit-X11-forwarding".into());
    assert_eq!(
        w.ops.reserve_issuance(x11).await.unwrap_err().code,
        Code::CapabilityUnavailable
    );
    w.clock.set_wall(at(-600));
    assert_eq!(
        w.ops
            .reserve_issuance(issuance(&g.grant_id, at(600)))
            .await
            .unwrap_err()
            .code,
        Code::TimeUncertain
    );
    w.clock.set_wall(t0());
    w.revoke(&g.grant_id, "req-rv-rr").await.unwrap();
    assert_eq!(
        w.ops
            .reserve_issuance(issuance(&g.grant_id, at(600)))
            .await
            .unwrap_err()
            .code,
        Code::CredentialExpired
    );
    // Nothing was ever reserved.
    assert!(
        w.store
            .transaction(|tx| tx.issuance_entries(&g.grant_id))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a07_a_reservation_found_after_a_restart_stays_counted_and_is_never_published() {
    let mut w = World::new().await;
    let g = w.ready("req-cr", "work-cr", &["h1"], None).await;
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1800)))
        .await
        .unwrap();
    w.restart().await;
    let e = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(entry(&w, &g.grant_id).state, IssuanceState::Reserved);
    assert_eq!(residual(&w, &g.grant_id), Some(at(1800)));
    // Recovery reserves afresh.
    let fresh = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1200)))
        .await
        .unwrap();
    w.ops.publish_issuance(&fresh.id, &facts()).await.unwrap();
    assert_eq!(residual(&w, &g.grant_id), Some(at(1800)));
}

#[tokio::test]
async fn a07_remote_pending_and_residual_are_reported_truthfully() {
    let w = World::new().await;
    let g = w.ready("req-rp", "work-rp", &["h1"], None).await;
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1500)))
        .await
        .unwrap();
    w.ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap();
    // The adapter cannot reach the remote side: revocation is local only.
    w.gated.revoke_fails.store(true, Ordering::SeqCst);
    let r = w.revoke(&g.grant_id, "req-rv-rp").await.unwrap();
    assert!(r.data.local_applied);
    assert_eq!(r.data.remote_pending, vec![g.grant_id.clone()]);
    assert_eq!(r.data.latest_possible_credential_expiry, Some(at(1500)));
    // Pending remote effects keep the grant in `revoking` with evidence.
    assert_eq!(w.grant(&g.grant_id).state, GrantState::Revoking);
    // A revoke replay returns the same truthful result.
    let replay = w.revoke(&g.grant_id, "req-rv-rp").await.unwrap();
    assert_eq!(replay.data, r.data);
}

// =================================================================================
// Sharing (spec §8.2)
// =================================================================================

#[tokio::test]
async fn equivalent_work_is_single_flight_with_separate_references() {
    let hook = Arc::new(CountCoalesce::default());
    let w = World::with_hook(hook.clone()).await;
    w.gated.hold_call.store(1, Ordering::SeqCst);
    let until = Some(DeadlineIntent::Absolute("2026-10-02T10:00:00Z".into()));
    let spawn = |rid: &'static str, work: &'static str| {
        let ops = w.ops.clone();
        let until = until.clone();
        tokio::spawn(async move {
            ops.ensure(
                &owner(501),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: [pair("h1", "deploy")].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse(work).unwrap(),
                    until,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                },
            )
            .await
        })
    };
    let leader = spawn("req-eq-1", "work-eq-1");
    w.gated.entered.notified().await;
    let follower = spawn("req-eq-2", "work-eq-2");
    // Wait until the follower entered `Coalesce` (it joins the leader's flight in
    // the same poll), then let the leader's prepare finish.
    while hook.entries.load(Ordering::SeqCst) < 2 {
        hook.changed.notified().await;
    }
    w.gated.release.add_permits(1);
    let a = leader.await.unwrap();
    let b = follower.await.unwrap();
    scan(&a);
    scan(&b);
    let (a, b) = (a.unwrap().data, b.unwrap().data);
    assert_eq!(w.fake.effect_count(), 1, "one preparation");
    assert_eq!(a.grant_id, b.grant_id, "equivalent work shares the grant");
    assert_ne!(a.binding_id, b.binding_id, "separate references");
    let refs = w
        .store
        .transaction(|tx| tx.grant_references(&a.grant_id))
        .unwrap();
    assert_eq!(refs.len(), 2);
    // Releasing one reference keeps the shared grant for the other.
    w.ops
        .release(
            &owner(501),
            ReleaseRequest {
                binding_id: a.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(w.grant(&a.grant_id).state, GrantState::Active);
    w.ops
        .release(
            &owner(501),
            ReleaseRequest {
                binding_id: b.binding_id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(w.grant(&a.grant_id).state, GrantState::Released);
}

// =================================================================================
// Properties
// =================================================================================

fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
    f: F,
) -> Result<(), TestCaseError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f)
}

fn prop_config(seed: u64) -> ProptestConfig {
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

/// #3 steps.
#[derive(Debug, Clone)]
enum Narrow {
    RevokeBase,
    Pause,
    CutoffNow,
    NewWork,
    Approve,
    BindBase,
    Advance(u8),
}

fn narrow() -> impl Strategy<Value = Narrow> {
    prop_oneof![
        1 => Just(Narrow::RevokeBase),
        1 => Just(Narrow::Pause),
        1 => Just(Narrow::CutoffNow),
        3 => Just(Narrow::NewWork),
        2 => Just(Narrow::Approve),
        2 => Just(Narrow::BindBase),
        1 => (1u8..20).prop_map(Narrow::Advance),
    ]
}

proptest! {
    #![proptest_config(prop_config(0x5535_5452_4f4d_4233))]

    /// Plan §6.3 #3: a tombstone or a hard stop (pause, cutoff) is never defeated
    /// by a stale callback (approval of an older decision, a late bind of a revoked
    /// binding) or by a new request ID.
    #[test]
    fn tombstones_and_cutoffs_are_never_defeated_by_stale_callbacks_or_new_ids(
        steps in prop::collection::vec(narrow(), 1..12)
    ) {
        block(async move {
            let w = World::new().await;
            let base = w.ready("req-base", "work-base", &["h1"], Some(DeadlineIntent::Duration("2h".into()))).await;
            let pending = w.ensure("req-ap", "work-ap", &["h1", "h3"], None).await.unwrap_err();
            prop_assert_eq!(&pending.code, &Code::InteractionRequired);
            let dec = DecisionId::parse(pending.next.decision_ref.as_deref().unwrap()).unwrap();
            let issued = w.clock.wall();
            let (mut revoked, mut paused, mut cut, mut moved, mut decided) = (false, false, false, false, false);
            let mut n = 0u32;
            for s in steps {
                n += 1;
                match s {
                    Narrow::RevokeBase => {
                        w.revoke(&base.grant_id, &format!("req-rv-{n}")).await.unwrap();
                        revoked = true;
                        moved = true;
                    }
                    Narrow::Pause => {
                        w.ops.policy(&owner(501), PolicyAction::Pause { policy_id: policy_id() }).await.unwrap();
                        paused = true;
                        moved = true;
                    }
                    Narrow::CutoffNow => {
                        let now = w.clock.wall();
                        let r = w.ops.policy(&owner(501), PolicyAction::Cutoff { policy_id: policy_id(), at: now }).await;
                        // An earlier cutoff narrows; a later one would be a decision.
                        if r.is_ok() {
                            cut = true;
                            moved = true;
                        }
                    }
                    Narrow::NewWork => {
                        let r = w.ensure(&format!("req-new-{n}"), &format!("work-new-{n}"), &["h1"], None).await;
                        let c = code_of(&r);
                        if paused {
                            prop_assert_eq!(c, Code::PolicyPaused);
                        } else if cut {
                            prop_assert_eq!(c, Code::PolicyCutoff);
                        } else {
                            prop_assert_eq!(c, Code::AccessReady);
                        }
                    }
                    Narrow::Approve => {
                        let r = w.ops.decide(&attended(501), DecideRequest { decision_id: dec.clone(), verdict: Verdict::Approve }).await;
                        scan(&r);
                        // Stale after a narrowing, after consumption, or once the
                        // 15-minute lifetime has passed.
                        let expired = w.clock.wall() >= issued.checked_add(jiff::SignedDuration::from_mins(15)).unwrap();
                        if moved || decided || expired {
                            prop_assert_eq!(code_of(&r), Code::DecisionStale);
                        } else {
                            prop_assert_eq!(code_of(&r), Code::Ok);
                            decided = true;
                        }
                    }
                    Narrow::BindBase => {
                        let r = w.bind(&base.binding_id, &format!("req-bind-{n}")).await;
                        scan(&r);
                        let c = code_of(&r);
                        if revoked {
                            prop_assert!(c != Code::AccessReady, "a revoked binding never binds");
                        } else if cut || w.clock.wall() >= base.expires_at {
                            // ADR-0006 §13.6 item 1: existing use past min(deadline, cutoff).
                            prop_assert_eq!(c, Code::CredentialExpired);
                        } else {
                            // A pause never stops an existing binding before its deadline.
                            prop_assert_eq!(c, Code::AccessReady, "paused={}", paused);
                        }
                    }
                    Narrow::Advance(m) => {
                        w.clock.advance(u32::from(m) * MINUTE);
                        w.ops.tick().await.unwrap();
                    }
                }
                if revoked {
                    prop_assert!(!w.grant(&base.grant_id).state.permits_use(), "the tombstoned grant never returns");
                }
            }
            Ok(())
        })?;
    }
}

/// #5 steps.
#[derive(Debug, Clone)]
enum Life {
    Ensure(u8),
    Advance(u8),
    Tick,
    Revoke(u8),
    Release(u8),
    Bind(u8),
    Restart,
}

fn life() -> impl Strategy<Value = Life> {
    prop_oneof![
        3 => (0u8..3).prop_map(Life::Ensure),
        2 => (1u8..90).prop_map(Life::Advance),
        1 => Just(Life::Tick),
        1 => (0u8..8).prop_map(Life::Revoke),
        1 => (0u8..8).prop_map(Life::Release),
        1 => (0u8..8).prop_map(Life::Bind),
        1 => Just(Life::Restart),
    ]
}

proptest! {
    #![proptest_config(prop_config(0x5535_4c49_4645_4335))]

    /// Plan §6.3 #5: expired, revoked or released grants never return to active,
    /// and a restart never resets a deadline (deadlines are immutable and every
    /// grant past it is expired after the next tick, restart or not).
    #[test]
    fn ended_grants_never_return_and_restart_never_resets_the_clock(
        steps in prop::collection::vec(life(), 1..16)
    ) {
        block(async move {
            let mut w = World::new().await;
            let mut grants: Vec<(GrantId, BindingId, Timestamp)> = Vec::new();
            let mut ended: BTreeSet<GrantId> = BTreeSet::new();
            let mut n = 0u32;
            for s in steps {
                n += 1;
                match s {
                    Life::Ensure(u) => {
                        let until = ["10m", "30m", "1h"][usize::from(u)];
                        let r = w.ensure(&format!("req-{n}"), &format!("work-{n}"), &["h1"], Some(DeadlineIntent::Duration(until.into()))).await;
                        if let Ok(c) = r {
                            let d = c.data;
                            grants.push((d.grant_id, d.binding_id, d.expires_at));
                        }
                    }
                    Life::Advance(m) => w.clock.advance(u32::from(m) * MINUTE),
                    Life::Tick => w.ops.tick().await.unwrap(),
                    Life::Revoke(i) => {
                        if let Some((g, _, _)) = grants.get(usize::from(i)) {
                            let _ = w.revoke(g, &format!("req-rv-{n}")).await;
                        }
                    }
                    Life::Release(i) => {
                        if let Some((_, b, _)) = grants.get(usize::from(i)) {
                            let _ = w.ops.release(&owner(501), ReleaseRequest { binding_id: b.clone() }).await;
                        }
                    }
                    Life::Bind(i) => {
                        if let Some((g, b, _)) = grants.get(usize::from(i)) {
                            let r = w.bind(b, &format!("req-bind-{n}")).await;
                            if ended.contains(g) {
                                prop_assert!(code_of(&r) != Code::AccessReady, "an ended grant never binds");
                            }
                        }
                    }
                    Life::Restart => {
                        w.restart().await;
                        w.ops.tick().await.unwrap();
                    }
                }
                let now = w.clock.wall();
                for (g, _, deadline) in &grants {
                    let snap = w.grant(g);
                    // Immutable deadline: nothing, restart included, moves it.
                    prop_assert_eq!(snap.deadline.effective, *deadline);
                    if ended.contains(g) {
                        prop_assert!(snap.state.is_terminal() || snap.state == GrantState::Revoking);
                        prop_assert!(!snap.state.permits_use());
                    }
                    if snap.state.is_terminal() || snap.state == GrantState::Revoking {
                        ended.insert(g.clone());
                    }
                    if matches!(s, Life::Tick | Life::Restart) && now >= *deadline {
                        prop_assert!(!snap.state.permits_use(), "past its deadline after a tick");
                    }
                }
            }
            Ok(())
        })?;
    }
}

/// #8 inputs: one request.
#[derive(Debug, Clone)]
struct Share {
    hosts: u8,
    until: u8,
}

fn share() -> impl Strategy<Value = Share> {
    (1u8..4, 0u8..2).prop_map(|(hosts, until)| Share { hosts, until })
}

fn hosts_of(mask: u8) -> Vec<&'static str> {
    let mut v = Vec::new();
    if mask & 1 != 0 {
        v.push("h1");
    }
    if mask & 2 != 0 {
        v.push("h2");
    }
    v
}

proptest! {
    #![proptest_config(prop_config(0x5535_5348_4152_4538))]

    /// Plan §6.3 #8: concurrent equivalent and unrelated requests: bindings share a
    /// grant only for identical scope and deadline; no reference keeps a grant
    /// usable past its deadline.
    #[test]
    fn sharing_never_merges_unrelated_scopes_or_outlives_the_deadline(
        reqs in prop::collection::vec(share(), 2..6),
        releases in prop::collection::vec(any::<bool>(), 6),
    ) {
        block(async move {
            let w = World::new().await;
            let mut handles = Vec::new();
            for (i, r) in reqs.iter().enumerate() {
                let ops = w.ops.clone();
                let until = ["2026-10-02T09:30:00Z", "2026-10-02T10:00:00Z"][usize::from(r.until)];
                let req = EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: hosts_of(r.hosts).into_iter().map(|h| pair(h, "deploy")).collect(),
                    environment: None,
                    work_id: WorkId::parse(&format!("work-{i}")).unwrap(),
                    until: Some(DeadlineIntent::Absolute(until.into())),
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(&format!("req-{i}")).unwrap(),
                    interaction: InteractionMode::NonInteractive,
                    wait: WaitMode::default(),
                };
                handles.push(tokio::spawn(async move { ops.ensure(&owner(501), req).await }));
            }
            let mut by_grant: BTreeMap<GrantId, Vec<(Scope, EnsureData)>> = BTreeMap::new();
            for h in handles {
                let r = h.await.unwrap();
                scan(&r);
                let d = r.unwrap().data;
                let b = w.store.transaction(|tx| tx.binding(&d.binding_id)).unwrap().unwrap();
                by_grant.entry(d.grant_id.clone()).or_default().push((b.scope, d));
            }
            for (g, members) in &by_grant {
                let grant = w.grant(g);
                for (scope, data) in members {
                    prop_assert_eq!(scope, &grant.scope, "a shared grant carries exactly each member's scope");
                    prop_assert_eq!(data.expires_at, grant.deadline.effective);
                }
            }
            let distinct: BTreeSet<(Vec<AccessPair>, Timestamp)> = by_grant
                .values()
                .map(|m| (m[0].0.pairs.iter().cloned().collect(), m[0].1.expires_at))
                .collect();
            prop_assert_eq!(distinct.len(), by_grant.len(), "unrelated scopes or deadlines never share a grant");
            let effects = w.fake.effect_count();
            prop_assert!(effects >= by_grant.len());
            // Release some references, then pass every deadline.
            let all: Vec<EnsureData> = by_grant.values().flatten().map(|(_, d)| d.clone()).collect();
            for (d, release) in all.iter().zip(releases.iter().cycle()) {
                if *release {
                    w.ops.release(&owner(501), ReleaseRequest { binding_id: d.binding_id.clone() }).await.unwrap();
                }
            }
            w.clock.advance(61 * MINUTE);
            w.ops.tick().await.unwrap();
            for g in by_grant.keys() {
                let snap = w.grant(g);
                prop_assert!(!snap.state.permits_use(), "references never retain a grant past its deadline");
            }
            Ok(())
        })?;
    }
}

/// Gap G07 (ADR-0006 §13.5 ruling 3): the permitted extensions come from the
/// grant's resolved scope, never from the request. An extension the snapshot does
/// not permit is refused at reserve whatever the caller sends; one it permits
/// (`permit-pty` for an ordinary pair) is reserved and published; and
/// `permit-agent-forwarding` needs the `agent-forwarding` capability, which this
/// grant does not have.
#[tokio::test]
async fn a07_permitted_extensions_come_from_the_grant_snapshot_not_the_caller() {
    let w = World::new().await;
    let g = w.ready("req-px", "work-px", &["h1"], None).await;
    let grant = w.grant(&g.grant_id);
    assert_eq!(
        heimdall_app::operations::permitted_extensions(&grant, &pair("h1", "deploy")),
        ["permit-pty".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert!(
        heimdall_app::operations::permitted_extensions(&grant, &pair("h9", "deploy")).is_empty(),
        "a pair outside the snapshot permits nothing"
    );
    for outside in [
        "permit-port-forwarding",
        "permit-agent-forwarding",
        "permit-user-rc",
    ] {
        let mut req = issuance(&g.grant_id, at(600));
        req.extensions.insert(outside.into());
        let e = w.ops.reserve_issuance(req).await.unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{outside}");
        assert_no_canary(&e.message);
    }
    assert!(
        w.store
            .transaction(|tx| tx.issuance_entries(&g.grant_id))
            .unwrap()
            .is_empty(),
        "nothing outside the snapshot was ever reserved"
    );
    let mut pty = issuance(&g.grant_id, at(600));
    pty.extensions.insert("permit-pty".into());
    let reserved = w.ops.reserve_issuance(pty).await.unwrap();
    let published = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap();
    assert_eq!(published.state, IssuanceState::Published);
    assert_eq!(
        published.bounds.extensions,
        ["permit-pty".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

// =================================================================================
// Code-review fixes (tests/evidence/artifacts/review-m01-code/area-a.md: A01–A04,
// A06, A07; ADR-0006 §13.6 item 11). Every case below was first run against the
// base commit and failed there (red); it passes with the fix. Faults are injected
// only through production hooks: the store `FaultHook`, the pipeline `StageHook`,
// the limits and the fake adapter's script and declared enforcement.
// =================================================================================

fn rq(rid: &str, work: &str, hosts: &[&str], until: Option<&str>) -> EnsureRequest {
    EnsureRequest {
        profile: ProfileId::parse("dev").unwrap(),
        profile_revision: None,
        scope: hosts.iter().map(|h| pair(h, "deploy")).collect(),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until: until.map(|u| DeadlineIntent::Duration(u.into())),
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(rid).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::default(),
    }
}

async fn ensure_as(w: &World, caller: &Caller, r: EnsureRequest) -> OpResult<EnsureData> {
    let out = w.ops.ensure(caller, r).await;
    scan(&out);
    out
}

async fn decide_as(w: &World, d: &DecisionId, verdict: Verdict) -> OpResult<serde_json::Value> {
    let r = w
        .ops
        .decide(
            &attended(501),
            DecideRequest {
                decision_id: d.clone(),
                verdict,
            },
        )
        .await;
    scan(&r);
    r
}

fn dec_of(e: &OpError) -> DecisionId {
    DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
}

fn op_of(w: &World, id: &OperationId) -> heimdall_domain::operation::OperationRecord {
    w.store.transaction(|tx| tx.operation(id)).unwrap().unwrap()
}

fn grant_of_op(w: &World, id: &OperationId) -> GrantId {
    w.store
        .transaction(|tx| tx.recovery_intent(id))
        .unwrap()
        .unwrap()
        .resolved
        .unwrap()
        .grant
        .unwrap()
}

fn attempts_of(w: &World, id: &OperationId) -> usize {
    w.store
        .transaction(|tx| tx.stage_receipts(id))
        .unwrap()
        .iter()
        .filter(|r| matches!(r.effect, EffectReceipt::Attempted { .. }))
        .count()
}

fn generation(w: &World) -> AuthorityGeneration {
    w.store.transaction(|tx| tx.authority_generation()).unwrap()
}

fn entries_of(w: &World, g: &GrantId) -> Vec<heimdall_domain::issuance::IssuanceEntry> {
    w.store.transaction(|tx| tx.issuance_entries(g)).unwrap()
}

fn delta_of(w: &World, d: &DecisionId) -> AuthorityDelta {
    match w
        .store
        .transaction(|tx| tx.decision(d))
        .unwrap()
        .unwrap()
        .kind
    {
        DecisionKind::ApproveAuthority { delta, .. } => delta,
        other => panic!("not an approval record: {other:?}"),
    }
}

fn pending_approvals(w: &World) -> Vec<DecisionRecord> {
    w.store
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .into_iter()
        .filter(|d| matches!(d.kind, DecisionKind::ApproveAuthority { .. }))
        .collect()
}

fn hosts(names: &[&str]) -> BTreeSet<AccessPair> {
    names.iter().map(|h| pair(h, "deploy")).collect()
}

/// Replace the standing policy's pairs at its next revision (a setup-level
/// write; it moves the authority generation, ADR-0006 §13.6 item 5).
fn set_policy_hosts(store: &Store, names: &[&str]) {
    store
        .transaction(|tx| {
            let mut p = tx.policy(&policy_id())?.expect("policy");
            p.scope.pairs = hosts(names);
            p.revision = PolicyRevision(p.revision.0 + 1);
            tx.upsert_policy(&p, true).map(|_| ())
        })
        .unwrap();
}

/// Turn the environment's automatic activation on or off (no generation move).
fn set_automatic_activation(store: &Store, on: bool) {
    store
        .transaction(|tx| {
            let mut e = tx.environment(&env_id())?.expect("environment");
            e.permissions.automatic_activation = on;
            tx.upsert_environment(&e)
        })
        .unwrap();
}

/// A policy for another profile: writing it moves the global authority
/// generation and touches nothing the grants of this suite rest on.
fn bump_unrelated(store: &Store, revision: u64) {
    store
        .transaction(|tx| {
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("pol-other").unwrap(),
                    revision: PolicyRevision(revision),
                    profile: ProfileId::parse("other").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: hosts(&["h9"]),
                        capabilities: ssh(),
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

type Probe = Box<dyn Fn(&mut Txn<'_>) -> heimdall_store::Result<bool> + Send + Sync>;
type ClockAct = Box<dyn Fn(&VirtualClock) + Send + Sync>;

/// Store fault hook (production `FaultHook`). Once armed, right before the k-th
/// store transaction begins (`BeforeTransaction`, where the store lock is not
/// held) it runs `probe` in a nested transaction ("had the operation under test
/// already decided?") and then changes the clock. The expectation therefore
/// depends only on whether the change landed before the decision, never on how
/// many transactions an implementation runs.
#[derive(Default)]
struct ClockAt {
    store: OnceLock<Weak<Store>>,
    clock: OnceLock<Arc<VirtualClock>>,
    plan: std::sync::Mutex<Option<(usize, ClockAct, Probe)>>,
    seen: AtomicUsize,
    nested: AtomicBool,
    fired: std::sync::Mutex<Option<bool>>,
}

impl ClockAt {
    fn bind(&self, w: &World) {
        let _ = self.store.set(Arc::downgrade(&w.store));
        let _ = self.clock.set(w.clock.clone());
    }

    fn arm(&self, k: usize, act: ClockAct, probe: Probe) {
        self.seen.store(0, Ordering::SeqCst);
        *self.fired.lock().unwrap() = None;
        *self.plan.lock().unwrap() = Some((k, act, probe));
    }

    /// `None`: the call ran fewer than k transactions; `Some(decided_before)`.
    fn fired(&self) -> Option<bool> {
        *self.fired.lock().unwrap()
    }
}

impl FaultHook for ClockAt {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point != FaultPoint::BeforeTransaction || self.nested.load(Ordering::SeqCst) {
            return FaultAction::Continue;
        }
        let mut plan = self.plan.lock().unwrap();
        let Some((k, _, _)) = plan.as_ref() else {
            return FaultAction::Continue;
        };
        let n = self.seen.fetch_add(1, Ordering::SeqCst) + 1;
        if n != *k {
            return FaultAction::Continue;
        }
        let (_, act, probe) = plan.take().unwrap();
        drop(plan);
        self.nested.store(true, Ordering::SeqCst);
        let decided = self
            .store
            .get()
            .and_then(Weak::upgrade)
            .map(|s| s.transaction(|tx| probe(tx)).unwrap())
            .unwrap_or(false);
        self.nested.store(false, Ordering::SeqCst);
        act(self.clock.get().unwrap());
        *self.fired.lock().unwrap() = Some(decided);
        FaultAction::Continue
    }
}

/// Store fault hook that moves the global authority generation (an unrelated
/// policy write in a nested transaction) right before each of the next `n` store
/// transactions.
#[derive(Default)]
struct Bumper {
    store: OnceLock<Weak<Store>>,
    remaining: std::sync::Mutex<usize>,
    nested: AtomicBool,
    revision: AtomicU64,
}

impl Bumper {
    fn bind(&self, w: &World) {
        let _ = self.store.set(Arc::downgrade(&w.store));
    }

    fn arm(&self, n: usize) {
        *self.remaining.lock().unwrap() = n;
    }
}

impl FaultHook for Bumper {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point != FaultPoint::BeforeTransaction || self.nested.load(Ordering::SeqCst) {
            return FaultAction::Continue;
        }
        {
            let mut left = self.remaining.lock().unwrap();
            if *left == 0 {
                return FaultAction::Continue;
            }
            *left -= 1;
        }
        self.nested.store(true, Ordering::SeqCst);
        let revision = self.revision.fetch_add(1, Ordering::SeqCst) + 1_000_000;
        if let Some(s) = self.store.get().and_then(Weak::upgrade) {
            bump_unrelated(&s, revision);
        }
        self.nested.store(false, Ordering::SeqCst);
        FaultAction::Continue
    }
}

type StageAct = Box<dyn FnOnce() + Send>;

/// Pipeline hook (production `StageHook`): runs one armed action before or after a
/// stage, and counts `Reconcile` entries.
#[derive(Default)]
struct AtStage {
    on: std::sync::Mutex<Option<(EnsureStage, bool, StageAct)>>,
    reconcile_entries: AtomicUsize,
    changed: Notify,
}

impl AtStage {
    fn arm(&self, stage: EnsureStage, after: bool, act: StageAct) {
        *self.on.lock().unwrap() = Some((stage, after, act));
    }

    fn fire(&self, stage: EnsureStage, after: bool) {
        let mut on = self.on.lock().unwrap();
        if matches!(on.as_ref(), Some((s, a, _)) if *s == stage && *a == after) {
            let (_, _, act) = on.take().unwrap();
            drop(on);
            act();
        }
    }
}

impl StageHook for AtStage {
    fn before(&self, stage: EnsureStage) -> Result<(), Code> {
        if stage == EnsureStage::Reconcile {
            self.reconcile_entries.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_one();
        }
        self.fire(stage, false);
        Ok(())
    }
    fn after(&self, stage: EnsureStage) -> Result<(), Code> {
        self.fire(stage, true);
        Ok(())
    }
}

/// A clock change at a transaction boundary.
#[derive(Debug, Clone, Copy)]
enum Shift {
    /// Wall and continuous run 3 h on: safe time, past every grant here.
    Expire,
    /// The wall clock steps back 2 minutes, continuous unchanged: `TIME_UNCERTAIN`.
    RollBack,
}

fn shift_act(s: Shift) -> ClockAct {
    match s {
        Shift::Expire => Box::new(|c: &VirtualClock| c.advance(3 * HOUR)),
        Shift::RollBack => Box::new(|c: &VirtualClock| {
            c.set_wall(
                c.wall()
                    .checked_sub(jiff::SignedDuration::from_mins(2))
                    .unwrap(),
            );
        }),
    }
}

/// A01: publication assesses the time gate and the continuous admission from a
/// fresh observation **inside** the transaction that publishes. The clock changes
/// right before the k-th store transaction of the publish call, for every k the
/// call performs; whenever the change lands before the entry was settled, the
/// entry is voided and nothing is released.
#[tokio::test]
async fn review_a01_publish_assesses_time_inside_its_own_transaction() {
    let mut exercised = 0;
    for shift in [Shift::Expire, Shift::RollBack] {
        for k in 1..=12 {
            let hook = Arc::new(ClockAt::default());
            let w = World::with_opts(Opts {
                faults: hook.clone(),
                ..Opts::default()
            })
            .await;
            hook.bind(&w);
            let g = w
                .ready(
                    "req-a01",
                    "work-a01",
                    &["h1"],
                    Some(DeadlineIntent::Duration("2h".into())),
                )
                .await;
            let reserved = w
                .ops
                .reserve_issuance(issuance(&g.grant_id, at(1800)))
                .await
                .unwrap();
            let (gid, rid) = (g.grant_id.clone(), reserved.id.clone());
            hook.arm(
                k,
                shift_act(shift),
                Box::new(move |tx| {
                    Ok(tx
                        .issuance_entries(&gid)?
                        .iter()
                        .any(|e| e.id == rid && e.state != IssuanceState::Reserved))
                }),
            );
            let r = w.ops.publish_issuance(&reserved.id, &facts()).await;
            let fired = hook.fired();
            let settled = entries_of(&w, &g.grant_id)
                .into_iter()
                .find(|e| e.id == reserved.id)
                .unwrap();
            match fired {
                None | Some(true) => {
                    // No change before the publish decided: it publishes.
                    r.unwrap_or_else(|e| panic!("{shift:?} k={k}: {} {}", e.code, e.message));
                    assert_eq!(settled.state, IssuanceState::Published, "{shift:?} k={k}");
                }
                Some(false) => {
                    exercised += 1;
                    let e = r.expect_err(&format!(
                        "{shift:?} before transaction {k} must void the publication"
                    ));
                    assert_no_canary(&e.message);
                    assert_eq!(settled.state, IssuanceState::Voided, "{shift:?} k={k}");
                    let (code, reasons): (Code, &[IssuanceRefusal]) = match shift {
                        Shift::Expire => (
                            Code::CredentialExpired,
                            &[IssuanceRefusal::BoundPassed, IssuanceRefusal::BudgetExpired],
                        ),
                        Shift::RollBack => (Code::TimeUncertain, &[IssuanceRefusal::TimeUncertain]),
                    };
                    assert_eq!(e.code, code, "{shift:?} k={k}");
                    assert!(
                        reasons.contains(settled.void_reason.as_ref().unwrap()),
                        "{shift:?} k={k}: {:?}",
                        settled.void_reason
                    );
                    assert_eq!(residual(&w, &g.grant_id), None, "nothing released");
                }
            }
            if fired.is_none() {
                break;
            }
        }
    }
    assert!(
        exercised > 0,
        "the clock change landed before the decision at least once"
    );
}

/// A01: reservation likewise assesses time inside the transaction that reserves.
#[tokio::test]
async fn review_a01_reserve_assesses_time_inside_its_own_transaction() {
    let mut exercised = 0;
    for shift in [Shift::Expire, Shift::RollBack] {
        for k in 1..=12 {
            let hook = Arc::new(ClockAt::default());
            let w = World::with_opts(Opts {
                faults: hook.clone(),
                ..Opts::default()
            })
            .await;
            hook.bind(&w);
            let g = w
                .ready(
                    "req-a01r",
                    "work-a01r",
                    &["h1"],
                    Some(DeadlineIntent::Duration("2h".into())),
                )
                .await;
            let gid = g.grant_id.clone();
            hook.arm(
                k,
                shift_act(shift),
                Box::new(move |tx| Ok(!tx.issuance_entries(&gid)?.is_empty())),
            );
            let r = w
                .ops
                .reserve_issuance(issuance(&g.grant_id, at(1800)))
                .await;
            let fired = hook.fired();
            match fired {
                None | Some(true) => {
                    let e =
                        r.unwrap_or_else(|e| panic!("{shift:?} k={k}: {} {}", e.code, e.message));
                    assert_eq!(e.state, IssuanceState::Reserved);
                }
                Some(false) => {
                    exercised += 1;
                    let e = r.expect_err(&format!(
                        "{shift:?} before transaction {k} must refuse the reservation"
                    ));
                    let code = match shift {
                        Shift::Expire => Code::CredentialExpired,
                        Shift::RollBack => Code::TimeUncertain,
                    };
                    assert_eq!(e.code, code, "{shift:?} k={k}");
                    assert!(entries_of(&w, &g.grant_id).is_empty(), "nothing reserved");
                }
            }
            if fired.is_none() {
                break;
            }
        }
    }
    assert!(
        exercised > 0,
        "the clock change landed before the decision at least once"
    );
}

/// A02: `Commit` re-assesses time with the gate (not only the continuous
/// admission): a wall clock stepped back between `Recheck` and `Commit` is
/// `TIME_UNCERTAIN` and nothing activates; once time is safe again the same key
/// resumes and activates.
#[tokio::test]
async fn review_a02_commit_reassesses_time_with_the_gate() {
    let hook = Arc::new(AtStage::default());
    let w = World::with_opts(Opts {
        hook: hook.clone(),
        ..Opts::default()
    })
    .await;
    let clock = w.clock.clone();
    hook.arm(
        EnsureStage::Recheck,
        true,
        Box::new(move || clock.set_wall(at(-120))),
    );
    let r = ensure_as(
        &w,
        &owner(501),
        rq("req-a02", "work-a02", &["h1"], Some("2h")),
    )
    .await;
    let e = r.expect_err("a commit under TIME_UNCERTAIN must not activate");
    assert_eq!(e.code, Code::TimeUncertain);
    assert_eq!(
        e.effect_status,
        heimdall_contract::envelope::EffectStatus::Partial
    );
    let op = e.operation_id.clone().unwrap();
    assert_eq!(
        op_of(&w, &op).state,
        heimdall_contract::OperationState::Running
    );
    assert_eq!(w.grant(&grant_of_op(&w, &op)).state, GrantState::Preparing);
    assert!(
        w.store
            .transaction(|tx| tx.bindings_for_work(&env_id(), &WorkId::parse("work-a02").unwrap()))
            .unwrap()
            .is_empty()
    );
    // The wall clock is back on its prediction: the same key resumes and activates.
    w.clock.set_wall(t0());
    let ready = ensure_as(
        &w,
        &owner(501),
        rq("req-a02", "work-a02", &["h1"], Some("2h")),
    )
    .await
    .unwrap();
    assert_eq!(ready.code, Code::AccessReady);
    assert_eq!(ready.operation_id, Some(op));
    assert_eq!(w.fake.effect_count(), 1);
}

fn succeeded(tx: &mut Txn<'_>) -> heimdall_store::Result<u64> {
    Ok(tx
        .operation_counts()?
        .into_iter()
        .find(|(s, _)| *s == heimdall_contract::OperationState::Succeeded)
        .map_or(0, |(_, n)| n))
}

/// A02 (binding): the transaction that admits a binding re-assesses time.
#[tokio::test]
async fn review_a02_bind_reassesses_time_in_the_admitting_transaction() {
    let mut exercised = 0;
    for k in 1..=16 {
        let hook = Arc::new(ClockAt::default());
        let w = World::with_opts(Opts {
            faults: hook.clone(),
            ..Opts::default()
        })
        .await;
        hook.bind(&w);
        let g = w
            .ready(
                "req-a02b",
                "work-a02b",
                &["h1"],
                Some(DeadlineIntent::Duration("2h".into())),
            )
            .await;
        let before = w.store.transaction(succeeded).unwrap();
        hook.arm(
            k,
            shift_act(Shift::RollBack),
            Box::new(move |tx| Ok(succeeded(tx)? > before)),
        );
        let r = w.bind(&g.binding_id, "req-a02b-bind").await;
        let fired = hook.fired();
        match fired {
            None | Some(true) => assert_eq!(code_of(&r), Code::AccessReady, "k={k}"),
            Some(false) => {
                exercised += 1;
                assert_eq!(
                    code_of(&r),
                    Code::TimeUncertain,
                    "a rollback before transaction {k} must stop the binding"
                );
            }
        }
        if fired.is_none() {
            break;
        }
    }
    assert!(
        exercised > 0,
        "the clock change landed before the decision at least once"
    );
}

/// A02 (decisions): approving re-assesses time in the deciding transaction.
#[tokio::test]
async fn review_a02_an_approval_reassesses_time_in_the_deciding_transaction() {
    let mut exercised = 0;
    for k in 1..=12 {
        let hook = Arc::new(ClockAt::default());
        let w = World::with_opts(Opts {
            faults: hook.clone(),
            ..Opts::default()
        })
        .await;
        hook.bind(&w);
        let pending = w
            .ensure("req-a02d", "work-a02d", &["h1", "h3"], None)
            .await
            .unwrap_err();
        let dec = dec_of(&pending);
        let d2 = dec.clone();
        hook.arm(
            k,
            shift_act(Shift::RollBack),
            Box::new(move |tx| {
                Ok(tx
                    .decision(&d2)?
                    .is_some_and(|d| d.state != DecisionState::Pending))
            }),
        );
        let r = decide_as(&w, &dec, Verdict::Approve).await;
        let fired = hook.fired();
        match fired {
            None | Some(true) => assert_eq!(code_of(&r), Code::Ok, "k={k}"),
            Some(false) => {
                exercised += 1;
                assert_eq!(code_of(&r), Code::TimeUncertain, "k={k}");
                let d = w
                    .store
                    .transaction(|tx| tx.decision(&dec))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    d.state,
                    DecisionState::Pending,
                    "nothing consumed under uncertain time"
                );
                assert_eq!(w.fake.effect_count(), 0);
            }
        }
        if fired.is_none() {
            break;
        }
    }
    assert!(
        exercised > 0,
        "the clock change landed before the decision at least once"
    );
}

/// A02 (decisions): a widening decision record is created only on time assessed
/// safe in its own transaction.
#[tokio::test]
async fn review_a02_a_widening_record_reassesses_time_in_its_transaction() {
    let mut exercised = 0;
    for k in 1..=12 {
        let hook = Arc::new(ClockAt::default());
        let w = World::with_opts(Opts {
            faults: hook.clone(),
            ..Opts::default()
        })
        .await;
        hook.bind(&w);
        w.ops
            .policy(
                &owner(501),
                PolicyAction::Pause {
                    policy_id: policy_id(),
                },
            )
            .await
            .unwrap();
        let widening = |tx: &mut Txn<'_>| -> heimdall_store::Result<bool> {
            Ok(tx
                .pending_decisions()?
                .iter()
                .any(|d| matches!(d.kind, DecisionKind::WidenPolicy { .. })))
        };
        hook.arm(k, shift_act(Shift::RollBack), Box::new(widening));
        let r = w
            .ops
            .policy(
                &attended(501),
                PolicyAction::Resume {
                    policy_id: policy_id(),
                },
            )
            .await;
        scan(&r);
        let fired = hook.fired();
        match fired {
            None | Some(true) => assert_eq!(code_of(&r), Code::ApprovalRequired, "k={k}"),
            Some(false) => {
                exercised += 1;
                assert_eq!(code_of(&r), Code::TimeUncertain, "k={k}");
                assert!(
                    !w.store.transaction(|tx| widening(tx)).unwrap(),
                    "no record"
                );
            }
        }
        if fired.is_none() {
            break;
        }
    }
    assert!(
        exercised > 0,
        "the clock change landed before the decision at least once"
    );
}

/// A03: the transaction authorizing the `Attempted` receipt validates current
/// authority, deadline and cutoff: no preparation once the grant's bound passed or
/// a cutoff took effect, even though nothing (no `tick`) moved the grant.
#[tokio::test]
async fn review_a03_no_preparation_after_the_deadline_or_a_cutoff() {
    // The deadline passes between resolution and `Reconcile`.
    let hook = Arc::new(AtStage::default());
    let w = World::with_opts(Opts {
        hook: hook.clone(),
        ..Opts::default()
    })
    .await;
    let clock = w.clock.clone();
    hook.arm(
        EnsureStage::Reconcile,
        false,
        Box::new(move || clock.advance(3 * HOUR)),
    );
    let e = ensure_as(
        &w,
        &owner(501),
        rq("req-a03", "work-a03", &["h1"], Some("2h")),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(
        w.fake.effect_count(),
        0,
        "no credential effect after the bound"
    );
    let op = e.operation_id.clone().unwrap();
    assert_eq!(attempts_of(&w, &op), 0, "no attempt was authorized");
    assert!(!w.grant(&grant_of_op(&w, &op)).state.permits_use());

    // A cutoff takes effect between resolution and `Reconcile`.
    let hook = Arc::new(AtStage::default());
    let w = World::with_opts(Opts {
        hook: hook.clone(),
        ..Opts::default()
    })
    .await;
    let store = w.store.clone();
    let now = w.clock.wall();
    hook.arm(
        EnsureStage::Reconcile,
        false,
        Box::new(move || {
            store
                .transaction(|tx| {
                    let mut p = tx.policy(&policy_id())?.unwrap();
                    p.cutoff_at = Some(now);
                    p.revision = PolicyRevision(p.revision.0 + 1);
                    tx.upsert_policy(&p, true).map(|_| ())
                })
                .unwrap();
        }),
    );
    let e = ensure_as(
        &w,
        &owner(501),
        rq("req-a03c", "work-a03c", &["h1"], Some("2h")),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, Code::PolicyCutoff);
    assert_eq!(
        w.fake.effect_count(),
        0,
        "no credential effect after a cutoff"
    );
    assert_eq!(attempts_of(&w, e.operation_id.as_ref().unwrap()), 0);
}

/// A03: authority is validated again after waiting for an adapter slot. B waits
/// for the only slot while A prepares; B's deadline passes meanwhile; B never
/// prepares.
#[tokio::test]
async fn review_a03_authority_is_rechecked_after_waiting_for_an_adapter_slot() {
    let hook = Arc::new(AtStage::default());
    let w = World::with_opts(Opts {
        hook: hook.clone(),
        limits: Limits {
            max_concurrent_adapter_calls: 1,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    w.gated.hold_call.store(1, Ordering::SeqCst);
    let spawn = |rid: &'static str, work: &'static str, host: &'static str, until: &'static str| {
        let ops = w.ops.clone();
        tokio::spawn(async move {
            ops.ensure(&owner(501), rq(rid, work, &[host], Some(until)))
                .await
        })
    };
    let a = spawn("req-slot-a", "work-slot-a", "h1", "2h");
    w.gated.entered.notified().await;
    let b = spawn("req-slot-b", "work-slot-b", "h2", "10m");
    while hook.reconcile_entries.load(Ordering::SeqCst) < 2 {
        hook.changed.notified().await;
    }
    // Let B reach the adapter slot, then pass its deadline while it waits.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    w.clock.advance(20 * MINUTE);
    w.gated.release.add_permits(1);
    let a = a.await.unwrap();
    let b = b.await.unwrap();
    scan(&a);
    scan(&b);
    assert_eq!(code_of(&a), Code::AccessReady);
    let b = b.unwrap_err();
    assert_eq!(b.code, Code::CredentialExpired);
    assert_eq!(w.fake.effect_count(), 1, "only A prepared; B never did");
    assert_eq!(attempts_of(&w, b.operation_id.as_ref().unwrap()), 0);
}

/// A03: an earlier attempt is still reconciled through its recorded adapter after
/// authority ended (never re-prepared, never abandoned).
#[tokio::test]
async fn review_a03_earlier_attempts_are_reconciled_after_authority_ended() {
    let w = World::with_opts(Opts {
        script: vec![
            FakeStep::ApplyButLoseReply(outcome()),
            FakeStep::Prepare(outcome()),
        ],
        ..Opts::default()
    })
    .await;
    let req = rq("req-a03r", "work-a03r", &["h1"], Some("2h"));
    let e = ensure_as(&w, &owner(501), req.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::OutcomeUnknown);
    let op = e.operation_id.clone().unwrap();
    let gid = grant_of_op(&w, &op);
    assert_eq!(w.fake.effect_count(), 1);
    w.clock.advance(3 * HOUR);
    let r = ensure_as(&w, &owner(501), req).await.unwrap_err();
    assert_eq!(r.code, Code::CredentialExpired);
    assert_eq!(w.fake.effect_count(), 1, "reconciled, never re-prepared");
    let rec = op_of(&w, &op);
    assert!(
        rec.state.is_settled(),
        "the earlier attempt was reconciled and settled"
    );
    assert!(
        w.fake.revocations.lock().unwrap().contains(&gid),
        "the reconciled credential was cleaned up"
    );
}

fn with_minimums(mut r: EnsureRequest, required: RequiredCapabilities) -> EnsureRequest {
    r.required_capabilities = required;
    r
}

fn offline_until(t: Timestamp) -> RequiredCapabilities {
    RequiredCapabilities {
        offline_until: Some(t),
        ..RequiredCapabilities::default()
    }
}

/// A04: prepared facts are validated against the caller's minimums before
/// activation. The adapter's actual offline coverage (10:00) falls short of the
/// requested minimum (10:30): `CAPABILITY_UNAVAILABLE` (exit 4), nothing activates
/// and the prepared credential is cleaned up. A met minimum activates.
#[tokio::test]
async fn review_a04_an_unmet_offline_minimum_is_capability_unavailable() {
    let w = World::new().await;
    let r = ensure_as(
        &w,
        &owner(501),
        with_minimums(
            rq("req-a04", "work-a04", &["h1"], Some("2h")),
            offline_until(at(5400)),
        ),
    )
    .await;
    let e = r.expect_err("an unmet offline minimum is never ACCESS_READY");
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.code.exit_code(), heimdall_contract::ExitCode::Denied);
    let op = e.operation_id.clone().unwrap();
    let gid = grant_of_op(&w, &op);
    assert!(!w.grant(&gid).state.permits_use());
    assert!(
        w.store
            .transaction(|tx| tx.bindings_for_work(&env_id(), &WorkId::parse("work-a04").unwrap()))
            .unwrap()
            .is_empty()
    );
    assert!(w.fake.revocations.lock().unwrap().contains(&gid));
    // Control: a minimum the prepared credential meets.
    let ok = ensure_as(
        &w,
        &owner(501),
        with_minimums(
            rq("req-a04b", "work-a04b", &["h2"], Some("2h")),
            offline_until(at(3000)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(ok.code, Code::AccessReady);
    assert!(ok.data.offline_until >= at(3000));
}

/// A04: the achieved destination-scope enforcement is checked, not only the
/// adapter's advertised one.
#[tokio::test]
async fn review_a04_achieved_enforcement_below_the_minimum_is_capability_unavailable() {
    let mut advertised = EnforcementEvidence::unknown();
    advertised.report.destination_scope = DestinationScopeEnforcement::ClientRouting;
    let mut achieved = outcome();
    achieved.enforcement.report.destination_scope = DestinationScopeEnforcement::UnenforcedIntent;
    let w = World::with_opts(Opts {
        enforcement: advertised,
        script: vec![FakeStep::Prepare(achieved)],
        ..Opts::default()
    })
    .await;
    let r = ensure_as(
        &w,
        &owner(501),
        with_minimums(
            rq("req-a04e", "work-a04e", &["h1"], Some("2h")),
            RequiredCapabilities {
                destination_scope_at_least: Some(DestinationScopeEnforcement::ClientRouting),
                ..RequiredCapabilities::default()
            },
        ),
    )
    .await;
    let e = r.expect_err("achieved enforcement below the minimum is never ACCESS_READY");
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert!(
        !w.grant(&grant_of_op(&w, e.operation_id.as_ref().unwrap()))
            .state
            .permits_use()
    );
}

/// A04: a caller's minimums survive coalescing: a follower that attaches to an
/// equivalent leader's grant is checked against its own minimums.
#[tokio::test]
async fn review_a04_minimums_survive_coalescing() {
    let hook = Arc::new(CountCoalesce::default());
    let w = World::with_hook(hook.clone()).await;
    w.gated.hold_call.store(1, Ordering::SeqCst);
    let until = "2026-10-02T11:00:00Z";
    let req = |rid: &str, work: &str, required: RequiredCapabilities| {
        let mut r = rq(rid, work, &["h1"], None);
        r.until = Some(DeadlineIntent::Absolute(until.into()));
        r.required_capabilities = required;
        r
    };
    let leader = {
        let ops = w.ops.clone();
        let r = req("req-a04l", "work-a04l", RequiredCapabilities::default());
        tokio::spawn(async move { ops.ensure(&owner(501), r).await })
    };
    w.gated.entered.notified().await;
    let follower = {
        let ops = w.ops.clone();
        let r = req("req-a04f", "work-a04f", offline_until(at(5400)));
        tokio::spawn(async move { ops.ensure(&owner(501), r).await })
    };
    while hook.entries.load(Ordering::SeqCst) < 2 {
        hook.changed.notified().await;
    }
    w.gated.release.add_permits(1);
    let leader = leader.await.unwrap();
    let follower = follower.await.unwrap();
    scan(&leader);
    scan(&follower);
    assert_eq!(code_of(&leader), Code::AccessReady);
    assert_eq!(
        code_of(&follower),
        Code::CapabilityUnavailable,
        "the follower's own offline minimum is unmet by the shared credential"
    );
    assert_eq!(w.fake.effect_count(), 1);
    let lg = leader.unwrap().data.grant_id;
    assert_eq!(
        w.grant(&lg).state,
        GrantState::Active,
        "the leader's grant is untouched"
    );
}

/// A04: a caller's minimums survive recovery: after a restart between `Reconcile`
/// and `Commit` the reconciled facts are checked against the stored minimums.
#[tokio::test]
async fn review_a04_minimums_survive_recovery() {
    let mut w = World::with_opts(Opts {
        hook: heimdall_testkit::ScriptedStageHook::new(
            [(EnsureStage::Commit, Code::ServiceUnavailable)],
            [],
        ),
        ..Opts::default()
    })
    .await;
    let req = with_minimums(
        rq("req-a04r", "work-a04r", &["h1"], Some("2h")),
        offline_until(at(5400)),
    );
    let e = ensure_as(&w, &owner(501), req.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::ServiceUnavailable);
    w.hook = Arc::new(NoStageHook);
    w.restart().await;
    let r = ensure_as(&w, &owner(501), req).await;
    let e2 = r.expect_err("recovery never activates below the caller's minimums");
    assert_eq!(e2.code, Code::CapabilityUnavailable);
    assert_eq!(e2.operation_id, e.operation_id);
    assert_eq!(w.fake.effect_count(), 1);
}

/// A06: a replacement decision's delta is recomputed against current policy, never
/// carried across a generation change; approving it completes the request.
#[tokio::test]
async fn review_a06_a_fresh_decision_recomputes_the_delta_against_current_policy() {
    let w = World::new().await;
    let first = w
        .ensure("req-a06", "work-a06", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let op = first.operation_id.clone().unwrap();
    let d1 = dec_of(&first);
    assert_eq!(delta_of(&w, &d1).added_scope.pairs, hosts(&["h3"]));
    // The policy stops covering h1 (a new revision; the generation moves).
    set_policy_hosts(&w.store, &["h2"]);
    let retry = w
        .ensure("req-a06", "work-a06", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(retry.code, Code::InteractionRequired);
    assert_eq!(retry.operation_id, Some(op.clone()));
    let d2 = dec_of(&retry);
    assert_ne!(d2, d1, "a fresh record");
    assert_eq!(
        delta_of(&w, &d2).added_scope.pairs,
        hosts(&["h1", "h3"]),
        "the fresh delta is recomputed against the current policy"
    );
    let rec = w.store.transaction(|tx| tx.decision(&d2)).unwrap().unwrap();
    assert_eq!(rec.generation, generation(&w));
    // The stale record cannot be approved; the fresh one completes the request.
    assert_eq!(
        code_of(&decide_as(&w, &d1, Verdict::Approve).await),
        Code::DecisionStale
    );
    let done = decide_as(&w, &d2, Verdict::Approve).await.unwrap();
    assert_eq!(done.data["operation_state"], "succeeded");
    let ready = w
        .ensure("req-a06", "work-a06", &["h1", "h3"], None)
        .await
        .unwrap();
    assert_eq!(ready.code, Code::AccessReady);
    assert_eq!(
        w.grant(&ready.data.grant_id).scope.pairs,
        hosts(&["h1", "h3"])
    );
    assert_eq!(w.fake.effect_count(), 1);
}

/// A06 with ADR-0006 §13.6 item 10: after the pause is lifted, the same-key retry
/// gets a fresh, recomputed decision, and approving it completes the request (the
/// approval re-bases the request on the policy revision it was decided under).
#[tokio::test]
async fn review_a06_a_fresh_decision_after_a_lifted_pause_completes() {
    let w = World::new().await;
    let first = w
        .ensure("req-a06p", "work-a06p", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let op = first.operation_id.clone().unwrap();
    w.ops
        .policy(
            &owner(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await
        .unwrap();
    let paused = w
        .ensure("req-a06p", "work-a06p", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(paused.code, Code::PolicyPaused);
    let resume = w
        .ops
        .policy(
            &attended(501),
            PolicyAction::Resume {
                policy_id: policy_id(),
            },
        )
        .await
        .unwrap_err();
    decide_as(&w, &dec_of(&resume), Verdict::Approve)
        .await
        .unwrap();
    let retry = w
        .ensure("req-a06p", "work-a06p", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(retry.code, Code::InteractionRequired);
    assert_eq!(retry.operation_id, Some(op));
    let fresh = dec_of(&retry);
    assert_eq!(delta_of(&w, &fresh).added_scope.pairs, hosts(&["h3"]));
    let done = decide_as(&w, &fresh, Verdict::Approve).await.unwrap();
    assert_eq!(done.data["operation_state"], "succeeded");
    let ready = w.ensure("req-a06p", "work-a06p", &["h1", "h3"], None).await;
    assert_eq!(code_of(&ready), Code::AccessReady);
    assert_eq!(w.fake.effect_count(), 1);
}

/// A06: before preparation the approved record is re-validated against the
/// authority actually used. A policy narrowing, or the environment losing its
/// automatic activation, after the approval refuses the preparation: nothing is
/// prepared on an approval that no longer describes the authority.
#[tokio::test]
async fn review_a06_an_approval_is_revalidated_before_preparation() {
    for change in ["policy", "environment"] {
        let hook = Arc::new(AtStage::default());
        let w = World::with_opts(Opts {
            hook: hook.clone(),
            ..Opts::default()
        })
        .await;
        let pending = w
            .ensure("req-a06v", "work-a06v", &["h1", "h3"], None)
            .await
            .unwrap_err();
        let store = w.store.clone();
        hook.arm(
            EnsureStage::Coalesce,
            false,
            Box::new(move || match change {
                "policy" => set_policy_hosts(&store, &["h2"]),
                _ => set_automatic_activation(&store, false),
            }),
        );
        decide_as(&w, &dec_of(&pending), Verdict::Approve)
            .await
            .unwrap();
        let after = w.ensure("req-a06v", "work-a06v", &["h1", "h3"], None).await;
        assert_eq!(code_of(&after), Code::CredentialExpired, "{change}");
        assert_eq!(
            w.fake.effect_count(),
            0,
            "{change}: nothing prepared on an approval that no longer covers the authority"
        );
    }
}

/// A07: equivalent pending added-authority requests (same caller, work, resolved
/// authority, deadline and generation; different request IDs) share one decision
/// record; each caller keeps its own operation; one approval completes both with
/// one preparation and separate references.
#[tokio::test]
async fn review_a07_equivalent_added_authority_requests_share_one_decision() {
    let w = World::new().await;
    let a = w
        .ensure("req-a07-1", "work-a07", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let b = w
        .ensure("req-a07-2", "work-a07", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(a.code, Code::InteractionRequired);
    assert_eq!(b.code, Code::InteractionRequired);
    assert_ne!(
        a.operation_id, b.operation_id,
        "each caller keeps its own operation"
    );
    assert_eq!(dec_of(&a), dec_of(&b), "one logical decision, one record");
    assert_eq!(pending_approvals(&w).len(), 1);
    // A same-key retry of either returns the same record.
    let again = w
        .ensure("req-a07-2", "work-a07", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(dec_of(&again), dec_of(&a));
    assert_eq!(again.operation_id, b.operation_id);
    let done = decide_as(&w, &dec_of(&a), Verdict::Approve).await.unwrap();
    assert_eq!(done.data["operation_state"], "succeeded");
    let ra = w
        .ensure("req-a07-1", "work-a07", &["h1", "h3"], None)
        .await
        .unwrap();
    let rb = w
        .ensure("req-a07-2", "work-a07", &["h1", "h3"], None)
        .await
        .unwrap();
    assert_eq!(ra.code, Code::AccessReady);
    assert_eq!(rb.code, Code::AccessReady);
    assert_eq!(ra.operation_id, a.operation_id);
    assert_eq!(rb.operation_id, b.operation_id);
    assert_eq!(ra.data.grant_id, rb.data.grant_id, "one grant");
    assert_ne!(
        ra.data.binding_id, rb.data.binding_id,
        "separate references"
    );
    assert_eq!(w.fake.effect_count(), 1, "one preparation");
}

/// A07: a broader request, another work ID or another caller never joins a
/// narrower decision.
#[tokio::test]
async fn review_a07_a_broader_request_never_joins_a_narrower_decision() {
    let w = World::new().await;
    let narrow = w
        .ensure("req-a07n", "work-a07n", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let broad = w
        .ensure("req-a07w", "work-a07n", &["h1", "h2", "h3"], None)
        .await
        .unwrap_err();
    let other_work = w
        .ensure("req-a07o", "work-a07o", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let other_caller = ensure_as(
        &w,
        &owner(502),
        rq("req-a07n", "work-a07n", &["h1", "h3"], None),
    )
    .await
    .unwrap_err();
    let d = dec_of(&narrow);
    for (what, e) in [
        ("broader", &broad),
        ("other work", &other_work),
        ("other caller", &other_caller),
    ] {
        assert_eq!(e.code, Code::InteractionRequired, "{what}");
        assert_ne!(dec_of(e), d, "{what} never joins the narrower decision");
    }
    assert_eq!(pending_approvals(&w).len(), 4);
    assert_eq!(
        delta_of(&w, &dec_of(&broad)).added_scope.pairs,
        hosts(&["h3"])
    );
}

/// A07: a shared decision's denial fails every waiting caller; cancelling one
/// caller's operation leaves the others waiting on the shared record.
#[tokio::test]
async fn review_a07_cancel_and_deny_of_a_shared_decision() {
    let w = World::new().await;
    let a = w
        .ensure("req-a07c1", "work-a07c", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let b = w
        .ensure("req-a07c2", "work-a07c", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let c = w
        .ensure("req-a07c3", "work-a07c", &["h1", "h3"], None)
        .await
        .unwrap_err();
    let d = dec_of(&a);
    assert_eq!(dec_of(&c), d);
    // Cancelling a caller that joined leaves the shared grant and record alone.
    let cancelled = w
        .ops
        .cancel(
            &owner(501),
            heimdall_contract::request::CancelRequest {
                operation_id: c.operation_id.clone().unwrap(),
            },
        )
        .await;
    scan(&cancelled);
    cancelled.unwrap();
    let gid = grant_of_op(&w, a.operation_id.as_ref().unwrap());
    assert_eq!(w.grant(&gid).state, GrantState::AwaitingApproval);
    let still = w
        .ensure("req-a07c2", "work-a07c", &["h1", "h3"], None)
        .await
        .unwrap_err();
    assert_eq!(dec_of(&still), d);
    // Denying the shared record fails every waiting caller.
    decide_as(&w, &d, Verdict::Deny).await.unwrap();
    for (rid, e) in [("req-a07c1", &a), ("req-a07c2", &b)] {
        let r = w
            .ensure(rid, "work-a07c", &["h1", "h3"], None)
            .await
            .unwrap_err();
        assert_eq!(r.code, Code::CapabilityUnavailable, "{rid}");
        assert_eq!(r.operation_id, e.operation_id);
    }
    assert_eq!(w.fake.effect_count(), 0);
}

/// ADR-0006 §13.6 item 11: a publish voided only by an unrelated generation move
/// (the grant and its chain are still valid) re-validates and re-reserves within
/// the same call, then publishes the fresh reservation.
#[tokio::test]
async fn review_13_6_11_an_unrelated_generation_move_rereserves_and_publishes() {
    let w = World::new().await;
    let g = w.ready("req-r11", "work-r11", &["h1"], None).await;
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1800)))
        .await
        .unwrap();
    bump_unrelated(&w.store, 1);
    let published = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap_or_else(|e| panic!("healthy publish refused: {} {}", e.code, e.message));
    assert_eq!(published.state, IssuanceState::Published);
    assert_ne!(
        published.id, reserved.id,
        "a fresh reservation was published"
    );
    assert_eq!(published.generation, generation(&w));
    assert_eq!(published.bounds.valid_before, reserved.bounds.valid_before);
    assert_eq!(published.bounds.principal, reserved.bounds.principal);
    assert_eq!(
        published.bounds.subject_fingerprint,
        reserved.bounds.subject_fingerprint
    );
    let original = entries_of(&w, &g.grant_id)
        .into_iter()
        .find(|e| e.id == reserved.id)
        .unwrap();
    assert_eq!(original.state, IssuanceState::Voided);
    assert_eq!(original.void_reason, Some(IssuanceRefusal::StaleGeneration));
    assert_eq!(residual(&w, &g.grant_id), Some(at(1800)));
}

/// ADR-0006 §13.6 item 11: still racing after 3 attempts within the same call ⇒
/// `SERVICE_UNAVAILABLE` (exit 5, retryable) with a retry `next`; nothing left
/// reserved or published.
#[tokio::test]
async fn review_13_6_11_a_generation_still_racing_after_three_attempts_is_service_unavailable() {
    let bumper = Arc::new(Bumper::default());
    let w = World::with_opts(Opts {
        faults: bumper.clone(),
        ..Opts::default()
    })
    .await;
    bumper.bind(&w);
    let g = w.ready("req-r11r", "work-r11r", &["h1"], None).await;
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1800)))
        .await
        .unwrap();
    bumper.arm(usize::MAX);
    let e = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap_err();
    bumper.arm(0);
    assert_no_canary(&e.message);
    assert_eq!(e.code, Code::ServiceUnavailable);
    assert_eq!(e.code.exit_code(), heimdall_contract::ExitCode::Unavailable);
    assert!(e.code.retryable());
    assert_eq!(e.next.action, "retry_after");
    let entries = entries_of(&w, &g.grant_id);
    assert_eq!(
        entries.len(),
        3,
        "three attempts: the original and two re-reservations"
    );
    for x in &entries {
        assert_eq!(x.state, IssuanceState::Voided);
        assert_eq!(x.void_reason, Some(IssuanceRefusal::StaleGeneration));
    }
    assert_eq!(residual(&w, &g.grant_id), None);
}

/// ADR-0006 §13.6 item 11: a failed re-validation answers that denial's own code.
#[tokio::test]
async fn review_13_6_11_a_failed_revalidation_answers_its_own_code() {
    // A pause between reserve and publish of a new activation: POLICY_PAUSED.
    let w = World::new().await;
    let g = w.ready("req-r11p", "work-r11p", &["h1"], None).await;
    let mut activation = issuance(&g.grant_id, at(1800));
    activation.facts.new_activation = true;
    let reserved = w.ops.reserve_issuance(activation.clone()).await.unwrap();
    w.ops
        .policy(
            &owner(501),
            PolicyAction::Pause {
                policy_id: policy_id(),
            },
        )
        .await
        .unwrap();
    let e = w
        .ops
        .publish_issuance(&reserved.id, &activation.facts)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PolicyPaused);
    assert_eq!(entries_of(&w, &g.grant_id).len(), 1, "no re-reservation");
    // A revoke between reserve and publish: CREDENTIAL_EXPIRED.
    let w = World::new().await;
    let g = w.ready("req-r11v", "work-r11v", &["h1"], None).await;
    let reserved = w
        .ops
        .reserve_issuance(issuance(&g.grant_id, at(1800)))
        .await
        .unwrap();
    w.revoke(&g.grant_id, "req-r11-rv").await.unwrap();
    let e = w
        .ops
        .publish_issuance(&reserved.id, &facts())
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(entries_of(&w, &g.grant_id).len(), 1, "no re-reservation");
}

/// Property steps between reserve and publish (A01, ADR-0006 §13.6 item 11).
#[derive(Debug, Clone)]
enum Interleave {
    /// A policy write elsewhere: the generation moves, nothing here changes.
    Unrelated,
    /// The grant is revoked.
    Revoke,
    /// A pause (continuing issuance is not a new activation).
    Pause,
    /// A cutoff at the current time.
    CutoffNow,
    /// Safe time passes (wall and continuous), in minutes.
    Advance(u8),
    /// The wall clock steps back 2 minutes: time is uncertain from then on.
    RollBack,
}

fn interleave() -> impl Strategy<Value = Interleave> {
    prop_oneof![
        3 => Just(Interleave::Unrelated),
        1 => Just(Interleave::Revoke),
        1 => Just(Interleave::Pause),
        1 => Just(Interleave::CutoffNow),
        2 => (1u8..=90).prop_map(Interleave::Advance),
        1 => Just(Interleave::RollBack),
    ]
}

proptest! {
    #![proptest_config(prop_config(0x5235_3131_5055_4231))]

    /// A01 with ADR-0006 §13.6 item 11: whatever happens between reserve and
    /// publish, and however often the generation races during the publish call,
    /// publication answers from the state and time of its own transaction:
    /// published exactly when the grant is still issuable, safe time holds and its
    /// bound has not passed and the generation settled within 3 attempts; refused
    /// with the denial's own code otherwise; `SERVICE_UNAVAILABLE` (retryable)
    /// only when only the generation kept racing. A published entry is the only
    /// one counted; nothing is published twice.
    #[test]
    fn publication_answers_from_the_state_and_time_of_its_own_transaction(
        steps in prop::collection::vec(interleave(), 0..6),
        racing in 0usize..5,
    ) {
        block(async move {
            let bumper = Arc::new(Bumper::default());
            let w = World::with_opts(Opts { faults: bumper.clone(), ..Opts::default() }).await;
            bumper.bind(&w);
            let g = w.ready("req-p11", "work-p11", &["h1"], Some(DeadlineIntent::Duration("2h".into()))).await;
            let reserved = w.ops.reserve_issuance(issuance(&g.grant_id, at(1800))).await.unwrap();
            let (mut revoked, mut cut, mut uncertain, mut advanced) = (false, false, false, 0u32);
            let mut n = 0;
            for s in &steps {
                n += 1;
                match s {
                    Interleave::Unrelated => bump_unrelated(&w.store, 1000 + n),
                    Interleave::Revoke => {
                        w.revoke(&g.grant_id, &format!("req-p11-rv-{n}")).await.unwrap();
                        revoked = true;
                    }
                    Interleave::Pause => {
                        w.ops.policy(&owner(501), PolicyAction::Pause { policy_id: policy_id() }).await.unwrap();
                    }
                    Interleave::CutoffNow => {
                        let at = w.clock.wall();
                        if w.ops.policy(&owner(501), PolicyAction::Cutoff { policy_id: policy_id(), at }).await.is_ok() {
                            cut = true;
                        }
                    }
                    Interleave::Advance(m) => {
                        w.clock.advance(u32::from(*m) * MINUTE);
                        advanced += u32::from(*m);
                    }
                    Interleave::RollBack => {
                        w.clock.set_wall(w.clock.wall().checked_sub(jiff::SignedDuration::from_mins(2)).unwrap());
                        uncertain = true;
                    }
                }
            }
            let expired = advanced >= 120;
            bumper.arm(racing);
            let r = w.ops.publish_issuance(&reserved.id, &facts()).await;
            bumper.arm(0);
            let entries = entries_of(&w, &g.grant_id);
            let published: Vec<_> = entries.iter().filter(|e| e.state == IssuanceState::Published).collect();
            let reserved_left = entries.iter().filter(|e| e.state == IssuanceState::Reserved).count();
            prop_assert_eq!(reserved_left, 0, "a publish call never leaves a reservation behind");
            prop_assert!(entries.len() <= 3, "at most 3 attempts in one call");
            let refused = revoked || cut || uncertain || expired;
            match r {
                Ok(e) => {
                    prop_assert!(!refused, "published although revoked={revoked} cut={cut} uncertain={uncertain} expired={expired}");
                    prop_assert!(racing < 3, "published although the generation raced {racing} times");
                    prop_assert_eq!(published.len(), 1);
                    prop_assert_eq!(&published[0].id, &e.id);
                    prop_assert_eq!(e.bounds.valid_before, at(1800));
                    prop_assert_eq!(residual(&w, &g.grant_id), Some(at(1800)));
                }
                Err(e) => {
                    assert_no_canary(&e.message);
                    prop_assert!(published.is_empty());
                    prop_assert_eq!(residual(&w, &g.grant_id), None, "nothing released");
                    if refused {
                        prop_assert!(
                            matches!(e.code, Code::CredentialExpired | Code::TimeUncertain),
                            "a refusal answers its own code: {}", e.code
                        );
                        if uncertain && !(revoked || cut || expired) {
                            prop_assert_eq!(&e.code, &Code::TimeUncertain);
                        }
                    } else {
                        prop_assert!(racing >= 3, "refused a healthy publish: {}", e.code);
                        prop_assert_eq!(&e.code, &Code::ServiceUnavailable);
                        prop_assert!(e.code.retryable());
                        prop_assert_eq!(entries.len(), 3);
                    }
                }
            }
            Ok(())
        })?;
    }
}
