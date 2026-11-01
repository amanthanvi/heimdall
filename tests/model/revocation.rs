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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    AccountName, BindingId, DecisionId, DestinationId, DeviceId, EnvironmentId, GrantId, PolicyId,
    ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    BindForm, BindRequest, DeadlineIntent, DecideRequest, DelegateRequest, EnsureData,
    EnsureRequest, InteractionMode, PolicyAction, RefreshDependency, ReleaseRequest,
    RequiredCapabilities, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::{IssuanceRefusal, IssuanceState};
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_store::Store;
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
    ops: Operations,
}

impl World {
    async fn new() -> Self {
        Self::with_hook(Arc::new(NoStageHook)).await
    }

    async fn with_hook(hook: Arc<dyn StageHook>) -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
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
            enforcement: EnforcementEvidence::unknown(),
            lock_continuity: LockContinuity::Unknown,
        };
        let fake = FakeCredentialAdapter::new(descriptor, [FakeStep::Prepare(outcome())]);
        let gated = Gated::new(fake.clone());
        let ops = Operations::start(config(&store, &clock, &sync, &gated, &hook))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            gated,
            hook,
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
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![gated.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: hook.clone(),
        limits: Limits::default(),
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
    for (between, expect) in [
        (
            Between::Revoke,
            IssuanceRefusal::GrantNotIssuable(GrantState::Revoked),
        ),
        // A cutoff is a policy change: the first failing predicate is the moved
        // revision (the cutoff itself would refuse next).
        (Between::Cutoff, IssuanceRefusal::StalePolicyRevision),
        // ADR-0006 §13.6 item 5: a revision of an applicable policy moves the
        // generation too; the chain re-validates against the new revision, so the
        // publish is voided because reserve and publish saw different generations.
        (Between::PolicyRevision, IssuanceRefusal::StaleGeneration),
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
