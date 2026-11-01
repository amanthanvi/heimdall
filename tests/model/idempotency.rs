//! M01-U5 idempotency, timeout and decision properties (plan §6.3 #4, #7; spec
//! §11.4, §17 A06/A19; ADR-0006 §3.1, §7).
//!
//! Property tests drive the production `heimdall_app::Operations` over
//! `Store::open_in_memory`, `testkit::VirtualClock` and
//! `testkit::FakeCredentialAdapter`, one fresh world per generated trace:
//!
//! * **#4 retries converge, conflict, expire:** random interleavings of sends
//!   (sequential and concurrent duplicates) over a few keys and parameter
//!   variants, with time advances and retention purges through `tick`, checked
//!   against a reference model of ADR-0006 §7.3–7.4 (replay, conflict naming the
//!   original operation, `REQUEST_EXPIRED` inside the marker window, a new
//!   operation only for a key the runtime no longer knows).
//! * **#7 timeout is not cancellation; uncertainty is never "not applied":**
//!   random adapter scripts (success, classified failure, lost reply) and random
//!   bounded waits; no operation is ever cancelled without an explicit cancel, and
//!   every `OUTCOME_UNKNOWN` (response or record) carries effect `unknown`.
//! * **Decisions are consume-once** under concurrent `decide`.
//!
//! Seeds: a fixed default (`RngSeed::Fixed`), overridden by `PROPTEST_RNG_SEED`;
//! failures persist to `tests/model/proptest-regressions/`. 256 cases each.
//!
//! Hosting: this target lives in `heimdall-app` (not `heimdall-runtime`) because
//! only this crate has the `proptest` dev-dependency edge (see its Cargo.toml).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, InteractionRequirement, LockContinuity,
    PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, DeviceId, EnvironmentId, OperationId, PolicyId,
    ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    DeadlineIntent, DecideRequest, EnsureRequest, InteractionMode, ObserveRequest,
    RefreshDependency, RequiredCapabilities, Verdict, WaitMode,
};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
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
use proptest::test_runner::{FileFailurePersistence, RngSeed, TestRunner};

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
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

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(12))
            .unwrap(),
        offline_until: t0()
            .checked_add(jiff::SignedDuration::from_hours(1))
            .unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        credential_ref: format!("{CANARY_PREFIX}idempotency_fixture"),
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
                    id: PolicyId::parse("pol").unwrap(),
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

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    fake: Arc<FakeCredentialAdapter>,
    ops: Operations,
}

impl World {
    async fn new(script: Vec<FakeStep>) -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
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
        let fake = FakeCredentialAdapter::new(descriptor, script);
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
        })
        .await
        .unwrap();
        Self {
            store,
            clock,
            fake,
            ops,
        }
    }

    fn op(&self, id: &OperationId) -> Option<heimdall_domain::operation::OperationRecord> {
        self.store.transaction(|tx| tx.operation(id)).unwrap()
    }
}

fn ensure_req(rid: &str, work: &str, h: &str, until: Option<&str>) -> EnsureRequest {
    EnsureRequest {
        profile: ProfileId::parse("dev").unwrap(),
        profile_revision: None,
        scope: [pair(h, "deploy")].into_iter().collect(),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until: until.map(|u| DeadlineIntent::Duration(u.into())),
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(rid).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::default(),
    }
}

/// Envelope JSON of a result, scanned for canaries.
fn scanned<T: serde::Serialize + Clone>(r: &OpResult<T>) {
    let s = match r {
        Ok(c) => serde_json::to_string(&c.clone().into_envelope()).unwrap(),
        Err(e) => serde_json::to_string(&e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&s);
}

/// Run one generated case on a fresh current-thread runtime (the production
/// flavour; overview §4).
fn block<F: std::future::Future<Output = Result<(), TestCaseError>>>(
    f: F,
) -> Result<(), TestCaseError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f)
}

fn config(cases: u32, seed: u64) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    // `ProptestConfig::default()` honours PROPTEST_RNG_SEED; otherwise pin a seed
    // so runs are reproducible.
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

// =================================================================================
// #4 — retries converge, conflict, expire (ADR-0006 §7.3, §7.4)
// =================================================================================

#[derive(Debug, Clone)]
enum Step {
    /// Send key `k` with parameter variant `p` (`n` concurrent copies).
    Send { k: u8, p: u8, n: u8 },
    /// Advance the clock by this many days and run the deadline tick (purges).
    Advance { days: u8 },
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (0u8..3, 0u8..2, 1u8..4).prop_map(|(k, p, n)| Step::Send { k, p, n }),
        2 => (0u8..40).prop_map(|days| Step::Advance { days }),
    ]
}

/// Reference model of one key.
#[derive(Debug, Clone)]
struct KeyModel {
    op: OperationId,
    params: u8,
    /// `expires_at` of the settled record.
    expires_at: Timestamp,
    /// `Some(marker_until)` once purged.
    marker_until: Option<Timestamp>,
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
        .unwrap()
}

fn request(k: u8, p: u8) -> EnsureRequest {
    // Parameter variants differ in the hashed deadline intent.
    let until = if p == 0 { None } else { Some("30m") };
    ensure_req(&format!("key-{k}"), &format!("work-{k}"), "h1", until)
}

/// Branches a trace exercised (non-vacuity across the whole run).
#[derive(Debug, Default)]
struct Coverage {
    replay: AtomicUsize,
    conflict: AtomicUsize,
    expired: AtomicUsize,
    fresh: AtomicUsize,
    fresh_after_marker: AtomicUsize,
    concurrent: AtomicUsize,
}

fn retry_trace(steps: Vec<Step>, cov: &Coverage) -> Result<(), TestCaseError> {
    block(async move {
        let w = World::new(vec![FakeStep::Prepare(outcome())]).await;
        let mut model: BTreeMap<u8, KeyModel> = BTreeMap::new();
        let mut forgotten: BTreeSet<u8> = BTreeSet::new();
        let mut new_ops = 0usize;
        for s in steps {
            match s {
                Step::Advance { days } => {
                    w.clock.advance(u32::from(days) * DAY);
                    w.ops.tick().await.unwrap();
                    let now = w.clock.wall();
                    for m in model.values_mut() {
                        if m.marker_until.is_none() && now >= m.expires_at {
                            m.marker_until = Some(plus(
                                m.expires_at,
                                heimdall_domain::idempotency::MARKER_WINDOW,
                            ));
                        }
                    }
                    let gone: Vec<u8> = model
                        .iter()
                        .filter(|(_, m)| m.marker_until.is_some_and(|u| now >= u))
                        .map(|(k, _)| *k)
                        .collect();
                    for k in gone {
                        model.remove(&k);
                        forgotten.insert(k);
                    }
                }
                Step::Send { k, p, n } => {
                    let now = w.clock.wall();
                    if n > 1 {
                        cov.concurrent.fetch_add(1, Ordering::Relaxed);
                    }
                    let mut handles = Vec::new();
                    for _ in 0..n {
                        let ops = w.ops.clone();
                        let req = request(k, p);
                        handles.push(tokio::spawn(
                            async move { ops.ensure(&owner(501), req).await },
                        ));
                    }
                    let mut results = Vec::new();
                    for h in handles {
                        let r = h.await.unwrap();
                        scanned(&r);
                        results.push(r);
                    }
                    let op_of = |r: &OpResult<heimdall_contract::request::EnsureData>| match r {
                        Ok(c) => c.operation_id.clone(),
                        Err(e) => e.operation_id.clone(),
                    };
                    match model.get(&k).cloned() {
                        // Known key, record retained: replay or conflict.
                        Some(m) if m.marker_until.is_none() => {
                            for r in &results {
                                if m.params == p {
                                    cov.replay.fetch_add(1, Ordering::Relaxed);
                                    prop_assert_eq!(
                                        op_of(r),
                                        Some(m.op.clone()),
                                        "replay converges"
                                    );
                                } else {
                                    cov.conflict.fetch_add(1, Ordering::Relaxed);
                                    let e = r.as_ref().unwrap_err();
                                    prop_assert_eq!(&e.code, &Code::RequestConflict);
                                    prop_assert_eq!(e.operation_id.clone(), Some(m.op.clone()));
                                }
                            }
                        }
                        // Purged, marker live: never silently new.
                        Some(_) => {
                            cov.expired.fetch_add(1, Ordering::Relaxed);
                            for r in &results {
                                prop_assert_eq!(
                                    &r.as_ref().unwrap_err().code,
                                    &Code::RequestExpired
                                );
                            }
                        }
                        // Unknown key: exactly one new operation for all copies.
                        None => {
                            cov.fresh.fetch_add(1, Ordering::Relaxed);
                            if forgotten.contains(&k) {
                                cov.fresh_after_marker.fetch_add(1, Ordering::Relaxed);
                            }
                            let ids: BTreeSet<_> = results.iter().map(op_of).collect();
                            prop_assert_eq!(ids.len(), 1);
                            let id = ids.into_iter().next().unwrap().expect("operation id");
                            let rec = w.op(&id).expect("operation persisted");
                            prop_assert!(rec.state.is_settled());
                            new_ops += 1;
                            model.insert(
                                k,
                                KeyModel {
                                    op: id,
                                    params: p,
                                    expires_at: heimdall_domain::idempotency::retention_expiry(
                                        now,
                                        Limits::default().operation_retention,
                                    ),
                                    marker_until: None,
                                },
                            );
                        }
                    }
                }
            }
        }
        // At most one effect per new operation (a work ID re-used after the
        // marker window is refused, never re-prepared).
        prop_assert!(w.fake.effect_count() <= new_ops);
        Ok(())
    })
}

#[test]
fn retries_converge_conflict_and_expire_under_interleavings_and_purges() {
    let cov = Coverage::default();
    let mut runner = TestRunner::new(config(256, 0x5535_4944_454d_5031));
    let result = runner.run(&prop::collection::vec(step(), 1..14), |steps| {
        retry_trace(steps, &cov)
    });
    if let Err(e) = result {
        panic!("{e}");
    }
    // Non-vacuity: every branch of the reference model was exercised.
    for (name, n) in [
        ("replay", &cov.replay),
        ("conflict", &cov.conflict),
        ("expired", &cov.expired),
        ("fresh", &cov.fresh),
        ("fresh_after_marker", &cov.fresh_after_marker),
        ("concurrent", &cov.concurrent),
    ] {
        assert!(
            n.load(Ordering::Relaxed) > 0,
            "branch {name} never exercised: {cov:?}"
        );
    }
}

// =================================================================================
// #7 — a caller timeout is not cancellation; uncertainty is never "not applied"
// =================================================================================

#[derive(Debug, Clone)]
enum Script {
    Ok,
    Fail,
    LoseReply,
}

fn fake_step(s: &Script) -> FakeStep {
    match s {
        Script::Ok => FakeStep::Prepare(outcome()),
        Script::Fail => FakeStep::Fail(AdapterError::Unavailable(format!(
            "{CANARY_PREFIX}adapter_error"
        ))),
        Script::LoseReply => FakeStep::ApplyButLoseReply(outcome()),
    }
}

fn script() -> impl Strategy<Value = Script> {
    prop_oneof![
        Just(Script::Ok),
        Just(Script::Fail),
        Just(Script::LoseReply)
    ]
}

fn wait_mode() -> impl Strategy<Value = WaitMode> {
    prop_oneof![
        Just(WaitMode::Async),
        Just(WaitMode::Sync { timeout_ms: 0 }),
        Just(WaitMode::Sync { timeout_ms: 30_000 }),
    ]
}

fn check_uncertainty(e: &OpError) -> Result<(), TestCaseError> {
    if e.code == Code::OutcomeUnknown {
        prop_assert_eq!(e.effect_status, EffectStatus::Unknown);
        prop_assert_eq!(e.state(), OperationState::OutcomeUnknown);
    }
    prop_assert!(
        e.code != Code::OperationCancelled,
        "never cancelled without a cancel"
    );
    Ok(())
}

proptest! {
    #![proptest_config(config(256, 0x5535_5449_4d45_4f55))]

    #[test]
    fn caller_timeouts_never_cancel_and_uncertain_effects_are_never_reported_as_none(
        scripts in prop::collection::vec(script(), 1..4),
        waits in prop::collection::vec(wait_mode(), 1..5),
    ) {
        block(async move {
            let w = World::new(scripts.iter().map(fake_step).collect()).await;
            let mut ops_seen = BTreeSet::new();
            for (i, wait) in waits.iter().enumerate() {
                let mut req = ensure_req(&format!("req-{i}"), &format!("work-{i}"), "h1", None);
                req.wait = *wait;
                let r = w.ops.ensure(&owner(501), req.clone()).await;
                scanned(&r);
                match &r {
                    Ok(c) => { ops_seen.insert(c.operation_id.clone().unwrap()); }
                    Err(e) => {
                        check_uncertainty(e)?;
                        if let Some(id) = &e.operation_id { ops_seen.insert(id.clone()); }
                    }
                }
                // A same-key retry (the caller came back after its timeout).
                req.wait = WaitMode::Sync { timeout_ms: 30_000 };
                let again = w.ops.ensure(&owner(501), req).await;
                scanned(&again);
                if let Err(e) = &again { check_uncertainty(e)?; }
            }
            // Let every operation reach quiescence, then check the records.
            for id in &ops_seen {
                let seen = w
                    .ops
                    .observe(&owner(501), ObserveRequest::Operation { operation_id: id.clone(), wait_ms: Some(5_000) })
                    .await
                    .unwrap();
                prop_assert!(seen.state.is_quiescent());
                let rec = w.op(id).unwrap();
                prop_assert!(rec.state != OperationState::Cancelled);
                prop_assert!(rec.cancellation.is_none());
                if rec.state == OperationState::OutcomeUnknown {
                    prop_assert_eq!(rec.effect_status, EffectStatus::Unknown);
                }
                if rec.state == OperationState::Succeeded {
                    prop_assert_eq!(rec.effect_status, EffectStatus::Applied);
                }
            }
            // Every applied effect belongs to a succeeded or still-unresolved
            // operation: none is hidden behind a failure that claims "none".
            let failed_none = ops_seen.iter().filter_map(|id| w.op(id)).filter(|r| r.state == OperationState::Failed && r.effect_status == EffectStatus::None).count();
            let not_failed = ops_seen.len() - failed_none;
            prop_assert!(w.fake.effect_count() <= not_failed);
            Ok(())
        })?;
    }
}

// =================================================================================
// Decisions are consume-once under concurrent `decide` (ADR-0006 §3.1)
// =================================================================================

proptest! {
    #![proptest_config(config(256, 0x5535_4445_4349_4445))]

    #[test]
    fn decisions_are_consumed_once_under_concurrent_decide(
        verdicts in prop::collection::vec(any::<bool>(), 2..7)
    ) {
        block(async move {
            let w = World::new(vec![FakeStep::Prepare(outcome())]).await;
            let mut req = ensure_req("req-dec", "work-dec", "h3", None);
            req.scope.insert(pair("h1", "deploy"));
            let pending = w.ops.ensure(&attended(501), req.clone()).await.unwrap_err();
            prop_assert_eq!(&pending.code, &Code::ApprovalRequired);
            let dec = DecisionId::parse(pending.next.decision_ref.as_deref().unwrap()).unwrap();
            let op = pending.operation_id.clone().unwrap();
            let mut handles = Vec::new();
            for approve in &verdicts {
                let ops = w.ops.clone();
                let d = DecideRequest {
                    decision_id: dec.clone(),
                    verdict: if *approve { Verdict::Approve } else { Verdict::Deny },
                };
                handles.push(tokio::spawn(async move { ops.decide(&attended(501), d).await }));
            }
            let mut winners = Vec::new();
            for (h, approve) in handles.into_iter().zip(&verdicts) {
                let r = h.await.unwrap();
                scanned(&r);
                match r {
                    Ok(_) => winners.push(*approve),
                    Err(e) => prop_assert_eq!(e.code, Code::DecisionStale),
                }
            }
            prop_assert_eq!(winners.len(), 1, "exactly one verdict is applied");
            let seen = w
                .ops
                .observe(&owner(501), ObserveRequest::Operation { operation_id: op.clone(), wait_ms: Some(5_000) })
                .await
                .unwrap();
            if winners[0] {
                prop_assert_eq!(seen.state, OperationState::Succeeded);
                prop_assert_eq!(w.fake.effect_count(), 1);
            } else {
                prop_assert_eq!(seen.state, OperationState::Failed);
                prop_assert_eq!(w.fake.effect_count(), 0);
            }
            Ok(())
        })?;
    }
}
