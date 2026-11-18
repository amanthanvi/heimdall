//! ⟨M05⟩ U3 journeys: expiry and re-entry, the hard cutoff, `stop` by profile, stopping one
//! job of two, and an `ensure` then `run` of one work ID (ADR-0011 §3.3, §7; §10; spec §5.6,
//! §6.1; m05-plan U3; the orchestrator's ruling I-1).
//!
//! Everything runs **in process** over the production `heimdall_app::Operations`,
//! `heimdall_store::Store::open_in_memory`, `testkit::VirtualClock`,
//! `testkit::ScriptedTimeSync` and `testkit::FakeCredentialAdapter` (whose scripted
//! `HangBeforeEffect` holds a `prepare`, so two requests are concurrent by construction).
//! The CLI surfaces
//! (`access stop`, `access allow`, `revoke --work`) land in wave 3; a "restart" is an
//! in-process reconstruction (a new `Operations` over the same store), as in
//! `model_operations`.
//!
//! * [`a05_expiry_reentry_and_hard_cutoff`] (A05);
//! * [`a05_stop_profile_revokes_and_blocks_until_resume`] (A05, spec §5.6);
//! * [`stop_one_job_leaves_the_other`] (ADR-0011 §7.2 "Stop (work)");
//! * [`ensure_then_run_same_work_id_reuses_the_grant`] (ruling I-1);
//! * [`targeted_actions_resolve_their_set_in_the_applying_transaction`] (ADR-0011 §7.3 and
//!   I5 at the boundaries the model does not reach).
//!
//! Cargo test target `e2e_stop_m05`, hosted by `heimdall-runtime`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use heimdall_app::ensure::{EnsureStage, StageHook};
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Attendance, Caller, OpResult, Operations, OperationsConfig};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{
    AccountName, BindingId, DecisionId, DestinationId, DeviceId, EnvironmentId, GrantId, PolicyId,
    ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    BindForm, BindRequest, DeadlineIntent, DecideRequest, DelegateRequest, EnsureData,
    EnsureRequest, InspectRequest, InspectSubject, InteractionMode, PolicyAction,
    RefreshDependency, RequiredCapabilities, RevokeData, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::trust::{PolicyTarget, PolicyTargetResult, RevokeTarget};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::binding::BindingState;
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::GrantSnapshot;
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
use tokio::sync::Notify;

// =================================================================================
// Harness
// =================================================================================

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn dev() -> ProfileId {
    ProfileId::parse("dev").unwrap()
}

fn ops() -> ProfileId {
    ProfileId::parse("ops").unwrap()
}

fn owner(attended: bool) -> Caller {
    let context = CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    };
    if attended {
        Caller {
            context,
            attendance: Attendance::Attended { since: t0() },
            interaction: InteractionMode::Interactive,
        }
    } else {
        Caller::unattended(context)
    }
}

fn pair(d: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn ssh() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: "2026-11-19T09:00:00Z".parse().unwrap(),
        offline_until: "2026-11-18T11:00:00Z".parse().unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        // A synthetic canary that must never reach an envelope or an event.
        credential_ref: format!("{CANARY_PREFIX}u3_fixture"),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
}

fn policy(id: &str, profile: ProfileId, hosts: &[&str]) -> StandingPolicy {
    StandingPolicy {
        id: PolicyId::parse(id).unwrap(),
        revision: PolicyRevision(1),
        profile,
        workspace: None,
        scope: Scope {
            pairs: hosts.iter().map(|h| pair(h)).collect(),
            capabilities: ssh(),
        },
        environments: [env_id()].into_iter().collect(),
        max_window: 2 * HOUR,
        pause: PauseState::Active,
        cutoff_at: None,
        source: PolicySource::SetupDefault,
        lock_behavior: Default::default(),
        connection: Default::default(),
        default: false,
    }
}

/// Profiles `dev` (h1–h3) and `ops` (o1); personal policies `pol-dev` (h1, h2) and
/// `pol-ops` (o1), each with a 2 h window; the environment permits automatic activation.
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
            for (id, hosts) in [(dev(), vec!["h1", "h2", "h3"]), (ops(), vec!["o1"])] {
                tx.upsert_profile(&ProfileDefinition {
                    id,
                    revision: 1,
                    scope: Scope {
                        pairs: hosts.iter().map(|h| pair(h)).collect(),
                        capabilities: ssh(),
                    },
                    label: None,
                })?;
            }
            tx.upsert_policy(&policy("pol-dev", dev(), &["h1", "h2"]), false)?;
            tx.upsert_policy(&policy("pol-ops", ops(), &["o1"]), false)?;
            Ok(())
        })
        .unwrap();
}

/// Counts pipeline entries into `Coalesce` (the production `StageHook`).
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
    hook: Arc<CountCoalesce>,
    ops: Operations,
}

impl World {
    async fn new() -> Self {
        Self::with_script(vec![FakeStep::Prepare(outcome())]).await
    }

    /// With the fake's `prepare` script (an exhausted script repeats its last step).
    async fn with_script(script: Vec<FakeStep>) -> Self {
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
            remote_credential_effect: false,
        };
        let fake = FakeCredentialAdapter::new(descriptor, script);
        let hook = Arc::new(CountCoalesce::default());
        let ops = Operations::start(config(&store, &clock, &sync, &fake, &hook))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
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
            &self.fake,
            &self.hook,
        ))
        .await
        .unwrap();
        self.ops.tick().await.unwrap();
    }

    fn grant(&self, id: &GrantId) -> GrantSnapshot {
        self.store.transaction(|tx| tx.grant(id)).unwrap().unwrap()
    }

    fn usable(&self, id: &GrantId) -> bool {
        self.grant(id).state.permits_use()
    }

    fn binding_state(&self, id: &BindingId) -> BindingState {
        self.store
            .transaction(|tx| tx.binding(id))
            .unwrap()
            .unwrap()
            .state
    }

    fn pending_decisions(&self) -> usize {
        self.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .len()
    }

    fn policy(&self, id: &str) -> StandingPolicy {
        self.store
            .transaction(|tx| tx.policy(&PolicyId::parse(id).unwrap()))
            .unwrap()
            .unwrap()
    }

    fn operations(&self) -> u64 {
        self.store
            .transaction(|tx| tx.table_counts())
            .unwrap()
            .operations
    }

    async fn ensure(
        &self,
        profile: &ProfileId,
        rid: &str,
        work: &str,
        hosts: &[&str],
        until: Option<DeadlineIntent>,
    ) -> OpResult<EnsureData> {
        let r = self
            .ops
            .ensure(&owner(false), request(profile, rid, work, hosts, until))
            .await;
        scan(&r);
        r
    }

    async fn ready(
        &self,
        profile: &ProfileId,
        rid: &str,
        work: &str,
        hosts: &[&str],
    ) -> EnsureData {
        match self.ensure(profile, rid, work, hosts, None).await {
            Ok(c) => {
                assert_eq!(c.code, Code::AccessReady, "{rid}");
                c.data
            }
            Err(e) => panic!("ensure {rid}: {}: {}", e.code, e.message),
        }
    }

    async fn delegate(&self, parent: &BindingId, rid: &str, work: &str) -> OpResult<EnsureData> {
        let r = self
            .ops
            .delegate(
                &owner(false),
                DelegateRequest {
                    parent_binding_id: parent.clone(),
                    scope: [pair("h1")].into_iter().collect(),
                    until: None,
                    work_id: WorkId::parse(work).unwrap(),
                    request_id: RequestId::parse(rid).unwrap(),
                    required_capabilities: RequiredCapabilities::default(),
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
                &owner(false),
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

    async fn act(&self, attended: bool, action: PolicyAction) -> OpResult<serde_json::Value> {
        let r = self.ops.policy(&owner(attended), action).await;
        scan(&r);
        r
    }

    async fn decide(
        &self,
        attended: bool,
        id: &DecisionId,
        verdict: Verdict,
    ) -> OpResult<serde_json::Value> {
        let r = self
            .ops
            .decide(
                &owner(attended),
                DecideRequest {
                    decision_id: id.clone(),
                    verdict,
                },
            )
            .await;
        scan(&r);
        r
    }

    async fn stop_work(&self, rid: &str, work: &str) -> OpResult<RevokeData> {
        let r = self
            .ops
            .revoke(
                &owner(false),
                RevokeRequest {
                    grant_id: None,
                    request_id: RequestId::parse(rid).unwrap(),
                    target: Some(RevokeTarget::Work {
                        environment: None,
                        work_id: WorkId::parse(work).unwrap(),
                    }),
                },
            )
            .await;
        scan(&r);
        r
    }
}

fn request(
    profile: &ProfileId,
    rid: &str,
    work: &str,
    hosts: &[&str],
    until: Option<DeadlineIntent>,
) -> EnsureRequest {
    EnsureRequest {
        profile: Some(profile.clone()),
        profile_revision: None,
        scope: hosts.iter().map(|h| pair(h)).collect(),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(rid).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::default(),
        connection: None,
        context: None,
        covered_only: false,
    }
}

fn config(
    store: &Arc<Store>,
    clock: &Arc<VirtualClock>,
    sync: &Arc<ScriptedTimeSync>,
    fake: &Arc<FakeCredentialAdapter>,
    hook: &Arc<CountCoalesce>,
) -> OperationsConfig {
    OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: hook.clone(),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
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

/// The decision a widening answered with (`APPROVAL_REQUIRED` / `INTERACTION_REQUIRED`).
fn decision_of<T: std::fmt::Debug>(r: &OpResult<T>, expected: Code) -> DecisionId {
    let e = r
        .as_ref()
        .expect_err("a widening answers with its decision");
    assert_eq!(e.code, expected, "{}", e.message);
    DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap()
}

fn profile_target(p: ProfileId) -> Option<PolicyTarget> {
    Some(PolicyTarget::Profile { profile: p })
}

// =================================================================================
// Journeys
// =================================================================================

/// A05 (spec §6.1; ADR-0011 §3.3, §7.2): a work ID's grant expires, and the same work ID is
/// refused `CREDENTIAL_EXPIRED`; distinct work proceeds under the standing policy with **no
/// decision** (automatic re-entry); after a hard cutoff, the live grant ends and fresh work
/// IDs, the old ones and a restarted runtime are all refused `POLICY_CUTOFF` (or, for an
/// ended work, its expiry); clearing the cutoff needs an attended decision, which neither a
/// requester nor an unattended session can complete.
///
/// A05's rows for the shell hook (U4) and ordinary-`ssh` default activation (U5) are added
/// in later waves: they are activations of the same kind (fresh work IDs under the
/// standing policy), and this journey already shows that no fresh work ID passes a cutoff.
#[tokio::test]
async fn a05_expiry_reentry_and_hard_cutoff() {
    let mut w = World::new().await;
    let decisions = w.pending_decisions();
    // 1. A work ID's grant expires at its deadline.
    let a = match w
        .ensure(
            &dev(),
            "a05-1",
            "job-a",
            &["h1"],
            Some(DeadlineIntent::Duration("30m".into())),
        )
        .await
    {
        Ok(c) => c.data,
        Err(e) => panic!("{}: {}", e.code, e.message),
    };
    w.clock.advance(31 * MINUTE);
    w.ops.tick().await.unwrap();
    assert_eq!(w.grant(&a.grant_id).state, GrantState::Expired);
    // 2. The same work ID never extends: CREDENTIAL_EXPIRED.
    let again = w.ensure(&dev(), "a05-2", "job-a", &["h1"], None).await;
    assert_eq!(code_of(&again), Code::CredentialExpired);
    // 3. Distinct work re-enters under the standing policy, with no decision.
    let b = w.ready(&dev(), "a05-3", "job-b", &["h1"]).await;
    assert_ne!(b.grant_id, a.grant_id);
    assert_eq!(w.pending_decisions(), decisions, "re-entry asks nothing");
    // 4. A hard cutoff now, by profile: a narrowing, applied at once without a decision;
    //    the live grant's bound has passed, so it ends now.
    let now = w.clock.wall();
    let cut = w
        .act(
            false,
            PolicyAction::Cutoff {
                policy_id: None,
                at: now,
                target: profile_target(dev()),
            },
        )
        .await
        .unwrap();
    assert_eq!(cut.data["changed"], true);
    assert_eq!(w.policy("pol-dev").cutoff_at, Some(now));
    assert_eq!(
        w.policy("pol-ops").cutoff_at,
        None,
        "another profile is not in the target"
    );
    assert!(!w.usable(&b.grant_id), "a grant past the cutoff ends");
    // Fresh work IDs, and the old ones, are refused.
    for (rid, work) in [("a05-4", "job-c"), ("a05-5", "job-d")] {
        let r = w.ensure(&dev(), rid, work, &["h1"], None).await;
        assert_eq!(code_of(&r), Code::PolicyCutoff, "{work}");
    }
    let old = w.ensure(&dev(), "a05-6", "job-b", &["h1"], None).await;
    assert!(code_of(&old) != Code::AccessReady);
    let rebind = w.bind(&b.binding_id, "a05-7").await;
    assert_eq!(code_of(&rebind), Code::CredentialExpired);
    // 5. A restarted runtime refuses as well.
    w.restart().await;
    let r = w.ensure(&dev(), "a05-8", "job-e", &["h1"], None).await;
    assert_eq!(code_of(&r), Code::PolicyCutoff);
    assert_eq!(
        w.pending_decisions(),
        decisions,
        "a refused activation asks nothing"
    );
    // 6. Clearing needs an attended decision: a requester's attempt is a pending record
    //    only, an unattended session cannot complete it, and nothing lifts meanwhile.
    let pending = w
        .act(
            false,
            PolicyAction::ClearCutoff {
                policy_id: None,
                target: profile_target(dev()),
            },
        )
        .await;
    let dec = decision_of(&pending, Code::InteractionRequired);
    let unattended = w.decide(false, &dec, Verdict::Approve).await;
    assert_eq!(code_of(&unattended), Code::InteractionRequired);
    assert_eq!(w.policy("pol-dev").cutoff_at, Some(now));
    let r = w.ensure(&dev(), "a05-9", "job-f", &["h1"], None).await;
    assert_eq!(code_of(&r), Code::PolicyCutoff);
    w.decide(true, &dec, Verdict::Approve).await.unwrap();
    assert_eq!(w.policy("pol-dev").cutoff_at, None);
    let fresh = w.ready(&dev(), "a05-10", "job-g", &["h1"]).await;
    assert!(w.usable(&fresh.grant_id));
    // Ended grants stay ended.
    assert!(!w.usable(&a.grant_id) && !w.usable(&b.grant_id));
}

/// A05 and spec §5.6 ("stop Heimdall access for this profile"; ADR-0011 §7.2 "Stop (policy
/// target)"): `stop {profile}` pauses the profile's policy and revokes, now and with the
/// cascade, every live grant resting on it (two jobs and a delegated child); new
/// activations, a restart and the old work IDs are refused; another profile is untouched;
/// only an attended `resume` lifts it, and the ended grants stay ended.
#[tokio::test]
async fn a05_stop_profile_revokes_and_blocks_until_resume() {
    let mut w = World::new().await;
    let a = w.ready(&dev(), "st-1", "job-a", &["h1"]).await;
    let b = w.ready(&dev(), "st-2", "job-b", &["h2"]).await;
    let child = w
        .delegate(&a.binding_id, "st-3", "job-a.child")
        .await
        .unwrap()
        .data;
    let other = w.ready(&ops(), "st-4", "job-o", &["o1"]).await;
    let stopped = w
        .act(
            false,
            PolicyAction::Stop {
                target: PolicyTarget::Profile { profile: dev() },
            },
        )
        .await
        .unwrap();
    // Paused and revoked in the one action, without a decision.
    let p = w.policy("pol-dev");
    assert!(matches!(p.pause, PauseState::Paused { .. }));
    let revoked: BTreeSet<String> = stopped.data["revoked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap().to_owned())
        .collect();
    for g in [&a.grant_id, &b.grant_id, &child.grant_id] {
        assert!(revoked.contains(g.as_str()), "{g} is revoked by the stop");
        assert!(!w.usable(g), "{g} ends now");
        assert!(
            matches!(w.grant(g).state, GrantState::Revoking | GrantState::Revoked),
            "{g}: revoked, not merely paused"
        );
    }
    assert!(w.usable(&other.grant_id), "another profile is untouched");
    assert!(
        !matches!(w.policy("pol-ops").pause, PauseState::Paused { .. }),
        "another profile's policy is untouched"
    );
    // New activations (fresh IDs), the old work IDs and the old bindings are refused.
    let fresh = w.ensure(&dev(), "st-5", "job-x", &["h1"], None).await;
    assert_eq!(code_of(&fresh), Code::PolicyPaused);
    let old = w.ensure(&dev(), "st-6", "job-a", &["h1"], None).await;
    assert!(code_of(&old) != Code::AccessReady);
    let rebind = w.bind(&a.binding_id, "st-7").await;
    assert!(code_of(&rebind) != Code::AccessReady);
    let o = w.ensure(&ops(), "st-8", "job-y", &["o1"], None).await;
    assert_eq!(
        code_of(&o),
        Code::AccessReady,
        "another profile still activates"
    );
    // A restart does not resurrect it (the supervisor and recovery are activations).
    w.restart().await;
    let fresh = w.ensure(&dev(), "st-9", "job-z", &["h1"], None).await;
    assert_eq!(code_of(&fresh), Code::PolicyPaused);
    for g in [&a.grant_id, &b.grant_id, &child.grant_id] {
        assert!(!w.usable(g));
    }
    // Only an attended `resume` lifts it: one decision, then approval.
    let resume = w
        .act(
            true,
            PolicyAction::Resume {
                policy_id: None,
                target: profile_target(dev()),
            },
        )
        .await;
    let dec = decision_of(&resume, Code::ApprovalRequired);
    assert!(matches!(
        w.policy("pol-dev").pause,
        PauseState::Paused { .. }
    ));
    w.decide(true, &dec, Verdict::Approve).await.unwrap();
    assert_eq!(w.policy("pol-dev").pause, PauseState::Active);
    let after = w.ready(&dev(), "st-10", "job-w", &["h1"]).await;
    assert!(w.usable(&after.grant_id));
    // Ended grants stay ended.
    for g in [&a.grant_id, &b.grant_id, &child.grant_id] {
        assert!(!w.usable(g), "{g} stays ended after the resume");
    }
}

/// ADR-0011 §7.2 "Stop (work)": jobs A and B share one grant (concurrent equivalent
/// requests are single-flight with separate references), job C has its own. Stopping A
/// drops only A's reference: the shared grant and B keep working, and C is untouched.
/// A's work ID never reactivates (`work_stopped`, nothing written). Stopping C, whose
/// grant nobody shares, revokes that grant.
#[tokio::test]
async fn stop_one_job_leaves_the_other() {
    // The first `prepare` hangs until released, so B joins A's flight (spec §8.2).
    let w = World::with_script(vec![
        FakeStep::HangBeforeEffect(outcome()),
        FakeStep::Prepare(outcome()),
    ])
    .await;
    let until = || Some(DeadlineIntent::Absolute("2026-11-18T10:00:00Z".into()));
    let spawn = |rid: &'static str, work: &'static str| {
        let ops = w.ops.clone();
        let req = request(&dev(), rid, work, &["h1"], until());
        tokio::spawn(async move { ops.ensure(&owner(false), req).await })
    };
    let ta = spawn("job-1", "job-a");
    for _ in 0..2000 {
        if w.fake.hangs_entered() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(w.fake.hangs_entered(), 1, "A is preparing");
    let tb = spawn("job-2", "job-b");
    // B joins A's flight in the poll in which it enters `Coalesce`.
    while w.hook.entries.load(Ordering::SeqCst) < 2 {
        w.hook.changed.notified().await;
    }
    w.fake.release_hangs();
    let a = ta.await.unwrap().unwrap().data;
    let b = tb.await.unwrap().unwrap().data;
    assert_eq!(a.grant_id, b.grant_id, "A and B share one grant");
    assert_ne!(a.binding_id, b.binding_id);
    let c = w.ready(&dev(), "job-3", "job-c", &["h2"]).await;
    assert_ne!(c.grant_id, a.grant_id);
    // Stop job A.
    let stopped = w.stop_work("stop-a", "job-a").await.unwrap();
    assert!(stopped.data.local_applied);
    assert!(
        w.usable(&a.grant_id),
        "the shared grant keeps the other's reference"
    );
    assert_eq!(w.binding_state(&a.binding_id), BindingState::Released);
    assert_eq!(w.binding_state(&b.binding_id), BindingState::Active);
    let refs = w
        .store
        .transaction(|tx| tx.grant_references(&a.grant_id))
        .unwrap();
    assert_eq!(refs.len(), 1, "only B's reference is left");
    assert_eq!(refs[0].binding, b.binding_id);
    // B keeps working; C is untouched.
    assert_eq!(
        code_of(&w.bind(&b.binding_id, "bind-b").await),
        Code::AccessReady
    );
    assert_eq!(
        code_of(&w.bind(&c.binding_id, "bind-c").await),
        Code::AccessReady
    );
    // A never reactivates: a new request or a bind for it is `work_stopped`, nothing
    // written.
    let ops_before = w.operations();
    let r = w.ensure(&dev(), "job-4", "job-a", &["h1"], until()).await;
    let e = r.as_ref().unwrap_err();
    assert_eq!(e.code, Code::CredentialExpired);
    assert_eq!(e.reason.as_deref(), Some(reason::WORK_STOPPED));
    let r = w.bind(&a.binding_id, "bind-a").await;
    assert_eq!(
        r.as_ref().unwrap_err().reason.as_deref(),
        Some(reason::WORK_STOPPED)
    );
    let r = w.delegate(&b.binding_id, "job-5", "job-a").await;
    assert_eq!(
        r.as_ref().unwrap_err().reason.as_deref(),
        Some(reason::WORK_STOPPED)
    );
    assert_eq!(
        w.operations(),
        ops_before,
        "nothing written for a stopped work ID"
    );
    // The stop replays its recorded result.
    let replay = w.stop_work("stop-a", "job-a").await.unwrap();
    assert_eq!(replay.data, stopped.data);
    // Stop job C: nobody shares its grant, so the grant is revoked.
    w.stop_work("stop-c", "job-c").await.unwrap();
    assert!(
        !w.usable(&c.grant_id),
        "an unshared grant of a stopped job is revoked"
    );
    assert!(w.usable(&b.grant_id), "B is unaffected");
    assert_eq!(
        code_of(&w.bind(&b.binding_id, "bind-b2").await),
        Code::AccessReady
    );
}

/// The orchestrator's ruling I-1: `access ensure` and then `run` with the same work ID (an
/// `ensure` of that work ID, then a bind) attaches the run to the ensure's grant as a
/// separate reference, with no second preparation; a differing pin keeps M01's behaviour
/// (a separate grant, capped at the work's first deadline).
#[tokio::test]
async fn ensure_then_run_same_work_id_reuses_the_grant() {
    let w = World::new().await;
    let ensured = w.ready(&dev(), "acc-1", "job-r", &["h1"]).await;
    assert_eq!(w.fake.effect_count(), 1);
    w.clock.advance(MINUTE);
    // `run --work-id job-r`: its ensure (no `--until`), then the launch bind.
    let run = w.ready(&dev(), "run-1", "job-r", &["h1"]).await;
    assert_eq!(run.grant_id, ensured.grant_id, "the same grant");
    assert_ne!(run.binding_id, ensured.binding_id, "a separate reference");
    assert_eq!(run.expires_at, ensured.expires_at);
    assert_eq!(w.fake.effect_count(), 1, "no second preparation");
    assert_eq!(
        code_of(&w.bind(&run.binding_id, "run-1-bind").await),
        Code::AccessReady
    );
    let refs = w
        .store
        .transaction(|tx| tx.grant_references(&ensured.grant_id))
        .unwrap();
    assert_eq!(refs.len(), 2, "two references on the one grant");
    // A differing pin (another scope): a separate grant, capped at the work's first
    // deadline.
    let wider = w.ready(&dev(), "run-2", "job-r", &["h1", "h2"]).await;
    assert_ne!(wider.grant_id, ensured.grant_id);
    assert_eq!(
        wider.expires_at, ensured.expires_at,
        "capped at the first deadline"
    );
    assert_eq!(w.fake.effect_count(), 2);
    // Another work ID with the same request never attaches (no flight in progress).
    let other = w.ready(&dev(), "run-3", "job-s", &["h1"]).await;
    assert_ne!(other.grant_id, ensured.grant_id);
}

/// ADR-0011 §7.3 "Targets" and I5, at the boundaries the model does not reach: an empty
/// target writes nothing (`NOT_FOUND`, `policy_target_empty`); a widening's one record
/// lists the policies it widens, and a listed policy revised before the approval makes it
/// stale **without consuming it**; a fresh request then lists the current set and its
/// approval changes only that action's own field; a cutoff that narrows one policy and
/// widens another applies the narrowing now and records the widening (effect `partial`);
/// under uncertain time a narrowing still applies and a widening is refused.
#[tokio::test]
async fn targeted_actions_resolve_their_set_in_the_applying_transaction() {
    use heimdall_contract::envelope::EffectStatus;
    use heimdall_domain::decision::DecisionState;
    let w = World::new().await;
    let decision_state = |id: &DecisionId| {
        w.store
            .transaction(|tx| tx.decision(id))
            .unwrap()
            .unwrap()
            .state
    };
    // An empty target: nothing is written.
    let revisions = (w.policy("pol-dev").revision, w.policy("pol-ops").revision);
    let decisions = w.pending_decisions();
    for action in [
        PolicyAction::Pause {
            policy_id: None,
            target: profile_target(ProfileId::parse("nobody").unwrap()),
        },
        PolicyAction::Stop {
            target: PolicyTarget::Policy {
                policy_id: PolicyId::parse("pol-missing").unwrap(),
            },
        },
        PolicyAction::Resume {
            policy_id: None,
            target: Some(PolicyTarget::Workspace {
                workspace: heimdall_contract::ids::WorkspaceId::from_random_bytes([5; 16]),
            }),
        },
    ] {
        let r = w.act(true, action).await;
        let e = r.as_ref().unwrap_err();
        assert_eq!(e.code, Code::NotFound);
        assert_eq!(e.reason.as_deref(), Some(reason::POLICY_TARGET_EMPTY));
    }
    assert_eq!(
        (w.policy("pol-dev").revision, w.policy("pol-ops").revision),
        revisions
    );
    assert_eq!(w.pending_decisions(), decisions);
    // Pause both; one `resume` record lists both.
    w.act(
        false,
        PolicyAction::Pause {
            policy_id: None,
            target: Some(PolicyTarget::All),
        },
    )
    .await
    .unwrap();
    let resume = || PolicyAction::Resume {
        policy_id: None,
        target: Some(PolicyTarget::All),
    };
    let first = decision_of(&w.act(true, resume()).await, Code::ApprovalRequired);
    assert_eq!(
        w.pending_decisions(),
        decisions + 1,
        "one record for the set"
    );
    // A listed policy is revised (an M01 cutoff on `pol-ops`): stale, not consumed.
    let hour = w
        .clock
        .wall()
        .checked_add(jiff::SignedDuration::from_hours(1))
        .unwrap();
    w.act(
        false,
        PolicyAction::Cutoff {
            policy_id: Some(PolicyId::parse("pol-ops").unwrap()),
            at: hour,
            target: None,
        },
    )
    .await
    .unwrap();
    let stale = w.decide(true, &first, Verdict::Approve).await;
    assert_eq!(code_of(&stale), Code::DecisionStale);
    assert_eq!(
        decision_state(&first),
        DecisionState::Pending,
        "not consumed"
    );
    assert!(matches!(
        w.policy("pol-dev").pause,
        PauseState::Paused { .. }
    ));
    // A fresh request lists the current set; approval resumes both and clears no cutoff.
    let second = decision_of(&w.act(true, resume()).await, Code::ApprovalRequired);
    assert_ne!(second, first);
    w.decide(true, &second, Verdict::Approve).await.unwrap();
    assert_eq!(w.policy("pol-dev").pause, PauseState::Active);
    assert_eq!(w.policy("pol-ops").pause, PauseState::Active);
    assert_eq!(
        w.policy("pol-ops").cutoff_at,
        Some(hour),
        "resume never clears a cutoff"
    );
    // A cutoff in two hours narrows `pol-dev` (none) now and widens `pol-ops` (in one).
    let two = hour
        .checked_add(jiff::SignedDuration::from_hours(1))
        .unwrap();
    let mixed = w
        .act(
            true,
            PolicyAction::Cutoff {
                policy_id: None,
                at: two,
                target: Some(PolicyTarget::All),
            },
        )
        .await;
    let dec = decision_of(&mixed, Code::ApprovalRequired);
    assert_eq!(
        mixed.as_ref().unwrap_err().effect_status,
        EffectStatus::Partial
    );
    assert_eq!(
        w.policy("pol-dev").cutoff_at,
        Some(two),
        "the narrowing part applied"
    );
    assert_eq!(
        w.policy("pol-ops").cutoff_at,
        Some(hour),
        "the widening part waits"
    );
    w.decide(true, &dec, Verdict::Approve).await.unwrap();
    assert_eq!(w.policy("pol-ops").cutoff_at, Some(two));
    assert_eq!(
        w.policy("pol-dev").pause,
        PauseState::Active,
        "a cutoff never pauses"
    );
    // Uncertain time (the wall clock jumps within the boot): a narrowing still applies,
    // a widening is refused with nothing written.
    w.clock.set_wall(two);
    w.act(
        false,
        PolicyAction::Pause {
            policy_id: None,
            target: profile_target(dev()),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        w.policy("pol-dev").pause,
        PauseState::Paused { .. }
    ));
    let pending = w.pending_decisions();
    let refused = w
        .act(
            true,
            PolicyAction::Resume {
                policy_id: None,
                target: profile_target(dev()),
            },
        )
        .await;
    assert_eq!(code_of(&refused), Code::TimeUncertain);
    assert_eq!(
        w.pending_decisions(),
        pending,
        "no record under uncertain time"
    );
    assert!(matches!(
        w.policy("pol-dev").pause,
        PauseState::Paused { .. }
    ));
}

/// ADR-0006 §17.9 C2: the result of every targeted action is the typed
/// [`PolicyTargetResult`]: it decodes from what the runtime answers and re-encodes to
/// exactly those bytes (so the contract type is the result's shape, not a second one):
/// `pause` of every policy, a `cutoff` (its time shown), and a `stop` with the grants it
/// revoked, where only `stop` carries `revoked`.
#[tokio::test]
async fn targeted_results_decode_into_the_typed_result() {
    let w = World::new().await;
    let grant = w.ready(&dev(), "c2-1", "job-a", &["h1"]).await.grant_id;
    let typed = |data: &serde_json::Value| -> PolicyTargetResult {
        let t: PolicyTargetResult = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(&serde_json::to_value(&t).unwrap(), data, "exact round trip");
        t
    };
    let paused = w
        .act(
            false,
            PolicyAction::Pause {
                policy_id: None,
                target: Some(PolicyTarget::All),
            },
        )
        .await
        .unwrap();
    let t = typed(&paused.data);
    assert_eq!(t.target, PolicyTarget::All);
    assert!(t.changed && t.revoked.is_none());
    assert_eq!(t.policies.len(), 2);
    assert!(t.policies.iter().all(|p| p.paused && p.changed));
    let at = w
        .clock
        .wall()
        .checked_add(jiff::SignedDuration::from_hours(1))
        .unwrap();
    let cutoff = w
        .act(
            false,
            PolicyAction::Cutoff {
                policy_id: None,
                at,
                target: profile_target(ops()),
            },
        )
        .await
        .unwrap();
    let t = typed(&cutoff.data);
    assert_eq!(t.policies.len(), 1);
    assert_eq!(t.policies[0].cutoff_at, Some(at));
    let stopped = w
        .act(
            false,
            PolicyAction::Stop {
                target: PolicyTarget::Profile { profile: dev() },
            },
        )
        .await
        .unwrap();
    let t = typed(&stopped.data);
    assert!(t.changed);
    assert_eq!(t.revoked, Some(vec![grant]));
    assert_eq!(t.policies[0].policy_id, PolicyId::parse("pol-dev").unwrap());
}

/// ADR-0006 §17.9 C1: the decision view of a targeted widening lists the policies and
/// revisions fixed at its creation (read from its decision basis); the view of a record
/// without one (an M01 single-policy `resume`) has no `policies` key.
#[tokio::test]
async fn a_targeted_widenings_decision_view_lists_its_policies() {
    let w = World::new().await;
    w.act(
        false,
        PolicyAction::Pause {
            policy_id: None,
            target: Some(PolicyTarget::All),
        },
    )
    .await
    .unwrap();
    let targeted = decision_of(
        &w.act(
            true,
            PolicyAction::Resume {
                policy_id: None,
                target: Some(PolicyTarget::All),
            },
        )
        .await,
        Code::ApprovalRequired,
    );
    let single = decision_of(
        &w.act(
            true,
            PolicyAction::Resume {
                policy_id: Some(PolicyId::parse("pol-dev").unwrap()),
                target: None,
            },
        )
        .await,
        Code::ApprovalRequired,
    );
    let view = w
        .ops
        .inspect(
            &owner(true),
            InspectRequest {
                subject: InspectSubject::Decisions,
                preview: None,
                cwd: None,
                redact: false,
            },
        )
        .await
        .unwrap()
        .data;
    let find = |id: &DecisionId| {
        view["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["decision_id"] == id.as_str())
            .unwrap()
            .clone()
    };
    let listed = serde_json::json!([
        {"policy_id": "pol-dev", "revision": w.policy("pol-dev").revision.0},
        {"policy_id": "pol-ops", "revision": w.policy("pol-ops").revision.0},
    ]);
    assert_eq!(find(&targeted)["policies"], listed);
    assert!(find(&single).get("policies").is_none());
}
