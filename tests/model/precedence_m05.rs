//! ⟨M05⟩ U3 model suite: block precedence over random traces (ADR-0011 §7.1–§7.3; spec §5.6,
//! §6.1, §13.5; plan §6.3 #3; R-AU-02; the orchestrator's ruling I-1).
//!
//! It extends the trace of `model_revocation`'s
//! `tombstones_and_cutoffs_are_never_defeated_by_stale_callbacks_or_new_ids` (fresh request
//! and work IDs against a revoke, a pause and a cutoff) with what M05 adds: `stop` of a work
//! and of a policy target, targeted `pause` and `cutoff`, `resume` and `clear_cutoff`
//! decisions (attended approval, denial, expiry, an unattended attempt), delegation,
//! restarts, and **background triggers**, modelled as fresh-work-ID `ensure`s from an
//! unattended, non-interactive caller (the shell hook and ordinary-`ssh` activation are
//! such requests; their own surfaces land with U4 and U5). That harness lives in another
//! crate's test target (`heimdall-app`) and M01's convention forbids `#[path]` inclusion, so
//! the few lines of world set-up are repeated here.
//!
//! Two profiles, `dev` and `ops`, each with one personal policy (2 h window). After **every**
//! step:
//!
//! * no `ensure` or `delegate` activates while its profile is paused, stopped or past a
//!   cutoff, whatever the request or work ID, and the refusal says which
//!   (`POLICY_PAUSED`, else `POLICY_CUTOFF`); unblocked covered work always activates;
//! * no grant outlives `min(window, parent, cutoff)` (checked after a tick or restart, when
//!   ended grants have been detected), and no `bind` admits past it;
//! * a grant once ended (terminal or `revoking`) never becomes usable again, and a stopped
//!   work ID never activates again (`work_stopped`, nothing written) nor keeps a usable
//!   binding;
//! * binding pins never change;
//! * the stored pause and cutoff of each policy are exactly the model's: `resume` never
//!   clears a cutoff, `clear_cutoff` never resumes a pause, a denied, expired or unattended
//!   decision changes nothing, and a widening applies only to the policies its record
//!   listed;
//! * a background trigger never creates a decision;
//! * I-1: an `ensure` of a work ID whose usable grant has every pin equal (the same scope,
//!   and the deadline it resolves to) attaches to that grant and creates no grant and no
//!   preparation.
//!
//! Seeds: fixed unless `PROPTEST_RNG_SEED` is set; failures persist next to this file.
//! "Restart" is an in-process reconstruction (a new `Operations` over the same store).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
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
    BindForm, BindRequest, DecideRequest, DelegateRequest, EnsureData, EnsureRequest,
    InteractionMode, PolicyAction, RefreshDependency, RequiredCapabilities, RevokeData,
    RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::trust::{PolicyTarget, RevokeTarget};
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::binding::{BindingRecord, BindingState};
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
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

// =================================================================================
// Harness
// =================================================================================

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const WINDOW: Duration = Duration::from_secs(2 * 3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
        .unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

/// Profile `i` (`dev`, `ops`), its policy, and the host its work asks for.
const PROFILES: [(&str, &str, &str); 2] = [("dev", "pol-dev", "h1"), ("ops", "pol-ops", "o1")];

fn profile(i: usize) -> ProfileId {
    ProfileId::parse(PROFILES[i].0).unwrap()
}

fn policy_id(i: usize) -> PolicyId {
    PolicyId::parse(PROFILES[i].1).unwrap()
}

fn host(i: usize) -> AccessPair {
    pair(PROFILES[i].2)
}

fn caller(attended: bool) -> Caller {
    let context = CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
        remote_client: None,
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
        usable_until: "2026-11-20T09:00:00Z".parse().unwrap(),
        offline_until: "2026-11-20T09:00:00Z".parse().unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: EnforcementEvidence::unknown(),
        credential_ref: format!("{CANARY_PREFIX}u3_model"),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
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
            for i in 0..PROFILES.len() {
                let scope = Scope {
                    pairs: [host(i)].into_iter().collect(),
                    capabilities: ssh(),
                };
                tx.upsert_profile(&ProfileDefinition {
                    id: profile(i),
                    revision: 1,
                    scope: scope.clone(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: policy_id(i),
                        revision: PolicyRevision(1),
                        profile: profile(i),
                        workspace: None,
                        scope,
                        environments: [env_id()].into_iter().collect(),
                        max_window: WINDOW,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: Default::default(),
                        connection: Default::default(),
                        default: false,
                    },
                    false,
                )?;
            }
            Ok(())
        })
        .unwrap();
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    ops: Operations,
}

fn config(
    w: (
        &Arc<Store>,
        &Arc<VirtualClock>,
        &Arc<ScriptedTimeSync>,
        &Arc<FakeCredentialAdapter>,
    ),
) -> OperationsConfig {
    OperationsConfig {
        store: w.0.clone(),
        clock: w.1.clone(),
        time_sync: w.2.clone(),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![w.3.clone() as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    }
}

impl World {
    async fn new() -> Self {
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
        let fake = FakeCredentialAdapter::new(descriptor, vec![FakeStep::Prepare(outcome())]);
        let ops = Operations::start(config((&store, &clock, &sync, &fake)))
            .await
            .unwrap();
        Self {
            store,
            clock,
            sync,
            fake,
            ops,
        }
    }

    async fn restart(&mut self) {
        self.ops = Operations::start(config((&self.store, &self.clock, &self.sync, &self.fake)))
            .await
            .unwrap();
    }

    fn now(&self) -> Timestamp {
        self.clock.wall()
    }

    fn grant(&self, id: &GrantId) -> GrantSnapshot {
        self.store.transaction(|tx| tx.grant(id)).unwrap().unwrap()
    }

    fn policy(&self, i: usize) -> StandingPolicy {
        self.store
            .transaction(|tx| tx.policy(&policy_id(i)))
            .unwrap()
            .unwrap()
    }

    fn work_bindings(&self, work: &str) -> Vec<BindingRecord> {
        let work = WorkId::parse(work).unwrap();
        self.store
            .transaction(|tx| tx.bindings_for_work(&env_id(), &work))
            .unwrap()
    }

    fn bindings(&self, works: &[Work]) -> Vec<BindingRecord> {
        works
            .iter()
            .flat_map(|w| self.work_bindings(&w.id))
            .collect()
    }

    fn pending_decisions(&self) -> usize {
        self.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .len()
    }

    fn counts(&self) -> (u64, u64) {
        let c = self.store.transaction(|tx| tx.table_counts()).unwrap();
        (c.operations, c.grants)
    }

    async fn ensure(
        &self,
        attended: bool,
        rid: &str,
        work: &str,
        p: usize,
    ) -> OpResult<EnsureData> {
        let interaction = if attended {
            InteractionMode::Interactive
        } else {
            InteractionMode::NonInteractive
        };
        let r = self
            .ops
            .ensure(
                &caller(attended),
                EnsureRequest {
                    profile: Some(profile(p)),
                    profile_revision: None,
                    scope: [host(p)].into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse(work).unwrap(),
                    until: None,
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(rid).unwrap(),
                    interaction,
                    wait: WaitMode::default(),
                    connection: None,
                    context: None,
                    covered_only: false,
                },
            )
            .await;
        scan(&r);
        r
    }

    async fn delegate(
        &self,
        parent: &BindingId,
        p: usize,
        rid: &str,
        work: &str,
    ) -> OpResult<EnsureData> {
        let r = self
            .ops
            .delegate(
                &caller(false),
                DelegateRequest {
                    parent_binding_id: parent.clone(),
                    scope: [host(p)].into_iter().collect(),
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
                &caller(false),
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
        let r = self.ops.policy(&caller(attended), action).await;
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
                &caller(attended),
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
                &caller(false),
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

fn reason_of<T>(r: &OpResult<T>) -> Option<&str> {
    r.as_ref().err().and_then(|e| e.reason.as_deref())
}

fn block() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
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

// =================================================================================
// The model
// =================================================================================

/// A policy target and the profiles (by index) it names.
#[derive(Debug, Clone, Copy)]
enum Tgt {
    Dev,
    Ops,
    All,
    DevPolicy,
}

impl Tgt {
    fn target(self) -> PolicyTarget {
        match self {
            Tgt::Dev => PolicyTarget::Profile {
                profile: profile(0),
            },
            Tgt::Ops => PolicyTarget::Profile {
                profile: profile(1),
            },
            Tgt::All => PolicyTarget::All,
            Tgt::DevPolicy => PolicyTarget::Policy {
                policy_id: policy_id(0),
            },
        }
    }

    fn profiles(self) -> &'static [usize] {
        match self {
            Tgt::Dev | Tgt::DevPolicy => &[0],
            Tgt::Ops => &[1],
            Tgt::All => &[0, 1],
        }
    }
}

/// What happens to a widening's decision record.
#[derive(Debug, Clone, Copy)]
enum How {
    Approve,
    Deny,
    /// Its 15-minute lifetime passes, then an approval is attempted.
    Expire,
    /// An unattended session attempts the approval.
    Unattended,
}

#[derive(Debug, Clone)]
enum Step {
    /// A foreground `ensure` (attended, interactive): fresh request and work IDs.
    Fresh(u8),
    /// A background trigger: an unattended, non-interactive `ensure` of a fresh work ID.
    Background(u8),
    /// An `ensure` of a known work ID (fresh request ID, the same scope; ruling I-1).
    Again(u8),
    /// A delegation from a known work's latest binding, with a fresh work ID.
    Delegate(u8),
    /// A `bind` of a known work's latest binding.
    Bind(u8),
    /// `revoke {target: work}`.
    StopWork(u8),
    /// `stop {target}`.
    StopPolicy(Tgt),
    Pause(Tgt),
    /// A targeted cutoff at now + the offset (minutes).
    Cutoff(Tgt, i8, How),
    Resume(Tgt, How),
    Clear(Tgt, How),
    Advance(u8),
    Tick,
    Restart,
}

fn tgt() -> impl Strategy<Value = Tgt> {
    prop_oneof![
        Just(Tgt::Dev),
        Just(Tgt::Ops),
        Just(Tgt::All),
        Just(Tgt::DevPolicy)
    ]
}

fn how() -> impl Strategy<Value = How> {
    prop_oneof![
        3 => Just(How::Approve),
        1 => Just(How::Deny),
        1 => Just(How::Expire),
        1 => Just(How::Unattended),
    ]
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        3 => (0u8..2).prop_map(Step::Fresh),
        2 => (0u8..2).prop_map(Step::Background),
        3 => any::<u8>().prop_map(Step::Again),
        1 => any::<u8>().prop_map(Step::Delegate),
        2 => any::<u8>().prop_map(Step::Bind),
        1 => any::<u8>().prop_map(Step::StopWork),
        1 => tgt().prop_map(Step::StopPolicy),
        1 => tgt().prop_map(Step::Pause),
        1 => (tgt(), -10i8..60, how()).prop_map(|(t, m, h)| Step::Cutoff(t, m, h)),
        2 => (tgt(), how()).prop_map(|(t, h)| Step::Resume(t, h)),
        2 => (tgt(), how()).prop_map(|(t, h)| Step::Clear(t, h)),
        2 => (1u8..40).prop_map(Step::Advance),
        1 => Just(Step::Tick),
        1 => Just(Step::Restart),
    ]
}

/// A work that activated at least once.
#[derive(Debug, Clone)]
struct Work {
    id: String,
    profile: usize,
    /// A delegated child's work.
    child: bool,
}

/// What a binding pins (spec §6.1; ADR-0011 §5.1): never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    environment: EnvironmentId,
    grant: GrantId,
    work: WorkId,
    profile: ProfileId,
    profile_revision: u64,
    scope: Scope,
    mechanism: String,
    parent: Option<BindingId>,
}

impl Pin {
    fn of(b: &BindingRecord) -> Self {
        Self {
            environment: b.environment.clone(),
            grant: b.grant.clone(),
            work: b.work_id.clone(),
            profile: b.profile.clone(),
            profile_revision: b.profile_revision,
            scope: b.scope.clone(),
            mechanism: b.mechanism.clone(),
            parent: b.parent.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct Model {
    paused: [bool; 2],
    cutoff: [Option<Timestamp>; 2],
    works: Vec<Work>,
    stopped: BTreeSet<String>,
    /// Every grant a caller received, with its profile and parent.
    grants: BTreeMap<GrantId, (usize, Option<GrantId>)>,
    ended: BTreeSet<GrantId>,
    pins: BTreeMap<BindingId, Pin>,
}

impl Model {
    fn cut(&self, p: usize, now: Timestamp) -> bool {
        self.cutoff[p].is_some_and(|c| now >= c)
    }

    fn blocked(&self, p: usize, now: Timestamp) -> bool {
        self.paused[p] || self.cut(p, now)
    }

    /// The refusal of a new activation of profile `p` (M01's report order: the pause
    /// first, ADR-0006 §13.6 item 1).
    fn block_code(&self, p: usize) -> Code {
        if self.paused[p] {
            Code::PolicyPaused
        } else {
            Code::PolicyCutoff
        }
    }

    fn pick(&self, i: u8, top_only: bool) -> Option<Work> {
        let pool: Vec<&Work> = self
            .works
            .iter()
            .filter(|w| !top_only || !w.child)
            .collect();
        (!pool.is_empty()).then(|| pool[usize::from(i) % pool.len()].clone())
    }
}

/// A new activation's answer (ensure or delegate) against the model.
fn check_activation(
    m: &Model,
    p: usize,
    now: Timestamp,
    r: &OpResult<EnsureData>,
    what: &str,
) -> Result<(), TestCaseError> {
    if let Ok(c) = r {
        prop_assert_eq!(&c.code, &Code::AccessReady);
        prop_assert!(!m.blocked(p, now), "{}: activated while blocked", what);
        prop_assert!(
            c.data.expires_at <= plus(now, WINDOW),
            "{}: past the window",
            what
        );
        if let Some(cut) = m.cutoff[p] {
            prop_assert!(c.data.expires_at <= cut, "{}: past the cutoff", what);
        }
        prop_assert!(
            !m.ended.contains(&c.data.grant_id),
            "{}: an ended grant",
            what
        );
    }
    Ok(())
}

/// Apply a widening's decision as `how` says; returns whether it was approved.
async fn settle_widening(
    w: &World,
    r: &OpResult<serde_json::Value>,
    how: How,
) -> Result<bool, TestCaseError> {
    let Err(e) = r else {
        return Ok(false);
    };
    prop_assert_eq!(&e.code, &Code::ApprovalRequired, "{}", e.message);
    let dec = DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
    match how {
        How::Approve => {
            let d = w.decide(true, &dec, Verdict::Approve).await;
            prop_assert_eq!(code_of(&d), Code::Ok);
            Ok(true)
        }
        How::Deny => {
            let d = w.decide(true, &dec, Verdict::Deny).await;
            prop_assert_eq!(code_of(&d), Code::Ok);
            Ok(false)
        }
        How::Expire => {
            w.clock.advance(16 * MINUTE);
            let d = w.decide(true, &dec, Verdict::Approve).await;
            prop_assert_eq!(code_of(&d), Code::DecisionStale);
            Ok(false)
        }
        How::Unattended => {
            let d = w.decide(false, &dec, Verdict::Approve).await;
            prop_assert_eq!(code_of(&d), Code::InteractionRequired);
            Ok(false)
        }
    }
}

/// The work's usable grant whose deadline a fresh `ensure` of it would resolve to: an
/// active binding of the work on a usable grant (I-1's candidate).
fn candidate(w: &World, work: &str) -> Option<GrantSnapshot> {
    w.work_bindings(work)
        .into_iter()
        .filter(|b| b.state == BindingState::Active && b.parent.is_none())
        .map(|b| w.grant(&b.grant))
        .find(|g| g.state.permits_use())
}

/// The earliest deadline of a work's grants (M01's `work_deadline`), read from the store.
fn work_deadline(w: &World, work: &str) -> Option<Timestamp> {
    w.work_bindings(work)
        .iter()
        .map(|b| w.grant(&b.grant).deadline.effective)
        .min()
}

async fn run_step(w: &mut World, m: &mut Model, s: &Step, n: u32) -> Result<(), TestCaseError> {
    let now = w.now();
    match s {
        Step::Fresh(p) | Step::Background(p) => {
            let p = usize::from(*p);
            let background = matches!(s, Step::Background(_));
            let work = format!("w-{n}");
            let decisions = w.pending_decisions();
            let r = w.ensure(!background, &format!("r-{n}"), &work, p).await;
            check_activation(m, p, now, &r, "fresh")?;
            if m.blocked(p, now) {
                prop_assert_eq!(
                    code_of(&r),
                    m.block_code(p),
                    "whatever the request or work ID"
                );
            } else {
                prop_assert_eq!(
                    code_of(&r),
                    Code::AccessReady,
                    "covered work under the policy"
                );
            }
            // Covered work never asks; a background trigger never creates a decision.
            prop_assert_eq!(
                w.pending_decisions(),
                decisions,
                "a trigger created a decision"
            );
            if let Ok(c) = r {
                m.grants.insert(c.data.grant_id, (p, None));
                m.works.push(Work {
                    id: work,
                    profile: p,
                    child: false,
                });
            }
        }
        Step::Again(i) => {
            let Some(work) = m.pick(*i, true) else {
                return Ok(());
            };
            let p = work.profile;
            let before = w.counts();
            let effects = w.fake.effect_count();
            let cand = candidate(w, &work.id);
            let end = work_deadline(w, &work.id);
            let r = w.ensure(false, &format!("r-{n}"), &work.id, p).await;
            check_activation(m, p, now, &r, "again")?;
            if m.stopped.contains(&work.id) {
                prop_assert_eq!(code_of(&r), Code::CredentialExpired);
                prop_assert_eq!(reason_of(&r), Some(reason::WORK_STOPPED));
                prop_assert_eq!(w.counts(), before, "nothing written for a stopped work ID");
            } else if end.is_some_and(|e| now >= e) {
                prop_assert_eq!(
                    code_of(&r),
                    Code::CredentialExpired,
                    "a work ID never extends"
                );
            } else if m.blocked(p, now) {
                prop_assert_eq!(code_of(&r), m.block_code(p));
            } else {
                prop_assert_eq!(code_of(&r), Code::AccessReady);
            }
            if let Ok(c) = &r {
                // I-1: equal pins attach to the work's grant; nothing new is prepared.
                if let Some(g) = cand.filter(|g| g.deadline.effective == c.data.expires_at) {
                    prop_assert_eq!(&c.data.grant_id, &g.id, "I-1: the work's grant is reused");
                    prop_assert_eq!(w.counts().1, before.1, "I-1: no grant is created");
                    prop_assert_eq!(w.fake.effect_count(), effects, "I-1: no second preparation");
                }
                m.grants.insert(c.data.grant_id.clone(), (p, None));
            }
        }
        Step::Delegate(i) => {
            let Some(parent) = m.pick(*i, true) else {
                return Ok(());
            };
            let Some(b) = w
                .work_bindings(&parent.id)
                .into_iter()
                .rev()
                .find(|b| b.state == BindingState::Active)
            else {
                return Ok(());
            };
            let p = parent.profile;
            let parent_grant = w.grant(&b.grant);
            let child = format!("c-{n}");
            let r = w.delegate(&b.id, p, &format!("r-{n}"), &child).await;
            check_activation(m, p, now, &r, "delegate")?;
            if m.stopped.contains(&parent.id) {
                prop_assert_eq!(reason_of(&r), Some(reason::WORK_STOPPED));
            }
            if let Ok(c) = r {
                prop_assert!(parent_grant.state.permits_use());
                prop_assert!(
                    c.data.expires_at <= parent_grant.deadline.effective,
                    "past the parent"
                );
                m.grants.insert(c.data.grant_id, (p, Some(parent_grant.id)));
                m.works.push(Work {
                    id: child,
                    profile: p,
                    child: true,
                });
            }
        }
        Step::Bind(i) => {
            let Some(work) = m.pick(*i, false) else {
                return Ok(());
            };
            let Some(b) = w.work_bindings(&work.id).into_iter().last() else {
                return Ok(());
            };
            let g = w.grant(&b.grant);
            let r = w.bind(&b.id, &format!("r-{n}")).await;
            if m.stopped.contains(&work.id) {
                prop_assert_eq!(code_of(&r), Code::CredentialExpired);
                prop_assert_eq!(reason_of(&r), Some(reason::WORK_STOPPED));
            }
            if code_of(&r) == Code::AccessReady {
                // An existing binding is not a new activation (a pause does not stop
                // it); revocation, the deadline and a cutoff do.
                prop_assert!(!m.stopped.contains(&work.id));
                prop_assert!(!m.ended.contains(&g.id), "an ended grant never binds");
                prop_assert!(now < g.deadline.effective, "bound past the deadline");
                prop_assert!(!m.cut(work.profile, now), "bound past the cutoff");
            }
        }
        Step::StopWork(i) => {
            let Some(work) = m.pick(*i, false) else {
                return Ok(());
            };
            // Other top-level work: its usable active bindings, which must stay usable.
            let others: Vec<BindingRecord> = m
                .works
                .iter()
                .filter(|x| x.id != work.id && !x.child)
                .flat_map(|x| w.work_bindings(&x.id))
                .filter(|b| {
                    b.state == BindingState::Active && w.grant(&b.grant).state.permits_use()
                })
                .collect();
            let r = w.stop_work(&format!("r-{n}"), &work.id).await;
            prop_assert_eq!(code_of(&r), Code::Ok);
            m.stopped.insert(work.id.clone());
            for b in others {
                let after = w
                    .store
                    .transaction(|tx| tx.binding(&b.id))
                    .unwrap()
                    .unwrap();
                prop_assert_eq!(
                    after.state,
                    BindingState::Active,
                    "other work is unaffected"
                );
                prop_assert!(
                    w.grant(&b.grant).state.permits_use(),
                    "other work is unaffected"
                );
            }
        }
        Step::StopPolicy(t) => {
            let live: Vec<GrantId> = m
                .grants
                .iter()
                .filter(|(_, (p, _))| t.profiles().contains(p))
                .map(|(g, _)| g.clone())
                .filter(|g| w.grant(g).state.permits_use())
                .collect();
            let others: Vec<GrantId> = m
                .grants
                .iter()
                .filter(|(_, (p, _))| !t.profiles().contains(p))
                .map(|(g, _)| g.clone())
                .filter(|g| w.grant(g).state.permits_use())
                .collect();
            let r = w
                .act(false, PolicyAction::Stop { target: t.target() })
                .await;
            prop_assert_eq!(code_of(&r), Code::Ok);
            for p in t.profiles() {
                m.paused[*p] = true;
            }
            for g in live {
                let st = w.grant(&g).state;
                prop_assert!(
                    matches!(st, GrantState::Revoking | GrantState::Revoked),
                    "a stop revokes every live grant resting on the target, now: {:?}",
                    st
                );
            }
            for g in others {
                prop_assert!(
                    w.grant(&g).state.permits_use(),
                    "another profile is untouched"
                );
            }
        }
        Step::Pause(t) => {
            let live: Vec<GrantId> = m
                .grants
                .keys()
                .filter(|g| w.grant(g).state.permits_use())
                .cloned()
                .collect();
            let r = w
                .act(
                    false,
                    PolicyAction::Pause {
                        policy_id: None,
                        target: Some(t.target()),
                    },
                )
                .await;
            prop_assert_eq!(code_of(&r), Code::Ok);
            for p in t.profiles() {
                m.paused[*p] = true;
            }
            for g in live {
                prop_assert!(w.grant(&g).state.permits_use(), "a pause ends no grant");
            }
        }
        Step::Cutoff(t, offset, how) => {
            let at = now
                .checked_add(jiff::SignedDuration::from_mins(i64::from(*offset)))
                .unwrap();
            let r = w
                .act(
                    true,
                    PolicyAction::Cutoff {
                        policy_id: None,
                        at,
                        target: Some(t.target()),
                    },
                )
                .await;
            let mut widened = Vec::new();
            for p in t.profiles() {
                match m.cutoff[*p] {
                    None => m.cutoff[*p] = Some(at),
                    Some(c) if at < c => m.cutoff[*p] = Some(at),
                    Some(c) if at > c => widened.push(*p),
                    Some(_) => {}
                }
            }
            if widened.is_empty() {
                prop_assert_eq!(code_of(&r), Code::Ok);
            }
            // The narrowing part applied whatever the widening part does.
            if settle_widening(w, &r, *how).await? {
                for p in widened {
                    m.cutoff[p] = Some(at);
                }
            }
        }
        Step::Resume(t, how) => {
            let widened: Vec<usize> = t
                .profiles()
                .iter()
                .copied()
                .filter(|p| m.paused[*p])
                .collect();
            let r = w
                .act(
                    true,
                    PolicyAction::Resume {
                        policy_id: None,
                        target: Some(t.target()),
                    },
                )
                .await;
            if widened.is_empty() {
                prop_assert_eq!(code_of(&r), Code::Ok);
            }
            if settle_widening(w, &r, *how).await? {
                for p in widened {
                    m.paused[p] = false;
                }
            }
        }
        Step::Clear(t, how) => {
            let widened: Vec<usize> = t
                .profiles()
                .iter()
                .copied()
                .filter(|p| m.cutoff[*p].is_some())
                .collect();
            let r = w
                .act(
                    true,
                    PolicyAction::ClearCutoff {
                        policy_id: None,
                        target: Some(t.target()),
                    },
                )
                .await;
            if widened.is_empty() {
                prop_assert_eq!(code_of(&r), Code::Ok);
            }
            if settle_widening(w, &r, *how).await? {
                for p in widened {
                    m.cutoff[p] = None;
                }
            }
        }
        Step::Advance(mins) => w.clock.advance(u32::from(*mins) * MINUTE),
        Step::Tick => w.ops.tick().await.unwrap(),
        Step::Restart => {
            w.restart().await;
            w.ops.tick().await.unwrap();
        }
    }
    Ok(())
}

/// The invariants that hold after every step.
fn check_invariants(w: &World, m: &mut Model, s: &Step) -> Result<(), TestCaseError> {
    let now = w.now();
    // The stored blocks are exactly the model's: `resume` never clears a cutoff,
    // `clear_cutoff` never resumes a pause, an unapproved decision changes nothing.
    for (p, (cut, paused)) in m.cutoff.iter().zip(m.paused).enumerate() {
        let stored = w.policy(p);
        prop_assert_eq!(stored.cutoff_at, *cut, "the cutoff of {}", PROFILES[p].1);
        prop_assert_eq!(
            matches!(stored.pause, PauseState::Paused { .. }),
            paused,
            "the pause of {}",
            PROFILES[p].1
        );
    }
    // Ended grants never return; no grant outlives min(window, parent, cutoff).
    let after_detection = matches!(s, Step::Tick | Step::Restart);
    for (g, (p, parent)) in &m.grants {
        let snap = w.grant(g);
        if m.ended.contains(g) {
            prop_assert!(!snap.state.permits_use(), "an ended grant returned");
        }
        if snap.state.is_terminal() || snap.state == GrantState::Revoking {
            m.ended.insert(g.clone());
        }
        prop_assert!(
            snap.deadline.effective <= plus(snap.starts_at, WINDOW),
            "past the window"
        );
        if let Some(parent) = parent {
            prop_assert!(
                snap.deadline.effective <= w.grant(parent).deadline.effective,
                "past the parent"
            );
        }
        if after_detection && snap.state.permits_use() {
            prop_assert!(now < snap.deadline.effective, "usable past its deadline");
            prop_assert!(!m.cut(*p, now), "usable past the cutoff");
        }
    }
    // A stopped work keeps no usable binding.
    for work in &m.stopped {
        for b in w.work_bindings(work) {
            prop_assert!(
                b.state != BindingState::Active || !w.grant(&b.grant).state.permits_use(),
                "a stopped work kept a usable binding"
            );
        }
    }
    // Pins never change.
    for b in w.bindings(&m.works) {
        let pin = Pin::of(&b);
        match m.pins.get(&b.id) {
            Some(seen) => prop_assert_eq!(seen, &pin, "a binding's pins changed"),
            None => {
                m.pins.insert(b.id.clone(), pin);
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(prop_config(0x5533_5052_4543_4544))]

    /// ADR-0011 §7: every block outranks standing permission and nothing (a fresh request
    /// or work ID, a restart, a background trigger, a stale or unattended decision)
    /// revives paused, stopped or cut-off access (module documentation for the invariants).
    #[test]
    fn blocks_outrank_standing_permission_and_nothing_revives_them(
        steps in prop::collection::vec(step(), 1..24)
    ) {
        block().block_on(async move {
            let mut w = World::new().await;
            let mut m = Model::default();
            let mut n = 0u32;
            for s in steps {
                n += 1;
                run_step(&mut w, &mut m, &s, n).await?;
                check_invariants(&w, &mut m, &s)?;
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}
