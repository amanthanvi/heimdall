//! ⟨M05⟩ U2 model suite **P10**: the prompt budget of scope-delta review (ADR-0011 §3.4,
//! §4.2–§4.3).
//!
//! N concurrent equivalent requesters (`Operations::raise_extension_for_test`, the seam
//! wave 2's `ensure` with `context` replaces, each on its own task over the production
//! `Operations` and an in-memory store), interleaved with manifest flips (other deltas in
//! the same burst), attended deny and approve, expiry, owner-initiated widening and time.
//! The model checks, after every step:
//!
//! * at most one pending record per (policy, revision, delta), shared by every requester;
//! * no record while a cooldown holds: a requester gets `decision_cooldown` with the denied
//!   record's reference, and no record is written;
//! * a broader delta never joins a narrower one (each distinct delta has its own record);
//! * an approval widens exactly the recorded delta;
//! * owner-initiated widening bypasses the cooldown, and its approval clears it.
//!
//! Seeds: fixed unless `PROPTEST_RNG_SEED` is set; failures persist next to this file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::{Extension, Limits};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity,
};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId,
};
use heimdall_contract::request::{
    DecideRequest, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, PolicyAction, RevocationStatus, Verdict,
    WorkloadIsolation,
};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{
    LockBehavior, PauseState, PolicyRevision, PolicySource, ScopeDelta, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{Clock as _, SyncStatus, TimePolicy};
use heimdall_store::Store;
use heimdall_testkit::{FakeCredentialAdapter, ScriptedTimeSync, VirtualClock};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const MINUTE: Duration = Duration::from_secs(60);
const WINDOW: Duration = Duration::from_secs(2 * 3600);

fn t0() -> Timestamp {
    "2026-11-18T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn pol() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn owner() -> Caller {
    Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: None,
        },
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn pair(d: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

const HOSTS: [&str; 4] = ["h1", "h2", "h3", "h4"];

fn hosts(bits: u8) -> BTreeSet<AccessPair> {
    HOSTS
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1 << i) != 0)
        .map(|(_, h)| pair(h))
        .collect()
}

fn ssh() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn descriptor() -> AdapterDescriptor {
    AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: "fake_agent".into(),
            instance: "fixture-1".into(),
        },
        capabilities: ssh(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
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
                ordinary_aliases: None,
                owner_functions: None,
            },
            evidence: Vec::new(),
        },
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

/// A trusted workspace's policy as the requester path sees it: profile `dev` (h1..h4),
/// the policy holding h1 only, `revoke_on_lock`, a 2 h window (seeded, as every model
/// suite seeds its starting policy).
async fn world() -> (Arc<Store>, Arc<VirtualClock>, Operations) {
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
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
                    pairs: hosts(0b1111),
                    capabilities: ssh(),
                },
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: pol(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: Some(heimdall_contract::ids::WorkspaceId::from_random_bytes(
                        [5; 16],
                    )),
                    scope: Scope {
                        pairs: hosts(0b0001),
                        capabilities: ssh(),
                    },
                    environments: [env_id()].into_iter().collect(),
                    max_window: WINDOW,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::RevokeOnLock,
                    connection: Default::default(),
                    default: false,
                },
                false,
            )?;
            Ok(())
        })
        .unwrap();
    let clock = VirtualClock::at(t0());
    let hook: Arc<dyn StageHook> = Arc::new(NoStageHook);
    let ops = Operations::start(OperationsConfig {
        store: store.clone(),
        clock: clock.clone(),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![
            FakeCredentialAdapter::new(descriptor(), Vec::new()) as Arc<dyn CredentialAdapter>
        ],
        stage_hook: hook,
        limits: Limits::default(),
        default_window: Duration::from_secs(12 * 3600),
        projection: None,
    })
    .await
    .unwrap();
    (store, clock, ops)
}

fn delta(bits: u8, background_work: bool) -> ScopeDelta {
    ScopeDelta {
        pairs: hosts(bits),
        background_work,
        ..ScopeDelta::default()
    }
}

#[derive(Debug, Clone)]
enum Step {
    /// One burst: every delta of the list, `copies` concurrent requesters each.
    Raise { deltas: Vec<(u8, bool)>, copies: u8 },
    /// The owner decides the `pick`th pending record.
    Decide { pick: u8, approve: bool },
    /// The owner asks for a delta on the owner channel.
    Owner { bits: u8, bg: bool },
    /// Time passes.
    Advance { minutes: u16 },
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (prop::collection::vec((0u8..16, any::<bool>()), 1..4), 1u8..6)
            .prop_map(|(deltas, copies)| Step::Raise { deltas, copies }),
        4 => (any::<u8>(), prop_oneof![3 => Just(false), 1 => Just(true)])
            .prop_map(|(pick, approve)| Step::Decide { pick, approve }),
        1 => (0u8..16, any::<bool>()).prop_map(|(bits, bg)| Step::Owner { bits, bg }),
        2 => prop_oneof![Just(5u16), Just(16), Just(60), Just(121)]
            .prop_map(|minutes| Step::Advance { minutes }),
    ]
}

fn config(seed: u64) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 64,
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
    // Concurrent tasks on the production flavour; each requester's transaction runs on
    // the blocking pool, so the store serializes truly concurrent writers.
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f)
}

/// The pending `extend_scope` records that can still be completed, by action (keyed by
/// the action's JSON: `PolicyAction` is not `Ord`).
type Live = BTreeMap<String, (PolicyAction, Vec<DecisionId>)>;

fn live_extensions(store: &Store, now: Timestamp) -> Result<Live, TestCaseError> {
    let (pending, generation) = store
        .transaction(|tx| Ok((tx.pending_decisions()?, tx.authority_generation()?)))
        .unwrap();
    let mut out: BTreeMap<String, (PolicyAction, Vec<DecisionId>)> = BTreeMap::new();
    for d in pending {
        if let DecisionKind::WidenPolicy { action } = &d.kind
            && matches!(action, PolicyAction::ExtendScope { .. })
            && now < d.expires_at
            && d.generation == generation
        {
            out.entry(serde_json::to_string(action).unwrap())
                .or_insert_with(|| (action.clone(), Vec::new()))
                .1
                .push(d.id);
        }
    }
    Ok(out)
}

/// One cooldown the model expects: the denied record and when it ends, at a revision.
#[derive(Debug, Clone)]
struct Cool {
    revision: PolicyRevision,
    decision: DecisionId,
    until: Timestamp,
}

#[allow(clippy::too_many_lines)]
async fn run(steps: Vec<Step>) -> Result<(), TestCaseError> {
    let (store, clock, ops) = world().await;
    let policy = |store: &Store| store.transaction(|tx| tx.policy(&pol())).unwrap().unwrap();
    // Keyed by the recorded action's JSON (`PolicyAction` is not `Ord`).
    let mut cooldowns: BTreeMap<String, Cool> = BTreeMap::new();
    for s in steps {
        let now = clock.wall();
        let p = policy(&store);
        match s {
            Step::Raise { deltas, copies } => {
                let before = live_extensions(&store, now)?;
                let mut tasks = Vec::new();
                for (i, (bits, bg)) in deltas.iter().enumerate() {
                    for _ in 0..copies {
                        let ops = ops.clone();
                        let d = delta(*bits, *bg);
                        tasks.push((
                            i,
                            tokio::spawn(async move {
                                ops.raise_extension_for_test(&pol(), None, d).await
                            }),
                        ));
                    }
                }
                let mut by_delta: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
                let mut record_of: BTreeMap<String, DecisionId> = BTreeMap::new();
                for (i, t) in tasks {
                    let r = t.await.unwrap();
                    let (bits, bg) = deltas[i];
                    let asked = delta(bits, bg);
                    let beyond = asked.beyond(&p);
                    let key = serde_json::to_string(&beyond.action(&pol())).unwrap();
                    let cooling = cooldowns
                        .get(&key)
                        .filter(|c| c.revision == p.revision && now < c.until);
                    match r {
                        Ok(Extension::Covered) => {
                            prop_assert!(beyond.is_empty(), "covered only when nothing is added");
                        }
                        Ok(Extension::Cooldown {
                            decision,
                            retry_after,
                        }) => {
                            let c = cooling.cloned();
                            prop_assert!(c.is_some(), "no cooldown without a denial");
                            let c = c.unwrap();
                            prop_assert_eq!(
                                &decision,
                                &c.decision,
                                "the denied record's reference"
                            );
                            prop_assert_eq!(retry_after, c.until);
                            // The error a requester gets carries both.
                            let e = Extension::Cooldown {
                                decision: decision.clone(),
                                retry_after,
                            }
                            .refusal(false, now)
                            .unwrap();
                            prop_assert_eq!(e.code, Code::InteractionRequired);
                            prop_assert_eq!(e.reason.as_deref(), Some("decision_cooldown"));
                            prop_assert_eq!(
                                e.next.decision_ref.as_deref(),
                                Some(decision.as_str())
                            );
                            prop_assert!(e.next.retry_after_ms.is_some());
                            by_delta
                                .entry(i)
                                .or_default()
                                .insert(format!("cool:{decision}"));
                        }
                        Ok(Extension::Pending { decision, .. }) => {
                            prop_assert!(
                                cooling.is_none(),
                                "no record during a cooldown ({})",
                                key
                            );
                            prop_assert!(!beyond.is_empty());
                            let rec = store
                                .transaction(|tx| tx.decision(&decision))
                                .unwrap()
                                .unwrap();
                            prop_assert_eq!(
                                &rec.kind,
                                &DecisionKind::WidenPolicy {
                                    action: beyond.action(&pol())
                                },
                                "the record shows exactly the added authority"
                            );
                            if let Some(other) = record_of.insert(key.clone(), decision.clone()) {
                                prop_assert_eq!(
                                    other,
                                    decision.clone(),
                                    "equal deltas share a record"
                                );
                            }
                            by_delta.entry(i).or_default().insert(decision.to_string());
                        }
                        Err(e) => prop_assert!(false, "{:?}: {}", e.code, e.message),
                    }
                }
                // Every requester of one delta got the same answer.
                for answers in by_delta.values() {
                    prop_assert_eq!(answers.len(), 1, "{:?}", answers);
                }
                // Distinct deltas (a broader one included) never share a record.
                let ids: Vec<&DecisionId> = record_of.values().collect();
                let unique: BTreeSet<&DecisionId> = ids.iter().copied().collect();
                prop_assert_eq!(
                    ids.len(),
                    unique.len(),
                    "a broader delta never joins a narrower one"
                );
                let after = live_extensions(&store, now)?;
                for (key, (action, records)) in &after {
                    prop_assert_eq!(records.len(), 1, "one pending record for {:?}", action);
                    let cooling = cooldowns
                        .get(key)
                        .is_some_and(|c| c.revision == p.revision && now < c.until);
                    if cooling {
                        prop_assert_eq!(
                            before.get(key).map(|(_, r)| r),
                            Some(records),
                            "no new record while cooling down"
                        );
                    }
                }
            }
            Step::Decide { pick, approve } => {
                let live: Vec<(PolicyAction, DecisionId)> = live_extensions(&store, now)?
                    .into_values()
                    .map(|(a, ids)| (a, ids[0].clone()))
                    .collect();
                if live.is_empty() {
                    continue;
                }
                let (action, id) = live[usize::from(pick) % live.len()].clone();
                let verdict = if approve {
                    Verdict::Approve
                } else {
                    Verdict::Deny
                };
                let r = ops
                    .decide(
                        &owner(),
                        DecideRequest {
                            decision_id: id.clone(),
                            verdict,
                        },
                    )
                    .await;
                prop_assert!(r.is_ok(), "{:?}", r.err().map(|e| e.code));
                let after = policy(&store);
                if approve {
                    let PolicyAction::ExtendScope {
                        pairs,
                        background_work,
                        ..
                    } = &action
                    else {
                        unreachable!()
                    };
                    let exact: BTreeSet<AccessPair> = p.scope.pairs.union(pairs).cloned().collect();
                    prop_assert_eq!(&after.scope.pairs, &exact, "exactly the recorded delta");
                    prop_assert_eq!(after.revision, PolicyRevision(p.revision.0 + 1));
                    if *background_work == Some(true) {
                        prop_assert_eq!(after.lock_behavior, LockBehavior::Continue);
                    } else {
                        prop_assert_eq!(after.lock_behavior, p.lock_behavior);
                    }
                    let left = store
                        .transaction(|tx| tx.decision_cooldowns_for_policy(&pol()))
                        .unwrap();
                    prop_assert!(left.is_empty(), "the revision change ends every cooldown");
                    cooldowns.clear();
                } else {
                    prop_assert_eq!(&after, &p, "a denial changes no policy");
                    cooldowns.insert(
                        serde_json::to_string(&action).unwrap(),
                        Cool {
                            revision: p.revision,
                            decision: id,
                            until: now
                                .checked_add(jiff::SignedDuration::try_from(p.max_window).unwrap())
                                .unwrap(),
                        },
                    );
                }
            }
            Step::Owner { bits, bg } => {
                let beyond = delta(bits, bg).beyond(&p);
                let action = beyond.action(&pol());
                let r = ops.policy(&owner(), action.clone()).await;
                if beyond.is_empty() {
                    prop_assert!(r.is_ok());
                    continue;
                }
                // Owner-initiated widening always creates (or shares) a pending record,
                // a cooldown notwithstanding.
                let e = r.unwrap_err();
                prop_assert_eq!(e.code, Code::ApprovalRequired);
                let id = DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
                let rec = store.transaction(|tx| tx.decision(&id)).unwrap().unwrap();
                prop_assert_eq!(rec.state, DecisionState::Pending);
                prop_assert_eq!(rec.kind, DecisionKind::WidenPolicy { action });
                let live = live_extensions(&store, now)?;
                for (_, records) in live.values() {
                    prop_assert_eq!(records.len(), 1);
                }
            }
            Step::Advance { minutes } => clock.advance(MINUTE * u32::from(minutes)),
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(0x0005_0010))]

    /// P10 (ADR-0011 §3.4, §4.2–§4.3): at most one pending record per (policy, revision,
    /// delta), shared by every concurrent requester; none during a cooldown; a broader
    /// delta never joins a narrower one; an approval widens exactly the recorded delta;
    /// owner-initiated widening bypasses the cooldown.
    #[test]
    fn p10_one_record_per_delta_none_during_a_cooldown(
        steps in prop::collection::vec(step(), 1..30)
    ) {
        block(run(steps))?;
    }
}

// =================================================================================
// ⟨M05⟩ U4: the trust cooldown (orchestrator ruling I-5)
// =================================================================================

/// An untrusted workspace, always (a fixed observation: the trace never approves).
struct UntrustedProbe;

fn repo_cwd() -> &'static str {
    if cfg!(windows) {
        r"C:\w\repo"
    } else {
        "/w/repo"
    }
}

fn manifest_digest() -> String {
    "ab".repeat(32)
}

impl heimdall_app::ports::WorkspaceProbe for UntrustedProbe {
    fn probe(
        &self,
        _environment: &EnvironmentId,
        _cwd: &str,
        _records: &[heimdall_domain::workspace::WorkspaceRecord],
    ) -> Result<heimdall_app::ports::ProbedWorkspace, heimdall_app::ports::ProbeError> {
        Ok(heimdall_app::ports::ProbedWorkspace {
            root: Some(repo_cwd().to_owned()),
            root_identity: Some(heimdall_domain::projection::FileIdentity::Unix {
                dev: 1,
                ino: 7,
                birth: None,
            }),
            git_common_identity: None,
            matched: Some(heimdall_domain::workspace::WorkspaceMatch::Untrusted),
            manifest: Some(heimdall_app::ports::ProbedManifest {
                access_digest: manifest_digest(),
                profile: ProfileId::parse("dev").unwrap(),
                pairs: vec!["h2:deploy".into()],
                environments: Vec::new(),
                capabilities: vec!["ssh-authentication".into()],
                background_work: false,
                project_label: Some("repo".into()),
            }),
        })
    }
}

/// The owner's own `trust_workspace` of that workspace: the server's proposal exactly.
fn owner_trust() -> PolicyAction {
    PolicyAction::TrustWorkspace {
        cwd: repo_cwd().to_owned(),
        access_digest: manifest_digest(),
        proposal: heimdall_contract::trust::TrustProposal {
            profile: ProfileId::parse("dev").unwrap(),
            pairs: hosts(0b0010),
            environments: BTreeSet::new(),
            capabilities: ssh(),
            background_work: false,
        },
    }
}

fn trust_request(n: usize) -> heimdall_contract::request::EnsureRequest {
    heimdall_contract::request::EnsureRequest {
        profile: None,
        profile_revision: None,
        scope: BTreeSet::new(),
        environment: None,
        work_id: heimdall_contract::ids::WorkId::parse(&format!("work-{n}")).unwrap(),
        until: None,
        required_capabilities: Default::default(),
        request_id: heimdall_contract::ids::RequestId::parse(&format!("req-{n}")).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: Default::default(),
        connection: None,
        context: Some(heimdall_contract::trust::WorkContext {
            cwd: repo_cwd().to_owned(),
        }),
        covered_only: false,
    }
}

#[derive(Debug, Clone)]
enum TrustStep {
    /// `copies` concurrent requesters run `ensure` in the workspace.
    Request { copies: u8 },
    /// The owner denies the pending trust record, if any.
    Deny,
    /// The owner asks for the trust on the owner channel.
    Owner,
    /// Time passes.
    Advance { minutes: u16 },
}

fn trust_step() -> impl Strategy<Value = TrustStep> {
    prop_oneof![
        5 => (1u8..4).prop_map(|copies| TrustStep::Request { copies }),
        3 => Just(TrustStep::Deny),
        1 => Just(TrustStep::Owner),
        2 => prop_oneof![Just(5u16), Just(16), Just(120), Just(721)]
            .prop_map(|minutes| TrustStep::Advance { minutes }),
    ]
}

fn decision_rows(store: &Store) -> u64 {
    store.transaction(|tx| tx.table_counts()).unwrap().decisions
}

/// Branches the trust traces exercised (non-vacuity across the run).
static COOLDOWN_ANSWERED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static OWNER_CLEARED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static SHARED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[allow(clippy::too_many_lines)]
async fn run_trust(steps: Vec<TrustStep>) -> Result<(), TestCaseError> {
    use std::sync::atomic::Ordering::Relaxed;
    let (store, clock, ops) = world().await;
    assert!(ops.set_workspace_probe(Arc::new(UntrustedProbe)));
    let lifetime = Limits::default().decision_lifetime;
    let plus = |t: Timestamp, d: Duration| {
        t.checked_add(jiff::SignedDuration::try_from(d).unwrap())
            .unwrap()
    };
    // The model: the live pending trust record (and when it expires), the cooldown.
    let mut pending: Option<(DecisionId, Timestamp)> = None;
    let mut cooling: Option<(DecisionId, Timestamp)> = None;
    let mut sent = 0usize;
    for s in steps {
        let now = clock.wall();
        if pending.as_ref().is_some_and(|(_, until)| now >= *until) {
            pending = None;
        }
        if cooling.as_ref().is_some_and(|(_, until)| now >= *until) {
            cooling = None;
        }
        match s {
            TrustStep::Request { copies } => {
                let rows = decision_rows(&store);
                let mut tasks = Vec::new();
                for _ in 0..copies {
                    sent += 1;
                    let ops = ops.clone();
                    let req = trust_request(sent);
                    tasks.push(tokio::spawn(async move { ops.ensure(&owner(), req).await }));
                }
                let mut refs = BTreeSet::new();
                for t in tasks {
                    let e = t.await.unwrap().unwrap_err();
                    prop_assert_eq!(&e.code, &Code::ApprovalRequired);
                    prop_assert!(e.operation_id.is_none(), "nothing is admitted");
                    let d = DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
                    match &cooling {
                        Some((denied, until)) => {
                            prop_assert_eq!(e.reason.as_deref(), Some("decision_cooldown"));
                            prop_assert_eq!(&d, denied, "the denied record's reference");
                            prop_assert!(e.next.retry_after_ms.is_some());
                            let wait = until.duration_since(now);
                            prop_assert!(wait > jiff::SignedDuration::ZERO);
                        }
                        None => {
                            prop_assert_eq!(e.reason.as_deref(), Some("workspace_untrusted"));
                        }
                    }
                    refs.insert(d);
                }
                prop_assert_eq!(refs.len(), 1, "every requester got the same answer");
                let d = refs.into_iter().next().unwrap();
                match (&cooling, &pending) {
                    (Some(_), _) => {
                        COOLDOWN_ANSWERED.fetch_add(1, Relaxed);
                        prop_assert_eq!(decision_rows(&store), rows, "no record during a cooldown");
                    }
                    (None, Some((p, _))) => {
                        SHARED.fetch_add(1, Relaxed);
                        prop_assert_eq!(&d, p, "requesters share the pending record");
                        prop_assert_eq!(decision_rows(&store), rows);
                    }
                    (None, None) => {
                        prop_assert_eq!(decision_rows(&store), rows + 1, "one record");
                        let rec = store.transaction(|tx| tx.decision(&d)).unwrap().unwrap();
                        let is_trust = matches!(rec.kind, DecisionKind::TrustWorkspace { .. });
                        prop_assert!(is_trust, "a TrustWorkspace record");
                        pending = Some((d, plus(now, lifetime)));
                    }
                }
            }
            TrustStep::Deny => {
                let Some((d, _)) = pending.take() else {
                    continue;
                };
                let r = ops
                    .decide(
                        &owner(),
                        DecideRequest {
                            decision_id: d.clone(),
                            verdict: Verdict::Deny,
                        },
                    )
                    .await;
                prop_assert!(r.is_ok(), "{:?}", r.err().map(|e| e.code));
                cooling = Some((d, plus(now, Duration::from_secs(12 * 3600))));
            }
            TrustStep::Owner => {
                let rows = decision_rows(&store);
                let e = ops.policy(&owner(), owner_trust()).await.unwrap_err();
                prop_assert_eq!(&e.code, &Code::ApprovalRequired);
                let d = DecisionId::parse(e.next.decision_ref.as_deref().unwrap()).unwrap();
                // Owner-initiated trust always creates (or shares) its record, a cooldown
                // notwithstanding, and clears the cooldown.
                match &pending {
                    Some((p, _)) => {
                        prop_assert_eq!(&d, p);
                        prop_assert_eq!(decision_rows(&store), rows);
                    }
                    None => {
                        prop_assert_eq!(decision_rows(&store), rows + 1);
                        pending = Some((d, plus(now, lifetime)));
                    }
                }
                if cooling.take().is_some() {
                    OWNER_CLEARED.fetch_add(1, Relaxed);
                }
            }
            TrustStep::Advance { minutes } => clock.advance(MINUTE * u32::from(minutes)),
        }
    }
    Ok(())
}

/// P10, the trust cooldown (orchestrator ruling I-5): requester-raised trust of one
/// workspace shares one pending record; a denial cools the key down for the policy's
/// default window, during which requesters get `decision_cooldown` with the denied
/// record's reference and **no** record is written; an owner-initiated
/// `trust_workspace` always creates (or shares) its record and clears the cooldown.
#[test]
fn p10_trust_cooldown_no_record_until_owner_asks() {
    use std::sync::atomic::Ordering::Relaxed;
    let mut runner = proptest::test_runner::TestRunner::new(config(0x0005_0011));
    let result = runner.run(&prop::collection::vec(trust_step(), 1..24), |steps| {
        block(run_trust(steps))
    });
    if let Err(e) = result {
        panic!("{e}");
    }
    for (name, n) in [
        ("cooldown answered", &COOLDOWN_ANSWERED),
        ("owner cleared a cooldown", &OWNER_CLEARED),
        ("requesters shared a record", &SHARED),
    ] {
        assert!(n.load(Relaxed) > 0, "branch {name} never exercised");
    }
}
