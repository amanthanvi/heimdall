//! ⟨M05⟩ U2 model suite: standing-policy actions, workspace trust and reconcile decisions,
//! and **P9** (ADR-0011 I1: one path creates or widens authority).
//!
//! Everything runs in process over the production `heimdall_app::Operations`,
//! `heimdall_store::Store::open_in_memory`, `testkit::VirtualClock`,
//! `testkit::ScriptedTimeSync`, `testkit::FakeCredentialAdapter` and a scripted
//! [`FakeProbe`] (the `WorkspaceProbe` port; wave 2 adds the real one). The probe's
//! "filesystem" is a table of working directories with a root, a root identity and a
//! manifest the test edits (digest flips, identity flips, moves, hostile manifests).
//!
//! **Restart label.** A "restart" is an in-process reconstruction (a new `Operations` over
//! the same store), as in `model_operations`.
//!
//! Seeds: P9 runs with a fixed seed unless `PROPTEST_RNG_SEED` is set; failures persist
//! next to this file (`trust_policy.proptest-regressions`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_app::ensure::{NoStageHook, StageHook};
use heimdall_app::operations::{Extension, Limits};
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
    ProbeError, ProbedManifest, ProbedWorkspace, WorkspaceProbe,
};
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations, OperationsConfig};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, DeviceId, EnvironmentId, OperationId, PolicyId,
    ProfileId, RequestId, WorkId, WorkspaceId,
};
use heimdall_contract::request::{
    DecideRequest, DestinationScopeEnforcement, Enforcement, EnsureRequest,
    ExistingConnectionsPolicy, InspectRequest, InspectSubject, InteractionMode,
    NewAuthenticationExpiry, ObserveRequest, PolicyAction, RefreshDependency, RequiredCapabilities,
    RevocationStatus, Verdict, WaitMode, WorkloadIsolation,
};
use heimdall_contract::trust::{PoliciesView, TrustProposal, WorkContext};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionState};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{
    LockBehavior, PauseState, PolicyRevision, ScopeDelta, StandingPolicy, coverage,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::projection::FileIdentity;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_domain::workspace::{
    AmbiguityReason, BindingContext, MAX_PROJECT_LABEL_BYTES, WorkspaceMatch, WorkspaceRecord,
    WorkspaceState,
};
use heimdall_store::Store;
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};

// =================================================================================
// Harness
// =================================================================================

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

fn owner(attended: bool) -> Caller {
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

/// Profile `dev`: h1..h4, `ssh-authentication`.
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
            ordinary_aliases: None,
            owner_functions: None,
        },
        evidence: Vec::new(),
    }
}

fn outcome() -> PrepareOutcome {
    PrepareOutcome {
        usable_until: "2026-11-19T09:00:00Z".parse().unwrap(),
        offline_until: "2026-11-18T10:00:00Z".parse().unwrap(),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        // A synthetic canary that must never reach an envelope or an event.
        credential_ref: format!("{CANARY_PREFIX}u2_fixture"),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
        managed: None,
    }
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
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

/// One working directory of the fake filesystem (the root is the directory itself).
#[derive(Debug, Clone)]
struct Dir {
    identity: Option<FileIdentity>,
    git: Option<FileIdentity>,
    manifest: Man,
}

#[derive(Debug, Clone)]
enum Man {
    /// A `.git` root without a manifest.
    Bare,
    /// A valid manifest.
    Valid {
        digest: String,
        pairs: Vec<String>,
        background_work: bool,
        label: Option<String>,
    },
    /// The probe refuses the directory.
    Refused(ProbeError),
}

fn ident(ino: u64) -> FileIdentity {
    FileIdentity::Unix {
        dev: 41,
        ino,
        birth: None,
    }
}

fn digest_of(n: u64) -> String {
    format!("{n:064x}")
}

/// The scripted `WorkspaceProbe`: a table `cwd → Dir`, matched against the records it is
/// given exactly as ADR-0011 §2.3 prescribes for a checkout (equal path and identity:
/// trusted; one of them: ambiguous; neither: untrusted).
#[derive(Default)]
struct FakeProbe {
    dirs: Mutex<BTreeMap<String, Dir>>,
}

impl FakeProbe {
    fn set(&self, cwd: &str, dir: Dir) {
        self.dirs.lock().unwrap().insert(cwd.to_owned(), dir);
    }
    fn get(&self, cwd: &str) -> Option<Dir> {
        self.dirs.lock().unwrap().get(cwd).cloned()
    }
    fn edit(&self, cwd: &str, f: impl FnOnce(&mut Dir)) {
        if let Some(d) = self.dirs.lock().unwrap().get_mut(cwd) {
            f(d);
        }
    }
    fn remove(&self, cwd: &str) -> Option<Dir> {
        self.dirs.lock().unwrap().remove(cwd)
    }
}

fn match_records(
    root: &str,
    identity: &FileIdentity,
    records: &[WorkspaceRecord],
) -> WorkspaceMatch {
    if let Some(r) = records
        .iter()
        .find(|r| r.root == root && r.root_identity.same_file(identity))
    {
        return WorkspaceMatch::Trusted {
            workspace: r.id.clone(),
        };
    }
    for r in records {
        if r.root == root {
            return WorkspaceMatch::Ambiguous {
                workspace: r.id.clone(),
                why: AmbiguityReason::SamePathOtherIdentity,
            };
        }
        if r.root_identity.same_file(identity) {
            return WorkspaceMatch::Ambiguous {
                workspace: r.id.clone(),
                why: AmbiguityReason::SameIdentityOtherPath,
            };
        }
    }
    WorkspaceMatch::Untrusted
}

impl WorkspaceProbe for FakeProbe {
    fn probe(
        &self,
        _environment: &EnvironmentId,
        cwd: &str,
        records: &[WorkspaceRecord],
    ) -> Result<ProbedWorkspace, ProbeError> {
        assert!(
            records.iter().all(|r| r.state == WorkspaceState::Active),
            "the probe is given active records only"
        );
        let Some(d) = self.get(cwd) else {
            return Err(ProbeError::Io);
        };
        let manifest = match &d.manifest {
            Man::Refused(e) => return Err(*e),
            Man::Bare => None,
            Man::Valid {
                digest,
                pairs,
                background_work,
                label,
            } => Some(ProbedManifest {
                access_digest: digest.clone(),
                profile: dev(),
                pairs: pairs.clone(),
                environments: vec!["native".into()],
                capabilities: vec!["ssh-authentication".into()],
                background_work: *background_work,
                project_label: label.clone(),
            }),
        };
        Ok(ProbedWorkspace {
            root: Some(cwd.to_owned()),
            root_identity: d.identity.clone(),
            git_common_identity: d.git.clone(),
            matched: Some(d.identity.as_ref().map_or(WorkspaceMatch::Untrusted, |i| {
                match_records(cwd, i, records)
            })),
            manifest,
        })
    }
}

/// A session-lock source that always reads unlocked.
struct Unlocked(tokio::sync::Notify);

impl heimdall_app::ports::SessionLockSource for Unlocked {
    fn state(&self) -> heimdall_app::ports::LockState {
        heimdall_app::ports::LockState::Unlocked
    }
    fn lock_epoch(&self) -> heimdall_domain::managed::LockEpoch {
        heimdall_domain::managed::LockEpoch {
            epoch: 0,
            observed: false,
        }
    }
    fn acknowledge(&self, _epoch: u64) {}
    fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.0.notified()
    }
}

struct World {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    fake: Arc<FakeCredentialAdapter>,
    probe: Arc<FakeProbe>,
    ops: Operations,
}

fn seed(store: &Store) {
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            // Nothing is automatic until an approved decision says so.
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: false,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.upsert_profile(&ProfileDefinition {
                id: dev(),
                revision: 1,
                scope: Scope {
                    pairs: hosts(0b1111),
                    capabilities: ssh(),
                },
                label: None,
            })?;
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("ops").unwrap(),
                revision: 1,
                scope: Scope {
                    pairs: hosts(0b1100),
                    capabilities: ssh(),
                },
                label: None,
            })?;
            Ok(())
        })
        .unwrap();
}

impl World {
    async fn new() -> Self {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        seed(&store);
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let fake = FakeCredentialAdapter::new(descriptor(), vec![FakeStep::Prepare(outcome())]);
        let probe = Arc::new(FakeProbe::default());
        let ops = Self::start(&store, &clock, &sync, &fake, &probe).await;
        Self {
            store,
            clock,
            sync,
            fake,
            probe,
            ops,
        }
    }

    async fn start(
        store: &Arc<Store>,
        clock: &Arc<VirtualClock>,
        sync: &Arc<ScriptedTimeSync>,
        fake: &Arc<FakeCredentialAdapter>,
        probe: &Arc<FakeProbe>,
    ) -> Operations {
        let hook: Arc<dyn StageHook> = Arc::new(NoStageHook);
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: sync.clone(),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: vec![fake.clone() as Arc<dyn CredentialAdapter>],
            stage_hook: hook,
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        // An unlocked session-lock source, so `revoke_on_lock` may be recorded.
        ops.set_session_lock_source(Arc::new(Unlocked(tokio::sync::Notify::new())));
        assert!(ops.set_workspace_probe(probe.clone() as Arc<dyn WorkspaceProbe>));
        assert!(
            !ops.set_workspace_probe(probe.clone() as Arc<dyn WorkspaceProbe>),
            "set once"
        );
        ops
    }

    async fn restart(&mut self) {
        self.ops = Self::start(
            &self.store,
            &self.clock,
            &self.sync,
            &self.fake,
            &self.probe,
        )
        .await;
    }

    fn snap(&self) -> Snap {
        self.store
            .transaction(|tx| {
                Ok(Snap {
                    policies: tx
                        .policies()?
                        .into_iter()
                        .map(|p| (p.id.clone(), p))
                        .collect(),
                    workspaces: tx
                        .workspaces_in_environment(&env_id())?
                        .into_iter()
                        .map(|w| (w.id.clone(), w))
                        .collect(),
                    automatic: tx
                        .environment(&env_id())?
                        .is_some_and(|e| e.permissions.automatic_activation),
                    pending: tx.pending_decisions()?.into_iter().map(|d| d.id).collect(),
                })
            })
            .unwrap()
    }

    fn decision(&self, id: &DecisionId) -> heimdall_domain::decision::DecisionRecord {
        self.store
            .transaction(|tx| tx.decision(id))
            .unwrap()
            .unwrap()
    }

    fn pending(&self) -> Vec<heimdall_domain::decision::DecisionRecord> {
        self.store.transaction(|tx| tx.pending_decisions()).unwrap()
    }

    async fn policy(&self, attended: bool, action: PolicyAction) -> OpResult<serde_json::Value> {
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
}

/// Every envelope is scanned for the canary.
fn scan<T: serde::Serialize + Clone>(r: &OpResult<T>) {
    let v = match r {
        Ok(c) => serde_json::to_value(c.clone().into_envelope()).unwrap(),
        Err(e) => serde_json::to_value(e.clone().into_envelope()).unwrap(),
    };
    assert_no_canary(&v.to_string());
}

fn decision_ref(e: &OpError) -> DecisionId {
    DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
}

/// The authority state I1 is about.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    policies: BTreeMap<PolicyId, StandingPolicy>,
    workspaces: BTreeMap<WorkspaceId, WorkspaceRecord>,
    automatic: bool,
    pending: BTreeSet<DecisionId>,
}

fn create(default: bool) -> PolicyAction {
    PolicyAction::Create {
        profile: dev(),
        environments: [env_id()].into_iter().collect(),
        max_window: None,
        default,
    }
}

fn manifest(n: u64, bits: u8, background_work: bool, label: Option<&str>) -> Man {
    Man::Valid {
        digest: digest_of(n),
        pairs: HOSTS
            .iter()
            .enumerate()
            .filter(|(i, _)| bits & (1 << i) != 0)
            .map(|(_, h)| format!("{h}:deploy"))
            .collect(),
        background_work,
        label: label.map(str::to_owned),
    }
}

/// The request a reviewer who saw the directory's current state sends (the server's own
/// view: the manifest ∩ the profile, the `native` environment, `ssh-authentication`).
fn trust_request(cwd: &str, d: &Dir) -> PolicyAction {
    let (access_digest, proposal) = match &d.manifest {
        Man::Valid {
            digest,
            pairs,
            background_work,
            ..
        } => (
            digest.clone(),
            TrustProposal {
                profile: dev(),
                pairs: pairs
                    .iter()
                    .map(|t| pair(t.split_once(':').unwrap().0))
                    .collect(),
                environments: [env_id()].into_iter().collect(),
                capabilities: ssh(),
                background_work: *background_work,
            },
        ),
        _ => (
            String::new(),
            TrustProposal {
                profile: dev(),
                pairs: hosts(0b0001),
                environments: BTreeSet::new(),
                capabilities: BTreeSet::new(),
                background_work: false,
            },
        ),
    };
    PolicyAction::TrustWorkspace {
        cwd: cwd.to_owned(),
        access_digest,
        proposal,
    }
}

fn ensure_req(request_id: &str, work: &str, bits: u8) -> EnsureRequest {
    EnsureRequest {
        profile: Some(dev()),
        profile_revision: None,
        scope: hosts(bits),
        environment: None,
        work_id: WorkId::parse(work).unwrap(),
        until: None,
        required_capabilities: RequiredCapabilities::default(),
        request_id: RequestId::parse(request_id).unwrap(),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
        context: None,
        covered_only: false,
        pair_issuers: Vec::new(),
    }
}

// =================================================================================
// (d) A widening approval resumes the requests it now covers (personal context)
// =================================================================================

/// ADR-0006 §13.7 item 2 through U2's widening: an `ensure` waiting on its
/// `ApproveAuthority` record proceeds, with no second decision, when the owner approves a
/// `create` personal policy that covers it; its own record is withdrawn, not consumed.
/// The approval also sets the environment's `automatic_activation`, the new grant pins
/// the personal context, and `inspect policies` shows the policy with its history.
#[tokio::test]
async fn an_approved_create_resumes_the_covered_waiter_without_a_second_decision() {
    let w = World::new().await;
    let e = w
        .ops
        .ensure(&owner(false), ensure_req("d-1", "d-work", 0b0001))
        .await;
    scan(&e);
    let e = e.unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    let waiting = decision_ref(&e);
    let op: OperationId = e.operation_id.clone().unwrap();
    assert!(matches!(
        w.decision(&waiting).kind,
        DecisionKind::ApproveAuthority { .. }
    ));
    let e = w.policy(true, create(true)).await.unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired);
    let widen = decision_ref(&e);
    assert!(!w.snap().automatic, "nothing applied on dispatch");
    let done = w.decide(true, &widen, Verdict::Approve).await.unwrap();
    assert_eq!(done.data["state"], "approved");
    let observed = w
        .ops
        .observe(
            &owner(false),
            ObserveRequest::Operation {
                operation_id: op.clone(),
                wait_ms: Some(5_000),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        observed.state,
        OperationState::Succeeded,
        "{:?}",
        observed.data
    );
    assert_eq!(w.decision(&waiting).state, DecisionState::Withdrawn);
    assert!(w.pending().is_empty(), "no second decision");
    let all: usize = w
        .store
        .transaction(|tx| Ok(tx.table_counts()?.decisions))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(all, 2);
    let snap = w.snap();
    assert!(snap.automatic);
    let p = snap.policies.values().next().unwrap().clone();
    assert!(p.default && p.workspace.is_none());
    assert_eq!(p.scope.pairs, hosts(0b1111), "the profile's snapshot scope");
    // The binding pins the personal context.
    let bindings = w
        .store
        .transaction(|tx| tx.bindings_for_work(&env_id(), &WorkId::parse("d-work").unwrap()))
        .unwrap();
    assert_eq!(bindings.len(), 1);
    let context = w
        .store
        .transaction(|tx| tx.binding_context(&bindings[0].id))
        .unwrap();
    assert_eq!(context, Some(BindingContext::Personal));
    // Fresh work is covered by the policy, and its grant's origin names it.
    let next = w
        .ops
        .ensure(&owner(false), ensure_req("d-2", "d-work-2", 0b0010))
        .await
        .unwrap();
    let origin = w
        .store
        .transaction(|tx| tx.grant_origin(&next.data.grant_id))
        .unwrap()
        .unwrap();
    assert_eq!(origin.policy_id, Some(p.id.clone()));
    assert_eq!(origin.workspace, None);
    // `inspect policies`: the policy, its default flag and its one applied revision.
    let view = w
        .ops
        .inspect(
            &owner(false),
            InspectRequest {
                subject: InspectSubject::Policies,
                preview: None,
                cwd: None,
                redact: false,
                select: None,
                page: None,
            },
        )
        .await
        .unwrap();
    let view: PoliciesView = serde_json::from_value(view.data).unwrap();
    assert_eq!(view.items.len(), 1);
    let item = &view.items[0];
    assert_eq!(item.policy_id, p.id);
    assert!(item.default);
    assert_eq!(item.environments, vec![env_id()]);
    assert_eq!(item.history.len(), 1);
    assert_eq!(item.history[0].cause, "decision");
    assert_eq!(item.history[0].decision_id, Some(widen));
    // A limited consumer sees nothing.
    let limited = Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 502 },
        role: ClientRole::LimitedConsumer,
        remote_client: None,
    });
    let none = w
        .ops
        .inspect(
            &limited,
            InspectRequest {
                subject: InspectSubject::Policies,
                preview: None,
                cwd: None,
                redact: false,
                select: None,
                page: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(none.data, serde_json::json!({ "items": [] }));
}

// =================================================================================
// TrustWorkspace and ReconcileWorkspace
// =================================================================================

/// ⟨W1 Windows fix⟩ A working directory is an absolute path by **this platform's** rule
/// (`WorkContext::validate`): `/w/...` is not absolute on Windows, which has no drive there,
/// so every fixture directory is written in the platform's absolute form.
fn wdir(name: &str) -> String {
    if cfg!(windows) {
        format!(r"C:\w\{name}")
    } else {
        format!("/w/{name}")
    }
}

const REPO: &str = if cfg!(windows) {
    r"C:\w\repo"
} else {
    "/w/repo"
};

fn repo(ino: u64, man: Man) -> Dir {
    Dir {
        identity: Some(ident(ino)),
        git: Some(ident(ino + 1)),
        manifest: man,
    }
}

/// A trust decision applies in one transaction: one workspace record (root, identity, Git
/// common identity, decision), one workspace policy (the proposal's pairs, the target
/// environment, `revoke_on_lock`-free lock behaviour only because nothing personal is
/// stricter), the environment's `automatic_activation`, the pending lock-disclosure
/// acknowledgement, and one history row. The project label is quoted data only.
#[tokio::test]
async fn trust_workspace_applies_the_record_it_was_created_from() {
    let w = World::new().await;
    w.probe.set(
        REPO,
        repo(
            100,
            manifest(1, 0b0011, false, Some("infra $(id)\n\u{202E}x")),
        ),
    );
    let req = trust_request(REPO, &w.probe.get(REPO).unwrap());
    let e = w.policy(false, req.clone()).await.unwrap_err();
    assert_eq!(
        e.code,
        Code::InteractionRequired,
        "unattended: a record, not an apply"
    );
    let d = decision_ref(&e);
    let rec = w.decision(&d);
    let DecisionKind::TrustWorkspace {
        action,
        project_label,
        lock_disclosure,
    } = &rec.kind
    else {
        panic!("{:?}", rec.kind)
    };
    assert_eq!(*action, req, "the verbatim server-built action");
    assert_eq!(project_label.as_deref(), Some("infra $(id)x"));
    assert!(*lock_disclosure);
    // The same request again: the same record.
    let again = w.policy(true, req.clone()).await.unwrap_err();
    assert_eq!(again.code, Code::ApprovalRequired);
    assert_eq!(decision_ref(&again), d);
    // An unattended decide is refused and consumes nothing.
    let refused = w.decide(false, &d, Verdict::Approve).await.unwrap_err();
    assert_eq!(refused.code, Code::InteractionRequired);
    assert_eq!(w.decision(&d).state, DecisionState::Pending);
    w.decide(true, &d, Verdict::Approve).await.unwrap();
    let snap = w.snap();
    assert_eq!(snap.workspaces.len(), 1);
    let ws = snap.workspaces.values().next().unwrap();
    assert_eq!(ws.root, REPO);
    assert_eq!(ws.root_identity, ident(100));
    assert_eq!(ws.git_common_identity, Some(ident(101)));
    assert_eq!(ws.decision, d);
    let p = snap.policies.values().next().unwrap();
    assert_eq!(p.workspace.as_ref(), Some(&ws.id));
    assert_eq!(p.scope.pairs, hosts(0b0011));
    assert_eq!(p.environments, [env_id()].into_iter().collect());
    assert_eq!(p.lock_behavior, LockBehavior::Continue);
    assert!(snap.automatic);
    let ack = w.store.transaction(|tx| tx.lock_disclosure_ack()).unwrap();
    assert!(
        ack.is_some(),
        "the pending lock disclosure was acknowledged"
    );
    let history = w.store.transaction(|tx| tx.policy_history(&p.id)).unwrap();
    assert_eq!(history.len(), 1);
    // Trusted now: a second trust request writes no record and returns the policy.
    let same = w.policy(true, req).await.unwrap();
    assert_eq!(same.data["policy_id"], p.id.as_str());
    assert_eq!(same.data["changed"], false);
    assert!(w.pending().is_empty());
}

/// I5 at request time (revert proof 1): a request whose proposal or access digest is not
/// what the server observes and computes is refused `USAGE_ERROR` and writes nothing,
/// whatever the attendance.
#[tokio::test]
async fn trust_workspace_refuses_a_request_unlike_the_servers_view() {
    let w = World::new().await;
    w.probe
        .set(REPO, repo(100, manifest(1, 0b0001, false, None)));
    let honest = trust_request(REPO, &w.probe.get(REPO).unwrap());
    let PolicyAction::TrustWorkspace {
        cwd,
        access_digest,
        proposal,
    } = honest
    else {
        unreachable!()
    };
    let wider = TrustProposal {
        pairs: hosts(0b0111),
        ..proposal.clone()
    };
    let background = TrustProposal {
        background_work: true,
        ..proposal.clone()
    };
    let before = w.snap();
    for (proposal, access_digest) in [
        (wider, access_digest.clone()),
        (background, access_digest.clone()),
        (proposal.clone(), digest_of(2)),
    ] {
        for attended in [true, false] {
            let e = w
                .policy(
                    attended,
                    PolicyAction::TrustWorkspace {
                        cwd: cwd.clone(),
                        access_digest: access_digest.clone(),
                        proposal: proposal.clone(),
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(e.code, Code::UsageError, "{proposal:?} {access_digest}");
            assert!(e.next.decision_ref.is_none());
            assert_eq!(w.snap(), before, "nothing was written");
        }
    }
}

/// I5 at approval time (revert proof 2): the approval re-probes the working directory
/// before its transaction and requires the observation the record was created from (root,
/// identity, access digest); a changed one is `DECISION_STALE` and the record stays
/// pending, not consumed. Restored, it applies.
#[tokio::test]
async fn trust_approval_refuses_a_changed_observation_without_consuming() {
    let w = World::new().await;
    w.probe
        .set(REPO, repo(100, manifest(1, 0b0001, false, None)));
    let req = trust_request(REPO, &w.probe.get(REPO).unwrap());
    let d = decision_ref(&w.policy(true, req).await.unwrap_err());
    let honest = w.probe.get(REPO).unwrap();
    let before = w.snap();
    // A re-clone at the same path (identity flip), then a manifest edit (digest flip), then
    // (review M05-W1-R01) the Git common directory replaced, reinitialized or removed while
    // the root and the manifest stay as reviewed: a common-only flip, its disappearance,
    // and (from a root reviewed without one) its appearance.
    for flipped in [
        repo(900, honest.manifest.clone()),
        Dir {
            manifest: manifest(7, 0b0001, false, None),
            ..honest.clone()
        },
        Dir {
            git: Some(ident(999)),
            ..honest.clone()
        },
        Dir {
            git: None,
            ..honest.clone()
        },
    ] {
        w.probe.set(REPO, flipped);
        let e = w.decide(true, &d, Verdict::Approve).await.unwrap_err();
        assert_eq!(e.code, Code::DecisionStale);
        assert_eq!(w.decision(&d).state, DecisionState::Pending, "not consumed");
        assert_eq!(w.snap(), before, "nothing applied");
    }
    w.probe.set(REPO, honest.clone());
    w.decide(true, &d, Verdict::Approve).await.unwrap();
    let snap = w.snap();
    assert_eq!(snap.workspaces.len(), 1);
    assert_eq!(
        snap.workspaces.values().next().unwrap().git_common_identity,
        honest.git,
        "the record keeps the reviewed common directory"
    );

    // A root reviewed with no Git common directory: one appearing before approval is not
    // what was reviewed either.
    let other = if cfg!(windows) {
        r"C:\w\plain"
    } else {
        "/w/plain"
    };
    let plain = Dir {
        git: None,
        ..repo(300, manifest(3, 0b0001, false, None))
    };
    w.probe.set(other, plain.clone());
    let d2 = decision_ref(
        &w.policy(true, trust_request(other, &plain))
            .await
            .unwrap_err(),
    );
    let before = w.snap();
    w.probe.set(
        other,
        Dir {
            git: Some(ident(777)),
            ..plain.clone()
        },
    );
    let e = w.decide(true, &d2, Verdict::Approve).await.unwrap_err();
    assert_eq!(e.code, Code::DecisionStale);
    assert_eq!(
        w.decision(&d2).state,
        DecisionState::Pending,
        "not consumed"
    );
    assert_eq!(w.snap(), before, "nothing applied");
}

/// ⟨W3, from U9a⟩ An owner `extend_scope` records only the authority the policy lacks
/// (spec §12.3: a review shows the added authority, never the whole scope). A request
/// naming a pair the policy already has and one it lacks gets a record listing only the
/// missing pair, and approving it widens exactly that (ADR-0011 I5: the action is fixed
/// from server state when the record is created).
#[tokio::test]
async fn an_owner_extension_records_only_the_added_authority() {
    let w = World::new().await;
    let d = decision_ref(&w.policy(true, create(false)).await.unwrap_err());
    w.decide(true, &d, Verdict::Approve).await.unwrap();
    let pid = w.snap().policies.keys().next().unwrap().clone();
    w.policy(
        true,
        PolicyAction::NarrowScope {
            policy_id: pid.clone(),
            pairs: hosts(0b1100),
        },
    )
    .await
    .unwrap();
    assert_eq!(w.snap().policies[&pid].scope.pairs, hosts(0b0011));
    let e = w
        .policy(
            true,
            PolicyAction::ExtendScope {
                policy_id: pid.clone(),
                pairs: hosts(0b0101),
                capabilities: BTreeSet::new(),
                environments: BTreeSet::new(),
                background_work: None,
            },
        )
        .await
        .unwrap_err();
    let id = decision_ref(&e);
    match w.decision(&id).kind {
        DecisionKind::WidenPolicy {
            action: PolicyAction::ExtendScope { pairs, .. },
        } => assert_eq!(pairs, hosts(0b0100), "only the missing pair"),
        other => panic!("{other:?}"),
    }
    w.decide(true, &id, Verdict::Approve).await.unwrap();
    assert_eq!(w.snap().policies[&pid].scope.pairs, hosts(0b0111));
}

/// `ReconcileWorkspace`: a re-clone at the same path is ambiguous; the decision, approved
/// against an unchanged re-probe, marks the old record `stale`, writes a new record (new
/// ID) and moves the policy to it (its revision and history row). A re-probe that no
/// longer matches the same way is `DECISION_STALE`, not consumed.
#[tokio::test]
async fn reconcile_moves_the_policy_to_a_new_record() {
    let w = World::new().await;
    w.probe.set(REPO, repo(100, Man::Bare));
    let req = trust_request(REPO, &w.probe.get(REPO).unwrap());
    let d = decision_ref(&w.policy(true, req).await.unwrap_err());
    w.decide(true, &d, Verdict::Approve).await.unwrap();
    let snap = w.snap();
    let old = snap.workspaces.keys().next().unwrap().clone();
    let pid = snap.policies.keys().next().unwrap().clone();
    // Re-cloned at the same path: a new identity.
    w.probe.set(REPO, repo(200, Man::Bare));
    let trust_again = w
        .policy(true, trust_request(REPO, &w.probe.get(REPO).unwrap()))
        .await
        .unwrap_err();
    assert_eq!(
        trust_again.code,
        Code::UsageError,
        "ambiguous: reconcile, not trust"
    );
    let action = PolicyAction::ReconcileWorkspace {
        workspace: old.clone(),
        cwd: REPO.into(),
    };
    let r = decision_ref(&w.policy(true, action).await.unwrap_err());
    assert!(matches!(
        w.decision(&r).kind,
        DecisionKind::ReconcileWorkspace {
            why: AmbiguityReason::SamePathOtherIdentity,
            ..
        }
    ));
    // The checkout changes again before approval: stale, not consumed.
    w.probe.set(REPO, repo(100, Man::Bare));
    let e = w.decide(true, &r, Verdict::Approve).await.unwrap_err();
    assert_eq!(e.code, Code::DecisionStale);
    assert_eq!(w.decision(&r).state, DecisionState::Pending);
    // ADR-0011 I5 (integrator, W1 security finding): re-cloned yet again at the same path
    // before approval. The observation is still `Ambiguous{SamePathOtherIdentity}` against
    // the same record, but it is not the checkout the record was created from: stale, not
    // consumed, and nothing is written for the third identity.
    w.probe.set(REPO, repo(300, Man::Bare));
    let e = w.decide(true, &r, Verdict::Approve).await.unwrap_err();
    assert_eq!(e.code, Code::DecisionStale);
    assert_eq!(w.decision(&r).state, DecisionState::Pending);
    assert!(
        w.snap()
            .workspaces
            .values()
            .all(|r| r.root_identity != ident(300)),
        "no record for an identity the owner never reviewed"
    );
    w.probe.set(REPO, repo(200, Man::Bare));
    w.decide(true, &r, Verdict::Approve).await.unwrap();
    let after = w.snap();
    assert_eq!(after.workspaces[&old].state, WorkspaceState::Stale);
    let new: Vec<_> = after
        .workspaces
        .values()
        .filter(|r| r.state == WorkspaceState::Active)
        .collect();
    assert_eq!(new.len(), 1);
    assert_ne!(new[0].id, old);
    assert_eq!(new[0].root_identity, ident(200));
    let p = &after.policies[&pid];
    assert_eq!(p.workspace.as_ref(), Some(&new[0].id));
    assert_eq!(p.revision, PolicyRevision(2));
    let history = w.store.transaction(|tx| tx.policy_history(&pid)).unwrap();
    assert_eq!(history.len(), 2);
}

// =================================================================================
// P9: one path creates or widens authority (ADR-0011 I1)
// =================================================================================

mod p9 {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    fn config(seed: u64) -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 128,
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

    const DIRS: usize = 3;

    fn cwd(i: u8) -> String {
        wdir(&format!("d{}", usize::from(i) % DIRS))
    }

    /// Hostile labels: shell text, newlines, bidirectional and zero-width controls.
    const LABELS: [&str; 4] = [
        "$(rm -rf ~)",
        "`id` && echo pwned",
        "line1\nline2\r\n\t",
        "\u{202E}cod.exe\u{2066}\u{200B}",
    ];

    #[derive(Debug, Clone)]
    enum Step {
        /// A request immediately followed by its attended approval (`flip` mutates the
        /// probe in between: 0 none, 1 identity, 2 digest, 3 the Git common directory
        /// replaced, 4 it removed; review M05-W1-R01).
        Approved {
            which: u8,
            arg: u8,
            flip: u8,
        },
        Create {
            default: bool,
            window: u8,
        },
        Extend {
            p: u8,
            bits: u8,
            bg: Option<bool>,
        },
        Narrow {
            p: u8,
            bits: u8,
        },
        Window {
            p: u8,
            hours: u8,
        },
        Remove {
            p: u8,
        },
        Pause {
            p: u8,
        },
        Resume {
            p: u8,
        },
        Cutoff {
            p: u8,
            minutes: u8,
        },
        Lock {
            p: u8,
            keep: bool,
        },
        Trust {
            dir: u8,
            tamper: u8,
            attended: bool,
        },
        /// ⟨W1 Windows fix⟩ A trust or reconcile request whose working directory is not
        /// absolute by this platform's rule (`form`: relative, rooted without a drive on
        /// Windows, empty, too long): `USAGE_ERROR` before anything is read or written.
        BadCwd {
            dir: u8,
            form: u8,
            reconcile: bool,
            attended: bool,
        },
        Reconcile {
            dir: u8,
            ws: u8,
        },
        Decide {
            pick: u8,
            attended: bool,
            approve: bool,
        },
        Forged {
            which: u8,
        },
        FlipIdentity {
            dir: u8,
        },
        FlipDigest {
            dir: u8,
            bits: u8,
            bg: bool,
        },
        Hostile {
            dir: u8,
            which: u8,
        },
        Raise {
            p: u8,
            bits: u8,
            bg: bool,
        },
        CoveredOnly {
            with_context: bool,
        },
        Advance {
            minutes: u8,
        },
        Restart,
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            8 => (0u8..6, any::<u8>(), prop_oneof![6 => Just(0u8), 1 => Just(1u8), 1 => Just(2u8), 1 => Just(3u8), 1 => Just(4u8)])
                .prop_map(|(which, arg, flip)| Step::Approved { which, arg, flip }),
            3 => (any::<bool>(), 0u8..3).prop_map(|(default, window)| Step::Create { default, window }),
            2 => (any::<u8>(), 1u8..16, prop::option::of(any::<bool>()))
                .prop_map(|(p, bits, bg)| Step::Extend { p, bits, bg }),
            2 => (any::<u8>(), 1u8..16).prop_map(|(p, bits)| Step::Narrow { p, bits }),
            1 => (any::<u8>(), 1u8..14).prop_map(|(p, hours)| Step::Window { p, hours }),
            1 => any::<u8>().prop_map(|p| Step::Remove { p }),
            1 => any::<u8>().prop_map(|p| Step::Pause { p }),
            1 => any::<u8>().prop_map(|p| Step::Resume { p }),
            1 => (any::<u8>(), any::<u8>()).prop_map(|(p, minutes)| Step::Cutoff { p, minutes }),
            1 => (any::<u8>(), any::<bool>()).prop_map(|(p, keep)| Step::Lock { p, keep }),
            4 => (any::<u8>(), 0u8..4, any::<bool>())
                .prop_map(|(dir, tamper, attended)| Step::Trust { dir, tamper, attended }),
            1 => (any::<u8>(), 0u8..4, any::<bool>(), any::<bool>()).prop_map(
                |(dir, form, reconcile, attended)| Step::BadCwd { dir, form, reconcile, attended }
            ),
            2 => (any::<u8>(), any::<u8>()).prop_map(|(dir, ws)| Step::Reconcile { dir, ws }),
            6 => (any::<u8>(), any::<bool>(), any::<bool>())
                .prop_map(|(pick, attended, approve)| Step::Decide { pick, attended, approve }),
            1 => any::<u8>().prop_map(|which| Step::Forged { which }),
            2 => any::<u8>().prop_map(|dir| Step::FlipIdentity { dir }),
            2 => (any::<u8>(), 1u8..16, any::<bool>())
                .prop_map(|(dir, bits, bg)| Step::FlipDigest { dir, bits, bg }),
            2 => (any::<u8>(), 0u8..7).prop_map(|(dir, which)| Step::Hostile { dir, which }),
            2 => (any::<u8>(), 1u8..16, any::<bool>())
                .prop_map(|(p, bits, bg)| Step::Raise { p, bits, bg }),
            1 => any::<bool>().prop_map(|with_context| Step::CoveredOnly { with_context }),
            1 => (1u8..40).prop_map(|minutes| Step::Advance { minutes }),
            1 => Just(Step::Restart),
        ]
    }

    /// What a trust record was created from (the oracle for approval-time I5).
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        identity: Option<FileIdentity>,
        /// The Git common directory's identity (review M05-W1-R01).
        git: Option<FileIdentity>,
        digest: Option<String>,
    }

    fn seen(d: &Dir) -> Seen {
        Seen {
            identity: d.identity.clone(),
            git: d.git.clone(),
            digest: match &d.manifest {
                Man::Valid { digest, .. } => Some(digest.clone()),
                _ => None,
            },
        }
    }

    fn widens(old: &StandingPolicy, new: &StandingPolicy) -> bool {
        !new.scope.pairs.is_subset(&old.scope.pairs)
            || !new.scope.capabilities.is_subset(&old.scope.capabilities)
            || !new.environments.is_subset(&old.environments)
            || new.max_window > old.max_window
            || (matches!(old.pause, PauseState::Paused { .. }) && new.pause == PauseState::Active)
            || old
                .cutoff_at
                .is_some_and(|c| new.cutoff_at.is_none_or(|n| n > c))
            || (old.lock_behavior == LockBehavior::RevokeOnLock
                && new.lock_behavior == LockBehavior::Continue)
            || old.workspace != new.workspace
            || (!old.default && new.default)
    }

    fn action_policy(a: &PolicyAction) -> Option<&PolicyId> {
        match a {
            PolicyAction::ExtendScope { policy_id, .. }
            | PolicyAction::SetMaxWindow { policy_id, .. } => Some(policy_id),
            other => other.policy_id(),
        }
    }

    /// I1 over one step: every policy, workspace record and `automatic_activation` that is
    /// new or wider after the step is explained by `approved`, the kind of the record an
    /// attended owner `decide` applied in that step; nothing else ever creates or widens.
    fn check_i1(
        before: &Snap,
        after: &Snap,
        approved: Option<&DecisionKind>,
    ) -> Result<(), TestCaseError> {
        let created: Vec<&StandingPolicy> = after
            .policies
            .values()
            .filter(|p| !before.policies.contains_key(&p.id))
            .collect();
        prop_assert!(created.len() <= 1, "one policy per decision");
        for p in &created {
            match approved {
                Some(DecisionKind::WidenPolicy {
                    action:
                        PolicyAction::Create {
                            profile,
                            environments,
                            default,
                            ..
                        },
                }) => {
                    prop_assert!(p.workspace.is_none());
                    prop_assert_eq!(&p.profile, profile);
                    prop_assert_eq!(&p.environments, environments);
                    prop_assert_eq!(p.default, *default);
                }
                Some(DecisionKind::TrustWorkspace {
                    action: PolicyAction::TrustWorkspace { proposal, .. },
                    ..
                }) => {
                    prop_assert!(p.workspace.is_some());
                    prop_assert_eq!(&p.profile, &proposal.profile);
                    // Ruling §10 item 2: `continue` only when the reviewed proposal asked
                    // for background work; otherwise never wider than the personal
                    // policies already approved for the profile there.
                    let personal_strictest = before
                        .policies
                        .values()
                        .filter(|q| {
                            q.workspace.is_none()
                                && q.profile == p.profile
                                && !q.environments.is_disjoint(&p.environments)
                        })
                        .map(|q| q.lock_behavior)
                        .reduce(heimdall_domain::policy::strictest_lock_behavior)
                        .unwrap_or_default();
                    let want = if proposal.background_work {
                        LockBehavior::Continue
                    } else {
                        personal_strictest
                    };
                    prop_assert_eq!(p.lock_behavior, want);
                }
                other => prop_assert!(false, "policy {} created by {:?}", p.id, other),
            }
        }
        for (id, new) in &after.policies {
            let Some(old) = before.policies.get(id) else {
                continue;
            };
            if !widens(old, new) {
                continue;
            }
            let explained = match approved {
                Some(DecisionKind::WidenPolicy { action }) => action_policy(action) == Some(id),
                Some(DecisionKind::ReconcileWorkspace {
                    action: PolicyAction::ReconcileWorkspace { workspace, .. },
                    ..
                }) => old.workspace.as_ref() == Some(workspace),
                _ => false,
            };
            prop_assert!(explained, "policy {} widened by {:?}", id, approved);
            if let Some(DecisionKind::WidenPolicy {
                action:
                    PolicyAction::ExtendScope {
                        pairs,
                        environments,
                        ..
                    },
            }) = approved
            {
                let exact: BTreeSet<AccessPair> = old.scope.pairs.union(pairs).cloned().collect();
                prop_assert_eq!(&new.scope.pairs, &exact, "exactly the recorded delta");
                let envs: BTreeSet<EnvironmentId> =
                    old.environments.union(environments).cloned().collect();
                prop_assert_eq!(&new.environments, &envs);
            }
        }
        let new_ws: Vec<&WorkspaceRecord> = after
            .workspaces
            .values()
            .filter(|w| !before.workspaces.contains_key(&w.id))
            .collect();
        prop_assert!(new_ws.len() <= 1);
        if !new_ws.is_empty() {
            prop_assert!(
                matches!(
                    approved,
                    Some(
                        DecisionKind::TrustWorkspace { .. }
                            | DecisionKind::ReconcileWorkspace { .. }
                    )
                ),
                "workspace record created by {:?}",
                approved
            );
        }
        for (id, old) in &before.workspaces {
            prop_assert!(
                !(old.state == WorkspaceState::Stale
                    && after.workspaces[id].state == WorkspaceState::Active),
                "a stale record never returns"
            );
        }
        if !before.automatic && after.automatic {
            prop_assert!(
                matches!(
                    approved,
                    Some(
                        DecisionKind::TrustWorkspace { .. }
                            | DecisionKind::WidenPolicy {
                                action: PolicyAction::Create { .. }
                                    | PolicyAction::ExtendScope { .. }
                            }
                    )
                ),
                "automatic_activation set by {:?}",
                approved
            );
        }
        Ok(())
    }

    fn nth<T>(v: &[T], i: u8) -> Option<&T> {
        (!v.is_empty()).then(|| &v[usize::from(i) % v.len()])
    }

    #[allow(clippy::too_many_lines)]
    async fn run(steps: Vec<Step>) -> Result<(), TestCaseError> {
        let mut w = World::new().await;
        for (i, label) in LABELS.iter().enumerate().take(DIRS) {
            let man = if i == 2 {
                Man::Bare
            } else {
                manifest(i as u64 + 1, 0b0011, i == 1, Some(label))
            };
            w.probe
                .set(&wdir(&format!("d{i}")), repo(100 * (i as u64 + 1), man));
        }
        let mut trust_seen: BTreeMap<DecisionId, (String, Seen)> = BTreeMap::new();
        let mut consumed: Vec<DecisionId> = Vec::new();
        let mut n: u64 = 10;
        for s in steps {
            n += 1;
            let before = w.snap();
            let pols: Vec<PolicyId> = before.policies.keys().cloned().collect();
            let mut approved: Option<DecisionKind> = None;
            match s {
                Step::Approved { which, arg, flip } => {
                    let req = match which {
                        0 | 1 => Some(PolicyAction::Create {
                            profile: if which == 0 {
                                dev()
                            } else {
                                ProfileId::parse("ops").unwrap()
                            },
                            environments: [env_id()].into_iter().collect(),
                            max_window: (arg.is_multiple_of(2)).then(|| "3h".to_owned()),
                            default: arg.is_multiple_of(3),
                        }),
                        2 => {
                            let c = cwd(arg);
                            w.probe.get(&c).map(|d| trust_request(&c, &d))
                        }
                        5 => {
                            // A reconcile of a checkout that partly matches a record.
                            let mut found = None;
                            for r in before.workspaces.values() {
                                if r.state != WorkspaceState::Active {
                                    continue;
                                }
                                for i in 0..DIRS {
                                    let c = wdir(&format!("d{i}"));
                                    if let Some(d) = w.probe.get(&c)
                                        && let Some(id) = &d.identity
                                        && ((r.root == c) != r.root_identity.same_file(id))
                                    {
                                        found = Some(PolicyAction::ReconcileWorkspace {
                                            workspace: r.id.clone(),
                                            cwd: c,
                                        });
                                    }
                                }
                            }
                            if found.is_none()
                                && let Some(r) = before
                                    .workspaces
                                    .values()
                                    .find(|r| r.state == WorkspaceState::Active)
                                && w.probe.get(&r.root).is_some()
                            {
                                // Re-clone the trusted checkout at the same path.
                                w.probe
                                    .edit(&r.root, |d| d.identity = Some(ident(5000 + n)));
                                found = Some(PolicyAction::ReconcileWorkspace {
                                    workspace: r.id.clone(),
                                    cwd: r.root.clone(),
                                });
                            }
                            found
                        }
                        3 => nth(&pols, arg).map(|pid| PolicyAction::ExtendScope {
                            policy_id: pid.clone(),
                            pairs: hosts(arg % 16),
                            capabilities: BTreeSet::new(),
                            environments: BTreeSet::new(),
                            background_work: Some(arg.is_multiple_of(2)),
                        }),
                        _ => nth(&pols, arg).map(|pid| PolicyAction::SetMaxWindow {
                            policy_id: pid.clone(),
                            max_window: format!("{}h", 1 + arg % 12),
                        }),
                    };
                    let Some(req) = req else {
                        continue;
                    };
                    let trust_cwd = match &req {
                        PolicyAction::TrustWorkspace { cwd, .. } => Some(cwd.clone()),
                        _ => None,
                    };
                    let r = w.policy(arg.is_multiple_of(2), req).await;
                    if let Err(e) = &r
                        && e.next.decision_ref.is_some()
                    {
                        let id = decision_ref(e);
                        if let Some(c) = &trust_cwd
                            && let Some(d) = w.probe.get(c)
                        {
                            trust_seen
                                .entry(id.clone())
                                .or_insert((c.clone(), seen(&d)));
                            match flip {
                                1 => w.probe.edit(c, |d| {
                                    if let Some(FileIdentity::Unix { ino, .. }) = &mut d.identity {
                                        *ino += 1000;
                                    }
                                }),
                                2 => w.probe.edit(c, |d| {
                                    d.manifest = manifest(n, 0b0110, false, None);
                                }),
                                // Review M05-W1-R01: the Git common directory replaced
                                // (or reinitialized), then removed, root and manifest kept.
                                3 => w.probe.edit(c, |d| d.git = Some(ident(5000 + n))),
                                4 => w.probe.edit(c, |d| d.git = None),
                                _ => {}
                            }
                        }
                        let kind = w.decision(&id).kind;
                        let r = w.decide(true, &id, Verdict::Approve).await;
                        if let Ok(v) = &r {
                            consumed.push(id.clone());
                            prop_assert_eq!(&v.data["state"], "approved");
                            if let (DecisionKind::TrustWorkspace { .. }, Some((c, at))) =
                                (&kind, trust_seen.get(&id))
                            {
                                let now = w.probe.get(c).map(|x| seen(&x));
                                prop_assert_eq!(
                                    now.as_ref(),
                                    Some(at),
                                    "approved only against the observation it was created from"
                                );
                            }
                            approved = Some(kind);
                        } else if trust_cwd.is_some() && flip != 0 {
                            let e = r.unwrap_err();
                            prop_assert_eq!(e.code, Code::DecisionStale);
                            prop_assert_eq!(
                                w.decision(&id).state,
                                DecisionState::Pending,
                                "not consumed"
                            );
                        }
                    }
                }
                Step::Create { default, window } => {
                    let r = w
                        .policy(
                            true,
                            PolicyAction::Create {
                                profile: dev(),
                                environments: [env_id()].into_iter().collect(),
                                max_window: [None, Some("2h".to_owned()), Some("PT12H".to_owned())]
                                    [usize::from(window)]
                                .clone(),
                                default,
                            },
                        )
                        .await;
                    if let Err(e) = &r {
                        prop_assert!(matches!(e.code, Code::ApprovalRequired | Code::UsageError));
                    } else {
                        prop_assert!(false, "a create is never applied on dispatch");
                    }
                }
                Step::Extend { p, bits, bg } => {
                    if let Some(pid) = nth(&pols, p) {
                        let _ = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::ExtendScope {
                                    policy_id: pid.clone(),
                                    pairs: hosts(bits),
                                    capabilities: BTreeSet::new(),
                                    environments: BTreeSet::new(),
                                    background_work: bg,
                                },
                            )
                            .await;
                        let after = w.snap();
                        if bg == Some(false)
                            && hosts(bits).is_subset(&before.policies[pid].scope.pairs)
                            && after.policies.contains_key(pid)
                        {
                            prop_assert_eq!(
                                after.policies[pid].lock_behavior,
                                LockBehavior::RevokeOnLock,
                                "the narrowing applies at once"
                            );
                        }
                    }
                }
                Step::Narrow { p, bits } => {
                    if let Some(pid) = nth(&pols, p) {
                        let r = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::NarrowScope {
                                    policy_id: pid.clone(),
                                    pairs: hosts(bits),
                                },
                            )
                            .await;
                        prop_assert!(r.is_ok(), "{:?}", r.err().map(|e| e.code));
                        let after = w.snap();
                        prop_assert!(
                            after.policies[pid].scope.pairs.is_disjoint(&hosts(bits)),
                            "the narrowing applies at once"
                        );
                    }
                }
                Step::Window { p, hours } => {
                    if let Some(pid) = nth(&pols, p) {
                        let r = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::SetMaxWindow {
                                    policy_id: pid.clone(),
                                    max_window: format!("{hours}h"),
                                },
                            )
                            .await;
                        let want = Duration::from_secs(u64::from(hours) * 3600);
                        let old = before.policies[pid].max_window;
                        match r {
                            Ok(_) => prop_assert!(want <= old),
                            Err(e) if hours > 12 => prop_assert_eq!(e.code, Code::UsageError),
                            Err(e) => {
                                prop_assert!(want > old);
                                prop_assert!(matches!(
                                    e.code,
                                    Code::ApprovalRequired | Code::InteractionRequired
                                ));
                            }
                        }
                        if want <= old {
                            prop_assert_eq!(w.snap().policies[pid].max_window, want);
                        }
                    }
                }
                Step::Remove { p } => {
                    if let Some(pid) = nth(&pols, p) {
                        let r = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::Remove {
                                    policy_id: pid.clone(),
                                },
                            )
                            .await;
                        prop_assert!(r.is_ok());
                        let after = w.snap();
                        prop_assert!(!after.policies.contains_key(pid), "removed at once");
                        if let Some(ws) = &before.policies[pid].workspace {
                            prop_assert_eq!(after.workspaces[ws].state, WorkspaceState::Stale);
                        }
                    }
                }
                Step::Pause { p } => {
                    if let Some(pid) = nth(&pols, p) {
                        let r = w
                            .policy(
                                false,
                                PolicyAction::Pause {
                                    policy_id: Some(pid.clone()),
                                    target: None,
                                },
                            )
                            .await;
                        prop_assert!(r.is_ok());
                        let paused =
                            matches!(w.snap().policies[pid].pause, PauseState::Paused { .. });
                        prop_assert!(paused, "a pause applies at once");
                    }
                }
                Step::Resume { p } => {
                    if let Some(pid) = nth(&pols, p) {
                        let _ = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::Resume {
                                    policy_id: Some(pid.clone()),
                                    target: None,
                                },
                            )
                            .await;
                    }
                }
                Step::Cutoff { p, minutes } => {
                    if let Some(pid) = nth(&pols, p) {
                        let at = w
                            .clock_wall()
                            .checked_add(jiff::SignedDuration::from_mins(i64::from(minutes) + 1));
                        let _ = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::Cutoff {
                                    policy_id: Some(pid.clone()),
                                    at: at.unwrap(),
                                    target: None,
                                },
                            )
                            .await;
                    }
                }
                Step::Lock { p, keep } => {
                    if let Some(pid) = nth(&pols, p) {
                        let _ = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::SetLockBehavior {
                                    policy_id: pid.clone(),
                                    behavior: if keep {
                                        LockBehavior::Continue
                                    } else {
                                        LockBehavior::RevokeOnLock
                                    },
                                },
                            )
                            .await;
                    }
                }
                Step::BadCwd {
                    dir,
                    form,
                    reconcile,
                    attended,
                } => {
                    let good = cwd(dir);
                    let Some(d) = w.probe.get(&good) else {
                        continue;
                    };
                    let name = format!("d{}", usize::from(dir) % DIRS);
                    let bad = match form {
                        // Relative everywhere.
                        0 => format!("w/{name}"),
                        // Rooted but drive-less: absolute on Unix, not on Windows.
                        1 if cfg!(windows) => format!("/w/{name}"),
                        1 => format!("./w/{name}"),
                        2 => String::new(),
                        _ => format!("{good}{}", "/x".repeat(2100)),
                    };
                    let req = if reconcile {
                        let Some(id) = before.workspaces.keys().next().cloned() else {
                            continue;
                        };
                        PolicyAction::ReconcileWorkspace {
                            workspace: id,
                            cwd: bad,
                        }
                    } else {
                        trust_request(&bad, &d)
                    };
                    let r = w.policy(attended, req).await;
                    let after = w.snap();
                    let e = match r {
                        Ok(v) => {
                            return Err(TestCaseError::fail(format!(
                                "a working directory that is not absolute was accepted: {v:?}"
                            )));
                        }
                        Err(e) => e,
                    };
                    prop_assert_eq!(e.code, Code::UsageError);
                    prop_assert!(e.next.decision_ref.is_none(), "no record");
                    prop_assert_eq!(&after.pending, &before.pending, "no record");
                    prop_assert_eq!(&after.workspaces, &before.workspaces);
                    prop_assert_eq!(&after.policies, &before.policies);
                }
                Step::Trust {
                    dir,
                    tamper,
                    attended,
                } => {
                    let cwd = cwd(dir);
                    let Some(d) = w.probe.get(&cwd) else {
                        continue;
                    };
                    let mut req = trust_request(&cwd, &d);
                    if let PolicyAction::TrustWorkspace {
                        access_digest,
                        proposal,
                        ..
                    } = &mut req
                    {
                        match tamper {
                            1 => *access_digest = digest_of(n.wrapping_mul(7919)),
                            2 => proposal.background_work = !proposal.background_work,
                            3 => {
                                proposal.pairs.insert(pair("zz"));
                            }
                            _ => {}
                        }
                    }
                    let r = w.policy(attended, req).await;
                    let after = w.snap();
                    match r {
                        Ok(v) => prop_assert_eq!(&v.data["changed"], false),
                        Err(e) if e.next.decision_ref.is_some() => {
                            // A manifest-less root's proposal is the owner's own request,
                            // so asking for background work there is no tampering.
                            prop_assert!(
                                tamper == 0 || (matches!(d.manifest, Man::Bare) && tamper == 2),
                                "a request unlike the server's view never gets a record"
                            );
                            prop_assert!(!matches!(d.manifest, Man::Refused(_)));
                            prop_assert!(d.identity.is_some());
                            let id = decision_ref(&e);
                            let rec = w.decision(&id);
                            if let DecisionKind::TrustWorkspace { project_label, .. } = &rec.kind {
                                if let Some(l) = project_label {
                                    prop_assert!(l.len() <= MAX_PROJECT_LABEL_BYTES);
                                    let hostile = l.chars().any(|c| {
                                        c.is_control()
                                            || matches!(
                                                c,
                                                '\u{200B}'..='\u{200F}'
                                                    | '\u{202A}'..='\u{202E}'
                                                    | '\u{2066}'..='\u{2069}'
                                            )
                                    });
                                    prop_assert!(!hostile, "the label is quoted data only");
                                }
                                trust_seen.insert(id, (cwd.clone(), seen(&d)));
                            }
                        }
                        Err(e) => {
                            prop_assert!(
                                matches!(
                                    e.code,
                                    Code::UsageError | Code::NotFound | Code::CapabilityUnavailable
                                ),
                                "{:?}",
                                e.code
                            );
                            if e.code == Code::CapabilityUnavailable {
                                prop_assert_eq!(
                                    e.reason.as_deref(),
                                    Some("workspace_identity_unavailable")
                                );
                            }
                            if let Man::Refused(ProbeError::Manifest { reason }) = d.manifest {
                                prop_assert_eq!(e.reason.as_deref(), Some(reason));
                            }
                            prop_assert_eq!(&after.pending, &before.pending, "no record");
                        }
                    }
                }
                Step::Reconcile { dir, ws } => {
                    let ids: Vec<WorkspaceId> = before.workspaces.keys().cloned().collect();
                    if let Some(id) = nth(&ids, ws) {
                        let _ = w
                            .policy(
                                n.is_multiple_of(2),
                                PolicyAction::ReconcileWorkspace {
                                    workspace: id.clone(),
                                    cwd: cwd(dir),
                                },
                            )
                            .await;
                    }
                }
                Step::Decide {
                    pick,
                    attended,
                    approve,
                } => {
                    let pending = w.pending();
                    if let Some(d) = nth(&pending, pick) {
                        let verdict = if approve {
                            Verdict::Approve
                        } else {
                            Verdict::Deny
                        };
                        let r = w.decide(attended, &d.id, verdict).await;
                        let state = w.decision(&d.id).state;
                        if !attended {
                            prop_assert_eq!(
                                r.as_ref().err().map(|e| e.code.clone()),
                                Some(Code::InteractionRequired)
                            );
                            prop_assert_eq!(
                                state,
                                DecisionState::Pending,
                                "unattended consumes nothing"
                            );
                        }
                        if let Ok(v) = &r {
                            consumed.push(d.id.clone());
                            if v.data["state"] == "approved" {
                                if let (DecisionKind::TrustWorkspace { .. }, Some((cwd, at))) =
                                    (&d.kind, trust_seen.get(&d.id))
                                {
                                    let now = w.probe.get(cwd).map(|x| seen(&x));
                                    prop_assert_eq!(
                                        now.as_ref(),
                                        Some(at),
                                        "approved only against the observation it was created from"
                                    );
                                }
                                approved = Some(d.kind.clone());
                            }
                        }
                    }
                }
                Step::Forged { which } => {
                    let (id, want) = match nth(&consumed, which) {
                        Some(id) if which % 2 == 0 => (id.clone(), Code::DecisionStale),
                        _ => (DecisionId::from_random_bytes([which; 16]), Code::NotFound),
                    };
                    for verdict in [Verdict::Approve, Verdict::Deny] {
                        let e = w.decide(true, &id, verdict).await.unwrap_err();
                        prop_assert_eq!(&e.code, &want);
                    }
                }
                Step::FlipIdentity { dir } => {
                    w.probe.edit(&cwd(dir), |d| {
                        if let Some(FileIdentity::Unix { ino, .. }) = &mut d.identity {
                            *ino += 1000;
                        }
                    });
                }
                Step::FlipDigest { dir, bits, bg } => {
                    w.probe.edit(&cwd(dir), |d| {
                        d.manifest = manifest(n, bits, bg, Some(LABELS[usize::from(bits) % 4]));
                    });
                }
                Step::Hostile { dir, which } => {
                    let c = cwd(dir);
                    match which {
                        0 => w.probe.edit(&c, |d| {
                            d.manifest = Man::Refused(ProbeError::Manifest {
                                reason: "manifest_authority_key",
                            });
                        }),
                        1 => w.probe.edit(&c, |d| {
                            d.manifest = Man::Refused(ProbeError::Manifest {
                                reason: "manifest_invalid",
                            });
                        }),
                        2 => w.probe.edit(&c, |d| d.identity = None),
                        3 => w.probe.edit(&c, |d| {
                            d.manifest = Man::Refused(ProbeError::IdentityUnavailable);
                        }),
                        4 => w.probe.edit(&c, |d| d.manifest = Man::Bare),
                        5 => {
                            // A move within one filesystem: same identity, other path.
                            if let Some(d) = w.probe.remove(&c) {
                                let other = cwd(dir.wrapping_add(1));
                                w.probe.set(&other, d);
                            }
                        }
                        _ => w.probe.edit(&c, |d| {
                            d.identity = Some(ident(100 + n));
                            d.manifest = manifest(n, 0b0101, true, Some(LABELS[0]));
                        }),
                    }
                }
                Step::Raise { p, bits, bg } => {
                    if let Some(pid) = nth(&pols, p) {
                        let pol = &before.policies[pid];
                        let delta = ScopeDelta {
                            pairs: hosts(bits),
                            background_work: bg,
                            ..ScopeDelta::default()
                        };
                        let r = w
                            .ops
                            .raise_extension_for_test(pid, None, delta.clone())
                            .await;
                        let beyond = delta.beyond(pol);
                        let profile = if pol.profile == dev() { 0b1111 } else { 0b1100 };
                        if !hosts(bits).is_subset(&hosts(profile)) {
                            // A29: request content never widens the profile.
                            prop_assert_eq!(r.err().map(|e| e.code), Some(Code::UsageError));
                            prop_assert_eq!(&w.snap().pending, &before.pending, "no record");
                        } else {
                            match r {
                                Ok(Extension::Covered) => prop_assert!(beyond.is_empty()),
                                Ok(Extension::Pending { decision, .. }) => {
                                    let rec = w.decision(&decision);
                                    prop_assert_eq!(
                                        rec.kind,
                                        DecisionKind::WidenPolicy {
                                            action: beyond.action(pid)
                                        },
                                        "only the added authority"
                                    );
                                }
                                Ok(Extension::Cooldown { .. }) => {}
                                Err(e) => prop_assert!(false, "{:?}", e.code),
                            }
                        }
                    }
                }
                Step::CoveredOnly { with_context } => {
                    let mut req = ensure_req(&format!("co-{n}"), &format!("co-w-{n}"), 0b0001);
                    req.covered_only = true;
                    if with_context {
                        req.context = Some(WorkContext { cwd: cwd(0) });
                    }
                    let r = w.ops.ensure(&owner(false), req).await;
                    if with_context {
                        // ⟨M05 U4⟩ Served: the covered subset activates, or the request
                        // is refused (`not_covered`, a probe refusal, a block), never
                        // with a decision reference (ruling 3).
                        if let Err(e) = &r {
                            prop_assert!(e.next.decision_ref.is_none(), "{:?}", e);
                        }
                    } else {
                        prop_assert_eq!(r.err().map(|e| e.code), Some(Code::UsageError));
                    }
                    prop_assert_eq!(&w.snap().pending, &before.pending, "no decision");
                }
                Step::Advance { minutes } => {
                    w.clock
                        .advance(Duration::from_secs(u64::from(minutes) * 60));
                }
                Step::Restart => w.restart().await,
            }
            let after = w.snap();
            check_i1(&before, &after, approved.as_ref())?;
        }
        Ok(())
    }

    /// ⟨W1 Windows fix⟩ The minimal input P9 failed with on Windows at `22dfb168` (the
    /// fixture's `/w/...` directories were not absolute there), kept as a fixed case so every
    /// platform replays it through the same trace runner and invariant checks: a hostile
    /// manifest, then an unattended trust request for that directory.
    #[test]
    fn p9_windows_minimal_input_hostile_then_unattended_trust() {
        if let Err(e) = block(run(vec![
            Step::Hostile { dir: 54, which: 0 },
            Step::Trust {
                dir: 3,
                tamper: 0,
                attended: false,
            },
        ])) {
            panic!("{e}");
        }
    }

    proptest! {
        #![proptest_config(config(0x0005_0009))]

        /// P9 (ADR-0011 I1): over random traces of every request kind U2 serves and the
        /// M01–M03 policy actions, attended and unattended `decide` (unknown, consumed,
        /// expired and stale IDs included), hostile probe results (authority-key and
        /// invalid manifests, shell text, newlines and bidirectional controls in labels,
        /// digest and identity flips between request and approval, moves, filesystems
        /// without identity), `raise_extension`, covered-only requests, time and restarts:
        /// no standing policy, workspace record or environment `automatic_activation` is
        /// created or widened except by an applied attended `decide` of a record whose
        /// action it is; narrowings apply at once.
        #[test]
        fn p9_authority_is_created_or_widened_only_by_an_applied_attended_decision(
            steps in prop::collection::vec(step(), 1..60)
        ) {
            block(run(steps))?;
        }

        /// ADR-0011 §10 item 2: `background_work = true` is covered only by a policy
        /// recording `continue`; a `revoke_on_lock` policy never yields `continue`
        /// coverage, and coverage never reports the request's lock behaviour.
        #[test]
        fn p9_background_work_is_never_covered_by_revoke_on_lock(
            policy_bits in 0u8..16, asked_bits in 0u8..16, continue_ in any::<bool>(), bg in any::<bool>()
        ) {
            let p = StandingPolicy {
                id: PolicyId::parse("p").unwrap(),
                revision: PolicyRevision(1),
                profile: dev(),
                workspace: None,
                scope: Scope { pairs: hosts(policy_bits), capabilities: ssh() },
                environments: [env_id()].into_iter().collect(),
                max_window: 12 * HOUR,
                pause: PauseState::Active,
                cutoff_at: None,
                source: heimdall_domain::policy::PolicySource::SetupDefault,
                lock_behavior: if continue_ { LockBehavior::Continue } else { LockBehavior::RevokeOnLock },
                connection: Default::default(),
                default: false,
            };
            let asked = Scope { pairs: hosts(asked_bits), capabilities: ssh() };
            let c = coverage(&p, &asked, &[env_id()].into_iter().collect(), bg);
            prop_assert_eq!(c.lock_behavior, p.lock_behavior);
            prop_assert_eq!(c.uncovered.background_work, bg && !continue_);
            prop_assert!(c.covered.pairs.is_subset(&p.scope.pairs));
            prop_assert_eq!(
                c.covered.pairs.union(&c.uncovered.pairs).cloned().collect::<BTreeSet<_>>(),
                asked.pairs
            );
        }
    }
}

impl World {
    fn clock_wall(&self) -> Timestamp {
        use heimdall_domain::time::Clock as _;
        self.clock.wall()
    }
}

// =================================================================================
// ⟨M06 W5⟩ Record source (b): a personal policy that names a recorded runner
// =================================================================================

fn runner_env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([9; 16])
}

/// This controller's record of the runner [`runner_env`], holding `role` there.
fn record_runner(w: &World, role: heimdall_contract::remote::Role) {
    use heimdall_contract::controller_record::{
        ManagementHop, ManagementRoute, RemoteEnvironmentPin,
    };
    let pin = RemoteEnvironmentPin {
        environment: runner_env(),
        destination: DestinationId::parse("runner1").unwrap(),
        route: ManagementRoute {
            runner: ManagementHop {
                hostname: "runner1.example".into(),
                port: None,
                account: AccountName::parse("deploy").unwrap(),
                host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
            },
            jump: None,
        },
        client: heimdall_contract::ids::ClientId::from_random_bytes([3; 16]),
        role,
        key_fingerprint: heimdall_contract::ids::KeyFingerprint::parse(&format!(
            "SHA256:{}",
            "K".repeat(43)
        ))
        .unwrap(),
        label: None,
        pinned_at: t0(),
    };
    w.store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &pin.environment,
                &pin.destination,
                &pin.route.runner.account,
                &pin.key_fingerprint,
                &serde_json::to_string(&pin).unwrap(),
                t0(),
            )
        })
        .unwrap();
}

fn create_for(profile: &str, environments: &[EnvironmentId], default: bool) -> PolicyAction {
    PolicyAction::Create {
        profile: ProfileId::parse(profile).unwrap(),
        environments: environments.iter().cloned().collect(),
        max_window: None,
        default,
    }
}

/// m06-plan §2 item 3 "Who can create one" and "It activates nothing locally"; ADR-0005
/// §3.5 condition 8 (b). A personal `create` may name an environment outside the managed
/// set in exactly one case: a single recorded runner on which this controller holds a role
/// the role table allows to issue, through the ordinary attended widening. An unrecorded
/// environment keeps the managed-set refusal; a limited role, a mixed set and `default`
/// are refused before any record. The approved policy changes nothing local: no
/// environment record, no automatic activation, no default profile, and a local `ensure`
/// for its profile still waits for its own approval and binds nothing. The role is judged
/// again when the decision is applied.
#[tokio::test]
async fn a_policy_naming_a_runner_needs_an_issuing_role_and_activates_nothing_locally() {
    use heimdall_contract::remote::Role;
    let w = World::new().await;
    let before = w.snap();
    let runner = [runner_env()];

    // Not recorded: the managed-set refusal, as ever.
    let e = w
        .policy(true, create_for("dev", &runner, false))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotFound, "{e:?}");

    // Recorded, with a role the table does not let issue.
    for role in [Role::Requester, Role::Viewer] {
        record_runner(&w, role);
        let e = w
            .policy(true, create_for("dev", &runner, false))
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
        assert_eq!(
            e.reason.as_deref(),
            Some(heimdall_contract::envelope::reason::ROLE_INSUFFICIENT)
        );
    }

    // An issuing role: never mixed with another environment, never the default.
    record_runner(&w, Role::Owner);
    let mixed = [env_id(), runner_env()];
    let e = w
        .policy(true, create_for("dev", &mixed, false))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError, "{e:?}");
    let e = w
        .policy(true, create_for("dev", &runner, true))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError, "{e:?}");
    assert_eq!(w.snap(), before, "no refusal wrote anything");

    // The ordinary widening: a decision record, applied only by the attended approval.
    let e = w
        .policy(false, create_for("dev", &runner, false))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    let widen = decision_ref(&e);
    assert!(w.snap().policies.is_empty(), "nothing applied on dispatch");
    let unattended = w.decide(false, &widen, Verdict::Approve).await;
    assert!(
        unattended.is_err(),
        "an unattended session approves nothing"
    );
    assert!(w.snap().policies.is_empty());
    w.decide(true, &widen, Verdict::Approve).await.unwrap();

    let snap = w.snap();
    assert_eq!(snap.policies.len(), 1);
    let p = snap.policies.values().next().unwrap().clone();
    assert_eq!(p.environments, BTreeSet::from([runner_env()]));
    assert!(!p.default && p.workspace.is_none());
    assert_eq!(p.scope.pairs, hosts(0b1111));
    // Nothing local moved.
    assert!(!snap.automatic, "no automatic activation here");
    w.store
        .transaction(|tx| {
            assert!(tx.environment(&runner_env())?.is_none(), "no record of it");
            assert!(tx.default_profile(&env_id())?.is_none());
            assert!(tx.default_profile(&runner_env())?.is_none());
            assert!(tx.policies_for(&dev(), &env_id())?.is_empty());
            Ok(())
        })
        .unwrap();

    // A local `ensure` for the same profile is not covered by it: it waits for its own
    // approval, and nothing is bound or prepared.
    let e = w
        .ops
        .ensure(&owner(false), ensure_req("rb-1", "rb-work", 0b0001))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    assert!(matches!(
        w.decision(&decision_ref(&e)).kind,
        DecisionKind::ApproveAuthority { .. }
    ));
    // An `ensure` naming the runner is not this pipeline's (the runtime forwards it).
    let mut remote = ensure_req("rb-2", "rb-work-2", 0b0001);
    remote.environment = Some(runner_env());
    let e = w.ops.ensure(&owner(false), remote).await.unwrap_err();
    assert_eq!(e.code, Code::NotFound, "{e:?}");
    w.store
        .transaction(|tx| {
            for (environment, work) in [(env_id(), "rb-work"), (runner_env(), "rb-work-2")] {
                assert!(
                    tx.bindings_for_work(&environment, &WorkId::parse(work).unwrap())?
                        .is_empty()
                );
            }
            // The one grant is the waiting local request's own (its approval is still
            // pending, asserted above); the request naming the runner created none.
            assert_eq!(tx.table_counts()?.grants, 1);
            Ok(())
        })
        .unwrap();

    // It never gains another environment, and no local policy gains the runner.
    let e = w
        .policy(
            true,
            PolicyAction::ExtendScope {
                policy_id: p.id.clone(),
                pairs: BTreeSet::new(),
                capabilities: BTreeSet::new(),
                environments: BTreeSet::from([env_id()]),
                background_work: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError, "{e:?}");
    let e = w.policy(true, create(false)).await.unwrap_err();
    let local = decision_ref(&e);
    w.decide(true, &local, Verdict::Approve).await.unwrap();
    let local = w
        .snap()
        .policies
        .into_values()
        .find(|q| q.environments.contains(&env_id()))
        .unwrap();
    let e = w
        .policy(
            true,
            PolicyAction::ExtendScope {
                policy_id: local.id.clone(),
                pairs: BTreeSet::new(),
                capabilities: BTreeSet::new(),
                environments: BTreeSet::from([runner_env()]),
                background_work: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::NotFound, "{e:?}");

    // The role is judged again at the approval: a decision made while the role was the
    // owner's applies nothing once it is not.
    let e = w
        .policy(true, create_for("ops", &runner, false))
        .await
        .unwrap_err();
    let later = decision_ref(&e);
    record_runner(&w, Role::Viewer);
    assert!(w.decide(true, &later, Verdict::Approve).await.is_err());
    assert_eq!(w.snap().policies.len(), 2, "no third policy");
}
