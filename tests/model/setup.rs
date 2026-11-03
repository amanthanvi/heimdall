//! W3-U5: the setup and catalog drivers (m02-plan U5; ADR-0007 §5, §7), through the
//! real `Operations`, a real store and the runtime's real projection writer
//! (`heimdall_runtime::service::wire_projection` over `LocalProjection`).
//!
//! Every test runs in a `heimdall_testkit::home::ScratchHome`: the writer is
//! configured with `SshPaths::with_test_override` and Heimdall's scratch configuration
//! directory, so nothing outside the scratch tree is read or written. The adopted keys
//! are synthetic public keys generated per run (no private key exists anywhere). No
//! client is run against the files and no agent is contacted.
//!
//! **Crashes** are in-process: the writer's test `ReplaceHook` panics at a point, the
//! blocking task unwinds, and a fresh `Operations` over the same store (with a fresh
//! writer) restarts. The writer keeps no state between calls (M2-S05), so this is what
//! a process restart sees; it is labelled an in-process unwind, never a process abort.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    HeldStep, PreviewError, ProjectionReceipt, ProjectionReconcile, ProjectionWriter,
    ReconcileError, StageSink,
};
use heimdall_app::{Attendance, Caller, OpError, Operations, OperationsConfig};
use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
    IdentitySourceSpec, IdentitySpec, ProfileSpec, WithdrawReason,
};
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, EnvironmentId, IdentityId, OperationId, ProfileId,
    RequestId,
};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{AccessPairRef, DecideRequest, InteractionMode, Verdict};
use heimdall_contract::setup::{
    ConflictKind, ConsentReasonKind, PlanDigest, PreviewIntent, ProjectionItem, RepairResolution,
    SetupPlan, SetupRequest,
};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord};
use heimdall_domain::operation::{LocalIntent, StageReceipt};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::projection::{ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent};
use heimdall_domain::resource::ResourceState;
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_localenv::env::Platform;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::{ProjectionConfig, ReplaceHook, ReplacePoint};
use heimdall_runtime::service::wire_projection;
use heimdall_store::{FaultHook, NoFaults, Store};
use heimdall_testkit::home::ScratchHome;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};

// --- fixtures ---------------------------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-03T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([0x5e; 16])
}

fn owner_ctx() -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::Owner,
    }
}

fn attended() -> Caller {
    Caller {
        context: owner_ctx(),
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn unattended() -> Caller {
    Caller::unattended(owner_ctx())
}

fn limited() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::LimitedConsumer,
    })
}

fn rid(s: &str) -> RequestId {
    RequestId::parse(s).unwrap()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let v = heimdall_app::ids::random_u64().unwrap().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    out
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A synthetic `ssh-ed25519` public key line over 32 random bytes, generated per run.
/// It has no private key.
fn synthetic_public_key() -> String {
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(random_bytes::<32>());
    format!("ssh-ed25519 {}", b64(&blob))
}

/// The panic payload of an injected crash.
struct Crash;

fn quiet_crashes() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.payload().is::<Crash>() {
                previous(info);
            }
        }));
    });
}

type Action = Arc<dyn Fn() + Send + Sync>;

/// One hook rule: the point, the step (any when `None`), and the action (a crash when
/// `None`).
type Rule = (ReplacePoint, Option<u16>, Option<Action>);

/// A scripted `ReplaceHook`: each rule fires once at its point (and step).
#[derive(Default)]
struct Hook {
    rules: Mutex<Vec<Rule>>,
}

impl Hook {
    fn crash_at(&self, point: ReplacePoint, step: Option<u16>) {
        self.rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((point, step, None));
    }

    fn run_at(&self, point: ReplacePoint, step: Option<u16>, f: impl Fn() + Send + Sync + 'static) {
        self.rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((point, step, Some(Arc::new(f))));
    }
}

impl ReplaceHook for Hook {
    fn at(&self, point: ReplacePoint, step: u16) {
        let act = {
            let mut rules = self.rules.lock().unwrap_or_else(PoisonError::into_inner);
            rules
                .iter()
                .position(|(p, s, _)| *p == point && s.is_none_or(|s| s == step))
                .map(|i| rules.remove(i).2)
        };
        match act {
            Some(None) => std::panic::panic_any(Crash),
            Some(Some(f)) => f(),
            None => {}
        }
    }
}

/// A store fault hook that fails the first commit after it is armed (the admission
/// transaction, when the writer's preview arms it).
#[derive(Default)]
struct ArmedFault {
    armed: std::sync::atomic::AtomicBool,
    fired: AtomicUsize,
}

impl FaultHook for ArmedFault {
    fn at(&self, point: heimdall_store::FaultPoint) -> heimdall_store::FaultAction {
        if point == heimdall_store::FaultPoint::BeforeCommit
            && self.armed.swap(false, Ordering::SeqCst)
        {
            self.fired.fetch_add(1, Ordering::SeqCst);
            return heimdall_store::FaultAction::Fail;
        }
        heimdall_store::FaultAction::Continue
    }
}

/// The runtime's writer with call counters (`apply` is called at most once per
/// operation; a restart only ever calls `reconcile`).
struct Counting {
    inner: Arc<dyn ProjectionWriter>,
    applies: AtomicUsize,
    reconciles: AtomicUsize,
    previews: AtomicUsize,
    /// Run after each preview (arms a store fault for the admission transaction).
    after_preview: Mutex<Option<Arc<ArmedFault>>>,
    /// Rewrites each `ItemCommit`'s consent decision (the sink's check).
    tamper_consent: std::sync::atomic::AtomicBool,
}

impl ProjectionWriter for Counting {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        self.previews.fetch_add(1, Ordering::SeqCst);
        let r = self.inner.preview(spec, intent);
        if let Some(f) = self
            .after_preview
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            f.armed.store(true, Ordering::SeqCst);
        }
        r
    }
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.applies.fetch_add(1, Ordering::SeqCst);
        if self.tamper_consent.load(Ordering::SeqCst) {
            let mut tampering = Tamper(sink);
            return self.inner.apply(intent, &mut tampering);
        }
        self.inner.apply(intent, sink)
    }
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        self.inner.reconcile(intent, receipts, sink)
    }
    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation> {
        self.inner.observe(record, aliases)
    }
    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError> {
        self.inner.observe_held(intent, receipts)
    }
}

/// A sink in front of the driver's that names another decision in every commit's
/// consent (ADR-0007 §12.19 item 9: the driver's sink must refuse it).
struct Tamper<'a>(&'a mut dyn StageSink);

impl StageSink for Tamper<'_> {
    fn append(
        &mut self,
        receipt: &heimdall_domain::operation::LocalReceipt,
    ) -> Result<(), heimdall_app::ports::SinkError> {
        self.0.append(receipt)
    }
    fn commit_item(
        &mut self,
        mut commit: heimdall_domain::projection::ItemCommit,
    ) -> Result<(), heimdall_app::ports::SinkError> {
        for states in commit.consent.items.values_mut() {
            states.decision = DecisionId::from_random_bytes([0x42; 16]);
        }
        self.0.commit_item(commit)
    }
}

/// One test's scratch world.
struct World {
    home: ScratchHome,
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    hook: Arc<Hook>,
    writer: Arc<Counting>,
    faults: Arc<dyn FaultHook>,
    limits: Limits,
    ops: Operations,
}

impl World {
    async fn new() -> World {
        World::with_faults(Arc::new(NoFaults)).await
    }

    async fn with_faults(faults: Arc<dyn FaultHook>) -> World {
        World::with(faults, Limits::default()).await
    }

    async fn with(faults: Arc<dyn FaultHook>, limits: Limits) -> World {
        quiet_crashes();
        let home = ScratchHome::new();
        std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
        let store =
            Arc::new(Store::open(&home.state_dir.join("state.db"), faults.clone()).unwrap());
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let hook = Arc::new(Hook::default());
        let writer = World::writer_of(&home, &store, &hook);
        let ops = Operations::start(World::config_of(&store, &clock, &sync, &writer, limits))
            .await
            .unwrap();
        World {
            home,
            store,
            clock,
            sync,
            hook,
            writer,
            faults,
            limits,
            ops,
        }
    }

    fn projection_config(home: &ScratchHome, hook: &Arc<Hook>) -> ProjectionConfig {
        let paths = SshPaths::with_test_override(home.git_home.clone(), home.root.join("etc-ssh"));
        let mut c = ProjectionConfig::new(paths, Platform::current(), home.config_dir.clone());
        let h: Arc<dyn ReplaceHook> = hook.clone();
        c.hook = Some(h);
        // Git's global files resolve under the scratch home (never the account's).
        c.env = heimdall_localenv::env::Env::from_vars([
            ("HOME", home.git_home.display().to_string()),
            ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ]);
        c
    }

    fn writer_of(home: &ScratchHome, store: &Arc<Store>, hook: &Arc<Hook>) -> Arc<Counting> {
        let wired = wire_projection(store.clone(), World::projection_config(home, hook));
        Arc::new(Counting {
            inner: wired.writer,
            applies: AtomicUsize::new(0),
            reconciles: AtomicUsize::new(0),
            previews: AtomicUsize::new(0),
            after_preview: Mutex::new(None),
            tamper_consent: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn config_of(
        store: &Arc<Store>,
        clock: &Arc<VirtualClock>,
        sync: &Arc<ScriptedTimeSync>,
        writer: &Arc<Counting>,
        limits: Limits,
    ) -> OperationsConfig {
        let writer: Arc<dyn ProjectionWriter> = writer.clone();
        OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: sync.clone(),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits,
            default_window: Duration::from_secs(12 * 3600),
            projection: Some(writer),
        }
    }

    /// In-process restart: a fresh writer and a new `Operations` over the same store.
    async fn restart(&mut self) {
        self.hook = Arc::new(Hook::default());
        self.writer = World::writer_of(&self.home, &self.store, &self.hook);
        self.ops = Operations::start(World::config_of(
            &self.store,
            &self.clock,
            &self.sync,
            &self.writer,
            self.limits,
        ))
        .await
        .unwrap();
    }

    fn p(&self) -> PathBuf {
        self.home.config_dir.join("ssh_config")
    }

    fn user(&self) -> &Path {
        &self.home.user_config
    }

    fn op(&self, id: &OperationId) -> heimdall_domain::operation::OperationRecord {
        self.store
            .transaction(|tx| tx.operation(id))
            .unwrap()
            .unwrap()
    }

    fn decisions(&self) -> Vec<DecisionRecord> {
        self.store.transaction(|tx| tx.pending_decisions()).unwrap()
    }

    fn record(&self) -> Option<ProjectionRecord> {
        self.store
            .transaction(|tx| tx.projection_record(&env_id()))
            .unwrap()
    }

    fn agent_endpoint(&self) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: self
                .home
                .root
                .join("fixture-agent.sock")
                .display()
                .to_string(),
        }
    }

    async fn catalog(
        &self,
        caller: &Caller,
        req: CatalogRequest,
    ) -> Result<serde_json::Value, OpError> {
        let r = self.ops.catalog(caller, req).await.map(|c| c.data);
        scan(&r);
        r
    }

    /// Adopt a synthetic identity at the scratch agent endpoint.
    async fn adopt(&self, request: &str) -> IdentityId {
        let data = self
            .catalog(
                &attended(),
                CatalogRequest::AdoptIdentity {
                    identity: IdentitySpec {
                        source: IdentitySourceSpec::NativeAgent {
                            endpoint: self.agent_endpoint(),
                        },
                        public_key: synthetic_public_key(),
                        label: None,
                    },
                    request_id: rid(request),
                },
            )
            .await
            .unwrap();
        IdentityId::parse(data["identity_id"].as_str().unwrap()).unwrap()
    }

    async fn destination(&self, request: &str, id: &str, alias: &str, identity: &IdentityId) {
        self.catalog(
            &attended(),
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(id).unwrap(),
                    alias: alias.to_owned(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: format!("{alias}.example.invalid"),
                        port: None,
                        account: AccountName::parse("fixture").unwrap(),
                        identity: identity.clone(),
                    },
                    label: None,
                },
                request_id: rid(request),
            },
        )
        .await
        .unwrap();
    }

    /// One identity and one managed alias `alpha`.
    async fn catalog_alpha(&self) -> IdentityId {
        let identity = self.adopt("r-adopt-alpha").await;
        self.destination("r-dest-alpha", "dst-alpha", "alpha", &identity)
            .await;
        identity
    }

    async fn preview(&self, intent: PreviewIntent) -> Result<SetupPlan, OpError> {
        let r = self
            .ops
            .setup(&attended(), SetupRequest::Preview { intent })
            .await
            .map(|c| serde_json::from_value::<SetupPlan>(c.data).unwrap());
        if let Ok(p) = &r {
            assert_no_canary(&serde_json::to_string(p).unwrap());
        }
        r
    }

    async fn effect(
        &self,
        caller: &Caller,
        kind: &str,
        digest: &PlanDigest,
        request: &str,
    ) -> Result<serde_json::Value, OpError> {
        let req = match kind {
            "apply" => SetupRequest::Apply {
                plan_digest: digest.clone(),
                request_id: rid(request),
            },
            "rollback" => SetupRequest::Rollback {
                plan_digest: digest.clone(),
                request_id: rid(request),
            },
            _ => SetupRequest::Repair {
                plan_digest: digest.clone(),
                request_id: rid(request),
            },
        };
        let r = self.ops.setup(caller, req).await.map(|c| {
            let mut v = c.data;
            if let Some(map) = v.as_object_mut() {
                map.insert("__code".to_owned(), serde_json::json!(c.code));
                map.insert("__state".to_owned(), serde_json::json!(c.state));
                if let Some(op) = &c.operation_id {
                    map.insert("__operation".to_owned(), serde_json::json!(op));
                }
            }
            v
        });
        scan(&r);
        r
    }

    async fn decide(&self, decision: &str, verdict: Verdict) -> Result<serde_json::Value, OpError> {
        self.ops
            .decide(
                &attended(),
                DecideRequest {
                    decision_id: DecisionId::parse(decision).unwrap(),
                    verdict,
                },
            )
            .await
            .map(|c| c.data)
    }

    /// Preview an apply, submit it, approve the decision it creates.
    async fn apply_approved(&self, request: &str) -> (OperationId, PlanDigest) {
        let plan = self
            .preview(PreviewIntent::Apply { include_git: false })
            .await
            .unwrap();
        let e = self
            .effect(&attended(), "apply", &plan.plan_digest, request)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
        let op = e.operation_id.clone().unwrap();
        let decision = e.next.decision_ref.clone().unwrap();
        self.decide(&decision, Verdict::Approve).await.unwrap();
        (op, plan.plan_digest)
    }

    /// Every stored event, scanned for canaries.
    fn events(&self) -> Vec<heimdall_store::StoredEvent> {
        let page = self
            .store
            .transaction(|tx| {
                tx.stored_events_after(
                    &env_id(),
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    10_000,
                )
            })
            .unwrap();
        for e in &page.events {
            assert_no_canary(&serde_json::to_string(&e.event).unwrap());
        }
        page.events
    }

    /// Content and identity of every entry under the scratch `~/.ssh` and the
    /// configuration directory.
    fn tree(&self) -> BTreeMap<String, (u64, Vec<u8>)> {
        use std::os::unix::fs::MetadataExt as _;
        fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, (u64, Vec<u8>)>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                let name = format!("{prefix}/{}", e.file_name().to_string_lossy());
                let meta = std::fs::symlink_metadata(&p).unwrap();
                if meta.is_dir() {
                    walk(&p, &name, out);
                } else {
                    out.insert(name, (meta.ino(), std::fs::read(&p).unwrap_or_default()));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.home.ssh_dir, "ssh", &mut out);
        walk(&self.home.config_dir, "config", &mut out);
        out
    }

    fn receipts(&self, id: &OperationId) -> Vec<StageReceipt> {
        self.store.transaction(|tx| tx.stage_receipts(id)).unwrap()
    }

    fn intent(&self, id: &OperationId) -> SetupIntent {
        match self
            .store
            .transaction(|tx| tx.recovery_intent(id))
            .unwrap()
            .unwrap()
            .local
        {
            Some(LocalIntent::Setup(i)) => i,
            other => panic!("no setup intent: {other:?}"),
        }
    }
}

fn scan<T: std::fmt::Debug>(r: &Result<T, OpError>) {
    assert_no_canary(&format!("{r:?}"));
}

fn projection_decisions(w: &World, op: &OperationId) -> Vec<DecisionRecord> {
    w.decisions()
        .into_iter()
        .filter(|d| matches!(&d.kind, DecisionKind::ApplyProjection { operation, .. } if operation == op))
        .collect()
}

// --- tests --------------------------------------------------------------------------------

#[tokio::test]
async fn apply_requires_decision_attended_and_unattended() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    assert!(
        plan.consent.decision_required,
        "first adoption needs a decision"
    );
    let before = w.tree();

    // Unattended: INTERACTION_REQUIRED with the decision reference, nothing written.
    let e = w
        .effect(&unattended(), "apply", &plan.plan_digest, "r-apply-1")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    let decision = e.next.decision_ref.clone().expect("decision_ref");
    let op = e.operation_id.clone().unwrap();
    assert_eq!(w.op(&op).state, OperationState::AwaitingApproval);
    let pending = projection_decisions(&w, &op);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id.to_string(), decision);
    match &pending[0].kind {
        DecisionKind::ApplyProjection {
            plan_digest,
            summary,
            ..
        } => {
            assert_eq!(*plan_digest, plan.plan_digest);
            assert!(summary.within_bounds());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        w.tree(),
        before,
        "nothing is written while a decision is pending"
    );
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 0);

    // The same request on an attended session: APPROVAL_REQUIRED, same decision.
    let e2 = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-apply-1")
        .await;
    // A different caller context is a different idempotency key: the second
    // caller is the same owner principal, so the key matches and it replays.
    let e2 = e2.unwrap_err();
    assert_eq!(e2.code, Code::ApprovalRequired);
    assert_eq!(e2.next.decision_ref.as_deref(), Some(decision.as_str()));

    // Approve: the waiting operation runs exactly this plan.
    w.decide(&decision, Verdict::Approve).await.unwrap();
    let done = w.op(&op);
    assert_eq!(done.state, OperationState::Succeeded, "{:?}", done.result);
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 1);
    assert!(w.p().exists());
    let user = std::fs::read_to_string(w.user()).unwrap();
    assert!(user.contains("Include"), "B is in the user file");
    w.events();
}

fn sha256_hex(bytes: &[u8]) -> String {
    heimdall_domain::projection::Sha256Hex::of(bytes)
        .as_str()
        .to_owned()
}

/// The index of the first step with `role` in an intent.
fn step_of(intent: &SetupIntent, role: heimdall_domain::projection::FileRole) -> u16 {
    u16::try_from(intent.files.iter().position(|s| s.role == role).unwrap()).unwrap()
}

#[tokio::test]
async fn apply_executes_exactly_the_decided_plan_digest() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-apply")
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let decision = projection_decisions(&w, &op).remove(0);
    let DecisionKind::ApplyProjection { plan_digest, .. } = &decision.kind else {
        panic!()
    };
    assert_eq!(*plan_digest, plan.plan_digest);
    assert_eq!(w.intent(&op).plan_digest, plan.plan_digest);
    w.decide(&decision.id.to_string(), Verdict::Approve)
        .await
        .unwrap();
    let intent = w.intent(&op);
    let approval = intent.approval.clone().expect("approval recorded");
    assert_eq!(approval.decision, decision.id);
    assert_eq!(approval.plan_digest, plan.plan_digest);
    // Every file the plan showed has exactly the digest the plan showed.
    for f in &plan.files {
        let path = intent
            .files
            .iter()
            .find(|s| s.path.ends_with(f.path_display.trim_start_matches('~')))
            .map(|s| PathBuf::from(&s.path));
        if let (Some(path), Some(after)) = (path, &f.after_sha256) {
            assert_eq!(
                sha256_hex(&std::fs::read(&path).unwrap()),
                *after,
                "{path:?}"
            );
        }
    }
    // The consent the commit recorded names the approving decision only.
    let consent = w
        .store
        .transaction(|tx| tx.get_projection_consent(&env_id()))
        .unwrap();
    assert!(!consent.items.is_empty());
    assert!(consent.items.values().all(|c| c.decision == decision.id));
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
}

#[tokio::test]
async fn apply_after_base_change_is_config_conflict_and_nothing_written() {
    // At admission: the user file changed since the preview.
    let w = World::new().await;
    w.catalog_alpha().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    std::fs::write(w.user(), "Host other\n    User changed\n").unwrap();
    let before = w.tree();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-stale")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
    assert_eq!(e.effect_status, EffectStatus::None);
    assert!(e.operation_id.is_none(), "nothing is admitted");
    assert!(w.decisions().is_empty());
    assert_eq!(w.tree(), before);
    let open = w
        .store
        .transaction(|tx| tx.open_setup_operations(&env_id()))
        .unwrap();
    assert!(open.is_empty());

    // After the decision: approve, the recomputed plan differs, nothing written.
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-stale-2")
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    std::fs::write(w.user(), "Host other\n    User again\n").unwrap();
    let before = w.tree();
    w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
        .await
        .unwrap();
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Failed);
    assert_eq!(rec.code, Some(Code::ConfigConflict));
    assert_eq!(rec.effect_status, EffectStatus::None);
    assert_eq!(w.tree(), before, "nothing written");
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rollback_to_consented_restore_needs_no_decision() {
    let w = World::new().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let original = std::fs::read(w.user()).unwrap();
    w.catalog_alpha().await;
    let (op, _) = w.apply_approved("r-apply").await;
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let plan = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    assert!(!plan.consent.decision_required, "{:?}", plan.consent);
    let decisions = w.decisions().len();
    let done = w
        .effect(&unattended(), "rollback", &plan.plan_digest, "r-rollback")
        .await
        .unwrap();
    assert_eq!(done["__code"], serde_json::json!("OK"), "{done}");
    assert_eq!(w.decisions().len(), decisions, "no decision record");
    assert_eq!(std::fs::read(w.user()).unwrap(), original, "byte-for-byte");
    // ADR-0007 §12.19 item 9: the rollback commit removed the item (kept as an empty
    // record that holds the generation).
    let record = w.record().unwrap();
    let ssh = &record.items[&ProjectionItem::Ssh];
    assert!(ssh.files.is_empty() && ssh.aliases.is_empty(), "{ssh:?}");
    assert_eq!(ssh.generation, 2);
    // P and the key file are handed to the cleaner.
    let resources = w
        .store
        .transaction(|tx| tx.projection_resources(&env_id()))
        .unwrap();
    assert!(!resources.is_empty());
    assert!(resources.iter().all(|r| r.desired == ResourceState::Absent));
    // Re-adoption after a rollback always needs a decision.
    let again = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    assert!(again.consent.decision_required);
}

#[tokio::test]
async fn rollback_exposing_inherited_hostname_and_agent_added_after_apply_needs_decision() {
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    // The user adds a `Host *` HostName and IdentityAgent after the apply.
    let mut text = std::fs::read_to_string(w.user()).unwrap();
    text.push_str(&format!(
        "\nHost *\n    HostName inherited.example.invalid\n    IdentityAgent {}\n",
        w.home.root.join("other-agent.sock").display()
    ));
    std::fs::write(w.user(), text).unwrap();
    let plan = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    assert!(plan.consent.decision_required, "{:?}", plan.consent);
    let e = w
        .effect(&unattended(), "rollback", &plan.plan_digest, "r-rollback")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    assert!(e.next.decision_ref.is_some());
}

#[tokio::test]
async fn rerender_repair_to_consented_state_needs_no_decision() {
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let p = std::fs::read(w.p()).unwrap();
    // P is lost; the rerender writes exactly the consented managed state again.
    std::fs::remove_file(w.p()).unwrap();
    let plan = w
        .preview(PreviewIntent::Repair {
            conflict: ConflictKind::ManagedFileEdited,
            resolution: RepairResolution::Rerender,
            operation: None,
        })
        .await
        .unwrap();
    assert!(!plan.consent.decision_required, "{:?}", plan.consent);
    let decisions = w.decisions().len();
    let done = w
        .effect(&unattended(), "repair", &plan.plan_digest, "r-rerender")
        .await
        .unwrap();
    assert_eq!(done["__code"], serde_json::json!("OK"), "{done}");
    assert_eq!(w.decisions().len(), decisions);
    assert_eq!(std::fs::read(w.p()).unwrap(), p);
}

#[tokio::test]
async fn same_request_id_replays_apply() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let (op, digest) = w.apply_approved("r-apply").await;
    let first = w.op(&op);
    // Files change afterwards; the replay still returns the first result and
    // recomputes nothing.
    std::fs::write(w.user(), "Host other\n").unwrap();
    let previews = w.writer.previews.load(Ordering::SeqCst);
    let again = w
        .effect(&attended(), "apply", &digest, "r-apply")
        .await
        .unwrap();
    assert_eq!(again["__operation"], serde_json::json!(op));
    assert_eq!(again["__code"], serde_json::json!("OK"));
    assert_eq!(w.writer.previews.load(Ordering::SeqCst), previews);
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 1);
    assert_eq!(w.op(&op), first);
}

#[tokio::test]
async fn changed_plan_same_request_is_request_conflict() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-x")
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let other = PlanDigest::parse(&"ab".repeat(32)).unwrap();
    let e = w
        .effect(&attended(), "apply", &other, "r-x")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::RequestConflict);
    assert_eq!(e.operation_id, Some(op));
}

#[tokio::test]
async fn limited_consumer_refused() {
    let w = World::new().await;
    let identity = w.catalog_alpha().await;
    let e = w
        .ops
        .setup(
            &limited(),
            SetupRequest::Preview {
                intent: PreviewIntent::Apply { include_git: false },
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    let e = w
        .catalog(
            &limited(),
            CatalogRequest::RemoveIdentity {
                id: identity,
                request_id: rid("r-limited"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert!(w.decisions().is_empty());
}

#[tokio::test]
async fn catalog_alias_rename_keeps_destination_id() {
    let w = World::new().await;
    let identity = w.catalog_alpha().await;
    w.destination("r-rename", "dst-alpha", "alpha2", &identity)
        .await;
    let d = w
        .store
        .transaction(|tx| tx.destination(&DestinationId::parse("dst-alpha").unwrap()))
        .unwrap()
        .unwrap();
    assert_eq!(d.alias, "alpha2");
    assert_eq!(d.revision, 2);
    assert!(
        w.store
            .transaction(|tx| tx.destination_by_alias("alpha"))
            .unwrap()
            .is_none()
    );
    // Another destination may not take the alias.
    let e = w
        .catalog(
            &attended(),
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse("dst-beta").unwrap(),
                    alias: "alpha2".to_owned(),
                    definition: DestinationDefinitionSpec::Observed,
                    label: None,
                },
                request_id: rid("r-collide"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(e.reason.as_deref(), Some("alias_collision"));
    // An alias that is not a literal Host name is refused before admission.
    let e = w
        .catalog(
            &attended(),
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse("dst-gamma").unwrap(),
                    alias: "a*".to_owned(),
                    definition: DestinationDefinitionSpec::Observed,
                    label: None,
                },
                request_id: rid("r-glob"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError);
}

#[tokio::test]
async fn profile_upsert_bumps_revision_and_does_not_widen_existing_grant() {
    let w = World::new().await;
    let pair = |d: &str| AccessPairRef {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    };
    let profile = ProfileId::parse("work").unwrap();
    let upsert = |request: &'static str, pairs: Vec<AccessPairRef>| CatalogRequest::UpsertProfile {
        profile: ProfileSpec {
            id: ProfileId::parse("work").unwrap(),
            pairs: pairs.into_iter().collect(),
            label: None,
        },
        request_id: rid(request),
    };
    let r1 = w
        .catalog(&attended(), upsert("r-p1", vec![pair("dst-alpha")]))
        .await
        .unwrap();
    assert_eq!(r1["revision"], 1);
    let r2 = w
        .catalog(
            &attended(),
            upsert("r-p2", vec![pair("dst-alpha"), pair("dst-beta")]),
        )
        .await
        .unwrap();
    assert_eq!(r2["revision"], 2);
    // The same content again is not a new revision.
    let r3 = w
        .catalog(
            &attended(),
            upsert("r-p3", vec![pair("dst-alpha"), pair("dst-beta")]),
        )
        .await
        .unwrap();
    assert_eq!(r3["revision"], 2);
    // A grant pinned to revision 1 keeps its snapshot: one pair, never widened.
    let pinned = w
        .store
        .transaction(|tx| tx.profile_snapshot(&profile, 1))
        .unwrap()
        .unwrap();
    assert_eq!(pinned.scope.pairs.len(), 1);
    let current = w
        .store
        .transaction(|tx| tx.profile_snapshot(&profile, 2))
        .unwrap()
        .unwrap();
    assert_eq!(current.scope.pairs.len(), 2);
}

fn eligibility_now(
    w: &World,
    identity: &IdentityId,
    endpoint: &EndpointRef,
) -> heimdall_contract::provider::InteractionKind {
    let (record, decl) = w
        .store
        .transaction(|tx| {
            Ok((
                tx.identity(identity)?,
                tx.interaction_declaration(identity)?,
            ))
        })
        .unwrap();
    use heimdall_domain::time::Clock as _;
    heimdall_domain::catalog::eligibility(&record.unwrap(), decl.as_ref(), endpoint, w.clock.wall())
        .interaction
}

async fn declare(w: &World, identity: &IdentityId, request: &str) -> String {
    declare_op(w, identity, request).await.0
}

async fn declare_op(w: &World, identity: &IdentityId, request: &str) -> (String, OperationId) {
    let e = w
        .catalog(
            &unattended(),
            CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: rid(request),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired, "{e:?}");
    (
        e.next.decision_ref.clone().unwrap(),
        e.operation_id.clone().unwrap(),
    )
}

#[tokio::test]
async fn declare_interaction_needs_attended_decision_and_lapses_on_endpoint_change_and_expiry() {
    use heimdall_contract::provider::InteractionKind;
    let w = World::new().await;
    let identity = w.adopt("r-adopt").await;
    let endpoint = w.agent_endpoint();
    assert_eq!(
        eligibility_now(&w, &identity, &endpoint),
        InteractionKind::Unknown
    );
    let decision = declare(&w, &identity, "r-declare").await;
    // An attended request for the same declaration answers APPROVAL_REQUIRED.
    let again = w
        .catalog(
            &attended(),
            CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: rid("r-declare"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(again.code, Code::ApprovalRequired);
    assert_eq!(again.next.decision_ref.as_deref(), Some(decision.as_str()));
    // Only an attended decide completes it.
    let e = w
        .ops
        .decide(
            &unattended(),
            DecideRequest {
                decision_id: DecisionId::parse(&decision).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    assert_eq!(
        eligibility_now(&w, &identity, &endpoint),
        InteractionKind::Unknown
    );
    w.decide(&decision, Verdict::Approve).await.unwrap();
    assert_eq!(
        eligibility_now(&w, &identity, &endpoint),
        InteractionKind::None
    );

    // The endpoint changes: the declaration lapses (recorded `endpoint_changed`).
    let key = w
        .store
        .transaction(|tx| tx.identity(&identity))
        .unwrap()
        .unwrap()
        .public_key;
    let moved = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: w.home.root.join("moved-agent.sock").display().to_string(),
    };
    w.catalog(
        &attended(),
        CatalogRequest::AdoptIdentity {
            identity: IdentitySpec {
                source: IdentitySourceSpec::NativeAgent {
                    endpoint: moved.clone(),
                },
                public_key: key,
                label: None,
            },
            request_id: rid("r-move"),
        },
    )
    .await
    .unwrap();
    let decl = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    assert_eq!(
        decl.state,
        heimdall_domain::catalog::DeclarationState::Lapsed
    );
    assert_eq!(
        decl.end_reason,
        Some(heimdall_domain::catalog::DeclarationEndReason::EndpointChanged)
    );
    assert_eq!(
        eligibility_now(&w, &identity, &moved),
        InteractionKind::Unknown
    );

    // Declared again at the new endpoint, it lapses at expiry.
    let decision = declare(&w, &identity, "r-declare-2").await;
    w.decide(&decision, Verdict::Approve).await.unwrap();
    assert_eq!(
        eligibility_now(&w, &identity, &moved),
        InteractionKind::None
    );
    w.clock
        .advance(heimdall_app::catalog::DECLARATION_VALIDITY + Duration::from_secs(1));
    assert_eq!(
        eligibility_now(&w, &identity, &moved),
        InteractionKind::Unknown
    );
}

#[tokio::test]
async fn withdraw_declaration_needs_no_decision() {
    let w = World::new().await;
    let identity = w.adopt("r-adopt").await;
    let decision = declare(&w, &identity, "r-declare").await;
    w.decide(&decision, Verdict::Approve).await.unwrap();
    let live = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    // A stale revision leaves the newer declaration live.
    let stale = w
        .catalog(
            &unattended(),
            CatalogRequest::WithdrawDeclaration {
                identity: identity.clone(),
                revision: Some(live.revision + 7),
                reason: WithdrawReason::ListingMissing,
                request_id: rid("r-withdraw-stale"),
            },
        )
        .await
        .unwrap();
    assert_eq!(stale["withdrawn"], false);
    assert_eq!(stale["revision"], live.revision);
    let decisions = w.decisions().len();
    // The current revision, on an unattended session, without a decision.
    let done = w
        .catalog(
            &unattended(),
            CatalogRequest::WithdrawDeclaration {
                identity: identity.clone(),
                revision: Some(live.revision),
                reason: WithdrawReason::ListingMissing,
                request_id: rid("r-withdraw"),
            },
        )
        .await
        .unwrap();
    assert_eq!(done["withdrawn"], true);
    assert_eq!(w.decisions().len(), decisions);
    let ended = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    assert_eq!(
        ended.state,
        heimdall_domain::catalog::DeclarationState::Lapsed
    );
    assert_eq!(
        ended.end_reason,
        Some(heimdall_domain::catalog::DeclarationEndReason::ListingMissing)
    );
}

#[tokio::test]
async fn declaration_written_from_decision_fields_only_and_stale_on_endpoint_change() {
    let w = World::new().await;
    let identity = w.adopt("r-adopt").await;
    let decision = declare(&w, &identity, "r-declare").await;
    let record = w
        .decisions()
        .into_iter()
        .find(|d| d.id.to_string() == decision)
        .unwrap();
    w.decide(&decision, Verdict::Approve).await.unwrap();
    let decl = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    let DecisionKind::DeclareInteraction {
        fingerprint,
        endpoint,
        interaction,
        valid_until,
        ..
    } = &record.kind
    else {
        panic!()
    };
    assert_eq!(decl.fingerprint, *fingerprint);
    assert_eq!(decl.endpoint, *endpoint);
    assert_eq!(decl.interaction, *interaction);
    assert_eq!(decl.expires_at, *valid_until);
    assert_eq!(decl.decision, record.id);

    // A catalog request changes the endpoint after the decision: DECISION_STALE,
    // nothing written.
    let (decision, op) = declare_op(&w, &identity, "r-declare-2").await;
    let key = w
        .store
        .transaction(|tx| tx.identity(&identity))
        .unwrap()
        .unwrap()
        .public_key;
    w.catalog(
        &attended(),
        CatalogRequest::AdoptIdentity {
            identity: IdentitySpec {
                source: IdentitySourceSpec::NativeAgent {
                    endpoint: EndpointRef {
                        kind: EndpointKind::UnixSocket,
                        locator: w.home.root.join("elsewhere.sock").display().to_string(),
                    },
                },
                public_key: key,
                label: None,
            },
            request_id: rid("r-move"),
        },
    )
    .await
    .unwrap();
    let before = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap();
    let _ = w.decide(&decision, Verdict::Approve).await;
    let after = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap();
    assert_eq!(before, after, "nothing written");
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Failed);
    assert_eq!(rec.code, Some(Code::DecisionStale));
}

fn open_setups(w: &World) -> Vec<OperationId> {
    w.store
        .transaction(|tx| tx.open_setup_operations(&env_id()))
        .unwrap()
}

fn count_rows(w: &World) -> (usize, usize, usize) {
    let page = w
        .store
        .transaction(|tx| {
            tx.stored_events_after(
                &env_id(),
                0,
                &heimdall_contract::event::EventFilter::default(),
                100_000,
            )
        })
        .unwrap();
    (open_setups(w).len(), w.decisions().len(), page.events.len())
}

#[tokio::test]
async fn second_setup_while_one_is_open_is_setup_in_progress() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let first = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-1")
        .await
        .unwrap_err()
        .operation_id
        .unwrap();
    let before = count_rows(&w);
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-2")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(e.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
    assert_eq!(e.next.operation_id, Some(first.clone()));
    assert_eq!(count_rows(&w), before, "nothing written");
    // A rollback is refused the same way.
    let rollback = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await;
    if let Ok(rollback) = rollback {
        let e = w
            .effect(&attended(), "rollback", &rollback.plan_digest, "r-3")
            .await
            .unwrap_err();
        assert_eq!(e.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
    }
    assert_eq!(open_setups(&w), vec![first]);
}

#[tokio::test]
async fn setup_in_progress_persists_across_restart() {
    let mut w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-1")
        .await
        .unwrap_err();
    let first = e.operation_id.clone().unwrap();
    w.restart().await;
    assert_eq!(w.op(&first).state, OperationState::AwaitingApproval);
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e2 = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-2")
        .await
        .unwrap_err();
    assert_eq!(e2.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
    // The restart kept the pending decision; deny settles the first.
    let pending = projection_decisions(&w, &first);
    assert_eq!(pending.len(), 1);
    w.decide(&pending[0].id.to_string(), Verdict::Deny)
        .await
        .unwrap();
    assert_eq!(w.op(&first).state, OperationState::Failed);
    let e3 = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-2")
        .await
        .unwrap_err();
    assert_eq!(e3.code, Code::ApprovalRequired, "admitted now: {e3:?}");
    assert_ne!(e3.operation_id, Some(first));
}

#[tokio::test]
async fn crash_during_setup_admission_leaves_no_blocker() {
    // In-process: the store fails the admission transaction at `BeforeCommit`, so it
    // rolls back exactly as a crash before the commit would leave it.
    let fault = Arc::new(ArmedFault::default());
    let mut w = World::with_faults(fault.clone()).await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    *w.writer
        .after_preview
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(fault.clone());
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-crash")
        .await
        .unwrap_err();
    assert_eq!(fault.fired.load(Ordering::SeqCst), 1);
    assert_eq!(e.code, Code::StateUnavailable, "{e:?}");
    w.restart().await;
    assert!(open_setups(&w).is_empty(), "no phantom blocker");
    assert!(w.decisions().is_empty());
    // The same request ID is admitted as new.
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-crash")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let _ = &w.faults;
}

/// Restart reconciliation never calls `apply` again: a crash inside the first apply
/// (first adoption at its commit step, and an update at P's exchange), then a fresh
/// `Operations` and writer over the same store.
#[tokio::test]
async fn restart_reconciles_attempted_apply_never_reapplies() {
    use heimdall_domain::projection::FileRole;
    for update in [false, true] {
        let mut w = World::new().await;
        let identity = w.catalog_alpha().await;
        if update {
            w.apply_approved("r-first").await;
            w.destination("r-dest-beta", "dst-beta", "beta", &identity)
                .await;
        }
        let plan = w
            .preview(PreviewIntent::Apply { include_git: false })
            .await
            .unwrap();
        let e = w
            .effect(&attended(), "apply", &plan.plan_digest, "r-crash")
            .await
            .unwrap_err();
        let op = e.operation_id.clone().unwrap();
        let intent = w.intent(&op);
        let commit = intent.files.iter().position(|s| s.commit).unwrap();
        let role = intent.files[commit].role;
        assert_eq!(
            role,
            if update {
                FileRole::ManagedSsh
            } else {
                FileRole::UserSsh
            }
        );
        w.hook.crash_at(
            ReplacePoint::AfterExchange,
            Some(u16::try_from(commit).unwrap()),
        );
        let applies = w.writer.applies.load(Ordering::SeqCst);
        let _ = w
            .decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
            .await;
        assert_eq!(w.writer.applies.load(Ordering::SeqCst), applies + 1);
        assert_eq!(w.op(&op).state, OperationState::Running, "update={update}");
        w.restart().await;
        assert_eq!(
            w.writer.applies.load(Ordering::SeqCst),
            0,
            "never re-applied"
        );
        assert!(w.writer.reconciles.load(Ordering::SeqCst) >= 1);
        let rec = w.op(&op);
        assert_eq!(
            rec.state,
            OperationState::Succeeded,
            "update={update} {:?}",
            rec.result
        );
        let p = std::fs::read_to_string(w.p()).unwrap();
        assert!(p.contains("Host alpha"));
        if update {
            assert!(p.contains("Host beta"));
        }
    }
}

#[tokio::test]
async fn projection_events_carry_generation_and_change() {
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let rollback = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    w.effect(&unattended(), "rollback", &rollback.plan_digest, "r-rb")
        .await
        .unwrap();
    let changes: Vec<(u64, String)> = w
        .events()
        .into_iter()
        .filter(|e| e.event.event_type == heimdall_contract::event::EventType::ResourceChanged)
        .filter(|e| {
            e.event
                .resource
                .as_ref()
                .is_some_and(|r| r.kind == "projection")
        })
        .map(|e| {
            (
                e.event.payload["generation"].as_u64().unwrap(),
                e.event.payload["change"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        changes,
        vec![(1, "applied".to_owned()), (2, "rolled_back".to_owned())]
    );
}

#[tokio::test]
async fn rollback_after_match_exec_command_edit_needs_decision() {
    let w = World::new().await;
    // `Match exec` chooses between candidate HostNames (never executed: static).
    let text = |cmd: &str| {
        format!(
            "Match host alpha exec \"{cmd}\"\n    HostName one.example.invalid\nHost alpha\n    HostName two.example.invalid\n"
        )
    };
    std::fs::write(w.user(), text("true")).unwrap();
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    // Only the command changes; the candidates and the condition kind stay.
    let user = std::fs::read_to_string(w.user())
        .unwrap()
        .replace("exec \"true\"", "exec \"false\"");
    std::fs::write(w.user(), user).unwrap();
    let plan = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    assert!(plan.consent.decision_required);
    assert!(
        plan.consent
            .reasons
            .iter()
            .any(|r| r.kind == ConsentReasonKind::UndeterminedState),
        "{:?}",
        plan.consent
    );
    let e = w
        .effect(&unattended(), "rollback", &plan.plan_digest, "r-rb")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::InteractionRequired);
    let op = e.operation_id.clone().unwrap();
    assert_eq!(
        projection_decisions(&w, &op)[0].id.to_string(),
        e.next.decision_ref.unwrap()
    );
}

/// ADR-0007 §12.19 item 9: the driver's sink refuses an `ItemCommit` whose consent
/// names another decision than the intent's approval; nothing is committed, and a
/// restart's reconcile (with an honest writer) commits under the approval.
#[tokio::test]
async fn sink_refuses_consent_under_another_decision() {
    let mut w = World::new().await;
    w.catalog_alpha().await;
    w.writer.tamper_consent.store(true, Ordering::SeqCst);
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-tamper")
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let decision = e.next.decision_ref.clone().unwrap();
    w.decide(&decision, Verdict::Approve).await.unwrap();
    assert!(w.record().is_none(), "nothing committed");
    let rec = w.op(&op);
    assert_ne!(rec.state, OperationState::Succeeded);
    w.restart().await;
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Succeeded, "{:?}", rec.result);
    let consent = w
        .store
        .transaction(|tx| tx.get_projection_consent(&env_id()))
        .unwrap();
    assert!(
        consent
            .items
            .values()
            .all(|c| c.decision.to_string() == decision)
    );
}

/// ADR-0007 §12.19 item 9: an item commit that leaves P unchanged keeps the record's
/// aliases and files (here, `move_include_to_top` writes only the user file).
#[tokio::test]
async fn item_record_aliases_merged_when_p_unchanged() {
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let first = w.record().unwrap().items[&ProjectionItem::Ssh].clone();
    assert_eq!(first.aliases, vec!["alpha".to_owned()]);
    // Put a section above B so that it is no longer first.
    let user = std::fs::read_to_string(w.user()).unwrap();
    std::fs::write(w.user(), format!("Host early\n    User fixture\n\n{user}")).unwrap();
    let plan = w
        .preview(PreviewIntent::Repair {
            conflict: ConflictKind::IncludeConditional,
            resolution: RepairResolution::MoveIncludeToTop,
            operation: None,
        })
        .await
        .unwrap();
    let done = w
        .effect(&attended(), "repair", &plan.plan_digest, "r-top")
        .await;
    let done = match done {
        Ok(v) => v,
        Err(e) if e.code == Code::ApprovalRequired => {
            w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
                .await
                .unwrap();
            serde_json::json!({})
        }
        Err(e) => panic!("{e:?}"),
    };
    let _ = done;
    let after = w.record().unwrap().items[&ProjectionItem::Ssh].clone();
    assert_eq!(after.aliases, first.aliases, "aliases merged");
    assert!(
        first.files.iter().all(|f| after
            .files
            .iter()
            .any(|a| a.path == f.path && a.role == f.role)),
        "files merged: {:?} vs {:?}",
        first.files,
        after.files
    );
}

/// ADR-0007 §12.19 item 7: a repair that takes two operations is offered again until
/// none is left: `move_include_to_top` leaves the old block (a duplicate), and only
/// the second operation, `remove_duplicate_markers`, makes the plan empty.
#[tokio::test]
async fn multi_operation_repair_is_offered_again_until_none_left() {
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let user = std::fs::read_to_string(w.user()).unwrap();
    std::fs::write(w.user(), format!("Host early\n    User fixture\n\n{user}")).unwrap();
    let run = |request: &'static str, resolution: RepairResolution, conflict: ConflictKind| {
        let w = &w;
        async move {
            let plan = w
                .preview(PreviewIntent::Repair {
                    conflict,
                    resolution,
                    operation: None,
                })
                .await
                .unwrap();
            if plan.files.is_empty() {
                return plan;
            }
            match w
                .effect(&attended(), "repair", &plan.plan_digest, request)
                .await
            {
                Ok(_) => {}
                Err(e) if e.code == Code::ApprovalRequired => {
                    w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
                        .await
                        .unwrap();
                }
                Err(e) => panic!("{e:?}"),
            }
            plan
        }
    };
    let first = run(
        "r-top",
        RepairResolution::MoveIncludeToTop,
        ConflictKind::IncludeConditional,
    )
    .await;
    assert!(
        !first.files.is_empty(),
        "the first operation changes the user file"
    );
    let again = w
        .preview(PreviewIntent::Repair {
            conflict: ConflictKind::MarkerDuplicated,
            resolution: RepairResolution::RemoveDuplicateMarkers,
            operation: None,
        })
        .await
        .unwrap();
    assert!(
        !again.files.is_empty(),
        "the next operation is still offered"
    );
    run(
        "r-dup",
        RepairResolution::RemoveDuplicateMarkers,
        ConflictKind::MarkerDuplicated,
    )
    .await;
    let none_left = w
        .preview(PreviewIntent::Repair {
            conflict: ConflictKind::MarkerDuplicated,
            resolution: RepairResolution::RemoveDuplicateMarkers,
            operation: None,
        })
        .await
        .unwrap();
    assert!(none_left.files.is_empty(), "{:?}", none_left.files);
}

/// ADR-0007 §12.19 item 9 and §12.16 item 3: a P path no literal `Include` can name is
/// manual mode, with `include_target_glob` as its own manual reason.
#[tokio::test]
async fn include_target_glob_is_its_own_manual_reason() {
    quiet_crashes();
    let home = ScratchHome::new();
    std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
    let globbed = home.root.join("cfg[1]");
    std::fs::create_dir_all(&globbed).unwrap();
    let store =
        Arc::new(Store::open(&home.state_dir.join("state.db"), Arc::new(NoFaults)).unwrap());
    let paths = SshPaths::with_test_override(home.git_home.clone(), home.root.join("etc-ssh"));
    let config = ProjectionConfig::new(paths, Platform::current(), globbed);
    let wired = wire_projection(store.clone(), config);
    let ops = Operations::start(OperationsConfig {
        projection: Some(wired.writer),
        ..World::config_of(
            &store,
            &VirtualClock::at(t0()),
            &ScriptedTimeSync::new(SyncStatus::Synchronized),
            &World::writer_of(&home, &store, &Arc::new(Hook::default())),
            Limits::default(),
        )
    })
    .await
    .unwrap();
    let identity = ops
        .catalog(
            &attended(),
            CatalogRequest::AdoptIdentity {
                identity: IdentitySpec {
                    source: IdentitySourceSpec::NativeAgent {
                        endpoint: EndpointRef {
                            kind: EndpointKind::UnixSocket,
                            locator: home.root.join("a.sock").display().to_string(),
                        },
                    },
                    public_key: synthetic_public_key(),
                    label: None,
                },
                request_id: rid("r-a"),
            },
        )
        .await
        .unwrap()
        .data["identity_id"]
        .as_str()
        .map(|s| IdentityId::parse(s).unwrap())
        .unwrap();
    ops.catalog(
        &attended(),
        CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-alpha").unwrap(),
                alias: "alpha".to_owned(),
                definition: DestinationDefinitionSpec::Managed {
                    hostname: "alpha.example.invalid".to_owned(),
                    port: None,
                    account: AccountName::parse("fixture").unwrap(),
                    identity,
                },
                label: None,
            },
            request_id: rid("r-d"),
        },
    )
    .await
    .unwrap();
    let plan: SetupPlan = serde_json::from_value(
        ops.setup(
            &attended(),
            SetupRequest::Preview {
                intent: PreviewIntent::Apply { include_git: false },
            },
        )
        .await
        .unwrap()
        .data,
    )
    .unwrap();
    assert_eq!(plan.mode, heimdall_contract::setup::SetupMode::Manual);
    assert!(
        plan.manual_reasons
            .iter()
            .any(|r| r == heimdall_contract::setup::manual_reason::INCLUDE_TARGET_GLOB),
        "{:?}",
        plan.manual_reasons
    );
    assert!(
        heimdall_contract::setup::manual_reason::ALL
            .contains(&heimdall_contract::setup::manual_reason::INCLUDE_TARGET_GLOB)
    );
}

/// ADR-0007 §12.17 item 11: the Git item's reasons are contract reasons. On a host
/// where Git's default SSH is not its bundled MSYS client, the Git item is not
/// applicable with `git_default_not_bundled_msys` (or, with no verified Git client,
/// `verified_client_unavailable`).
#[tokio::test]
async fn git_item_reasons_are_contract_reasons() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let plan = w
        .preview(PreviewIntent::Apply { include_git: true })
        .await
        .unwrap();
    let git = plan.git.expect("the Git part is planned");
    let found = git.reason.expect("not applicable on this host");
    if !cfg!(windows) {
        assert_eq!(found, reason::GIT_DEFAULT_NOT_BUNDLED_MSYS);
    }
    assert!(reason::ALL.contains(&found.as_str()));

    // With the test switch that offers the Git item whatever Git's default is, and no
    // verified client in the inventory: `verified_client_unavailable`.
    let mut config = World::projection_config(&w.home, &Arc::new(Hook::default()));
    config.test.git_item_any_default = true;
    let wired = wire_projection(w.store.clone(), config);
    let plan = wired
        .writer
        .preview(
            &heimdall_domain::projection::ProjectionSpec {
                environment: env_id(),
                aliases: Vec::new(),
                record: None,
                consent: heimdall_domain::projection::ConsentRecord::default(),
            },
            &PreviewIntent::Apply { include_git: true },
        )
        .unwrap();
    let found = plan.view.git.unwrap().reason.unwrap();
    assert_eq!(found, reason::VERIFIED_CLIENT_UNAVAILABLE);
    assert!(reason::ALL.contains(&found.as_str()));
}

// --- held operations (ADR-0007 §5.7 outcome H; QR12, QR14; M2-T03) ---------------------

/// How the fixture holds an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// An update whose displaced old P is moved away after P's exchange (U4's
    /// `a22_exchanged_with_displaced_missing_is_held`); the owner can put it back.
    DisplacedMissing,
    /// A first adoption whose inactive P is rewritten in place before the transaction
    /// check (C7a).
    Modified,
    /// A first adoption whose inactive P is replaced by a foreign file.
    Replaced,
    /// As `Modified`, with more than 1 MiB written (fingerprinted `unreadable`).
    ModifiedLarge,
}

/// A unique marker of observed content (scanned for in every output).
fn marker() -> String {
    format!(
        "hm-observed-{:016x}",
        heimdall_app::ids::random_u64().unwrap()
    )
}

fn content(mark: &str, large: bool) -> Vec<u8> {
    let mut v = format!("# {mark}\nHost edited\n").into_bytes();
    if large {
        v.resize((1 << 20) + 4096, b'#');
        v.push(b'\n');
    }
    v
}

fn rewrite_in_place(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn replace_foreign(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension("foreign-tmp");
    std::fs::write(&tmp, bytes).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

struct Held {
    w: World,
    op: OperationId,
    request: &'static str,
    digest: PlanDigest,
    /// Where the displaced P was moved (`DisplacedMissing`).
    stash: Option<(PathBuf, PathBuf)>,
    mark: String,
}

async fn held(kind: Hold) -> Held {
    use heimdall_domain::projection::FileRole;
    let w = World::new().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let identity = w.catalog_alpha().await;
    if kind == Hold::DisplacedMissing {
        w.apply_approved("r-first").await;
        w.destination("r-dest-beta", "dst-beta", "beta", &identity)
            .await;
    }
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let request = "r-held";
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, request)
        .await
        .unwrap_err();
    let op = e.operation_id.clone().unwrap();
    let intent = w.intent(&op);
    let p_step = step_of(&intent, FileRole::ManagedSsh);
    let user_step = intent
        .files
        .iter()
        .position(|s| s.role == FileRole::UserSsh);
    let p = w.p();
    let mark = marker();
    let mut stash = None;
    match kind {
        Hold::DisplacedMissing => {
            let displaced = w.home.config_dir.join(
                intent.files[usize::from(p_step)]
                    .displaced_name
                    .clone()
                    .unwrap(),
            );
            let away = w.home.root.join("stashed-displaced");
            stash = Some((displaced.clone(), away.clone()));
            w.hook.run_at(
                ReplacePoint::BeforeReceipt("post_validated"),
                Some(p_step),
                move || std::fs::rename(&displaced, &away).unwrap(),
            );
        }
        Hold::Modified | Hold::ModifiedLarge | Hold::Replaced => {
            let bytes = content(&mark, kind == Hold::ModifiedLarge);
            let step = u16::try_from(user_step.unwrap()).unwrap();
            w.hook.run_at(
                ReplacePoint::BeforeReceipt("post_validated"),
                Some(step),
                move || {
                    if kind == Hold::Replaced {
                        replace_foreign(&p, &bytes);
                    } else {
                        rewrite_in_place(&p, &bytes);
                    }
                },
            );
        }
    }
    w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
        .await
        .unwrap();
    let rec = w.op(&op);
    assert_eq!(
        rec.state,
        OperationState::OutcomeUnknown,
        "{kind:?}: {:?}",
        rec.result
    );
    // The hold is the one the fixture describes (the receipts' `file.held` reason).
    let expected = match kind {
        Hold::DisplacedMissing => "displaced_missing",
        Hold::Modified | Hold::ModifiedLarge => "active_entry_modified",
        Hold::Replaced => "active_entry_replaced",
    };
    let reasons: Vec<String> = w
        .receipts(&op)
        .iter()
        .filter_map(|r| match &r.local {
            Some(heimdall_domain::operation::LocalReceipt::File {
                phase: heimdall_domain::operation::FilePhase::Held { reason, .. },
                ..
            }) => serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned)),
            _ => None,
        })
        .collect();
    assert!(
        reasons.iter().any(|r| r == expected),
        "{kind:?}: {reasons:?}"
    );
    Held {
        w,
        op,
        request,
        digest: plan.plan_digest,
        stash,
        mark,
    }
}

fn held_reason(h: &Held) -> String {
    let v = h.w.op(&h.op).result.unwrap();
    v["setup"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["outcome"] == "held")
        .map(|_| v["error"]["reason"].as_str().unwrap().to_owned())
        .unwrap()
}

async fn held_plan(
    h: &Held,
    resolution: RepairResolution,
    op: &OperationId,
) -> Result<SetupPlan, OpError> {
    h.w.preview(PreviewIntent::Repair {
        conflict: ConflictKind::ProjectionHeld,
        resolution,
        operation: Some(op.clone()),
    })
    .await
}

/// ADR-0007 §12.17 item 6: a held item is `OUTCOME_UNKNOWN`, reason
/// `projection_held`, effect `unknown`, next `reconcile`, with both held repair
/// options, and the envelope carries the `SetupResult` in `data.setup`.
#[tokio::test]
async fn held_item_is_outcome_unknown_with_the_held_repair_options() {
    let h = held(Hold::DisplacedMissing).await;
    assert_eq!(held_reason(&h), reason::PROJECTION_HELD);
    let replay =
        h.w.effect(&attended(), "apply", &h.digest, h.request)
            .await
            .unwrap();
    assert_eq!(replay["__code"], "OUTCOME_UNKNOWN");
    assert_eq!(replay["__state"], "outcome_unknown");
    let error = &replay["error"];
    assert_eq!(error["reason"], reason::PROJECTION_HELD);
    assert_eq!(error["effect_status"], "unknown");
    assert_eq!(error["next"]["action"], "reconcile");
    assert_eq!(error["next"]["operation_id"], serde_json::json!(h.op));
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("retry_held") && message.contains("keep_held"),
        "{message}"
    );
    let items = replay["setup"]["items"].as_array().unwrap();
    assert!(items.iter().any(|i| i["outcome"] == "held"));
    assert!(
        items
            .iter()
            .flat_map(|i| i["files"].as_array().unwrap())
            .any(|f| f["state"] == "held")
    );
    // The idempotency record stays open: nothing is settled.
    let open = open_setups(&h.w);
    assert_eq!(open, vec![h.op.clone()]);
}

#[tokio::test]
async fn held_operation_blocks_setup_except_its_repair() {
    let mut h = held(Hold::DisplacedMissing).await;
    for round in 0..2 {
        // apply and rollback are refused, naming the held operation and both repairs.
        let apply =
            h.w.preview(PreviewIntent::Apply { include_git: false })
                .await
                .unwrap();
        let e =
            h.w.effect(
                &attended(),
                "apply",
                &apply.plan_digest,
                &format!("r-apply-{round}"),
            )
            .await
            .unwrap_err();
        assert_eq!(e.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
        assert_eq!(e.next.operation_id.as_ref(), Some(&h.op));
        assert!(e.message.contains("retry_held") && e.message.contains("keep_held"));
        if let Ok(rb) =
            h.w.preview(PreviewIntent::Rollback {
                keep_key_files: false,
                items: [ProjectionItem::Ssh].into_iter().collect(),
            })
            .await
        {
            let e =
                h.w.effect(
                    &attended(),
                    "rollback",
                    &rb.plan_digest,
                    &format!("r-rb-{round}"),
                )
                .await
                .unwrap_err();
            assert_eq!(e.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
        }
        // A held repair for another operation is refused.
        let other = OperationId::from_random_bytes(random_bytes());
        let e = held_plan(&h, RepairResolution::RetryHeld, &other)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict);
        // Both held repairs for it preview without a decision.
        for res in [RepairResolution::RetryHeld, RepairResolution::KeepHeld] {
            let plan = held_plan(&h, res, &h.op).await.unwrap();
            assert!(!plan.consent.decision_required);
        }
        if round == 0 {
            h.w.restart().await;
            assert!(
                h.w.writer.reconciles.load(Ordering::SeqCst) >= 1,
                "reconciled at restart"
            );
            assert_eq!(h.w.op(&h.op).state, OperationState::OutcomeUnknown);
        }
    }
    // RetryHeld is admitted (D is still missing: the operation stays held).
    let decisions = h.w.decisions().len();
    let retry = held_plan(&h, RepairResolution::RetryHeld, &h.op)
        .await
        .unwrap();
    let e =
        h.w.effect(&unattended(), "repair", &retry.plan_digest, "r-retry")
            .await
            .unwrap_err();
    assert!(e.operation_id.is_some(), "admitted: {e:?}");
    assert_eq!(e.reason.as_deref(), Some(reason::PROJECTION_HELD));
    assert_eq!(h.w.op(&h.op).state, OperationState::OutcomeUnknown);
    // KeepHeld is admitted and closes it.
    let keep = held_plan(&h, RepairResolution::KeepHeld, &h.op)
        .await
        .unwrap();
    let done =
        h.w.effect(&unattended(), "repair", &keep.plan_digest, "r-keep")
            .await
            .unwrap();
    assert_eq!(done["__code"], "OK", "{done}");
    assert_eq!(h.w.decisions().len(), decisions, "no decision record");
    assert!(open_setups(&h.w).is_empty());
}

#[tokio::test]
async fn held_repair_retry_continues_and_keep_closes_without_moving() {
    // retry, after the owner put D back: the operation continues to `applied`.
    let h = held(Hold::DisplacedMissing).await;
    let (displaced, away) = h.stash.clone().unwrap();
    std::fs::rename(&away, &displaced).unwrap();
    let decisions = h.w.decisions().len();
    let retry = held_plan(&h, RepairResolution::RetryHeld, &h.op)
        .await
        .unwrap();
    let done =
        h.w.effect(&unattended(), "repair", &retry.plan_digest, "r-retry")
            .await
            .unwrap();
    assert_eq!(done["__code"], "OK", "{done}");
    assert_eq!(h.w.op(&h.op).state, OperationState::Succeeded);
    assert!(
        std::fs::read_to_string(h.w.p())
            .unwrap()
            .contains("Host beta")
    );
    assert_eq!(h.w.decisions().len(), decisions);

    // keep, with nothing changed: no entry moves.
    let h = held(Hold::DisplacedMissing).await;
    let keep = held_plan(&h, RepairResolution::KeepHeld, &h.op)
        .await
        .unwrap();
    let tree = h.w.tree();
    let done =
        h.w.effect(&unattended(), "repair", &keep.plan_digest, "r-keep")
            .await
            .unwrap();
    assert_eq!(done["__code"], "OK", "{done}");
    assert_eq!(h.w.tree(), tree, "nothing moved");
    let o = h.w.op(&h.op);
    assert_eq!(o.state, OperationState::Failed);
    assert_eq!(o.code, Some(Code::ConfigConflict));
    assert_eq!(o.effect_status, EffectStatus::Partial);
    let remaining = o.result.unwrap()["setup"]["remaining"].clone();
    let kinds: Vec<&str> = remaining
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"conflict_file") && kinds.contains(&"quarantine"),
        "{remaining}"
    );
    // A new apply previews from the files as they are.
    h.w.preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();

    // keep, after the files changed since its preview: stale, nothing written.
    let h = held(Hold::DisplacedMissing).await;
    let keep = held_plan(&h, RepairResolution::KeepHeld, &h.op)
        .await
        .unwrap();
    let (displaced, away) = h.stash.clone().unwrap();
    std::fs::rename(&away, &displaced).unwrap();
    let tree = h.w.tree();
    let receipts = h.w.receipts(&h.op).len();
    let e =
        h.w.effect(&unattended(), "repair", &keep.plan_digest, "r-keep")
            .await
            .unwrap_err();
    assert_eq!(e.code, Code::ConfigConflict);
    assert_eq!(h.w.tree(), tree);
    assert_eq!(h.w.receipts(&h.op).len(), receipts, "nothing written");
    assert_eq!(h.w.op(&h.op).state, OperationState::OutcomeUnknown);
}

/// The plan, result, receipts and events of `h` hold no byte of the observed entries.
fn assert_no_observed_content(h: &Held, plan: &SetupPlan, outputs: &[String]) {
    let mut all = vec![serde_json::to_string(plan).unwrap()];
    all.extend(outputs.iter().cloned());
    all.push(serde_json::to_string(&h.w.receipts(&h.op)).unwrap());
    all.push(serde_json::to_string(&h.w.op(&h.op)).unwrap());
    for e in h.w.events() {
        all.push(serde_json::to_string(&e.event).unwrap());
    }
    for text in &all {
        assert_no_canary(text);
        assert!(!text.contains(&h.mark), "observed content leaked");
        assert!(!text.contains("Host edited"), "observed content leaked");
    }
}

#[tokio::test]
async fn held_repair_preview_binds_content_fingerprints() {
    // Two successive in-place edits: S rewritten to A (held), then to B.
    for kind in [Hold::Modified, Hold::ModifiedLarge] {
        let h = held(kind).await;
        let keep = held_plan(&h, RepairResolution::KeepHeld, &h.op)
            .await
            .unwrap();
        let other = content(&marker(), kind == Hold::ModifiedLarge);
        let mut b = content(&h.mark, kind == Hold::ModifiedLarge);
        // Same length (and the same identity): only the bytes and the change time differ.
        if let Some(last) = b.iter().position(|c| *c == b'H') {
            b[last] = b'h';
        }
        assert_ne!(b, other);
        std::thread::sleep(Duration::from_millis(20));
        rewrite_in_place(&h.w.p(), &b);
        let receipts = h.w.receipts(&h.op).len();
        let e =
            h.w.effect(&unattended(), "repair", &keep.plan_digest, "r-keep-1")
                .await
                .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "{kind:?}: {e:?}");
        assert_eq!(h.w.receipts(&h.op).len(), receipts, "nothing written");
        let fresh = held_plan(&h, RepairResolution::KeepHeld, &h.op)
            .await
            .unwrap();
        assert_ne!(fresh.plan_digest, keep.plan_digest, "{kind:?}");
        let done =
            h.w.effect(&unattended(), "repair", &fresh.plan_digest, "r-keep-2")
                .await
                .unwrap();
        assert_eq!(done["__code"], "OK");
        assert_eq!(h.w.op(&h.op).state, OperationState::Failed);
        assert_no_observed_content(&h, &fresh, &[done.to_string(), format!("{e:?}")]);
    }
    // Two different foreign replacements: X1 replaced by X2 (another identity, the
    // same bytes), and X1 rewritten in place (same identity, other bytes).
    for in_place in [false, true] {
        let h = held(Hold::Replaced).await;
        let keep = held_plan(&h, RepairResolution::KeepHeld, &h.op)
            .await
            .unwrap();
        let x1 = std::fs::read(h.w.p()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        if in_place {
            let mut other = x1.clone();
            other[2] = b'x';
            rewrite_in_place(&h.w.p(), &other);
        } else {
            replace_foreign(&h.w.p(), &x1);
        }
        let e =
            h.w.effect(&unattended(), "repair", &keep.plan_digest, "r-keep")
                .await
                .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "in_place={in_place}: {e:?}");
        assert_eq!(h.w.op(&h.op).state, OperationState::OutcomeUnknown);
        assert_no_observed_content(&h, &keep, &[format!("{e:?}")]);
    }
}

/// A first adoption held after its user file was restored: the result lists the user
/// file as `restored` and never as `applied` (the item never committed).
#[tokio::test]
async fn held_first_adoption_reports_restored_files() {
    let h = held(Hold::Modified).await;
    let result = h.w.op(&h.op).result.unwrap();
    let files = result["setup"]["items"][0]["files"]
        .as_array()
        .unwrap()
        .clone();
    let state = |role: &str| {
        files
            .iter()
            .find(|f| f["role"] == role)
            .map(|f| f["state"].as_str().unwrap().to_owned())
    };
    assert_eq!(state("user_ssh").as_deref(), Some("restored"), "{files:?}");
    assert_eq!(state("managed_ssh").as_deref(), Some("held"), "{files:?}");
    assert!(files.iter().all(|f| f["state"] != "applied"), "{files:?}");
}

// --- the process-abort variant of the restart test (M01 N06 labelling) -----------------

/// The scratch locations the child process works in (passed through the environment).
const CHILD_ENV: &str = "HM_U5_ABORT_CHILD";

struct ChildPaths {
    home: PathBuf,
    etc: PathBuf,
    config: PathBuf,
    db: PathBuf,
    update: bool,
}

impl ChildPaths {
    fn of(home: &ScratchHome, update: bool) -> ChildPaths {
        ChildPaths {
            home: home.git_home.clone(),
            etc: home.root.join("etc-ssh"),
            config: home.config_dir.clone(),
            db: home.state_dir.join("state.db"),
            update,
        }
    }

    fn encode(&self) -> String {
        [
            self.home.display().to_string(),
            self.etc.display().to_string(),
            self.config.display().to_string(),
            self.db.display().to_string(),
            self.update.to_string(),
        ]
        .join("\n")
    }

    fn decode(s: &str) -> ChildPaths {
        let v: Vec<&str> = s.split('\n').collect();
        ChildPaths {
            home: PathBuf::from(v[0]),
            etc: PathBuf::from(v[1]),
            config: PathBuf::from(v[2]),
            db: PathBuf::from(v[3]),
            update: v[4] == "true",
        }
    }

    fn writer(
        &self,
        store: &Arc<Store>,
        hook: Option<Arc<dyn ReplaceHook>>,
    ) -> Arc<dyn ProjectionWriter> {
        let paths = SshPaths::with_test_override(self.home.clone(), self.etc.clone());
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.config.clone());
        c.hook = hook;
        wire_projection(store.clone(), c).writer
    }

    async fn ops(&self, store: &Arc<Store>, writer: Arc<dyn ProjectionWriter>) -> Operations {
        Operations::start(OperationsConfig {
            store: store.clone(),
            clock: VirtualClock::at(t0()),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: Duration::from_secs(12 * 3600),
            projection: Some(writer),
        })
        .await
        .unwrap()
    }
}

/// Aborts the process at a point (a real crash: no unwinding, no destructors).
struct AbortAt {
    step: std::sync::atomic::AtomicU32,
}

impl ReplaceHook for AbortAt {
    fn at(&self, point: ReplacePoint, step: u16) {
        if point == ReplacePoint::AfterExchange
            && u32::from(step) == self.step.load(Ordering::SeqCst)
        {
            std::process::abort();
        }
    }
}

async fn child_apply(
    ops: &Operations,
    digest: &PlanDigest,
    request: &str,
) -> (OperationId, String) {
    let e = ops
        .setup(
            &attended(),
            SetupRequest::Apply {
                plan_digest: digest.clone(),
                request_id: rid(request),
            },
        )
        .await
        .unwrap_err();
    (e.operation_id.unwrap(), e.next.decision_ref.unwrap())
}

async fn child_preview(ops: &Operations) -> PlanDigest {
    let v = ops
        .setup(
            &attended(),
            SetupRequest::Preview {
                intent: PreviewIntent::Apply { include_git: false },
            },
        )
        .await
        .unwrap()
        .data;
    serde_json::from_value::<SetupPlan>(v).unwrap().plan_digest
}

async fn child_flow(paths: ChildPaths) {
    use heimdall_domain::projection::FileRole;
    let store = Arc::new(Store::open(&paths.db, Arc::new(NoFaults)).unwrap());
    let hook = Arc::new(AbortAt {
        step: std::sync::atomic::AtomicU32::new(u32::MAX),
    });
    let h: Arc<dyn ReplaceHook> = hook.clone();
    let ops = paths.ops(&store, paths.writer(&store, Some(h))).await;
    let adopt = ops
        .catalog(
            &attended(),
            CatalogRequest::AdoptIdentity {
                identity: IdentitySpec {
                    source: IdentitySourceSpec::NativeAgent {
                        endpoint: EndpointRef {
                            kind: EndpointKind::UnixSocket,
                            locator: paths.etc.join("agent.sock").display().to_string(),
                        },
                    },
                    public_key: synthetic_public_key(),
                    label: None,
                },
                request_id: rid("r-adopt"),
            },
        )
        .await
        .unwrap()
        .data;
    let identity = IdentityId::parse(adopt["identity_id"].as_str().unwrap()).unwrap();
    for (n, alias) in [(0, "alpha"), (1, "beta")] {
        if n == 1 && !paths.update {
            break;
        }
        if n == 1 {
            let digest = child_preview(&ops).await;
            let (_, d) = child_apply(&ops, &digest, "r-first").await;
            ops.decide(
                &attended(),
                DecideRequest {
                    decision_id: DecisionId::parse(&d).unwrap(),
                    verdict: Verdict::Approve,
                },
            )
            .await
            .unwrap();
        }
        ops.catalog(
            &attended(),
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(&format!("dst-{alias}")).unwrap(),
                    alias: alias.to_owned(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: format!("{alias}.example.invalid"),
                        port: None,
                        account: AccountName::parse("fixture").unwrap(),
                        identity: identity.clone(),
                    },
                    label: None,
                },
                request_id: rid(&format!("r-dest-{alias}")),
            },
        )
        .await
        .unwrap();
    }
    let digest = child_preview(&ops).await;
    let (op, d) = child_apply(&ops, &digest, "r-crash").await;
    let intent = match store
        .transaction(|tx| tx.recovery_intent(&op))
        .unwrap()
        .unwrap()
        .local
    {
        Some(LocalIntent::Setup(i)) => i,
        _ => panic!(),
    };
    let commit = intent.files.iter().position(|s| s.commit).unwrap();
    assert_eq!(
        intent.files[commit].role,
        if paths.update {
            FileRole::ManagedSsh
        } else {
            FileRole::UserSsh
        }
    );
    std::fs::write(paths.config.join("crash-op"), op.to_string()).unwrap();
    hook.step
        .store(u32::try_from(commit).unwrap(), Ordering::SeqCst);
    // The approval resumes the operation; `apply` aborts the process at the commit
    // step's exchange.
    let _ = ops
        .decide(
            &attended(),
            DecideRequest {
                decision_id: DecisionId::parse(&d).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await;
    panic!("the child was meant to abort inside apply");
}

/// The child half: runs only when the parent sets [`CHILD_ENV`].
#[test]
fn restart_child_aborts_inside_apply() {
    let Ok(encoded) = std::env::var(CHILD_ENV) else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(child_flow(ChildPaths::decode(&encoded)));
}

/// `restart_reconciles_attempted_apply_never_reapplies`, the **process-abort**
/// variant (labelled as such, M01 N06): a child process dies by `abort()` at the
/// commit step's exchange (first adoption and update), and a fresh `Operations` with a
/// fresh writer over the same store reconciles without calling `apply`.
#[tokio::test]
async fn restart_reconciles_attempted_apply_never_reapplies_after_a_process_abort() {
    use std::os::unix::process::ExitStatusExt as _;
    for update in [false, true] {
        let home = ScratchHome::new();
        std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
        let paths = ChildPaths::of(&home, update);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart_child_aborts_inside_apply",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, paths.encode())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(6),
            "update={update}: the child aborted ({status:?})"
        );
        let op = OperationId::parse(
            std::fs::read_to_string(paths.config.join("crash-op"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        std::fs::remove_file(paths.config.join("crash-op")).unwrap();
        let store = Arc::new(Store::open(&paths.db, Arc::new(NoFaults)).unwrap());
        let inner = paths.writer(&store, None);
        let counting = Arc::new(Counting {
            inner,
            applies: AtomicUsize::new(0),
            reconciles: AtomicUsize::new(0),
            previews: AtomicUsize::new(0),
            after_preview: Mutex::new(None),
            tamper_consent: std::sync::atomic::AtomicBool::new(false),
        });
        let writer: Arc<dyn ProjectionWriter> = counting.clone();
        let _ops = paths.ops(&store, writer).await;
        assert_eq!(
            counting.applies.load(Ordering::SeqCst),
            0,
            "never re-applied"
        );
        assert!(counting.reconciles.load(Ordering::SeqCst) >= 1);
        let rec = store.transaction(|tx| tx.operation(&op)).unwrap().unwrap();
        assert_eq!(
            rec.state,
            OperationState::Succeeded,
            "update={update}: {:?}",
            rec.result
        );
        let p = std::fs::read_to_string(home.config_dir.join("ssh_config")).unwrap();
        assert!(p.contains("Host alpha"));
        assert_eq!(p.contains("Host beta"), update);
    }
}

// --- W3b-gaps (ADR-0007 §12.22 items 3, 9 and 10) ------------------------------------------

/// Preview an apply and submit it: the operation waits for the decision it created.
async fn apply_waiting(w: &World, request: &str) -> (OperationId, String) {
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, request)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    (
        e.operation_id.clone().unwrap(),
        e.next.decision_ref.clone().unwrap(),
    )
}

/// The operation expired: `failed`, `CREDENTIAL_EXPIRED`, effect `none`, the expired
/// decision named, and nothing written.
fn assert_expired(w: &World, op: &OperationId, decision: &str) {
    let rec = w.op(op);
    assert_eq!(rec.state, OperationState::Failed, "{:?}", rec.result);
    assert_eq!(rec.code, Some(Code::CredentialExpired));
    assert_eq!(rec.effect_status, EffectStatus::None);
    let error = &rec.result.as_ref().unwrap()["error"];
    assert_eq!(error["next"]["action"], "new_work", "{error}");
    assert_eq!(error["resource"]["kind"], "decision", "{error}");
    assert_eq!(error["resource"]["id"], decision, "{error}");
}

/// ADR-0007 §12.22 item 9 (W3b-gaps): a setup operation in `awaiting_approval` whose
/// decision passed its deadline expires, as ADR-0006's `DeadlineReached` does. The
/// replay after the deadline answers `CREDENTIAL_EXPIRED` (`next: new_work`) and
/// issues no fresh decision; nothing is written; the expired record cannot be
/// approved; and the operation no longer blocks setup, so new work is a new request.
/// Before the deadline the replay keeps answering `APPROVAL_REQUIRED`.
#[tokio::test]
async fn expired_projection_decision_expires_the_operation() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let (op, first) = apply_waiting(&w, "r-apply").await;
    let before = w.tree();
    let digest = w.intent(&op).plan_digest;
    w.clock
        .advance(heimdall_domain::decision::DEFAULT_DECISION_LIFETIME - Duration::from_secs(1));
    let still = w
        .effect(&attended(), "apply", &digest, "r-apply")
        .await
        .unwrap_err();
    assert_eq!(still.code, Code::ApprovalRequired, "{still:?}");
    assert_eq!(still.next.decision_ref.as_deref(), Some(first.as_str()));
    w.clock.advance(Duration::from_secs(2));
    let again = w
        .effect(&attended(), "apply", &digest, "r-apply")
        .await
        .unwrap_err();
    assert_eq!(again.code, Code::CredentialExpired, "{again:?}");
    assert_eq!(again.next.action, "new_work");
    assert_eq!(again.effect_status, EffectStatus::None);
    assert_eq!(again.operation_id.as_ref(), Some(&op));
    assert_expired(&w, &op, &first);
    // No fresh decision: the only record naming the operation is the first one.
    let records = projection_decisions(&w, &op);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id.to_string(), first);
    assert_eq!(w.tree(), before, "nothing was written");
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 0);
    // The expired record cannot be approved, and the operation stays expired.
    let d = w.decide(&first, Verdict::Approve).await.unwrap_err();
    assert_eq!(d.code, Code::DecisionStale, "{d:?}");
    assert_expired(&w, &op, &first);
    assert_eq!(w.tree(), before);
    // It no longer blocks setup; the same request ID replays the expiry.
    assert!(open_setups(&w).is_empty());
    let replay = w
        .effect(&attended(), "apply", &digest, "r-apply")
        .await
        .unwrap_err();
    assert_eq!(replay.code, Code::CredentialExpired);
    let (fresh, _) = apply_waiting(&w, "r-apply-new").await;
    assert_ne!(fresh, op, "new work is a new operation");
    w.events();
}

/// ADR-0007 §12.22 item 9: the expiry happens whoever finds the deadline passed: a
/// `decide` of the expired record (in its transaction), the supervisor's tick (with
/// nobody asking), and restart recovery. Before the deadline none of them moves it.
#[tokio::test]
async fn expired_projection_decision_expires_at_decide_tick_and_restart() {
    for path in ["decide", "tick", "restart"] {
        let mut w = World::new().await;
        w.catalog_alpha().await;
        let (op, decision) = apply_waiting(&w, "r-apply").await;
        w.ops.tick().await.unwrap();
        assert_eq!(
            w.op(&op).state,
            OperationState::AwaitingApproval,
            "{path}: before the deadline"
        );
        w.clock
            .advance(heimdall_domain::decision::DEFAULT_DECISION_LIFETIME + Duration::from_secs(1));
        match path {
            "decide" => {
                let e = w.decide(&decision, Verdict::Deny).await.unwrap_err();
                assert_eq!(e.code, Code::DecisionStale, "{e:?}");
            }
            "tick" => w.ops.tick().await.unwrap(),
            _ => w.restart().await,
        }
        assert_expired(&w, &op, &decision);
        assert_eq!(w.writer.applies.load(Ordering::SeqCst), 0, "{path}");
        assert_eq!(
            projection_decisions(&w, &op).len(),
            1,
            "{path}: no new record"
        );
        assert!(open_setups(&w).is_empty(), "{path}");
    }
}

/// ADR-0007 §12.22 item 9 for the catalog: a `DeclareInteraction` operation whose
/// decision passed its deadline expires, at a replay (which before this answered
/// `ACCEPTED` for ever), at a `decide` and at the tick. No declaration is written.
#[tokio::test]
async fn expired_declaration_decision_expires_the_catalog_operation() {
    for path in ["replay", "decide", "tick"] {
        let w = World::new().await;
        let identity = w.adopt("r-adopt").await;
        let (decision, op) = declare_op(&w, &identity, "r-declare").await;
        w.clock
            .advance(heimdall_domain::decision::DEFAULT_DECISION_LIFETIME + Duration::from_secs(1));
        match path {
            "replay" => {
                let e = w
                    .catalog(
                        &attended(),
                        CatalogRequest::DeclareInteraction {
                            identity: identity.clone(),
                            interaction: DeclaredInteraction::None,
                            request_id: rid("r-declare"),
                        },
                    )
                    .await
                    .unwrap_err();
                assert_eq!(e.code, Code::CredentialExpired, "{e:?}");
                assert_eq!(e.operation_id.as_ref(), Some(&op));
            }
            "decide" => {
                let e = w.decide(&decision, Verdict::Approve).await.unwrap_err();
                assert_eq!(e.code, Code::DecisionStale, "{e:?}");
            }
            _ => w.ops.tick().await.unwrap(),
        }
        assert_expired(&w, &op, &decision);
        let row = w
            .store
            .transaction(|tx| tx.interaction_declaration(&identity))
            .unwrap();
        assert!(row.is_none(), "{path}: no declaration written");
        w.events();
    }
}

/// A writer that previews with one configuration and applies with another: the
/// verified Git client the preview found is gone by the time the apply runs.
struct Split {
    preview: Arc<dyn ProjectionWriter>,
    apply: Arc<dyn ProjectionWriter>,
}

impl ProjectionWriter for Split {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        self.preview.preview(spec, intent)
    }
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.apply.apply(intent, sink)
    }
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
        self.apply.reconcile(intent, receipts, sink)
    }
    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation> {
        self.preview.observe(record, aliases)
    }
    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError> {
        self.apply.observe_held(intent, receipts)
    }
}

/// ADR-0007 §12.22 item 3 (W3b-gaps): when the Git item's parse check cannot run
/// because no verified client is available at apply time, the setup driver settles
/// `CAPABILITY_UNAVAILABLE` with reason `verified_client_unavailable` (effect
/// `partial`: the SSH item applied), never `CONFIG_CONFLICT`. A replay reports the
/// same, with the `SetupResult` listing the Git item `not_applied`.
#[tokio::test]
async fn verified_client_unavailable_at_apply_is_capability_unavailable() {
    use heimdall_localenv::clients::{ClientCandidate, ClientInventory, ClientKind, ClientSource};
    use heimdall_localenv::local_query::LocalQueries;
    let mut w = World::new().await;
    w.catalog_alpha().await;
    let git = heimdall_testkit::home::find_program("git").expect("git is installed");
    let system = w.home.root.join("gitconfig-system");
    std::fs::write(&system, b"").unwrap();
    std::fs::write(
        w.home.git_home.join(".gitconfig"),
        b"[user]\n\tname = Scratch\n",
    )
    .unwrap();
    let mut config = World::projection_config(&w.home, &w.hook);
    config.env = heimdall_localenv::env::Env::from_vars([
        ("HOME", w.home.git_home.display().to_string()),
        (
            "XDG_CONFIG_HOME",
            w.home.git_home.join(".config").display().to_string(),
        ),
        ("GIT_CONFIG_SYSTEM", system.display().to_string()),
    ]);
    config.queries = LocalQueries::Enabled;
    let ssh = heimdall_testkit::home::find_program("ssh").expect("ssh is installed");
    let candidate = |kind, path| ClientCandidate {
        kind,
        path,
        source: ClientSource::Path,
        version: None,
        sha256: None,
        selected: true,
    };
    config.clients = ClientInventory {
        candidates: vec![
            candidate(ClientKind::Git, git),
            candidate(ClientKind::Ssh, ssh),
        ],
    };
    config.test.git_item_any_default = true;
    let mut gone = config.clone();
    gone.queries = LocalQueries::Disabled;
    let split: Arc<dyn ProjectionWriter> = Arc::new(Split {
        preview: wire_projection(w.store.clone(), config).writer,
        apply: wire_projection(w.store.clone(), gone).writer,
    });
    w.ops = Operations::start(OperationsConfig {
        projection: Some(split),
        ..World::config_of(&w.store, &w.clock, &w.sync, &w.writer, w.limits)
    })
    .await
    .unwrap();
    let plan = w
        .preview(PreviewIntent::Apply { include_git: true })
        .await
        .unwrap();
    let git_change = plan.git.clone().expect("the Git part is planned");
    assert_eq!(
        git_change.reason, None,
        "applicable at preview: {git_change:?}"
    );
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-apply")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    let op = e.operation_id.clone().unwrap();
    let decided = w
        .decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
        .await;
    assert!(decided.is_ok(), "{decided:?}");
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Failed, "{:?}", rec.result);
    assert_eq!(
        rec.code,
        Some(Code::CapabilityUnavailable),
        "{:?}",
        rec.result
    );
    assert_eq!(rec.effect_status, EffectStatus::Partial);
    let replay = w
        .ops
        .setup(
            &attended(),
            SetupRequest::Apply {
                plan_digest: plan.plan_digest.clone(),
                request_id: rid("r-apply"),
            },
        )
        .await;
    let data = match replay {
        Ok(c) => {
            assert_eq!(c.code, Code::CapabilityUnavailable);
            c.data
        }
        Err(e) => panic!("the failed envelope carries the setup result: {e:?}"),
    };
    assert_eq!(
        data["error"]["reason"],
        reason::VERIFIED_CLIENT_UNAVAILABLE,
        "{data}"
    );
    assert_eq!(data["error"]["code"], "CAPABILITY_UNAVAILABLE", "{data}");
    let items = data["setup"]["items"].as_array().unwrap();
    let outcome = |item: &str| {
        items
            .iter()
            .find(|i| i["item"] == item)
            .map(|i| i["outcome"].clone())
    };
    assert_eq!(outcome("ssh"), Some(serde_json::json!("applied")), "{data}");
    assert_eq!(
        outcome("git"),
        Some(serde_json::json!("not_applied")),
        "{data}"
    );
    assert!(
        std::fs::read_to_string(w.p())
            .unwrap()
            .contains("Host alpha")
    );
    assert_no_canary(&data.to_string());
}

/// ADR-0007 §12.22 item 10 (W3b-gaps): `RemoveProfile` works. It removes the
/// definition only (narrowing, no decision): new work naming the profile is refused
/// `NOT_FOUND`, every pinned snapshot stays, a replay returns the first result, a
/// second removal reports nothing removed, and a later definition of the same ID
/// continues after the highest pinned revision (never reusing one).
#[tokio::test]
async fn remove_profile_refuses_new_work_and_keeps_pinned_snapshots() {
    use heimdall_contract::request::{
        DeadlineIntent, EnsureRequest, RequiredCapabilities, WaitMode,
    };
    let w = World::new().await;
    let profile = ProfileId::parse("work").unwrap();
    let pair = |d: &str| AccessPairRef {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    };
    let upsert = |request: &str, pairs: Vec<AccessPairRef>| CatalogRequest::UpsertProfile {
        profile: ProfileSpec {
            id: profile.clone(),
            pairs: pairs.into_iter().collect(),
            label: None,
        },
        request_id: rid(request),
    };
    let remove = |request: &str| CatalogRequest::RemoveProfile {
        id: profile.clone(),
        request_id: rid(request),
    };
    w.catalog(&attended(), upsert("r-p1", vec![pair("dst-alpha")]))
        .await
        .unwrap();
    w.catalog(
        &attended(),
        upsert("r-p2", vec![pair("dst-alpha"), pair("dst-beta")]),
    )
    .await
    .unwrap();
    let ensure = |request: &str| EnsureRequest {
        profile: profile.clone(),
        profile_revision: None,
        scope: [pair("dst-alpha")].into_iter().collect(),
        environment: None,
        work_id: heimdall_contract::ids::WorkId::parse("w-profile").unwrap(),
        until: Some(DeadlineIntent::Absolute("2026-11-03T10:00:00Z".to_owned())),
        required_capabilities: RequiredCapabilities::default(),
        request_id: rid(request),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 2_000 },
    };
    let unknown_profile = |e: &OpError| {
        e.code == Code::NotFound && e.resource.as_ref().is_some_and(|r| r.kind == "profile")
    };
    let before = w.ops.ensure(&unattended(), ensure("r-ensure-before")).await;
    assert!(
        !before.as_ref().is_err_and(unknown_profile),
        "the profile resolves before its removal: {before:?}"
    );
    // Unattended: removal narrows and needs no decision.
    let removed = w.catalog(&unattended(), remove("r-rm")).await.unwrap();
    assert_eq!(removed["removed"], true, "{removed}");
    assert_eq!(removed["profile_id"], "work");
    assert!(w.decisions().is_empty());
    let replay = w.catalog(&unattended(), remove("r-rm")).await.unwrap();
    assert_eq!(replay, removed, "a replay returns the first result");
    let again = w.catalog(&unattended(), remove("r-rm-2")).await.unwrap();
    assert_eq!(again["removed"], false);
    let (current, s1, s2) = w
        .store
        .transaction(|tx| {
            Ok((
                tx.profile(&profile)?,
                tx.profile_snapshot(&profile, 1)?,
                tx.profile_snapshot(&profile, 2)?,
            ))
        })
        .unwrap();
    assert!(current.is_none());
    assert_eq!(s1.unwrap().scope.pairs.len(), 1, "revision 1 stays pinned");
    assert_eq!(s2.unwrap().scope.pairs.len(), 2, "revision 2 stays pinned");
    // New work naming the removed profile is refused.
    let after = w
        .ops
        .ensure(&unattended(), ensure("r-ensure-after"))
        .await
        .unwrap_err();
    assert!(unknown_profile(&after), "{after:?}");
    // Defined again with revision 1's content: a new revision 3, revision 1 unchanged.
    let r3 = w
        .catalog(&attended(), upsert("r-p3", vec![pair("dst-alpha")]))
        .await
        .unwrap();
    assert_eq!(r3["revision"], 3, "{r3}");
    let s1 = w
        .store
        .transaction(|tx| tx.profile_snapshot(&profile, 1))
        .unwrap()
        .unwrap();
    assert_eq!(s1.scope.pairs.len(), 1);
    w.events();
}

/// ADR-0007 §12.22 item 10 (W3b-gaps): the declaration's validity is
/// `Limits::declaration_validity` (`[setup] declaration_validity_days`), not a fixed
/// 30 days: the decision offers it, the approved declaration expires after it, and
/// eligibility lapses then.
#[tokio::test]
async fn declaration_validity_follows_the_configured_days() {
    use heimdall_contract::provider::InteractionKind;
    let days = Duration::from_secs(3 * 24 * 3600);
    let w = World::with(
        Arc::new(NoFaults),
        Limits {
            declaration_validity: days,
            ..Limits::default()
        },
    )
    .await;
    let identity = w.adopt("r-adopt").await;
    let endpoint = w.agent_endpoint();
    let (decision, _) = declare_op(&w, &identity, "r-declare").await;
    let expected: Timestamp = "2026-11-06T09:00:00Z".parse().unwrap();
    let record = w
        .store
        .transaction(|tx| tx.decision(&DecisionId::parse(&decision).unwrap()))
        .unwrap()
        .unwrap();
    match &record.kind {
        DecisionKind::DeclareInteraction { valid_until, .. } => {
            assert_eq!(*valid_until, expected);
        }
        other => panic!("{other:?}"),
    }
    w.decide(&decision, Verdict::Approve).await.unwrap();
    let declaration = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    assert_eq!(declaration.expires_at, expected);
    assert_eq!(
        eligibility_now(&w, &identity, &endpoint),
        InteractionKind::None
    );
    w.clock.advance(days + Duration::from_secs(1));
    assert_eq!(
        eligibility_now(&w, &identity, &endpoint),
        InteractionKind::Unknown,
        "lapsed after the configured validity"
    );
}

/// m02-plan U5 and ADR-0007 §12.22 item 10 (W3b-gaps): a stored receipt the writer
/// cannot read (`ReconcileError::UnreadableReceipt`: a file receipt naming a step the
/// intent does not have) leaves the setup operation unresolved and untouched, and it
/// is reported in `runtime_lifecycle` (`phase: unresolved`, reason
/// `unreadable_receipts`). Nothing is re-applied or settled, no file changes, and the
/// operation still blocks setup. A crash inside the first apply (an in-process unwind)
/// gives the receipts.
#[tokio::test]
async fn unreadable_receipt_leaves_setup_unresolved_and_reported() {
    use heimdall_domain::operation::{FilePhase, LocalReceipt};
    let mut w = World::new().await;
    w.catalog_alpha().await;
    let (op, decision) = apply_waiting(&w, "r-crash").await;
    let intent = w.intent(&op);
    let commit = intent.files.iter().position(|s| s.commit).unwrap();
    w.hook.crash_at(
        ReplacePoint::AfterExchange,
        Some(u16::try_from(commit).unwrap()),
    );
    let _ = w.decide(&decision, Verdict::Approve).await;
    assert_eq!(w.op(&op).state, OperationState::Running);
    // A receipt naming a step the intent does not have (as from an incompatible
    // build): copied from a real file receipt, its step moved out of range.
    let mut bogus = w
        .receipts(&op)
        .into_iter()
        .rev()
        .find(|r| matches!(r.local, Some(LocalReceipt::File { .. })))
        .unwrap();
    bogus.local = Some(LocalReceipt::File {
        step: 999,
        phase: FilePhase::Exchanged,
    });
    w.store
        .transaction(|tx| tx.append_stage_receipt(&op, &bogus))
        .unwrap();
    let receipts = w.receipts(&op).len();
    let tree = w.tree();
    let lifecycle_before = unresolved_reports(&w, &op).len();
    w.restart().await;
    assert_eq!(
        w.writer.applies.load(Ordering::SeqCst),
        0,
        "never re-applied"
    );
    assert!(w.writer.reconciles.load(Ordering::SeqCst) >= 1);
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Running, "{:?}", rec.result);
    assert_eq!(w.receipts(&op).len(), receipts, "nothing recorded");
    assert_eq!(w.tree(), tree, "no file moved");
    let reports = unresolved_reports(&w, &op);
    assert_eq!(reports.len(), lifecycle_before + 1, "{reports:?}");
    let last = reports.last().unwrap();
    assert_eq!(last["reason"], "unreadable_receipts", "{last}");
    assert_eq!(last["state"], "running");
    assert_eq!(open_setups(&w), vec![op.clone()], "it still blocks setup");
    // A replay reports it in progress, never as settled.
    let e = w
        .effect(&attended(), "apply", &intent.plan_digest, "r-crash")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Accepted, "{e:?}");
    assert_eq!(e.operation_id, Some(op));
}

/// The `runtime_lifecycle` reports that leave `op` unresolved.
fn unresolved_reports(w: &World, op: &OperationId) -> Vec<serde_json::Value> {
    w.events()
        .into_iter()
        .filter(|e| e.event.event_type == heimdall_contract::event::EventType::RuntimeLifecycle)
        .map(|e| e.event.payload)
        .filter(|p| p["phase"] == "unresolved" && p["operation_id"] == op.to_string())
        .collect()
}

/// ADR-0007 §12.22 item 10 (W3b-gaps), m02-plan U5: `RemoveDestination` changes no
/// file. The projection is stale (its record still names the alias) until the next
/// `setup apply`, whose preview shows the removal and whose apply removes the alias.
#[tokio::test]
async fn remove_destination_marks_projection_stale_and_changes_no_file() {
    let w = World::new().await;
    let identity = w.catalog_alpha().await;
    w.destination("r-dest-beta", "dst-beta", "beta", &identity)
        .await;
    let (op, _) = w.apply_approved("r-apply").await;
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let p = std::fs::read_to_string(w.p()).unwrap();
    assert!(p.contains("Host alpha") && p.contains("Host beta"), "{p}");
    let tree = w.tree();
    let unchanged = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let removed = w
        .catalog(
            &unattended(),
            CatalogRequest::RemoveDestination {
                id: DestinationId::parse("dst-beta").unwrap(),
                request_id: rid("r-rm-beta"),
            },
        )
        .await
        .unwrap();
    assert_eq!(removed["removed"], true, "{removed}");
    assert_eq!(removed["destination_id"], "dst-beta");
    assert_eq!(w.tree(), tree, "no file changed");
    assert!(w.decisions().is_empty(), "no decision");
    let again = w
        .catalog(
            &unattended(),
            CatalogRequest::RemoveDestination {
                id: DestinationId::parse("dst-beta").unwrap(),
                request_id: rid("r-rm-beta-2"),
            },
        )
        .await
        .unwrap();
    assert_eq!(again["removed"], false);
    // Stale: the projection record still names beta; the destination is gone.
    let record = w.record().unwrap();
    let ssh = record.items.get(&ProjectionItem::Ssh).unwrap();
    assert!(ssh.aliases.iter().any(|a| a == "beta"), "{:?}", ssh.aliases);
    assert!(
        w.store
            .transaction(|tx| tx.destination_by_alias("beta"))
            .unwrap()
            .is_none()
    );
    // The next apply's preview shows the removal.
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    assert_ne!(plan.plan_digest, unchanged.plan_digest);
    assert!(
        plan.files
            .iter()
            .any(|f| f.before_sha256 != f.after_sha256 && f.diff.contains("beta")),
        "{:?}",
        plan.files
    );
    // Applying it removes the alias from P, and only then.
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-apply-2")
        .await;
    if let Err(e) = &e {
        assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
        w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
            .await
            .unwrap();
    }
    let p = std::fs::read_to_string(w.p()).unwrap();
    assert!(p.contains("Host alpha") && !p.contains("Host beta"), "{p}");
    let record = w.record().unwrap();
    let ssh = record.items.get(&ProjectionItem::Ssh).unwrap();
    assert!(
        !ssh.aliases.iter().any(|a| a == "beta"),
        "{:?}",
        ssh.aliases
    );
}
