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
//!
//! The file runs natively on Unix and on Windows (wave 6x, WU-3). Where a fixture is
//! platform-shaped it has the faithful form of each platform: the owner is the account's
//! uid or SID, an agent endpoint is a socket path or a named pipe, a file's identity is
//! its inode or its volume serial and file ID, and a private file is mode 0600 or an
//! owner-only DACL.
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

/// The principal of the scratch owner: a fixed uid on Unix (the writer never compares
/// the caller's uid with a file owner here), and on Windows the account's own SID, as the
/// runtime names a client of this account (`PrincipalRef::WindowsUser`).
fn owner_principal() -> PrincipalRef {
    #[cfg(unix)]
    {
        PrincipalRef::UnixUser { uid: 501 }
    }
    #[cfg(windows)]
    {
        PrincipalRef::WindowsUser {
            sid: heimdall_ipc::windows::current_user_sid().unwrap(),
        }
    }
}

fn owner_ctx() -> CallerContext {
    CallerContext {
        principal: owner_principal(),
        role: ClientRole::Owner,
    }
}

/// The kind of an agent endpoint on this platform.
fn agent_kind() -> EndpointKind {
    if cfg!(windows) {
        EndpointKind::NamedPipe
    } else {
        EndpointKind::UnixSocket
    }
}

/// The locator of a scratch agent named `name` under `root`: a socket path
/// `<root>/<name>.sock` on Unix, a named pipe `\\.\pipe\hm-<scratch dir>-<name>` on
/// Windows. Nothing listens on it and no test connects to it.
fn agent_locator_at(root: &Path, name: &str) -> String {
    if cfg!(windows) {
        format!(
            r"\\.\pipe\hm-{}-{name}",
            root.file_name().unwrap().to_string_lossy()
        )
    } else {
        root.join(format!("{name}.sock")).display().to_string()
    }
}

fn agent_endpoint_at(root: &Path, name: &str) -> EndpointRef {
    EndpointRef {
        kind: agent_kind(),
        locator: agent_locator_at(root, name),
    }
}

/// What names one file object on this platform: its inode (Unix), or its volume serial
/// and 128-bit file ID read from an open handle (Windows; `std` exposes no stable
/// accessor, so this is the workspace's own `sys::handle_identity`).
#[cfg(unix)]
type FileId = u64;
#[cfg(windows)]
type FileId = heimdall_domain::projection::FileIdentity;

#[cfg(unix)]
fn file_id(_path: &Path, meta: &std::fs::Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt as _;
    meta.ino()
}

#[cfg(windows)]
fn file_id(path: &Path, _meta: &std::fs::Metadata) -> FileId {
    let file = std::fs::File::open(path).unwrap();
    heimdall_localenv::sys::handle_identity(&file).unwrap()
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
        principal: owner_principal(),
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
    /// ADR-0007 §12.23 item 1: the next `reconcile` stops at its entry, before the
    /// inner writer runs, until released ([`Counting::pause_next_reconcile`]).
    pause_reconcile: Mutex<Option<Pause>>,
}

/// One paused writer call: `entered` is set when the call reaches the pause; the call
/// continues when the sender of `release` sends or is dropped (or after 30 s, so an
/// abandoned test never hangs the blocking pool).
struct Pause {
    entered: Arc<std::sync::atomic::AtomicBool>,
    release: std::sync::mpsc::Receiver<()>,
}

impl Counting {
    /// Pause the next `reconcile` at its entry. Returns the flag it sets when it is
    /// paused and the sender that releases it.
    fn pause_next_reconcile(
        &self,
    ) -> (
        Arc<std::sync::atomic::AtomicBool>,
        std::sync::mpsc::Sender<()>,
    ) {
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        *self
            .pause_reconcile
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Pause {
            entered: entered.clone(),
            release: rx,
        });
        (entered, tx)
    }
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
        let pause = self
            .pause_reconcile
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(p) = pause {
            p.entered.store(true, Ordering::SeqCst);
            let _ = p.release.recv_timeout(Duration::from_secs(30));
        }
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
        // The snapshot of an original user file is the writer's (ADR-0007 §12.32 item 2):
        // the state directory is the scratch one.
        let mut c = ProjectionConfig::new(paths, Platform::current(), home.config_dir.clone())
            .with_state_dir(home.state_dir.clone());
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
            pause_reconcile: Mutex::new(None),
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
        agent_endpoint_at(&self.home.root, "fixture-agent")
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
    fn tree(&self) -> BTreeMap<String, (FileId, Vec<u8>)> {
        fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, (FileId, Vec<u8>)>) {
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
                    out.insert(
                        name,
                        (file_id(&p, &meta), std::fs::read(&p).unwrap_or_default()),
                    );
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
    assert!(
        !w.home.state_dir.join("backups").exists(),
        "a stale plan takes no snapshot"
    );

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
    assert!(
        !w.home.state_dir.join("backups").exists(),
        "a refused apply takes no snapshot either"
    );
}

/// The file is private to its owner. Unix: mode 0600. Windows: the protected owner-only
/// DACL `D:P(A;;FA;;;<own SID>)` that `sys::create_owner_only_exclusive` sets (full
/// control for the account and nobody else, no inherited entry), read back with the
/// in-box `icacls /save` (SDDL, one SID per entry; no principal name is printed).
/// `scratch` is a directory the check may write its temporary ACL listing into.
fn assert_private_to_owner(file: &Path, scratch: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = scratch;
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[cfg(windows)]
    {
        let sddl = dacl_sddl(file, scratch);
        let sid = heimdall_ipc::windows::current_user_sid().unwrap();
        assert_eq!(
            sddl,
            format!("D:P(A;;FA;;;{sid})"),
            "the file's DACL is not the owner-only form"
        );
    }
}

/// The DACL of `file` as SDDL (`D:…`), through `icacls <file> /save <list>`. The list
/// is UTF-16 text: the file name, then the descriptor.
#[cfg(windows)]
fn dacl_sddl(file: &Path, scratch: &Path) -> String {
    let list = scratch.join(format!(
        "acl-{}.txt",
        heimdall_app::ids::random_u64().unwrap()
    ));
    let icacls = Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
        .join("System32")
        .join("icacls.exe");
    let out = std::process::Command::new(icacls)
        .arg(file)
        .arg("/save")
        .arg(&list)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "icacls /save failed: {:?}",
        out.status
    );
    let raw = std::fs::read(&list).unwrap();
    std::fs::remove_file(&list).unwrap();
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let sddl: Vec<&str> = text
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}').trim())
        .filter(|l| l.starts_with("D:"))
        .collect();
    assert_eq!(sddl.len(), 1, "icacls listed one descriptor");
    sddl[0].to_owned()
}

/// The snapshots under `<state>/backups` whose name starts with `name.`, sorted.
fn snapshots_of(w: &World, name: &str) -> Vec<PathBuf> {
    let prefix = format!("{name}.");
    let mut found: Vec<PathBuf> = std::fs::read_dir(w.home.state_dir.join("backups"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// ADR-0007 §5.5 "Snapshots", §12.32 item 2 (Q-W5): the snapshot of the original user
/// file is the writer's, so an apply submitted through `Operations` alone (no CLI, no
/// TUI: the caller of every other client) copies the original to
/// `<state>/backups/ssh_config.<UTC timestamp>.orig` (0600, the original bytes) before
/// the first edit; a preview takes none; a rollback, which edits the file again, keeps
/// the first copy and adds none.
#[tokio::test]
async fn apply_through_operations_snapshots_the_original_user_file() {
    let w = World::new().await;
    w.catalog_alpha().await;
    let original: &[u8] = b"Host other\n    User fixture\n";
    std::fs::write(w.user(), original).unwrap();
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    assert!(
        snapshots_of(&w, "ssh_config").is_empty(),
        "a preview takes no snapshot"
    );
    let e = w
        .effect(&attended(), "apply", &plan.plan_digest, "r-snapshot")
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::ApprovalRequired, "{e:?}");
    assert!(
        snapshots_of(&w, "ssh_config").is_empty(),
        "nothing is copied while the decision is pending"
    );
    let op = e.operation_id.clone().unwrap();
    w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
        .await
        .unwrap();
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    let taken = snapshots_of(&w, "ssh_config");
    assert_eq!(taken.len(), 1, "{taken:?}");
    let name = taken[0].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.ends_with("Z.orig") && name.len() == "ssh_config.20261103T090807Z.orig".len(),
        "{name}"
    );
    assert_eq!(std::fs::read(&taken[0]).unwrap(), original);
    assert_private_to_owner(&taken[0], &w.home.root);
    assert_ne!(
        std::fs::read(w.user()).unwrap(),
        original,
        "the apply edited the user file after the copy"
    );
    // A rollback edits the user file again and keeps the first original.
    let rollback = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    w.effect(
        &attended(),
        "rollback",
        &rollback.plan_digest,
        "r-snapshot-rb",
    )
    .await
    .unwrap();
    assert_eq!(snapshots_of(&w, "ssh_config"), taken, "no second snapshot");
    assert_eq!(std::fs::read(&taken[0]).unwrap(), original);
}

/// The runtime's writer, but every preview carries `pad` more bytes of diff: the real
/// writer emits a diff beyond `MAX_DIFF_BYTES` only for a plan of a few hundred aliases.
struct Padded {
    inner: Arc<dyn ProjectionWriter>,
    pad: usize,
}

impl ProjectionWriter for Padded {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        let mut plan = self.inner.preview(spec, intent)?;
        let extra = format!("+{}\n", "x".repeat(self.pad.saturating_sub(2)));
        if let Some(f) = plan.view.files.first_mut() {
            f.diff.push_str(&extra);
        }
        if let Some(s) = plan.summary.as_mut() {
            s.diff_text.push_str(&extra);
        }
        Ok(plan)
    }
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.inner.apply(intent, sink)
    }
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
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

/// ADR-0007 §12.32 item 5: a plan whose full diff exceeds `MAX_DIFF_BYTES` is refused,
/// never cut. The preview, and an apply naming a digest the preview showed before the
/// diff outgrew the bound, answer `CAPABILITY_UNAVAILABLE` with reason `plan_too_large`
/// and effect `none` before anything is journaled, decided, written or copied: no
/// operation, decision, event or idempotency row, and no file. (The boundary itself, one
/// byte either way, is `setup::tests::a_diff_is_refused_one_byte_over_the_bound_and_never_cut`.)
#[tokio::test]
async fn a_plan_whose_full_diff_exceeds_the_bound_is_refused_before_anything_is_journaled() {
    use heimdall_contract::setup::MAX_DIFF_BYTES;
    let mut w = World::new().await;
    w.catalog_alpha().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let fitting = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let whole: usize = fitting.files.iter().map(|f| f.diff.len()).sum();
    assert!(whole > 0 && whole < MAX_DIFF_BYTES, "{whole}");
    let counts = |w: &World| w.store.transaction(|tx| tx.table_counts()).unwrap();
    // One byte over the bound in total: refused.
    let inner: Arc<dyn ProjectionWriter> = w.writer.clone();
    let padded: Arc<dyn ProjectionWriter> = Arc::new(Padded {
        inner,
        pad: MAX_DIFF_BYTES - whole + 1,
    });
    w.ops = Operations::start(OperationsConfig {
        projection: Some(padded),
        ..World::config_of(&w.store, &w.clock, &w.sync, &w.writer, w.limits)
    })
    .await
    .unwrap();
    let before_rows = counts(&w);
    let before_tree = w.tree();
    let refused = |e: &OpError| {
        assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
        assert_eq!(e.reason.as_deref(), Some(reason::PLAN_TOO_LARGE), "{e:?}");
        assert_eq!(e.effect_status, EffectStatus::None, "{e:?}");
        assert!(e.operation_id.is_none(), "nothing is admitted: {e:?}");
        assert!(e.message.contains("never shown cut"), "{}", e.message);
    };
    let e = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap_err();
    refused(&e);
    let e = w
        .effect(&attended(), "apply", &fitting.plan_digest, "r-too-large")
        .await
        .unwrap_err();
    refused(&e);
    assert_eq!(counts(&w), before_rows, "nothing was journaled");
    assert!(w.decisions().is_empty());
    assert_eq!(w.tree(), before_tree, "nothing was written");
    assert!(!w.home.state_dir.join("backups").exists());
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), 0);
}

/// The runtime's writer, but the first file of a plan with `role` carries `pad` more bytes
/// of diff (and of the writer's summary text): a file the real writer would never show
/// that large, in the place the bound is applied.
struct PaddedFile {
    inner: Arc<dyn ProjectionWriter>,
    role: heimdall_contract::setup::ProjectionFileRole,
    pad: usize,
}

impl ProjectionWriter for PaddedFile {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        let mut plan = self.inner.preview(spec, intent)?;
        let extra = format!("-{}\n", "x".repeat(self.pad.saturating_sub(2)));
        if let Some(f) = plan.view.files.iter_mut().find(|f| f.role == self.role) {
            f.diff.push_str(&extra);
        }
        if let Some(s) = plan.summary.as_mut() {
            s.diff_text.push_str(&extra);
        }
        Ok(plan)
    }
    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        self.inner.apply(intent, sink)
    }
    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
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

impl World {
    /// `count` more managed aliases `<prefix>000..` with long host names, on `identity`.
    async fn long_aliases(&self, identity: &IdentityId, prefix: &str, count: usize) {
        let label = "a".repeat(60);
        for i in 0..count {
            let alias = format!("{prefix}{i:03}");
            self.catalog(
                &attended(),
                CatalogRequest::UpsertDestination {
                    destination: DestinationSpec {
                        id: DestinationId::parse(&format!("dst-{alias}")).unwrap(),
                        alias: alias.clone(),
                        definition: DestinationDefinitionSpec::Managed {
                            hostname: format!("{label}.{label}.{label}.{alias}.example.invalid"),
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
    }

    /// A World whose P is far over `MAX_DIFF_BYTES` although no single apply's diff was
    /// (three applies of 80 long aliases each, every one approved): the way P gets past the
    /// bound is growth in steps. Returns the owner's original user file.
    async fn with_a_p_well_over_the_bound() -> (World, Vec<u8>) {
        use heimdall_contract::setup::MAX_DIFF_BYTES;
        let w = World::new().await;
        std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
        let original = std::fs::read(w.user()).unwrap();
        let identity = w.adopt("r-adopt-big").await;
        for (n, prefix) in ["a", "b", "c"].into_iter().enumerate() {
            w.long_aliases(&identity, prefix, 80).await;
            let (op, _) = w.apply_approved(&format!("r-apply-big-{n}")).await;
            assert_eq!(w.op(&op).state, OperationState::Succeeded);
        }
        let p = std::fs::metadata(w.p()).unwrap().len();
        assert!(
            usize::try_from(p).unwrap() > MAX_DIFF_BYTES + MAX_DIFF_BYTES / 4,
            "P is {p} bytes"
        );
        (w, original)
    }
}

fn rollback_ssh() -> PreviewIntent {
    PreviewIntent::Rollback {
        keep_key_files: false,
        items: [ProjectionItem::Ssh].into_iter().collect(),
    }
}

/// ADR-0007 §12.34 item 7: a rollback is never blocked by the size of what Heimdall wrote.
/// P is well over `MAX_DIFF_BYTES` (it grew past it across approved applies); the rollback
/// is previewed with P and the key file as one summary line each (name, line count,
/// SHA-256 of the removed content) and the owner's file change whole, within the bound,
/// and applies: the user file is back to its original bytes, the record is empty and the
/// files of Heimdall's own are handed to the cleaner.
#[tokio::test]
async fn a_rollback_of_a_p_well_over_the_bound_is_previewed_and_applied() {
    use heimdall_contract::setup::{MAX_DIFF_BYTES, ProjectionFileRole as Role};
    use heimdall_localenv::projection::plan::OwnRemoval;
    let (w, original) = World::with_a_p_well_over_the_bound().await;
    let p_bytes = std::fs::read(w.p()).unwrap();
    let plan = w.preview(rollback_ssh()).await.unwrap();
    let diff_of = |role: Role| -> Vec<String> {
        plan.files
            .iter()
            .filter(|f| f.role == role)
            .map(|f| f.diff.clone())
            .collect()
    };
    assert_eq!(
        diff_of(Role::ManagedSsh),
        [OwnRemoval::of("ssh_config", &p_bytes).to_string()],
        "P is one summary line"
    );
    let keys = diff_of(Role::KeyFile);
    assert_eq!(keys.len(), 1, "the one key file: {keys:?}");
    assert!(OwnRemoval::parse(keys[0].trim_end()).is_some(), "{keys:?}");
    let user = diff_of(Role::UserSsh);
    assert_eq!(user.len(), 1);
    assert!(
        user[0].contains("-# >>> heimdall managed include")
            && user[0].lines().all(|l| l.starts_with('-')),
        "the owner's file is whole: {}",
        user[0]
    );
    let shown: usize = plan.files.iter().map(|f| f.diff.len()).sum();
    assert!(shown < MAX_DIFF_BYTES, "{shown}");
    assert!(
        p_bytes.len() > 2 * shown,
        "P alone was far more than all of it"
    );
    let done = w
        .effect(
            &unattended(),
            "rollback",
            &plan.plan_digest,
            "r-rollback-big",
        )
        .await
        .unwrap();
    assert_eq!(done["__code"], serde_json::json!("OK"), "{done}");
    assert_eq!(std::fs::read(w.user()).unwrap(), original, "byte-for-byte");
    let record = w.record().unwrap();
    let ssh = &record.items[&ProjectionItem::Ssh];
    assert!(ssh.files.is_empty() && ssh.aliases.is_empty(), "{ssh:?}");
    let resources = w
        .store
        .transaction(|tx| tx.projection_resources(&env_id()))
        .unwrap();
    assert!(!resources.is_empty());
    assert!(resources.iter().all(|r| r.desired == ResourceState::Absent));
}

/// ADR-0007 §12.34 item 7: only the changes to the owner's files count toward the bound.
/// A rollback whose owner-file change is one byte past `MAX_DIFF_BYTES` is still refused
/// (`plan_too_large`, effect `none`, before anything is journaled or written), the preview
/// and an apply of a plan previewed before alike; the same change at exactly the bound
/// fits and applies, although the summary lines of the files of Heimdall's own that the
/// rollback removes (P, the key file) are beside it: they do not count.
#[tokio::test]
async fn a_rollback_is_refused_for_its_owner_file_change_alone() {
    use heimdall_contract::setup::{MAX_DIFF_BYTES, ProjectionFileRole as Role};
    let mut w = World::new().await;
    w.catalog_alpha().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let original = std::fs::read(w.user()).unwrap();
    w.apply_approved("r-apply").await;
    let fitting = w.preview(rollback_ssh()).await.unwrap();
    let user_len: usize = fitting
        .files
        .iter()
        .filter(|f| f.role == Role::UserSsh)
        .map(|f| f.diff.len())
        .sum();
    let beside: usize = fitting
        .files
        .iter()
        .filter(|f| f.role != Role::UserSsh)
        .map(|f| f.diff.len())
        .sum();
    assert!(user_len > 0 && beside > 0, "{user_len} {beside}");
    // The owner's change plus `extra` more bytes of it.
    let restart = |w: &World, extra: usize| {
        let padded: Arc<dyn ProjectionWriter> = Arc::new(PaddedFile {
            inner: w.writer.clone(),
            role: Role::UserSsh,
            pad: extra,
        });
        OperationsConfig {
            projection: Some(padded),
            ..World::config_of(&w.store, &w.clock, &w.sync, &w.writer, w.limits)
        }
    };
    // One byte past the bound: refused, nothing journaled or written.
    w.ops = Operations::start(restart(&w, MAX_DIFF_BYTES - user_len + 1))
        .await
        .unwrap();
    let counts = |w: &World| w.store.transaction(|tx| tx.table_counts()).unwrap();
    let (rows, tree) = (counts(&w), w.tree());
    let refused = |e: &OpError| {
        assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
        assert_eq!(e.reason.as_deref(), Some(reason::PLAN_TOO_LARGE), "{e:?}");
        assert_eq!(e.effect_status, EffectStatus::None, "{e:?}");
        assert!(e.operation_id.is_none(), "nothing is admitted: {e:?}");
    };
    refused(&w.preview(rollback_ssh()).await.unwrap_err());
    refused(
        &w.effect(
            &unattended(),
            "rollback",
            &fitting.plan_digest,
            "r-rollback-owner",
        )
        .await
        .unwrap_err(),
    );
    assert_eq!(counts(&w), rows, "nothing was journaled");
    assert_eq!(w.tree(), tree, "nothing was written");
    // Exactly the bound: the owner's change alone fills it, with the removals' summary
    // lines beside it (`beside` bytes that would not fit if they counted).
    w.ops = Operations::start(restart(&w, MAX_DIFF_BYTES - user_len))
        .await
        .unwrap();
    let plan = w.preview(rollback_ssh()).await.unwrap();
    let total: usize = plan.files.iter().map(|f| f.diff.len()).sum();
    assert_eq!(
        total,
        MAX_DIFF_BYTES + beside,
        "the bound plus the summaries"
    );
    let done = w
        .effect(
            &unattended(),
            "rollback",
            &plan.plan_digest,
            "r-rollback-fits",
        )
        .await
        .unwrap();
    assert_eq!(done["__code"], serde_json::json!("OK"), "{done}");
    assert_eq!(std::fs::read(w.user()).unwrap(), original, "byte-for-byte");
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
        agent_locator_at(&w.home.root, "other-agent")
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
    let moved = agent_endpoint_at(&w.home.root, "moved-agent");
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
                    endpoint: agent_endpoint_at(&w.home.root, "elsewhere"),
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

/// ADR-0007 §12.24 item 1: `inspect destinations` lists the catalog, under `items`,
/// with no `NOT_LISTED` warning: each destination with its ID, alias and definition
/// (`managed`, with the rendered fields, or `observed`). An alias rename keeps the ID,
/// a removed destination leaves the list, and a caller that is not the owner lists
/// nothing.
#[tokio::test]
async fn inspect_destinations_lists_the_catalog_with_alias_and_definition() {
    use heimdall_contract::request::{InspectRequest, InspectSubject};
    let w = World::new().await;
    let identity = w.catalog_alpha().await;
    w.catalog(
        &attended(),
        CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-user").unwrap(),
                alias: "user-host".to_owned(),
                definition: DestinationDefinitionSpec::Observed,
                label: Some("defined by the user".to_owned()),
            },
            request_id: rid("r-dest-user"),
        },
    )
    .await
    .unwrap();
    let list = |caller: Caller| {
        let ops = w.ops.clone();
        async move {
            let r = ops
                .inspect(
                    &caller,
                    InspectRequest {
                        subject: InspectSubject::Destinations,
                        preview: None,
                    },
                )
                .await
                .unwrap();
            assert!(r.warnings.is_empty(), "{:?}", r.warnings);
            assert_no_canary(&r.data.to_string());
            r.data["items"].as_array().unwrap().clone()
        }
    };
    let items = list(attended()).await;
    assert_eq!(items.len(), 2, "{items:?}");
    let by_alias = |items: &[serde_json::Value], alias: &str| {
        items.iter().find(|i| i["alias"] == alias).cloned()
    };
    let alpha = by_alias(&items, "alpha").unwrap();
    assert_eq!(alpha["destination_id"], "dst-alpha");
    assert_eq!(alpha["definition"], "managed");
    assert_eq!(alpha["hostname"], "alpha.example.invalid");
    assert_eq!(alpha["account"], "fixture");
    assert_eq!(alpha["identity_id"], serde_json::json!(identity));
    assert_eq!(alpha["revision"], 1);
    let user = by_alias(&items, "user-host").unwrap();
    assert_eq!(user["destination_id"], "dst-user");
    assert_eq!(user["definition"], "observed");
    assert_eq!(user["label"], "defined by the user");
    assert!(user.get("hostname").is_none(), "{user}");
    assert!(user.get("identity_id").is_none(), "{user}");

    // A rename keeps the ID; a removal leaves the list.
    w.catalog(
        &attended(),
        CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-user").unwrap(),
                alias: "user-host-2".to_owned(),
                definition: DestinationDefinitionSpec::Observed,
                label: None,
            },
            request_id: rid("r-dest-user-2"),
        },
    )
    .await
    .unwrap();
    w.catalog(
        &attended(),
        CatalogRequest::RemoveDestination {
            id: DestinationId::parse("dst-alpha").unwrap(),
            request_id: rid("r-dest-alpha-gone"),
        },
    )
    .await
    .unwrap();
    let items = list(unattended()).await;
    assert_eq!(items.len(), 1, "{items:?}");
    let renamed = by_alias(&items, "user-host-2").unwrap();
    assert_eq!(renamed["destination_id"], "dst-user");
    assert_eq!(renamed["revision"], 2);
    assert!(by_alias(&items, "alpha").is_none());
    // Not the owner: nothing is listed.
    assert!(list(limited()).await.is_empty());
}

/// ADR-0007 §12.24 item 1: `inspect profiles` lists the catalog's current profile
/// definitions under `items`, with no `NOT_LISTED` warning: each with its ID, revision,
/// label, pairs and capabilities. A new revision replaces the listed one, a removed
/// definition leaves the list, and a caller that is not the owner lists nothing.
#[tokio::test]
async fn inspect_profiles_lists_the_catalog_definitions() {
    use heimdall_contract::request::{InspectRequest, InspectSubject};
    let w = World::new().await;
    let list = |caller: Caller| {
        let ops = w.ops.clone();
        async move {
            let r = ops
                .inspect(
                    &caller,
                    InspectRequest {
                        subject: InspectSubject::Profiles,
                        preview: None,
                    },
                )
                .await
                .unwrap();
            assert!(r.warnings.is_empty(), "{:?}", r.warnings);
            assert_no_canary(&r.data.to_string());
            r.data["items"].as_array().unwrap().clone()
        }
    };
    let find = |items: &[serde_json::Value], id: &str| {
        items.iter().find(|i| i["profile_id"] == id).cloned()
    };
    let pair = |d: &str| AccessPairRef {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    };
    let upsert = |request: &str, pairs: Vec<AccessPairRef>, label: Option<&str>| {
        CatalogRequest::UpsertProfile {
            profile: ProfileSpec {
                id: ProfileId::parse("listed").unwrap(),
                pairs: pairs.into_iter().collect(),
                label: label.map(str::to_owned),
            },
            request_id: rid(request),
        }
    };
    let baseline = list(attended()).await.len();
    assert!(find(&list(attended()).await, "listed").is_none());
    w.catalog(
        &attended(),
        upsert("r-lp1", vec![pair("dst-alpha")], Some("listed profile")),
    )
    .await
    .unwrap();
    let items = list(attended()).await;
    assert_eq!(items.len(), baseline + 1, "{items:?}");
    let p = find(&items, "listed").unwrap();
    assert_eq!(p["revision"], 1);
    assert_eq!(p["label"], "listed profile");
    assert_eq!(p["pairs"].as_array().unwrap().len(), 1, "{p}");
    assert!(p["capabilities"].is_array(), "{p}");

    // A new revision replaces the listed definition.
    w.catalog(
        &attended(),
        upsert("r-lp2", vec![pair("dst-alpha"), pair("dst-beta")], None),
    )
    .await
    .unwrap();
    let items = list(unattended()).await;
    assert_eq!(items.len(), baseline + 1, "{items:?}");
    let p = find(&items, "listed").unwrap();
    assert_eq!(p["revision"], 2);
    assert_eq!(p["pairs"].as_array().unwrap().len(), 2, "{p}");
    // Not the owner: nothing is listed.
    assert!(list(limited()).await.is_empty());
    // A removed definition leaves the list.
    w.catalog(
        &attended(),
        CatalogRequest::RemoveProfile {
            id: ProfileId::parse("listed").unwrap(),
            request_id: rid("r-lp-rm"),
        },
    )
    .await
    .unwrap();
    let items = list(attended()).await;
    assert_eq!(items.len(), baseline, "{items:?}");
    assert!(find(&items, "listed").is_none());
}

/// Move the authority generation (an environment write, ADR-0006 §13.7 item 5): every
/// pending decision issued before it is stale at completion.
fn move_generation(w: &World) {
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    w.store
        .transaction(|tx| {
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: heimdall_contract::ids::DeviceId::from_random_bytes([0x5f; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: false,
                    managed_signing: false,
                    issuer_access: false,
                },
            })
        })
        .unwrap();
}

/// ADR-0007 §12.24 item 8: a catalog `DeclareInteraction` whose decision went stale
/// (the authority generation moved, so completing it is `DECISION_STALE` and the record
/// is `stale`) is reissued as the setup driver does. The replay of the request answers
/// with a fresh pending record bound to the identity's **current** fingerprint and
/// endpoint (the identity moved meanwhile), at the current generation; approving it
/// writes the declaration from it.
#[tokio::test]
async fn stale_declaration_decision_is_reissued_bound_to_the_current_identity() {
    let w = World::new().await;
    let identity = w.adopt("r-adopt").await;
    let (first, op) = declare_op(&w, &identity, "r-declare").await;
    let stored = w
        .store
        .transaction(|tx| tx.identity(&identity))
        .unwrap()
        .unwrap();
    let moved = agent_endpoint_at(&w.home.root, "moved");
    w.catalog(
        &attended(),
        CatalogRequest::AdoptIdentity {
            identity: IdentitySpec {
                source: IdentitySourceSpec::NativeAgent {
                    endpoint: moved.clone(),
                },
                public_key: stored.public_key.clone(),
                label: None,
            },
            request_id: rid("r-move"),
        },
    )
    .await
    .unwrap();
    move_generation(&w);
    let e = w.decide(&first, Verdict::Approve).await.unwrap_err();
    assert_eq!(e.code, Code::DecisionStale, "{e:?}");
    assert_eq!(w.op(&op).state, OperationState::AwaitingApproval);
    assert!(
        w.decisions().iter().all(|d| d.id.as_str() != first),
        "the first record left pending"
    );

    // The replay reissues: a fresh record, bound to the identity as it is now.
    let replay = w
        .catalog(
            &unattended(),
            CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: rid("r-declare"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(replay.code, Code::InteractionRequired, "{replay:?}");
    assert_eq!(replay.operation_id.as_ref(), Some(&op));
    let fresh = replay.next.decision_ref.clone().unwrap();
    assert_ne!(fresh, first);
    let record = w
        .decisions()
        .into_iter()
        .find(|d| d.id.as_str() == fresh)
        .unwrap();
    let current = w.store.transaction(|tx| tx.authority_generation()).unwrap();
    assert_eq!(record.generation, current);
    let DecisionKind::DeclareInteraction {
        operation,
        identity: named,
        fingerprint,
        endpoint,
        interaction,
        ..
    } = &record.kind
    else {
        panic!("{record:?}")
    };
    assert_eq!(operation, &op);
    assert_eq!(named, &identity);
    assert_eq!(fingerprint, &stored.fingerprint);
    assert_eq!(endpoint, &moved, "bound to the current endpoint");
    assert_eq!(*interaction, DeclaredInteraction::None);
    let naming = w
        .decisions()
        .iter()
        .filter(|d| matches!(&d.kind, DecisionKind::DeclareInteraction { operation, .. } if *operation == op))
        .count();
    assert_eq!(naming, 1, "exactly one pending record names the operation");
    // A second replay answers the same fresh record (no further reissue).
    let again = w
        .catalog(
            &unattended(),
            CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: rid("r-declare"),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(again.next.decision_ref.as_deref(), Some(fresh.as_str()));

    // Approving it writes the declaration from it.
    w.decide(&fresh, Verdict::Approve).await.unwrap();
    let rec = w.op(&op);
    assert_eq!(rec.state, OperationState::Succeeded, "{:?}", rec.result);
    let decl = w
        .store
        .transaction(|tx| tx.interaction_declaration(&identity))
        .unwrap()
        .unwrap();
    assert_eq!(decl.endpoint, moved);
    assert_eq!(decl.fingerprint, stored.fingerprint);
    assert_eq!(decl.decision.as_str(), fresh);
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
                        endpoint: agent_endpoint_at(&home.root, "a"),
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

/// Poll `f` every 5 ms until it holds; fails after 10 s.
async fn until(what: &str, f: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The repair the driver is running for `h` (the open setup operation that is not
/// the held one).
fn running_repair(h: &Held) -> OperationId {
    let open = open_setups(&h.w);
    let others: Vec<&OperationId> = open.iter().filter(|id| **id != h.op).collect();
    assert_eq!(others.len(), 1, "{open:?}");
    others[0].clone()
}

/// ADR-0007 §12.23 item 1 (review wave3a U01, the reviewer's probe). A held repair
/// records its own `setup.attempt` and is `running` before the driver writes anything
/// against the held operation. Paused just before the writer's reconcile, the repair
/// can no longer be cancelled: `OUTCOME_UNKNOWN`, effect `unknown`, `next: reconcile`
/// naming it, and nothing changes; it keeps its `setup_in_progress` blocker, so a second
/// repair of the same held operation is refused while it runs. Released, the held
/// operation completes and the repair is recorded as the repair that completed it.
#[tokio::test]
async fn held_repair_paused_before_the_writer_refuses_cancel_and_a_second_repair() {
    use heimdall_contract::request::CancelRequest;
    use heimdall_domain::operation::EffectReceipt;
    let h = held(Hold::DisplacedMissing).await;
    let (displaced, away) = h.stash.clone().unwrap();
    std::fs::rename(&away, &displaced).unwrap();
    let retry = held_plan(&h, RepairResolution::RetryHeld, &h.op)
        .await
        .unwrap();
    let reconciles = h.w.writer.reconciles.load(Ordering::SeqCst);
    let (entered, release) = h.w.writer.pause_next_reconcile();
    let ops = h.w.ops.clone();
    let digest = retry.plan_digest.clone();
    let submitted = tokio::spawn(async move {
        ops.setup(
            &unattended(),
            SetupRequest::Repair {
                plan_digest: digest,
                request_id: rid("r-retry"),
            },
        )
        .await
    });
    until("the repair paused before the writer", || {
        entered.load(Ordering::SeqCst)
    })
    .await;
    let repair = running_repair(&h);
    // The attempt is on the repair, before any receipt against the held operation.
    let receipts = h.w.receipts(&repair);
    assert!(
        receipts
            .iter()
            .any(|r| r.stage == "setup.attempt"
                && matches!(r.effect, EffectReceipt::Attempted { .. })),
        "{receipts:?}"
    );
    assert_eq!(h.w.op(&repair).state, OperationState::Running);
    let held_receipts = h.w.receipts(&h.op).len();

    // Cancelling it is refused.
    let e =
        h.w.ops
            .cancel(
                &attended(),
                CancelRequest {
                    operation_id: repair.clone(),
                },
            )
            .await
            .unwrap_err();
    scan(&Err::<(), _>(e.clone()));
    assert_eq!(e.code, Code::OutcomeUnknown, "{e:?}");
    assert_eq!(e.effect_status, EffectStatus::Unknown);
    assert_eq!(e.next.action, "reconcile");
    assert_eq!(e.next.operation_id.as_ref(), Some(&repair));
    let r = h.w.op(&repair);
    assert_eq!(r.state, OperationState::Running);
    assert_eq!(r.cancellation, None);

    // A second repair of the same held operation is refused while the first runs.
    let second =
        h.w.effect(&unattended(), "repair", &retry.plan_digest, "r-retry-2")
            .await
            .unwrap_err();
    assert_eq!(second.code, Code::ConfigConflict, "{second:?}");
    assert_eq!(second.reason.as_deref(), Some(reason::SETUP_IN_PROGRESS));
    assert_eq!(open_setups(&h.w).len(), 2, "no third operation admitted");
    assert_eq!(
        h.w.receipts(&h.op).len(),
        held_receipts,
        "nothing written yet"
    );

    // Released: the held operation completes, recorded through the repair.
    release.send(()).unwrap();
    let done = submitted.await.unwrap().unwrap();
    assert_eq!(done.code, Code::Ok, "{:?}", done.data);
    assert_eq!(done.operation_id.as_ref(), Some(&repair));
    assert_eq!(h.w.op(&h.op).state, OperationState::Succeeded);
    let r = h.w.op(&repair);
    assert_eq!(r.state, OperationState::Succeeded);
    assert_eq!(r.code, Some(Code::Ok));
    assert_eq!(r.cancellation, None);
    assert!(open_setups(&h.w).is_empty());
    assert_eq!(
        h.w.writer.reconciles.load(Ordering::SeqCst),
        reconciles + 1,
        "one reconcile of the held operation"
    );
    assert!(
        std::fs::read_to_string(h.w.p())
            .unwrap()
            .contains("Host beta")
    );
    // A cancellation now is idempotent and changes nothing.
    let after =
        h.w.ops
            .cancel(
                &attended(),
                CancelRequest {
                    operation_id: repair.clone(),
                },
            )
            .await
            .unwrap();
    assert_eq!(after.state, OperationState::Succeeded);
    h.w.events();
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
                        endpoint: agent_endpoint_at(&paths.etc, "agent"),
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

/// Whether the child ended by `std::process::abort()`: on Unix by SIGABRT (signal 6); on
/// Windows by the fast-fail abort, exit code `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN`
/// with `FAST_FAIL_FATAL_APP_EXIT`), which is what Rust's `abort` raises there.
fn died_by_abort(status: std::process::ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal() == Some(6)
    }
    #[cfg(windows)]
    {
        status.code().map(i32::cast_unsigned) == Some(0xC000_0409)
    }
}

/// `restart_reconciles_attempted_apply_never_reapplies`, the **process-abort**
/// variant (labelled as such, M01 N06): a child process dies by `abort()` at the
/// commit step's exchange (first adoption and update), and a fresh `Operations` with a
/// fresh writer over the same store reconciles without calling `apply`.
#[tokio::test]
async fn restart_reconciles_attempted_apply_never_reapplies_after_a_process_abort() {
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
        assert!(
            died_by_abort(status),
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
            pause_reconcile: Mutex::new(None),
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

/// ADR-0007 §12.24 item 3: the supervisor's next wake includes the earliest pending
/// decision deadline, so an operation waiting on a decision expires at the tick right
/// after it, never up to `max_idle_sleep` later. With nothing else due, the scheduler
/// pass answers exactly the decision's `expires_at` (an earlier decision wins); after
/// the deadline the pass expires the operation (`CREDENTIAL_EXPIRED`, `next:
/// new_work`), and a deadline in the past is never a wake (no tight loop).
#[tokio::test]
async fn supervisor_wakes_at_the_earliest_pending_decision_deadline() {
    use heimdall_runtime::supervisor::{Supervisor, SupervisorConfig};
    let w = World::new().await;
    let identity = w.catalog_alpha().await;
    let sup = Supervisor::new(w.ops.clone(), SupervisorConfig::default())
        .with_state(w.store.clone(), w.clock.clone());
    assert_eq!(sup.scheduler_pass().await.unwrap(), None, "nothing is due");
    let (op, decision) = apply_waiting(&w, "r-wake").await;
    let first = w
        .decisions()
        .into_iter()
        .find(|d| d.id.as_str() == decision)
        .unwrap();
    assert!(first.expires_at > t0());
    assert_eq!(sup.scheduler_pass().await.unwrap(), Some(first.expires_at));
    // A later decision does not move the wake; the earliest one is it.
    w.clock.advance(Duration::from_secs(60));
    let (_declaration_decision, _) = declare_op(&w, &identity, "r-wake-declare").await;
    assert!(
        w.decisions()
            .iter()
            .any(|d| d.expires_at > first.expires_at)
    );
    assert_eq!(sup.scheduler_pass().await.unwrap(), Some(first.expires_at));
    // At the deadline the pass expires the operation; the next wake is the later
    // decision's deadline, never one in the past.
    advance_to(&w, first.expires_at);
    let next = sup.scheduler_pass().await.unwrap();
    assert_expired(&w, &op, &decision);
    let later = w
        .decisions()
        .into_iter()
        .map(|d| d.expires_at)
        .filter(|t| *t > first.expires_at)
        .min();
    assert_eq!(next, later);
    advance_to(&w, later.unwrap());
    assert_eq!(sup.scheduler_pass().await.unwrap(), None);
}

/// Advance the virtual clock (wall and continuous together) to `t`.
fn advance_to(w: &World, t: Timestamp) {
    let now = heimdall_domain::time::Clock::wall(w.clock.as_ref());
    let span = Duration::try_from(now.duration_until(t)).unwrap();
    w.clock.advance(span);
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
        // M03 wave 0 (A1): fail closed until U0b
        connection: None,
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

// --- ADR-0007 §12.30 item 6: a conflict that changes nothing ------------------------------

/// The open setup operations of the scratch environment.
fn open_setup_ids(w: &World) -> Vec<OperationId> {
    w.store
        .transaction(|tx| tx.open_setup_operations(&env_id()))
        .unwrap()
}

/// `effect` refused by the driver with `CONFIG_CONFLICT` and `reason` before admission:
/// effect `none`, no operation, no decision, no writer call and nothing written.
async fn assert_refused_unchanged(
    w: &World,
    kind: &str,
    plan: &SetupPlan,
    request: &str,
    reason: &str,
) -> OpError {
    assert!(
        plan.files.is_empty(),
        "the plan changes nothing: {:?}",
        plan.files
    );
    assert!(
        plan.findings
            .iter()
            .any(|f| f.reason.as_deref() == Some(reason)),
        "the plan reports {reason}: {:?}",
        plan.findings
    );
    let before = w.tree();
    let decisions = w.decisions().len();
    let applies = w.writer.applies.load(Ordering::SeqCst);
    for caller in [attended(), unattended()] {
        let e = w
            .effect(&caller, kind, &plan.plan_digest, request)
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "{e:?}");
        assert_eq!(e.reason.as_deref(), Some(reason), "{e:?}");
        assert_eq!(e.effect_status, EffectStatus::None, "{e:?}");
        assert!(e.operation_id.is_none(), "nothing is admitted: {e:?}");
        assert!(e.message.contains("nothing was written"), "{}", e.message);
    }
    assert!(open_setup_ids(w).is_empty(), "no setup operation is open");
    assert_eq!(w.decisions().len(), decisions, "no decision record");
    assert_eq!(w.writer.applies.load(Ordering::SeqCst), applies);
    assert_eq!(w.tree(), before, "nothing written");
    w.effect(&attended(), kind, &plan.plan_digest, request)
        .await
        .unwrap_err()
}

/// ADR-0007 §12.30 item 6: the setup driver itself (not only the CLI) refuses a plan
/// that reports a conflict but changes nothing, with `CONFIG_CONFLICT` and the
/// conflict's reason, before anything is journaled: an apply over a managed file
/// another writer edited (`managed_file_edited`, whose refusal names the rollback that
/// resolves it), an apply over a conditional block (`include_conditional`), and a
/// rollback whose block was edited (`marker_edited`, ADR-0007 §5.5 step 1). A plan with
/// no conflict that changes nothing is not refused.
#[tokio::test]
async fn a_plan_that_reports_a_conflict_but_changes_nothing_is_refused_by_the_driver() {
    // managed_file_edited.
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    // No conflict and nothing to change: an unchanged projection is not refused.
    let unchanged = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let conflict = |f: &heimdall_contract::doctor::Finding| {
        f.reason.as_ref().is_some_and(|r| {
            serde_json::from_value::<ConflictKind>(serde_json::Value::String(r.clone())).is_ok()
        })
    };
    assert!(unchanged.files.is_empty(), "{:?}", unchanged.files);
    assert!(
        !unchanged.findings.iter().any(conflict),
        "{:?}",
        unchanged.findings
    );
    let ok = w
        .effect(
            &unattended(),
            "apply",
            &unchanged.plan_digest,
            "r-unchanged",
        )
        .await
        .unwrap();
    assert_eq!(ok["__code"], serde_json::json!("OK"), "{ok}");
    let edited = b"# edited by another writer\nHost alpha\n    User someone-else\n";
    std::fs::write(w.p(), edited).unwrap();
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    let e = assert_refused_unchanged(&w, "apply", &plan, "r-edited", "managed_file_edited").await;
    assert!(
        e.message.contains("resolve it with a rollback") && e.message.contains("hm-conflict"),
        "the refusal names the rollback that resolves it: {}",
        e.message
    );
    assert_eq!(
        std::fs::read(w.p()).unwrap(),
        edited,
        "P is never overwritten"
    );

    // include_conditional.
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let user = std::fs::read_to_string(w.user()).unwrap();
    std::fs::write(w.user(), format!("Host early\n    User fixture\n\n{user}")).unwrap();
    let plan = w
        .preview(PreviewIntent::Apply { include_git: false })
        .await
        .unwrap();
    assert_refused_unchanged(&w, "apply", &plan, "r-cond", "include_conditional").await;

    // marker_edited on rollback.
    let w = World::new().await;
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let user = std::fs::read_to_string(w.user()).unwrap();
    let include = user
        .lines()
        .find(|l| l.trim_start().starts_with("Include"))
        .unwrap()
        .to_owned();
    std::fs::write(
        w.user(),
        user.replace(&include, &format!("{include} # an owner's note")),
    )
    .unwrap();
    let record = w.record();
    let plan = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    assert_refused_unchanged(&w, "rollback", &plan, "r-rb", "marker_edited").await;
    assert_eq!(
        w.record(),
        record,
        "the projection record still manages the item"
    );
}

/// ADR-0007 §12.30 item 6: `managed_file_edited` is resolved by `rollback`, which keeps
/// the edited P as `ssh_config.hm-conflict-<generation>` (§5.5), never by `rerender`:
/// a rerender of an edited P plans no write and the driver refuses it with the
/// conflict, P byte-for-byte as edited. (A rerender of a P that is gone writes it
/// again: `rerender_repair_to_consented_state_needs_no_decision`.)
#[tokio::test]
async fn managed_file_edited_is_resolved_by_rollback_and_never_by_rerender() {
    let w = World::new().await;
    std::fs::write(w.user(), "Host other\n    User fixture\n").unwrap();
    let original = std::fs::read(w.user()).unwrap();
    w.catalog_alpha().await;
    w.apply_approved("r-apply").await;
    let edited = b"# edited by another writer\nHost alpha\n    User someone-else\n";
    std::fs::write(w.p(), edited).unwrap();
    let rerender = w
        .preview(PreviewIntent::Repair {
            conflict: ConflictKind::ManagedFileEdited,
            resolution: RepairResolution::Rerender,
            operation: None,
        })
        .await
        .unwrap();
    assert_refused_unchanged(&w, "repair", &rerender, "r-rerender", "managed_file_edited").await;
    assert_eq!(
        std::fs::read(w.p()).unwrap(),
        edited,
        "rerender never overwrites it"
    );

    let rollback = w
        .preview(PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        })
        .await
        .unwrap();
    assert!(!rollback.files.is_empty(), "the rollback removes the block");
    let done = match w
        .effect(&attended(), "rollback", &rollback.plan_digest, "r-rollback")
        .await
    {
        Ok(v) => v,
        Err(e) if e.code == Code::ApprovalRequired => {
            w.decide(e.next.decision_ref.as_deref().unwrap(), Verdict::Approve)
                .await
                .unwrap();
            w.effect(&attended(), "rollback", &rollback.plan_digest, "r-rollback")
                .await
                .unwrap()
        }
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(done["__code"], serde_json::json!("OK"), "{done}");
    assert_eq!(
        std::fs::read(w.user()).unwrap(),
        original,
        "the user file restored"
    );
    let generation = w.record().unwrap().items[&ProjectionItem::Ssh].generation;
    let kept = w
        .home
        .config_dir
        .join(format!("ssh_config.hm-conflict-{generation}"));
    assert_eq!(
        std::fs::read(&kept).ok().as_deref(),
        Some(&edited[..]),
        "the edited P is kept as a conflict file"
    );
    assert!(!w.p().exists());
}
