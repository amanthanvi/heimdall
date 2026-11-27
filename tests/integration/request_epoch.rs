//! ⟨M08 U2b-2⟩ The restore epoch and the replay fence through a real runtime (ADR-0014 §3.6
//! "The restore epoch and the replay fence", steps 2 to 4; H9, H13; ADR-0006 §19.3).
//!
//! Each test starts the real `Service` on a scratch home over the real control endpoint, with
//! the fake credential adapter and its durable effect ledger (an effect is a ledger line).
//!
//! **Modelled, not real:** nothing in this slice raises the epoch. The epoch is raised, and the
//! replay fence written from the request ledger, by the store's test seams
//! (`Txn::raise_restore_epoch_for_test`, `heimdall_store::fence::fence_ledger_for_test`), on a
//! stopped runtime's store, standing in for U2b-3's restore and repair. The stop between the
//! ledger append and the first store write is the request fence's test hook
//! (`ServiceOptions::request_fence_hook`), an in-process stop at that point, not a killed
//! process.
//!
//! ⟨M08 U2b-2 follow-up A⟩ The paired tests run a runner in process ([`Runner`]): the real
//! operations, the paired-session service and the request fence over the rig's store and
//! state directory, through the real dispatcher and IPC session over in-memory streams, with
//! the paired clients' rows seeded in the role table. A runner "started again" is a new
//! request fence over the same state, which reads the epoch then, as a runtime's start does.
//!
//! Hosted by `heimdall-runtime` as `[[test]] integration_request_epoch`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, PrepareOutcome,
};
use heimdall_app::{Operations, OperationsConfig};
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, reason};
use heimdall_contract::ids::{
    AccountName, ClientId, DecisionId, DestinationId, DeviceId, EnvironmentId, InvitationId,
    KeyFingerprint, PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::ipc::{ClientHello, PeerInfo, PrincipalInfo, capability};
use heimdall_contract::lifecycle::RestoreEpoch;
use heimdall_contract::remote::Role;
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, EnsureRequest, ExistingConnectionsPolicy,
    InteractionMode, NewAuthenticationExpiry, RefreshDependency, Request, RequiredCapabilities,
    RevocationStatus, WaitMode, WorkloadIsolation,
};
use heimdall_contract::{Code, PROTOCOL_VERSION, SchemaVersion, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_ipc::session::{
    ConnectionLimits, ControlClient, ControlConnection, client_capabilities,
};
use heimdall_runtime::Paths;
use heimdall_runtime::config::Config;
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use heimdall_runtime::paired::{PairedRunner, RunnerOptions, init_runner};
use heimdall_runtime::request_fence::{FenceHook, FencePoint, RequestFence};
use heimdall_runtime::service::{Service, ServiceOptions};
use heimdall_store::fence::{
    FenceSettlement, RequestFence as FenceRecord, fence_ledger_for_test, ledger_digest,
    restored_before_completion,
};
use heimdall_store::layout::stategen::RealFs;
use heimdall_store::layout::stategen::ledger::{Entry, LEDGER, Ledger};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::{
    CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
    assert_no_canary,
};
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
type ControlStream = tokio::net::UnixStream;
#[cfg(windows)]
type ControlStream = tokio::net::windows::named_pipe::NamedPipeClient;

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

fn rid(s: &str) -> RequestId {
    RequestId::parse(s).unwrap()
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn ssh_only() -> BTreeSet<Capability> {
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
        usable_until: at(12 * 3600),
        offline_until: at(3600),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        // The fake adapter's opaque credential reference: a canary, never in an answer.
        credential_ref: format!("{CANARY_PREFIX}epoch_fixture"),
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
        capabilities: ssh_only(),
        external_side_effects: false,
        interaction: InteractionRequirement::None,
        enforcement: enforcement(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    }
}

/// A scratch home, its seeded store, the clock and the fake adapter's effect ledger.
// ⟨W3 review fixes; PC job 65⟩ Fields drop in declaration order, so the temporary directory
// comes last. A test declares its `Rig` first, so the rig drops after every other local, and
// each test stops what it started (`Running::stop`, `Runner::stop`) before it ends: nothing
// holds `state.db` open when the directory is deleted. On Windows an open file cannot be
// deleted, and `TempDir`'s drop swallows that failure, which left fixture directories in TEMP.
struct Rig {
    home: PathBuf,
    clock: Arc<VirtualClock>,
    effects: PathBuf,
    _tmp: tempfile::TempDir,
}

/// A served runtime.
struct Running {
    control: PathBuf,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), heimdall_runtime::service::ServiceError>>,
}

impl Running {
    async fn stop(self) {
        self.shutdown.cancel();
        self.task.await.unwrap().unwrap();
    }
}

impl Rig {
    /// Identity, the environment record, profile `dev` (h1) and policy `pol` (h1, 2 h).
    fn new() -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("hh");
        let paths = Paths::under(&home);
        paths.ensure().unwrap();
        let store = Store::open(
            &heimdall_store::layout::db_path(&paths.state_dir).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap();
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
                        pairs: [pair("h1", "deploy")].into_iter().collect(),
                        capabilities: ssh_only(),
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
                            pairs: [pair("h1", "deploy")].into_iter().collect(),
                            capabilities: ssh_only(),
                        },
                        environments: [env_id()].into_iter().collect(),
                        max_window: 2 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: Default::default(),
                        connection: Default::default(),
                        default: false,
                    },
                    false,
                )?;
                Ok(())
            })
            .unwrap();
        Rig {
            effects: tmp.path().join("effects.ledger"),
            home,
            clock: VirtualClock::at(t0()),
            _tmp: tmp,
        }
    }

    fn state_dir(&self) -> PathBuf {
        Paths::under(&self.home).state_dir
    }

    fn clock_wall(&self) -> Timestamp {
        use heimdall_domain::time::Clock as _;
        self.clock.wall()
    }

    /// The store the runtime serves, opened by this test (the runtime is stopped, or its
    /// store is only read).
    fn store(&self) -> Store {
        Store::open(
            &heimdall_store::layout::db_path(&self.state_dir()).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap()
    }

    fn read_only(&self) -> Store {
        Store::open_read_only(
            &heimdall_store::layout::db_path(&self.state_dir()).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap()
    }

    /// Everything a request could have written: the store's tables, the request ledger and
    /// the fake adapter's effects.
    fn footprint(&self) -> (String, Vec<u8>, usize) {
        let counts = self
            .read_only()
            .transaction(|tx| tx.table_counts())
            .unwrap();
        let ledger = std::fs::read(self.state_dir().join(LEDGER)).unwrap_or_default();
        let effects = FakeCredentialAdapter::ledger_entries(&self.effects)
            .map(|e| e.len())
            .unwrap_or(0);
        (format!("{counts:?}"), ledger, effects)
    }

    fn ledger(&self) -> Vec<Entry> {
        Ledger::new(RealFs, self.state_dir())
            .read()
            .unwrap()
            .entries
    }

    async fn start(&self, hook: Option<FenceHook>) -> Running {
        let fake: Arc<dyn CredentialAdapter> = FakeCredentialAdapter::with_ledger(
            descriptor(),
            vec![FakeStep::Prepare(outcome()); 8],
            &self.effects,
        )
        .unwrap();
        let mut options = ServiceOptions::with_clock(
            self.clock.clone(),
            ScriptedTimeSync::new(SyncStatus::Synchronized),
        );
        options.endpoint_prefix = "hmtest-".to_owned();
        options.adapters = vec![fake];
        options.request_fence_hook = hook;
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(
            Paths::under(&self.home),
            Config::default(),
            options,
            shutdown.clone(),
        )
        .await
        .unwrap();
        let control = svc.endpoints().control.clone();
        Running {
            control,
            shutdown,
            task: tokio::spawn(svc.run()),
        }
    }
}

async fn client(endpoint: &Path, mode: InteractionMode) -> ControlClient<ControlStream> {
    #[cfg(unix)]
    let stream = heimdall_ipc::unix::connect(endpoint).await.unwrap();
    #[cfg(windows)]
    let stream = heimdall_ipc::windows::connect_with_owner(
        endpoint,
        heimdall_ipc::windows::ServerOwner::CurrentUser,
    )
    .await
    .unwrap();
    ControlClient::handshake(
        stream,
        heimdall_contract::ipc::PeerInfo {
            name: "epoch-test".into(),
            version: "0".into(),
        },
        BTreeSet::new(),
        mode,
    )
    .await
    .unwrap()
}

/// An interactive session marked attended (the owner at the terminal flow).
async fn attended(endpoint: &Path) -> ControlClient<ControlStream> {
    let mut c = client(endpoint, InteractionMode::Interactive).await;
    assert_eq!(c.attend().await.unwrap().code, Code::Ok);
    c
}

fn ensure(request_id: &str) -> Request {
    Request::Ensure(EnsureRequest {
        profile: Some(ProfileId::parse("dev").unwrap()),
        profile_revision: None,
        scope: Default::default(),
        environment: None,
        work_id: WorkId::parse("w1").unwrap(),
        until: Some(heimdall_contract::request::DeadlineIntent::Duration(
            "1h".into(),
        )),
        required_capabilities: RequiredCapabilities::default(),
        request_id: rid(request_id),
        interaction: InteractionMode::NonInteractive,
        wait: WaitMode::Sync { timeout_ms: 30_000 },
        connection: None,
        context: None,
        covered_only: false,
        pair_issuers: Vec::new(),
    })
}

fn error_of(env: &Envelope<serde_json::Value>) -> ErrorData {
    serde_json::from_value(env.data.clone()).unwrap()
}

/// The answer is `code` with `reason`, effect `none`, and reports the request ID and epoch.
fn assert_refused(
    env: &Envelope<serde_json::Value>,
    code: &Code,
    why: &str,
    request: &Request,
    epoch: RestoreEpoch,
) {
    let text = serde_json::to_string(env).unwrap();
    assert_no_canary(&text);
    assert_eq!(&env.code, code, "{} {text}", request.kind());
    let error = error_of(env);
    assert_eq!(
        error.error.reason.as_deref(),
        Some(why),
        "{}",
        request.kind()
    );
    assert_eq!(error.error.effect_status, EffectStatus::None);
    assert_eq!(
        env.request_id.as_ref(),
        request.request_id(),
        "{}",
        request.kind()
    );
    assert_eq!(env.request_epoch, Some(epoch), "{}", request.kind());
}

/// Every mutating request form this test sends: the checked-in request examples that change
/// something, and the forms no example has.
fn mutating_requests() -> Vec<Request> {
    let examples = [
        include_str!("../../schemas/examples/request.bind-launch.json"),
        include_str!("../../schemas/examples/request.catalog.adopt-identity.json"),
        include_str!("../../schemas/examples/request.catalog.adopt-identity-onepassword.json"),
        include_str!("../../schemas/examples/request.catalog.apply-import.json"),
        include_str!("../../schemas/examples/request.catalog.declare-interaction.json"),
        include_str!("../../schemas/examples/request.catalog.remove-destination.json"),
        include_str!("../../schemas/examples/request.catalog.remove-identity.json"),
        include_str!("../../schemas/examples/request.catalog.remove-profile.json"),
        include_str!("../../schemas/examples/request.catalog.set-default-profile.json"),
        include_str!("../../schemas/examples/request.catalog.upsert-destination.json"),
        include_str!("../../schemas/examples/request.catalog.upsert-destination-observed.json"),
        include_str!("../../schemas/examples/request.catalog.upsert-profile.json"),
        include_str!("../../schemas/examples/request.catalog.withdraw-declaration.json"),
        include_str!("../../schemas/examples/request.confirm-time.json"),
        include_str!("../../schemas/examples/request.decide.json"),
        include_str!("../../schemas/examples/request.enrollment.abandon.json"),
        include_str!("../../schemas/examples/request.enrollment.apply.json"),
        include_str!("../../schemas/examples/request.enrollment.reconcile.json"),
        include_str!("../../schemas/examples/request.enrollment.remove.json"),
        include_str!("../../schemas/examples/request.enrollment.remove-foreign.json"),
        include_str!("../../schemas/examples/request.enrollment.step.json"),
        include_str!("../../schemas/examples/request.enrollment.step-result.json"),
        include_str!("../../schemas/examples/request.enrollment.verify.json"),
        include_str!("../../schemas/examples/request.ensure.json"),
        include_str!("../../schemas/examples/request.ensure.context.json"),
        include_str!("../../schemas/examples/request.environment.container-add.json"),
        include_str!("../../schemas/examples/request.environment.container-remove.json"),
        include_str!("../../schemas/examples/request.environment.wsl-disable.json"),
        include_str!("../../schemas/examples/request.environment.wsl-enable.json"),
        include_str!("../../schemas/examples/request.issuer.bundle-written.json"),
        include_str!("../../schemas/examples/request.issuer.register.json"),
        include_str!("../../schemas/examples/request.issuer.register-report.json"),
        include_str!("../../schemas/examples/request.issuer.register-restore.json"),
        include_str!("../../schemas/examples/request.issuer.register-rotation.json"),
        include_str!("../../schemas/examples/request.issuer.retire.json"),
        include_str!("../../schemas/examples/request.issuer.retire-confirm.json"),
        include_str!("../../schemas/examples/request.issuer.unlock.json"),
        include_str!("../../schemas/examples/request.policy-cutoff.json"),
        include_str!("../../schemas/examples/request.policy.pause-target.json"),
        include_str!("../../schemas/examples/request.policy.trust-workspace.json"),
        include_str!("../../schemas/examples/request.revoke.json"),
        include_str!("../../schemas/examples/request.revoke.work.json"),
        include_str!("../../schemas/examples/request.setup.apply.json"),
        include_str!("../../schemas/examples/request.setup.repair.json"),
        include_str!("../../schemas/examples/request.setup.rollback.json"),
    ];
    let written = [
        serde_json::json!({"op": "delegate", "parent_binding_id": "binding_00112233445566778899aabbccddeeff",
            "scope": [], "work_id": "child-1", "request_id": "req-delegate"}),
        serde_json::json!({"op": "cancel", "operation_id": "op_00112233445566778899aabbccddeeff"}),
        serde_json::json!({"op": "release", "binding_id": "binding_00112233445566778899aabbccddeeff"}),
        serde_json::json!({"op": "policy", "action": "pause", "policy_id": "pol"}),
        serde_json::json!({"op": "policy", "action": "resume", "policy_id": "pol"}),
        serde_json::json!({"op": "policy", "action": "clear_cutoff", "policy_id": "pol"}),
        serde_json::json!({"op": "connections", "action": "close",
            "connection_id": "conn_00112233445566778899aabbccddeeff"}),
        serde_json::json!({"op": "uninstall_fence", "action": "acquire"}),
        // The rest of the forms the TUI sends (its stop menu and its Settings,
        // `heimdall::tui::{m05, m07}`): a profile's stop, a workspace's cutoff, the lock
        // behaviour and the connection policy.
        serde_json::json!({"op": "policy", "action": "stop",
            "target": {"kind": "profile", "profile": "dev"}}),
        serde_json::json!({"op": "policy", "action": "cutoff", "at": "2026-10-02T10:00:00Z",
            "target": {"kind": "workspace", "workspace": "ws_00112233445566778899aabbccddeeff"}}),
        serde_json::json!({"op": "policy", "action": "set_lock_behavior", "policy_id": "pol",
            "behavior": "continue"}),
        serde_json::json!({"op": "policy", "action": "set_connection_policy", "policy_id": "pol",
            "existing": "strict"}),
    ];
    let mut requests: Vec<Request> = examples
        .iter()
        .map(|text| serde_json::from_str(text).unwrap())
        .chain(
            written
                .into_iter()
                .map(|v| serde_json::from_value(v).unwrap()),
        )
        .collect();
    requests.retain(Request::is_effectful);
    requests
}

/// ADR-0014 §3.6 step 3: a mutating request whose epoch is not the current one is refused
/// `REQUEST_STALE` / `restore_epoch_stale`, attended or not, before any store write, ledger
/// append or effect: for every mutating form this runtime serves (every form the CLI, the TUI
/// and the wrapper send among them), on a non-interactive session and on an attended one.
/// Reads on the same sessions are served.
#[tokio::test]
async fn stale_epoch_is_refused_before_any_write() {
    let rig = Rig::new();
    rig.store()
        .transaction(|tx| tx.raise_restore_epoch_for_test(RestoreEpoch(2)))
        .unwrap();
    let running = rig.start(None).await;
    let mut agent = client(&running.control, InteractionMode::NonInteractive).await;
    let mut owner = attended(&running.control).await;
    for c in [&agent, &owner] {
        assert!(
            c.server()
                .capabilities
                .contains(capability::REQUEST_EPOCH_V1)
        );
        assert_eq!(c.server().restore_epoch, Some(RestoreEpoch(2)));
    }
    let before = rig.footprint();
    let requests = mutating_requests();
    let kinds: BTreeSet<&str> = requests.iter().map(Request::kind).collect();
    assert!(kinds.len() >= 30, "{kinds:?}");
    let stale = RestoreEpoch(1);
    let mut checked = BTreeSet::new();
    for request in &requests {
        for (session, c) in [("attended", &mut owner), ("non-interactive", &mut agent)] {
            let env = c
                .request_with_epoch(request.clone(), Some(stale))
                .await
                .unwrap();
            if session == "non-interactive" && request.requires_attended_session() {
                // Refused by the session before dispatch, as before (ADR-0006 §2.3).
                assert_eq!(env.code, Code::InteractionRequired, "{}", request.kind());
                continue;
            }
            assert_refused(
                &env,
                &Code::RequestStale,
                reason::RESTORE_EPOCH_STALE,
                request,
                stale,
            );
            checked.insert(request.kind());
        }
        // A frame with a future epoch is no more current.
        let env = owner
            .request_with_epoch(request.clone(), Some(RestoreEpoch(3)))
            .await
            .unwrap();
        assert_eq!(env.code, Code::RequestStale, "{}", request.kind());
    }
    assert_eq!(checked, kinds, "every form reached the check");
    // Nothing was written, appended or done.
    assert_eq!(rig.footprint(), before);
    // The same sessions still serve reads, and a fresh request bound at send.
    let read = agent
        .request(
            serde_json::from_value(serde_json::json!({"op": "inspect", "subject": "bindings"}))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.code, Code::Ok);
    assert_eq!((read.request_id, read.request_epoch), (None, None));
    let fresh = agent.request(ensure("r-after")).await.unwrap();
    assert_eq!(fresh.code, Code::AccessReady, "{fresh:?}");
    assert_eq!(fresh.request_epoch, Some(RestoreEpoch(2)));
    running.stop().await;
}

/// ADR-0014 §3.6 step 4 and H9: the ledger entry is durable before the request's first store
/// write. A stop between them leaves an entry and no record; an ordinary restart ignores it
/// and serves; once a restore's fence is written from the ledger (the test seam) a retry with
/// the original epoch is `restore_epoch_stale`, and one re-stamped with the new epoch (the
/// residual) or bound at receipt is answered from the fence, `restored_before_completion`.
/// Neither is run.
#[tokio::test]
async fn ledger_append_precedes_the_first_store_write() {
    let rig = Rig::new();
    let stop = Arc::new(AtomicBool::new(true));
    let hook: FenceHook = {
        let stop = Arc::clone(&stop);
        Arc::new(move |point| point == FencePoint::AfterLedgerAppend && stop.load(Ordering::SeqCst))
    };
    let running = rig.start(Some(hook)).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    let before = rig.footprint();
    let cut = c.request(ensure("r-cut")).await.unwrap();
    assert_eq!(cut.code, Code::InternalError, "stopped at the hook");
    assert_eq!(cut.request_epoch, Some(RestoreEpoch(0)));
    running.stop().await;
    // An entry, and no record.
    let caller = CallerContext::local(owner_principal(), ClientRole::Owner);
    let digest = ledger_digest(&caller, "ensure", &rid("r-cut")).unwrap();
    assert_eq!(rig.ledger(), [Entry { epoch: 0, digest }]);
    let after = rig.footprint();
    assert_eq!(after.0, before.0, "no store record");
    assert_eq!(after.2, before.2, "no effect");
    // An ordinary restart ignores the entry: the runtime serves and another request runs.
    stop.store(false, Ordering::SeqCst);
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    assert_eq!(c.server().restore_epoch, Some(RestoreEpoch(0)));
    let other = c.request(ensure("r-other")).await.unwrap();
    assert_eq!(other.code, Code::AccessReady);
    running.stop().await;
    // The restore's fence, from the ledger: `r-cut` has no terminal record, `r-other` has one.
    let store = rig.store();
    assert_eq!(
        fence_ledger_for_test(&store, &rig.state_dir(), RestoreEpoch(1), at(60)).unwrap(),
        1
    );
    drop(store);
    let effects = rig.footprint().2;
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    assert_eq!(c.server().restore_epoch, Some(RestoreEpoch(1)));
    let request = ensure("r-cut");
    let original = c
        .request_with_epoch(request.clone(), Some(RestoreEpoch(0)))
        .await
        .unwrap();
    assert_refused(
        &original,
        &Code::RequestStale,
        reason::RESTORE_EPOCH_STALE,
        &request,
        RestoreEpoch(0),
    );
    for epoch in [Some(RestoreEpoch(1)), None] {
        let fenced = c.request_with_epoch(request.clone(), epoch).await.unwrap();
        assert_refused(
            &fenced,
            &Code::RequestStale,
            reason::RESTORED_BEFORE_COMPLETION,
            &request,
            RestoreEpoch(1),
        );
    }
    assert_eq!(rig.footprint().2, effects, "the fenced request did nothing");
    // A request minted after the fresh hello proceeds.
    let new = c.request(ensure("r-new")).await.unwrap();
    assert_eq!(new.code, Code::AccessReady);
    assert_eq!(new.request_epoch, Some(RestoreEpoch(1)));
    running.stop().await;
    // The fenced request never ran: no record of it; the new one has its own.
    let key = |r: &str| heimdall_domain::idempotency::IdempotencyKey {
        caller: caller.clone(),
        kind: heimdall_domain::operation::OperationKind::Ensure,
        request_id: rid(r),
    };
    let store = rig.read_only();
    assert!(
        store
            .transaction(|tx| tx.idempotency_record(&key("r-cut")))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .transaction(|tx| tx.idempotency_record(&key("r-new")))
            .unwrap()
            .is_some()
    );
}

fn owner_principal() -> PrincipalRef {
    #[cfg(unix)]
    {
        PrincipalRef::UnixUser {
            uid: heimdall_ipc::unix::current_uid(),
        }
    }
    #[cfg(windows)]
    {
        PrincipalRef::WindowsUser {
            sid: heimdall_ipc::windows::current_user_sid().unwrap(),
        }
    }
}

/// ADR-0014 §3.6 step 4 (the ruling on N03): the fence is keyed by the full idempotency key.
/// With one key fenced, the same request ID from another principal, another role, another
/// paired client or for another kind is its own key: admitted, and its ledger entry is its
/// own.
#[tokio::test]
async fn equal_request_ids_across_clients_roles_and_kinds_have_separate_fences() {
    let rig = Rig::new();
    let store = Arc::new(rig.store());
    let owner = CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner);
    let mut other_principal = owner.clone();
    other_principal.principal = PrincipalRef::UnixUser { uid: 502 };
    let mut limited = owner.clone();
    limited.role = ClientRole::LimitedConsumer;
    let mut paired_a = owner.clone();
    paired_a.remote_client = Some(heimdall_contract::ids::ClientId::from_random_bytes([1; 16]));
    let mut paired_b = owner.clone();
    paired_b.remote_client = Some(heimdall_contract::ids::ClientId::from_random_bytes([2; 16]));
    let same = "r-same";
    let revoke: Request = serde_json::from_value(serde_json::json!({
        "op": "revoke", "grant_id": "grant_00112233445566778899aabbccddeeff", "request_id": same,
    }))
    .unwrap();
    // Fence exactly one key: the paired client A's `ensure`.
    let fenced = ledger_digest(&paired_a, "ensure", &rid(same)).unwrap();
    store
        .transaction(|tx| {
            tx.insert_request_fence(&FenceRecord {
                key_digest: fenced,
                epoch: RestoreEpoch(0),
                answer: restored_before_completion(),
                created_at: t0(),
                settlement: None,
            })
        })
        .unwrap();
    let fence = Arc::new(RequestFence::open(Arc::clone(&store), &rig.state_dir()).unwrap());
    let refused = fence
        .admit(&paired_a, &ensure(same), None, at(1))
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::RequestStale);
    assert_eq!(
        error_of(&refused).error.reason.as_deref(),
        Some(reason::RESTORED_BEFORE_COMPLETION)
    );
    let others = [
        (&owner, ensure(same)),
        (&other_principal, ensure(same)),
        (&limited, ensure(same)),
        (&paired_b, ensure(same)),
        (&paired_a, revoke.clone()),
        (&owner, revoke),
    ];
    for (caller, request) in &others {
        let stamp = fence
            .admit(caller, request, None, at(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stamp.request_id, Some(rid(same)));
    }
    let digests: BTreeSet<[u8; 32]> = rig.ledger().iter().map(|e| e.digest).collect();
    assert_eq!(digests.len(), others.len(), "one entry per key");
    assert!(
        !digests.contains(&fenced),
        "the fenced key was not appended"
    );
}

/// ADR-0006 §7.4 for the fence (ADR-0014 §3.6 step 4), through the runtime: an unresolved
/// key's fence is answered after any wait; a settled key's is answered until its retention
/// ends, then as an expired key until its 30-day marker ends, then no longer (the request is
/// new); the retention pass's purge removes only the settled one, after its marker. With only
/// the ledger readable, no entry is dropped (`may_trim` with an unknown settlement).
#[tokio::test]
async fn fence_retention_follows_the_idempotency_contract() {
    let rig = Rig::new();
    let caller = CallerContext::local(owner_principal(), ClientRole::Owner);
    let retention = jiff::SignedDuration::from_hours(7 * 24);
    let settled_at = at(0);
    let expires = settled_at.checked_add(retention).unwrap();
    let until = heimdall_domain::idempotency::marker_until(expires);
    let fence = |request_id: &str, settlement| FenceRecord {
        key_digest: ledger_digest(&caller, "ensure", &rid(request_id)).unwrap(),
        epoch: RestoreEpoch(0),
        answer: restored_before_completion(),
        created_at: at(0),
        settlement,
    };
    rig.store()
        .transaction(|tx| {
            tx.insert_request_fence(&fence("r-unresolved", None))?;
            tx.insert_request_fence(&fence(
                "r-settled",
                Some(FenceSettlement {
                    settled_at,
                    expires_at: expires,
                    marker_until: until,
                }),
            ))?;
            Ok(())
        })
        .unwrap();
    let second = jiff::SignedDuration::from_secs(1);
    let years = at(0)
        .checked_add(jiff::SignedDuration::from_hours(5 * 365 * 24))
        .unwrap();
    // `None`: the fence no longer answers, and the request reaches the application as new.
    for (now, settled) in [
        (
            expires.checked_sub(second).unwrap(),
            Some(Code::RequestStale),
        ),
        (expires, Some(Code::RequestExpired)),
        (
            until.checked_sub(second).unwrap(),
            Some(Code::RequestExpired),
        ),
        (years, None),
    ] {
        let by = now.duration_since(rig.clock_wall());
        rig.clock.advance(Duration::try_from(by).unwrap());
        let running = rig.start(None).await;
        let mut c = client(&running.control, InteractionMode::NonInteractive).await;
        let a = c.request(ensure("r-unresolved")).await.unwrap();
        assert_eq!(a.code, Code::RequestStale, "unresolved at {now}");
        assert_eq!(
            error_of(&a).error.reason.as_deref(),
            Some(reason::RESTORED_BEFORE_COMPLETION)
        );
        let b = c.request(ensure("r-settled")).await.unwrap();
        match settled {
            Some(code) => assert_eq!(b.code, code, "settled at {now}: {b:?}"),
            None => {
                assert!(
                    !matches!(b.code, Code::RequestStale | Code::RequestExpired),
                    "lapsed at {now}: {b:?}"
                );
            }
        }
        running.stop().await;
    }
    // The purge (the retention pass's `purge_markers_before`) keeps the unresolved fence.
    let store = rig.store();
    store
        .transaction(|tx| tx.purge_markers_before(years))
        .unwrap();
    let digest = |r: &str| ledger_digest(&caller, "ensure", &rid(r)).unwrap();
    assert!(
        store
            .transaction(|tx| tx.request_fence(&digest("r-unresolved")))
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .transaction(|tx| tx.request_fence(&digest("r-settled")))
            .unwrap()
            .is_none()
    );
    // Only the ledger readable: an entry whose settlement no store shows is kept.
    use heimdall_store::layout::stategen::ledger::{Settlement, may_trim};
    assert!(!rig.ledger().is_empty());
    for entry in rig.ledger() {
        let _ = entry;
        assert!(!may_trim(Settlement::Unknown, years));
    }
}

/// ADR-0014 §3.6 step 3 and U0-Q5 at the runtime: a mutating answer reports the request ID and
/// the epoch it was bound to; a retry of the kept request ID with the kept epoch replays the
/// same operation; once the epoch has risen, the same pair is refused `REQUEST_STALE`, never
/// replayed or re-run.
#[tokio::test]
async fn clients_carry_the_epoch_with_a_kept_request_id() {
    let rig = Rig::new();
    let running = rig.start(None).await;
    let mut first = client(&running.control, InteractionMode::NonInteractive).await;
    let answered = first.request(ensure("r-kept")).await.unwrap();
    assert_eq!(answered.code, Code::AccessReady);
    let kept = answered.request_epoch.expect("the answer names its epoch");
    assert_eq!(answered.request_id, Some(rid("r-kept")));
    assert_eq!(kept, RestoreEpoch(0));
    // Another session keeps the pair: the retry replays the same operation.
    let mut retry = client(&running.control, InteractionMode::NonInteractive).await;
    retry.keep_epoch(Some(kept));
    let replayed = retry.request(ensure("r-kept")).await.unwrap();
    assert_eq!(replayed.code, Code::AccessReady);
    assert_eq!(replayed.operation_id, answered.operation_id);
    assert_eq!(replayed.request_epoch, Some(kept));
    running.stop().await;
    let effects = rig.footprint().2;
    rig.store()
        .transaction(|tx| tx.raise_restore_epoch_for_test(RestoreEpoch(1)))
        .unwrap();
    let running = rig.start(None).await;
    let mut later = client(&running.control, InteractionMode::NonInteractive).await;
    later.keep_epoch(Some(kept));
    let request = ensure("r-kept");
    let refused = later.request(request.clone()).await.unwrap();
    assert_refused(
        &refused,
        &Code::RequestStale,
        reason::RESTORE_EPOCH_STALE,
        &request,
        kept,
    );
    running.stop().await;
    assert_eq!(rig.footprint().2, effects, "nothing ran again");
}

/// ADR-0014 §3.6 step 2: a decision reference minted under an older epoch is refused
/// `DECISION_STALE` / `restore_epoch_stale`, attended, before anything is decided; one minted
/// under the current epoch reaches the application.
#[tokio::test]
async fn a_decision_minted_under_an_older_epoch_is_stale() {
    let rig = Rig::new();
    let decision = |n: u8| heimdall_domain::decision::DecisionRecord {
        id: DecisionId::from_random_bytes([n; 16]),
        kind: heimdall_domain::decision::DecisionKind::WidenPolicy {
            action: heimdall_contract::request::PolicyAction::Resume {
                policy_id: Some(PolicyId::parse("pol").unwrap()),
                target: None,
            },
        },
        generation: heimdall_domain::policy::AuthorityGeneration(0),
        created_at: t0(),
        expires_at: at(3600),
        state: heimdall_domain::decision::DecisionState::Pending,
        decided_at: None,
    };
    let store = rig.store();
    store
        .transaction(|tx| tx.insert_decision(&decision(1)))
        .unwrap();
    store
        .transaction(|tx| {
            tx.raise_restore_epoch_for_test(RestoreEpoch(1))?;
            tx.insert_decision(&decision(2))
        })
        .unwrap();
    drop(store);
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let decide = |n: u8| -> Request {
        serde_json::from_value(serde_json::json!({
            "op": "decide", "decision_id": DecisionId::from_random_bytes([n; 16]), "verdict": "deny",
        }))
        .unwrap()
    };
    let old = owner.request(decide(1)).await.unwrap();
    assert_eq!(old.code, Code::DecisionStale, "{old:?}");
    assert_eq!(
        error_of(&old).error.reason.as_deref(),
        Some(reason::RESTORE_EPOCH_STALE)
    );
    let current = owner.request(decide(2)).await.unwrap();
    assert_ne!(
        error_of(&current).error.reason.as_deref(),
        Some(reason::RESTORE_EPOCH_STALE),
        "{current:?}"
    );
    running.stop().await;
    let pending = rig
        .read_only()
        .transaction(|tx| tx.decision(&DecisionId::from_random_bytes([1; 16])))
        .unwrap()
        .unwrap();
    assert_eq!(
        pending.state,
        heimdall_domain::decision::DecisionState::Pending,
        "the old decision was not decided"
    );
}

/// ⟨M08 W4 U2b-3a-F; orchestrator ruling 2026-11-26, option A⟩ Once the restore epoch is above
/// 0, a `dec_` reference with no recorded decision answers `DECISION_STALE` /
/// `restore_epoch_stale` (never `NOT_FOUND`), with nothing written. At epoch 0 an unrecorded
/// reference keeps `NOT_FOUND`, and a recorded decision minted under the current epoch keeps
/// its existing answers.
#[tokio::test]
async fn an_unrecorded_decision_reference_is_stale_once_the_epoch_is_above_zero() {
    let rig = Rig::new();
    let unknown = DecisionId::from_random_bytes([0xee; 16]);
    let decide = |id: &DecisionId, verdict: &str| -> Request {
        serde_json::from_value(serde_json::json!({
            "op": "decide", "decision_id": id, "verdict": verdict,
        }))
        .unwrap()
    };
    // At epoch 0: an unrecorded `dec_` reference keeps `NOT_FOUND` (both approve and deny),
    // and writes nothing.
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let before = rig.footprint();
    for verdict in ["approve", "deny"] {
        let env = owner.request(decide(&unknown, verdict)).await.unwrap();
        assert_eq!(env.code, Code::NotFound, "epoch 0 {verdict}: {env:?}");
        assert_eq!(env.request_epoch, Some(RestoreEpoch(0)));
        assert_eq!(error_of(&env).error.effect_status, EffectStatus::None);
    }
    assert_eq!(
        rig.footprint(),
        before,
        "epoch 0 unknown decide wrote nothing"
    );
    running.stop().await;

    // Raise the restore epoch (test seam) and record one decision minted under epoch 1.
    let current_id = DecisionId::from_random_bytes([0x22; 16]);
    let store = rig.store();
    store
        .transaction(|tx| {
            tx.raise_restore_epoch_for_test(RestoreEpoch(1))?;
            let generation = tx.authority_generation()?;
            tx.insert_decision(&heimdall_domain::decision::DecisionRecord {
                id: current_id.clone(),
                kind: heimdall_domain::decision::DecisionKind::WidenPolicy {
                    action: heimdall_contract::request::PolicyAction::Resume {
                        policy_id: Some(PolicyId::parse("pol").unwrap()),
                        target: None,
                    },
                },
                generation,
                created_at: t0(),
                expires_at: at(3600),
                state: heimdall_domain::decision::DecisionState::Pending,
                decided_at: None,
            })
        })
        .unwrap();
    drop(store);

    // At epoch 1: the same unrecorded `dec_` reference answers `DECISION_STALE` /
    // `restore_epoch_stale` with effect `none`, next `fix_request`, and writes nothing.
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let before = rig.footprint();
    let before_db = db_files_bytes(&rig.state_dir());
    let before_ledger = ledger_bytes(&rig.state_dir());
    for verdict in ["approve", "deny"] {
        let request = decide(&unknown, verdict);
        let env = owner.request(request.clone()).await.unwrap();
        assert_refused(
            &env,
            &Code::DecisionStale,
            reason::RESTORE_EPOCH_STALE,
            &request,
            RestoreEpoch(1),
        );
        let error = error_of(&env).error;
        assert!(!error.retryable);
        assert_eq!(error.next.action, "fix_request");
    }
    assert_eq!(
        rig.footprint(),
        before,
        "stale unknown decide wrote nothing"
    );
    assert_eq!(ledger_bytes(&rig.state_dir()), before_ledger);
    assert_eq!(db_files_bytes(&rig.state_dir()), before_db);

    // A recorded decision minted under the current epoch keeps its existing answer.
    let recorded = owner.request(decide(&current_id, "deny")).await.unwrap();
    assert_eq!(recorded.code, Code::Ok, "{recorded:?}");
    assert_eq!(recorded.request_epoch, Some(RestoreEpoch(1)));
    running.stop().await;
}

/// The damaged-ledger refusal (ruled 2026-11-23) at the runtime: a request ledger with damage
/// before its tail refuses every request that carries a request ID, `STATE_UNAVAILABLE` /
/// `ledger_damaged`, next `owner_decision` (the attended `state repair`), before anything is
/// written; the damaged ledger is left as it is. Reads are still served.
#[tokio::test]
async fn a_damaged_ledger_refuses_every_request_with_a_request_id() {
    let rig = Rig::new();
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    for id in ["r-1", "r-2"] {
        assert_eq!(c.request(ensure(id)).await.unwrap().code, Code::AccessReady);
    }
    running.stop().await;
    // Alter a byte of the first complete record: damage, not a torn tail.
    let path = rig.state_dir().join(LEDGER);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[20] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    let before = rig.footprint();
    let request = ensure("r-3");
    let refused = c.request(request.clone()).await.unwrap();
    assert_refused(
        &refused,
        &Code::StateUnavailable,
        reason::LEDGER_DAMAGED,
        &request,
        RestoreEpoch(0),
    );
    assert_eq!(
        refused.next.as_ref().map(|n| n.action.as_str()),
        Some("owner_decision")
    );
    assert_eq!(error_of(&refused).error.next.action, "owner_decision");
    assert_eq!(
        rig.footprint(),
        before,
        "nothing written, the ledger untouched"
    );
    let read: Request =
        serde_json::from_value(serde_json::json!({"op": "inspect", "subject": "bindings"}))
            .unwrap();
    assert_eq!(c.request(read).await.unwrap().code, Code::Ok);
    running.stop().await;
}

// --- ⟨M08 U2b-2 follow-up A⟩ authorization and admission before the request ledger -----------

fn req(v: serde_json::Value) -> Request {
    serde_json::from_value(v).unwrap()
}

/// The peer of every in-memory paired session.
fn paired_principal() -> PrincipalInfo {
    PrincipalInfo::OsUserUnix { uid: 501 }
}

/// A paired client's caller as the runner serves it (ADR-0012 §3.7): the key its ledger
/// entries are digested under.
fn paired_caller(client: &ClientId, role: Role) -> CallerContext {
    CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: heimdall_remote::roles::client_role(role),
        remote_client: Some(client.clone()),
    }
}

/// A runner in process over a rig's store and state directory (module docs).
struct Runner {
    store: Arc<Store>,
    ops: Operations,
    clock: Arc<VirtualClock>,
    state_dir: PathBuf,
    stop: CancellationToken,
    /// The runtime's dispatcher with its request fence ([`Self::restart`]).
    dispatcher: OperationsDispatcher,
    /// ⟨M08 W4 U2b-3a⟩ The dispatcher's request fence ([`Self::restart`] makes a new one).
    fence: Arc<RequestFence>,
    /// ⟨M08 W4 U2b-3a⟩ What [`Self::start_with`] was given, kept for [`Self::restart`].
    setup: RunnerSetup,
    /// The paired sessions' serving tasks this rig spawned ([`Self::connect`]), awaited by
    /// [`Self::stop`].
    sessions: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// ⟨M08 W4 U2b-3a⟩ How [`Runner::start_with`] serves: the request fence's cap and test hook,
/// the management-line writer (so an approved invitation runs), and the route and transport
/// forms over fixture K_iroh custody.
#[derive(Clone, Default)]
struct RunnerSetup {
    limits: Option<heimdall_runtime::request_fence::LedgerLimits>,
    hook: Option<FenceHook>,
    lines: bool,
    routes: bool,
    fake_adapter: bool,
}

impl Runner {
    /// The rig's installation, made a runner (`remote init`'s marker), and served.
    async fn start(rig: &Rig) -> Runner {
        Self::start_with(rig, RunnerSetup::default()).await
    }

    /// [`Self::start`], served as `setup` says.
    async fn start_with(rig: &Rig, setup: RunnerSetup) -> Runner {
        let store = Arc::new(rig.store());
        assert_eq!(init_runner(&store).unwrap(), env_id());
        let adapters: Vec<Arc<dyn CredentialAdapter>> = if setup.fake_adapter {
            vec![
                FakeCredentialAdapter::with_ledger(
                    descriptor(),
                    vec![FakeStep::Prepare(outcome()); 40],
                    &rig.effects,
                )
                .unwrap(),
            ]
        } else {
            Vec::new()
        };
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: rig.clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters,
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let (dispatcher, fence) =
            Self::serve(&store, &ops, &rig.clock, &rig.state_dir(), &stop, &setup);
        Runner {
            store,
            ops,
            clock: rig.clock.clone(),
            state_dir: rig.state_dir(),
            stop,
            dispatcher,
            fence,
            setup,
            sessions: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// ⟨W3 review fixes; PC job 65⟩ Stop the runner and wait until nothing it started holds
    /// the store, so the rig's `TempDir` finds `state.db` closed (the note on [`Rig`]). It
    /// cancels the stop token and awaits every paired session it spawned. It then waits,
    /// bounded, for the operations being driven (`Operations::running_operations`, as the
    /// runtime's own shutdown does), drops the runner, and waits, bounded, until the store's
    /// last handle is gone: an operation's leading task ends when its work does, and the
    /// event relay's task, which holds no store, ends once cancelled. Each test that starts a
    /// `Runner` calls this at its end.
    async fn stop(self) {
        self.stop.cancel();
        let sessions = std::mem::take(&mut *self.sessions.lock().unwrap());
        for session in sessions {
            session.await.unwrap();
        }
        let settled = tokio::time::timeout(Duration::from_secs(10), async {
            while self.ops.running_operations() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            settled.is_ok(),
            "operations still running at the runner's stop"
        );
        let store = Arc::downgrade(&self.store);
        drop(self);
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            while store.strong_count() > 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "the store is still held after the runner's stop"
        );
    }

    fn serve(
        store: &Arc<Store>,
        ops: &Operations,
        clock: &Arc<VirtualClock>,
        state_dir: &Path,
        stop: &CancellationToken,
        setup: &RunnerSetup,
    ) -> (OperationsDispatcher, Arc<RequestFence>) {
        let mut fence = RequestFence::open(Arc::clone(store), state_dir).unwrap();
        if let Some(limits) = setup.limits {
            fence = fence.with_limits(limits);
        }
        if let Some(hook) = &setup.hook {
            fence = fence.with_hook(Arc::clone(hook));
        }
        let fence = Arc::new(fence);
        let options = if setup.lines {
            RunnerOptions {
                lines: Some(Arc::new(
                    heimdall_remote::testing::MemoryLines::default_pair(),
                )),
                command: Some(
                    heimdall_remote::line::ServeCommand::new(
                        "/opt/heimdall/bin/heimdall",
                        "/srv/runner/heimdall",
                    )
                    .unwrap(),
                ),
                management_policy: heimdall_contract::remote::ManagementPolicy::Verified,
                ..RunnerOptions::default()
            }
        } else {
            RunnerOptions::default()
        };
        let runner = PairedRunner::new(Arc::clone(store), ops.clone(), clock.clone(), options);
        let mut dispatcher = OperationsDispatcher::new(
            ops.clone(),
            EventRelay::spawn(ops, stop.clone()),
            clock.clone(),
        )
        .with_request_fence(Arc::clone(&fence))
        .with_runner(Arc::new(runner));
        if setup.routes {
            use heimdall_runtime::supervise_transport::{
                CredentialKeys, NoPeerEndpoints, RouteTransport, ServeSpawn, SupervisorConfig,
                TransportSupervisor,
            };
            // The route and transport forms over fixture K_iroh custody; no serve child is
            // ever started (nothing here serves).
            let supervisor = Arc::new(TransportSupervisor::new(
                Arc::clone(store),
                Arc::new(NoPeerEndpoints),
                SupervisorConfig::new(ServeSpawn {
                    program: PathBuf::from("/nonexistent/heimdall"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
            ));
            let keys: Arc<dyn heimdall_app::transport::TransportKeys> = Arc::new(CredentialKeys(
                Arc::new(heimdall_credential::iroh::FixtureIrohStore::new()),
            ));
            dispatcher = dispatcher.with_route_transport(Arc::new(RouteTransport::new(
                Arc::clone(store),
                supervisor,
                keys,
                Arc::new(heimdall_app::transport::StorePeerEnrollments),
            )));
        }
        (dispatcher, fence)
    }

    /// The runtime started again on the same state: its request fence reads the epoch and the
    /// ledger now.
    fn restart(&mut self) {
        (self.dispatcher, self.fence) = Self::serve(
            &self.store,
            &self.ops,
            &self.clock,
            &self.state_dir,
            &self.stop,
            &self.setup,
        );
    }

    /// ⟨M08 W4 U2b-3a⟩ A session local to the runner: its local owner, attended when asked.
    async fn connect_local(&self, attended: bool) -> ControlClient<tokio::io::DuplexStream> {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let conn = ControlConnection::new(server_end, ConnectionLimits::default())
            .with_server_identity(
                env_id(),
                PeerInfo {
                    name: "runner".into(),
                    version: "0".into(),
                },
            );
        let (dispatcher, stop) = (self.dispatcher.clone(), self.stop.clone());
        let session = tokio::spawn(async move {
            let _ = conn.serve(paired_principal(), dispatcher, stop).await;
        });
        self.sessions.lock().unwrap().push(session);
        let mut c = ControlClient::handshake_hello(
            client_end,
            ClientHello {
                protocol: PROTOCOL_VERSION,
                schema_version: SchemaVersion::current(),
                client: PeerInfo {
                    name: "epoch-test".into(),
                    version: "0".into(),
                },
                capabilities: heimdall_ipc::session::Dispatcher::offered_capabilities(
                    &self.dispatcher,
                ),
                required: BTreeSet::new(),
                interaction: if attended {
                    InteractionMode::Interactive
                } else {
                    InteractionMode::NonInteractive
                },
                remote_client: None,
            },
        )
        .await
        .unwrap();
        if attended {
            assert_eq!(c.attend().await.unwrap().code, Code::Ok);
        }
        c
    }

    /// Client `n`'s row in the role table as the invitation service leaves it: pending, or
    /// active after its join.
    fn seed(&self, n: u8, role: Role, active: bool) -> ClientId {
        use heimdall_store::ext_m06::{
            AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
            RemoteInvitationRecord,
        };
        let client = ClientId::from_random_bytes([n; 16]);
        let invitation = InvitationId::from_random_bytes([n; 16]);
        let fp = KeyFingerprint::parse(&format!(
            "SHA256:{}",
            char::from(b'A' + n % 26).to_string().repeat(43)
        ))
        .unwrap();
        let record = RemoteClientRecord {
            client: client.clone(),
            role,
            key_fingerprint: fp.clone(),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Pending,
            invitation: Some(invitation.clone()),
            revoked_generation: None,
            revocation: None,
            created_at: t0(),
            updated_at: t0(),
            line: AppliedLine::Absent,
        };
        let generation = self
            .store
            .transaction(|tx| tx.authority_generation())
            .unwrap()
            .0;
        let pending = RemoteInvitationRecord {
            invitation: invitation.clone(),
            client: client.clone(),
            role,
            key_fingerprint: fp,
            generation,
            created_wall: t0(),
            created_boot_id: heimdall_domain::time::BootId("boot".into()),
            created_elapsed: Duration::from_secs(1),
            expires_wall: at(15 * 60),
            elapsed_bound: Duration::from_secs(900),
            probe_nonce: "00".into(),
            state: InvitationState::Pending,
            consumed_at: None,
            join: None,
            iroh_admission: false,
        };
        self.store
            .transaction(|tx| {
                tx.insert_remote_invitation(&record, &pending, t0())?;
                if active {
                    tx.activate_remote_client(&JoinRecord {
                        environment: env_id(),
                        invitation: invitation.clone(),
                        client: client.clone(),
                        role,
                        generation,
                        joined_at: t0(),
                    })?;
                }
                Ok(())
            })
            .unwrap();
        client
    }

    /// A paired session of `client`, as the runner's bridge opens it (its hello names the
    /// client), offering this build's capabilities and `remote-control/1`.
    async fn connect(&self, client: &ClientId) -> ControlClient<tokio::io::DuplexStream> {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let conn = ControlConnection::new(server_end, ConnectionLimits::default())
            .with_server_identity(
                env_id(),
                PeerInfo {
                    name: "runner".into(),
                    version: "0".into(),
                },
            );
        let (dispatcher, stop) = (self.dispatcher.clone(), self.stop.clone());
        let session = tokio::spawn(async move {
            let _ = conn.serve(paired_principal(), dispatcher, stop).await;
        });
        self.sessions.lock().unwrap().push(session);
        let mut capabilities = client_capabilities();
        capabilities.insert(capability::REMOTE_CONTROL_V1.to_owned());
        ControlClient::handshake_hello(
            client_end,
            ClientHello {
                protocol: PROTOCOL_VERSION,
                schema_version: SchemaVersion::current(),
                client: PeerInfo {
                    name: "epoch-test".into(),
                    version: "0".into(),
                },
                capabilities,
                required: BTreeSet::new(),
                interaction: InteractionMode::NonInteractive,
                remote_client: Some(client.clone()),
            },
        )
        .await
        .unwrap()
    }
}

// A test that fails before `Runner::stop` still cancels what the runner started.
impl Drop for Runner {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// ⟨M08 U2b-2 follow-up A⟩ A frame refused for its role is refused before the request fence:
/// nothing is appended to the request ledger and nothing is written. Through a runner's paired
/// sessions:
/// - a viewer's `request` forms (`role_insufficient`);
/// - a requester's owner-only forms (`role_insufficient`, `local_owner_required`);
/// - a paired owner's local-owner-only forms (`local_owner_required`);
/// - the frames the client's row refuses: a pending client's (`invitation_pending`) and a
///   revoked one's (`client_revoked`).
///
/// Each answer still reports its request ID and epoch. A request within its role is then
/// admitted, and its entry is the only one appended.
#[tokio::test]
async fn a_frame_refused_for_its_role_appends_nothing_to_the_ledger() {
    use heimdall_store::ext_m06::RevocationCause;
    let rig = Rig::new();
    let runner = Runner::start(&rig).await;
    let viewer = runner.seed(1, Role::Viewer, true);
    let requester = runner.seed(2, Role::Requester, true);
    let owner = runner.seed(3, Role::Owner, true);
    let pending = runner.seed(4, Role::Requester, false);
    let revoked = runner.seed(5, Role::Requester, true);
    let mut v = runner.connect(&viewer).await;
    let mut r = runner.connect(&requester).await;
    let mut o = runner.connect(&owner).await;
    let mut p = runner.connect(&pending).await;
    let mut x = runner.connect(&revoked).await;
    // Revoked in the role table after its hello: its next frame's row check refuses it.
    runner
        .store
        .transaction(|tx| tx.revoke_remote_client(&revoked, RevocationCause::Revoked, t0()))
        .unwrap();
    let binding = "binding_00112233445566778899aabbccddeeff";
    let role = || (Code::CapabilityUnavailable, reason::ROLE_INSUFFICIENT);
    let local = || (Code::InteractionRequired, reason::LOCAL_OWNER_REQUIRED);
    let cases = [
        (
            &mut v,
            vec![
                (ensure("r-v-ensure"), role()),
                (
                    req(serde_json::json!({"op": "bind", "binding_id": binding,
                        "form": {"form": "launch", "executable": "/usr/bin/ssh",
                            "holder": {"pid": 4242, "started_at": "1761912000.123456"}},
                        "request_id": "r-v-bind"})),
                    role(),
                ),
                (
                    req(
                        serde_json::json!({"op": "delegate", "parent_binding_id": binding,
                        "scope": [], "work_id": "child-1", "request_id": "r-v-delegate"}),
                    ),
                    role(),
                ),
                (
                    req(serde_json::json!({"op": "revoke",
                        "grant_id": "grant_00112233445566778899aabbccddeeff",
                        "request_id": "r-v-revoke"})),
                    role(),
                ),
            ],
        ),
        (
            &mut r,
            vec![
                (
                    req(serde_json::json!({"op": "policy", "action": "pause", "policy_id": "pol"})),
                    role(),
                ),
                (
                    req(serde_json::json!({"op": "controller_record",
                        "action": "remove_environment", "environment": env_id()})),
                    local(),
                ),
            ],
        ),
        (
            &mut o,
            vec![
                (
                    req(
                        serde_json::json!({"op": "runner_local", "action": "policy_recheck",
                        "request_id": "r-o-recheck"}),
                    ),
                    local(),
                ),
                (
                    req(serde_json::json!({"op": "runner_local",
                        "action": "designate_time_source", "client": owner,
                        "request_id": "r-o-time"})),
                    local(),
                ),
            ],
        ),
        (
            &mut p,
            vec![(
                ensure("r-p-ensure"),
                (Code::CapabilityUnavailable, reason::INVITATION_PENDING),
            )],
        ),
        // Last: the refusal ends the revoked client's session.
        (
            &mut x,
            vec![(
                ensure("r-x-ensure"),
                (Code::CapabilityUnavailable, reason::CLIENT_REVOKED),
            )],
        ),
    ];
    let before = rig.footprint();
    let mut with_id = 0;
    for (session, requests) in cases {
        for (request, (code, why)) in requests {
            with_id += usize::from(request.request_id().is_some());
            let env = session.request(request.clone()).await.unwrap();
            assert_refused(&env, &code, why, &request, RestoreEpoch(0));
        }
    }
    assert_eq!(
        with_id, 8,
        "the refusals that a ledger append could precede"
    );
    assert_eq!(rig.footprint(), before, "nothing appended or written");
    assert!(rig.ledger().is_empty());
    // Within the role: admitted, and only its entry is appended.
    let within = r.request(ensure("r-q-ensure")).await.unwrap();
    assert_eq!(within.request_epoch, Some(RestoreEpoch(0)), "{within:?}");
    let digest = ledger_digest(
        &paired_caller(&requester, Role::Requester),
        "ensure",
        &rid("r-q-ensure"),
    )
    .unwrap();
    assert_eq!(rig.ledger(), [Entry { epoch: 0, digest }]);
    runner.stop().await;
}

/// ⟨M08 U2b-2 follow-up A⟩ A fenced request (ADR-0008 §17.27 item 2) from a connection that does
/// not hold the uninstall fence, while another holds it, is refused `uninstall_in_progress`
/// before the request fence: nothing is appended to the request ledger and nothing is written,
/// and the answer still reports its request ID and epoch. The holder's own request runs under
/// its lease, past the request fence: its entry is the only one appended.
#[tokio::test]
async fn a_request_the_uninstall_fence_refuses_appends_nothing_to_the_ledger() {
    let rig = Rig::new();
    let running = rig.start(None).await;
    let mut holder = client(&running.control, InteractionMode::NonInteractive).await;
    let mut other = client(&running.control, InteractionMode::NonInteractive).await;
    let held = holder
        .request(req(
            serde_json::json!({"op": "uninstall_fence", "action": "acquire"}),
        ))
        .await
        .unwrap();
    assert_eq!(held.code, Code::Ok, "{held:?}");
    assert_eq!(held.data["fence"], "held");
    let fenced: Vec<Request> = [
        include_str!("../../schemas/examples/request.enrollment.apply.json"),
        include_str!("../../schemas/examples/request.enrollment.verify.json"),
        include_str!("../../schemas/examples/request.enrollment.remove.json"),
    ]
    .iter()
    .map(|text| serde_json::from_str(text).unwrap())
    .collect();
    let before = rig.footprint();
    for request in &fenced {
        assert!(request.request_id().is_some(), "{}", request.kind());
        let env = other.request(request.clone()).await.unwrap();
        assert_refused(
            &env,
            &Code::ServiceUnavailable,
            reason::UNINSTALL_IN_PROGRESS,
            request,
            RestoreEpoch(0),
        );
    }
    assert_eq!(rig.footprint(), before, "nothing appended or written");
    assert!(rig.ledger().is_empty());
    // The holder's own request runs in its lease: admitted, so its entry is appended.
    let apply = &fenced[0];
    let mine = holder.request(apply.clone()).await.unwrap();
    assert_ne!(mine.code, Code::ServiceUnavailable, "{mine:?}");
    let caller = CallerContext::local(owner_principal(), ClientRole::Owner);
    let digest = ledger_digest(&caller, apply.kind(), apply.request_id().unwrap()).unwrap();
    assert_eq!(rig.ledger(), [Entry { epoch: 0, digest }]);
    running.stop().await;
}

/// ⟨M08 U2b-2 follow-up A; ADR-0014 §3.6 step 3, H13⟩ A paired requester negotiates
/// `request-epoch/1` and carries the epoch it kept with a request ID: once the runner's epoch has
/// risen (a restore or a repair; here the store's test seam, then a new start), the same pair
/// is refused `REQUEST_STALE` / `restore_epoch_stale`, effect `none`, with nothing written. A
/// request it mints after the new hello carries the new epoch and is admitted.
#[tokio::test]
async fn a_requester_keeping_an_epoch_from_before_a_raise_is_refused_before_any_write() {
    let rig = Rig::new();
    let mut runner = Runner::start(&rig).await;
    let requester = runner.seed(1, Role::Requester, true);
    let mut first = runner.connect(&requester).await;
    assert!(
        first
            .server()
            .capabilities
            .contains(capability::REQUEST_EPOCH_V1),
        "{:?}",
        first.server()
    );
    assert_eq!(first.server().restore_epoch, Some(RestoreEpoch(0)));
    let request = ensure("r-kept");
    let answered = first.request(request.clone()).await.unwrap();
    assert_ne!(answered.code, Code::RequestStale, "{answered:?}");
    assert_eq!(answered.request_id, Some(rid("r-kept")));
    let kept = answered.request_epoch.expect("the answer names its epoch");
    assert_eq!(kept, RestoreEpoch(0));
    drop(first);
    runner
        .store
        .transaction(|tx| tx.raise_restore_epoch_for_test(RestoreEpoch(1)))
        .unwrap();
    runner.restart();
    let mut later = runner.connect(&requester).await;
    assert_eq!(later.server().restore_epoch, Some(RestoreEpoch(1)));
    later.keep_epoch(Some(kept));
    let before = rig.footprint();
    let refused = later.request(request.clone()).await.unwrap();
    assert_refused(
        &refused,
        &Code::RequestStale,
        reason::RESTORE_EPOCH_STALE,
        &request,
        kept,
    );
    assert_eq!(rig.footprint(), before, "nothing written, appended or done");
    // A request minted after the fresh hello carries the new epoch and is admitted.
    later.keep_epoch(None);
    let fresh = later.request(ensure("r-fresh")).await.unwrap();
    assert_ne!(fresh.code, Code::RequestStale, "{fresh:?}");
    assert_eq!(fresh.request_epoch, Some(RestoreEpoch(1)));
    let digest = ledger_digest(
        &paired_caller(&requester, Role::Requester),
        "ensure",
        &rid("r-fresh"),
    )
    .unwrap();
    assert_eq!(rig.ledger().last(), Some(&Entry { epoch: 1, digest }));
    runner.stop().await;
}

/// Exact raw bytes of the SQLite database family (main file plus any `-wal`/`-journal`),
/// without opening a new connection that could alter WAL state.
fn db_files_bytes(state_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let db = heimdall_store::layout::db_path(state_dir).unwrap();
    let dir = db.parent().unwrap();
    let base = db.file_name().unwrap().to_string_lossy();
    let mut files = Vec::new();
    for suffix in ["", "-wal", "-journal"] {
        let name = format!("{base}{suffix}");
        let path = dir.join(&name);
        if let Ok(bytes) = std::fs::read(&path) {
            files.push((name, bytes));
        }
    }
    files
}

fn ledger_bytes(state_dir: &Path) -> Vec<u8> {
    std::fs::read(state_dir.join(LEDGER)).unwrap_or_default()
}

fn example_request(name: &str) -> Request {
    let path = heimdall_testkit::repo::repo_path(format!("schemas/examples/request.{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

async fn connect_runner(
    dispatcher: &OperationsDispatcher,
    stop: &CancellationToken,
    sessions: &std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    client: Option<&ClientId>,
    capabilities: BTreeSet<String>,
) -> ControlClient<tokio::io::DuplexStream> {
    let (client_end, server_end) = tokio::io::duplex(1 << 20);
    let conn = ControlConnection::new(server_end, ConnectionLimits::default())
        .with_server_identity(
            env_id(),
            PeerInfo {
                name: "runner".into(),
                version: "0".into(),
            },
        );
    let (dispatcher, stop) = (dispatcher.clone(), stop.clone());
    let session = tokio::spawn(async move {
        let _ = conn.serve(paired_principal(), dispatcher, stop).await;
    });
    sessions.lock().unwrap().push(session);
    ControlClient::handshake_hello(
        client_end,
        ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client: PeerInfo {
                name: "sec3a-test".into(),
                version: "0".into(),
            },
            capabilities,
            required: BTreeSet::new(),
            interaction: InteractionMode::NonInteractive,
            remote_client: client.cloned(),
        },
    )
    .await
    .unwrap()
}

/// ⟨M08 W4 SEC-3a, S2-01; ADR-0012 §3.10 amendment 2026-11-26⟩ A paired owner session may
/// send only the allow-listed forms (views, honest controller management calls, narrowing
/// effects, widening submissions, and time/session lifecycle). Every runner-local
/// configuration form is refused before the request fence with `INTERACTION_REQUIRED` /
/// `local_owner_required`, effect `none`, leaving both `REQUEST-LEDGER` and the SQLite store
/// byte-identical, stopping no service and minting no K_iroh.
#[tokio::test]
async fn s2_01_paired_owner_cannot_run_runner_local_configuration_and_writes_nothing() {
    use heimdall_runtime::supervise_transport::{
        CredentialKeys, NoPeerEndpoints, RouteTransport, ServeSpawn, SupervisorConfig,
        TransportSupervisor,
    };

    let rig = Rig::new();
    let mut runner = Runner::start(&rig).await;
    let owner = runner.seed(1, Role::Owner, true);

    // Wire service control and RouteTransport (with an in-memory K_iroh fixture store) so
    // Shutdown and non-serving Transport::Enable would take real effect if admitted.
    let service_stop = CancellationToken::new();
    let iroh_store = Arc::new(heimdall_credential::iroh::FixtureIrohStore::new());
    let supervisor = Arc::new(TransportSupervisor::new(
        Arc::clone(&runner.store),
        Arc::new(NoPeerEndpoints),
        SupervisorConfig::new(ServeSpawn {
            program: PathBuf::from("/nonexistent/heimdall"),
            args: Vec::new(),
            env: Vec::new(),
        }),
    ));
    let keys: Arc<dyn heimdall_app::transport::TransportKeys> =
        Arc::new(CredentialKeys(iroh_store));
    let route_transport = Arc::new(RouteTransport::new(
        Arc::clone(&runner.store),
        supervisor,
        keys,
        Arc::new(heimdall_app::transport::StorePeerEnrollments),
    ));
    runner.dispatcher = runner
        .dispatcher
        .clone()
        .with_service_control(service_stop.clone())
        .with_route_transport(route_transport);

    // Negotiate every capability the runner offers so every excluded form reaches the
    // dispatcher's pre-fence check rather than stopping at capability negotiation.
    let all_caps = heimdall_ipc::session::Dispatcher::offered_capabilities(&runner.dispatcher);
    let mut session = connect_runner(
        &runner.dispatcher,
        &runner.stop,
        &runner.sessions,
        Some(&owner),
        all_caps,
    )
    .await;

    let mut excluded: Vec<(&str, Request)> = vec![
        (
            "catalog.upsert_destination",
            example_request("catalog.upsert-destination"),
        ),
        (
            "catalog.set_default_profile",
            example_request("catalog.set-default-profile"),
        ),
        (
            "catalog.apply_import",
            example_request("catalog.apply-import"),
        ),
        ("setup.rollback", example_request("setup.rollback")),
        ("setup.repair", example_request("setup.repair")),
        ("setup.apply", example_request("setup.apply")),
        ("setup.preview", example_request("setup.preview-apply")),
        ("shutdown", example_request("shutdown")),
        (
            "uninstall_fence.acquire",
            req(serde_json::json!({"op": "uninstall_fence", "action": "acquire"})),
        ),
        (
            "uninstall_fence.release",
            req(serde_json::json!({"op": "uninstall_fence", "action": "release"})),
        ),
        (
            "uninstall_fence.retry_remote_revocations",
            req(serde_json::json!({"op": "uninstall_fence", "action": "retry_remote_revocations"})),
        ),
        (
            "connections.close",
            req(
                serde_json::json!({"op": "connections", "action": "close", "connection_id": "conn_01010101010101010101010101010101"}),
            ),
        ),
        (
            "connections.register",
            req(serde_json::json!({
                "op": "connections", "action": "register",
                "binding_id": "binding_00112233445566778899aabbccddeeff",
                "pid": 4242, "created_at": "2026-10-02T09:00:00Z", "image": "/usr/bin/ssh"
            })),
        ),
        (
            "transport.enable_non_widening",
            req(serde_json::json!({
                "op": "transport", "action": "enable", "serve": false, "request_id": "s2-t-en"
            })),
        ),
        (
            "transport.disable",
            req(serde_json::json!({"op": "transport", "action": "disable"})),
        ),
        (
            "transport.rotate",
            req(serde_json::json!({"op": "transport", "action": "rotate"})),
        ),
        (
            "issuer.bundle_written",
            example_request("issuer.bundle-written"),
        ),
        ("issuer.unlock", example_request("issuer.unlock")),
        ("issuer.register", example_request("issuer.register")),
        ("issuer.retire", example_request("issuer.retire")),
        ("issuer.status", example_request("issuer.status")),
        ("issuer.bundle", example_request("issuer.bundle")),
        ("enrollment.step", example_request("enrollment.step")),
        (
            "enrollment.step_result",
            example_request("enrollment.step-result"),
        ),
        (
            "enrollment.reconcile",
            example_request("enrollment.reconcile"),
        ),
        ("enrollment.abandon", example_request("enrollment.abandon")),
        ("enrollment.apply", example_request("enrollment.apply")),
        ("enrollment.verify", example_request("enrollment.verify")),
        ("enrollment.remove", example_request("enrollment.remove")),
        ("enrollment.preview", example_request("enrollment.preview")),
        (
            "environment.wsl_enable",
            example_request("environment.wsl-enable"),
        ),
        (
            "environment.wsl_disable",
            example_request("environment.wsl-disable"),
        ),
        (
            "environment.container_add",
            example_request("environment.container-add"),
        ),
        (
            "environment.container_remove",
            example_request("environment.container-remove"),
        ),
        (
            "controller_record.remove_environment",
            req(serde_json::json!({
                "op": "controller_record", "action": "remove_environment", "environment": env_id()
            })),
        ),
        (
            "runner_local.designate_time_source",
            req(serde_json::json!({
                "op": "runner_local", "action": "designate_time_source",
                "client": owner, "request_id": "s2-rl-ts"
            })),
        ),
        (
            "device.retire",
            req(serde_json::json!({"op": "device", "action": "retire"})),
        ),
        ("decide", example_request("decide")),
        ("confirm_time", example_request("confirm-time")),
        (
            "route.remove",
            req(serde_json::json!({
                "op": "route", "action": "remove", "destination": "h1",
                "route": "route_01010101010101010101010101010101"
            })),
        ),
        (
            "route.prefer",
            req(serde_json::json!({
                "op": "route", "action": "prefer", "destination": "h1",
                "route": "route_01010101010101010101010101010101", "request_id": "s2-route-pref"
            })),
        ),
        (
            "route.resolve_binding",
            req(serde_json::json!({
                "op": "route", "action": "resolve_binding",
                "destination": "h1", "account": "deploy", "endpoint": "/run/agent.sock"
            })),
        ),
        (
            "route.record_health",
            req(serde_json::json!({
                "op": "route", "action": "record_health", "endpoint": "/run/agent.sock",
                "result": {"kind": "failed_over", "destination": "h1", "account": "deploy", "attempts": []}
            })),
        ),
        (
            "remote_environment.add",
            req(serde_json::json!({
                "op": "remote_environment", "action": "add",
                "destination": "h1", "account": "deploy"
            })),
        ),
        (
            "remote_environment.remove",
            req(serde_json::json!({
                "op": "remote_environment", "action": "remove", "environment": env_id()
            })),
        ),
    ];

    let before_footprint = rig.footprint();
    let before_ledger = ledger_bytes(&rig.state_dir());
    let before_db = db_files_bytes(&rig.state_dir());

    // Check the refusal order with an epoch that the fence would reject on its own.
    // This fixture cannot reach the catalog operation even if admission regresses.
    let request = example_request("catalog.upsert-destination");
    let stale = RestoreEpoch(42);
    assert!(request.request_id().is_some());
    let env = session
        .request_with_epoch(request.clone(), Some(stale))
        .await
        .unwrap();
    assert_refused(
        &env,
        &Code::InteractionRequired,
        reason::LOCAL_OWNER_REQUIRED,
        &request,
        stale,
    );

    for (label, request) in excluded.drain(..) {
        let env = session.request(request.clone()).await.unwrap();
        assert_eq!(
            env.code,
            Code::InteractionRequired,
            "{label}: expected INTERACTION_REQUIRED, got {env:?}"
        );
        assert_eq!(
            env.data["error"]["reason"],
            reason::LOCAL_OWNER_REQUIRED,
            "{label}: expected local_owner_required, got {env:?}"
        );
        assert_eq!(
            env.data["error"]["effect_status"], "none",
            "{label}: expected effect_status none, got {env:?}"
        );
        assert_eq!(env.request_id, request.request_id().cloned(), "{label}");
        assert_eq!(
            env.request_epoch,
            (request.is_effectful() && !request.requires_attended_session())
                .then_some(RestoreEpoch(0)),
            "{label}"
        );
    }

    assert!(
        !service_stop.is_cancelled(),
        "paired Shutdown cancelled the runtime's service stop token"
    );
    assert!(
        runner
            .store
            .transaction(|tx| tx.transport_keys())
            .unwrap()
            .is_empty(),
        "paired Transport::Enable minted K_iroh"
    );
    assert_eq!(
        ledger_bytes(&rig.state_dir()),
        before_ledger,
        "REQUEST-LEDGER changed after refused paired requests"
    );
    assert!(rig.ledger().is_empty());
    assert_eq!(
        db_files_bytes(&rig.state_dir()),
        before_db,
        "SQLite store bytes changed after refused paired requests"
    );
    assert_eq!(rig.footprint(), before_footprint);

    // Positive controls: allow-listed view and widening submission still work.
    let view = session
        .request(req(
            serde_json::json!({"op": "inspect", "subject": "environments"}),
        ))
        .await
        .unwrap();
    assert_eq!(view.code, Code::Ok, "{view:?}");
    let serve_widening = session
        .request(req(serde_json::json!({
            "op": "transport", "action": "enable", "serve": true,
            "request_id": "s2-t-serve-widen"
        })))
        .await
        .unwrap();
    assert_eq!(
        serve_widening.code,
        Code::ApprovalRequired,
        "widening submission must still create a pending runner-local decision: {serve_widening:?}"
    );
    runner.stop().await;
}

/// ⟨M08 W4 SEC-3a / U2b-3a item 2⟩ An unattended local owner's widening `runner_local` forms
/// (`trust_issuer`, `designate_time_source`, `policy_recheck`, `enroll_owner`) are refused
/// `INTERACTION_REQUIRED` before the request fence, leaving `REQUEST-LEDGER` and the store
/// byte-identical.
#[tokio::test]
async fn u2b_3a_unattended_local_owner_widening_runner_local_appends_nothing_to_ledger() {
    let rig = Rig::new();
    let runner = Runner::start(&rig).await;
    let owner = runner.seed(1, Role::Owner, true);
    let new_owner = ClientId::from_random_bytes([9; 16]);
    let ca_key =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ca";

    let mut caps = client_capabilities();
    caps.insert(capability::REMOTE_CONTROL_V1.to_owned());
    caps.insert(capability::REQUEST_EPOCH_V1.to_owned());
    // Local (remote_client = None), unattended (NonInteractive, no Attend frame).
    let mut local = connect_runner(
        &runner.dispatcher,
        &runner.stop,
        &runner.sessions,
        None,
        caps,
    )
    .await;

    let forms = [
        (
            "runner_local.trust_issuer",
            req(serde_json::json!({
                "op": "runner_local", "action": "trust_issuer",
                "controller": owner, "ca_public_key": ca_key, "request_id": "u2b-rl-trust"
            })),
        ),
        (
            "runner_local.designate_time_source",
            req(serde_json::json!({
                "op": "runner_local", "action": "designate_time_source",
                "client": owner, "request_id": "u2b-rl-time"
            })),
        ),
        (
            "runner_local.policy_recheck",
            req(serde_json::json!({
                "op": "runner_local", "action": "policy_recheck",
                "request_id": "u2b-rl-recheck"
            })),
        ),
        (
            "runner_local.enroll_owner",
            req(serde_json::json!({
                "op": "runner_local", "action": "enroll_owner",
                "client": new_owner, "public_key": ca_key, "request_id": "u2b-rl-enroll"
            })),
        ),
    ];

    let before_footprint = rig.footprint();
    let before_ledger = ledger_bytes(&rig.state_dir());
    let before_db = db_files_bytes(&rig.state_dir());

    for (label, request) in &forms {
        assert!(request.request_id().is_some(), "{label}");
        let env = local.request(request.clone()).await.unwrap();
        assert_eq!(
            env.code,
            Code::InteractionRequired,
            "{label}: expected INTERACTION_REQUIRED, got {env:?}"
        );
        assert!(
            env.data["error"]["reason"].is_null(),
            "{label}: local unattended refusal must not carry local_owner_required: {env:?}"
        );
        assert_eq!(env.data["error"]["effect_status"], "none", "{label}");
        assert_eq!(env.request_id, request.request_id().cloned(), "{label}");
        assert_eq!(env.request_epoch, Some(RestoreEpoch(0)), "{label}");
    }

    assert_eq!(
        ledger_bytes(&rig.state_dir()),
        before_ledger,
        "unattended local runner_local widening appended to REQUEST-LEDGER"
    );
    assert!(rig.ledger().is_empty());
    assert_eq!(
        db_files_bytes(&rig.state_dir()),
        before_db,
        "unattended local runner_local widening wrote to the SQLite store"
    );
    assert_eq!(rig.footprint(), before_footprint);
    runner.stop().await;
}

// --- ⟨M08 W4 U2b-3a⟩ the ledger bounded, its trim, and the terminal records of M06's kinds ----

/// The cap's refusal: `BACKPRESSURE`, retryable, effect `none`, next `retry_after` with a hint,
/// and the request's ID and epoch reported.
fn assert_ledger_full(env: &Envelope<serde_json::Value>, request: &Request) {
    let text = serde_json::to_string(env).unwrap();
    assert_no_canary(&text);
    assert_eq!(env.code, Code::Backpressure, "{text}");
    let error = error_of(env).error;
    assert!(error.retryable, "{text}");
    assert_eq!(error.effect_status, EffectStatus::None, "{text}");
    assert_eq!(error.next.action, "retry_after", "{text}");
    assert!(error.next.retry_after_ms.is_some(), "{text}");
    assert_eq!(env.request_id.as_ref(), request.request_id());
    assert_eq!(env.request_epoch, Some(RestoreEpoch(0)));
}

/// ⟨M08 W4 U2b-3a; the soak precondition and the orchestrator's cap of 2026-11-26⟩ An
/// authorized session's flood of distinct keys keeps the request ledger bounded, and an
/// append's cost does not grow with the ledger's history. Through a runner's paired sessions
/// and its local owner, with the cap's numbers made small (limit 24, owner reserve 6, share 8):
///
/// - each new key appends one entry, and **no append reads the ledger** (the fence's bytes read
///   stay at what its open read: the cost proxy is flat);
/// - past its share, a requester's next new key is refused `BACKPRESSURE` with nothing
///   appended (the ledger is byte-identical), while a retry of one of its keys is still
///   answered, appending nothing;
/// - another requester is not refused by the first one's flood;
/// - at the owner reserve's line a requester is refused although its own share is not full,
///   and the **owner's** new keys are admitted while requesters are at their share and at the
///   line, up to the limit, where the owner's own next key is refused: the ledger never holds
///   more than the limit;
/// - started again, the fence reads the ledger once, and the line holds (the count is the
///   ledger's own).
///
/// The application answers these `ensure`s with its own refusal (the rig has no adapter):
/// what the cap governs is the request fence's admission, which each assertion checks.
#[tokio::test]
async fn a_flood_of_distinct_keys_keeps_the_ledger_bounded() {
    use heimdall_runtime::request_fence::LedgerLimits;
    let rig = Rig::new();
    let limits = LedgerLimits {
        limit: 24,
        owner_reserve: 6,
        client_share: 8,
    };
    let mut runner = Runner::start_with(
        &rig,
        RunnerSetup {
            limits: Some(limits),
            ..RunnerSetup::default()
        },
    )
    .await;
    let flooder = runner.seed(1, Role::Requester, true);
    let second = runner.seed(2, Role::Requester, true);
    let third = runner.seed(3, Role::Requester, true);
    let opened = runner.fence.ledger_bytes_read();
    let admitted = |env: &Envelope<serde_json::Value>, id: &str, n: usize| {
        assert_ne!(env.code, Code::Backpressure, "{id}: {env:?}");
        assert_ne!(env.code, Code::StateUnavailable, "{id}: {env:?}");
        assert_eq!(env.request_id, Some(rid(id)), "{id}");
        assert_eq!(rig.ledger().len(), n, "{id}: one entry per new key");
    };
    // The flood, up to the share.
    let mut a = runner.connect(&flooder).await;
    for n in 0..8 {
        let id = format!("r-a-{n}");
        let env = a.request(ensure(&id)).await.unwrap();
        admitted(&env, &id, n + 1);
        assert_eq!(
            runner.fence.ledger_bytes_read(),
            opened,
            "{id}: an append reads nothing"
        );
    }
    // Past the share: refused before any append.
    let before = ledger_bytes(&rig.state_dir());
    let over = ensure("r-a-8");
    assert_ledger_full(&a.request(over.clone()).await.unwrap(), &over);
    assert_eq!(ledger_bytes(&rig.state_dir()), before, "nothing appended");
    // A retry of a key already in the ledger is deduplicated, and still answered.
    let retry = a.request(ensure("r-a-3")).await.unwrap();
    assert_ne!(retry.code, Code::Backpressure, "{retry:?}");
    assert_eq!(retry.request_id, Some(rid("r-a-3")));
    assert_eq!(
        ledger_bytes(&rig.state_dir()),
        before,
        "a retry appends nothing"
    );
    // Another requester is not refused by the first one's flood.
    let mut b = runner.connect(&second).await;
    for n in 0..8 {
        let id = format!("r-b-{n}");
        let env = b.request(ensure(&id)).await.unwrap();
        admitted(&env, &id, 9 + n);
    }
    let mut c = runner.connect(&third).await;
    for n in 0..2 {
        let id = format!("r-c-{n}");
        let env = c.request(ensure(&id)).await.unwrap();
        admitted(&env, &id, 17 + n);
    }
    // The owner reserve's line (24 - 6): the third requester is refused with its share not full.
    let at_line = ensure("r-c-2");
    assert_ledger_full(&c.request(at_line.clone()).await.unwrap(), &at_line);
    assert_eq!(rig.ledger().len(), 18);
    // The owner is admitted while requesters are at their share and at the line.
    let mut owner = runner.connect_local(false).await;
    for n in 0..6 {
        let id = format!("r-o-{n}");
        let env = owner.request(ensure(&id)).await.unwrap();
        admitted(&env, &id, 19 + n);
    }
    // The limit: the owner's own next key is refused; the ledger holds the limit, no more.
    let full = ensure("r-o-6");
    let before = ledger_bytes(&rig.state_dir());
    assert_ledger_full(&owner.request(full.clone()).await.unwrap(), &full);
    assert_eq!(ledger_bytes(&rig.state_dir()), before);
    assert_eq!(rig.ledger().len(), limits.limit);
    assert_eq!(
        runner.fence.ledger_bytes_read(),
        opened,
        "no append, refusal or retry read the ledger"
    );
    // Started again: the ledger is read once, and the line holds.
    drop((a, b, c, owner));
    runner.restart();
    assert_eq!(
        runner.fence.ledger_bytes_read(),
        (limits.limit * heimdall_store::layout::stategen::ledger::RECORD_LEN) as u64
    );
    let mut c = runner.connect(&third).await;
    let after = ensure("r-c-3");
    assert_ledger_full(&c.request(after.clone()).await.unwrap(), &after);
    assert_eq!(rig.ledger().len(), limits.limit);
    drop(c);
    runner.stop().await;
}

/// ⟨M08 W4 U2b-3a-F; orchestrator ruling 2026-11-26⟩ The per-caller share covers every
/// non-owner caller, local requester principals included, keyed by the caller identity the
/// session carries (principal plus client):
/// - a local requester principal (`ClientRole::LimitedConsumer`, `remote_client: None`) that
///   fills its share gets `BACKPRESSURE` with no append (the ledger is byte-identical), while
///   a retry of one of its keys still succeeds without appending;
/// - another local requester principal (and a paired requester) still succeed;
/// - a local requester sharing the local owner's OS principal is bounded by its own share,
///   while the local owner still succeeds and keeps the full owner reserve.
#[tokio::test]
async fn a_local_requester_principal_is_bounded_by_its_share() {
    use heimdall_app::Caller;
    use heimdall_runtime::request_fence::LedgerLimits;
    let rig = Rig::new();
    let limits = LedgerLimits {
        limit: 32,
        owner_reserve: 6,
        client_share: 8,
    };
    let runner = Runner::start_with(
        &rig,
        RunnerSetup {
            limits: Some(limits),
            fake_adapter: true,
            ..RunnerSetup::default()
        },
    )
    .await;
    let local_requester = |uid: u32| {
        Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid },
            ClientRole::LimitedConsumer,
        ))
    };
    let req_a = local_requester(502);
    let req_b = local_requester(503);
    let req_same_uid = local_requester(501);
    let paired = runner.seed(1, Role::Requester, true);
    let opened = runner.fence.ledger_bytes_read();

    let assert_ready = |env: &Envelope<serde_json::Value>, id: &str, expected_len: usize| {
        assert_eq!(env.code, Code::AccessReady, "{id}: {env:?}");
        assert_eq!(env.request_id, Some(rid(id)), "{id}");
        assert_eq!(env.request_epoch, Some(RestoreEpoch(0)), "{id}");
        assert_eq!(
            rig.ledger().len(),
            expected_len,
            "{id}: one entry per new key"
        );
        assert_eq!(
            runner.fence.ledger_bytes_read(),
            opened,
            "{id}: an append reads nothing"
        );
    };

    // Local requester A fills its share (8 entries).
    for n in 0..8 {
        let id = format!("r-la-{n}");
        let env = runner.dispatcher.handle_as(&req_a, ensure(&id)).await;
        assert_ready(&env, &id, n + 1);
    }
    // Past its share: refused BACKPRESSURE with no append and no adapter effect.
    let before_ledger = ledger_bytes(&rig.state_dir());
    let before_effects = rig.footprint().2;
    let over_a = ensure("r-la-8");
    let refused_a = runner.dispatcher.handle_as(&req_a, over_a.clone()).await;
    assert_ledger_full(&refused_a, &over_a);
    assert_eq!(
        ledger_bytes(&rig.state_dir()),
        before_ledger,
        "nothing appended"
    );
    assert_eq!(rig.footprint().2, before_effects, "no adapter effect");

    // A retry of an already-admitted key from requester A still succeeds, appending nothing.
    let retry_a = runner.dispatcher.handle_as(&req_a, ensure("r-la-3")).await;
    assert_eq!(retry_a.code, Code::AccessReady, "{retry_a:?}");
    assert_eq!(
        ledger_bytes(&rig.state_dir()),
        before_ledger,
        "retry appends nothing"
    );

    // Another local requester principal (B) still succeeds up to its own share.
    for n in 0..8 {
        let id = format!("r-lb-{n}");
        let env = runner.dispatcher.handle_as(&req_b, ensure(&id)).await;
        assert_ready(&env, &id, 9 + n);
    }
    let before_ledger = ledger_bytes(&rig.state_dir());
    let over_b = ensure("r-lb-8");
    assert_ledger_full(
        &runner.dispatcher.handle_as(&req_b, over_b.clone()).await,
        &over_b,
    );
    assert_eq!(ledger_bytes(&rig.state_dir()), before_ledger);

    // A local requester on the same OS principal as the local owner (uid 501) has its own share.
    for n in 0..8 {
        let id = format!("r-lc-{n}");
        let env = runner
            .dispatcher
            .handle_as(&req_same_uid, ensure(&id))
            .await;
        assert_ready(&env, &id, 17 + n);
    }
    let before_ledger = ledger_bytes(&rig.state_dir());
    let over_c = ensure("r-lc-8");
    assert_ledger_full(
        &runner
            .dispatcher
            .handle_as(&req_same_uid, over_c.clone())
            .await,
        &over_c,
    );
    assert_eq!(ledger_bytes(&rig.state_dir()), before_ledger);

    // A paired requester on uid 501 has its own (principal, client) key, until the owner reserve line (32 - 6 = 26).
    let mut paired_session = runner.connect(&paired).await;
    for n in 0..2 {
        let id = format!("r-p-{n}");
        let env = paired_session.request(ensure(&id)).await.unwrap();
        assert_ne!(env.code, Code::Backpressure, "{id}: {env:?}");
        assert_eq!(rig.ledger().len(), 25 + n);
    }
    let before_ledger = ledger_bytes(&rig.state_dir());
    let at_reserve = ensure("r-p-2");
    assert_ledger_full(
        &paired_session.request(at_reserve.clone()).await.unwrap(),
        &at_reserve,
    );
    assert_eq!(ledger_bytes(&rig.state_dir()), before_ledger);

    // The local owner (uid 501, Owner) still succeeds and fills its 6-entry owner reserve.
    let mut owner_session = runner.connect_local(false).await;
    for n in 0..6 {
        let id = format!("r-o-{n}");
        let env = owner_session.request(ensure(&id)).await.unwrap();
        assert_ready(&env, &id, 27 + n);
    }
    let before_ledger = ledger_bytes(&rig.state_dir());
    let at_limit = ensure("r-o-6");
    assert_ledger_full(
        &owner_session.request(at_limit.clone()).await.unwrap(),
        &at_limit,
    );
    assert_eq!(ledger_bytes(&rig.state_dir()), before_ledger);
    assert_eq!(rig.ledger().len(), limits.limit);

    drop((paired_session, owner_session));
    runner.stop().await;
}

/// ⟨M08 W4 U2b-3a; ADR-0006 §7.4, ADR-0014 §3.6 step 4⟩ The ledger's trim, through the
/// runtime: a settled key's entry is dropped only once its marker window has ended, as the
/// retention pass found on checked time, although its operation and idempotency record were
/// purged long before (its settlement is kept by the ledger's digest). An entry whose settlement
/// is unknown (its request stopped after the append, before any store write) is never dropped.
#[tokio::test]
async fn the_trim_drops_an_entry_only_after_its_marker_window() {
    let rig = Rig::new();
    let cut = Arc::new(AtomicBool::new(false));
    let hook: FenceHook = {
        let cut = Arc::clone(&cut);
        Arc::new(move |p| p == FencePoint::AfterLedgerAppend && cut.swap(false, Ordering::SeqCst))
    };
    let running = rig.start(Some(hook)).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    assert_eq!(
        c.request(ensure("r-done")).await.unwrap().code,
        Code::AccessReady
    );
    cut.store(true, Ordering::SeqCst);
    let stopped = c.request(ensure("r-cut")).await.unwrap();
    assert_eq!(stopped.code, Code::InternalError, "{stopped:?}");
    running.stop().await;
    let caller = CallerContext::local(owner_principal(), ClientRole::Owner);
    let digest = |r: &str| ledger_digest(&caller, "ensure", &rid(r)).unwrap();
    let digests =
        |rig: &Rig| -> BTreeSet<[u8; 32]> { rig.ledger().iter().map(|e| e.digest).collect() };
    assert_eq!(digests(&rig), [digest("r-done"), digest("r-cut")].into());
    // The retention pass's purges, on its time: `r-done` (settled at t0, retention 7 days) is
    // purged at once; its marker window ends 30 days after that.
    let store = rig.store();
    let purged_at = at(10 * 24 * 3600);
    assert!(
        store
            .transaction(|tx| tx.purge_operations_before(purged_at))
            .unwrap()
            >= 1
    );
    let terminal = store
        .transaction(|tx| tx.request_terminal(&digest("r-done")))
        .unwrap()
        .expect("the settlement is kept by the ledger's digest");
    let until = terminal.trim_after;
    let second = jiff::SignedDuration::from_secs(1);
    store
        .transaction(|tx| tx.purge_markers_before(until.checked_sub(second).unwrap()))
        .unwrap();
    drop(store);
    // Inside the window: the trim, at the next start's first request, drops nothing.
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    c.request(ensure("r-later-1")).await.unwrap();
    running.stop().await;
    assert!(
        digests(&rig).contains(&digest("r-done")),
        "kept inside its window"
    );
    // The window has ended: the next start's trim drops it, and its record goes.
    let store = rig.store();
    store
        .transaction(|tx| tx.purge_markers_before(until))
        .unwrap();
    drop(store);
    let running = rig.start(None).await;
    let mut c = client(&running.control, InteractionMode::NonInteractive).await;
    c.request(ensure("r-later-2")).await.unwrap();
    running.stop().await;
    let now = digests(&rig);
    assert!(!now.contains(&digest("r-done")), "dropped after its window");
    assert!(
        now.contains(&digest("r-cut")),
        "an unknown settlement is never dropped"
    );
    assert!(now.contains(&digest("r-later-1")) && now.contains(&digest("r-later-2")));
    assert_eq!(
        rig.read_only()
            .transaction(|tx| tx.request_terminal(&digest("r-done")))
            .unwrap(),
        None,
        "the trim removed the record it consumed"
    );
}

/// `trust_issuer` of `controller`'s CA (a public key line), as a request with `id`.
fn trust_issuer(controller: &ClientId, id: &str) -> Request {
    req(serde_json::json!({
        "op": "runner_local", "action": "trust_issuer", "controller": controller,
        "ca_public_key":
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ca",
        "request_id": id,
    }))
}

/// `route add` of a direct route to `lab`, as a request with `id`.
fn route_add(id: &str) -> Request {
    req(serde_json::json!({
        "op": "route", "action": "add", "destination": "lab",
        "route": {"kind": "direct", "host": "127.0.0.2", "port": 2222}, "request_id": id,
    }))
}

/// `transport enable` without serving, under the minimal policy, as a request with `id`.
fn transport_enable(id: &str) -> Request {
    req(serde_json::json!({
        "op": "transport", "action": "enable", "serve": false, "request_id": id,
    }))
}

/// `environment invite` of a requester whose key is the fixture key `n` (a synthetic public
/// key, no private half), as a request with `id`.
fn invite(n: u8, id: &str) -> Request {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    let mut k = [0x5au8; 32];
    k[0] = n;
    blob.extend_from_slice(&k);
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in blob.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let text = format!("ssh-ed25519 {b64}");
    let fp = heimdall_remote::line::PublicKeyText::parse(&text)
        .unwrap()
        .fingerprint();
    req(serde_json::json!({
        "op": "remote_environment", "action": "invite", "environment": env_id(),
        "role": "requester", "key_fingerprint": fp, "public_key": text, "request_id": id,
    }))
}

/// ⟨M08 W4 U2b-3a; the U2b-2 ruling "terminal records before restore lands"⟩ M06's request-ID
/// kinds have terminal records: one kind of each family completes (its answer is a success),
/// one request of the same kind is received but never completes, and a raise of the epoch
/// fences from the request ledger every entry with no terminal record
/// (`fence_ledger_for_test`, the restore's step in miniature). After it, a retry of each
/// completed request (bound at receipt, after a fresh hello) is answered again, never
/// `REQUEST_STALE`; a retry of each incomplete one is refused `REQUEST_STALE` /
/// `restored_before_completion` and never run. The families and kinds, on a runner served with
/// the route and transport forms and its management-line writer:
///
/// - **route:** the local owner's `route add` of a direct route (completed: the route is
///   stored; a retry finds it `already_present`);
/// - **transport:** the local owner's `transport enable`, not serving, minimal policy;
/// - **runner-local:** the attended local owner's `runner_local.trust_issuer`;
/// - **invite:** a paired owner's `remote_environment.invite`, a widening the runner's
///   attended local owner approves; the invite is completed once its retry is answered from
///   the decided record (the request it names then has its terminal record). The incomplete
///   one stays a pending decision.
///
/// An incomplete request of the first three is stopped by the request fence's test hook after
/// its ledger append, before the application, as a stop at that point leaves it.
#[tokio::test]
async fn m06_request_id_kinds_complete_with_terminal_records_and_only_the_incomplete_are_fenced() {
    let rig = Rig::new();
    let cut = Arc::new(AtomicBool::new(false));
    let hook: FenceHook = {
        let cut = Arc::clone(&cut);
        Arc::new(move |p| p == FencePoint::AfterLedgerAppend && cut.swap(false, Ordering::SeqCst))
    };
    let mut runner = Runner::start_with(
        &rig,
        RunnerSetup {
            hook: Some(hook),
            lines: true,
            routes: true,
            ..RunnerSetup::default()
        },
    )
    .await;
    let controller = runner.seed(1, Role::Owner, true);
    // The managed destination the route is added to.
    runner
        .store
        .transaction(|tx| {
            tx.upsert_destination(&heimdall_domain::catalog::DestinationRecord {
                id: DestinationId::parse("lab").unwrap(),
                alias: "lab".to_owned(),
                revision: 1,
                definition: heimdall_domain::catalog::DestinationDefinition::Managed {
                    hostname: "127.0.0.1".into(),
                    port: Some(22),
                    account: AccountName::parse("deploy").unwrap(),
                    identity: heimdall_contract::ids::IdentityId::from_random_bytes([7; 16]),
                    jump: None,
                },
                label: None,
                updated_at: t0(),
            })
        })
        .unwrap();
    let mut owner = runner.connect_local(true).await;
    let mut paired = runner.connect(&controller).await;
    let ok = |env: &Envelope<serde_json::Value>, what: &str| {
        assert!(
            matches!(env.code, Code::Ok | Code::AccessReady),
            "{what}: {env:?}"
        );
    };
    // Completed, one of each family. The transport family completes only where the Iroh
    // transport is built (`--features iroh`); without it `transport enable` is refused
    // `driver_unavailable` (no success, so no terminal record), and its retry after the raise
    // is fenced like an incomplete one.
    let mut completed = vec![
        ("route", route_add("r-route-done")),
        ("runner-local", trust_issuer(&controller, "r-trust-done")),
    ];
    if cfg!(feature = "iroh") {
        completed.push(("transport", transport_enable("r-transport-done")));
    } else {
        let refused = owner
            .request(transport_enable("r-transport-refused"))
            .await
            .unwrap();
        assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
        assert_eq!(
            error_of(&refused).error.reason.as_deref(),
            Some(reason::DRIVER_UNAVAILABLE)
        );
    }
    for (family, request) in &completed {
        ok(&owner.request(request.clone()).await.unwrap(), family);
    }
    let submitted = paired.request(invite(20, "r-invite-done")).await.unwrap();
    assert_eq!(submitted.code, Code::ApprovalRequired, "{submitted:?}");
    let decision = submitted
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .unwrap();
    let approved = owner
        .request(req(serde_json::json!({
            "op": "decide", "decision_id": decision, "verdict": "approve",
        })))
        .await
        .unwrap();
    ok(&approved, "the invite's approval");
    ok(
        &paired.request(invite(20, "r-invite-done")).await.unwrap(),
        "the invite's retry, answered from its decided record",
    );
    // Incomplete, one of each family (the refused transport request among them, where the
    // build has no Iroh transport: a refusal is no completion).
    let mut incomplete = vec![
        ("route", route_add("r-route-cut")),
        ("transport", transport_enable("r-transport-cut")),
        ("runner-local", trust_issuer(&controller, "r-trust-cut")),
    ];
    for (family, request) in &incomplete {
        cut.store(true, Ordering::SeqCst);
        let stopped = owner.request(request.clone()).await.unwrap();
        assert_eq!(stopped.code, Code::InternalError, "{family}: {stopped:?}");
    }
    let pending = paired
        .request(invite(21, "r-invite-pending"))
        .await
        .unwrap();
    assert_eq!(pending.code, Code::ApprovalRequired, "{pending:?}");
    if !cfg!(feature = "iroh") {
        incomplete.push(("transport", transport_enable("r-transport-refused")));
    }
    // The raise: every ledger entry with no terminal record is fenced, and only those.
    drop((owner, paired));
    let fenced =
        fence_ledger_for_test(&runner.store, &rig.state_dir(), RestoreEpoch(1), at(60)).unwrap();
    assert_eq!(
        fenced,
        incomplete.len() + 1,
        "the incomplete requests and the pending invite, and nothing else"
    );
    runner.restart();
    let mut owner = runner.connect_local(true).await;
    let mut paired = runner.connect(&controller).await;
    for (family, request) in &completed {
        let again = owner.request(request.clone()).await.unwrap();
        ok(&again, family);
        assert_eq!(again.request_epoch, Some(RestoreEpoch(1)), "{family}");
    }
    let again = paired.request(invite(20, "r-invite-done")).await.unwrap();
    ok(&again, "invite");
    for (family, request) in &incomplete {
        let refused = owner.request(request.clone()).await.unwrap();
        assert_refused(
            &refused,
            &Code::RequestStale,
            reason::RESTORED_BEFORE_COMPLETION,
            request,
            RestoreEpoch(1),
        );
        let _ = family;
    }
    let request = invite(21, "r-invite-pending");
    let refused = paired.request(request.clone()).await.unwrap();
    assert_refused(
        &refused,
        &Code::RequestStale,
        reason::RESTORED_BEFORE_COMPLETION,
        &request,
        RestoreEpoch(1),
    );
    drop((owner, paired));
    runner.stop().await;
}

// --- ⟨M08 W4 U2b-3b⟩ the restore through the real runtime ----------------------------------------

/// A backup of the generation the rig's pointer names, through SQLite, outside the home.
fn take_backup(rig: &Rig, name: &str) -> PathBuf {
    let out = rig._tmp.path().join(name);
    Store::open_read_only(
        &heimdall_store::layout::db_path(&rig.state_dir()).unwrap(),
        Arc::new(NoFaults),
    )
    .unwrap()
    .vacuum_into(&out)
    .unwrap();
    out
}

/// The restore, as `heimdall state restore` runs it: under the runtime's instance lock, the
/// runtime stopped.
fn restore_from(rig: &Rig, backup: &Path) -> heimdall_store::restore::RestoreOutcome {
    let _lock = heimdall_runtime::InstanceLock::try_acquire(&rig.state_dir()).unwrap();
    heimdall_runtime::state_store::restore_locked(
        &rig.state_dir(),
        backup,
        rig.clock_wall(),
        false,
        7 * 24 * HOUR,
    )
    .unwrap()
}

/// The served generation's database made unreadable (the old store lost).
fn lose_the_store(rig: &Rig) {
    let db = heimdall_store::layout::db_path(&rig.state_dir()).unwrap();
    for suffix in ["-wal", "-shm"] {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
    std::fs::write(&db, b"this is no longer a database").unwrap();
}

fn effects(rig: &Rig) -> usize {
    FakeCredentialAdapter::ledger_entries(&rig.effects)
        .map(|e| e.len())
        .unwrap_or(0)
}

/// `request_completed_after_the_backup_is_never_run_again`, both variants (ADR-0014 §3.6;
/// m08-plan U2b). A request completes after the backup; the store is restored from the
/// backup and the runtime started again:
/// - **the old store unreadable:** a retry with the same request ID, bound at receipt to the
///   new epoch, is answered `REQUEST_STALE` / `restored_before_completion` from its fence
///   record, never executed;
/// - **the old store readable:** the retry is answered from the carried terminal record (the
///   real recorded answer), never executed.
///
/// In both, a retry carrying the epoch the request ID was minted under is `REQUEST_STALE` /
/// `restore_epoch_stale`; the fixture adapter's ledger shows no second effect; and a request
/// with a new ID after the fresh hello proceeds. (The local owner has no quarantine to lift;
/// the paired clients' reauthorization is `restore_quarantines_a_later_revoked_management_client`.)
#[tokio::test]
async fn request_completed_after_the_backup_is_never_run_again() {
    for readable in [false, true] {
        let rig = Rig::new();
        rig.start(None).await.stop().await;
        let backup = take_backup(&rig, "backup.db");
        let running = rig.start(None).await;
        let mut owner = attended(&running.control).await;
        let first = owner.request(ensure("r-done")).await.unwrap();
        assert!(first.code.is_success(), "{first:?}");
        assert_eq!(first.request_epoch, Some(RestoreEpoch(0)));
        running.stop().await;
        let executed = effects(&rig);
        assert!(executed > 0, "the request ran once");
        if !readable {
            lose_the_store(&rig);
        }
        let out = restore_from(&rig, &backup);
        assert_eq!(out.carried_forward, readable);
        assert_eq!(out.current.record.restore_epoch, 1);
        assert_eq!(
            out.fenced_requests,
            u64::from(!readable),
            "readable {readable}"
        );

        let running = rig.start(None).await;
        let mut owner = attended(&running.control).await;
        assert_eq!(owner.server().restore_epoch, Some(RestoreEpoch(1)));
        let retry = owner.request(ensure("r-done")).await.unwrap();
        if readable {
            assert_eq!(
                retry.code, first.code,
                "the carried terminal answer: {retry:?}"
            );
            assert_eq!(retry.operation_id, first.operation_id);
        } else {
            let request = ensure("r-done");
            assert_refused(
                &retry,
                &Code::RequestStale,
                reason::RESTORED_BEFORE_COMPLETION,
                &request,
                RestoreEpoch(1),
            );
        }
        owner.keep_epoch(Some(RestoreEpoch(0)));
        let kept = owner.request(ensure("r-done")).await.unwrap();
        assert_refused(
            &kept,
            &Code::RequestStale,
            reason::RESTORE_EPOCH_STALE,
            &ensure("r-done"),
            RestoreEpoch(0),
        );
        assert_eq!(
            effects(&rig),
            executed,
            "readable {readable}: never executed again"
        );
        // A request minted after the fresh hello proceeds: past the epoch and the fence, to
        // the application, which finds the standing policy the restore paused.
        owner.keep_epoch(None);
        let fresh = owner.request(ensure("r-new")).await.unwrap();
        assert_eq!(fresh.code, Code::PolicyPaused, "{fresh:?}");
        assert_eq!(fresh.request_epoch, Some(RestoreEpoch(1)));
        running.stop().await;
    }
}

/// `no_duplicate_effect_when_store_and_ledger_are_both_lost` (ADR-0014 §3.6 step 5): the
/// request completes after the backup, then the store and the request ledger are both
/// destroyed. After the restore the same request ID with its original epoch is refused
/// `REQUEST_STALE` / `restore_epoch_stale`, sent attended and sent non-interactive, and the
/// fixture adapter's ledger shows no second effect; a request minted after a fresh hello
/// proceeds.
#[tokio::test]
async fn no_duplicate_effect_when_store_and_ledger_are_both_lost() {
    let rig = Rig::new();
    rig.start(None).await.stop().await;
    let backup = take_backup(&rig, "backup.db");
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let first = owner.request(ensure("r-lost")).await.unwrap();
    assert!(first.code.is_success(), "{first:?}");
    running.stop().await;
    let executed = effects(&rig);
    lose_the_store(&rig);
    std::fs::remove_file(rig.state_dir().join(LEDGER)).unwrap();
    let out = restore_from(&rig, &backup);
    assert!(!out.carried_forward);
    assert_eq!(
        out.fenced_requests, 0,
        "nothing left to fence: the epoch is the whole fence"
    );
    let running = rig.start(None).await;
    for attended_session in [true, false] {
        let mut c = if attended_session {
            attended(&running.control).await
        } else {
            client(&running.control, InteractionMode::NonInteractive).await
        };
        c.keep_epoch(Some(RestoreEpoch(0)));
        let retry = c.request(ensure("r-lost")).await.unwrap();
        assert_refused(
            &retry,
            &Code::RequestStale,
            reason::RESTORE_EPOCH_STALE,
            &ensure("r-lost"),
            RestoreEpoch(0),
        );
    }
    assert_eq!(effects(&rig), executed, "no second effect");
    // A request minted after a fresh hello proceeds: past the epoch and the fence, to the
    // application, which finds the standing policy the restore paused.
    let mut fresh = attended(&running.control).await;
    let new = fresh.request(ensure("r-after")).await.unwrap();
    assert_eq!(new.code, Code::PolicyPaused, "{new:?}");
    assert_eq!(new.request_epoch, Some(RestoreEpoch(1)));
    running.stop().await;
    assert_eq!(effects(&rig), executed);
}

/// `old_decision_reference_is_refused_after_restore_and_reauthorization`: a decision raised
/// after the backup, and one pending in it, are both closed by the restore under the epoch
/// they were minted in; approving either reference afterwards is refused `DECISION_STALE` /
/// `restore_epoch_stale`, and nothing is decided. (With the replaced store lost, a reference
/// minted after the backup has no record at all; that answer is the escalated U2b-3a item 5.)
#[tokio::test]
async fn old_decision_reference_is_refused_after_restore_and_reauthorization() {
    let rig = Rig::new();
    let decision = |n: u8| heimdall_domain::decision::DecisionRecord {
        id: DecisionId::from_random_bytes([n; 16]),
        kind: heimdall_domain::decision::DecisionKind::WidenPolicy {
            action: heimdall_contract::request::PolicyAction::Resume {
                policy_id: Some(PolicyId::parse("pol").unwrap()),
                target: None,
            },
        },
        generation: heimdall_domain::policy::AuthorityGeneration(0),
        created_at: t0(),
        expires_at: at(24 * 3600),
        state: heimdall_domain::decision::DecisionState::Pending,
        decided_at: None,
    };
    rig.start(None).await.stop().await;
    rig.store()
        .transaction(|tx| tx.insert_decision(&decision(1)))
        .unwrap();
    let backup = take_backup(&rig, "backup.db");
    rig.store()
        .transaction(|tx| tx.insert_decision(&decision(2)))
        .unwrap();
    let out = restore_from(&rig, &backup);
    assert_eq!(out.ended.decisions_closed, vec![decision(1).id]);
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    for n in [1u8, 2] {
        let approve: Request = serde_json::from_value(serde_json::json!({
            "op": "decide", "decision_id": decision(n).id, "verdict": "approve",
        }))
        .unwrap();
        let env = owner.request(approve).await.unwrap();
        assert_eq!(env.code, Code::DecisionStale, "decision {n}: {env:?}");
        assert_eq!(
            error_of(&env).error.reason.as_deref(),
            Some(reason::RESTORE_EPOCH_STALE),
            "decision {n}"
        );
    }
    running.stop().await;
    for n in [1u8, 2] {
        let record = rig
            .read_only()
            .transaction(|tx| tx.decision(&decision(n).id))
            .unwrap()
            .unwrap();
        assert_eq!(
            record.state,
            heimdall_domain::decision::DecisionState::Stale,
            "decision {n} was never approved"
        );
    }
}

/// `restore_keeps_a_later_revoked_grant_ended`, through the runtime: a grant active in the
/// backup and revoked after it stays ended after the restore and the restart, with its
/// tombstone; a retry of the request that made it is answered from its record and makes no
/// new grant; the adapter runs nothing again. (The binding endpoint's refusal of a held
/// connection across a restart is `adversarial_stale_signing_handle`'s; a restore restarts the
/// runtime in the same way.)
#[tokio::test]
async fn restore_keeps_a_later_revoked_grant_ended() {
    let rig = Rig::new();
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let made = owner.request(ensure("r-grant")).await.unwrap();
    assert!(made.code.is_success(), "{made:?}");
    running.stop().await;
    let grant = rig
        .read_only()
        .transaction(|tx| tx.live_grants())
        .unwrap()
        .into_iter()
        .next()
        .expect("the grant is live")
        .id;
    let backup = take_backup(&rig, "backup.db");
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let revoke: Request = serde_json::from_value(serde_json::json!({
        "op": "revoke", "grant_id": grant, "request_id": "r-revoke",
    }))
    .unwrap();
    let revoked = owner.request(revoke).await.unwrap();
    assert!(revoked.code.is_success(), "{revoked:?}");
    running.stop().await;
    let executed = effects(&rig);
    restore_from(&rig, &backup);
    let running = rig.start(None).await;
    let mut owner = attended(&running.control).await;
    let retry = owner.request(ensure("r-grant")).await.unwrap();
    assert_eq!(
        retry.operation_id, made.operation_id,
        "answered from its record"
    );
    running.stop().await;
    let store = rig.read_only();
    store
        .transaction(|tx| {
            assert_eq!(
                tx.grant(&grant)?.unwrap().state,
                heimdall_contract::GrantState::Revoked
            );
            assert!(tx.tombstone(&grant)?.is_some());
            assert!(tx.live_grants()?.is_empty(), "no grant came back");
            Ok(())
        })
        .unwrap();
    assert_eq!(effects(&rig), executed, "nothing ran again");
}

/// A paired session's hello of `client`, its refusal kept (`Runner::connect` unwraps it).
async fn hello_of(
    runner: &Runner,
    client: &ClientId,
) -> Result<ControlClient<tokio::io::DuplexStream>, Envelope<ErrorData>> {
    let mut capabilities = client_capabilities();
    capabilities.insert(capability::REMOTE_CONTROL_V1.to_owned());
    let (client_end, server_end) = tokio::io::duplex(1 << 20);
    let conn = ControlConnection::new(server_end, ConnectionLimits::default())
        .with_server_identity(
            env_id(),
            PeerInfo {
                name: "runner".into(),
                version: "0".into(),
            },
        );
    let (dispatcher, stop) = (runner.dispatcher.clone(), runner.stop.clone());
    let session = tokio::spawn(async move {
        let _ = conn.serve(paired_principal(), dispatcher, stop).await;
    });
    runner.sessions.lock().unwrap().push(session);
    ControlClient::handshake_hello(
        client_end,
        ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client: PeerInfo {
                name: "restore-test".into(),
                version: "0".into(),
            },
            capabilities,
            required: BTreeSet::new(),
            interaction: InteractionMode::NonInteractive,
            remote_client: Some(client.clone()),
        },
    )
    .await
    .map_err(|e| heimdall_ipc::session::transport_failure_envelope(&e, false))
}

fn refused_with(
    hello: Result<ControlClient<tokio::io::DuplexStream>, Envelope<ErrorData>>,
    why: &str,
) {
    match hello {
        Ok(_) => panic!("the hello was admitted, expected {why}"),
        Err(env) => {
            assert_eq!(env.data.error.reason.as_deref(), Some(why), "{env:?}");
            assert_eq!(env.data.error.effect_status, EffectStatus::None);
        }
    }
}

/// The rig's flat store adopted into the generation layout, as a runtime's first start does.
fn adopt(rig: &Rig) {
    drop(
        heimdall_runtime::state_store::open_locked(&rig.state_dir(), Arc::new(NoFaults), t0())
            .unwrap(),
    );
}

/// `restore_quarantines_a_later_revoked_management_client`, through a runner's paired
/// sessions. A client revoked after the backup stays refused: by its carried tombstone
/// (`client_revoked`) when the replaced store is readable, and quarantined
/// (`client_quarantined_after_restore`) when it is not. Every other recovered client is
/// quarantined, its hello refused, until the owner reauthorizes it at the runner. After the
/// reauthorization a fresh hello is admitted and reports the new epoch, and the client's
/// pre-restore request ID stays refused: by its epoch, and, retried without one, by its
/// carried record (readable) or its fence (lost) — never run again.
#[tokio::test]
async fn restore_quarantines_a_later_revoked_management_client() {
    use heimdall_store::ext_m06::RevocationCause;
    for readable in [true, false] {
        let rig = Rig::new();
        adopt(&rig);
        let runner = Runner::start(&rig).await;
        let revoked = runner.seed(1, Role::Requester, true);
        let kept = runner.seed(2, Role::Requester, true);
        runner.stop().await;
        let backup = take_backup(&rig, "backup.db");
        let runner = Runner::start(&rig).await;
        let mut k = runner.connect(&kept).await;
        let first = k.request(ensure("r-kept")).await.unwrap();
        assert_eq!(first.request_epoch, Some(RestoreEpoch(0)));
        runner.stop().await;
        rig.store()
            .transaction(|tx| tx.revoke_remote_client(&revoked, RevocationCause::Revoked, at(60)))
            .unwrap();
        if !readable {
            lose_the_store(&rig);
        }
        let out = restore_from(&rig, &backup);
        assert_eq!(out.carried_forward, readable);
        let runner = Runner::start(&rig).await;
        refused_with(
            hello_of(&runner, &revoked).await,
            if readable {
                reason::CLIENT_REVOKED
            } else {
                reason::CLIENT_QUARANTINED_AFTER_RESTORE
            },
        );
        refused_with(
            hello_of(&runner, &kept).await,
            reason::CLIENT_QUARANTINED_AFTER_RESTORE,
        );
        assert!(heimdall_runtime::paired::reauthorize_client(&runner.store, &kept).unwrap());
        if readable {
            assert!(
                !heimdall_runtime::paired::reauthorize_client(&runner.store, &revoked).unwrap(),
                "a revoked client is never reauthorized"
            );
        }
        let mut k = hello_of(&runner, &kept)
            .await
            .expect("admitted after reauthorization");
        assert_eq!(k.server().restore_epoch, Some(RestoreEpoch(1)));
        k.keep_epoch(Some(RestoreEpoch(0)));
        let stale = k.request(ensure("r-kept")).await.unwrap();
        assert_refused(
            &stale,
            &Code::RequestStale,
            reason::RESTORE_EPOCH_STALE,
            &ensure("r-kept"),
            RestoreEpoch(0),
        );
        k.keep_epoch(None);
        let unstamped = k.request(ensure("r-kept")).await.unwrap();
        if readable {
            assert_eq!(
                unstamped.operation_id, first.operation_id,
                "its carried record"
            );
            assert_eq!(unstamped.code, first.code);
        } else {
            assert_refused(
                &unstamped,
                &Code::RequestStale,
                reason::RESTORED_BEFORE_COMPLETION,
                &ensure("r-kept"),
                RestoreEpoch(1),
            );
        }
        runner.stop().await;
    }
}

/// `restore_voids_consumed_and_expired_invitations`, through a runner's paired sessions: an
/// invitation joined after the backup, and one that expired after it, cannot be joined, and a
/// join's replay is refused with them. A recovered pending client's hello, the only one that
/// may send a join, is refused `invitation_void_after_restore`, or, for the expired one when
/// the replaced store is readable, by its carried tombstone (`invitation_expired`).
#[tokio::test]
async fn restore_voids_consumed_and_expired_invitations() {
    use heimdall_store::ext_m06::{JoinRecord, RevocationCause};
    for readable in [true, false] {
        let rig = Rig::new();
        adopt(&rig);
        let runner = Runner::start(&rig).await;
        let joined = runner.seed(1, Role::Requester, false);
        let expired = runner.seed(2, Role::Requester, false);
        runner.stop().await;
        let backup = take_backup(&rig, "backup.db");
        rig.store()
            .transaction(|tx| {
                // The join names the generation its invitation recorded.
                let inv = tx
                    .remote_invitation(&InvitationId::from_random_bytes([1; 16]))?
                    .unwrap();
                tx.activate_remote_client(&JoinRecord {
                    environment: env_id(),
                    invitation: inv.invitation.clone(),
                    client: joined.clone(),
                    role: Role::Requester,
                    generation: inv.generation,
                    joined_at: at(120),
                })?;
                tx.revoke_remote_client(&expired, RevocationCause::InvitationExpired, at(2000))
                    .map(drop)
            })
            .unwrap();
        if !readable {
            lose_the_store(&rig);
        }
        restore_from(&rig, &backup);
        let runner = Runner::start(&rig).await;
        refused_with(
            hello_of(&runner, &joined).await,
            reason::INVITATION_VOID_AFTER_RESTORE,
        );
        refused_with(
            hello_of(&runner, &expired).await,
            if readable {
                reason::INVITATION_EXPIRED
            } else {
                reason::INVITATION_VOID_AFTER_RESTORE
            },
        );
        runner.stop().await;
    }
}

/// `reset_then_restart_serves_the_new_generation` (ADR-0014 §3.6, "Reset is the same
/// switch"): after a reset, the restarted runtime serves the new, empty generation: its hello
/// names the new environment at epoch 0, and the old generation is kept, whole, with the old
/// identity.
#[tokio::test]
async fn reset_then_restart_serves_the_new_generation() {
    let rig = Rig::new();
    let running = rig.start(None).await;
    let old = client(&running.control, InteractionMode::NonInteractive)
        .await
        .server()
        .environment_id
        .clone();
    running.stop().await;
    assert_eq!(old, env_id());
    let out = {
        let _lock = heimdall_runtime::InstanceLock::try_acquire(&rig.state_dir()).unwrap();
        heimdall_runtime::state_store::reset_locked(&rig.state_dir(), rig.clock_wall(), false)
            .unwrap()
    };
    let running = rig.start(None).await;
    let served = client(&running.control, InteractionMode::NonInteractive).await;
    assert_ne!(served.server().environment_id, old, "a new identity");
    assert_eq!(
        served.server().environment_id.as_str(),
        out.current.record.environment_id
    );
    assert_eq!(served.server().restore_epoch, Some(RestoreEpoch(0)));
    drop(served);
    running.stop().await;
    let kept = out.left_behind.expect("the replaced generation");
    let db = rig
        .state_dir()
        .join("generations")
        .join(kept.as_str())
        .join(heimdall_store::layout::DB_FILE);
    let kept_env = Store::open_read_only(&db, Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| tx.self_environment())
        .unwrap();
    assert_eq!(
        kept_env,
        Some(old),
        "the old generation keeps the old identity"
    );
}
