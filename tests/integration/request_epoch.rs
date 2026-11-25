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
struct Rig {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    clock: Arc<VirtualClock>,
    effects: PathBuf,
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
}

impl Runner {
    /// The rig's installation, made a runner (`remote init`'s marker), and served.
    async fn start(rig: &Rig) -> Runner {
        let store = Arc::new(rig.store());
        assert_eq!(init_runner(&store).unwrap(), env_id());
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: rig.clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env_id(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let dispatcher = Self::serve(&store, &ops, &rig.clock, &rig.state_dir(), &stop);
        Runner {
            store,
            ops,
            clock: rig.clock.clone(),
            state_dir: rig.state_dir(),
            stop,
            dispatcher,
        }
    }

    fn serve(
        store: &Arc<Store>,
        ops: &Operations,
        clock: &Arc<VirtualClock>,
        state_dir: &Path,
        stop: &CancellationToken,
    ) -> OperationsDispatcher {
        let fence = Arc::new(RequestFence::open(Arc::clone(store), state_dir).unwrap());
        let runner = PairedRunner::new(
            Arc::clone(store),
            ops.clone(),
            clock.clone(),
            RunnerOptions::default(),
        );
        OperationsDispatcher::new(
            ops.clone(),
            EventRelay::spawn(ops, stop.clone()),
            clock.clone(),
        )
        .with_request_fence(fence)
        .with_runner(Arc::new(runner))
    }

    /// The runtime started again on the same state: its request fence reads the epoch now.
    fn restart(&mut self) {
        self.dispatcher = Self::serve(
            &self.store,
            &self.ops,
            &self.clock,
            &self.state_dir,
            &self.stop,
        );
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
        tokio::spawn(async move {
            let _ = conn.serve(paired_principal(), dispatcher, stop).await;
        });
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
}
