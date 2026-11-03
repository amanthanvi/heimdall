//! W3-U5: setup and catalog end to end (m02-plan U5, M2-D08): a real
//! `heimdall_runtime::service::Service` (store, restart recovery, the wired projection
//! writer and its cleaner), real control sessions (`ControlConnection` and
//! `ControlClient` over in-memory duplex streams) and the real dispatcher.
//!
//! Everything lives in a `heimdall_testkit::home::ScratchHome`: the runtime's
//! directories, the scratch `~/.ssh` the writer is configured with
//! (`SshPaths::with_test_override`), and Heimdall's scratch configuration directory.
//! Adopted keys are synthetic public keys generated per run; no client runs and no
//! agent is contacted.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use heimdall_app::{Attendance, Caller};
use heimdall_contract::catalog::{
    CatalogRequest, DestinationDefinitionSpec, DestinationSpec, IdentitySourceSpec, IdentitySpec,
};
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, EnvironmentId, IdentityId, RequestId,
};
use heimdall_contract::ipc::{PeerInfo, PrincipalInfo, capability};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, InteractionMode, Request, Verdict,
};
use heimdall_contract::setup::{
    PlanDigest, PreviewIntent, ProjectionItem, SetupPlan, SetupRequest,
};
use heimdall_contract::{Code, OperationState};
use heimdall_domain::idempotency::IdempotencyKey;
use heimdall_domain::operation::OperationKind;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::SyncStatus;
use heimdall_ipc::session::{
    ConnectionLimits, ControlClient, ControlConnection, server_capabilities,
};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::ProjectionConfig;
use heimdall_runtime::config::{Config, Paths};
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
use heimdall_testkit::home::ScratchHome;
use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};
use tokio_util::sync::CancellationToken;

fn t0() -> heimdall_contract::Timestamp {
    "2026-11-03T09:00:00Z".parse().unwrap()
}

fn rid(s: &str) -> RequestId {
    RequestId::parse(s).unwrap()
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

/// A synthetic `ssh-ed25519` public key over 32 random bytes (no private key exists).
fn synthetic_public_key() -> String {
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    for _ in 0..4 {
        blob.extend(heimdall_app::ids::random_u64().unwrap().to_le_bytes());
    }
    format!("ssh-ed25519 {}", b64(&blob))
}

/// One scratch runtime: a `Service` over the scratch home.
struct Rig {
    home: ScratchHome,
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
}

impl Rig {
    fn new() -> Rig {
        let home = ScratchHome::new();
        std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
        Rig {
            home,
            clock: VirtualClock::at(t0()),
            sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        }
    }

    fn projection(&self) -> ProjectionConfig {
        let paths = SshPaths::with_test_override(
            self.home.git_home.clone(),
            self.home.root.join("etc-ssh"),
        );
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
        c.env = Env::from_vars([
            ("HOME", self.home.git_home.display().to_string()),
            ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ]);
        c
    }

    async fn start(&self, wiring: ProjectionWiring) -> Service {
        self.start_configured(wiring, Config::default()).await
    }

    async fn start_configured(&self, wiring: ProjectionWiring, config: Config) -> Service {
        let mut o = ServiceOptions::with_clock(self.clock.clone(), self.sync.clone());
        o.projection = wiring;
        o.endpoint_prefix = "hmtest-".to_owned();
        Service::start_with(
            Paths::under(&self.home.root.join("rt")),
            config,
            o,
            CancellationToken::new(),
        )
        .await
        .unwrap()
    }

    async fn service(&self) -> Service {
        self.start(ProjectionWiring::Config(Box::new(self.projection())))
            .await
    }
}

/// A real control session to `service`'s operations through the real dispatcher.
struct Session {
    client: ControlClient<tokio::io::DuplexStream>,
    _served: tokio::task::JoinHandle<()>,
}

impl Session {
    async fn open(
        service: &Service,
        required: BTreeSet<String>,
        interaction: InteractionMode,
    ) -> Result<Session, Code> {
        let (server, stream) = tokio::io::duplex(1 << 20);
        let ops = service.operations().clone();
        let relay = EventRelay::spawn(&ops, CancellationToken::new());
        let dispatcher = OperationsDispatcher::new(
            ops,
            relay,
            Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
        );
        let env = service.environment().clone();
        let served = tokio::spawn(async move {
            let _ = ControlConnection::new(server, ConnectionLimits::default())
                .with_server_identity(
                    env,
                    PeerInfo {
                        name: "heimdall".into(),
                        version: "test".into(),
                    },
                )
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                )
                .await;
        });
        let client = ControlClient::handshake(
            stream,
            PeerInfo {
                name: "heimdall-u5-test".into(),
                version: "0".into(),
            },
            required,
            interaction,
        )
        .await
        .map_err(|_| Code::SchemaUnsupported)?;
        Ok(Session {
            client,
            _served: served,
        })
    }

    async fn setup_session(service: &Service, interaction: InteractionMode) -> Session {
        Session::open(
            service,
            [capability::SETUP_V1.to_owned()].into_iter().collect(),
            interaction,
        )
        .await
        .unwrap()
    }

    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        let env = self.client.request(request).await.unwrap();
        assert_no_canary(&serde_json::to_string(&env).unwrap());
        env
    }
}

fn error_of(env: &Envelope<serde_json::Value>) -> &serde_json::Value {
    &env.data["error"]
}

async fn adopt_and_alias(s: &mut Session, endpoint: EndpointRef) -> IdentityId {
    let env = s
        .request(Request::Catalog(CatalogRequest::AdoptIdentity {
            identity: IdentitySpec {
                source: IdentitySourceSpec::NativeAgent { endpoint },
                public_key: synthetic_public_key(),
                label: None,
            },
            request_id: rid("r-adopt"),
        }))
        .await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    let identity = IdentityId::parse(env.data["identity_id"].as_str().unwrap()).unwrap();
    let env = s
        .request(Request::Catalog(CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-alpha").unwrap(),
                alias: "alpha".to_owned(),
                definition: DestinationDefinitionSpec::Managed {
                    hostname: "alpha.example.invalid".to_owned(),
                    port: None,
                    account: AccountName::parse("fixture").unwrap(),
                    identity: identity.clone(),
                },
                label: None,
            },
            request_id: rid("r-dest"),
        }))
        .await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    identity
}

async fn preview(s: &mut Session, intent: PreviewIntent) -> SetupPlan {
    let env = s
        .request(Request::Setup(SetupRequest::Preview { intent }))
        .await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    serde_json::from_value(env.data).unwrap()
}

fn apply(digest: &PlanDigest, request: &str) -> Request {
    Request::Setup(SetupRequest::Apply {
        plan_digest: digest.clone(),
        request_id: rid(request),
    })
}

#[tokio::test]
async fn e2e_setup_preview_apply_decide_restart_through_dispatcher() {
    let rig = Rig::new();
    let service = rig.service().await;
    let mut s = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let endpoint = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: rig
            .home
            .root
            .join("fixture-agent.sock")
            .display()
            .to_string(),
    };
    adopt_and_alias(&mut s, endpoint).await;
    let plan = preview(&mut s, PreviewIntent::Apply { include_git: false }).await;
    assert!(plan.consent.decision_required);
    let env = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(env.code, Code::InteractionRequired);
    let decision = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
    let op = env.operation_id.clone().unwrap();
    assert!(!rig.home.config_dir.join("ssh_config").exists());
    drop(s);
    drop(service);

    // Restart: the operation still waits; an attended session decides it.
    let service = rig.service().await;
    let mut s = Session::setup_session(&service, InteractionMode::Interactive).await;
    let attend = s.client.attend().await.unwrap();
    assert_eq!(attend.code, Code::Ok);
    let env = s
        .request(Request::Decide(DecideRequest {
            decision_id: DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        }))
        .await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    let replay = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(replay.code, Code::Ok, "{:?}", replay.data);
    assert_eq!(replay.operation_id, Some(op.clone()));
    assert_eq!(replay.data["items"][0]["outcome"], "applied");
    assert!(rig.home.config_dir.join("ssh_config").exists());
    let inspect = s
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Projections,
            preview: None,
        }))
        .await;
    assert_eq!(inspect.code, Code::Ok);
    assert!(
        !inspect.data["projections"].as_array().unwrap().is_empty(),
        "{:?}",
        inspect.data
    );
    drop(s);
    drop(service);

    // A second restart reconciles nothing and re-applies nothing: the result stands.
    let service = rig.service().await;
    let mut s = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let again = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(again.code, Code::Ok);
    assert_eq!(again.data, replay.data);
}

#[tokio::test]
async fn e2e_setup_without_capability_is_schema_unsupported() {
    let rig = Rig::new();
    let service = rig.service().await;
    assert!(server_capabilities().contains(capability::SETUP_V1));
    let preview = Request::Setup(SetupRequest::Preview {
        intent: PreviewIntent::Apply { include_git: false },
    });
    let catalog = Request::Catalog(CatalogRequest::RemoveIdentity {
        id: IdentityId::from_random_bytes([1; 16]),
        request_id: rid("r-x"),
    });
    // A session that negotiated `setup/1` is dispatched.
    let mut negotiated = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let env = negotiated.request(preview.clone()).await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    drop(negotiated);
    // Raw hello without `setup/1` in the offer.
    let (server, stream) = tokio::io::duplex(1 << 16);
    let ops = service.operations().clone();
    let relay = EventRelay::spawn(&ops, CancellationToken::new());
    let dispatcher = OperationsDispatcher::new(
        ops,
        relay,
        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
    );
    let env_id: EnvironmentId = service.environment().clone();
    let served = tokio::spawn(async move {
        let _ = ControlConnection::new(server, ConnectionLimits::default())
            .with_server_identity(
                env_id,
                PeerInfo {
                    name: "heimdall".into(),
                    version: "test".into(),
                },
            )
            .serve(
                PrincipalInfo::OsUserUnix { uid: 501 },
                dispatcher,
                CancellationToken::new(),
            )
            .await;
    });
    let mut raw = RawClient::handshake(stream, without_setup()).await;
    for r in [preview, catalog] {
        let env = raw.request(r).await;
        assert_eq!(env.code, Code::SchemaUnsupported, "{:?}", env.data);
    }
    drop(raw);
    let _ = served.await;
}

fn without_setup() -> BTreeSet<String> {
    server_capabilities()
        .into_iter()
        .filter(|c| c != capability::SETUP_V1)
        .collect()
}

/// A minimal client whose hello offers exactly `capabilities` (the production client
/// always offers every capability it knows).
struct RawClient {
    stream: tokio::io::DuplexStream,
    buf: Vec<u8>,
    seq: u64,
}

impl RawClient {
    async fn handshake(
        mut stream: tokio::io::DuplexStream,
        capabilities: BTreeSet<String>,
    ) -> RawClient {
        use heimdall_contract::ipc::{ClientHello, ClientMessage, ServerMessage};
        use heimdall_ipc::frame::{CONTROL_LIMIT, encode_frame};
        use tokio::io::AsyncWriteExt as _;
        let hello = ClientMessage::Hello(ClientHello {
            protocol: heimdall_contract::PROTOCOL_VERSION,
            schema_version: heimdall_contract::SchemaVersion::current(),
            client: PeerInfo {
                name: "heimdall-u5-raw".into(),
                version: "0".into(),
            },
            capabilities,
            required: BTreeSet::new(),
            interaction: InteractionMode::NonInteractive,
        });
        stream
            .write_all(&encode_frame(&hello, CONTROL_LIMIT).unwrap())
            .await
            .unwrap();
        let mut me = RawClient {
            stream,
            buf: Vec::new(),
            seq: 0,
        };
        match me.next().await {
            ServerMessage::Hello(h) => assert!(!h.capabilities.contains(capability::SETUP_V1)),
            _ => panic!("the hello was refused"),
        }
        me
    }

    async fn next(&mut self) -> heimdall_contract::ipc::ServerMessage {
        use heimdall_ipc::frame::{CONTROL_LIMIT, decode_frame};
        use tokio::io::AsyncReadExt as _;
        loop {
            if let Some((msg, used)) = decode_frame(&self.buf, CONTROL_LIMIT).unwrap() {
                self.buf.drain(..used);
                return msg;
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the server closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        use heimdall_contract::ipc::{ClientMessage, ServerMessage};
        use heimdall_ipc::frame::{CONTROL_LIMIT, encode_frame};
        use tokio::io::AsyncWriteExt as _;
        self.seq += 1;
        let seq = self.seq;
        let frame = encode_frame(&ClientMessage::Request { seq, request }, CONTROL_LIMIT).unwrap();
        self.stream.write_all(&frame).await.unwrap();
        loop {
            if let ServerMessage::Response {
                in_reply_to,
                envelope,
            } = self.next().await
                && in_reply_to == seq
            {
                return envelope;
            }
        }
    }
}

fn key_of(kind: OperationKind, request: &str) -> IdempotencyKey {
    IdempotencyKey {
        caller: owner_ctx(),
        kind,
        request_id: rid(request),
    }
}

/// §12.8 item 6: two setup requests sent at once on two sessions admit exactly one;
/// the other gets `setup_in_progress` naming the winner and writes nothing. Apply
/// against apply, rollback against apply, and repair against apply.
#[tokio::test]
async fn simultaneous_setup_admissions_admit_exactly_one() {
    const ROUNDS: usize = 200;
    let rig = Rig::new();
    let service = rig.service().await;
    let mut setup = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let endpoint = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: rig
            .home
            .root
            .join("fixture-agent.sock")
            .display()
            .to_string(),
    };
    let identity = adopt_and_alias(&mut setup, endpoint).await;
    // Every plan of the race needs a decision, so the winner stays open: the
    // projection is applied once (approved), a second alias joins the catalog (the
    // apply and the rerender add it), and the user's configuration gains an inherited
    // HostName that a rollback would expose.
    let first = preview(&mut setup, PreviewIntent::Apply { include_git: false }).await;
    let env = setup.request(apply(&first.plan_digest, "r-first")).await;
    let d = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
    service
        .operations()
        .decide(
            &attended(),
            DecideRequest {
                decision_id: DecisionId::parse(&d).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap();
    let env = setup
        .request(Request::Catalog(CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-beta").unwrap(),
                alias: "beta".to_owned(),
                definition: DestinationDefinitionSpec::Managed {
                    hostname: "beta.example.invalid".to_owned(),
                    port: None,
                    account: AccountName::parse("fixture").unwrap(),
                    identity,
                },
                label: None,
            },
            request_id: rid("r-dest-beta"),
        }))
        .await;
    assert_eq!(env.code, Code::Ok);
    let mut user = std::fs::read_to_string(&rig.home.user_config).unwrap();
    user.push_str("\nHost *\n    HostName inherited.example.invalid\n");
    std::fs::write(&rig.home.user_config, user).unwrap();
    let apply_plan = preview(&mut setup, PreviewIntent::Apply { include_git: false }).await;
    let rollback_plan = preview(
        &mut setup,
        PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        },
    )
    .await;
    let repair_plan = preview(
        &mut setup,
        PreviewIntent::Repair {
            conflict: heimdall_contract::setup::ConflictKind::ManagedFileEdited,
            resolution: heimdall_contract::setup::RepairResolution::Rerender,
            operation: None,
        },
    )
    .await;
    for p in [&apply_plan, &rollback_plan, &repair_plan] {
        assert!(p.consent.decision_required, "{:?}", p.intent);
    }
    let mut a = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let mut b = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    let store = service.store().clone();
    let ops = service.operations().clone();
    for round in 0..ROUNDS {
        let (kind_b, other) = match round % 3 {
            0 => (
                OperationKind::SetupApply,
                apply(&apply_plan.plan_digest, &format!("r-b-{round}")),
            ),
            1 => (
                OperationKind::SetupRollback,
                Request::Setup(SetupRequest::Rollback {
                    plan_digest: rollback_plan.plan_digest.clone(),
                    request_id: rid(&format!("r-b-{round}")),
                }),
            ),
            _ => (
                OperationKind::SetupRepair,
                Request::Setup(SetupRequest::Repair {
                    plan_digest: repair_plan.plan_digest.clone(),
                    request_id: rid(&format!("r-b-{round}")),
                }),
            ),
        };
        let first = apply(&apply_plan.plan_digest, &format!("r-a-{round}"));
        let events_before = store
            .transaction(|tx| {
                tx.stored_events_after(
                    service.environment(),
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    1_000_000,
                )
            })
            .unwrap()
            .events
            .len();
        let decisions_before = store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .len();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (ba, bb) = (barrier.clone(), barrier);
        let ((ea, a2), (eb, b2)) = tokio::join!(
            async move {
                ba.wait().await;
                let e = a.request(first).await;
                (e, a)
            },
            async move {
                bb.wait().await;
                let e = b.request(other).await;
                (e, b)
            }
        );
        a = a2;
        b = b2;
        let admitted: Vec<&Envelope<serde_json::Value>> = [&ea, &eb]
            .into_iter()
            .filter(|e| e.operation_id.is_some())
            .collect();
        assert_eq!(
            admitted.len(),
            1,
            "round {round}: {:?} {:?}",
            ea.code,
            eb.code
        );
        let winner = admitted[0].operation_id.clone().unwrap();
        let (loser, loser_key) = if ea.operation_id.is_some() {
            (&eb, key_of(kind_b, &format!("r-b-{round}")))
        } else {
            (
                &ea,
                key_of(OperationKind::SetupApply, &format!("r-a-{round}")),
            )
        };
        assert_eq!(loser.code, Code::ConfigConflict, "round {round}");
        assert_eq!(error_of(loser)["reason"], reason::SETUP_IN_PROGRESS);
        assert_eq!(
            error_of(loser)["next"]["operation_id"],
            serde_json::json!(winner)
        );
        assert!(
            store
                .transaction(|tx| tx.idempotency_record(&loser_key))
                .unwrap()
                .is_none(),
            "round {round}: the loser left an idempotency record"
        );
        let open = store
            .transaction(|tx| tx.open_setup_operations(service.environment()))
            .unwrap();
        assert_eq!(open, vec![winner.clone()], "round {round}");
        let pending = store.transaction(|tx| tx.pending_decisions()).unwrap();
        assert_eq!(
            pending.len(),
            decisions_before + 1,
            "round {round}: one decision"
        );
        let events_after = store
            .transaction(|tx| {
                tx.stored_events_after(
                    service.environment(),
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    1_000_000,
                )
            })
            .unwrap()
            .events;
        assert!(
            events_after[events_before..]
                .iter()
                .all(|e| e.event.operation_id.as_ref() == Some(&winner)),
            "round {round}: the loser wrote an event"
        );
        // Settle the winner (deny its decision) before the next round.
        let d = pending
            .into_iter()
            .find(|d| {
                matches!(&d.kind, heimdall_domain::decision::DecisionKind::ApplyProjection { operation, .. } if *operation == winner)
            })
            .unwrap();
        ops.decide(
            &attended(),
            DecideRequest {
                decision_id: d.id,
                verdict: Verdict::Deny,
            },
        )
        .await
        .unwrap();
        let state = store
            .transaction(|tx| tx.operation(&winner))
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, OperationState::Failed);
    }
}

// --- catalog → ensure → bind through the dispatcher (existing-access adapters) ----------

impl Rig {
    async fn existing_access(&self) -> Service {
        let mut o = ServiceOptions::with_clock(self.clock.clone(), self.sync.clone());
        o.projection = ProjectionWiring::Config(Box::new(self.projection()));
        o.existing_access = true;
        o.endpoint_prefix = "hmtest-".to_owned();
        Service::start_with(
            Paths::under(&self.home.root.join("rt")),
            Config::default(),
            o,
            CancellationToken::new(),
        )
        .await
        .unwrap()
    }
}

/// The environment's permissions and a standing policy covering `dst-alpha`/`fixture`
/// for profile `work` (seeded through the store, as M01's suites do).
fn seed_policy(service: &Service) {
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::scope::Scope;
    let env = service.environment().clone();
    service
        .store()
        .transaction(|tx| {
            tx.upsert_environment(&EnvironmentRecord {
                id: env.clone(),
                device: heimdall_contract::ids::DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: heimdall_contract::ids::PolicyId::parse("pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: heimdall_contract::ids::ProfileId::parse("work").unwrap(),
                    workspace: None,
                    scope: Scope {
                        pairs: [pair()].into_iter().collect(),
                        capabilities: [heimdall_contract::request::Capability::SshAuthentication]
                            .into_iter()
                            .collect(),
                    },
                    environments: [env.clone()].into_iter().collect(),
                    max_window: std::time::Duration::from_secs(2 * 3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                },
                false,
            )
        })
        .unwrap();
}

fn pair() -> heimdall_contract::request::AccessPairRef {
    heimdall_contract::request::AccessPairRef {
        destination: DestinationId::parse("dst-alpha").unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    }
}

fn ensure(request: &str, work: &str, interaction: InteractionMode) -> Request {
    Request::Ensure(heimdall_contract::request::EnsureRequest {
        profile: heimdall_contract::ids::ProfileId::parse("work").unwrap(),
        profile_revision: None,
        scope: [pair()].into_iter().collect(),
        environment: None,
        work_id: heimdall_contract::ids::WorkId::parse(work).unwrap(),
        until: None,
        required_capabilities: heimdall_contract::request::RequiredCapabilities::default(),
        request_id: rid(request),
        interaction,
        wait: heimdall_contract::request::WaitMode::Sync { timeout_ms: 30_000 },
    })
}

fn bind(binding: &str, request: &str) -> Request {
    Request::Bind(heimdall_contract::request::BindRequest {
        binding_id: heimdall_contract::ids::BindingId::parse(binding).unwrap(),
        form: heimdall_contract::request::BindForm::Materialize,
        request_id: rid(request),
    })
}

/// Catalog an identity at the scratch decoy agent, the managed alias `alpha` and the
/// profile `work`; apply the projection (approved).
async fn catalog_and_project(rig: &Rig, service: &Service) -> (IdentityId, EndpointRef) {
    let mut s = Session::setup_session(service, InteractionMode::NonInteractive).await;
    let endpoint = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: rig
            .home
            .decoy_agent()
            .endpoint()
            .locator()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    let identity = adopt_and_alias(&mut s, endpoint.clone()).await;
    let env = s
        .request(Request::Catalog(CatalogRequest::UpsertProfile {
            profile: heimdall_contract::catalog::ProfileSpec {
                id: heimdall_contract::ids::ProfileId::parse("work").unwrap(),
                pairs: [pair()].into_iter().collect(),
                label: None,
            },
            request_id: rid("r-profile"),
        }))
        .await;
    assert_eq!(env.code, Code::Ok, "{:?}", env.data);
    seed_policy(service);
    let plan = preview(&mut s, PreviewIntent::Apply { include_git: false }).await;
    let env = s.request(apply(&plan.plan_digest, "r-apply")).await;
    let d = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
    service
        .operations()
        .decide(
            &attended(),
            DecideRequest {
                decision_id: DecisionId::parse(&d).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap();
    (identity, endpoint)
}

fn pair_of(env: &Envelope<serde_json::Value>) -> serde_json::Value {
    let pairs = env.data["consumer"]["pairs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(pairs.len(), 1, "{:?}", env.data);
    pairs[0].clone()
}

/// The history part of a pair (what `PreparedFacts` keeps).
fn history(p: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "destination": p["destination"],
        "account": p["account"],
        "identity": p["identity"],
        "mechanism": p["mechanism"],
        "endpoint": p["endpoint"],
        "alias": p["alias"],
        "identity_selection": p["identity_selection"],
        "selection_observed_at": p["selection_observed_at"],
    })
}

#[tokio::test]
async fn e2e_catalog_then_ensure_bind_carry_pairs_and_selection() {
    let rig = Rig::new();
    let service = rig.existing_access().await;
    let (identity, endpoint) = catalog_and_project(&rig, &service).await;
    let mut ni = Session::setup_session(&service, InteractionMode::NonInteractive).await;
    // No declaration: the interaction is unknown, so a non-interactive ensure is
    // refused and an interactive one proceeds (ADR-0007 §7).
    let refused = ni
        .request(ensure(
            "r-ensure-ni",
            "w-0",
            InteractionMode::NonInteractive,
        ))
        .await;
    assert_eq!(refused.code, Code::InteractionRequired);
    assert_eq!(error_of(&refused)["reason"], "interaction_unknown");
    let mut s = Session::setup_session(&service, InteractionMode::Interactive).await;
    let ensured = s
        .request(ensure("r-ensure", "w-1", InteractionMode::Interactive))
        .await;
    assert_eq!(ensured.code, Code::AccessReady, "{:?}", ensured.data);
    assert_eq!(ensured.data["credential_mechanism"], "native_agent");
    let p = pair_of(&ensured);
    assert_eq!(p["identity"], serde_json::json!(identity));
    assert_eq!(p["alias"], "alpha");
    assert_eq!(p["endpoint"], serde_json::json!(endpoint));
    assert!(p.get("identity_selection").is_some());
    let binding = ensured.data["binding_id"].as_str().unwrap().to_owned();
    let bound = s.request(bind(&binding, "r-bind")).await;
    assert_eq!(bound.code, Code::AccessReady, "{:?}", bound.data);
    assert_eq!(history(&pair_of(&bound)), history(&p), "the same history");
    assert_eq!(
        rig.home.decoy_agent().contact_count(),
        0,
        "no agent contact"
    );
}

#[tokio::test]
async fn declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher() {
    for (variant, restart) in [
        ("withdrawn", false),
        ("withdrawn", true),
        ("listing_missing", false),
        ("listing_missing", true),
    ] {
        let rig = Rig::new();
        let mut service = rig.existing_access().await;
        let (identity, _) = catalog_and_project(&rig, &service).await;
        // Declare `none` (attended decision).
        let mut s = Session::setup_session(&service, InteractionMode::NonInteractive).await;
        let env = s
            .request(Request::Catalog(CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: heimdall_contract::catalog::DeclaredInteraction::None,
                request_id: rid("r-declare"),
            }))
            .await;
        assert_eq!(env.code, Code::InteractionRequired);
        let d = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
        service
            .operations()
            .decide(
                &attended(),
                DecideRequest {
                    decision_id: DecisionId::parse(&d).unwrap(),
                    verdict: Verdict::Approve,
                },
            )
            .await
            .unwrap();
        let ensured = s
            .request(ensure("r-ensure", "w-1", InteractionMode::NonInteractive))
            .await;
        assert_eq!(ensured.code, Code::AccessReady, "{:?}", ensured.data);
        assert_eq!(pair_of(&ensured)["interaction"], "none", "{variant}");
        let binding = ensured.data["binding_id"].as_str().unwrap().to_owned();
        let reason = if variant == "withdrawn" {
            heimdall_contract::catalog::WithdrawReason::Owner
        } else {
            heimdall_contract::catalog::WithdrawReason::ListingMissing
        };
        let env = s
            .request(Request::Catalog(CatalogRequest::WithdrawDeclaration {
                identity: identity.clone(),
                revision: None,
                reason,
                request_id: rid("r-withdraw"),
            }))
            .await;
        assert_eq!(env.code, Code::Ok);
        assert_eq!(env.data["withdrawn"], true);
        if restart {
            drop(s);
            drop(service);
            service = rig.existing_access().await;
            s = Session::setup_session(&service, InteractionMode::NonInteractive).await;
        }
        let bound = s.request(bind(&binding, "r-bind")).await;
        assert_eq!(
            bound.code,
            Code::AccessReady,
            "{variant} restart={restart}: {:?}",
            bound.data
        );
        let p = pair_of(&bound);
        assert_eq!(p["interaction"], "unknown", "{variant} restart={restart}");
        assert_eq!(p["noninteractive"]["eligible"], false);
        assert!(p.get("declaration").is_none_or(serde_json::Value::is_null));
    }
}

// --- the activation, end to end (wave-3a integration) ----------------------------------

/// The activation change set end to end through the real runtime, dispatcher and
/// sessions, with the real `ProjectionWriter` over the scratch home: `setup/1` is
/// offered by both capability lists; an attended session previews an apply, gets
/// `APPROVAL_REQUIRED` with a `decision_ref`, approves it, and the apply lands;
/// `inspect projections` lists the managed resources; a rollback to the consented
/// restore needs no decision, restores the user file byte for byte, and hands every
/// resource to the cleaner (`desired: absent`).
#[tokio::test]
async fn e2e_setup_attended_apply_inspect_rollback_through_dispatcher() {
    assert!(server_capabilities().contains(capability::SETUP_V1));
    let rig = Rig::new();
    std::fs::write(&rig.home.user_config, "Host other\n    User fixture\n").unwrap();
    let original = std::fs::read(&rig.home.user_config).unwrap();
    let service = rig.service().await;
    let mut s = Session::setup_session(&service, InteractionMode::Interactive).await;
    let attend = s.client.attend().await.unwrap();
    assert_eq!(attend.code, Code::Ok);
    let caps = s
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Capabilities,
            preview: None,
        }))
        .await;
    assert_eq!(caps.code, Code::Ok);
    assert!(
        caps.data["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == capability::SETUP_V1),
        "{:?}",
        caps.data["capabilities"]
    );
    let endpoint = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: rig
            .home
            .root
            .join("fixture-agent.sock")
            .display()
            .to_string(),
    };
    adopt_and_alias(&mut s, endpoint).await;

    // Preview, then apply: an attended session is asked for approval.
    let plan = preview(&mut s, PreviewIntent::Apply { include_git: false }).await;
    assert!(plan.consent.decision_required);
    let env = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(env.code, Code::ApprovalRequired, "{:?}", env.data);
    let decision = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
    let op = env.operation_id.clone().unwrap();
    assert!(!rig.home.config_dir.join("ssh_config").exists());
    assert_eq!(std::fs::read(&rig.home.user_config).unwrap(), original);
    let decided = s
        .request(Request::Decide(DecideRequest {
            decision_id: DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        }))
        .await;
    assert_eq!(decided.code, Code::Ok, "{:?}", decided.data);
    let applied = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(applied.code, Code::Ok, "{:?}", applied.data);
    assert_eq!(applied.operation_id, Some(op));
    assert_eq!(applied.data["items"][0]["outcome"], "applied");
    assert!(rig.home.config_dir.join("ssh_config").exists());
    assert_ne!(std::fs::read(&rig.home.user_config).unwrap(), original);

    // Inspect: the managed resources are listed, present.
    let listed = inspect_projections(&mut s).await;
    assert_eq!(listed.code, Code::Ok);
    let resources = listed.data["projections"].as_array().unwrap().clone();
    assert!(!resources.is_empty(), "{:?}", listed.data);
    assert!(
        resources.iter().all(|r| r["desired"] == "present"),
        "{resources:?}"
    );

    // Rollback to the consented restore: no decision, the user file restored.
    let back = preview(
        &mut s,
        PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        },
    )
    .await;
    assert!(!back.consent.decision_required, "{:?}", back.consent);
    let rolled = s
        .request(Request::Setup(SetupRequest::Rollback {
            plan_digest: back.plan_digest.clone(),
            request_id: rid("r-rollback"),
        }))
        .await;
    assert_eq!(rolled.code, Code::Ok, "{:?}", rolled.data);
    assert_eq!(rolled.data["items"][0]["outcome"], "applied");
    assert_eq!(
        std::fs::read(&rig.home.user_config).unwrap(),
        original,
        "byte for byte"
    );
    let after = inspect_projections(&mut s).await;
    assert_eq!(after.code, Code::Ok);
    let resources = after.data["projections"].as_array().unwrap();
    assert!(!resources.is_empty(), "{:?}", after.data);
    assert!(
        resources.iter().all(|r| r["desired"] == "absent"),
        "{resources:?}"
    );
}

async fn inspect_projections(s: &mut Session) -> Envelope<serde_json::Value> {
    s.request(Request::Inspect(InspectRequest {
        subject: InspectSubject::Projections,
        preview: None,
    }))
    .await
}

/// ADR-0007 §12.22 item 10 (W3b-gaps): a supervisor-driven cleaner deletion after a
/// rollback, through the real service. The rollback hands Heimdall's files to the
/// cleaner (`desired: absent`) and moves none of them; the service's supervisor
/// (`Service::supervisor`, the one `Service::run` builds, with the wired
/// `ProjectionCleaner`) deletes each one by generation, identity and digest in its
/// cleanup pass and records it `observed: absent`. The user file stays as the
/// rollback restored it, and a second pass deletes nothing.
#[tokio::test]
async fn e2e_supervisor_cleaner_deletes_after_rollback_through_the_service() {
    let rig = Rig::new();
    std::fs::write(&rig.home.user_config, "Host other\n    User fixture\n").unwrap();
    let original = std::fs::read(&rig.home.user_config).unwrap();
    let service = rig.service().await;
    let mut s = Session::setup_session(&service, InteractionMode::Interactive).await;
    assert_eq!(s.client.attend().await.unwrap().code, Code::Ok);
    let endpoint = EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: rig
            .home
            .root
            .join("fixture-agent.sock")
            .display()
            .to_string(),
    };
    adopt_and_alias(&mut s, endpoint).await;
    let plan = preview(&mut s, PreviewIntent::Apply { include_git: false }).await;
    let env = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(env.code, Code::ApprovalRequired, "{:?}", env.data);
    let decision = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
    let decided = s
        .request(Request::Decide(DecideRequest {
            decision_id: DecisionId::parse(&decision).unwrap(),
            verdict: Verdict::Approve,
        }))
        .await;
    assert_eq!(decided.code, Code::Ok, "{:?}", decided.data);
    let applied = s.request(apply(&plan.plan_digest, "r-apply")).await;
    assert_eq!(applied.code, Code::Ok, "{:?}", applied.data);
    let p = rig.home.config_dir.join("ssh_config");
    assert!(p.exists());

    // Nothing to clean while the projection is wanted.
    let supervisor = service.supervisor();
    let idle = supervisor.cleanup_pass().await.unwrap();
    assert!(idle.deleted.is_empty(), "{:?}", idle.deleted);
    assert!(p.exists());

    let back = preview(
        &mut s,
        PreviewIntent::Rollback {
            keep_key_files: false,
            items: [ProjectionItem::Ssh].into_iter().collect(),
        },
    )
    .await;
    let rolled = s
        .request(Request::Setup(SetupRequest::Rollback {
            plan_digest: back.plan_digest.clone(),
            request_id: rid("r-rollback"),
        }))
        .await;
    assert_eq!(rolled.code, Code::Ok, "{:?}", rolled.data);
    assert_eq!(std::fs::read(&rig.home.user_config).unwrap(), original);
    let handed = inspect_projections(&mut s).await.data["projections"]
        .as_array()
        .unwrap()
        .clone();
    assert!(!handed.is_empty());
    assert!(
        handed
            .iter()
            .all(|r| r["desired"] == "absent" && r["observed"] == "present"),
        "the rollback moves nothing itself: {handed:?}"
    );
    let paths: Vec<std::path::PathBuf> = handed
        .iter()
        .map(|r| {
            let locator: serde_json::Value =
                serde_json::from_str(r["locator"].as_str().unwrap()).unwrap();
            std::path::PathBuf::from(locator["path"].as_str().unwrap())
        })
        .collect();
    assert!(paths.contains(&p), "{paths:?}");
    assert!(paths.iter().all(|f| f.exists()), "{paths:?}");

    // The supervisor's cleanup pass deletes every handed-over file.
    let report = supervisor.cleanup_pass().await.unwrap();
    assert_eq!(report.deleted.len(), handed.len(), "{:?}", report.deleted);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert!(report.retry_scheduled.is_empty());
    for f in &paths {
        assert!(!f.exists(), "{f:?} was not deleted");
    }
    let after = inspect_projections(&mut s).await.data["projections"]
        .as_array()
        .unwrap()
        .clone();
    assert!(
        after
            .iter()
            .all(|r| r["desired"] == "absent" && r["observed"] == "absent"),
        "{after:?}"
    );
    assert_eq!(std::fs::read(&rig.home.user_config).unwrap(), original);
    // Idempotent: the next pass finds nothing to delete.
    let again = supervisor.cleanup_pass().await.unwrap();
    assert!(again.deleted.is_empty(), "{:?}", again.deleted);
    assert!(again.failed.is_empty());
}

/// ADR-0007 §12.22 item 10 (W3b-gaps): `[setup] declaration_validity_days` is wired
/// through the real service. A declaration requested through the dispatcher is
/// offered, and approved, for the configured days; the default is 30.
#[tokio::test]
async fn e2e_declaration_validity_days_come_from_the_configuration() {
    for (text, days) in [
        (
            "schema_version = 1\n[setup]\ndeclaration_validity_days = 3\n",
            3_i64,
        ),
        ("schema_version = 1\n", 30),
    ] {
        let rig = Rig::new();
        let config = Config::parse(text).unwrap();
        let service = rig
            .start_configured(ProjectionWiring::Config(Box::new(rig.projection())), config)
            .await;
        let mut s = Session::setup_session(&service, InteractionMode::Interactive).await;
        assert_eq!(s.client.attend().await.unwrap().code, Code::Ok);
        let endpoint = EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: rig.home.root.join("agent.sock").display().to_string(),
        };
        let identity = adopt_and_alias(&mut s, endpoint).await;
        let env = s
            .request(Request::Catalog(CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: heimdall_contract::catalog::DeclaredInteraction::None,
                request_id: rid("r-declare"),
            }))
            .await;
        assert_eq!(env.code, Code::ApprovalRequired, "{:?}", env.data);
        let decision = env.next.as_ref().unwrap().decision_ref.clone().unwrap();
        let expected = t0()
            .checked_add(jiff::SignedDuration::from_hours(24 * days))
            .unwrap();
        let record = service
            .store()
            .transaction(|tx| tx.decision(&DecisionId::parse(&decision).unwrap()))
            .unwrap()
            .unwrap();
        match &record.kind {
            heimdall_domain::decision::DecisionKind::DeclareInteraction { valid_until, .. } => {
                assert_eq!(*valid_until, expected, "{days} days")
            }
            other => panic!("{other:?}"),
        }
        let decided = s
            .request(Request::Decide(DecideRequest {
                decision_id: DecisionId::parse(&decision).unwrap(),
                verdict: Verdict::Approve,
            }))
            .await;
        assert_eq!(decided.code, Code::Ok, "{:?}", decided.data);
        let declaration = service
            .store()
            .transaction(|tx| tx.interaction_declaration(&identity))
            .unwrap()
            .unwrap();
        assert_eq!(declaration.expires_at, expected, "{days} days");
    }
}
