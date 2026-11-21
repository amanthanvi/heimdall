//! ⟨M06⟩ W2: the runner runtime serving paired sessions (ADR-0012 §3.6–§3.11; m06-plan U1's
//! W2 items; ADR-0006 §18.5 readings 1, 5, 7, 17), through the real `OperationsDispatcher`
//! and the real IPC session over in-memory streams, with disposable fixtures only (an
//! in-memory or scratch state store, in-memory authorized_keys files, fixture public keys).
//!
//! * runner mode and acceptance: only a runner offers `remote-control/1`; a hello's client is
//!   accepted only once the role table resolves it, with the table's role;
//! * per-frame checks and revocation: role permissions, no attendance, revocation rechecked
//!   per request, and a revoked client's sessions and subscriptions closed with the terminal
//!   `client.revoked` event;
//! * M06-W0-R06: a pending session negotiates and dispatches only the activation probe and
//!   `join` (a viewer and a requester activated; adjacent forms refused; an identity
//!   mismatch on retry);
//! * runner-local widening (T-RA1–T-RA4, RC-R03): pending records only, `Decide` refused
//!   from a paired session, local attended approval, the terminal result replayed with no
//!   new record and no re-execution, across a restart.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ensure::NoStageHook;
use heimdall_app::operations::Limits;
use heimdall_app::{Operations, OperationsConfig};
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::event::EventFilter;
use heimdall_contract::ids::{ClientId, DecisionId, DeviceId, EnvironmentId, KeyFingerprint};
use heimdall_contract::ipc::{ClientHello, PeerInfo, PrincipalInfo, capability};
use heimdall_contract::remote::{ManagementPolicy, Role};
use heimdall_contract::request::{InteractionMode, Request};
use heimdall_contract::{Code, PROTOCOL_VERSION, SchemaVersion, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy};
use heimdall_ipc::session::{
    ConnectionLimits, ControlClient, ControlConnection, Dispatcher, ServerRefusal, SessionInfo,
    SubscribeOutcome, server_capabilities, server_refusal,
};
use heimdall_remote::invitations::{Invitations, JoinRequest, NewInvitation, TimeReading};
use heimdall_remote::line::{PublicKeyText, ServeCommand};
use heimdall_remote::testing::MemoryLines;
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use heimdall_runtime::paired::{PairedRunner, RunnerOptions, init_runner, is_runner};
use heimdall_store::ext_m06::{ClientState, RevocationCause};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::{ScriptedTimeSync, VirtualClock};
use tokio::io::DuplexStream;
use tokio_util::sync::CancellationToken;

const HOUR: Duration = Duration::from_secs(3600);
const HEIMDALL: &str = "/opt/heimdall/bin/heimdall";
const HOME: &str = "/srv/runner/heimdall";

fn t0() -> Timestamp {
    "2026-11-21T09:00:00Z".parse().unwrap()
}

fn principal() -> PrincipalInfo {
    PrincipalInfo::OsUserUnix { uid: 501 }
}

/// Standard base64 (padded), enough for a fixture key blob.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A disposable Ed25519 public key (fixed bytes; public text only, never a private key).
fn key(n: u8) -> (String, KeyFingerprint) {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    let mut k = [0x5au8; 32];
    k[0] = n;
    blob.extend_from_slice(&k);
    let text = format!("ssh-ed25519 {}", b64(&blob));
    let fp = PublicKeyText::parse(&text).unwrap().fingerprint();
    (text, fp)
}

fn req(json: &str) -> Request {
    serde_json::from_str(json).unwrap()
}

fn reason_of(env: &Envelope<serde_json::Value>) -> Option<String> {
    env.data["error"]["reason"].as_str().map(str::to_owned)
}

/// One runner (or plain runtime) in process: the real operations, dispatcher and IPC
/// sessions over in-memory streams.
struct Rig {
    store: Arc<Store>,
    clock: Arc<VirtualClock>,
    lines: Arc<MemoryLines>,
    /// The harness's own line lock for its direct invitation-service calls.
    serial: heimdall_remote::invitations::LineSerial,
    environment: EnvironmentId,
    dispatcher: OperationsDispatcher,
    stop: CancellationToken,
}

impl Rig {
    async fn new(runner: bool) -> Self {
        Self::over(
            Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap()),
            runner,
            Arc::new(MemoryLines::default_pair()),
        )
        .await
    }

    async fn over(store: Arc<Store>, runner: bool, lines: Arc<MemoryLines>) -> Self {
        let clock = VirtualClock::at(t0());
        let environment = match store.transaction(|tx| tx.self_environment()).unwrap() {
            Some(e) => e,
            None => {
                let e = EnvironmentId::from_random_bytes([7; 16]);
                store
                    .transaction(|tx| {
                        tx.init_self_environment(&e)?;
                        tx.upsert_environment(&EnvironmentRecord {
                            id: e.clone(),
                            device: DeviceId::from_random_bytes([8; 16]),
                            kind: EnvironmentKind::NativeSession,
                            label: None,
                            permissions: EnvironmentPermissions::default(),
                        })
                    })
                    .unwrap();
                e
            }
        };
        if runner {
            assert_eq!(init_runner(&store).unwrap(), environment);
        }
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: environment.clone(),
            adapters: Vec::new(),
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        let stop = CancellationToken::new();
        let relay = EventRelay::spawn(&ops, stop.clone());
        let mut dispatcher = OperationsDispatcher::new(ops.clone(), relay, clock.clone());
        if store.transaction(is_runner).unwrap() {
            let shared: Arc<dyn heimdall_remote::line::ManagementLines> = lines.clone();
            dispatcher = dispatcher.with_runner(Arc::new(PairedRunner::new(
                store.clone(),
                ops,
                clock.clone(),
                RunnerOptions {
                    lines: Some(shared),
                    command: Some(ServeCommand::new(HEIMDALL, HOME).unwrap()),
                    management_policy: ManagementPolicy::Verified,
                    ..RunnerOptions::default()
                },
            )));
        }
        Self {
            store,
            clock,
            lines,
            serial: heimdall_remote::invitations::LineSerial::default(),
            environment,
            dispatcher,
            stop,
        }
    }

    async fn connect(
        &self,
        hello: ClientHello,
    ) -> Result<ControlClient<DuplexStream>, heimdall_ipc::FrameError> {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let conn = ControlConnection::new(server_end, ConnectionLimits::default())
            .with_server_identity(
                self.environment.clone(),
                PeerInfo {
                    name: "runner".into(),
                    version: "0".into(),
                },
            );
        let d = self.dispatcher.clone();
        let stop = self.stop.clone();
        tokio::spawn(async move {
            let _ = conn.serve(principal(), d, stop).await;
        });
        ControlClient::handshake_hello(client_end, hello).await
    }

    fn invitations<'a>(&'a self, command: &'a ServeCommand) -> Invitations<'a> {
        Invitations {
            store: &self.store,
            lines: self.lines.as_ref(),
            environment: &self.environment,
            command,
            clock: self.clock.as_ref(),
            serial: &self.serial,
        }
    }

    fn now(&self) -> TimeReading {
        TimeReading::safe(&self.clock.observe())
    }

    /// Invite a fixture client directly through the invitation service (the executor of a
    /// runner-local decision): pending, with its line written.
    fn invite(&self, n: u8, role: Role) -> Invited {
        let command = ServeCommand::new(HEIMDALL, HOME).unwrap();
        let (public_key, fp) = key(n);
        let done = self
            .invitations(&command)
            .invite(
                &NewInvitation {
                    role,
                    public_key: &public_key,
                    key_fingerprint: &fp,
                    lifetime: Duration::from_secs(900),
                },
                ManagementPolicy::Verified,
                &self.now(),
            )
            .unwrap();
        Invited {
            client: done.invitation.client.clone(),
            join: JoinRequest {
                environment: self.environment.clone(),
                invitation: done.invitation.invitation.clone(),
                role,
                generation: done.invitation.generation,
            },
            nonce: done.invitation.probe_nonce,
        }
    }

    /// Invite and activate a fixture client directly.
    fn enroll(&self, n: u8, role: Role) -> ClientId {
        let inv = self.invite(n, role);
        let command = ServeCommand::new(HEIMDALL, HOME).unwrap();
        self.invitations(&command)
            .join(&inv.client, &inv.join, &self.now())
            .unwrap();
        inv.client
    }

    fn decisions(&self) -> usize {
        self.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .len()
    }
}

struct Invited {
    client: ClientId,
    join: JoinRequest,
    nonce: String,
}

fn join_request(j: &JoinRequest) -> Request {
    req(&format!(
        r#"{{"op":"remote_environment","action":"join","environment":"{}","invitation":"{}","role":"{}","generation":{}}}"#,
        j.environment,
        j.invitation,
        serde_json::to_value(j.role).unwrap().as_str().unwrap(),
        j.generation
    ))
}

/// A hello as the bridge originates it (`remote_client` from argv) or a local caller sends
/// it (no client).
fn hello(client: Option<&ClientId>, required: &[&str], interactive: bool) -> ClientHello {
    let mut capabilities = server_capabilities();
    capabilities.insert(capability::REMOTE_CONTROL_V1.to_owned());
    ClientHello {
        protocol: PROTOCOL_VERSION,
        schema_version: SchemaVersion::current(),
        client: PeerInfo {
            name: "fixture".into(),
            version: "0".into(),
        },
        capabilities,
        required: required.iter().map(|c| (*c).to_owned()).collect(),
        interaction: if interactive {
            InteractionMode::Interactive
        } else {
            InteractionMode::NonInteractive
        },
        remote_client: client.cloned(),
    }
}

/// What the IPC session hands a paired session's dispatch (never attended).
fn paired_session() -> SessionInfo {
    SessionInfo {
        principal: principal(),
        interaction: InteractionMode::NonInteractive,
        attended: false,
    }
}

/// The hello's refusal envelope.
fn rejected(
    r: Result<ControlClient<DuplexStream>, heimdall_ipc::FrameError>,
) -> Envelope<serde_json::Value> {
    let err = match r {
        Ok(_) => panic!("the hello was accepted"),
        Err(e) => e,
    };
    match server_refusal(&err) {
        Some(ServerRefusal::Rejected(env)) => {
            (**env).clone().map(|d| serde_json::to_value(d).unwrap())
        }
        other => panic!("not a hello refusal: {other:?} ({err})"),
    }
}

/// Item 1: only a runner offers `remote-control/1` and accepts a paired client, and only one
/// the role table resolves, with the table's role; capabilities alone never establish an
/// identity (ADR-0006 §18.5 reading 1). The runner-init marker is the environment record.
#[tokio::test]
async fn only_a_runner_accepts_a_paired_client_and_only_a_resolved_one() {
    // A runtime that is not a runner: wave 0's refusal, and no remote-control/1.
    let plain = Rig::new(false).await;
    assert!(!plain.store.transaction(is_runner).unwrap());
    let someone = ClientId::from_random_bytes([0xee; 16]);
    let env = rejected(plain.connect(hello(Some(&someone), &[], false)).await);
    assert_eq!(env.code, Code::SchemaUnsupported);
    let local = plain.connect(hello(None, &[], false)).await.unwrap();
    assert!(
        !local
            .server()
            .capabilities
            .contains(capability::REMOTE_CONTROL_V1)
    );
    assert_eq!(local.server().role, None);

    let rig = Rig::new(true).await;
    assert!(rig.store.transaction(is_runner).unwrap());
    // Idempotent; the environment ID is kept.
    assert_eq!(init_runner(&rig.store).unwrap(), rig.environment);
    // The local same-uid caller on a runner is the owner, unreported, with remote-control/1;
    // advertising remote-control/1 establishes no client.
    let local = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    assert!(
        local
            .server()
            .capabilities
            .contains(capability::REMOTE_CONTROL_V1)
    );
    assert_eq!(local.server().role, None);
    // An unknown client: refused, nothing about it echoed.
    let env = rejected(rig.connect(hello(Some(&someone), &[], false)).await);
    assert_eq!(env.code, Code::CapabilityUnavailable);
    assert_eq!(reason_of(&env).as_deref(), Some(reason::CLIENT_REVOKED));
    assert!(!env.data.to_string().contains(someone.as_str()));
    // An active viewer: its table role, its role's capabilities only.
    let viewer = rig.enroll(1, Role::Viewer);
    let session = rig.connect(hello(Some(&viewer), &[], false)).await.unwrap();
    assert_eq!(session.server().role, Some(Role::Viewer));
    let want: BTreeSet<String> = capability::VIEWER.map(str::to_owned).into_iter().collect();
    assert_eq!(session.server().capabilities, want);
    let env = rejected(
        rig.connect(hello(
            Some(&viewer),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await,
    );
    assert_eq!(reason_of(&env).as_deref(), Some(reason::ROLE_INSUFFICIENT));
    // A tombstoned client: refused.
    rig.store
        .transaction(|tx| tx.revoke_remote_client(&viewer, RevocationCause::Revoked, t0()))
        .unwrap();
    let env = rejected(rig.connect(hello(Some(&viewer), &[], false)).await);
    assert_eq!(reason_of(&env).as_deref(), Some(reason::CLIENT_REVOKED));
}

/// Item 2: every paired request is checked against the client's row (role permissions; no
/// attendance; revocation rechecked per request), and revoking a client ends its sessions
/// and subscriptions with the terminal `client.revoked` event, while another client's
/// session continues.
#[tokio::test]
async fn paired_frames_are_checked_and_revocation_ends_the_clients_sessions() {
    let rig = Rig::new(true).await;
    let owner = rig.enroll(1, Role::Owner);
    let viewer = rig.enroll(2, Role::Viewer);
    let requester = rig.enroll(3, Role::Requester);
    let mut v = rig.connect(hello(Some(&viewer), &[], false)).await.unwrap();
    // Within the role: dispatched.
    let ok = v
        .request(req(r#"{"op":"inspect","subject":"capabilities"}"#))
        .await
        .unwrap();
    assert_eq!(ok.code, Code::Ok, "{ok:?}");
    // Outside it: role_insufficient, before dispatch.
    for form in [
        r#"{"op":"policy","action":"pause","policy_id":"pol"}"#,
        r#"{"op":"ensure","profile":"dev","work_id":"w","request_id":"r-v"}"#,
    ] {
        let env = v.request(req(form)).await.unwrap();
        assert_eq!(env.code, Code::CapabilityUnavailable, "{form}");
        assert_eq!(
            reason_of(&env).as_deref(),
            Some(reason::ROLE_INSUFFICIENT),
            "{form}"
        );
    }
    // Never attended, whatever the hello declared (T-RA2's session half).
    let mut a = rig.connect(hello(Some(&owner), &[], true)).await.unwrap();
    assert_eq!(a.attend().await.unwrap().code, Code::InteractionRequired);
    let decide = req(&format!(
        r#"{{"op":"decide","decision_id":"{}","verdict":"approve"}}"#,
        DecisionId::from_random_bytes([1; 16])
    ));
    assert_eq!(
        a.request(decide).await.unwrap().code,
        Code::InteractionRequired
    );
    // The owner's subscription, and a requester's.
    let SubscribeOutcome::Subscribed { subscription, .. } =
        a.subscribe(EventFilter::default(), None).await.unwrap()
    else {
        panic!("subscribe refused");
    };
    let mut r = rig
        .connect(hello(Some(&requester), &[], false))
        .await
        .unwrap();
    assert!(matches!(
        r.subscribe(EventFilter::default(), None).await.unwrap(),
        SubscribeOutcome::Subscribed { .. }
    ));
    // The local owner revokes the paired owner (narrowing, no decision).
    let mut local = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    let revoked = local
        .request(req(&format!(
            r#"{{"op":"remote_environment","action":"revoke_client","environment":"{}","client":"{owner}"}}"#,
            rig.environment
        )))
        .await
        .unwrap();
    assert_eq!(revoked.code, Code::Ok, "{revoked:?}");
    // Its subscription ends with the terminal client.revoked event, then the session.
    let (sub, terminal) = a.next_event().await.unwrap();
    assert_eq!(sub, subscription);
    assert_eq!(terminal.payload["kind"], "revoked");
    assert_eq!(terminal.payload["client"], owner.as_str());
    let end = a.next_event().await.unwrap_err();
    assert!(
        matches!(server_refusal(&end), Some(ServerRefusal::Goodbye { code, .. }) if *code == Code::CapabilityUnavailable),
        "{end}"
    );
    let env = rejected(rig.connect(hello(Some(&owner), &[], false)).await);
    assert_eq!(reason_of(&env).as_deref(), Some(reason::CLIENT_REVOKED));
    // The requester's session continues.
    assert_eq!(
        r.request(req(r#"{"op":"inspect","subject":"capabilities"}"#))
            .await
            .unwrap()
            .code,
        Code::Ok
    );
    // Revocation rechecked per request, even when no session was told: the viewer's next
    // request is refused, and its session then ends.
    rig.store
        .transaction(|tx| tx.revoke_remote_client(&viewer, RevocationCause::Revoked, t0()))
        .unwrap();
    let env = v
        .request(req(r#"{"op":"inspect","subject":"capabilities"}"#))
        .await
        .unwrap();
    assert_eq!(reason_of(&env).as_deref(), Some(reason::CLIENT_REVOKED));
    assert!(v.next_event().await.is_err(), "the viewer's session ended");
}

/// Item 3 (M06-W0-R06): a pending client's session negotiates only `remote-control/1` and is
/// served only the activation probe and `join`, with the invitation and identity checks
/// ahead of any recorded result; a viewer and a requester are activated; adjacent
/// management forms are refused while pending; an identity mismatch on retry says nothing.
#[tokio::test]
async fn pending_sessions_reach_only_the_probe_and_join() {
    let rig = Rig::new(true).await;
    let viewer = rig.invite(1, Role::Viewer);
    let requester = rig.invite(2, Role::Requester);
    let pending_only: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
    // Requiring more than the pending path: invitation_pending at the hello.
    let env = rejected(
        rig.connect(hello(
            Some(&viewer.client),
            &[capability::REMOTE_CONTROL_V1, capability::OPERATIONS_V1],
            false,
        ))
        .await,
    );
    assert_eq!(reason_of(&env).as_deref(), Some(reason::INVITATION_PENDING));

    for (inv, other) in [(&viewer, &requester), (&requester, &viewer)] {
        let mut s = rig
            .connect(hello(
                Some(&inv.client),
                &[capability::REMOTE_CONTROL_V1],
                false,
            ))
            .await
            .unwrap();
        assert_eq!(s.server().capabilities, pending_only);
        // Adjacent forms, refused before dispatch while pending.
        for form in [
            r#"{"op":"inspect","subject":"capabilities"}"#.to_owned(),
            r#"{"op":"remote_environment","action":"status"}"#.to_owned(),
            format!(
                r#"{{"op":"remote_environment","action":"revoke_client","environment":"{}","client":"{}"}}"#,
                rig.environment, other.client
            ),
            format!(
                r#"{{"op":"remote_environment","action":"invite","environment":"{}","role":"viewer","key_fingerprint":"{}","public_key":"{}","request_id":"r1"}}"#,
                rig.environment,
                key(9).1,
                key(9).0
            ),
        ] {
            let env = s.request(req(&form)).await.unwrap();
            assert_eq!(
                reason_of(&env).as_deref(),
                Some(reason::INVITATION_PENDING),
                "{form}: {env:?}"
            );
        }
        match s.subscribe(EventFilter::default(), None).await.unwrap() {
            SubscribeOutcome::Refused(env) => {
                assert_eq!(reason_of(&env).as_deref(), Some(reason::INVITATION_PENDING));
            }
            SubscribeOutcome::Subscribed { .. } => panic!("a pending session subscribed"),
        }
        // The probe echoes the argv client and the pending record's nonce.
        let probe = s
            .request(req(&format!(
                r#"{{"op":"remote_environment","action":"activation_probe","environment":"{}","nonce":"{}"}}"#,
                rig.environment, inv.nonce
            )))
            .await
            .unwrap();
        assert_eq!(probe.code, Code::Ok, "{probe:?}");
        assert_eq!(probe.data["client"], inv.client.as_str());
        assert_eq!(probe.data["nonce"], inv.nonce.as_str());
        let wrong = s
            .request(req(&format!(
                r#"{{"op":"remote_environment","action":"activation_probe","environment":"{}","nonce":"00"}}"#,
                rig.environment
            )))
            .await
            .unwrap();
        assert_eq!(
            reason_of(&wrong).as_deref(),
            Some(reason::DECISION_BINDING_MISMATCH)
        );
        // An identity mismatch (the other client's invitation): the uniform "not live"
        // answer, nothing about the record.
        let mut theirs = other.join.clone();
        theirs.role = inv.join.role;
        let env = s.request(join_request(&theirs)).await.unwrap();
        assert_eq!(reason_of(&env).as_deref(), Some(reason::INVITATION_EXPIRED));
        assert!(!env.data.to_string().contains(other.client.as_str()));
        // The join, then a retry on the same session: the recorded result.
        let joined = s.request(join_request(&inv.join)).await.unwrap();
        assert_eq!(joined.code, Code::Ok, "{joined:?}");
        assert_eq!(joined.data["replayed"], false);
        let again = s.request(join_request(&inv.join)).await.unwrap();
        assert_eq!(again.data["replayed"], true);
        assert_eq!(again.data["invitation"], joined.data["invitation"]);
        // The session stays pending-only for its lifetime.
        let env = s
            .request(req(r#"{"op":"inspect","subject":"capabilities"}"#))
            .await
            .unwrap();
        assert_eq!(reason_of(&env).as_deref(), Some(reason::INVITATION_PENDING));
        let state = rig
            .store
            .transaction(|tx| tx.remote_client(&inv.client))
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, ClientState::Active);
        // Its next session is an ordinary one for its role: no remote-control/1, so neither
        // join nor the probe is negotiated.
        let mut next = rig
            .connect(hello(Some(&inv.client), &[], false))
            .await
            .unwrap();
        assert_eq!(next.server().role, Some(inv.join.role));
        assert!(
            !next
                .server()
                .capabilities
                .contains(capability::REMOTE_CONTROL_V1)
        );
        assert_eq!(
            next.request(join_request(&inv.join)).await.unwrap().code,
            Code::SchemaUnsupported
        );
        assert_eq!(
            next.request(req(r#"{"op":"inspect","subject":"capabilities"}"#))
                .await
                .unwrap()
                .code,
            Code::Ok
        );
    }
    // Once consumed, the other client's retry naming it still says nothing.
    let mut late = rig.invite(3, Role::Viewer);
    late.join.invitation = viewer.join.invitation.clone();
    let mut s = rig
        .connect(hello(
            Some(&late.client),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await
        .unwrap();
    let env = s.request(join_request(&late.join)).await.unwrap();
    assert_eq!(reason_of(&env).as_deref(), Some(reason::INVITATION_EXPIRED));
}

/// Item 4 (ADR-0012 §3.10; T-RA1–T-RA4, RC-R03): a paired owner's widening request is a
/// durable pending runner-local decision record answered `APPROVAL_REQUIRED` with
/// `next.decision_ref`; the paired session cannot decide it; a viewer's is
/// `role_insufficient`; only an attended local session approves it, running the exact
/// request once; a replay, also after a restart, returns the recorded terminal result with
/// no new record and no re-execution; an exposure widening stays pending.
#[tokio::test]
async fn paired_widening_is_confirmed_runner_locally_and_replays_its_result() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("state.db");
    let lines = Arc::new(MemoryLines::default_pair());
    let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
    let rig = Rig::over(store, true, lines.clone()).await;
    let owner = rig.enroll(1, Role::Owner);
    let viewer = rig.enroll(2, Role::Viewer);
    let (public_key, fp) = key(7);
    let invite = format!(
        r#"{{"op":"remote_environment","action":"invite","environment":"{}","role":"requester","key_fingerprint":"{fp}","public_key":"{public_key}","request_id":"inv-1"}}"#,
        rig.environment
    );
    let mut a = rig.connect(hello(Some(&owner), &[], false)).await.unwrap();
    let before = rig.decisions();
    let clients_before = rig
        .store
        .transaction(|tx| tx.remote_clients())
        .unwrap()
        .len();
    // T-RA1: a pending record only.
    let pending = a.request(req(&invite)).await.unwrap();
    assert_eq!(pending.code, Code::ApprovalRequired, "{pending:?}");
    let decision = pending
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .unwrap();
    assert_eq!(rig.decisions(), before + 1);
    assert_eq!(
        rig.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len(),
        clients_before,
        "nothing executed"
    );
    // A replay while pending: the same record.
    let replay = a.request(req(&invite)).await.unwrap();
    assert_eq!(replay.next.unwrap().decision_ref.unwrap(), decision);
    assert_eq!(rig.decisions(), before + 1);
    // The same key with another request: REQUEST_CONFLICT.
    let conflicting = invite.replace("\"requester\"", "\"viewer\"");
    assert_eq!(
        a.request(req(&conflicting)).await.unwrap().code,
        Code::RequestConflict
    );
    // T-RA2: the paired session's Decide never reaches a decision.
    let decide = |verdict: &str| {
        req(&format!(
            r#"{{"op":"decide","decision_id":"{decision}","verdict":"{verdict}"}}"#
        ))
    };
    assert_eq!(
        a.request(decide("approve")).await.unwrap().code,
        Code::InteractionRequired
    );
    // T-RA4: a viewer's widening request is role_insufficient, with no record: it cannot
    // negotiate `remote-control/1` (role_insufficient at the hello), its session refuses the
    // form before dispatch, and past the gate the runtime's check refuses it by role.
    let env = rejected(
        rig.connect(hello(
            Some(&viewer),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await,
    );
    assert_eq!(reason_of(&env).as_deref(), Some(reason::ROLE_INSUFFICIENT));
    let mut v = rig.connect(hello(Some(&viewer), &[], false)).await.unwrap();
    let viewer_invite = req(&invite.replace("inv-1", "inv-v"));
    assert_eq!(
        v.request(viewer_invite.clone()).await.unwrap().code,
        Code::SchemaUnsupported
    );
    let mut bound_viewer = rig.dispatcher.clone();
    Dispatcher::bind_paired(&mut bound_viewer, &hello(Some(&viewer), &[], false)).unwrap();
    let env = bound_viewer.handle(&paired_session(), viewer_invite).await;
    assert_eq!(reason_of(&env).as_deref(), Some(reason::ROLE_INSUFFICIENT));
    assert_eq!(rig.decisions(), before + 1);
    // RC-R03: adopting a roost submitted remotely. A runner offers no `transport-iroh/1`,
    // so the session refuses it before dispatch, with no record.
    let roost_form = req(&format!(
        r#"{{"op":"transport","action":"adopt_roost","destination":"dst-lab1","endpoint":"{}","request_id":"roost-1"}}"#,
        "ab".repeat(32)
    ));
    assert_eq!(
        a.request(roost_form.clone()).await.unwrap().code,
        Code::SchemaUnsupported
    );
    assert_eq!(rig.decisions(), before + 1);
    // Past the session gate (as when a runner offers the capability, U56), the runtime's own
    // path: a pending record only; this build has no executor for it, so even a local
    // approval leaves it pending.
    let mut bound = rig.dispatcher.clone();
    Dispatcher::bind_paired(&mut bound, &hello(Some(&owner), &[], false)).unwrap();
    let roost = bound.handle(&paired_session(), roost_form).await;
    assert_eq!(roost.code, Code::ApprovalRequired, "{roost:?}");
    let roost_decision = roost.next.unwrap().decision_ref.unwrap();
    assert_eq!(rig.decisions(), before + 2);
    // The decision is listed to the local owner (its CLI and TUI), with the exact request.
    let mut local = rig.connect(hello(None, &[], true)).await.unwrap();
    let listed = local
        .request(req(r#"{"op":"inspect","subject":"decisions"}"#))
        .await
        .unwrap();
    assert!(listed.data.to_string().contains(&decision), "{listed:?}");
    // An unattended local session cannot decide; an attended one approves.
    let mut unattended = rig.connect(hello(None, &[], false)).await.unwrap();
    assert_eq!(
        unattended.request(decide("approve")).await.unwrap().code,
        Code::InteractionRequired
    );
    assert_eq!(local.attend().await.unwrap().code, Code::Ok);
    let roost_env = local
        .request(req(&format!(
            r#"{{"op":"decide","decision_id":"{roost_decision}","verdict":"approve"}}"#
        )))
        .await
        .unwrap();
    assert_eq!(
        reason_of(&roost_env).as_deref(),
        Some(reason::DRIVER_UNAVAILABLE)
    );
    let writes = lines.writes();
    let approved = local.request(decide("approve")).await.unwrap();
    assert_eq!(approved.code, Code::Ok, "{approved:?}");
    let invited = approved.data["client"].as_str().unwrap().to_owned();
    assert_eq!(approved.data["role"], "requester");
    assert!(lines.writes() > writes, "the pending line was written");
    let clients_after = rig
        .store
        .transaction(|tx| tx.remote_clients())
        .unwrap()
        .len();
    assert_eq!(clients_after, clients_before + 1);
    // Consume-once: a second approval is stale.
    assert_eq!(
        local.request(decide("approve")).await.unwrap().code,
        Code::DecisionStale
    );
    // T-RA3: the replay returns the recorded terminal result; no new record, no re-run.
    let writes = lines.writes();
    let replayed = a.request(req(&invite)).await.unwrap();
    assert_eq!(replayed.code, Code::Ok);
    assert_eq!(replayed.data, approved.data);
    assert_eq!(lines.writes(), writes);
    assert_eq!(
        rig.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len(),
        clients_after
    );
    // The roost record is still pending.
    assert!(
        rig.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .iter()
            .any(|d| d.id.as_str() == roost_decision)
    );

    // Durable: after a restart over the same state, the replay still returns the result.
    rig.stop.cancel();
    drop((a, v, local, unattended));
    drop(rig);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let store = Arc::new(Store::open(&db, Arc::new(NoFaults)).unwrap());
    let rig = Rig::over(store, false, lines.clone()).await;
    let mut a = rig.connect(hello(Some(&owner), &[], false)).await.unwrap();
    let after_restart = a.request(req(&invite)).await.unwrap();
    assert_eq!(after_restart.data, approved.data);
    assert_eq!(after_restart.data["client"], invited.as_str());
    assert_eq!(
        rig.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len(),
        clients_after
    );
}

/// Item 1, end to end on a real runtime (Unix sockets; the named-pipe transport carries the
/// same session): an installation marked by `init_runner` starts as a runner, so its
/// control socket resolves a paired hello in the role table (an unknown client:
/// `client_revoked`) and offers `remote-control/1`; an unmarked one keeps wave 0's refusal.
#[cfg(unix)]
#[tokio::test]
async fn the_runner_marker_decides_what_a_started_runtime_serves() {
    use heimdall_runtime::service::{STATE_DB_FILE, Service, ServiceOptions};
    use heimdall_runtime::{Config, Paths};
    for runner in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::under(&tmp.path().join("hh"));
        paths.ensure().unwrap();
        if runner {
            let store =
                Store::open(&paths.state_dir.join(STATE_DB_FILE), Arc::new(NoFaults)).unwrap();
            init_runner(&store).unwrap();
        }
        let stop = CancellationToken::new();
        let service = Service::start_with(
            paths,
            Config::default(),
            ServiceOptions::with_clock(
                VirtualClock::at(t0()),
                ScriptedTimeSync::new(SyncStatus::Synchronized),
            ),
            stop.clone(),
        )
        .await
        .unwrap();
        let endpoint = std::path::PathBuf::from(&service.instance().control_endpoint);
        let running = tokio::spawn(service.run());
        let connect = |hello: ClientHello| {
            let endpoint = endpoint.clone();
            async move {
                let stream = heimdall_ipc::unix::connect(&endpoint).await.unwrap();
                ControlClient::handshake_hello(stream, hello).await
            }
        };
        let someone = ClientId::from_random_bytes([0xee; 16]);
        let err = match connect(hello(Some(&someone), &[], false)).await {
            Ok(_) => panic!("an unknown client was accepted"),
            Err(e) => e,
        };
        let Some(ServerRefusal::Rejected(env)) = server_refusal(&err) else {
            panic!("not a hello refusal: {err}");
        };
        let local = connect(hello(None, &[], false)).await.unwrap();
        if runner {
            assert_eq!(env.code, Code::CapabilityUnavailable);
            assert_eq!(
                env.data.error.reason.as_deref(),
                Some(reason::CLIENT_REVOKED)
            );
            assert!(
                local
                    .server()
                    .capabilities
                    .contains(capability::REMOTE_CONTROL_V1)
            );
        } else {
            assert_eq!(env.code, Code::SchemaUnsupported);
            assert!(
                !local
                    .server()
                    .capabilities
                    .contains(capability::REMOTE_CONTROL_V1)
            );
        }
        drop(local);
        stop.cancel();
        running.await.unwrap().unwrap();
    }
}

/// Transport fakes for the runner's executor and admission hook (no platform store, no
/// serve child).
#[derive(Default)]
struct TransportFakes {
    created: std::sync::atomic::AtomicUsize,
    started: std::sync::atomic::AtomicUsize,
    narrowed: std::sync::atomic::AtomicUsize,
}

impl heimdall_app::transport::TransportKeys for TransportFakes {
    fn create(
        &self,
    ) -> Result<heimdall_app::transport::NewTransportKey, heimdall_app::transport::KeyStoreRefusal>
    {
        let n = self
            .created
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let endpoint =
            heimdall_contract::ids::IrohEndpointId::parse(&format!("{:02x}", n + 1).repeat(32))
                .unwrap();
        Ok(heimdall_app::transport::NewTransportKey {
            store_ref: format!("fixture/{}", endpoint.as_str()),
            endpoint,
            store_kind: "fixture_test".into(),
        })
    }

    fn destroy(
        &self,
        _: &heimdall_app::transport::TransportKeyRecord,
    ) -> Result<(), heimdall_app::transport::KeyStoreRefusal> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl heimdall_app::transport::ServeControl for TransportFakes {
    fn check_policy(
        &self,
        _: &heimdall_contract::route::ExposurePolicy,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    async fn start(&self) -> Result<(), heimdall_app::OpError> {
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn apply_narrowing(&self) -> heimdall_app::transport::AdmissionReport {
        self.narrowed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        heimdall_app::transport::AdmissionReport::Applied
    }

    async fn stop(&self) -> heimdall_app::transport::AdmissionReport {
        heimdall_app::transport::AdmissionReport::Applied
    }
}

impl heimdall_app::transport::PeerEnrollments for TransportFakes {
    fn clear(&self) -> Result<usize, heimdall_app::OpError> {
        Ok(0)
    }
}

/// ⟨W2 fixes⟩ U56-Q6 and U56's revocation hook: a transport widening record is bound to the
/// exact exposure delta its request applied when it was created (shown with the record);
/// approval executes only while that delta still holds: after another approved widening
/// changed the endpoint, the first record's approval is refused
/// `decision_binding_mismatch` before it is claimed (it stays pending, no key is created),
/// while the intact one ran once. A client revocation applies its narrowing to the serve
/// child's supervision after the tombstone and reports it.
#[tokio::test]
async fn transport_widening_runs_only_its_exact_delta_and_revocation_narrows_admission() {
    let fakes = Arc::new(TransportFakes::default());
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    let mut rig = Rig::over(store, true, Arc::new(MemoryLines::default_pair())).await;
    // Rebuild the dispatcher with the transport ports (the rig's has none).
    let ops = Operations::start(OperationsConfig {
        store: rig.store.clone(),
        clock: rig.clock.clone(),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: rig.environment.clone(),
        adapters: Vec::new(),
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    let lines: Arc<dyn heimdall_remote::line::ManagementLines> = rig.lines.clone();
    let serve: Arc<dyn heimdall_app::transport::ServeControl> = fakes.clone();
    rig.dispatcher = OperationsDispatcher::new(
        ops.clone(),
        EventRelay::spawn(&ops, rig.stop.clone()),
        rig.clock.clone(),
    )
    .with_runner(Arc::new(PairedRunner::new(
        rig.store.clone(),
        ops,
        rig.clock.clone(),
        RunnerOptions {
            lines: Some(lines),
            command: Some(ServeCommand::new(HEIMDALL, HOME).unwrap()),
            management_policy: ManagementPolicy::Verified,
            admission: None,
            transport: Some(heimdall_runtime::paired::RunnerTransport {
                keys: fakes.clone(),
                serve,
                peers: fakes.clone(),
            }),
        },
    )));
    let owner = rig.enroll(1, Role::Owner);
    let mut bound = rig.dispatcher.clone();
    Dispatcher::bind_paired(&mut bound, &hello(Some(&owner), &[], false)).unwrap();
    let enable = |id: &str| {
        req(&format!(
            r#"{{"op":"transport","action":"enable","serve":true,"request_id":"{id}"}}"#
        ))
    };
    let mut decisions = Vec::new();
    for id in ["t1", "t2"] {
        let env = bound.handle(&paired_session(), enable(id)).await;
        assert_eq!(env.code, Code::ApprovalRequired, "{env:?}");
        decisions.push(env.next.unwrap().decision_ref.unwrap());
    }
    // The record shows the exact delta it is bound to.
    let mut local = rig.connect(hello(None, &[], true)).await.unwrap();
    let listed = local
        .request(req(r#"{"op":"inspect","subject":"decisions"}"#))
        .await
        .unwrap();
    assert!(
        listed.data.to_string().contains("serve_after"),
        "{listed:?}"
    );
    assert_eq!(local.attend().await.unwrap().code, Code::Ok);
    let approve = |d: &str| {
        req(&format!(
            r#"{{"op":"decide","decision_id":"{d}","verdict":"approve"}}"#
        ))
    };
    // The second runs once: a key, a consent, the serve child started.
    let ran = local.request(approve(&decisions[1])).await.unwrap();
    assert_eq!(ran.code, Code::Ok, "{ran:?}");
    assert_eq!(fakes.created.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(fakes.started.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The first was bound to the delta from a non-serving endpoint: it no longer holds.
    let refused = local.request(approve(&decisions[0])).await.unwrap();
    assert_eq!(
        reason_of(&refused).as_deref(),
        Some(reason::DECISION_BINDING_MISMATCH),
        "{refused:?}"
    );
    assert_eq!(
        fakes.created.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "nothing executed"
    );
    assert!(
        rig.store
            .transaction(|tx| tx.pending_decisions())
            .unwrap()
            .iter()
            .any(|d| d.id.as_str() == decisions[0]),
        "not claimed"
    );
    // A revocation narrows Iroh admission through the supervision, after the tombstone.
    let viewer = rig.enroll(2, Role::Viewer);
    let mut l2 = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    let revoked = l2
        .request(req(&format!(
            r#"{{"op":"remote_environment","action":"revoke_client","environment":"{}","client":"{viewer}"}}"#,
            rig.environment
        )))
        .await
        .unwrap();
    assert_eq!(revoked.code, Code::Ok, "{revoked:?}");
    assert_eq!(revoked.data["iroh_admission"]["state"], "applied");
    assert_eq!(revoked.data["line_removed"], true);
    assert_eq!(fakes.narrowed.load(std::sync::atomic::Ordering::SeqCst), 1);
}
