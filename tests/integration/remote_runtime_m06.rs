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
//!   new record and no re-execution, across a restart;
//! * ⟨M06 W3⟩ a paired owner controller's `runner/1` forms reach the runner runtime (limited
//!   roles, the local owner and a plain runtime still refuse them), and the runner-local
//!   decisions (`issuer_trust`, the time source) are the attended local owner's only.
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
    /// What a recheck's "`sshd -T` verifies now" answers on this runner (true at first): the
    /// rig never runs the account's sshd.
    sshd_verifies: Arc<std::sync::atomic::AtomicBool>,
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
        let sshd_verifies = Arc::new(std::sync::atomic::AtomicBool::new(true));
        if store.transaction(is_runner).unwrap() {
            let shared: Arc<dyn heimdall_remote::line::ManagementLines> = lines.clone();
            // ⟨M06 W3⟩ With its runner runtime, as `Service::start_with` wires it.
            let runtime = Arc::new(heimdall_runtime::runner::RunnerRuntime::new(
                store.clone(),
                clock.clone(),
                Arc::new(heimdall_credential::vault::KeyVault::new()),
                heimdall_runtime::runner::time::RunnerTimePolicy::default(),
                heimdall_contract::remote::RunnerLifetime::Unknown,
            ));
            dispatcher = dispatcher.with_runner(Arc::new(
                PairedRunner::new(
                    store.clone(),
                    ops,
                    clock.clone(),
                    RunnerOptions {
                        lines: Some(shared),
                        command: Some(ServeCommand::new(HEIMDALL, HOME).unwrap()),
                        management_policy: ManagementPolicy::Verified,
                        ..RunnerOptions::default()
                    },
                )
                .with_runtime(runtime)
                .with_sshd_recheck({
                    let verifies = sshd_verifies.clone();
                    Arc::new(move || verifies.load(std::sync::atomic::Ordering::SeqCst))
                }),
            ));
        }
        Self {
            sshd_verifies,
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
                    iroh_admission: false,
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
                iroh_endpoint: None,
                // ⟨§18.7 item 16⟩ A limited role reports its probes; an owner need not.
                probe: (role != Role::Owner).then_some(PROBES_AGREE),
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

/// What a joining device's probes observe on a restricted session.
const PROBES_AGREE: heimdall_contract::remote::ProbeObservation =
    heimdall_contract::remote::ProbeObservation {
        pty_refused: true,
        forward_refused: true,
        agent_forward_refused: true,
        setenv_canary_delivered: false,
    };

fn join_request(j: &JoinRequest) -> Request {
    let probe = j.probe.map_or_else(String::new, |p| {
        format!(r#","probe":{}"#, serde_json::to_string(&p).unwrap())
    });
    req(&format!(
        r#"{{"op":"remote_environment","action":"join","environment":"{}","invitation":"{}","role":"{}","generation":{}{probe}}}"#,
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
    capabilities.insert(capability::RUNNER_V1.to_owned());
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
    // ⟨rev 6.3; ADR-0006 §18.7 items 9 and 15⟩ Every attended-only frame names its reason.
    let decide = format!(
        r#"{{"op":"decide","decision_id":"{}","verdict":"approve"}}"#,
        DecisionId::from_random_bytes([1; 16])
    );
    let mut answers = vec![("attend", a.attend().await.unwrap())];
    for form in [
        decide.as_str(),
        r#"{"op":"confirm_time","observed_wall":"2026-11-20T10:00:00Z"}"#,
        r#"{"op":"issuer","action":"unlock"}"#,
        r#"{"op":"device","action":"retire"}"#,
    ] {
        answers.push((form, a.request(req(form)).await.unwrap()));
    }
    for (form, refused) in answers {
        assert_eq!(refused.code, Code::InteractionRequired, "{form}");
        assert_eq!(
            refused.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED,
            "{form}: {refused:?}"
        );
        assert_eq!(refused.data["error"]["effect_status"], "none", "{form}");
    }
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

/// ⟨ADR-0006 §18.7 item 16; ADR-0012 §3.2 "Limits"⟩ `Join.probe` through the real dispatcher,
/// on a runner whose sshd policy is verified:
///
/// * **agree**: a viewer's join with an agreeing observation activates it;
/// * **missing for a limited role**: refused (`USAGE_ERROR`, effect `none`), the client stays
///   pending and the runner stays verified, and the same join with the observation succeeds;
/// * **owner exempt**: an owner's join without an observation activates it;
/// * **disagree**: refused `management_sshd_unsupported`, the client stays pending, and the
///   downgrade is sticky: a later limited invitation is refused
///   `management_sshd_unverified` at its runner-local approval (no client, no line), another
///   pending limited client's agreeing join is refused, an owner's join still succeeds.
#[tokio::test]
async fn a_joins_probe_observation_is_checked_before_the_commit() {
    let rig = Rig::new(true).await;
    let owner = rig.enroll(1, Role::Owner);
    let state_of = |c: &ClientId| {
        rig.store
            .transaction(|tx| tx.remote_client(c))
            .unwrap()
            .unwrap()
            .state
    };
    let pending_session = |c: ClientId| {
        let rig = &rig;
        async move {
            rig.connect(hello(Some(&c), &[capability::REMOTE_CONTROL_V1], false))
                .await
                .unwrap()
        }
    };
    // Agree.
    let agreeing = rig.invite(2, Role::Viewer);
    let mut s = pending_session(agreeing.client.clone()).await;
    let joined = s.request(join_request(&agreeing.join)).await.unwrap();
    assert_eq!(joined.code, Code::Ok, "{joined:?}");
    assert_eq!(state_of(&agreeing.client), ClientState::Active);
    // Missing for a limited role.
    let silent = rig.invite(3, Role::Requester);
    let mut s = pending_session(silent.client.clone()).await;
    let mut unobserved = silent.join.clone();
    unobserved.probe = None;
    let refused = s.request(join_request(&unobserved)).await.unwrap();
    assert_eq!(refused.code, Code::UsageError, "{refused:?}");
    assert_eq!(refused.data["error"]["effect_status"], "none");
    assert_eq!(reason_of(&refused), None);
    assert_eq!(state_of(&silent.client), ClientState::Pending);
    let joined = s.request(join_request(&silent.join)).await.unwrap();
    assert_eq!(
        joined.code,
        Code::Ok,
        "the runner was not lowered: {joined:?}"
    );
    // Owner exempt.
    let second_owner = rig.invite(4, Role::Owner);
    assert_eq!(second_owner.join.probe, None);
    let mut s = pending_session(second_owner.client.clone()).await;
    let joined = s.request(join_request(&second_owner.join)).await.unwrap();
    assert_eq!(joined.code, Code::Ok, "{joined:?}");
    // Disagree: an agent was forwarded.
    let waiting = rig.invite(6, Role::Viewer);
    let unrestricted = rig.invite(5, Role::Viewer);
    let mut s = pending_session(unrestricted.client.clone()).await;
    let mut disagreeing = unrestricted.join.clone();
    disagreeing.probe = Some(heimdall_contract::remote::ProbeObservation {
        agent_forward_refused: false,
        ..PROBES_AGREE
    });
    let refused = s.request(join_request(&disagreeing)).await.unwrap();
    assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
    assert_eq!(
        reason_of(&refused).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNSUPPORTED)
    );
    assert_eq!(state_of(&unrestricted.client), ClientState::Pending);
    // ⟨ADR-0012 §3.2⟩ The refusal's durable row, written by the join's own transaction.
    assert_eq!(
        rig.store
            .transaction(|tx| tx.runner_downgrade())
            .unwrap()
            .map(|d| (d.cause, d.epoch)),
        Some(("probe_disagreed".to_owned(), 1))
    );
    // Sticky: the same client's agreeing retry, and another pending limited client.
    for (session, join) in [
        (&mut s, &unrestricted.join),
        (
            &mut pending_session(waiting.client.clone()).await,
            &waiting.join,
        ),
    ] {
        let refused = session.request(join_request(join)).await.unwrap();
        assert_eq!(
            reason_of(&refused).as_deref(),
            Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
            "{refused:?}"
        );
    }
    assert_eq!(state_of(&waiting.client), ClientState::Pending);
    // A later limited invitation: refused at its runner-local approval.
    let (public_key, fp) = key(7);
    let mut a = rig.connect(hello(Some(&owner), &[], false)).await.unwrap();
    let pending = a
        .request(req(&format!(
            r#"{{"op":"remote_environment","action":"invite","environment":"{}","role":"viewer","key_fingerprint":"{fp}","public_key":"{public_key}","request_id":"inv-late"}}"#,
            rig.environment
        )))
        .await
        .unwrap();
    assert_eq!(pending.code, Code::ApprovalRequired, "{pending:?}");
    let decision = pending.next.unwrap().decision_ref.unwrap();
    let clients = rig
        .store
        .transaction(|tx| tx.remote_clients())
        .unwrap()
        .len();
    let mut local = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(local.attend().await.unwrap().code, Code::Ok);
    let decided = local
        .request(req(&format!(
            r#"{{"op":"decide","decision_id":"{decision}","verdict":"approve"}}"#
        )))
        .await
        .unwrap();
    assert_eq!(
        reason_of(&decided).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
        "{decided:?}"
    );
    assert_eq!(
        rig.store
            .transaction(|tx| tx.remote_clients())
            .unwrap()
            .len(),
        clients,
        "no client was created"
    );
    // An owner still joins.
    let third_owner = rig.invite(8, Role::Owner);
    let mut s = pending_session(third_owner.client.clone()).await;
    let joined = s.request(join_request(&third_owner.join)).await.unwrap();
    assert_eq!(joined.code, Code::Ok, "{joined:?}");
}

/// Fails the next commit once armed (`heimdall_store`'s fault points): the process stops
/// between a transaction's last statement and its `COMMIT`.
#[derive(Debug, Default)]
struct FailNextCommit(std::sync::atomic::AtomicBool);

impl heimdall_store::FaultHook for FailNextCommit {
    fn at(&self, point: heimdall_store::FaultPoint) -> heimdall_store::FaultAction {
        if point == heimdall_store::FaultPoint::BeforeCommit
            && self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            heimdall_store::FaultAction::Fail
        } else {
            heimdall_store::FaultAction::Continue
        }
    }
}

/// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ A join refused on a disagreeing probe
/// commits its refusal and the runner's owner-only row in **one** transaction, and the
/// join's own changes do not commit. The check (`RunnerPolicy::check_join_in`) is handed
/// the join's commit transaction:
/// * **a failure between the check and the commit** (the fault armed from inside the
///   check, so it is that transaction's commit): neither the row nor anything of the join
///   is there afterwards;
/// * **the refusal**: the row is there (first cause, epoch 1) and the client, its
///   invitation and the admission generation are exactly as before;
/// * **read in the same transaction**: the next join, agreeing, is refused
///   `management_sshd_unverified` by the row alone (a policy object that never saw the
///   disagreement), and moves nothing;
/// * **an owner's disagreeing join** on a verified runner activates and writes the row in
///   its one transaction; failed at the commit, neither happens.
#[tokio::test]
async fn a_refused_joins_downgrade_commits_with_the_refusal_or_not_at_all() {
    use heimdall_remote::roles::Refusal;
    let disagree = heimdall_contract::remote::ProbeObservation {
        pty_refused: false,
        ..PROBES_AGREE
    };
    let row = |cause: &str, epoch| Some((cause.to_owned(), epoch));

    let (rig, faults) = faulting_rig().await;
    let viewer = rig.invite(2, Role::Viewer);
    let before = everything(&rig);
    assert_eq!(before.0, None);
    // A failure between the check and the commit: nothing of either.
    assert_eq!(
        checked_join(&rig, &faults, &viewer, Some(disagree), true),
        Err(Refusal::State)
    );
    assert_eq!(everything(&rig), before);
    // The refusal: the row, and nothing of the join.
    assert_eq!(
        checked_join(&rig, &faults, &viewer, Some(disagree), false),
        Err(Refusal::ManagementSshdUnsupported)
    );
    let refused = everything(&rig);
    assert_eq!(refused.0, row("probe_disagreed", 1));
    assert_eq!(
        (&refused.1, &refused.2, &refused.3),
        (&before.1, &before.2, &before.3),
        "the refused join changed something of its own"
    );
    // The row is read in the join's transaction: an agreeing join is refused by it.
    assert_eq!(
        checked_join(&rig, &faults, &viewer, Some(PROBES_AGREE), false),
        Err(Refusal::ManagementSshdUnverified)
    );
    assert_eq!(everything(&rig), refused);

    // An owner's disagreeing join on a verified runner, failed at its commit: no
    // activation and no row.
    let (rig, faults) = faulting_rig().await;
    let owner = rig.invite(3, Role::Owner);
    let before = everything(&rig);
    assert_eq!(
        checked_join(&rig, &faults, &owner, Some(disagree), true),
        Err(Refusal::State)
    );
    assert_eq!(everything(&rig), before);
    // And committed: both, together.
    assert_eq!(
        checked_join(&rig, &faults, &owner, Some(disagree), false),
        Ok(owner.client.clone())
    );
    let joined = everything(&rig);
    assert_eq!(joined.0, row("probe_disagreed", 1));
    assert!(
        joined
            .1
            .iter()
            .any(|c| c.client == owner.client && c.state == ClientState::Active),
        "{:?}",
        joined.1
    );
}

/// A runner over a store whose next commit can be failed.
async fn faulting_rig() -> (Rig, Arc<FailNextCommit>) {
    let faults = Arc::new(FailNextCommit::default());
    let store = Arc::new(Store::open_in_memory(faults.clone()).unwrap());
    let rig = Rig::over(store, true, Arc::new(MemoryLines::default_pair())).await;
    (rig, faults)
}

/// What [`everything`] reads.
type Everything = (
    Option<(String, u64)>,
    Vec<heimdall_store::ext_m06::RemoteClientRecord>,
    Vec<heimdall_store::ext_m06::RemoteInvitationRecord>,
    u64,
);

/// The downgrade row (cause, epoch), every client, every pending invitation and the
/// admission generation.
fn everything(rig: &Rig) -> Everything {
    rig.store
        .transaction(|tx| {
            Ok((
                tx.runner_downgrade()?.map(|d| (d.cause, d.epoch)),
                tx.remote_clients()?,
                tx.remote_invitations_pending()?,
                tx.remote_authority_generation()?,
            ))
        })
        .unwrap()
}

/// One join through the invitation service with the runner's own in-transaction check
/// (a policy object that has seen nothing before); `fail` arms the fault after the check
/// ran, inside the join's commit transaction.
fn checked_join(
    rig: &Rig,
    faults: &FailNextCommit,
    invited: &Invited,
    probe: Option<heimdall_contract::remote::ProbeObservation>,
    fail: bool,
) -> Result<ClientId, heimdall_remote::roles::Refusal> {
    let command = ServeCommand::new(HEIMDALL, HOME).unwrap();
    let policy = heimdall_runtime::paired::RunnerPolicy::with_store(
        ManagementPolicy::Verified,
        rig.store.clone(),
    );
    let mut request = invited.join.clone();
    request.probe = probe;
    rig.invitations(&command)
        .join_confirmed(&invited.client, &request, &rig.now(), &|tx, j| {
            let (judged, _) =
                policy.check_join_in(tx, &j.client, j.role, request.probe.as_ref(), t0())?;
            faults.0.store(fail, std::sync::atomic::Ordering::SeqCst);
            Ok(judged)
        })
        .map(|joined| joined.join.client)
}

fn recheck_request(
    environment: &EnvironmentId,
    probe: &heimdall_contract::remote::ProbeObservation,
) -> Request {
    Request::RemoteEnvironment(
        heimdall_contract::remote::RemoteEnvironmentRequest::RunnerPolicyRecheck {
            environment: environment.clone(),
            probe: *probe,
        },
    )
}

fn lift_request(id: &str) -> Request {
    req(&format!(
        r#"{{"op":"runner_local","action":"policy_recheck","request_id":"{id}"}}"#
    ))
}

/// ⟨ADR-0006 §18.7 items 18–19⟩ Lifting the owner-only downgrade, over the real dispatcher
/// and IPC sessions. Only an owner's **agreeing** probe, recorded while the runner's own
/// sshd check verifies now, followed by the **attended local** owner's lift within 15
/// minutes and before any later downgrade, lifts it. Each of these does not: no evidence;
/// a limited client's recheck (`role_insufficient`); a disagreeing probe
/// (`management_sshd_unsupported`, and one more downgrade event); an agreeing probe while
/// the sshd check does not verify (`management_sshd_unverified`); an unattended lift; a
/// paired owner's `runner_local.policy_recheck` (`local_owner_required`); stale evidence;
/// evidence from before a later downgrade.
#[tokio::test]
async fn the_owner_only_downgrade_lifts_only_on_fresh_agreeing_evidence_attended() {
    use heimdall_runtime::paired::{OwnerOnlyCause, record_owner_only};
    let rig = Rig::new(true).await;
    let owner = rig.enroll(1, Role::Owner);
    let viewer = rig.enroll(2, Role::Viewer);
    record_owner_only(&rig.store, OwnerOnlyCause::SessionPty, rig.clock.wall()).unwrap();
    let downgrade = || rig.store.transaction(|tx| tx.runner_downgrade()).unwrap();
    let evidence = || rig.store.transaction(|tx| tx.policy_recheck()).unwrap();
    let unverified = |env: &Envelope<serde_json::Value>, said: &str| {
        assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
        assert_eq!(
            reason_of(env).as_deref(),
            Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
            "{env:?}"
        );
        assert_eq!(env.data["error"]["effect_status"], "none", "{env:?}");
        let message = env.data["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(said), "{message}");
    };
    let mut attended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(attended.attend().await.unwrap().code, Code::Ok);
    let mut paired = rig.connect(hello(Some(&owner), &[], false)).await.unwrap();

    // While it stands, a limited join is refused, whatever its probes say.
    let early = rig.invite(3, Role::Viewer);
    let mut pending = rig
        .connect(hello(
            Some(&early.client),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await
        .unwrap();
    let refused = pending.request(join_request(&early.join)).await.unwrap();
    assert_eq!(
        reason_of(&refused).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
        "{refused:?}"
    );

    // No evidence: the attended lift is refused.
    let env = attended.request(lift_request("l-1")).await.unwrap();
    unverified(&env, "no recheck from an owner's controller is recorded");
    assert_eq!(downgrade().unwrap().epoch, 1);

    // A limited client cannot leave evidence: its session never negotiates
    // `remote-control/1`, so the form is refused before dispatch (the role table itself
    // answers `role_insufficient`: `roles::tests`).
    let mut limited = rig.connect(hello(Some(&viewer), &[], false)).await.unwrap();
    let env = limited
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    assert_eq!(env.code, Code::SchemaUnsupported, "{env:?}");
    assert_eq!(evidence(), None);

    // A paired owner cannot lift: the form has no remote decision path.
    let env = paired.request(lift_request("l-2")).await.unwrap();
    assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
    assert_eq!(
        reason_of(&env).as_deref(),
        Some(reason::LOCAL_OWNER_REQUIRED),
        "{env:?}"
    );

    // A disagreeing probe: refused, nothing recorded, and one more downgrade event.
    let disagreeing = heimdall_contract::remote::ProbeObservation {
        pty_refused: false,
        ..PROBES_AGREE
    };
    let env = paired
        .request(recheck_request(&rig.environment, &disagreeing))
        .await
        .unwrap();
    assert_eq!(
        reason_of(&env).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNSUPPORTED),
        "{env:?}"
    );
    assert_eq!(evidence(), None);
    let standing = downgrade().unwrap();
    assert_eq!(
        (standing.epoch, standing.cause.as_str()),
        (2, "session_pty")
    );
    let env = attended.request(lift_request("l-3")).await.unwrap();
    unverified(&env, "no recheck");

    // An agreeing probe while the runner's own sshd check does not verify: not recorded.
    rig.sshd_verifies
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let env = paired
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    unverified(&env, "does not verify now");
    assert_eq!(evidence(), None);
    rig.sshd_verifies
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // Both hold: recorded, for the standing epoch, naming the probing controller.
    let env = paired
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["recorded"], true);
    assert_eq!(env.data["controller"], owner.as_str());
    let recorded = evidence().unwrap();
    assert_eq!((recorded.epoch, &recorded.controller), (2, &owner));
    assert!(downgrade().is_some(), "the recheck lifts nothing");

    // An unattended local lift: refused.
    let mut unattended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    let env = unattended.request(lift_request("l-4")).await.unwrap();
    assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
    assert!(downgrade().is_some());

    // Stale: one second past 15 minutes.
    rig.clock.advance(Duration::from_secs(15 * 60 + 1));
    let env = attended.request(lift_request("l-5")).await.unwrap();
    unverified(&env, "older than 15 minutes");
    assert!(downgrade().is_some());

    // From before a later downgrade: fresh evidence, then another event.
    let env = paired
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    record_owner_only(&rig.store, OwnerOnlyCause::SessionAgent, rig.clock.wall()).unwrap();
    let env = attended.request(lift_request("l-6")).await.unwrap();
    unverified(&env, "from before a later downgrade");
    assert_eq!(downgrade().unwrap().epoch, 3);

    // Fresh agreeing evidence for the standing epoch, then the attended lift.
    let env = paired
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    rig.clock.advance(Duration::from_secs(14 * 60));
    let env = attended.request(lift_request("l-7")).await.unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["lifted"], true);
    assert_eq!(env.data["controller"], owner.as_str());
    assert_eq!(downgrade(), None);
    assert_eq!(evidence(), None, "the evidence is spent with the lift");
    // The running runner admits limited roles again, without a restart.
    let late = rig.invite(4, Role::Viewer);
    let mut pending = rig
        .connect(hello(
            Some(&late.client),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await
        .unwrap();
    let joined = pending.request(join_request(&late.join)).await.unwrap();
    assert_eq!(joined.code, Code::Ok, "{joined:?}");
    // Nothing to lift: converges, and a recheck records nothing.
    let env = attended.request(lift_request("l-8")).await.unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["lifted"], false);
    let env = paired
        .request(recheck_request(&rig.environment, &PROBES_AGREE))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["recorded"], false);
    assert_eq!(evidence(), None);
    // A disagreeing recheck of a verified runner lowers it again.
    let env = paired
        .request(recheck_request(&rig.environment, &disagreeing))
        .await
        .unwrap();
    assert_eq!(
        reason_of(&env).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNSUPPORTED),
        "{env:?}"
    );
    let again = downgrade().unwrap();
    assert_eq!((again.epoch, again.cause.as_str()), (1, "probe_disagreed"));
}

/// ⟨ADR-0006 §18.7 items 18–19⟩ "`sshd -T` alone never lifts it": a runner that starts over
/// a store holding the downgrade is owner-only although its start check verified and its
/// sshd check verifies now, and the attended local owner's lift is refused while no owner
/// controller's probe evidence is recorded. (Revert proof: target/m06-w3/followups-e/revert/.)
#[tokio::test]
async fn sshd_t_alone_does_not_lift_the_downgrade() {
    use heimdall_runtime::paired::{OwnerOnlyCause, record_owner_only};
    let store = Arc::new(Store::open_in_memory(Arc::new(NoFaults)).unwrap());
    record_owner_only(&store, OwnerOnlyCause::Probe, t0()).unwrap();
    // A new start: the start check verified (`ManagementPolicy::Verified`), and so does the
    // check now.
    let rig = Rig::over(store, true, Arc::new(MemoryLines::default_pair())).await;
    assert!(rig.sshd_verifies.load(std::sync::atomic::Ordering::SeqCst));
    rig.enroll(1, Role::Owner);
    let invited = rig.invite(2, Role::Viewer);
    let mut pending = rig
        .connect(hello(
            Some(&invited.client),
            &[capability::REMOTE_CONTROL_V1],
            false,
        ))
        .await
        .unwrap();
    let refused = pending.request(join_request(&invited.join)).await.unwrap();
    assert_eq!(
        reason_of(&refused).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
        "{refused:?}"
    );
    let mut attended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(attended.attend().await.unwrap().code, Code::Ok);
    let env = attended.request(lift_request("l-1")).await.unwrap();
    assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
    assert_eq!(
        reason_of(&env).as_deref(),
        Some(reason::MANAGEMENT_SSHD_UNVERIFIED),
        "{env:?}"
    );
    assert!(
        rig.store
            .transaction(|tx| tx.runner_downgrade())
            .unwrap()
            .is_some(),
        "the downgrade stands"
    );
}

/// ⟨ADR-0006 §18.7 item 15; follow-ups C Q5⟩ The dispatcher's own entry, past every session
/// gate: an attended-only form from a caller bound to a paired client answers
/// `local_owner_required`, even when the caller claims attendance; a local unattended caller
/// keeps the plain `INTERACTION_REQUIRED` (ask and retry can succeed there).
#[tokio::test]
async fn the_dispatcher_names_local_owner_required_for_a_paired_callers_attended_only_form() {
    use heimdall_app::{Attendance, Caller};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    let rig = Rig::new(false).await;
    let local = CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner);
    let paired = CallerContext {
        remote_client: Some(ClientId::from_random_bytes([9; 16])),
        ..local.clone()
    };
    let forms = [
        r#"{"op":"confirm_time","observed_wall":"2026-11-20T10:00:00Z"}"#,
        r#"{"op":"issuer","action":"unlock"}"#,
    ];
    for form in forms {
        for caller in [
            Caller::unattended(paired.clone()),
            Caller {
                context: paired.clone(),
                attendance: Attendance::Attended { since: t0() },
                interaction: InteractionMode::Interactive,
            },
        ] {
            let env = rig.dispatcher.handle_as(&caller, req(form)).await;
            assert_eq!(env.code, Code::InteractionRequired, "{form}: {env:?}");
            assert_eq!(
                reason_of(&env).as_deref(),
                Some(reason::LOCAL_OWNER_REQUIRED),
                "{form}: {env:?}"
            );
            assert_eq!(env.data["error"]["effect_status"], "none", "{form}");
        }
        let env = rig
            .dispatcher
            .handle_as(&Caller::unattended(local.clone()), req(form))
            .await;
        assert_eq!(env.code, Code::InteractionRequired, "{form}: {env:?}");
        assert_eq!(reason_of(&env), None, "{form}: {env:?}");
    }
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
            sshd: None,
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

/// ⟨M06 W3; m06-plan W2 carry-over⟩ A paired owner controller's `runner/1` forms reach the
/// runner runtime through the real dispatcher and IPC session: the runner offers `runner/1`
/// to it, a time challenge is answered once the local owner designated it (the runner-local
/// form, attended), and a prepare for a grant the runner does not hold is the runtime's own
/// `NOT_FOUND`. The role table and pre-dispatch rules still come first: a limited role cannot
/// negotiate `runner/1`, a pending client cannot either; the local owner's runner form is
/// refused (`driver_unavailable`: controllers only); a plain runtime offers no `runner/1` and
/// refuses the form as before.
#[tokio::test]
async fn paired_runner_forms_reach_the_runner_runtime_and_other_runtimes_refuse_them() {
    let rig = Rig::new(true).await;
    let owner = rig.enroll(1, Role::Owner);
    let requester = rig.enroll(2, Role::Requester);
    let pending = rig.invite(3, Role::Owner);
    let challenge = req(r#"{"op":"runner","action":"time_challenge"}"#);

    // The local owner designates the paired owner as the time source, attended.
    let mut local = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(local.attend().await.unwrap().code, Code::Ok);
    let designated = local
        .request(req(&format!(
            r#"{{"op":"runner_local","action":"designate_time_source","client":"{owner}","request_id":"r-ts"}}"#
        )))
        .await
        .unwrap();
    assert_eq!(designated.code, Code::Ok, "{designated:?}");

    // The paired owner negotiates runner/1 and its forms reach the runner runtime.
    let mut a = rig
        .connect(hello(Some(&owner), &[capability::RUNNER_V1], false))
        .await
        .unwrap();
    let env = a.request(challenge.clone()).await.unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(
        env.data["nonce"].as_str().map(str::len),
        Some(32),
        "{env:?}"
    );
    // ⟨M06 W3 `driver`; ADR-0006 §18.7 item 11⟩ The runner's per-session gate, through the
    // real dispatcher: a session that has not read the authority report is refused
    // `resync_pending` before any issuance check; after the report the form reaches issuance.
    let prepare_form = r#"{"op":"runner","action":"prepare_remote_grant","grant":"grant_0000000000000000000000","grant_generation":1}"#;
    let gated = a.request(req(prepare_form)).await.unwrap();
    assert_eq!(gated.code, Code::CapabilityUnavailable, "{gated:?}");
    assert_eq!(gated.data["error"]["reason"], "resync_pending");
    assert_eq!(gated.data["error"]["effect_status"], "none");
    let report = a
        .request(req(r#"{"op":"runner","action":"authority_report"}"#))
        .await
        .unwrap();
    assert_eq!(report.code, Code::Ok, "{report:?}");
    let prepare = a.request(req(prepare_form)).await.unwrap();
    assert_eq!(prepare.code, Code::NotFound, "{prepare:?}");
    assert_eq!(prepare.data["error"]["resource"]["kind"], "grant");

    // A limited role and a pending client cannot negotiate runner/1 at all.
    for client in [&requester, &pending.client] {
        let refused = rejected(
            rig.connect(hello(Some(client), &[capability::RUNNER_V1], false))
                .await,
        );
        assert!(
            matches!(
                refused.code,
                Code::SchemaUnsupported | Code::CapabilityUnavailable
            ),
            "{refused:?}"
        );
    }
    // Without negotiating it, the form never dispatches.
    let mut r = rig
        .connect(hello(Some(&requester), &[], false))
        .await
        .unwrap();
    assert_eq!(
        r.request(challenge.clone()).await.unwrap().code,
        Code::SchemaUnsupported
    );
    // The local owner is not a controller: the runtime refuses it.
    let mut l = rig
        .connect(hello(None, &[capability::RUNNER_V1], false))
        .await
        .unwrap();
    let env = l.request(challenge.clone()).await.unwrap();
    assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
    assert_eq!(reason_of(&env).as_deref(), Some(reason::DRIVER_UNAVAILABLE));

    // A plain runtime offers no runner/1 and still refuses the form.
    let plain = Rig::new(false).await;
    let refused = rejected(
        plain
            .connect(hello(None, &[capability::RUNNER_V1], false))
            .await,
    );
    assert_eq!(refused.code, Code::SchemaUnsupported, "{refused:?}");
    let mut p = plain.connect(hello(None, &[], false)).await.unwrap();
    assert_eq!(
        p.request(challenge).await.unwrap().code,
        Code::SchemaUnsupported
    );
}

/// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ The runner-local decisions over the real dispatcher: the
/// widening forms (`trust_issuer`, `designate_time_source`) need the attended local owner
/// (`INTERACTION_REQUIRED` unattended, nothing written); the narrowing forms the local owner;
/// a paired owner is refused before dispatch (`INTERACTION_REQUIRED`), whatever the form; a
/// controller that is not an active owner is `role_insufficient`.
#[tokio::test]
async fn runner_local_decisions_are_the_attended_local_owners_only() {
    let rig = Rig::new(true).await;
    let owner = rig.enroll(1, Role::Owner);
    let viewer = rig.enroll(2, Role::Viewer);
    let (ca, _) = key(9);
    let trust = |controller: &ClientId, rid: &str| {
        req(&format!(
            r#"{{"op":"runner_local","action":"trust_issuer","controller":"{controller}","ca_public_key":"{ca}","request_id":"{rid}"}}"#
        ))
    };
    let trusted = |rig: &Rig| {
        rig.store
            .transaction(|tx| tx.remote_issuer_trust())
            .unwrap()
    };
    // Unattended: refused, nothing written.
    let mut unattended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    let env = unattended.request(trust(&owner, "r-1")).await.unwrap();
    assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
    assert!(trusted(&rig).is_empty());
    // A paired owner: refused before dispatch, widening or narrowing.
    let mut paired = rig.connect(hello(Some(&owner), &[], false)).await.unwrap();
    for form in [
        trust(&owner, "r-2"),
        req(r#"{"op":"runner_local","action":"clear_time_source"}"#),
        // ⟨M06-W2-R02⟩ `remote init`'s form is the local owner's too.
        req(&format!(
            r#"{{"op":"runner_local","action":"enroll_owner","client":"{}","public_key":"ssh-ed25519 AAAA","request_id":"r-3"}}"#,
            owner.as_str()
        )),
    ] {
        let refused = paired.request(form).await.unwrap();
        assert_eq!(refused.code, Code::InteractionRequired);
        assert_eq!(
            refused.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED,
            "{refused:?}"
        );
    }
    // Attended: a limited client is not an issuer; the owner is.
    let mut attended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(attended.attend().await.unwrap().code, Code::Ok);
    let env = attended.request(trust(&viewer, "r-3")).await.unwrap();
    assert_eq!(reason_of(&env).as_deref(), Some(reason::ROLE_INSUFFICIENT));
    let env = attended.request(trust(&owner, "r-4")).await.unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    let entries = trusted(&rig);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].controller, owner);
    assert_eq!(
        env.data["ca_fingerprint"],
        entries[0].ca_fingerprint.as_str()
    );
    // Narrowing needs no attendance.
    let env = unattended
        .request(req(&format!(
            r#"{{"op":"runner_local","action":"distrust_issuer","ca_fingerprint":"{}"}}"#,
            entries[0].ca_fingerprint
        )))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["removed"], true);
    assert!(trusted(&rig).is_empty());
    let env = unattended
        .request(req(r#"{"op":"runner_local","action":"clear_time_source"}"#))
        .await
        .unwrap();
    assert_eq!(env.code, Code::Ok, "{env:?}");
    assert_eq!(env.data["cleared"], false);
}

/// ⟨M06-W2-R02; ADR-0006 §18.7 items 8 and 14⟩ `runner_local.enroll_owner` over the real
/// dispatcher, as `remote init` sends it while the runtime runs: the attended local owner
/// only (unattended: `INTERACTION_REQUIRED`, nothing written); idempotent for the same
/// `request_id` and for the same key and client under a new one (one client, the same
/// line); the same key under another client ID answers the first client; an endpoint ID
/// adds the owner's admission and first endpoint, the same one again is unchanged, and
/// another one never replaces it; another client's endpoint refuses the whole enrollment.
#[tokio::test]
async fn enroll_owner_is_attended_idempotent_and_never_replaces_an_endpoint() {
    let rig = Rig::new(true).await;
    let (public_key, fp) = key(31);
    let client = ClientId::from_random_bytes([0x31; 16]);
    // Two RFC 8032 test-vector public keys: endpoint IDs the Iroh library accepts too.
    let (ep_a, ep_b) = (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    let form = |client: &ClientId, key: &str, endpoint: Option<&str>, rid: &str| {
        let mut v = serde_json::json!({
            "op": "runner_local", "action": "enroll_owner", "client": client,
            "public_key": key, "request_id": rid,
        });
        if let Some(e) = endpoint {
            v["iroh_endpoint"] = e.into();
        }
        serde_json::from_value::<Request>(v).unwrap()
    };
    let clients = |rig: &Rig| rig.store.transaction(|tx| tx.remote_clients()).unwrap();
    let endpoints = |rig: &Rig| {
        rig.store
            .transaction(|tx| tx.remote_client_endpoints())
            .unwrap()
    };

    // Unattended: refused, nothing written.
    let mut unattended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], false))
        .await
        .unwrap();
    let env = unattended
        .request(form(&client, &public_key, None, "eo-1"))
        .await
        .unwrap();
    assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
    assert!(clients(&rig).is_empty());

    let mut attended = rig
        .connect(hello(None, &[capability::REMOTE_CONTROL_V1], true))
        .await
        .unwrap();
    assert_eq!(attended.attend().await.unwrap().code, Code::Ok);
    let first = attended
        .request(form(&client, &public_key, None, "eo-2"))
        .await
        .unwrap();
    assert_eq!(first.code, Code::Ok, "{first:?}");
    assert_eq!(first.data["created"], true);
    assert_eq!(first.data["client"], client.as_str());
    assert_eq!(first.data["key_fingerprint"], fp.as_str());
    assert_eq!(first.data["line_written"], true, "{first:?}");
    assert!(first.data.get("iroh_admission").is_none(), "{first:?}");
    // The same request again, the same key and client under a new request ID, and the same
    // key under another client ID: the first enrollment stands, unchanged.
    let other_id = ClientId::from_random_bytes([0x32; 16]);
    for (c, rid) in [(&client, "eo-2"), (&client, "eo-3"), (&other_id, "eo-4")] {
        let again = attended
            .request(form(c, &public_key, None, rid))
            .await
            .unwrap();
        assert_eq!(again.code, Code::Ok, "{rid}: {again:?}");
        assert_eq!(again.data["created"], false, "{rid}");
        assert_eq!(again.data["client"], client.as_str(), "{rid}");
        assert_eq!(
            again.data["management_line"], first.data["management_line"],
            "{rid}"
        );
        assert_eq!(again.data["line_written"], true, "{rid}");
    }
    let rows = clients(&rig);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].role, Role::Owner);
    assert!(endpoints(&rig).is_empty(), "no endpoint ID, no admission");

    // The later opt-in adds admission and a first endpoint, and never replaces one.
    for (endpoint, rid, change) in [
        (ep_a, "eo-5", "recorded"),
        (ep_a, "eo-5", "unchanged"),
        (ep_a, "eo-6", "unchanged"),
        (ep_b, "eo-7", "kept"),
    ] {
        let env = attended
            .request(form(&client, &public_key, Some(endpoint), rid))
            .await
            .unwrap();
        assert_eq!(env.code, Code::Ok, "{rid}: {env:?}");
        assert_eq!(env.data["created"], false);
        assert_eq!(env.data["iroh_admission"]["endpoint"], change, "{rid}");
        if change == "kept" {
            assert_eq!(env.data["iroh_admission"]["kept_endpoint"], ep_a);
        }
        let recorded = endpoints(&rig);
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].0, client);
        assert_eq!(recorded[0].1.as_str(), ep_a, "{rid}: never replaced");
    }
    assert!(
        rig.store
            .transaction(|tx| tx.remote_client_iroh_admission(&client))
            .unwrap()
    );

    // Another key that names the first client's endpoint: the whole enrollment is refused.
    let (second_key, _) = key(32);
    let refused = attended
        .request(form(&other_id, &second_key, Some(ep_a), "eo-8"))
        .await
        .unwrap();
    assert_eq!(refused.code, Code::UsageError, "{refused:?}");
    assert_eq!(refused.data["error"]["effect_status"], "none");
    assert_eq!(
        clients(&rig).len(),
        1,
        "the refused enrollment wrote no client"
    );

    // A paired owner never reaches it (`local_owner_required`), whatever it names.
    let mut paired = rig.connect(hello(Some(&client), &[], false)).await.unwrap();
    let refused = paired
        .request(form(&client, &public_key, Some(ep_b), "eo-9"))
        .await
        .unwrap();
    assert_eq!(refused.code, Code::InteractionRequired);
    assert_eq!(
        refused.data["error"]["reason"],
        heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED
    );
    assert_eq!(endpoints(&rig)[0].1.as_str(), ep_a);
}
