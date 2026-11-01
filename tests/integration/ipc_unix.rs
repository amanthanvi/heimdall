//! Unix control endpoint and sessions over real sockets (M01-U6; ADR-0006 §2.1,
//! §2.2, §2.3, §2.5; spec §13.2).
//!
//! Cargo test target `integration_ipc_unix` hosted by `heimdall-ipc` (review F09
//! convention): it uses only the crate's public API plus the `#[doc(hidden)]`
//! injected-`stat` rules of `heimdall_ipc::unix`. Every socket lives in a fresh
//! temp directory created by the test; nothing outside it is touched. The file is
//! `#![cfg(unix)]`: on Windows the target builds with zero tests.
//!
//! Not covered here, recorded as `blocked`: a real peer with a different uid
//! (needs a second Unix account) and a real foreign-owned socket file (needs
//! root to `chown`). Those branches are exercised with forged `PeerIdentity`
//! values and injected `PathFacts`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::event::{Cursor, Event, EventFilter, EventType, Snapshot};
use heimdall_contract::ids::{DecisionId, EnvironmentId, EventId, OperationId, PolicyId};
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, PeerInfo,
    PrincipalInfo, ServerMessage, capability,
};
use heimdall_contract::request::{
    CancelRequest, ConfirmTimeRequest, DecideRequest, InspectRequest, InspectSubject,
    InteractionMode, PolicyAction, Request, Verdict,
};
use heimdall_contract::{
    Code, EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, OperationState,
    PROTOCOL_VERSION, SchemaVersion,
};
use heimdall_ipc::endpoint::{
    EndpointKind, EndpointPaths, ExpectedOwner, PeerIdentity, PeerRejected, verify_peer,
};
use heimdall_ipc::frame::{FrameError, decode_frame, encode_frame};
use heimdall_ipc::session::{
    ConnectionLimits, ControlClient, ControlConnection, Dispatcher, LiveEvent, ServerRefusal,
    SessionInfo, SubscribeOutcome, SubscriptionStart, server_capabilities, server_refusal,
    transport_failure_envelope,
};
use heimdall_ipc::unix::{
    ConnectError, DirProblem, Existing, FileKind, Listener, PathFacts, check_own_socket,
    check_private_dir, classify_existing, connect, current_uid,
};
use heimdall_testkit::{CANARY_PREFIX, assert_no_canary};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

/// Synthetic canary built per run; never committed as a value.
fn canary() -> String {
    format!("{CANARY_PREFIX}{:x}", std::process::id())
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn server_info() -> PeerInfo {
    PeerInfo {
        name: "heimdall".into(),
        version: "test".into(),
    }
}

fn client_info() -> PeerInfo {
    PeerInfo {
        name: "heimdall-test-client".into(),
        version: "0".into(),
    }
}

fn inspect() -> Request {
    Request::Inspect(InspectRequest {
        subject: InspectSubject::Capabilities,
        preview: None,
    })
}

fn cancel(n: u8) -> Request {
    Request::Cancel(CancelRequest {
        operation_id: OperationId::from_random_bytes([n; 16]),
    })
}

/// Test dispatcher: records requests in a shared "journal" (cancel operation IDs)
/// and every dispatch with the session it saw, optionally holds each dispatch
/// until the gate grants a permit, answers `inspect` with the journal, and serves
/// subscriptions from a shared broadcast channel with cursors `c<seq>`.
///
/// Widening policy actions are answered the way the application must answer them
/// (ADR-0006 §3.1, §13.4 N04): never executed, always a decision record —
/// `APPROVAL_REQUIRED` on an attended session, `INTERACTION_REQUIRED` on an
/// unattended one, both with `next.decision_ref`.
#[derive(Clone)]
struct TestDispatcher {
    journal: Arc<Mutex<Vec<String>>>,
    seen: Arc<Mutex<Vec<(&'static str, SessionInfo)>>>,
    gate: Option<Arc<Semaphore>>,
    events: broadcast::Sender<Arc<LiveEvent>>,
}

impl TestDispatcher {
    fn new() -> Self {
        Self {
            journal: Arc::default(),
            seen: Arc::default(),
            gate: None,
            events: broadcast::channel(heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION).0,
        }
    }
    fn gated(gate: Arc<Semaphore>) -> Self {
        Self {
            gate: Some(gate),
            ..Self::new()
        }
    }
}

#[async_trait::async_trait]
impl Dispatcher for TestDispatcher {
    async fn dispatch(
        &self,
        session: &SessionInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        self.seen
            .lock()
            .unwrap()
            .push((request.kind(), session.clone()));
        if let Request::Cancel(c) = &request {
            self.journal
                .lock()
                .unwrap()
                .push(c.operation_id.as_str().to_owned());
        }
        if let Some(g) = &self.gate {
            g.acquire().await.unwrap().forget();
        }
        if request.is_widening_policy_action() {
            return decision_required(session.attended);
        }
        let journal = self.journal.lock().unwrap().clone();
        Envelope::ok(serde_json::json!({
            "kind": request.kind(),
            "principal": session.principal,
            "attended": session.attended,
            "interaction": session.interaction,
            "journal": journal,
        }))
    }

    async fn subscribe(
        &self,
        _session: &SessionInfo,
        _filter: EventFilter,
        from: Option<Cursor>,
    ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
        Ok(SubscriptionStart {
            cursor: from.unwrap_or_else(|| Cursor("c0".into())),
            boundary_seq: 0,
            snapshot: None,
            backlog: Vec::new(),
            live: self.events.subscribe(),
            cursor_for: Arc::new(|seq| Cursor(format!("c{seq}"))),
        })
    }
}

/// Fixture decision reference returned by the test dispatcher's decision flow.
const FIXTURE_DECISION_REF: &str = "dec_fixture";

/// The application's answer to a widening action (N04): a pending decision record,
/// nothing executed.
fn decision_required(attended: bool) -> Envelope<serde_json::Value> {
    let code = if attended {
        Code::ApprovalRequired
    } else {
        Code::InteractionRequired
    };
    let mut next = NextAction::for_code(code.clone());
    next.decision_ref = Some(FIXTURE_DECISION_REF.into());
    let mut env = Envelope::failed(
        None,
        ErrorDetail {
            code,
            effect_status: EffectStatus::None,
            retryable: false,
            resource: None,
            next: next.clone(),
            message: "an owner decision is required".into(),
        },
    );
    env.state = OperationState::AwaitingApproval;
    env.next = Some(next);
    env.map(|d| serde_json::to_value(d).unwrap())
}

/// A widening action's answer: the given code, a decision reference, no effect.
fn assert_decision_required(env: &Envelope<serde_json::Value>, code: Code) {
    assert_eq!(env.code, code);
    assert_eq!(env.state, OperationState::AwaitingApproval);
    let detail: ErrorData = serde_json::from_value(env.data.clone()).unwrap();
    assert_eq!(detail.error.effect_status, EffectStatus::None);
    assert_eq!(
        detail.error.next.decision_ref.as_deref(),
        Some(FIXTURE_DECISION_REF)
    );
    assert_eq!(
        env.next.as_ref().and_then(|n| n.decision_ref.as_deref()),
        Some(FIXTURE_DECISION_REF)
    );
}

/// A neutral event (cursor not yet personalized; the session sets it).
fn neutral(n: u64, ty: EventType, op: Option<OperationId>) -> Event {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_be_bytes());
    Event {
        schema_version: SchemaVersion::current(),
        event_id: EventId::from_random_bytes(id),
        event_type: ty,
        environment_id: env_id(),
        operation_id: op,
        resource: None,
        timestamp: heimdall_contract::Timestamp::UNIX_EPOCH,
        cursor: Cursor(String::new()),
        payload: serde_json::json!({ "n": n }),
    }
}

fn event(n: u64, ty: EventType, op: Option<OperationId>) -> Arc<LiveEvent> {
    Arc::new(LiveEvent {
        seq: n,
        event: neutral(n, ty, op),
    })
}

/// Stand-in for the runtime's event publisher (ADR-0006 §8): a durable log of
/// neutral sequences plus the bounded live channel. Every subscription is a
/// distinct reader `r<k>` with its own `cursor_for` (`r<k>:<seq>`), standing in
/// for reader-scoped cursor tags. `subscribe` follows the handshake order: live
/// receiver first, then (after `race` events committed by "another task" in
/// between) one read of head + backlog-or-snapshot.
#[derive(Clone)]
struct LogDispatcher {
    log: Arc<Mutex<Vec<LiveEvent>>>,
    live: broadcast::Sender<Arc<LiveEvent>>,
    readers: Arc<AtomicU64>,
    race: Arc<Mutex<Vec<LiveEvent>>>,
    snapshot_pad: usize,
}

impl LogDispatcher {
    fn new() -> Self {
        Self {
            log: Arc::default(),
            live: broadcast::channel(heimdall_contract::ipc::EVENT_BUFFER_PER_SUBSCRIPTION).0,
            readers: Arc::default(),
            race: Arc::default(),
            snapshot_pad: 0,
        }
    }

    /// Durable append, then live announce (no receivers is not an error).
    fn publish(&self, ev: LiveEvent) {
        self.log.lock().unwrap().push(ev.clone());
        let _ = self.live.send(Arc::new(ev));
    }

    /// Announce only (an event the log already holds, announced late).
    fn announce(&self, ev: LiveEvent) {
        let _ = self.live.send(Arc::new(ev));
    }
}

fn seq_of(cursor: &Cursor) -> Option<u64> {
    cursor.0.rsplit_once(':')?.1.parse().ok()
}

#[async_trait::async_trait]
impl Dispatcher for LogDispatcher {
    async fn dispatch(
        &self,
        _session: &SessionInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({ "kind": request.kind() }))
    }

    async fn subscribe(
        &self,
        _session: &SessionInfo,
        _filter: EventFilter,
        from: Option<Cursor>,
    ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
        let tag = format!("r{}", self.readers.fetch_add(1, Ordering::SeqCst));
        // 1. Live receiver first.
        let live = self.live.subscribe();
        // A concurrent commit lands between the receiver and the boundary read: it
        // is in the receiver *and* in what the boundary read sees.
        let raced: Vec<LiveEvent> = self.race.lock().unwrap().drain(..).collect();
        for ev in raced {
            self.publish(ev);
        }
        // 2. One consistent read: head plus backlog-or-snapshot.
        let log = self.log.lock().unwrap().clone();
        let boundary_seq = log.last().map_or(0, |e| e.seq);
        let cursor_for: Arc<dyn Fn(u64) -> Cursor + Send + Sync> =
            Arc::new(move |seq| Cursor(format!("{tag}:{seq}")));
        let cursor = cursor_for(boundary_seq);
        let (snapshot, backlog) = match from.as_ref().and_then(seq_of) {
            None => (
                Some(Snapshot {
                    data: serde_json::json!({
                        "through": boundary_seq,
                        "pad": "x".repeat(self.snapshot_pad),
                    }),
                    cursor: cursor.clone(),
                    taken_at: heimdall_contract::Timestamp::UNIX_EPOCH,
                }),
                Vec::new(),
            ),
            Some(after) => (
                None,
                log.iter()
                    .filter(|e| e.seq > after)
                    .map(|e| {
                        let mut ev = e.event.clone();
                        ev.cursor = cursor_for(e.seq);
                        ev
                    })
                    .collect(),
            ),
        };
        Ok(SubscriptionStart {
            cursor,
            boundary_seq,
            snapshot,
            backlog,
            live,
            cursor_for,
        })
    }
}

fn live_event(n: u64) -> LiveEvent {
    LiveEvent {
        seq: n,
        event: neutral(n, EventType::OperationStateChanged, None),
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    paths: EndpointPaths,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let paths = EndpointPaths::for_runtime(&tmp.path().join("rt"), "unused");
    Fixture { _tmp: tmp, paths }
}

fn principal_for(peer: &PeerIdentity) -> PrincipalInfo {
    verify_peer(peer, &ExpectedOwner::Uid(current_uid())).unwrap()
}

/// Accept one connection on `listener` and serve it to completion.
async fn serve_one<D: Dispatcher>(
    listener: &Listener,
    dispatcher: D,
    limits: ConnectionLimits,
    shutdown: CancellationToken,
) -> Result<(), FrameError> {
    let (stream, peer) = listener.accept().await?;
    let principal = principal_for(&peer);
    ControlConnection::new(stream, limits)
        .with_server_identity(env_id(), server_info())
        .serve(principal, dispatcher, shutdown)
        .await
}

fn client_hello(schema: &str, name: &str) -> ClientHello {
    ClientHello {
        protocol: PROTOCOL_VERSION,
        schema_version: SchemaVersion(schema.into()),
        client: PeerInfo {
            name: name.into(),
            version: "0".into(),
        },
        capabilities: server_capabilities(),
        required: BTreeSet::new(),
        interaction: InteractionMode::NonInteractive,
    }
}

fn hello_frame(schema: &str, name: &str) -> Vec<u8> {
    encode_frame(
        &ClientMessage::Hello(client_hello(schema, name)),
        MAX_HELLO_FRAME_BYTES,
    )
    .unwrap()
}

fn frame_of(msg: &ClientMessage) -> Vec<u8> {
    encode_frame(msg, MAX_CONTROL_FRAME_BYTES).unwrap()
}

/// Read from `stream` until `n` more server frames are decoded (`buf` keeps
/// partial bytes between calls); the raw bytes are scanned for canaries.
async fn read_n(stream: &mut UnixStream, buf: &mut Vec<u8>, n: usize) -> Vec<ServerMessage> {
    let mut got = Vec::new();
    loop {
        while got.len() < n {
            match decode_frame::<ServerMessage>(buf, MAX_CONTROL_FRAME_BYTES).unwrap() {
                Some((m, used)) => {
                    got.push(m);
                    buf.drain(..used);
                }
                None => break,
            }
        }
        if got.len() == n {
            return got;
        }
        let mut chunk = [0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("server frame did not arrive")
            .unwrap();
        assert!(read > 0, "server closed early");
        assert_no_canary(&String::from_utf8_lossy(&chunk[..read]));
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Read every server frame until EOF; also asserts no canary in the raw bytes.
async fn read_all_frames(stream: &mut UnixStream) -> Vec<ServerMessage> {
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    assert_no_canary(&String::from_utf8_lossy(&buf));
    let mut out = Vec::new();
    let mut rest = buf.as_slice();
    while let Some((m, used)) =
        decode_frame::<ServerMessage>(rest, MAX_CONTROL_FRAME_BYTES).unwrap()
    {
        out.push(m);
        rest = &rest[used..];
    }
    out
}

fn reject_code(m: &ServerMessage) -> Option<Code> {
    match m {
        ServerMessage::Reject(env) => Some(env.code.clone()),
        _ => None,
    }
}

// ---- directory, socket and stale-socket rules --------------------------------

#[tokio::test]
async fn bind_creates_0700_dir_and_0600_socket_owned_by_us() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let dir = std::fs::symlink_metadata(f.paths.control.parent().unwrap()).unwrap();
    assert!(dir.is_dir());
    assert_eq!(dir.mode() & 0o777, 0o700);
    assert_eq!(dir.uid(), current_uid());
    let sock = std::fs::symlink_metadata(&f.paths.control).unwrap();
    assert!(sock.file_type().is_socket());
    assert_eq!(sock.mode() & 0o777, 0o600);
    assert_eq!(sock.uid(), current_uid());
    assert_eq!(l.kind(), EndpointKind::Control);
    assert_eq!(l.path(), f.paths.control.as_path());

    // current_uid agrees with the owner of a file this process creates.
    let probe = f.paths.control.parent().unwrap().join("probe");
    std::fs::write(&probe, b"x").unwrap();
    assert_eq!(std::fs::metadata(&probe).unwrap().uid(), current_uid());
    std::fs::remove_file(probe).unwrap();
}

#[tokio::test]
async fn bind_refuses_a_permissive_or_symlinked_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let open_dir = tmp.path().join("open");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = Listener::bind(&open_dir.join("control.sock"), EndpointKind::Control).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!open_dir.join("control.sock").exists());
    // Never silently "fixed".
    assert_eq!(std::fs::metadata(&open_dir).unwrap().mode() & 0o777, 0o755);

    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = Listener::bind(&link.join("control.sock"), EndpointKind::Control).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!real.join("control.sock").exists());
}

#[tokio::test]
async fn client_refuses_a_permissive_directory_or_socket() {
    let f = fixture();
    let _l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let dir = f.paths.control.parent().unwrap().to_path_buf();

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::Insecure)
    ));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(connect(&f.paths.control).await.is_ok());

    std::fs::set_permissions(&f.paths.control, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::Insecure)
    ));
}

#[tokio::test]
async fn client_reports_not_running() {
    let f = fixture();
    // No directory at all.
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::NotRunning)
    ));
    // Directory, no socket.
    let l = Listener::bind(&f.paths.signing, EndpointKind::Signing).unwrap();
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::NotRunning)
    ));
    drop(l);
    // A dead socket of ours.
    let std_l = std::os::unix::net::UnixListener::bind(&f.paths.control).unwrap();
    std::fs::set_permissions(&f.paths.control, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(std_l);
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::NotRunning)
    ));
}

#[tokio::test]
async fn dead_socket_of_ours_is_replaced() {
    let f = fixture();
    // Create the private dir, then leave a dead socket (std does not unlink).
    drop(Listener::bind(&f.paths.signing, EndpointKind::Signing).unwrap());
    let std_l = std::os::unix::net::UnixListener::bind(&f.paths.control).unwrap();
    drop(std_l);
    assert!(f.paths.control.exists());
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let (accepted, client) = tokio::join!(l.accept(), connect(&f.paths.control));
    accepted.unwrap();
    client.unwrap();
}

#[tokio::test]
async fn live_socket_is_not_replaced() {
    let f = fixture();
    let first = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let err = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    let (accepted, client) = tokio::join!(first.accept(), connect(&f.paths.control));
    accepted.unwrap();
    client.unwrap();
}

#[tokio::test]
async fn non_socket_file_at_the_endpoint_is_left_alone() {
    let f = fixture();
    drop(Listener::bind(&f.paths.signing, EndpointKind::Signing).unwrap());
    std::fs::write(&f.paths.control, b"not a socket").unwrap();
    let before = std::fs::metadata(&f.paths.control).unwrap();
    let err = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    let after = std::fs::metadata(&f.paths.control).unwrap();
    assert_eq!(std::fs::read(&f.paths.control).unwrap(), b"not a socket");
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    assert_eq!(before.ino(), after.ino());
    assert!(matches!(
        connect(&f.paths.control).await,
        Err(ConnectError::Insecure)
    ));
}

#[test]
fn foreign_owned_socket_is_never_probed_or_unlinked() {
    // Injected stat: a real foreign-owned socket needs root to create (blocked).
    let me = 501;
    let foreign = PathFacts {
        kind: FileKind::Socket,
        uid: me + 1,
        mode: 0o600,
    };
    assert_eq!(
        classify_existing(Some(foreign), me, || panic!("must not probe")),
        Existing::ForeignOwner
    );
    let ours = PathFacts { uid: me, ..foreign };
    let refused = || Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    assert_eq!(
        classify_existing(Some(ours), me, refused),
        Existing::DeadOurs
    );
    assert_eq!(
        classify_existing(Some(ours), me, || Ok(())),
        Existing::LiveOurs
    );
    let denied = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(
        classify_existing(Some(ours), me, denied),
        Existing::LiveOurs
    );
    for kind in [FileKind::Dir, FileKind::Symlink, FileKind::Other] {
        assert_eq!(
            classify_existing(Some(PathFacts { kind, ..ours }), me, || panic!("no probe")),
            Existing::NotASocket
        );
    }
    assert_eq!(
        classify_existing(None, me, || panic!("no probe")),
        Existing::Absent
    );

    // Directory and client-side socket rules with injected owners and modes.
    let dir = PathFacts {
        kind: FileKind::Dir,
        uid: me,
        mode: 0o700,
    };
    assert_eq!(check_private_dir(&dir, me), Ok(()));
    assert_eq!(
        check_private_dir(&PathFacts { uid: 0, ..dir }, me),
        Err(DirProblem::WrongOwner)
    );
    assert_eq!(
        check_private_dir(&PathFacts { mode: 0o701, ..dir }, me),
        Err(DirProblem::TooPermissive)
    );
    assert_eq!(
        check_private_dir(
            &PathFacts {
                kind: FileKind::Symlink,
                ..dir
            },
            me
        ),
        Err(DirProblem::NotADirectory)
    );
    assert!(check_own_socket(&ours, me).is_ok());
    assert!(matches!(
        check_own_socket(&foreign, me),
        Err(ConnectError::Insecure)
    ));
}

#[tokio::test]
async fn dropping_a_listener_unlinks_only_its_own_socket() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    drop(l);
    assert!(!f.paths.control.exists());

    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    std::fs::remove_file(&f.paths.control).unwrap();
    let other = std::os::unix::net::UnixListener::bind(&f.paths.control).unwrap();
    drop(l);
    assert!(
        f.paths.control.exists(),
        "a socket we did not bind was removed"
    );
    drop(other);
}

// ---- peer credentials ---------------------------------------------------------

#[tokio::test]
async fn same_user_peer_is_accepted_and_reported() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = TestDispatcher::new();
    let shutdown = CancellationToken::new();
    let server = serve_one(&l, d, ConnectionLimits::default(), shutdown.clone());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        assert_eq!(
            c.server().principal,
            PrincipalInfo::OsUserUnix { uid: current_uid() }
        );
        assert_eq!(c.server().environment_id, env_id());
        assert_eq!(c.server().capabilities, server_capabilities());
        let env = c.request(inspect()).await.unwrap();
        assert_eq!(env.code, Code::Ok);
        assert_eq!(env.data["kind"], "inspect");
        assert_eq!(env.data["principal"]["uid"], current_uid());
        let text = serde_json::to_string(&env).unwrap();
        assert_no_canary(&text);
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[test]
fn forged_peer_with_another_uid_is_rejected() {
    // A real second account is required for the live cross-user case (blocked).
    let me = current_uid();
    let other = me.wrapping_add(1);
    let forged = PeerIdentity::Unix {
        uid: other,
        gid: 0,
        pid: Some(1),
    };
    assert_eq!(
        verify_peer(&forged, &ExpectedOwner::Uid(me)),
        Err(PeerRejected::DifferentUser)
    );
    let root = PeerIdentity::Unix {
        uid: 0,
        gid: 0,
        pid: None,
    };
    if me != 0 {
        assert!(verify_peer(&root, &ExpectedOwner::Uid(me)).is_err());
    }
}

#[tokio::test]
async fn signing_endpoint_over_a_real_socket_is_distinct_and_peer_checked() {
    let f = fixture();
    let sign = Listener::bind(&f.paths.signing, EndpointKind::Signing).unwrap();
    let _ctrl = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    assert_ne!(f.paths.signing, f.paths.control);
    let server = async {
        let (stream, peer) = sign.accept().await.unwrap();
        principal_for(&peer);
        heimdall_ipc::signing::serve(
            stream,
            Arc::new(heimdall_ipc::signing::NoIdentities),
            CancellationToken::new(),
        )
        .await
    };
    let client = async {
        let mut s = connect(&f.paths.signing).await.unwrap();
        s.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
        // A control hello on the signing socket: failure, never JSON-parsed.
        s.write_all(&hello_frame("1", &canary())).await.unwrap();
        s.shutdown().await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_no_canary(&String::from_utf8_lossy(&out));
        out
    };
    let (r, out) = tokio::join!(server, client);
    r.unwrap();
    assert_eq!(
        out,
        [
            heimdall_ipc::signing::empty_identities_frame().as_slice(),
            heimdall_ipc::signing::failure_frame().as_slice()
        ]
        .concat()
    );
}

// ---- hello phase ----------------------------------------------------------------

/// Run a raw client script against a served connection; returns the server's
/// result and every frame the server sent.
async fn raw_session(
    limits: ConnectionLimits,
    script: impl AsyncFnOnce(&mut UnixStream),
) -> (Result<(), FrameError>, Vec<ServerMessage>, Duration) {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let start = Instant::now();
    let server = serve_one(&l, TestDispatcher::new(), limits, CancellationToken::new());
    let client = async {
        let mut s = connect(&f.paths.control).await.unwrap();
        script(&mut s).await;
        read_all_frames(&mut s).await
    };
    let (r, frames) = tokio::join!(server, client);
    if let Err(e) = &r {
        assert_no_canary(&format!("{e} {e:?}"));
    }
    (r, frames, start.elapsed())
}

#[tokio::test]
async fn hello_timeout_closes_a_silent_connection() {
    let limits = ConnectionLimits {
        hello_timeout_ms: 150,
        ..ConnectionLimits::default()
    };
    let (r, frames, elapsed) = raw_session(limits, async |_s| {}).await;
    match r {
        Err(FrameError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
        other => panic!("{other:?}"),
    }
    assert!(frames.is_empty());
    assert!(
        elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(4),
        "{elapsed:?}"
    );
    assert_eq!(
        ConnectionLimits::default().hello_timeout_ms,
        heimdall_contract::ipc::HELLO_TIMEOUT_MS
    );
}

#[tokio::test]
async fn oversize_length_prefix_closes_before_allocation() {
    let (r, frames, elapsed) = raw_session(ConnectionLimits::default(), async |s| {
        // Header only: if the server tried to buffer 4 GiB it would wait for it.
        s.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).await.unwrap();
    })
    .await;
    match r {
        Err(FrameError::TooLarge { len, limit }) => {
            assert_eq!(len, u32::MAX as usize);
            assert_eq!(limit, MAX_HELLO_FRAME_BYTES);
        }
        other => panic!("{other:?}"),
    }
    assert!(elapsed < Duration::from_secs(4));
    assert_eq!(frames.len(), 1);
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));

    // A hello-sized limit applies to the first frame even below the control limit.
    let (r, _, _) = raw_session(ConnectionLimits::default(), async |s| {
        let len = (MAX_HELLO_FRAME_BYTES + 1) as u32;
        s.write_all(&len.to_be_bytes()).await.unwrap();
    })
    .await;
    assert!(matches!(r, Err(FrameError::TooLarge { .. })));
}

#[tokio::test]
async fn oversize_frame_after_hello_closes_with_goodbye() {
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&hello_frame("1", "t")).await.unwrap();
        s.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).await.unwrap();
    })
    .await;
    match r {
        Err(FrameError::TooLarge { len, limit }) => {
            assert_eq!(len, u32::MAX as usize);
            assert_eq!(limit, MAX_CONTROL_FRAME_BYTES);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(frames[0], ServerMessage::Hello(_)));
    assert!(matches!(
        frames[1],
        ServerMessage::Goodbye {
            code: Code::UsageError,
            ..
        }
    ));
}

#[tokio::test]
async fn truncated_frame_is_reported_and_closed() {
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&[0, 0, 0, 100]).await.unwrap();
        s.write_all(&[b'{'; 10]).await.unwrap();
        s.shutdown().await.unwrap();
    })
    .await;
    assert!(matches!(r, Err(FrameError::Truncated)), "{r:?}");
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));
}

#[tokio::test]
async fn invalid_utf8_and_malformed_hello_are_rejected_without_echo() {
    let c = canary();
    // Invalid UTF-8 inside a JSON string, next to a canary.
    let mut body = format!("{{\"type\":\"hello\",\"x\":\"{c}").into_bytes();
    body.extend_from_slice(&[0xFF, 0xFE, b'"', b'}']);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&frame).await.unwrap();
    })
    .await;
    assert!(matches!(r, Err(FrameError::Json(_))), "{r:?}");
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));

    // Wrong shape whose serde error would quote the canary.
    let body = format!("{{\"type\":\"{c}\"}}");
    let frame = [
        (body.len() as u32).to_be_bytes().as_slice(),
        body.as_bytes(),
    ]
    .concat();
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&frame).await.unwrap();
    })
    .await;
    let e = r.unwrap_err();
    assert_no_canary(&format!("{e} {e:?}"));
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));
}

#[tokio::test]
async fn wrong_first_message_is_rejected() {
    let req = encode_frame(
        &ClientMessage::Request {
            seq: 1,
            request: inspect(),
        },
        MAX_CONTROL_FRAME_BYTES,
    )
    .unwrap();
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&req).await.unwrap();
    })
    .await;
    assert!(r.is_err());
    assert_eq!(frames.len(), 1);
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));

    // SSH-agent bytes sent to the control endpoint (control/signing confusion).
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
    })
    .await;
    assert!(matches!(r, Err(FrameError::Json(_))));
    assert_eq!(reject_code(&frames[0]), Some(Code::UsageError));
}

#[tokio::test]
async fn schema_or_capability_mismatch_is_rejected_explicitly() {
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&hello_frame("2", "t")).await.unwrap();
    })
    .await;
    r.unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(reject_code(&frames[0]), Some(Code::SchemaUnsupported));

    // Review F10: an inconsistent hello that requires `events/1` while omitting it
    // from its own capabilities is rejected, although the server offers it.
    let mut inconsistent = client_hello("1", "t");
    inconsistent.capabilities.remove(capability::EVENTS_V1);
    inconsistent
        .required
        .insert(capability::EVENTS_V1.to_owned());
    assert!(server_capabilities().contains(capability::EVENTS_V1));
    let frame = encode_frame(&ClientMessage::Hello(inconsistent), MAX_HELLO_FRAME_BYTES).unwrap();
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&frame).await.unwrap();
    })
    .await;
    r.unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(reject_code(&frames[0]), Some(Code::SchemaUnsupported));

    // Through the client: a required capability the server lacks.
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let server = serve_one(
        &l,
        TestDispatcher::new(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let required: BTreeSet<String> = ["future/9".to_owned()].into_iter().collect();
        let err =
            ControlClient::handshake(s, client_info(), required, InteractionMode::NonInteractive)
                .await
                .unwrap_err();
        match server_refusal(&err) {
            Some(ServerRefusal::Rejected(env)) => {
                assert_eq!(env.code, Code::SchemaUnsupported);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            transport_failure_envelope(&err, false).code,
            Code::SchemaUnsupported
        );
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn hello_never_echoes_client_metadata() {
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&hello_frame("1", &canary())).await.unwrap();
        s.shutdown().await.unwrap();
    })
    .await;
    r.unwrap();
    // read_all_frames already scanned the raw bytes for the canary.
    assert!(matches!(frames[0], ServerMessage::Hello(_)));
}

#[tokio::test]
async fn repeated_hello_ends_the_session() {
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&hello_frame("1", "t")).await.unwrap();
        s.write_all(&hello_frame("1", "t")).await.unwrap();
    })
    .await;
    assert!(r.is_err());
    assert!(matches!(
        frames[1],
        ServerMessage::Goodbye {
            code: Code::UsageError,
            ..
        }
    ));
}

#[tokio::test]
async fn serve_without_server_identity_says_goodbye() {
    let (a, b) = tokio::io::duplex(4096);
    let conn = ControlConnection::new(a, ConnectionLimits::default());
    let server = conn.serve(
        PrincipalInfo::OsUserUnix { uid: 1 },
        TestDispatcher::new(),
        CancellationToken::new(),
    );
    let client = async {
        let mut b = b;
        let mut buf = Vec::new();
        b.read_to_end(&mut buf).await.unwrap();
        buf
    };
    let (r, buf) = tokio::join!(server, client);
    assert!(r.is_err());
    let (m, _): (ServerMessage, usize) = decode_frame(&buf, MAX_CONTROL_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert!(matches!(
        m,
        ServerMessage::Goodbye {
            code: Code::InternalError,
            ..
        }
    ));
}

// ---- per-connection limits ------------------------------------------------------

#[tokio::test]
async fn seventeenth_inflight_request_gets_backpressure() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let d = TestDispatcher::gated(gate.clone());
    let shutdown = CancellationToken::new();
    let server = serve_one(&l, d.clone(), ConnectionLimits::default(), shutdown.clone());
    let client = async {
        let mut s = connect(&f.paths.control).await.unwrap();
        s.write_all(&hello_frame("1", "t")).await.unwrap();
        let mut frames = Vec::new();
        for seq in 1..=17u64 {
            frames.extend(
                encode_frame(
                    &ClientMessage::Request {
                        seq,
                        request: cancel(seq as u8),
                    },
                    MAX_CONTROL_FRAME_BYTES,
                )
                .unwrap(),
            );
        }
        s.write_all(&frames).await.unwrap();
        // Read the hello and the backpressure answer before releasing the gate.
        let mut buf = Vec::new();
        let mut got: Vec<ServerMessage> = Vec::new();
        while got.len() < 2 {
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
            while let Some((m, used)) =
                decode_frame::<ServerMessage>(&buf, MAX_CONTROL_FRAME_BYTES).unwrap()
            {
                got.push(m);
                buf.drain(..used);
            }
        }
        assert!(matches!(got[0], ServerMessage::Hello(_)));
        match &got[1] {
            ServerMessage::Response {
                in_reply_to,
                envelope,
            } => {
                assert_eq!(*in_reply_to, 17);
                assert_eq!(envelope.code, Code::Backpressure);
                let detail: heimdall_contract::ErrorData =
                    serde_json::from_value(envelope.data.clone()).unwrap();
                assert!(detail.error.retryable);
                assert_eq!(detail.error.effect_status, EffectStatus::None);
                assert!(detail.error.next.retry_after_ms.is_some());
            }
            other => panic!("{other:?}"),
        }
        // The 17th was never dispatched.
        assert_eq!(d.journal.lock().unwrap().len(), 16);
        gate.add_permits(16);
        let mut done = BTreeSet::new();
        while done.len() < 16 {
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&chunk[..n]);
            while let Some((m, used)) =
                decode_frame::<ServerMessage>(&buf, MAX_CONTROL_FRAME_BYTES).unwrap()
            {
                buf.drain(..used);
                if let ServerMessage::Response {
                    in_reply_to,
                    envelope,
                } = m
                {
                    assert_eq!(envelope.code, Code::Ok);
                    done.insert(in_reply_to);
                }
            }
        }
        assert_eq!(done, (1..=16).collect());
        shutdown.cancel();
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn fifth_subscription_gets_backpressure_and_events_flow() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = TestDispatcher::new();
    let events = d.events.clone();
    let server = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let op = OperationId::from_random_bytes([3; 16]);
        let mut subs = Vec::new();
        for i in 0..4 {
            let filter = if i == 0 {
                EventFilter {
                    operation_id: Some(op.clone()),
                    types: vec![],
                }
            } else {
                EventFilter::default()
            };
            match c.subscribe(filter, None).await.unwrap() {
                SubscribeOutcome::Subscribed {
                    subscription,
                    cursor,
                    snapshot,
                } => {
                    assert_eq!(cursor, Cursor("c0".into()));
                    assert_eq!(snapshot, None);
                    subs.push(subscription);
                }
                other => panic!("{other:?}"),
            }
        }
        match c.subscribe(EventFilter::default(), None).await.unwrap() {
            SubscribeOutcome::Refused(env) => assert_eq!(env.code, Code::Backpressure),
            other => panic!("{other:?}"),
        }
        // Oversize cursor is refused before the dispatcher sees it.
        let long = Cursor("x".repeat(heimdall_contract::event::MAX_CURSOR_LEN + 1));
        assert_eq!(c.unsubscribe(subs[3]).await.unwrap().code, Code::Ok);
        match c
            .subscribe(EventFilter::default(), Some(long))
            .await
            .unwrap()
        {
            SubscribeOutcome::Refused(env) => assert_eq!(env.code, Code::UsageError),
            other => panic!("{other:?}"),
        }
        assert_eq!(c.unsubscribe(999).await.unwrap().code, Code::NotFound);

        // One unrelated event and one for `op`: sub 0 (filtered) sees only `op`.
        events
            .send(event(1, EventType::GrantStateChanged, None))
            .unwrap();
        events
            .send(event(2, EventType::OperationStateChanged, Some(op.clone())))
            .unwrap();
        let mut seen: Vec<(u64, String)> = Vec::new();
        // subs[1], subs[2] get both; subs[0] gets one; subs[3] is gone: 5 events.
        while seen.len() < 5 {
            let (sub, ev) = c.next_event().await.unwrap();
            seen.push((sub, ev.cursor.0.clone()));
        }
        assert!(seen.contains(&(subs[0], "c2".into())));
        assert!(!seen.contains(&(subs[0], "c1".into())));
        assert!(!seen.iter().any(|(s, _)| *s == subs[3]));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn lagging_subscriber_gets_one_resync_and_the_backlog_is_dropped() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = TestDispatcher::new();
    let events = d.events.clone();
    let server = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let SubscribeOutcome::Subscribed { subscription, .. } =
            c.subscribe(EventFilter::default(), None).await.unwrap()
        else {
            panic!("refused")
        };
        events
            .send(event(1, EventType::GrantStateChanged, None))
            .unwrap();
        let (_, first) = c.next_event().await.unwrap();
        assert_eq!(first.cursor, Cursor("c1".into()));
        // 300 events with no yield: the 256-slot buffer overflows.
        for n in 2..=301 {
            events
                .send(event(n, EventType::GrantStateChanged, None))
                .unwrap();
        }
        let (sub, resync) = c.next_event().await.unwrap();
        assert_eq!(sub, subscription);
        assert_eq!(resync.event_type, EventType::ResyncRequired);
        // Boundary: the last event delivered before the gap.
        assert_eq!(resync.cursor, Cursor("c1".into()));
        assert!(resync.payload["dropped"].as_u64().unwrap() >= 300 - 256);
        assert_eq!(resync.environment_id, env_id());
        // Live delivery resumes after the resync; nothing from the backlog.
        events
            .send(event(302, EventType::GrantStateChanged, None))
            .unwrap();
        let (_, next) = c.next_event().await.unwrap();
        assert_eq!(next.cursor, Cursor("c302".into()));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

// ---- fault points -----------------------------------------------------------------

#[tokio::test]
async fn server_dropped_mid_response_surfaces_service_unavailable() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let journal: Arc<Mutex<Vec<String>>> = Arc::default();

    // A server that journals the request, writes half a response frame and dies.
    let half_server = async {
        let (mut s, _peer) = l.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut frames: Vec<ClientMessage> = Vec::new();
        while frames.len() < 2 {
            let mut chunk = [0u8; 4096];
            let n = s.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..n]);
            while let Some((m, used)) =
                decode_frame::<ClientMessage>(&buf, MAX_CONTROL_FRAME_BYTES).unwrap()
            {
                frames.push(m);
                buf.drain(..used);
                if frames.len() == 1 {
                    let hello = heimdall_ipc::session::negotiate(
                        match &frames[0] {
                            ClientMessage::Hello(h) => h,
                            _ => panic!(),
                        },
                        PrincipalInfo::OsUserUnix { uid: current_uid() },
                        env_id(),
                        server_info(),
                    )
                    .unwrap();
                    s.write_all(
                        &encode_frame(&ServerMessage::Hello(hello), MAX_HELLO_FRAME_BYTES).unwrap(),
                    )
                    .await
                    .unwrap();
                }
            }
        }
        if let ClientMessage::Request {
            request: Request::Cancel(c),
            seq,
        } = &frames[1]
        {
            journal
                .lock()
                .unwrap()
                .push(c.operation_id.as_str().to_owned());
            let full = encode_frame(
                &ServerMessage::Response {
                    in_reply_to: *seq,
                    envelope: Envelope::ok(serde_json::json!({ "done": true })),
                },
                MAX_CONTROL_FRAME_BYTES,
            )
            .unwrap();
            s.write_all(&full[..full.len() / 2]).await.unwrap();
        }
        drop(s);
    };
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let err = c.request(cancel(42)).await.unwrap_err();
        assert!(matches!(err, FrameError::Truncated), "{err:?}");
        let env = transport_failure_envelope(&err, true);
        assert_eq!(env.code, Code::ServiceUnavailable);
        assert_eq!(env.data.error.effect_status, EffectStatus::Unknown);
        assert!(env.data.error.retryable);
        assert_eq!(env.data.error.next.action, "retry_after");
    };
    tokio::join!(half_server, client);

    // The journal is the truth: a second connection (real server) sees the entry.
    let d = TestDispatcher {
        journal: journal.clone(),
        ..TestDispatcher::new()
    };
    let server = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let env = c.request(inspect()).await.unwrap();
        let expected = OperationId::from_random_bytes([42; 16]);
        assert_eq!(env.data["journal"], serde_json::json!([expected.as_str()]));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn server_task_dropped_while_dispatching_surfaces_service_unavailable() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let d = TestDispatcher::gated(gate);
    let journal = d.journal.clone();
    let stop_server = CancellationToken::new();
    let server = async {
        tokio::select! {
            r = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new()) => r,
            // Simulated crash: drop the whole serve future (no goodbye).
            () = stop_server.cancelled() => Ok(()),
        }
    };
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let req = c.request(cancel(9));
        let watcher = async {
            while journal.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
            stop_server.cancel();
        };
        let (res, ()) = tokio::join!(req, watcher);
        let err = res.unwrap_err();
        assert_eq!(
            transport_failure_envelope(&err, true).code,
            Code::ServiceUnavailable
        );
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
    assert_eq!(journal.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn shutdown_sends_goodbye_service_unavailable() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let shutdown = CancellationToken::new();
    let server = serve_one(
        &l,
        TestDispatcher::new(),
        ConnectionLimits::default(),
        shutdown.clone(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        shutdown.cancel();
        let err = c.next_event().await.unwrap_err();
        match server_refusal(&err) {
            Some(ServerRefusal::Goodbye { code, .. }) => {
                assert_eq!(*code, Code::ServiceUnavailable);
            }
            other => panic!("{other:?}"),
        }
        let env = transport_failure_envelope(&err, false);
        assert_eq!(env.code, Code::ServiceUnavailable);
        assert_eq!(env.data.error.effect_status, EffectStatus::None);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

// ---- attended sessions (ADR-0006 §2.3, §3.1; review F03) -------------------------

fn decide() -> Request {
    Request::Decide(DecideRequest {
        decision_id: DecisionId::from_random_bytes([5; 16]),
        verdict: Verdict::Approve,
    })
}

fn policy(action: fn(PolicyId) -> PolicyAction) -> Request {
    Request::Policy(action(PolicyId::parse("fixture-policy").unwrap()))
}

/// Requests the session refuses before dispatch on an unattended session
/// (ADR-0006 §2.3; design-fix second round R5). Widening policy actions are
/// deliberately not here: they are dispatched and the application answers with a
/// `WidenPolicy` decision record.
fn attended_only_requests() -> Vec<Request> {
    vec![
        decide(),
        Request::ConfirmTime(ConfirmTimeRequest {
            observed_wall: heimdall_contract::Timestamp::UNIX_EPOCH,
        }),
    ]
}

fn assert_interaction_required(env: &Envelope<serde_json::Value>) {
    assert_eq!(env.code, Code::InteractionRequired);
    let detail: ErrorData = serde_json::from_value(env.data.clone()).unwrap();
    assert_eq!(detail.error.effect_status, EffectStatus::None);
    assert_eq!(detail.error.next.action, "interact");
}

#[tokio::test]
async fn non_interactive_session_can_never_be_attended() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = TestDispatcher::new();
    let seen = d.seen.clone();
    let server = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        for req in attended_only_requests() {
            assert!(req.requires_attended_session());
            assert_interaction_required(&c.request(req).await.unwrap());
        }
        assert_interaction_required(&c.attend().await.unwrap());
        // Still refused after the failed Attend, and never dispatched.
        assert_interaction_required(&c.request(decide()).await.unwrap());
        assert!(
            seen.lock().unwrap().is_empty(),
            "refused request was dispatched"
        );
        // Ordinary requests are dispatched with an unattended session.
        let env = c.request(inspect()).await.unwrap();
        assert_eq!(env.code, Code::Ok);
        assert_eq!(env.data["attended"], false);
        assert_eq!(env.data["interaction"], "non_interactive");
        let pause = c
            .request(policy(|policy_id| PolicyAction::Pause { policy_id }))
            .await
            .unwrap();
        assert_eq!(pause.code, Code::Ok, "narrowing actions need no attendance");
        // Widening actions are dispatched even when unattended (R5): the session
        // must not refuse them itself; the application answers with a
        // `WidenPolicy` decision record and `INTERACTION_REQUIRED` (N04).
        let widening = policy(|policy_id| PolicyAction::Resume { policy_id });
        assert!(widening.is_widening_policy_action());
        assert!(!widening.requires_attended_session());
        let env = c.request(widening).await.unwrap();
        assert_decision_required(&env, Code::InteractionRequired);
        assert_interaction_required(&env);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "inspect, pause and resume were dispatched");
        assert!(seen.iter().all(|(_, s)| !s.attended));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn interactive_session_is_attended_only_after_attend() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = TestDispatcher::new();
    let seen = d.seen.clone();
    let server = serve_one(&l, d, ConnectionLimits::default(), CancellationToken::new());
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::Interactive,
        )
        .await
        .unwrap();
        // Declared interactive but not yet attended: refused, not dispatched.
        for req in attended_only_requests() {
            assert_interaction_required(&c.request(req).await.unwrap());
        }
        assert!(seen.lock().unwrap().is_empty());
        let before = c.request(inspect()).await.unwrap();
        assert_eq!(before.data["attended"], false);
        assert_eq!(before.data["interaction"], "interactive");

        let attend = c.attend().await.unwrap();
        assert_eq!(attend.code, Code::Ok);
        assert_eq!(attend.data, serde_json::json!({ "attended": true }));
        // Idempotent.
        assert_eq!(c.attend().await.unwrap().code, Code::Ok);

        // Attended: the widening policy actions (dispatched either way, R5) are
        // still never executed on dispatch; the application answers each with a
        // decision record and `APPROVAL_REQUIRED` (N04: attendance is not the
        // confirmation). Only `decide` on this attended session completes it.
        for req in [
            policy(|policy_id| PolicyAction::Resume { policy_id }),
            policy(|policy_id| PolicyAction::ClearCutoff { policy_id }),
        ] {
            let env = c.request(req).await.unwrap();
            assert_decision_required(&env, Code::ApprovalRequired);
        }
        // decide and confirm_time pass the session gate on the attended session.
        for req in attended_only_requests() {
            let kind = req.kind();
            let env = c.request(req).await.unwrap();
            assert_eq!(env.code, Code::Ok, "{kind}");
            assert_eq!(env.data["attended"], true, "{kind}");
        }
        let seen = seen.lock().unwrap().clone();
        let kinds: Vec<&str> = seen.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            ["inspect", "policy", "policy", "decide", "confirm_time"]
        );
        assert!(!seen[0].1.attended);
        assert!(seen[1..].iter().all(|(_, s)| s.attended
            && s.interaction == InteractionMode::Interactive
            && s.principal == PrincipalInfo::OsUserUnix { uid: current_uid() }));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

#[tokio::test]
async fn hello_without_interaction_defaults_to_non_interactive() {
    // A hello that omits `interaction` (an older or minimal client).
    let mut hello = serde_json::to_value(ClientMessage::Hello(client_hello("1", "t"))).unwrap();
    assert!(
        hello
            .as_object_mut()
            .unwrap()
            .remove("interaction")
            .is_some()
    );
    let mut input = encode_frame(&hello, MAX_HELLO_FRAME_BYTES).unwrap();
    input.extend(frame_of(&ClientMessage::Attend { seq: 1 }));
    input.extend(frame_of(&ClientMessage::Request {
        seq: 2,
        request: decide(),
    }));
    let (r, frames, _) = raw_session(ConnectionLimits::default(), async |s| {
        s.write_all(&input).await.unwrap();
        s.shutdown().await.unwrap();
    })
    .await;
    r.unwrap();
    assert!(matches!(frames[0], ServerMessage::Hello(_)));
    for (frame, seq) in frames[1..].iter().zip([1u64, 2]) {
        match frame {
            ServerMessage::Response {
                in_reply_to,
                envelope,
            } => {
                assert_eq!(*in_reply_to, seq);
                assert_interaction_required(envelope);
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(frames.len(), 3);
}

// ---- subscriptions: snapshot / backlog / live handoff (ADR-0006 §8; review F08) ---

fn subscribe_frame(seq: u64, from_cursor: Option<Cursor>) -> Vec<u8> {
    frame_of(&ClientMessage::Subscribe {
        seq,
        filter: EventFilter::default(),
        from_cursor,
    })
}

fn event_of(m: &ServerMessage) -> (u64, &Event) {
    match m {
        ServerMessage::Event {
            subscription,
            event,
        } => (*subscription, event),
        other => panic!("expected an event, got {other:?}"),
    }
}

/// Publish during replay-to-live: an event committed between the live
/// receiver's creation and the boundary read is in both the backlog and the
/// receiver; it is delivered exactly once. A late re-announce of an event at or
/// below the boundary is dropped too. Wire order (raw frames): `Subscribed`, then
/// the backlog in order, then live events after the boundary.
#[tokio::test]
async fn publish_during_replay_to_live_is_delivered_exactly_once_in_order() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher::new();
    d.publish(live_event(1));
    d.publish(live_event(2));
    d.race.lock().unwrap().push(live_event(3));
    let server = serve_one(
        &l,
        d.clone(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let mut s = connect(&f.paths.control).await.unwrap();
        let mut buf = Vec::new();
        s.write_all(&hello_frame("1", "t")).await.unwrap();
        // Resume after seq 1 (a cursor this fake accepts from any reader).
        s.write_all(&subscribe_frame(1, Some(Cursor("r-:1".into()))))
            .await
            .unwrap();
        let first = read_n(&mut s, &mut buf, 4).await;
        assert!(matches!(first[0], ServerMessage::Hello(_)));
        let subscription = match &first[1] {
            ServerMessage::Subscribed {
                in_reply_to,
                subscription,
                cursor,
                snapshot,
            } => {
                assert_eq!(*in_reply_to, 1);
                assert_eq!(
                    cursor,
                    &Cursor("r0:3".into()),
                    "boundary after the raced commit"
                );
                assert!(
                    snapshot.is_none(),
                    "a usable cursor gets the backlog, not a snapshot"
                );
                *subscription
            }
            other => panic!("{other:?}"),
        };
        let backlog: Vec<(u64, Event)> = first[2..]
            .iter()
            .map(|m| {
                let (sub, ev) = event_of(m);
                (sub, ev.clone())
            })
            .collect();
        assert_eq!(
            backlog
                .iter()
                .map(|(_, e)| e.payload["n"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(backlog.iter().all(|(sub, _)| *sub == subscription));
        assert_eq!(backlog[0].1.cursor, Cursor("r0:2".into()));
        assert_eq!(backlog[1].1.cursor, Cursor("r0:3".into()));

        // Late re-announce of seq 2 (at or below the boundary): dropped. Then live.
        d.announce(live_event(2));
        d.publish(live_event(4));
        d.publish(live_event(5));
        let live = read_n(&mut s, &mut buf, 2).await;
        let ids: Vec<(u64, Cursor)> = live
            .iter()
            .map(|m| {
                let (sub, ev) = event_of(m);
                assert_eq!(sub, subscription);
                (ev.payload["n"].as_u64().unwrap(), ev.cursor.clone())
            })
            .collect();
        assert_eq!(
            ids,
            [(4, Cursor("r0:4".into())), (5, Cursor("r0:5".into()))],
            "the raced seq 3 or the re-announced seq 2 was delivered twice"
        );
        // Every event ID seen exactly once.
        let mut all: Vec<EventId> = backlog.iter().map(|(_, e)| e.event_id.clone()).collect();
        all.extend(live.iter().map(|m| event_of(m).1.event_id.clone()));
        let unique: std::collections::HashSet<_> = all.iter().cloned().collect();
        assert_eq!(unique.len(), all.len());
        assert_eq!(all.len(), 4);
        // Dropping the stream here ends the session (peer closed between frames).
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

/// No cursor: the subscription starts from a snapshot whose cursor is the
/// boundary; the raced commit is reflected in the snapshot and not re-sent live.
#[tokio::test]
async fn no_cursor_starts_from_a_snapshot_at_the_boundary() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher::new();
    d.publish(live_event(1));
    d.race.lock().unwrap().push(live_event(2));
    let server = serve_one(
        &l,
        d.clone(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let SubscribeOutcome::Subscribed {
            subscription,
            cursor,
            snapshot,
        } = c.subscribe(EventFilter::default(), None).await.unwrap()
        else {
            panic!("refused")
        };
        let snapshot = snapshot.expect("snapshot");
        assert_eq!(snapshot.cursor, cursor);
        assert_eq!(cursor, Cursor("r0:2".into()));
        assert_eq!(snapshot.data["through"], 2);
        d.publish(live_event(3));
        let (sub, ev) = c.next_event().await.unwrap();
        assert_eq!(sub, subscription);
        assert_eq!(
            ev.payload["n"], 3,
            "the raced seq 2 was re-sent after the snapshot"
        );
        assert_eq!(ev.cursor, Cursor("r0:3".into()));
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

/// Two readers get the same event (same `event_id`) with their own cursors, each
/// built by that subscription's `cursor_for`, and each cursor resumes that reader.
#[tokio::test]
async fn two_readers_get_the_same_event_with_their_own_cursors() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher::new();
    let stop = CancellationToken::new();
    let server_a = serve_one(&l, d.clone(), ConnectionLimits::default(), stop.clone());
    let server_b = serve_one(&l, d.clone(), ConnectionLimits::default(), stop.clone());
    let client = async {
        let mut readers = Vec::new();
        for _ in 0..2 {
            let s = connect(&f.paths.control).await.unwrap();
            let mut c = ControlClient::handshake(
                s,
                client_info(),
                BTreeSet::new(),
                InteractionMode::NonInteractive,
            )
            .await
            .unwrap();
            let SubscribeOutcome::Subscribed { cursor, .. } =
                c.subscribe(EventFilter::default(), None).await.unwrap()
            else {
                panic!("refused")
            };
            readers.push((c, cursor));
        }
        assert_ne!(readers[0].1, readers[1].1, "reader cursors must differ");
        d.publish(live_event(7));
        let mut got = Vec::new();
        for (c, _) in &mut readers {
            let (_, ev) = c.next_event().await.unwrap();
            got.push(ev);
        }
        assert_eq!(got[0].event_id, got[1].event_id);
        assert_eq!(got[0].payload, got[1].payload);
        assert_ne!(got[0].cursor, got[1].cursor);
        let tags: Vec<&str> = got
            .iter()
            .map(|e| e.cursor.0.split_once(':').unwrap().0)
            .collect();
        assert_ne!(tags[0], tags[1]);
        assert!(got.iter().all(|e| seq_of(&e.cursor) == Some(7)));
        // Each reader's cursor is usable: resuming from it replays nothing new and
        // the next event continues after it.
        let (c, _) = &mut readers[0];
        let SubscribeOutcome::Subscribed {
            subscription,
            snapshot,
            ..
        } = c
            .subscribe(EventFilter::default(), Some(got[0].cursor.clone()))
            .await
            .unwrap()
        else {
            panic!("refused")
        };
        assert!(snapshot.is_none());
        d.publish(live_event(8));
        // The first subscription and the resumed one both get seq 8, nothing older.
        let mut subs_seen = BTreeSet::new();
        for _ in 0..2 {
            let (sub, ev) = c.next_event().await.unwrap();
            assert_eq!(ev.payload["n"], 8);
            subs_seen.insert(sub);
        }
        assert!(subs_seen.contains(&subscription));
        stop.cancel();
    };
    let (a, b, ()) = tokio::join!(server_a, server_b, client);
    a.unwrap();
    b.unwrap();
}

/// A `Subscribed` frame over the control limit (oversize snapshot) is replaced by
/// an `INTERNAL_ERROR` response and no subscription exists afterwards.
#[tokio::test]
async fn oversize_subscribed_frame_establishes_no_subscription() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher {
        snapshot_pad: MAX_CONTROL_FRAME_BYTES,
        ..LogDispatcher::new()
    };
    let server = serve_one(
        &l,
        d.clone(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        match c.subscribe(EventFilter::default(), None).await.unwrap() {
            SubscribeOutcome::Refused(env) => assert_eq!(env.code, Code::InternalError),
            other => panic!("{other:?}"),
        }
        d.publish(live_event(1));
        // Nothing is delivered for the refused subscription; the handle is unknown.
        assert_eq!(c.unsubscribe(1).await.unwrap().code, Code::NotFound);
        let env = c.request(inspect()).await.unwrap();
        assert_eq!(env.code, Code::Ok);
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

// ---- oversized events (ADR-0006 §8, §13.4 N03) -----------------------------------

/// An event whose frame exceeds the control limit.
fn oversized_event(n: u64) -> LiveEvent {
    let mut ev = live_event(n);
    ev.event.payload = serde_json::json!({ "n": n, "pad": "x".repeat(MAX_CONTROL_FRAME_BYTES) });
    ev
}

fn assert_oversized_resync(ev: &Event, last_delivered: &Cursor) {
    assert_eq!(ev.event_type, EventType::ResyncRequired);
    assert_eq!(
        &ev.cursor, last_delivered,
        "cursor must stay at the last delivered event"
    );
    assert_eq!(ev.payload["reason"], "event_too_large");
    assert_eq!(ev.payload["subscription_ended"], true);
    assert_eq!(ev.environment_id, env_id());
}

/// After the oversized event's subscription ended: further publication and a lag
/// burst deliver nothing on it, its handle is gone, resubscribing *from* the
/// carried cursor meets the same event again, and a fresh snapshot recovers.
async fn after_oversized_resync(
    c: &mut ControlClient<UnixStream>,
    d: &LogDispatcher,
    ended: u64,
    carried: Cursor,
    next_seq: u64,
) {
    // Further publication and a lag burst (> the 256-event buffer).
    for n in next_seq..next_seq + 300 {
        d.publish(live_event(n));
    }
    assert_eq!(
        c.unsubscribe(ended).await.unwrap().code,
        Code::NotFound,
        "the subscription must have ended"
    );
    // Resubscribing from the carried cursor replays the backlog after it, meets the
    // same oversized event and gets ResyncRequired again; nothing else.
    let SubscribeOutcome::Subscribed {
        subscription: again,
        snapshot,
        ..
    } = c
        .subscribe(EventFilter::default(), Some(carried.clone()))
        .await
        .unwrap()
    else {
        panic!("refused")
    };
    assert!(snapshot.is_none());
    let (sub, ev) = c.next_event().await.unwrap();
    assert_eq!(sub, again);
    assert_oversized_resync(&ev, &carried);
    assert_eq!(c.unsubscribe(again).await.unwrap().code, Code::NotFound);
    // Documented recovery: a fresh snapshot (no cursor).
    let SubscribeOutcome::Subscribed {
        subscription: fresh,
        cursor,
        snapshot,
    } = c.subscribe(EventFilter::default(), None).await.unwrap()
    else {
        panic!("refused")
    };
    let head = next_seq + 299;
    assert_eq!(snapshot.expect("snapshot").data["through"], head);
    assert_eq!(seq_of(&cursor), Some(head));
    d.publish(live_event(head + 1));
    // The next event on the wire is the fresh subscription's: nothing was sent for
    // the ended ones in between.
    let (sub, ev) = c.next_event().await.unwrap();
    assert_eq!(sub, fresh);
    assert_eq!(ev.payload["n"], head + 1);
    assert_eq!(seq_of(&ev.cursor), Some(head + 1));
}

/// N03, backlog path: an oversized backlog event is replaced by `ResyncRequired`
/// at the last delivered cursor, the rest of the backlog is not sent, and the
/// subscription ends.
#[tokio::test]
async fn oversized_backlog_event_ends_the_subscription_at_the_last_delivered_cursor() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher::new();
    d.publish(live_event(1));
    d.publish(live_event(2));
    d.publish(oversized_event(3));
    d.publish(live_event(4));
    let server = serve_one(
        &l,
        d.clone(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let SubscribeOutcome::Subscribed { subscription, .. } = c
            .subscribe(EventFilter::default(), Some(Cursor("r-:1".into())))
            .await
            .unwrap()
        else {
            panic!("refused")
        };
        let (sub, two) = c.next_event().await.unwrap();
        assert_eq!((sub, two.payload["n"].as_u64()), (subscription, Some(2)));
        let (sub, resync) = c.next_event().await.unwrap();
        assert_eq!(sub, subscription);
        assert_oversized_resync(&resync, &two.cursor);
        assert_no_canary(&serde_json::to_string(&resync).unwrap());
        after_oversized_resync(&mut c, &d, subscription, two.cursor.clone(), 5).await;
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}

/// N03, live path: an oversized live event is replaced by `ResyncRequired` at the
/// last delivered cursor (not the oversized event's), and the subscription ends.
#[tokio::test]
async fn oversized_live_event_ends_the_subscription_at_the_last_delivered_cursor() {
    let f = fixture();
    let l = Listener::bind(&f.paths.control, EndpointKind::Control).unwrap();
    let d = LogDispatcher::new();
    d.publish(live_event(1));
    let server = serve_one(
        &l,
        d.clone(),
        ConnectionLimits::default(),
        CancellationToken::new(),
    );
    let client = async {
        let s = connect(&f.paths.control).await.unwrap();
        let mut c = ControlClient::handshake(
            s,
            client_info(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        let SubscribeOutcome::Subscribed { subscription, .. } =
            c.subscribe(EventFilter::default(), None).await.unwrap()
        else {
            panic!("refused")
        };
        d.publish(live_event(2));
        let (sub, two) = c.next_event().await.unwrap();
        assert_eq!((sub, two.payload["n"].as_u64()), (subscription, Some(2)));
        d.publish(oversized_event(3));
        let (sub, resync) = c.next_event().await.unwrap();
        assert_eq!(sub, subscription);
        assert_oversized_resync(&resync, &two.cursor);
        after_oversized_resync(&mut c, &d, subscription, two.cursor.clone(), 4).await;
        drop(c);
    };
    let (r, ()) = tokio::join!(server, client);
    r.unwrap();
}
