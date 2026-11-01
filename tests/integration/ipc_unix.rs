//! Unix control endpoint and sessions over real sockets (M01-U6; ADR-0006 §2.1,
//! §2.2, §2.3, §2.5; spec §13.2).
//!
//! Compiled as a unit-test module of `heimdall_ipc::unix` (`#[path]` include) so
//! it can reach the injected-`stat` decision functions. Every socket lives in a
//! fresh temp directory created by the test; nothing outside it is touched.
//!
//! Not covered here, recorded as `blocked`: a real peer with a different uid
//! (needs a second Unix account) and a real foreign-owned socket file (needs
//! root to `chown`). Those branches are exercised with forged `PeerIdentity`
//! values and injected `PathFacts`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::event::{Cursor, Event, EventFilter, EventType};
use heimdall_contract::ids::{EnvironmentId, EventId, OperationId};
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, PeerInfo,
    PrincipalInfo, ServerMessage,
};
use heimdall_contract::request::{CancelRequest, InspectRequest, InspectSubject, Request};
use heimdall_contract::{Code, EffectStatus, Envelope, ErrorData, PROTOCOL_VERSION, SchemaVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, broadcast};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::endpoint::{EndpointPaths, ExpectedOwner, verify_peer};
use crate::frame::{FrameError, decode_frame, encode_frame};
use crate::session::{
    ConnectionLimits, ControlClient, ControlConnection, Dispatcher, ServerRefusal,
    SubscribeOutcome, server_refusal, transport_failure_envelope,
};

/// Same rule as `heimdall_testkit::assert_no_canary` (testkit is not a
/// dev-dependency of this crate; see the M01-U6U7 hand-off escalation).
pub(crate) fn assert_no_canary(output: &str) {
    assert!(
        !output.contains("HEIMDALL_CANARY_"),
        "canary leaked into output"
    );
}

fn canary() -> String {
    format!("HEIMDALL_CANARY_{:x}", std::process::id())
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

/// Test dispatcher: records requests in a shared "journal", optionally holds
/// each dispatch until the gate grants a permit, answers `inspect` with the
/// journal, and serves subscriptions from a shared broadcast channel.
#[derive(Clone)]
struct TestDispatcher {
    journal: Arc<Mutex<Vec<String>>>,
    gate: Option<Arc<Semaphore>>,
    events: broadcast::Sender<Arc<Event>>,
}

impl TestDispatcher {
    fn new() -> Self {
        Self {
            journal: Arc::default(),
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
        principal: &PrincipalInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        if let Request::Cancel(c) = &request {
            self.journal
                .lock()
                .unwrap()
                .push(c.operation_id.as_str().to_owned());
        }
        if let Some(g) = &self.gate {
            g.acquire().await.unwrap().forget();
        }
        let journal = self.journal.lock().unwrap().clone();
        Envelope::ok(serde_json::json!({
            "kind": request.kind(),
            "principal": principal,
            "journal": journal,
        }))
    }

    async fn subscribe(
        &self,
        _principal: &PrincipalInfo,
        _filter: EventFilter,
        from: Option<Cursor>,
    ) -> Result<(Cursor, broadcast::Receiver<Arc<Event>>), Box<Envelope<ErrorData>>> {
        Ok((
            from.unwrap_or_else(|| Cursor("c0".into())),
            self.events.subscribe(),
        ))
    }
}

fn event(n: u64, ty: EventType, op: Option<OperationId>) -> Arc<Event> {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_be_bytes());
    Arc::new(Event {
        schema_version: SchemaVersion::current(),
        event_id: EventId::from_random_bytes(id),
        event_type: ty,
        environment_id: env_id(),
        operation_id: op,
        resource: None,
        timestamp: heimdall_contract::Timestamp::UNIX_EPOCH,
        cursor: Cursor(format!("c{n}")),
        payload: serde_json::json!({ "n": n }),
    })
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

fn principal_for(peer: &crate::endpoint::PeerIdentity) -> PrincipalInfo {
    verify_peer(peer, &ExpectedOwner::Uid(current_uid())).unwrap()
}

/// Accept one connection on `listener` and serve it to completion.
async fn serve_one(
    listener: &Listener,
    dispatcher: TestDispatcher,
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

fn hello_frame(schema: &str, name: &str) -> Vec<u8> {
    encode_frame(
        &ClientMessage::Hello(ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion(schema.into()),
            client: PeerInfo {
                name: name.into(),
                version: "0".into(),
            },
            capabilities: crate::session::server_capabilities(),
            required: BTreeSet::new(),
        }),
        MAX_HELLO_FRAME_BYTES,
    )
    .unwrap()
}

/// Read every server frame until EOF; also asserts no canary in the raw bytes.
async fn read_all_frames(stream: &mut tokio::net::UnixStream) -> Vec<ServerMessage> {
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
        ServerMessage::Reject(env) => Some(env.code),
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(
            c.server().principal,
            PrincipalInfo::OsUserUnix { uid: current_uid() }
        );
        assert_eq!(c.server().environment_id, env_id());
        assert_eq!(
            c.server().capabilities,
            crate::session::server_capabilities()
        );
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
    let forged = crate::endpoint::PeerIdentity::Unix {
        uid: other,
        gid: 0,
        pid: Some(1),
    };
    assert_eq!(
        verify_peer(&forged, &ExpectedOwner::Uid(me)),
        Err(crate::endpoint::PeerRejected::DifferentUser)
    );
    let root = crate::endpoint::PeerIdentity::Unix {
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
        crate::signing::serve(
            stream,
            Arc::new(crate::signing::NoIdentities),
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
            crate::signing::empty_identities_frame().as_slice(),
            crate::signing::failure_frame().as_slice()
        ]
        .concat()
    );
}

// ---- hello phase ----------------------------------------------------------------

/// Run a raw client script against a served connection; returns the server's
/// result and every frame the server sent.
async fn raw_session(
    limits: ConnectionLimits,
    script: impl AsyncFnOnce(&mut tokio::net::UnixStream),
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
        let err = ControlClient::handshake(s, client_info(), required)
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
                } => {
                    assert_eq!(cursor, Cursor("c0".into()));
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
                    let hello = crate::session::negotiate(
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
        let mut c = ControlClient::handshake(s, client_info(), BTreeSet::new())
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
