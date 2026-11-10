//! Signing endpoint, M03 connection context and capacity-then-release order
//! (m03-plan U0b row 1; ADR-0008 D2 item 3a steps 6–9; §17.4 items 6 and 9, §17.7
//! item 2, §17.10 item 1).
//!
//! Cargo test target `integration_ipc_signing_m03` hosted by `heimdall-ipc`. Every
//! test except the Unix-socket part of `signing_session_carries_peer_and_endpoint`
//! runs on every platform: `serve_with_limits` is driven over in-memory duplex
//! streams, and the order of steps 6–8 is observed on the `#[doc(hidden)]`
//! `enqueue_signed` core with a queue the test owns, polled by hand. Ordering never
//! relies on sleeps: the fixture `Signer` and `ReleaseCheck` signal through
//! `Notify`, a test-controlled slow reader (a 9-byte duplex buffer that the client
//! does not drain) fills the outbound queue, and timeouts run in paused virtual time.
//! Fixture key blobs and signatures are synthetic bytes, never real keys.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_ipc::PeerIdentity;
use heimdall_ipc::signing::{
    EnqueueEnd, NoIdentities, PermitGuard, ReleaseCheck, ServeLimits, SessionBindRecord,
    SignOutcome, Signer, SigningSession, empty_identities_frame, enqueue_signed, failure_frame,
    serve_with_limits, sign_response_frame, success_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

// ---- fixtures ---------------------------------------------------------------------

/// Synthetic signature bytes (not a real signature).
const SIG: &[u8] = b"fixture-signature";

fn sig_frame() -> Vec<u8> {
    sign_response_frame(SIG).unwrap()
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn ident_req() -> Vec<u8> {
    framed(&[11])
}

fn sign_req() -> Vec<u8> {
    let mut body = vec![13];
    string(&mut body, b"fixture-key-blob");
    string(&mut body, b"data to sign");
    body.extend_from_slice(&0u32.to_be_bytes());
    framed(&body)
}

fn bind_contents(host_key: &[u8], forwarding: u8) -> Vec<u8> {
    let mut c = Vec::new();
    string(&mut c, host_key);
    string(&mut c, b"fixture-session-id");
    string(&mut c, b"fixture-host-signature");
    c.push(forwarding);
    c
}

fn bind_req(contents: &[u8]) -> Vec<u8> {
    let mut body = vec![27];
    string(&mut body, b"session-bind@openssh.com");
    body.extend_from_slice(contents);
    framed(&body)
}

fn split_frames(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert!(bytes.len() >= 4 + len, "answer truncated");
        out.push(bytes[..4 + len].to_vec());
        bytes = &bytes[4 + len..];
    }
    assert!(bytes.is_empty(), "trailing partial answer");
    out
}

fn unix_peer(uid: u32) -> PeerIdentity {
    PeerIdentity::Unix {
        uid,
        gid: uid,
        pid: None,
    }
}

fn sock(locator: &str) -> EndpointRef {
    EndpointRef {
        kind: EndpointKind::UnixSocket,
        locator: locator.to_owned(),
    }
}

/// What the fixture permit observed. Shared between the signer, the permits it
/// issues and the test.
#[derive(Default)]
struct Probe {
    /// `may_release` answers false (a refused release check).
    refuse: AtomicBool,
    /// The in-memory `narrowing_pending` mark (the real one lives in `app`).
    pending: AtomicBool,
    /// `may_release` calls.
    checks: AtomicUsize,
    /// The guard was dropped.
    dropped: AtomicBool,
    /// Signalled on drop.
    drop_notify: Notify,
}

type Hook = Box<dyn Fn() + Send + Sync>;

/// Fixture `ReleaseCheck`: answers from the probe, runs optional hooks at the check
/// and at drop (the core tests use them to look at the queue at that instant).
struct Check {
    probe: Arc<Probe>,
    expires: Instant,
    on_check: Option<Hook>,
    on_drop: Option<Hook>,
}

impl Check {
    fn new(probe: &Arc<Probe>, expires: Instant) -> Self {
        Self {
            probe: probe.clone(),
            expires,
            on_check: None,
            on_drop: None,
        }
    }
}

impl ReleaseCheck for Check {
    fn may_release(&self) -> bool {
        self.probe.checks.fetch_add(1, Ordering::SeqCst);
        if let Some(h) = &self.on_check {
            h();
        }
        !self.probe.refuse.load(Ordering::SeqCst) && !self.probe.pending.load(Ordering::SeqCst)
    }

    fn expires_at(&self) -> Instant {
        self.expires
    }
}

impl Drop for Check {
    fn drop(&mut self) {
        if let Some(h) = &self.on_drop {
            h();
        }
        self.probe.dropped.store(true, Ordering::SeqCst);
        self.probe.drop_notify.notify_one();
    }
}

/// `(peer, endpoint, bind)` as a signer call saw its session.
type Seen = (PeerIdentity, EndpointRef, Option<SessionBindRecord>);

/// Fixture signer: no identities, signs everything with a permit from `probe`,
/// accepts a session-bind whose host key is `good-host`.
struct PermitSigner {
    probe: Arc<Probe>,
    permit_life: Duration,
    /// Set the pending mark right after "admission" (a narrowing marking the grant
    /// between the fresh read and the release).
    mark_pending_after_admit: bool,
    seen: Mutex<Vec<Seen>>,
    binds: Mutex<Vec<Vec<u8>>>,
    signed: Notify,
}

impl PermitSigner {
    fn new(probe: &Arc<Probe>, permit_life: Duration) -> Self {
        Self {
            probe: probe.clone(),
            permit_life,
            mark_pending_after_admit: false,
            seen: Mutex::default(),
            binds: Mutex::default(),
            signed: Notify::new(),
        }
    }

    fn record(&self, s: &SigningSession) {
        self.seen
            .lock()
            .unwrap()
            .push((s.peer.clone(), s.endpoint.clone(), s.bind.clone()));
    }
}

#[async_trait::async_trait]
impl Signer for PermitSigner {
    async fn identities(&self, session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        self.record(session);
        Vec::new()
    }

    async fn sign(
        &self,
        session: &SigningSession,
        _key_blob: &[u8],
        _data: &[u8],
        _flags: u32,
    ) -> SignOutcome {
        self.record(session);
        let check = Check::new(&self.probe, Instant::now() + self.permit_life);
        if self.mark_pending_after_admit {
            self.probe.pending.store(true, Ordering::SeqCst);
        }
        self.signed.notify_one();
        SignOutcome::signature(SIG, PermitGuard(Box::new(check)))
    }

    fn session_bind(&self, session: &mut SigningSession, payload: &[u8]) -> bool {
        self.binds.lock().unwrap().push(payload.to_vec());
        match SessionBindRecord::parse(payload) {
            Some(rec) if rec.host_key == b"good-host" => {
                session.bind = Some(rec);
                true
            }
            _ => false,
        }
    }
}

fn limits(enqueue: Duration) -> ServeLimits {
    ServeLimits {
        idle: Duration::from_secs(30),
        enqueue_timeout: enqueue,
        outbound_frames: 1,
    }
}

/// Write `input`, close the write half, read until the server closes.
async fn exchange(
    signer: Arc<dyn Signer>,
    peer: PeerIdentity,
    endpoint: EndpointRef,
    input: &[u8],
) -> (std::io::Result<()>, Vec<u8>) {
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let srv = serve_with_limits(
        server,
        peer,
        endpoint,
        signer,
        CancellationToken::new(),
        limits(Duration::from_secs(2)),
    );
    let cli = async {
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    };
    tokio::join!(srv, cli)
}

/// The slow-reader setup: a 9-byte server→client buffer the client does not drain,
/// and a one-frame queue. Three identity answers fill the buffer (1), the writer
/// (2) and the queue (3); the sign reply then waits for capacity.
fn slow_pipe() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(9)
}

fn three_idents_then_sign() -> Vec<u8> {
    [ident_req(), ident_req(), ident_req(), sign_req()].concat()
}

fn poll_once<F: Future + ?Sized>(f: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

// ---- tests (platform-neutral first) -------------------------------------------------

#[tokio::test]
async fn signing_session_carries_peer_and_endpoint() {
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let input = [ident_req(), sign_req()].concat();

    let peer_a = unix_peer(4242);
    let ep_a = sock("/fixture/b/0123456789abcdef/agent.sock");
    let (res, out) = exchange(signer.clone(), peer_a.clone(), ep_a.clone(), &input).await;
    res.unwrap();
    assert_eq!(
        out,
        [empty_identities_frame().to_vec(), sig_frame()].concat()
    );

    // A second connection gets its own session.
    let peer_b = PeerIdentity::Windows {
        sid: "S-1-5-21-1-2-3-1001".to_owned(),
        pid: Some(7),
    };
    let ep_b = EndpointRef {
        kind: EndpointKind::NamedPipe,
        locator: r"\\.\pipe\heimdall-fixture-v0123456789abcdef".to_owned(),
    };
    let (res, _) = exchange(signer.clone(), peer_b.clone(), ep_b.clone(), &input).await;
    res.unwrap();

    let seen = signer.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            (peer_a.clone(), ep_a.clone(), None),
            (peer_a, ep_a, None),
            (peer_b.clone(), ep_b.clone(), None),
            (peer_b, ep_b, None),
        ]
    );

    // Over a real Unix socket the session carries the peer the transport
    // authenticated at accept.
    #[cfg(unix)]
    {
        use heimdall_ipc::endpoint::{EndpointKind as Ipc, EndpointPaths};
        use heimdall_ipc::unix::{Listener, connect, current_uid};

        let tmp = tempfile::tempdir().unwrap();
        let paths = EndpointPaths::for_runtime(&tmp.path().join("rt"), "unused");
        let listener = Listener::bind(&paths.signing, Ipc::Signing).unwrap();
        let ep = sock(paths.signing.to_str().unwrap());
        let unix_signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
        let server = async {
            let (stream, peer) = listener.accept().await.unwrap();
            let r = serve_with_limits(
                stream,
                peer.clone(),
                ep.clone(),
                unix_signer.clone(),
                CancellationToken::new(),
                limits(Duration::from_secs(2)),
            )
            .await;
            (r, peer)
        };
        let client = async {
            let mut s = connect(&paths.signing).await.unwrap();
            s.write_all(&ident_req()).await.unwrap();
            s.shutdown().await.unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            out
        };
        let ((r, accepted), out) = tokio::join!(server, client);
        r.unwrap();
        assert_eq!(out, empty_identities_frame());
        let PeerIdentity::Unix { uid, .. } = &accepted else {
            panic!("not a Unix peer");
        };
        assert_eq!(*uid, current_uid());
        let seen = unix_signer.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![(accepted, ep, None)]);
    }
}

#[tokio::test]
async fn session_bind_reaches_signer_and_answers_success_or_failure() {
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let good = bind_contents(b"good-host", 0);
    let bad = bind_contents(b"other-host", 1);
    let malformed = b"\x00\x00\x00\x09short".to_vec();
    let input = [
        bind_req(&bad),
        bind_req(&malformed),
        ident_req(), // the session has no bind yet
        bind_req(&good),
        sign_req(), // the accepted bind is on the session
    ]
    .concat();
    let (res, out) = exchange(signer.clone(), unix_peer(1000), sock("/s"), &input).await;
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![
            failure_frame().to_vec(),
            failure_frame().to_vec(),
            empty_identities_frame().to_vec(),
            success_frame().to_vec(),
            sig_frame(),
        ]
    );
    // The signer received the contents after the extension name, verbatim.
    assert_eq!(
        signer.binds.lock().unwrap().clone(),
        vec![bad, malformed, good.clone()]
    );
    let seen = signer.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].2, None);
    assert_eq!(seen[1].2, SessionBindRecord::parse(&good));
    assert!(!seen[1].2.as_ref().unwrap().is_forwarding);

    // The M01 signer refuses every bind (the trait's default).
    let (res, out) = exchange(
        Arc::new(NoIdentities),
        unix_peer(1000),
        sock("/s"),
        &bind_req(&bind_contents(b"good-host", 0)),
    )
    .await;
    res.unwrap();
    assert_eq!(out, failure_frame());
}

/// Steps 6–8 on the core with a queue the test owns: at the release check the frame
/// is not yet queued; at the drop it is. Over a served connection, the guard stays
/// alive while the reply waits for capacity and is gone once the signature is out.
#[tokio::test]
async fn permit_dropped_only_after_enqueue() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
    let rx = Arc::new(Mutex::new(rx));
    let probe = Arc::new(Probe::default());
    let at_check = Arc::new(Mutex::new(None));
    let at_drop = Arc::new(Mutex::new(None));
    let mut check = Check::new(&probe, Instant::now() + Duration::from_secs(3600));
    {
        let (q, at) = (rx.clone(), at_check.clone());
        check.on_check = Some(Box::new(move || {
            *at.lock().unwrap() = Some(q.lock().unwrap().len());
        }));
        let (q, at) = (rx.clone(), at_drop.clone());
        check.on_drop = Some(Box::new(move || {
            *at.lock().unwrap() = Some(q.lock().unwrap().len());
        }));
    }
    let r = enqueue_signed(
        &tx,
        sig_frame(),
        PermitGuard(Box::new(check)),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(r, Ok(()));
    assert_eq!(
        *at_check.lock().unwrap(),
        Some(0),
        "queued before the check"
    );
    assert_eq!(
        *at_drop.lock().unwrap(),
        Some(1),
        "dropped before the enqueue"
    );
    assert_eq!(rx.lock().unwrap().try_recv().unwrap(), sig_frame());

    // Served: the guard outlives the capacity wait.
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let (mut client, server) = slow_pipe();
    let srv = serve_with_limits(
        server,
        unix_peer(1000),
        sock("/s"),
        signer.clone(),
        CancellationToken::new(),
        limits(Duration::from_secs(3600)),
    );
    let cli = async {
        client.write_all(&three_idents_then_sign()).await.unwrap();
        client.shutdown().await.unwrap();
        signer.signed.notified().await;
        assert!(
            !probe.dropped.load(Ordering::SeqCst),
            "dropped while waiting"
        );
        assert_eq!(probe.checks.load(Ordering::SeqCst), 0);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    };
    let (res, out) = tokio::join!(srv, cli);
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![
            empty_identities_frame().to_vec(),
            empty_identities_frame().to_vec(),
            empty_identities_frame().to_vec(),
            sig_frame(),
        ]
    );
    assert!(probe.dropped.load(Ordering::SeqCst));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
}

/// No capacity within `signing_enqueue_timeout`: the connection closes and the
/// reply is never sent; the release check never ran.
#[tokio::test(start_paused = true)]
async fn enqueue_timeout_closes_without_frame() {
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let (mut client, server) = slow_pipe();
    let done = Notify::new();
    let srv = async {
        let r = serve_with_limits(
            server,
            unix_peer(1000),
            sock("/s"),
            signer.clone(),
            CancellationToken::new(),
            limits(Duration::from_secs(2)),
        )
        .await;
        done.notify_one();
        r
    };
    let cli = async {
        client.write_all(&three_idents_then_sign()).await.unwrap();
        signer.signed.notified().await;
        let waiting_since = Instant::now();
        // The slow reader reads nothing until the server has given up.
        done.notified().await;
        let waited = waiting_since.elapsed();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        (out, waited)
    };
    let (res, (out, waited)) = tokio::join!(srv, cli);
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(waited, Duration::from_secs(2));
    // Only what was already in the socket buffer: the first identities answer.
    assert_eq!(out, empty_identities_frame());
    assert_eq!(probe.checks.load(Ordering::SeqCst), 0);
    assert!(probe.dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn release_check_false_sends_failure_not_signature() {
    let probe = Arc::new(Probe::default());
    probe.refuse.store(true, Ordering::SeqCst);
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let (res, out) = exchange(
        signer.clone(),
        unix_peer(1000),
        sock("/s"),
        &[sign_req(), ident_req()].concat(),
    )
    .await;
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![failure_frame().to_vec(), empty_identities_frame().to_vec()]
    );
    assert!(!out.windows(SIG.len()).any(|w| w == SIG));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
    assert!(probe.dropped.load(Ordering::SeqCst));
}

/// The check runs only once room for the whole frame is reserved: with the queue
/// full the core waits and never calls `may_release`; when the room frees the check
/// sees the queue's only slot held by its own reservation and the frame not yet in.
#[tokio::test]
async fn capacity_reserved_before_release_check() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
    tx.try_send(b"earlier frame".to_vec()).unwrap();
    let probe = Arc::new(Probe::default());
    let at_check = Arc::new(Mutex::new(None));
    let mut check = Check::new(&probe, Instant::now() + Duration::from_secs(3600));
    {
        let (tx, at) = (tx.clone(), at_check.clone());
        check.on_check = Some(Box::new(move || {
            *at.lock().unwrap() = Some(tx.capacity());
        }));
    }
    let fut = enqueue_signed(
        &tx,
        sig_frame(),
        PermitGuard(Box::new(check)),
        Duration::from_secs(3600),
    );
    let mut fut = std::pin::pin!(fut);
    for _ in 0..3 {
        assert!(poll_once(fut.as_mut()).is_pending());
    }
    assert_eq!(
        probe.checks.load(Ordering::SeqCst),
        0,
        "checked without room"
    );
    assert!(!probe.dropped.load(Ordering::SeqCst));

    assert_eq!(rx.try_recv().unwrap(), b"earlier frame");
    assert_eq!(poll_once(fut.as_mut()), Poll::Ready(Ok(())));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
    assert_eq!(
        *at_check.lock().unwrap(),
        Some(0),
        "room not reserved at check"
    );
    assert_eq!(rx.try_recv().unwrap(), sig_frame());
}

/// Whenever `may_release` runs, the same poll finishes the enqueue: there is no
/// wait (no `Pending`) between the release check and the linearized effect, so a
/// deadline cannot pass in between.
#[tokio::test]
async fn enqueue_after_release_check_never_waits() {
    for prefilled in [false, true] {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        if prefilled {
            tx.try_send(b"earlier frame".to_vec()).unwrap();
        }
        let probe = Arc::new(Probe::default());
        let poll_no = Arc::new(AtomicUsize::new(0));
        let checked_in = Arc::new(Mutex::new(None));
        let mut check = Check::new(&probe, Instant::now() + Duration::from_secs(3600));
        {
            let (n, at) = (poll_no.clone(), checked_in.clone());
            check.on_check = Some(Box::new(move || {
                *at.lock().unwrap() = Some(n.load(Ordering::SeqCst));
            }));
        }
        let fut = enqueue_signed(
            &tx,
            sig_frame(),
            PermitGuard(Box::new(check)),
            Duration::from_secs(3600),
        );
        let mut fut = std::pin::pin!(fut);
        let mut ready_in = None;
        for i in 1..=4 {
            if i == 3 && prefilled {
                assert_eq!(rx.try_recv().unwrap(), b"earlier frame");
            }
            poll_no.store(i, Ordering::SeqCst);
            match poll_once(fut.as_mut()) {
                Poll::Pending => {
                    assert!(checked_in.lock().unwrap().is_none(), "checked, then waited")
                }
                Poll::Ready(r) => {
                    assert_eq!(r, Ok(()));
                    ready_in = Some(i);
                    break;
                }
            }
        }
        assert_eq!(ready_in, Some(if prefilled { 3 } else { 1 }));
        assert_eq!(
            *checked_in.lock().unwrap(),
            ready_in,
            "check and enqueue apart"
        );
        assert!(probe.dropped.load(Ordering::SeqCst));
        assert_eq!(rx.try_recv().unwrap(), sig_frame());
    }
}

/// The permit expires while the reply waits for capacity: the wait is cancelled at
/// the expiry, the signature is discarded and the permit dropped without a release
/// check, and `SSH_AGENT_FAILURE` goes out once room frees within the window. If no
/// room frees in the window, the connection closes without a reply.
#[tokio::test(start_paused = true)]
async fn expiry_cancels_capacity_wait_and_replies_failure() {
    // Room frees after the expiry, within the window: failure.
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_millis(500)));
    let (mut client, server) = slow_pipe();
    let srv = serve_with_limits(
        server,
        unix_peer(1000),
        sock("/s"),
        signer.clone(),
        CancellationToken::new(),
        limits(Duration::from_secs(2)),
    );
    let cli = async {
        client.write_all(&three_idents_then_sign()).await.unwrap();
        client.shutdown().await.unwrap();
        signer.signed.notified().await;
        let signed_at = Instant::now();
        probe.drop_notify.notified().await;
        assert_eq!(signed_at.elapsed(), Duration::from_millis(500));
        assert_eq!(probe.checks.load(Ordering::SeqCst), 0);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    };
    let (res, out) = tokio::join!(srv, cli);
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![
            empty_identities_frame().to_vec(),
            empty_identities_frame().to_vec(),
            empty_identities_frame().to_vec(),
            failure_frame().to_vec(),
        ]
    );
    assert!(!out.windows(SIG.len()).any(|w| w == SIG));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 0);

    // No room within the window after the expiry: closed without a reply.
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_millis(500)));
    let (mut client, server) = slow_pipe();
    let done = Notify::new();
    let srv = async {
        let r = serve_with_limits(
            server,
            unix_peer(1000),
            sock("/s"),
            signer.clone(),
            CancellationToken::new(),
            limits(Duration::from_secs(2)),
        )
        .await;
        done.notify_one();
        r
    };
    let cli = async {
        client.write_all(&three_idents_then_sign()).await.unwrap();
        signer.signed.notified().await;
        let signed_at = Instant::now();
        done.notified().await;
        assert_eq!(signed_at.elapsed(), Duration::from_secs(2));
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    };
    let (res, out) = tokio::join!(srv, cli);
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(out, empty_identities_frame());
    assert_eq!(probe.checks.load(Ordering::SeqCst), 0);
    assert!(probe.dropped.load(Ordering::SeqCst));
}

/// At the ipc layer: a `ReleaseCheck` whose `may_release` is false because the
/// grant is marked `narrowing_pending` (the real mark is `app`'s) gets
/// `SSH_AGENT_FAILURE`, never the signature, both when the mark lands between
/// admission and the enqueue, and while the reply waits for capacity.
#[tokio::test]
async fn may_release_refuses_while_pending() {
    // Marked right after admission.
    let probe = Arc::new(Probe::default());
    let mut signer = PermitSigner::new(&probe, Duration::from_secs(3600));
    signer.mark_pending_after_admit = true;
    let (res, out) = exchange(Arc::new(signer), unix_peer(1000), sock("/s"), &sign_req()).await;
    res.unwrap();
    assert_eq!(out, failure_frame());
    assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
    assert!(probe.dropped.load(Ordering::SeqCst));

    // Control: unmarked, the same signer releases the signature.
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let (res, out) = exchange(signer, unix_peer(1000), sock("/s"), &sign_req()).await;
    res.unwrap();
    assert_eq!(out, sig_frame());

    // Marked while the admitted reply waits for capacity.
    let probe = Arc::new(Probe::default());
    let signer = Arc::new(PermitSigner::new(&probe, Duration::from_secs(3600)));
    let (mut client, server) = slow_pipe();
    let srv = serve_with_limits(
        server,
        unix_peer(1000),
        sock("/s"),
        signer.clone(),
        CancellationToken::new(),
        limits(Duration::from_secs(3600)),
    );
    let cli = async {
        client.write_all(&three_idents_then_sign()).await.unwrap();
        client.shutdown().await.unwrap();
        signer.signed.notified().await;
        probe.pending.store(true, Ordering::SeqCst);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        out
    };
    let (res, out) = tokio::join!(srv, cli);
    res.unwrap();
    assert_eq!(
        split_frames(&out).last().unwrap(),
        &failure_frame().to_vec()
    );
    assert!(!out.windows(SIG.len()).any(|w| w == SIG));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 1);
    assert!(probe.dropped.load(Ordering::SeqCst));
}

/// Fixture signer for ADR-0008 §17.15: returns a permit-less signature, either as a
/// raw outcome (not declared ungated: a gated grant whose permit is missing) or
/// declared ungated (a grant with no signing gate, like the M01 fixtures). It
/// records the session's refusal counter at every call.
struct PermitlessSigner {
    declare_ungated: bool,
    refused_seen: Mutex<Vec<u32>>,
}

#[async_trait::async_trait]
impl Signer for PermitlessSigner {
    async fn identities(&self, session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        self.refused_seen
            .lock()
            .unwrap()
            .push(session.refused_permitless);
        Vec::new()
    }

    async fn sign(
        &self,
        session: &SigningSession,
        _key_blob: &[u8],
        _data: &[u8],
        _flags: u32,
    ) -> SignOutcome {
        self.refused_seen
            .lock()
            .unwrap()
            .push(session.refused_permitless);
        if self.declare_ungated {
            SignOutcome::ungated_signature(SIG)
        } else {
            SignOutcome {
                frame: sig_frame(),
                permit: None,
                ungated: false,
            }
        }
    }
}

#[tokio::test]
async fn permitless_signature_for_gated_grant_refused_and_recorded() {
    let signer = Arc::new(PermitlessSigner {
        declare_ungated: false,
        refused_seen: Mutex::default(),
    });
    let input = [sign_req(), sign_req(), ident_req()].concat();
    let (res, out) = exchange(signer.clone(), unix_peer(1000), sock("/s"), &input).await;
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![
            failure_frame().to_vec(),
            failure_frame().to_vec(),
            empty_identities_frame().to_vec(),
        ]
    );
    assert!(!out.windows(SIG.len()).any(|w| w == SIG));
    // Recorded per connection: the counter the later calls see.
    assert_eq!(signer.refused_seen.lock().unwrap().clone(), vec![0, 1, 2]);

    // A fresh connection starts at zero.
    let (res, _) = exchange(signer.clone(), unix_peer(1000), sock("/s"), &ident_req()).await;
    res.unwrap();
    assert_eq!(signer.refused_seen.lock().unwrap().last(), Some(&0));
}

#[tokio::test]
async fn permitless_signature_for_ungated_m01_fixture_sent() {
    let signer = Arc::new(PermitlessSigner {
        declare_ungated: true,
        refused_seen: Mutex::default(),
    });
    let input = [sign_req(), ident_req()].concat();
    let (res, out) = exchange(signer.clone(), unix_peer(1000), sock("/s"), &input).await;
    res.unwrap();
    assert_eq!(
        split_frames(&out),
        vec![sig_frame(), empty_identities_frame().to_vec()]
    );
    assert_eq!(signer.refused_seen.lock().unwrap().clone(), vec![0, 0]);
    let o = SignOutcome::ungated_signature(SIG);
    assert!(o.ungated && o.permit.is_none());
    // An oversize ungated signature is still a failure, never a truncated frame.
    let big =
        SignOutcome::ungated_signature(&vec![0u8; heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES]);
    assert_eq!(big.frame, failure_frame());
    assert!(!big.ungated);
}

/// `EnqueueEnd` is the core's only failure surface: a closed queue is reported, not
/// waited on.
#[tokio::test]
async fn enqueue_signed_reports_a_closed_queue() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
    drop(rx);
    let probe = Arc::new(Probe::default());
    let check = Check::new(&probe, Instant::now() + Duration::from_secs(3600));
    let r = enqueue_signed(
        &tx,
        sig_frame(),
        PermitGuard(Box::new(check)),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(r, Err(EnqueueEnd::Closed));
    assert_eq!(probe.checks.load(Ordering::SeqCst), 0);
    assert!(probe.dropped.load(Ordering::SeqCst));
}
