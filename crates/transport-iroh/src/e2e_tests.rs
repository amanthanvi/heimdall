//! Loopback end-to-end tests (feature `iroh`; m06-plan U6a): dialer ↔ server ↔ a local TCP
//! echo target, in process. Every endpoint runs the minimal policy: loopback binds, no
//! relay, no lookup, no DNS nameserver. Keys are generated per run and never written.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::{ExposurePolicy, RouteFailureClass};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::admission::{
    Allowlist, AuthorityGeneration, AuthorityHandle, ChannelAuthority, LeaseLoss,
};
use crate::dial::{DialError, DialRequest, PeerClose, PigeonsStream, dial};
use crate::endpoint::close_bounded;
use crate::keys::{InMemoryKeySource, KeySource};
use crate::lifecycle::{CLOSE_BOUND, LEASE_POLL_INTERVAL, SESSION_DRAIN_BOUND};
use crate::policy::RouteAddresses;
use crate::serve::{ServeConfig, ServeExit, Server, ShutdownHandle};
use crate::target::LoopbackTarget;

const STEP: Duration = Duration::from_secs(10);

/// A loopback TCP echo target that counts the connections it accepted.
struct Echo {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Echo {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        Self {
            addr,
            accepted,
            task,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Client {
    keys: InMemoryKeySource,
    id: IrohEndpointId,
}

fn client() -> Client {
    let keys = InMemoryKeySource::generate();
    let id = keys.load().unwrap().endpoint_id().unwrap();
    Client { keys, id }
}

/// Where a dialer reaches a server.
#[derive(Clone)]
struct Target {
    id: IrohEndpointId,
    addr: SocketAddr,
}

struct Running {
    target: Target,
    bound: Vec<SocketAddr>,
    shutdown: ShutdownHandle,
    run: JoinHandle<ServeExit>,
}

/// Binds a server for `allow` (with the authority admitting `admitted`) in front of `echo`,
/// and runs it.
async fn serve(
    allow: &[&IrohEndpointId],
    admitted: &[&IrohEndpointId],
    echo: &Echo,
) -> (Running, AuthorityHandle) {
    let (authority, handle) = ChannelAuthority::new(
        AuthorityGeneration(1),
        admitted.iter().map(|id| (*id).clone()),
    );
    let config = ServeConfig {
        policy: ExposurePolicy::default(),
        allowlist: Allowlist::new(allow.iter().map(|id| (*id).clone())).unwrap(),
        target: LoopbackTarget::new(echo.addr).unwrap(),
    };
    let server = Server::bind(config, &InMemoryKeySource::generate(), authority)
        .await
        .unwrap();
    let bound = server.bound_sockets();
    let addr = *bound.iter().find(|a| a.is_ipv4()).unwrap();
    let running = Running {
        target: Target {
            id: server.endpoint_id().clone(),
            addr,
        },
        bound,
        shutdown: server.shutdown_handle(),
        run: tokio::spawn(server.run()),
    };
    (running, handle)
}

async fn dial_to(
    server: &Target,
    who: &Client,
    timeout: Duration,
) -> Result<PigeonsStream, DialError> {
    let policy = ExposurePolicy::default();
    let route = RouteAddresses {
        direct: vec![server.addr],
        relay_hints: vec![],
    };
    dial(
        DialRequest {
            policy: &policy,
            peer: &server.id,
            route: &route,
            connect_timeout: timeout,
        },
        &who.keys,
    )
    .await
}

/// Writes `msg` and reads the same number of bytes back.
async fn round_trip(stream: &mut PigeonsStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    stream.write_all(msg).await?;
    stream.flush().await?;
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(STEP, stream.read_exact(&mut back))
        .await
        .map_err(|_| std::io::Error::other("read timed out"))??;
    Ok(back)
}

/// Waits until the stream reports the serving side's close (a read fails or ends).
async fn wait_peer_close(stream: &mut PigeonsStream) -> Option<PeerClose> {
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(STEP, async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    stream.peer_close()
}

/// A dial the serving side must refuse: either the dial itself fails with
/// `admission_refused`, or the stream fails on first use with the refusal close code.
async fn expect_admission_refused(server: &Target, who: &Client) {
    match dial_to(server, who, STEP).await {
        Err(e) => assert_eq!(
            e.failure_class(),
            Some(RouteFailureClass::AdmissionRefused),
            "{e}"
        ),
        Ok(mut stream) => {
            let r = round_trip(&mut stream, b"must not arrive").await;
            assert!(r.is_err(), "a refused stream carried bytes");
            assert_eq!(
                wait_peer_close(&mut stream).await,
                Some(PeerClose::AdmissionRefused)
            );
            stream.close().await;
        }
    }
}

async fn stop(server: Running) -> ServeExit {
    server.shutdown.shutdown();
    tokio::time::timeout(STEP, server.run)
        .await
        .unwrap()
        .unwrap()
}

fn assert_all_loopback(sockets: &[SocketAddr], who: &str) {
    assert!(!sockets.is_empty(), "{who} bound nothing");
    for s in sockets {
        assert!(
            s.ip().is_loopback(),
            "{who} bound a non-loopback socket: {s}"
        );
    }
}

/// Bytes round-trip through dialer, server and the loopback target; every bound socket of
/// both endpoints is loopback; the dialer's and the server's closes return within bounds.
#[tokio::test]
async fn loopback_round_trip_and_every_bound_socket_is_loopback() {
    let echo = Echo::start().await;
    let a = client();
    let (server, _handle) = serve(&[&a.id], &[&a.id], &echo).await;
    assert_all_loopback(&server.bound, "the server");
    let mut stream = dial_to(&server.target, &a, STEP).await.unwrap();
    assert_all_loopback(&stream.bound_sockets(), "the dialer");
    assert_eq!(stream.remote_id().as_ref(), Some(&server.target.id));
    let back = round_trip(&mut stream, b"hello over /pigeons/0")
        .await
        .unwrap();
    assert_eq!(back, b"hello over /pigeons/0");
    let back = round_trip(&mut stream, &[0u8, 255, 10, 13]).await.unwrap();
    assert_eq!(back, [0u8, 255, 10, 13]);
    assert_eq!(echo.accepted(), 1);
    let start = Instant::now();
    assert!(
        stream.close().await,
        "the dialer's endpoint close exceeded its bound"
    );
    assert!(start.elapsed() < CLOSE_BOUND * 2 + Duration::from_millis(500));
    assert_eq!(stop(server).await, ServeExit::Shutdown);
}

/// ⟨M08 W4 SEC-3b, S2-03⟩ One allowlist entry that is not an endpoint key (64 hex
/// characters whose 32 bytes are not an Ed25519 public key) is skipped and reported
/// ([`Server::skipped_allowlist_entries`]); it never stops the server for every other
/// client: the valid client is admitted and served. An allowlist with no valid entry is
/// still refused.
#[tokio::test]
async fn an_invalid_allowlist_entry_is_skipped_and_reported_and_the_rest_are_served() {
    let not_a_key = (0u8..=255)
        .map(|b| IrohEndpointId::parse(&format!("{b:02x}").repeat(32)).unwrap())
        .find(|id| crate::endpoint::iroh_id(id).is_none())
        .expect("some repeated-byte string is not a curve point");
    let echo = Echo::start().await;
    let a = client();
    let (authority, _handle) =
        ChannelAuthority::new(AuthorityGeneration(1), [a.id.clone(), not_a_key.clone()]);
    let config = ServeConfig {
        policy: ExposurePolicy::default(),
        allowlist: Allowlist::new([a.id.clone(), not_a_key.clone()]).unwrap(),
        target: LoopbackTarget::new(echo.addr).unwrap(),
    };
    let server = match Server::bind(config, &InMemoryKeySource::generate(), authority).await {
        Ok(s) => s,
        Err(e) => panic!("one invalid entry stopped the server for every client: {e}"),
    };
    assert_eq!(
        server.skipped_allowlist_entries(),
        std::slice::from_ref(&not_a_key)
    );
    let bound = server.bound_sockets();
    let running = Running {
        target: Target {
            id: server.endpoint_id().clone(),
            addr: *bound.iter().find(|addr| addr.is_ipv4()).unwrap(),
        },
        bound,
        shutdown: server.shutdown_handle(),
        run: tokio::spawn(server.run()),
    };
    let mut stream = dial_to(&running.target, &a, STEP).await.unwrap();
    assert_eq!(
        round_trip(&mut stream, b"still served").await.unwrap(),
        b"still served"
    );
    assert!(stream.close().await);
    assert_eq!(stop(running).await, ServeExit::Shutdown);
    // No valid entry at all: refused, as before.
    let (authority, _handle) = ChannelAuthority::new(AuthorityGeneration(1), [not_a_key.clone()]);
    let config = ServeConfig {
        policy: ExposurePolicy::default(),
        allowlist: Allowlist::new([not_a_key]).unwrap(),
        target: LoopbackTarget::new(echo.addr).unwrap(),
    };
    assert!(
        Server::bind(config, &InMemoryKeySource::generate(), authority)
            .await
            .is_err()
    );
}

/// ADR-0012 §2.3 item 1: a dialer not on the allowlist, and an allowlisted dialer the
/// authority does not admit (tombstoned), are refused before any byte reaches the target:
/// the echo target sees no connection.
#[tokio::test]
async fn non_admitted_dialers_are_refused_before_any_byte_reaches_the_target() {
    let echo = Echo::start().await;
    let enrolled = client();
    let stranger = client();
    let tombstoned = client();
    let (server, _handle) = serve(&[&enrolled.id, &tombstoned.id], &[&enrolled.id], &echo).await;
    expect_admission_refused(&server.target, &stranger).await;
    expect_admission_refused(&server.target, &tombstoned).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(echo.accepted(), 0, "the target saw a refused dialer");
    // Positive control: the enrolled client gets through.
    let mut ok = dial_to(&server.target, &enrolled, STEP).await.unwrap();
    assert_eq!(round_trip(&mut ok, b"ok").await.unwrap(), b"ok");
    assert_eq!(echo.accepted(), 1);
    ok.close().await;
    stop(server).await;
}

/// ADR-0012 §2.3 item 4: revoking an endpoint through the admission hook closes its live
/// stream and refuses new ones, acknowledged after the close; other endpoints keep working
/// and are still admitted at the new generation.
#[tokio::test]
async fn revoking_an_endpoint_closes_its_live_stream_and_refuses_new_ones() {
    let echo = Echo::start().await;
    let a = client();
    let b = client();
    let (server, handle) = serve(&[&a.id, &b.id], &[&a.id, &b.id], &echo).await;
    let mut sa = dial_to(&server.target, &a, STEP).await.unwrap();
    let mut sb = dial_to(&server.target, &b, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sa, b"a1").await.unwrap(), b"a1");
    assert_eq!(round_trip(&mut sb, b"b1").await.unwrap(), b"b1");
    assert_eq!(echo.accepted(), 2);

    let report = tokio::time::timeout(STEP, handle.revoke(vec![a.id.clone()]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.generation, AuthorityGeneration(2));
    assert_eq!(report.closed, 1);
    assert!(
        report.complete,
        "the revoked session did not end within the drain bound"
    );

    assert_eq!(wait_peer_close(&mut sa).await, Some(PeerClose::Revoked));
    assert!(round_trip(&mut sa, b"a2").await.is_err());
    assert_eq!(round_trip(&mut sb, b"b2").await.unwrap(), b"b2");
    expect_admission_refused(&server.target, &a).await;
    let mut sb2 = dial_to(&server.target, &b, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sb2, b"b3").await.unwrap(), b"b3");
    assert_eq!(
        echo.accepted(),
        3,
        "the revoked endpoint reached the target again"
    );
    sa.close().await;
    sb.close().await;
    sb2.close().await;
    stop(server).await;
}

/// ADR-0012 §2.3 item 3: lease loss (here channel EOF: the runtime's handle is dropped)
/// closes every stream at once, stops admission and ends the server within its bounds.
#[tokio::test]
async fn lease_loss_closes_every_stream_and_ends_the_server() {
    let echo = Echo::start().await;
    let a = client();
    let b = client();
    let (server, handle) = serve(&[&a.id, &b.id], &[&a.id, &b.id], &echo).await;
    let mut sa = dial_to(&server.target, &a, STEP).await.unwrap();
    let mut sb = dial_to(&server.target, &b, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sa, b"a").await.unwrap(), b"a");
    assert_eq!(round_trip(&mut sb, b"b").await.unwrap(), b"b");

    let target = server.target.clone();
    let start = Instant::now();
    drop(handle);
    let exit = tokio::time::timeout(STEP, server.run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit, ServeExit::LeaseLost(LeaseLoss::ChannelClosed));
    assert!(
        start.elapsed() < SESSION_DRAIN_BOUND + CLOSE_BOUND + Duration::from_millis(500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(wait_peer_close(&mut sa).await, Some(PeerClose::LeaseLost));
    assert_eq!(wait_peer_close(&mut sb).await, Some(PeerClose::LeaseLost));
    let before = echo.accepted();
    let again = dial_to(&target, &a, Duration::from_secs(2)).await;
    assert!(again.is_err(), "a stopped server admitted a dialer");
    assert_eq!(echo.accepted(), before);
    sa.close().await;
    sb.close().await;
}

/// The same with the lease reported lost explicitly (runtime exit): every stream closed.
#[tokio::test]
async fn reported_lease_loss_closes_every_stream() {
    let echo = Echo::start().await;
    let a = client();
    let (server, handle) = serve(&[&a.id], &[&a.id], &echo).await;
    let mut sa = dial_to(&server.target, &a, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sa, b"a").await.unwrap(), b"a");
    handle.lose_lease(LeaseLoss::RuntimeExited);
    let exit = tokio::time::timeout(STEP, server.run)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit, ServeExit::LeaseLost(LeaseLoss::RuntimeExited));
    assert_eq!(wait_peer_close(&mut sa).await, Some(PeerClose::LeaseLost));
    sa.close().await;
}

/// ADR-0012 §2.3 item 3: a generation change the child has not acknowledged is lease loss:
/// the established stream is closed at once (by the lease watchdog, with no other event),
/// new streams are refused and never reach the target, and admission resumes only under a
/// fresh lease for the new generation.
#[tokio::test]
async fn unacknowledged_generation_closes_streams_and_refuses_until_a_fresh_lease() {
    let echo = Echo::start().await;
    let a = client();
    let (server, handle) = serve(&[&a.id], &[&a.id], &echo).await;
    let mut sa = dial_to(&server.target, &a, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sa, b"before").await.unwrap(), b"before");
    assert_eq!(echo.accepted(), 1);

    let start = Instant::now();
    assert_eq!(handle.advance_generation_silently(), AuthorityGeneration(2));
    assert_eq!(wait_peer_close(&mut sa).await, Some(PeerClose::LeaseLost));
    let took = start.elapsed();
    assert!(
        took < LEASE_POLL_INTERVAL * 5 + Duration::from_millis(500),
        "the established stream outlived the lost lease: {took:?}"
    );
    assert!(round_trip(&mut sa, b"after").await.is_err());
    expect_admission_refused(&server.target, &a).await;
    expect_admission_refused(&server.target, &a).await;
    assert_eq!(
        echo.accepted(),
        1,
        "a stream reached the target without a lease"
    );
    assert!(
        !server.run.is_finished(),
        "an unacknowledged generation ended the server"
    );

    let report = tokio::time::timeout(STEP, handle.grant_lease())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.generation, AuthorityGeneration(2));
    assert!(report.resumed);
    let mut again = dial_to(&server.target, &a, STEP).await.unwrap();
    assert_eq!(round_trip(&mut again, b"fresh").await.unwrap(), b"fresh");
    assert_eq!(echo.accepted(), 2);
    sa.close().await;
    again.close().await;
    assert_eq!(stop(server).await, ServeExit::Shutdown);
}

#[tokio::test]
async fn server_shutdown_with_a_live_stream_is_bounded() {
    let echo = Echo::start().await;
    let a = client();
    let (server, _handle) = serve(&[&a.id], &[&a.id], &echo).await;
    let mut sa = dial_to(&server.target, &a, STEP).await.unwrap();
    assert_eq!(round_trip(&mut sa, b"x").await.unwrap(), b"x");
    let start = Instant::now();
    let exit = stop(server).await;
    let took = start.elapsed();
    assert_eq!(exit, ServeExit::Shutdown);
    assert!(
        took < SESSION_DRAIN_BOUND + CLOSE_BOUND + Duration::from_millis(500),
        "{took:?}"
    );
    let start = Instant::now();
    sa.close().await;
    assert!(start.elapsed() < CLOSE_BOUND * 2 + Duration::from_millis(500));
}

/// A direct bounded close of a bound endpoint that has a live connection.
#[tokio::test]
async fn direct_endpoint_close_with_a_live_connection_is_bounded() {
    use crate::endpoint::{Role, plan_endpoint};
    let echo = Echo::start().await;
    let a = client();
    let (server, _handle) = serve(&[&a.id], &[&a.id], &echo).await;
    let route = RouteAddresses {
        direct: vec![server.target.addr],
        relay_hints: vec![],
    };
    let plan = plan_endpoint(
        &ExposurePolicy::default(),
        Role::Dial {
            peer: &server.target.id,
            route: &route,
        },
    )
    .unwrap();
    let endpoint = plan
        .builder
        .secret_key(a.keys.load().unwrap().secret_key())
        .bind()
        .await
        .unwrap();
    assert_all_loopback(&endpoint.bound_sockets(), "the raw dialer");
    let conn = endpoint
        .connect(plan.peer.unwrap(), crate::ALPN)
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"live").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(STEP, recv.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    let start = Instant::now();
    let in_time = close_bounded(&endpoint).await;
    let took = start.elapsed();
    assert!(took < CLOSE_BOUND + Duration::from_millis(300), "{took:?}");
    assert!(in_time || took >= CLOSE_BOUND);
    stop(server).await;
}

// --- stdin independence (ADR-0012 §1 item 5; G06 S03) ----------------------------------

const STDIN_CHILD: &str = "HM_TRANSPORT_IROH_STDIN_CHILD";
const STDIN_TEST: &str = "e2e_tests::dial_and_serve_do_not_depend_on_stdin";

/// Regression: the library's dial and serve futures depend on no standard stream, so a
/// runtime that ran them is released by a plain drop while the process's stdin stays open
/// (G06 S03: tokio's stdin reader, a blocking thread, held the probe's runtime and ssh open).
///
/// The test re-runs itself as a child whose stdin is a pipe this process holds open and
/// never writes. The `library` child runs a loopback round trip (server, dialer, target) on
/// a fresh runtime and then drops the runtime plainly; it must exit. The `control` child
/// starts a blocking stdin read on its runtime and drops it the same way; it must not exit
/// within the bound, which shows the harness detects the S03 defect.
#[test]
fn dial_and_serve_do_not_depend_on_stdin() {
    match std::env::var(STDIN_CHILD).as_deref() {
        Ok("library") => return stdin_child_library(),
        Ok("control") => return stdin_child_control(),
        _ => {}
    }
    assert_eq!(
        run_stdin_child("control", Duration::from_secs(2)),
        None,
        "the control child exited although its stdin stayed open: the check proves nothing"
    );
    assert_eq!(
        run_stdin_child("library", Duration::from_secs(60)),
        Some(true),
        "the library child did not exit cleanly while its stdin stayed open"
    );
}

/// Runs this test binary as a child in `mode`, with stdin held open. `Some(success)` if it
/// exited within `bound`; `None` if not (it is then killed through its own handle).
fn run_stdin_child(mode: &str, bound: Duration) -> Option<bool> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args(["--exact", STDIN_TEST, "--test-threads=1", "--quiet"])
        .env(STDIN_CHILD, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let held_open = child.stdin.take();
    let deadline = std::time::Instant::now() + bound;
    let out = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status.success());
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(held_open);
    out
}

fn stdin_child_library() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let echo = Echo::start().await;
        let a = client();
        let (server, _handle) = serve(&[&a.id], &[&a.id], &echo).await;
        let mut stream = dial_to(&server.target, &a, STEP).await.unwrap();
        assert_eq!(round_trip(&mut stream, b"stdin").await.unwrap(), b"stdin");
        stream.close().await;
        stop(server).await;
    });
    // Deliberately a plain drop: it would wait for any blocking stdin reader.
    drop(rt);
}

fn stdin_child_control() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // What tokio's stdin does internally: a blocking read on a pool thread.
        drop(tokio::task::spawn_blocking(|| {
            use std::io::Read as _;
            let mut b = [0u8; 1];
            let _ = std::io::stdin().read(&mut b);
        }));
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    drop(rt);
}
