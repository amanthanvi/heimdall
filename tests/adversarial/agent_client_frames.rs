//! The bounded agent client under adversarial replies (m02-plan U6 "Adversarial";
//! ADR-0007 §6 `agent` level: one `SSH_AGENTC_REQUEST_IDENTITIES`, 256 KiB, 1024
//! identities, 2 s).
//!
//! Cargo test target `adversarial_agent_client_frames` hosted by `heimdall-ipc`
//! (review F09 convention). It drives `heimdall_ipc::agent_client` through its public
//! API and its `#[doc(hidden)]` pieces (`exchange`, `parse_reply`). Replies come from
//! in-memory duplex streams and, on Unix, from a scripted server on a socket in a
//! scratch directory this test creates; nothing else is contacted. Key blobs are
//! synthetic public Ed25519 keys built per run (no private key exists anywhere), and
//! comments are per-run `HEIMDALL_CANARY_*` strings, so a leaked comment fails the
//! canary check. Fingerprints are checked against `ssh-key`, an independent
//! computation from the one under test only in that the test builds the expected
//! value from the key, not from the reply.
//!
//! A Unix peer with a different UID needs a second account: that native case is
//! `blocked` where none exists (m02-plan U6), and the decision itself is covered
//! here through `check_peer_uid`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use heimdall_ipc::agent_client::{
    AgentClientError, ClientBounds, MAX_IDENTITIES, MAX_REPLY_BYTES, MAX_TIMEOUT,
    REQUEST_IDENTITIES_FRAME, check_peer_uid, exchange, identity_of_blob, parse_reply,
};
use heimdall_testkit::CANARY_PREFIX;
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};
use ssh_encoding::Encode;
use ssh_key::HashAlg;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A synthetic public key blob (public material only; no private key exists).
fn blob(seed: u8) -> Vec<u8> {
    let mut out = Vec::new();
    KeyData::Ed25519(Ed25519PublicKey([seed; 32]))
        .encode(&mut out)
        .unwrap();
    out
}

fn fingerprint(seed: u8) -> String {
    KeyData::Ed25519(Ed25519PublicKey([seed; 32]))
        .fingerprint(HashAlg::Sha256)
        .to_string()
}

/// A per-run canary comment (never committed as a value).
fn canary() -> String {
    format!("{CANARY_PREFIX}U6_{:x}", std::process::id())
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

/// `SSH_AGENT_IDENTITIES_ANSWER` body listing `blobs`, each with `comment`.
fn answer(blobs: &[Vec<u8>], comment: &[u8]) -> Vec<u8> {
    let mut body = vec![12];
    body.extend_from_slice(&u32::try_from(blobs.len()).unwrap().to_be_bytes());
    for b in blobs {
        put_string(&mut body, b);
        put_string(&mut body, comment);
    }
    body
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// Run the exchange against an in-memory peer that reads the request and answers
/// `reply` (raw bytes), then closes. Returns the result and every byte the client
/// wrote.
async fn duplex_exchange(
    reply: Vec<u8>,
    bounds: ClientBounds,
) -> (
    Result<Vec<heimdall_ipc::agent_client::AgentIdentity>, AgentClientError>,
    Vec<u8>,
) {
    let (mut client, mut server) = tokio::io::duplex(1 << 20);
    let peer = async move {
        let mut request = [0u8; 5];
        server.read_exact(&mut request).await.unwrap();
        server.write_all(&reply).await.unwrap();
        server.flush().await.unwrap();
        let mut written = request.to_vec();
        // Anything else the client writes before closing.
        let mut rest = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_millis(200), server.read_to_end(&mut rest)).await;
        written.extend_from_slice(&rest);
        written
    };
    let client_side = async move {
        let r = exchange(&mut client, &bounds).await;
        drop(client);
        r
    };
    let (r, written) = tokio::join!(client_side, peer);
    (r, written)
}

#[tokio::test]
async fn a_well_formed_listing_round_trips_and_discards_comments() {
    let comment = canary();
    let blobs: Vec<Vec<u8>> = (1..=3).map(blob).collect();
    let (r, written) = duplex_exchange(
        framed(&answer(&blobs, comment.as_bytes())),
        ClientBounds::default(),
    )
    .await;
    let ids = r.unwrap();
    assert_eq!(
        written, REQUEST_IDENTITIES_FRAME,
        "exactly one request, nothing else"
    );
    assert_eq!(ids.len(), 3);
    for (i, id) in ids.iter().enumerate() {
        let seed = u8::try_from(i + 1).unwrap();
        assert_eq!(id.key_type, "ssh-ed25519");
        assert_eq!(id.fingerprint, fingerprint(seed));
        assert_eq!(id.public_blob, blob(seed));
    }
    heimdall_testkit::assert_no_canary(&format!("{ids:?}"));
}

#[tokio::test]
async fn truncated_replies_are_refused() {
    let full = framed(&answer(&[blob(1)], b"c"));
    // Nothing at all, half a header, a header and part of the body.
    for cut in [0, 2, 4, 9, full.len() - 1] {
        let (r, _) = duplex_exchange(full[..cut].to_vec(), ClientBounds::default()).await;
        assert_eq!(r, Err(AgentClientError::Truncated), "cut at {cut}");
    }
}

#[tokio::test]
async fn an_oversized_reply_is_refused_from_its_header() {
    let declared = MAX_REPLY_BYTES + 1;
    let header = u32::try_from(declared).unwrap().to_be_bytes().to_vec();
    // Only the header is sent and the peer then closes: the client must not wait
    // for a body it would refuse anyway.
    let (r, _) = duplex_exchange(header, ClientBounds::default()).await;
    assert_eq!(r, Err(AgentClientError::ReplyTooLarge { declared }));
    // A caller can only tighten the bound.
    let narrow = ClientBounds {
        max_reply_bytes: 16,
        ..ClientBounds::default()
    };
    let (r, _) = duplex_exchange(framed(&answer(&[blob(1)], b"c")), narrow).await;
    assert!(matches!(r, Err(AgentClientError::ReplyTooLarge { .. })));
    let wide = ClientBounds {
        max_reply_bytes: usize::MAX,
        ..ClientBounds::default()
    };
    let (r, _) = duplex_exchange(u32::MAX.to_be_bytes().to_vec(), wide).await;
    assert!(matches!(r, Err(AgentClientError::ReplyTooLarge { .. })));
}

#[tokio::test]
async fn identity_count_bound_is_1024() {
    let many: Vec<Vec<u8>> = (0..MAX_IDENTITIES)
        .map(|i| {
            let mut out = Vec::new();
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
            KeyData::Ed25519(Ed25519PublicKey(key))
                .encode(&mut out)
                .unwrap();
            out
        })
        .collect();
    let (r, _) = duplex_exchange(framed(&answer(&many, b"")), ClientBounds::default()).await;
    assert_eq!(r.unwrap().len(), MAX_IDENTITIES);

    let mut over = many.clone();
    over.push(blob(9));
    let body = answer(&over, b"");
    assert!(
        body.len() + 4 <= MAX_REPLY_BYTES,
        "the size bound is not what refuses"
    );
    let (r, _) = duplex_exchange(framed(&body), ClientBounds::default()).await;
    assert_eq!(
        r,
        Err(AgentClientError::TooManyIdentities {
            declared: MAX_IDENTITIES + 1
        })
    );
}

#[tokio::test]
async fn wrong_message_types_and_failures_are_distinct() {
    for (body, expected) in [
        (
            vec![14u8, 0, 0, 0, 0],
            AgentClientError::UnexpectedMessage(14),
        ),
        (vec![6u8], AgentClientError::UnexpectedMessage(6)),
        (vec![5u8], AgentClientError::AgentFailure),
    ] {
        let (r, _) = duplex_exchange(framed(&body), ClientBounds::default()).await;
        assert_eq!(r, Err(expected));
    }
    let (r, _) = duplex_exchange(vec![0, 0, 0, 0], ClientBounds::default()).await;
    assert!(matches!(r, Err(AgentClientError::Malformed(_))));
}

#[test]
fn malformed_answers_refuse_the_whole_reply() {
    let good = answer(&[blob(1), blob(2)], b"c");
    // Trailing byte.
    let mut trailing = good.clone();
    trailing.push(0);
    // A count beyond the bytes present.
    let mut short = vec![12u8];
    short.extend_from_slice(&3u32.to_be_bytes());
    put_string(&mut short, &blob(1));
    put_string(&mut short, b"c");
    // A string length beyond the reply.
    let mut overrun = vec![12u8, 0, 0, 0, 1, 0, 0, 1, 0];
    overrun.extend_from_slice(b"short");
    // A key blob ssh-key cannot decode, between two good ones.
    let mut bad_blob = blob(3);
    bad_blob.truncate(bad_blob.len() - 1);
    let middle = answer(&[blob(1), bad_blob, blob(2)], b"c");
    // A key blob with trailing bytes.
    let mut long_blob = blob(4);
    long_blob.push(0);
    let long = answer(&[long_blob], b"c");
    // An algorithm name that is not printable ASCII.
    let mut odd = Vec::new();
    put_string(&mut odd, b"ssh-\x01ed25519");
    put_string(&mut odd, &[7u8; 32]);
    let odd = answer(&[odd], b"c");
    for (name, body) in [
        ("trailing", trailing),
        ("short", short),
        ("overrun", overrun),
        ("bad blob", middle),
        ("long blob", long),
        ("odd name", odd),
    ] {
        assert!(
            matches!(
                parse_reply(&body, MAX_IDENTITIES),
                Err(AgentClientError::Malformed(_))
            ),
            "{name}"
        );
    }
    assert_eq!(parse_reply(&good, MAX_IDENTITIES).unwrap().len(), 2);
}

#[test]
fn errors_never_carry_reply_content() {
    let comment = canary();
    let mut body = answer(&[blob(1)], comment.as_bytes());
    body.push(0xff);
    let e = parse_reply(&body, MAX_IDENTITIES).unwrap_err();
    heimdall_testkit::assert_no_canary(&format!("{e} {e:?}"));
    let mut bad = Vec::new();
    put_string(&mut bad, comment.as_bytes());
    let e = identity_of_blob(&bad).unwrap_err();
    heimdall_testkit::assert_no_canary(&format!("{e} {e:?}"));
}

/// 32 bytes seeded from the OS for this run only (std's `RandomState`): never a
/// committed value.
fn run_seed() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(0x5536);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

#[test]
fn certificates_are_fingerprinted_by_the_certified_key() {
    use ssh_key::PrivateKey;
    use ssh_key::certificate::{Builder, CertType};
    use ssh_key::private::Ed25519Keypair;
    // A throwaway CA generated in memory for this run; never written anywhere.
    let ca = PrivateKey::from(Ed25519Keypair::from_seed(&run_seed()));
    let subject = KeyData::Ed25519(Ed25519PublicKey([5; 32]));
    let mut builder = Builder::new(run_seed().to_vec(), subject, 0, 4_000_000_000).unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.valid_principal("fixture").unwrap();
    let cert = builder.sign(&ca).unwrap();
    let mut cert_blob = Vec::new();
    cert.encode(&mut cert_blob).unwrap();
    let id = identity_of_blob(&cert_blob).unwrap();
    assert_eq!(id.key_type, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(id.fingerprint, fingerprint(5));
    // A certificate blob cut short is refused, not guessed at.
    assert!(identity_of_blob(&cert_blob[..cert_blob.len() - 1]).is_err());
}

#[test]
fn a_foreign_peer_uid_is_refused() {
    assert_eq!(check_peer_uid(1000, 1000), Ok(()));
    assert_eq!(check_peer_uid(0, 1000), Err(AgentClientError::ForeignPeer));
    assert_eq!(
        check_peer_uid(1001, 1000),
        Err(AgentClientError::ForeignPeer)
    );
}

#[test]
fn bounds_never_exceed_the_hard_maximums() {
    let c = ClientBounds {
        timeout: Duration::from_secs(3600),
        max_reply_bytes: usize::MAX,
        max_identities: usize::MAX,
    }
    .clamped();
    assert_eq!(c.timeout, MAX_TIMEOUT);
    assert_eq!(c.timeout, Duration::from_secs(2));
    assert_eq!(c.max_reply_bytes, 256 * 1024);
    assert_eq!(c.max_identities, 1024);
}

fn props_config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5536_4147_454e_5431);
    }
    c
}

proptest! {
    #![proptest_config(props_config())]

    /// Arbitrary reply bodies never panic and never yield more identities than the
    /// bound or than the reply could hold.
    #[test]
    fn arbitrary_bodies_are_total(body in proptest::collection::vec(any::<u8>(), 0..2048),
                                  max in 0usize..2048) {
        if let Ok(ids) = parse_reply(&body, max) {
            prop_assert!(ids.len() <= max.min(MAX_IDENTITIES));
            prop_assert!(ids.len() * 8 < body.len().max(1));
        }
    }

    /// Generated well-formed answers parse exactly: the fingerprints are the keys'
    /// own, in order, whatever the comments hold (canaries included).
    #[test]
    fn generated_answers_parse_exactly(
        seeds in proptest::collection::vec(any::<u8>(), 0..64),
        comment in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut comment = comment;
        comment.extend_from_slice(canary().as_bytes());
        let blobs: Vec<Vec<u8>> = seeds.iter().map(|s| blob(*s)).collect();
        let ids = parse_reply(&answer(&blobs, &comment), MAX_IDENTITIES).unwrap();
        prop_assert_eq!(ids.len(), seeds.len());
        for (id, s) in ids.iter().zip(&seeds) {
            prop_assert_eq!(&id.fingerprint, &fingerprint(*s));
        }
        heimdall_testkit::assert_no_canary(&format!("{ids:?}"));
    }

    /// A single changed byte in the outer grammar never makes the parser read past
    /// the reply or return another key's fingerprint unnoticed: either it fails, or
    /// every listed fingerprint is that of its listed blob.
    #[test]
    fn mutated_answers_stay_consistent(seeds in proptest::collection::vec(any::<u8>(), 1..8),
                                       at in any::<prop::sample::Index>(),
                                       to in any::<u8>()) {
        let mut body = answer(&seeds.iter().map(|s| blob(*s)).collect::<Vec<_>>(), b"c");
        let i = at.index(body.len());
        body[i] = to;
        if let Ok(ids) = parse_reply(&body, MAX_IDENTITIES) {
            for id in ids {
                let again = identity_of_blob(&id.public_blob).unwrap();
                prop_assert_eq!(again.fingerprint, id.fingerprint);
            }
        }
    }
}

/// Socket-level cases: a scripted agent on a Unix socket in a scratch directory
/// this test creates (removed when the test ends, pass or fail).
#[cfg(unix)]
mod unix_socket {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use heimdall_ipc::agent_client::{
        AgentClientError, AgentLocator, ClientBounds, REQUEST_IDENTITIES_FRAME, ServerPrincipal,
        list_identities,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::Notify;

    use super::{answer, blob, fingerprint, framed};

    /// What the scripted agent does after reading the request.
    #[derive(Clone)]
    enum Script {
        /// Write these bytes, then wait for the client to close.
        Reply(Vec<u8>),
        /// Write these bytes one at a time, `gap` apart.
        Drip(Vec<u8>, Duration),
        /// Never answer.
        Hold,
    }

    /// Everything the scripted agent saw on its one connection.
    #[derive(Default)]
    struct Seen {
        /// Bytes received, in order (the request and anything after it).
        received: Vec<u8>,
        /// Whether the client closed the connection.
        closed: bool,
    }

    struct Scripted {
        _dir: tempfile::TempDir,
        path: PathBuf,
        seen: Arc<Mutex<Seen>>,
        requested: Arc<Notify>,
        closed: Arc<Notify>,
    }

    fn start(script: Script) -> Scripted {
        let dir = tempfile::Builder::new().prefix("hm-u6-").tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let requested = Arc::new(Notify::new());
        let closed = Arc::new(Notify::new());
        let (seen2, requested2, closed2) = (seen.clone(), requested.clone(), closed.clone());
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0u8; 5];
            if s.read_exact(&mut request).await.is_ok() {
                seen2.lock().unwrap().received.extend_from_slice(&request);
                requested2.notify_one();
                match script {
                    Script::Reply(bytes) => {
                        let _ = s.write_all(&bytes).await;
                    }
                    Script::Drip(bytes, gap) => {
                        for b in bytes {
                            if s.write_all(&[b]).await.is_err() {
                                break;
                            }
                            tokio::time::sleep(gap).await;
                        }
                    }
                    Script::Hold => {}
                }
            }
            let mut rest = [0u8; 256];
            loop {
                match s.read(&mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen2.lock().unwrap().received.extend_from_slice(&rest[..n]),
                }
            }
            seen2.lock().unwrap().closed = true;
            closed2.notify_one();
        });
        Scripted {
            _dir: dir,
            path,
            seen,
            requested,
            closed,
        }
    }

    fn locator(s: &Scripted) -> AgentLocator {
        AgentLocator::UnixSocket(s.path.clone())
    }

    #[tokio::test]
    async fn one_request_over_a_real_socket_and_the_connection_closes() {
        let agent = start(Script::Reply(framed(&answer(&[blob(1), blob(2)], b"c"))));
        let listing = list_identities(&locator(&agent), &ClientBounds::default())
            .await
            .unwrap();
        assert_eq!(listing.server, ServerPrincipal::CurrentUser);
        let fps: Vec<_> = listing
            .identities
            .iter()
            .map(|i| i.fingerprint.clone())
            .collect();
        assert_eq!(fps, vec![fingerprint(1), fingerprint(2)]);
        tokio::time::timeout(Duration::from_secs(2), agent.closed.notified())
            .await
            .unwrap();
        let seen = agent.seen.lock().unwrap();
        assert!(seen.closed);
        assert_eq!(
            seen.received, REQUEST_IDENTITIES_FRAME,
            "nothing but one request"
        );
    }

    #[tokio::test]
    async fn a_slow_loris_reply_ends_at_the_bound() {
        let reply = framed(&answer(&[blob(1)], b"c"));
        let agent = start(Script::Drip(reply, Duration::from_millis(50)));
        let bound = Duration::from_millis(300);
        let started = Instant::now();
        let r = list_identities(
            &locator(&agent),
            &ClientBounds {
                timeout: bound,
                ..ClientBounds::default()
            },
        )
        .await;
        let took = started.elapsed();
        assert_eq!(r, Err(AgentClientError::Timeout));
        // Generous upper margin: the bound ends the call, a loaded host only delays it.
        assert!(
            took >= bound && took < bound + Duration::from_secs(3),
            "took {took:?}"
        );
        tokio::time::timeout(Duration::from_secs(2), agent.closed.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_silent_agent_ends_at_the_default_bound() {
        let agent = start(Script::Hold);
        let started = Instant::now();
        let r = list_identities(&locator(&agent), &ClientBounds::default()).await;
        let took = started.elapsed();
        assert_eq!(r, Err(AgentClientError::Timeout));
        assert!(
            took >= Duration::from_secs(2) && took < Duration::from_secs(6),
            "took {took:?}"
        );
    }

    #[tokio::test]
    async fn dropping_the_listing_closes_the_connection_and_spawns_nothing() {
        let agent = start(Script::Hold);
        let tasks_before = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let loc = locator(&agent);
        let bounds = ClientBounds::default();
        let listing = list_identities(&loc, &bounds);
        tokio::select! {
            _ = listing => panic!("a held agent cannot complete the listing"),
            () = agent.requested.notified() => {}
        }
        // The listing future is dropped here, mid-wait for the reply.
        tokio::time::timeout(Duration::from_secs(2), agent.closed.notified())
            .await
            .expect("the dropped listing closed its connection");
        let seen = agent.seen.lock().unwrap();
        assert_eq!(
            seen.received, REQUEST_IDENTITIES_FRAME,
            "nothing after the drop"
        );
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            tasks_before - 1,
            "only the scripted agent's own task existed, and it ended"
        );
    }

    #[tokio::test]
    async fn absent_and_non_socket_endpoints_are_refused_without_contact() {
        let dir = tempfile::Builder::new().prefix("hm-u6-").tempdir().unwrap();
        let absent = AgentLocator::UnixSocket(dir.path().join("none.sock"));
        assert_eq!(
            list_identities(&absent, &ClientBounds::default()).await,
            Err(AgentClientError::NotFound)
        );
        let file = dir.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let r = list_identities(&AgentLocator::UnixSocket(file), &ClientBounds::default()).await;
        assert!(matches!(r, Err(AgentClientError::Refused(_))), "{r:?}");
        let pipe = AgentLocator::NamedPipe("openssh-ssh-agent".into());
        assert!(matches!(
            list_identities(&pipe, &ClientBounds::default()).await,
            Err(AgentClientError::Refused(_))
        ));
    }
}
