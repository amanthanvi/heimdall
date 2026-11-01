//! Signing-endpoint framer: adversarial frames (M01-U7; plan §6.3 A29; ADR-0006
//! §2.6; `prototypes/rust/REPORT.md` §4 crafted-frame corpus, ported to the
//! server side).
//!
//! Cargo test target `adversarial_agent_frames` hosted by `heimdall-ipc` (review
//! F09 convention). It drives the framer through the public `heimdall_ipc::signing`
//! API plus its `#[doc(hidden)]` pieces (`serve_with_idle`, `identities_frame`,
//! `sign_response_frame`, `parse_sign_request`); every test runs against in-memory
//! duplex streams with synthetic, public-format fixture blobs (no real keys).
//! Interoperability is checked by encoding requests and decoding answers with
//! `ssh_agent_lib::proto`, an independent implementation of the protocol. Idle
//! timeouts run in paused virtual time (tokio `test-util`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES;
use heimdall_ipc::signing::{
    AllowedRequest, IDLE_TIMEOUT_MS, MAX_IDENTITIES, NoIdentities, Signer, SigningRefusal,
    classify, empty_identities_frame, failure_frame, identities_frame, parse_sign_request, serve,
    serve_with_idle, sign_response_frame,
};
use heimdall_testkit::CANARY_PREFIX;
use proptest::prelude::*;
use ssh_agent_lib::proto::{PublicCredential, Request, Response, SignRequest};
use ssh_encoding::{Decode, Encode};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// `heimdall_testkit::assert_no_canary` over raw bytes (ASCII canaries survive
/// the lossy conversion intact).
fn assert_no_canary(output: &[u8]) {
    heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(output));
}

fn synthetic_canary() -> String {
    // Built per run; never committed as a value.
    format!("{CANARY_PREFIX}{:x}", std::process::id())
}

/// Independent reader for one draft-miller `string` (u32 length + bytes): returns
/// the string and the rest, or `None` on overrun. Deliberately not the library's
/// own reader, so the answer is checked against a second implementation.
fn read_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = buf.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    (len <= rest.len()).then(|| rest.split_at(len))
}

/// `(key_blob, data, flags)` as the signer received them.
type SeenSign = (Vec<u8>, Vec<u8>, u32);

/// Fixture signer: scripted identities and signature, records what it saw.
#[derive(Default)]
struct ScriptedSigner {
    identities: Vec<(Vec<u8>, String)>,
    signature: Option<Vec<u8>>,
    seen: Mutex<Vec<SeenSign>>,
}

#[async_trait::async_trait]
impl Signer for ScriptedSigner {
    async fn identities(&self) -> Vec<(Vec<u8>, String)> {
        self.identities.clone()
    }
    async fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .push((key_blob.to_vec(), data.to_vec(), flags));
        self.signature.clone()
    }
}

/// A public-format ed25519 key blob over synthetic bytes (not a real key).
fn ed25519_blob(i: u8) -> (KeyData, Vec<u8>) {
    let kd = KeyData::Ed25519(Ed25519PublicKey([i; 32]));
    let blob = enc(&kd);
    (kd, blob)
}

fn enc<T: Encode>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out).unwrap();
    out
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn split_frames(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert!(len <= MAX_SIGNING_FRAME_BYTES, "server answer above limit");
        assert!(bytes.len() >= 4 + len, "server answer truncated");
        out.push(bytes[4..4 + len].to_vec());
        bytes = &bytes[4 + len..];
    }
    assert!(bytes.is_empty(), "trailing partial answer");
    out
}

/// Write `input`, close our write half, collect everything the server sends
/// until it closes; returns the server's result, the bytes and the elapsed time.
async fn exchange(
    input: &[u8],
    signer: Arc<dyn Signer>,
    idle: Duration,
) -> (std::io::Result<()>, Vec<u8>, Duration) {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let shutdown = CancellationToken::new();
    let start = Instant::now();
    let srv = serve_with_idle(server, signer, shutdown, idle);
    let cli = async {
        // The server may close early (oversize); write errors are expected then.
        let _ = client.write_all(input).await;
        let _ = client.shutdown().await;
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        out
    };
    let (res, out) = tokio::join!(srv, cli);
    assert_no_canary(&out);
    if let Err(e) = &res {
        assert_no_canary(format!("{e} {e:?}").as_bytes());
    }
    (res, out, start.elapsed())
}

const IDLE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn m01_default_endpoint_lists_nothing_and_refuses_signing() {
    let (kd, _) = ed25519_blob(1);
    let ask = framed(&enc(&Request::RequestIdentities));
    let sign = framed(&enc(&Request::SignRequest(SignRequest {
        credential: PublicCredential::Key(kd),
        data: b"session data".to_vec(),
        flags: 0,
    })));
    let input = [ask, sign].concat();
    let (res, out, _) = exchange(&input, Arc::new(NoIdentities), IDLE).await;
    res.unwrap();
    let frames = split_frames(&out);
    assert_eq!(frames.len(), 2);
    assert_eq!(&out[..9], &empty_identities_frame());
    assert_eq!(
        Response::decode(&mut frames[0].as_slice()).unwrap(),
        Response::IdentitiesAnswer(vec![])
    );
    assert_eq!(&out[9..], &failure_frame());
}

#[tokio::test]
async fn sixty_fifth_identity_is_never_listed() {
    let identities: Vec<(Vec<u8>, String)> = (0..65u8)
        .map(|i| (ed25519_blob(i).1, format!("fixture-{i}")))
        .collect();
    let signer = Arc::new(ScriptedSigner {
        identities,
        ..Default::default()
    });
    let (res, out, _) = exchange(&framed(&[11]), signer, IDLE).await;
    res.unwrap();
    let frames = split_frames(&out);
    assert_eq!(frames.len(), 1);
    let Response::IdentitiesAnswer(ids) = Response::decode(&mut frames[0].as_slice()).unwrap()
    else {
        panic!("not an identities answer")
    };
    assert_eq!(ids.len(), MAX_IDENTITIES);
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(id.comment, format!("fixture-{i}"));
    }
    assert!(!String::from_utf8_lossy(&out).contains("fixture-64"));
}

#[test]
fn identities_answer_never_exceeds_the_frame_limit() {
    // 64 opaque 8 KiB blobs would need 512 KiB; the answer stops before 256 KiB.
    let identities: Vec<(Vec<u8>, String)> = (0..64u8)
        .map(|i| (vec![i; 8 << 10], format!("big-{i}")))
        .collect();
    let out = identities_frame(&identities);
    let frames = split_frames(&out);
    assert_eq!(frames.len(), 1);
    let body = &frames[0];
    assert_eq!(body[0], 12);
    let n = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert!(n > 0 && n < 64, "listed {n}");
    let mut rest = &body[5..];
    for i in 0..n {
        let (blob, after_blob) = read_string(rest).unwrap();
        let (comment, after_comment) = read_string(after_blob).unwrap();
        assert_eq!(blob, vec![i as u8; 8 << 10].as_slice());
        assert_eq!(comment, format!("big-{i}").as_bytes());
        rest = after_comment;
    }
    assert!(
        rest.is_empty(),
        "trailing bytes after the listed identities"
    );
    assert!(out.len() <= 4 + MAX_SIGNING_FRAME_BYTES);
}

#[tokio::test]
async fn sign_request_reaches_the_signer_verbatim_and_answer_interoperates() {
    let (kd, blob) = ed25519_blob(9);
    let sig = ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, vec![7u8; 64]).unwrap();
    let signer = Arc::new(ScriptedSigner {
        signature: Some(enc(&sig)),
        ..Default::default()
    });
    let req = Request::SignRequest(SignRequest {
        credential: PublicCredential::Key(kd),
        data: b"to be signed".to_vec(),
        flags: 4,
    });
    let (res, out, _) = exchange(&framed(&enc(&req)), signer.clone(), IDLE).await;
    res.unwrap();
    let frames = split_frames(&out);
    assert_eq!(
        Response::decode(&mut frames[0].as_slice()).unwrap(),
        Response::SignResponse(sig)
    );
    let seen = signer.seen.lock().unwrap().clone();
    assert_eq!(seen, vec![(blob, b"to be signed".to_vec(), 4)]);
}

#[test]
fn oversize_signature_becomes_failure() {
    assert!(sign_response_frame(&vec![0u8; MAX_SIGNING_FRAME_BYTES]).is_none());
    assert!(sign_response_frame(&[1, 2, 3]).is_some());
}

#[tokio::test]
async fn oversize_zero_length_and_truncated_frames_close_without_reply() {
    let cases: Vec<(&str, Vec<u8>, std::io::ErrorKind)> = vec![
        (
            "max+1",
            ((MAX_SIGNING_FRAME_BYTES + 1) as u32)
                .to_be_bytes()
                .to_vec(),
            std::io::ErrorKind::InvalidData,
        ),
        (
            "u32::MAX",
            [0xFF, 0xFF, 0xFF, 0xFF, 11].to_vec(),
            std::io::ErrorKind::InvalidData,
        ),
        (
            "zero",
            [0, 0, 0, 0, 11].to_vec(),
            std::io::ErrorKind::InvalidData,
        ),
        (
            "short header",
            [0, 0].to_vec(),
            std::io::ErrorKind::UnexpectedEof,
        ),
        (
            "short body",
            [0, 0, 0, 10, 13, 0, 0].to_vec(),
            std::io::ErrorKind::UnexpectedEof,
        ),
    ];
    for (name, input, kind) in cases {
        let (res, out, elapsed) = exchange(&input, Arc::new(NoIdentities), IDLE).await;
        let err = res.expect_err(name);
        assert_eq!(err.kind(), kind, "{name}");
        assert!(out.is_empty(), "{name}: no reply expected");
        // Refused from the header alone: no waiting for a body that never comes.
        assert!(elapsed < Duration::from_secs(2), "{name}: {elapsed:?}");
    }
}

#[tokio::test]
async fn a_valid_frame_after_an_oversize_header_is_never_read() {
    let mut input = (u32::MAX).to_be_bytes().to_vec();
    input.extend_from_slice(&framed(&[11]));
    let (res, out, _) = exchange(&input, Arc::new(NoIdentities), IDLE).await;
    assert!(res.is_err());
    assert!(out.is_empty());
}

#[tokio::test]
async fn disallowed_types_get_failure_and_the_connection_stays_usable() {
    let mut input = Vec::new();
    // add identity (17) with junk that would be private-key material: never parsed.
    input.extend(framed(&[
        17, 0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a',
    ]));
    for t in [18u8, 19, 20, 21, 22, 23, 25, 26] {
        input.extend(framed(&[t, 0, 0, 0, 0]));
    }
    let mut query = vec![27, 0, 0, 0, 5];
    query.extend_from_slice(b"query");
    input.extend(framed(&query));
    let mut bind = vec![27, 0, 0, 0, 24];
    bind.extend_from_slice(b"session-bind@openssh.com");
    input.extend(framed(&bind));
    input.extend(framed(&[11]));
    let signer = Arc::new(ScriptedSigner::default());
    let (res, out, _) = exchange(&input, signer.clone(), IDLE).await;
    res.unwrap();
    let frames = split_frames(&out);
    assert_eq!(frames.len(), 12);
    for f in &frames[..11] {
        assert_eq!(f.as_slice(), &[5]);
    }
    assert_eq!(frames[11].as_slice(), &empty_identities_frame()[4..]);
    assert!(signer.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn control_bytes_on_the_signing_endpoint_get_failure_and_no_json_parse() {
    // A real control hello (as the control client would send it), carrying a
    // synthetic canary in client metadata.
    let canary = synthetic_canary();
    let hello = heimdall_contract::ipc::ClientMessage::Hello(heimdall_contract::ipc::ClientHello {
        protocol: heimdall_contract::PROTOCOL_VERSION,
        schema_version: heimdall_contract::SchemaVersion::current(),
        client: heimdall_contract::ipc::PeerInfo {
            name: canary.clone(),
            version: "0".into(),
        },
        capabilities: heimdall_ipc::session::server_capabilities(),
        required: Default::default(),
        interaction: heimdall_contract::request::InteractionMode::NonInteractive,
    });
    let control_frame =
        heimdall_ipc::frame::encode_frame(&hello, heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES)
            .unwrap();
    assert_eq!(control_frame[4], b'{');
    // `{` (0x7b = 123) is not an agent type: classified, refused, never parsed.
    assert_eq!(
        classify(&control_frame[4..]),
        Err(SigningRefusal::NotPermitted(b'{'))
    );
    let mut input = control_frame;
    input.extend(framed(&[11]));
    let (res, out, _) = exchange(&input, Arc::new(NoIdentities), IDLE).await;
    res.unwrap();
    assert_eq!(
        out,
        [
            failure_frame().as_slice(),
            empty_identities_frame().as_slice()
        ]
        .concat()
    );
    assert_no_canary(&out);

    // A control-sized frame (above the signing limit) closes the connection.
    let big = serde_json::json!({ "type": "request", "pad": "x".repeat(300 << 10) });
    let big =
        heimdall_ipc::frame::encode_frame(&big, heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES)
            .unwrap();
    let (res, out, _) = exchange(&big, Arc::new(NoIdentities), IDLE).await;
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    assert!(out.is_empty());
}

/// REPORT.md §4 corpus (nkeys > 1024, string overrun, trailing bytes, truncation,
/// wrong type), ported: each well-framed crafted message gets `SSH_AGENT_FAILURE`
/// and never reaches the signer.
#[tokio::test]
async fn report_section4_crafted_frame_corpus() {
    let (_, blob) = ed25519_blob(3);
    let mut corpus: Vec<(&str, Vec<u8>)> = Vec::new();

    // An identities *answer* claiming 1025 keys, sent to the server.
    let mut nkeys = vec![12];
    nkeys.extend_from_slice(&1025u32.to_be_bytes());
    corpus.push(("nkeys>1024 answer sent to server", nkeys));

    // Sign request whose key-blob length overruns the frame.
    let mut overrun = vec![13];
    overrun.extend_from_slice(&(blob.len() as u32 + 1000).to_be_bytes());
    overrun.extend_from_slice(&blob);
    corpus.push(("key blob string overrun", overrun));

    // Sign request whose data length is u32::MAX.
    let mut huge = vec![13];
    huge.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    huge.extend_from_slice(&blob);
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    corpus.push(("data string length u32::MAX", huge));

    // Well-formed sign request plus trailing bytes.
    let mut trailing = vec![13];
    trailing.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    trailing.extend_from_slice(&blob);
    trailing.extend_from_slice(&3u32.to_be_bytes());
    trailing.extend_from_slice(b"abc");
    trailing.extend_from_slice(&0u32.to_be_bytes());
    trailing.extend_from_slice(b"junk");
    corpus.push(("sign request trailing bytes", trailing));

    // Sign request missing its flags (truncated inside the message).
    let mut noflags = vec![13];
    noflags.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    noflags.extend_from_slice(&blob);
    noflags.extend_from_slice(&0u32.to_be_bytes());
    corpus.push(("sign request missing flags", noflags));

    corpus.push(("sign request without body", vec![13]));
    corpus.push(("request identities with trailing bytes", vec![11, 0]));
    corpus.push(("extension name overrun", vec![27, 0, 0, 0, 200, b's']));
    corpus.push(("extension without name", vec![27, 0]));
    corpus.push(("unknown type", vec![200, 1, 2, 3]));
    corpus.push(("failure frame sent to server", vec![5]));

    let signer = Arc::new(ScriptedSigner {
        signature: Some(vec![1, 2, 3]),
        ..Default::default()
    });
    for (name, body) in corpus {
        let (res, out, _) = exchange(&framed(&body), signer.clone(), IDLE).await;
        res.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(out, failure_frame(), "{name}");
    }
    assert!(signer.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn idle_connection_closes_at_the_idle_timeout() {
    // Short real-time timeout; the production constant runs in virtual time in
    // `public_serve_closes_after_thirty_seconds_idle`.
    let idle = Duration::from_millis(100);
    let (client, server) = tokio::io::duplex(1024);
    let start = Instant::now();
    let res = serve_with_idle(
        server,
        Arc::new(NoIdentities),
        CancellationToken::new(),
        idle,
    )
    .await;
    let elapsed = start.elapsed();
    res.unwrap();
    assert!(
        elapsed >= idle && elapsed < Duration::from_secs(3),
        "{elapsed:?}"
    );
    drop(client);

    // A trickling peer (one header byte, then silence) is cut off as well.
    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(&[0]).await.unwrap();
    let start = Instant::now();
    serve_with_idle(
        server,
        Arc::new(NoIdentities),
        CancellationToken::new(),
        idle,
    )
    .await
    .unwrap();
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(IDLE_TIMEOUT_MS, 30_000);
}

/// The public `serve` with the production 30 s constant, in paused virtual time
/// (tokio `test-util`): closed exactly at the deadline, not before. A trickling
/// peer (header byte, then silence) is cut off at the same deadline.
#[tokio::test(start_paused = true)]
async fn public_serve_closes_after_thirty_seconds_idle() {
    let deadline = Duration::from_millis(IDLE_TIMEOUT_MS);
    let (_client, server) = tokio::io::duplex(1024);
    let start = tokio::time::Instant::now();
    serve(server, Arc::new(NoIdentities), CancellationToken::new())
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= deadline && elapsed < deadline + Duration::from_secs(1),
        "{elapsed:?}"
    );

    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(&[0]).await.unwrap();
    let start = tokio::time::Instant::now();
    serve(server, Arc::new(NoIdentities), CancellationToken::new())
        .await
        .unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= deadline && elapsed < deadline + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn shutdown_closes_promptly() {
    let (_client, server) = tokio::io::duplex(1024);
    let token = CancellationToken::new();
    token.cancel();
    let start = Instant::now();
    serve(server, Arc::new(NoIdentities), token).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

fn crafted_stream() -> impl Strategy<Value = Vec<u8>> {
    let frame = prop_oneof![
        // Arbitrary well-framed bodies with interesting first bytes.
        (
            prop_oneof![Just(11u8), Just(13u8), Just(27u8), any::<u8>()],
            proptest::collection::vec(any::<u8>(), 0..512)
        )
            .prop_map(|(t, mut rest)| {
                rest.insert(0, t);
                framed(&rest)
            }),
        // Headers that lie about the length.
        (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..64)).prop_map(|(n, rest)| {
            let mut v = n.to_be_bytes().to_vec();
            v.extend(rest);
            v
        }),
        // Raw noise.
        proptest::collection::vec(any::<u8>(), 0..256),
    ];
    proptest::collection::vec(frame, 0..6).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Any byte stream: the framer never panics, always terminates, and every
    /// answer is a complete, bounded failure / identities / sign-response frame.
    #[test]
    fn framer_survives_arbitrary_streams(input in crafted_stream()) {
        let signer = Arc::new(ScriptedSigner {
            identities: vec![(ed25519_blob(1).1, "a".into()), (ed25519_blob(2).1, "b".into())],
            signature: Some(vec![9; 16]),
            ..Default::default()
        });
        let (_res, out, _) = rt().block_on(exchange(&input, signer, Duration::from_secs(2)));
        for f in split_frames(&out) {
            prop_assert!(matches!(f.first(), Some(5 | 12 | 14)), "unexpected answer type");
        }
    }

    /// `classify` is total and agrees with the type byte outside extensions.
    #[test]
    fn classify_is_total(payload in proptest::collection::vec(any::<u8>(), 0..64)) {
        let r = classify(&payload);
        match payload.first() {
            None => prop_assert_eq!(r, Err(SigningRefusal::Malformed)),
            Some(11) => prop_assert_eq!(r, Ok(AllowedRequest::RequestIdentities)),
            Some(13) => prop_assert_eq!(r, Ok(AllowedRequest::SignRequest)),
            Some(27) => prop_assert!(r != Ok(AllowedRequest::RequestIdentities)),
            Some(&t) => prop_assert_eq!(r, Err(SigningRefusal::NotPermitted(t))),
        }
    }

    /// Sign-request fields round-trip; every truncation and every trailing
    /// extension is refused.
    #[test]
    fn sign_fields_are_exact(
        blob in proptest::collection::vec(any::<u8>(), 0..128),
        data in proptest::collection::vec(any::<u8>(), 0..128),
        flags in any::<u32>(),
        cut in any::<prop::sample::Index>(),
        extra in proptest::collection::vec(any::<u8>(), 1..8),
    ) {
        let mut body = Vec::new();
        body.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        body.extend_from_slice(&blob);
        body.extend_from_slice(&(data.len() as u32).to_be_bytes());
        body.extend_from_slice(&data);
        body.extend_from_slice(&flags.to_be_bytes());
        let parsed = parse_sign_request(&body).unwrap();
        prop_assert_eq!(parsed.key_blob, blob.as_slice());
        prop_assert_eq!(parsed.data, data.as_slice());
        prop_assert_eq!(parsed.flags, flags);
        let n = cut.index(body.len());
        prop_assert!(parse_sign_request(&body[..n]).is_none());
        let mut longer = body.clone();
        longer.extend(extra);
        prop_assert!(parse_sign_request(&longer).is_none());
    }
}
