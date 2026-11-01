//! Control-endpoint framing under adversarial input (M01-U6; plan §6.3 A29
//! "parsers bounded"; ADR-0006 §2.2).
//!
//! Compiled as a unit-test module of `heimdall_ipc::session` (`#[path]` include).
//! Fuzz-style: `proptest` byte strategies (malformed, truncated, oversized and
//! mutated frames) against the pure `decode_frame`, the streaming
//! `BoundedFrameCodec`, and a full `ControlConnection::serve` over an in-memory
//! duplex stream. Reproduce a failure with `PROPTEST_RNG_SEED=<seed>`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::event::{Cursor, Event, EventFilter};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, PeerInfo,
    PrincipalInfo, ServerMessage,
};
use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
use heimdall_contract::{Envelope, ErrorData, PROTOCOL_VERSION, SchemaVersion};
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::frame::{FrameError, decode_frame, encode_frame};

/// Same rule as `heimdall_testkit::assert_no_canary` (testkit is not a
/// dev-dependency of this crate; see the M01-U6U7 hand-off escalation).
fn assert_no_canary(output: &[u8]) {
    let needle = b"HEIMDALL_CANARY_";
    assert!(
        !output.windows(needle.len()).any(|w| w == needle),
        "canary leaked into output"
    );
}

fn canary() -> String {
    format!("HEIMDALL_CANARY_{:x}", std::process::id())
}

struct EchoDispatcher {
    events: broadcast::Sender<Arc<Event>>,
}

#[async_trait::async_trait]
impl Dispatcher for EchoDispatcher {
    async fn dispatch(
        &self,
        _principal: &PrincipalInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({ "kind": request.kind() }))
    }
    async fn subscribe(
        &self,
        _principal: &PrincipalInfo,
        _filter: EventFilter,
        _from: Option<Cursor>,
    ) -> Result<(Cursor, broadcast::Receiver<Arc<Event>>), Box<Envelope<ErrorData>>> {
        Ok((Cursor("c0".into()), self.events.subscribe()))
    }
}

fn hello(name: &str) -> Vec<u8> {
    encode_frame(
        &ClientMessage::Hello(ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client: PeerInfo {
                name: name.into(),
                version: "0".into(),
            },
            capabilities: server_capabilities(),
            required: BTreeSet::new(),
        }),
        MAX_HELLO_FRAME_BYTES,
    )
    .unwrap()
}

fn request_frame(seq: u64) -> Vec<u8> {
    encode_frame(
        &ClientMessage::Request {
            seq,
            request: Request::Inspect(InspectRequest {
                subject: InspectSubject::Capabilities,
                preview: None,
            }),
        },
        MAX_CONTROL_FRAME_BYTES,
    )
    .unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

/// Feed `input` to a served connection, close the write side, and return the
/// server result plus all frames it sent (each must decode as `ServerMessage`).
async fn drive(input: Vec<u8>) -> (Result<(), FrameError>, Vec<ServerMessage>) {
    let (mut client, server) = tokio::io::duplex(4 << 20);
    let dispatcher = EchoDispatcher {
        events: broadcast::channel(8).0,
    };
    let limits = ConnectionLimits {
        hello_timeout_ms: 2_000,
        ..ConnectionLimits::default()
    };
    let conn = ControlConnection::new(server, limits).with_server_identity(
        EnvironmentId::from_random_bytes([1; 16]),
        PeerInfo {
            name: "heimdall".into(),
            version: "test".into(),
        },
    );
    let srv = conn.serve(
        PrincipalInfo::OsUserUnix { uid: 1 },
        dispatcher,
        CancellationToken::new(),
    );
    let cli = async {
        let _ = client.write_all(&input).await;
        let _ = client.shutdown().await;
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        out
    };
    let (res, out) =
        tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(srv, cli) })
            .await
            .expect("serve did not terminate");
    assert_no_canary(&out);
    if let Err(e) = &res {
        assert_no_canary(format!("{e} {e:?}").as_bytes());
    }
    let mut frames = Vec::new();
    let mut rest = out.as_slice();
    loop {
        match decode_frame::<ServerMessage>(rest, MAX_CONTROL_FRAME_BYTES) {
            Ok(Some((m, used))) => {
                frames.push(m);
                rest = &rest[used..];
            }
            Ok(None) => break,
            Err(e) => panic!("server sent an undecodable frame: {e}"),
        }
    }
    assert!(rest.is_empty(), "server sent a partial frame");
    (res, frames)
}

#[test]
fn codec_refuses_oversize_from_the_header_without_reserving() {
    let mut codec = BoundedFrameCodec::new(1024);
    let mut src = BytesMut::with_capacity(16);
    src.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, b'x']);
    let before = src.capacity();
    match codec.decode(&mut src) {
        Err(FrameError::TooLarge { len, limit }) => {
            assert_eq!(len, u32::MAX as usize);
            assert_eq!(limit, 1024);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(src.capacity(), before, "buffer grew for a refused frame");

    // An accepted length reserves at most the declared size.
    let mut src = BytesMut::new();
    src.extend_from_slice(&1000u32.to_be_bytes());
    assert!(codec.decode(&mut src).unwrap().is_none());
    assert!(src.capacity() >= 1004 && src.capacity() < 4096);

    // Bytes left at EOF are a truncation, not a silent drop.
    let mut src = BytesMut::from(&[0u8, 0, 0, 9, b'{'][..]);
    assert!(matches!(
        codec.decode_eof(&mut src),
        Err(FrameError::Truncated)
    ));
    let mut empty = BytesMut::new();
    assert!(codec.decode_eof(&mut empty).unwrap().is_none());
}

#[test]
fn parse_errors_never_quote_the_input() {
    let c = canary();
    for body in [
        format!("{{\"type\":\"{c}\"}}"),
        format!("{{\"type\":\"request\",\"seq\":\"{c}\"}}"),
        format!("\"{c}"),
        c.clone(),
    ] {
        let e = parse_frame::<ClientMessage>(body.as_bytes()).unwrap_err();
        assert_no_canary(format!("{e} {e:?}").as_bytes());
    }
}

#[test]
fn zero_length_and_wrong_types_after_hello_close_with_goodbye() {
    let mut input = hello("t");
    input.extend_from_slice(&[0, 0, 0, 0]);
    let (res, frames) = rt().block_on(drive(input));
    assert!(matches!(res, Err(FrameError::Json(_))));
    assert!(matches!(frames[0], ServerMessage::Hello(_)));
    assert!(matches!(
        frames[1],
        ServerMessage::Goodbye {
            code: heimdall_contract::Code::UsageError,
            ..
        }
    ));

    // A server message sent by the client is a protocol error.
    let mut input = hello("t");
    input.extend(
        encode_frame(
            &ServerMessage::Goodbye {
                code: heimdall_contract::Code::Ok,
                message: "x".into(),
            },
            MAX_CONTROL_FRAME_BYTES,
        )
        .unwrap(),
    );
    let (res, _) = rt().block_on(drive(input));
    assert!(res.is_err());
}

#[test]
fn many_valid_requests_are_all_answered() {
    let mut input = hello("t");
    for seq in 1..=10 {
        input.extend(request_frame(seq));
    }
    let (res, frames) = rt().block_on(drive(input));
    res.unwrap();
    let answered: BTreeSet<u64> = frames
        .iter()
        .filter_map(|m| match m {
            ServerMessage::Response { in_reply_to, .. } => Some(*in_reply_to),
            _ => None,
        })
        .collect();
    // Each completed dispatch is answered before the next frame is read.
    assert_eq!(answered, (1..=10).collect());
}

/// Fragments a stream adversary might send.
fn piece() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // valid frames
        Just(hello("p")),
        any::<u64>().prop_map(request_frame),
        // valid frame truncated at a random point
        (any::<u64>(), any::<prop::sample::Index>()).prop_map(|(s, i)| {
            let f = request_frame(s);
            let n = i.index(f.len());
            f[..n].to_vec()
        }),
        // valid frame with one byte flipped
        (any::<u64>(), any::<prop::sample::Index>(), any::<u8>()).prop_map(|(s, i, b)| {
            let mut f = request_frame(s);
            let n = i.index(f.len());
            f[n] ^= b | 1;
            f
        }),
        // lying or oversize headers
        any::<u32>().prop_map(|n| n.to_be_bytes().to_vec()),
        Just(u32::MAX.to_be_bytes().to_vec()),
        Just(
            ((MAX_CONTROL_FRAME_BYTES + 1) as u32)
                .to_be_bytes()
                .to_vec()
        ),
        // a frame with arbitrary (often non-UTF-8, non-JSON) payload
        proptest::collection::vec(any::<u8>(), 0..256).prop_map(|b| {
            let mut v = (b.len() as u32).to_be_bytes().to_vec();
            v.extend(b);
            v
        }),
        // a JSON frame carrying a canary in an unknown variant
        Just({
            let body = format!("{{\"type\":\"{}\"}}", canary());
            let mut v = (body.len() as u32).to_be_bytes().to_vec();
            v.extend(body.into_bytes());
            v
        }),
        // raw noise
        proptest::collection::vec(any::<u8>(), 0..64),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// A29 corpus: `decode_frame` is total and bounded on arbitrary bytes.
    #[test]
    fn decode_frame_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..2048), limit in 0usize..4096) {
        match decode_frame::<serde_json::Value>(&buf, limit) {
            Ok(None) => {
                if buf.len() >= 4 {
                    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    prop_assert!(len <= limit && buf.len() < 4 + len);
                }
            }
            Ok(Some((_, used))) => {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                prop_assert_eq!(used, 4 + len);
                prop_assert!(len <= limit);
            }
            Err(FrameError::TooLarge { len, limit: l }) => prop_assert!(len > l),
            Err(FrameError::Json(_)) => {}
            Err(other) => prop_assert!(false, "unexpected {other:?}"),
        }
    }

    /// The streaming codec agrees with `decode_frame` however the bytes are chunked.
    #[test]
    fn codec_matches_pure_decoder(pieces in proptest::collection::vec(piece(), 0..6), chunk in 1usize..64) {
        let stream: Vec<u8> = pieces.concat();
        let mut codec = BoundedFrameCodec::new(MAX_CONTROL_FRAME_BYTES);
        let mut src = BytesMut::new();
        let mut from_codec: Vec<Vec<u8>> = Vec::new();
        let mut codec_err = false;
        'outer: for part in stream.chunks(chunk) {
            src.extend_from_slice(part);
            loop {
                match codec.decode(&mut src) {
                    Ok(Some(f)) => from_codec.push(f.to_vec()),
                    Ok(None) => break,
                    Err(_) => { codec_err = true; break 'outer; }
                }
            }
        }
        // Pure reference: walk headers.
        let mut rest = stream.as_slice();
        let mut reference: Vec<Vec<u8>> = Vec::new();
        let mut ref_err = false;
        while rest.len() >= 4 {
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if len > MAX_CONTROL_FRAME_BYTES { ref_err = true; break; }
            if rest.len() < 4 + len { break; }
            reference.push(rest[4..4 + len].to_vec());
            rest = &rest[4 + len..];
        }
        prop_assert_eq!(from_codec, reference);
        prop_assert_eq!(codec_err, ref_err);
    }

    /// Full session under adversarial streams: never panics, always terminates,
    /// every server frame is well formed, and nothing echoes a canary.
    #[test]
    fn serve_survives_adversarial_streams(start_with_hello in any::<bool>(), pieces in proptest::collection::vec(piece(), 0..8)) {
        let mut input = if start_with_hello { hello(&canary()) } else { Vec::new() };
        input.extend(pieces.concat());
        let (_res, frames) = rt().block_on(drive(input));
        if let Some(first) = frames.first() {
            prop_assert!(matches!(first, ServerMessage::Hello(_) | ServerMessage::Reject(_)));
        }
    }

    /// Client messages round-trip through the framing for arbitrary sequence numbers.
    #[test]
    fn client_messages_round_trip(seq in any::<u64>(), sub in any::<u64>()) {
        for msg in [
            ClientMessage::Unsubscribe { seq, subscription: sub },
            ClientMessage::Subscribe { seq, filter: EventFilter::default(), from_cursor: Some(Cursor("c".into())) },
        ] {
            let bytes = encode_frame(&msg, MAX_CONTROL_FRAME_BYTES).unwrap();
            let (back, used): (ClientMessage, usize) =
                decode_frame(&bytes, MAX_CONTROL_FRAME_BYTES).unwrap().unwrap();
            prop_assert_eq!(used, bytes.len());
            prop_assert_eq!(back, msg);
        }
    }
}
