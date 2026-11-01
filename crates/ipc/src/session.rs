//! Control-endpoint sessions: hello negotiation, attendance, request dispatch,
//! subscriptions (ADR-0006 §2.3–§2.5, §3.1, §8).
//!
//! Wire rules enforced here (both sides share [`crate::frame`]):
//!
//! * The first frame each way is the hello; it is limited to
//!   `MAX_HELLO_FRAME_BYTES` and must arrive within `hello_timeout_ms`, otherwise
//!   the connection is closed. A malformed or wrong first frame gets
//!   `Reject(USAGE_ERROR)` and a close; a negotiation failure gets
//!   `Reject(SCHEMA_UNSUPPORTED)` and a close. `required` must be a subset of the
//!   **negotiated** set (server offer ∩ client `capabilities`), so a hello cannot
//!   require what it did not offer to speak (review F10).
//! * Afterwards frames are limited to `MAX_CONTROL_FRAME_BYTES`. A declared
//!   length above the limit is refused from the 4-byte header alone, before any
//!   buffer for the body is reserved. Malformed frames end the connection with
//!   `Goodbye(USAGE_ERROR)`.
//! * At most `max_inflight` requests (and pending subscribes) run concurrently;
//!   the excess request is answered `BACKPRESSURE` with `retry_after_ms` and is
//!   not dispatched. At most `max_subscriptions` subscriptions exist; the excess
//!   subscribe is answered `BACKPRESSURE`.
//! * When the peer disconnects, outstanding dispatch futures are dropped (the
//!   application layer is cancellation-safe: a dropped caller never changes
//!   operation state, plan §6.3 #7); on `shutdown` the server sends
//!   `Goodbye(SERVICE_UNAVAILABLE)` and closes.
//!
//! **Attendance** (ADR-0006 §2.3, §3.1; review F03). The hello's `interaction`
//! is recorded in the session's [`SessionInfo`]. `Attend` on a session that
//! declared `interactive` marks it attended and is answered `OK {"attended":
//! true}`; on any other session it is answered `INTERACTION_REQUIRED` and changes
//! nothing. A request for which `Request::requires_attended_session()` holds
//! (`decide`, `confirm_time`) on an unattended session is answered
//! `INTERACTION_REQUIRED` and never dispatched; the application layer checks again
//! (defence in depth). Widening policy actions (`resume`, `clear_cutoff`) are
//! dispatched on every session: the application always answers them with a
//! server-issued decision record (`APPROVAL_REQUIRED` attended,
//! `INTERACTION_REQUIRED` unattended, both with `next.decision_ref`) and never
//! executes them on dispatch; only `Decide` on an attended session completes them
//! (ADR-0006 §3.1, §13.4 N04). This module never executes anything; attendance is
//! not a confirmation of any particular action. Attendance is a session
//! property set by the runtime when it accepts `Attend`; it is never a request
//! field, and every dispatch receives a snapshot of it taken when the request
//! frame was read. **Disclosed limit:** a process running as the same OS user can
//! open an interactive session and send `Attend` itself, imitating the terminal
//! flow (spec §13.2, §14.2). Attendance is a boundary against non-interactive
//! agents and paired clients, not isolation from same-user code.
//!
//! **Subscriptions** (ADR-0006 §8; review F08). [`Dispatcher::subscribe`] returns
//! a [`SubscriptionStart`]: the live receiver (created before the boundary was
//! read), the boundary as the reader's cursor and as a neutral sequence, and either
//! a consistent snapshot or the retained backlog after the client's cursor. The
//! session replies `Subscribed { cursor, snapshot }`, then sends every backlog
//! event (already cursor-personalized by the dispatcher), then live events with
//! `seq > boundary_seq` only, each personalized by the subscription's `cursor_for`
//! at delivery. Overlap between the boundary read and the live receiver is
//! therefore deduplicated here. A subscriber that lags its bounded broadcast
//! buffer gets exactly one `ResyncRequired` event per lag episode; the backlog is
//! dropped, never buffered without bound. The backlog itself is bounded by the
//! dispatcher (store retention and paging), not by this module.
//!
//! **Oversized events** (ADR-0006 §8, §13.4 N03). An event whose frame exceeds the
//! control frame limit is never delivered: `send_event` reports
//! [`Delivery::Replaced`], the subscription's cursor stays at the last event
//! actually delivered, one `ResyncRequired` event carrying that cursor (payload
//! `reason: "event_too_large"`, `subscription_ended: true`) is sent, and the
//! subscription **ends**. Recovery is a fresh snapshot (subscribe without a
//! cursor); resubscribing from the carried cursor meets the same event again.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::{SinkExt, StreamExt};
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction};
use heimdall_contract::event::{Cursor, Event, EventFilter, EventType, MAX_CURSOR_LEN, Snapshot};
use heimdall_contract::ids::{EnvironmentId, EventId};
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, EVENT_BUFFER_PER_SUBSCRIPTION, HELLO_TIMEOUT_MS,
    MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, MAX_SUBSCRIPTIONS_PER_CONNECTION, PeerInfo,
    PrincipalInfo, ServerHello, ServerMessage, capability,
};
use heimdall_contract::request::{InteractionMode, Request};
use heimdall_contract::{Code, PROTOCOL_VERSION, SchemaVersion};
use tokio::sync::broadcast;
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tokio_util::sync::CancellationToken;

use crate::frame::{FrameError, encode_frame};

/// Capabilities this build serves.
#[must_use]
pub fn server_capabilities() -> BTreeSet<String> {
    [
        capability::OPERATIONS_V1,
        capability::EVENTS_V1,
        capability::OWNER_POLICY_V1,
        capability::SCHEMA_DISCOVERY_V1,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Negotiate a client hello. Pure: the transport has already authenticated the
/// peer and supplies `principal`.
///
/// The negotiated set is the server offer ∩ the client's `capabilities`; every
/// `required` capability must be in it (ADR-0006 §2.3 rev2, review F10), else
/// `SCHEMA_UNSUPPORTED`. Rejection messages never quote client-supplied strings.
pub fn negotiate(
    hello: &ClientHello,
    principal: PrincipalInfo,
    environment: EnvironmentId,
    server: PeerInfo,
) -> Result<ServerHello, Box<Envelope<ErrorData>>> {
    let reject = |code: Code, message: &str| {
        Box::new(Envelope::failed(
            None,
            ErrorDetail {
                code: code.clone(),
                effect_status: EffectStatus::None,
                retryable: false,
                resource: None,
                next: NextAction::for_code(code),
                message: message.to_owned(),
            },
        ))
    };

    if hello.protocol != PROTOCOL_VERSION {
        return Err(reject(
            Code::SchemaUnsupported,
            "unsupported IPC protocol version",
        ));
    }
    if !hello.schema_version.is_supported() {
        return Err(reject(
            Code::SchemaUnsupported,
            "unsupported schema major version",
        ));
    }
    let offered = server_capabilities();
    let capabilities: BTreeSet<String> =
        offered.intersection(&hello.capabilities).cloned().collect();
    if !hello.required.is_subset(&capabilities) {
        let message = if hello.required.is_subset(&offered) {
            "a required capability is missing from the client's own capabilities"
        } else {
            "a required capability is not available"
        };
        return Err(reject(Code::SchemaUnsupported, message));
    }
    Ok(ServerHello {
        protocol: PROTOCOL_VERSION,
        schema_version: SchemaVersion::current(),
        server,
        capabilities,
        principal,
        environment_id: environment,
    })
}

/// What a [`Dispatcher`] learns about the session a request or subscription came
/// from (ADR-0006 §2.3, §3.1).
///
/// `principal` is what the transport authenticated; `interaction` is what the
/// hello declared; `attended` is set only by the session itself, when it accepts
/// `Attend` on an `interactive` session. None of it is read from request content.
/// Each dispatch gets a copy taken when its frame was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Authenticated OS principal.
    pub principal: PrincipalInfo,
    /// Interaction mode declared in the hello.
    pub interaction: InteractionMode,
    /// Whether the session was marked attended (owner present at the interactive
    /// CLI/TUI flow). Same-user code can imitate that flow (module docs).
    pub attended: bool,
}

/// One live event as published: the neutral store sequence and the event with
/// a not-yet-personalized cursor (the session sets it with `cursor_for`).
#[derive(Debug, Clone, PartialEq)]
pub struct LiveEvent {
    /// Store sequence (monotonic per environment).
    pub seq: u64,
    /// The event; its `cursor` is replaced at delivery.
    pub event: Event,
}

/// What a subscription starts with (ADR-0006 §8; review F08). Same shape as
/// `heimdall_app::events::SubscriptionStart`; the runtime adapts one to the other.
pub struct SubscriptionStart {
    /// Boundary the stream continues after, as the reader's cursor (sent in
    /// `Subscribed.cursor`).
    pub cursor: Cursor,
    /// Highest sequence reflected in `snapshot`/`backlog`; live events with
    /// `seq <= boundary_seq` are duplicates and are not sent.
    pub boundary_seq: u64,
    /// Consistent snapshot taken at the boundary, when the client had no usable
    /// cursor.
    pub snapshot: Option<Snapshot<serde_json::Value>>,
    /// Retained events after the client's cursor up to the boundary, in order and
    /// already cursor-personalized for this reader.
    pub backlog: Vec<Event>,
    /// Live receiver created **before** the boundary was read.
    pub live: broadcast::Receiver<Arc<LiveEvent>>,
    /// Builds this reader's cursor for a live event's sequence.
    pub cursor_for: Arc<dyn Fn(u64) -> Cursor + Send + Sync>,
}

impl std::fmt::Debug for SubscriptionStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionStart")
            .field("boundary_seq", &self.boundary_seq)
            .field("snapshot", &self.snapshot.is_some())
            .field("backlog", &self.backlog.len())
            .finish_non_exhaustive()
    }
}

/// Per-connection bookkeeping limits (ADR-0006 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// In-flight requests.
    pub max_inflight: usize,
    /// Subscriptions.
    pub max_subscriptions: usize,
    /// Hello deadline.
    pub hello_timeout_ms: u64,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_inflight: heimdall_contract::ipc::MAX_INFLIGHT_REQUESTS_PER_CONNECTION,
            max_subscriptions: heimdall_contract::ipc::MAX_SUBSCRIPTIONS_PER_CONNECTION,
            hello_timeout_ms: heimdall_contract::ipc::HELLO_TIMEOUT_MS,
        }
    }
}

/// Bound on one frame write; a peer that stops reading for longer is dropped
/// (slow-reader defence; not a contract limit).
const WRITE_TIMEOUT: Duration = Duration::from_millis(HELLO_TIMEOUT_MS);
/// `retry_after_ms` suggested with a per-connection `BACKPRESSURE` answer.
const BACKPRESSURE_RETRY_AFTER_MS: u64 = 250;
/// Client-side bound on events queued while waiting for a response.
const CLIENT_EVENT_BACKLOG: usize =
    EVENT_BUFFER_PER_SUBSCRIPTION * MAX_SUBSCRIPTIONS_PER_CONNECTION;

/// Length-prefixed frame codec with a hard, switchable limit. The declared length
/// is compared with the limit from the header alone; only an accepted length
/// reserves buffer space. Bytes left at EOF are [`FrameError::Truncated`].
///
/// Public for the `adversarial_ipc_frames` test target only; not a supported API.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct BoundedFrameCodec {
    max: usize,
}

impl BoundedFrameCodec {
    /// Codec refusing frames above `max` bytes.
    #[doc(hidden)]
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self { max }
    }
}

impl Decoder for BoundedFrameCodec {
    type Item = BytesMut;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, FrameError> {
        let Some(header) = src.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if len > self.max {
            return Err(FrameError::TooLarge {
                len,
                limit: self.max,
            });
        }
        let total = 4 + len;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }
        src.advance(4);
        Ok(Some(src.split_to(len)))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, FrameError> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None => Err(FrameError::Truncated),
        }
    }
}

impl Encoder<Bytes> for BoundedFrameCodec {
    type Error = FrameError;

    /// `item` is a complete frame produced by [`encode_frame`].
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), FrameError> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

type Wire<S> = Framed<S, BoundedFrameCodec>;

async fn write_frame<S, T>(wire: &mut Wire<S>, msg: &T, limit: usize) -> Result<(), FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let bytes = encode_frame(msg, limit)?;
    match tokio::time::timeout(WRITE_TIMEOUT, wire.send(Bytes::from(bytes))).await {
        Ok(r) => r,
        Err(_) => Err(FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "peer did not read a frame in time",
        ))),
    }
}

/// Parse one frame body. The error is rebuilt without serde's message, which can
/// quote fragments of the (untrusted, possibly secret-bearing) input; only the
/// error category survives, so logging a returned [`FrameError`] never echoes
/// peer bytes.
///
/// Public for [`crate::frame::decode_frame`] and the test targets; not a
/// supported API.
#[doc(hidden)]
pub fn parse_frame<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(bytes).map_err(|e| {
        let what = match e.classify() {
            serde_json::error::Category::Io => "malformed frame (io)",
            serde_json::error::Category::Syntax => "malformed frame (not JSON or not UTF-8)",
            serde_json::error::Category::Data => "malformed frame (unexpected message shape)",
            serde_json::error::Category::Eof => "malformed frame (truncated JSON)",
        };
        FrameError::Json(<serde_json::Error as serde::de::Error>::custom(what))
    })
}

/// Error envelope with the code table's defaults (ADR-0006 §5).
fn error_envelope(code: Code, effect_status: EffectStatus, message: &str) -> Envelope<ErrorData> {
    let mut next = NextAction::for_code(code.clone());
    if code == Code::Backpressure {
        next.retry_after_ms = Some(BACKPRESSURE_RETRY_AFTER_MS);
    }
    Envelope::failed(
        None,
        ErrorDetail {
            code: code.clone(),
            effect_status,
            retryable: code.retryable(),
            resource: None,
            next,
            message: message.to_owned(),
        },
    )
}

fn to_value_envelope(env: Envelope<ErrorData>) -> Envelope<serde_json::Value> {
    env.map(|d| serde_json::to_value(d).unwrap_or_default())
}

fn response(seq: u64, code: Code, message: &str) -> ServerMessage {
    ServerMessage::Response {
        in_reply_to: seq,
        envelope: to_value_envelope(error_envelope(code, EffectStatus::None, message)),
    }
}

fn goodbye(code: Code, message: &str) -> ServerMessage {
    ServerMessage::Goodbye {
        code,
        message: message.to_owned(),
    }
}

/// An event ID for a session-synthesized `ResyncRequired` event. Uniqueness is
/// all that is needed (consumers deduplicate by it); it is not a secret. The
/// bytes are SipHash outputs under std's per-process random keys (seeded from
/// the OS random source) over a process-wide counter and the wall time, because
/// the IPC crate has no CSPRNG dependency.
fn session_event_id() -> EventId {
    use std::hash::BuildHasher;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let keys = std::collections::hash_map::RandomState::new();
    let a = keys.hash_one((n, t, 0u8));
    let b = keys.hash_one((n, t, 1u8));
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_be_bytes());
    bytes[8..].copy_from_slice(&b.to_be_bytes());
    EventId::from_random_bytes(bytes)
}

/// A `ResyncRequired` event whose cursor is the last position the subscriber
/// was delivered (before the gap): resuming from it never skips the gap.
fn resync_event(environment: &EnvironmentId, cursor: &Cursor, dropped: u64) -> Event {
    resync_event_with(
        environment,
        cursor,
        serde_json::json!({ "reason": "subscriber_lagged", "dropped": dropped }),
    )
}

/// The `ResyncRequired` event sent in place of an oversized event; the
/// subscription ends after it (N03).
fn oversized_resync_event(environment: &EnvironmentId, cursor: &Cursor) -> Event {
    resync_event_with(
        environment,
        cursor,
        serde_json::json!({ "reason": "event_too_large", "subscription_ended": true }),
    )
}

fn resync_event_with(
    environment: &EnvironmentId,
    cursor: &Cursor,
    payload: serde_json::Value,
) -> Event {
    Event {
        schema_version: SchemaVersion::current(),
        event_id: session_event_id(),
        event_type: EventType::ResyncRequired,
        environment_id: environment.clone(),
        operation_id: None,
        resource: None,
        timestamp: heimdall_contract::Timestamp::now(),
        cursor: cursor.clone(),
        payload,
    }
}

fn filter_matches(filter: &EventFilter, event: &Event) -> bool {
    if let Some(op) = &filter.operation_id
        && event.operation_id.as_ref() != Some(op)
    {
        return false;
    }
    filter.types.is_empty() || filter.types.contains(&event.event_type)
}

/// Server side of one control connection. Generic over the stream so Unix and
/// Windows share it; the dispatcher is supplied by the runtime.
#[derive(Debug)]
pub struct ControlConnection<S> {
    stream: S,
    limits: ConnectionLimits,
    identity: Option<(EnvironmentId, PeerInfo)>,
}

enum Done {
    Response {
        seq: u64,
        envelope: Envelope<serde_json::Value>,
    },
    Subscribed {
        seq: u64,
        filter: EventFilter,
        from: Option<Cursor>,
        result: Result<SubscriptionStart, Box<Envelope<ErrorData>>>,
    },
}

type Pending<'a> = Pin<Box<dyn Future<Output = Done> + Send + 'a>>;

struct SubPoll {
    id: u64,
    rx: broadcast::Receiver<Arc<LiveEvent>>,
    result: Result<Arc<LiveEvent>, broadcast::error::RecvError>,
}

type SubFuture = Pin<Box<dyn Future<Output = Option<SubPoll>> + Send>>;

fn next_from(
    id: u64,
    mut rx: broadcast::Receiver<Arc<LiveEvent>>,
    stop: CancellationToken,
) -> SubFuture {
    Box::pin(async move {
        tokio::select! {
            biased;
            () = stop.cancelled() => None,
            result = rx.recv() => Some(SubPoll { id, rx, result }),
        }
    })
}

struct SubState {
    filter: EventFilter,
    /// Last position delivered to (or passed by) this subscriber; the cursor of a
    /// `ResyncRequired` event.
    last_cursor: Cursor,
    /// Live events at or below this sequence were covered by the snapshot/backlog.
    boundary_seq: u64,
    cursor_for: Arc<dyn Fn(u64) -> Cursor + Send + Sync>,
    stop: CancellationToken,
}

/// Whether a reply went out as built or was replaced because it exceeded the
/// frame limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    AsBuilt,
    Replaced,
}

/// Outcome of sending one event frame (ADR-0006 §8, §13.4 N03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// The event went out as built.
    Delivered,
    /// The event exceeded the frame limit and was replaced by a `ResyncRequired`
    /// event at the last delivered cursor; the subscription must end and its
    /// cursor must not advance.
    Replaced,
}

impl<S> ControlConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Wrap an authenticated stream.
    #[must_use]
    pub fn new(stream: S, limits: ConnectionLimits) -> Self {
        Self {
            stream,
            limits,
            identity: None,
        }
    }

    /// Set what the server reports in `ServerHello` (its environment ID and
    /// software). Required before [`ControlConnection::serve`]; without it the
    /// connection is closed with `Goodbye(INTERNAL_ERROR)`.
    ///
    /// Kept as a builder by decision (ADR-0006 §2.1 rev2, wave-1 E13): the runtime
    /// (M01-U8) sets the environment ID and server `PeerInfo` once per listener and
    /// applies them to each accepted connection.
    #[must_use]
    pub fn with_server_identity(mut self, environment_id: EnvironmentId, server: PeerInfo) -> Self {
        self.identity = Some((environment_id, server));
        self
    }

    /// Run the hello exchange, then the request/subscription loop until the peer
    /// closes, a limit trips, or `shutdown` fires. Backpressure on a subscription
    /// emits a `ResyncRequired` event rather than buffering without bound.
    ///
    /// Returns `Ok(())` for orderly ends (peer closed between frames, hello
    /// negotiated-and-rejected, shutdown) and the framing error for protocol
    /// violations (oversize, truncated or malformed frames, hello timeout, write
    /// timeout); in every case the connection is closed when this returns.
    pub async fn serve<D>(
        self,
        principal: PrincipalInfo,
        dispatcher: D,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), crate::frame::FrameError>
    where
        D: Dispatcher,
    {
        let limits = self.limits;
        let mut wire = Framed::new(self.stream, BoundedFrameCodec::new(MAX_HELLO_FRAME_BYTES));

        let Some((environment, server)) = self.identity else {
            let _ = write_frame(
                &mut wire,
                &goodbye(Code::InternalError, "server identity is not configured"),
                MAX_HELLO_FRAME_BYTES,
            )
            .await;
            return Err(FrameError::Io(std::io::Error::other(
                "ControlConnection::serve called without with_server_identity",
            )));
        };

        // ---- hello -------------------------------------------------------
        let hello_wait = Duration::from_millis(limits.hello_timeout_ms);
        let first = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            r = tokio::time::timeout(hello_wait, wire.next()) => r,
        };
        let usage_reject = |message: &str| {
            ServerMessage::Reject(error_envelope(
                Code::UsageError,
                EffectStatus::None,
                message,
            ))
        };
        let frame = match first {
            Err(_elapsed) => {
                return Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no hello within the hello timeout",
                )));
            }
            Ok(None) => return Ok(()),
            Ok(Some(Err(e))) => {
                if !matches!(e, FrameError::Io(_)) {
                    let _ = write_frame(
                        &mut wire,
                        &usage_reject("malformed hello frame"),
                        MAX_HELLO_FRAME_BYTES,
                    )
                    .await;
                }
                return Err(e);
            }
            Ok(Some(Ok(frame))) => frame,
        };
        let hello = match parse_frame::<ClientMessage>(&frame) {
            Ok(ClientMessage::Hello(hello)) => hello,
            Ok(_) => {
                let _ = write_frame(
                    &mut wire,
                    &usage_reject("the first frame must be a hello"),
                    MAX_HELLO_FRAME_BYTES,
                )
                .await;
                return Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "first frame was not a hello",
                )));
            }
            Err(e) => {
                let _ = write_frame(
                    &mut wire,
                    &usage_reject("malformed hello"),
                    MAX_HELLO_FRAME_BYTES,
                )
                .await;
                return Err(e);
            }
        };
        match negotiate(&hello, principal.clone(), environment.clone(), server) {
            Ok(server_hello) => {
                write_frame(
                    &mut wire,
                    &ServerMessage::Hello(server_hello),
                    MAX_HELLO_FRAME_BYTES,
                )
                .await?;
            }
            Err(reject) => {
                let _ = write_frame(
                    &mut wire,
                    &ServerMessage::Reject(*reject),
                    MAX_HELLO_FRAME_BYTES,
                )
                .await;
                return Ok(());
            }
        }
        wire.codec_mut().max = MAX_CONTROL_FRAME_BYTES;

        // ---- request / subscription loop ---------------------------------
        let mut session = SessionInfo {
            principal,
            interaction: hello.interaction,
            attended: false,
        };
        let dispatcher = &dispatcher;
        let mut inflight: FuturesUnordered<Pending<'_>> = FuturesUnordered::new();
        let mut pending_subscribes = 0usize;
        let mut subs: HashMap<u64, SubState> = HashMap::new();
        let mut sub_polls: FuturesUnordered<SubFuture> = FuturesUnordered::new();
        let mut next_sub_id = 1u64;
        let limit = MAX_CONTROL_FRAME_BYTES;

        let result = loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    let _ = write_frame(
                        &mut wire,
                        &goodbye(Code::ServiceUnavailable, "the runtime is shutting down"),
                        limit,
                    )
                    .await;
                    break Ok(());
                }
                Some(done) = inflight.next(), if !inflight.is_empty() => {
                    match done {
                        Done::Response { seq, envelope } => {
                            let msg = ServerMessage::Response { in_reply_to: seq, envelope };
                            if let Err(e) = send_or_internal(&mut wire, msg).await {
                                break Err(e);
                            }
                        }
                        Done::Subscribed { seq, result: Err(env), .. } => {
                            pending_subscribes -= 1;
                            let msg = ServerMessage::Response {
                                in_reply_to: seq,
                                envelope: to_value_envelope(*env),
                            };
                            if let Err(e) = send_or_internal(&mut wire, msg).await {
                                break Err(e);
                            }
                        }
                        Done::Subscribed { seq, filter, from, result: Ok(start) } => {
                            pending_subscribes -= 1;
                            let id = next_sub_id;
                            next_sub_id += 1;
                            let stop = shutdown.child_token();
                            match start_subscription(&mut wire, &environment, seq, id, filter, from, start, stop).await {
                                Ok(Some((state, live))) => {
                                    sub_polls.push(next_from(id, live, state.stop.clone()));
                                    subs.insert(id, state);
                                }
                                // The `Subscribed` frame was over the limit and was
                                // replaced by an error response: no subscription.
                                Ok(None) => {}
                                Err(e) => break Err(e),
                            }
                        }
                    }
                }
                Some(Some(poll)) = sub_polls.next(), if !sub_polls.is_empty() => {
                    let SubPoll { id, mut rx, result } = poll;
                    let Some(state) = subs.get_mut(&id) else { continue };
                    let msg = match result {
                        // Covered by the snapshot/backlog: overlap, not sent.
                        Ok(live) if live.seq <= state.boundary_seq => None,
                        Ok(live) => {
                            let mut event = live.event.clone();
                            event.cursor = (state.cursor_for)(live.seq);
                            if filter_matches(&state.filter, &event) {
                                // The cursor advances only once the frame is out.
                                let before = state.last_cursor.clone();
                                let advance_to = Some(event.cursor.clone());
                                Some((ServerMessage::Event { subscription: id, event }, before, advance_to))
                            } else {
                                // Passed by (filtered out): nothing to deliver, the
                                // position moves past it.
                                state.last_cursor = event.cursor;
                                None
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            let mut dropped = n;
                            // Drop the retained backlog; bounded by the channel capacity.
                            for _ in 0..=EVENT_BUFFER_PER_SUBSCRIPTION {
                                match rx.try_recv() {
                                    Ok(_) => dropped += 1,
                                    Err(broadcast::error::TryRecvError::Lagged(k)) => dropped += k,
                                    Err(_) => break,
                                }
                            }
                            Some((
                                ServerMessage::Event {
                                    subscription: id,
                                    event: resync_event(&environment, &state.last_cursor, dropped),
                                },
                                state.last_cursor.clone(),
                                None,
                            ))
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            subs.remove(&id);
                            continue;
                        }
                    };
                    let Some((msg, before, advance_to)) = msg else {
                        sub_polls.push(next_from(id, rx, state.stop.clone()));
                        continue;
                    };
                    match send_event(&mut wire, msg, &environment, &before).await {
                        Ok(Delivery::Delivered) => {
                            if let Some(cursor) = advance_to {
                                state.last_cursor = cursor;
                            }
                            sub_polls.push(next_from(id, rx, state.stop.clone()));
                        }
                        Ok(Delivery::Replaced) => {
                            // N03: the cursor stays at the last delivered event, the
                            // resync went out, and the subscription ends.
                            if let Some(state) = subs.remove(&id) {
                                state.stop.cancel();
                            }
                        }
                        Err(e) => break Err(e),
                    }
                }
                frame = wire.next() => {
                    let frame = match frame {
                        None => break Ok(()),
                        Some(Err(e)) => {
                            if !matches!(e, FrameError::Io(_)) {
                                let _ = write_frame(
                                    &mut wire,
                                    &goodbye(Code::UsageError, "frame violates the framing rules"),
                                    limit,
                                )
                                .await;
                            }
                            break Err(e);
                        }
                        Some(Ok(frame)) => frame,
                    };
                    let msg = match parse_frame::<ClientMessage>(&frame) {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = write_frame(&mut wire, &goodbye(Code::UsageError, "malformed frame"), limit).await;
                            break Err(e);
                        }
                    };
                    let reply = match msg {
                        ClientMessage::Request { seq, request } => {
                            if request.requires_attended_session() && !session.attended {
                                // Defence in depth: never dispatched (ADR-0006 §2.3).
                                Some(response(seq, Code::InteractionRequired, "this request requires an attended interactive session"))
                            } else if inflight.len() >= limits.max_inflight {
                                Some(response(seq, Code::Backpressure, "too many requests in flight on this connection"))
                            } else {
                                let session = session.clone();
                                inflight.push(Box::pin(async move {
                                    let envelope = dispatcher.dispatch(&session, request).await;
                                    Done::Response { seq, envelope }
                                }));
                                None
                            }
                        }
                        ClientMessage::Attend { seq } => {
                            if session.interaction == InteractionMode::Interactive {
                                session.attended = true;
                                Some(ServerMessage::Response {
                                    in_reply_to: seq,
                                    envelope: Envelope::ok(serde_json::json!({ "attended": true })),
                                })
                            } else {
                                Some(response(seq, Code::InteractionRequired, "only a session that declared interactive mode can be attended"))
                            }
                        }
                        ClientMessage::Subscribe { seq, filter, from_cursor } => {
                            if from_cursor.as_ref().is_some_and(|c| c.0.len() > MAX_CURSOR_LEN) {
                                Some(response(seq, Code::UsageError, "cursor exceeds the maximum length"))
                            } else if subs.len() + pending_subscribes >= limits.max_subscriptions {
                                Some(response(seq, Code::Backpressure, "too many subscriptions on this connection"))
                            } else if inflight.len() >= limits.max_inflight {
                                Some(response(seq, Code::Backpressure, "too many requests in flight on this connection"))
                            } else {
                                pending_subscribes += 1;
                                let session = session.clone();
                                inflight.push(Box::pin(async move {
                                    let result = dispatcher.subscribe(&session, filter.clone(), from_cursor.clone()).await;
                                    Done::Subscribed { seq, filter, from: from_cursor, result }
                                }));
                                None
                            }
                        }
                        ClientMessage::Unsubscribe { seq, subscription } => {
                            if let Some(state) = subs.remove(&subscription) {
                                state.stop.cancel();
                                Some(ServerMessage::Response {
                                    in_reply_to: seq,
                                    envelope: Envelope::ok(serde_json::json!({
                                        "subscription": subscription,
                                        "unsubscribed": true,
                                    })),
                                })
                            } else {
                                Some(response(seq, Code::NotFound, "no such subscription on this connection"))
                            }
                        }
                        ClientMessage::Hello(_) => {
                            let _ = write_frame(&mut wire, &goodbye(Code::UsageError, "hello may only be sent once"), limit).await;
                            break Err(FrameError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "repeated hello",
                            )));
                        }
                        _ => Some(goodbye_unknown()),
                    };
                    if let Some(reply) = reply {
                        let closing = matches!(reply, ServerMessage::Goodbye { .. });
                        if let Err(e) = write_frame(&mut wire, &reply, limit).await {
                            break Err(e);
                        }
                        if closing {
                            break Err(FrameError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "unsupported client message",
                            )));
                        }
                    }
                }
            }
        };
        for state in subs.values() {
            state.stop.cancel();
        }
        result
    }
}

/// Reply `Subscribed`, then send the backlog, and hand back the state for live
/// delivery. `Ok(None)` when the `Subscribed` frame itself was over the limit (it
/// was replaced by an `INTERNAL_ERROR` response and no subscription exists), or
/// when a backlog event was over the limit (it was replaced by `ResyncRequired` at
/// the last delivered cursor and the subscription ended; N03).
#[allow(clippy::too_many_arguments)]
async fn start_subscription<S>(
    wire: &mut Wire<S>,
    environment: &EnvironmentId,
    seq: u64,
    id: u64,
    filter: EventFilter,
    from: Option<Cursor>,
    start: SubscriptionStart,
    stop: CancellationToken,
) -> Result<Option<(SubState, broadcast::Receiver<Arc<LiveEvent>>)>, FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let SubscriptionStart {
        cursor,
        boundary_seq,
        snapshot,
        backlog,
        live,
        cursor_for,
    } = start;
    let reply = ServerMessage::Subscribed {
        in_reply_to: seq,
        subscription: id,
        cursor: cursor.clone(),
        snapshot,
    };
    if send_or_internal(wire, reply).await? == Sent::Replaced {
        return Ok(None);
    }
    // Backlog: the reader's position starts at its own cursor and ends at the
    // boundary.
    let mut last = from.unwrap_or_else(|| cursor.clone());
    for event in backlog {
        let next = event.cursor.clone();
        if filter_matches(&filter, &event) {
            let msg = ServerMessage::Event {
                subscription: id,
                event,
            };
            if send_event(wire, msg, environment, &last).await? == Delivery::Replaced {
                // N03: `last` stays at the last delivered event; the resync carried
                // it; the subscription ends here (no live state is returned).
                stop.cancel();
                return Ok(None);
            }
        }
        last = next;
    }
    Ok(Some((
        SubState {
            filter,
            last_cursor: cursor,
            boundary_seq,
            cursor_for,
            stop,
        },
        live,
    )))
}

fn goodbye_unknown() -> ServerMessage {
    goodbye(Code::UsageError, "unsupported client message")
}

/// Send a response or subscription frame; one that exceeds the frame limit is
/// replaced by an `INTERNAL_ERROR` response for the same sequence number.
async fn send_or_internal<S>(wire: &mut Wire<S>, msg: ServerMessage) -> Result<Sent, FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match write_frame(wire, &msg, MAX_CONTROL_FRAME_BYTES).await {
        Ok(()) => Ok(Sent::AsBuilt),
        Err(FrameError::TooLarge { .. }) => {
            let seq = match &msg {
                ServerMessage::Response { in_reply_to, .. }
                | ServerMessage::Subscribed { in_reply_to, .. } => *in_reply_to,
                _ => 0,
            };
            write_frame(
                wire,
                &response(seq, Code::InternalError, "response exceeds the frame limit"),
                MAX_CONTROL_FRAME_BYTES,
            )
            .await
            .map(|()| Sent::Replaced)
        }
        Err(e) => Err(e),
    }
}

/// Send an event frame. One that exceeds the frame limit is never delivered: it is
/// replaced by a `ResyncRequired` event at `before` (the last delivered position)
/// and `Delivery::Replaced` is returned, so the caller keeps its cursor at
/// `before` and ends the subscription (ADR-0006 §8, §13.4 N03). The consumer
/// recovers from a fresh snapshot; a resume from `before` never skips the event.
async fn send_event<S>(
    wire: &mut Wire<S>,
    msg: ServerMessage,
    environment: &EnvironmentId,
    before: &Cursor,
) -> Result<Delivery, FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match write_frame(wire, &msg, MAX_CONTROL_FRAME_BYTES).await {
        Ok(()) => Ok(Delivery::Delivered),
        Err(FrameError::TooLarge { .. }) => {
            let subscription = match &msg {
                ServerMessage::Event { subscription, .. } => *subscription,
                _ => 0,
            };
            write_frame(
                wire,
                &ServerMessage::Event {
                    subscription,
                    event: oversized_resync_event(environment, before),
                },
                MAX_CONTROL_FRAME_BYTES,
            )
            .await
            .map(|()| Delivery::Replaced)
        }
        Err(e) => Err(e),
    }
}

/// What the runtime provides to a connection.
#[async_trait::async_trait]
pub trait Dispatcher: Send + Sync {
    /// Handle one request. `session` is a copy taken when the request frame was
    /// read. A request for which `Request::requires_attended_session()` holds
    /// reaches the dispatcher only from an attended session; the application must
    /// check again (it is the authority, this module is defence in depth).
    async fn dispatch(
        &self,
        session: &SessionInfo,
        request: Request,
    ) -> Envelope<serde_json::Value>;

    /// Start a subscription (ADR-0006 §8): create the live receiver first, then read
    /// the boundary and the backlog after `from` (or a snapshot when `from` is
    /// absent or unusable) in one store transaction. The backlog must already be
    /// bounded and cursor-personalized for this reader. An error envelope (for
    /// example `RESYNC_REQUIRED` for a strict caller) is sent as the subscribe
    /// response.
    async fn subscribe(
        &self,
        session: &SessionInfo,
        filter: EventFilter,
        from: Option<Cursor>,
    ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>>;
}

/// Why the server ended a client's session. Carried inside
/// [`FrameError::Io`] (`std::io::Error::get_ref`), recoverable with
/// [`server_refusal`].
#[derive(Debug, thiserror::Error)]
pub enum ServerRefusal {
    /// The hello was rejected (`SCHEMA_UNSUPPORTED` or `USAGE_ERROR`).
    #[error("the server rejected the hello: {}", .0.code)]
    Rejected(Box<Envelope<ErrorData>>),
    /// The server said goodbye (shutdown, limit or protocol error).
    #[error("the server closed the connection: {code}")]
    Goodbye {
        /// Reason code.
        code: Code,
        /// Server text.
        message: String,
    },
}

/// The [`ServerRefusal`] inside a client error, if that is what it was.
#[must_use]
pub fn server_refusal(err: &FrameError) -> Option<&ServerRefusal> {
    match err {
        FrameError::Io(e) => e.get_ref().and_then(|inner| inner.downcast_ref()),
        _ => None,
    }
}

/// The envelope a client surfaces for a transport failure (ADR-0006 §5, §6).
///
/// A server refusal keeps its own code. Anything else (connection lost,
/// truncated or malformed frame) is `SERVICE_UNAVAILABLE`. When the request had
/// already been sent, `effect_status` is `unknown`: the operation's state is
/// whatever the runtime's journal says, and a retry with the same `request_id`
/// replays it rather than repeating it (ADR-0006 §7.3).
#[must_use]
pub fn transport_failure_envelope(err: &FrameError, request_sent: bool) -> Envelope<ErrorData> {
    let effect = if request_sent {
        EffectStatus::Unknown
    } else {
        EffectStatus::None
    };
    match server_refusal(err) {
        Some(ServerRefusal::Rejected(env)) => (**env).clone(),
        Some(ServerRefusal::Goodbye { code, .. }) => {
            let effect = if *code == Code::UsageError {
                EffectStatus::None
            } else {
                effect
            };
            error_envelope(code.clone(), effect, "the runtime closed the connection")
        }
        None => error_envelope(
            Code::ServiceUnavailable,
            effect,
            "the runtime connection was lost",
        ),
    }
}

/// Result of [`ControlClient::subscribe`].
#[derive(Debug, Clone, PartialEq)]
pub enum SubscribeOutcome {
    /// Subscription established. Backlog events (if any) and then live events
    /// follow through [`ControlClient::next_event`].
    Subscribed {
        /// Handle for events and `unsubscribe`.
        subscription: u64,
        /// Boundary the stream continues after (the snapshot's boundary when a
        /// snapshot is present).
        cursor: Cursor,
        /// Consistent view at `cursor`, when the server started from a snapshot
        /// (no cursor sent, or an expired/foreign one the server resynced).
        snapshot: Option<Snapshot<serde_json::Value>>,
    },
    /// The server refused (e.g. `BACKPRESSURE`, `RESYNC_REQUIRED`).
    Refused(Box<Envelope<serde_json::Value>>),
}

/// Client side: connect, hello, attend, request, subscribe.
#[derive(Debug)]
pub struct ControlClient<S> {
    stream: Wire<S>,
    hello: ServerHello,
    next_seq: u64,
    events: VecDeque<(u64, Event)>,
}

fn invalid(msg: &'static str) -> FrameError {
    FrameError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
}

impl<S> ControlClient<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Perform the hello exchange on a connected stream. A server rejection is
    /// returned as an error carrying a [`ServerRefusal`] (see [`server_refusal`]).
    ///
    /// `required` is also offered in `capabilities` (the server requires
    /// `required ⊆ offer ∩ capabilities`). `interaction` is the session's mode:
    /// only an `Interactive` session can later be attended ([`Self::attend`]).
    pub async fn handshake(
        stream: S,
        client: PeerInfo,
        required: BTreeSet<String>,
        interaction: InteractionMode,
    ) -> Result<Self, crate::frame::FrameError> {
        let mut wire = Framed::new(stream, BoundedFrameCodec::new(MAX_HELLO_FRAME_BYTES));
        let mut capabilities = server_capabilities();
        capabilities.extend(required.iter().cloned());
        let hello = ClientMessage::Hello(ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client,
            capabilities,
            required: required.clone(),
            interaction,
        });
        write_frame(&mut wire, &hello, MAX_HELLO_FRAME_BYTES).await?;
        let reply = tokio::time::timeout(Duration::from_millis(HELLO_TIMEOUT_MS), wire.next())
            .await
            .map_err(|_| {
                FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no server hello within the hello timeout",
                ))
            })?;
        let frame = match reply {
            None => return Err(FrameError::Truncated),
            Some(r) => r?,
        };
        match parse_frame::<ServerMessage>(&frame)? {
            ServerMessage::Hello(h) => {
                if h.protocol != PROTOCOL_VERSION || !h.schema_version.is_supported() {
                    return Err(invalid(
                        "server hello has an unsupported protocol or schema",
                    ));
                }
                if !required.is_subset(&h.capabilities) {
                    return Err(invalid("server hello lacks a required capability"));
                }
                wire.codec_mut().max = MAX_CONTROL_FRAME_BYTES;
                Ok(Self {
                    stream: wire,
                    hello: h,
                    next_seq: 1,
                    events: VecDeque::new(),
                })
            }
            ServerMessage::Reject(env) => Err(refused(ServerRefusal::Rejected(Box::new(env)))),
            ServerMessage::Goodbye { code, message } => {
                Err(refused(ServerRefusal::Goodbye { code, message }))
            }
            _ => Err(invalid("unexpected first server frame")),
        }
    }

    /// Negotiated server hello.
    #[must_use]
    pub fn server(&self) -> &ServerHello {
        &self.hello
    }

    async fn send(&mut self, msg: &ClientMessage) -> Result<(), FrameError> {
        write_frame(&mut self.stream, msg, MAX_CONTROL_FRAME_BYTES).await
    }

    async fn read(&mut self) -> Result<ServerMessage, FrameError> {
        match self.stream.next().await {
            None => Err(FrameError::Truncated),
            Some(frame) => parse_frame::<ServerMessage>(&frame?),
        }
    }

    fn queue_event(&mut self, subscription: u64, event: Event) -> Result<(), FrameError> {
        if self.events.len() >= CLIENT_EVENT_BACKLOG {
            return Err(invalid(
                "client event backlog exceeded; resubscribe from a snapshot",
            ));
        }
        self.events.push_back((subscription, event));
        Ok(())
    }

    /// Read until the frame answering `seq`, queueing events that arrive first.
    async fn await_reply(&mut self, seq: u64) -> Result<ServerMessage, FrameError> {
        loop {
            match self.read().await? {
                m @ (ServerMessage::Response { .. } | ServerMessage::Subscribed { .. }) => {
                    let in_reply_to = match &m {
                        ServerMessage::Response { in_reply_to, .. }
                        | ServerMessage::Subscribed { in_reply_to, .. } => *in_reply_to,
                        _ => 0,
                    };
                    if in_reply_to == seq {
                        return Ok(m);
                    }
                }
                ServerMessage::Event {
                    subscription,
                    event,
                } => self.queue_event(subscription, event)?,
                ServerMessage::Goodbye { code, message } => {
                    return Err(refused(ServerRefusal::Goodbye { code, message }));
                }
                _ => return Err(invalid("unexpected server frame")),
            }
        }
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Send one request and await its response. Transport failures are errors;
    /// map them with [`transport_failure_envelope`] (request already sent).
    pub async fn request(
        &mut self,
        request: Request,
    ) -> Result<Envelope<serde_json::Value>, crate::frame::FrameError> {
        let seq = self.take_seq();
        self.send(&ClientMessage::Request { seq, request }).await?;
        match self.await_reply(seq).await? {
            ServerMessage::Response { envelope, .. } => Ok(envelope),
            _ => Err(invalid("subscription reply to a request")),
        }
    }

    /// Ask the runtime to mark this session attended (ADR-0006 §3.1). `OK
    /// {"attended": true}` on a session whose hello declared `Interactive`,
    /// `INTERACTION_REQUIRED` otherwise. The caller (CLI/TUI) sends this only from
    /// its owner-present interactive flow; same-user code can imitate that flow,
    /// which is the disclosed limit.
    pub async fn attend(&mut self) -> Result<Envelope<serde_json::Value>, FrameError> {
        let seq = self.take_seq();
        self.send(&ClientMessage::Attend { seq }).await?;
        match self.await_reply(seq).await? {
            ServerMessage::Response { envelope, .. } => Ok(envelope),
            _ => Err(invalid("unexpected attend reply")),
        }
    }

    /// Subscribe to events.
    pub async fn subscribe(
        &mut self,
        filter: EventFilter,
        from_cursor: Option<Cursor>,
    ) -> Result<SubscribeOutcome, FrameError> {
        let seq = self.take_seq();
        self.send(&ClientMessage::Subscribe {
            seq,
            filter,
            from_cursor,
        })
        .await?;
        match self.await_reply(seq).await? {
            ServerMessage::Subscribed {
                subscription,
                cursor,
                snapshot,
                ..
            } => Ok(SubscribeOutcome::Subscribed {
                subscription,
                cursor,
                snapshot,
            }),
            ServerMessage::Response { envelope, .. } => {
                Ok(SubscribeOutcome::Refused(Box::new(envelope)))
            }
            _ => Err(invalid("unexpected subscription reply")),
        }
    }

    /// Stop a subscription.
    pub async fn unsubscribe(
        &mut self,
        subscription: u64,
    ) -> Result<Envelope<serde_json::Value>, FrameError> {
        let seq = self.take_seq();
        self.send(&ClientMessage::Unsubscribe { seq, subscription })
            .await?;
        match self.await_reply(seq).await? {
            ServerMessage::Response { envelope, .. } => Ok(envelope),
            _ => Err(invalid("unexpected unsubscribe reply")),
        }
    }

    /// Next event for any subscription on this connection (queued first).
    pub async fn next_event(&mut self) -> Result<(u64, Event), FrameError> {
        if let Some(e) = self.events.pop_front() {
            return Ok(e);
        }
        loop {
            match self.read().await? {
                ServerMessage::Event {
                    subscription,
                    event,
                } => return Ok((subscription, event)),
                ServerMessage::Response { .. } | ServerMessage::Subscribed { .. } => {}
                ServerMessage::Goodbye { code, message } => {
                    return Err(refused(ServerRefusal::Goodbye { code, message }));
                }
                _ => return Err(invalid("unexpected server frame")),
            }
        }
    }
}

fn refused(r: ServerRefusal) -> FrameError {
    let kind = match r {
        ServerRefusal::Rejected(_) => std::io::ErrorKind::ConnectionRefused,
        ServerRefusal::Goodbye { .. } => std::io::ErrorKind::ConnectionAborted,
    };
    FrameError::Io(std::io::Error::new(kind, r))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn hello(protocol: u16, schema: &str, required: &[&str]) -> ClientHello {
        ClientHello {
            protocol,
            schema_version: SchemaVersion(schema.to_owned()),
            client: PeerInfo {
                name: "t".into(),
                version: "0".into(),
            },
            capabilities: server_capabilities(),
            required: required.iter().map(|s| (*s).to_owned()).collect(),
            interaction: InteractionMode::NonInteractive,
        }
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn srv() -> PeerInfo {
        PeerInfo {
            name: "heimdall".into(),
            version: "0".into(),
        }
    }

    #[test]
    fn rejects_wrong_major_and_missing_required_capability() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let ok = negotiate(&hello(PROTOCOL_VERSION, "1", &[]), p.clone(), env(), srv());
        assert!(ok.is_ok());
        let bad_schema = negotiate(&hello(PROTOCOL_VERSION, "2", &[]), p.clone(), env(), srv());
        assert_eq!(bad_schema.unwrap_err().code, Code::SchemaUnsupported);
        let bad_cap = negotiate(&hello(PROTOCOL_VERSION, "1", &["nope/9"]), p, env(), srv());
        assert_eq!(bad_cap.unwrap_err().code, Code::SchemaUnsupported);
    }

    /// Review F10: `required` must be within the negotiated set, not merely the
    /// server's offer. A hello that requires `events/1` but omits it from its own
    /// capabilities is rejected; the same hello with `events/1` offered passes and
    /// the server hello lists it.
    #[test]
    fn inconsistent_hello_requiring_an_unoffered_capability_is_rejected() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let mut inconsistent = hello(PROTOCOL_VERSION, "1", &[capability::EVENTS_V1]);
        inconsistent.capabilities.remove(capability::EVENTS_V1);
        assert!(server_capabilities().contains(capability::EVENTS_V1));
        let err = negotiate(&inconsistent, p.clone(), env(), srv()).unwrap_err();
        assert_eq!(err.code, Code::SchemaUnsupported);
        assert_eq!(err.data.error.effect_status, EffectStatus::None);

        // Required, offered, and served: accepted and in effect.
        let consistent = hello(PROTOCOL_VERSION, "1", &[capability::EVENTS_V1]);
        let ok = negotiate(&consistent, p.clone(), env(), srv()).unwrap();
        assert!(ok.capabilities.contains(capability::EVENTS_V1));

        // Not required and not offered: accepted, and absent from the result.
        let mut narrow = hello(PROTOCOL_VERSION, "1", &[]);
        narrow.capabilities.remove(capability::EVENTS_V1);
        let ok = negotiate(&narrow, p.clone(), env(), srv()).unwrap();
        assert!(!ok.capabilities.contains(capability::EVENTS_V1));

        // Empty capabilities with any requirement: rejected.
        let mut empty = hello(PROTOCOL_VERSION, "1", &[capability::OPERATIONS_V1]);
        empty.capabilities.clear();
        assert_eq!(
            negotiate(&empty, p, env(), srv()).unwrap_err().code,
            Code::SchemaUnsupported
        );
    }

    #[test]
    fn subscription_start_debug_omits_contents() {
        // Synthetic canary built per run (never committed as a value).
        let canary = format!(
            "{}{:x}",
            heimdall_testkit::CANARY_PREFIX,
            std::process::id()
        );
        let (_tx, live) = broadcast::channel(1);
        let start = SubscriptionStart {
            cursor: Cursor(canary),
            boundary_seq: 9,
            snapshot: None,
            backlog: Vec::new(),
            live,
            cursor_for: Arc::new(|seq| Cursor(format!("c{seq}"))),
        };
        let shown = format!("{start:?}");
        assert!(shown.contains("boundary_seq: 9"));
        heimdall_testkit::assert_no_canary(&shown);
    }
}
