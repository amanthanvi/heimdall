//! Bounded SSH-agent-protocol framer for the signing endpoint (spec §13.2, §7.2
//! "established libraries, not guessed parsing"; ADR-0006 §2.6).
//!
//! The signing endpoint performs only already-authorized credential operations.
//! M01 ships the framer and the allow-list; the real signer (keys, certificates,
//! grant/pause/cutoff checks per signature) arrives in M03. The default signer,
//! [`NoIdentities`], answers `SSH_AGENT_IDENTITIES_ANSWER` with zero keys and
//! `SSH_AGENT_FAILURE` to everything else, which already exercises the boundary.
//!
//! The `ssh_agent_lib` listener helpers are not used (no `agent` feature): they
//! cannot apply our DACL/peer checks. This module never parses key material: the
//! type byte is classified ([`classify`]) and a sign request is split into its three
//! draft-miller fields (`string key_blob, string data, uint32 flags`) by a
//! zero-copy reader that checks every declared length against the bytes present
//! before slicing and refuses trailing bytes. Key blobs stay opaque to `ipc`.
//! Answers are encoded with the same grammar; the tests decode them with
//! `ssh_agent_lib::proto::Response` to check interoperability.
//!
//! Connection rules (each violation closes the connection without a reply):
//! a declared frame length of zero or above `MAX_SIGNING_FRAME_BYTES` (checked
//! from the 4-byte header, before the body buffer exists), EOF inside a frame,
//! and no complete frame within `IDLE_TIMEOUT_MS`. A well-framed message that is
//! not allowed, malformed, or refused by the signer gets `SSH_AGENT_FAILURE` and
//! the connection stays usable. Answers never exceed the frame limit or list
//! more than `MAX_IDENTITIES`. Per-endpoint concurrency
//! (`MAX_SIGNING_CONNECTIONS`) is enforced by the accept loop that calls
//! [`serve`].
//!
//! ⟨M03⟩ (m03-plan U0b row 1; ADR-0008 D2 items 3 and 3a):
//! * every [`Signer`] call receives the connection's [`SigningSession`] (the
//!   transport-authenticated peer, the endpoint it arrived on, and the
//!   `session-bind@openssh.com` record the signer accepted, if any). [`serve`]
//!   creates one per connection and hands `session-bind` requests to
//!   [`Signer::session_bind`], answering `SSH_AGENT_SUCCESS` or `SSH_AGENT_FAILURE`;
//! * [`Signer::sign`] returns a [`SignOutcome`], whose optional [`PermitGuard`] is the
//!   opaque signing permit (`heimdall-credential` fills it from
//!   `app::managed::SignPermit`; `ipc` depends only on `heimdall-contract`). A
//!   signature without a permit is sent only when the signer declares its grant
//!   ungated (no signing gate; [`SignOutcome::ungated_signature`]); otherwise it is
//!   refused with `SSH_AGENT_FAILURE` and recorded (ADR-0008 §17.15);
//! * **capacity, then release.** Each connection has a bounded outbound queue of
//!   whole frames, drained to the socket by its own writer (the reader never awaits
//!   `write_all`/`flush` itself; M-F33). For a reply carrying a permit, [`serve`]
//!   (step 6) reserves room for one complete frame, waiting at most
//!   [`ServeLimits::enqueue_timeout`] (`signing_enqueue_timeout`, 2 s), and the
//!   permit's [`ReleaseCheck::expires_at`] cancels that wait, whichever comes first;
//!   (step 7) with the room held, calls [`ReleaseCheck::may_release`] immediately
//!   before the enqueue; (step 8) puts the signature, or `SSH_AGENT_FAILURE` when the
//!   check fails, into the reserved room, an enqueue that cannot wait; and only then
//!   drops the guard. On expiry during the wait the signature is discarded and the
//!   reply becomes `SSH_AGENT_FAILURE` once room frees within the same enqueue
//!   window; when no room frees in that window the connection is closed without a
//!   reply. Replies without a permit go through the same queue.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ipc::MAX_SIGNING_FRAME_BYTES;
use heimdall_contract::provider::EndpointRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::endpoint::PeerIdentity;

/// Maximum identities ever listed.
pub const MAX_IDENTITIES: usize = 64;
/// Idle timeout for a signing connection (milliseconds).
pub const IDLE_TIMEOUT_MS: u64 = 30_000;
/// ⟨M03⟩ Default `signing_enqueue_timeout` (milliseconds): the longest a signature
/// reply waits for outbound capacity before the release check (m03-plan §5 item 17;
/// ADR-0008 D2 item 3a step 6). The authoritative value is `app::Limits`; `ipc`
/// cannot depend on `app`, so callers pass it in [`ServeLimits`].
pub const SIGNING_ENQUEUE_TIMEOUT_MS: u64 = 2_000;
/// ⟨M03⟩ Default capacity of a connection's outbound queue, in whole frames.
pub const OUTBOUND_QUEUE_FRAMES: usize = 4;

/// Agent message types the signing endpoint accepts (RFC draft-miller-ssh-agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedRequest {
    /// `SSH_AGENTC_REQUEST_IDENTITIES` (11).
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST` (13).
    SignRequest,
    /// `SSH_AGENTC_EXTENSION` (27) with `session-bind@openssh.com` only (spec S03).
    SessionBind,
}

/// Why a request is refused before any signer logic runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigningRefusal {
    /// Frame exceeds the limit.
    #[error("agent frame of {0} bytes exceeds limit")]
    Oversize(usize),
    /// Malformed message.
    #[error("malformed agent message")]
    Malformed,
    /// Add/remove/lock/unlock/smartcard or an unknown extension: refused.
    #[error("agent message type {0} is not permitted on the signing endpoint")]
    NotPermitted(u8),
}

/// The `session-bind@openssh.com` extension name.
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Classify a raw agent message (after the 4-byte length prefix) into an allowed
/// request or a refusal. Pure; does not parse key material.
pub fn classify(payload: &[u8]) -> Result<AllowedRequest, SigningRefusal> {
    if payload.len() > MAX_SIGNING_FRAME_BYTES {
        return Err(SigningRefusal::Oversize(payload.len()));
    }
    let Some(&ty) = payload.first() else {
        return Err(SigningRefusal::Malformed);
    };
    match ty {
        11 => Ok(AllowedRequest::RequestIdentities),
        13 => Ok(AllowedRequest::SignRequest),
        27 => {
            // string extension-name follows the type byte.
            if payload.len() < 5 {
                return Err(SigningRefusal::Malformed);
            }
            let n = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
            let name = payload.get(5..5 + n).ok_or(SigningRefusal::Malformed)?;
            if name == SESSION_BIND {
                Ok(AllowedRequest::SessionBind)
            } else {
                Err(SigningRefusal::NotPermitted(ty))
            }
        }
        other => Err(SigningRefusal::NotPermitted(other)),
    }
}

/// `SSH_AGENT_FAILURE` (5) as a complete frame.
#[must_use]
pub fn failure_frame() -> [u8; 5] {
    [0, 0, 0, 1, 5]
}

/// ⟨M03⟩ `SSH_AGENT_SUCCESS` (6) as a complete frame (the answer to an accepted
/// `session-bind@openssh.com`).
#[must_use]
pub fn success_frame() -> [u8; 5] {
    [0, 0, 0, 1, 6]
}

/// `SSH_AGENT_IDENTITIES_ANSWER` (12) with zero keys as a complete frame.
#[must_use]
pub fn empty_identities_frame() -> [u8; 9] {
    [0, 0, 0, 5, 12, 0, 0, 0, 0]
}

// --- ⟨M03⟩ connection context, permits, outcomes --------------------------------------

/// ⟨M03⟩ A `session-bind@openssh.com` request as plain data (OpenSSH PROTOCOL.agent:
/// `string hostkey, string session_identifier, string signature, bool
/// is_forwarding`). Recording it verifies nothing: the signer
/// ([`Signer::session_bind`]) decides whether it is valid and stores it in
/// [`SigningSession::bind`]. None of the fields is secret (public host key, session
/// hash and the host's signature over it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBindRecord {
    /// The server host key blob, opaque to `ipc`.
    pub host_key: Vec<u8>,
    /// The SSH session identifier (exchange hash).
    pub session_id: Vec<u8>,
    /// The host key's signature over the session identifier, opaque to `ipc`.
    pub signature: Vec<u8>,
    /// Whether the client binds a forwarded agent connection.
    pub is_forwarding: bool,
}

impl SessionBindRecord {
    /// Structural split of the extension contents (the bytes after the extension
    /// name). `None` on any overrun, a boolean other than 0 or 1, or trailing bytes.
    /// No signature, key or identifier is checked here.
    #[must_use]
    pub fn parse(contents: &[u8]) -> Option<Self> {
        let mut f = Fields(contents);
        let host_key = f.string()?.to_vec();
        let session_id = f.string()?.to_vec();
        let signature = f.string()?.to_vec();
        let (&flag, rest) = f.0.split_first()?;
        if !rest.is_empty() || flag > 1 {
            return None;
        }
        Some(Self {
            host_key,
            session_id,
            signature,
            is_forwarding: flag == 1,
        })
    }
}

/// ⟨M03⟩ One signing connection's context, created by [`serve`] when the connection
/// starts and passed to every [`Signer`] call on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SigningSession {
    /// The OS principal the transport authenticated (Unix peer credentials, Windows
    /// client SID). PIDs in it are metadata only (spec §4.2).
    pub peer: PeerIdentity,
    /// The endpoint the connection arrived on (environment, binding or verification
    /// endpoint; ADR-0008 D2 item 2).
    pub endpoint: EndpointRef,
    /// The `session-bind@openssh.com` the signer accepted on this connection, if
    /// any. Only the signer sets it.
    pub bind: Option<SessionBindRecord>,
    /// ⟨M03⟩ Signature frames refused on this connection because they carried no
    /// permit and were not declared ungated (ADR-0008 §17.15). Only [`serve`]
    /// increments it; each refusal is also logged (`tracing` warn, nonsecret fields).
    pub refused_permitless: u32,
}

impl SigningSession {
    /// A fresh session with no bind record.
    #[must_use]
    pub fn new(peer: PeerIdentity, endpoint: EndpointRef) -> Self {
        Self {
            peer,
            endpoint,
            bind: None,
            refused_permitless: 0,
        }
    }
}

/// ⟨M03⟩ The release check of a signing permit (ADR-0008 D2 item 3a step 7; §17.4
/// item 9). Implemented by `heimdall-credential` over `app::managed::SignPermit`;
/// `ipc` calls it and knows nothing else about the permit.
pub trait ReleaseCheck: Send + Sync {
    /// Whether the signature may be released now: the permit has not expired on
    /// either clock, time is still `Safe`, and neither the grant nor any ancestor is
    /// marked `narrowing_pending`. Called by [`serve`] with outbound capacity already
    /// reserved, immediately before an enqueue that cannot wait. Must not block.
    fn may_release(&self) -> bool;
    /// The continuous-clock instant at which the permit expires. It cancels the wait
    /// for outbound capacity (step 6).
    fn expires_at(&self) -> tokio::time::Instant;
}

/// ⟨M03⟩ The opaque signing permit that crosses into `ipc` (ADR-0008 D2 item 3a;
/// §18). `heimdall-credential` fills it from `app::managed::SignPermit`. Holding it
/// holds the grant's signing gate shared; [`serve`] drops it only after the reply
/// (signature or failure) is in the connection's outbound queue.
pub struct PermitGuard(pub Box<dyn ReleaseCheck + Send + Sync>);

impl std::fmt::Debug for PermitGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PermitGuard(..)")
    }
}

/// ⟨M03⟩ What [`Signer::sign`] returns: the complete answer frame and, for a
/// signature, the permit whose release check gates it.
///
/// **A signature needs a permit** (ADR-0008 §17.15). [`serve`] sends a signature
/// frame (`SSH_AGENT_SIGN_RESPONSE`) without a permit only when the outcome is
/// declared `ungated` ([`SignOutcome::ungated_signature`]); otherwise it is treated as
/// gated: replaced by `SSH_AGENT_FAILURE` and recorded
/// ([`SigningSession::refused_permitless`]).
#[derive(Debug)]
pub struct SignOutcome {
    /// A complete agent frame (4-byte length prefix included). A frame that is not
    /// well formed or exceeds the signing frame limit is replaced by
    /// `SSH_AGENT_FAILURE`.
    pub frame: Vec<u8>,
    /// The permit. When present, the frame is sent only if the release check passes
    /// with outbound capacity held; otherwise `SSH_AGENT_FAILURE` takes its place.
    pub permit: Option<PermitGuard>,
    /// The signer's declaration that the signature's grant has **no signing gate**
    /// (`app::managed::SigningGates::contains` is false), so no permit exists. Only
    /// meaningful when `permit` is `None`; a permit always wins. Set it only through
    /// [`SignOutcome::ungated_signature`].
    pub ungated: bool,
}

impl SignOutcome {
    /// `SSH_AGENT_FAILURE`, no permit.
    #[must_use]
    pub fn failure() -> Self {
        Self {
            frame: failure_frame().to_vec(),
            permit: None,
            ungated: false,
        }
    }

    /// `SSH_AGENT_SIGN_RESPONSE` over `signature`, gated by `permit` (the release
    /// check of ADR-0008 D2 item 3a). A signature that would exceed the frame limit
    /// becomes [`SignOutcome::failure`] and the permit is dropped.
    #[must_use]
    pub fn signature(signature: &[u8], permit: PermitGuard) -> Self {
        match sign_response_frame(signature) {
            Some(frame) => Self {
                frame,
                permit: Some(permit),
                ungated: false,
            },
            None => Self::failure(),
        }
    }

    /// `SSH_AGENT_SIGN_RESPONSE` over `signature` with no permit, **only for a grant
    /// that has no signing gate** (`app::managed::SigningGates::contains` is false;
    /// ADR-0008 §17.15). The signer must decide it from the gates, never by default;
    /// the M01 fixture signers model such grants. A signature that would exceed the
    /// frame limit becomes [`SignOutcome::failure`].
    #[must_use]
    pub fn ungated_signature(signature: &[u8]) -> Self {
        match sign_response_frame(signature) {
            Some(frame) => Self {
                frame,
                permit: None,
                ungated: true,
            },
            None => Self::failure(),
        }
    }
}

/// What the signer behind the endpoint must implement (M03). Every call receives
/// the connection's [`SigningSession`] and must recheck grant state, deadline,
/// pause, cutoff and generation before signing (spec §6.1, R-SE-07).
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Identities visible to this endpoint (public blobs and comments only).
    async fn identities(&self, session: &SigningSession) -> Vec<(Vec<u8>, String)>;
    /// Sign `data` with the key identified by `key_blob` if authorized now. A
    /// signature carries the permit of its admission ([`SignOutcome::signature`]),
    /// or, only for a grant with no signing gate, is declared ungated
    /// ([`SignOutcome::ungated_signature`]); any other permit-less signature is
    /// refused by [`serve`].
    async fn sign(
        &self,
        session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> SignOutcome;
    /// A `session-bind@openssh.com` request: `payload` is the extension contents
    /// after the name ([`SessionBindRecord::parse`] splits it structurally). The
    /// signer verifies it and records it in `session.bind`; `true` answers
    /// `SSH_AGENT_SUCCESS`, `false` `SSH_AGENT_FAILURE`. Must not block. The default
    /// refuses every bind.
    fn session_bind(&self, session: &mut SigningSession, payload: &[u8]) -> bool {
        let _ = (session, payload);
        false
    }
}

/// A signer with no identities that refuses every signature and every bind: the
/// M01 endpoint behaviour (empty identity list, `SSH_AGENT_FAILURE` otherwise, never
/// a permit).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoIdentities;

#[async_trait::async_trait]
impl Signer for NoIdentities {
    async fn identities(&self, _session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        Vec::new()
    }

    async fn sign(
        &self,
        _session: &SigningSession,
        _key_blob: &[u8],
        _data: &[u8],
        _flags: u32,
    ) -> SignOutcome {
        SignOutcome::failure()
    }
}

/// ⟨M03⟩ Per-connection limits of [`serve_with_limits`]. `Default` gives the
/// production values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// No complete frame within this closes the connection; also bounds each socket
    /// write and the queue wait of a reply without a permit
    /// ([`IDLE_TIMEOUT_MS`]).
    pub idle: Duration,
    /// `signing_enqueue_timeout`: the longest a reply with a permit waits for
    /// outbound capacity ([`SIGNING_ENQUEUE_TIMEOUT_MS`]).
    pub enqueue_timeout: Duration,
    /// Outbound queue capacity in whole frames (at least 1;
    /// [`OUTBOUND_QUEUE_FRAMES`]).
    pub outbound_frames: usize,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            idle: Duration::from_millis(IDLE_TIMEOUT_MS),
            enqueue_timeout: Duration::from_millis(SIGNING_ENQUEUE_TIMEOUT_MS),
            outbound_frames: OUTBOUND_QUEUE_FRAMES,
        }
    }
}

/// Serve one signing connection with the bounded framer and the production
/// [`ServeLimits`].
///
/// `peer` and `endpoint` become the connection's [`SigningSession`]. Returns
/// `Ok(())` when the peer closes between frames (after the queued replies are
/// written), the connection is idle for `IDLE_TIMEOUT_MS`, or `shutdown` fires;
/// returns an `InvalidData` / `UnexpectedEof` error for a framing violation and a
/// `TimedOut` error when the peer does not take replies in time. The connection is
/// closed in every case.
pub async fn serve<S>(
    stream: S,
    peer: PeerIdentity,
    endpoint: EndpointRef,
    signer: Arc<dyn Signer>,
    shutdown: CancellationToken,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    serve_with_limits(
        stream,
        peer,
        endpoint,
        signer,
        shutdown,
        ServeLimits::default(),
    )
    .await
}

/// [`serve`] with an explicit idle timeout (tests use short ones). Public for the
/// `adversarial_agent_frames` test target only; not a supported API.
#[doc(hidden)]
pub async fn serve_with_idle<S>(
    stream: S,
    peer: PeerIdentity,
    endpoint: EndpointRef,
    signer: Arc<dyn Signer>,
    shutdown: CancellationToken,
    idle: Duration,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let limits = ServeLimits {
        idle,
        ..ServeLimits::default()
    };
    serve_with_limits(stream, peer, endpoint, signer, shutdown, limits).await
}

/// How the reading half of a connection ended.
enum ReadEnd {
    /// Clean EOF between frames, or idle.
    Clean,
    /// Framing violation.
    Violation(io::Error),
    /// No outbound capacity within the bound: close without a reply.
    CapacityTimeout,
    /// The writer is gone (its error is reported by the writer branch).
    WriterGone,
}

/// [`serve`] with explicit [`ServeLimits`].
pub async fn serve_with_limits<S>(
    stream: S,
    peer: PeerIdentity,
    endpoint: EndpointRef,
    signer: Arc<dyn Signer>,
    shutdown: CancellationToken,
    limits: ServeLimits,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut rd, wr) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Vec<u8>>(limits.outbound_frames.max(1));
    let mut session = SigningSession::new(peer, endpoint);
    // The writer drains whole frames to the socket; it runs concurrently with the
    // reader in this task and ends when the reader drops the sender.
    let writer = write_loop(wr, rx, limits.idle);
    tokio::pin!(writer);
    let end = {
        let reader = read_loop(&mut rd, tx, &mut session, signer.as_ref(), limits);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            w = &mut writer => return w,
            end = reader => end,
        }
    };
    match end {
        ReadEnd::Clean => drain(writer, &shutdown).await,
        ReadEnd::Violation(e) => {
            // Replies to earlier frames still go out, as in M01; then close.
            let _ = drain(writer, &shutdown).await;
            Err(e)
        }
        ReadEnd::CapacityTimeout => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "agent peer did not take the answer in time",
        )),
        ReadEnd::WriterGone => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "agent connection writer ended",
        )),
    }
}

async fn drain<F>(writer: std::pin::Pin<&mut F>, shutdown: &CancellationToken) -> io::Result<()>
where
    F: std::future::Future<Output = io::Result<()>>,
{
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Ok(()),
        w = writer => w,
    }
}

async fn write_loop<W>(mut wr: W, mut rx: mpsc::Receiver<Vec<u8>>, idle: Duration) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(frame) = rx.recv().await {
        let write = async {
            wr.write_all(&frame).await?;
            wr.flush().await
        };
        match tokio::time::timeout(idle, write).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "agent peer did not read the answer in time",
                ));
            }
        }
    }
    Ok(())
}

async fn read_loop<R>(
    rd: &mut R,
    tx: mpsc::Sender<Vec<u8>>,
    session: &mut SigningSession,
    signer: &dyn Signer,
    limits: ServeLimits,
) -> ReadEnd
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let payload = match tokio::time::timeout(limits.idle, read_agent_frame(rd)).await {
            Err(_) | Ok(Ok(None)) => return ReadEnd::Clean,
            Ok(Ok(Some(payload))) => payload,
            Ok(Err(e)) => return ReadEnd::Violation(e),
        };
        let SignOutcome {
            frame,
            permit,
            ungated,
        } = answer(&payload, signer, session).await;
        let frame = if !well_formed(&frame) {
            failure_frame().to_vec()
        } else if permit.is_none() && !ungated && is_sign_response(&frame) {
            // ADR-0008 §17.15: a permit-less signature not declared ungated is
            // treated as gated, refused and recorded.
            session.refused_permitless = session.refused_permitless.saturating_add(1);
            tracing::warn!(
                endpoint_kind = ?session.endpoint.kind,
                refused = session.refused_permitless,
                "signature without a permit for a gated grant refused"
            );
            failure_frame().to_vec()
        } else {
            frame
        };
        let sent = match permit {
            Some(guard) => enqueue_signed(&tx, frame, guard, limits.enqueue_timeout).await,
            None => match tokio::time::timeout(limits.idle, tx.reserve()).await {
                Ok(Ok(room)) => {
                    room.send(frame);
                    Ok(())
                }
                Ok(Err(_closed)) => Err(EnqueueEnd::Closed),
                Err(_elapsed) => Err(EnqueueEnd::CapacityTimeout),
            },
        };
        match sent {
            Ok(()) => {}
            Err(EnqueueEnd::CapacityTimeout) => return ReadEnd::CapacityTimeout,
            Err(EnqueueEnd::Closed) => return ReadEnd::WriterGone,
        }
    }
}

/// Why [`enqueue_signed`] put nothing into the queue.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueEnd {
    /// No room within the enqueue timeout: the connection is closed without a reply.
    CapacityTimeout,
    /// The queue's receiver is gone.
    Closed,
}

/// ADR-0008 D2 item 3a steps 6–8 for one reply carrying a permit; [`serve`]'s
/// signing path. Public for the `integration_ipc_signing_m03` test target only (it
/// owns the queue to observe the order); not a supported API.
///
/// 6. Reserve room for one whole frame, waiting at most `enqueue_timeout`; the
///    permit's `expires_at()` cancels the wait. On expiry the signature is discarded,
///    the permit dropped, and `SSH_AGENT_FAILURE` is queued once room frees within
///    the same window.
/// 7. With the room held, the release check: not expired, and `may_release()`.
/// 8. Put the signature or `SSH_AGENT_FAILURE` into the reserved room
///    (`Permit::send` cannot wait), then drop the guard.
#[doc(hidden)]
pub async fn enqueue_signed(
    tx: &mpsc::Sender<Vec<u8>>,
    frame: Vec<u8>,
    guard: PermitGuard,
    enqueue_timeout: Duration,
) -> Result<(), EnqueueEnd> {
    let window_end = tokio::time::Instant::now() + enqueue_timeout;
    let expiry = guard.0.expires_at();
    // Step 6. Biased towards expiry: an expired permit never reaches the check.
    let reserved = tokio::select! {
        biased;
        () = tokio::time::sleep_until(expiry) => None,
        r = tokio::time::timeout_at(window_end, tx.reserve()) => Some(r),
    };
    let room = match reserved {
        Some(Ok(Ok(room))) => room,
        Some(Ok(Err(_closed))) => return Err(EnqueueEnd::Closed),
        Some(Err(_elapsed)) => return Err(EnqueueEnd::CapacityTimeout),
        None => {
            // Expired while waiting: nothing of the signature is ever released. The
            // permit (and the gate it holds) goes now; the failure needs no gate.
            drop(frame);
            drop(guard);
            return match tokio::time::timeout_at(window_end, tx.reserve()).await {
                Ok(Ok(room)) => {
                    room.send(failure_frame().to_vec());
                    Ok(())
                }
                Ok(Err(_closed)) => Err(EnqueueEnd::Closed),
                Err(_elapsed) => Err(EnqueueEnd::CapacityTimeout),
            };
        }
    };
    // Step 7: nothing from here to the send awaits.
    let release = tokio::time::Instant::now() < expiry && guard.0.may_release();
    // Step 8: the linearized effect.
    room.send(if release {
        frame
    } else {
        failure_frame().to_vec()
    });
    drop(guard);
    Ok(())
}

/// Whether a complete frame is an `SSH_AGENT_SIGN_RESPONSE` (14).
fn is_sign_response(frame: &[u8]) -> bool {
    frame.get(4) == Some(&14)
}

/// A complete frame whose header matches its body, within the signing limit.
fn well_formed(frame: &[u8]) -> bool {
    match frame.split_first_chunk::<4>() {
        Some((len, body)) => {
            let len = u32::from_be_bytes(*len) as usize;
            len == body.len() && len > 0 && len <= MAX_SIGNING_FRAME_BYTES
        }
        None => false,
    }
}

fn violation(kind: io::ErrorKind, msg: &'static str) -> io::Error {
    io::Error::new(kind, msg)
}

/// Read one agent frame body. `Ok(None)` is a clean EOF before any header byte.
/// The declared length is checked before the body buffer is allocated.
pub(crate) async fn read_agent_frame<S>(stream: &mut S) -> io::Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            violation(io::ErrorKind::UnexpectedEof, "agent frame header truncated")
        } else {
            e
        }
    })?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(violation(
            io::ErrorKind::InvalidData,
            "zero-length agent frame",
        ));
    }
    if len > MAX_SIGNING_FRAME_BYTES {
        return Err(violation(
            io::ErrorKind::InvalidData,
            "agent frame exceeds the signing frame limit",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            violation(io::ErrorKind::UnexpectedEof, "agent frame body truncated")
        } else {
            e
        }
    })?;
    Ok(Some(body))
}

/// Zero-copy reader for the draft-miller grammar.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > self.0.len() {
            return None;
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(s)
    }
}

/// A parsed `SSH_AGENTC_SIGN_REQUEST` body (after the type byte).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignFields<'a> {
    /// Opaque public key blob (not parsed in M01).
    pub key_blob: &'a [u8],
    /// Data to sign.
    pub data: &'a [u8],
    /// Signature flags.
    pub flags: u32,
}

/// Split a sign request body; `None` on any overrun, short field or trailing
/// byte.
#[doc(hidden)]
#[must_use]
pub fn parse_sign_request(body: &[u8]) -> Option<SignFields<'_>> {
    let mut f = Fields(body);
    let key_blob = f.string()?;
    let data = f.string()?;
    let flags = f.u32()?;
    if !f.0.is_empty() {
        return None;
    }
    Some(SignFields {
        key_blob,
        data,
        flags,
    })
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(s.len()).ok()?.to_be_bytes());
    out.extend_from_slice(s);
    Some(())
}

fn frame(body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() || body.len() > MAX_SIGNING_FRAME_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
    out.extend_from_slice(body);
    Some(out)
}

/// `SSH_AGENT_IDENTITIES_ANSWER` listing at most [`MAX_IDENTITIES`] identities, in
/// the signer's order, stopping before the frame limit would be exceeded.
#[doc(hidden)]
#[must_use]
pub fn identities_frame(identities: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut body = vec![12u8, 0, 0, 0, 0];
    let mut count: u32 = 0;
    for (blob, comment) in identities.iter().take(MAX_IDENTITIES) {
        let need = 8 + blob.len() + comment.len();
        if body.len() + need > MAX_SIGNING_FRAME_BYTES {
            break;
        }
        if put_string(&mut body, blob).is_none()
            || put_string(&mut body, comment.as_bytes()).is_none()
        {
            break;
        }
        count += 1;
    }
    body[1..5].copy_from_slice(&count.to_be_bytes());
    frame(&body).unwrap_or_else(|| empty_identities_frame().to_vec())
}

/// `SSH_AGENT_SIGN_RESPONSE` (14) or `None` if it would exceed the frame limit.
#[doc(hidden)]
#[must_use]
pub fn sign_response_frame(signature: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(5 + signature.len());
    body.push(14);
    put_string(&mut body, signature)?;
    frame(&body)
}

/// The answer for one well-framed agent message: a complete frame and, for a
/// signature, its permit.
pub(crate) async fn answer(
    payload: &[u8],
    signer: &dyn Signer,
    session: &mut SigningSession,
) -> SignOutcome {
    let plain = |frame: Vec<u8>| SignOutcome {
        frame,
        permit: None,
        ungated: false,
    };
    match classify(payload) {
        Ok(AllowedRequest::RequestIdentities) if payload.len() == 1 => {
            plain(identities_frame(&signer.identities(session).await))
        }
        Ok(AllowedRequest::SignRequest) => {
            let Some(req) = payload.get(1..).and_then(parse_sign_request) else {
                return SignOutcome::failure();
            };
            signer
                .sign(session, req.key_blob, req.data, req.flags)
                .await
        }
        Ok(AllowedRequest::SessionBind) => {
            // classify checked the name: type, u32 length, name, then the contents.
            let contents = payload.get(5 + SESSION_BIND.len()..).unwrap_or_default();
            if signer.session_bind(session, contents) {
                plain(success_frame().to_vec())
            } else {
                SignOutcome::failure()
            }
        }
        Ok(AllowedRequest::RequestIdentities) | Err(_) => SignOutcome::failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_is_exact() {
        assert_eq!(classify(&[11]), Ok(AllowedRequest::RequestIdentities));
        assert_eq!(classify(&[13, 0]), Ok(AllowedRequest::SignRequest));
        for t in [17u8, 18, 19, 20, 21, 22, 23, 9, 25, 26] {
            assert_eq!(
                classify(&[t]),
                Err(SigningRefusal::NotPermitted(t)),
                "type {t}"
            );
        }
        let mut ext = vec![27, 0, 0, 0, 24];
        ext.extend_from_slice(b"session-bind@openssh.com");
        assert_eq!(classify(&ext), Ok(AllowedRequest::SessionBind));
        let mut other = vec![27, 0, 0, 0, 5];
        other.extend_from_slice(b"query");
        assert_eq!(classify(&other), Err(SigningRefusal::NotPermitted(27)));
        assert_eq!(
            classify(&[27, 0, 0, 0, 9, b'x']),
            Err(SigningRefusal::Malformed)
        );
        assert_eq!(classify(&[]), Err(SigningRefusal::Malformed));
    }

    #[test]
    fn canned_frames_are_well_formed() {
        assert_eq!(&failure_frame()[..4], &1u32.to_be_bytes());
        assert_eq!(&success_frame()[..4], &1u32.to_be_bytes());
        assert_eq!(&empty_identities_frame()[..4], &5u32.to_be_bytes());
        assert!(well_formed(&failure_frame()));
        assert!(well_formed(&empty_identities_frame()));
        assert!(!well_formed(&[0, 0, 0, 2, 5]));
        assert!(!well_formed(&[0, 0, 0, 0]));
        assert!(!well_formed(&[]));
    }

    #[test]
    fn session_bind_record_is_structural_only() {
        let mut c = Vec::new();
        for s in [&b"hostkey"[..], b"sid", b"sig"] {
            c.extend_from_slice(&(s.len() as u32).to_be_bytes());
            c.extend_from_slice(s);
        }
        let mut ok = c.clone();
        ok.push(1);
        let Some(r) = SessionBindRecord::parse(&ok) else {
            panic!("well-formed contents refused");
        };
        assert_eq!(r.host_key, b"hostkey");
        assert_eq!(r.session_id, b"sid");
        assert_eq!(r.signature, b"sig");
        assert!(r.is_forwarding);
        let mut bad_bool = c.clone();
        bad_bool.push(2);
        assert!(SessionBindRecord::parse(&bad_bool).is_none());
        let mut trailing = ok.clone();
        trailing.push(0);
        assert!(SessionBindRecord::parse(&trailing).is_none());
        assert!(SessionBindRecord::parse(&c).is_none());
        assert!(SessionBindRecord::parse(&ok[..ok.len() - 3]).is_none());
    }
}
