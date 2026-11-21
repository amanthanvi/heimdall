//! The dialer (feature `iroh`; ADR-0012 §1 item 2, §2.1): one connection on `/pigeons/0`,
//! one bidirectional stream of raw bytes.
//!
//! [`dial`] builds its endpoint through [`crate::endpoint::plan_endpoint`] (so every
//! address, relay and hint comes from the policy), connects within a bound, opens the one
//! stream and returns it as a [`PigeonsStream`]. It holds no bytes and does no SSH
//! identification gating: that is the route helper's (m06-plan U5a; ADR-0012 §5.5).
//!
//! **Admission is not visible at dial time.** Pigeons has no admission acknowledgement: a
//! serving side refuses with application close [`crate::lifecycle::CLOSE_REFUSED`] right after
//! the handshake, which can reach the dialer before [`dial`] returns
//! ([`DialError::Failed`] with `admission_refused`) or after it, on the first read or write;
//! [`PigeonsStream::peer_close`] then classifies the cause. QUIC also opens the stream at
//! the server only with the dialer's first byte, so the serving side connects its target
//! only once the dialer has written something.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::{ExposurePolicy, RouteFailureClass};
use iroh::Endpoint;
use iroh::endpoint::{
    ConnectError, ConnectingError, Connection, ConnectionError, RecvStream, SendStream, VarInt,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ALPN;
use crate::endpoint::{Role, close_bounded, contract_id, plan_endpoint};
use crate::keys::{KeySource, KeySourceError};
use crate::lifecycle::{
    CLOSE_BOUND, CLOSE_DONE, CLOSE_LEASE_LOST, CLOSE_REFUSED, CLOSE_REVOKED,
    CLOSE_TARGET_UNAVAILABLE, bounded,
};
use crate::policy::{PolicyError, RouteAddresses};

/// The default connect bound (bind, handshake and stream open together).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What to dial.
#[derive(Debug, Clone, Copy)]
pub struct DialRequest<'a> {
    /// The route's effective exposure policy.
    pub policy: &'a ExposurePolicy,
    /// The serving endpoint.
    pub peer: &'a IrohEndpointId,
    /// The route record's addresses and relay hints.
    pub route: &'a RouteAddresses,
    /// The connect bound.
    pub connect_timeout: Duration,
}

/// Why a dial failed. Internal: no exit code; [`DialError::reason`] and
/// [`DialError::failure_class`] carry the structured cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialError {
    /// The policy, a hint or an address was refused before anything bound.
    Policy(PolicyError),
    /// K_iroh could not be loaded.
    Key(KeySourceError),
    /// The endpoint could not bind its policy's sockets.
    Bind,
    /// The attempt failed: `refused`, `timeout` or `admission_refused`.
    Failed(RouteFailureClass),
}

impl DialError {
    /// The stable reason token.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Policy(p) => p.reason.token(),
            Self::Key(k) => k.reason(),
            Self::Bind => reason::TRANSPORT_UNAVAILABLE,
            Self::Failed(_) => reason::TRANSPORT_REFUSED,
        }
    }

    /// The route-health failure class, for an attempt that was made.
    #[must_use]
    pub fn failure_class(&self) -> Option<RouteFailureClass> {
        match self {
            Self::Failed(c) => Some(*c),
            _ => None,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(p) => write!(f, "{p}"),
            Self::Key(k) => write!(f, "{k}"),
            Self::Bind => write!(f, "{}: endpoint bind failed", self.reason()),
            Self::Failed(c) => write!(f, "{}: {c:?}", self.reason()),
        }
    }
}

impl std::error::Error for DialError {}

/// Why the serving side closed the connection, read from its application close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerClose {
    /// Not admitted (allowlist, authority, suspension or lease): before any byte was
    /// forwarded.
    AdmissionRefused,
    /// Admission withdrawn (the endpoint was revoked) while the stream was live.
    Revoked,
    /// The serving side lost its lease and closed every stream.
    LeaseLost,
    /// The serving side could not reach its loopback target.
    TargetUnavailable,
    /// A normal end.
    Done,
    /// Any other close (timeout, reset, transport error, another code).
    Other,
}

/// One dialed `/pigeons/0` stream: raw bytes both ways. It owns its endpoint; close it
/// with [`PigeonsStream::close`] (bounded).
#[derive(Debug)]
pub struct PigeonsStream {
    endpoint: Endpoint,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl PigeonsStream {
    /// The serving endpoint's ID (authenticated by the handshake).
    #[must_use]
    pub fn remote_id(&self) -> Option<IrohEndpointId> {
        contract_id(&self.conn.remote_id())
    }

    /// Every socket the dialer's endpoint bound.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Why the serving side closed the connection, once it has.
    #[must_use]
    pub fn peer_close(&self) -> Option<PeerClose> {
        self.conn.close_reason().map(|e| peer_close_of(&e))
    }

    /// Finishes the send side, waits (within [`CLOSE_BOUND`]) for the peer to acknowledge
    /// it, closes the connection and closes the endpoint (within [`CLOSE_BOUND`]). Returns
    /// whether the endpoint close completed within its bound.
    pub async fn close(mut self) -> bool {
        let _ = self.send.finish();
        let _ = bounded(CLOSE_BOUND, self.send.stopped()).await;
        self.conn.close(VarInt::from_u32(CLOSE_DONE), b"done");
        close_bounded(&self.endpoint).await
    }
}

impl AsyncRead for PigeonsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for PigeonsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}

/// Dials `request.peer` on `/pigeons/0` under `request.policy` and opens the one stream.
///
/// The bound covers binding, the handshake and opening the stream. On any failure the
/// endpoint is closed within [`CLOSE_BOUND`].
///
/// # Errors
///
/// [`DialError`]: the policy refusals first (before the key is loaded or anything binds),
/// then the key, the bind, and the attempt's failure class.
pub async fn dial(
    request: DialRequest<'_>,
    keys: &dyn KeySource,
) -> Result<PigeonsStream, DialError> {
    let plan = plan_endpoint(
        request.policy,
        Role::Dial {
            peer: request.peer,
            route: request.route,
        },
    )
    .map_err(DialError::Policy)?;
    let peer_addr = plan
        .peer
        .ok_or(DialError::Policy(PolicyError::route("no peer address")))?;
    let secret = keys.load().map_err(DialError::Key)?;
    let deadline = tokio::time::Instant::now() + request.connect_timeout;
    let endpoint = match tokio::time::timeout_at(
        deadline,
        plan.builder.secret_key(secret.secret_key()).bind(),
    )
    .await
    {
        Err(_) => return Err(DialError::Failed(RouteFailureClass::Timeout)),
        Ok(Err(_)) => return Err(DialError::Bind),
        Ok(Ok(ep)) => ep,
    };
    let attempt = async {
        let conn = endpoint
            .connect(peer_addr, ALPN)
            .await
            .map_err(|e| connect_failure(&e))?;
        let (send, recv) = conn.open_bi().await.map_err(|e| connection_failure(&e))?;
        Ok::<_, RouteFailureClass>((conn, send, recv))
    };
    let outcome = match tokio::time::timeout_at(deadline, attempt).await {
        Err(_) => Err(RouteFailureClass::Timeout),
        Ok(Err(class)) => Err(class),
        Ok(Ok((conn, send, recv))) => match conn.close_reason() {
            Some(e) => Err(connection_failure(&e)),
            None => Ok((conn, send, recv)),
        },
    };
    match outcome {
        Ok((conn, send, recv)) => Ok(PigeonsStream {
            endpoint,
            conn,
            send,
            recv,
        }),
        Err(class) => {
            close_bounded(&endpoint).await;
            Err(DialError::Failed(class))
        }
    }
}

fn connect_failure(e: &ConnectError) -> RouteFailureClass {
    match e {
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => connection_failure(source),
        _ => RouteFailureClass::Refused,
    }
}

fn connection_failure(e: &ConnectionError) -> RouteFailureClass {
    match peer_close_of(e) {
        PeerClose::AdmissionRefused => RouteFailureClass::AdmissionRefused,
        _ if matches!(e, ConnectionError::TimedOut) => RouteFailureClass::Timeout,
        _ => RouteFailureClass::Refused,
    }
}

fn peer_close_of(e: &ConnectionError) -> PeerClose {
    let ConnectionError::ApplicationClosed(close) = e else {
        return PeerClose::Other;
    };
    match u64::from(close.error_code) {
        c if c == u64::from(CLOSE_REFUSED) => PeerClose::AdmissionRefused,
        c if c == u64::from(CLOSE_REVOKED) => PeerClose::Revoked,
        c if c == u64::from(CLOSE_LEASE_LOST) => PeerClose::LeaseLost,
        c if c == u64::from(CLOSE_TARGET_UNAVAILABLE) => PeerClose::TargetUnavailable,
        c if c == u64::from(CLOSE_DONE) => PeerClose::Done,
        _ => PeerClose::Other,
    }
}
