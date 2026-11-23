//! ⟨M06 U5a⟩ Failover before the forwarding boundary (ADR-0012 §5.5; m06-plan U5a).
//!
//! 1. **The establishment point** is the receipt, through the candidate, of the server's SSH
//!    identification line (`SSH-…`, ending in LF). Until then the client's bytes are held:
//!    the client side is not read at all. Lines the server sends before its identification
//!    (RFC 4253 §4.2) are buffered, at most [`FailoverConfig::max_pre_identification_bytes`]
//!    (8 KiB) and [`FailoverConfig::max_pre_identification_lines`] (32), and forwarded
//!    unchanged with the identification and anything after it; past either bound, or past the
//!    route's identification wait (10 s by default), the attempt fails as
//!    `identification_timeout`. A server that waits for the client to identify first times
//!    out at that bound.
//! 2. **The forwarding boundary** is the first byte forwarded in either direction, which is
//!    the buffered identification itself. Failover is allowed only before it: a connect
//!    refusal or timeout, a jump leg that ends before identification, the identification
//!    bound. After it every failure is terminal for the attempt and recorded
//!    (`terminal_after_forwarding`): an I/O error on either side, or a jump leg that ends
//!    unsuccessfully.
//! 3. **Never** failed over: a leg's own host-key or authentication failure
//!    ([`DialFailure::Terminal`], [`LegEnd::terminal`]). Never tried: a route that is not in
//!    the planned (approved) list; this module only walks that list, in order.
//! 4. **Route health**: one `RouteHealthPayload` when the attempt is established (`health`,
//!    or `failed_over` when earlier routes failed), one more if it later fails after the
//!    boundary, and one when no route is established (`final_route` absent).
//! 5. ⟨M06 U56; ADR-0012 §5.5 item 5, 2026-11-21⟩ **An Iroh leg identifies the client
//!    first**: a QUIC stream reaches the serving side only once the dialer writes, so on an
//!    Iroh leg the helper reads the client's SSH identification line and sends **only that
//!    line** before the server's identification arrives (no preamble: raw `/pigeons/0`). The
//!    line is validated before anything is sent: it starts with `SSH-2.0-`, ends in CRLF
//!    and is at most 255 bytes including the CRLF (RFC 4253 §4.2), read within the connect's
//!    one client window (the first Iroh route's identification wait; ⟨2026-11-21⟩ a later
//!    Iroh route replays the held line and starts no new client window, so it waits only
//!    for the server). Anything else fails closed with nothing sent to the route.
//!    ⟨M06-W2-R06⟩ The line is read and validated **before the Iroh leg is dialed**: an
//!    invalid or silent client causes no outbound connection to that route (the server's
//!    identification wait starts after the dial, as on every leg).
//!    ⟨Ruling 3, 2026-11-21⟩ Which failures end what ([`ClientIdentification`]): a malformed
//!    or overlong line (or a client that ended first) is terminal for the whole connect,
//!    with a precise diagnostic, and no other route is tried (the client's bytes would be
//!    the same on every route); a timeout waiting for the line is route-local, so the next
//!    approved route may be tried. Neither counts against the Iroh route's health: no
//!    attempt is recorded for it ([`FailoverOutcome::client_failure`] keeps the reason).
//!    Every other client byte stays held. The line is stateless, so it is kept and replayed exactly once to the next
//!    candidate (written first on another Iroh leg; forwarded first, after the server's
//!    identification, on a direct or jump leg). Failover stays allowed until the server's
//!    identification arrives; an Iroh close with Pigeons' refusal before it is
//!    `admission_refused`, failed over. Anything after the server's identification is
//!    terminal, as for every leg. The line's contents are never logged.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::ids::{AccountName, DestinationId, RouteId};
use heimdall_contract::route::{
    RouteAttempt, RouteEventKind, RouteFailureClass, RouteHealthPayload,
};
use heimdall_domain::routes::{PRE_IDENTIFICATION_MAX_BYTES, PRE_IDENTIFICATION_MAX_LINES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{LegPlan, PlannedRoute};

/// The direct leg's connect bound.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 4253 §4.2: the identification line is at most 255 bytes, CR LF included.
pub const IDENTIFICATION_LINE_MAX: usize = 255;

/// The helper's bounds (ADR-0012 §5.5 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverConfig {
    /// Pre-identification bytes buffered (8 KiB).
    pub max_pre_identification_bytes: usize,
    /// Pre-identification lines buffered (32).
    pub max_pre_identification_lines: usize,
    /// The direct leg's connect bound.
    pub connect_timeout: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            max_pre_identification_bytes: PRE_IDENTIFICATION_MAX_BYTES,
            max_pre_identification_lines: PRE_IDENTIFICATION_MAX_LINES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// Why a leg could not be dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialFailure {
    /// Refused (or unavailable in this build): failover allowed.
    Refused,
    /// The connect bound passed: failover allowed.
    Timeout,
    /// The leg's own host-key or authentication failure: never failed over.
    Terminal,
    /// ⟨M06 U56⟩ The Iroh serving side refused admission while the leg was dialed:
    /// failover allowed.
    AdmissionRefused,
}

/// How a leg ended (the jump leg's `ssh`, the Iroh connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LegEnd {
    /// It ended successfully.
    pub success: bool,
    /// It ended on a host-key or authentication failure.
    pub terminal: bool,
    /// ⟨M06 U56⟩ The Iroh serving side closed it with Pigeons' refusal (admission refused).
    pub admission_refused: bool,
}

/// The end of a leg that is a process.
#[async_trait]
pub trait LegEnding: Send {
    /// Wait (bounded) for the leg to end, and say how. Idempotent.
    async fn end(&mut self) -> LegEnd;

    /// End the leg now (an attempt that failed before identification), then as
    /// [`LegEnding::end`].
    async fn abort(&mut self) -> LegEnd {
        self.end().await
    }
}

/// A dialed leg: the stream to the server, and its process end when it has one.
pub struct Leg {
    /// Bytes from the server.
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// Bytes to the server.
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    /// The leg's process, when it is one.
    pub ending: Option<Box<dyn LegEnding>>,
}

/// Opens one planned route's leg.
#[async_trait]
pub trait LegDialer: Send + Sync {
    /// Dial `route` (a direct connect is bounded by `connect_timeout`).
    async fn dial(
        &self,
        route: &PlannedRoute,
        connect_timeout: Duration,
    ) -> Result<Leg, DialFailure>;
}

/// Where the identification scan stands ([`scan_identification`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scan {
    /// Not yet: read more.
    NeedMore,
    /// The identification line ends at byte `end` (exclusive).
    Identified {
        /// One past the identification line's LF.
        end: usize,
    },
    /// A bound was exceeded before identification.
    Overflow,
}

/// Scan the bytes a server sent so far for its identification line (module docs).
#[must_use]
pub fn scan_identification(buf: &[u8], config: &FailoverConfig) -> Scan {
    let mut start = 0usize;
    let mut lines = 0usize;
    loop {
        let rest = &buf[start..];
        let maybe_ident =
            rest.starts_with(b"SSH-") || (rest.len() < 4 && b"SSH-".starts_with(rest));
        let newline = rest.iter().position(|b| *b == b'\n');
        if maybe_ident && !rest.is_empty() {
            return match newline {
                Some(i) if i < IDENTIFICATION_LINE_MAX => Scan::Identified { end: start + i + 1 },
                Some(_) => Scan::Overflow,
                None if rest.len() >= IDENTIFICATION_LINE_MAX => Scan::Overflow,
                None => Scan::NeedMore,
            };
        }
        match newline {
            Some(i) => {
                lines += 1;
                start += i + 1;
                if lines > config.max_pre_identification_lines
                    || start > config.max_pre_identification_bytes
                {
                    return Scan::Overflow;
                }
            }
            None if buf.len() > config.max_pre_identification_bytes => return Scan::Overflow,
            None => return Scan::NeedMore,
        }
    }
}

/// The result of one helper run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverOutcome {
    /// Every route-health result recorded, in order.
    pub health: Vec<RouteHealthPayload>,
    /// The route that was established, if any.
    pub final_route: Option<RouteId>,
    /// A failure after the forwarding boundary ended the attempt.
    pub late_failure: bool,
    /// ⟨2026-11-21, ruling 3⟩ The last reason the client's identification line could not be
    /// sent to an Iroh leg (module docs, item 5). A terminal one ended the connect; neither
    /// kind is recorded as a route attempt.
    pub client_failure: Option<ClientIdentification>,
}

impl FailoverOutcome {
    /// Whether the session was established and ended without a recorded failure.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.final_route.is_some() && !self.late_failure
    }
}

/// How waiting for the identification ended.
enum Establish {
    /// The bytes received so far, ending at or after the identification line.
    Identified(Vec<u8>),
    /// Failed before the boundary; `terminal`: never failed over.
    Failed(RouteFailureClass, bool),
}

/// The failure class of a leg that ended (EOF or an error) before identification, from
/// its ending: a host-key or authentication failure (terminal), an Iroh admission refusal,
/// or a plain refusal.
/// `true` with the class: never failed over.
async fn ended_before_identification(leg: &mut Leg) -> (RouteFailureClass, bool) {
    let end = match leg.ending.as_mut() {
        Some(e) => e.end().await,
        None => LegEnd::default(),
    };
    // A terminal ending is a host-key or authentication failure at the jump host
    // (ADR-0012 §5.5 item 3): its own class, never failed over.
    if end.terminal {
        (RouteFailureClass::AuthenticationOrTrust, true)
    } else if end.admission_refused {
        (RouteFailureClass::AdmissionRefused, false)
    } else {
        (RouteFailureClass::Refused, false)
    }
}

async fn establish(
    leg: &mut Leg,
    deadline: tokio::time::Instant,
    config: &FailoverConfig,
) -> Establish {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = vec![0u8; 4096];
    loop {
        match scan_identification(&buf, config) {
            Scan::Identified { .. } => return Establish::Identified(buf),
            Scan::Overflow => {
                return Establish::Failed(RouteFailureClass::IdentificationTimeout, false);
            }
            Scan::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, leg.reader.read(&mut chunk)).await {
            Err(_) => return Establish::Failed(RouteFailureClass::IdentificationTimeout, false),
            Ok(Ok(0) | Err(_)) => {
                let (class, terminal) = ended_before_identification(leg).await;
                return Establish::Failed(class, terminal);
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// ⟨2026-11-21, ruling 3; ADR-0012 §5.5 item 5⟩ Why the client's identification line could
/// not be sent to an Iroh leg. The client's bytes would be the same on every route, so a
/// malformed or overlong line (or a client that closed first) is terminal for the whole
/// connect: no further route is tried, and the helper reports it precisely
/// ([`Self::message`]). A timeout waiting for the line stays route-local: the next approved
/// route may be tried. Neither counts against the Iroh route's health: no route attempt is
/// recorded for it (the route-health classes describe the route, and this is the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientIdentification {
    /// The first line does not start with `SSH-2.0-` or does not end in CRLF.
    Malformed,
    /// No line end within 255 bytes (RFC 4253 §4.2's bound, CRLF included).
    Overlong,
    /// The client side ended before a complete line.
    Closed,
    /// No complete line within the route's identification wait (route-local).
    Timeout,
}

impl ClientIdentification {
    /// Whether it ends the whole connect (every case but [`Self::Timeout`]).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        !matches!(self, ClientIdentification::Timeout)
    }

    /// The helper's diagnostic (never the line's contents).
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            ClientIdentification::Malformed => {
                "the client's SSH identification line is malformed (it must start with \
                 `SSH-2.0-` and end in CRLF): nothing was forwarded and no other route was tried"
            }
            ClientIdentification::Overlong => {
                "the client's SSH identification line is longer than 255 bytes: nothing was \
                 forwarded and no other route was tried"
            }
            ClientIdentification::Closed => {
                "the client closed before sending its SSH identification line: nothing was \
                 forwarded and no other route was tried"
            }
            ClientIdentification::Timeout => {
                "the client did not send its SSH identification line within the Iroh route's \
                 identification wait: nothing was sent to that route"
            }
        }
    }
}

/// ⟨M06 U56⟩ The client bytes the helper has read before any leg was established (module
/// docs, item 5): only ever the client's identification line and what arrived with it.
#[derive(Debug, Default)]
struct ClientPrefix {
    /// Every byte read from the client so far, in order.
    bytes: Vec<u8>,
    /// Where the client's identification line ends (one past its CRLF), once read and
    /// valid.
    line_end: Option<usize>,
    /// ⟨ruling 3⟩ The client's first bytes cannot be an identification line (malformed,
    /// overlong) or it ended first: terminal for the connect, nothing is sent anywhere.
    failure: Option<ClientIdentification>,
    /// ⟨2026-11-21; ADR-0012 §5.5 item 5, "waited for once"⟩ When the client window of this
    /// connect ends: set by the first Iroh route (now plus its identification wait) and
    /// never moved, so a later Iroh route starts no new window.
    window_ends: Option<tokio::time::Instant>,
}

/// The prefix an identification line sent to an Iroh leg must have (ADR-0012 §5.5 item 5).
const CLIENT_IDENTIFICATION_PREFIX: &[u8] = b"SSH-2.0-";

impl ClientPrefix {
    /// The client's identification line, reading it from `client_in` within the connect's
    /// one client window if it has not been read yet (ADR-0012 §5.5 item 5): it must start
    /// with `SSH-2.0-`, end in CRLF and be at most 255 bytes including the CRLF (RFC 4253
    /// §4.2). Otherwise why not ([`ClientIdentification`]): a terminal failure is kept
    /// (every later call answers it again); a timeout keeps what was read.
    ///
    /// **The window applies once per connect.** The first call opens it (`wait` from now);
    /// every later call, on any later Iroh route, reads against the same end and so waits
    /// no further once it has passed (bytes that have already arrived are still taken). A
    /// held line is replayed without any wait. Nothing read here is sent anywhere until the
    /// caller sends the returned line; its contents are never logged.
    async fn identification<I>(
        &mut self,
        client_in: &mut I,
        wait: Duration,
    ) -> Result<&[u8], ClientIdentification>
    where
        I: AsyncRead + Unpin + Send,
    {
        let deadline = *self
            .window_ends
            .get_or_insert_with(|| tokio::time::Instant::now() + wait);
        let mut chunk = [0u8; IDENTIFICATION_LINE_MAX];
        while self.line_end.is_none() && self.failure.is_none() {
            if let Some(i) = self.bytes.iter().position(|b| *b == b'\n') {
                let line = &self.bytes[..=i];
                if line.len() > IDENTIFICATION_LINE_MAX {
                    self.failure = Some(ClientIdentification::Overlong);
                } else if line.starts_with(CLIENT_IDENTIFICATION_PREFIX) && line.ends_with(b"\r\n")
                {
                    self.line_end = Some(i + 1);
                } else {
                    self.failure = Some(ClientIdentification::Malformed);
                }
                break;
            }
            let n = self.bytes.len().min(CLIENT_IDENTIFICATION_PREFIX.len());
            if self.bytes[..n] != CLIENT_IDENTIFICATION_PREFIX[..n] {
                self.failure = Some(ClientIdentification::Malformed);
                break;
            }
            if self.bytes.len() >= IDENTIFICATION_LINE_MAX {
                self.failure = Some(ClientIdentification::Overlong);
                break;
            }
            // Never read past the line's bound: what is read is held, not sent.
            let room = IDENTIFICATION_LINE_MAX - self.bytes.len();
            match tokio::time::timeout_at(deadline, client_in.read(&mut chunk[..room])).await {
                // The window passed: route-local (another approved route may be tried; a
                // later Iroh route opens no new window).
                Err(_) => return Err(ClientIdentification::Timeout),
                Ok(Ok(0) | Err(_)) => self.failure = Some(ClientIdentification::Closed),
                Ok(Ok(n)) => self.bytes.extend_from_slice(&chunk[..n]),
            }
        }
        match (self.failure, self.line_end) {
            (Some(f), _) => Err(f),
            (None, Some(end)) => Ok(&self.bytes[..end]),
            (None, None) => Err(ClientIdentification::Timeout),
        }
    }

    /// The held client bytes an established leg still needs, before the rest of the client
    /// stream: on a leg that was sent the identification line already (an Iroh leg), what
    /// came after it; on any other leg, everything held.
    fn unsent(&self, line_sent: bool) -> &[u8] {
        match (line_sent, self.line_end) {
            (true, Some(end)) => &self.bytes[end..],
            _ => &self.bytes,
        }
    }
}

/// Write the client's identification line to an Iroh leg (module docs, item 5). `false`
/// when the leg would not take it (it closed: the failure is read from its ending).
async fn send_identification(leg: &mut Leg, line: &[u8], deadline: tokio::time::Instant) -> bool {
    let write = async {
        leg.writer.write_all(line).await?;
        leg.writer.flush().await
    };
    matches!(tokio::time::timeout_at(deadline, write).await, Ok(Ok(())))
}

/// Forward the buffered server `prefix` to the client and the held client bytes `up` to the
/// leg, then both directions, until the server side ends. Returns whether a failure ended
/// the attempt after the boundary.
async fn forward<I, O>(
    leg: Leg,
    prefix: Vec<u8>,
    up: &[u8],
    mut client_in: I,
    mut client_out: O,
) -> bool
where
    I: AsyncRead + Unpin + Send,
    O: AsyncWrite + Unpin + Send,
{
    let Leg {
        mut reader,
        mut writer,
        ending,
    } = leg;
    let prefix_sent = client_out.write_all(&prefix).await.is_ok()
        && client_out.flush().await.is_ok()
        && (up.is_empty() || (writer.write_all(up).await.is_ok() && writer.flush().await.is_ok()));
    if !prefix_sent {
        if let Some(mut e) = ending {
            e.end().await;
        }
        return true;
    }
    let up = async {
        let r = tokio::io::copy(&mut client_in, &mut writer).await;
        let _ = writer.shutdown().await;
        r.is_ok()
    };
    let down = async {
        let r = tokio::io::copy(&mut reader, &mut client_out).await;
        let flushed = client_out.flush().await.is_ok();
        let _ = client_out.shutdown().await;
        r.is_ok() && flushed
    };
    tokio::pin!(up);
    tokio::pin!(down);
    let mut up_ok: Option<bool> = None;
    // The session ends when the server side ends; the client side may stay open (the client
    // is gone or waiting), so it is never awaited after that.
    let down_ok = loop {
        tokio::select! {
            ok = &mut down => break ok,
            ok = &mut up, if up_ok.is_none() => up_ok = Some(ok),
        }
    };
    let mut failed = !down_ok || up_ok == Some(false);
    if let Some(mut e) = ending {
        failed |= !e.end().await.success;
    }
    failed
}

fn payload(
    destination: &DestinationId,
    account: &AccountName,
    attempts: &[RouteAttempt],
    final_route: Option<&RouteId>,
) -> RouteHealthPayload {
    let failed_over = final_route.is_some() && attempts.len() > 1;
    RouteHealthPayload {
        kind: if failed_over {
            RouteEventKind::FailedOver
        } else {
            RouteEventKind::Health
        },
        destination: destination.clone(),
        account: account.clone(),
        attempts: attempts.to_vec(),
        final_route: final_route.cloned(),
    }
}

/// Try `routes` in order with failover before the forwarding boundary, then forward between
/// the client and the established leg (module docs). `record` receives each route-health
/// result as it is produced.
#[allow(clippy::too_many_arguments)]
pub async fn run_failover<D, I, O, F, Fut>(
    destination: &DestinationId,
    account: &AccountName,
    routes: &[PlannedRoute],
    dialer: &D,
    client_in: I,
    client_out: O,
    config: &FailoverConfig,
    record: &F,
) -> FailoverOutcome
where
    D: LegDialer + ?Sized,
    I: AsyncRead + Unpin + Send,
    O: AsyncWrite + Unpin + Send,
    F: Fn(RouteHealthPayload) -> Fut + ?Sized,
    Fut: Future<Output = ()>,
{
    let mut client_in = client_in;
    let mut held = ClientPrefix::default();
    let mut outcome = FailoverOutcome {
        health: Vec::new(),
        final_route: None,
        late_failure: false,
        client_failure: None,
    };
    let mut attempts: Vec<RouteAttempt> = Vec::new();
    // ⟨rev6.5; ADR-0006 §18.9 item 11⟩ Each attempt reports how long it took, bounded.
    let took = |started: tokio::time::Instant| {
        Some(
            u32::try_from(started.elapsed().as_millis())
                .unwrap_or(u32::MAX)
                .min(heimdall_contract::route::ROUTE_ATTEMPT_DURATION_MAX_MS),
        )
    };
    let failed = |route: &PlannedRoute, class, started: tokio::time::Instant| RouteAttempt {
        route: route.id.clone(),
        failure: Some(class),
        duration_ms: took(started),
    };
    for route in routes {
        let started = tokio::time::Instant::now();
        let client_first = matches!(route.leg, LegPlan::Iroh { .. });
        // ⟨M06 U56; M06-W2-R06⟩ An Iroh leg is sent the client's identification line, and
        // only that, before the server's (module docs, item 5). The line is read and
        // validated BEFORE the dial: invalid or silent client bytes cause no outbound
        // connection at all.
        let client_line: Option<Vec<u8>> = if client_first {
            // ⟨2026-11-21⟩ One client window per connect: the first Iroh route opens it.
            match held
                .identification(&mut client_in, route.identification_timeout)
                .await
            {
                Ok(line) => Some(line.to_vec()),
                Err(why) => {
                    // ⟨2026-11-21, ruling 3⟩ The client's failure, not the route's: no
                    // attempt is recorded against the route. A malformed or overlong line
                    // (or a closed client) ends the whole connect; a timeout is route-local.
                    outcome.client_failure = Some(why);
                    if why.is_terminal() {
                        break;
                    }
                    continue;
                }
            }
        } else {
            None
        };
        let mut leg = match dialer.dial(route, config.connect_timeout).await {
            Ok(leg) => leg,
            Err(DialFailure::Refused) => {
                attempts.push(failed(route, RouteFailureClass::Refused, started));
                continue;
            }
            Err(DialFailure::Timeout) => {
                attempts.push(failed(route, RouteFailureClass::Timeout, started));
                continue;
            }
            // ⟨M06-W1-R05⟩ A leg's own host-key or authentication failure while dialing is
            // its own class (rev 6.1), as before identification: never failed over.
            Err(DialFailure::Terminal) => {
                attempts.push(failed(
                    route,
                    RouteFailureClass::AuthenticationOrTrust,
                    started,
                ));
                break;
            }
            Err(DialFailure::AdmissionRefused) => {
                attempts.push(failed(route, RouteFailureClass::AdmissionRefused, started));
                continue;
            }
        };
        let deadline = tokio::time::Instant::now() + route.identification_timeout;
        if let Some(line) = &client_line {
            let sent = send_identification(&mut leg, line, deadline).await;
            if !sent {
                let (class, terminal) = ended_before_identification(&mut leg).await;
                attempts.push(failed(route, class, started));
                if let Some(mut e) = leg.ending.take() {
                    drop(leg);
                    e.abort().await;
                }
                if terminal {
                    break;
                }
                continue;
            }
        }
        match establish(&mut leg, deadline, config).await {
            Establish::Failed(class, terminal) => {
                attempts.push(failed(route, class, started));
                if let Some(mut e) = leg.ending.take() {
                    drop(leg);
                    e.abort().await;
                }
                if terminal {
                    break;
                }
            }
            Establish::Identified(prefix) => {
                attempts.push(RouteAttempt {
                    route: route.id.clone(),
                    failure: None,
                    duration_ms: took(started),
                });
                let established = payload(destination, account, &attempts, Some(&route.id));
                record(established.clone()).await;
                outcome.health.push(established);
                outcome.final_route = Some(route.id.clone());
                let up = held.unsent(client_first).to_vec();
                if forward(leg, prefix, &up, client_in, client_out).await {
                    outcome.late_failure = true;
                    if let Some(last) = attempts.last_mut() {
                        last.failure = Some(RouteFailureClass::TerminalAfterForwarding);
                    }
                    let mut late = payload(destination, account, &attempts, Some(&route.id));
                    late.kind = RouteEventKind::Health;
                    record(late.clone()).await;
                    outcome.health.push(late);
                }
                return outcome;
            }
        }
    }
    let none = payload(destination, account, &attempts, None);
    record(none.clone()).await;
    outcome.health.push(none);
    outcome
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// The attempts without their durations, after checking that each was measured and is
    /// inside the contract's bound (⟨rev6.5; ADR-0006 §18.9 item 11⟩).
    fn untimed(attempts: &[RouteAttempt]) -> Vec<RouteAttempt> {
        attempts
            .iter()
            .map(|a| {
                assert!(
                    a.duration_ms.is_some_and(
                        |ms| ms <= heimdall_contract::route::ROUTE_ATTEMPT_DURATION_MAX_MS
                    ),
                    "{a:?}"
                );
                RouteAttempt {
                    duration_ms: None,
                    ..a.clone()
                }
            })
            .collect()
    }
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::routes::LegPlan;
    use proptest::prelude::*;
    use tokio::io::DuplexStream;

    /// A scripted server behind one route.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Script {
        /// Dial refused.
        DialRefused,
        /// Dial timed out.
        DialTimeout,
        /// A host-key or authentication failure while dialing.
        DialTerminal,
        /// Closes before identifying (`terminal`: on a host-key or authentication failure).
        EofBeforeIdentification { terminal: bool },
        /// Sends nothing (a client-first server).
        Silent,
        /// Sends `lines` pre-identification lines, then identifies, then echoes the client;
        /// `late`: then fails after the boundary.
        Identifies { lines: usize, late: bool },
    }

    #[derive(Default)]
    struct Log {
        dialed: Vec<RouteId>,
        /// Bytes each route's server received from the client, and whether it had identified
        /// before the first of them.
        received: BTreeMap<RouteId, (Vec<u8>, bool)>,
    }

    struct Dialer {
        scripts: BTreeMap<RouteId, Script>,
        log: Arc<Mutex<Log>>,
    }

    struct End(LegEnd);

    #[async_trait]
    impl LegEnding for End {
        async fn end(&mut self) -> LegEnd {
            self.0
        }
    }

    const IDENT: &[u8] = b"SSH-2.0-OpenSSH_test\r\n";

    async fn serve(mut server: DuplexStream, script: Script, id: RouteId, log: Arc<Mutex<Log>>) {
        let Script::Identifies { lines, late } = script else {
            if script == Script::Silent {
                // Hold the stream open until the helper drops it; anything the helper sent
                // here would have reached a server that never identified.
                let mut sink = Vec::new();
                let _ = server.read_to_end(&mut sink).await;
                if !sink.is_empty() {
                    log.lock().unwrap().received.insert(id, (sink, false));
                }
            }
            return;
        };
        for i in 0..lines {
            let _ = server
                .write_all(format!("banner line {i}\r\n").as_bytes())
                .await;
        }
        let _ = server.write_all(IDENT).await;
        let _ = server.write_all(b"after-ident").await;
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf).await.unwrap_or(0);
        if n > 0 {
            let mut l = log.lock().unwrap();
            let entry = l.received.entry(id).or_insert_with(|| (Vec::new(), true));
            entry.0.extend_from_slice(&buf[..n]);
        }
        if !late {
            let _ = server.write_all(&buf[..n]).await;
        }
        // Dropping the stream ends the server side; a late failure is reported by the leg.
    }

    #[async_trait]
    impl LegDialer for Dialer {
        async fn dial(&self, route: &PlannedRoute, _: Duration) -> Result<Leg, DialFailure> {
            self.log.lock().unwrap().dialed.push(route.id.clone());
            let script = self.scripts[&route.id].clone();
            match script {
                Script::DialRefused => return Err(DialFailure::Refused),
                Script::DialTimeout => return Err(DialFailure::Timeout),
                Script::DialTerminal => return Err(DialFailure::Terminal),
                _ => {}
            }
            let (client, server) = tokio::io::duplex(64 * 1024);
            let ending: Option<Box<dyn LegEnding>> = match &script {
                Script::EofBeforeIdentification { terminal } => Some(Box::new(End(LegEnd {
                    success: false,
                    terminal: *terminal,
                    admission_refused: false,
                }))),
                Script::Identifies { late: true, .. } => Some(Box::new(End(LegEnd {
                    success: false,
                    terminal: false,
                    admission_refused: false,
                }))),
                _ => None,
            };
            tokio::spawn(serve(server, script, route.id.clone(), self.log.clone()));
            let (reader, writer) = tokio::io::split(client);
            Ok(Leg {
                reader: Box::new(reader),
                writer: Box::new(writer),
                ending,
            })
        }
    }

    fn planned(n: u8) -> PlannedRoute {
        PlannedRoute {
            id: RouteId::from_random_bytes([n; 16]),
            leg: LegPlan::Direct {
                host: "127.0.0.1".into(),
                port: 1,
            },
            identification_timeout: Duration::from_secs(10),
        }
    }

    /// Run the helper over `scripts` (route i has script i), with the client writing
    /// `b"hello"` and then waiting for the echo.
    fn run(scripts: &[Script]) -> (FailoverOutcome, Log, Vec<u8>, Vec<RouteHealthPayload>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let routes: Vec<PlannedRoute> =
                (0..scripts.len()).map(|i| planned(i as u8 + 1)).collect();
            let log = Arc::new(Mutex::new(Log::default()));
            let dialer = Dialer {
                scripts: routes
                    .iter()
                    .zip(scripts)
                    .map(|(r, s)| (r.id.clone(), s.clone()))
                    .collect(),
                log: log.clone(),
            };
            let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
            let (helper_in, helper_out) = tokio::io::split(helper_side);
            let (mut client_read, mut client_write) = tokio::io::split(client_side);
            // The client writes first (as an OpenSSH client does), then reads until EOF.
            client_write.write_all(b"hello").await.unwrap();
            let reader = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = client_read.read_to_end(&mut got).await;
                got
            });
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let rec = recorded.clone();
            let record = move |p: RouteHealthPayload| {
                rec.lock().unwrap().push(p);
                async {}
            };
            let outcome = run_failover(
                &DestinationId::parse("lab").unwrap(),
                &AccountName::parse("deploy").unwrap(),
                &routes,
                &dialer,
                helper_in,
                helper_out,
                &FailoverConfig::default(),
                &record,
            )
            .await;
            drop(client_write);
            let got = reader.await.unwrap();
            let log = std::mem::take(&mut *log.lock().unwrap());
            let recorded = recorded.lock().unwrap().clone();
            (outcome, log, got, recorded)
        })
    }

    #[test]
    fn scan_finds_the_identification_within_bounds() {
        let c = FailoverConfig::default();
        assert_eq!(scan_identification(b"", &c), Scan::NeedMore);
        assert_eq!(scan_identification(b"SS", &c), Scan::NeedMore);
        assert_eq!(scan_identification(b"SSH-2.0-x", &c), Scan::NeedMore);
        assert_eq!(
            scan_identification(b"SSH-2.0-x\r\nKEX", &c),
            Scan::Identified { end: 11 }
        );
        assert_eq!(
            scan_identification(b"hello\r\nworld\nSSH-2.0-x\n", &c),
            Scan::Identified { end: 23 }
        );
        let many = "l\n".repeat(32) + "SSH-2.0-x\n";
        assert!(matches!(
            scan_identification(many.as_bytes(), &c),
            Scan::Identified { .. }
        ));
        let too_many = "l\n".repeat(33) + "SSH-2.0-x\n";
        assert_eq!(scan_identification(too_many.as_bytes(), &c), Scan::Overflow);
        let too_long = "x".repeat(8 * 1024 + 1);
        assert_eq!(scan_identification(too_long.as_bytes(), &c), Scan::Overflow);
        // The bound counts every pre-identification byte, line ends included.
        let long_lines = format!("{}\n", "x".repeat(8 * 1024 - 1)) + "SSH-2.0-x\n";
        assert!(matches!(
            scan_identification(long_lines.as_bytes(), &c),
            Scan::Identified { .. }
        ));
        let over = format!("{}\n", "x".repeat(8 * 1024)) + "SSH-2.0-x\n";
        assert_eq!(scan_identification(over.as_bytes(), &c), Scan::Overflow);
        let ident_too_long = format!("SSH-2.0-{}\n", "x".repeat(300));
        assert_eq!(
            scan_identification(ident_too_long.as_bytes(), &c),
            Scan::Overflow
        );
    }

    /// ADR-0012 §5.5: pre-identification lines are forwarded unchanged, in order, with the
    /// identification; the client's bytes reach the server only after it identified.
    #[test]
    fn pre_identification_lines_are_forwarded_in_order() {
        let (outcome, log, got, recorded) = run(&[Script::Identifies {
            lines: 3,
            late: false,
        }]);
        assert!(outcome.succeeded(), "{outcome:?}");
        let expected = b"banner line 0\r\nbanner line 1\r\nbanner line 2\r\nSSH-2.0-OpenSSH_test\r\nafter-identhello";
        assert_eq!(got, expected);
        assert_eq!(log.received.values().next().unwrap().0, b"hello");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, RouteEventKind::Health);
        assert_eq!(recorded[0].final_route, Some(planned(1).id));
    }

    /// A client-first server times out at the bound (`identification_timeout`) and the next
    /// approved route is tried; the result is `failed_over`.
    #[test]
    fn a_client_first_server_times_out_and_fails_over() {
        let (outcome, _, got, recorded) = run(&[
            Script::Silent,
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.succeeded());
        assert!(got.starts_with(IDENT));
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, RouteEventKind::FailedOver);
        assert_eq!(
            untimed(&recorded[0].attempts),
            [
                RouteAttempt {
                    route: planned(1).id,
                    failure: Some(RouteFailureClass::IdentificationTimeout),
                    duration_ms: None,
                },
                RouteAttempt {
                    route: planned(2).id,
                    failure: None,
                    duration_ms: None,
                },
            ]
        );
    }

    /// After the boundary a failure is terminal and recorded; no later route is tried.
    #[test]
    fn a_late_failure_is_terminal_and_recorded() {
        let (outcome, log, _, recorded) = run(&[
            Script::Identifies {
                lines: 0,
                late: true,
            },
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.late_failure);
        assert_eq!(
            log.dialed,
            [planned(1).id],
            "never failed over after the boundary"
        );
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            untimed(&recorded[1].attempts),
            [RouteAttempt {
                route: planned(1).id,
                failure: Some(RouteFailureClass::TerminalAfterForwarding),
                duration_ms: None,
            }]
        );
        assert_eq!(recorded[1].final_route, Some(planned(1).id));
    }

    /// A host-key or authentication failure of a leg (while dialing or before
    /// identification) is never failed over.
    #[test]
    fn host_key_or_authentication_failures_are_never_failed_over() {
        for first in [
            Script::DialTerminal,
            Script::EofBeforeIdentification { terminal: true },
        ] {
            let (outcome, log, _, recorded) = run(&[
                first.clone(),
                Script::Identifies {
                    lines: 0,
                    late: false,
                },
            ]);
            assert_eq!(outcome.final_route, None, "{first:?}");
            assert_eq!(log.dialed, [planned(1).id], "{first:?}");
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].final_route, None);
            // ⟨M06-W1-R05⟩ Both a dial-time and a pre-identification host-key or
            // authentication failure are recorded `authentication_or_trust`.
            assert_eq!(
                untimed(&recorded[0].attempts),
                [RouteAttempt {
                    route: planned(1).id,
                    failure: Some(RouteFailureClass::AuthenticationOrTrust),
                    duration_ms: None,
                }],
                "{first:?}"
            );
        }
        // Without the host-key or authentication marker, a jump leg ending before
        // identification is failed over.
        let (outcome, log, _, _) = run(&[
            Script::EofBeforeIdentification { terminal: false },
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.succeeded());
        assert_eq!(log.dialed.len(), 2);
    }

    // --- ⟨M06 U56⟩ the Iroh leg's identification gating (module docs, item 5) ---------

    const CLIENT_IDENT: &[u8] = b"SSH-2.0-OpenSSH_client\r\n";

    /// A scripted Iroh serving side: like a QUIC stream, it sees nothing until the dialer
    /// writes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IrohScript {
        /// Reads the client's line, then identifies and echoes.
        Identifies,
        /// Reads the client's line, then closes with Pigeons' refusal (admission refused).
        Refuses,
        /// Reads the client's line, then dies (closes with no refusal code).
        Dies,
    }

    #[derive(Default)]
    struct IrohLog {
        dialed: Vec<RouteId>,
        /// Per route: the bytes received before it identified, and after.
        before: BTreeMap<RouteId, Vec<u8>>,
        after: BTreeMap<RouteId, Vec<u8>>,
    }

    struct IrohDialer {
        /// Route -> Some(script) for an Iroh route, None for a direct one that identifies.
        scripts: BTreeMap<RouteId, Option<IrohScript>>,
        log: Arc<Mutex<IrohLog>>,
    }

    async fn serve_iroh(
        mut server: DuplexStream,
        script: Option<IrohScript>,
        id: RouteId,
        log: Arc<Mutex<IrohLog>>,
    ) {
        let mut before = Vec::new();
        if script.is_some() {
            // Read until the client's line ends (a server that waits for the dialer).
            let mut byte = [0u8; 1];
            while !before.ends_with(b"\n") {
                match server.read(&mut byte).await {
                    Ok(1) => before.push(byte[0]),
                    _ => break,
                }
            }
            // Anything else that arrived before identification is recorded too.
            let mut extra = [0u8; 64];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(50), server.read(&mut extra)).await
            {
                before.extend_from_slice(&extra[..n]);
            }
        }
        log.lock().unwrap().before.insert(id.clone(), before);
        if matches!(script, Some(IrohScript::Refuses | IrohScript::Dies)) {
            return;
        }
        let _ = server.write_all(IDENT).await;
        let mut buf = [0u8; 128];
        let mut got = Vec::new();
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(200), server.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let _ = server.write_all(&got).await;
        log.lock().unwrap().after.insert(id, got);
    }

    #[async_trait]
    impl LegDialer for IrohDialer {
        async fn dial(&self, route: &PlannedRoute, _: Duration) -> Result<Leg, DialFailure> {
            self.log.lock().unwrap().dialed.push(route.id.clone());
            let script = self.scripts[&route.id];
            let (client, server) = tokio::io::duplex(64 * 1024);
            let ending: Option<Box<dyn LegEnding>> = match script {
                Some(IrohScript::Refuses) => Some(Box::new(End(LegEnd {
                    success: false,
                    terminal: false,
                    admission_refused: true,
                }))),
                _ => None,
            };
            tokio::spawn(serve_iroh(
                server,
                script,
                route.id.clone(),
                self.log.clone(),
            ));
            let (reader, writer) = tokio::io::split(client);
            Ok(Leg {
                reader: Box::new(reader),
                writer: Box::new(writer),
                ending,
            })
        }
    }

    fn planned_iroh(n: u8) -> PlannedRoute {
        PlannedRoute {
            id: RouteId::from_random_bytes([n; 16]),
            leg: LegPlan::Iroh {
                endpoint: heimdall_contract::ids::IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                direct_addresses: vec!["127.0.0.1:1".into()],
                exposure: heimdall_contract::route::ExposurePolicy::default(),
                external_roost: false,
            },
            identification_timeout: Duration::from_secs(10),
        }
    }

    /// Run the helper over `legs` (route i is Iroh with its script, or direct), the client
    /// writing `client` and then waiting for the echo.
    fn run_iroh(
        client: &[u8],
        legs: &[Option<IrohScript>],
    ) -> (FailoverOutcome, IrohLog, Vec<u8>, Vec<RouteHealthPayload>) {
        let (outcome, log, got, recorded, _) = run_iroh_timed(client, legs);
        (outcome, log, got, recorded)
    }

    /// [`run_iroh`], also returning how long (virtual time) the helper ran.
    fn run_iroh_timed(
        client: &[u8],
        legs: &[Option<IrohScript>],
    ) -> (
        FailoverOutcome,
        IrohLog,
        Vec<u8>,
        Vec<RouteHealthPayload>,
        Duration,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let routes: Vec<PlannedRoute> = legs
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let n = i as u8 + 1;
                    if l.is_some() {
                        planned_iroh(n)
                    } else {
                        planned(n)
                    }
                })
                .collect();
            let log = Arc::new(Mutex::new(IrohLog::default()));
            let dialer = IrohDialer {
                scripts: routes
                    .iter()
                    .zip(legs)
                    .map(|(r, l)| (r.id.clone(), *l))
                    .collect(),
                log: log.clone(),
            };
            let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
            let (helper_in, helper_out) = tokio::io::split(helper_side);
            let (mut client_read, mut client_write) = tokio::io::split(client_side);
            client_write.write_all(client).await.unwrap();
            let reader = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = client_read.read_to_end(&mut got).await;
                got
            });
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let rec = recorded.clone();
            let record = move |p: RouteHealthPayload| {
                rec.lock().unwrap().push(p);
                async {}
            };
            let started = tokio::time::Instant::now();
            let outcome = run_failover(
                &DestinationId::parse("lab").unwrap(),
                &AccountName::parse("deploy").unwrap(),
                &routes,
                &dialer,
                helper_in,
                helper_out,
                &FailoverConfig::default(),
                &record,
            )
            .await;
            let elapsed = started.elapsed();
            drop(client_write);
            let got = reader.await.unwrap();
            let log = std::mem::take(&mut *log.lock().unwrap());
            let recorded = recorded.lock().unwrap().clone();
            (outcome, log, got, recorded, elapsed)
        })
    }

    /// ⟨M06 U56⟩ On an Iroh leg the server receives the client's identification line and
    /// nothing else before it identifies; the held bytes follow only after.
    #[test]
    fn an_iroh_leg_receives_only_the_client_identification_before_the_server_identifies() {
        let client = [CLIENT_IDENT, b"held-kexinit"].concat();
        let (outcome, log, got, recorded) = run_iroh(&client, &[Some(IrohScript::Identifies)]);
        assert!(outcome.succeeded(), "{outcome:?}");
        let id = planned_iroh(1).id;
        assert_eq!(
            log.before[&id], CLIENT_IDENT,
            "only the identification line"
        );
        assert_eq!(log.after[&id], b"held-kexinit");
        assert!(got.starts_with(IDENT));
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].final_route, Some(id));
    }

    /// ⟨M06 U56; ADR-0012 §5.5 item 5 "replay on failover"⟩ Route 1 receives the
    /// identification line and dies before the server's identification (with Pigeons'
    /// refusal: `admission_refused`; without: `refused`), and is failed over; route 2
    /// receives the same bytes exactly once (an Iroh candidate: the line, then the held
    /// bytes only after it identified; a direct one: everything after it identified), and the
    /// session completes.
    #[test]
    fn an_iroh_refusal_fails_over_and_the_identification_line_is_replayed() {
        let client = [CLIENT_IDENT, b"held"].concat();
        let cases = [
            (IrohScript::Refuses, RouteFailureClass::AdmissionRefused),
            (IrohScript::Dies, RouteFailureClass::Refused),
        ];
        for ((dies, class), next) in cases
            .into_iter()
            .flat_map(|c| [(c, Some(IrohScript::Identifies)), (c, None)])
        {
            let (outcome, log, got, recorded) = run_iroh(&client, &[Some(dies), next]);
            assert!(outcome.succeeded(), "{next:?}: {outcome:?}");
            let first = planned_iroh(1).id;
            let second = if next.is_some() {
                planned_iroh(2).id
            } else {
                planned(2).id
            };
            assert_eq!(log.dialed, [first.clone(), second.clone()]);
            assert_eq!(log.before[&first], CLIENT_IDENT);
            if next.is_some() {
                assert_eq!(log.before[&second], CLIENT_IDENT);
                assert_eq!(log.after[&second], b"held");
            } else {
                assert!(
                    log.before[&second].is_empty(),
                    "direct: nothing before identifying"
                );
                assert_eq!(
                    log.after[&second], client,
                    "the line first, then the held bytes"
                );
            }
            assert!(got.starts_with(IDENT));
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].kind, RouteEventKind::FailedOver);
            assert_eq!(
                untimed(std::slice::from_ref(&recorded[0].attempts[0]))[0],
                RouteAttempt {
                    route: first,
                    failure: Some(class),
                    duration_ms: None,
                },
                "{dies:?}"
            );
        }
    }

    /// The bytes route `id`'s server saw, before and after it identified.
    fn seen(log: &IrohLog, id: &RouteId) -> usize {
        log.before.get(id).map_or(0, Vec::len) + log.after.get(id).map_or(0, Vec::len)
    }

    /// ⟨M06 U56; ADR-0012 §5.5 item 5; ruling 3 (2026-11-21)⟩ A first client line that is
    /// not `SSH-2.0-…` CRLF within 255 bytes (another version, a bare LF, 256 bytes with no
    /// CRLF, not SSH) is terminal for the whole connect: ⟨M06-W2-R06⟩ no route is dialed at
    /// all (the line is validated before the Iroh dial, so not even that route; no later
    /// Iroh or direct route either), no route is established, nothing is recorded against
    /// the route, and the precise reason is kept.
    #[test]
    fn an_invalid_client_identification_ends_the_whole_connect() {
        let long = [b"SSH-2.0-".as_slice(), &[b'x'; 248]].concat();
        assert_eq!(long.len(), 256);
        let inputs: [(&[u8], ClientIdentification); 4] = [
            (b"SSH-1.99-old\r\n", ClientIdentification::Malformed),
            (b"SSH-2.0-bare_lf\n", ClientIdentification::Malformed),
            (&long, ClientIdentification::Overlong),
            (b"hello\r\n", ClientIdentification::Malformed),
        ];
        for (input, why) in inputs {
            for next in [Some(IrohScript::Identifies), None] {
                let (outcome, log, got, recorded) =
                    run_iroh(input, &[Some(IrohScript::Identifies), next]);
                let first = planned_iroh(1).id;
                assert_eq!(outcome.final_route, None, "{input:?}");
                assert_eq!(outcome.client_failure, Some(why), "{input:?}");
                assert_eq!(seen(&log, &first), 0, "nothing forwarded: {input:?}");
                assert!(
                    log.dialed.is_empty(),
                    "no dial at all, the Iroh route included ({next:?}): {input:?}"
                );
                assert!(got.is_empty(), "nothing reached the client: {input:?}");
                assert_eq!(recorded.len(), 1);
                assert!(
                    recorded[0].attempts.is_empty(),
                    "not counted against the route: {input:?}"
                );
            }
            assert!(why.is_terminal());
        }
        // The largest valid line (255 bytes including the CRLF) is accepted.
        let max = [b"SSH-2.0-".as_slice(), &[b'x'; 245], b"\r\n"].concat();
        assert_eq!(max.len(), 255);
        let (outcome, log, _, _) = run_iroh(&max, &[Some(IrohScript::Identifies)]);
        assert!(outcome.succeeded(), "{outcome:?}");
        assert_eq!(outcome.client_failure, None);
        assert_eq!(log.before[&planned_iroh(1).id], max);
    }

    /// ⟨Ruling 3⟩ A silent client (no line before the route's identification wait) sends
    /// nothing to the Iroh route, which is not even dialed (M06-W2-R06); the timeout is
    /// route-local and not counted against it.
    #[test]
    fn a_silent_client_sends_nothing_to_an_iroh_route() {
        let (outcome, log, got, recorded) = run_iroh(b"", &[Some(IrohScript::Identifies)]);
        let id = planned_iroh(1).id;
        assert_eq!(outcome.final_route, None);
        assert_eq!(outcome.client_failure, Some(ClientIdentification::Timeout));
        assert_eq!(seen(&log, &id), 0);
        assert!(log.dialed.is_empty(), "no dial for a silent client");
        assert!(got.is_empty());
        assert!(recorded[0].attempts.is_empty(), "{recorded:?}");
    }

    /// ⟨Ruling 3⟩ A timeout waiting for the client's line is route-local: the next approved
    /// route (here a direct one) is tried and used; the Iroh route got nothing, was not
    /// dialed (M06-W2-R06), and no attempt is recorded against it.
    #[test]
    fn a_client_line_timeout_is_route_local() {
        let (outcome, log, got, recorded) = run_iroh(b"", &[Some(IrohScript::Identifies), None]);
        let (first, second) = (planned_iroh(1).id, planned(2).id);
        assert!(outcome.succeeded(), "{outcome:?}");
        assert_eq!(outcome.final_route, Some(second.clone()));
        assert_eq!(outcome.client_failure, Some(ClientIdentification::Timeout));
        assert_eq!(log.dialed, std::slice::from_ref(&second));
        assert_eq!(seen(&log, &first), 0);
        assert!(got.starts_with(IDENT));
        assert_eq!(
            untimed(&recorded[0].attempts),
            [RouteAttempt {
                route: second,
                failure: None,
                duration_ms: None,
            }]
        );
    }

    /// ⟨2026-11-21; ADR-0012 §5.5 item 5, "waited for once"⟩ The client window applies once
    /// per connect: with a silent client and two Iroh routes, the second Iroh route starts
    /// no new client window (the whole connect waits one window, not two), neither route is
    /// dialed, and nothing is recorded against either.
    #[test]
    fn a_second_iroh_route_starts_no_new_client_window() {
        let (outcome, log, got, recorded, elapsed) = run_iroh_timed(
            b"",
            &[Some(IrohScript::Identifies), Some(IrohScript::Identifies)],
        );
        let window = planned_iroh(1).identification_timeout;
        assert_eq!(outcome.final_route, None);
        assert_eq!(outcome.client_failure, Some(ClientIdentification::Timeout));
        assert!(log.dialed.is_empty(), "no dial for a silent client");
        assert!(got.is_empty());
        assert!(recorded[0].attempts.is_empty(), "{recorded:?}");
        assert!(
            elapsed >= window && elapsed < window + Duration::from_secs(1),
            "one client window for the connect, not one per Iroh route: {elapsed:?}"
        );
    }

    fn script() -> impl Strategy<Value = Script> {
        prop_oneof![
            Just(Script::DialRefused),
            Just(Script::DialTimeout),
            Just(Script::DialTerminal),
            any::<bool>().prop_map(|terminal| Script::EofBeforeIdentification { terminal }),
            Just(Script::Silent),
            (0usize..40, any::<bool>())
                .prop_map(|(lines, late)| Script::Identifies { lines, late }),
        ]
    }

    /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (the crate's convention).
    fn config() -> ProptestConfig {
        use proptest::test_runner::{FileFailurePersistence, RngSeed};
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x4d30_3655_3561_0001);
        }
        c
    }

    proptest! {
        #![proptest_config(config())]

        /// m06-plan U5a property: failover never selects a route outside the approved
        /// (planned) list and never fires after the first forwarded byte; it stops at a
        /// host-key or authentication failure; client bytes reach a server only after that
        /// server identified; the health result names exactly the routes tried.
        #[test]
        fn failover_stays_on_approved_routes_and_before_the_first_byte(
            scripts in proptest::collection::vec(script(), 1..6)
        ) {
            let (outcome, log, _, recorded) = run(&scripts);
            let approved: Vec<RouteId> = (0..scripts.len()).map(|i| planned(i as u8 + 1).id).collect();
            // Only approved routes, each at most once, in preference order.
            prop_assert!(log.dialed.len() <= approved.len());
            prop_assert_eq!(&log.dialed[..], &approved[..log.dialed.len()]);
            // The walk stops at the first route that identified (the boundary) or failed
            // terminally; every earlier route failed before any byte was forwarded.
            for (i, id) in log.dialed.iter().enumerate() {
                let s = &scripts[i];
                let stops = matches!(s,
                    Script::DialTerminal
                    | Script::EofBeforeIdentification { terminal: true }
                    | Script::Identifies { lines: 0..=32, .. });
                if stops {
                    prop_assert_eq!(i, log.dialed.len() - 1, "route {} stops the walk", id);
                }
            }
            // Client bytes went only to an identified server.
            for (id, (bytes, identified)) in &log.received {
                prop_assert!(*identified);
                prop_assert_eq!(Some(id), outcome.final_route.as_ref());
                prop_assert!(bytes.len() <= 5);
            }
            // The health result: the routes tried, in order; at most one has no failure, and
            // it is the final route.
            let last = recorded.last().unwrap();
            let tried: Vec<RouteId> = last.attempts.iter().map(|a| a.route.clone()).collect();
            prop_assert_eq!(&tried, &log.dialed);
            prop_assert_eq!(&last.final_route, &outcome.final_route);
            let used: Vec<_> = last.attempts.iter().filter(|a| a.failure.is_none()).collect();
            prop_assert!(used.len() <= 1);
            if let Some(u) = used.first() {
                prop_assert_eq!(Some(&u.route), outcome.final_route.as_ref());
            }
        }
    }
}
