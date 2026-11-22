//! The serving side (feature `iroh`; ADR-0012 §2.3): accept on `/pigeons/0`, admit only
//! allowlisted endpoints the authority admits under a held lease, and forward the one stream
//! to the loopback target.
//!
//! Admission is checked at three points, all under one lock with the suspension set and the
//! session registry, so a suspend can never miss a session:
//!
//! 1. **After the handshake** (an endpoint hook): a refused peer's connection is closed with
//!    [`CLOSE_REFUSED`] before the server ever sees it, so no stream is accepted and the
//!    target sees nothing.
//! 2. **At registration** of the admitted connection.
//! 3. **After the stream arrives and before the target is connected** (time has passed).
//!
//! Each check requires: the server not stopped; the peer on the [`Allowlist`]; the peer not
//! suspended; the lease held (not revoked) for exactly the generation the server last
//! acknowledged; and the authority admitting the peer at that generation.
//!
//! **Lease loss** (ADR-0012 §2.3 item 3) stops all admission and closes every stream at once
//! ([`CLOSE_LEASE_LOST`]). The lease is read on every admission check, on every signal and by
//! a watchdog every [`LEASE_POLL_INTERVAL`]:
//! * a lease reporting a **newer generation than the server acknowledged** (an
//!   unacknowledged generation change) is a lease loss: every live connection is closed at
//!   once and admission stops. The server keeps running and resumes admission only under a
//!   [`crate::admission::LeaseGrant`] for the new generation;
//! * a lease reporting an **older** generation is an acknowledgement still in flight: new
//!   admissions are refused until it catches up, and nothing is closed;
//! * a lease reported **lost** (or the signal [`AdmissionSignal::LeaseLost`]: channel EOF,
//!   runtime exit) stops the server: every connection closed, the endpoint closed within
//!   [`crate::lifecycle::CLOSE_BOUND`], and [`Server::run`] returns.
//!
//! [`Server::run`] also serves the authority's other signals: a suspend closes the named
//! endpoints' live connections ([`CLOSE_REVOKED`]), waits for their sessions to end (their
//! target sockets dropped) within [`SESSION_DRAIN_BOUND`], and acknowledges; a grant
//! restores the lease for its generation and acknowledges.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::IrohEndpointId;
use heimdall_contract::route::ExposurePolicy;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, EndpointHooks, Incoming, QuicTransportConfig, Side, VarInt,
};
use iroh::{Endpoint, EndpointId};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinSet;

use crate::ALPN;
use crate::admission::{
    AdmissionAuthority, AdmissionSignal, Allowlist, AuthorityGeneration, GrantReport, LeaseGrant,
    LeaseLoss, LeaseState, ServeConfigError, SuspendReport, SuspendRequest,
};
use crate::endpoint::{Role, close_bounded, contract_id, iroh_id, plan_endpoint};
use crate::keys::{KeySource, KeySourceError};
use crate::lifecycle::{
    CLOSE_DONE, CLOSE_LEASE_LOST, CLOSE_REFUSED, CLOSE_REVOKED, CLOSE_TARGET_UNAVAILABLE,
    LEASE_POLL_INTERVAL, SESSION_DRAIN_BOUND, bounded,
};
use crate::policy::PolicyError;
use crate::target::LoopbackTarget;

/// How long a session whose two directions both ended waits for the dialer to close the
/// connection (so the last bytes are delivered) before closing it itself.
const LINGER: Duration = Duration::from_secs(2);

/// A serve configuration: the endpoint's policy, the allowlist and the target.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// The serving endpoint's effective exposure policy.
    pub policy: ExposurePolicy,
    /// The enrolled clients (required, nonempty).
    pub allowlist: Allowlist,
    /// `127.0.0.1:<sshd port>` or `[::1]:<sshd port>`.
    pub target: LoopbackTarget,
}

/// Why the server could not start. Internal; [`ServeError::reason`] is the reason token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError {
    /// The configuration was refused.
    Config(ServeConfigError),
    /// The policy was refused.
    Policy(PolicyError),
    /// The authority could not be read: the child is not started (ADR-0012 §2.3 item 5).
    AuthorityLost(LeaseLoss),
    /// K_iroh could not be loaded.
    Key(KeySourceError),
    /// The endpoint could not bind its policy's sockets.
    Bind,
}

impl ServeError {
    /// The stable reason token.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Config(c) => c.reason(),
            Self::Policy(p) => p.reason.token(),
            Self::AuthorityLost(l) => l.reason(),
            Self::Key(k) => k.reason(),
            Self::Bind => reason::TRANSPORT_UNAVAILABLE,
        }
    }
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(c) => write!(f, "{c}"),
            Self::Policy(p) => write!(f, "{p}"),
            Self::AuthorityLost(l) => write!(f, "{}: {l:?}", l.reason()),
            Self::Key(k) => write!(f, "{k}"),
            Self::Bind => write!(f, "{}: endpoint bind failed", self.reason()),
        }
    }
}

impl std::error::Error for ServeError {}

/// Why [`Server::run`] returned. Internal (no exit code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeExit {
    /// The lease was lost; every stream was closed (`transport_authority_lost`).
    LeaseLost(LeaseLoss),
    /// [`ShutdownHandle::shutdown`] was called.
    Shutdown,
    /// The endpoint closed underneath the server.
    EndpointClosed,
}

/// Stops a running server (every stream closed, the endpoint closed within its bound).
#[derive(Debug, Clone)]
pub struct ShutdownHandle(Arc<Notify>);

impl ShutdownHandle {
    /// Asks the server to stop.
    pub fn shutdown(&self) {
        self.0.notify_one();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopCause {
    LeaseLost(LeaseLoss),
    Shutdown,
    EndpointClosed,
}

struct Session {
    peer: EndpointId,
    conn: Connection,
    done: oneshot::Receiver<()>,
}

struct State {
    acked: AuthorityGeneration,
    /// The lease was lost to an unacknowledged generation change: every stream was closed
    /// and admission waits for a grant.
    lease_revoked: bool,
    stopped: Option<StopCause>,
    suspended: BTreeSet<EndpointId>,
    sessions: BTreeMap<u64, Session>,
    next_session: u64,
}

struct Shared<A> {
    authority: Arc<A>,
    allowlist: BTreeMap<EndpointId, IrohEndpointId>,
    target: LoopbackTarget,
    state: Mutex<State>,
    lease_lost: Notify,
}

impl<A> std::fmt::Debug for Shared<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("allowlist", &self.allowlist.len())
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl<A: AdmissionAuthority> Shared<A> {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The admission check (see the module docs). Called with the state locked.
    fn admits(&self, st: &mut State, peer: &EndpointId) -> bool {
        if st.stopped.is_some() {
            return false;
        }
        let Some(id) = self.allowlist.get(peer) else {
            return false;
        };
        if st.suspended.contains(peer) {
            return false;
        }
        match self.lease_gate(st) {
            Some(g) => self.authority.is_admitted(g, id),
            None => false,
        }
    }

    /// Reads the lease (state locked) and applies it: `Some(generation)` when admission may
    /// proceed at that generation. A lost lease stops the server; a newer generation than
    /// acknowledged revokes the lease (every stream closed) until a grant; an older one is an
    /// acknowledgement in flight.
    fn lease_gate(&self, st: &mut State) -> Option<AuthorityGeneration> {
        if st.stopped.is_some() {
            return None;
        }
        match self.authority.lease() {
            LeaseState::Lost(loss) => {
                Self::stop_locked(st, StopCause::LeaseLost(loss));
                self.lease_lost.notify_one();
                None
            }
            LeaseState::Held(g) if g > st.acked => {
                if !st.lease_revoked {
                    st.lease_revoked = true;
                    Self::close_all_locked(st, CLOSE_LEASE_LOST, b"lease lost");
                }
                None
            }
            LeaseState::Held(g) if g < st.acked || st.lease_revoked => None,
            LeaseState::Held(g) => Some(g),
        }
    }

    fn close_all_locked(st: &State, code: u32, reason: &[u8]) {
        for s in st.sessions.values() {
            s.conn.close(VarInt::from_u32(code), reason);
        }
    }

    /// The watchdog: applies the lease now. Returns the stop cause if the server stopped.
    fn poll_lease(&self) -> Option<StopCause> {
        let mut st = self.state();
        let _ = self.lease_gate(&mut st);
        st.stopped
    }

    /// A fresh lease for `grant.generation`: admission resumes if the lease agrees.
    fn grant(&self, grant: LeaseGrant) {
        let report = {
            let mut st = self.state();
            if st.stopped.is_none() && grant.generation > st.acked {
                st.acked = grant.generation;
            }
            let resumed = match (st.stopped, self.authority.lease()) {
                (None, LeaseState::Held(h)) if h <= st.acked => {
                    st.lease_revoked = false;
                    true
                }
                (None, LeaseState::Lost(loss)) => {
                    Self::stop_locked(&mut st, StopCause::LeaseLost(loss));
                    self.lease_lost.notify_one();
                    false
                }
                _ => false,
            };
            GrantReport {
                generation: st.acked,
                resumed,
            }
        };
        grant.ack.acknowledge(report);
    }

    /// Marks the server stopped and closes every live connection at once. Idempotent; the
    /// first cause wins.
    fn stop_locked(st: &mut State, cause: StopCause) {
        if st.stopped.is_none() {
            st.stopped = Some(cause);
        }
        let code = match st.stopped {
            Some(StopCause::LeaseLost(_)) => CLOSE_LEASE_LOST,
            _ => CLOSE_DONE,
        };
        Self::close_all_locked(st, code, b"serve stopped");
    }

    fn check(&self, peer: &EndpointId) -> bool {
        let mut st = self.state();
        self.admits(&mut st, peer)
    }

    fn register(self: &Arc<Self>, conn: &Connection) -> Option<SessionGuard<A>> {
        let peer = conn.remote_id();
        let mut st = self.state();
        if !self.admits(&mut st, &peer) {
            return None;
        }
        let id = st.next_session;
        st.next_session = st.next_session.wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        st.sessions.insert(
            id,
            Session {
                peer,
                conn: conn.clone(),
                done: rx,
            },
        );
        Some(SessionGuard {
            shared: Arc::clone(self),
            id,
            _done: tx,
        })
    }

    /// Whether a registered session may still connect its target.
    fn still_admitted(&self, id: u64, peer: &EndpointId) -> bool {
        let mut st = self.state();
        st.sessions.contains_key(&id) && self.admits(&mut st, peer)
    }

    async fn suspend(&self, req: SuspendRequest) {
        let peers: BTreeSet<EndpointId> = req.endpoints.iter().filter_map(iroh_id).collect();
        let (waits, generation) = {
            let mut st = self.state();
            st.suspended.extend(peers.iter().copied());
            if req.generation > st.acked {
                st.acked = req.generation;
            }
            let ids: Vec<u64> = st
                .sessions
                .iter()
                .filter(|(_, s)| peers.contains(&s.peer))
                .map(|(id, _)| *id)
                .collect();
            let mut waits = Vec::with_capacity(ids.len());
            for id in ids {
                if let Some(s) = st.sessions.remove(&id) {
                    s.conn
                        .close(VarInt::from_u32(CLOSE_REVOKED), b"admission withdrawn");
                    waits.push(s.done);
                }
            }
            (waits, st.acked)
        };
        let closed = waits.len();
        let complete = drain(waits).await;
        req.ack.acknowledge(SuspendReport {
            generation,
            closed,
            complete,
        });
    }

    /// Stops the server (if not yet stopped) and takes every session for draining.
    fn stop_all(&self, cause: StopCause) -> (StopCause, Vec<oneshot::Receiver<()>>) {
        let mut st = self.state();
        Self::stop_locked(&mut st, cause);
        let cause = st.stopped.unwrap_or(cause);
        let waits = std::mem::take(&mut st.sessions)
            .into_values()
            .map(|s| s.done)
            .collect();
        (cause, waits)
    }

    fn stopped(&self) -> Option<StopCause> {
        self.state().stopped
    }
}

/// Waits for every closed session to end, within [`SESSION_DRAIN_BOUND`].
async fn drain(waits: Vec<oneshot::Receiver<()>>) -> bool {
    bounded(SESSION_DRAIN_BOUND, async move {
        for w in waits {
            let _ = w.await;
        }
    })
    .await
    .is_some()
}

/// Deregisters a session when its task ends (or is aborted); dropping `_done` tells a
/// draining suspend or stop that the session (and its target socket) is gone.
struct SessionGuard<A: AdmissionAuthority> {
    shared: Arc<Shared<A>>,
    id: u64,
    _done: oneshot::Sender<()>,
}

impl<A: AdmissionAuthority> Drop for SessionGuard<A> {
    fn drop(&mut self) {
        let removed = self.shared.state().sessions.remove(&self.id);
        drop(removed);
    }
}

/// The server's admission hook (check point 1).
struct AdmissionHook<A>(Arc<Shared<A>>);

impl<A> std::fmt::Debug for AdmissionHook<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AdmissionHook").field(&self.0).finish()
    }
}

impl<A: AdmissionAuthority> EndpointHooks for AdmissionHook<A> {
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        let ok =
            conn.side() == Side::Server && conn.alpn() == ALPN && self.0.check(&conn.remote_id());
        async move {
            if ok {
                AfterHandshakeOutcome::Accept
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(CLOSE_REFUSED),
                    reason: b"not admitted".to_vec(),
                }
            }
        }
    }
}

/// A bound serving endpoint. [`Server::run`] serves until the lease is lost or it is shut
/// down.
pub struct Server<A: AdmissionAuthority> {
    endpoint: Endpoint,
    endpoint_id: IrohEndpointId,
    shared: Arc<Shared<A>>,
    shutdown: Arc<Notify>,
}

impl<A: AdmissionAuthority> std::fmt::Debug for Server<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("endpoint_id", &self.endpoint_id)
            .finish_non_exhaustive()
    }
}

impl<A: AdmissionAuthority> Server<A> {
    /// Validates the configuration, reads the lease, loads K_iroh and binds the endpoint
    /// built from the policy alone.
    ///
    /// # Errors
    ///
    /// [`ServeError`], in this order: an allowlist entry that is not an endpoint key; the
    /// policy; a lost lease (`transport_authority_lost`: nothing binds); the key; the bind.
    pub async fn bind(
        config: ServeConfig,
        keys: &dyn KeySource,
        authority: Arc<A>,
    ) -> Result<Self, ServeError> {
        let mut allowlist = BTreeMap::new();
        for id in config.allowlist.iter() {
            let key =
                iroh_id(id).ok_or(ServeError::Config(ServeConfigError::InvalidAllowlistEntry))?;
            allowlist.insert(key, id.clone());
        }
        let plan = plan_endpoint(&config.policy, Role::Serve).map_err(ServeError::Policy)?;
        let acked = match authority.lease() {
            LeaseState::Held(g) => g,
            LeaseState::Lost(loss) => return Err(ServeError::AuthorityLost(loss)),
        };
        let secret = keys.load().map_err(ServeError::Key)?;
        let shared = Arc::new(Shared {
            authority,
            allowlist,
            target: config.target,
            state: Mutex::new(State {
                acked,
                lease_revoked: false,
                stopped: None,
                suspended: BTreeSet::new(),
                sessions: BTreeMap::new(),
                next_session: 0,
            }),
            lease_lost: Notify::new(),
        });
        // One bidirectional stream per connection (Pigeons); nothing else changes.
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .build();
        let endpoint = plan
            .builder
            .secret_key(secret.secret_key())
            .alpns(vec![ALPN.to_vec()])
            .transport_config(transport)
            .hooks(AdmissionHook(Arc::clone(&shared)))
            .bind()
            .await
            .map_err(|_| ServeError::Bind)?;
        let Some(endpoint_id) = contract_id(&endpoint.id()) else {
            close_bounded(&endpoint).await;
            return Err(ServeError::Bind);
        };
        Ok(Self {
            endpoint,
            endpoint_id,
            shared,
            shutdown: Arc::new(Notify::new()),
        })
    }

    /// This endpoint's ID.
    #[must_use]
    pub fn endpoint_id(&self) -> &IrohEndpointId {
        &self.endpoint_id
    }

    /// Every socket the endpoint bound.
    #[must_use]
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// A handle that stops [`Server::run`].
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(Arc::clone(&self.shutdown))
    }

    /// Serves until the lease is lost, the server is shut down, or the endpoint closes.
    /// On the way out every connection is closed at once, the sessions are drained within
    /// [`SESSION_DRAIN_BOUND`] and the endpoint is closed within its bound.
    pub async fn run(self) -> ServeExit {
        let Self {
            endpoint,
            shared,
            shutdown,
            ..
        } = self;
        let authority = Arc::clone(&shared.authority);
        let mut sessions: JoinSet<()> = JoinSet::new();
        let mut signal = Box::pin(authority.next_signal());
        let mut lease_poll = tokio::time::interval(LEASE_POLL_INTERVAL);
        lease_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let cause = loop {
            tokio::select! {
                sig = &mut signal => match sig {
                    AdmissionSignal::Suspend(req) => {
                        shared.suspend(req).await;
                        signal = Box::pin(authority.next_signal());
                        if let Some(cause) = shared.poll_lease() {
                            break cause;
                        }
                    }
                    AdmissionSignal::Grant(grant) => {
                        shared.grant(grant);
                        signal = Box::pin(authority.next_signal());
                        if let Some(cause) = shared.poll_lease() {
                            break cause;
                        }
                    }
                    AdmissionSignal::LeaseLost(loss) => break StopCause::LeaseLost(loss),
                },
                _ = lease_poll.tick() => {
                    if let Some(cause) = shared.poll_lease() {
                        break cause;
                    }
                }
                () = shared.lease_lost.notified() => {
                    break shared.stopped().unwrap_or(StopCause::Shutdown);
                }
                () = shutdown.notified() => break StopCause::Shutdown,
                inc = endpoint.accept() => match inc {
                    None => break StopCause::EndpointClosed,
                    Some(inc) => {
                        if shared.stopped().is_some() {
                            inc.refuse();
                        } else {
                            sessions.spawn(session(Arc::clone(&shared), inc));
                        }
                    }
                },
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            }
        };
        drop(signal);
        let (cause, waits) = shared.stop_all(cause);
        let _ = drain(waits).await;
        close_bounded(&endpoint).await;
        sessions.abort_all();
        match cause {
            StopCause::LeaseLost(loss) => ServeExit::LeaseLost(loss),
            StopCause::Shutdown => ServeExit::Shutdown,
            StopCause::EndpointClosed => ServeExit::EndpointClosed,
        }
    }
}

/// One admitted connection: the one stream, forwarded to the loopback target.
async fn session<A: AdmissionAuthority>(shared: Arc<Shared<A>>, incoming: Incoming) {
    // The handshake runs the admission hook: a refused peer never gets here.
    let Ok(conn) = incoming.await else {
        return;
    };
    let peer = conn.remote_id();
    let Some(guard) = shared.register(&conn) else {
        conn.close(VarInt::from_u32(CLOSE_REFUSED), b"not admitted");
        return;
    };
    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
        return;
    };
    if !shared.still_admitted(guard.id, &peer) {
        conn.close(VarInt::from_u32(CLOSE_REFUSED), b"not admitted");
        return;
    }
    let tcp = tokio::select! {
        r = shared.target.connect() => r,
        _ = conn.closed() => return,
    };
    let Ok(tcp) = tcp else {
        conn.close(VarInt::from_u32(CLOSE_TARGET_UNAVAILABLE), b"target");
        return;
    };
    let (mut target_read, mut target_write) = tcp.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut recv, &mut target_write).await;
        let _ = target_write.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut target_read, &mut send).await;
        let _ = send.finish();
    };
    tokio::select! {
        ((), ()) = async { tokio::join!(up, down) } => {
            let _ = bounded(LINGER, conn.closed()).await;
            conn.close(VarInt::from_u32(CLOSE_DONE), b"done");
        }
        _ = conn.closed() => {}
    }
    drop(guard);
}
