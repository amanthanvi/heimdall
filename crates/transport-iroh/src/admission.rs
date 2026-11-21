//! The serving side's admission seam (ADR-0012 §2.3 items 1 and 3-5).
//!
//! The serve child holds no authority of its own: the runtime's durable tombstones and
//! enrollment records are the only admission authority, and the child admits and forwards
//! only while it holds a lease for the runtime's current authority generation. This module
//! is the child's side of that contract, with no iroh types, so m06-plan U56 implements it
//! without the `iroh` feature:
//!
//! * [`Allowlist`]: the endpoint IDs enrolled for the environment, required and nonempty,
//!   fixed for one serve child's life (a new enrollment starts a new child, which is also how
//!   closure is replayed after a restart, item 5).
//! * [`AdmissionAuthority`]: the lease ([`AdmissionAuthority::lease`]), the per-endpoint
//!   answer at a generation ([`AdmissionAuthority::is_admitted`]) and the signals
//!   ([`AdmissionAuthority::next_signal`]): suspend these endpoints and close their streams,
//!   then acknowledge ([`SuspendRequest`]); a fresh lease for a new generation
//!   ([`LeaseGrant`]); or the lease is lost for good ([`AdmissionSignal::LeaseLost`]).
//! * **Lease loss** (§2.3 item 3) stops all admission and closes every stream at once. An
//!   unacknowledged generation change (the lease reports a newer generation than the child
//!   acknowledged) is a lease loss the child survives: it resumes admission only under a
//!   [`LeaseGrant`] for the new generation. Channel EOF, runtime exit or a lease reported
//!   [`LeaseState::Lost`] end the child.
//! * [`ChannelAuthority`] and [`AuthorityHandle`]: an in-process implementation driven
//!   through a channel. It is the crate's test implementation and an adapter U56 may feed
//!   from its supervision channel; dropping the handle is channel EOF (lease lost).

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::IrohEndpointId;
use tokio::sync::{mpsc, oneshot};

/// The runtime's authority generation (ADR-0012 §2.3 item 4: a committed tombstone moves it
/// from g to g+1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityGeneration(pub u64);

/// Why the lease was lost (ADR-0012 §2.3 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseLoss {
    /// The supervision channel reached EOF.
    ChannelClosed,
    /// The runtime exited.
    RuntimeExited,
    /// The generation changed and the child did not acknowledge it in the runtime's bound.
    GenerationUnacknowledged,
    /// The authority state cannot be read (corrupt or unavailable).
    AuthorityUnreadable,
}

impl LeaseLoss {
    /// The stable reason token (`transport_authority_lost`).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        reason::TRANSPORT_AUTHORITY_LOST
    }
}

/// The child's lease, as the authority sees it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseState {
    /// Held for this generation.
    Held(AuthorityGeneration),
    /// Lost.
    Lost(LeaseLoss),
}

/// What the child reports after suspending endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuspendReport {
    /// The generation the child now holds its lease for (the request's, or a later one it
    /// had already acknowledged).
    pub generation: AuthorityGeneration,
    /// Live connections of the suspended endpoints that were closed.
    pub closed: usize,
    /// Whether every closed connection's session (its stream and its target socket) ended
    /// within the child's bound. When `false`, the runtime stops the child by its exact PID
    /// before it reports the revocation applied (ADR-0012 §2.3 item 4.3).
    pub complete: bool,
}

/// The acknowledgement channel of one [`SuspendRequest`].
#[derive(Debug)]
pub struct SuspendAck(oneshot::Sender<SuspendReport>);

impl SuspendAck {
    /// A new acknowledgement channel: the sender side for the request, the receiver for the
    /// runtime (or its supervision-channel adapter).
    #[must_use]
    pub fn channel() -> (Self, oneshot::Receiver<SuspendReport>) {
        let (tx, rx) = oneshot::channel();
        (Self(tx), rx)
    }

    /// Sends the report. A dropped receiver is ignored: the runtime then treats the child
    /// as unacknowledged and stops it.
    pub fn acknowledge(self, report: SuspendReport) {
        let _ = self.0.send(report);
    }
}

/// Suspend admission for these endpoints and close their existing streams, then
/// acknowledge (ADR-0012 §2.3 item 4.2).
#[derive(Debug)]
pub struct SuspendRequest {
    /// The generation the runtime committed (the tombstone's).
    pub generation: AuthorityGeneration,
    /// The endpoints whose admission is suspended for the rest of this child's life.
    pub endpoints: Vec<IrohEndpointId>,
    /// Where the [`SuspendReport`] goes.
    pub ack: SuspendAck,
}

/// What the child reports after a [`LeaseGrant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantReport {
    /// The generation the child now holds its lease for.
    pub generation: AuthorityGeneration,
    /// Whether admission resumed. `false` when the lease still reports a newer generation
    /// than the grant (the grant is stale) or the child has stopped.
    pub resumed: bool,
}

/// The acknowledgement channel of one [`LeaseGrant`].
#[derive(Debug)]
pub struct GrantAck(oneshot::Sender<GrantReport>);

impl GrantAck {
    /// A new acknowledgement channel.
    #[must_use]
    pub fn channel() -> (Self, oneshot::Receiver<GrantReport>) {
        let (tx, rx) = oneshot::channel();
        (Self(tx), rx)
    }

    /// Sends the report (a dropped receiver is ignored).
    pub fn acknowledge(self, report: GrantReport) {
        let _ = self.0.send(report);
    }
}

/// A fresh lease for `generation`: after an unacknowledged generation change closed every
/// stream, admission resumes only under one of these (ADR-0012 §2.3 items 3 and 5).
#[derive(Debug)]
pub struct LeaseGrant {
    /// The generation granted.
    pub generation: AuthorityGeneration,
    /// Where the [`GrantReport`] goes.
    pub ack: GrantAck,
}

/// A signal from the authority to the serve child.
#[derive(Debug)]
pub enum AdmissionSignal {
    /// Suspend endpoints, close their streams, acknowledge.
    Suspend(SuspendRequest),
    /// A fresh lease for a new generation.
    Grant(LeaseGrant),
    /// The lease is lost for good: stop all admission, close every stream at once, exit.
    LeaseLost(LeaseLoss),
}

/// The admission authority as the serve child sees it. Implemented by m06-plan U56 over the
/// supervision channel (and by [`ChannelAuthority`] here).
///
/// Contract for implementations:
/// * [`Self::lease`] and [`Self::is_admitted`] are called on the accept path and by the
///   server's lease watchdog, under the server's admission lock: they must not block and must
///   not call back into the server.
/// * [`Self::lease`] reports the generation the runtime has **granted** the child. It
///   advances only through a handshake the child acknowledges: a [`SuspendRequest`] (record
///   the [`SuspendReport`]'s generation once it arrives) or a [`LeaseGrant`]. Reporting a newer
///   generation than the child acknowledged is an unacknowledged generation change: the child
///   treats it as lease loss at once (every stream closed, admission stopped) and resumes only
///   after a [`LeaseGrant`] for that generation. Reporting [`LeaseState::Lost`] stops the child.
/// * [`Self::is_admitted`] answers for the given generation only: an endpoint that is not
///   enrolled, or is tombstoned, at that generation is not admitted. Answer `false` for any
///   generation other than the current committed one.
/// * [`Self::next_signal`] yields [`AdmissionSignal::LeaseLost`] on channel EOF and on runtime
///   exit. Once it has yielded `LeaseLost` it is not polled again.
pub trait AdmissionAuthority: Send + Sync + 'static {
    /// The lease now.
    fn lease(&self) -> LeaseState;

    /// Whether `endpoint` is enrolled and not tombstoned at `generation`.
    fn is_admitted(&self, generation: AuthorityGeneration, endpoint: &IrohEndpointId) -> bool;

    /// Waits for the next signal.
    fn next_signal(&self) -> impl Future<Output = AdmissionSignal> + Send + '_;
}

/// A serve configuration error (refused before anything binds). Every variant answers
/// `transport_unavailable`: the serving endpoint cannot apply such a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServeConfigError {
    /// The allowlist is empty (ADR-0012 §2.3 item 1).
    EmptyAllowlist,
    /// An allowlist entry is not a valid endpoint public key.
    InvalidAllowlistEntry,
    /// The target is not `127.0.0.1` or `::1` (ADR-0012 §2.3 item 2).
    NonLoopbackTarget,
}

impl ServeConfigError {
    /// The stable reason token.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        reason::TRANSPORT_UNAVAILABLE
    }
}

impl std::fmt::Display for ServeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            Self::EmptyAllowlist => "the serve allowlist is empty",
            Self::InvalidAllowlistEntry => "a serve allowlist entry is not an endpoint key",
            Self::NonLoopbackTarget => "the serve target is not 127.0.0.1 or ::1",
        };
        write!(f, "{}: {what}", self.reason())
    }
}

impl std::error::Error for ServeConfigError {}

impl From<crate::target::NonLoopbackTarget> for ServeConfigError {
    fn from(_: crate::target::NonLoopbackTarget) -> Self {
        Self::NonLoopbackTarget
    }
}

/// The serve allowlist: required and nonempty (ADR-0012 §2.3 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist(BTreeSet<IrohEndpointId>);

impl Allowlist {
    /// Builds the allowlist.
    ///
    /// # Errors
    ///
    /// [`ServeConfigError::EmptyAllowlist`] when `ids` is empty.
    pub fn new(ids: impl IntoIterator<Item = IrohEndpointId>) -> Result<Self, ServeConfigError> {
        let set: BTreeSet<IrohEndpointId> = ids.into_iter().collect();
        if set.is_empty() {
            Err(ServeConfigError::EmptyAllowlist)
        } else {
            Ok(Self(set))
        }
    }

    /// Whether `id` is on the list.
    #[must_use]
    pub fn contains(&self, id: &IrohEndpointId) -> bool {
        self.0.contains(id)
    }

    /// The entries.
    pub fn iter(&self) -> impl Iterator<Item = &IrohEndpointId> {
        self.0.iter()
    }
}

#[derive(Debug)]
struct View {
    /// The authority's committed generation (tombstones move it).
    committed: AuthorityGeneration,
    /// The generation granted to the child (what [`AdmissionAuthority::lease`] reports).
    granted: AuthorityGeneration,
    admitted: BTreeSet<IrohEndpointId>,
    lost: Option<LeaseLoss>,
}

/// An in-process [`AdmissionAuthority`] driven by an [`AuthorityHandle`].
#[derive(Debug)]
pub struct ChannelAuthority {
    view: Mutex<View>,
    signals: tokio::sync::Mutex<mpsc::UnboundedReceiver<AdmissionSignal>>,
}

/// The runtime's side of a [`ChannelAuthority`]. Dropping it is channel EOF: the child's
/// lease is lost.
#[derive(Debug)]
pub struct AuthorityHandle {
    authority: Arc<ChannelAuthority>,
    tx: mpsc::UnboundedSender<AdmissionSignal>,
}

/// The child did not acknowledge (it exited or dropped the request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unacknowledged;

impl ChannelAuthority {
    /// An authority at `generation` that admits exactly `admitted`.
    #[must_use]
    pub fn new(
        generation: AuthorityGeneration,
        admitted: impl IntoIterator<Item = IrohEndpointId>,
    ) -> (Arc<Self>, AuthorityHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let authority = Arc::new(Self {
            view: Mutex::new(View {
                committed: generation,
                granted: generation,
                admitted: admitted.into_iter().collect(),
                lost: None,
            }),
            signals: tokio::sync::Mutex::new(rx),
        });
        let handle = AuthorityHandle {
            authority: Arc::clone(&authority),
            tx,
        };
        (authority, handle)
    }

    fn view(&self) -> std::sync::MutexGuard<'_, View> {
        self.view.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AdmissionAuthority for ChannelAuthority {
    fn lease(&self) -> LeaseState {
        let v = self.view();
        match v.lost {
            Some(loss) => LeaseState::Lost(loss),
            None => LeaseState::Held(v.granted),
        }
    }

    fn is_admitted(&self, generation: AuthorityGeneration, endpoint: &IrohEndpointId) -> bool {
        let v = self.view();
        v.lost.is_none() && v.committed == generation && v.admitted.contains(endpoint)
    }

    async fn next_signal(&self) -> AdmissionSignal {
        let mut rx = self.signals.lock().await;
        match rx.recv().await {
            Some(signal) => signal,
            None => AdmissionSignal::LeaseLost(LeaseLoss::ChannelClosed),
        }
    }
}

impl AuthorityHandle {
    /// The authority's committed generation.
    #[must_use]
    pub fn generation(&self) -> AuthorityGeneration {
        self.authority.view().committed
    }

    /// Revokes `endpoints` in ADR-0012 §2.3 item 4's order: commits the tombstone (the
    /// committed generation moves to g+1 and the endpoints stop being admitted), tells the
    /// child to suspend them and close their streams, and returns its acknowledgement. The
    /// lease reports g+1 only once the acknowledgement arrived. The caller bounds the wait;
    /// without an acknowledgement in its bound the runtime stops the child.
    ///
    /// # Errors
    ///
    /// [`Unacknowledged`] when the child dropped the request or is gone.
    pub async fn revoke(
        &self,
        endpoints: Vec<IrohEndpointId>,
    ) -> Result<SuspendReport, Unacknowledged> {
        let generation = {
            let mut v = self.authority.view();
            v.committed = AuthorityGeneration(v.committed.0.saturating_add(1));
            for e in &endpoints {
                v.admitted.remove(e);
            }
            v.committed
        };
        let (ack, rx) = SuspendAck::channel();
        self.tx
            .send(AdmissionSignal::Suspend(SuspendRequest {
                generation,
                endpoints,
                ack,
            }))
            .map_err(|_| Unacknowledged)?;
        let report = rx.await.map_err(|_| Unacknowledged)?;
        let mut v = self.authority.view();
        if report.generation > v.granted {
            v.granted = report.generation;
        }
        Ok(report)
    }

    /// Moves the committed generation and the lease to g+1 without any handshake: a
    /// generation change the child has not acknowledged. The child treats it as lease loss
    /// (every stream closed, admission stopped) until [`Self::grant_lease`].
    pub fn advance_generation_silently(&self) -> AuthorityGeneration {
        let mut v = self.authority.view();
        v.committed = AuthorityGeneration(v.committed.0.saturating_add(1));
        v.granted = v.committed;
        v.committed
    }

    /// Grants the child a fresh lease for the committed generation and returns its report.
    ///
    /// # Errors
    ///
    /// [`Unacknowledged`] when the child dropped the grant or is gone.
    pub async fn grant_lease(&self) -> Result<GrantReport, Unacknowledged> {
        let generation = {
            let mut v = self.authority.view();
            v.granted = v.committed;
            v.committed
        };
        let (ack, rx) = GrantAck::channel();
        self.tx
            .send(AdmissionSignal::Grant(LeaseGrant { generation, ack }))
            .map_err(|_| Unacknowledged)?;
        rx.await.map_err(|_| Unacknowledged)
    }

    /// Reports the lease lost for good and signals the child.
    pub fn lose_lease(&self, loss: LeaseLoss) {
        self.authority.view().lost = Some(loss);
        let _ = self.tx.send(AdmissionSignal::LeaseLost(loss));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn id(c: char) -> IrohEndpointId {
        IrohEndpointId::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// ADR-0012 §2.3 item 1: an empty allowlist is refused at configuration.
    #[test]
    fn empty_allowlist_is_refused() {
        assert_eq!(
            Allowlist::new(Vec::new()),
            Err(ServeConfigError::EmptyAllowlist)
        );
        assert_eq!(
            ServeConfigError::EmptyAllowlist.reason(),
            "transport_unavailable"
        );
        let list = Allowlist::new([id('a'), id('a'), id('b')]).unwrap();
        assert_eq!(list.iter().count(), 2);
        assert!(list.contains(&id('a')) && !list.contains(&id('c')));
    }

    /// The channel authority: revocation moves the generation and stops admission for the
    /// revoked endpoint at the new generation; the old generation answers nothing; dropping
    /// the handle is channel EOF.
    #[tokio::test]
    async fn channel_authority_revoke_and_eof() {
        let (auth, handle) = ChannelAuthority::new(AuthorityGeneration(7), [id('a'), id('b')]);
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(7)));
        assert!(auth.is_admitted(AuthorityGeneration(7), &id('a')));
        assert!(!auth.is_admitted(AuthorityGeneration(6), &id('a')));
        let revoke = tokio::spawn(async move {
            let r = handle.revoke(vec![id('a')]).await;
            (r, handle)
        });
        let AdmissionSignal::Suspend(req) = auth.next_signal().await else {
            panic!("expected a suspend");
        };
        assert_eq!(req.generation, AuthorityGeneration(8));
        assert_eq!(req.endpoints, vec![id('a')]);
        assert!(!auth.is_admitted(AuthorityGeneration(8), &id('a')));
        assert!(auth.is_admitted(AuthorityGeneration(8), &id('b')));
        // The lease moves only with the child's acknowledgement.
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(7)));
        req.ack.acknowledge(SuspendReport {
            generation: req.generation,
            closed: 0,
            complete: true,
        });
        let (r, handle) = revoke.await.unwrap();
        assert_eq!(r.unwrap().generation, AuthorityGeneration(8));
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(8)));
        // An unacknowledged change moves the lease at once; a grant follows it.
        assert_eq!(handle.advance_generation_silently(), AuthorityGeneration(9));
        assert_eq!(auth.lease(), LeaseState::Held(AuthorityGeneration(9)));
        let grant = tokio::spawn(async move {
            let r = handle.grant_lease().await;
            (r, handle)
        });
        let AdmissionSignal::Grant(g) = auth.next_signal().await else {
            panic!("expected a grant");
        };
        assert_eq!(g.generation, AuthorityGeneration(9));
        g.ack.acknowledge(GrantReport {
            generation: g.generation,
            resumed: true,
        });
        let (r, handle) = grant.await.unwrap();
        assert!(r.unwrap().resumed);
        drop(handle);
        assert!(matches!(
            auth.next_signal().await,
            AdmissionSignal::LeaseLost(LeaseLoss::ChannelClosed)
        ));
        assert_eq!(
            LeaseLoss::ChannelClosed.reason(),
            "transport_authority_lost"
        );
    }
}
