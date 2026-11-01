//! The control endpoint's [`Dispatcher`] over [`Operations`] (overview §1: "`ipc`
//! does not know `app`; the runtime supplies a `Dispatcher`"; ADR-0006 §2.3, §3.1,
//! §8).
//!
//! * **Caller.** Built from the session only: the principal the transport
//!   authenticated (Unix peer credentials, Windows client SID), the role `Owner`
//!   (a peer that passed the same-user check is the owner; paired
//!   `LimitedConsumer` clients are G07 and never arrive on this endpoint), the
//!   hello's interaction mode, and attendance as the session recorded it. Nothing
//!   is read from request content (A29: no client-supplied "attended" value).
//! * **Attended-only requests** (`decide`, `confirm_time`) are refused by the
//!   session before dispatch on unattended sessions; this dispatcher refuses them
//!   again, and the application checks a third time (defence in depth).
//! * **Widening policy actions** (`resume`, `clear_cutoff`) and added authority
//!   are dispatched on every session unchanged; the application always answers
//!   with a server-issued decision record (`APPROVAL_REQUIRED` attended,
//!   `INTERACTION_REQUIRED` unattended, both with `next.decision_ref`) and never
//!   executes them on dispatch (ADR-0006 §13.1 R5, §13.4 N04).
//! * **Service control** (ADR-0006 §13.6 item 8). `Request::Shutdown` reaches this
//!   dispatcher only on a session that negotiated `service-control/1` (the session
//!   refuses it otherwise). It is accepted only from the **owner** role, on any
//!   session (attended or not: an availability action, not a widening), and only
//!   when the service gave this dispatcher its stop token
//!   ([`OperationsDispatcher::with_service_control`]); a limited consumer gets
//!   `CAPABILITY_UNAVAILABLE`. The answer is `OK {"stopping": true,
//!   "already_stopping": <bool>}`; the drain itself starts from
//!   [`Dispatcher::replied`], after that answer is written, by cancelling the
//!   service token, which runs the same graceful drain as a signal. Repeated
//!   requests are idempotent. This dispatcher serves the control endpoint only:
//!   the signing endpoint speaks the agent protocol and has no such request.
//! * **Subscriptions.** The application's [`heimdall_app::events::SubscriptionStart`]
//!   carries a live receiver of `SequencedEvent`s; the session wants
//!   [`LiveEvent`]s. One runtime-wide [`EventRelay`] converts the application's
//!   live channel into a `LiveEvent` channel of the same bound. A subscription
//!   takes its relay receiver **before** the application reads the boundary, so
//!   every event committed after the boundary reaches it (overlap is removed by the
//!   session's `seq <= boundary_seq` rule).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use heimdall_app::events::SubscribeRefusal;
use heimdall_app::{Attendance, Caller, OpError, OpResult, Operations};
use heimdall_contract::envelope::{Envelope, ErrorData};
use heimdall_contract::event::{Cursor, EventFilter, EventType};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::ipc::{EVENT_BUFFER_PER_SUBSCRIPTION, PrincipalInfo};
use heimdall_contract::request::Request;
use heimdall_contract::{Code, SchemaVersion};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::Clock;
use heimdall_ipc::session::{Dispatcher, LiveEvent, SessionInfo, SubscriptionStart};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// The authenticated caller for one request: principal and role from the
/// transport, interaction and attendance from the session (never from request
/// fields).
#[must_use]
pub fn caller_for(session: &SessionInfo, now: heimdall_contract::Timestamp) -> Caller {
    let principal = match &session.principal {
        PrincipalInfo::OsUserUnix { uid } => PrincipalRef::UnixUser { uid: *uid },
        PrincipalInfo::OsUserWindows { sid } => PrincipalRef::WindowsUser { sid: sid.clone() },
    };
    Caller {
        context: CallerContext {
            principal,
            role: ClientRole::Owner,
        },
        attendance: if session.attended {
            Attendance::Attended { since: now }
        } else {
            Attendance::Unattended
        },
        interaction: session.interaction,
    }
}

/// Render a value envelope; a payload that cannot be serialized becomes an
/// `INTERNAL_ERROR` envelope (never a success with a null payload).
fn value_envelope<T: serde::Serialize>(env: Envelope<T>) -> Envelope<serde_json::Value> {
    let Envelope {
        schema_version,
        operation_id,
        state,
        code,
        data,
        warnings,
        next,
    } = env;
    match serde_json::to_value(data) {
        Ok(data) => Envelope {
            schema_version,
            operation_id,
            state,
            code,
            data,
            warnings,
            next,
        },
        Err(_) => error_value(OpError::new(
            Code::InternalError,
            "response could not be rendered",
        )),
    }
}

fn error_value(e: OpError) -> Envelope<serde_json::Value> {
    e.into_envelope()
        .map(|d: ErrorData| serde_json::to_value(d).unwrap_or_default())
}

/// Render an application result as the wire envelope.
#[must_use]
pub fn render<T: serde::Serialize>(result: OpResult<T>) -> Envelope<serde_json::Value> {
    match result {
        Ok(done) => value_envelope(done.into_envelope()),
        Err(e) => error_value(e),
    }
}

/// [`Dispatcher`] over the shared application operations.
#[derive(Clone)]
pub struct OperationsDispatcher {
    operations: Operations,
    relay: EventRelay,
    clock: Arc<dyn Clock>,
    /// The service's stop token, when this dispatcher may stop the service.
    stop: Option<CancellationToken>,
}

impl std::fmt::Debug for OperationsDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationsDispatcher")
            .finish_non_exhaustive()
    }
}

impl OperationsDispatcher {
    /// Dispatcher over `operations`, delivering live events through `relay`.
    #[must_use]
    pub fn new(operations: Operations, relay: EventRelay, clock: Arc<dyn Clock>) -> Self {
        Self {
            operations,
            relay,
            clock,
            stop: None,
        }
    }

    /// Let owner `Shutdown` requests stop the service by cancelling `stop` (the
    /// token `Service::run` drains on). Without it, `Shutdown` is not supported
    /// (`USAGE_ERROR`).
    #[must_use]
    pub fn with_service_control(mut self, stop: CancellationToken) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Handle one request for an already-authenticated session.
    pub async fn handle(
        &self,
        session: &SessionInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        let caller = caller_for(session, self.clock.wall());
        self.handle_as(&caller, request).await
    }

    /// [`Self::handle`] for an explicit caller (the role-based refusals are
    /// testable with a `LimitedConsumer` caller, which the control endpoint never
    /// builds itself before G07).
    #[doc(hidden)]
    pub async fn handle_as(
        &self,
        caller: &Caller,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        let caller = caller.clone();
        if request.requires_attended_session() && !caller.is_attended() {
            return error_value(OpError::new(
                Code::InteractionRequired,
                "this request requires an attended interactive session",
            ));
        }
        if let Request::Shutdown(_) = request {
            return self.shutdown(&caller);
        }
        let ops = &self.operations;
        match request {
            Request::Inspect(r) => render(ops.inspect(&caller, r).await),
            Request::Ensure(r) => render(ops.ensure(&caller, r).await),
            Request::Bind(r) => render(ops.bind(&caller, r).await),
            Request::Delegate(r) => render(ops.delegate(&caller, r).await),
            Request::Observe(r) => render(ops.observe(&caller, r).await),
            Request::Cancel(r) => render(ops.cancel(&caller, r).await),
            Request::Release(r) => render(ops.release(&caller, r).await),
            Request::Revoke(r) => render(ops.revoke(&caller, r).await),
            // Widening actions included: the application answers with a decision
            // record and never executes them here (R5, N04).
            Request::Policy(r) => render(ops.policy(&caller, r).await),
            Request::Decide(r) => render(ops.decide(&caller, r).await),
            Request::ConfirmTime(r) => render(ops.confirm_time(&caller, r).await),
            // ⟨M02⟩ m02-plan U0b row 17: routed to the application's entry points,
            // which answer `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) in wave 0
            // before any admission (row 18; ADR-0007 §12.7 QR7). A session never
            // gets here in wave 0: `setup/1` is not offered.
            Request::Setup(r) => render(ops.setup(&caller, r).await),
            Request::Catalog(r) => render(ops.catalog(&caller, r).await),
            // A request kind this build does not know is never executed.
            _ => error_value(OpError::new(
                Code::UsageError,
                "this request kind is not supported by this runtime",
            )),
        }
    }

    /// `Shutdown` (module docs): owner role only; the drain starts after the
    /// answer is written ([`Dispatcher::replied`]).
    fn shutdown(&self, caller: &Caller) -> Envelope<serde_json::Value> {
        if !caller.context.is_owner() {
            return error_value(OpError::new(
                Code::CapabilityUnavailable,
                "service control needs the owner principal on the control endpoint",
            ));
        }
        let Some(stop) = &self.stop else {
            return error_value(OpError::new(
                Code::UsageError,
                "this request kind is not supported by this runtime",
            ));
        };
        // `already_stopping`: the drain had already started when this arrived.
        let already = stop.is_cancelled();
        if !already {
            tracing::info!("stop requested by the owner over the control endpoint");
        }
        value_envelope(Envelope::ok(serde_json::json!({
            "stopping": true,
            "already_stopping": already,
        })))
    }

    /// Start a subscription (ADR-0006 §8): relay receiver first, then the
    /// application's boundary/backlog/snapshot transaction. A cursor that is
    /// foreign, malformed or past retention starts from a fresh snapshot.
    pub async fn start_subscription(
        &self,
        session: &SessionInfo,
        filter: EventFilter,
        from: Option<Cursor>,
    ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
        let caller = caller_for(session, self.clock.wall());
        // Created before the boundary is read: nothing committed after it is missed.
        let live = self.relay.subscribe();
        match self
            .operations
            .events()
            .subscribe(&caller.context, filter, from, false)
            .await
        {
            Ok(start) => Ok(SubscriptionStart {
                cursor: start.cursor,
                boundary_seq: start.boundary_seq,
                snapshot: start.snapshot,
                backlog: start.backlog,
                live,
                cursor_for: start.cursor_for,
            }),
            Err(SubscribeRefusal::ResyncRequired) => Err(Box::new(
                OpError::new(
                    Code::ResyncRequired,
                    "the cursor cannot be resumed; subscribe without a cursor for a snapshot",
                )
                .into_envelope(),
            )),
            Err(SubscribeRefusal::StateUnavailable) => Err(Box::new(
                OpError::new(Code::StateUnavailable, "state store unavailable")
                    .with_resource("store", None)
                    .into_envelope(),
            )),
        }
    }
}

// `heimdall_ipc::session::Dispatcher` is declared with `#[async_trait]`; this is
// the same signature written out, so the runtime needs no extra macro dependency.
impl Dispatcher for OperationsDispatcher {
    fn dispatch<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session: &'life1 SessionInfo,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Envelope<serde_json::Value>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.handle(session, request))
    }

    fn subscribe<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session: &'life1 SessionInfo,
        filter: EventFilter,
        from: Option<Cursor>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SubscriptionStart, Box<Envelope<ErrorData>>>>
                + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.start_subscription(session, filter, from))
    }

    fn replied(&self, _session: &SessionInfo, request_kind: &'static str, code: &Code) {
        if request_kind == "shutdown"
            && *code == Code::Ok
            && let Some(stop) = &self.stop
        {
            stop.cancel();
        }
    }
}

/// Runtime-wide conversion of the application's live channel
/// (`Arc<SequencedEvent>`) into the session's (`Arc<LiveEvent>`), with the same
/// bound (`EVENT_BUFFER_PER_SUBSCRIPTION`).
///
/// **Lag.** If the relay itself falls behind the application's channel, events
/// were dropped for every subscriber. The relay then sends one burst of
/// `EVENT_BUFFER_PER_SUBSCRIPTION + 1` filler items (sequence 0, which every
/// session discards as covered by its boundary) without yielding, so every
/// downstream receiver overflows and its session emits exactly one
/// `ResyncRequired` at that subscriber's own last delivered cursor (ADR-0006 §8).
/// This relies on the service's current-thread executor (overview §4): no
/// receiver can drain the burst concurrently.
#[derive(Clone)]
pub struct EventRelay {
    tx: broadcast::Sender<Arc<LiveEvent>>,
}

impl std::fmt::Debug for EventRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventRelay")
            .field("receivers", &self.tx.receiver_count())
            .finish()
    }
}

impl EventRelay {
    /// Start relaying `operations`' live events until `shutdown`. Must be called
    /// inside a tokio runtime. The application receiver is taken here, before this
    /// returns, so no event announced afterwards is missed by the relay.
    #[must_use]
    pub fn spawn(operations: &Operations, shutdown: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel(EVENT_BUFFER_PER_SUBSCRIPTION);
        let mut from_app = operations.events().live_receiver();
        let environment = operations.environment().clone();
        let out = tx.clone();
        tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    r = from_app.recv() => r,
                };
                match next {
                    Ok(ev) => {
                        let _ = out.send(Arc::new(LiveEvent {
                            seq: ev.seq,
                            event: ev.event.clone(),
                        }));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("event relay lagged; subscribers will resynchronize");
                        let filler = Arc::new(filler_event(&environment));
                        for _ in 0..=EVENT_BUFFER_PER_SUBSCRIPTION {
                            let _ = out.send(filler.clone());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Self { tx }
    }

    /// A receiver for one subscription.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.tx.subscribe()
    }
}

/// Sequence-0 placeholder used only to force downstream lag; never delivered
/// (every boundary is `>= 0`).
fn filler_event(environment: &EnvironmentId) -> LiveEvent {
    LiveEvent {
        seq: 0,
        event: heimdall_contract::event::Event {
            schema_version: SchemaVersion::current(),
            event_id: heimdall_contract::ids::EventId::from_random_bytes([0; 16]),
            event_type: EventType::ResyncRequired,
            environment_id: environment.clone(),
            operation_id: None,
            resource: None,
            timestamp: heimdall_contract::Timestamp::UNIX_EPOCH,
            cursor: Cursor(String::new()),
            payload: serde_json::Value::Null,
        },
    }
}
