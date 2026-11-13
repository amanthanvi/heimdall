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
//! * ⟨M03; ADR-0008 §17.27 item 2⟩ **The uninstall fence**
//!   (`Request::UninstallFence`, `service-control/1`, owner role only, any session):
//!   held by **this connection**. Each clone of the dispatcher is one connection's
//!   scope (the control listener clones it once per accepted connection and drops
//!   that clone when the connection ends, whatever the reason), so the fence is
//!   released by `release` on the holding connection, when that connection ends
//!   (the scope's `Drop`), or with the runtime.
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
use heimdall_contract::enrollment::EnrollmentRequest;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData};
use heimdall_contract::event::{Cursor, EventFilter, EventType};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::ipc::{EVENT_BUFFER_PER_SUBSCRIPTION, PrincipalInfo};
use heimdall_contract::managed::ConnectionsRequest;
use heimdall_contract::request::Request;
use heimdall_contract::{Code, SchemaVersion};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::Clock;
use heimdall_ipc::session::{Dispatcher, LiveEvent, SessionInfo, SubscriptionStart};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::supervisor::ManagedConnections;

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

/// ⟨M03⟩ m03-plan U0b row 13 (F20; ADR-0008 D5 §6.3, §6.7, §6.10, D8 item 2): the
/// M03 requests accepted from the **owner** role only: `Enrollment::{Step,
/// StepResult, Reconcile}` and `Connections::{Close, Register}`.
#[must_use]
pub fn owner_only_m03(request: &Request) -> bool {
    matches!(
        request,
        Request::Enrollment(
            EnrollmentRequest::Step { .. }
                | EnrollmentRequest::StepResult { .. }
                | EnrollmentRequest::Reconcile { .. }
        ) | Request::Connections(
            ConnectionsRequest::Close { .. } | ConnectionsRequest::Register { .. }
        )
    )
}

/// ⟨M03⟩ `Request::Connections` (m03-plan §5 item 4a) over the wired connection
/// control. The owner role was checked first by the dispatcher.
async fn connections_request(
    c: &ManagedConnections,
    r: ConnectionsRequest,
) -> OpResult<serde_json::Value> {
    match r {
        ConnectionsRequest::Close { connection_id } => c.close_request(&connection_id).await,
        ConnectionsRequest::Register {
            binding_id,
            pid,
            created_at,
            image,
        } => {
            c.register_request(&binding_id, pid, created_at, &image)
                .await
        }
        // A future action this build does not know is never executed.
        _ => Err(OpError::new(
            Code::UsageError,
            "this connections action is not supported by this runtime",
        )),
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

/// ⟨ADR-0008 §17.27 item 2, §17.28 item 1⟩ Whether `request` can start or advance
/// remote or CA work, so that the uninstall fence refuses it from any connection but
/// the holder (the request-to-verdict table is in `.m03-wave5-r3-api.md` § U3):
/// * fenced: `enrollment` `apply`, `verify`, `remove` (own and foreign), `reconcile`,
///   `abandon` and `step` (dispatching a remote step); `issuer` `register` (rotation
///   and restore included), `unlock` and `retire` (with or without `deleted_locator`);
///   `decide` with `approve`, whatever the kind;
/// * not fenced: every read-only request (`inspect`, `observe`, the previews, `issuer`
///   `status` and `bundle`), `decide` with `deny`, `enrollment` `step_result` (a step
///   dispatched before the fence records its truth; a new one cannot be dispatched under
///   it), `issuer` `bundle_written`, and every M01/M02 request (`ensure` and `bind`
///   reach a certificate only through the reservation, which the application refuses
///   itself while the fence is held). An unknown action is fenced (fail closed).
fn fenced(request: &Request) -> bool {
    use heimdall_contract::issuer::IssuerRequest as I;
    use heimdall_contract::request::Verdict;
    match request {
        Request::Enrollment(r) => !matches!(
            r,
            EnrollmentRequest::Preview { .. } | EnrollmentRequest::StepResult { .. }
        ),
        Request::Issuer(r) => !matches!(r, I::Status | I::Bundle { .. } | I::BundleWritten { .. }),
        Request::Decide(r) => r.verdict != Verdict::Deny,
        _ => false,
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
    /// ⟨M03⟩ wave 4: connection control for `Request::Connections` (`None`: an unwired
    /// runtime, which answers `driver_unavailable`).
    connections: Option<Arc<ManagedConnections>>,
    /// ⟨M03 wave 4, round 3 (ADR-0008 §17.22 item 13; R2C-Q2)⟩ The runtime registry's
    /// live binding endpoints, which a managed `bind` result names
    /// ([`Self::with_binding_endpoints`]). `None`: no managed wiring, so no endpoint is
    /// named.
    binding_endpoints: Option<Arc<dyn crate::connections::BindingEndpoints>>,
    /// ⟨ADR-0008 §17.27 item 2⟩ This dispatcher's connection identity, for the
    /// uninstall fence ([`ConnectionScope`]).
    scope: ConnectionScope,
}

/// ⟨ADR-0008 §17.27 item 2⟩ One connection's identity for the uninstall fence. A
/// clone is a **new** identity (one per accepted connection, module docs); dropping
/// a scope releases the fence if that scope holds it, so a connection that ends for
/// any reason (the CLI finished, was refused, or died) never leaves it held.
struct ConnectionScope {
    id: u64,
    operations: Operations,
}

/// The next connection identity (never reused within a runtime).
static NEXT_CONNECTION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl ConnectionScope {
    fn new(operations: Operations) -> Self {
        Self {
            id: NEXT_CONNECTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            operations,
        }
    }
}

impl Clone for ConnectionScope {
    fn clone(&self) -> Self {
        Self::new(self.operations.clone())
    }
}

impl Drop for ConnectionScope {
    fn drop(&mut self) {
        let _ = self.operations.uninstall_fence_release(self.id);
    }
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
            scope: ConnectionScope::new(operations.clone()),
            operations,
            relay,
            clock,
            stop: None,
            connections: None,
            binding_endpoints: None,
        }
    }

    /// ⟨M03 wave 4, round 3 (ADR-0008 §17.22 item 13; R2C-Q2)⟩ Name the binding's
    /// endpoint in a managed `bind` result: `consumer.signing_endpoint` is read from
    /// `endpoints` (the runtime's endpoint registry) for **that exact** binding at the
    /// moment the result is answered, and is absent when the registry has no live
    /// endpoint for it, so `connect` refuses before launch (it never guesses one). The
    /// stored operation result is unchanged (it keeps no live state); a replay of the
    /// bind reads the registry again. Results of every other mechanism are returned as
    /// the application answered them (existing access unchanged).
    #[must_use]
    pub fn with_binding_endpoints(
        mut self,
        endpoints: Arc<dyn crate::connections::BindingEndpoints>,
    ) -> Self {
        self.binding_endpoints = Some(endpoints);
        self
    }

    /// The managed `bind` result with its live binding endpoint ([`Self::with_binding_endpoints`]).
    fn bind_result(
        &self,
        result: OpResult<heimdall_contract::request::EnsureData>,
    ) -> OpResult<heimdall_contract::request::EnsureData> {
        result.map(|mut done| {
            if done.data.credential_mechanism == heimdall_app::operations::MANAGED_CERTIFICATE {
                done.data.consumer.signing_endpoint = self
                    .binding_endpoints
                    .as_ref()
                    .and_then(|e| e.endpoint(&done.data.binding_id))
                    .map(|e| e.locator);
            }
            done
        })
    }

    /// ⟨M03⟩ wave 4 (U0b row 13, phase 2): route `Connections::{Close, Register}` to
    /// `connections` (U7's supervisor with the `Connection` events). Without it they
    /// answer `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) before any record is
    /// written.
    #[must_use]
    pub fn with_connections(mut self, connections: Arc<ManagedConnections>) -> Self {
        self.connections = Some(connections);
        self
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
        if let Request::UninstallFence(r) = request {
            return self.uninstall_fence(&caller, r).await;
        }
        // ⟨ADR-0008 §17.27 item 2, §17.28 item 1⟩ The uninstall fence ([`fenced`]): the
        // holder's requests run in its scope and are never refused; a fenced request
        // from any other connection holds the admission guard from its check until it
        // has been handled, and is refused while another connection holds the fence.
        let holder = self.operations.uninstall_fence_holder();
        if holder == Some(self.scope.id) {
            return heimdall_app::operations::as_fence_holder(self.route(caller, request)).await;
        }
        if fenced(&request) {
            let _admission = self.operations.uninstall_fence_admission().await;
            if self
                .operations
                .uninstall_fence_holder()
                .is_some_and(|h| h != self.scope.id)
            {
                return error_value(
                    heimdall_app::operations::uninstall_in_progress()
                        .with_effect(EffectStatus::None),
                );
            }
            return self.route(caller, request).await;
        }
        self.route(caller, request).await
    }

    /// Route one request that passed the session checks and the uninstall fence.
    async fn route(&self, caller: Caller, request: Request) -> Envelope<serde_json::Value> {
        let ops = &self.operations;
        match request {
            Request::Inspect(r) => render(ops.inspect(&caller, r).await),
            Request::Ensure(r) => render(ops.ensure(&caller, r).await),
            Request::Bind(r) => render(self.bind_result(ops.bind(&caller, r).await)),
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
            // ⟨M02⟩ m02-plan U0b row 17: routed to the application's entry points
            // (U5's drivers since the activation change set). A session reaches
            // these arms only after negotiating `setup/1` (row 19); a runtime without
            // a projection writer answers every Setup request
            // `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) before any admission
            // (row 18). Neither request reaches the wildcard below.
            Request::Setup(r) => render(ops.setup(&caller, r).await),
            Request::Catalog(r) => render(ops.catalog(&caller, r).await),
            // ⟨M03⟩ m03-plan U0b row 13, phase 2 (wave 4): routed to U10's drivers;
            // a driver or port that is not wired answers `CAPABILITY_UNAVAILABLE`
            // (`driver_unavailable`) before any record is written. The owner-only
            // requests (F20) are refused for any other role first: authorization
            // before capability, so a non-owner learns nothing about this build's
            // drivers, and the refusal reads and writes nothing.
            Request::Issuer(_) | Request::Enrollment(_) | Request::Connections(_) => {
                if owner_only_m03(&request) && !caller.context.is_owner() {
                    return error_value(
                        OpError::new(
                            Code::CapabilityUnavailable,
                            "this request needs the owner role",
                        )
                        .with_effect(EffectStatus::None),
                    );
                }
                // ⟨M03⟩ U0b row 13, phase 2 (wave 4): U10's drivers. A runtime whose
                // M03 ports are not wired answers `driver_unavailable` from them,
                // before any record is written.
                match request {
                    Request::Issuer(r) => render(ops.issuer_request(&caller, r).await),
                    Request::Enrollment(r) => render(ops.enrollment_request(&caller, r).await),
                    // ⟨M03⟩ wave 4: U7's connection control, with the `Connection`
                    // events (U7-Q3); an unwired runtime answers `driver_unavailable`.
                    Request::Connections(r) => match &self.connections {
                        Some(c) => render(connections_request(c, r).await),
                        None => error_value(OpError::driver_unavailable(
                            "connection control is not available in this runtime",
                        )),
                    },
                    _ => error_value(OpError::driver_unavailable(
                        "this request is not available in this build",
                    )),
                }
            }
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

    /// ⟨ADR-0008 §17.27 item 2⟩ `UninstallFence` (module docs): owner role only;
    /// `acquire` holds the fence for this connection (refused
    /// `uninstall_in_progress` while another holds it), `release` lifts it when this
    /// connection holds it. Answers `OK {"fence": "held" | "released"}`.
    async fn uninstall_fence(
        &self,
        caller: &Caller,
        request: heimdall_contract::request::UninstallFenceRequest,
    ) -> Envelope<serde_json::Value> {
        use heimdall_contract::request::UninstallFenceRequest;
        if !caller.context.is_owner() {
            return error_value(
                OpError::new(
                    Code::CapabilityUnavailable,
                    "service control needs the owner principal on the control endpoint",
                )
                .with_effect(EffectStatus::None),
            );
        }
        let held = match request {
            UninstallFenceRequest::Acquire => {
                match self.operations.uninstall_fence_acquire(self.scope.id).await {
                    Ok(_) => true,
                    Err(e) => return error_value(e.with_effect(EffectStatus::None)),
                }
            }
            UninstallFenceRequest::Release => {
                self.operations.uninstall_fence_release(self.scope.id)
            }
            _ => {
                return error_value(OpError::new(
                    Code::UsageError,
                    "this uninstall fence action is not supported by this runtime",
                ));
            }
        };
        value_envelope(Envelope::ok(serde_json::json!({
            "fence": if held { "held" } else { "released" },
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_app::operations::{Limits, OperationsConfig};
    use heimdall_contract::Timestamp;
    use heimdall_contract::request::UninstallFenceRequest;
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_store::Store;
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

    use super::*;

    fn t0() -> Timestamp {
        "2026-11-13T09:00:00Z".parse().unwrap()
    }

    async fn dispatcher() -> OperationsDispatcher {
        let env = EnvironmentId::from_random_bytes([5; 16]);
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        store
            .transaction(|tx| tx.init_self_environment(&env))
            .unwrap();
        let clock = VirtualClock::at(t0());
        let ops = Operations::start(OperationsConfig {
            store,
            clock: clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env,
            adapters: Vec::new(),
            stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
            limits: Limits::default(),
            default_window: std::time::Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap();
        let relay = EventRelay::spawn(&ops, CancellationToken::new());
        OperationsDispatcher::new(ops, relay, clock)
    }

    fn owner() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn fence(action: UninstallFenceRequest) -> Request {
        Request::UninstallFence(action)
    }

    fn apply() -> Request {
        let path =
            heimdall_testkit::repo::repo_path("schemas/examples/request.enrollment.apply.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn fenced_envelope(env: &Envelope<serde_json::Value>) -> bool {
        env.code == Code::ServiceUnavailable
            && env.data["error"]["reason"]
                == heimdall_contract::envelope::reason::UNINSTALL_IN_PROGRESS
    }

    /// `uninstall_fence_is_held_by_its_connection` (ADR-0008 §17.27 item 2): each
    /// dispatcher clone is one connection. The holder's `acquire` answers `held`; another
    /// connection's `acquire` and new enrollment work are refused
    /// `uninstall_in_progress`; that connection's `release` does not lift it. The
    /// holder's `release` lifts it, and so does the holder's connection ending (its
    /// dispatcher dropped), whatever happened before.
    #[tokio::test]
    async fn uninstall_fence_is_held_by_its_connection() {
        let listener = dispatcher().await;
        let a = listener.clone();
        let b = listener.clone();
        let held = a
            .handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(held.code, Code::Ok, "{held:?}");
        assert_eq!(held.data["fence"], "held");
        assert!(fenced_envelope(
            &b.handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
                .await
        ));
        assert!(fenced_envelope(&b.handle_as(&owner(), apply()).await));
        let other = b
            .handle_as(&owner(), fence(UninstallFenceRequest::Release))
            .await;
        assert_eq!(
            other.data["fence"], "held",
            "another connection cannot lift it"
        );
        assert!(fenced_envelope(&b.handle_as(&owner(), apply()).await));
        let lifted = a
            .handle_as(&owner(), fence(UninstallFenceRequest::Release))
            .await;
        assert_eq!(lifted.data["fence"], "released");
        assert!(!fenced_envelope(&b.handle_as(&owner(), apply()).await));
        // Held again, then the holder's connection ends: lifted.
        let c = listener.clone();
        assert_eq!(
            c.handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
                .await
                .code,
            Code::Ok
        );
        assert!(fenced_envelope(&b.handle_as(&owner(), apply()).await));
        drop(c);
        assert!(!fenced_envelope(&b.handle_as(&owner(), apply()).await));
        let taken = b
            .handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(taken.data["fence"], "held", "{taken:?}");
    }

    fn attended() -> Caller {
        Caller {
            context: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            attendance: Attendance::Attended { since: t0() },
            interaction: heimdall_contract::request::InteractionMode::Interactive,
        }
    }

    fn example(name: &str) -> Request {
        let path =
            heimdall_testkit::repo::repo_path(format!("schemas/examples/request.{name}.json"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn deny() -> Request {
        let mut v: serde_json::Value = serde_json::to_value(example("decide")).unwrap();
        v["verdict"] = "deny".into();
        serde_json::from_value(v).unwrap()
    }

    /// `uninstall_fence_refuses_remote_and_ca_work_from_other_connections` (ADR-0008
    /// §17.28 item 1): while one connection holds the fence, every other connection's
    /// request that can start or advance remote or CA work is refused
    /// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` (`step`, `abandon`, `reconcile`,
    /// `apply`, `verify`, `remove` own and foreign; issuer `register` incl. rotation and
    /// restore, `unlock`, `retire` incl. its deletion confirmation; an approval), and
    /// the rest is not (a denial, `step_result`, the previews and reads,
    /// `bundle_written`). The holder's own requests, its retirement and approval
    /// included, are never refused for the fence. After the fence is lifted nothing is.
    #[tokio::test]
    async fn uninstall_fence_refuses_remote_and_ca_work_from_other_connections() {
        let listener = dispatcher().await;
        let holder = listener.clone();
        let other = listener.clone();
        let table: Vec<(Request, bool)> = vec![
            (example("enrollment.step"), true),
            (example("enrollment.abandon"), true),
            (example("enrollment.reconcile"), true),
            (example("enrollment.apply"), true),
            (example("enrollment.verify"), true),
            (example("enrollment.remove"), true),
            (example("enrollment.remove-foreign"), true),
            (example("issuer.retire"), true),
            (example("issuer.retire-confirm"), true),
            (example("issuer.register"), true),
            (example("issuer.register-rotation"), true),
            (example("issuer.register-restore"), true),
            (example("issuer.unlock"), true),
            (example("decide"), true),
            (deny(), false),
            (example("enrollment.step-result"), false),
            (example("enrollment.preview"), false),
            (example("issuer.status"), false),
            (example("issuer.bundle"), false),
            (example("issuer.bundle-written"), false),
            (example("ensure"), false),
        ];
        let acquired = holder
            .handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(acquired.data["fence"], "held", "{acquired:?}");
        for (request, refused) in &table {
            let kind = request.kind();
            assert_eq!(fenced(request), *refused, "{kind}: the table");
            let env = other.handle_as(&attended(), request.clone()).await;
            assert_eq!(
                fenced_envelope(&env),
                *refused,
                "{kind} from another connection: {env:?}"
            );
            let env = holder.handle_as(&attended(), request.clone()).await;
            assert!(!fenced_envelope(&env), "{kind} from the holder: {env:?}");
        }
        let lifted = holder
            .handle_as(&owner(), fence(UninstallFenceRequest::Release))
            .await;
        assert_eq!(lifted.data["fence"], "released");
        for (request, _) in &table {
            let env = other.handle_as(&attended(), request.clone()).await;
            assert!(
                !fenced_envelope(&env),
                "{} after the release: {env:?}",
                request.kind()
            );
        }
    }

    /// Only the owner may take or lift the fence.
    #[tokio::test]
    async fn uninstall_fence_needs_the_owner() {
        let d = dispatcher().await;
        let consumer = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::LimitedConsumer,
        });
        let refused = d
            .handle_as(&consumer, fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
        assert!(!d.operations.uninstall_fence_held());
    }
}
