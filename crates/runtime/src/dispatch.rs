//! The control endpoint's [`Dispatcher`] over [`Operations`] (overview §1: "`ipc`
//! does not know `app`; the runtime supplies a `Dispatcher`"; ADR-0006 §2.3, §3.1,
//! §8).
//!
//! * **Caller.** Built from the session only: the principal the transport
//!   authenticated (Unix peer credentials, Windows client SID), the role `Owner`
//!   (a peer that passed the same-user check is the owner), the hello's interaction
//!   mode, and attendance as the session recorded it. Nothing is read from request
//!   content (A29: no client-supplied "attended" value). ⟨M06 W2⟩ On a **runner**
//!   ([`OperationsDispatcher::with_runner`], `crate::paired`), a session whose hello
//!   names a paired client is bound at the hello to the client the role table resolves
//!   ([`Dispatcher::bind_paired`]); its caller is `{principal, role, remote_client}` with
//!   the table's role, every frame is checked against the client's row before dispatch,
//!   its live events are scoped ([`Dispatcher::live_visibility`]) and it ends when the
//!   client is revoked ([`Dispatcher::session_end`]). Any other runtime refuses such a
//!   hello.
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
use heimdall_ipc::session::{
    Dispatcher, LiveEvent, LiveVisibility, PairedBinding, SessionEndFuture, SessionInfo,
    SubscriptionStart, server_capabilities,
};
use std::collections::BTreeSet;

use heimdall_contract::ipc::{ClientHello, capability};

use crate::paired::{PairedRunner, PairedSession};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::supervisor::ManagedConnections;

/// The authenticated caller for one request: principal and role from the
/// transport, interaction and attendance from the session (never from request
/// fields).
#[must_use]
pub fn caller_for(session: &SessionInfo, now: heimdall_contract::Timestamp) -> Caller {
    let principal = principal_ref(&session.principal);
    // ⟨rev6⟩ ADR-0006 §18: no paired client. ⟨M06 W2⟩ Only a runner runtime's paired
    // session has one, from its bridge's hello resolved by the role table
    // (`crate::paired::PairedRunner::caller`); no request field ever sets it.
    Caller {
        context: CallerContext::local(principal, ClientRole::Owner),
        attendance: if session.attended {
            Attendance::Attended { since: now }
        } else {
            Attendance::Unattended
        },
        interaction: session.interaction,
    }
}

/// The domain principal of the transport's authenticated peer.
#[must_use]
pub fn principal_ref(principal: &PrincipalInfo) -> PrincipalRef {
    match principal {
        PrincipalInfo::OsUserUnix { uid } => PrincipalRef::UnixUser { uid: *uid },
        PrincipalInfo::OsUserWindows { sid } => PrincipalRef::WindowsUser { sid: sid.clone() },
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
    let stuck = e.reason.as_deref()
        == Some(heimdall_contract::envelope::reason::UNINSTALL_FENCE_RELEASE_STUCK);
    let mut env = e
        .into_envelope()
        .map(|d: ErrorData| serde_json::to_value(d).unwrap_or_default());
    // ⟨ADR-0008 §17.33 item 9⟩ A fence stuck releasing names the way out in the error
    // data too: the command, and the two-step restart.
    if stuck && let serde_json::Value::Object(map) = &mut env.data {
        map.insert(
            "next_command".to_owned(),
            heimdall_app::operations::UNINSTALL_FENCE_RELEASE_STUCK_NEXT_COMMAND.into(),
        );
        map.insert(
            "next_step".to_owned(),
            heimdall_app::operations::UNINSTALL_FENCE_RELEASE_STUCK_NEXT_STEP.into(),
        );
    }
    env
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
/// the holder: the application's one classification
/// ([`heimdall_app::operations::uninstall_fenced`], whose docs list it; the
/// request-to-verdict table is in `.m03-wave5-r3-api.md` § U3).
fn fenced(request: &Request) -> bool {
    heimdall_app::operations::uninstall_fenced(request)
}

/// ⟨M06 W3 host⟩ How long a local cutoff of every policy waits for the hosted driver's
/// delivery pass before it answers with what is still pending.
const RUNNER_DELIVERY_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

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
    /// ⟨M06 W2⟩ The runner's paired-session service (`None`: this runtime is not a runner,
    /// and a hello naming a paired client is refused, wave 0's answer).
    runner: Option<Arc<PairedRunner>>,
    /// ⟨M06 W2⟩ This connection's paired client, bound once at the hello
    /// ([`Dispatcher::bind_paired`]) for the session's lifetime. A clone keeps it, so a
    /// bound dispatcher never becomes the local owner.
    paired: Option<PairedSession>,
    /// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The store the controller-record forms write
    /// ([`Self::with_controller_records`]); `None`: they answer `driver_unavailable`.
    controller_records: Option<Arc<heimdall_store::Store>>,
    /// ⟨M06 W3 host⟩ The hosted controller driver ([`Self::with_outbox_delivery`]): a
    /// narrowing put in a runner's outbox is delivered without waiting for its next pass.
    /// `None`: the row waits for the next reconnect.
    outbox_delivery: Option<Arc<dyn heimdall_app::remote_status_driver::OutboxDelivery>>,
    /// ⟨M06 W3 grant-path⟩ The hosted controller driver as the forwarder of an `ensure`
    /// that names a recorded runner's environment ([`Self::with_ensure_forwarding`]).
    ensure_forwarding: Option<Arc<dyn heimdall_app::remote_status_driver::EnsureForwarding>>,
    /// ⟨M06 W3⟩ The route and transport forms ([`Self::with_route_transport`]); `None`: they
    /// answer `driver_unavailable` (wave 0's landing) and `routes/1` and `transport-iroh/1`
    /// are not offered.
    route_transport: Option<Arc<crate::supervise_transport::RouteTransport>>,
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
            runner: None,
            paired: None,
            controller_records: None,
            outbox_delivery: None,
            ensure_forwarding: None,
            route_transport: None,
        }
    }

    /// ⟨M06 W3 grant-path; ADR-0012 §4 item 2 ⟨2026-11-21⟩⟩ Forward the local owner's
    /// `ensure` that names a runner this controller records through `forwarding` (the hosted
    /// controller driver), which records exactly what was asked. An `ensure` naming any
    /// other environment, a paired caller's, and every `ensure` on a runner take the local
    /// path unchanged.
    #[must_use]
    pub fn with_ensure_forwarding(
        mut self,
        forwarding: Arc<dyn heimdall_app::remote_status_driver::EnsureForwarding>,
    ) -> Self {
        self.ensure_forwarding = Some(forwarding);
        self
    }

    /// ⟨M06 W3 host⟩ Tell `delivery` (the hosted controller driver) when a local narrowing
    /// became an outbox row for a runner.
    #[must_use]
    pub fn with_outbox_delivery(
        mut self,
        delivery: Arc<dyn heimdall_app::remote_status_driver::OutboxDelivery>,
    ) -> Self {
        self.outbox_delivery = Some(delivery);
        self
    }

    /// ⟨M06 W3; m06-plan W2 carry-over⟩ Serve `Request::Route` and `Request::Transport`
    /// through `service` (`crate::supervise_transport::RouteTransport`), and offer `routes/1`
    /// and `transport-iroh/1`.
    #[must_use]
    pub fn with_route_transport(
        mut self,
        service: Arc<crate::supervise_transport::RouteTransport>,
    ) -> Self {
        self.route_transport = Some(service);
        self
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ Serve `Request::ControllerRecord` over `store` (the
    /// controller's records of its runners, which the CLI writes through the runtime while
    /// one runs): the local owner only; a paired session is refused.
    #[must_use]
    pub fn with_controller_records(mut self, store: Arc<heimdall_store::Store>) -> Self {
        self.controller_records = Some(store);
        self
    }

    /// `Request::ControllerRecord` ([`Self::with_controller_records`]): a paired caller is
    /// refused `INTERACTION_REQUIRED` with reason `local_owner_required` (ruling Q5, ADR-0006
    /// §18.7 item 9), a local caller without the owner role `CAPABILITY_UNAVAILABLE`; then
    /// `heimdall_app::remote_env::apply_controller_record`, with the host-key fingerprint from
    /// `heimdall-credential`.
    fn controller_record(
        &self,
        caller: &Caller,
        request: &heimdall_contract::controller_record::ControllerRecordRequest,
    ) -> Envelope<serde_json::Value> {
        if caller.context.remote_client.is_some() {
            // ⟨ruling Q5; ADR-0006 §18.7 item 9⟩ The controller's records are the local
            // owner's alone.
            return error_value(
                OpError::new(
                    Code::InteractionRequired,
                    "the controller's records are written by the local owner only",
                )
                .with_reason(heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED)
                .with_effect(EffectStatus::None),
            );
        }
        if !caller.context.has_global_access() {
            return error_value(
                OpError::new(
                    Code::CapabilityUnavailable,
                    "this request needs the owner role",
                )
                .with_effect(EffectStatus::None),
            );
        }
        let Some(store) = &self.controller_records else {
            return error_value(OpError::driver_unavailable(
                "the controller's records are not available in this runtime",
            ));
        };
        render(
            heimdall_app::remote_env::apply_controller_record(
                store,
                request,
                &heimdall_credential::mgmt::openssh_fingerprint,
            )
            .map(|data| heimdall_app::error::Completed::ok(Code::Ok, data)),
        )
    }

    /// ⟨M06 W3 `driver`⟩ The controller's store for a narrowing that names a runner's grant
    /// or policy ([`Self::with_controller_records`]'s store, which holds the pins and the
    /// outbox): for the local owner only, and never on a runner (a runner records no
    /// runners; a paired owner's narrowing of this runtime's own grants is local).
    fn runner_narrowing_store(&self, caller: &Caller) -> Option<&Arc<heimdall_store::Store>> {
        if caller.context.remote_client.is_some()
            || !caller.context.has_global_access()
            || self.runner.is_some()
        {
            return None;
        }
        self.controller_records.as_ref()
    }

    /// ⟨M06 W2⟩ Serve paired sessions as a runner (`crate::paired`): offer
    /// `remote-control/1`, resolve a hello's client in the role table, check every paired
    /// frame, scope its live events, and decide runner-local widening records locally.
    #[must_use]
    pub fn with_runner(mut self, runner: Arc<PairedRunner>) -> Self {
        self.runner = Some(runner);
        self
    }

    /// The caller of `session` on this connection: the paired client's when bound
    /// ([`PairedRunner::caller`]), else the local owner ([`caller_for`]).
    fn caller(&self, session: &SessionInfo) -> Caller {
        match (&self.paired, &self.runner) {
            (Some(p), Some(r)) => r.caller(&session.principal, p),
            _ => caller_for(session, self.clock.wall()),
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
        // ⟨M06 W2⟩ A paired session: every frame is checked against the client's row first
        // (`crate::paired`); only a request that passes reaches the application, as the
        // client's caller.
        if let Some(paired) = &self.paired {
            // ⟨ruling Q5; ADR-0006 §18.7 item 9⟩ A paired session's controller-record form is
            // answered here, whatever its role (the refusal names the local owner).
            if let Request::ControllerRecord(r) = &request {
                return self.controller_record(&self.caller(session), r);
            }
            // ⟨rev6.3; ADR-0006 §18.7 item 10⟩ So is `transport.rotate`: rotating this
            // device's K_iroh is the local owner's alone (`local_owner_required`), whatever
            // the paired client's role, and nothing is left pending.
            if matches!(
                request,
                Request::Transport(heimdall_contract::route::TransportRequest::Rotate)
            ) {
                return error_value(
                    heimdall_remote::roles::Refusal::LocalOwnerRequired.to_op_error(),
                );
            }
            let Some(runner) = &self.runner else {
                return error_value(
                    OpError::new(
                        Code::SchemaUnsupported,
                        "this runtime does not accept a paired client",
                    )
                    .with_effect(EffectStatus::None),
                );
            };
            return match runner.frame(&session.principal, paired, request).await {
                crate::paired::Frame::Answer(env) => env,
                crate::paired::Frame::Route(caller, request) => {
                    // ⟨M06 W2⟩ Reads that list events or decisions (event pages, snapshots,
                    // `inspect decisions`) reach a paired caller without decision handles.
                    let reads = matches!(request, Request::Observe(_) | Request::Inspect(_));
                    let mut env = self.handle_as(&caller, request).await;
                    if reads {
                        crate::paired::redact_value(&mut env.data);
                    }
                    env
                }
            };
        }
        let caller = caller_for(session, self.clock.wall());
        // ⟨M06 W2; ADR-0012 §3.10 item 2⟩ On a runner, `Decide` on a runner-local widening
        // record is decided here, locally (attended only); any other decision goes to the
        // application.
        if let (Some(runner), Request::Decide(d)) = (&self.runner, &request) {
            // An approval runs the recorded request: it is admitted past the uninstall fence
            // as the application's own approvals are (ADR-0008 §17.31 item 2), unless this
            // connection holds the fence.
            let admission = if d.verdict == heimdall_contract::request::Verdict::Approve
                && self
                    .operations
                    .uninstall_fence_lease(self.scope.id)
                    .is_none()
            {
                match self.operations.uninstall_fence_admit() {
                    Ok(a) => Some(a),
                    Err(e) => return error_value(e.with_effect(EffectStatus::None)),
                }
            } else {
                None
            };
            let decided = runner.decide_local(caller.is_attended(), d).await;
            drop(admission);
            if let Some(env) = decided {
                return env;
            }
        }
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
        // ⟨rev 6.3; ADR-0006 §18.7 item 9⟩ A paired session's `decide` has no remote path:
        // it names its reason, so a wrapper does not ask the user and retry.
        // ⟨§18.7 item 15⟩ So does every attended-only form: a paired caller is never the
        // local owner, whatever its session says about attendance.
        if (matches!(request, Request::Decide(_)) || request.requires_attended_session())
            && caller.context.remote_client.is_some()
        {
            return error_value(heimdall_remote::roles::Refusal::LocalOwnerRequired.to_op_error());
        }
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
        // ⟨ADR-0008 §17.27 item 2, §17.28 item 1, §17.31 item 2⟩ The uninstall fence
        // ([`fenced`]): the holder's requests run in its scope and are never refused; a
        // fenced request from any other connection holds the admission from its check
        // until it has been handled, and is refused while another connection holds the
        // fence or is acquiring it. The application routes check again themselves.
        // ⟨§17.33 item 1⟩ The holder's request runs under its lease (this connection, the
        // fence's current generation), which it carries into the work it spawns and
        // re-checks at each step; a releasing or released fence grants none.
        if let Some(lease) = self.operations.uninstall_fence_lease(self.scope.id) {
            return heimdall_app::operations::with_fence_lease(lease, self.route(caller, request))
                .await;
        }
        if fenced(&request) {
            // ⟨§17.31 item 2⟩ The application's one admission (refused while the fence
            // is held or being acquired), held until the request has been handled.
            let _admission = match self.operations.uninstall_fence_admit() {
                Ok(a) => a,
                Err(e) => return error_value(e.with_effect(EffectStatus::None)),
            };
            return self.route(caller, request).await;
        }
        self.route(caller, request).await
    }

    /// Route one request that passed the session checks and the uninstall fence.
    async fn route(&self, caller: Caller, request: Request) -> Envelope<serde_json::Value> {
        let ops = &self.operations;
        // ⟨M06 W2⟩ On a runner, an owner's client revocation (narrowing, ADR-0012 §3.11) is
        // served by the runner (a paired owner's arrives through `PairedRunner::frame`).
        if let (
            Some(runner),
            Request::RemoteEnvironment(
                heimdall_contract::remote::RemoteEnvironmentRequest::RevokeClient {
                    environment,
                    client,
                },
            ),
        ) = (&self.runner, &request)
            && caller.context.is_owner()
        {
            return runner.revoke_client(environment, client).await;
        }
        // ⟨M06 W3⟩ On a runner, a controller's `runner/1` forms reach the runner runtime (a
        // paired session's arrive here only after `PairedRunner::frame`'s role-table and
        // pre-dispatch checks; `RunnerRuntime::handle` refuses a caller without a paired
        // client), and the runner-local decisions are the runner's (local owner only). Every
        // other runtime refuses both below, as before.
        if let Some(runner) = &self.runner {
            match &request {
                Request::Runner(r) if runner.runtime().is_some() => {
                    return runner
                        .runner_request(&caller, self.scope.id, r.clone())
                        .await;
                }
                Request::RunnerLocal(r) => return runner.runner_local(&caller, r.clone()).await,
                _ => {}
            }
        }
        match request {
            Request::Inspect(r) => render(ops.inspect(&caller, r).await),
            Request::Ensure(r) => {
                // ⟨M06 W3 grant-path⟩ The local owner's `ensure` naming a recorded runner's
                // environment is forwarded over the management session; the forwarder
                // answers `None` for every other environment, and the local path stands.
                if r.environment.is_some()
                    && self.runner_narrowing_store(&caller).is_some()
                    && let Some(forwarding) = &self.ensure_forwarding
                    && let Some(answer) = forwarding.forward(&r).await
                {
                    return render(answer);
                }
                render(ops.ensure(&caller, r).await)
            }
            Request::Bind(r) => render(self.bind_result(ops.bind(&caller, r).await)),
            Request::Delegate(r) => render(ops.delegate(&caller, r).await),
            Request::Observe(r) => render(ops.observe(&caller, r).await),
            Request::Cancel(r) => render(ops.cancel(&caller, r).await),
            Request::Release(r) => render(ops.release(&caller, r).await),
            Request::Revoke(r) => {
                let named = r.grant_id.clone();
                let local = ops.revoke(&caller, r).await;
                // ⟨M06 W3 `driver`; ADR-0012 §7.2⟩ A grant this installation does not hold
                // may live on a runner this controller records: the owner's revoke is then a
                // typed effect in the outbox, `remote_pending` until the runner acknowledges.
                match (&local, named, self.runner_narrowing_store(&caller)) {
                    (Err(e), Some(grant), Some(store)) if e.code == Code::NotFound => {
                        let narrowed = heimdall_app::remote_status_driver::revoke_on_runner(
                            store,
                            &grant,
                            heimdall_contract::Timestamp::now(),
                        );
                        // ⟨host⟩ `OK`, `local_applied: false`, the grant `remote_pending`:
                        // the hosted driver delivers it without waiting for its next pass.
                        if matches!(narrowed, Some(Ok(_)))
                            && let Some(d) = &self.outbox_delivery
                        {
                            d.notify();
                        }
                        render(narrowed.unwrap_or(local))
                    }
                    _ => render(local),
                }
            }
            // Widening actions included: the application answers with a decision
            // record and never executes them here (R5, N04).
            Request::Policy(r) => {
                let local = ops.policy(&caller, r.clone()).await;
                // ⟨M06 W3 `driver`⟩ As the revoke above, for a pause or cutoff naming one
                // policy a recorded runner's last report listed. Never a widening.
                match (local, self.runner_narrowing_store(&caller)) {
                    (Err(e), Some(store)) if e.code == Code::NotFound => {
                        let narrowed = heimdall_app::remote_status_driver::policy_on_runner(
                            store,
                            &r,
                            heimdall_contract::Timestamp::now(),
                        );
                        if matches!(narrowed, Some(Ok(_)))
                            && let Some(d) = &self.outbox_delivery
                        {
                            d.notify();
                        }
                        render(narrowed.unwrap_or(Err(e)))
                    }
                    // ⟨M06 W3 host; ruling on `driver` Q2⟩ A local cutoff of every policy
                    // that was applied here also goes to every runner this controller
                    // owns (it only narrows); a profile's or a workspace's stays local.
                    // The answer lists every runner it was delivered to and every runner
                    // it is still pending on.
                    (Ok(mut done), Some(store))
                        if done.state == heimdall_contract::OperationState::Succeeded
                            && done.data.get("policies").is_some() =>
                    {
                        if let Some(at) = heimdall_app::remote_status_driver::cutoff_of_all(&r)
                            && let Ok(sent) =
                                heimdall_app::remote_status_driver::cutoff_all_on_runners(
                                    store,
                                    at,
                                    heimdall_contract::Timestamp::now(),
                                )
                            && !sent.is_empty()
                        {
                            if let Some(d) = &self.outbox_delivery {
                                d.deliver(RUNNER_DELIVERY_BOUND).await;
                            }
                            if let Some(data) = done.data.as_object_mut() {
                                data.insert(
                                    "runners".to_owned(),
                                    heimdall_app::remote_status_driver::runner_deliveries(
                                        store, &sent,
                                    ),
                                );
                            }
                        }
                        render(Ok(done))
                    }
                    (local, _) => render(local),
                }
            }
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
            // ⟨M04⟩ ADR-0006 revision 5: add or remove a WSL or container environment.
            // Owner role first (authorization before capability); then the application's
            // entry point (`Operations::environment_request`): U3b's WSL forms (Mode B
            // answers `driver_unavailable` until U4) and U5's container forms.
            Request::Environment(r) => {
                if !caller.context.is_owner() {
                    return error_value(
                        OpError::new(
                            Code::CapabilityUnavailable,
                            "this request needs the owner role",
                        )
                        .with_effect(EffectStatus::None),
                    );
                }
                render(ops.environment_request(&caller, r).await)
            }
            // ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The controller's own records.
            Request::ControllerRecord(r) => self.controller_record(&caller, &r),
            // ⟨M06 W3⟩ The route and transport forms, when this runtime serves them.
            Request::Route(r) if self.route_transport.is_some() => match &self.route_transport {
                Some(t) => render(
                    t.route(&caller, &r, self.clock.wall())
                        .map(|data| heimdall_app::error::Completed::ok(Code::Ok, data)),
                ),
                None => error_value(OpError::driver_unavailable("routes are not served")),
            },
            Request::Transport(r) if self.route_transport.is_some() => {
                match &self.route_transport {
                    Some(t) => render(
                        t.transport(&caller, &r, self.clock.wall())
                            .await
                            .map(|data| heimdall_app::error::Completed::ok(Code::Ok, data)),
                    ),
                    None => error_value(OpError::driver_unavailable("transport is not served")),
                }
            }
            // ⟨M06⟩ ADR-0006 revision 6 (§18): every revision-6 form answers
            // `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) from the application before
            // any record is written, whatever the role (wave 0; a session never gets here,
            // their capabilities are not offered).
            Request::RemoteEnvironment(_)
            | Request::Device(_)
            | Request::Route(_)
            | Request::Transport(_)
            | Request::Runner(_)
            | Request::RunnerLocal(_) => render(ops.revision_6_request(&caller, &request).await),
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
            // ⟨§17.33 item 1⟩ Waits (bounded) for the holder's in-flight work.
            UninstallFenceRequest::Release => {
                match self
                    .operations
                    .uninstall_fence_release_waiting(self.scope.id)
                    .await
                {
                    Ok(held) => held,
                    Err(e) => return error_value(e),
                }
            }
            // ⟨ADR-0008 §17.32 item 7⟩ Holder only: the application takes this
            // connection's lease and runs each round under it (§17.33 item 1).
            UninstallFenceRequest::RetryRemoteRevocations => {
                let retried = self
                    .operations
                    .uninstall_fence_retry_remote_revocations(self.scope.id)
                    .await;
                return match retried {
                    Ok(r) => value_envelope(Envelope::ok(serde_json::json!({
                        "remote_revocations": r,
                    }))),
                    Err(e) => error_value(e),
                };
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
        // ⟨M06 W2⟩ A paired session's subscription: the client's row is rechecked first.
        if let (Some(p), Some(r)) = (&self.paired, &self.runner)
            && let Err(refusal) = r.subscribe_check(p)
        {
            return Err(Box::new(refusal.envelope()));
        }
        let caller = self.caller(session);
        let paired = self.paired.is_some();
        // Created before the boundary is read: nothing committed after it is missed.
        // ⟨M06 W2⟩ A paired session's live events come with every decision handle stripped.
        let live = if paired {
            self.relay.subscribe_paired()
        } else {
            self.relay.subscribe()
        };
        match self
            .operations
            .events()
            .subscribe(&caller.context, filter, from, false)
            .await
        {
            Ok(mut start) => {
                // ⟨M06 W2⟩ And so do its resumed backlog and its snapshot.
                if paired {
                    start
                        .backlog
                        .iter_mut()
                        .for_each(crate::paired::redact_event);
                    if let Some(snapshot) = &mut start.snapshot {
                        crate::paired::redact_value(&mut snapshot.data);
                    }
                }
                Ok(SubscriptionStart {
                    cursor: start.cursor,
                    boundary_seq: start.boundary_seq,
                    snapshot: start.snapshot,
                    backlog: start.backlog,
                    live,
                    cursor_for: start.cursor_for,
                })
            }
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

    /// ⟨M06-W0-R03; M06 W2, blocking⟩ A paired session's live events reach it only within
    /// its client scope and the environment views its role permits, while its client is not
    /// revoked ([`PairedRunner::live_visibility`]); the local owner keeps every event.
    fn live_visibility(&self, session: &SessionInfo) -> Option<LiveVisibility> {
        match (&self.paired, &self.runner) {
            (None, _) => None,
            (Some(p), Some(r)) => {
                let caller = r.caller(&session.principal, p);
                Some(r.live_visibility(&caller.context, &p.client))
            }
            // Unreachable by construction (a binding needs the runner); fail closed.
            (Some(_), None) => Some(Arc::new(|_: &heimdall_contract::event::Event| false)),
        }
    }

    /// ⟨M06 W2⟩ A runner also offers `remote-control/1` (ADR-0012 §6.3); every other
    /// runtime keeps this build's offer.
    fn offered_capabilities(&self) -> BTreeSet<String> {
        let mut offer = server_capabilities();
        if let Some(runner) = &self.runner {
            offer.insert(capability::REMOTE_CONTROL_V1.to_owned());
            // ⟨M06 W3⟩ A runner with its runner runtime also offers `runner/1`, so a paired
            // owner controller's `runner.*` forms reach it (the role term keeps it from
            // limited roles; a pending session negotiates `remote-control/1` only).
            if runner.runtime().is_some() {
                offer.insert(capability::RUNNER_V1.to_owned());
            }
        }
        // ⟨M06 W3⟩ The route and transport forms are offered where they are served.
        if self.route_transport.is_some() {
            offer.insert(capability::ROUTES_V1.to_owned());
            offer.insert(capability::TRANSPORT_IROH_V1.to_owned());
        }
        offer
    }

    /// ⟨M06 W2; ADR-0006 §18.5 reading 1⟩ Resolve the hello's paired client in the runner's
    /// role table ([`PairedRunner::bind`]) and bind this connection to it.
    fn bind_paired(
        &mut self,
        hello: &ClientHello,
    ) -> Result<PairedBinding, Box<Envelope<ErrorData>>> {
        let Some(runner) = &self.runner else {
            return Err(Box::new(
                OpError::new(
                    Code::SchemaUnsupported,
                    "this runtime does not accept a paired client",
                )
                .with_effect(EffectStatus::None)
                .into_envelope(),
            ));
        };
        match runner.bind(hello) {
            Ok(Some(session)) => {
                let binding = PairedBinding {
                    role: session.role,
                    pending: session.pending,
                };
                self.paired = Some(session);
                Ok(binding)
            }
            Ok(None) => Err(Box::new(
                OpError::new(Code::SchemaUnsupported, "the hello names no paired client")
                    .with_effect(EffectStatus::None)
                    .into_envelope(),
            )),
            Err(refusal) => Err(Box::new(refusal.envelope())),
        }
    }

    /// ⟨M06 W2⟩ A paired session ends when its client is revoked
    /// ([`PairedRunner::session_end`]).
    fn session_end(&self) -> Option<SessionEndFuture> {
        match (&self.paired, &self.runner) {
            (Some(p), Some(r)) => Some(r.session_end(p)),
            _ => None,
        }
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
    /// ⟨M06 W2⟩ The same events with every decision handle stripped
    /// (`crate::paired::redact_event`), for paired sessions' subscriptions.
    paired: broadcast::Sender<Arc<LiveEvent>>,
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
        let (paired, _) = broadcast::channel(EVENT_BUFFER_PER_SUBSCRIPTION);
        let mut from_app = operations.events().live_receiver();
        let environment = operations.environment().clone();
        let out = tx.clone();
        let out_paired = paired.clone();
        tokio::spawn(async move {
            loop {
                let next = tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    r = from_app.recv() => r,
                };
                match next {
                    Ok(ev) => {
                        if out_paired.receiver_count() > 0 {
                            let mut event = ev.event.clone();
                            crate::paired::redact_event(&mut event);
                            let _ = out_paired.send(Arc::new(LiveEvent { seq: ev.seq, event }));
                        }
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
                            let _ = out_paired.send(filler.clone());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Self { tx, paired }
    }

    /// A receiver for one subscription.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.tx.subscribe()
    }

    /// ⟨M06 W2⟩ A receiver for one paired session's subscription: the same events, in the
    /// same order and with the same lag behaviour, with every decision handle stripped.
    #[must_use]
    pub fn subscribe_paired(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.paired.subscribe()
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
            remote_client: None,
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

    /// `uninstall_fence_retry_is_holder_only` (ADR-0008 §17.32 item 7): through the
    /// dispatcher, `retry_remote_revocations` is refused `SERVICE_UNAVAILABLE` on a
    /// connection that does not hold the fence (`uninstall_in_progress` while another
    /// holds it; no reason when none does) and answers the holder with its records.
    #[tokio::test]
    async fn uninstall_fence_retry_is_holder_only() {
        let listener = dispatcher().await;
        let a = listener.clone();
        let b = listener.clone();
        let retry = || fence(UninstallFenceRequest::RetryRemoteRevocations);
        let none = a.handle_as(&owner(), retry()).await;
        assert_eq!(none.code, Code::ServiceUnavailable, "{none:?}");
        assert!(none.data["error"]["reason"].is_null(), "{none:?}");
        assert_eq!(
            a.handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
                .await
                .code,
            Code::Ok
        );
        assert!(fenced_envelope(&b.handle_as(&owner(), retry()).await));
        let held = a.handle_as(&owner(), retry()).await;
        assert_eq!(held.code, Code::Ok, "{held:?}");
        assert_eq!(held.data["remote_revocations"], serde_json::json!([]));
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
                remote_client: None,
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

    /// `fence_release_stuck_refusal_names_the_restart` (ADR-0008 §17.33 item 9): while the
    /// holder's work never ends, its `release` waits out its bound and reports
    /// `uninstall_fence_release_stuck`; another connection's fenced request then gets that
    /// reason too, with `data.next_command` `heimdall service stop` and `data.next_step`
    /// naming the restart. Before the release, the same request gets
    /// `uninstall_in_progress` with no next command.
    #[tokio::test(start_paused = true)]
    async fn fence_release_stuck_refusal_names_the_restart() {
        let listener = dispatcher().await;
        let holder = listener.clone();
        let other = listener.clone();
        let acquired = holder
            .handle_as(&owner(), fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(acquired.data["fence"], "held", "{acquired:?}");
        let env = other
            .handle_as(&attended(), example("enrollment.step"))
            .await;
        assert_eq!(
            env.data["error"]["reason"], "uninstall_in_progress",
            "{env:?}"
        );
        assert!(env.data.get("next_command").is_none());
        let never_ends = holder
            .operations
            .uninstall_fence_lease(holder.scope.id)
            .unwrap();
        let released = holder
            .handle_as(&owner(), fence(UninstallFenceRequest::Release))
            .await;
        assert_eq!(released.code, Code::ServiceUnavailable, "{released:?}");
        assert_eq!(
            released.data["error"]["reason"],
            "uninstall_fence_release_stuck"
        );
        let env = other
            .handle_as(&attended(), example("enrollment.step"))
            .await;
        assert_eq!(env.code, Code::ServiceUnavailable, "{env:?}");
        assert_eq!(env.data["error"]["reason"], "uninstall_fence_release_stuck");
        assert_eq!(env.data["next_command"], "heimdall service stop");
        assert_eq!(
            env.data["next_step"],
            "stop the runtime (`heimdall service stop`), then start it again (`heimdall service run --detach`)"
        );
        drop(never_ends);
        assert!(!holder.operations.uninstall_fence_held());
    }

    /// ⟨rev6⟩ ADR-0006 §18 (the revision-5 precedent, §17.7 "The landing"): every
    /// revision-6 request form reached in process, from the owner and from a limited caller,
    /// answers `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable` and effect `none`,
    /// and nothing is written: no operation, no decision record, no event, no generation
    /// change.
    #[tokio::test]
    async fn w0_revision_6_requests_fail_closed_before_any_record() {
        let env = EnvironmentId::from_random_bytes([6; 16]);
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        store
            .transaction(|tx| tx.init_self_environment(&env))
            .unwrap();
        let clock = VirtualClock::at(t0());
        let ops = Operations::start(OperationsConfig {
            store: store.clone(),
            clock: clock.clone(),
            time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
            time_policy: TimePolicy::default(),
            environment: env.clone(),
            adapters: Vec::new(),
            stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
            limits: Limits::default(),
            default_window: std::time::Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap();
        let relay = EventRelay::spawn(&ops, CancellationToken::new());
        let d = OperationsDispatcher::new(ops, relay, clock);
        let records = || {
            store
                .transaction(|tx| {
                    Ok((
                        tx.snapshot_boundary(&env)?,
                        tx.pending_decisions()?.len(),
                        tx.open_operations()?.len(),
                        tx.unresolved_operations()?.len(),
                    ))
                })
                .unwrap()
        };
        let before = records();
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(heimdall_testkit::repo::repo_path(
                "tests/contracts/golden/rev6-requests.golden.json",
            ))
            .unwrap(),
        )
        .unwrap();
        let limited = Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        ));
        let rows = golden["requests"].as_array().unwrap();
        // 24 forms at revision 6; revision 6.1 (ADR-0006 §18.4) adds the activation probe;
        // revision 6.3 (§18.7) adds rotate_endpoint, runner_policy_recheck, transport.rotate
        // and the six runner_local forms.
        assert_eq!(rows.len(), 34);
        for row in rows {
            let request: Request = serde_json::from_value(row["json"].clone()).unwrap();
            assert!(request.is_revision_6());
            for caller in [owner(), limited.clone()] {
                let env = d.handle_as(&caller, request.clone()).await;
                assert_eq!(
                    env.code,
                    Code::CapabilityUnavailable,
                    "{}: {env:?}",
                    row["what"]
                );
                assert_eq!(
                    env.data["error"]["reason"],
                    heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE,
                    "{}",
                    row["what"]
                );
                assert_eq!(
                    env.data["error"]["effect_status"], "none",
                    "{}",
                    row["what"]
                );
            }
        }
        assert_eq!(records(), before, "a revision-6 request wrote a record");
    }

    /// ⟨M06 W3 grant-path; ADR-0012 §4 item 2⟩ The forwarding arm: the local owner's
    /// `ensure` that names an environment is offered to the forwarder, whose answer stands
    /// when it has one (a recorded runner) and whose `None` leaves the local path as it was.
    /// A paired caller's, a limited caller's and an `ensure` naming no environment never
    /// reach the forwarder.
    #[tokio::test]
    async fn an_ensure_naming_a_recorded_runner_is_forwarded_for_the_local_owner_only() {
        use heimdall_app::remote_status_driver::{EnsureForwarding, forwarded_pending};
        use heimdall_contract::request::EnsureRequest;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Records the runner `known`; counts what it was offered.
        struct Forwarder {
            known: EnvironmentId,
            offered: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl EnsureForwarding for Forwarder {
            async fn forward(
                &self,
                request: &EnsureRequest,
            ) -> Option<heimdall_app::OpResult<serde_json::Value>> {
                self.offered.fetch_add(1, Ordering::SeqCst);
                (request.environment.as_ref() == Some(&self.known)).then(|| {
                    Err(forwarded_pending(
                        &heimdall_contract::ids::GrantId::from_random_bytes([4; 16]),
                    ))
                })
            }
        }
        let runner = EnvironmentId::from_random_bytes([7; 16]);
        let forwarder = Arc::new(Forwarder {
            known: runner.clone(),
            offered: AtomicUsize::new(0),
        });
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        let d = dispatcher()
            .await
            .with_controller_records(store)
            .with_ensure_forwarding(forwarder.clone());
        let ensure = |environment: Option<&EnvironmentId>, id: &str| -> Request {
            Request::Ensure(EnsureRequest {
                profile: Some(heimdall_contract::ids::ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: [heimdall_contract::request::AccessPairRef {
                    destination: heimdall_contract::ids::DestinationId::parse("h1").unwrap(),
                    account: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
                }]
                .into_iter()
                .collect(),
                environment: environment.cloned(),
                work_id: heimdall_contract::ids::WorkId::parse("w1").unwrap(),
                until: Some(heimdall_contract::request::DeadlineIntent::Duration(
                    "1h".into(),
                )),
                required_capabilities: heimdall_contract::request::RequiredCapabilities::default(),
                request_id: heimdall_contract::ids::RequestId::parse(id).unwrap(),
                interaction: heimdall_contract::request::InteractionMode::NonInteractive,
                wait: heimdall_contract::request::WaitMode::default(),
                connection: None,
                context: None,
                covered_only: false,
            })
        };
        // The recorded runner: the forwarder's answer, naming the grant.
        let env = d.handle_as(&owner(), ensure(Some(&runner), "r1")).await;
        assert_eq!(env.code, Code::Accepted, "{env:?}");
        assert_eq!(env.data["error"]["resource"]["kind"], "grant");
        assert_eq!(forwarder.offered.load(Ordering::SeqCst), 1);
        // Another environment: offered, not taken; the local answer stands (not managed here).
        let other = EnvironmentId::from_random_bytes([8; 16]);
        let env = d.handle_as(&owner(), ensure(Some(&other), "r2")).await;
        assert_eq!(env.code, Code::NotFound, "{env:?}");
        assert_eq!(forwarder.offered.load(Ordering::SeqCst), 2);
        // No environment named, a paired owner, a limited caller: never offered.
        let _ = d.handle_as(&owner(), ensure(None, "r3")).await;
        let paired = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: Some(heimdall_contract::ids::ClientId::from_random_bytes([9; 16])),
        });
        let env = d.handle_as(&paired, ensure(Some(&runner), "r4")).await;
        assert_ne!(env.code, Code::Accepted, "{env:?}");
        let limited = Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        ));
        let env = d.handle_as(&limited, ensure(Some(&runner), "r5")).await;
        assert_ne!(env.code, Code::Accepted, "{env:?}");
        assert_eq!(forwarder.offered.load(Ordering::SeqCst), 2);
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ `controller_record.*` through the dispatcher: the local
    /// owner's put and remove write `remote_environment_pins`; a paired caller (owner role
    /// included) and a local limited caller are refused before anything is written; a
    /// dispatcher with no store answers `driver_unavailable`.
    #[tokio::test]
    async fn controller_records_are_written_for_the_local_owner_only() {
        use heimdall_contract::controller_record::{
            ControllerRecordRequest, ManagementHop, ManagementRoute, RemoteEnvironmentPin,
        };
        let unwired = dispatcher().await;
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        let d = unwired.clone().with_controller_records(store.clone());
        let runner = EnvironmentId::from_random_bytes([7; 16]);
        let pin = RemoteEnvironmentPin {
            environment: runner.clone(),
            destination: heimdall_contract::ids::DestinationId::parse("lab").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "10.0.0.7".into(),
                    port: None,
                    account: heimdall_contract::ids::AccountName::parse("runner").unwrap(),
                    host_keys: vec![
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn"
                            .into(),
                    ],
                },
                jump: None,
            },
            client: heimdall_contract::ids::ClientId::from_random_bytes([8; 16]),
            role: heimdall_contract::remote::Role::Owner,
            key_fingerprint: heimdall_contract::ids::KeyFingerprint::parse(&format!(
                "SHA256:{}",
                "K".repeat(43)
            ))
            .unwrap(),
            label: None,
            pinned_at: t0(),
        };
        let put = Request::ControllerRecord(ControllerRecordRequest::PutEnvironment {
            record: pin.clone(),
        });
        let remove = Request::ControllerRecord(ControllerRecordRequest::RemoveEnvironment {
            environment: runner.clone(),
        });
        let rows = || {
            store
                .transaction(|tx| tx.remote_environment_pins())
                .unwrap()
        };
        let paired = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: Some(heimdall_contract::ids::ClientId::from_random_bytes([9; 16])),
        });
        let limited = Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        ));
        // ⟨ruling Q5; ADR-0006 §18.7 item 9⟩ A paired caller (owner role included).
        let env = d.handle_as(&paired, put.clone()).await;
        assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
        assert_eq!(
            env.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED
        );
        assert_eq!(env.data["error"]["effect_status"], "none");
        let env = d.handle_as(&limited, put.clone()).await;
        assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
        assert_eq!(env.data["error"]["effect_status"], "none");
        assert!(rows().is_empty(), "a refused caller wrote nothing");
        let env = unwired.handle_as(&owner(), put.clone()).await;
        assert_eq!(
            env.data["error"]["reason"],
            heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE
        );
        let env = d.handle_as(&owner(), put).await;
        assert_eq!(env.code, Code::Ok, "{env:?}");
        let stored = rows();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            serde_json::from_str::<RemoteEnvironmentPin>(&stored[0].1).unwrap(),
            pin
        );
        let env = d.handle_as(&owner(), remove.clone()).await;
        assert_eq!(env.data["removed"], true, "{env:?}");
        assert!(rows().is_empty());
        let env = d.handle_as(&owner(), remove).await;
        assert_eq!(env.data["removed"], false);
    }

    /// ⟨M06 W3⟩ The route and transport forms through a dispatcher that serves them: the
    /// owner's route add and remove change the stored list, a limited caller is refused,
    /// the helper's lookup without a served binding is `route_binding_ambiguous`, a widening
    /// `transport enable --serve` writes nothing, `disable` narrows, and `routes/1` and
    /// `transport-iroh/1` are offered only by such a dispatcher.
    #[tokio::test]
    async fn route_and_transport_forms_are_served_when_wired() {
        use heimdall_contract::ids::{AccountName, DestinationId, IdentityId};
        use heimdall_contract::route::{RouteRequest, RouteSpec, TransportRequest};
        let unwired = dispatcher().await;
        assert!(
            !unwired
                .offered_capabilities()
                .contains(capability::ROUTES_V1)
        );
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        let lab = DestinationId::parse("lab").unwrap();
        store
            .transaction(|tx| {
                tx.upsert_destination(&heimdall_domain::catalog::DestinationRecord {
                    id: lab.clone(),
                    alias: "lab".into(),
                    revision: 1,
                    definition: heimdall_domain::catalog::DestinationDefinition::Managed {
                        hostname: "lab.lan".into(),
                        port: None,
                        account: AccountName::parse("deploy").unwrap(),
                        identity: IdentityId::from_random_bytes([1; 16]),
                        jump: None,
                    },
                    label: None,
                    updated_at: t0(),
                })
            })
            .unwrap();
        let supervisor = Arc::new(crate::supervise_transport::TransportSupervisor::new(
            store.clone(),
            Arc::new(crate::supervise_transport::NoPeerEndpoints),
            crate::supervise_transport::SupervisorConfig::new(
                crate::supervise_transport::ServeSpawn {
                    program: std::path::PathBuf::from("/nonexistent/heimdall"),
                    args: Vec::new(),
                    env: Vec::new(),
                },
            ),
        ));
        let keys: Arc<dyn heimdall_app::transport::TransportKeys> =
            Arc::new(crate::supervise_transport::CredentialKeys(Arc::new(
                heimdall_credential::iroh::FixtureIrohStore::new(),
            )));
        let d = unwired.with_route_transport(Arc::new(
            crate::supervise_transport::RouteTransport::new(
                store.clone(),
                supervisor,
                keys,
                Arc::new(heimdall_app::transport::NoPeerEnrollments),
            ),
        ));
        let offer = d.offered_capabilities();
        assert!(
            offer.contains(capability::ROUTES_V1) && offer.contains(capability::TRANSPORT_IROH_V1)
        );
        let add = Request::Route(RouteRequest::Add {
            destination: lab.clone(),
            route: RouteSpec::Direct {
                host: "10.0.0.9".into(),
                port: Some(2222),
            },
            exposure: None,
            request_id: heimdall_contract::ids::RequestId::parse("req_route").unwrap(),
        });
        let limited = Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        ));
        let refused = d.handle_as(&limited, add.clone()).await;
        assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
        let routes = || store.transaction(|tx| tx.destination_routes(&lab)).unwrap();
        assert!(routes().is_empty());
        let added = d.handle_as(&owner(), add).await;
        assert_eq!(added.code, Code::Ok, "{added:?}");
        assert_eq!(
            routes().len(),
            2,
            "the one-element case made explicit, plus the new route"
        );
        let new_route =
            heimdall_contract::ids::RouteId::parse(added.data["route"].as_str().unwrap()).unwrap();
        let removed = d
            .handle_as(
                &owner(),
                Request::Route(RouteRequest::Remove {
                    destination: lab.clone(),
                    route: new_route,
                }),
            )
            .await;
        assert_eq!(removed.code, Code::Ok, "{removed:?}");
        assert!(routes().is_empty(), "back to the one-element case");
        let lookup = d
            .handle_as(
                &owner(),
                Request::Route(RouteRequest::ResolveBinding {
                    destination: lab.clone(),
                    account: AccountName::parse("deploy").unwrap(),
                    endpoint: "/run/agent.sock".into(),
                }),
            )
            .await;
        assert_eq!(
            lookup.data["error"]["reason"],
            heimdall_contract::envelope::reason::ROUTE_BINDING_AMBIGUOUS,
            "{lookup:?}"
        );
        let serve = d
            .handle_as(
                &owner(),
                Request::Transport(TransportRequest::Enable {
                    serve: true,
                    exposure: None,
                    request_id: heimdall_contract::ids::RequestId::parse("req_serve").unwrap(),
                }),
            )
            .await;
        assert_eq!(serve.code, Code::CapabilityUnavailable, "{serve:?}");
        assert_eq!(serve.data["error"]["effect_status"], "none");
        #[cfg(feature = "iroh")]
        assert_eq!(
            serve.data["error"]["reason"],
            heimdall_contract::envelope::reason::EXPOSURE_UNCONSENTED
        );
        assert!(
            store
                .transaction(|tx| tx.transport_keys())
                .unwrap()
                .is_empty(),
            "a widening generated and recorded nothing"
        );
        // ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate` is the local owner's alone: a
        // paired caller (owner role included) is refused `INTERACTION_REQUIRED` with
        // `local_owner_required`, before any effect; a limited local caller has no access;
        // the local owner reaches the rotation (here nothing is enabled).
        let rotate = || Request::Transport(TransportRequest::Rotate);
        let paired = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: Some(heimdall_contract::ids::ClientId::from_random_bytes([9; 16])),
        });
        let env = d.handle_as(&paired, rotate()).await;
        assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
        assert_eq!(
            env.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED
        );
        assert_eq!(env.data["error"]["effect_status"], "none");
        let limited = Caller::unattended(CallerContext::local(
            PrincipalRef::UnixUser { uid: 501 },
            ClientRole::LimitedConsumer,
        ));
        let env = d.handle_as(&limited, rotate()).await;
        assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
        let env = d.handle_as(&owner(), rotate()).await;
        assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
        assert_eq!(
            env.data["error"]["reason"],
            heimdall_contract::envelope::reason::TRANSPORT_UNAVAILABLE,
            "the local owner reaches the rotation: nothing is enabled"
        );
        assert!(
            store
                .transaction(|tx| tx.transport_keys())
                .unwrap()
                .is_empty()
        );
        let disable = d
            .handle_as(&owner(), Request::Transport(TransportRequest::Disable))
            .await;
        assert_eq!(disable.code, Code::Ok, "{disable:?}");
    }

    /// Only the owner may take or lift the fence.
    #[tokio::test]
    async fn uninstall_fence_needs_the_owner() {
        let d = dispatcher().await;
        let consumer = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::LimitedConsumer,
            remote_client: None,
        });
        let refused = d
            .handle_as(&consumer, fence(UninstallFenceRequest::Acquire))
            .await;
        assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
        assert!(!d.operations.uninstall_fence_held());
    }
}
