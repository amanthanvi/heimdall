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
//!   refuses it otherwise). It is accepted only from the **local owner** role,
//!   whether attended or unattended, and only
//!   when the service gave this dispatcher its stop token
//!   ([`OperationsDispatcher::with_service_control`]); a limited consumer gets
//!   `CAPABILITY_UNAVAILABLE`. The answer is `OK {"stopping": true,
//!   "already_stopping": <bool>}`; the drain itself starts from
//!   [`Dispatcher::replied`], after that answer is written, by cancelling the
//!   service token, which runs the same graceful drain as a signal. Repeated
//!   requests are idempotent. This dispatcher serves the control endpoint only:
//!   the signing endpoint speaks the agent protocol and has no such request.
//! * ⟨M03; ADR-0008 §17.27 item 2⟩ **The uninstall fence**
//!   (`Request::UninstallFence`, `service-control/1`, local owner only):
//!   held by **this connection**. Each clone of the dispatcher is one connection's
//!   scope (the control listener clones it once per accepted connection and drops
//!   that clone when the connection ends, whatever the reason), so the fence is
//!   released by `release` on the holding connection, when that connection ends
//!   (the scope's `Drop`), or with the runtime.
//! * ⟨M08 U2b-2; ADR-0014 §3.6 steps 2 to 4; H9, H13⟩ **The epoch and the replay fence.**
//!   With a [`crate::request_fence::RequestFence`] ([`OperationsDispatcher::with_request_fence`],
//!   which every serving runtime has), the dispatcher offers `request-epoch/1`, reports the
//!   epoch in the hello, and checks every mutating request before it runs, attended or not
//!   and whatever its session: a frame epoch that is not current is `REQUEST_STALE`
//!   (`restore_epoch_stale`), a fenced key is answered from its fence, and the request ledger
//!   is appended before the request reaches the application. The caller the check keys by is
//!   the one the request is served as (a paired session's client included). Every answer to a
//!   mutating request reports its `request_id` and `request_epoch`.
//!
//!   ⟨follow-up A; M08 W4 SEC-3a⟩ **The order, for every mutating frame:** (1) the single
//!   pre-fence check (`pre_fence_refusal`): the paired-session allow-list (refusing any
//!   runner-local configuration form `INTERACTION_REQUIRED` / `local_owner_required`), a
//!   paired client's row and role check (`PairedRunner::frame`), local attended-only forms
//!   (including widening `runner_local` forms on a runner), and local owner-only forms;
//!   (2) the uninstall-fence admission (the holder's lease, or `uninstall_fence_admit`), held
//!   across what follows; (3) the request fence (`Gate::pass`); (4) the request. A frame
//!   refused at (1) or (2) appends nothing to the ledger and writes nothing; its answer still
//!   reports the request ID and the epoch it is bound to.
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

/// ⟨M08 W4 SEC-3a, S2-01 & U2b-3a item 2; ADR-0012 §3.10 amendment 2026-11-26⟩ The single
/// pre-fence admission check, evaluated before `PairedRunner::frame`, uninstall-fence admission,
/// and `Gate::pass`, so every refused request writes nothing to `REQUEST-LEDGER` or SQLite:
///
/// 1. **Paired sessions** (`caller.context.remote_client.is_some()`): only requests in
///    [`heimdall_domain::principal::paired_session_allows`] pass. Everything else — runner-local
///    configuration, service control, attended-only actions, controller records — is refused
///    `INTERACTION_REQUIRED` with reason `local_owner_required` and effect `none`.
/// 2. **Local callers** (`remote_client.is_none()`):
///    - attended-only forms (`Request::requires_attended_session`) without attendance are
///      refused `INTERACTION_REQUIRED`, effect `none`;
///    - on a runner (`is_runner`), `Request::RunnerLocal` requires global owner access
///      (`role_insufficient` otherwise) and, for widening forms (`trust_issuer`,
///      `designate_time_source`, `enroll_owner`, `policy_recheck`), an attended session
///      (`INTERACTION_REQUIRED`, effect `none` — the sole runtime check, with no second copy
///      after the fence);
///    - owner-only forms (`owner_only_m03`, `Environment`, `ControllerRecord`, `UninstallFence`)
///      require the owner role (`CAPABILITY_UNAVAILABLE`, effect `none`).
fn pre_fence_refusal(
    caller: &Caller,
    request: &Request,
    is_runner: bool,
) -> Option<Envelope<serde_json::Value>> {
    if caller.context.remote_client.is_some() {
        if !heimdall_domain::principal::paired_session_allows(request) {
            return Some(error_value(
                heimdall_remote::roles::Refusal::LocalOwnerRequired.to_op_error(),
            ));
        }
        return None;
    }
    if request.requires_attended_session() && !caller.is_attended() {
        return Some(error_value(
            OpError::new(
                Code::InteractionRequired,
                "this request requires an attended interactive session",
            )
            .with_effect(EffectStatus::None),
        ));
    }
    if is_runner && let Request::RunnerLocal(r) = request {
        if !caller.context.has_global_access() {
            return Some(error_value(
                heimdall_remote::roles::Refusal::RoleInsufficient.to_op_error(),
            ));
        }
        return crate::runner::check_runner_local_attendance(r, caller.is_attended())
            .err()
            .map(error_value);
    }
    let needs_the_owner_role = || {
        error_value(
            OpError::new(
                Code::CapabilityUnavailable,
                "this request needs the owner role",
            )
            .with_effect(EffectStatus::None),
        )
    };
    match request {
        // ⟨M03⟩ m03-plan U0b row 13, phase 2 (wave 4): the owner-only M03 requests (F20).
        _ if owner_only_m03(request) && !caller.context.is_owner() => Some(needs_the_owner_role()),
        // ⟨M04⟩ ADR-0006 revision 5: adding or removing a WSL or container environment.
        Request::Environment(_) if !caller.context.is_owner() => Some(needs_the_owner_role()),
        // ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The controller's own records (local owner only).
        Request::ControllerRecord(_) if !caller.context.has_global_access() => {
            Some(needs_the_owner_role())
        }
        // ⟨ADR-0008 §17.27 item 2⟩ Taking, lifting or retrying under the uninstall fence.
        Request::UninstallFence(_) if !caller.context.is_owner() => Some(error_value(
            OpError::new(
                Code::CapabilityUnavailable,
                "service control needs the owner principal on the control endpoint",
            )
            .with_effect(EffectStatus::None),
        )),
        _ => None,
    }
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
        request_id,
        request_epoch,
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
            request_id,
            request_epoch,
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

/// ⟨M06 W5 `w5n`⟩ Add each destination's latest route-health report to an `inspect
/// destinations` answer: `route_health` (the `RouteHealthPayload`, with `reported_at`) and,
/// when the route helper refused for it, `host_pin_defeated` (the setting). Additive: an
/// item without a report is unchanged.
fn add_route_health(
    data: &mut serde_json::Value,
    routes: &crate::supervise_transport::RouteTransport,
) {
    let Some(items) = data
        .get_mut("items")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for item in items {
        let Some(report) = item
            .get("destination_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| heimdall_contract::ids::DestinationId::parse(id).ok())
            .and_then(|id| routes.route_health(&id))
        else {
            continue;
        };
        if let serde_json::Value::Object(map) = item {
            if !report.result.attempts.is_empty() {
                map.insert(
                    "route_health".to_owned(),
                    serde_json::json!({
                        "result": report.result,
                        "reported_at": report.reported_at,
                    }),
                );
            }
            if let Some(setting) = &report.host_pin_defeated {
                map.insert(
                    "host_pin_defeated".to_owned(),
                    serde_json::json!({
                        "setting": setting,
                        "reported_at": report.reported_at,
                    }),
                );
            }
        }
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
    /// ⟨M08 U2b-2⟩ The epoch check, the replay fence and the request ledger
    /// ([`Self::with_request_fence`]); `None` (a dispatcher a test builds without a service):
    /// no check, and `request-epoch/1` is not offered, so no frame carries an epoch.
    fence: Option<Arc<crate::request_fence::RequestFence>>,
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

/// ⟨M08 U2b-2 follow-up A⟩ One request's pass through the request fence
/// ([`crate::request_fence::RequestFence::admit`]), taken where the request is about to run:
/// after the role checks and the uninstall-fence admission (module docs). It is taken once;
/// a later pass (a local decision path that declined the decision) is a no-op.
struct Gate<'a> {
    /// `None`: no request fence ([`OperationsDispatcher::handle`]), every pass is open.
    check: Option<GateCheck<'a>>,
    admitted: std::sync::atomic::AtomicBool,
}

/// The fence's check of one frame, as [`OperationsDispatcher::handle_framed`] received it.
struct GateCheck<'a> {
    fence: &'a Arc<crate::request_fence::RequestFence>,
    /// The caller the request is served as (a paired session's client, or the local owner).
    caller: CallerContext,
    frame_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
    clock: &'a dyn Clock,
}

impl<'a> Gate<'a> {
    /// No request fence.
    fn open() -> Self {
        Self {
            check: None,
            admitted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn checked(check: GateCheck<'a>) -> Self {
        Self {
            check: Some(check),
            ..Self::open()
        }
    }

    /// The request fence's check of `request`, which runs next. `Err`: the fence's answer
    /// (stamped), and the request is not run.
    async fn pass(&self, request: &Request) -> Result<(), Envelope<serde_json::Value>> {
        use std::sync::atomic::Ordering;
        let Some(c) = &self.check else {
            return Ok(());
        };
        if self.admitted.load(Ordering::Acquire) {
            return Ok(());
        }
        c.fence
            .admit(&c.caller, request, c.frame_epoch, c.clock.wall())
            .await
            .map_err(|refused| *refused)?;
        self.admitted.store(true, Ordering::Release);
        Ok(())
    }

    /// ⟨M08 W4 U2b-3a⟩ Whether the request fence admitted the request (it then ran).
    fn admitted(&self) -> bool {
        self.admitted.load(std::sync::atomic::Ordering::Acquire)
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
            fence: None,
        }
    }

    /// ⟨M08 U2b-2; ADR-0014 §3.6⟩ Check every mutating request through `fence` (module docs),
    /// offer `request-epoch/1` and report the fence's epoch in the hello.
    #[must_use]
    pub fn with_request_fence(mut self, fence: Arc<crate::request_fence::RequestFence>) -> Self {
        self.fence = Some(fence);
        self
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

    /// `Request::ControllerRecord` ([`Self::with_controller_records`]) for a caller that
    /// [`controller_record_refusal`] admitted: `heimdall_app::remote_env::apply_controller_record`,
    /// with the host-key fingerprint from `heimdall-credential`.
    fn controller_record(
        &self,
        caller: &Caller,
        request: &heimdall_contract::controller_record::ControllerRecordRequest,
    ) -> Envelope<serde_json::Value> {
        let Some(store) = &self.controller_records else {
            return error_value(OpError::driver_unavailable(
                "the controller's records are not available in this runtime",
            ));
        };
        // ⟨rev6.4; ADR-0006 §18.8 item 4⟩ The owner's acknowledgement of a lift: attended
        // only. The hosted driver's next pass then issues what the barrier now permits.
        if let heimdall_contract::controller_record::ControllerRecordRequest::ResumeIssuance {
            environment,
            effects,
        } = request
        {
            // Only the effects the owner was shown and named: one delivered since keeps
            // blocking. An empty list or an ID that is no delivered pause or cutoff of
            // this runner refuses the whole request, effect `none`.
            let done = heimdall_app::remote_status_driver::resume_issuance_named(
                store,
                environment,
                effects,
                caller.is_attended(),
                self.clock.wall(),
            );
            if done.is_ok()
                && let Some(d) = &self.outbox_delivery
            {
                d.notify();
            }
            return render(done.map(|data| heimdall_app::error::Completed::ok(Code::Ok, data)));
        }
        render(
            heimdall_app::remote_env::apply_controller_record(
                store,
                request,
                &heimdall_credential::mgmt::openssh_fingerprint,
                self.clock.wall(),
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

    /// ⟨M08 U2b-2; ADR-0014 §3.6 steps 2 to 4⟩ Handle one request whose frame carried
    /// `frame_epoch`, as [`Self::handle`] does, with the request fence's check last before the
    /// request runs (module docs: ⟨follow-up A⟩ after the role checks and the uninstall-fence
    /// admission). Every answer to a mutating request reports its request ID and the epoch it
    /// is bound to, whichever check answered it. Without a fence this is [`Self::handle`].
    pub async fn handle_framed(
        &self,
        session: &SessionInfo,
        request: Request,
        frame_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
    ) -> Envelope<serde_json::Value> {
        let Some(fence) = &self.fence else {
            return self.handle(session, request).await;
        };
        // The caller the request is served as: a paired session's client, as the runner's
        // role table resolved it at the hello, or the local owner.
        let caller = match (&self.paired, &self.runner) {
            (Some(paired), Some(runner)) => runner.caller(&session.principal, paired).context,
            (None, _) => caller_for(session, self.clock.wall()).context,
            // Unreachable by construction (a binding needs the runner); the paired path below
            // refuses it before anything is read or written.
            (Some(_), None) => return self.handle(session, request).await,
        };
        let binding = fence.binding(&request, frame_epoch);
        // ⟨M08 W4 U2b-3a⟩ A request-ID request the journal does not hold gets its terminal
        // record when it completes, so a restore replays it instead of fencing it.
        let terminal = fence.terminal_key(&caller, &request);
        let gate = Gate::checked(GateCheck {
            fence,
            caller,
            frame_epoch,
            clock: self.clock.as_ref(),
        });
        let mut env = self.handle_gated(session, request, &gate).await;
        if let Some(stamp) = binding {
            stamp.apply(&mut env);
        }
        if let Some(digest) = terminal
            && gate.admitted()
            && matches!(env.code, Code::Ok | Code::AccessReady)
        {
            fence
                .record_terminal(
                    digest,
                    self.clock.wall(),
                    self.operations.operation_retention(),
                )
                .await;
        }
        env
    }

    /// Handle one request for an already-authenticated session.
    ///
    /// ⟨M06 W5 `w5s`, M06-W5-R05⟩ Every answer leaves with its relay URLs in their shown form
    /// ([`heimdall_contract::route::display_relay_urls`]): no path, query or userinfo of a
    /// relay URL reaches any client, local or paired, in an answer, an error, a decision
    /// view or `inspect`. What is stored is unchanged.
    pub async fn handle(
        &self,
        session: &SessionInfo,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        self.handle_gated(session, request, &Gate::open()).await
    }

    /// [`Self::handle`], the request passing `gate` where it is about to run.
    async fn handle_gated(
        &self,
        session: &SessionInfo,
        request: Request,
        gate: &Gate<'_>,
    ) -> Envelope<serde_json::Value> {
        let mut env = self.handle_unshown(session, request, gate).await;
        heimdall_contract::route::display_relay_urls(&mut env.data);
        env
    }

    async fn handle_unshown(
        &self,
        session: &SessionInfo,
        request: Request,
        gate: &Gate<'_>,
    ) -> Envelope<serde_json::Value> {
        // ⟨M06 W2; M08 W4 SEC-3a⟩ A paired session: the single pre-fence allow-list runs first,
        // then every allowed frame is checked against the client's row (`crate::paired`); only a
        // request that passes reaches the request fence and the application, as the client's
        // caller.
        if let Some(paired) = &self.paired {
            let Some(runner) = &self.runner else {
                return error_value(
                    OpError::new(
                        Code::SchemaUnsupported,
                        "this runtime does not accept a paired client",
                    )
                    .with_effect(EffectStatus::None),
                );
            };
            let caller = runner.caller(&session.principal, paired);
            if let Some(refused) = pre_fence_refusal(&caller, &request, true) {
                return refused;
            }
            return match runner.frame(&session.principal, paired, request) {
                crate::paired::Frame::Answer(env) => env,
                // ⟨M08 U2b-2 follow-up A⟩ Passed the row check and answered by the runner
                // itself: the request fence, then the runner's answer.
                crate::paired::Frame::Runner(frame) => match gate.pass(frame.request()).await {
                    Ok(()) => runner.answer(frame).await,
                    Err(refused) => refused,
                },
                crate::paired::Frame::Route(caller, request) => {
                    // ⟨M06 W2⟩ Reads that list events or decisions (event pages, snapshots,
                    // `inspect decisions`) reach a paired caller without decision handles.
                    let reads = matches!(request, Request::Observe(_) | Request::Inspect(_));
                    let mut env = self.handle_as_gated(&caller, request, gate).await;
                    if reads {
                        crate::paired::redact_value(&mut env.data);
                    }
                    env
                }
            };
        }
        let caller = caller_for(session, self.clock.wall());
        if let Some(refused) = pre_fence_refusal(&caller, &request, self.runner.is_some()) {
            return refused;
        }
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
            // ⟨M08 U2b-2 follow-up A⟩ Then the request fence, held under that admission.
            if let Err(refused) = gate.pass(&request).await {
                return refused;
            }
            let decided = runner.decide_local(caller.is_attended(), d).await;
            drop(admission);
            if let Some(env) = decided {
                return env;
            }
        }
        self.handle_as_gated(&caller, request, gate).await
    }

    /// [`Self::handle`] for an explicit caller (the role-based refusals are
    /// testable with a `LimitedConsumer` caller, which the control endpoint never
    /// builds itself before G07). ⟨M08 W4 U2b-3a-F⟩ When this dispatcher has a
    /// request fence ([`Self::with_request_fence`]), the request passes it as
    /// `caller` (epoch bound at receipt, as [`Self::handle_framed`] does with no
    /// frame epoch), after `pre_fence_refusal` and the uninstall-fence admission.
    #[doc(hidden)]
    pub async fn handle_as(
        &self,
        caller: &Caller,
        request: Request,
    ) -> Envelope<serde_json::Value> {
        let Some(fence) = &self.fence else {
            if let Some(refused) = pre_fence_refusal(caller, &request, self.runner.is_some()) {
                return refused;
            }
            return self.handle_as_gated(caller, request, &Gate::open()).await;
        };
        let binding = fence.binding(&request, None);
        let terminal = fence.terminal_key(&caller.context, &request);
        let gate = Gate::checked(GateCheck {
            fence,
            caller: caller.context.clone(),
            frame_epoch: None,
            clock: self.clock.as_ref(),
        });
        let mut env =
            if let Some(refused) = pre_fence_refusal(caller, &request, self.runner.is_some()) {
                refused
            } else {
                self.handle_as_gated(caller, request, &gate).await
            };
        if let Some(stamp) = binding {
            stamp.apply(&mut env);
        }
        if let Some(digest) = terminal
            && gate.admitted()
            && matches!(env.code, Code::Ok | Code::AccessReady)
        {
            fence
                .record_terminal(
                    digest,
                    self.clock.wall(),
                    self.operations.operation_retention(),
                )
                .await;
        }
        env
    }

    /// [`Self::handle_as`], the request passing `gate` where it is about to run.
    async fn handle_as_gated(
        &self,
        caller: &Caller,
        request: Request,
        gate: &Gate<'_>,
    ) -> Envelope<serde_json::Value> {
        let mut env = self.handle_as_unshown(caller, request, gate).await;
        heimdall_contract::route::display_relay_urls(&mut env.data);
        env
    }

    /// After `pre_fence_refusal`, hold the uninstall-fence admission across the request fence
    /// ([`Gate::pass`]) and the request.
    async fn handle_as_unshown(
        &self,
        caller: &Caller,
        request: Request,
        gate: &Gate<'_>,
    ) -> Envelope<serde_json::Value> {
        let caller = caller.clone();
        // ⟨M06 W5; ADR-0006 §18.9 item 8; ADR-0012 §3.10 item 4⟩ On every installation that
        // serves the route and transport forms, `Decide` on a **local** widening record is
        // decided here, before the application (attended, local owner, checked time); a paired client's record is
        // the runner's ([`Self::handle`]), and any other decision the application's.
        if let (Some(local), Request::Decide(d)) = (&self.route_transport, &request) {
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
            // ⟨M08 U2b-2 follow-up A⟩ Then the request fence, held under that admission.
            if let Err(refused) = gate.pass(&request).await {
                return refused;
            }
            let checked = self
                .operations
                .timegate()
                .check()
                .await
                .ok()
                .map(|safe| safe.anchor.wall);
            let decided = local
                .decide_local(&caller, d, checked, self.clock.wall())
                .await;
            drop(admission);
            if let Some(env) = decided {
                return env;
            }
        }
        if let Request::Shutdown(_) = request {
            return self.shutdown(&caller);
        }
        if let Request::UninstallFence(r) = &request {
            // ⟨M08 U2b-2 follow-up A⟩ The fence itself admits nothing: the request fence, then
            // the action.
            if let Err(refused) = gate.pass(&request).await {
                return refused;
            }
            return self.uninstall_fence(*r).await;
        }
        // ⟨ADR-0008 §17.27 item 2, §17.28 item 1, §17.31 item 2⟩ The uninstall fence
        // ([`fenced`]): the holder's requests run in its scope and are never refused; a
        // fenced request from any other connection holds the admission from its check
        // until it has been handled, and is refused while another connection holds the
        // fence or is acquiring it. The application routes check again themselves.
        // ⟨§17.33 item 1⟩ The holder's request runs under its lease (this connection, the
        // fence's current generation), which it carries into the work it spawns and
        // re-checks at each step; a releasing or released fence grants none.
        // ⟨M08 U2b-2 follow-up A⟩ The lease or the admission is held across the request
        // fence ([`Self::route`]'s first step) and the request.
        if let Some(lease) = self.operations.uninstall_fence_lease(self.scope.id) {
            return heimdall_app::operations::with_fence_lease(
                lease,
                self.route(caller, request, gate),
            )
            .await;
        }
        if fenced(&request) {
            // ⟨§17.31 item 2⟩ The application's one admission (refused while the fence
            // is held or being acquired), held until the request has been handled.
            let _admission = match self.operations.uninstall_fence_admit() {
                Ok(a) => a,
                Err(e) => return error_value(e.with_effect(EffectStatus::None)),
            };
            return self.route(caller, request, gate).await;
        }
        self.route(caller, request, gate).await
    }

    /// Route one request that passed the session checks, the role checks and the uninstall
    /// fence. ⟨M08 U2b-2 follow-up A⟩ Its first step is the request fence (`gate`); only a
    /// request the fence admits runs.
    async fn route(
        &self,
        caller: Caller,
        request: Request,
        gate: &Gate<'_>,
    ) -> Envelope<serde_json::Value> {
        if let Err(refused) = gate.pass(&request).await {
            return refused;
        }
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
                Request::RunnerLocal(r) => return runner.runner_local(r.clone()).await,
                _ => {}
            }
        }
        match request {
            Request::Inspect(r) => {
                let destinations =
                    r.subject == heimdall_contract::request::InspectSubject::Destinations;
                let mut answer = render(ops.inspect(&caller, r).await);
                // ⟨M06 W5 `w5n`; ADR-0012 §5.5 item 4, §5.2⟩ Each destination's latest
                // route-health report (and the pin setting found defeated), additive.
                if destinations && let Some(t) = &self.route_transport {
                    add_route_health(&mut answer.data, t);
                }
                answer
            }
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
                let mut answer = render(ops.ensure(&caller, r).await);
                // ⟨M06 W4 grant-e2e⟩ On a runner, an admitted grant that waits for its
                // issuer answers `ACCEPTED` with the pending state in its data.
                if self.runner.is_some()
                    && answer.code == Code::Accepted
                    && let Some(operation) = &answer.operation_id
                    && let Some(grant) = ops.awaiting_issuer_grant(operation).await
                {
                    heimdall_app::remote_status_driver::mark_pending(&mut answer.data, &grant);
                }
                answer
            }
            Request::Bind(r) => render(self.bind_result(ops.bind(&caller, r).await)),
            Request::Delegate(r) => render(ops.delegate(&caller, r).await),
            Request::Observe(r) => {
                // ⟨M06 W4 grant-e2e⟩ `operation wait` on a forwarded `ensure` that answered
                // pending names the runner's operation, which this installation does not
                // hold: the forwarder drives it. Local owner only, never on a runner.
                let forwarded = match &r {
                    heimdall_contract::request::ObserveRequest::Operation {
                        operation_id,
                        wait_ms,
                    } if self.runner_narrowing_store(&caller).is_some() => {
                        Some((operation_id.clone(), *wait_ms))
                    }
                    _ => None,
                };
                let local = ops.observe(&caller, r).await;
                if let (Err(e), Some((operation, wait_ms)), Some(forwarding)) =
                    (&local, &forwarded, &self.ensure_forwarding)
                    && e.code == Code::NotFound
                    && let Some(answer) = forwarding.observe(operation, *wait_ms).await
                {
                    return render(answer);
                }
                render(local)
            }
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
            // requests (F20) were refused for any other role first
            // ([`owner_only_refusal`]): authorization before capability, so a non-owner
            // learns nothing about this build's drivers, and the refusal reads and writes
            // nothing.
            Request::Issuer(_) | Request::Enrollment(_) | Request::Connections(_) => {
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
            // Owner role first (authorization before capability, [`owner_only_refusal`]);
            // then the application's entry point (`Operations::environment_request`): U3b's
            // WSL forms (Mode B answers `driver_unavailable` until U4) and U5's container
            // forms.
            Request::Environment(r) => render(ops.environment_request(&caller, r).await),
            // ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The controller's own records (the local owner
            // only, [`controller_record_refusal`]).
            Request::ControllerRecord(r) => self.controller_record(&caller, &r),
            // ⟨M06 W3⟩ The route and transport forms, when this runtime serves them.
            Request::Route(r) if self.route_transport.is_some() => match &self.route_transport {
                Some(t) => {
                    let done = t.route(&caller, &r, self.clock.wall());
                    // ⟨M06 W5 `w5n`; ADR-0012 §5.5 item 4⟩ `route.health` for every
                    // attempt (`failed_over` is its subtype, in the payload's kind). A
                    // report without an attempt (a refusal before any route) has no
                    // result to state.
                    if done.is_ok()
                        && let heimdall_contract::route::RouteRequest::RecordHealth {
                            result, ..
                        } = &r
                        && !result.attempts.is_empty()
                        && let Ok(payload) = serde_json::to_value(result)
                        && let Err(e) = ops.events().publish(EventType::Route, None, payload)
                    {
                        tracing::warn!(code = %e.code, "a route.health event was not recorded");
                    }
                    render(done.map(|data| heimdall_app::error::Completed::ok(Code::Ok, data)))
                }
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

    /// ⟨ADR-0008 §17.27 item 2⟩ `UninstallFence` (module docs) for the owner role (the others
    /// are refused first, [`owner_only_refusal`]): `acquire` holds the fence for this
    /// connection (refused `uninstall_in_progress` while another holds it), `release` lifts it
    /// when this connection holds it. Answers `OK {"fence": "held" | "released"}`.
    async fn uninstall_fence(
        &self,
        request: heimdall_contract::request::UninstallFenceRequest,
    ) -> Envelope<serde_json::Value> {
        use heimdall_contract::request::UninstallFenceRequest;
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
        // ⟨M08 U2b-2⟩ A frame with no epoch: bound to the current one at receipt.
        Box::pin(self.handle_framed(session, request, None))
    }

    /// ⟨M08 U2b-2; ADR-0014 H13⟩ The request fence's check, then the request ([`Self::handle_framed`]).
    fn dispatch_request<'life0, 'life1, 'async_trait>(
        &'life0 self,
        session: &'life1 SessionInfo,
        request: Request,
        request_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
    ) -> Pin<Box<dyn Future<Output = Envelope<serde_json::Value>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.handle_framed(session, request, request_epoch))
    }

    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 1⟩ The fence's epoch, read at start-up.
    fn restore_epoch(&self) -> Option<heimdall_contract::lifecycle::RestoreEpoch> {
        self.fence.as_ref().map(|f| f.epoch())
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
        // ⟨M08 U2b-2; ADR-0014 H13⟩ The frame epoch is offered where it is checked.
        if self.fence.is_some() {
            offer.insert(capability::REQUEST_EPOCH_V1.to_owned());
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
            // ⟨M08 U2b-3b⟩ A client or invitation a restore put on hold is not admitted.
            Ok(Some(session)) if let Some(refusal) = runner.hold_refusal(&session) => {
                Err(Box::new(refusal))
            }
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
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        dispatcher_on(store).await
    }

    async fn dispatcher_on(store: Arc<Store>) -> OperationsDispatcher {
        dispatcher_and_clock_on(store).await.0
    }

    async fn dispatcher_and_clock_on(
        store: Arc<Store>,
    ) -> (OperationsDispatcher, Arc<VirtualClock>) {
        let env = EnvironmentId::from_random_bytes([5; 16]);
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
        (OperationsDispatcher::new(ops, relay, clock.clone()), clock)
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
        // and the six runner_local forms. ⟨M06 W5 `w5n`⟩ `route.record_health`.
        assert_eq!(rows.len(), 35);
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
                    Ok(forwarded_pending(
                        &heimdall_contract::ids::GrantId::from_random_bytes([4; 16]),
                        Some(&heimdall_contract::ids::OperationId::from_random_bytes(
                            [5; 16],
                        )),
                    ))
                })
            }

            async fn observe(
                &self,
                operation: &heimdall_contract::ids::OperationId,
                _wait_ms: Option<u64>,
            ) -> Option<heimdall_app::OpResult<serde_json::Value>> {
                (*operation == heimdall_contract::ids::OperationId::from_random_bytes([5; 16]))
                    .then(|| {
                        Ok(heimdall_app::error::Completed::ok(
                            Code::Ok,
                            serde_json::json!({ "observed": true }),
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
                pair_issuers: Vec::new(),
            })
        };
        // The recorded runner: the forwarder's answer, naming the grant.
        let env = d.handle_as(&owner(), ensure(Some(&runner), "r1")).await;
        assert_eq!(env.code, Code::Accepted, "{env:?}");
        assert_eq!(env.data["error"]["resource"]["kind"], "grant");
        // ⟨M06 W4⟩ The pending state: no reason, the refresh dependency, the grant pending.
        assert!(env.data["error"].get("reason").is_none(), "{env:?}");
        assert_eq!(env.data["refresh_dependency"], "controller");
        assert_eq!(
            env.data["remote_pending"],
            serde_json::json!([heimdall_contract::ids::GrantId::from_random_bytes([4; 16])])
        );
        assert_eq!(forwarder.offered.load(Ordering::SeqCst), 1);
        // `operation wait` on the operation that answer named is the forwarder's; any other
        // unknown operation, and a paired caller's, keep the local NOT_FOUND.
        let wait = |bytes: u8| {
            Request::Observe(heimdall_contract::request::ObserveRequest::Operation {
                operation_id: heimdall_contract::ids::OperationId::from_random_bytes([bytes; 16]),
                wait_ms: Some(10),
            })
        };
        assert_eq!(env.operation_id, {
            let Request::Observe(heimdall_contract::request::ObserveRequest::Operation {
                operation_id,
                ..
            }) = wait(5)
            else {
                unreachable!()
            };
            Some(operation_id)
        });
        let observed = d.handle_as(&owner(), wait(5)).await;
        assert_eq!(observed.code, Code::Ok, "{observed:?}");
        assert_eq!(observed.data["observed"], true);
        assert_eq!(d.handle_as(&owner(), wait(6)).await.code, Code::NotFound);
        let paired_wait = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: Some(heimdall_contract::ids::ClientId::from_random_bytes([9; 16])),
        });
        assert_ne!(d.handle_as(&paired_wait, wait(5)).await.code, Code::Ok);
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
        // ⟨rev6.4; ADR-0006 §18.8 item 4⟩ `resume_issuance`: the local owner, attended,
        // naming the delivered effects the owner was shown.
        use heimdall_contract::ids::EffectId;
        use heimdall_contract::remote::EffectTarget;
        use heimdall_contract::trust::PolicyTarget;
        use heimdall_store::ext_effects::{AppliedRecord, EffectAck, EffectKey};
        let policy = heimdall_contract::ids::PolicyId::parse("pol").unwrap();
        let cutoff = |n: u8| EffectKey {
            producer: pin.client.clone(),
            effect: EffectId::from_random_bytes([n; 16]),
            target: EffectTarget::PolicyCutoff {
                scope: PolicyTarget::Policy {
                    policy_id: policy.clone(),
                },
                at: t0(),
                revision: u64::from(n),
            },
        };
        let deliver = |environment: &EnvironmentId, key: &EffectKey| {
            let ack = EffectAck {
                key: key.clone(),
                applied_at: t0(),
                record: AppliedRecord::PolicyRevision {
                    scope_key: heimdall_store::ext_effects::policy_scope_key(&policy),
                    runner_seq: key.target.generation(),
                    policies: vec![policy.clone()],
                    cutoff_at: Some(t0()),
                    fired: true,
                },
            };
            store
                .transaction(|tx| {
                    assert!(tx.enqueue_remote_effect(environment, key, t0())?);
                    assert!(tx.acknowledge_remote_effect(&ack, t0())?);
                    Ok(())
                })
                .unwrap();
        };
        let lift_ack = |key: &EffectKey| store.transaction(|tx| tx.remote_lift_ack(key)).unwrap();
        let resume_of = |effects: &[&EffectKey]| {
            Request::ControllerRecord(ControllerRecordRequest::ResumeIssuance {
                environment: runner.clone(),
                effects: effects.iter().map(|k| k.effect.clone()).collect(),
            })
        };
        // The owner is shown `shown`; `later` is delivered before their `yes` arrives.
        let (shown, later) = (cutoff(1), cutoff(2));
        deliver(&runner, &shown);
        let resume = resume_of(&[&shown]);
        deliver(&runner, &later);
        // A cutoff delivered to another runner, and one never produced.
        let elsewhere = cutoff(3);
        deliver(&EnvironmentId::from_random_bytes([6; 16]), &elsewhere);
        let never = cutoff(4);

        let env = d.handle_as(&paired, resume.clone()).await;
        assert_eq!(
            env.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED
        );
        let env = d.handle_as(&owner(), resume.clone()).await;
        assert_eq!(env.code, Code::InteractionRequired, "unattended: {env:?}");
        assert_eq!(env.data["error"]["effect_status"], "none");
        // An empty list, an unknown ID, another environment's ID: refused whole.
        for (refused, code) in [
            (resume_of(&[]), Code::UsageError),
            (resume_of(&[&shown, &never]), Code::NotFound),
            (resume_of(&[&shown, &elsewhere]), Code::NotFound),
        ] {
            let env = d.handle_as(&attended(), refused).await;
            assert_eq!(env.code, code, "{env:?}");
            assert_eq!(env.data["error"]["effect_status"], "none");
            for key in [&shown, &later, &elsewhere] {
                assert_eq!(lift_ack(key), None, "a refused request wrote nothing");
            }
        }
        let env = d.handle_as(&attended(), resume.clone()).await;
        assert_eq!(env.code, Code::Ok, "{env:?}");
        assert_eq!(
            env.data["acknowledged"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["effect"].clone())
                .collect::<Vec<_>>(),
            [serde_json::json!(shown.effect)]
        );
        assert_eq!(env.data["not_named"], 1);
        assert!(lift_ack(&shown).is_some());
        assert_eq!(
            lift_ack(&later),
            None,
            "the cutoff delivered between the list and the yes is not acknowledged"
        );
        let env = d.handle_as(&owner(), remove.clone()).await;
        assert_eq!(env.data["removed"], true, "{env:?}");
        assert!(rows().is_empty());
        let env = d.handle_as(&attended(), resume).await;
        assert_eq!(env.code, Code::NotFound, "an unrecorded runner: {env:?}");
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
        let served = Arc::new(crate::supervise_transport::RouteTransport::new(
            store.clone(),
            supervisor,
            keys,
            Arc::new(heimdall_app::transport::StorePeerEnrollments),
        ));
        let d = unwired.with_route_transport(Arc::clone(&served));
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
        // Without the transport this build cannot serve at all; with it, an unattended
        // owner's serve is a widening that needs the terminal (⟨rev6.5; ADR-0006 §18.9
        // item 10⟩). Nothing is written either way.
        #[cfg(not(feature = "iroh"))]
        {
            assert_eq!(serve.code, Code::CapabilityUnavailable, "{serve:?}");
            // ⟨M06 exit, ruling E2⟩ The refusal names the preview and how to build it.
            assert_eq!(
                serve.data["error"]["reason"],
                heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE,
                "{serve:?}"
            );
            assert_eq!(
                serve.data["error"]["message"],
                heimdall_app::transport::IROH_PREVIEW_UNAVAILABLE,
                "{serve:?}"
            );
        }
        #[cfg(feature = "iroh")]
        {
            assert_eq!(serve.code, Code::InteractionRequired, "{serve:?}");
            assert!(
                serve.data["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("`transport.enable` widens")
                        && m.contains("serving this host's sshd")),
                "{serve:?}"
            );
        }
        assert_eq!(serve.data["error"]["effect_status"], "none");
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

    /// Binding endpoints from a fixed table.
    struct FixedEndpoints(Vec<(heimdall_contract::ids::BindingId, String)>);

    impl crate::connections::BindingEndpoints for FixedEndpoints {
        fn endpoint(
            &self,
            binding: &heimdall_contract::ids::BindingId,
        ) -> Option<heimdall_contract::provider::EndpointRef> {
            self.0.iter().find(|(b, _)| b == binding).map(|(_, l)| {
                heimdall_contract::provider::EndpointRef {
                    kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                    locator: l.clone(),
                }
            })
        }
    }

    /// An active grant and binding `n` for `lab:deploy`, owned by `owner`.
    fn seed_binding(
        store: &Store,
        n: u8,
        owner: &CallerContext,
    ) -> heimdall_contract::ids::BindingId {
        let id = heimdall_contract::ids::BindingId::from_random_bytes([n; 16]);
        seed_binding_with_id(store, id.clone(), usize::from(n), owner);
        id
    }

    fn seed_binding_with_id(
        store: &Store,
        id: heimdall_contract::ids::BindingId,
        n: usize,
        owner: &CallerContext,
    ) {
        use heimdall_contract::ids::{AccountName, DestinationId, GrantId};
        use heimdall_contract::request::{
            DeadlineIntent, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
            NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
        };
        let environment = store
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap();
        let scope = heimdall_domain::scope::Scope {
            pairs: [heimdall_domain::scope::AccessPair {
                destination: DestinationId::parse("lab").unwrap(),
                account: AccountName::parse("deploy").unwrap(),
            }]
            .into_iter()
            .collect(),
            capabilities: [heimdall_domain::scope::Capability::SshAuthentication]
                .into_iter()
                .collect(),
        };
        let grant = heimdall_domain::grant::GrantSnapshot {
            id: {
                let mut g = [0x47_u8; 16];
                g[..8].copy_from_slice(&(n as u64).to_be_bytes());
                GrantId::from_random_bytes(g)
            },
            environment: environment.clone(),
            scope: scope.clone(),
            starts_at: t0(),
            deadline: heimdall_domain::time::Deadline {
                intent: DeadlineIntent::Duration("60m".into()),
                resolved_at: t0(),
                effective: heimdall_contract::Timestamp::from_second(t0().as_second() + 3600)
                    .unwrap(),
            },
            parent: None,
            source: heimdall_domain::grant::AuthorizationSource::StandingPolicy {
                revision: heimdall_domain::policy::PolicyRevision(1),
            },
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            state: heimdall_contract::GrantState::Active,
            enforcement: heimdall_domain::evidence::EnforcementEvidence {
                report: Enforcement::new(
                    DestinationScopeEnforcement::Unknown,
                    NewAuthenticationExpiry::Unknown,
                    WorkloadIsolation::SharedOsUser,
                    ExistingConnectionsPolicy::Unknown,
                    RevocationStatus::Unknown,
                ),
                evidence: Vec::new(),
            },
        };
        let binding = heimdall_domain::binding::BindingRecord {
            id,
            environment,
            grant: grant.id.clone(),
            work_id: heimdall_contract::ids::WorkId::parse(&format!("w{n}")).unwrap(),
            owner: owner.clone(),
            profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope,
            mechanism: "existing_access".to_owned(),
            parent: None,
            created_at: t0(),
            released_at: None,
            state: heimdall_domain::binding::BindingState::Active,
        };
        store
            .transaction(|tx| {
                tx.insert_grant(&grant)?;
                tx.insert_binding(&binding)
            })
            .unwrap();
    }

    /// ⟨rev6.5; ADR-0006 §18.9 item 11⟩ `route.record_health`, each condition of the ruling:
    /// * (a) only the caller that owns the binding served at the named endpoint for the
    ///   pair may report. Refused, nothing kept: a paired session; a local caller with
    ///   another principal, **the local owner included** (its access to every caller's
    ///   objects does not apply here); the owning caller naming an endpoint no binding of
    ///   its own is served at, or another caller's endpoint;
    /// * (b) the report is typed: an unknown route ID, another account, a duration past
    ///   the bound, too many attempts, a pin setting outside the contract's list, a final
    ///   route that is not the one attempt that did not fail, and any free-text or host
    ///   field's value in a typed position are refused;
    /// * (c) a report changes nothing but the ledger: the stored route list, its order
    ///   and its consents are exactly as before, whatever was reported;
    /// * (d) the ledger is bounded: a binding keeps its newest
    ///   `ROUTE_HEALTH_REPORTS_PER_BINDING` reports, and at most
    ///   `ROUTE_HEALTH_BINDINGS_MAX` bindings are kept;
    /// * (e) it is in memory only: a new `RouteTransport` over the same store holds none.
    #[tokio::test]
    async fn route_health_is_reported_only_by_the_binding_typed_and_bounded() {
        use crate::supervise_transport::{
            ROUTE_HEALTH_BINDINGS_MAX, ROUTE_HEALTH_REPORTS_PER_BINDING, RouteTransport,
        };
        use heimdall_contract::route::{
            ROUTE_ATTEMPT_DURATION_MAX_MS, ROUTE_HEALTH_ATTEMPTS_MAX, RouteRequest, RouteSpec,
        };
        let (store, d, lab, _clock) = local_widening_rig().await;
        // A second approved route, so a report can name a failover.
        let approved = d
            .handle_as(
                &owner(),
                Request::Route(RouteRequest::Add {
                    destination: lab.clone(),
                    route: RouteSpec::Direct {
                        host: "10.0.0.10".into(),
                        port: None,
                    },
                    exposure: None,
                    request_id: heimdall_contract::ids::RequestId::parse("req_route_h").unwrap(),
                }),
            )
            .await;
        assert_eq!(approved.code, Code::Ok, "{approved:?}");
        let routes: Vec<heimdall_contract::ids::RouteId> =
            serde_json::from_value(approved.data["routes"].clone()).unwrap();
        let stored_before = store.transaction(|tx| tx.destination_routes(&lab)).unwrap();
        let consents_before = store.transaction(|tx| tx.all_route_consents()).unwrap();

        // The helper's caller (an agent's local session) owns binding 1; another local
        // caller owns binding 2.
        let helper_ctx = CallerContext::local(
            PrincipalRef::UnixUser { uid: 1001 },
            ClientRole::LimitedConsumer,
        );
        let other_ctx = CallerContext::local(
            PrincipalRef::UnixUser { uid: 1002 },
            ClientRole::LimitedConsumer,
        );
        let helper = Caller::unattended(helper_ctx.clone());
        let other = Caller::unattended(other_ctx.clone());
        let b1 = seed_binding(&store, 1, &helper_ctx);
        let b2 = seed_binding(&store, 2, &other_ctx);
        let (mine, theirs) = ("/run/b1/agent.sock", "/run/b2/agent.sock");
        let wire = |served: Vec<(heimdall_contract::ids::BindingId, String)>| {
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
            Arc::new(
                RouteTransport::new(
                    store.clone(),
                    supervisor,
                    keys,
                    Arc::new(heimdall_app::transport::StorePeerEnrollments),
                )
                .with_binding_endpoints(Arc::new(FixedEndpoints(served))),
            )
        };
        let served = wire(vec![(b1.clone(), mine.to_owned()), (b2, theirs.to_owned())]);
        let report = |endpoint: &str, result: serde_json::Value, pin: Option<&str>| {
            let mut doc = serde_json::json!({
                "op": "route", "action": "record_health", "endpoint": endpoint, "result": result,
            });
            if let Some(pin) = pin {
                doc["host_pin_defeated"] = serde_json::json!(pin);
            }
            match serde_json::from_value::<Request>(doc).unwrap() {
                Request::Route(r) => r,
                other => panic!("{other:?}"),
            }
        };
        let result = |attempts: serde_json::Value,
                      last: Option<&heimdall_contract::ids::RouteId>| {
            let mut r = serde_json::json!({
                "kind": "failed_over", "destination": "lab", "account": "deploy",
                "attempts": attempts,
            });
            if let Some(last) = last {
                r["final_route"] = serde_json::json!(last);
            }
            r
        };
        let good = || {
            result(
                serde_json::json!([
                    {"route": routes[0], "failure": "refused", "duration_ms": 12},
                    {"route": routes[1], "duration_ms": 30},
                ]),
                Some(&routes[1]),
            )
        };
        let now = t0();
        let send = |caller: &Caller, request: &RouteRequest| served.route(caller, request, now);

        // (a) who may report.
        let mut paired = helper.clone();
        paired.context.remote_client =
            Some(heimdall_contract::ids::ClientId::from_random_bytes([4; 16]));
        for (who, caller, endpoint) in [
            ("a paired session", &paired, mine),
            ("another local caller", &other, mine),
            ("the local owner", &owner(), mine),
            (
                "the owning caller at another caller's endpoint",
                &helper,
                theirs,
            ),
            (
                "the owning caller at no binding's endpoint",
                &helper,
                "/run/none/agent.sock",
            ),
        ] {
            let e = send(caller, &report(endpoint, good(), None)).unwrap_err();
            assert_eq!(e.code, Code::CapabilityUnavailable, "{who}: {e:?}");
            assert_eq!(e.effect_status, EffectStatus::None, "{who}");
        }
        assert_eq!(
            served.route_health_len(),
            (0, 0),
            "a refused report was kept"
        );

        // (b) typed.
        let unknown = heimdall_contract::ids::RouteId::from_random_bytes([9; 16]);
        let too_many: Vec<_> = (0..=ROUTE_HEALTH_ATTEMPTS_MAX)
            .map(|_| serde_json::json!({"route": routes[0], "failure": "timeout"}))
            .collect();
        let mut other_account = good();
        other_account["account"] = serde_json::json!("root");
        for (what, request) in [
            (
                "an unknown route",
                report(
                    mine,
                    result(serde_json::json!([{"route": unknown}]), Some(&unknown)),
                    None,
                ),
            ),
            ("another account", report(mine, other_account, None)),
            (
                "a duration past the bound",
                report(
                    mine,
                    result(
                        serde_json::json!([{"route": routes[0], "failure": "timeout",
                            "duration_ms": ROUTE_ATTEMPT_DURATION_MAX_MS + 1}]),
                        None,
                    ),
                    None,
                ),
            ),
            (
                "too many attempts",
                report(mine, result(serde_json::json!(too_many), None), None),
            ),
            (
                "a final route that no attempt used",
                report(
                    mine,
                    result(
                        serde_json::json!([{"route": routes[0], "failure": "refused"}]),
                        Some(&routes[1]),
                    ),
                    None,
                ),
            ),
            (
                "a used route without a final route",
                report(
                    mine,
                    result(serde_json::json!([{"route": routes[0]}]), None),
                    None,
                ),
            ),
            (
                "a pin setting outside the list",
                report(mine, result(serde_json::json!([]), None), Some("hostname")),
            ),
            (
                "free text as the pin setting",
                report(
                    mine,
                    result(serde_json::json!([]), None),
                    Some("lab.lan was unreachable"),
                ),
            ),
        ] {
            let e = send(&helper, &request).unwrap_err();
            // No binding of the caller covers another account's pair: that one is refused
            // as "not the binding" before the catalog is read.
            let expected = if what == "another account" {
                Code::CapabilityUnavailable
            } else {
                Code::UsageError
            };
            assert_eq!(e.code, expected, "{what}: {e:?}");
        }
        // A free-text outcome, a host string as the route, or a text duration is not the
        // form at all.
        for bad in [
            serde_json::json!([{"route": routes[0], "failure": "the host was down"}]),
            serde_json::json!([{"route": "lab.lan:22", "failure": "refused"}]),
            serde_json::json!([{"route": routes[0], "failure": "refused", "duration_ms": "long"}]),
        ] {
            let doc = serde_json::json!({
                "op": "route", "action": "record_health", "endpoint": mine,
                "result": result(bad.clone(), None),
            });
            assert!(serde_json::from_value::<Request>(doc).is_err(), "{bad}");
        }
        assert_eq!(
            served.route_health_len(),
            (0, 0),
            "a refused report was kept"
        );

        // The binding's own caller: kept.
        send(&helper, &report(mine, good(), None)).unwrap();
        let kept = served.route_health(&lab).expect("the report is kept");
        assert_eq!(kept.result.final_route.as_ref(), Some(&routes[1]));
        assert_eq!(kept.result.attempts[0].duration_ms, Some(12));
        send(
            &helper,
            &report(
                mine,
                result(serde_json::json!([]), None),
                Some("stricthostkeychecking"),
            ),
        )
        .unwrap();
        assert_eq!(served.route_health_len(), (1, 2));

        // (c) nothing but the ledger changed: the same routes, in the same order, the same
        // consents, though the first route was reported failed.
        assert_eq!(
            store.transaction(|tx| tx.destination_routes(&lab)).unwrap(),
            stored_before
        );
        assert_eq!(
            store.transaction(|tx| tx.all_route_consents()).unwrap(),
            consents_before
        );

        // (d) bounded per binding, and in bindings.
        for _ in 0..(ROUTE_HEALTH_REPORTS_PER_BINDING * 3) {
            send(&helper, &report(mine, good(), None)).unwrap();
        }
        assert_eq!(
            served.route_health_len(),
            (1, ROUTE_HEALTH_REPORTS_PER_BINDING)
        );
        let mut many = vec![(b1, mine.to_owned())];
        for n in 10..(10 + ROUTE_HEALTH_BINDINGS_MAX as u16 + 5) {
            // Distinct IDs: two bytes of the 16 vary.
            let mut id = [0xEE_u8; 16];
            id[0] = (n >> 8) as u8;
            id[1] = (n & 0xff) as u8;
            many.push((
                heimdall_contract::ids::BindingId::from_random_bytes(id),
                format!("/run/x{n}/agent.sock"),
            ));
        }
        // (e) a new transport over the same store starts empty: memory only.
        let fresh = wire(many.clone());
        assert_eq!(fresh.route_health_len(), (0, 0));
        assert!(fresh.route_health(&lab).is_none());
        // Fill past the binding bound through the ledger's own insert path: each binding
        // must exist and be the caller's, so seed them.
        for (i, (binding, endpoint)) in many.iter().enumerate().skip(1) {
            seed_binding_with_id(&store, binding.clone(), 1000 + i, &helper_ctx);
            fresh
                .route(&helper, &report(endpoint, good(), None), now)
                .unwrap();
        }
        let (bindings, reports) = fresh.route_health_len();
        assert_eq!(bindings, ROUTE_HEALTH_BINDINGS_MAX);
        assert_eq!(reports, ROUTE_HEALTH_BINDINGS_MAX);
    }

    /// A non-runner dispatcher with the route and transport forms wired over a store that
    /// holds one managed destination, `lab`.
    async fn local_widening_rig() -> (
        Arc<Store>,
        OperationsDispatcher,
        heimdall_contract::ids::DestinationId,
        Arc<VirtualClock>,
    ) {
        use heimdall_contract::ids::{AccountName, DestinationId, IdentityId};
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
        let (d, clock) = dispatcher_and_clock_on(store.clone()).await;
        let d = d.with_route_transport(Arc::new(crate::supervise_transport::RouteTransport::new(
            store.clone(),
            supervisor,
            keys,
            Arc::new(heimdall_app::transport::StorePeerEnrollments),
        )));
        (store, d, lab, clock)
    }

    /// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ `route add`'s relay URLs, at the runtime:
    /// * each refusal class (a scheme the relay transport does not accept, userinfo, a query
    ///   string, a fragment, a malformed URL) is `USAGE_ERROR`, effect none, for an attended
    ///   and an unattended owner alike, and makes no record and no route; the answer never
    ///   quotes the URL;
    /// * the request is normalised before it is recorded: the record's request and delta
    ///   hold the one spelling, each distinct URL once, sorted;
    /// * a retry that spells the same URLs differently, in another order, finds the same
    ///   pending record (one digest); another URL is another record;
    /// * after the approval the stored route's policy and its consent's delta hold the
    ///   normal form.
    /// ⟨M06 W5 `w5s`, M06-W5-R05; ADR-0006 §18.9 item 9⟩ A relay URL whose path carries a
    /// token: stored as given (the record, the route and the consent's delta), and never
    /// shown. No answer carries its path: the unattended refusal's detail, the attended
    /// `APPROVAL_REQUIRED`, `inspect decisions`, the approval, `inspect destinations` and
    /// the event pages. Each shows the scheme, host and port with the URL's digest.
    #[tokio::test]
    async fn a_relay_urls_path_is_stored_and_never_shown() {
        use heimdall_contract::ids::IrohEndpointId;
        use heimdall_contract::request::{
            DecideRequest, InspectRequest, InspectSubject, ObserveRequest, Verdict,
        };
        use heimdall_contract::route::{
            ExposurePolicy, InfrastructureProfile, RouteRequest, RouteSpec, relay_display,
        };
        const TOKEN: &str = "t0k3nInThePath";
        let relay = format!("https://relay.invalid.:8443/{TOKEN}");
        let (store, d, lab, _clock) = local_widening_rig().await;
        let add = |request_id: &str| {
            Request::Route(RouteRequest::Add {
                destination: lab.clone(),
                route: RouteSpec::Iroh {
                    endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                    direct_addresses: Vec::new(),
                    external_roost: false,
                },
                exposure: Some(ExposurePolicy {
                    infrastructure: InfrastructureProfile::Custom {
                        relays: vec![relay.clone()],
                    },
                    ..ExposurePolicy::default()
                }),
                request_id: heimdall_contract::ids::RequestId::parse(request_id).unwrap(),
            })
        };
        let shown = relay_display(&relay);
        assert!(
            shown.starts_with("https://relay.invalid.:8443 (sha256:"),
            "{shown}"
        );
        let unseen = |what: &str, env: &Envelope<serde_json::Value>| {
            let text = serde_json::to_string(env).unwrap();
            assert!(
                !text.contains(TOKEN),
                "{what} shows the relay URL's path: {text}"
            );
        };

        let unattended = d.handle_as(&owner(), add("req_1")).await;
        assert_eq!(unattended.code, Code::InteractionRequired, "{unattended:?}");
        unseen("the unattended refusal", &unattended);
        assert!(
            unattended.data.to_string().contains(&shown),
            "the refusal names the relay: {unattended:?}"
        );
        let asked = d.handle_as(&attended(), add("req_2")).await;
        assert_eq!(asked.code, Code::ApprovalRequired, "{asked:?}");
        unseen("the approval request", &asked);
        let id = heimdall_contract::ids::DecisionId::parse(
            asked
                .next
                .as_ref()
                .unwrap()
                .decision_ref
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        // Stored as given.
        let recorded = store.transaction(|tx| tx.pending_decisions()).unwrap();
        assert!(
            serde_json::to_string(&recorded).unwrap().contains(TOKEN),
            "the record keeps the URL"
        );
        let inspect = |subject| {
            Request::Inspect(InspectRequest {
                subject,
                preview: None,
                cwd: None,
                redact: false,
            })
        };
        let listed = d
            .handle_as(&attended(), inspect(InspectSubject::Decisions))
            .await;
        unseen("inspect decisions", &listed);
        assert!(listed.data.to_string().contains(&shown), "{listed:?}");

        let approved = d
            .handle_as(
                &attended(),
                Request::Decide(DecideRequest {
                    decision_id: id,
                    verdict: Verdict::Approve,
                }),
            )
            .await;
        assert_eq!(approved.code, Code::Ok, "{approved:?}");
        unseen("the approval", &approved);
        let routes = store.transaction(|tx| tx.destination_routes(&lab)).unwrap();
        assert!(
            serde_json::to_string(&routes).unwrap().contains(TOKEN),
            "the stored route keeps the URL"
        );
        let added = routes
            .iter()
            .find(|r| matches!(r.route, RouteSpec::Iroh { .. }))
            .expect("the route");
        let consents = store
            .transaction(|tx| tx.route_consents(Some(&added.id)))
            .unwrap();
        assert!(
            consents
                .iter()
                .any(|c| c.delta.relays_added == vec![relay.clone()]),
            "the consent's delta keeps the URL"
        );
        for subject in [InspectSubject::Destinations, InspectSubject::Decisions] {
            let env = d.handle_as(&attended(), inspect(subject)).await;
            unseen("inspect", &env);
        }
        let events = d
            .handle_as(
                &attended(),
                Request::Observe(ObserveRequest::Events {
                    cursor: None,
                    filter: Default::default(),
                    limit: None,
                }),
            )
            .await;
        unseen("the event page", &events);
        // The same add again under the same policy: the existing route, shown so too.
        let again = d.handle_as(&attended(), add("req_3")).await;
        assert_eq!(again.code, Code::Ok, "{again:?}");
        unseen("already_present", &again);
    }

    #[tokio::test]
    async fn route_add_relay_urls_are_validated_and_normalised_before_any_record() {
        use heimdall_contract::ids::IrohEndpointId;
        use heimdall_contract::request::{DecideRequest, Verdict};
        use heimdall_contract::route::{
            ExposurePolicy, InfrastructureProfile, RouteRequest, RouteSpec,
        };
        let (store, d, lab, _clock) = local_widening_rig().await;
        let add = |request_id: &str, relays: &[&str]| {
            Request::Route(RouteRequest::Add {
                destination: lab.clone(),
                route: RouteSpec::Iroh {
                    endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                    direct_addresses: Vec::new(),
                    external_roost: false,
                },
                exposure: Some(ExposurePolicy {
                    infrastructure: InfrastructureProfile::Custom {
                        relays: relays.iter().map(|r| (*r).to_owned()).collect(),
                    },
                    ..ExposurePolicy::default()
                }),
                request_id: heimdall_contract::ids::RequestId::parse(request_id).unwrap(),
            })
        };
        let pending = || {
            store
                .transaction(|tx| tx.pending_decisions())
                .unwrap()
                .into_iter()
                .filter_map(|d| match d.kind {
                    heimdall_domain::decision::DecisionKind::RemoteWidening(w) => Some((d.id, *w)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let routes = || store.transaction(|tx| tx.destination_routes(&lab)).unwrap();

        for (bad, class) in [
            ("ftp://relay.invalid./", "https:// or http://"),
            (
                "https://user:hunter2@relay.invalid./",
                "no user name or password",
            ),
            ("https://relay.invalid./?token=hunter2", "no query string"),
            ("https://relay.invalid./#hunter2", "no fragment"),
            ("https://relay.invalid.:0/", "a scheme, a host"),
        ] {
            for caller in [attended(), owner()] {
                let env = d
                    .handle_as(&caller, add("req_bad", &["https://ok.invalid./", bad]))
                    .await;
                assert_eq!(env.code, Code::UsageError, "{bad}: {env:?}");
                assert_eq!(env.data["error"]["effect_status"], "none", "{bad}");
                let text = env.data.to_string();
                assert!(text.contains("relay URL 2"), "{bad}: {text}");
                assert!(text.contains(class), "{bad}: {text}");
                assert!(!text.contains("hunter2"), "{bad}: the URL is quoted");
            }
            assert!(pending().is_empty(), "{bad}: a record was made");
            assert!(routes().is_empty(), "{bad}");
        }

        // Two spellings of one relay and a second relay: one record, the normal form.
        let first = d
            .handle_as(
                &attended(),
                add(
                    "req_1",
                    &[
                        "HTTPS://Relay.Invalid.:443",
                        "http://other.invalid.:8080/r",
                        "https://relay.invalid./",
                    ],
                ),
            )
            .await;
        assert_eq!(first.code, Code::ApprovalRequired, "{first:?}");
        let reference = first.next.as_ref().and_then(|n| n.decision_ref.clone());
        let recorded = pending();
        assert_eq!(recorded.len(), 1);
        let (id, w) = &recorded[0];
        let normal = ["http://other.invalid.:8080/r", "https://relay.invalid./"];
        assert_eq!(w.request, add("req_1", &normal));
        let delta = w.exposure.clone().expect("the record carries its delta");
        assert_eq!(
            delta["relays_added"],
            serde_json::json!(normal),
            "each URL is named in the delta, once: {delta}"
        );
        // A retry in another spelling: the same record.
        let again = d
            .handle_as(
                &attended(),
                add(
                    "req_2",
                    &["https://RELAY.invalid.", "HTTP://other.invalid.:08080/r"],
                ),
            )
            .await;
        assert_eq!(again.code, Code::ApprovalRequired, "{again:?}");
        assert_eq!(
            again.next.as_ref().and_then(|n| n.decision_ref.clone()),
            reference
        );
        assert_eq!(pending().len(), 1, "another spelling made a second record");
        // Another URL (the path differs in case) is another record.
        let other = d
            .handle_as(
                &attended(),
                add(
                    "req_3",
                    &["https://relay.invalid./", "http://other.invalid.:8080/R"],
                ),
            )
            .await;
        assert_eq!(other.code, Code::ApprovalRequired, "{other:?}");
        assert_eq!(pending().len(), 2);
        assert!(routes().is_empty());

        let approved = d
            .handle_as(
                &attended(),
                Request::Decide(DecideRequest {
                    decision_id: id.clone(),
                    verdict: Verdict::Approve,
                }),
            )
            .await;
        assert_eq!(approved.code, Code::Ok, "{approved:?}");
        let stored = routes();
        assert_eq!(stored.len(), 2, "the definition's route and the new one");
        let added = stored
            .iter()
            .find(|r| matches!(r.route, RouteSpec::Iroh { .. }))
            .expect("the route");
        assert_eq!(
            added.exposure.as_ref().map(|e| &e.infrastructure),
            Some(&InfrastructureProfile::Custom {
                relays: normal.iter().map(|r| (*r).to_owned()).collect()
            })
        );
        let consents = store
            .transaction(|tx| tx.route_consents(Some(&added.id)))
            .unwrap();
        assert_eq!(consents.len(), 1);
        assert_eq!(serde_json::to_value(&consents[0].delta).unwrap(), delta);
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A local widening decision through a dispatcher that
    /// is **not a runner** (no paired-runner service): a widening `route add`.
    ///
    /// * an unattended local owner is answered `INTERACTION_REQUIRED`, the detail naming
    ///   the request and what it adds, with no reason, and no record is made (⟨rev6.5;
    ///   ADR-0006 §18.9 item 10⟩);
    /// * a paired session never produces a local record, even one that claims attendance
    ///   (a caller the frame never builds): refused, nothing recorded;
    /// * the attended local owner gets `APPROVAL_REQUIRED` with the decision reference; the
    ///   record says `origin: local`, names no client, and carries the exact delta;
    /// * a retry with a fresh request ID returns the same pending record;
    /// * another delta is another record;
    /// * an unattended or paired `Decide` never approves it; nothing is written meanwhile;
    /// * the attended local owner's approval runs the exact request once: the route is
    ///   stored with a recorded consent naming the decision and the delta; a second
    ///   approval is `DECISION_STALE`; the same request again is the existing route.
    #[tokio::test]
    async fn a_local_widening_is_recorded_and_approved_only_by_the_attended_local_owner() {
        use heimdall_contract::ids::IrohEndpointId;
        use heimdall_contract::request::{DecideRequest, Verdict};
        use heimdall_contract::route::{ExposurePolicy, RouteRequest, RouteSpec};
        let (store, d, lab, _clock) = local_widening_rig().await;
        let add = |request_id: &str, fallback: bool, relay: bool| {
            Request::Route(RouteRequest::Add {
                destination: lab.clone(),
                route: RouteSpec::Iroh {
                    endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                    direct_addresses: Vec::new(),
                    external_roost: false,
                },
                exposure: Some(ExposurePolicy {
                    direct_fallback: fallback,
                    infrastructure: if relay {
                        heimdall_contract::route::InfrastructureProfile::Custom {
                            relays: vec!["https://relay.invalid./".into()],
                        }
                    } else {
                        heimdall_contract::route::InfrastructureProfile::None
                    },
                    ..ExposurePolicy::default()
                }),
                request_id: heimdall_contract::ids::RequestId::parse(request_id).unwrap(),
            })
        };
        let pending = || {
            store
                .transaction(|tx| tx.pending_decisions())
                .unwrap()
                .into_iter()
                .filter_map(|d| match d.kind {
                    heimdall_domain::decision::DecisionKind::RemoteWidening(w) => Some((d.id, *w)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let routes = || store.transaction(|tx| tx.destination_routes(&lab)).unwrap();
        let unconsented = |env: &Envelope<serde_json::Value>| {
            assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
            assert_eq!(
                env.data["error"]["reason"],
                heimdall_contract::envelope::reason::EXPOSURE_UNCONSENTED,
                "{env:?}"
            );
            assert_eq!(env.data["error"]["effect_status"], "none", "{env:?}");
        };

        // An unattended local owner: `INTERACTION_REQUIRED` naming the widening, no record.
        for (request, names) in [
            (add("req_u", true, false), "direct fallback"),
            (
                add("req_r", false, true),
                // ⟨`w5s`, M06-W5-R05⟩ Shown as scheme, host and port with its digest.
                "the relay https://relay.invalid. (sha256:",
            ),
        ] {
            let env = d.handle_as(&owner(), request).await;
            assert_eq!(env.code, Code::InteractionRequired, "{env:?}");
            assert_eq!(env.data["error"]["effect_status"], "none", "{env:?}");
            assert!(
                env.data["error"]
                    .get("reason")
                    .is_none_or(serde_json::Value::is_null)
            );
            let detail = env.data.to_string();
            assert!(detail.contains("`route.add` widens"), "{detail}");
            assert!(detail.contains(names), "{detail}");
            assert!(
                env.next
                    .as_ref()
                    .and_then(|n| n.decision_ref.as_ref())
                    .is_none(),
                "there is no record to name"
            );
        }
        assert!(pending().is_empty());
        // A paired session, even one claiming attendance: refused, no record.
        let paired_client = heimdall_contract::ids::ClientId::from_random_bytes([9; 16]);
        let paired = Caller {
            context: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
                remote_client: Some(paired_client),
            },
            attendance: Attendance::Attended { since: t0() },
            interaction: heimdall_contract::request::InteractionMode::Interactive,
        };
        unconsented(&d.handle_as(&paired, add("req_p", true, false)).await);
        assert!(
            pending().is_empty(),
            "a paired session produced a widening record on the local path"
        );

        // The attended local owner: a pending local record, bound to the exact delta.
        let first = d.handle_as(&attended(), add("req_1", true, false)).await;
        assert_eq!(first.code, Code::ApprovalRequired, "{first:?}");
        assert_eq!(first.data["error"]["effect_status"], "none", "{first:?}");
        let reference = first
            .next
            .as_ref()
            .and_then(|n| n.decision_ref.clone())
            .expect("the pending answer names its decision");
        let recorded = pending();
        assert_eq!(recorded.len(), 1);
        let (id, w) = &recorded[0];
        assert_eq!(id.as_str(), reference);
        assert_eq!(w.origin, heimdall_domain::decision::WideningOrigin::Local);
        assert_eq!(w.client, None);
        assert_eq!(w.request, add("req_1", true, false));
        let delta = w.exposure.clone().expect("the record carries its delta");
        assert_eq!(delta["direct_fallback_added"], true, "{delta}");
        let document = serde_json::to_value(
            heimdall_domain::decision::DecisionKind::RemoteWidening(Box::new(w.clone())),
        )
        .unwrap();
        assert_eq!(document["origin"], "local", "{document}");
        assert!(document.get("client").is_none(), "{document}");
        // The owner's decision list shows it so.
        let listed = d
            .handle_as(
                &attended(),
                Request::Inspect(heimdall_contract::request::InspectRequest {
                    subject: heimdall_contract::request::InspectSubject::Decisions,
                    preview: None,
                    cwd: None,
                    redact: false,
                }),
            )
            .await;
        let shown = &listed.data["decisions"][0];
        assert_eq!(shown["decision_id"], reference.as_str(), "{listed:?}");
        assert_eq!(shown["request"]["origin"], "local", "{listed:?}");
        assert!(shown["request"].get("client").is_none(), "{listed:?}");
        assert_eq!(shown["request"]["exposure"], delta, "{listed:?}");

        // A retry (a fresh request ID, the same widening): the same pending record.
        let again = d.handle_as(&attended(), add("req_2", true, false)).await;
        assert_eq!(again.code, Code::ApprovalRequired, "{again:?}");
        assert_eq!(
            again.next.as_ref().and_then(|n| n.decision_ref.clone()),
            Some(reference.clone())
        );
        assert_eq!(pending().len(), 1, "a retry made a second record");
        // Another delta is another record.
        let other = d.handle_as(&attended(), add("req_3", true, true)).await;
        assert_eq!(other.code, Code::ApprovalRequired, "{other:?}");
        assert_ne!(
            other.next.as_ref().and_then(|n| n.decision_ref.clone()),
            Some(reference.clone())
        );
        assert_eq!(pending().len(), 2);
        assert!(routes().is_empty(), "nothing is written before an approval");
        assert!(
            store
                .transaction(|tx| tx.all_route_consents())
                .unwrap()
                .is_empty()
        );

        // Only the attended local owner decides.
        let decide = |verdict| {
            Request::Decide(DecideRequest {
                decision_id: id.clone(),
                verdict,
            })
        };
        let unattended = d.handle_as(&owner(), decide(Verdict::Approve)).await;
        assert_eq!(unattended.code, Code::InteractionRequired, "{unattended:?}");
        let from_paired = d.handle_as(&paired, decide(Verdict::Approve)).await;
        assert_eq!(
            from_paired.code,
            Code::InteractionRequired,
            "{from_paired:?}"
        );
        assert_eq!(
            from_paired.data["error"]["reason"],
            heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED
        );
        assert!(routes().is_empty());
        assert_eq!(pending().len(), 2, "a refused decide consumed nothing");

        let approved = d.handle_as(&attended(), decide(Verdict::Approve)).await;
        assert_eq!(approved.code, Code::Ok, "{approved:?}");
        let route =
            heimdall_contract::ids::RouteId::parse(approved.data["route"].as_str().unwrap())
                .unwrap();
        let stored = routes();
        let added = stored.iter().find(|r| r.id == route).expect("the route");
        assert!(added.exposure.as_ref().is_some_and(|e| e.direct_fallback));
        let consents = store
            .transaction(|tx| tx.route_consents(Some(&route)))
            .unwrap();
        assert_eq!(consents.len(), 1);
        assert_eq!(&consents[0].decision, id);
        assert_eq!(serde_json::to_value(&consents[0].delta).unwrap(), delta);
        assert_eq!(added.consents, vec![consents[0].consent.clone()]);
        // Consumed once.
        let twice = d.handle_as(&attended(), decide(Verdict::Approve)).await;
        assert_eq!(twice.code, Code::DecisionStale, "{twice:?}");
        assert_eq!(routes().len(), stored.len());
        // The same widening again is the existing route: no new record.
        let present = d.handle_as(&attended(), add("req_4", true, false)).await;
        assert_eq!(present.code, Code::Ok, "{present:?}");
        assert_eq!(present.data["already_present"], true, "{present:?}");
        assert_eq!(
            pending().len(),
            1,
            "only the other delta's record is pending"
        );
        // The route write moved the authority generation: the other record, issued before
        // it, is stale and is never approved; the same widening submitted again is a new
        // record (not the stale one), and a denial of it writes nothing.
        let other_id = pending()[0].0.clone();
        let decide_other = |decision_id: heimdall_contract::ids::DecisionId, verdict| {
            Request::Decide(DecideRequest {
                decision_id,
                verdict,
            })
        };
        let stale = d
            .handle_as(
                &attended(),
                decide_other(other_id.clone(), Verdict::Approve),
            )
            .await;
        assert_eq!(stale.code, Code::DecisionStale, "{stale:?}");
        assert!(pending().is_empty());
        // ⟨M06 W5 `w5s`, M06-W5-R02⟩ The approved route's endpoint again with another
        // policy (a relay added) is not the existing route: `CONFIG_CONFLICT` with the next
        // step, no record, nothing changed; never `already_present` with the relay dropped.
        let same_route = d.handle_as(&attended(), add("req_5", true, true)).await;
        assert_eq!(same_route.code, Code::ConfigConflict, "{same_route:?}");
        assert_eq!(
            same_route.data["error"]["message"],
            heimdall_app::routes::ops::EXPOSURE_DIFFERS,
            "{same_route:?}"
        );
        assert!(pending().is_empty());
        assert_eq!(routes(), stored);
        let mut elsewhere = add("req_6", true, true);
        if let Request::Route(RouteRequest::Add {
            route: RouteSpec::Iroh { endpoint, .. },
            ..
        }) = &mut elsewhere
        {
            *endpoint = IrohEndpointId::parse(&"cd".repeat(32)).unwrap();
        }
        let fresh = d.handle_as(&attended(), elsewhere).await;
        assert_eq!(fresh.code, Code::ApprovalRequired, "{fresh:?}");
        let fresh_id = pending()[0].0.clone();
        assert_ne!(fresh_id, other_id);
        let denied = d
            .handle_as(&attended(), decide_other(fresh_id, Verdict::Deny))
            .await;
        assert_eq!(denied.code, Code::CapabilityUnavailable, "{denied:?}");
        assert!(pending().is_empty());
        assert_eq!(routes().len(), stored.len());
    }

    /// ⟨M06 W5 `w5o`; brief item 5⟩ A local widening record that lapses:
    /// * while inside its lifetime it is listed `pending`, `expired: false`, no reason;
    /// * at the first decision read past its deadline it is listed once more, as
    ///   `state: expired`, `expired: true`, `reason: approval_lapsed`; the store holds it
    ///   `expired` with the `DECISION_STALE` / `approval_lapsed` answer; the event log has
    ///   one `decision` event naming it with state `expired`;
    /// * the next read lists nothing and appends no second event;
    /// * an approval of it is `DECISION_STALE` and writes nothing; the same widening
    ///   submitted again is a new record.
    #[tokio::test]
    async fn a_lapsed_local_widening_shows_expired_with_its_reason_and_is_in_the_event_log() {
        use heimdall_contract::ids::IrohEndpointId;
        use heimdall_contract::request::{DecideRequest, Verdict};
        use heimdall_contract::route::{ExposurePolicy, RouteRequest, RouteSpec};
        let (store, d, lab, clock) = local_widening_rig().await;
        let add = |request_id: &str| {
            Request::Route(RouteRequest::Add {
                destination: lab.clone(),
                route: RouteSpec::Iroh {
                    endpoint: IrohEndpointId::parse(&"ab".repeat(32)).unwrap(),
                    direct_addresses: Vec::new(),
                    external_roost: false,
                },
                exposure: Some(ExposurePolicy {
                    direct_fallback: true,
                    ..ExposurePolicy::default()
                }),
                request_id: heimdall_contract::ids::RequestId::parse(request_id).unwrap(),
            })
        };
        let listed = || async {
            d.handle_as(
                &attended(),
                Request::Inspect(heimdall_contract::request::InspectRequest {
                    subject: heimdall_contract::request::InspectSubject::Decisions,
                    preview: None,
                    cwd: None,
                    redact: false,
                }),
            )
            .await
            .data["decisions"]
                .as_array()
                .cloned()
                .unwrap()
        };
        let decision_events = |id: &str| {
            let env = store
                .transaction(|tx| tx.self_environment())
                .unwrap()
                .unwrap();
            store
                .transaction(|tx| {
                    tx.events_after(
                        &env,
                        0,
                        &heimdall_contract::event::EventFilter::default(),
                        1000,
                    )
                })
                .unwrap()
                .events
                .into_iter()
                .filter(|e| {
                    e.event_type == heimdall_contract::event::EventType::Decision
                        && e.payload["decision_id"] == id
                })
                .map(|e| e.payload["state"].as_str().unwrap_or_default().to_owned())
                .collect::<Vec<_>>()
        };

        let first = d.handle_as(&attended(), add("req_1")).await;
        assert_eq!(first.code, Code::ApprovalRequired, "{first:?}");
        let reference = first
            .next
            .as_ref()
            .and_then(|n| n.decision_ref.clone())
            .unwrap();
        let shown = listed().await;
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0]["state"], "pending");
        assert_eq!(shown[0]["expired"], false);
        assert!(shown[0].get("reason").is_none());
        assert!(!decision_events(&reference).contains(&"expired".to_owned()));

        clock.advance(
            heimdall_domain::decision::DEFAULT_DECISION_LIFETIME
                + std::time::Duration::from_secs(1),
        );
        let shown = listed().await;
        assert_eq!(shown.len(), 1, "{shown:?}");
        assert_eq!(shown[0]["decision_id"], reference.as_str());
        assert_eq!(shown[0]["state"], "expired", "{shown:?}");
        assert_eq!(shown[0]["expired"], true);
        assert_eq!(
            shown[0]["reason"],
            heimdall_contract::envelope::reason::APPROVAL_LAPSED
        );
        assert_eq!(shown[0]["request"]["origin"], "local");
        let id = heimdall_contract::ids::DecisionId::parse(&reference).unwrap();
        let (record, row) = store
            .transaction(|tx| tx.remote_widening(&id))
            .unwrap()
            .unwrap();
        assert_eq!(
            record.state,
            heimdall_domain::decision::DecisionState::Expired
        );
        let answer = row.result.expect("the lapse's recorded answer");
        assert_eq!(answer["code"], "DECISION_STALE", "{answer}");
        assert_eq!(answer["data"]["error"]["reason"], "approval_lapsed");
        let events = decision_events(&reference);
        assert_eq!(
            events.iter().filter(|s| *s == "expired").count(),
            1,
            "{events:?}"
        );

        // The next read: gone from the list, no second event.
        assert!(listed().await.is_empty());
        assert_eq!(decision_events(&reference), events);
        // Never approved; a resubmission is a new record.
        let late = d
            .handle_as(
                &attended(),
                Request::Decide(DecideRequest {
                    decision_id: id.clone(),
                    verdict: Verdict::Approve,
                }),
            )
            .await;
        assert_eq!(late.code, Code::DecisionStale, "{late:?}");
        assert!(
            store
                .transaction(|tx| tx.destination_routes(&lab))
                .unwrap()
                .is_empty()
        );
        let again = d.handle_as(&attended(), add("req_2")).await;
        assert_eq!(again.code, Code::ApprovalRequired, "{again:?}");
        assert_ne!(
            again.next.as_ref().and_then(|n| n.decision_ref.clone()),
            Some(reference)
        );
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
