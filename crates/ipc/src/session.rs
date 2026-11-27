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
//! * A request that needs a capability beyond `operations/1`
//!   (`Request::required_capabilities`: `Shutdown` needs `service-control/1`) is
//!   answered `SCHEMA_UNSUPPORTED` and never dispatched unless the session
//!   negotiated that capability (ADR-0006 §2.4, §13.6 item 8); so is a `Subscribe`
//!   without `events/1` (⟨M07 W10 S2-08⟩). Authorization comes first (ADR-0006 §19.10):
//!   a capability the session's role or pending invitation cannot hold at all is refused
//!   `CAPABILITY_UNAVAILABLE` with reason `role_insufficient` or `invitation_pending`
//!   instead, never dispatched either. After each
//!   dispatched request's response is written, [`Dispatcher::replied`] runs (the
//!   runtime starts a requested drain there).
//! * ⟨M08 U2b-2; ADR-0014 H13⟩ A request frame's `request_epoch` is accepted only on a
//!   session that negotiated `request-epoch/1`; on any other session the frame is answered
//!   `SCHEMA_UNSUPPORTED` and never dispatched (an epoch is never silently dropped). The
//!   dispatcher gets the frame's epoch with its request ([`Dispatcher::dispatch_request`]),
//!   and a session that negotiated the capability reads the runtime's epoch in its hello
//!   ([`Dispatcher::restore_epoch`], `ServerHello.restore_epoch`).
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
//! session replies `Subscribed { cursor, snapshot, backlog, resync_reason }`, then sends
//! every backlog event (already cursor-personalized by the dispatcher), then live events
//! with `seq > boundary_seq` only, each personalized by the subscription's `cursor_for`
//! at delivery. Overlap between the boundary read and the live receiver is
//! therefore deduplicated here. ⟨rev7; D6, PC6⟩ Without a snapshot, `Subscribed.backlog`
//! is exactly the number of backlog event frames that follow it; with one,
//! `resync_reason` is the dispatcher's reason for not resuming the client's cursor
//! (ADR-0013 §5.3). The backlog itself is bounded by the dispatcher (store retention
//! and paging), not by this module.
//!
//! **Every gap ends the stream** (⟨rev7; PC9⟩ ADR-0013 §5.4). A subscriber that lags its
//! bounded broadcast buffer gets exactly one `ResyncRequired` event (`subscriber_lagged`,
//! with `dropped`), never a buffer without bound. A live `ResyncRequired` above the
//! subscription's boundary is the publisher's trim marker (retention removed events
//! before they were fanned out): the subscriber gets exactly one `ResyncRequired` with
//! the marker's reason (`history_trimmed`). Either carries the subscriber's last
//! delivered cursor and `subscription_ended: true`, and the subscription ends after it:
//! nothing more is sent for it, and `Unsubscribe` of it answers `NOT_FOUND`. A live
//! `ResyncRequired` at or below the boundary (a relay's sequence-0 filler, a trim the
//! subscription's own snapshot or backlog already covers) is overlap and dropped.
//!
//! **Paired sessions** (⟨M06 W2⟩ ADR-0012 §3.6–§3.11; ADR-0006 §18.5 readings 1, 5, 17).
//! The offer is the dispatcher's ([`Dispatcher::offered_capabilities`]: a runner adds
//! `remote-control/1`). A hello naming a `remote_client` passes the precheck (protocol,
//! schema, an offer with `remote-control/1`, else `SCHEMA_UNSUPPORTED`), then the
//! dispatcher resolves the client in the runner's role table and binds the connection to
//! it for the session's lifetime ([`Dispatcher::bind_paired`]; a refusal is the hello's
//! `Reject`); capabilities alone never establish an identity. Negotiation is then
//! [`negotiate_session`]: the role's set, or, for a client pending at the hello, only
//! [`PENDING_CAPABILITIES`]. A paired session is non-interactive whatever its hello said,
//! so `Attend` and attended-only requests are refused here. Its live events pass the
//! dispatcher's per-subscription visibility ([`Dispatcher::live_visibility`]), and when
//! the dispatcher's [`Dispatcher::session_end`] resolves (a revoked client) every
//! subscription receives the terminal event, then `Goodbye`, and the connection closes.
//!
//! **Oversized events** (ADR-0006 §8, §13.4 N03). An event whose frame exceeds the
//! control frame limit is never delivered: `send_event` reports
//! [`Delivery::Replaced`], the subscription's cursor stays at the last event
//! actually delivered, one `ResyncRequired` event carrying that cursor (payload
//! `reason: "event_too_large"`, `subscription_ended: true`) is sent, and the
//! subscription **ends**. Recovery is a fresh snapshot: ⟨rev7; D6⟩ the runtime's
//! dispatcher checks every backlog event's frame in the subscribe transaction, so a
//! resubscription from the carried cursor starts from a whole snapshot with
//! `resync_reason: event_too_large` (ADR-0013 §5.3) instead of meeting the event again.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::{SinkExt, StreamExt};
use heimdall_contract::envelope::{
    EffectStatus, Envelope, ErrorData, ErrorDetail, NextAction, reason,
};
use heimdall_contract::event::{
    Cursor, Event, EventFilter, EventType, MAX_CURSOR_LEN, ResyncReason, Snapshot,
};
use heimdall_contract::ids::{EnvironmentId, EventId, RequestId};
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, EVENT_BUFFER_PER_SUBSCRIPTION, HELLO_TIMEOUT_MS,
    MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, MAX_SUBSCRIPTIONS_PER_CONNECTION, PeerInfo,
    PrincipalInfo, ServerHello, ServerMessage, capability,
};
use heimdall_contract::lifecycle::RestoreEpoch;
use heimdall_contract::remote::Role;
use heimdall_contract::request::{InteractionMode, ObserveRequest, Request};
use heimdall_contract::{Code, PROTOCOL_VERSION, SchemaVersion};
use tokio::sync::broadcast;
use tokio_util::bytes::{Buf, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tokio_util::sync::CancellationToken;

use crate::frame::{FrameError, encode_frame};

/// Capabilities this build serves.
///
/// ⟨M02⟩ m02-plan U0b row 19, phase 2 (the activation change set): `setup/1` is
/// offered, so a session that negotiates it may send Setup and Catalog requests. A
/// session that did not negotiate it is still answered `SCHEMA_UNSUPPORTED` by the
/// gate, without dispatch. A runtime without a projection writer answers every
/// Setup request `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) in the application.
/// `Operations::inspect` lists the same set.
///
/// ⟨M03⟩ m03-plan U0b row 13, phase 2 (wave 4, the activation change set): the four M03
/// capabilities (`capability::M03_DECLARED`: `issuer/1`, `enrollment/1`,
/// `managed-credentials/1`, `connections/1`) are offered. A session that did not
/// negotiate one is still refused `SCHEMA_UNSUPPORTED` by the gate for its requests; a
/// runtime whose M03 ports are not wired answers them `CAPABILITY_UNAVAILABLE`
/// (`driver_unavailable`) before any record is written.
#[must_use]
pub fn server_capabilities() -> BTreeSet<String> {
    [
        capability::OPERATIONS_V1,
        capability::EVENTS_V1,
        capability::OWNER_POLICY_V1,
        capability::SCHEMA_DISCOVERY_V1,
        capability::SERVICE_CONTROL_V1,
        capability::SETUP_V1,
        // ⟨M04⟩ Revision 5's environment forms: U1's login entry setup item (a setup preview
        // naming an M04 item requires it), U3b's WSL requests, U5's container requests and
        // U6's destination upsert naming a jump.
        capability::ENVIRONMENTS_V1,
    ]
    .into_iter()
    .chain(capability::M03_DECLARED)
    // ⟨M05⟩ W3 (ADR-0006 §17.8; m05-plan §4 item 10): every trusted-work form is served.
    .chain([capability::TRUSTED_WORK_V1])
    // ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.1): `inspect`'s `select` and `page` are served.
    .chain([capability::PAGES_V1])
    .map(str::to_owned)
    .collect()
}

/// ⟨M08 U2b-2; ADR-0014 H13⟩ What this build's client offers in its hello
/// ([`ControlClient::handshake`]): [`server_capabilities`] and `request-epoch/1`, which only a
/// runtime that checks the epoch offers (it is not in [`server_capabilities`], the default
/// offer of a [`Dispatcher`]). Offered, never required: a runtime that does not offer it is
/// still served, without an epoch on any frame.
#[must_use]
pub fn client_capabilities() -> BTreeSet<String> {
    let mut offer = server_capabilities();
    offer.insert(capability::REQUEST_EPOCH_V1.to_owned());
    offer
}

/// ⟨M08 U2b-2; ADR-0014 §3.6 step 3; the ruling on ASK-H13b⟩ What a request frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochChoice {
    /// Send the frame with this `request_epoch` (none: the field is omitted).
    Send(Option<RestoreEpoch>),
    /// Send nothing: the caller holds a kept epoch, and the session did not negotiate
    /// `request-epoch/1`, so the runtime could not check it.
    Refuse,
}

/// ⟨M08 U2b-2; ADR-0014 §3.6 step 3; the ruling on ASK-H13b⟩ The epoch a request frame carries
/// on a session whose server hello is `hello`. A read carries none. A mutating request
/// ([`Request::is_effectful`]) carries `kept` (the epoch kept with a request ID for a retry)
/// where the session negotiated `request-epoch/1`, and is refused, unsent, where it did not.
/// With no kept epoch it carries the hello's epoch where negotiated (bound at send), and
/// none otherwise (a fresh request is sent without one).
#[must_use]
pub fn choose_request_epoch(
    hello: &ServerHello,
    request: &Request,
    kept: Option<RestoreEpoch>,
) -> EpochChoice {
    if !request.is_effectful() {
        return EpochChoice::Send(None);
    }
    let negotiated = hello.capabilities.contains(capability::REQUEST_EPOCH_V1);
    match (kept, negotiated) {
        (Some(kept), true) => EpochChoice::Send(Some(kept)),
        (Some(_), false) => EpochChoice::Refuse,
        (None, true) => EpochChoice::Send(Some(hello.restore_epoch())),
        (None, false) => EpochChoice::Send(None),
    }
}

/// ⟨M08 U2b-2⟩ The answer to a kept epoch that cannot be sent ([`EpochChoice::Refuse`]):
/// `SCHEMA_UNSUPPORTED`, effect `none`, nothing sent.
#[must_use]
pub fn kept_epoch_unsupported() -> Envelope<serde_json::Value> {
    to_value_envelope(error_envelope(
        Code::SchemaUnsupported,
        EffectStatus::None,
        "this request keeps the restore epoch it was first sent with, and the runtime does not \
         offer request-epoch/1, so it could not check it: nothing was sent",
    ))
}

/// Negotiate a client hello. Pure: the transport has already authenticated the
/// peer and supplies `principal`.
///
/// The negotiated set is the server offer ∩ the client's `capabilities`; every
/// `required` capability must be in it (ADR-0006 §2.3 rev2, review F10), else
/// `SCHEMA_UNSUPPORTED`. Rejection messages never quote client-supplied strings.
///
/// This is the local same-user session: the owner (ADR-0006 §2.1), whose role is not
/// reported, so the server hello is byte-identical to revision 5's
/// ([`negotiate_for_role`] with no role).
pub fn negotiate(
    hello: &ClientHello,
    principal: PrincipalInfo,
    environment: EnvironmentId,
    server: PeerInfo,
) -> Result<ServerHello, Box<Envelope<ErrorData>>> {
    negotiate_for_role(hello, principal, None, environment, server)
}

/// ⟨rev6⟩ Negotiate a hello for a caller in `role` (ADR-0012 §6.2, §9 item 4; ADR-0006
/// §18): `required ⊆ offer ∩ server ∩ role`.
///
/// * A protocol or schema-major mismatch, a `required` capability outside `offer ∩
///   server`, and a hello naming a `remote_client` to a runtime that does not offer
///   `remote-control/1` are `SCHEMA_UNSUPPORTED`.
/// * A `required` capability the role lacks is `CAPABILITY_UNAVAILABLE` with reason
///   `role_insufficient`.
/// * Optional capabilities are in effect only inside the intersection with the role's
///   set ([`capability::for_role`]).
///
/// `role: None` is the local same-user caller: the owner, not reported in the server hello.
/// `Some` is reported (`ServerHello.role`). A role never comes from the hello itself.
///
/// The server offer is this build's ([`server_capabilities`]); a runner's session, whose
/// offer adds `remote-control/1`, negotiates with [`negotiate_session`].
pub fn negotiate_for_role(
    hello: &ClientHello,
    principal: PrincipalInfo,
    role: Option<Role>,
    environment: EnvironmentId,
    server: PeerInfo,
) -> Result<ServerHello, Box<Envelope<ErrorData>>> {
    let paired = role.map(|role| PairedBinding {
        role,
        pending: false,
    });
    negotiate_session(
        hello,
        principal,
        &server_capabilities(),
        paired,
        environment,
        server,
    )
}

/// ⟨M06 W2⟩ The capabilities a **pending** client's session may negotiate, whatever its
/// role (ADR-0012 §3.9 item 3; M06-W0-R06, ADR-0006 §18.5 reading 5): only the capability
/// that carries the activation probe and `join`. A limited role's ordinary negotiation never
/// includes it, so this does not open `join`'s capability to every limited session.
pub const PENDING_CAPABILITIES: [&str; 1] = [capability::REMOTE_CONTROL_V1];

/// ⟨M06 W2⟩ A paired client's binding for one session (ADR-0012 §3.6, §3.7), as the runner
/// resolved it from its role table ([`Dispatcher::bind_paired`]); never read from the hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairedBinding {
    /// The client's role, from the role table.
    pub role: Role,
    /// Whether the client was pending at the hello: the session then negotiates the
    /// pending-only set ([`PENDING_CAPABILITIES`]) and, for its whole lifetime, is served
    /// only the activation probe and `join`.
    pub pending: bool,
}

/// The precheck every hello passes before its paired client is resolved: the protocol, the
/// schema major, and a paired client only to a runtime that offers `remote-control/1`.
fn hello_precheck(
    hello: &ClientHello,
    offered: &BTreeSet<String>,
) -> Result<(), Box<Envelope<ErrorData>>> {
    if hello.protocol != PROTOCOL_VERSION {
        return Err(hello_reject(
            Code::SchemaUnsupported,
            "unsupported IPC protocol version",
            None,
        ));
    }
    if !hello.schema_version.is_supported() {
        return Err(hello_reject(
            Code::SchemaUnsupported,
            "unsupported schema major version",
            None,
        ));
    }
    // ⟨rev6⟩ A paired client is declared only by a runner's bridge, to a runtime that
    // serves paired clients (ADR-0012 §3.6). Any other runtime refuses the hello.
    if hello.remote_client.is_some() && !offered.contains(capability::REMOTE_CONTROL_V1) {
        return Err(hello_reject(
            Code::SchemaUnsupported,
            "this runtime does not accept a paired client",
            None,
        ));
    }
    Ok(())
}

fn hello_reject(code: Code, message: &str, reason: Option<&str>) -> Box<Envelope<ErrorData>> {
    Box::new(Envelope::failed(
        None,
        ErrorDetail {
            code: code.clone(),
            effect_status: EffectStatus::None,
            retryable: false,
            resource: None,
            next: NextAction::for_code(code),
            message: message.to_owned(),
            reason: reason.map(str::to_owned),
            entries: Vec::new(),
            field: None,
            bound: None,
            unit: None,
            section: None,
            narrow: None,
        },
    ))
}

/// ⟨M06 W2⟩ Negotiate a hello against an explicit server offer (`offered`: the runtime's
/// [`Dispatcher::offered_capabilities`]) for an explicit caller: `paired: None` is the
/// local same-user owner, `Some` a paired client the runner resolved
/// ([`Dispatcher::bind_paired`]). The rules are [`negotiate_for_role`]'s; a pending client's
/// role set is [`PENDING_CAPABILITIES`], and a `required` capability outside it is
/// `CAPABILITY_UNAVAILABLE` with reason `invitation_pending` (ADR-0012 §3.9 item 3).
/// A hello naming a `remote_client` with no binding is refused (`SCHEMA_UNSUPPORTED`):
/// a client is never accepted unresolved.
pub fn negotiate_session(
    hello: &ClientHello,
    principal: PrincipalInfo,
    offered: &BTreeSet<String>,
    paired: Option<PairedBinding>,
    environment: EnvironmentId,
    server: PeerInfo,
) -> Result<ServerHello, Box<Envelope<ErrorData>>> {
    hello_precheck(hello, offered)?;
    if hello.remote_client.is_some() && paired.is_none() {
        return Err(hello_reject(
            Code::SchemaUnsupported,
            "this runtime does not accept a paired client",
            None,
        ));
    }
    let capabilities: BTreeSet<String> =
        offered.intersection(&hello.capabilities).cloned().collect();
    if !hello.required.is_subset(&capabilities) {
        let message = if hello.required.is_subset(offered) {
            "a required capability is missing from the client's own capabilities"
        } else {
            "a required capability is not available"
        };
        return Err(hello_reject(Code::SchemaUnsupported, message, None));
    }
    let pending = paired.is_some_and(|p| p.pending);
    let allowed: BTreeSet<&str> = if pending {
        PENDING_CAPABILITIES.iter().copied().collect()
    } else {
        capability::for_role(paired.map_or(Role::Owner, |p| p.role))
            .iter()
            .copied()
            .collect()
    };
    if !hello.required.iter().all(|c| allowed.contains(c.as_str())) {
        let (message, why) = if pending {
            (
                "the client's invitation is pending: only the activation probe and join are available",
                reason::INVITATION_PENDING,
            )
        } else {
            (
                "a required capability is not available to this role",
                reason::ROLE_INSUFFICIENT,
            )
        };
        return Err(hello_reject(
            Code::CapabilityUnavailable,
            message,
            Some(why),
        ));
    }
    let capabilities = capabilities
        .into_iter()
        .filter(|c| allowed.contains(c.as_str()))
        .collect();
    Ok(ServerHello {
        protocol: PROTOCOL_VERSION,
        schema_version: SchemaVersion::current(),
        server,
        capabilities,
        principal,
        environment_id: environment,
        role: paired.map(|p| p.role),
        // ⟨rev6.2⟩ The resolved paired client, reported back (None for the local owner).
        remote_client: paired.and(hello.remote_client.clone()),
        // ⟨M08 U2b-2⟩ Set by the serving session from its dispatcher
        // ([`Dispatcher::restore_epoch`]) when `request-epoch/1` was negotiated.
        restore_epoch: None,
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

/// ⟨M06-W0-R03⟩ Whether one subscription's reader may see a live event (the same shape as
/// `heimdall_app::events::LiveVisibility`): supplied per subscription by
/// [`Dispatcher::live_visibility`].
pub type LiveVisibility = Arc<dyn Fn(&Event) -> bool + Send + Sync>;

/// ⟨M06 W2⟩ Why a session must end now ([`Dispatcher::session_end`]): a revoked client's
/// sessions and subscriptions close at once (ADR-0012 §3.7, §3.11).
#[derive(Debug, Clone, PartialEq)]
pub struct SessionEnd {
    /// The terminal event every live subscription receives before the goodbye (the
    /// `client.revoked` event); its `cursor` is replaced by each subscription's last
    /// delivered position.
    pub event: Event,
    /// The goodbye's code.
    pub code: Code,
    /// The goodbye's message (fixed text, never request content).
    pub message: String,
}

/// ⟨M06 W2⟩ Resolves when the session must end ([`Dispatcher::session_end`]).
pub type SessionEndFuture = Pin<Box<dyn Future<Output = SessionEnd> + Send>>;

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
    /// ⟨rev7; D6, PC6⟩ With `snapshot`, why the client's cursor was not resumed
    /// (`Subscribed.resync_reason`, ADR-0013 §5.3); `None` otherwise.
    pub resync_reason: Option<ResyncReason>,
    /// Retained events after the client's cursor up to the boundary, in order and
    /// already cursor-personalized for this reader: the visible ones, each fitting one
    /// frame. The ones matching the filter are `Subscribed.backlog`'s count.
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
            reason: None,
            entries: Vec::new(),
            field: None,
            bound: None,
            unit: None,
            section: None,
            narrow: None,
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

/// ⟨rev 6.3; ADR-0006 §18.7 items 9 and 15⟩ The answer to a paired session's attended-only
/// frame: `INTERACTION_REQUIRED` with reason `local_owner_required`, effect `none`.
fn local_owner_required(seq: u64) -> ServerMessage {
    let mut env = error_envelope(
        Code::InteractionRequired,
        EffectStatus::None,
        "this request is decided by the owner at the runner, never by a paired session",
    );
    env.data.error.reason =
        Some(heimdall_contract::envelope::reason::LOCAL_OWNER_REQUIRED.to_owned());
    ServerMessage::Response {
        in_reply_to: seq,
        envelope: to_value_envelope(env),
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
/// was delivered (before the gap): resuming from it never skips the gap. ⟨rev7; PC9⟩ The
/// lag ends the subscription.
fn resync_event(environment: &EnvironmentId, cursor: &Cursor, dropped: u64) -> Event {
    resync_event_with(
        environment,
        cursor,
        serde_json::json!({
            "reason": ResyncReason::SubscriberLagged.as_str(),
            "dropped": dropped,
            "subscription_ended": true,
        }),
    )
}

/// ⟨rev7; PC6, PC9⟩ The `ResyncRequired` event for a live gap marker above the
/// subscription's boundary (the publisher's trim marker): the marker's reason
/// (`history_trimmed`) at the subscriber's last delivered cursor, with its own event ID
/// and `subscription_ended: true`. The subscription ends after it.
fn gap_event(environment: &EnvironmentId, cursor: &Cursor, marker: &Event) -> Event {
    let reason = marker
        .payload
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(ResyncReason::HistoryTrimmed.as_str());
    resync_event_with(
        environment,
        cursor,
        serde_json::json!({ "reason": reason, "subscription_ended": true }),
    )
}

/// The `ResyncRequired` event sent in place of an oversized event; the
/// subscription ends after it (N03).
fn oversized_resync_event(environment: &EnvironmentId, cursor: &Cursor) -> Event {
    resync_event_with(
        environment,
        cursor,
        serde_json::json!({
            "reason": ResyncReason::EventTooLarge.as_str(),
            "subscription_ended": true,
        }),
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

/// ⟨M06-W0-R10⟩ Whether a filter selects an event type whose producing capability the
/// session did not negotiate (`EventType::required_capability`): refused
/// `SCHEMA_UNSUPPORTED` at subscribe and `observe`, never an accepted subscription that
/// silently filters everything out.
fn selects_unnegotiated(filter: &EventFilter, negotiated: &BTreeSet<String>) -> bool {
    filter
        .required_capabilities()
        .any(|c| !negotiated.contains(c))
}

/// ⟨M07 W10 S2-08; ADR-0006 §2.4, §19.10⟩ The answer to a request or subscription that needs
/// a capability (`needed`) the session did not negotiate, or `None` when it negotiated every
/// one. Authorization comes before capability, as at the hello ([`negotiate_session`]): when
/// the session's role ([`capability::for_role`]; the local owner holds every capability) or
/// its pending invitation ([`PENDING_CAPABILITIES`]) cannot hold a missing capability at all,
/// the answer is ADR-0012's refusal, as the dispatcher's role check words it:
/// `CAPABILITY_UNAVAILABLE` with reason `role_insufficient` (§3.8, T-RA4) or
/// `invitation_pending` (§3.9 item 3). Only a capability the role holds and the session did
/// not negotiate is `SCHEMA_UNSUPPORTED`. Either way, effect `none` and never dispatched.
///
/// `stamp` is what the dispatcher's request fence reports on every answer to a mutating
/// request, its role refusals included (`heimdall_runtime::request_fence::RequestFence::
/// binding`): the request ID, and the frame's epoch or else the runtime's. The role refusal
/// carries it as the dispatcher's does.
fn unnegotiated(
    seq: u64,
    needed: impl Iterator<Item = &'static str>,
    negotiated: &BTreeSet<String>,
    paired: Option<PairedBinding>,
    stamp: Option<(Option<RequestId>, RestoreEpoch)>,
) -> Option<ServerMessage> {
    let missing: Vec<&str> = needed.filter(|c| !negotiated.contains(*c)).collect();
    if missing.is_empty() {
        return None;
    }
    let pending = paired.is_some_and(|p| p.pending);
    let allowed: &[&str] = if pending {
        &PENDING_CAPABILITIES
    } else {
        capability::for_role(paired.map_or(Role::Owner, |p| p.role))
    };
    if missing.iter().all(|c| allowed.contains(c)) {
        return Some(response(
            seq,
            Code::SchemaUnsupported,
            "this request needs a capability the session did not negotiate",
        ));
    }
    // The wording of `heimdall_remote::roles::Refusal`, which the dispatcher answers.
    let (message, why) = if pending {
        (
            "the client's invitation is pending: only the activation probe and join are accepted",
            reason::INVITATION_PENDING,
        )
    } else {
        (
            "the client's role does not permit this request",
            reason::ROLE_INSUFFICIENT,
        )
    };
    let mut env = error_envelope(Code::CapabilityUnavailable, EffectStatus::None, message);
    env.data.error.reason = Some(why.to_owned());
    env.next = Some(env.data.error.next.clone());
    if let Some((request_id, epoch)) = stamp {
        env.request_id = request_id;
        env.request_epoch = Some(epoch);
    }
    Some(ServerMessage::Response {
        in_reply_to: seq,
        envelope: to_value_envelope(env),
    })
}

/// The request fence's stamp for `request` ([`unnegotiated`]): for a mutating request on a
/// dispatcher that checks the epoch ([`Dispatcher::restore_epoch`]), its request ID and the
/// frame's epoch, or else the runtime's.
fn fence_stamp<D: Dispatcher + ?Sized>(
    request: &Request,
    frame_epoch: Option<RestoreEpoch>,
    dispatcher: &D,
) -> Option<(Option<RequestId>, RestoreEpoch)> {
    if !request.is_effectful() {
        return None;
    }
    let fenced = dispatcher.restore_epoch()?;
    Some((request.request_id().cloned(), frame_epoch.unwrap_or(fenced)))
}

const UNNEGOTIATED_SELECTOR: &str =
    "an event type in the filter needs a capability the session did not negotiate";

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
        kind: &'static str,
        envelope: Envelope<serde_json::Value>,
    },
    Subscribed {
        seq: u64,
        filter: EventFilter,
        from: Option<Cursor>,
        result: Result<SubscriptionStart, Box<Envelope<ErrorData>>>,
        visible: Option<LiveVisibility>,
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
    /// ⟨M06-W0-R03⟩ The reader's live-event visibility (`None`: every event).
    visible: Option<LiveVisibility>,
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
        // ⟨M06 W2⟩ The runtime's offer, and the paired client a runner's bridge declared:
        // resolved by the dispatcher (the runner's role table) after the precheck, never
        // taken from the hello or its capabilities (ADR-0006 §18.5 reading 1). The binding
        // holds for the session's whole lifetime (ADR-0012 §3.6).
        let mut dispatcher = dispatcher;
        let offered = dispatcher.offered_capabilities();
        // A session that negotiates with a `remote_client` is bound to it (else refused).
        let paired_session = hello.remote_client.is_some();
        let paired = match &hello.remote_client {
            None => Ok(None),
            Some(_) => hello_precheck(&hello, &offered)
                .and_then(|()| dispatcher.bind_paired(&hello).map(Some)),
        };
        let negotiation = paired.and_then(|paired| {
            negotiate_session(
                &hello,
                principal.clone(),
                &offered,
                paired,
                environment.clone(),
                server,
            )
            .map(|h| (h, paired))
        });
        let (negotiated, paired) = match negotiation {
            Ok((mut server_hello, paired)) => {
                // ⟨M08 U2b-2; ADR-0014 §3.6 step 1⟩ A session that negotiated
                // `request-epoch/1` reads the runtime's current epoch in its hello.
                if server_hello
                    .capabilities
                    .contains(capability::REQUEST_EPOCH_V1)
                {
                    server_hello.restore_epoch = dispatcher.restore_epoch();
                }
                let negotiated = server_hello.capabilities.clone();
                write_frame(
                    &mut wire,
                    &ServerMessage::Hello(server_hello),
                    MAX_HELLO_FRAME_BYTES,
                )
                .await?;
                (negotiated, paired)
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
        };
        wire.codec_mut().max = MAX_CONTROL_FRAME_BYTES;

        // ---- request / subscription loop ---------------------------------
        // ⟨M06 W2⟩ A paired session is never attended (ADR-0012 §3.10 item 1): whatever its
        // hello declared, it is non-interactive, so `Attend` is refused and an attended-only
        // request never reaches the dispatcher.
        let mut session = SessionInfo {
            principal,
            interaction: if paired.is_some() {
                InteractionMode::NonInteractive
            } else {
                hello.interaction
            },
            attended: false,
        };
        let dispatcher = &dispatcher;
        // ⟨M06 W2⟩ When the dispatcher says this session must end (a revoked client,
        // ADR-0012 §3.7, §3.11): every subscription gets the terminal event, then the
        // goodbye, and the connection closes.
        let mut session_end: Pin<Box<dyn Future<Output = SessionEnd> + Send>> = dispatcher
            .session_end()
            .unwrap_or_else(|| Box::pin(std::future::pending()));
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
                end = &mut session_end => {
                    break end_session(&mut wire, &environment, &subs, end).await;
                }
                Some(done) = inflight.next(), if !inflight.is_empty() => {
                    match done {
                        Done::Response { seq, kind, envelope } => {
                            let code = envelope.code.clone();
                            let msg = ServerMessage::Response { in_reply_to: seq, envelope };
                            let sent = send_or_internal(&mut wire, msg).await;
                            // After the reply was written (or could not be): the
                            // runtime starts a requested drain only now, so the
                            // requester reads its answer before any goodbye.
                            dispatcher.replied(&session, kind, &code);
                            if let Err(e) = sent {
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
                        Done::Subscribed { seq, filter, from, result: Ok(start), visible } => {
                            pending_subscribes -= 1;
                            let id = next_sub_id;
                            next_sub_id += 1;
                            let stop = shutdown.child_token();
                            match start_subscription(&mut wire, &environment, seq, id, filter, from, start, visible, stop).await {
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
                    // ⟨rev7; PC9⟩ Whether the frame is a gap's `ResyncRequired`, after which
                    // the subscription ends (ADR-0013 §5.4).
                    let mut gap = false;
                    let msg = match result {
                        // Covered by the snapshot/backlog: overlap, not sent.
                        Ok(live) if live.seq <= state.boundary_seq => None,
                        // ⟨rev7; PC6⟩ A trim marker: retention removed events this
                        // subscriber had not received. Never filtered: the gap may hold
                        // any event the filter admits.
                        Ok(live) if live.event.event_type == EventType::ResyncRequired => {
                            gap = true;
                            Some((
                                ServerMessage::Event {
                                    subscription: id,
                                    event: gap_event(&environment, &state.last_cursor, &live.event),
                                },
                                state.last_cursor.clone(),
                                None,
                            ))
                        }
                        Ok(live) => {
                            let mut event = live.event.clone();
                            event.cursor = (state.cursor_for)(live.seq);
                            let visible = state.visible.as_ref().is_none_or(|v| v(&event));
                            if visible && filter_matches(&state.filter, &event) {
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
                            gap = true;
                            let mut dropped = n;
                            // The retained backlog is never delivered either: counted as
                            // dropped; bounded by the channel capacity.
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
                        // ⟨rev7; PC9⟩ The gap's resync went out: the subscription ends, and
                        // nothing more is sent for it.
                        Ok(Delivery::Delivered) if gap => {
                            if let Some(state) = subs.remove(&id) {
                                state.stop.cancel();
                            }
                        }
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
                        ClientMessage::Request { seq, request, request_epoch } => {
                            if request_epoch.is_some() && !negotiated.contains(capability::REQUEST_EPOCH_V1) {
                                // ⟨M08 U2b-2; ADR-0014 H13⟩ An epoch on a session that did not
                                // negotiate it is never dropped silently: refused, not dispatched.
                                Some(response(seq, Code::SchemaUnsupported, "this request carries a restore epoch, which the session did not negotiate (request-epoch/1)"))
                            } else if let Some(refused) = unnegotiated(seq, request.required_capabilities(), &negotiated, paired, fence_stamp(&request, request_epoch, dispatcher)) {
                                // ADR-0006 §2.4, §13.6 item 8: a request outside the
                                // negotiated capabilities is never dispatched. ⟨M07 W10
                                // S2-08; §19.10⟩ Refused by role first.
                                Some(refused)
                            } else if let Request::Observe(ObserveRequest::Events { filter, .. }) = &request
                                && selects_unnegotiated(filter, &negotiated)
                            {
                                // ⟨M06-W0-R10⟩ Never dispatched either.
                                Some(response(seq, Code::SchemaUnsupported, UNNEGOTIATED_SELECTOR))
                            } else if paired_session && request.requires_attended_session() {
                                // ⟨rev 6.3; ADR-0006 §18.7 items 9 and 15⟩ A paired session's
                                // attended-only form (`decide`, `confirm_time`, issuer unlock)
                                // has no remote path: never dispatched, and it names its reason
                                // so a wrapper does not ask the user and retry.
                                Some(local_owner_required(seq))
                            } else if request.requires_attended_session() && !session.attended {
                                // Defence in depth: never dispatched (ADR-0006 §2.3).
                                Some(response(seq, Code::InteractionRequired, "this request requires an attended interactive session"))
                            } else if inflight.len() >= limits.max_inflight {
                                Some(response(seq, Code::Backpressure, "too many requests in flight on this connection"))
                            } else {
                                let session = session.clone();
                                let kind = request.kind();
                                inflight.push(Box::pin(async move {
                                    let envelope = dispatcher.dispatch_request(&session, request, request_epoch).await;
                                    Done::Response { seq, kind, envelope }
                                }));
                                None
                            }
                        }
                        ClientMessage::Attend { seq } => {
                            if paired_session {
                                // ⟨rev 6.3; ADR-0006 §18.7 item 15⟩ Never attended, whatever
                                // its hello declared: the same reason.
                                Some(local_owner_required(seq))
                            } else if session.interaction == InteractionMode::Interactive {
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
                            if let Some(refused) = unnegotiated(seq, [capability::EVENTS_V1].into_iter(), &negotiated, paired, None) {
                                // ⟨M07 W10 S2-08; ADR-0006 §2.4⟩ Subscriptions are `events/1`'s:
                                // without it the subscribe is refused (by role first), never served.
                                Some(refused)
                            } else if from_cursor.as_ref().is_some_and(|c| c.0.len() > MAX_CURSOR_LEN) {
                                Some(response(seq, Code::UsageError, "cursor exceeds the maximum length"))
                            } else if selects_unnegotiated(&filter, &negotiated) {
                                // ⟨M06-W0-R10⟩
                                Some(response(seq, Code::SchemaUnsupported, UNNEGOTIATED_SELECTOR))
                            } else if subs.len() + pending_subscribes >= limits.max_subscriptions {
                                Some(response(seq, Code::Backpressure, "too many subscriptions on this connection"))
                            } else if inflight.len() >= limits.max_inflight {
                                Some(response(seq, Code::Backpressure, "too many requests in flight on this connection"))
                            } else {
                                pending_subscribes += 1;
                                let session = session.clone();
                                inflight.push(Box::pin(async move {
                                    let result = dispatcher.subscribe(&session, filter.clone(), from_cursor.clone()).await;
                                    let visible = dispatcher.live_visibility(&session);
                                    Done::Subscribed { seq, filter, from: from_cursor, result, visible }
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
    visible: Option<LiveVisibility>,
    stop: CancellationToken,
) -> Result<Option<(SubState, broadcast::Receiver<Arc<LiveEvent>>)>, FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let SubscriptionStart {
        cursor,
        boundary_seq,
        snapshot,
        resync_reason,
        backlog,
        live,
        cursor_for,
    } = start;
    // ⟨rev7; D6, PC6⟩ Exactly the backlog frames that follow (ADR-0013 §5.3): the filter's
    // events, counted before `Subscribed` goes out. A backlog start only; a snapshot start
    // carries the reason it was not one.
    let sent = backlog
        .iter()
        .filter(|e| filter_matches(&filter, e))
        .count();
    let (backlog_count, resync_reason) = if snapshot.is_some() {
        (None, resync_reason)
    } else {
        (Some(u32::try_from(sent).unwrap_or(u32::MAX)), None)
    };
    let reply = ServerMessage::Subscribed {
        in_reply_to: seq,
        subscription: id,
        cursor: cursor.clone(),
        snapshot,
        backlog: backlog_count,
        resync_reason,
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
                // it; the subscription ends here (no live state is returned). The
                // dispatcher checks each backlog event's frame before it counts it, so
                // this is a defence only.
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
            visible,
            stop,
        },
        live,
    )))
}

/// ⟨M06 W2⟩ End the session ([`SessionEnd`]): the terminal event to every live
/// subscription, at its last delivered position, then the goodbye. Every subscription ends.
async fn end_session<S>(
    wire: &mut Wire<S>,
    environment: &EnvironmentId,
    subs: &HashMap<u64, SubState>,
    end: SessionEnd,
) -> Result<(), FrameError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut ids: Vec<u64> = subs.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        let Some(state) = subs.get(&id) else { continue };
        let mut event = end.event.clone();
        event.cursor = state.last_cursor.clone();
        let msg = ServerMessage::Event {
            subscription: id,
            event,
        };
        send_event(wire, msg, environment, &state.last_cursor).await?;
    }
    let _ = write_frame(
        wire,
        &goodbye(end.code, &end.message),
        MAX_CONTROL_FRAME_BYTES,
    )
    .await;
    Ok(())
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

    /// ⟨M08 U2b-2; ADR-0014 H13⟩ Handle one request with the restore epoch its frame carried
    /// (`None`: the frame carried none). A frame reaches this with an epoch only on a session
    /// that negotiated `request-epoch/1`, which only a dispatcher that checks the epoch
    /// offers ([`Self::offered_capabilities`]); such a dispatcher overrides this. Default:
    /// [`Self::dispatch`], for a dispatcher that offers no `request-epoch/1` and so never
    /// gets an epoch.
    async fn dispatch_request(
        &self,
        session: &SessionInfo,
        request: Request,
        request_epoch: Option<RestoreEpoch>,
    ) -> Envelope<serde_json::Value> {
        let _ = request_epoch;
        self.dispatch(session, request).await
    }

    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 1⟩ The runtime's current restore epoch, reported in the
    /// hello of a session that negotiated `request-epoch/1`. Default: `None` (a dispatcher
    /// that does not check the epoch).
    fn restore_epoch(&self) -> Option<RestoreEpoch> {
        None
    }

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

    /// ⟨M06-W0-R03⟩ The reader-scoped visibility of live events for a subscription of
    /// `session`, asked once when the subscription starts (the backlog and snapshot are
    /// already scoped by [`Self::subscribe`]). `None` delivers every live event, which is
    /// correct only for a session whose caller is the local owner (ADR-0006 §18.2 item
    /// 17): a dispatcher that serves any other caller (a paired client, M06 W2) must
    /// return the caller's visibility (`heimdall_app::events::EventPublisher::
    /// live_visibility`). Default: `None`.
    fn live_visibility(&self, session: &SessionInfo) -> Option<LiveVisibility> {
        let _ = session;
        None
    }

    /// ⟨M06 W2⟩ The capabilities this dispatcher's runtime offers in the hello. Default:
    /// this build's ([`server_capabilities`]), which has no `remote-control/1`, so a hello
    /// naming a paired client is refused (`SCHEMA_UNSUPPORTED`). A runner runtime adds
    /// `remote-control/1` (ADR-0012 §6.3).
    fn offered_capabilities(&self) -> BTreeSet<String> {
        server_capabilities()
    }

    /// ⟨M06 W2⟩ Resolve the paired client a hello names (`hello.remote_client`, which only a
    /// runner's bridge originates; ADR-0012 §3.6; ADR-0006 §18.5 reading 1), once, at the
    /// hello, before negotiation, and bind this connection's
    /// dispatcher to it for the session's whole lifetime. Called only for a hello that
    /// passed the precheck (protocol, schema, and an offer with `remote-control/1`). The
    /// role comes from the runner's role table, never from the hello. An error envelope is
    /// sent as the hello's `Reject`. Default: refused (`SCHEMA_UNSUPPORTED`), so a
    /// dispatcher that does not resolve clients never serves one.
    ///
    /// # Errors
    ///
    /// The refusal envelope (an unknown, revoked or unresolvable client).
    fn bind_paired(
        &mut self,
        hello: &ClientHello,
    ) -> Result<PairedBinding, Box<Envelope<ErrorData>>> {
        let _ = hello;
        Err(hello_reject(
            Code::SchemaUnsupported,
            "this runtime does not accept a paired client",
            None,
        ))
    }

    /// ⟨M06 W2⟩ A future that resolves when this session must end ([`SessionEnd`]: a
    /// revoked client), asked once after the hello. Default: `None` (never).
    fn session_end(&self) -> Option<SessionEndFuture> {
        None
    }

    /// Called once per dispatched request, **after** its response frame was
    /// written to the peer (or the write failed), with the request's kind and the
    /// response code. The runtime starts a requested graceful drain here
    /// (`Shutdown`, ADR-0006 §13.6 item 8), so the requester reads its `OK` before
    /// the session's `Goodbye`. Must not block. Default: nothing.
    fn replied(&self, session: &SessionInfo, request_kind: &'static str, code: &Code) {
        let _ = (session, request_kind, code);
    }
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
        /// ⟨rev7; D6⟩ Without a snapshot: exactly how many backlog events follow
        /// before live events (`Subscribed.backlog`).
        backlog: Option<u32>,
        /// ⟨rev7; D6⟩ With a snapshot started although a cursor was sent: why
        /// (`Subscribed.resync_reason`).
        resync_reason: Option<ResyncReason>,
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
    /// ⟨M08 U2b-2⟩ The epoch kept with a request ID for a retry ([`Self::keep_epoch`]).
    kept_epoch: Option<RestoreEpoch>,
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
        // ⟨M08 U2b-2⟩ `request-epoch/1` is offered, never required (ASK-H13b).
        let mut capabilities = client_capabilities();
        capabilities.extend(required.iter().cloned());
        let hello = ClientMessage::Hello(ClientHello {
            protocol: PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            client,
            capabilities,
            required: required.clone(),
            interaction,
            remote_client: None,
        });
        write_frame(&mut wire, &hello, MAX_HELLO_FRAME_BYTES).await?;
        Self::finish_handshake(wire, &required).await
    }

    async fn finish_handshake(
        mut wire: Wire<S>,
        required: &BTreeSet<String>,
    ) -> Result<Self, crate::frame::FrameError> {
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
                    kept_epoch: None,
                })
            }
            ServerMessage::Reject(env) => Err(refused(ServerRefusal::Rejected(Box::new(env)))),
            ServerMessage::Goodbye { code, message } => {
                Err(refused(ServerRefusal::Goodbye { code, message }))
            }
            _ => Err(invalid("unexpected first server frame")),
        }
    }

    /// ⟨M06 W2⟩ [`Self::handshake`] with an explicit hello, sent as given (the bridge's
    /// local hello names its paired client; tests drive a runner's paired sessions with it).
    /// The `required` capabilities must be in the server hello.
    pub async fn handshake_hello(
        stream: S,
        hello: ClientHello,
    ) -> Result<Self, crate::frame::FrameError> {
        let required = hello.required.clone();
        let mut wire = Framed::new(stream, BoundedFrameCodec::new(MAX_HELLO_FRAME_BYTES));
        write_frame(
            &mut wire,
            &ClientMessage::Hello(hello),
            MAX_HELLO_FRAME_BYTES,
        )
        .await?;
        Self::finish_handshake(wire, &required).await
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
    ///
    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 3⟩ A mutating request carries the restore epoch
    /// [`choose_request_epoch`] picks: the kept one ([`Self::keep_epoch`]) or the hello's,
    /// where the session negotiated `request-epoch/1`. A kept epoch the session cannot carry
    /// is answered here, with nothing sent: `Ok` with [`kept_epoch_unsupported`]
    /// (`SCHEMA_UNSUPPORTED`, effect `none`).
    pub async fn request(
        &mut self,
        request: Request,
    ) -> Result<Envelope<serde_json::Value>, crate::frame::FrameError> {
        match choose_request_epoch(&self.hello, &request, self.kept_epoch) {
            EpochChoice::Send(request_epoch) => {
                self.request_with_epoch(request, request_epoch).await
            }
            EpochChoice::Refuse => Ok(kept_epoch_unsupported()),
        }
    }

    /// ⟨M08 U2b-2⟩ Send one request with exactly this frame epoch (none: omitted), whatever
    /// the session negotiated, and await its response. [`Self::request`] chooses the epoch;
    /// this is for callers that already chose it, and for tests of the runtime's checks.
    pub async fn request_with_epoch(
        &mut self,
        request: Request,
        request_epoch: Option<RestoreEpoch>,
    ) -> Result<Envelope<serde_json::Value>, crate::frame::FrameError> {
        let seq = self.take_seq();
        self.send(&ClientMessage::Request {
            seq,
            request,
            request_epoch,
        })
        .await?;
        match self.await_reply(seq).await? {
            ServerMessage::Response { envelope, .. } => Ok(envelope),
            _ => Err(invalid("subscription reply to a request")),
        }
    }

    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 3⟩ Keep `epoch` for every mutating request this session
    /// sends from now on: the epoch a retried request ID was first bound to (`--request-epoch`).
    /// `None` goes back to binding the hello's epoch at send.
    pub fn keep_epoch(&mut self, epoch: Option<RestoreEpoch>) {
        self.kept_epoch = epoch;
    }

    /// ⟨M08 U2b-2⟩ The epoch a fresh mutating request sent now carries: the hello's where the
    /// session negotiated `request-epoch/1`, `None` otherwise. The kept epoch is not looked at.
    #[must_use]
    pub fn fresh_epoch(&self) -> Option<RestoreEpoch> {
        self.hello
            .capabilities
            .contains(capability::REQUEST_EPOCH_V1)
            .then(|| self.hello.restore_epoch())
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
                backlog,
                resync_reason,
                ..
            } => Ok(SubscribeOutcome::Subscribed {
                subscription,
                cursor,
                snapshot,
                backlog,
                resync_reason,
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
            remote_client: None,
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

    /// ⟨M04 U5, M05 W3⟩ Revision 5's two capabilities are both offered: `environments/1`
    /// (M04: the login entry item, the WSL and container requests, routes) and
    /// `trusted-work/1` (M05: every trusted-work form, ADR-0006 §17.8), and a hello that
    /// requires either negotiates it.
    #[test]
    fn the_revision_5_offer_is_environments_and_trusted_work() {
        let offered = server_capabilities();
        assert!(offered.contains(capability::ENVIRONMENTS_V1));
        assert!(offered.contains(capability::TRUSTED_WORK_V1));
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        for required in [capability::ENVIRONMENTS_V1, capability::TRUSTED_WORK_V1] {
            let h = hello(PROTOCOL_VERSION, "1", &[required]);
            let ok = negotiate(&h, p.clone(), env(), srv()).unwrap();
            assert!(ok.capabilities.contains(required), "{required}");
        }
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

    /// ⟨rev6⟩ ADR-0006 §18 (ADR-0012 §6.3, §9 item 4): the four revision-6 capabilities
    /// are declared and **not offered**: a hello that requires one is `SCHEMA_UNSUPPORTED`,
    /// and one that merely offers them negotiates without them.
    #[test]
    fn the_revision_6_capabilities_are_declared_not_offered() {
        let offered = server_capabilities();
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        for c in capability::REVISION_6_DECLARED {
            assert!(!offered.contains(c), "{c} offered");
            let err = negotiate(&hello(PROTOCOL_VERSION, "1", &[c]), p.clone(), env(), srv())
                .unwrap_err();
            assert_eq!(err.code, Code::SchemaUnsupported, "{c}");
            assert_eq!(err.data.error.reason, None, "{c}");
        }
        let mut h = hello(PROTOCOL_VERSION, "1", &[]);
        h.capabilities
            .extend(capability::REVISION_6_DECLARED.map(str::to_owned));
        let ok = negotiate(&h, p, env(), srv()).unwrap();
        assert!(
            ok.capabilities.is_disjoint(
                &capability::REVISION_6_DECLARED
                    .map(str::to_owned)
                    .into_iter()
                    .collect()
            )
        );
    }

    /// ⟨rev6⟩ `required ⊆ offer ∩ server ∩ role` with both refusal codes (ADR-0012 §6.2):
    /// outside the server's offer is `SCHEMA_UNSUPPORTED` whatever the role; inside it but
    /// outside the role's set is `CAPABILITY_UNAVAILABLE` / `role_insufficient`; optional
    /// capabilities the role lacks are dropped from the negotiated set. The local caller
    /// (no role) is the owner, negotiates everything offered and is not reported; an
    /// explicit role is reported.
    #[test]
    fn negotiation_intersects_the_role_with_both_refusal_codes() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let all = hello(PROTOCOL_VERSION, "1", &[]);
        let local = negotiate(&all, p.clone(), env(), srv()).unwrap();
        assert_eq!(local.capabilities, server_capabilities());
        assert_eq!(local.role, None);
        let text = serde_json::to_string(&ServerMessage::Hello(local.clone())).unwrap();
        assert!(
            !text.contains("\"role\""),
            "the local hello is unchanged: {text}"
        );
        let owner = negotiate_for_role(&all, p.clone(), Some(Role::Owner), env(), srv()).unwrap();
        assert_eq!(owner.capabilities, local.capabilities);
        assert_eq!(owner.role, Some(Role::Owner));

        // Server lacks it: SCHEMA_UNSUPPORTED, for every role.
        for role in [None, Some(Role::Owner), Some(Role::Viewer)] {
            let h = hello(PROTOCOL_VERSION, "1", &[capability::RUNNER_V1]);
            let err = negotiate_for_role(&h, p.clone(), role, env(), srv()).unwrap_err();
            assert_eq!(err.code, Code::SchemaUnsupported, "{role:?}");
        }
        // Server offers it, the role lacks it: role_insufficient.
        for (role, required) in [
            (Role::Viewer, capability::OWNER_POLICY_V1),
            (Role::Viewer, capability::MANAGED_CREDENTIALS_V1),
            (Role::Requester, capability::SERVICE_CONTROL_V1),
            (Role::Requester, capability::ISSUER_V1),
        ] {
            let h = hello(PROTOCOL_VERSION, "1", &[required]);
            let err = negotiate_for_role(&h, p.clone(), Some(role), env(), srv()).unwrap_err();
            assert_eq!(err.code, Code::CapabilityUnavailable, "{role:?} {required}");
            assert_eq!(
                err.data.error.reason.as_deref(),
                Some(reason::ROLE_INSUFFICIENT),
                "{role:?} {required}"
            );
            assert_eq!(err.data.error.effect_status, EffectStatus::None);
        }
        // Optional capabilities outside the role are dropped.
        let viewer = negotiate_for_role(&all, p.clone(), Some(Role::Viewer), env(), srv()).unwrap();
        let want: BTreeSet<String> = capability::VIEWER.map(str::to_owned).into_iter().collect();
        assert_eq!(viewer.capabilities, want);
        let requester = negotiate_for_role(
            &hello(PROTOCOL_VERSION, "1", &[capability::MANAGED_CREDENTIALS_V1]),
            p,
            Some(Role::Requester),
            env(),
            srv(),
        )
        .unwrap();
        assert!(!requester.capabilities.contains(capability::OWNER_POLICY_V1));
        assert_eq!(requester.role, Some(Role::Requester));
    }

    /// ⟨M06 W2; M06-W0-R06⟩ A runner's offer (`remote-control/1` added): a pending client of
    /// any role negotiates only `remote-control/1` (the probe and `join`), and requiring
    /// anything else is `CAPABILITY_UNAVAILABLE` / `invitation_pending`; the same client once
    /// active negotiates its role's set, which for a limited role has no `remote-control/1`
    /// (requiring it is `role_insufficient`). A hello naming a client with no binding is
    /// refused even by a runner, and the default dispatcher binds nobody.
    #[test]
    fn a_pending_session_negotiates_only_the_pending_path() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let mut offered = server_capabilities();
        offered.insert(capability::REMOTE_CONTROL_V1.to_owned());
        let mut h = hello(PROTOCOL_VERSION, "1", &[capability::REMOTE_CONTROL_V1]);
        h.capabilities = offered.clone();
        h.remote_client = Some(heimdall_contract::ids::ClientId::from_random_bytes([4; 16]));
        let pending = |role| {
            Some(PairedBinding {
                role,
                pending: true,
            })
        };
        let active = |role| {
            Some(PairedBinding {
                role,
                pending: false,
            })
        };
        let want: BTreeSet<String> = PENDING_CAPABILITIES
            .map(str::to_owned)
            .into_iter()
            .collect();
        for role in [Role::Viewer, Role::Requester, Role::Owner] {
            let ok =
                negotiate_session(&h, p.clone(), &offered, pending(role), env(), srv()).unwrap();
            assert_eq!(ok.capabilities, want, "{role:?}");
            assert_eq!(ok.role, Some(role));
            let mut more = h.clone();
            more.required.insert(capability::OPERATIONS_V1.to_owned());
            let err = negotiate_session(&more, p.clone(), &offered, pending(role), env(), srv())
                .unwrap_err();
            assert_eq!(err.code, Code::CapabilityUnavailable, "{role:?}");
            assert_eq!(
                err.data.error.reason.as_deref(),
                Some(reason::INVITATION_PENDING)
            );
        }
        for role in [Role::Viewer, Role::Requester] {
            let err =
                negotiate_session(&h, p.clone(), &offered, active(role), env(), srv()).unwrap_err();
            assert_eq!(
                err.data.error.reason.as_deref(),
                Some(reason::ROLE_INSUFFICIENT),
                "{role:?}"
            );
            let mut optional = h.clone();
            optional.required.clear();
            let ok = negotiate_session(&optional, p.clone(), &offered, active(role), env(), srv())
                .unwrap();
            assert!(!ok.capabilities.contains(capability::REMOTE_CONTROL_V1));
        }
        let owner =
            negotiate_session(&h, p.clone(), &offered, active(Role::Owner), env(), srv()).unwrap();
        assert!(owner.capabilities.contains(capability::REMOTE_CONTROL_V1));
        // No binding: refused, even with the runner's offer.
        let err = negotiate_session(&h, p, &offered, None, env(), srv()).unwrap_err();
        assert_eq!(err.code, Code::SchemaUnsupported);
        // The default dispatcher binds nobody.
        struct Nobody;
        #[async_trait::async_trait]
        impl Dispatcher for Nobody {
            async fn dispatch(&self, _: &SessionInfo, _: Request) -> Envelope<serde_json::Value> {
                Envelope::ok(serde_json::Value::Null)
            }
            async fn subscribe(
                &self,
                _: &SessionInfo,
                _: EventFilter,
                _: Option<Cursor>,
            ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
                Err(Box::new(error_envelope(
                    Code::NotFound,
                    EffectStatus::None,
                    "none",
                )))
            }
        }
        let mut d = Nobody;
        assert_eq!(d.bind_paired(&h).unwrap_err().code, Code::SchemaUnsupported);
        assert!(
            !d.offered_capabilities()
                .contains(capability::REMOTE_CONTROL_V1)
        );
        assert!(d.session_end().is_none());
    }

    /// ⟨rev6⟩ m06-plan U0: `remote_client` is refused outside a runner runtime. A hello
    /// that names a paired client gets `SCHEMA_UNSUPPORTED` from a runtime that does not
    /// offer `remote-control/1`, which in wave 0 is every runtime, whatever else the hello
    /// says and whatever role the caller has; the same hello without it negotiates.
    #[test]
    fn a_hello_naming_a_remote_client_is_refused_without_remote_control() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let mut h = hello(PROTOCOL_VERSION, "1", &[]);
        h.capabilities
            .insert(capability::REMOTE_CONTROL_V1.to_owned());
        h.remote_client = Some(heimdall_contract::ids::ClientId::from_random_bytes([3; 16]));
        for role in [None, Some(Role::Owner), Some(Role::Viewer)] {
            let err = negotiate_for_role(&h, p.clone(), role, env(), srv()).unwrap_err();
            assert_eq!(err.code, Code::SchemaUnsupported, "{role:?}");
            assert_eq!(err.data.error.effect_status, EffectStatus::None);
            assert!(
                !err.data.error.message.contains("cl_"),
                "no client text echoed"
            );
        }
        h.remote_client = None;
        assert!(negotiate(&h, p, env(), srv()).is_ok());
        // The hello field is omitted when absent: the wire form is unchanged.
        let text = serde_json::to_string(&ClientMessage::Hello(h)).unwrap();
        assert!(!text.contains("remote_client"), "{text}");
    }

    // --- ⟨M08 U2b-2; ADR-0014 H13⟩ the frame epoch ----------------------------------------

    fn revoke(n: u8) -> Request {
        Request::Revoke(heimdall_contract::request::RevokeRequest {
            grant_id: Some(heimdall_contract::ids::GrantId::from_random_bytes([n; 16])),
            request_id: heimdall_contract::ids::RequestId::parse(&format!("r{n}")).unwrap(),
            target: None,
        })
    }

    fn capabilities_read() -> Request {
        Request::Inspect(heimdall_contract::request::InspectRequest {
            subject: heimdall_contract::request::InspectSubject::Capabilities,
            preview: None,
            cwd: None,
            redact: false,
            select: None,
            page: None,
        })
    }

    type Seen = Arc<std::sync::Mutex<Vec<(&'static str, Option<RestoreEpoch>)>>>;

    /// A dispatcher that records each request's kind and frame epoch; with `epoch` it offers
    /// `request-epoch/1` and reports that epoch, as the runtime does.
    struct EpochDispatcher {
        epoch: Option<RestoreEpoch>,
        seen: Seen,
    }

    #[async_trait::async_trait]
    impl Dispatcher for EpochDispatcher {
        async fn dispatch(&self, s: &SessionInfo, r: Request) -> Envelope<serde_json::Value> {
            self.dispatch_request(s, r, None).await
        }
        async fn dispatch_request(
            &self,
            _: &SessionInfo,
            r: Request,
            epoch: Option<RestoreEpoch>,
        ) -> Envelope<serde_json::Value> {
            self.seen.lock().unwrap().push((r.kind(), epoch));
            Envelope::ok(serde_json::json!({}))
        }
        async fn subscribe(
            &self,
            _: &SessionInfo,
            _: EventFilter,
            _: Option<Cursor>,
        ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
            Err(Box::new(error_envelope(
                Code::NotFound,
                EffectStatus::None,
                "none",
            )))
        }
        fn offered_capabilities(&self) -> BTreeSet<String> {
            let mut offer = server_capabilities();
            if self.epoch.is_some() {
                offer.insert(capability::REQUEST_EPOCH_V1.to_owned());
            }
            offer
        }
        fn restore_epoch(&self) -> Option<RestoreEpoch> {
            self.epoch
        }
    }

    /// A served session over an in-memory pipe, and this build's client on its other end.
    async fn epoch_session(
        epoch: Option<RestoreEpoch>,
    ) -> (ControlClient<tokio::io::DuplexStream>, Seen) {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let seen: Seen = Arc::default();
        let dispatcher = EpochDispatcher {
            epoch,
            seen: Arc::clone(&seen),
        };
        tokio::spawn(
            ControlConnection::new(server_end, ConnectionLimits::default())
                .with_server_identity(env(), srv())
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                ),
        );
        let client = ControlClient::handshake(
            client_end,
            srv(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        (client, seen)
    }

    /// The session gate: a frame epoch is accepted only where `request-epoch/1` was
    /// negotiated. Elsewhere the frame is answered `SCHEMA_UNSUPPORTED` and never reaches the
    /// dispatcher, and the hello reports no epoch.
    #[tokio::test]
    async fn a_frame_epoch_without_the_capability_is_refused_and_never_dispatched() {
        let (mut c, seen) = epoch_session(None).await;
        assert!(
            !c.server()
                .capabilities
                .contains(capability::REQUEST_EPOCH_V1)
        );
        assert_eq!(c.server().restore_epoch, None);
        assert_eq!(c.fresh_epoch(), None);
        let refused = c
            .request_with_epoch(revoke(1), Some(RestoreEpoch(0)))
            .await
            .unwrap();
        assert_eq!(refused.code, Code::SchemaUnsupported);
        assert!(seen.lock().unwrap().is_empty(), "never dispatched");
        // The same request with no epoch is served.
        assert_eq!(c.request(revoke(1)).await.unwrap().code, Code::Ok);
        assert_eq!(*seen.lock().unwrap(), [("revoke", None)]);
    }

    /// Where negotiated, the hello reports the dispatcher's epoch; a fresh mutating request
    /// carries it, a read carries none, and a kept epoch is sent as kept.
    #[tokio::test]
    async fn the_hello_reports_the_epoch_and_each_mutating_frame_carries_one() {
        let (mut c, seen) = epoch_session(Some(RestoreEpoch(4))).await;
        assert!(
            c.server()
                .capabilities
                .contains(capability::REQUEST_EPOCH_V1)
        );
        assert_eq!(c.server().restore_epoch, Some(RestoreEpoch(4)));
        assert_eq!(c.fresh_epoch(), Some(RestoreEpoch(4)));
        for request in [revoke(1), capabilities_read()] {
            assert_eq!(c.request(request).await.unwrap().code, Code::Ok);
        }
        c.keep_epoch(Some(RestoreEpoch(2)));
        assert_eq!(c.request(revoke(2)).await.unwrap().code, Code::Ok);
        assert_eq!(
            *seen.lock().unwrap(),
            [
                ("revoke", Some(RestoreEpoch(4))),
                ("inspect", None),
                ("revoke", Some(RestoreEpoch(2))),
            ]
        );
    }

    /// A runtime that offers no `request-epoch/1`, read on the wire: it answers its hello
    /// with `capabilities` and records every later frame as JSON, answering each `OK`.
    async fn wire_runtime(
        capabilities: &[&str],
    ) -> (
        ControlClient<tokio::io::DuplexStream>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (client_end, mut server_end) = tokio::io::duplex(1 << 20);
        let frames: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
        let recorded = Arc::clone(&frames);
        let offered: BTreeSet<String> = capabilities.iter().map(|c| (*c).to_owned()).collect();
        tokio::spawn(async move {
            let read = async |end: &mut tokio::io::DuplexStream| {
                let mut len = [0u8; 4];
                end.read_exact(&mut len).await.ok()?;
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                end.read_exact(&mut body).await.ok()?;
                serde_json::from_slice::<serde_json::Value>(&body).ok()
            };
            let Some(_hello) = read(&mut server_end).await else {
                return;
            };
            let hello = ServerMessage::Hello(ServerHello {
                protocol: PROTOCOL_VERSION,
                schema_version: SchemaVersion::current(),
                server: srv(),
                capabilities: offered,
                principal: PrincipalInfo::OsUserUnix { uid: 501 },
                environment_id: env(),
                role: None,
                remote_client: None,
                restore_epoch: None,
            });
            let frame = encode_frame(&hello, MAX_HELLO_FRAME_BYTES).unwrap();
            server_end.write_all(&frame).await.unwrap();
            while let Some(frame) = read(&mut server_end).await {
                let seq = frame["seq"].as_u64().unwrap_or(0);
                recorded.lock().unwrap().push(frame);
                let reply = ServerMessage::Response {
                    in_reply_to: seq,
                    envelope: Envelope::ok(serde_json::json!({})),
                };
                let bytes = encode_frame(&reply, MAX_CONTROL_FRAME_BYTES).unwrap();
                if server_end.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        });
        let client = ControlClient::handshake(
            client_end,
            srv(),
            BTreeSet::new(),
            InteractionMode::NonInteractive,
        )
        .await
        .unwrap();
        (client, frames)
    }

    /// The ruling on ASK-H13b, first half: a kept epoch facing a runtime that does not offer
    /// `request-epoch/1` is refused `SCHEMA_UNSUPPORTED` (effect `none`) and nothing is sent.
    /// A read on the same session still goes.
    #[tokio::test]
    async fn kept_epoch_against_a_runtime_without_request_epoch_refuses_schema_unsupported() {
        let (mut c, frames) = wire_runtime(&[capability::OPERATIONS_V1]).await;
        c.keep_epoch(Some(RestoreEpoch(3)));
        let refused = c.request(revoke(1)).await.unwrap();
        assert_eq!(refused.code, Code::SchemaUnsupported);
        let error: ErrorData = serde_json::from_value(refused.data).unwrap();
        assert_eq!(error.error.effect_status, EffectStatus::None);
        assert!(frames.lock().unwrap().is_empty(), "nothing was sent");
        assert_eq!(c.request(capabilities_read()).await.unwrap().code, Code::Ok);
        let sent = frames.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["request"]["op"], "inspect");
        assert!(sent[0].get("request_epoch").is_none());
    }

    /// The ruling on ASK-H13b, second half: a fresh request with no kept epoch is sent, with no
    /// `request_epoch` field at all, to a runtime that does not offer `request-epoch/1`.
    #[tokio::test]
    async fn fresh_request_without_kept_epoch_is_sent_without_one() {
        let (mut c, frames) = wire_runtime(&[capability::OPERATIONS_V1]).await;
        assert_eq!(c.request(revoke(1)).await.unwrap().code, Code::Ok);
        let sent = frames.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["request"]["op"], "revoke");
        assert!(sent[0].get("request_epoch").is_none(), "{}", sent[0]);
        // The frame is byte-identical to the earlier wire form.
        let earlier =
            serde_json::json!({"type": "request", "seq": 1, "request": sent[0]["request"]});
        assert_eq!(sent[0], earlier);
    }

    // --- ⟨M07 W10 S2-08; ADR-0006 §2.4, §19.10⟩ the base capabilities, role first --------

    /// What a dispatcher was asked: request kinds and subscribe count.
    type Asked = Arc<std::sync::Mutex<(Vec<&'static str>, usize)>>;

    /// A dispatcher that records every request it is handed and serves every subscription
    /// from an empty snapshot. With `binding` it is a runner's (its offer adds
    /// `remote-control/1`) that binds the hello's paired client to it.
    struct Recorder {
        asked: Asked,
        live: broadcast::Sender<Arc<LiveEvent>>,
        binding: Option<PairedBinding>,
    }

    #[async_trait::async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch(&self, _: &SessionInfo, r: Request) -> Envelope<serde_json::Value> {
            self.asked.lock().unwrap().0.push(r.kind());
            Envelope::ok(serde_json::json!({}))
        }
        async fn subscribe(
            &self,
            _: &SessionInfo,
            _: EventFilter,
            _: Option<Cursor>,
        ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
            self.asked.lock().unwrap().1 += 1;
            Ok(SubscriptionStart {
                cursor: Cursor("c0".into()),
                boundary_seq: 0,
                snapshot: None,
                resync_reason: None,
                backlog: Vec::new(),
                live: self.live.subscribe(),
                cursor_for: Arc::new(|seq| Cursor(format!("c{seq}"))),
            })
        }
        fn offered_capabilities(&self) -> BTreeSet<String> {
            let mut offer = server_capabilities();
            if self.binding.is_some() {
                offer.insert(capability::REMOTE_CONTROL_V1.to_owned());
            }
            offer
        }
        fn bind_paired(
            &mut self,
            _: &ClientHello,
        ) -> Result<PairedBinding, Box<Envelope<ErrorData>>> {
            Ok(self.binding.unwrap())
        }
    }

    /// A served session whose client offers exactly `offer`: the local owner's, or with
    /// `binding` a paired client's.
    async fn offering(
        offer: BTreeSet<String>,
        binding: Option<PairedBinding>,
    ) -> (ControlClient<tokio::io::DuplexStream>, Asked) {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let asked: Asked = Arc::default();
        let dispatcher = Recorder {
            asked: Arc::clone(&asked),
            live: broadcast::channel(4).0,
            binding,
        };
        tokio::spawn(
            ControlConnection::new(server_end, ConnectionLimits::default())
                .with_server_identity(env(), srv())
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                ),
        );
        let client = ControlClient::handshake_hello(
            client_end,
            ClientHello {
                protocol: PROTOCOL_VERSION,
                schema_version: SchemaVersion::current(),
                client: srv(),
                capabilities: offer,
                required: BTreeSet::new(),
                interaction: InteractionMode::NonInteractive,
                remote_client: binding
                    .map(|_| heimdall_contract::ids::ClientId::from_random_bytes([4; 16])),
            },
        )
        .await
        .unwrap();
        (client, asked)
    }

    fn wire(v: &str) -> Request {
        serde_json::from_str(v).unwrap()
    }

    /// The requests each base capability covers: the four policy actions ADR-0006 §2.4 names
    /// (and a targeted one) for `owner-policy/1`; a snapshot and an event page for
    /// `events/1`; `inspect capabilities` for `schema-discovery/1`.
    fn covered(capability: &str) -> Vec<Request> {
        let forms: &[&str] = match capability {
            capability::OWNER_POLICY_V1 => &[
                r#"{"op":"policy","action":"pause","policy_id":"p"}"#,
                r#"{"op":"policy","action":"resume","policy_id":"p"}"#,
                r#"{"op":"policy","action":"cutoff","policy_id":"p","at":"2026-10-02T10:00:00Z"}"#,
                r#"{"op":"policy","action":"clear_cutoff","policy_id":"p"}"#,
                r#"{"op":"policy","action":"clear_cutoff","target":{"kind":"policy","policy_id":"p"}}"#,
            ],
            capability::EVENTS_V1 => &[
                r#"{"op":"observe","kind":"events","filter":{}}"#,
                r#"{"op":"observe","kind":"events","filter":{},"cursor":"c1","limit":10}"#,
            ],
            _ => &[r#"{"op":"inspect","subject":"capabilities"}"#],
        };
        forms.iter().map(|f| wire(f)).collect()
    }

    const BASE: [&str; 3] = [
        capability::OWNER_POLICY_V1,
        capability::EVENTS_V1,
        capability::SCHEMA_DISCOVERY_V1,
    ];

    fn refusal(env: &Envelope<serde_json::Value>) -> (Code, Option<String>, EffectStatus) {
        let e: ErrorData = serde_json::from_value(env.data.clone()).unwrap();
        (env.code.clone(), e.error.reason, e.error.effect_status)
    }

    fn subscribe_refusal(outcome: SubscribeOutcome) -> (Code, Option<String>, EffectStatus) {
        match outcome {
            SubscribeOutcome::Refused(env) => refusal(&env),
            SubscribeOutcome::Subscribed { .. } => panic!("subscribed"),
        }
    }

    /// S2-08: a session whose role holds `owner-policy/1`, `events/1` or `schema-discovery/1`
    /// but which did not negotiate it is refused the requests it covers, and without
    /// `events/1` its subscriptions, `SCHEMA_UNSUPPORTED` with effect `none`; nothing reaches
    /// the dispatcher. The same session is still served what it negotiated, and with every
    /// capability it is served as before. A `policy` action other than the four is not
    /// gated on `owner-policy/1`.
    #[tokio::test]
    async fn a_base_capability_not_negotiated_refuses_its_requests_and_subscriptions() {
        let unsupported = (Code::SchemaUnsupported, None, EffectStatus::None);
        for missing in BASE {
            let mut offer = server_capabilities();
            assert!(offer.remove(missing), "{missing}");
            let (mut c, asked) = offering(offer, None).await;
            assert!(!c.server().capabilities.contains(missing));
            for request in covered(missing) {
                let kind = request.kind();
                let env = c.request(request).await.unwrap();
                assert_eq!(refusal(&env), unsupported, "{missing} {kind}");
            }
            let subscribed = c.subscribe(EventFilter::default(), None).await.unwrap();
            if missing == capability::EVENTS_V1 {
                assert_eq!(subscribe_refusal(subscribed), unsupported);
                assert_eq!(asked.lock().unwrap().1, 0, "never subscribed");
            } else {
                assert!(matches!(subscribed, SubscribeOutcome::Subscribed { .. }));
            }
            assert!(
                asked.lock().unwrap().0.is_empty(),
                "{missing}: never dispatched"
            );
            // What the session did negotiate is still served.
            let read = wire(r#"{"op":"inspect","subject":"destinations"}"#);
            assert_eq!(c.request(read).await.unwrap().code, Code::Ok);
            let lock = wire(
                r#"{"op":"policy","action":"set_lock_behavior","policy_id":"p","behavior":"revoke_on_lock"}"#,
            );
            assert_eq!(c.request(lock).await.unwrap().code, Code::Ok);
            assert_eq!(asked.lock().unwrap().0, ["inspect", "policy"]);
        }
        // With every capability: served as today.
        let (mut c, asked) = offering(server_capabilities(), None).await;
        let mut want = Vec::new();
        for request in BASE.into_iter().flat_map(covered) {
            want.push(request.kind());
            assert_eq!(c.request(request).await.unwrap().code, Code::Ok);
        }
        assert!(matches!(
            c.subscribe(EventFilter::default(), None).await.unwrap(),
            SubscribeOutcome::Subscribed { .. }
        ));
        assert_eq!(asked.lock().unwrap().0, want);
        assert_eq!(asked.lock().unwrap().1, 1);
    }

    /// S2-08, ruled 2026-11-26 (ADR-0006 §19.10): authorization comes before capability. A
    /// paired session whose role cannot hold a capability (a viewer's `owner-policy/1`) is
    /// refused its forms `CAPABILITY_UNAVAILABLE` / `role_insufficient`, and a pending one
    /// everything beyond its path `invitation_pending` (subscriptions included), never
    /// `SCHEMA_UNSUPPORTED` and never dispatched. A capability the role holds but the session
    /// did not negotiate is still `SCHEMA_UNSUPPORTED`.
    #[tokio::test]
    async fn a_capability_the_role_cannot_hold_is_refused_by_role_first() {
        let viewer = PairedBinding {
            role: Role::Viewer,
            pending: false,
        };
        let by_role = (
            Code::CapabilityUnavailable,
            Some(reason::ROLE_INSUFFICIENT.to_owned()),
            EffectStatus::None,
        );
        // The viewer offers everything: owner-policy/1 is outside its role.
        let (mut v, asked) = offering(server_capabilities(), Some(viewer)).await;
        assert!(
            !v.server()
                .capabilities
                .contains(capability::OWNER_POLICY_V1)
        );
        for request in covered(capability::OWNER_POLICY_V1) {
            let kind = request.kind();
            let env = v.request(request).await.unwrap();
            assert_eq!(refusal(&env), by_role, "{kind}");
            assert_eq!(
                env.next.as_ref().map(|n| n.action.as_str()),
                Some("narrow_request")
            );
        }
        assert!(asked.lock().unwrap().0.is_empty(), "never dispatched");
        // What the role holds is served.
        let mut want = Vec::new();
        for request in [capability::EVENTS_V1, capability::SCHEMA_DISCOVERY_V1]
            .into_iter()
            .flat_map(covered)
        {
            want.push(request.kind());
            assert_eq!(v.request(request).await.unwrap().code, Code::Ok);
        }
        assert!(matches!(
            v.subscribe(EventFilter::default(), None).await.unwrap(),
            SubscribeOutcome::Subscribed { .. }
        ));
        assert_eq!(asked.lock().unwrap().0, want);

        // A viewer that did not offer events/1, which its role holds: SCHEMA_UNSUPPORTED.
        let mut offer = server_capabilities();
        offer.remove(capability::EVENTS_V1);
        let (mut v, asked) = offering(offer, Some(viewer)).await;
        let unsupported = (Code::SchemaUnsupported, None, EffectStatus::None);
        for request in covered(capability::EVENTS_V1) {
            assert_eq!(refusal(&v.request(request).await.unwrap()), unsupported);
        }
        let outcome = v.subscribe(EventFilter::default(), None).await.unwrap();
        assert_eq!(subscribe_refusal(outcome), unsupported);
        // Its policy pause is still refused by role.
        let pause = covered(capability::OWNER_POLICY_V1).remove(0);
        assert_eq!(refusal(&v.request(pause).await.unwrap()), by_role);
        assert_eq!(*asked.lock().unwrap(), (Vec::new(), 0), "never dispatched");

        // A pending client: only its path; everything else by its invitation.
        let pending = PairedBinding {
            role: Role::Requester,
            pending: true,
        };
        let mut offer = server_capabilities();
        offer.insert(capability::REMOTE_CONTROL_V1.to_owned());
        let (mut p, asked) = offering(offer, Some(pending)).await;
        let want: BTreeSet<String> = [capability::REMOTE_CONTROL_V1.to_owned()].into();
        assert_eq!(p.server().capabilities, want);
        let by_invitation = (
            Code::CapabilityUnavailable,
            Some(reason::INVITATION_PENDING.to_owned()),
            EffectStatus::None,
        );
        for request in BASE.into_iter().flat_map(covered) {
            let kind = request.kind();
            assert_eq!(
                refusal(&p.request(request).await.unwrap()),
                by_invitation,
                "{kind}"
            );
        }
        let outcome = p.subscribe(EventFilter::default(), None).await.unwrap();
        assert_eq!(subscribe_refusal(outcome), by_invitation);
        assert_eq!(*asked.lock().unwrap(), (Vec::new(), 0), "never dispatched");
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
            resync_reason: None,
            backlog: Vec::new(),
            live,
            cursor_for: Arc::new(|seq| Cursor(format!("c{seq}"))),
        };
        let shown = format!("{start:?}");
        assert!(shown.contains("boundary_seq: 9"));
        heimdall_testkit::assert_no_canary(&shown);
    }
}
