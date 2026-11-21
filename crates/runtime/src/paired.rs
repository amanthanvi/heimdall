//! ⟨M06⟩ W2: the runner runtime's paired sessions (ADR-0012 §3.6–§3.11; m06-plan U1's W2
//! items M06-W0-R03 and M06-W0-R06; ADR-0006 §18.5 readings 1, 5, 7 and 17).
//!
//! * **Runner mode** ([`init_runner`], [`is_runner`]). The runner-init marker is this
//!   installation's own environment record with kind `remote_runner` (ADR-0012 §4 item 1):
//!   `heimdall remote init`'s library half writes it once (creating the environment ID at
//!   first use), and the runtime reads it at start. Only a runner offers `remote-control/1`
//!   and accepts a hello naming a paired client; every other runtime keeps wave 0's refusal
//!   (`SCHEMA_UNSUPPORTED`). The marker is not a boundary against same-account code, which
//!   is owner anyway (§3.12): a hello's client is still accepted only once the role table
//!   resolves it.
//! * **Acceptance** ([`PairedRunner::bind`]). A hello's `remote_client` (which only the
//!   bridge originates, from its argv, §3.6) is resolved by `heimdall_remote::roles::
//!   resolve_session` against the role table: an unknown or tombstoned client is refused
//!   (`client_revoked`, `invitation_expired`). The session's caller is then `{principal,
//!   role, remote_client}` with the table's role; capabilities never establish an identity
//!   (reading 1). The session is bound to that client for its lifetime.
//! * **Per-frame checks** ([`PairedRunner::frame`]). Every request of a paired session runs
//!   `heimdall_remote::roles::check` against the client's row read for that frame:
//!   revocation is rechecked per request; a pending client is refused everything but the
//!   activation probe and `join` (`invitation_pending`); `Attend` and `Decide` never reach
//!   the application (`INTERACTION_REQUIRED`: the session is non-interactive, §3.10 item 1);
//!   a permission outside the role is `role_insufficient`.
//! * **Pending sessions** (R06). A client pending at its hello negotiates only
//!   `remote-control/1` (`heimdall_ipc::session::PENDING_CAPABILITIES`), and that session
//!   is served only the activation probe and `join`, with the invitation and identity
//!   checks (`Invitations::join`) ahead of any recorded result, for its whole lifetime:
//!   after a successful join the client reconnects for an ordinary session. A limited role's
//!   ordinary negotiation never includes `remote-control/1`.
//! * **Runner-local widening** (§3.10). A paired owner's widening request becomes a pending
//!   ADR-0006 §3.1 decision record (`heimdall_remote::widening::StoreWidening`) and answers
//!   `APPROVAL_REQUIRED` with `next.decision_ref`; only an attended session local to the
//!   runner decides it ([`PairedRunner::decide_local`]), running the exact recorded request
//!   once; a replay returns the recorded terminal result.
//! * **Live events** (R03, blocking). A paired session's live events pass
//!   [`PairedRunner::live_visibility`]: its client still not revoked **and**
//!   `heimdall_app::events::event_visible_in` for its caller (client scope plus the views its
//!   role permits). The local owner keeps everything.
//! * **Revocation** (§3.7, §3.11). [`PairedRunner::revoke_client`] commits the tombstone
//!   first, then the line, then wakes every session of the client
//!   ([`PairedRunner::session_end`]): each of its subscriptions gets the terminal
//!   `client.revoked` event and the session closes.

use std::sync::Arc;

use heimdall_app::events::LiveVisibility;
use heimdall_app::transport::{
    AdmissionReport, ApprovedWidening, ExposureDelta, PeerEnrollments, ServeControl, TransportKeys,
    TransportOps,
};
use heimdall_app::{Attendance, Caller, OpError};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ResourceRef};
use heimdall_contract::event::{Cursor, Event, EventType};
use heimdall_contract::ids::{ClientId, EnvironmentId};
use heimdall_contract::ipc::{ClientHello, PrincipalInfo};
use heimdall_contract::remote::{
    ClientEventKind, ClientEventPayload, ManagementPolicy, RemoteEnvironmentRequest, Role,
};
use heimdall_contract::request::{DecideRequest, InteractionMode, Request, Verdict};
use heimdall_contract::{SchemaVersion, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::Clock;
use heimdall_ipc::session::{SessionEnd, SessionEndFuture};
use heimdall_remote::Refusal;
use heimdall_remote::invitations::{BootReading, Invitations, JoinRequest, TimeReading};
use heimdall_remote::line::{ManagementLines, ServeCommand};
use heimdall_remote::roles::{self, NoConsents, SessionFrame, SessionIdentity, Verdict as Check};
use heimdall_remote::widening::{self, DecidingSession, StoreWidening, WideningRecords as _};
use heimdall_store::ext_m06::{ClientState, RemoteClientRecord, RevocationCause};
use heimdall_store::{Store, Txn};
use tokio::sync::watch;

/// `heimdall remote serve`'s library half (ADR-0012 §3.6), re-exported for the CLI wiring:
/// [`ServeArgs::parse`] reads exactly `--client <cid> --home <abs>` from argv, and
/// [`serve_bridge`] runs one bridged session between the remote side (stdin, stdout) and
/// the home's runtime control endpoint (`connect`).
pub use heimdall_remote::bridge::{
    ArgsError as ServeArgsError, BridgeEnd, ServeArgs, serve as serve_bridge,
};
/// The ports [`RunnerOptions`] takes, re-exported for the wiring.
pub use heimdall_remote::line::{
    ManagementLines as ManagementLinesPort, ServeCommand as RunnerServeCommand,
};

/// The ports a runner's paired sessions use besides the state store. The integrator's
/// `heimdall remote serve` / `service run` wiring supplies them
/// (`crate::service::ServiceOptions::runner`).
#[derive(Clone)]
pub struct RunnerOptions {
    /// The authorized_keys writer (`heimdall_remote::line::ManagementLines`). `None`: an
    /// approved invitation, a `join` and the activation probe answer `driver_unavailable`;
    /// a revocation still commits its tombstone (the admission authority), and the
    /// reconciler removes the line once a writer exists.
    pub lines: Option<Arc<dyn ManagementLines>>,
    /// The forced command's paths (`exec "<heimdall>" remote serve --client <cid> --home
    /// "<home>"`). Needed with [`Self::lines`].
    pub command: Option<ServeCommand>,
    /// Whether limited roles may enroll (ADR-0012 §3.2): the verified effective sshd
    /// policy, or `owner_only` (the default, fail closed).
    pub management_policy: ManagementPolicy,
    /// ⟨M06 W2⟩ The serve child's supervision (`crate::supervise_transport::
    /// TransportSupervisor`): a client revocation applies its narrowing there (ADR-0012
    /// §3.11 step 2: suspend, close streams, acknowledge or kill, then report). `None`: no
    /// serve child (the supervisor's watchdog, when wired, still applies it).
    pub admission: Option<Arc<dyn ServeControl>>,
    /// ⟨M06 W2, U56-Q6⟩ The transport executor's ports: with them an approved transport
    /// widening record runs `heimdall_app::transport::TransportOps::execute`, bound to its
    /// exact exposure delta; without them such a record stays pending on approval.
    pub transport: Option<RunnerTransport>,
}

/// ⟨M06 W2⟩ The ports `heimdall_app::transport::TransportOps` runs over on a runner.
#[derive(Clone)]
pub struct RunnerTransport {
    /// K_iroh custody (`crate::supervise_transport::CredentialKeys`).
    pub keys: Arc<dyn TransportKeys>,
    /// The serve child's supervision.
    pub serve: Arc<dyn ServeControl>,
    /// The serve allowlist's enrollments.
    pub peers: Arc<dyn PeerEnrollments>,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            lines: None,
            command: None,
            management_policy: ManagementPolicy::OwnerOnly,
            admission: None,
            transport: None,
        }
    }
}

impl std::fmt::Debug for RunnerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerOptions")
            .field("lines", &self.lines.is_some())
            .field("command", &self.command.is_some())
            .field("management_policy", &self.management_policy)
            .field("admission", &self.admission.is_some())
            .field("transport", &self.transport.is_some())
            .finish()
    }
}

/// Whether this installation is a remote runner (module docs, "Runner mode"): its own
/// environment record's kind is `remote_runner`.
///
/// # Errors
///
/// The store's.
pub fn is_runner(tx: &mut Txn<'_>) -> heimdall_store::Result<bool> {
    let Some(id) = tx.self_environment()? else {
        return Ok(false);
    };
    Ok(tx
        .environment(&id)?
        .is_some_and(|e| e.kind == EnvironmentKind::RemoteRunner))
}

/// `heimdall remote init`'s library half (ADR-0012 §3.3 step 2; module docs, "Runner
/// mode"): record this installation's environment ID at first use and mark its own
/// environment record `remote_runner`, keeping any recorded permissions, device and label.
/// Idempotent. The caller holds the instance lock (no runtime is running on this home), or
/// runs inside the runtime; the runtime reads the marker at its next start.
///
/// # Errors
///
/// `STATE_UNAVAILABLE` from the store; `INTERNAL_ERROR` when randomness is unavailable.
pub fn init_runner(store: &Store) -> Result<EnvironmentId, OpError> {
    let fresh = heimdall_app::ids::new_environment_id().map_err(OpError::from)?;
    let id = store.transaction(|tx| {
        let id = match tx.self_environment()? {
            Some(id) => id,
            None => {
                tx.init_self_environment(&fresh)?;
                fresh.clone()
            }
        };
        let record = match tx.environment(&id)? {
            Some(mut e) => {
                e.kind = EnvironmentKind::RemoteRunner;
                e
            }
            None => EnvironmentRecord {
                id: id.clone(),
                device: heimdall_contract::ids::DeviceId::from_random_bytes([0; 16]),
                kind: EnvironmentKind::RemoteRunner,
                label: None,
                permissions: EnvironmentPermissions::default(),
            },
        };
        tx.upsert_environment(&record)?;
        Ok(id)
    })?;
    Ok(id)
}

/// ⟨M06 W2; the orchestrator's ruling on M06-W0-R03⟩ Strip every decision handle from an
/// event a paired caller receives: a decision event reaches a paired owner as a read-only
/// owner-role view (V1 has no `RemoteDecide`), so its payload loses `decision_id` and a
/// `decision` resource reference loses its ID. Applied on every paired delivery path: live
/// events (the relay's paired channel, `crate::dispatch::EventRelay`), resumed backlogs,
/// snapshots, event pages and `inspect decisions` ([`redact_value`]).
pub fn redact_event(event: &mut Event) {
    redact_value(&mut event.payload);
    if let Some(r) = &mut event.resource
        && r.kind == "decision"
    {
        r.id = None;
    }
}

/// [`redact_event`] over a document (an event page, a snapshot, a decision listing): every
/// `decision_id` member is removed, and every object naming `kind: "decision"` loses its
/// `id`, at any depth.
pub fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("decision_id");
            if map.get("kind").and_then(serde_json::Value::as_str) == Some("decision") {
                map.remove("id");
            }
            for child in map.values_mut() {
                redact_value(child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_value),
        _ => {}
    }
}

/// One paired session's binding (module docs, "Acceptance")./// One paired session's binding (module docs, "Acceptance").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedSession {
    /// The client, from the bridge's hello, resolved by the role table.
    pub client: ClientId,
    /// Its role, from the role table.
    pub role: Role,
    /// Whether it was pending at the hello (module docs, "Pending sessions").
    pub pending: bool,
}

/// What a paired session's request becomes ([`PairedRunner::frame`]).
#[derive(Debug)]
pub enum Frame {
    /// Answered here (a refusal, the probe, `join`, a pending widening record, a client
    /// revocation).
    Answer(Envelope<serde_json::Value>),
    /// Passed every check: dispatch to the application as this caller.
    Route(Box<Caller>, Request),
}

fn value_of(e: Envelope<impl serde::Serialize>) -> Envelope<serde_json::Value> {
    e.map(|d| serde_json::to_value(d).unwrap_or_default())
}

fn refused(r: Refusal) -> Envelope<serde_json::Value> {
    value_of(r.envelope())
}

fn ok(data: serde_json::Value) -> Envelope<serde_json::Value> {
    Envelope::ok(data)
}

/// The runner runtime's paired-session service (module docs). One per runtime, shared by
/// every connection's dispatcher.
pub struct PairedRunner {
    store: Arc<Store>,
    operations: heimdall_app::Operations,
    clock: Arc<dyn Clock>,
    options: RunnerOptions,
    /// Moves on every client revocation this runtime commits; each paired session's
    /// [`Self::session_end`] rereads its client's row then.
    revocations: watch::Sender<u64>,
    /// ⟨M06 W1 review⟩ The one line-write lock of this runner: every invitation service over
    /// it shares it, so a revocation's line removal always wins over an in-flight reconcile.
    serial: heimdall_remote::invitations::LineSerial,
}

impl std::fmt::Debug for PairedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedRunner")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PairedRunner {
    /// The service over this runtime's store and operations.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        operations: heimdall_app::Operations,
        clock: Arc<dyn Clock>,
        options: RunnerOptions,
    ) -> Self {
        let (revocations, _) = watch::channel(0);
        Self {
            store,
            operations,
            clock,
            options,
            revocations,
            serial: heimdall_remote::invitations::LineSerial::default(),
        }
    }

    /// This runner's environment.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        self.operations.environment()
    }

    /// The client's row now (`None`: unknown).
    fn row(&self, client: &ClientId) -> Result<Option<RemoteClientRecord>, Refusal> {
        self.store
            .transaction(|tx| tx.remote_client(client))
            .map_err(|_| Refusal::State)
    }

    /// Resolve a hello (module docs, "Acceptance"): `None` for a hello naming no client
    /// (the local same-uid owner), else the bound session.
    ///
    /// # Errors
    ///
    /// The resolution's refusal: `client_revoked`, `invitation_expired`, or
    /// `STATE_UNAVAILABLE` (the role table could not be read: refused, never accepted).
    pub fn bind(&self, hello: &ClientHello) -> Result<Option<PairedSession>, Refusal> {
        let mut read_failed = false;
        let identity = roles::resolve_session(true, hello, |client| match self.row(client) {
            Ok(row) => row,
            Err(_) => {
                read_failed = true;
                None
            }
        });
        if read_failed {
            return Err(Refusal::State);
        }
        match identity? {
            SessionIdentity::Local => Ok(None),
            SessionIdentity::Paired {
                client,
                role,
                state,
            } => Ok(Some(PairedSession {
                client,
                role,
                pending: state == ClientState::Pending,
            })),
        }
    }

    /// The caller of a paired session (ADR-0012 §3.7): `{principal, role, remote_client}`,
    /// never attended, non-interactive.
    #[must_use]
    pub fn caller(&self, principal: &PrincipalInfo, session: &PairedSession) -> Caller {
        let principal = crate::dispatch::principal_ref(principal);
        Caller {
            context: CallerContext {
                principal,
                role: roles::client_role(session.role),
                remote_client: Some(session.client.clone()),
            },
            attendance: Attendance::Unattended,
            interaction: InteractionMode::NonInteractive,
        }
    }

    /// The check of one paired request (module docs, "Per-frame checks"; "Pending
    /// sessions"): answered here, or routed to the application as the client's caller.
    pub async fn frame(
        &self,
        principal: &PrincipalInfo,
        session: &PairedSession,
        request: Request,
    ) -> Frame {
        let record = match self.row(&session.client) {
            Ok(r) => r,
            Err(r) => return Frame::Answer(refused(r)),
        };
        // ⟨Gemini R03⟩ The wire activation probe goes through `roles::check` as it is.
        let verdict = roles::check(
            record.as_ref(),
            SessionFrame::Request(&request),
            &NoConsents,
        );
        // R06: a session that started pending is served only the probe and `join`, whatever
        // the row says now.
        if session.pending && !matches!(verdict, Check::Probe | Check::Join | Check::Refuse(_)) {
            return Frame::Answer(refused(Refusal::InvitationPending));
        }
        match verdict {
            Check::Refuse(r) => {
                if matches!(r, Refusal::ClientRevoked | Refusal::InvitationExpired) {
                    // Whatever revoked it, this client's other sessions end too.
                    self.revocations.send_modify(|n| *n = n.wrapping_add(1));
                }
                Frame::Answer(refused(r))
            }
            Check::Probe => Frame::Answer(self.probe(&session.client, &request).await),
            Check::Join => Frame::Answer(self.join(&session.client, &request).await),
            Check::PendingRunnerLocal { .. } => {
                Frame::Answer(self.submit_widening(&session.client, &request))
            }
            Check::Dispatch { .. } => match &request {
                Request::RemoteEnvironment(RemoteEnvironmentRequest::RevokeClient {
                    environment,
                    client,
                }) => Frame::Answer(self.revoke_client(environment, client).await),
                _ => Frame::Route(Box::new(self.caller(principal, session)), request),
            },
        }
    }

    /// The subscription check of a paired session (module docs): the row reread now; a
    /// pending session subscribes to nothing.
    ///
    /// # Errors
    ///
    /// The check's refusal.
    pub fn subscribe_check(&self, session: &PairedSession) -> Result<(), Refusal> {
        if session.pending {
            return Err(Refusal::InvitationPending);
        }
        let record = self.row(&session.client)?;
        match roles::check(record.as_ref(), SessionFrame::Subscribe, &NoConsents) {
            Check::Dispatch { .. } => Ok(()),
            Check::Refuse(r) => Err(r),
            _ => Err(Refusal::NotAvailableRemotely),
        }
    }

    /// ⟨M06-W0-R03⟩ A paired session's live-event visibility (module docs, "Live events"):
    /// its client still not revoked (reread per event, a store failure hides the event), and
    /// the application's per-reader scope for its caller.
    #[must_use]
    pub fn live_visibility(&self, caller: &CallerContext, client: &ClientId) -> LiveVisibility {
        let scope = self.operations.events().live_visibility(caller);
        let store = Arc::clone(&self.store);
        let client = client.clone();
        Arc::new(move |event: &Event| {
            let live = store
                .transaction(|tx| tx.remote_client(&client))
                .ok()
                .flatten()
                .is_some_and(|r| r.state != ClientState::Revoked);
            live && scope(event)
        })
    }

    /// The terminal `client.revoked` event of a client's own subscriptions.
    fn revoked_event(&self, client: &ClientId, role: Option<Role>) -> Event {
        let payload = ClientEventPayload {
            kind: ClientEventKind::Revoked,
            environment: self.environment().clone(),
            client: client.clone(),
            role,
        };
        Event {
            schema_version: SchemaVersion::current(),
            event_id: heimdall_app::ids::new_event_id()
                .unwrap_or_else(|_| heimdall_contract::ids::EventId::from_random_bytes([0; 16])),
            event_type: EventType::Client,
            environment_id: self.environment().clone(),
            operation_id: None,
            resource: Some(ResourceRef {
                kind: "client".to_owned(),
                id: Some(client.as_str().to_owned()),
            }),
            timestamp: self.clock.wall(),
            cursor: Cursor(String::new()),
            payload: serde_json::to_value(payload).unwrap_or_default(),
        }
    }

    /// The future that ends a paired session once its client is revoked (module docs,
    /// "Revocation"): it wakes on every revocation this runtime commits and rereads the
    /// row; a missing or tombstoned row, or a row that cannot be read, ends it.
    pub fn session_end(&self, session: &PairedSession) -> SessionEndFuture {
        let mut rx = self.revocations.subscribe();
        let store = Arc::clone(&self.store);
        let terminal = self.revoked_event(&session.client, Some(session.role));
        let client = session.client.clone();
        Box::pin(async move {
            loop {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                let gone = store
                    .transaction(|tx| tx.remote_client(&client))
                    .map_or(true, |r| r.is_none_or(|r| r.state == ClientState::Revoked));
                if gone {
                    let mut event = terminal;
                    event.timestamp = Timestamp::now();
                    return SessionEnd {
                        event,
                        code: Code::CapabilityUnavailable,
                        message: "the client was revoked on this runner".to_owned(),
                    };
                }
            }
        })
    }

    /// The time reading of the invitation rules: the shared gate's `Safe` observation, or
    /// an uncertain wall clock with the boot anchor.
    async fn time_reading(&self) -> TimeReading {
        match self.operations.timegate().check().await {
            Ok(safe) => TimeReading::safe(&safe.anchor),
            Err(_) => TimeReading::uncertain(Some(BootReading {
                boot_id: self.clock.boot_id(),
                continuous: self.clock.continuous(),
            })),
        }
    }

    fn invitations(&self) -> Result<Invitations<'_>, Refusal> {
        match (&self.options.lines, &self.options.command) {
            (Some(lines), Some(command)) => Ok(Invitations {
                store: &self.store,
                lines: lines.as_ref(),
                environment: self.operations.environment(),
                command,
                clock: self.clock.as_ref(),
                serial: &self.serial,
            }),
            _ => Err(Refusal::LinesUnavailable),
        }
    }

    /// The activation probe (ADR-0012 §3.2): the client from the bridge's argv and the
    /// pending record's nonce, for a probe naming this runner and that nonce, while a pending
    /// client's invitation is live (`Invitations::probe` checks all three).
    async fn probe(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        let Some(probe) = heimdall_remote::invitations::ProbeRequest::from_request(request) else {
            return refused(Refusal::NotAvailableRemotely);
        };
        let now = self.time_reading().await;
        let echo = match self
            .invitations()
            .and_then(|i| i.probe(client, &probe, &now))
        {
            Ok(e) => e,
            Err(r) => return refused(r),
        };
        ok(serde_json::json!({
            "environment": self.environment(),
            "client": echo.client,
            "nonce": echo.nonce,
        }))
    }

    /// `join` (ADR-0012 §3.9 items 3–6): identity first, the compare-and-set at join time,
    /// then the line; a retried join returns the recorded result after the same check.
    async fn join(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        let Some(join) = JoinRequest::from_request(request) else {
            return refused(Refusal::NotAvailableRemotely);
        };
        let now = self.time_reading().await;
        match self.invitations().and_then(|i| i.join(client, &join, &now)) {
            Ok(joined) => ok(serde_json::json!({
                "environment": joined.join.environment,
                "invitation": joined.join.invitation,
                "client": joined.join.client,
                "role": joined.join.role,
                "generation": joined.join.generation,
                "joined_at": joined.join.joined_at,
                "replayed": joined.replayed,
            })),
            Err(r) => refused(r),
        }
    }

    /// The transport executor over the configured ports (`None`: not configured).
    fn transport_ops(&self) -> Option<TransportOps<'_>> {
        self.options.transport.as_ref().map(|t| TransportOps {
            store: &self.store,
            keys: t.keys.as_ref(),
            serve: t.serve.as_ref(),
            peers: t.peers.as_ref(),
        })
    }

    /// ⟨U56-Q6⟩ The exact exposure delta a transport request applies now, as the record's
    /// document; `None` for any other request, a narrowing form, or without the transport
    /// ports (then an approval leaves the record pending).
    fn exposure_of(&self, request: &Request) -> Result<Option<serde_json::Value>, OpError> {
        let (Request::Transport(t), Some(ops)) = (request, self.transport_ops()) else {
            return Ok(None);
        };
        ops.delta_of(t)?
            .map(|d| {
                serde_json::to_value(d)
                    .map_err(|_| OpError::new(Code::InternalError, "a delta cannot be recorded"))
            })
            .transpose()
    }

    /// A paired owner's widening request (§3.10 item 3): a pending runner-local record bound
    /// to its exact request (and, for an exposure widening, its exact delta), or the
    /// recorded answer of the same key.
    fn submit_widening(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        let generation = match self.store.transaction(|tx| tx.authority_generation()) {
            Ok(g) => g,
            Err(_) => return refused(Refusal::State),
        };
        let exposure = match self.exposure_of(request) {
            Ok(e) => e,
            Err(e) => return value_of(e.into_envelope()),
        };
        let records = StoreWidening::new(Arc::clone(&self.store));
        match widening::submit_bound(
            &records,
            client,
            request,
            exposure,
            generation,
            self.clock.wall(),
        ) {
            Ok((_, answer)) => answer,
            Err(r) => refused(r),
        }
    }

    /// Whether this build can run an approved record now (checked before the record is
    /// claimed, so a refusal leaves it pending): an invite needs the line writer; a transport
    /// widening needs the transport ports and a recorded delta that is still exactly the one
    /// its request applies (⟨U56-Q6⟩; otherwise `decision_binding_mismatch`).
    fn executable(
        &self,
        record: &widening::WideningRecord,
    ) -> Result<(), Envelope<serde_json::Value>> {
        let unavailable = || {
            value_of(
                OpError::driver_unavailable(
                    "this runner cannot run the recorded request in this build; the record stays pending",
                )
                .with_resource("decision", Some(record.decision.to_string()))
                .into_envelope(),
            )
        };
        match &record.request {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { .. }) => {
                self.invitations().map(drop).map_err(|_| unavailable())
            }
            Request::Transport(_) => {
                let Some(recorded) = &record.exposure else {
                    return Err(unavailable());
                };
                match self.exposure_of(&record.request) {
                    Ok(Some(now)) if &now == recorded => Ok(()),
                    Ok(Some(_)) => Err(refused(Refusal::BindingMismatch)),
                    Ok(None) => Err(unavailable()),
                    Err(e) => Err(value_of(e.into_envelope())),
                }
            }
            _ => Err(unavailable()),
        }
    }

    /// ⟨§3.10 item 2⟩ `Decide` on a runner-local widening record, from a session local to
    /// the runner (never a paired one: that never reaches here). `None` when the decision
    /// is not a runner-local widening record (the application decides it). Approval needs
    /// an attended session and checked time; the record must still be bound to exactly its
    /// decided request (`heimdall_remote::widening::verify_binding`) and executable now
    /// ([`Self::executable`]), else it is refused before it is claimed and stays pending;
    /// then the exact request runs once. A denial records the owner's refusal.
    pub async fn decide_local(
        &self,
        attended: bool,
        decide: &DecideRequest,
    ) -> Option<Envelope<serde_json::Value>> {
        let records = StoreWidening::new(Arc::clone(&self.store));
        let record = match records.by_decision(&decide.decision_id) {
            Ok(Some(r)) => r,
            Ok(None) => return None,
            Err(_) => return Some(refused(Refusal::State)),
        };
        if !attended {
            return Some(refused(Refusal::InteractionRequired));
        }
        let time = self.time_reading().await;
        if decide.verdict == Verdict::Approve
            && record.state == heimdall_domain::decision::DecisionState::Pending
        {
            if time.checked_wall.is_none() {
                return Some(refused(Refusal::TimeUncertain));
            }
            if let Err(r) = widening::verify_binding(&record) {
                return Some(refused(r));
            }
            if let Err(env) = self.executable(&record) {
                return Some(env);
            }
        }
        let current = match self.store.transaction(|tx| tx.authority_generation()) {
            Ok(g) => g,
            Err(_) => return Some(refused(Refusal::State)),
        };
        let now = time.checked_wall.unwrap_or_else(|| self.clock.wall());
        let policy = self.options.management_policy;
        let decided = widening::decide_async(
            &records,
            DecidingSession {
                remote_client: None,
                attended,
            },
            &decide.decision_id,
            decide.verdict,
            current,
            now,
            async |claimed: &widening::WideningRecord| {
                self.execute(claimed, policy, &time, now).await
            },
        )
        .await;
        Some(decided.unwrap_or_else(refused))
    }

    /// Run an approved record's exact request once (the claimed record): its binding is
    /// checked again first (a mismatch runs nothing); an invite enrolls exactly the bound key
    /// and role; a transport widening runs with exactly the recorded delta as its approval,
    /// which `TransportOps::execute` compares with the delta it reads (a different one runs
    /// nothing: `exposure_unconsented`).
    async fn execute(
        &self,
        record: &widening::WideningRecord,
        policy: ManagementPolicy,
        time: &TimeReading,
        now: Timestamp,
    ) -> Envelope<serde_json::Value> {
        if let Err(r) = widening::verify_binding(record) {
            return refused(r);
        }
        if let Some(binding) = &record.invite {
            let invited = self
                .invitations()
                .and_then(|i| i.invite_bound(binding, policy, time));
            return match invited {
                Ok(done) => ok(serde_json::json!({
                    "environment": self.environment(),
                    "invitation": done.invitation.invitation,
                    "client": done.invitation.client,
                    "role": done.invitation.role,
                    "key_fingerprint": done.invitation.key_fingerprint,
                    "generation": done.invitation.generation,
                    "expires_wall": done.invitation.expires_wall,
                    "probe_nonce": done.invitation.probe_nonce,
                })),
                Err(r) => refused(r),
            };
        }
        if let (Request::Transport(t), Some(ops), Some(recorded)) =
            (&record.request, self.transport_ops(), &record.exposure)
        {
            let Ok(delta) = serde_json::from_value::<ExposureDelta>(recorded.clone()) else {
                return refused(Refusal::BindingMismatch);
            };
            let approved = ApprovedWidening {
                decision: record.decision.clone(),
                delta,
            };
            return match ops.execute(t, Some(&approved), now).await {
                Ok(data) => ok(data),
                Err(e) => value_of(e.into_envelope()),
            };
        }
        value_of(
            OpError::driver_unavailable("no executor for this request in this build")
                .into_envelope(),
        )
    }

    /// Revoke a client on this runner (ADR-0012 §3.11; narrowing, no decision), in the
    /// ADR's order: (1) the tombstone, the admission authority (it also moves the admission
    /// generation), and every session of the client ends ([`Self::session_end`]); (2) Iroh
    /// admission closed through the serve child's supervision (suspend, close streams,
    /// acknowledge or kill, then report: `iroh_admission`); (3) the line removed (or left to
    /// the reconciler when no writer is wired); then the `client.revoked` event.
    pub async fn revoke_client(
        &self,
        environment: &EnvironmentId,
        client: &ClientId,
    ) -> Envelope<serde_json::Value> {
        if environment != self.environment() {
            return value_of(
                OpError::new(Code::NotFound, "unknown environment")
                    .with_resource("environment", None)
                    .with_effect(EffectStatus::None)
                    .into_envelope(),
            );
        }
        let now = self.clock.wall();
        let tomb = self
            .store
            .transaction(|tx| {
                if tx.remote_client(client)?.is_none() {
                    return Ok(None);
                }
                tx.revoke_remote_client(client, RevocationCause::Revoked, now)
                    .map(Some)
            })
            .map_err(|_| Refusal::State)
            .and_then(|r| r.ok_or(Refusal::ClientRevoked));
        let tomb = match tomb {
            Ok(t) => t,
            Err(r) => return refused(r),
        };
        self.revocations.send_modify(|n| *n = n.wrapping_add(1));
        let admission = self.options.admission.clone().or_else(|| {
            self.options
                .transport
                .as_ref()
                .map(|t| Arc::clone(&t.serve))
        });
        let iroh = match admission {
            Some(serve) => serve.apply_narrowing().await,
            None => AdmissionReport::NotServing,
        };
        // Idempotent on the tombstone (already revoked: nothing moves); it removes the line.
        let line_removed = self
            .invitations()
            .and_then(|i| i.revoke(client, now))
            .is_ok_and(|r| r.line_removed);
        let payload = ClientEventPayload {
            kind: ClientEventKind::Revoked,
            environment: self.environment().clone(),
            client: client.clone(),
            role: Some(tomb.role),
        };
        // The tombstone is committed: a lost event costs only the report.
        let _ = self.operations.events().publish(
            EventType::Client,
            None,
            serde_json::to_value(payload).unwrap_or_default(),
        );
        ok(serde_json::json!({
            "environment": self.environment(),
            "client": client,
            "state": "revoked",
            "iroh_admission": iroh,
            "line_removed": line_removed,
        }))
    }

    /// Bring every client's line in line with the role table (the invitation service's
    /// idempotent reconciler, after tombstoning invitations that definitely expired); run at
    /// the runtime's start. Without a line writer it does nothing.
    pub async fn reconcile_lines(&self) {
        let now = self.time_reading().await;
        if let Ok(i) = self.invitations() {
            if let Ok(expired) = i.expire_due(&now)
                && !expired.is_empty()
            {
                self.revocations.send_modify(|n| *n = n.wrapping_add(1));
            }
            if let Ok(report) = i.reconcile(&now)
                && report.failed > 0
            {
                tracing::warn!(
                    failed = report.failed,
                    "a management line could not be reconciled"
                );
            }
        }
    }
}
