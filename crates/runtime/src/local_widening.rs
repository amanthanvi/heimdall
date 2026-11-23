//! ⟨M06 W5; ADR-0006 §18.9 item 8; ADR-0012 §2.1, §2.8, §3.10 item 4⟩ **Local widening
//! decisions**, on every installation: a runner's `transport enable --serve`, and a
//! controller's `transport adopt-roost` and widening `route add`.
//!
//! * **Who may submit** ([`RouteTransport::submit_local_widening`]): only a session that is
//!   not paired, that the runtime authenticated as this installation's local owner (the
//!   check every owner form uses), and that is attended. A paired session never gets a
//!   local record: it is turned away before the record port is touched, whatever its
//!   attendance says, and the record port has no way to mark a client's request local.
//!   ⟨rev6.5; ADR-0006 §18.9 item 10⟩ An unattended local owner is answered
//!   `INTERACTION_REQUIRED`, the detail naming the widening ([`unattended`]), and nothing
//!   is written: no record exists for it to approve later.
//! * **The record** is ADR-0006 §3.1's decision record with `origin = local` and no client
//!   (`heimdall_remote::widening::submit_local`), bound to the exact request and the exact
//!   exposure delta: each added relay URL, the bind scope before and after, the direct
//!   fallback, public infrastructure and external roost changes, and the policy after the
//!   change (its serve port and sshd port); the request itself carries the destination and
//!   the route. The answer is `APPROVAL_REQUIRED` with `next.decision_ref`; nothing is
//!   generated, recorded as consent, or started.
//! * **A retry** of the same widening (the CLI mints a fresh request ID per run) returns the
//!   pending record: the lookup is by origin, request kind and the digest of the request
//!   without its ID and the delta.
//! * **Approval** ([`RouteTransport::decide_local`]) is an attended local `Decide` with
//!   checked time, never automatic and never from a paired session. Before the record is
//!   claimed, its binding is verified and the delta the request would apply **now** is
//!   compared with the recorded one: a changed request or delta is
//!   `decision_binding_mismatch`, and the record stays pending. Then the exact request runs
//!   once with exactly the recorded delta as its approval; the operation compares it again
//!   with its own read.

use std::sync::Arc;

use heimdall_app::Caller;
use heimdall_app::error::OpError;
use heimdall_app::routes::ops::RouteOps;
use heimdall_app::transport::{ApprovedWidening, ExposureDelta, TransportOps};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope};
use heimdall_contract::request::{DecideRequest, Request, Verdict};
use heimdall_contract::route::RouteRequest;
use heimdall_domain::decision::DecisionState;
use heimdall_remote::roles::Refusal;
use heimdall_remote::widening::{
    self, DecidingSession, StoreWidening, WideningRecord, WideningRecords as _,
};

use crate::supervise_transport::RouteTransport;

fn value_of(e: Envelope<impl serde::Serialize>) -> Envelope<serde_json::Value> {
    e.map(|d| serde_json::to_value(d).unwrap_or_default())
}

fn refused(r: Refusal) -> Envelope<serde_json::Value> {
    value_of(r.envelope())
}

/// What a widening request from `caller` may do here.
pub(crate) enum Submission {
    /// A paired session: it never submits a local record. The caller answers as it did
    /// before local records existed (the operation's own `exposure_unconsented`).
    Paired,
    /// The local owner, attended: it may submit.
    LocalAttended,
    /// The local owner, unattended: answered [`unattended`], nothing written.
    LocalUnattended,
}

/// Classify `caller` for a widening request (module docs, "Who may submit"). The owner role
/// was checked by the caller of this function.
///
/// # Errors
/// A local session without the owner role: nothing is written.
pub(crate) fn submission_of(caller: &Caller) -> Result<Submission, OpError> {
    if caller.context.remote_client.is_some() {
        return Ok(Submission::Paired);
    }
    if !caller.context.is_owner() {
        return Err(OpError::new(
            Code::CapabilityUnavailable,
            "this request needs the owner role",
        )
        .with_effect(EffectStatus::None));
    }
    Ok(if caller.is_attended() {
        Submission::LocalAttended
    } else {
        Submission::LocalUnattended
    })
}

/// What `delta` widens, in words, for a refusal's detail: each added relay by its URL (a
/// normalised relay URL carries no credential), the bind scope's change, direct fallback,
/// public infrastructure, serving, an adopted roost.
fn widening_words(delta: &ExposureDelta) -> String {
    let mut parts: Vec<String> = Vec::new();
    if delta.serve_after && !delta.serve_before {
        parts.push("serving this host's sshd over Iroh".to_owned());
    }
    if delta.bind_after != delta.bind_before {
        parts.push(format!(
            "the bind scope from {} to {}",
            kind_token(&delta.bind_before),
            kind_token(&delta.bind_after)
        ));
    }
    for relay in &delta.relays_added {
        parts.push(format!("the relay {relay}"));
    }
    if delta.direct_fallback_added {
        parts.push("direct fallback to learned addresses".to_owned());
    }
    if delta.public_infrastructure_added {
        parts.push("public relay and lookup infrastructure".to_owned());
    }
    if delta.external_roost.is_some() {
        parts.push("an external roost".to_owned());
    }
    if parts.is_empty() {
        parts.push("a wider exposure policy".to_owned());
    }
    parts.join(", ")
}

/// The wire token of a small tagged contract value (its `kind`), for a message.
fn kind_token(value: &impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// ⟨rev6.5; ADR-0006 §18.9 item 10⟩ The answer to an **unattended local owner's** widening
/// `request` (kind `request_kind`): `INTERACTION_REQUIRED`, effect none, the detail naming
/// the request and exactly what it would add. No reason is set: the exposure-consent reason
/// (`exposure_unconsented`) is `CAPABILITY_UNAVAILABLE`'s in the reason table, and
/// `local_owner_required` is a paired session's refusal, so neither names this case.
pub(crate) fn unattended(request_kind: &str, delta: &ExposureDelta) -> OpError {
    OpError::new(
        Code::InteractionRequired,
        format!(
            "`{request_kind}` widens this host's exposure (it adds: {}). That needs the owner \
             at an interactive terminal on this host: run it there, then approve the decision \
             it names. Nothing was recorded",
            widening_words(delta)
        ),
    )
    .with_effect(EffectStatus::None)
}

impl RouteTransport {
    fn transport_ops(&self) -> TransportOps<'_> {
        TransportOps {
            store: self.store(),
            keys: self.keys().as_ref(),
            serve: self.supervisor().as_ref(),
            peers: self.peers().as_ref(),
        }
    }

    /// The exact exposure delta a widening `request` applies now; `None` when the request
    /// widens nothing (it runs directly, with no decision).
    pub(crate) fn widening_delta(
        &self,
        request: &Request,
    ) -> Result<Option<ExposureDelta>, OpError> {
        match request {
            Request::Transport(t) => Ok(self
                .transport_ops()
                .delta_of(t)?
                .filter(heimdall_app::transport::widens)),
            Request::Route(RouteRequest::Add {
                route, exposure, ..
            }) => Ok(RouteOps::add_delta(route, exposure.as_ref())),
            _ => Ok(None),
        }
    }

    /// Record the attended local owner's widening `request`, bound to `delta`, and return
    /// its pending answer as the request's refusal (`APPROVAL_REQUIRED`, `next.decision_ref`).
    /// **The caller has established [`Submission::LocalAttended`].**
    pub(crate) fn submit_local_widening(
        &self,
        request: &Request,
        delta: &ExposureDelta,
        now: Timestamp,
    ) -> OpError {
        let state = || Refusal::State.to_op_error();
        let Ok(generation) = self.store().transaction(|tx| tx.authority_generation()) else {
            return state();
        };
        let Ok(exposure) = serde_json::to_value(delta) else {
            return state();
        };
        let records = StoreWidening::new(Arc::clone(self.store_arc()));
        match widening::submit_local(&records, request, exposure, generation, now) {
            Ok((submitted, _)) => {
                let (widening::Submitted::Created(id) | widening::Submitted::Replayed(id)) =
                    submitted;
                widening::pending_local_error(&id)
            }
            Err(r) => r.to_op_error(),
        }
    }

    /// Whether an approved local record can run now (checked before it is claimed, so a
    /// refusal leaves it pending): it has a recorded delta, and the delta its request would
    /// apply now is exactly that one (otherwise `decision_binding_mismatch`).
    fn executable(
        &self,
        record: &WideningRecord,
    ) -> Result<ExposureDelta, Envelope<serde_json::Value>> {
        let Some(recorded) = &record.exposure else {
            return Err(refused(Refusal::BindingMismatch));
        };
        let Ok(recorded) = serde_json::from_value::<ExposureDelta>(recorded.clone()) else {
            return Err(refused(Refusal::BindingMismatch));
        };
        match self.widening_delta(&record.request) {
            Ok(Some(now)) if now == recorded => Ok(recorded),
            // Another delta now, or a request that no longer widens: not what was decided.
            Ok(_) => Err(refused(Refusal::BindingMismatch)),
            Err(e) => Err(value_of(e.into_envelope())),
        }
    }

    /// `Decide` on a local widening record (module docs, "Approval"). `None` when the
    /// decision is not a local widening record (a paired client's record is the runner's
    /// to decide; anything else is the application's). `checked_wall` is the time gate's
    /// accepted reading, `None` when time is uncertain.
    pub async fn decide_local(
        &self,
        caller: &Caller,
        decide: &DecideRequest,
        checked_wall: Option<Timestamp>,
        wall: Timestamp,
    ) -> Option<Envelope<serde_json::Value>> {
        let records = StoreWidening::new(Arc::clone(self.store_arc()));
        let record = match records.by_decision(&decide.decision_id) {
            Ok(Some(r)) if r.key.submitter.is_local() => r,
            Ok(_) => return None,
            Err(_) => return Some(refused(Refusal::State)),
        };
        let session = DecidingSession {
            remote_client: caller.context.remote_client.as_ref(),
            attended: caller.is_attended(),
        };
        if session.remote_client.is_some() || !session.attended || !caller.context.is_owner() {
            return Some(refused(Refusal::InteractionRequired));
        }
        if decide.verdict == Verdict::Approve && record.state == DecisionState::Pending {
            if checked_wall.is_none() {
                return Some(refused(Refusal::TimeUncertain));
            }
            if let Err(r) = widening::verify_binding(&record) {
                return Some(refused(r));
            }
            if let Err(env) = self.executable(&record) {
                return Some(env);
            }
        }
        let current = match self.store().transaction(|tx| tx.authority_generation()) {
            Ok(g) => g,
            Err(_) => return Some(refused(Refusal::State)),
        };
        let now = checked_wall.unwrap_or(wall);
        let decided = widening::decide_async(
            &records,
            session,
            &decide.decision_id,
            decide.verdict,
            current,
            now,
            async |claimed: &WideningRecord| self.execute_local(claimed, now).await,
        )
        .await;
        Some(decided.unwrap_or_else(refused))
    }

    /// Run a claimed local record's exact request once, with exactly its recorded delta as
    /// the approval. The binding and the delta are checked again first: a mismatch runs
    /// nothing.
    async fn execute_local(
        &self,
        record: &WideningRecord,
        now: Timestamp,
    ) -> Envelope<serde_json::Value> {
        if !record.key.submitter.is_local() {
            return refused(Refusal::BindingMismatch);
        }
        if let Err(r) = widening::verify_binding(record) {
            return refused(r);
        }
        let delta = match self.executable(record) {
            Ok(d) => d,
            Err(env) => return env,
        };
        let approved = ApprovedWidening {
            decision: record.decision.clone(),
            delta,
        };
        let done = match &record.request {
            Request::Transport(t) => self.transport_ops().execute(t, Some(&approved), now).await,
            Request::Route(r @ RouteRequest::Add { .. }) => RouteOps {
                store: self.store(),
            }
            .execute(r, Some(&approved), now),
            _ => Err(OpError::driver_unavailable(
                "no executor for this request in this build",
            )),
        };
        match done {
            Ok(data) => Envelope::ok(data),
            Err(e) => value_of(e.into_envelope()),
        }
    }
}
