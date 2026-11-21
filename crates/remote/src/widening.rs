//! No remote widening: widening is confirmed runner-locally (ADR-0012 §3.10; ADR-0006 §18
//! item 3; M06 U1). There is **no `RemoteDecide`**.
//!
//! * **A paired client's widening request** ([`submit`]) creates a pending runner-local
//!   record and grants nothing: the answer is `APPROVAL_REQUIRED` with `next.decision_ref`
//!   (T-RA1). The request is never dispatched. A limited client never gets here
//!   (`role_insufficient`, [`crate::roles::check`]; T-RA4).
//! * **`Decide` and `Attend` from a paired session** are refused before dispatch
//!   (`INTERACTION_REQUIRED`, [`crate::roles::check`]; T-RA2).
//! * **The record** follows ADR-0006 §3.1's decision record: server-issued, bound to the
//!   exact request (its canonical hash) and its caller-namespaced key `(client, kind,
//!   request_id)`, issued under the authority generation, expiring after
//!   [`heimdall_domain::decision::DEFAULT_DECISION_LIFETIME`], and consumed once.
//! * **Only an attended session local to the runner decides** ([`decide`]): a session with
//!   a paired client, or an unattended one, is refused `INTERACTION_REQUIRED`. Approval
//!   claims the record (`pending → approved`) **before** the request runs, then records
//!   its terminal result; so the request runs at most once, and a crash between the claim
//!   and the result leaves `OUTCOME_UNKNOWN`, never a second run.
//! * ⟨M06-W0-R07⟩ **An invite is bound to its exact key and role** ([`invite_binding`]):
//!   before any record exists, the runner recomputes the fingerprint of
//!   `Invite.public_key` and refuses a mismatch (`decision_binding_mismatch`), so a
//!   mismatched key and fingerprint yield no record, hence no decision capable of
//!   enrollment and no line. The record carries the canonical key and the role
//!   ([`WideningRecord::invite`]), and the executor enrolls exactly those
//!   ([`crate::invitations::Invitations::invite_bound`]).
//! * **A replay** of the same key and request returns the recorded result (the pending
//!   answer while pending, the terminal result once decided): no new record and no
//!   re-execution (T-RA3, ADR-0006 §7.3). The same key with a different request is
//!   `REQUEST_CONFLICT`.
//!
//! **Persistence.** The domain's `DecisionKind` has no variant for a revision-6 widening
//! request (invite, route add or prefer, transport enable, roost adoption), and this unit
//! may not change the domain, so the records sit behind the [`WideningRecords`] port with
//! an in-memory implementation ([`crate::testing::MemoryWidening`]). Its store-backed
//! implementation over the `decisions` table lands with that variant (DONE question).

use heimdall_contract::Timestamp;
use heimdall_contract::canonical::{RequestHash, request_hash};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction};
use heimdall_contract::ids::{ClientId, DecisionId, KeyFingerprint, RequestId};
use heimdall_contract::remote::{RemoteEnvironmentRequest, Role};
use heimdall_contract::request::{Request, Verdict};
use heimdall_contract::route::{RouteRequest, TransportRequest};
use heimdall_domain::decision::{DEFAULT_DECISION_LIFETIME, DecisionState};
use heimdall_domain::policy::AuthorityGeneration;

use crate::roles::Refusal;

/// The caller-namespaced key of a widening request (ADR-0012 §3.7: two clients' identical
/// request IDs are different keys).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WideningKey {
    /// The paired client.
    pub client: ClientId,
    /// The request kind (`remote_environment.invite`, …).
    pub kind: String,
    /// The request ID.
    pub request_id: RequestId,
}

/// ⟨M06-W0-R07⟩ The exact key and role a runner-local invite decision is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteBinding {
    /// The role the invited client will hold.
    pub role: Role,
    /// The receiving key, canonical (`ssh-ed25519 <base64>`, no comment).
    pub public_key: String,
    /// Its fingerprint, recomputed by the runner and equal to the one the owner confirmed.
    pub key_fingerprint: KeyFingerprint,
}

/// ⟨M06-W0-R07⟩ The binding of an `invite` request: the runner recomputes the fingerprint
/// of `public_key` and refuses a key that is not one Ed25519 key or whose fingerprint is
/// not `key_fingerprint`. `None` for any other request.
///
/// # Errors
///
/// [`Refusal::BindingMismatch`].
pub fn invite_binding(request: &Request) -> Result<Option<InviteBinding>, Refusal> {
    let Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite {
        role,
        key_fingerprint,
        public_key,
        ..
    }) = request
    else {
        return Ok(None);
    };
    let key =
        crate::line::PublicKeyText::parse(public_key).map_err(|_| Refusal::BindingMismatch)?;
    if &key.fingerprint() != key_fingerprint {
        return Err(Refusal::BindingMismatch);
    }
    Ok(Some(InviteBinding {
        role: *role,
        public_key: key.openssh(),
        key_fingerprint: key_fingerprint.clone(),
    }))
}

/// One pending (or decided) runner-local record.
#[derive(Debug, Clone, PartialEq)]
pub struct WideningRecord {
    /// The record's ID, the nonsecret `next.decision_ref`.
    pub decision: DecisionId,
    /// Its key.
    pub key: WideningKey,
    /// The exact request it is bound to.
    pub request: Request,
    /// The request's canonical hash.
    pub request_hash: RequestHash,
    /// ⟨M06-W0-R07⟩ For an invite: the exact key and role the decision enrolls.
    pub invite: Option<InviteBinding>,
    /// The authority generation it was issued under.
    pub generation: AuthorityGeneration,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it lapses unless decided.
    pub expires_at: Timestamp,
    /// The state (ADR-0006 §3.1's states).
    pub state: DecisionState,
    /// When it was decided.
    pub decided_at: Option<Timestamp>,
    /// The recorded terminal result, once there is one.
    pub result: Option<Envelope<serde_json::Value>>,
}

/// Why the record port failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// A record with this key or ID exists.
    #[error("a record with this key or ID exists")]
    Exists,
    /// No such record.
    #[error("no such record")]
    Missing,
    /// The record is not in the expected state (a lost compare-and-set).
    #[error("the record moved")]
    Moved,
    /// The backing store failed.
    #[error("the record store failed")]
    Store,
}

/// Where runner-local records live (module docs, "Persistence").
pub trait WideningRecords: Send + Sync {
    /// The record for a key.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Store`].
    fn by_key(&self, key: &WideningKey) -> Result<Option<WideningRecord>, LedgerError>;

    /// The record with an ID.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Store`].
    fn by_decision(&self, id: &DecisionId) -> Result<Option<WideningRecord>, LedgerError>;

    /// Insert a new pending record; its key and ID must be new.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Exists`], [`LedgerError::Store`].
    fn insert(&self, record: WideningRecord) -> Result<(), LedgerError>;

    /// Compare-and-set a record from `pending` to `state` at `at`, with `result` when it
    /// is already known (a denial, a lapse). Returns the record as stored.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Missing`], [`LedgerError::Moved`], [`LedgerError::Store`].
    fn settle(
        &self,
        id: &DecisionId,
        state: DecisionState,
        at: Timestamp,
        result: Option<Envelope<serde_json::Value>>,
    ) -> Result<WideningRecord, LedgerError>;

    /// Record the terminal result of an approved record that has none yet.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Missing`], [`LedgerError::Moved`], [`LedgerError::Store`].
    fn record_result(
        &self,
        id: &DecisionId,
        result: Envelope<serde_json::Value>,
    ) -> Result<WideningRecord, LedgerError>;
}

/// The request ID of a revision-6 widening form, `None` for any other request.
#[must_use]
pub fn request_id_of(request: &Request) -> Option<&RequestId> {
    match request {
        Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { request_id, .. })
        // ⟨M06-W0-R08⟩ `route prefer`'s request ID is optional: a preference among
        // already-consented routes needs no decision (no terminal replay owed); when present
        // it keys the replay of the (rare) unconsented preference, which widens.
        | Request::Route(
            RouteRequest::Add { request_id, .. }
            | RouteRequest::Prefer {
                request_id: Some(request_id),
                ..
            },
        )
        | Request::Transport(
            TransportRequest::Enable { request_id, .. }
            | TransportRequest::AdoptRoost { request_id, .. },
        ) => Some(request_id),
        _ => None,
    }
}

/// The canonical hash binding a record to its exact request.
///
/// # Errors
///
/// [`Refusal::State`] when the request does not serialize canonically.
pub fn hash_of(request: &Request) -> Result<RequestHash, Refusal> {
    let value = serde_json::to_value(request).map_err(|_| Refusal::State)?;
    request_hash("remote-widening", &value).map_err(|_| Refusal::State)
}

fn store_err(_: LedgerError) -> Refusal {
    Refusal::State
}

/// The pending answer: `APPROVAL_REQUIRED` with `next.decision_ref` (§3.10 item 3).
#[must_use]
pub fn pending_envelope(decision: &DecisionId) -> Envelope<serde_json::Value> {
    let mut next = NextAction::for_code(Code::ApprovalRequired);
    next.decision_ref = Some(decision.as_str().to_owned());
    heimdall_app::OpError::new(
        Code::ApprovalRequired,
        "the request needs an owner's confirmation at the runner",
    )
    .with_effect(EffectStatus::None)
    .with_next(next)
    .into_envelope()
    .map(|d| serde_json::to_value(d).unwrap_or_default())
}

fn refusal_envelope(r: Refusal) -> Envelope<serde_json::Value> {
    r.envelope()
        .map(|d| serde_json::to_value(d).unwrap_or_default())
}

/// What a replay of a record answers (module docs, "A replay").
fn replay_answer(rec: &WideningRecord, now: Timestamp) -> Envelope<serde_json::Value> {
    if let Some(result) = &rec.result {
        return result.clone();
    }
    match rec.state {
        DecisionState::Pending if now < rec.expires_at => pending_envelope(&rec.decision),
        DecisionState::Approved => refusal_envelope(Refusal::OutcomeUnknown),
        _ => refusal_envelope(Refusal::DecisionStale),
    }
}

/// What [`submit`] did.
#[derive(Debug, Clone, PartialEq)]
pub enum Submitted {
    /// A new pending record was created.
    Created(DecisionId),
    /// The key already had this request: its recorded answer, nothing new.
    Replayed(DecisionId),
}

/// Submit a paired client's widening request (module docs). Returns what happened and the
/// answer to send.
///
/// # Errors
///
/// `REQUEST_CONFLICT` for the key with a different request; `driver_unavailable` for a
/// request that is not a keyed widening form; `decision_binding_mismatch` for an invite
/// whose key does not match its fingerprint (before any record is read or written);
/// `STATE_UNAVAILABLE`.
pub fn submit(
    records: &dyn WideningRecords,
    client: &ClientId,
    request: &Request,
    generation: AuthorityGeneration,
    now: Timestamp,
) -> Result<(Submitted, Envelope<serde_json::Value>), Refusal> {
    let request_id = request_id_of(request).ok_or(Refusal::NotAvailableRemotely)?;
    let invite = invite_binding(request)?;
    let key = WideningKey {
        client: client.clone(),
        kind: request.kind().to_owned(),
        request_id: request_id.clone(),
    };
    let hash = hash_of(request)?;
    if let Some(rec) = records.by_key(&key).map_err(store_err)? {
        if rec.request_hash != hash {
            return Err(Refusal::RequestConflict);
        }
        let answer = replay_answer(&rec, now);
        return Ok((Submitted::Replayed(rec.decision), answer));
    }
    let decision = heimdall_app::ids::new_decision_id().map_err(|_| Refusal::State)?;
    let span =
        jiff::SignedDuration::try_from(DEFAULT_DECISION_LIFETIME).map_err(|_| Refusal::State)?;
    let rec = WideningRecord {
        decision: decision.clone(),
        key,
        request: request.clone(),
        request_hash: hash,
        invite,
        generation,
        created_at: now,
        expires_at: now.checked_add(span).map_err(|_| Refusal::State)?,
        state: DecisionState::Pending,
        decided_at: None,
        result: None,
    };
    records.insert(rec).map_err(store_err)?;
    let answer = pending_envelope(&decision);
    Ok((Submitted::Created(decision), answer))
}

/// The session a decision arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecidingSession<'a> {
    /// The paired client, for a bridged session; `None` for a session local to the runner.
    pub remote_client: Option<&'a ClientId>,
    /// Whether the session is attended (ADR-0006 §3.1).
    pub attended: bool,
}

/// Decide a runner-local record (module docs): only on an attended session local to the
/// runner; consume-once and generation-checked; approval claims the record, runs `execute`
/// exactly once on the claimed record (its exact request and, for an invite, its bound key
/// and role), and records its result; denial records the owner's refusal. Returns the
/// terminal result.
///
/// # Errors
///
/// `INTERACTION_REQUIRED` from a paired or unattended session; `DECISION_STALE` for a
/// record that is not pending, has lapsed, or was issued under another generation (a stale
/// one is marked so); `STATE_UNAVAILABLE`.
pub fn decide(
    records: &dyn WideningRecords,
    session: DecidingSession<'_>,
    decision: &DecisionId,
    verdict: Verdict,
    current: AuthorityGeneration,
    now: Timestamp,
    execute: impl FnOnce(&WideningRecord) -> Envelope<serde_json::Value>,
) -> Result<Envelope<serde_json::Value>, Refusal> {
    if session.remote_client.is_some() || !session.attended {
        return Err(Refusal::InteractionRequired);
    }
    let rec = records
        .by_decision(decision)
        .map_err(store_err)?
        .ok_or(Refusal::DecisionStale)?;
    if rec.state != DecisionState::Pending {
        return Err(Refusal::DecisionStale);
    }
    if now >= rec.expires_at {
        let _ = records.settle(
            decision,
            DecisionState::Expired,
            now,
            Some(refusal_envelope(Refusal::DecisionStale)),
        );
        return Err(Refusal::DecisionStale);
    }
    if rec.generation != current {
        let _ = records.settle(
            decision,
            DecisionState::Stale,
            now,
            Some(refusal_envelope(Refusal::DecisionStale)),
        );
        return Err(Refusal::DecisionStale);
    }
    match verdict {
        Verdict::Deny => {
            let denied = heimdall_app::OpError::new(
                Code::CapabilityUnavailable,
                "the owner denied the request at the runner",
            )
            .with_effect(EffectStatus::None)
            .into_envelope()
            .map(|d| serde_json::to_value(d).unwrap_or_default());
            records
                .settle(decision, DecisionState::Denied, now, Some(denied.clone()))
                .map_err(|e| match e {
                    LedgerError::Moved => Refusal::DecisionStale,
                    _ => Refusal::State,
                })?;
            Ok(denied)
        }
        Verdict::Approve => {
            // Claim first: whoever wins this compare-and-set is the only one that runs.
            let claimed = records
                .settle(decision, DecisionState::Approved, now, None)
                .map_err(|e| match e {
                    LedgerError::Moved => Refusal::DecisionStale,
                    _ => Refusal::State,
                })?;
            let result = execute(&claimed);
            records
                .record_result(decision, result.clone())
                .map_err(store_err)?;
            Ok(result)
        }
    }
}
