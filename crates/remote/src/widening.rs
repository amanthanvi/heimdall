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
//! **Persistence.** ⟨M06 W2⟩ The records are ADR-0006 §3.1 decision records
//! ([`StoreWidening`]): a `decisions` row of kind `DecisionKind::RemoteWidening` (the client,
//! the request kind and ID, the exact request and, for an invite, the bound key and role),
//! with its side row in `remote_widening` (migration 0010: the caller-namespaced key, the
//! request's canonical hash and the recorded terminal result). Because the record is a
//! decision, the runner's own CLI and TUI list it (`inspect decisions`) and an attended
//! `decision approve` local to the runner decides it through [`decide`]. The in-memory
//! implementation ([`crate::testing::MemoryWidening`]) stays for this crate's model tests.

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
    /// ⟨M06 W2, U56-Q6⟩ For an exposure widening: the exact exposure delta the request
    /// applies, computed when the record was created (the store's `ExposureDelta` document).
    pub exposure: Option<serde_json::Value>,
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

/// ⟨M06 W2⟩ The durable [`WideningRecords`] (module docs, "Persistence"): ADR-0006 §3.1
/// decision records in the runner's state store.
#[derive(Clone)]
pub struct StoreWidening {
    store: std::sync::Arc<heimdall_store::Store>,
}

impl std::fmt::Debug for StoreWidening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreWidening").finish_non_exhaustive()
    }
}

impl StoreWidening {
    /// Over `store`.
    #[must_use]
    pub fn new(store: std::sync::Arc<heimdall_store::Store>) -> Self {
        Self { store }
    }

    fn read(
        &self,
        f: impl FnOnce(
            &mut heimdall_store::Txn<'_>,
        ) -> heimdall_store::Result<
            Option<(
                heimdall_domain::decision::DecisionRecord,
                heimdall_store::ext_m06::RemoteWideningRow,
            )>,
        >,
    ) -> Result<Option<WideningRecord>, LedgerError> {
        self.store
            .transaction(f)
            .map_err(|_| LedgerError::Store)?
            .map(|(d, row)| to_record(d, row))
            .transpose()
    }
}

/// A lost compare-and-set is [`LedgerError::Moved`]; anything else a store failure (a
/// missing record is checked first, [`LedgerError::Missing`]).
fn ledger_err(e: heimdall_store::StoreError) -> LedgerError {
    match e {
        heimdall_store::StoreError::GenerationConflict(_) => LedgerError::Moved,
        _ => LedgerError::Store,
    }
}

/// A stored record as the port's [`WideningRecord`]; a record that does not decode is a
/// store failure (fail closed).
fn to_record(
    d: heimdall_domain::decision::DecisionRecord,
    row: heimdall_store::ext_m06::RemoteWideningRow,
) -> Result<WideningRecord, LedgerError> {
    let heimdall_domain::decision::DecisionKind::RemoteWidening(w) = d.kind else {
        return Err(LedgerError::Store);
    };
    let request_hash = RequestHash::from_hex(&row.request_hash).map_err(|_| LedgerError::Store)?;
    let result = row
        .result
        .map(serde_json::from_value::<Envelope<serde_json::Value>>)
        .transpose()
        .map_err(|_| LedgerError::Store)?;
    let w = *w;
    Ok(WideningRecord {
        decision: d.id,
        key: WideningKey {
            client: w.client,
            kind: w.request_kind,
            request_id: w.request_id,
        },
        request: w.request,
        request_hash,
        invite: w.invite.map(|b| InviteBinding {
            role: b.role,
            public_key: b.public_key,
            key_fingerprint: b.key_fingerprint,
        }),
        exposure: w.exposure,
        generation: d.generation,
        created_at: d.created_at,
        expires_at: d.expires_at,
        state: d.state,
        decided_at: d.decided_at,
        result,
    })
}

fn envelope_value(e: &Envelope<serde_json::Value>) -> Result<serde_json::Value, LedgerError> {
    serde_json::to_value(e).map_err(|_| LedgerError::Store)
}

impl WideningRecords for StoreWidening {
    fn by_key(&self, key: &WideningKey) -> Result<Option<WideningRecord>, LedgerError> {
        self.read(|tx| tx.remote_widening_by_key(&key.client, &key.kind, &key.request_id))
    }

    fn by_decision(&self, id: &DecisionId) -> Result<Option<WideningRecord>, LedgerError> {
        self.read(|tx| tx.remote_widening(id))
    }

    fn insert(&self, record: WideningRecord) -> Result<(), LedgerError> {
        use heimdall_domain::decision::{
            DecisionKind, DecisionRecord, RemoteInviteBinding, RemoteWidening,
        };
        let hash = record.request_hash.to_hex();
        let decision = DecisionRecord {
            id: record.decision,
            kind: DecisionKind::RemoteWidening(Box::new(RemoteWidening {
                client: record.key.client,
                request_kind: record.key.kind,
                request_id: record.key.request_id,
                request: record.request,
                invite: record.invite.map(|b| RemoteInviteBinding {
                    role: b.role,
                    public_key: b.public_key,
                    key_fingerprint: b.key_fingerprint,
                }),
                exposure: record.exposure,
            })),
            generation: record.generation,
            created_at: record.created_at,
            expires_at: record.expires_at,
            state: record.state,
            decided_at: record.decided_at,
        };
        self.store
            .transaction(|tx| tx.insert_remote_widening(&decision, &hash))
            .map_err(|e| match e {
                heimdall_store::StoreError::GenerationConflict(_) => LedgerError::Exists,
                _ => LedgerError::Store,
            })
    }

    fn settle(
        &self,
        id: &DecisionId,
        state: DecisionState,
        at: Timestamp,
        result: Option<Envelope<serde_json::Value>>,
    ) -> Result<WideningRecord, LedgerError> {
        let value = result.as_ref().map(envelope_value).transpose()?;
        self.by_decision(id)?.ok_or(LedgerError::Missing)?;
        let (d, row) = self
            .store
            .transaction(|tx| tx.settle_remote_widening(id, state, at, value.as_ref()))
            .map_err(ledger_err)?;
        to_record(d, row)
    }

    fn record_result(
        &self,
        id: &DecisionId,
        result: Envelope<serde_json::Value>,
    ) -> Result<WideningRecord, LedgerError> {
        let value = envelope_value(&result)?;
        self.by_decision(id)?.ok_or(LedgerError::Missing)?;
        let (d, row) = self
            .store
            .transaction(|tx| tx.record_remote_widening_result(id, &value))
            .map_err(ledger_err)?;
        to_record(d, row)
    }
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
    submit_bound(records, client, request, None, generation, now)
}

/// ⟨M06 W2, U56-Q6⟩ [`submit`] for a request whose record is also bound to the exact
/// exposure delta it applies (`exposure`, computed by the caller from the runner's recorded
/// endpoint): approval executes only while the delta is still exactly this one
/// ([`WideningRecord::exposure`]). A replay of the same request returns the recorded answer
/// whatever the delta is now.
///
/// # Errors
///
/// As [`submit`].
pub fn submit_bound(
    records: &dyn WideningRecords,
    client: &ClientId,
    request: &Request,
    exposure: Option<serde_json::Value>,
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
        exposure,
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

/// ⟨M06 W2, U56-Q6⟩ Whether a record is still bound to exactly the request it was decided
/// for: the request's canonical hash equals the one recorded at submission, its kind and
/// request ID are the key's, and, for an invite, the key and role recomputed from the
/// request are the recorded binding. Checked before a record is claimed and again by the
/// executor: a mismatch executes nothing.
///
/// # Errors
///
/// [`Refusal::BindingMismatch`]; `STATE_UNAVAILABLE` when the request does not serialize.
pub fn verify_binding(record: &WideningRecord) -> Result<(), Refusal> {
    let same = hash_of(&record.request)? == record.request_hash
        && record.request.kind() == record.key.kind
        && request_id_of(&record.request) == Some(&record.key.request_id)
        && invite_binding(&record.request)? == record.invite;
    if same {
        Ok(())
    } else {
        Err(Refusal::BindingMismatch)
    }
}

/// What the shared precheck of [`decide`] and [`decide_async`] left to do.
enum Step {
    /// Denied and recorded: the answer.
    Denied(Box<Envelope<serde_json::Value>>),
    /// Claimed (`pending → approved`): run it once, then record its result.
    Claimed(Box<WideningRecord>),
}

fn claim(
    records: &dyn WideningRecords,
    session: DecidingSession<'_>,
    decision: &DecisionId,
    verdict: Verdict,
    current: AuthorityGeneration,
    now: Timestamp,
) -> Result<Step, Refusal> {
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
    let moved = |e: LedgerError| match e {
        LedgerError::Moved => Refusal::DecisionStale,
        _ => Refusal::State,
    };
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
                .map_err(moved)?;
            Ok(Step::Denied(Box::new(denied)))
        }
        Verdict::Approve => {
            // A record no longer bound to its exact request is never claimed: nothing runs,
            // and it stays pending until it lapses.
            verify_binding(&rec)?;
            // Claim first: whoever wins this compare-and-set is the only one that runs.
            let claimed = records
                .settle(decision, DecisionState::Approved, now, None)
                .map_err(moved)?;
            Ok(Step::Claimed(Box::new(claimed)))
        }
    }
}

/// Decide a runner-local record (module docs): only on an attended session local to the
/// runner; consume-once and generation-checked; approval checks the record's binding
/// ([`verify_binding`]), claims it, runs `execute` exactly once on the claimed record (its
/// exact request and, for an invite, its bound key and role), and records its result;
/// denial records the owner's refusal. Returns the terminal result.
///
/// # Errors
///
/// `INTERACTION_REQUIRED` from a paired or unattended session; `DECISION_STALE` for a
/// record that is not pending, has lapsed, or was issued under another generation (a stale
/// one is marked so); `decision_binding_mismatch` for a record no longer bound to its exact
/// request (not claimed); `STATE_UNAVAILABLE`.
pub fn decide(
    records: &dyn WideningRecords,
    session: DecidingSession<'_>,
    decision: &DecisionId,
    verdict: Verdict,
    current: AuthorityGeneration,
    now: Timestamp,
    execute: impl FnOnce(&WideningRecord) -> Envelope<serde_json::Value>,
) -> Result<Envelope<serde_json::Value>, Refusal> {
    match claim(records, session, decision, verdict, current, now)? {
        Step::Denied(answer) => Ok(*answer),
        Step::Claimed(claimed) => {
            let result = execute(&claimed);
            records
                .record_result(decision, result.clone())
                .map_err(store_err)?;
            Ok(result)
        }
    }
}

/// [`decide`] with an asynchronous executor (the runtime's transport executor).
///
/// # Errors
///
/// As [`decide`].
pub async fn decide_async(
    records: &dyn WideningRecords,
    session: DecidingSession<'_>,
    decision: &DecisionId,
    verdict: Verdict,
    current: AuthorityGeneration,
    now: Timestamp,
    execute: impl AsyncFnOnce(&WideningRecord) -> Envelope<serde_json::Value>,
) -> Result<Envelope<serde_json::Value>, Refusal> {
    match claim(records, session, decision, verdict, current, now)? {
        Step::Denied(answer) => Ok(*answer),
        Step::Claimed(claimed) => {
            let result = execute(&claimed).await;
            records
                .record_result(decision, result.clone())
                .map_err(store_err)?;
            Ok(result)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testing::MemoryWidening;

    fn key_text(n: u8) -> (String, KeyFingerprint) {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[n; 32]);
        let text = format!(
            "ssh-ed25519 {}",
            <base64ct::Base64 as base64ct::Encoding>::encode_string(&blob)
        );
        let fp = crate::line::PublicKeyText::parse(&text)
            .unwrap()
            .fingerprint();
        (text, fp)
    }

    fn invite(n: u8, request_id: &str) -> Request {
        let (public_key, fp) = key_text(n);
        serde_json::from_value(serde_json::json!({
            "op": "remote_environment", "action": "invite",
            "environment": heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16]),
            "role": "owner", "key_fingerprint": fp, "public_key": public_key,
            "request_id": request_id,
        }))
        .unwrap()
    }

    /// ⟨M06 W2, U56-Q6⟩ Approval runs only a record still bound to exactly its decided
    /// request: a record whose request no longer hashes to the recorded hash, or whose
    /// invite binding names another key, is refused `decision_binding_mismatch` before it is
    /// claimed (the executor never runs and the record stays pending); an intact record runs
    /// once.
    #[tokio::test]
    async fn approval_executes_only_the_exact_decided_request() {
        let records = MemoryWidening::new();
        let client = ClientId::from_random_bytes([1; 16]);
        let now: Timestamp = "2026-11-21T09:00:00Z".parse().unwrap();
        let generation = AuthorityGeneration(3);
        let local = DecidingSession {
            remote_client: None,
            attended: true,
        };
        let mut ids = Vec::new();
        for (n, id) in [(1u8, "a"), (2, "b"), (3, "c")] {
            let (Submitted::Created(d), _) =
                submit(&records, &client, &invite(n, id), generation, now).unwrap()
            else {
                panic!("not created");
            };
            ids.push(d);
        }
        // Tamper: (a) the request no longer matches its hash; (b) the binding names another
        // key while the request (and so its hash) is intact.
        let mut all = records.all();
        let tampered_request = all.iter_mut().find(|r| r.decision == ids[0]).unwrap();
        tampered_request.request = invite(9, "a");
        let tampered_binding = records.all().into_iter().find(|r| r.decision == ids[1]);
        let mut tampered_binding = tampered_binding.unwrap();
        tampered_binding.invite = invite_binding(&invite(8, "b")).unwrap();
        let replaced = MemoryWidening::new();
        for r in [
            tampered_request.clone(),
            tampered_binding,
            records
                .all()
                .into_iter()
                .find(|r| r.decision == ids[2])
                .unwrap(),
        ] {
            replaced.insert(r).unwrap();
        }
        for id in &ids[..2] {
            let mut ran = false;
            let out = decide_async(
                &replaced,
                local,
                id,
                Verdict::Approve,
                generation,
                now,
                async |_: &WideningRecord| {
                    ran = true;
                    pending_envelope(id)
                },
            )
            .await;
            assert_eq!(out, Err(Refusal::BindingMismatch));
            assert!(!ran, "nothing executed");
            assert_eq!(
                replaced.by_decision(id).unwrap().unwrap().state,
                DecisionState::Pending
            );
        }
        let mut runs = 0;
        let out = decide(
            &replaced,
            local,
            &ids[2],
            Verdict::Approve,
            generation,
            now,
            |claimed| {
                runs += 1;
                assert_eq!(claimed.invite, invite_binding(&invite(3, "c")).unwrap());
                pending_envelope(&ids[2])
            },
        );
        assert!(out.is_ok());
        assert_eq!(runs, 1);
    }
}
