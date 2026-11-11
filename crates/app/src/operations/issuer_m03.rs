//! ⟨M03⟩ wave 4 (U10): the issuer request handling over the store (ADR-0008 D3, D4;
//! m03-plan U10 `issuer::handle`): `issuer.status`, `register` (through the
//! `RegisterIssuer` decision), `unlock`, `retire` (through the `RetireIssuer`
//! decision) and `bundle`; the completion of both decision kinds; the supervisor's
//! issuer supervision pass. The public part is [`crate::issuer`].
//!
//! **Fail closed (R4).** Every action needs the runtime's issuer wiring
//! (`ManagedWiring.issuer`; `register` and `unlock` also `issuer_lifecycle`): without
//! it the answer is `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, before any
//! record is written. Every action needs the owner role; `unlock` an attended session
//! (the dispatcher refuses both first; checked again here, R5).
//!
//! **`register`** (D4 item 1 steps 3 and 7) validates the request (one Ed25519 public
//! key line without a comment, a hex SHA-256 backup digest, no second registration of
//! the fingerprint, a rotation's CA registered and `active`), then always creates (or
//! joins: spec §5.5, one logical decision, one record) a pending `RegisterIssuer`
//! decision with time assessed in the writing transaction, and answers
//! `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED` with its reference. It
//! never executes on dispatch. Approval, in the decide transaction: the `issuers` row
//! (`active`, or `pending` for a rotation's new CA), the native environment's
//! `managed_signing` and `issuer_access` permissions (which moves the authority
//! generation, ADR-0006 §13.7 item 5) and, when the record disclosed it, the lock
//! disclosure's acknowledgement; after the commit the child is started or reloaded.
//!
//! **The registration's public key** is not part of the `RegisterIssuer` record (the
//! frozen `DecisionKind` names the fingerprint and digests only), and no store table
//! holds it before approval. It is kept in this process (`PendingRegistrations`,
//! keyed by the decision ID, bounded) between the request and its decision. A
//! decision this process does not hold the key for (a restart in between) is refused
//! `DECISION_STALE` and not consumed: register again (questions file U10B-Q1).
//!
//! **`retire`** (D4 item 3; §17.1 item 7) is refused, writing nothing, while any
//! enrollment of the CA is neither final nor `abandoned`; otherwise it creates (or
//! joins) a `RetireIssuer` decision listing the abandoned enrollments. Approval moves
//! the CA to `retiring` in the decide transaction (which refuses new reservations
//! for it, `ca_retiring`); after the commit the retirement steps are driven by
//! [`Operations::resume_ca_retirements`] (the child's unload; the store item's
//! deletion needs this installation's recorded store locator, ADR-0008 §17.17 item 3,
//! which nothing persists yet: the CA then stays `unloaded`, questions file
//! U10B-Q2). The supervision pass resumes them.
//!
//! **`unlock`** (D4 item 2; §17.17 item 10, U4-Q2(b)) reloads the CA set through the
//! lifecycle. Heimdall never shows a store prompt: a locked store is reported
//! (`issuer_store_locked`, with how to unlock it), never unlocked.
//!
//! **`status`** is the child's last observed state (no I/O) with the store's CA
//! records filled in; **`bundle`** is `crate::issuer::bundle::export` over the store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, DecisionId, EnrollmentId, OperationId};
use heimdall_contract::issuer::{
    CaState, CaStatus, IssuerRequest, IssuerState, IssuerStatus, StoreKind,
};
use heimdall_contract::managed::IssuerIsolation;
use heimdall_contract::request::Verdict;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::enrollment::EnrollmentRecord;
use heimdall_domain::issuance::CaEvent;
use heimdall_domain::operation::OperationRecord;
use heimdall_store::{IssuerRecord, StoreError, Txn};

use super::{Emit, Operations, approval_needed, internal, plus};
use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::issuer::bundle::{EnrollmentEntry, Redaction, StoreView, export};
use crate::issuer::{
    IssuerLifecycle, ca_public_key_fingerprint, enrollment_counts, is_sha256_hex,
    register_disclosures, retire_admissible, unlock_guidance,
};
use crate::ports::{IssuerError, IssuerPort, IssuerStatusSnapshot};
use crate::timegate::uncertain;

// -----------------------------------------------------------------------------
// The registrations waiting for their decision
// -----------------------------------------------------------------------------

/// The most registrations held at once; the oldest is forgotten first (its decision
/// is then refused `DECISION_STALE`, not consumed).
pub(crate) const MAX_PENDING_REGISTRATIONS: usize = 64;

/// What a pending `RegisterIssuer` decision needs at approval and its record does not
/// carry (module docs). Public values only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRegistration {
    public_key: String,
    backup_created_at: Timestamp,
    /// Insertion order, for the bound.
    seq: u64,
}

/// Decision ID → its registration. Process-wide: decision IDs are random, so two
/// runtimes in one process (tests) never share an entry.
#[derive(Default)]
struct PendingRegistrations {
    by_decision: HashMap<DecisionId, PendingRegistration>,
    next: u64,
}

/// ⟨wave 4, integrator⟩ The registrations held by **this** `Operations` instance
/// (one field of its M03 state), so a restart — in-process or not — forgets them
/// and refuses the waiting approval `DECISION_STALE`, not consumed (U10B-Q1).
#[derive(Default)]
pub(super) struct IssuerProcessState {
    pending: Mutex<PendingRegistrations>,
}

impl IssuerProcessState {
    fn lock(&self) -> MutexGuard<'_, PendingRegistrations> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn hold_registration(
    state: &IssuerProcessState,
    decision: &DecisionId,
    public_key: &str,
    backup_created_at: Timestamp,
) {
    let mut p = state.lock();
    let seq = p.next;
    p.next = p.next.saturating_add(1);
    p.by_decision.insert(
        decision.clone(),
        PendingRegistration {
            public_key: public_key.to_owned(),
            backup_created_at,
            seq,
        },
    );
    while p.by_decision.len() > MAX_PENDING_REGISTRATIONS {
        let Some(oldest) = p
            .by_decision
            .iter()
            .min_by_key(|(_, r)| r.seq)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        p.by_decision.remove(&oldest);
    }
}

fn held_registration(
    state: &IssuerProcessState,
    decision: &DecisionId,
) -> Option<PendingRegistration> {
    state.lock().by_decision.get(decision).cloned()
}

fn forget_registration(state: &IssuerProcessState, decision: &DecisionId) {
    state.lock().by_decision.remove(decision);
}

// -----------------------------------------------------------------------------
// Pure views and checks
// -----------------------------------------------------------------------------

fn owner_only() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "issuer requests need the owner role",
    )
}

fn not_wired() -> OpError {
    OpError::driver_unavailable("the issuer is not available in this runtime")
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg.to_owned())
}

fn unknown_ca(ca: &CaFingerprint) -> OpError {
    OpError::new(Code::NotFound, "no registered CA has that fingerprint")
        .with_resource("issuer", Some(ca.to_string()))
}

/// An issuer failure as the request's error (nonsecret reason only).
fn issuer_failure(e: &IssuerError) -> OpError {
    match e {
        IssuerError::Unavailable(why) => {
            let (code, why) = match why.as_str() {
                reason::ISSUER_RESTARTING => (Code::ServiceUnavailable, reason::ISSUER_RESTARTING),
                reason::ISSUER_STORE_LOCKED => {
                    (Code::CapabilityUnavailable, reason::ISSUER_STORE_LOCKED)
                }
                reason::ISSUER_STORE_UNAVAILABLE => (
                    Code::CapabilityUnavailable,
                    reason::ISSUER_STORE_UNAVAILABLE,
                ),
                reason::ISSUER_NOT_INITIALIZED => {
                    (Code::CapabilityUnavailable, reason::ISSUER_NOT_INITIALIZED)
                }
                _ => (Code::CapabilityUnavailable, reason::ISSUER_UNAVAILABLE),
            };
            let msg = unlock_guidance(why).unwrap_or("the issuer is not available");
            OpError::new(code, msg).with_reason(why)
        }
        IssuerError::Timeout => OpError::new(
            Code::ServiceUnavailable,
            "the issuer did not answer in time",
        )
        .with_reason(reason::ISSUER_UNAVAILABLE),
        IssuerError::Refused(_) | IssuerError::Protocol(_) => {
            OpError::new(Code::CapabilityUnavailable, "the issuer is not available")
                .with_reason(reason::ISSUER_UNAVAILABLE)
        }
    }
}

/// The `issuer.status` view: the child's last observed state (`snapshot`; `None`
/// without an issuer port) with the store's CA records and their enrollment counts.
/// No CA registered is `not_initialized`, whatever the child says. Orphan store items
/// are the child's to find (the runtime holds no store handle): none are listed.
/// ⟨reading⟩ No record of a written bundle exists (the CLI writes the file), so the
/// last bundle is reported stale whenever an enrollment exists.
pub(crate) fn status_view(
    snapshot: Option<&IssuerStatusSnapshot>,
    cas: &[IssuerRecord],
    enrollments: &[EnrollmentRecord],
) -> IssuerStatus {
    let (state, reason_text) = if cas.is_empty() {
        (
            IssuerState::NotInitialized,
            Some(reason::ISSUER_NOT_INITIALIZED.to_owned()),
        )
    } else {
        match snapshot {
            Some(s) => (s.status.state, s.status.reason.clone()),
            None => (
                IssuerState::Unavailable,
                Some(reason::ISSUER_UNAVAILABLE.to_owned()),
            ),
        }
    };
    IssuerStatus {
        state,
        reason: reason_text,
        cas: cas
            .iter()
            .map(|c| CaStatus {
                fingerprint: c.ca_fingerprint.clone(),
                state: c.state,
                store: c.store_kind,
                backup_sha256: c.backup_sha256.clone(),
                backup_created_at: c.backup_created_at,
                restored_without_log: c.restored_without_log,
                enrollments: enrollment_counts(&c.ca_fingerprint, enrollments),
            })
            .collect(),
        orphan_store_items: Vec::new(),
        issuer_isolation: IssuerIsolation::SameUserProcess,
        bundle_stale: !enrollments.is_empty(),
    }
}

/// Every registered CA and every enrollment under one of them, in one transaction.
fn read_cas_and_enrollments(
    tx: &mut Txn<'_>,
) -> heimdall_store::Result<(Vec<IssuerRecord>, Vec<EnrollmentRecord>)> {
    let cas = tx.issuers()?;
    let mut enrollments = Vec::new();
    for c in &cas {
        enrollments.extend(tx.enrollments_for_ca(&c.ca_fingerprint)?);
    }
    Ok((cas, enrollments))
}

/// The decision a `register` creates or joins.
#[derive(Debug, Clone)]
struct RegisterAsk {
    fingerprint: CaFingerprint,
    store: StoreKind,
    backup_sha256: String,
    rotation_of: Option<CaFingerprint>,
    restored_without_log: bool,
}

impl RegisterAsk {
    /// Whether `kind` is a `RegisterIssuer` for exactly this registration.
    fn same(&self, kind: &DecisionKind) -> bool {
        matches!(
            kind,
            DecisionKind::RegisterIssuer {
                ca_fingerprint,
                store,
                backup_sha256,
                rotation_of,
                restored_without_log,
                ..
            } if *ca_fingerprint == self.fingerprint
                && *store == self.store
                && *backup_sha256 == self.backup_sha256
                && *rotation_of == self.rotation_of
                && *restored_without_log == self.restored_without_log
        )
    }
}

/// The state checks a registration needs now (request and approval alike): the CA
/// is not registered, and a rotation's CA is registered and `active`.
fn register_admissible(
    tx: &mut Txn<'_>,
    fingerprint: &CaFingerprint,
    rotation_of: Option<&CaFingerprint>,
) -> heimdall_store::Result<Result<(), OpError>> {
    if tx.issuer(fingerprint)?.is_some() {
        return Ok(Err(OpError::new(
            Code::ConfigConflict,
            "a CA with that fingerprint is already registered; restore its store item with `heimdall issuer restore` instead",
        )
        .with_resource("issuer", Some(fingerprint.to_string()))));
    }
    if let Some(old) = rotation_of {
        match tx.issuer(old)? {
            Some(r) if r.state == CaState::Active => {}
            Some(_) => {
                return Ok(Err(OpError::new(
                    Code::ConfigConflict,
                    "the CA being rotated is not active",
                )
                .with_resource("issuer", Some(old.to_string()))));
            }
            None => return Ok(Err(unknown_ca(old))),
        }
    }
    Ok(Ok(()))
}

/// The state checks a retirement needs now: the CA is registered and `active` or
/// `pending`, and every enrollment under it is final or abandoned. `Ok(Ok(abandoned))`.
fn retire_check(
    tx: &mut Txn<'_>,
    ca: &CaFingerprint,
) -> heimdall_store::Result<Result<Vec<EnrollmentId>, OpError>> {
    let Some(record) = tx.issuer(ca)? else {
        return Ok(Err(unknown_ca(ca)));
    };
    if !matches!(record.state, CaState::Active | CaState::Pending) {
        return Ok(Err(OpError::new(
            Code::ConfigConflict,
            "the CA's retirement has already begun; it resumes on its own",
        )
        .with_resource("issuer", Some(ca.to_string()))));
    }
    let enrollments = tx.enrollments_for_ca(ca)?;
    Ok(retire_admissible(ca, &enrollments).map_err(|open| {
        OpError::new(
            Code::ConfigConflict,
            format!(
                "{} enrollment(s) under this CA are neither final nor abandoned: remove or abandon them first",
                open.len()
            ),
        )
        .with_resource("issuer", Some(ca.to_string()))
    }))
}

// -----------------------------------------------------------------------------
// The request handling
// -----------------------------------------------------------------------------

impl Operations {
    /// `Request::Issuer` (capability `issuer/1`; module docs).
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn issuer_request(
        &self,
        caller: &Caller,
        req: IssuerRequest,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(owner_only());
        }
        let wiring = self.managed_wiring().ok_or_else(not_wired)?;
        let issuer = wiring.issuer.clone().ok_or_else(not_wired)?;
        match req {
            IssuerRequest::Status => self.issuer_status(issuer.as_ref()).await,
            IssuerRequest::Bundle { redact_hostnames } => {
                self.issuer_bundle(redact_hostnames).await
            }
            IssuerRequest::Register {
                ca_public_key,
                store,
                backup_sha256,
                backup_created_at,
                rotation_of,
                restored_without_log,
            } => {
                if wiring.issuer_lifecycle.is_none() {
                    return Err(not_wired());
                }
                let ask = Registration {
                    ca_public_key,
                    store,
                    backup_sha256,
                    backup_created_at,
                    rotation_of,
                    restored_without_log,
                };
                self.issuer_register(caller, ask).await
            }
            IssuerRequest::Unlock => {
                let lifecycle = wiring.issuer_lifecycle.clone().ok_or_else(not_wired)?;
                self.issuer_unlock(caller, issuer.as_ref(), lifecycle.as_ref())
                    .await
            }
            IssuerRequest::Retire { ca_fingerprint } => {
                self.issuer_retire(caller, ca_fingerprint).await
            }
            _ => Err(OpError::new(
                Code::UsageError,
                "this issuer action is not supported by this runtime",
            )),
        }
    }

    async fn issuer_status(&self, issuer: &dyn IssuerPort) -> OpResult<serde_json::Value> {
        let snapshot = issuer.status();
        let (cas, enrollments) = self.write(|tx, _| read_cas_and_enrollments(tx)).await?;
        let view = status_view(Some(&snapshot), &cas, &enrollments);
        let data = serde_json::to_value(view).map_err(|_| internal("issuer status"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    async fn issuer_bundle(&self, redact_hostnames: bool) -> OpResult<serde_json::Value> {
        let created_at = self.inner.config.clock.wall();
        let (cas, enrollments, aliases) = self
            .write(|tx, _| {
                let (cas, enrollments) = read_cas_and_enrollments(tx)?;
                let mut aliases = Vec::with_capacity(enrollments.len());
                for e in &enrollments {
                    // A destination no longer in the catalog keeps its ID as the label.
                    aliases.push(
                        tx.destination(&e.destination)?
                            .map_or_else(|| e.destination.as_str().to_owned(), |d| d.alias),
                    );
                }
                Ok((cas, enrollments, aliases))
            })
            .await?;
        let entries: Vec<EnrollmentEntry<'_>> = enrollments
            .iter()
            .zip(&aliases)
            .map(|(record, alias)| EnrollmentEntry { record, alias })
            .collect();
        let redact = if redact_hostnames {
            Redaction::Hostnames
        } else {
            Redaction::None
        };
        let bundle = export(
            &StoreView {
                created_at,
                cas: &cas,
                enrollments: &entries,
            },
            redact,
        )
        .map_err(|_| internal("the recovery bundle names an unregistered CA"))?;
        let data = serde_json::to_value(bundle).map_err(|_| internal("recovery bundle"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    async fn issuer_register(
        &self,
        caller: &Caller,
        reg: Registration,
    ) -> OpResult<serde_json::Value> {
        let Some(fingerprint) = ca_public_key_fingerprint(&reg.ca_public_key) else {
            return Err(OpError::new(
                Code::UsageError,
                "ca_public_key must be one OpenSSH Ed25519 public key line without a comment",
            ));
        };
        if !is_sha256_hex(&reg.backup_sha256) {
            return Err(OpError::new(
                Code::UsageError,
                "backup_sha256 must be the hex SHA-256 of the prepared backup bytes",
            ));
        }
        if reg.rotation_of.is_some() && reg.restored_without_log {
            return Err(OpError::new(
                Code::UsageError,
                "a key-only restore is not a rotation",
            ));
        }
        if reg.rotation_of.as_ref() == Some(&fingerprint) {
            return Err(OpError::new(Code::UsageError, "a CA cannot rotate itself"));
        }
        let ask = RegisterAsk {
            fingerprint,
            store: reg.store,
            backup_sha256: reg.backup_sha256,
            rotation_of: reg.rotation_of,
            restored_without_log: reg.restored_without_log,
        };
        let (public_key, backup_created_at) = (reg.ca_public_key, reg.backup_created_at);
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let held_here = Arc::clone(&self.inner.managed_ops.issuer);
        let decided = self
            .write(move |tx, emit| {
                // A decision's lifetime is measured on accepted time only (G10).
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u))),
                };
                if let Err(e) = register_admissible(tx, &ask.fingerprint, ask.rotation_of.as_ref())?
                {
                    return Ok(Err(e));
                }
                let current = tx.authority_generation()?;
                if let Some(existing) = tx
                    .pending_decisions()?
                    .into_iter()
                    .find(|d| ask.same(&d.kind) && now < d.expires_at && d.generation == current)
                {
                    hold_registration(&held_here, &existing.id, &public_key, backup_created_at);
                    return Ok(Ok(existing.id));
                }
                let acknowledged = tx.lock_disclosure_ack()?.is_some();
                let d = DecisionRecord {
                    id: decision_id,
                    kind: DecisionKind::RegisterIssuer {
                        ca_fingerprint: ask.fingerprint.clone(),
                        store: ask.store,
                        backup_sha256: ask.backup_sha256.clone(),
                        rotation_of: ask.rotation_of.clone(),
                        restored_without_log: ask.restored_without_log,
                        disclosures: register_disclosures(ask.restored_without_log, acknowledged),
                    },
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&d)?;
                emit.decision(tx, &d, None)?;
                hold_registration(&held_here, &d.id, &public_key, backup_created_at);
                Ok(Ok(d.id))
            })
            .await??;
        Err(approval_needed(
            caller.is_attended(),
            decided.as_str(),
            "registering a CA needs an attended owner decision (RegisterIssuer)",
        )
        .with_resource("decision", Some(decided.to_string())))
    }

    async fn issuer_unlock(
        &self,
        caller: &Caller,
        issuer: &dyn IssuerPort,
        lifecycle: &dyn IssuerLifecycle,
    ) -> OpResult<serde_json::Value> {
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "issuer unlock is completed only on an attended session",
            ));
        }
        let registered = self
            .write(|tx, _| {
                Ok(tx
                    .issuers()?
                    .iter()
                    .any(|c| matches!(c.state, CaState::Active | CaState::Pending)))
            })
            .await?;
        if !registered {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "no CA is registered: run `heimdall issuer init` first",
            )
            .with_reason(reason::ISSUER_NOT_INITIALIZED));
        }
        // §17.17 item 10 (U4-Q2(b)): a reload over the child, which never allows
        // interaction on a store read. A locked store is reported, never unlocked.
        match tokio::time::timeout(self.adapter_limit(), lifecycle.reload()).await {
            Ok(Ok(())) => self.issuer_status(issuer).await,
            Ok(Err(e)) => Err(issuer_failure(&e)),
            Err(_) => Err(issuer_failure(&IssuerError::Timeout)),
        }
    }

    async fn issuer_retire(
        &self,
        caller: &Caller,
        ca: CaFingerprint,
    ) -> OpResult<serde_json::Value> {
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let decided = self
            .write(move |tx, emit| {
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u))),
                };
                let abandoned = match retire_check(tx, &ca)? {
                    Ok(a) => a,
                    Err(e) => return Ok(Err(e)),
                };
                let current = tx.authority_generation()?;
                if let Some(existing) = tx.pending_decisions()?.into_iter().find(|d| {
                    matches!(
                        &d.kind,
                        DecisionKind::RetireIssuer { ca_fingerprint, abandoned_enrollments }
                            if *ca_fingerprint == ca && *abandoned_enrollments == abandoned
                    ) && now < d.expires_at
                        && d.generation == current
                }) {
                    return Ok(Ok(existing.id));
                }
                let d = DecisionRecord {
                    id: decision_id,
                    kind: DecisionKind::RetireIssuer {
                        ca_fingerprint: ca.clone(),
                        abandoned_enrollments: abandoned,
                    },
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&d)?;
                emit.decision(tx, &d, None)?;
                Ok(Ok(d.id))
            })
            .await??;
        Err(approval_needed(
            caller.is_attended(),
            decided.as_str(),
            "retiring a CA needs an attended owner decision (RetireIssuer)",
        )
        .with_resource("decision", Some(decided.to_string())))
    }

    /// Supervisor pass (m03-plan U10 `issuer_supervision_pass`; ADR-0008 D3 item 7,
    /// D4 item 3): with a CA registered (`active` or `pending`) and a child never
    /// started (`not_initialized`), start it (a child that crashed is restarted by the
    /// client's own bounded backoff; one that was **stopped** is never restarted here,
    /// §17.19 item 3); then resume every CA retirement left in `retiring`, `unloaded`
    /// or `deleted` (each step only after its effect is confirmed). Existing grants
    /// keep signing whatever the issuer's state: nothing here degrades a grant (the
    /// re-issue pass does that, for a lost K_env, `credential_reissue_pending`).
    ///
    /// # Errors
    /// [`OpError`] (the store).
    pub async fn issuer_supervision_pass(&self) -> Result<(), OpError> {
        let Some(wiring) = self.managed_wiring() else {
            return Ok(());
        };
        let Some(issuer) = wiring.issuer.clone() else {
            return Ok(());
        };
        let cas = self.write(|tx, _| tx.issuers()).await?;
        let live = cas
            .iter()
            .any(|c| matches!(c.state, CaState::Active | CaState::Pending));
        if live
            && issuer.status().status.state == IssuerState::NotInitialized
            && let Some(lifecycle) = wiring.issuer_lifecycle.as_ref()
        {
            match tokio::time::timeout(self.adapter_limit(), lifecycle.start()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "the issuer child did not start"),
                Err(_) => tracing::warn!("the issuer child did not start in time"),
            }
        }
        if cas.iter().any(|c| {
            matches!(
                c.state,
                CaState::Retiring | CaState::Unloaded | CaState::Deleted
            )
        }) {
            let report = self
                .resume_ca_retirements(Some(issuer.as_ref()), None)
                .await?;
            for (ca, state, why) in &report.stalled {
                tracing::debug!(ca = %ca, ?state, reason = %why, "a CA retirement waits");
            }
        }
        Ok(())
    }

    /// After an issuer decision committed (see `decisions_m03`): a registration's
    /// child start or reload, a retirement's steps. Never fails the decide request.
    pub(super) async fn issuer_after_decision(&self, record: &DecisionRecord, verdict: Verdict) {
        let wiring = self.managed_wiring();
        match (&record.kind, verdict) {
            (DecisionKind::RegisterIssuer { .. }, Verdict::Approve) => {
                forget_registration(&self.inner.managed_ops.issuer, &record.id);
                let Some(lifecycle) = wiring.as_ref().and_then(|w| w.issuer_lifecycle.clone())
                else {
                    return;
                };
                // D4 item 1 step 7: "Then it starts the issuer child" (a reload starts
                // one when none runs, and loads a rotation's new CA into a running one).
                match tokio::time::timeout(self.adapter_limit(), lifecycle.reload()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "the issuer child did not load the new CA");
                    }
                    Err(_) => tracing::warn!("the issuer child did not load the new CA in time"),
                }
            }
            (DecisionKind::RegisterIssuer { .. }, _) => {
                forget_registration(&self.inner.managed_ops.issuer, &record.id)
            }
            (DecisionKind::RetireIssuer { .. }, Verdict::Approve) => {
                let issuer = wiring.as_ref().and_then(|w| w.issuer.clone());
                if let Err(e) = self.resume_ca_retirements(issuer.as_deref(), None).await {
                    tracing::warn!(code = %e.code, "a CA retirement could not be resumed");
                }
            }
            _ => {}
        }
    }
}

/// An `issuer.register` request's fields.
struct Registration {
    ca_public_key: String,
    store: StoreKind,
    backup_sha256: String,
    backup_created_at: Timestamp,
    rotation_of: Option<CaFingerprint>,
    restored_without_log: bool,
}

// -----------------------------------------------------------------------------
// The decisions (inside `Operations::decide`'s transaction)
// -----------------------------------------------------------------------------

/// `decisions_m03::precheck` for `RegisterIssuer` and `RetireIssuer`: an approval
/// re-checks what the request checked against the current store (and, for a
/// registration, that this process holds its public key); a refusal writes nothing,
/// so the record stays pending and is not consumed. A denial always proceeds. Neither
/// kind waits on an operation.
pub(super) fn decision_precheck(
    tx: &mut Txn<'_>,
    state: &IssuerProcessState,
    d: &DecisionRecord,
    verdict: Verdict,
    _now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(None));
    }
    match &d.kind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint,
            rotation_of,
            ..
        } => {
            let Some(held) = held_registration(state, &d.id) else {
                return Ok(Err(stale(
                    "this runtime no longer holds the registration's public key; run the registration again",
                )));
            };
            if ca_public_key_fingerprint(&held.public_key).as_ref() != Some(ca_fingerprint) {
                return Ok(Err(stale("the registration does not match its decision")));
            }
            Ok(register_admissible(tx, ca_fingerprint, rotation_of.as_ref())?.map(|()| None))
        }
        DecisionKind::RetireIssuer {
            ca_fingerprint,
            abandoned_enrollments,
        } => Ok(match retire_check(tx, ca_fingerprint)? {
            Ok(abandoned) if abandoned == *abandoned_enrollments => Ok(None),
            Ok(_) => Err(stale(
                "the enrollments under the CA changed since the decision; retire again",
            )),
            Err(e) => Err(e),
        }),
        _ => Ok(Err(OpError::driver_unavailable(
            "this decision kind is not available in this build",
        ))),
    }
}

/// `decisions_m03::apply` for `RegisterIssuer` and `RetireIssuer` (module docs). A
/// denial changes nothing. An inner `Err` rolls the decide transaction back.
#[allow(clippy::too_many_arguments)]
pub(super) fn decision_apply(
    tx: &mut Txn<'_>,
    state: &IssuerProcessState,
    _emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    _waiting: Option<OperationRecord>,
    now: Timestamp,
    _retention: std::time::Duration,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(Vec::new()));
    }
    match &record.kind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint,
            store,
            backup_sha256,
            rotation_of,
            restored_without_log,
            disclosures,
        } => {
            let Some(held) = held_registration(state, &record.id) else {
                return Ok(Err(stale(
                    "this runtime no longer holds the registration's public key; run the registration again",
                )));
            };
            if let Err(e) = register_admissible(tx, ca_fingerprint, rotation_of.as_ref())? {
                return Ok(Err(e));
            }
            let issuer = IssuerRecord {
                ca_fingerprint: ca_fingerprint.clone(),
                public_key: held.public_key,
                // D4 item 3: a rotation's new CA starts `pending`.
                state: if rotation_of.is_some() {
                    CaState::Pending
                } else {
                    CaState::Active
                },
                store_kind: *store,
                backup_sha256: backup_sha256.clone(),
                backup_created_at: held.backup_created_at,
                restored_without_log: *restored_without_log,
                created_at: now,
                retired_at: None,
            };
            match tx.insert_issuer(&issuer) {
                Ok(()) => {}
                Err(StoreError::GenerationConflict(_)) => {
                    return Ok(Err(stale(
                        "a CA with that fingerprint is already registered",
                    )));
                }
                Err(e) => return Err(e),
            }
            // D4 item 1 step 7: the native environment's `managed_signing` and
            // `issuer_access`, which moves the generation (ADR-0006 §13.7 item 5).
            let Some(env_id) = tx.self_environment()? else {
                return Ok(Err(internal("this installation has no environment")));
            };
            let Some(mut env) = tx.environment(&env_id)? else {
                return Ok(Err(internal("this installation's environment is unknown")));
            };
            if !(env.permissions.managed_signing && env.permissions.issuer_access) {
                env.permissions.managed_signing = true;
                env.permissions.issuer_access = true;
                tx.upsert_environment(&env)?;
            }
            if disclosures
                .contains(&heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce)
            {
                tx.set_lock_disclosure_ack(now)?;
            }
            Ok(Ok(Vec::new()))
        }
        DecisionKind::RetireIssuer { ca_fingerprint, .. } => {
            let Some(current) = tx.issuer(ca_fingerprint)? else {
                return Ok(Err(unknown_ca(ca_fingerprint)));
            };
            match tx.set_issuer_state(ca_fingerprint, current.state, CaEvent::RetireApproved, now) {
                Ok(Ok(_)) => Ok(Ok(Vec::new())),
                Ok(Err(_)) | Err(StoreError::GenerationConflict(_)) => {
                    Ok(Err(stale("the CA's state changed since the decision")))
                }
                Err(e) => Err(e),
            }
        }
        _ => Ok(Ok(Vec::new())),
    }
}
