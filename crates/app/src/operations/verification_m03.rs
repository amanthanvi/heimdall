//! ⟨M03⟩ U0b row 4 (ADR-0008 D5 §6.5 item 2, D7 item 4): the verification issuance
//! table's reserve, publish and void, under `heimdall_domain::verification::check`.
//!
//! Verification certificates have no grant, so they are reserved in
//! `verification_issuance` with their own predicate, applied identically at reserve
//! and at publish, with time assessed by the gate **inside** each transaction (as
//! for grant issuance). Reserved and published entries count toward the per-pair
//! residual until their `valid_before` ([`Operations::pair_residual`]).
//!
//! **The operation facts** the predicate needs come from the store, never from the
//! request:
//! * *kind, authorization and stage* (⟨wave 4⟩ ADR-0008 §17.21 item 5): each
//!   verification has its own predicate, `enrollment_m03::verification_authority`:
//!   wave 0's presence check (an `enrollment.verify` whose stored request names this
//!   enrollment in mode `presence`; no decision), the system form's absence check
//!   (mode `absence`, the system-form record `removal_verifying`), an
//!   `enrollment.apply`'s initial verification (its approved `EnrollAccount`, the
//!   record `verifying` after a confirmed append) and a target change's (its approved
//!   `ApproveTargetChange` with the proposed target, the record `reverifying` from
//!   `held`). No other open operation may drive the record, and an attempt must have
//!   started (an `enroll.verify.started` receipt);
//! * *the plan's pair and CA*: the enrollment record's;
//! * *attempts*: the operation's `enroll.verify.started` receipts; *entries in the
//!   attempt*: its entries reserved at or after the last of them.
//!
//! An entry reserved before this runtime instance started is never published: it
//! stays `reserved` and counted until its `valid_before`.

use std::collections::BTreeSet;

use heimdall_contract::ids::{CaFingerprint, EnrollmentId, IssuanceId, OperationId};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::issuance::{CertificateBounds, IssuanceState};
use heimdall_domain::operation::enrollment_stage;
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::TimeStatus;
use heimdall_domain::verification::{
    VerificationCheck, VerificationEntry, VerificationPurpose, VerificationRefusal,
    VerifyingOperation, check,
};
use heimdall_store::Txn;

use super::managed_state_m03::ReservedVerification;
use super::{Operations, issuance_time};
use crate::error::OpError;

/// A verification certificate reservation (ADR-0008 D5 §6.5 item 2). The serial is
/// drawn by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    /// The verifying operation (`enrollment.apply` or `enrollment.verify`).
    pub operation: OperationId,
    /// The enrollment whose plan the entry is checked against.
    pub enrollment: EnrollmentId,
    /// The pair the certificate is for (must be the plan's).
    pub pair: AccessPair,
    /// The CA that will sign it (must be the plan's).
    pub ca_fingerprint: CaFingerprint,
    /// Positive or negative.
    pub purpose: VerificationPurpose,
    /// The principal (`hm:<destination-id>:<account>` or the negative form).
    pub principal: String,
    /// Key ID.
    pub key_id: String,
    /// Validity start.
    pub valid_after: Timestamp,
    /// Validity end.
    pub valid_before: Timestamp,
    /// Extensions (must be empty).
    pub extensions: BTreeSet<String>,
    /// Fingerprint of K_verify.
    pub subject_fingerprint: String,
    /// K_verify is registered by this operation's verification endpoint.
    pub subject_registered: bool,
}

/// The store facts of the verifying operation.
struct OperationFacts {
    operation: VerifyingOperation,
    plan_pair: AccessPair,
    plan_ca: CaFingerprint,
    attempts: u32,
    entries_in_attempt: u32,
}

/// Read the operation facts (module docs). `Err` refuses before the predicate runs:
/// an unknown operation or enrollment is `OperationNotVerifying`. `counting_new`
/// adds the entry being reserved to the attempt's count.
fn operation_facts(
    tx: &mut Txn<'_>,
    operation: &OperationId,
    enrollment: &EnrollmentId,
    counting_new: bool,
) -> heimdall_store::Result<Result<OperationFacts, VerificationRefusal>> {
    let Some(op) = tx.operation(operation)? else {
        return Ok(Err(VerificationRefusal::OperationNotVerifying));
    };
    let Some(record) = tx.enrollment(enrollment)? else {
        return Ok(Err(VerificationRefusal::OperationNotVerifying));
    };
    // ⟨M03⟩ wave 4 (§17.21 item 5): each verification has its own predicate, from
    // the store (`enrollment_m03::verification_authority`): wave 0's presence check
    // by the stored request, the system form's absence check, an `enrollment.apply`'s
    // initial verification and a target change's. The authority must name this
    // enrollment, and the operation must be at that verification's own stage.
    let authority = super::enrollment_m03::verification_authority(tx, &op)?;
    let receipts = tx.stage_receipts(operation)?;
    let starts: Vec<Timestamp> = receipts
        .iter()
        .filter(|r| r.stage == enrollment_stage::VERIFY_STARTED)
        .map(|r| r.recorded_at)
        .collect();
    let attempts = u32::try_from(starts.len()).unwrap_or(u32::MAX);
    let (authorized, at_verification_stage) = match &authority {
        Some(a) if a.enrollment == *enrollment => (a.authorized, a.at_stage && attempts > 0),
        _ => (false, false),
    };
    let entries_in_attempt = match starts.iter().max() {
        Some(last) => {
            let n = tx
                .verification_entries(operation)?
                .iter()
                .filter(|e| e.reserved_at >= *last)
                .count();
            u32::try_from(n)
                .unwrap_or(u32::MAX)
                .saturating_add(u32::from(counting_new))
        }
        None => u32::from(counting_new),
    };
    Ok(Ok(OperationFacts {
        operation: VerifyingOperation {
            kind: op.kind,
            authorized,
            at_verification_stage,
        },
        plan_pair: AccessPair {
            destination: record.destination,
            account: record.account,
        },
        plan_ca: record.ca_fingerprint,
        attempts,
        entries_in_attempt,
    }))
}

/// The predicate over `entry_pair`/`bounds` with the operation facts.
#[allow(clippy::too_many_arguments)]
fn run_check(
    facts: &OperationFacts,
    entry_pair: &AccessPair,
    purpose: VerificationPurpose,
    bounds: &CertificateBounds,
    subject_registered: bool,
    time: TimeStatus,
    now: Timestamp,
    max_validity: std::time::Duration,
) -> Result<(), VerificationRefusal> {
    check(&VerificationCheck {
        operation: facts.operation,
        entry_pair,
        plan_pair: &facts.plan_pair,
        plan_ca: &facts.plan_ca,
        purpose,
        bounds,
        subject_registered,
        time,
        now,
        max_validity,
        entries_in_attempt: facts.entries_in_attempt,
        attempts: facts.attempts,
    })
}

/// ⟨M03⟩ U3 (ADR-0008 D3 item 4 step 2): the verification predicate over the stored
/// `entry`, read-only, for the issuer child and the signing admission: the same
/// [`operation_facts`] and [`run_check`] as [`Operations::publish_verification`]. The
/// enrollment is the one the operation's own verification authority names (§17.21
/// item 5); an operation with none is refused `operation_not_verifying`. Reads only.
pub(crate) fn verification_check_read_only(
    tx: &mut Txn<'_>,
    entry: &VerificationEntry,
    subject_registered: bool,
    time: TimeStatus,
    now: Timestamp,
    max_validity: std::time::Duration,
) -> heimdall_store::Result<Result<(), VerificationRefusal>> {
    // The enrollment the operation's own verification authority names (§17.21
    // item 5): its stored `enrollment.verify` request, or an `enrollment.apply`'s
    // journal.
    let enrollment = match tx.operation(&entry.operation)? {
        Some(op) => super::enrollment_m03::verification_authority(tx, &op)?.map(|a| a.enrollment),
        None => None,
    };
    let Some(enrollment) = enrollment else {
        return Ok(Err(VerificationRefusal::OperationNotVerifying));
    };
    Ok(
        match operation_facts(tx, &entry.operation, &enrollment, false)? {
            Ok(facts) => run_check(
                &facts,
                &entry.pair,
                entry.purpose,
                &entry.bounds,
                subject_registered,
                time,
                now,
                max_validity,
            ),
            Err(refused) => Err(refused),
        },
    )
}

fn not_reserved_here() -> OpError {
    OpError::new(
        Code::CredentialExpired,
        "this verification entry was not reserved by this runtime instance; reserve afresh",
    )
    .with_resource("issuance", None)
}

impl Operations {
    /// ⟨M03⟩ U0b row 4: reserve a verification certificate (module docs): every
    /// predicate of `verification::check` against current store state and time
    /// assessed inside the transaction, then the `reserved` entry with complete
    /// bounds. The inner `Err` is the predicate's refusal; nothing is written then.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store) or `INTERNAL_ERROR` (no randomness).
    pub async fn reserve_verification(
        &self,
        req: VerificationRequest,
    ) -> Result<Result<VerificationEntry, VerificationRefusal>, OpError> {
        let id = crate::ids::new_issuance_id()?;
        let serial = crate::ids::random_u64()?;
        let gate = self.inner.timegate.in_txn();
        let max_validity = self.inner.config.limits.verification_max_validity;
        let tracked = ReservedVerification {
            operation: req.operation.clone(),
            enrollment: req.enrollment.clone(),
        };
        let r = self
            .write(move |tx, _| {
                let (_, time, now) = issuance_time(&gate, tx)?;
                let facts = match operation_facts(tx, &req.operation, &req.enrollment, true)? {
                    Ok(f) => f,
                    Err(refused) => return Ok(Err(refused)),
                };
                let bounds = CertificateBounds {
                    serial,
                    key_id: req.key_id,
                    principal: req.principal,
                    valid_after: req.valid_after,
                    valid_before: req.valid_before,
                    extensions: req.extensions,
                    subject_fingerprint: req.subject_fingerprint,
                    ca_fingerprint: Some(req.ca_fingerprint),
                };
                if let Err(refused) = run_check(
                    &facts,
                    &req.pair,
                    req.purpose,
                    &bounds,
                    req.subject_registered,
                    time,
                    now,
                    max_validity,
                ) {
                    return Ok(Err(refused));
                }
                let entry = VerificationEntry {
                    id,
                    operation: req.operation,
                    pair: req.pair,
                    purpose: req.purpose,
                    bounds,
                    state: IssuanceState::Reserved,
                    reserved_at: now,
                    settled_at: None,
                    void_reason: None,
                };
                tx.reserve_verification(&entry)?;
                Ok(Ok(entry))
            })
            .await?;
        if let Ok(entry) = &r {
            self.inner
                .managed_ops
                .track_verification(entry.id.clone(), tracked);
        }
        Ok(r)
    }

    /// ⟨M03⟩ U0b row 4: publish a verification entry reserved by **this** runtime
    /// instance: every predicate again, with current state and time assessed in the
    /// publishing transaction. On a refusal the entry is `voided` with that reason
    /// (the inner `Err`) and nothing may be released.
    ///
    /// # Errors
    /// `CREDENTIAL_EXPIRED` for an entry this instance did not reserve (it stays
    /// reserved and counted until its `valid_before`); `REQUEST_CONFLICT` for an
    /// entry already settled; `STATE_UNAVAILABLE` (store).
    pub async fn publish_verification(
        &self,
        id: &IssuanceId,
        subject_registered: bool,
    ) -> Result<Result<VerificationEntry, VerificationRefusal>, OpError> {
        let Some(tracked) = self.inner.managed_ops.reserved_verification(id) else {
            return Err(not_reserved_here());
        };
        let gate = self.inner.timegate.in_txn();
        let max_validity = self.inner.config.limits.verification_max_validity;
        let entry_id = id.clone();
        let r = self
            .write(move |tx, _| {
                let (_, time, now) = issuance_time(&gate, tx)?;
                let Some(entry) = tx
                    .verification_entries(&tracked.operation)?
                    .into_iter()
                    .find(|e| e.id == entry_id)
                else {
                    return Ok(Err(OpError::new(
                        Code::NotFound,
                        "unknown verification entry",
                    )));
                };
                if entry.state != IssuanceState::Reserved {
                    return Ok(Err(OpError::new(
                        Code::RequestConflict,
                        "the verification entry is already settled",
                    )));
                }
                let verdict =
                    match operation_facts(tx, &tracked.operation, &tracked.enrollment, false)? {
                        Ok(facts) => run_check(
                            &facts,
                            &entry.pair,
                            entry.purpose,
                            &entry.bounds,
                            subject_registered,
                            time,
                            now,
                            max_validity,
                        ),
                        Err(refused) => Err(refused),
                    };
                Ok(Ok(match verdict {
                    Ok(()) => Ok(tx.publish_verification(&entry_id, now)?),
                    Err(refused) => {
                        tx.void_verification(&entry_id, refused, now)?;
                        Err(refused)
                    }
                }))
            })
            .await?;
        self.inner.managed_ops.settle_verification(id);
        r
    }

    /// ⟨M03⟩ U0b row 4: void a verification entry reserved by this runtime instance
    /// (the issuer could not sign it, or the attempt was abandoned), with `reason`.
    ///
    /// # Errors
    /// As [`Operations::publish_verification`].
    pub async fn void_verification(
        &self,
        id: &IssuanceId,
        reason: VerificationRefusal,
    ) -> Result<VerificationEntry, OpError> {
        let Some(tracked) = self.inner.managed_ops.reserved_verification(id) else {
            return Err(not_reserved_here());
        };
        let gate = self.inner.timegate.in_txn();
        let entry_id = id.clone();
        let r = self
            .write(move |tx, _| {
                let (_, _, now) = issuance_time(&gate, tx)?;
                let reserved = tx
                    .verification_entries(&tracked.operation)?
                    .into_iter()
                    .any(|e| e.id == entry_id && e.state == IssuanceState::Reserved);
                if !reserved {
                    return Ok(Err(OpError::new(
                        Code::RequestConflict,
                        "the verification entry is not reserved",
                    )));
                }
                Ok(Ok(tx.void_verification(&entry_id, reason, now)?))
            })
            .await?;
        self.inner.managed_ops.settle_verification(id);
        r
    }

    /// ⟨M03⟩ ADR-0008 D7 item 4: the per-pair residual, the latest `valid_before`
    /// over the pair's reserved and published grant **and** verification entries
    /// under `ca` (`None`: every CA). Read-only.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store).
    pub async fn pair_residual(
        &self,
        pair: &AccessPair,
        ca: Option<&CaFingerprint>,
    ) -> Result<Option<Timestamp>, OpError> {
        let pair = pair.clone();
        let ca = ca.cloned();
        self.write(move |tx, _| tx.pair_residual(&pair, ca.as_ref()))
            .await
    }
}
