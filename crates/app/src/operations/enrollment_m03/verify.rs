//! E4 and E5 (ADR-0008 D5 §6.4, §6.5; m03-plan U10 `run_verification`): the
//! verification runs **in the runtime**. Its endpoint comes from
//! `VerificationEndpoints::create(op, plan)` with a fresh K_verify; both certificates
//! are reserved and published through `Operations` and signed through `IssuerPort`;
//! the Verifier installs each one just before its attempt; the session is dropped
//! (zeroizing K_verify) on **every** exit path, because it lives only inside
//! [`Operations::run_verification`]'s scope. The verdict is
//! `heimdall_domain::verification::classify`'s, and the record moves in one
//! transaction with the outcome receipt; a pass commits E5 there too.

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::enrollment::{
    EnrollmentForm, EnrollmentNext, EnrollmentState, RemoteStage, VerifyMode,
};
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::OperationId;
use heimdall_contract::managed::ClockMeasurement;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::enrollment::{
    EnrollmentEventKind, EnrollmentEvidence, EnrollmentHold, EnrollmentRecord, HoldReason,
    LateWrite, ReverifyFrom,
};
use heimdall_domain::issuance::principal_for;
use heimdall_domain::operation::{EffectReceipt, OperationKind, OperationRecord, enrollment_stage};
use heimdall_domain::verification::{
    ClassifyContext, InconclusiveReason, KnownOffset, VerificationPhase, VerificationPurpose,
    VerificationRefusal, VerificationVerdict,
};
use heimdall_registry::classify::{Inspection, StepClass};
use heimdall_registry::hm1;
use heimdall_store::Txn;

use super::super::{Emit, Operations, internal};
use super::steps::{Ctx, load_ctx};
use super::{
    adapter, emit_record, move_record, pair_of, put_journal, receipt, record_preference,
    result_for, settle_ok, settle_open, store_conflict,
};
use crate::enrollment::{Journal, plan_of_record};
use crate::error::OpError;
use crate::operations::VerificationRequest;
use crate::ports::{IssuanceRef, IssuanceTable, VerificationOutcome};

/// What a verification run observed.
#[derive(Debug, Clone)]
pub(super) struct Observed {
    pub(super) outcome: VerificationOutcome,
    pub(super) clock: Option<ClockMeasurement>,
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    super::super::plus(t, d)
}

fn minus(t: Timestamp, d: Duration) -> Timestamp {
    super::super::minus(t, d)
}

/// A 32-hex nonce for the negative principal.
fn nonce() -> Result<String, OpError> {
    super::new_step_token()
}

impl Operations {
    /// Run the verification `id`'s record is at (`verifying`, `reverifying`,
    /// `removal_verifying`) and record its outcome. Nothing happens for a record in
    /// any other state.
    pub(super) async fn verify_operation(&self, id: &OperationId) -> Result<(), OpError> {
        let oid = id.clone();
        let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
        let phase = match ctx.record.state {
            EnrollmentState::Verifying => VerificationPhase::Initial,
            EnrollmentState::Reverifying => VerificationPhase::Reverify,
            EnrollmentState::RemovalVerifying => VerificationPhase::Initial,
            _ => return Ok(()),
        };
        let absence = ctx.record.state == EnrollmentState::RemovalVerifying;
        // ⟨round 3⟩ ADR-0008 §17.22 item 7 (D5 §6.5): a re-verification of the
        // approved target (no proposed target: not an `ApproveTargetChange`) whose
        // alias now evaluates to another host key for the same route is recorded as
        // the host-key mismatch it is, from the evaluation alone: no session, no
        // certificate, no login.
        if phase == VerificationPhase::Reverify
            && ctx.journal.proposed_target.is_none()
            && self.evaluated_host_key_changed(&ctx)
        {
            let observed = Observed {
                outcome: host_key_mismatch_outcome(),
                clock: None,
            };
            return self
                .record_verification(&ctx, phase, absence, &observed)
                .await;
        }
        let observed = self.run_verification(&ctx, absence).await;
        let observed = match observed {
            Ok(o) => o,
            Err(e) if e.code == Code::InternalError => return Err(e),
            Err(_) => Observed {
                outcome: VerificationOutcome::default(),
                clock: None,
            },
        };
        self.record_verification(&ctx, phase, absence, &observed)
            .await
    }

    /// ⟨ADR-0008 §17.28 item 3⟩ End a `late_write` absence check whose read could not
    /// be issued with `err` (no step outstanding; the residual is kept).
    pub(super) async fn settle_late_write_check(
        &self,
        id: &OperationId,
        err: &OpError,
    ) -> Result<(), OpError> {
        let (oid, err) = (id.clone(), err.clone());
        let retention = self.retention();
        let now = self.narrowing_now().await;
        self.write(move |tx, emit| {
            let Ok(mut ctx) = load_ctx(tx, &oid)? else {
                return Ok(());
            };
            if !late_write_ctx(&ctx) || ctx.journal.outstanding.is_some() {
                return Ok(());
            }
            let err = err.with_effect(EffectStatus::None);
            settle_open(tx, emit, &mut ctx.op, &err, now, retention)
        })
        .await
    }

    /// ⟨round 3⟩ Whether the runtime's target evaluator finds a host-key change of
    /// `ctx`'s approved target for its alias (the same route, another key; no
    /// evaluator or no alias: `false`, and the verification runs as before).
    fn evaluated_host_key_changed(&self, ctx: &Ctx) -> bool {
        let Ok(ports) = self.verification_ports() else {
            return false;
        };
        ports.wiring.target.as_ref().is_some_and(|t| {
            !ctx.alias.is_empty()
                && crate::enrollment::host_key_changed(&ctx.record.target, &t.evaluate(&ctx.alias))
        })
    }

    /// E4 (module docs). The session exists only in this function's scope, so it is
    /// dropped on every exit path (an early return, an error, a panic unwinding).
    pub(super) async fn run_verification(
        &self,
        ctx: &Ctx,
        absence: bool,
    ) -> Result<Observed, OpError> {
        let ports = self.verification_ports()?;
        let (Some(endpoints), Some(runner), Some(issuer)) = (
            ports.wiring.verification_endpoints.clone(),
            ports.wiring.verification_runner.clone(),
            ports.wiring.issuer.clone(),
        ) else {
            return Err(OpError::driver_unavailable("verification is not available"));
        };
        let target = ctx
            .journal
            .proposed_target
            .clone()
            .unwrap_or_else(|| ctx.record.target.clone());
        let tag = ctx
            .journal
            .tag
            .clone()
            .unwrap_or_else(|| crate::enrollment::tag_of(&ctx.record.id));
        let paths = ports
            .host
            .paths(&tag)
            .ok_or_else(|| OpError::driver_unavailable("the enrollment files are unavailable"))?;
        let plan = plan_of_record(
            &ctx.record,
            &target,
            &ctx.alias,
            &ctx.ca_key,
            &ctx.mechanism,
            &paths,
        )
        .ok_or_else(|| internal("the enrollment's plan cannot be rebuilt"))?;
        // `enroll.verify.started`: the attempt counts (at most 3 per operation).
        let (oid, now) = (ctx.op.id.clone(), self.narrowing_now().await);
        self.write(move |tx, _| {
            tx.append_stage_receipt(
                &oid,
                &receipt(
                    enrollment_stage::VERIFY_STARTED,
                    now,
                    EffectReceipt::NotAttempted,
                ),
            )
        })
        .await?;
        let session = endpoints
            .create(&ctx.op.id, &plan)
            .await
            .map_err(|e| OpError::from_adapter_for(&e, "verification"))?;
        let subject = session.public_key().to_owned();
        let subject_fp = crate::issuance_ro::subject_fingerprint(&subject)
            .ok_or_else(|| internal("the verification key is unreadable"))?;
        let pair = pair_of(&ctx.record);
        let wall = self.clock().wall();
        let max_validity = self.limits().verification_max_validity;
        let negative_principal = format!(
            "{}{}",
            heimdall_domain::verification::NEGATIVE_PRINCIPAL_PREFIX,
            nonce()?
        );
        let mut certs = Vec::new();
        for (purpose, principal) in [
            (VerificationPurpose::Positive, principal_for(&pair)),
            (VerificationPurpose::Negative, negative_principal),
        ] {
            if absence && purpose == VerificationPurpose::Negative {
                // The absence check needs only the positive certificate (§6.9); the
                // Verifier still runs a negative attempt, with the positive line.
                break;
            }
            let req = VerificationRequest {
                operation: ctx.op.id.clone(),
                enrollment: ctx.record.id.clone(),
                pair: pair.clone(),
                ca_fingerprint: ctx.record.ca_fingerprint.clone(),
                purpose,
                principal,
                key_id: format!(
                    "heimdall:{}:{}:{}",
                    self.environment(),
                    ctx.op.id,
                    match purpose {
                        VerificationPurpose::Positive => "positive",
                        _ => "negative",
                    }
                ),
                valid_after: minus(wall, heimdall_domain::verification::BACKDATE),
                valid_before: plus(wall, max_validity),
                extensions: BTreeSet::new(),
                subject_fingerprint: subject_fp.clone(),
                subject_registered: true,
            };
            let entry = match self.reserve_verification(req).await? {
                Ok(e) => e,
                Err(refused) => {
                    return Err(OpError::new(
                        Code::CapabilityUnavailable,
                        format!("the verification certificate was refused: {refused}"),
                    )
                    .with_reason(reason::VERIFICATION_INCONCLUSIVE));
                }
            };
            let signed = issuer
                .sign(
                    IssuanceRef {
                        table: IssuanceTable::Verification,
                        id: entry.id.clone(),
                    },
                    &subject,
                )
                .await;
            let line = match signed {
                Ok(l) => l,
                Err(_) => {
                    let _ = self
                        .void_verification(&entry.id, VerificationRefusal::OperationNotVerifying)
                        .await;
                    return Err(OpError::new(
                        Code::CapabilityUnavailable,
                        "the issuer did not sign the verification certificate",
                    )
                    .with_reason(reason::ISSUER_UNAVAILABLE));
                }
            };
            match self.publish_verification(&entry.id, true).await? {
                Ok(_) => certs.push(line),
                Err(refused) => {
                    return Err(OpError::new(
                        Code::CapabilityUnavailable,
                        format!("the verification certificate was not published: {refused}"),
                    )
                    .with_reason(reason::VERIFICATION_INCONCLUSIVE));
                }
            }
        }
        let positive = certs.first().cloned().unwrap_or_default();
        let negative = certs.get(1).cloned().unwrap_or_else(|| positive.clone());
        let t1 = self.clock().wall();
        let outcome = runner
            .run(&plan, &positive, &negative, session.as_ref())
            .await;
        let t2 = self.clock().wall();
        drop(session);
        // A conservative measurement: t1 before the run started and t2 after it
        // ended bound the Verifier's own reading from both sides (decision A-D2).
        let clock = outcome.positive.remote_now.and_then(|remote| {
            let t2_ms = i128::from(t2.as_millisecond());
            let behind = (t2_ms - i128::from(remote).saturating_mul(1000) + 1000).max(0);
            let rtt = (t2_ms - i128::from(t1.as_millisecond())).max(0);
            Some(ClockMeasurement {
                behind_upper_ms: u64::try_from(behind).ok()?,
                rtt_ms: u64::try_from(rtt).ok()?,
                measured_at: t2,
            })
        });
        Ok(Observed { outcome, clock })
    }

    /// Record a verification outcome (one transaction; D5 §6.2 `verifying`,
    /// `reverifying` and `removal_verifying` rows, §6.5 tables, E5).
    async fn record_verification(
        &self,
        ctx: &Ctx,
        phase: VerificationPhase,
        absence: bool,
        observed: &Observed,
    ) -> Result<(), OpError> {
        let limits = *self.limits();
        let offset = match phase {
            VerificationPhase::Initial => ctx.journal.remote_offset.map(|(o, u)| KnownOffset {
                remote_minus_local_ms: o,
                uncertainty_ms: u,
            }),
            _ => ctx
                .record
                .evidence
                .as_ref()
                .and_then(|e| e.clock.as_ref())
                .map(|c| KnownOffset {
                    remote_minus_local_ms: -i64::try_from(c.behind_upper_ms).unwrap_or(i64::MAX),
                    uncertainty_ms: c.rtt_ms.saturating_add(1000),
                }),
        };
        let cctx = ClassifyContext {
            unrecorded: observed.outcome.unrecorded,
            offset,
            skew_lag_ms: super::steps::ms(limits.verification_skew_lag),
            skew_lead_ms: super::steps::ms(limits.verification_skew_lead),
        };
        let verdict = heimdall_domain::verification::classify(
            &observed.outcome.positive,
            &observed.outcome.negative,
            phase,
            ctx.record.form,
            &cctx,
        );
        let absent = absence
            && heimdall_domain::verification::absence_verified(&observed.outcome.positive, &cctx);
        let (safe, safe_ok) = self.safe_now().await;
        let approval_valid = safe_ok
            && ctx
                .journal
                .approval_valid(safe, limits.enrollment_approval_validity);
        let retention = self.retention();
        let now = self.clock().wall();
        let freshness = limits.enrollment_evidence_freshness;
        let evidence = EnrollmentEvidence {
            client: observed.outcome.client.clone().unwrap_or_default(),
            server: observed
                .outcome
                .positive
                .trace
                .server_version
                .clone()
                .unwrap_or_default(),
            operation: ctx.op.id.clone(),
            verified_at: now,
            fresh_until: plus(now, freshness),
            clock: observed.clock,
        };
        let oid = ctx.op.id.clone();
        let degrade = self
            .write(move |tx, emit| {
                let Ok(mut ctx) = load_ctx(tx, &oid)? else {
                    return Ok(false);
                };
                tx.append_stage_receipt(
                    &oid,
                    &receipt(
                        enrollment_stage::VERIFY_OUTCOME,
                        now,
                        EffectReceipt::Confirmed {
                            adapter: adapter("verification"),
                            credential_ref: serde_json::to_string(&verdict)
                                .map_err(|_| store_conflict("verdict"))?,
                        },
                    ),
                )?;
                let mut updated = ctx.record.clone();
                updated.updated_at = now;
                let from = ctx.record.state;
                if absence {
                    let origin = ctx
                        .record
                        .removal_origin
                        .as_ref()
                        .map_or(EnrollmentState::Verified, |o| o.state);
                    let event = if absent {
                        EnrollmentEventKind::AbsenceVerified { origin }
                    } else {
                        EnrollmentEventKind::AbsenceNotVerified
                    };
                    if absent {
                        updated.removal_origin = None;
                        updated.evidence = None;
                        updated.verified_at = None;
                    }
                    ctx.record = move_record(tx, emit, from, event, &updated, Some(&oid))?;
                    if absent {
                        tx.remove_issuing_ca(&pair_of(&ctx.record), &ctx.record.ca_fingerprint, now)?;
                        let data = serde_json::to_value(result_for(&ctx.record, Some(&ctx.alias), None))
                            .map_err(|_| store_conflict("result"))?;
                        settle_ok(tx, emit, &mut ctx.op, data.clone(), now, retention)?;
                        // The manual removal's own operation settles with it.
                        for mut open in super::open_removals_of(tx, &ctx.record.id)? {
                            settle_ok(tx, emit, &mut open, data.clone(), now, retention)?;
                        }
                    } else {
                        let err = OpError::new(
                            Code::CapabilityUnavailable,
                            "the absence check did not verify that the trust is gone; the lines may still be installed",
                        )
                        .with_reason(reason::VERIFICATION_INCONCLUSIVE)
                        .with_effect(EffectStatus::None);
                        settle_open(tx, emit, &mut ctx.op, &err, now, retention)?;
                    }
                    put_journal(tx, &oid, &ctx.journal, now)?;
                    return Ok(false);
                }
                let mut degrade = false;
                let event = match from {
                    EnrollmentState::Verifying => EnrollmentEventKind::VerificationResult {
                        verdict,
                        approval_valid,
                    },
                    _ => EnrollmentEventKind::ReverificationResult {
                        from: ctx.journal.reverify_from.unwrap_or(ReverifyFrom::Verified),
                        verdict,
                    },
                };
                match verdict {
                    VerificationVerdict::Passed => {
                        updated.evidence = Some(evidence.clone());
                        updated.verified_at = Some(now);
                        updated.hold = None;
                        if let Some(p) = &ctx.journal.proposed_target {
                            // §17.7 item 5: the proposed target replaces the approved
                            // one only on a pass, with the move to `verified`.
                            updated.target = p.clone();
                        }
                    }
                    VerificationVerdict::HostKeyMismatch => {
                        if ctx.journal.proposed_target.is_none() {
                            updated.hold = Some(EnrollmentHold {
                                reason: HoldReason::HostKeyChanged,
                                evidence_based: false,
                            });
                        }
                    }
                    VerificationVerdict::PrincipalsNotEnforced | VerificationVerdict::PositiveRefused => {
                        let to_hold = !(from == EnrollmentState::Verifying
                            && ctx.record.form == EnrollmentForm::Account
                            && approval_valid)
                            && !(from == EnrollmentState::Verifying
                                && ctx.record.form == EnrollmentForm::System
                                && verdict == VerificationVerdict::PositiveRefused);
                        if to_hold && ctx.journal.proposed_target.is_none() {
                            updated.hold = Some(EnrollmentHold {
                                reason: if verdict == VerificationVerdict::PositiveRefused {
                                    HoldReason::PositiveRefused
                                } else {
                                    HoldReason::PrincipalsNotEnforced
                                },
                                evidence_based: true,
                            });
                        }
                    }
                    _ => {}
                }
                ctx.record = move_record(tx, emit, from, event, &updated, Some(&oid))?;
                let to = ctx.record.state;
                put_journal(tx, &oid, &ctx.journal, now)?;
                match to {
                    EnrollmentState::Verified if verdict == VerificationVerdict::Passed => {
                        // E5: the CA joins the pair's issuing set; the preference moves
                        // to `managed_certificate` + `projection: pending` only when the
                        // pair is not already managed with an applied projection (F05).
                        let pending =
                            record_preference(tx, &pair_of(&ctx.record), &ctx.record.ca_fingerprint, now)?;
                        let next = (pending && from == EnrollmentState::Verifying)
                            .then_some(EnrollmentNext::SetupApply);
                        let data = serde_json::to_value(result_for(&ctx.record, Some(&ctx.alias), next))
                            .map_err(|_| store_conflict("result"))?;
                        settle_ok(tx, emit, &mut ctx.op, data, now, retention)?;
                    }
                    EnrollmentState::Verified => {
                        // Re-verification inconclusive from `verified`: unchanged
                        // freshness, a doctor finding (`reverification_inconclusive`).
                        let err = verdict_error(verdict);
                        settle_open(tx, emit, &mut ctx.op, &err, now, retention)?;
                    }
                    EnrollmentState::RollbackPending => {
                        // The rollback runs through the operation's next steps.
                    }
                    EnrollmentState::AppliedUnverified if approval_valid => {
                        // B R2-06: the retry runs through `enroll reconcile`, under the
                        // still-open `enrollment.apply`.
                    }
                    EnrollmentState::Held => {
                        degrade = from == EnrollmentState::Reverifying;
                        let err = verdict_error(verdict);
                        settle_open(tx, emit, &mut ctx.op, &err, now, retention)?;
                    }
                    _ => {
                        let err = verdict_error(verdict);
                        settle_open(tx, emit, &mut ctx.op, &err, now, retention)?;
                    }
                }
                Ok(degrade && ctx.journal.reverify_from == Some(ReverifyFrom::Verified))
            })
            .await?;
        if degrade {
            // §6.5: a re-verification failure degrades the grants under that CA for
            // that pair (`pair_unenrolled`), through the narrowing protocol.
            self.degrade_grants_under_ca(&ctx.record.ca_fingerprint, &pair_of(&ctx.record))
                .await?;
        }
        Ok(())
    }
}

// --- ⟨ADR-0008 §17.28 item 3⟩ the `late_write` residual's absence check -------------
//
// D5 §6.7: the residual clears only when an `inspect` whose **destination clock
// reading** (the HM1 record's `remote_now`, epoch seconds on the destination) is
// strictly past the residual's `not_after_remote` (also destination-clock seconds,
// from `heimdall_registry::fence::not_after_remote`) shows no marker line and no lock
// with the residual's token. That is exactly `heimdall_registry::fence::late_write_cleared`;
// no local or safe wall time, and no drift allowance (`RESIDUAL_DRIFT_PPM` belongs to
// the revocation residual), enters it. The runtime Verifier's certificate check sees
// neither the lock nor the marker line, so it is not used here.
//
// `enroll verify <enrollment> --absence` on an account-form record carrying the
// residual (whatever its state: `withdrawn`, `abandoned`, and an abandoned record's
// later states) admits an `enrollment.verify` operation (attended callers only) that
// issues one client-executed `inspect` and settles with its result; the record's state
// never moves. Only an observed absence clears the residual, in the same transaction
// as the operation's result; every other outcome keeps it.

/// Whether `record` takes the `late_write` absence check (account form, carrying the
/// residual; the system form's absence check is §6.9's, from `manual_removal_pending`).
pub(super) fn late_write_checkable(record: &EnrollmentRecord) -> bool {
    record.form == EnrollmentForm::Account && record.late_write.is_some()
}

/// Whether `op` (with its journal) is a `late_write` absence check of an own record.
pub(super) fn is_late_write_check(op: &OperationRecord, j: &Journal) -> bool {
    op.kind == OperationKind::EnrollmentVerify
        && j.mode == Some(VerifyMode::Absence)
        && j.foreign.is_none()
}

/// Whether `ctx` is a `late_write` absence check (an absence verification of an
/// account-form record; the system form's never is).
pub(super) fn late_write_ctx(ctx: &Ctx) -> bool {
    ctx.foreign.is_none()
        && ctx.record.form == EnrollmentForm::Account
        && is_late_write_check(&ctx.op, &ctx.journal)
}

/// The answer of a check that kept the residual.
fn kept(msg: String) -> OpError {
    OpError::new(Code::CapabilityUnavailable, msg)
        .with_reason(reason::VERIFICATION_INCONCLUSIVE)
        .with_effect(EffectStatus::None)
}

/// Why `reading` does not clear `residual` (the first unmet condition of
/// `late_write_cleared`, in its order).
fn kept_because(reading: &Inspection, residual: &LateWrite, marker: &str, id: &str) -> OpError {
    use heimdall_registry::classify::{FileKind, LockReading};
    if reading.remote_now <= residual.not_after_remote {
        return kept(format!(
            "the residual's not-after (remote time {}) has not passed on the destination's clock (remote time {}); the late_write residual is kept: run `heimdall enroll verify {id} --absence` again after it",
            residual.not_after_remote, reading.remote_now
        ));
    }
    let lock_ours = match &reading.lock {
        LockReading::None => false,
        LockReading::Held(h) => h.token == residual.step_token,
        _ => true,
    };
    if lock_ours {
        return kept(
            "the uncertain append's lock (or an unreadable lock record) is still present; the late_write residual is kept".to_owned(),
        );
    }
    if !matches!(reading.file, FileKind::Regular | FileKind::Absent) {
        return kept(
            "the registry could not be read as a regular file; the late_write residual is kept"
                .to_owned(),
        );
    }
    let present = reading.marker_lines > 0
        || reading
            .preimage()
            .is_none_or(|c| heimdall_registry::line::marker_lines(c, marker) > 0);
    if present {
        return kept(format!(
            "the registry holds this enrollment's marker line: the uncertain append may have landed; the late_write residual is kept. Remove the line with `heimdall enroll remove {id}`"
        ));
    }
    kept("the inspection did not establish absence; the late_write residual is kept".to_owned())
}

/// The answer of an inspection that did not complete.
fn not_inspected(class: StepClass) -> OpError {
    let (code, why) = match class {
        StepClass::HostTrustChanged => {
            (Code::HostTrustChanged, reason::ENROLLMENT_HOST_KEY_MISMATCH)
        }
        StepClass::ProviderLocked => (Code::ProviderLocked, "provider_locked"),
        StepClass::InteractionRequired => (Code::InteractionRequired, "interaction_required"),
        _ => (
            Code::CapabilityUnavailable,
            reason::VERIFICATION_INCONCLUSIVE,
        ),
    };
    OpError::new(
        code,
        "the registry inspection did not complete; the late_write residual is kept",
    )
    .with_reason(why)
    .with_effect(EffectStatus::None)
}

/// Record the check's step result (one transaction, the caller's): an absence observed
/// after the not-after clears the residual and settles the operation succeeded; any
/// other result keeps it and settles the operation failed. A settled operation (a
/// superseded check) records nothing more.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_late_write_check(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    stage: RemoteStage,
    class: StepClass,
    stdout: &str,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<()> {
    if stage == RemoteStage::Inspect {
        tx.append_stage_receipt(
            &ctx.op.id,
            &receipt(
                enrollment_stage::INSPECT_OBSERVED,
                now,
                EffectReceipt::NotAttempted,
            ),
        )?;
    }
    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
    if ctx.op.state.is_settled() {
        return Ok(());
    }
    let marker = ctx.record.marker.clone();
    let id = ctx.record.id.to_string();
    let reading = (stage == RemoteStage::Inspect && class == StepClass::Confirmed)
        .then(|| {
            hm1::parse(stdout.as_bytes())
                .ok()
                .and_then(|rec| Inspection::from_record(&rec, &marker).ok())
        })
        .flatten();
    let Some(reading) = reading else {
        return settle_open(tx, emit, &mut ctx.op, &not_inspected(class), now, retention);
    };
    let Some(residual) = ctx.record.late_write.clone() else {
        // Already cleared (by an earlier check): nothing more to observe.
        let data = serde_json::to_value(result_for(&ctx.record, Some(&ctx.alias), None))
            .map_err(|_| store_conflict("result"))?;
        return settle_ok(tx, emit, &mut ctx.op, data, now, retention);
    };
    if !heimdall_registry::fence::late_write_cleared(&reading, &residual, &marker) {
        let err = kept_because(&reading, &residual, &marker, &id);
        return settle_open(tx, emit, &mut ctx.op, &err, now, retention);
    }
    let Some(cleared) =
        tx.clear_late_write(&ctx.record.id, ctx.record.state, &residual.step_token, now)?
    else {
        let err = OpError::new(
            Code::ConfigConflict,
            "the enrollment changed during the check; the late_write residual is kept: run the check again",
        )
        .with_reason("enrollment_state")
        .with_effect(EffectStatus::None);
        return settle_open(tx, emit, &mut ctx.op, &err, now, retention);
    };
    emit_record(tx, emit, &cleared, Some(&ctx.op.id))?;
    ctx.record = cleared;
    let data = serde_json::to_value(result_for(&ctx.record, Some(&ctx.alias), None))
        .map_err(|_| store_conflict("result"))?;
    settle_ok(tx, emit, &mut ctx.op, data, now, retention)
}

/// ⟨round 3⟩ The outcome of a re-verification that never ran because the evaluation
/// already shows a host-key change: a host-key failure, no client, no signature
/// (`classify` reads it as `HostKeyMismatch`).
fn host_key_mismatch_outcome() -> VerificationOutcome {
    let attempt = heimdall_domain::verification::AttemptResult {
        trace: heimdall_domain::verification::TraceEvents {
            host_key_failure: true,
            ..Default::default()
        },
        ..Default::default()
    };
    VerificationOutcome {
        positive: attempt.clone(),
        negative: attempt,
        client: None,
        unrecorded: false,
    }
}

/// The answer a verdict that is not a pass stands for.
pub(super) fn verdict_error(v: VerificationVerdict) -> OpError {
    let (code, why, msg) = match v {
        VerificationVerdict::PrincipalsNotEnforced => (
            Code::CapabilityUnavailable,
            reason::PRINCIPALS_NOT_ENFORCED,
            "the negative certificate was accepted: the server does not enforce principals",
        ),
        VerificationVerdict::PositiveRefused => (
            Code::CapabilityUnavailable,
            reason::VERIFICATION_FAILED,
            "the positive certificate was refused: the registry is probably not the server's authoritative one, or certificates are unsupported",
        ),
        VerificationVerdict::HostKeyMismatch => (
            Code::HostTrustChanged,
            reason::ENROLLMENT_HOST_KEY_MISMATCH,
            "the destination's host key is not the approved one; review the host trust",
        ),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::DestinationClockSkew,
        } => (
            Code::CapabilityUnavailable,
            reason::DESTINATION_CLOCK_SKEW,
            "the refusal may come from the destination's clock skew; nothing was rolled back",
        ),
        VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::CaNotHeld,
        } => (
            Code::CapabilityUnavailable,
            reason::CA_NOT_HELD,
            "this device holds no key of the removed CA; the absence cannot be verified",
        ),
        _ => (
            Code::CapabilityUnavailable,
            reason::VERIFICATION_INCONCLUSIVE,
            "the verification was inconclusive",
        ),
    };
    OpError::new(code, msg)
        .with_reason(why)
        .with_effect(EffectStatus::None)
}
