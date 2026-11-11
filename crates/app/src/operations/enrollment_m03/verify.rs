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

use heimdall_contract::enrollment::{EnrollmentForm, EnrollmentNext, EnrollmentState};
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::OperationId;
use heimdall_contract::managed::ClockMeasurement;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::enrollment::{
    EnrollmentEventKind, EnrollmentEvidence, EnrollmentHold, HoldReason, ReverifyFrom,
};
use heimdall_domain::issuance::principal_for;
use heimdall_domain::operation::{EffectReceipt, enrollment_stage};
use heimdall_domain::verification::{
    ClassifyContext, InconclusiveReason, KnownOffset, VerificationPhase, VerificationPurpose,
    VerificationRefusal, VerificationVerdict,
};

use super::super::{Operations, internal};
use super::steps::{Ctx, load_ctx};
use super::{
    adapter, move_record, pair_of, put_journal, receipt, record_preference, result_of, settle_ok,
    settle_open, store_conflict,
};
use crate::enrollment::plan_of_record;
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
                        let data = serde_json::to_value(result_of(&ctx.record, None))
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
                        let data = serde_json::to_value(result_of(&ctx.record, next))
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
