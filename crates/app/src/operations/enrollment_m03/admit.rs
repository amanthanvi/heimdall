//! Admission of the journaled enrollment operations (`apply`, `verify`, `remove`),
//! each in **one** store transaction with its record and decision (ADR-0008 D5 §6.4
//! E0), and the completion of the enrollment decision kinds inside `decide`'s
//! transaction (`decisions_m03`).

use std::collections::BTreeSet;

use heimdall_contract::enrollment::{
    EnrollmentForm, EnrollmentRequest, EnrollmentSpec, EnrollmentState, RemovalTarget, VerifyMode,
};
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::ids::{EnrollmentId, OperationId, RequestId};
use heimdall_contract::request::{InteractionMode, Request, RequiredCapabilities, Verdict};
use heimdall_contract::setup::PlanDigest;
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::decision::{
    DecisionKind, DecisionRecord, DecisionState, EnrollmentPlanSummary,
};
use heimdall_domain::enrollment::{
    EnrollmentEventKind, EnrollmentRecord, ExistingAccessRecord, HoldKind, RemovalOrigin,
    ReverifyFrom,
};
use heimdall_domain::idempotency::{
    HashInput, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, classify, compute_hash,
};
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{
    OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata,
};
use heimdall_store::Txn;

use super::super::{Emit, Operations, internal, op_to, settle_failed};
use super::{
    affected_grants, emit_record, journal_of, move_record, open_operation_of, pair_of, put_journal,
    refuse, result_of, settle_ok, stale_preview, store_conflict, unknown_enrollment,
};
use crate::context::Caller;
use crate::enrollment::{ApprovalFact, Journal, endpoint_ref, proposed_target, tag_of};
use crate::error::{OpError, OpResult};

/// The idempotency classification in the caller's transaction (no write):
/// `Ok(None)` for new work, `Ok(Some(id))` for a replay, `Err` for a conflicting reuse.
/// Every refusal of an admission is decided after this and **before** [`insert_op`],
/// so a refused request writes nothing.
fn replay_in(
    tx: &mut Txn<'_>,
    key: &IdempotencyKey,
    hash: heimdall_contract::canonical::RequestHash,
    now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationId>, OpError>> {
    let key_hash = key
        .hash()
        .map_err(|_| store_conflict("the idempotency key cannot be hashed"))?;
    let record = tx.idempotency_record(key)?;
    let marker = tx.expired_key_marker(&key_hash)?;
    Ok(
        match classify(record.as_ref(), marker.as_ref(), hash, now) {
            IdempotencyOutcome::New => Ok(None),
            IdempotencyOutcome::Replay(id) => Ok(Some(id)),
            other => Err(Operations::refuse_outcome(&other)
                .unwrap_or_else(|| internal("unexpected idempotency outcome"))),
        },
    )
}

/// Insert a new operation (`Queued`) with its recovery intent, in the caller's
/// transaction (the M01 admission, minus the pipeline receipt).
#[allow(clippy::too_many_arguments)]
fn insert_op(
    tx: &mut Txn<'_>,
    key: &IdempotencyKey,
    hash: heimdall_contract::canonical::RequestHash,
    kind: OperationKind,
    request: &Request,
    environment: &heimdall_contract::ids::EnvironmentId,
    id: OperationId,
    now: Timestamp,
) -> heimdall_store::Result<OperationRecord> {
    let op = OperationRecord {
        id: id.clone(),
        kind,
        environment: environment.clone(),
        key: key.clone(),
        request_hash: hash,
        effect_class: kind
            .m03_effect_class()
            .unwrap_or(heimdall_domain::operation::EffectClass::Local),
        state: OperationState::Queued,
        code: None,
        effect_status: EffectStatus::None,
        result: None,
        created_at: now,
        updated_at: now,
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    tx.insert_operation(
        &op,
        &IdempotencyRecord {
            key: key.clone(),
            request_hash: hash,
            operation_id: id.clone(),
            created_at: now,
            expires_at: None,
        },
    )?;
    tx.set_recovery_intent(
        &id,
        &RecoveryIntent {
            request: serde_json::to_value(request)
                .map_err(|_| store_conflict("the request cannot be stored"))?,
            resolved: None,
            local: None,
        },
    )?;
    Ok(op)
}

/// The request hash of an enrollment kind: the environment and the kind's fields.
fn hash_of(
    kind: OperationKind,
    environment: &heimdall_contract::ids::EnvironmentId,
    extra: serde_json::Value,
) -> Result<heimdall_contract::canonical::RequestHash, OpError> {
    let scope = BTreeSet::new();
    let required = RequiredCapabilities::default();
    compute_hash(
        kind,
        &HashInput {
            environment,
            profile: None,
            profile_revision: None,
            scope: &scope,
            deadline_intent: None,
            work_id: None,
            required_capabilities: &required,
            parent_binding: None,
            extra,
        },
    )
    .map_err(|_| internal("the request cannot be hashed"))
}

/// A fresh decision record of `kind`.
fn decision(
    tx: &mut Txn<'_>,
    id: heimdall_contract::ids::DecisionId,
    kind: DecisionKind,
    now: Timestamp,
    lifetime: std::time::Duration,
) -> heimdall_store::Result<DecisionRecord> {
    Ok(DecisionRecord {
        id,
        kind,
        generation: tx.authority_generation()?,
        created_at: now,
        expires_at: super::super::plus(now, lifetime),
        state: DecisionState::Pending,
        decided_at: None,
    })
}

/// Move a queued operation to `awaiting_approval` with its decision.
fn await_decision(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    record: &DecisionRecord,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    tx.insert_decision(record)?;
    op_to(op, OperationEvent::ApprovalNeeded, now)?;
    tx.update_operation(op)?;
    emit.op(tx, op)?;
    emit.decision(tx, record, Some(&op.id))
}

impl Operations {
    /// `enrollment.apply` (E0): replay, recall the previewed plan, recompute it,
    /// then in one transaction: the operation, the `planned` record, the
    /// `EnrollAccount` (or `EnrollSystemForm`) decision and the journal. Answers
    /// `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED` with the decision.
    pub(super) async fn enroll_apply(
        &self,
        caller: &Caller,
        spec: EnrollmentSpec,
        digest: PlanDigest,
        request_id: RequestId,
        interaction: InteractionMode,
    ) -> OpResult<serde_json::Value> {
        let ports = self.enrollment_ports()?;
        let kind = OperationKind::EnrollmentApply;
        let environment = self.environment().clone();
        let hash = hash_of(
            kind,
            &environment,
            serde_json::json!({ "spec": spec, "plan_digest": digest }),
        )?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id: request_id.clone(),
        };
        let now = self.timegate().check().await?.wall();
        // Replays and conflicting reuses first: a replay never recomputes anything.
        {
            let (k, h) = (key.clone(), hash);
            let outcome = self
                .write(move |tx, _| {
                    let key_hash = k.hash().map_err(|_| store_conflict("key hash"))?;
                    let record = tx.idempotency_record(&k)?;
                    let marker = tx.expired_key_marker(&key_hash)?;
                    Ok(classify(record.as_ref(), marker.as_ref(), h, now))
                })
                .await?;
            match outcome {
                IdempotencyOutcome::New => {}
                IdempotencyOutcome::Replay(id) => {
                    return self.enrollment_respond(&id, caller).await;
                }
                other => {
                    return Err(Operations::refuse_outcome(&other)
                        .unwrap_or_else(|| internal("unexpected idempotency outcome")));
                }
            }
        }
        let Some(previewed) = self.inner.managed_ops.enrollment.recall(&digest) else {
            return Err(stale_preview());
        };
        if previewed.spec != spec {
            return Err(stale_preview());
        }
        let plan = self
            .enrollment_plan(&ports, &spec, &previewed.enrollment)
            .await?;
        if plan.plan_digest != digest {
            return Err(stale_preview());
        }
        let request = Request::Enrollment(EnrollmentRequest::Apply {
            spec: spec.clone(),
            plan_digest: digest.clone(),
            request_id,
            interaction,
            wait: heimdall_contract::request::WaitMode::default(),
        });
        let op_id = crate::ids::new_operation_id().map_err(|_| internal("randomness"))?;
        let decision_id = crate::ids::new_decision_id().map_err(|_| internal("randomness"))?;
        let lifetime = self.limits().decision_lifetime;
        let enrollment = previewed.enrollment.clone();
        let canonical = heimdall_contract::enrollment::RegistryCanonical {
            path: spec.registry_path.clone(),
            resolved_by: plan.registry.resolved_by,
        };
        let pk_file = None::<String>;
        let r = self
            .write(move |tx, emit| {
                match replay_in(tx, &key, hash, now)? {
                    Ok(None) => {}
                    Ok(Some(id)) => return Ok(Ok(Err(id))),
                    Err(e) => return Ok(Err(e)),
                }
                // D5 §6.1: no live enrollment for the (pair, CA) (the store's index rule).
                let pair = heimdall_domain::scope::AccessPair {
                    destination: plan.destination_id.clone(),
                    account: plan.account.clone(),
                };
                let live = tx.enrollments_for_pair(&pair)?.into_iter().any(|e| {
                    e.ca_fingerprint == plan.ca_fingerprint
                        && heimdall_registry::plan::PairEnrollment {
                            ca_fingerprint: e.ca_fingerprint.clone(),
                            state: e.state,
                            removal_origin_set: e.removal_origin.is_some(),
                        }
                        .live()
                });
                if live {
                    return Ok(Err(refuse(
                        Code::ConfigConflict,
                        heimdall_contract::envelope::reason::ALREADY_ENROLLED,
                        "the pair is already enrolled under this CA",
                    )));
                }
                let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                let identity = plan.existing_access.identity_id.clone();
                let public_key_file = match tx.identity(&identity)?.map(|i| i.source) {
                    Some(heimdall_domain::catalog::IdentitySource::PublicKeyFile { path }) => {
                        Some(path.replace('\\', "/"))
                    }
                    _ => pk_file,
                };
                let record = EnrollmentRecord {
                    id: enrollment.clone(),
                    destination: plan.destination_id.clone(),
                    account: plan.account.clone(),
                    ca_fingerprint: plan.ca_fingerprint.clone(),
                    form: plan.form,
                    marker: heimdall_domain::enrollment::marker_for(&enrollment),
                    registry: plan.registry.clone(),
                    registry_canonical: canonical,
                    line_sha256: plan.line_sha256.clone(),
                    target: plan.approved_target.clone(),
                    existing_access: ExistingAccessRecord {
                        identity,
                        endpoint: Some(endpoint_ref(&plan.existing_access.endpoint)),
                        public_key_file,
                    },
                    hold: None,
                    removal_origin: None,
                    late_write: None,
                    state: EnrollmentState::Planned,
                    verified_at: None,
                    evidence: None,
                    created_at: now,
                    updated_at: now,
                };
                tx.insert_enrollment(&record)?;
                emit_record(tx, emit, &record, Some(&op.id))?;
                let summary = EnrollmentPlanSummary::from_plan(&plan);
                let kind = match plan.form {
                    EnrollmentForm::System => DecisionKind::EnrollSystemForm {
                        operation: op.id.clone(),
                        plan_digest: plan.plan_digest.clone(),
                        summary,
                        sshd_lines: crate::enrollment::system_form_lines(
                            plan.line
                                .split_once(' ')
                                .map_or("", |(_, rest)| rest)
                                .rsplit_once(' ')
                                .map_or("", |(k, _)| k),
                            &plan.verification.positive_principal,
                        ),
                    },
                    _ => DecisionKind::EnrollAccount {
                        operation: op.id.clone(),
                        plan_digest: plan.plan_digest.clone(),
                        summary,
                    },
                };
                let d = decision(tx, decision_id, kind, now, lifetime)?;
                await_decision(tx, emit, &mut op, &d, now)?;
                put_journal(
                    tx,
                    &op.id,
                    &Journal {
                        enrollment: Some(enrollment.clone()),
                        interactive: interaction == InteractionMode::Interactive,
                        tag: Some(tag_of(&enrollment)),
                        ..Journal::default()
                    },
                    now,
                )?;
                Ok(Ok(Ok(op.id)))
            })
            .await;
        let id = match r?? {
            Ok(id) | Err(id) => id,
        };
        self.enrollment_respond(&id, caller).await
    }

    /// `enrollment.verify` (ADR-0008 D5 §6.5, §6.9; §17.7 item 5): presence (a
    /// re-verification of a verified or evidence-held pair, the system form's
    /// verification, an initial verification after the approval lapsed), absence
    /// (the system form's manual removal), or a target change (which needs
    /// `ApproveTargetChange`). Never removes anything.
    pub(super) async fn enroll_verify(
        &self,
        caller: &Caller,
        enrollment: EnrollmentId,
        request_id: RequestId,
        mode: VerifyMode,
    ) -> OpResult<serde_json::Value> {
        let ports = self.verification_ports()?;
        let kind = OperationKind::EnrollmentVerify;
        let environment = self.environment().clone();
        let hash = hash_of(
            kind,
            &environment,
            serde_json::json!({ "enrollment_id": enrollment, "mode": mode }),
        )?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id: request_id.clone(),
        };
        let now = self.narrowing_now().await;
        // A target change evaluates the target first (no write).
        let proposed = if mode == VerifyMode::TargetChange {
            let eid = enrollment.clone();
            let found = self
                .write(move |tx, _| {
                    let Some(r) = tx.enrollment(&eid)? else {
                        return Ok(None);
                    };
                    let alias = tx.destination(&r.destination)?.map(|d| d.alias);
                    Ok(alias.map(|a| (r, a)))
                })
                .await?;
            let Some((record, alias)) = found else {
                return Err(unknown_enrollment());
            };
            let target = ports
                .wiring
                .target
                .as_ref()
                .ok_or_else(|| OpError::driver_unavailable("no target evaluator"))?;
            let evaluation = target.evaluate(&alias);
            match proposed_target(&record.target, &evaluation) {
                Some(p) => Some(p),
                None => {
                    return Err(refuse(
                        Code::CapabilityUnavailable,
                        heimdall_contract::envelope::reason::HOST_TRUST_UNDETERMINED,
                        "the target evaluates to no single new host key; nothing to approve",
                    ));
                }
            }
        } else {
            None
        };
        let request = Request::Enrollment(EnrollmentRequest::Verify {
            enrollment_id: enrollment.clone(),
            request_id,
            mode,
            wait: heimdall_contract::request::WaitMode::default(),
        });
        let op_id = crate::ids::new_operation_id().map_err(|_| internal("randomness"))?;
        let decision_id = crate::ids::new_decision_id().map_err(|_| internal("randomness"))?;
        let lifetime = self.limits().decision_lifetime;
        let validity = self.limits().enrollment_approval_validity;
        let retention = self.retention();
        let attended = caller.is_attended();
        let r = self
            .write(move |tx, emit| {
                match replay_in(tx, &key, hash, now)? {
                    Ok(None) => {}
                    Ok(Some(id)) => return Ok(Ok((id, false))),
                    Err(e) => return Ok(Err(e)),
                }
                let Some(record) = tx.enrollment(&enrollment)? else {
                    // A foreign system-form record's absence check (Q28): this device
                    // holds no key of the removed CA, so it ends inconclusive
                    // (`ca_not_held`), the record back in `manual_removal_pending` with
                    // that fact pinned; it is never reported removed.
                    let foreign = tx
                        .foreign_removals_by_marker(&heimdall_domain::enrollment::marker_for(&enrollment))?
                        .into_iter()
                        .rev()
                        .find(|f| f.state == EnrollmentState::ManualRemovalPending);
                    let (Some(f), VerifyMode::Absence) = (foreign, mode) else {
                        return Ok(Err(unknown_enrollment()));
                    };
                    let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                    let checking = tx
                        .transition_foreign_removal(
                            f.state,
                            EnrollmentEventKind::OwnerConfirmsRemoved,
                            &f,
                        )?
                        .map_err(|e| store_conflict(&e.to_string()))?;
                    let mut updated = checking.clone();
                    if let Some(o) = updated.removal_origin.as_mut() {
                        o.ca_not_held_seen = true;
                    }
                    tx.transition_foreign_removal(
                        checking.state,
                        EnrollmentEventKind::AbsenceNotVerified,
                        &updated,
                    )?
                    .map_err(|e| store_conflict(&e.to_string()))?;
                    put_journal(
                        tx,
                        &op.id,
                        &Journal {
                            foreign: Some(f.id.clone()),
                            mode: Some(mode),
                            ..Journal::default()
                        },
                        now,
                    )?;
                    let err = super::verify::verdict_error(
                        heimdall_domain::verification::VerificationVerdict::Inconclusive {
                            reason: heimdall_domain::verification::InconclusiveReason::CaNotHeld,
                        },
                    );
                    op_to(&mut op, OperationEvent::Start, now)?;
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    return Ok(Ok((op.id, false)));
                };
                use EnrollmentState as S;
                let hold = record.hold.map(|h| h.kind());
                let mut journal = Journal {
                    enrollment: Some(record.id.clone()),
                    mode: Some(mode),
                    tag: Some(tag_of(&record.id)),
                    ..Journal::default()
                };
                let mut updated = record.clone();
                updated.updated_at = now;
                let event = match (mode, record.state) {
                    (VerifyMode::Presence, S::Verified) => {
                        journal.reverify_from = Some(ReverifyFrom::Verified);
                        EnrollmentEventKind::StartReverification
                    }
                    (VerifyMode::Presence, S::Held) if hold == Some(HoldKind::EvidenceBased) => {
                        journal.reverify_from = Some(ReverifyFrom::Held);
                        EnrollmentEventKind::OwnerReverify {
                            hold: HoldKind::EvidenceBased,
                        }
                    }
                    (VerifyMode::Presence, S::ManualPending) => EnrollmentEventKind::OwnerConfirmsApplied,
                    (VerifyMode::Presence, S::AppliedUnverified) => {
                        // Through reconcile while the `enrollment.apply` approval is
                        // valid (B R2-06); through `enroll verify` after it lapsed.
                        if let Some((open, j)) = open_operation_of(tx, &record.id)?
                            && open.kind == OperationKind::EnrollmentApply
                            && j.approval_valid(now, validity)
                        {
                            return Ok(Err(OpError::new(
                                Code::ConfigConflict,
                                "the enrollment's approval is still valid: retry the verification with `enroll reconcile`",
                            )
                            .with_next(super::next("reconcile", Some(&open.id)))
                            .with_effect(EffectStatus::None)));
                        }
                        EnrollmentEventKind::StartVerification
                    }
                    (VerifyMode::Absence, S::ManualRemovalPending) => EnrollmentEventKind::OwnerConfirmsRemoved,
                    (VerifyMode::TargetChange, S::Held) if hold == Some(HoldKind::HostKeyChanged) => {
                        journal.reverify_from = Some(ReverifyFrom::Held);
                        journal.proposed_target = proposed.clone();
                        let Some(p) = proposed.clone() else {
                            return Ok(Err(internal("no proposed target")));
                        };
                        let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                        let d = decision(
                            tx,
                            decision_id,
                            DecisionKind::ApproveTargetChange {
                                operation: op.id.clone(),
                                enrollment: record.id.clone(),
                                approved: record.target.clone(),
                                proposed: p,
                            },
                            now,
                            lifetime,
                        )?;
                        await_decision(tx, emit, &mut op, &d, now)?;
                        put_journal(tx, &op.id, &journal, now)?;
                        return Ok(Ok((op.id, false)));
                    }
                    _ => {
                        return Ok(Err(refuse(
                            Code::ConfigConflict,
                            "enrollment_state",
                            "this verification does not apply to the enrollment's current state",
                        )));
                    }
                };
                let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                op_to(&mut op, OperationEvent::Start, now)?;
                tx.update_operation(&op)?;
                emit.op(tx, &op)?;
                move_record(tx, emit, record.state, event, &updated, Some(&op.id))?;
                put_journal(tx, &op.id, &journal, now)?;
                Ok(Ok((op.id, true)))
            })
            .await??;
        let (id, run) = r;
        let _ = attended;
        if run {
            self.verify_operation(&id).await?;
        }
        self.enrollment_respond(&id, caller).await
    }

    /// `enrollment.remove` (ADR-0008 D5 §6.8, §6.9; D4 item 5): an account-form
    /// enrollment needs `RemoveEnrollment` (with the affected grants and the residual);
    /// a system-form one moves to `manual_removal_pending` on the owner's typed
    /// confirmation (the request itself), changing nothing remote; a foreign target
    /// goes through `foreign_remove`.
    pub(super) async fn enroll_remove(
        &self,
        caller: &Caller,
        target: RemovalTarget,
        request_id: RequestId,
        interaction: InteractionMode,
    ) -> OpResult<serde_json::Value> {
        let ports = self.enrollment_ports()?;
        let kind = OperationKind::EnrollmentRemove;
        let environment = self.environment().clone();
        let enrollment = match &target {
            RemovalTarget::Enrollment { enrollment_id } => enrollment_id.clone(),
            RemovalTarget::Foreign(t) => {
                return self
                    .enroll_remove_foreign(caller, t.clone(), request_id, interaction)
                    .await;
            }
            _ => {
                return Err(OpError::new(
                    Code::UsageError,
                    "this removal target is not supported",
                ));
            }
        };
        let hash = hash_of(kind, &environment, serde_json::json!({ "target": target }))?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id: request_id.clone(),
        };
        let now = self.narrowing_now().await;
        // A held host-key change carries a freshly evaluated target (D5 §6.8).
        let eid = enrollment.clone();
        let found = self
            .write(move |tx, _| {
                let Some(r) = tx.enrollment(&eid)? else {
                    return Ok(None);
                };
                let alias = tx.destination(&r.destination)?.map(|d| d.alias);
                Ok(Some((r, alias)))
            })
            .await?;
        let Some((record0, alias)) = found else {
            return Err(unknown_enrollment());
        };
        if record0.form == EnrollmentForm::System && !caller.context.is_owner() {
            return Err(super::not_owner());
        }
        let fresh = match (record0.hold.map(|h| h.kind()), alias) {
            (Some(HoldKind::HostKeyChanged), Some(alias)) => ports
                .wiring
                .target
                .as_ref()
                .and_then(|t| proposed_target(&record0.target, &t.evaluate(&alias))),
            _ => None,
        };
        let request = Request::Enrollment(EnrollmentRequest::Remove {
            target: target.clone(),
            request_id,
            interaction,
            wait: heimdall_contract::request::WaitMode::default(),
        });
        let op_id = crate::ids::new_operation_id().map_err(|_| internal("randomness"))?;
        let decision_id = crate::ids::new_decision_id().map_err(|_| internal("randomness"))?;
        let lifetime = self.limits().decision_lifetime;
        let retention = self.retention();
        let r = self
            .write(move |tx, emit| {
                match replay_in(tx, &key, hash, now)? {
                    Ok(None) => {}
                    Ok(Some(id)) => return Ok(Ok(id)),
                    Err(e) => return Ok(Err(e)),
                }
                let Some(record) = tx.enrollment(&enrollment)? else {
                    return Ok(Err(unknown_enrollment()));
                };
                use EnrollmentState as S;
                let journal = Journal {
                    enrollment: Some(record.id.clone()),
                    interactive: interaction == InteractionMode::Interactive,
                    fresh_target: fresh.clone(),
                    tag: Some(tag_of(&record.id)),
                    ..Journal::default()
                };
                if record.form == EnrollmentForm::System {
                    // D5 §6.9: no decision; the typed confirmation moves it, with the
                    // origin (state and evidence) persisted (§17.4 item 5).
                    let mut updated = record.clone();
                    updated.updated_at = now;
                    let event = match record.state {
                        S::Verified | S::Held | S::Abandoned => {
                            updated.removal_origin = Some(RemovalOrigin {
                                state: record.state,
                                evidence: record.evidence.clone(),
                                hold: record.hold,
                                ca_not_held_seen: false,
                            });
                            EnrollmentEventKind::ManualRemovalConfirmed
                        }
                        S::ManualPending => {
                            updated.removal_origin = Some(RemovalOrigin {
                                state: S::ManualPending,
                                evidence: None,
                                hold: None,
                                ca_not_held_seen: false,
                            });
                            EnrollmentEventKind::OwnerCancelsManualEnrollment
                        }
                        _ => {
                            return Ok(Err(refuse(
                                Code::ConfigConflict,
                                "enrollment_state",
                                "this enrollment cannot be removed in its current state",
                            )));
                        }
                    };
                    let mut op =
                        insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                    let moved = move_record(tx, emit, record.state, event, &updated, Some(&op.id))?;
                    put_journal(tx, &op.id, &journal, now)?;
                    let ca_key =
                        super::ca_public_key(tx, &record.ca_fingerprint)?.unwrap_or_default();
                    let lines = crate::enrollment::system_form_lines(
                        &ca_key,
                        &heimdall_domain::issuance::principal_for(&pair_of(&record)),
                    );
                    let mut result = result_of(&moved, None);
                    result.instructions = vec![
                        format!(
                            "delete the TrustedUserCAKeys line: {}",
                            lines.trusted_user_ca_keys_line
                        ),
                        format!(
                            "delete the principals-file line for {}: {}",
                            record.account, lines.principals_line
                        ),
                        format!(
                            "then confirm with: heimdall enroll verify {} --absence",
                            record.id
                        ),
                    ];
                    // The manual removal's operation stays open until the absence
                    // check settles it, or the owner cancels it (`cancel`).
                    op_to(&mut op, OperationEvent::Start, now)?;
                    op.result =
                        Some(serde_json::to_value(&result).map_err(|_| store_conflict("result"))?);
                    tx.update_operation(&op)?;
                    emit.op(tx, &op)?;
                    let _ = retention;
                    return Ok(Ok(op.id));
                }
                if !matches!(
                    record.state,
                    S::Verified | S::Held | S::AppliedUnverified | S::Abandoned
                ) {
                    return Ok(Err(refuse(
                        Code::ConfigConflict,
                        "enrollment_state",
                        "this enrollment cannot be removed in its current state",
                    )));
                }
                let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                let pair = pair_of(&record);
                let affected = affected_grants(tx, &record.ca_fingerprint, &pair)?;
                let residual = tx.pair_residual(&pair, Some(&record.ca_fingerprint))?;
                let invocation = match (
                    &record.existing_access.endpoint,
                    &record.existing_access.public_key_file,
                ) {
                    (Some(e), file) => heimdall_registry::step::access_pins(
                        &e.locator,
                        file.as_deref().unwrap_or("/identity.pub"),
                    )
                    .map(|p| heimdall_registry::step::render_invocation(&p))
                    .unwrap_or_default(),
                    _ => Vec::new(),
                };
                let d = decision(
                    tx,
                    decision_id,
                    DecisionKind::RemoveEnrollment {
                        operation: op.id.clone(),
                        target: RemovalTarget::Enrollment {
                            enrollment_id: record.id.clone(),
                        },
                        invocation,
                        affected_grants: affected,
                        pair_residual_until: residual,
                        fresh_target: fresh.clone(),
                    },
                    now,
                    lifetime,
                )?;
                await_decision(tx, emit, &mut op, &d, now)?;
                put_journal(tx, &op.id, &journal, now)?;
                Ok(Ok(op.id))
            })
            .await??;
        self.manual_or_respond(&r, caller).await
    }

    /// A running manual removal answers its instructions (the operation stays open);
    /// anything else answers as [`Operations::enrollment_respond`].
    async fn manual_or_respond(
        &self,
        id: &OperationId,
        caller: &Caller,
    ) -> OpResult<serde_json::Value> {
        let oid = id.clone();
        let op = self.write(move |tx, _| tx.operation(&oid)).await?;
        if let Some(op) = op
            && op.state == OperationState::Running
            && op.kind == OperationKind::EnrollmentRemove
            && let Some(data) = op.result.clone()
        {
            return Ok(crate::error::Completed {
                operation_id: Some(op.id.clone()),
                state: op.state,
                code: Code::Ok,
                data,
                warnings: Vec::new(),
                next: None,
            });
        }
        self.enrollment_respond(id, caller).await
    }
}

/// The waiting operation an enrollment decision names, and its journal.
fn waiting_of(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
) -> heimdall_store::Result<Option<(OperationRecord, Journal)>> {
    let Some(op_id) = super::decision_operation(&d.kind) else {
        return Ok(None);
    };
    let Some(op) = tx.operation(op_id)? else {
        return Ok(None);
    };
    let receipts = tx.stage_receipts(&op.id)?;
    Ok(journal_of(&receipts).map(|j| (op, j)))
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg)
}

/// `decisions_m03::precheck` for the enrollment kinds: the waiting operation is
/// `awaiting_approval` with its kind, and the record is in the state the decision was
/// issued for. Anything else is `DECISION_STALE` with nothing written.
pub(super) fn decision_precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    _verdict: Verdict,
    _now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    let Some((op, journal)) = waiting_of(tx, d)? else {
        return Ok(Err(stale(
            "the decision names no waiting enrollment operation",
        )));
    };
    let kind_ok = match &d.kind {
        DecisionKind::EnrollAccount { .. } | DecisionKind::EnrollSystemForm { .. } => {
            op.kind == OperationKind::EnrollmentApply
        }
        DecisionKind::RemoveEnrollment { .. } => op.kind == OperationKind::EnrollmentRemove,
        DecisionKind::ApproveTargetChange { .. } => op.kind == OperationKind::EnrollmentVerify,
        _ => false,
    };
    if !kind_ok || op.state != OperationState::AwaitingApproval {
        return Ok(Err(stale(
            "the operation is no longer awaiting this decision",
        )));
    }
    if let Some(fid) = journal.foreign.clone() {
        // D4 item 5, §17.7 item 4: a foreign record is admitted `planned → removing`.
        let ok = matches!(&d.kind, DecisionKind::RemoveEnrollment { .. })
            && tx.foreign_removal(&fid)?.is_some_and(|f| {
                matches!(f.state, EnrollmentState::Planned | EnrollmentState::Held)
                    && f.target.form == EnrollmentForm::Account
            });
        if !ok {
            return Ok(Err(stale(
                "the foreign removal is no longer in the state this decision was issued for",
            )));
        }
        return Ok(Ok(Some(op)));
    }
    let Some(eid) = journal.enrollment.clone() else {
        return Ok(Err(stale("the operation names no enrollment")));
    };
    let Some(record) = tx.enrollment(&eid)? else {
        return Ok(Err(stale("the enrollment is gone")));
    };
    use EnrollmentState as S;
    let state_ok = match &d.kind {
        DecisionKind::EnrollAccount { .. } => {
            record.state == S::Planned && record.form == EnrollmentForm::Account
        }
        DecisionKind::EnrollSystemForm { .. } => {
            record.state == S::Planned && record.form == EnrollmentForm::System
        }
        DecisionKind::RemoveEnrollment { .. } => matches!(
            record.state,
            S::Verified | S::Held | S::AppliedUnverified | S::Abandoned
        ),
        DecisionKind::ApproveTargetChange { approved, .. } => {
            record.state == S::Held
                && record.hold.map(|h| h.kind()) == Some(HoldKind::HostKeyChanged)
                && &record.target == approved
        }
        _ => false,
    };
    if !state_ok {
        return Ok(Err(stale(
            "the enrollment is no longer in the state this decision was issued for",
        )));
    }
    Ok(Ok(Some(op)))
}

/// `decisions_m03::apply` for the enrollment kinds (same transaction as the
/// completion; module docs).
#[allow(clippy::too_many_arguments)]
pub(super) fn decision_apply(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    waiting: Option<OperationRecord>,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    let Some(mut op) = waiting else {
        return Ok(Err(stale(
            "the decision names no waiting enrollment operation",
        )));
    };
    let receipts = tx.stage_receipts(&op.id)?;
    let Some(mut journal) = journal_of(&receipts) else {
        return Ok(Err(stale("the operation has no journal")));
    };
    if let Some(fid) = journal.foreign.clone() {
        let Some(mut f) = tx.foreign_removal(&fid)? else {
            return Ok(Err(stale("the foreign removal is gone")));
        };
        f.operation = op.id.clone();
        let event = if verdict == Verdict::Approve {
            Some(EnrollmentEventKind::RemoveEnrollmentApproved)
        } else if f.state == EnrollmentState::Planned {
            Some(EnrollmentEventKind::DecisionWithdrawn)
        } else {
            None
        };
        if let Some(event) = event {
            tx.transition_foreign_removal(f.state, event, &f)?
                .map_err(|e| store_conflict(&e.to_string()))?;
        }
        if verdict == Verdict::Approve {
            journal.approval = Some(ApprovalFact {
                decision: record.id.clone(),
                at: now,
            });
            op_to(&mut op, OperationEvent::Approved, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
            put_journal(tx, &op.id, &journal, now)?;
        } else {
            let err = OpError::new(
                Code::CapabilityUnavailable,
                "the owner denied the foreign removal; nothing remote was touched",
            )
            .with_effect(EffectStatus::None);
            settle_failed(tx, emit, &mut op, &err, now, retention)?;
        }
        return Ok(Ok(Vec::new()));
    }
    let Some(eid) = journal.enrollment.clone() else {
        return Ok(Err(stale("the operation names no enrollment")));
    };
    let Some(enrollment) = tx.enrollment(&eid)? else {
        return Ok(Err(stale("the enrollment is gone")));
    };
    let mut updated = enrollment.clone();
    updated.updated_at = now;
    if verdict == Verdict::Deny {
        let err = OpError::new(
            Code::CapabilityUnavailable,
            "the owner denied the enrollment decision",
        )
        .with_effect(EffectStatus::None);
        if enrollment.state == EnrollmentState::Planned {
            move_record(
                tx,
                emit,
                EnrollmentState::Planned,
                EnrollmentEventKind::DecisionWithdrawn,
                &updated,
                Some(&op.id),
            )?;
        }
        settle_failed(tx, emit, &mut op, &err, now, retention)?;
        return Ok(Ok(Vec::new()));
    }
    journal.approval = Some(ApprovalFact {
        decision: record.id.clone(),
        at: now,
    });
    match &record.kind {
        DecisionKind::EnrollAccount { .. } => {
            move_record(
                tx,
                emit,
                EnrollmentState::Planned,
                EnrollmentEventKind::EnrollAccountApproved,
                &updated,
                Some(&op.id),
            )?;
            op_to(&mut op, OperationEvent::Approved, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
            put_journal(tx, &op.id, &journal, now)?;
        }
        DecisionKind::EnrollSystemForm { sshd_lines, .. } => {
            let moved = move_record(
                tx,
                emit,
                EnrollmentState::Planned,
                EnrollmentEventKind::EnrollSystemFormApproved,
                &updated,
                Some(&op.id),
            )?;
            put_journal(tx, &op.id, &journal, now)?;
            let mut result = result_of(&moved, None);
            result.instructions = vec![
                format!(
                    "add to the TrustedUserCAKeys file: {}",
                    sshd_lines.trusted_user_ca_keys_line
                ),
                format!(
                    "add to the account's AuthorizedPrincipalsFile: {}",
                    sshd_lines.principals_line
                ),
            ];
            result
                .instructions
                .extend(sshd_lines.sshd_directives.iter().cloned());
            result.instructions.push(format!(
                "then confirm with: heimdall enroll verify {}",
                moved.id
            ));
            let data = serde_json::to_value(&result).map_err(|_| store_conflict("result"))?;
            settle_ok(tx, emit, &mut op, data, now, retention)?;
        }
        DecisionKind::RemoveEnrollment { fresh_target, .. } => {
            journal.fresh_target = fresh_target.clone();
            move_record(
                tx,
                emit,
                enrollment.state,
                EnrollmentEventKind::RemoveEnrollmentApproved,
                &updated,
                Some(&op.id),
            )?;
            op_to(&mut op, OperationEvent::Approved, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
            put_journal(tx, &op.id, &journal, now)?;
        }
        DecisionKind::ApproveTargetChange { proposed, .. } => {
            journal.proposed_target = Some(proposed.clone());
            journal.reverify_from = Some(ReverifyFrom::Held);
            move_record(
                tx,
                emit,
                EnrollmentState::Held,
                EnrollmentEventKind::TargetChangeApproved {
                    hold: HoldKind::HostKeyChanged,
                },
                &updated,
                Some(&op.id),
            )?;
            op_to(&mut op, OperationEvent::Approved, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
            put_journal(tx, &op.id, &journal, now)?;
        }
        _ => return Ok(Err(stale("not an enrollment decision"))),
    }
    Ok(Ok(Vec::new()))
}

impl Operations {
    /// `enrollment.remove` of a foreign enrollment (ADR-0008 D4 item 5; §17.4 item 10,
    /// §17.7 item 4): the descriptor from a recovery bundle. Before anything is
    /// written: a redacted bundle is refused (`bundle_redacted`); the line is rebuilt
    /// from the descriptor and must match its `line_sha256`; the local alias's
    /// evaluated `HostName` and `Port` must equal the bundle's byte for byte
    /// (`bundle_host_mismatch`), with exactly one host key (the removal's target); the
    /// alias's existing access must name a concrete endpoint. Then the record is
    /// `planned`: the account form waits for `RemoveEnrollment` (`planned →
    /// removing`, and the removal sub-machine keyed by marker), the system form moves
    /// on this typed confirmation to `manual_removal_pending` (origin `planned`).
    pub(super) async fn enroll_remove_foreign(
        &self,
        caller: &Caller,
        t: heimdall_contract::enrollment::ForeignRemovalTarget,
        request_id: RequestId,
        interaction: InteractionMode,
    ) -> OpResult<serde_json::Value> {
        use heimdall_contract::envelope::reason as r;
        let ports = self.enrollment_ports()?;
        if t.form == EnrollmentForm::System && !caller.context.is_owner() {
            return Err(super::not_owner());
        }
        if t.bundle_hostname.is_empty() {
            return Err(refuse(
                Code::CapabilityUnavailable,
                r::BUNDLE_REDACTED,
                "the recovery bundle is redacted: a foreign removal needs the bundle's host name",
            ));
        }
        // The line, rebuilt and digest-checked before connecting.
        let rebuilt = heimdall_contract::ids::DestinationId::parse(&t.bundle_destination_id)
            .ok()
            .and_then(|d| heimdall_registry::line::principal(&d, &t.account).ok())
            .and_then(|p| {
                heimdall_registry::line::expected_line(&t.ca_public_key, &p, &t.marker).ok()
            });
        let line_ok = rebuilt.as_ref().is_some_and(|l| {
            heimdall_domain::projection::Sha256Hex::of(l.as_bytes()).as_str() == t.line_sha256
        });
        if !line_ok {
            return Err(OpError::new(
                Code::UsageError,
                "the foreign descriptor's line does not match its line_sha256",
            )
            .with_effect(EffectStatus::None));
        }
        let alias = t.local_alias.clone();
        let found = self
            .write(move |tx, _| {
                let Some(d) = tx.destination_by_alias(&alias)? else {
                    return Ok(None);
                };
                let heimdall_domain::catalog::DestinationDefinition::Managed { identity, .. } =
                    &d.definition
                else {
                    return Ok(None);
                };
                Ok(tx.identity(identity)?.map(|i| (d.clone(), i)))
            })
            .await?;
        let Some((_dest, identity)) = found else {
            return Err(refuse(
                Code::CapabilityUnavailable,
                r::OBSERVED_ALIAS_UNMANAGED,
                "the local alias is not a managed destination with an adopted identity",
            ));
        };
        if identity.source.endpoint().is_none() {
            return Err(refuse(
                Code::CapabilityUnavailable,
                r::EXISTING_ACCESS_ENDPOINT_UNRECORDED,
                "the local alias's identity names no existing-access endpoint",
            ));
        }
        let evaluator = ports
            .wiring
            .target
            .as_ref()
            .ok_or_else(|| OpError::driver_unavailable("no target evaluator"))?;
        let evaluation = evaluator.evaluate(&t.local_alias);
        if evaluation.hostname != t.bundle_hostname || evaluation.port != t.bundle_port {
            return Err(refuse(
                Code::CapabilityUnavailable,
                r::BUNDLE_HOST_MISMATCH,
                "the local alias does not evaluate to the bundle's host name and port",
            ));
        }
        let live: Vec<_> = evaluation.host_keys.iter().filter(|k| !k.revoked).collect();
        let fresh = match live.as_slice() {
            [k] if evaluation.determinism
                == heimdall_domain::enrollment::Determinism::Determined
                && evaluation.proxy == heimdall_domain::enrollment::ProxyRoute::None
                && heimdall_registry::step::host_key_algorithms(&k.key_type).is_some() =>
            {
                let Ok(user) = heimdall_contract::ids::AccountName::parse(&evaluation.user) else {
                    return Err(refuse(
                        Code::CapabilityUnavailable,
                        r::ROUTE_UNDETERMINED,
                        "the local alias's user is undetermined",
                    ));
                };
                heimdall_contract::enrollment::ApprovedTarget {
                    hostname: evaluation.hostname.clone(),
                    port: evaluation.port,
                    user,
                    proxy: heimdall_contract::enrollment::NoProxy::None,
                    host_key: k.approved(),
                }
            }
            _ => {
                return Err(refuse(
                    Code::CapabilityUnavailable,
                    r::HOST_TRUST_UNDETERMINED,
                    "the local alias has not exactly one known host key",
                ));
            }
        };
        let kind = OperationKind::EnrollmentRemove;
        let environment = self.environment().clone();
        let target = RemovalTarget::Foreign(t.clone());
        let hash = hash_of(kind, &environment, serde_json::json!({ "target": target }))?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id: request_id.clone(),
        };
        let now = self.narrowing_now().await;
        let request = Request::Enrollment(EnrollmentRequest::Remove {
            target: target.clone(),
            request_id,
            interaction,
            wait: heimdall_contract::request::WaitMode::default(),
        });
        let op_id = crate::ids::new_operation_id().map_err(|_| internal("randomness"))?;
        let decision_id = crate::ids::new_decision_id().map_err(|_| internal("randomness"))?;
        let mut fb = [0u8; 16];
        getrandom::fill(&mut fb).map_err(|_| internal("randomness"))?;
        let fid = heimdall_contract::ids::ForeignRemovalId::from_random_bytes(fb);
        let lifetime = self.limits().decision_lifetime;
        let invocation = identity
            .source
            .endpoint()
            .and_then(|e| heimdall_registry::step::access_pins(&e.locator, "/identity.pub").ok())
            .map(|p| heimdall_registry::step::render_invocation(&p))
            .unwrap_or_default();
        let r = self
            .write(move |tx, emit| {
                match replay_in(tx, &key, hash, now)? {
                    Ok(None) => {}
                    Ok(Some(id)) => return Ok(Ok(id)),
                    Err(e) => return Ok(Err(e)),
                }
                let existing = tx
                    .foreign_removals_by_marker(&t.marker)?
                    .into_iter()
                    .rev()
                    .find(|f| !f.state.is_final() && f.state != EnrollmentState::Abandoned);
                // A held foreign record is recovered by a new decision (§17.7 item 4);
                // any other live one refuses a second removal.
                let held = match existing {
                    Some(f) if f.state == EnrollmentState::Held && t.form == EnrollmentForm::Account => Some(f),
                    Some(_) => {
                        return Ok(Err(refuse(
                            Code::ConfigConflict,
                            "foreign_removal_open",
                            "a removal of this foreign enrollment is already open",
                        )));
                    }
                    None => None,
                };
                let mut op = insert_op(tx, &key, hash, kind, &request, &environment, op_id, now)?;
                let record = match held {
                    Some(f) => f,
                    None => {
                        let record = heimdall_domain::enrollment::ForeignRemovalRecord {
                            id: fid.clone(),
                            target: t.clone(),
                            state: EnrollmentState::Planned,
                            operation: op.id.clone(),
                            created_at: now,
                            removal_origin: None,
                        };
                        tx.insert_foreign_removal(&record)?;
                        record
                    }
                };
                let fid = record.id.clone();
                let journal = Journal {
                    foreign: Some(fid.clone()),
                    interactive: interaction == InteractionMode::Interactive,
                    fresh_target: Some(fresh.clone()),
                    tag: Some(heimdall_registry::plan::trust_tag(
                        &heimdall_contract::ids::EnrollmentId::from_random_bytes(fb),
                    )),
                    ..Journal::default()
                };
                if t.form == EnrollmentForm::System {
                    let mut updated = record.clone();
                    updated.removal_origin = Some(RemovalOrigin {
                        state: EnrollmentState::Planned,
                        evidence: None,
                        hold: None,
                        ca_not_held_seen: false,
                    });
                    let moved = tx
                        .transition_foreign_removal(
                            EnrollmentState::Planned,
                            EnrollmentEventKind::ManualRemovalConfirmed,
                            &updated,
                        )?
                        .map_err(|e| store_conflict(&e.to_string()))?;
                    let _ = moved;
                    op_to(&mut op, OperationEvent::Start, now)?;
                    op.result = Some(serde_json::json!({
                        "foreign_removal_id": fid,
                        "state": EnrollmentState::ManualRemovalPending,
                        "instructions": [
                            format!("delete from the TrustedUserCAKeys file: {}", t.ca_public_key.trim()),
                            format!(
                                "delete from {}'s AuthorizedPrincipalsFile: hm:{}:{}",
                                t.account, t.bundle_destination_id, t.account
                            ),
                        ],
                    }));
                    tx.update_operation(&op)?;
                    emit.op(tx, &op)?;
                    put_journal(tx, &op.id, &journal, now)?;
                    return Ok(Ok(op.id));
                }
                let d = decision(
                    tx,
                    decision_id,
                    DecisionKind::RemoveEnrollment {
                        operation: op.id.clone(),
                        target: RemovalTarget::Foreign(t.clone()),
                        invocation,
                        affected_grants: Vec::new(),
                        pair_residual_until: None,
                        fresh_target: Some(fresh.clone()),
                    },
                    now,
                    lifetime,
                )?;
                await_decision(tx, emit, &mut op, &d, now)?;
                put_journal(tx, &op.id, &journal, now)?;
                Ok(Ok(op.id))
            })
            .await??;
        self.manual_or_respond(&r, caller).await
    }
}
