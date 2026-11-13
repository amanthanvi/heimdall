//! ⟨M03⟩ wave 4 (U10): the enrollment stage driver over the store (ADR-0008 D5
//! §6.4–§6.9; m03-plan U10 "Interfaces"): `enrollment.preview`, `apply`, `verify`,
//! `remove`, `reconcile`, `abandon`, `step`, `step_result`; the completion of the
//! enrollment decision kinds; the supervisor's re-verification and step-timeout
//! passes. The public, pure part is [`crate::enrollment`].
//!
//! **The journal.** An enrollment operation's durable facts ([`Journal`]: the
//! enrollment it drives, its approval, the outstanding step, the latest inspect
//! reading, the counters) are appended as stage receipts named
//! [`JOURNAL_STAGE`], each carrying the whole journal as JSON in the
//! `Confirmed.credential_ref` of the adapter `{mechanism: "enrollment", instance:
//! "journal"}`; the last one is current (questions file A-Q1: the frozen
//! `StageReceipt` has no typed slot for it). Beside them, the ADR-0008 D5 §6.4 stage
//! receipts are written as the table names them: `enroll.inspect.started`, and
//! `Attempted` for `enroll.bootstrap` (effect token = marker + `:dir`),
//! `enroll.append` (the marker) and `enroll.rollback` / `enroll.remove` (marker +
//! `:rm`), then `Confirmed` or `Uncertain`; `enroll.verify.started` and
//! `enroll.verify.outcome`. The cancellation rule reads those.
//!
//! **Fail closed.** A missing port (the target evaluator, the issuer, the
//! verification factory or runner, the [`EnrollmentHost`]) refuses with
//! `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, before any write.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use heimdall_contract::enrollment::{
    EnrollmentEvidenceView, EnrollmentNext, EnrollmentNote, EnrollmentNoteKind, EnrollmentPlan,
    EnrollmentRequest, EnrollmentResult, EnrollmentSpec, EnrollmentState, EnrollmentView,
    EnrollmentsView, TargetSummary, VerifyMode,
};
use heimdall_contract::envelope::{EffectStatus, NextAction, reason};
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{CaFingerprint, EnrollmentId, GrantId, OperationId};
use heimdall_contract::managed::{EnrollmentEventPayload, PreferredMechanism};
use heimdall_contract::request::Verdict;
use heimdall_contract::setup::PlanDigest;
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord};
use heimdall_domain::enrollment::{
    CatalogView, EnrollmentEventKind, EnrollmentRecord, LateWrite, PairPreference, ProjectionStatus,
};
use heimdall_domain::issuance::IssuanceState;
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, OperationKind, OperationRecord, StageReceipt,
};
use heimdall_domain::scope::AccessPair;
use heimdall_registry::plan::{CaView, CaViewEntry, PairEnrollment, PlanContext};
use heimdall_store::{StoreError, Txn};

use super::{
    Emit, Operations, approval_needed, internal, op_to, resource, settle_failed, settle_succeeded,
};
use crate::context::Caller;
use crate::enrollment::{EnrollmentHost, Journal, tag_of};
use crate::error::{Completed, OpError, OpResult};

mod admit;
mod passes;
mod steps;
mod verify;

/// The journal receipts' stage name (module docs).
pub(super) const JOURNAL_STAGE: &str = "enroll.journal";

/// The adapter identity of every enrollment receipt.
pub(super) fn adapter(instance: &str) -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "enrollment".to_owned(),
        instance: instance.to_owned(),
    }
}

/// A receipt of `stage` with `effect`.
pub(super) fn receipt(stage: &str, now: Timestamp, effect: EffectReceipt) -> StageReceipt {
    StageReceipt {
        stage: stage.to_owned(),
        recorded_at: now,
        effect,
        local: None,
    }
}

/// The current journal of an operation's receipts (the last journal receipt).
pub(super) fn journal_of(receipts: &[StageReceipt]) -> Option<Journal> {
    receipts
        .iter()
        .rev()
        .find_map(|r| match (&r.stage, &r.effect) {
            (s, EffectReceipt::Confirmed { credential_ref, .. }) if s == JOURNAL_STAGE => {
                serde_json::from_str(credential_ref).ok()
            }
            _ => None,
        })
}

/// Append `journal` as the operation's current journal.
pub(super) fn put_journal(
    tx: &mut Txn<'_>,
    op: &OperationId,
    journal: &Journal,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let payload = serde_json::to_string(journal)
        .map_err(|_| StoreError::GenerationConflict("the enrollment journal".to_owned()))?;
    tx.append_stage_receipt(
        op,
        &receipt(
            JOURNAL_STAGE,
            now,
            EffectReceipt::Confirmed {
                adapter: adapter("journal"),
                credential_ref: payload,
            },
        ),
    )
}

// --- per-instance state: the host port and the remembered previews --------------------

/// A remembered preview: the spec and the enrollment ID minted for it.
#[derive(Debug, Clone)]
struct Previewed {
    spec: EnrollmentSpec,
    enrollment: EnrollmentId,
}

/// How many previews a runtime remembers.
const PREVIEW_MEMORY: usize = 64;

/// How many inspected registries a runtime remembers (in memory only; §17.21 item 4).
const INSPECTED_MEMORY: usize = 16;

/// ⟨wave 4, integrator⟩ The enrollment driver's in-memory state of **this**
/// `Operations` instance (one field of its M03 state): the host port and the
/// remembered previews (the enrollment ID minted at preview, with its digest). A
/// restart forgets both, so an apply after it must preview again.
#[derive(Default)]
pub(super) struct EnrollmentProcessState {
    host: RwLock<Option<Arc<dyn EnrollmentHost>>>,
    previews: Mutex<VecDeque<(PlanDigest, Previewed)>>,
    /// ⟨round 2⟩ The full bytes of each operation's latest `inspect` reading, in
    /// memory only: the journal keeps the registry's digest and Heimdall's own
    /// lines (§17.21 item 4), and a removal's post-image needs the bytes. A restart
    /// forgets them, and the removal then inspects again.
    inspected: Mutex<VecDeque<(OperationId, Vec<u8>)>>,
    /// **Test configuration only** (debug builds; ADR-0008 §17.25 item 3, D13 item 3):
    /// the script pause directory the runtime was started with
    /// (`ManagedOptions::script_pause_dir`). `Some(Err(()))`: set, but not a usable
    /// [`PauseDir`](heimdall_registry::script::test_form::PauseDir), so every step is
    /// refused (a test that expects pauses never runs unpaused).
    #[cfg(debug_assertions)]
    script_pause: RwLock<Option<ScriptPause>>,
}

/// The test form's pause directory, or why it is unusable (debug builds).
#[cfg(debug_assertions)]
pub(super) type ScriptPause = Result<heimdall_registry::script::test_form::PauseDir, ()>;

impl EnrollmentProcessState {
    fn remember(&self, digest: &PlanDigest, p: Previewed) {
        let mut v = self.previews.lock().unwrap_or_else(PoisonError::into_inner);
        v.retain(|(d, _)| d != digest);
        v.push_back((digest.clone(), p));
        while v.len() > PREVIEW_MEMORY {
            v.pop_front();
        }
    }

    /// Remember `op`'s latest inspected registry bytes (replacing older ones).
    pub(super) fn remember_inspected(&self, op: &OperationId, content: Vec<u8>) {
        let mut v = self
            .inspected
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        v.retain(|(o, _)| o != op);
        v.push_back((op.clone(), content));
        while v.len() > INSPECTED_MEMORY {
            v.pop_front();
        }
    }

    /// `op`'s remembered registry bytes, if they are exactly `digest`'s image.
    pub(super) fn inspected(
        &self,
        op: &OperationId,
        digest: &crate::enrollment::RegistryDigest,
    ) -> Option<Vec<u8>> {
        self.inspected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(o, c)| o == op && digest.matches(c))
            .map(|(_, c)| c.clone())
    }

    fn recall(&self, digest: &PlanDigest) -> Option<Previewed> {
        self.previews
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(d, _)| d == digest)
            .map(|(_, p)| p.clone())
    }
}

// --- errors --------------------------------------------------------------------------------

fn refuse(code: Code, reason_name: &str, msg: &str) -> OpError {
    OpError::new(code, msg)
        .with_reason(reason_name)
        .with_effect(EffectStatus::None)
}

fn not_owner() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this enrollment action needs the owner role",
    )
    .with_effect(EffectStatus::None)
}

fn unknown_operation() -> OpError {
    OpError::new(Code::NotFound, "unknown enrollment operation").with_resource("operation", None)
}

fn unknown_enrollment() -> OpError {
    OpError::new(Code::NotFound, "unknown enrollment").with_resource("enrollment", None)
}

fn stale_preview() -> OpError {
    OpError::new(
        Code::ConfigConflict,
        "the enrollment preview is stale: the catalog, the route, the CA or the pair changed since the plan was shown; preview again",
    )
    .with_effect(EffectStatus::None)
}

fn store_conflict(msg: &str) -> StoreError {
    StoreError::GenerationConflict(msg.to_owned())
}

fn next(action: &str, op: Option<&OperationId>) -> NextAction {
    NextAction {
        action: action.to_owned(),
        operation_id: op.cloned(),
        ..NextAction::default()
    }
}

/// What the ports give the driver, checked before anything is written.
pub(super) struct Ports {
    pub(super) wiring: Arc<crate::managed::ManagedWiring>,
    pub(super) host: Arc<dyn EnrollmentHost>,
}

impl Operations {
    /// ⟨M03 wave 4⟩ Install the [`EnrollmentHost`] the enrollment driver uses (the
    /// runtime's, or a test's), for this `Operations` instance. Without it every
    /// enrollment action that needs it fails closed (`driver_unavailable`).
    pub fn set_enrollment_host(&self, host: Arc<dyn EnrollmentHost>) {
        *self
            .inner
            .managed_ops
            .enrollment
            .host
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(host);
    }

    /// ⟨§17.25 item 3⟩ **Test configuration only, debug builds**: the directory in
    /// which every remote step's script pauses at its test-form points
    /// (`heimdall_registry::script::test_form`; `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`, which
    /// the runtime's test configuration validated). The runtime inserts the points when
    /// it builds a step; the CLI runs the script it receives. `None` clears it. A
    /// directory that is not a plain absolute UTF-8 path refuses every step
    /// (`driver_unavailable`) rather than running it unpaused. A release build has no
    /// such method, and its scripts are the release form.
    #[cfg(debug_assertions)]
    pub fn set_script_pause_dir(&self, dir: Option<&std::path::Path>) {
        let setting = dir.map(|d| {
            d.to_str()
                .and_then(|s| heimdall_registry::script::test_form::PauseDir::parse(s).ok())
                .ok_or(())
        });
        *self
            .inner
            .managed_ops
            .enrollment
            .script_pause
            .write()
            .unwrap_or_else(PoisonError::into_inner) = setting;
    }

    /// The test form's pause directory, if one is set (debug builds).
    #[cfg(debug_assertions)]
    pub(super) fn script_pause(&self) -> Option<ScriptPause> {
        self.inner
            .managed_ops
            .enrollment
            .script_pause
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// This instance's enrollment driver state.
    pub(super) fn enrollment_state(&self) -> &EnrollmentProcessState {
        &self.inner.managed_ops.enrollment
    }

    fn enrollment_host(&self) -> Option<Arc<dyn EnrollmentHost>> {
        self.inner
            .managed_ops
            .enrollment
            .host
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The ports every enrollment path needs (target, issuer, host), or
    /// `driver_unavailable`.
    pub(super) fn enrollment_ports(&self) -> Result<Ports, OpError> {
        let unavailable =
            || OpError::driver_unavailable("enrollment is not available in this runtime");
        let wiring = self.managed_wiring().ok_or_else(unavailable)?;
        if wiring.target.is_none() || wiring.issuer.is_none() {
            return Err(unavailable());
        }
        let host = self.enrollment_host().ok_or_else(unavailable)?;
        Ok(Ports { wiring, host })
    }

    /// The verification ports too (endpoints and runner).
    pub(super) fn verification_ports(&self) -> Result<Ports, OpError> {
        let p = self.enrollment_ports()?;
        if p.wiring.verification_endpoints.is_none() || p.wiring.verification_runner.is_none() {
            return Err(OpError::driver_unavailable(
                "verification is not available in this runtime",
            ));
        }
        Ok(p)
    }

    /// `Request::Enrollment` (capability `enrollment/1`). The dispatcher has already
    /// refused the owner-only actions for any other role (U0b row 13, F20); this
    /// checks again.
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn enrollment_request(
        &self,
        caller: &Caller,
        req: EnrollmentRequest,
    ) -> OpResult<serde_json::Value> {
        let owner = caller.context.is_owner();
        match req {
            EnrollmentRequest::Preview { spec } => self.enroll_preview(spec).await,
            EnrollmentRequest::Apply {
                spec,
                plan_digest,
                request_id,
                interaction,
                ..
            } => {
                self.enroll_apply(caller, spec, plan_digest, request_id, interaction)
                    .await
            }
            EnrollmentRequest::Verify {
                enrollment_id,
                request_id,
                mode,
                ..
            } => {
                if mode == VerifyMode::Absence && !owner {
                    return Err(not_owner());
                }
                self.enroll_verify(caller, enrollment_id, request_id, mode)
                    .await
            }
            EnrollmentRequest::Remove {
                target,
                request_id,
                interaction,
                ..
            } => {
                self.enroll_remove(caller, target, request_id, interaction)
                    .await
            }
            EnrollmentRequest::Reconcile {
                operation_id,
                interaction,
                after_manual_recovery,
            } => {
                if !owner {
                    return Err(not_owner());
                }
                self.enroll_reconcile(caller, &operation_id, interaction, after_manual_recovery)
                    .await
            }
            EnrollmentRequest::Abandon { enrollment_id } => {
                if !owner {
                    return Err(not_owner());
                }
                self.enroll_abandon(&enrollment_id).await
            }
            EnrollmentRequest::Step { operation_id } => {
                if !owner {
                    return Err(not_owner());
                }
                let answer = self.enroll_step(&operation_id).await?;
                let data = serde_json::to_value(&answer).map_err(|_| internal("step answer"))?;
                Ok(Completed::ok(Code::Ok, data).with_operation(operation_id))
            }
            EnrollmentRequest::StepResult {
                operation_id,
                step_token,
                exit_status,
                stdout,
                stderr_excerpt,
            } => {
                if !owner {
                    return Err(not_owner());
                }
                let recorded = self
                    .enroll_step_result(
                        &operation_id,
                        &step_token,
                        exit_status,
                        stdout,
                        stderr_excerpt,
                    )
                    .await?;
                let data = serde_json::to_value(&recorded).map_err(|_| internal("step result"))?;
                Ok(Completed::ok(Code::Ok, data).with_operation(operation_id))
            }
            _ => Err(OpError::new(
                Code::UsageError,
                "this enrollment action is not supported by this runtime",
            )),
        }
    }

    // --- preview -------------------------------------------------------------------

    /// The plan for `spec` with the enrollment ID `enrollment` (no write).
    pub(super) async fn enrollment_plan(
        &self,
        ports: &Ports,
        spec: &EnrollmentSpec,
        enrollment: &EnrollmentId,
    ) -> Result<EnrollmentPlan, OpError> {
        let destination = spec.destination.clone();
        let env = self.environment().clone();
        let facts = self
            .write(move |tx, _| {
                let dest = tx.destination(&destination)?;
                let identity = match dest.as_ref().map(|d| &d.definition) {
                    Some(heimdall_domain::catalog::DestinationDefinition::Managed {
                        identity,
                        ..
                    }) => tx.identity(identity)?,
                    _ => None,
                };
                let issuers = tx.issuers()?;
                let pair_enrollments = match dest.as_ref().map(|d| &d.definition) {
                    Some(heimdall_domain::catalog::DestinationDefinition::Managed {
                        account,
                        ..
                    }) => tx.enrollments_for_pair(&AccessPair {
                        destination: destination.clone(),
                        account: account.clone(),
                    })?,
                    _ => Vec::new(),
                };
                let ack = tx.lock_disclosure_ack()?.is_some();
                let _ = &env;
                Ok((dest, identity, issuers, pair_enrollments, ack))
            })
            .await?;
        let (dest, identity, issuers, pair_enrollments, ack) = facts;
        let Some(dest) = dest else {
            return Err(OpError::new(Code::NotFound, "unknown destination")
                .with_resource("destination", Some(spec.destination.to_string())));
        };
        let tag = tag_of(enrollment);
        let paths = ports
            .host
            .paths(&tag)
            .ok_or_else(|| OpError::driver_unavailable("the enrollment files are unavailable"))?;
        let target = ports
            .wiring
            .target
            .as_ref()
            .ok_or_else(|| OpError::driver_unavailable("no target evaluator"))?;
        let evaluation = target.evaluate(&dest.alias);
        let issuer_state = ports
            .wiring
            .issuer
            .as_ref()
            .map(|i| i.status().status.state);
        let catalog = CatalogView {
            destination: dest.clone(),
            identity,
            heimdall_endpoints: ports.host.heimdall_endpoints(),
        };
        let ca_view = CaView {
            cas: issuers
                .iter()
                .map(|i| CaViewEntry {
                    fingerprint: i.ca_fingerprint.clone(),
                    state: i.state,
                    public_key: i.public_key.clone(),
                })
                .collect(),
            issuer: issuer_state,
            context: Some(PlanContext {
                enrollment_id: enrollment.clone(),
                trust_files: paths.trust.clone(),
                identity_file: Some(paths.identity_file.clone()),
                alias_identity_agent: ports.host.identity_agent(&dest.alias),
                pair_enrollments: pair_enrollments
                    .iter()
                    .map(|e| PairEnrollment {
                        ca_fingerprint: e.ca_fingerprint.clone(),
                        state: e.state,
                        removal_origin_set: e.removal_origin.is_some(),
                    })
                    .collect(),
                lock_continuity_acknowledged: ack,
            }),
        };
        heimdall_registry::plan::build(&catalog, &evaluation, &ca_view, spec.clone()).map_err(|r| {
            OpError::new(r.code(), r.to_string())
                .with_reason(r.reason())
                .with_effect(EffectStatus::None)
        })
    }

    async fn enroll_preview(&self, spec: EnrollmentSpec) -> OpResult<serde_json::Value> {
        let ports = self.enrollment_ports()?;
        let enrollment = new_enrollment_id()?;
        let plan = self.enrollment_plan(&ports, &spec, &enrollment).await?;
        self.inner
            .managed_ops
            .enrollment
            .remember(&plan.plan_digest, Previewed { spec, enrollment });
        let data =
            serde_json::to_value(&plan).map_err(|_| internal("the plan cannot be rendered"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    // --- the caller's view of an operation -------------------------------------------------

    /// The caller's view of enrollment operation `id` (replays and every answer).
    pub(super) async fn enrollment_respond(
        &self,
        id: &OperationId,
        caller: &Caller,
    ) -> OpResult<serde_json::Value> {
        let oid = id.clone();
        let (op, pending) = self
            .write(move |tx, _| {
                let op = tx.operation(&oid)?;
                let pending = tx
                    .pending_decisions()?
                    .into_iter()
                    .find(|d| decision_operation(&d.kind) == Some(&oid));
                Ok((op, pending))
            })
            .await?;
        let Some(op) = op else {
            return Err(unknown_operation());
        };
        match op.state {
            OperationState::AwaitingApproval => match pending {
                Some(d) => Err(approval_needed(
                    caller.is_attended(),
                    d.id.as_str(),
                    "the enrollment needs the owner's attended decision",
                )
                .with_resource("decision", Some(d.id.to_string()))
                .with_operation(op.id.clone())),
                None => Err(OpError::new(
                    Code::Accepted,
                    "the operation awaits its decision; observe it",
                )
                .with_operation(op.id.clone())),
            },
            OperationState::Succeeded => Ok(Completed {
                operation_id: Some(op.id.clone()),
                state: op.state,
                code: op.code.clone().unwrap_or(Code::Ok),
                data: op.result.clone().unwrap_or(serde_json::Value::Null),
                warnings: Vec::new(),
                next: None,
            }),
            OperationState::Failed | OperationState::Cancelled => Err(stored_error(&op)),
            OperationState::OutcomeUnknown => Err(OpError::new(
                Code::OutcomeUnknown,
                "the remote step may or may not have applied; reconcile",
            )
            .with_reason(match op.kind {
                OperationKind::EnrollmentRemove => reason::REMOVE_OUTCOME_UNKNOWN,
                _ => reason::REGISTRY_OUTCOME_UNKNOWN,
            })
            .with_next(next("reconcile", Some(&op.id)))
            .with_operation(op.id.clone())),
            OperationState::Queued | OperationState::Running => Err(OpError::new(
                Code::Accepted,
                "the enrollment operation runs through its client-executed steps; drive it with `enroll step`",
            )
            .with_next(next("step", Some(&op.id)))
            .with_operation(op.id.clone())),
        }
    }

    /// Supervisor pass (ADR-0008 D5 §6.5, F27; §17.4 item 11): re-verify each
    /// `verified` pair before its evidence lapses, and promptly after a client or CA
    /// change. Returns the enrollments it re-verified.
    ///
    /// # Errors
    /// [`OpError`] (a store failure is reported, never an empty success).
    pub async fn reverify_pass(&self) -> Result<Vec<EnrollmentId>, OpError> {
        self.reverify_due().await
    }

    /// Supervisor pass (m03-plan U10): a step result that never arrives makes its
    /// stage `Uncertain` after `enrollment_step_timeout`. Returns the operations it
    /// moved.
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn enrollment_step_timeout_pass(&self) -> Result<Vec<OperationId>, OpError> {
        self.step_timeouts().await
    }

    /// After an enrollment decision committed (see `decisions_m03`): an approved
    /// removal degrades the grants under the removed CA for the pair (U0b row 20,
    /// through the narrowing protocol); an approved target change runs its
    /// verification. A failure is logged and left to the operation's own recovery
    /// (the next `enroll step`, or `enroll verify`).
    pub(super) async fn enrollment_after_decision(
        &self,
        record: &DecisionRecord,
        verdict: Verdict,
    ) {
        if verdict != Verdict::Approve {
            return;
        }
        match &record.kind {
            DecisionKind::RemoveEnrollment { operation, .. } => {
                if self.degrade_for_removal(operation).await.is_err() {
                    tracing::warn!("enrollment removal: the grants could not be degraded yet");
                }
            }
            DecisionKind::ApproveTargetChange { operation, .. } => {
                let _ = self.verify_operation(operation).await.inspect_err(|_| {
                    tracing::warn!("enrollment target change: the verification did not run");
                });
            }
            _ => {}
        }
    }

    /// The `RemoveEnrollment`'s degradation (idempotent): every grant holding a
    /// certificate under the removed CA for the pair (D5 §6.8; §17.3 item 3).
    pub(super) async fn degrade_for_removal(&self, op: &OperationId) -> Result<(), OpError> {
        let oid = op.clone();
        let target = self
            .write(move |tx, _| {
                let receipts = tx.stage_receipts(&oid)?;
                let Some(j) = journal_of(&receipts) else {
                    return Ok(None);
                };
                let Some(eid) = j.enrollment else {
                    return Ok(None);
                };
                Ok(tx.enrollment(&eid)?.map(|r| {
                    (
                        r.ca_fingerprint.clone(),
                        AccessPair {
                            destination: r.destination,
                            account: r.account,
                        },
                    )
                }))
            })
            .await?;
        if let Some((ca, pair)) = target {
            self.degrade_grants_under_ca(&ca, &pair).await?;
        }
        Ok(())
    }

    // --- abandon -------------------------------------------------------------------------

    async fn enroll_abandon(&self, id: &EnrollmentId) -> OpResult<serde_json::Value> {
        // R4: refuse before any write (the time read below persists its anchor).
        let _ = self.enrollment_ports()?;
        let now = self.narrowing_now().await;
        let retention = self.retention();
        let eid = id.clone();
        let r = self
            .write(move |tx, emit| {
                if let Some(record) = tx.enrollment(&eid)? {
                    // The open operation of this enrollment, if any, and its journal.
                    let open = open_operation_of(tx, &eid)?;
                    let mut updated = record.clone();
                    if let Some((_, j)) = &open
                        && let Some(u) = &j.uncertain
                        && u.purpose == crate::enrollment::StepPurpose::Append
                        && let Some(not_after) = u.not_after_remote
                    {
                        updated.late_write = Some(LateWrite {
                            step_token: u.token.clone(),
                            not_after_remote: not_after,
                        });
                    }
                    updated.updated_at = now;
                    let moved = match tx.transition_enrollment(
                        record.state,
                        EnrollmentEventKind::OwnerAbandon,
                        &updated,
                    )? {
                        Ok(m) => m,
                        Err(_) => {
                            return Ok(Err(refuse(
                                Code::ConfigConflict,
                                "abandon_not_allowed",
                                "this enrollment cannot be abandoned in its current state",
                            )));
                        }
                    };
                    emit_record(tx, emit, &moved, open.as_ref().map(|(o, _)| &o.id))?;
                    if let Some((mut op, _)) = open {
                        let err = OpError::new(
                            Code::OperationCancelled,
                            "the owner abandoned the enrollment",
                        )
                        .with_effect(EffectStatus::Unknown);
                        settle_open(tx, emit, &mut op, &err, now, retention)?;
                    }
                    return Ok(Ok(serde_json::to_value(result_of(&moved, None))
                        .map_err(|_| store_conflict("result"))?));
                }
                // A foreign record, named by its marker's enrollment ID (§17.10 item
                // 2: from `manual_removal_pending`, keeping `pending_until_line_removed`).
                let Some(record) = tx
                    .foreign_removals_by_marker(&heimdall_domain::enrollment::marker_for(&eid))?
                    .into_iter()
                    .rev()
                    .find(|f| !f.state.is_final() && f.state != EnrollmentState::Abandoned)
                else {
                    return Ok(Err(unknown_enrollment()));
                };
                let fop = record.operation.clone();
                match tx.transition_foreign_removal(
                    record.state,
                    EnrollmentEventKind::OwnerAbandon,
                    &record,
                )? {
                    Ok(moved) => {
                        if let Some(mut op) = tx.operation(&fop)? {
                            let err = OpError::new(
                                Code::OperationCancelled,
                                "the owner abandoned the foreign removal",
                            )
                            .with_effect(EffectStatus::Unknown);
                            settle_open(tx, emit, &mut op, &err, now, retention)?;
                        }
                        Ok(Ok(serde_json::json!({
                            "foreign_removal_id": moved.id,
                            "state": moved.state,
                            "residual": "pending_until_line_removed",
                        })))
                    }
                    Err(_) => Ok(Err(refuse(
                        Code::ConfigConflict,
                        "abandon_not_allowed",
                        "this foreign removal cannot be abandoned in its current state",
                    ))),
                }
            })
            .await??;
        Ok(Completed::ok(Code::Ok, r))
    }
}

// --- shared helpers ------------------------------------------------------------------------

/// A new enrollment ID (`enr_` + 32 hex).
pub(super) fn new_enrollment_id() -> Result<EnrollmentId, OpError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| internal("operating system randomness unavailable"))?;
    Ok(EnrollmentId::from_random_bytes(b))
}

/// A new step token (128 random bits, 32 lowercase hex).
pub(super) fn new_step_token() -> Result<String, OpError> {
    use std::fmt::Write as _;
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| internal("operating system randomness unavailable"))?;
    let mut s = String::with_capacity(32);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    Ok(s)
}

/// The operation an M03 enrollment decision names.
pub(super) fn decision_operation(kind: &DecisionKind) -> Option<&OperationId> {
    match kind {
        DecisionKind::EnrollAccount { operation, .. }
        | DecisionKind::EnrollSystemForm { operation, .. }
        | DecisionKind::RemoveEnrollment { operation, .. }
        | DecisionKind::ApproveTargetChange { operation, .. } => Some(operation),
        _ => None,
    }
}

/// The stored error of a settled operation.
fn stored_error(op: &OperationRecord) -> OpError {
    let detail = op
        .result
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| serde_json::from_value(e.clone()).ok());
    match detail {
        Some(d) => OpError::from_detail(d, Some(op.id.clone())),
        None => OpError::new(
            op.code.clone().unwrap_or(Code::InternalError),
            "the enrollment operation failed",
        )
        .with_effect(op.effect_status)
        .with_operation(op.id.clone()),
    }
}

/// The `Enrollment` event for `record`.
pub(super) fn emit_record(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    record: &EnrollmentRecord,
    op: Option<&OperationId>,
) -> heimdall_store::Result<()> {
    let payload = EnrollmentEventPayload {
        enrollment_id: record.id.clone(),
        state: record.state,
        operation_id: op.cloned(),
    };
    emit.event(
        tx,
        EventType::Enrollment,
        op.cloned(),
        Some(resource("enrollment", &record.id)),
        serde_json::to_value(payload).map_err(|_| store_conflict("enrollment event"))?,
    )
}

/// Apply `kind` to `record` (the stored state is `record.state`), with the mutable
/// fields of `updated`; the event is emitted. An event the table refuses is a store
/// conflict (the transaction rolls back): the driver only applies events its state
/// checks admitted.
pub(super) fn move_record(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    expected: EnrollmentState,
    kind: EnrollmentEventKind,
    updated: &EnrollmentRecord,
    op: Option<&OperationId>,
) -> heimdall_store::Result<EnrollmentRecord> {
    let moved = tx
        .transition_enrollment(expected, kind, updated)?
        .map_err(|e| store_conflict(&e.to_string()))?;
    emit_record(tx, emit, &moved, op)?;
    Ok(moved)
}

/// The open enrollment operation of `enrollment`, with its journal.
pub(super) fn open_operation_of(
    tx: &mut Txn<'_>,
    enrollment: &EnrollmentId,
) -> heimdall_store::Result<Option<(OperationRecord, Journal)>> {
    let mut ops = tx.open_operations()?;
    for o in tx.unresolved_operations()? {
        if ops.iter().all(|x| x.id != o.id) {
            ops.push(o);
        }
    }
    for op in ops {
        if !op.kind.is_enrollment() || op.state.is_settled() {
            continue;
        }
        let receipts = tx.stage_receipts(&op.id)?;
        if let Some(j) = journal_of(&receipts)
            && j.enrollment.as_ref() == Some(enrollment)
        {
            return Ok(Some((op, j)));
        }
    }
    Ok(None)
}

/// The open `enrollment.remove` operations of `enrollment` (a manual removal waiting
/// for its absence check).
pub(super) fn open_removals_of(
    tx: &mut Txn<'_>,
    enrollment: &EnrollmentId,
) -> heimdall_store::Result<Vec<OperationRecord>> {
    let mut out = Vec::new();
    for op in tx.open_operations()? {
        if op.kind != OperationKind::EnrollmentRemove || op.state.is_settled() {
            continue;
        }
        let receipts = tx.stage_receipts(&op.id)?;
        if journal_of(&receipts).is_some_and(|j| j.enrollment.as_ref() == Some(enrollment)) {
            out.push(op);
        }
    }
    Ok(out)
}

/// Settle an open (not settled) operation failed with `err`, whatever its state.
pub(super) fn settle_open(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    err: &OpError,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    if op.state.is_settled() {
        return Ok(());
    }
    if op.state == OperationState::Queued {
        op_to(op, OperationEvent::Start, now)?;
    }
    settle_failed(tx, emit, op, err, now, retention)
}

/// Settle an open operation succeeded with `data`.
pub(super) fn settle_ok(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    data: serde_json::Value,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    if op.state.is_settled() {
        return Ok(());
    }
    if op.state == OperationState::AwaitingApproval {
        op_to(op, OperationEvent::Approved, now)?;
    }
    settle_succeeded(tx, emit, op, Code::Ok, data, now, retention)
}

/// The enrollment result of `record` (with `operation`'s evidence view), from a path
/// that does not know the record's alias (only ever a record that is not `verified`;
/// a `verified` one's note then carries no command, never a guessed one).
pub(super) fn result_of(
    record: &EnrollmentRecord,
    next_action: Option<EnrollmentNext>,
) -> EnrollmentResult {
    result_for(record, None, next_action)
}

/// [`result_of`] with the record's alias (`Ctx.alias`; empty when the destination
/// record is gone): a `verified` record's `ordinary_ssh_needs_held_slot` note carries
/// `slot_free_command(alias)`, the command of the preview, `enroll status` and the
/// doctor (ADR-0008 §17.25 item 5). An unknown alias gives the note without a command.
pub(super) fn result_for(
    record: &EnrollmentRecord,
    alias: Option<&str>,
    next_action: Option<EnrollmentNext>,
) -> EnrollmentResult {
    let evidence = record.evidence.as_ref().map(|e| EnrollmentEvidenceView {
        client: e.client.clone(),
        server: e.server.clone(),
        operation_id: e.operation.clone(),
        clock: e.clock,
    });
    let mut notes = Vec::new();
    if record.state == EnrollmentState::Verified {
        // §17.4 item 12 (B R2-18): ordinary `ssh <alias>` works only while a binding
        // holds the pair's slot (`slot_free`).
        notes.push(EnrollmentNote {
            kind: EnrollmentNoteKind::OrdinarySshNeedsHeldSlot,
            command: alias
                .filter(|a| !a.is_empty())
                .map(heimdall_domain::managed::slot_free_command),
        });
    }
    if record.late_write.is_some() {
        notes.push(EnrollmentNote {
            kind: EnrollmentNoteKind::PossibleLateWrite,
            command: Some(format!("heimdall enroll remove {}", record.id)),
        });
    }
    EnrollmentResult {
        enrollment_id: record.id.clone(),
        state: record.state,
        verified_at: record.verified_at,
        evidence,
        next: next_action,
        commands: Vec::new(),
        instructions: Vec::new(),
        notes,
    }
}

/// The record's pair.
pub(super) fn pair_of(record: &EnrollmentRecord) -> AccessPair {
    AccessPair {
        destination: record.destination.clone(),
        account: record.account.clone(),
    }
}

/// The CA public key of `ca` (registered).
pub(super) fn ca_public_key(
    tx: &mut Txn<'_>,
    ca: &CaFingerprint,
) -> heimdall_store::Result<Option<String>> {
    Ok(tx.issuer(ca)?.map(|i| i.public_key))
}

/// The live managed grants with a `reserved` or `published` certificate for `pair`
/// under `ca` (D5 §6.8 "which live grants are degraded"; the set of
/// `heimdall_adapters::managed::report::grants_under_ca`, read from the store).
pub(super) fn affected_grants(
    tx: &mut Txn<'_>,
    ca: &CaFingerprint,
    pair: &AccessPair,
) -> heimdall_store::Result<Vec<GrantId>> {
    let mut out = Vec::new();
    for g in tx.grants_due(Timestamp::MAX)? {
        if !matches!(
            g.state,
            GrantState::Active | GrantState::Degraded | GrantState::Preparing
        ) {
            continue;
        }
        let under = tx.issuance_entries(&g.id)?.into_iter().any(|e| {
            e.pair == *pair
                && e.bounds.ca_fingerprint.as_ref() == Some(ca)
                && matches!(e.state, IssuanceState::Reserved | IssuanceState::Published)
        });
        if under {
            out.push(g.id);
        }
    }
    Ok(out)
}

/// E5 (D5 §6.4; §6.6, F05): the pair's preference after a verification pass. It
/// adds the CA to the issuing set; only a pair that is not already managed with an
/// applied projection gets `managed_certificate` with `projection: pending`. Returns
/// whether the projection is now pending for this pass (next `setup_apply`).
pub(super) fn record_preference(
    tx: &mut Txn<'_>,
    pair: &AccessPair,
    ca: &CaFingerprint,
    now: Timestamp,
) -> heimdall_store::Result<bool> {
    let current = tx.pair_preference(pair)?;
    let applied_managed = current.as_ref().is_some_and(|p| {
        p.mechanism == PreferredMechanism::ManagedCertificate
            && matches!(p.projection, ProjectionStatus::Applied { .. })
    });
    if applied_managed {
        tx.add_issuing_ca(pair, ca, now)?;
        return Ok(false);
    }
    let mut issuing = current
        .as_ref()
        .map(|p| p.issuing_cas.clone())
        .unwrap_or_default();
    issuing.insert(ca.clone());
    tx.set_pair_preference(
        &PairPreference {
            destination: pair.destination.clone(),
            account: pair.account.clone(),
            mechanism: PreferredMechanism::ManagedCertificate,
            projection: ProjectionStatus::Pending,
            issuing_cas: issuing,
        },
        now,
    )?;
    Ok(true)
}

/// `inspect enrollments`: every enrollment record as
/// `EnrollmentView`s (m03-plan §5 item 3), with the open operation, the live grants
/// under its CA for the pair and the `late_write` residual.
pub(super) fn enrollments_view_in(tx: &mut Txn<'_>) -> heimdall_store::Result<EnrollmentsView> {
    let mut records = tx.open_enrollments()?;
    // Final records too: every record of every pair this installation knows.
    let mut seen: BTreeSet<EnrollmentId> = records.iter().map(|r| r.id.clone()).collect();
    for issuer in tx.issuers()? {
        for r in tx.enrollments_for_ca(&issuer.ca_fingerprint)? {
            if seen.insert(r.id.clone()) {
                records.push(r);
            }
        }
    }
    let mut out = Vec::new();
    for r in records {
        let pair = pair_of(&r);
        let live_grants = affected_grants(tx, &r.ca_fingerprint, &pair)?;
        let open = open_operation_of(tx, &r.id)?.map(|(o, _)| o.id);
        let residual = tx.pair_residual(&pair, Some(&r.ca_fingerprint))?;
        let hold = hold_view(&r, open.as_ref());
        out.push(EnrollmentView {
            enrollment_id: r.id.clone(),
            destination_id: r.destination.clone(),
            account: r.account.clone(),
            form: r.form,
            ca_fingerprint: r.ca_fingerprint.clone(),
            marker: r.marker.clone(),
            state: r.state,
            registry: r.registry.clone(),
            verified_at: r.verified_at,
            evidence_fresh_until: r.evidence.as_ref().map(|e| e.fresh_until),
            pair_residual_until: residual,
            destination_clock: heimdall_contract::managed::DestinationClock::default(),
            residual_status: None,
            approved_target: TargetSummary {
                hostname: r.target.hostname.clone(),
                port: r.target.port,
                user: r.target.user.clone(),
                host_key_fingerprint: r.target.host_key.fingerprint.clone(),
            },
            removal_purpose: r.removal_purpose(),
            live_grants,
            open_operation_id: open,
            possible_late_write: r.late_write.is_some(),
            hold,
        });
    }
    Ok(EnrollmentsView { enrollments: out })
}

/// The manual step of a `lock_holder_unresolved` hold (ADR-0008 D5 §6.7: the owner
/// checks the holder process and removes the lock link by hand, then reconciles).
pub(super) const LOCK_HOLDER_MANUAL_STEP: &str = "on the destination, check that the registry lock's holder process is gone, then remove the lock link by hand";

/// `EnrollmentView.hold` (ADR-0008 §17.25 item 4): a `held` record's reason and the
/// owner's next step, from `record.hold`, so `enroll status` and the TUI show the same
/// commands. Each command is one of the `held` row's exits (D5 §6.2):
///
/// * `host_key_changed`: `enroll verify <e> --approve-target-change` (the
///   `ApproveTargetChange` decision), or `enroll remove <e>` (a `RemoveEnrollment` with
///   the freshly evaluated target);
/// * an evidence-based hold (`principals_not_enforced`, positive refused): `enroll
///   verify <e>` (re-verification), or `enroll remove <e>`;
/// * `lock_holder_unresolved`: the manual step, then `enroll reconcile <op>
///   --after-manual-recovery` on the open operation (§6.7; never a redispatch). Without
///   an open operation there is nothing to reconcile, so `enroll remove <e>` (whose
///   reconcile may break the stale lock once its holder is proven gone);
/// * any other hold: `enroll remove <e>` or `enroll abandon <e>`.
///
/// `None` for a record that is not `held`, or a `held` one without a `hold`.
#[must_use]
pub(super) fn hold_view(
    record: &EnrollmentRecord,
    open: Option<&OperationId>,
) -> Option<heimdall_contract::enrollment::EnrollmentHoldView> {
    use heimdall_domain::enrollment::HoldKind;
    if record.state != EnrollmentState::Held {
        return None;
    }
    let hold = record.hold?;
    let reason = serde_json::to_value(hold.reason).ok()?.as_str()?.to_owned();
    let id = &record.id;
    let remove = format!("heimdall enroll remove {id}");
    let next = match hold.kind() {
        HoldKind::HostKeyChanged => vec![
            format!("heimdall enroll verify {id} --approve-target-change"),
            remove,
        ],
        HoldKind::EvidenceBased => vec![format!("heimdall enroll verify {id}"), remove],
        HoldKind::LockHolderUnresolved => vec![
            LOCK_HOLDER_MANUAL_STEP.to_owned(),
            match open {
                Some(op) => format!("heimdall enroll reconcile {op} --after-manual-recovery"),
                None => remove,
            },
        ],
        _ => vec![remove, format!("heimdall enroll abandon {id}")],
    };
    Some(heimdall_contract::enrollment::EnrollmentHoldView { reason, next })
}

/// `decisions_m03::precheck` for the enrollment kinds.
pub(super) fn decision_precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
    now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    admit::decision_precheck(tx, d, verdict, now)
}

/// `decisions_m03::apply` for the enrollment kinds.
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
    let applied = admit::decision_apply(tx, emit, record, verdict, waiting, now, retention)?;
    // ⟨M03; ADR-0008 §17.25 item 21, D9 item 1⟩ Approving an enrollment decision that
    // displayed the lock disclosure records its acknowledgement, once (the store keeps
    // the first time), in the same transaction, as `RegisterIssuer`'s approval does
    // (`issuer_m03::decision_apply`). Worker R2's edit.
    if applied.is_ok() && verdict == Verdict::Approve && displayed_lock_disclosure(&record.kind) {
        tx.set_lock_disclosure_ack(now)?;
    }
    Ok(applied)
}

/// Whether an enrollment decision displayed the lock disclosure (`lock_continuity_once`
/// among its plan's disclosures).
fn displayed_lock_disclosure(kind: &DecisionKind) -> bool {
    match kind {
        DecisionKind::EnrollAccount { summary, .. }
        | DecisionKind::EnrollSystemForm { summary, .. } => summary
            .disclosures
            .contains(&heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce),
        _ => false,
    }
}

/// Which verification an operation's authority is (ADR-0008 §17.21 item 5): wave 0's
/// stored-request presence check, and the three that the driver's durable facts
/// authorize, each with its own predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerificationKind {
    /// An `enrollment.verify` in mode `presence` (wave 0's rule: no decision).
    Presence,
    /// The system form's absence check: an `enrollment.verify` in mode `absence`
    /// whose system-form record is `removal_verifying` (D5 §6.9).
    SystemAbsence,
    /// An `enrollment.apply`'s initial verification (E4, D5 §6.4).
    ApplyInitial,
    /// A target change's verification (`ApproveTargetChange`; §17.7 item 5).
    TargetChange,
}

/// The verification authority of one operation (module docs of
/// [`verification_authority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerificationAuthority {
    /// The enrollment the operation verifies (from its immutable request, or its
    /// journal for an `enrollment.apply`).
    pub(super) enrollment: EnrollmentId,
    /// Which verification.
    pub(super) kind: VerificationKind,
    /// Its own authorization is in place.
    pub(super) authorized: bool,
    /// The operation and the record are at **this** verification's stage, and no
    /// other open operation drives the record (so no operation borrows another's
    /// stage). The attempt count is the caller's check.
    pub(super) at_stage: bool,
}

/// The other open enrollment operations whose journal names `enrollment`.
fn other_open_operations(
    tx: &mut Txn<'_>,
    op: &OperationId,
    enrollment: &EnrollmentId,
) -> heimdall_store::Result<Vec<OperationRecord>> {
    let mut ops = tx.open_operations()?;
    for o in tx.unresolved_operations()? {
        if ops.iter().all(|x| x.id != o.id) {
            ops.push(o);
        }
    }
    let mut out = Vec::new();
    for o in ops {
        if o.id == *op || !o.kind.is_enrollment() || o.state.is_settled() {
            continue;
        }
        let receipts = tx.stage_receipts(&o.id)?;
        if journal_of(&receipts).is_some_and(|j| j.enrollment.as_ref() == Some(enrollment)) {
            out.push(o);
        }
    }
    Ok(out)
}

/// Whether the journal's approval is an **approved** decision of `kind_ok`'s shape
/// (the decision record itself, never the journal's word alone).
fn approved_decision(
    tx: &mut Txn<'_>,
    j: &Journal,
    kind_ok: impl Fn(&DecisionKind) -> bool,
) -> heimdall_store::Result<bool> {
    let Some(a) = &j.approval else {
        return Ok(false);
    };
    Ok(tx.decision(&a.decision)?.is_some_and(|d| {
        d.state == heimdall_domain::decision::DecisionState::Approved && kind_ok(&d.kind)
    }))
}

/// ⟨for `verification_m03` (U0b row 4, INT-Q13; ADR-0008 §17.21 item 5)⟩ The
/// verification authority of `op`, from the store. Each verification has **its own**
/// predicate, so an operation never borrows another operation's authority or stage:
///
/// | Verification | Operation | Authorized | At its stage |
/// |---|---|---|---|
/// | presence (wave 0) | `enrollment.verify`, stored request `presence` | always | `running`; record `verifying`, or `reverifying` without a proposed target |
/// | system absence | `enrollment.verify`, stored request `absence` | always | `running`; system-form record `removal_verifying` with its origin |
/// | apply's initial | `enrollment.apply` | the journal's approval is an **approved** `EnrollAccount` naming this operation | `running` or `outcome_unknown` (reconciled); account-form record `verifying`; an `enroll.append` `Confirmed` receipt with the record's marker; nothing outstanding or uncertain |
/// | target change | `enrollment.verify`, stored request `target_change` | the journal's approval is an **approved** `ApproveTargetChange` naming this operation, this enrollment, the journal's proposed target and the record's approved target | `running`; record `reverifying` from `held` |
///
/// Every row also needs the journal (when present) to name the same enrollment and
/// mode, and no other open enrollment operation of the record (a system-form manual
/// removal's own `enrollment.remove` excepted for the absence check). Anything else
/// is `None` (refused `operation_not_verifying`).
pub(super) fn verification_authority(
    tx: &mut Txn<'_>,
    op: &OperationRecord,
) -> heimdall_store::Result<Option<VerificationAuthority>> {
    use EnrollmentState as S;
    let receipts = tx.stage_receipts(&op.id)?;
    let journal = journal_of(&receipts);
    let (enrollment, kind) = match op.kind {
        OperationKind::EnrollmentVerify => {
            // The immutable intent names the enrollment and the mode.
            let Some((e, mode)) = stored_verify_request(tx, &op.id)? else {
                return Ok(None);
            };
            if let Some(j) = &journal
                && (j.enrollment.as_ref() != Some(&e) || j.mode.is_some_and(|m| m != mode))
            {
                return Ok(None);
            }
            let kind = match mode {
                VerifyMode::Presence => VerificationKind::Presence,
                VerifyMode::Absence => VerificationKind::SystemAbsence,
                VerifyMode::TargetChange => VerificationKind::TargetChange,
                _ => return Ok(None),
            };
            (e, kind)
        }
        OperationKind::EnrollmentApply => {
            let Some(e) = journal.as_ref().and_then(|j| j.enrollment.clone()) else {
                return Ok(None);
            };
            (e, VerificationKind::ApplyInitial)
        }
        _ => return Ok(None),
    };
    let Some(record) = tx.enrollment(&enrollment)? else {
        return Ok(None);
    };
    let others = other_open_operations(tx, &op.id, &enrollment)?;
    let running = op.state == OperationState::Running;
    let (authorized, at_stage) = match kind {
        VerificationKind::Presence => {
            let proposed = journal
                .as_ref()
                .is_some_and(|j| j.proposed_target.is_some());
            let stage = running
                && (record.state == S::Verifying || (record.state == S::Reverifying && !proposed))
                && others.is_empty();
            (true, stage)
        }
        VerificationKind::SystemAbsence => {
            let stage = running
                && record.form == heimdall_contract::enrollment::EnrollmentForm::System
                && record.state == S::RemovalVerifying
                && record.removal_origin.is_some()
                && others
                    .iter()
                    .all(|o| o.kind == OperationKind::EnrollmentRemove);
            (true, stage)
        }
        VerificationKind::ApplyInitial => {
            let Some(j) = journal.as_ref() else {
                return Ok(None);
            };
            let oid = op.id.clone();
            let authorized = record.form == heimdall_contract::enrollment::EnrollmentForm::Account
                && approved_decision(
                    tx,
                    j,
                    |k| matches!(k, DecisionKind::EnrollAccount { operation, .. } if *operation == oid),
                )?;
            let appended = receipts.iter().any(|r| {
                r.stage == heimdall_domain::operation::enrollment_stage::APPEND
                    && matches!(&r.effect, EffectReceipt::Confirmed { credential_ref, .. }
                        if *credential_ref == record.marker)
            });
            let stage = matches!(
                op.state,
                OperationState::Running | OperationState::OutcomeUnknown
            ) && record.state == S::Verifying
                && appended
                && j.outstanding.is_none()
                && j.uncertain.is_none()
                && others.is_empty();
            (authorized, stage)
        }
        VerificationKind::TargetChange => {
            let Some(j) = journal.as_ref() else {
                return Ok(None);
            };
            let (oid, eid) = (op.id.clone(), enrollment.clone());
            let (proposed, approved_now) = (j.proposed_target.clone(), record.target.clone());
            let authorized = proposed.is_some()
                && approved_decision(tx, j, |k| {
                    matches!(k, DecisionKind::ApproveTargetChange { operation, enrollment, approved, proposed: p }
                        if *operation == oid
                            && *enrollment == eid
                            && *approved == approved_now
                            && Some(p) == proposed.as_ref())
                })?;
            let stage = running
                && record.state == S::Reverifying
                && j.reverify_from == Some(heimdall_domain::enrollment::ReverifyFrom::Held)
                && others.is_empty();
            (authorized, stage)
        }
    };
    Ok(Some(VerificationAuthority {
        enrollment,
        kind,
        authorized,
        at_stage,
    }))
}

/// The enrollment and mode an operation's stored `enrollment.verify` request names
/// (the immutable recovery intent).
fn stored_verify_request(
    tx: &mut Txn<'_>,
    operation: &OperationId,
) -> heimdall_store::Result<Option<(EnrollmentId, VerifyMode)>> {
    Ok(tx
        .recovery_intent(operation)?
        .and_then(|i| serde_json::from_value::<heimdall_contract::request::Request>(i.request).ok())
        .and_then(|r| match r {
            heimdall_contract::request::Request::Enrollment(EnrollmentRequest::Verify {
                enrollment_id,
                mode,
                ..
            }) => Some((enrollment_id, mode)),
            _ => None,
        }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use heimdall_contract::enrollment::{
        ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentNoteKind, EnrollmentState,
        NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy,
    };
    use heimdall_contract::ids::{
        AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId, OperationId,
    };
    use heimdall_domain::enrollment::{
        EnrollmentHold, EnrollmentRecord, ExistingAccessRecord, HoldReason, marker_for,
    };

    use super::{LOCK_HOLDER_MANUAL_STEP, hold_view, result_for, result_of};

    const ID: &str = "enr_00112233445566778899aabbccddeeff";

    fn record(state: EnrollmentState, hold: Option<(HoldReason, bool)>) -> EnrollmentRecord {
        let id = EnrollmentId::parse(ID).unwrap();
        let now = heimdall_contract::Timestamp::from_second(1_800_000_000).unwrap();
        EnrollmentRecord {
            marker: marker_for(&id),
            id,
            destination: DestinationId::parse("dst_lab").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
            ca_fingerprint: CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap(),
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "$HOME/.ssh/authorized_keys".to_owned(),
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            registry_canonical: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            line_sha256: "ab".repeat(32),
            target: ApprovedTarget {
                hostname: "lab.example.invalid".to_owned(),
                port: 22,
                user: AccountName::parse("deploy").unwrap(),
                proxy: NoProxy::None,
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".to_owned(),
                    key: "AAAA".to_owned(),
                    fingerprint: format!("SHA256:{}", "B".repeat(43)),
                },
            },
            existing_access: ExistingAccessRecord {
                identity: IdentityId::from_random_bytes([7; 16]),
                endpoint: None,
                public_key_file: None,
            },
            hold: hold.map(|(reason, evidence_based)| EnrollmentHold {
                reason,
                evidence_based,
            }),
            removal_origin: None,
            late_write: None,
            state,
            verified_at: None,
            evidence: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// ADR-0008 §17.25 item 4: `EnrollmentView.hold` carries the record's reason and the
    /// `held` row's exits (D5 §6.2), each an existing `heimdall enroll` command.
    #[test]
    fn hold_view_names_the_held_rows_exits() {
        let op = OperationId::parse("op_00112233445566778899aabbccddeeff").unwrap();
        let view = |reason, evidence, open: Option<&OperationId>| {
            hold_view(
                &record(EnrollmentState::Held, Some((reason, evidence))),
                open,
            )
            .unwrap()
        };
        let v = view(HoldReason::HostKeyChanged, false, None);
        assert_eq!(v.reason, "host_key_changed");
        assert_eq!(
            v.next,
            [
                format!("heimdall enroll verify {ID} --approve-target-change"),
                format!("heimdall enroll remove {ID}"),
            ]
        );
        for reason in [
            HoldReason::PrincipalsNotEnforced,
            HoldReason::PositiveRefused,
        ] {
            let v = view(reason, true, None);
            assert_eq!(
                v.next,
                [
                    format!("heimdall enroll verify {ID}"),
                    format!("heimdall enroll remove {ID}"),
                ],
                "{reason:?}"
            );
        }
        let v = view(HoldReason::LockHolderUnresolved, false, Some(&op));
        assert_eq!(v.reason, "lock_holder_unresolved");
        assert_eq!(
            v.next,
            [
                LOCK_HOLDER_MANUAL_STEP.to_owned(),
                format!("heimdall enroll reconcile {op} --after-manual-recovery"),
            ]
        );
        // No open operation: nothing to reconcile, so the removal.
        let v = view(HoldReason::LockHolderUnresolved, false, None);
        assert_eq!(v.next[1], format!("heimdall enroll remove {ID}"));
        for reason in [
            HoldReason::RegistryLineDamaged,
            HoldReason::RegistryChanged,
            HoldReason::RegistryNotRewritable,
            HoldReason::PostWriteCheckFailed,
            // Not evidence-based: no re-verification is offered.
            HoldReason::PrincipalsNotEnforced,
        ] {
            let v = view(reason, false, None);
            assert_eq!(
                v.next,
                [
                    format!("heimdall enroll remove {ID}"),
                    format!("heimdall enroll abandon {ID}"),
                ],
                "{reason:?}"
            );
            assert_eq!(
                serde_json::to_value(reason).unwrap().as_str().unwrap(),
                v.reason
            );
        }
        // Only a `held` record with a hold has one.
        assert!(hold_view(&record(EnrollmentState::Held, None), None).is_none());
        assert!(
            hold_view(
                &record(
                    EnrollmentState::Reverifying,
                    Some((HoldReason::HostKeyChanged, false))
                ),
                None
            )
            .is_none()
        );
    }

    /// ADR-0008 §17.25 item 5: a verified result's `ordinary_ssh_needs_held_slot` note
    /// names `slot_free_command(alias)`, the preview's, `status`'s and the doctor's
    /// command; with the alias unknown it names none (never a guess).
    #[test]
    fn verified_note_names_the_slot_free_command() {
        let verified = record(EnrollmentState::Verified, None);
        let note = |alias: Option<&str>| {
            result_for(&verified, alias, None)
                .notes
                .into_iter()
                .find(|n| n.kind == EnrollmentNoteKind::OrdinarySshNeedsHeldSlot)
                .unwrap()
                .command
        };
        assert_eq!(
            note(Some("lab")).as_deref(),
            Some("heimdall run --profile <profile> -- ssh lab")
        );
        assert_eq!(
            note(Some("lab")),
            Some(heimdall_domain::managed::slot_free_command("lab"))
        );
        assert_eq!(note(Some("")), None);
        assert_eq!(note(None), None);
        assert!(
            result_of(&verified, None)
                .notes
                .iter()
                .all(|n| n.command.as_deref() != Some("heimdall connect <alias>"))
        );
    }
}
