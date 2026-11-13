//! The client-executed steps (ADR-0008 D5 §6.3, §6.4, §6.7, §6.8): `Enrollment::Step`
//! issues the next stage with its receipt written first, `Enrollment::StepResult`
//! classifies the CLI's result and records the outcome with the enrollment's
//! transition in one transaction, and `Enrollment::Reconcile` drives an uncertain
//! step through `inspect` and `fence`.

use heimdall_contract::enrollment::{ApprovedTarget, EnrollmentForm, EnrollmentState, RemoteStage};
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::OperationId;
use heimdall_contract::request::InteractionMode;
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::enrollment::{
    EnrollmentEventKind, EnrollmentHold, EnrollmentRecord, HoldKind, HoldReason, LateWrite,
    RecoveryPurpose,
};
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{EffectReceipt, OperationKind, OperationRecord, enrollment_stage};
use heimdall_registry::classify::{
    Expected, Inspection, NotAppliedReason, StepClass, StepResult as RegistryStepResult,
    classify_step,
};
use heimdall_registry::fence::{
    FenceReading, FenceView, LockView, Observation, OurLock, ReconcileClass, ReconcileExpected,
    ReconcilePurpose, UnresolvedReason, classify_reconcile,
};
use heimdall_registry::hm1;
use heimdall_registry::step::{self, StageInput, StepEnv, StepTarget};
use heimdall_store::Txn;

use super::super::{Emit, Operations, internal, op_to};
use super::{
    adapter, journal_of, move_record, new_step_token, next, pair_of, put_journal, receipt, refuse,
    result_of, settle_ok, settle_open, store_conflict,
};
use crate::context::Caller;
use crate::enrollment::{
    FenceFact, InspectFact, IssuedStep, Journal, ReconcileFact, StepAnswer, StepPurpose,
    StepRecorded, UncertainStep, endpoint_of, known_hosts_line, registry_canonical, route_matches,
};
use crate::error::{Completed, OpError, OpResult};

/// An enrollment operation with everything its steps need.
#[derive(Debug, Clone)]
pub(super) struct Ctx {
    pub(super) op: OperationRecord,
    pub(super) journal: Journal,
    pub(super) record: EnrollmentRecord,
    pub(super) alias: String,
    pub(super) ca_key: String,
    pub(super) mechanism: String,
    pub(super) identity_public: Option<String>,
    /// A foreign removal (D4 item 5): `record` is then its in-memory image (the
    /// bundle's marker, line digest, registry and form; the local alias's existing
    /// access; the freshly evaluated target), never stored as an enrollment.
    pub(super) foreign: Option<heimdall_domain::enrollment::ForeignRemovalRecord>,
}

/// The in-memory enrollment image of a foreign removal (module docs of [`Ctx`]).
fn foreign_image(
    tx: &mut Txn<'_>,
    f: &heimdall_domain::enrollment::ForeignRemovalRecord,
    journal: &Journal,
) -> heimdall_store::Result<Option<(EnrollmentRecord, String, Option<String>)>> {
    let t = &f.target;
    let Some(id) = t
        .marker
        .strip_prefix("heimdall:")
        .and_then(|i| heimdall_contract::ids::EnrollmentId::parse(i).ok())
    else {
        return Ok(None);
    };
    let Ok(destination) = heimdall_contract::ids::DestinationId::parse(&t.bundle_destination_id)
    else {
        return Ok(None);
    };
    let Some(ca) = crate::issuance_ro::subject_fingerprint(&t.ca_public_key)
        .and_then(|fp| heimdall_contract::ids::CaFingerprint::parse(&fp).ok())
    else {
        return Ok(None);
    };
    let Some(local) = tx.destination_by_alias(&t.local_alias)? else {
        return Ok(None);
    };
    let heimdall_domain::catalog::DestinationDefinition::Managed { identity, .. } =
        &local.definition
    else {
        return Ok(None);
    };
    let Some(identity) = tx.identity(identity)? else {
        return Ok(None);
    };
    let Some(target) = journal.fresh_target.clone() else {
        return Ok(None);
    };
    let public_key_file = match &identity.source {
        heimdall_domain::catalog::IdentitySource::PublicKeyFile { path } => {
            Some(path.replace('\\', "/"))
        }
        _ => None,
    };
    // ⟨round 5, Y-W⟩ The concrete rendering an own record stores (the catalog's
    // `\\.\pipe\<name>` is `//./pipe/<name>`), re-validated before every step.
    let endpoint = crate::enrollment::foreign_endpoint(&identity.source);
    let record = EnrollmentRecord {
        id,
        destination,
        account: t.account.clone(),
        ca_fingerprint: ca,
        form: t.form,
        marker: t.marker.clone(),
        registry: heimdall_contract::enrollment::RegistryRef {
            path_display: t
                .registry
                .path
                .clone()
                .unwrap_or_else(|| heimdall_registry::plan::REMOTE_HOME_DISPLAY.to_owned()),
            resolved_by: t.registry.resolved_by,
        },
        registry_canonical: t.registry.clone(),
        line_sha256: t.line_sha256.clone(),
        target,
        existing_access: heimdall_domain::enrollment::ExistingAccessRecord {
            identity: identity.id.clone(),
            endpoint,
            public_key_file,
        },
        hold: None,
        removal_origin: f.removal_origin.clone(),
        late_write: None,
        state: f.state,
        verified_at: None,
        evidence: None,
        created_at: f.created_at,
        updated_at: f.created_at,
    };
    Ok(Some((
        record,
        identity.source.mechanism().to_owned(),
        Some(identity.public_key),
    )))
}

/// Apply `kind` to the context's record (own: the enrollment table; foreign: the
/// foreign removal table), with the mutable fields of `updated`.
pub(super) fn move_ctx(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    kind: EnrollmentEventKind,
    updated: &EnrollmentRecord,
) -> heimdall_store::Result<()> {
    if let Some(f) = ctx.foreign.clone() {
        let mut uf = f.clone();
        uf.removal_origin = updated.removal_origin.clone();
        let moved = tx
            .transition_foreign_removal(f.state, kind, &uf)?
            .map_err(|e| store_conflict(&e.to_string()))?;
        ctx.record.state = moved.state;
        ctx.record.removal_origin = moved.removal_origin.clone();
        ctx.foreign = Some(moved);
        return Ok(());
    }
    ctx.record = move_record(tx, emit, ctx.record.state, kind, updated, Some(&ctx.op.id))?;
    Ok(())
}

/// Load `id`'s context (`Err`: unknown or not an enrollment operation).
pub(super) fn load_ctx(
    tx: &mut Txn<'_>,
    id: &OperationId,
) -> heimdall_store::Result<Result<Ctx, OpError>> {
    let Some(op) = tx.operation(id)? else {
        return Ok(Err(super::unknown_operation()));
    };
    if !op.kind.is_enrollment() {
        return Ok(Err(super::unknown_operation()));
    }
    let receipts = tx.stage_receipts(id)?;
    let Some(journal) = journal_of(&receipts) else {
        return Ok(Err(internal("the enrollment operation has no journal")));
    };
    if let Some(fid) = journal.foreign.clone() {
        let Some(f) = tx.foreign_removal(&fid)? else {
            return Ok(Err(super::unknown_enrollment()));
        };
        let Some((record, mechanism, identity_public)) = foreign_image(tx, &f, &journal)? else {
            return Ok(Err(internal("the foreign removal cannot be rebuilt")));
        };
        return Ok(Ok(Ctx {
            op,
            journal,
            alias: f.target.local_alias.clone(),
            ca_key: f.target.ca_public_key.clone(),
            mechanism,
            identity_public,
            record,
            foreign: Some(f),
        }));
    }
    let Some(eid) = journal.enrollment.clone() else {
        return Ok(Err(internal(
            "the enrollment operation names no enrollment",
        )));
    };
    let Some(record) = tx.enrollment(&eid)? else {
        return Ok(Err(super::unknown_enrollment()));
    };
    let alias = tx
        .destination(&record.destination)?
        .map(|d| d.alias)
        .unwrap_or_default();
    let ca_key = super::ca_public_key(tx, &record.ca_fingerprint)?.unwrap_or_default();
    let identity = tx.identity(&record.existing_access.identity)?;
    let mechanism = identity
        .as_ref()
        .map_or("native_agent", |i| i.source.mechanism())
        .to_owned();
    let identity_public = identity.map(|i| i.public_key);
    Ok(Ok(Ctx {
        op,
        journal,
        record,
        alias,
        ca_key,
        mechanism,
        identity_public,
        foreign: None,
    }))
}

/// What the next `Step` issues.
#[derive(Debug, Clone)]
enum Next {
    /// A remote stage.
    Issue {
        stage: RemoteStage,
        purpose: StepPurpose,
        terminate: bool,
        removal: Option<(Vec<u8>, Vec<u8>)>,
    },
    /// The removal found nothing of ours: confirmed without a remote change.
    AlreadyRemoved,
    /// The removal found a damaged line: `held`.
    RemovalDamaged,
    /// The initial verification runs now (runtime-side).
    Verify,
    /// Nothing to do now (the operation's answer).
    Nothing,
}

/// The fresh inspection a mutation may rest on: not consumed, same boot, younger
/// than `enrollment_inspect_max_age`.
fn fresh_inspection<'a>(
    j: &'a Journal,
    boot: &str,
    now_ms: u64,
    max_age_ms: u64,
) -> Option<&'a InspectFact> {
    j.inspection.as_ref().filter(|i| {
        !i.consumed
            && i.boot_id == boot
            && now_ms.saturating_sub(i.read_continuous_ms) <= max_age_ms
            && i.exit_status == 0
    })
}

/// The (minimized) inspection reading of a stored fact (§17.21 item 4: Heimdall's
/// own marker lines only; never the registry's preimage).
fn parsed(i: &InspectFact) -> Option<Inspection> {
    i.inspection()
}

/// The stored fact of a full `inspect` reading: the registry's digest and the
/// reading minimized to Heimdall's exact canonical `line` plus parsed facts of every
/// other marker-bearing line (§17.21 item 4, §17.22 item 2).
fn inspect_fact(
    reading: &Inspection,
    marker: &str,
    line: Option<&str>,
    r: &Recording<'_>,
) -> InspectFact {
    InspectFact {
        registry: reading
            .preimage_digest()
            .map(|d| crate::enrollment::RegistryDigest::from(&d)),
        reading: crate::enrollment::StoredReading::of(reading, marker, line),
        exit_status: r.exit_status,
        read_continuous_ms: r.c_read,
        read_wall: r.now,
        boot_id: r.boot.to_owned(),
        remote_now: reading.remote_now,
        consumed: false,
    }
}

/// The exact line of a record (rebuilt from the CA key; digest-checked).
pub(super) fn line_of(ctx: &Ctx) -> Option<String> {
    let principal =
        heimdall_registry::line::principal(&ctx.record.destination, &ctx.record.account).ok()?;
    let line =
        heimdall_registry::line::expected_line(&ctx.ca_key, &principal, &ctx.record.marker).ok()?;
    (heimdall_domain::projection::Sha256Hex::of(line.as_bytes()).as_str() == ctx.record.line_sha256)
        .then_some(line)
}

/// The stage the operation needs next (pure; D5 §6.4 table). `full` is this
/// runtime's memory of the fresh reading's registry bytes (digest-checked), which a
/// removal's post-image needs; without it the removal inspects again.
fn next_of(
    ctx: &Ctx,
    boot: &str,
    now_ms: u64,
    max_age_ms: u64,
    approval_valid: bool,
    full: Option<&[u8]>,
) -> Next {
    use EnrollmentState as S;
    let j = &ctx.journal;
    if let Some(r) = &j.reconcile {
        // A fence the last classification asked for (`Fence`, or `Terminate` past the
        // holder's not-after), on the same unconsumed reading.
        if let Some(FenceFact::Alive {
            not_after_passed,
            terminated: false,
        }) = r.fence
            && j.inspection.as_ref().is_some_and(|i| !i.consumed)
        {
            return Next::Issue {
                stage: RemoteStage::Fence,
                purpose: StepPurpose::Reconcile,
                terminate: not_after_passed,
                removal: None,
            };
        }
        return Next::Issue {
            stage: RemoteStage::Inspect,
            purpose: StepPurpose::Reconcile,
            terminate: false,
            removal: None,
        };
    }
    let fresh = fresh_inspection(j, boot, now_ms, max_age_ms);
    match ctx.record.state {
        S::Applying => match fresh.and_then(parsed) {
            None => Next::Issue {
                stage: RemoteStage::Inspect,
                purpose: StepPurpose::Append,
                terminate: false,
                removal: None,
            },
            Some(i)
                if i.dir == heimdall_registry::classify::DirState::Absent && !j.bootstrap_done =>
            {
                Next::Issue {
                    stage: RemoteStage::Bootstrap,
                    purpose: StepPurpose::Append,
                    terminate: false,
                    removal: None,
                }
            }
            Some(_) => Next::Issue {
                stage: RemoteStage::Append,
                purpose: StepPurpose::Append,
                terminate: false,
                removal: None,
            },
        },
        S::RollbackPending | S::Removing => {
            let purpose = if ctx.record.state == S::RollbackPending {
                StepPurpose::Rollback
            } else {
                StepPurpose::Removal
            };
            let inspect = Next::Issue {
                stage: RemoteStage::Inspect,
                purpose,
                terminate: false,
                removal: None,
            };
            let Some(i) = fresh.and_then(parsed) else {
                return inspect;
            };
            // `i` holds only our marker lines: enough to decide absent or damaged.
            let (Some(ours), Some(line)) = (i.preimage(), line_of(ctx)) else {
                return Next::RemovalDamaged;
            };
            if i.marker_lines == 0 {
                return Next::AlreadyRemoved;
            }
            if heimdall_registry::post_image::post_image_without(ours, &line).is_err() {
                return Next::RemovalDamaged;
            }
            // The post-image needs the full bytes: from memory, or inspect again.
            let Some(pre) = full else {
                return inspect;
            };
            match heimdall_registry::post_image::post_image_without(pre, &line) {
                Ok(post) => Next::Issue {
                    stage: RemoteStage::Remove,
                    purpose,
                    terminate: false,
                    removal: Some((pre.to_vec(), post)),
                },
                Err(_) => Next::RemovalDamaged,
            }
        }
        S::AppliedUnverified
            if ctx.op.kind == OperationKind::EnrollmentApply
                && approval_valid
                && !ctx.op.state.is_settled() =>
        {
            Next::Verify
        }
        _ => Next::Nothing,
    }
}

/// The step's target: a removal of a held host-key change uses the freshly
/// evaluated target the decision carried (D5 §6.8).
fn effective_target(ctx: &Ctx) -> ApprovedTarget {
    match (&ctx.journal.fresh_target, ctx.op.kind) {
        (Some(t), OperationKind::EnrollmentRemove) => t.clone(),
        _ => ctx.record.target.clone(),
    }
}

fn class_name(c: StepClass) -> &'static str {
    match c {
        StepClass::Confirmed => "confirmed",
        StepClass::AlreadyPresent => "already_present",
        StepClass::NotApplied(_) => "not_applied",
        StepClass::Uncertain => "uncertain",
        StepClass::HostTrustChanged => "host_trust_changed",
        StepClass::ProviderLocked => "provider_locked",
        StepClass::InteractionRequired => "interaction_required",
        StepClass::Held => "held",
        _ => "unknown",
    }
}

/// The refusal of a step that ran nothing remote (before `HM1 ready`, or a lock
/// refusal), for the record's `failed_unwritten` settlement.
fn unwritten_error(class: StepClass) -> OpError {
    let (code, why, msg) = match class {
        StepClass::HostTrustChanged => (
            Code::HostTrustChanged,
            reason::ENROLLMENT_HOST_KEY_MISMATCH,
            "the destination's host key is not the approved one; nothing was written",
        ),
        StepClass::ProviderLocked => (
            Code::ProviderLocked,
            "provider_locked",
            "the existing-access provider is locked; nothing was written",
        ),
        StepClass::InteractionRequired => (
            Code::InteractionRequired,
            "interaction_required",
            "the existing access needs the owner's interaction; nothing was written",
        ),
        StepClass::NotApplied(NotAppliedReason::NotAfterPassed) => (
            Code::CapabilityUnavailable,
            "not_after_passed",
            "the step's remote not-after had passed; nothing was written",
        ),
        StepClass::NotApplied(NotAppliedReason::ParentAbsent) => (
            Code::CapabilityUnavailable,
            reason::REGISTRY_PARENT_ABSENT,
            "the registry's parent directory is absent; nothing was written",
        ),
        StepClass::NotApplied(NotAppliedReason::NoProcessGroup) => (
            Code::CapabilityUnavailable,
            reason::NO_PROCESS_GROUP,
            "the remote shell is not its own process-group leader; nothing was written",
        ),
        StepClass::NotApplied(NotAppliedReason::TooLarge) => (
            Code::ConfigConflict,
            reason::REGISTRY_TOO_LARGE,
            "the registry is too large; nothing was written",
        ),
        StepClass::NotApplied(NotAppliedReason::Busy) => (
            Code::ConfigConflict,
            reason::REGISTRY_BUSY,
            "the registry stayed locked; nothing was written",
        ),
        _ => (
            Code::CapabilityUnavailable,
            reason::REGISTRY_UNSUPPORTED,
            "the registry is not manageable, or the remote shell is not POSIX; nothing was written",
        ),
    };
    OpError::new(code, msg)
        .with_reason(why)
        .with_effect(EffectStatus::None)
}

fn held_error(reason_name: &str, msg: &str) -> OpError {
    OpError::new(Code::ConfigConflict, msg)
        .with_reason(reason_name)
        .with_effect(EffectStatus::Unknown)
}

impl Operations {
    /// The safe wall time (or the raw wall time when time is uncertain, with
    /// `false`: approvals are then not valid, failing closed).
    pub(super) async fn safe_now(&self) -> (Timestamp, bool) {
        match self.timegate().check().await {
            Ok(s) => (s.wall(), true),
            Err(_) => (self.narrowing_now().await, false),
        }
    }

    /// `Enrollment::Step` (ADR-0008 D5 §6.3 item 1; m03-plan U10 `next_step`).
    pub(super) async fn enroll_step(&self, id: &OperationId) -> Result<StepAnswer, OpError> {
        // R4: an unwired runtime refuses before anything (the time reads persist anchors).
        let _ = self.enrollment_ports()?;
        for _ in 0..4 {
            let oid = id.clone();
            let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
            if ctx.op.state.is_settled() || ctx.op.state == OperationState::AwaitingApproval {
                return self.done_answer(&ctx).await;
            }
            if ctx.journal.outstanding.is_some() {
                return Err(OpError::new(
                    Code::RequestConflict,
                    "a step of this enrollment is outstanding; send its result first",
                )
                .with_reason(reason::STEP_OUTSTANDING)
                .with_operation(id.clone()));
            }
            let clock = self.clock();
            let (boot, now_ms) = (clock.boot_id().0, ms(clock.continuous()));
            let (safe, safe_ok) = self.safe_now().await;
            let validity = self.limits().enrollment_approval_validity;
            let approval_valid = safe_ok && ctx.journal.approval_valid(safe, validity);
            let max_age = ms(self.limits().enrollment_inspect_max_age);
            let full = ctx
                .journal
                .inspection
                .as_ref()
                .and_then(|i| i.registry.as_ref())
                .and_then(|d| self.enrollment_state().inspected(&ctx.op.id, d));
            match next_of(
                &ctx,
                &boot,
                now_ms,
                max_age,
                approval_valid,
                full.as_deref(),
            ) {
                Next::Issue {
                    stage,
                    purpose,
                    terminate,
                    removal,
                } => {
                    return self
                        .issue(&ctx, stage, purpose, terminate, removal)
                        .await
                        .map(|s| StepAnswer::Step { step: Box::new(s) });
                }
                Next::Verify => {
                    self.start_initial_verification(id).await?;
                    self.verify_operation(id).await?;
                }
                Next::AlreadyRemoved => self.removal_without_step(&ctx, true).await?,
                Next::RemovalDamaged => self.removal_without_step(&ctx, false).await?,
                Next::Nothing => return self.done_answer(&ctx).await,
            }
        }
        let oid = id.clone();
        let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
        self.done_answer(&ctx).await
    }

    /// What `Step` answers when no step is needed: the stored result, or the error
    /// the operation's state stands for.
    async fn done_answer(&self, ctx: &Ctx) -> Result<StepAnswer, OpError> {
        match ctx.op.state {
            OperationState::Succeeded => {
                let result = ctx
                    .op
                    .result
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_else(|| result_of(&ctx.record, None));
                Ok(StepAnswer::Done {
                    result: Box::new(result),
                })
            }
            OperationState::OutcomeUnknown if ctx.journal.reconcile.is_none() => Err(OpError::new(
                Code::OutcomeUnknown,
                "the remote step may or may not have applied; reconcile",
            )
            .with_reason(if ctx.op.kind == OperationKind::EnrollmentRemove {
                reason::REMOVE_OUTCOME_UNKNOWN
            } else {
                reason::REGISTRY_OUTCOME_UNKNOWN
            })
            .with_next(next("reconcile", Some(&ctx.op.id)))
            .with_operation(ctx.op.id.clone())),
            OperationState::Running | OperationState::OutcomeUnknown => Ok(StepAnswer::Done {
                result: Box::new(result_of(&ctx.record, None)),
            }),
            _ => {
                let caller = Caller::unattended(ctx.op.key.caller.clone());
                match self.enrollment_respond(&ctx.op.id, &caller).await {
                    Ok(c) => Ok(StepAnswer::Done {
                        result: Box::new(
                            serde_json::from_value(c.data)
                                .unwrap_or_else(|_| result_of(&ctx.record, None)),
                        ),
                    }),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Issue `stage` (route re-evaluation, endpoint re-validation, the generated
    /// files, the one-time `ssh -G` check, then the receipt and the journal in one
    /// transaction).
    async fn issue(
        &self,
        ctx: &Ctx,
        stage: RemoteStage,
        purpose: StepPurpose,
        terminate: bool,
        removal: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<heimdall_contract::enrollment::RemoteStep, OpError> {
        let ports = self.enrollment_ports()?;
        let client = ports
            .host
            .client()
            .ok_or_else(|| OpError::driver_unavailable("no verified client"))?;
        let target = effective_target(ctx);
        // §17.1 item 2: the route re-evaluated before every dispatch.
        let evaluator = ports
            .wiring
            .target
            .as_ref()
            .ok_or_else(|| OpError::driver_unavailable("no target evaluator"))?;
        if !route_matches(&target, &evaluator.evaluate(&ctx.alias)) {
            return Err(refuse(
                Code::CapabilityUnavailable,
                reason::ROUTE_CHANGED,
                "the alias no longer evaluates to the approved target; a new enrollment decision is needed",
            )
            .with_operation(ctx.op.id.clone()));
        }
        let endpoint =
            endpoint_of(&ctx.record).ok_or_else(|| internal("the enrollment names no endpoint"))?;
        if !ports.host.endpoint_valid(&endpoint) {
            return Err(refuse(
                Code::CapabilityUnavailable,
                reason::EXISTING_ACCESS_CHANGED,
                "the approved existing-access endpoint changed; a new enrollment decision is needed",
            )
            .with_operation(ctx.op.id.clone()));
        }
        let tag = ctx
            .journal
            .tag
            .clone()
            .unwrap_or_else(|| crate::enrollment::tag_of(&ctx.record.id));
        let identity_public = if ctx.record.existing_access.public_key_file.is_none() {
            ctx.identity_public.as_deref()
        } else {
            None
        };
        let paths = ports
            .host
            .write_files(&tag, &known_hosts_line(&tag, &target), identity_public)
            .map_err(|_| {
                OpError::driver_unavailable("the enrollment files could not be written")
            })?;
        let identity_file = ctx
            .record
            .existing_access
            .public_key_file
            .clone()
            .unwrap_or_else(|| paths.identity_file.clone());
        let host_trust =
            step::trust_pins(&target, &paths.trust).map_err(|_| internal("the host-trust pins"))?;
        let access = step::access_pins(&endpoint, &identity_file)
            .map_err(|_| internal("the existing-access pins"))?;
        let host_trust = step::render_pairs(&host_trust);
        let invocation = step::render_invocation(&access);
        let registry = registry_canonical(&ctx.record);
        let line = line_of(ctx).ok_or_else(|| internal("the registry line cannot be rebuilt"))?;
        let st = StepTarget {
            alias: &ctx.alias,
            target: &target,
            host_trust: &host_trust,
            invocation: &invocation,
            registry: &registry,
            line: &line,
        };
        let interactive = ctx
            .journal
            .reconcile
            .as_ref()
            .map_or(ctx.journal.interactive, |r| r.interactive);
        let limits = *self.limits();
        let timeout = if interactive {
            limits.enrollment_step_timeout_interactive
        } else {
            limits.enrollment_step_timeout
        };
        let clock = self.clock();
        let c_issue = clock.continuous();
        let boot = clock.boot_id().0;
        let wall = clock.wall();
        let hard = heimdall_registry::fence::step_hard_deadline(c_issue, timeout)
            .ok_or_else(|| internal("deadline overflow"))?;
        let mutating = matches!(stage, RemoteStage::Append | RemoteStage::Remove);
        let not_after = if mutating {
            let i = ctx
                .journal
                .inspection
                .as_ref()
                .ok_or_else(|| internal("a mutation without an inspection"))?;
            Some(
                heimdall_registry::fence::not_after_remote(
                    i.remote_now,
                    std::time::Duration::from_millis(i.read_continuous_ms),
                    c_issue,
                    timeout,
                )
                .map_err(|_| internal("the remote not-after"))?,
            )
        } else {
            None
        };
        let token = new_step_token()?;
        let input = match (&stage, &removal) {
            (RemoteStage::Inspect, _) => StageInput::Inspect,
            (RemoteStage::Bootstrap, _) => StageInput::Bootstrap,
            (RemoteStage::Append, _) => StageInput::Append,
            (RemoteStage::Remove, Some((pre, post))) => StageInput::Remove {
                preimage: pre,
                post_image: post,
            },
            (RemoteStage::Fence, _) => StageInput::Fence { terminate },
            _ => return Err(internal("unknown stage")),
        };
        let gssapi = ctx.journal.effective_checked.unwrap_or(false);
        let timeout_ms = ms(timeout);
        let hard_ms = ms(hard);
        // ⟨round 2⟩ D5 §6.7: `fence` fences the **uncertain step's** lock (its token
        // is in the holder record); the fence step keeps its own step token, which
        // its result must carry.
        let script_token = match stage {
            RemoteStage::Fence => ctx
                .journal
                .uncertain
                .as_ref()
                .map(|u| u.token.clone())
                .ok_or_else(|| internal("a fence without an uncertain step"))?,
            _ => token.clone(),
        };
        let build = |gss: bool| {
            step::remote_step_for(
                input,
                &st,
                &script_token,
                hard_ms,
                not_after,
                &StepEnv {
                    client: &client,
                    timeout_ms,
                    interactive,
                    gssapi_key_exchange: gss,
                },
            )
            .map(|mut s| {
                s.step_token.clone_from(&token);
                s
            })
            .map_err(|_| internal("the remote step cannot be built"))
        };
        let mut remote = build(gssapi)?;
        // ⟨D5 §6.3⟩ The effective configuration is checked once per operation (Q23).
        let mut checked = ctx.journal.effective_checked;
        if checked.is_none() {
            let unpinnable = || {
                refuse(
                    Code::CapabilityUnavailable,
                    reason::HOST_TRUST_UNPINNABLE,
                    "the client's effective configuration does not have every host-trust pin",
                )
                .with_operation(ctx.op.id.clone())
            };
            let mut out = ports
                .host
                .effective_config(&remote)
                .map_err(|_| unpinnable())?;
            let mut gss = false;
            if step::client_lists_gssapi_kex(&out) {
                gss = true;
                remote = build(true)?;
                out = ports
                    .host
                    .effective_config(&remote)
                    .map_err(|_| unpinnable())?;
            }
            step::check_effective(&out, &remote.pins).map_err(|_| unpinnable())?;
            checked = Some(gss);
        }
        let issued = IssuedStep {
            stage,
            token: token.clone(),
            purpose,
            issued_continuous_ms: ms(c_issue),
            issued_wall: wall,
            boot_id: boot,
            timeout_ms,
            hard_deadline_ms: hard_ms,
            hard_deadline_wall: super::super::plus(wall, hard.saturating_sub(c_issue)),
            not_after_remote: not_after,
            terminate,
            preimage: removal
                .as_ref()
                .map(|(p, _)| crate::enrollment::RegistryDigest::of(p)),
            post_image: removal
                .as_ref()
                .map(|(_, p)| crate::enrollment::RegistryDigest::of(p)),
        };
        let (oid, expected_state, marker, eid) = (
            ctx.op.id.clone(),
            ctx.record.state,
            ctx.record.marker.clone(),
            ctx.record.id.to_string(),
        );
        let now = wall;
        self.write(move |tx, _| {
            let fresh = match load_ctx(tx, &oid)? {
                Ok(c) => c,
                Err(e) => return Ok(Err(e)),
            };
            let mut j = fresh.journal;
            if j.outstanding.is_some() || fresh.record.state != expected_state {
                return Ok(Err(OpError::new(
                    Code::RequestConflict,
                    "a step of this enrollment is outstanding; send its result first",
                )
                .with_reason(reason::STEP_OUTSTANDING)));
            }
            // The stage receipt first (D5 §6.3 item 1).
            let effect = |suffix: &str| EffectReceipt::Attempted {
                adapter: adapter(&eid),
                effect_token: format!("{marker}{suffix}"),
            };
            let (name, effect) = match (stage, purpose) {
                (RemoteStage::Inspect, _) => (
                    enrollment_stage::INSPECT_STARTED,
                    EffectReceipt::NotAttempted,
                ),
                (RemoteStage::Bootstrap, _) => (enrollment_stage::BOOTSTRAP, effect(":dir")),
                (RemoteStage::Append, _) => (enrollment_stage::APPEND, effect("")),
                (RemoteStage::Remove, StepPurpose::Rollback) => {
                    (enrollment_stage::ROLLBACK, effect(":rm"))
                }
                (RemoteStage::Remove, _) => (enrollment_stage::REMOVE, effect(":rm")),
                _ => ("enroll.fence", EffectReceipt::NotAttempted),
            };
            tx.append_stage_receipt(&oid, &receipt(name, now, effect))?;
            j.outstanding = Some(issued);
            j.effective_checked = checked;
            put_journal(tx, &oid, &j, now)?;
            Ok(Ok(()))
        })
        .await??;
        Ok(remote)
    }

    /// `Enrollment::StepResult` (ADR-0008 D5 §6.3 items 2–3; m03-plan U10
    /// `record_step_result`).
    pub(super) async fn enroll_step_result(
        &self,
        id: &OperationId,
        token: &str,
        exit_status: i32,
        stdout: String,
        stderr_excerpt: String,
    ) -> Result<StepRecorded, OpError> {
        let _ = self.enrollment_ports()?;
        let oid = id.clone();
        let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
        let Some(issued) = ctx.journal.outstanding.clone().filter(|s| s.token == token) else {
            return Err(OpError::new(
                Code::RequestConflict,
                "this step token is not the outstanding step's; nothing was recorded",
            )
            .with_reason(reason::STEP_TOKEN_MISMATCH)
            .with_operation(id.clone()));
        };
        let limits = *self.limits();
        let stdout = if stdout.len() > limits.remote_stdout_max {
            String::new()
        } else {
            stdout
        };
        let stderr_excerpt: String = stderr_excerpt
            .chars()
            .take(limits.remote_stderr_excerpt)
            .collect();
        let line = line_of(&ctx);
        // §17.21 item 4: the checks take the images by their digests.
        let preimage_digest = match issued.stage {
            RemoteStage::Remove => issued.preimage.as_ref(),
            _ => ctx
                .journal
                .inspection
                .as_ref()
                .and_then(|i| i.registry.as_ref()),
        };
        let expected = Expected {
            marker: ctx.record.marker.clone(),
            line: line.clone(),
            preimage: None,
            post_image: None,
            preimage_digest: preimage_digest.map(crate::enrollment::RegistryDigest::image),
            post_image_digest: issued
                .post_image
                .as_ref()
                .map(crate::enrollment::RegistryDigest::image),
        };
        if issued.stage == RemoteStage::Inspect {
            // The full bytes stay in this runtime's memory only (§17.21 item 4).
            if let Some(content) = hm1::parse(stdout.as_bytes())
                .ok()
                .and_then(|rec| Inspection::from_record(&rec, &ctx.record.marker).ok())
                .and_then(|i| i.preimage().map(<[u8]>::to_vec))
            {
                self.enrollment_state().remember_inspected(id, content);
            }
        }
        let result = RegistryStepResult {
            exit_status,
            stdout: stdout.clone(),
            stderr_excerpt,
        };
        let class = classify_step(issued.stage, &result, &expected);
        let clock = self.clock();
        let (c_read, boot, wall) = (ms(clock.continuous()), clock.boot_id().0, clock.wall());
        let (safe, safe_ok) = self.safe_now().await;
        let approval_valid = safe_ok
            && ctx
                .journal
                .approval_valid(safe, limits.enrollment_approval_validity);
        let retention = self.retention();
        let busy_retries = limits.enrollment_busy_retries;
        let token_owned = token.to_owned();
        let oid = id.clone();
        let issued_stage = issued.stage;
        let verify_after = self
            .write(move |tx, emit| {
                let fresh = load_ctx(tx, &oid)?;
                let Ok(mut ctx) = fresh else {
                    return Ok(Err(internal("the operation vanished")));
                };
                if ctx.journal.outstanding.as_ref().map(|s| s.token.as_str())
                    != Some(token_owned.as_str())
                {
                    return Ok(Err(OpError::new(
                        Code::RequestConflict,
                        "this step token is not the outstanding step's; nothing was recorded",
                    )
                    .with_reason(reason::STEP_TOKEN_MISMATCH)));
                }
                ctx.journal.outstanding = None;
                let rec = Recording {
                    issued: &issued,
                    class,
                    stdout: &stdout,
                    exit_status,
                    c_read,
                    boot: &boot,
                    now: wall,
                    approval_valid,
                    retention,
                    busy_retries,
                };
                record_result(tx, emit, &mut ctx, &rec).map(Ok)
            })
            .await??;
        if verify_after {
            self.start_initial_verification(id).await?;
            self.verify_operation(id).await?;
        }
        let oid = id.clone();
        let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
        let settled = ctx.op.state.is_settled();
        let more = !settled
            && matches!(
                ctx.record.state,
                EnrollmentState::Applying
                    | EnrollmentState::RollbackPending
                    | EnrollmentState::Removing
            )
            || ctx.journal.reconcile.is_some();
        let succeeded = ctx.op.state == OperationState::Succeeded;
        let result = succeeded.then(|| {
            Box::new(
                ctx.op
                    .result
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_else(|| result_of(&ctx.record, None)),
            )
        });
        let error = (settled && !succeeded)
            .then(|| ctx.op.result.as_ref().and_then(|v| v.get("error").cloned()))
            .flatten();
        Ok(StepRecorded {
            stage: issued_stage,
            class: class_name(class).to_owned(),
            state: ctx.record.state,
            more,
            result,
            error,
        })
    }

    /// Move a running `applied_unverified` apply to `verifying` (E4 starts).
    pub(super) async fn start_initial_verification(&self, id: &OperationId) -> Result<(), OpError> {
        let oid = id.clone();
        let now = self.narrowing_now().await;
        self.write(move |tx, emit| {
            let Ok(ctx) = load_ctx(tx, &oid)? else {
                return Ok(());
            };
            if ctx.record.state != EnrollmentState::AppliedUnverified {
                return Ok(());
            }
            let mut updated = ctx.record.clone();
            updated.updated_at = now;
            move_record(
                tx,
                emit,
                EnrollmentState::AppliedUnverified,
                EnrollmentEventKind::StartVerification,
                &updated,
                Some(&oid),
            )?;
            Ok(())
        })
        .await
    }

    /// A removal whose inspect showed nothing of ours (confirmed with no remote
    /// change) or a damaged line (`held`).
    async fn removal_without_step(&self, ctx: &Ctx, absent: bool) -> Result<(), OpError> {
        let oid = ctx.op.id.clone();
        let retention = self.retention();
        let now = self.narrowing_now().await;
        self.write(move |tx, emit| {
            let Ok(mut ctx) = load_ctx(tx, &oid)? else {
                return Ok(());
            };
            if absent {
                removal_confirmed(tx, emit, &mut ctx, now, retention)
            } else {
                hold(
                    tx,
                    emit,
                    &mut ctx,
                    EnrollmentEventKind::RemovalHeld,
                    HoldReason::RegistryLineDamaged,
                    held_error(
                        reason::REGISTRY_LINE_DAMAGED,
                        "the registry holds a damaged or repeated marker line; check it by hand",
                    ),
                    now,
                    retention,
                )
            }
        })
        .await
    }

    /// `Enrollment::Reconcile` (ADR-0008 D5 §6.7; F20): owner role (checked by the
    /// caller). An uncertain step enters the reconcile, whose `inspect` and `fence`
    /// are client-executed (`enroll step`); an `applied_unverified` record under a
    /// valid approval retries its initial verification here.
    pub(super) async fn enroll_reconcile(
        &self,
        caller: &Caller,
        id: &OperationId,
        interaction: InteractionMode,
        after_manual_recovery: bool,
    ) -> OpResult<serde_json::Value> {
        let _ = self.enrollment_ports()?;
        let oid = id.clone();
        let ctx = self.write(move |tx, _| load_ctx(tx, &oid)).await??;
        use EnrollmentState as S;
        let (safe, safe_ok) = self.safe_now().await;
        let approval_valid = safe_ok
            && ctx
                .journal
                .approval_valid(safe, self.limits().enrollment_approval_validity);
        let uncertain_state = matches!(
            ctx.record.state,
            S::OutcomeUnknown | S::RollbackUnknown | S::RemoveUnknown
        );
        let manual = ctx.record.state == S::Held
            && ctx.record.hold.map(|h| h.kind()) == Some(HoldKind::LockHolderUnresolved)
            && after_manual_recovery
            && ctx.record.form == EnrollmentForm::Account;
        if ctx.record.state == S::AppliedUnverified
            && ctx.op.kind == OperationKind::EnrollmentApply
            && !ctx.op.state.is_settled()
        {
            if !approval_valid {
                // B R2-06: after the approval lapsed the retry is `enroll verify`.
                let oid = id.clone();
                let retention = self.retention();
                let now = self.narrowing_now().await;
                self.write(move |tx, emit| {
                    let Some(mut op) = tx.operation(&oid)? else {
                        return Ok(());
                    };
                    let err = OpError::new(
                        Code::DecisionStale,
                        "the enrollment's approval lapsed: verify it with `enroll verify`",
                    )
                    .with_reason(reason::APPROVAL_LAPSED)
                    .with_effect(EffectStatus::Applied);
                    settle_open(tx, emit, &mut op, &err, now, retention)
                })
                .await?;
                return self.enrollment_respond(id, caller).await;
            }
            self.start_initial_verification(id).await?;
            self.verify_operation(id).await?;
            return self.enrollment_respond(id, caller).await;
        }
        if !(uncertain_state || manual) || ctx.journal.uncertain.is_none() {
            if matches!(
                ctx.record.state,
                S::Applying | S::RollbackPending | S::Removing
            ) && !ctx.op.state.is_settled()
            {
                return Ok(Completed::ok(
                    Code::Accepted,
                    serde_json::json!({ "next": "step", "operation_id": id }),
                )
                .with_operation(id.clone()));
            }
            return Err(refuse(
                Code::ConfigConflict,
                "nothing_to_reconcile",
                "this enrollment operation has no uncertain step to reconcile",
            )
            .with_operation(id.clone()));
        }
        let attended = caller.is_attended();
        let interactive = interaction == InteractionMode::Interactive;
        let oid = id.clone();
        let now = self.narrowing_now().await;
        self.write(move |tx, _| {
            let receipts = tx.stage_receipts(&oid)?;
            let Some(mut j) = journal_of(&receipts) else {
                return Ok(());
            };
            if j.outstanding.is_some() {
                return Ok(());
            }
            j.reconcile = Some(ReconcileFact {
                attended,
                interactive,
                after_manual_recovery,
                fence: None,
            });
            if let Some(i) = j.inspection.as_mut() {
                i.consumed = true;
            }
            put_journal(tx, &oid, &j, now)
        })
        .await?;
        Ok(Completed::ok(
            Code::Accepted,
            serde_json::json!({ "next": "step", "operation_id": id }),
        )
        .with_operation(id.clone()))
    }
}

/// The facts of one step result.
struct Recording<'a> {
    issued: &'a IssuedStep,
    class: StepClass,
    stdout: &'a str,
    exit_status: i32,
    c_read: u64,
    boot: &'a str,
    now: Timestamp,
    approval_valid: bool,
    retention: std::time::Duration,
    busy_retries: u32,
}

/// Record one step result with its transition (one transaction). Returns whether
/// the initial verification runs next.
fn record_result(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    r: &Recording<'_>,
) -> heimdall_store::Result<bool> {
    let now = r.now;
    let eid = ctx.record.id.to_string();
    let marker = ctx.record.marker.clone();
    if ctx.journal.reconcile.is_some() {
        return record_reconcile(tx, emit, ctx, r);
    }
    match r.issued.stage {
        RemoteStage::Inspect => {
            tx.append_stage_receipt(
                &ctx.op.id,
                &receipt(
                    enrollment_stage::INSPECT_OBSERVED,
                    now,
                    EffectReceipt::NotAttempted,
                ),
            )?;
            match r.class {
                StepClass::Confirmed => {
                    let reading = hm1::parse(r.stdout.as_bytes())
                        .ok()
                        .and_then(|rec| Inspection::from_record(&rec, &marker).ok());
                    let Some(reading) = reading else {
                        put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                        return Ok(false);
                    };
                    // The E2 reading is the initial verification's known offset: the
                    // remote clock minus local time, within 1 s plus the round trip.
                    let local_ms = i128::from(now.as_millisecond());
                    let remote_ms = i128::from(reading.remote_now).saturating_mul(1000);
                    let offset = i64::try_from(remote_ms - local_ms).unwrap_or(i64::MIN);
                    let rtt = r.c_read.saturating_sub(r.issued.issued_continuous_ms);
                    ctx.journal.remote_offset = Some((offset, rtt.saturating_add(1000)));
                    ctx.journal.inspection =
                        Some(inspect_fact(&reading, &marker, line_of(ctx).as_deref(), r));
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    Ok(false)
                }
                c @ (StepClass::HostTrustChanged
                | StepClass::ProviderLocked
                | StepClass::InteractionRequired
                | StepClass::NotApplied(_)) => {
                    // A read that wrote nothing: for an initial append, the record is
                    // `failed_unwritten` (D5 §6.10: refused before any write); for a
                    // removal it stays, and the owner retries.
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    if ctx.record.state == EnrollmentState::Applying {
                        unwritten(tx, emit, ctx, unwritten_error(c), now, r.retention)?;
                    }
                    Ok(false)
                }
                _ => {
                    // A read can be retried.
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    Ok(false)
                }
            }
        }
        RemoteStage::Bootstrap => match r.class {
            StepClass::Confirmed | StepClass::AlreadyPresent => {
                tx.append_stage_receipt(
                    &ctx.op.id,
                    &receipt(
                        enrollment_stage::BOOTSTRAP,
                        now,
                        EffectReceipt::Confirmed {
                            adapter: adapter(&eid),
                            credential_ref: "dir_present".to_owned(),
                        },
                    ),
                )?;
                ctx.journal.bootstrap_done = true;
                put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                let mut updated = ctx.record.clone();
                updated.updated_at = now;
                move_ctx(
                    tx,
                    emit,
                    ctx,
                    EnrollmentEventKind::BootstrapConfirmed,
                    &updated,
                )?;
                Ok(false)
            }
            StepClass::Uncertain => {
                uncertain(
                    tx,
                    emit,
                    ctx,
                    r,
                    &format!("{marker}:dir"),
                    enrollment_stage::BOOTSTRAP,
                )?;
                Ok(false)
            }
            c => {
                tx.append_stage_receipt(
                    &ctx.op.id,
                    &receipt(
                        enrollment_stage::BOOTSTRAP,
                        now,
                        EffectReceipt::NotAttempted,
                    ),
                )?;
                put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                unwritten(tx, emit, ctx, unwritten_error(c), now, r.retention)?;
                Ok(false)
            }
        },
        RemoteStage::Append => {
            if let Some(i) = ctx.journal.inspection.as_mut() {
                i.consumed = true;
            }
            match r.class {
                StepClass::Confirmed | StepClass::AlreadyPresent => {
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(
                            enrollment_stage::APPEND,
                            now,
                            EffectReceipt::Confirmed {
                                adapter: adapter(&eid),
                                credential_ref: marker.clone(),
                            },
                        ),
                    )?;
                    ctx.journal.busy = 0;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    let mut updated = ctx.record.clone();
                    updated.updated_at = now;
                    move_ctx(
                        tx,
                        emit,
                        ctx,
                        EnrollmentEventKind::AppendConfirmed,
                        &updated,
                    )?;
                    Ok(r.approval_valid)
                }
                StepClass::Uncertain => {
                    uncertain(tx, emit, ctx, r, &marker, enrollment_stage::APPEND)?;
                    Ok(false)
                }
                StepClass::Held => {
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(
                            enrollment_stage::APPEND,
                            now,
                            EffectReceipt::Uncertain {
                                adapter: adapter(&eid),
                                effect_token: marker.clone(),
                            },
                        ),
                    )?;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    hold(
                        tx,
                        emit,
                        ctx,
                        EnrollmentEventKind::PostWriteCheckFailed,
                        HoldReason::PostWriteCheckFailed,
                        held_error(
                            reason::REGISTRY_LINE_DAMAGED,
                            "the post-write check failed: check the registry's exact bytes by hand",
                        ),
                        now,
                        r.retention,
                    )?;
                    Ok(false)
                }
                StepClass::NotApplied(NotAppliedReason::Busy) => {
                    ctx.journal.busy = ctx.journal.busy.saturating_add(1);
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(enrollment_stage::APPEND, now, EffectReceipt::NotAttempted),
                    )?;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    if ctx.journal.busy >= r.busy_retries {
                        unwritten(tx, emit, ctx, unwritten_error(r.class), now, r.retention)?;
                    } else {
                        let mut updated = ctx.record.clone();
                        updated.updated_at = now;
                        move_ctx(tx, emit, ctx, EnrollmentEventKind::StepBusy, &updated)?;
                    }
                    Ok(false)
                }
                StepClass::NotApplied(NotAppliedReason::DirAbsent)
                    if !ctx.journal.bootstrap_done =>
                {
                    // The directory vanished after the inspect: inspect again.
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(enrollment_stage::APPEND, now, EffectReceipt::NotAttempted),
                    )?;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    Ok(false)
                }
                c => {
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(enrollment_stage::APPEND, now, EffectReceipt::NotAttempted),
                    )?;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    unwritten(tx, emit, ctx, unwritten_error(c), now, r.retention)?;
                    Ok(false)
                }
            }
        }
        RemoteStage::Remove => {
            if let Some(i) = ctx.journal.inspection.as_mut() {
                i.consumed = true;
            }
            let stage_name = if ctx.record.state == EnrollmentState::RollbackPending {
                enrollment_stage::ROLLBACK
            } else {
                enrollment_stage::REMOVE
            };
            match r.class {
                StepClass::Confirmed | StepClass::AlreadyPresent => {
                    tx.append_stage_receipt(
                        &ctx.op.id,
                        &receipt(
                            stage_name,
                            now,
                            EffectReceipt::Confirmed {
                                adapter: adapter(&eid),
                                credential_ref: format!("{marker}:rm"),
                            },
                        ),
                    )?;
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    removal_confirmed(tx, emit, ctx, now, r.retention)?;
                    Ok(false)
                }
                StepClass::Uncertain => {
                    uncertain(tx, emit, ctx, r, &format!("{marker}:rm"), stage_name)?;
                    Ok(false)
                }
                StepClass::NotApplied(NotAppliedReason::ChangedSinceRead) => {
                    ctx.journal.changed = ctx.journal.changed.saturating_add(1);
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    if ctx.journal.changed >= 3 {
                        hold(
                            tx,
                            emit,
                            ctx,
                            EnrollmentEventKind::RemovalHeld,
                            HoldReason::RegistryChanged,
                            held_error(
                                reason::REGISTRY_CHANGED,
                                "the registry changed during the removal three times",
                            ),
                            now,
                            r.retention,
                        )?;
                    }
                    Ok(false)
                }
                StepClass::NotApplied(NotAppliedReason::Refused) | StepClass::Held => {
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    hold(
                        tx,
                        emit,
                        ctx,
                        EnrollmentEventKind::RemovalHeld,
                        HoldReason::RegistryNotRewritable,
                        held_error(
                            reason::REGISTRY_NOT_REWRITABLE,
                            "the registry cannot be rewritten safely: delete the line by hand, then reconcile",
                        ),
                        now,
                        r.retention,
                    )?;
                    Ok(false)
                }
                _ => {
                    // Nothing changed (busy, host trust, provider, not-after): the
                    // removal stays, and the owner retries the step.
                    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                    Ok(false)
                }
            }
        }
        _ => {
            put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
            Ok(false)
        }
    }
}

/// An uncertain mutation (lost, timed out, or ambiguous): `Uncertain` receipt, the
/// record's `*_unknown` state and the operation `outcome_unknown` (D5 §6.4).
fn uncertain(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    r: &Recording<'_>,
    effect_token: &str,
    stage_name: &str,
) -> heimdall_store::Result<()> {
    mark_uncertain(tx, emit, ctx, r.issued, effect_token, stage_name, r.now)
}

/// [`uncertain`] for the step-timeout pass too.
pub(super) fn mark_uncertain(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    issued: &IssuedStep,
    effect_token: &str,
    stage_name: &str,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let eid = ctx.record.id.to_string();
    tx.append_stage_receipt(
        &ctx.op.id,
        &receipt(
            stage_name,
            now,
            EffectReceipt::Uncertain {
                adapter: adapter(&eid),
                effect_token: effect_token.to_owned(),
            },
        ),
    )?;
    ctx.journal.outstanding = None;
    ctx.journal.uncertain = Some(UncertainStep {
        stage: issued.stage,
        token: issued.token.clone(),
        not_after_remote: issued.not_after_remote,
        purpose: issued.purpose,
        hard_deadline_ms: issued.hard_deadline_ms,
        hard_deadline_wall: issued.hard_deadline_wall,
        boot_id: issued.boot_id.clone(),
    });
    put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
    let event = match ctx.record.state {
        EnrollmentState::Applying => EnrollmentEventKind::AppendOutcomeLost,
        _ => EnrollmentEventKind::RemovalOutcomeLost,
    };
    let mut updated = ctx.record.clone();
    updated.updated_at = now;
    move_ctx(tx, emit, ctx, event, &updated)?;
    if ctx.op.state == OperationState::Running {
        op_to(&mut ctx.op, OperationEvent::EffectUncertain, now)?;
        ctx.op.code = Some(Code::OutcomeUnknown);
        ctx.op.effect_status = EffectStatus::Unknown;
        tx.update_operation(&ctx.op)?;
        emit.op(tx, &ctx.op)?;
    }
    Ok(())
}

/// The record `failed_unwritten` and the operation failed with `err`.
fn unwritten(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    err: OpError,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    if ctx.record.state == EnrollmentState::Applying {
        let mut updated = ctx.record.clone();
        updated.updated_at = now;
        move_ctx(
            tx,
            emit,
            ctx,
            EnrollmentEventKind::RefusedBeforeWrite,
            &updated,
        )?;
    }
    settle_open(tx, emit, &mut ctx.op, &err, now, retention)
}

/// The record `held` with `reason` (event `kind`), the operation failed with `err`.
#[allow(clippy::too_many_arguments)]
fn hold(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    kind: EnrollmentEventKind,
    why: HoldReason,
    err: OpError,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    let mut updated = ctx.record.clone();
    updated.updated_at = now;
    updated.hold = Some(EnrollmentHold {
        reason: why,
        evidence_based: false,
    });
    move_ctx(tx, emit, ctx, kind, &updated)?;
    settle_open(tx, emit, &mut ctx.op, &err, now, retention)
}

/// A removal or rollback removed the line: `removed` / `verification_failed`, the
/// CA leaves the pair's issuing set, and the operation settles.
fn removal_confirmed(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    let rollback = ctx.record.state == EnrollmentState::RollbackPending;
    let event = match ctx.record.state {
        EnrollmentState::RollbackUnknown | EnrollmentState::RemoveUnknown => {
            EnrollmentEventKind::ReconcileApplied
        }
        _ => EnrollmentEventKind::RemovalConfirmed,
    };
    let rollback = rollback || ctx.record.state == EnrollmentState::RollbackUnknown;
    let mut updated = ctx.record.clone();
    updated.updated_at = now;
    updated.hold = None;
    move_ctx(tx, emit, ctx, event, &updated)?;
    if ctx.foreign.is_none() {
        tx.remove_issuing_ca(&pair_of(&ctx.record), &ctx.record.ca_fingerprint, now)?;
    }
    if rollback {
        let err = OpError::new(
            Code::CapabilityUnavailable,
            "the verification failed and the line was rolled back: the registry is probably not the server's authoritative one, or certificates are unsupported",
        )
        .with_reason(reason::VERIFICATION_FAILED)
        .with_effect(EffectStatus::Applied);
        settle_open(tx, emit, &mut ctx.op, &err, now, retention)
    } else {
        let data = serde_json::to_value(result_of(&ctx.record, None))
            .map_err(|_| store_conflict("result"))?;
        settle_ok(tx, emit, &mut ctx.op, data, now, retention)
    }
}

/// The reconcile's purpose for the uncertain step.
fn reconcile_purpose(u: &UncertainStep) -> ReconcilePurpose {
    match (u.stage, u.purpose) {
        (RemoteStage::Bootstrap, _) => ReconcilePurpose::Bootstrap,
        (_, StepPurpose::Rollback) => ReconcilePurpose::Rollback,
        (_, StepPurpose::Removal) => ReconcilePurpose::Removal,
        _ => ReconcilePurpose::Append,
    }
}

fn lock_view(f: Option<FenceFact>) -> LockView {
    match f {
        None => LockView::None,
        Some(FenceFact::None) => LockView::None,
        Some(FenceFact::Other) => LockView::Other,
        Some(FenceFact::Gone) => LockView::Ours(OurLock::Gone),
        Some(FenceFact::Alive {
            not_after_passed,
            terminated,
        }) => LockView::Ours(OurLock::Alive {
            not_after_passed,
            terminated,
        }),
        Some(FenceFact::Unproven { .. }) => LockView::Ours(OurLock::Unproven {
            signals: heimdall_registry::fence::FenceSignals::None,
        }),
    }
}

fn fence_fact(v: LockView) -> FenceFact {
    match v {
        LockView::Ours(OurLock::Gone) => FenceFact::Gone,
        LockView::Ours(OurLock::Alive {
            not_after_passed,
            terminated,
        }) => FenceFact::Alive {
            not_after_passed,
            terminated,
        },
        LockView::Ours(OurLock::Unproven { signals }) => FenceFact::Unproven {
            terminated: signals.any(),
        },
        LockView::Other => FenceFact::Other,
        _ => FenceFact::None,
    }
}

/// A reconcile step's result (D5 §6.7: fencing first, then the table).
fn record_reconcile(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    ctx: &mut Ctx,
    r: &Recording<'_>,
) -> heimdall_store::Result<bool> {
    let now = r.now;
    let marker = ctx.record.marker.clone();
    let Some(rec_fact) = ctx.journal.reconcile.clone() else {
        return Ok(false);
    };
    let Some(u) = ctx.journal.uncertain.clone() else {
        ctx.journal.reconcile = None;
        put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
        return Ok(false);
    };
    let Some(line) = line_of(ctx) else {
        return Err(store_conflict("the registry line"));
    };
    let mut fence = rec_fact.fence;
    match r.issued.stage {
        RemoteStage::Inspect => {
            tx.append_stage_receipt(
                &ctx.op.id,
                &receipt(
                    enrollment_stage::INSPECT_OBSERVED,
                    now,
                    EffectReceipt::NotAttempted,
                ),
            )?;
            let reading = (r.class == StepClass::Confirmed)
                .then(|| {
                    hm1::parse(r.stdout.as_bytes())
                        .ok()
                        .and_then(|rec| Inspection::from_record(&rec, &marker).ok())
                })
                .flatten();
            if let Some(reading) = &reading {
                ctx.journal.inspection =
                    Some(inspect_fact(reading, &marker, line_of(ctx).as_deref(), r));
            }
        }
        RemoteStage::Fence => {
            let reading = hm1::parse(r.stdout.as_bytes())
                .ok()
                .and_then(|rec| FenceReading::from_record(&rec, r.exit_status).ok());
            // §17.10 item 4: the audit keeps what the fence decided and sent.
            let audit = serde_json::json!({
                "lock_token": u.token,
                "terminate": r.issued.terminate,
                "exit_status": r.exit_status,
                "decisions": reading.as_ref().map(|f| f.decisions.iter().map(|d| format!("{d:?}").to_ascii_lowercase()).collect::<Vec<_>>()),
                "signals": reading.as_ref().map(|f| f.signals.as_str()),
                "holder": reading.as_ref().and_then(|f| f.holder.as_ref().map(heimdall_registry::classify::HolderRecord::render)),
            });
            tx.append_stage_receipt(
                &ctx.op.id,
                &receipt(
                    "enroll.fence",
                    now,
                    EffectReceipt::Confirmed {
                        adapter: adapter("fence"),
                        credential_ref: audit.to_string(),
                    },
                ),
            )?;
            let view = match &reading {
                Some(f) => f.lock_view(r.issued.terminate),
                None => LockView::Ours(OurLock::Unproven {
                    signals: heimdall_registry::fence::FenceSignals::TermKill,
                }),
            };
            fence = Some(fence_fact(view));
            if matches!(view, LockView::Ours(OurLock::Gone)) {
                // Gone: the link is removed; the next read is classified (inspect again).
                if let Some(i) = ctx.journal.inspection.as_mut() {
                    i.consumed = true;
                }
                ctx.journal.reconcile = Some(ReconcileFact { fence, ..rec_fact });
                put_journal(tx, &ctx.op.id, &ctx.journal, now)?;
                return Ok(false);
            }
        }
        _ => {}
    }
    let observation = match ctx.journal.inspection.as_ref().filter(|i| !i.consumed) {
        Some(i) => match parsed(i) {
            Some(p) => Observation::Inspected(Box::new(p)),
            None => Observation::Unavailable,
        },
        None => Observation::Unavailable,
    };
    let expected = ReconcileExpected {
        purpose: reconcile_purpose(&u),
        line: &line,
        step_token: &u.token,
        not_after_remote: u.not_after_remote,
        approval_valid: r.approval_valid,
        attended: rec_fact.attended,
        route_unchanged: true,
        after_manual_recovery: rec_fact.after_manual_recovery,
    };
    let view = FenceView {
        lock: lock_view(fence),
        attempts: ctx.journal.fence_attempts,
    };
    let class = classify_reconcile(&observation, &expected, view);
    if class.counts_attempt() {
        ctx.journal.fence_attempts = ctx.journal.fence_attempts.saturating_add(1);
    }
    let mut updated = ctx.record.clone();
    updated.updated_at = now;
    let op_id = ctx.op.id.clone();
    let end_reconcile = |j: &mut Journal| {
        j.reconcile = None;
    };
    match class {
        ReconcileClass::Fence | ReconcileClass::Terminate => {
            let terminate = class == ReconcileClass::Terminate;
            ctx.journal.reconcile = Some(ReconcileFact {
                fence: Some(FenceFact::Alive {
                    not_after_passed: terminate,
                    terminated: false,
                }),
                ..rec_fact
            });
            // The next step is the fence on the same reading.
            put_journal(tx, &op_id, &ctx.journal, now)?;
            Ok(false)
        }
        ReconcileClass::Applied => {
            end_reconcile(&mut ctx.journal);
            ctx.journal.uncertain = None;
            put_journal(tx, &op_id, &ctx.journal, now)?;
            match expected.purpose {
                ReconcilePurpose::Append => {
                    // D5 §6.7: "Applied → `Confirmed`, then `applied_unverified`": the
                    // append's confirmation receipt, which the initial verification's
                    // own authority requires (§17.21 item 5).
                    append_confirmed(tx, ctx, now)?;
                    move_ctx(
                        tx,
                        emit,
                        ctx,
                        EnrollmentEventKind::ReconcileApplied,
                        &updated,
                    )?;
                    if !r.approval_valid {
                        let data = serde_json::to_value({
                            let mut res = result_of(&ctx.record, None);
                            res.commands =
                                vec![format!("heimdall enroll verify {}", ctx.record.id)];
                            res
                        })
                        .map_err(|_| store_conflict("result"))?;
                        settle_ok(tx, emit, &mut ctx.op, data, now, r.retention)?;
                        return Ok(false);
                    }
                    Ok(true)
                }
                ReconcilePurpose::Bootstrap => {
                    // Present and checked: continue at E3 (no record event needed
                    // beyond leaving `outcome_unknown` through a redispatch).
                    ctx.journal.bootstrap_done = true;
                    move_ctx(
                        tx,
                        emit,
                        ctx,
                        EnrollmentEventKind::ReconcileRedispatch,
                        &updated,
                    )?;
                    put_journal(tx, &op_id, &ctx.journal, now)?;
                    Ok(false)
                }
                _ => {
                    removal_confirmed(tx, emit, ctx, now, r.retention)?;
                    Ok(false)
                }
            }
        }
        ReconcileClass::Redispatch => {
            end_reconcile(&mut ctx.journal);
            ctx.journal.uncertain = None;
            ctx.journal.busy = 0;
            put_journal(tx, &op_id, &ctx.journal, now)?;
            move_ctx(
                tx,
                emit,
                ctx,
                EnrollmentEventKind::ReconcileRedispatch,
                &updated,
            )?;
            Ok(false)
        }
        ReconcileClass::Damaged => {
            end_reconcile(&mut ctx.journal);
            put_journal(tx, &op_id, &ctx.journal, now)?;
            hold(
                tx,
                emit,
                ctx,
                EnrollmentEventKind::ReconcileDamaged,
                HoldReason::RegistryLineDamaged,
                held_error(
                    reason::REGISTRY_LINE_DAMAGED,
                    "the registry holds a damaged or repeated marker line; check its exact bytes by hand",
                ),
                now,
                r.retention,
            )?;
            Ok(false)
        }
        ReconcileClass::ApprovalLapsed => {
            end_reconcile(&mut ctx.journal);
            put_journal(tx, &op_id, &ctx.journal, now)?;
            if let Some(n) = u.not_after_remote {
                updated.late_write = Some(LateWrite {
                    step_token: u.token.clone(),
                    not_after_remote: n,
                });
            }
            move_ctx(
                tx,
                emit,
                ctx,
                EnrollmentEventKind::ReconcileApprovalLapsed,
                &updated,
            )?;
            let err = OpError::new(
                Code::DecisionStale,
                "the line is absent and the enrollment's approval lapsed: the enrollment is withdrawn",
            )
            .with_reason(reason::APPROVAL_LAPSED)
            .with_effect(EffectStatus::None);
            settle_open(tx, emit, &mut ctx.op, &err, now, r.retention)?;
            Ok(false)
        }
        ReconcileClass::HolderUnresolved => {
            end_reconcile(&mut ctx.journal);
            put_journal(tx, &op_id, &ctx.journal, now)?;
            updated.hold = Some(EnrollmentHold {
                reason: HoldReason::LockHolderUnresolved,
                evidence_based: false,
            });
            move_ctx(
                tx,
                emit,
                ctx,
                EnrollmentEventKind::HolderUnresolved,
                &updated,
            )?;
            Ok(false)
        }
        ReconcileClass::ManualRecoveryLinePresent | ReconcileClass::ManualRecoveryLineAbsent => {
            end_reconcile(&mut ctx.journal);
            ctx.journal.uncertain = None;
            put_journal(tx, &op_id, &ctx.journal, now)?;
            let purpose = match expected.purpose {
                ReconcilePurpose::Rollback => RecoveryPurpose::Rollback,
                ReconcilePurpose::Removal => RecoveryPurpose::Removal,
                _ => RecoveryPurpose::Append,
            };
            let present = class == ReconcileClass::ManualRecoveryLinePresent;
            let event = if present {
                EnrollmentEventKind::ManualRecoveryLinePresent {
                    hold: HoldKind::LockHolderUnresolved,
                    purpose,
                }
            } else {
                EnrollmentEventKind::ManualRecoveryLineAbsent {
                    hold: HoldKind::LockHolderUnresolved,
                    purpose,
                }
            };
            if !present
                && purpose == RecoveryPurpose::Append
                && let Some(n) = u.not_after_remote
            {
                updated.late_write = Some(LateWrite {
                    step_token: u.token.clone(),
                    not_after_remote: n,
                });
            }
            if present && purpose == RecoveryPurpose::Append {
                updated.hold = None;
                append_confirmed(tx, ctx, now)?;
            }
            move_ctx(tx, emit, ctx, event, &updated)?;
            let data = serde_json::to_value(result_of(&ctx.record, None))
                .map_err(|_| store_conflict("result"))?;
            if ctx.record.state.is_final() || ctx.record.state == EnrollmentState::AppliedUnverified
            {
                settle_ok(tx, emit, &mut ctx.op, data, now, r.retention)?;
            }
            Ok(false)
        }
        ReconcileClass::Unresolved(why) => {
            end_reconcile(&mut ctx.journal);
            put_journal(tx, &op_id, &ctx.journal, now)?;
            let _ = why;
            if matches!(
                ctx.record.state,
                EnrollmentState::OutcomeUnknown
                    | EnrollmentState::RollbackUnknown
                    | EnrollmentState::RemoveUnknown
            ) {
                move_ctx(
                    tx,
                    emit,
                    ctx,
                    EnrollmentEventKind::ReconcileUnresolved,
                    &updated,
                )?;
            }
            Ok(false)
        }
        _ => {
            end_reconcile(&mut ctx.journal);
            put_journal(tx, &op_id, &ctx.journal, now)?;
            Ok(false)
        }
    }
}

/// The `enroll.append` `Confirmed` receipt (effect = the marker) of a line found
/// present by a reconcile.
fn append_confirmed(tx: &mut Txn<'_>, ctx: &Ctx, now: Timestamp) -> heimdall_store::Result<()> {
    tx.append_stage_receipt(
        &ctx.op.id,
        &receipt(
            enrollment_stage::APPEND,
            now,
            EffectReceipt::Confirmed {
                adapter: adapter(&ctx.record.id.to_string()),
                credential_ref: ctx.record.marker.clone(),
            },
        ),
    )
}

/// Milliseconds of a duration (saturating).
pub(super) fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `UnresolvedReason`'s registered answer, for the reconcile's caller.
#[allow(dead_code)]
fn unresolved_error(why: UnresolvedReason) -> OpError {
    match why {
        UnresolvedReason::Unreachable => OpError::new(
            Code::DestinationUnreachable,
            "the destination could not be read; the step stays uncertain",
        ),
        UnresolvedReason::NotAttended => OpError::new(
            Code::InteractionRequired,
            "a redispatch of the append needs an attended session",
        ),
        _ => OpError::new(
            Code::OutcomeUnknown,
            "the step stays uncertain; reconcile again later",
        ),
    }
}
