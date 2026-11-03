//! ⟨M02⟩ The setup driver (m02-plan U5; ADR-0007 §5): previews, the decision flow,
//! the journaled apply, rollback and repair operations, held operations and their two
//! repairs, and restart reconciliation.
//!
//! **Entry point.** [`Operations::setup`] answers every `SetupRequest`. A caller that
//! is not the owner gets `CAPABILITY_UNAVAILABLE`. A runtime without a projection
//! writer (`OperationsConfig.projection = None`) keeps the wave-0 refusal,
//! `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable`, before anything is read
//! or written (m02-plan §5 item 4).
//!
//! * **Preview** is read-only and journals nothing. It builds the `ProjectionSpec`
//!   from the catalog, the projection record and the stored consent, and asks the
//!   writer. A held repair (`retry_held`, `keep_held`) is built here instead, from
//!   `ProjectionWriter::observe_held`: its digest covers the held operation's
//!   canonical observation and every held step's content fingerprint, and nothing of
//!   an observed entry's content enters the plan (M2-T03).
//! * **Apply, rollback, repair** carry the digest of a plan the caller saw. A replay
//!   or a conflicting reuse of the request ID is classified first, so a replay never
//!   recomputes anything. Otherwise the plan is recomputed from the files as they are
//!   (ADR-0007 §5.4 step 1): a digest that differs is `CONFIG_CONFLICT` ("preview is
//!   stale") and nothing is written. The intent of the digest is the one a preview of
//!   this runtime remembered, else one of the few apply and rollback intents, else a
//!   held repair of the held operation; the remembered intent only names what to
//!   recompute, and the recomputed plan must reproduce the digest. Admission is
//!   U0b's `admit` with `SetupAdmission`, so the `SetupIntent`, with every target's
//!   content, is stored in the transaction that checks for another open setup
//!   operation (`setup_in_progress`, ADR-0007 §5.7).
//!
//! **Driver** ([`drive`], also reached through `Operations::drive` at restart and
//! after a decision). Every step is one store transaction:
//! * before any write it recomputes the plan and refuses a stale one; it runs only
//!   with an approval for exactly the intent's digest, or with no decision required
//!   (M2-R07). A required decision creates an `ApplyProjection` record and moves the
//!   operation to `awaiting_approval`; an affected item with an undetermined state
//!   always takes that path (M2-R03);
//! * it mints the effect token and writes the `setup.attempt` receipt (`Attempted`,
//!   adapter `config_projection/<environment>`) in the transaction that starts the
//!   operation, then calls `ProjectionWriter::apply` once with a [`StageSink`] that
//!   writes each receipt in its own transaction. Once that receipt exists the driver
//!   only ever calls `reconcile`, never a second `apply` (R-RT-05);
//! * it settles from the writer's item outcomes: all applied is `OK`; a held item is
//!   `OUTCOME_UNKNOWN`, reason `projection_held`, effect `unknown`, next
//!   `reconcile`, with the held repair options in the message and the `SetupResult`
//!   in the envelope's `data.setup` (ADR-0007 §12.17 item 6); anything else is
//!   `CONFIG_CONFLICT` with the conflict as its reason;
//! * files the outcome leaves to the cleaner (a committed item's target-absent steps,
//!   and an uncommitted item's written-inactive files) get their `config_projection`
//!   resource marked `desired: absent` in the settling transaction, so the
//!   supervisor's cleanup executor removes them by generation, identity and digest
//!   (ADR-0007 §5.8). A held item hands nothing over.
//!
//! **Sink** ([`StoreSink`]). `append` fixes each receipt's effect by its phase
//! (`Confirmed` for `item.committed` and `item.finished{applied}`, `Attempted` with
//! the operation's token otherwise). `commit_item` refuses an `ItemCommit` whose
//! consent names any decision but the intent's approval (ADR-0007 §12.19 item 9),
//! completes the writer's placeholders (environment, operation, commit time), merges
//! the files and, when P is unchanged, the aliases of the stored item record, and
//! writes it through `Txn::commit_projection_item` in one transaction.
//!
//! **A rollback commit removes the item** (§12.19 item 9). The store's
//! `commit_projection_item` refuses a record without the committed item at its
//! generation, and `preview` takes the next generation from the record, so the item
//! is kept as an empty record (no files, no aliases) at the committed generation: a
//! removed item that still holds the generation's high-water mark. Every reader here
//! treats such a record as absent for consent ([`load_spec`] drops its stored
//! consent, so a re-adoption always needs a decision). Escalated: the store would
//! need to accept a removal and keep a generation mark elsewhere.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use heimdall_contract::canonical::canonical_json;
use heimdall_contract::doctor::{Finding, FindingSeverity};
use heimdall_contract::envelope::{EffectStatus, NextAction, ResourceRef, reason};
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{EnvironmentId, IdentityId, OperationId, RequestId};
use heimdall_contract::provider::ProbeLevel;
use heimdall_contract::request::RequiredCapabilities;
use heimdall_contract::setup::{
    ConflictKind, ConsentNeed, ConsentReasonKind, FileOutcome, FileOutcomeState, ItemOutcomeKind,
    PlanDigest, PreviewIntent, ProjectionFileRole, ProjectionItem, RemainingArtifact,
    RemainingArtifactKind, RepairResolution, SetupMode, SetupPlan, SetupRequest, SetupResult,
    manual_reason,
};
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::catalog::{DestinationDefinition, IdentityRecord};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::idempotency::{
    HashInput, IdempotencyKey, IdempotencyOutcome, classify, compute_hash,
};
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{
    AdapterIdentity, EffectClass, EffectReceipt, FilePhase, ItemFinish, ItemPhase, LocalIntent,
    LocalReceipt, OperationKind, OperationRecord, StageReceipt,
};
use heimdall_domain::projection::{
    FileRole, ItemCommit, ItemId, ItemRecord, ManagedAliasSpec, ProjectionLocator, ProjectionPlan,
    ProjectionRecord, ProjectionSpec, ProjectionSummary, SetupIntent, Sha256Hex, SummaryIntent,
    Target, projection_resource_id,
};
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};
use heimdall_store::{Store, StoreError, Txn};

use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::operations::{
    LocalDriver, LocalEmit, Operations, SetupAdmission, local_approval_needed, local_op_to,
    local_refuse_outcome, local_settle_failed, local_settle_succeeded,
};
use crate::ports::{
    HeldStep, ItemOutcome, PreviewError, ProjectionWriter, ReconcileError, SinkError, StageSink,
};

/// The mechanism of every local setup receipt's adapter identity
/// (`config_projection/<environment>`, ADR-0007 §5.7 "Receipts").
pub const PROJECTION_MECHANISM: &str = "config_projection";

/// The stage of the receipt that records the operation's effect token before the
/// writer's first call (ADR-0007 §5.4 step 2). It carries no local payload, so the
/// writer's recovery never reads it; its presence means `apply` may have run, and
/// only `reconcile` is called from then on.
pub const STAGE_SETUP_ATTEMPT: &str = "setup.attempt";

/// The domain tag of a held repair's plan digest.
const HELD_DIGEST_TAG: &str = "heimdall.held_repair.v1";

/// How many previewed intents a runtime remembers (by plan digest).
const PREVIEW_MEMORY: usize = 64;

/// A lifecycle reason: a stored receipt this build cannot read.
const UNREADABLE_RECEIPTS: &str = "unreadable_receipts";

/// A lifecycle reason: the stored setup intent is missing or invalid.
const INTENT_UNREADABLE: &str = "intent_unreadable";

// --- previewed intents ------------------------------------------------------------------

type Remembered = VecDeque<(EnvironmentId, PlanDigest, PreviewIntent)>;

fn previews() -> &'static Mutex<Remembered> {
    static PREVIEWS: OnceLock<Mutex<Remembered>> = OnceLock::new();
    PREVIEWS.get_or_init(Mutex::default)
}

/// Remember which intent produced `digest` (only to know what to recompute later; the
/// recomputed plan must reproduce the digest).
fn remember(environment: &EnvironmentId, digest: &PlanDigest, intent: &PreviewIntent) {
    let mut p = previews().lock().unwrap_or_else(PoisonError::into_inner);
    p.retain(|(e, d, _)| !(e == environment && d == digest));
    p.push_back((environment.clone(), digest.clone(), intent.clone()));
    while p.len() > PREVIEW_MEMORY {
        p.pop_front();
    }
}

fn recall(environment: &EnvironmentId, digest: &PlanDigest) -> Option<PreviewIntent> {
    previews()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .rev()
        .find(|(e, d, _)| e == environment && d == digest)
        .map(|(_, _, i)| i.clone())
}

/// The operation kind an intent is executed under.
fn kind_of(intent: &PreviewIntent) -> Option<OperationKind> {
    match intent {
        PreviewIntent::Apply { .. } => Some(OperationKind::SetupApply),
        PreviewIntent::Rollback { .. } => Some(OperationKind::SetupRollback),
        PreviewIntent::Repair { .. } => Some(OperationKind::SetupRepair),
        _ => None,
    }
}

/// The few intents of `kind` that can be recomputed without a remembered preview:
/// both applies and the six rollbacks. Other repairs need a remembered preview.
fn candidates(kind: OperationKind) -> Vec<PreviewIntent> {
    match kind {
        OperationKind::SetupApply => vec![
            PreviewIntent::Apply { include_git: false },
            PreviewIntent::Apply { include_git: true },
        ],
        OperationKind::SetupRollback => {
            let sets: [&[ProjectionItem]; 3] = [
                &[ProjectionItem::Ssh, ProjectionItem::Git],
                &[ProjectionItem::Ssh],
                &[ProjectionItem::Git],
            ];
            let mut out = Vec::new();
            for keep_key_files in [false, true] {
                for items in sets {
                    out.push(PreviewIntent::Rollback {
                        keep_key_files,
                        items: items.iter().copied().collect(),
                    });
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

// --- small helpers ------------------------------------------------------------------------

fn internal(msg: &str) -> OpError {
    OpError::new(Code::InternalError, msg.to_owned())
}

fn store_conflict(msg: &str) -> StoreError {
    StoreError::GenerationConflict(msg.to_owned())
}

/// `CONFIG_CONFLICT` ("preview is stale"), effect `none` (ADR-0007 §5.4 step 1).
fn stale() -> OpError {
    OpError::new(
        Code::ConfigConflict,
        "preview is stale: the files, the catalog or the consent changed since the plan was shown; preview again",
    )
    .with_effect(EffectStatus::None)
}

/// The projection resource reference of events.
fn projection_ref(environment: &EnvironmentId) -> ResourceRef {
    ResourceRef {
        kind: "projection".to_owned(),
        id: Some(environment.to_string()),
    }
}

fn adapter_identity(environment: &EnvironmentId) -> AdapterIdentity {
    AdapterIdentity {
        mechanism: PROJECTION_MECHANISM.to_owned(),
        instance: environment.to_string(),
    }
}

fn item_name(item: ProjectionItem) -> &'static str {
    match item {
        ProjectionItem::Git => "git",
        _ => "ssh",
    }
}

fn wire_role(role: FileRole) -> Option<ProjectionFileRole> {
    match role {
        FileRole::UserSsh => Some(ProjectionFileRole::UserSsh),
        FileRole::ManagedSsh => Some(ProjectionFileRole::ManagedSsh),
        FileRole::Key => Some(ProjectionFileRole::KeyFile),
        FileRole::GitInclude => Some(ProjectionFileRole::GitInclude),
        FileRole::GitManaged => Some(ProjectionFileRole::GitManaged),
        FileRole::GitLock => None,
    }
}

/// Roles whose files are `config_projection` resources (P, the key files, P_git).
fn is_resource_role(role: FileRole) -> bool {
    matches!(
        role,
        FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged
    )
}

/// A held repair's resolution and operation, when `intent` is one.
fn held_repair(intent: &PreviewIntent) -> Option<(RepairResolution, &OperationId)> {
    match intent {
        PreviewIntent::Repair {
            resolution,
            operation: Some(target),
            ..
        } if resolution.is_held_resolution() => Some((*resolution, target)),
        _ => None,
    }
}

/// Run synchronous projection work on the blocking pool. A panic in it (an injected
/// crash) is reported as `INTERNAL_ERROR`; whatever the writer made durable stays for
/// `reconcile`.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, OpError> {
    tokio::task::spawn_blocking(f).await.map_err(|_| {
        internal("the projection writer stopped; the operation is left for reconciliation")
    })
}

fn preview_error(e: PreviewError) -> OpError {
    match e {
        PreviewError::TooLarge => OpError::new(
            Code::CapabilityUnavailable,
            "the plan exceeds the setup intent's content bounds",
        )
        .with_reason(reason::PROJECTION_TOO_LARGE)
        .with_effect(EffectStatus::None),
        other => {
            OpError::driver_unavailable(&format!("the projection cannot be previewed: {other}"))
        }
    }
}

/// Only the local receipts (what the writer reads).
fn local_only(receipts: &[StageReceipt]) -> Vec<StageReceipt> {
    receipts
        .iter()
        .filter(|r| r.local.is_some())
        .cloned()
        .collect()
}

/// The effect token of the `setup.attempt` receipt, when `apply` may have run.
fn attempt_token(receipts: &[StageReceipt]) -> Option<String> {
    receipts.iter().rev().find_map(|r| match &r.effect {
        EffectReceipt::Attempted { effect_token, .. } if r.stage == STAGE_SETUP_ATTEMPT => {
            Some(effect_token.clone())
        }
        _ => None,
    })
}

/// Whether `op` is held: `outcome_unknown` with its last local receipt `file.held`
/// (the store's admission exception uses the same rule).
fn is_held(op: &OperationRecord, receipts: &[StageReceipt]) -> bool {
    op.state == OperationState::OutcomeUnknown
        && matches!(
            receipts.iter().rev().find_map(|r| r.local.as_ref()),
            Some(LocalReceipt::File {
                phase: FilePhase::Held { .. },
                ..
            })
        )
}

/// The canonical SHA-256 of `value` as a plan digest.
fn digest_of(value: &serde_json::Value) -> Result<PlanDigest, OpError> {
    let bytes = canonical_json(value).map_err(|_| internal("the plan cannot be canonicalized"))?;
    PlanDigest::parse(Sha256Hex::of(&bytes).as_str()).map_err(|_| internal("plan digest"))
}

/// The idempotency hash of an effectful setup request: environment and plan digest
/// (m02-plan §5 item 16).
fn setup_hash(
    kind: OperationKind,
    environment: &EnvironmentId,
    digest: &PlanDigest,
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
            extra: serde_json::json!({ "plan_digest": digest }),
        },
    )
    .map_err(|_| internal("the request cannot be hashed"))
}

/// ADR-0007 §12.19 item 9: `include_target_glob` is its own manual reason. The writer
/// reports it as an `unmanageable_file` finding with that reason; the finding is part
/// of the plan digest, so listing the reason too changes nothing the digest binds.
fn decorate(view: &mut SetupPlan) {
    let glob = view.findings.iter().any(|f| {
        f.code == manual_reason::UNMANAGEABLE_FILE
            && f.reason.as_deref() == Some(manual_reason::INCLUDE_TARGET_GLOB)
    });
    if glob
        && !view
            .manual_reasons
            .iter()
            .any(|r| r == manual_reason::INCLUDE_TARGET_GLOB)
    {
        view.manual_reasons
            .push(manual_reason::INCLUDE_TARGET_GLOB.to_owned());
    }
}

/// Whether executing `plan` needs an owner decision (ADR-0007 §5.2): the plan's
/// classification, any undetermined item (M2-R03, whatever the flag says), or any
/// consent the intent would record (which only a decision may carry).
fn decision_needed(plan: &ProjectionPlan, intent: &SetupIntent) -> bool {
    held_repair(&intent.intent).is_none()
        && (plan.view.consent.decision_required
            || plan
                .view
                .consent
                .reasons
                .iter()
                .any(|r| r.kind == ConsentReasonKind::UndeterminedState)
            || !intent.consent.items.is_empty())
}

/// The longest prefix of `text` within `max` bytes, at a character boundary.
fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The decision summary: the plan's, or one built from its view when the writer gave
/// none; the diff is always within its bound.
fn summary_of(plan: &ProjectionPlan) -> ProjectionSummary {
    let mut summary = plan.summary.clone().unwrap_or_else(|| {
        let view = &plan.view;
        let intent = match view.intent {
            PreviewIntent::Rollback { .. } => SummaryIntent::Rollback,
            PreviewIntent::Repair { .. } => SummaryIntent::Repair,
            _ => SummaryIntent::Apply,
        };
        let diff: String = view.files.iter().map(|f| f.diff.as_str()).collect();
        ProjectionSummary {
            intent,
            added_aliases: Vec::new(),
            changed_aliases: view.aliases.iter().map(|a| a.alias.clone()).collect(),
            removed_aliases: Vec::new(),
            files: view.files.iter().map(|f| f.path_display.clone()).collect(),
            git: view.git.is_some(),
            restore: Vec::new(),
            diff_text: diff,
        }
    });
    summary.diff_text = bounded(&summary.diff_text, ProjectionSummary::MAX_DIFF_TEXT);
    summary
}

/// The held error (ADR-0007 §5.7 outcome H; §12.17 item 6): `OUTCOME_UNKNOWN`, reason
/// `projection_held`, effect `unknown`, next `reconcile`, naming both repairs.
fn held_error(id: &OperationId) -> OpError {
    let mut e = OpError::new(
        Code::OutcomeUnknown,
        format!(
            "setup operation {id} is held for the owner: a file it manages changed while it ran, and nothing was moved; repair it with `retry_held` (after putting the file back) or `keep_held` (keeping the files as they are), each naming operation {id}"
        ),
    )
    .with_reason(reason::PROJECTION_HELD)
    .with_effect(EffectStatus::Unknown)
    .with_resource("operation", Some(id.to_string()))
    .with_operation(id.clone());
    e.next.action = "reconcile".to_owned();
    e.next.operation_id = Some(id.clone());
    e
}

/// `{"error": …, "setup": …}`: the wire form of a failed or held setup envelope's
/// data (`heimdall_contract::envelope::ErrorData`).
fn error_data(e: &OpError, result: Option<&SetupResult>) -> serde_json::Value {
    let mut v = serde_json::json!({ "error": e.detail() });
    if let (Some(r), Some(map)) = (result, v.as_object_mut())
        && let Ok(r) = serde_json::to_value(r)
    {
        map.insert("setup".to_owned(), r);
    }
    v
}

// --- the stored state of one setup operation ---------------------------------------------

/// One setup operation as the driver reads it.
struct SetupState {
    op: OperationRecord,
    /// The stored setup intent; `None` when missing or invalid.
    intent: Option<SetupIntent>,
    /// Every receipt; `None` when one cannot be read.
    receipts: Option<Vec<StageReceipt>>,
}

async fn load_setup(ops: &Operations, id: &OperationId) -> Result<SetupState, OpError> {
    let id2 = id.clone();
    ops.local_write(move |tx, _| {
        let Some(op) = tx.operation(&id2)? else {
            return Ok(None);
        };
        let intent = match tx.recovery_intent(&id2) {
            Ok(Some(r)) => match r.local {
                Some(LocalIntent::Setup(i)) if i.validate().is_ok() => Some(i),
                _ => None,
            },
            Ok(None) | Err(StoreError::Corrupt(_)) => None,
            Err(e) => return Err(e),
        };
        let receipts = match tx.stage_receipts(&id2) {
            Ok(r) => Some(r),
            Err(StoreError::Corrupt(_)) => None,
            Err(e) => return Err(e),
        };
        Ok(Some(SetupState {
            op,
            intent,
            receipts,
        }))
    })
    .await?
    .ok_or_else(|| {
        OpError::new(Code::NotFound, "unknown operation").with_resource("operation", None)
    })
}

/// Leave `op` unresolved and untouched, and say why (`runtime_lifecycle`, the wave-0
/// E2 payload). A build or a later run that can read it reconciles it.
async fn unresolved(ops: &Operations, op: &OperationRecord, why: &str) -> Result<(), OpError> {
    let payload = serde_json::json!({
        "phase": "unresolved",
        "operation_id": op.id,
        "kind": op.kind,
        "state": op.state,
        "reason": why,
    });
    let id = op.id.clone();
    ops.local_write(move |tx, emit| {
        emit.event(
            tx,
            EventType::RuntimeLifecycle,
            Some(id.clone()),
            Some(ResourceRef {
                kind: "operation".to_owned(),
                id: Some(id.to_string()),
            }),
            payload,
        )
    })
    .await
}

// --- the spec a preview renders from ------------------------------------------------------

/// The `ProjectionSpec` of this environment: every managed destination of the catalog
/// (in alias order) with its identity's endpoint, the projection record and the
/// stored consent. Consent stored for an item whose record is empty (removed by a
/// rollback, see the module docs) is dropped, so it is never reused.
///
/// `key_file` is left empty: the key file's path is the writer's (it lives under
/// Heimdall's configuration directory and is named by the key's fingerprint,
/// `heimdall_localenv::materialize::key_file_path`), and the runtime's writer fills
/// it before rendering.
async fn load_spec(ops: &Operations) -> Result<ProjectionSpec, OpError> {
    let environment = ops.environment().clone();
    ops.local_write(move |tx, _| {
        let identities: BTreeMap<IdentityId, IdentityRecord> = tx
            .identities()?
            .into_iter()
            .map(|i| (i.id.clone(), i))
            .collect();
        let mut aliases = Vec::new();
        for d in tx.destinations()? {
            if let DestinationDefinition::Managed {
                hostname,
                port,
                account,
                identity,
            } = d.definition
            {
                let endpoint = identities
                    .get(&identity)
                    .and_then(|i| i.source.endpoint().cloned());
                aliases.push(ManagedAliasSpec {
                    alias: d.alias,
                    destination: d.id,
                    hostname,
                    port,
                    account,
                    identity,
                    endpoint,
                    key_file: String::new(),
                });
            }
        }
        let record = tx.projection_record(&environment)?;
        let mut consent = tx.get_projection_consent(&environment)?;
        let removed = |item: ProjectionItem| {
            record
                .as_ref()
                .and_then(|r| r.items.get(&item))
                .is_none_or(|r| r.files.is_empty() && r.aliases.is_empty())
        };
        let ssh_removed = removed(ProjectionItem::Ssh);
        let git_removed = removed(ProjectionItem::Git);
        consent.items.retain(|id, _| {
            if *id == ItemId::git_selection() {
                !git_removed
            } else {
                !ssh_removed
            }
        });
        Ok(ProjectionSpec {
            environment,
            aliases,
            record,
            consent,
        })
    })
    .await
}

/// A recomputed plan and, for a held repair, the operation it names.
struct Planned {
    plan: ProjectionPlan,
    repair_target: Option<OperationId>,
}

/// Recompute the plan of `intent` from the files and the store as they are now.
async fn plan_for(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    intent: &PreviewIntent,
) -> Result<Planned, OpError> {
    intent
        .validate()
        .map_err(|e| OpError::new(Code::UsageError, e.to_string()))?;
    if let Some((_, target)) = held_repair(intent) {
        let plan = held_plan(ops, writer, intent, target).await?;
        return Ok(Planned {
            plan,
            repair_target: Some(target.clone()),
        });
    }
    let spec = load_spec(ops).await?;
    let w = Arc::clone(writer);
    let i = intent.clone();
    let mut plan = blocking(move || w.preview(&spec, &i))
        .await?
        .map_err(preview_error)?;
    decorate(&mut plan.view);
    Ok(Planned {
        plan,
        repair_target: None,
    })
}

/// The canonical form of a held operation's observation that a held repair's digest
/// covers (M2-T03): every held step's index, role, reason, normalized observation
/// and content fingerprint; identities, types, lengths, times and digests only.
fn held_view(steps: &[HeldStep]) -> serde_json::Value {
    serde_json::Value::Array(
        steps
            .iter()
            .map(|s| {
                serde_json::json!({
                    "step": s.step,
                    "role": s.role,
                    "reason": s.reason,
                    "observed": s.observed,
                    "fingerprint": s.fingerprint,
                })
            })
            .collect(),
    )
}

/// The digest of a held repair (ADR-0007 §5.7 "Repair path"; M2-T03).
fn held_digest(
    intent: &PreviewIntent,
    target: &OperationId,
    held: &SetupIntent,
    steps: &[HeldStep],
) -> Result<PlanDigest, OpError> {
    digest_of(&serde_json::json!({
        "tag": HELD_DIGEST_TAG,
        "intent": intent,
        "operation": target,
        "held_plan_digest": held.plan_digest,
        "generation": held.generation,
        "steps": held_view(steps),
    }))
}

/// The plan of `retry_held` or `keep_held` for `target`, from
/// `ProjectionWriter::observe_held` (passive). No decision is ever needed (QR12).
async fn held_plan(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    intent: &PreviewIntent,
    target: &OperationId,
) -> Result<ProjectionPlan, OpError> {
    let not_held = || {
        OpError::new(
            Code::ConfigConflict,
            "the named operation is not a held setup operation of this environment",
        )
        .with_reason(reason::PROJECTION_HELD)
        .with_effect(EffectStatus::None)
        .with_resource("operation", Some(target.to_string()))
    };
    let st = match load_setup(ops, target).await {
        Ok(st) => st,
        Err(e) if e.code == Code::NotFound => return Err(not_held()),
        Err(e) => return Err(e),
    };
    let (Some(held), Some(receipts)) = (st.intent, st.receipts) else {
        return Err(not_held());
    };
    if !st.op.kind.is_setup()
        || st.op.environment != *ops.environment()
        || !is_held(&st.op, &receipts)
    {
        return Err(not_held());
    }
    let steps = observe_held(writer, &held, &receipts).await?;
    let digest = held_digest(intent, target, &held, &steps)?;
    let findings = steps
        .iter()
        .map(|s| Finding {
            code: reason::PROJECTION_HELD.to_owned(),
            severity: FindingSeverity::Problem,
            subject: ResourceRef {
                kind: "operation".to_owned(),
                id: Some(target.to_string()),
            },
            level: ProbeLevel::Static,
            provenance: None,
            message: format!("step {} ({}) is held", s.step, s.path_display),
            next: NextAction::for_code(Code::OutcomeUnknown),
            reason: serde_json::to_value(s.reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned)),
        })
        .collect();
    Ok(ProjectionPlan {
        view: SetupPlan {
            plan_digest: digest,
            intent: intent.clone(),
            mode: SetupMode::Automatic,
            manual_reasons: Vec::new(),
            files: Vec::new(),
            git: None,
            aliases: Vec::new(),
            consent: ConsentNeed {
                decision_required: false,
                reasons: Vec::new(),
            },
            unaffected_names_checked: 0,
            findings,
        },
        generation: held.generation,
        consent: heimdall_domain::projection::ConsentRecord::default(),
        files: Vec::new(),
        summary: None,
    })
}

async fn observe_held(
    writer: &Arc<dyn ProjectionWriter>,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
) -> Result<Vec<HeldStep>, OpError> {
    let w = Arc::clone(writer);
    let i = intent.clone();
    let r = local_only(receipts);
    blocking(move || w.observe_held(&i, &r))
        .await?
        .map_err(|e| {
            OpError::driver_unavailable(&format!("the held operation cannot be observed: {e}"))
        })
}

// --- the entry point ----------------------------------------------------------------------

impl Operations {
    /// `Request::Setup` (preview, apply, rollback, repair); see the module docs.
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE` for a caller that is not the owner, and with reason
    /// `driver_unavailable` while no projection writer is configured; `USAGE_ERROR`
    /// for an intent that breaks its rules; `CONFIG_CONFLICT` for a stale preview, a
    /// conflict or `setup_in_progress`; `APPROVAL_REQUIRED`/`INTERACTION_REQUIRED`
    /// with `next.decision_ref` while the owner's decision is pending; and the other
    /// codes of the effect discipline.
    pub async fn setup(&self, caller: &Caller, req: SetupRequest) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(
                OpError::new(Code::CapabilityUnavailable, "setup needs the owner role")
                    .with_effect(EffectStatus::None),
            );
        }
        let Some(writer) = self.local_projection() else {
            return Err(OpError::driver_unavailable(
                "setup is not available in this runtime: no projection writer is configured",
            ));
        };
        match &req {
            SetupRequest::Preview { intent } => self.setup_preview(&writer, intent).await,
            SetupRequest::Apply {
                plan_digest,
                request_id,
            } => {
                self.setup_effect(
                    caller,
                    &writer,
                    OperationKind::SetupApply,
                    plan_digest,
                    request_id,
                    &req,
                )
                .await
            }
            SetupRequest::Rollback {
                plan_digest,
                request_id,
            } => {
                self.setup_effect(
                    caller,
                    &writer,
                    OperationKind::SetupRollback,
                    plan_digest,
                    request_id,
                    &req,
                )
                .await
            }
            SetupRequest::Repair {
                plan_digest,
                request_id,
            } => {
                self.setup_effect(
                    caller,
                    &writer,
                    OperationKind::SetupRepair,
                    plan_digest,
                    request_id,
                    &req,
                )
                .await
            }
            _ => Err(OpError::new(
                Code::UsageError,
                "this setup action is not supported by this runtime",
            )),
        }
    }

    /// Read-only preview (journals nothing).
    async fn setup_preview(
        &self,
        writer: &Arc<dyn ProjectionWriter>,
        intent: &PreviewIntent,
    ) -> OpResult<serde_json::Value> {
        let planned = plan_for(self, writer, intent).await?;
        remember(self.environment(), &planned.plan.view.plan_digest, intent);
        let data = serde_json::to_value(&planned.plan.view)
            .map_err(|_| internal("the plan cannot be rendered"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    /// Apply, rollback or repair a previewed plan.
    async fn setup_effect(
        &self,
        caller: &Caller,
        writer: &Arc<dyn ProjectionWriter>,
        kind: OperationKind,
        digest: &PlanDigest,
        request_id: &RequestId,
        request: &SetupRequest,
    ) -> OpResult<serde_json::Value> {
        let now = self.timegate().check().await?.wall();
        let environment = self.environment().clone();
        let hash = setup_hash(kind, &environment, digest)?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id: request_id.clone(),
        };
        // Replays and conflicting reuses first: a replay never recomputes anything.
        match self.classify_key(&key, hash, now).await? {
            IdempotencyOutcome::New => {}
            IdempotencyOutcome::Replay(id) => return self.setup_respond(&id, caller).await,
            other => {
                return Err(local_refuse_outcome(&other)
                    .unwrap_or_else(|| internal("unexpected idempotency outcome")));
            }
        }
        let planned = self.find_plan(writer, kind, digest).await?;
        let request_json =
            serde_json::to_value(request).map_err(|_| internal("request is not serializable"))?;
        let admission = SetupAdmission {
            environment,
            intent: LocalIntent::Setup(planned.plan.intent()),
            repair_target: planned.repair_target.clone(),
        };
        let effect_class = kind
            .m02_effect_class()
            .unwrap_or(EffectClass::LocalResources);
        let outcome = match self
            .local_admit(
                key,
                hash,
                kind,
                effect_class,
                request_json,
                now,
                Some(admission),
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return Err(self.held_hint(e).await),
        };
        if let Some(e) = local_refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        if let Some(Err(e)) = self
            .local_lead_bounded(&id, LocalDriver::Setup, self.limits().max_wait)
            .await
        {
            return Err(e);
        }
        self.setup_respond(&id, caller).await
    }

    /// The idempotency classification of `key`, read-only.
    async fn classify_key(
        &self,
        key: &IdempotencyKey,
        hash: heimdall_contract::canonical::RequestHash,
        now: Timestamp,
    ) -> Result<IdempotencyOutcome, OpError> {
        let key_hash = key
            .hash()
            .map_err(|_| internal("the idempotency key cannot be hashed"))?;
        let key = key.clone();
        self.local_write(move |tx, _| {
            let record = tx.idempotency_record(&key)?;
            let marker = tx.expired_key_marker(&key_hash)?;
            Ok(classify(record.as_ref(), marker.as_ref(), hash, now))
        })
        .await
    }

    /// The recomputed plan whose digest is `digest`, or "preview is stale".
    async fn find_plan(
        &self,
        writer: &Arc<dyn ProjectionWriter>,
        kind: OperationKind,
        digest: &PlanDigest,
    ) -> Result<Planned, OpError> {
        let environment = self.environment().clone();
        if let Some(intent) = recall(&environment, digest).filter(|i| kind_of(i) == Some(kind)) {
            let planned = plan_for(self, writer, &intent).await?;
            if planned.plan.view.plan_digest == *digest {
                return Ok(planned);
            }
            return Err(stale());
        }
        let mut intents = candidates(kind);
        if kind == OperationKind::SetupRepair {
            intents.extend(self.held_candidates().await?);
        }
        for intent in intents {
            if let Ok(planned) = plan_for(self, writer, &intent).await
                && planned.plan.view.plan_digest == *digest
            {
                return Ok(planned);
            }
        }
        Err(stale())
    }

    /// `retry_held` and `keep_held` for each held setup operation of this environment.
    async fn held_candidates(&self) -> Result<Vec<PreviewIntent>, OpError> {
        let environment = self.environment().clone();
        let open = self
            .local_write(move |tx, _| tx.open_setup_operations(&environment))
            .await?;
        let mut out = Vec::new();
        for id in open {
            for resolution in [RepairResolution::RetryHeld, RepairResolution::KeepHeld] {
                out.push(PreviewIntent::Repair {
                    conflict: ConflictKind::ProjectionHeld,
                    resolution,
                    operation: Some(id.clone()),
                });
            }
        }
        Ok(out)
    }

    /// `setup_in_progress` naming a held operation also names its two repairs
    /// (m02-plan U5 `held_operation_blocks_setup_except_its_repair`).
    async fn held_hint(&self, mut e: OpError) -> OpError {
        if e.reason.as_deref() != Some(reason::SETUP_IN_PROGRESS) {
            return e;
        }
        let Some(blocker) = e.next.operation_id.clone() else {
            return e;
        };
        if let Ok(st) = load_setup(self, &blocker).await
            && st.receipts.as_deref().is_some_and(|r| is_held(&st.op, r))
        {
            e.message = format!(
                "setup operation {blocker} is held for the owner and blocks every other setup operation; repair it with `retry_held` or `keep_held` naming operation {blocker}"
            );
        }
        e
    }

    /// The caller's view of a setup operation's durable state.
    async fn setup_respond(
        &self,
        id: &OperationId,
        caller: &Caller,
    ) -> OpResult<serde_json::Value> {
        let st = load_setup(self, id).await?;
        let op = st.op;
        match op.state {
            OperationState::AwaitingApproval => {
                let now = self.local_narrowing_now().await;
                let mut pending = pending_projection_decision(self, id, now).await?;
                if pending.is_none() {
                    // The decision expired or was withdrawn: the driver issues a fresh
                    // one from a recomputed plan, or settles a stale plan failed.
                    if let Some(Err(e)) = self
                        .local_lead_bounded(id, LocalDriver::Setup, self.limits().max_wait)
                        .await
                    {
                        return Err(e);
                    }
                    let now = self.local_narrowing_now().await;
                    pending = pending_projection_decision(self, id, now).await?;
                    if pending.is_none() {
                        let op = load_setup(self, id).await?.op;
                        if op.state != OperationState::AwaitingApproval {
                            return Box::pin(self.setup_respond(id, caller)).await;
                        }
                    }
                }
                match pending {
                    Some(d) => Err(local_approval_needed(
                        caller.is_attended(),
                        d.as_str(),
                        "the projection change needs the owner's decision",
                    )
                    .with_resource("decision", Some(d.to_string()))
                    .with_operation(id.clone())),
                    None => Err(OpError::new(
                        Code::Accepted,
                        "the operation awaits a fresh decision; observe it",
                    )
                    .with_operation(id.clone())),
                }
            }
            OperationState::Succeeded => Ok(Completed {
                operation_id: Some(op.id.clone()),
                state: op.state,
                code: op.code.clone().unwrap_or(Code::Ok),
                data: op.result.clone().unwrap_or(serde_json::Value::Null),
                warnings: Vec::new(),
                next: None,
            }),
            OperationState::Failed | OperationState::Cancelled | OperationState::OutcomeUnknown => {
                error_with_setup(&op, stored_error(&op))
            }
            OperationState::Queued | OperationState::Running => Err(OpError::new(
                Code::Accepted,
                "the operation is still in progress; observe it",
            )
            .with_operation(op.id.clone())),
        }
    }
}

/// The stored error of a settled or held operation.
fn stored_error(op: &OperationRecord) -> OpError {
    let detail = op
        .result
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|e| serde_json::from_value(e.clone()).ok());
    match detail {
        Some(d) => OpError::from_detail(d, Some(op.id.clone())),
        None if op.state == OperationState::OutcomeUnknown => OpError::new(
            Code::OutcomeUnknown,
            "the setup operation is unresolved; it will be reconciled",
        )
        .with_operation(op.id.clone()),
        None => OpError::new(
            op.code.clone().unwrap_or(Code::InternalError),
            "the setup operation failed",
        )
        .with_effect(op.effect_status)
        .with_operation(op.id.clone()),
    }
}

/// A failed or held envelope that carries the operation's `SetupResult` in
/// `data.setup` (m02-plan §5 item 2): the exact wire form of the error envelope
/// (`ErrorData { error, setup }`, its state, code and next action), rendered from
/// the stored result. Without a stored `SetupResult` it stays the plain error.
fn error_with_setup(op: &OperationRecord, e: OpError) -> OpResult<serde_json::Value> {
    let Some(setup) = op.result.as_ref().and_then(|v| v.get("setup")).cloned() else {
        return Err(e);
    };
    let mut data = serde_json::json!({ "error": e.detail() });
    if let Some(map) = data.as_object_mut() {
        map.insert("setup".to_owned(), setup);
    }
    Ok(Completed {
        operation_id: Some(op.id.clone()),
        state: e.state(),
        code: e.code.clone(),
        data,
        warnings: Vec::new(),
        next: Some(e.next.clone()),
    })
}

/// The pending, unexpired `ApplyProjection` record of `id`, if any.
async fn pending_projection_decision(
    ops: &Operations,
    id: &OperationId,
    now: Timestamp,
) -> Result<Option<heimdall_contract::ids::DecisionId>, OpError> {
    let id = id.clone();
    ops.local_write(move |tx, _| {
        Ok(tx
            .pending_decisions()?
            .into_iter()
            .rev()
            .find(|d| {
                matches!(&d.kind, DecisionKind::ApplyProjection { operation, .. } if *operation == id)
                    && now < d.expires_at
            })
            .map(|d| d.id))
    })
    .await
}

// --- the driver ------------------------------------------------------------------------------

/// Drive setup operation `id` from its durable state (module docs). Restart recovery
/// and a decision's resume reach it through `Operations::drive`; requests through the
/// same per-operation flight.
///
/// # Errors
/// A store failure, or the writer stopping (the operation stays where it is).
pub(crate) async fn drive(ops: &Operations, id: &OperationId) -> Result<(), OpError> {
    let st = load_setup(ops, id).await?;
    if st.op.state.is_settled() {
        return Ok(());
    }
    let Some(writer) = ops.local_projection() else {
        return unresolved(ops, &st.op, reason::DRIVER_UNAVAILABLE).await;
    };
    let Some(intent) = st.intent.clone() else {
        return unresolved(ops, &st.op, INTENT_UNREADABLE).await;
    };
    let Some(receipts) = st.receipts.clone() else {
        return unresolved(ops, &st.op, UNREADABLE_RECEIPTS).await;
    };
    if let Some((resolution, target)) = held_repair(&intent.intent) {
        return drive_held_repair(ops, &writer, &st.op, &intent, resolution, target).await;
    }
    match (st.op.state, attempt_token(&receipts)) {
        (_, Some(token)) => reconcile_op(ops, &writer, &st.op, &intent, &token).await,
        (OperationState::AwaitingApproval, None) => {
            ensure_decision(ops, &writer, &st.op, &intent).await
        }
        (OperationState::Queued | OperationState::Running, None) => {
            prepare_and_apply(ops, &writer, &st.op, &intent).await
        }
        _ => unresolved(ops, &st.op, INTENT_UNREADABLE).await,
    }
}

/// Settle `id` failed with `e` before anything was written (effect as `e` says).
async fn fail_unwritten(ops: &Operations, id: &OperationId, e: OpError) -> Result<(), OpError> {
    let id = id.clone();
    let retention = ops.local_retention();
    let now = ops.local_narrowing_now().await;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state.is_settled() {
            return Ok(());
        }
        local_settle_failed(tx, emit, &mut op, &e, now, retention)
    })
    .await
}

/// §5.4 step 1 and M2-R07, then the decision or the single `apply`.
async fn prepare_and_apply(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    op: &OperationRecord,
    intent: &SetupIntent,
) -> Result<(), OpError> {
    let planned = match plan_for(ops, writer, &intent.intent).await {
        Ok(p) => p,
        Err(e) if e.code == Code::InternalError => return Err(e),
        Err(e) => return fail_unwritten(ops, &op.id, e.with_effect(EffectStatus::None)).await,
    };
    if planned.plan.view.plan_digest != intent.plan_digest {
        return fail_unwritten(ops, &op.id, stale()).await;
    }
    if decision_needed(&planned.plan, intent) {
        match op.state {
            OperationState::Queued => {
                return create_decision(ops, &op.id, intent, &planned.plan).await;
            }
            _ => {
                // M2-R07: only an approval of exactly this digest lets it run.
                let approved = intent
                    .approval
                    .as_ref()
                    .is_some_and(|a| a.plan_digest == intent.plan_digest);
                if !approved {
                    return fail_unwritten(
                        ops,
                        &op.id,
                        OpError::new(
                            Code::DecisionStale,
                            "the projection change needs an approval of exactly this plan",
                        )
                        .with_effect(EffectStatus::None),
                    )
                    .await;
                }
            }
        }
    }
    let token = crate::ids::new_effect_token()?;
    start_attempt(ops, &op.id, &token).await?;
    execute(ops, writer, &op.id, intent, &token).await
}

/// An `awaiting_approval` operation keeps a pending, unexpired decision: a fresh one
/// when it expired, from a recomputed plan that must still reproduce the digest.
async fn ensure_decision(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    op: &OperationRecord,
    intent: &SetupIntent,
) -> Result<(), OpError> {
    let now = ops.local_narrowing_now().await;
    if pending_projection_decision(ops, &op.id, now)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let planned = match plan_for(ops, writer, &intent.intent).await {
        Ok(p) => p,
        Err(e) if e.code == Code::InternalError => return Err(e),
        Err(e) => return fail_unwritten(ops, &op.id, e.with_effect(EffectStatus::None)).await,
    };
    if planned.plan.view.plan_digest != intent.plan_digest {
        return fail_unwritten(ops, &op.id, stale()).await;
    }
    create_decision(ops, &op.id, intent, &planned.plan).await
}

/// Create the `ApplyProjection` record and move the operation to `awaiting_approval`
/// (one transaction).
async fn create_decision(
    ops: &Operations,
    id: &OperationId,
    intent: &SetupIntent,
    plan: &ProjectionPlan,
) -> Result<(), OpError> {
    let decision = crate::ids::new_decision_id()?;
    let summary = summary_of(plan);
    let digest = intent.plan_digest.clone();
    let lifetime = ops.limits().decision_lifetime;
    let now = ops.local_narrowing_now().await;
    let id = id.clone();
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if !matches!(
            op.state,
            OperationState::Queued | OperationState::AwaitingApproval
        ) {
            return Ok(());
        }
        let record = DecisionRecord {
            id: decision,
            kind: DecisionKind::ApplyProjection {
                operation: id.clone(),
                plan_digest: digest,
                summary,
            },
            generation: tx.authority_generation()?,
            created_at: now,
            expires_at: plus(now, lifetime),
            state: DecisionState::Pending,
            decided_at: None,
        };
        tx.insert_decision(&record)?;
        emit.decision(tx, &record, Some(&id))?;
        if op.state == OperationState::Queued {
            local_op_to(&mut op, OperationEvent::ApprovalNeeded, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
        }
        Ok(())
    })
    .await
}

fn plus(t: Timestamp, d: std::time::Duration) -> Timestamp {
    jiff::SignedDuration::try_from(d)
        .ok()
        .and_then(|s| t.checked_add(s).ok())
        .unwrap_or(Timestamp::MAX)
}

/// Start the operation and record its effect token (`setup.attempt`, `Attempted`)
/// in one transaction, before the writer's first call.
async fn start_attempt(ops: &Operations, id: &OperationId, token: &str) -> Result<(), OpError> {
    let id = id.clone();
    let token = token.to_owned();
    let environment = ops.environment().clone();
    let now = ops.local_narrowing_now().await;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Err(store_conflict("the setup operation vanished"));
        };
        if op.state == OperationState::Queued {
            local_op_to(&mut op, OperationEvent::Start, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
        }
        if op.state != OperationState::Running {
            return Err(store_conflict("the setup operation is not running"));
        }
        tx.append_stage_receipt(
            &id,
            &StageReceipt {
                stage: STAGE_SETUP_ATTEMPT.to_owned(),
                recorded_at: now,
                effect: EffectReceipt::Attempted {
                    adapter: adapter_identity(&environment),
                    effect_token: token,
                },
                local: None,
            },
        )
    })
    .await
}

/// The one `apply` of an operation.
async fn execute(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    id: &OperationId,
    intent: &SetupIntent,
    token: &str,
) -> Result<(), OpError> {
    let sink = StoreSink::new(ops, id, intent, token);
    let w = Arc::clone(writer);
    let i = intent.clone();
    let (result, wrote) = blocking(move || {
        let mut sink = sink;
        let r = w.apply(&i, &mut sink);
        (r, sink.wrote)
    })
    .await?;
    match result {
        Ok(receipt) => settle(ops, id, intent, receipt.items).await,
        Err(ReconcileError::IntentInvalid(_)) if !wrote => {
            fail_unwritten(
                ops,
                id,
                OpError::new(
                    Code::InternalError,
                    "the stored setup intent does not bind its content; nothing was written",
                )
                .with_effect(EffectStatus::None),
            )
            .await
        }
        Err(ReconcileError::Unavailable(_)) if !wrote => {
            fail_unwritten(
                ops,
                id,
                OpError::driver_unavailable("the projection writer cannot act on these files"),
            )
            .await
        }
        Err(e) => uncertain(ops, id, &e).await,
    }
}

/// `reconcile` from the receipts (restart, a held operation, `retry_held`). Never
/// `apply`.
async fn reconcile_op(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    op: &OperationRecord,
    intent: &SetupIntent,
    token: &str,
) -> Result<(), OpError> {
    let st = load_setup(ops, &op.id).await?;
    let Some(receipts) = st.receipts else {
        return unresolved(ops, &st.op, UNREADABLE_RECEIPTS).await;
    };
    let sink = StoreSink::new(ops, &op.id, intent, token);
    let w = Arc::clone(writer);
    let i = intent.clone();
    let r = local_only(&receipts);
    let result = blocking(move || {
        let mut sink = sink;
        w.reconcile(&i, &r, &mut sink)
    })
    .await?;
    match result {
        Ok(rec) => settle(ops, &op.id, intent, rec.items).await,
        Err(ReconcileError::UnreadableReceipt(_)) => {
            unresolved(ops, &st.op, UNREADABLE_RECEIPTS).await
        }
        Err(ReconcileError::IntentInvalid(_)) => unresolved(ops, &st.op, INTENT_UNREADABLE).await,
        Err(ReconcileError::Sink(_)) => Err(OpError::new(
            Code::ServiceUnavailable,
            "a setup receipt could not be made durable; the operation is reconciled again later",
        )
        .with_effect(EffectStatus::Unknown)
        .with_operation(op.id.clone())),
        Err(_) => unresolved(ops, &st.op, reason::DRIVER_UNAVAILABLE).await,
    }
}

/// The writer stopped with receipts written (a sink failure): the effect is unknown
/// until `reconcile` (restart) establishes it.
async fn uncertain(ops: &Operations, id: &OperationId, e: &ReconcileError) -> Result<(), OpError> {
    let id2 = id.clone();
    let now = ops.local_narrowing_now().await;
    let message =
        format!("the projection change was interrupted ({e}); it is reconciled at restart");
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id2)? else {
            return Ok(());
        };
        if op.state != OperationState::Running {
            return Ok(());
        }
        local_op_to(&mut op, OperationEvent::EffectUncertain, now)?;
        let err = OpError::new(Code::OutcomeUnknown, message).with_operation(id2.clone());
        op.code = Some(Code::OutcomeUnknown);
        op.effect_status = EffectStatus::Unknown;
        op.result = Some(error_data(&err, None));
        tx.update_operation(&op)?;
        emit.op(tx, &op)
    })
    .await
}

// --- settlement -------------------------------------------------------------------------------

fn outcome_item(o: &ItemOutcome) -> ProjectionItem {
    match o {
        ItemOutcome::Applied { item, .. }
        | ItemOutcome::NotApplied { item, .. }
        | ItemOutcome::Restored { item, .. }
        | ItemOutcome::ConflictPreserved { item }
        | ItemOutcome::Held { item, .. } => *item,
    }
}

/// Per step of an intent, what its receipts say.
#[derive(Default, Clone)]
struct StepTrace {
    staged: Option<heimdall_domain::projection::FileIdentity>,
    exchanged: bool,
    restored: bool,
    settled: bool,
}

fn traces(intent: &SetupIntent, receipts: &[StageReceipt]) -> Vec<StepTrace> {
    let mut out = vec![StepTrace::default(); intent.files.len()];
    for r in receipts {
        if let Some(LocalReceipt::File { step, phase }) = &r.local
            && let Some(t) = out.get_mut(usize::from(*step))
        {
            match phase {
                FilePhase::Staged { identity } => t.staged = Some(identity.clone()),
                FilePhase::Exchanged => t.exchanged = true,
                FilePhase::Restored => t.restored = true,
                FilePhase::Settled { .. } | FilePhase::SettleConflict { .. } => t.settled = true,
                _ => {}
            }
        }
    }
    out
}

/// The wire result of an outcome.
fn setup_result(
    intent: &SetupIntent,
    outcomes: &[ItemOutcome],
    receipts: &[StageReceipt],
    preserved: bool,
) -> SetupResult {
    let traces = traces(intent, receipts);
    let mut remaining = Vec::new();
    let mut items = Vec::new();
    for o in outcomes {
        let item = outcome_item(o);
        let held: BTreeMap<u16, &HeldStep> = match o {
            ItemOutcome::Held { steps, .. } => steps.iter().map(|s| (s.step, s)).collect(),
            _ => BTreeMap::new(),
        };
        let kind = match o {
            ItemOutcome::Applied { .. } => ItemOutcomeKind::Applied,
            ItemOutcome::NotApplied { .. } => ItemOutcomeKind::NotApplied,
            ItemOutcome::Restored { .. } => ItemOutcomeKind::Restored,
            ItemOutcome::ConflictPreserved { .. } => ItemOutcomeKind::ConflictPreserved,
            ItemOutcome::Held { .. } => {
                if preserved {
                    ItemOutcomeKind::ConflictPreserved
                } else {
                    ItemOutcomeKind::Held
                }
            }
        };
        let mut files = Vec::new();
        for (idx, step) in intent.files.iter().enumerate() {
            let Some(role) = wire_role(step.role) else {
                continue;
            };
            if step.role.item() != item {
                continue;
            }
            let t = traces.get(idx).cloned().unwrap_or_default();
            let index = u16::try_from(idx).unwrap_or(u16::MAX);
            let (state, path_display) = if let Some(h) = held.get(&index) {
                let state = if preserved {
                    FileOutcomeState::ConflictPreserved
                } else {
                    FileOutcomeState::Held
                };
                if preserved {
                    remaining.push(RemainingArtifact {
                        kind: RemainingArtifactKind::ConflictFile,
                        path_display: h.path_display.clone(),
                    });
                }
                (state, h.path_display.clone())
            } else {
                let absent = matches!(step.target, Target::Absent);
                let state = match o {
                    ItemOutcome::Applied { .. } if absent => FileOutcomeState::Removed,
                    ItemOutcome::Applied { .. } if t.staged.is_some() => FileOutcomeState::Applied,
                    ItemOutcome::Applied { .. } => continue,
                    // An exchange the run undid (the user file's restore, an inactive
                    // file rolled back).
                    _ if t.restored => FileOutcomeState::Restored,
                    _ if t.exchanged && !t.settled && is_resource_role(step.role) => {
                        FileOutcomeState::WrittenInactive
                    }
                    ItemOutcome::ConflictPreserved { .. } | ItemOutcome::Held { .. }
                        if t.exchanged =>
                    {
                        FileOutcomeState::Applied
                    }
                    _ => FileOutcomeState::NotApplied,
                };
                (state, step.path.clone())
            };
            files.push(FileOutcome {
                role,
                path_display,
                state,
            });
        }
        items.push(heimdall_contract::setup::ItemOutcome {
            item,
            outcome: kind,
            files,
        });
    }
    if preserved {
        let mut dirs = BTreeSet::new();
        for o in outcomes {
            if let ItemOutcome::Held { steps, .. } = o {
                for s in steps {
                    if let Some(parent) = std::path::Path::new(&s.path_display).parent() {
                        dirs.insert(parent.join(".hm-quarantine").display().to_string());
                    }
                }
            }
        }
        for d in dirs {
            remaining.push(RemainingArtifact {
                kind: RemainingArtifactKind::Quarantine,
                path_display: d,
            });
        }
    }
    SetupResult {
        generation: intent.generation,
        items,
        remaining,
    }
}

/// The `resource_changed` change of an item outcome.
fn change_of(intent: &PreviewIntent, o: &ItemOutcome) -> &'static str {
    match o {
        ItemOutcome::Applied { .. } => match intent {
            PreviewIntent::Rollback { .. } => "rolled_back",
            PreviewIntent::Repair { .. } => "repaired",
            _ => "applied",
        },
        ItemOutcome::Restored { .. } => "restored",
        ItemOutcome::Held { .. } => "held",
        ItemOutcome::NotApplied { .. } | ItemOutcome::ConflictPreserved { .. } => "conflict",
    }
}

/// The first conflict an outcome names.
fn conflict_reason(outcomes: &[ItemOutcome]) -> Option<ConflictKind> {
    outcomes.iter().find_map(|o| match o {
        ItemOutcome::NotApplied { reason, .. } | ItemOutcome::Restored { reason, .. } => *reason,
        _ => None,
    })
}

fn wire_name<T: serde::Serialize>(v: &T) -> Option<String> {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
}

/// Settle `id` from the writer's outcomes, hand the files it leaves to the cleaner,
/// and publish one `resource_changed` per item (one transaction).
async fn settle(
    ops: &Operations,
    id: &OperationId,
    intent: &SetupIntent,
    outcomes: Vec<ItemOutcome>,
) -> Result<(), OpError> {
    let id = id.clone();
    let intent = intent.clone();
    let environment = ops.environment().clone();
    let retention = ops.local_retention();
    let now = ops.local_narrowing_now().await;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state.is_settled() {
            return Ok(());
        }
        let receipts = tx.stage_receipts(&id)?;
        let result = setup_result(&intent, &outcomes, &receipts, false);
        let held = outcomes.iter().any(|o| matches!(o, ItemOutcome::Held { .. }));
        if held {
            to_held(tx, emit, &mut op, &result, now)?;
        } else if outcomes
            .iter()
            .all(|o| matches!(o, ItemOutcome::Applied { .. }))
        {
            let data = serde_json::to_value(&result)
                .map_err(|_| store_conflict("the setup result cannot be rendered"))?;
            local_settle_succeeded(tx, emit, &mut op, Code::Ok, data, now, retention)?;
        } else {
            let applied = outcomes.iter().any(|o| {
                matches!(
                    o,
                    ItemOutcome::Applied { .. } | ItemOutcome::ConflictPreserved { .. }
                )
            });
            let reason = conflict_reason(&outcomes);
            let mut e = OpError::new(
                Code::ConfigConflict,
                "the projection change was not applied: a file changed or a check failed; preview again",
            )
            .with_effect(if applied {
                EffectStatus::Partial
            } else {
                EffectStatus::None
            });
            if let Some(name) = reason.as_ref().and_then(wire_name) {
                e = e.with_reason(&name);
            }
            local_settle_failed(tx, emit, &mut op, &e, now, retention)?;
            op.result = Some(error_data(&e.with_operation(id.clone()), Some(&result)));
            tx.update_operation(&op)?;
        }
        if !held {
            hand_to_cleaner(tx, &environment, &id, &intent, &outcomes, &receipts, now)?;
        }
        for o in &outcomes {
            emit.event(
                tx,
                EventType::ResourceChanged,
                Some(id.clone()),
                Some(projection_ref(&environment)),
                serde_json::json!({
                    "item": outcome_item(o),
                    "generation": intent.generation,
                    "change": change_of(&intent.intent, o),
                }),
            )?;
        }
        Ok(())
    })
    .await
}

/// Outcome H: `outcome_unknown`, nothing settled (the idempotency record stays open).
fn to_held(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &mut OperationRecord,
    result: &SetupResult,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    if op.state == OperationState::Running {
        local_op_to(op, OperationEvent::EffectUncertain, now)?;
    }
    if op.state != OperationState::OutcomeUnknown {
        return Err(store_conflict(
            "a held setup operation is running or unresolved",
        ));
    }
    let e = held_error(&op.id);
    op.code = Some(Code::OutcomeUnknown);
    op.effect_status = EffectStatus::Unknown;
    op.result = Some(error_data(&e, Some(result)));
    op.updated_at = now;
    tx.update_operation(op)?;
    emit.op(tx, op)
}

/// ADR-0007 §5.4, §5.8: the files an outcome leaves to the cleaner. A committed
/// item's target-absent steps (a rollback's P and key files, an update's unreferenced
/// key files) mark their resource `desired: absent`; an uncommitted item's files that
/// were exchanged into place and never restored or settled (`written_inactive`) get a
/// resource at the intent's generation, `desired: absent`, bound to the staged
/// identity and the target digest. Anything else is left alone.
fn hand_to_cleaner(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    operation: &OperationId,
    intent: &SetupIntent,
    outcomes: &[ItemOutcome],
    receipts: &[StageReceipt],
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let traces = traces(intent, receipts);
    for o in outcomes {
        let item = outcome_item(o);
        for (idx, step) in intent.files.iter().enumerate() {
            if step.role.item() != item || !is_resource_role(step.role) {
                continue;
            }
            let id = projection_resource_id(environment, step.role, &step.path);
            match (o, &step.target) {
                (ItemOutcome::Applied { .. }, Target::Absent) => {
                    let Some(stored) = tx.resource(&id)? else {
                        continue;
                    };
                    if stored.desired != ResourceState::Present {
                        continue;
                    }
                    let Ok(locator) = serde_json::from_str::<ProjectionLocator>(&stored.locator)
                    else {
                        continue;
                    };
                    let next = ManagedResource {
                        desired: ResourceState::Absent,
                        last_operation: Some(operation.clone()),
                        updated_at: now,
                        ..stored.clone()
                    };
                    tx.put_projection_resource(
                        &next,
                        Some((stored.generation, &locator.identity)),
                    )?;
                }
                (
                    ItemOutcome::NotApplied { .. } | ItemOutcome::Restored { .. },
                    Target::Present { sha256 },
                ) => {
                    let Some(t) = traces.get(idx) else {
                        continue;
                    };
                    let Some(identity) = t.staged.clone() else {
                        continue;
                    };
                    if !t.exchanged || t.restored || t.settled || tx.resource(&id)?.is_some() {
                        continue;
                    }
                    let locator = ProjectionLocator {
                        role: step.role,
                        path: step.path.clone(),
                        identity,
                        sha256: sha256.clone(),
                    };
                    let Ok(canonical) = locator.canonical() else {
                        continue;
                    };
                    tx.put_projection_resource(
                        &ManagedResource {
                            id,
                            kind: ResourceKind::ConfigProjection,
                            owner: OwnerRef::Projection {
                                environment: environment.clone(),
                            },
                            generation: ResourceGeneration(intent.generation),
                            desired: ResourceState::Absent,
                            observed: ResourceState::Present,
                            last_operation: Some(operation.clone()),
                            locator: canonical,
                            updated_at: now,
                        },
                        None,
                    )?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

// --- held repairs (ADR-0007 §5.7 "Repair path"; QR12, QR14) -----------------------------------

/// `retry_held` reconciles the held operation inside this repair's driver and settles
/// the repair with its resulting state; `keep_held` closes it in place. Neither creates
/// a decision.
async fn drive_held_repair(
    ops: &Operations,
    writer: &Arc<dyn ProjectionWriter>,
    repair: &OperationRecord,
    intent: &SetupIntent,
    resolution: RepairResolution,
    target: &OperationId,
) -> Result<(), OpError> {
    if repair.state == OperationState::Queued || repair.state == OperationState::AwaitingApproval {
        start_repair(ops, &repair.id).await?;
    }
    let held = load_setup(ops, target).await?;
    let (Some(held_intent), Some(held_receipts)) = (held.intent.clone(), held.receipts.clone())
    else {
        return finish_repair(ops, &repair.id, Err(stored_error(&held.op))).await;
    };
    if !held.op.state.is_settled() {
        match resolution {
            RepairResolution::RetryHeld => {
                let token = attempt_token(&held_receipts).unwrap_or_default();
                reconcile_op(ops, writer, &held.op, &held_intent, &token).await?;
            }
            _ => {
                if !is_held(&held.op, &held_receipts) {
                    return finish_repair(ops, &repair.id, Err(stale())).await;
                }
                let steps = observe_held(writer, &held_intent, &held_receipts).await?;
                if held_digest(&intent.intent, target, &held_intent, &steps)? != intent.plan_digest
                {
                    return finish_repair(ops, &repair.id, Err(stale())).await;
                }
                keep(ops, &held.op, &held_intent, &held_receipts, steps).await?;
            }
        }
    }
    let after = load_setup(ops, target).await?;
    let answer = match after.op.state {
        OperationState::Succeeded => Ok(after.op.result.clone().unwrap_or(serde_json::Value::Null)),
        OperationState::OutcomeUnknown => Err((
            OpError::new(
                Code::ConfigConflict,
                format!("setup operation {target} is still held; nothing was moved"),
            )
            .with_reason(reason::PROJECTION_HELD)
            .with_effect(EffectStatus::None)
            .with_resource("operation", Some(target.to_string())),
            after.op.result.clone(),
        )),
        _ => Err((stored_error(&after.op), after.op.result.clone())),
    };
    match (resolution, answer) {
        // `keep_held` closed the held operation: the repair itself succeeded.
        (RepairResolution::KeepHeld, Err((e, result)))
            if after.op.state == OperationState::Failed =>
        {
            let mut data = result.unwrap_or_else(|| error_data(&e, None));
            if let Some(map) = data.as_object_mut() {
                map.insert("operation".to_owned(), serde_json::json!(target));
            }
            finish_repair(ops, &repair.id, Ok(data)).await
        }
        (_, Ok(data)) => finish_repair(ops, &repair.id, Ok(data)).await,
        (_, Err((e, _))) => finish_repair(ops, &repair.id, Err(e)).await,
    }
}

async fn start_repair(ops: &Operations, id: &OperationId) -> Result<(), OpError> {
    let id = id.clone();
    let now = ops.local_narrowing_now().await;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state == OperationState::Queued {
            local_op_to(&mut op, OperationEvent::Start, now)?;
            tx.update_operation(&op)?;
            emit.op(tx, &op)?;
        }
        Ok(())
    })
    .await
}

async fn finish_repair(
    ops: &Operations,
    id: &OperationId,
    answer: Result<serde_json::Value, OpError>,
) -> Result<(), OpError> {
    let id = id.clone();
    let retention = ops.local_retention();
    let now = ops.local_narrowing_now().await;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state.is_settled() {
            return Ok(());
        }
        match answer {
            Ok(data) => local_settle_succeeded(tx, emit, &mut op, Code::Ok, data, now, retention),
            Err(e) => local_settle_failed(tx, emit, &mut op, &e, now, retention),
        }
    })
    .await
}

/// `keep_held`: through the held operation's sink, `item.finished{applied}` for each
/// open item that has `item.committed` and `item.finished{conflict_preserved}` for the
/// others; then settle it failed (`CONFIG_CONFLICT`, effect `partial`) with every
/// entry it left in `remaining`. No file moves; nothing goes to the cleaner.
async fn keep(
    ops: &Operations,
    held: &OperationRecord,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
    steps: Vec<HeldStep>,
) -> Result<(), OpError> {
    let mut committed = BTreeSet::new();
    let mut finished = BTreeSet::new();
    for r in receipts {
        if let Some(LocalReceipt::Item { item, phase }) = &r.local {
            match phase {
                ItemPhase::Committed { .. } => {
                    committed.insert(*item);
                }
                ItemPhase::Finished { .. } => {
                    finished.insert(*item);
                }
                _ => {}
            }
        }
    }
    let items: BTreeSet<ProjectionItem> = intent.files.iter().map(|s| s.role.item()).collect();
    let token = attempt_token(receipts).unwrap_or_default();
    let mut closing = Vec::new();
    let mut outcomes = Vec::new();
    for item in items {
        if finished.contains(&item) {
            continue;
        }
        let outcome = if committed.contains(&item) {
            ItemFinish::Applied
        } else {
            ItemFinish::ConflictPreserved
        };
        closing.push(LocalReceipt::Item {
            item,
            phase: ItemPhase::Finished {
                outcome,
                reason: None,
            },
        });
        let mine: Vec<HeldStep> = steps
            .iter()
            .filter(|s| s.role.item() == item)
            .cloned()
            .collect();
        outcomes.push(ItemOutcome::Held { item, steps: mine });
    }
    let mut sink = StoreSink::new(ops, &held.id, intent, &token);
    blocking(move || closing.iter().try_for_each(|r| sink.append(r)))
        .await?
        .map_err(|e| {
            OpError::new(
                Code::ServiceUnavailable,
                format!("the held operation cannot be closed: {e}"),
            )
            .with_effect(EffectStatus::None)
        })?;
    let result = setup_result(intent, &outcomes, receipts, true);
    let id = held.id.clone();
    let retention = ops.local_retention();
    let now = ops.local_narrowing_now().await;
    let environment = ops.environment().clone();
    let generation = intent.generation;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state.is_settled() {
            return Ok(());
        }
        let e = OpError::new(
            Code::ConfigConflict,
            "the held setup operation was closed by the owner with the files kept as they are; preview again",
        )
        .with_reason(reason::PROJECTION_HELD)
        .with_effect(EffectStatus::Partial);
        local_settle_failed(tx, emit, &mut op, &e, now, retention)?;
        op.result = Some(error_data(&e.with_operation(id.clone()), Some(&result)));
        tx.update_operation(&op)?;
        for item in result.items.iter().map(|i| i.item) {
            emit.event(
                tx,
                EventType::ResourceChanged,
                Some(id.clone()),
                Some(projection_ref(&environment)),
                serde_json::json!({ "item": item, "generation": generation, "change": "conflict" }),
            )?;
        }
        Ok(())
    })
    .await
}

// --- the sink over the store -----------------------------------------------------------------

/// The writer's `StageSink` over the store (module docs). Each call is one synchronous
/// store transaction; it runs on the blocking pool with the writer.
pub(crate) struct StoreSink {
    store: Arc<Store>,
    clock: Arc<dyn heimdall_domain::time::Clock>,
    operation: OperationId,
    environment: EnvironmentId,
    intent: SetupIntent,
    token: String,
    /// Whether any receipt was made durable through this sink.
    wrote: bool,
}

impl StoreSink {
    fn new(ops: &Operations, operation: &OperationId, intent: &SetupIntent, token: &str) -> Self {
        Self {
            store: ops.local_store(),
            clock: ops.local_clock(),
            operation: operation.clone(),
            environment: ops.environment().clone(),
            intent: intent.clone(),
            token: token.to_owned(),
            wrote: false,
        }
    }

    /// The effect a local receipt's phase fixes (ADR-0007 §5.7 "Receipts").
    fn effect(&self, local: &LocalReceipt) -> EffectReceipt {
        let adapter = adapter_identity(&self.environment);
        if local.effect_is_confirmed() {
            let (item, generation) = match local {
                LocalReceipt::Item {
                    item,
                    phase: ItemPhase::Committed { generation },
                } => (*item, *generation),
                LocalReceipt::Item { item, .. } => (*item, self.intent.generation),
                LocalReceipt::File { .. } => (ProjectionItem::Ssh, self.intent.generation),
            };
            EffectReceipt::Confirmed {
                adapter,
                credential_ref: format!("projection/{}/{generation}", item_name(item)),
            }
        } else {
            EffectReceipt::Attempted {
                adapter,
                effect_token: self.token.clone(),
            }
        }
    }
}

/// The environment's projection record after `commit` (module docs): placeholders
/// completed, the stored record's other items kept, the item's files merged (stored
/// files this intent neither rewrote nor removed stay), its aliases merged when P is
/// unchanged, and a rollback's item emptied.
fn committed_record(
    stored: Option<ProjectionRecord>,
    commit: &ItemCommit,
    intent: &SetupIntent,
    environment: &EnvironmentId,
    operation: &OperationId,
    at: Timestamp,
) -> ProjectionRecord {
    let mut record = stored.unwrap_or_else(|| ProjectionRecord {
        environment: environment.clone(),
        items: BTreeMap::new(),
    });
    record.environment = environment.clone();
    let previous = record.items.get(&commit.item).cloned();
    let given = commit.record.items.get(&commit.item).cloned();
    let item = if matches!(intent.intent, PreviewIntent::Rollback { .. }) {
        ItemRecord {
            generation: commit.generation,
            files: Vec::new(),
            aliases: Vec::new(),
            operation: operation.clone(),
            committed_at: at,
        }
    } else {
        let written: Vec<ProjectionLocator> = given
            .as_ref()
            .map_or_else(|| commit.resources.clone(), |g| g.files.clone());
        let removed: BTreeSet<&str> = intent
            .files
            .iter()
            .filter(|s| s.role.item() == commit.item && matches!(s.target, Target::Absent))
            .map(|s| s.path.as_str())
            .collect();
        let mut files: Vec<ProjectionLocator> = previous
            .as_ref()
            .map(|p| {
                p.files
                    .iter()
                    .filter(|f| {
                        !removed.contains(f.path.as_str())
                            && !written.iter().any(|w| w.role == f.role && w.path == f.path)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        files.extend(written.iter().cloned());
        files.sort_by(|a, b| (a.role, &a.path).cmp(&(b.role, &b.path)));
        let p_written = written.iter().any(|w| w.role == FileRole::ManagedSsh);
        let aliases = if p_written || previous.is_none() {
            given.map(|g| g.aliases).unwrap_or_default()
        } else {
            previous.map(|p| p.aliases).unwrap_or_default()
        };
        ItemRecord {
            generation: commit.generation,
            files,
            aliases,
            operation: operation.clone(),
            committed_at: at,
        }
    };
    record.items.insert(commit.item, item);
    record
}

impl StageSink for StoreSink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        let stage = StageReceipt {
            stage: receipt.stage().to_owned(),
            recorded_at: self.clock.wall(),
            effect: self.effect(receipt),
            local: Some(receipt.clone()),
        };
        let op = &self.operation;
        self.store
            .transaction(|tx| tx.append_stage_receipt(op, &stage))
            .map_err(|e| SinkError(format!("receipt not durable: {e}")))?;
        self.wrote = true;
        Ok(())
    }

    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        // ADR-0007 §12.19 item 9: consent is recorded only under the decision that
        // approved exactly this intent.
        let approved = self.intent.approval.as_ref().map(|a| &a.decision);
        if commit
            .consent
            .items
            .values()
            .any(|c| Some(&c.decision) != approved)
        {
            return Err(SinkError(
                "the commit's consent names a decision other than the intent's approval".to_owned(),
            ));
        }
        let now = self.clock.wall();
        let local = LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        };
        let receipt = StageReceipt {
            stage: local.stage().to_owned(),
            recorded_at: now,
            effect: self.effect(&local),
            local: Some(local),
        };
        let (op, env, intent) = (&self.operation, &self.environment, &self.intent);
        self.store
            .transaction(|tx| {
                let stored = tx.projection_record(env)?;
                let record = committed_record(stored, &commit, intent, env, op, now);
                let full = ItemCommit {
                    record,
                    ..commit.clone()
                };
                tx.commit_projection_item(op, &full, &receipt)
            })
            .map_err(|e| SinkError(format!("commit not durable: {e}")))?;
        self.wrote = true;
        Ok(())
    }
}
