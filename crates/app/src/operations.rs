//! The six primitives as one shared implementation (spec §11.7 "the same
//! application operations used by CLI and TUI"; R-UX-05, R-AP-07), plus the
//! attended-session actions (ADR-0006 §3.1): `attend`, `decide`, `confirm_time`.
//!
//! # Pipeline (plan §4.2; ADR-0006 §14.1; m01-plan U5)
//!
//! `ensure` and `delegate` share one durable pipeline driven **from stored state**:
//! the operation row, its [`RecoveryIntent`] and its append-only [`StageReceipt`]s.
//! A new request, a same-key retry, an approval and restart recovery all call the
//! same driver, which reads what is durable and continues from the first stage
//! without a receipt. Nothing is re-resolved after `ResolveMechanism` (the pinned
//! [`ResolvedIntent`] carries scope, deadline, policy revision and generation).
//!
//! * The idempotency row and the operation row are inserted in **one**
//!   transaction together with the `Authenticate` receipt, after
//!   `classify(record, marker, hash, now)` in that same transaction (ADR-0006 §7.3),
//!   so concurrent duplicates are linearized by the store.
//! * `Reconcile` mints an effect token and writes an `Attempted` receipt **before**
//!   `CredentialAdapter::prepare`; with an `Attempted` or `Uncertain` receipt on
//!   record a retry or restart calls `reconcile(token)` on the **recorded adapter
//!   identity**, never `prepare`, until the adapter says `NotApplied`. A lost reply
//!   moves the operation to `outcome_unknown` (quiescent, never settled, its key
//!   never expires); reconciliation later settles it.
//! * `TimeGate::check` runs before resolution, before `prepare`, at `Recheck`
//!   (immediately before `Commit`) and in `tick`; `TimeGate::anchor_grant` anchors
//!   the grant right before activation; the `Commit` transaction re-validates
//!   tombstones, generation, pause/cutoff, policy revision, deadline and the
//!   continuous admission of the persisted anchor before it writes the active
//!   binding, so a revocation that commits first always wins.
//! * Added authority (`ApprovalRequired`) always creates a server-issued
//!   [`DecisionRecord`] with the exact delta and an `awaiting_approval` grant
//!   (ADR-0006 §3.1, ⟨r2.1⟩ N04): attended ⇒ `APPROVAL_REQUIRED`, unattended ⇒
//!   `INTERACTION_REQUIRED`, both with `next.decision_ref`. Only `decide` on an
//!   attended session completes it. An expired decision is `DECISION_STALE` and the
//!   operation stays waiting; a same-key retry returns a fresh `decision_ref`; the
//!   grant reaching its deadline fails the waiting operation with
//!   `CREDENTIAL_EXPIRED` (ADR-0006 §13.3).
//!
//! # Readings chosen where the documents leave a gap (fail closed; escalated)
//!
//! * There is no destination-capability table in the M01 store: a requested pair's
//!   destination capability is the selected adapter's declared enforcement.
//! * A requested pair outside the profile snapshot is `USAGE_ERROR` (request
//!   content never widens a profile).
//! * A continuing work ID never extends its expiry: a new grant for a work ID that
//!   already had bindings is capped at the earliest of their deadlines, and refused
//!   with `CREDENTIAL_EXPIRED` once that has passed (spec §6.1).
//! * An operation whose authority changed under it (tombstone, generation moved,
//!   policy revision moved) fails with `CREDENTIAL_EXPIRED` (`next: new_work`);
//!   an owner denial fails it with `CAPABILITY_UNAVAILABLE`.
//! * `awaiting_approval → failed` uses the lifecycle's only legal edge,
//!   `DecisionDenied`, for deadline expiry and authority changes too.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use heimdall_contract::envelope::{EffectStatus, NextAction, ResourceRef, Warning};
use heimdall_contract::event::{EventType, Snapshot};
use heimdall_contract::ids::{
    BindingId, DestinationId, EnvironmentId, GrantId, IssuanceId, OperationId, PolicyId, ProfileId,
    WorkId,
};
use heimdall_contract::request::{
    BindForm, BindRequest, CancelRequest, ConfirmTimeRequest, ConsumerIntegration, DeadlineIntent,
    DecideRequest, DelegateRequest, DestinationScopeEnforcement, EnsureData, EnsureRequest,
    InspectRequest, InspectSubject, InteractionMode, MAX_ARGV_BYTES, MAX_SCOPE_PAIRS,
    ObserveRequest, PolicyAction, RefreshDependency, ReleaseRequest, Request, RequiredCapabilities,
    RevokeData, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::authority::{
    AuthorityDecision, AuthorityDelta, AuthorityInput, resolve_authority,
};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome, may_act_on};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionRefusal, DecisionState};
use heimdall_domain::environment::{
    DestinationCapability, EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::idempotency::{
    HashInput, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, classify, compute_hash,
    retention_expiry,
};
use heimdall_domain::issuance::{
    CertificateBounds, IssuanceCheck, IssuanceEntry, IssuanceRefusal, IssuanceState,
};
use heimdall_domain::lifecycle::{
    GrantEvent, OperationEvent, grant_transition, operation_transition,
};
use heimdall_domain::operation::{
    AdapterIdentity, CancellationRecord, EffectClass, EffectReceipt, OperationKind,
    OperationRecord, RecoveryIntent, RecoveryMetadata, ResolvedIntent, StageReceipt,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::ProfileSnapshot;
use heimdall_domain::revocation::Tombstone;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{self as dtime, Admission, Clock, Deadline, TimePolicy, TimeSync};
use heimdall_store::{DecisionCompletion, Store, StoreError, Txn};
use tokio::sync::watch;

use crate::context::{Attendance, Caller};
use crate::ensure::{EnsureHandle, EnsureStage, EquivalenceKey, StageHook};
use crate::error::{Completed, OpError, OpResult};
use crate::events::{EventPublisher, SequencedEvent, decision_kind_name, visible_to};
use crate::ports::{
    AdapterError, CredentialAdapter, PrepareOutcome, PrepareRequest, ReconcileOutcome,
};
use crate::singleflight::{Flight, SingleFlight, follow};
use crate::timegate::{SafeNow, TimeGate};

/// Bounds the application enforces regardless of caller (spec §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrent operations in `running`.
    pub max_running_operations: usize,
    /// Maximum concurrent adapter prepare/probe calls.
    pub max_concurrent_adapter_calls: usize,
    /// Maximum events returned by one `observe` page.
    pub max_event_page: u32,
    /// Maximum bounded wait a caller may request.
    pub max_wait: Duration,
    /// Retention of settled operations and idempotency records after settlement
    /// (never below `MIN_RETENTION`; unresolved operations are never purged).
    pub operation_retention: Duration,
    /// Retention of the event log.
    pub event_retention: Duration,
    /// Lifetime of a pending decision record.
    pub decision_lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_running_operations: 32,
            max_concurrent_adapter_calls: 4,
            max_event_page: 500,
            max_wait: Duration::from_secs(300),
            operation_retention: heimdall_domain::idempotency::DEFAULT_RETENTION,
            event_retention: Duration::from_secs(7 * 24 * 60 * 60),
            decision_lifetime: heimdall_domain::decision::DEFAULT_DECISION_LIFETIME,
        }
    }
}

/// Row cap for the event log trimmed by `tick` (in addition to the age bound).
pub const EVENT_ROW_CAP: u64 = 100_000;

/// Suggested retry delay for `BACKPRESSURE`.
const BACKPRESSURE_RETRY_MS: u64 = 1_000;

/// Upper bound on pipeline steps per drive (a stage that does not make durable
/// progress can never spin).
const MAX_DRIVE_STEPS: usize = 32;

/// Longest ancestor chain walked for a delegated grant.
const MAX_ANCESTRY: usize = 64;

/// Construction parameters.
pub struct OperationsConfig {
    /// State store.
    pub store: Arc<Store>,
    /// Clock (system or virtual).
    pub clock: Arc<dyn Clock>,
    /// Platform synchronization report (stub returning `Unknown` until evidenced).
    pub time_sync: Arc<dyn TimeSync>,
    /// Time plausibility policy.
    pub time_policy: TimePolicy,
    /// This runtime's environment.
    pub environment: EnvironmentId,
    /// Credential adapters by mechanism name.
    pub adapters: Vec<Arc<dyn CredentialAdapter>>,
    /// Pipeline fault-injection hook; production passes `NoStageHook`
    /// (plan §6.4; review F09).
    pub stage_hook: Arc<dyn StageHook>,
    /// Limits.
    pub limits: Limits,
    /// Default maximum window for new work (spec P04).
    pub default_window: Duration,
}

impl std::fmt::Debug for OperationsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationsConfig")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// The application operations. Cheap to clone (`Arc` inside); one instance per
/// runtime.
#[derive(Clone)]
pub struct Operations {
    inner: Arc<Inner>,
}

/// Result a per-operation leader publishes to concurrent duplicates.
type DriveResult = Result<(), OpError>;

struct Inner {
    config: OperationsConfig,
    publisher: EventPublisher,
    timegate: TimeGate,
    /// Equivalent work (spec §8.2): one preparation, separate references.
    singleflight: SingleFlight<EquivalenceKey, EnsureHandle>,
    /// One driver per operation; concurrent duplicates and retries follow it.
    flights: SingleFlight<OperationId, DriveResult>,
    /// Operations currently driven by this process (`max_running_operations`).
    running: AtomicUsize,
    /// Concurrent adapter calls (`max_concurrent_adapter_calls`).
    adapter_slots: tokio::sync::Semaphore,
    /// Signalled after every committed state change (bounded `observe` waits).
    changed: tokio::sync::Notify,
    /// Issuance entries reserved by **this** runtime instance; a `reserved` entry
    /// found after a restart is never published (ADR-0005 §3.5).
    reserved_here: Mutex<HashMap<IssuanceId, GrantId>>,
}

impl std::fmt::Debug for Operations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operations")
            .field("environment", &self.inner.config.environment)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------

fn join_error(_: tokio::task::JoinError) -> OpError {
    OpError::new(Code::InternalError, "operation task failed")
}

fn internal(msg: &str) -> OpError {
    OpError::new(Code::InternalError, msg.to_owned())
}

fn conflict(msg: &str) -> StoreError {
    StoreError::GenerationConflict(msg.to_owned())
}

fn resource(kind: &str, id: impl ToString) -> ResourceRef {
    ResourceRef {
        kind: kind.to_owned(),
        id: Some(id.to_string()),
    }
}

fn plus(t: Timestamp, d: Duration) -> Timestamp {
    jiff::SignedDuration::try_from(d)
        .ok()
        .and_then(|s| t.checked_add(s).ok())
        .unwrap_or(Timestamp::MAX)
}

fn minus(t: Timestamp, d: Duration) -> Timestamp {
    jiff::SignedDuration::try_from(d)
        .ok()
        .and_then(|s| t.checked_sub(s).ok())
        .unwrap_or(Timestamp::MIN)
}

/// Apply an operation transition (spec §11.4 table); an illegal one is a state
/// conflict (fail closed, `STATE_UNAVAILABLE`).
fn op_to(
    op: &mut OperationRecord,
    ev: OperationEvent,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    op.state =
        operation_transition(op.state, ev).map_err(|_| conflict("illegal operation transition"))?;
    op.updated_at = now;
    Ok(())
}

/// Apply a grant transition (spec §6.3 table).
fn grant_to(g: &mut GrantSnapshot, ev: GrantEvent) -> heimdall_store::Result<()> {
    g.state = grant_transition(g.state, ev).map_err(|_| conflict("illegal grant transition"))?;
    Ok(())
}

/// Apply a grant event when the table allows it from the current state; terminal
/// and other states stay as they are. Returns whether it moved.
fn grant_try(g: &mut GrantSnapshot, ev: GrantEvent) -> bool {
    match grant_transition(g.state, ev) {
        Ok(next) if next != g.state => {
            g.state = next;
            true
        }
        _ => false,
    }
}

fn receipt(stage: EnsureStage, now: Timestamp, effect: EffectReceipt) -> StageReceipt {
    StageReceipt {
        stage: stage.as_str().to_owned(),
        recorded_at: now,
        effect,
    }
}

fn stage_of(name: &str) -> Option<EnsureStage> {
    EnsureStage::ALL.into_iter().find(|s| s.as_str() == name)
}

/// The last `Reconcile` receipt (the effect state of the operation).
fn last_reconcile(receipts: &[StageReceipt]) -> Option<&EffectReceipt> {
    receipts
        .iter()
        .rev()
        .find(|r| r.stage == EnsureStage::Reconcile.as_str())
        .map(|r| &r.effect)
}

/// Token of the most recent `Attempted`/`Uncertain` receipt.
fn last_token(receipts: &[StageReceipt]) -> Option<String> {
    receipts.iter().rev().find_map(|r| match &r.effect {
        EffectReceipt::Attempted { effect_token, .. }
        | EffectReceipt::Uncertain { effect_token, .. } => Some(effect_token.clone()),
        _ => None,
    })
}

/// Whether this operation attached to an equivalent leader's grant instead of
/// preparing (its `Reconcile` receipt is `NotAttempted`).
fn coalesced(receipts: &[StageReceipt]) -> bool {
    matches!(last_reconcile(receipts), Some(EffectReceipt::NotAttempted))
}

/// First stage without a durable receipt. `Reconcile` counts as done only once its
/// last receipt is `Confirmed` (or `NotAttempted` when coalesced).
fn next_stage(receipts: &[StageReceipt]) -> Option<EnsureStage> {
    let mut done = BTreeSet::new();
    for r in receipts {
        if let Some(s) = stage_of(&r.stage)
            && s != EnsureStage::Reconcile
        {
            done.insert(s);
        }
    }
    if matches!(
        last_reconcile(receipts),
        Some(EffectReceipt::Confirmed { .. } | EffectReceipt::NotAttempted)
    ) {
        done.insert(EnsureStage::Reconcile);
    }
    EnsureStage::ALL.into_iter().find(|s| !done.contains(s))
}

/// What the receipts say about the external effect so far (never `none` once an
/// attempt is on record without a confirmation).
fn effect_so_far(receipts: &[StageReceipt]) -> EffectStatus {
    match last_reconcile(receipts) {
        Some(EffectReceipt::Attempted { .. } | EffectReceipt::Uncertain { .. }) => {
            EffectStatus::Unknown
        }
        Some(EffectReceipt::Confirmed { .. }) => EffectStatus::Partial,
        _ => EffectStatus::None,
    }
}

fn may_have_external_effect(receipts: &[StageReceipt]) -> bool {
    receipts.iter().any(|r| {
        matches!(
            r.effect,
            EffectReceipt::Attempted { .. }
                | EffectReceipt::Confirmed { .. }
                | EffectReceipt::Uncertain { .. }
        )
    })
}

/// An environment with no enrolled permissions (nothing is automatic) for a
/// runtime whose own environment record has not been written yet.
fn unenrolled(id: &EnvironmentId) -> EnvironmentRecord {
    EnvironmentRecord {
        id: id.clone(),
        device: heimdall_contract::ids::DeviceId::from_random_bytes([0; 16]),
        kind: EnvironmentKind::NativeSession,
        label: None,
        permissions: EnvironmentPermissions::default(),
    }
}

/// The applicable policy among several naming the profile and environment: one
/// that blocks activation at `now` wins (pause/cutoff override allow), else the
/// first by ID. Its scope, window and revision are the ones resolution used.
fn choose_policy(policies: &[StandingPolicy], now: Timestamp) -> Option<&StandingPolicy> {
    policies
        .iter()
        .find(|p| p.blocks_activation_at(now).is_some())
        .or_else(|| policies.first())
}

/// The policy view every bound, block and issuance check uses: the chosen policy
/// (scope, window, revision) restricted by **every** applicable policy's pause and
/// cutoff (gap G08; plan §6.3 #2): the earliest cutoff of any applicable policy
/// bounds the grant, and any applicable pause blocks activation. Never wider than
/// the chosen policy alone.
fn merged_policy(policies: &[StandingPolicy], now: Timestamp) -> Option<StandingPolicy> {
    let mut merged = choose_policy(policies, now)?.clone();
    for p in policies {
        if let Some(c) = p.cutoff_at {
            merged.cutoff_at = Some(merged.cutoff_at.map_or(c, |m| m.min(c)));
        }
        if let PauseState::Paused { since } = p.pause {
            merged.pause = match merged.pause {
                PauseState::Paused { since: s } => PauseState::Paused {
                    since: s.min(since),
                },
                PauseState::Active => PauseState::Paused { since },
            };
        }
    }
    Some(merged)
}

/// Events committed with a transaction; announced to live subscribers after it.
struct Emit {
    publisher: EventPublisher,
    events: Vec<SequencedEvent>,
}

impl Emit {
    fn event(
        &mut self,
        tx: &mut Txn<'_>,
        ty: EventType,
        op: Option<OperationId>,
        res: Option<ResourceRef>,
        payload: serde_json::Value,
    ) -> heimdall_store::Result<()> {
        let e = self.publisher.append_in(tx, ty, op, res, payload)?;
        self.events.push(e);
        Ok(())
    }

    fn op(&mut self, tx: &mut Txn<'_>, op: &OperationRecord) -> heimdall_store::Result<()> {
        self.event(
            tx,
            EventType::OperationStateChanged,
            Some(op.id.clone()),
            Some(resource("operation", &op.id)),
            serde_json::json!({
                "kind": op.kind,
                "state": op.state,
                "code": op.code,
                "effect_status": op.effect_status,
            }),
        )
    }

    fn grant(
        &mut self,
        tx: &mut Txn<'_>,
        g: &GrantSnapshot,
        op: Option<&OperationId>,
    ) -> heimdall_store::Result<()> {
        self.event(
            tx,
            EventType::GrantStateChanged,
            op.cloned(),
            Some(resource("grant", &g.id)),
            serde_json::json!({ "grant_id": g.id, "state": g.state }),
        )
    }

    fn decision(
        &mut self,
        tx: &mut Txn<'_>,
        d: &DecisionRecord,
        op: Option<&OperationId>,
    ) -> heimdall_store::Result<()> {
        self.event(
            tx,
            EventType::Decision,
            op.cloned(),
            Some(resource("decision", &d.id)),
            serde_json::json!({
                "decision_id": d.id,
                "kind": decision_kind_name(&d.kind),
                "state": d.state,
                "expires_at": d.expires_at,
            }),
        )
    }

    fn policy(&mut self, tx: &mut Txn<'_>, p: &StandingPolicy) -> heimdall_store::Result<()> {
        self.event(
            tx,
            EventType::PolicyChanged,
            None,
            Some(resource("policy", &p.id)),
            serde_json::json!({
                "policy_id": p.id,
                "revision": p.revision.0,
                "paused": matches!(p.pause, PauseState::Paused { .. }),
                "cutoff_at": p.cutoff_at,
            }),
        )
    }
}

/// Settle an operation as failed with `err` (and its idempotency record).
fn settle_failed(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    err: &OpError,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<()> {
    let ev = match op.state {
        OperationState::AwaitingApproval => OperationEvent::DecisionDenied,
        OperationState::OutcomeUnknown => OperationEvent::ReconciledNotApplied,
        _ => OperationEvent::Fail,
    };
    op_to(op, ev, now)?;
    let err = err.clone().with_operation(op.id.clone());
    op.code = Some(err.code.clone());
    op.effect_status = err.effect_status;
    op.result = Some(serde_json::json!({ "error": err.detail() }));
    tx.update_operation(op)?;
    tx.settle_idempotency(&op.key, retention_expiry(now, retention))?;
    emit.op(tx, op)
}

/// Settle an operation as succeeded with `code` and `data`.
fn settle_succeeded(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    code: Code,
    data: serde_json::Value,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<()> {
    if op.state == OperationState::Queued {
        op_to(op, OperationEvent::Start, now)?;
    }
    let ev = if op.state == OperationState::OutcomeUnknown {
        OperationEvent::ReconciledApplied
    } else {
        OperationEvent::Succeed
    };
    op_to(op, ev, now)?;
    op.code = Some(code);
    op.effect_status = EffectStatus::Applied;
    op.result = Some(data);
    tx.update_operation(op)?;
    tx.settle_idempotency(&op.key, retention_expiry(now, retention))?;
    emit.op(tx, op)
}

/// The recorded parent grant and the chain above it, nearest first (the shape
/// `IssuanceCheck` wants: `parent`, then `ancestors`).
fn ancestry(tx: &mut Txn<'_>, grant: &GrantSnapshot) -> heimdall_store::Result<Vec<GrantSnapshot>> {
    let mut chain = Vec::new();
    let mut next = grant.parent.clone();
    while let Some(id) = next {
        if chain.len() >= MAX_ANCESTRY {
            return Err(StoreError::Corrupt("grant ancestry is too deep".into()));
        }
        let Some(g) = tx.grant(&id)? else {
            break;
        };
        next = g.parent.clone();
        chain.push(g);
    }
    Ok(chain)
}

/// Where a grant's authority comes from: profile (and revision), the policy
/// revision it was resolved under, the caller it was resolved for and its
/// mechanism. The store has no grant → operation index (escalated), so this looks
/// at open/unresolved operations that pin the grant, then at the bindings
/// realizing it (never at a delegated child's binding that only holds a reference).
struct GrantContext {
    profile: Option<ProfileId>,
    profile_revision: Option<u64>,
    expected_policy_revision: Option<PolicyRevision>,
    caller: Option<CallerContext>,
    mechanism: Option<String>,
}

fn grant_context(tx: &mut Txn<'_>, grant: &GrantSnapshot) -> heimdall_store::Result<GrantContext> {
    let recorded = match &grant.source {
        AuthorizationSource::StandingPolicy { revision } => Some(*revision),
        _ => None,
    };
    let mut ops = tx.open_operations()?;
    ops.extend(tx.unresolved_operations()?);
    for op in ops {
        if let Some(intent) = tx.recovery_intent(&op.id)?
            && let Some(resolved) = intent.resolved
            && resolved.grant.as_ref() == Some(&grant.id)
        {
            return Ok(GrantContext {
                profile: Some(resolved.profile),
                profile_revision: Some(resolved.profile_revision),
                expected_policy_revision: resolved.policy_revision.or(recorded),
                caller: Some(op.key.caller.clone()),
                mechanism: resolved.adapter.map(|a| a.mechanism),
            });
        }
    }
    for r in tx.grant_references(&grant.id)? {
        if let Some(b) = tx.binding(&r.binding)?
            && b.grant == grant.id
        {
            return Ok(GrantContext {
                profile: Some(b.profile),
                profile_revision: Some(b.profile_revision),
                expected_policy_revision: recorded,
                caller: Some(b.owner),
                mechanism: Some(b.mechanism),
            });
        }
    }
    Ok(GrantContext {
        profile: None,
        profile_revision: None,
        expected_policy_revision: recorded,
        caller: None,
        mechanism: None,
    })
}

/// The generation at which `grant` was last validated: its authorization
/// generation, or a later re-validation (ADR-0006 §13.5 ruling 2).
fn validated_generation(
    tx: &mut Txn<'_>,
    grant: &GrantSnapshot,
) -> heimdall_store::Result<heimdall_domain::policy::AuthorityGeneration> {
    Ok(tx
        .grant_validation(&grant.id)?
        .map_or(grant.generation, |v| v.max(grant.generation)))
}

/// A grant and its ancestors (nearest first), each validated at the current
/// authority generation; the copies carry that generation so the generation
/// predicates (`issuance::check`, `resolve_authority`'s parent rule, activation)
/// compare the **last validated** generation with the current one.
struct Validated {
    grant: GrantSnapshot,
    ancestors: Vec<GrantSnapshot>,
}

fn revalidation_failed(msg: &str) -> OpError {
    authority_changed(msg)
}

/// ADR-0006 §13.5 ruling 2: when the global authority generation moved since a
/// grant or an ancestor was last validated, re-run authority resolution against
/// the **current** policy (every applicable pause and cutoff), tombstones and the
/// parent chain, with the grant's unchanged scope and deadline as the request, no
/// widening and no prompt (spec §5.5 silent repair within saved authority). On
/// success the new validated generation is recorded for every member; any
/// failure denies (`CREDENTIAL_EXPIRED`, `next: new_work`; nothing is recorded).
///
/// Acceptance per authorization source: `StandingPolicy` and `Delegation` grants
/// need `Allowed` (a narrowed policy that no longer covers the grant's scope or
/// window denies); an `OwnerDecision` grant needs only "not denied" (the owner
/// already approved the delta; pause, cutoff, parent and role rules still apply).
fn revalidate_chain(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    now: Timestamp,
) -> heimdall_store::Result<Result<Validated, OpError>> {
    let current = tx.authority_generation()?;
    if tx.denied_ancestor(&grant.id)?.is_some() {
        return Ok(Err(revalidation_failed(
            "the grant or an ancestor was revoked",
        )));
    }
    let chain = ancestry(tx, grant)?;
    if grant.parent.is_some() && chain.is_empty() {
        return Ok(Err(revalidation_failed("the parent grant is missing")));
    }
    let mut parent: Option<GrantSnapshot> = None;
    let mut members: Vec<GrantSnapshot> = Vec::with_capacity(chain.len() + 1);
    let mut revalidated: Vec<GrantId> = Vec::new();
    for g in chain.iter().rev().chain(std::iter::once(grant)) {
        if g.state.is_terminal() {
            return Ok(Err(revalidation_failed(
                "the grant or an ancestor has ended",
            )));
        }
        if validated_generation(tx, g)? != current {
            if let Err(e) =
                revalidate_one(tx, environment, adapters, g, parent.as_ref(), current, now)?
            {
                return Ok(Err(e));
            }
            revalidated.push(g.id.clone());
        }
        let mut copy = g.clone();
        copy.generation = current;
        parent = Some(copy.clone());
        members.push(copy);
    }
    for id in &revalidated {
        tx.record_grant_validation(id, current)?;
    }
    let Some(grant) = members.pop() else {
        return Err(conflict("empty grant chain"));
    };
    members.reverse();
    Ok(Ok(Validated {
        grant,
        ancestors: members,
    }))
}

/// Re-run `resolve_authority` for one chain member (see [`revalidate_chain`]).
fn revalidate_one(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    g: &GrantSnapshot,
    parent: Option<&GrantSnapshot>,
    current: heimdall_domain::policy::AuthorityGeneration,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    let decision = match resolve_existing(tx, environment, adapters, g, parent, current, now)? {
        Ok(d) => d,
        Err(e) => return Ok(Err(e)),
    };
    Ok(match (decision, &g.source) {
        (AuthorityDecision::Allowed(_), _)
        | (AuthorityDecision::ApprovalRequired { .. }, AuthorizationSource::OwnerDecision { .. }) => {
            Ok(())
        }
        (AuthorityDecision::ApprovalRequired { .. }, _) => Err(revalidation_failed(
            "the standing policy no longer covers the grant",
        )),
        (AuthorityDecision::Denied(_), _) => Err(revalidation_failed(
            "the grant's authority is no longer current",
        )),
    })
}

/// The added authority an existing (waiting) grant still needs against current
/// policy, for a fresh decision record when no earlier record is pending.
fn current_delta(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    g: &GrantSnapshot,
    now: Timestamp,
) -> heimdall_store::Result<Option<AuthorityDelta>> {
    let Ok(v) = revalidate_chain(tx, environment, adapters, g, now)? else {
        return Ok(None);
    };
    let current = tx.authority_generation()?;
    Ok(
        match resolve_existing(
            tx,
            environment,
            adapters,
            g,
            v.ancestors.first(),
            current,
            now,
        )? {
            Ok(AuthorityDecision::ApprovalRequired { delta, .. }) => Some(delta),
            _ => None,
        },
    )
}

/// `resolve_authority` over an existing grant's unchanged scope and deadline.
fn resolve_existing(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    g: &GrantSnapshot,
    parent: Option<&GrantSnapshot>,
    current: heimdall_domain::policy::AuthorityGeneration,
    now: Timestamp,
) -> heimdall_store::Result<Result<AuthorityDecision, OpError>> {
    if dtime::is_expired(now, g.deadline.effective) {
        return Ok(Err(OpError::new(
            Code::CredentialExpired,
            "the grant reached its deadline",
        )
        .with_resource("grant", Some(g.id.to_string()))));
    }
    let ctx = grant_context(tx, g)?;
    let (Some(profile_id), Some(revision), Some(caller)) =
        (ctx.profile, ctx.profile_revision, ctx.caller)
    else {
        return Ok(Err(revalidation_failed(
            "the grant's authority can no longer be re-validated",
        )));
    };
    let Some(profile) = tx.profile_snapshot(&profile_id, revision)? else {
        return Ok(Err(revalidation_failed(
            "the grant's profile revision is unknown",
        )));
    };
    let Some(adapter) = ctx
        .mechanism
        .as_deref()
        .and_then(|m| adapters.iter().find(|a| a.identity.mechanism == m))
    else {
        return Ok(Err(revalidation_failed(
            "the grant's credential mechanism is no longer configured",
        )));
    };
    let env_record = tx
        .environment(environment)?
        .unwrap_or_else(|| unenrolled(environment));
    let policies = tx.policies_for(&profile_id, environment)?;
    let policy = merged_policy(&policies, now);
    let destinations: BTreeMap<DestinationId, DestinationCapability> = g
        .scope
        .pairs
        .iter()
        .map(|p| {
            (
                p.destination.clone(),
                DestinationCapability {
                    destination: p.destination.clone(),
                    enrollment_level: 1,
                    scope_enforcement: adapter.scope_enforcement,
                    mechanisms: [adapter.identity.mechanism.clone()].into_iter().collect(),
                },
            )
        })
        .collect();
    let required = RequiredCapabilities::default();
    let decision = resolve_authority(&AuthorityInput {
        caller: &caller,
        policy: policy.as_ref(),
        generation: current,
        environment: &env_record,
        profile: &profile,
        requested: &g.scope,
        parent,
        destinations: &destinations,
        required: &required,
        requested_deadline: &g.deadline,
        now,
    });
    Ok(Ok(decision))
}

/// Write a grant state change and its event; when the grant reached a terminal
/// state (or `revoking`, which only leads to `revoked`), drop the references it
/// holds on its parent (ADR-0006 §13.5 ruling 1) and let a parent left without
/// references become `released`, up the chain.
fn put_grant(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    g: &GrantSnapshot,
    op: Option<&OperationId>,
) -> heimdall_store::Result<()> {
    tx.update_grant_state(g)?;
    emit.grant(tx, g, op)?;
    let mut child = g.clone();
    for _ in 0..MAX_ANCESTRY {
        // `revoking` can only become `revoked`: the child is never live again, so
        // its reference goes now rather than when remote revocation completes
        // (fail closed: a parent is not kept alive by a dead child).
        if !(child.state.is_terminal() || child.state == GrantState::Revoking) {
            break;
        }
        let Some(pid) = child.parent.clone() else {
            break;
        };
        let mut remaining = None;
        for r in tx.grant_references(&pid)? {
            if tx.binding(&r.binding)?.is_some_and(|b| b.grant == child.id) {
                remaining = Some(tx.remove_grant_reference(&r)?);
            }
        }
        let Some(remaining) = remaining else {
            break;
        };
        let Some(mut p) = tx.grant(&pid)? else {
            break;
        };
        if remaining == 0 && grant_try(&mut p, GrantEvent::LastReferenceReleased) {
            // Release is never revoke (ADR-0006 §13.1 item 2): no tombstone, no
            // cascade to other descendants.
            tx.update_grant_state(&p)?;
            emit.grant(tx, &p, None)?;
            child = p;
        } else {
            break;
        }
    }
    Ok(())
}

/// `min(deadline, every ancestor deadline, cutoff)` (ADR-0005 §3.6).
fn grant_bound(
    grant: &GrantSnapshot,
    ancestors: &[GrantSnapshot],
    policy: Option<&StandingPolicy>,
) -> Timestamp {
    let mut bound = grant.deadline.effective;
    for a in ancestors {
        bound = bound.min(a.deadline.effective);
    }
    if let Some(cutoff) = policy.and_then(|p| p.cutoff_at) {
        bound = bound.min(cutoff);
    }
    bound
}

/// The bound to anchor with: never later than a bound already persisted for the
/// grant, even when that anchor belongs to another boot and is being replaced
/// (ADR-0006 §10: re-anchored "with the same persisted bound"; nothing lengthens).
fn anchor_bound(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    bound: Timestamp,
) -> heimdall_store::Result<Timestamp> {
    Ok(match tx.grant_anchor(grant)? {
        Some(a) => a.bound.min(bound),
        None => bound,
    })
}

/// A refused activation and the grant event it implies.
struct Refusal {
    error: OpError,
    grant_event: Option<GrantEvent>,
}

impl Refusal {
    fn new(error: OpError, grant_event: Option<GrantEvent>) -> Self {
        Self { error, grant_event }
    }
}

fn authority_changed(msg: &str) -> OpError {
    OpError::new(Code::CredentialExpired, msg.to_owned()).with_resource("grant", None)
}

/// Re-validate an activation inside the transaction that would write it
/// (`Recheck` and `Commit`): grant state, tombstone on the grant or an ancestor,
/// generation, ancestors, pause/cutoff, policy revision, deadline.
fn activation_refusal(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    intent: &ResolvedIntent,
    grant: &GrantSnapshot,
    now: Timestamp,
    attached: bool,
) -> heimdall_store::Result<Option<Refusal>> {
    let expected_ok = if attached {
        grant.state.permits_use()
    } else {
        grant.state == GrantState::Preparing
    };
    if !expected_ok {
        let error = match grant.state {
            GrantState::Cancelled => {
                OpError::new(Code::OperationCancelled, "the grant was cancelled")
            }
            GrantState::Revoking | GrantState::Revoked => {
                authority_changed("the grant was revoked")
            }
            GrantState::Expired => {
                OpError::new(Code::CredentialExpired, "the grant reached its deadline")
            }
            _ => authority_changed("the grant is no longer usable"),
        };
        return Ok(Some(Refusal::new(error, None)));
    }
    if tx.denied_ancestor(&grant.id)?.is_some() {
        return Ok(Some(Refusal::new(
            authority_changed("the grant or an ancestor was revoked"),
            Some(GrantEvent::RevokeLocal),
        )));
    }
    let current = tx.authority_generation()?;
    let raw = ancestry(tx, grant)?;
    if grant.parent.is_some() && raw.is_empty() {
        return Ok(Some(Refusal::new(
            authority_changed("the parent grant is missing"),
            Some(GrantEvent::PreparationFailed),
        )));
    }
    // ADR-0006 §13.5 ruling 2: a generation that moved since the request was
    // resolved (or since the grant or an ancestor was last validated) triggers one
    // silent re-validation; only a change that touches this chain refuses.
    let mut stale = current != intent.generation || validated_generation(tx, grant)? != current;
    for a in &raw {
        stale = stale || validated_generation(tx, a)? != current;
    }
    let ancestors = if stale {
        match revalidate_chain(tx, environment, adapters, grant, now)? {
            Ok(v) => v.ancestors,
            Err(error) => {
                return Ok(Some(Refusal::new(
                    error,
                    Some(GrantEvent::PreparationFailed),
                )));
            }
        }
    } else {
        raw.into_iter()
            .map(|mut a| {
                a.generation = current;
                a
            })
            .collect()
    };
    for a in &ancestors {
        if !a.state.permits_use()
            || a.generation != current
            || dtime::is_expired(now, a.deadline.effective)
        {
            return Ok(Some(Refusal::new(
                authority_changed("a parent grant is no longer usable"),
                Some(GrantEvent::PreparationFailed),
            )));
        }
    }
    let policies = tx.policies_for(&intent.profile, environment)?;
    let merged = merged_policy(&policies, now);
    let policy = merged.as_ref();
    if let Some(p) = policy
        && let Some(block) = p.blocks_activation_at(now)
    {
        let error = match block {
            heimdall_domain::policy::ActivationBlock::Paused { .. } => {
                OpError::new(Code::PolicyPaused, "the standing policy is paused")
            }
            heimdall_domain::policy::ActivationBlock::Cutoff { .. } => {
                OpError::new(Code::PolicyCutoff, "a policy cutoff is in effect")
            }
        }
        .with_resource("policy", Some(p.id.to_string()));
        return Ok(Some(Refusal::new(
            error,
            Some(GrantEvent::PreparationFailed),
        )));
    }
    if let Some(expected) = intent.policy_revision {
        let applicable = policy.filter(|p| p.profile == intent.profile);
        if applicable.is_none_or(|p| p.revision != expected) {
            return Ok(Some(Refusal::new(
                authority_changed("the standing policy changed while the request was in progress"),
                Some(GrantEvent::PreparationFailed),
            )));
        }
    }
    let bound = grant_bound(grant, &ancestors, policy);
    if dtime::is_expired(now, bound) {
        return Ok(Some(Refusal::new(
            OpError::new(Code::CredentialExpired, "the grant reached its deadline")
                .with_resource("grant", Some(grant.id.to_string())),
            Some(GrantEvent::DeadlineReached),
        )));
    }
    Ok(None)
}

/// Earliest deadline among grants already bound to `work_id` (a continuing work
/// binding never resets its expiry; spec §6.1).
fn work_deadline(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    work_id: &WorkId,
) -> heimdall_store::Result<Option<Timestamp>> {
    let mut end: Option<Timestamp> = None;
    for b in tx.bindings_for_work(environment, work_id)? {
        if let Some(g) = tx.grant(&b.grant)? {
            end = Some(end.map_or(g.deadline.effective, |e| e.min(g.deadline.effective)));
        }
    }
    Ok(end)
}

/// Static facts of one configured adapter (copied out of the descriptor so they
/// can move into store closures).
#[derive(Debug, Clone)]
struct AdapterInfo {
    identity: AdapterIdentity,
    capabilities: BTreeSet<Capability>,
    scope_enforcement: DestinationScopeEnforcement,
}

/// The first adapter that meets the caller's minimum capabilities and
/// destination-scope enforcement (never a silently weaker one).
fn select_adapter<'a>(
    adapters: &'a [AdapterInfo],
    required: &RequiredCapabilities,
) -> Option<&'a AdapterInfo> {
    adapters.iter().find(|a| {
        required.capabilities.is_subset(&a.capabilities)
            && required
                .destination_scope_at_least
                .is_none_or(|m| a.scope_enforcement >= m)
    })
}

// ---------------------------------------------------------------------------------
// Work requests (ensure / delegate)
// ---------------------------------------------------------------------------------

/// What an `ensure`/`delegate` asks for, reconstructed from the recovery intent's
/// stored request (so a restart resumes exactly what was asked).
#[derive(Debug, Clone)]
struct WorkSpec {
    kind: OperationKind,
    profile: Option<ProfileId>,
    profile_revision: Option<u64>,
    environment: EnvironmentId,
    pairs: BTreeSet<AccessPair>,
    work_id: WorkId,
    until: Option<DeadlineIntent>,
    required: RequiredCapabilities,
    interactive: bool,
    parent_binding: Option<BindingId>,
}

impl WorkSpec {
    fn from_request(request: &Request, own: &EnvironmentId) -> Option<Self> {
        match request {
            Request::Ensure(r) => Some(Self {
                kind: OperationKind::Ensure,
                profile: Some(r.profile.clone()),
                profile_revision: r.profile_revision,
                environment: r.environment.clone().unwrap_or_else(|| own.clone()),
                pairs: r.scope.clone(),
                work_id: r.work_id.clone(),
                until: r.until.clone(),
                required: r.required_capabilities.clone(),
                interactive: r.interaction == InteractionMode::Interactive,
                parent_binding: None,
            }),
            Request::Delegate(r) => Some(Self {
                kind: OperationKind::Delegate,
                profile: None,
                profile_revision: None,
                environment: own.clone(),
                pairs: r.scope.clone(),
                work_id: r.work_id.clone(),
                until: r.until.clone(),
                required: r.required_capabilities.clone(),
                interactive: false,
                parent_binding: Some(r.parent_binding_id.clone()),
            }),
            _ => None,
        }
    }
}

/// Inputs to authority resolution that live outside the store.
struct ResolveInput {
    spec: WorkSpec,
    caller: CallerContext,
    operation: OperationId,
    environment: EnvironmentId,
    now: Timestamp,
    default_window: Duration,
    adapters: Vec<AdapterInfo>,
    grant_id: GrantId,
}

/// Outcome of resolution for a work request.
enum Resolution {
    Allowed(Box<ResolvedIntent>),
    Approval(Box<Approval>),
}

/// Added authority waiting for an owner decision.
struct Approval {
    intent: ResolvedIntent,
    grant: GrantSnapshot,
    delta: AuthorityDelta,
}

/// What resolution saw (for `inspect --preview`).
struct Resolved {
    decision: AuthorityDecision,
    requested: Scope,
    deadline: Deadline,
    profile: ProfileSnapshot,
    parent: Option<GrantSnapshot>,
    policy: Option<StandingPolicy>,
    generation: heimdall_domain::policy::AuthorityGeneration,
    adapter: Option<AdapterInfo>,
}

/// Load everything resolution needs from `tx` and run `resolve_authority` (pure).
/// `Err(OpError)` for a refusal no approval can lift.
fn resolve_in(
    tx: &mut Txn<'_>,
    inp: &ResolveInput,
) -> heimdall_store::Result<Result<Resolved, OpError>> {
    macro_rules! refuse {
        ($e:expr) => {
            return Ok(Err($e))
        };
    }
    if inp.spec.environment != inp.environment {
        refuse!(
            OpError::new(
                Code::NotFound,
                "the environment is not managed by this runtime"
            )
            .with_resource("environment", None)
        );
    }
    let (profile, parent) = match inp.spec.kind {
        OperationKind::Delegate => {
            let Some(pb) = &inp.spec.parent_binding else {
                refuse!(OpError::new(
                    Code::UsageError,
                    "a delegation names its parent binding"
                ));
            };
            let Some(binding) = tx.binding(pb)?.filter(|b| may_act_on(b, &inp.caller)) else {
                refuse!(
                    OpError::new(Code::NotFound, "unknown binding").with_resource("binding", None)
                );
            };
            let Some(snapshot) = tx.profile_snapshot(&binding.profile, binding.profile_revision)?
            else {
                refuse!(
                    OpError::new(Code::NotFound, "the parent's profile revision is unknown")
                        .with_resource("profile", None)
                );
            };
            let Some(mut parent) = tx.grant(&binding.grant)? else {
                refuse!(OpError::new(Code::NotFound, "unknown grant").with_resource("grant", None));
            };
            // ADR-0006 §13.5 ruling 2: a parent last validated at an older
            // generation is re-validated first; a failure leaves it stale, so
            // resolution denies it (`ParentNotUsable`).
            if let Ok(v) = revalidate_chain(tx, &inp.environment, &inp.adapters, &parent, inp.now)?
            {
                parent = v.grant;
            }
            (snapshot, Some(parent))
        }
        _ => {
            let Some(pid) = &inp.spec.profile else {
                refuse!(OpError::new(Code::UsageError, "a profile is required"));
            };
            let revision = match inp.spec.profile_revision {
                Some(r) => r,
                None => match tx.profile(pid)? {
                    Some(p) => p.revision,
                    None => refuse!(
                        OpError::new(Code::NotFound, "unknown profile")
                            .with_resource("profile", None)
                    ),
                },
            };
            let Some(snapshot) = tx.profile_snapshot(pid, revision)? else {
                refuse!(
                    OpError::new(Code::NotFound, "unknown profile revision")
                        .with_resource("profile", None)
                );
            };
            (snapshot, None)
        }
    };
    let environment = tx
        .environment(&inp.environment)?
        .unwrap_or_else(|| unenrolled(&inp.environment));
    let policies = tx.policies_for(&profile.id, &inp.environment)?;
    let policy = merged_policy(&policies, inp.now);
    let generation = tx.authority_generation()?;
    let base = parent.as_ref().map_or(&profile.scope, |p| &p.scope);
    let pairs = if inp.spec.pairs.is_empty() {
        base.pairs.clone()
    } else {
        inp.spec.pairs.clone()
    };
    if inp.spec.kind == OperationKind::Ensure && !pairs.is_subset(&profile.scope.pairs) {
        // Request content never widens the profile (A29).
        refuse!(
            OpError::new(
                Code::UsageError,
                "the requested scope names pairs outside the profile"
            )
            .with_resource("profile", Some(profile.id.to_string()))
        );
    }
    let adapter = select_adapter(&inp.adapters, &inp.spec.required).cloned();
    let mut capabilities = base.capabilities.clone();
    if let Some(a) = &adapter {
        capabilities = capabilities
            .intersection(&a.capabilities)
            .copied()
            .collect();
    }
    let requested = Scope {
        pairs,
        capabilities,
    };
    let destinations: BTreeMap<DestinationId, DestinationCapability> = adapter
        .as_ref()
        .map(|a| {
            requested
                .pairs
                .iter()
                .map(|p| {
                    (
                        p.destination.clone(),
                        DestinationCapability {
                            destination: p.destination.clone(),
                            enrollment_level: 1,
                            scope_enforcement: a.scope_enforcement,
                            mechanisms: [a.identity.mechanism.clone()].into_iter().collect(),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let intent = match (&inp.spec.until, &parent) {
        (Some(i), _) => i.clone(),
        (None, Some(p)) => DeadlineIntent::Absolute(p.deadline.effective.to_string()),
        (None, None) => {
            let window = policy
                .as_ref()
                .map_or(inp.default_window, |p| p.max_window)
                .min(inp.default_window);
            DeadlineIntent::Duration(format!("{}s", window.as_secs().max(1)))
        }
    };
    let mut deadline = match dtime::resolve_deadline(&intent, inp.now, inp.default_window) {
        Ok(d) => d,
        Err(e) => refuse!(OpError::from_deadline(&e)),
    };
    if let Some(end) = work_deadline(tx, &inp.environment, &inp.spec.work_id)? {
        if dtime::is_expired(inp.now, end) {
            refuse!(OpError::new(
                Code::CredentialExpired,
                "this work ID's binding has ended; new work needs a new work ID"
            ));
        }
        deadline.effective = deadline.effective.min(end);
    }
    let decision = resolve_authority(&AuthorityInput {
        caller: &inp.caller,
        policy: policy.as_ref(),
        generation,
        environment: &environment,
        profile: &profile,
        requested: &requested,
        parent: parent.as_ref(),
        destinations: &destinations,
        required: &inp.spec.required,
        requested_deadline: &deadline,
        now: inp.now,
    });
    Ok(Ok(Resolved {
        decision,
        requested,
        deadline,
        profile,
        parent,
        policy,
        generation,
        adapter,
    }))
}

/// Turn a resolution into the pinned intent (and, for added authority, the
/// waiting grant).
fn pin(inp: &ResolveInput, r: Resolved) -> Result<Resolution, OpError> {
    let applicable_revision = r
        .policy
        .as_ref()
        .filter(|p| p.profile == r.profile.id)
        .map(|p| p.revision);
    match r.decision {
        AuthorityDecision::Denied(d) => Err(OpError::from_denial(&d)),
        _ if r.adapter.is_none() => Err(OpError::new(
            Code::CapabilityUnavailable,
            "no configured credential mechanism meets the requested minimums",
        )),
        AuthorityDecision::Allowed(auth) => Ok(Resolution::Allowed(Box::new(ResolvedIntent {
            profile: r.profile.id.clone(),
            profile_revision: r.profile.revision,
            scope: auth.scope,
            deadline: Deadline {
                intent: r.deadline.intent.clone(),
                resolved_at: inp.now,
                effective: auth.deadline,
            },
            policy_revision: auth.policy_revision,
            generation: auth.generation,
            grant: None,
            binding: None,
            adapter: r.adapter.map(|a| a.identity),
        }))),
        AuthorityDecision::ApprovalRequired { delta, .. } => {
            // What approval would grant: exactly the requested scope (covered ∪
            // delta) until the hard bound no approval can lift.
            let mut effective = r.deadline.effective;
            if let Some(p) = &r.parent {
                effective = effective.min(p.deadline.effective);
            }
            if let Some(c) = r.policy.as_ref().and_then(|p| p.cutoff_at) {
                effective = effective.min(c);
            }
            let deadline = Deadline {
                intent: r.deadline.intent.clone(),
                resolved_at: inp.now,
                effective,
            };
            let grant = GrantSnapshot {
                id: inp.grant_id.clone(),
                environment: inp.environment.clone(),
                scope: r.requested.clone(),
                starts_at: inp.now,
                deadline: deadline.clone(),
                parent: r.parent.as_ref().map(|p| p.id.clone()),
                source: AuthorizationSource::OwnerDecision {
                    operation_id: inp.operation.clone(),
                },
                generation: r.generation,
                state: GrantState::Requested,
                enforcement: EnforcementEvidence::unknown(),
            };
            let intent = ResolvedIntent {
                profile: r.profile.id.clone(),
                profile_revision: r.profile.revision,
                scope: r.requested,
                deadline,
                policy_revision: applicable_revision,
                generation: r.generation,
                grant: Some(inp.grant_id.clone()),
                binding: None,
                adapter: r.adapter.map(|a| a.identity),
            };
            Ok(Resolution::Approval(Box::new(Approval {
                intent,
                grant,
                delta,
            })))
        }
    }
}

/// Durable state of one operation.
struct WorkState {
    op: OperationRecord,
    intent: RecoveryIntent,
    receipts: Vec<StageReceipt>,
}

impl WorkState {
    fn request(&self) -> Option<Request> {
        serde_json::from_value(self.intent.request.clone()).ok()
    }
}

/// How a stage ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// The stage durably completed; continue with the next.
    Continue,
    /// The operation left the pipeline (settled, awaiting approval, unresolved, or
    /// no longer in the expected state); nothing more to drive now.
    Stop,
}

/// Drive-local facts; all of them are re-derived after a restart.
#[derive(Default)]
struct DriveLocal {
    prepared: Option<PrepareOutcome>,
    safe: Option<SafeNow>,
    bound: Option<Timestamp>,
    lead: Option<(EquivalenceKey, watch::Sender<Option<EnsureHandle>>)>,
    leader_data: Option<EnsureData>,
}

/// Prepared-credential facts reported for a binding.
struct Facts {
    usable_until: Timestamp,
    offline_until: Timestamp,
    refresh_dependency: RefreshDependency,
    enforcement: heimdall_contract::request::Enforcement,
}

impl Facts {
    fn from_outcome(o: &PrepareOutcome) -> Self {
        Self {
            usable_until: o.usable_until,
            offline_until: o.offline_until,
            refresh_dependency: o.refresh_dependency,
            enforcement: o.enforcement.report.clone(),
        }
    }

    fn from_data(d: &EnsureData) -> Self {
        Self {
            usable_until: d.usable_until,
            offline_until: d.offline_until,
            refresh_dependency: d.refresh_dependency,
            enforcement: d.enforcement.clone(),
        }
    }

    /// Facts claimable without the prepare outcome (bind, or an attached binding
    /// resumed after a restart): no claim beyond `now` (never overclaims).
    fn conservative(grant: &GrantSnapshot, now: Timestamp) -> Self {
        Self {
            usable_until: now.min(grant.deadline.effective),
            offline_until: now.min(grant.deadline.effective),
            refresh_dependency: RefreshDependency::ProviderInteraction,
            enforcement: grant.enforcement.report.clone(),
        }
    }
}

fn ensure_data(
    binding: &BindingRecord,
    grant: &GrantSnapshot,
    facts: &Facts,
    bound: Timestamp,
) -> EnsureData {
    let end = grant.deadline.effective.min(bound);
    EnsureData {
        binding_id: binding.id.clone(),
        environment_id: binding.environment.clone(),
        profile_revision: binding.profile_revision,
        grant_id: grant.id.clone(),
        expires_at: grant.deadline.effective,
        usable_until: facts.usable_until.min(end),
        offline_until: facts.offline_until.min(end),
        refresh_dependency: facts.refresh_dependency,
        credential_mechanism: binding.mechanism.clone(),
        enforcement: facts.enforcement.clone(),
        consumer: ConsumerIntegration {
            signing_endpoint: None,
            ssh_config_include: None,
            environment: Vec::new(),
        },
    }
}

fn operation_view(op: &OperationRecord) -> serde_json::Value {
    serde_json::json!({
        "operation_id": op.id,
        "kind": op.kind,
        "state": op.state,
        "code": op.code,
        "effect_status": op.effect_status,
        "created_at": op.created_at,
        "updated_at": op.updated_at,
        "cancellation": op.cancellation,
        "result": op.result,
    })
}

fn decision_view(d: &DecisionRecord, now: Timestamp) -> serde_json::Value {
    let action = match &d.kind {
        DecisionKind::ApproveAuthority { operation, delta } => serde_json::json!({
            "operation_id": operation,
            "delta": delta,
        }),
        DecisionKind::WidenPolicy { action } => serde_json::json!({ "action": action }),
        DecisionKind::ConfirmTime { observed_wall, .. } => {
            serde_json::json!({ "observed_wall": observed_wall })
        }
    };
    serde_json::json!({
        "decision_id": d.id,
        "kind": decision_kind_name(&d.kind),
        "state": d.state,
        "created_at": d.created_at,
        "expires_at": d.expires_at,
        // R7: the store returns pending records past their expiry; the
        // application compares with its own `now`.
        "expired": now >= d.expires_at,
        "request": action,
    })
}

/// Facts the issuer supplies with a certificate request (ADR-0005 §3.5 refusal
/// list items it alone knows). Used at reserve and again at publish. The
/// permitted extensions are **not** a caller fact: they are derived inside the
/// reserve and publish transactions from the grant's resolved scope (ADR-0006
/// §13.5 ruling 3; [`permitted_extensions`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssuanceFacts {
    /// Whether this issuance activates a new grant (pause applies).
    pub new_activation: bool,
    /// The subject key is registered by this environment's signer for the grant.
    pub subject_registered: bool,
    /// A critical option was requested.
    pub critical_option: bool,
}

/// A certificate reservation request (ADR-0005 §3.5 step 1). The serial is drawn
/// by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRequest {
    /// Grant.
    pub grant: GrantId,
    /// Pair.
    pub pair: AccessPair,
    /// Requested principal (must be exactly `hm:<destination>:<account>`).
    pub principal: String,
    /// Key ID.
    pub key_id: String,
    /// Validity start.
    pub valid_after: Timestamp,
    /// Validity end.
    pub valid_before: Timestamp,
    /// Extensions.
    pub extensions: BTreeSet<String>,
    /// Subject key fingerprint.
    pub subject_fingerprint: String,
    /// Issuer-side facts.
    pub facts: IssuanceFacts,
}

impl Operations {
    /// Build. Performs restart recovery before returning (spec §13.3, R-RT-07;
    /// review F05/F07): active operations are re-driven from their last stage
    /// receipt; unresolved (`outcome_unknown`) ones are listed for reconciliation
    /// through the recorded adapter identity and effect token; no deadline is
    /// reset, no pause revived, no effect replayed from a hash or stage marker.
    pub async fn start(config: OperationsConfig) -> Result<Self, crate::OpError> {
        let publisher = EventPublisher::new(config.store.clone(), config.environment.clone())
            .with_clock(config.clock.clone());
        let timegate = TimeGate::new(
            config.store.clone(),
            config.clock.clone(),
            config.time_sync.clone(),
            config.time_policy,
        );
        let slots = config.limits.max_concurrent_adapter_calls.max(1);
        let inner = Inner {
            config,
            publisher,
            timegate,
            singleflight: SingleFlight::new(),
            flights: SingleFlight::with_bound(4096),
            running: AtomicUsize::new(0),
            adapter_slots: tokio::sync::Semaphore::new(slots),
            changed: tokio::sync::Notify::new(),
            reserved_here: Mutex::new(HashMap::new()),
        };
        let ops = Self {
            inner: Arc::new(inner),
        };
        ops.recover_after_restart().await?;
        Ok(ops)
    }

    /// Limits in effect.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.inner.config.limits
    }

    /// Event publisher (used by the IPC server for subscriptions).
    #[must_use]
    pub fn events(&self) -> &EventPublisher {
        &self.inner.publisher
    }

    /// The shared time gate (used by the signer and issuer as well).
    #[must_use]
    pub fn timegate(&self) -> &TimeGate {
        &self.inner.timegate
    }

    /// This runtime's environment ID.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.inner.config.environment
    }

    /// Stage hook in force (production: no-op).
    #[must_use]
    pub fn stage_hook(&self) -> &Arc<dyn StageHook> {
        &self.inner.config.stage_hook
    }

    /// Operations this process is currently driving.
    #[must_use]
    pub fn running_operations(&self) -> usize {
        self.inner.running.load(Ordering::SeqCst)
    }

    // -----------------------------------------------------------------------------
    // Plumbing
    // -----------------------------------------------------------------------------

    fn retention(&self) -> Duration {
        self.inner.config.limits.operation_retention
    }

    fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.inner.config.clock)
    }

    fn adapter_infos(&self) -> Vec<AdapterInfo> {
        self.inner
            .config
            .adapters
            .iter()
            .map(|a| {
                let d = a.descriptor();
                AdapterInfo {
                    identity: d.identity.clone(),
                    capabilities: d.capabilities.clone(),
                    scope_enforcement: d.enforcement.report.destination_scope,
                }
            })
            .collect()
    }

    /// The adapter with exactly the recorded identity (recovery never substitutes
    /// another adapter).
    fn adapter(&self, identity: Option<&AdapterIdentity>) -> Option<Arc<dyn CredentialAdapter>> {
        let identity = identity?;
        self.inner
            .config
            .adapters
            .iter()
            .find(|a| &a.descriptor().identity == identity)
            .cloned()
    }

    /// Run `f` in one store transaction on the blocking pool; announce the events
    /// it appended after the commit and wake bounded waiters.
    async fn write<R, F>(&self, f: F) -> Result<R, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Txn<'_>, &mut Emit) -> heimdall_store::Result<R> + Send + 'static,
    {
        let store = Arc::clone(&self.inner.config.store);
        let publisher = self.inner.publisher.clone();
        let joined = tokio::task::spawn_blocking(move || {
            store.transaction(|tx| {
                let mut emit = Emit {
                    publisher,
                    events: Vec::new(),
                };
                let r = f(tx, &mut emit)?;
                Ok((r, emit.events))
            })
        })
        .await
        .map_err(join_error)?;
        let (r, events) = joined?;
        for e in events {
            self.inner.publisher.announce(e);
        }
        self.inner.changed.notify_waiters();
        Ok(r)
    }

    /// `now` for narrowing actions (pause, cutoff, revoke, release, cancel): the
    /// gate's accepted time, else the raw wall clock. Narrowing only restricts, so
    /// it never waits for safe time.
    async fn narrowing_now(&self) -> Timestamp {
        match self.inner.timegate.check().await {
            Ok(s) => s.wall(),
            Err(_) => self.inner.config.clock.wall(),
        }
    }

    fn hook_before(&self, stage: EnsureStage, effect: EffectStatus) -> Result<(), OpError> {
        self.inner.config.stage_hook.before(stage).map_err(|code| {
            OpError::new(
                code,
                "the operation was interrupted; retry with the same request ID",
            )
            .with_effect(effect)
        })
    }

    fn hook_after(&self, stage: EnsureStage, effect: EffectStatus) -> Result<(), OpError> {
        self.inner.config.stage_hook.after(stage).map_err(|code| {
            OpError::new(
                code,
                "the operation was interrupted; retry with the same request ID",
            )
            .with_effect(effect)
        })
    }

    async fn load_work(&self, id: &OperationId) -> Result<WorkState, OpError> {
        let id = id.clone();
        self.write(move |tx, _| {
            let Some(op) = tx.operation(&id)? else {
                return Ok(None);
            };
            let intent = tx.recovery_intent(&id)?.unwrap_or(RecoveryIntent {
                request: serde_json::Value::Null,
                resolved: None,
            });
            let receipts = tx.stage_receipts(&id)?;
            Ok(Some(WorkState {
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

    // -----------------------------------------------------------------------------
    // Restart recovery
    // -----------------------------------------------------------------------------

    /// Restart recovery (M01-U5). Pure reads plus state-machine transitions;
    /// never re-executes a remote mutation (R-RT-05).
    async fn recover_after_restart(&self) -> Result<(), crate::OpError> {
        let environment = self.inner.config.environment.clone();
        let (open, unresolved) = self
            .write(move |tx, emit| {
                // Identity never changes across a restart (R-RT-07): a different
                // recorded environment ID refuses to start.
                tx.init_self_environment(&environment)?;
                let open = tx.open_operations()?;
                let unresolved = tx.unresolved_operations()?;
                emit.event(
                    tx,
                    EventType::RuntimeLifecycle,
                    None,
                    None,
                    serde_json::json!({
                        "phase": "started",
                        "open_operations": open.len(),
                        "unresolved_operations": unresolved.len(),
                    }),
                )?;
                Ok((open, unresolved))
            })
            .await
            .map_err(|e| {
                if e.code == Code::StateUnavailable {
                    OpError::new(
                        Code::StateUnavailable,
                        "the state store belongs to another environment or is unavailable",
                    )
                    .with_resource("store", None)
                } else {
                    e
                }
            })?;
        for op in open.into_iter().chain(unresolved) {
            if op.environment != self.inner.config.environment {
                continue;
            }
            // Each operation is driven from its own durable state; a failure
            // leaves it where it is (fail closed) for a later retry or restart.
            if let Err(e) = self.lead(&op.id, false).await {
                tracing::warn!(code = %e.code, "restart recovery left an operation unfinished");
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------------
    // Leading and following one operation
    // -----------------------------------------------------------------------------

    /// Drive `id` from its durable state, or follow the in-process driver that
    /// already does.
    async fn lead(&self, id: &OperationId, interactive: bool) -> Result<(), OpError> {
        for _ in 0..3 {
            match self.inner.flights.join_or_lead(id.clone()) {
                Err(_) => {
                    return Err(
                        OpError::new(Code::Backpressure, "too many operations in flight")
                            .with_retry_after(BACKPRESSURE_RETRY_MS),
                    );
                }
                Ok(Flight::Lead(tx)) => {
                    struct Running<'a>(&'a AtomicUsize);
                    impl Drop for Running<'_> {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    self.inner.running.fetch_add(1, Ordering::SeqCst);
                    let guard = Running(&self.inner.running);
                    let r = self.drive(id, interactive).await;
                    drop(guard);
                    let _ = tx.send(Some(r.clone()));
                    self.inner.flights.finish(id);
                    return r;
                }
                Ok(Flight::Follow(rx)) => match follow(rx).await {
                    Ok(r) => return r,
                    Err(_) => continue,
                },
            }
        }
        Err(internal("operation driver did not settle"))
    }

    /// Lead in a spawned task so a caller's timeout or disconnect never stops the
    /// work (spec §11.4: a caller timeout is not cancellation), and wait at most
    /// `wait` for it. `None` when the wait ended first.
    async fn lead_bounded(
        &self,
        id: &OperationId,
        interactive: bool,
        wait: Option<Duration>,
    ) -> Option<Result<(), OpError>> {
        let me = self.clone();
        let id = id.clone();
        let task = tokio::spawn(async move { me.lead(&id, interactive).await });
        let wait = wait?;
        match tokio::time::timeout(wait, task).await {
            Ok(Ok(r)) => Some(r),
            Ok(Err(e)) => Some(Err(join_error(e))),
            Err(_) => None,
        }
    }

    fn bounded_wait(&self, wait: WaitMode) -> Option<Duration> {
        match wait {
            WaitMode::Async => None,
            WaitMode::Sync { timeout_ms } => {
                Some(Duration::from_millis(timeout_ms).min(self.inner.config.limits.max_wait))
            }
        }
    }

    async fn drive(&self, id: &OperationId, interactive: bool) -> Result<(), OpError> {
        let st = self.load_work(id).await?;
        let r = match st.op.kind {
            OperationKind::Ensure | OperationKind::Delegate => {
                let mut local = DriveLocal::default();
                let r = self.drive_work(id, interactive, &mut local).await;
                if let Some((key, tx)) = local.lead.take() {
                    let _ = tx.send(Some(EnsureHandle {
                        operation_id: id.clone(),
                    }));
                    self.inner.singleflight.finish(&key);
                }
                r
            }
            OperationKind::Revoke => self.drive_revoke(id).await,
            OperationKind::Bind => self.drive_bind(id).await,
            _ => Ok(()),
        };
        r.map_err(|e| {
            if e.operation_id.is_none() {
                e.with_operation(id.clone())
            } else {
                e
            }
        })
    }

    // -----------------------------------------------------------------------------
    // The ensure/delegate pipeline
    // -----------------------------------------------------------------------------

    async fn drive_work(
        &self,
        id: &OperationId,
        interactive: bool,
        local: &mut DriveLocal,
    ) -> Result<(), OpError> {
        for _ in 0..MAX_DRIVE_STEPS {
            let st = self.load_work(id).await?;
            let expected = match st.op.state {
                OperationState::Queued | OperationState::Running => OperationState::Running,
                OperationState::OutcomeUnknown => match last_reconcile(&st.receipts) {
                    Some(EffectReceipt::Confirmed { .. }) => OperationState::OutcomeUnknown,
                    _ => {
                        if self.reconcile_unresolved(&st, local).await? == Flow::Stop {
                            return Ok(());
                        }
                        continue;
                    }
                },
                _ => return Ok(()),
            };
            let Some(spec) = st
                .request()
                .and_then(|r| WorkSpec::from_request(&r, &self.inner.config.environment))
            else {
                return Err(internal("the stored request cannot be read"));
            };
            let Some(stage) = next_stage(&st.receipts) else {
                return Ok(());
            };
            self.hook_before(stage, effect_so_far(&st.receipts))?;
            let flow = match stage {
                EnsureStage::Authenticate => self.stage_receipt(id, stage, expected).await?,
                EnsureStage::LoadAuthority => self.stage_load_authority(&st, &spec).await?,
                EnsureStage::ResolveMechanism => self.stage_resolve(&st, &spec).await?,
                EnsureStage::Coalesce => self.stage_coalesce(&st, local).await?,
                EnsureStage::Reconcile => {
                    self.stage_reconcile(&st, &spec, interactive, local).await?
                }
                EnsureStage::Probe => self.stage_receipt(id, stage, expected).await?,
                EnsureStage::Recheck => self.stage_recheck(&st, expected, local).await?,
                EnsureStage::Commit => self.stage_commit(&st, expected, local).await?,
            };
            if flow == Flow::Stop {
                return Ok(());
            }
            // What the receipts now say: committed ⇒ applied; an effect confirmed
            // but not yet activated ⇒ partial.
            let after_effect = if stage == EnsureStage::Commit {
                EffectStatus::Applied
            } else if stage >= EnsureStage::Reconcile && !coalesced(&st.receipts) {
                EffectStatus::Partial
            } else {
                effect_so_far(&st.receipts)
            };
            self.hook_after(stage, after_effect)?;
        }
        Err(internal("the pipeline did not converge"))
    }

    /// A stage with no work of its own (`Probe`: no authorized probes in M01).
    async fn stage_receipt(
        &self,
        id: &OperationId,
        stage: EnsureStage,
        expected: OperationState,
    ) -> Result<Flow, OpError> {
        let id = id.clone();
        let clock = self.clock();
        self.write(move |tx, _| {
            let Some(op) = tx.operation(&id)? else {
                return Ok(Flow::Stop);
            };
            if op.state != expected
                && !(expected == OperationState::Running && op.state == OperationState::Queued)
            {
                return Ok(Flow::Stop);
            }
            tx.append_stage_receipt(
                &id,
                &receipt(stage, clock.wall(), EffectReceipt::NotAttempted),
            )?;
            Ok(Flow::Continue)
        })
        .await
    }

    async fn stage_load_authority(&self, st: &WorkState, spec: &WorkSpec) -> Result<Flow, OpError> {
        let id = st.op.id.clone();
        let spec = spec.clone();
        let own = self.inner.config.environment.clone();
        let clock = self.clock();
        let retention = self.retention();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(Flow::Stop);
            };
            if op.state != OperationState::Queued {
                return Ok(Flow::Stop);
            }
            let now = clock.wall();
            let refusal = if spec.environment != own {
                Some(
                    OpError::new(
                        Code::NotFound,
                        "the environment is not managed by this runtime",
                    )
                    .with_resource("environment", None),
                )
            } else {
                match spec.kind {
                    OperationKind::Delegate => {
                        let found = match &spec.parent_binding {
                            Some(pb) => tx
                                .binding(pb)?
                                .filter(|b| may_act_on(b, &op.key.caller))
                                .is_some(),
                            None => false,
                        };
                        (!found).then(|| {
                            OpError::new(Code::NotFound, "unknown binding")
                                .with_resource("binding", None)
                        })
                    }
                    _ => {
                        let found = match &spec.profile {
                            Some(p) => tx.profile(p)?.is_some(),
                            None => false,
                        };
                        (!found).then(|| {
                            OpError::new(Code::NotFound, "unknown profile")
                                .with_resource("profile", None)
                        })
                    }
                }
            };
            if let Some(err) = refusal {
                settle_failed(tx, emit, &mut op, &err, now, retention)?;
                return Ok(Flow::Stop);
            }
            tx.append_stage_receipt(
                &id,
                &receipt(EnsureStage::LoadAuthority, now, EffectReceipt::NotAttempted),
            )?;
            Ok(Flow::Continue)
        })
        .await
    }

    async fn stage_resolve(&self, st: &WorkState, spec: &WorkSpec) -> Result<Flow, OpError> {
        let safe = self.inner.timegate.check().await?;
        let now = safe.wall();
        let inp = ResolveInput {
            spec: spec.clone(),
            caller: st.op.key.caller.clone(),
            operation: st.op.id.clone(),
            environment: self.inner.config.environment.clone(),
            now,
            default_window: self.inner.config.default_window,
            adapters: self.adapter_infos(),
            grant_id: crate::ids::new_grant_id()?,
        };
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let retention = self.retention();
        let id = st.op.id.clone();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(Flow::Stop);
            };
            if op.state != OperationState::Queued {
                return Ok(Flow::Stop);
            }
            let Some(mut intent) = tx.recovery_intent(&id)? else {
                return Err(conflict("operation has no recovery intent"));
            };
            let resolution = match resolve_in(tx, &inp)? {
                Ok(r) => pin(&inp, r),
                Err(e) => Err(e),
            };
            match resolution {
                Err(err) => {
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    tx.append_stage_receipt(
                        &id,
                        &receipt(
                            EnsureStage::ResolveMechanism,
                            now,
                            EffectReceipt::NotAttempted,
                        ),
                    )?;
                    Ok(Flow::Stop)
                }
                Ok(Resolution::Allowed(resolved)) => {
                    intent.resolved = Some(*resolved);
                    tx.set_recovery_intent(&id, &intent)?;
                    op_to(&mut op, OperationEvent::Start, now)?;
                    tx.update_operation(&op)?;
                    tx.append_stage_receipt(
                        &id,
                        &receipt(
                            EnsureStage::ResolveMechanism,
                            now,
                            EffectReceipt::NotAttempted,
                        ),
                    )?;
                    emit.op(tx, &op)?;
                    Ok(Flow::Continue)
                }
                Ok(Resolution::Approval(approval)) => {
                    let Approval {
                        intent: resolved,
                        mut grant,
                        delta,
                    } = *approval;
                    grant_to(&mut grant, GrantEvent::ApprovalNeeded)?;
                    tx.insert_grant(&grant)?;
                    intent.resolved = Some(resolved.clone());
                    tx.set_recovery_intent(&id, &intent)?;
                    let decision = DecisionRecord {
                        id: decision_id,
                        kind: DecisionKind::ApproveAuthority {
                            operation: id.clone(),
                            delta,
                        },
                        generation: resolved.generation,
                        created_at: now,
                        expires_at: plus(now, lifetime),
                        state: DecisionState::Pending,
                        decided_at: None,
                    };
                    tx.insert_decision(&decision)?;
                    op_to(&mut op, OperationEvent::ApprovalNeeded, now)?;
                    tx.update_operation(&op)?;
                    tx.append_stage_receipt(
                        &id,
                        &receipt(
                            EnsureStage::ResolveMechanism,
                            now,
                            EffectReceipt::NotAttempted,
                        ),
                    )?;
                    emit.grant(tx, &grant, Some(&id))?;
                    emit.decision(tx, &decision, Some(&id))?;
                    emit.op(tx, &op)?;
                    Ok(Flow::Stop)
                }
            }
        })
        .await
    }

    async fn stage_coalesce(
        &self,
        st: &WorkState,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let Some(resolved) = st.intent.resolved.clone() else {
            return Err(internal("operation has no resolved intent"));
        };
        let id = st.op.id.clone();
        if resolved.grant.is_some() {
            // Approved added authority already has its own grant.
            return self
                .stage_receipt(&id, EnsureStage::Coalesce, OperationState::Running)
                .await;
        }
        let key = EquivalenceKey {
            environment: st.op.environment.clone(),
            profile: resolved.profile.clone(),
            profile_revision: resolved.profile_revision,
            scope: resolved.scope.clone(),
            mechanism: resolved
                .adapter
                .as_ref()
                .map(|a| a.mechanism.clone())
                .unwrap_or_default(),
            deadline: resolved.deadline.effective.to_string(),
        };
        let leader = match self.inner.singleflight.join_or_lead(key.clone()) {
            Err(_) => {
                return Err(
                    OpError::new(Code::Backpressure, "too much equivalent work in flight")
                        .with_retry_after(BACKPRESSURE_RETRY_MS),
                );
            }
            Ok(Flight::Lead(tx)) => {
                local.lead = Some((key, tx));
                None
            }
            Ok(Flight::Follow(rx)) => follow(rx).await.ok().map(|h| h.operation_id),
        };
        let clock = self.clock();
        let attached: Option<EnsureData> = self
            .write(move |tx, _| {
                let Some(op) = tx.operation(&id)? else {
                    return Ok(None);
                };
                if op.state != OperationState::Running {
                    return Ok(None);
                }
                let now = clock.wall();
                // Separate references to an equivalent leader's result (spec §8.2):
                // only an identical, still-usable grant of the same generation.
                let mut attach: Option<(GrantId, EnsureData)> = None;
                if let Some(leader) = &leader
                    && let Some(lop) = tx.operation(leader)?
                    && lop.state == OperationState::Succeeded
                    && let Some(lintent) = tx.recovery_intent(leader)?.and_then(|i| i.resolved)
                    && let Some(gid) = lintent.grant.clone()
                    && let Some(g) = tx.grant(&gid)?
                    && g.state.permits_use()
                    && g.generation == resolved.generation
                    && g.scope == resolved.scope
                    && g.deadline.effective == resolved.deadline.effective
                    && let Some(data) = lop
                        .result
                        .clone()
                        .and_then(|v| serde_json::from_value::<EnsureData>(v).ok())
                {
                    attach = Some((gid, data));
                }
                match attach {
                    Some((gid, data)) => {
                        let mut intent = tx
                            .recovery_intent(&id)?
                            .ok_or_else(|| conflict("operation has no recovery intent"))?;
                        if let Some(r) = intent.resolved.as_mut() {
                            r.grant = Some(gid);
                        }
                        tx.set_recovery_intent(&id, &intent)?;
                        tx.append_stage_receipt(
                            &id,
                            &receipt(EnsureStage::Coalesce, now, EffectReceipt::NotAttempted),
                        )?;
                        tx.append_stage_receipt(
                            &id,
                            &receipt(EnsureStage::Reconcile, now, EffectReceipt::NotAttempted),
                        )?;
                        Ok(Some(data))
                    }
                    None => {
                        tx.append_stage_receipt(
                            &id,
                            &receipt(EnsureStage::Coalesce, now, EffectReceipt::NotAttempted),
                        )?;
                        Ok(None)
                    }
                }
            })
            .await?;
        local.leader_data = attached;
        Ok(Flow::Continue)
    }

    /// Fail a running operation before any effect was attempted.
    async fn fail_running(
        &self,
        id: &OperationId,
        err: OpError,
        grant_event: Option<GrantEvent>,
    ) -> Result<Flow, OpError> {
        let id = id.clone();
        let clock = self.clock();
        let retention = self.retention();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(Flow::Stop);
            };
            if !matches!(
                op.state,
                OperationState::Running | OperationState::OutcomeUnknown
            ) {
                return Ok(Flow::Stop);
            }
            let now = clock.wall();
            if let Some(ev) = grant_event
                && let Some(gid) = tx
                    .recovery_intent(&id)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.grant)
                && let Some(mut g) = tx.grant(&gid)?
                && grant_try(&mut g, ev)
            {
                put_grant(tx, emit, &g, Some(&id))?;
            }
            settle_failed(tx, emit, &mut op, &err, now, retention)?;
            Ok(Flow::Stop)
        })
        .await
    }

    /// Record that the effect's outcome is unknown: `Uncertain` receipt, operation
    /// `outcome_unknown` (quiescent, not settled; its key never expires).
    async fn mark_uncertain(
        &self,
        id: &OperationId,
        adapter: AdapterIdentity,
        token: String,
    ) -> Result<Flow, OpError> {
        let id = id.clone();
        let clock = self.clock();
        self.write(move |tx, emit| {
            let now = clock.wall();
            tx.append_stage_receipt(
                &id,
                &receipt(
                    EnsureStage::Reconcile,
                    now,
                    EffectReceipt::Uncertain {
                        adapter,
                        effect_token: token,
                    },
                ),
            )?;
            let Some(mut op) = tx.operation(&id)? else {
                return Ok(Flow::Stop);
            };
            if op.state == OperationState::Running {
                op_to(&mut op, OperationEvent::EffectUncertain, now)?;
                let err = OpError::new(
                    Code::OutcomeUnknown,
                    "the credential effect may or may not have applied; it will be reconciled",
                )
                .with_operation(id.clone());
                op.code = Some(Code::OutcomeUnknown);
                op.effect_status = EffectStatus::Unknown;
                op.result = Some(serde_json::json!({ "error": err.detail() }));
                tx.update_operation(&op)?;
                emit.op(tx, &op)?;
            }
            Ok(Flow::Stop)
        })
        .await
    }

    /// Ask the recorded adapter what happened to an uncertain effect; settle or
    /// re-arm accordingly. Never calls `prepare`.
    async fn reconcile_unresolved(
        &self,
        st: &WorkState,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let id = st.op.id.clone();
        let Some(resolved) = st.intent.resolved.clone() else {
            return Ok(Flow::Stop);
        };
        let (Some(grant), Some(token)) = (resolved.grant.clone(), last_token(&st.receipts)) else {
            return Ok(Flow::Stop);
        };
        let Some(identity) = resolved.adapter.clone() else {
            return Ok(Flow::Stop);
        };
        let Some(adapter) = self.adapter(Some(&identity)) else {
            // The recorded adapter is not configured: stays unresolved.
            return Ok(Flow::Stop);
        };
        self.hook_before(EnsureStage::Reconcile, EffectStatus::Unknown)?;
        let outcome = {
            let _slot = self
                .inner
                .adapter_slots
                .acquire()
                .await
                .map_err(|_| internal("adapter slots closed"))?;
            adapter.reconcile(&grant, &token).await
        };
        match outcome {
            Ok(ReconcileOutcome::Applied(o)) => {
                let credential_ref = o.credential_ref.clone();
                local.prepared = Some(o);
                let clock = self.clock();
                let id2 = id.clone();
                self.write(move |tx, _| {
                    tx.append_stage_receipt(
                        &id2,
                        &receipt(
                            EnsureStage::Reconcile,
                            clock.wall(),
                            EffectReceipt::Confirmed {
                                adapter: identity,
                                credential_ref,
                            },
                        ),
                    )?;
                    Ok(())
                })
                .await?;
                self.hook_after(EnsureStage::Reconcile, EffectStatus::Partial)?;
                Ok(Flow::Continue)
            }
            Ok(ReconcileOutcome::NotApplied) => {
                // Established: nothing happened. The lifecycle has no edge back to
                // `running`, so the operation fails truthfully with no effect; a new
                // request ID performs the work afresh.
                let err = OpError::new(
                    Code::ServiceUnavailable,
                    "reconciliation established that the credential effect did not apply; retry with a new request ID",
                )
                .with_effect(EffectStatus::None)
                // `new_request_id`: this key's work is settled.
                .with_next(NextAction::for_code(Code::RequestExpired));
                self.fail_running(&id, err, Some(GrantEvent::PreparationFailed))
                    .await
            }
            Ok(ReconcileOutcome::Unknown) | Err(_) => Ok(Flow::Stop),
        }
    }

    async fn stage_reconcile(
        &self,
        st: &WorkState,
        spec: &WorkSpec,
        interactive: bool,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let id = st.op.id.clone();
        if st.op.state != OperationState::Running {
            return Ok(Flow::Stop);
        }
        let Some(resolved) = st.intent.resolved.clone() else {
            return Err(internal("operation has no resolved intent"));
        };
        let identity = resolved.adapter.clone();
        let adapter = self.adapter(identity.as_ref());
        // 1. The grant exists before any effect (Requested → Preparing).
        let grant_id = match resolved.grant.clone() {
            Some(g) => g,
            None => {
                let gid = crate::ids::new_grant_id()?;
                let id2 = id.clone();
                let clock = self.clock();
                let parent_binding = spec.parent_binding.clone();
                let created = self
                    .write(move |tx, emit| {
                        let Some(op) = tx.operation(&id2)? else {
                            return Ok(None);
                        };
                        if op.state != OperationState::Running {
                            return Ok(None);
                        }
                        let mut intent = tx
                            .recovery_intent(&id2)?
                            .ok_or_else(|| conflict("operation has no recovery intent"))?;
                        let Some(r) = intent.resolved.clone() else {
                            return Err(conflict("operation has no resolved intent"));
                        };
                        let parent = match &parent_binding {
                            Some(pb) => tx.binding(pb)?.map(|b| b.grant),
                            None => None,
                        };
                        let source = match (&parent, r.policy_revision) {
                            (Some(p), _) => AuthorizationSource::Delegation { parent: p.clone() },
                            (None, Some(revision)) => {
                                AuthorizationSource::StandingPolicy { revision }
                            }
                            (None, None) => AuthorizationSource::OwnerDecision {
                                operation_id: id2.clone(),
                            },
                        };
                        let mut g = GrantSnapshot {
                            id: gid.clone(),
                            environment: op.environment.clone(),
                            scope: r.scope.clone(),
                            starts_at: clock.wall(),
                            deadline: r.deadline.clone(),
                            parent,
                            source,
                            generation: r.generation,
                            state: GrantState::Requested,
                            enforcement: EnforcementEvidence::unknown(),
                        };
                        grant_to(&mut g, GrantEvent::Authorized)?;
                        tx.insert_grant(&g)?;
                        if let Some(rr) = intent.resolved.as_mut() {
                            rr.grant = Some(gid.clone());
                        }
                        tx.set_recovery_intent(&id2, &intent)?;
                        emit.grant(tx, &g, Some(&id2))?;
                        Ok(Some(gid))
                    })
                    .await?;
                match created {
                    Some(g) => g,
                    None => return Ok(Flow::Stop),
                }
            }
        };
        // 2. Effect state from the receipts.
        if let Some(EffectReceipt::Attempted {
            adapter: recorded,
            effect_token,
        }) = last_reconcile(&st.receipts)
        {
            // Only the adapter identity recorded with the attempt may reconcile it;
            // without that adapter the outcome stays unknown (never re-prepared
            // through another adapter).
            let identity = recorded.clone();
            let Some(adapter) = self.adapter(Some(recorded)) else {
                return self
                    .mark_uncertain(&id, identity, effect_token.clone())
                    .await;
            };
            let outcome = {
                let _slot = self
                    .inner
                    .adapter_slots
                    .acquire()
                    .await
                    .map_err(|_| internal("adapter slots closed"))?;
                adapter.reconcile(&grant_id, effect_token).await
            };
            match outcome {
                Ok(ReconcileOutcome::Applied(o)) => {
                    return self.confirm(&id, identity, o, &grant_id, local).await;
                }
                Ok(ReconcileOutcome::NotApplied) => {} // a fresh attempt is safe
                Ok(ReconcileOutcome::Unknown) | Err(_) => {
                    return self
                        .mark_uncertain(&id, identity, effect_token.clone())
                        .await;
                }
            }
        }
        let (Some(adapter), Some(identity)) = (adapter, identity) else {
            return self
                .fail_running(
                    &id,
                    OpError::new(
                        Code::CapabilityUnavailable,
                        "the selected credential mechanism is no longer configured",
                    ),
                    Some(GrantEvent::PreparationFailed),
                )
                .await;
        };
        // 3. Fresh attempt: safe time, token, `Attempted` receipt, then prepare.
        let safe = self.inner.timegate.check().await?;
        let token = crate::ids::new_effect_token()?;
        let id2 = id.clone();
        let gid = grant_id.clone();
        let ident = identity.clone();
        let tok = token.clone();
        let retention = self.retention();
        let now = safe.wall();
        let grant = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok(None);
                };
                if op.state != OperationState::Running {
                    return Ok(None);
                }
                let Some(g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                if g.state != GrantState::Preparing {
                    // Revoked, expired or cancelled before any effect.
                    let err = match g.state {
                        GrantState::Revoked | GrantState::Revoking => {
                            authority_changed("the grant was revoked")
                        }
                        GrantState::Expired => {
                            OpError::new(Code::CredentialExpired, "the grant reached its deadline")
                        }
                        _ => authority_changed("the grant is no longer usable"),
                    };
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    return Ok(None);
                }
                tx.append_stage_receipt(
                    &id2,
                    &receipt(
                        EnsureStage::Reconcile,
                        now,
                        EffectReceipt::Attempted {
                            adapter: ident,
                            effect_token: tok,
                        },
                    ),
                )?;
                Ok(Some(g))
            })
            .await?;
        let Some(grant) = grant else {
            return Ok(Flow::Stop);
        };
        let interactive = interactive && spec.interactive;
        let result = {
            let _slot = self
                .inner
                .adapter_slots
                .acquire()
                .await
                .map_err(|_| internal("adapter slots closed"))?;
            adapter
                .prepare(PrepareRequest {
                    grant: &grant,
                    scope: &grant.scope,
                    required: &spec.required,
                    interactive,
                    effect_token: &token,
                    now: self.inner.config.clock.wall(),
                })
                .await
        };
        match result {
            Ok(o) => self.confirm(&id, identity, o, &grant_id, local).await,
            Err(AdapterError::OutcomeUnknown(_)) => self.mark_uncertain(&id, identity, token).await,
            Err(e) => {
                self.fail_running(&id, OpError::from(e), Some(GrantEvent::PreparationFailed))
                    .await
            }
        }
    }

    /// Write the `Confirmed` receipt for an applied effect; if the operation left
    /// `running` meanwhile (cancelled, or its grant revoked), the receipt still
    /// records the truth and the credential is cleaned up.
    async fn confirm(
        &self,
        id: &OperationId,
        identity: AdapterIdentity,
        o: PrepareOutcome,
        grant: &GrantId,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let id2 = id.clone();
        let clock = self.clock();
        let credential_ref = o.credential_ref.clone();
        let still_running = self
            .write(move |tx, _| {
                tx.append_stage_receipt(
                    &id2,
                    &receipt(
                        EnsureStage::Reconcile,
                        clock.wall(),
                        EffectReceipt::Confirmed {
                            adapter: identity,
                            credential_ref,
                        },
                    ),
                )?;
                Ok(tx
                    .operation(&id2)?
                    .is_some_and(|op| op.state == OperationState::Running))
            })
            .await?;
        if !still_running {
            self.cleanup(grant).await;
            return Ok(Flow::Stop);
        }
        local.prepared = Some(o);
        Ok(Flow::Continue)
    }

    /// Best-effort local revocation of a credential prepared for an activation
    /// that did not happen (cancelled, revoked, expired or refused at commit).
    async fn cleanup(&self, grant: &GrantId) {
        let now = self.inner.config.clock.wall();
        for a in &self.inner.config.adapters {
            let _ = a.revoke(grant, now).await;
        }
    }

    async fn stage_recheck(
        &self,
        st: &WorkState,
        expected: OperationState,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let safe = self.inner.timegate.check().await?;
        let id = st.op.id.clone();
        let env = self.inner.config.environment.clone();
        let attached = coalesced(&st.receipts);
        let effect = if attached {
            EffectStatus::None
        } else {
            effect_so_far(&st.receipts)
        };
        let retention = self.retention();
        let adapters = self.adapter_infos();
        let now = safe.wall();
        let outcome = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id)? else {
                    return Ok(None);
                };
                if op.state != expected {
                    return Ok(None);
                }
                let Some(resolved) = tx.recovery_intent(&id)?.and_then(|i| i.resolved) else {
                    return Err(conflict("operation has no resolved intent"));
                };
                let Some(gid) = resolved.grant.clone() else {
                    return Err(conflict("operation has no grant"));
                };
                let Some(mut g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                if let Some(refusal) =
                    activation_refusal(tx, &env, &adapters, &resolved, &g, now, attached)?
                {
                    if !attached
                        && let Some(ev) = refusal.grant_event
                        && grant_try(&mut g, ev)
                    {
                        put_grant(tx, emit, &g, Some(&id))?;
                    }
                    let err = refusal.error.with_effect(effect);
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    return Ok(Some(Err(gid)));
                }
                let ancestors = ancestry(tx, &g)?;
                let policies = tx.policies_for(&resolved.profile, &env)?;
                let bound = grant_bound(&g, &ancestors, merged_policy(&policies, now).as_ref());
                let bound = anchor_bound(tx, &gid, bound)?;
                tx.append_stage_receipt(
                    &id,
                    &receipt(EnsureStage::Recheck, now, EffectReceipt::NotAttempted),
                )?;
                Ok(Some(Ok((gid, bound))))
            })
            .await?;
        match outcome {
            None => Ok(Flow::Stop),
            Some(Err(gid)) => {
                if !attached && effect != EffectStatus::None {
                    self.cleanup(&gid).await;
                }
                Ok(Flow::Stop)
            }
            Some(Ok((gid, bound))) => {
                // Activation anchor (ADR-0005 §3.6), cut by the accepted tolerance.
                self.inner.timegate.anchor_grant(&gid, &safe, bound).await?;
                local.safe = Some(safe);
                local.bound = Some(bound);
                Ok(Flow::Continue)
            }
        }
    }

    async fn stage_commit(
        &self,
        st: &WorkState,
        expected: OperationState,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let id = st.op.id.clone();
        let attached = coalesced(&st.receipts);
        let Some(resolved) = st.intent.resolved.clone() else {
            return Err(internal("operation has no resolved intent"));
        };
        let Some(gid) = resolved.grant.clone() else {
            return Err(internal("operation has no grant"));
        };
        let env = self.inner.config.environment.clone();
        // Safe time and the activation anchor from `Recheck`; re-derived after a
        // restart between the two stages.
        let (safe, bound) = match (local.safe.clone(), local.bound) {
            (Some(s), Some(b)) => (s, b),
            _ => {
                let s = self.inner.timegate.check().await?;
                let gid2 = gid.clone();
                let env2 = env.clone();
                let r2 = resolved.clone();
                let now = s.wall();
                let b = self
                    .write(move |tx, _| {
                        let Some(g) = tx.grant(&gid2)? else {
                            return Err(conflict("grant missing"));
                        };
                        let ancestors = ancestry(tx, &g)?;
                        let policies = tx.policies_for(&r2.profile, &env2)?;
                        let bound =
                            grant_bound(&g, &ancestors, merged_policy(&policies, now).as_ref());
                        anchor_bound(tx, &gid2, bound)
                    })
                    .await?;
                self.inner.timegate.anchor_grant(&gid, &s, b).await?;
                (s, b)
            }
        };
        // The prepared facts: this drive's outcome, the leader's for an attached
        // binding, or the recorded adapter's reconciliation after a restart.
        let facts: Option<Facts> = if attached {
            local.leader_data.as_ref().map(Facts::from_data)
        } else if let Some(o) = &local.prepared {
            Some(Facts::from_outcome(o))
        } else {
            let token = last_token(&st.receipts);
            let adapter = self.adapter(resolved.adapter.as_ref());
            match (adapter, token) {
                (Some(a), Some(t)) => {
                    let r = {
                        let _slot = self
                            .inner
                            .adapter_slots
                            .acquire()
                            .await
                            .map_err(|_| internal("adapter slots closed"))?;
                        a.reconcile(&gid, &t).await
                    };
                    match r {
                        Ok(ReconcileOutcome::Applied(o)) => Some(Facts::from_outcome(&o)),
                        Ok(ReconcileOutcome::NotApplied) => {
                            return self
                                .fail_running(
                                    &id,
                                    OpError::new(
                                        Code::ServiceUnavailable,
                                        "the prepared credential is no longer present",
                                    ),
                                    Some(GrantEvent::PreparationFailed),
                                )
                                .await;
                        }
                        Ok(ReconcileOutcome::Unknown) | Err(_) => {
                            return Err(OpError::new(
                                Code::ServiceUnavailable,
                                "the credential adapter could not confirm the prepared credential",
                            )
                            .with_effect(EffectStatus::Partial));
                        }
                    }
                }
                _ => None,
            }
        };
        let binding_id = crate::ids::new_binding_id()?;
        let clock = self.clock();
        let retention = self.retention();
        let effect = if attached {
            EffectStatus::None
        } else {
            EffectStatus::Partial
        };
        let parent_binding = st
            .request()
            .and_then(|r| WorkSpec::from_request(&r, &env))
            .and_then(|s| s.parent_binding);
        let mechanism = resolved
            .adapter
            .as_ref()
            .map(|a| a.mechanism.clone())
            .unwrap_or_default();
        let adapters = self.adapter_infos();
        let outcome = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id)? else {
                    return Ok(None);
                };
                if op.state != expected {
                    return Ok(None);
                }
                let now = safe.wall();
                let Some(mut g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                let refusal =
                    match activation_refusal(tx, &env, &adapters, &resolved, &g, now, attached)? {
                        Some(r) => Some(r),
                        None => {
                            // Continuous admission of the persisted anchor at the
                            // accepted observation and at a fresh reading (stricter).
                            match tx.grant_anchor(&gid)? {
                                None => Some(Refusal::new(
                                    OpError::new(
                                        Code::TimeUncertain,
                                        "time uncertain: the grant has no anchor in this boot",
                                    )
                                    .with_resource("clock", None),
                                    None,
                                )),
                                Some(anchor) => {
                                    let a1 = dtime::admission(&anchor, &safe.anchor);
                                    let a2 = dtime::admission(&anchor, &clock.observe());
                                    if a1 == Admission::Expired || a2 == Admission::Expired {
                                        Some(Refusal::new(
                                            OpError::new(
                                                Code::CredentialExpired,
                                                "the grant reached its deadline",
                                            )
                                            .with_resource("grant", Some(gid.to_string())),
                                            Some(GrantEvent::DeadlineReached),
                                        ))
                                    } else if a1 == Admission::NeedsAnchor
                                        || a2 == Admission::NeedsAnchor
                                    {
                                        // Another boot since the anchor: retry later.
                                        return Ok(Some(Err(None)));
                                    } else {
                                        None
                                    }
                                }
                            }
                        }
                    };
                if let Some(refusal) = refusal {
                    if refusal.error.code == Code::TimeUncertain {
                        return Ok(Some(Err(None)));
                    }
                    if !attached
                        && let Some(ev) = refusal.grant_event
                        && grant_try(&mut g, ev)
                    {
                        put_grant(tx, emit, &g, Some(&id))?;
                    }
                    let err = refusal.error.with_effect(effect);
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    return Ok(Some(Err(Some(gid))));
                }
                let facts = facts.unwrap_or_else(|| Facts::conservative(&g, now));
                if g.state == GrantState::Preparing {
                    grant_to(&mut g, GrantEvent::Prepared)?;
                    g.enforcement = EnforcementEvidence {
                        report: facts.enforcement.clone(),
                        evidence: Vec::new(),
                    };
                    put_grant(tx, emit, &g, Some(&id))?;
                }
                let binding = BindingRecord {
                    id: binding_id.clone(),
                    environment: op.environment.clone(),
                    grant: gid.clone(),
                    work_id: match tx
                        .recovery_intent(&id)?
                        .and_then(|i| serde_json::from_value::<Request>(i.request).ok())
                    {
                        Some(Request::Ensure(r)) => r.work_id,
                        Some(Request::Delegate(r)) => r.work_id,
                        _ => return Err(conflict("operation request is unreadable")),
                    },
                    owner: op.key.caller.clone(),
                    profile: resolved.profile.clone(),
                    profile_revision: resolved.profile_revision,
                    scope: resolved.scope.clone(),
                    mechanism: mechanism.clone(),
                    parent: parent_binding.clone(),
                    created_at: now,
                    released_at: None,
                    state: BindingState::Active,
                };
                tx.insert_binding(&binding)?;
                // ADR-0006 §13.5 ruling 1: a delegated child holds an
                // ownership-aware reference on its parent, owned by the child grant
                // (keyed by the child's binding; dropped in `put_grant` when the
                // child reaches a terminal state), so releasing the parent's
                // consumers cannot end it while the child is live.
                if let Some(parent_grant) = g.parent.clone() {
                    tx.add_grant_reference(&heimdall_domain::grant::GrantReference {
                        binding: binding_id.clone(),
                        grant: parent_grant,
                        acquired_at: now,
                    })?;
                }
                let mut intent = tx
                    .recovery_intent(&id)?
                    .ok_or_else(|| conflict("operation has no recovery intent"))?;
                if let Some(r) = intent.resolved.as_mut() {
                    r.binding = Some(binding_id.clone());
                }
                tx.set_recovery_intent(&id, &intent)?;
                let data = ensure_data(&binding, &g, &facts, bound);
                let value = serde_json::to_value(&data)?;
                settle_succeeded(tx, emit, &mut op, Code::AccessReady, value, now, retention)?;
                tx.append_stage_receipt(
                    &id,
                    &receipt(EnsureStage::Commit, now, EffectReceipt::NotAttempted),
                )?;
                Ok(Some(Ok(())))
            })
            .await?;
        match outcome {
            None => Ok(Flow::Stop),
            Some(Ok(())) => Ok(Flow::Continue),
            Some(Err(None)) => Err(OpError::new(
                Code::TimeUncertain,
                "time uncertain: the grant must be re-anchored before activation",
            )
            .with_resource("clock", None)),
            Some(Err(Some(gid))) => {
                if !attached {
                    self.cleanup(&gid).await;
                }
                Ok(Flow::Stop)
            }
        }
    }

    // -----------------------------------------------------------------------------
    // Admission of a request (idempotency) and rendering
    // -----------------------------------------------------------------------------

    /// Classify and, for a new key, insert the operation, its idempotency record,
    /// its recovery intent and its `Authenticate` receipt in **one** transaction.
    #[allow(clippy::too_many_arguments)]
    async fn admit(
        &self,
        key: IdempotencyKey,
        hash: heimdall_contract::canonical::RequestHash,
        kind: OperationKind,
        effect_class: EffectClass,
        request: serde_json::Value,
        now: Timestamp,
        pipeline: bool,
    ) -> Result<IdempotencyOutcome, OpError> {
        let key_hash = key
            .hash()
            .map_err(|_| internal("the idempotency key cannot be hashed"))?;
        let id = crate::ids::new_operation_id()?;
        let new_id = id.clone();
        let environment = self.inner.config.environment.clone();
        let allow_new = self.inner.running.load(Ordering::SeqCst)
            < self.inner.config.limits.max_running_operations;
        let outcome = self
            .write(move |tx, emit| {
                let record = tx.idempotency_record(&key)?;
                // R7: the marker is returned whatever its age; `classify` compares
                // `marker_until` with `now`.
                let marker = tx.expired_key_marker(&key_hash)?;
                let outcome = classify(record.as_ref(), marker.as_ref(), hash, now);
                if outcome != IdempotencyOutcome::New {
                    return Ok(Some(outcome));
                }
                if !allow_new {
                    return Ok(None);
                }
                let op = OperationRecord {
                    id: id.clone(),
                    kind,
                    environment,
                    key: key.clone(),
                    request_hash: hash,
                    effect_class,
                    state: OperationState::Queued,
                    code: None,
                    effect_status: EffectStatus::None,
                    result: None,
                    created_at: now,
                    updated_at: now,
                    cancellation: None,
                    recovery: RecoveryMetadata::default(),
                };
                let idem = IdempotencyRecord {
                    key,
                    request_hash: hash,
                    operation_id: id.clone(),
                    created_at: now,
                    expires_at: None,
                };
                tx.insert_operation(&op, &idem)?;
                tx.set_recovery_intent(
                    &id,
                    &RecoveryIntent {
                        request,
                        resolved: None,
                    },
                )?;
                if pipeline {
                    tx.append_stage_receipt(
                        &id,
                        &receipt(EnsureStage::Authenticate, now, EffectReceipt::NotAttempted),
                    )?;
                }
                emit.op(tx, &op)?;
                Ok(Some(IdempotencyOutcome::New))
            })
            .await?;
        let outcome = outcome.ok_or_else(|| {
            OpError::new(Code::Backpressure, "too many operations are running")
                .with_retry_after(BACKPRESSURE_RETRY_MS)
        })?;
        Ok(match outcome {
            IdempotencyOutcome::New => IdempotencyOutcome::Replay(new_id),
            other => other,
        })
    }

    fn refuse_outcome(outcome: &IdempotencyOutcome) -> Option<OpError> {
        match outcome {
            IdempotencyOutcome::Conflict(op) => Some(
                OpError::new(
                    Code::RequestConflict,
                    "this request ID was already used with different parameters",
                )
                .with_resource("operation", Some(op.to_string()))
                .with_operation(op.clone()),
            ),
            IdempotencyOutcome::Expired => Some(OpError::new(
                Code::RequestExpired,
                "this request ID's retention has expired; use a new request ID",
            )),
            _ => None,
        }
    }

    /// Run a work request (`ensure`/`delegate`) through admission, the pipeline
    /// and the caller's bounded wait.
    #[allow(clippy::too_many_arguments)]
    async fn run_work(
        &self,
        caller: &Caller,
        kind: OperationKind,
        request: Request,
        hash: heimdall_contract::canonical::RequestHash,
        request_id: heimdall_contract::ids::RequestId,
        wait: WaitMode,
    ) -> OpResult<EnsureData> {
        let safe = self.inner.timegate.check().await?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id,
        };
        self.hook_before(EnsureStage::Authenticate, EffectStatus::None)?;
        let request_json =
            serde_json::to_value(&request).map_err(|_| internal("request is not serializable"))?;
        let outcome = self
            .admit(
                key,
                hash,
                kind,
                EffectClass::LocalResources,
                request_json,
                safe.wall(),
                true,
            )
            .await?;
        if let Some(e) = Self::refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        self.hook_after(EnsureStage::Authenticate, EffectStatus::None)
            .map_err(|e| e.with_operation(id.clone()))?;
        let interactive = caller.interaction == InteractionMode::Interactive;
        if let Some(Err(e)) = self
            .lead_bounded(&id, interactive, self.bounded_wait(wait))
            .await
        {
            return Err(e);
        }
        self.respond_work(&id, caller).await
    }

    /// The caller's view of a work operation's current durable state.
    async fn respond_work(&self, id: &OperationId, caller: &Caller) -> OpResult<EnsureData> {
        let st = self.load_work(id).await?;
        if st.op.state == OperationState::AwaitingApproval {
            return Err(self.awaiting_response(id, caller).await);
        }
        let done = render_settled::<EnsureData>(&st.op)?;
        Ok(Completed {
            next: Some(NextAction {
                action: "use_binding".to_owned(),
                binding_id: Some(done.data.binding_id.clone()),
                ..NextAction::default()
            }),
            ..done
        })
    }

    /// An operation waiting for an owner decision: the current `decision_ref`, a
    /// fresh one when the pending record expired (ADR-0006 §13.3), or the failure
    /// when the grant reached its deadline or the authority generation moved.
    async fn awaiting_response(&self, id: &OperationId, caller: &Caller) -> OpError {
        let now = match self.inner.timegate.check().await {
            Ok(s) => s.wall(),
            Err(e) => return e.with_operation(id.clone()),
        };
        let decision_id = match crate::ids::new_decision_id() {
            Ok(d) => d,
            Err(e) => return OpError::from(e),
        };
        let lifetime = self.inner.config.limits.decision_lifetime;
        let retention = self.retention();
        let id2 = id.clone();
        let attended = caller.is_attended();
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let r = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown operation")));
                };
                if op.state != OperationState::AwaitingApproval {
                    return Ok(Ok(None));
                }
                let Some(resolved) = tx.recovery_intent(&id2)?.and_then(|i| i.resolved) else {
                    return Err(conflict("operation has no resolved intent"));
                };
                let grant = match &resolved.grant {
                    Some(g) => tx.grant(g)?,
                    None => None,
                };
                let current = tx.authority_generation()?;
                // Nothing waits past its deadline (spec §11.3; §13.3).
                let expired = dtime::is_expired(now, resolved.deadline.effective)
                    || grant.as_ref().is_some_and(|g| g.state == GrantState::Expired);
                // ADR-0006 §13.5 ruling 2: a moved generation re-validates the
                // waiting grant silently; only a change touching it is stale.
                let generation_stale = current != resolved.generation
                    && match &grant {
                        Some(g) => revalidate_chain(tx, &env, &adapters, g, now)?.is_err(),
                        None => true,
                    };
                let stale = generation_stale
                    || grant.as_ref().is_some_and(|g| g.state.is_terminal());
                if expired || stale {
                    let (err, ev) = if expired {
                        (
                            OpError::new(Code::CredentialExpired, "the requested grant reached its deadline while awaiting approval")
                                .with_resource("grant", resolved.grant.as_ref().map(ToString::to_string)),
                            GrantEvent::DeadlineReached,
                        )
                    } else {
                        (
                            authority_changed("the authority generation changed while the request awaited approval"),
                            GrantEvent::DecisionDenied,
                        )
                    };
                    if let Some(mut g) = grant
                        && grant_try(&mut g, ev)
                    {
                        put_grant(tx, emit, &g, Some(&id2))?;
                    }
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    return Ok(Err(err.with_operation(id2.clone())));
                }
                let mine: Vec<DecisionRecord> = tx
                    .pending_decisions()?
                    .into_iter()
                    .filter(|d| matches!(&d.kind, DecisionKind::ApproveAuthority { operation, .. } if operation == &id2))
                    .collect();
                // R7: compare expiry and generation ourselves.
                if let Some(valid) = mine
                    .iter()
                    .rev()
                    .find(|d| now < d.expires_at && d.generation == current)
                {
                    return Ok(Ok(Some(valid.id.clone())));
                }
                // The earlier record expired or went stale (an unrelated
                // authority change; ADR-0006 §13.5 ruling 2): issue a fresh one
                // for the delta the waiting grant still needs.
                let kind = match mine.last() {
                    Some(previous) => previous.kind.clone(),
                    None => match &grant {
                        Some(g) => match current_delta(tx, &env, &adapters, g, now)? {
                            Some(delta) => DecisionKind::ApproveAuthority {
                                operation: id2.clone(),
                                delta,
                            },
                            None => {
                                return Err(conflict(
                                    "awaiting operation has no decision on record",
                                ));
                            }
                        },
                        None => {
                            return Err(conflict("awaiting operation has no decision on record"));
                        }
                    },
                };
                let fresh = DecisionRecord {
                    id: decision_id,
                    kind,
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&fresh)?;
                emit.decision(tx, &fresh, Some(&id2))?;
                Ok(Ok(Some(fresh.id)))
            })
            .await;
        match r {
            Err(e) => e.with_operation(id.clone()),
            Ok(Err(e)) => e,
            Ok(Ok(None)) => OpError::new(
                Code::Accepted,
                "the operation is no longer awaiting approval; observe it",
            )
            .with_operation(id.clone()),
            Ok(Ok(Some(dec))) => approval_needed(
                attended,
                dec.as_str(),
                "the request needs additional owner authority",
            )
            .with_resource("decision", Some(dec.to_string()))
            .with_operation(id.clone()),
        }
    }

    // -----------------------------------------------------------------------------
    // Public primitives
    // -----------------------------------------------------------------------------

    /// Promote a session to attended. Only sessions that declared `interactive`
    /// may attend (ADR-0006 §3.1); others get `INTERACTION_REQUIRED`. Returns the
    /// attendance the session now has.
    pub async fn attend(&self, caller: &Caller) -> OpResult<Attendance> {
        if !caller.may_attend() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "only a session that declared interactive may attend",
            ));
        }
        Ok(Completed::ok(
            Code::Ok,
            Attendance::Attended {
                since: self.inner.config.clock.wall(),
            },
        ))
    }

    /// `inspect` (read-only, passive; spec §10.2).
    pub async fn inspect(
        &self,
        caller: &Caller,
        req: InspectRequest,
    ) -> OpResult<serde_json::Value> {
        let mut warnings = Vec::new();
        // Passive reads continue with a warning while time is uncertain (spec §6.4).
        let now = match self.inner.timegate.peek().await {
            Ok(dtime::TimeStatus::Safe) => self.inner.config.clock.wall(),
            Ok(dtime::TimeStatus::Uncertain(_)) => {
                warnings.push(Warning {
                    code: "TIME_UNCERTAIN".to_owned(),
                    message: "safe time cannot be established; activation is stopped".to_owned(),
                });
                self.inner.config.clock.wall()
            }
            Err(e) => return Err(e),
        };
        let ctx = caller.context.clone();
        let environment = self.inner.config.environment.clone();
        let mut data = match req.subject {
            InspectSubject::Capabilities => serde_json::json!({
                "capabilities": [
                    heimdall_contract::ipc::capability::OPERATIONS_V1,
                    heimdall_contract::ipc::capability::EVENTS_V1,
                    heimdall_contract::ipc::capability::OWNER_POLICY_V1,
                    heimdall_contract::ipc::capability::SCHEMA_DISCOVERY_V1,
                ],
                "schemas": heimdall_contract::schema::public_schemas()
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>(),
                "codes": heimdall_contract::schema::code_table()["codes"].clone(),
                "schema_version": heimdall_contract::SchemaVersion::current(),
            }),
            InspectSubject::Environments => {
                self.write(move |tx, _| {
                    let record = tx.environment(&environment)?;
                    Ok(serde_json::json!({
                        "environment_id": environment,
                        "enrolled": record.is_some(),
                        "environments": record.into_iter().collect::<Vec<_>>(),
                    }))
                })
                .await?
            }
            InspectSubject::Profiles | InspectSubject::Destinations => {
                warnings.push(Warning {
                    code: "NOT_LISTED".to_owned(),
                    message: "this runtime does not list this subject yet".to_owned(),
                });
                serde_json::json!({ "items": [] })
            }
            InspectSubject::Grants | InspectSubject::Bindings => {
                let subject = req.subject;
                self.write(move |tx, _| {
                    let mut grants = Vec::new();
                    let mut bindings = Vec::new();
                    for g in tx.grants_due(Timestamp::MAX)? {
                        let refs = tx.grant_references(&g.id)?;
                        let mut visible = ctx.is_owner();
                        for r in refs {
                            // A delegated child's reference on its parent is not a
                            // binding of the parent.
                            if let Some(b) = tx.binding(&r.binding)?
                                && b.grant == g.id
                                && may_act_on(&b, &ctx)
                            {
                                visible = true;
                                bindings.push(serde_json::json!({
                                    "binding_id": b.id,
                                    "grant_id": b.grant,
                                    "work_id": b.work_id,
                                    "profile": b.profile,
                                    "profile_revision": b.profile_revision,
                                    "state": b.state,
                                    "created_at": b.created_at,
                                }));
                            }
                        }
                        if visible {
                            grants.push(serde_json::json!({
                                "grant_id": g.id,
                                "state": g.state,
                                "expires_at": g.deadline.effective,
                                "parent": g.parent,
                                "scope": g.scope,
                            }));
                        }
                    }
                    Ok(if subject == InspectSubject::Grants {
                        serde_json::json!({ "grants": grants })
                    } else {
                        serde_json::json!({ "bindings": bindings })
                    })
                })
                .await?
            }
            InspectSubject::Operations => {
                self.write(move |tx, _| {
                    let mut ops = tx.open_operations()?;
                    ops.extend(tx.unresolved_operations()?);
                    let counts = tx.operation_counts()?;
                    Ok(serde_json::json!({
                        "operations": ops
                            .iter()
                            .filter(|o| visible_to(&o.key.caller, &ctx))
                            .map(operation_view)
                            .collect::<Vec<_>>(),
                        "counts": counts
                            .into_iter()
                            .map(|(s, n)| serde_json::json!({ "state": s, "count": n }))
                            .collect::<Vec<_>>(),
                    }))
                })
                .await?
            }
            InspectSubject::Decisions => {
                if !ctx.is_owner() {
                    serde_json::json!({ "decisions": [] })
                } else {
                    self.write(move |tx, _| {
                        let pending = tx.pending_decisions()?;
                        Ok(serde_json::json!({
                            "decisions": pending
                                .iter()
                                .map(|d| decision_view(d, now))
                                .collect::<Vec<_>>(),
                        }))
                    })
                    .await?
                }
            }
        };
        if let Some(preview) = req.preview {
            let p = self.preview(caller, preview, now).await?;
            if let serde_json::Value::Object(map) = &mut data {
                map.insert("preview".to_owned(), p);
            }
        }
        Ok(Completed {
            warnings,
            ..Completed::ok(Code::Ok, data)
        })
    }

    /// `inspect --preview`: resolution without effects.
    async fn preview(
        &self,
        caller: &Caller,
        p: heimdall_contract::request::EnsurePreview,
        now: Timestamp,
    ) -> Result<serde_json::Value, OpError> {
        let own = self.inner.config.environment.clone();
        let inp = ResolveInput {
            spec: WorkSpec {
                kind: OperationKind::Ensure,
                profile: Some(p.profile),
                profile_revision: None,
                environment: p.environment.unwrap_or_else(|| own.clone()),
                pairs: BTreeSet::new(),
                work_id: WorkId::parse("preview").map_err(|_| internal("work id"))?,
                until: p.until,
                required: p.required_capabilities,
                interactive: false,
                parent_binding: None,
            },
            caller: caller.context.clone(),
            operation: OperationId::from_random_bytes([0; 16]),
            environment: own,
            now,
            default_window: self.inner.config.default_window,
            adapters: self.adapter_infos(),
            grant_id: GrantId::from_random_bytes([0; 16]),
        };
        self.write(move |tx, _| {
            Ok(match resolve_in(tx, &inp)? {
                Err(e) => serde_json::json!({ "outcome": "denied", "code": e.code, "message": e.message }),
                Ok(r) => {
                    let mechanism = r.adapter.as_ref().map(|a| a.identity.mechanism.clone());
                    let snapshot = serde_json::json!({
                        "profile": r.profile.id,
                        "profile_revision": r.profile.revision,
                        "requested": r.requested,
                        "deadline": r.deadline.effective,
                        "mechanism": mechanism,
                    });
                    match r.decision {
                        AuthorityDecision::Allowed(a) => serde_json::json!({
                            "outcome": "allowed", "snapshot": snapshot, "effective": a,
                        }),
                        AuthorityDecision::ApprovalRequired { covered, delta } => serde_json::json!({
                            "outcome": "approval_required", "snapshot": snapshot,
                            "covered": covered, "delta": delta,
                        }),
                        AuthorityDecision::Denied(d) => {
                            let e = OpError::from_denial(&d);
                            serde_json::json!({ "outcome": "denied", "code": e.code, "message": e.message })
                        }
                    }
                }
            })
        })
        .await
    }

    /// `ensure` (plan §4.2 pipeline; `crate::ensure`).
    pub async fn ensure(&self, caller: &Caller, req: EnsureRequest) -> OpResult<EnsureData> {
        if req.scope.len() > MAX_SCOPE_PAIRS {
            return Err(OpError::new(
                Code::UsageError,
                "too many destination/account pairs",
            ));
        }
        let own = self.inner.config.environment.clone();
        let environment = req.environment.clone().unwrap_or_else(|| own.clone());
        if environment != own {
            return Err(OpError::new(
                Code::NotFound,
                "the environment is not managed by this runtime",
            )
            .with_resource("environment", None));
        }
        let hash = compute_hash(
            OperationKind::Ensure,
            &HashInput {
                environment: &environment,
                profile: Some(&req.profile),
                profile_revision: req.profile_revision,
                scope: &req.scope,
                deadline_intent: req.until.as_ref(),
                work_id: Some(&req.work_id),
                required_capabilities: &req.required_capabilities,
                parent_binding: None,
                extra: serde_json::Value::Null,
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        let request_id = req.request_id.clone();
        let wait = req.wait;
        self.run_work(
            caller,
            OperationKind::Ensure,
            Request::Ensure(req),
            hash,
            request_id,
            wait,
        )
        .await
    }

    /// `bind` (materialize only in M01; launch is the CLI's job after ensure).
    /// Authorized by binding ownership or owner role.
    pub async fn bind(&self, caller: &Caller, req: BindRequest) -> OpResult<EnsureData> {
        if let BindForm::Launch { argv } = &req.form {
            let total: usize = argv.iter().map(String::len).sum();
            if argv.is_empty() || total > MAX_ARGV_BYTES {
                return Err(OpError::new(Code::UsageError, "argv is empty or too large"));
            }
        }
        let safe = self.inner.timegate.check().await?;
        let own = self.inner.config.environment.clone();
        let hash = compute_hash(
            OperationKind::Bind,
            &HashInput {
                environment: &own,
                profile: None,
                profile_revision: None,
                scope: &BTreeSet::new(),
                deadline_intent: None,
                work_id: None,
                required_capabilities: &RequiredCapabilities::default(),
                parent_binding: None,
                extra: serde_json::json!({ "binding_id": req.binding_id, "form": req.form }),
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        // Authorize before any record exists: an unknown or foreign binding is
        // `NOT_FOUND` (IDs are not bearer credentials).
        let ctx = caller.context.clone();
        let bid = req.binding_id.clone();
        let visible = self
            .write(move |tx, _| Ok(tx.binding(&bid)?.is_some_and(|b| may_act_on(&b, &ctx))))
            .await?;
        if !visible {
            return Err(
                OpError::new(Code::NotFound, "unknown binding").with_resource("binding", None)
            );
        }
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind: OperationKind::Bind,
            request_id: req.request_id.clone(),
        };
        let request_json = serde_json::to_value(Request::Bind(req))
            .map_err(|_| internal("request is not serializable"))?;
        let outcome = self
            .admit(
                key,
                hash,
                OperationKind::Bind,
                EffectClass::Local,
                request_json,
                safe.wall(),
                false,
            )
            .await?;
        if let Some(e) = Self::refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        if let Some(Err(e)) = self
            .lead_bounded(&id, false, Some(self.inner.config.limits.max_wait))
            .await
        {
            return Err(e);
        }
        let st = self.load_work(&id).await?;
        let done = render_settled::<EnsureData>(&st.op)?;
        Ok(Completed {
            next: Some(NextAction {
                action: "use_binding".to_owned(),
                binding_id: Some(done.data.binding_id.clone()),
                ..NextAction::default()
            }),
            ..done
        })
    }

    async fn drive_bind(&self, id: &OperationId) -> Result<(), OpError> {
        let st = self.load_work(id).await?;
        if st.op.state.is_quiescent() {
            return Ok(());
        }
        let Some(Request::Bind(req)) = st.request() else {
            return Err(internal("the stored request cannot be read"));
        };
        let safe = self.inner.timegate.check().await?;
        let now = safe.wall();
        let bid = req.binding_id.clone();
        let env = self.inner.config.environment.clone();
        // First validation in this boot anchors the grant (ADR-0005 §3.6).
        let pre = self
            .write(move |tx, _| {
                let Some(b) = tx.binding(&bid)? else {
                    return Ok(None);
                };
                let Some(g) = tx.grant(&b.grant)? else {
                    return Ok(None);
                };
                let ancestors = ancestry(tx, &g)?;
                let policies = tx.policies_for(&b.profile, &env)?;
                let bound = grant_bound(&g, &ancestors, merged_policy(&policies, now).as_ref());
                let bound = anchor_bound(tx, &g.id, bound)?;
                Ok(Some((g.id, bound, g.state.permits_use())))
            })
            .await?;
        if let Some((gid, bound, true)) = &pre
            && !dtime::is_expired(now, *bound)
        {
            self.inner.timegate.anchor_grant(gid, &safe, *bound).await?;
        }
        let id2 = id.clone();
        let env = self.inner.config.environment.clone();
        let retention = self.retention();
        let clock = self.clock();
        let adapters = self.adapter_infos();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id2)? else {
                return Ok(());
            };
            if op.state.is_quiescent() {
                return Ok(());
            }
            if op.state == OperationState::Queued {
                op_to(&mut op, OperationEvent::Start, now)?;
                tx.update_operation(&op)?;
            }
            let fail = |tx: &mut Txn<'_>, emit: &mut Emit, op: &mut OperationRecord, e: OpError| {
                settle_failed(tx, emit, op, &e, now, retention)
            };
            let Some(b) = tx
                .binding(&req.binding_id)?
                .filter(|b| may_act_on(b, &op.key.caller))
            else {
                return fail(
                    tx,
                    emit,
                    &mut op,
                    OpError::new(Code::NotFound, "unknown binding").with_resource("binding", None),
                );
            };
            if b.state != BindingState::Active {
                return fail(
                    tx,
                    emit,
                    &mut op,
                    OpError::new(Code::CredentialExpired, "the binding was released")
                        .with_resource("binding", Some(b.id.to_string())),
                );
            }
            let Some(g) = tx.grant(&b.grant)? else {
                return fail(
                    tx,
                    emit,
                    &mut op,
                    OpError::new(Code::NotFound, "unknown grant").with_resource("grant", None),
                );
            };
            let resolved = ResolvedIntent {
                profile: b.profile.clone(),
                profile_revision: b.profile_revision,
                scope: g.scope.clone(),
                deadline: g.deadline.clone(),
                policy_revision: None,
                generation: g.generation,
                grant: Some(g.id.clone()),
                binding: Some(b.id.clone()),
                adapter: None,
            };
            // An existing binding is not a new activation: pause does not stop it,
            // revocation, generation, deadline and cutoff do.
            let mut refusal = activation_refusal(tx, &env, &adapters, &resolved, &g, now, true)?
                .map(|r| r.error)
                .filter(|e| e.code != Code::PolicyPaused);
            if refusal.is_none() {
                let anchor = tx.grant_anchor(&g.id)?;
                let adm = anchor.map(|a| {
                    let x = dtime::admission(&a, &safe.anchor);
                    let y = dtime::admission(&a, &clock.observe());
                    if x == Admission::Expired || y == Admission::Expired {
                        Admission::Expired
                    } else if x == Admission::NeedsAnchor || y == Admission::NeedsAnchor {
                        Admission::NeedsAnchor
                    } else {
                        Admission::Open
                    }
                });
                refusal = match adm {
                    Some(Admission::Open) => None,
                    Some(Admission::Expired) => Some(
                        OpError::new(Code::CredentialExpired, "the grant reached its deadline")
                            .with_resource("grant", Some(g.id.to_string())),
                    ),
                    _ => Some(
                        OpError::new(
                            Code::TimeUncertain,
                            "time uncertain: the grant has no anchor in this boot",
                        )
                        .with_resource("clock", None),
                    ),
                };
            }
            if let Some(e) = refusal {
                return fail(tx, emit, &mut op, e);
            }
            let ancestors = ancestry(tx, &g)?;
            let policies = tx.policies_for(&b.profile, &env)?;
            let bound = grant_bound(&g, &ancestors, merged_policy(&policies, now).as_ref());
            let data = ensure_data(&b, &g, &Facts::conservative(&g, now), bound);
            let value = serde_json::to_value(&data)?;
            settle_succeeded(tx, emit, &mut op, Code::AccessReady, value, now, retention)
        })
        .await
    }

    /// `delegate` (spec §6.7, §8.7). Authorized by parent-binding ownership.
    pub async fn delegate(&self, caller: &Caller, req: DelegateRequest) -> OpResult<EnsureData> {
        if req.scope.len() > MAX_SCOPE_PAIRS {
            return Err(OpError::new(
                Code::UsageError,
                "too many destination/account pairs",
            ));
        }
        let ctx = caller.context.clone();
        let pb = req.parent_binding_id.clone();
        let visible = self
            .write(move |tx, _| Ok(tx.binding(&pb)?.is_some_and(|b| may_act_on(&b, &ctx))))
            .await?;
        if !visible {
            return Err(
                OpError::new(Code::NotFound, "unknown binding").with_resource("binding", None)
            );
        }
        let own = self.inner.config.environment.clone();
        let hash = compute_hash(
            OperationKind::Delegate,
            &HashInput {
                environment: &own,
                profile: None,
                profile_revision: None,
                scope: &req.scope,
                deadline_intent: req.until.as_ref(),
                work_id: Some(&req.work_id),
                required_capabilities: &req.required_capabilities,
                parent_binding: Some(&req.parent_binding_id),
                extra: serde_json::Value::Null,
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        let request_id = req.request_id.clone();
        self.run_work(
            caller,
            OperationKind::Delegate,
            Request::Delegate(req),
            hash,
            request_id,
            WaitMode::default(),
        )
        .await
    }

    /// `observe` (spec §11.5; timeout ≠ cancel).
    pub async fn observe(
        &self,
        caller: &Caller,
        req: ObserveRequest,
    ) -> OpResult<serde_json::Value> {
        match req {
            ObserveRequest::Operation {
                operation_id,
                wait_ms,
            } => {
                let deadline = wait_ms.map(|ms| {
                    tokio::time::Instant::now()
                        + Duration::from_millis(ms).min(self.inner.config.limits.max_wait)
                });
                loop {
                    let notified = self.inner.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let id = operation_id.clone();
                    let ctx = caller.context.clone();
                    let op = self
                        .write(move |tx, _| {
                            Ok(tx
                                .operation(&id)?
                                .filter(|o| visible_to(&o.key.caller, &ctx)))
                        })
                        .await?
                        .ok_or_else(|| {
                            OpError::new(Code::NotFound, "unknown operation")
                                .with_resource("operation", None)
                        })?;
                    let waiting = deadline.is_some_and(|d| tokio::time::Instant::now() < d);
                    if op.state.is_quiescent() || !waiting {
                        let mut done = Completed::ok(Code::Ok, operation_view(&op));
                        done.state = op.state;
                        done.operation_id = Some(op.id.clone());
                        if !op.state.is_quiescent() {
                            done.next = Some(NextAction {
                                action: "observe".to_owned(),
                                operation_id: Some(op.id.clone()),
                                ..NextAction::default()
                            });
                        }
                        return Ok(done);
                    }
                    if let Some(d) = deadline {
                        let _ = tokio::time::timeout_at(d, notified).await;
                    }
                }
            }
            ObserveRequest::Events {
                cursor,
                filter,
                limit,
            } => {
                let publisher = self.inner.publisher.clone();
                let ctx = caller.context.clone();
                let env = self.inner.config.environment.clone();
                let page_max = self.inner.config.limits.max_event_page;
                let limit = limit.unwrap_or(page_max).clamp(1, page_max);
                let snapshot_at = self.inner.config.clock.wall();
                let from = match &cursor {
                    Some(c) => match publisher.cursor_for_reader(&ctx, c) {
                        Some(seq) => Some(seq),
                        None => return Err(self.resync(&ctx).await),
                    },
                    None => None,
                };
                let p2 = publisher.clone();
                let r = self
                    .write(move |tx, _| {
                        let (generation, head) = tx.snapshot_boundary(&env)?;
                        match from {
                            None => {
                                let data = crate::events::snapshot_data(tx, &env, &ctx, &filter, generation, head)?;
                                Ok(Ok(serde_json::json!({
                                    "snapshot": Snapshot { data, cursor: p2.cursor_at(&ctx, head), taken_at: snapshot_at },
                                })))
                            }
                            Some(seq) => {
                                let page = tx.stored_events_after(&env, seq, &filter, limit)?;
                                if seq < page.tail_seq || seq > page.head_seq {
                                    return Ok(Err(()));
                                }
                                let full = page.events.len() >= limit as usize;
                                let next_seq = if full {
                                    page.events.last().map_or(seq, |e| e.seq)
                                } else {
                                    page.head_seq.max(seq)
                                };
                                let events: Vec<_> = page
                                    .events
                                    .into_iter()
                                    .map(|s| {
                                        let mut e = s.event;
                                        e.cursor = p2.cursor_at(&ctx, s.seq);
                                        e
                                    })
                                    .collect();
                                Ok(Ok(serde_json::json!({
                                    "events": events,
                                    "cursor": p2.cursor_at(&ctx, next_seq),
                                    "more": full,
                                })))
                            }
                        }
                    })
                    .await?;
                match r {
                    Ok(data) => Ok(Completed::ok(Code::Ok, data)),
                    Err(()) => Err(self.resync(&caller.context).await),
                }
            }
        }
    }

    /// `RESYNC_REQUIRED` with a usable snapshot-boundary cursor for this reader.
    async fn resync(&self, ctx: &CallerContext) -> OpError {
        let mut next = NextAction::for_code(Code::ResyncRequired);
        let publisher = self.inner.publisher.clone();
        let c2 = ctx.clone();
        let env = self.inner.config.environment.clone();
        if let Ok(head) = self
            .write(move |tx, _| Ok(tx.snapshot_boundary(&env)?.1))
            .await
        {
            next.cursor = Some(publisher.cursor_at(&c2, head));
        }
        OpError::new(
            Code::ResyncRequired,
            "the cursor is expired, foreign or malformed; take a snapshot and resume from its cursor",
        )
        .with_next(next)
    }

    /// `cancel` (explicit, idempotent; reports possible external effect).
    pub async fn cancel(&self, caller: &Caller, req: CancelRequest) -> OpResult<serde_json::Value> {
        let now = self.narrowing_now().await;
        let ctx = caller.context.clone();
        let id = req.operation_id.clone();
        let retention = self.retention();
        let (op, cleanup) = self
            .write(move |tx, emit| {
                let Some(mut op) = tx
                    .operation(&id)?
                    .filter(|o| visible_to(&o.key.caller, &ctx))
                else {
                    return Ok(None);
                };
                // Settled or unresolved: idempotent, nothing changes (a timeout or
                // an uncertain effect is never turned into a cancellation).
                if op.state.is_quiescent() {
                    return Ok(Some((op, None)));
                }
                let receipts = tx.stage_receipts(&id)?;
                let may_have = may_have_external_effect(&receipts);
                let mut cleanup = None;
                if let Some(gid) = tx
                    .recovery_intent(&id)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.grant)
                    && !coalesced(&receipts)
                    && let Some(mut g) = tx.grant(&gid)?
                {
                    if grant_try(&mut g, GrantEvent::Cancel) {
                        put_grant(tx, emit, &g, Some(&id))?;
                    }
                    if may_have {
                        cleanup = Some(gid);
                    }
                }
                op_to(&mut op, OperationEvent::Cancel, now)?;
                op.cancellation = Some(CancellationRecord {
                    requested_at: now,
                    may_have_external_effect: may_have,
                });
                let err = OpError::new(Code::OperationCancelled, "the operation was cancelled")
                    .with_effect(if may_have {
                        EffectStatus::Partial
                    } else {
                        EffectStatus::None
                    })
                    .with_operation(id.clone());
                op.code = Some(Code::OperationCancelled);
                op.effect_status = err.effect_status;
                op.result = Some(serde_json::json!({ "error": err.detail() }));
                tx.update_operation(&op)?;
                tx.settle_idempotency(&op.key, retention_expiry(now, retention))?;
                emit.op(tx, &op)?;
                Ok(Some((op, cleanup)))
            })
            .await?
            .ok_or_else(|| {
                OpError::new(Code::NotFound, "unknown operation").with_resource("operation", None)
            })?;
        if let Some(gid) = cleanup {
            self.cleanup(&gid).await;
        }
        let may_have = op
            .cancellation
            .as_ref()
            .map(|c| c.may_have_external_effect)
            .unwrap_or(op.effect_status != EffectStatus::None);
        let mut done = Completed::ok(
            Code::Ok,
            serde_json::json!({
                "operation_id": op.id,
                "state": op.state,
                "may_have_external_effect": may_have || op.state.is_unresolved(),
                "operation": operation_view(&op),
            }),
        );
        done.operation_id = Some(op.id.clone());
        Ok(done)
    }

    /// `release` (drops a reference; idempotent; never revokes a shared grant;
    /// spec §6.3). Authorized by binding ownership or owner role.
    pub async fn release(
        &self,
        caller: &Caller,
        req: ReleaseRequest,
    ) -> OpResult<serde_json::Value> {
        let now = self.narrowing_now().await;
        let ctx = caller.context.clone();
        let bid = req.binding_id.clone();
        let r = self
            .write(move |tx, emit| {
                let Some(binding) = tx.binding(&bid)? else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown binding")
                        .with_resource("binding", None)));
                };
                let outcome = tx.release_binding(&bid, &ctx, now)?;
                let mut grant_state = None;
                match outcome {
                    ReleaseOutcome::NotOwner => {
                        return Ok(Err(OpError::new(
                            Code::CapabilityUnavailable,
                            "this caller does not own the binding",
                        )
                        .with_resource("binding", None)));
                    }
                    ReleaseOutcome::Released {
                        remaining_references,
                    } => {
                        if let Some(mut g) = tx.grant(&binding.grant)? {
                            // Release is never revoke (ADR-0006 §13.1 item 2): the last
                            // reference ends the grant locally, no tombstone, no cascade.
                            if remaining_references == 0
                                && grant_try(&mut g, GrantEvent::LastReferenceReleased)
                            {
                                put_grant(tx, emit, &g, None)?;
                            }
                            grant_state = Some(g.state);
                        }
                    }
                    ReleaseOutcome::AlreadyReleased => {
                        grant_state = tx.grant(&binding.grant)?.map(|g| g.state);
                    }
                }
                Ok(Ok(serde_json::json!({
                    "binding_id": bid,
                    "outcome": outcome,
                    "grant_id": binding.grant,
                    "grant_state": grant_state,
                })))
            })
            .await?;
        Ok(Completed::ok(Code::Ok, r?))
    }

    /// `revoke` (tombstone before acknowledgment; cascade; residual from the
    /// issuance log; spec §6.7).
    pub async fn revoke(&self, caller: &Caller, req: RevokeRequest) -> OpResult<RevokeData> {
        let now = self.narrowing_now().await;
        let own = self.inner.config.environment.clone();
        let hash = compute_hash(
            OperationKind::Revoke,
            &HashInput {
                environment: &own,
                profile: None,
                profile_revision: None,
                scope: &BTreeSet::new(),
                deadline_intent: None,
                work_id: None,
                required_capabilities: &RequiredCapabilities::default(),
                parent_binding: None,
                extra: serde_json::json!({ "grant_id": req.grant_id }),
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        // Owner role, or a caller holding a binding on the grant; anyone else sees
        // `NOT_FOUND`.
        let ctx = caller.context.clone();
        let gid = req.grant_id.clone();
        let visible = self
            .write(move |tx, _| {
                if tx.grant(&gid)?.is_none() {
                    return Ok(false);
                }
                if ctx.is_owner() {
                    return Ok(true);
                }
                for r in tx.grant_references(&gid)? {
                    if tx
                        .binding(&r.binding)?
                        .is_some_and(|b| b.grant == gid && b.owner.principal == ctx.principal)
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .await?;
        if !visible {
            return Err(OpError::new(Code::NotFound, "unknown grant").with_resource("grant", None));
        }
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind: OperationKind::Revoke,
            request_id: req.request_id.clone(),
        };
        let request_json = serde_json::to_value(Request::Revoke(req))
            .map_err(|_| internal("request is not serializable"))?;
        let outcome = self
            .admit(
                key,
                hash,
                OperationKind::Revoke,
                EffectClass::LocalResources,
                request_json,
                now,
                false,
            )
            .await?;
        if let Some(e) = Self::refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        if let Some(Err(e)) = self
            .lead_bounded(&id, false, Some(self.inner.config.limits.max_wait))
            .await
        {
            return Err(e);
        }
        let st = self.load_work(&id).await?;
        render_settled::<RevokeData>(&st.op)
    }

    async fn drive_revoke(&self, id: &OperationId) -> Result<(), OpError> {
        let st = self.load_work(id).await?;
        if st.op.state.is_quiescent() {
            return Ok(());
        }
        let Some(Request::Revoke(req)) = st.request() else {
            return Err(internal("the stored request cannot be read"));
        };
        let now = self.narrowing_now().await;
        let retention = self.retention();
        // Phase 1 (once): tombstone + generation + cascade, before acknowledgment.
        let id2 = id.clone();
        let root = req.grant_id.clone();
        let grants = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok(Vec::new());
                };
                let mut all = vec![root.clone()];
                all.extend(tx.grant_descendants(&root)?);
                if op.state != OperationState::Queued {
                    return Ok(all);
                }
                let tombstone = Tombstone {
                    grant: root.clone(),
                    cascade: all[1..].to_vec(),
                    generation: tx.authority_generation()?,
                    revoked_at: now,
                    remote_pending: Vec::new(),
                };
                tx.insert_tombstone(&tombstone)?;
                for gid in &all {
                    let Some(mut g) = tx.grant(gid)? else {
                        continue;
                    };
                    let moved = match g.state {
                        GrantState::Requested | GrantState::AwaitingApproval => {
                            grant_try(&mut g, GrantEvent::DecisionDenied)
                        }
                        _ => grant_try(&mut g, GrantEvent::RevokeLocal),
                    };
                    if moved {
                        put_grant(tx, emit, &g, Some(&id2))?;
                        emit.event(
                            tx,
                            EventType::CredentialLifecycle,
                            Some(id2.clone()),
                            Some(resource("grant", gid)),
                            serde_json::json!({ "grant_id": gid, "event": "revoked_locally" }),
                        )?;
                    }
                }
                // Operations waiting for approval on a revoked grant end now.
                for mut waiting in tx.open_operations()? {
                    if waiting.state != OperationState::AwaitingApproval {
                        continue;
                    }
                    let pinned = tx
                        .recovery_intent(&waiting.id)?
                        .and_then(|i| i.resolved)
                        .and_then(|r| r.grant);
                    if pinned.is_some_and(|g| all.contains(&g)) {
                        let err = authority_changed("the requested grant was revoked");
                        settle_failed(tx, emit, &mut waiting, &err, now, retention)?;
                    }
                }
                op_to(&mut op, OperationEvent::Start, now)?;
                tx.update_operation(&op)?;
                emit.op(tx, &op)?;
                Ok(all)
            })
            .await?;
        if grants.is_empty() {
            return Ok(());
        }
        // Phase 2: local revocation through every adapter; remote effects are
        // reported, never assumed.
        let mut pending: BTreeSet<GrantId> = BTreeSet::new();
        let mut adapter_expiry: Option<Timestamp> = None;
        for gid in &grants {
            for a in &self.inner.config.adapters {
                match a.revoke(gid, now).await {
                    Ok(out) => {
                        if !out.remote_pending.is_empty() {
                            pending.insert(gid.clone());
                        }
                        if let Some(t) = out.latest_possible_credential_expiry {
                            adapter_expiry = Some(adapter_expiry.map_or(t, |e| e.max(t)));
                        }
                    }
                    Err(_) => {
                        pending.insert(gid.clone());
                    }
                }
            }
        }
        // Phase 3: settle with the residual from the issuance log ∪ adapters.
        let id3 = id.clone();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id3)? else {
                return Ok(());
            };
            if op.state != OperationState::Running {
                return Ok(());
            }
            for gid in &grants {
                if pending.contains(gid) {
                    continue;
                }
                if let Some(mut g) = tx.grant(gid)?
                    && grant_try(&mut g, GrantEvent::RevokeComplete)
                {
                    put_grant(tx, emit, &g, Some(&id3))?;
                }
            }
            let residual = tx.issuance_residual(&grants)?;
            let latest = match (residual, adapter_expiry) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            let data = RevokeData {
                local_applied: true,
                remote_pending: pending.into_iter().collect(),
                latest_possible_credential_expiry: latest,
            };
            let value = serde_json::to_value(&data)?;
            settle_succeeded(tx, emit, &mut op, Code::Ok, value, now, retention)
        })
        .await
    }

    /// Owner-channel policy actions (spec §6.1). `pause` and an earlier `cutoff`
    /// narrow and are accepted from any owner-role caller. `resume`,
    /// `clear_cutoff` and a later `cutoff` widen: they always create a
    /// `WidenPolicy` decision record and are never executed on dispatch
    /// (⟨r2.1⟩ N04): `APPROVAL_REQUIRED` on an attended session,
    /// `INTERACTION_REQUIRED` on an unattended one, both with `next.decision_ref`.
    pub async fn policy(&self, caller: &Caller, req: PolicyAction) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "owner-channel actions need the owner role",
            ));
        }
        // Narrowing never waits for safe time; a widening decision record's
        // lifetime is measured on accepted time only (gap G10): under
        // `TIME_UNCERTAIN` no widening record is created.
        let gate = self.inner.timegate.check().await;
        let now = match &gate {
            Ok(s) => s.wall(),
            Err(_) => self.inner.config.clock.wall(),
        };
        let unsafe_time = gate.err();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let attended = caller.is_attended();
        let action = req.clone();
        let r = self
            .write(move |tx, emit| {
                let pid: PolicyId = match &action {
                    PolicyAction::Pause { policy_id }
                    | PolicyAction::Resume { policy_id }
                    | PolicyAction::Cutoff { policy_id, .. }
                    | PolicyAction::ClearCutoff { policy_id } => policy_id.clone(),
                };
                let Some(mut p) = tx.policy(&pid)? else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown policy")
                        .with_resource("policy", None)));
                };
                let widening = match &action {
                    PolicyAction::Pause { .. } => false,
                    PolicyAction::Resume { .. } => true,
                    PolicyAction::ClearCutoff { .. } => true,
                    PolicyAction::Cutoff { at, .. } => p.cutoff_at.is_some_and(|c| *at > c),
                };
                let unchanged = match &action {
                    PolicyAction::Pause { .. } => matches!(p.pause, PauseState::Paused { .. }),
                    PolicyAction::Resume { .. } => p.pause == PauseState::Active,
                    PolicyAction::ClearCutoff { .. } => p.cutoff_at.is_none(),
                    PolicyAction::Cutoff { at, .. } => p.cutoff_at == Some(*at),
                };
                if unchanged {
                    return Ok(Ok(PolicyOutcome::Applied(Box::new(p), false)));
                }
                if widening {
                    if let Some(e) = unsafe_time {
                        return Ok(Err(e));
                    }
                    // One logical decision, one record (spec §5.5): reuse an
                    // unexpired pending record for the same verbatim action.
                    let current = tx.authority_generation()?;
                    if let Some(existing) = tx.pending_decisions()?.into_iter().find(|d| {
                        matches!(&d.kind, DecisionKind::WidenPolicy { action: a } if *a == action)
                            && now < d.expires_at
                            && d.generation == current
                    }) {
                        return Ok(Ok(PolicyOutcome::Decision(existing.id)));
                    }
                    let d = DecisionRecord {
                        id: decision_id,
                        kind: DecisionKind::WidenPolicy {
                            action: action.clone(),
                        },
                        generation: current,
                        created_at: now,
                        expires_at: plus(now, lifetime),
                        state: DecisionState::Pending,
                        decided_at: None,
                    };
                    tx.insert_decision(&d)?;
                    emit.decision(tx, &d, None)?;
                    return Ok(Ok(PolicyOutcome::Decision(d.id)));
                }
                match &action {
                    PolicyAction::Pause { .. } => p.pause = PauseState::Paused { since: now },
                    PolicyAction::Cutoff { at, .. } => p.cutoff_at = Some(*at),
                    _ => {}
                }
                p.revision = PolicyRevision(p.revision.0.saturating_add(1));
                p.source = PolicySource::OwnerDecision { decided_at: now };
                tx.upsert_policy(&p, true)?;
                emit.policy(tx, &p)?;
                Ok(Ok(PolicyOutcome::Applied(Box::new(p), true)))
            })
            .await??;
        match r {
            PolicyOutcome::Applied(p, changed) => {
                Ok(Completed::ok(Code::Ok, policy_view(&p, changed)))
            }
            PolicyOutcome::Decision(dec) => Err(approval_needed(
                attended,
                dec.as_str(),
                "widening a standing policy needs an attended owner decision",
            )
            .with_resource("decision", Some(dec.to_string()))),
        }
    }

    /// Complete a server-issued decision on an attended session (consume-once;
    /// stale generation ⇒ `DECISION_STALE`). Approval applies exactly the recorded
    /// delta and resumes the waiting operation.
    pub async fn decide(&self, caller: &Caller, req: DecideRequest) -> OpResult<serde_json::Value> {
        // The session layer refuses this before dispatch; the application is the
        // authority and checks again (R5).
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "decisions are completed only on an attended session",
            ));
        }
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "owner decisions need the owner role",
            ));
        }
        let now = match req.verdict {
            Verdict::Approve => self.inner.timegate.check().await?.wall(),
            Verdict::Deny => self.narrowing_now().await,
        };
        let retention = self.retention();
        let did = req.decision_id.clone();
        let verdict = req.verdict;
        let r = self
            .write(move |tx, emit| {
                let Some(d) = tx.decision(&did)? else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown decision")
                        .with_resource("decision", None)));
                };
                let stale = |r: &DecisionRefusal| {
                    OpError::from_decision_refusal(r)
                        .with_resource("decision", Some(did.to_string()))
                };
                if d.state != DecisionState::Pending {
                    return Ok(Err(stale(&DecisionRefusal::NotPending(d.state))));
                }
                // R7: the store does not compare expiry with any clock.
                if now >= d.expires_at {
                    return Ok(Err(stale(&DecisionRefusal::Expired)));
                }
                let waiting = match &d.kind {
                    DecisionKind::ApproveAuthority { operation, .. } => {
                        match tx.operation(operation)? {
                            Some(op) if op.state == OperationState::AwaitingApproval => Some(op),
                            _ => {
                                return Ok(Err(OpError::new(
                                    Code::DecisionStale,
                                    "the operation is no longer awaiting this decision",
                                )
                                .with_resource("decision", Some(did.to_string()))));
                            }
                        }
                    }
                    DecisionKind::WidenPolicy { .. } => None,
                    DecisionKind::ConfirmTime { .. } => {
                        return Ok(Err(stale(&DecisionRefusal::NotPending(d.state))));
                    }
                };
                let record = match tx.complete_decision(&did, verdict, now)? {
                    DecisionCompletion::Completed(r) => r,
                    DecisionCompletion::Refused { record, .. } => {
                        let refusal = match heimdall_domain::decision::complete(
                            &record,
                            verdict,
                            tx.authority_generation()?,
                            now,
                        ) {
                            Err(r) => r,
                            Ok(_) => DecisionRefusal::NotPending(record.state),
                        };
                        if record.state == DecisionState::Stale {
                            emit.decision(tx, &record, None)?;
                        }
                        return Ok(Err(stale(&refusal)));
                    }
                };
                let op_id = waiting.as_ref().map(|o| o.id.clone());
                emit.decision(tx, &record, op_id.as_ref())?;
                let mut resume = None;
                match (&record.kind, verdict, waiting) {
                    (DecisionKind::ApproveAuthority { .. }, Verdict::Approve, Some(mut op)) => {
                        if let Some(gid) = tx
                            .recovery_intent(&op.id)?
                            .and_then(|i| i.resolved)
                            .and_then(|r| r.grant)
                            && let Some(mut g) = tx.grant(&gid)?
                            && grant_try(&mut g, GrantEvent::Approved)
                        {
                            put_grant(tx, emit, &g, Some(&op.id))?;
                        }
                        op_to(&mut op, OperationEvent::Approved, now)?;
                        tx.update_operation(&op)?;
                        emit.op(tx, &op)?;
                        resume = Some(op.id.clone());
                    }
                    (DecisionKind::ApproveAuthority { .. }, Verdict::Deny, Some(mut op)) => {
                        if let Some(gid) = tx
                            .recovery_intent(&op.id)?
                            .and_then(|i| i.resolved)
                            .and_then(|r| r.grant)
                            && let Some(mut g) = tx.grant(&gid)?
                            && grant_try(&mut g, GrantEvent::DecisionDenied)
                        {
                            put_grant(tx, emit, &g, Some(&op.id))?;
                        }
                        let err = OpError::new(
                            Code::CapabilityUnavailable,
                            "the owner denied the requested additional authority",
                        );
                        settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    }
                    (DecisionKind::WidenPolicy { action }, Verdict::Approve, _) => {
                        if let Err(e) = apply_widening(tx, emit, action, now)? {
                            return Ok(Err(e));
                        }
                    }
                    _ => {}
                }
                Ok(Ok((record, op_id, resume)))
            })
            .await??;
        let (record, op_id, resume) = r;
        let mut operation_state = None;
        if let Some(id) = &resume {
            // Resume the waiting operation (bounded wait; the work continues).
            let _ = self
                .lead_bounded(id, false, Some(self.inner.config.limits.max_wait))
                .await;
        }
        if let Some(id) = &op_id {
            operation_state = self.load_work(id).await.ok().map(|s| s.op.state);
        }
        let mut done = Completed::ok(
            Code::Ok,
            serde_json::json!({
                "decision_id": record.id,
                "verdict": verdict,
                "state": record.state,
                "operation_id": op_id,
                "operation_state": operation_state,
            }),
        );
        done.operation_id = op_id;
        Ok(done)
    }

    /// Attended confirmation of the current time (ADR-0005 §3.6). Creates and
    /// consumes a `ConfirmTime` decision in one step on an attended session and
    /// records the confirmation through the time gate. Never moves deadlines.
    pub async fn confirm_time(
        &self,
        caller: &Caller,
        req: ConfirmTimeRequest,
    ) -> OpResult<serde_json::Value> {
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "time is confirmed only on an attended session",
            ));
        }
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "time confirmation needs the owner role",
            ));
        }
        let observed = self.inner.config.clock.observe();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let record = DecisionRecord {
            id: decision_id.clone(),
            kind: DecisionKind::ConfirmTime {
                boot_id: observed.boot_id.clone(),
                observed_wall: observed.wall,
            },
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            created_at: observed.wall,
            expires_at: plus(observed.wall, lifetime),
            state: DecisionState::Pending,
            decided_at: None,
        };
        self.write(move |tx, emit| {
            let mut record = record;
            record.generation = tx.authority_generation()?;
            tx.insert_decision(&record)?;
            emit.decision(tx, &record, None)
        })
        .await?;
        let confirmed = self
            .inner
            .timegate
            .confirm_attended(req.observed_wall, decision_id.clone())
            .await;
        let verdict = if confirmed.is_ok() {
            Verdict::Approve
        } else {
            Verdict::Deny
        };
        let did = decision_id.clone();
        let now = observed.wall;
        self.write(move |tx, emit| {
            if let DecisionCompletion::Completed(r) = tx.complete_decision(&did, verdict, now)? {
                emit.decision(tx, &r, None)?;
            }
            Ok(())
        })
        .await?;
        let confirmation = confirmed?;
        Ok(Completed::ok(
            Code::Ok,
            serde_json::json!({
                "decision_id": decision_id,
                "boot_id": confirmation.boot_id,
                "accepted_wall": confirmation.wall,
                "deadlines_moved": false,
            }),
        ))
    }

    /// Deadline tick: expire due grants (wall bound or continuous budget), close
    /// owned resources, trim retention (M01-U8 supervisor calls this at persisted
    /// deadlines and after wake/restart).
    pub async fn tick(&self) -> Result<(), crate::OpError> {
        let (safe, wall) = match self.inner.timegate.check().await {
            Ok(s) => {
                let w = s.wall();
                (Some(s), w)
            }
            // While uncertain only the wall branch applies (it can only deny).
            Err(e) if e.code == Code::TimeUncertain => (None, self.inner.config.clock.wall()),
            Err(e) => return Err(e),
        };
        let env = self.inner.config.environment.clone();
        let candidates = self
            .write(move |tx, _| {
                let mut out = Vec::new();
                for g in tx.grants_due(Timestamp::MAX)? {
                    if g.state == GrantState::Revoking {
                        continue;
                    }
                    let ancestors = ancestry(tx, &g)?;
                    let ctx = grant_context(tx, &g)?;
                    let policies = match &ctx.profile {
                        Some(p) => tx.policies_for(p, &env)?,
                        None => Vec::new(),
                    };
                    let bound =
                        grant_bound(&g, &ancestors, merged_policy(&policies, wall).as_ref());
                    let bound = anchor_bound(tx, &g.id, bound)?;
                    let anchor = tx.grant_anchor(&g.id)?;
                    out.push((g, bound, anchor));
                }
                Ok(out)
            })
            .await?;
        for (g, bound, anchor) in candidates {
            let mut expired = dtime::is_expired(wall, bound);
            if !expired
                && let Some(safe) = &safe
                && g.state.permits_use()
            {
                // First validation in this boot anchors; a later earlier bound
                // (cutoff) shortens; nothing lengthens.
                let fresh_boot = anchor
                    .as_ref()
                    .is_none_or(|a| a.anchor.boot_id != safe.anchor.boot_id);
                if fresh_boot {
                    self.inner.timegate.anchor_grant(&g.id, safe, bound).await?;
                } else if anchor.as_ref().is_some_and(|a| a.bound > bound) {
                    self.inner.timegate.shorten_grant(&g.id, bound).await?;
                }
                expired = self.inner.timegate.admission(&g.id, safe).await? == Admission::Expired;
            }
            if expired {
                self.expire_grant(&g.id, wall).await?;
            }
        }
        if let Some(safe) = safe {
            let now = safe.wall();
            let env = self.inner.config.environment.clone();
            let keep_after = minus(now, self.inner.config.limits.event_retention);
            self.write(move |tx, _| {
                tx.purge_operations_before(now)?;
                tx.purge_markers_before(now)?;
                tx.trim_events(&env, keep_after, EVENT_ROW_CAP)?;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    /// The grant reached its admission deadline: `DeadlineReached`; an operation
    /// waiting for approval on it fails with `CREDENTIAL_EXPIRED` (§13.3).
    async fn expire_grant(&self, gid: &GrantId, now: Timestamp) -> Result<(), OpError> {
        let gid = gid.clone();
        let retention = self.retention();
        self.write(move |tx, emit| {
            let Some(mut g) = tx.grant(&gid)? else {
                return Ok(());
            };
            if grant_try(&mut g, GrantEvent::DeadlineReached) {
                put_grant(tx, emit, &g, None)?;
                emit.event(
                    tx,
                    EventType::CredentialLifecycle,
                    None,
                    Some(resource("grant", &gid)),
                    serde_json::json!({ "grant_id": gid, "event": "expired" }),
                )?;
            }
            for mut op in tx.open_operations()? {
                if op.state != OperationState::AwaitingApproval {
                    continue;
                }
                let pinned = tx
                    .recovery_intent(&op.id)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.grant);
                if pinned.as_ref() == Some(&gid) {
                    let err = OpError::new(
                        Code::CredentialExpired,
                        "the requested grant reached its deadline while awaiting approval",
                    )
                    .with_resource("grant", Some(gid.to_string()));
                    settle_failed(tx, emit, &mut op, &err, now, retention)?;
                }
            }
            Ok(())
        })
        .await
    }

    // -----------------------------------------------------------------------------
    // Issuance (ADR-0005 §3.5; ADR-0006 §13.4 N02) — the M03 issuer's substrate
    // -----------------------------------------------------------------------------

    /// Reserve a certificate (ADR-0005 §3.5 step 1): every predicate of
    /// `issuance::check` against current store state and the time gate's
    /// observation, then the `reserved` entry with complete bounds, in one
    /// transaction. Nothing is signed before this commits.
    pub async fn reserve_issuance(&self, req: IssuanceRequest) -> Result<IssuanceEntry, OpError> {
        let (safe, time) = self.issuance_time().await?;
        if let Some(s) = &safe {
            self.anchor_for_issuance(&req.grant, s).await?;
        }
        let id = crate::ids::new_issuance_id()?;
        let serial = crate::ids::random_u64()?;
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let raw_now = self.inner.config.clock.wall();
        let r = self
            .write(move |tx, emit| {
                let now = safe.as_ref().map_or(raw_now, SafeNow::wall);
                let Some(grant) = tx.grant(&req.grant)? else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown grant").with_resource("grant", None)));
                };
                let bounds = CertificateBounds {
                    serial,
                    key_id: req.key_id.clone(),
                    principal: req.principal.clone(),
                    valid_after: req.valid_after,
                    valid_before: req.valid_before,
                    extensions: req.extensions.clone(),
                    subject_fingerprint: req.subject_fingerprint.clone(),
                };
                if let Err(refusal) = run_issuance_check(tx, &env, &adapters, &grant, &req.pair, &bounds, &req.facts, time, safe.as_ref(), now)? {
                    return Ok(Err(OpError::from_issuance_refusal(&refusal)));
                }
                let entry = IssuanceEntry {
                    id: id.clone(),
                    grant: grant.id.clone(),
                    generation: tx.authority_generation()?,
                    pair: req.pair.clone(),
                    bounds,
                    state: IssuanceState::Reserved,
                    reserved_at: now,
                    settled_at: None,
                    void_reason: None,
                };
                tx.reserve_issuance(&entry)?;
                emit.event(
                    tx,
                    EventType::CredentialLifecycle,
                    None,
                    Some(resource("grant", &grant.id)),
                    serde_json::json!({ "grant_id": grant.id, "issuance_id": entry.id, "event": "reserved" }),
                )?;
                Ok(Ok(entry))
            })
            .await??;
        self.inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(r.id.clone(), r.grant.clone());
        Ok(r)
    }

    /// Publish a reservation (ADR-0005 §3.5 step 3): re-run **every** predicate
    /// with current state and time; on any refusal the entry is `voided` and
    /// nothing is released. An entry reserved before this runtime instance started
    /// is never published (it stays counted until its `valid_before`).
    pub async fn publish_issuance(
        &self,
        id: &IssuanceId,
        facts: &IssuanceFacts,
    ) -> Result<IssuanceEntry, OpError> {
        let grant = self
            .inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned();
        let Some(grant) = grant else {
            return Err(OpError::new(
                Code::CredentialExpired,
                "this reservation was not made by this runtime instance; reserve afresh",
            )
            .with_resource("grant", None));
        };
        let (safe, time) = self.issuance_time().await?;
        let env = self.inner.config.environment.clone();
        let raw_now = self.inner.config.clock.wall();
        let id2 = id.clone();
        let facts = facts.clone();
        let adapters = self.adapter_infos();
        let r = self
            .write(move |tx, emit| {
                let now = safe.as_ref().map_or(raw_now, SafeNow::wall);
                let Some(entry) = tx.issuance_entries(&grant)?.into_iter().find(|e| e.id == id2) else {
                    return Ok(Err(OpError::new(Code::NotFound, "unknown issuance entry")));
                };
                if entry.state != IssuanceState::Reserved {
                    return Ok(Err(OpError::new(Code::RequestConflict, "the issuance entry is already settled")));
                }
                // Reserve and publish observe the same generation (ADR-0006 §13.5
                // ruling 2): any authority change in between voids the entry.
                let check = match tx.grant(&grant)? {
                    None => Err(IssuanceRefusal::GrantNotIssuable(GrantState::Revoked)),
                    Some(g) => match run_issuance_check(tx, &env, &adapters, &g, &entry.pair, &entry.bounds, &facts, time, safe.as_ref(), now)? {
                        Ok(()) if tx.authority_generation()? != entry.generation => {
                            Err(IssuanceRefusal::StaleGeneration)
                        }
                        r => r,
                    },
                };
                match check {
                    Ok(()) => {
                        let published = tx.publish_issuance(&id2, now)?;
                        emit.event(tx, EventType::CredentialLifecycle, None, Some(resource("grant", &grant)),
                            serde_json::json!({ "grant_id": grant, "issuance_id": id2, "event": "published" }))?;
                        Ok(Ok(published))
                    }
                    Err(refusal) => {
                        tx.void_issuance(&id2, &refusal, now)?;
                        emit.event(tx, EventType::CredentialLifecycle, None, Some(resource("grant", &grant)),
                            serde_json::json!({ "grant_id": grant, "issuance_id": id2, "event": "voided" }))?;
                        Ok(Err(OpError::from_issuance_refusal(&refusal)))
                    }
                }
            })
            .await?;
        self.inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        r
    }

    /// Time evidence for an issuance step: the gate's verdict (`Uncertain` is a
    /// refusal reason, not an error) and the accepted observation when `Safe`.
    async fn issuance_time(&self) -> Result<(Option<SafeNow>, dtime::TimeStatus), OpError> {
        match self.inner.timegate.check().await {
            Ok(s) => Ok((Some(s), dtime::TimeStatus::Safe)),
            Err(e) if e.code == Code::TimeUncertain => {
                let status = match self.inner.timegate.peek().await {
                    Ok(dtime::TimeStatus::Uncertain(u)) => dtime::TimeStatus::Uncertain(u),
                    // Raced back to safe after the check: still use the refusal.
                    _ => dtime::TimeStatus::Uncertain(dtime::TimeUncertainty::Unsynchronized {
                        sync: dtime::SyncStatus::Unknown,
                    }),
                };
                Ok((None, status))
            }
            Err(e) => Err(e),
        }
    }

    /// First validation of a grant in this boot anchors it; a later earlier bound
    /// shortens it.
    async fn anchor_for_issuance(&self, gid: &GrantId, safe: &SafeNow) -> Result<(), OpError> {
        let env = self.inner.config.environment.clone();
        let gid2 = gid.clone();
        let now = safe.wall();
        let info = self
            .write(move |tx, _| {
                let Some(g) = tx.grant(&gid2)? else {
                    return Ok(None);
                };
                let ancestors = ancestry(tx, &g)?;
                let ctx = grant_context(tx, &g)?;
                let policies = match &ctx.profile {
                    Some(p) => tx.policies_for(p, &env)?,
                    None => Vec::new(),
                };
                let bound = grant_bound(&g, &ancestors, merged_policy(&policies, now).as_ref());
                let bound = anchor_bound(tx, &gid2, bound)?;
                Ok(Some((
                    g.state.permits_issuance(),
                    bound,
                    tx.grant_anchor(&gid2)?,
                )))
            })
            .await?;
        let Some((issuable, bound, anchor)) = info else {
            return Ok(());
        };
        if !issuable || dtime::is_expired(now, bound) {
            return Ok(());
        }
        match anchor {
            Some(a) if a.anchor.boot_id == safe.anchor.boot_id => {
                if a.bound > bound {
                    self.inner.timegate.shorten_grant(gid, bound).await?;
                }
            }
            _ => {
                self.inner.timegate.anchor_grant(gid, safe, bound).await?;
            }
        }
        Ok(())
    }
}

/// Extensions the grant permits for `pair` (ADR-0006 §13.5 ruling 3), derived
/// from the grant's resolved scope (its profile-snapshot capabilities), never from
/// request fields: `permit-pty` for an ordinary pair in the scope (ADR-0005 §3.4),
/// and `permit-agent-forwarding` only with the `agent-forwarding` capability.
/// Nothing else (no route data in M01, so no `permit-port-forwarding`; never
/// `permit-X11-forwarding`). M03 replaces this with the §3.4 profile/route
/// derivation.
#[must_use]
pub fn permitted_extensions(grant: &GrantSnapshot, pair: &AccessPair) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if !grant.scope.pairs.contains(pair) {
        return out;
    }
    out.insert("permit-pty".to_owned());
    if grant
        .scope
        .capabilities
        .contains(&Capability::AgentForwarding)
    {
        out.insert(heimdall_domain::issuance::EXTENSION_AGENT_FORWARDING.to_owned());
    }
    out
}

/// Build `IssuanceCheck` from current store state inside the caller's transaction
/// (ADR-0006 §13.4 N02) and run the production predicate. A grant or ancestor last
/// validated at an older generation is re-validated first (ADR-0006 §13.5 ruling
/// 2); when that fails the stale snapshots go to the predicate, which refuses.
#[allow(clippy::too_many_arguments)]
fn run_issuance_check(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    pair: &AccessPair,
    bounds: &CertificateBounds,
    facts: &IssuanceFacts,
    time: dtime::TimeStatus,
    safe: Option<&SafeNow>,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), IssuanceRefusal>> {
    let current_generation = tx.authority_generation()?;
    let raw = ancestry(tx, grant)?;
    let mut stale = validated_generation(tx, grant)? != current_generation;
    for a in &raw {
        stale = stale || validated_generation(tx, a)? != current_generation;
    }
    let at_current = |mut g: GrantSnapshot| {
        g.generation = current_generation;
        g
    };
    // On a failed re-validation the predicate still runs (so the refusal names
    // the substantive reason: tombstone, cutoff, ancestor state, ...); if it finds
    // nothing, the stale generation itself refuses.
    let (subject, chain, revalidation_failed) = if stale {
        match revalidate_chain(tx, env, adapters, grant, now)? {
            Ok(v) => (v.grant, v.ancestors, false),
            Err(_) => (
                at_current(grant.clone()),
                raw.into_iter().map(at_current).collect(),
                true,
            ),
        }
    } else {
        (
            at_current(grant.clone()),
            raw.into_iter().map(at_current).collect(),
            false,
        )
    };
    let (parent, ancestors) = match chain.split_first() {
        Some((p, rest)) => (Some(p), rest),
        None => (None, &[][..]),
    };
    let ctx = grant_context(tx, grant)?;
    let policies = match &ctx.profile {
        Some(p) => tx.policies_for(p, env)?,
        None => Vec::new(),
    };
    let merged = merged_policy(&policies, now);
    let policy = merged.as_ref();
    let tombstoned = tx.denied_ancestor(&grant.id)?.is_some();
    // Continuous admission from the **same** observation the gate assessed.
    let admission = match (safe, tx.grant_anchor(&grant.id)?) {
        (Some(s), Some(anchor)) => dtime::admission(&anchor, &s.anchor),
        _ => Admission::NeedsAnchor,
    };
    let permitted = permitted_extensions(grant, pair);
    let check = IssuanceCheck {
        grant: &subject,
        parent,
        ancestors,
        policy,
        expected_policy_revision: ctx.expected_policy_revision,
        current_generation,
        tombstoned,
        pair,
        bounds,
        permitted_extensions: &permitted,
        new_activation: facts.new_activation,
        subject_registered: facts.subject_registered,
        critical_option: facts.critical_option,
        time,
        admission,
        now,
    };
    Ok(match heimdall_domain::issuance::check(&check) {
        Ok(()) if revalidation_failed => Err(IssuanceRefusal::StaleGeneration),
        r => r,
    })
}

/// Outcome of a policy action.
enum PolicyOutcome {
    Applied(Box<StandingPolicy>, bool),
    Decision(heimdall_contract::ids::DecisionId),
}

fn policy_view(p: &StandingPolicy, changed: bool) -> serde_json::Value {
    serde_json::json!({
        "policy_id": p.id,
        "revision": p.revision.0,
        "paused": matches!(p.pause, PauseState::Paused { .. }),
        "cutoff_at": p.cutoff_at,
        "changed": changed,
    })
}

/// Apply exactly the recorded widening action after an attended approval.
fn apply_widening(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    action: &PolicyAction,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    let pid = match action {
        PolicyAction::Pause { policy_id }
        | PolicyAction::Resume { policy_id }
        | PolicyAction::Cutoff { policy_id, .. }
        | PolicyAction::ClearCutoff { policy_id } => policy_id,
    };
    let Some(mut p) = tx.policy(pid)? else {
        return Ok(Err(
            OpError::new(Code::NotFound, "unknown policy").with_resource("policy", None)
        ));
    };
    match action {
        PolicyAction::Resume { .. } => p.pause = PauseState::Active,
        PolicyAction::ClearCutoff { .. } => p.cutoff_at = None,
        PolicyAction::Cutoff { at, .. } => p.cutoff_at = Some(*at),
        PolicyAction::Pause { .. } => p.pause = PauseState::Paused { since: now },
    }
    p.revision = PolicyRevision(p.revision.0.saturating_add(1));
    p.source = PolicySource::OwnerDecision { decided_at: now };
    tx.upsert_policy(&p, false)?;
    emit.policy(tx, &p)?;
    Ok(Ok(()))
}

/// `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED` (unattended), both
/// carrying the nonsecret `next.decision_ref` (⟨r2.1⟩ N04). The next action keeps
/// the code table's default (`observe` / `interact`; ADR-0006 §5).
fn approval_needed(attended: bool, decision_ref: &str, msg: &str) -> OpError {
    let code = if attended {
        Code::ApprovalRequired
    } else {
        Code::InteractionRequired
    };
    OpError::new(code, msg.to_owned()).with_decision(decision_ref)
}

/// Render a non-waiting operation for a caller: the stored result, the stored
/// error, `OUTCOME_UNKNOWN`, or `ACCEPTED` while it is still running.
fn render_settled<T: serde::de::DeserializeOwned>(op: &OperationRecord) -> OpResult<T> {
    match op.state {
        OperationState::Succeeded => {
            let data = op
                .result
                .clone()
                .and_then(|v| serde_json::from_value::<T>(v).ok())
                .ok_or_else(|| internal("the stored result cannot be read"))?;
            Ok(Completed {
                operation_id: Some(op.id.clone()),
                state: op.state,
                code: op.code.clone().unwrap_or(Code::Ok),
                data,
                warnings: Vec::new(),
                next: None,
            })
        }
        OperationState::Failed | OperationState::Cancelled => {
            let detail = op
                .result
                .as_ref()
                .and_then(|v| v.get("error"))
                .and_then(|e| serde_json::from_value(e.clone()).ok());
            Err(match detail {
                Some(d) => OpError::from_detail(d, Some(op.id.clone())),
                None => OpError::new(
                    op.code.clone().unwrap_or(Code::InternalError),
                    "the operation failed",
                )
                .with_effect(op.effect_status)
                .with_operation(op.id.clone()),
            })
        }
        OperationState::OutcomeUnknown => Err(OpError::new(
            Code::OutcomeUnknown,
            "the credential effect may or may not have applied; it will be reconciled",
        )
        .with_operation(op.id.clone())),
        OperationState::Queued | OperationState::Running | OperationState::AwaitingApproval => {
            Err(OpError::new(
                Code::Accepted,
                "the operation is still in progress; observe it",
            )
            .with_operation(op.id.clone()))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn r(stage: EnsureStage, effect: EffectReceipt) -> StageReceipt {
        receipt(stage, "2026-10-02T00:00:00Z".parse().unwrap(), effect)
    }

    fn ident() -> AdapterIdentity {
        AdapterIdentity {
            mechanism: "fake".into(),
            instance: "1".into(),
        }
    }

    #[test]
    fn next_stage_needs_a_confirmed_reconcile() {
        use EnsureStage as S;
        let mut rs = vec![
            r(S::Authenticate, EffectReceipt::NotAttempted),
            r(S::LoadAuthority, EffectReceipt::NotAttempted),
            r(S::ResolveMechanism, EffectReceipt::NotAttempted),
            r(S::Coalesce, EffectReceipt::NotAttempted),
        ];
        assert_eq!(next_stage(&rs), Some(S::Reconcile));
        rs.push(r(
            S::Reconcile,
            EffectReceipt::Attempted {
                adapter: ident(),
                effect_token: "eff_1".into(),
            },
        ));
        assert_eq!(next_stage(&rs), Some(S::Reconcile));
        assert_eq!(effect_so_far(&rs), EffectStatus::Unknown);
        assert_eq!(last_token(&rs).as_deref(), Some("eff_1"));
        rs.push(r(
            S::Reconcile,
            EffectReceipt::Confirmed {
                adapter: ident(),
                credential_ref: "c".into(),
            },
        ));
        assert_eq!(next_stage(&rs), Some(S::Probe));
        assert_eq!(effect_so_far(&rs), EffectStatus::Partial);
        assert!(may_have_external_effect(&rs));
        assert!(!coalesced(&rs));
    }

    #[test]
    fn approval_codes_follow_attendance_and_carry_the_reference() {
        let a = approval_needed(true, "dec_x", "m");
        assert_eq!(a.code, Code::ApprovalRequired);
        assert_eq!(a.next.decision_ref.as_deref(), Some("dec_x"));
        let u = approval_needed(false, "dec_x", "m");
        assert_eq!(u.code, Code::InteractionRequired);
        assert_eq!(u.state(), OperationState::AwaitingApproval);
    }
}
