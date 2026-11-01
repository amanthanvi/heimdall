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
//!   never expires); reconciliation later settles it. A fresh attempt first waits
//!   for an adapter slot, then one transaction validates current authority,
//!   deadline, cutoff and continuous admission exactly as activation would before
//!   writing the `Attempted` receipt; nothing is prepared after the bound, and
//!   the adapter gets the grant narrowed to it (code review A03).
//! * **Time is assessed inside the transaction that acts on it** (code review
//!   A01, A02): resolution, the attempt, `Recheck`, `Commit`, `bind`, issuance
//!   reserve and publish, decision records and their completion run the shared
//!   gate (`TimeGate::in_txn`) on a fresh observation in their own transaction, so
//!   no accepted time is carried across asynchronous work. `Commit` re-validates
//!   tombstones, generation, pause/cutoff, policy revision, deadline, the
//!   continuous admission of the persisted anchor and the caller's minimums
//!   against the prepared facts (code review A04: actual offline coverage,
//!   achieved enforcement; `CAPABILITY_UNAVAILABLE` otherwise) before it writes
//!   the active binding, so a revocation that commits first always wins.
//! * Added authority (`ApprovalRequired`) always creates a server-issued
//!   [`DecisionRecord`] with the exact delta and an `awaiting_approval` grant
//!   (ADR-0006 §3.1, ⟨r2.1⟩ N04): attended ⇒ `APPROVAL_REQUIRED`, unattended ⇒
//!   `INTERACTION_REQUIRED`, both with `next.decision_ref`. Only `decide` on an
//!   attended session completes it. An expired decision is `DECISION_STALE` and the
//!   operation stays waiting; a same-key retry returns a fresh `decision_ref`
//!   whose delta is recomputed against current policy (code review A06); the
//!   grant reaching its deadline fails the waiting operation with
//!   `CREDENTIAL_EXPIRED` (ADR-0006 §13.3). Equivalent waiting requests share one
//!   record and one grant, each keeping its own operation (code review A07). An
//!   approval is recorded as the intent's `ApprovalBasis` and re-validated before
//!   preparation and activation.
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
//! * ⟨r2.4⟩ ADR-0006 §13.7 item 2 (replaces the earlier empty-delta replacement
//!   record): a waiting added-authority request whose recomputed delta is empty is
//!   covered by the owner's saved standing policy and proceeds as a standing-policy
//!   activation on its same-key retry, with no decision record: every waiter on
//!   the shared grant records a `CoveredBasis` and resumes, the grant moves to
//!   `preparing` (the lifecycle's only edge out of `awaiting_approval` towards
//!   activation, `Approved`), pending records of the waiters are withdrawn, and the
//!   normal time, pause, cutoff, generation and revision checks run at the attempt,
//!   `Recheck` and `Commit`. The grant's source keeps naming the shared request's
//!   owner (so joiners attach to its result); with no approval recorded with the
//!   grant it rests on the standing policy alone.
//! * A request that joined another caller's decision fails with
//!   `CREDENTIAL_EXPIRED` (`next: new_work`) when that request ends without
//!   activating; cancelling a request that joined never touches the shared grant.
//!   ⟨r2.4⟩ §13.7 item 4: cancelling the request that owns a shared **waiting**
//!   grant moves the grant and its pending decision to the oldest remaining waiter
//!   (the decision stays pending); the grant is cancelled, and its decision
//!   withdrawn, only with its last waiter; a deny settles every waiter.
//!   ⟨r2.5⟩ §13.8 item 5: cancelling the owner **after** approval while other
//!   operations remain attached settles the owner's operation `cancelled` with
//!   `may_have_external_effect: true`; the shared preparation continues on the
//!   owner's own receipts and effect token (nothing is handed over mid-effect;
//!   `continues_for_others`), activates the grant without a binding for the owner,
//!   and the attached operations attach as normal (their facts reconciled through
//!   the owner's effect token). When the last attached operation cancels (or
//!   fails), the grant is cancelled (or `released`, if it was already activated
//!   with no binding) and its credential cleaned up through the usual path.
//! * Approval re-bases an added-authority intent on the generation and policy
//!   revision of the decision record it approves (the record was recomputed against
//!   them); preparation and activation refuse when what the grant needs is no
//!   longer within the approved delta. ⟨r2.4⟩ §13.7 item 3: the basis is also
//!   persisted with the grant (`Txn::set_grant_approval`, never purged by
//!   operation retention) and every re-validation of an owner-approved grant
//!   requires its scope ⊆ (current applicable standing policy ∪ approved delta);
//!   a narrowing that removes an uncovered part ends continuing use with the
//!   denial's code (`CREDENTIAL_EXPIRED`), a pause does not.
//! * ⟨r2.4⟩ §13.7 item 5: an environment write moves the authority generation
//!   (`Txn::upsert_environment`), so a change in environment permissions
//!   re-validates; a grant the environment no longer permits ends the same way.
//! * ⟨r2.5⟩ ADR-0006 §13.8 item 4: "ends" for an active or degraded grant whose
//!   re-validation fails means the grant moves to a terminal state when that is
//!   detected, at use (bind, issuance reserve and publish, delegation from it, an
//!   attached binding, and its ancestors with it) and in the scheduler pass
//!   (`tick`): a passed deadline or cutoff (or exhausted continuous budget) ⇒
//!   `expired`; withdrawn authority (a revoke on the chain, a narrowing outside
//!   the approval, a removed environment permission) ⇒ `revoking` with a tombstone
//!   whose cause is `authority_withdrawn` (descendants in its cascade), then
//!   `revoked` once local denial through the adapters is applied, reported in an
//!   `authority_withdrawn` credential-lifecycle event with the residual as for any
//!   revocation. The use itself is refused with the denial's code. A pause never
//!   ends a grant (continuing work does not see it), nothing is ended without
//!   safe time, and a re-validation that cannot be determined (the grant's
//!   context or profile revision cannot be found, or it is pinned to another
//!   environment) refuses the use but ends nothing (fail closed for the use, never
//!   a fabricated withdrawal).
//! * ⟨r2.7⟩ ADR-0006 §13.10 item 2: a credential mechanism that is no longer
//!   configured is not an authority question. Re-validation judges authority
//!   alone (so withdrawal and expiry are still found), and every use checks the
//!   grant's own recorded mechanism: when it is not configured the use is refused
//!   with `CAPABILITY_UNAVAILABLE` and nothing ends, and the grant moves `active →
//!   degraded` with reason `mechanism_unavailable` (in the use's transaction and in
//!   `tick`). Once the mechanism is configured again and re-validation passes
//!   (the chain, plus the grant's own authority re-resolved now), the grant returns
//!   to `active`; a deadline passing or a withdrawal while degraded ends it as
//!   usual.
//! * ⟨r2.7⟩ ADR-0006 §13.10 item 3: what local denial of a revocation leaves
//!   pending remotely is recorded per tombstoned root
//!   (`PendingRemoteRevocation`); the start-up and per-pass sweep never calls the
//!   adapters again for it. Further rounds come only from the supervisor's single
//!   retry owner on its bounded, jittered schedule
//!   ([`Operations::retry_remote_revocation`]), capped, after which the grant stays
//!   `revoking` with the record visible and nothing is called or reported until an
//!   explicit `revoke` (which starts a fresh record) or a round that finds nothing
//!   pending.
//! * ⟨r2.9⟩ ADR-0006 §13.12 (review round 4 T01, T02): every adapter round of a
//!   pending remote revocation is claimed in a committed transaction before any
//!   adapter is called (`attempts + 1`, `claimed_at`), so a round whose completion
//!   fails or never runs still counts and the cap bounds the calls whatever fails;
//!   an explicit revoke calls the adapters only in the drive that wrote its
//!   tombstone. The record keeps each unresolved obligation per grant and
//!   responsible adapter (from the grant's recovery intents and receipts); a round
//!   asks only that adapter, and only its confirmation clears the obligation. With
//!   it not configured the obligation stays pending (`adapter_unavailable`), the
//!   round calls nothing and consumes no attempt, and the grant stays `revoking`
//!   until every obligation has cleared.

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
use heimdall_domain::grant::{AuthorizationSource, DegradedReason, GrantOrigin, GrantSnapshot};
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
    AdapterIdentity, ApprovalBasis, CancellationRecord, CoveredBasis, EffectClass, EffectReceipt,
    OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata, ResolvedIntent, StageReceipt,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::ProfileSnapshot;
use heimdall_domain::revocation::{
    PendingRemoteRevocation, RemoteObligation, RemotePendingReason, RevocationCause, Tombstone,
};
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
use crate::timegate::{SafeNow, TimeGate, TxnGate, uncertain};

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

/// Publication attempts for one reservation when only an unrelated generation move
/// voids it (ADR-0006 §13.6 item 11): the original reservation and each
/// re-reservation handed back to the issuer, counted across `publish_issuance`
/// round trips (§13.8 item 1).
const PUBLISH_ATTEMPTS: usize = 3;

/// Suggested retry delay when the generation kept moving during publication.
const PUBLISH_RETRY_MS: u64 = 1_000;

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
    /// found after a restart is never published (ADR-0005 §3.5). With each, its
    /// grant and its publication attempt: 1 for a reservation, one more for each
    /// re-reservation handed back to the issuer (ADR-0006 §13.8 item 1).
    reserved_here: Mutex<HashMap<IssuanceId, (GrantId, usize)>>,
    /// ⟨r2.10⟩ ADR-0006 §13.13 item 4: the roots whose pending remote record
    /// carried a claimed but uncompleted round when this runtime started (a crash
    /// between a round's claim and its completion). Read before restart recovery
    /// runs; a root leaves the set in the transaction of the next round this process
    /// claims for it, so a claim of this process is never mistaken for one.
    interrupted_rounds: Arc<Mutex<BTreeSet<GrantId>>>,
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

/// The applicable policy among several naming the profile and environment whose
/// scope, window and revision resolution uses: the first by ID. Blocks need no
/// preference here, because [`merged_policy`] carries every applicable pause and
/// the earliest cutoff whichever policy is chosen; choosing by ID keeps the
/// pinned revision stable when another applicable policy is paused (ADR-0006
/// §13.6 items 1 and 5).
fn choose_policy(policies: &[StandingPolicy]) -> Option<&StandingPolicy> {
    policies.first()
}

/// The policy view every bound, block and issuance check uses: the chosen policy
/// (scope, window, revision) restricted by **every** applicable policy's pause and
/// cutoff (gap G08; plan §6.3 #2; ADR-0006 §13.6 item 5): the earliest cutoff of
/// any applicable policy bounds the grant, and any applicable pause blocks
/// activation. Never wider than the chosen policy alone.
fn merged_policy(policies: &[StandingPolicy]) -> Option<StandingPolicy> {
    let mut merged = choose_policy(policies)?.clone();
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

/// The policy view for **continuing** work (ADR-0006 §13.6 item 1): the merged
/// view without its pause. A pause blocks new grants and new work bindings only;
/// running grants and their existing bindings continue until `min(deadline,
/// cutoff)` (spec §5.6; ADR-0005 §3.5–§3.7), so re-validation and issuance
/// within an existing grant never see the pause, while every applicable cutoff
/// still bounds them.
fn continuing_policy(policies: &[StandingPolicy]) -> Option<StandingPolicy> {
    let mut view = merged_policy(policies)?;
    view.pause = PauseState::Active;
    Some(view)
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

    /// ⟨r2.7⟩ A grant that moved to `degraded` for `reason` (ADR-0006 §13.10 item
    /// 2): the state change with its reason.
    fn grant_degraded(
        &mut self,
        tx: &mut Txn<'_>,
        g: &GrantSnapshot,
        reason: DegradedReason,
        op: Option<&OperationId>,
    ) -> heimdall_store::Result<()> {
        self.event(
            tx,
            EventType::GrantStateChanged,
            op.cloned(),
            Some(resource("grant", &g.id)),
            serde_json::json!({ "grant_id": g.id, "state": g.state, "reason": reason }),
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
/// revision it rests on, the caller it was resolved for and its mechanism.
///
/// ⟨r2.6⟩ ADR-0006 §13.9 item 2: derived from the grant's own persisted record
/// only: its origin (`Txn::grant_origin`, written when the grant was created), its
/// source, and the approval basis persisted with it (or the covered basis in its
/// origin). No consumer binding and no operation record plays a part, so a parent
/// kept alive only by its delegated child's reference re-validates like any other
/// grant. Every field is `None` only for a grant whose record truly lacks the data
/// (it predates schema version 4 with nothing to backfill from): its re-validation
/// is undetermined (refuse the use, end nothing).
struct GrantContext {
    profile: Option<ProfileId>,
    profile_revision: Option<u64>,
    expected_policy_revision: Option<PolicyRevision>,
    caller: Option<CallerContext>,
    mechanism: Option<String>,
}

fn grant_context(tx: &mut Txn<'_>, grant: &GrantSnapshot) -> heimdall_store::Result<GrantContext> {
    let origin = tx.grant_origin(&grant.id)?;
    // The policy revision the authority rests on: a standing-policy grant's own
    // source revision; an owner-approved grant's approval basis (it re-bases the
    // intent, §13.7 item 1), else the covered basis of a request the saved policy
    // came to cover (§13.7 item 2), else the revision applicable at resolution; a
    // delegated grant's revision at resolution.
    let expected_policy_revision = match &grant.source {
        AuthorizationSource::StandingPolicy { revision } => Some(*revision),
        AuthorizationSource::OwnerDecision { .. } => match tx.grant_approval(&grant.id)? {
            Some(basis) => basis.policy_revision,
            None => origin.as_ref().and_then(|o| match &o.covered {
                Some(c) => c.policy_revision,
                None => o.policy_revision,
            }),
        },
        AuthorizationSource::Delegation { .. } => origin.as_ref().and_then(|o| o.policy_revision),
    };
    Ok(match origin {
        Some(o) => GrantContext {
            profile: Some(o.profile),
            profile_revision: Some(o.profile_revision),
            expected_policy_revision,
            caller: Some(o.caller),
            mechanism: Some(o.mechanism),
        },
        None => GrantContext {
            profile: None,
            profile_revision: None,
            expected_policy_revision,
            caller: None,
            mechanism: None,
        },
    })
}

/// ⟨r2.6⟩ ADR-0006 §13.9 item 2: the origin recorded with a grant created for an
/// operation of `caller` resolved as `r` (`None` without a selected mechanism,
/// which resolution never pins).
fn origin_of(r: &ResolvedIntent, caller: &CallerContext) -> Option<GrantOrigin> {
    Some(GrantOrigin {
        profile: r.profile.clone(),
        profile_revision: r.profile_revision,
        policy_revision: r.policy_revision,
        caller: caller.clone(),
        mechanism: r.adapter.as_ref()?.mechanism.clone(),
        covered: None,
        // ⟨r2.10⟩ Recorded with the first `Attempted` receipt (§13.13 item 1).
        adapter: None,
    })
}

/// ⟨r2.7⟩ ADR-0006 §13.10 item 2: whether the credential mechanism recorded in
/// `grant`'s origin is not configured in this runtime. `false` for a grant without
/// a recorded origin (its re-validation is undetermined instead, which refuses the
/// use on its own).
fn mechanism_unavailable(
    tx: &mut Txn<'_>,
    adapters: &[AdapterInfo],
    grant: &GrantId,
) -> heimdall_store::Result<bool> {
    Ok(tx
        .grant_origin(grant)?
        .is_some_and(|o| !adapters.iter().any(|a| a.identity.mechanism == o.mechanism)))
}

/// ⟨r2.7⟩ ADR-0006 §13.10 item 2: whether a use of `grant` is refused for its
/// mechanism: the mechanism is not configured, or the grant is still `degraded`
/// for that reason (the use's own transaction repairs it first when it can,
/// [`track_mechanism_in`]; a grant still degraded then is refused, fail closed).
fn mechanism_refuses(
    tx: &mut Txn<'_>,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
) -> heimdall_store::Result<bool> {
    Ok(mechanism_unavailable(tx, adapters, &grant.id)?
        || (grant.state == GrantState::Degraded
            && tx.grant_degradation(&grant.id)? == Some(DegradedReason::MechanismUnavailable)))
}

/// The refusal of a use whose grant's credential mechanism is unavailable
/// (ADR-0006 §13.10 item 2): `CAPABILITY_UNAVAILABLE`, nothing ended.
fn mechanism_refusal(grant: &GrantId) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the grant's credential mechanism is unavailable",
    )
    .with_resource("grant", Some(grant.to_string()))
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
/// the **current** policy (every applicable cutoff), tombstones and the parent
/// chain, with the grant's unchanged scope and deadline as the request, no
/// widening and no prompt (spec §5.5 silent repair within saved authority). On
/// success the new validated generation is recorded for every member; any
/// failure denies (`CREDENTIAL_EXPIRED`, `next: new_work`; nothing is recorded).
///
/// ⟨r2.3⟩ §13.6 item 1: this is the check for **continuing** work, so it uses
/// [`continuing_policy`]: a pause never fails it (a pause blocks new grants and
/// new work bindings only, which their own paths refuse with `POLICY_PAUSED`); a
/// cutoff that has passed does (`CREDENTIAL_EXPIRED`, use past the bound).
///
/// Acceptance per authorization source: `StandingPolicy` and `Delegation` grants
/// need `Allowed` (a narrowed policy that no longer covers the grant's scope or
/// window denies); an `OwnerDecision` grant still waiting for its decision needs
/// only "not denied"; ⟨r2.4⟩ an owner-approved one (ADR-0006 §13.7 item 3) needs
/// what it requires beyond the current standing policy to stay within the approved
/// delta persisted with the grant (`Txn::grant_approval`, which operation retention
/// never purges), so a narrowing that removes a part the approval did not cover
/// ends it; pause, cutoff, parent and role rules apply to every source.
fn revalidate_chain(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    now: Timestamp,
) -> heimdall_store::Result<Result<Validated, OpError>> {
    Ok(revalidate_chain_verdict(tx, environment, adapters, grant, now)?.map_err(|f| f.error))
}

/// A failed re-validation, and whether it shows the authority **withdrawn**
/// (ADR-0006 §13.8 item 4: a tombstone on the chain, an ended or missing ancestor,
/// a resolution that now denies or needs authority beyond the standing policy and
/// the recorded approval) or only that it could not be determined (the grant's
/// context or profile revision cannot be found, or its deadline passed, which the
/// caller classifies as expiry). ⟨r2.7⟩ The credential mechanism plays no part
/// (ADR-0006 §13.10 item 2: [`mechanism_refuses`] judges it at every use).
struct RevalidationFailure {
    error: OpError,
    withdrawn: bool,
}

/// [`revalidate_chain`] with the failure classified ([`RevalidationFailure`]).
fn revalidate_chain_verdict(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    now: Timestamp,
) -> heimdall_store::Result<Result<Validated, RevalidationFailure>> {
    let withdrawn = |msg: &str| RevalidationFailure {
        error: revalidation_failed(msg),
        withdrawn: true,
    };
    let current = tx.authority_generation()?;
    if tx.denied_ancestor(&grant.id)?.is_some() {
        return Ok(Err(withdrawn("the grant or an ancestor was revoked")));
    }
    let chain = ancestry(tx, grant)?;
    if grant.parent.is_some() && chain.is_empty() {
        return Ok(Err(withdrawn("the parent grant is missing")));
    }
    let mut parent: Option<GrantSnapshot> = None;
    let mut members: Vec<GrantSnapshot> = Vec::with_capacity(chain.len() + 1);
    let mut revalidated: Vec<GrantId> = Vec::new();
    for g in chain.iter().rev().chain(std::iter::once(grant)) {
        if g.state.is_terminal() {
            return Ok(Err(withdrawn("the grant or an ancestor has ended")));
        }
        if validated_generation(tx, g)? != current {
            if let Err(f) =
                revalidate_one_verdict(tx, environment, adapters, g, parent.as_ref(), current, now)?
            {
                return Ok(Err(f));
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

/// Re-run `resolve_authority` for one chain member (see [`revalidate_chain`]); a
/// failure is classified ([`RevalidationFailure`]): one `resolve_existing` could
/// not even run is undetermined, a decision that no longer covers the grant is a
/// withdrawal.
fn revalidate_one_verdict(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    g: &GrantSnapshot,
    parent: Option<&GrantSnapshot>,
    current: heimdall_domain::policy::AuthorityGeneration,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), RevalidationFailure>> {
    let decision = match resolve_existing(tx, environment, adapters, g, parent, current, now)? {
        Ok(d) => d,
        Err(error) => {
            return Ok(Err(RevalidationFailure {
                error,
                withdrawn: false,
            }));
        }
    };
    let verdict = match (decision, &g.source) {
        (AuthorityDecision::Allowed(_), _) => Ok(()),
        // A grant still waiting for the owner's decision: "not denied" is enough
        // (the pending decision is what would add the delta).
        (AuthorityDecision::ApprovalRequired { .. }, AuthorizationSource::OwnerDecision { .. })
            if waiting(g) =>
        {
            Ok(())
        }
        // ⟨r2.4⟩ §13.7 item 3: continuing use of an owner-approved grant needs its
        // scope ⊆ (current applicable standing policy ∪ the approved delta recorded
        // with the grant), i.e. what it needs beyond the policy stays within that
        // delta. A grant with no recorded approval (a waiting request the standing
        // policy came to cover, §13.7 item 2) rests on the policy alone.
        (
            AuthorityDecision::ApprovalRequired { delta, .. },
            AuthorizationSource::OwnerDecision { .. },
        ) => match tx.grant_approval(&g.id)? {
            Some(basis) if delta_within(&delta, &basis.delta) => Ok(()),
            _ => Err(revalidation_failed(
                "the standing policy and the owner's approval no longer cover the grant",
            )),
        },
        (AuthorityDecision::ApprovalRequired { .. }, _) => Err(revalidation_failed(
            "the standing policy no longer covers the grant",
        )),
        (AuthorityDecision::Denied(_), _) => Err(revalidation_failed(
            "the grant's authority is no longer current",
        )),
    };
    Ok(verdict.map_err(|error| RevalidationFailure {
        error,
        withdrawn: true,
    }))
}

/// The added authority an existing (waiting) grant needs against **current**
/// policy at the current generation (code review A06: every replacement decision
/// is recomputed, never carried across a generation change); empty when the
/// standing policy now covers it all, `None` when its chain no longer validates.
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
            Ok(d) => needed_delta(&d),
            Err(_) => None,
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
    // ⟨r2.7⟩ ADR-0006 §13.10 item 2: authority does not depend on whether the
    // grant's credential mechanism is configured right now. Re-validation judges
    // authority alone (so a withdrawal or an expiry is still found for a grant whose
    // mechanism is gone); the mechanism is judged separately at every use
    // ([`mechanism_unavailable`]), which refuses it and degrades the grant. Without
    // caller minimums the destination record only has to exist, so a mechanism
    // that is not configured is described with `Unknown` enforcement.
    let mechanism = ctx.mechanism.unwrap_or_default();
    let scope_enforcement = adapters
        .iter()
        .find(|a| a.identity.mechanism == mechanism)
        .map_or(DestinationScopeEnforcement::Unknown, |a| {
            a.scope_enforcement
        });
    // ⟨r2.6⟩ §13.9 item 2: the environment is the grant's own (its snapshot); a
    // grant pinned to an environment this runtime does not manage is undetermined.
    if g.environment != *environment {
        return Ok(Err(revalidation_failed(
            "the grant's environment is not managed by this runtime",
        )));
    }
    let env_record = tx
        .environment(&g.environment)?
        .unwrap_or_else(|| unenrolled(&g.environment));
    // Re-validation is for continuing work: the pause does not apply (ADR-0006
    // §13.6 item 1), every applicable cutoff does.
    let policies = tx.policies_for(&profile_id, &g.environment)?;
    let policy = continuing_policy(&policies);
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
                    scope_enforcement,
                    mechanisms: [mechanism.clone()].into_iter().collect(),
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

/// The bound of `grant` inside `tx`: [`grant_bound`] over its ancestors and every
/// applicable policy of `profile`, never later than a bound already persisted
/// for the grant ([`anchor_bound`]).
fn bound_of(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    grant: &GrantSnapshot,
    profile: Option<&ProfileId>,
) -> heimdall_store::Result<Timestamp> {
    let ancestors = ancestry(tx, grant)?;
    let policies = match profile {
        Some(p) => tx.policies_for(p, env)?,
        None => Vec::new(),
    };
    let bound = grant_bound(grant, &ancestors, merged_policy(&policies).as_ref());
    anchor_bound(tx, &grant.id, bound)
}

/// First validation of a grant in this boot anchors it from `safe`; a later
/// earlier bound shortens the anchor (ADR-0005 §3.6). Nothing once `bound` has
/// passed (the checks that follow refuse).
fn first_validation_anchor(
    tx: &mut Txn<'_>,
    gate: &TxnGate,
    gid: &GrantId,
    safe: &SafeNow,
    bound: Timestamp,
) -> heimdall_store::Result<()> {
    if dtime::is_expired(safe.wall(), bound) {
        return Ok(());
    }
    match tx.grant_anchor(gid)? {
        Some(a) if a.anchor.boot_id == safe.anchor.boot_id => {
            let shortened = dtime::shorten(&a, bound);
            if shortened != a {
                tx.set_grant_anchor(&shortened)?;
            }
        }
        _ => {
            gate.anchor_grant(tx, gid, safe, bound)?;
        }
    }
    Ok(())
}

/// What a resolution over an existing grant still needs from an owner decision:
/// the delta, empty when the standing policy covers everything, `None` when
/// denied.
fn needed_delta(decision: &AuthorityDecision) -> Option<AuthorityDelta> {
    match decision {
        AuthorityDecision::ApprovalRequired { delta, .. } => Some(delta.clone()),
        AuthorityDecision::Allowed(_) => Some(AuthorityDelta {
            added_scope: Scope::empty(),
            extra_window: None,
            environment_not_covered: false,
        }),
        AuthorityDecision::Denied(_) => None,
    }
}

/// `needed ⊆ approved`, component-wise (code review A06): no pair, capability,
/// window or uncovered environment beyond what the owner approved.
fn delta_within(needed: &AuthorityDelta, approved: &AuthorityDelta) -> bool {
    needed.added_scope.is_subset_of(&approved.added_scope)
        && needed.extra_window.unwrap_or_default() <= approved.extra_window.unwrap_or_default()
        && (!needed.environment_not_covered || approved.environment_not_covered)
}

/// The operation whose decision record a waiting grant answers to: the creator
/// of an `OwnerDecision` grant (code review A07: equivalent requests join its
/// decision), else `me`.
fn decision_owner(grant: Option<&GrantSnapshot>, me: &OperationId) -> OperationId {
    match grant.map(|g| &g.source) {
        Some(AuthorizationSource::OwnerDecision { operation_id }) => operation_id.clone(),
        _ => me.clone(),
    }
}

/// Whether `op` may change `grant` on its own: false for a caller that joined
/// another caller's equivalent decision (code review A07).
fn owns_grant(grant: &GrantSnapshot, op: &OperationId) -> bool {
    !matches!(&grant.source, AuthorizationSource::OwnerDecision { operation_id } if operation_id != op)
}

/// A grant that has not left the decision stage (`requested`, `awaiting_approval`).
fn waiting(g: &GrantSnapshot) -> bool {
    matches!(
        g.state,
        GrantState::Requested | GrantState::AwaitingApproval
    )
}

/// Nothing beyond the standing policy: no pair, capability or window, and the
/// environment is covered (ADR-0006 §13.7 item 2).
fn delta_is_empty(d: &AuthorityDelta) -> bool {
    d.added_scope.pairs.is_empty()
        && d.added_scope.capabilities.is_empty()
        && d.extra_window.is_none()
        && !d.environment_not_covered
}

/// Every operation still `awaiting_approval` on `grant` (its creator and the
/// requests that joined its decision, code review A07), oldest first (creation
/// time, then ID): the order in which ownership of a shared waiting grant passes on
/// (ADR-0006 §13.7 item 4).
fn waiters_on(tx: &mut Txn<'_>, grant: &GrantId) -> heimdall_store::Result<Vec<OperationRecord>> {
    let mut out = Vec::new();
    for o in tx.open_operations()? {
        if o.state == OperationState::AwaitingApproval
            && tx
                .recovery_intent(&o.id)?
                .and_then(|i| i.resolved)
                .and_then(|r| r.grant)
                .as_ref()
                == Some(grant)
        {
            out.push(o);
        }
    }
    out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(out)
}

/// Every operation other than `except` that is still active (queued, running or
/// awaiting approval) and whose resolved intent pins `grant`: the requests attached
/// to a shared grant (ADR-0006 §13.8 item 5).
fn attached_on(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    except: &OperationId,
) -> heimdall_store::Result<Vec<OperationRecord>> {
    let mut out = Vec::new();
    for o in tx.open_operations()? {
        if o.id != *except
            && tx
                .recovery_intent(&o.id)?
                .and_then(|i| i.resolved)
                .and_then(|r| r.grant)
                .as_ref()
                == Some(grant)
        {
            out.push(o);
        }
    }
    Ok(out)
}

/// The owner named by a shared owner-decision grant's source, if `g` has one.
fn shared_owner(g: &GrantSnapshot) -> Option<&OperationId> {
    match &g.source {
        AuthorizationSource::OwnerDecision { operation_id } => Some(operation_id),
        _ => None,
    }
}

/// ⟨r2.5⟩ ADR-0006 §13.8 item 5: whether `op`, the owner of a shared
/// owner-decision grant whose caller cancelled it **after** approval, still
/// prepares that grant for the operations attached to it: `op` is `cancelled`, its
/// pinned grant is still `preparing` and names `op` as its owner, and another
/// active operation pins the grant. The preparation then continues on `op`'s own
/// receipts and effect token (nothing is handed over mid-effect), although `op`
/// itself stays settled `cancelled` and gets no binding.
fn continues_for_others(tx: &mut Txn<'_>, op: &OperationRecord) -> heimdall_store::Result<bool> {
    if op.state != OperationState::Cancelled {
        return Ok(false);
    }
    let Some(gid) = tx
        .recovery_intent(&op.id)?
        .and_then(|i| i.resolved)
        .and_then(|r| r.grant)
    else {
        return Ok(false);
    };
    let Some(g) = tx.grant(&gid)? else {
        return Ok(false);
    };
    if g.state != GrantState::Preparing || shared_owner(&g) != Some(&op.id) {
        return Ok(false);
    }
    Ok(!attached_on(tx, &gid, &op.id)?.is_empty())
}

/// Whether a stage of `op`'s pipeline may write, for a drive that expects
/// `expected`: the operation is still in that state (a queued one counts as
/// running), or, for a cancelled owner, while its preparation continues for others
/// ([`continues_for_others`]).
fn drivable(
    tx: &mut Txn<'_>,
    op: &OperationRecord,
    expected: OperationState,
) -> heimdall_store::Result<bool> {
    Ok(match expected {
        OperationState::Cancelled => continues_for_others(tx, op)?,
        OperationState::Running => {
            matches!(op.state, OperationState::Running | OperationState::Queued)
        }
        other => op.state == other,
    })
}

/// ⟨r2.5⟩ ADR-0006 §13.8 item 5: after an attached operation of a shared grant
/// whose owner was cancelled post-approval settled (`me`), the grant ends when no
/// attached operation is left to use it: `preparing ⇒ cancelled`, or, if the
/// owner's continued preparation already activated it and no binding references it,
/// `released` (release is never revoke). Returns the grant when its prepared
/// credential needs the usual cleanup (the owner's receipts show a possible
/// effect).
fn end_orphaned_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grant: &GrantId,
    me: &OperationId,
) -> heimdall_store::Result<Option<GrantId>> {
    let Some(mut g) = tx.grant(grant)? else {
        return Ok(None);
    };
    let Some(owner) = shared_owner(&g).cloned() else {
        return Ok(None);
    };
    if owner == *me
        || !tx
            .operation(&owner)?
            .is_some_and(|o| o.state == OperationState::Cancelled)
        || !attached_on(tx, grant, me)?.is_empty()
    {
        return Ok(None);
    }
    let moved = match g.state {
        GrantState::Preparing => grant_try(&mut g, GrantEvent::Cancel),
        GrantState::Active | GrantState::Degraded if tx.grant_references(grant)?.is_empty() => {
            grant_try(&mut g, GrantEvent::LastReferenceReleased)
        }
        _ => false,
    };
    if !moved {
        return Ok(None);
    }
    put_grant(tx, emit, &g, Some(&owner))?;
    let effect = may_have_external_effect(&tx.stage_receipts(&owner)?);
    Ok(effect.then(|| grant.clone()))
}

/// Pending `ApproveAuthority` records that name `op` as their waiting operation.
fn pending_records_of(
    tx: &mut Txn<'_>,
    op: &OperationId,
) -> heimdall_store::Result<Vec<DecisionRecord>> {
    Ok(tx
        .pending_decisions()?
        .into_iter()
        .filter(|d| matches!(&d.kind, DecisionKind::ApproveAuthority { operation, .. } if operation == op))
        .collect())
}

/// Code review A04: the prepared facts against every caller minimum before
/// activation (spec §4.3, §6.5; ADR-0006 §5): the actual offline coverage
/// `min(offline_until, deadline, bound)` reaches the requested `offline_until`;
/// the achieved destination-scope enforcement is at least the requested minimum
/// (`Unknown` never satisfies one); the grant carries every required capability.
/// Never silently weaker access: `CAPABILITY_UNAVAILABLE` (exit 4).
fn unmet_minimum(
    required: &RequiredCapabilities,
    facts: &Facts,
    grant: &GrantSnapshot,
    bound: Timestamp,
) -> Option<OpError> {
    let short = |msg: &str| {
        OpError::new(Code::CapabilityUnavailable, msg.to_owned())
            .with_resource("grant", Some(grant.id.to_string()))
    };
    let end = grant.deadline.effective.min(bound);
    if let Some(minimum) = required.offline_until
        && facts.offline_until.min(end) < minimum
    {
        return Some(short(
            "the prepared credential's offline coverage is shorter than the requested minimum",
        ));
    }
    if let Some(minimum) = required.destination_scope_at_least {
        let achieved = facts.enforcement.destination_scope;
        if achieved == DestinationScopeEnforcement::Unknown || achieved < minimum {
            return Some(short(
                "the prepared credential's destination-scope enforcement is below the requested minimum",
            ));
        }
    }
    if !required.capabilities.is_subset(&grant.scope.capabilities) {
        return Some(short("the prepared credential lacks a required capability"));
    }
    None
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

/// What an activation check admits (ADR-0006 §13.6 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Activation {
    /// A new grant and its new work binding (`Recheck`/`Commit` of an ensure or a
    /// delegation that prepared its own grant).
    NewGrant,
    /// A new work binding attached to an equivalent leader's live grant.
    NewBinding,
    /// Continuing use of an existing binding (`bind`): no new grant, no new
    /// binding, so a pause does not apply.
    Existing,
}

impl Activation {
    fn attached(self) -> bool {
        self != Self::NewGrant
    }
}

/// Re-validate an activation inside the transaction that would write it
/// (the attempt authorizing `prepare`, `Recheck` and `Commit`, and `bind`): grant
/// state, tombstone on the grant or an ancestor, pause/cutoff for a new grant or
/// binding, generation, ancestors, policy revision, deadline, and for approved
/// added authority that the approval still covers what the grant needs (code
/// review A03, A06).
///
/// ⟨r2.3⟩ §13.6 item 1: a new grant or new binding is refused by an applicable
/// pause (`POLICY_PAUSED`) or a cutoff at or before `now` (`POLICY_CUTOFF`)
/// **before** re-validation, so neither is reported as an expiry. Continuing use
/// ([`Activation::Existing`]) ignores the pause and ends at `min(deadline,
/// cutoff)` with `CREDENTIAL_EXPIRED`.
fn activation_refusal(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    intent: &ResolvedIntent,
    grant: &GrantSnapshot,
    now: Timestamp,
    activation: Activation,
) -> heimdall_store::Result<Option<Refusal>> {
    let expected_ok = if activation.attached() {
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
    let policies = tx.policies_for(&intent.profile, environment)?;
    let merged = merged_policy(&policies);
    if activation != Activation::Existing
        && let Some(p) = merged.as_ref()
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
    let current = tx.authority_generation()?;
    let raw = ancestry(tx, grant)?;
    if grant.parent.is_some() && raw.is_empty() {
        return Ok(Some(Refusal::new(
            authority_changed("the parent grant is missing"),
            Some(GrantEvent::PreparationFailed),
        )));
    }
    // An approved added-authority request rests on its approval's generation and
    // policy revision (code review A06); ⟨r2.4⟩ a waiting one the standing policy
    // came to cover entirely rests on the generation and revision at which it did
    // (ADR-0006 §13.7 item 2); anything else on its resolution's.
    let (basis_generation, expected_revision) = match (&intent.approval, &intent.covered) {
        (Some(a), _) => (a.generation, a.policy_revision),
        (None, Some(c)) => (c.generation, c.policy_revision),
        (None, None) => (intent.generation, intent.policy_revision),
    };
    // ADR-0006 §13.5 ruling 2: a generation that moved since the request was
    // resolved (or since the grant or an ancestor was last validated) triggers one
    // silent re-validation; only a change that touches this chain refuses.
    let mut stale = current != basis_generation || validated_generation(tx, grant)? != current;
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
    let policy = merged.as_ref();
    if let Some(expected) = expected_revision {
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
    // Code review A06: the approved record must still describe the authority the
    // grant uses: what it needs beyond current policy now stays within the
    // approved delta (checked even when no generation moved; ⟨r2.4⟩ an environment
    // write now moves it too, ADR-0006 §13.7 item 5).
    if let Some(approval) = &intent.approval
        && matches!(grant.source, AuthorizationSource::OwnerDecision { .. })
    {
        let needed = match resolve_existing(
            tx,
            environment,
            adapters,
            grant,
            ancestors.first(),
            current,
            now,
        )? {
            Ok(d) => needed_delta(&d),
            Err(_) => None,
        };
        if needed.is_none_or(|n| !delta_within(&n, &approval.delta)) {
            return Ok(Some(Refusal::new(
                authority_changed("the approved authority no longer covers the request"),
                Some(GrantEvent::PreparationFailed),
            )));
        }
    }
    // ⟨r2.7⟩ ADR-0006 §13.10 item 2: a grant whose credential mechanism is not
    // configured is refused (`CAPABILITY_UNAVAILABLE`) after every authority check,
    // so a withdrawal or an expiry is still reported as such. A new grant fails its
    // preparation; a live one ends nothing (its use's transaction degrades it,
    // [`track_mechanism_in`]).
    if mechanism_refuses(tx, adapters, grant)? {
        let event = (!activation.attached()).then_some(GrantEvent::PreparationFailed);
        return Ok(Some(Refusal::new(mechanism_refusal(&grant.id), event)));
    }
    Ok(None)
}

/// How an `active` or `degraded` grant whose re-validation failed ends (ADR-0006
/// §13.8 item 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantEnd {
    /// Its deadline, a parent's deadline or an applicable cutoff passed, or its
    /// continuous budget ran out: `expired`.
    Expired,
    /// Its authority was withdrawn (a revoke on its chain, a narrowing outside its
    /// approval, a removed environment permission, or anything else that makes its
    /// re-validation fail): `revoking` with an `authority_withdrawn` tombstone, then
    /// `revoked` once local denial is applied.
    Withdrawn,
}

/// ADR-0006 §13.8 item 4: whether `g` must end now, judged on the gate's accepted
/// observation `safe` inside the caller's transaction. Only an `active` or
/// `degraded` grant ends here (`None` otherwise).
///
/// Independent of what the caller was doing, so every path (a use, the scheduler
/// pass) classifies alike: a passed bound (`min(deadline, ancestors' deadlines,
/// every applicable cutoff)`, never later than the persisted anchor bound) or an
/// expired continuous admission ⇒ `Expired`; a tombstone on the grant or an
/// ancestor, an ancestor no longer usable, or a failed re-validation (§13.5
/// ruling 2, which runs on the pause-free continuing view, ADR-0006 §13.6 item 1)
/// ⇒ `Withdrawn`. A pause is therefore never a reason, and the caller never asks
/// without safe time (uncertain time is no reason either).
fn grant_end(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    gate: &TxnGate,
    g: &GrantSnapshot,
    safe: &SafeNow,
) -> heimdall_store::Result<Option<GrantEnd>> {
    if !g.state.permits_use() {
        return Ok(None);
    }
    let now = safe.wall();
    let ctx = grant_context(tx, g)?;
    let bound = bound_of(tx, env, g, ctx.profile.as_ref())?;
    // ⟨r2.6⟩ §13.9 item 1: only trusted evidence ends a grant: the accepted wall
    // time and the continuous budget, never an unassessed fresh wall reading.
    if dtime::is_expired(now, bound) || gate.expired(tx, &g.id, safe)? {
        return Ok(Some(GrantEnd::Expired));
    }
    if tx.denied_ancestor(&g.id)?.is_some() {
        return Ok(Some(GrantEnd::Withdrawn));
    }
    let ancestors = ancestry(tx, g)?;
    if (g.parent.is_some() && ancestors.is_empty())
        || ancestors.iter().any(|a| !a.state.permits_use())
    {
        return Ok(Some(GrantEnd::Withdrawn));
    }
    // A failure that only shows the authority could not be determined (no context,
    // unknown profile revision) refuses the use but ends nothing: only withdrawn
    // authority does. (⟨r2.7⟩ A mechanism no longer configured degrades the grant
    // instead, `track_mechanism_in`.)
    Ok(match revalidate_chain_verdict(tx, env, adapters, g, now)? {
        Err(f) if f.withdrawn => Some(GrantEnd::Withdrawn),
        _ => None,
    })
}

/// Grants ended in one transaction (ADR-0006 §13.8 item 4). Each withdrawn root
/// with every grant its tombstone covers (itself first): they are `revoking` and
/// still need local denial through the adapters, then completion
/// ([`Operations::complete_withdrawals`]), after the transaction commits.
#[derive(Debug, Default)]
struct Ended {
    withdrawn: Vec<(GrantId, Vec<GrantId>)>,
}

impl Ended {
    fn is_empty(&self) -> bool {
        self.withdrawn.is_empty()
    }

    fn extend(&mut self, other: Self) {
        self.withdrawn.extend(other.withdrawn);
    }
}

/// ADR-0006 §13.8 item 4, on detection: `grant` and then each of its ancestors
/// (nearest first), re-read from the store, end per [`grant_end`] when they are
/// `active` or `degraded` and can no longer be used. `expired` is written here; a
/// withdrawal writes its tombstone (cause `authority_withdrawn`, descendants in its
/// cascade) and moves the grants to `revoking` here, and is completed by the
/// caller after the commit.
#[allow(clippy::too_many_arguments)]
fn end_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    gate: &TxnGate,
    grant: &GrantId,
    safe: &SafeNow,
    op: Option<&OperationId>,
    retention: Duration,
) -> heimdall_store::Result<Ended> {
    let mut ended = Ended::default();
    let mut members = vec![grant.clone()];
    if let Some(g) = tx.grant(grant)? {
        members.extend(ancestry(tx, &g)?.into_iter().map(|a| a.id));
    }
    for id in members {
        let Some(g) = tx.grant(&id)? else {
            continue;
        };
        match grant_end(tx, env, adapters, gate, &g, safe)? {
            None => {}
            Some(GrantEnd::Expired) => {
                let mut g = g;
                if grant_try(&mut g, GrantEvent::DeadlineReached) {
                    put_grant(tx, emit, &g, op)?;
                    emit.event(
                        tx,
                        EventType::CredentialLifecycle,
                        op.cloned(),
                        Some(resource("grant", &g.id)),
                        serde_json::json!({ "grant_id": g.id, "event": "expired" }),
                    )?;
                }
            }
            Some(GrantEnd::Withdrawn) => {
                let mut all = vec![g.id.clone()];
                all.extend(tx.grant_descendants(&g.id)?);
                let generation = tx.authority_generation()?;
                tx.insert_tombstone(&Tombstone {
                    grant: g.id.clone(),
                    cascade: all[1..].to_vec(),
                    generation,
                    revoked_at: safe.wall(),
                    remote_pending: Vec::new(),
                    cause: RevocationCause::AuthorityWithdrawn,
                })?;
                revoke_locally_in(
                    tx,
                    emit,
                    &all,
                    RevocationCause::AuthorityWithdrawn,
                    safe.wall(),
                    op,
                    retention,
                )?;
                ended.withdrawn.push((g.id.clone(), all));
            }
        }
    }
    Ok(ended)
}

/// ⟨r2.7⟩ ADR-0006 §13.10 item 2: keep the state of `grant` truthful about its
/// credential mechanism, judged on the gate's accepted observation `safe` inside
/// the caller's transaction (a use of the grant before its checks run, and the
/// scheduler pass).
///
/// * `active` and its recorded mechanism is not configured ⇒ `degraded` with
///   reason `mechanism_unavailable` ([`Txn::set_grant_degradation`]). Nothing ends:
///   an owner's configuration change can be undone before the deadline, so ending
///   the grant would be irreversible over a reversible cause. Every use is refused
///   meanwhile ([`mechanism_refuses`]).
/// * `degraded` for that reason and the mechanism is configured again ⇒ `active`,
///   but only when re-validation passes: the chain re-validates (§13.5 ruling 2)
///   **and** the grant's own authority is re-resolved now whatever the generation
///   ([`repair_revalidates`]). Otherwise it stays `degraded` and refused.
///
/// A grant that must end ([`grant_end`]: a passed bound or budget, withdrawn
/// authority) is left to [`end_in`]; a grant without a recorded origin is left
/// alone (undetermined). Both directions are reversible; neither touches
/// bindings, references or tombstones.
#[allow(clippy::too_many_arguments)]
fn track_mechanism_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    gate: &TxnGate,
    grant: &GrantId,
    safe: &SafeNow,
    op: Option<&OperationId>,
) -> heimdall_store::Result<()> {
    let Some(mut g) = tx.grant(grant)? else {
        return Ok(());
    };
    if !g.state.permits_use() || tx.grant_origin(grant)?.is_none() {
        return Ok(());
    }
    let unavailable = mechanism_unavailable(tx, adapters, grant)?;
    let degraded_here = g.state == GrantState::Degraded
        && tx.grant_degradation(grant)? == Some(DegradedReason::MechanismUnavailable);
    let event = match (g.state, unavailable) {
        (GrantState::Active, true) => GrantEvent::Degrade,
        (GrantState::Degraded, false) if degraded_here => GrantEvent::Repaired,
        _ => return Ok(()),
    };
    if grant_end(tx, env, adapters, gate, &g, safe)?.is_some() {
        return Ok(());
    }
    if event == GrantEvent::Repaired && !repair_revalidates(tx, env, adapters, &g, safe.wall())? {
        return Ok(());
    }
    grant_to(&mut g, event)?;
    if event == GrantEvent::Degrade {
        let reason = DegradedReason::MechanismUnavailable;
        tx.update_grant_state(&g)?;
        tx.set_grant_degradation(&g.id, reason)?;
        emit.grant_degraded(tx, &g, reason, op)
    } else {
        // `update_grant_state` removes the degradation reason with the state.
        put_grant(tx, emit, &g, op)
    }
}

/// ⟨r2.7⟩ ADR-0006 §13.10 item 2: re-validation for a repair, stricter than the
/// generation-driven one: the chain re-validates as for any use (§13.5 ruling 2),
/// then the grant's own authority is re-resolved against current policy at the
/// current generation even if nothing moved, with the acceptance rules of its
/// authorization source ([`revalidate_one_verdict`]). Records the validation.
fn repair_revalidates(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    g: &GrantSnapshot,
    now: Timestamp,
) -> heimdall_store::Result<bool> {
    let Ok(v) = revalidate_chain_verdict(tx, env, adapters, g, now)? else {
        return Ok(false);
    };
    let current = tx.authority_generation()?;
    if revalidate_one_verdict(tx, env, adapters, g, v.ancestors.first(), current, now)?.is_err() {
        return Ok(false);
    }
    tx.record_grant_validation(&g.id, current)?;
    Ok(true)
}

/// Local denial written with a tombstone (spec §6.7; ADR-0006 §13.8 item 4), in
/// the tombstone's transaction: every grant in `grants` leaves usable states (a
/// waiting one is denied, any other `revoking`, or `revoked` from `preparing`), and
/// every operation waiting for approval on one of them ends now.
fn revoke_locally_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grants: &[GrantId],
    cause: RevocationCause,
    now: Timestamp,
    op: Option<&OperationId>,
    retention: Duration,
) -> heimdall_store::Result<()> {
    for gid in grants {
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
            put_grant(tx, emit, &g, op)?;
            emit.event(
                tx,
                EventType::CredentialLifecycle,
                op.cloned(),
                Some(resource("grant", gid)),
                serde_json::json!({ "grant_id": gid, "event": "revoked_locally", "cause": cause }),
            )?;
        }
    }
    for mut waiting in tx.open_operations()? {
        if waiting.state != OperationState::AwaitingApproval {
            continue;
        }
        let pinned = tx
            .recovery_intent(&waiting.id)?
            .and_then(|i| i.resolved)
            .and_then(|r| r.grant);
        if pinned.is_some_and(|g| grants.contains(&g)) {
            let err = authority_changed("the requested grant was revoked");
            settle_failed(tx, emit, &mut waiting, &err, now, retention)?;
        }
    }
    Ok(())
}

/// The second half of a local revocation, after the adapters were asked to deny
/// locally (spec §6.7): every grant with nothing pending moves `revoking →
/// revoked`, and the result reports what is still pending and the residual
/// (`latest_possible_credential_expiry`: the issuance log's `reserved` and
/// `published` entries ∪ what the adapters reported).
fn complete_revocation_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grants: &[GrantId],
    pending: &BTreeSet<GrantId>,
    adapter_expiry: Option<Timestamp>,
    op: Option<&OperationId>,
) -> heimdall_store::Result<RevokeData> {
    for gid in grants {
        if pending.contains(gid) {
            continue;
        }
        if let Some(mut g) = tx.grant(gid)?
            && grant_try(&mut g, GrantEvent::RevokeComplete)
        {
            put_grant(tx, emit, &g, op)?;
        }
    }
    let residual = tx.issuance_residual(grants)?;
    let latest = match (residual, adapter_expiry) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    Ok(RevokeData {
        local_applied: true,
        remote_pending: pending.iter().cloned().collect(),
        latest_possible_credential_expiry: latest,
    })
}

/// ⟨r2.9⟩ One adapter `revoke()` call of a remote-revocation round (ADR-0006
/// §13.12): the grant and the configured adapter asked about it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundCall {
    grant: GrantId,
    adapter: AdapterIdentity,
}

/// ⟨r2.9⟩ A remote-revocation round planned (and, when it owes a call to an
/// obligation, claimed) in a committed transaction before any adapter is called
/// (ADR-0006 §13.12 item 1).
#[derive(Debug, Clone, Default)]
struct Round {
    /// The calls to make, each once.
    calls: Vec<RoundCall>,
    /// `(claimed_at, attempts)` written by the claim; `None` when this round
    /// claimed no attempt (no call owed to an obligation, or nothing to claim).
    claim: Option<(Timestamp, u32)>,
}

/// ⟨r2.9⟩ What a round's calls answered: `(grant, adapter, confirmed)` per call
/// (`confirmed`: the adapter answered with nothing pending remotely; an error or a
/// pending remote effect is not a confirmation), and the latest credential expiry
/// the adapters reported.
#[derive(Debug, Clone, Default)]
struct RoundAnswers {
    answers: Vec<(GrantId, AdapterIdentity, bool)>,
    adapter_expiry: Option<Timestamp>,
}

/// ⟨r2.10⟩ What `inspect grants` shows of one grant's pending remote part: its own
/// obligations' highest attempt count (ADR-0006 §13.13 item 3), the record's last
/// round, whether its retries stopped (the record, or every obligation of the
/// grant at its cap) and whether a responsible adapter is not configured.
struct RemoteView {
    attempts: u32,
    last_attempt_at: Timestamp,
    stopped: bool,
    unavailable: bool,
}

/// ⟨r2.9⟩ ADR-0006 §13.12 item 2: the adapters responsible for the remote effect
/// of `grant`.
///
/// ⟨r2.10⟩ ADR-0006 §13.13 item 1: first the adapter that prepared the grant,
/// persisted with its origin (mechanism and instance; it survives operation
/// retention). Without it (a grant written before the field existed, or one whose
/// preparation was never attempted): the identities its recovery intents and
/// stage receipts record ([`Txn::grant_adapters`]); when none is left (purged with
/// their settled operations), the grant's recorded origin mechanism with an empty
/// instance, and with no origin either, an empty identity
/// ([`RemoteObligation::served_by`]). Never another mechanism.
fn responsible_adapters(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> heimdall_store::Result<Vec<AdapterIdentity>> {
    let origin = tx.grant_origin(grant)?;
    if let Some(adapter) = origin.as_ref().and_then(|o| o.adapter.clone()) {
        return Ok(vec![adapter]);
    }
    let recorded = tx.grant_adapters(grant)?;
    if !recorded.is_empty() {
        return Ok(recorded);
    }
    Ok(vec![AdapterIdentity {
        mechanism: origin.map(|o| o.mechanism).unwrap_or_default(),
        instance: String::new(),
    }])
}

/// ⟨r2.10⟩ A fresh obligation of `grant` to `adapter` (no attempt counted yet).
fn obligation(grant: &GrantId, adapter: AdapterIdentity) -> RemoteObligation {
    RemoteObligation {
        grant: grant.clone(),
        adapter,
        reason: None,
        attempts: Some(0),
        stopped: false,
    }
}

/// ⟨r2.9⟩ The pending remote record of `root` with its obligations: a record
/// written before ADR-0006 §13.12 (its grant list alone) gains one obligation per
/// grant still `revoking` and responsible adapter ([`responsible_adapters`]); a
/// grant of such a record that left `revoking` has nothing left to complete.
///
/// ⟨r2.10⟩ ADR-0006 §13.13 item 3: every obligation carries its own attempt
/// count; one recorded before per-obligation counts existed is read with the
/// record's count (and stop), conservatively, as those rounds were already used.
fn load_remote_record(
    tx: &mut Txn<'_>,
    root: &GrantId,
) -> heimdall_store::Result<Option<PendingRemoteRevocation>> {
    let Some(mut r) = tx.remote_revocation(root)? else {
        return Ok(None);
    };
    if r.obligations.is_empty() {
        for g in r.grants.clone() {
            if !tx
                .grant(&g)?
                .is_some_and(|s| s.state == GrantState::Revoking)
            {
                continue;
            }
            for adapter in responsible_adapters(tx, &g)? {
                r.obligations.push(RemoteObligation {
                    attempts: None,
                    ..obligation(&g, adapter)
                });
            }
        }
    }
    let (attempts, stopped) = (r.attempts, r.stopped);
    for o in &mut r.obligations {
        if o.attempts.is_none() {
            o.attempts = Some(attempts);
            o.stopped |= stopped;
        }
    }
    Ok(Some(r))
}

/// `grants` = the grants that still have an obligation, in obligation order.
fn sync_obligation_grants(r: &mut PendingRemoteRevocation) {
    let mut grants: Vec<GrantId> = Vec::new();
    for o in &r.obligations {
        if !grants.contains(&o.grant) {
            grants.push(o.grant.clone());
        }
    }
    r.grants = grants;
}

fn push_call(calls: &mut Vec<RoundCall>, grant: &GrantId, adapter: &AdapterIdentity) {
    let call = RoundCall {
        grant: grant.clone(),
        adapter: adapter.clone(),
    };
    if !calls.contains(&call) {
        calls.push(call);
    }
}

/// ⟨r2.9⟩ ADR-0006 §13.12 item 2: the calls a round owes `obligations`, each to
/// the configured adapters responsible for it and to no other. An obligation whose
/// responsible adapter is not configured gets no call and the reason
/// `adapter_unavailable`; one that is called loses any reason.
///
/// ⟨r2.10⟩ ADR-0006 §13.13 item 3: an obligation that reached its own cap
/// (`stopped`, or `max_attempts` rounds counted) gets no call; every obligation
/// that gets one counts this round (the caller claims it before any call).
fn plan_obligation_calls(
    obligations: &mut [RemoteObligation],
    configured: &[AdapterIdentity],
    max_attempts: Option<u32>,
    calls: &mut Vec<RoundCall>,
) {
    for o in obligations {
        let counted = o.attempts.unwrap_or(0);
        if o.stopped || max_attempts.is_some_and(|m| counted >= m) {
            continue;
        }
        let mut served = false;
        for a in configured.iter().filter(|a| o.served_by(a)) {
            push_call(calls, &o.grant, a);
            served = true;
        }
        o.reason = (!served).then_some(RemotePendingReason::AdapterUnavailable);
        if served {
            o.attempts = Some(counted.saturating_add(1));
        }
    }
}

/// ⟨r2.10⟩ ADR-0006 §13.13 item 3: mark every obligation that reached
/// `max_attempts` rounds `stopped`; the record is `stopped` only when every
/// obligation left is.
fn stop_capped_obligations(r: &mut PendingRemoteRevocation, max_attempts: u32) {
    let record = r.attempts;
    for o in &mut r.obligations {
        if o.attempts.unwrap_or(record) >= max_attempts {
            o.stopped = true;
        }
    }
    if !r.obligations.is_empty() && r.obligations.iter().all(|o| o.stopped) {
        r.stopped = true;
    }
}

/// ⟨r2.10⟩ ADR-0006 §13.13 item 4: `root`'s next round is claimed by this
/// process (inside the claiming transaction), so its record no longer carries a
/// round a previous run left uncompleted.
fn forget_interrupted(interrupted: &Mutex<BTreeSet<GrantId>>, root: &GrantId) {
    interrupted
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(root);
}

/// ⟨r2.9⟩ ADR-0006 §13.12: plan and claim the first local denial of the
/// revocation rooted at `root` (`grants`: the root, then the descendants its
/// tombstone covers) inside the caller's transaction, which commits before any
/// adapter is called (an explicit revoke's tombstone transaction, or a
/// withdrawal's own claim).
///
/// Every grant now `revoking` owes each of its responsible adapters a confirmation
/// (an obligation, kept with any the record already holds). ⟨r2.10⟩ ADR-0006
/// §13.13 item 2: a grant that already left usable states another way (`preparing
/// → revoked`, a denied waiting grant) is asked of each responsible adapter that
/// is configured, and each such call is an obligation too, recorded here before
/// the call: only that adapter's confirmation clears it, a pending answer keeps
/// it and the supervisor retries it (no untracked one-off call). When any call is
/// owed the round is claimed: `attempts + 1` and `claimed_at` (§13.12 item 1),
/// and each called obligation counts it (§13.13 item 3); a round with no call
/// consumes no attempt. `rearm` (an authorized explicit revoke, ADR-0006 §13.11
/// item 4) restarts every count, lifts every stop and supersedes an unfinished
/// claim first. The record is written when any obligation exists.
fn claim_first_round_in(
    tx: &mut Txn<'_>,
    root: &GrantId,
    grants: &[GrantId],
    configured: &[AdapterIdentity],
    now: Timestamp,
    rearm: bool,
) -> heimdall_store::Result<Round> {
    let mut record = load_remote_record(tx, root)?.unwrap_or(PendingRemoteRevocation {
        root: root.clone(),
        grants: Vec::new(),
        attempts: 0,
        last_attempt_at: now,
        stopped: false,
        obligations: Vec::new(),
        claimed_at: None,
    });
    if rearm {
        record.attempts = 0;
        record.stopped = false;
        record.claimed_at = None;
        for o in &mut record.obligations {
            o.attempts = Some(0);
            o.stopped = false;
        }
    }
    for g in grants {
        let revoking = tx
            .grant(g)?
            .is_some_and(|s| s.state == GrantState::Revoking);
        for adapter in responsible_adapters(tx, g)? {
            let owed = obligation(g, adapter);
            let tracked = revoking || configured.iter().any(|a| owed.served_by(a));
            if tracked
                && !record
                    .obligations
                    .iter()
                    .any(|o| o.grant == owed.grant && o.adapter == owed.adapter)
            {
                record.obligations.push(owed);
            }
        }
    }
    let mut calls = Vec::new();
    plan_obligation_calls(&mut record.obligations, configured, None, &mut calls);
    if record.obligations.is_empty() {
        return Ok(Round { calls, claim: None });
    }
    let mut claim = None;
    if !calls.is_empty() {
        record.attempts = record.attempts.saturating_add(1);
        record.claimed_at = Some(now);
        record.last_attempt_at = now;
        claim = Some((now, record.attempts));
    }
    sync_obligation_grants(&mut record);
    tx.set_remote_revocation(&record)?;
    Ok(Round { calls, claim })
}

/// ⟨r2.9⟩ What a retry round's claim found (ADR-0006 §13.12).
enum RetryClaim {
    /// Nothing pending any more: the record (if any) was removed.
    Gone,
    /// No adapter is called: the record is stopped, reached the cap (now
    /// `stopped`), or no responsible adapter is configured (no attempt consumed).
    Unchanged(PendingRemoteRevocation),
    /// A round was claimed; the grants it concerns.
    Claimed(Round, Vec<GrantId>),
}

/// ⟨r2.9⟩ ADR-0006 §13.12: claim a retry round of the revocation rooted at
/// `root` in its own transaction, before any adapter is called: `attempts + 1`,
/// `claimed_at`, and the calls owed to each obligation's responsible adapter. A
/// stopped record, one whose every obligation reached its cap (stopped now) or
/// one whose callable obligations' responsible adapters are all unconfigured
/// (reason `adapter_unavailable`, no attempt consumed) is returned without a
/// claim. A record written before §13.12 whose grants all left `revoking` has
/// nothing left to complete and is removed.
///
/// ⟨r2.10⟩ ADR-0006 §13.13: the cap is applied per obligation (item 3): an
/// obligation at its cap is stopped and gets no call while the others continue,
/// each within its own cap; an obligation of a grant in any state is kept until
/// its adapter confirms (item 2).
fn claim_retry_round_in(
    tx: &mut Txn<'_>,
    root: &GrantId,
    configured: &[AdapterIdentity],
    now: Timestamp,
    max_attempts: u32,
) -> heimdall_store::Result<RetryClaim> {
    let stored = tx.remote_revocation(root)?;
    let Some(mut r) = load_remote_record(tx, root)? else {
        return Ok(RetryClaim::Gone);
    };
    if r.obligations.is_empty() {
        tx.clear_remote_revocation(root)?;
        return Ok(RetryClaim::Gone);
    }
    sync_obligation_grants(&mut r);
    if r.stopped {
        return Ok(RetryClaim::Unchanged(r));
    }
    stop_capped_obligations(&mut r, max_attempts);
    if r.stopped {
        tx.set_remote_revocation(&r)?;
        return Ok(RetryClaim::Unchanged(r));
    }
    let mut calls = Vec::new();
    plan_obligation_calls(
        &mut r.obligations,
        configured,
        Some(max_attempts),
        &mut calls,
    );
    if calls.is_empty() {
        if stored.as_ref() != Some(&r) {
            tx.set_remote_revocation(&r)?;
        }
        return Ok(RetryClaim::Unchanged(r));
    }
    r.attempts = r.attempts.saturating_add(1);
    r.claimed_at = Some(now);
    r.last_attempt_at = now;
    tx.set_remote_revocation(&r)?;
    let grants = r.grants.clone();
    Ok(RetryClaim::Claimed(
        Round {
            calls,
            claim: Some((now, r.attempts)),
        },
        grants,
    ))
}

/// ⟨r2.9⟩ ADR-0006 §13.12: complete a round of the revocation rooted at `root` in
/// one transaction. An obligation is cleared only when an adapter responsible for
/// it confirmed in `answers` (and every responsible adapter asked confirmed);
/// another adapter's answer, or no answer, clears nothing. When the record still
/// carries this round's claim, the claim is completed (`claimed_at` cleared) and,
/// with `max_attempts` given, ⟨r2.10⟩ each obligation that reached its own cap is
/// `stopped`, the record only once every obligation left is (ADR-0006 §13.13
/// item 3). Every grant of `grants` with no obligation left (in this record or
/// another root's) moves `revoking → revoked`; the record is removed once no
/// obligation is left. The result reports the grants still pending (obligations,
/// plus any call that was not confirmed) and the residual
/// ([`complete_revocation_in`]).
#[allow(clippy::too_many_arguments)]
fn complete_round_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    root: &GrantId,
    grants: &[GrantId],
    claim: Option<(Timestamp, u32)>,
    answers: &RoundAnswers,
    max_attempts: Option<u32>,
    op: Option<&OperationId>,
) -> heimdall_store::Result<RevokeData> {
    let confirmed = |o: &RemoteObligation| {
        let mut asked = false;
        for (g, a, ok) in &answers.answers {
            if g == &o.grant && o.served_by(a) {
                if !ok {
                    return false;
                }
                asked = true;
            }
        }
        asked
    };
    let mut pending: BTreeSet<GrantId> = BTreeSet::new();
    if let Some(mut r) = load_remote_record(tx, root)? {
        r.obligations.retain(|o| !confirmed(o));
        if let Some((at, attempts)) = claim
            && r.claimed_at == Some(at)
            && r.attempts == attempts
        {
            r.claimed_at = None;
            if let Some(m) = max_attempts {
                stop_capped_obligations(&mut r, m);
            }
        }
        pending.extend(r.obligations.iter().map(|o| o.grant.clone()));
        if r.obligations.is_empty() {
            tx.clear_remote_revocation(root)?;
        } else {
            sync_obligation_grants(&mut r);
            tx.set_remote_revocation(&r)?;
        }
    }
    for (g, _, ok) in &answers.answers {
        if !ok {
            pending.insert(g.clone());
        }
    }
    // A grant leaves `revoking` only when every obligation on it has cleared,
    // including one held by another root's record (a descendant withdrawn on its
    // own before its ancestor was revoked).
    for r in tx.remote_revocations()? {
        if &r.root != root {
            pending.extend(r.grants.into_iter().filter(|g| grants.contains(g)));
        }
    }
    complete_revocation_in(tx, emit, grants, &pending, answers.adapter_expiry, op)
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
    let policy = merged_policy(&policies);
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
    // ⟨r2.7⟩ ADR-0006 §13.10 item 2: delegation is a use of the parent; a parent
    // whose credential mechanism is unavailable is refused (after the authority
    // decision, so a denial keeps its own code) and ends nothing.
    if let Some(p) = &parent
        && !matches!(decision, AuthorityDecision::Denied(_))
        && mechanism_refuses(tx, &inp.adapters, p)?
    {
        refuse!(mechanism_refusal(&p.id));
    }
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
            approval: None,
            covered: None,
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
                approval: None,
                covered: None,
            };
            Ok(Resolution::Approval(Box::new(Approval {
                intent,
                grant,
                delta,
            })))
        }
    }
}

/// Code review A07: the grant of an equivalent request already waiting for an
/// owner decision, which a new request joins instead of creating another record
/// (spec §5.5 "one coalesced approval request for one logical decision";
/// R-UX-06). Equivalent means the same caller, operation kind, environment, work
/// ID and parent binding; the same resolved profile revision, scope, mechanism,
/// policy revision and effective deadline at the current authority generation; and
/// a pending, unexpired record for exactly the same delta. A broader or longer
/// request, other work or another caller never joins.
fn equivalent_waiting(
    tx: &mut Txn<'_>,
    op: &OperationRecord,
    spec: &WorkSpec,
    resolved: &ResolvedIntent,
    delta: &AuthorityDelta,
    now: Timestamp,
) -> heimdall_store::Result<Option<GrantId>> {
    let current = tx.authority_generation()?;
    if resolved.generation != current {
        return Ok(None);
    }
    for d in tx.pending_decisions()? {
        let DecisionKind::ApproveAuthority {
            operation,
            delta: recorded,
        } = &d.kind
        else {
            continue;
        };
        if now >= d.expires_at || d.generation != current || recorded != delta {
            continue;
        }
        let Some(other) = tx.operation(operation)? else {
            continue;
        };
        if other.state != OperationState::AwaitingApproval
            || other.kind != op.kind
            || other.environment != op.environment
            || other.key.caller != op.key.caller
        {
            continue;
        }
        let Some(intent) = tx.recovery_intent(operation)? else {
            continue;
        };
        let same_work = serde_json::from_value::<Request>(intent.request)
            .ok()
            .and_then(|r| WorkSpec::from_request(&r, &op.environment))
            .is_some_and(|w| {
                w.work_id == spec.work_id
                    && w.parent_binding == spec.parent_binding
                    && w.environment == spec.environment
            });
        let Some(theirs) = intent.resolved else {
            continue;
        };
        if !same_work
            || theirs.profile != resolved.profile
            || theirs.profile_revision != resolved.profile_revision
            || theirs.scope != resolved.scope
            || theirs.deadline.effective != resolved.deadline.effective
            || theirs.adapter != resolved.adapter
            || theirs.policy_revision != resolved.policy_revision
            || theirs.generation != resolved.generation
        {
            continue;
        }
        let Some(gid) = theirs.grant else {
            continue;
        };
        if tx
            .grant(&gid)?
            .is_some_and(|g| g.state == GrantState::AwaitingApproval)
        {
            return Ok(Some(gid));
        }
    }
    Ok(None)
}

/// What a request waiting for an owner decision answers (`awaiting_response`).
enum Awaiting {
    /// Still waiting (`decision_ref`), paused, or ended: the answer.
    Answer(Box<OpError>),
    /// ⟨r2.4⟩ ADR-0006 §13.7 item 2: the saved standing policy now covers the
    /// request entirely; these waiters resumed (the shared grant's owner first) and
    /// are driven through the normal pipeline.
    Proceed(Vec<OperationId>),
}

/// The outcome of the waiting check's transaction.
enum Waiting {
    /// The operation is no longer `awaiting_approval`.
    Left,
    /// The pending record that answers for it.
    Decision(heimdall_contract::ids::DecisionId),
    /// See [`Awaiting::Proceed`].
    Proceed(Vec<OperationId>),
}

/// ⟨r2.4⟩ ADR-0006 §13.7 item 2, inside the waiting check's transaction (time
/// already assessed, pause already refused, `grant`'s chain re-validated at
/// `current` with an empty recomputed delta): the waiting request proceeds as a
/// standing-policy activation and gets no decision record.
///
/// Every waiter on the shared grant (its owner first, then the requests that joined
/// it, oldest first) records a [`CoveredBasis`] (`current` and the applicable
/// policy revision) and leaves `awaiting_approval`; the grant moves to `preparing`
/// (its source keeps naming the owner, so joiners still attach to the owner's
/// result; with no approval recorded with the grant, re-validation needs the
/// standing policy alone); every pending record of the waiters is withdrawn. No
/// effect is attempted here: the attempt, `Recheck` and `Commit` re-check time,
/// pause, cutoff, generation, revision, bound and admission as for any activation.
#[allow(clippy::too_many_arguments)]
fn proceed_covered(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    env: &EnvironmentId,
    grant: &GrantSnapshot,
    owner: &OperationId,
    profile: &ProfileId,
    current: heimdall_domain::policy::AuthorityGeneration,
    now: Timestamp,
) -> heimdall_store::Result<Vec<OperationId>> {
    let revision = merged_policy(&tx.policies_for(profile, env)?)
        .filter(|p| &p.profile == profile)
        .map(|p| p.revision);
    let basis = CoveredBasis {
        generation: current,
        policy_revision: revision,
    };
    let mut waiters = waiters_on(tx, &grant.id)?;
    // The owner leads the preparation; the others attach to its result. An owner
    // that no longer waits hands the grant to the oldest waiter first (§13.7 item
    // 4), so no joiner is left attached to a request that will never activate.
    let previous = owner;
    let owner = match waiters.first() {
        Some(first)
            if waiters.iter().all(|o| o.id != *previous)
                && matches!(&grant.source, AuthorizationSource::OwnerDecision { operation_id } if operation_id == previous) =>
        {
            tx.transfer_waiting_grant(&grant.id, previous, &first.id)?;
            first.id.clone()
        }
        _ => previous.clone(),
    };
    let owner = &owner;
    waiters.sort_by_key(|o| o.id != *owner);
    // No record is issued for, or left pending on, a request the policy covers.
    if waiters.iter().all(|o| o.id != *previous) {
        for d in pending_records_of(tx, previous)? {
            let withdrawn = tx.withdraw_decision(&d.id)?;
            emit.decision(tx, &withdrawn, Some(owner))?;
        }
    }
    let mut g = grant.clone();
    if grant_try(&mut g, GrantEvent::Approved) {
        put_grant(tx, emit, &g, Some(owner))?;
    }
    // ⟨r2.6⟩ §13.9 item 2: the covered basis is part of the grant's own record.
    tx.set_grant_covered(&grant.id, &basis)?;
    let mut resumed = Vec::with_capacity(waiters.len());
    for mut op in waiters {
        for d in pending_records_of(tx, &op.id)? {
            let withdrawn = tx.withdraw_decision(&d.id)?;
            emit.decision(tx, &withdrawn, Some(&op.id))?;
        }
        let mut intent = tx
            .recovery_intent(&op.id)?
            .ok_or_else(|| conflict("operation has no recovery intent"))?;
        if let Some(r) = intent.resolved.as_mut() {
            r.covered = Some(basis.clone());
        }
        tx.set_recovery_intent(&op.id, &intent)?;
        op_to(&mut op, OperationEvent::Approved, now)?;
        tx.update_operation(&op)?;
        emit.op(tx, &op)?;
        resumed.push(op.id);
    }
    Ok(resumed)
}

/// Durable state of one operation.
struct WorkState {
    op: OperationRecord,
    intent: RecoveryIntent,
    receipts: Vec<StageReceipt>,
    /// ⟨r2.5⟩ A cancelled owner whose preparation continues for the operations
    /// attached to its grant ([`continues_for_others`], ADR-0006 §13.8 item 5).
    continuing: bool,
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

/// The transaction authorizing an effect attempt (A03).
enum Attempt {
    /// Authorized: the `Attempted` receipt is durable; prepare this bounded grant.
    Go(Box<GrantSnapshot>, Timestamp),
    /// Time is uncertain: nothing recorded, the operation stays running.
    Uncertain(dtime::TimeUncertainty),
    /// The grant could not be anchored in this boot: nothing recorded.
    Unanchored,
    /// Refused and settled (the grant or an ancestor may have to end, ADR-0006
    /// §13.8 item 4).
    Refused,
    /// No longer running.
    Stop,
}

/// Outcome of a `Recheck` or `Commit` transaction.
enum Checked {
    /// Passed (receipt written / activated).
    Passed,
    /// Time is uncertain: nothing written, the operation stays where it is.
    Uncertain(dtime::TimeUncertainty),
    /// The grant could not be anchored in this boot: nothing written.
    Unanchored,
    /// Refused and settled; the grant's prepared credential may need cleanup, and
    /// a shared grant left without attached operations (ADR-0006 §13.8 item 5)
    /// may need the usual cleanup of its owner's credential.
    Refused(GrantId, Option<GrantId>),
    /// The operation is no longer in the expected state.
    Stop,
}

/// `TIME_UNCERTAIN` for a grant with no usable anchor in this boot.
fn unanchored() -> OpError {
    OpError::new(
        Code::TimeUncertain,
        "time uncertain: the grant must be re-anchored before activation",
    )
    .with_resource("clock", None)
}

/// How a request that joined another caller's decision continues (A07).
enum Joined {
    Attached(Box<EnsureData>),
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 5: attached to a grant its cancelled owner
    /// prepared, with the facts reconciled through the owner's effect token.
    Prepared(Box<PrepareOutcome>),
    Pending,
    Stop,
}

/// Drive-local facts; all of them are re-derived after a restart.
#[derive(Default)]
struct DriveLocal {
    prepared: Option<PrepareOutcome>,
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
            interrupted_rounds: Arc::new(Mutex::new(BTreeSet::new())),
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
            let continuing = continues_for_others(tx, &op)?;
            Ok(Some(WorkState {
                op,
                intent,
                receipts,
                continuing,
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
        // ⟨r2.10⟩ ADR-0006 §13.13 item 4: remember, before anything below can claim
        // a round, which pending remote records a previous run left with a claimed
        // but uncompleted round; the supervisor runs those at once. Best effort: an
        // unreadable record keeps its normal back-off.
        match self
            .write(|tx, _| {
                Ok(tx
                    .remote_revocations()?
                    .into_iter()
                    .filter(|r| r.claimed_at.is_some())
                    .map(|r| r.root)
                    .collect::<BTreeSet<GrantId>>())
            })
            .await
        {
            Ok(claimed) => {
                *self
                    .inner
                    .interrupted_rounds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = claimed;
            }
            Err(e) => {
                tracing::warn!(code = %e.code, "interrupted remote revocation rounds could not be read");
            }
        }
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
        // ⟨r2.6⟩ ADR-0006 §13.9 item 3: withdrawals interrupted between their
        // tombstone and their completion complete now (after the open revoke
        // operations above completed their own).
        self.complete_interrupted_withdrawals().await;
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

    /// [`Self::lead`] behind a type-erased future, for the one place a drive
    /// follows another operation's drive (a request that joined another caller's
    /// decision, A07): the erasure keeps the futures' types from recursing.
    fn lead_boxed(
        &self,
        id: OperationId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), OpError>> + Send>> {
        let me = self.clone();
        Box::pin(async move { me.lead(&id, false).await })
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

    /// ⟨r2.5⟩ ADR-0006 §13.8 item 2: resume every operation in `ids` at once (each
    /// led in its own spawned task, `(id, interactive)`, so a caller's timeout never
    /// stops the work) and wait for them **together** at most `wait`: one bound for
    /// the whole request, never one per operation. Each entry is that operation's
    /// drive result when it finished within the bound, `None` otherwise (it keeps
    /// running and stays observable).
    async fn lead_all_bounded(
        &self,
        ids: &[(OperationId, bool)],
        wait: Duration,
    ) -> Vec<Option<Result<(), OpError>>> {
        let tasks: Vec<_> = ids
            .iter()
            .map(|(id, interactive)| {
                let me = self.clone();
                let id = id.clone();
                let interactive = *interactive;
                tokio::spawn(async move { me.lead(&id, interactive).await })
            })
            .collect();
        let deadline = tokio::time::Instant::now() + wait;
        let mut out = Vec::with_capacity(tasks.len());
        for task in tasks {
            out.push(match tokio::time::timeout_at(deadline, task).await {
                Ok(Ok(r)) => Some(r),
                Ok(Err(e)) => Some(Err(join_error(e))),
                Err(_) => None,
            });
        }
        out
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
                // ⟨r2.5⟩ ADR-0006 §13.8 item 5: the shared preparation of a
                // cancelled owner continues for the operations attached to it.
                OperationState::Cancelled if st.continuing => OperationState::Cancelled,
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
                EnsureStage::Coalesce => self.stage_coalesce(&st, expected, local).await?,
                EnsureStage::Reconcile => {
                    self.stage_reconcile(&st, &spec, interactive, local).await?
                }
                EnsureStage::Probe => self.stage_receipt(id, stage, expected).await?,
                EnsureStage::Recheck => self.stage_recheck(&st, expected).await?,
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
            if !drivable(tx, &op, expected)? {
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
        let gate = self.inner.timegate.in_txn();
        let mut inp = ResolveInput {
            spec: spec.clone(),
            caller: st.op.key.caller.clone(),
            operation: st.op.id.clone(),
            environment: self.inner.config.environment.clone(),
            now: self.inner.config.clock.wall(),
            default_window: self.inner.config.default_window,
            adapters: self.adapter_infos(),
            grant_id: crate::ids::new_grant_id()?,
        };
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let retention = self.retention();
        let id = st.op.id.clone();
        let none = Ended::default;
        let (flow, ended) = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id)? else {
                    return Ok((Ok(Flow::Stop), none()));
                };
                if op.state != OperationState::Queued {
                    return Ok((Ok(Flow::Stop), none()));
                }
                // Resolution and the decision record it may create use time assessed
                // in this transaction (code review A02).
                let safe = match gate.check(tx)? {
                    Ok(s) => s,
                    Err(u) => return Ok((Err(uncertain(&u)), none())),
                };
                let now = safe.wall();
                inp.now = now;
                let Some(mut intent) = tx.recovery_intent(&id)? else {
                    return Err(conflict("operation has no recovery intent"));
                };
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2: delegation uses the parent, whose
                // state reflects its mechanism before resolution judges it.
                if inp.spec.kind == OperationKind::Delegate
                    && let Some(pb) = &inp.spec.parent_binding
                    && let Some(b) = tx.binding(pb)?.filter(|b| may_act_on(b, &inp.caller))
                {
                    track_mechanism_in(
                        tx,
                        emit,
                        &inp.environment,
                        &inp.adapters,
                        &gate,
                        &b.grant,
                        &safe,
                        Some(&id),
                    )?;
                }
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
                        // ⟨r2.5⟩ ADR-0006 §13.8 item 4: delegation is a use of the
                        // parent; a parent that can no longer be used ends now.
                        let parent = match &inp.spec.parent_binding {
                            Some(pb) if inp.spec.kind == OperationKind::Delegate => {
                                tx.binding(pb)?.map(|b| b.grant)
                            }
                            _ => None,
                        };
                        let ended = match parent {
                            Some(pg) => end_in(
                                tx,
                                emit,
                                &inp.environment,
                                &inp.adapters,
                                &gate,
                                &pg,
                                &safe,
                                Some(&id),
                                retention,
                            )?,
                            None => none(),
                        };
                        Ok((Ok(Flow::Stop), ended))
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
                        Ok((Ok(Flow::Continue), none()))
                    }
                    Ok(Resolution::Approval(approval)) => {
                        let Approval {
                            intent: resolved,
                            mut grant,
                            delta,
                        } = *approval;
                        // Code review A07: one logical decision, one record (spec
                        // §5.5): an equivalent request already waiting joins its
                        // decision and its grant; this caller keeps its own operation.
                        let joined =
                            equivalent_waiting(tx, &op, &inp.spec, &resolved, &delta, now)?;
                        let resolved = match joined {
                            Some(gid) => ResolvedIntent {
                                grant: Some(gid),
                                ..resolved
                            },
                            None => {
                                grant_to(&mut grant, GrantEvent::ApprovalNeeded)?;
                                tx.insert_grant(&grant)?;
                                // ⟨r2.6⟩ §13.9 item 2: the context re-validation
                                // needs is persisted with the grant.
                                if let Some(origin) = origin_of(&resolved, &op.key.caller) {
                                    tx.set_grant_origin(&grant.id, &origin)?;
                                }
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
                                emit.grant(tx, &grant, Some(&id))?;
                                emit.decision(tx, &decision, Some(&id))?;
                                resolved
                            }
                        };
                        intent.resolved = Some(resolved);
                        tx.set_recovery_intent(&id, &intent)?;
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
                        emit.op(tx, &op)?;
                        Ok((Ok(Flow::Stop), none()))
                    }
                }
            })
            .await?;
        self.complete_withdrawals(ended).await;
        flow
    }

    async fn stage_coalesce(
        &self,
        st: &WorkState,
        expected: OperationState,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let Some(resolved) = st.intent.resolved.clone() else {
            return Err(internal("operation has no resolved intent"));
        };
        let id = st.op.id.clone();
        if let Some(gid) = resolved.grant.clone() {
            // Approved added authority already has its own grant, unless this
            // operation joined another caller's equivalent decision (code review
            // A07): then it attaches to that operation's result.
            let (id2, g2) = (id.clone(), gid.clone());
            let owner = self
                .write(move |tx, _| {
                    Ok(tx
                        .grant(&g2)?
                        .filter(|g| !owns_grant(g, &id2))
                        .map(|g| decision_owner(Some(&g), &id2)))
                })
                .await?;
            return match owner {
                Some(owner) => self.attach_to_owner(st, &owner, &gid, local).await,
                None => {
                    self.stage_receipt(&id, EnsureStage::Coalesce, expected)
                        .await
                }
            };
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

    /// ⟨r2.5⟩ ADR-0006 §13.8 item 5: the prepared facts of `grant` when `owner` is a
    /// cancelled owner whose continued preparation activated it, reconciled through
    /// the owner's recorded adapter identity and its own effect token (no new
    /// effect, nothing handed over). `None` otherwise or when the adapter cannot
    /// confirm the credential now.
    async fn continued_preparation(
        &self,
        owner: &OperationId,
        grant: &GrantId,
    ) -> Option<PrepareOutcome> {
        let (owner2, gid) = (owner.clone(), grant.clone());
        let found = self
            .write(move |tx, _| {
                let Some(op) = tx.operation(&owner2)? else {
                    return Ok(None);
                };
                if op.state != OperationState::Cancelled
                    || !tx
                        .grant(&gid)?
                        .is_some_and(|g| g.state.permits_use() && shared_owner(&g) == Some(&owner2))
                {
                    return Ok(None);
                }
                let identity = tx
                    .recovery_intent(&owner2)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.adapter);
                let token = last_token(&tx.stage_receipts(&owner2)?);
                Ok(identity.zip(token))
            })
            .await
            .ok()
            .flatten()?;
        let (identity, token) = found;
        let adapter = self.adapter(Some(&identity))?;
        let outcome = {
            let _slot = self.inner.adapter_slots.acquire().await.ok()?;
            adapter.reconcile(grant, &token).await
        };
        match outcome {
            Ok(ReconcileOutcome::Applied(o)) => Some(o),
            _ => None,
        }
    }

    /// Code review A07: a request that joined another caller's equivalent decision
    /// follows that operation (or drives it, after a restart), then attaches a
    /// separate reference to its grant with that operation's prepared facts. It
    /// never prepares; when that operation ended without activating, it fails
    /// with `CREDENTIAL_EXPIRED` (`next: new_work`).
    async fn attach_to_owner(
        &self,
        st: &WorkState,
        owner: &OperationId,
        gid: &GrantId,
        local: &mut DriveLocal,
    ) -> Result<Flow, OpError> {
        let led = self.lead_boxed(owner.clone()).await;
        // ⟨r2.5⟩ ADR-0006 §13.8 item 5: an owner cancelled after approval prepared
        // the shared grant for the operations attached to it; its facts come from
        // its recorded adapter through its own effect token (never a new effect).
        let prepared = self.continued_preparation(owner, gid).await;
        let id = st.op.id.clone();
        let owner2 = owner.clone();
        let gid2 = gid.clone();
        let clock = self.clock();
        let retention = self.retention();
        let outcome = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id)? else {
                    return Ok(Joined::Stop);
                };
                if op.state != OperationState::Running {
                    return Ok(Joined::Stop);
                }
                let now = clock.wall();
                let owner_op = tx.operation(&owner2)?;
                match owner_op.as_ref().map(|o| o.state) {
                    Some(OperationState::Succeeded) => {
                        let data = owner_op
                            .and_then(|o| o.result)
                            .and_then(|v| serde_json::from_value::<EnsureData>(v).ok())
                            .filter(|d| d.grant_id == gid2);
                        if let Some(data) = data
                            && tx.grant(&gid2)?.is_some_and(|g| g.state.permits_use())
                        {
                            tx.append_stage_receipt(
                                &id,
                                &receipt(EnsureStage::Coalesce, now, EffectReceipt::NotAttempted),
                            )?;
                            tx.append_stage_receipt(
                                &id,
                                &receipt(EnsureStage::Reconcile, now, EffectReceipt::NotAttempted),
                            )?;
                            return Ok(Joined::Attached(Box::new(data)));
                        }
                    }
                    Some(
                        OperationState::Queued
                        | OperationState::Running
                        | OperationState::AwaitingApproval
                        | OperationState::OutcomeUnknown,
                    ) => return Ok(Joined::Pending),
                    Some(OperationState::Cancelled) => {
                        let usable = tx.grant(&gid2)?.is_some_and(|g| g.state.permits_use());
                        if usable && let Some(o) = prepared {
                            tx.append_stage_receipt(
                                &id,
                                &receipt(EnsureStage::Coalesce, now, EffectReceipt::NotAttempted),
                            )?;
                            tx.append_stage_receipt(
                                &id,
                                &receipt(EnsureStage::Reconcile, now, EffectReceipt::NotAttempted),
                            )?;
                            return Ok(Joined::Prepared(Box::new(o)));
                        }
                        // Still preparing for us, or prepared but its facts could
                        // not be confirmed just now: keep running, retry.
                        if usable
                            || owner_op
                                .as_ref()
                                .map(|o| continues_for_others(tx, o))
                                .transpose()?
                                .unwrap_or(false)
                        {
                            return Ok(Joined::Pending);
                        }
                    }
                    _ => {}
                }
                let err = authority_changed(
                    "the equivalent request this one joined ended without activating",
                );
                settle_failed(tx, emit, &mut op, &err, now, retention)?;
                Ok(Joined::Stop)
            })
            .await?;
        match outcome {
            Joined::Attached(data) => {
                local.leader_data = Some(*data);
                Ok(Flow::Continue)
            }
            Joined::Prepared(o) => {
                local.prepared = Some(*o);
                Ok(Flow::Continue)
            }
            Joined::Stop => Ok(Flow::Stop),
            Joined::Pending => Err(match led {
                // The joined operation's own refusal (time, backpressure, ...),
                // not attributed to it: this operation stays running.
                Err(mut e) => {
                    e.operation_id = None;
                    e.next.operation_id = None;
                    e
                }
                Ok(()) => OpError::new(
                    Code::ServiceUnavailable,
                    "the equivalent request this one joined is still in progress; retry with the same request ID",
                ),
            }),
        }
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
            let continuing = continues_for_others(tx, &op)?;
            if !continuing
                && !matches!(
                    op.state,
                    OperationState::Running | OperationState::OutcomeUnknown
                )
            {
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
            // A continuing cancelled owner is settled already (ADR-0006 §13.8
            // item 5); the attached operations learn the outcome from the grant.
            if !continuing {
                settle_failed(tx, emit, &mut op, &err, now, retention)?;
            }
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
        // ⟨r2.5⟩ A cancelled owner's preparation continues for the operations
        // attached to its grant (ADR-0006 §13.8 item 5).
        let expected = if st.continuing {
            OperationState::Cancelled
        } else {
            OperationState::Running
        };
        if st.op.state != expected {
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
                        // ⟨r2.6⟩ §13.9 item 2: the context re-validation needs is
                        // persisted with the grant.
                        if let Some(origin) = origin_of(&r, &op.key.caller) {
                            tx.set_grant_origin(&gid, &origin)?;
                        }
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
        // 2. Effect state from the receipts (an `Uncertain` one is on record only
        // for a continuing cancelled owner, whose operation cannot become
        // `outcome_unknown`: it is reconciled the same way, never re-prepared).
        if let Some(
            EffectReceipt::Attempted {
                adapter: recorded,
                effect_token,
            }
            | EffectReceipt::Uncertain {
                adapter: recorded,
                effect_token,
            },
        ) = last_reconcile(&st.receipts)
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
        // 3. Fresh attempt (code review A03). Wait for an adapter slot first, then
        // authorize the attempt in one transaction: time assessed by the gate,
        // current authority, deadline, cutoff and continuous admission validated
        // exactly as activation would, and only then the `Attempted` receipt.
        // Never prepare after the bound. (Earlier attempts were reconciled above,
        // whatever the authority now says.)
        let slot = self
            .inner
            .adapter_slots
            .acquire()
            .await
            .map_err(|_| internal("adapter slots closed"))?;
        let token = crate::ids::new_effect_token()?;
        let gate = self.inner.timegate.in_txn();
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let id2 = id.clone();
        let gid = grant_id.clone();
        let ident = identity.clone();
        let tok = token.clone();
        let retention = self.retention();
        let attempt = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok(Attempt::Stop);
                };
                if !drivable(tx, &op, expected)? {
                    return Ok(Attempt::Stop);
                }
                let safe = match gate.check(tx)? {
                    Ok(s) => s,
                    Err(u) => return Ok(Attempt::Uncertain(u)),
                };
                let now = safe.wall();
                let Some(resolved) = tx.recovery_intent(&id2)?.and_then(|i| i.resolved) else {
                    return Err(conflict("operation has no resolved intent"));
                };
                let Some(mut g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                let refusal = match activation_refusal(
                    tx,
                    &env,
                    &adapters,
                    &resolved,
                    &g,
                    now,
                    Activation::NewGrant,
                )? {
                    Some(r) => r,
                    None => {
                        // First validation in this boot anchors the grant; the
                        // continuous budget must still be open.
                        let bound = bound_of(tx, &env, &g, Some(&resolved.profile))?;
                        if gate.anchor_grant(tx, &gid, &safe, bound)?.is_none() {
                            return Ok(Attempt::Unanchored);
                        }
                        match gate.admission(tx, &gid, &safe)? {
                            Admission::Open => {
                                // ⟨r2.10⟩ ADR-0006 §13.13 item 1: the adapter that
                                // prepares the grant is persisted with it in the
                                // transaction of its first `Attempted` receipt
                                // (written once, then immutable), so operation
                                // retention cannot remove its responsible adapter.
                                if let Some(origin) = tx.grant_origin(&gid)?
                                    && origin.adapter.is_none()
                                {
                                    tx.set_grant_origin(
                                        &gid,
                                        &GrantOrigin {
                                            adapter: Some(ident.clone()),
                                            ..origin
                                        },
                                    )?;
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
                                // The adapter bounds what it creates by the
                                // recorded bound (deadline, ancestors, cutoff).
                                let mut bounded = g;
                                bounded.deadline.effective = bounded.deadline.effective.min(bound);
                                return Ok(Attempt::Go(Box::new(bounded), now));
                            }
                            Admission::NeedsAnchor => return Ok(Attempt::Unanchored),
                            Admission::Expired => Refusal::new(
                                OpError::new(
                                    Code::CredentialExpired,
                                    "the grant reached its deadline",
                                )
                                .with_resource("grant", Some(gid.to_string())),
                                Some(GrantEvent::DeadlineReached),
                            ),
                        }
                    }
                };
                if let Some(ev) = refusal.grant_event
                    && grant_try(&mut g, ev)
                {
                    put_grant(tx, emit, &g, Some(&id2))?;
                }
                // A cancelled owner is settled already; the attached operations
                // learn the outcome from the grant.
                if op.state != OperationState::Cancelled {
                    settle_failed(tx, emit, &mut op, &refusal.error, now, retention)?;
                }
                Ok(Attempt::Refused)
            })
            .await?;
        let (grant, now) = match attempt {
            Attempt::Go(g, now) => (g, now),
            Attempt::Stop => return Ok(Flow::Stop),
            Attempt::Refused => {
                // ⟨r2.5⟩ ADR-0006 §13.8 item 4: an ancestor this preparation rests
                // on may have to end now.
                self.end_if_invalid(&grant_id).await;
                return Ok(Flow::Stop);
            }
            Attempt::Uncertain(u) => return Err(uncertain(&u)),
            Attempt::Unanchored => {
                return Err(OpError::new(
                    Code::TimeUncertain,
                    "time uncertain: the grant has no anchor in this boot",
                )
                .with_resource("clock", None));
            }
        };
        let interactive = interactive && spec.interactive;
        let result = adapter
            .prepare(PrepareRequest {
                grant: &grant,
                scope: &grant.scope,
                required: &spec.required,
                interactive,
                effect_token: &token,
                now,
            })
            .await;
        drop(slot);
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
                Ok(match tx.operation(&id2)? {
                    Some(op) => {
                        op.state == OperationState::Running || continues_for_others(tx, &op)?
                    }
                    None => false,
                })
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
    ) -> Result<Flow, OpError> {
        let gate = self.inner.timegate.in_txn();
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
        let outcome = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id)? else {
                    return Ok(Checked::Stop);
                };
                if !drivable(tx, &op, expected)? {
                    return Ok(Checked::Stop);
                }
                // Time is assessed by the gate in this transaction (A02).
                let safe = match gate.check(tx)? {
                    Ok(s) => s,
                    Err(u) => return Ok(Checked::Uncertain(u)),
                };
                let now = safe.wall();
                let Some(resolved) = tx.recovery_intent(&id)?.and_then(|i| i.resolved) else {
                    return Err(conflict("operation has no resolved intent"));
                };
                let Some(gid) = resolved.grant.clone() else {
                    return Err(conflict("operation has no grant"));
                };
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2: an attached binding uses a live
                // grant, whose state reflects its mechanism before it is judged.
                if attached {
                    track_mechanism_in(tx, emit, &env, &adapters, &gate, &gid, &safe, Some(&id))?;
                }
                let Some(mut g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                let activation = if attached {
                    Activation::NewBinding
                } else {
                    Activation::NewGrant
                };
                if let Some(refusal) =
                    activation_refusal(tx, &env, &adapters, &resolved, &g, now, activation)?
                {
                    if !attached
                        && let Some(ev) = refusal.grant_event
                        && grant_try(&mut g, ev)
                    {
                        put_grant(tx, emit, &g, Some(&id))?;
                    }
                    let err = refusal.error.with_effect(effect);
                    // A continuing cancelled owner is settled already (§13.8 item 5).
                    if op.state != OperationState::Cancelled {
                        settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    }
                    let orphan = if attached {
                        end_orphaned_in(tx, emit, &gid, &id)?
                    } else {
                        None
                    };
                    return Ok(Checked::Refused(gid, orphan));
                }
                // Activation anchor (ADR-0005 §3.6), cut by the accepted tolerance.
                let bound = bound_of(tx, &env, &g, Some(&resolved.profile))?;
                if gate.anchor_grant(tx, &gid, &safe, bound)?.is_none() {
                    return Ok(Checked::Unanchored);
                }
                tx.append_stage_receipt(
                    &id,
                    &receipt(EnsureStage::Recheck, now, EffectReceipt::NotAttempted),
                )?;
                Ok(Checked::Passed)
            })
            .await?;
        match outcome {
            Checked::Passed => Ok(Flow::Continue),
            Checked::Stop => Ok(Flow::Stop),
            Checked::Uncertain(u) => Err(uncertain(&u).with_effect(effect)),
            Checked::Unanchored => Err(unanchored().with_effect(effect)),
            Checked::Refused(gid, orphan) => {
                if (!attached && effect != EffectStatus::None) || orphan.is_some() {
                    self.cleanup(&gid).await;
                }
                // ⟨r2.5⟩ ADR-0006 §13.8 item 4: detected at use (an attached
                // binding's live grant, or an ancestor), a grant that can no
                // longer be used ends now.
                self.end_if_invalid(&gid).await;
                Ok(Flow::Stop)
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
        let effect = if attached {
            EffectStatus::None
        } else {
            EffectStatus::Partial
        };
        // The prepared facts: this drive's outcome, the leader's for an attached
        // binding, or the recorded adapter's reconciliation after a restart.
        let facts: Option<Facts> = if attached {
            // An attached binding: the leader's result, or the facts of a shared
            // grant a cancelled owner prepared, reconciled through its effect token
            // (ADR-0006 §13.8 item 5).
            local
                .leader_data
                .as_ref()
                .map(Facts::from_data)
                .or_else(|| local.prepared.as_ref().map(Facts::from_outcome))
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
        // The caller's minimums travel with the stored request, so they hold for
        // a coalesced binding and after a restart alike (A04).
        let required = st
            .request()
            .and_then(|r| WorkSpec::from_request(&r, &env))
            .map(|s| s.required)
            .unwrap_or_default();
        let binding_id = crate::ids::new_binding_id()?;
        let gate = self.inner.timegate.in_txn();
        let retention = self.retention();
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
                    return Ok(Checked::Stop);
                };
                if !drivable(tx, &op, expected)? {
                    return Ok(Checked::Stop);
                }
                // ⟨r2.5⟩ ADR-0006 §13.8 item 5: a cancelled owner still preparing
                // the shared grant for others activates it, but gets no binding and
                // stays settled; its caller's minimums no longer apply (each
                // attached operation checks its own at its commit).
                let for_others = op.state == OperationState::Cancelled;
                // A02: the commit re-assesses time with the gate, from a fresh
                // observation in this transaction, not only the admission.
                let safe = match gate.check(tx)? {
                    Ok(s) => s,
                    Err(u) => return Ok(Checked::Uncertain(u)),
                };
                let now = safe.wall();
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2 (as at `Recheck`).
                if attached {
                    track_mechanism_in(tx, emit, &env, &adapters, &gate, &gid, &safe, Some(&id))?;
                }
                let Some(mut g) = tx.grant(&gid)? else {
                    return Err(conflict("grant missing"));
                };
                let activation = if attached {
                    Activation::NewBinding
                } else {
                    Activation::NewGrant
                };
                let bound = bound_of(tx, &env, &g, Some(&resolved.profile))?;
                let facts = facts.unwrap_or_else(|| Facts::conservative(&g, now));
                let refusal = match activation_refusal(
                    tx, &env, &adapters, &resolved, &g, now, activation,
                )? {
                    Some(r) => Some(r),
                    None => {
                        // Continuous admission of the anchor (re-anchored from this
                        // observation; never longer) at the accepted observation and
                        // at a fresh reading (stricter).
                        if gate.anchor_grant(tx, &gid, &safe, bound)?.is_none() {
                            return Ok(Checked::Unanchored);
                        }
                        match gate.admission(tx, &gid, &safe)? {
                            Admission::NeedsAnchor => return Ok(Checked::Unanchored),
                            Admission::Expired => Some(Refusal::new(
                                OpError::new(
                                    Code::CredentialExpired,
                                    "the grant reached its deadline",
                                )
                                .with_resource("grant", Some(gid.to_string())),
                                Some(GrantEvent::DeadlineReached),
                            )),
                            // A04: the prepared facts meet every caller minimum.
                            Admission::Open if for_others => None,
                            Admission::Open => unmet_minimum(&required, &facts, &g, bound)
                                .map(|e| Refusal::new(e, Some(GrantEvent::PreparationFailed))),
                        }
                    }
                };
                if let Some(refusal) = refusal {
                    if !attached
                        && let Some(ev) = refusal.grant_event
                        && grant_try(&mut g, ev)
                    {
                        put_grant(tx, emit, &g, Some(&id))?;
                    }
                    let err = refusal.error.with_effect(effect);
                    if !for_others {
                        settle_failed(tx, emit, &mut op, &err, now, retention)?;
                    }
                    let orphan = if attached {
                        end_orphaned_in(tx, emit, &gid, &id)?
                    } else {
                        None
                    };
                    return Ok(Checked::Refused(gid, orphan));
                }
                if g.state == GrantState::Preparing {
                    grant_to(&mut g, GrantEvent::Prepared)?;
                    g.enforcement = EnforcementEvidence {
                        report: facts.enforcement.clone(),
                        evidence: Vec::new(),
                    };
                    put_grant(tx, emit, &g, Some(&id))?;
                }
                if for_others {
                    tx.append_stage_receipt(
                        &id,
                        &receipt(EnsureStage::Commit, now, EffectReceipt::NotAttempted),
                    )?;
                    return Ok(Checked::Passed);
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
                Ok(Checked::Passed)
            })
            .await?;
        match outcome {
            Checked::Passed => Ok(Flow::Continue),
            Checked::Stop => Ok(Flow::Stop),
            Checked::Uncertain(u) => Err(uncertain(&u).with_effect(effect)),
            Checked::Unanchored => Err(unanchored().with_effect(effect)),
            Checked::Refused(gid, orphan) => {
                if !attached || orphan.is_some() {
                    self.cleanup(&gid).await;
                }
                // ⟨r2.5⟩ ADR-0006 §13.8 item 4 (as at `Recheck`).
                self.end_if_invalid(&gid).await;
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
        let mut st = self.load_work(id).await?;
        if st.op.state == OperationState::AwaitingApproval {
            match self.awaiting_response(id, caller).await {
                Awaiting::Answer(e) => return Err(*e),
                Awaiting::Proceed(resumed) => {
                    // ⟨r2.4⟩ §13.7 item 2: the standing policy now covers the
                    // request; every waiter resumed (the shared grant's owner first)
                    // and goes through the normal activation checks. Bounded waits:
                    // the work continues whatever the caller does.
                    // One overall bound for the request, every waiter resumed at
                    // once (⟨r2.5⟩ ADR-0006 §13.8 item 2, as for `decide`).
                    let interactive = caller.interaction == InteractionMode::Interactive;
                    let resumed: Vec<(OperationId, bool)> = resumed
                        .into_iter()
                        .map(|r| {
                            let mine = r == *id;
                            (r, mine && interactive)
                        })
                        .collect();
                    let led = self
                        .lead_all_bounded(&resumed, self.inner.config.limits.max_wait)
                        .await;
                    for ((r, _), led) in resumed.iter().zip(led) {
                        if r == id
                            && let Some(Err(e)) = led
                        {
                            return Err(e);
                        }
                    }
                    st = self.load_work(id).await?;
                }
            }
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
    /// fresh one when the pending record expired or went stale (ADR-0006 §13.3,
    /// §13.6 item 2), or the failure when the grant reached its deadline or its
    /// chain no longer validates. A request that joined an equivalent request's
    /// decision answers with that shared record (code review A07). A replacement
    /// record's delta is recomputed against current policy, never copied from the
    /// earlier record (code review A06), and time is assessed in the transaction
    /// that issues it (A02).
    ///
    /// ⟨r2.4⟩ ADR-0006 §13.7 item 2: when the recomputed delta is **empty** the
    /// owner's saved standing policy covers the request entirely. No decision
    /// record is issued (the empty-delta replacement record is withdrawn as a
    /// behaviour): in the same transaction every waiter on the shared grant leaves
    /// `awaiting_approval` with a [`CoveredBasis`] (the current generation and
    /// applicable revision), the grant moves to `preparing` (the table's only edge
    /// out of `awaiting_approval` towards activation), any pending record of the
    /// waiters is withdrawn, and the waiters are returned to be driven through the
    /// normal pipeline (time, pause, cutoff, generation, revision, bound and
    /// admission checks at the attempt, `Recheck` and `Commit`). The pause check
    /// above still answers `POLICY_PAUSED` first.
    async fn awaiting_response(&self, id: &OperationId, caller: &Caller) -> Awaiting {
        let decision_id = match crate::ids::new_decision_id() {
            Ok(d) => d,
            Err(e) => return Awaiting::Answer(Box::new(OpError::from(e))),
        };
        let gate = self.inner.timegate.in_txn();
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
                    return Ok(Ok(Waiting::Left));
                }
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u).with_operation(id2.clone()))),
                };
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
                // ⟨r2.3⟩ §13.6 item 1: the waiting grant is a new grant, which a
                // pause refuses with POLICY_PAUSED. The pause is not an expiry and
                // terminates nothing: the operation keeps waiting (until its
                // deadline, a revoke, or a resume and a fresh decision), and no
                // decision record is issued while the policy is paused.
                let policies = tx.policies_for(&resolved.profile, &env)?;
                if let Some(p) = merged_policy(&policies)
                    && matches!(p.pause, PauseState::Paused { .. })
                {
                    return Ok(Err(OpError::new(
                        Code::PolicyPaused,
                        "the standing policy is paused; the request keeps waiting",
                    )
                    .with_resource("policy", Some(p.id.to_string()))
                    .with_operation(id2.clone())));
                }
                let Some(g) = grant else {
                    return Err(conflict("awaiting operation has no grant on record"));
                };
                // What the waiting grant needs now, against current policy.
                let Some(needed) = current_delta(tx, &env, &adapters, &g, now)? else {
                    return Err(conflict("awaiting operation has no decision on record"));
                };
                let owner = decision_owner(Some(&g), &id2);
                // ⟨r2.4⟩ §13.7 item 2: fully covered by the saved standing policy.
                if delta_is_empty(&needed) {
                    let resumed =
                        proceed_covered(tx, emit, &env, &g, &owner, &resolved.profile, current, now)?;
                    return Ok(Ok(Waiting::Proceed(resumed)));
                }
                // R7: compare expiry and generation ourselves; a pending record is
                // reused only while it still covers what is needed.
                if let Some(valid) = tx.pending_decisions()?.iter().rev().find(|d| {
                    matches!(&d.kind, DecisionKind::ApproveAuthority { operation, delta }
                        if operation == &owner && delta_within(&needed, delta))
                        && now < d.expires_at
                        && d.generation == current
                }) {
                    return Ok(Ok(Waiting::Decision(valid.id.clone())));
                }
                // A06: the replacement carries the delta recomputed against current
                // policy at the current generation, never the earlier record's.
                let fresh = DecisionRecord {
                    id: decision_id,
                    kind: DecisionKind::ApproveAuthority {
                        operation: owner,
                        delta: needed,
                    },
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&fresh)?;
                emit.decision(tx, &fresh, Some(&id2))?;
                Ok(Ok(Waiting::Decision(fresh.id)))
            })
            .await;
        Awaiting::Answer(Box::new(match r {
            Err(e) => e.with_operation(id.clone()),
            Ok(Err(e)) => e,
            Ok(Ok(Waiting::Proceed(resumed))) => return Awaiting::Proceed(resumed),
            Ok(Ok(Waiting::Left)) => OpError::new(
                Code::Accepted,
                "the operation is no longer awaiting approval; observe it",
            )
            .with_operation(id.clone()),
            Ok(Ok(Waiting::Decision(dec))) => approval_needed(
                attended,
                dec.as_str(),
                "the request needs additional owner authority",
            )
            .with_resource("decision", Some(dec.to_string()))
            .with_operation(id.clone()),
        }))
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
                    heimdall_contract::ipc::capability::SERVICE_CONTROL_V1,
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
                    // ⟨r2.7⟩ ADR-0006 §13.10 item 3: a pending remote revocation stays
                    // visible on each grant it covers. ⟨r2.9⟩ §13.12 item 2: with the
                    // reason `adapter_unavailable` while a responsible adapter of one
                    // of its obligations is not configured. ⟨r2.10⟩ §13.13: the retry
                    // count and stop are the grant's own obligations' (item 3), and
                    // a grant that ended before activation keeps its pending remote
                    // part visible too (item 2; R-AU-04), so such a terminal grant
                    // stays listed while it has an obligation.
                    let mut remote: BTreeMap<GrantId, RemoteView> = BTreeMap::new();
                    for r in tx.remote_revocations()? {
                        for g in &r.grants {
                            let own: Vec<&RemoteObligation> =
                                r.obligations.iter().filter(|o| &o.grant == g).collect();
                            remote.insert(
                                g.clone(),
                                RemoteView {
                                    attempts: own
                                        .iter()
                                        .map(|o| r.obligation_attempts(o))
                                        .max()
                                        .unwrap_or(r.attempts),
                                    last_attempt_at: r.last_attempt_at,
                                    stopped: r.stopped
                                        || (!own.is_empty() && own.iter().all(|o| o.stopped)),
                                    unavailable: own.iter().any(|o| {
                                        o.reason == Some(RemotePendingReason::AdapterUnavailable)
                                    }),
                                },
                            );
                        }
                    }
                    let mut listed: Vec<(GrantSnapshot, bool)> = tx
                        .grants_due(Timestamp::MAX)?
                        .into_iter()
                        .map(|g| (g, false))
                        .collect();
                    for gid in remote.keys() {
                        if let Some(g) = tx.grant(gid)?
                            && g.state.is_terminal()
                        {
                            listed.push((g, true));
                        }
                    }
                    for (g, ended) in listed {
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
                                if ended {
                                    // Listed for its pending remote part only; its
                                    // bindings are not live.
                                    continue;
                                }
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
                            let mut view = serde_json::json!({
                                "grant_id": g.id,
                                "state": g.state,
                                "expires_at": g.deadline.effective,
                                "parent": g.parent,
                                "scope": g.scope,
                            });
                            // ⟨r2.7⟩ ADR-0006 §13.10 items 2 and 3 (added fields only).
                            if let serde_json::Value::Object(map) = &mut view {
                                if g.state == GrantState::Degraded
                                    && let Some(reason) = tx.grant_degradation(&g.id)?
                                {
                                    map.insert(
                                        "degraded_reason".to_owned(),
                                        serde_json::to_value(reason)?,
                                    );
                                }
                                if let Some(r) = remote.get(&g.id) {
                                    map.insert(
                                        "remote_pending".to_owned(),
                                        serde_json::json!(true),
                                    );
                                    if r.unavailable {
                                        map.insert(
                                            "remote_pending_reason".to_owned(),
                                            serde_json::to_value(
                                                RemotePendingReason::AdapterUnavailable,
                                            )?,
                                        );
                                    }
                                    map.insert(
                                        "remote_retries".to_owned(),
                                        serde_json::json!({
                                            "attempts": r.attempts,
                                            "last_attempt_at": r.last_attempt_at,
                                            "stopped": r.stopped,
                                        }),
                                    );
                                }
                            }
                            grants.push(view);
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
        let gate = self.inner.timegate.in_txn();
        let id2 = id.clone();
        let env = self.inner.config.environment.clone();
        let retention = self.retention();
        let adapters = self.adapter_infos();
        let none = Ended::default;
        let (r, ended) = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok((Ok(()), none()));
                };
                if op.state.is_quiescent() {
                    return Ok((Ok(()), none()));
                }
                // Time is assessed by the gate in the transaction that admits the
                // binding (code review A02); uncertain time leaves the request queued.
                let safe = match gate.check(tx)? {
                    Ok(s) => s,
                    Err(u) => return Ok((Err(uncertain(&u)), none())),
                };
                let now = safe.wall();
                // First validation in this boot anchors the grant (ADR-0005 §3.6).
                if let Some(b) = tx.binding(&req.binding_id)?
                    && let Some(g) = tx.grant(&b.grant)?
                {
                    let bound = bound_of(tx, &env, &g, Some(&b.profile))?;
                    if g.state.permits_use() && !dtime::is_expired(now, bound) {
                        gate.anchor_grant(tx, &g.id, &safe, bound)?;
                    }
                }
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2: the grant's state reflects its
                // mechanism before the use is judged.
                if let Some(b) = tx
                    .binding(&req.binding_id)?
                    .filter(|b| may_act_on(b, &op.key.caller))
                {
                    track_mechanism_in(
                        tx,
                        emit,
                        &env,
                        &adapters,
                        &gate,
                        &b.grant,
                        &safe,
                        Some(&id2),
                    )?;
                }
                if op.state == OperationState::Queued {
                    op_to(&mut op, OperationEvent::Start, now)?;
                    tx.update_operation(&op)?;
                }
                let fail =
                    |tx: &mut Txn<'_>, emit: &mut Emit, op: &mut OperationRecord, e: OpError| {
                        settle_failed(tx, emit, op, &e, now, retention).map(|()| (Ok(()), none()))
                    };
                let Some(b) = tx
                    .binding(&req.binding_id)?
                    .filter(|b| may_act_on(b, &op.key.caller))
                else {
                    return fail(
                        tx,
                        emit,
                        &mut op,
                        OpError::new(Code::NotFound, "unknown binding")
                            .with_resource("binding", None),
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
                    approval: None,
                    covered: None,
                };
                // An existing binding is not a new activation (ADR-0006 §13.6 item 1):
                // a pause does not stop it (nor its re-validation); revocation and
                // `min(deadline, cutoff)` do, the latter as CREDENTIAL_EXPIRED.
                let mut refusal = activation_refusal(
                    tx,
                    &env,
                    &adapters,
                    &resolved,
                    &g,
                    now,
                    Activation::Existing,
                )?
                .map(|r| r.error);
                if refusal.is_none() {
                    refusal = match gate.admission(tx, &g.id, &safe)? {
                        Admission::Open => None,
                        Admission::Expired => Some(
                            OpError::new(Code::CredentialExpired, "the grant reached its deadline")
                                .with_resource("grant", Some(g.id.to_string())),
                        ),
                        Admission::NeedsAnchor => Some(
                            OpError::new(
                                Code::TimeUncertain,
                                "time uncertain: the grant has no anchor in this boot",
                            )
                            .with_resource("clock", None),
                        ),
                    };
                }
                if let Some(e) = refusal {
                    // ⟨r2.5⟩ ADR-0006 §13.8 item 4: detected at use, a grant that can
                    // no longer be used ends in this transaction (never for uncertain
                    // time, which is no reason to end it).
                    let ended = if e.code == Code::TimeUncertain {
                        none()
                    } else {
                        end_in(
                            tx,
                            emit,
                            &env,
                            &adapters,
                            &gate,
                            &g.id,
                            &safe,
                            Some(&id2),
                            retention,
                        )?
                    };
                    return fail(tx, emit, &mut op, e).map(|(r, _)| (r, ended));
                }
                let bound = bound_of(tx, &env, &g, Some(&b.profile))?;
                let data = ensure_data(&b, &g, &Facts::conservative(&g, now), bound);
                let value = serde_json::to_value(&data)?;
                settle_succeeded(tx, emit, &mut op, Code::AccessReady, value, now, retention)
                    .map(|()| (Ok(()), none()))
            })
            .await?;
        self.complete_withdrawals(ended).await;
        r
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
    ///
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 5: the owner of a shared owner-decision grant
    /// cancelled after approval while other operations remain attached settles
    /// `cancelled` with `may_have_external_effect: true` and the shared preparation
    /// continues for them; the last attached operation's cancellation ends the grant
    /// and cleans up its credential.
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
                let mut may_have = may_have_external_effect(&receipts);
                let mut cleanup = None;
                let pinned = tx
                    .recovery_intent(&id)?
                    .and_then(|i| i.resolved)
                    .and_then(|r| r.grant);
                // ⟨r2.5⟩ ADR-0006 §13.8 item 5: the owner of a shared grant
                // cancelled AFTER approval while other operations remain attached:
                // its operation settles `cancelled` (reporting a possible external
                // effect, since the shared preparation continues), and the grant's
                // preparation continues for the others on this operation's receipts
                // and effect token. The grant is not touched here.
                let shared_preparing = match &pinned {
                    Some(gid) if !coalesced(&receipts) => match tx.grant(gid)? {
                        Some(g) => {
                            g.state == GrantState::Preparing
                                && shared_owner(&g) == Some(&id)
                                && !attached_on(tx, gid, &id)?.is_empty()
                        }
                        None => false,
                    },
                    _ => false,
                };
                if shared_preparing {
                    may_have = true;
                }
                // A request attached to, or waiting on, another operation's grant
                // (coalesced work, or a joined decision: code review A07) never
                // cancels that grant (but see §13.8 item 5 below).
                if !shared_preparing
                    && let Some(gid) = pinned.clone()
                    && !coalesced(&receipts)
                    && let Some(mut g) = tx.grant(&gid)?
                    && owns_grant(&g, &id)
                {
                    // ⟨r2.4⟩ §13.7 item 4: the creator of a shared waiting
                    // decision hands the shared grant and its pending decision to
                    // the oldest remaining waiter (the decision stays pending); the
                    // grant ends only with its last waiter, and then its decision
                    // is withdrawn.
                    let shared_waiting = waiting(&g)
                        && matches!(&g.source, AuthorizationSource::OwnerDecision { operation_id } if *operation_id == id);
                    let heir = if shared_waiting {
                        waiters_on(tx, &gid)?.into_iter().find(|o| o.id != id)
                    } else {
                        None
                    };
                    if let Some(heir) = heir {
                        tx.transfer_waiting_grant(&gid, &id, &heir.id)?;
                        for d in pending_records_of(tx, &id)? {
                            let moved = tx.transfer_decision(&d.id, &id, &heir.id)?;
                            emit.decision(tx, &moved, Some(&heir.id))?;
                        }
                    } else {
                        if grant_try(&mut g, GrantEvent::Cancel) {
                            put_grant(tx, emit, &g, Some(&id))?;
                        }
                        if shared_waiting {
                            for d in pending_records_of(tx, &id)? {
                                let withdrawn = tx.withdraw_decision(&d.id)?;
                                emit.decision(tx, &withdrawn, Some(&id))?;
                            }
                        }
                        if may_have {
                            cleanup = Some(gid);
                        }
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
                // ⟨r2.5⟩ §13.8 item 5: when the last operation attached to a
                // shared grant whose owner was cancelled after approval cancels,
                // the grant is cancelled (or released, if the owner's continued
                // preparation already activated it) and its prepared credential is
                // cleaned up through the usual path.
                if let Some(gid) = &pinned
                    && let Some(orphan) = end_orphaned_in(tx, emit, gid, &id)?
                {
                    cleanup = Some(orphan);
                }
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
        let configured = self.adapter_identities();
        // Phase 1 (once): tombstone + generation + cascade, before acknowledgment.
        // ⟨r2.9⟩ ADR-0006 §13.12: the same committed transaction claims the first
        // local denial round (an explicit revoke re-arms the bounded schedule,
        // §13.11 item 4), so the adapters are called only by the drive that ran
        // phase 1; a later drive (restart recovery, a same-key retry) never calls
        // them again and completes from the record.
        let id2 = id.clone();
        let root = req.grant_id.clone();
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        let (grants, round) = self
            .write(move |tx, emit| {
                let Some(mut op) = tx.operation(&id2)? else {
                    return Ok((Vec::new(), None));
                };
                let mut all = vec![root.clone()];
                all.extend(tx.grant_descendants(&root)?);
                if op.state != OperationState::Queued {
                    return Ok((all, None));
                }
                let tombstone = Tombstone {
                    grant: root.clone(),
                    cascade: all[1..].to_vec(),
                    generation: tx.authority_generation()?,
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                };
                tx.insert_tombstone(&tombstone)?;
                // Local denial; operations waiting for approval on a revoked grant
                // end now.
                revoke_locally_in(
                    tx,
                    emit,
                    &all,
                    RevocationCause::Revoke,
                    now,
                    Some(&id2),
                    retention,
                )?;
                let round = claim_first_round_in(tx, &root, &all, &configured, now, true)?;
                // ⟨r2.10⟩ §13.13 item 4: the re-armed record's claim (if any) is this
                // process's; an interrupted one found at startup is superseded.
                forget_interrupted(&interrupted, &root);
                op_to(&mut op, OperationEvent::Start, now)?;
                tx.update_operation(&op)?;
                emit.op(tx, &op)?;
                Ok((all, Some(round)))
            })
            .await?;
        if grants.is_empty() {
            return Ok(());
        }
        // Phase 2: local revocation through each grant's responsible adapters;
        // remote effects are reported, never assumed.
        let round = round.unwrap_or_default();
        let answers = self.run_round(&round, now).await;
        // Phase 3: settle with the residual from the issuance log ∪ adapters; only
        // a responsible adapter's confirmation clears an obligation.
        let id3 = id.clone();
        self.write(move |tx, emit| {
            let Some(mut op) = tx.operation(&id3)? else {
                return Ok(());
            };
            if op.state != OperationState::Running {
                return Ok(());
            }
            let data = complete_round_in(
                tx,
                emit,
                &grants[0],
                &grants,
                round.claim,
                &answers,
                None,
                Some(&id3),
            )?;
            let value = serde_json::to_value(&data)?;
            settle_succeeded(tx, emit, &mut op, Code::Ok, value, now, retention)
        })
        .await
    }

    /// ⟨r2.9⟩ The configured adapters' identities.
    fn adapter_identities(&self) -> Vec<AdapterIdentity> {
        self.inner
            .config
            .adapters
            .iter()
            .map(|a| a.descriptor().identity.clone())
            .collect()
    }

    /// ⟨r2.9⟩ Make a claimed round's calls (spec §6.7; ADR-0006 §13.12): each
    /// grant is asked of exactly the configured adapter the round names (an
    /// adapter error or a pending remote effect is not a confirmation; an adapter
    /// gone since the claim answers nothing), and the latest credential expiry the
    /// adapters reported.
    async fn run_round(&self, round: &Round, now: Timestamp) -> RoundAnswers {
        let mut out = RoundAnswers::default();
        for call in &round.calls {
            let Some(adapter) = self.adapter(Some(&call.adapter)) else {
                continue;
            };
            let confirmed = match adapter.revoke(&call.grant, now).await {
                Ok(o) => {
                    if let Some(t) = o.latest_possible_credential_expiry {
                        out.adapter_expiry = Some(out.adapter_expiry.map_or(t, |e| e.max(t)));
                    }
                    o.remote_pending.is_empty()
                }
                Err(_) => false,
            };
            out.answers
                .push((call.grant.clone(), call.adapter.clone(), confirmed));
        }
        out
    }

    /// Complete the withdrawals [`end_in`] started (ADR-0006 §13.8 item 4): local
    /// denial through the adapters, then, per withdrawn root, `revoking → revoked`
    /// for every covered grant with nothing pending and one `authority_withdrawn`
    /// credential-lifecycle event reporting the result as for any revocation
    /// (`local_applied`, `remote_pending`, `latest_possible_credential_expiry`).
    /// Best effort after the tombstone committed: a failure leaves the grants
    /// `revoking`, which already refuses every use, and the next scheduler pass or
    /// the next start completes them ([`Operations::complete_interrupted_withdrawals`],
    /// ADR-0006 §13.9 item 3).
    async fn complete_withdrawals(&self, ended: Ended) {
        if ended.is_empty() {
            return;
        }
        for (root, grants) in ended.withdrawn {
            self.complete_withdrawal(root, grants, RevocationCause::AuthorityWithdrawn)
                .await;
        }
    }

    /// Complete one revocation rooted at `root` (`grants`: the root, then the
    /// descendants its tombstone covers), idempotently: local denial through every
    /// adapter, `revoking → revoked` for every grant with nothing pending remotely,
    /// and, for a withdrawal (`AuthorityWithdrawn`), the `authority_withdrawn`
    /// credential-lifecycle event with the residual, reported **once** per root
    /// (`Txn::record_withdrawal_report` in the same transaction; ⟨r2.6⟩ ADR-0006
    /// §13.9 item 3). An explicit revoke reports through its own operation's result,
    /// so it emits no such event here.
    async fn complete_withdrawal(
        &self,
        root: GrantId,
        grants: Vec<GrantId>,
        cause: RevocationCause,
    ) {
        let now = self.narrowing_now().await;
        // ⟨r2.9⟩ ADR-0006 §13.12: the first local denial is claimed in its own
        // committed transaction before any adapter is called. A root that already
        // has a pending record (an earlier claim, completed or not) is never called
        // again here: it is completed from the record, and further rounds come only
        // from the supervisor's bounded schedule.
        let configured = self.adapter_identities();
        let (r, g) = (root.clone(), grants.clone());
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        let claimed = self
            .write(move |tx, _| {
                if tx.remote_revocation(&r)?.is_some() {
                    return Ok(Round::default());
                }
                let round = claim_first_round_in(tx, &r, &g, &configured, now, false)?;
                if round.claim.is_some() {
                    forget_interrupted(&interrupted, &r);
                }
                Ok(round)
            })
            .await;
        let round = match claimed {
            Ok(round) => round,
            Err(e) => {
                tracing::warn!(code = %e.code, "a withdrawn grant was left revoking");
                return;
            }
        };
        let answers = self.run_round(&round, now).await;
        let done = self
            .write(move |tx, emit| {
                // ⟨r2.7⟩ §13.10 item 3: anything still pending is retried by the
                // supervisor only, on its bounded, jittered schedule.
                let data = complete_round_in(
                    tx,
                    emit,
                    &root,
                    &grants,
                    round.claim,
                    &answers,
                    None,
                    None,
                )?;
                if cause == RevocationCause::AuthorityWithdrawn && tx.record_withdrawal_report(&root)? {
                    emit.event(
                        tx,
                        EventType::CredentialLifecycle,
                        None,
                        Some(resource("grant", &root)),
                        serde_json::json!({
                            "grant_id": root,
                            "event": "authority_withdrawn",
                            "cause": RevocationCause::AuthorityWithdrawn,
                            "cascade": &grants[1..],
                            "local_applied": data.local_applied,
                            "remote_pending": data.remote_pending,
                            "latest_possible_credential_expiry": data.latest_possible_credential_expiry,
                        }),
                    )?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = done {
            tracing::warn!(code = %e.code, "a withdrawn grant was left revoking");
        }
    }

    /// ⟨r2.6⟩ ADR-0006 §13.9 item 3: at startup and in every scheduler pass,
    /// idempotently complete every grant left in `revoking` (a crash or a failure
    /// between a tombstone and its completion): local denial, the residual, the
    /// move to `revoked` once nothing is pending remotely, and, for a withdrawal,
    /// its one `credential_lifecycle` report ([`Operations::complete_withdrawal`]).
    /// Grants are grouped by the tombstoned root that covers them (the grant itself
    /// or its nearest tombstoned ancestor). An explicit revoke whose operation is
    /// still open is left to that operation (restart recovery drives it). A grant in
    /// `revoking` without any tombstone on its chain is left as it is (it refuses
    /// every use). Narrowing only, so it runs whatever the time status.
    async fn complete_interrupted_withdrawals(&self) {
        let found = self
            .write(move |tx, _| {
                let revoking: Vec<GrantSnapshot> = tx
                    .grants_due(Timestamp::MAX)?
                    .into_iter()
                    .filter(|g| g.state == GrantState::Revoking)
                    .collect();
                let mut roots: BTreeMap<GrantId, (Vec<GrantId>, RevocationCause)> = BTreeMap::new();
                if revoking.is_empty() {
                    return Ok(roots);
                }
                let mut driven: BTreeSet<GrantId> = BTreeSet::new();
                for op in tx.open_operations()? {
                    if op.kind != OperationKind::Revoke {
                        continue;
                    }
                    if let Some(intent) = tx.recovery_intent(&op.id)?
                        && let Ok(Request::Revoke(r)) = serde_json::from_value(intent.request)
                    {
                        driven.insert(r.grant_id);
                    }
                }
                for g in revoking {
                    let Some(root) = tx.denied_ancestor(&g.id)? else {
                        continue;
                    };
                    if roots.contains_key(&root) {
                        continue;
                    }
                    let Some(t) = tx.tombstone(&root)? else {
                        continue;
                    };
                    if t.cause == RevocationCause::Revoke && driven.contains(&root) {
                        continue;
                    }
                    // ⟨r2.7⟩ ADR-0006 §13.10 item 3: local denial already ran (or was
                    // claimed, ⟨r2.9⟩ §13.12) and left a remote effect pending.
                    // Repeated adapter calls for it follow the supervisor's bounded,
                    // jittered backoff (`Operations::retry_remote_revocation`), never
                    // every pass. A withdrawal whose claimed first round never
                    // completed still owes its one report: it is completed from the
                    // record, without calling the adapters.
                    if tx.remote_revocation(&root)?.is_some()
                        && (t.cause != RevocationCause::AuthorityWithdrawn
                            || tx.withdrawal_reported(&root)?)
                    {
                        continue;
                    }
                    let mut all = vec![root.clone()];
                    all.extend(t.cascade.iter().filter(|c| **c != root).cloned());
                    roots.insert(root, (all, t.cause));
                }
                Ok(roots)
            })
            .await;
        let roots = match found {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(code = %e.code, "interrupted withdrawals could not be read");
                return;
            }
        };
        for (root, (grants, cause)) in roots {
            self.complete_withdrawal(root, grants, cause).await;
        }
    }

    /// ⟨r2.7⟩ ADR-0006 §13.10 item 3: every revocation whose remote part local
    /// denial left pending (one record per tombstoned root, ordered by root),
    /// stopped ones included. The supervisor's revocation retry executor reads this.
    pub async fn pending_remote_revocations(
        &self,
    ) -> Result<Vec<PendingRemoteRevocation>, OpError> {
        self.write(|tx, _| tx.remote_revocations()).await
    }

    /// ⟨r2.10⟩ ADR-0006 §13.13 item 4: whether `record` carries a claimed but
    /// uncompleted round that a previous run of the runtime left behind (found when
    /// this runtime started, and not claimed again by it since). The supervisor runs
    /// such a round at once instead of after a back-off; the interrupted round
    /// still counts as attempted (§13.12 item 1). A round claimed by this process
    /// and still in flight, or one whose completion failed in this process, is not
    /// interrupted in this sense.
    #[must_use]
    pub fn round_interrupted(&self, record: &PendingRemoteRevocation) -> bool {
        record.claimed_at.is_some()
            && self
                .inner
                .interrupted_rounds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&record.root)
    }

    /// ⟨r2.7⟩ ADR-0006 §13.10 item 3: one round of the bounded retries of the
    /// pending remote part of the revocation rooted at `root`, called by the
    /// supervisor's single retry owner when the round is due on its jittered
    /// schedule (spec §13.5; §13.6 item 4). Narrowing, so it runs whatever the
    /// time status.
    ///
    /// * No record, or none of its grants still `revoking`: nothing to do; the
    ///   record (if any) is removed and the answer is `None`.
    /// * A `stopped` record: no adapter call, the record is returned unchanged.
    /// * `attempts >= max_attempts`: the record is marked `stopped` and returned;
    ///   no adapter call.
    /// * ⟨r2.9⟩ ADR-0006 §13.12 item 2: no adapter responsible for any obligation
    ///   is configured: no call, **no attempt consumed**, each such obligation
    ///   carries the reason `adapter_unavailable`; the record is returned with the
    ///   same `attempts` (the supervisor still backs off).
    /// * Otherwise ⟨r2.9⟩ (§13.12 item 1) the round is first **claimed** in its own
    ///   committed transaction (`attempts + 1`, `claimed_at`), then each obligation
    ///   is asked of its responsible adapter only, then the completion transaction
    ///   clears each obligation that adapter confirmed, moves every grant with no
    ///   obligation left to `revoked`, completes the claim (`claimed_at` cleared,
    ///   `stopped` once it reached `max_attempts` with something still pending) or
    ///   removes the record when nothing is left (`None`). A completion that fails,
    ///   or never runs (a crash after the call), leaves the claimed attempt
    ///   counted, so the cap bounds the adapter calls whatever fails.
    ///
    /// No event other than a grant's own `revoking → revoked` change is emitted
    /// (spec §12.3: no repeated nuisance notifications); the withdrawal report and
    /// the explicit revoke's result stay the only reports. A record rewritten
    /// meanwhile (an explicit revoke re-arms it) keeps its own count and claim; the
    /// round's confirmations still clear the obligations they answer.
    pub async fn retry_remote_revocation(
        &self,
        root: &GrantId,
        max_attempts: u32,
    ) -> Result<Option<PendingRemoteRevocation>, OpError> {
        let now = self.narrowing_now().await;
        let configured = self.adapter_identities();
        let r = root.clone();
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        let claimed = self
            .write(move |tx, _| {
                let claimed = claim_retry_round_in(tx, &r, &configured, now, max_attempts)?;
                if matches!(claimed, RetryClaim::Claimed(..)) {
                    forget_interrupted(&interrupted, &r);
                }
                Ok(claimed)
            })
            .await?;
        let (round, grants) = match claimed {
            RetryClaim::Gone => return Ok(None),
            RetryClaim::Unchanged(record) => return Ok(Some(record)),
            RetryClaim::Claimed(round, grants) => (round, grants),
        };
        let answers = self.run_round(&round, now).await;
        let r = root.clone();
        self.write(move |tx, emit| {
            complete_round_in(
                tx,
                emit,
                &r,
                &grants,
                round.claim,
                &answers,
                Some(max_attempts),
                None,
            )?;
            tx.remote_revocation(&r)
        })
        .await
    }

    /// ADR-0006 §13.8 item 4 at use, after a refused use of `grant` that the
    /// caller could not end in its own transaction: end `grant` and its ancestors
    /// when they can no longer be used (fresh time assessed in this transaction;
    /// uncertain time ends nothing), and complete any withdrawal.
    async fn end_if_invalid(&self, grant: &GrantId) {
        let gate = self.inner.timegate.in_txn();
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let retention = self.retention();
        let gid = grant.clone();
        let ended = self
            .write(move |tx, emit| {
                let Ok(safe) = gate.check(tx)? else {
                    return Ok(Ended::default());
                };
                end_in(
                    tx, emit, &env, &adapters, &gate, &gid, &safe, None, retention,
                )
            })
            .await;
        match ended {
            Ok(ended) => self.complete_withdrawals(ended).await,
            Err(e) => tracing::warn!(code = %e.code, "a grant's end could not be recorded"),
        }
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
        // `TIME_UNCERTAIN` no widening record is created. Time is assessed in the
        // transaction that writes (code review A02).
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let attended = caller.is_attended();
        let action = req.clone();
        let r = self
            .write(move |tx, emit| {
                let assessed = gate.check(tx)?;
                let now = match &assessed {
                    Ok(s) => s.wall(),
                    Err(_) => gate.clock().wall(),
                };
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
                    if let Err(u) = &assessed {
                        return Ok(Err(uncertain(u)));
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
    /// delta and resumes the waiting operation, and every request that joined the
    /// same record (code review A07).
    ///
    /// An approval is assessed against time in its own transaction (A02) and is
    /// refused (`DECISION_STALE`, nothing consumed) when the record no longer
    /// covers what the waiting grant needs against current policy (A06); a same-key
    /// retry then gets a recomputed record. The approval is recorded on each
    /// waiting intent as its [`ApprovalBasis`], which activation re-validates.
    ///
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 2: every resumed waiter is driven at once and the
    /// request waits for them under ONE overall `Limits::max_wait`; when it is
    /// reached the durable decision result is returned (the work continues, every
    /// waiter's operation observable). Waiters never wait one after another.
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
        // A denial narrows and never waits for safe time.
        let deny_now = match req.verdict {
            Verdict::Approve => None,
            Verdict::Deny => Some(self.narrowing_now().await),
        };
        let gate = self.inner.timegate.in_txn();
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let retention = self.retention();
        let did = req.decision_id.clone();
        let verdict = req.verdict;
        let r = self
            .write(move |tx, emit| {
                let now = match deny_now {
                    Some(now) => now,
                    None => match gate.check(tx)? {
                        Ok(s) => s.wall(),
                        Err(u) => return Ok(Err(uncertain(&u))),
                    },
                };
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
                // The waiting grant (shared by every request that joined it).
                let grant = match &waiting {
                    Some(op) => tx
                        .recovery_intent(&op.id)?
                        .and_then(|i| i.resolved)
                        .and_then(|r| r.grant)
                        .map(|g| tx.grant(&g))
                        .transpose()?
                        .flatten(),
                    None => None,
                };
                let current = tx.authority_generation()?;
                // A06: an approval must still describe the authority the waiting
                // grant needs now (checked at the record's own generation; a moved
                // generation is the store's `Stale` refusal below).
                if verdict == Verdict::Approve
                    && d.generation == current
                    && let DecisionKind::ApproveAuthority { delta, .. } = &d.kind
                {
                    let needed = match &grant {
                        Some(g) => current_delta(tx, &env, &adapters, g, now)?,
                        None => None,
                    };
                    if needed.is_none_or(|n| !delta_within(&n, delta)) {
                        return Ok(Err(OpError::new(
                            Code::DecisionStale,
                            "the decision no longer describes the authority the request needs; retry the request for a fresh decision",
                        )
                        .with_resource("decision", Some(did.to_string()))));
                    }
                }
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
                // Every operation waiting on the record's grant: its creator first,
                // then the requests that joined it (A07).
                let mut waiters: Vec<OperationRecord> = waiting.into_iter().collect();
                if let Some(g) = &grant {
                    for o in tx.open_operations()? {
                        if o.state == OperationState::AwaitingApproval
                            && waiters.iter().all(|w| w.id != o.id)
                            && tx
                                .recovery_intent(&o.id)?
                                .and_then(|i| i.resolved)
                                .and_then(|r| r.grant)
                                .as_ref()
                                == Some(&g.id)
                        {
                            waiters.push(o);
                        }
                    }
                }
                let mut resume = Vec::new();
                match (&record.kind, verdict) {
                    (DecisionKind::ApproveAuthority { delta, .. }, Verdict::Approve) => {
                        if let Some(mut g) = grant.clone()
                            && grant_try(&mut g, GrantEvent::Approved)
                        {
                            put_grant(tx, emit, &g, op_id.as_ref())?;
                        }
                        let mut recorded_with_grant = false;
                        for mut op in waiters {
                            let mut intent = tx
                                .recovery_intent(&op.id)?
                                .ok_or_else(|| conflict("operation has no recovery intent"))?;
                            if let Some(r) = intent.resolved.as_mut() {
                                let revision = merged_policy(&tx.policies_for(&r.profile, &env)?)
                                    .filter(|p| p.profile == r.profile)
                                    .map(|p| p.revision);
                                let basis = ApprovalBasis {
                                    decision: record.id.clone(),
                                    delta: delta.clone(),
                                    generation: record.generation,
                                    policy_revision: revision,
                                };
                                // ⟨r2.4⟩ §13.7 item 3: the basis is persisted with
                                // the shared grant in this transaction, so
                                // operation retention cannot purge it.
                                if !recorded_with_grant && let Some(g) = &grant {
                                    tx.set_grant_approval(&g.id, &basis)?;
                                    recorded_with_grant = true;
                                }
                                r.approval = Some(basis);
                            }
                            tx.set_recovery_intent(&op.id, &intent)?;
                            op_to(&mut op, OperationEvent::Approved, now)?;
                            tx.update_operation(&op)?;
                            emit.op(tx, &op)?;
                            resume.push(op.id.clone());
                        }
                    }
                    (DecisionKind::ApproveAuthority { .. }, Verdict::Deny) => {
                        if let Some(mut g) = grant.clone()
                            && grant_try(&mut g, GrantEvent::DecisionDenied)
                        {
                            put_grant(tx, emit, &g, op_id.as_ref())?;
                        }
                        let err = OpError::new(
                            Code::CapabilityUnavailable,
                            "the owner denied the requested additional authority",
                        );
                        for mut op in waiters {
                            settle_failed(tx, emit, &mut op, &err, now, retention)?;
                        }
                    }
                    (DecisionKind::WidenPolicy { action }, Verdict::Approve) => {
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
        // Resume the waiting operations, all at once (the record's own operation
        // first), under ONE overall bound for this request (⟨r2.5⟩ ADR-0006 §13.8
        // item 2): when it is reached the durable decision result is returned and
        // the work continues, every waiter's operation observable.
        let resume: Vec<(OperationId, bool)> = resume.into_iter().map(|id| (id, false)).collect();
        self.lead_all_bounded(&resume, self.inner.config.limits.max_wait)
            .await;
        let mut operation_state = None;
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
    ///
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 4 (the supervisor's scheduler pass): on safe time,
    /// every active or degraded grant whose re-validation fails ends here too, even
    /// if nothing uses it (`expired`, or `revoking`/`revoked` with an
    /// `authority_withdrawn` tombstone).
    pub async fn tick(&self) -> Result<(), crate::OpError> {
        let safe = match self.inner.timegate.check().await {
            Ok(s) => Some(s),
            // ⟨r2.6⟩ ADR-0006 §13.9 item 1: while uncertain, only the continuous
            // budget can end a grant (below); the wall clock ends nothing.
            Err(e) if e.code == Code::TimeUncertain => None,
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
                    let bound = grant_bound(&g, &ancestors, merged_policy(&policies).as_ref());
                    let bound = anchor_bound(tx, &g.id, bound)?;
                    let anchor = tx.grant_anchor(&g.id)?;
                    out.push((g, bound, anchor));
                }
                Ok(out)
            })
            .await?;
        for (g, bound, anchor) in candidates {
            let expired = match &safe {
                Some(safe) => {
                    let mut expired = dtime::is_expired(safe.wall(), bound);
                    if !expired && g.state.permits_use() {
                        // First validation in this boot anchors; a later earlier
                        // bound (cutoff) shortens; nothing lengthens.
                        let fresh_boot = anchor
                            .as_ref()
                            .is_none_or(|a| a.anchor.boot_id != safe.anchor.boot_id);
                        if fresh_boot {
                            self.inner.timegate.anchor_grant(&g.id, safe, bound).await?;
                        } else if anchor.as_ref().is_some_and(|a| a.bound > bound) {
                            self.inner.timegate.shorten_grant(&g.id, bound).await?;
                        }
                        // Trusted evidence only (§13.9 item 1): the accepted wall
                        // time and the continuous budget.
                        expired = self.inner.timegate.expired(&g.id, safe).await?;
                    }
                    expired
                }
                // §13.9 item 1: a wall bound that appears passed on an uncertain or
                // forward-jumped reading ends nothing (use is refused with
                // `TIME_UNCERTAIN` until time is safe, and the grant is judged
                // then); a continuous budget that ran out (a real sleep across the
                // deadline included) still expires it.
                None => anchor.is_some() && self.inner.timegate.budget_exhausted(&g.id).await?,
            };
            if expired {
                let at = safe
                    .as_ref()
                    .map_or_else(|| self.inner.config.clock.wall(), SafeNow::wall);
                self.expire_grant(&g.id, at).await?;
            }
        }
        // ⟨r2.5⟩ ADR-0006 §13.8 item 4, in the scheduler pass: every active or
        // degraded grant whose re-validation fails ends now, even if nothing uses
        // it (withdrawn authority ⇒ `revoking`/`revoked`; a bound found passed ⇒
        // `expired`). Only on time the gate accepts in this transaction: uncertain
        // time ends nothing, and a pause is never a reason.
        if safe.is_some() {
            let gate = self.inner.timegate.in_txn();
            let env = self.inner.config.environment.clone();
            let adapters = self.adapter_infos();
            let retention = self.retention();
            let ended = self
                .write(move |tx, emit| {
                    let mut ended = Ended::default();
                    let Ok(safe) = gate.check(tx)? else {
                        return Ok(ended);
                    };
                    for g in tx.grants_due(Timestamp::MAX)? {
                        if g.state.permits_use() {
                            ended.extend(end_in(
                                tx, emit, &env, &adapters, &gate, &g.id, &safe, None, retention,
                            )?);
                            // ⟨r2.7⟩ §13.10 item 2: a live grant whose mechanism went
                            // away degrades; one whose mechanism is back is repaired
                            // when re-validation passes.
                            track_mechanism_in(
                                tx, emit, &env, &adapters, &gate, &g.id, &safe, None,
                            )?;
                        }
                    }
                    Ok(ended)
                })
                .await?;
            self.complete_withdrawals(ended).await;
        }
        // ⟨r2.6⟩ ADR-0006 §13.9 item 3: every pass completes any grant left in
        // `revoking` (idempotent; narrowing, so whatever the time status).
        self.complete_interrupted_withdrawals().await;
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
    /// `issuance::check` against current store state and time, then the
    /// `reserved` entry with complete bounds, in one transaction. Nothing is signed
    /// before this commits. Time evidence (the gate's verdict and the continuous
    /// admission) comes from a fresh observation assessed **inside** that
    /// transaction (code review A01; ADR-0006 §14.2).
    ///
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 4: a refusal that shows the grant can no longer
    /// be used (on safe time) ends it in the same transaction (`expired`, or
    /// `revoking`/`revoked` with an `authority_withdrawn` tombstone).
    pub async fn reserve_issuance(&self, req: IssuanceRequest) -> Result<IssuanceEntry, OpError> {
        let id = crate::ids::new_issuance_id()?;
        let serial = crate::ids::random_u64()?;
        let env = self.inner.config.environment.clone();
        let adapters = self.adapter_infos();
        let gate = self.inner.timegate.in_txn();
        let retention = self.retention();
        let (r, ended) = self
            .write(move |tx, emit| {
                let (safe, time, now) = issuance_time(&gate, tx)?;
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2 (before the use is judged).
                if let Some(s) = &safe {
                    track_mechanism_in(tx, emit, &env, &adapters, &gate, &req.grant, s, None)?;
                }
                let Some(grant) = tx.grant(&req.grant)? else {
                    return Ok((
                        Err(OpError::new(Code::NotFound, "unknown grant")
                            .with_resource("grant", None)),
                        Ended::default(),
                    ));
                };
                // First validation in this boot anchors; an earlier bound shortens.
                if let Some(s) = &safe
                    && grant.state.permits_issuance()
                {
                    let ctx = grant_context(tx, &grant)?;
                    let bound = bound_of(tx, &env, &grant, ctx.profile.as_ref())?;
                    first_validation_anchor(tx, &gate, &grant.id, s, bound)?;
                }
                let bounds = CertificateBounds {
                    serial,
                    key_id: req.key_id.clone(),
                    principal: req.principal.clone(),
                    valid_after: req.valid_after,
                    valid_before: req.valid_before,
                    extensions: req.extensions.clone(),
                    subject_fingerprint: req.subject_fingerprint.clone(),
                };
                if let Err(refusal) = run_issuance_check(
                    tx,
                    &env,
                    &adapters,
                    &grant,
                    &req.pair,
                    &bounds,
                    &req.facts,
                    time,
                    safe.as_ref(),
                    now,
                )? {
                    let ended = match &safe {
                        Some(s) => end_in(
                            tx, emit, &env, &adapters, &gate, &grant.id, s, None, retention,
                        )?,
                        None => Ended::default(),
                    };
                    return Ok((Err(OpError::from_issuance_refusal(&refusal)), ended));
                }
                Ok((
                    Ok(reserve_entry(
                        tx, emit, id, &grant.id, &req.pair, bounds, now,
                    )?),
                    Ended::default(),
                ))
            })
            .await?;
        self.complete_withdrawals(ended).await;
        let r = r?;
        self.inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(r.id.clone(), (r.grant.clone(), 1));
        Ok(r)
    }

    /// Publish a reservation (ADR-0005 §3.5 step 3): re-run **every** predicate
    /// with current state and time, assessed inside the publishing transaction
    /// (code review A01); on any refusal the entry is `voided` and nothing is
    /// released. An entry reserved before this runtime instance started is never
    /// published (it stays counted until its `valid_before`).
    ///
    /// ⟨r2.5⟩ ADR-0006 §13.8 item 1 (with §13.6 item 11 and the ADR-0005 §3.5
    /// amendment): a reservation voided **only** because the authority generation
    /// moved (the grant and its chain re-validate at the current generation and
    /// every predicate holds) is voided and a fresh reservation is made in the same
    /// transaction, with the same bounds and a fresh serial and ID at the current
    /// generation, under the reserve rules. That reservation is returned
    /// **unpublished** as [`Publication::Rereserved`]: the issuer signs exactly its
    /// bounds and calls this method again with its ID; that final publish runs
    /// every predicate again in its own transaction, so a revoke, an expiry or
    /// uncertain time between signing and publishing voids it. The
    /// [`PUBLISH_ATTEMPTS`] bound counts these round trips (the original
    /// reservation is attempt 1): a reservation whose publication would need yet
    /// another one is voided and answered `SERVICE_UNAVAILABLE` (exit 5,
    /// retryable, `next: retry_after`), with nothing left reserved. A failed
    /// re-validation answers that denial's own code and, per §13.8 item 4, ends a
    /// grant that can no longer be used in the same transaction.
    pub async fn publish_issuance(
        &self,
        id: &IssuanceId,
        facts: &IssuanceFacts,
    ) -> Result<Publication, OpError> {
        let tracked = self
            .inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned();
        let Some((grant, attempt)) = tracked else {
            return Err(OpError::new(
                Code::CredentialExpired,
                "this reservation was not made by this runtime instance; reserve afresh",
            )
            .with_resource("grant", None));
        };
        let last = attempt >= PUBLISH_ATTEMPTS;
        let fresh_id = crate::ids::new_issuance_id()?;
        let serial = crate::ids::random_u64()?;
        let env = self.inner.config.environment.clone();
        let gate = self.inner.timegate.in_txn();
        let entry_id = id.clone();
        let facts = facts.clone();
        let adapters = self.adapter_infos();
        let retention = self.retention();
        let gid = grant.clone();
        let (outcome, ended) = self
            .write(move |tx, emit| {
                let (safe, time, now) = issuance_time(&gate, tx)?;
                let Some(entry) = tx
                    .issuance_entries(&gid)?
                    .into_iter()
                    .find(|e| e.id == entry_id)
                else {
                    return Ok((
                        Published::refused(OpError::new(Code::NotFound, "unknown issuance entry")),
                        Ended::default(),
                    ));
                };
                if entry.state != IssuanceState::Reserved {
                    return Ok((
                        Published::refused(OpError::new(
                            Code::RequestConflict,
                            "the issuance entry is already settled",
                        )),
                        Ended::default(),
                    ));
                }
                // ⟨r2.7⟩ ADR-0006 §13.10 item 2 (before the use is judged).
                if let Some(s) = &safe {
                    track_mechanism_in(tx, emit, &env, &adapters, &gate, &gid, s, None)?;
                }
                let check = match tx.grant(&gid)? {
                    None => Err(IssuanceRefusal::GrantNotIssuable(GrantState::Revoked)),
                    Some(g) => run_issuance_check(
                        tx,
                        &env,
                        &adapters,
                        &g,
                        &entry.pair,
                        &entry.bounds,
                        &facts,
                        time,
                        safe.as_ref(),
                        now,
                    )?,
                };
                // Reserve and publish observe the same generation (ADR-0006
                // §13.5 ruling 2).
                let generation = tx.authority_generation()?;
                match check {
                    Ok(()) if generation == entry.generation => {
                        let published = tx.publish_issuance(&entry_id, now)?;
                        issuance_event(tx, emit, &gid, &entry_id, "published")?;
                        Ok((Published::Done(Box::new(published)), Ended::default()))
                    }
                    Ok(()) => {
                        // §13.6 item 11: only the generation moved; the chain
                        // re-validated and every predicate holds now. §13.8 item 1:
                        // the fresh reservation goes back to the issuer unsigned.
                        tx.void_issuance(&entry_id, &IssuanceRefusal::StaleGeneration, now)?;
                        issuance_event(tx, emit, &gid, &entry_id, "voided")?;
                        if last {
                            return Ok((Published::Racing, Ended::default()));
                        }
                        let bounds = CertificateBounds {
                            serial,
                            ..entry.bounds
                        };
                        let fresh =
                            reserve_entry(tx, emit, fresh_id, &gid, &entry.pair, bounds, now)?;
                        Ok((Published::Rereserved(Box::new(fresh)), Ended::default()))
                    }
                    Err(refusal) => {
                        tx.void_issuance(&entry_id, &refusal, now)?;
                        issuance_event(tx, emit, &gid, &entry_id, "voided")?;
                        let ended = match &safe {
                            Some(s) => {
                                end_in(tx, emit, &env, &adapters, &gate, &gid, s, None, retention)?
                            }
                            None => Ended::default(),
                        };
                        Ok((
                            Published::refused(OpError::from_issuance_refusal(&refusal)),
                            ended,
                        ))
                    }
                }
            })
            .await?;
        self.complete_withdrawals(ended).await;
        let mut here = self
            .inner
            .reserved_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        here.remove(id);
        match outcome {
            Published::Done(entry) => Ok(Publication::Published(*entry)),
            Published::Refused(e) => Err(*e),
            Published::Rereserved(fresh) => {
                here.insert(fresh.id.clone(), (grant, attempt + 1));
                Ok(Publication::Rereserved {
                    reservation: *fresh,
                })
            }
            Published::Racing => Err(OpError::new(
                Code::ServiceUnavailable,
                "the authority generation kept changing during publication; reserve again and retry",
            )
            .with_resource("grant", None)
            .with_retry_after(PUBLISH_RETRY_MS)),
        }
    }
}

/// Time evidence for an issuance step, assessed by the gate inside the step's own
/// transaction (code review A01): the accepted observation when `Safe`, the
/// verdict (`Uncertain` is a refusal reason, not an error), and `now` (the
/// accepted wall time, else the raw wall clock, which can only refuse).
fn issuance_time(
    gate: &TxnGate,
    tx: &mut Txn<'_>,
) -> heimdall_store::Result<(Option<SafeNow>, dtime::TimeStatus, Timestamp)> {
    Ok(match gate.check(tx)? {
        Ok(s) => {
            let now = s.wall();
            (Some(s), dtime::TimeStatus::Safe, now)
        }
        Err(u) => (None, dtime::TimeStatus::Uncertain(u), gate.clock().wall()),
    })
}

/// Insert a `reserved` entry at the current generation, with its event.
fn reserve_entry(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    id: IssuanceId,
    grant: &GrantId,
    pair: &AccessPair,
    bounds: CertificateBounds,
    now: Timestamp,
) -> heimdall_store::Result<IssuanceEntry> {
    let entry = IssuanceEntry {
        id,
        grant: grant.clone(),
        generation: tx.authority_generation()?,
        pair: pair.clone(),
        bounds,
        state: IssuanceState::Reserved,
        reserved_at: now,
        settled_at: None,
        void_reason: None,
    };
    tx.reserve_issuance(&entry)?;
    issuance_event(tx, emit, grant, &entry.id, "reserved")?;
    Ok(entry)
}

fn issuance_event(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grant: &GrantId,
    id: &IssuanceId,
    event: &str,
) -> heimdall_store::Result<()> {
    emit.event(
        tx,
        EventType::CredentialLifecycle,
        None,
        Some(resource("grant", grant)),
        serde_json::json!({ "grant_id": grant, "issuance_id": id, "event": event }),
    )
}

/// One publication transaction (ADR-0006 §13.6 item 11, §13.8 item 1).
enum Published {
    Done(Box<IssuanceEntry>),
    Rereserved(Box<IssuanceEntry>),
    Racing,
    Refused(Box<OpError>),
}

/// The outcome of one publication round trip (ADR-0005 §3.5 step 3 with its
/// 2026-11-01 amendment; ⟨r2.5⟩ ADR-0006 §13.8 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    /// Every predicate held in the publishing transaction: the entry is
    /// `published`; the certificate signed over exactly its bounds may be
    /// released.
    Published(IssuanceEntry),
    /// Only the authority generation moved (the grant and its chain re-validated
    /// and every predicate held): the entry was voided and this fresh reservation
    /// (new serial and ID, the other bounds unchanged, at the current generation)
    /// was made in the same transaction. It is **not** published. The issuer signs
    /// exactly its bounds, then calls [`Operations::publish_issuance`] with its
    /// ID; the round trips count towards the attempt bound.
    Rereserved {
        /// The fresh `reserved` entry.
        reservation: IssuanceEntry,
    },
}

impl Published {
    fn refused(e: OpError) -> Self {
        Self::Refused(Box::new(e))
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
    // nothing, the stale generation itself refuses. Re-validation measures the
    // policy window from `now`, so it runs only on time the gate accepted: on
    // uncertain time it is deferred (nothing recorded) and the predicate refuses
    // on time (`TIME_UNCERTAIN`) unless a time-independent predicate refuses
    // first, instead of a spurious authority refusal (code review A01).
    let (subject, chain, revalidation_failed) = if stale && safe.is_none() {
        (
            at_current(grant.clone()),
            raw.into_iter().map(at_current).collect(),
            false,
        )
    } else if stale {
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
    // ⟨r2.3⟩ §13.6 item 1: issuance within an existing grant (renewal, re-issue
    // under ADR-0005 §3.7) is continuing work and does not see a pause; a new
    // activation does.
    let view = if facts.new_activation {
        merged_policy(&policies)
    } else {
        continuing_policy(&policies)
    };
    let policy = view.as_ref();
    // §13.5 ruling 2 with §13.6 item 5: every change to an applicable policy
    // moves the generation, so a chain validated at the current generation was
    // validated against the current applicable revision. That revision is then the
    // expected one (and the one the validated copy carries); a chain that failed
    // re-validation keeps its recorded revision, so a changed policy refuses.
    let mut subject = subject;
    let mut expected_policy_revision = ctx.expected_policy_revision;
    if !revalidation_failed
        && let Some(p) = policy.filter(|p| Some(&p.profile) == ctx.profile.as_ref())
    {
        if let AuthorizationSource::StandingPolicy { revision } = &mut subject.source {
            *revision = p.revision;
        }
        if expected_policy_revision.is_some() {
            expected_policy_revision = Some(p.revision);
        }
    }
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
        expected_policy_revision,
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
    // ⟨r2.7⟩ ADR-0006 §13.10 item 2: after every predicate held, a grant whose
    // credential mechanism is unavailable is still refused (nothing ends).
    let mechanism = mechanism_refuses(tx, adapters, grant)?;
    Ok(match heimdall_domain::issuance::check(&check) {
        Ok(()) if revalidation_failed => Err(IssuanceRefusal::StaleGeneration),
        Ok(()) if mechanism => Err(IssuanceRefusal::MechanismUnavailable),
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
