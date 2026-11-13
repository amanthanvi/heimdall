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
//!   `CREDENTIAL_EXPIRED` (ADR-0006 §13.3). ⟨M02⟩ A setup or catalog operation has no
//!   grant: when its `ApplyProjection` or `DeclareInteraction` record passes its
//!   deadline the operation itself expires the same way, with no fresh record
//!   (ADR-0007 §12.22 item 9; `expire_awaiting_local_in`). Equivalent waiting
//!   requests share one record and one grant, each keeping its own operation (code
//!   review A07). An
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
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use heimdall_contract::envelope::{EffectStatus, NextAction, ResourceRef, Warning};
use heimdall_contract::event::{EventType, Snapshot};
use heimdall_contract::ids::{
    BindingId, DestinationId, EnvironmentId, GrantId, IssuanceId, OperationId, PolicyId, ProfileId,
    WorkId,
};
use heimdall_contract::provider::{
    CredentialAvailability, EndpointRef, EvidenceBasis, IdentitiesOnly, IdentitySelection,
    IdentitySelectionReport, InteractionKind, NoninteractiveEligibility, ProviderKind,
    ProviderStatus, noninteractive_reason,
};
use heimdall_contract::request::{
    BindForm, BindRequest, CancelRequest, ConfirmTimeRequest, ConsumerIntegration, DeadlineIntent,
    DecideRequest, DelegateRequest, DestinationScopeEnforcement, EnsureData, EnsureRequest,
    InspectRequest, InspectSubject, InteractionMode, MAX_SCOPE_PAIRS, ObserveRequest,
    PairIntegration, PolicyAction, RefreshDependency, ReleaseRequest, Request,
    RequiredCapabilities, RevokeData, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
use heimdall_domain::authority::{
    AuthorityDecision, AuthorityDelta, AuthorityInput, resolve_authority,
};
use heimdall_domain::binding::{BindingRecord, BindingState, ReleaseOutcome, may_act_on};
use heimdall_domain::catalog::{
    CatalogAction, DeclarationApproval, DestinationDefinition, IdentityRecord,
    InteractionDeclaration, PairEligibility, PreparedFacts, PreparedPair,
};
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
    LocalIntent, OperationKind, OperationRecord, RecoveryIntent, RecoveryMetadata, ResolvedIntent,
    StageReceipt,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::profile::ProfileSnapshot;
use heimdall_domain::projection::ProjectionApproval;
use heimdall_domain::revocation::{
    CleanupIntent, DEFAULT_ROUND_CAP, PendingRemoteRevocation, RearmedEffect, RemoteObligation,
    RemotePendingReason, RevocationCause, Tombstone,
};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{self as dtime, Admission, Clock, Deadline, TimePolicy, TimeSync};
use heimdall_store::{DecisionCompletion, SetupAdmitted, Store, StoreError, Txn};
use tokio::sync::watch;

use crate::context::{Attendance, Caller};
use crate::ensure::{EnsureHandle, EnsureStage, EquivalenceKey, StageHook};
use crate::error::{Completed, OpError, OpResult};
use crate::events::{EventPublisher, SequencedEvent, decision_kind_name, visible_to};
use crate::ports::{
    AdapterError, CredentialAdapter, IntegrationSnapshot, InteractionRequirement, LockContinuity,
    PrepareOutcome, PreparePair, PrepareRequest, ReconcileOutcome,
};
use crate::singleflight::{Flight, SingleFlight, follow};
use crate::timegate::{SafeNow, TimeGate, TxnGate, uncertain};

// ⟨M03⟩ U0b rows 6, 7, 8, 17, 23: restart recovery and supervisor hooks (wave 0).
mod restart_m03;
// ⟨M03⟩ U0b row 20 (G): the narrowing protocol; rows 5, 25, 26 (G): signature
// authorization, the lock revocation, the owned-connection registration.
mod authorize;
mod connections;
mod lock;
pub mod narrowing;
pub use lock::LockRevocation;
pub use lock_connection_m03::ConnectionWording;
pub use restart_m03::{
    AWAITING_OWNER_DELETION, BoundedReport, IntentOutcome, OWNER_RECONCILE, RetirementResume,
    only_bounded,
};
// ⟨M03⟩ U0b rows 2-4, 9-12, 19, E10 (O): CA issuance, verification issuance, per-pair
// mechanism, lock and connection policy, the bind-time owned connection, enrollment cancel.
mod bind_connection_m03;
mod ca_issuance_m03;
mod enrollment_cancel_m03;
mod lock_connection_m03;
mod managed_state_m03;
mod pair_mechanism_m03;
mod verification_m03;
// ⟨M03⟩ wave 4 (U10 + U0b phase 2): the enrollment stage driver, the issuer request
// handling, the managed effect driver's store side and re-issue pass, and the M03
// decision kinds' completion (each a child of `operations`, sharing the journal's
// private helpers).
mod decisions_m03;
mod enrollment_m03;
mod issuer_m03;
mod managed_driver_m03;
// ⟨M03⟩ wave 5, round 3 (ADR-0008 §17.27 item 2, W5-S01): the uninstall fence.
mod uninstall_fence_m03;
pub use bind_connection_m03::{dedicated_at_bind, verified_client_image};
pub use ca_issuance_m03::MANAGED_CERTIFICATE;
pub use uninstall_fence_m03::{
    ACQUIRE_WAIT as UNINSTALL_FENCE_ACQUIRE_WAIT, FenceAcquired, FenceAdmission, as_fence_holder,
    uninstall_in_progress, unresolved_remote_steps,
};
// ⟨W4-C02⟩ The scope evidence selection a fresh preparation and a follower share.
pub use managed_driver_m03::pair_evidence_under_ca;
pub use pair_mechanism_m03::unattended_refusal;
pub use verification_m03::VerificationRequest;
// ⟨M03⟩ U3: the issuer's read-only check shares the publish predicate (`issuance_ro`).
pub(crate) use verification_m03::verification_check_read_only;

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
    /// ⟨M02⟩ U0b row 24 (M2-T06; ADR-0006 §13.20 item 3; ADR-0007 §7 "Every call is
    /// bounded"; P12): the bound on one `CredentialAdapter` call, applied to the
    /// adapter future alone through [`bounded_adapter_call`]. Production default
    /// [`crate::ports::DEFAULT_ADAPTER_CALL_TIMEOUT`] (30 s); the production minimum
    /// is [`crate::ports::MIN_ADAPTER_CALL_TIMEOUT`] (1 s), which `Operations::start`
    /// does not enforce so that tests may use less (wave-0 verify E14).
    pub adapter_call_timeout: Duration,
    /// ⟨M02⟩ ADR-0007 §12.22 item 10 (m02-plan §5 item 19; QR1): how long an approved
    /// interaction declaration stays in force, from `[setup] declaration_validity_days`
    /// (default [`crate::catalog::DECLARATION_VALIDITY`], 30 days; the configuration
    /// accepts 1–90 days).
    pub declaration_validity: Duration,
    // --- ⟨M03⟩ m03-plan §5 item 17 (P7 as amended: proposals, tunable in M08 with
    // evidence; every payload limit derived with its serialization overhead) ---
    /// ⟨M03⟩ The bound on one signature's authorization (ADR-0008 D2 item 3); a
    /// timeout refuses. 2 s.
    pub signature_authorization_timeout: Duration,
    /// ⟨M03⟩ How long a signer waits for its grant's gate shared before it refuses
    /// (a signer waiting behind a narrowing; D2 item 3a step 3). 1 s.
    pub signing_gate_wait: Duration,
    /// ⟨M03⟩ The wait for outbound **capacity**, before the release check; the
    /// permit's expiry cancels it earlier, and the enqueue itself never waits (D2
    /// item 3a step 6; §17.7 item 2). 2 s.
    pub signing_enqueue_timeout: Duration,
    /// ⟨M03⟩ `KeyVault::sign` on the blocking pool; an overrun expires the permit (D2
    /// item 3a step 5). 1 s.
    pub signing_budget: Duration,
    /// ⟨M03⟩ The holder bound in the permit's expiry: a 2 s fresh read + the 1 s
    /// signature + 2 s of capacity wait (§17.4 item 6). 5 s.
    pub signing_holder_max: Duration,
    /// ⟨M03⟩ `H` in the narrowing's derived bound: the longest any holder keeps a
    /// gate, max(`signing_holder_max`, `delegation_gate_hold_max`,
    /// `connection_registration_txn_max`) (Q27; D2 item 3a). 10 s.
    pub signing_gate_max_wait: Duration,
    /// ⟨M03⟩ A delegation holds the gates of the parent and every ancestor shared
    /// until the child's first install; an overrun aborts fail-closed (Q26). 10 s.
    pub delegation_gate_hold_max: Duration,
    /// ⟨M03⟩ The narrowing commit **target**, not a ceiling (§17.13 item 1): tested
    /// at the budgets below, within `H + R ≈ 14.1 s` with no earlier overlapping
    /// narrowing and `H + 2R ≈ 18.2 s` with one. Never aborts; past it the narrowing
    /// reports `narrowing_over_target` with its derived bound. 20 s.
    pub narrowing_gate_wait_max: Duration,
    /// ⟨M03⟩ The Windows connection registration's transaction under the shared
    /// gate (U0b row 26; a holder the derived bound counts). 2 s.
    pub connection_registration_txn_max: Duration,
    /// ⟨M03⟩ `t_read`: one store read of a set or a subtree; the derived bound uses
    /// `(r + 3)·t_read` reads in all, round 1 `(r + 1)·t_read` (§17.13 item 1).
    /// 150 ms.
    pub narrowing_read_budget: Duration,
    /// ⟨M03⟩ `n_max`: the set size at which the 20 s target is tested; a larger set
    /// still proceeds and its bound is reported (§17.14 item 1). 256 grants.
    pub narrowing_set_budget: usize,
    /// ⟨M03⟩ `r_max`: the root count at which the target is tested; likewise
    /// reported, never refused. 16 roots.
    pub narrowing_root_budget: usize,
    /// ⟨M03⟩ `t_commit`: the tombstone transaction. 200 ms.
    pub narrowing_commit_budget: Duration,
    /// ⟨M03⟩ `ε`: the in-memory mark check, one gate step, or one key destruction.
    /// 1 ms.
    pub pending_check_budget: Duration,
    /// ⟨M03⟩ One issuer request, inside the 30 s adapter-call bound (ADR-0008 D3 item
    /// 6). 10 s.
    pub issuer_request_timeout: Duration,
    /// ⟨M03⟩ The issuer child's start (D3 item 7). 5 s.
    pub issuer_start_timeout: Duration,
    /// ⟨M03⟩ Issuer signatures per minute (D3 item 5). 600.
    pub issuer_signatures_per_minute: u32,
    /// ⟨M03⟩ Certificates per grant: the endpoint lists at most 64 identities (D3
    /// item 5). 64.
    pub max_certificates_per_grant: u32,
    /// ⟨M03⟩ One remote enrollment step, non-interactive (D5 §6.3). 120 s.
    pub enrollment_step_timeout: Duration,
    /// ⟨M03⟩ One remote enrollment step, interactive. 300 s.
    pub enrollment_step_timeout_interactive: Duration,
    /// ⟨M03⟩ Added to the step timeout for the script's remote not-after, on top of
    /// the inspect's remote reading (D5 §6.3; replaces revision 2's
    /// `enrollment_mutation_window`). 60 s ([`Self::enrollment_not_after`]).
    pub enrollment_not_after_allowance: Duration,
    /// ⟨M03⟩ Added to timeout + not-after allowance for the step's hard deadline on
    /// the continuous clock, persisted with the wall deadline and boot ID (D5 §6.3).
    /// 30 s ([`Self::enrollment_step_hard_deadline`]).
    pub enrollment_hard_deadline_margin: Duration,
    /// ⟨M03⟩ An older remote inspect reading is refreshed before a mutating step
    /// (D5 §6.3). 10 min.
    pub enrollment_inspect_max_age: Duration,
    /// ⟨M03⟩ Retries of a `busy` remote step, jittered (D5 §6.3). 3.
    pub enrollment_busy_retries: u32,
    /// ⟨M03⟩ Reconciles that try to terminate a lock holder before the record goes
    /// `held` (`lock_holder_unresolved`; D5 §6.3). 3.
    pub holder_termination_attempts: u32,
    /// ⟨M03⟩ `fence --terminate`: the grace after TERM (D5 §6.3). 5 s.
    pub holder_term_grace: Duration,
    /// ⟨M03⟩ `fence --terminate`: the grace after KILL. 5 s.
    pub holder_kill_grace: Duration,
    /// ⟨M03⟩ The remote registry's size: inspect's `od` hex is about 3.2 bytes per
    /// byte (≈ 410 KiB) ≤ `remote_stdout_max`; `remove` carries two hex payloads
    /// (≈ 4.2 × 128 KiB + 8 KiB of script ≈ 546 KiB) inside one 1 MiB control frame
    /// with its envelope. 128 KiB.
    pub registry_max_bytes: usize,
    /// ⟨M03⟩ A remote step's stdout: a `StepResult` must fit one 1 MiB control frame
    /// (`MAX_CONTROL_FRAME_BYTES`) with its JSON envelope and escaping (F25).
    /// 512 KiB.
    pub remote_stdout_max: usize,
    /// ⟨M03⟩ A remote step's stderr. 64 KiB.
    pub remote_stderr_max: usize,
    /// ⟨M03⟩ The stderr excerpt kept in a result. 4 KiB.
    pub remote_stderr_excerpt: usize,
    /// ⟨M03⟩ A verification certificate's validity (D5 §6.5). 300 s.
    pub verification_max_validity: Duration,
    /// ⟨M03⟩ Verification attempts per operation (D5 §6.5;
    /// `heimdall_domain::verification::MAX_ATTEMPTS_PER_OPERATION`). 3.
    pub verification_attempts: u32,
    /// ⟨M03⟩ The `-v` stderr parsed per attempt (D5 §6.5). 64 KiB.
    pub verification_trace_max: usize,
    /// ⟨M03⟩ An enrollment approval's validity, measured on safe time. 24 h.
    pub enrollment_approval_validity: Duration,
    /// ⟨M03⟩ Enrollment evidence freshness: 90 days at most (Q11 as amended).
    pub enrollment_evidence_freshness: Duration,
    /// ⟨M03⟩ The supervisor re-verifies before the window lapses (F27). 80 days.
    pub reverify_after: Duration,
    /// ⟨M03⟩ Re-verification after a client or CA change (§17.4 item 11). 10 min.
    pub reverify_prompt_delay: Duration,
    /// ⟨M03⟩ `destination_clock_skew`: a destination lagging by at least this
    /// (D5 §6.5). 60 s.
    pub verification_skew_lag: Duration,
    /// ⟨M03⟩ `destination_clock_skew`: a destination leading by at least this.
    /// 300 s.
    pub verification_skew_lead: Duration,
    /// ⟨M03⟩ Residual drift, parts per million of the measurement's age (§17.1 item
    /// 10; `heimdall_domain::revocation::RESIDUAL_DRIFT_PPM`). 100 ppm.
    pub residual_drift_ppm: u64,
    /// ⟨M03⟩ An owned master's close grace (D8). 5 s.
    pub owned_master_close_grace: Duration,
    /// ⟨M03⟩ An owned dedicated connection's close grace (D8). 5 s.
    pub dedicated_close_grace: Duration,
    /// ⟨M03⟩ Lock events within this window coalesce (D9). 1 s.
    pub lock_event_coalesce: Duration,
}

impl Limits {
    /// ⟨M03⟩ `enrollment_not_after_allowance` past the step timeout: the script's
    /// remote not-after offset (m03-plan §5 item 17: timeout + 60 s).
    #[must_use]
    pub fn enrollment_not_after(&self, interactive: bool) -> Duration {
        self.step_timeout(interactive)
            .saturating_add(self.enrollment_not_after_allowance)
    }

    /// ⟨M03⟩ The step's hard deadline on the continuous clock (m03-plan §5 item 17:
    /// timeout + 60 s + 30 s).
    #[must_use]
    pub fn enrollment_step_hard_deadline(&self, interactive: bool) -> Duration {
        self.enrollment_not_after(interactive)
            .saturating_add(self.enrollment_hard_deadline_margin)
    }

    fn step_timeout(&self, interactive: bool) -> Duration {
        if interactive {
            self.enrollment_step_timeout_interactive
        } else {
            self.enrollment_step_timeout
        }
    }
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
            adapter_call_timeout: crate::ports::DEFAULT_ADAPTER_CALL_TIMEOUT,
            declaration_validity: crate::catalog::DECLARATION_VALIDITY,
            signature_authorization_timeout: Duration::from_secs(2),
            signing_gate_wait: Duration::from_secs(1),
            signing_enqueue_timeout: Duration::from_secs(2),
            signing_budget: Duration::from_secs(1),
            signing_holder_max: Duration::from_secs(5),
            signing_gate_max_wait: Duration::from_secs(10),
            delegation_gate_hold_max: Duration::from_secs(10),
            narrowing_gate_wait_max: Duration::from_secs(20),
            connection_registration_txn_max: Duration::from_secs(2),
            narrowing_read_budget: Duration::from_millis(150),
            narrowing_set_budget: 256,
            narrowing_root_budget: 16,
            narrowing_commit_budget: Duration::from_millis(200),
            pending_check_budget: Duration::from_millis(1),
            issuer_request_timeout: Duration::from_secs(10),
            issuer_start_timeout: Duration::from_secs(5),
            issuer_signatures_per_minute: 600,
            max_certificates_per_grant: 64,
            enrollment_step_timeout: Duration::from_secs(120),
            enrollment_step_timeout_interactive: Duration::from_secs(300),
            enrollment_not_after_allowance: Duration::from_secs(60),
            enrollment_hard_deadline_margin: Duration::from_secs(30),
            enrollment_inspect_max_age: Duration::from_secs(10 * 60),
            enrollment_busy_retries: 3,
            holder_termination_attempts: 3,
            holder_term_grace: Duration::from_secs(5),
            holder_kill_grace: Duration::from_secs(5),
            registry_max_bytes: 128 * 1024,
            remote_stdout_max: 512 * 1024,
            remote_stderr_max: 64 * 1024,
            remote_stderr_excerpt: 4 * 1024,
            verification_max_validity: Duration::from_secs(300),
            verification_attempts: heimdall_domain::verification::MAX_ATTEMPTS_PER_OPERATION,
            verification_trace_max: 64 * 1024,
            enrollment_approval_validity: Duration::from_secs(24 * 60 * 60),
            enrollment_evidence_freshness: Duration::from_secs(90 * 24 * 60 * 60),
            reverify_after: Duration::from_secs(80 * 24 * 60 * 60),
            reverify_prompt_delay: Duration::from_secs(10 * 60),
            verification_skew_lag: Duration::from_secs(60),
            verification_skew_lead: Duration::from_secs(300),
            residual_drift_ppm: heimdall_domain::revocation::RESIDUAL_DRIFT_PPM,
            owned_master_close_grace: Duration::from_secs(5),
            dedicated_close_grace: Duration::from_secs(5),
            lock_event_coalesce: Duration::from_secs(1),
        }
    }
}

/// ⟨M02⟩ The answer of an adapter call whose bound elapsed (U0b row 24). Fixed,
/// nonsecret text.
pub const ADAPTER_CALL_TIMED_OUT: &str = "adapter call timed out";

/// ⟨M02⟩ U0b row 24 (M2-T06; ADR-0006 §13.20 item 3; ADR-0007 §7 "Every call is
/// bounded"): await one `CredentialAdapter` call for at most `limit`.
///
/// It wraps **the adapter future alone**: callers acquire an adapter slot first
/// and call this inside the slot, so neither the slot wait nor a caller's bounded
/// wait is ever counted. When the bound elapses the future is **dropped** (the
/// adapter's drop contract, `crate::ports::CredentialAdapter`) and the call answers
/// `AdapterError::OutcomeUnknown(`[`ADAPTER_CALL_TIMED_OUT`]`)`. Each call site then
/// runs its existing arm for that answer, unchanged; nothing here decides cleanup
/// ownership.
///
/// ⟨M02⟩ ADR-0007 §12.23 item 2 (U02): an answer that arrives after the bound is
/// not accepted either. A future that did not yield (synchronous work the timer
/// could not interrupt) and returned past the deadline answers `OutcomeUnknown`
/// exactly as a dropped one does, so the bound keeps its meaning whatever the call
/// did. Every store and file read an adapter needs is made before the bound
/// ([`crate::ports::CredentialAdapter::read_sources`]), so a conforming adapter
/// answers within it.
///
/// # Errors
/// The adapter's own error, or `OutcomeUnknown` when the bound elapsed.
pub async fn bounded_adapter_call<T, F>(limit: Duration, call: F) -> Result<T, AdapterError>
where
    F: std::future::Future<Output = Result<T, AdapterError>>,
{
    let deadline = tokio::time::Instant::now() + limit;
    match tokio::time::timeout_at(deadline, call).await {
        Ok(_) if tokio::time::Instant::now() > deadline => Err(AdapterError::OutcomeUnknown(
            ADAPTER_CALL_TIMED_OUT.to_owned(),
        )),
        Ok(answer) => answer,
        Err(_) => Err(AdapterError::OutcomeUnknown(
            ADAPTER_CALL_TIMED_OUT.to_owned(),
        )),
    }
}

/// ⟨M02⟩ ADR-0007 §12.23 item 2 (U02): `adapter`'s
/// [`CredentialAdapter::read_sources`] for `pairs`, on the blocking pool and awaited
/// (never detached, never under the adapter bound), before the bounded
/// `prepare_from` of the same step. A read that panicked claims nothing (an empty
/// snapshot, which fails closed).
async fn read_prepare_sources(
    adapter: &Arc<dyn CredentialAdapter>,
    pairs: &[PreparePair],
) -> IntegrationSnapshot {
    let adapter = Arc::clone(adapter);
    let pairs = pairs.to_vec();
    tokio::task::spawn_blocking(move || adapter.read_sources(&pairs))
        .await
        .unwrap_or_default()
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
    /// ⟨M02⟩ U5 (m02-plan U5; ADR-0007 §12.14 item 8): the managed-projection
    /// writer the setup driver uses. `None` keeps every `Request::Setup` at
    /// `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable` (m02-plan §5 item 4).
    pub projection: Option<Arc<dyn crate::ports::ProjectionWriter>>,
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
    /// ⟨r2.14⟩ ADR-0006 §13.17 item 1: the supervisor's per-obligation cap of
    /// revocation rounds, which decides whether a covering obligation is still live
    /// ([`Operations::set_revocation_cap`]; also every
    /// [`Operations::retry_remote_revocation`] call). ⟨r2.15⟩ ADR-0006 §13.18 item 3:
    /// [`NO_CONFIGURED_CAP`] until the supervisor sets it (restart recovery runs
    /// first), so recovery judges each record by its own stored cap alone, never by
    /// a default; a record is always judged by
    /// [`PendingRemoteRevocation::round_cap`] of this value.
    revocation_cap: AtomicU32,
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: the operations whose credential preparation
    /// this process is running (from before its `Attempted` receipt is recorded until
    /// `prepare` returns). A cleanup intent written while its attempt may be in flight
    /// is left to that preparation's return path while it runs.
    preparing: Mutex<BTreeSet<OperationId>>,
    /// ⟨M02⟩ U0b row 23, phase 2: how many times admission called
    /// `Txn::insert_setup_operation` (whatever it answered); a test hook
    /// ([`Operations::setup_insert_calls`]).
    setup_inserts: Arc<AtomicUsize>,
    /// ⟨M03⟩ U0b row 24 (wave-0 verify E6d): the per-grant signing gates and pending
    /// marks, shared with the signer through [`Operations::signing_gates`].
    signing_gates: crate::managed::SigningGates,
    /// ⟨M03⟩ U0b rows 5, 20, 25 (G): the narrowing hook, running narrowings, reports,
    /// the session-lock source and the authorization time seam.
    narrowing: narrowing::NarrowingState,
    /// ⟨M03⟩ U0b row 4 (O): the verification entries this runtime instance reserved.
    managed_ops: managed_state_m03::ManagedOpsState,
    /// ⟨M03; ADR-0008 §17.27 item 2⟩ The uninstall fence (`uninstall_fence_m03`).
    uninstall_fence: Arc<uninstall_fence_m03::UninstallFence>,
}

/// ⟨r2.16⟩ ADR-0006 §13.19 item 2: marks one operation's preparation as running in
/// this process while alive ([`Inner::preparing`]).
struct Preparing<'a> {
    set: &'a Mutex<BTreeSet<OperationId>>,
    operation: OperationId,
}

impl Drop for Preparing<'_> {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.operation);
    }
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
        local: None,
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
    // ⟨M03⟩ U0b row 11 (O): the strictest lock behaviour and connection policy of every
    // applicable policy (fail closed).
    heimdall_domain::policy::merge_lock_and_connection(&mut merged, policies);
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
    /// ⟨M03⟩ U0b row 20 (G; reading E6b): the signing gates, so [`end_in`] defers a
    /// withdrawal whose cascade has a gate to the narrowing protocol.
    gates: crate::managed::SigningGates,
    /// ⟨M03⟩ Inside a narrowing's commit: the set whose gates it holds (empty
    /// otherwise). Only a gated member outside it defers a withdrawal.
    narrowing_set: BTreeSet<GrantId>,
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

/// ⟨M02⟩ ADR-0007 §12.25 item 4 (T04): one live holder per launch binding. In the
/// caller's transaction, with `binding` active: when its holder row names another
/// process, or names one and this launch has none, returns `false` and writes
/// nothing (the existing holder is kept); otherwise registers `holder` (when given)
/// and returns `true`. A holder row counts as live until the holder pass releases
/// the binding: this path observes no liveness, and unknown liveness never counts as
/// an exit (ADR-0007 §8). The check and the registration share the transaction, so of
/// two overlapping launches of one binding at most one is admitted.
fn claim_launch_holder(
    tx: &mut Txn<'_>,
    binding: &BindingId,
    holder: Option<&heimdall_domain::holder::ProcessHolder>,
) -> heimdall_store::Result<bool> {
    match (tx.binding_holder(binding)?, holder) {
        (Some(current), Some(this)) => Ok(current == *this),
        (Some(_), None) => Ok(false),
        (None, Some(this)) => tx.set_binding_holder(binding, this).map(|()| true),
        (None, None) => Ok(true),
    }
}

/// ⟨M02⟩ ADR-0007 §12.25 item 4: the refusal of a launch whose binding another live
/// holder holds: `REQUEST_CONFLICT`, reason `binding_in_use`, `next:
/// new_request_id`, effect `none`, the binding as the resource.
fn binding_in_use(binding: &BindingId) -> OpError {
    OpError::new(
        Code::RequestConflict,
        "another running launch holds this binding; nothing was launched (retry with a new request ID)",
    )
    .with_reason(heimdall_contract::envelope::reason::BINDING_IN_USE)
    .with_effect(EffectStatus::None)
    .with_resource("binding", Some(binding.to_string()))
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
        // ⟨M03⟩ U0b row 10 (O): filled in the creating transaction by
        // `lock_connection_m03::with_lock_and_connection`.
        lock_behavior: None,
        connection: None,
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
    // ⟨M03⟩ U0b row 12 (O): the degraded reason's domain rule decides; only a reason
    // whose rule is `Refuse` (`mechanism_unavailable`) refuses the use. `NoKey`
    // (`credential_reissue_pending`) is the signer's refusal, never the re-issue's.
    Ok(mechanism_unavailable(tx, adapters, &grant.id)?
        || (grant.state == GrantState::Degraded
            && tx
                .grant_degradation(&grant.id)?
                .is_some_and(degraded_refuses_use)))
}

/// ⟨M03⟩ U0b row 12 (ADR-0008 D2 item 3): whether a grant `degraded` for `reason`
/// is refused every use: `DegradedReason::sign_rule` is `Refuse`. `issuer_unavailable`
/// and `pair_unenrolled` permit use (and signing with an installed key);
/// `credential_reissue_pending` has no key, which only the signer refuses.
#[must_use]
pub fn degraded_refuses_use(reason: DegradedReason) -> bool {
    reason.sign_rule() == heimdall_domain::grant::DegradedSignRule::Refuse
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
    revalidate_chain_verdict_with(tx, environment, adapters, grant, now, true)
}

/// [`revalidate_chain_verdict`]; with `record` false (⟨M03⟩ U3: the issuer's
/// read-only check) the new validated generation is **not** recorded, so the
/// verdict is computed without any write.
fn revalidate_chain_verdict_with(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    now: Timestamp,
    record: bool,
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
    if record {
        for id in &revalidated {
            tx.record_grant_validation(id, current)?;
        }
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
/// `released` (release is never revoke). Returns the owner operation when the
/// grant's prepared credential needs the usual cleanup (the owner's receipts show
/// a possible effect; ⟨r2.14⟩ they also key that effect, ADR-0006 §13.17).
fn end_orphaned_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    grant: &GrantId,
    me: &OperationId,
) -> heimdall_store::Result<Option<OperationId>> {
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
    Ok(effect.then_some(owner))
}

/// ⟨M02⟩ U0b row 1, phase 2 (§5 item 17): whether an `ApplyProjection` or
/// `DeclareInteraction` record describes `op`'s stored local intent exactly.
///
/// * `ApplyProjection` needs a setup operation whose intent is `LocalIntent::Setup`
///   with an equal `plan_digest` and no approval yet;
/// * `DeclareInteraction` needs a catalog operation whose intent is
///   `LocalIntent::Catalog` for a `DeclareInteraction` action on the same identity and
///   interaction, with no approval yet.
///
/// Any other combination (a kind/intent mismatch, a differing digest or identity, an
/// intent that also carries a resolved intent, an approval already set) does not
/// fit, which `decide` answers `DECISION_STALE` with nothing applied.
fn local_decision_fits(
    kind: &DecisionKind,
    op: &OperationRecord,
    intent: Option<&RecoveryIntent>,
) -> bool {
    let Some(intent) = intent.filter(|i| i.resolved.is_none()) else {
        return false;
    };
    match (kind, intent.local.as_ref()) {
        (DecisionKind::ApplyProjection { plan_digest, .. }, Some(LocalIntent::Setup(setup))) => {
            op.kind.is_setup() && setup.plan_digest == *plan_digest && setup.approval.is_none()
        }
        (
            DecisionKind::DeclareInteraction {
                identity,
                interaction,
                ..
            },
            Some(LocalIntent::Catalog(catalog)),
        ) => {
            op.kind == OperationKind::Catalog
                && catalog.approval.is_none()
                && catalog.action
                    == CatalogAction::DeclareInteraction {
                        identity: identity.clone(),
                        interaction: *interaction,
                    }
        }
        _ => false,
    }
}

/// The result of a cancellation's transaction: the operation as it now stands and
/// the cleanup intent to process after the commit, or the refusal.
type Cancelled = Result<(OperationRecord, Option<CleanupIntent>), OpError>;

/// ⟨M02⟩ ADR-0007 §12.14 item 3 (E1), phase 2: cancel an open setup or catalog
/// operation (called inside `cancel`'s transaction, after the quiescent check).
///
/// ADR-0007 §5.4 honours a cancellation only **before the first commit point**.
/// The reading applied here is the fail-closed one: a cancellation is honoured only
/// while the operation's driver has **started nothing** (no receipt with an effect
/// other than `not_attempted`, and no local receipt), so no file can have been
/// written and nothing needs settling. It then settles `cancelled` with effect
/// `none` and `may_have_external_effect: false`, withdraws any pending
/// `ApplyProjection` or `DeclareInteraction` record naming it, and releases its key
/// for retention, like any cancellation. A driver that takes the next step
/// re-reads the state in its own transaction and finds the operation cancelled.
///
/// Once the driver has started, the commit point may have passed (§5.4: "after it,
/// the driver finishes or restores"): the answer is `OUTCOME_UNKNOWN` (effect
/// `unknown`) with `next: reconcile` naming the operation, and nothing is written.
fn cancel_local_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    mut op: OperationRecord,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<Cancelled> {
    let receipts = tx.stage_receipts(&op.id)?;
    let started = receipts
        .iter()
        .any(|r| r.local.is_some() || r.effect != EffectReceipt::NotAttempted);
    if started {
        return Ok(Err(OpError::new(
            Code::OutcomeUnknown,
            "the operation's driver has started and may be past its first commit point; it finishes or restores, so reconcile it",
        )
        .with_resource("operation", Some(op.id.to_string()))
        .with_operation(op.id.clone())));
    }
    for d in tx.pending_decisions()? {
        let names_op = matches!(
            &d.kind,
            DecisionKind::ApplyProjection { operation, .. }
                | DecisionKind::DeclareInteraction { operation, .. }
                if *operation == op.id
        );
        if names_op {
            let withdrawn = tx.withdraw_decision(&d.id)?;
            emit.decision(tx, &withdrawn, Some(&op.id))?;
        }
    }
    op_to(&mut op, OperationEvent::Cancel, now)?;
    op.cancellation = Some(CancellationRecord {
        requested_at: now,
        may_have_external_effect: false,
    });
    let err = OpError::new(Code::OperationCancelled, "the operation was cancelled")
        .with_effect(EffectStatus::None)
        .with_operation(op.id.clone());
    op.code = Some(Code::OperationCancelled);
    op.effect_status = err.effect_status;
    op.result = Some(serde_json::json!({ "error": err.detail() }));
    tx.update_operation(&op)?;
    tx.settle_idempotency(&op.key, retention_expiry(now, retention))?;
    emit.op(tx, &op)?;
    Ok(Ok((op, None)))
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
    /// ⟨M03⟩ U0b row 20 (G; reading E6b): withdrawals detected here whose cascade has
    /// a signing gate, with the detection time. Nothing was written for them: the
    /// caller's [`Operations::complete_withdrawals`] takes the gates and re-runs
    /// [`end_in`] under them (the narrowing protocol).
    gated: Vec<(GrantId, Timestamp)>,
    /// ⟨M03 wave 4, round 3; ADR-0008 §17.22 item 4 (W4-R01)⟩ Grants this
    /// transaction moved to `expired` (an expiry found at use or by the scheduler's
    /// re-validation): the caller's [`Operations::complete_withdrawals`] runs their
    /// managed cleanup after the commit, outside every gate (K_env destroyed, the
    /// binding endpoints and files removed, the instances `destroyed`).
    expired: Vec<GrantId>,
}

impl Ended {
    fn is_empty(&self) -> bool {
        self.withdrawn.is_empty() && self.gated.is_empty() && self.expired.is_empty()
    }

    fn extend(&mut self, other: Self) {
        self.withdrawn.extend(other.withdrawn);
        self.gated.extend(other.gated);
        self.expired.extend(other.expired);
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
                    ended.expired.push(g.id.clone());
                }
            }
            Some(GrantEnd::Withdrawn) => {
                let mut all = vec![g.id.clone()];
                all.extend(tx.grant_descendants(&g.id)?);
                // ⟨M03⟩ U0b row 20 (G; reading E6b): detected here, committed only under
                // the gates. A gated cascade is deferred to the narrowing protocol.
                if all
                    .iter()
                    .any(|m| emit.gates.contains(m) && !emit.narrowing_set.contains(m))
                {
                    ended.gated.push((g.id.clone(), safe.wall()));
                    continue;
                }
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
        // M03 wave 0 (A1): fail closed until U0b
        remote_effects: Vec::new(),
        owned_connections: Vec::new(),
        notes: Vec::new(),
        requested_at: None,
        committed_at: None,
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
    /// ⟨r2.16⟩ The claim's identity, the record's `claim_seq` it wrote (ADR-0006
    /// §13.19 item 1); `None` when this round claimed no attempt (no call owed to an
    /// obligation, or nothing to claim).
    claim: Option<u64>,
}

/// ⟨r2.9⟩ What a round's calls answered: `(grant, adapter, confirmed)` per call
/// (`confirmed`: the adapter answered with nothing pending remotely; an error or a
/// pending remote effect is not a confirmation), and the latest credential expiry
/// the adapters reported.
#[derive(Debug, Clone, Default)]
struct RoundAnswers {
    answers: Vec<(GrantId, AdapterIdentity, bool)>,
    adapter_expiry: Option<Timestamp>,
    /// ⟨M03⟩ wave 4 (U10-C; D7 item 2 step 5): the managed adapter's per-pair rows,
    /// carried from its `RevokeOutcome` into the revoke result (one row per
    /// destination and account: the latest `valid_before` wins).
    remote_effects: Vec<heimdall_contract::managed::RemoteEffectReport>,
}

impl RoundAnswers {
    /// ⟨M03⟩ wave 4 (U10-C): merge `rows` into [`RoundAnswers::remote_effects`].
    fn merge_remote_effects(&mut self, rows: Vec<heimdall_contract::managed::RemoteEffectReport>) {
        for r in rows {
            match self
                .remote_effects
                .iter_mut()
                .find(|x| x.destination == r.destination && x.account == r.account)
            {
                Some(x) if r.latest_valid_before > x.latest_valid_before => *x = r,
                Some(_) => {}
                None => self.remote_effects.push(r),
            }
        }
    }
}

/// ⟨r2.10⟩ What `inspect grants` shows of one grant's pending remote part: its own
/// obligations' highest attempt count (ADR-0006 §13.13 item 3), the record's last
/// round, whether its retries stopped (the record, or every obligation of the
/// grant at its cap) and why its obligations are still pending.
///
/// ⟨r2.12⟩ ADR-0006 §13.15 item 2 (review round 5 U01): a grant can be covered by
/// several records (a delegated child is in its own root's record and in an
/// ancestor's); its view combines all of them ([`RemoteView::combine`]).
struct RemoteView {
    attempts: u32,
    last_attempt_at: Timestamp,
    stopped: bool,
    /// Every reason present, each once, in first-seen order.
    reasons: Vec<RemotePendingReason>,
}

impl RemoteView {
    /// The view of `grant` from the one record `r` that covers it.
    fn of(r: &PendingRemoteRevocation, grant: &GrantId) -> Self {
        let own: Vec<&RemoteObligation> =
            r.obligations.iter().filter(|o| &o.grant == grant).collect();
        let mut reasons = Vec::new();
        for reason in own.iter().filter_map(|o| o.reason) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        Self {
            attempts: own
                .iter()
                .map(|o| r.obligation_attempts(o))
                .max()
                .unwrap_or(r.attempts),
            last_attempt_at: r.last_attempt_at,
            stopped: r.stopped || (!own.is_empty() && own.iter().all(|o| o.stopped)),
            reasons,
        }
    }

    /// ⟨r2.12⟩ §13.15 item 2: two records' views of one grant, combined: stopped
    /// only if every remaining obligation of both is, every reason of either, the
    /// highest attempt count and the latest round.
    fn combine(mut self, other: Self) -> Self {
        self.attempts = self.attempts.max(other.attempts);
        self.last_attempt_at = self.last_attempt_at.max(other.last_attempt_at);
        self.stopped = self.stopped && other.stopped;
        for reason in other.reasons {
            if !self.reasons.contains(&reason) {
                self.reasons.push(reason);
            }
        }
        self
    }
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

/// ⟨r2.11⟩ ADR-0006 §13.14 item 2: whether `grant`'s remote state is unknown
/// rather than known empty: an `Attempted`, `Confirmed` (applied) or `Uncertain`
/// effect receipt is on record for it, or its origin records the preparing adapter
/// (written with the first `Attempted` receipt, so it survives the receipts'
/// retention).
fn had_effect(tx: &mut Txn<'_>, grant: &GrantId) -> heimdall_store::Result<bool> {
    if tx.grant_origin(grant)?.is_some_and(|o| o.adapter.is_some()) {
        return Ok(true);
    }
    tx.grant_has_effect_receipt(grant)
}

/// ⟨r2.10⟩ A fresh obligation of `grant` to `adapter` (no attempt counted yet).
fn obligation(grant: &GrantId, adapter: AdapterIdentity) -> RemoteObligation {
    RemoteObligation {
        grant: grant.clone(),
        adapter,
        reason: None,
        attempts: Some(0),
        stopped: false,
        effect_round: None,
        effect_seq: None,
        // M03 wave 0 (A1): fail closed until U0b
        kind: Default::default(),
    }
}

/// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the configured revocation cap before any is
/// configured (no supervisor yet): a record is then judged by its own cap alone
/// ([`PendingRemoteRevocation::round_cap`]).
const NO_CONFIGURED_CAP: u32 = u32::MAX;

/// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the cap in force for a record created or re-armed
/// now: the configured cap (`configured`), or with none configured yet (restart
/// recovery), the record's own `stored` cap, and for a new record the default
/// ([`DEFAULT_ROUND_CAP`], the cap production configures).
fn cap_in_force(configured: u32, stored: Option<u32>) -> u32 {
    if configured == NO_CONFIGURED_CAP {
        stored.unwrap_or(DEFAULT_ROUND_CAP)
    } else {
        configured
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
///
/// ⟨r2.16⟩ ADR-0006 §13.19 item 1: a record written before claim sequences existed
/// is read with a derived starting sequence, and an effect it recorded by round
/// migrates conservatively ([`PendingRemoteRevocation::migrate_claim_seq`]).
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
    r.migrate_claim_seq();
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
        // ⟨M03⟩ U0b row 6 (ADR-0008 D7 item 3): a `bounded_by_expiry` obligation is
        // settled by expiry alone: no adapter call, no attempt counted, no reason.
        if !o.kind.is_needs_remote_action() {
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
/// it and the supervisor retries it (no untracked one-off call). ⟨r2.11⟩ ADR-0006
/// §13.14 item 2: such a grant whose responsible adapter is not configured is an
/// obligation too when it has an effect receipt ([`had_effect`]): its remote state
/// is unknown, so it waits with reason `adapter_unavailable` (no call, no attempt
/// consumed) until that adapter is configured again; one with no effect receipt
/// owes nothing. When any call is
/// owed the round is claimed: `attempts + 1` and `claimed_at` (§13.12 item 1),
/// and each called obligation counts it (§13.13 item 3); a round with no call
/// consumes no attempt. `rearm` (an authorized explicit revoke, ADR-0006 §13.11
/// item 4) restarts every count, lifts every stop and supersedes an unfinished
/// claim first. The record is written when any obligation exists.
///
/// ⟨r2.15⟩ ADR-0006 §13.18 item 3: a record created here, or re-armed by `rearm`,
/// stores the cap in force ([`cap_in_force`] of `configured_cap`, the configured
/// revocation cap).
///
/// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the claim is identified by a new
/// [`PendingRemoteRevocation::claim_seq`] from the store's counter
/// ([`Txn::next_remote_claim_seq`]), never assigned before, also not to a removed
/// record of the same root. A re-arm restarts the counts and
/// supersedes an unfinished claim, but never resets the sequence or a recorded
/// effect's ([`RemoteObligation::effect_seq`]): every claim from here on has a
/// greater sequence than any effect recorded so far, and a superseded claim's
/// completion clears nothing.
#[allow(clippy::too_many_arguments)]
fn claim_first_round_in(
    tx: &mut Txn<'_>,
    root: &GrantId,
    grants: &[GrantId],
    configured: &[AdapterIdentity],
    now: Timestamp,
    rearm: bool,
    configured_cap: u32,
) -> heimdall_store::Result<Round> {
    let mut record = match load_remote_record(tx, root)? {
        Some(r) => r,
        None => PendingRemoteRevocation {
            root: root.clone(),
            grants: Vec::new(),
            attempts: 0,
            last_attempt_at: now,
            stopped: false,
            obligations: Vec::new(),
            claimed_at: None,
            rearmed_effects: Vec::new(),
            cap: Some(cap_in_force(configured_cap, None)),
            claim_seq: Some(0),
        },
    };
    if rearm {
        record.attempts = 0;
        record.stopped = false;
        record.claimed_at = None;
        record.cap = Some(cap_in_force(configured_cap, record.cap));
        for o in &mut record.obligations {
            o.attempts = Some(0);
            o.stopped = false;
        }
    }
    for g in grants {
        let revoking = tx
            .grant(g)?
            .is_some_and(|s| s.state == GrantState::Revoking);
        let mut effect: Option<bool> = None;
        for adapter in responsible_adapters(tx, g)? {
            let owed = obligation(g, adapter);
            let tracked = revoking
                || configured.iter().any(|a| owed.served_by(a))
                || match effect {
                    Some(e) => e,
                    None => *effect.insert(had_effect(tx, g)?),
                };
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
        record.claim_seq = Some(tx.next_remote_claim_seq(record.current_claim_seq())?);
        claim = record.claim_seq;
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
///
/// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the cap applied is the record's
/// ([`PendingRemoteRevocation::round_cap`] of `max_attempts`, the configured cap).
///
/// ⟨r2.16⟩ ADR-0006 §13.19 item 1: the claim is identified by a new
/// [`PendingRemoteRevocation::claim_seq`] ([`Txn::next_remote_claim_seq`]).
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
    let max_attempts = r.round_cap(max_attempts);
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
    r.claim_seq = Some(tx.next_remote_claim_seq(r.current_claim_seq())?);
    tx.set_remote_revocation(&r)?;
    let grants = r.grants.clone();
    Ok(RetryClaim::Claimed(
        Round {
            calls,
            claim: r.claim_seq,
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
///
/// ⟨r2.15⟩ ADR-0006 §13.18 item 2 (amends §13.12 item 2): a confirmation means
/// "revoked as of the call". It clears an obligation with an effect recorded only
/// when this round is still the record's current claim and was claimed after that
/// effect; otherwise the obligation stays, and the next round makes the call. This holds for every path that completes a round:
/// the explicit revoke's and the withdrawal's first round, and the supervisor's
/// retries. Item 3: `max_attempts` is judged as the record's
/// [`PendingRemoteRevocation::round_cap`].
///
/// ⟨r2.16⟩ ADR-0006 §13.19 item 1 (amends the above): `claim` is the round's
/// [`PendingRemoteRevocation::claim_seq`]. The round is the record's current claim
/// only while the record still carries an uncompleted claim with that sequence (an
/// explicit revoke's re-arm, or any later claim, supersedes it). A current round's
/// confirmation clears an obligation unless the obligation's recorded effect
/// ([`RemoteObligation::effect_seq`]) is at or after its claim; a superseded round's
/// confirmations clear nothing ([`RemoteObligation::cleared_by_claim`]).
#[allow(clippy::too_many_arguments)]
fn complete_round_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    root: &GrantId,
    grants: &[GrantId],
    claim: Option<u64>,
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
        let current = claim.filter(|seq| r.claimed_at.is_some() && r.claim_seq == Some(*seq));
        // ⟨M03⟩ U0b row 6 (ADR-0008 D7 item 3): an adapter answer never clears a
        // `bounded_by_expiry` obligation; only expiry on safe time settles it.
        r.obligations.retain(|o| {
            !(o.kind.is_needs_remote_action() && confirmed(o) && o.cleared_by_claim(current))
        });
        if current.is_some() {
            r.claimed_at = None;
            if let Some(m) = max_attempts {
                let m = r.round_cap(m);
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

/// ⟨r2.14⟩ ADR-0006 §13.17: a credential effect that was applied, or may have been,
/// for a grant: the adapter its attempt asked and the attempt's key (its effect
/// token and whether a confirmation followed), taken from the stage receipts of
/// the operation that made the attempt. ⟨r2.15⟩ The key names no grant or adapter
/// here; the cleanup decision scopes it to both (ADR-0006 §13.18 item 4).
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedEffect {
    adapter: AdapterIdentity,
    key: RearmedEffect,
}

/// ⟨r2.14⟩ The latest effect attempt in `receipts` (its `Attempted` or `Uncertain`
/// receipt), confirmed when a `Confirmed` receipt follows it. `None` when no
/// attempt is on record (never attempted, or purged with a settled operation).
fn applied_effect(receipts: &[StageReceipt]) -> Option<AppliedEffect> {
    let (at, adapter, token) =
        receipts
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, r)| match &r.effect {
                EffectReceipt::Attempted {
                    adapter,
                    effect_token,
                }
                | EffectReceipt::Uncertain {
                    adapter,
                    effect_token,
                } => Some((i, adapter, effect_token)),
                _ => None,
            })?;
    let confirmed = receipts[at + 1..]
        .iter()
        .any(|r| matches!(r.effect, EffectReceipt::Confirmed { .. }));
    Some(AppliedEffect {
        adapter: adapter.clone(),
        key: RearmedEffect {
            grant: None,
            adapter: None,
            effect_token: token.clone(),
            confirmed,
        },
    })
}

/// ⟨r2.14⟩ Who makes the revocation call for an applied effect
/// ([`own_applied_effect_in`]). ⟨r2.16⟩ ADR-0006 §13.19 item 2: a call that is made
/// later ([`Self::Immediate`], [`Self::Bounded`]) is owed by a cleanup intent written
/// with the decision ([`settle_effect_in`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum EffectOwner {
    /// No pending remote record covers the grant: the cleanup makes its immediate
    /// best-effort call, as before (ADR-0006 §13.17 item 3).
    Immediate,
    /// A covering record holds a live obligation for (the grant, every applying
    /// adapter): its rounds make the call (item 1). ⟨r2.15⟩ The effect was recorded
    /// on it (§13.18 item 2).
    Live,
    /// A stopped or capped obligation for an applying adapter was re-armed, or one
    /// was added, in this transaction; the supervisor's rounds make the call
    /// (item 2).
    Rearmed,
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 4: for these applying adapters the effect already
    /// re-armed a covering record once (§13.17 item 4) and no covering obligation is
    /// live. The bound allows no second re-arm, but it never suppresses the call:
    /// the cleanup calls each of them now, best effort, and a pending answer is
    /// tracked as an obligation ([`track_bounded_answers_in`]). Any other applying
    /// adapter is owned as for [`Self::Live`] or [`Self::Rearmed`].
    Bounded(Vec<AdapterIdentity>),
}

/// ⟨r2.14⟩ ADR-0006 §13.17, inside the transaction of the cleanup decision for a
/// credential effect applied (or possibly applied) for `grant`.
///
/// * **Item 3.** When no pending remote record covers the grant (lists it in
///   `grants`), the answer is [`EffectOwner::Immediate`] and nothing is written.
/// * Otherwise the applying adapters are the effect's adapter (from its receipts)
///   or, with no attempt on record, the grant's responsible adapters
///   ([`responsible_adapters`]), and [`decide_applied_effect`] decides; the records
///   it changed are written here, in the decision's transaction, so the decision
///   is durable from this commit on.
///
/// `cap` is the configured revocation cap ([`NO_CONFIGURED_CAP`] before the
/// supervisor set one); each record is judged by its
/// [`PendingRemoteRevocation::round_cap`] of it (⟨r2.15⟩ §13.18 item 3).
fn own_applied_effect_in(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    effect: Option<&AppliedEffect>,
    cap: u32,
) -> heimdall_store::Result<EffectOwner> {
    let mut covering = covering_records(tx, grant)?;
    if covering.is_empty() {
        return Ok(EffectOwner::Immediate);
    }
    let applying = match effect {
        Some(e) => vec![e.adapter.clone()],
        None => responsible_adapters(tx, grant)?,
    };
    let (owner, changed) =
        decide_applied_effect(&mut covering, grant, &applying, effect.map(|e| &e.key), cap);
    for i in changed {
        tx.set_remote_revocation(&covering[i])?;
    }
    Ok(owner)
}

/// ⟨r2.14⟩ The pending remote records that cover `grant` (list it in `grants`),
/// with their obligations ([`load_remote_record`]).
fn covering_records(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> heimdall_store::Result<Vec<PendingRemoteRevocation>> {
    let mut covering: Vec<PendingRemoteRevocation> = Vec::new();
    for r in tx.remote_revocations()? {
        if r.grants.contains(grant)
            && let Some(loaded) = load_remote_record(tx, &r.root)?
        {
            covering.push(loaded);
        }
    }
    Ok(covering)
}

/// ⟨r2.15⟩ Whether `o` owes `grant`'s remote effect to `adapter`.
fn owes(o: &RemoteObligation, grant: &GrantId, adapter: &AdapterIdentity) -> bool {
    &o.grant == grant && o.served_by(adapter)
}

/// ⟨r2.15⟩ Whether `r` holds a live obligation of `grant` for `adapter`: neither it
/// nor the record stopped, and below the record's cap
/// ([`PendingRemoteRevocation::round_cap`] of the configured `cap`), so a round
/// will still call it.
fn owns_live(
    r: &PendingRemoteRevocation,
    grant: &GrantId,
    adapter: &AdapterIdentity,
    cap: u32,
) -> bool {
    let limit = r.round_cap(cap);
    !r.stopped
        && r.obligations
            .iter()
            .any(|o| owes(o, grant, adapter) && !o.stopped && r.obligation_attempts(o) < limit)
}

/// ⟨r2.15⟩ ADR-0006 §13.18 item 2, ⟨r2.16⟩ §13.19 item 1: record a credential
/// effect on obligation `o` of a record whose latest claim is `seq`
/// ([`PendingRemoteRevocation::current_claim_seq`]): the latest effect wins, so only a
/// current claim made after it clears the obligation.
fn record_effect(o: &mut RemoteObligation, seq: u64) -> bool {
    let at = o.effect_seq.map_or(seq, |e| e.max(seq));
    let changed = o.effect_seq != Some(at);
    o.effect_seq = Some(at);
    changed
}

/// ⟨r2.14⟩ ADR-0006 §13.17 item 2: give `adapter` a live obligation of `grant` in
/// `covering`: the first record with an obligation of this grant served by it has
/// that obligation re-armed (attempts `0`, `stopped` cleared); with none, one is
/// added to the first record. ⟨r2.15⟩ §13.18: the effect is recorded on it at the
/// record's current claim (item 2; ⟨r2.16⟩ §13.19 item 1: its sequence), and the
/// record stores the cap in force (item 3). The changed record is no longer
/// `stopped`. Returns its index.
fn rearm_or_add(
    covering: &mut [PendingRemoteRevocation],
    grant: &GrantId,
    adapter: &AdapterIdentity,
    cap: u32,
) -> usize {
    let i = covering
        .iter()
        .position(|r| r.obligations.iter().any(|o| owes(o, grant, adapter)))
        .unwrap_or(0);
    let r = &mut covering[i];
    let seq = r.current_claim_seq();
    let mut found = false;
    for o in r.obligations.iter_mut().filter(|o| owes(o, grant, adapter)) {
        o.attempts = Some(0);
        o.stopped = false;
        record_effect(o, seq);
        found = true;
    }
    if !found {
        let mut o = obligation(grant, adapter.clone());
        o.effect_seq = Some(seq);
        r.obligations.push(o);
    }
    r.stopped = false;
    r.cap = Some(cap_in_force(cap, r.cap));
    sync_obligation_grants(r);
    i
}

/// ⟨r2.14⟩⟨r2.15⟩ ADR-0006 §13.17 and §13.18: the cleanup decision for an effect
/// applied (or possibly applied) for `grant` by each of `applying`, over the
/// records that cover it (`covering`, not empty), changed in place. Returns who
/// makes the call and the indices of the records changed. It leaves no applied
/// effect with neither a live owning obligation nor a call made after it.
///
/// * **§13.18 item 2.** The effect is recorded on every covering obligation that
///   owes it (any applying adapter), as that record's latest claim now (⟨r2.16⟩ its
///   sequence, §13.19 item 1; [`record_effect`]): only a current claim made after it
///   clears the obligation.
/// * **§13.17 item 1.** When every applying adapter has a live obligation
///   ([`owns_live`]), the call is owned: [`EffectOwner::Live`].
/// * **§13.17 item 2.** Each applying adapter without one is re-armed or added
///   ([`rearm_or_add`]), and the effect's key is recorded in `rearmed_effects`.
/// * **§13.18 item 4.** The key is (grant, adapter, effect token, recorded state).
///   An adapter whose key a covering record already lists is not re-armed again;
///   it is returned in [`EffectOwner::Bounded`] for the immediate call. An effect
///   with an empty token, or no attempt on record (`effect` is `None`), cannot be
///   told apart from another one: it is never bounded and its key never recorded,
///   so it always re-arms.
fn decide_applied_effect(
    covering: &mut [PendingRemoteRevocation],
    grant: &GrantId,
    applying: &[AdapterIdentity],
    effect: Option<&RearmedEffect>,
    cap: u32,
) -> (EffectOwner, BTreeSet<usize>) {
    let mut changed: BTreeSet<usize> = BTreeSet::new();
    for (i, r) in covering.iter_mut().enumerate() {
        let seq = r.current_claim_seq();
        for o in r
            .obligations
            .iter_mut()
            .filter(|o| applying.iter().any(|a| owes(o, grant, a)))
        {
            if record_effect(o, seq) {
                changed.insert(i);
            }
        }
    }
    let unowned: Vec<&AdapterIdentity> = applying
        .iter()
        .filter(|a| !covering.iter().any(|r| owns_live(r, grant, a, cap)))
        .collect();
    if unowned.is_empty() {
        return (EffectOwner::Live, changed);
    }
    let known = effect.filter(|k| !k.effect_token.is_empty());
    let mut bounded: Vec<AdapterIdentity> = Vec::new();
    for a in unowned {
        let key = known.map(|k| RearmedEffect {
            grant: Some(grant.clone()),
            adapter: Some(a.clone()),
            effect_token: k.effect_token.clone(),
            confirmed: k.confirmed,
        });
        if let Some(key) = &key
            && covering.iter().any(|r| r.rearmed_effects.contains(key))
        {
            bounded.push(a.clone());
            continue;
        }
        let i = rearm_or_add(covering, grant, a, cap);
        if let Some(key) = key {
            covering[i].rearmed_effects.push(key);
        }
        changed.insert(i);
    }
    let owner = if bounded.is_empty() {
        EffectOwner::Rearmed
    } else {
        EffectOwner::Bounded(bounded)
    };
    (owner, changed)
}

/// ⟨r2.15⟩ ADR-0006 §13.18 item 4, after the immediate calls a bounded effect got
/// ([`EffectOwner::Bounded`]): each answer for `grant`, per applying adapter
/// (`Some(true)` confirmed, `Some(false)` pending or failed, `None` not called
/// because the adapter is not configured), tracked in the records that cover it.
///
/// * A confirmation changes nothing.
/// * A pending answer is tracked as an obligation (§13.13 item 2): a covering
///   obligation of this grant for that adapter is kept as it is (a stopped one stays
///   stopped: the bound allows no re-arm, and the call was made after the effect);
///   with none, one is added ([`rearm_or_add`]).
/// * No call: nothing was made after the effect, so the adapter's obligation is
///   re-armed or added ([`rearm_or_add`]), live with reason `adapter_unavailable`
///   from its next round, until that adapter is configured again (fail closed).
///
/// A grant no record covers any more is left as for a grant without a record
/// (§13.17 item 3).
fn track_bounded_answers_in(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    answers: &[(AdapterIdentity, Option<bool>)],
    cap: u32,
) -> heimdall_store::Result<()> {
    let mut covering = covering_records(tx, grant)?;
    if covering.is_empty() {
        return Ok(());
    }
    let mut changed: BTreeSet<usize> = BTreeSet::new();
    for (a, answer) in answers {
        let tracked = covering
            .iter()
            .any(|r| r.obligations.iter().any(|o| owes(o, grant, a)));
        match answer {
            Some(true) => {}
            Some(false) if tracked => {}
            Some(false) | None => {
                changed.insert(rearm_or_add(&mut covering, grant, a, cap));
            }
        }
    }
    for i in changed {
        tx.set_remote_revocation(&covering[i])?;
    }
    Ok(())
}

/// ⟨r2.16⟩ ADR-0006 §13.19 item 2: the cleanup decision for a credential effect
/// applied (or possibly applied) for `grant` by the attempt of `effect_of`, written
/// in the transaction that settles the operation with that effect (a late
/// `Confirmed` or `Uncertain` receipt, a recheck or commit refusal, a cancellation).
///
/// The decision is [`own_applied_effect_in`]'s, under the §13.17 and §13.18 rules: a
/// covering obligation that owns the call is registered or re-armed here. When the
/// call must instead be made later, after this commit (the immediate call for a grant
/// no record covers, or a bounded call), a **cleanup intent** is recorded here too,
/// and returned for the caller to process ([`Operations::process_cleanup_intent`]).
/// So is one while the attempt has no answer yet (its last receipt is `Attempted`):
/// its preparation may still be in flight, and an obligation that owns the call now
/// could be cleared by a call made before the effect lands. Otherwise an earlier
/// intent of (`grant`, `effect_of`) is removed: an obligation owns the call.
///
/// `cap` is the configured revocation cap ([`NO_CONFIGURED_CAP`] before the
/// supervisor set one).
fn settle_effect_in(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    effect_of: &OperationId,
    cap: u32,
    now: Timestamp,
) -> heimdall_store::Result<Option<CleanupIntent>> {
    let receipts = tx.stage_receipts(effect_of)?;
    let effect = applied_effect(&receipts);
    let in_flight = matches!(
        last_reconcile(&receipts),
        Some(EffectReceipt::Attempted { .. })
    );
    let owner = own_applied_effect_in(tx, grant, effect.as_ref(), cap)?;
    if !in_flight && matches!(owner, EffectOwner::Live | EffectOwner::Rearmed) {
        tx.clear_cleanup_intent(grant, effect_of)?;
        return Ok(None);
    }
    let (adapter, effect_token, confirmed) = match effect {
        Some(e) => (Some(e.adapter), e.key.effect_token, e.key.confirmed),
        None => (None, String::new(), false),
    };
    tx.record_cleanup_intent(&CleanupIntent {
        grant: grant.clone(),
        operation: effect_of.clone(),
        adapter,
        effect_token,
        confirmed,
        in_flight,
        version: 0,
        recorded_at: now,
    })
    .map(Some)
}

/// ⟨r2.16⟩ The effect a cleanup intent names, as the cleanup decision reads it.
fn intent_effect(intent: &CleanupIntent) -> Option<AppliedEffect> {
    intent.adapter.as_ref().map(|adapter| AppliedEffect {
        adapter: adapter.clone(),
        key: RearmedEffect {
            grant: None,
            adapter: None,
            effect_token: intent.effect_token.clone(),
            confirmed: intent.confirmed,
        },
    })
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
    /// ⟨M02⟩ U0b row 9: the adapter can meet `unattended`: its lock continuity is
    /// `Verified` and it needs no interaction. `Unknown` never meets a minimum.
    unattended: bool,
}

/// The first adapter that meets the caller's minimum capabilities and
/// destination-scope enforcement (never a silently weaker one).
///
/// ⟨M02⟩ U0b rows 7 and 9: when the catalog's pairs name a mechanism, only an
/// adapter of that mechanism is considered; `unattended` is met only by an adapter
/// that can meet it (never in M02).
///
/// ⟨M03 wave 4, round 3b (X-M); ADR-0008 §17.23 item 1⟩ The managed descriptor
/// advertises `verified_server_principals`, which a managed grant achieves only for a
/// pair resolved to `managed_certificate` (its applied preference and verified
/// enrollment; the per-pair evidence comparison then decides). For pairs resolved to no
/// mechanism (the M01 selection) its scope counts as `unknown`, as before, so no
/// M01/M02 resolution changes.
fn select_adapter<'a>(
    adapters: &'a [AdapterInfo],
    required: &RequiredCapabilities,
    mechanism: Option<&str>,
) -> Option<&'a AdapterInfo> {
    adapters.iter().find(|a| {
        let scope = if mechanism.is_none() && a.identity.mechanism == MANAGED_CERTIFICATE {
            DestinationScopeEnforcement::Unknown
        } else {
            a.scope_enforcement
        };
        mechanism.is_none_or(|m| a.identity.mechanism == m)
            && required.capabilities.is_subset(&a.capabilities)
            && required
                .destination_scope_at_least
                .is_none_or(|m| scope >= m)
            && (!required.unattended || a.unattended)
    })
}

/// ⟨M02⟩ U0b rows 7 and 8: the catalog's identity for each pair in `pairs`. A
/// managed destination whose account is the pair's names its identity; observed
/// destinations and pairs without a catalog destination name none. A named
/// identity that is not adopted is refused (fail closed).
fn catalog_pairs(
    tx: &mut Txn<'_>,
    pairs: &BTreeSet<AccessPair>,
) -> heimdall_store::Result<Result<Vec<PreparePair>, OpError>> {
    let mut out = Vec::new();
    for p in pairs {
        let Some(d) = tx.destination(&p.destination)? else {
            continue;
        };
        let DestinationDefinition::Managed {
            account, identity, ..
        } = &d.definition
        else {
            continue;
        };
        if *account != p.account {
            continue;
        }
        let Some(record) = tx.identity(identity)? else {
            return Ok(Err(OpError::new(
                Code::CapabilityUnavailable,
                "the catalog names an identity for a requested pair that is not adopted",
            )
            .with_resource("identity", Some(identity.to_string()))));
        };
        out.push(PreparePair {
            destination: p.destination.clone(),
            account: p.account.clone(),
            identity: record,
            alias: Some(d.alias.clone()),
        });
    }
    Ok(Ok(out))
}

/// ⟨M02⟩ The one mechanism the catalog's pairs name (`None` when they name none),
/// or `CAPABILITY_UNAVAILABLE`, reason `mixed_mechanisms` (P6; ADR-0007 §7 "One
/// mechanism per grant").
fn catalog_mechanism(pairs: &[PreparePair]) -> Result<Option<&'static str>, OpError> {
    let named: BTreeSet<&'static str> = pairs
        .iter()
        .map(|p| p.identity.source.mechanism())
        .collect();
    if named.len() > 1 {
        return Err(mixed_mechanisms());
    }
    Ok(named.into_iter().next())
}

fn mixed_mechanisms() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the requested pairs name identities of different credential mechanisms; split the profile",
    )
    .with_reason(heimdall_contract::envelope::reason::MIXED_MECHANISMS)
    .with_resource("profile", None)
}

/// ⟨M02⟩ The `resource.kind` of an existing-access provider result (m02-plan §5
/// item 15; ADR-0007 §7 "Results and codes").
const PROVIDER_RESOURCE: &str = "provider";

/// ⟨M02⟩ The provider an existing-access mechanism fronts (ADR-0007 §7): `native_agent`
/// and `onepassword`; `None` for any other adapter (the M01 mapping applies).
fn existing_access_provider(mechanism: &str) -> Option<ProviderKind> {
    match mechanism {
        heimdall_domain::catalog::MECHANISM_NATIVE_AGENT => Some(ProviderKind::NativeAgent),
        heimdall_domain::catalog::MECHANISM_ONEPASSWORD => Some(ProviderKind::OnePassword),
        _ => None,
    }
}

/// ⟨M02⟩ `next: interact` with the provider's interaction, never a `decision_ref`
/// (spec §5.5; ADR-0007 §7).
fn provider_interaction_next(
    code: Code,
    provider: ProviderKind,
    kind: InteractionKind,
) -> NextAction {
    NextAction {
        provider_interaction: Some(heimdall_contract::provider::ProviderInteractionRef {
            provider,
            kind,
        }),
        ..NextAction::for_code(code)
    }
}

/// ⟨M02⟩ ADR-0007 §12.15 item 7 (E-U6-4): the interaction and stable reason of an
/// existing-access `INTERACTION_REQUIRED`, from the runtime's fresh eligibility of
/// each pair, in the request's order. The first pair that is not eligible decides.
/// Every pair eligible: the adapter refused for an uncleared fallback identity
/// (`fallback_identity_interaction`). No pair: the provider's documented interaction
/// (1Password `provider_approval`, otherwise `unknown`).
///
/// ⟨M02⟩ ADR-0007 §12.26 item 4: for `fallback_identity_interaction`, also the refused
/// entries' provenance, as the CLI's pre-launch refusal names them: the refused
/// `IdentityFile` lines (which may lie inside `Host *`), each once, of the first
/// prepared pair whose selection the domain's fallback clearance rule does not clear
/// ([`refused_entries`]). Empty for every other reason.
fn interaction_refusal(
    provider: ProviderKind,
    pairs: &[PairEligibility],
    prepared: &[PreparePair],
    sources: &IntegrationSnapshot,
    now: Timestamp,
) -> (
    InteractionKind,
    &'static str,
    Vec<heimdall_contract::doctor::ConfigProvenance>,
) {
    use heimdall_contract::envelope::reason;
    let Some(first) = pairs.first() else {
        return if provider == ProviderKind::OnePassword {
            (
                InteractionKind::ProviderApproval,
                reason::PROVIDER_INTERACTION,
                Vec::new(),
            )
        } else {
            (
                InteractionKind::Unknown,
                reason::INTERACTION_UNKNOWN,
                Vec::new(),
            )
        };
    };
    match pairs.iter().find(|p| !p.noninteractive.eligible) {
        Some(p) => (
            p.interaction,
            match p.noninteractive.reason.as_deref() {
                Some(noninteractive_reason::PROVIDER_INTERACTION) => reason::PROVIDER_INTERACTION,
                Some(noninteractive_reason::FALLBACK_IDENTITY_INTERACTION) => {
                    reason::FALLBACK_IDENTITY_INTERACTION
                }
                // `interaction_unknown`, and any reason a newer domain adds: the
                // narrowing reading.
                _ => reason::INTERACTION_UNKNOWN,
            },
            Vec::new(),
        ),
        None => (
            first.interaction,
            reason::FALLBACK_IDENTITY_INTERACTION,
            refused_entries(prepared, sources, now),
        ),
    }
}

/// ⟨M02⟩ ADR-0007 §12.26 item 4: the provenance of the entries the adapter's fallback
/// clearance refused, recomputed from the snapshot the adapter evaluated (its static
/// observation, catalog identities and declaration rows) with the one domain rule
/// (`heimdall_domain::catalog::fallback_clearance`), as the adapter applies it: the
/// selection is the alias's observed report, read as `undetermined` when it claims
/// `exclusive` without the identity's own managed entry; the agent is the identity's
/// endpoint; an alternative's eligibility is the domain's over its declaration row, and
/// an identity outside the catalog is not eligible. The first pair that is not cleared
/// decides; each line is named once, in entry order. A pair with no observation names
/// nothing (its refusal has no line to name).
fn refused_entries(
    prepared: &[PreparePair],
    sources: &IntegrationSnapshot,
    now: Timestamp,
) -> Vec<heimdall_contract::doctor::ConfigProvenance> {
    for pair in prepared {
        let Some(mut report) = pair.alias.as_deref().and_then(|alias| {
            sources
                .observations
                .iter()
                .find(|o| o.alias == alias)
                .and_then(|o| o.identity_selection.clone())
        }) else {
            continue;
        };
        let adopted = report.entries.iter().any(|e| {
            e.source == heimdall_contract::provider::IdentityEntrySource::Managed
                && e.fingerprint.as_deref() == Some(pair.identity.fingerprint.as_str())
        });
        if report.selection == IdentitySelection::Exclusive {
            if adopted {
                continue;
            }
            report.selection = IdentitySelection::Undetermined;
        }
        let endpoint = pair
            .identity
            .source
            .endpoint()
            .cloned()
            .unwrap_or_else(no_endpoint);
        let eligibility_of = |id: &heimdall_contract::ids::IdentityId| -> PairEligibility {
            match sources.identities.iter().find(|r| &r.id == id) {
                Some(r) => heimdall_domain::catalog::eligibility(
                    r,
                    sources.declarations.get(id),
                    r.source.endpoint().unwrap_or(&endpoint),
                    now,
                ),
                None => PairEligibility {
                    interaction: InteractionKind::Unknown,
                    basis: EvidenceBasis::Inferred,
                    declaration: None,
                    noninteractive: NoninteractiveEligibility {
                        eligible: false,
                        reason: Some(noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
                    },
                },
            }
        };
        let clearance = heimdall_domain::catalog::fallback_clearance(
            &report,
            &sources.identities,
            &eligibility_of,
            &endpoint,
            &pair.identity.fingerprint,
        );
        if clearance.cleared {
            continue;
        }
        let mut out: Vec<heimdall_contract::doctor::ConfigProvenance> = Vec::new();
        for p in clearance
            .uncleared
            .iter()
            .filter_map(|i| report.entries.get(*i))
            .filter_map(|e| e.provenance.clone())
        {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        return out;
    }
    Vec::new()
}

/// ⟨M02⟩ The stable `INTERACTION_REQUIRED` reason of a fresh non-interactive
/// eligibility reason (ADR-0007 §7's results table): `provider_interaction` and
/// `fallback_identity_interaction` as they are; `interaction_unknown`, and any reason a
/// newer domain adds, as `interaction_unknown` (the narrowing reading).
fn eligibility_refusal_reason(reason: Option<&str>) -> &'static str {
    use heimdall_contract::envelope::reason;
    match reason {
        Some(noninteractive_reason::PROVIDER_INTERACTION) => reason::PROVIDER_INTERACTION,
        Some(noninteractive_reason::FALLBACK_IDENTITY_INTERACTION) => {
            reason::FALLBACK_IDENTITY_INTERACTION
        }
        _ => reason::INTERACTION_UNKNOWN,
    }
}

/// ⟨M02⟩ ADR-0007 §12.27 item 1 (S01): the final activation of a request that
/// requires no interaction is checked against the store, in the commit's own
/// transaction, before the grant is activated or its binding created. The adapter
/// judged eligibility over a snapshot read before its bound (§12.23 item 2), so a
/// declaration withdrawn, lapsed or changed since, or a fallback clearance that no
/// longer holds, is seen here:
///
/// * `pairs` carry each pair's fresh eligibility ([`Facts::with_eligibility`], read
///   in `tx`). The first pair that is not eligible refuses, with its fresh interaction
///   and reason;
/// * a pair the adapter cleared through its fallback clearance (a selection that is
///   not `exclusive`) is cleared again over the selection the adapter evaluated, with
///   the catalog identities and their declaration rows read in `tx`, under the one
///   domain rule (`heimdall_domain::catalog::fallback_clearance`). A clearance that no
///   longer holds refuses with `fallback_identity_interaction`, naming the uncleared
///   entries' lines (§12.26 item 4).
///
/// The refusal is `INTERACTION_REQUIRED` with `next: interact` and the provider's
/// interaction (never a `decision_ref`, spec §5.5), as `prepare_error` maps the
/// adapter's own refusal. `None` when every pair still holds (or there is no pair).
///
/// ⟨M02⟩ ADR-0007 §12.30 item 8: `next.provider_interaction.kind` is the refused pair's
/// fresh interaction kind, as the CLI's pre-launch check names it
/// (`heimdall::launch_flow::refusal_provider`): a pair whose fresh kind is `none` (its
/// own key needs nothing, but a fallback it relies on is no longer cleared) is
/// `unknown`, since which interaction ssh's other key needs is not known, and so is a
/// pair whose identity left the catalog ([`refused_interaction_kind`]).
fn noninteractive_commit_refusal(
    tx: &mut Txn<'_>,
    pairs: &[PairIntegration],
    mechanism: &str,
    now: Timestamp,
) -> heimdall_store::Result<Option<OpError>> {
    let refused = match pairs.iter().find(|p| !p.noninteractive.eligible) {
        Some(p) => Some((
            p.interaction,
            eligibility_refusal_reason(p.noninteractive.reason.as_deref()),
            Vec::new(),
        )),
        None => fresh_fallback_refusal(tx, pairs, now)?,
    };
    let Some((kind, reason, entries)) = refused else {
        return Ok(None);
    };
    let kind = refused_interaction_kind(kind);
    let provider = existing_access_provider(mechanism).unwrap_or(ProviderKind::Unknown);
    let mut error = OpError::from_adapter_for(
        &AdapterError::InteractionRequired(InteractionRequirement::ProviderDialog),
        PROVIDER_RESOURCE,
    )
    .with_resource(PROVIDER_RESOURCE, Some(mechanism.to_owned()))
    .with_reason(reason)
    .with_next(provider_interaction_next(
        Code::InteractionRequired,
        provider,
        kind,
    ));
    if !entries.is_empty() {
        let lines: Vec<String> = entries
            .iter()
            .map(|p| format!("{}:{}", p.path_display, p.line))
            .collect();
        error.message.push_str(&format!(
            "; an identity ssh may also try is not cleared for use without interaction ({})",
            lines.join(", ")
        ));
        error = error.with_entries(entries);
    }
    Ok(Some(error))
}

/// ⟨M02⟩ ADR-0007 §12.30 item 8: the interaction a non-interactive refusal names for the
/// refused pair's fresh `kind`, aligned with the pre-launch check: a refusal never names
/// `none` (that would say no interaction is needed), so `none` is `unknown`; every other
/// kind, `unknown` included, is named as it is.
fn refused_interaction_kind(kind: InteractionKind) -> InteractionKind {
    if kind == InteractionKind::None {
        InteractionKind::Unknown
    } else {
        kind
    }
}

/// ⟨M02⟩ The fallback clearance half of [`noninteractive_commit_refusal`]: for each
/// pair whose recorded selection is not `exclusive` (so its eligibility rested on a
/// clearance), the clearance over the recorded report with fresh store facts. The
/// first pair it no longer clears decides: its fresh interaction,
/// `fallback_identity_interaction`, and its uncleared entries' provenance (each once,
/// in entry order). A pair whose identity left the catalog, or that has no endpoint,
/// is not cleared.
fn fresh_fallback_refusal(
    tx: &mut Txn<'_>,
    pairs: &[PairIntegration],
    now: Timestamp,
) -> heimdall_store::Result<
    Option<(
        InteractionKind,
        &'static str,
        Vec<heimdall_contract::doctor::ConfigProvenance>,
    )>,
> {
    use heimdall_contract::envelope::reason;
    let mut catalog: Option<Vec<IdentityRecord>> = None;
    for pair in pairs {
        if pair.identity_selection == IdentitySelection::Exclusive {
            continue;
        }
        let refused = |entries| {
            Some((
                pair.interaction,
                reason::FALLBACK_IDENTITY_INTERACTION,
                entries,
            ))
        };
        // ⟨M03 wave 4, R2C-Q1; ADR-0008 D10 item 6⟩ A managed pair whose alias is not
        // classified `exclusive` may try an inherited identity that can prompt: refused
        // non-interactively, without consulting the catalog identity's endpoint (which is
        // not what signs for it).
        if pair.mechanism == MANAGED_CERTIFICATE {
            return Ok(refused(Vec::new()));
        }
        let Some(identity) = tx.identity(&pair.identity)? else {
            return Ok(refused(Vec::new()));
        };
        let Some(endpoint) = current_endpoint(&identity, pair.endpoint.as_ref()) else {
            return Ok(refused(Vec::new()));
        };
        let report = match &pair.identity_selection_report {
            Some(r) if r.selection == pair.identity_selection => r.clone(),
            _ => selection_report(pair.identity_selection),
        };
        let identities = match &catalog {
            Some(c) => c.clone(),
            None => {
                let c = tx.identities()?;
                catalog = Some(c.clone());
                c
            }
        };
        let mut fresh: BTreeMap<heimdall_contract::ids::IdentityId, PairEligibility> =
            BTreeMap::new();
        for r in &identities {
            let (e, _) = fresh_eligibility(tx, r, Some(&endpoint), now)?;
            fresh.insert(r.id.clone(), e);
        }
        let eligibility_of = |id: &heimdall_contract::ids::IdentityId| -> PairEligibility {
            fresh.get(id).cloned().unwrap_or_else(|| PairEligibility {
                interaction: InteractionKind::Unknown,
                basis: EvidenceBasis::Inferred,
                declaration: None,
                noninteractive: NoninteractiveEligibility {
                    eligible: false,
                    reason: Some(noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
                },
            })
        };
        let clearance = heimdall_domain::catalog::fallback_clearance(
            &report,
            &identities,
            &eligibility_of,
            &endpoint,
            &identity.fingerprint,
        );
        if clearance.cleared {
            continue;
        }
        let mut entries: Vec<heimdall_contract::doctor::ConfigProvenance> = Vec::new();
        for p in clearance
            .uncleared
            .iter()
            .filter_map(|i| report.entries.get(*i))
            .filter_map(|e| e.provenance.clone())
        {
            if !entries.contains(&p) {
                entries.push(p);
            }
        }
        return Ok(refused(entries));
    }
    Ok(None)
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
    /// ⟨M03⟩ ADR-0008 §17.17 item 4: the R3 session-lock floor in force
    /// (`Operations::session_lock_floor`), recorded in a new grant's origin.
    lock_floor: heimdall_contract::managed::LockBehavior,
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
    /// ⟨M03⟩ U0b row 9 (O): the per-pair mechanism resolution.
    pairs: pair_mechanism_m03::PairsResolution,
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
    // ⟨M02⟩ U0b row 7: the catalog's mechanism decides the adapter; with no catalog
    // identity for the pairs, the M01 selection. ⟨M03⟩ U0b row 9 (O): per pair, the
    // stored preference first (`pair_mechanism_m03`); without one, exactly M02's rule.
    let resolved_pairs = match pair_mechanism_m03::resolve_pairs(tx, &pairs)? {
        Ok(r) => r,
        Err(e) => refuse!(e),
    };
    let mechanism = resolved_pairs.mechanism;
    let adapter = select_adapter(&inp.adapters, &inp.spec.required, mechanism).cloned();
    // A pending projection whose existing mechanism cannot meet the minimums, or a
    // managed pair (wave 0: no driver), is refused with its reason before authority
    // resolution (which would otherwise deny on the missing mechanism).
    if adapter.is_none()
        && (resolved_pairs.pending_projection
            || resolved_pairs.mechanism == Some(MANAGED_CERTIFICATE))
    {
        // ⟨wave 4, U10-C⟩ `driver_unavailable` only while no managed adapter is
        // configured (a configured one is wired: `ensure_precheck` refused otherwise).
        refuse!(pair_mechanism_m03::no_mechanism(
            &inp.spec.required,
            resolved_pairs,
            heimdall_domain::policy::strictest_lock_behavior(
                inp.lock_floor,
                policy
                    .as_ref()
                    .map_or_else(Default::default, |p| p.lock_behavior),
            ),
            inp.adapters
                .iter()
                .find(|a| a.identity.mechanism == MANAGED_CERTIFICATE)
                .map(|a| a.unattended),
        ));
    }
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
        pairs: resolved_pairs,
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
        // ⟨M03⟩ U0b row 9 (O): with its M03 reason (`driver_unavailable`,
        // `projection_pending`, the `unattended` reason); otherwise M01's refusal.
        // ⟨wave 4, U10-C⟩ `driver_unavailable` only while no managed adapter is
        // configured (a configured one is wired: `ensure_precheck` refused otherwise).
        _ if r.adapter.is_none() => Err(pair_mechanism_m03::no_mechanism(
            &inp.spec.required,
            r.pairs,
            heimdall_domain::policy::strictest_lock_behavior(
                inp.lock_floor,
                r.policy
                    .as_ref()
                    .map_or_else(Default::default, |p| p.lock_behavior),
            ),
            inp.adapters
                .iter()
                .find(|a| a.identity.mechanism == MANAGED_CERTIFICATE)
                .map(|a| a.unattended),
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
            binding_id: None,
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
                binding_id: None,
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
    /// Authorized: the `Attempted` receipt is durable; prepare this bounded grant,
    /// with the catalog's pairs read in the same transaction (⟨M02⟩ U0b row 8).
    Go(Box<GrantSnapshot>, Timestamp, Vec<PreparePair>),
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
    /// may need the usual cleanup of its owner's credential (⟨r2.14⟩ the owner
    /// operation whose receipts record that effect). ⟨r2.16⟩ ADR-0006 §13.19 item
    /// 2: that cleanup was decided in the refusal's transaction; the cleanup intent
    /// it recorded, if any, owes a call after the commit.
    Refused(GrantId, Option<CleanupIntent>),
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

/// ⟨M02⟩ U0b row 23: what one admission transaction decided.
enum Admitted {
    /// The idempotency classification (`New` once inserted).
    Outcome(IdempotencyOutcome),
    /// A new key while the running counter was at its limit; nothing written.
    Backpressure,
    /// Another open or unresolved setup operation blocks it; nothing written.
    InProgress(Vec<OperationId>),
}

/// ⟨M02⟩ U0b row 23: a setup admission (m02-plan §5 item 18). The operation is
/// inserted through `Txn::insert_setup_operation` in the admission transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupAdmission {
    /// The environment whose setup operations are serialized (this runtime's).
    pub environment: EnvironmentId,
    /// The local intent stored at admission (`LocalIntent::Setup`).
    pub intent: LocalIntent,
    /// The held operation a `retry_held`/`keep_held` repair names.
    pub repair_target: Option<OperationId>,
}

/// ⟨M02⟩ `CONFIG_CONFLICT`, reason `setup_in_progress`, naming the blocking
/// operations in the resource and the oldest in `next.operation_id` (ADR-0007 §5.7).
fn setup_in_progress(blocking: &[OperationId]) -> OpError {
    let ids = blocking
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut e = OpError::new(
        Code::ConfigConflict,
        "another setup operation of this environment is open or unresolved",
    )
    .with_reason(heimdall_contract::envelope::reason::SETUP_IN_PROGRESS)
    .with_effect(EffectStatus::None)
    .with_resource("operation", Some(ids));
    e.next.operation_id = blocking.first().cloned();
    e
}

/// Drive-local facts; all of them are re-derived after a restart.
#[derive(Default)]
struct DriveLocal {
    prepared: Option<PrepareOutcome>,
    lead: Option<(EquivalenceKey, watch::Sender<Option<EnsureHandle>>)>,
    leader_data: Option<EnsureData>,
}

/// Prepared-credential facts reported for a binding.
///
/// ⟨M02⟩ U0b rows 4 to 6: `provider` and `integration` are **history**, the same
/// part `PreparedFacts` stores, so `ensure`, an attached binding, `bind`, a replay
/// and a restart report the same history. The fresh part of each pair
/// (`interaction`, `interaction_basis`, `declared_at`, `declaration`,
/// `noninteractive`, `eligibility_checked_at`) and `availability` are placeholders
/// until [`Facts::with_eligibility`] computes them in the transaction that builds
/// the result (M2-R04).
struct Facts {
    usable_until: Timestamp,
    offline_until: Timestamp,
    refresh_dependency: RefreshDependency,
    enforcement: heimdall_contract::request::Enforcement,
    provider: Option<ProviderStatus>,
    integration: ConsumerIntegration,
    availability: CredentialAvailability,
    /// ⟨M03; ADR-0008 §17.25 item 18⟩ The managed adapter's report
    /// (`PrepareOutcome.managed`), carried from the outcome only: absent from stored
    /// facts, so `from_data` and `conservative` leave it `None` (fail closed), and
    /// `ensure_data` copies it for a managed binding.
    managed: Option<crate::ports::ManagedResultFacts>,
}

impl Facts {
    fn from_outcome(o: &PrepareOutcome) -> Self {
        Self {
            usable_until: o.usable_until,
            offline_until: o.offline_until,
            refresh_dependency: o.refresh_dependency,
            enforcement: o.enforcement.report.clone(),
            provider: o.provider.clone(),
            integration: history_only(&o.integration),
            availability: CredentialAvailability::Unknown,
            managed: o.managed.clone(),
        }
    }

    fn from_data(d: &EnsureData) -> Self {
        Self {
            usable_until: d.usable_until,
            offline_until: d.offline_until,
            refresh_dependency: d.refresh_dependency,
            enforcement: d.enforcement.clone(),
            provider: d.provider.clone(),
            integration: history_only(&d.consumer),
            availability: CredentialAvailability::Unknown,
            managed: None,
        }
    }

    /// Facts claimable without the prepare outcome (bind, or an attached binding
    /// resumed after a restart): no claim beyond `now` (never overclaims). ⟨M02⟩ The
    /// history comes from the grant's stored `PreparedFacts`; without them the
    /// integration is empty (U0b row 5).
    fn conservative(
        grant: &GrantSnapshot,
        prepared: Option<&PreparedFacts>,
        now: Timestamp,
    ) -> Self {
        Self {
            usable_until: now.min(grant.deadline.effective),
            offline_until: now.min(grant.deadline.effective),
            refresh_dependency: RefreshDependency::ProviderInteraction,
            enforcement: grant.enforcement.report.clone(),
            provider: prepared.and_then(|p| p.provider.clone()),
            integration: prepared.map(integration_of).unwrap_or_default(),
            availability: CredentialAvailability::Unknown,
            managed: None,
        }
    }

    /// ⟨M02⟩ U0b row 5: every pair's fresh interaction and eligibility, and the
    /// result's `credential_availability`, from the catalog identity and its live
    /// declaration row read in `tx`, the transaction that builds the result, under
    /// the one pure rule `heimdall_domain::catalog::eligibility` (ADR-0007 §7).
    /// Nothing here is taken from stored facts.
    fn with_eligibility(
        mut self,
        tx: &mut Txn<'_>,
        now: Timestamp,
    ) -> heimdall_store::Result<Self> {
        for pair in &mut self.integration.pairs {
            fresh_pair(tx, pair, now)?;
        }
        self.availability = availability_of(&self.integration.pairs);
        Ok(self)
    }
}

/// ⟨M02⟩ The history part of an integration (what `PreparedFacts` keeps), with
/// every fresh pair field reset to its fail-closed placeholder.
fn history_only(i: &ConsumerIntegration) -> ConsumerIntegration {
    ConsumerIntegration {
        signing_endpoint: None,
        ssh_config_include: None,
        environment: i.environment.clone(),
        executables: i.executables.clone(),
        overrides: i.overrides.clone(),
        pairs: i
            .pairs
            .iter()
            .map(|p| history_pair(prepared_pair(p), p.selection_observed_at))
            .collect(),
    }
}

/// ⟨M02⟩ The history of one reported pair; its fresh fields are dropped.
///
/// ⟨M02⟩ ADR-0007 §12.15 item 3(c): the stored selection is the pair's full
/// `identity_selection_report` (entries and `IdentitiesOnly`, completing §12.14 item
/// 6). A pair without one, or whose report contradicts its verdict, keeps the
/// verdict alone ([`selection_report`]), which never clears a fallback.
fn prepared_pair(p: &PairIntegration) -> PreparedPair {
    let identity_selection = match &p.identity_selection_report {
        Some(report) if report.selection == p.identity_selection => report.clone(),
        _ => selection_report(p.identity_selection),
    };
    PreparedPair {
        destination: p.destination.clone(),
        account: p.account.clone(),
        identity: p.identity.clone(),
        mechanism: p.mechanism.clone(),
        endpoint: p.endpoint.clone(),
        alias: p.alias.clone(),
        identity_selection,
        selection_observed_at: p.selection_observed_at,
    }
}

/// ⟨M02⟩ A selection verdict as a report, for a pair that carries no full report:
/// no entries and an undetermined `IdentitiesOnly`, which never clears a fallback
/// (ADR-0007 §7).
fn selection_report(selection: IdentitySelection) -> IdentitySelectionReport {
    IdentitySelectionReport {
        selection,
        entries: Vec::new(),
        identities_only: IdentitiesOnly::Undetermined,
    }
}

/// ⟨M02⟩ A pair from its history, with the fresh fields at their fail-closed
/// placeholders (`unknown`, not eligible), checked at `at`.
fn history_pair(p: PreparedPair, at: Timestamp) -> PairIntegration {
    PairIntegration {
        destination: p.destination,
        account: p.account,
        identity: p.identity,
        mechanism: p.mechanism,
        endpoint: p.endpoint,
        alias: p.alias,
        interaction: InteractionKind::Unknown,
        interaction_basis: EvidenceBasis::Inferred,
        declared_at: None,
        identity_selection: p.identity_selection.selection,
        selection_observed_at: p.selection_observed_at,
        declaration: None,
        noninteractive: NoninteractiveEligibility {
            eligible: false,
            reason: Some(noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
        },
        eligibility_checked_at: at,
        // ⟨M02⟩ §12.15 item 3(c): history, reported as stored.
        identity_selection_report: Some(p.identity_selection),
    }
}

/// ⟨M02⟩ The integration a stored `PreparedFacts` describes (history only).
fn integration_of(p: &PreparedFacts) -> ConsumerIntegration {
    ConsumerIntegration {
        signing_endpoint: None,
        ssh_config_include: None,
        environment: p.environment.clone(),
        executables: p.executables.clone(),
        overrides: p.overrides.clone(),
        pairs: p
            .pairs
            .iter()
            .cloned()
            .map(|pair| history_pair(pair, p.recorded_at))
            .collect(),
    }
}

/// ⟨M02⟩ U0b row 6: `PreparedFacts` from an outcome. Every interaction,
/// availability and eligibility field of the outcome is dropped (M2-R04).
fn prepared_facts_of(o: &PrepareOutcome, recorded_at: Timestamp) -> PreparedFacts {
    PreparedFacts {
        provider: o.provider.clone(),
        executables: o.integration.executables.clone(),
        overrides: o.integration.overrides.clone(),
        environment: o.integration.environment.clone(),
        pairs: o.integration.pairs.iter().map(prepared_pair).collect(),
        recorded_at,
    }
}

/// ⟨M02⟩ An identity's current endpoint: the catalog record's, else the endpoint
/// the pair's history recorded.
fn current_endpoint(
    identity: &IdentityRecord,
    recorded: Option<&EndpointRef>,
) -> Option<EndpointRef> {
    identity.source.endpoint().or(recorded).cloned()
}

/// ⟨M02⟩ ADR-0007 §7 for one identity, fresh: its live declaration row is read in
/// `tx`. With no endpoint known, no declaration can count, and the documented kinds
/// (1Password, FIDO) still apply.
fn fresh_eligibility(
    tx: &mut Txn<'_>,
    identity: &IdentityRecord,
    recorded: Option<&EndpointRef>,
    now: Timestamp,
) -> heimdall_store::Result<(PairEligibility, Option<InteractionDeclaration>)> {
    let declaration = tx.interaction_declaration(&identity.id)?;
    let eligibility = match current_endpoint(identity, recorded) {
        Some(endpoint) => {
            heimdall_domain::catalog::eligibility(identity, declaration.as_ref(), &endpoint, now)
        }
        None => heimdall_domain::catalog::eligibility(identity, None, &no_endpoint(), now),
    };
    Ok((eligibility, declaration))
}

/// An endpoint that never equals a recorded one: only passed with no declaration,
/// so it is never compared.
fn no_endpoint() -> EndpointRef {
    EndpointRef {
        kind: heimdall_contract::provider::EndpointKind::UnixSocket,
        locator: String::new(),
    }
}

/// ⟨M02⟩ Fill one pair's fresh fields (U0b row 5). An identity that left the
/// catalog is `unknown` and not eligible.
fn fresh_pair(
    tx: &mut Txn<'_>,
    pair: &mut PairIntegration,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    // ⟨M03 wave 4, R2C-Q1; ADR-0008 D6 item 7⟩ A `managed_certificate` pair signs with
    // the in-process signer, never through its catalog identity (the existing access
    // the enrollment used): its interaction (`none`) and eligibility are the managed
    // adapter's, and only the check time moves. Its identity selection stays the
    // adapter's per-pair D10 item 6 classification, which `fresh_fallback_refusal`
    // judges (a non-exclusive managed alias is refused non-interactively).
    // ⟨M03 wave 4, round 3b (X-M); ADR-0008 §17.23 item 5⟩ The facts reach the commit
    // through their history (`Facts::from_outcome` → `history_only`), which resets every
    // fresh field to its fail-closed placeholder (`unknown`, not eligible), so the
    // adapter's values are restored here, exactly as `prepare::pair_integrations` sets
    // them for every managed pair (interaction `none`, inferred: the signer is
    // in-process; eligible). Without this, every non-interactive managed request (a
    // delegation is always one) was refused `interaction_unknown` before its selection
    // was judged.
    if pair.mechanism == MANAGED_CERTIFICATE {
        pair.interaction = InteractionKind::None;
        pair.interaction_basis = EvidenceBasis::Inferred;
        pair.declaration = None;
        pair.declared_at = None;
        pair.noninteractive = NoninteractiveEligibility {
            eligible: true,
            reason: None,
        };
        pair.eligibility_checked_at = now;
        return Ok(());
    }
    let fresh = match tx.identity(&pair.identity)? {
        Some(identity) => Some(fresh_eligibility(
            tx,
            &identity,
            pair.endpoint.as_ref(),
            now,
        )?),
        None => None,
    };
    let (interaction, basis, declaration, declared_at, noninteractive) = match fresh {
        Some((e, decl)) => {
            let declared_at = e
                .declaration
                .as_ref()
                .and(decl.as_ref())
                .map(|d| d.declared_at);
            (
                e.interaction,
                e.basis,
                e.declaration,
                declared_at,
                e.noninteractive,
            )
        }
        None => (
            InteractionKind::Unknown,
            EvidenceBasis::Inferred,
            None,
            None,
            NoninteractiveEligibility {
                eligible: false,
                reason: Some(noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
            },
        ),
    };
    pair.interaction = interaction;
    pair.interaction_basis = basis;
    pair.declaration = declaration;
    pair.declared_at = declared_at;
    pair.noninteractive = noninteractive;
    pair.eligibility_checked_at = now;
    Ok(())
}

/// ⟨M02⟩ A result's `credential_availability` from its fresh pairs (ADR-0007 §7
/// "Results and codes"): `current_only` when every pair is `none` (declared), else
/// `interaction_required`; `unknown` without pairs (nothing was established, and
/// availability is never stored).
fn availability_of(pairs: &[PairIntegration]) -> CredentialAvailability {
    if pairs.is_empty() {
        CredentialAvailability::Unknown
    } else if pairs.iter().all(|p| p.interaction == InteractionKind::None) {
        CredentialAvailability::CurrentOnly
    } else {
        CredentialAvailability::InteractionRequired
    }
}

fn ensure_data(
    binding: &BindingRecord,
    grant: &GrantSnapshot,
    facts: &Facts,
    bound: Timestamp,
) -> EnsureData {
    let end = grant.deadline.effective.min(bound);
    // ⟨M03; ADR-0008 §17.25 item 18⟩ The managed adapter's six report fields, for a
    // managed binding whose facts came from this process's outcome. After a restart
    // (`Facts::conservative`) or for any other mechanism they stay absent (fail
    // closed; M01/M02 results unchanged).
    let is_managed = binding.mechanism.as_str() == ca_issuance_m03::MANAGED_CERTIFICATE;
    let managed = facts.managed.as_ref().filter(|_| is_managed);
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
        consumer: facts.integration.clone(),
        credential_availability: facts.availability,
        provider: facts.provider.clone(),
        lock_continuity: managed.map(|m| m.lock_continuity),
        conditions: managed.map(|m| m.conditions.clone()).unwrap_or_default(),
        refresh_condition: managed.map(|m| m.refresh_condition),
        revocation: managed.map(|m| m.revocation.clone()),
        evidence: managed.map(|m| m.evidence.clone()).unwrap_or_default(),
        connection_policy: managed.map(|m| m.connection_policy.clone()),
    }
}

/// ⟨M03; ADR-0008 §17.25 item 15⟩ The `TIME_UNCERTAIN` warning's additive reason:
/// `time_confirmation_after_reboot` exactly when the gate's cause is no time reference
/// for this boot (`Unsynchronized`: no same-boot runtime anchor or attended confirmation,
/// and the clock not reported synchronized), the cause `heimdall time confirm` clears.
/// None for a rollback (`BelowHighWater`), skew or a backwards continuous clock.
fn time_warning_reason(u: &dtime::TimeUncertainty) -> Option<&'static str> {
    match u {
        dtime::TimeUncertainty::Unsynchronized { .. } => {
            Some(heimdall_contract::envelope::m03_warning::TIME_CONFIRMATION_AFTER_REBOOT)
        }
        dtime::TimeUncertainty::BelowHighWater { .. }
        | dtime::TimeUncertainty::Skew { .. }
        | dtime::TimeUncertainty::ContinuousWentBackwards => None,
    }
}

/// ⟨M02⟩ U0b row 21: one catalog identity for `inspect identities`, with its fresh
/// eligibility (row 5) and its live declaration's `DeclarationRef` (the pre-launch
/// check compares its revision, endpoint and expiry; ADR-0007 §7). Public material
/// only.
fn identity_view(
    tx: &mut Txn<'_>,
    identity: &IdentityRecord,
    now: Timestamp,
) -> heimdall_store::Result<serde_json::Value> {
    let (e, declaration) = fresh_eligibility(tx, identity, None, now)?;
    let live = declaration
        .as_ref()
        .filter(|d| d.state == heimdall_domain::catalog::DeclarationState::Live)
        .map(|d| heimdall_contract::provider::DeclarationRef {
            revision: d.revision,
            endpoint: d.endpoint.clone(),
            expires_at: d.expires_at,
        });
    let declared_at = e
        .declaration
        .as_ref()
        .and(declaration.as_ref())
        .map(|d| d.declared_at);
    Ok(serde_json::json!({
        "identity_id": identity.id,
        "revision": identity.revision,
        "fingerprint": identity.fingerprint,
        "key_type": identity.key_type(),
        "mechanism": identity.source.mechanism(),
        "endpoint": identity.source.endpoint(),
        "label": identity.label,
        "interaction": e.interaction,
        "interaction_basis": e.basis,
        "declared_at": declared_at,
        "declaration": live,
        "noninteractive": e.noninteractive,
        "eligibility_checked_at": now,
    }))
}

/// ⟨M02⟩ ADR-0007 §12.24 item 1: one catalog destination as `inspect destinations`
/// lists it: its ID, alias, revision, label and definition (`managed` or `observed`,
/// the `heimdall_contract::doctor::AliasDefinition` names); a managed destination also
/// carries the fields P renders (`hostname`, `port`, `account`, `identity_id`).
/// Catalog fields only: no file is read.
///
/// ⟨M03⟩ U8-Q6 (additive): a managed destination whose (destination, account) pair has
/// a stored `pair_preferences` row also carries `"preference": {"mechanism":
/// <PreferredMechanism>, "projection": <ProjectionStatus>}` (`{"state": "pending"}` or
/// `{"state": "applied", "generation": N}`), so `connect` takes ADR-0008 D8 item 2's
/// flow only for `managed_certificate` with `applied`. No row, or an observed
/// destination: no `preference` key (M02's listing, unchanged).
fn destination_view(
    d: &heimdall_domain::catalog::DestinationRecord,
    preference: Option<&heimdall_domain::enrollment::PairPreference>,
) -> serde_json::Value {
    use heimdall_contract::doctor::AliasDefinition;
    let mut view = serde_json::json!({
        "destination_id": d.id,
        "alias": d.alias,
        "revision": d.revision,
        "label": d.label,
        "updated_at": d.updated_at,
    });
    let (definition, rendered) = match &d.definition {
        DestinationDefinition::Managed {
            hostname,
            port,
            account,
            identity,
        } => (
            AliasDefinition::Managed,
            Some(serde_json::json!({
                "hostname": hostname,
                "port": port,
                "account": account,
                "identity_id": identity,
            })),
        ),
        DestinationDefinition::Observed => (AliasDefinition::Observed, None),
    };
    if let serde_json::Value::Object(map) = &mut view {
        map.insert("definition".to_owned(), serde_json::json!(definition));
        if let Some(serde_json::Value::Object(fields)) = rendered {
            map.extend(fields);
        }
        if definition == AliasDefinition::Managed
            && let Some(p) = preference
        {
            map.insert(
                "preference".to_owned(),
                serde_json::json!({
                    "mechanism": p.mechanism,
                    "projection": p.projection,
                }),
            );
        }
    }
    view
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
        // ⟨M02⟩ U0b row 2: the plan digest, the summary counts, the whole diff and the
        // restore column. The diff is never cut: a plan whose full diff exceeds
        // `MAX_DIFF_BYTES` is refused before a decision exists (`plan_too_large`,
        // ADR-0007 §12.32 item 5; ADR-0006 §3.1). What counts is the changes to the
        // owner's files and the content of Heimdall's own files that is created or
        // changed; the removal of Heimdall's own files is one summary line each, which
        // does not (§12.34 item 7; `setup::diff_exceeds_bound`).
        DecisionKind::ApplyProjection {
            operation,
            plan_digest,
            summary,
        } => serde_json::json!({
            "operation_id": operation,
            "plan_digest": plan_digest,
            "intent": summary.intent,
            "added_aliases": summary.added_aliases.len(),
            "changed_aliases": summary.changed_aliases.len(),
            "removed_aliases": summary.removed_aliases.len(),
            "files": summary.files.len(),
            "git": summary.git,
            "restore": summary.restore,
            "diff_text": summary.diff_text,
        }),
        DecisionKind::DeclareInteraction {
            operation,
            identity,
            fingerprint,
            endpoint,
            interaction,
            valid_until,
        } => serde_json::json!({
            "operation_id": operation,
            "identity_id": identity,
            "fingerprint": fingerprint,
            "endpoint": endpoint,
            "interaction": interaction,
            "valid_until": valid_until,
        }),
        // M03 wave 0 (A1): fail closed until U0b: no M03 decision is created in wave 0; were one
        // stored, its recorded content is shown verbatim.
        DecisionKind::RegisterIssuer { .. }
        | DecisionKind::RetireIssuer { .. }
        | DecisionKind::EnrollAccount { .. }
        | DecisionKind::EnrollSystemForm { .. }
        | DecisionKind::RemoveEnrollment { .. }
        | DecisionKind::ApproveTargetChange { .. } => {
            serde_json::to_value(&d.kind).unwrap_or_default()
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
            revocation_cap: AtomicU32::new(NO_CONFIGURED_CAP),
            preparing: Mutex::new(BTreeSet::new()),
            setup_inserts: Arc::new(AtomicUsize::new(0)),
            signing_gates: crate::managed::SigningGates::new(),
            narrowing: narrowing::NarrowingState::default(),
            managed_ops: managed_state_m03::ManagedOpsState::default(),
            uninstall_fence: Arc::default(),
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
                    unattended: d.lock_continuity == LockContinuity::Verified
                        && d.interaction == InteractionRequirement::None,
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

    /// ⟨M02⟩ U0b row 24: the bound in force for one adapter call.
    fn adapter_limit(&self) -> Duration {
        self.inner.config.limits.adapter_call_timeout
    }

    /// ⟨M02⟩ Test hook for U0b row 24: the operations whose preparation this
    /// process is running (the preparing marker, ADR-0006 §13.19 item 2). Not part
    /// of the supported API.
    #[doc(hidden)]
    #[must_use]
    pub fn preparing_operations(&self) -> Vec<OperationId> {
        self.inner
            .preparing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// ⟨M02⟩ Test hook for U0b row 24: adapter slots free now
    /// (`max_concurrent_adapter_calls` when no call is in progress). Not part of the
    /// supported API.
    #[doc(hidden)]
    #[must_use]
    pub fn available_adapter_slots(&self) -> usize {
        self.inner.adapter_slots.available_permits()
    }

    /// ⟨M02⟩ Test hook for U0b row 23, phase 2
    /// (`u0b_setup_admission_goes_through_insert_setup_operation`): how many times
    /// admission called `Txn::insert_setup_operation` in this process, whatever it
    /// answered. Not part of the supported API.
    #[doc(hidden)]
    #[must_use]
    pub fn setup_insert_calls(&self) -> usize {
        self.inner.setup_inserts.load(Ordering::SeqCst)
    }

    /// ⟨M03⟩ U0b row 24 (ADR-0008 D2 item 3a; wave-0 verify E6d): this runtime's
    /// signing gates and pending marks, shared by the narrowing paths and the signer.
    #[must_use]
    pub fn signing_gates(&self) -> &crate::managed::SigningGates {
        &self.inner.signing_gates
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
        let gates = self.inner.signing_gates.clone();
        let joined = tokio::task::spawn_blocking(move || {
            store.transaction(|tx| {
                let mut emit = Emit {
                    publisher,
                    events: Vec::new(),
                    gates,
                    narrowing_set: BTreeSet::new(),
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
                local: None,
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
                // ⟨M03⟩ U0b row 8 (ADR-0008 D2 table; F18): in this one transaction,
                // before any listener binds, installed credential instances become
                // `lost` and pending ones `destroyed` (their entries stay counted).
                restart_m03::mark_lost_in(tx, emit)?;
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
        // ⟨r2.16⟩ ADR-0006 §13.19 item 2: every cleanup intent a previous run left,
        // whatever its operation's state (nothing is in flight any more).
        if let Err(e) = self.process_cleanup_intents().await {
            tracing::warn!(code = %e.code, "cleanup intents could not be read at startup");
        }
        // ⟨M03⟩ U0b row 23 (ADR-0008 D4 item 3): CA retirements resume at their next
        // step. No issuer child runs yet, and the store item's deletion is the
        // owner-present CLI's (ADR-0008 §17.22 item 12): `retiring` and `unloaded`
        // stay (fail closed), and only `deleted → retired` (a store step alone) can
        // complete.
        match self.resume_ca_retirements(None).await {
            Ok(r) if !r.stalled.is_empty() => {
                tracing::info!(
                    count = r.stalled.len(),
                    "CA retirements wait for the issuer"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(code = %e.code, "CA retirements could not be resumed"),
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

    /// Whether `id`'s stored request is an interactive ensure (ADR-0007 §12.30 item 1).
    /// A delegation, any other kind, or a request that cannot be loaded or read is not.
    async fn stored_request_is_interactive(&self, id: &OperationId) -> bool {
        let Ok(st) = self.load_work(id).await else {
            return false;
        };
        matches!(
            st.request(),
            Some(Request::Ensure(r)) if r.interaction == InteractionMode::Interactive
        )
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
            // ⟨M02⟩ U0b row 10, phase 2: the setup and catalog drivers (U5). A
            // runtime without a projection writer cannot reconcile a setup
            // operation: it stays unresolved and untouched, reported with
            // `driver_unavailable`, exactly as in phase 1 (the fail-closed landing,
            // m02-plan §5 item 4), for a runtime that has one.
            OperationKind::SetupApply
            | OperationKind::SetupRollback
            | OperationKind::SetupRepair => {
                if self.inner.config.projection.is_some() {
                    crate::setup::drive(self, id).await
                } else {
                    self.local_driver_unavailable(&st.op).await
                }
            }
            OperationKind::Catalog => crate::catalog::drive(self, id).await,
            // Declared, never journaled (`Probe` reserved; U0's kind test): no row
            // of these kinds is ever admitted, so there is nothing to drive.
            OperationKind::Cancel
            | OperationKind::Release
            | OperationKind::Policy
            | OperationKind::Probe => Ok(()),
            // ⟨M03⟩ U0b row 17, phase 1 (ADR-0008 D5 §6.4): an M03 operation is never
            // driven (restart included); it stays unresolved and untouched, reported
            // once with reason `owner_reconcile` (wave-0 verify E8).
            OperationKind::EnrollmentApply
            | OperationKind::EnrollmentVerify
            | OperationKind::EnrollmentRemove => self.owner_reconcile_unresolved(&st.op).await,
        };
        r.map_err(|e| {
            if e.operation_id.is_none() {
                e.with_operation(id.clone())
            } else {
                e
            }
        })
    }

    /// ⟨M02⟩ U0b row 10 (m02-plan §5 item 4; wave-0 verify E2 reading): a setup
    /// operation found by a drive (restart recovery included) in a runtime without
    /// a projection writer (phase 2; in phase 1, every setup and catalog operation)
    /// stays unresolved and untouched: no file, no receipt, no state change. One
    /// additive `runtime_lifecycle` event names it, with its kind and reason
    /// `driver_unavailable`, so a runtime that has the writer can reconcile it.
    /// Never fails the drive: the operation is simply left where it is.
    async fn local_driver_unavailable(&self, op: &OperationRecord) -> Result<(), OpError> {
        if op.state.is_settled() {
            return Ok(());
        }
        let payload = serde_json::json!({
            "phase": "unresolved",
            "operation_id": op.id,
            "kind": op.kind,
            "state": op.state,
            "reason": heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE,
        });
        let id = op.id.clone();
        self.write(move |tx, emit| {
            emit.event(
                tx,
                EventType::RuntimeLifecycle,
                Some(id.clone()),
                Some(resource("operation", &id)),
                payload,
            )?;
            Ok(())
        })
        .await
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
            lock_floor: self.session_lock_floor(),
        };
        let decision_id = crate::ids::new_decision_id()?;
        // ⟨M03 wave 4, §17.21 item 1⟩ The binding ID of a `managed_certificate`
        // resolution, minted here and recorded in the intent (unused otherwise).
        let managed_binding = crate::ids::new_binding_id()?;
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
                    Ok(r) => pin(&inp, r)
                        .map(|r| managed_driver_m03::with_managed_binding(r, &managed_binding)),
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
                                    let origin = lock_connection_m03::with_lock_and_connection(
                                        tx,
                                        &op.environment,
                                        origin,
                                        &intent.request,
                                        inp.lock_floor,
                                    )?;
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
            // ⟨M02⟩ U0b row 24: a timed-out call yields no facts, as any error.
            bounded_adapter_call(self.adapter_limit(), adapter.reconcile(grant, &token)).await
        };
        match outcome {
            Ok(ReconcileOutcome::Applied(o)) => Some(o),
            // ⟨M02⟩ ADR-0007 §12.15 item 7 (E-U6-6): an adapter with no external
            // effect keeps its integrations in instance memory, which a restart
            // empties. Its `not_applied` for a confirmed effect is answered from
            // the facts recorded with that confirmation.
            Ok(ReconcileOutcome::NotApplied) if !adapter.descriptor().external_side_effects => {
                self.confirmed_from_prepared_facts(owner, grant).await
            }
            _ => None,
        }
    }

    /// ⟨M02⟩ ADR-0007 §12.15 item 7 (E-U6-6): the outcome of `operation`'s confirmed
    /// effect for `grant`, answered from the `PreparedFacts` its `Confirmed` receipt
    /// recorded (U0b row 6), never from an adapter instance's memory. Only for an
    /// adapter with no external effect: its "effect" is the integration it returned,
    /// which those facts record. Conservative beyond the history: no claim past the
    /// current time ([`Facts::conservative`]), the grant's recorded enforcement, a
    /// provider-interaction refresh dependency, availability `unknown`. `None` when
    /// no `Confirmed` receipt or no stored facts exist (the caller fails closed).
    async fn confirmed_from_prepared_facts(
        &self,
        operation: &OperationId,
        grant: &GrantId,
    ) -> Option<PrepareOutcome> {
        let (op, gid) = (operation.clone(), grant.clone());
        let clock = self.clock();
        self.write(move |tx, _| {
            let credential_ref =
                tx.stage_receipts(&op)?
                    .into_iter()
                    .rev()
                    .find_map(|r| match r.effect {
                        EffectReceipt::Confirmed { credential_ref, .. } => Some(credential_ref),
                        _ => None,
                    });
            let (Some(credential_ref), Some(facts), Some(g)) = (
                credential_ref,
                tx.grant_prepared_facts(&gid)?,
                tx.grant(&gid)?,
            ) else {
                return Ok(None);
            };
            let now = clock.wall();
            let conservative = Facts::conservative(&g, Some(&facts), now);
            Ok(Some(PrepareOutcome {
                usable_until: conservative.usable_until,
                offline_until: conservative.offline_until,
                refresh_dependency: conservative.refresh_dependency,
                enforcement: g.enforcement.clone(),
                credential_ref,
                availability: CredentialAvailability::Unknown,
                provider: conservative.provider,
                integration: conservative.integration,
                managed: None,
            }))
        })
        .await
        .ok()
        .flatten()
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
    ///
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: when the operation already left `running`
    /// (cancelled while the preparation was in flight) and no attached operation
    /// continues with its grant, the possibly applied credential needs cleanup: the
    /// receipt's transaction also records who makes the call after it
    /// ([`settle_effect_in`]), and an owed call is made after the commit.
    async fn mark_uncertain(
        &self,
        id: &OperationId,
        adapter: AdapterIdentity,
        token: String,
        grant: &GrantId,
    ) -> Result<Flow, OpError> {
        let id = id.clone();
        let clock = self.clock();
        let gid = grant.clone();
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let intent = self
            .write(move |tx, emit| {
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
                    return Ok(None);
                };
                if op.state != OperationState::Running {
                    if op.state == OperationState::OutcomeUnknown || continues_for_others(tx, &op)?
                    {
                        return Ok(None);
                    }
                    return settle_effect_in(tx, &gid, &id, cap, now);
                }
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
                Ok(None)
            })
            .await?;
        if let Some(intent) = intent {
            self.process_cleanup_intent(intent, true).await;
        }
        Ok(Flow::Stop)
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
            // ⟨M02⟩ U0b row 24: a timed-out call leaves the operation unresolved,
            // as any error does below.
            bounded_adapter_call(self.adapter_limit(), adapter.reconcile(&grant, &token)).await
        };
        match outcome {
            Ok(ReconcileOutcome::Applied(o)) => {
                let credential_ref = o.credential_ref.clone();
                let outcome = o.clone();
                local.prepared = Some(o);
                let clock = self.clock();
                let id2 = id.clone();
                self.write(move |tx, _| {
                    let now = clock.wall();
                    tx.append_stage_receipt(
                        &id2,
                        &receipt(
                            EnsureStage::Reconcile,
                            now,
                            EffectReceipt::Confirmed {
                                adapter: identity,
                                credential_ref,
                            },
                        ),
                    )?;
                    // ⟨M02⟩ U0b row 6: the history `prepare` observed, in the
                    // transaction of its `Confirmed` receipt.
                    tx.set_grant_prepared_facts(&grant, &prepared_facts_of(&outcome, now))?;
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
            // ⟨M03 wave 4, §17.22 item 8 (W4-R05)⟩ A managed preparation's uncertain
            // effect is never left unresolved: its key lived in the process that drove
            // it, so it fails, and its cleanup (key, instances, endpoint, files) runs.
            Ok(ReconcileOutcome::Unknown) | Err(_) if identity.mechanism == MANAGED_CERTIFICATE => {
                self.fail_unrecoverable_preparation(&id, &grant).await
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
                // ⟨M03⟩ ADR-0008 §17.17 item 4: the floor the new grant's origin records.
                let floor = self.session_lock_floor();
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
                            let origin = lock_connection_m03::with_lock_and_connection(
                                tx,
                                &op.environment,
                                origin,
                                &intent.request,
                                floor,
                            )?;
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
                    .mark_uncertain(&id, identity, effect_token.clone(), &grant_id)
                    .await;
            };
            let outcome = {
                let _slot = self
                    .inner
                    .adapter_slots
                    .acquire()
                    .await
                    .map_err(|_| internal("adapter slots closed"))?;
                // ⟨M02⟩ U0b row 24: a timed-out call marks the attempt uncertain,
                // as any error does below.
                bounded_adapter_call(
                    self.adapter_limit(),
                    adapter.reconcile(&grant_id, effect_token),
                )
                .await
            };
            match outcome {
                Ok(ReconcileOutcome::Applied(o)) => {
                    return self.confirm(&id, identity, o, &grant_id, local).await;
                }
                Ok(ReconcileOutcome::NotApplied) => {} // a fresh attempt is safe
                // ⟨M03 wave 4, §17.22 item 8 (W4-R05)⟩ An `Attempted` or uncertain
                // managed preparation that cannot be confirmed (a crash anywhere between
                // the attempt and the confirmation, the materialization included): it
                // fails, and its cleanup intent runs, never left `outcome_unknown`.
                Ok(ReconcileOutcome::Unknown) | Err(_)
                    if identity.mechanism == MANAGED_CERTIFICATE =>
                {
                    return self.fail_unrecoverable_preparation(&id, &grant_id).await;
                }
                Ok(ReconcileOutcome::Unknown) | Err(_) => {
                    return self
                        .mark_uncertain(&id, identity, effect_token.clone(), &grant_id)
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
        // ⟨r2.16⟩ ADR-0006 §13.19 item 2: from before the attempt is recorded until
        // `prepare` returns, this process runs the preparation.
        let preparing = self.preparing(&id);
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
                        // ⟨M02⟩ U0b row 8: the catalog's pairs for the grant's
                        // scope, read with the attempt; a pair naming another
                        // mechanism than the pinned adapter's is refused (P6).
                        // ⟨M03 wave 4, §17.21 item 1; U0b row 9⟩ For the managed
                        // adapter the pairs' stored preference decided the mechanism
                        // at resolve (mixing refused there); the catalog identity of a
                        // managed pair is its existing access, not its mechanism.
                        let managed = ident.mechanism == MANAGED_CERTIFICATE;
                        let named = catalog_pairs(tx, &g.scope.pairs)?.and_then(|named| {
                            match catalog_mechanism(&named)? {
                                Some(m) if m != ident.mechanism && !managed => {
                                    Err(mixed_mechanisms())
                                }
                                _ => Ok(named),
                            }
                        });
                        match (gate.admission(tx, &gid, &safe)?, named) {
                            (Admission::Open, Err(e)) => {
                                Refusal::new(e, Some(GrantEvent::PreparationFailed))
                            }
                            (Admission::Open, Ok(named)) => {
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
                                // ⟨M03 wave 4, §17.22 item 8 (W4-R05, W4-R06)⟩ A managed
                                // preparation's cleanup owner exists from here, before
                                // its first external effect.
                                if managed {
                                    managed_driver_m03::record_preparation_intent_in(
                                        tx,
                                        &gid,
                                        &id2,
                                        ident.clone(),
                                        tok.clone(),
                                        now,
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
                                return Ok(Attempt::Go(Box::new(bounded), now, named));
                            }
                            (Admission::NeedsAnchor, _) => return Ok(Attempt::Unanchored),
                            (Admission::Expired, _) => Refusal::new(
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
        let (grant, now, named) = match attempt {
            Attempt::Go(g, now, named) => (g, now, named),
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
        // ⟨M02⟩ ADR-0007 §12.23 item 2 (U02): every input the call needs (catalog
        // identities, declaration rows, executables, the projection observation) is
        // read here, in this step and before the bound, on the blocking pool. A
        // blocked store or a slow observation delays this step as any store wait
        // does, never the bounded call.
        let mut sources = read_prepare_sources(&adapter, &named).await;
        // ⟨M03⟩ U0b row 21, phase 2 (wave 4): for the managed adapter only, the effect
        // driver runs here, outside the adapter bound (ADR-0008 D6 item 0), and its
        // results go into the snapshot `prepare_from` computes from. A driver failure
        // takes the same arms as a failed `prepare_from` below.
        let driven = self
            .run_effect_driver(
                &adapter,
                PrepareRequest {
                    grant: &grant,
                    scope: &grant.scope,
                    required: &spec.required,
                    interactive,
                    effect_token: &token,
                    now,
                    pairs: &named,
                },
                &mut sources,
            )
            .await;
        // ⟨M02⟩ U0b row 24: the bound covers `prepare_from` alone, inside the slot and
        // the preparing marker; a timed-out call answers `OutcomeUnknown` and takes
        // the `mark_uncertain` arm below, after both are released.
        let result = match driven {
            Err(e) => Err(e),
            Ok(()) => {
                bounded_adapter_call(
                    self.adapter_limit(),
                    adapter.prepare_from(
                        PrepareRequest {
                            grant: &grant,
                            scope: &grant.scope,
                            required: &spec.required,
                            interactive,
                            effect_token: &token,
                            now,
                            pairs: &named,
                        },
                        &sources,
                    ),
                )
                .await
            }
        };
        drop(slot);
        drop(preparing);
        // ⟨M03 wave 4, §17.22 item 8⟩ A managed preparation is local work (its key lives
        // in this process): it is never left `outcome_unknown`.
        let managed = identity.mechanism == MANAGED_CERTIFICATE;
        let flow = match result {
            Ok(o) => self.confirm(&id, identity, o, &grant_id, local).await,
            Err(AdapterError::OutcomeUnknown(_)) if !managed => {
                self.mark_uncertain(&id, identity, token, &grant_id).await
            }
            Err(AdapterError::OutcomeUnknown(_)) => {
                self.fail_unrecoverable_preparation(&id, &grant_id).await
            }
            Err(e) => {
                let error = self
                    .prepare_error(&e, &identity, &named, &sources, now)
                    .await;
                // ⟨M03 wave 4, §17.21 item 1; §17.22 item 8 (W4-R06)⟩ Any managed
                // failure after the attempt (the driver's own, whose cleanup may not
                // have completed, or `prepare_from`'s): the failure keeps the cleanup
                // intent recorded with the attempt, processed just below and retried
                // until the key, the binding endpoint and the files are gone.
                if managed {
                    self.fail_managed_preparation(&id, error, &grant_id)
                        .await
                        .map(|_| Flow::Stop)
                } else {
                    self.fail_running(&id, error, Some(GrantEvent::PreparationFailed))
                        .await
                }
            }
        };
        // ⟨r2.16⟩ ADR-0006 §13.19 item 2: a cleanup intent written while this
        // preparation was in flight (a cancellation) is processed now that it
        // returned, whatever its own step did (that step's commit may have failed).
        self.process_cleanup_intent_of(&grant_id, &id).await;
        flow
    }

    /// Write the `Confirmed` receipt for an applied effect; if the operation left
    /// `running` meanwhile (cancelled, or its grant revoked), the receipt still
    /// records the truth and the credential is cleaned up.
    ///
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: the cleanup decision is written in the
    /// receipt's transaction ([`settle_effect_in`]), so a failure after it, or a
    /// crash, cannot leave the confirmed credential with neither an owning
    /// obligation nor a call owed by a cleanup intent. An owed call is made after the
    /// commit.
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
        let gid = grant.clone();
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let outcome = o.clone();
        let (still_running, intent) = self
            .write(move |tx, _| {
                let now = clock.wall();
                tx.append_stage_receipt(
                    &id2,
                    &receipt(
                        EnsureStage::Reconcile,
                        now,
                        EffectReceipt::Confirmed {
                            adapter: identity,
                            credential_ref,
                        },
                    ),
                )?;
                // ⟨M02⟩ U0b row 6: the history `prepare` observed, in the same
                // transaction as the receipt and the cleanup decision below. A store
                // error fails all three together; prepared facts never decide cleanup
                // ownership.
                tx.set_grant_prepared_facts(&gid, &prepared_facts_of(&outcome, now))?;
                let running = match tx.operation(&id2)? {
                    Some(op) => {
                        op.state == OperationState::Running || continues_for_others(tx, &op)?
                    }
                    None => false,
                };
                if running {
                    return Ok((true, None));
                }
                Ok((false, settle_effect_in(tx, &gid, &id2, cap, now)?))
            })
            .await?;
        if !still_running {
            if let Some(intent) = intent {
                self.process_cleanup_intent(intent, true).await;
            }
            return Ok(Flow::Stop);
        }
        local.prepared = Some(o);
        Ok(Flow::Continue)
    }

    /// The classified error of a failed `prepare` (not `OutcomeUnknown`, which
    /// `mark_uncertain` handles).
    ///
    /// ⟨M02⟩ ADR-0007 §12.15 item 7 (E-U6-4): an existing-access adapter's error
    /// (mechanism `native_agent` or `onepassword`) maps with
    /// `OpError::from_adapter_for(&e, "provider")`, naming the provider:
    /// * an absent endpoint (`Unavailable`) carries reason `endpoint_absent`;
    /// * `INTERACTION_REQUIRED` carries its reason and `next.provider_interaction`
    ///   from the pair eligibility **the runtime computes** in a fresh transaction
    ///   (`heimdall_domain::catalog::eligibility` over the catalog identity and its
    ///   live declaration row; ADR-0007 §7). The first pair that is not eligible
    ///   decides; when the runtime finds every pair eligible, the adapter's refusal
    ///   can only come from its fallback clearance, so the reason is
    ///   `fallback_identity_interaction`; with no pair, the provider's documented
    ///   interaction decides. Never a `decision_ref` (spec §5.5);
    /// * `PROVIDER_LOCKED` carries `next.provider_interaction` `provider_unlock`.
    ///
    /// ⟨M03 wave 4, round 2 (R2-E)⟩ A managed preparation whose effect driver could not
    /// have its certificate signed (`Unavailable(`[`ISSUER_SIGN_FAILED`]`)`: the issuer
    /// refused unavailable, or did not answer within the bound) is
    /// `CAPABILITY_UNAVAILABLE`, reason `issuer_unavailable` (ADR-0008 D3 item 7: "while
    /// the issuer is not `ready`, new activations ... fail with `CAPABILITY_UNAVAILABLE`,
    /// reason `issuer_unavailable`"), not the M01 `SERVICE_UNAVAILABLE` of a local
    /// adapter dependency. ⟨R2-F⟩ When the issuer answered a store reason
    /// (`issuer_store_locked`, `issuer_store_unavailable`), that is the reason ("or the
    /// store reason"; [`issuer_sign_failure_reason`]).
    ///
    /// Any other adapter keeps the M01 mapping. Adapter text is never echoed.
    ///
    /// [`ISSUER_SIGN_FAILED`]: crate::managed::driver::ISSUER_SIGN_FAILED
    /// [`issuer_sign_failure_reason`]: crate::managed::driver::issuer_sign_failure_reason
    async fn prepare_error(
        &self,
        e: &AdapterError,
        adapter: &AdapterIdentity,
        pairs: &[PreparePair],
        sources: &IntegrationSnapshot,
        now: Timestamp,
    ) -> OpError {
        if adapter.mechanism == MANAGED_CERTIFICATE
            && let Some(why) = crate::managed::driver::issuer_sign_failure_reason(e)
        {
            return OpError::new(
                Code::CapabilityUnavailable,
                "the issuer is unavailable: no new certificate can be issued",
            )
            .with_resource("issuer", None)
            .with_reason(why);
        }
        let Some(provider) = existing_access_provider(&adapter.mechanism) else {
            return OpError::from(e.clone());
        };
        let base = OpError::from_adapter_for(e, PROVIDER_RESOURCE)
            .with_resource(PROVIDER_RESOURCE, Some(adapter.mechanism.clone()));
        match e {
            AdapterError::Unavailable(_) => {
                base.with_reason(heimdall_contract::envelope::reason::ENDPOINT_ABSENT)
            }
            AdapterError::ProviderLocked => base.with_next(provider_interaction_next(
                Code::ProviderLocked,
                provider,
                InteractionKind::ProviderUnlock,
            )),
            AdapterError::InteractionRequired(_) => {
                let identities: Vec<IdentityRecord> =
                    pairs.iter().map(|p| p.identity.clone()).collect();
                let judged = self
                    .write(move |tx, _| {
                        let mut out = Vec::with_capacity(identities.len());
                        for identity in &identities {
                            out.push(fresh_eligibility(tx, identity, None, now)?.0);
                        }
                        Ok(out)
                    })
                    .await;
                let (kind, reason, entries) = match judged {
                    Ok(eligibility) => {
                        interaction_refusal(provider, &eligibility, pairs, sources, now)
                    }
                    // Unreadable: the narrowing reading.
                    Err(_) => (
                        InteractionKind::Unknown,
                        heimdall_contract::envelope::reason::INTERACTION_UNKNOWN,
                        Vec::new(),
                    ),
                };
                let mut error = base
                    .with_reason(reason)
                    .with_next(provider_interaction_next(
                        Code::InteractionRequired,
                        provider,
                        kind,
                    ));
                // ADR-0007 §12.26 item 4: the refused lines, as the CLI's pre-launch
                // refusal names them (display paths, `~` for the account home).
                if !entries.is_empty() {
                    let lines: Vec<String> = entries
                        .iter()
                        .map(|p| format!("{}:{}", p.path_display, p.line))
                        .collect();
                    error.message.push_str(&format!(
                        "; an identity ssh may also try is not cleared for use without interaction ({})",
                        lines.join(", ")
                    ));
                }
                error.with_entries(entries)
            }
            _ => base,
        }
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: mark `operation`'s preparation as running in
    /// this process until the guard drops.
    fn preparing(&self, operation: &OperationId) -> Preparing<'_> {
        self.inner
            .preparing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(operation.clone());
        Preparing {
            set: &self.inner.preparing,
            operation: operation.clone(),
        }
    }

    /// ⟨r2.16⟩ Whether this process runs `operation`'s preparation now.
    fn is_preparing(&self, operation: &OperationId) -> bool {
        self.inner
            .preparing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(operation)
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: every cleanup intent on record is processed
    /// ([`Self::process_cleanup_intent`]), whatever the state of its operation
    /// (cancelled, refused, failed, settled long ago): restart recovery runs it once
    /// the open operations were driven, and the supervisor in every revocation pass
    /// (`Supervisor::revocation_pass`). An intent whose attempt may still be in flight
    /// in this process is left to that preparation's return path.
    pub async fn process_cleanup_intents(&self) -> Result<(), OpError> {
        let intents = self.write(|tx, _| tx.cleanup_intents()).await?;
        for intent in intents {
            self.process_cleanup_intent(intent, false).await;
        }
        Ok(())
    }

    /// ⟨r2.16⟩ The cleanup intent of (`grant`, `operation`), if one is on record,
    /// processed by its originating path ([`Self::process_cleanup_intent`]).
    async fn process_cleanup_intent_of(&self, grant: &GrantId, operation: &OperationId) {
        let (g, op) = (grant.clone(), operation.clone());
        match self.write(move |tx, _| tx.cleanup_intent(&g, &op)).await {
            Ok(Some(intent)) => self.process_cleanup_intent(intent, true).await,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(code = %e.code, "a cleanup intent could not be read; it is kept");
            }
        }
    }

    /// Best-effort local revocation of a credential prepared for an activation
    /// that did not happen (cancelled, revoked, expired or refused at commit).
    ///
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: it runs from a cleanup `intent`, written in
    /// the transaction that settled the operation with the effect
    /// ([`settle_effect_in`]). `origin` is set when the path that wrote it (or the
    /// preparation's return path) runs it right after its commit.
    ///
    /// 1. The decision is taken again for the intent's effect, in one transaction,
    ///    if the intent is still the one on record ([`own_applied_effect_in`]): a
    ///    covering record may own the call by now. When a live obligation owns it,
    ///    or one was re-armed or added, the intent is removed and nothing is called.
    /// 2. Otherwise the call is made. For a grant no record covers (ADR-0006 §13.17
    ///    item 3), the immediate best-effort call goes to every configured adapter,
    ///    as before, but only when the applying adapter is configured (otherwise no
    ///    call could follow the effect: the intent is kept until it is configured
    ///    again). For a bounded effect (§13.18 item 4), each applying adapter that is
    ///    configured is called (exactly its identity), and its answers are tracked
    ///    ([`track_bounded_answers_in`]).
    /// 3. The intent is removed (when it is still the one processed) in the
    ///    transaction that tracks the answers: a call was made after the effect, or
    ///    an obligation owns it.
    ///
    /// An intent whose attempt may still be in flight in this process (`in_flight`,
    /// and its preparation runs) is skipped unless `origin` is set, and then
    /// processed without being removed: the call made now may precede the effect,
    /// and the preparation's return path processes it again. A failure leaves it on
    /// record for the next supervisor pass or restart (fail closed). No outcome
    /// leaves an applied effect with neither a live owning obligation nor a call
    /// made after it, or an intent that owes one.
    ///
    /// ⟨M03 wave 4, §17.22 items 6 and 8⟩ For a `managed_certificate` grant, first
    /// (`managed_driver_m03::IntentDisposition`): the intent a managed preparation
    /// recorded with its attempt is not processed while that preparation lives in this
    /// process (whatever `origin`); a coalesced follower's intent clears only its own
    /// uncommitted binding, never the shared grant's key.
    async fn process_cleanup_intent(&self, intent: CleanupIntent, origin: bool) {
        match self.cleanup_intent_disposition(&intent).await {
            managed_driver_m03::IntentDisposition::Live => return,
            managed_driver_m03::IntentDisposition::Follower => {
                self.cleanup_follower_binding(&intent).await;
                return;
            }
            managed_driver_m03::IntentDisposition::Other => {}
        }
        let in_flight = intent.in_flight && self.is_preparing(&intent.operation);
        if in_flight && !origin {
            return;
        }
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let effect = intent_effect(&intent);
        let version = intent.version;
        let (g, op) = (intent.grant.clone(), intent.operation.clone());
        let decided = self
            .write(move |tx, _| {
                if tx
                    .cleanup_intent(&g, &op)?
                    .is_none_or(|i| i.version != version)
                {
                    return Ok(None);
                }
                match own_applied_effect_in(tx, &g, effect.as_ref(), cap)? {
                    EffectOwner::Live | EffectOwner::Rearmed => {
                        if !in_flight {
                            tx.clear_cleanup_intent(&g, &op)?;
                        }
                        Ok(None)
                    }
                    owner => Ok(Some(owner)),
                }
            })
            .await;
        let owner = match decided {
            Ok(Some(owner)) => owner,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(code = %e.code, "a cleanup intent could not be processed; it is kept");
                return;
            }
        };
        let grant = &intent.grant;
        let now = self.inner.config.clock.wall();
        let limit = self.adapter_limit();
        let mut keep_intent = false;
        let answers = match owner {
            EffectOwner::Bounded(adapters) => {
                let mut answers: Vec<(AdapterIdentity, Option<bool>)> = Vec::new();
                for a in adapters {
                    // ⟨M02⟩ U0b row 24 (QR17): a timed-out bounded call is an
                    // unconfirmed answer, tracked as an obligation below.
                    let answer = match self.adapter(Some(&a)) {
                        Some(adapter) => Some(
                            bounded_adapter_call(limit, adapter.revoke(grant, now))
                                .await
                                .is_ok_and(|o| o.remote_pending.is_empty()),
                        ),
                        None => None,
                    };
                    answers.push((a, answer));
                }
                answers
            }
            _ => {
                let applying_configured = match &intent.adapter {
                    Some(a) => self.adapter(Some(a)).is_some(),
                    None => !self.inner.config.adapters.is_empty(),
                };
                if !applying_configured {
                    return;
                }
                // ⟨M02⟩ U0b row 24 (QR17, M02 only): the immediate best-effort call
                // for an uncovered grant counts as made when it times out, as an
                // error does in M01; M02's adapters create no remote effect.
                // ⟨M03⟩ U0b row 7 (G; ADR-0008 D7 item 5): for an adapter with a
                // remote credential effect a timed-out call never counts as made: the
                // intent is kept, and the supervisor retries it with bounded, jittered
                // back-off (`process_cleanup_intent_reporting` answers `Kept`).
                for a in &self.inner.config.adapters {
                    let answer = bounded_adapter_call(limit, a.revoke(grant, now)).await;
                    if a.descriptor().remote_credential_effect
                        && matches!(&answer, Err(AdapterError::OutcomeUnknown(m)) if m == ADAPTER_CALL_TIMED_OUT)
                    {
                        keep_intent = true;
                    }
                }
                Vec::new()
            }
        };
        // ⟨M03 wave 4, §17.21 item 1⟩ A managed preparation's key, instances and
        // uncommitted binding (endpoint and files) go with the call; a failed clear
        // keeps the intent for the next pass.
        if !self.cleanup_uncommitted_managed(&intent).await {
            keep_intent = true;
        }
        let (g, op) = (intent.grant.clone(), intent.operation.clone());
        let done = self
            .write(move |tx, _| {
                if answers.iter().any(|(_, answer)| *answer != Some(true)) {
                    track_bounded_answers_in(tx, &g, &answers, cap)?;
                }
                if !in_flight
                    && !keep_intent
                    && tx
                        .cleanup_intent(&g, &op)?
                        .is_some_and(|i| i.version == version)
                {
                    tx.clear_cleanup_intent(&g, &op)?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = done {
            tracing::warn!(code = %e.code, "a cleanup call's answer could not be recorded; its intent is kept");
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
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
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
                    // ⟨r2.16⟩ ADR-0006 §13.19 item 2: the credential's cleanup is
                    // decided in the refusal's transaction.
                    let effect_of = match orphan {
                        Some(owner) => Some(owner),
                        None => (!attached && effect != EffectStatus::None).then(|| id.clone()),
                    };
                    let intent = match &effect_of {
                        Some(owner) => settle_effect_in(tx, &gid, owner, cap, now)?,
                        None => None,
                    };
                    return Ok(Checked::Refused(gid, intent));
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
            Checked::Refused(gid, intent) => {
                if let Some(intent) = intent {
                    self.process_cleanup_intent(intent, true).await;
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
                        // ⟨M02⟩ U0b row 24: a timed-out call is `SERVICE_UNAVAILABLE`
                        // with effect `partial`, as any error below.
                        bounded_adapter_call(self.adapter_limit(), a.reconcile(&gid, &t)).await
                    };
                    match r {
                        Ok(ReconcileOutcome::Applied(o)) => Some(Facts::from_outcome(&o)),
                        // ⟨M03 wave 4, §17.21 item 1⟩ A managed preparation's key lives
                        // in the process that drove it: without its results here (a
                        // restart), the effect cannot be completed. The operation fails
                        // with a cleanup intent (key, instances, binding endpoint and
                        // files), never left running.
                        _ if a.descriptor().identity.mechanism == MANAGED_CERTIFICATE => {
                            let error = OpError::new(
                                Code::ServiceUnavailable,
                                "the managed credential did not survive the runtime restart",
                            )
                            .with_effect(EffectStatus::Partial);
                            if let Some(intent) =
                                self.fail_managed_preparation(&id, error, &gid).await?
                            {
                                self.process_cleanup_intent(intent, true).await;
                            }
                            return Ok(Flow::Stop);
                        }
                        // ⟨M02⟩ ADR-0007 §12.15 item 7 (E-U6-6): an adapter with no
                        // external effect forgets its integrations at a restart; the
                        // confirmed effect is answered from the facts its `Confirmed`
                        // receipt recorded (U0b row 6), never from instance memory.
                        Ok(ReconcileOutcome::NotApplied)
                            if !a.descriptor().external_side_effects
                                && self
                                    .confirmed_from_prepared_facts(&id, &gid)
                                    .await
                                    .is_some() =>
                        {
                            // `Facts::conservative` over the stored facts, in the
                            // commit's own transaction below.
                            None
                        }
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
        // ⟨M02⟩ ADR-0007 §12.27 item 1 (S01): whether the request requires no
        // interaction, from the stored request too (an unreadable one is read as
        // requiring none: fail closed).
        let noninteractive = st
            .request()
            .and_then(|r| WorkSpec::from_request(&r, &env))
            .is_none_or(|s| !s.interactive);
        // ⟨M03 wave 4, §17.21 item 1⟩ A managed binding is committed under the ID minted
        // at resolve (its endpoint and files were materialized under it).
        let binding_id = match &resolved.binding_id {
            Some(b) => b.clone(),
            None => crate::ids::new_binding_id()?,
        };
        // ⟨§17.21 item 1⟩ The binding endpoint this drive's managed preparation named
        // (`consumer.signing_endpoint`; the stored history keeps none). `None` for
        // every M01/M02 adapter, whose results are unchanged.
        let signing_endpoint = local
            .prepared
            .as_ref()
            .and_then(|o| o.integration.signing_endpoint.clone())
            .filter(|_| !attached);
        let managed = resolved
            .adapter
            .as_ref()
            .is_some_and(|a| a.mechanism == MANAGED_CERTIFICATE);
        // ⟨M03 wave 4, §17.22 item 6 (W4-R03)⟩ A coalesced or decision-joined follower of
        // a managed grant gets its own binding materialized against the existing grant
        // and key before its commit, or is refused at it: never `ACCESS_READY` for an
        // unmaterialized binding.
        let follower = if attached && managed {
            Some(self.materialize_follower(&id, &gid, &binding_id).await)
        } else {
            None
        };
        let (follower_endpoint, follower_refusal) = match follower {
            Some(Ok(endpoint)) => (Some(endpoint), None),
            Some(Err(e)) => (None, Some(e)),
            None => (None, None),
        };
        // ⟨M03 wave 4, round 5 (W4-C02); §17.22 item 7, §17.23 item 1⟩ Every newly
        // committed managed follower's scope claim is its own, from evidence read now
        // (the grant's pairs, the current client and target evaluation, the installed
        // certificates' CAs), never the leader's historical result: it replaces the
        // `destination_scope` of the facts below, before the minimums are checked.
        let follower_scope = if attached && managed {
            Some(self.follower_scope(&gid, resolved.adapter.as_ref()).await?)
        } else {
            None
        };
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
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
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
                // ⟨M02⟩ U0b rows 4 and 5: without this drive's facts, the grant's
                // stored history; then fresh eligibility in this transaction.
                let mut facts = match facts {
                    Some(f) => f,
                    None => Facts::conservative(&g, tx.grant_prepared_facts(&gid)?.as_ref(), now),
                }
                .with_eligibility(tx, now)?;
                // ⟨W4-C02⟩ A managed follower reports, and is held to its minimum by, its
                // own claim at this commit's time.
                if let Some(scope) = &follower_scope {
                    facts.enforcement.destination_scope = scope.claim(now);
                }
                // ⟨§17.22 item 6⟩ A follower whose own binding could not be
                // materialized is refused here, on the attached refusal path (no grant
                // event: the grant is not its own).
                let follower_refused = follower_refusal.map(|e| Refusal::new(e, None));
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
                            Admission::Open => {
                                // ⟨M02⟩ ADR-0007 §12.27 item 1 (S01): a request that
                                // requires no interaction holds against the store's
                                // fresh eligibility, in this transaction, before the
                                // grant is activated or its binding created.
                                let ineligible = if noninteractive {
                                    noninteractive_commit_refusal(
                                        tx,
                                        &facts.integration.pairs,
                                        &mechanism,
                                        now,
                                    )?
                                } else {
                                    None
                                };
                                ineligible
                                    .or_else(|| unmet_minimum(&required, &facts, &g, bound))
                                    .map(|e| Refusal::new(e, Some(GrantEvent::PreparationFailed)))
                            }
                        }
                    }
                };
                let refusal = follower_refused.or(refusal);
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
                    // ⟨r2.16⟩ ADR-0006 §13.19 item 2 (as at `Recheck`).
                    let effect_of = match orphan {
                        Some(owner) => Some(owner),
                        None => (!attached).then(|| id.clone()),
                    };
                    let intent = match &effect_of {
                        Some(owner) => settle_effect_in(tx, &gid, owner, cap, now)?,
                        None => None,
                    };
                    return Ok(Checked::Refused(gid, intent));
                }
                if g.state == GrantState::Preparing {
                    grant_to(&mut g, GrantEvent::Prepared)?;
                    g.enforcement = EnforcementEvidence {
                        report: facts.enforcement.clone(),
                        evidence: Vec::new(),
                    };
                    put_grant(tx, emit, &g, Some(&id))?;
                }
                // ⟨M03 wave 4, §17.22 items 6 and 8⟩ The commit retires the managed
                // cleanup intent of this operation (its attempt's, or a follower's
                // binding's): the grant's lifecycle owns the credential from here.
                if managed {
                    tx.clear_cleanup_intent(&gid, &id)?;
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
                let mut data = ensure_data(&binding, &g, &facts, bound);
                if signing_endpoint.is_some() {
                    data.consumer.signing_endpoint = signing_endpoint;
                }
                // ⟨§17.22 item 6; §17.23 item 6⟩ A follower's result names its own
                // binding endpoint: the one its materialization created.
                if let Some(endpoint) = &follower_endpoint {
                    managed_driver_m03::name_follower_endpoint(&mut data.consumer, endpoint);
                }
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
            Checked::Refused(gid, intent) => {
                if let Some(intent) = intent {
                    self.process_cleanup_intent(intent, true).await;
                }
                // ⟨§17.22 item 6⟩ A refused follower's own binding (materialized or
                // not) is cleared through its intent.
                if attached && managed {
                    self.process_cleanup_intent_of(&gid, &st.op.id).await;
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
    ///
    /// ⟨M02⟩ U0b row 23, with the preserve list's order unchanged: `allow_new` is
    /// captured before the transaction; inside it the key is classified, any outcome
    /// but `New` returns at once, the backpressure test runs next, and only then is
    /// anything inserted. With `exclusive`, the insertion is
    /// `Txn::insert_setup_operation` in this same transaction (the setup check and
    /// the insert are atomic, ADR-0007 §5.7 "Admission is atomic"); a blocker writes
    /// nothing and answers `CONFIG_CONFLICT`, reason `setup_in_progress`. Replays and
    /// conflicts are classified first, so they never see the check. `pipeline` keeps
    /// its meaning: the `Authenticate` receipt is written only with it.
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
        exclusive: Option<SetupAdmission>,
    ) -> Result<IdempotencyOutcome, OpError> {
        let key_hash = key
            .hash()
            .map_err(|_| internal("the idempotency key cannot be hashed"))?;
        let environment = self.inner.config.environment.clone();
        if let Some(adm) = &exclusive
            && (adm.environment != environment || !kind.is_setup())
        {
            return Err(internal(
                "a setup admission names this runtime's environment and a setup kind",
            ));
        }
        let id = crate::ids::new_operation_id()?;
        let new_id = id.clone();
        let allow_new = self.inner.running.load(Ordering::SeqCst)
            < self.inner.config.limits.max_running_operations;
        let inserts = Arc::clone(&self.inner.setup_inserts);
        let outcome = self
            .write(move |tx, emit| {
                let record = tx.idempotency_record(&key)?;
                // R7: the marker is returned whatever its age; `classify` compares
                // `marker_until` with `now`.
                let marker = tx.expired_key_marker(&key_hash)?;
                let outcome = classify(record.as_ref(), marker.as_ref(), hash, now);
                if outcome != IdempotencyOutcome::New {
                    return Ok(Admitted::Outcome(outcome));
                }
                if !allow_new {
                    return Ok(Admitted::Backpressure);
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
                match exclusive {
                    Some(adm) => {
                        let intent = RecoveryIntent {
                            request,
                            resolved: None,
                            local: Some(adm.intent),
                        };
                        inserts.fetch_add(1, Ordering::SeqCst);
                        if let SetupAdmitted::InProgress(blocking) = tx.insert_setup_operation(
                            &op,
                            &idem,
                            &intent,
                            adm.repair_target.as_ref(),
                        )? {
                            return Ok(Admitted::InProgress(blocking));
                        }
                    }
                    None => {
                        tx.insert_operation(&op, &idem)?;
                        tx.set_recovery_intent(
                            &id,
                            &RecoveryIntent {
                                request,
                                resolved: None,
                                local: None,
                            },
                        )?;
                    }
                }
                if pipeline {
                    tx.append_stage_receipt(
                        &id,
                        &receipt(EnsureStage::Authenticate, now, EffectReceipt::NotAttempted),
                    )?;
                }
                emit.op(tx, &op)?;
                Ok(Admitted::Outcome(IdempotencyOutcome::New))
            })
            .await?;
        match outcome {
            Admitted::Outcome(IdempotencyOutcome::New) => Ok(IdempotencyOutcome::Replay(new_id)),
            Admitted::Outcome(other) => Ok(other),
            Admitted::Backpressure => Err(OpError::new(
                Code::Backpressure,
                "too many operations are running",
            )
            .with_retry_after(BACKPRESSURE_RETRY_MS)),
            Admitted::InProgress(blocking) => Err(setup_in_progress(&blocking)),
        }
    }

    /// Test hook for U0b row 23 (`u0b_admit_keeps_backpressure_order`): the
    /// admission step alone, with the caller's key, a precomputed hash and an
    /// optional setup admission. Not part of the supported API; requests reach
    /// admission through the setup and catalog entry points (U5).
    ///
    /// # Errors
    /// As [`Operations::admit`]: `BACKPRESSURE`, `CONFIG_CONFLICT`
    /// (`setup_in_progress`), or a store failure.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub async fn admit_for_test(
        &self,
        caller: &Caller,
        kind: OperationKind,
        request_id: heimdall_contract::ids::RequestId,
        hash: heimdall_contract::canonical::RequestHash,
        request: serde_json::Value,
        pipeline: bool,
        exclusive: Option<SetupAdmission>,
    ) -> Result<IdempotencyOutcome, OpError> {
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind,
            request_id,
        };
        let effect_class = kind
            .m02_effect_class()
            .unwrap_or(EffectClass::LocalResources);
        let now = self.inner.config.clock.wall();
        self.admit(
            key,
            hash,
            kind,
            effect_class,
            request,
            now,
            pipeline,
            exclusive,
        )
        .await
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
                None,
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
            Ok(dtime::TimeStatus::Uncertain(u)) => {
                warnings.push(Warning {
                    code: "TIME_UNCERTAIN".to_owned(),
                    message: "safe time cannot be established; activation is stopped".to_owned(),
                    reason: time_warning_reason(&u).map(str::to_owned),
                });
                self.inner.config.clock.wall()
            }
            Err(e) => return Err(e),
        };
        let ctx = caller.context.clone();
        let environment = self.inner.config.environment.clone();
        let capabilities = matches!(req.subject, InspectSubject::Capabilities);
        let mut data =
            match req.subject {
                // ⟨M02⟩ U0b row 19, phase 2: the same set as
                // `heimdall_ipc::session::server_capabilities()`, `setup/1` included.
                // ⟨M03⟩ U0b row 13, phase 2 (wave 4): and the four M03 capabilities.
                InspectSubject::Capabilities => serde_json::json!({
                    "capabilities": [
                        heimdall_contract::ipc::capability::OPERATIONS_V1,
                        heimdall_contract::ipc::capability::EVENTS_V1,
                        heimdall_contract::ipc::capability::OWNER_POLICY_V1,
                        heimdall_contract::ipc::capability::SCHEMA_DISCOVERY_V1,
                        heimdall_contract::ipc::capability::SERVICE_CONTROL_V1,
                        heimdall_contract::ipc::capability::SETUP_V1,
                        heimdall_contract::ipc::capability::ISSUER_V1,
                        heimdall_contract::ipc::capability::ENROLLMENT_V1,
                        heimdall_contract::ipc::capability::MANAGED_CREDENTIALS_V1,
                        heimdall_contract::ipc::capability::CONNECTIONS_V1,
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
                // ⟨M02⟩ ADR-0007 §12.24 item 1: the catalog's destinations, each with its
                // alias and its definition (`managed`, with the rendered fields, or
                // `observed`), read in one transaction, under the `items` key this subject
                // always answered with. Owner role only, like the other catalog subjects
                // (identities, projections, decisions).
                InspectSubject::Destinations => {
                    if !ctx.is_owner() {
                        serde_json::json!({ "items": [] })
                    } else {
                        self.destinations_view(environment.clone()).await?
                    }
                }
                // ⟨M02⟩ ADR-0007 §12.24 item 1 (profiles): the catalog's current profile
                // definitions, read in one transaction, under `items`. Owner role only, as
                // for destinations.
                InspectSubject::Profiles => {
                    if !ctx.is_owner() {
                        serde_json::json!({ "items": [] })
                    } else {
                        self.write(move |tx, _| {
                            let items: Vec<serde_json::Value> = tx
                                .profiles()?
                                .iter()
                                .map(|p| {
                                    serde_json::json!({
                                        "profile_id": p.id,
                                        "revision": p.revision,
                                        "label": p.label,
                                        "pairs": p.scope.pairs,
                                        "capabilities": p.scope.capabilities,
                                    })
                                })
                                .collect();
                            Ok(serde_json::json!({ "items": items }))
                        })
                        .await?
                    }
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
                        // ⟨r2.12⟩ §13.15 item 2: every record covering a grant counts.
                        let mut remote: BTreeMap<GrantId, RemoteView> = BTreeMap::new();
                        for r in tx.remote_revocations()? {
                            for g in &r.grants {
                                let view = RemoteView::of(&r, g);
                                let view = match remote.remove(g) {
                                    Some(seen) => seen.combine(view),
                                    None => view,
                                };
                                remote.insert(g.clone(), view);
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
                        // ⟨r2.17⟩ ADR-0006 §13.20 item 1: a grant whose applied effect still
                        // waits on a cleanup intent (§13.19 item 2) stays visible, ended or
                        // not (spec §12.3: a pending remote revocation remains visible).
                        let cleanup_pending: std::collections::BTreeSet<GrantId> =
                            tx.cleanup_intents()?.into_iter().map(|i| i.grant).collect();
                        for gid in &cleanup_pending {
                            if remote.contains_key(gid) {
                                continue;
                            }
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
                                        // ⟨r2.12⟩ §13.15 item 2 / §13.16 item 1: every
                                        // reason present, always as an array (one
                                        // stable shape, whatever the reason count).
                                        if !r.reasons.is_empty() {
                                            map.insert(
                                                "remote_pending_reasons".to_owned(),
                                                serde_json::to_value(&r.reasons)?,
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
                                    if cleanup_pending.contains(&g.id) {
                                        map.insert(
                                            "cleanup_pending".to_owned(),
                                            serde_json::json!(true),
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
                // ⟨M02⟩ U0b row 21: the catalog's identities, each with its fresh
                // eligibility (row 5; ADR-0007 §7) and its live declaration, read in one
                // transaction. Owner role only, like decisions (reading; escalated).
                InspectSubject::Identities => {
                    if !ctx.is_owner() {
                        serde_json::json!({ "identities": [] })
                    } else {
                        self.write(move |tx, _| {
                            let mut items = Vec::new();
                            for identity in tx.identities()? {
                                items.push(identity_view(tx, &identity, now)?);
                            }
                            Ok(serde_json::json!({ "identities": items }))
                        })
                        .await?
                    }
                }
                // ⟨M02⟩ U0b row 21: this environment's projection resources and record,
                // read-only. Empty until a projection is committed.
                InspectSubject::Projections => {
                    if !ctx.is_owner() {
                        serde_json::json!({ "projections": [], "record": null })
                    } else {
                        self.write(move |tx, _| {
                            let resources = tx.projection_resources(&environment)?;
                            let record = tx.projection_record(&environment)?;
                            Ok(serde_json::json!({
                                "projections": resources,
                                "record": record,
                            }))
                        })
                        .await?
                    }
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
                // ⟨M03⟩ wave 4 (U10): `inspect enrollments` (owner only, like decisions:
                // the records name hosts and accounts) and `inspect issuer` (the
                // `issuer.status` view). `inspect connections` has no reader yet (no store
                // index lists every owned connection, U7-Q4): fail closed.
                InspectSubject::Enrollments => {
                    if !ctx.is_owner() {
                        serde_json::json!({ "enrollments": [] })
                    } else {
                        let view = self
                            .write(move |tx, _| enrollment_m03::enrollments_view_in(tx))
                            .await?;
                        serde_json::to_value(view).map_err(|_| {
                            OpError::new(Code::InternalError, "enrollments could not be rendered")
                        })?
                    }
                }
                InspectSubject::Issuer => {
                    self.issuer_request(caller, heimdall_contract::issuer::IssuerRequest::Status)
                        .await?
                        .data
                }
                // ⟨M03⟩ wave 4, round 2 (ADR-0008 §17.21 item 11; §5 item 4): `inspect
                // connections`, read-only over the owned-connection rows, owner only like
                // decisions (rows name bindings, grants and destinations). Only live rows
                // (`up`, `closing`) are listed; PIDs, start tokens, images and control paths
                // never leave the process. Per row: the destination (a master's from its
                // stable mux path `<runtime_dir>/mux/<destination-id>`, else the binding's
                // first destination; a row whose binding is unknown is not listed), the
                // grant's effective connection policy (D8 item 1's merge: its origin and
                // every current applicable policy; no origin: `strict`/`disabled`, fail
                // closed), and `closes_at`: the grant's bound for a master (closed at the
                // deadline under both policies, D8 item 3) or under `strict`, `null` for a
                // dedicated connection under `graceful`.
                InspectSubject::Connections => {
                    use heimdall_contract::managed::{
                        ConnectionEntry, ConnectionKind, ConnectionPolicy, ConnectionState,
                        ConnectionsView, ExistingConnectionsMode, MultiplexingMode,
                    };
                    use heimdall_domain::managed::OwnedConnectionState;
                    if !ctx.is_owner() {
                        serde_json::json!({ "connections": [] })
                    } else {
                        let env = self.inner.config.environment.clone();
                        let view = self
                        .write(move |tx, _| {
                            let mut connections = Vec::new();
                            for c in tx.owned_connections()? {
                                let state = match c.state {
                                    OwnedConnectionState::Up => ConnectionState::Up,
                                    OwnedConnectionState::Closing => ConnectionState::Closing,
                                    _ => continue,
                                };
                                let Some(binding) = tx.binding(&c.binding)? else {
                                    continue;
                                };
                                let from_mux = c
                                    .control_path
                                    .as_deref()
                                    .filter(|_| c.kind == ConnectionKind::Master)
                                    .and_then(|p| std::path::Path::new(p).file_name())
                                    .and_then(|n| n.to_str())
                                    .and_then(|n| DestinationId::parse(n).ok())
                                    .filter(|d| {
                                        binding.scope.pairs.iter().any(|p| &p.destination == d)
                                    });
                                let Some(destination_id) = from_mux.or_else(|| {
                                    binding.scope.pairs.iter().next().map(|p| p.destination.clone())
                                }) else {
                                    continue;
                                };
                                let grant = tx.grant(&c.grant)?;
                                let origin = tx.grant_origin(&c.grant)?;
                                let policy = match (&grant, &origin) {
                                    (Some(g), Some(o)) => {
                                        let current: Vec<ConnectionPolicy> = tx
                                            .policies_for(&o.profile, &g.environment)?
                                            .iter()
                                            .map(|p| p.connection)
                                            .collect();
                                        heimdall_domain::connection::effective_connection_policy(
                                            o.connection,
                                            &current,
                                            None,
                                        )
                                    }
                                    _ => ConnectionPolicy {
                                        existing: ExistingConnectionsMode::Strict,
                                        multiplexing: MultiplexingMode::Disabled,
                                    },
                                };
                                let closes = c.kind == ConnectionKind::Master
                                    || policy.existing == ExistingConnectionsMode::Strict;
                                let closes_at = match (&grant, closes) {
                                    (Some(g), true) => {
                                        let profile = origin.as_ref().map(|o| &o.profile);
                                        Some(bound_of(tx, &env, g, profile)?)
                                    }
                                    _ => None,
                                };
                                connections.push(ConnectionEntry {
                                    id: c.id,
                                    kind: c.kind,
                                    binding_id: c.binding,
                                    grant_id: c.grant,
                                    destination_id,
                                    started_at: c.started_at,
                                    policy,
                                    closes_at,
                                    state,
                                });
                            }
                            Ok(ConnectionsView { connections })
                        })
                        .await?;
                        serde_json::to_value(view).map_err(|_| {
                            OpError::new(Code::InternalError, "connections could not be rendered")
                        })?
                    }
                }
            };
        if let Some(preview) = req.preview {
            let p = self.preview(caller, preview, now).await?;
            if let serde_json::Value::Object(map) = &mut data {
                map.insert("preview".to_owned(), p);
            }
        }
        let mut done = Completed {
            warnings,
            ..Completed::ok(Code::Ok, data)
        };
        // ⟨M03 wave 5⟩ U9-Q3 (a): `inspect capabilities` carries the current lock
        // behaviour's `signal_unverified` (ADR-0008 D9 items 1 and 3).
        if capabilities {
            self.add_capabilities_lock(&mut done.data).await;
            self.label_capabilities_lock(&mut done).await;
        }
        Ok(done)
    }

    /// `inspect destinations` (owner role): every catalog destination
    /// ([`destination_view`]), read in one transaction. ⟨M03; ADR-0008 §17.25 item 19⟩ A
    /// `managed_certificate` preference covered by a standing policy also carries
    /// `preference.connection_policy` from the runtime's wording source, computed after
    /// the transaction (it reads the alias's static observation).
    async fn destinations_view(&self, env: EnvironmentId) -> Result<serde_json::Value, OpError> {
        type Pending = Vec<(usize, String, heimdall_contract::managed::ConnectionPolicy)>;
        let (mut items, pending) = self
            .write(move |tx, _| {
                let mut items: Vec<serde_json::Value> = Vec::new();
                let mut pending: Pending = Vec::new();
                for d in tx.destinations()? {
                    // ⟨M03⟩ U8-Q6: the managed definition's pair preference.
                    let pair = match &d.definition {
                        DestinationDefinition::Managed { account, .. } => {
                            Some(heimdall_domain::scope::AccessPair {
                                destination: d.id.clone(),
                                account: account.clone(),
                            })
                        }
                        DestinationDefinition::Observed => None,
                    };
                    let preference = match &pair {
                        Some(p) => tx.pair_preference(p)?,
                        None => None,
                    };
                    let managed = preference.as_ref().is_some_and(|p| {
                        p.mechanism
                            == heimdall_contract::managed::PreferredMechanism::ManagedCertificate
                    });
                    if let Some(p) = pair.as_ref().filter(|_| managed)
                        && let Some(policy) =
                            lock_connection_m03::pair_connection_policy(tx, &env, p)?
                    {
                        pending.push((items.len(), d.alias.clone(), policy));
                    }
                    items.push(destination_view(&d, preference.as_ref()));
                }
                Ok((items, pending))
            })
            .await?;
        self.add_connection_policies(&mut items, pending).await;
        Ok(serde_json::json!({ "items": items }))
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
            lock_floor: self.session_lock_floor(),
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
        // ⟨M03⟩ U0b row 9 (O): `connection: graceful` and a pair resolving to
        // `managed_certificate` (wave 0) are refused before any record is written.
        let precheck = self.ensure_precheck(&req).await?;
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
                // ⟨M03⟩ U0b row 9 (O): `connection` only when present.
                extra: pair_mechanism_m03::ensure_hash_extra(&req),
            },
        )
        .map_err(|_| OpError::new(Code::UsageError, "the request cannot be canonicalized"))?;
        let request_id = req.request_id.clone();
        let wait = req.wait;
        let r = self
            .run_work(
                caller,
                OperationKind::Ensure,
                Request::Ensure(req),
                hash,
                request_id,
                wait,
            )
            .await;
        // ⟨M03 wave 5⟩ U9-Q3 (a): a `revoke_on_lock` grant over an unverified signal
        // carries `signal_unverified` (ADR-0008 D9 item 3).
        let mut r = precheck.decorate(r);
        if let Ok(done) = &mut r {
            let grant = done.data.grant_id.clone();
            self.label_grant_lock(done, &grant).await;
        }
        r
    }

    /// `bind` (materialize only in M01; launch is the CLI's job after ensure).
    /// Authorized by binding ownership or owner role.
    pub async fn bind(&self, caller: &Caller, req: BindRequest) -> OpResult<EnsureData> {
        // ⟨M02⟩ U0b row 3 (m02-plan §5 items 5 and 16): a launch binding names an
        // absolute executable and, optionally, its holder process; `argv` never
        // crosses IPC. The holder is delivery metadata and stays out of the hash, so
        // the same request ID with another holder replays. Materialize hashes as in
        // M01, so a key stored by M01 still replays.
        let form_hashed = match &req.form {
            BindForm::Launch(launch) => {
                if let Err(e) = launch.validate() {
                    return Err(OpError::new(Code::UsageError, e.to_string()));
                }
                serde_json::json!({ "form": "launch", "executable": launch.executable })
            }
            other => serde_json::to_value(other).map_err(|_| {
                OpError::new(Code::UsageError, "the request cannot be canonicalized")
            })?,
        };
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
                extra: serde_json::json!({ "binding_id": req.binding_id, "form": form_hashed }),
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
        // ⟨M02⟩ ADR-0007 §12.25 item 4 (T04): this request's holder, which a replay
        // does not store (the holder is not hashed), so the replayed launch is
        // checked against the binding's holder below.
        let launch_holder = match &req.form {
            BindForm::Launch(launch) => Some(launch.holder.clone()),
            BindForm::Materialize => None,
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
                None,
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
        if let Some(holder) = launch_holder {
            self.claim_replayed_launch(&done.data.binding_id, holder, &id)
                .await?;
        }
        let grant = done.data.grant_id.clone();
        let mut done = Completed {
            next: Some(NextAction {
                action: "use_binding".to_owned(),
                binding_id: Some(done.data.binding_id.clone()),
                ..NextAction::default()
            }),
            ..done
        };
        // ⟨M03 wave 5⟩ U9-Q3 (a), as for `ensure`.
        self.label_grant_lock(&mut done, &grant).await;
        Ok(done)
    }

    /// ⟨M02⟩ ADR-0007 §12.25 item 4 (T04): a settled launch `bind` names this
    /// request's `holder` as the binding's one live holder, in one transaction with
    /// the check ([`claim_launch_holder`]). A replay with the same request ID (the
    /// holder is not hashed, so another process replays the stored result) is refused
    /// with `REQUEST_CONFLICT`, reason `binding_in_use`, while another holder holds the
    /// binding; that holder is kept. A binding that is no longer active is left to
    /// `run`'s active re-check (§12.24 item 2, §12.26 item 3): nothing is registered on
    /// it and the stored result is returned unchanged.
    async fn claim_replayed_launch(
        &self,
        binding: &BindingId,
        holder: Option<heimdall_domain::holder::ProcessHolder>,
        operation: &OperationId,
    ) -> Result<(), OpError> {
        let bid = binding.clone();
        // ⟨M03⟩ U0b row 19 (O): a replayed launch that claims its holder registers its
        // `dedicated` owned connection in the same transaction, as a new one does.
        let now = self.inner.config.clock.wall();
        let op_id = operation.clone();
        let claimed = self
            .write(move |tx, _| match tx.binding(&bid)? {
                Some(b) if b.state == BindingState::Active => {
                    let claimed = claim_launch_holder(tx, &bid, holder.as_ref())?;
                    if claimed
                        && let Some(executable) =
                            bind_connection_m03::stored_launch_executable(tx, &op_id)?
                    {
                        bind_connection_m03::register_at_bind(
                            tx,
                            &b,
                            &executable,
                            holder.as_ref(),
                            now,
                        )?;
                    }
                    Ok(claimed)
                }
                _ => Ok(true),
            })
            .await?;
        if claimed {
            Ok(())
        } else {
            Err(binding_in_use(binding).with_operation(operation.clone()))
        }
    }

    async fn drive_bind(&self, id: &OperationId) -> Result<(), OpError> {
        // ⟨M03 wave 4, §17.21 item 2⟩ A launch of a managed binding: the first pass
        // claims every pair's slot (store CAS) and stops; the slot files and the
        // listing are written; the second pass settles the bind.
        if let Some(binding) = self.drive_bind_pass(id, false).await? {
            if let Err(e) = self.write_bind_slots_managed(&binding).await {
                return self.fail_managed_bind(id, e).await;
            }
            self.drive_bind_pass(id, true).await?;
        }
        Ok(())
    }

    /// One settling pass of `drive_bind`. `Some(binding)`: the slots of the managed
    /// `binding` were claimed in this pass and the bind waits for their files
    /// (`slots_ready` false only).
    async fn drive_bind_pass(
        &self,
        id: &OperationId,
        slots_ready: bool,
    ) -> Result<Option<BindingId>, OpError> {
        let st = self.load_work(id).await?;
        if st.op.state.is_quiescent() {
            return Ok(None);
        }
        let claimed: Arc<Mutex<Option<BindingId>>> = Arc::default();
        let claimed_in = Arc::clone(&claimed);
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
                *claimed_in.lock().unwrap_or_else(PoisonError::into_inner) = None;
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
                    // ⟨M02⟩ ADR-0007 §12.26 item 3(a): a released binding names its
                    // reason.
                    return fail(
                        tx,
                        emit,
                        &mut op,
                        OpError::new(Code::CredentialExpired, "the binding was released")
                            .with_reason(heimdall_contract::envelope::reason::BINDING_RELEASED)
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
                    binding_id: None,
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
                // ⟨M03 wave 4, §17.21 item 2⟩ A launch of a managed binding claims each
                // pair's environment slot (store CAS) before anything else is written;
                // a slot that cannot be claimed refuses the bind with its reason.
                if !slots_ready
                    && matches!(req.form, BindForm::Launch(_))
                    && b.mechanism == MANAGED_CERTIFICATE
                {
                    return match managed_driver_m03::claim_bind_slots_in(tx, &env, &b, now)? {
                        Err(e) => fail(tx, emit, &mut op, e),
                        Ok(()) => {
                            *claimed_in.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some(b.id.clone());
                            Ok((Ok(()), none()))
                        }
                    };
                }
                let bound = bound_of(tx, &env, &g, Some(&b.profile))?;
                // ⟨M02⟩ U0b rows 4 and 5: the grant's stored history, then fresh
                // eligibility, in this settling transaction.
                let facts = Facts::conservative(&g, tx.grant_prepared_facts(&g.id)?.as_ref(), now)
                    .with_eligibility(tx, now)?;
                let data = ensure_data(&b, &g, &facts, bound);
                let value = serde_json::to_value(&data)?;
                // ⟨M02⟩ U0b row 4: the launch binding's holder, when given. ADR-0007
                // §12.25 item 4 (T04): checked and registered in this settling
                // transaction; a binding another live holder holds is refused and
                // that holder is kept.
                if let BindForm::Launch(launch) = &req.form
                    && !claim_launch_holder(tx, &b.id, launch.holder.as_ref())?
                {
                    return fail(tx, emit, &mut op, binding_in_use(&b.id));
                }
                // ⟨M03⟩ U0b row 19 (O): Unix, the verified client: the `dedicated`
                // owned connection, in this transaction, with the expected image.
                if let BindForm::Launch(launch) = &req.form {
                    bind_connection_m03::register_at_bind(
                        tx,
                        &b,
                        &launch.executable,
                        launch.holder.as_ref(),
                        now,
                    )?;
                }
                settle_succeeded(tx, emit, &mut op, Code::AccessReady, value, now, retention)
                    .map(|()| (Ok(()), none()))
            })
            .await?;
        self.complete_withdrawals(ended).await;
        r?;
        Ok(claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take())
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
        let mut r = self
            .run_work(
                caller,
                OperationKind::Delegate,
                Request::Delegate(req),
                hash,
                request_id,
                WaitMode::default(),
            )
            .await;
        // ⟨M03 wave 5⟩ U9-Q3 (a), as for `ensure`.
        if let Ok(done) = &mut r {
            let grant = done.data.grant_id.clone();
            self.label_grant_lock(done, &grant).await;
        }
        r
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
        let cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let (op, intent) = self
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
                    return Ok(Some(Ok((op, None))));
                }
                // ⟨M03⟩ wave-0 E10 (O), ⟨wave 4⟩ U10: an open enrollment operation is
                // cancelled by the enrollment driver's rule (`enrollment_cancel_m03::
                // cancel_in`): refused, writing nothing, once a remote mutation's
                // `Attempted` receipt exists or a step is outstanding; before that,
                // cancelled (`planned → withdrawn`, `applying → failed_unwritten`, the
                // pending decision withdrawn).
                if op.kind.is_enrollment() {
                    return enrollment_cancel_m03::cancel_in(tx, emit, op, now, retention).map(Some);
                }
                // ⟨M02⟩ ADR-0007 §12.14 item 3 (E1), phase 2: a setup or catalog
                // operation is cancelled only before its first commit point (§5.4);
                // after it, the answer is `OUTCOME_UNKNOWN` with `next: reconcile`
                // and nothing is written ([`cancel_local_in`]).
                if op.kind.is_setup() || op.kind == OperationKind::Catalog {
                    return cancel_local_in(tx, emit, op, now, retention).map(Some);
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
                            cleanup = Some((gid, id.clone()));
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
                    && let Some(owner) = end_orphaned_in(tx, emit, gid, &id)?
                {
                    cleanup = Some((gid.clone(), owner));
                }
                // ⟨r2.16⟩ ADR-0006 §13.19 item 2: the credential's cleanup is decided
                // in the cancellation's transaction.
                let intent = match &cleanup {
                    Some((gid, effect_of)) => settle_effect_in(tx, gid, effect_of, cap, now)?,
                    None => None,
                };
                Ok(Some(Ok((op, intent))))
            })
            .await?
            .ok_or_else(|| {
                OpError::new(Code::NotFound, "unknown operation").with_resource("operation", None)
            })??;
        if let Some(intent) = intent {
            self.process_cleanup_intent(intent, true).await;
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
        self.release_checked(caller, req, None).await
    }

    /// ⟨M02⟩ `release`, done only while the binding is active and its holder row still
    /// names exactly `holder`, checked in the release's own transaction (m02-plan U8,
    /// the holder pass). A binding whose holder was replaced, or that is no longer
    /// active, is left alone: the answer then has `"outcome": null`. Nothing else
    /// differs from [`release`](Self::release).
    pub(crate) async fn release_if_held_by(
        &self,
        caller: &Caller,
        req: ReleaseRequest,
        holder: heimdall_domain::holder::ProcessHolder,
    ) -> OpResult<serde_json::Value> {
        self.release_checked(caller, req, Some(holder)).await
    }

    async fn release_checked(
        &self,
        caller: &Caller,
        req: ReleaseRequest,
        holder: Option<heimdall_domain::holder::ProcessHolder>,
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
                if let Some(expected) = &holder
                    && (binding.state != heimdall_domain::binding::BindingState::Active
                        || tx.binding_holder(&bid)?.as_ref() != Some(expected))
                {
                    return Ok(Ok((
                        serde_json::json!({
                            "binding_id": bid,
                            "outcome": null,
                        }),
                        false,
                    )));
                }
                // ⟨M03⟩ U0b row 19 (O): the holder pass observed this exact holder
                // exit (or its exec fail): its `dedicated` owned connection closes.
                if let Some(exited) = &holder {
                    bind_connection_m03::close_on_exit(tx, &bid, exited)?;
                }
                let outcome = tx.release_binding(&bid, &ctx, now)?;
                let mut grant_state = None;
                // ⟨§17.22 item 10 (W4-R08); D10 item 2⟩ A managed binding released now:
                // each slot it holds moves to `clearing` in this transaction, even while
                // its grant lives on through another reference.
                let slots_cleared = matches!(outcome, ReleaseOutcome::Released { .. })
                    && managed_driver_m03::release_binding_slots_in(tx, &binding, now)?;
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
                Ok(Ok((
                    serde_json::json!({
                        "binding_id": bid,
                        "outcome": outcome,
                        "grant_id": binding.grant,
                        "grant_state": grant_state,
                    }),
                    slots_cleared,
                )))
            })
            .await?;
        let (value, managed_released) = r?;
        // ⟨§17.22 item 10 (W4-R08)⟩ The released managed binding's endpoint, listing
        // and files go now, after the commit; its slots' files follow in the
        // supervisor's ended-binding pass (the `clearing` row is the obligation). K_env
        // is destroyed only with the last reference (below).
        if managed_released {
            self.after_binding_release_m03(&req.binding_id).await;
        }
        // ⟨M03⟩ wave 4 (U10-C; ADR-0008 D7 item 7): the release of a managed grant's
        // last reference destroys K_env, removes its files and closes its owned
        // connections (masters; dedicated ones by the policy), after the commit and
        // outside every gate. No tombstone, no cascade.
        if value.get("grant_state").and_then(serde_json::Value::as_str) == Some("released")
            && let Some(gid) = value
                .get("grant_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|g| GrantId::parse(g).ok())
        {
            self.after_release_m03(&gid, now).await;
        }
        Ok(Completed::ok(Code::Ok, value))
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
                None,
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
        let configured_cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        // Phase 1 (once): tombstone + generation + cascade, before acknowledgment.
        // ⟨r2.9⟩ ADR-0006 §13.12: the same committed transaction claims the first
        // local denial round (an explicit revoke re-arms the bounded schedule,
        // §13.11 item 4), so the adapters are called only by the drive that ran
        // phase 1; a later drive (restart recovery, a same-key retry) never calls
        // them again and completes from the record.
        let id2 = id.clone();
        let root = req.grant_id.clone();
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        // ⟨M03⟩ U0b rows 20 and 27 (G): phase 1 commits through the narrowing protocol
        // (the cascade's gates, exclusively, before the commit); `requested_at` is the
        // admission time stored with the operation, `committed_at` is read inside the
        // tombstone transaction and stored as the tombstone's `revoked_at`.
        let requested_at = st.op.created_at;
        let narrowed = self
            .narrow(
                narrowing::NarrowingKind::Revoke,
                requested_at,
                narrowing::subtree_reader(root.clone()),
                move |tx, emit, ctx| {
                    let Some(mut op) = tx.operation(&id2)? else {
                        return Ok((Vec::new(), None));
                    };
                    let mut all = vec![root.clone()];
                    all.extend(tx.grant_descendants(&root)?);
                    if op.state != OperationState::Queued {
                        return Ok((all, None));
                    }
                    ctx.destroy = all.clone();
                    let tombstone = Tombstone {
                        grant: root.clone(),
                        cascade: all[1..].to_vec(),
                        generation: tx.authority_generation()?,
                        revoked_at: ctx.committed_at,
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
                    let round = claim_first_round_in(
                        tx,
                        &root,
                        &all,
                        &configured,
                        now,
                        true,
                        configured_cap,
                    )?;
                    // ⟨r2.10⟩ §13.13 item 4: the re-armed record's claim (if any) is this
                    // process's; an interrupted one found at startup is superseded.
                    forget_interrupted(&interrupted, &root);
                    op_to(&mut op, OperationEvent::Start, now)?;
                    tx.update_operation(&op)?;
                    emit.op(tx, &op)?;
                    Ok((all, Some(round)))
                },
            )
            .await?;
        let committed_here = narrowed
            .value
            .1
            .is_some()
            .then_some(narrowed.report.committed_at);
        let (grants, round) = narrowed.value;
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
            let mut data = complete_round_in(
                tx,
                emit,
                &grants[0],
                &grants,
                round.claim,
                &answers,
                None,
                Some(&id3),
            )?;
            // ⟨M03⟩ wave 4 (U10-C; D7 item 2 steps 5–6, F15): for a cascade with a
            // managed grant, the adapter's per-pair residual rows, every owned
            // connection of the cascade (`up`/`closing` → `closing`, `closed`,
            // `unverified`: `report::owned_connection_reports`' mapping, reproduced
            // here because `app` has no `adapters` edge) and the fixed note.
            managed_driver_m03::fill_revoke_data(
                tx,
                &grants,
                &mut data,
                answers.remote_effects.clone(),
            )?;
            // ⟨M03⟩ U0b row 27 (G): the stored originals; a replay renders this value.
            data.requested_at = Some(op.created_at);
            data.committed_at = match committed_here {
                Some(t) => Some(t),
                None => tx.tombstone(&grants[0])?.map(|t| t.revoked_at),
            };
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
        let limit = self.adapter_limit();
        for call in &round.calls {
            let Some(adapter) = self.adapter(Some(&call.adapter)) else {
                continue;
            };
            // ⟨M02⟩ U0b row 24 (QR17): a timed-out call is unconfirmed; the
            // obligation stays and the claimed round counts.
            let confirmed =
                match bounded_adapter_call(limit, adapter.revoke(&call.grant, now)).await {
                    Ok(o) => {
                        if let Some(t) = o.latest_possible_credential_expiry {
                            out.adapter_expiry = Some(out.adapter_expiry.map_or(t, |e| e.max(t)));
                        }
                        let confirmed = o.remote_pending.is_empty();
                        out.merge_remote_effects(o.remote_effects);
                        confirmed
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
        let mut ended = ended;
        // ⟨M03⟩ U0b row 20 (G; reading E6b): gated withdrawals commit under the gates.
        // An ancestor's withdrawal found under them may defer again (bounded).
        for _ in 0..MAX_ANCESTRY {
            if ended.gated.is_empty() {
                break;
            }
            let gated = std::mem::take(&mut ended.gated);
            let more = self.narrow_withdrawals(gated).await;
            ended.extend(more);
        }
        ended.gated.clear();
        let expired = std::mem::take(&mut ended.expired);
        if ended.is_empty() && expired.is_empty() {
            return;
        }
        for (root, grants) in ended.withdrawn {
            self.complete_withdrawal(root, grants, RevocationCause::AuthorityWithdrawn)
                .await;
        }
        // ⟨§17.22 item 4 (W4-R01)⟩ An expiry found at use (or by the scheduler's
        // re-validation): the managed cleanup, after the commit and every gate.
        if !expired.is_empty() {
            let now = self.narrowing_now().await;
            self.after_end_m03(&expired, now).await;
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
        let configured_cap = self.inner.revocation_cap.load(Ordering::SeqCst);
        let (r, g) = (root.clone(), grants.clone());
        let interrupted = Arc::clone(&self.inner.interrupted_rounds);
        let claimed = self
            .write(move |tx, _| {
                if tx.remote_revocation(&r)?.is_some() {
                    return Ok(Round::default());
                }
                let round =
                    claim_first_round_in(tx, &r, &g, &configured, now, false, configured_cap)?;
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

    /// ⟨r2.14⟩ ADR-0006 §13.17 item 1: the per-obligation cap of revocation rounds
    /// the supervisor's single retry owner applies (`Backoff::max_attempts`). A
    /// covering obligation below it and not stopped is live, so a cleanup leaves the
    /// call to the rounds; one at it is re-armed. The supervisor sets it when it is
    /// built, and every [`Self::retry_remote_revocation`] call sets it again.
    ///
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: a record created or re-armed stores the cap in
    /// force (this one), and every record is judged by the lower of its stored cap
    /// and this one ([`PendingRemoteRevocation::round_cap`]). Until the supervisor
    /// sets it (restart recovery runs inside [`Self::start`]) no cap is configured,
    /// so recovery judges each record by its stored cap alone (a record written
    /// before the field: [`DEFAULT_ROUND_CAP`]) and never by a default.
    pub fn set_revocation_cap(&self, max_attempts: u32) {
        self.inner
            .revocation_cap
            .store(max_attempts, Ordering::SeqCst);
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
    /// meanwhile (an explicit revoke re-arms it) keeps its own count and claim;
    /// ⟨r2.16⟩ the superseded round's confirmations clear nothing (ADR-0006 §13.19
    /// item 1).
    pub async fn retry_remote_revocation(
        &self,
        root: &GrantId,
        max_attempts: u32,
    ) -> Result<Option<PendingRemoteRevocation>, OpError> {
        // ⟨r2.14⟩ ADR-0006 §13.17 item 1: the cap the rounds apply is the one that
        // decides whether a covering obligation is still live.
        self.set_revocation_cap(max_attempts);
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
        // ⟨M03⟩ U0b row 11 (O): `revoke_on_lock` without a usable lock signal is refused
        // before anything is written (`lock_connection_m03`; ADR-0008 D9 item 3).
        if let Some(e) = self.policy_refusal_m03(&req) {
            return Err(e);
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
        // ⟨M03⟩ U0b rows 20 and 27 (G; reading E6c): a cutoff commits through the
        // narrowing protocol, its set the grants whose bound it lowers.
        let requested_at = self.inner.config.clock.wall();
        let r = self
            .policy_commit(&req, requested_at, move |tx, emit| {
                let assessed = gate.check(tx)?;
                let now = match &assessed {
                    Ok(s) => s.wall(),
                    Err(_) => gate.clock().wall(),
                };
                let pid: PolicyId = match &action {
                    PolicyAction::Pause { policy_id }
                    | PolicyAction::Resume { policy_id }
                    | PolicyAction::Cutoff { policy_id, .. }
                    | PolicyAction::ClearCutoff { policy_id }
                    | PolicyAction::SetLockBehavior { policy_id, .. }
                    | PolicyAction::SetConnectionPolicy { policy_id, .. } => policy_id.clone(),
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
                    // ⟨M03⟩ U0b row 11 (O): against the current values.
                    PolicyAction::SetLockBehavior { .. }
                    | PolicyAction::SetConnectionPolicy { .. } => {
                        lock_connection_m03::widening(&action, &p)
                    }
                };
                let unchanged = match &action {
                    PolicyAction::Pause { .. } => matches!(p.pause, PauseState::Paused { .. }),
                    PolicyAction::Resume { .. } => p.pause == PauseState::Active,
                    PolicyAction::ClearCutoff { .. } => p.cutoff_at.is_none(),
                    PolicyAction::Cutoff { at, .. } => p.cutoff_at == Some(*at),
                    PolicyAction::SetLockBehavior { .. }
                    | PolicyAction::SetConnectionPolicy { .. } => {
                        lock_connection_m03::unchanged(&action, &p)
                    }
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
                    // ⟨M03⟩ U0b row 11 (O): narrowing takes effect now.
                    a if lock_connection_m03::is_m03(a) => lock_connection_m03::apply(a, &mut p),
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
                let mut done = Completed::ok(Code::Ok, policy_view(&p, changed, &req));
                // ⟨M03 wave 5⟩ U9-Q3 (a): a `SetLockBehavior` result is about the
                // policy's behaviour now; `revoke_on_lock` over an unverified signal
                // carries `signal_unverified` (ADR-0008 D9 item 3).
                if matches!(req, PolicyAction::SetLockBehavior { .. }) {
                    crate::lock::label_completed(
                        &mut done,
                        p.lock_behavior,
                        self.session_lock_signal(),
                    );
                }
                Ok(done)
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
    ///
    /// ⟨M02⟩ m02-plan U0b row 1, phase 2: an `ApplyProjection` or
    /// `DeclareInteraction` record needs its operation in `awaiting_approval` and
    /// must describe that operation's stored local intent exactly
    /// ([`local_decision_fits`]); otherwise `DECISION_STALE` with nothing applied.
    /// Approval writes the kind's own approval into the intent (a
    /// `ProjectionApproval` with the record's `plan_digest`, or a
    /// `DeclarationApproval` copied from the record's fields), moves the operation
    /// to `running` and resumes it (the setup or catalog driver); denial fails it
    /// `CAPABILITY_UNAVAILABLE`. No A06 delta check applies to these kinds.
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
        // ⟨M03⟩ wave 4: an M03 driver's refusal after completion rolls the transaction
        // back; its error travels out through this slot.
        let m03_refused: Arc<Mutex<Option<OpError>>> = Arc::new(Mutex::new(None));
        let m03_refused2 = Arc::clone(&m03_refused);
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
                    // ⟨M02⟩ ADR-0007 §12.22 item 9: the setup or catalog operation
                    // waiting on an expired record expires with it, in this
                    // transaction ([`expire_awaiting_local_in`]).
                    if let DecisionKind::ApplyProjection { operation, .. }
                    | DecisionKind::DeclareInteraction { operation, .. } = &d.kind
                        && let Some(mut op) = tx.operation(operation)?
                    {
                        expire_awaiting_local_in(tx, emit, &mut op, now, retention)?;
                    }
                    return Ok(Err(stale(&DecisionRefusal::Expired)));
                }
                // ⟨M03⟩ wave 4: what an M03 kind's precheck found (its waiting
                // operation, if any); `None` for every M01/M02 kind.
                let mut m03_waiting: Option<Option<OperationRecord>> = None;
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
                    // ⟨M02⟩ U0b row 1, phase 2: the waiting operation must be
                    // `awaiting_approval`, and the record must describe its stored
                    // local intent exactly (kind, plan digest or identity and
                    // interaction, approval not yet set). Anything else is
                    // `DECISION_STALE` before anything is written: the record stays
                    // pending and the operation untouched. No A06 delta check: these
                    // kinds carry no `AuthorityDelta`; the generation check below is
                    // unchanged.
                    DecisionKind::ApplyProjection { operation, .. }
                    | DecisionKind::DeclareInteraction { operation, .. } => {
                        let op = match tx.operation(operation)? {
                            Some(op) if op.state == OperationState::AwaitingApproval => op,
                            _ => {
                                return Ok(Err(OpError::new(
                                    Code::DecisionStale,
                                    "the operation is no longer awaiting this decision",
                                )
                                .with_resource("decision", Some(did.to_string()))));
                            }
                        };
                        let intent = tx.recovery_intent(&op.id)?;
                        if !local_decision_fits(&d.kind, &op, intent.as_ref()) {
                            return Ok(Err(OpError::new(
                                Code::DecisionStale,
                                "the decision does not describe the waiting operation's intent; preview or request again",
                            )
                            .with_resource("decision", Some(did.to_string()))));
                        }
                        Some(op)
                    }
                    // ⟨M03⟩ U0b row 14, phase 2 (wave 4): the kind's driver checks the
                    // record first (`decisions_m03::precheck`); a refusal writes nothing,
                    // so the record stays pending and is not consumed.
                    DecisionKind::RegisterIssuer { .. }
                    | DecisionKind::RetireIssuer { .. }
                    | DecisionKind::EnrollAccount { .. }
                    | DecisionKind::EnrollSystemForm { .. }
                    | DecisionKind::RemoveEnrollment { .. }
                    | DecisionKind::ApproveTargetChange { .. } => {
                        match decisions_m03::precheck(tx, &d, verdict, now)? {
                            Ok(w) => {
                                m03_waiting = Some(w);
                                None
                            }
                            Err(e) => {
                                return Ok(Err(
                                    e.with_resource("decision", Some(did.to_string()))
                                ));
                            }
                        }
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
                    // ⟨M02⟩ U0b row 1, phase 2 (§5 item 17): explicit arms, never
                    // absorbed by the fallback. Approval writes the kind's own
                    // approval into the waiting operation's local intent (add-only,
                    // row 16), moves it to `approved` and resumes exactly it. The
                    // `waiting` match checked the intent; a mismatch here rolls the
                    // whole transaction back, so nothing is consumed.
                    (DecisionKind::ApplyProjection { plan_digest, .. }, Verdict::Approve) => {
                        for mut op in waiters {
                            let mut intent = tx
                                .recovery_intent(&op.id)?
                                .ok_or_else(|| conflict("operation has no recovery intent"))?;
                            let Some(LocalIntent::Setup(setup)) = intent.local.as_mut() else {
                                return Err(conflict("the waiting operation has no setup intent"));
                            };
                            setup.approval = Some(ProjectionApproval {
                                decision: record.id.clone(),
                                plan_digest: plan_digest.clone(),
                            });
                            tx.set_recovery_intent(&op.id, &intent)?;
                            op_to(&mut op, OperationEvent::Approved, now)?;
                            tx.update_operation(&op)?;
                            emit.op(tx, &op)?;
                            resume.push(op.id.clone());
                        }
                    }
                    (
                        DecisionKind::DeclareInteraction {
                            identity,
                            fingerprint,
                            endpoint,
                            interaction,
                            valid_until,
                            ..
                        },
                        Verdict::Approve,
                    ) => {
                        for mut op in waiters {
                            let mut intent = tx
                                .recovery_intent(&op.id)?
                                .ok_or_else(|| conflict("operation has no recovery intent"))?;
                            let Some(LocalIntent::Catalog(catalog)) = intent.local.as_mut() else {
                                return Err(conflict("the waiting operation has no catalog intent"));
                            };
                            // Copied from the record's fields; the catalog driver builds
                            // the declaration from this alone (ADR-0007 §7).
                            catalog.approval = Some(DeclarationApproval {
                                decision: record.id.clone(),
                                identity: identity.clone(),
                                fingerprint: fingerprint.clone(),
                                endpoint: endpoint.clone(),
                                interaction: *interaction,
                                valid_until: *valid_until,
                            });
                            tx.set_recovery_intent(&op.id, &intent)?;
                            op_to(&mut op, OperationEvent::Approved, now)?;
                            tx.update_operation(&op)?;
                            emit.op(tx, &op)?;
                            resume.push(op.id.clone());
                        }
                    }
                    // Denial: the waiting operation fails; no file or catalog row is
                    // touched.
                    (DecisionKind::ApplyProjection { .. }, Verdict::Deny) => {
                        let err = OpError::new(
                            Code::CapabilityUnavailable,
                            "the owner denied the projection change",
                        );
                        for mut op in waiters {
                            settle_failed(tx, emit, &mut op, &err, now, retention)?;
                        }
                    }
                    (DecisionKind::DeclareInteraction { .. }, Verdict::Deny) => {
                        let err = OpError::new(
                            Code::CapabilityUnavailable,
                            "the owner denied the declaration",
                        );
                        for mut op in waiters {
                            settle_failed(tx, emit, &mut op, &err, now, retention)?;
                        }
                    }
                    (
                        DecisionKind::WidenPolicy { .. } | DecisionKind::ConfirmTime { .. },
                        _,
                    ) => {}
                    // ⟨M03⟩ U0b row 14, phase 2 (wave 4): the kind's driver, in this
                    // transaction. A refusal here rolls the whole transaction back
                    // (nothing consumed): it is returned as a store-level conflict
                    // carrying no data, then reported from `m03_refusal`.
                    (
                        DecisionKind::RegisterIssuer { .. }
                        | DecisionKind::RetireIssuer { .. }
                        | DecisionKind::EnrollAccount { .. }
                        | DecisionKind::EnrollSystemForm { .. }
                        | DecisionKind::RemoveEnrollment { .. }
                        | DecisionKind::ApproveTargetChange { .. },
                        _,
                    ) => {
                        let waiting_op = m03_waiting.take().flatten();
                        match decisions_m03::apply(
                            tx, emit, &record, verdict, waiting_op, now, retention,
                        )? {
                            Ok(more) => resume.extend(more),
                            Err(e) => {
                                *m03_refused2
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner) = Some(e);
                                return Err(conflict("m03 decision refused by its driver"));
                            }
                        }
                    }
                }
                Ok(Ok((record, op_id, resume)))
            })
            .await;
        if let Some(e) = m03_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            return Err(e.with_resource("decision", Some(req.decision_id.to_string())));
        }
        let (record, op_id, resume) = r??;
        if record.kind.is_m03() {
            self.m03_after_decision(&record, verdict).await;
        }
        // Resume the waiting operations, all at once (the record's own operation
        // first), under ONE overall bound for this request (⟨r2.5⟩ ADR-0006 §13.8
        // item 2): when it is reached the durable decision result is returned and
        // the work continues, every waiter's operation observable.
        // ⟨M02⟩ ADR-0007 §12.30 item 1: each waiter resumes with the interaction mode
        // its own stored request asked for. An interactive ensure that waited for this
        // decision stays interactive (the owner just attended it); everything else,
        // and a request that cannot be read, resumes non-interactive (fail closed).
        let mut modes = Vec::with_capacity(resume.len());
        for id in resume {
            let interactive = self.stored_request_is_interactive(&id).await;
            modes.push((id, interactive));
        }
        let resume: Vec<(OperationId, bool)> = modes;
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
        // ⟨M02⟩ ADR-0007 §12.22 item 9: a setup or catalog operation still awaiting a
        // decision that passed its deadline expires here even if nobody asks about it
        // ([`expire_awaiting_local_in`]). Judged on time the gate accepted, as a
        // grant's deadline is above: uncertain time expires nothing in this pass.
        if let Some(s) = &safe {
            let now = s.wall();
            let retention = self.retention();
            self.write(move |tx, emit| {
                for mut op in tx.open_operations()? {
                    expire_awaiting_local_in(tx, emit, &mut op, now, retention)?;
                }
                Ok(())
            })
            .await?;
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
    ///
    /// ⟨M03 wave 4, round 3; ADR-0008 §17.22 item 4 (W4-R01)⟩ After the commit, the
    /// expired grant's managed cleanup runs (K_env destroyed, its binding endpoints
    /// and files removed, its instances `destroyed` and the gate released), with or
    /// without a held slot. Its durable obligation is the instance row
    /// (`Txn::managed_cleanup_owed`): a crash or a failure before the end of the
    /// cleanup leaves it for the supervisor's ended-grant pass.
    async fn expire_grant(&self, gid: &GrantId, now: Timestamp) -> Result<(), OpError> {
        let gid = gid.clone();
        let ended = gid.clone();
        let retention = self.retention();
        let expired = self
            .write(move |tx, emit| {
                let Some(mut g) = tx.grant(&gid)? else {
                    return Ok(false);
                };
                let expired = grant_try(&mut g, GrantEvent::DeadlineReached);
                if expired {
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
                Ok(expired)
            })
            .await?;
        if expired {
            self.after_end_m03(std::slice::from_ref(&ended), now).await;
        }
        Ok(())
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
    ///
    /// ⟨M03⟩ U0b row 3 (O): on the M03 path the transaction selects the CA itself
    /// (`ca_issuance_m03`); an M01 request (no CA named, a grant whose mechanism is not
    /// `managed_certificate`) is unchanged.
    pub async fn reserve_issuance(&self, req: IssuanceRequest) -> Result<IssuanceEntry, OpError> {
        self.reserve_issuance_with(req, None).await
    }

    /// [`Operations::reserve_issuance`], with the CA the request names, if any.
    async fn reserve_issuance_with(
        &self,
        req: IssuanceRequest,
        named_ca: Option<heimdall_contract::ids::CaFingerprint>,
    ) -> Result<IssuanceEntry, OpError> {
        // ⟨ADR-0008 §17.27 item 2, §17.28 item 1⟩ no new certificate while an
        // uninstall holds the fence (unless the holder's own request reserves it).
        self.fence_check()?;
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
                // ⟨M03⟩ U0b row 3 (O): the CA, selected in this transaction.
                let ca_fingerprint = match ca_issuance_m03::select_ca(
                    tx,
                    &grant.id,
                    &req.pair,
                    named_ca.as_ref(),
                )? {
                    Ok(ca) => ca,
                    Err(refusal) => {
                        return Ok((
                            Err(ca_issuance_m03::refusal_error(&refusal)),
                            Ended::default(),
                        ));
                    }
                };
                let bounds = CertificateBounds {
                    serial,
                    key_id: req.key_id.clone(),
                    principal: req.principal.clone(),
                    valid_after: req.valid_after,
                    valid_before: req.valid_before,
                    extensions: req.extensions.clone(),
                    subject_fingerprint: req.subject_fingerprint.clone(),
                    ca_fingerprint,
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
                    return Ok((Err(ca_issuance_m03::refusal_error(&refusal)), ended));
                }
                // ⟨§17.19 item 2⟩ The reserve transaction persists what it judged:
                // issuance within an existing grant (continuing work) or a new
                // activation.
                Ok((
                    Ok(reserve_entry(
                        tx,
                        emit,
                        id,
                        &grant.id,
                        &req.pair,
                        bounds,
                        !req.facts.new_activation,
                        now,
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
                // ⟨§17.19 item 2, W2-R02⟩ Continuing work only if the reserve
                // transaction recorded it: a caller's facts can make publication
                // stricter (a new activation), never laxer than the entry. So
                // publication and the issuer, which reads only the entry, judge the
                // same distinction.
                let facts = IssuanceFacts {
                    new_activation: facts.new_activation || !entry.continuing,
                    ..facts.clone()
                };
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
                        let fresh = reserve_entry(
                            tx,
                            emit,
                            fresh_id,
                            &gid,
                            &entry.pair,
                            bounds,
                            entry.continuing,
                            now,
                        )?;
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
                            Published::refused(ca_issuance_m03::refusal_error(&refusal)),
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

/// Insert a `reserved` entry at the current generation, with its event. `continuing`
/// is persisted with it (⟨§17.19 item 2⟩ `IssuanceEntry::continuing`): issuance within
/// an existing grant, which publication and the issuer then read from the entry.
#[allow(clippy::too_many_arguments)]
fn reserve_entry(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    id: IssuanceId,
    grant: &GrantId,
    pair: &AccessPair,
    bounds: CertificateBounds,
    continuing: bool,
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
        continuing,
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
///
/// ⟨M03⟩ U0b row 2 (O): a wrapper over `heimdall_domain::issuance::extension_profile`
/// (ADR-0008 D6 item 1), whose output is identical for every M01 grant.
#[must_use]
pub fn permitted_extensions(grant: &GrantSnapshot, pair: &AccessPair) -> BTreeSet<String> {
    heimdall_domain::issuance::extension_profile(grant, pair)
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
    let verdict = issuance_check_snapshot(
        tx,
        env,
        adapters,
        grant,
        pair,
        bounds,
        facts,
        time,
        safe.map(|s| &s.anchor),
        now,
        true,
    )?;
    // ⟨r2.7⟩ ADR-0006 §13.10 item 2: after every predicate held, a grant whose
    // credential mechanism is unavailable is still refused (nothing ends).
    let mechanism = mechanism_refuses(tx, adapters, grant)?;
    Ok(match verdict {
        Ok(()) if mechanism => Err(IssuanceRefusal::MechanismUnavailable),
        r => r,
    })
}

/// ⟨M03⟩ U3: the body of [`run_issuance_check`] before the mechanism check, shared
/// with the issuer's read-only check ([`issuance_check_read_only`]). `safe` is the
/// accepted observation (`None` on uncertain time); with `record` false a
/// re-validation is judged but not recorded, so nothing is written.
#[allow(clippy::too_many_arguments)]
fn issuance_check_snapshot(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    adapters: &[AdapterInfo],
    grant: &GrantSnapshot,
    pair: &AccessPair,
    bounds: &CertificateBounds,
    facts: &IssuanceFacts,
    time: dtime::TimeStatus,
    safe: Option<&dtime::TimeAnchor>,
    now: Timestamp,
    record: bool,
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
        match revalidate_chain_verdict_with(tx, env, adapters, grant, now, record)? {
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
    // Continuous admission from the **same** observation the gate assessed.
    let admission = match (safe, tx.grant_anchor(&grant.id)?) {
        (Some(s), Some(anchor)) => dtime::admission(&anchor, s),
        _ => Admission::NeedsAnchor,
    };
    let verdict = issuance_predicate(
        tx,
        env,
        &IssuanceSnapshot {
            grant,
            subject,
            chain: &chain,
            revalidation_failed,
            current_generation,
        },
        pair,
        bounds,
        facts,
        time,
        admission,
        now,
    )?;
    Ok(match verdict {
        Ok(()) if revalidation_failed => Err(IssuanceRefusal::StaleGeneration),
        r => r,
    })
}

/// ⟨M03⟩ U3 (ADR-0008 D3 item 4 step 2; §17.1 item 12, F21): the snapshot one
/// issuance predicate run sees, assembled by the reserve and publish transactions
/// ([`run_issuance_check`]) and by the issuer's read-only check
/// ([`issuance_check_read_only`]) alike.
struct IssuanceSnapshot<'a> {
    /// The grant as stored.
    grant: &'a GrantSnapshot,
    /// The grant as the predicate sees it (at the current generation when
    /// re-validated, else at its validated generation's copy).
    subject: GrantSnapshot,
    /// Its ancestors, nearest first, as the predicate sees them.
    chain: &'a [GrantSnapshot],
    /// A re-validation was attempted and failed: the recorded policy revision stays
    /// the expected one.
    revalidation_failed: bool,
    /// The current authority generation.
    current_generation: heimdall_domain::policy::AuthorityGeneration,
}

/// The predicate over one assembled snapshot (merged or continuing policy, the
/// expected policy revision, tombstones, the CA facts): the code the reserve and
/// publish transactions and the issuer's read-only check share, so they can never
/// disagree about what the predicate sees (ADR-0008 D3 item 4 step 2). Reads only.
#[allow(clippy::too_many_arguments)]
fn issuance_predicate(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    snapshot: &IssuanceSnapshot<'_>,
    pair: &AccessPair,
    bounds: &CertificateBounds,
    facts: &IssuanceFacts,
    time: dtime::TimeStatus,
    admission: Admission,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), IssuanceRefusal>> {
    let grant = snapshot.grant;
    let revalidation_failed = snapshot.revalidation_failed;
    let current_generation = snapshot.current_generation;
    let (parent, ancestors) = match snapshot.chain.split_first() {
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
    let mut subject = snapshot.subject.clone();
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
    let permitted = permitted_extensions(grant, pair);
    // ⟨M03⟩ U0b row 2 (O): the CA inputs, read here (`None` on the M01 path).
    let cas = ca_issuance_m03::ca_facts(tx, &grant.id, pair, bounds)?;
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
        enrolled_cas: cas.as_ref().map(ca_issuance_m03::CaFacts::input),
    };
    Ok(heimdall_domain::issuance::check(&check))
}

/// ⟨M03⟩ U3 (ADR-0008 D3 item 4 step 2; §17.1 item 12, F21): the publish
/// predicate over the stored `entry`, read-only, for the issuer child. It is
/// [`issuance_check_snapshot`], the code [`run_issuance_check`] runs at reserve and
/// publish, with two differences a read-only reader needs:
/// * **a re-validation is judged, never recorded** (`record` false). It runs without
///   the runtime's adapter list: `resolve_existing` reads adapters only for the
///   destination's enforcement label, `unknown` without one, which no caller minimum
///   is checked against here, so the verdict is the runtime's;
/// * **the mechanism is judged from the store only:** a grant `degraded` for a reason
///   whose rule refuses every use is refused; whether the mechanism is configured is
///   the runtime's own fact, judged again by its publish transaction.
///
/// When every predicate holds but the entry was reserved at another authority
/// generation, it refuses [`IssuanceRefusal::StaleGeneration`] where publish would
/// void and re-reserve: the D3 item 4 generation-only refusal. So the verdict is the
/// publish transaction's, with "re-reserved" read as `stale_generation`.
///
/// `time` is the read-only assessment of the observation `now`. Reads only.
pub(crate) fn issuance_check_read_only(
    tx: &mut Txn<'_>,
    entry: &IssuanceEntry,
    facts: &IssuanceFacts,
    now: &dtime::TimeAnchor,
    time: &dtime::TimeStatus,
) -> heimdall_store::Result<Result<(), IssuanceRefusal>> {
    let Some(grant) = tx.grant(&entry.grant)? else {
        return Ok(Err(IssuanceRefusal::GrantNotIssuable(GrantState::Revoked)));
    };
    let Some(env) = tx.self_environment()? else {
        return Ok(Err(IssuanceRefusal::GrantNotIssuable(GrantState::Revoked)));
    };
    let safe = (*time == dtime::TimeStatus::Safe).then_some(now);
    let verdict = issuance_check_snapshot(
        tx,
        &env,
        &[],
        &grant,
        &entry.pair,
        &entry.bounds,
        facts,
        *time,
        safe,
        now.wall,
        false,
    )?;
    let degraded_refuses = grant.state == GrantState::Degraded
        && tx
            .grant_degradation(&grant.id)?
            .is_some_and(degraded_refuses_use);
    let current_generation = tx.authority_generation()?;
    Ok(match verdict {
        Ok(()) if degraded_refuses => Err(IssuanceRefusal::MechanismUnavailable),
        Ok(()) if entry.generation != current_generation => Err(IssuanceRefusal::StaleGeneration),
        r => r,
    })
}

/// Outcome of a policy action.
enum PolicyOutcome {
    Applied(Box<StandingPolicy>, bool),
    Decision(heimdall_contract::ids::DecisionId),
}

/// A policy action's result. ⟨M03; ADR-0008 §17.25 item 22 (Q-R2 (b))⟩ For the two M03
/// actions (`SetLockBehavior`, `SetConnectionPolicy`) only, it also carries **this
/// policy's** stored values after the action: `lock_behavior` and `connection`
/// (`{existing, multiplexing}`). Every M01 action's result is unchanged.
fn policy_view(p: &StandingPolicy, changed: bool, action: &PolicyAction) -> serde_json::Value {
    let mut view = serde_json::json!({
        "policy_id": p.id,
        "revision": p.revision.0,
        "paused": matches!(p.pause, PauseState::Paused { .. }),
        "cutoff_at": p.cutoff_at,
        "changed": changed,
    });
    if lock_connection_m03::is_m03(action)
        && let serde_json::Value::Object(map) = &mut view
    {
        map.insert(
            "lock_behavior".to_owned(),
            serde_json::json!(p.lock_behavior),
        );
        map.insert("connection".to_owned(), serde_json::json!(p.connection));
    }
    view
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
        | PolicyAction::ClearCutoff { policy_id }
        | PolicyAction::SetLockBehavior { policy_id, .. }
        | PolicyAction::SetConnectionPolicy { policy_id, .. } => policy_id,
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
        // ⟨M03⟩ U0b row 11 (O): exactly the recorded action (the widening parts, and
        // any narrowing part of a mixed action, with it).
        PolicyAction::SetLockBehavior { .. } | PolicyAction::SetConnectionPolicy { .. } => {
            lock_connection_m03::apply(action, &mut p);
        }
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

// ---------------------------------------------------------------------------------
// ⟨M02⟩ U5 seam: the operations' plumbing as the setup and catalog drivers
// (`crate::setup`, `crate::catalog`) reach it. Thin crate-visible wrappers only; no
// behaviour of its own. The drivers keep the M01 rules: one store transaction per
// step with its events, the admission order of row 23, and one in-process driver per
// operation (the same `flights` map `lead` uses, so a request, a decision's resume
// and restart recovery never drive one operation twice at once).
// ---------------------------------------------------------------------------------

/// ⟨M02⟩ U5: the events of one local-driver transaction (wraps [`Emit`]).
pub(crate) struct LocalEmit<'e>(&'e mut Emit);

impl LocalEmit<'_> {
    /// `operation_state_changed` for `op`.
    pub(crate) fn op(
        &mut self,
        tx: &mut Txn<'_>,
        op: &OperationRecord,
    ) -> heimdall_store::Result<()> {
        self.0.op(tx, op)
    }

    /// `decision` for `d`.
    pub(crate) fn decision(
        &mut self,
        tx: &mut Txn<'_>,
        d: &DecisionRecord,
        op: Option<&OperationId>,
    ) -> heimdall_store::Result<()> {
        self.0.decision(tx, d, op)
    }

    /// Any event.
    pub(crate) fn event(
        &mut self,
        tx: &mut Txn<'_>,
        ty: EventType,
        op: Option<OperationId>,
        res: Option<ResourceRef>,
        payload: serde_json::Value,
    ) -> heimdall_store::Result<()> {
        self.0.event(tx, ty, op, res, payload)
    }
}

/// ⟨M02⟩ U5: which local driver a lead runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalDriver {
    /// `crate::setup::drive`.
    Setup,
    /// `crate::catalog::drive`.
    Catalog,
}

/// ⟨M02⟩ U5: [`settle_failed`] for the local drivers.
pub(crate) fn local_settle_failed(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &mut OperationRecord,
    err: &OpError,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<()> {
    settle_failed(tx, emit.0, op, err, now, retention)
}

/// ⟨M02⟩ ADR-0007 §12.22 item 9 (W3b-gaps): an `awaiting_approval` setup or catalog
/// operation whose decision passed its deadline expires, as ADR-0006's
/// `DeadlineReached` does for a waiting grant (§4.2: `awaiting_approval → expired`; a
/// new operation creates new work). M01 settles an operation waiting on an expired
/// grant `failed` with `CREDENTIAL_EXPIRED` (`next: new_work`, [`Operations::tick`]'s
/// `expire_grant`); the operation table has no `expired` state, so the same
/// settlement is used here: the `awaiting_approval → failed` edge, `CREDENTIAL_EXPIRED`,
/// effect `none` (nothing was written while it waited), the expired decision named
/// as the resource. No fresh decision is issued: a new request is new work.
///
/// It applies only when at least one pending `ApplyProjection` or
/// `DeclareInteraction` record names `op` and every such record has reached its
/// `expires_at` at `now`. A record that is not pending (stale, withdrawn) is not a
/// deadline, so it leaves the operation to its driver. Returns whether `op` expired.
/// The record itself is left as it is: completion refuses it at its deadline
/// (`DECISION_STALE`), and `inspect decisions` reports it `expired`, as for M01.
fn expire_awaiting_local_in(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    op: &mut OperationRecord,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<bool> {
    let local = op.kind.is_setup() || op.kind == OperationKind::Catalog;
    if op.state != OperationState::AwaitingApproval || !local {
        return Ok(false);
    }
    let mut expired = None;
    for d in tx.pending_decisions()? {
        let names_op = matches!(
            &d.kind,
            DecisionKind::ApplyProjection { operation, .. }
                | DecisionKind::DeclareInteraction { operation, .. }
                if *operation == op.id
        );
        if !names_op {
            continue;
        }
        if now < d.expires_at {
            return Ok(false);
        }
        expired = Some(d.id);
    }
    let Some(decision) = expired else {
        return Ok(false);
    };
    let err = OpError::new(
        Code::CredentialExpired,
        "the owner's decision reached its deadline before it was made: the operation expired, and new work needs a new request",
    )
    .with_effect(EffectStatus::None)
    .with_resource("decision", Some(decision.to_string()));
    settle_failed(tx, emit, op, &err, now, retention)?;
    Ok(true)
}

/// ⟨M02⟩ W3b-gaps: [`expire_awaiting_local_in`] for the local drivers.
pub(crate) fn local_expire_awaiting(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &mut OperationRecord,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<bool> {
    expire_awaiting_local_in(tx, emit.0, op, now, retention)
}

/// ⟨M02⟩ U5: [`settle_succeeded`] for the local drivers.
pub(crate) fn local_settle_succeeded(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &mut OperationRecord,
    code: Code,
    data: serde_json::Value,
    now: Timestamp,
    retention: Duration,
) -> heimdall_store::Result<()> {
    settle_succeeded(tx, emit.0, op, code, data, now, retention)
}

/// ⟨M02⟩ U5: [`op_to`] for the local drivers.
pub(crate) fn local_op_to(
    op: &mut OperationRecord,
    ev: OperationEvent,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    op_to(op, ev, now)
}

/// ⟨M02⟩ U5: [`approval_needed`] for the local drivers.
pub(crate) fn local_approval_needed(attended: bool, decision_ref: &str, msg: &str) -> OpError {
    approval_needed(attended, decision_ref, msg)
}

/// ⟨M02⟩ U5: [`Operations::refuse_outcome`] for the local drivers.
pub(crate) fn local_refuse_outcome(outcome: &IdempotencyOutcome) -> Option<OpError> {
    Operations::refuse_outcome(outcome)
}

impl Operations {
    /// ⟨M02⟩ U5: the configured projection writer.
    pub(crate) fn local_projection(&self) -> Option<Arc<dyn crate::ports::ProjectionWriter>> {
        self.inner.config.projection.clone()
    }

    /// ⟨M02⟩ U5: the clock.
    pub(crate) fn local_clock(&self) -> Arc<dyn Clock> {
        self.clock()
    }

    /// ⟨M02⟩ U5: the store, for the `StageSink` the projection writer calls on the
    /// blocking pool (one synchronous transaction per receipt; no events).
    pub(crate) fn local_store(&self) -> Arc<Store> {
        Arc::clone(&self.inner.config.store)
    }

    /// ⟨M02⟩ U5: the retention of settled operations.
    pub(crate) fn local_retention(&self) -> Duration {
        self.retention()
    }

    /// ⟨M02⟩ U5: `now` for narrowing actions.
    pub(crate) async fn local_narrowing_now(&self) -> Timestamp {
        self.narrowing_now().await
    }

    /// ⟨M02⟩ U5: one store transaction with its events ([`Operations::write`]).
    pub(crate) async fn local_write<R, F>(&self, f: F) -> Result<R, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Txn<'_>, &mut LocalEmit<'_>) -> heimdall_store::Result<R> + Send + 'static,
    {
        self.write(move |tx, emit| f(tx, &mut LocalEmit(emit)))
            .await
    }

    /// ⟨M02⟩ U5: admission (row 23) with `pipeline: false` (local receipts only).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn local_admit(
        &self,
        key: IdempotencyKey,
        hash: heimdall_contract::canonical::RequestHash,
        kind: OperationKind,
        effect_class: EffectClass,
        request: serde_json::Value,
        now: Timestamp,
        exclusive: Option<SetupAdmission>,
    ) -> Result<IdempotencyOutcome, OpError> {
        self.admit(
            key,
            hash,
            kind,
            effect_class,
            request,
            now,
            false,
            exclusive,
        )
        .await
    }

    /// ⟨M02⟩ U5: lead `id` with `driver` in a spawned task (a caller's timeout never
    /// stops the work) and wait at most `wait`; `None` when the wait ended first.
    pub(crate) async fn local_lead_bounded(
        &self,
        id: &OperationId,
        driver: LocalDriver,
        wait: Duration,
    ) -> Option<Result<(), OpError>> {
        let me = self.clone();
        let id = id.clone();
        let task = tokio::spawn(async move { me.local_lead(&id, driver).await });
        match tokio::time::timeout(wait, task).await {
            Ok(Ok(r)) => Some(r),
            Ok(Err(e)) => Some(Err(join_error(e))),
            Err(_) => None,
        }
    }

    /// ⟨M02⟩ U5: [`Operations::lead`] with the local driver called directly, under the
    /// same per-operation flight and running count.
    async fn local_lead(&self, id: &OperationId, driver: LocalDriver) -> Result<(), OpError> {
        struct Running<'a>(&'a AtomicUsize);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        for _ in 0..3 {
            match self.inner.flights.join_or_lead(id.clone()) {
                Err(_) => {
                    return Err(
                        OpError::new(Code::Backpressure, "too many operations in flight")
                            .with_retry_after(BACKPRESSURE_RETRY_MS),
                    );
                }
                Ok(Flight::Lead(tx)) => {
                    self.inner.running.fetch_add(1, Ordering::SeqCst);
                    let guard = Running(&self.inner.running);
                    let r = match driver {
                        LocalDriver::Setup => crate::setup::drive(self, id).await,
                        LocalDriver::Catalog => crate::catalog::drive(self, id).await,
                    };
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ⟨M03 wave 4 round 2, R2C-Q1; ADR-0008 D6 item 7, D10 item 6⟩ A managed pair as the
    /// managed adapter reports it: interaction `none`, eligible, signing in-process; its
    /// catalog identity (`ident`) is NOT in the store, so M02's recomputation would make
    /// it `unknown` and ineligible.
    fn managed_pair(selection: IdentitySelection) -> PairIntegration {
        PairIntegration {
            destination: heimdall_contract::ids::DestinationId::parse("dst-w").unwrap(),
            account: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
            identity: heimdall_contract::ids::IdentityId::from_random_bytes([5; 16]),
            mechanism: MANAGED_CERTIFICATE.to_owned(),
            endpoint: None,
            alias: Some("work".to_owned()),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Inferred,
            declared_at: None,
            identity_selection: selection,
            selection_observed_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            identity_selection_report: None,
        }
    }

    #[test]
    fn managed_pair_commit_eligibility_is_the_signers_and_follows_its_selection() {
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let now: Timestamp = "2026-10-02T00:10:00Z".parse().unwrap();
        store
            .transaction(|tx| {
                // The commit's fresh re-check keeps the signer's facts.
                let mut p = managed_pair(IdentitySelection::Exclusive);
                fresh_pair(tx, &mut p, now)?;
                assert_eq!(p.interaction, InteractionKind::None);
                assert!(p.noninteractive.eligible, "{:?}", p.noninteractive);
                assert_eq!(p.eligibility_checked_at, now);
                // Exclusive: a non-interactive commit is not refused.
                assert!(
                    noninteractive_commit_refusal(tx, &[p], MANAGED_CERTIFICATE, now)?.is_none()
                );
                // The pair's catalog identity (the enrollment's existing access) exists,
                // with an agent endpoint and no inherited entries, so M02's fallback
                // clearance of *that* identity would pass: a managed pair is still judged
                // by its own selection only.
                let endpoint = heimdall_contract::provider::EndpointRef {
                    kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                    locator: "/fixture/agent.sock".to_owned(),
                };
                tx.upsert_identity(&IdentityRecord {
                    id: heimdall_contract::ids::IdentityId::from_random_bytes([5; 16]),
                    revision: 1,
                    source: heimdall_domain::catalog::IdentitySource::NativeAgent {
                        endpoint: endpoint.clone(),
                    },
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl".to_owned(),
                    fingerprint: "SHA256:fixturefixturefixturefixturefixturefixtur".to_owned(),
                    interaction: heimdall_domain::catalog::InteractionProfile {
                        interaction: InteractionKind::None,
                        basis: EvidenceBasis::Declared,
                    },
                    label: None,
                    adopted_at: now,
                    updated_at: now,
                })?;
                // Not exclusive / undetermined: an inherited identity may prompt.
                for sel in [IdentitySelection::NotExclusive, IdentitySelection::Undetermined] {
                    let mut p = managed_pair(sel);
                    p.endpoint = Some(endpoint.clone());
                    fresh_pair(tx, &mut p, now)?;
                    let e = noninteractive_commit_refusal(tx, &[p], MANAGED_CERTIFICATE, now)?
                        .expect("refused");
                    assert_eq!(e.code, Code::InteractionRequired, "{sel:?}");
                    assert_eq!(
                        e.reason.as_deref(),
                        Some(heimdall_contract::envelope::reason::FALLBACK_IDENTITY_INTERACTION),
                        "{sel:?}"
                    );
                }
                Ok(())
            })
            .unwrap();
    }

    fn r(stage: EnsureStage, effect: EffectReceipt) -> StageReceipt {
        receipt(stage, "2026-10-02T00:00:00Z".parse().unwrap(), effect)
    }

    fn ident() -> AdapterIdentity {
        AdapterIdentity {
            mechanism: "fake".into(),
            instance: "1".into(),
        }
    }

    /// ADR-0007 §12.32 item 5: a decision's request carries the summary's diff whole. It
    /// was once cut to `MAX_DIFF_BYTES` here without a word; a plan whose diff does not
    /// fit is now refused before a decision exists, so this never has to cut.
    #[test]
    fn a_projection_decision_shows_its_whole_diff() {
        use heimdall_contract::ids::DecisionId;
        use heimdall_domain::policy::AuthorityGeneration;
        use heimdall_domain::projection::{ProjectionSummary, SummaryIntent};
        let diff = format!(
            "{}\n+the line past the bound\n",
            "+x".repeat(ProjectionSummary::MAX_DIFF_TEXT)
        );
        let record = DecisionRecord {
            id: DecisionId::from_random_bytes([4; 16]),
            kind: DecisionKind::ApplyProjection {
                operation: OperationId::from_random_bytes([5; 16]),
                plan_digest: heimdall_contract::setup::PlanDigest::from_sha256([6; 32]),
                summary: ProjectionSummary {
                    intent: SummaryIntent::Apply,
                    added_aliases: Vec::new(),
                    changed_aliases: Vec::new(),
                    removed_aliases: Vec::new(),
                    files: Vec::new(),
                    git: false,
                    restore: Vec::new(),
                    diff_text: diff.clone(),
                },
            },
            generation: AuthorityGeneration(0),
            created_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            expires_at: "2026-10-02T00:15:00Z".parse().unwrap(),
            state: DecisionState::Pending,
            decided_at: None,
        };
        let view = decision_view(&record, "2026-10-02T00:00:01Z".parse().unwrap());
        assert_eq!(view["request"]["diff_text"].as_str(), Some(diff.as_str()));
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

    /// ⟨r2.12⟩ ADR-0006 §13.15 item 2: combining the views of the records that
    /// cover one grant is independent of their order: stopped only if both are,
    /// every reason of either (each once), the highest count and the latest round.
    #[test]
    fn remote_views_combine_whatever_the_record_order() {
        let at = |s: &str| -> Timestamp { s.parse().unwrap() };
        let view = |attempts, last: &str, stopped, reasons: &[RemotePendingReason]| RemoteView {
            attempts,
            last_attempt_at: at(last),
            stopped,
            reasons: reasons.to_vec(),
        };
        let unavailable = RemotePendingReason::AdapterUnavailable;
        let capped = || view(3, "2026-10-02T00:00:10Z", true, &[]);
        let retryable = || view(1, "2026-10-02T00:01:00Z", false, &[unavailable]);
        for v in [capped().combine(retryable()), retryable().combine(capped())] {
            assert_eq!(v.attempts, 3);
            assert_eq!(v.last_attempt_at, at("2026-10-02T00:01:00Z"));
            assert!(!v.stopped, "one obligation remains retryable");
            assert_eq!(v.reasons, vec![unavailable]);
        }
        let both = capped().combine(view(2, "2026-10-02T00:00:01Z", true, &[unavailable]));
        assert!(both.stopped, "every obligation stopped");
        let twice = retryable().combine(retryable());
        assert_eq!(twice.reasons, vec![unavailable], "each reason once");
    }

    /// ⟨r2.14⟩ ADR-0006 §13.17: the effect of an operation is its latest attempt
    /// (`Attempted` or `Uncertain`), with its adapter and token, confirmed only when
    /// a `Confirmed` receipt follows that attempt; none without an attempt.
    #[test]
    fn applied_effect_is_the_latest_attempt_and_whether_it_was_confirmed() {
        use EnsureStage as S;
        let attempted = |token: &str| {
            r(
                S::Reconcile,
                EffectReceipt::Attempted {
                    adapter: ident(),
                    effect_token: token.into(),
                },
            )
        };
        let confirmed = || {
            r(
                S::Reconcile,
                EffectReceipt::Confirmed {
                    adapter: ident(),
                    credential_ref: "c".into(),
                },
            )
        };
        let key = |token: &str, confirmed| AppliedEffect {
            adapter: ident(),
            key: RearmedEffect {
                grant: None,
                adapter: None,
                effect_token: token.into(),
                confirmed,
            },
        };
        let mut rs = vec![r(S::Authenticate, EffectReceipt::NotAttempted)];
        assert_eq!(applied_effect(&rs), None);
        rs.push(attempted("eff_1"));
        assert_eq!(applied_effect(&rs), Some(key("eff_1", false)));
        rs.push(r(
            S::Reconcile,
            EffectReceipt::Uncertain {
                adapter: ident(),
                effect_token: "eff_1".into(),
            },
        ));
        assert_eq!(applied_effect(&rs), Some(key("eff_1", false)));
        rs.push(confirmed());
        assert_eq!(applied_effect(&rs), Some(key("eff_1", true)));
        rs.push(attempted("eff_2"));
        assert_eq!(
            applied_effect(&rs),
            Some(key("eff_2", false)),
            "an earlier confirmation is not this attempt's"
        );
    }

    /// ⟨r2.14⟩ ADR-0006 §13.17 items 1–4 on the cleanup decision's transaction (a
    /// replay of the same effect cannot be produced through the public operations,
    /// whose cleanup paths settle the operation first, so the bound is checked
    /// here):
    /// * no covering record: the immediate call, nothing written;
    /// * a live obligation (not stopped, below the cap): skipped; ⟨r2.15⟩ the
    ///   effect is recorded on it at the record's round count (§13.18 item 2);
    /// * a capped obligation (at the cap, or stopped): re-armed, the record no
    ///   longer stopped, the effect recorded (key and round);
    /// * the same effect again after its re-armed obligation was capped again: no
    ///   second re-arm, ⟨r2.15⟩ but the immediate call to the applying adapter
    ///   (§13.18 item 4); the same token's other recorded state (possibly applied,
    ///   then confirmed) and another token each re-arm once;
    /// * no obligation for the applying adapter: one is added.
    #[test]
    fn an_applied_effect_rearms_a_covering_record_at_most_once_per_effect() {
        use heimdall_domain::operation::AdapterIdentity as Id;
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let at: Timestamp = "2026-10-02T00:00:00Z".parse().unwrap();
        let root = GrantId::from_random_bytes([7; 16]);
        let uncovered = GrantId::from_random_bytes([8; 16]);
        let cap = 3;
        let effect = |token: &str, confirmed| AppliedEffect {
            adapter: ident(),
            key: RearmedEffect {
                grant: None,
                adapter: None,
                effect_token: token.into(),
                confirmed,
            },
        };
        // The key a re-arm records: scoped to the grant and the applying adapter.
        let scoped = |token: &str, confirmed| RearmedEffect {
            grant: Some(root.clone()),
            adapter: Some(ident()),
            effect_token: token.into(),
            confirmed,
        };
        let owed = |attempts, stopped, effect_seq| RemoteObligation {
            grant: root.clone(),
            adapter: ident(),
            reason: None,
            attempts: Some(attempts),
            stopped,
            effect_round: None,
            effect_seq,
            // M03 wave 0 (A1): fail closed until U0b
            kind: Default::default(),
        };
        // ⟨r2.16⟩ In the current form: its latest claim is sequence 3 (§13.19 item 1).
        let record = |o: RemoteObligation| PendingRemoteRevocation {
            root: root.clone(),
            grants: vec![root.clone()],
            attempts: 3,
            last_attempt_at: at,
            stopped: o.stopped,
            obligations: vec![o],
            claimed_at: None,
            rearmed_effects: Vec::new(),
            cap: None,
            claim_seq: Some(3),
        };
        store
            .transaction(|tx| {
                tx.insert_tombstone(&Tombstone {
                    grant: root.clone(),
                    cascade: Vec::new(),
                    generation: heimdall_domain::policy::AuthorityGeneration(0),
                    revoked_at: at,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
                tx.set_remote_revocation(&record(owed(1, false, None)))
            })
            .unwrap();
        let decide = |e: &AppliedEffect| {
            store
                .transaction(|tx| own_applied_effect_in(tx, &root, Some(e), cap))
                .unwrap()
        };
        let stored = || {
            store
                .transaction(|tx| tx.remote_revocation(&root))
                .unwrap()
                .unwrap()
        };
        // The rounds capped the record's obligation again (stopped at the cap).
        let cap_again = || {
            let mut r = stored();
            r.obligations[0].attempts = Some(cap);
            r.obligations[0].stopped = true;
            r.stopped = true;
            store
                .transaction(|tx| tx.set_remote_revocation(&r))
                .unwrap();
        };
        // Re-armed at the record's round 3, with the cap in force (the configured one).
        let assert_rearmed = |keys: &[RearmedEffect]| {
            let r = stored();
            assert!(!r.stopped);
            assert_eq!(r.obligations, vec![owed(0, false, Some(3))]);
            assert_eq!(r.rearmed_effects, keys);
            assert_eq!(r.cap, Some(cap));
        };
        let bounded = || EffectOwner::Bounded(vec![ident()]);
        let uncovered_owner = store
            .transaction(|tx| {
                own_applied_effect_in(tx, &uncovered, Some(&effect("eff_0", true)), cap)
            })
            .unwrap();
        assert_eq!(uncovered_owner, EffectOwner::Immediate);
        let live = stored();
        assert_eq!(decide(&effect("eff_1", false)), EffectOwner::Live);
        assert_eq!(
            stored(),
            record(owed(1, false, Some(3))),
            "a live obligation: only the effect is recorded, at round 3"
        );
        assert_ne!(stored(), live);
        // At the cap but not yet marked stopped (e.g. a failed completion).
        store
            .transaction(|tx| tx.set_remote_revocation(&record(owed(cap, false, None))))
            .unwrap();
        assert_eq!(decide(&effect("eff_1", false)), EffectOwner::Rearmed);
        let k1 = scoped("eff_1", false);
        assert_rearmed(std::slice::from_ref(&k1));
        cap_again();
        let capped = stored();
        assert_eq!(
            decide(&effect("eff_1", false)),
            bounded(),
            "the immediate call"
        );
        assert_eq!(stored(), capped, "a replay never re-arms twice");
        assert_eq!(decide(&effect("eff_1", true)), EffectOwner::Rearmed);
        let k1c = scoped("eff_1", true);
        assert_rearmed(&[k1.clone(), k1c.clone()]);
        cap_again();
        let capped = stored();
        assert_eq!(decide(&effect("eff_1", true)), bounded());
        assert_eq!(decide(&effect("eff_1", false)), bounded());
        assert_eq!(stored(), capped, "neither state re-arms twice");
        assert_eq!(decide(&effect("eff_2", true)), EffectOwner::Rearmed);
        assert_rearmed(&[k1, k1c, scoped("eff_2", true)]);
        // The record owes the grant to another adapter only: one is added.
        let other = Id {
            mechanism: "fake_other".into(),
            instance: "2".into(),
        };
        store
            .transaction(|tx| {
                tx.set_remote_revocation(&record(RemoteObligation {
                    adapter: other.clone(),
                    ..owed(1, false, None)
                }))
            })
            .unwrap();
        assert_eq!(decide(&effect("eff_3", true)), EffectOwner::Rearmed);
        let r = stored();
        assert_eq!(r.grants, vec![root.clone()]);
        assert_eq!(
            r.obligations,
            vec![
                RemoteObligation {
                    adapter: other,
                    ..owed(1, false, None)
                },
                owed(0, false, Some(3)),
            ]
        );
        assert_eq!(decide(&effect("eff_3", true)), EffectOwner::Live);
    }

    /// ⟨r2.15⟩ A store holding one pending record, rooted at `root`, built from its
    /// stored (JSON) form, so these cases read the same at every commit since §13.17.
    fn r1318_store(root: &GrantId, record: &serde_json::Value) -> Store {
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let at: Timestamp = "2026-10-02T00:00:00Z".parse().unwrap();
        let record: PendingRemoteRevocation = serde_json::from_value(record.clone()).unwrap();
        store
            .transaction(|tx| {
                tx.insert_tombstone(&Tombstone {
                    grant: root.clone(),
                    cascade: Vec::new(),
                    generation: heimdall_domain::policy::AuthorityGeneration(0),
                    revoked_at: at,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
                tx.set_remote_revocation(&record)
            })
            .unwrap();
        store
    }

    /// ⟨r2.15⟩ The effect an operation's receipts record: an attempt by `adapter`
    /// with `token`, confirmed afterwards.
    fn r1318_confirmed(adapter: &AdapterIdentity, token: &str) -> Option<AppliedEffect> {
        use EnsureStage as S;
        applied_effect(&[
            r(
                S::Reconcile,
                EffectReceipt::Attempted {
                    adapter: adapter.clone(),
                    effect_token: token.into(),
                },
            ),
            r(
                S::Reconcile,
                EffectReceipt::Confirmed {
                    adapter: adapter.clone(),
                    credential_ref: "c".into(),
                },
            ),
        ])
    }

    /// ⟨r2.15⟩ Mark every obligation of `root`'s record stopped at `cap` again, as
    /// the rounds of a re-armed obligation would.
    fn r1318_cap_again(store: &Store, root: &GrantId, cap: u32) {
        store
            .transaction(|tx| {
                let mut r = tx.remote_revocation(root)?.unwrap();
                for o in &mut r.obligations {
                    o.attempts = Some(cap);
                    o.stopped = true;
                }
                r.stopped = true;
                tx.set_remote_revocation(&r)
            })
            .unwrap();
    }

    /// Red at 8d17ace9 (ADR-0006 §13.18 item 4, [MEDIUM] "the re-arm bound key
    /// collides"). One record covers two grants whose responsible adapters differ,
    /// both obligations stopped at the cap. An effect for the first grant re-arms its
    /// obligation. An effect for the second grant, by the other adapter, with the
    /// same effect token and recorded state, is a different effect: it re-arms the
    /// second grant's obligation too, instead of being bounded by the first's re-arm.
    /// The bound is keyed by (grant, adapter, token, state).
    #[test]
    fn r1318_4_one_grants_rearm_never_bounds_another_grants_effect() {
        let cap = 3;
        let g1 = GrantId::from_random_bytes([21; 16]);
        let g2 = GrantId::from_random_bytes([22; 16]);
        let a = ident();
        let b = AdapterIdentity {
            mechanism: "fake_other".into(),
            instance: "2".into(),
        };
        let store = r1318_store(
            &g1,
            &serde_json::json!({
                "root": g1,
                "grants": [g1, g2],
                "attempts": 3,
                "last_attempt_at": "2026-10-02T00:00:00Z",
                "stopped": true,
                "obligations": [
                    {"grant": g1, "adapter": a, "attempts": 3, "stopped": true},
                    {"grant": g2, "adapter": b, "attempts": 3, "stopped": true},
                ],
            }),
        );
        let decide = |g: &GrantId, e: Option<AppliedEffect>| {
            store
                .transaction(|tx| own_applied_effect_in(tx, g, e.as_ref(), cap))
                .unwrap()
        };
        let owed = |g: &GrantId| {
            store
                .transaction(|tx| tx.remote_revocation(&g1))
                .unwrap()
                .unwrap()
                .obligations
                .into_iter()
                .find(|o| &o.grant == g)
                .unwrap()
        };
        assert_eq!(
            decide(&g1, r1318_confirmed(&a, "eff_1")),
            EffectOwner::Rearmed
        );
        assert_eq!(owed(&g1).attempts, Some(0));
        assert!(
            owed(&g2).stopped,
            "the other grant's obligation is untouched"
        );
        assert_eq!(
            decide(&g2, r1318_confirmed(&b, "eff_1")),
            EffectOwner::Rearmed,
            "another grant's re-arm never bounds this effect"
        );
        let o2 = owed(&g2);
        assert_eq!(o2.attempts, Some(0), "re-armed: {o2:?}");
        assert!(!o2.stopped);
    }

    /// Red at 8d17ace9 (ADR-0006 §13.18 item 4, [MEDIUM] "the re-arm bound key
    /// collides"). An effect with an empty token, or with no attempt on record at all
    /// (unknown), cannot be told apart from another such effect, so it is never
    /// treated as already re-armed: each one re-arms the capped obligation again.
    #[test]
    fn r1318_4_an_unknown_or_empty_token_is_never_bounded() {
        let cap = 3;
        let g = GrantId::from_random_bytes([23; 16]);
        let store = r1318_store(
            &g,
            &serde_json::json!({
                "root": g,
                "grants": [g],
                "attempts": 3,
                "last_attempt_at": "2026-10-02T00:00:00Z",
                "stopped": true,
                "obligations": [
                    {"grant": g, "adapter": ident(), "attempts": 3, "stopped": true},
                    {"grant": g, "adapter": {"mechanism": "", "instance": ""},
                     "attempts": 3, "stopped": true},
                ],
            }),
        );
        let decide = |e: Option<AppliedEffect>| {
            store
                .transaction(|tx| own_applied_effect_in(tx, &g, e.as_ref(), cap))
                .unwrap()
        };
        let live = || {
            let r = store
                .transaction(|tx| tx.remote_revocation(&g))
                .unwrap()
                .unwrap();
            !r.stopped
                && r.obligations
                    .iter()
                    .any(|o| !o.stopped && o.attempts == Some(0))
        };
        for (what, attempted) in [("empty token", true), ("unknown", false)] {
            let effect = || attempted.then(|| r1318_confirmed(&ident(), "")).flatten();
            for round in 0..2 {
                assert_eq!(
                    decide(effect()),
                    EffectOwner::Rearmed,
                    "{what}, replay {round}: never bounded"
                );
                assert!(live(), "{what}, replay {round}: re-armed");
                r1318_cap_again(&store, &g, cap);
            }
        }
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: a record written without a stored cap is
    /// judged by the cap production configures, the default back-off's.
    #[test]
    fn r1318_the_default_round_cap_is_the_default_backoffs() {
        assert_eq!(
            DEFAULT_ROUND_CAP,
            crate::reconcile::Backoff::default().max_attempts
        );
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 4: the answers of a bounded effect's immediate
    /// calls are tracked in the covering records. A confirmation changes nothing; a
    /// pending answer with an obligation on record keeps it as it is (stopped stays
    /// stopped: no re-arm) and with none adds a live one; an adapter that could not
    /// be called (not configured) gets its obligation re-armed, live, since no call
    /// was made after the effect. Each changed obligation carries the effect at the
    /// record's round.
    #[test]
    fn r1318_4_a_pending_answer_to_a_bounded_call_is_tracked() {
        let cap = 3;
        let g = GrantId::from_random_bytes([24; 16]);
        let other = AdapterIdentity {
            mechanism: "fake_other".into(),
            instance: "2".into(),
        };
        let store = r1318_store(
            &g,
            &serde_json::json!({
                "root": g,
                "grants": [g],
                "attempts": 4,
                "last_attempt_at": "2026-10-02T00:00:00Z",
                "stopped": true,
                "obligations": [
                    {"grant": g, "adapter": other, "attempts": 3, "stopped": true},
                ],
            }),
        );
        let track = |answers: &[(AdapterIdentity, Option<bool>)]| {
            store
                .transaction(|tx| track_bounded_answers_in(tx, &g, answers, cap))
                .unwrap();
            store
                .transaction(|tx| tx.remote_revocation(&g))
                .unwrap()
                .unwrap()
        };
        let before = track(&[]);
        assert_eq!(
            track(&[(ident(), Some(true))]),
            before,
            "confirmed: nothing"
        );
        let r = track(&[(ident(), Some(false))]);
        let added = r.obligations.iter().find(|o| o.adapter == ident()).unwrap();
        assert_eq!(
            (added.attempts, added.stopped, added.effect_seq),
            (Some(0), false, Some(4)),
            "a pending answer with no obligation adds one, live"
        );
        assert!(!r.stopped);
        let kept = r1318_cap_again_returning(&store, &g, cap);
        assert_eq!(
            track(&[(ident(), Some(false))]),
            kept,
            "a pending answer with an obligation keeps it as it is"
        );
        let r = track(&[(other.clone(), None)]);
        let rearmed = r.obligations.iter().find(|o| o.adapter == other).unwrap();
        assert_eq!(
            (rearmed.attempts, rearmed.stopped, rearmed.effect_seq),
            (Some(0), false, Some(4)),
            "no call: re-armed, live"
        );
        assert!(!r.stopped);
    }

    /// [`r1318_cap_again`], then the stored record.
    fn r1318_cap_again_returning(
        store: &Store,
        root: &GrantId,
        cap: u32,
    ) -> PendingRemoteRevocation {
        r1318_cap_again(store, root, cap);
        store
            .transaction(|tx| tx.remote_revocation(root))
            .unwrap()
            .unwrap()
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1, a record written before claim sequences (at
    /// 8263ee6c): three rounds claimed, the last one never completed (its process is
    /// gone), and an effect recorded by round. It is read with the sequence 3, and the
    /// effect conservatively at sequence 3. The next claim is sequence 4. A completion
    /// naming sequence 3 (the claim the old process left) is superseded and clears
    /// nothing; the current claim's confirmation, made after the effect, clears the
    /// obligation. The upgraded record is written in the current form.
    #[test]
    fn r1319_1_a_record_written_before_claim_seq_is_claimed_and_completed_by_sequence() {
        let g = GrantId::from_random_bytes([25; 16]);
        let store = Arc::new(r1318_store(
            &g,
            &serde_json::json!({
                "root": g,
                "grants": [g],
                "attempts": 3,
                "last_attempt_at": "2026-10-02T00:00:00Z",
                "stopped": false,
                "claimed_at": "2026-10-02T00:00:00Z",
                "obligations": [
                    {"grant": g, "adapter": ident(), "attempts": 3, "effect_round": 2},
                ],
            }),
        ));
        let now: Timestamp = "2026-10-02T00:01:00Z".parse().unwrap();
        let round = store
            .transaction(|tx| claim_retry_round_in(tx, &g, &[ident()], now, 8))
            .unwrap();
        let RetryClaim::Claimed(round, grants) = round else {
            panic!("a claimed round");
        };
        assert_eq!(
            round.claim,
            Some(4),
            "the next sequence after the derived one"
        );
        let stored = || {
            store
                .transaction(|tx| tx.remote_revocation(&g))
                .unwrap()
                .unwrap()
        };
        let r = stored();
        assert_eq!(r.claim_seq, Some(4));
        assert_eq!(r.obligations[0].effect_round, None, "migrated");
        assert_eq!(
            r.obligations[0].effect_seq,
            Some(3),
            "conservatively at the derived sequence"
        );
        let confirmed = RoundAnswers {
            answers: vec![(g.clone(), ident(), true)],
            adapter_expiry: None,
            ..RoundAnswers::default()
        };
        let env = EnvironmentId::from_random_bytes([26; 16]);
        // The publisher reads the store, so it is built outside the transaction.
        let publisher = EventPublisher::new(Arc::clone(&store), env);
        let complete = |claim: Option<u64>| {
            store
                .transaction(|tx| {
                    let mut emit = Emit {
                        publisher: publisher.clone(),
                        events: Vec::new(),
                        gates: crate::managed::SigningGates::new(),
                        narrowing_set: BTreeSet::new(),
                    };
                    complete_round_in(tx, &mut emit, &g, &grants, claim, &confirmed, Some(8), None)
                })
                .unwrap()
        };
        let stale = complete(Some(3));
        assert_eq!(
            stale.remote_pending,
            vec![g.clone()],
            "superseded: nothing cleared"
        );
        assert_eq!(
            stored().claimed_at,
            Some(now),
            "the current claim stays open"
        );
        let done = complete(Some(4));
        assert!(done.remote_pending.is_empty(), "{done:?}");
        assert!(
            store
                .transaction(|tx| tx.remote_revocation(&g))
                .unwrap()
                .is_none(),
            "cleared by the current claim, made after the effect"
        );
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 1: an explicit revoke's re-arm restarts the
    /// record's counts but never its claim sequence. A re-arm that calls nothing (no
    /// responsible adapter configured) keeps it as it was; the re-armed first round
    /// that calls gets a sequence greater than every earlier one, its round count
    /// restarted at 1.
    #[test]
    fn r1319_1_an_explicit_revokes_rearm_never_resets_the_claim_sequence() {
        let g = GrantId::from_random_bytes([30; 16]);
        let store = r1318_store(
            &g,
            &serde_json::json!({
                "root": g,
                "grants": [g],
                "attempts": 3,
                "last_attempt_at": "2026-10-02T00:00:00Z",
                "stopped": true,
                "obligations": [
                    {"grant": g, "adapter": ident(), "attempts": 3, "stopped": true},
                ],
                "claim_seq": 7,
            }),
        );
        let now: Timestamp = "2026-10-02T00:01:00Z".parse().unwrap();
        let stored = || {
            store
                .transaction(|tx| tx.remote_revocation(&g))
                .unwrap()
                .unwrap()
        };
        let round = store
            .transaction(|tx| {
                claim_first_round_in(tx, &g, std::slice::from_ref(&g), &[], now, true, 3)
            })
            .unwrap();
        assert_eq!(round.claim, None, "nothing configured: no call, no claim");
        let r = stored();
        assert_eq!((r.attempts, r.stopped), (0, false), "re-armed");
        assert_eq!(r.claim_seq, Some(7), "the sequence is kept");
        let round = store
            .transaction(|tx| {
                claim_first_round_in(tx, &g, std::slice::from_ref(&g), &[ident()], now, true, 3)
            })
            .unwrap();
        assert_eq!(round.claim, Some(8), "greater than every earlier claim");
        let r = stored();
        assert_eq!((r.attempts, r.claim_seq), (1, Some(8)));
    }

    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2, the decision written with the settlement
    /// ([`settle_effect_in`]):
    /// * no record covers the grant: the immediate call is owed by a cleanup intent
    ///   naming the effect, with a fresh version each time;
    /// * a live covering obligation owns the call of a confirmed effect: no intent,
    ///   and the earlier one is removed;
    /// * an attempt with no answer yet (its preparation may be in flight): an
    ///   in-flight intent even though the live obligation owns the call now.
    #[test]
    fn r1319_2_the_settlement_records_who_makes_the_call_after_the_effect() {
        use EnsureStage as S;
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let at: Timestamp = "2026-10-02T00:00:00Z".parse().unwrap();
        let g = GrantId::from_random_bytes([27; 16]);
        let op = OperationId::from_random_bytes([28; 16]);
        let attempted = r(
            S::Reconcile,
            EffectReceipt::Attempted {
                adapter: ident(),
                effect_token: "eff_1".into(),
            },
        );
        let confirmed = r(
            S::Reconcile,
            EffectReceipt::Confirmed {
                adapter: ident(),
                credential_ref: "c".into(),
            },
        );
        store
            .transaction(|tx| {
                let key = IdempotencyKey {
                    caller: CallerContext {
                        principal: heimdall_domain::principal::PrincipalRef::UnixUser { uid: 1 },
                        role: heimdall_domain::principal::ClientRole::Owner,
                    },
                    kind: OperationKind::Ensure,
                    request_id: heimdall_contract::ids::RequestId::parse("r1319-u").unwrap(),
                };
                let hash = heimdall_contract::canonical::RequestHash([0; 32]);
                tx.insert_operation(
                    &OperationRecord {
                        id: op.clone(),
                        kind: OperationKind::Ensure,
                        environment: EnvironmentId::from_random_bytes([29; 16]),
                        key: key.clone(),
                        request_hash: hash,
                        effect_class: EffectClass::LocalResources,
                        state: OperationState::Cancelled,
                        code: None,
                        effect_status: EffectStatus::Partial,
                        result: None,
                        created_at: at,
                        updated_at: at,
                        cancellation: None,
                        recovery: RecoveryMetadata::default(),
                    },
                    &IdempotencyRecord {
                        key,
                        request_hash: hash,
                        operation_id: op.clone(),
                        created_at: at,
                        expires_at: None,
                    },
                )?;
                tx.append_stage_receipt(&op, &attempted)
            })
            .unwrap();
        let settle = || {
            store
                .transaction(|tx| settle_effect_in(tx, &g, &op, 3, at))
                .unwrap()
        };
        let stored = || store.transaction(|tx| tx.cleanup_intent(&g, &op)).unwrap();
        // No record covers the grant; the attempt has no answer yet.
        let first = settle().expect("the immediate call is owed");
        assert_eq!(first.adapter, Some(ident()));
        assert_eq!(first.effect_token, "eff_1");
        assert!(first.in_flight && !first.confirmed);
        assert_eq!(stored(), Some(first.clone()));
        store
            .transaction(|tx| tx.append_stage_receipt(&op, &confirmed))
            .unwrap();
        let second = settle().expect("still uncovered");
        assert!(second.confirmed && !second.in_flight);
        assert!(second.version > first.version, "a fresh version");
        // A live covering obligation owns the call of the confirmed effect.
        store
            .transaction(|tx| {
                tx.insert_tombstone(&Tombstone {
                    grant: g.clone(),
                    cascade: Vec::new(),
                    generation: heimdall_domain::policy::AuthorityGeneration(0),
                    revoked_at: at,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })?;
                tx.set_remote_revocation(&PendingRemoteRevocation {
                    root: g.clone(),
                    grants: vec![g.clone()],
                    attempts: 1,
                    last_attempt_at: at,
                    stopped: false,
                    obligations: vec![obligation(&g, ident())],
                    claimed_at: None,
                    rearmed_effects: Vec::new(),
                    cap: Some(3),
                    claim_seq: Some(1),
                })
            })
            .unwrap();
        assert_eq!(settle(), None, "the live obligation owns it");
        assert_eq!(stored(), None, "the earlier intent is removed");
        let owed = store
            .transaction(|tx| tx.remote_revocation(&g))
            .unwrap()
            .unwrap()
            .obligations
            .remove(0);
        assert_eq!(
            owed.effect_seq,
            Some(1),
            "the effect recorded at the latest claim"
        );
        // A new attempt with no answer yet: owned now, but in flight.
        store
            .transaction(|tx| {
                tx.append_stage_receipt(
                    &op,
                    &r(
                        S::Reconcile,
                        EffectReceipt::Attempted {
                            adapter: ident(),
                            effect_token: "eff_2".into(),
                        },
                    ),
                )
            })
            .unwrap();
        let third = settle().expect("in flight: an intent all the same");
        assert!(third.in_flight);
        assert_eq!(third.effect_token, "eff_2");
    }

    /// ⟨r2.15⟩ ADR-0006 §13.18 item 4, the invariant as a property over the cleanup
    /// decision ([`decide_applied_effect`]): for any covering records (obligations of
    /// this grant and another, by exact, mechanism-only and unknown adapters, at any
    /// count, stopped or not, with or without a recorded effect; any stored cap; any
    /// re-armed keys, legacy unscoped ones included), any effect (known, empty or
    /// unknown token, either recorded state) and any configured cap, no outcome
    /// leaves an applied effect with neither a live owning obligation nor a call
    /// made after it. A live owning obligation carries the effect at or after the
    /// record's latest claim (⟨r2.16⟩ its sequence, §13.19 item 1), so no claim made
    /// so far, and no superseded one, can clear it (§13.18 item 2). Besides: a `Live` outcome re-arms nothing; an
    /// empty or unknown token is never bounded; a known key already recorded for
    /// (this grant, an adapter) without a live obligation always means the
    /// immediate call for that adapter, never a second re-arm.
    mod r1318_props {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::{FileFailurePersistence, RngSeed};

        /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
        fn config() -> ProptestConfig {
            let mut c = ProptestConfig {
                cases: 256,
                failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                    "proptest-regressions",
                ))),
                ..ProptestConfig::default()
            };
            if matches!(c.rng_seed, RngSeed::Random) {
                c.rng_seed = RngSeed::Fixed(0x5231_3331_385f_3034);
            }
            c
        }

        fn grant(i: usize) -> GrantId {
            GrantId::from_random_bytes([31 + u8::try_from(i).unwrap(); 16])
        }

        fn adapter(i: usize) -> AdapterIdentity {
            let (m, n) = [("fake", "1"), ("fake_other", "2"), ("fake", ""), ("", "")][i];
            AdapterIdentity {
                mechanism: m.into(),
                instance: n.into(),
            }
        }

        fn token(i: usize) -> String {
            ["", "t1", "t2"][i].into()
        }

        fn obligation_s() -> impl Strategy<Value = RemoteObligation> {
            (
                0..2usize,
                0..4usize,
                0..6u32,
                any::<bool>(),
                proptest::option::of(0..6u64),
            )
                .prop_map(|(g, a, attempts, stopped, effect_seq)| RemoteObligation {
                    grant: grant(g),
                    adapter: adapter(a),
                    reason: None,
                    attempts: Some(attempts),
                    stopped,
                    effect_round: None,
                    effect_seq,
                    // M03 wave 0 (A1): fail closed until U0b
                    kind: Default::default(),
                })
        }

        fn key_s() -> impl Strategy<Value = RearmedEffect> {
            (
                proptest::option::of(0..2usize),
                proptest::option::of(0..4usize),
                0..3usize,
                any::<bool>(),
            )
                .prop_map(|(g, a, t, confirmed)| RearmedEffect {
                    grant: g.map(grant),
                    adapter: a.map(adapter),
                    effect_token: token(t),
                    confirmed,
                })
        }

        fn record_s() -> impl Strategy<Value = PendingRemoteRevocation> {
            (
                0..6u32,
                any::<bool>(),
                proptest::collection::vec(obligation_s(), 0..4),
                proptest::option::of(1..6u32),
                proptest::collection::vec(key_s(), 0..3),
                proptest::option::of(0..8u64),
            )
                .prop_map(
                    |(attempts, stopped, obligations, cap, rearmed_effects, claim_seq)| {
                        let mut r = PendingRemoteRevocation {
                            root: grant(0),
                            grants: Vec::new(),
                            attempts,
                            last_attempt_at: "2026-10-02T00:00:00Z".parse().unwrap(),
                            stopped,
                            obligations,
                            claimed_at: None,
                            rearmed_effects,
                            cap,
                            claim_seq,
                        };
                        sync_obligation_grants(&mut r);
                        r
                    },
                )
        }

        /// The effect: a known attempt (its adapter applies it), or none on record
        /// (the grant's responsible adapters apply it).
        fn effect_s() -> impl Strategy<Value = (Vec<AdapterIdentity>, Option<RearmedEffect>)> {
            prop_oneof![
                (0..2usize, 0..3usize, any::<bool>()).prop_map(|(a, t, confirmed)| {
                    (
                        vec![adapter(a)],
                        Some(RearmedEffect {
                            grant: None,
                            adapter: None,
                            effect_token: token(t),
                            confirmed,
                        }),
                    )
                }),
                proptest::sample::subsequence(vec![0usize, 1, 2, 3], 1..=2)
                    .prop_map(|a| (a.into_iter().map(adapter).collect(), None)),
            ]
        }

        proptest! {
            #![proptest_config(config())]

            #[test]
            fn r1318_cleanup_never_leaves_an_applied_effect_unowned_and_uncalled(
                before in proptest::collection::vec(record_s(), 1..3),
                (applying, effect) in effect_s(),
                cap in prop_oneof![Just(1u32), Just(2), Just(3), Just(5), Just(NO_CONFIGURED_CAP)],
            ) {
                let g = grant(0);
                let mut after = before.clone();
                let (owner, changed) =
                    decide_applied_effect(&mut after, &g, &applying, effect.as_ref(), cap);
                let called: &[AdapterIdentity] = match &owner {
                    EffectOwner::Bounded(list) => list,
                    _ => &[],
                };
                prop_assert!(owner != EffectOwner::Immediate);
                for (i, (b, a)) in before.iter().zip(&after).enumerate() {
                    if !changed.contains(&i) {
                        prop_assert_eq!(b, a, "an unlisted record is unchanged");
                    }
                }
                let known = effect.as_ref().filter(|k| !k.effect_token.is_empty());
                for a in &applying {
                    let owned = after.iter().any(|r| {
                        let limit = r.round_cap(cap);
                        !r.stopped
                            && r.obligations.iter().any(|o| {
                                owes(o, &g, a)
                                    && !o.stopped
                                    && r.obligation_attempts(o) < limit
                                    && !o.cleared_by_claim(Some(r.current_claim_seq()))
                                    && !o.cleared_by_claim(None)
                            })
                    });
                    prop_assert!(
                        owned || called.contains(a),
                        "neither owned nor called: {:?} {:?} -> {:?}",
                        a, owner, after
                    );
                    if known.is_none() {
                        prop_assert!(!called.contains(a), "an unknown token is never bounded");
                    }
                    let was_live = before.iter().any(|r| owns_live(r, &g, a, cap));
                    if let Some(k) = known
                        && !was_live
                    {
                        let key = RearmedEffect {
                            grant: Some(g.clone()),
                            adapter: Some(a.clone()),
                            ..k.clone()
                        };
                        if before.iter().any(|r| r.rearmed_effects.contains(&key)) {
                            prop_assert!(called.contains(a), "bounded: the immediate call");
                        }
                    }
                }
                if owner == EffectOwner::Live {
                    let erase = |rs: &[PendingRemoteRevocation]| {
                        let mut rs = rs.to_vec();
                        for o in rs.iter_mut().flat_map(|r| r.obligations.iter_mut()) {
                            o.effect_seq = None;
                        }
                        rs
                    };
                    prop_assert_eq!(erase(&before), erase(&after), "live: nothing re-armed");
                }
            }
        }
    }

    /// ⟨M03; ADR-0008 §17.25 item 18⟩ `ensure_data` copies the managed adapter's six
    /// report fields from this process's outcome (`Facts::from_outcome`) for a
    /// `managed_certificate` binding only; after a restart (`Facts::conservative`, the
    /// stored facts) and from a leader's result (`Facts::from_data`) they stay absent,
    /// and any other mechanism's result is unchanged even if an outcome carried them.
    #[test]
    fn ensure_data_carries_managed_facts_only_from_this_process_outcome() {
        use heimdall_contract::managed::{
            ConnectionPolicyReport, ExistingConnectionsMode, LockContinuityReport, MultiplexingMode,
        };
        let now: Timestamp = "2026-10-02T00:10:00Z".parse().unwrap();
        let deadline: Timestamp = "2026-10-02T02:10:00Z".parse().unwrap();
        let grant = GrantSnapshot {
            id: GrantId::from_random_bytes([0x18; 16]),
            environment: EnvironmentId::from_random_bytes([0x17; 16]),
            scope: Scope {
                pairs: BTreeSet::new(),
                capabilities: BTreeSet::new(),
            },
            starts_at: now,
            deadline: heimdall_domain::time::Deadline {
                intent: heimdall_contract::request::DeadlineIntent::Duration("2h".to_owned()),
                resolved_at: now,
                effective: deadline,
            },
            parent: None,
            source: heimdall_domain::grant::AuthorizationSource::StandingPolicy {
                revision: heimdall_domain::policy::PolicyRevision(1),
            },
            generation: heimdall_domain::policy::AuthorityGeneration(1),
            state: GrantState::Active,
            enforcement: EnforcementEvidence::unknown(),
        };
        let binding = |mechanism: &str| BindingRecord {
            id: heimdall_contract::ids::BindingId::from_random_bytes([0x19; 16]),
            environment: grant.environment.clone(),
            grant: grant.id.clone(),
            work_id: WorkId::parse("w-r2").unwrap(),
            owner: CallerContext {
                principal: heimdall_domain::principal::PrincipalRef::UnixUser { uid: 1 },
                role: heimdall_domain::principal::ClientRole::Owner,
            },
            profile: heimdall_contract::ids::ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope: grant.scope.clone(),
            mechanism: mechanism.to_owned(),
            parent: None,
            created_at: now,
            released_at: None,
            state: heimdall_domain::binding::BindingState::Active,
        };
        let policy = ConnectionPolicyReport {
            existing: ExistingConnectionsMode::Strict,
            multiplexing: MultiplexingMode::Disabled,
            wording: "Connections Heimdall started are closed at the deadline.".to_owned(),
        };
        let outcome = PrepareOutcome {
            usable_until: deadline,
            offline_until: deadline,
            refresh_dependency: RefreshDependency::LocalIssuer,
            enforcement: EnforcementEvidence::unknown(),
            credential_ref: "fixture".to_owned(),
            availability: CredentialAvailability::ThroughDeadline,
            provider: None,
            integration: ConsumerIntegration::default(),
            managed: Some(crate::ports::ManagedResultFacts {
                lock_continuity: LockContinuityReport::Verified,
                conditions: Vec::new(),
                refresh_condition: heimdall_contract::managed::RefreshCondition {
                    needed_only_after: heimdall_contract::managed::RefreshTrigger::SignerRestart,
                    source: RefreshDependency::LocalIssuer,
                },
                revocation: serde_json::from_value(serde_json::json!({
                    "local": "immediate",
                    "remote": "unbounded_unknown",
                    "destination_clock": "unmeasured",
                }))
                .unwrap(),
                evidence: Vec::new(),
                connection_policy: policy.clone(),
            }),
        };
        let managed = binding(MANAGED_CERTIFICATE);
        let fresh = ensure_data(&managed, &grant, &Facts::from_outcome(&outcome), deadline);
        assert_eq!(fresh.connection_policy, Some(policy));
        assert_eq!(fresh.lock_continuity, Some(LockContinuityReport::Verified));
        assert!(fresh.refresh_condition.is_some() && fresh.revocation.is_some());
        let absent = |d: &EnsureData| {
            d.lock_continuity.is_none()
                && d.conditions.is_empty()
                && d.refresh_condition.is_none()
                && d.revocation.is_none()
                && d.evidence.is_empty()
                && d.connection_policy.is_none()
        };
        // After a restart: the stored facts, conservative.
        let restarted = ensure_data(
            &managed,
            &grant,
            &Facts::conservative(&grant, None, now),
            deadline,
        );
        assert!(absent(&restarted), "{restarted:?}");
        // From a leader's result (an attached binding).
        assert!(absent(&ensure_data(
            &managed,
            &grant,
            &Facts::from_data(&fresh),
            deadline
        )));
        // Another mechanism: never, so M01/M02 results stay byte-identical.
        let other = ensure_data(
            &binding("fake_agent"),
            &grant,
            &Facts::from_outcome(&outcome),
            deadline,
        );
        assert!(absent(&other), "{other:?}");
    }
}
