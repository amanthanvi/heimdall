//! Supervisor, deadline scheduler and time guard (spec §13.5, §6.4, §11.5 "one
//! supervisor owns retries for a resource"; R-RT-01, R-RT-06; overview §4.3;
//! ADR-0005 §3.6).
//!
//! * **Cleanup executor** (m01-plan U8 ⟨r2.1⟩ N06): the supervisor is the single
//!   owner of resource cleanup and of every retry of it. One pass reads the
//!   records whose desired and observed states differ, plans each
//!   (`reconcile::plan`), runs the deletion-boundary hook
//!   ([`heimdall_app::reconcile::CleanupHook`], `Decided`), re-reads the record and
//!   guards on its generation (`reconcile::guard_cleanup`; a replacement N+1 is
//!   `Superseded` and left alone), runs the hook again (`Guarded`), then calls the
//!   generation-bound [`heimdall_app::ports::ResourceCleaner::delete`] and records
//!   `observed = absent` with a generation CAS. `AdapterError::Unavailable` is
//!   retried by this one executor with `reconcile::Backoff` **and jitter**
//!   ([`retry_delay`]: `delay(n) * (0.5 + 0.5 * unit)` from the injectable
//!   [`Jitter`] source, [`RandomJitter`] in production, deterministic in tests;
//!   ADR-0006 §13.6 item 4, spec §13.5), delays on the continuous clock, attempts
//!   capped by `Backoff::max_attempts`; then the resource stops being retried and
//!   a stable code (`SERVICE_UNAVAILABLE`) is published as a `resource_changed`
//!   event. No operation, decision record or prompt is ever created by a retry,
//!   and nothing else retries a resource. M01 has no repair executor (no repair
//!   port exists before the M02 adapters); when it arrives it uses the same
//!   [`retry_delay`]. A failed scheduler pass is retried by the loop after a
//!   jittered delay too.
//! * **Pending remote revocations** (⟨r2.7⟩ ADR-0006 §13.10 item 3; spec §12.3,
//!   §13.5): when local denial left a revocation's remote effect pending
//!   (`heimdall_domain::revocation::PendingRemoteRevocation`, one durable record
//!   per tombstoned root), this supervisor is the only caller of the repeated
//!   adapter `revoke()` rounds for it ([`Supervisor::revocation_pass`], run by every
//!   scheduler pass). Round `n + 1` is due [`retry_delay`]`(backoff, n, jitter)`
//!   after the pass that saw round `n` (continuous clock; the same injectable
//!   [`Jitter`]; the backoff is [`Supervisor::with_revocation_backoff`], default
//!   `Backoff::default()`), rounds are capped by `Backoff::max_attempts` (the
//!   first local denial counts; the count is durable, so a restart never resets
//!   it), and once capped the record is `stopped`: the grant stays `revoking` with
//!   its remote part visible, and nothing calls the adapters or reports again until
//!   an explicit `revoke` (a fresh record) or a round that finds nothing pending.
//!   A round emits no event except a grant's own `revoking → revoked` change.
//!   ⟨r2.9⟩ ADR-0006 §13.12: the count is the number of rounds **claimed** (durably,
//!   before any adapter call), so a round whose completion failed or was
//!   interrupted still counts and the cap bounds the calls; a round that found no
//!   responsible adapter configured calls nothing and consumes no attempt, and the
//!   next one is backed off further (`RevocationReport::waiting`).
//!   ⟨r2.10⟩ ADR-0006 §13.13: the cap counts each (grant, adapter) obligation's own
//!   rounds, so one adapter's rounds never exhaust another's obligation and the
//!   record stops only when every obligation has cleared or reached its cap; at
//!   startup a round a previous run claimed and never completed is due at once (it
//!   still counts).
//!   ⟨r2.14⟩ ADR-0006 §13.17: a stopped record can be re-armed by a credential
//!   effect applied late for a grant it covers. The re-armed record is scheduled
//!   from its count like any record seen again, and its re-armed obligation gets its
//!   own cap of rounds. The supervisor gives the operations its cap
//!   (`Operations::set_revocation_cap`), so they can tell whether a covering
//!   obligation is still live.
//!   ⟨r2.15⟩ ADR-0006 §13.18 item 3: each record stores the cap in force when it was
//!   created or re-armed, and is judged by the lower of that cap and this
//!   supervisor's (`PendingRemoteRevocation::round_cap`), the same way restart
//!   recovery judges it before any supervisor exists.
//!   ⟨r2.16⟩ ADR-0006 §13.19 item 2: every revocation pass also processes the
//!   recoverable cleanup intents (`heimdall_domain::revocation::CleanupIntent`) that
//!   operations settled with an applied credential effect left behind
//!   (`Operations::process_cleanup_intents`), whatever the operation's state.
//!   ⟨M02⟩ m02-plan U0b row 24 (ADR-0006 §13.20 item 3): every adapter call is
//!   bounded (`Limits::adapter_call_timeout`), so a preparation that hangs after its
//!   effect is answered `Uncertain` at the bound and its preparing marker released.
//!   An intent written with `in_flight` while it hung is then no longer skipped, and
//!   the next pass processes it in this same process, with no restart. Each call a
//!   pass makes is bounded the same way, so no pass waits on an adapter for longer
//!   than the bound per call.
//! * **Caller operations are not retried here.** An operation whose adapter
//!   `prepare` reports `Unavailable` is answered once with
//!   `SERVICE_UNAVAILABLE` (exit 5) by the operations path and is not retried by
//!   the supervisor or a restart; the caller retries with the same request ID
//!   (ADR-0006 §13.6 item 4).
//!   M01 operations create no managed resources and M01 configures no
//!   `ResourceCleaner` (the M02 adapters add both); the executor runs only when
//!   [`Supervisor::with_cleaner`] supplied one.
//! * The deadline scheduler sleeps until the earliest persisted absolute deadline
//!   or budget end, re-reads on wake/restart, and calls `Operations::tick`. Sleep
//!   does not suspend deadlines: on wake it re-evaluates immediately against the
//!   continuous clock.
//! * The time guard runs the **shared** gate (`Operations::timegate`) every
//!   `anchor_interval` and after any wake; the gate persists the anchor and the
//!   high-water mark on `Safe`. There is no separate supervisor-private flag
//!   (review F01): every admission, signature and issuance consults the same gate.
//!
//! * ⟨M02⟩ **Holder pass** (m02-plan U8; ADR-0007 §8 "Holder process", Q5 as
//!   qualified): every [`SupervisorConfig::holder_interval`], jittered like every
//!   supervisor-owned repetition (`interval * (0.5 + 0.5 * unit)`, ADR-0006 §13.6 item
//!   4), [`Supervisor::holder_pass`] calls `Operations::release_exited_holders`, which
//!   releases each active launch binding whose exact holder process (PID and start
//!   time) is observed exited; it observes at most
//!   `heimdall_app::holders::MAX_HOLDERS_PER_PASS` bindings per pass. Liveness is
//!   [`PlatformLiveness`] (the M01 [`crate::platform::process_start_time`]) unless
//!   [`Supervisor::with_liveness`] replaced it. `Unknown` never releases. A failed pass
//!   is logged and the next one runs on schedule.
//!
//! * ⟨M03⟩ **Managed credentials, wave 0** (m03-plan U0b rows 6, 7, 8):
//!   - every revocation pass that finds a `bounded_by_expiry` obligation runs
//!     `Operations::settle_bounded_obligations` (ADR-0008 D7 item 3): such
//!     obligations move on safe time only, with no adapter call and no attempt
//!     counted, and a record of bounded obligations only gets no adapter round (a
//!     record holding a `nominally_expired` obligation is kept, ADR-0008 §17.15); the
//!     scheduler also wakes when a bound may have passed ([`RevocationReport::bounded`]);
//!   - with an adapter declaring a remote credential effect configured, a cleanup
//!     intent that a processing kept (a timed-out immediate call, ADR-0008 D7 item 5)
//!     is processed again only after [`retry_delay`] and at most
//!     `Backoff::max_attempts` times in this process; otherwise the M02 behaviour
//!     (every intent, every pass) is unchanged;
//!   - [`Supervisor::managed_reissue_pass`] runs beside the scheduler pass: the hook
//!     for re-issuing lost credentials (U6/U10), a no-op while the managed adapter is
//!     unregistered.
//!
//! * ⟨M03⟩ **Wave 4** (m03-plan U10), with [`Supervisor::with_connections`]: after every
//!   `tick`, [`Supervisor::connection_end_sweep`] closes the owned connections of the
//!   grants that ended (deadline or cutoff, revocation, release; by their stored state),
//!   with the `Connection` events ([`ManagedConnections`]); when the time gate leaves
//!   `Safe`, `time_uncertain_close`; and every [`SupervisorConfig::managed_interval`]
//!   ([`Supervisor::managed_pass`]) the sweep again (the retry of a discovery failure:
//!   the durable rows are the cleanup intent, D7 item 2), the reap pass,
//!   `Operations::issuer_supervision_pass`, `reverify_pass` and
//!   `enrollment_step_timeout_pass`. With [`Supervisor::with_session_lock`] the lock
//!   passes (`heimdall_app::lock::run_lock_passes`) run beside the loops. The holder
//!   pass stays M02's.
//!
//! **Wake-ups.** [`Supervisor::run`] runs the time guard at start and every
//! `anchor_interval`, and a scheduler pass at start, at the next wake instant a
//! pass returns (never later than `max_idle_sleep`), shortly after any committed
//! state change (a policy cutoff, a new grant), and immediately after the time
//! guard returns to `Safe` or the continuous clock shows the machine slept. The
//! scheduler is bookkeeping: admission is enforced at every use by the gate and
//! `admission`, so a late wake never lets a grant be used past its bound.
//!
//! **Resume detection (review B04).** No platform resume notification is used:
//! the loop's wait is bounded by [`SupervisorConfig::resume_check_interval`]
//! (default 2 s, clamped to at most [`MAX_RESUME_CHECK_INTERVAL`] = 5 s and at
//! least [`MIN_RESUME_CHECK_INTERVAL`]), so after a resume the next bounded wake
//! (at most that much awake time later, even where the timer's monotonic clock
//! excludes suspend) compares continuous-clock progress with monotonic progress
//! and, on a sleep, runs the time guard and a scheduler pass at once. A bounded
//! wake that finds no sleep and nothing due does only that comparison (one clock
//! read, no store access), keeping idle cost negligible. Native suspend/resume
//! evidence with production intervals is an M04 item.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::error::Completed;
use heimdall_app::lock::LockPassConfig;
use heimdall_app::operations::{BoundedReport, IntentOutcome, only_bounded};
use heimdall_app::ports::{
    AdapterError, ConnError, ConnectionControl, ProcessLiveness, ResourceCleaner, SessionLockSource,
};
use heimdall_app::{OpError, OpResult, Operations};
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::ConnectionId;
use heimdall_contract::managed::{CloseReason, ConnectionEventKind, ConnectionEventPayload};
use heimdall_domain::connection::ConnectionKind;
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};
use heimdall_domain::scope::AccessPair;

use crate::connections::{ConnectionSupervisor, PassReport, PassResult};
use heimdall_app::reconcile::{
    Action, Backoff, CleanupHook, CleanupPoint, guard_cleanup, plan, should_retry,
};
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{BindingId, GrantId, OperationId, ResourceId};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::holder::{HolderState, ProcessHolder};
use heimdall_domain::resource::{
    CleanupDecision, ManagedResource, ResourceGeneration, ResourceState,
};
use heimdall_domain::time::{Clock, TimePolicy, TimeStatus};
use heimdall_store::Store;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Supervisor tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// How often to run the time guard while idle.
    pub anchor_interval: Duration,
    /// Maximum sleep between scheduler wake-ups even with no deadline (bounded
    /// polling, not a tight loop; spec §15.1 idle budgets).
    pub max_idle_sleep: Duration,
    /// Time policy in force (informational; the gate inside `Operations` holds the
    /// authoritative copy).
    pub time_policy: TimePolicy,
    /// Longest the loop waits before re-checking whether the machine slept
    /// (review B04): a resume is detected within this much awake time. Clamped
    /// to `[MIN_RESUME_CHECK_INTERVAL, MAX_RESUME_CHECK_INTERVAL]` by
    /// [`Self::resume_bound`]; default 2 s.
    pub resume_check_interval: Duration,
    /// ⟨M02⟩ m02-plan U8: the base interval of the holder pass (each wait is jittered
    /// into `[interval / 2, interval]`); clamped to at least
    /// [`MIN_HOLDER_INTERVAL`]. Default [`DEFAULT_HOLDER_INTERVAL`].
    pub holder_interval: Duration,
    /// ⟨M03⟩ wave 4 (m03-plan U10): the base interval of the M03 passes (the
    /// connection-end sweep, the reap pass, issuer supervision, re-verification and the
    /// enrollment step timeout), jittered like the holder pass and clamped to at least
    /// [`MIN_HOLDER_INTERVAL`]. Default [`DEFAULT_MANAGED_INTERVAL`]. Used only by a
    /// supervisor with M03 wiring ([`Supervisor::with_connections`]).
    pub managed_interval: Duration,
}

/// ⟨M03⟩ Default base interval of the M03 passes.
pub const DEFAULT_MANAGED_INTERVAL: Duration = Duration::from_secs(5);

/// ⟨M02⟩ Default base interval of the holder pass.
pub const DEFAULT_HOLDER_INTERVAL: Duration = Duration::from_secs(5);

/// ⟨M02⟩ Lower bound of [`SupervisorConfig::holder_interval`] (never a tight loop).
pub const MIN_HOLDER_INTERVAL: Duration = Duration::from_millis(20);

/// Upper bound of [`SupervisorConfig::resume_check_interval`]: a resume is
/// detected within at most 5 s of awake time.
pub const MAX_RESUME_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Lower bound of [`SupervisorConfig::resume_check_interval`] (never a tight
/// loop, spec §15.1).
pub const MIN_RESUME_CHECK_INTERVAL: Duration = Duration::from_millis(10);

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            anchor_interval: Duration::from_secs(60),
            max_idle_sleep: Duration::from_secs(300),
            time_policy: TimePolicy::default(),
            resume_check_interval: Duration::from_secs(2),
            holder_interval: DEFAULT_HOLDER_INTERVAL,
            managed_interval: DEFAULT_MANAGED_INTERVAL,
        }
    }
}

impl SupervisorConfig {
    /// The effective resume-check interval: `resume_check_interval` clamped to
    /// `[MIN_RESUME_CHECK_INTERVAL, MAX_RESUME_CHECK_INTERVAL]`.
    #[must_use]
    pub fn resume_bound(&self) -> Duration {
        self.resume_check_interval
            .clamp(MIN_RESUME_CHECK_INTERVAL, MAX_RESUME_CHECK_INTERVAL)
    }
}

/// Delay between a committed state change and the scheduler pass it triggers
/// (coalesces bursts of events into one pass).
const CHANGE_DEBOUNCE: Duration = Duration::from_millis(250);

/// Back-off after a failed scheduler pass (store unavailable and similar); the
/// failure is retried by this one loop, never by a second one.
const FAILED_PASS_RETRY: Duration = Duration::from_secs(5);

/// Continuous-clock progress beyond monotonic progress that counts as a system
/// sleep (re-evaluate immediately on wake).
const SLEEP_DETECTION: Duration = Duration::from_secs(2);

/// Source of retry jitter (spec §13.5 "bounded backoff and jitter"; ADR-0006
/// §13.6 item 4). Production uses [`RandomJitter`]; tests inject a deterministic
/// source with [`Supervisor::with_jitter`].
pub trait Jitter: Send + Sync {
    /// A value in `[0, 1]`; out-of-range values are clamped by the user.
    fn unit(&self) -> f64;
}

/// Production jitter from the operating system's CSPRNG (`heimdall_app::ids`).
/// If randomness is unavailable the unit is `1.0`: the full, unjittered delay, so
/// a failure never shortens a retry interval.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomJitter;

impl Jitter for RandomJitter {
    fn unit(&self) -> f64 {
        match heimdall_app::ids::random_u64() {
            // 53 random bits: uniform in [0, 1).
            Ok(v) => (v >> 11) as f64 / (1u64 << 53) as f64,
            Err(_) => 1.0,
        }
    }
}

/// A constant jitter unit (tests; `FixedJitter(1.0)` reproduces the unjittered
/// schedule).
#[derive(Debug, Clone, Copy)]
pub struct FixedJitter(pub f64);

impl Jitter for FixedJitter {
    fn unit(&self) -> f64 {
        self.0
    }
}

/// The delay before retry `attempt` (1-based) of a supervisor-owned retry: the
/// bounded exponential backoff with equal jitter, `delay(attempt) * (0.5 + 0.5 *
/// unit)`, so it lies in `[delay/2, delay]` and never exceeds `backoff.max`.
#[must_use]
pub fn retry_delay(backoff: &Backoff, attempt: u32, jitter: &dyn Jitter) -> Duration {
    backoff.jittered(attempt, jitter.unit())
}

/// ⟨M02⟩ Holder liveness through the M01 [`crate::platform::process_start_time`] (Q5
/// as qualified; ADR-0007 §8):
/// * the start token of the process now at the holder's PID equals the holder's:
///   `Alive`;
/// * another token (the PID was reused): `Exited`, since that exact process is gone;
/// * no token: `Exited` when the same query succeeds for this runtime's own process,
///   so the platform query works here and the holder is gone or has exited (Linux
///   and Windows report an exited, unreaped process as gone); otherwise `Unknown`,
///   which never releases.
///
/// The holder is the same user as the runtime (the control endpoint is owner-only),
/// so a query failing for permission is not expected; such a failure would read as
/// an exit (a residual, reported).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformLiveness;

impl ProcessLiveness for PlatformLiveness {
    fn state(&self, holder: &ProcessHolder) -> HolderState {
        match crate::platform::process_start_time(holder.pid) {
            Some(token) if token == holder.started_at => HolderState::Alive,
            Some(_) => HolderState::Exited,
            None if crate::platform::process_start_time(std::process::id()).is_some() => {
                HolderState::Exited
            }
            None => HolderState::Unknown,
        }
    }
}

/// Runs the resource owners, the deadline scheduler and the time guard.
pub struct Supervisor {
    operations: Operations,
    config: SupervisorConfig,
    state: Option<(Arc<Store>, Arc<dyn Clock>)>,
    cleanup: Option<tokio::sync::Mutex<CleanupExecutor>>,
    revocations: tokio::sync::Mutex<RevocationRetries>,
    jitter: Arc<dyn Jitter>,
    /// ⟨M02⟩ U8: where the holder pass reads liveness.
    liveness: Arc<dyn ProcessLiveness>,
    /// ⟨M03⟩ U0b row 7: the back-off of kept cleanup intents, per (grant,
    /// operation), when an adapter with a remote credential effect is configured.
    intents: tokio::sync::Mutex<HashMap<(GrantId, OperationId), IntentRetry>>,
    /// ⟨M03⟩ wave 4: connection control and the M03 passes (`None`: an M01/M02
    /// supervisor, unchanged).
    managed: Option<ManagedSupervision>,
    /// ⟨M03⟩ wave 4 (U9): the session-lock source the lock passes read.
    lock: Option<(Arc<dyn SessionLockSource>, LockPassConfig)>,
}

/// ⟨M03⟩ U0b row 7 (ADR-0007 §12.13; ADR-0008 D7 item 5): the retry schedule of one
/// kept cleanup intent version (in memory: a restart processes every intent once
/// again, then schedules afresh, still bounded by the cap).
#[derive(Debug, Clone, Copy)]
struct IntentRetry {
    /// The intent version this schedule belongs to (a rewritten intent starts over).
    version: u64,
    /// Processings so far that left it on record.
    attempts: u32,
    /// Continuous-clock instant of the next processing.
    at: Duration,
    /// The cap was reached: not processed again in this process.
    stopped: bool,
}

/// ⟨r2.7⟩ The single owner of the repeated adapter `revoke()` rounds for pending
/// remote revocations (ADR-0006 §13.10 item 3): its backoff and, per tombstoned
/// root, the attempt count the next round was scheduled for and that round's
/// continuous-clock instant (in memory; the attempt count itself is durable).
struct RevocationRetries {
    backoff: Backoff,
    due: HashMap<GrantId, ScheduledRound>,
}

/// ⟨r2.9⟩ The next round of one root: the durable attempt count it was scheduled
/// for, its continuous-clock instant, and how many rounds in a row found no
/// responsible adapter configured (ADR-0006 §13.12 item 2: no attempt consumed,
/// but each such round backs off further, so nothing spins).
#[derive(Debug, Clone, Copy)]
struct ScheduledRound {
    attempts: u32,
    at: Duration,
    idle: u32,
}

/// ⟨r2.7⟩ What one revocation retry pass did (tests and telemetry; ADR-0006
/// §13.10 item 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationReport {
    /// Rounds scheduled in this pass: `(root, attempts so far, delay until the
    /// next round)`.
    pub scheduled: Vec<(GrantId, u32, Duration)>,
    /// Rounds run in this pass: `(root, attempts after the round)`.
    pub retried: Vec<(GrantId, u32)>,
    /// Roots whose remote part completed in this pass (nothing pending any more).
    pub completed: Vec<GrantId>,
    /// Roots whose capped retries stopped in this pass.
    pub stopped: Vec<GrantId>,
    /// Continuous-clock delay until the earliest scheduled round, if any.
    pub next_due_in: Option<Duration>,
    /// ⟨r2.9⟩ Roots whose due round in this pass called no adapter because no
    /// adapter responsible for any obligation is configured (ADR-0006 §13.12 item
    /// 2): no attempt consumed; the next round is backed off further.
    pub waiting: Vec<GrantId>,
    /// ⟨M03⟩ U0b row 6: what the bounded-obligation step did (run only when a
    /// record holds a `bounded_by_expiry` obligation; `None` otherwise).
    pub bounded: Option<BoundedReport>,
    /// ⟨M03⟩ U0b row 7: kept cleanup intents scheduled for another processing:
    /// `(grant, operation, processings so far, delay until the next)`.
    pub intents_scheduled: Vec<(GrantId, OperationId, u32, Duration)>,
    /// ⟨M03⟩ U0b row 7: kept cleanup intents that reached the cap in this pass (not
    /// processed again in this process; restart recovery processes them once more).
    pub intents_stopped: Vec<(GrantId, OperationId)>,
}

/// The single cleanup executor's port, hook, backoff and per-resource retry state.
struct CleanupExecutor {
    cleaner: Arc<dyn ResourceCleaner>,
    hook: Arc<dyn CleanupHook>,
    backoff: Backoff,
    retries: HashMap<ResourceId, Retry>,
}

/// Retry bookkeeping for one resource generation (in memory: a restart starts the
/// count afresh, still bounded by the cap).
#[derive(Debug, Clone, Copy)]
struct Retry {
    generation: ResourceGeneration,
    attempts: u32,
    /// Continuous-clock instant of the next attempt.
    next_due: Duration,
    /// Attempts exhausted or a non-transient failure: never retried again for this
    /// generation.
    stopped: bool,
}

/// What one cleanup pass did (tests and telemetry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Resources whose generation-bound delete succeeded and was recorded.
    pub deleted: Vec<ResourceId>,
    /// Cleanups whose resource was replaced by a newer generation (left alone).
    pub superseded: Vec<ResourceId>,
    /// Transient failures with a retry scheduled: `(resource, attempts so far,
    /// delay until the next attempt)`.
    pub retry_scheduled: Vec<(ResourceId, u32, Duration)>,
    /// Cleanups that stopped retrying, with their stable code.
    pub failed: Vec<(ResourceId, Code)>,
    /// Continuous-clock delay until the earliest scheduled retry, if any.
    pub next_due_in: Option<Duration>,
}

impl std::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Supervisor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// New supervisor over the shared operations (clock, sync and gate live there).
    ///
    /// Without [`Self::with_state`] the scheduler cannot read persisted deadlines
    /// and wakes every `max_idle_sleep` (and on every committed change).
    #[must_use]
    pub fn new(operations: Operations, config: SupervisorConfig) -> Self {
        // ⟨r2.14⟩ ADR-0006 §13.17 item 1: the operations judge a covering
        // obligation live against this supervisor's cap.
        operations.set_revocation_cap(Backoff::default().max_attempts);
        Self {
            operations,
            config,
            state: None,
            cleanup: None,
            revocations: tokio::sync::Mutex::new(RevocationRetries {
                backoff: Backoff::default(),
                due: HashMap::new(),
            }),
            jitter: Arc::new(RandomJitter),
            liveness: Arc::new(PlatformLiveness),
            intents: tokio::sync::Mutex::new(HashMap::new()),
            managed: None,
            lock: None,
        }
    }

    /// ⟨M03⟩ wave 4 (m03-plan U10): run the M03 passes over `connections` (module docs):
    /// the connection-end sweep after every `tick`, `time_uncertain_close` when the gate
    /// leaves `Safe`, and every [`SupervisorConfig::managed_interval`] the sweep again,
    /// the reap pass, issuer supervision, re-verification and the enrollment step
    /// timeout.
    #[must_use]
    pub fn with_connections(mut self, connections: Arc<ManagedConnections>) -> Self {
        self.managed = Some(ManagedSupervision {
            connections,
            finished: tokio::sync::Mutex::new(std::collections::BTreeSet::new()),
            uncertain_close_owed: std::sync::atomic::AtomicBool::new(false),
            end_cleanup: None,
        });
        self
    }

    /// ⟨M03⟩ wave 4, round 2 (ADR-0008 §17.21 item 11): the managed adapter's
    /// end-of-grant cleanup (`StoreCleanup` behind the runtime's late binding), which
    /// [`Self::ended_slot_pass`] runs for every ended grant that still holds a slot.
    /// Effective only after [`Self::with_connections`].
    #[must_use]
    pub fn with_end_cleanup(
        mut self,
        cleanup: Arc<dyn heimdall_adapters::managed::EndCleanup>,
    ) -> Self {
        if let Some(m) = self.managed.as_mut() {
            m.end_cleanup = Some(cleanup);
        }
        self
    }

    /// ⟨M03⟩ wave 4 (U9): drive `heimdall_app::lock::run_lock_passes` over `source`
    /// beside the other loops in [`Self::run`], until shutdown.
    #[must_use]
    pub fn with_session_lock(
        mut self,
        source: Arc<dyn SessionLockSource>,
        config: LockPassConfig,
    ) -> Self {
        self.lock = Some((source, config));
        self
    }

    /// ⟨r2.7⟩ Bound the repeated adapter `revoke()` rounds of pending remote
    /// revocations by `backoff` (default `Backoff::default()`; ADR-0006 §13.10
    /// item 3). `max_attempts` caps every round of a record, the first local
    /// denial included.
    #[must_use]
    pub fn with_revocation_backoff(self, backoff: Backoff) -> Self {
        self.operations.set_revocation_cap(backoff.max_attempts);
        Self {
            revocations: tokio::sync::Mutex::new(RevocationRetries {
                backoff,
                due: HashMap::new(),
            }),
            ..self
        }
    }

    /// Replace the retry jitter source (default [`RandomJitter`]); tests inject a
    /// deterministic one (ADR-0006 §13.6 item 4).
    #[must_use]
    pub fn with_jitter(mut self, jitter: Arc<dyn Jitter>) -> Self {
        self.jitter = jitter;
        self
    }

    /// ⟨M02⟩ Replace where the holder pass reads liveness (default
    /// [`PlatformLiveness`]); tests inject a scripted one.
    #[must_use]
    pub fn with_liveness(mut self, liveness: Arc<dyn ProcessLiveness>) -> Self {
        self.liveness = liveness;
        self
    }

    /// ⟨M02⟩ One holder pass (m02-plan U8; module docs): release every active launch
    /// binding whose exact holder process is observed exited. Returns the bindings
    /// released.
    ///
    /// # Errors
    /// The store cannot be read (`STATE_UNAVAILABLE`).
    pub async fn holder_pass(&self) -> Result<Vec<BindingId>, heimdall_app::OpError> {
        self.operations
            .release_exited_holders(self.liveness.as_ref())
            .await
            .map(|done| done.data)
    }

    /// ⟨M02⟩ The jittered wait before the next holder pass: `[interval / 2,
    /// interval]`, the interval clamped to at least [`MIN_HOLDER_INTERVAL`].
    fn holder_wait(&self) -> Duration {
        self.config
            .holder_interval
            .max(MIN_HOLDER_INTERVAL)
            .mul_f64(0.5 + 0.5 * self.jitter.unit().clamp(0.0, 1.0))
    }

    /// Own resource cleanup through `cleaner` (needs [`Self::with_state`]):
    /// generation-guarded deletes with retries bounded by `backoff`. `hook` is the
    /// deletion-boundary fault hook (production: `NoCleanupHook`).
    #[must_use]
    pub fn with_cleaner(
        mut self,
        cleaner: Arc<dyn ResourceCleaner>,
        hook: Arc<dyn CleanupHook>,
        backoff: Backoff,
    ) -> Self {
        self.cleanup = Some(tokio::sync::Mutex::new(CleanupExecutor {
            cleaner,
            hook,
            backoff,
            retries: HashMap::new(),
        }));
        self
    }

    /// Give the scheduler read access to the persisted deadlines and anchors (the
    /// same store and clock the operations use) so it can compute its next wake.
    #[must_use]
    pub fn with_state(mut self, store: Arc<Store>, clock: Arc<dyn Clock>) -> Self {
        self.state = Some((store, clock));
        self
    }

    /// Run all loops until cancelled. ⟨M03⟩ With a session-lock source
    /// ([`Self::with_session_lock`]) the lock passes run beside them, until the same
    /// cancellation.
    pub async fn run(self, shutdown: CancellationToken) {
        match self.lock.clone() {
            Some((source, config)) => {
                let stop = shutdown.clone();
                let lock = heimdall_app::lock::run_lock_passes(
                    self.operations.clone(),
                    source,
                    config,
                    async move { stop.cancelled().await },
                );
                let ((), report) = tokio::join!(self.run_loops(shutdown), lock);
                tracing::debug!(
                    passes = report.passes,
                    failures = report.failures,
                    "lock passes ended"
                );
            }
            None => self.run_loops(shutdown).await,
        }
    }

    async fn run_loops(&self, shutdown: CancellationToken) {
        let mut events = Some(self.operations.events().live_receiver());
        let start = Instant::now();
        let mut next_guard = start;
        let mut next_pass = start;
        // ⟨M02⟩ U8: the first holder pass runs at start (holders that exited while the
        // runtime was down are released), then every jittered interval.
        let mut next_holder = start;
        // ⟨M03⟩ The M03 passes run at start, then every jittered interval.
        let mut next_managed = start;
        let mut last_safe: Option<bool> = None;
        let mut last_mono = start;
        let mut last_cont = self.state.as_ref().map(|(_, c)| c.continuous());
        let resume_bound = self.config.resume_bound();
        loop {
            let mut wake = next_guard.min(next_pass).min(next_holder);
            if self.managed.is_some() {
                wake = wake.min(next_managed);
            }
            if self.state.is_some() {
                // Bounded wait: re-check for a system sleep at least this often
                // (review B04); such a wake costs one clock read.
                wake = wake.min(Instant::now() + resume_bound);
            }
            let changed = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep_until(wake) => false,
                r = recv_change(&mut events) => r,
            };
            let now = Instant::now();
            if changed {
                next_pass = next_pass.min(now + CHANGE_DEBOUNCE);
                continue;
            }
            // Events held back behind an unread gap (a failed catch-up read) are
            // retried on every timed wake, so they do not wait for the next commit
            // (review A05); a no-op when nothing is held back.
            self.operations.events().retry_held();
            // A machine sleep shows as continuous progress the monotonic timer did
            // not see: run both passes now.
            if let (Some((_, clock)), Some(prev)) = (&self.state, last_cont) {
                let cont = clock.continuous();
                let mono = now.saturating_duration_since(last_mono);
                if cont.saturating_sub(prev) > mono + SLEEP_DETECTION {
                    next_guard = now;
                    next_pass = now;
                }
                last_cont = Some(cont);
                last_mono = now;
            }
            if now >= next_guard {
                next_guard = now + self.config.anchor_interval;
                match self.time_guard_pass().await {
                    Ok(status) => {
                        let safe = status == TimeStatus::Safe;
                        if safe && last_safe != Some(true) {
                            // Back to safe time: expiries that needed the gate run now.
                            next_pass = now;
                        }
                        if !safe && last_safe != Some(false) {
                            tracing::warn!(
                                "time is uncertain; activation, signing and issuance are stopped"
                            );
                            // ⟨M03⟩ D7 item 10: the gate left `Safe`.
                            self.time_uncertain_close().await;
                        }
                        last_safe = Some(safe);
                    }
                    Err(e) => tracing::warn!(code = %e.code, "time guard pass failed"),
                }
            }
            if now >= next_holder {
                next_holder = now + self.holder_wait();
                match self.holder_pass().await {
                    Ok(released) if !released.is_empty() => {
                        tracing::info!(count = released.len(), "holder pass released bindings");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(code = %e.code, "holder pass failed"),
                }
            }
            if self.managed.is_some() && now >= next_managed {
                next_managed = now + self.managed_wait();
                self.managed_pass(last_safe == Some(false)).await;
            }
            if now >= next_pass {
                next_pass = match self.scheduler_pass().await {
                    Ok(next) => now + self.sleep_until_wall(next),
                    Err(e) => {
                        tracing::warn!(code = %e.code, "scheduler pass failed; retrying");
                        // Jittered like every supervisor-owned retry (§13.5).
                        let base = FAILED_PASS_RETRY.min(self.config.max_idle_sleep);
                        now + base.mul_f64(0.5 + 0.5 * self.jitter.unit().clamp(0.0, 1.0))
                    }
                };
                // ⟨M03⟩ U0b row 8: the managed re-issue hook (a no-op while the
                // managed adapter is unregistered).
                if let Err(e) = self.managed_reissue_pass().await {
                    tracing::warn!(code = %e.code, "managed re-issue pass failed");
                }
                if self.cleanup.is_some() {
                    match self.cleanup_pass().await {
                        Ok(report) => {
                            if let Some(due) = report.next_due_in {
                                next_pass = next_pass.min(now + due);
                            }
                        }
                        Err(e) => tracing::warn!(code = %e.code, "cleanup pass failed"),
                    }
                }
            }
        }
    }

    /// Monotonic delay until a wall instant, bounded by `max_idle_sleep`.
    fn sleep_until_wall(&self, next: Option<Timestamp>) -> Duration {
        let cap = self.config.max_idle_sleep;
        let (Some(next), Some((_, clock))) = (next, &self.state) else {
            return cap;
        };
        Duration::try_from(next.duration_since(clock.wall()))
            .unwrap_or(Duration::ZERO)
            .min(cap)
    }

    /// One scheduler pass (exposed for virtual-clock tests): expire due grants by
    /// wall bound or continuous budget, return the next wake instant.
    ///
    /// The next wake is the earliest of every live grant's resolved deadline, its
    /// persisted anchor bound (which a cutoff or parent bound may have shortened)
    /// and, for an anchor of the current boot, the wall instant at which its
    /// continuous budget runs out; instants not in the future are skipped (a grant
    /// whose budget ran out while time was uncertain is retried after the time
    /// guard returns to `Safe`). `None` when nothing is due or no state was given.
    ///
    /// ⟨r2.7⟩ After `tick` it runs [`Self::revocation_pass`] (ADR-0006 §13.10 item
    /// 3); the next wake also covers the earliest scheduled revocation round. A
    /// failed revocation pass is logged and does not fail the scheduler pass.
    pub async fn scheduler_pass(
        &self,
    ) -> Result<Option<heimdall_contract::Timestamp>, heimdall_app::OpError> {
        self.operations.tick().await?;
        // ⟨M03⟩ The owned connections of the grants this tick ended (deadline, cutoff,
        // re-validation): closed by the policy, with their events.
        if self.managed.is_some() {
            let _ = self.connection_end_sweep().await;
            // ⟨§17.21 item 11⟩ Then the slots those grants still hold.
            let _ = self.ended_slot_pass().await;
        }
        let mut bounded_at = None;
        let retry_in = match self.revocation_pass().await {
            Ok(report) => {
                bounded_at = report.bounded.and_then(|b| b.next_at);
                report.next_due_in
            }
            Err(e) => {
                tracing::warn!(code = %e.code, "revocation retry pass failed");
                None
            }
        };
        let next = self.next_wake().await?;
        // ⟨M03⟩ U0b row 6: wake when a bounded obligation's bound may have passed.
        let next = match (next, bounded_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let retry_at = match (retry_in, &self.state) {
            (Some(d), Some((_, clock))) => jiff::SignedDuration::try_from(d)
                .ok()
                .and_then(|span| clock.wall().checked_add(span).ok()),
            _ => None,
        };
        Ok(match (next, retry_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        })
    }

    /// ⟨r2.7⟩ One pass of the single retry owner for pending remote revocations
    /// (exposed for virtual-clock tests; ADR-0006 §13.10 item 3, see the module
    /// docs). Without state (no clock) it does nothing.
    ///
    /// For each record that is not `stopped`: a record first seen at `n` attempts
    /// (or seen again at another count, e.g. after an explicit revoke re-armed it,
    /// or after a round whose completion failed but whose claim counted) gets its
    /// next round scheduled `retry_delay(backoff, n, jitter)` later and is not
    /// called in this pass; a due round calls `Operations::retry_remote_revocation`,
    /// then the next one is scheduled from the new count. A record at or past the
    /// cap is stopped without a call. A round that fails is rescheduled at the
    /// count it was scheduled for (never a tight loop); ⟨r2.9⟩ the round itself
    /// was claimed durably before any adapter call (ADR-0006 §13.12 item 1), so the
    /// next pass sees the higher count and the cap still bounds the calls. A due
    /// round that found no responsible adapter configured (same count, not
    /// stopped; §13.12 item 2) is listed in `waiting` and the next one is scheduled
    /// `retry_delay(backoff, n + k, jitter)` later after `k` such rounds in a row.
    ///
    /// ⟨r2.10⟩ ADR-0006 §13.13: the cap applies per (grant, adapter) obligation
    /// (item 3): a record is stopped without a call only when every obligation
    /// reached its own cap (`PendingRemoteRevocation::capped`), and a round whose
    /// remaining callable obligations all wait for an unconfigured adapter is a
    /// `waiting` round like any other. A record first seen carrying a round that a
    /// previous run claimed and never completed (`Operations::round_interrupted`;
    /// item 4) gets that round in this pass, not after a back-off.
    ///
    /// ⟨r2.15⟩ ADR-0006 §13.18 item 3: the cap a record is judged by is its own
    /// stored cap, or `backoff.max_attempts` when lower
    /// (`PendingRemoteRevocation::round_cap`).
    ///
    /// ⟨r2.16⟩ ADR-0006 §13.19 item 2: each pass first processes every cleanup
    /// intent on record (`Operations::process_cleanup_intents`), whatever the state of
    /// the operation that wrote it, so an owed call is made, or an obligation the
    /// intent re-arms is scheduled in this same pass. A failure to read them is
    /// logged and does not fail the pass.
    pub async fn revocation_pass(&self) -> Result<RevocationReport, heimdall_app::OpError> {
        let mut report = RevocationReport::default();
        let Some((_, clock)) = self.state.clone() else {
            return Ok(report);
        };
        let mut ex = self.revocations.lock().await;
        let backoff = ex.backoff;
        self.cleanup_intent_step(clock.continuous(), &backoff, &mut report)
            .await;
        let pending = self.operations.pending_remote_revocations().await?;
        // ⟨M03⟩ U0b row 6 (ADR-0008 D7 item 3): `bounded_by_expiry` obligations move
        // on safe time alone, with no adapter call and no attempt counted. Run only
        // when a record holds one, so M01/M02 passes are unchanged.
        if pending.iter().any(|p| {
            p.obligations
                .iter()
                .any(|o| !o.kind.is_needs_remote_action())
        }) {
            match self.operations.settle_bounded_obligations().await {
                Ok(b) => report.bounded = Some(b),
                Err(e) => tracing::warn!(code = %e.code, "bounded obligations were not settled"),
            }
        }
        let now = clock.continuous();
        ex.due
            .retain(|root, _| pending.iter().any(|p| &p.root == root && !p.stopped));
        let cap = backoff.max_attempts;
        for p in pending {
            // A record of bounded obligations only has no adapter round to run (the
            // step above settles it).
            if p.stopped || only_bounded(&p) {
                ex.due.remove(&p.root);
                continue;
            }
            let scheduled = ex
                .due
                .get(&p.root)
                .filter(|s| s.attempts == p.attempts)
                .copied();
            let slot = match scheduled {
                Some(slot) => slot,
                // ⟨r2.15⟩ ADR-0006 §13.18 item 3: judged by the record's own cap, or
                // this supervisor's when lower, as restart recovery judges it.
                None if p.capped(p.round_cap(cap)) => {
                    // ⟨r2.10⟩ Every obligation reached its own cap already (by the
                    // first local denial, a lower cap, or a claimed round whose
                    // completion failed; ADR-0006 §13.13 item 3): stop without
                    // another call.
                    if self
                        .operations
                        .retry_remote_revocation(&p.root, cap)
                        .await?
                        .is_some_and(|r| r.stopped)
                    {
                        report.stopped.push(p.root.clone());
                    }
                    ex.due.remove(&p.root);
                    continue;
                }
                // ⟨r2.10⟩ ADR-0006 §13.13 item 4: a round a previous run claimed and
                // never completed is due now, not after a back-off (it counted).
                None if self.operations.round_interrupted(&p) => ScheduledRound {
                    attempts: p.attempts,
                    at: now,
                    idle: 0,
                },
                None => {
                    let delay = retry_delay(&backoff, p.attempts, self.jitter.as_ref());
                    ex.due.insert(
                        p.root.clone(),
                        ScheduledRound {
                            attempts: p.attempts,
                            at: now + delay,
                            idle: 0,
                        },
                    );
                    report.scheduled.push((p.root.clone(), p.attempts, delay));
                    continue;
                }
            };
            if slot.at > now {
                continue;
            }
            match self.operations.retry_remote_revocation(&p.root, cap).await {
                Ok(None) => {
                    ex.due.remove(&p.root);
                    report.completed.push(p.root.clone());
                }
                Ok(Some(next)) if next.stopped => {
                    if next.attempts != p.attempts {
                        report.retried.push((p.root.clone(), next.attempts));
                    }
                    ex.due.remove(&p.root);
                    report.stopped.push(p.root.clone());
                }
                Ok(Some(next)) if next.attempts == p.attempts => {
                    // ⟨r2.9⟩ No responsible adapter configured: no call, no
                    // attempt consumed; back off further all the same.
                    let idle = slot.idle.saturating_add(1);
                    let delay = retry_delay(
                        &backoff,
                        p.attempts.saturating_add(idle),
                        self.jitter.as_ref(),
                    );
                    ex.due.insert(
                        p.root.clone(),
                        ScheduledRound {
                            attempts: p.attempts,
                            at: now + delay,
                            idle,
                        },
                    );
                    report.waiting.push(p.root.clone());
                    report.scheduled.push((p.root.clone(), p.attempts, delay));
                }
                Ok(Some(next)) => {
                    report.retried.push((p.root.clone(), next.attempts));
                    let delay = retry_delay(&backoff, next.attempts, self.jitter.as_ref());
                    ex.due.insert(
                        p.root.clone(),
                        ScheduledRound {
                            attempts: next.attempts,
                            at: now + delay,
                            idle: 0,
                        },
                    );
                    report
                        .scheduled
                        .push((p.root.clone(), next.attempts, delay));
                }
                Err(e) => {
                    tracing::warn!(code = %e.code, "a pending remote revocation round failed");
                    let delay = retry_delay(&backoff, p.attempts, self.jitter.as_ref());
                    ex.due.insert(
                        p.root.clone(),
                        ScheduledRound {
                            at: now + delay,
                            ..slot
                        },
                    );
                }
            }
        }
        report.next_due_in = ex.due.values().map(|s| s.at.saturating_sub(now)).min();
        let intents_due = self
            .intents
            .lock()
            .await
            .values()
            .filter(|r| !r.stopped)
            .map(|r| r.at.saturating_sub(now))
            .min();
        report.next_due_in = match (report.next_due_in, intents_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        Ok(report)
    }

    /// ⟨M03⟩ U0b row 7 (ADR-0007 §12.13; ADR-0008 D7 item 5): process the cleanup
    /// intents on record (ADR-0006 §13.19 item 2), as every revocation pass does.
    ///
    /// * With no adapter declaring a remote credential effect (every M02 adapter):
    ///   unchanged, `Operations::process_cleanup_intents`, every intent every pass.
    /// * Otherwise each intent is processed on its own schedule: a new one at once;
    ///   one that a processing left on record (a kept intent: its immediate call
    ///   timed out, or its applying adapter is not configured) again after
    ///   [`retry_delay`]`(backoff, n, jitter)` on the continuous clock, `n` being the
    ///   processings so far, and not again in this process once `n` reaches
    ///   `backoff.max_attempts`. An intent whose attempt is still in flight here is
    ///   skipped without a schedule (its preparation's return path processes it). A
    ///   rewritten intent (a new version) starts over.
    async fn cleanup_intent_step(
        &self,
        now: Duration,
        backoff: &Backoff,
        report: &mut RevocationReport,
    ) {
        if !self.operations.has_remote_effect_adapter() {
            if let Err(e) = self.operations.process_cleanup_intents().await {
                tracing::warn!(code = %e.code, "cleanup intents could not be processed");
            }
            return;
        }
        let intents = match self.operations.cleanup_intents().await {
            Ok(intents) => intents,
            Err(e) => {
                tracing::warn!(code = %e.code, "cleanup intents could not be processed");
                return;
            }
        };
        let mut schedule = self.intents.lock().await;
        schedule.retain(|(g, o), _| intents.iter().any(|i| &i.grant == g && &i.operation == o));
        for intent in intents {
            let key = (intent.grant.clone(), intent.operation.clone());
            let version = intent.version;
            let current = schedule.get(&key).copied().filter(|r| r.version == version);
            if current.is_some_and(|r| r.stopped || r.at > now) {
                continue;
            }
            match self
                .operations
                .process_cleanup_intent_reporting(intent)
                .await
            {
                IntentOutcome::Kept => {
                    let attempts = current.map_or(0, |r| r.attempts).saturating_add(1);
                    let stopped = attempts >= backoff.max_attempts;
                    let delay = if stopped {
                        Duration::ZERO
                    } else {
                        retry_delay(backoff, attempts, self.jitter.as_ref())
                    };
                    if stopped {
                        tracing::warn!(
                            attempts,
                            "a kept cleanup intent reached its retry cap; it is kept for the next restart"
                        );
                        report.intents_stopped.push(key.clone());
                    } else {
                        report.intents_scheduled.push((
                            key.0.clone(),
                            key.1.clone(),
                            attempts,
                            delay,
                        ));
                    }
                    schedule.insert(
                        key,
                        IntentRetry {
                            version,
                            attempts,
                            at: now + delay,
                            stopped,
                        },
                    );
                }
                IntentOutcome::Cleared => {
                    schedule.remove(&key);
                }
                // Skipped (in flight here) or a later outcome: no schedule.
                _ => {}
            }
        }
    }

    /// ⟨M03⟩ U0b row 8 (ADR-0008 D2 table; F18): the supervisor hook for
    /// re-issuing the credentials of `lost` instances (grants degraded
    /// `credential_reissue_pending`). Its body is U6/U10's. While the managed
    /// adapter is not registered (wave 0: it does not exist) it is a no-op that
    /// reads and writes nothing; it returns the grants it re-issued (none).
    ///
    /// # Errors
    /// None in wave 0; U6/U10's body reports a store failure as
    /// `STATE_UNAVAILABLE`.
    pub async fn managed_reissue_pass(&self) -> Result<Vec<GrantId>, heimdall_app::OpError> {
        // ⟨M03⟩ wave 4: the body is `Operations::managed_reissue_pass` (U10), a no-op
        // while the managed adapter is unwired.
        self.operations.managed_reissue_pass().await
    }

    /// ⟨M03⟩ The jittered wait before the next M03 pass: `[interval / 2, interval]`,
    /// the interval clamped to at least [`MIN_HOLDER_INTERVAL`].
    fn managed_wait(&self) -> Duration {
        self.config
            .managed_interval
            .max(MIN_HOLDER_INTERVAL)
            .mul_f64(0.5 + 0.5 * self.jitter.unit().clamp(0.0, 1.0))
    }

    /// ⟨M03⟩ wave 4 (m03-plan U10; exposed for tests): one round of the M03 passes, each
    /// logged and retried by the next round on failure: the connection-end sweep, the
    /// ended-grant slot pass ([`Self::ended_slot_pass`]), the owed `time_uncertain_close` while time stays uncertain (`uncertain`), the reap
    /// pass, issuer supervision, re-verification and the enrollment step timeout. A
    /// supervisor without M03 wiring does nothing.
    pub async fn managed_pass(&self, uncertain: bool) {
        let Some(m) = &self.managed else {
            return;
        };
        let _ = self.connection_end_sweep().await;
        let _ = self.ended_slot_pass().await;
        if uncertain
            && m.uncertain_close_owed
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.time_uncertain_close().await;
        }
        if let Err(f) = m.connections.reap_pass().await {
            tracing::warn!(word = f.word(), "reap pass could not enumerate; retrying");
        }
        if let Err(e) = self.operations.issuer_supervision_pass().await {
            tracing::warn!(code = %e.code, "issuer supervision pass failed");
        }
        if let Err(e) = self.operations.reverify_pass().await {
            tracing::warn!(code = %e.code, "re-verification pass failed");
        }
        if let Err(e) = self.operations.enrollment_step_timeout_pass().await {
            tracing::warn!(code = %e.code, "enrollment step timeout pass failed");
        }
    }

    /// ⟨M03⟩ D7 item 10 (exposed for tests): `time_uncertain_close` with its events;
    /// a discovery failure keeps it owed, so the next M03 pass retries it while time
    /// stays uncertain (D7 item 2). Without M03 wiring, nothing.
    pub async fn time_uncertain_close(&self) {
        let Some(m) = &self.managed else {
            return;
        };
        let owed = match m.connections.time_uncertain_close().await {
            Ok(r) => !r.pending.is_empty() || !r.failed.is_empty(),
            Err(f) => {
                tracing::warn!(word = f.word(), "time-uncertain close could not enumerate");
                true
            }
        };
        m.uncertain_close_owed
            .store(owed, std::sync::atomic::Ordering::SeqCst);
    }

    /// ⟨M03⟩ wave 4 (exposed for tests): close the owned connections of every ended
    /// grant that still has open rows, by the reason its stored state gives
    /// ([`close_reason_for`]): `connection_deadline_pass` for an expired grant,
    /// `revocation_close` for a revoked one, `release_close` for a released one, each
    /// with its events. The durable rows are the cleanup intent (D7 item 2): a grant
    /// whose pass left a row pending or failed, or could not read its rows
    /// (`DiscoveryFailed`), is passed again by the next sweep; a grant whose pass
    /// finished (rows closed, or kept by the policy) is not passed again. Without M03
    /// wiring, nothing.
    pub async fn connection_end_sweep(&self) -> ConnectionSweep {
        let mut sweep = ConnectionSweep::default();
        let Some(m) = &self.managed else {
            return sweep;
        };
        let Some((store, _)) = &self.state else {
            return sweep;
        };
        let open = match read_store(store, grants_with_open_connections).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(code = %e.code, "connection sweep could not enumerate; retrying");
                sweep.discovery_failed = true;
                return sweep;
            }
        };
        let mut finished = m.finished.lock().await;
        finished.retain(|g| open.iter().any(|(o, _)| o == g));
        for (grant, state) in open {
            let Some(reason) = close_reason_for(state) else {
                continue;
            };
            if finished.contains(&grant) {
                continue;
            }
            let result = m.connections.close_by_reason(&grant, reason).await;
            match result {
                Ok(r) if r.pending.is_empty() && r.failed.is_empty() => {
                    finished.insert(grant.clone());
                    sweep.handled.push((grant, reason));
                }
                Ok(_) => sweep.retry.push(grant),
                Err(f) => {
                    tracing::warn!(word = f.word(), "connection pass could not read its rows");
                    sweep.retry.push(grant);
                }
            }
        }
        sweep
    }

    /// ⟨M03⟩ wave 4, round 2 (ADR-0008 §17.21 item 11; exposed for tests): slot
    /// cleanup when a grant ends; ⟨round 3, §17.22 items 4, 9, 10⟩ the ended-grant and
    /// ended-binding cleanup pass, discovered from durable rows only, never from held
    /// slots alone:
    ///
    /// * every grant of this environment that has ended (terminal, or `revoking`)
    ///   while a binding of it still holds (or is clearing) a managed slot
    ///   (`Txn::held_slots_of_ended_grants`);
    /// * every terminal grant with a credential instance not yet `destroyed`, and
    ///   every grant (live ones included) with a slot held or clearing for a released
    ///   binding, ⟨round 5, W4-C01⟩ or with a released binding whose release cleanup
    ///   (its endpoint and files of every generation, slot or no slot) is not yet
    ///   recorded done (`Txn::managed_cleanup_owed`; `StoreCleanup` records it done).
    ///
    /// For each: an ended managed grant's K_env is destroyed in memory
    /// (`Operations::managed_end_destroy_keys`); the managed adapter's end cleanup
    /// runs (`StoreCleanup`: each slot cleared by its own store generation, the binding
    /// endpoints and files removed by generation, the mux paths, the slots freed last,
    /// the owned connections closed; for a live grant only its released bindings); and
    /// only when that completed do the ended grant's instances become `destroyed`
    /// (`Operations::managed_end_instances_destroyed`, the gate released). It runs
    /// after every scheduler `tick` and in every M03 pass, so a failed, missed or
    /// crashed cleanup is retried (the `clearing` slot row and the undestroyed
    /// instance row are the cleanup intent). Returns the grants whose cleanup
    /// succeeded, in grant order. Without M03 wiring, an end cleanup or state,
    /// nothing.
    ///
    /// # Errors
    /// The store read failed (nothing was cleaned; the next pass retries).
    pub async fn ended_slot_pass(&self) -> Result<Vec<GrantId>, heimdall_app::OpError> {
        let (Some(m), Some((store, _))) = (&self.managed, &self.state) else {
            return Ok(Vec::new());
        };
        let Some(cleanup) = &m.end_cleanup else {
            return Ok(Vec::new());
        };
        let environment = self.operations.environment().clone();
        let owed = match read_store(store, move |tx| {
            let mut owed: std::collections::BTreeSet<GrantId> = tx
                .held_slots_of_ended_grants(&environment)?
                .into_iter()
                .map(|(g, _)| g)
                .collect();
            owed.extend(tx.managed_cleanup_owed(&environment)?);
            Ok(owed)
        })
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(code = %e.code, "ended-grant slot pass could not enumerate; retrying");
                return Err(e);
            }
        };
        let mut cleaned = Vec::new();
        for grant in owed {
            let ended = match self.operations.managed_end_destroy_keys(&grant).await {
                Ok(ended) => ended,
                Err(e) => {
                    tracing::warn!(code = %e.code, "an ended grant could not be read; retrying");
                    continue;
                }
            };
            if cleanup
                .after_end(std::slice::from_ref(&grant))
                .await
                .is_err()
            {
                tracing::warn!("an ended grant's slot cleanup is incomplete; retrying");
                continue;
            }
            if ended
                && let Err(e) = self
                    .operations
                    .managed_end_instances_destroyed(&grant)
                    .await
            {
                tracing::warn!(code = %e.code, "an ended grant's instances could not be updated; retrying");
                continue;
            }
            cleaned.push(grant);
        }
        Ok(cleaned)
    }

    async fn next_wake(&self) -> Result<Option<Timestamp>, heimdall_app::OpError> {
        let Some((store, clock)) = self.state.clone() else {
            return Ok(None);
        };
        let joined = tokio::task::spawn_blocking(move || {
            let wall = clock.wall();
            let continuous = clock.continuous();
            let boot = clock.boot_id();
            store.transaction(|tx| {
                let mut earliest: Option<Timestamp> = None;
                let mut consider = |t: Timestamp| {
                    if t > wall && earliest.is_none_or(|e| t < e) {
                        earliest = Some(t);
                    }
                };
                for g in tx.grants_due(Timestamp::MAX)? {
                    consider(g.deadline.effective);
                    if let Some(a) = tx.grant_anchor(&g.id)? {
                        consider(a.bound);
                        if a.anchor.boot_id == boot {
                            let left = a.budget_end.saturating_sub(continuous);
                            if let Ok(span) = jiff::SignedDuration::try_from(left)
                                && let Ok(t) = wall.checked_add(span)
                            {
                                consider(t);
                            }
                        }
                    }
                }
                // ⟨M02⟩ ADR-0007 §12.24 item 3: the earliest pending decision deadline,
                // so a setup or catalog operation waiting on it settles
                // (`CREDENTIAL_EXPIRED`, `next: new_work`) at the tick right after it,
                // never up to `max_idle_sleep` later.
                for d in tx.pending_decisions()? {
                    consider(d.expires_at);
                }
                Ok(earliest)
            })
        })
        .await;
        match joined {
            Ok(Ok(next)) => Ok(next),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(heimdall_app::OpError::new(
                Code::InternalError,
                "scheduler task failed",
            )),
        }
    }

    /// One cleanup pass (exposed for virtual-clock tests; see the module docs).
    /// Without a cleaner or state it does nothing.
    pub async fn cleanup_pass(&self) -> Result<CleanupReport, heimdall_app::OpError> {
        let mut report = CleanupReport::default();
        let (Some(cleanup), Some((store, clock))) = (&self.cleanup, self.state.clone()) else {
            return Ok(report);
        };
        let mut ex = cleanup.lock().await;
        let pending = read_store(&store, |tx| tx.resources_needing_reconcile()).await?;
        let now = clock.continuous();
        // Review B02: a retry belongs to one generation's cleanup candidacy. Drop
        // every entry whose resource is no longer a cleanup candidate at that
        // generation (reconciled, replaced by N+1, no longer planned for cleanup,
        // or gone), so neither the next wake nor the map is driven by obsolete
        // work. Entries for current candidates are kept (including stopped ones: a
        // stopped generation is never retried again).
        let candidates: HashMap<&ResourceId, ResourceGeneration> = pending
            .iter()
            .filter_map(|r| match plan(r) {
                Action::Cleanup { generation } => Some((&r.id, generation)),
                _ => None,
            })
            .collect();
        ex.retries
            .retain(|id, rt| candidates.get(id) == Some(&rt.generation));
        for r in pending {
            if let Some(rt) = ex.retries.get(&r.id).copied() {
                if rt.generation != r.generation {
                    ex.retries.remove(&r.id);
                } else if rt.stopped || rt.next_due > now {
                    continue;
                }
            }
            let Action::Cleanup { generation } = plan(&r) else {
                continue;
            };
            ex.hook.at(CleanupPoint::Decided, &r);
            let id = r.id.clone();
            let current = read_store(&store, move |tx| tx.resource(&id)).await?;
            let Some(current) = current else {
                ex.retries.remove(&r.id);
                continue;
            };
            if guard_cleanup(generation, &current) == CleanupDecision::Superseded {
                ex.retries.remove(&r.id);
                report.superseded.push(r.id.clone());
                continue;
            }
            ex.hook.at(CleanupPoint::Guarded, &r);
            match ex.cleaner.delete(&r).await {
                Ok(()) => {
                    ex.retries.remove(&r.id);
                    let id = r.id.clone();
                    let wall = clock.wall();
                    let recorded = read_store(&store, move |tx| {
                        let Some(cur) = tx.resource(&id)? else {
                            return Ok(false);
                        };
                        if cur.generation != generation {
                            return Ok(false);
                        }
                        let done = ManagedResource {
                            observed: ResourceState::Absent,
                            updated_at: wall,
                            ..cur
                        };
                        tx.upsert_resource(&done, Some(generation))?;
                        Ok(true)
                    })
                    .await?;
                    if recorded {
                        report.deleted.push(r.id.clone());
                        self.resource_event(&r, generation, "deleted", None, 0);
                    } else {
                        report.superseded.push(r.id.clone());
                    }
                }
                Err(e) => {
                    let attempts = ex
                        .retries
                        .get(&r.id)
                        .map_or(0, |rt| rt.attempts)
                        .saturating_add(1);
                    let transient = matches!(e, AdapterError::Unavailable(_));
                    let backoff = ex.backoff;
                    match should_retry(attempts, &backoff, true, !transient) {
                        Ok(()) => {
                            let delay = retry_delay(&backoff, attempts, self.jitter.as_ref());
                            ex.retries.insert(
                                r.id.clone(),
                                Retry {
                                    generation,
                                    attempts,
                                    next_due: now + delay,
                                    stopped: false,
                                },
                            );
                            report.retry_scheduled.push((r.id.clone(), attempts, delay));
                        }
                        Err(_) => {
                            let code = heimdall_app::OpError::from(e).code;
                            ex.retries.insert(
                                r.id.clone(),
                                Retry {
                                    generation,
                                    attempts,
                                    next_due: now,
                                    stopped: true,
                                },
                            );
                            self.resource_event(
                                &r,
                                generation,
                                "cleanup_failed",
                                Some(&code),
                                attempts,
                            );
                            report.failed.push((r.id.clone(), code));
                        }
                    }
                }
            }
        }
        report.next_due_in = ex
            .retries
            .values()
            .filter(|rt| !rt.stopped)
            .map(|rt| rt.next_due.saturating_sub(now))
            .min();
        Ok(report)
    }

    /// A redacted `resource_changed` event (identifiers, generation, outcome,
    /// stable code; never the locator).
    fn resource_event(
        &self,
        r: &ManagedResource,
        generation: ResourceGeneration,
        outcome: &str,
        code: Option<&Code>,
        attempts: u32,
    ) {
        let payload = serde_json::json!({
            "resource_id": r.id,
            "kind": r.kind,
            "generation": generation.0,
            "outcome": outcome,
            "code": code,
            "attempts": attempts,
        });
        if let Err(e) = self
            .operations
            .events()
            .publish(EventType::ResourceChanged, None, payload)
        {
            tracing::warn!(code = %e.code, "resource event was not recorded");
        }
    }

    /// One time-guard pass (exposed for tests): run the shared gate (persists on
    /// `Safe`) and return its status.
    ///
    /// `Uncertain` carries the gate's reason (read back with `peek`, which
    /// persists nothing). If two passes disagree (the clock moved between them),
    /// the result is the `TIME_UNCERTAIN` error: never reported safe without a
    /// persisting `check`.
    pub async fn time_guard_pass(&self) -> Result<TimeStatus, heimdall_app::OpError> {
        let gate = self.operations.timegate();
        for _ in 0..2 {
            match gate.check().await {
                Ok(_) => return Ok(TimeStatus::Safe),
                Err(e) if e.code == Code::TimeUncertain => match gate.peek().await? {
                    TimeStatus::Uncertain(u) => return Ok(TimeStatus::Uncertain(u)),
                    TimeStatus::Safe => {}
                },
                Err(e) => return Err(e),
            }
        }
        Err(heimdall_app::OpError::new(
            Code::TimeUncertain,
            "safe time could not be established consistently",
        ))
    }
}

// --- ⟨M03⟩ wave 4 (U10): connection control with its events -----------------------------

/// ⟨M03⟩ m03-plan U10 (U7-Q3 option (a), ADR-0008 §17.20 item 14): U7's
/// [`ConnectionSupervisor`] with the `Connection` events. It implements
/// [`ConnectionControl`] itself, so every close made through it emits one `Connection`
/// event (`{connection_id, kind, event, reason}`) per row it actually closed: the
/// owner's `Connections::Close` (`owner_request`), the supervisor's passes (the reason of
/// the pass), and the revoke and release paths of `Operations` through
/// `ManagedWiring.connections` (their reason). A start or a registration emits
/// `started`. A pass emits from its `PassReport::closed`, so a row closed once is never
/// reported closed again. Events carry IDs and fixed words only (no PID, no path).
pub struct ManagedConnections {
    supervisor: Arc<ConnectionSupervisor>,
    store: Arc<Store>,
    operations: Operations,
}

impl std::fmt::Debug for ManagedConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedConnections").finish_non_exhaustive()
    }
}

/// The `Connection` event payload of one row.
fn connection_payload(
    id: &ConnectionId,
    kind: ConnectionKind,
    event: ConnectionEventKind,
    reason: Option<CloseReason>,
) -> serde_json::Value {
    serde_json::to_value(ConnectionEventPayload {
        connection_id: id.clone(),
        kind,
        event,
        reason,
    })
    .unwrap_or(serde_json::Value::Null)
}

impl ManagedConnections {
    /// Connection control over `supervisor`, reading rows from `store` and publishing
    /// events through `operations`.
    #[must_use]
    pub fn new(
        supervisor: Arc<ConnectionSupervisor>,
        store: Arc<Store>,
        operations: Operations,
    ) -> Self {
        Self {
            supervisor,
            store,
            operations,
        }
    }

    /// U7's supervisor.
    #[must_use]
    pub fn supervisor(&self) -> &Arc<ConnectionSupervisor> {
        &self.supervisor
    }

    fn emit(
        &self,
        id: &ConnectionId,
        kind: ConnectionKind,
        event: ConnectionEventKind,
        reason: Option<CloseReason>,
    ) {
        let payload = connection_payload(id, kind, event, reason);
        if let Err(e) = self
            .operations
            .events()
            .publish(EventType::Connection, None, payload)
        {
            tracing::warn!(code = %e.code, "connection event was not recorded");
        }
    }

    /// Emit `closed` with `reason` for every row `closed` names (its kind read from the
    /// store; a row that cannot be read is reported by its ID with the kind the store
    /// last had, or not at all when it is gone).
    async fn emit_closed(&self, closed: &[ConnectionId], reason: Option<CloseReason>) {
        if closed.is_empty() {
            return;
        }
        let ids = closed.to_vec();
        let rows = read_store(&self.store, move |tx| {
            let mut out = Vec::new();
            for id in &ids {
                if let Some(c) = tx.owned_connection(id)? {
                    out.push((c.id, c.kind));
                }
            }
            Ok(out)
        })
        .await;
        match rows {
            Ok(rows) => {
                for (id, kind) in rows {
                    self.emit(&id, kind, ConnectionEventKind::Closed, reason);
                }
            }
            Err(e) => tracing::warn!(code = %e.code, "connection events could not be read"),
        }
    }

    /// Emit the events of one pass result and return it unchanged.
    async fn reported(&self, result: PassResult, reason: Option<CloseReason>) -> PassResult {
        let report = match &result {
            Ok(r) => r,
            Err(f) => &f.report,
        };
        self.emit_closed(&report.closed, reason).await;
        result
    }

    /// `connection_restart_pass` (first at start), with its events. A master closed here
    /// is reported with the reason its grant's stored state gives
    /// ([`close_reason_for`]), `time_uncertain` when the grant is still live.
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn restart_pass(&self) -> PassResult {
        let result = self.supervisor.connection_restart_pass().await;
        let report = match &result {
            Ok(r) => r,
            Err(f) => &f.report,
        };
        if !report.closed.is_empty() {
            let ids = report.closed.clone();
            let rows = read_store(&self.store, move |tx| {
                let mut out = Vec::new();
                for id in &ids {
                    if let Some(c) = tx.owned_connection(id)? {
                        let state = tx.grant(&c.grant)?.map(|g| g.state);
                        out.push((c.id, c.kind, state));
                    }
                }
                Ok(out)
            })
            .await
            .unwrap_or_default();
            for (id, kind, state) in rows {
                let reason = state
                    .and_then(close_reason_for)
                    .unwrap_or(CloseReason::TimeUncertain);
                self.emit(&id, kind, ConnectionEventKind::Closed, Some(reason));
            }
        }
        result
    }

    /// Close the owned connections of `grants` by the reason each grant's stored state
    /// gives ([`close_reason_for`]), with their events (the end-of-grant cleanup, and
    /// the sweep). `true` when every pass finished (nothing pending, failed or
    /// undiscovered); a grant that has not ended is left alone.
    pub async fn close_ended(&self, grants: &[GrantId]) -> bool {
        let ids = grants.to_vec();
        let Ok(states) = read_store(&self.store, move |tx| {
            let mut out = Vec::new();
            for g in ids {
                if let Some(s) = tx.grant(&g)? {
                    out.push((g, s.state));
                }
            }
            Ok(out)
        })
        .await
        else {
            return false;
        };
        let mut ok = true;
        for (grant, state) in states {
            let Some(reason) = close_reason_for(state) else {
                continue;
            };
            ok &= finished(&self.close_by_reason(&grant, reason).await);
        }
        ok
    }

    async fn close_by_reason(&self, grant: &GrantId, reason: CloseReason) -> PassResult {
        let one = std::slice::from_ref(grant);
        match reason {
            CloseReason::Revocation => self.revocation_close(one).await,
            CloseReason::Release => self.release_close(one).await,
            _ => self.deadline_pass(one).await,
        }
    }

    /// `connection_deadline_pass` with its events (`admission_deadline`).
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn deadline_pass(&self, ended: &[GrantId]) -> PassResult {
        let r = self.supervisor.connection_deadline_pass(ended).await;
        self.reported(r, Some(CloseReason::AdmissionDeadline)).await
    }

    /// `revocation_close` with its events (`revocation`): D7 item 2 step 4, after the
    /// revoke's gates are released.
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn revocation_close(&self, cascade: &[GrantId]) -> PassResult {
        let r = self.supervisor.revocation_close(cascade).await;
        self.reported(r, Some(CloseReason::Revocation)).await
    }

    /// `release_close` with its events (`release`).
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn release_close(&self, grants: &[GrantId]) -> PassResult {
        let r = self.supervisor.release_close(grants).await;
        self.reported(r, Some(CloseReason::Release)).await
    }

    /// `time_uncertain_close` with its events (`time_uncertain`).
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn time_uncertain_close(&self) -> PassResult {
        let r = self.supervisor.time_uncertain_close().await;
        self.reported(r, Some(CloseReason::TimeUncertain)).await
    }

    /// `reap_pass` with its events (`process_exited`).
    ///
    /// # Errors
    /// [`crate::connections::DiscoveryFailed`] (U7).
    pub async fn reap_pass(&self) -> PassResult {
        let r = self.supervisor.reap_pass().await;
        self.reported(r, Some(CloseReason::ProcessExited)).await
    }

    /// Runtime exit: close this process's masters. The contract has no close reason
    /// for a runtime stop, so their `closed` events carry none.
    pub async fn shutdown(&self) -> PassReport {
        let report = self.supervisor.shutdown().await;
        self.emit_closed(&report.closed, None).await;
        report
    }

    /// `Connections::Close { connection_id }` (m03-plan §5 item 4a; the owner role was
    /// checked by the dispatcher): close one owned connection through
    /// `ConnectionControl::close` (reason `owner_request`). An unverifiable process is
    /// reported, never signalled. A row already ended answers its state again
    /// (idempotent), emitting nothing.
    ///
    /// Data: `{"connection_id", "kind", "state"}`, `state` one of `closed`,
    /// `unverified`, `closing` (the close is pending and is retried by the reap pass).
    ///
    /// # Errors
    /// `NOT_FOUND` for an unknown connection; `STATE_UNAVAILABLE` when the store cannot
    /// be read; `SERVICE_UNAVAILABLE` when the close failed (the row stays `closing`).
    pub async fn close_request(&self, id: &ConnectionId) -> OpResult<serde_json::Value> {
        let want = id.clone();
        let row = read_store(&self.store, move |tx| tx.owned_connection(&want)).await?;
        let Some(row) = row else {
            return Err(OpError::new(Code::NotFound, "unknown owned connection")
                .with_resource("connection", Some(id.to_string()))
                .with_effect(EffectStatus::None));
        };
        let state = |s: &str| {
            Completed::ok(
                Code::Ok,
                serde_json::json!({
                    "connection_id": row.id,
                    "kind": row.kind,
                    "state": s,
                }),
            )
        };
        match row.state {
            OwnedConnectionState::Closed => return Ok(state("closed")),
            OwnedConnectionState::Unverified => return Ok(state("unverified")),
            // `up`, `closing` (and a state this build does not know): close it.
            _ => {}
        }
        match ConnectionControl::close(self, &row, CloseReason::OwnerRequest).await {
            Ok(()) => Ok(state("closed")),
            Err(ConnError::Unverified) => Ok(state("unverified")),
            Err(ConnError::Unavailable(_)) => Ok(state("closing")),
            Err(_) => Err(OpError::new(
                Code::ServiceUnavailable,
                "the owned connection could not be closed; it is retried",
            )
            .with_resource("connection", Some(row.id.to_string()))),
        }
    }

    /// `Connections::Register` (Windows; m03-plan §5 item 4a, U0b row 26): through
    /// `ConnectionControl::register`. Data: `{"connection_id", "kind": "dedicated"}`.
    ///
    /// # Errors
    /// `LAUNCH_FAILED` with `connection_registration_refused` for every refusal (the
    /// launcher then closes its job, fail closed); `CAPABILITY_UNAVAILABLE`
    /// (`driver_unavailable`) where registration does not exist (Unix).
    pub async fn register_request(
        &self,
        binding: &BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &str,
    ) -> OpResult<serde_json::Value> {
        match ConnectionControl::register(self, binding, pid, created_at, image).await {
            Ok(c) => Ok(Completed::ok(
                Code::Ok,
                serde_json::json!({ "connection_id": c.id, "kind": c.kind }),
            )),
            Err(ConnError::RegistrationRefused(word))
                if word == crate::connections::refusal::WINDOWS_ONLY =>
            {
                Err(OpError::driver_unavailable(
                    "connection registration exists on Windows only",
                ))
            }
            Err(ConnError::RegistrationRefused(_)) => Err(OpError::new(
                Code::LaunchFailed,
                "the connection registration was refused",
            )
            .with_reason(reason::CONNECTION_REGISTRATION_REFUSED)
            .with_effect(EffectStatus::None)),
            Err(_) => Err(OpError::new(
                Code::LaunchFailed,
                "the connection could not be registered",
            )
            .with_reason(reason::CONNECTION_REGISTRATION_FAILED)
            .with_effect(EffectStatus::None)),
        }
    }
}

/// A pass that left nothing to retry.
fn finished(r: &PassResult) -> bool {
    matches!(r, Ok(p) if p.pending.is_empty() && p.failed.is_empty())
}

/// The close reason a grant's stored state gives (the post-tick sweep and the restart
/// pass): `expired` (and the other ended states that never served) is the admission
/// deadline, `revoking`/`revoked` revocation, `released` release; `None` for a grant
/// that is still live.
#[must_use]
pub fn close_reason_for(state: heimdall_contract::GrantState) -> Option<CloseReason> {
    use heimdall_contract::GrantState as G;
    match state {
        G::Expired | G::Denied | G::Cancelled | G::Failed => Some(CloseReason::AdmissionDeadline),
        G::Revoking | G::Revoked => Some(CloseReason::Revocation),
        G::Released => Some(CloseReason::Release),
        _ => None,
    }
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

// `heimdall_app::ports::ConnectionControl` is declared with `#[async_trait]`; this is the
// desugared form (as `connections.rs` does), delegating to U7's supervisor and emitting.
impl ConnectionControl for ManagedConnections {
    fn start_master<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        binding: &'life1 BindingId,
        pair: &'life2 AccessPair,
    ) -> BoxFuture<'async_trait, Result<OwnedConnection, ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let c = ConnectionControl::start_master(&*self.supervisor, binding, pair).await?;
            self.emit(&c.id, c.kind, ConnectionEventKind::Started, None);
            Ok(c)
        })
    }

    fn close<'life0, 'life1, 'async_trait>(
        &'life0 self,
        c: &'life1 OwnedConnection,
        reason: CloseReason,
    ) -> BoxFuture<'async_trait, Result<(), ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            ConnectionControl::close(&*self.supervisor, c, reason).await?;
            self.emit(&c.id, c.kind, ConnectionEventKind::Closed, Some(reason));
            Ok(())
        })
    }

    fn register<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        binding: &'life1 BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &'life2 str,
    ) -> BoxFuture<'async_trait, Result<OwnedConnection, ConnError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let c = ConnectionControl::register(&*self.supervisor, binding, pid, created_at, image)
                .await?;
            self.emit(&c.id, c.kind, ConnectionEventKind::Started, None);
            Ok(c)
        })
    }
}

/// ⟨M03⟩ The grants with an open owned connection (`up` or `closing`), with their
/// stored state: the rows of the bindings with a recorded holder and of the bindings
/// owning a process resource (U7's enumeration; `connections::owned_row_invariant`).
fn grants_with_open_connections(
    tx: &mut heimdall_store::Txn<'_>,
) -> heimdall_store::Result<Vec<(GrantId, heimdall_contract::GrantState)>> {
    use heimdall_domain::resource::{OwnerRef, ResourceKind};
    let mut bindings: std::collections::BTreeSet<BindingId> =
        tx.binding_holders()?.into_iter().map(|(b, _)| b).collect();
    for (_, json) in tx.raw_documents(heimdall_store::RawDocuments::Resources)? {
        let Ok(r) = serde_json::from_str::<ManagedResource>(&json) else {
            continue;
        };
        if let (ResourceKind::Process, OwnerRef::Binding { id }) = (r.kind, r.owner) {
            bindings.insert(id);
        }
    }
    let mut grants = std::collections::BTreeSet::new();
    for b in bindings {
        for c in tx.owned_connections_for_binding(&b)? {
            if matches!(
                c.state,
                OwnedConnectionState::Up | OwnedConnectionState::Closing
            ) {
                grants.insert(c.grant);
            }
        }
    }
    let mut out = Vec::new();
    for g in grants {
        if let Some(snapshot) = tx.grant(&g)? {
            out.push((g, snapshot.state));
        }
    }
    Ok(out)
}

/// ⟨M03⟩ What one connection-end sweep did (tests and telemetry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionSweep {
    /// Grants whose rows a pass closed or kept, by the reason applied.
    pub handled: Vec<(GrantId, CloseReason)>,
    /// Grants whose pass found rows it could not finish (pending, failed, or a
    /// discovery failure): retried by the next sweep (D7 item 2).
    pub retry: Vec<GrantId>,
    /// The sweep could not enumerate the open rows (retried by the next one).
    pub discovery_failed: bool,
}

/// ⟨M03⟩ The supervisor's M03 state: connection control and what the sweep finished.
struct ManagedSupervision {
    connections: Arc<ManagedConnections>,
    /// Ended grants whose last pass finished (every row closed or kept by the policy):
    /// not passed again while their rows stay as they are.
    finished: tokio::sync::Mutex<std::collections::BTreeSet<GrantId>>,
    /// `time_uncertain_close` is owed (the gate left `Safe` and the last attempt failed).
    uncertain_close_owed: std::sync::atomic::AtomicBool,
    /// ⟨§17.21 item 11⟩ The end-of-grant cleanup [`Supervisor::ended_slot_pass`] runs.
    end_cleanup: Option<Arc<dyn heimdall_adapters::managed::EndCleanup>>,
}

/// Wait for the next committed change (`true`), or forever once the publisher is
/// gone. A lagged receiver counts as a change.
async fn recv_change(
    events: &mut Option<
        tokio::sync::broadcast::Receiver<Arc<heimdall_app::events::SequencedEvent>>,
    >,
) -> bool {
    use tokio::sync::broadcast::error::RecvError;
    let Some(rx) = events.as_mut() else {
        return std::future::pending().await;
    };
    match rx.recv().await {
        Ok(_) | Err(RecvError::Lagged(_)) => true,
        Err(RecvError::Closed) => {
            *events = None;
            false
        }
    }
}

/// Run `f` in one store transaction on the blocking pool.
async fn read_store<R, F>(store: &Arc<Store>, f: F) -> Result<R, heimdall_app::OpError>
where
    R: Send + 'static,
    F: FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<R> + Send + 'static,
{
    let store = Arc::clone(store);
    match tokio::task::spawn_blocking(move || store.transaction(f)).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err(heimdall_app::OpError::new(
            Code::InternalError,
            "supervisor task failed",
        )),
    }
}

/// ⟨M02⟩ U8: the holder pass's liveness source and schedule.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod holder_tests {
    use super::*;

    fn holder_of(pid: u32) -> ProcessHolder {
        ProcessHolder {
            pid,
            started_at: crate::platform::process_start_time(pid).unwrap(),
        }
    }

    /// A running child is `Alive`; the same PID with another start token (a reused
    /// PID) is `Exited`; once the child is reaped its holder is `Exited`.
    #[test]
    fn platform_liveness_reads_pid_and_start_time() {
        let _serial = crate::spawn_guard();
        let mut child = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
            .args(if cfg!(windows) {
                ["/d", "/c", "ping -n 30 127.0.0.1 >NUL"]
            } else {
                ["-c", "sleep 30", ""]
            })
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let holder = holder_of(child.id());
        assert_eq!(PlatformLiveness.state(&holder), HolderState::Alive);
        let reused = ProcessHolder {
            started_at: format!("{}-other", holder.started_at),
            ..holder.clone()
        };
        assert_eq!(PlatformLiveness.state(&reused), HolderState::Exited);
        // Stopped by its own handle (exact PID), then reaped.
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(PlatformLiveness.state(&holder), HolderState::Exited);
        // This runtime's own process is alive.
        assert_eq!(
            PlatformLiveness.state(&holder_of(std::process::id())),
            HolderState::Alive
        );
    }

    async fn supervisor(interval: Duration, unit: f64) -> Supervisor {
        let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
        let environment = heimdall_contract::ids::EnvironmentId::from_random_bytes([3; 16]);
        store
            .transaction(|tx| tx.init_self_environment(&environment))
            .unwrap();
        let clock = heimdall_testkit::VirtualClock::at("2026-11-03T09:00:00Z".parse().unwrap());
        let operations = Operations::start(heimdall_app::OperationsConfig {
            store,
            clock,
            time_sync: heimdall_testkit::ScriptedTimeSync::new(
                heimdall_domain::time::SyncStatus::Synchronized,
            ),
            time_policy: TimePolicy::default(),
            environment,
            adapters: Vec::new(),
            stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
            limits: heimdall_app::operations::Limits::default(),
            default_window: Duration::from_secs(3600),
            projection: None,
        })
        .await
        .unwrap();
        Supervisor::new(
            operations,
            SupervisorConfig {
                holder_interval: interval,
                ..SupervisorConfig::default()
            },
        )
        .with_jitter(Arc::new(FixedJitter(unit)))
    }

    /// Each wait is the interval with equal jitter, `[interval / 2, interval]`, and
    /// never shorter than `MIN_HOLDER_INTERVAL / 2` (no tight loop).
    #[tokio::test]
    async fn holder_waits_are_jittered_and_bounded() {
        assert_eq!(
            SupervisorConfig::default().holder_interval,
            DEFAULT_HOLDER_INTERVAL
        );
        let base = Duration::from_millis(400);
        for (unit, expected) in [(0.0, 200), (1.0, 400), (0.5, 300), (7.0, 400), (-1.0, 200)] {
            let sup = supervisor(base, unit).await;
            assert_eq!(sup.holder_wait(), Duration::from_millis(expected), "{unit}");
        }
        let sup = supervisor(Duration::ZERO, 0.0).await;
        assert_eq!(sup.holder_wait(), MIN_HOLDER_INTERVAL / 2);
    }

    /// The pass reads liveness through the injected source; with no held binding it
    /// observes nothing and releases nothing.
    #[tokio::test]
    async fn holder_pass_uses_the_injected_liveness() {
        struct Never(std::sync::atomic::AtomicUsize);
        impl ProcessLiveness for Never {
            fn state(&self, _holder: &ProcessHolder) -> HolderState {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                HolderState::Exited
            }
        }
        let never = Arc::new(Never(std::sync::atomic::AtomicUsize::new(0)));
        let sup = supervisor(DEFAULT_HOLDER_INTERVAL, 1.0)
            .await
            .with_liveness(never.clone());
        assert!(sup.holder_pass().await.unwrap().is_empty());
        assert_eq!(never.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
