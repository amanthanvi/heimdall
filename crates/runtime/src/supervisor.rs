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

use heimdall_app::Operations;
use heimdall_app::ports::{AdapterError, ResourceCleaner};
use heimdall_app::reconcile::{
    Action, Backoff, CleanupHook, CleanupPoint, guard_cleanup, plan, should_retry,
};
use heimdall_contract::event::EventType;
use heimdall_contract::ids::ResourceId;
use heimdall_contract::{Code, Timestamp};
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
}

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

/// Runs the resource owners, the deadline scheduler and the time guard.
pub struct Supervisor {
    operations: Operations,
    config: SupervisorConfig,
    state: Option<(Arc<Store>, Arc<dyn Clock>)>,
    cleanup: Option<tokio::sync::Mutex<CleanupExecutor>>,
    jitter: Arc<dyn Jitter>,
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
        Self {
            operations,
            config,
            state: None,
            cleanup: None,
            jitter: Arc::new(RandomJitter),
        }
    }

    /// Replace the retry jitter source (default [`RandomJitter`]); tests inject a
    /// deterministic one (ADR-0006 §13.6 item 4).
    #[must_use]
    pub fn with_jitter(mut self, jitter: Arc<dyn Jitter>) -> Self {
        self.jitter = jitter;
        self
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

    /// Run all loops until cancelled.
    pub async fn run(self, shutdown: CancellationToken) {
        let mut events = Some(self.operations.events().live_receiver());
        let start = Instant::now();
        let mut next_guard = start;
        let mut next_pass = start;
        let mut last_safe: Option<bool> = None;
        let mut last_mono = start;
        let mut last_cont = self.state.as_ref().map(|(_, c)| c.continuous());
        let resume_bound = self.config.resume_bound();
        loop {
            let mut wake = next_guard.min(next_pass);
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
                        }
                        last_safe = Some(safe);
                    }
                    Err(e) => tracing::warn!(code = %e.code, "time guard pass failed"),
                }
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
    pub async fn scheduler_pass(
        &self,
    ) -> Result<Option<heimdall_contract::Timestamp>, heimdall_app::OpError> {
        self.operations.tick().await?;
        self.next_wake().await
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
