//! A08 model variant through the production time gate (M01-U5t; spec §17 A08,
//! §6.2, §6.4; ADR-0005 §3.6; ADR-0006 §10 and rulings R2–R4, R7).
//!
//! The U3 cases of `tests/model/time.rs` re-run with the same expectations, but the
//! runtime anchor, the high-water mark, the attended confirmation and the grant
//! anchor now live in a real `heimdall_store::Store` (in memory, same schema and
//! code paths as on disk) and every assessment goes through
//! `heimdall_app::TimeGate` (`check`, `peek`, `confirm_attended`, `anchor_grant`,
//! `shorten_grant`, `admission`). Time is driven by `testkit::VirtualClock` and
//! `testkit::ScriptedTimeSync`; faults are injected only through the production
//! `heimdall_store::FaultHook`.
//!
//! Harness model (the operations wiring itself is U5):
//!
//! * `guard()` runs `peek` then `check` and asserts they agree (`Safe` ⇔ `Ok`;
//!   `Uncertain` ⇔ `TIME_UNCERTAIN`); every error message and envelope is scanned
//!   with `assert_no_canary`;
//! * `admits()` = `check` is `Ok` ∧ `permits_use` ∧ `TimeGate::admission == Open`;
//! * `schedule()` emits `DeadlineReached` on `Admission::Expired` only, evaluated on
//!   the persisted grant anchor at the raw observation (the wall branch can only
//!   deny; `NeedsAnchor` is not an expiry);
//! * `restart()` is a same-boot process restart: a new `TimeGate` over the same
//!   store (or a reopened database file), nothing kept in memory;
//! * `reanchor()` mirrors U3: after a `Safe` check, a grant anchor from another
//!   boot is re-created through `TimeGate::anchor_grant` with the **persisted**
//!   bound; in its own boot nothing is rebuilt.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use heimdall_app::{OpError, SafeNow, TimeGate};
use heimdall_contract::ids::{DecisionId, GrantId};
use heimdall_contract::request::DeadlineIntent;
use heimdall_contract::{Code, GrantState, Timestamp};
use heimdall_domain::lifecycle::{GrantEvent, grant_transition};
use heimdall_domain::time::{
    Admission, AttendedTimeConfirmation, Clock, Deadline, GrantAnchor, SyncStatus, TimeAnchor,
    TimePolicy, TimeStatus, TimeSync, TimeUncertainty, admission, anchor_grant, is_expired,
    resolve_deadline,
};
use heimdall_store::{FaultAction, FaultHook, FaultPoint, Store};
use heimdall_testkit::{ScriptedTimeSync, VirtualClock, assert_no_canary};

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const SECOND: Duration = Duration::from_secs(1);
const MAX_WINDOW: Duration = Duration::from_secs(12 * 3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap()
}

/// Production fault hook, armed on demand: fails at `point` while armed.
#[derive(Debug)]
struct Armed {
    point: FaultPoint,
    armed: AtomicBool,
}

impl Armed {
    fn new(point: FaultPoint) -> Arc<Self> {
        Arc::new(Self {
            point,
            armed: AtomicBool::new(false),
        })
    }
    fn arm(&self, on: bool) {
        self.armed.store(on, Ordering::SeqCst);
    }
}

impl FaultHook for Armed {
    fn at(&self, point: FaultPoint) -> FaultAction {
        if point == self.point && self.armed.load(Ordering::SeqCst) {
            FaultAction::Fail
        } else {
            FaultAction::Continue
        }
    }
}

/// Everything the time gate persists, read back from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Persisted {
    runtime_anchor: Option<TimeAnchor>,
    high_water: Option<Timestamp>,
    confirmation: Option<AttendedTimeConfirmation>,
    grant_anchor: Option<GrantAnchor>,
}

fn scan_error(e: &OpError) {
    assert_no_canary(&e.message);
    assert_no_canary(&e.to_string());
    assert_no_canary(&serde_json::to_string(&e.clone().into_envelope()).unwrap());
}

fn expect_uncertain<T: std::fmt::Debug>(r: Result<T, OpError>) -> OpError {
    let e = r.expect_err("expected TIME_UNCERTAIN");
    assert_eq!(e.code, Code::TimeUncertain, "{e}");
    scan_error(&e);
    e
}

struct Model {
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    policy: TimePolicy,
    faults: Arc<Armed>,
    store: Arc<Store>,
    /// Database file for restarts that reopen the store; `None` = in memory.
    file: Option<(tempfile::TempDir, PathBuf)>,
    gate: TimeGate,
    grant: GrantId,
    deadline: Deadline,
    /// Earliest owner cutoff set so far (N01; gap G11).
    cutoff: Option<Timestamp>,
    state: GrantState,
}

impl Model {
    async fn activate(intent: &str) -> Self {
        Self::activate_with(intent, false).await
    }

    /// First start at `t0` with synchronized time: resolve the deadline once, pass
    /// the gate, activate and anchor the grant through `TimeGate::anchor_grant`.
    async fn activate_with(intent: &str, on_disk: bool) -> Self {
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let policy = TimePolicy::default();
        let faults = Armed::new(FaultPoint::BeforeCommit);
        let file = on_disk.then(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.sqlite3");
            (dir, path)
        });
        let store = Arc::new(match &file {
            Some((_, path)) => Store::open(path, faults.clone()).unwrap(),
            None => Store::open_in_memory(faults.clone()).unwrap(),
        });
        let gate = TimeGate::new(store.clone(), clock.clone(), sync.clone(), policy);
        let deadline = resolve_deadline(
            &DeadlineIntent::Duration(intent.to_owned()),
            clock.wall(),
            MAX_WINDOW,
        )
        .unwrap();
        let mut m = Self {
            clock,
            sync,
            policy,
            faults,
            store,
            file,
            gate,
            grant: GrantId::from_random_bytes([9; 16]),
            deadline,
            cutoff: None,
            state: GrantState::Requested,
        };
        let safe = m.gate.check().await.expect("activation needs safe time");
        assert_eq!(safe.tolerance_used, Duration::ZERO);
        for e in [GrantEvent::Authorized, GrantEvent::Prepared] {
            m.state = grant_transition(m.state, e).unwrap();
        }
        let anchored = m
            .gate
            .anchor_grant(&m.grant, &safe, m.deadline.effective)
            .await
            .unwrap();
        assert_eq!(
            anchored,
            anchor_grant(m.grant.clone(), safe.anchor.clone(), m.deadline.effective)
        );
        m
    }

    fn persisted(&self) -> Persisted {
        let grant = self.grant.clone();
        self.store
            .transaction(|t| {
                Ok(Persisted {
                    runtime_anchor: t.runtime_anchor()?,
                    high_water: t.high_water_mark()?,
                    confirmation: t.time_confirmation()?,
                    grant_anchor: t.grant_anchor(&grant)?,
                })
            })
            .unwrap()
    }

    fn grant_anchor(&self) -> GrantAnchor {
        self.persisted().grant_anchor.expect("grant anchored")
    }

    fn high_water(&self) -> Option<Timestamp> {
        self.persisted().high_water
    }

    fn runtime_anchor(&self) -> Option<TimeAnchor> {
        self.persisted().runtime_anchor
    }

    /// `check` and `peek` agree; returns the status and the accepted observation.
    async fn guard_full(&mut self) -> (TimeStatus, Option<SafeNow>) {
        let peeked = self.gate.peek().await.unwrap();
        let before = self.persisted();
        match self.gate.check().await {
            Ok(safe) => {
                assert_eq!(peeked, TimeStatus::Safe, "peek and check disagree");
                (TimeStatus::Safe, Some(safe))
            }
            Err(e) => {
                assert_eq!(e.code, Code::TimeUncertain, "{e}");
                scan_error(&e);
                assert!(
                    matches!(peeked, TimeStatus::Uncertain(_)),
                    "peek and check disagree"
                );
                assert_eq!(self.persisted(), before, "Uncertain persisted something");
                (peeked, None)
            }
        }
    }

    async fn guard(&mut self) -> TimeStatus {
        self.guard_full().await.0
    }

    /// Raw admission at the current observation over the persisted grant anchor.
    fn admission_now(&self) -> Admission {
        admission(&self.grant_anchor(), &self.clock.observe())
    }

    fn schedule(&mut self) {
        if self.admission_now() == Admission::Expired
            && let Ok(next) = grant_transition(self.state, GrantEvent::DeadlineReached)
        {
            self.state = next;
        }
    }

    async fn admits(&mut self) -> bool {
        let (_, safe) = self.guard_full().await;
        self.schedule();
        let Some(safe) = safe else {
            return false;
        };
        let verdict = self.gate.admission(&self.grant, &safe).await.unwrap();
        self.state.permits_use() && verdict == Admission::Open
    }

    /// Same-boot process restart: nothing survives but the store (reopened from
    /// disk when file-backed).
    fn restart(&mut self) {
        if let Some((_, path)) = &self.file {
            // Drop every handle so the database is closed before reopening.
            let placeholder = Arc::new(Store::open_in_memory(self.faults.clone()).unwrap());
            self.gate = TimeGate::new(
                placeholder.clone(),
                self.clock.clone(),
                self.sync.clone(),
                self.policy,
            );
            self.store = placeholder;
            self.store = Arc::new(Store::open(path, self.faults.clone()).unwrap());
        }
        self.gate = TimeGate::new(
            self.store.clone(),
            self.clock.clone(),
            self.sync.clone(),
            self.policy,
        );
    }

    fn reboot(&mut self, wall: Timestamp) {
        self.clock.reboot(wall);
    }

    async fn reanchor(&mut self) -> bool {
        let (status, safe) = self.guard_full().await;
        let Some(safe) = safe else {
            assert!(matches!(status, TimeStatus::Uncertain(_)));
            return false;
        };
        let stored = self.grant_anchor();
        if stored.anchor.boot_id != safe.anchor.boot_id {
            let rebuilt = self
                .gate
                .anchor_grant(&self.grant, &safe, stored.bound)
                .await
                .unwrap();
            assert_eq!(rebuilt.anchor, safe.anchor);
        }
        assert_eq!(
            self.grant_anchor().bound,
            self.current_bound(),
            "the bound never moves later"
        );
        true
    }

    /// `min(deadline, cutoff)`: the bound the persisted anchor must carry.
    fn current_bound(&self) -> Timestamp {
        self.cutoff
            .map_or(self.deadline.effective, |c| c.min(self.deadline.effective))
    }

    /// The owner sets a cutoff: the persisted anchor is shortened through
    /// `TimeGate::shorten_grant` (N01: the budget drops by the bound reduction, so
    /// a tolerance margin is kept).
    async fn cutoff(&mut self, at: Timestamp) {
        self.cutoff = Some(self.cutoff.map_or(at, |c| c.min(at)));
        let bound = self.current_bound();
        let cut = self
            .gate
            .shorten_grant(&self.grant, bound)
            .await
            .unwrap()
            .expect("anchored grant");
        assert_eq!(cut.bound, bound);
        assert_eq!(self.grant_anchor(), cut);
    }

    /// Attended owner confirmation of the clock as shown (the caller has verified
    /// attendance and consumed the decision).
    async fn confirm_time(&mut self) -> Result<AttendedTimeConfirmation, OpError> {
        let before = self.persisted();
        let r = self
            .gate
            .confirm_attended(self.clock.wall(), DecisionId::from_random_bytes([5; 16]))
            .await;
        let after = self.persisted();
        assert_eq!(
            after.grant_anchor, before.grant_anchor,
            "confirmation never touches a grant anchor"
        );
        if let Err(e) = &r {
            scan_error(e);
            assert_eq!(after, before, "a refused confirmation persisted something");
        }
        r
    }

    fn budget_left(&self) -> Duration {
        self.grant_anchor()
            .budget_end
            .saturating_sub(self.clock.continuous())
    }
}

fn assert_expired_for_good(m: &Model) {
    assert_eq!(m.state, GrantState::Expired);
    for e in [
        GrantEvent::Repaired,
        GrantEvent::Prepared,
        GrantEvent::Approved,
        GrantEvent::Authorized,
    ] {
        assert!(
            grant_transition(m.state, e).is_err(),
            "expired moved on {e:?}"
        );
    }
}

// =====================================================================================
// U3 A08 cases re-run through TimeGate + store.
// =====================================================================================

#[tokio::test]
async fn sleep_across_expiry_expires_and_is_never_extended() {
    let mut m = Model::activate("PT1H").await;
    let original = m.deadline.clone();
    let anchor = m.grant_anchor();
    assert!(m.admits().await);

    m.clock.advance_continuous_only(2 * HOUR);
    assert!(!is_expired(m.clock.wall(), m.deadline.effective));
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert_eq!(
        m.admission_now(),
        Admission::Expired,
        "budget spent in sleep"
    );
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
    assert!(!m.admits().await);

    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert!(!m.admits().await);
    assert_eq!(m.deadline, original);
    assert_eq!(m.grant_anchor(), anchor, "budget never rebuilt");
    assert_expired_for_good(&m);
}

#[tokio::test]
async fn sleep_with_wall_running_expires_at_the_persisted_instant() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(HOUR - SECOND);
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(!m.admits().await);
    assert_eq!(m.state, GrantState::Expired);
    assert_eq!(m.clock.wall(), m.deadline.effective);
    assert_eq!(m.clock.continuous(), m.grant_anchor().budget_end);
}

#[tokio::test]
async fn backward_jump_is_time_uncertain_and_budget_still_runs_out() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    assert!(m.admits().await);
    let mark = m.high_water().unwrap();
    assert_eq!(mark, shift(t0(), 600));

    m.clock.set_wall(shift(t0(), 600 - 3600));
    assert_eq!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(t0(), 600 - 3600),
        })
    );
    assert!(!m.admits().await);
    assert_eq!(m.high_water(), Some(mark), "the mark never decreases");

    m.clock.advance(50 * MINUTE);
    assert!(!m.admits().await);
    assert_eq!(m.state, GrantState::Expired);
    assert!(!is_expired(m.clock.wall(), m.deadline.effective));
}

#[tokio::test]
async fn forward_jump_without_continuous_progress_is_uncertain_and_wall_branch_expires() {
    let mut m = Model::activate("PT1H").await;
    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert_eq!(m.admission_now(), Admission::Expired);
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
    assert!(!m.admits().await);
}

#[tokio::test]
async fn forward_jump_within_tolerance_only_ends_access_sooner() {
    let mut m = Model::activate("PT1H").await;
    m.clock
        .set_wall(shift(t0(), secs(m.policy.max_tolerated_skew)));
    assert!(m.admits().await);
    m.clock.advance(HOUR - MINUTE - SECOND);
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(!m.admits().await);
    assert_eq!(m.state, GrantState::Expired);
    assert!(m.budget_left() > Duration::ZERO, "wall branch, not budget");
}

#[tokio::test]
async fn restart_with_stuck_wall_must_not_extend_the_budget() {
    let mut m = Model::activate("PT1H").await;
    let anchor = m.grant_anchor();
    m.clock.advance_continuous_only(50 * MINUTE);
    m.restart();
    assert_eq!(
        m.grant_anchor(),
        anchor,
        "same boot: persisted anchor resumed"
    );
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.reanchor().await);
    assert_eq!(
        m.grant_anchor(),
        anchor,
        "never rebuilt from the stuck wall"
    );
    m.clock.advance(50 * MINUTE);
    assert!(
        !m.admits().await,
        "admitted 100 real minutes into a 1 h grant"
    );
    assert_eq!(m.state, GrantState::Expired);
    m.clock.set_wall(shift(t0(), 100 * 60));
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert!(!m.admits().await);
    assert_expired_for_good(&m);
}

#[tokio::test]
async fn stuck_wall_checked_often_and_restarted_still_expires_on_real_time() {
    let mut m = Model::activate("PT1H").await;
    let step = m.policy.max_tolerated_skew;
    let mut real = Duration::ZERO;
    while real < 30 * MINUTE {
        m.clock.advance_continuous_only(step);
        real += step;
        assert!(m.admits().await, "admits at {real:?}");
    }
    m.restart();
    loop {
        m.clock.advance_continuous_only(step);
        real += step;
        let admitted = m.admits().await;
        assert_eq!(admitted, real < HOUR, "at {real:?}");
        if !admitted {
            break;
        }
    }
    assert_eq!(real, HOUR);
    assert_eq!(m.state, GrantState::Expired);
    assert_eq!(m.clock.wall(), t0(), "the wall never moved");
}

async fn same_boot_restart_keeps_the_remaining_budget(on_disk: bool) {
    let mut m = Model::activate_with("PT1H", on_disk).await;
    let original = m.deadline.clone();
    let anchor = m.grant_anchor();
    m.clock.advance(30 * MINUTE);
    assert!(m.admits().await);
    let before = m.persisted();
    let (boot, continuous) = (m.clock.boot_id(), m.clock.continuous());

    m.restart();
    assert_eq!(m.persisted(), before, "every row survives the restart");
    assert_eq!(m.clock.boot_id(), boot);
    assert_eq!(m.clock.continuous(), continuous);
    assert_eq!(m.grant_anchor(), anchor);
    assert!(m.reanchor().await);
    assert_eq!(m.grant_anchor(), anchor, "never rebuilt in its own boot");
    assert_eq!(m.budget_left(), 30 * MINUTE, "exactly the remaining budget");
    assert!(m.admits().await);
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(!m.admits().await);
    assert_eq!(m.clock.wall(), original.effective);
    assert_eq!(m.state, GrantState::Expired);
}

#[tokio::test]
async fn same_boot_restart_keeps_the_deadline_and_the_remaining_budget() {
    same_boot_restart_keeps_the_remaining_budget(false).await;
}

#[tokio::test]
async fn same_boot_restart_from_a_reopened_database_keeps_the_exact_budget() {
    same_boot_restart_keeps_the_remaining_budget(true).await;
}

#[tokio::test]
async fn reboot_with_wall_below_the_mark_is_refused_even_when_synchronized() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(30 * MINUTE);
    assert!(m.admits().await);
    let mark = m.high_water().unwrap();

    m.reboot(shift(t0(), 10 * 60));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(t0(), 10 * 60),
        })
    );
    assert!(!m.reanchor().await);
    assert!(!m.admits().await);
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
    assert_eq!(
        m.state,
        GrantState::Active,
        "a void anchor is not an expiry"
    );
    // An attended confirmation cannot accept a wall below the mark either: it is
    // refused and persists nothing.
    expect_uncertain(m.confirm_time().await);
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
    ));
    assert!(!m.reanchor().await);
    assert_eq!(m.high_water(), Some(mark));
}

#[tokio::test]
async fn reboot_above_the_mark_needs_synchronized_time_and_keeps_the_bound() {
    let mut m = Model::activate("PT1H").await;
    let original = m.deadline.clone();
    m.clock.advance(20 * MINUTE);
    assert!(m.admits().await);

    m.reboot(shift(t0(), 30 * 60));
    for sync in [SyncStatus::Unknown, SyncStatus::NotSynchronized] {
        m.sync.set(sync);
        assert_eq!(
            m.guard().await,
            TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { sync })
        );
        assert!(!m.reanchor().await, "{sync:?}");
        assert!(!m.admits().await, "{sync:?}");
        assert_eq!(m.admission_now(), Admission::NeedsAnchor);
        assert_eq!(m.state, GrantState::Active);
    }

    m.sync.set(SyncStatus::Synchronized);
    // Before re-anchoring, TimeGate::admission refuses with NeedsAnchor.
    let (_, safe) = m.guard_full().await;
    let safe = safe.unwrap();
    assert_eq!(
        m.gate.admission(&m.grant, &safe).await.unwrap(),
        Admission::NeedsAnchor
    );
    assert!(m.reanchor().await);
    assert_eq!(m.grant_anchor().anchor.boot_id, m.clock.boot_id());
    assert_eq!(
        m.grant_anchor().bound,
        original.effective,
        "same persisted bound"
    );
    assert_eq!(m.budget_left(), 30 * MINUTE, "no fresh budget");
    assert!(m.admits().await);
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(!m.admits().await);
    assert_eq!(m.clock.wall(), original.effective);
    assert_eq!(m.deadline, original);
    assert_expired_for_good(&m);
}

#[tokio::test]
async fn reboot_with_attended_confirmation_resolves_without_moving_the_deadline() {
    let mut m = Model::activate("PT1H").await;
    let original = m.deadline.clone();
    m.clock.advance(20 * MINUTE);
    assert!(m.admits().await);

    m.reboot(shift(t0(), 30 * 60));
    m.sync.set(SyncStatus::Unknown);
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
    ));
    assert!(!m.admits().await);

    m.confirm_time().await.unwrap();
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert!(m.reanchor().await);
    assert_eq!(m.deadline, original);
    assert_eq!(m.grant_anchor().bound, original.effective);
    // R4: accepted through the confirmation's prediction, so the rebuilt budget is
    // cut by the skew tolerance.
    assert_eq!(m.budget_left(), 30 * MINUTE - m.policy.max_tolerated_skew);
    assert!(m.admits().await);
    m.clock.advance(15 * MINUTE);
    assert!(m.admits().await);

    // A confirmation covers only its own boot (R7: compared by the gate).
    let left = m.budget_left();
    m.restart();
    assert!(m.admits().await, "same boot after restart");
    assert_eq!(m.budget_left(), left);
    m.reboot(shift(t0(), 50 * 60));
    assert!(
        m.persisted().confirmation.is_some(),
        "the stale confirmation is still on record"
    );
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
    ));
    assert!(!m.reanchor().await);
    assert!(!m.admits().await);
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
}

#[tokio::test]
async fn rolled_back_clock_above_the_mark_after_downtime_is_refused_unsynchronized() {
    let mut m = Model::activate("PT3H").await;
    m.clock.advance(HOUR);
    assert!(m.admits().await);
    let mark = m.high_water().unwrap();
    assert_eq!(mark, shift(t0(), 3600));

    m.reboot(shift(t0(), 3600 + 60));
    m.sync.set(SyncStatus::NotSynchronized);
    assert!(m.clock.wall() > mark);
    assert_eq!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
            sync: SyncStatus::NotSynchronized
        })
    );
    assert!(!m.reanchor().await);
    assert!(!m.admits().await);

    m.clock.set_wall(shift(t0(), 3 * 3600 + 5));
    m.sync.set(SyncStatus::Synchronized);
    assert!(m.reanchor().await);
    assert_eq!(m.admission_now(), Admission::Expired);
    assert!(!m.admits().await);
    assert_expired_for_good(&m);
}

#[tokio::test]
async fn frozen_wall_checked_every_thirty_seconds_becomes_uncertain() {
    let mut m = Model::activate("PT2H").await;
    m.sync.set(SyncStatus::Unknown);
    let anchor_before = m.runtime_anchor();
    let mark_before = m.high_water();
    for _ in 0..2 {
        m.clock.advance_continuous_only(30 * SECOND);
        assert_eq!(m.guard().await, TimeStatus::Safe);
    }
    assert_eq!(
        m.runtime_anchor(),
        anchor_before,
        "R2: no re-base unsynchronized"
    );
    assert_eq!(m.high_water(), mark_before, "frozen wall: mark unchanged");
    m.clock.advance_continuous_only(30 * SECOND);
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.admits().await);
    m.clock.set_wall(shift(t0(), 90));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert_ne!(m.runtime_anchor(), anchor_before);
    assert_eq!(m.runtime_anchor(), Some(m.clock.observe()));
}

#[tokio::test]
async fn same_boot_skew_is_cleared_by_attended_confirmation_without_moving_anything() {
    let mut m = Model::activate("PT1H").await;
    m.sync.set(SyncStatus::Unknown);
    m.clock.advance(10 * MINUTE);
    assert!(m.admits().await);
    let deadline = m.deadline.clone();
    let budget = m.grant_anchor();
    m.clock.set_wall(shift(t0(), 30 * 60));
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.admits().await);
    let conf = m.confirm_time().await.unwrap();
    // R3: the confirmation is the new runtime anchor for this boot.
    assert_eq!(m.runtime_anchor(), Some(conf.as_anchor()));
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert!(m.admits().await);
    assert_eq!(m.deadline, deadline);
    assert_eq!(
        m.grant_anchor(),
        budget,
        "confirmation never rebuilds a budget"
    );
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(!m.admits().await);
    assert_eq!(m.clock.wall(), m.deadline.effective);
}

/// R4 with N05 (ADR-0006 §13.4): after a reboot a synchronized clock 4 s below the
/// mark is uncertain (no rollback allowance without a same-boot reference) until an
/// attended confirmation becomes this boot's reference; the re-anchor from that
/// acceptance carries the rollback share and ends early, never late.
#[tokio::test]
async fn reboot_synchronized_slightly_below_mark_is_uncertain_until_confirmed() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(30 * MINUTE);
    assert!(m.admits().await);
    let mark = m.high_water().unwrap();
    m.reboot(shift(shift(t0(), 30 * 60), -4));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(mark, -4),
        })
    );
    assert!(!m.reanchor().await);
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
    // Within the rollback tolerance of the mark the confirmation is accepted.
    m.confirm_time().await.unwrap();
    assert_eq!(m.high_water(), Some(mark), "the mark never decreases");
    let (_, safe) = m.guard_full().await;
    assert_eq!(
        safe.unwrap().tolerance_used,
        m.policy.max_tolerated_rollback
    );
    assert!(m.reanchor().await);
    assert_eq!(
        m.grant_anchor().budget_end,
        Duration::from_secs(30 * 60 - 1)
    );
    m.clock.advance(Duration::from_secs(30 * 60 - 2));
    assert!(m.admits().await);
    m.clock.advance(SECOND);
    assert!(
        !m.admits().await,
        "ends at most the tolerance early, never late"
    );
}

// =====================================================================================
// Persistence properties of the gate.
// =====================================================================================

/// `Uncertain` persists nothing, for every uncertainty the virtual clock can
/// produce (a continuous clock running backwards cannot be scripted).
#[tokio::test]
async fn uncertain_persists_nothing() {
    // Skew (frozen wall), with a confirmation on record from this boot.
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(5 * MINUTE);
    m.confirm_time().await.unwrap();
    m.clock.advance_continuous_only(10 * MINUTE);
    let before = m.persisted();
    assert!(before.confirmation.is_some());
    let e = expect_uncertain(m.gate.check().await);
    assert!(e.message.contains("skew"), "{e}");
    assert_eq!(e.resource.as_ref().map(|r| r.kind.as_str()), Some("clock"));
    assert_eq!(m.persisted(), before);

    // BelowHighWater.
    let m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    m.gate.check().await.unwrap();
    m.clock.set_wall(shift(t0(), 0));
    let before = m.persisted();
    let e = expect_uncertain(m.gate.check().await);
    assert!(e.message.contains("rollback"), "{e}");
    assert_eq!(m.persisted(), before);

    // Unsynchronized after reboot, both reports.
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    m.gate.check().await.unwrap();
    m.reboot(shift(t0(), 20 * 60));
    for sync in [SyncStatus::Unknown, SyncStatus::NotSynchronized] {
        m.sync.set(sync);
        let before = m.persisted();
        let e = expect_uncertain(m.gate.check().await);
        assert!(e.message.contains("synchroniz"), "{e}");
        assert_eq!(m.persisted(), before);
    }
    // peek never persists, even when Safe.
    m.sync.set(SyncStatus::Synchronized);
    let before = m.persisted();
    assert_eq!(m.gate.peek().await.unwrap(), TimeStatus::Safe);
    assert_eq!(m.persisted(), before);
}

/// `Safe` persists the runtime anchor and the mark in one transaction: a store
/// failure at `BeforeCommit` leaves both unchanged; the next pass writes both.
#[tokio::test]
async fn safe_persists_anchor_and_mark_atomically() {
    let m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    let first = m.gate.check().await.unwrap();
    let p = m.persisted();
    assert_eq!(p.runtime_anchor, Some(first.anchor.clone()));
    assert_eq!(p.high_water, Some(first.wall()));

    m.clock.advance(10 * MINUTE);
    let before = m.persisted();
    m.faults.arm(true);
    let e = m.gate.check().await.expect_err("injected fault");
    m.faults.arm(false);
    assert_eq!(e.code, Code::StateUnavailable);
    scan_error(&e);
    assert_eq!(m.persisted(), before, "neither anchor nor mark moved");
    assert_eq!(before.runtime_anchor, Some(first.anchor.clone()));
    assert_eq!(before.high_water, Some(first.wall()));

    let second = m.gate.check().await.unwrap();
    let p = m.persisted();
    assert_eq!(p.runtime_anchor, Some(second.anchor.clone()));
    assert_eq!(p.high_water, Some(second.wall()));
    assert_eq!(second.wall(), shift(t0(), 20 * 60));
}

/// R2: an unsynchronized `Safe` pass advances the mark but keeps the anchor.
#[tokio::test]
async fn unsynchronized_safe_pass_advances_the_mark_and_keeps_the_anchor() {
    let m = Model::activate("PT1H").await;
    let anchor = m.runtime_anchor();
    m.sync.set(SyncStatus::Unknown);
    m.clock.advance(20 * SECOND);
    let safe = m.gate.check().await.unwrap();
    assert_eq!(safe.sync, SyncStatus::Unknown);
    assert_eq!(safe.tolerance_used, m.policy.max_tolerated_skew);
    assert_eq!(m.runtime_anchor(), anchor);
    assert_eq!(m.high_water(), Some(shift(t0(), 20)));
}

/// `confirm_attended` refuses an owner value outside the skew tolerance (inclusive
/// boundary accepted) and never changes the grant anchor.
#[tokio::test]
async fn confirm_attended_refuses_values_outside_tolerance_and_never_moves_grant_anchor() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    m.sync.set(SyncStatus::Unknown);
    m.clock.set_wall(shift(m.clock.wall(), 5 * 60));
    assert!(matches!(
        m.guard().await,
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    let grant_before = m.grant_anchor();
    let tol = secs(m.policy.max_tolerated_skew);
    let wall = m.clock.wall();
    for off in [tol + 1, -(tol + 1), 3600, -3600] {
        let before = m.persisted();
        let offered = shift(wall, off);
        let e = expect_uncertain(
            m.gate
                .confirm_attended(offered, DecisionId::from_random_bytes([6; 16]))
                .await,
        );
        assert!(
            !e.message.contains(&offered.to_string()),
            "error echoes the owner's value"
        );
        assert_eq!(m.persisted(), before, "refusal persisted something");
        assert!(matches!(m.guard().await, TimeStatus::Uncertain(_)));
    }
    // Exactly the tolerance away is accepted; the clock's own reading is recorded.
    let decision = DecisionId::from_random_bytes([7; 16]);
    let conf = m
        .gate
        .confirm_attended(shift(wall, -tol), decision.clone())
        .await
        .unwrap();
    assert_eq!(conf.wall, wall);
    assert_eq!(conf.decision, decision);
    assert_eq!(conf.boot_id, m.clock.boot_id());
    let p = m.persisted();
    assert_eq!(p.confirmation, Some(conf.clone()));
    assert_eq!(p.runtime_anchor, Some(conf.as_anchor()));
    assert_eq!(p.high_water, Some(wall));
    assert_eq!(p.grant_anchor, Some(grant_before.clone()));
    assert_eq!(m.guard().await, TimeStatus::Safe);
    assert_eq!(m.grant_anchor(), grant_before);
    assert_eq!(m.grant_anchor().bound, m.deadline.effective);
}

/// R4 + store min(): a same-boot `anchor_grant` never lengthens the bound or the
/// budget; a shorter bound or a larger tolerance only shortens it.
#[tokio::test]
async fn anchor_grant_in_the_same_boot_keeps_the_minimum() {
    let m = Model::activate("PT1H").await;
    let original = m.grant_anchor();
    m.clock.advance(10 * MINUTE);
    let safe = m.gate.check().await.unwrap();

    // A later bound from a later observation: unchanged.
    let later = shift(m.deadline.effective, 3600);
    let got = m.gate.anchor_grant(&m.grant, &safe, later).await.unwrap();
    assert_eq!(got, original);
    assert_eq!(m.grant_anchor(), original);

    // Same bound, accepted within a tolerance: budget cut by it, bound kept.
    let tolerant = SafeNow {
        tolerance_used: 30 * SECOND,
        ..safe.clone()
    };
    let got = m
        .gate
        .anchor_grant(&m.grant, &tolerant, m.deadline.effective)
        .await
        .unwrap();
    assert_eq!(got.bound, original.bound);
    assert_eq!(got.budget_end, original.budget_end - 30 * SECOND);
    assert_eq!(m.grant_anchor(), got);

    // An earlier bound with zero tolerance: bound shortened, budget min()'d. The
    // stored budget is reduced by the bound reduction (N01), so the 30 s margin cut
    // above is kept: 40 min − 30 s, less than the fresh 40 min.
    let earlier = shift(t0(), 40 * 60);
    let got2 = m.gate.anchor_grant(&m.grant, &safe, earlier).await.unwrap();
    assert_eq!(got2.bound, earlier);
    assert_eq!(got2.budget_end, 40 * MINUTE - 30 * SECOND);
    assert!(got2.budget_end <= got.budget_end);
    assert_eq!(m.grant_anchor(), got2);
}

/// An observation from another boot cannot anchor a budget.
#[tokio::test]
async fn anchor_grant_refuses_an_observation_from_another_boot() {
    let mut m = Model::activate("PT1H").await;
    m.clock.advance(10 * MINUTE);
    let stale = m.gate.check().await.unwrap();
    m.reboot(shift(t0(), 20 * 60));
    let before = m.persisted();
    expect_uncertain(
        m.gate
            .anchor_grant(&m.grant, &stale, m.deadline.effective)
            .await,
    );
    assert_eq!(m.persisted(), before);
}

/// `shorten_grant` only shortens; unknown grants are `None`.
#[tokio::test]
async fn shorten_grant_never_lengthens() {
    let m = Model::activate("PT1H").await;
    let original = m.grant_anchor();
    let none = m
        .gate
        .shorten_grant(&GrantId::from_random_bytes([1; 16]), t0())
        .await
        .unwrap();
    assert_eq!(none, None);

    let later = shift(m.deadline.effective, 600);
    let same = m.gate.shorten_grant(&m.grant, later).await.unwrap();
    assert_eq!(same, Some(original.clone()));
    assert_eq!(m.grant_anchor(), original);

    let cutoff = shift(t0(), 20 * 60);
    let cut = m
        .gate
        .shorten_grant(&m.grant, cutoff)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cut.bound, cutoff);
    assert_eq!(cut.budget_end, 20 * MINUTE);
    assert_eq!(m.grant_anchor(), cut);
    // A later bound after the cut does not undo it.
    m.gate.shorten_grant(&m.grant, later).await.unwrap();
    assert_eq!(m.grant_anchor(), cut);
}

/// `admission`: no anchor ⇒ `NeedsAnchor`; a stale `SafeNow` never admits past the
/// budget.
#[tokio::test]
async fn admission_fails_closed_without_anchor_and_on_stale_observation() {
    let m = Model::activate("PT1H").await;
    let safe = m.gate.check().await.unwrap();
    assert_eq!(
        m.gate
            .admission(&GrantId::from_random_bytes([2; 16]), &safe)
            .await
            .unwrap(),
        Admission::NeedsAnchor
    );
    assert_eq!(
        m.gate.admission(&m.grant, &safe).await.unwrap(),
        Admission::Open
    );
    // An hour of real time passes while the caller still holds the old SafeNow.
    m.clock.advance_continuous_only(HOUR);
    assert_eq!(
        m.gate.admission(&m.grant, &safe).await.unwrap(),
        Admission::Expired
    );
}

// =====================================================================================
// N01 through the gate with a nonzero tolerance (gap G11).
// =====================================================================================

/// N01 reviewer counterexample through `TimeGate`: a re-anchor accepted with the
/// 60 s skew tolerance (unsynchronized reboot, attended confirmation), then a
/// cutoff 30 s before the bound. `shorten_grant` drops the budget by exactly the
/// bound reduction, keeping the tolerance margin; the pre-fix recomputation from
/// the raw anchor (`min(old, anchor + (new_bound - wall))`) would not have
/// shortened it at all.
#[tokio::test]
async fn shorten_preserves_tolerance_margin_reviewer_counterexample_through_the_gate() {
    let mut m = Model::activate("PT1H").await;
    m.sync.set(SyncStatus::Unknown);
    let truth = shift(t0(), 10 * 60);
    m.reboot(truth);
    m.confirm_time().await.unwrap();
    let (status, safe) = m.guard_full().await;
    assert_eq!(status, TimeStatus::Safe);
    let safe = safe.unwrap();
    assert_eq!(safe.tolerance_used, m.policy.max_tolerated_skew);
    let bound = m.grant_anchor().bound;
    let tolerant = m.gate.anchor_grant(&m.grant, &safe, bound).await.unwrap();
    let raw_left = Duration::try_from(bound.duration_since(safe.anchor.wall)).unwrap();
    assert_eq!(
        tolerant.budget_end,
        safe.anchor.continuous + raw_left - m.policy.max_tolerated_skew,
        "R4: the re-anchor deducts the tolerance"
    );
    let new_bound = shift(bound, -30);
    m.cutoff(new_bound).await;
    let cut = m.grant_anchor();
    assert_eq!(cut.bound, new_bound);
    assert_eq!(
        cut.budget_end,
        tolerant.budget_end - 30 * SECOND,
        "N01: the budget drops by the bound reduction"
    );
    let pre_fix = (safe.anchor.continuous + (raw_left - 30 * SECOND)).min(tolerant.budget_end);
    assert_eq!(
        pre_fix, tolerant.budget_end,
        "the pre-fix value kept the old budget"
    );
    assert!(cut.budget_end < pre_fix);
    // The wall lags the truth by the full tolerance: one second before the
    // shortened budget ends the grant is open, at its end it is expired, although
    // the wall branch alone would still admit.
    let left = cut.budget_end - m.clock.continuous();
    m.clock.advance_continuous_only(left - SECOND);
    assert_eq!(m.admission_now(), Admission::Open);
    m.clock.advance_continuous_only(SECOND);
    assert!(
        m.clock.wall() < new_bound,
        "the wall branch alone would admit"
    );
    assert_eq!(m.admission_now(), Admission::Expired);
    assert!(!m.admits().await);
}

/// N01 end to end through the gate: tolerance-aware re-anchoring after a confirmed
/// reboot, then a cutoff, with the wall lagging the truth: admission stops by the
/// true cutoff (mirror of `model_time`'s case, with every row in the store).
#[tokio::test]
async fn cutoff_after_tolerant_reanchor_stops_admission_by_the_true_cutoff() {
    let mut m = Model::activate("PT2H").await;
    m.sync.set(SyncStatus::Unknown);
    m.clock.advance(10 * MINUTE);
    assert!(m.admits().await);
    let truth = shift(t0(), 15 * 60);
    m.reboot(truth);
    m.confirm_time().await.unwrap();
    assert!(m.reanchor().await);
    // The wall freezes for 50 s, lagging the truth (within the skew tolerance).
    m.clock.advance_continuous_only(50 * SECOND);
    let mut real = 50 * SECOND;
    assert_eq!(m.guard().await, TimeStatus::Safe);
    let cut = shift(truth, 30 * 60);
    m.cutoff(cut).await;
    let mut last_admitted = None;
    while real < 31 * MINUTE {
        if m.admits().await {
            last_admitted = Some(real);
        }
        m.clock.advance(SECOND * 10);
        real += SECOND * 10;
    }
    let last = last_admitted.expect("admitted before the cutoff");
    assert!(
        last >= 20 * MINUTE,
        "admission ran until close to the cutoff"
    );
    assert!(
        last < 30 * MINUTE,
        "admitted at {last:?}, at/after the true cutoff"
    );
}

// =====================================================================================
// Property: no admission after the true bound (proptest; mirrors U3 `props_rev2`
// through the gate, with Cutoff steps; gap G11).
// =====================================================================================

mod props_gate {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// Steps the owner, the machine and the clock may take. Truth = t0 + real.
    #[derive(Debug, Clone)]
    enum Step {
        Pass(u64),
        FrozenWall(u64),
        WallJump(i64),
        Restart,
        /// Downtime, wall drift from the truth after the reboot, and whether the
        /// platform reports synchronized time (truthfully: only with no drift).
        Reboot {
            down: u64,
            drift: i64,
            sync: bool,
        },
        /// The owner confirms a clock within the skew tolerance of the truth.
        Confirm,
        Reanchor,
        /// A cutoff this many seconds after the runtime's wall clock (N01).
        Cutoff(i64),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (1u64..1200).prop_map(Step::Pass),
            (1u64..1200).prop_map(Step::FrozenWall),
            (-7200i64..7200).prop_map(Step::WallJump),
            Just(Step::Restart),
            (0u64..7200, -7200i64..7200, any::<bool>())
                .prop_map(|(down, drift, sync)| Step::Reboot { down, drift, sync }),
            Just(Step::Confirm),
            Just(Step::Reanchor),
            (-600i64..7200).prop_map(Step::Cutoff),
        ]
    }

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
            c.rng_seed = RngSeed::Fixed(0x5435_7454_4741_5445);
        }
        c
    }

    async fn trace(minutes: u64, steps: Vec<Step>) -> Result<(), TestCaseError> {
        let mut m = Model::activate(&format!("{minutes}m")).await;
        let granted = Duration::from_secs(minutes * 60);
        let mut real = Duration::ZERO;
        let truth = |real: Duration| shift(t0(), secs(real));
        for s in steps {
            match s {
                Step::Pass(d) => {
                    m.clock.advance(Duration::from_secs(d));
                    real += Duration::from_secs(d);
                }
                Step::FrozenWall(d) => {
                    m.clock.advance_continuous_only(Duration::from_secs(d));
                    real += Duration::from_secs(d);
                }
                Step::WallJump(d) => m.clock.set_wall(shift(m.clock.wall(), d)),
                Step::Restart => m.restart(),
                Step::Reboot { down, drift, sync } => {
                    real += Duration::from_secs(down);
                    // A truthful platform reports synchronization only for a wall
                    // clock showing real time (ADR-0006 §13.3 item 4).
                    if sync {
                        m.reboot(truth(real));
                        m.sync.set(SyncStatus::Synchronized);
                    } else {
                        m.reboot(shift(truth(real), drift));
                        m.sync.set(SyncStatus::Unknown);
                    }
                    m.restart();
                }
                Step::Confirm => {
                    let off = m.clock.wall().duration_since(truth(real)).unsigned_abs();
                    if off <= m.policy.max_tolerated_skew {
                        let _ = m.confirm_time().await;
                    }
                }
                Step::Reanchor => {
                    let _ = m.reanchor().await;
                }
                Step::Cutoff(after) => m.cutoff(shift(m.clock.wall(), after)).await,
            }
            if m.clock.wall() != truth(real) && m.sync.status() == SyncStatus::Synchronized {
                m.sync.set(SyncStatus::NotSynchronized);
            }
            let admitted = m.admits().await;
            prop_assert!(
                !(admitted && real >= granted),
                "admitted after {:?} of {:?}",
                real,
                granted
            );
            prop_assert!(
                !(admitted && truth(real) >= m.current_bound()),
                "admitted at {:?}, at/after the current bound {:?}",
                truth(real),
                m.current_bound()
            );
            prop_assert_eq!(m.grant_anchor().bound, m.current_bound());
            if !m.state.permits_use() {
                prop_assert!(m.state.is_terminal());
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        /// No admission after the true bound `min(deadline, cutoff)` across sleep,
        /// wall jumps, restarts, reboots (synchronized or not), attended
        /// confirmations, tolerance-aware re-anchors and cutoffs, every row
        /// persisted in the store and every assessment through `TimeGate`.
        #[test]
        fn no_admission_after_true_bound_through_the_gate(
            minutes in 1u64..=720,
            steps in prop::collection::vec(step(), 1..40),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(trace(minutes, steps))?;
        }
    }
}
