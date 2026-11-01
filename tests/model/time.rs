//! A08 model variant (spec §17 A08, §6.2, §6.4; ADR-0005 §3.6 revision 3; plan §5
//! M01-T02; review F01): sleep, clock jumps, process restart and reboot never add
//! authority. Driven by `heimdall_testkit::VirtualClock` (wall clock, boot-scoped
//! continuous clock, boot ID) and `ScriptedTimeSync` against the production
//! `heimdall_domain::time` rules.
//!
//! Model of the runtime used here (the real wiring is U5/U8):
//!
//! * persisted rows: the grant's resolved [`Deadline`], the runtime anchor (the last
//!   observation the gate assessed `Safe`), the high-water mark, the grant's
//!   [`GrantAnchor`], an attended time confirmation if one was given, and the grant
//!   state;
//! * `guard()` is the shared gate ([`gate`]) over the persisted runtime anchor and
//!   mark, the current observation, the sync report and the confirmation; on `Safe`
//!   it persists the mark from [`next_high_water`] and the anchor chosen by
//!   [`next_runtime_anchor`] (re-based only on synchronized time; design-fix R2);
//!   an attended confirmation installs its own anchor (R3); a re-anchor after a
//!   reboot subtracts the tolerance the gate used ([`anchor_grant_with_tolerance`],
//!   R4);
//! * `admits()` = `Safe` ∧ `permits_use` ∧ [`admission`] `== Open`;
//! * `schedule()` emits `DeadlineReached` on `Admission::Expired` only
//!   (`NeedsAnchor` is not an expiry);
//! * `restart()` is a same-boot process restart: nothing happens to the clock
//!   (continuous time is boot-scoped) and every persisted row is re-read from JSON;
//! * `reboot(wall)` changes the boot, which voids the grant anchor (`NeedsAnchor`,
//!   fail closed) until `reanchor()` re-creates it from a `Safe` observation via
//!   [`anchor_grant`] with the **same persisted bound**. In the boot it was created
//!   in, a grant anchor is never rebuilt (ADR-0005 §3.6 "never rebuilds a budget
//!   from the current wall clock");
//! * `cutoff(at)` is a later-set earlier bound (policy cutoff): the persisted bound
//!   becomes `min(deadline, cutoff)` and the grant budget is cut by [`shorten`],
//!   which reduces the **existing** budget by the bound reduction (ADR-0006 §13.4
//!   N01), so a tolerance deduction made at re-anchoring is kept.
//!
//! The property test seeds a fixed RNG (override with `PROPTEST_RNG_SEED=<u64>`)
//! and persists failures next to this file under `proptest-regressions/`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::{
    DecisionId, EnvironmentId, GrantId, OperationId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{DeadlineIntent, RequiredCapabilities};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::idempotency::{
    HashInput, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, classify, compute_hash,
};
use heimdall_domain::lifecycle::{GrantEvent, grant_transition};
use heimdall_domain::operation::OperationKind;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::{
    Admission, AttendedTimeConfirmation, Clock, Deadline, GateInput, GrantAnchor, SyncStatus,
    TimeAnchor, TimePolicy, TimeStatus, TimeSync, TimeUncertainty, accepted_tolerance, admission,
    anchor_grant, anchor_grant_with_tolerance, gate, is_expired, next_high_water,
    next_runtime_anchor, resolve_deadline, shorten,
};
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

/// Minimal runtime model; see the module docs.
struct Model {
    clock: Arc<VirtualClock>,
    sync: Arc<ScriptedTimeSync>,
    policy: TimePolicy,
    grant: GrantId,
    // --- persisted rows ---
    deadline: Deadline,
    runtime_anchor: Option<TimeAnchor>,
    high_water: Option<Timestamp>,
    grant_anchor: GrantAnchor,
    confirmation: Option<AttendedTimeConfirmation>,
    /// Policy cutoff set after activation, if any (N01).
    cutoff: Option<Timestamp>,
    state: GrantState,
    // --- process memory (not persisted) ---
    /// The last observation the gate accepted in this process (R2 keeps the
    /// persisted runtime anchor older than this on unsynchronized time).
    last_accepted: Option<TimeAnchor>,
}

impl Model {
    /// First start at `t0` with synchronized time: resolve the deadline once,
    /// assess time (`Safe` on a first start needs synchronization, gate rule 3),
    /// activate, and anchor the grant at that observation.
    fn activate(intent: &str) -> Self {
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let policy = TimePolicy::default();
        let deadline = resolve_deadline(
            &DeadlineIntent::Duration(intent.to_owned()),
            clock.wall(),
            MAX_WINDOW,
        )
        .unwrap();
        let now = clock.observe();
        let status = gate(&GateInput {
            previous: None,
            high_water: None,
            now: &now,
            sync: SyncStatus::Synchronized,
            confirmation: None,
            policy: &policy,
        });
        assert_eq!(status, TimeStatus::Safe, "activation needs safe time");
        let mut state = GrantState::Requested;
        for e in [GrantEvent::Authorized, GrantEvent::Prepared] {
            state = grant_transition(state, e).unwrap();
        }
        let grant = GrantId::from_random_bytes([9; 16]);
        let grant_anchor = anchor_grant(grant.clone(), now.clone(), deadline.effective);
        Self {
            clock,
            sync,
            policy,
            grant,
            high_water: Some(next_high_water(None, now.wall)),
            last_accepted: Some(now.clone()),
            runtime_anchor: Some(now),
            deadline,
            grant_anchor,
            confirmation: None,
            cutoff: None,
            state,
        }
    }

    /// The current absolute bound: `min(deadline, cutoff)`.
    fn current_bound(&self) -> Timestamp {
        self.cutoff
            .map_or(self.deadline.effective, |c| c.min(self.deadline.effective))
    }

    /// The owner sets a cutoff at the absolute instant `at` (ADR-0005 §3.6 "an earlier
    /// cutoff set later shortens it; nothing lengthens it"). A later cutoff than the
    /// current bound changes nothing.
    fn cutoff(&mut self, at: Timestamp) {
        self.cutoff = Some(self.cutoff.map_or(at, |c| c.min(at)));
        self.grant_anchor = shorten(&self.grant_anchor, self.current_bound());
        assert_eq!(self.grant_anchor.bound, self.current_bound());
    }

    /// Time guard pass: the shared gate; on `Safe` persist the mark and the anchor
    /// chosen by `next_runtime_anchor` (design-fix second round R2: within a boot
    /// the anchor is re-based only on synchronized time, so drift against the last
    /// synchronized or confirmed anchor accumulates and is detected).
    fn guard(&mut self) -> TimeStatus {
        let (status, _) = self.guard_with_tolerance();
        status
    }

    /// `guard` plus the tolerance the gate used to accept the observation (R4).
    fn guard_with_tolerance(&mut self) -> (TimeStatus, Duration) {
        let now = self.clock.observe();
        let sync = self.sync.status();
        let input = GateInput {
            previous: self.runtime_anchor.as_ref(),
            high_water: self.high_water,
            now: &now,
            sync,
            confirmation: self.confirmation.as_ref(),
            policy: &self.policy,
        };
        let status = gate(&input);
        let tolerance = accepted_tolerance(&input);
        if status == TimeStatus::Safe {
            self.high_water = Some(next_high_water(self.high_water, now.wall));
            self.runtime_anchor = Some(next_runtime_anchor(
                self.runtime_anchor.as_ref(),
                &now,
                sync,
            ));
            self.last_accepted = Some(now);
        }
        (status, tolerance)
    }

    /// The admission-deadline check at the current observation.
    fn admission_now(&self) -> Admission {
        admission(&self.grant_anchor, &self.clock.observe())
    }

    /// Scheduler pass: emit `DeadlineReached` once the admission deadline passed.
    fn schedule(&mut self) {
        if self.admission_now() == Admission::Expired
            && let Ok(next) = grant_transition(self.state, GrantEvent::DeadlineReached)
        {
            self.state = next;
        }
    }

    /// Whether a signature/admission would be allowed now.
    fn admits(&mut self) -> bool {
        let status = self.guard();
        self.schedule();
        status == TimeStatus::Safe
            && self.state.permits_use()
            && self.admission_now() == Admission::Open
    }

    /// Same-boot process restart: the clock is untouched; every persisted row is
    /// written out and re-read as the store would.
    fn restart(&mut self) {
        let persisted = serde_json::json!({
            "deadline": self.deadline,
            "runtime_anchor": self.runtime_anchor,
            "high_water": self.high_water,
            "grant_anchor": self.grant_anchor,
            "confirmation": self.confirmation,
            "cutoff": self.cutoff,
            "state": self.state,
        })
        .to_string();
        assert_no_canary(&persisted);
        let v: serde_json::Value = serde_json::from_str(&persisted).unwrap();
        let row = |k: &str| v[k].clone();
        self.deadline = serde_json::from_value(row("deadline")).unwrap();
        self.runtime_anchor = serde_json::from_value(row("runtime_anchor")).unwrap();
        self.high_water = serde_json::from_value(row("high_water")).unwrap();
        self.grant_anchor = serde_json::from_value(row("grant_anchor")).unwrap();
        self.confirmation = serde_json::from_value(row("confirmation")).unwrap();
        self.cutoff = serde_json::from_value(row("cutoff")).unwrap();
        self.state = serde_json::from_value(row("state")).unwrap();
        // Process memory does not survive: the new process must pass the gate
        // before it may re-anchor anything.
        self.last_accepted = None;
    }

    /// Machine reboot: new boot ID, continuous time from zero, wall clock at `wall`.
    fn reboot(&mut self, wall: Timestamp) {
        self.clock.reboot(wall);
    }

    /// "First validated in the current boot" (ADR-0005 §3.6): only from a `Safe`
    /// observation, and only when the persisted grant anchor belongs to another
    /// boot, re-create it from that observation with the same persisted bound. In
    /// the anchor's own boot nothing is rebuilt. Returns whether the grant has a
    /// current-boot anchor and time is safe.
    fn reanchor(&mut self) -> bool {
        let (status, tolerance) = self.guard_with_tolerance();
        if status != TimeStatus::Safe {
            return false;
        }
        let now = self
            .last_accepted
            .clone()
            .expect("Safe records the accepted observation");
        if self.grant_anchor.anchor.boot_id != now.boot_id {
            // R4: an observation accepted within a tolerance may lag the truth by
            // that much; cut the budget as if it were that much later (early, never
            // late). A same-boot budget would be min()'d by the store.
            self.grant_anchor = anchor_grant_with_tolerance(
                self.grant.clone(),
                now,
                self.grant_anchor.bound,
                tolerance,
            );
        }
        assert_eq!(
            self.grant_anchor.bound,
            self.current_bound(),
            "the bound never moves except by a cutoff"
        );
        true
    }

    /// Attended owner confirmation of the current time for this boot.
    fn confirm_time(&mut self) {
        let now = self.clock.observe();
        let confirmation = AttendedTimeConfirmation {
            boot_id: now.boot_id.clone(),
            continuous: now.continuous,
            wall: now.wall,
            decision: DecisionId::from_random_bytes([5; 16]),
        };
        // R3: an accepted confirmation installs a new runtime anchor for this boot,
        // so the gate predicts from it and a same-boot skew is cleared. It never
        // touches the deadline or the grant budget.
        self.runtime_anchor = Some(confirmation.as_anchor());
        self.high_water = Some(next_high_water(self.high_water, now.wall));
        self.last_accepted = Some(now);
        self.confirmation = Some(confirmation);
    }

    /// Continuous time left in the grant's budget (zero when spent or void).
    fn budget_left(&self) -> Duration {
        self.grant_anchor
            .budget_end
            .saturating_sub(self.clock.continuous())
    }
}

fn assert_expired_for_good(m: &Model) {
    assert_eq!(m.state, GrantState::Expired);
    assert!(m.state.is_terminal());
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

// --- (a) sleep across expiry ---------------------------------------------------------

#[test]
fn sleep_across_expiry_expires_and_is_never_extended() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    let anchor = m.grant_anchor.clone();
    assert!(m.admits());

    // Two hours of sleep: the continuous clock counts it, the wall clock is frozen
    // until wake.
    m.clock.advance_continuous_only(2 * HOUR);
    assert!(
        !is_expired(m.clock.wall(), m.deadline.effective),
        "the wall branch alone would still admit"
    );
    // The frozen wall disagrees with the continuous prediction.
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert_eq!(
        m.admission_now(),
        Admission::Expired,
        "budget spent in sleep"
    );
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
    assert!(!m.admits());

    // Wake: the wall clock catches up; time is consistent again; still expired.
    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(!m.admits());
    assert_eq!(m.deadline, original, "persisted deadline unchanged");
    assert_eq!(m.grant_anchor, anchor, "budget never rebuilt");
    assert_expired_for_good(&m);
}

// --- (b) wall running -----------------------------------------------------------------

#[test]
fn sleep_with_wall_running_expires_at_the_persisted_instant() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(HOUR - SECOND);
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits());
    assert_eq!(m.state, GrantState::Expired);
    assert_eq!(m.clock.wall(), m.deadline.effective);
    assert_eq!(m.clock.continuous(), m.grant_anchor.budget_end);
}

// --- (c) backward jump ----------------------------------------------------------------

#[test]
fn backward_jump_is_time_uncertain_and_budget_still_runs_out() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(10 * MINUTE);
    assert!(m.admits());
    let mark = m.high_water.unwrap();
    assert_eq!(mark, shift(t0(), 600));

    // Wall clock stepped back one hour.
    m.clock.set_wall(shift(t0(), 600 - 3600));
    let status = m.guard();
    assert_eq!(
        status,
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(t0(), 600 - 3600),
        })
    );
    assert!(!m.admits(), "no admission while time is uncertain");
    assert_eq!(m.high_water, Some(mark), "the mark never decreases");

    // Even if the wall stays an hour behind, the continuous budget ends on time.
    m.clock.advance(50 * MINUTE);
    assert!(!m.admits());
    assert_eq!(m.state, GrantState::Expired);
    assert!(!is_expired(m.clock.wall(), m.deadline.effective));
}

// --- (d) forward jump -----------------------------------------------------------------

#[test]
fn forward_jump_without_continuous_progress_is_uncertain_and_wall_branch_expires() {
    let mut m = Model::activate("PT1H");
    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    // The wall branch expires the grant anyway: forward jumps only end access sooner.
    assert_eq!(m.admission_now(), Admission::Expired);
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
    assert!(!m.admits());
}

#[test]
fn forward_jump_within_tolerance_only_ends_access_sooner() {
    let mut m = Model::activate("PT1H");
    // Exactly the skew tolerance: accepted (inclusive boundary).
    m.clock
        .set_wall(shift(t0(), secs(TimePolicy::default().max_tolerated_skew)));
    assert!(m.admits());
    // The wall branch now ends access one tolerance earlier in real time.
    m.clock.advance(HOUR - MINUTE - SECOND);
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits());
    assert_eq!(m.state, GrantState::Expired);
    assert!(m.budget_left() > Duration::ZERO, "wall branch, not budget");
}

// --- (e) same-boot restart with a stuck wall -----------------------------------------

/// Formerly `#[ignore]`d (blocked on the per-process monotonic clock); ADR-0005
/// §3.6 revision 3 closes it with the boot-scoped continuous clock and boot ID.
#[test]
fn restart_with_stuck_wall_must_not_extend_the_budget() {
    let mut m = Model::activate("PT1H");
    let anchor = m.grant_anchor.clone();
    // Wall clock stuck for 50 minutes of real time; restart before the guard runs.
    m.clock.advance_continuous_only(50 * MINUTE);
    m.restart();
    assert_eq!(
        m.grant_anchor, anchor,
        "same boot: the persisted anchor is resumed"
    );
    // The stuck wall disagrees with the anchor's prediction: no re-anchor.
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.reanchor());
    assert_eq!(m.grant_anchor, anchor, "never rebuilt from the stuck wall");
    // 50 more real minutes: 100 real minutes after a one-hour grant.
    m.clock.advance(50 * MINUTE);
    assert!(!m.admits(), "admitted 100 real minutes into a 1 h grant");
    assert_eq!(m.state, GrantState::Expired);
    // Correcting the wall makes time safe again; the grant stays expired.
    m.clock.set_wall(shift(t0(), 100 * 60));
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(!m.admits());
    assert_expired_for_good(&m);
}

#[test]
fn stuck_wall_checked_often_and_restarted_still_expires_on_real_time() {
    // Observed every tolerance interval, a stuck wall passes the gate each time
    // (the disagreement equals the tolerance); the budget still ends after exactly
    // one real hour, across a restart in the middle.
    let mut m = Model::activate("PT1H");
    let step = TimePolicy::default().max_tolerated_skew;
    let mut real = Duration::ZERO;
    while real < 30 * MINUTE {
        m.clock.advance_continuous_only(step);
        real += step;
        assert!(m.admits(), "admits at {real:?}");
    }
    m.restart();
    loop {
        m.clock.advance_continuous_only(step);
        real += step;
        let admitted = m.admits();
        assert_eq!(admitted, real < HOUR, "at {real:?}");
        if !admitted {
            break;
        }
    }
    assert_eq!(real, HOUR);
    assert_eq!(m.state, GrantState::Expired);
    assert_eq!(m.clock.wall(), t0(), "the wall never moved");
}

// --- (f) same-boot restart keeps the remaining budget ---------------------------------

#[test]
fn same_boot_restart_keeps_the_deadline_and_the_remaining_budget() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    let anchor = m.grant_anchor.clone();
    m.clock.advance(30 * MINUTE);
    assert!(m.admits());
    let (boot, continuous) = (m.clock.boot_id(), m.clock.continuous());

    m.restart();
    assert_eq!(m.clock.boot_id(), boot, "a process restart is not a reboot");
    assert_eq!(m.clock.continuous(), continuous);
    assert_eq!(m.deadline, original, "deadline unchanged across restart");
    assert_eq!(m.grant_anchor, anchor);
    assert!(m.reanchor());
    assert_eq!(m.grant_anchor, anchor, "never rebuilt in its own boot");
    // 30 minutes remain, not a fresh hour.
    assert_eq!(m.budget_left(), 30 * MINUTE);
    assert!(m.admits());
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits());
    assert_eq!(m.clock.wall(), original.effective);
    assert_eq!(m.state, GrantState::Expired);
}

// --- (g) reboot below the mark ----------------------------------------------------------

#[test]
fn reboot_with_wall_below_the_mark_is_refused_even_when_synchronized() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(30 * MINUTE);
    assert!(m.admits());
    let mark = m.high_water.unwrap();

    m.reboot(shift(t0(), 10 * 60));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(t0(), 10 * 60),
        })
    );
    assert!(!m.reanchor());
    assert!(!m.admits());
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
    assert_eq!(
        m.state,
        GrantState::Active,
        "a void anchor is not an expiry"
    );
    // An attended confirmation cannot accept a wall below the mark either.
    m.confirm_time();
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
    ));
    assert!(!m.reanchor());
    assert_eq!(m.high_water, Some(mark));
}

// --- (h) reboot above the mark: synchronization required -----------------------------

#[test]
fn reboot_above_the_mark_needs_synchronized_time_and_keeps_the_bound() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    m.clock.advance(20 * MINUTE);
    assert!(m.admits());

    // Ten minutes of downtime; the wall clock is right but not reported synchronized.
    m.reboot(shift(t0(), 30 * 60));
    for sync in [SyncStatus::Unknown, SyncStatus::NotSynchronized] {
        m.sync.set(sync);
        assert_eq!(
            m.guard(),
            TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { sync })
        );
        assert!(!m.reanchor(), "{sync:?}");
        assert!(!m.admits(), "{sync:?}");
        assert_eq!(m.admission_now(), Admission::NeedsAnchor);
        assert_eq!(m.state, GrantState::Active);
    }

    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(m.reanchor());
    assert_eq!(m.grant_anchor.anchor.boot_id, m.clock.boot_id());
    assert_eq!(
        m.grant_anchor.bound, original.effective,
        "same persisted bound"
    );
    assert_eq!(m.budget_left(), 30 * MINUTE, "no fresh budget");
    assert!(m.admits());
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits());
    assert_eq!(m.clock.wall(), original.effective);
    assert_eq!(m.deadline, original);
    assert_expired_for_good(&m);
}

// --- (i) reboot + attended confirmation ---------------------------------------------------

#[test]
fn reboot_with_attended_confirmation_resolves_without_moving_the_deadline() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    m.clock.advance(20 * MINUTE);
    assert!(m.admits());

    m.reboot(shift(t0(), 30 * 60));
    m.sync.set(SyncStatus::Unknown);
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
    ));
    assert!(!m.admits());

    m.confirm_time();
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(m.reanchor());
    assert_eq!(m.deadline, original, "confirmation never moves a deadline");
    assert_eq!(m.grant_anchor.bound, original.effective);
    // R4: the observation was accepted through the confirmation's prediction
    // (skew tolerance 60 s), so the rebuilt-in-this-boot budget is cut by that
    // tolerance: 30 min − 60 s remain, never a fresh hour, never more than the
    // persisted bound allows.
    assert_eq!(
        m.budget_left(),
        30 * MINUTE - m.policy.max_tolerated_skew,
        "nor rebuilds a budget; ends early by at most the tolerance"
    );
    assert!(m.admits());
    m.clock.advance(15 * MINUTE);
    assert!(m.admits());

    // A confirmation covers only its own boot.
    let left = m.budget_left();
    m.restart();
    assert!(m.admits(), "same boot after restart");
    assert_eq!(m.budget_left(), left);
    m.reboot(shift(t0(), 50 * 60));
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
    ));
    assert!(!m.reanchor());
    assert!(!m.admits());
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
}

// --- (j) stopped at 10:00, real 12:00, clock reset to 10:01 ----------------------------

#[test]
fn rolled_back_clock_above_the_mark_after_downtime_is_refused_unsynchronized() {
    // Grant until 12:00; runtime last accepted 10:00; machine off until real 12:00;
    // the real-time clock comes back at 10:01.
    let mut m = Model::activate("PT3H");
    assert_eq!(m.deadline.effective, shift(t0(), 3 * 3600));
    m.clock.advance(HOUR);
    assert!(m.admits());
    let mark = m.high_water.unwrap();
    assert_eq!(mark, shift(t0(), 3600), "mark at 10:00");

    let ten_oh_one = shift(t0(), 3600 + 60);
    m.reboot(ten_oh_one);
    m.sync.set(SyncStatus::NotSynchronized);
    assert!(m.clock.wall() > mark, "above the mark");
    assert_eq!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
            sync: SyncStatus::NotSynchronized
        })
    );
    assert!(!m.reanchor());
    assert!(!m.admits());
    // What accepting 10:01 would have meant: a budget of 1 h 59 min starting at
    // real 12:00, i.e. authority until real 13:59.
    let would_be = anchor_grant(m.grant.clone(), m.clock.observe(), m.deadline.effective);
    assert_eq!(would_be.budget_end, 119 * MINUTE);

    // Time sync comes back with the real time: the wall branch has passed.
    m.clock.set_wall(shift(t0(), 3 * 3600 + 5));
    m.sync.set(SyncStatus::Synchronized);
    assert!(m.reanchor());
    assert_eq!(m.admission_now(), Admission::Expired);
    assert!(!m.admits());
    assert_expired_for_good(&m);
}

// --- (l) idempotent retry across restart ---------------------------------------------------

fn hash_input_hash(intent: &DeadlineIntent) -> heimdall_contract::canonical::RequestHash {
    let env = EnvironmentId::from_random_bytes([7; 16]);
    let profile = ProfileId::parse("work").unwrap();
    let work = WorkId::parse("task-1").unwrap();
    let scope = BTreeSet::new();
    let caps = RequiredCapabilities::default();
    compute_hash(
        OperationKind::Ensure,
        &HashInput {
            environment: &env,
            profile: Some(&profile),
            profile_revision: None,
            scope: &scope,
            deadline_intent: Some(intent),
            work_id: Some(&work),
            required_capabilities: &caps,
            parent_binding: None,
            extra: serde_json::Value::Null,
        },
    )
    .unwrap()
}

#[test]
fn duration_retry_after_restart_hashes_equal_and_keeps_original_instant() {
    let mut m = Model::activate("PT2H");
    let intent = DeadlineIntent::Duration("PT2H".to_owned());
    let first_hash = hash_input_hash(&intent);
    let op = OperationId::from_random_bytes([3; 16]);
    let record = IdempotencyRecord {
        key: IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 1000 },
                role: ClientRole::Owner,
            },
            kind: OperationKind::Ensure,
            request_id: RequestId::parse("req-7").unwrap(),
        },
        request_hash: first_hash,
        operation_id: op.clone(),
        created_at: m.clock.wall(),
        expires_at: Some(shift(m.clock.wall(), 7 * 86_400)),
    };
    let persisted = m.deadline.clone();

    m.clock.advance(45 * MINUTE);
    m.restart();

    let retry_hash = hash_input_hash(&intent);
    assert_eq!(retry_hash, first_hash, "intent hashes, not the instant");
    assert_eq!(
        classify(Some(&record), None, retry_hash, m.clock.wall()),
        IdempotencyOutcome::Replay(op)
    );
    // The replay returns the persisted deadline. Resolving again would move the
    // instant later, which is exactly what must never happen.
    let would_be = resolve_deadline(&intent, m.clock.wall(), MAX_WINDOW).unwrap();
    assert!(would_be.effective > persisted.effective);
    assert_eq!(m.deadline, persisted);
    assert_eq!(m.deadline.effective, shift(t0(), 2 * 3600));
}

// --- (m) errors never echo input -------------------------------------------------------------

#[test]
fn deadline_errors_never_echo_input() {
    // Synthetic canary defined by this fixture; it must not reach any message.
    let canary = format!("HEIMDALL_CANARY_{:016x}", 0x5eed_u64 ^ 0xa5a5_a5a5);
    let now = t0();
    for intent in [
        DeadlineIntent::Absolute(canary.clone()),
        DeadlineIntent::Duration(canary.clone()),
        DeadlineIntent::Absolute(format!("2026-10-02T10:00:00[{canary}]")),
        DeadlineIntent::Duration(format!("1h {canary}")),
    ] {
        let err = resolve_deadline(&intent, now, MAX_WINDOW).unwrap_err();
        assert_no_canary(&err.to_string());
        assert_no_canary(&format!("{err:?}"));
    }
}

// --- (k) property ------------------------------------------------------------------------------

/// Plan §6.3 #5 over the virtual clock: whatever sequence of normal passage,
/// frozen wall, wall jumps, same-boot process restarts, reboots (with right or
/// wrong wall clocks), wall corrections and attended confirmations occurs,
/// admission is never allowed once the real elapsed time since activation reaches
/// the granted duration, the persisted deadline and bound never move, and the
/// grant never leaves a terminal state.
///
/// Environment assumptions (ADR-0005 §3.6 threat model: accidental faults, not a
/// lying time service or a mistaken owner): the platform reports `Synchronized`
/// only while the wall clock shows real time, and the owner confirms only a wall
/// clock that shows real time.
mod props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    #[derive(Debug, Clone)]
    enum Step {
        /// Awake: both clocks advance.
        Pass(u64),
        /// Sleep or a stuck wall: only the continuous clock advances.
        FrozenWall(u64),
        /// Wall clock stepped by this many seconds.
        WallJump(i64),
        /// Same-boot process restart.
        Restart,
        /// Machine off for `downtime` seconds, then booted with the sync report
        /// `sync`; an unsynchronized wall clock is off real time by `wall_error`.
        Reboot {
            downtime: u64,
            wall_error: i64,
            sync: SyncStatus,
        },
        /// The wall clock is set to real time (time service or owner), optionally
        /// reported synchronized; the runtime then tries to re-anchor.
        CorrectWall { synchronized: bool },
        /// Attended owner confirmation (only of a wall clock showing real time);
        /// the runtime then tries to re-anchor.
        Confirm,
    }

    fn sync_status() -> impl Strategy<Value = SyncStatus> {
        prop_oneof![
            Just(SyncStatus::Synchronized),
            Just(SyncStatus::NotSynchronized),
            Just(SyncStatus::Unknown),
        ]
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            4 => (1u64..1200).prop_map(Step::Pass),
            3 => (1u64..1200).prop_map(Step::FrozenWall),
            3 => (-7200i64..7200).prop_map(Step::WallJump),
            1 => Just(Step::Restart),
            1 => (0u64..7200, -7200i64..7200, sync_status()).prop_map(
                |(downtime, wall_error, sync)| Step::Reboot { downtime, wall_error, sync }
            ),
            1 => any::<bool>().prop_map(|synchronized| Step::CorrectWall { synchronized }),
            1 => Just(Step::Confirm),
        ]
    }

    fn config() -> ProptestConfig {
        let mut config = ProptestConfig {
            cases: 512,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        // `ProptestConfig::default()` honours PROPTEST_RNG_SEED; otherwise pin a
        // seed so runs are reproducible.
        if matches!(config.rng_seed, RngSeed::Random) {
            config.rng_seed = RngSeed::Fixed(0x4130_385f_5449_4d45);
        }
        config
    }

    /// What a trace exercised (non-vacuity counters).
    #[derive(Debug, Default)]
    struct Coverage {
        /// Admitted at least once after a same-boot restart.
        admitted_after_restart: u32,
        /// A reboot left the grant without a current-boot anchor (refused).
        void_after_reboot: u32,
        /// Re-anchored in a later boot and admitted there.
        admitted_after_reanchor: u32,
        /// Re-anchored through an attended confirmation.
        reanchored_by_confirmation: u32,
        /// Expired by the continuous budget while the wall branch was still open.
        budget_expiry_wall_open: u32,
        /// Ran into the granted duration while not yet expired by the scheduler.
        reached_granted: u32,
    }

    /// Apply `steps` to a fresh grant of `minutes`, checking the invariants after
    /// every step.
    fn run(minutes: u64, steps: &[Step], cov: &mut Coverage) -> Result<(), TestCaseError> {
        let mut m = Model::activate(&format!("{minutes}m"));
        let original = m.deadline.clone();
        let granted = Duration::from_secs(minutes * 60);
        let mut real = Duration::ZERO;
        let real_wall = |real: Duration| shift(t0(), secs(real));
        let (mut restarted, mut rebooted) = (false, false);
        let (
            mut seen_restart,
            mut seen_void,
            mut seen_reanchor,
            mut seen_conf,
            mut seen_budget,
            mut seen_granted,
        ) = (false, false, false, false, false, false);
        for s in steps {
            match *s {
                Step::Pass(d) => {
                    m.clock.advance(Duration::from_secs(d));
                    real += Duration::from_secs(d);
                }
                Step::FrozenWall(d) => {
                    m.clock.advance_continuous_only(Duration::from_secs(d));
                    real += Duration::from_secs(d);
                }
                Step::WallJump(d) => m.clock.set_wall(shift(m.clock.wall(), d)),
                Step::Restart => {
                    m.restart();
                    restarted = true;
                }
                Step::Reboot {
                    downtime,
                    wall_error,
                    sync,
                } => {
                    real += Duration::from_secs(downtime);
                    let wall = if sync == SyncStatus::Synchronized {
                        real_wall(real)
                    } else {
                        shift(real_wall(real), wall_error)
                    };
                    m.reboot(wall);
                    m.sync.set(sync);
                    m.reanchor();
                    rebooted = true;
                }
                Step::CorrectWall { synchronized } => {
                    m.clock.set_wall(real_wall(real));
                    if synchronized {
                        m.sync.set(SyncStatus::Synchronized);
                    }
                    m.reanchor();
                }
                Step::Confirm => {
                    if m.clock.wall() == real_wall(real) {
                        m.confirm_time();
                        let was_void = m.grant_anchor.anchor.boot_id != m.clock.boot_id();
                        if m.reanchor() && was_void {
                            seen_conf = true;
                        }
                    }
                }
            }
            // A truthful platform stops reporting synchronized time once the wall
            // clock no longer shows real time.
            if m.clock.wall() != real_wall(real) && m.sync.status() == SyncStatus::Synchronized {
                m.sync.set(SyncStatus::NotSynchronized);
            }
            let was_active = m.state.permits_use();
            let admitted = m.admits();
            prop_assert!(
                !(admitted && real >= granted),
                "admitted after {:?} of {:?}",
                real,
                granted
            );
            // Absorbing: once out of use, never back in use.
            if !m.state.permits_use() {
                prop_assert!(m.state.is_terminal(), "{:?}", m.state);
            }
            prop_assert_eq!(&m.deadline, &original);
            prop_assert_eq!(m.grant_anchor.bound, original.effective);

            seen_restart |= admitted && restarted;
            seen_void |= rebooted && m.admission_now() == Admission::NeedsAnchor && was_active;
            // After a reboot, admission needs a current-boot anchor: re-anchored.
            seen_reanchor |= admitted && rebooted;
            seen_budget |= was_active
                && m.state == GrantState::Expired
                && !is_expired(m.clock.wall(), m.deadline.effective);
            seen_granted |= was_active && real >= granted;
        }
        cov.admitted_after_restart += u32::from(seen_restart);
        cov.void_after_reboot += u32::from(seen_void);
        cov.admitted_after_reanchor += u32::from(seen_reanchor);
        cov.reanchored_by_confirmation += u32::from(seen_conf);
        cov.budget_expiry_wall_open += u32::from(seen_budget);
        cov.reached_granted += u32::from(seen_granted);
        Ok(())
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn no_admission_past_real_duration(
            minutes in 1u64..=720,
            steps in prop::collection::vec(step(), 1..60),
        ) {
            run(minutes, &steps, &mut Coverage::default())?;
        }
    }

    /// Non-vacuity (review F09): with a fixed seed the generator reaches every path
    /// the property is meant to cover, so passing it says something.
    #[test]
    fn generator_reaches_restart_reboot_reanchor_and_budget_expiry() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};

        let mut runner = TestRunner::new_with_rng(
            ProptestConfig::default(),
            TestRng::from_seed(RngAlgorithm::ChaCha, &[0x08; 32]),
        );
        let strategy = (1u64..=720, prop::collection::vec(step(), 1..60));
        let mut cov = Coverage::default();
        for _ in 0..2_000 {
            let (minutes, steps) = strategy.new_tree(&mut runner).unwrap().current();
            run(minutes, &steps, &mut cov).unwrap();
        }
        for (name, n) in [
            ("admitted_after_restart", cov.admitted_after_restart),
            ("void_after_reboot", cov.void_after_reboot),
            ("admitted_after_reanchor", cov.admitted_after_reanchor),
            ("reanchored_by_confirmation", cov.reanchored_by_confirmation),
            ("budget_expiry_wall_open", cov.budget_expiry_wall_open),
            ("reached_granted", cov.reached_granted),
        ] {
            assert!(n >= 20, "{name} under-generated: {cov:?}");
        }
    }
}

// ---------------------------------------------------------------------------------
// Design-fix second round (ADR-0006 §13.1 rulings R2–R4).
// ---------------------------------------------------------------------------------

/// R2: within a boot the runtime anchor is re-based only on synchronized time. A
/// frozen wall clock checked every 30 s therefore accumulates skew against the last
/// synchronized anchor and becomes `Uncertain` once it exceeds the 60 s tolerance,
/// instead of being re-accepted on every pass.
#[test]
fn frozen_wall_checked_every_thirty_seconds_becomes_uncertain() {
    let mut m = Model::activate("PT2H");
    m.sync.set(SyncStatus::Unknown);
    let anchor_before = m.runtime_anchor.clone();
    // 30 s and 60 s of cumulative skew are within tolerance (inclusive).
    for _ in 0..2 {
        m.clock.advance_continuous_only(30 * SECOND);
        assert_eq!(m.guard(), TimeStatus::Safe);
    }
    assert_eq!(
        m.runtime_anchor, anchor_before,
        "unsynchronized passes must not re-base the anchor"
    );
    m.clock.advance_continuous_only(30 * SECOND);
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.admits());
    // Synchronized time re-bases the anchor when the wall agrees again.
    m.clock.set_wall(shift(t0(), 90));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert_ne!(m.runtime_anchor, anchor_before);
}

/// R3: an accepted attended confirmation installs a new runtime anchor for this
/// boot, so a same-boot skew is cleared by it; the deadline and the grant budget are
/// untouched.
#[test]
fn same_boot_skew_is_cleared_by_attended_confirmation_without_moving_anything() {
    let mut m = Model::activate("PT1H");
    m.sync.set(SyncStatus::Unknown);
    m.clock.advance(10 * MINUTE);
    assert!(m.admits());
    let deadline = m.deadline.clone();
    let budget = m.grant_anchor.clone();
    // Wall jumps forward 20 minutes with no continuous progress: skew.
    m.clock.set_wall(shift(t0(), 30 * 60));
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    assert!(!m.admits());
    m.confirm_time();
    assert_eq!(
        m.guard(),
        TimeStatus::Safe,
        "confirmation is the new reference"
    );
    assert!(m.admits());
    assert_eq!(m.deadline, deadline, "confirmation never moves a deadline");
    assert_eq!(
        m.grant_anchor, budget,
        "confirmation never rebuilds a budget"
    );
    // The continuous budget still has 50 real minutes, but the wall clock now runs
    // 20 minutes ahead, so the wall branch reaches the bound after 30 more minutes:
    // a forward jump only ends access sooner, never later.
    m.clock.advance(30 * MINUTE - SECOND);
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits());
    assert_eq!(m.clock.wall(), m.deadline.effective);
}

/// R4: an observation accepted within a tolerance may lag the truth by that much;
/// a re-anchor from it ends up to the tolerance early, never late.
#[test]
fn reanchor_accepted_within_tolerance_ends_early_never_late() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(30 * MINUTE);
    assert!(m.admits());
    // Reboot after some downtime; the clock comes back 4 s below the mark and the
    // platform reports synchronized time. N05: after a reboot nothing below the mark
    // is accepted, so the owner confirms; within the confirmed boot the 5 s rollback
    // tolerance applies and is deducted from the budget (R4).
    m.reboot(shift(shift(t0(), 30 * 60), -4));
    m.sync.set(SyncStatus::Synchronized);
    assert!(!m.reanchor());
    m.confirm_time();
    assert!(m.reanchor());
    // Budget: bound − (wall + 5 s tolerance) = 30 min − 1 s on the continuous clock.
    assert_eq!(m.grant_anchor.budget_end, Duration::from_secs(30 * 60 - 1));
    m.clock.advance(Duration::from_secs(30 * 60 - 2));
    assert!(m.admits());
    m.clock.advance(SECOND);
    assert!(!m.admits(), "ends at most the tolerance early, never late");
}

/// N05 (ADR-0006 §13.4): after a reboot the rollback tolerance does not apply. A
/// synchronized wall 4 s below the high-water mark is `Uncertain` (it was accepted
/// before round 2); an attended confirmation for this boot resolves it without
/// moving the deadline or the bound.
#[test]
fn reboot_synchronized_slightly_below_mark_is_uncertain_until_confirmed() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(30 * MINUTE);
    assert!(m.admits());
    let mark = m.high_water.unwrap();
    let deadline = m.deadline.clone();
    m.reboot(shift(mark, -4));
    m.sync.set(SyncStatus::Synchronized);
    assert_eq!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
            mark,
            observed: shift(mark, -4),
        })
    );
    assert!(!m.reanchor());
    assert!(!m.admits());
    assert_eq!(m.admission_now(), Admission::NeedsAnchor);
    m.confirm_time();
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(m.reanchor());
    assert!(m.admits());
    assert_eq!(m.deadline, deadline);
    assert_eq!(m.grant_anchor.bound, deadline.effective);
    assert_eq!(m.high_water, Some(mark), "the mark never lowers");
}

/// N01 (ADR-0006 §13.4), the reviewer's counterexample: anchor at continuous 0 with
/// a 60 s tolerance and bound 3600 s; the bound is cut to 3570 s; the wall clock
/// lags the truth by 60 s throughout. Admission must close by continuous 3510 (the
/// true new bound), not 3540.
#[test]
fn shorten_preserves_tolerance_margin_reviewer_counterexample() {
    let clock = VirtualClock::at(t0());
    let anchor = clock.observe();
    let g = GrantId::from_random_bytes([7; 16]);
    let tolerant =
        anchor_grant_with_tolerance(g, anchor, shift(t0(), 3600), Duration::from_secs(60));
    assert_eq!(tolerant.budget_end, Duration::from_secs(3540));
    let narrowed = shorten(&tolerant, shift(t0(), 3570));
    assert_eq!(narrowed.bound, shift(t0(), 3570));
    assert_eq!(narrowed.budget_end, Duration::from_secs(3510));
    // Truth = wall + 60 s. One second before the true new bound: open.
    clock.advance(Duration::from_secs(3509));
    assert_eq!(admission(&narrowed, &clock.observe()), Admission::Open);
    // At the true new bound (wall still 60 s behind, so the wall branch is open):
    // the continuous budget closes admission.
    clock.advance(SECOND);
    assert!(
        clock.wall() < narrowed.bound,
        "the wall branch alone would admit"
    );
    assert_eq!(admission(&narrowed, &clock.observe()), Admission::Expired);
    // The pre-fix value would have admitted for 30 more seconds.
    let pre_fix = anchor_grant(
        narrowed.grant.clone(),
        narrowed.anchor.clone(),
        narrowed.bound,
    )
    .budget_end
    .min(tolerant.budget_end);
    assert_eq!(pre_fix, Duration::from_secs(3540));
    assert!(narrowed.budget_end < pre_fix);
}

/// N01 through the runtime model: tolerance-aware re-anchoring after a confirmed
/// reboot, then a cutoff, with the wall lagging the truth: admission stops by the
/// true cutoff.
#[test]
fn cutoff_after_tolerant_reanchor_stops_admission_by_the_true_cutoff() {
    let mut m = Model::activate("PT2H");
    m.sync.set(SyncStatus::Unknown);
    m.clock.advance(10 * MINUTE);
    assert!(m.admits());
    // Reboot; the wall comes back right; unsynchronized, so the owner confirms. The
    // re-anchor deducts the skew tolerance (60 s).
    let truth = shift(t0(), 15 * 60);
    m.reboot(truth);
    m.confirm_time();
    assert!(m.reanchor());
    // The wall freezes for 50 s, so it lags the truth by 50 s (within the skew
    // tolerance, still at the mark).
    m.clock.advance_continuous_only(50 * SECOND);
    let mut real = 50 * SECOND;
    assert_eq!(m.guard(), TimeStatus::Safe);
    // Cutoff at the true instant truth + 30 min.
    let cut = shift(truth, 30 * 60);
    m.cutoff(cut);
    // Advance until the truth passes the cutoff; never admitted at or after it.
    let mut last_admitted = None;
    while real < 31 * MINUTE {
        if m.admits() {
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

mod props_rev2 {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::FileFailurePersistence;

    /// Steps the owner, the machine and the clock may take. Truth = t0 + real.
    #[derive(Debug, Clone)]
    enum Step {
        Pass(u64),
        FrozenWall(u64),
        WallJump(i64),
        Restart,
        /// Downtime in seconds, wall drift from the truth after the reboot, and
        /// whether the platform reports synchronized time afterwards.
        Reboot {
            down: u64,
            drift: i64,
            sync: bool,
        },
        /// The owner confirms the time; modelled as refusing a clock more than the
        /// skew tolerance away from the truth (the owner looks at a watch).
        Confirm,
        Reanchor,
        /// The owner sets a cutoff this many seconds after the runtime's current
        /// wall clock (an absolute instant; may lie in the past). N01.
        Cutoff(i64),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (1u64..1200).prop_map(Step::Pass),
            (1u64..1200).prop_map(Step::FrozenWall),
            (-7200i64..7200).prop_map(Step::WallJump),
            Just(Step::Restart),
            (0u64..7200, -120i64..3600, any::<bool>())
                .prop_map(|(down, drift, sync)| Step::Reboot { down, drift, sync }),
            Just(Step::Confirm),
            Just(Step::Reanchor),
            (-600i64..7200).prop_map(Step::Cutoff),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 384,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
            ..ProptestConfig::default()
        })]

        /// No admission after the true (current) bound `min(deadline, cutoff)`,
        /// across sleep, jumps, restarts, reboots (synchronized or not), attended
        /// confirmations, tolerance-aware re-anchors and cutoffs (N01).
        #[test]
        fn no_admission_after_true_bound_with_reboot_and_confirmation(
            minutes in 1u64..=720,
            steps in prop::collection::vec(step(), 1..60),
        ) {
            let mut m = Model::activate(&format!("{minutes}m"));
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
                        m.reboot(shift(truth(real), drift));
                        m.sync.set(if sync { SyncStatus::Synchronized } else { SyncStatus::Unknown });
                        m.restart();
                    }
                    Step::Confirm => {
                        let off = m.clock.wall().duration_since(truth(real)).unsigned_abs();
                        if off <= m.policy.max_tolerated_skew {
                            m.confirm_time();
                        }
                    }
                    Step::Reanchor => {
                        let _ = m.reanchor();
                    }
                    Step::Cutoff(after) => {
                        m.cutoff(shift(m.clock.wall(), after));
                    }
                }
                let admitted = m.admits();
                prop_assert!(
                    !(admitted && real >= granted),
                    "admitted after {real:?} of {granted:?}"
                );
                prop_assert!(
                    !(admitted && truth(real) >= m.current_bound()),
                    "admitted at {:?} at/after the current bound {:?}",
                    truth(real),
                    m.current_bound()
                );
                if !m.state.permits_use() {
                    prop_assert!(m.state.is_terminal());
                }
            }
        }
    }
}
