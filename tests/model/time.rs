//! A08 model variant (spec §17 A08, §6.2, §6.4; ADR-0005 §3.6; plan §5 M01-T02):
//! sleep, clock jumps and restart never add authority. Driven by
//! `heimdall_testkit::VirtualClock` against the production `heimdall_domain::time`
//! functions.
//!
//! Model of the runtime used here (the real wiring is U5/U8): a grant's deadline is
//! resolved once and persisted; the time guard persists a high-water anchor with
//! `next_anchor` after every `Safe` assessment; admission needs a `Safe` time
//! status and an open admission deadline (`admission`, wall bound and monotonic
//! budget); the scheduler expires the grant only on `Admission::Expired`.
//! `process_generation` counts process starts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::{EnvironmentId, OperationId, ProfileId, RequestId, WorkId};
use heimdall_contract::request::{DeadlineIntent, RequiredCapabilities};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::idempotency::{
    HashInput, IdempotencyKey, IdempotencyOutcome, IdempotencyRecord, classify, compute_hash,
};
use heimdall_domain::lifecycle::{GrantEvent, grant_transition};
use heimdall_domain::operation::OperationKind;
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::time::{
    Admission, Clock, Deadline, TimeAnchor, TimePolicy, TimeStatus, TimeUncertainty, admission,
    assess_time, is_expired, next_anchor, resolve_deadline,
};
use heimdall_testkit::{VirtualClock, assert_no_canary};

const HOUR: Duration = Duration::from_secs(3600);
const MAX_WINDOW: Duration = Duration::from_secs(12 * 3600);

fn t0() -> Timestamp {
    "2026-10-02T09:00:00Z".parse().unwrap()
}

fn read(clock: &VirtualClock, generation: u64) -> TimeAnchor {
    TimeAnchor {
        wall: clock.wall(),
        monotonic: clock.monotonic(),
        process_generation: generation,
    }
}

fn shift(t: Timestamp, secs: i64) -> Timestamp {
    t.checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap()
}

/// Minimal runtime model: persisted deadline, persisted high-water anchor, the
/// grant's budget anchor and state.
struct Model {
    clock: Arc<VirtualClock>,
    generation: u64,
    policy: TimePolicy,
    deadline: Deadline,
    hwm: TimeAnchor,
    budget: TimeAnchor,
    state: GrantState,
}

impl Model {
    fn activate(intent: &str) -> Self {
        let clock = VirtualClock::at(t0());
        let deadline = resolve_deadline(
            &DeadlineIntent::Duration(intent.to_owned()),
            clock.wall(),
            MAX_WINDOW,
        )
        .unwrap();
        let a = read(&clock, 1);
        let mut state = GrantState::Requested;
        for e in [GrantEvent::Authorized, GrantEvent::Prepared] {
            state = grant_transition(state, e).unwrap();
        }
        Self {
            clock,
            generation: 1,
            policy: TimePolicy::default(),
            deadline,
            hwm: a,
            budget: a,
            state,
        }
    }

    /// Time guard pass: assess, persist the mark on `Safe`.
    fn guard(&mut self) -> TimeStatus {
        let now = read(&self.clock, self.generation);
        let status = assess_time(Some(&self.hwm), &now, &self.policy);
        if status == TimeStatus::Safe {
            self.hwm = next_anchor(Some(&self.hwm), now);
        }
        status
    }

    /// Scheduler pass: emit `DeadlineReached` once the admission deadline passed.
    fn schedule(&mut self) {
        let now = read(&self.clock, self.generation);
        if admission(self.deadline.effective, &self.budget, &now) == Admission::Expired
            && let Ok(next) = grant_transition(self.state, GrantEvent::DeadlineReached)
        {
            self.state = next;
        }
    }

    /// Whether a signature/admission would be allowed now.
    fn admits(&mut self) -> bool {
        let status = self.guard();
        self.schedule();
        let now = read(&self.clock, self.generation);
        status == TimeStatus::Safe
            && self.state.permits_use()
            && admission(self.deadline.effective, &self.budget, &now) == Admission::Open
    }

    /// Process restart: monotonic resets, generation bumps, persisted rows reload
    /// (round-tripped through JSON as the store would).
    fn restart(&mut self) {
        let persisted = serde_json::to_string(&self.deadline).unwrap();
        assert_no_canary(&persisted);
        self.clock.restart();
        self.generation += 1;
        self.deadline = serde_json::from_str(&persisted).unwrap();
    }

    /// Re-anchor the grant budget in the current generation (only from `Safe` time).
    fn reanchor(&mut self) -> bool {
        if self.guard() != TimeStatus::Safe {
            return false;
        }
        self.budget = read(&self.clock, self.generation);
        true
    }
}

#[test]
fn sleep_across_expiry_expires_and_is_never_extended() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    assert!(m.admits());

    // Sleep for two hours: the continuous clock counts it, the wall clock is
    // frozen until wake (monotonic-only advance).
    m.clock.advance_monotonic_only(2 * HOUR);
    assert!(
        !is_expired(m.clock.wall(), m.deadline.effective),
        "wall branch alone would still admit"
    );
    // The guard sees the frozen wall disagree with the monotonic clock.
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    m.schedule();
    assert_eq!(m.state, GrantState::Expired, "budget ran out during sleep");
    assert!(!m.admits());

    // Wake: the wall clock catches up. Time is consistent again; still expired.
    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert_eq!(m.guard(), TimeStatus::Safe);
    assert!(!m.admits());
    assert_eq!(m.deadline, original, "persisted deadline unchanged");
    for e in [
        GrantEvent::Repaired,
        GrantEvent::Prepared,
        GrantEvent::Approved,
    ] {
        assert!(
            grant_transition(m.state, e).is_err(),
            "expired moved on {e:?}"
        );
    }
}

#[test]
fn sleep_with_wall_running_expires_at_the_persisted_instant() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(HOUR - Duration::from_secs(1));
    assert!(m.admits());
    m.clock.advance(Duration::from_secs(1));
    assert!(!m.admits());
    assert_eq!(m.state, GrantState::Expired);
    assert_eq!(m.clock.wall(), m.deadline.effective);
}

#[test]
fn backward_jump_is_time_uncertain_and_budget_still_runs_out() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(Duration::from_secs(600));
    assert!(m.admits());

    // Wall clock stepped back one hour.
    m.clock.set_wall(shift(t0(), 600 - 3600));
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Rollback { .. })
    ));
    assert!(!m.admits(), "no admission while time is uncertain");

    // Even if the wall stays an hour behind, the monotonic budget ends on time.
    m.clock.advance(Duration::from_secs(3000));
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
    assert!(!is_expired(m.clock.wall(), m.deadline.effective));
}

#[test]
fn forward_jump_without_monotonic_progress_is_uncertain_in_process() {
    let mut m = Model::activate("PT1H");
    m.clock.set_wall(shift(t0(), 2 * 3600));
    assert!(matches!(
        m.guard(),
        TimeStatus::Uncertain(TimeUncertainty::Skew { .. })
    ));
    // The wall branch expires the grant anyway: forward jumps only end access
    // sooner.
    m.schedule();
    assert_eq!(m.state, GrantState::Expired);
}

#[test]
fn restart_with_persisted_anchor_keeps_the_deadline() {
    let mut m = Model::activate("PT1H");
    let original = m.deadline.clone();
    m.clock.advance(Duration::from_secs(1800));
    assert!(m.admits());
    let hwm_before = m.hwm;

    m.restart();
    assert_eq!(m.clock.monotonic(), Duration::ZERO);
    assert_eq!(m.deadline, original, "deadline unchanged across restart");
    // The old budget anchor belongs to the previous process: void, fail closed.
    assert!(!m.admits());
    // Re-anchoring from Safe time keeps the persisted bound: 30 minutes remain,
    // not a fresh hour.
    assert!(m.reanchor());
    assert!(m.hwm.wall >= hwm_before.wall);
    assert!(m.admits());
    m.clock.advance(Duration::from_secs(1799));
    assert!(m.admits());
    m.clock.advance(Duration::from_secs(1));
    assert!(!m.admits());
    assert_eq!(m.clock.wall(), original.effective);
    assert_eq!(m.state, GrantState::Expired);
}

#[test]
fn restart_after_rollback_refuses_to_reanchor() {
    let mut m = Model::activate("PT1H");
    m.clock.advance(Duration::from_secs(1800));
    assert!(m.admits());
    m.restart();
    m.clock.set_wall(shift(t0(), 1800 - 600));
    assert!(!m.reanchor(), "rollback below the mark across restart");
    assert!(!m.admits());
}

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
        expires_at: shift(m.clock.wall(), 7 * 86_400),
    };
    let persisted = m.deadline.clone();

    m.clock.advance(Duration::from_secs(45 * 60));
    m.restart();

    let retry_hash = hash_input_hash(&intent);
    assert_eq!(retry_hash, first_hash, "intent hashes, not the instant");
    assert_eq!(
        classify(Some(&record), retry_hash, m.clock.wall()),
        IdempotencyOutcome::Replay(op)
    );
    // The replay returns the persisted deadline. Resolving again would move the
    // instant later, which is exactly what must never happen.
    let would_be = resolve_deadline(&intent, m.clock.wall(), MAX_WINDOW).unwrap();
    assert!(would_be.effective > persisted.effective);
    assert_eq!(m.deadline, persisted);
    assert_eq!(m.deadline.effective, shift(t0(), 2 * 3600));
}

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

/// Plan §6.3 #5 over the virtual clock: within one process, whatever sequence of
/// normal passage, frozen wall, and wall jumps occurs, admission is never allowed
/// once the real elapsed time since activation reaches the granted duration.
mod props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::FileFailurePersistence;

    #[derive(Debug, Clone)]
    enum Step {
        Pass(u64),
        FrozenWall(u64),
        WallJump(i64),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (1u64..1200).prop_map(Step::Pass),
            (1u64..1200).prop_map(Step::FrozenWall),
            (-7200i64..7200).prop_map(Step::WallJump),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 512,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
            ..ProptestConfig::default()
        })]

        #[test]
        fn no_admission_past_real_duration(
            minutes in 1u64..=720,
            steps in prop::collection::vec(step(), 1..60),
        ) {
            let mut m = Model::activate(&format!("{minutes}m"));
            let granted = Duration::from_secs(minutes * 60);
            let mut real = Duration::ZERO;
            for s in steps {
                match s {
                    Step::Pass(d) => {
                        m.clock.advance(Duration::from_secs(d));
                        real += Duration::from_secs(d);
                    }
                    Step::FrozenWall(d) => {
                        m.clock.advance_monotonic_only(Duration::from_secs(d));
                        real += Duration::from_secs(d);
                    }
                    Step::WallJump(d) => m.clock.set_wall(shift(m.clock.wall(), d)),
                }
                let admitted = m.admits();
                prop_assert!(!(admitted && real >= granted), "admitted after {real:?} of {granted:?}");
                // Absorbing: once out of use, never back in use.
                if !m.state.permits_use() {
                    prop_assert!(m.state.is_terminal());
                }
            }
        }
    }
}

/// Known gap, recorded rather than hidden (ADR-0005 §3.6 "same-boot restart"):
/// with a per-process monotonic clock, a restart while the wall clock is stuck lets
/// the runtime re-anchor the budget from the stuck wall time, so real elapsed time
/// before the restart is not charged. ADR-0005 closes this with a boot-wide
/// continuous clock and a boot ID persisted in the anchor, which the current
/// `Clock`/`TimeAnchor` signatures cannot express. Run with `--ignored`; it fails
/// until that change lands.
#[test]
#[ignore = "blocked: needs ADR-0005 boot-wide continuous clock in Clock/TimeAnchor"]
fn restart_with_stuck_wall_must_not_extend_the_budget() {
    let mut m = Model::activate("PT1H");
    // Wall clock stuck for 50 minutes of real time; restart before the guard runs.
    m.clock.advance_monotonic_only(Duration::from_secs(50 * 60));
    m.restart();
    assert!(m.reanchor());
    // 50 more real minutes: 100 real minutes after a one-hour grant.
    m.clock.advance(Duration::from_secs(50 * 60));
    assert!(!m.admits(), "admitted 100 real minutes into a 1 h grant");
}
