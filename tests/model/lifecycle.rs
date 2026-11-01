//! Grant and operation lifecycle model tests (spec §6.3, §6.7, §11.4; ADR-0006 §4;
//! plan §6.3 properties #2, #3 generation part, #5). Exercises the production
//! `heimdall_domain::lifecycle` tables, `GrantSnapshot::permits_child` and
//! `revocation::generation_still_valid`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use heimdall_contract::{GrantState, OperationState, Timestamp};
use heimdall_domain::lifecycle::{
    GrantEvent, OperationEvent, grant_transition, operation_transition,
};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::generation_still_valid;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

const GRANT_STATES: [GrantState; 12] = [
    GrantState::Requested,
    GrantState::AwaitingApproval,
    GrantState::Preparing,
    GrantState::Active,
    GrantState::Degraded,
    GrantState::Revoking,
    GrantState::Revoked,
    GrantState::Expired,
    GrantState::Released,
    GrantState::Denied,
    GrantState::Cancelled,
    GrantState::Failed,
];

const GRANT_EVENTS: [GrantEvent; 13] = [
    GrantEvent::Authorized,
    GrantEvent::ApprovalNeeded,
    GrantEvent::Approved,
    GrantEvent::DecisionDenied,
    GrantEvent::Cancel,
    GrantEvent::Prepared,
    GrantEvent::Degrade,
    GrantEvent::Repaired,
    GrantEvent::PreparationFailed,
    GrantEvent::DeadlineReached,
    GrantEvent::RevokeLocal,
    GrantEvent::RevokeComplete,
    GrantEvent::LastReferenceReleased,
];

const OP_STATES: [OperationState; 7] = [
    OperationState::Queued,
    OperationState::Running,
    OperationState::AwaitingApproval,
    OperationState::Succeeded,
    OperationState::Failed,
    OperationState::Cancelled,
    OperationState::OutcomeUnknown,
];

const OP_EVENTS: [OperationEvent; 10] = [
    OperationEvent::Start,
    OperationEvent::ApprovalNeeded,
    OperationEvent::Approved,
    OperationEvent::DecisionDenied,
    OperationEvent::Succeed,
    OperationEvent::Fail,
    OperationEvent::Cancel,
    OperationEvent::EffectUncertain,
    OperationEvent::ReconciledApplied,
    OperationEvent::ReconciledNotApplied,
];

/// ADR-0006 §4.2, written out independently of the implementation.
fn adr_grant_row(s: GrantState, e: GrantEvent) -> Option<GrantState> {
    use GrantEvent as E;
    use GrantState as S;
    Some(match (s, e) {
        (S::Requested, E::Authorized) => S::Preparing,
        (S::Requested, E::ApprovalNeeded) => S::AwaitingApproval,
        (S::Requested, E::DecisionDenied) => S::Denied,
        (S::Requested, E::Cancel) => S::Cancelled,
        (S::AwaitingApproval, E::Approved) => S::Preparing,
        (S::AwaitingApproval, E::DecisionDenied) => S::Denied,
        (S::AwaitingApproval, E::Cancel) => S::Cancelled,
        (S::AwaitingApproval, E::DeadlineReached) => S::Expired,
        (S::Preparing, E::Prepared) => S::Active,
        (S::Preparing, E::Degrade) => S::Degraded,
        (S::Preparing, E::PreparationFailed) => S::Failed,
        (S::Preparing, E::Cancel) => S::Cancelled,
        (S::Preparing, E::RevokeLocal) => S::Revoked,
        (S::Preparing, E::DeadlineReached) => S::Expired,
        (S::Active, E::Degrade) => S::Degraded,
        (S::Active, E::DeadlineReached) => S::Expired,
        (S::Active, E::RevokeLocal) => S::Revoking,
        (S::Active, E::LastReferenceReleased) => S::Released,
        (S::Degraded, E::Repaired) => S::Active,
        (S::Degraded, E::PreparationFailed) => S::Failed,
        (S::Degraded, E::DeadlineReached) => S::Expired,
        (S::Degraded, E::RevokeLocal) => S::Revoking,
        (S::Degraded, E::LastReferenceReleased) => S::Released,
        (S::Revoking, E::RevokeComplete) => S::Revoked,
        (S::Revoking, E::DeadlineReached) => S::Revoking,
        _ => return None,
    })
}

/// ADR-0006 §4.1, written out independently of the implementation.
fn adr_op_row(s: OperationState, e: OperationEvent) -> Option<OperationState> {
    use OperationEvent as E;
    use OperationState as S;
    Some(match (s, e) {
        (S::Queued, E::Start) => S::Running,
        (S::Queued, E::ApprovalNeeded) => S::AwaitingApproval,
        (S::Queued, E::Cancel) => S::Cancelled,
        (S::Queued, E::Fail) => S::Failed,
        (S::Running, E::ApprovalNeeded) => S::AwaitingApproval,
        (S::Running, E::Succeed) => S::Succeeded,
        (S::Running, E::Fail) => S::Failed,
        (S::Running, E::Cancel) => S::Cancelled,
        (S::Running, E::EffectUncertain) => S::OutcomeUnknown,
        (S::AwaitingApproval, E::Approved) => S::Running,
        (S::AwaitingApproval, E::DecisionDenied) => S::Failed,
        (S::AwaitingApproval, E::Cancel) => S::Cancelled,
        (S::OutcomeUnknown, E::ReconciledApplied) => S::Succeeded,
        (S::OutcomeUnknown, E::ReconciledNotApplied) => S::Failed,
        _ => return None,
    })
}

#[test]
fn grant_table_matches_adr_0006_exactly() {
    let mut legal = 0;
    for s in GRANT_STATES {
        for e in GRANT_EVENTS {
            let got = grant_transition(s, e).ok();
            assert_eq!(got, adr_grant_row(s, e), "{s:?} on {e:?}");
            legal += usize::from(got.is_some());
        }
    }
    assert_eq!(legal, 25, "ADR-0006 §4.2 has 25 legal rows");
}

#[test]
fn operation_table_matches_adr_0006_exactly() {
    let mut legal = 0;
    for s in OP_STATES {
        for e in OP_EVENTS {
            let got = operation_transition(s, e).ok();
            assert_eq!(got, adr_op_row(s, e), "{s:?} on {e:?}");
            legal += usize::from(got.is_some());
        }
    }
    assert_eq!(legal, 14, "ADR-0006 §4.1 has 14 legal rows");
}

#[test]
fn rejected_transition_names_state_and_event() {
    let err = grant_transition(GrantState::Expired, GrantEvent::Repaired).unwrap_err();
    assert_eq!(err.from, "Expired");
    assert_eq!(err.event, "Repaired");
    heimdall_testkit::assert_no_canary(&err.to_string());
}

#[test]
fn revoking_stays_pending_at_deadline_until_complete() {
    let s = grant_transition(GrantState::Active, GrantEvent::RevokeLocal).unwrap();
    assert_eq!(s, GrantState::Revoking);
    assert!(!s.permits_use(), "local denial applies immediately");
    let s = grant_transition(s, GrantEvent::DeadlineReached).unwrap();
    assert_eq!(s, GrantState::Revoking);
    assert_eq!(
        grant_transition(s, GrantEvent::RevokeComplete),
        Ok(GrantState::Revoked)
    );
}

/// ADR-0006 §4.1 (review F07): `outcome_unknown` is quiescent (nothing runs) but
/// not settled (the effect is not known); only reconciliation settles it.
#[test]
fn outcome_unknown_is_quiescent_not_settled_until_reconciled() {
    use OperationEvent as E;
    use OperationState as S;
    let unknown = S::OutcomeUnknown;
    assert!(unknown.is_quiescent());
    assert!(!unknown.is_settled());
    assert!(unknown.is_unresolved());
    for (event, settled) in [
        (E::ReconciledApplied, S::Succeeded),
        (E::ReconciledNotApplied, S::Failed),
    ] {
        let next = operation_transition(unknown, event).unwrap();
        assert_eq!(next, settled, "{event:?}");
        assert!(next.is_settled() && next.is_quiescent() && !next.is_unresolved());
    }
    // No retry, cancellation or blind outcome moves it.
    for e in OP_EVENTS {
        if !matches!(e, E::ReconciledApplied | E::ReconciledNotApplied) {
            assert!(operation_transition(unknown, e).is_err(), "{e:?}");
        }
    }
    // The three classes partition the states.
    for st in OP_STATES {
        let active = matches!(st, S::Queued | S::Running | S::AwaitingApproval);
        assert_eq!(st.is_quiescent(), !active, "{st:?}");
        assert_eq!(
            st.is_settled(),
            matches!(st, S::Succeeded | S::Failed | S::Cancelled),
            "{st:?}"
        );
        assert_eq!(st.is_unresolved(), st == S::OutcomeUnknown, "{st:?}");
        assert_eq!(st.is_quiescent(), st.is_settled() || st.is_unresolved());
    }
}

#[test]
fn only_active_and_degraded_permit_use() {
    for s in GRANT_STATES {
        assert_eq!(
            s.permits_use(),
            matches!(s, GrantState::Active | GrantState::Degraded),
            "{s:?}"
        );
    }
}

fn grant_state() -> impl Strategy<Value = GrantState> {
    prop::sample::select(GRANT_STATES.to_vec())
}

fn grant_event() -> impl Strategy<Value = GrantEvent> {
    prop::sample::select(GRANT_EVENTS.to_vec())
}

fn op_state() -> impl Strategy<Value = OperationState> {
    prop::sample::select(OP_STATES.to_vec())
}

fn op_event() -> impl Strategy<Value = OperationEvent> {
    prop::sample::select(OP_EVENTS.to_vec())
}

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_second(1_790_000_000 + secs).unwrap()
}

mod props {
    use heimdall_contract::ids::{EnvironmentId, GrantId};
    use heimdall_contract::request::DeadlineIntent;
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
    use heimdall_domain::policy::PolicyRevision;
    use heimdall_domain::scope::Scope;
    use heimdall_domain::time::Deadline;
    use heimdall_testkit::strategies::scope;

    use super::*;

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 512,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        }
    }

    fn grant(scope: Scope, deadline_secs: i64, seed: u8) -> GrantSnapshot {
        GrantSnapshot {
            id: GrantId::from_random_bytes([seed; 16]),
            environment: EnvironmentId::from_random_bytes([1; 16]),
            scope,
            starts_at: ts(0),
            deadline: Deadline {
                intent: DeadlineIntent::Absolute(ts(deadline_secs).to_string()),
                resolved_at: ts(0),
                effective: ts(deadline_secs),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(1),
            state: GrantState::Active,
            enforcement: EnforcementEvidence::unknown(),
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// For random event traces from any state: terminal states are absorbing
        /// (`expired` and `revoked` included), `revoking` only stays or completes,
        /// and `active` is entered only from `preparing` or `degraded`.
        #[test]
        fn grant_traces_never_reactivate(
            start in grant_state(),
            trace in prop::collection::vec(grant_event(), 0..64),
        ) {
            let mut state = start;
            let mut seen_terminal_or_revoking = state.is_terminal() || state == GrantState::Revoking;
            for e in trace {
                let before = state;
                match grant_transition(before, e) {
                    Ok(next) => {
                        prop_assert!(!before.is_terminal(), "{before:?} moved on {e:?}");
                        if before == GrantState::Revoking {
                            prop_assert!(matches!(next, GrantState::Revoking | GrantState::Revoked));
                        }
                        if next == GrantState::Active {
                            prop_assert!(matches!(before, GrantState::Preparing | GrantState::Degraded));
                        }
                        state = next;
                    }
                    Err(_) => prop_assert_eq!(adr_grant_row(before, e), None),
                }
                if seen_terminal_or_revoking {
                    prop_assert!(!state.permits_use(), "{state:?} usable after terminal/revoking");
                }
                seen_terminal_or_revoking |= state.is_terminal() || state == GrantState::Revoking;
            }
        }

        /// `expired` and `revoked` are absorbing under every event sequence.
        #[test]
        fn expired_and_revoked_are_absorbing(
            terminal in prop::sample::select(vec![GrantState::Expired, GrantState::Revoked]),
            trace in prop::collection::vec(grant_event(), 1..64),
        ) {
            for e in trace {
                prop_assert!(grant_transition(terminal, e).is_err());
            }
        }

        /// Operation traces: settled states (succeeded/failed/cancelled) absorb;
        /// `outcome_unknown` is quiescent and leaves only through reconciliation to
        /// a settled truth; a timeout is not an event, so no table entry models it.
        #[test]
        fn operation_traces_are_absorbing(
            start in op_state(),
            trace in prop::collection::vec(op_event(), 0..64),
        ) {
            let mut state = start;
            for e in trace {
                let before = state;
                if let Ok(next) = operation_transition(before, e) {
                    prop_assert!(!matches!(
                        before,
                        OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
                    ));
                    prop_assert!(!before.is_settled(), "{:?} is settled", before);
                    if before == OperationState::OutcomeUnknown {
                        prop_assert!(matches!(
                            e,
                            OperationEvent::ReconciledApplied | OperationEvent::ReconciledNotApplied
                        ));
                        prop_assert!(matches!(next, OperationState::Succeeded | OperationState::Failed));
                    }
                    state = next;
                } else {
                    prop_assert_eq!(adr_op_row(before, e), None);
                }
            }
        }

        /// Plan §6.3 #2: every accepted delegation has child scope ⊆ parent and child
        /// deadline ≤ parent; `permits_child` accepts exactly those.
        #[test]
        fn delegation_is_narrower(
            parent_scope in scope(),
            child_scope in scope(),
            parent_deadline in 1i64..86_400,
            child_deadline in 1i64..86_400,
        ) {
            let parent = grant(parent_scope.clone(), parent_deadline, 2);
            let accepted = parent.permits_child(&child_scope, ts(child_deadline));
            let expected = child_scope.is_subset_of(&parent_scope) && child_deadline <= parent_deadline;
            prop_assert_eq!(accepted, expected);
            if accepted {
                prop_assert!(ts(child_deadline) <= parent.deadline.effective);
                prop_assert!(child_scope.pairs.is_subset(&parent_scope.pairs));
            }
        }

        /// A chain of accepted delegations never exceeds the root's deadline or
        /// scope, at any depth.
        #[test]
        fn delegation_chains_stay_within_the_root(
            root_scope in scope(),
            links in prop::collection::vec((scope(), 1i64..86_400), 1..8),
        ) {
            let root = grant(root_scope.clone(), 43_200, 3);
            let mut current = root.clone();
            for (i, (s, d)) in links.into_iter().enumerate() {
                // Offer the intersection so some children are accepted.
                let candidate = s.intersect(&current.scope);
                if current.permits_child(&candidate, ts(d)) {
                    let mut child = grant(candidate, d, 4 + u8::try_from(i).unwrap());
                    child.parent = Some(current.id.clone());
                    prop_assert!(child.deadline.effective <= root.deadline.effective);
                    prop_assert!(child.scope.is_subset_of(&root.scope));
                    current = child;
                }
            }
            prop_assert!(current.scope.pairs.is_subset(&root_scope.pairs));
        }

        /// Plan §6.3 #3 (generation part): after any number of revocations,
        /// pauses or narrowings (each bumps the generation), an action authorized
        /// at an older generation is refused and only the current one proceeds.
        #[test]
        fn stale_generations_fail_closed(
            start in 0u64..1_000_000,
            bumps in prop::collection::vec(any::<bool>(), 0..32),
            probe in 0usize..33,
        ) {
            let mut history = vec![AuthorityGeneration(start)];
            for bump in bumps {
                if bump {
                    let next = history.last().copied().unwrap().next();
                    history.push(next);
                }
            }
            let current = *history.last().unwrap();
            let authorized_at = history[probe.min(history.len() - 1)];
            prop_assert_eq!(
                generation_still_valid(authorized_at, current),
                authorized_at == current
            );
            for older in &history[..history.len() - 1] {
                prop_assert!(!generation_still_valid(*older, current));
            }
        }
    }
}
