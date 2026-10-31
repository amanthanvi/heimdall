//! Executable grant and operation state machines (spec §6.3, §11.4; ADR-0006 §4).
//!
//! `transition(state, event)` is total over the table and rejects everything else.
//! Terminal states never reactivate; a timeout is not an event.

use heimdall_contract::{GrantState, OperationState};
use serde::{Deserialize, Serialize};

/// Events that move a grant (names follow spec §6.3 columns).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantEvent {
    /// Authority resolved; reconciliation starts.
    Authorized,
    /// Added authority needs an owner/provider decision.
    ApprovalNeeded,
    /// Decision recorded: approved.
    Approved,
    /// Decision recorded: denied.
    DecisionDenied,
    /// Caller cancelled before activation.
    Cancel,
    /// Preparation verified the specified capability.
    Prepared,
    /// Some capability became unavailable (repair may proceed).
    Degrade,
    /// Repair restored the capability.
    Repaired,
    /// Required preparation cannot complete.
    PreparationFailed,
    /// Deadline reached (persisted absolute instant).
    DeadlineReached,
    /// Local revocation applied (tombstone persisted).
    RevokeLocal,
    /// Remote effects acknowledged or bounded; revocation complete.
    RevokeComplete,
    /// Last authorized consumer reference dropped.
    LastReferenceReleased,
}

/// Events that move an operation (spec §11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEvent {
    /// Picked up by the runtime.
    Start,
    /// Needs an owner/provider decision.
    ApprovalNeeded,
    /// Decision recorded; work resumes.
    Approved,
    /// Decision recorded: denied.
    DecisionDenied,
    /// Completed with a result.
    Succeed,
    /// Failed with a classified error.
    Fail,
    /// Explicit cancellation (idempotent; a no-op in terminal states is reported
    /// by the caller, not modelled as a transition).
    Cancel,
    /// External effect may or may not have applied.
    EffectUncertain,
    /// Reconciliation established the real outcome: applied.
    ReconciledApplied,
    /// Reconciliation established the real outcome: not applied.
    ReconciledNotApplied,
}

/// A rejected transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid transition from {from:?} on {event}")]
pub struct InvalidTransition {
    /// State before.
    pub from: String,
    /// Event name.
    pub event: String,
}

/// Grant transition table (spec §6.3). `released` from `active`/`degraded` is only
/// legal when the caller has verified no other authorized binding holds the grant;
/// that reference count lives in the store, not here.
pub fn grant_transition(
    state: GrantState,
    event: GrantEvent,
) -> Result<GrantState, InvalidTransition> {
    use GrantEvent as E;
    use GrantState as S;
    let next = match (state, event) {
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
        // Remains pending with explicit evidence until complete (spec §6.3).
        (S::Revoking, E::DeadlineReached) => S::Revoking,

        (from, ev) => {
            return Err(InvalidTransition {
                from: format!("{from:?}"),
                event: format!("{ev:?}"),
            });
        }
    };
    Ok(next)
}

/// Operation transition table (spec §11.4, primitives-draft §3).
pub fn operation_transition(
    state: OperationState,
    event: OperationEvent,
) -> Result<OperationState, InvalidTransition> {
    use OperationEvent as E;
    use OperationState as S;
    let next = match (state, event) {
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

        // Reconciliation of an uncertain outcome creates a terminal truth.
        (S::OutcomeUnknown, E::ReconciledApplied) => S::Succeeded,
        (S::OutcomeUnknown, E::ReconciledNotApplied) => S::Failed,

        (from, ev) => {
            return Err(InvalidTransition {
                from: format!("{from:?}"),
                event: format!("{ev:?}"),
            });
        }
    };
    Ok(next)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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

    #[test]
    fn terminal_grant_states_never_move() {
        for s in GRANT_STATES.into_iter().filter(|s| s.is_terminal()) {
            for e in GRANT_EVENTS {
                assert!(grant_transition(s, e).is_err(), "{s:?} moved on {e:?}");
            }
        }
    }

    #[test]
    fn nothing_returns_to_active_from_terminal_or_revoking() {
        for s in GRANT_STATES {
            for e in GRANT_EVENTS {
                if let Ok(next) = grant_transition(s, e)
                    && next == GrantState::Active
                {
                    assert!(
                        matches!(s, GrantState::Preparing | GrantState::Degraded),
                        "{s:?} -> active on {e:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn spec_6_3_rows() {
        use GrantEvent as E;
        use GrantState as S;
        assert_eq!(
            grant_transition(S::Requested, E::Authorized),
            Ok(S::Preparing)
        );
        assert_eq!(grant_transition(S::Active, E::RevokeLocal), Ok(S::Revoking));
        assert_eq!(
            grant_transition(S::Revoking, E::RevokeComplete),
            Ok(S::Revoked)
        );
        assert_eq!(grant_transition(S::Degraded, E::Repaired), Ok(S::Active));
        assert!(grant_transition(S::Expired, E::Repaired).is_err());
    }

    #[test]
    fn timeout_is_not_an_operation_event_and_terminal_ops_stay() {
        use OperationEvent as E;
        use OperationState as S;
        for s in [S::Succeeded, S::Failed, S::Cancelled] {
            for e in [E::Start, E::Succeed, E::Fail, E::Cancel, E::EffectUncertain] {
                assert!(operation_transition(s, e).is_err());
            }
        }
        assert_eq!(
            operation_transition(S::Running, E::EffectUncertain),
            Ok(S::OutcomeUnknown)
        );
        assert_eq!(
            operation_transition(S::OutcomeUnknown, E::ReconciledApplied),
            Ok(S::Succeeded)
        );
        assert!(operation_transition(S::OutcomeUnknown, E::Cancel).is_err());
    }
}
