//! Operation and grant state enums (spec §11.4, §6.3; ADR-0006 §4). Transition
//! rules are in `heimdall_domain::lifecycle`; this module only names the states on
//! the wire.
//!
//! Operation states fall into three classes (ADR-0006 §4.1, review F07):
//! **active** (`queued`, `running`, `awaiting_approval`), **settled** (`succeeded`,
//! `failed`, `cancelled`: final, never transition again) and **unresolved**
//! (`outcome_unknown`: quiescent, no work is running, but the real outcome is still
//! to be established by reconciliation). Restart recovery drives active operations
//! and reconciles unresolved ones; retention purges only settled ones.

use serde::{Deserialize, Serialize};

/// Operation states (spec §11.4). A caller timeout is not a state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted and journaled; not yet running.
    Queued,
    /// In progress.
    Running,
    /// Waiting for an owner or provider decision on an owner channel.
    AwaitingApproval,
    /// Settled: completed with a result.
    Succeeded,
    /// Settled: failed with a classified error.
    Failed,
    /// Settled: explicitly cancelled; the result says whether an irreversible or
    /// uncertain step may have occurred.
    Cancelled,
    /// Unresolved: an external effect may or may not have applied. Quiescent until
    /// reconciliation settles it to `succeeded` or `failed`; never purged while
    /// unresolved; never retried blindly.
    OutcomeUnknown,
}

impl OperationState {
    /// Final: no transition is possible and a new operation is needed for new work.
    #[must_use]
    pub fn is_settled(self) -> bool {
        matches!(
            self,
            OperationState::Succeeded | OperationState::Failed | OperationState::Cancelled
        )
    }

    /// Nothing is running for this operation: settled or unresolved. Callers
    /// waiting for "the operation stopped" wait for this; callers needing a truth
    /// about the effect need [`Self::is_settled`].
    #[must_use]
    pub fn is_quiescent(self) -> bool {
        self.is_settled() || self == OperationState::OutcomeUnknown
    }

    /// Awaiting reconciliation of an uncertain external effect.
    #[must_use]
    pub fn is_unresolved(self) -> bool {
        self == OperationState::OutcomeUnknown
    }
}

/// Grant states (spec §6.3 table). Terminal states never reactivate the same grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Intent recorded; no usable access promised.
    Requested,
    /// Additional owner/provider action required.
    AwaitingApproval,
    /// Authorized resources are being reconciled.
    Preparing,
    /// Specified capability verified within recorded evidence freshness.
    Active,
    /// Some capability unavailable; authorized repair may proceed.
    Degraded,
    /// Local denial applied; remote effects may be pending.
    Revoking,
    /// Terminal.
    Revoked,
    /// Terminal.
    Expired,
    /// Terminal.
    Released,
    /// Terminal.
    Denied,
    /// Terminal.
    Cancelled,
    /// Terminal: required preparation could not complete.
    Failed,
}

impl GrantState {
    /// Whether the grant can never become usable again (spec §6.3).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            GrantState::Revoked
                | GrantState::Expired
                | GrantState::Released
                | GrantState::Denied
                | GrantState::Cancelled
                | GrantState::Failed
        )
    }

    /// Whether new signing or admission may be permitted in this state (subject to
    /// deadline, pause, cutoff, time gate and generation rechecks).
    #[must_use]
    pub fn permits_use(self) -> bool {
        matches!(self, GrantState::Active | GrantState::Degraded)
    }

    /// Whether the issuer may reserve a certificate for a grant in this state
    /// (ADR-0005 §3.5 refusal 1).
    #[must_use]
    pub fn permits_issuance(self) -> bool {
        matches!(
            self,
            GrantState::Preparing | GrantState::Active | GrantState::Degraded
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_unknown_is_quiescent_but_not_settled() {
        assert!(OperationState::OutcomeUnknown.is_quiescent());
        assert!(!OperationState::OutcomeUnknown.is_settled());
        assert!(OperationState::OutcomeUnknown.is_unresolved());
        assert!(OperationState::Succeeded.is_settled());
        assert!(!OperationState::Running.is_quiescent());
    }
}
