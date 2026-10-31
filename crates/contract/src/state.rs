//! Operation and grant state enums (spec §11.4, §6.3). Transition rules are in
//! `heimdall_domain::lifecycle`; this module only names the states on the wire.

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
    /// Terminal: completed with a result.
    Succeeded,
    /// Terminal: failed with a classified error.
    Failed,
    /// Terminal: explicitly cancelled; the result says whether an irreversible or
    /// uncertain step may have occurred.
    Cancelled,
    /// Terminal until reconciled: an external effect may or may not have applied.
    OutcomeUnknown,
}

impl OperationState {
    /// Whether no further transition is expected without a new operation.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            OperationState::Succeeded
                | OperationState::Failed
                | OperationState::Cancelled
                | OperationState::OutcomeUnknown
        )
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
    /// deadline, pause, cutoff and generation rechecks).
    #[must_use]
    pub fn permits_use(self) -> bool {
        matches!(self, GrantState::Active | GrantState::Degraded)
    }
}
