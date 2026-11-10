//! ⟨M03⟩ U0b rows 10 and 11 (ADR-0008 D8 item 1, D9 items 2–3; m03-plan §5 item 6):
//! lock behaviour and connection policy on standing policies and in grant origins.
//!
//! **Policy actions.** `SetLockBehavior` and `SetConnectionPolicy` are classified
//! against the policy's current values, as `Cutoff` is: a change to `continue`
//! (from `revoke_on_lock`), to `existing: graceful` (from `strict`) or to
//! `multiplexing: owned_masters` (from `disabled`) is **widening** and creates a
//! `WidenPolicy` decision record (ADR-0006 §3.1); any other change narrows, takes
//! effect at once and moves the authority generation. An action that both widens one
//! field and narrows another is widening as a whole: nothing of it applies before the
//! attended decision (questions file O, Q5). Setting `revoke_on_lock` while the
//! session-lock source is `unavailable`, or while this runtime has none (the runtime
//! wires no source in wave 0), is refused `CAPABILITY_UNAVAILABLE`, `lock_signal_unavailable`,
//! before anything is written (D9 item 3: never accepted silently).
//!
//! **Grant origins** (row 10). The lock behaviour and connection policy in force when a
//! grant is created are recorded in its `GrantOrigin`, in the creating transaction,
//! and never change afterwards (`Txn::set_grant_origin` refuses any change). The
//! values recorded are the merged (strictest) applicable policy's, narrowed by the
//! request's `connection.existing: strict`. A default value (`continue`; `graceful`,
//! `disabled`) is recorded as absent, so an M01/M02 origin stays byte-identical; the
//! effective value is always the strictest of the origin and the current policies.

use std::sync::Arc;

use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::managed::{
    ConnectionPolicy, ExistingConnectionsMode, LockBehavior, MultiplexingMode,
};
use heimdall_contract::request::{PolicyAction, Request};
use heimdall_domain::grant::GrantOrigin;
use heimdall_domain::policy::StandingPolicy;
use heimdall_store::Txn;

use super::{Operations, merged_policy};
use crate::error::OpError;
use crate::ports::{LockState, SessionLockSource};

/// Whether `action` is one of the M03 policy actions.
pub(super) fn is_m03(action: &PolicyAction) -> bool {
    matches!(
        action,
        PolicyAction::SetLockBehavior { .. } | PolicyAction::SetConnectionPolicy { .. }
    )
}

/// Whether applying the M03 `action` to `p` changes nothing.
pub(super) fn unchanged(action: &PolicyAction, p: &StandingPolicy) -> bool {
    match action {
        PolicyAction::SetLockBehavior { behavior, .. } => *behavior == p.lock_behavior,
        PolicyAction::SetConnectionPolicy {
            existing,
            multiplexing,
            ..
        } => {
            existing.is_none_or(|e| e == p.connection.existing)
                && multiplexing.is_none_or(|m| m == p.connection.multiplexing)
        }
        _ => false,
    }
}

/// Whether the M03 `action` widens `p` (module docs). Unknown values never widen
/// silently: a value this build does not know is treated as widening.
pub(super) fn widening(action: &PolicyAction, p: &StandingPolicy) -> bool {
    match action {
        PolicyAction::SetLockBehavior { behavior, .. } => {
            *behavior != LockBehavior::RevokeOnLock && p.lock_behavior != *behavior
        }
        PolicyAction::SetConnectionPolicy {
            existing,
            multiplexing,
            ..
        } => {
            let widens_existing = existing.is_some_and(|e| {
                e != ExistingConnectionsMode::Strict && e != p.connection.existing
            });
            let widens_mux = multiplexing
                .is_some_and(|m| m != MultiplexingMode::Disabled && m != p.connection.multiplexing);
            widens_existing || widens_mux
        }
        _ => false,
    }
}

/// Apply the M03 `action` to `p` (the caller bumps the revision and writes it).
pub(super) fn apply(action: &PolicyAction, p: &mut StandingPolicy) {
    match action {
        PolicyAction::SetLockBehavior { behavior, .. } => p.lock_behavior = *behavior,
        PolicyAction::SetConnectionPolicy {
            existing,
            multiplexing,
            ..
        } => {
            if let Some(e) = existing {
                p.connection.existing = *e;
            }
            if let Some(m) = multiplexing {
                p.connection.multiplexing = *m;
            }
        }
        _ => {}
    }
}

/// Whether a lock source can carry `revoke_on_lock` (D9 item 3): none, or one that
/// reports `unavailable`, cannot.
fn lock_signal_available(source: Option<&Arc<dyn SessionLockSource>>) -> bool {
    source.is_some_and(|s| s.state() != LockState::Unavailable)
}

/// The origin `origin_of` built, with the lock behaviour and connection policy in
/// force at creation (module docs). `request` is the operation's stored request;
/// `floor` is the R3 session-lock floor in force (ADR-0008 §17.17 item 4).
pub(super) fn with_lock_and_connection(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    mut origin: GrantOrigin,
    request: &serde_json::Value,
    floor: LockBehavior,
) -> heimdall_store::Result<GrantOrigin> {
    let policies = tx.policies_for(&origin.profile, environment)?;
    let merged = merged_policy(&policies);
    let mut connection = merged
        .as_ref()
        .map_or(ConnectionPolicy::default(), |p| p.connection);
    if let Ok(Request::Ensure(r)) = serde_json::from_value::<Request>(request.clone())
        && r.connection
            .as_ref()
            .is_some_and(|c| c.existing == Some(ExistingConnectionsMode::Strict))
    {
        connection.existing = ExistingConnectionsMode::Strict;
    }
    // ⟨M03⟩ ADR-0008 §17.17 item 4 (U9-Q2): the strictest of the applicable policies
    // and the R3 floor in force at creation, so a later configuration edit plus a
    // restart cannot turn this grant into `continue` without an attended decision.
    origin.lock_behavior = crate::lock::origin_behavior(&policies, floor);
    origin.connection = (!connection.is_default()).then_some(connection);
    Ok(origin)
}

impl Operations {
    /// ⟨M03⟩ U0b row 11: the refusal of an M03 policy action that is checked before
    /// any transaction (module docs), if any. The session-lock source is the one the
    /// lock revocation path holds (`Inner::narrowing.lock_source`, agent G's).
    pub(super) fn policy_refusal_m03(&self, action: &PolicyAction) -> Option<OpError> {
        let source = self
            .inner
            .narrowing
            .lock_source
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match action {
            PolicyAction::SetLockBehavior {
                behavior: LockBehavior::RevokeOnLock,
                ..
            } if !lock_signal_available(source.as_ref()) => Some(
                OpError::new(
                    Code::CapabilityUnavailable,
                    "revoke on lock needs a session-lock signal, which is unavailable here",
                )
                .with_reason(reason::LOCK_SIGNAL_UNAVAILABLE)
                .with_effect(EffectStatus::None)
                .with_resource("policy", None),
            ),
            _ => None,
        }
    }
}
