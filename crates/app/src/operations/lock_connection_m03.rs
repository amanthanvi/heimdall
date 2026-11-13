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

/// ⟨M03; ADR-0008 §17.25 item 19 (Q-T2 (a))⟩ The runtime's D8 wording for a managed
/// alias under a connection policy: the `ConnectionPolicyReport` the managed adapter's
/// report would carry for that alias (its identity selection, observed by the runtime,
/// and `heimdall_adapters::managed::report::connection_wording`). `app` cannot compute
/// the wording itself (the texts live in `localenv` and `adapters`, which `app` may not
/// depend on), so the runtime wires it ([`Operations::set_connection_wording`]). `None`:
/// not computable here, and the caller reports nothing (fail closed).
pub trait ConnectionWording: Send + Sync {
    /// The report for `alias` under `policy`. May read the alias's static observation
    /// (files): never called inside a store transaction, and called on the blocking pool.
    fn report(
        &self,
        alias: &str,
        policy: &ConnectionPolicy,
    ) -> Option<heimdall_contract::managed::ConnectionPolicyReport>;
}

/// ⟨§17.25 item 19⟩ A pair's connection policy as `inspect destinations` reports it: the
/// strictest (`effective_connection_policy`, D8 item 1's fail-closed merge) over every
/// current standing policy covering the pair (its profile's, applicable in `env`, its
/// scope naming the pair), as the runtime's pair-level mux rendering merges them. No
/// covering policy: `None` (nothing to report).
pub(super) fn pair_connection_policy(
    tx: &mut Txn<'_>,
    env: &EnvironmentId,
    pair: &heimdall_domain::scope::AccessPair,
) -> heimdall_store::Result<Option<ConnectionPolicy>> {
    let mut applicable: Vec<ConnectionPolicy> = Vec::new();
    for profile in tx.profiles()? {
        for p in tx.policies_for(&profile.id, env)? {
            if p.scope.pairs.contains(pair) {
                applicable.push(p.connection);
            }
        }
    }
    let Some((first, rest)) = applicable.split_first() else {
        return Ok(None);
    };
    Ok(Some(
        heimdall_domain::connection::effective_connection_policy(Some(*first), rest, None),
    ))
}

impl Operations {
    /// ⟨M03; ADR-0008 §17.25 item 19⟩ Wire the runtime's D8 wording source
    /// ([`ConnectionWording`]). Without it `inspect destinations` carries no
    /// `preference.connection_policy`.
    pub fn set_connection_wording(&self, wording: Arc<dyn ConnectionWording>) {
        *self
            .inner
            .narrowing
            .connection_wording
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(wording);
    }

    /// ⟨§17.25 item 19⟩ Insert `preference.connection_policy` into each `items[index]`
    /// of `pending` (index, alias, the pair's policy) whose report the wired source
    /// computes; any other item is left as it is (the key absent).
    pub(super) async fn add_connection_policies(
        &self,
        items: &mut [serde_json::Value],
        pending: Vec<(usize, String, ConnectionPolicy)>,
    ) {
        if pending.is_empty() {
            return;
        }
        let Some(wording) = self
            .inner
            .narrowing
            .connection_wording
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        let reports = tokio::task::spawn_blocking(move || {
            pending
                .into_iter()
                .filter_map(|(i, alias, policy)| wording.report(&alias, &policy).map(|r| (i, r)))
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        for (i, report) in reports {
            if let Some(serde_json::Value::Object(pref)) =
                items.get_mut(i).and_then(|item| item.get_mut("preference"))
            {
                pref.insert("connection_policy".to_owned(), serde_json::json!(report));
            }
        }
    }

    /// ⟨M03; ADR-0008 §17.25 item 21 (Q-T5 (a)), D9 item 1⟩ Add the read-only
    /// `lock: {behavior, disclosure, acknowledged_at?}` to an `inspect capabilities`
    /// answer, from [`Operations::lock_disclosure`] with this runtime's signal and the
    /// claim table's `lock_continuity` verdict (a wired managed adapter's descriptor;
    /// none: not verified). A store failure leaves the key absent (the reader shows
    /// "unknown").
    pub(super) async fn add_capabilities_lock(&self, data: &mut serde_json::Value) {
        let continuity_verified = self.inner.config.adapters.iter().any(|a| {
            let d = a.descriptor();
            d.identity.mechanism == super::MANAGED_CERTIFICATE
                && d.lock_continuity == crate::ports::LockContinuity::Verified
        });
        let disclosure = match self
            .lock_disclosure(continuity_verified, self.session_lock_signal())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(code = %e.code, "the lock disclosure could not be read");
                return;
            }
        };
        let mut lock = serde_json::json!({
            "behavior": disclosure.behavior,
            "disclosure": disclosure.text,
        });
        if let (Some(at), serde_json::Value::Object(map)) = (disclosure.acknowledged_at, &mut lock)
        {
            map.insert("acknowledged_at".to_owned(), serde_json::json!(at));
        }
        if let serde_json::Value::Object(map) = data {
            map.insert("lock".to_owned(), lock);
        }
    }

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
