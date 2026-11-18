//! ⟨M05⟩ U2: scope-delta review, coalescing and the cooldown (ADR-0011 §4.1–§4.3).
//!
//! **The requester path** (§4.1 option B): when a trusted workspace's manifest asks for more
//! than its policy covers, the added authority becomes one `WidenPolicy{extend_scope}`
//! decision on that policy, shared by every concurrent requester of the same delta
//! ([`raise_extension`]). Wave 2's `ensure` with `context` (U4) calls it inside its own
//! transaction; [`Operations::raise_extension_for_test`] runs it alone until then.
//!
//! * **Coalescing** (§4.2): the key is `heimdall_domain::policy::coalescing_key` over
//!   {policy, revision, environment, canonical delta}. A requester joins only an unexpired
//!   pending record at the current generation whose action is exactly its own: a broader
//!   delta never joins a narrower one. The record shows only the added authority.
//! * **Cooldown** (§4.3): a denied record cools its key down until the denial time plus the
//!   policy's window (P04); an equivalent requester then gets `decision_cooldown` with
//!   `retry_after` and the denied record's reference, and **no new record**. An expired,
//!   unanswered record has none. A revision change ends every cooldown of the policy
//!   (`trust_m05::record_change`). Owner-initiated widening (`policy`) never consults it.
//! * **Narrowing**: a manifest asking for less never narrows a policy; only the owner does.
//!
//! Nothing here creates or widens authority: it only reads policies and writes decision
//! records, their bases and cooldowns (ADR-0011 I1).

use std::collections::BTreeMap;
use std::time::Duration;

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{DecisionId, EnvironmentId, PolicyId};
use heimdall_contract::request::PolicyAction;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::policy::{ScopeDelta, StandingPolicy, coalescing_key};
use heimdall_domain::workspace::{DecisionBasis, DecisionCooldown};
use heimdall_store::Txn;

use super::{Emit, Operations, approval_needed, plus};
use crate::error::OpError;
use crate::timegate::uncertain;

/// What [`raise_extension`] found for a requester's delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// The policy already covers the delta: nothing to review.
    Covered,
    /// One pending `WidenPolicy{extend_scope}` record answers for it: this requester
    /// raised it (`joined: false`) or joined an equal one (`joined: true`).
    Pending {
        /// The record.
        decision: DecisionId,
        /// Whether an existing record was joined.
        joined: bool,
    },
    /// The same delta was denied recently: no record until `retry_after`.
    Cooldown {
        /// The denied record.
        decision: DecisionId,
        /// When the cooldown ends.
        retry_after: Timestamp,
    },
}

impl Extension {
    /// The refusal a requester gets (`None` for [`Extension::Covered`]):
    /// `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED` with the record's
    /// reference; during a cooldown, reason `decision_cooldown` with `retry_after` and
    /// the **denied** record's reference.
    #[must_use]
    pub fn refusal(&self, attended: bool, now: Timestamp) -> Option<OpError> {
        match self {
            Extension::Covered => None,
            Extension::Pending { decision, .. } => Some(
                approval_needed(
                    attended,
                    decision.as_str(),
                    "the workspace asks for more than its policy covers; the owner reviews the added authority",
                )
                .with_resource("decision", Some(decision.to_string())),
            ),
            Extension::Cooldown {
                decision,
                retry_after,
            } => {
                let wait = Duration::try_from(retry_after.duration_since(now))
                    .unwrap_or(Duration::ZERO);
                let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
                Some(
                    approval_needed(
                        attended,
                        decision.as_str(),
                        "the owner denied this added authority recently; it is not asked again until the cooldown ends",
                    )
                    .with_reason(reason::DECISION_COOLDOWN)
                    .with_retry_after(ms)
                    .with_resource("decision", Some(decision.to_string())),
                )
            }
        }
    }
}

/// ⟨M05⟩ Raise, join or refuse the review of `delta` on `policy` for a requester in
/// `environment`, inside the caller's transaction at the caller's assessed `now` (no
/// record is written under uncertain time: the caller refuses first). `own` is the
/// runtime's environment (admission of the delta's environments); `decision_id` and
/// `lifetime` are the new record's, if one is written.
///
/// A29: the delta's pairs and capabilities must lie within the profile's latest snapshot
/// and its environments must be managed (`USAGE_ERROR` / `NOT_FOUND` otherwise); request
/// content never widens the profile.
///
/// # Errors
/// A store error (outer); the refusal (inner).
#[allow(clippy::too_many_arguments)]
pub(crate) fn raise_extension(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    policy: &StandingPolicy,
    own: &EnvironmentId,
    environment: &EnvironmentId,
    delta: &ScopeDelta,
    now: Timestamp,
    decision_id: DecisionId,
    lifetime: Duration,
) -> heimdall_store::Result<Result<Extension, OpError>> {
    // The stored policy is the one the key and the record are about.
    let Some(p) = tx.policy(&policy.id)? else {
        return Ok(Err(
            OpError::new(Code::NotFound, "unknown policy").with_resource("policy", None)
        ));
    };
    let Some(def) = tx.profile(&p.profile)? else {
        return Ok(Err(OpError::new(
            Code::NotFound,
            "the policy's profile is unknown",
        )
        .with_resource("profile", None)));
    };
    if !delta.pairs.is_subset(&def.scope.pairs)
        || !delta.capabilities.is_subset(&def.scope.capabilities)
    {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "the requested scope names authority outside the profile",
        )
        .with_resource("profile", Some(def.id.to_string()))));
    }
    for e in &delta.environments {
        if let Err(err) = crate::environments::admit(tx, own, e)? {
            return Ok(Err(err));
        }
    }
    let added = delta.beyond(&p);
    if added.is_empty() {
        return Ok(Ok(Extension::Covered));
    }
    let key = coalescing_key(&p.id, p.revision, environment, &added);
    if let Some(c) = tx.decision_cooldown(&key)? {
        if now < c.until && c.revision == p.revision {
            return Ok(Ok(Extension::Cooldown {
                decision: c.decision,
                retry_after: c.until,
            }));
        }
        tx.delete_decision_cooldown(&key)?;
    }
    let action = added.action(&p.id);
    let current = tx.authority_generation()?;
    let existing = tx.pending_decisions()?.into_iter().find(|d| {
        matches!(&d.kind, DecisionKind::WidenPolicy { action: a } if *a == action)
            && now < d.expires_at
            && d.generation == current
    });
    if let Some(d) = existing {
        // Join it, and remember this requester's key so a denial cools it down too.
        let mut keys = match tx.decision_basis(&d.id)? {
            Some(DecisionBasis::Extension { keys, .. }) => keys,
            _ => BTreeMap::new(),
        };
        if keys.insert(key, environment.clone()).is_none() {
            tx.put_decision_basis(
                &d.id,
                &DecisionBasis::Extension {
                    revision: p.revision,
                    keys,
                },
            )?;
        }
        return Ok(Ok(Extension::Pending {
            decision: d.id,
            joined: true,
        }));
    }
    let d = DecisionRecord {
        id: decision_id,
        kind: DecisionKind::WidenPolicy { action },
        generation: current,
        created_at: now,
        expires_at: plus(now, lifetime),
        state: DecisionState::Pending,
        decided_at: None,
    };
    tx.prune_decision_bases()?;
    tx.insert_decision(&d)?;
    tx.put_decision_basis(
        &d.id,
        &DecisionBasis::Extension {
            revision: p.revision,
            keys: [(key, environment.clone())].into_iter().collect(),
        },
    )?;
    emit.decision(tx, &d, None)?;
    Ok(Ok(Extension::Pending {
        decision: d.id,
        joined: false,
    }))
}

/// ⟨M05⟩ A denied `WidenPolicy{extend_scope}` (ADR-0011 §4.3): its key cools down until the
/// denial time plus the policy's window, for every requester that raised or joined it and,
/// for an owner-initiated record, for each of the policy's environments. Runs in the
/// denial's transaction; a deny is completed only at the record's own generation, so the
/// policy's revision is still the one the record was raised against.
pub(super) fn record_cooldowns(
    tx: &mut Txn<'_>,
    record: &DecisionRecord,
    action: &PolicyAction,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    let PolicyAction::ExtendScope {
        policy_id,
        pairs,
        capabilities,
        environments,
        background_work,
    } = action
    else {
        return Ok(());
    };
    let Some(p) = tx.policy(policy_id)? else {
        return Ok(());
    };
    let delta = ScopeDelta {
        pairs: pairs.clone(),
        capabilities: capabilities.clone(),
        environments: environments.clone(),
        background_work: *background_work == Some(true),
    };
    let mut keys: BTreeMap<String, EnvironmentId> = match tx.decision_basis(&record.id)? {
        Some(DecisionBasis::Extension { keys, .. }) => keys,
        _ => BTreeMap::new(),
    };
    for e in &p.environments {
        keys.insert(coalescing_key(&p.id, p.revision, e, &delta), e.clone());
    }
    let until = plus(now, p.max_window);
    for (key, environment) in keys {
        tx.put_decision_cooldown(&DecisionCooldown {
            key,
            policy: p.id.clone(),
            revision: p.revision,
            environment,
            decision: record.id.clone(),
            until,
        })?;
    }
    Ok(())
}

impl Operations {
    /// ⟨M05⟩ [`raise_extension`] in one transaction of its own, at fresh accepted time
    /// (`TIME_UNCERTAIN` writes nothing): the seam the P10 model drives until wave 2's
    /// `ensure` with `context` calls it from its resolution. `environment` defaults to the
    /// runtime's own.
    ///
    /// # Errors
    /// `NOT_FOUND` for an unknown policy, `TIME_UNCERTAIN`, the refusals of
    /// [`raise_extension`], a store failure.
    #[doc(hidden)]
    pub async fn raise_extension_for_test(
        &self,
        policy: &PolicyId,
        environment: Option<EnvironmentId>,
        delta: ScopeDelta,
    ) -> Result<Extension, OpError> {
        let gate = self.inner.timegate.in_txn();
        let own = self.environment().clone();
        let environment = environment.unwrap_or_else(|| own.clone());
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let pid = policy.clone();
        self.write(move |tx, emit| {
            let now = match gate.check(tx)? {
                Ok(s) => s.wall(),
                Err(u) => return Ok(Err(uncertain(&u))),
            };
            let Some(p) = tx.policy(&pid)? else {
                return Ok(Err(
                    OpError::new(Code::NotFound, "unknown policy").with_resource("policy", None)
                ));
            };
            raise_extension(
                tx,
                emit,
                &p,
                &own,
                &environment,
                &delta,
                now,
                decision_id,
                lifetime,
            )
        })
        .await?
    }
}
