//! Effective authority resolution (spec §6.2; plan §4.2 steps 2–3, §4.3 "pure
//! function over an input snapshot"; plan §6.3 properties 1–3).
//!
//! `effective = policy ∩ environment permissions ∩ requested snapshot ∩ parent
//! ∩ destination capability`, then pause/cutoff override allow, then deadline =
//! narrowest of request, policy window, parent, cutoff. Command-line options can
//! narrow or request authority; they cannot grant it.

use std::collections::BTreeMap;

use heimdall_contract::ids::DestinationId;
use heimdall_contract::request::RequiredCapabilities;
use heimdall_contract::{GrantState, Timestamp};
use serde::{Deserialize, Serialize};

use crate::environment::{DestinationCapability, EnvironmentRecord};
use crate::grant::GrantSnapshot;
use crate::policy::{ActivationBlock, AuthorityGeneration, PolicyRevision, StandingPolicy};
use crate::principal::{CallerContext, ClientRole};
use crate::profile::ProfileSnapshot;
use crate::scope::Scope;
use crate::time::{Deadline, is_expired, narrowest};

/// Everything resolution may look at. Built by the application layer from the
/// store at one consistent point; resolution itself reads nothing else.
#[derive(Debug, Clone)]
pub struct AuthorityInput<'a> {
    /// Authenticated caller.
    pub caller: &'a CallerContext,
    /// Applicable standing policy, if any.
    pub policy: Option<&'a StandingPolicy>,
    /// Current authority generation.
    pub generation: AuthorityGeneration,
    /// Environment the work would run in.
    pub environment: &'a EnvironmentRecord,
    /// Profile snapshot resolved for this request.
    pub profile: &'a ProfileSnapshot,
    /// Requested scope (subset of the profile or the whole profile).
    pub requested: &'a Scope,
    /// Parent grant for delegation.
    pub parent: Option<&'a GrantSnapshot>,
    /// Known destination capabilities.
    pub destinations: &'a BTreeMap<DestinationId, DestinationCapability>,
    /// Minimum capabilities the caller requires.
    pub required: &'a RequiredCapabilities,
    /// Requested deadline (already resolved once).
    pub requested_deadline: &'a Deadline,
    /// Now.
    pub now: Timestamp,
}

/// Authority that may be exercised without a new decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAuthority {
    /// Effective scope.
    pub scope: Scope,
    /// Effective absolute deadline (narrowest applicable bound).
    pub deadline: Timestamp,
    /// Policy revision the authority rests on.
    pub policy_revision: Option<PolicyRevision>,
    /// Generation the authority rests on; rechecked before activation.
    pub generation: AuthorityGeneration,
}

/// The added authority a request needs beyond what is saved (spec §5.3, §12.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDelta {
    /// Pairs/capabilities not covered.
    pub added_scope: Scope,
    /// Requested deadline exceeds the saved window by this much, if at all.
    pub extra_window: Option<std::time::Duration>,
    /// Environment not covered by the policy.
    pub environment_not_covered: bool,
}

/// A refusal that no approval can lift as asked (spec §6.1, §6.7, §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Denial {
    /// Policy paused or cut off.
    Blocked(ActivationBlockRepr),
    /// Delegation broader or longer than its parent.
    ExceedsParent {
        /// Scope outside the parent.
        excess_scope: Scope,
        /// Deadline later than the parent's, if so.
        later_than_parent: bool,
    },
    /// Minimum capability unmet by every available mechanism.
    CapabilityUnavailable {
        /// What was required.
        required: RequiredCapabilities,
    },
    /// Caller role may not perform the operation.
    RoleForbidden,
    /// Parent grant is not usable.
    ParentNotUsable,
}

/// Serializable mirror of [`ActivationBlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivationBlockRepr {
    /// Paused.
    Paused {
        /// Since.
        since: Timestamp,
    },
    /// Cutoff.
    Cutoff {
        /// At.
        at: Timestamp,
    },
}

impl From<ActivationBlock> for ActivationBlockRepr {
    fn from(b: ActivationBlock) -> Self {
        match b {
            ActivationBlock::Paused { since } => Self::Paused { since },
            ActivationBlock::Cutoff { at } => Self::Cutoff { at },
        }
    }
}

/// Outcome of resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityDecision {
    /// Proceed under existing authority.
    Allowed(EffectiveAuthority),
    /// Only the delta needs an owner decision; the covered part may proceed where
    /// the caller asked for it (spec §5.3).
    ApprovalRequired {
        /// What is already covered: present when any requested pair or capability
        /// is covered, so `delta.added_scope == requested − covered.scope` exactly.
        /// It can permit nothing by itself ([`Scope::is_empty`]) when only one
        /// component is covered; proceed with it only when `!scope.is_empty()`.
        covered: Option<EffectiveAuthority>,
        /// What needs a decision.
        delta: AuthorityDelta,
    },
    /// Refused.
    Denied(Denial),
}

/// Resolve effective authority. Pure and deterministic; property tests in
/// `tests/model/authority.rs` check plan §6.3 properties 1–3 against it.
///
/// Precedence, first match wins:
///
/// 1. **Pause / cutoff** of the supplied policy at `now` ⇒
///    `Denied(Blocked)`. A user stop outranks every allow and every approval path,
///    whatever the request or work ID (spec §6.1, §6.2; R-AU-02). The check uses the
///    supplied policy even when it names a different profile (fail closed).
/// 2. **Parent usability** ⇒ `Denied(ParentNotUsable)` unless the parent is
///    `active` or `degraded`, its generation equals the current generation, and its
///    deadline has not passed (spec §6.7; ADR-0005 §3.6 "generation is current").
/// 3. **Parent attenuation** ⇒ `Denied(ExceedsParent)` when the requested scope is
///    not a subset of the parent's scope or the requested deadline is later than
///    the parent's. A broader or longer delegation is denied, never escalated to
///    approval (primitives-draft §4.4).
/// 4. **Caller minimums** ⇒ `Denied(CapabilityUnavailable)` when a required
///    capability is not in the requested scope, a requested destination is unknown
///    or below `destination_scope_at_least`, or `offline_until` is later than the
///    bound no approval can lift (request, parent, cutoff). Unknown never satisfies
///    a minimum (spec §4.3; ADR-0005 §7.1).
/// 5. **Intersection.** `covered = policy ∩ profile snapshot ∩ requested ∩ parent ∩
///    destination capability`, and empty when there is no policy for this profile,
///    the environment is not in the policy, or the environment lacks
///    `automatic_activation`. `deadline = min(requested, now + policy window,
///    parent, cutoff)`.
/// 6. **Delta.** `delta.added_scope = requested − covered` (component-wise
///    [`Scope::difference`]); `extra_window` is how far the requested deadline
///    runs past the policy window; `environment_not_covered` as in step 5. An empty
///    delta yields `Allowed(covered)`; otherwise `ApprovalRequired`, with `covered`
///    present when any pair or capability is covered (spec §5.3 "only the added
///    authority requires a decision").
/// 7. **Role.** A `LimitedConsumer` may request allowed work only (principal.rs);
///    a non-empty delta for it is `Denied(RoleForbidden)`.
///
/// A requested deadline already at or before `now` is never moved later: the
/// result carries that past instant (enforcement is `now >= deadline`), so an
/// expired binding is not extended by re-resolution (spec §6.1; A05).
#[must_use]
pub fn resolve_authority(input: &AuthorityInput<'_>) -> AuthorityDecision {
    let now = input.now;
    let requested = input.requested;
    let request_deadline = input.requested_deadline.effective;

    // 1. Pause and cutoff override allow.
    if let Some(block) = input.policy.and_then(|p| p.blocks_activation_at(now)) {
        return AuthorityDecision::Denied(Denial::Blocked(block.into()));
    }

    // 2–3. Parent usability and attenuation.
    if let Some(parent) = input.parent {
        if !parent_usable(parent, input.generation, now) {
            return AuthorityDecision::Denied(Denial::ParentNotUsable);
        }
        let excess_scope = requested.difference(&parent.scope);
        let later_than_parent = request_deadline > parent.deadline.effective;
        if !scope_is_void(&excess_scope) || later_than_parent {
            return AuthorityDecision::Denied(Denial::ExceedsParent {
                excess_scope,
                later_than_parent,
            });
        }
    }

    // Bounds that no owner approval can lift (the policy window can be).
    let cutoff = input.policy.and_then(|p| p.cutoff_at);
    let parent_deadline = input.parent.map(|p| p.deadline.effective);
    let hard_bound = narrowest_of(request_deadline, [parent_deadline, cutoff]);

    // 4. Caller minimums.
    if !minimums_met(input, hard_bound) {
        return AuthorityDecision::Denied(Denial::CapabilityUnavailable {
            required: input.required.clone(),
        });
    }

    // 5. Intersection.
    let applicable = input.policy.filter(|p| p.profile == input.profile.id);
    let environment_covered = applicable
        .is_some_and(|p| p.environments.contains(&input.environment.id))
        && input.environment.permissions.automatic_activation;
    let covered_scope = match applicable {
        Some(policy) if environment_covered => {
            let mut scope = policy
                .scope
                .intersect(&input.profile.scope)
                .intersect(requested);
            if let Some(parent) = input.parent {
                scope = scope.intersect(&parent.scope);
            }
            scope.intersect(&destination_capability_scope(requested, input.destinations))
        }
        _ => Scope::empty(),
    };
    let window_end = input.policy.map(|p| saturating_add(now, p.max_window));
    let deadline = narrowest_of(hard_bound, [window_end]);
    let authority = EffectiveAuthority {
        scope: covered_scope,
        deadline,
        policy_revision: applicable.map(|p| p.revision),
        generation: input.generation,
    };

    // 6. Delta.
    let added_scope = requested.difference(&authority.scope);
    let extra_window = window_end
        .filter(|end| request_deadline > *end)
        .map(|end| request_deadline.duration_since(end).unsigned_abs());
    if scope_is_void(&added_scope) && extra_window.is_none() && environment_covered {
        return AuthorityDecision::Allowed(authority);
    }

    // 7. Role.
    if input.caller.role != ClientRole::Owner {
        return AuthorityDecision::Denied(Denial::RoleForbidden);
    }

    let covered = (!scope_is_void(&authority.scope)).then_some(authority);
    AuthorityDecision::ApprovalRequired {
        covered,
        delta: AuthorityDelta {
            added_scope,
            extra_window,
            environment_not_covered: !environment_covered,
        },
    }
}

/// Neither component has any member (stricter than [`Scope::is_empty`], which is
/// true when either component is empty).
fn scope_is_void(scope: &Scope) -> bool {
    scope.pairs.is_empty() && scope.capabilities.is_empty()
}

fn parent_usable(parent: &GrantSnapshot, generation: AuthorityGeneration, now: Timestamp) -> bool {
    matches!(parent.state, GrantState::Active | GrantState::Degraded)
        && parent.generation == generation
        && !is_expired(now, parent.deadline.effective)
}

/// Requested pairs whose destination has a recorded capability, with every
/// requested capability (the capability record constrains destinations only).
fn destination_capability_scope(
    requested: &Scope,
    destinations: &BTreeMap<DestinationId, DestinationCapability>,
) -> Scope {
    Scope {
        pairs: requested
            .pairs
            .iter()
            .filter(|pair| known_destination(destinations, &pair.destination).is_some())
            .cloned()
            .collect(),
        capabilities: requested.capabilities.clone(),
    }
}

fn known_destination<'a>(
    destinations: &'a BTreeMap<DestinationId, DestinationCapability>,
    id: &DestinationId,
) -> Option<&'a DestinationCapability> {
    destinations.get(id).filter(|cap| &cap.destination == id)
}

fn minimums_met(input: &AuthorityInput<'_>, hard_bound: Timestamp) -> bool {
    let required = input.required;
    if !required
        .capabilities
        .is_subset(&input.requested.capabilities)
    {
        return false;
    }
    if let Some(minimum) = required.destination_scope_at_least {
        let all_meet = input.requested.pairs.iter().all(|pair| {
            known_destination(input.destinations, &pair.destination)
                .is_some_and(|cap| cap.scope_enforcement >= minimum)
        });
        if !all_meet {
            return false;
        }
    }
    if let Some(offline_until) = required.offline_until
        && offline_until > hard_bound
    {
        return false;
    }
    true
}

fn narrowest_of<const N: usize>(first: Timestamp, rest: [Option<Timestamp>; N]) -> Timestamp {
    narrowest(std::iter::once(first).chain(rest.into_iter().flatten())).unwrap_or(first)
}

/// `now + window`, or the latest representable instant when that overflows (an
/// unbounded window never narrows anything).
fn saturating_add(now: Timestamp, window: std::time::Duration) -> Timestamp {
    jiff::SignedDuration::try_from(window)
        .ok()
        .and_then(|span| now.checked_add(span).ok())
        .unwrap_or(Timestamp::MAX)
}
