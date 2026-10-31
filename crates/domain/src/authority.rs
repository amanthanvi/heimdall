//! Effective authority resolution (spec §6.2; plan §4.2 steps 2–3, §4.3 "pure
//! function over an input snapshot"; plan §6.3 properties 1–3).
//!
//! `effective = policy ∩ environment permissions ∩ requested snapshot ∩ parent
//! ∩ destination capability`, then pause/cutoff override allow, then deadline =
//! narrowest of request, policy window, parent, cutoff. Command-line options can
//! narrow or request authority; they cannot grant it.

use std::collections::BTreeMap;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::DestinationId;
use heimdall_contract::request::RequiredCapabilities;
use serde::{Deserialize, Serialize};

use crate::environment::{DestinationCapability, EnvironmentRecord};
use crate::grant::GrantSnapshot;
use crate::policy::{ActivationBlock, AuthorityGeneration, PolicyRevision, StandingPolicy};
use crate::principal::CallerContext;
use crate::profile::ProfileSnapshot;
use crate::scope::Scope;
use crate::time::Deadline;

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
        /// What is already covered.
        covered: Option<EffectiveAuthority>,
        /// What needs a decision.
        delta: AuthorityDelta,
    },
    /// Refused.
    Denied(Denial),
}

/// Resolve effective authority. Pure and deterministic; property tests in
/// `tests/model/` check plan §6.3 properties 1–3 against it.
#[must_use]
pub fn resolve_authority(_input: &AuthorityInput<'_>) -> AuthorityDecision {
    todo!("M01-T01: intersection, pause/cutoff precedence, parent attenuation, capability minimums")
}
