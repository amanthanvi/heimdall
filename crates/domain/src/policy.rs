//! Standing policy (spec §4.1, §6.1; plan §4.3 "mutable versioned standing
//! policies"). Pause and cutoff outrank standing automatic permission.

use std::collections::BTreeSet;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{EnvironmentId, PolicyId, ProfileId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// ⟨M03⟩ The lock behaviour and connection policy types are wire-visible (policy
/// actions carry them), so they live in the contract and are re-exported here.
pub use heimdall_contract::managed::{
    ConnectionPolicy, ExistingConnectionsMode, LockBehavior, MultiplexingMode,
};

use crate::scope::Scope;

/// Monotonic revision of a policy definition. Grants pin the revision they were
/// authorized under (spec §4.1 "Grant ... policy revision").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRevision(pub u64);

/// Monotonic authority generation. Bumped on revocation, pause, cutoff and policy
/// narrowing; stale approvals, renewals and retries against an older generation
/// are invalid (spec §6.7, R-SE-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityGeneration(pub u64);

impl AuthorityGeneration {
    /// Next generation.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Where a policy decision came from (spec §13.4 "owner's verified decision").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySource {
    /// Owner decision recorded on the owner channel at `decided_at`.
    OwnerDecision {
        /// When.
        decided_at: Timestamp,
    },
    /// Personal default profile created at setup.
    SetupDefault,
}

/// Pause state (spec §5.6, §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PauseState {
    /// Automatic activation allowed.
    Active,
    /// Paused since `since`; blocks new automatic activation, not existing work.
    Paused {
        /// When.
        since: Timestamp,
    },
}

/// A saved user decision permitting automatic creation of bounded access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPolicy {
    /// Policy ID.
    pub id: PolicyId,
    /// Revision.
    pub revision: PolicyRevision,
    /// Profile this policy authorizes (resolved to a snapshot at activation).
    pub profile: ProfileId,
    /// Optional workspace the policy is bound to (trust lives here, not in the repo).
    pub workspace: Option<WorkspaceId>,
    /// Maximum scope automatic work may receive.
    pub scope: Scope,
    /// Environments in which the policy applies.
    pub environments: BTreeSet<EnvironmentId>,
    /// Maximum window for a new work binding (spec P04 default 12 h).
    pub max_window: Duration,
    /// Pause state.
    pub pause: PauseState,
    /// Hard cutoff; after it no new work activates until deliberately cleared.
    pub cutoff_at: Option<Timestamp>,
    /// Provenance.
    pub source: PolicySource,
    /// ⟨M03⟩ What a session lock does to grants under this policy (ADR-0008 D9; §5
    /// item 6). Serde default `continue`, omitted when `continue`, so every M01/M02
    /// policy record decodes and re-encodes unchanged.
    #[serde(default, skip_serializing_if = "is_continue")]
    pub lock_behavior: LockBehavior,
    /// ⟨M03⟩ The connection policy (ADR-0008 D8 item 1). Serde default `graceful`,
    /// `disabled`, omitted when default.
    #[serde(default, skip_serializing_if = "ConnectionPolicy::is_default")]
    pub connection: ConnectionPolicy,
    /// ⟨M05⟩ The personal default of its environments (ADR-0011 §3.1: at most one personal
    /// policy per environment is marked; ADR-0006 §17.5 item 5 left where it is recorded to
    /// M05). Set and moved only by an approved `create {default: true}`; the previous
    /// default of an environment loses it in the same transaction. Serde default `false`,
    /// omitted when `false`, so every M01–M03 policy record decodes and re-encodes
    /// unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default: bool,
}

fn is_continue(b: &LockBehavior) -> bool {
    *b == LockBehavior::Continue
}

/// ⟨M03⟩ The stricter of two lock behaviours: `revoke_on_lock` wins (fail closed;
/// U0b row 11). Any value this build does not know counts as `revoke_on_lock`.
#[must_use]
pub fn strictest_lock_behavior(a: LockBehavior, b: LockBehavior) -> LockBehavior {
    match (a, b) {
        (LockBehavior::Continue, LockBehavior::Continue) => LockBehavior::Continue,
        _ => LockBehavior::RevokeOnLock,
    }
}

/// ⟨M03⟩ The stricter of two connection policies, field by field (ADR-0008 D8
/// item 1: the effective policy is the strictest of every source): `strict` beats
/// `graceful`, `disabled` beats `owned_masters`.
#[must_use]
pub fn strictest_connection_policy(a: ConnectionPolicy, b: ConnectionPolicy) -> ConnectionPolicy {
    let existing = match (a.existing, b.existing) {
        (ExistingConnectionsMode::Graceful, ExistingConnectionsMode::Graceful) => {
            ExistingConnectionsMode::Graceful
        }
        _ => ExistingConnectionsMode::Strict,
    };
    let multiplexing = match (a.multiplexing, b.multiplexing) {
        (MultiplexingMode::OwnedMasters, MultiplexingMode::OwnedMasters) => {
            MultiplexingMode::OwnedMasters
        }
        _ => MultiplexingMode::Disabled,
    };
    ConnectionPolicy {
        existing,
        multiplexing,
    }
}

/// ⟨M03⟩ U0b row 11: extend a merged policy view (the application's
/// `merged_policy`) fail closed for the two M03 fields: the strictest lock
/// behaviour and connection policy of `merged` and every applicable policy.
pub fn merge_lock_and_connection(merged: &mut StandingPolicy, policies: &[StandingPolicy]) {
    for p in policies {
        merged.lock_behavior = strictest_lock_behavior(merged.lock_behavior, p.lock_behavior);
        merged.connection = strictest_connection_policy(merged.connection, p.connection);
    }
}

/// ⟨M05⟩ The context a policy resolution runs in (ADR-0011 §3.1 as ruled in §10 item 1;
/// ADR-0006 revision 5, §17, replacing §13.6 item 5's first-by-ID choice).
///
/// Every resolution path names one: `ensure` and `run` from the request's context
/// (personal when it has none), renewal, re-validation and issuance from the grant's
/// recorded context ([`crate::grant::GrantOrigin::workspace`]), `activation_refusal`
/// from the resolved intent's ([`crate::operation::ResolvedIntent::workspace`]),
/// ordinary `ssh` (personal), the shell hook (the match of its working directory).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "workspace", rename_all = "snake_case")]
pub enum PolicyContext {
    /// Repository-free work, ordinary `ssh`, and every request without a workspace
    /// match: only policies with `workspace: None` apply.
    Personal,
    /// A workspace the observation matched as `Trusted` or `Member` (never `Ambiguous`).
    Workspace(WorkspaceId),
}

impl PolicyContext {
    /// The context of a workspace match: `Trusted` and `Member` select that workspace;
    /// `Untrusted` and `Ambiguous` are personal, so an ambiguous match (a re-clone or
    /// restore at the same path, a move) never activates the old record's scope (ADR-0011
    /// §10 item 1). Whether an ambiguous request may still use what personal policy
    /// covers, and the `ReconcileWorkspace` decision it raises, are the activation's
    /// (M05 U4); resolution only guarantees the old workspace's scope is out of reach.
    #[must_use]
    pub fn of_match(m: &crate::workspace::WorkspaceMatch) -> Self {
        use crate::workspace::WorkspaceMatch;
        match m {
            WorkspaceMatch::Trusted { workspace } | WorkspaceMatch::Member { workspace } => {
                Self::Workspace(workspace.clone())
            }
            _ => Self::Personal,
        }
    }

    /// The context recorded on a grant or intent: `None` is personal (every M01–M03
    /// record).
    #[must_use]
    pub fn of_recorded(workspace: Option<&WorkspaceId>) -> Self {
        workspace.map_or(Self::Personal, |w| Self::Workspace(w.clone()))
    }

    /// The workspace, when there is one (what a grant or intent records).
    #[must_use]
    pub fn workspace(&self) -> Option<&WorkspaceId> {
        match self {
            Self::Personal => None,
            Self::Workspace(w) => Some(w),
        }
    }
}

/// ⟨M05⟩ The standing policies that apply in `context` (ADR-0011 §10 item 1; ADR-0006
/// revision 5 §17 item 3, replacing §13.6 item 5's "every policy naming the profile and
/// environment"). `policies` are those naming the profile and environment
/// (`heimdall_store::Txn::policies_for`, ordered by ID).
///
/// * [`PolicyContext::Personal`]: the personal policies (`workspace: None`) only.
/// * [`PolicyContext::Workspace`]: that workspace's own policies first, then the
///   personal ones (a personal pause or cutoff stops that profile's workspace work);
///   when the workspace has no policy for the profile, the personal ones alone.
///
/// Another workspace's policy never applies, and a workspace policy never applies to
/// personal work. Idempotent: applying it to its own result returns the same list.
#[must_use]
pub fn applicable_policies(
    policies: &[StandingPolicy],
    context: &PolicyContext,
) -> Vec<StandingPolicy> {
    let mut out: Vec<StandingPolicy> = match context {
        PolicyContext::Personal => Vec::new(),
        PolicyContext::Workspace(w) => policies
            .iter()
            .filter(|p| p.workspace.as_ref() == Some(w))
            .cloned()
            .collect(),
    };
    out.extend(policies.iter().filter(|p| p.workspace.is_none()).cloned());
    out
}

/// ⟨M05⟩ The policy view a resolution in `context` uses (ADR-0011 §10 item 1; ADR-0006
/// revision 5 §17 item 3, replacing §13.6 item 5's first-by-ID merge).
///
/// * **Scope, window and revision** come from the first of
///   [`applicable_policies`]: the context's own policy (in [`PolicyContext::Workspace`],
///   that workspace's policy for the profile, else the personal one; in
///   [`PolicyContext::Personal`], the personal one). A workspace policy never supplies
///   personal scope, and one workspace's policy never applies to another workspace.
///   Among several policies of one context (none is created in production) the first by
///   ID is chosen, as before.
/// * **Blocks** (any pause, the earliest cutoff, the strictest lock behaviour and
///   connection policy) are merged fail closed over every applicable policy: a personal
///   pause or cutoff stops that profile's workspace work; a workspace's pause, cutoff or
///   lock behaviour never reaches personal work or another workspace.
///
/// `None` when no policy applies in the context: the request then needs an owner
/// decision, never another context's policy.
#[must_use]
pub fn resolve_policy(
    policies: &[StandingPolicy],
    context: &PolicyContext,
) -> Option<StandingPolicy> {
    let applicable = applicable_policies(policies, context);
    let mut merged = applicable.first()?.clone();
    for p in &applicable {
        if let Some(c) = p.cutoff_at {
            merged.cutoff_at = Some(merged.cutoff_at.map_or(c, |m| m.min(c)));
        }
        if let PauseState::Paused { since } = p.pause {
            merged.pause = match merged.pause {
                PauseState::Paused { since: s } => PauseState::Paused {
                    since: s.min(since),
                },
                PauseState::Active => PauseState::Paused { since },
            };
        }
    }
    merge_lock_and_connection(&mut merged, &applicable);
    Some(merged)
}

/// ⟨M05⟩ [`resolve_policy`] for **continuing** work (ADR-0006 §13.6 item 1): the same view
/// without its pause. A pause blocks new grants and new work bindings only; every
/// applicable cutoff of the context still bounds running grants.
#[must_use]
pub fn resolve_continuing_policy(
    policies: &[StandingPolicy],
    context: &PolicyContext,
) -> Option<StandingPolicy> {
    let mut view = resolve_policy(policies, context)?;
    view.pause = PauseState::Active;
    Some(view)
}

/// ⟨M05⟩ The default maximum window of a new standing policy (spec P04: "new
/// trusted-work sessions inherit a 12-hour maximum window").
pub const DEFAULT_MAX_WINDOW: Duration = Duration::from_secs(12 * 60 * 60);

/// ⟨M05⟩ Why a policy window string was refused (`create.max_window`,
/// `set_max_window.max_window`; ADR-0006 §17.6 R5-Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WindowError {
    /// Not an ISO 8601 (`PT12H`) or friendly (`12h`, `1h 30m`) duration of exact units,
    /// or longer than 128 bytes.
    #[error("the window is not a duration of exact units (`12h`, `30m`, `PT12H`)")]
    Malformed,
    /// Zero or negative.
    #[error("the window must be longer than zero")]
    NotPositive,
    /// Longer than the longest window the runtime allows (spec P04).
    #[error("the window exceeds the maximum session window")]
    ExceedsMaximum,
}

/// ⟨M05⟩ Parse a policy window (ADR-0006 §17.6 R5-Q3: a duration string): an ISO 8601
/// (`PT12H`) or friendly (`12h`, `30m`, `1h 30m`) duration of exact units, the parser
/// `heimdall_domain::time::resolve_deadline` uses, bounded to `0 < window ≤ max`. `max`
/// is the runtime's session maximum (spec P04: "a 12-hour maximum window, visible and
/// adjustable during setup"; `OperationsConfig::default_window`, which already caps every
/// policy window at resolution), so a stored window never exceeds what resolution would
/// honour. Pure; bounded input (A29).
///
/// # Errors
/// [`WindowError`].
pub fn parse_max_window(text: &str, max: Duration) -> Result<Duration, WindowError> {
    if text.len() > 128 {
        return Err(WindowError::Malformed);
    }
    let signed: jiff::SignedDuration = text.trim().parse().map_err(|_| WindowError::Malformed)?;
    if signed <= jiff::SignedDuration::ZERO {
        return Err(WindowError::NotPositive);
    }
    let window = Duration::try_from(signed).map_err(|_| WindowError::Malformed)?;
    if window > max {
        return Err(WindowError::ExceedsMaximum);
    }
    Ok(window)
}

/// ⟨M05⟩ Authority a request asks for beyond a standing policy (ADR-0011 §4.1–§4.2): the
/// added pairs, capabilities and environments, and whether it asks for `continue` lock
/// behaviour the policy does not record. Additions only: a request that asks for less
/// never narrows a policy (§4.2 "Narrowing").
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopeDelta {
    /// Added pairs.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pairs: BTreeSet<crate::scope::AccessPair>,
    /// Added capabilities.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub capabilities: BTreeSet<crate::scope::Capability>,
    /// Added environments.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub environments: BTreeSet<EnvironmentId>,
    /// `continue` lock behaviour asked for while the policy records `revoke_on_lock`
    /// (ADR-0011 §10 item 2: coverage includes lock behaviour).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub background_work: bool,
}

impl ScopeDelta {
    /// Whether nothing is added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
            && self.capabilities.is_empty()
            && self.environments.is_empty()
            && !self.background_work
    }

    /// The part of `self` that `policy` does not already hold (the delta a record
    /// shows: only the added authority, spec §12.3).
    #[must_use]
    pub fn beyond(&self, policy: &StandingPolicy) -> ScopeDelta {
        ScopeDelta {
            pairs: self
                .pairs
                .difference(&policy.scope.pairs)
                .cloned()
                .collect(),
            capabilities: self
                .capabilities
                .difference(&policy.scope.capabilities)
                .copied()
                .collect(),
            environments: self
                .environments
                .difference(&policy.environments)
                .cloned()
                .collect(),
            background_work: self.background_work && policy.lock_behavior != LockBehavior::Continue,
        }
    }

    /// The verbatim `extend_scope` action that adds exactly this delta to `policy`
    /// (`background_work: Some(true)` only when the delta asks for `continue`).
    #[must_use]
    pub fn action(&self, policy: &PolicyId) -> heimdall_contract::request::PolicyAction {
        heimdall_contract::request::PolicyAction::ExtendScope {
            policy_id: policy.clone(),
            pairs: self.pairs.clone(),
            capabilities: self.capabilities.clone(),
            environments: self.environments.clone(),
            background_work: self.background_work.then_some(true),
        }
    }
}

/// ⟨M05⟩ What a standing policy covers of a request (ADR-0011 §3.2 covered-or-nothing,
/// as ruled in §10 item 2), from [`coverage`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The covered part of the requested scope (requested ∩ the policy's scope).
    pub covered: Scope,
    /// The covered environments (requested ∩ the policy's environments).
    pub environments: BTreeSet<EnvironmentId>,
    /// What the policy does not cover. Never consulted for activation.
    pub uncovered: ScopeDelta,
    /// The lock behaviour activation uses: always the policy's recorded one, never the
    /// request's (§10 item 2).
    pub lock_behavior: LockBehavior,
}

/// ⟨M05⟩ Coverage of a request by `policy` (ADR-0011 §10 item 2; Q10: covering "the
/// whole request" includes lock behaviour). Pure.
///
/// * `covered` is `requested ∩ policy.scope`; `environments` is
///   `requested_environments ∩ policy.environments`.
/// * `uncovered` is the rest; `background_work = true` is covered only when the policy's
///   recorded lock behaviour is `continue`, so a `revoke_on_lock` policy never yields
///   `continue` coverage.
/// * `lock_behavior` is the policy's recorded lock behaviour, whatever the request asked.
#[must_use]
pub fn coverage(
    policy: &StandingPolicy,
    requested: &Scope,
    requested_environments: &BTreeSet<EnvironmentId>,
    background_work: bool,
) -> Coverage {
    let asked = ScopeDelta {
        pairs: requested.pairs.clone(),
        capabilities: requested.capabilities.clone(),
        environments: requested_environments.clone(),
        background_work,
    };
    Coverage {
        covered: requested.intersect(&policy.scope),
        environments: requested_environments
            .intersection(&policy.environments)
            .cloned()
            .collect(),
        uncovered: asked.beyond(policy),
        lock_behavior: policy.lock_behavior,
    }
}

/// ⟨M05⟩ The coalescing key of a scope delta (ADR-0011 §4.2): lowercase-hex SHA-256 of a
/// canonical encoding of {policy ID, policy revision, environment, canonical delta (added
/// pairs, capabilities, environments, lock behaviour)}. Sets are ordered (`BTreeSet`) and
/// the field order is fixed, so equal inputs give equal keys and any change of policy,
/// revision, environment or delta gives another key. Pure.
#[must_use]
pub fn coalescing_key(
    policy: &PolicyId,
    revision: PolicyRevision,
    environment: &EnvironmentId,
    delta: &ScopeDelta,
) -> String {
    use sha2::Digest as _;
    #[derive(Serialize)]
    struct Canonical<'a> {
        v: &'static str,
        policy: &'a PolicyId,
        revision: u64,
        environment: &'a EnvironmentId,
        pairs: &'a BTreeSet<crate::scope::AccessPair>,
        capabilities: &'a BTreeSet<crate::scope::Capability>,
        environments: &'a BTreeSet<EnvironmentId>,
        background_work: bool,
    }
    let bytes = serde_json::to_vec(&Canonical {
        v: "heimdall-coalescing-key/1",
        policy,
        revision: revision.0,
        environment,
        pairs: &delta.pairs,
        capabilities: &delta.capabilities,
        environments: &delta.environments,
        background_work: delta.background_work,
    })
    .unwrap_or_default();
    let digest = sha2::Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl StandingPolicy {
    /// Whether automatic activation is blocked at `now` by pause or cutoff. Pure.
    #[must_use]
    pub fn blocks_activation_at(&self, now: Timestamp) -> Option<ActivationBlock> {
        if let PauseState::Paused { since } = self.pause {
            return Some(ActivationBlock::Paused { since });
        }
        if let Some(cutoff) = self.cutoff_at
            && now >= cutoff
        {
            return Some(ActivationBlock::Cutoff { at: cutoff });
        }
        None
    }
}

/// Why a policy refuses activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationBlock {
    /// Paused.
    Paused {
        /// Since.
        since: Timestamp,
    },
    /// Cutoff passed.
    Cutoff {
        /// At.
        at: Timestamp,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn m02_policy_record_reads_defaults_and_reencodes_unchanged() {
        let old = serde_json::json!({
            "id": "default", "revision": 1, "profile": "personal", "workspace": null,
            "scope": {"pairs": [], "capabilities": []}, "environments": [],
            "max_window": {"secs": 43200, "nanos": 0}, "pause": {"state": "active"},
            "cutoff_at": null, "source": {"kind": "setup_default"}
        });
        let p: StandingPolicy = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(p.lock_behavior, LockBehavior::Continue);
        assert!(p.connection.is_default());
        // ⟨M05⟩ `default` reads `false` and is omitted: the record is byte-identical.
        assert!(!p.default);
        assert_eq!(serde_json::to_value(&p).unwrap(), old);
        // And byte-identical as the store writes it (field order of the type).
        let stored = concat!(
            r#"{"id":"default","revision":1,"profile":"personal","workspace":null,"#,
            r#""scope":{"pairs":[],"capabilities":[]},"environments":[],"#,
            r#""max_window":{"secs":43200,"nanos":0},"pause":{"state":"active"},"#,
            r#""cutoff_at":null,"source":{"kind":"setup_default"}}"#
        );
        let decoded: StandingPolicy = serde_json::from_str(stored).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), stored);
        let mut marked = p;
        marked.default = true;
        let v = serde_json::to_value(&marked).unwrap();
        assert_eq!(v["default"], true);
        assert_eq!(serde_json::from_value::<StandingPolicy>(v).unwrap(), marked);
    }

    /// ⟨M05⟩ The window parser's bounds (P04) and the coalescing key's sensitivity to each
    /// of its inputs (ADR-0011 §4.2).
    #[test]
    fn m05_window_bounds_and_coalescing_key_inputs() {
        let max = DEFAULT_MAX_WINDOW;
        assert_eq!(parse_max_window("12h", max), Ok(max));
        assert_eq!(parse_max_window("PT12H", max), Ok(max));
        assert_eq!(
            parse_max_window("30m", max),
            Ok(Duration::from_secs(30 * 60))
        );
        assert_eq!(parse_max_window("0s", max), Err(WindowError::NotPositive));
        assert_eq!(parse_max_window("-1h", max), Err(WindowError::NotPositive));
        assert_eq!(
            parse_max_window("13h", max),
            Err(WindowError::ExceedsMaximum)
        );
        assert_eq!(
            parse_max_window("1 month", max),
            Err(WindowError::Malformed)
        );
        assert_eq!(
            parse_max_window(&"1".repeat(200), max),
            Err(WindowError::Malformed)
        );
        let pol = PolicyId::parse("pol").unwrap();
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let pair = |d: &str| crate::scope::AccessPair {
            destination: heimdall_contract::ids::DestinationId::parse(d).unwrap(),
            account: heimdall_contract::ids::AccountName::parse("u").unwrap(),
        };
        let delta = ScopeDelta {
            pairs: [pair("h1")].into_iter().collect(),
            ..ScopeDelta::default()
        };
        let k = coalescing_key(&pol, PolicyRevision(1), &env, &delta);
        assert_eq!(k.len(), 64);
        assert!(
            k.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(
            k,
            coalescing_key(&pol, PolicyRevision(1), &env, &delta.clone())
        );
        let broader = ScopeDelta {
            pairs: [pair("h1"), pair("h2")].into_iter().collect(),
            ..ScopeDelta::default()
        };
        let locked = ScopeDelta {
            background_work: true,
            ..delta.clone()
        };
        for other in [
            coalescing_key(
                &PolicyId::parse("pol2").unwrap(),
                PolicyRevision(1),
                &env,
                &delta,
            ),
            coalescing_key(&pol, PolicyRevision(2), &env, &delta),
            coalescing_key(
                &pol,
                PolicyRevision(1),
                &EnvironmentId::from_random_bytes([2; 16]),
                &delta,
            ),
            coalescing_key(&pol, PolicyRevision(1), &env, &broader),
            coalescing_key(&pol, PolicyRevision(1), &env, &locked),
        ] {
            assert_ne!(k, other);
        }
    }

    #[test]
    fn strictest_is_fail_closed() {
        use ExistingConnectionsMode as E;
        use MultiplexingMode as M;
        assert_eq!(
            strictest_lock_behavior(LockBehavior::Continue, LockBehavior::RevokeOnLock),
            LockBehavior::RevokeOnLock
        );
        let wide = ConnectionPolicy {
            existing: E::Graceful,
            multiplexing: M::OwnedMasters,
        };
        let narrow = ConnectionPolicy {
            existing: E::Strict,
            multiplexing: M::Disabled,
        };
        assert_eq!(strictest_connection_policy(wide, narrow), narrow);
        assert_eq!(strictest_connection_policy(wide, wide), wide);
    }
}
