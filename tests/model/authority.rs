//! M01-U2 (M01-T01): authority resolution model and property tests.
//!
//! Properties (plan §6.3 #1, #2, #3 part; m01-plan.md §1 U2), each over
//! generated inputs with at least 256 cases:
//!
//! * effective scope ⊆ policy ∩ environment ∩ requested ∩ parent ∩ destination
//!   capability (and the pinned profile snapshot);
//! * effective deadline ≤ min(request, policy window, parent, cutoff);
//! * a paused or cut-off policy never yields `Allowed` (or an approval path);
//!   request and work IDs are not inputs of resolution, so no identifier change can
//!   reach a different outcome;
//! * `ApprovalRequired.delta.added_scope` is exactly `requested − covered`;
//! * resolution is pure: same input ⇒ same output across 1000 shuffled
//!   constructions of the same sets and maps.
//!
//! Model rows (spec §17 A05, model variant) are table tests below.
//!
//! Reproduce a failure with `PROPTEST_RNG_SEED=<seed>` or the committed
//! regression file next to this source. Every decision a test produces is
//! serialized and scanned with `heimdall_testkit::assert_no_canary`; fixtures
//! carry synthetic `HEIMDALL_CANARY_*` labels to prove nothing is echoed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use heimdall_contract::ids::{AccountName, DestinationId, DeviceId, EnvironmentId, GrantId};
use heimdall_contract::ids::{PolicyId, ProfileId};
use heimdall_contract::request::{
    Capability, DeadlineIntent, DestinationScopeEnforcement, RequiredCapabilities,
};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::authority::{
    ActivationBlockRepr, AuthorityDecision, AuthorityInput, Denial, EffectiveAuthority,
    resolve_authority,
};
use heimdall_domain::environment::{
    DestinationCapability, EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::policy::{
    AuthorityGeneration, PauseState, PolicyRevision, PolicySource, StandingPolicy,
};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileSnapshot;
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_domain::time::{Deadline, is_expired};
use heimdall_testkit::{assert_no_canary, strategies};
use jiff::SignedDuration;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

// ---------------------------------------------------------------------------
// Fixture model
// ---------------------------------------------------------------------------

const NOW: &str = "2026-10-01T12:00:00Z";
const CANARY_ENV_LABEL: &str = "HEIMDALL_CANARY_U2_ENV_LABEL";
const CANARY_MECHANISM: &str = "HEIMDALL_CANARY_U2_MECHANISM";
const ENFORCEMENT_LEVELS: [DestinationScopeEnforcement; 6] = [
    DestinationScopeEnforcement::Unknown,
    DestinationScopeEnforcement::UnenforcedIntent,
    DestinationScopeEnforcement::ClientRouting,
    DestinationScopeEnforcement::AuthenticatedAgentRestriction,
    DestinationScopeEnforcement::VerifiedServerPrincipals,
    DestinationScopeEnforcement::IsolatedExecutionBoundary,
];
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

fn now() -> Timestamp {
    NOW.parse().unwrap()
}

fn at(offset_secs: i64) -> Timestamp {
    now()
        .checked_add(SignedDuration::from_secs(offset_secs))
        .unwrap()
}

fn env_id(n: u8) -> EnvironmentId {
    EnvironmentId::parse(&format!("env_{n:032x}")).unwrap()
}

fn dest(n: u8) -> DestinationId {
    DestinationId::parse(&format!("h{n}")).unwrap()
}

fn pair(d: u8, a: u8) -> AccessPair {
    AccessPair {
        destination: dest(d),
        account: AccountName::parse(&format!("u{a}")).unwrap(),
    }
}

fn scope(pairs: &[(u8, u8)], caps: &[Capability]) -> Scope {
    Scope {
        pairs: pairs.iter().map(|&(d, a)| pair(d, a)).collect(),
        capabilities: caps.iter().copied().collect(),
    }
}

fn union(a: &Scope, b: &Scope) -> Scope {
    Scope {
        pairs: a.pairs.union(&b.pairs).cloned().collect(),
        capabilities: a.capabilities.union(&b.capabilities).copied().collect(),
    }
}

fn void(s: &Scope) -> bool {
    s.pairs.is_empty() && s.capabilities.is_empty()
}

fn deadline_at(effective: Timestamp) -> Deadline {
    Deadline {
        intent: DeadlineIntent::Absolute(effective.to_string()),
        resolved_at: now(),
        effective,
    }
}

fn capability_record(
    d: &DestinationId,
    level: DestinationScopeEnforcement,
) -> DestinationCapability {
    DestinationCapability {
        destination: d.clone(),
        enrollment_level: 2,
        scope_enforcement: level,
        mechanisms: [CANARY_MECHANISM.to_owned()].into_iter().collect(),
    }
}

/// Owned inputs; [`Fixture::input`] borrows them as an [`AuthorityInput`].
#[derive(Debug, Clone)]
struct Fixture {
    caller: CallerContext,
    policy: Option<StandingPolicy>,
    generation: AuthorityGeneration,
    environment: EnvironmentRecord,
    profile: ProfileSnapshot,
    requested: Scope,
    parent: Option<GrantSnapshot>,
    destinations: BTreeMap<DestinationId, DestinationCapability>,
    required: RequiredCapabilities,
    requested_deadline: Deadline,
    now: Timestamp,
}

impl Fixture {
    fn input(&self) -> AuthorityInput<'_> {
        AuthorityInput {
            caller: &self.caller,
            policy: self.policy.as_ref(),
            generation: self.generation,
            environment: &self.environment,
            profile: &self.profile,
            requested: &self.requested,
            parent: self.parent.as_ref(),
            destinations: &self.destinations,
            required: &self.required,
            requested_deadline: &self.requested_deadline,
            now: self.now,
        }
    }

    fn resolve(&self) -> AuthorityDecision {
        let decision = resolve_authority(&self.input());
        scan(&decision);
        decision
    }

    /// A covering owner request: policy, profile and destinations all cover
    /// `requested`; no parent; 12 h window; request deadline 2 h out.
    fn covered(requested: Scope) -> Self {
        let profile_id = ProfileId::parse("homelab-dev").unwrap();
        let environment = EnvironmentRecord {
            id: env_id(1),
            device: DeviceId::parse(&format!("dev_{:032x}", 1)).unwrap(),
            kind: EnvironmentKind::NativeSession,
            label: Some(CANARY_ENV_LABEL.to_owned()),
            permissions: EnvironmentPermissions {
                automatic_activation: true,
                managed_signing: true,
                issuer_access: true,
            },
        };
        let destinations = requested
            .pairs
            .iter()
            .map(|p| {
                (
                    p.destination.clone(),
                    capability_record(
                        &p.destination,
                        DestinationScopeEnforcement::VerifiedServerPrincipals,
                    ),
                )
            })
            .collect();
        Self {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            policy: Some(StandingPolicy {
                id: PolicyId::parse("homelab-auto").unwrap(),
                revision: PolicyRevision(3),
                profile: profile_id.clone(),
                workspace: None,
                scope: requested.clone(),
                environments: [env_id(1)].into_iter().collect(),
                max_window: Duration::from_secs(12 * 3600),
                pause: PauseState::Active,
                cutoff_at: None,
                source: PolicySource::SetupDefault,
            }),
            generation: AuthorityGeneration(7),
            environment,
            profile: ProfileSnapshot {
                id: profile_id,
                revision: 3,
                scope: requested.clone(),
            },
            requested,
            parent: None,
            destinations,
            required: RequiredCapabilities::default(),
            requested_deadline: deadline_at(at(2 * 3600)),
            now: now(),
        }
    }

    fn policy_mut(&mut self) -> &mut StandingPolicy {
        self.policy.as_mut().unwrap()
    }

    fn with_parent(mut self, parent_scope: Scope, parent_deadline: Timestamp) -> Self {
        self.parent = Some(GrantSnapshot {
            id: GrantId::parse(&format!("grant_{:032x}", 9)).unwrap(),
            environment: env_id(1),
            scope: parent_scope,
            starts_at: at(-3600),
            deadline: deadline_at(parent_deadline),
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(3),
            },
            generation: self.generation,
            state: GrantState::Active,
            enforcement: EnforcementEvidence::unknown(),
        });
        self
    }
}

/// Canary scan over the serialized and debug forms of a decision.
fn scan(decision: &AuthorityDecision) {
    assert_no_canary(&serde_json::to_string(decision).unwrap());
    assert_no_canary(&format!("{decision:?}"));
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PolicyParams {
    scope: Scope,
    environments: BTreeSet<u8>,
    window_secs: u64,
    paused: bool,
    cutoff: Option<i64>,
    profile_matches: bool,
    revision: u64,
}

#[derive(Debug, Clone)]
struct ParentParams {
    scope: Scope,
    deadline: i64,
    state: GrantState,
    generation_skew: i8,
}

fn policy_params() -> impl Strategy<Value = PolicyParams> {
    (
        strategies::scope(),
        prop::collection::btree_set(0u8..3, 0..3),
        0u64..=2 * 86_400,
        prop::bool::weighted(0.15),
        prop::option::weighted(0.3, -7_200i64..=172_800),
        prop::bool::weighted(0.9),
        0u64..5,
    )
        .prop_map(
            |(scope, environments, window_secs, paused, cutoff, profile_matches, revision)| {
                PolicyParams {
                    scope,
                    environments,
                    window_secs,
                    paused,
                    cutoff,
                    profile_matches,
                    revision,
                }
            },
        )
}

fn parent_params() -> impl Strategy<Value = ParentParams> {
    (
        strategies::scope(),
        -3_600i64..=172_800,
        prop_oneof![
            6 => Just(GrantState::Active),
            2 => Just(GrantState::Degraded),
            4 => prop::sample::select(GRANT_STATES.to_vec()),
        ],
        prop_oneof![8 => Just(0i8), 1 => Just(-1i8), 1 => Just(1i8)],
    )
        .prop_map(|(scope, deadline, state, generation_skew)| ParentParams {
            scope,
            deadline,
            state,
            generation_skew,
        })
}

fn destinations_strategy() -> impl Strategy<Value = BTreeMap<DestinationId, DestinationCapability>>
{
    prop::collection::vec(
        (
            prop::bool::weighted(0.75),
            prop::sample::select(ENFORCEMENT_LEVELS.to_vec()),
            prop::bool::weighted(0.05),
        ),
        6,
    )
    .prop_map(|entries| {
        entries
            .into_iter()
            .enumerate()
            .filter(|(_, (present, _, _))| *present)
            .map(|(i, (_, level, mislabeled))| {
                let key = dest(u8::try_from(i).unwrap());
                // A record whose own destination differs from its key must not
                // count as capability for the key (fail closed).
                let recorded = if mislabeled { dest(9) } else { key.clone() };
                (key, capability_record(&recorded, level))
            })
            .collect()
    })
}

fn required_strategy() -> impl Strategy<Value = RequiredCapabilities> {
    (
        prop::collection::btree_set(strategies::capability(), 0..2),
        prop::option::weighted(0.3, prop::sample::select(ENFORCEMENT_LEVELS.to_vec())),
        prop::option::weighted(0.2, -3_600i64..=172_800),
    )
        .prop_map(|(capabilities, min, offline)| RequiredCapabilities {
            capabilities,
            destination_scope_at_least: min,
            offline_until: offline.map(at),
        })
}

prop_compose! {
    fn fixture()(
        owner in prop::bool::weighted(0.85),
        policy in prop::option::weighted(0.9, policy_params()),
        generation in 1u64..10,
        environment in 0u8..3,
        automatic_activation in prop::bool::weighted(0.85),
        profile_scope in strategies::scope(),
        requested in strategies::scope(),
        parent in prop::option::weighted(0.4, parent_params()),
        destinations in destinations_strategy(),
        required in required_strategy(),
        request_deadline in -3_600i64..=172_800,
        boost in prop::bool::weighted(0.5),
    ) -> Fixture {
        let profile_id = ProfileId::parse("homelab-dev").unwrap();
        let mut destinations = destinations;
        let mut profile_scope = profile_scope;
        let mut policy = policy;
        let mut parent = parent;
        if boost {
            // Make Allowed reachable: cover the request everywhere.
            profile_scope = union(&profile_scope, &requested);
            if let Some(p) = policy.as_mut() {
                p.scope = union(&p.scope, &requested);
                p.environments.insert(environment);
            }
            if let Some(p) = parent.as_mut() {
                p.scope = union(&p.scope, &requested);
            }
            for pr in &requested.pairs {
                destinations.entry(pr.destination.clone()).or_insert_with(|| {
                    capability_record(&pr.destination, DestinationScopeEnforcement::ClientRouting)
                });
            }
        }
        let policy = policy.map(|p| StandingPolicy {
            id: PolicyId::parse("auto").unwrap(),
            revision: PolicyRevision(p.revision),
            profile: if p.profile_matches {
                profile_id.clone()
            } else {
                ProfileId::parse("other-profile").unwrap()
            },
            workspace: None,
            scope: p.scope,
            environments: p.environments.into_iter().map(env_id).collect(),
            max_window: Duration::from_secs(p.window_secs),
            pause: if p.paused {
                PauseState::Paused { since: at(-60) }
            } else {
                PauseState::Active
            },
            cutoff_at: p.cutoff.map(at),
            source: PolicySource::SetupDefault,
        });
        let generation = AuthorityGeneration(generation);
        let parent = parent.map(|p| GrantSnapshot {
            id: GrantId::parse(&format!("grant_{:032x}", 1)).unwrap(),
            environment: env_id(environment),
            scope: p.scope,
            starts_at: at(-7_200),
            deadline: deadline_at(at(p.deadline)),
            parent: None,
            source: AuthorizationSource::StandingPolicy { revision: PolicyRevision(0) },
            generation: AuthorityGeneration(
                generation.0.saturating_add_signed(i64::from(p.generation_skew)),
            ),
            state: p.state,
            enforcement: EnforcementEvidence::unknown(),
        });
        Fixture {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: if owner { ClientRole::Owner } else { ClientRole::LimitedConsumer },
            },
            policy,
            generation,
            environment: EnvironmentRecord {
                id: env_id(environment),
                device: DeviceId::parse(&format!("dev_{:032x}", 1)).unwrap(),
                kind: EnvironmentKind::NativeSession,
                label: Some(CANARY_ENV_LABEL.to_owned()),
                permissions: EnvironmentPermissions {
                    automatic_activation,
                    managed_signing: true,
                    issuer_access: false,
                },
            },
            profile: ProfileSnapshot { id: profile_id, revision: 3, scope: profile_scope },
            requested,
            parent,
            destinations,
            required,
            requested_deadline: deadline_at(at(request_deadline)),
            now: now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Independent oracle (written from spec §6.2, not from the implementation)
// ---------------------------------------------------------------------------

fn known(f: &Fixture, d: &DestinationId) -> Option<DestinationScopeEnforcement> {
    f.destinations
        .get(d)
        .filter(|c| &c.destination == d)
        .map(|c| c.scope_enforcement)
}

fn policy_applies(f: &Fixture) -> bool {
    f.policy.as_ref().is_some_and(|p| p.profile == f.profile.id)
}

fn environment_permitted(f: &Fixture) -> bool {
    policy_applies(f)
        && f.policy
            .as_ref()
            .is_some_and(|p| p.environments.contains(&f.environment.id))
        && f.environment.permissions.automatic_activation
}

/// policy ∩ environment ∩ requested ∩ parent ∩ destination capability ∩ profile.
fn upper_bound(f: &Fixture) -> Scope {
    if !environment_permitted(f) {
        return Scope::empty();
    }
    let policy = f.policy.as_ref().unwrap();
    let pairs: BTreeSet<AccessPair> = f
        .requested
        .pairs
        .iter()
        .filter(|p| policy.scope.pairs.contains(p))
        .filter(|p| f.profile.scope.pairs.contains(p))
        .filter(|p| f.parent.as_ref().is_none_or(|g| g.scope.pairs.contains(p)))
        .filter(|p| known(f, &p.destination).is_some())
        .cloned()
        .collect();
    let caps: BTreeSet<Capability> = f
        .requested
        .capabilities
        .iter()
        .filter(|c| policy.scope.capabilities.contains(c))
        .filter(|c| f.profile.scope.capabilities.contains(c))
        .filter(|c| {
            f.parent
                .as_ref()
                .is_none_or(|g| g.scope.capabilities.contains(c))
        })
        .copied()
        .collect();
    Scope {
        pairs,
        capabilities: caps,
    }
}

/// min(request, now + policy window, parent, cutoff).
fn deadline_bound(f: &Fixture) -> Timestamp {
    let mut bound = f.requested_deadline.effective;
    if let Some(p) = &f.policy {
        let window = SignedDuration::try_from(p.max_window).unwrap();
        bound = bound.min(f.now.checked_add(window).unwrap());
        if let Some(c) = p.cutoff_at {
            bound = bound.min(c);
        }
    }
    if let Some(g) = &f.parent {
        bound = bound.min(g.deadline.effective);
    }
    bound
}

fn blocked(f: &Fixture) -> bool {
    f.policy.as_ref().is_some_and(|p| {
        matches!(p.pause, PauseState::Paused { .. }) || p.cutoff_at.is_some_and(|c| f.now >= c)
    })
}

fn authority_of(d: &AuthorityDecision) -> Option<&EffectiveAuthority> {
    match d {
        AuthorityDecision::Allowed(a) => Some(a),
        AuthorityDecision::ApprovalRequired { covered, .. } => covered.as_ref(),
        AuthorityDecision::Denied(_) => None,
    }
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

/// Deterministic Fisher–Yates driven by a generated seed (xorshift64*).
fn shuffled<T: Clone>(items: impl IntoIterator<Item = T>, seed: &mut u64) -> Vec<T> {
    let mut v: Vec<T> = items.into_iter().collect();
    for i in (1..v.len()).rev() {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        let j = usize::try_from(*seed % (u64::try_from(i).unwrap() + 1)).unwrap();
        v.swap(i, j);
    }
    v
}

fn rebuild_scope(s: &Scope, seed: &mut u64) -> Scope {
    let mut out = Scope::empty();
    for p in shuffled(s.pairs.iter().cloned(), seed) {
        out.pairs.insert(p);
    }
    for c in shuffled(s.capabilities.iter().copied(), seed) {
        out.capabilities.insert(c);
    }
    out
}

/// The same fixture with every set and map rebuilt from a shuffled insertion order.
fn reshuffle(f: &Fixture, mut seed: u64) -> Fixture {
    seed |= 1;
    let mut g = f.clone();
    g.requested = rebuild_scope(&f.requested, &mut seed);
    g.profile.scope = rebuild_scope(&f.profile.scope, &mut seed);
    if let (Some(gp), Some(fp)) = (g.policy.as_mut(), f.policy.as_ref()) {
        gp.scope = rebuild_scope(&fp.scope, &mut seed);
        gp.environments = shuffled(fp.environments.iter().cloned(), &mut seed)
            .into_iter()
            .collect();
    }
    if let (Some(gp), Some(fp)) = (g.parent.as_mut(), f.parent.as_ref()) {
        gp.scope = rebuild_scope(&fp.scope, &mut seed);
    }
    g.destinations = shuffled(f.destinations.clone(), &mut seed)
        .into_iter()
        .collect();
    g.required.capabilities = shuffled(f.required.capabilities.iter().copied(), &mut seed)
        .into_iter()
        .collect();
    g
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(config(512))]

    /// plan §6.3 #1: effective scope never exceeds policy, environment, requested
    /// snapshot, parent or destination capability.
    #[test]
    fn effective_scope_within_every_bound(f in fixture()) {
        let d = f.resolve();
        if let Some(a) = authority_of(&d) {
            let bound = upper_bound(&f);
            prop_assert!(a.scope.is_subset_of(&bound), "scope {:?} exceeds {:?}", a.scope, bound);
            prop_assert!(a.scope.is_subset_of(&f.requested));
            prop_assert!(policy_applies(&f), "authority without an applicable policy");
            prop_assert!(environment_permitted(&f), "authority in a non-permitted environment");
            prop_assert_eq!(a.generation, f.generation);
            prop_assert_eq!(a.policy_revision, f.policy.as_ref().map(|p| p.revision));
        }
        if matches!(d, AuthorityDecision::Allowed(_)) {
            prop_assert!(!blocked(&f));
        }
    }

    /// plan §6.3 #2 (deadline part): effective deadline ≤ min(request, policy
    /// window, parent, cutoff); it equals that minimum (narrowest bound wins).
    #[test]
    fn effective_deadline_is_narrowest_bound(f in fixture()) {
        let d = f.resolve();
        if let Some(a) = authority_of(&d) {
            let bound = deadline_bound(&f);
            prop_assert!(a.deadline <= bound);
            prop_assert!(a.deadline <= f.requested_deadline.effective);
            prop_assert_eq!(a.deadline, bound);
        }
    }

    /// plan §6.3 #3 (policy part): pause or reached cutoff is always
    /// `Denied(Blocked)`, never `Allowed` or an approval path, for every other
    /// generated input, including fully covering ones.
    #[test]
    fn pause_and_cutoff_always_block(mut f in fixture(), paused in any::<bool>(), cutoff_back in 0i64..86_400) {
        if f.policy.is_none() {
            let mut g = Fixture::covered(f.requested.clone());
            g.requested_deadline = f.requested_deadline.clone();
            f.policy = g.policy;
        }
        let p = f.policy_mut();
        if paused {
            p.pause = PauseState::Paused { since: at(-cutoff_back) };
        } else {
            p.pause = PauseState::Active;
            p.cutoff_at = Some(at(-cutoff_back));
        }
        let d = f.resolve();
        let expected = if paused {
            ActivationBlockRepr::Paused { since: at(-cutoff_back) }
        } else {
            ActivationBlockRepr::Cutoff { at: at(-cutoff_back) }
        };
        prop_assert_eq!(d, AuthorityDecision::Denied(Denial::Blocked(expected)));
    }

    /// spec §5.3 / m01-plan U2: `delta.added_scope` is exactly `requested −
    /// covered`, and covered ∪ delta reconstructs the request.
    #[test]
    fn approval_delta_is_requested_minus_covered(f in fixture()) {
        let d = f.resolve();
        if let AuthorityDecision::ApprovalRequired { covered, delta } = &d {
            let covered_scope = covered.as_ref().map_or_else(Scope::empty, |c| c.scope.clone());
            prop_assert_eq!(&delta.added_scope, &f.requested.difference(&covered_scope));
            prop_assert_eq!(&union(&covered_scope, &delta.added_scope), &f.requested);
            prop_assert!(
                !void(&delta.added_scope) || delta.extra_window.is_some() || delta.environment_not_covered,
                "approval with an empty delta"
            );
            prop_assert_eq!(delta.environment_not_covered, !environment_permitted(&f));
            if let Some(c) = covered {
                prop_assert!(!void(&c.scope));
            }
            prop_assert_eq!(f.caller.role, ClientRole::Owner);
        }
    }

    /// Delegation broader or longer than its parent is denied, never escalated;
    /// an unusable parent never yields authority (spec §6.7, primitives §4.4).
    #[test]
    fn delegation_never_exceeds_or_outlives_parent(f in fixture()) {
        let d = f.resolve();
        if let Some(parent) = &f.parent {
            let excess = f.requested.difference(&parent.scope);
            let later = f.requested_deadline.effective > parent.deadline.effective;
            let usable = matches!(parent.state, GrantState::Active | GrantState::Degraded)
                && parent.generation == f.generation
                && !is_expired(f.now, parent.deadline.effective);
            if !usable || !void(&excess) || later {
                prop_assert!(matches!(d, AuthorityDecision::Denied(_)), "got {:?}", d);
            }
            if let AuthorityDecision::Denied(Denial::ExceedsParent { excess_scope, later_than_parent }) = &d {
                prop_assert_eq!(excess_scope, &excess);
                prop_assert_eq!(*later_than_parent, later);
            }
            if let Some(a) = authority_of(&d) {
                prop_assert!(parent.permits_child(&a.scope, a.deadline));
            }
        } else {
            let is_parent_denial = matches!(
                d,
                AuthorityDecision::Denied(Denial::ExceedsParent { .. } | Denial::ParentNotUsable)
            );
            prop_assert!(!is_parent_denial);
        }
    }

    /// Caller minimums: `Allowed` always satisfies them; unmet or unknown
    /// minimums are `CapabilityUnavailable`, never silently weaker access.
    #[test]
    fn allowed_meets_required_minimums(f in fixture()) {
        let d = f.resolve();
        if let AuthorityDecision::Allowed(a) = &d {
            prop_assert!(f.required.capabilities.is_subset(&a.scope.capabilities));
            if let Some(min) = f.required.destination_scope_at_least {
                for p in &a.scope.pairs {
                    prop_assert!(known(&f, &p.destination).is_some_and(|l| l >= min));
                }
            }
            if let Some(t) = f.required.offline_until {
                prop_assert!(t <= a.deadline);
            }
        }
        let unknown_or_unmet = f.required.destination_scope_at_least.is_some_and(|min| {
            f.requested.pairs.iter().any(|p| known(&f, &p.destination).is_none_or(|l| l < min))
        }) || !f.required.capabilities.is_subset(&f.requested.capabilities);
        if unknown_or_unmet {
            prop_assert!(matches!(d, AuthorityDecision::Denied(_)), "got {:?}", d);
        }
    }

    /// A limited consumer may request allowed work only.
    #[test]
    fn limited_consumer_never_escalates(mut f in fixture()) {
        f.caller.role = ClientRole::LimitedConsumer;
        let d = f.resolve();
        let is_approval = matches!(d, AuthorityDecision::ApprovalRequired { .. });
        prop_assert!(!is_approval);
        let mut owner = f.clone();
        owner.caller.role = ClientRole::Owner;
        match (owner.resolve(), &d) {
            (AuthorityDecision::ApprovalRequired { .. }, got) => {
                prop_assert_eq!(got, &AuthorityDecision::Denied(Denial::RoleForbidden));
            }
            (other, got) => prop_assert_eq!(&other, got),
        }
    }

    /// Narrowing the request never escalates: if `R` is allowed, every
    /// `R' ⊆ R` (still naming the required capabilities) is allowed as `R'`.
    #[test]
    fn narrowing_an_allowed_request_stays_allowed(f in fixture(), keep in prop::collection::vec(any::<bool>(), 16)) {
        if let AuthorityDecision::Allowed(a) = f.resolve() {
            let mut g = f.clone();
            let mut k = keep.iter().cycle();
            g.requested.pairs.retain(|_| *k.next().unwrap());
            g.requested.capabilities.retain(|c| *k.next().unwrap() || f.required.capabilities.contains(c));
            match g.resolve() {
                AuthorityDecision::Allowed(b) => {
                    prop_assert_eq!(&b.scope, &g.requested);
                    prop_assert_eq!(b.deadline, a.deadline);
                }
                other => prop_assert!(false, "narrowed request not allowed: {:?}", other),
            }
        }
    }
}

proptest! {
    #![proptest_config(config(1000))]

    /// Resolution is a pure function: same input ⇒ same output, including when
    /// every set and map is rebuilt from a shuffled insertion order (1000 cases).
    #[test]
    fn resolution_is_pure_under_shuffles(f in fixture(), seed in any::<u64>()) {
        let first = f.resolve();
        prop_assert_eq!(&f.resolve(), &first);
        let g = reshuffle(&f, seed);
        prop_assert_eq!(&g.resolve(), &first);
    }
}

// ---------------------------------------------------------------------------
// Model rows (A05 model variant) and precedence tables
// ---------------------------------------------------------------------------

fn web() -> Scope {
    scope(&[(1, 0), (2, 0)], &[Capability::SshAuthentication])
}

#[test]
fn a05_fresh_work_after_cutoff_is_denied() {
    // A standing policy permits fresh bounded work; the owner set a hard stop.
    let cutoff = at(-1);
    let mut f = Fixture::covered(web());
    f.policy_mut().cutoff_at = Some(cutoff);
    let denied =
        AuthorityDecision::Denied(Denial::Blocked(ActivationBlockRepr::Cutoff { at: cutoff }));

    // Fresh work under every variation that is an input to resolution: a new
    // generation (restarted agent), new deadline intents and a narrower or empty
    // request. Request and work IDs are not
    // inputs at all, so changing them cannot change this outcome.
    for (generation, deadline_offset, requested) in [
        (7, 3_600, web()),
        (8, 60, web()),
        (
            9,
            12 * 3_600,
            scope(&[(1, 0)], &[Capability::SshAuthentication]),
        ),
        (1, 1, Scope::empty()),
    ] {
        let mut g = f.clone();
        g.generation = AuthorityGeneration(generation);
        g.requested_deadline = deadline_at(at(deadline_offset));
        g.requested = requested;
        assert_eq!(g.resolve(), denied);
    }

    // The cutoff instant itself is inclusive.
    f.policy_mut().cutoff_at = Some(now());
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::Blocked(ActivationBlockRepr::Cutoff { at: now() }))
    );

    // Before the cutoff, new work is allowed but never outlives it.
    f.policy_mut().cutoff_at = Some(at(1_800));
    match f.resolve() {
        AuthorityDecision::Allowed(a) => assert_eq!(a.deadline, at(1_800)),
        other => panic!("expected allowed before cutoff, got {other:?}"),
    }
}

#[test]
fn a05_pause_blocks_new_activation_even_when_fully_covered() {
    let mut f = Fixture::covered(web());
    f.policy_mut().pause = PauseState::Paused { since: at(-600) };
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::Blocked(ActivationBlockRepr::Paused {
            since: at(-600)
        }))
    );
    // A delegation under the paused policy is blocked as well.
    let g = f.with_parent(web(), at(6 * 3_600));
    assert!(matches!(
        g.resolve(),
        AuthorityDecision::Denied(Denial::Blocked(_))
    ));
}

#[test]
fn a05_expired_binding_is_not_extended() {
    // Re-resolving a binding whose persisted deadline has passed keeps that past
    // instant; it never receives a fresh window from `now`.
    let persisted = at(-60);
    for now_offset in [0, 3_600, 86_400] {
        let mut f = Fixture::covered(web());
        f.now = at(now_offset);
        f.requested_deadline = Deadline {
            intent: DeadlineIntent::Duration("PT2H".to_owned()),
            resolved_at: at(-2 * 3_600 - 60),
            effective: persisted,
        };
        let d = f.resolve();
        let a = authority_of(&d).expect("covered request keeps its authority record");
        assert_eq!(a.deadline, persisted);
        assert!(is_expired(f.now, a.deadline));
    }
}

#[test]
fn a05_distinct_new_work_obeys_standing_policy() {
    let f = Fixture::covered(web());
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Allowed(EffectiveAuthority {
            scope: web(),
            deadline: at(2 * 3_600),
            policy_revision: Some(PolicyRevision(3)),
            generation: AuthorityGeneration(7),
        })
    );
    // A request running past the 12 h policy window needs a decision for the
    // extra time only; the covered part is clamped to the window.
    let mut long = f.clone();
    long.requested_deadline = deadline_at(at(14 * 3_600));
    match long.resolve() {
        AuthorityDecision::ApprovalRequired { covered, delta } => {
            assert_eq!(delta.extra_window, Some(Duration::from_secs(2 * 3_600)));
            assert!(void(&delta.added_scope));
            assert!(!delta.environment_not_covered);
            assert_eq!(covered.unwrap().deadline, at(12 * 3_600));
        }
        other => panic!("expected approval for extra window, got {other:?}"),
    }
}

#[test]
fn approval_delta_names_only_the_added_authority() {
    // Policy covers h1/h2 for SSH; the request adds h3 and Git signing.
    let mut f = Fixture::covered(web());
    f.requested = scope(
        &[(1, 0), (2, 0), (3, 0)],
        &[Capability::SshAuthentication, Capability::GitSigning],
    );
    f.profile.scope = f.requested.clone();
    f.destinations.insert(
        dest(3),
        capability_record(&dest(3), DestinationScopeEnforcement::ClientRouting),
    );
    match f.resolve() {
        AuthorityDecision::ApprovalRequired { covered, delta } => {
            assert_eq!(covered.unwrap().scope, web());
            assert_eq!(
                delta.added_scope,
                scope(&[(3, 0)], &[Capability::GitSigning])
            );
            assert_eq!(delta.extra_window, None);
            assert!(!delta.environment_not_covered);
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

#[test]
fn environment_and_policy_gaps_require_a_decision() {
    // Environment not in the policy.
    let mut f = Fixture::covered(web());
    f.policy_mut().environments.clear();
    let expect_all = |d: AuthorityDecision| match d {
        AuthorityDecision::ApprovalRequired { covered, delta } => {
            assert_eq!(covered, None);
            assert_eq!(delta.added_scope, web());
            assert!(delta.environment_not_covered);
        }
        other => panic!("expected approval, got {other:?}"),
    };
    expect_all(f.resolve());

    // Environment not enrolled for automatic activation.
    let mut f = Fixture::covered(web());
    f.environment.permissions.automatic_activation = false;
    expect_all(f.resolve());

    // No standing policy at all.
    let mut f = Fixture::covered(web());
    f.policy = None;
    expect_all(f.resolve());

    // A policy for another profile covers nothing, but its pause still blocks.
    let mut f = Fixture::covered(web());
    f.policy_mut().profile = ProfileId::parse("other").unwrap();
    expect_all(f.resolve());
    f.policy_mut().pause = PauseState::Paused { since: at(-1) };
    assert!(matches!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::Blocked(_))
    ));
}

#[test]
fn delegation_table() {
    let parent_deadline = at(6 * 3_600);
    let child = scope(&[(1, 0)], &[Capability::SshAuthentication]);
    let base = {
        let mut f = Fixture::covered(web()).with_parent(web(), parent_deadline);
        f.requested = child.clone();
        f.requested_deadline = deadline_at(at(3_600));
        f
    };

    // Within the parent: allowed, deadline bounded by the request.
    match base.resolve() {
        AuthorityDecision::Allowed(a) => {
            assert_eq!(a.scope, child);
            assert_eq!(a.deadline, at(3_600));
        }
        other => panic!("expected allowed child, got {other:?}"),
    }

    // Longer than the parent: denied, not clamped or escalated.
    let mut f = base.clone();
    f.requested_deadline = deadline_at(at(7 * 3_600));
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::ExceedsParent {
            excess_scope: Scope::empty(),
            later_than_parent: true,
        })
    );

    // Broader than the parent: denied with the excess named.
    let mut f = base.clone();
    f.requested = scope(
        &[(1, 0), (4, 0)],
        &[Capability::SshAuthentication, Capability::AgentForwarding],
    );
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::ExceedsParent {
            excess_scope: scope(&[(4, 0)], &[Capability::AgentForwarding]),
            later_than_parent: false,
        })
    );

    // Unusable parents: every non-usable state, a stale or future generation, and
    // a passed deadline.
    for state in GRANT_STATES {
        let mut f = base.clone();
        f.parent.as_mut().unwrap().state = state;
        let d = f.resolve();
        if matches!(state, GrantState::Active | GrantState::Degraded) {
            assert!(
                matches!(d, AuthorityDecision::Allowed(_)),
                "{state:?}: {d:?}"
            );
        } else {
            assert_eq!(
                d,
                AuthorityDecision::Denied(Denial::ParentNotUsable),
                "{state:?}"
            );
        }
    }
    for generation in [6, 8] {
        let mut f = base.clone();
        f.parent.as_mut().unwrap().generation = AuthorityGeneration(generation);
        assert_eq!(
            f.resolve(),
            AuthorityDecision::Denied(Denial::ParentNotUsable)
        );
    }
    let mut f = base.clone();
    f.parent.as_mut().unwrap().deadline = deadline_at(now());
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::ParentNotUsable)
    );

    // Within the parent but outside the policy: an owner decision, never more than
    // the parent.
    let mut f = base.clone();
    f.policy_mut().scope = scope(&[(2, 0)], &[Capability::SshAuthentication]);
    match f.resolve() {
        AuthorityDecision::ApprovalRequired { covered, delta } => {
            assert_eq!(
                covered.map(|c| c.scope),
                Some(scope(&[], &[Capability::SshAuthentication]))
            );
            assert_eq!(delta.added_scope, scope(&[(1, 0)], &[]));
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

#[test]
fn capability_minimum_table() {
    let base = Fixture::covered(web());

    // Met.
    let mut f = base.clone();
    f.required.destination_scope_at_least =
        Some(DestinationScopeEnforcement::VerifiedServerPrincipals);
    f.required.capabilities = [Capability::SshAuthentication].into_iter().collect();
    f.required.offline_until = Some(at(2 * 3_600));
    assert!(matches!(f.resolve(), AuthorityDecision::Allowed(_)));

    let unavailable = |f: &Fixture| {
        assert_eq!(
            f.resolve(),
            AuthorityDecision::Denied(Denial::CapabilityUnavailable {
                required: f.required.clone()
            })
        );
    };

    // Enforcement below the minimum.
    let mut f = base.clone();
    f.required.destination_scope_at_least =
        Some(DestinationScopeEnforcement::IsolatedExecutionBoundary);
    unavailable(&f);

    // Unknown destination never satisfies a minimum.
    let mut f = base.clone();
    f.destinations.remove(&dest(2));
    f.required.destination_scope_at_least = Some(DestinationScopeEnforcement::Unknown);
    unavailable(&f);

    // A required capability that the request does not include.
    let mut f = base.clone();
    f.required.capabilities = [Capability::GitSigning].into_iter().collect();
    unavailable(&f);

    // Offline coverage beyond what no approval can lift (request deadline).
    let mut f = base.clone();
    f.required.offline_until = Some(at(2 * 3_600 + 1));
    unavailable(&f);

    // ... or beyond a future cutoff.
    let mut f = base.clone();
    f.policy_mut().cutoff_at = Some(at(3_600));
    f.required.offline_until = Some(at(5_400));
    unavailable(&f);

    // Without a minimum, an unknown destination is simply not covered.
    let mut f = base.clone();
    f.destinations.remove(&dest(2));
    match f.resolve() {
        AuthorityDecision::ApprovalRequired { delta, .. } => {
            assert_eq!(delta.added_scope, scope(&[(2, 0)], &[]));
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

#[test]
fn precedence_table() {
    // Blocked outranks parent, capability and role problems.
    let mut f = Fixture::covered(web()).with_parent(Scope::empty(), at(-1));
    f.caller.role = ClientRole::LimitedConsumer;
    f.required.destination_scope_at_least =
        Some(DestinationScopeEnforcement::IsolatedExecutionBoundary);
    f.policy_mut().cutoff_at = Some(at(-5));
    assert!(matches!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::Blocked(_))
    ));
    // Then parent usability.
    f.policy_mut().cutoff_at = None;
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::ParentNotUsable)
    );
    // Then parent attenuation.
    f.parent.as_mut().unwrap().deadline = deadline_at(at(3_600));
    assert!(matches!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::ExceedsParent { .. })
    ));
    // Then caller minimums.
    f.parent = None;
    assert!(matches!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::CapabilityUnavailable { .. })
    ));
    // Then the role check on a non-empty delta.
    f.required = RequiredCapabilities::default();
    f.policy_mut().environments.clear();
    assert_eq!(
        f.resolve(),
        AuthorityDecision::Denied(Denial::RoleForbidden)
    );
    // A limited consumer still receives work that is already allowed.
    f.policy_mut().environments.insert(env_id(1));
    assert!(matches!(f.resolve(), AuthorityDecision::Allowed(_)));
}

#[test]
fn unbounded_policy_window_never_narrows() {
    let mut f = Fixture::covered(web());
    f.policy_mut().max_window = Duration::MAX;
    match f.resolve() {
        AuthorityDecision::Allowed(a) => assert_eq!(a.deadline, at(2 * 3_600)),
        other => panic!("expected allowed, got {other:?}"),
    }
    // A zero window means any future request exceeds it.
    f.policy_mut().max_window = Duration::ZERO;
    match f.resolve() {
        AuthorityDecision::ApprovalRequired { covered, delta } => {
            assert_eq!(delta.extra_window, Some(Duration::from_secs(2 * 3_600)));
            assert_eq!(covered.unwrap().deadline, now());
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

/// Non-vacuity: the generator reaches every outcome class, so the properties
/// above are exercised on allowed, approval and each denial path. Fixed seed.
#[test]
fn generator_reaches_every_outcome_class() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{RngAlgorithm, TestRng, TestRunner};

    let mut runner = TestRunner::new_with_rng(
        ProptestConfig::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
    );
    let strategy = fixture();
    let mut seen = BTreeMap::<&'static str, u32>::new();
    for _ in 0..4_000 {
        let f = strategy.new_tree(&mut runner).unwrap().current();
        let class = match f.resolve() {
            AuthorityDecision::Allowed(_) => "allowed",
            AuthorityDecision::ApprovalRequired {
                covered: Some(_), ..
            } => "approval_partial",
            AuthorityDecision::ApprovalRequired { covered: None, .. } => "approval_none",
            AuthorityDecision::Denied(Denial::Blocked(_)) => "blocked",
            AuthorityDecision::Denied(Denial::ParentNotUsable) => "parent_not_usable",
            AuthorityDecision::Denied(Denial::ExceedsParent { .. }) => "exceeds_parent",
            AuthorityDecision::Denied(Denial::CapabilityUnavailable { .. }) => "capability",
            AuthorityDecision::Denied(Denial::RoleForbidden) => "role",
            AuthorityDecision::Denied(Denial::DeadlinePassed { .. }) => "deadline_passed",
        };
        *seen.entry(class).or_default() += 1;
    }
    for class in [
        "allowed",
        "approval_partial",
        "approval_none",
        "blocked",
        "parent_not_usable",
        "exceeds_parent",
        "capability",
        "role",
    ] {
        assert!(
            seen.get(class).copied().unwrap_or(0) >= 20,
            "{class} under-generated: {seen:?}"
        );
    }
}

proptest! {
    #![proptest_config(config(512))]

    /// Scope algebra laws resolution relies on (component-wise sets).
    #[test]
    fn scope_algebra_laws(a in strategies::scope(), b in strategies::scope()) {
        let i = a.intersect(&b);
        prop_assert!(i.is_subset_of(&a) && i.is_subset_of(&b));
        prop_assert_eq!(&i, &b.intersect(&a));
        let d = a.difference(&b);
        prop_assert!(d.is_subset_of(&a));
        prop_assert!(void(&d.intersect(&b)));
        prop_assert_eq!(&union(&i, &d), &a);
        prop_assert_eq!(a.is_subset_of(&b), void(&a.difference(&b)));
        prop_assert!(a.intersect(&Scope::empty()).is_empty());
    }
}
