//! Issuance substrate (ADR-0005 §3.5, §12; review F06). Pure records and the
//! refusal predicates. Cryptography and the issuer endpoint's protocol are M03; the
//! transactional reserve/publish/void methods are `heimdall_store::Txn`.
//!
//! Protocol summary: **reserve** (one transaction: run every predicate, write the
//! entry `reserved` with its complete bounds) → **sign** outside the transaction →
//! **publish** (second transaction: re-run **every** predicate with current time,
//! then `published`; else `voided` and nothing is released). A `reserved` entry
//! found after a crash stays counted in the residual until its `valid_before`
//! passes and is never published; recovery reserves afresh.
//!
//! [`check`] is the whole ADR-0005 §3.5 refusal list plus the §3.6 admission
//! deadline (ADR-0006 §13.4 N02). The caller builds [`IssuanceCheck`] from current
//! store state **inside** the reserve transaction and again inside the publish
//! transaction; at publish a refusal means `void_issuance(reason)`, never
//! publication.

use std::collections::BTreeSet;

use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CredentialInstanceId, GrantId, IssuanceId};
use serde::{Deserialize, Serialize};

use crate::grant::{AuthorizationSource, GrantSnapshot};
use crate::policy::{AuthorityGeneration, PolicyRevision, StandingPolicy};
use crate::scope::{AccessPair, Capability};
use crate::time::{Admission, TimeStatus};

/// SSH certificate extension that is never issued in V1 (ADR-0005 §3.4).
pub const EXTENSION_X11_FORWARDING: &str = "permit-X11-forwarding";
/// SSH certificate extension that needs the explicit `agent-forwarding` capability
/// (ADR-0005 §3.4; spec §8.5).
pub const EXTENSION_AGENT_FORWARDING: &str = "permit-agent-forwarding";

/// The single certificate principal for a pair (ADR-0005 §3.3):
/// `hm:<destination-id>:<account>`.
#[must_use]
pub fn principal_for(pair: &AccessPair) -> String {
    format!("hm:{}:{}", pair.destination.as_str(), pair.account.as_str())
}

/// Issuance-log states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    /// Bounds committed; nothing signed yet, or signed but not yet published.
    /// Counted in the residual.
    Reserved,
    /// Released to a signer. Counted in the residual.
    Published,
    /// Never released; excluded from the residual.
    Voided,
}

/// Complete certificate bounds recorded at reservation (ADR-0005 §3.5 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBounds {
    /// Random serial.
    pub serial: u64,
    /// Key ID string embedded in the certificate.
    pub key_id: String,
    /// The single principal (`hm:<destination>:<account>`), ADR-0005 §3.3.
    pub principal: String,
    /// Validity start.
    pub valid_after: Timestamp,
    /// Validity end; never later than `min(deadline, cutoff, parent deadline)`.
    pub valid_before: Timestamp,
    /// Extensions requested (critical options are refused outright).
    pub extensions: BTreeSet<String>,
    /// Fingerprint of the subject (working) key.
    pub subject_fingerprint: String,
}

/// Why issuance is refused (ADR-0005 §3.5 refusal list, same for reserve and publish).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum IssuanceRefusal {
    /// Grant not `preparing`/`active`/`degraded`.
    #[error("grant state {0:?} does not permit issuance")]
    GrantNotIssuable(GrantState),
    /// Generation, ancestor or policy revision moved.
    #[error("authority generation is stale")]
    StaleGeneration,
    /// Tombstone for the grant or an ancestor.
    #[error("grant or ancestor is revoked")]
    Tombstoned,
    /// Pair outside the grant's resolved snapshot.
    #[error("pair is outside the grant snapshot")]
    PairOutsideSnapshot,
    /// Child pair not a subset of the parent's.
    #[error("child pair exceeds parent")]
    ChildExceedsParent,
    /// `valid_before` later than the bound.
    #[error("requested validity exceeds the bound")]
    BoundTooLate,
    /// The bound has already passed.
    #[error("the bound has passed")]
    BoundPassed,
    /// New activation under a paused policy.
    #[error("policy is paused")]
    PausedActivation,
    /// New activation at or after a cutoff (ADR-0006 §13.6 item 1). Issuance
    /// within an existing grant past the cutoff is [`IssuanceRefusal::BoundPassed`]
    /// (the cutoff bounds the grant at `min(deadline, cutoff)`).
    #[error("policy cutoff passed")]
    CutoffPassed,
    /// Subject key not registered by this environment's signer for the grant.
    #[error("subject key is not registered for this grant")]
    UnknownSubjectKey,
    /// A critical option was requested. (Before revision 2.1 this also covered
    /// unpermitted extensions; those are now [`IssuanceRefusal::UnpermittedExtension`].)
    #[error("critical option requested")]
    CriticalOption,
    /// Time gate not `Safe`, or the grant has no anchor in this boot
    /// (`Admission::NeedsAnchor`: fail closed, not an expiry).
    #[error("time is uncertain")]
    TimeUncertain,
    /// The grant's continuous budget has run out (ADR-0005 §3.6 admission deadline
    /// branch (b)), even if the wall clock and the gate look fine.
    #[error("the grant's continuous time budget has run out")]
    BudgetExpired,
    /// The principal is not exactly `hm:<destination-id>:<account>` for the pair
    /// (ADR-0005 §3.3; several principals are refused too).
    #[error("principal does not match the pair")]
    WrongPrincipal,
    /// An extension outside the grant's permissions for this pair (ADR-0005 §3.4).
    #[error("extension outside the grant's permissions requested")]
    UnpermittedExtension,
    /// The applicable policy's revision differs from the one the grant was
    /// authorized/reserved under, or the policy is gone.
    #[error("policy revision is stale")]
    StalePolicyRevision,
    /// A delegated grant's recorded parent (or a further ancestor) was not supplied,
    /// or the supplied chain does not match the recorded parent links.
    #[error("ancestor chain is missing or inconsistent")]
    AncestorMissing,
    /// An ancestor is not in an issuable state (denied, revoked, revoking, expired,
    /// released, failed, cancelled or not yet authorized).
    #[error("an ancestor grant does not permit issuance")]
    AncestorDenied,
    /// An ancestor's authority generation is not the current one.
    #[error("an ancestor's authority generation is stale")]
    StaleAncestor,
    /// ⟨r2.7⟩ The credential mechanism recorded with the grant is not configured in
    /// this runtime (ADR-0006 §13.10 item 2): the use is refused and nothing ends
    /// (the grant is `degraded` with reason `mechanism_unavailable`). Applied by the
    /// application around [`check`], which knows no mechanisms.
    #[error("the grant's credential mechanism is unavailable")]
    MechanismUnavailable,
}

/// One issuance-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceEntry {
    /// ID.
    pub id: IssuanceId,
    /// Grant.
    pub grant: GrantId,
    /// Authority generation at reservation.
    pub generation: AuthorityGeneration,
    /// Pair covered.
    pub pair: AccessPair,
    /// Bounds.
    pub bounds: CertificateBounds,
    /// State.
    pub state: IssuanceState,
    /// Reserved at.
    pub reserved_at: Timestamp,
    /// Published or voided at.
    pub settled_at: Option<Timestamp>,
    /// Why voided, when voided.
    pub void_reason: Option<IssuanceRefusal>,
}

/// Credential instance: a key handle plus per-pair certificates (ADR-0005 §12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialInstance {
    /// ID.
    pub id: CredentialInstanceId,
    /// Grant.
    pub grant: GrantId,
    /// Opaque reference to the protected working key (never the material).
    pub key_handle_ref: String,
    /// Issuance entries (one per pair) attached to this key.
    pub certificates: Vec<IssuanceId>,
    /// State.
    pub state: CredentialState,
}

/// Credential instance lifecycle (ADR-0005 §3.6 "at grant end ... destroys").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    /// Key generated, certificates pending.
    Pending,
    /// Installed in the signer.
    Installed,
    /// Key destroyed and certificates dropped.
    Destroyed,
}

/// Everything the predicates look at; built inside the reserve or publish
/// transaction from current store state and the time gate.
#[derive(Debug, Clone)]
pub struct IssuanceCheck<'a> {
    /// The grant.
    pub grant: &'a GrantSnapshot,
    /// The recorded parent's **current** snapshot, for a delegated grant. Required
    /// when `grant.parent` is set and must carry that ID (`AncestorMissing`).
    pub parent: Option<&'a GrantSnapshot>,
    /// **⟨r2.1⟩** Current snapshots of the ancestors **above** the parent, nearest
    /// first (grandparent, great-grandparent, …, root). Each must be the recorded
    /// parent of the one before it, and the last has no parent (`AncestorMissing`).
    /// Empty for a root grant or a grant whose parent is a root.
    pub ancestors: &'a [GrantSnapshot],
    /// Applicable policy, if any.
    pub policy: Option<&'a StandingPolicy>,
    /// **⟨r2.1⟩** The policy revision the grant was authorized under (its
    /// `ResolvedIntent.policy_revision`); must equal the applicable policy's current
    /// revision. A grant whose `source` is `StandingPolicy { revision }` is checked
    /// against that revision even when this is `None`.
    pub expected_policy_revision: Option<PolicyRevision>,
    /// Current authority generation.
    pub current_generation: AuthorityGeneration,
    /// Tombstone exists for the grant or an ancestor.
    pub tombstoned: bool,
    /// Requested pair.
    pub pair: &'a AccessPair,
    /// Requested bounds.
    pub bounds: &'a CertificateBounds,
    /// **⟨r2.1⟩** Extensions the grant permits for this pair (ADR-0005 §3.4
    /// profile: `permit-pty`, `permit-port-forwarding` for a jump host, …). Never
    /// contains `permit-X11-forwarding`; `permit-agent-forwarding` counts only when
    /// the grant's scope has the `agent-forwarding` capability.
    pub permitted_extensions: &'a BTreeSet<String>,
    /// Whether this issuance activates a new grant (pause applies) rather than
    /// re-issuing for an existing one.
    pub new_activation: bool,
    /// Subject key is registered by this environment's signer for the grant.
    pub subject_registered: bool,
    /// Critical option requested.
    pub critical_option: bool,
    /// Time gate result.
    pub time: TimeStatus,
    /// **⟨r2.1⟩** Continuous admission evidence: `time::admission(&grant_anchor,
    /// &observation)` for the grant's persisted anchor and the **same** observation
    /// the gate assessed. `Expired` ⇒ `BudgetExpired`; `NeedsAnchor` ⇒
    /// `TimeUncertain` (fail closed).
    pub admission: Admission,
    /// Now (the wall time of that observation).
    pub now: Timestamp,
}

/// The ancestor chain, nearest first, after checking it matches the recorded
/// parent links.
fn ancestor_chain<'a>(
    input: &IssuanceCheck<'a>,
) -> Result<Vec<&'a GrantSnapshot>, IssuanceRefusal> {
    let mut chain = Vec::new();
    match (&input.grant.parent, input.parent) {
        (None, None) if input.ancestors.is_empty() => return Ok(chain),
        (Some(recorded), Some(parent)) if &parent.id == recorded => chain.push(parent),
        _ => return Err(IssuanceRefusal::AncestorMissing),
    }
    for next in input.ancestors {
        let last = chain
            .last()
            .copied()
            .ok_or(IssuanceRefusal::AncestorMissing)?;
        if last.parent.as_ref() != Some(&next.id) {
            return Err(IssuanceRefusal::AncestorMissing);
        }
        chain.push(next);
    }
    if chain.last().is_some_and(|root| root.parent.is_some()) {
        return Err(IssuanceRefusal::AncestorMissing);
    }
    Ok(chain)
}

/// ADR-0005 §3.5 refusal list plus the §3.6 admission deadline, in order. Applied
/// identically at reserve and at publish (with the then-current store state and
/// time); the first failing predicate is returned.
///
/// 1. grant state, generation, tombstone (grant or ancestor);
/// 2. ancestry: recorded parent supplied, chain consistent (`AncestorMissing`),
///    every ancestor issuable (`AncestorDenied`) and at the current generation
///    (`StaleAncestor`);
/// 3. policy revision unchanged (`StalePolicyRevision`);
/// 4. pair inside the snapshot and inside every ancestor's; exact principal;
/// 5. `min(deadline, every ancestor deadline, cutoff)`: cutoff and pause refuse
///    a **new activation** only (`CutoffPassed`, `PausedActivation`); issuance
///    within an existing grant continues under a pause and past the bound is
///    `BoundPassed` (ADR-0006 §13.6 item 1; ADR-0005 §3.5 refusals 3–4, §3.7);
/// 6. time gate `Safe`; continuous budget open (`BudgetExpired`);
/// 7. `valid_before` within the bound;
/// 8. subject key registered; no critical option; extensions ⊆ permitted.
pub fn check(input: &IssuanceCheck<'_>) -> Result<(), IssuanceRefusal> {
    if !input.grant.state.permits_issuance() {
        return Err(IssuanceRefusal::GrantNotIssuable(input.grant.state));
    }
    if input.grant.generation != input.current_generation {
        return Err(IssuanceRefusal::StaleGeneration);
    }
    if input.tombstoned {
        return Err(IssuanceRefusal::Tombstoned);
    }
    let chain = ancestor_chain(input)?;
    for ancestor in &chain {
        if !ancestor.state.permits_issuance() {
            return Err(IssuanceRefusal::AncestorDenied);
        }
        if ancestor.generation != input.current_generation {
            return Err(IssuanceRefusal::StaleAncestor);
        }
    }
    let recorded_revision = match &input.grant.source {
        AuthorizationSource::StandingPolicy { revision } => Some(*revision),
        _ => None,
    };
    if let (Some(a), Some(b)) = (recorded_revision, input.expected_policy_revision)
        && a != b
    {
        return Err(IssuanceRefusal::StalePolicyRevision);
    }
    if let Some(expected) = input.expected_policy_revision.or(recorded_revision)
        && input.policy.is_none_or(|p| p.revision != expected)
    {
        return Err(IssuanceRefusal::StalePolicyRevision);
    }
    if !input.grant.scope.pairs.contains(input.pair) {
        return Err(IssuanceRefusal::PairOutsideSnapshot);
    }
    if chain.iter().any(|a| !a.scope.pairs.contains(input.pair)) {
        return Err(IssuanceRefusal::ChildExceedsParent);
    }
    if input.bounds.principal != principal_for(input.pair) {
        return Err(IssuanceRefusal::WrongPrincipal);
    }
    let mut bound = input.grant.deadline.effective;
    for ancestor in &chain {
        bound = bound.min(ancestor.deadline.effective);
    }
    if let Some(policy) = input.policy {
        if let Some(cutoff) = policy.cutoff_at {
            bound = bound.min(cutoff);
            if input.new_activation && input.now >= cutoff {
                return Err(IssuanceRefusal::CutoffPassed);
            }
        }
        if input.new_activation && policy.blocks_activation_at(input.now).is_some() {
            return Err(IssuanceRefusal::PausedActivation);
        }
    }
    if input.now >= bound {
        return Err(IssuanceRefusal::BoundPassed);
    }
    if input.time != TimeStatus::Safe {
        return Err(IssuanceRefusal::TimeUncertain);
    }
    match input.admission {
        Admission::Open => {}
        Admission::Expired => return Err(IssuanceRefusal::BudgetExpired),
        Admission::NeedsAnchor => return Err(IssuanceRefusal::TimeUncertain),
    }
    if input.bounds.valid_before > bound {
        return Err(IssuanceRefusal::BoundTooLate);
    }
    if !input.subject_registered {
        return Err(IssuanceRefusal::UnknownSubjectKey);
    }
    if input.critical_option {
        return Err(IssuanceRefusal::CriticalOption);
    }
    let agent_forwarding = input
        .grant
        .scope
        .capabilities
        .contains(&Capability::AgentForwarding);
    for extension in &input.bounds.extensions {
        let permitted = input.permitted_extensions.contains(extension)
            && extension != EXTENSION_X11_FORWARDING
            && (extension != EXTENSION_AGENT_FORWARDING || agent_forwarding);
        if !permitted {
            return Err(IssuanceRefusal::UnpermittedExtension);
        }
    }
    Ok(())
}

/// `latest_possible_credential_expiry` (spec §6.7; ADR-0005 §3.5): the latest
/// `valid_before` among `reserved` and `published` entries, whether or not delivery
/// was acknowledged. Only `voided` entries are excluded.
#[must_use]
pub fn residual(entries: &[IssuanceEntry]) -> Option<Timestamp> {
    entries
        .iter()
        .filter(|e| matches!(e.state, IssuanceState::Reserved | IssuanceState::Published))
        .map(|e| e.bounds.valid_before)
        .max()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(state: IssuanceState, before: &str) -> IssuanceEntry {
        IssuanceEntry {
            id: IssuanceId::from_random_bytes([1; 16]),
            grant: GrantId::from_random_bytes([2; 16]),
            generation: AuthorityGeneration(1),
            pair: AccessPair {
                destination: heimdall_contract::ids::DestinationId::parse("h").unwrap(),
                account: heimdall_contract::ids::AccountName::parse("u").unwrap(),
            },
            bounds: CertificateBounds {
                serial: 1,
                key_id: "k".into(),
                principal: "hm:h:u".into(),
                valid_after: "2026-10-02T00:00:00Z".parse().unwrap(),
                valid_before: before.parse().unwrap(),
                extensions: BTreeSet::new(),
                subject_fingerprint: "fp".into(),
            },
            state,
            reserved_at: "2026-10-02T00:00:00Z".parse().unwrap(),
            settled_at: None,
            void_reason: None,
        }
    }

    #[test]
    fn residual_counts_reserved_and_published_only() {
        let es = [
            entry(IssuanceState::Voided, "2026-10-02T09:00:00Z"),
            entry(IssuanceState::Reserved, "2026-10-02T06:00:00Z"),
            entry(IssuanceState::Published, "2026-10-02T05:00:00Z"),
        ];
        assert_eq!(residual(&es), Some("2026-10-02T06:00:00Z".parse().unwrap()));
        assert_eq!(residual(&es[..1]), None);
    }
}

/// N02 (ADR-0006 §13.4): one refusal per predicate, and reserve/publish
/// interleavings that run the production [`check`] again at publish after the
/// world changed between the two transactions.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod predicate_tests {
    use std::time::Duration;

    use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, PolicyId, ProfileId};
    use heimdall_contract::request::DeadlineIntent;

    use super::*;
    use crate::evidence::EnforcementEvidence;
    use crate::policy::{PauseState, PolicySource};
    use crate::scope::Scope;
    use crate::time::{
        BootId, Deadline, GrantAnchor, TimeAnchor, TimeUncertainty, admission, anchor_grant,
        shorten,
    };

    fn t(secs: i64) -> Timestamp {
        "2026-10-02T09:00:00Z"
            .parse::<Timestamp>()
            .unwrap()
            .checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    fn pair(d: &str, a: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse(a).unwrap(),
        }
    }

    fn snapshot(
        id: u8,
        parent: Option<u8>,
        deadline: i64,
        source: AuthorizationSource,
    ) -> GrantSnapshot {
        GrantSnapshot {
            id: GrantId::from_random_bytes([id; 16]),
            environment: EnvironmentId::from_random_bytes([1; 16]),
            scope: Scope {
                pairs: [pair("web", "deploy"), pair("db", "ops")].into(),
                capabilities: [Capability::SshAuthentication].into(),
            },
            starts_at: t(0),
            deadline: Deadline {
                intent: DeadlineIntent::Duration("PT2H".into()),
                resolved_at: t(0),
                effective: t(deadline),
            },
            parent: parent.map(|p| GrantId::from_random_bytes([p; 16])),
            source,
            generation: AuthorityGeneration(7),
            state: GrantState::Active,
            enforcement: EnforcementEvidence::unknown(),
        }
    }

    /// Mutable "store state" between reserve and publish; `check()` builds the
    /// production `IssuanceCheck` from it exactly as a transaction would.
    struct World {
        grant: GrantSnapshot,
        parent: Option<GrantSnapshot>,
        ancestors: Vec<GrantSnapshot>,
        policy: Option<StandingPolicy>,
        expected_policy_revision: Option<PolicyRevision>,
        generation: AuthorityGeneration,
        tombstoned: bool,
        pair: AccessPair,
        bounds: CertificateBounds,
        permitted: BTreeSet<String>,
        new_activation: bool,
        subject_registered: bool,
        critical_option: bool,
        time: TimeStatus,
        grant_anchor: GrantAnchor,
        observation: TimeAnchor,
    }

    impl World {
        /// A delegated grant (child 3 → parent 2 → root 1) under policy revision 4,
        /// anchored at t0 on continuous 0, observed at t0 + 10 min.
        fn new() -> Self {
            let source = AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(4),
            };
            let grant = snapshot(3, Some(2), 3600, source.clone());
            let parent = snapshot(2, Some(1), 5400, source.clone());
            let root = snapshot(1, None, 7200, source);
            let policy = StandingPolicy {
                id: PolicyId::parse("default").unwrap(),
                revision: PolicyRevision(4),
                profile: ProfileId::parse("personal").unwrap(),
                workspace: None,
                scope: grant.scope.clone(),
                environments: [grant.environment.clone()].into(),
                max_window: Duration::from_secs(12 * 3600),
                pause: PauseState::Active,
                cutoff_at: None,
                source: PolicySource::SetupDefault,
            };
            let p = pair("web", "deploy");
            let anchor = TimeAnchor {
                boot_id: BootId("boot-1".into()),
                continuous: Duration::ZERO,
                wall: t(0),
            };
            let grant_anchor = anchor_grant(grant.id.clone(), anchor, grant.deadline.effective);
            Self {
                bounds: CertificateBounds {
                    serial: 42,
                    key_id: "k".into(),
                    principal: principal_for(&p),
                    valid_after: t(0),
                    valid_before: t(3600),
                    extensions: ["permit-pty".to_owned()].into(),
                    subject_fingerprint: "fp".into(),
                },
                grant,
                parent: Some(parent),
                ancestors: vec![root],
                policy: Some(policy),
                expected_policy_revision: Some(PolicyRevision(4)),
                generation: AuthorityGeneration(7),
                tombstoned: false,
                pair: p,
                permitted: ["permit-pty".to_owned(), "permit-port-forwarding".to_owned()].into(),
                new_activation: false,
                subject_registered: true,
                critical_option: false,
                time: TimeStatus::Safe,
                grant_anchor,
                observation: TimeAnchor {
                    boot_id: BootId("boot-1".into()),
                    continuous: Duration::from_secs(600),
                    wall: t(600),
                },
            }
        }

        fn check(&self) -> Result<(), IssuanceRefusal> {
            check(&IssuanceCheck {
                grant: &self.grant,
                parent: self.parent.as_ref(),
                ancestors: &self.ancestors,
                policy: self.policy.as_ref(),
                expected_policy_revision: self.expected_policy_revision,
                current_generation: self.generation,
                tombstoned: self.tombstoned,
                pair: &self.pair,
                bounds: &self.bounds,
                permitted_extensions: &self.permitted,
                new_activation: self.new_activation,
                subject_registered: self.subject_registered,
                critical_option: self.critical_option,
                time: self.time,
                admission: admission(&self.grant_anchor, &self.observation),
                now: self.observation.wall,
            })
        }

        /// Time passes on both clocks.
        fn pass(&mut self, secs: u64) {
            self.observation.continuous += Duration::from_secs(secs);
            self.observation.wall = self
                .observation
                .wall
                .checked_add(jiff::SignedDuration::from_secs(
                    i64::try_from(secs).unwrap(),
                ))
                .unwrap();
        }

        /// Revocation of `who`: tombstone + generation bump in one transaction.
        fn revoke(&mut self) {
            self.tombstoned = true;
            self.generation = self.generation.next();
        }
    }

    /// (name, expected refusal, change applied to the world).
    type Case = (&'static str, IssuanceRefusal, Box<dyn FnOnce(&mut World)>);

    fn refused(f: impl FnOnce(&mut World)) -> IssuanceRefusal {
        let mut w = World::new();
        assert_eq!(w.check(), Ok(()), "baseline passes");
        f(&mut w);
        w.check().expect_err("must be refused")
    }

    #[test]
    fn baseline_passes_and_principal_is_exact() {
        assert_eq!(World::new().check(), Ok(()));
        assert_eq!(principal_for(&pair("web", "deploy")), "hm:web:deploy");
    }

    #[test]
    fn refuses_each_predicate() {
        use IssuanceRefusal as R;
        let cases: Vec<Case> = vec![
            (
                "grant state",
                R::GrantNotIssuable(GrantState::Revoking),
                Box::new(|w| w.grant.state = GrantState::Revoking),
            ),
            (
                "generation",
                R::StaleGeneration,
                Box::new(|w| w.generation = w.generation.next()),
            ),
            (
                "tombstone",
                R::Tombstoned,
                Box::new(|w| w.tombstoned = true),
            ),
            (
                "parent not supplied",
                R::AncestorMissing,
                Box::new(|w| w.parent = None),
            ),
            (
                "wrong parent supplied",
                R::AncestorMissing,
                Box::new(|w| w.parent = Some(w.ancestors[0].clone())),
            ),
            (
                "ancestor chain cut short",
                R::AncestorMissing,
                Box::new(|w| w.ancestors.clear()),
            ),
            (
                "ancestors without parent",
                R::AncestorMissing,
                Box::new(|w| {
                    w.grant.parent = None;
                    w.parent = None;
                }),
            ),
            (
                "parent denied",
                R::AncestorDenied,
                Box::new(|w| w.parent.as_mut().unwrap().state = GrantState::Denied),
            ),
            (
                "parent revoked",
                R::AncestorDenied,
                Box::new(|w| w.parent.as_mut().unwrap().state = GrantState::Revoked),
            ),
            (
                "grandparent revoked",
                R::AncestorDenied,
                Box::new(|w| w.ancestors[0].state = GrantState::Revoked),
            ),
            (
                "parent generation",
                R::StaleAncestor,
                Box::new(|w| w.parent.as_mut().unwrap().generation = AuthorityGeneration(6)),
            ),
            (
                "grandparent generation",
                R::StaleAncestor,
                Box::new(|w| w.ancestors[0].generation = AuthorityGeneration(6)),
            ),
            (
                "policy revision moved",
                R::StalePolicyRevision,
                Box::new(|w| w.policy.as_mut().unwrap().revision = PolicyRevision(5)),
            ),
            (
                "policy gone",
                R::StalePolicyRevision,
                Box::new(|w| w.policy = None),
            ),
            (
                "expected revision disagrees with the grant",
                R::StalePolicyRevision,
                Box::new(|w| w.expected_policy_revision = Some(PolicyRevision(3))),
            ),
            (
                "pair outside snapshot",
                R::PairOutsideSnapshot,
                Box::new(|w| w.pair = pair("mail", "root")),
            ),
            (
                "child exceeds parent",
                R::ChildExceedsParent,
                Box::new(|w| {
                    w.parent
                        .as_mut()
                        .unwrap()
                        .scope
                        .pairs
                        .remove(&pair("web", "deploy"));
                }),
            ),
            (
                "child exceeds grandparent",
                R::ChildExceedsParent,
                Box::new(|w| {
                    w.ancestors[0].scope.pairs.remove(&pair("web", "deploy"));
                }),
            ),
            (
                "principal for another pair",
                R::WrongPrincipal,
                Box::new(|w| w.bounds.principal = principal_for(&pair("db", "ops"))),
            ),
            (
                "several principals",
                R::WrongPrincipal,
                Box::new(|w| w.bounds.principal = "hm:web:deploy,hm:db:ops".into()),
            ),
            (
                "bare account principal",
                R::WrongPrincipal,
                Box::new(|w| w.bounds.principal = "deploy".into()),
            ),
            (
                "cutoff passed, new activation",
                R::CutoffPassed,
                Box::new(|w| {
                    w.new_activation = true;
                    w.policy.as_mut().unwrap().cutoff_at = Some(t(300));
                }),
            ),
            (
                // ADR-0006 §13.6 item 1: existing use past min(deadline, cutoff).
                "cutoff passed, issuance within the existing grant",
                R::BoundPassed,
                Box::new(|w| w.policy.as_mut().unwrap().cutoff_at = Some(t(300))),
            ),
            (
                // ADR-0006 §13.6 item 1: a pause never stops the existing grant.
                "paused, issuance within the existing grant is not refused for the pause",
                R::TimeUncertain,
                Box::new(|w| {
                    w.policy.as_mut().unwrap().pause = PauseState::Paused { since: t(1) };
                    w.time = TimeStatus::Uncertain(TimeUncertainty::ContinuousWentBackwards);
                }),
            ),
            (
                "paused new activation",
                R::PausedActivation,
                Box::new(|w| {
                    w.new_activation = true;
                    w.policy.as_mut().unwrap().pause = PauseState::Paused { since: t(1) };
                }),
            ),
            (
                "grandparent deadline passed",
                R::BoundPassed,
                Box::new(|w| w.ancestors[0].deadline.effective = t(500)),
            ),
            (
                "time uncertain",
                R::TimeUncertain,
                Box::new(|w| {
                    w.time = TimeStatus::Uncertain(TimeUncertainty::ContinuousWentBackwards)
                }),
            ),
            (
                "anchor from another boot",
                R::TimeUncertain,
                Box::new(|w| w.observation.boot_id = BootId("boot-2".into())),
            ),
            (
                "continuous budget expired while gate is Safe",
                R::BudgetExpired,
                Box::new(|w| {
                    // The wall clock lags (still 10 min in) while 3600 s of continuous
                    // time passed: the gate is Safe by assumption, the budget is gone.
                    w.observation.continuous = Duration::from_secs(3600);
                }),
            ),
            (
                "valid_before past the bound",
                R::BoundTooLate,
                Box::new(|w| w.bounds.valid_before = t(3601)),
            ),
            (
                "valid_before past the parent deadline",
                R::BoundTooLate,
                Box::new(|w| {
                    w.parent.as_mut().unwrap().deadline.effective = t(1800);
                    w.bounds.valid_before = t(1801);
                }),
            ),
            (
                "unknown subject key",
                R::UnknownSubjectKey,
                Box::new(|w| w.subject_registered = false),
            ),
            (
                "critical option",
                R::CriticalOption,
                Box::new(|w| w.critical_option = true),
            ),
            (
                "extension not permitted",
                R::UnpermittedExtension,
                Box::new(|w| {
                    w.bounds.extensions.insert("permit-user-rc".into());
                }),
            ),
            (
                "X11 never",
                R::UnpermittedExtension,
                Box::new(|w| {
                    w.permitted.insert(EXTENSION_X11_FORWARDING.into());
                    w.bounds.extensions.insert(EXTENSION_X11_FORWARDING.into());
                }),
            ),
            (
                "agent forwarding without the capability",
                R::UnpermittedExtension,
                Box::new(|w| {
                    w.permitted.insert(EXTENSION_AGENT_FORWARDING.into());
                    w.bounds
                        .extensions
                        .insert(EXTENSION_AGENT_FORWARDING.into());
                }),
            ),
        ];
        for (name, expected, mutate) in cases {
            assert_eq!(refused(mutate), expected, "{name}");
        }
    }

    #[test]
    fn agent_forwarding_is_permitted_with_the_capability() {
        let mut w = World::new();
        w.grant
            .scope
            .capabilities
            .insert(Capability::AgentForwarding);
        w.permitted.insert(EXTENSION_AGENT_FORWARDING.into());
        w.bounds
            .extensions
            .insert(EXTENSION_AGENT_FORWARDING.into());
        assert_eq!(w.check(), Ok(()));
    }

    #[test]
    fn root_grant_needs_no_ancestors() {
        let mut w = World::new();
        w.grant.parent = None;
        w.parent = None;
        w.ancestors.clear();
        assert_eq!(w.check(), Ok(()));
    }

    /// Reserve passes; something happens; the production predicate at publish
    /// refuses (so the entry is voided, nothing released). ADR-0005 §3.5 step 3.
    #[test]
    fn publish_rechecks_after_changes_between_reserve_and_publish() {
        use IssuanceRefusal as R;
        let cases: Vec<Case> = vec![
            (
                "revoke of the grant",
                R::StaleGeneration,
                Box::new(World::revoke),
            ),
            (
                "revoke of the parent (tombstone found through denied_ancestor)",
                R::StaleGeneration,
                Box::new(|w| {
                    w.revoke();
                    w.parent.as_mut().unwrap().state = GrantState::Revoked;
                }),
            ),
            (
                "revoke without a generation bump still hits the tombstone",
                R::Tombstoned,
                Box::new(|w| w.tombstoned = true),
            ),
            (
                "cutoff (cutoff + generation in one transaction)",
                R::StaleGeneration,
                Box::new(|w| {
                    w.policy.as_mut().unwrap().cutoff_at = Some(w.observation.wall);
                    w.generation = w.generation.next();
                }),
            ),
            (
                "cutoff reached between reserve and publish (no revision moves)",
                R::BoundPassed,
                Box::new(|w| {
                    w.policy.as_mut().unwrap().cutoff_at = Some(t(900));
                    w.pass(300);
                }),
            ),
            (
                "policy change",
                R::StalePolicyRevision,
                Box::new(|w| w.policy.as_mut().unwrap().revision = PolicyRevision(5)),
            ),
            (
                "continuous budget expiry with the wall clock frozen",
                R::BudgetExpired,
                Box::new(|w| {
                    w.observation.continuous += Duration::from_secs(3000);
                }),
            ),
            (
                "cutoff shortens the budget; wall lagging",
                R::BudgetExpired,
                Box::new(|w| {
                    // Cutoff at t0 + 1200 s shortens the persisted budget (N01); the wall
                    // lags, the continuous clock reaches the shortened budget end.
                    w.grant_anchor = shorten(&w.grant_anchor, t(1200));
                    w.policy.as_mut().unwrap().cutoff_at = Some(t(1200));
                    w.bounds.valid_before = t(1200);
                    w.observation.continuous = Duration::from_secs(1200);
                }),
            ),
            (
                "deadline passes",
                R::BoundPassed,
                Box::new(|w| w.pass(3000)),
            ),
            (
                "time becomes uncertain",
                R::TimeUncertain,
                Box::new(|w| {
                    w.time = TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
                        sync: crate::time::SyncStatus::Unknown,
                    });
                }),
            ),
        ];
        for (name, expected, between) in cases {
            let mut w = World::new();
            assert_eq!(w.check(), Ok(()), "reserve: {name}");
            between(&mut w);
            assert_eq!(w.check(), Err(expected), "publish: {name}");
        }
    }

    #[test]
    fn refusals_serialize_without_echoing_input() {
        // Synthetic canary built per run (prefix as in `heimdall_testkit`).
        let prefix = "HEIMDALL_CANARY_";
        let canary = format!("{prefix}{:x}", std::process::id());
        let w = {
            let mut w = World::new();
            w.bounds.principal = canary.clone();
            w
        };
        let r = w.check().unwrap_err();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"reason":"wrong_principal"}"#);
        assert!(!json.contains(prefix) && !r.to_string().contains(prefix));
        assert!(!format!("{r:?}").contains(&canary));
    }
}
