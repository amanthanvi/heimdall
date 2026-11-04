//! The pre-launch non-interactive eligibility check (m02-plan U8; ADR-0007 §7, §8;
//! M2-R04, M2-R05).
//!
//! Under `--non-interactive` without `--allow-provider-interaction`, after Git
//! resolution and as the last step before writing `launching`, every pair must have:
//! * a fresh interaction of `none`;
//! * every declaration the bind result relied on still live in a **fresh** `inspect
//!   identities`, with the same revision and endpoint, and `expires_at > now`;
//! * a selection, re-evaluated now by a static `sshconf` pass in the CLI process, that
//!   is `exclusive`, or whose alternatives `domain::catalog::fallback_clearance`
//!   clears.
//!
//! A refusal writes `prelaunch_failed` and exits 3 with `INTERACTION_REQUIRED`. A
//! replayed `bind` result is checked the same way.
//!
//! **Readings applied (fail closed).** Pairs are checked in the bind result's order and
//! the first pair that fails decides (QR5: any pair refuses). Within a pair:
//! 1. the identity must be in the fresh view, and both the bind result's interaction
//!    and the fresh one must be `none` (a result that relied on nothing is never
//!    upgraded by a later declaration); a provider-owned interaction
//!    (`provider_approval`, `provider_unlock`, `hardware_presence`) is
//!    `provider_interaction`, anything else `interaction_unknown`;
//! 2. the result's declaration must exist, and the fresh view must name a live
//!    declaration with the same revision and endpoint whose `expires_at` is later than
//!    `now` (`expires_at == now` no longer counts), else `interaction_unknown`;
//! 3. the alias's effective `IdentityAgent`, as the fresh static pass determined it,
//!    must be the pair's endpoint; a different or undetermined agent is
//!    `interaction_unknown` (the declaration covers one endpoint only);
//! 4. the fresh selection (`selection[i]` for `bound[i]`, the same alias) is
//!    `exclusive` only when a managed entry carries the identity's own fingerprint
//!    (otherwise the projection does not select the adopted key, and the verdict is
//!    read as `undetermined`); a selection that is not `exclusive` must be cleared by
//!    the one domain rule, `heimdall_domain::catalog::fallback_clearance`, against the
//!    fresh view, else `fallback_identity_interaction` naming each uncleared entry's
//!    file and line. A missing selection clears nothing.
//!
//! **Every invocation profile** (ADR-0007 §12.25 item 1, T01). The launched work may be
//! a shell, a remote command (Git over SSH, SCP) or SFTP, so a [`FreshSelection`]
//! carries the alias's selection and agent under each profile of [`required_profiles`]
//! (`shell`, `exec`, `subsystem:sftp`, the consent v3 set). Steps 3 and 4 hold for
//! every profile: an agent that differs or is undetermined in any profile refuses
//! first (`interaction_unknown`), then a selection uncleared or undetermined in any
//! profile refuses (`fallback_identity_interaction`, naming every uncleared entry of
//! every profile once, in profile order). A profile the selection does not carry is
//! undetermined, so it refuses.
//!
//! The fresh view carries no key type or mechanism, so the catalog records the
//! clearance rule reads are rebuilt from it: an identity is at its viewed endpoint,
//! and its viewed fresh interaction decides. A 1Password or FIDO identity is never
//! `none` in a fresh view (the domain table), so it never clears an alternative.
//!
//! Pure: the caller takes both views and `now`; nothing here reads, executes or
//! contacts anything.

use heimdall_contract::Timestamp;
use heimdall_contract::doctor::ConfigProvenance;
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{
    DeclarationRef, EndpointRef, EvidenceBasis, IdentityEntrySource, IdentitySelection,
    IdentitySelectionReport, InteractionKind, NoninteractiveEligibility,
};
use heimdall_contract::request::PairIntegration;
use heimdall_domain::catalog::{
    IdentityRecord, IdentitySource, InteractionProfile, PairEligibility, fallback_clearance,
};

/// One identity as a fresh `inspect identities` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityView {
    /// The identity.
    pub identity: IdentityId,
    /// Its fingerprint.
    pub fingerprint: String,
    /// Its current endpoint.
    pub endpoint: Option<EndpointRef>,
    /// Its fresh interaction.
    pub interaction: InteractionKind,
    /// Its live declaration, if any.
    pub declaration: Option<DeclarationRef>,
}

/// A fresh `inspect identities`, taken immediately before the check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentitiesView {
    /// Every identity.
    pub identities: Vec<IdentityView>,
}

impl IdentitiesView {
    /// The view of `identity`, if the fresh listing has it.
    #[must_use]
    pub fn get(&self, identity: &IdentityId) -> Option<&IdentityView> {
        self.identities.iter().find(|v| &v.identity == identity)
    }
}

/// The invocation profiles a launch can use, by name, in order: `shell`, `exec` (any
/// remote command) and `subsystem:sftp` (ADR-0007 §12.25 item 1; the consent v3 set,
/// `heimdall_localenv::projection::observe::profile_names`).
#[must_use]
pub fn required_profiles() -> Vec<String> {
    heimdall_localenv::projection::observe::profile_names()
}

/// One invocation profile's fresh selection (ADR-0007 §12.25 item 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSelection {
    /// The profile's name ([`required_profiles`]).
    pub profile: String,
    /// The identity selection the static pass found under it.
    pub report: IdentitySelectionReport,
    /// The alias's effective `IdentityAgent` endpoint under it, when determined.
    pub endpoint: Option<EndpointRef>,
}

/// One pair's selection, re-evaluated now in the CLI process (passive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshSelection {
    /// The pair's alias.
    pub alias: String,
    /// The identity selection the static pass found for the first profile, `shell`
    /// (also what `connect` reads the alias's identity from).
    pub report: IdentitySelectionReport,
    /// The alias's effective `IdentityAgent` endpoint under `shell`, when determined.
    pub endpoint: Option<EndpointRef>,
    /// ADR-0007 §12.25 item 1 (T01): the selections under every other profile of
    /// [`required_profiles`] (`exec`, `subsystem:sftp`). The check reads `shell` from
    /// `report` and `endpoint`; a profile missing here is undetermined and refuses.
    pub profiles: Vec<ProfileSelection>,
}

impl FreshSelection {
    /// Every profile's `(name, report, endpoint)`, `shell` first.
    fn every_profile(&self) -> Vec<(&str, &IdentitySelectionReport, Option<&EndpointRef>)> {
        let mut out = vec![("shell", &self.report, self.endpoint.as_ref())];
        out.extend(
            self.profiles
                .iter()
                .map(|p| (p.profile.as_str(), &p.report, p.endpoint.as_ref())),
        );
        out
    }

    /// Whether every profile of [`required_profiles`] is carried.
    fn covers_every_profile(&self) -> bool {
        let carried: Vec<&str> = self.every_profile().iter().map(|(n, _, _)| *n).collect();
        required_profiles()
            .iter()
            .all(|r| carried.contains(&r.as_str()))
    }
}

/// What the check needs of one bound pair: a bind result's [`PairIntegration`]
/// ([`BoundPair::from_pair`]), or, for `connect`, the alias's identity as the first
/// `inspect identities` of the command showed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundPair {
    /// The adopted identity.
    pub identity: IdentityId,
    /// The managed alias, if any.
    pub alias: Option<String>,
    /// The agent endpoint the result names.
    pub endpoint: Option<EndpointRef>,
    /// The result's (fresh at its own time) interaction.
    pub interaction: InteractionKind,
    /// The declaration the result relied on.
    pub declaration: Option<DeclarationRef>,
}

impl BoundPair {
    /// The parts of a bind (or ensure) result's pair the check reads.
    #[must_use]
    pub fn from_pair(pair: &PairIntegration) -> BoundPair {
        BoundPair {
            identity: pair.identity.clone(),
            alias: pair.alias.clone(),
            endpoint: pair.endpoint.clone(),
            interaction: pair.interaction,
            declaration: pair.declaration.clone(),
        }
    }

    /// `connect`: the alias's identity as a listing showed it.
    #[must_use]
    pub fn from_view(view: &IdentityView, alias: &str) -> BoundPair {
        BoundPair {
            identity: view.identity.clone(),
            alias: Some(alias.to_owned()),
            endpoint: view.endpoint.clone(),
            interaction: view.interaction,
            declaration: view.declaration.clone(),
        }
    }
}

/// Why a launch is refused before it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrelaunchReason {
    /// `interaction_unknown`.
    InteractionUnknown,
    /// `provider_interaction`.
    ProviderInteraction,
    /// `fallback_identity_interaction`.
    FallbackIdentityInteraction,
}

impl PrelaunchReason {
    /// The stable reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrelaunchReason::InteractionUnknown => "interaction_unknown",
            PrelaunchReason::ProviderInteraction => "provider_interaction",
            PrelaunchReason::FallbackIdentityInteraction => "fallback_identity_interaction",
        }
    }
}

/// The refusal: reason, the pair (index into the bound pairs), and the configuration
/// lines of uncleared fallback entries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("launch refused before start: {}", .reason.as_str())]
pub struct PrelaunchRefusal {
    /// Why.
    pub reason: PrelaunchReason,
    /// Which bound pair.
    pub pair: usize,
    /// The uncleared entries' provenance.
    pub entries: Vec<ConfigProvenance>,
}

/// Check every bound pair (ADR-0007 §7, QR5: any pair refuses).
///
/// `selection[i]` is the fresh static selection of `bound[i]`'s alias.
///
/// # Errors
/// [`PrelaunchRefusal`].
pub fn check_noninteractive(
    bound: &[PairIntegration],
    fresh: &IdentitiesView,
    selection: &[FreshSelection],
    now: Timestamp,
) -> Result<(), PrelaunchRefusal> {
    let pairs: Vec<BoundPair> = bound.iter().map(BoundPair::from_pair).collect();
    check_pairs(&pairs, fresh, selection, now)
}

/// [`check_noninteractive`] over [`BoundPair`]s (`connect` has no bind result).
///
/// # Errors
/// [`PrelaunchRefusal`].
pub fn check_pairs(
    bound: &[BoundPair],
    fresh: &IdentitiesView,
    selection: &[FreshSelection],
    now: Timestamp,
) -> Result<(), PrelaunchRefusal> {
    for (index, pair) in bound.iter().enumerate() {
        check_pair(index, pair, fresh, selection.get(index), now)?;
    }
    Ok(())
}

fn refusal(reason: PrelaunchReason, pair: usize) -> PrelaunchRefusal {
    PrelaunchRefusal {
        reason,
        pair,
        entries: Vec::new(),
    }
}

/// The reason an interaction that is not `none` gives.
fn interaction_reason(kind: InteractionKind) -> PrelaunchReason {
    match kind {
        InteractionKind::ProviderApproval
        | InteractionKind::ProviderUnlock
        | InteractionKind::HardwarePresence => PrelaunchReason::ProviderInteraction,
        // `unknown`, `passphrase`, and any kind a newer contract adds: the narrowing
        // reading.
        _ => PrelaunchReason::InteractionUnknown,
    }
}

fn check_pair(
    index: usize,
    pair: &BoundPair,
    fresh: &IdentitiesView,
    selection: Option<&FreshSelection>,
    now: Timestamp,
) -> Result<(), PrelaunchRefusal> {
    // 1. Interaction, in the result and fresh.
    let Some(view) = fresh.get(&pair.identity) else {
        return Err(refusal(PrelaunchReason::InteractionUnknown, index));
    };
    if pair.interaction != InteractionKind::None {
        return Err(refusal(interaction_reason(pair.interaction), index));
    }
    if view.interaction != InteractionKind::None {
        return Err(refusal(interaction_reason(view.interaction), index));
    }
    // 2. The declaration the result relied on, still live and unchanged.
    let (Some(relied), Some(live)) = (&pair.declaration, &view.declaration) else {
        return Err(refusal(PrelaunchReason::InteractionUnknown, index));
    };
    if live.revision != relied.revision
        || live.endpoint != relied.endpoint
        || live.expires_at <= now
        || relied.expires_at <= now
    {
        return Err(refusal(PrelaunchReason::InteractionUnknown, index));
    }
    // 3. The agent ssh will use for the alias is the declared one, in every profile
    //    (ADR-0007 §12.25 item 1).
    let Some(selection) = selection.filter(|s| pair.alias.as_deref() == Some(s.alias.as_str()))
    else {
        return Err(refusal(PrelaunchReason::FallbackIdentityInteraction, index));
    };
    let Some(bound) = pair.endpoint.as_ref().filter(|b| **b == relied.endpoint) else {
        return Err(refusal(PrelaunchReason::InteractionUnknown, index));
    };
    let profiles = selection.every_profile();
    if profiles
        .iter()
        .any(|(_, _, alias_agent)| *alias_agent != Some(bound))
    {
        return Err(refusal(PrelaunchReason::InteractionUnknown, index));
    }
    // 4. The selection, in every profile: exclusive for the adopted key, or every
    //    alternative cleared. A profile the selection does not carry clears nothing.
    let mut entries: Vec<ConfigProvenance> = Vec::new();
    let mut cleared = selection.covers_every_profile();
    let records = records_of(fresh, now);
    let eligibility_of = |id: &IdentityId| eligibility_of(fresh, id);
    for (_, report, _) in profiles {
        let adopted_entry = report.entries.iter().any(|e| {
            e.source == IdentityEntrySource::Managed
                && e.fingerprint.as_deref() == Some(view.fingerprint.as_str())
        });
        if report.selection == IdentitySelection::Exclusive && adopted_entry {
            continue;
        }
        let clearance =
            fallback_clearance(report, &records, &eligibility_of, bound, &view.fingerprint);
        if clearance.cleared {
            continue;
        }
        cleared = false;
        for p in clearance
            .uncleared
            .iter()
            .filter_map(|i| report.entries.get(*i))
            .filter_map(|e| e.provenance.clone())
        {
            if !entries.contains(&p) {
                entries.push(p);
            }
        }
    }
    if cleared {
        return Ok(());
    }
    Err(PrelaunchRefusal {
        reason: PrelaunchReason::FallbackIdentityInteraction,
        pair: index,
        entries,
    })
}

/// The catalog records the clearance rule reads, rebuilt from the fresh view (module
/// docs): each identity at its viewed endpoint, with its viewed interaction.
fn records_of(fresh: &IdentitiesView, now: Timestamp) -> Vec<IdentityRecord> {
    fresh
        .identities
        .iter()
        .map(|v| IdentityRecord {
            id: v.identity.clone(),
            revision: 0,
            source: match &v.endpoint {
                Some(endpoint) => IdentitySource::NativeAgent {
                    endpoint: endpoint.clone(),
                },
                // No endpoint: no alias's agent can be this identity's.
                None => IdentitySource::PublicKeyFile {
                    path: String::new(),
                },
            },
            public_key: String::new(),
            fingerprint: v.fingerprint.clone(),
            interaction: InteractionProfile {
                interaction: v.interaction,
                basis: EvidenceBasis::Inferred,
            },
            label: None,
            adopted_at: now,
            updated_at: now,
        })
        .collect()
}

/// An identity's fresh eligibility as the view shows it; an identity the view does not
/// list is `unknown`.
fn eligibility_of(fresh: &IdentitiesView, id: &IdentityId) -> PairEligibility {
    let (interaction, declaration) = fresh.get(id).map_or((InteractionKind::Unknown, None), |v| {
        (v.interaction, v.declaration.clone())
    });
    let none = interaction == InteractionKind::None;
    PairEligibility {
        interaction,
        basis: if none {
            EvidenceBasis::Declared
        } else {
            EvidenceBasis::Inferred
        },
        declaration,
        noninteractive: NoninteractiveEligibility {
            eligible: none,
            reason: (!none).then(|| interaction_reason(interaction).as_str().to_owned()),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::provider::{
        Certainty, EndpointKind, IdentitiesOnly, IdentityBacking, IdentityEntry, IdentityEntryKind,
    };

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn now() -> Timestamp {
        t("2026-11-03T12:00:00Z")
    }

    fn later() -> Timestamp {
        t("2026-12-01T00:00:00Z")
    }

    fn ep(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.to_owned(),
        }
    }

    fn id(n: u8) -> IdentityId {
        IdentityId::from_random_bytes([n; 16])
    }

    fn fp(n: u8) -> String {
        format!("SHA256:fixture-{n}")
    }

    fn decl(revision: u64, locator: &str, expires_at: Timestamp) -> DeclarationRef {
        DeclarationRef {
            revision,
            endpoint: ep(locator),
            expires_at,
        }
    }

    /// Identity `n`, declared `none` at `A` with revision `n`.
    fn declared(n: u8) -> IdentityView {
        IdentityView {
            identity: id(n),
            fingerprint: fp(n),
            endpoint: Some(ep(A)),
            interaction: InteractionKind::None,
            declaration: Some(decl(u64::from(n), A, later())),
        }
    }

    const A: &str = "/scratch/a.sock";
    const B: &str = "/scratch/b.sock";

    fn bound_of(view: &IdentityView, alias: &str) -> BoundPair {
        BoundPair::from_view(view, alias)
    }

    fn entry(
        source: IdentityEntrySource,
        fp: Option<&str>,
        backing: IdentityBacking,
    ) -> IdentityEntry {
        IdentityEntry {
            kind: IdentityEntryKind::IdentityFile,
            source,
            provenance: Some(ConfigProvenance {
                path_display: "~/.ssh/config".to_owned(),
                line: 7,
            }),
            certainty: Certainty::Determined,
            fingerprint: fp.map(str::to_owned),
            backing,
            cleared: None,
        }
    }

    fn managed(n: u8) -> IdentityEntry {
        entry(
            IdentityEntrySource::Managed,
            Some(&fp(n)),
            IdentityBacking::Agent,
        )
    }

    /// `s` with every other profile (`exec`, `subsystem:sftp`) the same as `shell`.
    fn synced(mut s: FreshSelection) -> FreshSelection {
        s.profiles = required_profiles()
            .into_iter()
            .filter(|p| p != "shell")
            .map(|profile| ProfileSelection {
                profile,
                report: s.report.clone(),
                endpoint: s.endpoint.clone(),
            })
            .collect();
        s
    }

    /// A selection with the same report and agent in every profile.
    fn sel(
        alias: &str,
        selection: IdentitySelection,
        entries: Vec<IdentityEntry>,
    ) -> FreshSelection {
        synced(FreshSelection {
            alias: alias.to_owned(),
            report: IdentitySelectionReport {
                selection,
                entries,
                identities_only: IdentitiesOnly::DeterminedYes,
            },
            endpoint: Some(ep(A)),
            profiles: Vec::new(),
        })
    }

    fn exclusive(alias: &str, n: u8) -> FreshSelection {
        sel(alias, IdentitySelection::Exclusive, vec![managed(n)])
    }

    fn view(items: Vec<IdentityView>) -> IdentitiesView {
        IdentitiesView { identities: items }
    }

    fn reason(r: Result<(), PrelaunchRefusal>) -> Option<(PrelaunchReason, usize)> {
        r.err().map(|e| (e.reason, e.pair))
    }

    #[test]
    fn no_pair_and_exclusive_declared_pairs_launch() {
        assert_eq!(
            check_pairs(&[], &IdentitiesView::default(), &[], now()),
            Ok(())
        );
        let one = declared(1);
        assert_eq!(
            check_pairs(
                &[bound_of(&one, "a")],
                &view(vec![one.clone()]),
                &[exclusive("a", 1)],
                now()
            ),
            Ok(())
        );
    }

    #[test]
    fn fresh_interaction_must_be_none_and_the_identity_listed() {
        let one = declared(1);
        let b = [bound_of(&one, "a")];
        let s = [exclusive("a", 1)];
        assert_eq!(
            reason(check_pairs(&b, &IdentitiesView::default(), &s, now())),
            Some((PrelaunchReason::InteractionUnknown, 0)),
            "an identity the fresh listing lacks"
        );
        for (kind, expected) in [
            (
                InteractionKind::Unknown,
                PrelaunchReason::InteractionUnknown,
            ),
            (
                InteractionKind::Passphrase,
                PrelaunchReason::InteractionUnknown,
            ),
            (
                InteractionKind::ProviderApproval,
                PrelaunchReason::ProviderInteraction,
            ),
            (
                InteractionKind::ProviderUnlock,
                PrelaunchReason::ProviderInteraction,
            ),
            (
                InteractionKind::HardwarePresence,
                PrelaunchReason::ProviderInteraction,
            ),
        ] {
            let mut fresh = one.clone();
            fresh.interaction = kind;
            assert_eq!(
                reason(check_pairs(&b, &view(vec![fresh]), &s, now())),
                Some((expected, 0)),
                "{kind:?}"
            );
            // The bind result's own interaction is checked too: a later declaration
            // never upgrades a result that relied on none.
            let mut stale = b[0].clone();
            stale.interaction = kind;
            assert_eq!(
                reason(check_pairs(&[stale], &view(vec![one.clone()]), &s, now())),
                Some((expected, 0)),
                "bound {kind:?}"
            );
        }
    }

    #[test]
    fn withdrawal_redeclaration_expiry_and_endpoint_change_refuse() {
        let one = declared(1);
        let b = [bound_of(&one, "a")];
        let s = [exclusive("a", 1)];
        let check = |fresh: IdentityView, at: Timestamp| {
            reason(check_pairs(&b, &view(vec![fresh]), &s, at))
        };
        // Withdrawn: the fresh view is `unknown` with no live declaration.
        let mut withdrawn = one.clone();
        withdrawn.interaction = InteractionKind::Unknown;
        withdrawn.declaration = None;
        assert_eq!(
            check(withdrawn, now()),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        // Re-declared: `none` again, but a new revision.
        let mut redeclared = one.clone();
        redeclared.declaration = Some(decl(2, A, later()));
        assert_eq!(
            check(redeclared, now()),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        // The endpoint the declaration covers changed.
        let mut moved = one.clone();
        moved.declaration = Some(decl(1, B, later()));
        assert_eq!(
            check(moved, now()),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        // Expiry: at `expires_at` it no longer counts; one second before it does.
        assert_eq!(
            check(one.clone(), later()),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        let before = later()
            .checked_sub(jiff::SignedDuration::from_secs(1))
            .unwrap();
        assert_eq!(check(one.clone(), before), None);
        // A result that relied on no declaration is refused, whatever the fresh view.
        let mut undeclared = b[0].clone();
        undeclared.declaration = None;
        assert_eq!(
            reason(check_pairs(&[undeclared], &view(vec![one]), &s, now())),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
    }

    #[test]
    fn the_alias_agent_must_be_the_declared_endpoint() {
        let one = declared(1);
        let b = [bound_of(&one, "a")];
        let fresh = view(vec![one]);
        let mut other = exclusive("a", 1);
        other.endpoint = Some(ep(B));
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[synced(other)], now())),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        let mut undetermined = exclusive("a", 1);
        undetermined.endpoint = None;
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[synced(undetermined)], now())),
            Some((PrelaunchReason::InteractionUnknown, 0))
        );
        // A missing selection, or one for another alias, clears nothing.
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[], now())),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[exclusive("other", 1)], now())),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
    }

    #[test]
    fn exclusive_needs_the_adopted_managed_entry() {
        let one = declared(1);
        let b = [bound_of(&one, "a")];
        let fresh = view(vec![one]);
        // `exclusive` over another key's managed entry is not the adopted key's
        // selection; read as undetermined, it is refused through the clearance rule.
        let wrong = sel("a", IdentitySelection::Exclusive, vec![managed(9)]);
        let r = check_pairs(&b, &fresh, &[wrong], now()).unwrap_err();
        assert_eq!(r.reason, PrelaunchReason::FallbackIdentityInteraction);
        assert_eq!(r.entries.len(), 1, "the other managed entry is named");
    }

    #[test]
    fn fallback_alternatives_are_cleared_only_by_the_domain_rule() {
        let one = declared(1);
        let two = declared(2);
        let b = [bound_of(&one, "a")];
        let alt = |backing, fp: Option<&str>| entry(IdentityEntrySource::User, fp, backing);
        // An agent-backed alternative adopted and declared at the same endpoint clears.
        let cleared = sel(
            "a",
            IdentitySelection::NotExclusive,
            vec![managed(1), alt(IdentityBacking::Agent, Some(&fp(2)))],
        );
        assert_eq!(
            check_pairs(
                &b,
                &view(vec![one.clone(), two.clone()]),
                std::slice::from_ref(&cleared),
                now()
            ),
            Ok(())
        );
        // The same alternative, but not declared: refused, naming its line.
        let mut undeclared = two.clone();
        undeclared.interaction = InteractionKind::Unknown;
        undeclared.declaration = None;
        let r = check_pairs(
            &b,
            &view(vec![one.clone(), undeclared]),
            std::slice::from_ref(&cleared),
            now(),
        )
        .unwrap_err();
        assert_eq!(r.reason, PrelaunchReason::FallbackIdentityInteraction);
        assert_eq!(
            r.entries,
            [ConfigProvenance {
                path_display: "~/.ssh/config".to_owned(),
                line: 7
            }]
        );
        // Declared, but at another endpoint.
        let mut elsewhere = two.clone();
        elsewhere.endpoint = Some(ep(B));
        assert_eq!(
            reason(check_pairs(
                &b,
                &view(vec![one.clone(), elsewhere]),
                &[cleared],
                now()
            )),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
        // A file-backed alternative is never cleared, even when its `.pub` is adopted
        // and declared.
        let file = sel(
            "a",
            IdentitySelection::NotExclusive,
            vec![managed(1), alt(IdentityBacking::File, Some(&fp(2)))],
        );
        assert_eq!(
            reason(check_pairs(
                &b,
                &view(vec![one.clone(), two.clone()]),
                &[file],
                now()
            )),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
        // A `.pub`-less alternative, and an alias without `IdentitiesOnly yes`.
        let blind = sel(
            "a",
            IdentitySelection::NotExclusive,
            vec![managed(1), alt(IdentityBacking::Agent, None)],
        );
        assert_eq!(
            reason(check_pairs(
                &b,
                &view(vec![one.clone(), two.clone()]),
                &[blind],
                now()
            )),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
        let mut open = sel("a", IdentitySelection::NotExclusive, vec![managed(1)]);
        open.report.identities_only = IdentitiesOnly::DeterminedNo;
        assert_eq!(
            reason(check_pairs(
                &b,
                &view(vec![one, two]),
                &[synced(open)],
                now()
            )),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
    }

    #[test]
    fn any_pair_refuses_and_names_its_index() {
        let one = declared(1);
        let two = declared(2);
        let b = [bound_of(&one, "a"), bound_of(&two, "b")];
        let s = [exclusive("a", 1), exclusive("b", 2)];
        assert_eq!(
            check_pairs(&b, &view(vec![one.clone(), two.clone()]), &s, now()),
            Ok(())
        );
        let mut locked = two;
        locked.interaction = InteractionKind::ProviderApproval;
        assert_eq!(
            reason(check_pairs(&b, &view(vec![one, locked]), &s, now())),
            Some((PrelaunchReason::ProviderInteraction, 1))
        );
    }

    #[test]
    fn bind_result_pairs_are_read_through_from_pair() {
        let one = declared(1);
        let pair = PairIntegration {
            destination: heimdall_contract::ids::DestinationId::parse("d").unwrap(),
            account: heimdall_contract::ids::AccountName::parse("u").unwrap(),
            identity: one.identity.clone(),
            mechanism: "native_agent".to_owned(),
            endpoint: one.endpoint.clone(),
            alias: Some("a".to_owned()),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Declared,
            declared_at: Some(now()),
            identity_selection: IdentitySelection::Exclusive,
            selection_observed_at: now(),
            declaration: one.declaration.clone(),
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: now(),
            identity_selection_report: None,
        };
        assert_eq!(BoundPair::from_pair(&pair), bound_of(&one, "a"));
        let fresh = view(vec![one]);
        assert_eq!(
            check_noninteractive(
                std::slice::from_ref(&pair),
                &fresh,
                &[exclusive("a", 1)],
                now()
            ),
            Ok(())
        );
        // A stored selection is never what the check reads: the fresh one decides.
        assert_eq!(
            reason(check_noninteractive(&[pair], &fresh, &[], now())),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
    }

    /// ADR-0007 §12.25 item 1 (T01): the check covers every invocation profile. A
    /// shell selection that is exclusive at the declared agent launches only when the
    /// `exec` and `subsystem:sftp` selections are too: an exec-only or subsystem-only
    /// fallback identity refuses (`fallback_identity_interaction`, naming its line),
    /// and so does an exec-only or subsystem-only `IdentityAgent` override, or an
    /// undetermined agent there (`interaction_unknown`). A selection that does not
    /// carry every profile, or whose other profile is undetermined, refuses.
    #[test]
    fn every_invocation_profile_must_be_cleared() {
        let one = declared(1);
        let b = [bound_of(&one, "a")];
        let fresh = view(vec![one]);
        assert_eq!(required_profiles(), ["shell", "exec", "subsystem:sftp"]);
        let line = |n: u32| ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line: n,
        };
        let fallback = |n: u32| {
            let mut e = entry(IdentityEntrySource::User, None, IdentityBacking::Agent);
            e.provenance = Some(line(n));
            e
        };
        let with =
            |profile: &str, report: IdentitySelectionReport, endpoint: Option<EndpointRef>| {
                let mut s = exclusive("a", 1);
                for p in &mut s.profiles {
                    if p.profile == profile {
                        p.report = report.clone();
                        p.endpoint = endpoint.clone();
                    }
                }
                s
            };
        let not_exclusive = |n: u32| IdentitySelectionReport {
            selection: IdentitySelection::NotExclusive,
            entries: vec![managed(1), fallback(n)],
            identities_only: IdentitiesOnly::DeterminedYes,
        };
        let exclusive_report = exclusive("a", 1).report;
        assert_eq!(
            check_pairs(&b, &fresh, &[exclusive("a", 1)], now()),
            Ok(()),
            "control: exclusive everywhere"
        );
        for (profile, n) in [("exec", 11), ("subsystem:sftp", 12)] {
            let r = check_pairs(
                &b,
                &fresh,
                &[with(profile, not_exclusive(n), Some(ep(A)))],
                now(),
            )
            .unwrap_err();
            assert_eq!(
                r.reason,
                PrelaunchReason::FallbackIdentityInteraction,
                "{profile}"
            );
            assert_eq!(r.entries, [line(n)], "{profile} names its fallback line");
            for agent in [Some(ep(B)), None] {
                assert_eq!(
                    reason(check_pairs(
                        &b,
                        &fresh,
                        &[with(profile, exclusive_report.clone(), agent.clone())],
                        now()
                    )),
                    Some((PrelaunchReason::InteractionUnknown, 0)),
                    "{profile} agent {agent:?}"
                );
            }
            // An agent override behind the profile is refused even with a fallback
            // there: the agent is checked first.
            assert_eq!(
                reason(check_pairs(
                    &b,
                    &fresh,
                    &[with(profile, not_exclusive(n), Some(ep(B)))],
                    now()
                )),
                Some((PrelaunchReason::InteractionUnknown, 0))
            );
            // Undetermined there: an entry that may apply (a `Match command` it sits
            // behind, say) is never cleared.
            let mut maybe = fallback(n);
            maybe.certainty = Certainty::Undetermined;
            let undetermined = IdentitySelectionReport {
                selection: IdentitySelection::Undetermined,
                entries: vec![managed(1), maybe],
                identities_only: IdentitiesOnly::DeterminedYes,
            };
            assert_eq!(
                reason(check_pairs(
                    &b,
                    &fresh,
                    &[with(profile, undetermined, Some(ep(A)))],
                    now()
                )),
                Some((PrelaunchReason::FallbackIdentityInteraction, 0)),
                "{profile} undetermined"
            );
        }
        // Fallbacks in both other profiles: each line once, in profile order.
        let mut both = with("exec", not_exclusive(11), Some(ep(A)));
        if let Some(p) = both
            .profiles
            .iter_mut()
            .find(|p| p.profile == "subsystem:sftp")
        {
            p.report = IdentitySelectionReport {
                selection: IdentitySelection::NotExclusive,
                entries: vec![managed(1), fallback(12), fallback(11)],
                identities_only: IdentitiesOnly::DeterminedYes,
            };
        }
        let r = check_pairs(&b, &fresh, &[both], now()).unwrap_err();
        assert_eq!(r.entries, [line(11), line(12)]);
        // A selection without the other profiles is undetermined there.
        let mut shell_only = exclusive("a", 1);
        shell_only.profiles.clear();
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[shell_only], now())),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0))
        );
        let mut renamed = exclusive("a", 1);
        renamed.profiles[0].profile = "exec:git-upload-pack".to_owned();
        assert_eq!(
            reason(check_pairs(&b, &fresh, &[renamed], now())),
            Some((PrelaunchReason::FallbackIdentityInteraction, 0)),
            "a known command is not the unknown-command profile"
        );
    }

    /// Properties over generated pair sets (≥ 256 cases, fixed seed unless
    /// `PROPTEST_RNG_SEED` is set): the check launches exactly when every pair would
    /// launch alone, the refusal names the first pair that would be refused alone with
    /// that pair's own reason, and the verdict does not depend on the other pairs.
    mod props {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::{FileFailurePersistence, RngSeed};

        fn config() -> ProptestConfig {
            let mut c = ProptestConfig {
                cases: 256,
                failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                    "proptest-regressions",
                ))),
                ..ProptestConfig::default()
            };
            if matches!(c.rng_seed, RngSeed::Random) {
                c.rng_seed = RngSeed::Fixed(0x5538_5f65_6c69_6731);
            }
            c
        }

        /// One generated pair: its fresh view, its bound pair and its selection.
        fn pair_case() -> impl Strategy<Value = (u8, u8, u8, u8, u8)> {
            // (fresh interaction, declaration change, selection kind, endpoint, expiry)
            (0u8..4, 0u8..4, 0u8..4, 0u8..3, 0u8..3)
        }

        fn build(n: u8, c: (u8, u8, u8, u8, u8)) -> (IdentityView, BoundPair, FreshSelection) {
            let (interaction, change, selection, endpoint, expiry) = c;
            let base = declared(n);
            let bound = bound_of(&base, &format!("alias{n}"));
            let mut fresh = base;
            fresh.interaction = match interaction {
                0 | 1 => InteractionKind::None,
                2 => InteractionKind::Unknown,
                _ => InteractionKind::ProviderApproval,
            };
            match change {
                1 => fresh.declaration = None,
                2 => {
                    if let Some(d) = fresh.declaration.as_mut() {
                        d.revision += 100;
                    }
                }
                _ => {}
            }
            if let Some(d) = fresh.declaration.as_mut() {
                d.expires_at = match expiry {
                    0 => later(),
                    1 => now(),
                    _ => t("2026-11-01T00:00:00Z"),
                };
            }
            let mut s = match selection {
                0 | 1 => exclusive(&format!("alias{n}"), n),
                2 => sel(
                    &format!("alias{n}"),
                    IdentitySelection::NotExclusive,
                    vec![
                        managed(n),
                        entry(IdentityEntrySource::User, None, IdentityBacking::Agent),
                    ],
                ),
                _ => sel(
                    &format!("alias{n}"),
                    IdentitySelection::Exclusive,
                    vec![managed(n + 50)],
                ),
            };
            s.endpoint = match endpoint {
                0 | 1 => Some(ep(A)),
                _ => Some(ep(B)),
            };
            (fresh, bound, synced(s))
        }

        proptest! {
            #![proptest_config(config())]
            #[test]
            fn launches_exactly_when_every_pair_would_alone(
                cases in proptest::collection::vec(pair_case(), 0..5),
            ) {
                let built: Vec<_> = cases
                    .iter()
                    .enumerate()
                    .map(|(i, c)| build(u8::try_from(i + 1).unwrap(), *c))
                    .collect();
                let fresh = view(built.iter().map(|(v, _, _)| v.clone()).collect());
                let bound: Vec<BoundPair> = built.iter().map(|(_, b, _)| b.clone()).collect();
                let selections: Vec<FreshSelection> = built.iter().map(|(_, _, s)| s.clone()).collect();
                let alone: Vec<Option<PrelaunchReason>> = built
                    .iter()
                    .map(|(v, b, s)| {
                        check_pairs(
                            std::slice::from_ref(b),
                            &view(vec![v.clone()]),
                            std::slice::from_ref(s),
                            now(),
                        )
                        .err()
                        .map(|e| e.reason)
                    })
                    .collect();
                let all = check_pairs(&bound, &fresh, &selections, now());
                match alone.iter().position(Option::is_some) {
                    None => prop_assert_eq!(all, Ok(())),
                    Some(first) => {
                        let e = all.unwrap_err();
                        prop_assert_eq!(e.pair, first);
                        prop_assert_eq!(Some(e.reason), alone[first]);
                    }
                }
            }
        }
    }
}
