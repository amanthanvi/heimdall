//! ⟨M03⟩ The managed preparation's computation (ADR-0008 D6 items 0, 6–7; D10 item 4;
//! D12): what `read_sources` reads (through the source trait [`ManagedSourceRead`],
//! reading R6) and what `prepare_from` computes from that snapshot and the effect
//! driver's results. Nothing here runs an effect or reads the store.
//!
//! **Refusals** ([`ManagedRefusal`]): each carries its stable reason (the
//! `envelope::reason` values), so the runtime's mapping (U10) can report it; through
//! the port every refusal is `AdapterError::CapabilityUnavailable` (no fallback to the
//! existing identity: D11 item 3, spec §15.2).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use heimdall_app::enrollment::EnrollmentHost;
use heimdall_app::managed::driver_results;
use heimdall_app::operations::MANAGED_CERTIFICATE;
use heimdall_app::operations::unattended_refusal;
use heimdall_app::ports::{
    AdapterError, IntegrationSnapshot, IssuerStatusSnapshot, ManagedPrepared, ManagedSlot,
    ManagedSources, PrepareOutcome, PreparePair, PrepareRequest, PreparedCertificate,
    TargetEvaluator,
};
use heimdall_contract::Timestamp;
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, GrantId};
use heimdall_contract::issuer::IssuerState;
use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
use heimdall_contract::provider::{
    EndpointRef, EvidenceBasis, IdentitySelection, InteractionKind, NoninteractiveEligibility,
};
use heimdall_contract::request::{ConsumerIntegration, PairIntegration};
use heimdall_credential::endpoints::{EndpointLayout, EndpointTag};
use heimdall_domain::claims::{CLAIMS, Claim, Platform};
use heimdall_domain::enrollment::{EnrollmentRecord, EnrollmentState, TargetEvaluation};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::issuance::IssuanceEntry;
use heimdall_domain::managed::OwnedConnection;
use heimdall_domain::scope::AccessPair;

use super::report::{
    self, ManagedReport, PairEvidence, ReportContext, SelectionClass, current_platform,
};

/// The terms of a grant the report needs (its origin's lock behaviour and the
/// effective connection policy; U6-Q5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GrantTerms {
    /// The lock behaviour recorded with the grant.
    pub lock_behavior: LockBehavior,
    /// The effective (strictest) connection policy.
    pub policy: ConnectionPolicy,
}

/// Everything the managed adapter reads (reading R6: the M02 `IntegrationSources`
/// pattern). U10 implements it over the store; every default claims nothing (fail
/// closed): no enrollment (so every pair is `pair_not_enrolled`), no CA, no slot, no
/// issuer (not ready), no driver results (so `prepare_from` refuses), the compiled
/// claim table only.
pub trait ManagedSourceRead: Send + Sync {
    /// The enrollments of `pairs` (only `verified` ones count).
    fn enrollments(&self, pairs: &[AccessPair]) -> Vec<EnrollmentRecord> {
        let _ = pairs;
        Vec::new()
    }

    /// Each pair's issuing-CA set (`pair_preferences.issuing_cas`).
    fn issuing_cas(&self, pairs: &[AccessPair]) -> BTreeMap<AccessPair, BTreeSet<CaFingerprint>> {
        let _ = pairs;
        BTreeMap::new()
    }

    /// The pairs' slots.
    fn slots(&self, pairs: &[AccessPair]) -> Vec<ManagedSlot> {
        let _ = pairs;
        Vec::new()
    }

    /// The applicable claim-table entries: by default the compiled table's entries
    /// for the running platform (`heimdall_domain::claims::CLAIMS`; empty in the M03
    /// baseline). A test source may supply a fixture table.
    fn claims(&self) -> Vec<Claim> {
        let p = current_platform();
        CLAIMS.iter().filter(|c| c.platform == p).copied().collect()
    }

    /// The issuer's last observed status.
    fn issuer(&self) -> Option<IssuerStatusSnapshot> {
        None
    }

    /// The effect driver's results for `pairs`, when the driver ran.
    fn prepared(&self, pairs: &[AccessPair]) -> Option<ManagedPrepared> {
        let _ = pairs;
        None
    }

    /// The grant's terms. **In-memory** (it is read inside the bound, U6-Q5): U10
    /// records them when the activation transaction commits. Default: none, and
    /// missing terms refuse the computation with [`GRANT_TERMS_UNAVAILABLE`] (ADR-0008
    /// §17.20 item 14, U6-Q5 amended: never a default `continue`, which could report a
    /// `revoke_on_lock` grant's lock continuity as `verified`).
    fn terms(&self, grant: &GrantId) -> Option<GrantTerms> {
        let _ = grant;
        None
    }

    /// The grant and every descendant its revocation cascades to (D7 item 6).
    /// Default: the grant alone.
    fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
        vec![grant.clone()]
    }

    /// Every issuance entry of `grants` (any state; only `reserved` and `published`
    /// count in a residual).
    fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
        let _ = grants;
        Vec::new()
    }

    /// Whether the CA was restored from a key-only backup (D4 item 4): every residual
    /// is then `unbounded_unknown`.
    fn key_only_restore(&self) -> bool {
        false
    }

    /// The outcome the effect driver recorded for `grant`'s preparation under
    /// `effect_token` (what `reconcile` answers `Applied` with). Default: none, so a
    /// reconcile that finds everything installed is still `Unknown` (fail closed).
    fn recorded_outcome(&self, grant: &GrantId, effect_token: &str) -> Option<PrepareOutcome> {
        let _ = (grant, effect_token);
        None
    }

    /// The owned connections of `grants` (D7 item 2 step 6).
    fn owned_connections(&self, grants: &[GrantId]) -> Vec<OwnedConnection> {
        let _ = grants;
        Vec::new()
    }

    /// ⟨§17.21 item 11⟩ The static observation of the managed `aliases` (D10 item 6's
    /// classification: the projection writer's `observe` over the stored projection
    /// record, as M02's existing-access sources read it). Default: none, so every
    /// pair's selection is `undetermined` (fail closed).
    fn observations(&self, aliases: &[String]) -> Vec<AliasObservation> {
        let _ = aliases;
        Vec::new()
    }

    /// ⟨§17.22 item 7⟩ The current static evaluation of a managed alias (the runtime's
    /// `TargetEvaluator`), for the evidence comparison [`snapshot`] runs. Default:
    /// none, so no evidence holds (every pair's `destination_scope` is `unknown`).
    fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
        let _ = alias;
        None
    }

    /// ⟨§17.22 item 7⟩ The current verifying client's version line (the enrollment
    /// host's `client_version`, `OpenSSH_10.5p1, …`). Default: none, so no evidence
    /// holds.
    fn client_version(&self) -> Option<String> {
        None
    }
}

/// ⟨§17.22 item 7⟩ The inputs of the evidence comparison: the runtime's target
/// evaluator and its verifying client's version line, read when the sources are read.
pub trait EvidenceFeed: Send + Sync {
    /// The current evaluation of `alias` (`None`: not evaluable).
    fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation>;
    /// The current verifying client's version line.
    fn client_version(&self) -> Option<String>;
}

/// ⟨§17.22 item 7⟩ An [`EvidenceFeed`] over a target evaluator and an enrollment host
/// (the runtime's own: the same evaluator and host the enrollment driver uses).
pub struct TargetAndClient {
    /// The target evaluator.
    pub target: Arc<dyn TargetEvaluator>,
    /// The enrollment host (its `client_version`).
    pub host: Arc<dyn EnrollmentHost>,
}

impl EvidenceFeed for TargetAndClient {
    fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
        Some(self.target.evaluate(alias))
    }

    fn client_version(&self) -> Option<String> {
        self.host.client_version()
    }
}

/// ⟨§17.22 item 7⟩ `inner` with the evidence comparison's inputs from `feed`; every
/// other read is `inner`'s.
pub struct WithEvidenceFeed {
    /// The sources.
    pub inner: Arc<dyn ManagedSourceRead>,
    /// The comparison's inputs.
    pub feed: Arc<dyn EvidenceFeed>,
}

impl ManagedSourceRead for WithEvidenceFeed {
    fn enrollments(&self, pairs: &[AccessPair]) -> Vec<EnrollmentRecord> {
        self.inner.enrollments(pairs)
    }
    fn issuing_cas(&self, pairs: &[AccessPair]) -> BTreeMap<AccessPair, BTreeSet<CaFingerprint>> {
        self.inner.issuing_cas(pairs)
    }
    fn slots(&self, pairs: &[AccessPair]) -> Vec<ManagedSlot> {
        self.inner.slots(pairs)
    }
    fn claims(&self) -> Vec<Claim> {
        self.inner.claims()
    }
    fn issuer(&self) -> Option<IssuerStatusSnapshot> {
        self.inner.issuer()
    }
    fn prepared(&self, pairs: &[AccessPair]) -> Option<ManagedPrepared> {
        self.inner.prepared(pairs)
    }
    fn terms(&self, grant: &GrantId) -> Option<GrantTerms> {
        self.inner.terms(grant)
    }
    fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
        self.inner.cascade(grant)
    }
    fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
        self.inner.issuance_entries(grants)
    }
    fn key_only_restore(&self) -> bool {
        self.inner.key_only_restore()
    }
    fn recorded_outcome(&self, grant: &GrantId, effect_token: &str) -> Option<PrepareOutcome> {
        self.inner.recorded_outcome(grant, effect_token)
    }
    fn owned_connections(&self, grants: &[GrantId]) -> Vec<OwnedConnection> {
        self.inner.owned_connections(grants)
    }
    fn observations(&self, aliases: &[String]) -> Vec<AliasObservation> {
        self.inner.observations(aliases)
    }
    fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
        self.feed.evaluate_target(alias)
    }
    fn client_version(&self) -> Option<String> {
        self.feed.client_version()
    }
}

/// ⟨§17.22 item 7⟩ The comparison at `read_sources` time (D5 §6.5: "the
/// `TargetEvaluator` comparison, run when `inspect` or `ensure` touches the pair"):
/// each enrollment of `pairs` keeps its evidence in the snapshot only when it still
/// holds (`heimdall_app::enrollment::evidence_holds`: the pair's alias evaluates to
/// exactly the approved target, and the evidence names the current client); otherwise
/// the snapshot's copy carries **no evidence**, so the report's `destination_scope` is
/// `unknown` and a minimum that needs it fails, whatever the record's state and
/// whatever a later network attempt finds. A pair without an alias has no
/// evaluation. Nothing is written: the record's own state and evidence are the
/// enrollment driver's.
pub fn invalidate_evidence(
    sources: &dyn ManagedSourceRead,
    pairs: &[PreparePair],
    enrollments: &mut [EnrollmentRecord],
) {
    if enrollments.iter().all(|e| e.evidence.is_none()) {
        return;
    }
    let client = sources.client_version();
    let mut evaluations: BTreeMap<(String, String), Option<TargetEvaluation>> = BTreeMap::new();
    for e in enrollments.iter_mut().filter(|e| e.evidence.is_some()) {
        let alias = pairs
            .iter()
            .find(|p| p.destination == e.destination && p.account == e.account)
            .and_then(|p| p.alias.clone());
        let eval = alias.and_then(|a| {
            evaluations
                .entry((e.destination.as_str().to_owned(), a.clone()))
                .or_insert_with(|| sources.evaluate_target(&a))
                .clone()
        });
        if !heimdall_app::enrollment::evidence_holds(e, eval.as_ref(), client.as_deref()) {
            e.evidence = None;
        }
    }
}

/// ⟨§17.21 item 11⟩ D10 item 6's classification of the request's pairs, as the report
/// takes it: each pair's managed-alias observation (`identity_selection.selection`:
/// `exclusive`, `not_exclusive`, anything else `undetermined`; a pair without an alias
/// or without an observation is `undetermined`), the weakest over the pairs
/// (`undetermined` < `not_exclusive` < `exclusive`). No pair: `undetermined`.
#[must_use]
pub fn selection_class(pairs: &[PreparePair], observations: &[AliasObservation]) -> SelectionClass {
    fn rank(c: SelectionClass) -> u8 {
        match c {
            SelectionClass::Exclusive => 2,
            SelectionClass::NotExclusive => 1,
            SelectionClass::Undetermined => 0,
        }
    }
    let of = |p: &PreparePair| -> SelectionClass {
        let observed = p.alias.as_deref().and_then(|alias| {
            observations
                .iter()
                .find(|o| o.alias == alias)
                .and_then(|o| o.identity_selection.as_ref())
        });
        match observed.map(|r| r.selection) {
            Some(IdentitySelection::Exclusive) => SelectionClass::Exclusive,
            Some(IdentitySelection::NotExclusive) => SelectionClass::NotExclusive,
            _ => SelectionClass::Undetermined,
        }
    };
    pairs
        .iter()
        .map(of)
        .min_by_key(|c| rank(*c))
        .unwrap_or(SelectionClass::Undetermined)
}

/// Sources that claim nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoManagedSources;

impl ManagedSourceRead for NoManagedSources {}

/// `read_sources` for the managed adapter: the snapshot's `managed` part, read
/// through `sources` (U0b row 21).
#[must_use]
pub fn snapshot(sources: &dyn ManagedSourceRead, pairs: &[PreparePair]) -> IntegrationSnapshot {
    let request_pairs = pairs;
    // ⟨§17.21 item 11⟩ The request's managed aliases' static observation (D10 item 6).
    let aliases: Vec<String> = pairs.iter().filter_map(|p| p.alias.clone()).collect();
    let observations = if aliases.is_empty() {
        Vec::new()
    } else {
        sources.observations(&aliases)
    };
    let pairs: Vec<AccessPair> = pairs
        .iter()
        .map(|p| AccessPair {
            destination: p.destination.clone(),
            account: p.account.clone(),
        })
        .collect();
    let mut enrollments = sources.enrollments(&pairs);
    invalidate_evidence(sources, request_pairs, &mut enrollments);
    IntegrationSnapshot {
        managed: Some(ManagedSources {
            enrollments,
            issuing_cas: sources.issuing_cas(&pairs),
            slots: sources.slots(&pairs),
            claims: sources.claims(),
            issuer: sources.issuer(),
            prepared: sources.prepared(&pairs),
        }),
        observations,
        ..IntegrationSnapshot::default()
    }
}

/// Why a managed preparation is refused, with its stable reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedRefusal {
    /// The stable reason (`pair_not_enrolled`, `lock_continuity_unverified`, …).
    pub reason: &'static str,
}

impl ManagedRefusal {
    /// The port error (`CAPABILITY_UNAVAILABLE`; no fallback).
    #[must_use]
    pub fn into_adapter_error(self) -> AdapterError {
        AdapterError::CapabilityUnavailable
    }
}

/// The offline bound refusal (D6 item 6: `required.offline_until` later than the
/// admission bound).
pub const OFFLINE_UNTIL_BEYOND_BOUND: &str = "offline_until_beyond_bound";
/// The refusal of a minimum the managed report does not meet (destination scope,
/// capabilities).
pub const MINIMUM_NOT_MET: &str = "minimum_not_met";
/// ⟨§17.20 item 14, U6-Q5⟩ The `AdapterError::Unavailable` text when the grant's terms
/// were not recorded: the report is not computed.
pub const GRANT_TERMS_UNAVAILABLE: &str = "grant_terms_unavailable";
/// ⟨§17.20 item 8⟩ The `AdapterError::Protocol` text of a prepared certificate whose
/// `valid_before` is not after the observation time.
pub const PREPARED_CERTIFICATE_EXPIRED: &str = "prepared_certificate_expired";
/// ⟨§17.20 item 8⟩ The `AdapterError::Protocol` text of a prepared certificate whose
/// `valid_after` is after the observation time, or whose validity start is not known
/// for the installed entry (fail closed).
pub const PREPARED_CERTIFICATE_NOT_YET_VALID: &str = "prepared_certificate_not_yet_valid";

/// A pair has a `verified` enrollment and a non-empty issuing-CA set.
#[must_use]
pub fn pair_enrolled(managed: &ManagedSources, pair: &AccessPair) -> bool {
    let verified = managed.enrollments.iter().any(|e| {
        e.destination == pair.destination
            && e.account == pair.account
            && e.state == EnrollmentState::Verified
    });
    let cas = managed.issuing_cas.get(pair).is_some_and(|s| !s.is_empty());
    verified && cas
}

/// Every pair is enrolled (`pair_not_enrolled` otherwise; D6 item 1).
///
/// # Errors
/// [`ManagedRefusal`].
pub fn check_enrolled(
    managed: &ManagedSources,
    pairs: &[AccessPair],
) -> Result<(), ManagedRefusal> {
    if !pairs.is_empty() && pairs.iter().all(|p| pair_enrolled(managed, p)) {
        Ok(())
    } else {
        Err(ManagedRefusal {
            reason: reason::PAIR_NOT_ENROLLED,
        })
    }
}

/// The issuer is `ready` in the snapshot.
#[must_use]
pub fn issuer_ready(managed: &ManagedSources) -> bool {
    managed
        .issuer
        .as_ref()
        .is_some_and(|s| s.status.state == IssuerState::Ready)
}

/// The driver's results cover exactly `pairs`, one certificate each, none valid past
/// the grant's effective deadline (D6 item 3; ADR-0005 §3.4: `valid_before` ≤ D), and
/// each valid **now** (§17.20 item 8; W3-R06): `valid_after ≤ now < valid_before`.
/// `valid_after` is the installed entry's ([`super::effects::InstalledValidity`],
/// through `valid_after_of`; `None` when the installed entry is not this certificate's
/// or is unknown, which refuses).
///
/// # Errors
/// `AdapterError::Protocol` when they do not: `prepared_results_mismatch`,
/// [`PREPARED_CERTIFICATE_EXPIRED`], [`PREPARED_CERTIFICATE_NOT_YET_VALID`].
pub fn check_prepared(
    prepared: &ManagedPrepared,
    pairs: &[AccessPair],
    deadline: Timestamp,
    now: Timestamp,
    valid_after_of: &dyn Fn(&PreparedCertificate) -> Option<Timestamp>,
) -> Result<(), AdapterError> {
    let mismatch = || AdapterError::Protocol("prepared_results_mismatch".to_owned());
    let mut seen = BTreeSet::new();
    for c in &prepared.certificates {
        if !pairs.contains(&c.pair) || !seen.insert(c.pair.clone()) || c.valid_before > deadline {
            return Err(mismatch());
        }
        if c.valid_before <= now {
            return Err(AdapterError::Protocol(
                PREPARED_CERTIFICATE_EXPIRED.to_owned(),
            ));
        }
        if valid_after_of(c).is_none_or(|after| after > now) {
            return Err(AdapterError::Protocol(
                PREPARED_CERTIFICATE_NOT_YET_VALID.to_owned(),
            ));
        }
    }
    if seen.len() != pairs.len() {
        return Err(mismatch());
    }
    Ok(())
}

/// The minimums of `req` against the computed `report` (R-AU-08; D6 items 6–7).
///
/// # Errors
/// [`ManagedRefusal`] with `offline_until_beyond_bound`, D6 item 7's reasons
/// (`lock_continuity_unverified`, `lock_revokes_chosen`, `interaction_required`), or
/// `minimum_not_met`.
pub fn check_minimums(
    req: &PrepareRequest<'_>,
    report: &ManagedReport,
    terms: &GrantTerms,
    capabilities: &BTreeSet<heimdall_contract::request::Capability>,
) -> Result<(), ManagedRefusal> {
    if req
        .required
        .offline_until
        .is_some_and(|t| t > report.offline_until)
    {
        return Err(ManagedRefusal {
            reason: OFFLINE_UNTIL_BEYOND_BOUND,
        });
    }
    if req.required.unattended
        && let Some(why) =
            unattended_refusal(true, report.lock_claim_verified, terms.lock_behavior, false)
    {
        return Err(ManagedRefusal { reason: why });
    }
    if req
        .required
        .destination_scope_at_least
        .is_some_and(|min| report.enforcement.destination_scope < min)
        || !req.required.capabilities.is_subset(capabilities)
    {
        return Err(ManagedRefusal {
            reason: MINIMUM_NOT_MET,
        });
    }
    Ok(())
}

/// The binding endpoint of the driver's materialized files (D10 item 4, wave-2
/// request: `consumer.signing_endpoint` names the **binding** endpoint), from the
/// directory's tag and the runtime's endpoint layout. ⟨§17.23 item 6⟩ The endpoint the
/// materialization reports it created comes first; the layout's form of the
/// directory's tag is only for a materialization that reused a running endpoint.
#[must_use]
pub fn binding_endpoint(
    prepared: &ManagedPrepared,
    layout: Option<&EndpointLayout>,
) -> Option<EndpointRef> {
    let materialized = prepared.materialized.as_ref()?;
    if let Some(created) = &materialized.endpoint {
        return Some(created.clone());
    }
    let dir = &materialized.directory;
    let tag = EndpointTag::parse(dir.file_name()?.to_str()?)?;
    Some(layout?.binding(&tag))
}

/// The per-pair integrations of a managed grant. The selection stays `undetermined`
/// until U0b phase 2 classifies managed aliases (U6-Q3); a managed key needs no
/// interaction (`none`, inferred: the signer is in-process).
#[must_use]
pub fn pair_integrations(
    pairs: &[PreparePair],
    endpoint: Option<&EndpointRef>,
    observations: &[AliasObservation],
    now: Timestamp,
) -> Vec<PairIntegration> {
    pairs
        .iter()
        .map(|p| {
            // ⟨wave 4, integrator; §17.21 item 11, R2C-Q1⟩ Each pair's own D10 item 6
            // classification (its managed alias's static observation); absent:
            // `undetermined`. The M02 commit re-check refuses a non-exclusive managed
            // pair non-interactively (`fresh_fallback_refusal`).
            let report = p.alias.as_deref().and_then(|alias| {
                observations
                    .iter()
                    .find(|o| o.alias == alias)
                    .and_then(|o| o.identity_selection.clone())
            });
            (p, report)
        })
        .map(|(p, report)| PairIntegration {
            destination: p.destination.clone(),
            account: p.account.clone(),
            identity: p.identity.id.clone(),
            mechanism: MANAGED_CERTIFICATE.to_owned(),
            endpoint: endpoint.cloned(),
            alias: p.alias.clone(),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Inferred,
            declared_at: None,
            identity_selection: report
                .as_ref()
                .map_or(IdentitySelection::Undetermined, |r| r.selection),
            selection_observed_at: now,
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: now,
            identity_selection_report: report,
        })
        .collect()
}

/// The evidence of each pair's enrollment: the newest of its `verified` enrollments
/// **under the CA of the certificate being prepared** for the pair (⟨§17.22 item 7⟩:
/// another CA's evidence says nothing about this certificate's principals; a pair with
/// no prepared certificate has none). Evidence the comparison invalidated is already
/// gone from the snapshot ([`invalidate_evidence`]). ⟨W4-C02⟩ The selection is
/// [`heimdall_app::operations::pair_evidence_under_ca`], the one a managed follower's
/// commit uses for its installed certificate's CA.
#[must_use]
pub fn pair_evidence<'a>(
    managed: &'a ManagedSources,
    pairs: &'a [AccessPair],
    prepared: &ManagedPrepared,
) -> Vec<PairEvidence<'a>> {
    pairs
        .iter()
        .filter_map(|p| {
            let ca = &prepared.certificates.iter().find(|c| &c.pair == p)?.ca;
            heimdall_app::operations::pair_evidence_under_ca(managed, p, ca).map(|e| (p, e))
        })
        .collect()
}

/// `prepare_from` for `managed_certificate` (D6 item 0): computes the outcome from the
/// snapshot and the driver's results; reads nothing, causes nothing.
///
/// # Errors
/// `AdapterError::Protocol(MANAGED_PREPARE_WITHOUT_DRIVER)` without driver results;
/// `Unavailable(GRANT_TERMS_UNAVAILABLE)` without the grant's terms (U6-Q5 amended);
/// `CapabilityUnavailable` for a refusal ([`ManagedRefusal`]); `Protocol` for driver
/// results that do not match the request or a certificate not valid now
/// ([`check_prepared`]).
pub fn outcome(
    req: &PrepareRequest<'_>,
    sources: &IntegrationSnapshot,
    terms: Option<&GrantTerms>,
    layout: Option<&EndpointLayout>,
    platform: Platform,
    capabilities: &BTreeSet<heimdall_contract::request::Capability>,
    valid_after_of: &dyn Fn(&PreparedCertificate) -> Option<Timestamp>,
) -> Result<(PrepareOutcome, ManagedReport), AdapterError> {
    let prepared = driver_results(sources)?;
    let Some(managed) = sources.managed.as_ref() else {
        return Err(AdapterError::Protocol(
            heimdall_app::managed::MANAGED_PREPARE_WITHOUT_DRIVER.to_owned(),
        ));
    };
    let pairs: Vec<AccessPair> = req.scope.pairs.iter().cloned().collect();
    check_enrolled(managed, &pairs).map_err(ManagedRefusal::into_adapter_error)?;
    check_prepared(
        prepared,
        &pairs,
        req.grant.deadline.effective,
        req.now,
        valid_after_of,
    )?;
    // No report without the grant's recorded terms (U6-Q5 amended).
    let Some(terms) = terms else {
        return Err(AdapterError::Unavailable(
            GRANT_TERMS_UNAVAILABLE.to_owned(),
        ));
    };
    let evidence = pair_evidence(managed, &pairs, prepared);
    let ctx = ReportContext {
        platform,
        lock_behavior: terms.lock_behavior,
        policy: terms.policy,
        issuer_ready: issuer_ready(managed),
        reissue_pending: false,
        now: req.now,
        // ⟨§17.21 item 11⟩ D10 item 6's classification, weakest over the pairs.
        selection: selection_class(req.pairs, &sources.observations),
    };
    let report = report::compute(req.grant, prepared, &managed.claims, &ctx, &evidence);
    check_minimums(req, &report, terms, capabilities)
        .map_err(ManagedRefusal::into_adapter_error)?;
    let endpoint = binding_endpoint(prepared, layout);
    let integration = ConsumerIntegration {
        signing_endpoint: endpoint.as_ref().map(|e| e.locator.clone()),
        pairs: pair_integrations(req.pairs, endpoint.as_ref(), &sources.observations, req.now),
        ..ConsumerIntegration::default()
    };
    let outcome = PrepareOutcome {
        usable_until: report.usable_until,
        offline_until: report.offline_until,
        refresh_dependency: report.refresh_dependency,
        enforcement: EnforcementEvidence {
            report: report.enforcement.clone(),
            evidence: Vec::new(),
        },
        credential_ref: prepared.instance.to_string(),
        availability: report.availability,
        provider: None,
        integration,
    };
    Ok((outcome, report))
}
