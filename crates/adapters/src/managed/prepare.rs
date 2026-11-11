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

use heimdall_app::managed::driver_results;
use heimdall_app::operations::MANAGED_CERTIFICATE;
use heimdall_app::operations::unattended_refusal;
use heimdall_app::ports::{
    AdapterError, IntegrationSnapshot, IssuerStatusSnapshot, ManagedPrepared, ManagedSlot,
    ManagedSources, PrepareOutcome, PreparePair, PrepareRequest, PreparedCertificate,
};
use heimdall_contract::Timestamp;
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
use heimdall_domain::enrollment::{EnrollmentRecord, EnrollmentState};
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
}

/// Sources that claim nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoManagedSources;

impl ManagedSourceRead for NoManagedSources {}

/// `read_sources` for the managed adapter: the snapshot's `managed` part, read
/// through `sources` (U0b row 21).
#[must_use]
pub fn snapshot(sources: &dyn ManagedSourceRead, pairs: &[PreparePair]) -> IntegrationSnapshot {
    let pairs: Vec<AccessPair> = pairs
        .iter()
        .map(|p| AccessPair {
            destination: p.destination.clone(),
            account: p.account.clone(),
        })
        .collect();
    IntegrationSnapshot {
        managed: Some(ManagedSources {
            enrollments: sources.enrollments(&pairs),
            issuing_cas: sources.issuing_cas(&pairs),
            slots: sources.slots(&pairs),
            claims: sources.claims(),
            issuer: sources.issuer(),
            prepared: sources.prepared(&pairs),
        }),
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
/// directory's tag and the runtime's endpoint layout.
#[must_use]
pub fn binding_endpoint(
    prepared: &ManagedPrepared,
    layout: Option<&EndpointLayout>,
) -> Option<EndpointRef> {
    let dir = &prepared.materialized.as_ref()?.directory;
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
    now: Timestamp,
) -> Vec<PairIntegration> {
    pairs
        .iter()
        .map(|p| PairIntegration {
            destination: p.destination.clone(),
            account: p.account.clone(),
            identity: p.identity.id.clone(),
            mechanism: MANAGED_CERTIFICATE.to_owned(),
            endpoint: endpoint.cloned(),
            alias: p.alias.clone(),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Inferred,
            declared_at: None,
            identity_selection: IdentitySelection::Undetermined,
            selection_observed_at: now,
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: now,
            identity_selection_report: None,
        })
        .collect()
}

/// The evidence of each pair's enrollment (the newest verified one).
#[must_use]
pub fn pair_evidence<'a>(
    managed: &'a ManagedSources,
    pairs: &'a [AccessPair],
) -> Vec<PairEvidence<'a>> {
    pairs
        .iter()
        .filter_map(|p| {
            managed
                .enrollments
                .iter()
                .filter(|e| {
                    e.destination == p.destination
                        && e.account == p.account
                        && e.state == EnrollmentState::Verified
                })
                .filter_map(|e| e.evidence.as_ref())
                .max_by_key(|e| e.verified_at)
                .map(|e| (p, e))
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
    let evidence = pair_evidence(managed, &pairs);
    let ctx = ReportContext {
        platform,
        lock_behavior: terms.lock_behavior,
        policy: terms.policy,
        issuer_ready: issuer_ready(managed),
        reissue_pending: false,
        now: req.now,
        selection: SelectionClass::Undetermined,
    };
    let report = report::compute(req.grant, prepared, &managed.claims, &ctx, &evidence);
    check_minimums(req, &report, terms, capabilities)
        .map_err(ManagedRefusal::into_adapter_error)?;
    let endpoint = binding_endpoint(prepared, layout);
    let integration = ConsumerIntegration {
        signing_endpoint: endpoint.as_ref().map(|e| e.locator.clone()),
        pairs: pair_integrations(req.pairs, endpoint.as_ref(), req.now),
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
