//! ⟨M03⟩ The managed credential adapter (m03-plan U6; ADR-0008 D6, D7, D10, D12;
//! rulings §17.3, §17.4, §17.17–§17.19 win over the D text).
//!
//! * [`ManagedCertificateAdapter`] implements `app::ports::CredentialAdapter` for the
//!   mechanism `managed_certificate` (`external_side_effects`,
//!   `remote_credential_effect`, no interaction; `lock_continuity` from the claim
//!   table for the running platform, `Unknown` without an entry).
//!   * `read_sources` reads through [`prepare::ManagedSourceRead`] (reading R6: no
//!     `adapters → store` edge; U10 implements it over the store; the defaults claim
//!     nothing) into `IntegrationSnapshot.managed`.
//!   * `prepare_from` only **computes** the outcome from the snapshot and the effect
//!     driver's results (`app::managed::driver_results`; without them
//!     `AdapterError::Protocol(MANAGED_PREPARE_WITHOUT_DRIVER)`). `prepare` (no
//!     snapshot) refuses the same way. The consumer integration names the
//!     **binding** endpoint as `signing_endpoint` (D6 item 1 step 6, D10 item 4).
//!   * `renew` is D6 item 4's re-issue. It cannot run the stage sequence itself (that
//!     is `app::managed::drive_preparation`, U10's, failing closed; reading R5): it
//!     refuses what the request alone shows ineligible, then fails closed with
//!     [`RENEW_THROUGH_DRIVER`]. The supervisor's `managed_reissue_pass` (U10)
//!     computes the outcome with [`ManagedCertificateAdapter::reissue_from`], which
//!     holds only when [`reissue::eligible`] does and never widens the grant.
//!   * `reconcile`: `NotApplied` when nothing is published, `Applied` when every pair
//!     is published and installed (with the outcome U10 recorded), else `Unknown`.
//!   * `revoke(grant, now)` (D7 item 2): K_env of the grant and of its cascade is
//!     destroyed (zeroized and unlisted, in memory, under the gates the caller holds);
//!     the residual is the maximum `valid_before` over `reserved`|`published` entries
//!     (voided excluded), and `remote_effects` has one row per (destination,
//!     account) with its clock and D7 item 3 status. Files are not removed here (D7
//!     item 2 step 4: the cleanup after the gates).
//! * [`effects::ManagedEffectsImpl`] implements `app::ports::ManagedEffects`.
//! * [`reissue`], [`report`] and [`files`] are pure computations and file work.
//!
//! **Drop contract** (`app::ports::CredentialAdapter`): no call spawns anything; every
//! await is the signer table's install view under `effects`' own bound.

pub mod effects;
pub mod files;
pub mod prepare;
pub mod reissue;
pub mod report;

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use heimdall_app::managed::MANAGED_PREPARE_WITHOUT_DRIVER;
use heimdall_app::operations::MANAGED_CERTIFICATE;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot,
    InteractionRequirement, LockContinuity, ManagedEffects, PrepareOutcome, PreparePair,
    PrepareRequest, PreparedCertificate, ReconcileOutcome, RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DestinationId, GrantId};
use heimdall_contract::managed::{LockBehavior, ResidualStatus};
use heimdall_contract::request::{
    Capability, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
    NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
};
use heimdall_credential::endpoints::EndpointLayout;
use heimdall_domain::claims::{Claim, Platform};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{GrantOrigin, GrantSnapshot};
use heimdall_domain::issuance::{IssuanceEntry, IssuanceState};
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::scope::AccessPair;
use heimdall_domain::time::{Admission, TimeStatus};

use self::effects::ManagedEffectsImpl;
use self::prepare::{GrantTerms, ManagedSourceRead};
use self::reissue::{ReissueRefusal, StoreRead};

/// The `AdapterError::Protocol` text of a `renew` called through the port: a re-issue
/// runs through the effect driver's `managed_reissue_pass` (U10), never inside one
/// bounded adapter call (ADR-0008 D6 items 0 and 4; reading R5).
pub const RENEW_THROUGH_DRIVER: &str =
    "managed re-issue runs through the effect driver (managed_reissue_pass)";

/// The capabilities a managed certificate realizes: SSH authentication, and agent
/// forwarding only through its explicit extension (ADR-0005 §3.4).
#[must_use]
pub fn managed_capabilities() -> BTreeSet<Capability> {
    [Capability::SshAuthentication, Capability::AgentForwarding]
        .into_iter()
        .collect()
}

/// `lock_continuity` from the claim table for `platform` (`Unknown` without an
/// entry; the M03 baseline table is empty).
#[must_use]
pub fn lock_continuity_from(claims: &[Claim], platform: &Platform) -> LockContinuity {
    if report::claimed(claims, platform, report::FIELD_LOCK_CONTINUITY, "verified") {
        LockContinuity::Verified
    } else {
        LockContinuity::Unknown
    }
}

/// The baseline report a managed grant can claim with an empty claim table: the
/// limitations and the binding's own configuration only (D12 item 3).
#[must_use]
pub fn baseline_enforcement() -> Enforcement {
    Enforcement {
        destination_scope: DestinationScopeEnforcement::Unknown,
        new_authentication_expiry: NewAuthenticationExpiry::Unknown,
        workload_isolation: WorkloadIsolation::SharedOsUser,
        existing_connections: ExistingConnectionsPolicy::Unknown,
        revocation: RevocationStatus::Unknown,
        identity_selection: Some(heimdall_contract::managed::IdentitySelectionEnforcement::Unknown),
        new_signing_expiry: Some(heimdall_contract::managed::NewSigningExpiry::Unknown),
        owned_multiplexing: Some(heimdall_contract::managed::OwnedMultiplexing::Disabled),
        remote_processes: Some(heimdall_contract::managed::RemoteProcesses::NotTerminated),
        unmanaged_connections: Some(
            heimdall_contract::managed::UnmanagedConnections::NotControlled,
        ),
        issuer_isolation: Some(heimdall_contract::managed::IssuerIsolation::SameUserProcess),
    }
}

/// What [`ManagedCertificateAdapter::reissue_from`] needs beside the request: the
/// grant as the store holds it and the time assessment, read in one store
/// transaction by the supervisor's `managed_reissue_pass` (U10).
#[derive(Debug, Clone, Copy)]
pub struct ReissueInput<'a> {
    /// The stored grant.
    pub stored: &'a GrantSnapshot,
    /// Its recorded origin.
    pub origin: &'a GrantOrigin,
    /// The gate's verdict.
    pub time: &'a TimeStatus,
    /// The admission check.
    pub admission: &'a Admission,
    /// The lock behaviour in force.
    pub lock_behavior: LockBehavior,
    /// The store facts.
    pub read: &'a StoreRead,
}

/// The managed credential adapter (module docs).
pub struct ManagedCertificateAdapter {
    descriptor: AdapterDescriptor,
    sources: Arc<dyn ManagedSourceRead>,
    effects: Option<ManagedEffectsImpl>,
    layout: Option<EndpointLayout>,
    platform: Platform,
}

impl std::fmt::Debug for ManagedCertificateAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedCertificateAdapter")
            .field("descriptor", &self.descriptor)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

impl ManagedCertificateAdapter {
    /// The adapter `instance`, reading through `sources`, destroying keys through
    /// `effects` (`None`: no signer in this process; `revoke` then destroys nothing
    /// and says so), naming binding endpoints in `layout`.
    #[must_use]
    pub fn new(
        instance: &str,
        sources: Arc<dyn ManagedSourceRead>,
        effects: Option<ManagedEffectsImpl>,
        layout: Option<EndpointLayout>,
    ) -> Self {
        let platform = report::current_platform();
        Self::for_platform(instance, sources, effects, layout, platform)
    }

    /// As [`Self::new`], for an explicit claim-table platform row (tests of another
    /// platform's report).
    #[must_use]
    pub fn for_platform(
        instance: &str,
        sources: Arc<dyn ManagedSourceRead>,
        effects: Option<ManagedEffectsImpl>,
        layout: Option<EndpointLayout>,
        platform: Platform,
    ) -> Self {
        let claims = sources.claims();
        let descriptor = AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: MANAGED_CERTIFICATE.to_owned(),
                instance: instance.to_owned(),
            },
            capabilities: managed_capabilities(),
            external_side_effects: true,
            interaction: InteractionRequirement::None,
            enforcement: EnforcementEvidence {
                report: baseline_enforcement(),
                evidence: Vec::new(),
            },
            lock_continuity: lock_continuity_from(&claims, &platform),
            remote_credential_effect: true,
        };
        Self {
            descriptor,
            sources,
            effects,
            layout,
            platform,
        }
    }

    /// The effects this adapter destroys keys through.
    #[must_use]
    pub fn effects(&self) -> Option<&ManagedEffectsImpl> {
        self.effects.as_ref()
    }

    fn terms(&self, grant: &GrantId) -> Option<GrantTerms> {
        self.sources.terms(grant)
    }

    /// `valid_after` of the installed entry behind `c` (§17.20 item 8): the effects'
    /// record of the install, only when it is this certificate's entry; `None`
    /// otherwise (no signer in this process, or another entry), which refuses.
    fn valid_after_of(&self, grant: &GrantId, c: &PreparedCertificate) -> Option<Timestamp> {
        self.effects
            .as_ref()?
            .installed_validity(grant, &c.pair)
            .filter(|v| v.issuance == c.issuance && v.valid_before == c.valid_before)
            .map(|v| v.valid_after)
    }

    /// D6 item 4's re-issue outcome: refused unless [`reissue::eligible`] holds for
    /// the **stored** grant and the request names exactly its pairs and deadline
    /// ([`reissue::same_grant`]); then the outcome is computed from `sources` (the
    /// driver's re-issue results) as `prepare_from` computes it. Never later than
    /// the stored deadline, never other pairs.
    ///
    /// # Errors
    /// `CapabilityUnavailable` for an ineligible grant ([`ReissueRefusal`]), and every
    /// error of `prepare_from`.
    pub fn reissue_from(
        &self,
        req: PrepareRequest<'_>,
        sources: &IntegrationSnapshot,
        input: &ReissueInput<'_>,
    ) -> Result<PrepareOutcome, AdapterError> {
        reissue::eligible(
            input.stored,
            input.origin,
            input.time,
            input.admission,
            input.lock_behavior,
            input.read,
        )
        .map_err(reissue_error)?;
        let plan = reissue::same_grant(input.stored, req.grant).map_err(reissue_error)?;
        let terms = self.terms(&plan.grant);
        let (outcome, _) = prepare::outcome(
            &req,
            sources,
            terms.as_ref(),
            self.layout.as_ref(),
            self.platform,
            &self.descriptor.capabilities,
            &|c| self.valid_after_of(&plan.grant, c),
        )?;
        let pairs: BTreeSet<(DestinationId, String)> = outcome
            .integration
            .pairs
            .iter()
            .map(|p| (p.destination.clone(), p.account.as_str().to_owned()))
            .collect();
        let stored: BTreeSet<(DestinationId, String)> = plan
            .pairs
            .iter()
            .map(|p| (p.destination.clone(), p.account.as_str().to_owned()))
            .collect();
        if outcome.usable_until > plan.valid_before
            || outcome.offline_until > plan.valid_before
            || (!pairs.is_empty() && pairs != stored)
        {
            return Err(reissue_error(ReissueRefusal::ScopeChanged));
        }
        Ok(outcome)
    }

    /// The residual of `grants` as at their revocation (D7 item 2 step 5, item 3):
    /// statuses are not moved by the caller's `now` (see `REVOKE_MOVES_NO_RESIDUAL`).
    fn residual(&self, grants: &[GrantId], now: Timestamp) -> RevokeOutcome {
        let entries: Vec<IssuanceEntry> = self.sources.issuance_entries(grants);
        let pairs: Vec<AccessPair> = entries
            .iter()
            .map(|e| e.pair.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let enrollments = self.sources.enrollments(&pairs);
        let clocks: Vec<(
            AccessPair,
            Option<heimdall_contract::managed::ClockMeasurement>,
        )> = pairs
            .iter()
            .map(|p| {
                let clock = enrollments
                    .iter()
                    .filter(|e| e.destination == p.destination && e.account == p.account)
                    .filter_map(|e| e.evidence.as_ref())
                    .max_by_key(|e| e.verified_at)
                    .and_then(|e| e.clock);
                (p.clone(), clock)
            })
            .collect();
        let refs: Vec<report::PairClock<'_>> = clocks.iter().map(|(p, c)| (p, *c)).collect();
        // ⟨REVOKE_MOVES_NO_RESIDUAL⟩ The port's `now` is the caller's wall reading, not
        // a time the gate accepted (the cleanup-intent path passes a raw clock read), so
        // the revoke result moves no residual: every row is reported as at revocation
        // (`pending_until`, or `unbounded_unknown`), with the completion bound's drift
        // run to `now`. The supervisor's pass moves them on safe time (D7 item 3).
        let remote_effects =
            report::remote_effects(&entries, &refs, now, None, self.sources.key_only_restore());
        let remote_pending: Vec<DestinationId> = remote_effects
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    ResidualStatus::PendingUntil | ResidualStatus::UnboundedUnknown
                )
            })
            .map(|r| r.destination.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        RevokeOutcome {
            remote_pending,
            latest_possible_credential_expiry: report::latest_possible_credential_expiry(&entries),
            remote_effects,
        }
    }
}

fn reissue_error(_: ReissueRefusal) -> AdapterError {
    AdapterError::CapabilityUnavailable
}

/// The request alone shows the grant cannot re-issue (rule 1 as far as it is visible
/// without the store).
fn renew_precheck(req: &PrepareRequest<'_>) -> Result<(), AdapterError> {
    use heimdall_contract::GrantState;
    let continuing = matches!(req.grant.state, GrantState::Active | GrantState::Degraded);
    if !continuing || req.now >= req.grant.deadline.effective {
        return Err(AdapterError::CapabilityUnavailable);
    }
    Ok(())
}

#[async_trait]
impl CredentialAdapter for ManagedCertificateAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    async fn prepare(&self, _req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        // No snapshot, so no driver results (D6 item 0).
        Err(AdapterError::Protocol(
            MANAGED_PREPARE_WITHOUT_DRIVER.to_owned(),
        ))
    }

    fn read_sources(&self, pairs: &[PreparePair]) -> IntegrationSnapshot {
        prepare::snapshot(self.sources.as_ref(), pairs)
    }

    async fn prepare_from(
        &self,
        req: PrepareRequest<'_>,
        sources: &IntegrationSnapshot,
    ) -> Result<PrepareOutcome, AdapterError> {
        let terms = self.terms(&req.grant.id);
        let grant = req.grant.id.clone();
        prepare::outcome(
            &req,
            sources,
            terms.as_ref(),
            self.layout.as_ref(),
            self.platform,
            &self.descriptor.capabilities,
            &|c| self.valid_after_of(&grant, c),
        )
        .map(|(o, _)| o)
    }

    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        renew_precheck(&req)?;
        Err(AdapterError::Protocol(RENEW_THROUGH_DRIVER.to_owned()))
    }

    async fn reconcile(
        &self,
        grant: &GrantId,
        effect_token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        let entries = self.sources.issuance_entries(std::slice::from_ref(grant));
        let published: Vec<&IssuanceEntry> = entries
            .iter()
            .filter(|e| &e.grant == grant && e.state == IssuanceState::Published)
            .collect();
        if published.is_empty() {
            return Ok(ReconcileOutcome::NotApplied);
        }
        let Some(effects) = &self.effects else {
            return Ok(ReconcileOutcome::Unknown);
        };
        let Some(pairs) = effects.grant_pairs(grant) else {
            return Ok(ReconcileOutcome::Unknown);
        };
        let installed: BTreeSet<_> = effects
            .table()
            .installed_entries(grant)
            .into_iter()
            .collect();
        let complete = pairs.iter().all(|p| {
            published
                .iter()
                .any(|e| &e.pair == p && installed.contains(&e.id))
        });
        if !complete || !effects.generated_under(grant, effect_token) {
            return Ok(ReconcileOutcome::Unknown);
        }
        match self.sources.recorded_outcome(grant, effect_token) {
            Some(o) => Ok(ReconcileOutcome::Applied(o)),
            None => Ok(ReconcileOutcome::Unknown),
        }
    }

    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError> {
        let mut grants = self.sources.cascade(grant);
        if !grants.contains(grant) {
            grants.insert(0, grant.clone());
        }
        if let Some(effects) = &self.effects {
            effects.destroy(&grants).await?;
        }
        Ok(self.residual(&grants, now))
    }
}
