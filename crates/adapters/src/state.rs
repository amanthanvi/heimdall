//! Interaction states and fallback clearance (m02-plan U6; ADR-0007 §7; M2-R04,
//! M2-R05).
//!
//! Both functions delegate to the pure domain rules
//! (`heimdall_domain::catalog::{eligibility, fallback_clearance}`), so the runtime,
//! the adapters and the CLI apply one rule. A declaration counts only when it is
//! `live`, its endpoint equals the current endpoint, and `expires_at > now`.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{
    EndpointRef, EvidenceBasis, IdentitySelectionReport, InteractionKind,
};
use heimdall_domain::catalog::{
    FallbackClearance, IdentityRecord, InteractionDeclaration, PairEligibility,
};

/// What passive detection observed of an identity's endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointObservation {
    /// The endpoint as currently configured.
    pub endpoint: EndpointRef,
    /// Whether the socket or pipe exists.
    pub present: bool,
    /// When.
    pub observed_at: Timestamp,
}

/// The identity's interaction and its basis (ADR-0007 §7's table, declaration lapse
/// included): `heimdall_domain::catalog::eligibility` at the observed endpoint.
#[must_use]
pub fn interaction_profile(
    identity: &IdentityRecord,
    declaration: Option<&InteractionDeclaration>,
    endpoint: &EndpointObservation,
    now: Timestamp,
) -> (InteractionKind, EvidenceBasis) {
    let e = heimdall_domain::catalog::eligibility(identity, declaration, &endpoint.endpoint, now);
    (e.interaction, e.basis)
}

/// Whether every fallback identity of a non-exclusive selection is cleared
/// (ADR-0007 §7 clearance rule).
#[must_use]
pub fn fallback_clearance(
    report: &IdentitySelectionReport,
    identities: &[IdentityRecord],
    eligibility: &dyn Fn(&IdentityId) -> PairEligibility,
    endpoint: &EndpointRef,
) -> FallbackClearance {
    heimdall_domain::catalog::fallback_clearance(report, identities, eligibility, endpoint)
}
