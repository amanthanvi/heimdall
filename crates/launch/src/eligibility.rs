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

use heimdall_contract::Timestamp;
use heimdall_contract::doctor::ConfigProvenance;
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{
    DeclarationRef, EndpointRef, IdentitySelectionReport, InteractionKind,
};
use heimdall_contract::request::PairIntegration;

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

/// One pair's selection, re-evaluated now in the CLI process (passive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshSelection {
    /// The pair's alias.
    pub alias: String,
    /// The identity selection the static pass found.
    pub report: IdentitySelectionReport,
    /// The alias's effective `IdentityAgent` endpoint, when determined.
    pub endpoint: Option<EndpointRef>,
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
/// # Errors
/// [`PrelaunchRefusal`].
pub fn check_noninteractive(
    bound: &[PairIntegration],
    fresh: &IdentitiesView,
    selection: &[FreshSelection],
    now: Timestamp,
) -> Result<(), PrelaunchRefusal> {
    let _ = (bound, fresh, selection, now);
    todo!("M02-U8 eligibility::check_noninteractive")
}
