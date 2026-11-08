//! The enrollment plan (ADR-0008 D5 §6.1; §17.4 item 9; m03-plan U5 "Interfaces"),
//! moved below `app` so that `app` calls it directly, through no port (§0.6).
//!
//! The signatures of [`build`] and [`plan_digest`] are frozen in wave 0 (U0); their
//! bodies are U5's. **Wave 0:** both refuse with [`PlanRefusal::DriverUnavailable`]
//! (`CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`), so no plan, decision or
//! record is ever produced from them.

use heimdall_contract::Code;
use heimdall_contract::enrollment::{EnrollmentPlan, EnrollmentSpec};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::CaState;
use heimdall_contract::setup::PlanDigest;
use heimdall_domain::enrollment::{CatalogView, TargetEvaluation};

/// One registered CA as the plan sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaViewEntry {
    /// Fingerprint.
    pub fingerprint: CaFingerprint,
    /// State (`active` CAs are eligible; `pending` only for rotation's enrollments).
    pub state: CaState,
    /// The CA's OpenSSH public key line (the registry line's key).
    pub public_key: String,
}

/// The CAs the plan may choose from (`EnrollmentSpec.ca_fingerprint`, default the
/// newest active CA).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaView {
    /// Registered CAs, newest last.
    pub cas: Vec<CaViewEntry>,
}

/// Why no plan was built (ADR-0008 D5 §6.1 preconditions). Each maps to a stable
/// reason of `contract::envelope::reason::M03` (or `driver_unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PlanRefusal {
    /// The plan builder is not in this build (wave 0; U5 fills it).
    #[error("the enrollment plan is not available in this build")]
    DriverUnavailable,
    /// An account other than the managed definition's (`USAGE_ERROR`).
    #[error("the account override is refused")]
    AccountOverrideRefused,
    /// The route is not statically determined.
    #[error("the route is undetermined")]
    RouteUndetermined,
    /// The existing access is of a kind M03 cannot use.
    #[error("the existing-access kind is unsupported")]
    ExistingAccessKindUnsupported,
    /// The existing-access endpoint is neither recorded nor statically determined.
    #[error("the existing-access endpoint is unrecorded")]
    ExistingAccessEndpointUnrecorded,
    /// The existing-access endpoint is (or resolves to) a Heimdall endpoint.
    #[error("the existing-access endpoint is Heimdall's")]
    ExistingAccessEndpointIsHeimdall,
}

impl PlanRefusal {
    /// The stable sub-reason (`data.error.reason`).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            PlanRefusal::DriverUnavailable => reason::DRIVER_UNAVAILABLE,
            PlanRefusal::AccountOverrideRefused => reason::ACCOUNT_OVERRIDE_REFUSED,
            PlanRefusal::RouteUndetermined => reason::ROUTE_UNDETERMINED,
            PlanRefusal::ExistingAccessKindUnsupported => reason::EXISTING_ACCESS_KIND_UNSUPPORTED,
            PlanRefusal::ExistingAccessEndpointUnrecorded => {
                reason::EXISTING_ACCESS_ENDPOINT_UNRECORDED
            }
            PlanRefusal::ExistingAccessEndpointIsHeimdall => {
                reason::EXISTING_ACCESS_ENDPOINT_IS_HEIMDALL
            }
        }
    }

    /// The public code.
    #[must_use]
    pub fn code(self) -> Code {
        match self {
            PlanRefusal::AccountOverrideRefused => Code::UsageError,
            PlanRefusal::DriverUnavailable
            | PlanRefusal::RouteUndetermined
            | PlanRefusal::ExistingAccessKindUnsupported
            | PlanRefusal::ExistingAccessEndpointUnrecorded
            | PlanRefusal::ExistingAccessEndpointIsHeimdall => Code::CapabilityUnavailable,
        }
    }
}

/// Build the enrollment plan: the D5 §6.1 preconditions, the approved target, the
/// existing-access invocation, the conditional bootstrap step, the disclosures and
/// the digest.
///
/// **Wave 0:** refuses with [`PlanRefusal::DriverUnavailable`] for every input.
pub fn build(
    catalog: &CatalogView,
    target: &TargetEvaluation,
    cas: &CaView,
    spec: EnrollmentSpec,
) -> Result<EnrollmentPlan, PlanRefusal> {
    let _ = (catalog, target, cas, spec);
    Err(PlanRefusal::DriverUnavailable)
}

/// The digest over every field of `plan` except `plan_digest` itself (the decision
/// and the request hash cover it).
///
/// **Wave 0:** refuses with [`PlanRefusal::DriverUnavailable`].
pub fn plan_digest(plan: &EnrollmentPlan) -> Result<PlanDigest, PlanRefusal> {
    let _ = plan;
    Err(PlanRefusal::DriverUnavailable)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn refusal_reasons_are_registered_with_their_codes() {
        let all = [
            PlanRefusal::DriverUnavailable,
            PlanRefusal::AccountOverrideRefused,
            PlanRefusal::RouteUndetermined,
            PlanRefusal::ExistingAccessKindUnsupported,
            PlanRefusal::ExistingAccessEndpointUnrecorded,
            PlanRefusal::ExistingAccessEndpointIsHeimdall,
        ];
        for r in all {
            if r == PlanRefusal::DriverUnavailable {
                assert_eq!(r.code(), Code::CapabilityUnavailable);
                continue;
            }
            assert!(
                reason::M03
                    .iter()
                    .any(|(name, code)| *name == r.reason() && *code == r.code()),
                "{}",
                r.reason()
            );
        }
    }
}
