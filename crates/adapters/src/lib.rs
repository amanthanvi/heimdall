//! Existing-access credential adapters (m02-plan U6; ADR-0007 §7).
//!
//! [`native_agent::NativeAgentAdapter`] and [`onepassword::OnePasswordAdapter`]
//! implement the app ports `CredentialAdapter` and `ProviderProbe`. `prepare` is local
//! only: it checks presence passively and materializes the consumer integration
//! ([`integration`]). It never contacts an agent; only the explicit `agent` probe
//! (`ProviderProbe::list_identities`) sends one `SSH_AGENTC_REQUEST_IDENTITIES`, and
//! nothing ever sends a sign, add, remove, lock or extension message. Interaction and
//! eligibility follow one rule, `heimdall_domain::catalog::eligibility`, through
//! [`state`].
//!
//! **Drop contract** (M2-T06): each `prepare`, `reconcile` and `revoke` future stops
//! all work when dropped: no detached task, no blocking call outside the agent
//! client's own bound, and any child it started is killed on drop.
//!
//! **1Password paths** (m02-plan U0; ADR-0007 §7). The pinned vendor excerpts for the
//! agent socket paths and the `agent.toml` location are not in `docs/sources` yet, so
//! no 1Password path is hardcoded: detection uses `SSH_AUTH_SOCK` and `IdentityAgent`
//! references in the configuration only.
//!
//! **Skeleton status (m02-plan U0, wave 0).** Types, descriptors and signatures are
//! fixed by the integrator; U6 writes the bodies. Every adapter call answers
//! `AdapterError::Unavailable("not available in this build")` and contacts nothing;
//! passive detection reports `unknown`, which never satisfies a minimum. No runtime
//! registers these adapters in this build (U5 wires them in wave 3).

pub mod detect;
pub mod integration;
pub mod native_agent;
pub mod onepassword;
pub mod state;

use heimdall_app::ports::AdapterError;
use heimdall_contract::Timestamp;
use heimdall_contract::provider::{
    EvidenceBasis, InteractionKind, ProbeLevel, ProviderAvailability, ProviderKind, ProviderStatus,
};

/// The message of every skeleton answer.
pub const NOT_AVAILABLE: &str = "not available in this build";

/// The skeleton answer of an adapter call.
pub(crate) fn not_available() -> AdapterError {
    AdapterError::Unavailable(NOT_AVAILABLE.to_owned())
}

/// A status that claims nothing: availability and interaction `unknown`, observed
/// at the `static` level, basis `inferred`.
#[must_use]
pub fn unknown_status(provider: ProviderKind, now: Timestamp) -> ProviderStatus {
    ProviderStatus {
        provider,
        availability: ProviderAvailability::Unknown,
        interaction: InteractionKind::Unknown,
        observed_level: ProbeLevel::Static,
        observed_at: now,
        basis: EvidenceBasis::Inferred,
    }
}

#[cfg(test)]
mod tests {
    use heimdall_app::ports::{
        AdapterError, CredentialAdapter, DetectContext, InteractionRequirement, LockContinuity,
        ProbeBounds, ProviderProbe,
    };
    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::GrantId;
    use heimdall_contract::provider::{
        EvidenceBasis, InteractionKind, ProviderAvailability, ProviderKind,
    };
    use heimdall_contract::request::Capability;

    use crate::native_agent::NativeAgentAdapter;
    use crate::onepassword::OnePasswordAdapter;

    #[test]
    fn descriptors_state_the_existing_access_mechanisms() {
        let native = NativeAgentAdapter::new("w0".into(), None);
        let op = OnePasswordAdapter::new("w0".into(), None);
        for (d, mechanism, lock) in [
            (native.descriptor(), "native_agent", LockContinuity::Unknown),
            (op.descriptor(), "onepassword", LockContinuity::StopsOnLock),
        ] {
            assert_eq!(d.mechanism(), mechanism);
            assert!(!d.external_side_effects, "{mechanism}");
            assert_eq!(
                d.interaction,
                InteractionRequirement::ProviderDialog,
                "{mechanism}"
            );
            assert_eq!(d.lock_continuity, lock, "{mechanism}");
            assert!(d.capabilities.contains(&Capability::SshAuthentication));
            // Never `Verified` with no interaction: `required.unattended` is never met.
            assert_ne!(d.lock_continuity, LockContinuity::Verified, "{mechanism}");
        }
        assert_eq!(native.provider(), ProviderKind::NativeAgent);
        assert_eq!(op.provider(), ProviderKind::OnePassword);
    }

    #[tokio::test]
    async fn skeleton_calls_fail_closed_and_detection_claims_nothing() {
        let now = Timestamp::UNIX_EPOCH;
        let grant = GrantId::parse("grant_w0").unwrap_or_else(|e| panic!("grant id: {e}"));
        let native = NativeAgentAdapter::new("w0".into(), None);
        let op = OnePasswordAdapter::new("w0".into(), None);
        let adapters: [&dyn CredentialAdapter; 2] = [&native, &op];
        for a in adapters {
            assert!(matches!(
                a.reconcile(&grant, "tok").await,
                Err(AdapterError::Unavailable(_))
            ));
            assert!(matches!(
                a.revoke(&grant, now).await,
                Err(AdapterError::Unavailable(_))
            ));
        }
        let probes: [&dyn ProviderProbe; 2] = [&native, &op];
        let ctx = DetectContext {
            now,
            endpoint: None,
        };
        for p in probes {
            let status = p.detect(&ctx);
            assert_eq!(status.availability, ProviderAvailability::Unknown);
            assert_eq!(status.interaction, InteractionKind::Unknown);
            assert_eq!(status.basis, EvidenceBasis::Inferred);
            assert_eq!(status.observed_at, now);
            assert!(matches!(
                p.list_identities(&ProbeBounds::default()).await,
                Err(AdapterError::Unavailable(_))
            ));
        }
    }
}
