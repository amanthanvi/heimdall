//! The native SSH agent adapter (m02-plan U6; ADR-0007 §7).
//!
//! Descriptor: mechanism `native_agent`, no external side effects, interaction
//! `ProviderDialog` (a native key may carry a confirmation constraint, ADR-0007 F23),
//! lock continuity `Unknown`.

use std::collections::BTreeSet;

use async_trait::async_trait;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, DetectContext, IdentityListing,
    InteractionRequirement, LockContinuity, PrepareOutcome, PrepareRequest, ProbeBounds,
    ProviderProbe, ReconcileOutcome, RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use heimdall_contract::provider::{EndpointRef, ProviderKind, ProviderStatus};
use heimdall_contract::request::Capability;
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;

/// The mechanism name recorded in receipts and reported as `credential_mechanism`.
pub const MECHANISM: &str = "native_agent";

/// The native SSH agent (`ssh-agent`, the Windows OpenSSH agent service).
#[derive(Debug, Clone)]
pub struct NativeAgentAdapter {
    descriptor: AdapterDescriptor,
    endpoint: Option<EndpointRef>,
}

impl NativeAgentAdapter {
    /// An adapter instance for `endpoint` (the agent `SSH_AUTH_SOCK` or an
    /// `IdentityAgent` reference names), recorded under `instance`.
    ///
    /// The enforcement report claims nothing yet ([`EnforcementEvidence::unknown`]);
    /// U6 sets the exact existing-access report (`enforcement_report_is_exact_…`).
    #[must_use]
    pub fn new(instance: String, endpoint: Option<EndpointRef>) -> Self {
        Self {
            descriptor: AdapterDescriptor {
                identity: AdapterIdentity {
                    mechanism: MECHANISM.to_owned(),
                    instance,
                },
                capabilities: BTreeSet::from([Capability::SshAuthentication]),
                external_side_effects: false,
                interaction: InteractionRequirement::ProviderDialog,
                enforcement: EnforcementEvidence::unknown(),
                lock_continuity: LockContinuity::Unknown,
            },
            endpoint,
        }
    }

    /// The endpoint this instance fronts.
    #[must_use]
    pub fn endpoint(&self) -> Option<&EndpointRef> {
        self.endpoint.as_ref()
    }
}

#[async_trait]
impl CredentialAdapter for NativeAgentAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        let _ = req;
        Err(crate::not_available())
    }

    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        let _ = req;
        Err(crate::not_available())
    }

    async fn reconcile(
        &self,
        grant: &GrantId,
        effect_token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        let _ = (grant, effect_token);
        Err(crate::not_available())
    }

    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError> {
        let _ = (grant, now);
        Err(crate::not_available())
    }
}

#[async_trait]
impl ProviderProbe for NativeAgentAdapter {
    fn provider(&self) -> ProviderKind {
        ProviderKind::NativeAgent
    }

    fn detect(&self, ctx: &DetectContext) -> ProviderStatus {
        crate::unknown_status(ProviderKind::NativeAgent, ctx.now)
    }

    async fn list_identities(&self, bounds: &ProbeBounds) -> Result<IdentityListing, AdapterError> {
        let _ = bounds;
        Err(crate::not_available())
    }
}
