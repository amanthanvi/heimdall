//! The 1Password SSH agent adapter (m02-plan U6; ADR-0007 §7).
//!
//! Descriptor: mechanism `onepassword`, no external side effects, interaction
//! `ProviderDialog`, lock continuity `StopsOnLock` [S06]. Every 1Password identity is
//! `provider_approval` (documented, F17), plus `provider_unlock` while locked, whatever
//! any declaration says; `refresh_dependency` is `provider_interaction`.
//!
//! No 1Password socket or pipe path is hardcoded (ADR-0007 §7, §12.14 item 8): the
//! pinned vendor excerpts do not exist, so the endpoint comes only from
//! `SSH_AUTH_SOCK`, an `IdentityAgent` reference, or the catalog identity that names
//! it. Without one, the adapter reports the provider `unavailable`.
//!
//! `prepare`, `renew`, `reconcile` and `revoke` never contact the agent; only
//! `list_identities` (the explicit `agent` probe) does, with one
//! `SSH_AGENTC_REQUEST_IDENTITIES`. 1Password's listing behaviour while locked is
//! `[U]` (ADR-0007 §7); an empty listing or a refusal is reported `locked` with basis
//! `inferred` ([`crate::state::status_from_listing`]).

use std::sync::Arc;

use async_trait::async_trait;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, DetectContext, IdentityListing,
    LockContinuity, PrepareOutcome, PrepareRequest, ProbeBounds, ProviderProbe, ReconcileOutcome,
    RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use heimdall_contract::provider::{EndpointRef, ProviderKind, ProviderStatus};
use heimdall_contract::request::RefreshDependency;
use heimdall_domain::time::Clock;

use crate::integration::{Core, IntegrationSources, Prepared};

/// The mechanism name recorded in receipts and reported as `credential_mechanism`.
pub const MECHANISM: &str = "onepassword";

/// The 1Password SSH agent.
#[derive(Debug, Clone)]
pub struct OnePasswordAdapter {
    core: Core,
}

impl OnePasswordAdapter {
    /// An adapter instance for `endpoint` (named by `SSH_AUTH_SOCK` or an
    /// `IdentityAgent` reference), recorded under `instance`. An identity whose
    /// catalog record names its own endpoint uses that one.
    #[must_use]
    pub fn new(instance: String, endpoint: Option<EndpointRef>) -> Self {
        Self {
            core: Core::new(
                ProviderKind::OnePassword,
                MECHANISM,
                LockContinuity::StopsOnLock,
                RefreshDependency::ProviderInteraction,
                instance,
                endpoint,
            ),
        }
    }

    /// The same adapter reading its selection, catalog and client facts from
    /// `sources` (the runtime wiring, U5). Without sources nothing is claimed.
    #[must_use]
    pub fn with_sources(mut self, sources: Arc<dyn IntegrationSources>) -> Self {
        self.core.set_sources(sources);
        self
    }

    /// The same adapter timing its listings with `clock` (default: the system wall
    /// clock).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.core.set_clock(clock);
        self
    }

    /// The endpoint this instance fronts.
    #[must_use]
    pub fn endpoint(&self) -> Option<&EndpointRef> {
        self.core.endpoint.as_ref()
    }

    /// `prepare` with each pair's full identity selection (ADR-0007 §12.14 item 6).
    /// Synchronous, local and passive; [`CredentialAdapter::prepare`] returns its
    /// `outcome`.
    ///
    /// # Errors
    /// [`AdapterError`] by ADR-0007 §7's table ([`crate::state::readiness`]).
    pub fn prepare_detailed(&self, req: &PrepareRequest<'_>) -> Result<Prepared, AdapterError> {
        self.core.prepare(req)
    }
}

#[async_trait]
impl CredentialAdapter for OnePasswordAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.core.descriptor
    }

    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.core.prepare(&req).map(|p| p.outcome)
    }

    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.core.prepare(&req).map(|p| p.outcome)
    }

    async fn reconcile(
        &self,
        grant: &GrantId,
        effect_token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        Ok(self.core.reconcile(grant, effect_token))
    }

    async fn revoke(&self, grant: &GrantId, now: Timestamp) -> Result<RevokeOutcome, AdapterError> {
        let _ = now;
        Ok(self.core.revoke(grant))
    }
}

#[async_trait]
impl ProviderProbe for OnePasswordAdapter {
    fn provider(&self) -> ProviderKind {
        ProviderKind::OnePassword
    }

    fn detect(&self, ctx: &DetectContext) -> ProviderStatus {
        self.core.detect(ctx)
    }

    async fn list_identities(&self, bounds: &ProbeBounds) -> Result<IdentityListing, AdapterError> {
        self.core.list_identities(bounds).await
    }
}
