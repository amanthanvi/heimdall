//! ⟨M06 W3 grant-path⟩ The `managed_certificate` mechanism **on a remote runner** (ADR-0012
//! §4 items 1–2, the ⟨2026-11-21⟩ bullets "How a grant comes to exist on a runner"; ADR-0005
//! §3.5 "Remote reservations", §4.3).
//!
//! A runner cannot issue. Its `ensure` pipeline (`heimdall_app::operations`) admits a grant
//! under the runner's own policy or a runner-local decision and then waits
//! (`heimdall_app::operations::RunnerGrants`): the controller's host prepares K_env in the
//! runner's signer, issues under its own record, and installs the certificates
//! (`crate::runner::issuance`). Only then does the pipeline reach this adapter, which is
//! configured **in place of** the local managed adapter on a runner:
//!
//! * **`prepare_from`** issues nothing and generates nothing. It checks that the runner's
//!   signer holds the grant's K_env with a certificate, valid now and within the attempt's
//!   bound, for every pair of the grant; finds the binding minted for the attempt; and has
//!   the binding materialized from the runner's signer ([`RunnerMaterializer`]): its endpoint
//!   lists that grant's K_env certificates only, never a controller's socket (ADR-0012
//!   §4.6). A grant that is not issued is refused here too (`awaiting_issuer`): nothing is
//!   ever prepared from an issuer on the runner.
//! * **Readiness.** `refresh_dependency` is `controller`: K_env lives in this process's
//!   memory only, and a restart needs the controller's issuer again. `usable_until` and
//!   `offline_until` are the earliest installed `valid_before`, never past the attempt's
//!   bound. Every enforcement claim is `unknown`: this adapter holds no evidence for one.
//! * **`reconcile`** answers `NotApplied`: a fresh attempt is safe (the materialization is
//!   idempotent per binding and generation, and without K_env the attempt refuses).
//! * **`revoke`** destroys the grant's K_env in the runner's signer and removes every
//!   binding materialized for it. The certificates already issued stay valid at servers
//!   until their `valid_before`, which is what it reports.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use heimdall_app::operations::{MANAGED_CERTIFICATE, RunnerGrants};
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot,
    InteractionRequirement, LockContinuity, PrepareOutcome, PreparePair, PrepareRequest,
    ReconcileOutcome, RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, GrantId};
use heimdall_contract::provider::{CredentialAvailability, EndpointRef};
use heimdall_contract::request::{Capability, ConsumerIntegration, RefreshDependency};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::{AdapterIdentity, EffectReceipt};
use heimdall_store::Store;

use crate::runner::RunnerRuntime;

/// The `AdapterError::Unavailable` text of a grant the controller has not issued for.
pub const AWAITING_ISSUER: &str = "awaiting_issuer";
/// The `AdapterError::Unavailable` text before the runner's parts are bound, or after stop.
pub const RUNNER_UNAVAILABLE: &str = "runner_unavailable";
/// The `AdapterError::Protocol` text of an attempt no open operation minted a binding for.
pub const NO_BINDING: &str = "no_binding_for_attempt";

/// The resource generation of a binding materialized at activation (one per binding, as
/// the local managed driver's).
pub const BINDING_GENERATION: u64 = 1;

/// The bindings being materialized for a runner grant before their rows are committed:
/// what lets the runner's binding endpoints know a binding's grant during its own
/// activation (`crate::service::RunnerBindingEndpoints::with_pending`). An entry is added by
/// the attempt and removed with the grant.
#[derive(Debug, Clone, Default)]
pub struct PendingBindings(Arc<Mutex<HashMap<BindingId, GrantId>>>);

impl PendingBindings {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BindingId, GrantId>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The grant `binding` is being materialized for.
    #[must_use]
    pub fn grant_of(&self, binding: &BindingId) -> Option<GrantId> {
        self.lock().get(binding).cloned()
    }

    fn note(&self, binding: &BindingId, grant: &GrantId) {
        self.lock().insert(binding.clone(), grant.clone());
    }

    fn forget_grant(&self, grant: &GrantId) {
        self.lock().retain(|_, g| g != grant);
    }
}

/// Where a runner grant's binding is realized: the runner's binding endpoints and the
/// binding's files (the service implements it over the managed effects, whose materialize
/// site serves a runner grant from the runner's signer only).
pub trait RunnerMaterializer: Send + Sync {
    /// Create (or find) `binding`'s endpoint and write its files from the K_env public key
    /// and installed certificates of the runner grant `grant`. Idempotent. Synchronous file
    /// work: called on the blocking pool.
    ///
    /// # Errors
    /// [`AdapterError`]; nothing of the binding is left behind.
    fn materialize(
        &self,
        binding: &BindingId,
        grant: &GrantId,
    ) -> Result<EndpointRef, AdapterError>;

    /// Remove the endpoint and files of every binding materialized for `grant`.
    ///
    /// # Errors
    /// [`AdapterError`] when something could not be removed (the caller's cleanup intent is
    /// kept and retried).
    fn clear(&self, grant: &GrantId) -> Result<(), AdapterError>;
}

/// The parts bound after the runner runtime exists.
struct Bound {
    runner: Arc<RunnerRuntime>,
    materializer: Arc<dyn RunnerMaterializer>,
}

/// The runner's adapter for `managed_certificate` (module docs).
pub struct RunnerManagedAdapter {
    descriptor: AdapterDescriptor,
    store: Arc<Store>,
    pending: PendingBindings,
    bound: Mutex<Option<Arc<Bound>>>,
}

impl std::fmt::Debug for RunnerManagedAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerManagedAdapter")
            .finish_non_exhaustive()
    }
}

impl RunnerManagedAdapter {
    /// The adapter over the runner's `store`. Until [`Self::bind`] every preparation
    /// refuses.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            descriptor: AdapterDescriptor {
                identity: AdapterIdentity {
                    mechanism: MANAGED_CERTIFICATE.to_owned(),
                    instance: "runner".to_owned(),
                },
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
                external_side_effects: true,
                interaction: InteractionRequirement::None,
                // Nothing is advertised: this adapter holds no evidence for a claim.
                enforcement: EnforcementEvidence::unknown(),
                lock_continuity: LockContinuity::Unknown,
                // The certificates are authority usable at servers until they expire.
                remote_credential_effect: true,
            },
            store,
            pending: PendingBindings::default(),
            bound: Mutex::new(None),
        }
    }

    /// The bindings in activation (for the runner's binding endpoints).
    #[must_use]
    pub fn pending(&self) -> PendingBindings {
        self.pending.clone()
    }

    /// Bind the runner runtime (its signer) and where bindings are realized.
    pub fn bind(&self, runner: Arc<RunnerRuntime>, materializer: Arc<dyn RunnerMaterializer>) {
        *self.bound.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(Bound {
            runner,
            materializer,
        }));
    }

    /// Unbind (runtime stop): every later call refuses.
    pub fn unbind(&self) {
        *self.bound.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn bound(&self) -> Result<Arc<Bound>, AdapterError> {
        self.bound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| AdapterError::Unavailable(RUNNER_UNAVAILABLE.to_owned()))
    }

    /// The binding minted at resolve for the open operation whose attempt carries `token`.
    fn binding_of_attempt(&self, token: &str) -> Result<BindingId, AdapterError> {
        let found = self
            .store
            .transaction(|tx| {
                for op in tx.open_operations()? {
                    let carries = tx.stage_receipts(&op.id)?.iter().any(|r| {
                        matches!(&r.effect, EffectReceipt::Attempted { effect_token, .. }
                            if effect_token == token)
                    });
                    if carries {
                        return Ok(tx
                            .recovery_intent(&op.id)?
                            .and_then(|i| i.resolved)
                            .and_then(|r| r.binding_id));
                    }
                }
                Ok(None)
            })
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))?;
        found.ok_or_else(|| AdapterError::Protocol(NO_BINDING.to_owned()))
    }
}

/// The earliest `valid_before` of `grant`'s installed certificates when the runner's signer
/// holds one, valid at `now` and not past `bound`, for **every** pair in `pairs`; `None`
/// otherwise (the grant waits for its issuer).
fn issued_until(
    runner: &RunnerRuntime,
    grant: &GrantId,
    pairs: &BTreeSet<heimdall_contract::request::AccessPairRef>,
    now: Timestamp,
    bound: Option<Timestamp>,
) -> Option<Timestamp> {
    let keys = runner.issuance().keys();
    keys.public_key(grant)?;
    let installed = keys.certificates(grant);
    if pairs.is_empty() {
        return None;
    }
    let mut earliest: Option<Timestamp> = None;
    for pair in pairs {
        let c = installed.get(pair)?;
        if c.valid_before <= now || bound.is_some_and(|b| c.valid_before > b) {
            return None;
        }
        earliest = Some(earliest.map_or(c.valid_before, |e| e.min(c.valid_before)));
    }
    earliest
}

impl RunnerGrants for RunnerRuntime {
    /// The runner's signer holds K_env and a certificate for every pair of the grant as the
    /// store records it. A grant the store does not hold is never issued.
    fn issued(&self, grant: &GrantId) -> bool {
        let Ok(Some(pairs)) = self
            .store()
            .transaction(|tx| Ok(tx.grant(grant)?.map(|g| g.scope.pairs)))
        else {
            return false;
        };
        issued_until(self, grant, &pairs, self.wall(), None).is_some()
    }
}

#[async_trait]
impl CredentialAdapter for RunnerManagedAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.prepare_from(req, &IntegrationSnapshot::default())
            .await
    }

    fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
        IntegrationSnapshot::default()
    }

    async fn prepare_from(
        &self,
        req: PrepareRequest<'_>,
        _sources: &IntegrationSnapshot,
    ) -> Result<PrepareOutcome, AdapterError> {
        let bound = self.bound()?;
        let grant = req.grant.id.clone();
        // Issued by the controller for every pair, valid now, within the attempt's bound.
        let until = issued_until(
            &bound.runner,
            &grant,
            &req.scope.pairs,
            req.now,
            Some(req.grant.deadline.effective),
        )
        .ok_or_else(|| AdapterError::Unavailable(AWAITING_ISSUER.to_owned()))?;
        let fingerprint = bound
            .runner
            .issuance()
            .keys()
            .public_key(&grant)
            .map(|(_, public)| public.fingerprint)
            .ok_or_else(|| AdapterError::Unavailable(AWAITING_ISSUER.to_owned()))?;
        let binding = self.binding_of_attempt(req.effect_token)?;
        self.pending.note(&binding, &grant);
        let materializer = Arc::clone(&bound.materializer);
        let (b, g) = (binding.clone(), grant.clone());
        let endpoint = tokio::task::spawn_blocking(move || materializer.materialize(&b, &g))
            .await
            .map_err(|_| AdapterError::Unavailable("materialize_task".to_owned()))??;
        Ok(PrepareOutcome {
            usable_until: until,
            offline_until: until,
            refresh_dependency: RefreshDependency::Controller,
            enforcement: EnforcementEvidence::unknown(),
            credential_ref: fingerprint,
            // Through the deadline when the certificates run to the attempt's bound;
            // otherwise the controller's next issue is needed before it.
            availability: if until >= req.grant.deadline.effective {
                CredentialAvailability::ThroughDeadline
            } else {
                CredentialAvailability::RefreshDependent
            },
            provider: None,
            integration: ConsumerIntegration {
                signing_endpoint: Some(endpoint.locator),
                ..ConsumerIntegration::default()
            },
            managed: None,
        })
    }

    async fn renew(&self, _req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        // A renewal is the controller's new issue; nothing renews here.
        Err(AdapterError::CapabilityUnavailable)
    }

    async fn reconcile(
        &self,
        _grant: &GrantId,
        _effect_token: &str,
    ) -> Result<ReconcileOutcome, AdapterError> {
        Ok(ReconcileOutcome::NotApplied)
    }

    async fn revoke(
        &self,
        grant: &GrantId,
        _now: Timestamp,
    ) -> Result<RevokeOutcome, AdapterError> {
        let bound = self.bound()?;
        let keys = bound.runner.issuance().keys();
        let latest = keys
            .certificates(grant)
            .values()
            .map(|c| c.valid_before)
            .max();
        bound.runner.issuance().destroy(grant);
        self.pending.forget_grant(grant);
        let materializer = Arc::clone(&bound.materializer);
        let g = grant.clone();
        tokio::task::spawn_blocking(move || materializer.clear(&g))
            .await
            .map_err(|_| AdapterError::Unavailable("clear_task".to_owned()))??;
        Ok(RevokeOutcome {
            remote_pending: Vec::new(),
            latest_possible_credential_expiry: latest,
            remote_effects: Vec::new(),
        })
    }
}
