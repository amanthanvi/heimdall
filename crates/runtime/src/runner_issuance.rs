//! ⟨M06 U3⟩ Runner issuance: `runner.prepare_remote_grant` and `runner.install_certificate`
//! (ADR-0012 §4.1–§4.2; ADR-0005 §3.5 step 4, §3.7, §4.2–§4.3; m06-plan U3).
//!
//! A runner cannot issue (ADR-0005 §4.3). Its grants are realized by the controller that
//! issued them, over the paired channel:
//!
//! 1. **Admission is the runner's.** A grant exists in the runner's store only under a
//!    covering standing policy or a decision confirmed by an attended session local to the
//!    runner (a paired session never decides, ADR-0012 §3.10). [`RunnerIssuance::prepare`]
//!    serves only such a grant: this environment's, issuable (`preparing`, `active`,
//!    `degraded`), at the current authority generation, with no tombstone for it or an
//!    ancestor.
//! 2. **K_env** is generated in the runner signer's memory (the credential vault: locked,
//!    zeroized pages; no at-rest copy, ADR-0005 §3.7) and K_env.pub is returned bound to the
//!    grant and its generation (`heimdall_issuer::remote::PreparedRemoteGrant`). A repeated
//!    prepare at the same generation returns the same key (a lost reply); another generation
//!    destroys the old key first.
//! 3. **Issuer pin and `issuer_trust`.** A grant is pinned to the controller and CA of its
//!    first installed certificate (`remote_grant_issuers`); a prepare or install from another
//!    controller, or a certificate from another CA, is refused `issuer_untrusted`. Before the
//!    first install the controller must hold a CA in this runner's `issuer_trust`.
//! 4. **Install** ([`RunnerIssuance::install`]) checks, in one store transaction: the
//!    certificate is one user certificate whose CA signature verifies; its key is the grant's
//!    K_env for that generation; its CA is in `issuer_trust` for this controller (and the
//!    trusted key is that CA's) and matches the pin; exactly one principal, one of the grant's
//!    pairs, not yet installed; flag extensions only; then ADR-0005 §3.5's refusal list against
//!    the runner's own store with the runner's time (`heimdall_app::readiness_runner::
//!    runner_install_check`): grant state, generation, tombstones, ancestry, policy revision,
//!    pause for a new activation, `valid_before` within `min(D, cutoff, parent)`, permitted
//!    extensions, and a safe deadline: the grant's runner anchor, shortened from the latest
//!    qualifying time sample in this boot, must be open. Without such a sample:
//!    `TIME_UNCERTAIN`. A refused certificate is discarded; its issuance entry stays counted at
//!    the controller.
//! 5. **Grant end.** [`RunnerIssuance::destroy`] zeroizes K_env and drops its certificates
//!    (expiry, cutoff, revocation, release; ADR-0005 §3.6 "At grant end").
//! 6. ⟨M06 W3; ADR-0012 §4.1, §4.6⟩ **The runner's signer.** K_env is registered, and each
//!    certificate the checks above accepted is installed, in the runner's own
//!    `heimdall_credential::table::SignerTable` ([`RunnerKeys::table`]) over the same vault:
//!    the existing local binding-endpoint machinery (ADR-0008 D2: certificates only, never the
//!    plain K_env; a binding endpoint lists and signs for its own grant only). Runner-onward
//!    ssh is served by [`RunnerKeys::binding_signer`] for a binding attached to a runner grant,
//!    never by a controller socket; the table's install view re-reads the runner's store (the
//!    grant still issuable, not tombstoned) at the install.
//!
//! Nothing here reaches the controller's agent or any other signer (ADR-0012 §4.6).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use heimdall_app::OpError;
use heimdall_app::readiness_runner::{runner_bound, runner_install_check, shorten_runner_anchor};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, ClientId, EnvironmentId, GrantId};
use heimdall_contract::request::AccessPairRef;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_credential::signer::{ManagedSigner, SignerLimits};
use heimdall_credential::table::{InstallRefusal, InstallView, SignerTable};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo, VaultSlot};
use heimdall_domain::issuance::{CertificateBounds, IssuanceRefusal, principal_for};
use heimdall_domain::time::{Clock, SyncStatus, TimeStatus, TimeUncertainty};
use heimdall_issuer::remote::{
    CertificateFacts, PinnedIssuer, PreparedRemoteGrant, public_key_fingerprint, read_certificate,
};
use heimdall_store::ext_runner::{PinOutcome, RemoteGrantIssuer};
use heimdall_store::{Store, Txn};
use serde::{Deserialize, Serialize};

use crate::runner::time::RunnerTime;

/// The data of a successful `runner.install_certificate`: public facts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRemoteCertificate {
    /// The grant.
    pub grant: GrantId,
    /// Its generation.
    pub grant_generation: u64,
    /// The pair the certificate is for.
    pub pair: AccessPairRef,
    /// The certificate's serial.
    pub serial: u64,
    /// Its `valid_before`.
    pub valid_before: Timestamp,
    /// The CA that signed it (the grant's pin).
    pub ca_fingerprint: CaFingerprint,
    /// Whether every pair of the grant now has its certificate.
    pub complete: bool,
}

/// Why a prepare or an install is refused. Each maps to a contract code (and reason) through
/// [`IssuanceFailure::to_error`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuanceFailure {
    /// This installation is not a remote runner.
    #[error("this installation is not a remote runner")]
    NotARunner,
    /// No such grant in this environment.
    #[error("no such grant on this runner")]
    UnknownGrant,
    /// ADR-0005 §3.5's refusal list.
    #[error("issuance refused: {0}")]
    Refused(IssuanceRefusal),
    /// The controller or the certificate's CA is not this grant's issuer, or not in
    /// `issuer_trust` (`issuer_untrusted`).
    #[error("the issuer is not trusted for this grant")]
    IssuerUntrusted,
    /// The runner holds no K_env for this grant at that generation (never prepared, a restart,
    /// or destroyed at grant end).
    #[error("no working key for this grant and generation")]
    NoKey,
    /// The certificate is malformed, not a user certificate, or its signature fails.
    #[error("the certificate is malformed or its signature does not verify")]
    Certificate,
    /// The pair already holds a different certificate.
    #[error("the pair already has a certificate")]
    AlreadyInstalled,
    /// No qualifying time sample in this boot (`TIME_UNCERTAIN`).
    #[error("the runner's time is uncertain")]
    TimeUncertain,
    /// The key vault failed.
    #[error("the key vault is unavailable")]
    Vault,
    /// The state store failed.
    #[error("the state store is unavailable")]
    State,
}

impl IssuanceFailure {
    /// The envelope error.
    #[must_use]
    pub fn to_error(&self) -> OpError {
        let msg = self.to_string();
        match self {
            Self::NotARunner => OpError::driver_unavailable("this installation is not a remote runner"),
            Self::UnknownGrant => OpError::new(Code::NotFound, msg).with_resource("grant", None),
            Self::Refused(r) => OpError::from_issuance_refusal(r),
            Self::IssuerUntrusted => OpError::new(Code::CapabilityUnavailable, msg)
                .with_reason(reason::ISSUER_UNTRUSTED)
                .with_resource("grant", None),
            Self::NoKey | Self::AlreadyInstalled => {
                OpError::new(Code::RequestConflict, msg).with_resource("grant", None)
            }
            Self::Certificate => OpError::new(Code::CapabilityUnavailable, msg)
                .with_resource("grant", None),
            Self::TimeUncertain => OpError::new(
                Code::TimeUncertain,
                "time uncertain: no qualifying sample from this runner's designated time source in this boot",
            )
            .with_resource("clock", None),
            Self::Vault => OpError::new(Code::ServiceUnavailable, msg),
            Self::State => OpError::new(Code::StateUnavailable, msg),
        }
    }
}

fn state(_: heimdall_store::StoreError) -> IssuanceFailure {
    IssuanceFailure::State
}

/// One installed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerCertificate {
    /// The OpenSSH certificate line (public).
    pub certificate: String,
    /// Its serial.
    pub serial: u64,
    /// Its `valid_before`.
    pub valid_before: Timestamp,
    /// Its CA.
    pub ca_fingerprint: CaFingerprint,
}

struct PreparedKey {
    generation: u64,
    slot: VaultSlot,
    public: PublicKeyInfo,
    pairs: BTreeSet<AccessPairRef>,
    installed: BTreeMap<AccessPairRef, RunnerCertificate>,
}

/// The runner signer's working keys: K_env per grant, in the vault's memory only, and the
/// runner's signer table that serves them (module docs item 6).
pub struct RunnerKeys {
    vault: Arc<KeyVault>,
    keys: Mutex<HashMap<GrantId, PreparedKey>>,
    table: SignerTable,
}

/// ⟨M06 W3⟩ The runner table's install view (ADR-0008 D2 item 6's read): at the install, the
/// grant is still this runner's, issuable and not tombstoned (the full ADR-0005 §3.5 check
/// already ran in [`RunnerIssuance::install`]'s transaction; this re-reads it at the table's
/// own install, so a grant ended in between is never listed).
struct RunnerInstallView {
    store: Arc<Store>,
}

#[async_trait::async_trait]
impl InstallView for RunnerInstallView {
    async fn check(
        &self,
        grant: &GrantId,
        _entry: &heimdall_domain::issuance::IssuanceEntry,
    ) -> Result<(), InstallRefusal> {
        let live = self.store.transaction(|tx| {
            let Ok((_, g)) = runner_grant(tx, grant) else {
                return Ok(false);
            };
            Ok(g.state.permits_issuance() && tx.denied_ancestor(grant)?.is_none())
        });
        match live {
            Ok(true) => Ok(()),
            Ok(false) => Err(InstallRefusal::View("runner_grant_not_live")),
            Err(_) => Err(InstallRefusal::View("store")),
        }
    }
}

/// Drive a future that never waits on I/O (the runner table's install: its view reads the
/// store synchronously) to completion on this thread.
fn run_ready<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

impl std::fmt::Debug for RunnerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerKeys")
            .field("grants", &self.lock().len())
            .finish_non_exhaustive()
    }
}

impl RunnerKeys {
    /// Keys held in `vault`, served by a signer table over the same vault whose install view
    /// reads `store`.
    #[must_use]
    pub fn new(vault: Arc<KeyVault>, store: Arc<Store>) -> Self {
        let table = SignerTable::new(Arc::clone(&vault));
        table.set_install_view(Arc::new(RunnerInstallView { store }));
        Self {
            vault,
            keys: Mutex::new(HashMap::new()),
            table,
        }
    }

    /// ⟨M06 W3⟩ The runner's signer table (module docs item 6).
    #[must_use]
    pub fn table(&self) -> &SignerTable {
        &self.table
    }

    /// ⟨M06 W3; ADR-0012 §4.6⟩ The signer of `binding`'s endpoint, a binding of the runner grant
    /// `grant` (ADR-0008 D2: it lists and signs for that grant's installed certificates only,
    /// never the plain K_env, never another grant's key, never a controller's). `None` when
    /// the runner holds no K_env for `grant`. The caller serves it on the binding's local
    /// endpoint (`heimdall_ipc::signing`) under the runtime's `SignatureAuthority`.
    #[must_use]
    pub fn binding_signer(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &GrantId,
        authority: Arc<dyn heimdall_app::ports::SignatureAuthority>,
        limits: SignerLimits,
    ) -> Option<ManagedSigner> {
        self.table.slot(grant)?;
        self.table.attach_binding(binding, grant);
        Some(ManagedSigner::new(
            heimdall_app::ports::SignerEndpoint::Binding(binding.clone()),
            self.table.clone(),
            authority,
            limits,
        ))
    }

    /// ⟨M06 W3; runner Q7⟩ Attach `binding` to the runner grant `grant` in the runner's
    /// table, so the binding's endpoint (a registry over [`Self::table`]) lists that
    /// grant's installed certificates. `false`, attaching nothing, when the runner holds
    /// no K_env for `grant`.
    pub fn attach_binding(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &GrantId,
    ) -> bool {
        if self.table.slot(grant).is_none() {
            return false;
        }
        self.table.attach_binding(binding, grant);
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<GrantId, PreparedKey>> {
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `grant`'s K_env public half and its generation, while it is live.
    #[must_use]
    pub fn public_key(&self, grant: &GrantId) -> Option<(u64, PublicKeyInfo)> {
        self.lock()
            .get(grant)
            .map(|k| (k.generation, k.public.clone()))
    }

    /// `grant`'s vault slot (for its binding endpoint), while it is live.
    #[must_use]
    pub fn slot(&self, grant: &GrantId) -> Option<VaultSlot> {
        self.lock().get(grant).map(|k| k.slot)
    }

    /// `grant`'s installed certificates, by pair.
    #[must_use]
    pub fn certificates(&self, grant: &GrantId) -> BTreeMap<AccessPairRef, RunnerCertificate> {
        self.lock()
            .get(grant)
            .map(|k| k.installed.clone())
            .unwrap_or_default()
    }

    /// ⟨M06 U4⟩ Every grant that has a K_env now.
    #[must_use]
    pub fn grants(&self) -> Vec<GrantId> {
        self.lock().keys().cloned().collect()
    }

    /// ⟨M06 U4⟩ Every installed certificate now, as `(grant, its generation, pair,
    /// certificate)`, by grant and pair (the authority report, ADR-0012 §7.4 step 3).
    #[must_use]
    pub fn installed(&self) -> Vec<(GrantId, u64, AccessPairRef, RunnerCertificate)> {
        let mut out: Vec<_> = self
            .lock()
            .iter()
            .flat_map(|(g, k)| {
                k.installed
                    .iter()
                    .map(|(p, c)| (g.clone(), k.generation, p.clone(), c.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        out.sort_by(|a, b| (a.0.as_str(), &a.2).cmp(&(b.0.as_str(), &b.2)));
        out
    }

    /// Zeroize `grant`'s K_env and drop its certificates (also from the signer table, with
    /// its bindings); `false` when none was held.
    pub fn destroy(&self, grant: &GrantId) -> bool {
        let removed = self.lock().remove(grant);
        self.table.destroy_grant(grant);
        match removed {
            Some(k) => {
                self.vault.destroy(&k.slot);
                true
            }
            None => false,
        }
    }

    /// Zeroize every K_env (process exit, a time closure).
    pub fn destroy_all(&self) {
        let all: Vec<(GrantId, PreparedKey)> = self.lock().drain().collect();
        for (g, k) in all {
            self.table.destroy_grant(&g);
            self.vault.destroy(&k.slot);
        }
    }
}

/// Runner issuance (module docs).
pub struct RunnerIssuance {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    time: Arc<RunnerTime>,
    keys: RunnerKeys,
}

impl std::fmt::Debug for RunnerIssuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerIssuance")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// The checks every prepare and install share, in `tx`: this is a runner, the grant is this
/// environment's.
fn runner_grant(
    tx: &mut Txn<'_>,
    grant: &GrantId,
) -> Result<(EnvironmentId, heimdall_domain::grant::GrantSnapshot), IssuanceFailure> {
    if !crate::paired::is_runner(tx).map_err(state)? {
        return Err(IssuanceFailure::NotARunner);
    }
    let env = tx
        .self_environment()
        .map_err(state)?
        .ok_or(IssuanceFailure::NotARunner)?;
    let g = tx
        .grant(grant)
        .map_err(state)?
        .filter(|g| g.environment == env)
        .ok_or(IssuanceFailure::UnknownGrant)?;
    Ok((env, g))
}

/// Whether `controller` holds a CA in this runner's `issuer_trust`.
fn controller_trusted(tx: &mut Txn<'_>, controller: &ClientId) -> Result<bool, IssuanceFailure> {
    Ok(tx
        .remote_issuer_trust()
        .map_err(state)?
        .iter()
        .any(|e| &e.controller == controller))
}

/// The certificate's bounds as the predicate reads them (no CA: `issuer_trust` judges it).
fn bounds_of(facts: &CertificateFacts, principal: &str) -> CertificateBounds {
    CertificateBounds {
        serial: facts.serial,
        key_id: facts.key_id.clone(),
        principal: principal.to_owned(),
        valid_after: facts.valid_after,
        valid_before: facts.valid_before,
        extensions: facts.extensions.clone(),
        subject_fingerprint: facts.subject_fingerprint.clone(),
        ca_fingerprint: None,
    }
}

/// Whether the key ID is `heimdall:<environment>:<grant>:<decimal serial>` for `grant`.
fn key_id_names(key_id: &str, grant: &GrantId) -> bool {
    let mut parts = key_id.split(':');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("heimdall"), Some(env), Some(g), Some(serial), None)
            if EnvironmentId::parse(env).is_ok()
                && g == grant.as_str()
                && !serial.is_empty()
                && serial.parse::<u64>().is_ok()
    )
}

impl RunnerIssuance {
    /// Issuance over the runner's store, clock and time-sample state, holding K_env in
    /// `vault`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        time: Arc<RunnerTime>,
        vault: Arc<KeyVault>,
    ) -> Self {
        Self {
            keys: RunnerKeys::new(vault, Arc::clone(&store)),
            store,
            clock,
            time,
        }
    }

    /// The working keys.
    #[must_use]
    pub fn keys(&self) -> &RunnerKeys {
        &self.keys
    }

    /// The time-sample state.
    #[must_use]
    pub fn time(&self) -> &Arc<RunnerTime> {
        &self.time
    }

    /// Zeroize `grant`'s K_env (grant end; module docs item 5).
    pub fn destroy(&self, grant: &GrantId) -> bool {
        self.keys.destroy(grant)
    }

    /// `runner.prepare_remote_grant` from `controller` (module docs items 1–3).
    ///
    /// # Errors
    ///
    /// The [`IssuanceFailure`] that applies; no key is generated then.
    pub fn prepare(
        &self,
        controller: &ClientId,
        grant: &GrantId,
        generation: u64,
    ) -> Result<PreparedRemoteGrant, IssuanceFailure> {
        let (env, snapshot, bound, pin, policy) = self
            .store
            .transaction(|tx| {
                Ok((|| {
                    let (env, g) = runner_grant(tx, grant)?;
                    if !g.state.permits_issuance() {
                        return Err(IssuanceFailure::Refused(IssuanceRefusal::GrantNotIssuable(
                            g.state,
                        )));
                    }
                    if tx.authority_generation().map_err(state)?.0 != generation {
                        return Err(IssuanceFailure::Refused(IssuanceRefusal::StaleGeneration));
                    }
                    if tx.denied_ancestor(grant).map_err(state)?.is_some() {
                        return Err(IssuanceFailure::Refused(IssuanceRefusal::Tombstoned));
                    }
                    let pin = tx.remote_grant_issuer(grant).map_err(state)?;
                    match &pin {
                        Some(p) if &p.issuer_client != controller => {
                            return Err(IssuanceFailure::IssuerUntrusted);
                        }
                        Some(_) => {}
                        None if !controller_trusted(tx, controller)? => {
                            return Err(IssuanceFailure::IssuerUntrusted);
                        }
                        None => {}
                    }
                    let bound = runner_bound(tx, &g).map_err(state)?.bound;
                    // ⟨ADR-0006 §18.7 item 12⟩ The standing policy the grant rests on: the
                    // one recorded with it, else the one its origin resolves to now (the
                    // policy `runner_bound` takes the cutoff from).
                    let origin = tx.grant_origin(grant).map_err(state)?;
                    let policy = match &origin {
                        Some(o) if o.policy_id.is_some() => o.policy_id.clone(),
                        Some(o) => {
                            let context =
                                heimdall_app::policy_context::grant_context(origin.as_ref());
                            let policies =
                                tx.policies_for(&o.profile, &g.environment).map_err(state)?;
                            heimdall_domain::policy::resolve_policy(&policies, &context)
                                .map(|p| p.id.clone())
                        }
                        None => None,
                    };
                    Ok((env, g, bound, pin, policy))
                })())
            })
            .map_err(state)??;
        let public = {
            let mut keys = self.keys.lock();
            match keys.get(grant) {
                Some(k) if k.generation == generation => k.public.clone(),
                _ => {
                    if let Some(old) = keys.remove(grant) {
                        self.keys.table.destroy_grant(grant);
                        self.keys.vault.destroy(&old.slot);
                    }
                    let (slot, public) = self
                        .keys
                        .vault
                        .generate_ed25519()
                        .map_err(|_| IssuanceFailure::Vault)?;
                    // ⟨M06 W3⟩ The runner's signer serves it (module docs item 6); nothing
                    // is listed until a certificate is installed.
                    let pairs: Vec<AccessPairRef> = snapshot.scope.pairs.iter().cloned().collect();
                    if self
                        .keys
                        .table
                        .register(grant, slot, public.clone(), &pairs)
                        .is_err()
                    {
                        self.keys.vault.destroy(&slot);
                        return Err(IssuanceFailure::Vault);
                    }
                    keys.insert(
                        grant.clone(),
                        PreparedKey {
                            generation,
                            slot,
                            public: public.clone(),
                            pairs: snapshot.scope.pairs.clone(),
                            installed: BTreeMap::new(),
                        },
                    );
                    public
                }
            }
        };
        Ok(PreparedRemoteGrant {
            environment: env,
            grant: grant.clone(),
            grant_generation: generation,
            public_key: public.openssh_line,
            key_fingerprint: public.fingerprint,
            pairs: snapshot.scope.pairs.iter().cloned().collect(),
            bound,
            pinned_issuer: pin.map(|p| PinnedIssuer {
                controller: p.issuer_client,
                ca_fingerprint: p.ca_fingerprint,
            }),
            policy,
        })
    }

    /// `runner.install_certificate` from `controller` (module docs item 4).
    ///
    /// # Errors
    ///
    /// The [`IssuanceFailure`] that applies; the certificate is discarded then.
    pub fn install(
        &self,
        controller: &ClientId,
        grant: &GrantId,
        generation: u64,
        certificate: &str,
    ) -> Result<InstalledRemoteCertificate, IssuanceFailure> {
        let facts = read_certificate(certificate).map_err(|_| IssuanceFailure::Certificate)?;
        // The key: this grant's K_env at this generation.
        let (key_fingerprint, pairs, already) = {
            let keys = self.keys.lock();
            let k = keys
                .get(grant)
                .filter(|k| k.generation == generation)
                .ok_or(IssuanceFailure::NoKey)?;
            (
                k.public.fingerprint.clone(),
                k.pairs.clone(),
                k.installed.clone(),
            )
        };
        if facts.subject_fingerprint != key_fingerprint {
            return Err(IssuanceFailure::Refused(IssuanceRefusal::UnknownSubjectKey));
        }
        // Exactly one principal, one of the grant's pairs.
        let [principal] = facts.principals.as_slice() else {
            return Err(IssuanceFailure::Refused(IssuanceRefusal::WrongPrincipal));
        };
        let pair = pairs
            .iter()
            .find(|p| principal_for(p) == *principal)
            .cloned()
            .ok_or(IssuanceFailure::Refused(IssuanceRefusal::WrongPrincipal))?;
        if let Some(existing) = already.get(&pair) {
            return if existing.certificate == certificate {
                Ok(self.installed(grant, generation, &pair, existing, &pairs))
            } else {
                Err(IssuanceFailure::AlreadyInstalled)
            };
        }
        if facts.extension_data {
            return Err(IssuanceFailure::Refused(
                IssuanceRefusal::UnpermittedExtension,
            ));
        }
        if !key_id_names(&facts.key_id, grant) {
            return Err(IssuanceFailure::Certificate);
        }
        let sample = self.time.sample();
        let bounds = bounds_of(&facts, principal);
        let clock = Arc::clone(&self.clock);
        self.store
            .transaction(|tx| {
                Ok((|| {
                    let (_, g) = runner_grant(tx, grant)?;
                    // The CA: in issuer_trust for this controller, the trusted key is that CA's,
                    // and the grant's pin (if any) names this controller and CA.
                    let trusted = tx
                        .trusted_remote_issuer(&facts.ca_fingerprint)
                        .map_err(state)?
                        .filter(|e| {
                            &e.controller == controller
                                && public_key_fingerprint(&e.ca_public_key).as_deref()
                                    == Some(facts.ca_fingerprint.as_str())
                        });
                    if trusted.is_none() {
                        return Err(IssuanceFailure::IssuerUntrusted);
                    }
                    if let Some(p) = tx.remote_grant_issuer(grant).map_err(state)?
                        && (&p.issuer_client != controller
                            || p.ca_fingerprint != facts.ca_fingerprint)
                    {
                        return Err(IssuanceFailure::IssuerUntrusted);
                    }
                    // The safe deadline: the runner anchor from the latest qualifying sample.
                    let now = clock.observe();
                    let time = match &sample {
                        Some(s) if s.exchange.boot_id == now.boot_id => {
                            let bound = runner_bound(tx, &g).map_err(state)?.bound;
                            shorten_runner_anchor(tx, grant, bound, &s.exchange, &now, false)
                                .map_err(state)?;
                            TimeStatus::Safe
                        }
                        _ => TimeStatus::Uncertain(TimeUncertainty::Unsynchronized {
                            sync: SyncStatus::Unknown,
                        }),
                    };
                    let verdict = runner_install_check(
                        tx,
                        &g,
                        &pair,
                        &bounds,
                        generation,
                        facts.critical_option,
                        time,
                        &now,
                    )
                    .map_err(state)?;
                    match verdict {
                        Ok(()) => {}
                        Err(IssuanceRefusal::TimeUncertain) => {
                            return Err(IssuanceFailure::TimeUncertain);
                        }
                        Err(r) => return Err(IssuanceFailure::Refused(r)),
                    }
                    match tx
                        .pin_remote_grant_issuer(&RemoteGrantIssuer {
                            grant: grant.clone(),
                            issuer_client: controller.clone(),
                            ca_fingerprint: facts.ca_fingerprint.clone(),
                            grant_generation: generation,
                            pinned_at: now.wall,
                        })
                        .map_err(state)?
                    {
                        PinOutcome::Pinned | PinOutcome::Same => Ok(()),
                        PinOutcome::Conflict(_) => Err(IssuanceFailure::IssuerUntrusted),
                    }
                })())
            })
            .map_err(state)??;
        // Installed only while the same K_env is still live (a revocation may have destroyed
        // it meanwhile: then nothing is installed and the entry stays counted).
        let live =
            self.keys.lock().get(grant).is_some_and(|k| {
                k.generation == generation && k.public.fingerprint == key_fingerprint
            });
        if !live {
            return Err(IssuanceFailure::NoKey);
        }
        let cert = RunnerCertificate {
            certificate: certificate.to_owned(),
            serial: facts.serial,
            valid_before: facts.valid_before,
            ca_fingerprint: facts.ca_fingerprint.clone(),
        };
        // ⟨M06 W3⟩ Installed in the runner's signer table too (module docs item 6), against
        // an entry built from the facts just accepted; its view re-reads the grant.
        let entry = heimdall_domain::issuance::IssuanceEntry {
            id: heimdall_contract::ids::IssuanceId::from_random_bytes(
                heimdall_app::ids::random_u64()
                    .and_then(|a| heimdall_app::ids::random_u64().map(|b| (a, b)))
                    .map(|(a, b)| {
                        let mut out = [0u8; 16];
                        out[..8].copy_from_slice(&a.to_be_bytes());
                        out[8..].copy_from_slice(&b.to_be_bytes());
                        out
                    })
                    .map_err(|_| IssuanceFailure::Vault)?,
            ),
            grant: grant.clone(),
            generation: heimdall_domain::policy::AuthorityGeneration(generation),
            pair: pair.clone(),
            bounds: CertificateBounds {
                ca_fingerprint: Some(facts.ca_fingerprint.clone()),
                ..bounds.clone()
            },
            state: heimdall_domain::issuance::IssuanceState::Published,
            reserved_at: self.clock.wall(),
            settled_at: Some(self.clock.wall()),
            void_reason: None,
            continuing: false,
        };
        let parsed = ssh_key::Certificate::from_openssh(certificate.trim())
            .map_err(|_| IssuanceFailure::Certificate)?;
        run_ready(self.keys.table.install(grant, &pair, &parsed, &entry))
            .map_err(|_| IssuanceFailure::Certificate)?;
        let mut keys = self.keys.lock();
        let k = keys
            .get_mut(grant)
            .filter(|k| k.generation == generation && k.public.fingerprint == key_fingerprint)
            .ok_or(IssuanceFailure::NoKey)?;
        k.installed.insert(pair.clone(), cert.clone());
        let complete = k.installed.len() == k.pairs.len();
        Ok(InstalledRemoteCertificate {
            grant: grant.clone(),
            grant_generation: generation,
            pair,
            serial: cert.serial,
            valid_before: cert.valid_before,
            ca_fingerprint: cert.ca_fingerprint,
            complete,
        })
    }

    fn installed(
        &self,
        grant: &GrantId,
        generation: u64,
        pair: &AccessPairRef,
        cert: &RunnerCertificate,
        pairs: &BTreeSet<AccessPairRef>,
    ) -> InstalledRemoteCertificate {
        let complete = self
            .keys
            .lock()
            .get(grant)
            .is_some_and(|k| k.installed.len() == pairs.len());
        InstalledRemoteCertificate {
            grant: grant.clone(),
            grant_generation: generation,
            pair: pair.clone(),
            serial: cert.serial,
            valid_before: cert.valid_before,
            ca_fingerprint: cert.ca_fingerprint.clone(),
            complete,
        }
    }

    /// Whether `grant` is still a live runner grant here (issuable, not tombstoned); used by
    /// the caller that ends grants to know when to [`Self::destroy`].
    ///
    /// # Errors
    ///
    /// [`IssuanceFailure::State`].
    pub fn grant_state(&self, grant: &GrantId) -> Result<Option<GrantState>, IssuanceFailure> {
        self.store
            .transaction(|tx| Ok(tx.grant(grant)?.map(|g| g.state)))
            .map_err(state)
    }
}
