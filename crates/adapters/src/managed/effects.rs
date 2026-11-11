//! ⟨M03⟩ The managed effects (ADR-0008 D6 item 0; m03-plan U6
//! `effects::ManagedEffectsImpl`): `generate_key`, `install` and `destroy` over U2's
//! signer table and key vault, `materialize` and `clear` over [`super::files`].
//!
//! The stage sequence, the store transactions and the receipts are
//! `app::managed::drive_preparation`'s (U10, wave 4; reading R5): this type performs
//! an effect only when asked.
//!
//! **Bounded; drop contract** (`app::ports::CredentialAdapter`). `generate_key` and
//! `destroy` are in-memory work (vault and table), with no await. `install` awaits
//! only the signer table's D2 item 6 store view, under [`ManagedEffectsImpl`]'s own
//! bound (`call_timeout`); a dropped or timed-out `install` installs nothing (the
//! table inserts the certificate only after the view answers). Nothing here spawns a
//! task, a thread or a timer. `materialize` and `clear` are synchronous file work for
//! the blocking pool.
//!
//! **`install` needs a store view** (U2-Q2): `SignerTable::install` refuses without an
//! `InstallView` (`table::INSTALL_STORE_VIEW_WIRED = false`) and this type does not
//! set one; U10 wires the production view, tests set a fixture view on the table.
//!
//! **K_env's pairs** (U6-Q2): `ManagedEffects::generate_key(grant, token)` names no
//! pairs, while `SignerTable::generate` registers the key for its pairs. The pairs come
//! from a [`GrantScopes`] source (U10: the grant's stored scope; default: none, so the
//! call refuses, fail closed).

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::ports::{
    AdapterError, KeyRegistration, ManagedEffects, MaterializeSpec, MaterializedFiles,
};
use heimdall_contract::ids::{BindingId, DestinationId, GrantId};
use heimdall_contract::provider::EndpointRef;
use heimdall_credential::endpoints::EndpointRegistry;
use heimdall_credential::table::{InstallRefusal, SignerTable};
use heimdall_domain::issuance::IssuanceEntry;
use heimdall_domain::scope::AccessPair;

use super::files::{self, BindingFiles, ClearOutcome, FilesError, SlotRoot};

/// Where K_env's pairs come from (U6-Q2). U10 implements it over the grant's stored
/// scope; the default knows no grant (fail closed).
pub trait GrantScopes: Send + Sync {
    /// The pairs of `grant`, `None` when unknown.
    fn pairs(&self, grant: &GrantId) -> Option<Vec<AccessPair>> {
        let _ = grant;
        None
    }
}

/// Knows no grant: every `generate_key` refuses.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGrantScopes;

impl GrantScopes for NoGrantScopes {}

/// Where binding endpoints are found (U2's `EndpointRegistry`, or a fixture).
pub trait BindingEndpoints: Send + Sync {
    /// The newest endpoint of `binding`, if it exists.
    fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef>;
}

impl BindingEndpoints for EndpointRegistry {
    fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
        EndpointRegistry::binding_endpoint(self, binding).map(|(e, _)| e)
    }
}

/// The default bound of one `install` (the M02 adapter-call bound).
pub const DEFAULT_CALL_TIMEOUT: Duration = heimdall_app::ports::DEFAULT_ADAPTER_CALL_TIMEOUT;

/// The `AdapterError::Unavailable` text when [`GrantScopes`] knows no pairs.
pub const GRANT_SCOPE_UNAVAILABLE: &str = "grant_scope_unavailable";
/// The `AdapterError::Unavailable` text when the binding has no endpoint.
pub const BINDING_ENDPOINT_UNAVAILABLE: &str = "binding_endpoint_unavailable";
/// The `AdapterError::Unavailable` text when the table has no store view (U2-Q2).
pub const INSTALL_VIEW_UNAVAILABLE: &str = "store_view_unavailable";

#[derive(Debug, Clone)]
struct Generated {
    token: String,
    registration: KeyRegistration,
}

#[derive(Default)]
struct State {
    /// The token each live key was generated under.
    generated: HashMap<GrantId, Generated>,
    /// The installed certificate lines (public), per grant and pair: what the files
    /// and the slots carry.
    certificates: HashMap<GrantId, Vec<(AccessPair, String)>>,
    /// The files each binding's last materialization wrote.
    bindings: HashMap<BindingId, BindingFiles>,
}

/// The managed effects (module docs). Cloning shares it.
#[derive(Clone)]
pub struct ManagedEffectsImpl {
    table: SignerTable,
    endpoints: Arc<dyn BindingEndpoints>,
    scopes: Arc<dyn GrantScopes>,
    runtime_dir: PathBuf,
    slots: SlotRoot,
    call_timeout: Duration,
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for ManagedEffectsImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedEffectsImpl")
            .field("call_timeout", &self.call_timeout)
            .finish_non_exhaustive()
    }
}

fn adapter_from_files(e: &FilesError) -> AdapterError {
    match e {
        FilesError::Content(_) | FilesError::Path(_) | FilesError::Environment => {
            AdapterError::Protocol(e.to_string())
        }
        FilesError::Directory(_) | FilesError::Io(_) => AdapterError::Unavailable(e.to_string()),
    }
}

fn install_error(r: InstallRefusal) -> AdapterError {
    match r {
        InstallRefusal::StoreViewUnavailable => {
            AdapterError::Unavailable(INSTALL_VIEW_UNAVAILABLE.to_owned())
        }
        other => AdapterError::Protocol(format!("install refused: {}", other.code())),
    }
}

impl ManagedEffectsImpl {
    /// Effects over `table`, finding binding endpoints in `endpoints`, K_env's pairs in
    /// `scopes`, binding files under `runtime_dir` and slots under `slots`.
    #[must_use]
    pub fn new(
        table: SignerTable,
        endpoints: Arc<dyn BindingEndpoints>,
        scopes: Arc<dyn GrantScopes>,
        runtime_dir: PathBuf,
        slots: SlotRoot,
    ) -> Self {
        Self {
            table,
            endpoints,
            scopes,
            runtime_dir,
            slots,
            call_timeout: DEFAULT_CALL_TIMEOUT,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// With another bound for `install`.
    #[must_use]
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The signer table.
    #[must_use]
    pub fn table(&self) -> &SignerTable {
        &self.table
    }

    /// The slot root (`Paths.state_dir` and its environment).
    #[must_use]
    pub fn slot_root(&self) -> &SlotRoot {
        &self.slots
    }

    /// The runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> &std::path::Path {
        &self.runtime_dir
    }

    /// The installed certificate line of `grant` for `pair` (public), if installed
    /// through this instance.
    #[must_use]
    pub fn certificate(&self, grant: &GrantId, pair: &AccessPair) -> Option<String> {
        self.lock()
            .certificates
            .get(grant)
            .and_then(|v| v.iter().find(|(p, _)| p == pair).map(|(_, c)| c.clone()))
    }

    /// The pairs of `grant`, from the [`GrantScopes`] source.
    #[must_use]
    pub fn grant_pairs(&self, grant: &GrantId) -> Option<Vec<AccessPair>> {
        self.scopes.pairs(grant)
    }

    /// Whether `grant`'s live key was generated under `token` (reconcile's check that
    /// the installed key is this effect's).
    #[must_use]
    pub fn generated_under(&self, grant: &GrantId, token: &str) -> bool {
        let live = self.table.public_key(grant);
        self.lock().generated.get(grant).is_some_and(|g| {
            g.token == token && live.is_some_and(|k| k.fingerprint == g.registration.fingerprint)
        })
    }

    /// The binding's files, from its endpoint (R2) for `dests`.
    fn files_for(
        &self,
        binding: &BindingId,
        dests: &[DestinationId],
    ) -> Result<BindingFiles, AdapterError> {
        let endpoint = self
            .endpoints
            .binding_endpoint(binding)
            .ok_or_else(|| AdapterError::Unavailable(BINDING_ENDPOINT_UNAVAILABLE.to_owned()))?;
        files::binding_files_for_endpoint(&self.runtime_dir, &endpoint, dests)
            .ok_or_else(|| AdapterError::Unavailable(BINDING_ENDPOINT_UNAVAILABLE.to_owned()))
    }

    /// Write `pair`'s environment slot for `binding` at the slot's `generation` (D10
    /// item 2: the files first, **then** the environment endpoint lists the key), from
    /// the binding's grant's key and installed certificate. Used by [`Self::materialize`]
    /// and the slot claim ([`ManagedSlotTable`]).
    ///
    /// # Errors
    /// [`AdapterError`]; on a listing refusal the files just written are cleared.
    pub fn materialize_slot(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
        generation: u64,
    ) -> Result<Vec<PathBuf>, AdapterError> {
        let grant = self
            .table
            .binding_grant(binding)
            .ok_or_else(|| AdapterError::Protocol("binding_not_attached".to_owned()))?;
        let key = self
            .table
            .public_key(&grant)
            .ok_or_else(|| AdapterError::Protocol("no_key".to_owned()))?;
        let cert = self
            .certificate(&grant, pair)
            .ok_or_else(|| AdapterError::Protocol("not_installed".to_owned()))?;
        let written = files::write_slot(
            &self.slots,
            &self.slots.environment,
            pair,
            binding,
            generation,
            &key.openssh_line,
            &cert,
        )
        .map_err(|e| adapter_from_files(&e))?;
        if let Err(e) = self.table.materialize(binding, std::slice::from_ref(pair)) {
            let _ = files::clear_slot(&self.slots, &self.slots.environment, pair, generation);
            return Err(AdapterError::Protocol(format!("materialize refused: {e}")));
        }
        Ok(written)
    }

    /// Clear `pair`'s slot of `generation` (D10 item 2: `held → clearing`, the key
    /// unlisted at once, then the files of `generation` removed).
    ///
    /// # Errors
    /// [`AdapterError`].
    pub fn clear_slot(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
        generation: u64,
    ) -> Result<ClearOutcome, AdapterError> {
        self.table.unmaterialize(binding);
        files::clear_slot(&self.slots, &self.slots.environment, pair, generation)
            .map_err(|e| adapter_from_files(&e))
    }
}

#[async_trait]
impl ManagedEffects for ManagedEffectsImpl {
    async fn generate_key(
        &self,
        grant: &GrantId,
        token: &str,
    ) -> Result<KeyRegistration, AdapterError> {
        let live = self.table.public_key(grant);
        if let Some(g) = self.lock().generated.get(grant).cloned() {
            match live {
                Some(k) if k.fingerprint == g.registration.fingerprint => {
                    return if g.token == token {
                        // The same effect token: the same key, no second effect.
                        Ok(g.registration)
                    } else {
                        Err(AdapterError::Protocol("already_registered".to_owned()))
                    };
                }
                // The key was destroyed: a repeated token does not regenerate it.
                _ if g.token == token => {
                    return Err(AdapterError::Protocol("key_destroyed".to_owned()));
                }
                _ => {}
            }
        }
        let pairs = self
            .scopes
            .pairs(grant)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| AdapterError::Unavailable(GRANT_SCOPE_UNAVAILABLE.to_owned()))?;
        let registration = self
            .table
            .generate(grant, &pairs)
            .map_err(|r| AdapterError::Protocol(format!("register refused: {}", r.code())))?;
        self.lock().generated.insert(
            grant.clone(),
            Generated {
                token: token.to_owned(),
                registration: registration.clone(),
            },
        );
        Ok(registration)
    }

    async fn install(
        &self,
        grant: &GrantId,
        entry: &IssuanceEntry,
        cert: &str,
    ) -> Result<(), AdapterError> {
        let line = cert.trim_end_matches('\n');
        // `ssh_key::Certificate` by inference from `SignerTable::install` (no direct
        // dependency on the parser crate: U6-Q1).
        let parsed = line
            .parse()
            .map_err(|_| AdapterError::Protocol("certificate_unparsable".to_owned()))?;
        let result = tokio::time::timeout(
            self.call_timeout,
            self.table.install(grant, &entry.pair, &parsed, entry),
        )
        .await
        .map_err(|_| AdapterError::OutcomeUnknown("install_timed_out".to_owned()))?;
        result.map_err(install_error)?;
        let mut s = self.lock();
        let certs = s.certificates.entry(grant.clone()).or_default();
        certs.retain(|(p, _)| p != &entry.pair);
        certs.push((entry.pair.clone(), line.to_owned()));
        Ok(())
    }

    async fn destroy(&self, grants: &[GrantId]) -> Result<(), AdapterError> {
        for g in grants {
            self.table.destroy_grant(g);
            let mut s = self.lock();
            s.certificates.remove(g);
            // The token record stays, so a replay of the same token never regenerates.
        }
        Ok(())
    }

    fn materialize(
        &self,
        binding: &BindingId,
        spec: &MaterializeSpec,
    ) -> Result<MaterializedFiles, AdapterError> {
        let grant = self
            .table
            .binding_grant(binding)
            .ok_or_else(|| AdapterError::Protocol("binding_not_attached".to_owned()))?;
        let key = self
            .table
            .public_key(&grant)
            .ok_or_else(|| AdapterError::Protocol("no_key".to_owned()))?;
        if key.openssh_line.trim_end() != spec.public_key.trim_end() {
            return Err(AdapterError::Protocol("public_key_mismatch".to_owned()));
        }
        let dests: Vec<DestinationId> = spec
            .certificates
            .iter()
            .map(|c| c.pair.destination.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if dests.len() != spec.certificates.len() {
            return Err(AdapterError::Protocol(
                "one_certificate_per_pair".to_owned(),
            ));
        }
        let files = self.files_for(binding, &dests)?;
        let certs: Vec<(DestinationId, String)> = spec
            .certificates
            .iter()
            .map(|c| (c.pair.destination.clone(), c.certificate.clone()))
            .collect();
        let mut written =
            files::write_binding_files(&files, binding, spec.generation, &spec.public_key, &certs)
                .map_err(|e| adapter_from_files(&e))?;
        self.lock().bindings.insert(binding.clone(), files.clone());
        if spec.environment_slots {
            for c in &spec.certificates {
                written.extend(self.materialize_slot(binding, &c.pair, spec.generation)?);
            }
        }
        Ok(MaterializedFiles {
            directory: files.directory,
            files: written,
            generation: spec.generation,
        })
    }

    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError> {
        // The key is unlisted from the environment endpoint at once (D10 item 2).
        self.table.unmaterialize(binding);
        let remembered = self.lock().bindings.get(binding).cloned();
        let mut dirs: Vec<BindingFiles> = remembered.into_iter().collect();
        for (dir, g) in files::binding_directories_of(&self.runtime_dir, binding) {
            if g == generation && !dirs.iter().any(|f| f.directory == dir) {
                dirs.push(BindingFiles {
                    key_pub: dir.join(files::BINDING_KEY_FILE),
                    certificates: Vec::new(),
                    directory: dir,
                });
            }
        }
        for f in &dirs {
            files::clear_binding_files(f, binding, generation)
                .map_err(|e| adapter_from_files(&e))?;
        }
        for (dir, g) in files::slots_written_by(&self.slots.data_dir, binding) {
            if g == generation {
                files::clear_slot_dir(&dir, binding, generation)
                    .map_err(|e| adapter_from_files(&e))?;
            }
        }
        Ok(())
    }
}

// --- the slot table for `run` (wave-2 request; D10 items 2 and 5) --------------------

/// The store side of the slot table (D10 item 2). U10 implements it over
/// `heimdall_store::Txn::{slot, claim_slot}` and serves it to `run` through the
/// runtime; the default knows no slot (every call fails closed).
pub trait SlotStore: Send + Sync {
    /// The slot of `pair` (`free(0)` for one never claimed).
    ///
    /// # Errors
    /// [`AdapterError`]; the default is `Unavailable("driver_unavailable")`.
    fn slot(
        &self,
        environment: &heimdall_contract::ids::EnvironmentId,
        pair: &AccessPair,
    ) -> Result<heimdall_domain::managed::SlotState, AdapterError> {
        let _ = (environment, pair);
        Err(AdapterError::Unavailable(SLOT_STORE_UNAVAILABLE.to_owned()))
    }

    /// Claim the slot of `pair` for `binding` in one store transaction: CAS `free(g) →
    /// held(binding, g + 1)`, idempotent for the holder (`Txn::claim_slot`). The inner
    /// `Err` is the table's refusal.
    ///
    /// # Errors
    /// [`AdapterError`]; the default is `Unavailable("driver_unavailable")`.
    fn claim(
        &self,
        environment: &heimdall_contract::ids::EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
    ) -> Result<
        Result<heimdall_domain::managed::SlotState, heimdall_domain::managed::SlotRefusal>,
        AdapterError,
    > {
        let _ = (environment, pair, binding);
        Err(AdapterError::Unavailable(SLOT_STORE_UNAVAILABLE.to_owned()))
    }
}

/// The text of the default [`SlotStore`]'s refusal (`CAPABILITY_UNAVAILABLE`,
/// `driver_unavailable`, as `run_cmd::UnavailableSlots`).
pub const SLOT_STORE_UNAVAILABLE: &str = "driver_unavailable";

/// The default [`SlotStore`]: no slot table in this build.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSlotStore;

impl SlotStore for NoSlotStore {}

/// Why a slot claim failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotClaimError {
    /// The table refused (`managed_slot_held`: `CONFIG_CONFLICT`, next
    /// `release_binding`; a `clearing` slot: not applicable yet).
    Refused(heimdall_domain::managed::SlotRefusal),
    /// The store or the files failed; when the claim committed, the slot is held
    /// with no files (ssh fails closed for the alias) until it is released.
    Failed(AdapterError),
}

/// The slot table `run` needs (`heimdall::run_cmd::ManagedSlots`; wave-2 request): a
/// pair's [`SlotState`](heimdall_domain::managed::SlotState) from the store, and a
/// claim of a free slot for a binding: the store's CAS first (through [`SlotStore`],
/// U10's), then the slot files, then the environment listing (D10 item 2).
pub struct ManagedSlotTable<S: SlotStore> {
    store: S,
    effects: ManagedEffectsImpl,
}

impl<S: SlotStore> ManagedSlotTable<S> {
    /// The table over `store` and `effects`.
    pub fn new(store: S, effects: ManagedEffectsImpl) -> Self {
        Self { store, effects }
    }

    /// The slot of `pair` in the effects' environment.
    ///
    /// # Errors
    /// [`AdapterError`].
    pub fn state(
        &self,
        pair: &AccessPair,
    ) -> Result<heimdall_domain::managed::SlotState, AdapterError> {
        self.store.slot(&self.effects.slot_root().environment, pair)
    }

    /// Claim `pair`'s slot for `binding` and write its files at the new generation;
    /// a slot `binding` already holds is rewritten at its generation (idempotent).
    /// A slot another binding holds is refused before any write.
    ///
    /// # Errors
    /// [`SlotClaimError`].
    pub fn claim(
        &self,
        binding: &BindingId,
        pair: &AccessPair,
    ) -> Result<heimdall_domain::managed::SlotState, SlotClaimError> {
        use heimdall_domain::managed::{SlotEvent, SlotState, slot_transition};
        let env = self.effects.slot_root().environment.clone();
        let current = self
            .store
            .slot(&env, pair)
            .map_err(SlotClaimError::Failed)?;
        slot_transition(
            &current,
            &SlotEvent::Claim {
                binding: binding.clone(),
            },
        )
        .map_err(SlotClaimError::Refused)?;
        let held = self
            .store
            .claim(&env, pair, binding)
            .map_err(SlotClaimError::Failed)?
            .map_err(SlotClaimError::Refused)?;
        let SlotState::Held { generation, .. } = &held else {
            return Err(SlotClaimError::Failed(AdapterError::Protocol(
                "slot_not_held_after_claim".to_owned(),
            )));
        };
        self.effects
            .materialize_slot(binding, pair, *generation)
            .map_err(SlotClaimError::Failed)?;
        Ok(held)
    }
}
