//! ⟨M03⟩ wave 4 (U10): the managed adapter's store-backed sources (ADR-0008 §17.20
//! "For U10"; reading R6 of wave 3).
//!
//! * [`StoreSources`] implements `heimdall_adapters::managed::prepare::ManagedSourceRead`,
//!   `heimdall_adapters::managed::effects::{GrantScopes, SlotStore}` over the state
//!   store. A store failure claims nothing (no enrollment, no CA, no slot: fail
//!   closed), and a slot failure is an `AdapterError`.
//!   * **`GrantScopes`** reads the grant's **stored** scope only (U6-Q1/Q2), never a
//!     request or a process file. It is called by `generate_key`, the activation's
//!     (and the re-issue's) first effect, outside the adapter bound; the same read
//!     **records the grant's terms** in memory (its effective lock behaviour and
//!     connection policy).
//!   * **`terms`** answers only what was recorded (U6-Q5 amended, §17.20 item 14):
//!     a grant whose terms were never recorded has none, and the report refuses
//!     `grant_terms_unavailable`, never a default `continue`.
//! * [`OpsInstallView`] is the production `heimdall_credential::table::InstallView`
//!   (U2-Q2): D2 item 6's read is `Operations::managed_install_check`.
//! * [`StoreCleanup`] is the managed adapter's [`EndCleanup`]: after a grant ended
//!   (revocation, release, expiry), outside every gate, each slot its bindings hold is
//!   cleared **by its own store generation** (U6-Q4: `held → clearing`, the files and
//!   the listing of that generation removed, `clearing → free`; a slot whose pair had
//!   no owned master gets its stable path cleared too), the binding files are removed
//!   by generation, and the owned connections are closed through the connection
//!   supervisor as the end requires. ⟨round 3, §17.22 items 9–10⟩ A slot is freed
//!   only after its binding's files and its mux path are gone (the `clearing` row
//!   stays the obligation until then), every binding of the grant is found (a
//!   released one included), and for a grant that has **not** ended only its released
//!   bindings are cleaned (D10 item 2).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use heimdall_adapters::managed::EndCleanup;
use heimdall_adapters::managed::effects::{GrantScopes, ManagedEffectsImpl, SlotStore};
use heimdall_adapters::managed::files;
use heimdall_adapters::managed::prepare::{GrantTerms, ManagedSourceRead};
use heimdall_app::Operations;
use heimdall_app::ports::{
    AdapterError, IssuerPort, IssuerStatusSnapshot, ManagedEffects, ManagedSlot,
};
use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, CaFingerprint, EnvironmentId, GrantId};
use heimdall_contract::managed::{ConnectionKind, LockBehavior};
use heimdall_credential::table::{InstallRefusal, InstallView};
use heimdall_domain::enrollment::EnrollmentRecord;
use heimdall_domain::issuance::IssuanceEntry;
use heimdall_domain::managed::{OwnedConnection, SlotRefusal, SlotState};
use heimdall_domain::scope::AccessPair;
use heimdall_store::{ManagedSlot as StoreSlot, Store};

use crate::connections::{ConnectionSupervisor, effective_policy_in};

/// The store-backed managed sources (module docs).
#[derive(Clone)]
pub struct StoreSources {
    store: Arc<Store>,
    environment: EnvironmentId,
    /// The terms recorded at activation (in-memory; U6-Q5).
    terms: Arc<Mutex<HashMap<GrantId, GrantTerms>>>,
    /// The R3 lock floor (`[session] lock_behavior`), joined into the recorded lock
    /// behaviour fail closed.
    floor: Arc<RwLock<LockBehavior>>,
    /// The issuer client whose last observed status `issuer()` reports.
    issuer: Arc<RwLock<Option<Arc<dyn IssuerPort>>>>,
}

impl std::fmt::Debug for StoreSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSources")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl StoreSources {
    /// Sources over `store` for `environment`.
    #[must_use]
    pub fn new(store: Arc<Store>, environment: EnvironmentId) -> Self {
        Self {
            store,
            environment,
            terms: Arc::default(),
            floor: Arc::new(RwLock::new(LockBehavior::Continue)),
            issuer: Arc::default(),
        }
    }

    /// Set the R3 lock floor joined into every recorded lock behaviour (call before
    /// the first activation; the default is `continue`, the floor that adds nothing).
    pub fn set_lock_floor(&self, floor: LockBehavior) {
        *self.floor.write().unwrap_or_else(PoisonError::into_inner) = floor;
    }

    /// Set the issuer client whose status `ManagedSourceRead::issuer` reports
    /// (without one: no status, so the issuer is not `ready` in any report).
    pub fn set_issuer(&self, issuer: Arc<dyn IssuerPort>) {
        *self.issuer.write().unwrap_or_else(PoisonError::into_inner) = Some(issuer);
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The environment.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    fn read<R>(
        &self,
        f: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<R>,
    ) -> Option<R> {
        self.store.transaction(f).ok()
    }

    /// Record `grant`'s terms from the store now (its origin's lock behaviour joined
    /// with the current applicable policies and the floor; the effective connection
    /// policy). Nothing is recorded for an unknown grant or a failed read.
    fn record_terms(&self, tx: &mut heimdall_store::Txn<'_>, grant: &GrantId) {
        let floor = *self.floor.read().unwrap_or_else(PoisonError::into_inner);
        let read = (|| -> heimdall_store::Result<Option<GrantTerms>> {
            let Some(g) = tx.grant(grant)? else {
                return Ok(None);
            };
            let origin = tx.grant_origin(grant)?;
            let policies = match &origin {
                Some(o) => tx.policies_for(&o.profile, &g.environment)?,
                None => Vec::new(),
            };
            let lock_behavior = heimdall_app::lock::effective_behavior_with_floor(
                origin.as_ref(),
                &policies,
                floor,
            );
            let policy = effective_policy_in(tx, grant, None)?;
            Ok(Some(GrantTerms {
                lock_behavior,
                policy,
            }))
        })();
        if let Ok(Some(t)) = read {
            self.terms
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(grant.clone(), t);
        }
    }
}

impl ManagedSourceRead for StoreSources {
    fn enrollments(&self, pairs: &[AccessPair]) -> Vec<EnrollmentRecord> {
        self.read(|tx| {
            let mut out = Vec::new();
            for p in pairs {
                out.extend(tx.enrollments_for_pair(p)?);
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    fn issuing_cas(&self, pairs: &[AccessPair]) -> BTreeMap<AccessPair, BTreeSet<CaFingerprint>> {
        self.read(|tx| {
            let mut out = BTreeMap::new();
            for p in pairs {
                let cas = tx
                    .pair_preference(p)?
                    .map(|pref| pref.issuing_cas)
                    .unwrap_or_default();
                out.insert(p.clone(), cas);
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    fn slots(&self, pairs: &[AccessPair]) -> Vec<ManagedSlot> {
        self.read(|tx| {
            let mut out = Vec::new();
            for p in pairs {
                out.push(ManagedSlot {
                    environment: self.environment.clone(),
                    pair: p.clone(),
                    state: tx.slot(&self.environment, p)?,
                });
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    fn issuer(&self) -> Option<IssuerStatusSnapshot> {
        self.issuer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|i| i.status())
    }

    fn terms(&self, grant: &GrantId) -> Option<GrantTerms> {
        self.terms
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(grant)
            .copied()
    }

    fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
        let mut out = vec![grant.clone()];
        if let Some(d) = self.read(|tx| tx.grant_descendants(grant)) {
            out.extend(d);
        }
        out
    }

    fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
        self.read(|tx| {
            let mut out = Vec::new();
            for g in grants {
                out.extend(tx.issuance_entries(g)?);
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    fn key_only_restore(&self) -> bool {
        // A failed read cannot rule a key-only restore out: every residual is then
        // reported `unbounded_unknown` (fail closed).
        self.read(|tx| Ok(tx.issuers()?.iter().any(|i| i.restored_without_log)))
            .unwrap_or(true)
    }

    fn owned_connections(&self, grants: &[GrantId]) -> Vec<OwnedConnection> {
        self.read(|tx| {
            let mut out = Vec::new();
            for g in grants {
                out.extend(tx.owned_connections_for_grant(g)?);
            }
            Ok(out)
        })
        .unwrap_or_default()
    }
}

impl GrantScopes for StoreSources {
    fn pairs(&self, grant: &GrantId) -> Option<Vec<AccessPair>> {
        self.store
            .transaction(|tx| {
                let pairs = tx
                    .grant(grant)?
                    .map(|g| g.scope.pairs.into_iter().collect::<Vec<_>>());
                if pairs.is_some() {
                    self.record_terms(tx, grant);
                }
                Ok(pairs)
            })
            .ok()
            .flatten()
    }
}

impl SlotStore for StoreSources {
    fn slot(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
    ) -> Result<SlotState, AdapterError> {
        self.store
            .transaction(|tx| tx.slot(environment, pair))
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))
    }

    fn claim(
        &self,
        environment: &EnvironmentId,
        pair: &AccessPair,
        binding: &BindingId,
    ) -> Result<Result<SlotState, SlotRefusal>, AdapterError> {
        let at = Timestamp::now();
        self.store
            .transaction(|tx| tx.claim_slot(environment, pair, binding, at))
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))
    }
}

/// The production install view (U2-Q2): D2 item 6's read is
/// `Operations::managed_install_check`.
#[derive(Clone)]
pub struct OpsInstallView {
    ops: Operations,
}

impl std::fmt::Debug for OpsInstallView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsInstallView").finish_non_exhaustive()
    }
}

impl OpsInstallView {
    /// The view over `ops`.
    #[must_use]
    pub fn new(ops: Operations) -> Self {
        Self { ops }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl InstallView for OpsInstallView {
    fn check<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        grant: &'life1 GrantId,
        entry: &'life2 IssuanceEntry,
    ) -> BoxFuture<'async_trait, Result<(), InstallRefusal>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            self.ops
                .managed_install_check(grant, entry)
                .await
                .map_err(InstallRefusal::View)
        })
    }
}

/// The runtime's cleanup after a managed grant ended (module docs).
#[derive(Clone)]
pub struct StoreCleanup {
    sources: StoreSources,
    effects: ManagedEffectsImpl,
    connections: Option<Arc<ConnectionSupervisor>>,
}

impl std::fmt::Debug for StoreCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreCleanup")
            .field("connections", &self.connections.is_some())
            .finish_non_exhaustive()
    }
}

/// How a grant ended, as its stored state shows it (the connection policy's event).
fn end_of(state: GrantState) -> Option<heimdall_domain::connection::ConnectionEnd> {
    use heimdall_domain::connection::ConnectionEnd;
    match state {
        GrantState::Revoking | GrantState::Revoked => Some(ConnectionEnd::Revocation),
        GrantState::Released => Some(ConnectionEnd::Release),
        GrantState::Expired | GrantState::Failed | GrantState::Cancelled => {
            Some(ConnectionEnd::AdmissionDeadline)
        }
        _ => None,
    }
}

impl StoreCleanup {
    /// The cleanup over `sources` and `effects`, closing connections through
    /// `connections` (`None`: no connection supervisor in this process).
    #[must_use]
    pub fn new(
        sources: StoreSources,
        effects: ManagedEffectsImpl,
        connections: Option<Arc<ConnectionSupervisor>>,
    ) -> Self {
        Self {
            sources,
            effects,
            connections,
        }
    }

    /// The bindings of `grant` the store knows (its references, the bindings of its
    /// owned connections and ⟨§17.22 items 9–10⟩ every binding whose grant it is, a
    /// released one included), with the slots each holds, and the control paths of
    /// the grant's owned masters.
    fn bindings_and_slots(
        &self,
        grant: &GrantId,
    ) -> heimdall_store::Result<(Vec<BindingId>, Vec<StoreSlot>, BTreeSet<String>)> {
        self.sources.store.transaction(|tx| {
            let mut bindings: BTreeSet<BindingId> = tx
                .grant_references(grant)?
                .into_iter()
                .map(|r| r.binding)
                .collect();
            let rows = tx.owned_connections_for_grant(grant)?;
            let masters: BTreeSet<String> = rows
                .iter()
                .filter(|c| c.kind == ConnectionKind::Master)
                .filter_map(|c| c.control_path.clone())
                .collect();
            bindings.extend(rows.into_iter().map(|c| c.binding));
            bindings.extend(tx.bindings_of_grant(grant)?);
            let mut slots = Vec::new();
            for b in &bindings {
                slots.extend(tx.slots_for_binding(b)?);
            }
            // ⟨wave 4 round 2, integrator (R2-D → R2-C request)⟩ A released binding has
            // no grant reference any more, but its slot rows still name it: an ended
            // grant's held or clearing slots are also found by their binding's grant.
            for (g, slot) in tx.held_slots_of_ended_grants(&self.sources.environment)? {
                if g == *grant
                    && !slots
                        .iter()
                        .any(|s| s.pair == slot.pair && s.environment == slot.environment)
                {
                    if let Some(b) = &slot.binding {
                        bindings.insert(b.clone());
                    }
                    slots.push(slot);
                }
            }
            Ok((bindings.into_iter().collect(), slots, masters))
        })
    }

    /// ⟨§17.22 item 10 (W4-R08)⟩ The **released** bindings of a live `grant` (D10
    /// item 2: a released binding's slots clear while its grant lives on through
    /// another reference), with the slots each still names, and the control paths of
    /// the grant's owned masters.
    fn released_bindings_and_slots(
        &self,
        grant: &GrantId,
    ) -> heimdall_store::Result<(Vec<BindingId>, Vec<StoreSlot>, BTreeSet<String>)> {
        self.sources.store.transaction(|tx| {
            let mut bindings = Vec::new();
            let mut slots = Vec::new();
            for b in tx.bindings_of_grant(grant)? {
                let released = tx
                    .binding(&b)?
                    .is_some_and(|r| r.state == heimdall_domain::binding::BindingState::Released);
                if released {
                    slots.extend(tx.slots_for_binding(&b)?);
                    bindings.push(b);
                }
            }
            let masters: BTreeSet<String> = tx
                .owned_connections_for_grant(grant)?
                .into_iter()
                .filter(|c| c.kind == ConnectionKind::Master)
                .filter_map(|c| c.control_path)
                .collect();
            Ok((bindings, slots, masters))
        })
    }

    /// The store generation at which `binding`'s `slot` is to be cleared: `held` by
    /// it, or `clearing`; `None` for a slot it no longer has (free, or held by
    /// another binding now).
    fn clearing_generation(binding: &BindingId, slot: &StoreSlot) -> Option<u64> {
        if slot.binding.as_ref() != Some(binding) {
            return None;
        }
        match &slot.state {
            SlotState::Held {
                binding: holder,
                generation,
            } if holder == binding => Some(*generation),
            SlotState::Clearing { generation } => Some(*generation),
            _ => None,
        }
    }

    /// The first half of one slot's clear, by its own store generation (U6-Q4):
    /// `held → clearing` committed, then the key unlisted and the files of that
    /// generation removed. The slot stays `clearing`: it is freed only by
    /// [`Self::finish_slot`], once the rest of its binding's generation-bound work is
    /// done (§17.22 item 9).
    fn begin_slot(
        &self,
        binding: &BindingId,
        slot: &StoreSlot,
        generation: u64,
    ) -> Result<(), AdapterError> {
        let env = slot.environment.clone();
        let at = Timestamp::now();
        let (pair, b) = (slot.pair.clone(), binding.clone());
        self.sources
            .store
            .transaction(|tx| match tx.slot(&env, &pair)? {
                SlotState::Held { .. } => {
                    tx.release_slot(&env, &pair, &b, generation, at).map(|_| ())
                }
                _ => Ok(()),
            })
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))?;
        self.effects.clear_slot(binding, &slot.pair, generation)?;
        Ok(())
    }

    /// The second half: the slot's stable mux path cleared when its pair had no
    /// owned master, then `clearing → free` committed. Called only after the slot's
    /// files and its binding's files are removed (§17.22 item 9): until this commits,
    /// the `clearing` row keeps the obligation discoverable.
    async fn finish_slot(
        &self,
        slot: &StoreSlot,
        generation: u64,
        had_master: bool,
    ) -> Result<(), AdapterError> {
        if !had_master
            && let Some(c) = &self.connections
            && c.clear_slot_path(&slot.pair.destination).await.is_err()
        {
            return Err(AdapterError::Unavailable("slot_path".to_owned()));
        }
        let env = slot.environment.clone();
        let pair = slot.pair.clone();
        let at = Timestamp::now();
        self.sources
            .store
            .transaction(|tx| {
                tx.slot_files_removed(&env, &pair, generation, at)
                    .map(|_| ())
            })
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))
    }

    /// Clean up each binding in `bindings` (and each holder named by `slots`):
    /// every slot it holds or is clearing is cleared by its own generation, its
    /// binding endpoints and files are removed by generation (found on disk by their
    /// marker), and only then are its slots' mux paths cleared and the slots freed
    /// (§17.22 item 9: freeing a slot never ends the obligation while the binding's
    /// files or a mux path remain). `false` when anything failed (retried by the next
    /// pass: the `clearing` row, or the grant's undestroyed instance, keeps it
    /// discoverable).
    async fn clean_bindings(
        &self,
        bindings: &[BindingId],
        slots: &[StoreSlot],
        masters: &BTreeSet<String>,
    ) -> bool {
        let mut all: BTreeSet<BindingId> = bindings.iter().cloned().collect();
        all.extend(slots.iter().filter_map(|s| s.binding.clone()));
        let mut ok = true;
        for b in &all {
            let mine: Vec<(&StoreSlot, u64)> = slots
                .iter()
                .filter_map(|s| Self::clearing_generation(b, s).map(|g| (s, g)))
                .collect();
            let mut done = true;
            for (s, generation) in &mine {
                if self.begin_slot(b, s, *generation).is_err() {
                    done = false;
                }
            }
            match files::binding_directories_of(self.effects.runtime_dir(), b) {
                Ok(dirs) => {
                    for (_, generation) in dirs {
                        if self.effects.clear(b, generation).is_err() {
                            done = false;
                        }
                    }
                }
                Err(_) => done = false,
            }
            if done {
                for (s, generation) in &mine {
                    let had_master = masters.iter().any(|p| {
                        heimdall_localenv::projection::content::checked_mux_path(
                            self.effects.runtime_dir(),
                            &s.pair.destination,
                        )
                        .is_ok_and(|m| m.to_string_lossy() == p.as_str())
                    });
                    if self.finish_slot(s, *generation, had_master).await.is_err() {
                        done = false;
                    }
                }
            }
            ok &= done;
        }
        ok
    }

    async fn clean(&self, grants: &[GrantId]) -> Result<(), AdapterError> {
        let mut failed = false;
        let mut revoked = Vec::new();
        let mut released = Vec::new();
        let mut expired = Vec::new();
        for g in grants {
            let gid = g.clone();
            let state = self
                .sources
                .store
                .transaction(|tx| tx.grant(&gid))
                .map_err(|_| AdapterError::Unavailable("store".to_owned()))?
                .map(|s| s.state);
            match state.and_then(end_of) {
                Some(heimdall_domain::connection::ConnectionEnd::Revocation) => {
                    revoked.push(g.clone());
                }
                Some(heimdall_domain::connection::ConnectionEnd::Release) => {
                    released.push(g.clone());
                }
                Some(_) => expired.push(g.clone()),
                // ⟨§17.22 item 10⟩ A grant that has not ended: only its released
                // bindings (their slots, files and endpoints); nothing else of it.
                None => {
                    if state.is_some() {
                        match self.released_bindings_and_slots(g) {
                            Ok((bindings, slots, masters)) => {
                                failed |= !self.clean_bindings(&bindings, &slots, &masters).await;
                            }
                            Err(_) => failed = true,
                        }
                    }
                    continue;
                }
            }
            let Ok((bindings, slots, masters)) = self.bindings_and_slots(g) else {
                failed = true;
                continue;
            };
            failed |= !self.clean_bindings(&bindings, &slots, &masters).await;
        }
        if let Some(c) = &self.connections {
            for (set, which) in [(&revoked, 0u8), (&released, 1), (&expired, 2)] {
                if set.is_empty() {
                    continue;
                }
                let r = match which {
                    0 => c.revocation_close(set).await,
                    1 => c.release_close(set).await,
                    _ => c.connection_deadline_pass(set).await,
                };
                // W3-R11: a discovery failure is a failure (the intent is kept).
                if r.is_err() || r.is_ok_and(|p| !p.failed.is_empty()) {
                    failed = true;
                }
            }
        }
        if failed {
            Err(AdapterError::Unavailable(
                "managed_cleanup_incomplete".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

impl EndCleanup for StoreCleanup {
    fn after_end<'a>(&'a self, grants: &'a [GrantId]) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(self.clean(grants))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! The store-backed sources over a real scratch store (U6-Q1/Q2/Q4/Q5).
    use super::*;
    use heimdall_adapters::managed::effects::BindingEndpoints;
    use heimdall_adapters::managed::files::SlotRoot;
    use heimdall_contract::ids::{AccountName, DestinationId, ProfileId, WorkId};
    use heimdall_contract::provider::EndpointRef;
    use heimdall_contract::request::{
        DeadlineIntent, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
        NewAuthenticationExpiry, RevocationStatus, WorkloadIsolation,
    };
    use heimdall_credential::table::SignerTable;
    use heimdall_credential::vault::KeyVault;
    use heimdall_domain::binding::{BindingRecord, BindingState};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantOrigin, GrantReference, GrantSnapshot};
    use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::{Capability, Scope};
    use heimdall_domain::time::Deadline;
    use heimdall_store::NoFaults;

    fn t0() -> Timestamp {
        "2026-11-02T09:00:00Z".parse().unwrap()
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn h1() -> AccessPair {
        AccessPair {
            destination: DestinationId::parse("h1").unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        }
    }

    fn owner_only(path: &std::path::Path) {
        std::fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn caller() -> CallerContext {
        CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        }
    }

    fn scope() -> Scope {
        Scope {
            pairs: [h1()].into_iter().collect(),
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
        }
    }

    fn grant(n: u8, state: GrantState) -> GrantSnapshot {
        GrantSnapshot {
            id: GrantId::from_random_bytes([n; 16]),
            environment: env(),
            scope: scope(),
            starts_at: t0(),
            deadline: Deadline {
                intent: DeadlineIntent::Duration("PT2H".into()),
                resolved_at: t0(),
                effective: Timestamp::from_second(t0().as_second() + 7200).unwrap(),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(0),
            state,
            enforcement: EnforcementEvidence {
                report: Enforcement {
                    destination_scope: DestinationScopeEnforcement::Unknown,
                    new_authentication_expiry: NewAuthenticationExpiry::Unknown,
                    workload_isolation: WorkloadIsolation::SharedOsUser,
                    existing_connections: ExistingConnectionsPolicy::Unknown,
                    revocation: RevocationStatus::Unknown,
                    identity_selection: None,
                    new_signing_expiry: None,
                    owned_multiplexing: None,
                    remote_processes: None,
                    unmanaged_connections: None,
                    issuer_isolation: None,
                },
                evidence: Vec::new(),
            },
        }
    }

    fn binding(n: u8, g: &GrantId) -> BindingRecord {
        BindingRecord {
            id: BindingId::from_random_bytes([n; 16]),
            environment: env(),
            grant: g.clone(),
            work_id: WorkId::parse(&format!("w{n}")).unwrap(),
            owner: caller(),
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: 1,
            scope: scope(),
            mechanism: "managed_certificate".into(),
            parent: None,
            created_at: t0(),
            released_at: None,
            state: BindingState::Active,
        }
    }

    struct World {
        _dir: tempfile::TempDir,
        store: Arc<Store>,
        sources: StoreSources,
        effects: ManagedEffectsImpl,
    }

    struct NoEndpoints;
    impl BindingEndpoints for NoEndpoints {
        fn binding_endpoint(&self, _binding: &BindingId) -> Option<EndpointRef> {
            None
        }
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        owner_only(&dir.path().join("state"));
        owner_only(&dir.path().join("run"));
        let store = Arc::new(
            Store::open(
                &dir.path().join("state").join("state.db"),
                Arc::new(NoFaults),
            )
            .unwrap(),
        );
        store
            .transaction(|tx| tx.init_self_environment(&env()))
            .unwrap();
        let sources = StoreSources::new(store.clone(), env());
        let effects = ManagedEffectsImpl::new(
            SignerTable::new(Arc::new(KeyVault::new())),
            Arc::new(NoEndpoints),
            Arc::new(sources.clone()),
            dir.path().join("run"),
            SlotRoot {
                data_dir: dir.path().join("state"),
                environment: env(),
            },
        )
        .with_slot_store(Arc::new(sources.clone()));
        World {
            _dir: dir,
            store,
            sources,
            effects,
        }
    }

    fn insert(w: &World, g: &GrantSnapshot, lock: Option<LockBehavior>) {
        w.store
            .transaction(|tx| {
                tx.insert_grant(g)?;
                tx.set_grant_origin(
                    &g.id,
                    &GrantOrigin {
                        profile: ProfileId::parse("dev").unwrap(),
                        profile_revision: 1,
                        policy_revision: None,
                        caller: caller(),
                        mechanism: "managed_certificate".into(),
                        covered: None,
                        adapter: None,
                        lock_behavior: lock,
                        connection: None,
                    },
                )
            })
            .unwrap();
    }

    /// U6-Q5 amended (§17.20 item 14): the production sources never default a
    /// grant's terms. Absent until the activation's stored-scope read records them;
    /// then the recorded `revoke_on_lock` (never `continue`).
    #[test]
    fn terms_absent_until_recorded_never_default_continue() {
        let w = world();
        let g = grant(1, GrantState::Preparing);
        insert(&w, &g, Some(LockBehavior::RevokeOnLock));
        assert_eq!(w.sources.terms(&g.id), None, "no terms before activation");
        assert_eq!(w.sources.pairs(&g.id), Some(vec![h1()]));
        let t = w.sources.terms(&g.id).expect("recorded at the scope read");
        assert_eq!(t.lock_behavior, LockBehavior::RevokeOnLock);
        // A grant the store does not know: no scope, no terms.
        let unknown = GrantId::from_random_bytes([9; 16]);
        assert_eq!(w.sources.pairs(&unknown), None);
        assert_eq!(w.sources.terms(&unknown), None);
    }

    /// U6-Q1/Q2: the pairs come from the grant's **stored** scope only.
    #[test]
    fn grant_scopes_read_the_stored_scope_only() {
        let w = world();
        let g = grant(2, GrantState::Active);
        insert(&w, &g, None);
        assert_eq!(w.sources.pairs(&g.id), Some(vec![h1()]));
        // A floor joins the recorded behaviour fail closed.
        w.sources.set_lock_floor(LockBehavior::RevokeOnLock);
        w.sources.pairs(&g.id);
        assert_eq!(
            w.sources.terms(&g.id).unwrap().lock_behavior,
            LockBehavior::RevokeOnLock
        );
    }

    /// U6-Q4: an ended grant's slot is cleared by **its own store generation**
    /// (here 3, unrelated to any binding resource generation), and a slot another
    /// binding holds now is never touched.
    #[tokio::test]
    async fn cleanup_clears_each_slot_by_its_own_generation() {
        let w = world();
        let ended = grant(3, GrantState::Revoked);
        let live = grant(4, GrantState::Active);
        insert(&w, &ended, None);
        insert(&w, &live, None);
        let b_ended = binding(3, &ended.id);
        let b_live = binding(4, &live.id);
        let p = h1();
        w.store
            .transaction(|tx| {
                tx.insert_binding(&b_ended)?;
                tx.insert_binding(&b_live)?;
                tx.add_grant_reference(&GrantReference {
                    binding: b_ended.id.clone(),
                    grant: ended.id.clone(),
                    acquired_at: t0(),
                })?;
                // Generations 1 and 2 come and go; the ended binding holds 3.
                for g in 1..=2u64 {
                    tx.claim_slot(&env(), &p, &b_ended.id, t0())?.unwrap();
                    tx.release_slot(&env(), &p, &b_ended.id, g, t0())?.unwrap();
                    tx.slot_files_removed(&env(), &p, g, t0())?.unwrap();
                }
                tx.claim_slot(&env(), &p, &b_ended.id, t0())?.unwrap();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            w.sources.slot(&env(), &p).unwrap(),
            SlotState::Held {
                binding: b_ended.id.clone(),
                generation: 3
            }
        );
        let cleanup = StoreCleanup::new(w.sources.clone(), w.effects.clone(), None);
        cleanup
            .after_end(std::slice::from_ref(&ended.id))
            .await
            .unwrap();
        assert_eq!(
            w.sources.slot(&env(), &p).unwrap(),
            SlotState::Free { generation: 3 },
            "cleared at its own generation"
        );
        // The next holder gets 4; a late cleanup of the ended grant leaves it alone.
        w.store
            .transaction(|tx| tx.claim_slot(&env(), &p, &b_live.id, t0()).map(|_| ()))
            .unwrap();
        cleanup
            .after_end(std::slice::from_ref(&ended.id))
            .await
            .unwrap();
        assert_eq!(
            w.sources.slot(&env(), &p).unwrap(),
            SlotState::Held {
                binding: b_live.id.clone(),
                generation: 4
            }
        );
        // A grant that has not ended is never cleaned up.
        cleanup
            .after_end(std::slice::from_ref(&live.id))
            .await
            .unwrap();
        assert!(matches!(
            w.sources.slot(&env(), &p).unwrap(),
            SlotState::Held { generation: 4, .. }
        ));
    }
}

/// ⟨M03 wave 4, round 2⟩ ADR-0008 §17.21 item 1, live: the production effect driver
/// through the real `Operations`, `ManagedCertificateAdapter`, [`StoreSources`],
/// [`OpsInstallView`], [`StoreCleanup`], `ManagedEffectsImpl`, signer table and
/// **`EndpointRegistry`** (a real binding endpoint on a Unix socket in a scratch
/// runtime directory). Certificates are signed in process by a per-run K_ca (the
/// fixture issuer: `IssuerPort` over `heimdall_credential::cert::build_and_sign`); every
/// key is generated per run; nothing of the owner's is touched; the only listener is
/// the binding endpoint, owner-only, in the scratch directory.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod live_tests {
    use super::*;
    use heimdall_adapters::managed::ManagedCertificateAdapter;
    use heimdall_adapters::managed::effects::BindingEndpoints;
    use heimdall_adapters::managed::files::SlotRoot;
    use heimdall_app::ensure::{EnsureStage, NoStageHook, StageHook};
    use heimdall_app::managed::ManagedWiring;
    use heimdall_app::operations::Limits;
    use heimdall_app::ports::{CredentialAdapter, IssuanceRef, IssuerError};
    use heimdall_app::{Caller, OperationsConfig};
    use heimdall_contract::Code;
    use heimdall_contract::doctor::AliasObservation;
    use heimdall_contract::ids::{
        AccountName, DestinationId, DeviceId, EnrollmentId, IdentityId, OperationId, PolicyId,
        ProfileId, RequestId, WorkId,
    };
    use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
    use heimdall_contract::managed::{
        ClockMeasurement, ConnectionPolicy, IssuerIsolation, PreferredMechanism,
    };
    use heimdall_contract::provider::{
        EndpointRef, IdentitiesOnly, IdentitySelection, IdentitySelectionReport,
    };
    use heimdall_contract::request::{
        EnsureData, EnsureRequest, InteractionMode, RequiredCapabilities, RevokeRequest, WaitMode,
    };
    use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
    use heimdall_credential::endpoints::{EndpointLayout, EndpointRegistry};
    use heimdall_credential::signer::SignerLimits;
    use heimdall_credential::table::SignerTable;
    use heimdall_credential::vault::KeyVault;
    use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
    use heimdall_domain::enrollment::TargetEvaluation;
    use heimdall_domain::enrollment::{
        ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentState,
        ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus, RegistryCanonical,
        RegistryRef, RegistryResolvedBy, marker_for,
    };
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::issuance::CredentialState;
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{Capability, Scope};
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_ipc::agent_client::{AgentLocator, ClientBounds, list_identities};
    use heimdall_store::{IssuerRecord, NoFaults};
    use heimdall_testkit::{ScriptedTimeSync, VirtualClock};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    const HOUR: Duration = Duration::from_secs(3600);

    /// ⟨R3-C1⟩ ADR-0008 §17.22 items 4, 9, 10 (`managed_store/live_tests/cleanup.rs`).
    mod cleanup;
    /// ⟨R3-C2⟩ ADR-0008 §17.22 items 5, 6, 8 (`managed_store/live_tests/pipeline.rs`).
    mod pipeline;
    /// ⟨X-M⟩ ADR-0008 §17.23 items 1 and 5 (`managed_store/live_tests/selection.rs`).
    mod selection;

    fn t0() -> Timestamp {
        "2026-11-02T09:00:00Z".parse().unwrap()
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    fn pair(d: &str, a: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse(a).unwrap(),
        }
    }

    fn pairs() -> Vec<AccessPair> {
        vec![pair("h1", "deploy"), pair("h2", "ops")]
    }

    fn caller() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn owner_only(path: &std::path::Path) {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn enrollment(seed: u8, ca: &CaFingerprint, p: &AccessPair) -> EnrollmentRecord {
        let id = EnrollmentId::from_random_bytes([seed; 16]);
        EnrollmentRecord {
            marker: marker_for(&id),
            id,
            destination: p.destination.clone(),
            account: p.account.clone(),
            ca_fingerprint: ca.clone(),
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "~/.ssh/authorized_keys".into(),
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            registry_canonical: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            line_sha256: "ab".repeat(32),
            target: ApprovedTarget {
                hostname: format!("{}.example.invalid", p.destination.as_str()),
                port: 22,
                user: p.account.clone(),
                proxy: NoProxy::None,
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".into(),
                    key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                    fingerprint: "SHA256:hostfixture".into(),
                },
            },
            existing_access: ExistingAccessRecord {
                identity: IdentityId::from_random_bytes([1; 16]),
                endpoint: None,
                public_key_file: None,
            },
            hold: None,
            removal_origin: None,
            late_write: None,
            state: EnrollmentState::Verified,
            verified_at: Some(t0()),
            evidence: Some(EnrollmentEvidence {
                client: "OpenSSH_10.5p1".into(),
                server: "OpenSSH_10.0p2".into(),
                operation: OperationId::from_random_bytes([seed; 16]),
                verified_at: t0(),
                fresh_until: Timestamp::from_second(t0().as_second() + 90 * 86_400).unwrap(),
                clock: Some(ClockMeasurement {
                    behind_upper_ms: 1400,
                    rtt_ms: 38,
                    measured_at: t0(),
                }),
            }),
            created_at: t0(),
            updated_at: t0(),
        }
    }

    fn existing_identity() -> heimdall_domain::catalog::IdentityRecord {
        heimdall_domain::catalog::IdentityRecord {
            id: IdentityId::from_random_bytes([1; 16]),
            revision: 1,
            source: heimdall_domain::catalog::IdentitySource::PublicKeyFile {
                path: "/nonexistent/fixture.pub".into(),
            },
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".into(),
            fingerprint: "SHA256:fixture".into(),
            interaction: heimdall_domain::catalog::InteractionProfile {
                interaction: heimdall_contract::provider::InteractionKind::Unknown,
                basis: heimdall_contract::provider::EvidenceBasis::Inferred,
            },
            label: None,
            adopted_at: t0(),
            updated_at: t0(),
        }
    }

    /// The fixture world over `pairs` (the profile `dev`, its standing policy, the
    /// adopted existing identity, the issuer row, and per pair a managed destination,
    /// a verified enrollment and the applied `managed_certificate` preference).
    fn seed_pairs(store: &Store, ca: &SecretCaKey, seeded: &[AccessPair]) {
        let fp = ca.fingerprint().unwrap();
        let public = ca.public_openssh().unwrap();
        store
            .transaction(|tx| {
                tx.init_self_environment(&env())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env(),
                    device: DeviceId::from_random_bytes([8; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: true,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                let scope = Scope {
                    pairs: seeded.iter().cloned().collect(),
                    capabilities: [Capability::SshAuthentication].into_iter().collect(),
                };
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: scope.clone(),
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: PolicyId::parse("pol").unwrap(),
                        revision: PolicyRevision(1),
                        profile: ProfileId::parse("dev").unwrap(),
                        workspace: None,
                        scope,
                        environments: [env()].into_iter().collect(),
                        max_window: 2 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        lock_behavior: LockBehavior::Continue,
                        connection: ConnectionPolicy::default(),
                    },
                    false,
                )?;
                tx.upsert_identity(&existing_identity())?;
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: t0(),
                    restored_without_log: false,
                    created_at: t0(),
                    retired_at: None,
                })?;
                for (i, p) in seeded.iter().enumerate() {
                    // A managed destination (P renders the alias) whose identity is the
                    // pair's existing access (an adopted public-key file, never read).
                    tx.upsert_destination(&DestinationRecord {
                        id: p.destination.clone(),
                        alias: p.destination.as_str().into(),
                        revision: 1,
                        definition: DestinationDefinition::Managed {
                            hostname: format!("{}.example.invalid", p.destination.as_str()),
                            port: None,
                            account: p.account.clone(),
                            identity: existing_identity().id,
                        },
                        label: None,
                        updated_at: t0(),
                    })?;
                    tx.seed_enrollment(&enrollment(u8::try_from(i + 1).unwrap(), &fp, p))?;
                    tx.set_pair_preference(
                        &PairPreference {
                            destination: p.destination.clone(),
                            account: p.account.clone(),
                            mechanism: PreferredMechanism::ManagedCertificate,
                            projection: ProjectionStatus::Applied { generation: 1 },
                            issuing_cas: [fp.clone()].into_iter().collect(),
                        },
                        t0(),
                    )?;
                }
                Ok(())
            })
            .unwrap();
    }

    /// The fixture issuer: K_ca signs exactly the reserved bounds, for the grant's
    /// live K_env (read from the signer table), in process.
    struct FixtureIssuer {
        store: Arc<Store>,
        table: SignerTable,
        ca: Arc<SecretCaKey>,
        /// ⟨X-M⟩ Further CAs ([`Live::add_ca`]): an entry reserved under one of them is
        /// signed by it.
        others: Arc<Mutex<Vec<Arc<SecretCaKey>>>>,
    }

    fn ready() -> IssuerStatusSnapshot {
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: IssuerState::Ready,
                reason: None,
                cas: Vec::new(),
                orphan_store_items: Vec::new(),
                issuer_isolation: IssuerIsolation::SameUserProcess,
                bundle_stale: false,
            },
        }
    }

    impl IssuerPort for FixtureIssuer {
        fn status(&self) -> IssuerStatusSnapshot {
            ready()
        }

        fn sign<'a, 'b, 'c>(
            &'a self,
            entry: IssuanceRef,
            _subject: &'b str,
        ) -> BoxFuture<'c, Result<String, IssuerError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move {
                let refused = || IssuerError::Protocol("fixture".into());
                let e = self
                    .store
                    .transaction(|tx| tx.issuance_entry(&entry.id))
                    .map_err(|_| refused())?
                    .ok_or_else(refused)?;
                let key = self
                    .table
                    .public_key(&e.grant)
                    .ok_or_else(refused)?
                    .public_key()
                    .map_err(|_| refused())?;
                let other = self
                    .others
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|c| c.fingerprint().ok().as_ref() == e.bounds.ca_fingerprint.as_ref())
                    .cloned();
                let ca = other.unwrap_or_else(|| self.ca.clone());
                build_and_sign(&CertificateProfile::from_bounds(&e.bounds), &key, &ca)
                    .map_err(|_| refused())?
                    .to_openssh()
                    .map_err(|_| refused())
            })
        }

        fn unload<'a, 'b, 'c>(
            &'a self,
            _ca: &'b CaFingerprint,
        ) -> BoxFuture<'c, Result<(), IssuerError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            Box::pin(async move { Ok(()) })
        }
    }

    /// The registry, set after `Operations::start` (its authority is the
    /// `Operations`), as the runtime's late registry does.
    #[derive(Default)]
    struct Late(RwLock<Option<EndpointRegistry>>);

    impl Late {
        fn get(&self) -> Option<EndpointRegistry> {
            self.0.read().unwrap().clone()
        }
    }

    impl BindingEndpoints for Late {
        fn binding_endpoint(&self, binding: &BindingId) -> Option<EndpointRef> {
            self.get()
                .and_then(|r| BindingEndpoints::binding_endpoint(&r, binding))
        }
        fn create_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<EndpointRef, AdapterError> {
            self.get()
                .ok_or_else(|| AdapterError::Unavailable("no registry".into()))?
                .create_binding_endpoint(binding, generation)
        }
        fn remove_binding_endpoint(
            &self,
            binding: &BindingId,
            generation: u64,
        ) -> Result<bool, AdapterError> {
            match self.get() {
                Some(r) => r.remove_binding_endpoint(binding, generation),
                None => Ok(false),
            }
        }
    }

    /// Fails the stage before `Commit` while armed: a crash point **after** the ensure
    /// confirmation (the `Confirmed` receipt) and before the commit. ⟨R3-C2⟩ The
    /// interval between the materialization and the confirmation is
    /// `pipeline::crash_between_materialize_and_confirmation_leaves_no_endpoint_file_or_key`'s.
    #[derive(Default)]
    struct CrashBeforeCommit(AtomicBool);

    impl StageHook for CrashBeforeCommit {
        fn before(&self, stage: EnsureStage) -> Result<(), Code> {
            if stage == EnsureStage::Commit && self.0.load(Ordering::SeqCst) {
                Err(Code::ServiceUnavailable)
            } else {
                Ok(())
            }
        }
        fn after(&self, _stage: EnsureStage) -> Result<(), Code> {
            Ok(())
        }
    }

    /// ⟨R3-C2⟩ A one-shot hold of `prepare_from` (after the effect driver ran, before
    /// the confirmation): when armed, the next call announces `reached` and waits for
    /// `release` (never, for a crash: the test then drops the process's runtime).
    #[derive(Default)]
    struct Hold {
        armed: AtomicBool,
        reached: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    /// The real managed adapter, whose `prepare_from` refuses (after the effect
    /// driver ran) while `fail` is set: a failure between materialization and commit.
    /// ⟨R3-C2⟩ It also waits at an armed [`Hold`].
    struct FailPrepare {
        inner: ManagedCertificateAdapter,
        fail: Arc<AtomicBool>,
        hold: Arc<Hold>,
    }

    impl CredentialAdapter for FailPrepare {
        fn descriptor(&self) -> &heimdall_app::ports::AdapterDescriptor {
            self.inner.descriptor()
        }
        fn prepare<'a, 'b, 'c>(
            &'a self,
            req: heimdall_app::ports::PrepareRequest<'b>,
        ) -> BoxFuture<'c, Result<heimdall_app::ports::PrepareOutcome, AdapterError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            self.inner.prepare(req)
        }
        fn read_sources(
            &self,
            pairs: &[heimdall_app::ports::PreparePair],
        ) -> heimdall_app::ports::IntegrationSnapshot {
            self.inner.read_sources(pairs)
        }
        fn prepare_from<'a, 'b, 'c, 'd>(
            &'a self,
            req: heimdall_app::ports::PrepareRequest<'b>,
            sources: &'c heimdall_app::ports::IntegrationSnapshot,
        ) -> BoxFuture<'d, Result<heimdall_app::ports::PrepareOutcome, AdapterError>>
        where
            'a: 'd,
            'b: 'd,
            'c: 'd,
            Self: 'd,
        {
            if self.fail.load(Ordering::SeqCst) {
                return Box::pin(async { Err(AdapterError::CapabilityUnavailable) });
            }
            if self.hold.armed.swap(false, Ordering::SeqCst) {
                let hold = Arc::clone(&self.hold);
                return Box::pin(async move {
                    let released = hold.release.notified();
                    hold.reached.notify_one();
                    released.await;
                    self.inner.prepare_from(req, sources).await
                });
            }
            self.inner.prepare_from(req, sources)
        }
        fn renew<'a, 'b, 'c>(
            &'a self,
            req: heimdall_app::ports::PrepareRequest<'b>,
        ) -> BoxFuture<'c, Result<heimdall_app::ports::PrepareOutcome, AdapterError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            self.inner.renew(req)
        }
        fn reconcile<'a, 'b, 'c, 'd>(
            &'a self,
            grant: &'b GrantId,
            token: &'c str,
        ) -> BoxFuture<'d, Result<heimdall_app::ports::ReconcileOutcome, AdapterError>>
        where
            'a: 'd,
            'b: 'd,
            'c: 'd,
            Self: 'd,
        {
            self.inner.reconcile(grant, token)
        }
        fn revoke<'a, 'b, 'c>(
            &'a self,
            grant: &'b GrantId,
            now: Timestamp,
        ) -> BoxFuture<'c, Result<heimdall_app::ports::RevokeOutcome, AdapterError>>
        where
            'a: 'c,
            'b: 'c,
            Self: 'c,
        {
            self.inner.revoke(grant, now)
        }
    }

    /// One runtime process: its own vault, table, registry, effects, adapter and
    /// `Operations` over the shared store.
    struct Process {
        ops: Operations,
        table: SignerTable,
        registry: EndpointRegistry,
        effects: ManagedEffectsImpl,
        shutdown: CancellationToken,
    }

    struct Live {
        dir: tempfile::TempDir,
        store: Arc<Store>,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
        ca: Arc<SecretCaKey>,
        /// ⟨X-M, §17.23 items 1 and 5⟩ What the managed read sources of every process
        /// see beside the store; empty by default (no observation, no evaluation, no
        /// client: every pair `undetermined`, no evidence holds, as before).
        feed: Arc<LiveFeed>,
        /// ⟨X-M⟩ The CAs added by [`Live::add_ca`].
        others: Arc<Mutex<Vec<Arc<SecretCaKey>>>>,
    }

    /// ⟨X-M, ADR-0008 §17.23 items 1 and 5⟩ The live harness's equivalent of the
    /// runtime's managed read sources (`service.rs` `mod sources`): the D10 item 6
    /// observation of each managed alias (the runtime's `Observing`: the projection
    /// writer's `observe`), and the evidence comparison's inputs (the runtime's
    /// `LateEvidenceFeed`: the target evaluator and the verifying client), set by a
    /// test. Read through [`Observed`] and `prepare::WithEvidenceFeed`, exactly where
    /// production reads them.
    #[derive(Default)]
    struct LiveFeed {
        observations: Mutex<std::collections::HashMap<String, AliasObservation>>,
        targets: Mutex<std::collections::HashMap<String, TargetEvaluation>>,
        client: Mutex<Option<String>>,
    }

    impl LiveFeed {
        /// `alias` classified `selection` (D10 item 6), as the projection writer's
        /// static observation reports it.
        fn observe(&self, alias: &str, selection: IdentitySelection) {
            self.observations.lock().unwrap().insert(
                alias.to_owned(),
                AliasObservation {
                    alias: alias.to_owned(),
                    definition: heimdall_contract::doctor::AliasDefinition::Managed,
                    behavior: Vec::new(),
                    identity_selection: Some(IdentitySelectionReport {
                        selection,
                        entries: Vec::new(),
                        identities_only: if selection == IdentitySelection::Exclusive {
                            IdentitiesOnly::DeterminedYes
                        } else {
                            IdentitiesOnly::Undetermined
                        },
                    }),
                },
            );
        }

        /// The approved target of [`enrollment`] for `p` (what its alias evaluates to
        /// while nothing changed).
        fn approved(p: &AccessPair) -> TargetEvaluation {
            TargetEvaluation {
                hostname: format!("{}.example.invalid", p.destination.as_str()),
                port: 22,
                user: p.account.as_str().to_owned(),
                proxy: heimdall_domain::enrollment::ProxyRoute::None,
                determinism: heimdall_domain::enrollment::Determinism::Determined,
                host_keys: vec![heimdall_domain::enrollment::RawHostKey {
                    key_type: "ssh-ed25519".into(),
                    key_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                    fingerprint: "SHA256:hostfixture".into(),
                    origin_display: "fixture".into(),
                    revoked: false,
                }],
            }
        }

        /// Every pair of `ps` evaluates to its approved target, and the verifying
        /// client is the evidence's: the seeded evidence holds.
        fn evidence_holds(&self, ps: &[AccessPair]) {
            let mut t = self.targets.lock().unwrap();
            for p in ps {
                t.insert(p.destination.as_str().to_owned(), Self::approved(p));
            }
            *self.client.lock().unwrap() = Some(EVIDENCE_CLIENT.to_owned());
        }
    }

    /// The verifying client of the seeded evidence ([`enrollment`]).
    const EVIDENCE_CLIENT: &str = "OpenSSH_10.5p1, LibreSSL 3.3.6";

    impl heimdall_adapters::managed::prepare::EvidenceFeed for LiveFeed {
        fn evaluate_target(&self, alias: &str) -> Option<TargetEvaluation> {
            self.targets.lock().unwrap().get(alias).cloned()
        }
        fn client_version(&self) -> Option<String> {
            self.client.lock().unwrap().clone()
        }
    }

    /// [`StoreSources`] with [`LiveFeed`]'s observations (the runtime's `Observing`);
    /// every other read is the store's.
    struct Observed {
        inner: StoreSources,
        feed: Arc<LiveFeed>,
    }

    impl ManagedSourceRead for Observed {
        fn enrollments(&self, pairs: &[AccessPair]) -> Vec<EnrollmentRecord> {
            self.inner.enrollments(pairs)
        }
        fn issuing_cas(
            &self,
            pairs: &[AccessPair],
        ) -> std::collections::BTreeMap<AccessPair, std::collections::BTreeSet<CaFingerprint>>
        {
            self.inner.issuing_cas(pairs)
        }
        fn slots(&self, pairs: &[AccessPair]) -> Vec<heimdall_app::ports::ManagedSlot> {
            self.inner.slots(pairs)
        }
        fn claims(&self) -> Vec<heimdall_domain::claims::Claim> {
            self.inner.claims()
        }
        fn issuer(&self) -> Option<IssuerStatusSnapshot> {
            self.inner.issuer()
        }
        fn prepared(&self, pairs: &[AccessPair]) -> Option<heimdall_app::ports::ManagedPrepared> {
            self.inner.prepared(pairs)
        }
        fn terms(
            &self,
            grant: &GrantId,
        ) -> Option<heimdall_adapters::managed::prepare::GrantTerms> {
            self.inner.terms(grant)
        }
        fn cascade(&self, grant: &GrantId) -> Vec<GrantId> {
            self.inner.cascade(grant)
        }
        fn issuance_entries(&self, grants: &[GrantId]) -> Vec<IssuanceEntry> {
            self.inner.issuance_entries(grants)
        }
        fn key_only_restore(&self) -> bool {
            self.inner.key_only_restore()
        }
        fn recorded_outcome(
            &self,
            grant: &GrantId,
            effect_token: &str,
        ) -> Option<heimdall_app::ports::PrepareOutcome> {
            self.inner.recorded_outcome(grant, effect_token)
        }
        fn owned_connections(
            &self,
            grants: &[GrantId],
        ) -> Vec<heimdall_domain::managed::OwnedConnection> {
            self.inner.owned_connections(grants)
        }
        fn observations(&self, aliases: &[String]) -> Vec<AliasObservation> {
            let o = self.feed.observations.lock().unwrap();
            aliases.iter().filter_map(|a| o.get(a).cloned()).collect()
        }
    }

    /// ⟨R3-C2⟩ Wraps the effects a process wires for its driver.
    type WrapEffects = Arc<dyn Fn(ManagedEffectsImpl) -> Arc<dyn ManagedEffects> + Send + Sync>;

    /// ⟨R3-C2⟩ The test seams of one process ([`Live::process_opts`]).
    #[derive(Default)]
    struct Opts {
        /// `prepare_from` refuses while set.
        fail: Arc<AtomicBool>,
        /// `prepare_from` waits at it once armed.
        hold: Arc<Hold>,
        /// Wraps the effects the driver uses (the wiring's), not the adapter's.
        wrap: Option<WrapEffects>,
    }

    impl Live {
        fn new() -> Self {
            Self::seeded(&pairs(), t0())
        }

        /// ⟨R3-C2⟩ A world over `pairs` (each seeded as in [`seed`]) whose clock starts
        /// at `start`.
        fn seeded(pairs: &[AccessPair], start: Timestamp) -> Self {
            let dir = tempfile::tempdir().unwrap();
            owner_only(&dir.path().join("state"));
            owner_only(&dir.path().join("run"));
            let store = Arc::new(
                Store::open(
                    &dir.path().join("state").join("state.db"),
                    Arc::new(NoFaults),
                )
                .unwrap(),
            );
            let ca = Arc::new(SecretCaKey::generate().unwrap());
            seed_pairs(&store, &ca, pairs);
            Self {
                dir,
                store,
                clock: VirtualClock::at(start),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                ca,
                feed: Arc::default(),
                others: Arc::default(),
            }
        }

        /// ⟨X-M⟩ A further active CA, created after the seeded one (its issuer row; the
        /// fixture issuer signs with it for an entry reserved under it). Returns its
        /// fingerprint.
        fn add_ca(&self) -> CaFingerprint {
            let ca = Arc::new(SecretCaKey::generate().unwrap());
            let fp = ca.fingerprint().unwrap();
            let public = ca.public_openssh().unwrap();
            self.store
                .transaction(|tx| {
                    tx.insert_issuer(&IssuerRecord {
                        ca_fingerprint: fp.clone(),
                        public_key: public.clone(),
                        state: CaState::Active,
                        store_kind: StoreKind::LinuxSecretService,
                        backup_sha256: "cd".repeat(32),
                        backup_created_at: t0(),
                        restored_without_log: false,
                        // Newer than every CA before it: the newest verified CA issues.
                        created_at: Timestamp::from_second(t0().as_second() + 60).unwrap(),
                        retired_at: None,
                    })
                })
                .unwrap();
            self.others.lock().unwrap().push(ca);
            fp
        }

        fn run_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("run")
        }

        async fn process(&self, hook: Arc<dyn StageHook>) -> Process {
            self.process_with(hook, Arc::default()).await
        }

        async fn process_with(&self, hook: Arc<dyn StageHook>, fail: Arc<AtomicBool>) -> Process {
            self.process_opts(
                hook,
                Opts {
                    fail,
                    ..Opts::default()
                },
            )
            .await
        }

        async fn process_opts(&self, hook: Arc<dyn StageHook>, opts: Opts) -> Process {
            let Opts { fail, hold, wrap } = opts;
            let sources = StoreSources::new(self.store.clone(), env());
            let table = SignerTable::new(Arc::new(KeyVault::new()));
            let late = Arc::new(Late::default());
            let layout = EndpointLayout::unix(&self.run_dir()).unwrap();
            let effects = ManagedEffectsImpl::new(
                table.clone(),
                late.clone(),
                Arc::new(sources.clone()),
                self.run_dir(),
                SlotRoot {
                    data_dir: self.dir.path().join("state"),
                    environment: env(),
                },
            )
            .with_slot_store(Arc::new(sources.clone()));
            // ⟨X-M⟩ The adapter reads the store through the harness's equivalent of the
            // runtime's `Observing` and evidence feed (empty unless a test sets them).
            let read: Arc<dyn ManagedSourceRead> =
                Arc::new(heimdall_adapters::managed::prepare::WithEvidenceFeed {
                    inner: Arc::new(Observed {
                        inner: sources.clone(),
                        feed: self.feed.clone(),
                    }),
                    feed: self.feed.clone(),
                });
            let adapter = ManagedCertificateAdapter::new(
                "managed-1",
                read,
                Some(effects.clone()),
                Some(layout.clone()),
            )
            .with_cleanup(Arc::new(StoreCleanup::new(
                sources.clone(),
                effects.clone(),
                None,
            )));
            let ops = Operations::start(OperationsConfig {
                store: self.store.clone(),
                clock: self.clock.clone(),
                time_sync: self.sync.clone(),
                time_policy: TimePolicy::default(),
                environment: env(),
                adapters: vec![Arc::new(FailPrepare {
                    inner: adapter,
                    fail,
                    hold,
                }) as Arc<dyn CredentialAdapter>],
                stage_hook: hook,
                limits: Limits::default(),
                default_window: 12 * HOUR,
                projection: None,
            })
            .await
            .unwrap();
            let shutdown = CancellationToken::new();
            let registry = EndpointRegistry::new(
                layout,
                heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
                table.clone(),
                Arc::new(ops.clone()),
                SignerLimits::default(),
                shutdown.clone(),
            );
            *late.0.write().unwrap() = Some(registry.clone());
            table.set_install_view(Arc::new(OpsInstallView::new(ops.clone())));
            let issuer: Arc<dyn IssuerPort> = Arc::new(FixtureIssuer {
                store: self.store.clone(),
                table: table.clone(),
                ca: self.ca.clone(),
                others: self.others.clone(),
            });
            sources.set_issuer(issuer.clone());
            let wired: Arc<dyn ManagedEffects> = match &wrap {
                Some(w) => w(effects.clone()),
                None => Arc::new(effects.clone()),
            };
            ops.set_managed_wiring(ManagedWiring {
                effects: Some(wired),
                issuer: Some(issuer),
                ..ManagedWiring::default()
            });
            Process {
                ops,
                table,
                registry,
                effects,
                shutdown,
            }
        }

        async fn ensure(
            &self,
            p: &Process,
            tag: &str,
            required: RequiredCapabilities,
        ) -> Result<EnsureData, heimdall_app::OpError> {
            p.ops
                .ensure(
                    &caller(),
                    EnsureRequest {
                        profile: ProfileId::parse("dev").unwrap(),
                        profile_revision: None,
                        scope: pairs().into_iter().collect(),
                        environment: None,
                        work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                        until: None,
                        required_capabilities: required,
                        request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                        // An interactive request: a non-interactive one is refused at the
                        // commit by M02's catalog-identity eligibility (R2C-Q1).
                        interaction: InteractionMode::Interactive,
                        wait: WaitMode::Sync { timeout_ms: 30_000 },
                        connection: None,
                    },
                )
                .await
                .map(|c| c.data)
        }

        /// The binding directories on disk whose marker names `binding`.
        fn binding_dirs(&self, binding: &BindingId) -> Vec<(std::path::PathBuf, u64)> {
            files::binding_directories_of(&self.run_dir(), binding).unwrap()
        }

        /// The grant of `op` (its recovery intent).
        fn grant_of(&self, op: &OperationId) -> GrantId {
            self.store
                .transaction(|tx| tx.recovery_intent(op))
                .unwrap()
                .and_then(|i| i.resolved)
                .and_then(|r| r.grant)
                .expect("a grant")
        }

        /// `grant`'s credential instances still live (`pending` or `installed`).
        fn live_instances(&self, grant: &GrantId) -> usize {
            self.store
                .transaction(|tx| tx.credential_instances_for_grant(grant))
                .unwrap()
                .iter()
                .filter(|i| {
                    matches!(
                        i.state,
                        CredentialState::Pending | CredentialState::Installed
                    )
                })
                .count()
        }

        /// The binding ID minted at resolve for `op` (its recovery intent).
        fn minted_binding(&self, op: &OperationId) -> BindingId {
            self.store
                .transaction(|tx| tx.recovery_intent(op))
                .unwrap()
                .and_then(|i| i.resolved)
                .and_then(|r| r.binding_id)
                .expect("a binding ID minted at resolve")
        }
    }

    async fn listed(endpoint: &str) -> Result<usize, heimdall_ipc::agent_client::AgentClientError> {
        list_identities(
            &AgentLocator::UnixSocket(std::path::PathBuf::from(endpoint)),
            &ClientBounds::default(),
        )
        .await
        .map(|l| l.identities.len())
    }

    /// The endpoint stops answering (its accept loop ends asynchronously).
    async fn gone(endpoint: &str) -> bool {
        for _ in 0..200 {
            if listed(endpoint).await.is_err() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// §17.21 item 1: a managed `ensure` materializes the binding during preparation
    /// under the ID minted at resolve: the binding endpoint (generation 1) is named in
    /// `consumer.signing_endpoint` and on every pair, and it lists the grant's two
    /// certificates; the binding files are on disk at generation 1. A replay of the same
    /// request returns the same binding and endpoint. The revoke removes the endpoint,
    /// the files and the key.
    #[tokio::test]
    async fn managed_ensure_names_binding_endpoint_listing_grant_certificates() {
        let w = Live::new();
        let p = w.process(Arc::new(NoStageHook)).await;
        let data = w
            .ensure(&p, "named", RequiredCapabilities::default())
            .await
            .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
        let (endpoint, generation) = p
            .registry
            .binding_endpoint(&data.binding_id)
            .expect("the binding endpoint was created");
        assert_eq!(generation, heimdall_domain::resource::ResourceGeneration(1));
        assert_eq!(
            data.consumer.signing_endpoint.as_deref(),
            Some(endpoint.locator.as_str()),
            "the result names the binding endpoint"
        );
        assert!(
            data.consumer
                .pairs
                .iter()
                .all(|pi| pi.endpoint.as_ref() == Some(&endpoint))
        );
        assert_eq!(
            listed(&endpoint.locator).await.unwrap(),
            2,
            "the endpoint lists the grant's two certificates"
        );
        let dirs = w.binding_dirs(&data.binding_id);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].1, 1, "generation 1");
        assert!(dirs[0].0.join(files::BINDING_KEY_FILE).exists());
        for pr in pairs() {
            let name = files::binding_cert_name(&pr.destination).unwrap();
            assert!(dirs[0].0.join(name).exists());
        }
        // A replay of the same request: the same binding and endpoint.
        let again = w
            .ensure(&p, "named", RequiredCapabilities::default())
            .await
            .unwrap();
        assert_eq!(again.binding_id, data.binding_id);
        assert_eq!(
            again.consumer.signing_endpoint,
            data.consumer.signing_endpoint
        );
        assert_eq!(
            p.registry.binding_endpoint(&data.binding_id),
            Some((endpoint.clone(), generation))
        );
        // The revoke: endpoint, files and key gone.
        p.ops
            .revoke(
                &caller(),
                RevokeRequest {
                    grant_id: data.grant_id.clone(),
                    request_id: RequestId::parse("rv-named").unwrap(),
                },
            )
            .await
            .unwrap();
        assert!(p.registry.binding_endpoint(&data.binding_id).is_none());
        assert!(gone(&endpoint.locator).await, "the endpoint is gone");
        assert!(
            w.binding_dirs(&data.binding_id).is_empty(),
            "no binding file"
        );
        assert_eq!(p.table.vault().len(), 0, "no key");
        assert_eq!(w.live_instances(&data.grant_id), 0);
    }

    /// §17.21 item 1: a failure after the driver materialized (`prepare_from` refuses)
    /// is cleaned up before the call returns: no endpoint, no binding file, no key, no
    /// live instance, no binding committed, no cleanup intent left.
    #[tokio::test]
    async fn managed_prepare_failure_after_materialize_leaves_no_endpoint_file_or_key() {
        let w = Live::new();
        let p = w
            .process_with(Arc::new(NoStageHook), Arc::new(AtomicBool::new(true)))
            .await;
        let e = w
            .ensure(&p, "refused", RequiredCapabilities::default())
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::CapabilityUnavailable, "{}", e.message);
        let op = e.operation_id.clone().expect("the operation");
        let binding = w.minted_binding(&op);
        let grant = w.grant_of(&op);
        let stages: Vec<String> = w
            .store
            .transaction(|tx| tx.stage_receipts(&op))
            .unwrap()
            .into_iter()
            .map(|r| r.stage)
            .collect();
        assert!(
            stages.iter().any(|s| s == "managed.materialize"),
            "the driver materialized before the refusal: {stages:?}"
        );
        assert!(
            p.registry.binding_endpoint(&binding).is_none(),
            "no endpoint"
        );
        assert!(w.binding_dirs(&binding).is_empty(), "no binding file");
        assert_eq!(p.table.vault().len(), 0, "no key");
        assert!(p.table.public_key(&grant).is_none());
        assert_eq!(w.live_instances(&grant), 0);
        assert!(!p.ops.signing_gates().contains(&grant), "the gate released");
        let (committed, intents) = w
            .store
            .transaction(|tx| Ok((tx.binding(&binding)?, tx.cleanup_intents()?)))
            .unwrap();
        assert!(committed.is_none());
        assert!(intents.is_empty());
    }

    /// §17.21 item 1: a crash **after the ensure confirmation** and before the commit
    /// (the stage before `Commit` fails; the process then dies: its endpoint stops
    /// without its own cleanup) and a restart over the same store: recovery fails the
    /// operation with a cleanup intent, and once the effects are wired the cleanup pass
    /// leaves no endpoint, no binding file and no key; nothing is committed. ⟨R3-C2;
    /// W4-R05⟩ Renamed from `crash_between_materialize_and_commit_…`, which named an
    /// interval it did not cover; the materialize-to-confirmation crash is
    /// `pipeline::crash_between_materialize_and_confirmation_leaves_no_endpoint_file_or_key`.
    #[tokio::test]
    async fn crash_after_confirmation_before_commit_leaves_no_endpoint_file_or_key() {
        let w = Live::new();
        let hook = Arc::new(CrashBeforeCommit(AtomicBool::new(true)));
        let p = w.process(hook).await;
        let e = w
            .ensure(&p, "crash", RequiredCapabilities::default())
            .await
            .unwrap_err();
        let op = e.operation_id.clone().expect("the operation");
        let binding = w.minted_binding(&op);
        let grant = w.grant_of(&op);
        let (endpoint, _) = p
            .registry
            .binding_endpoint(&binding)
            .expect("materialized before the crash");
        assert_eq!(listed(&endpoint.locator).await.unwrap(), 2);
        assert_eq!(w.binding_dirs(&binding).len(), 1, "the files were written");
        // The crash: the process ends; nothing of it runs its own cleanup.
        p.shutdown.cancel();
        drop(p);
        assert!(gone(&endpoint.locator).await);
        // The restart: recovery, then the wiring, then the supervisor's cleanup pass.
        let q = w.process(Arc::new(NoStageHook)).await;
        q.ops.process_cleanup_intents().await.unwrap();
        assert!(w.binding_dirs(&binding).is_empty(), "no binding file");
        assert!(
            q.registry.binding_endpoint(&binding).is_none(),
            "no endpoint"
        );
        assert!(listed(&endpoint.locator).await.is_err());
        assert_eq!(q.table.vault().len(), 0, "no key");
        assert!(q.table.public_key(&grant).is_none());
        assert_eq!(w.live_instances(&grant), 0);
        let (committed, intents, state, grant_state) = w
            .store
            .transaction(|tx| {
                Ok((
                    tx.binding(&binding)?,
                    tx.cleanup_intents()?,
                    tx.operation(&op)?.map(|o| o.state),
                    tx.grant(&grant)?.map(|g| g.state),
                ))
            })
            .unwrap();
        assert!(committed.is_none(), "no binding committed");
        assert!(intents.is_empty(), "the cleanup intent was processed");
        assert_eq!(state, Some(heimdall_contract::OperationState::Failed));
        assert_eq!(grant_state, Some(GrantState::Failed));
    }

    async fn launch_bind(
        p: &Process,
        binding: &BindingId,
        tag: &str,
        holder: Option<heimdall_contract::request::ProcessHolder>,
    ) -> Result<EnsureData, heimdall_app::OpError> {
        use heimdall_contract::request::{BindForm, BindRequest, LaunchBinding};
        p.ops
            .bind(
                &caller(),
                BindRequest {
                    binding_id: binding.clone(),
                    form: BindForm::Launch(LaunchBinding {
                        executable: "/usr/bin/true".into(),
                        holder,
                    }),
                    request_id: RequestId::parse(&format!("bind-{tag}")).unwrap(),
                },
            )
            .await
            .map(|c| c.data)
    }

    fn slot_of(w: &Live, pr: &AccessPair) -> SlotState {
        w.store.transaction(|tx| tx.slot(&env(), pr)).unwrap()
    }

    /// §17.21 item 2: `BindForm::Launch` of a managed binding claims each pair's free
    /// environment slot in the runtime: the store CAS (`held(b, 1)`), the slot files
    /// at that generation, and the signer's environment listing of the binding's
    /// certificates.
    #[tokio::test]
    async fn launch_bind_claims_the_free_slot() {
        let w = Live::new();
        let p = w.process(Arc::new(NoStageHook)).await;
        let data = w
            .ensure(&p, "slot", RequiredCapabilities::default())
            .await
            .unwrap();
        for pr in pairs() {
            assert_eq!(slot_of(&w, &pr), SlotState::Free { generation: 0 });
        }
        launch_bind(&p, &data.binding_id, "slot", None)
            .await
            .unwrap_or_else(|e| panic!("bind: {} {}", e.code, e.message));
        let root = p.effects.slot_root().clone();
        for pr in pairs() {
            assert_eq!(
                slot_of(&w, &pr),
                SlotState::Held {
                    binding: data.binding_id.clone(),
                    generation: 1
                }
            );
            assert_eq!(files::slot_generation(&root, &pr).unwrap(), Some(1));
            let paths = files::slot_paths(&root.data_dir, &pr).unwrap();
            assert!(paths.key_pub.exists() && paths.cert_pub.exists());
            assert_eq!(
                p.table.materialized_generation(&data.binding_id, &pr),
                Some(1),
                "the environment listing names the binding at the slot's generation"
            );
        }
        assert_eq!(
            p.table
                .list(&heimdall_app::ports::SignerEndpoint::Environment)
                .len(),
            2,
            "the environment endpoint lists the binding's two certificates"
        );
    }

    /// §17.21 item 2: a slot another binding holds refuses the launch bind with its
    /// reason (`CONFIG_CONFLICT`, `managed_slot_held`, next `release_binding`) and
    /// writes nothing else: no slot claim, no holder, no slot file or listing for the
    /// refused binding; the holder's slot is untouched.
    #[tokio::test]
    async fn launch_bind_refuses_a_held_slot_with_its_reason_and_writes_nothing_else() {
        let w = Live::new();
        let p = w.process(Arc::new(NoStageHook)).await;
        let first = w
            .ensure(&p, "first", RequiredCapabilities::default())
            .await
            .unwrap();
        let second = w
            .ensure(&p, "second", RequiredCapabilities::default())
            .await
            .unwrap();
        assert_ne!(first.binding_id, second.binding_id);
        launch_bind(&p, &first.binding_id, "first", None)
            .await
            .unwrap();
        let holder = heimdall_contract::request::ProcessHolder {
            pid: std::process::id(),
            started_at: "fixture-start".into(),
        };
        let e = launch_bind(&p, &second.binding_id, "second", Some(holder))
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::ConfigConflict, "{}", e.message);
        assert_eq!(e.reason.as_deref(), Some("managed_slot_held"));
        assert_eq!(e.next.action, "release_binding");
        for pr in pairs() {
            assert_eq!(
                slot_of(&w, &pr),
                SlotState::Held {
                    binding: first.binding_id.clone(),
                    generation: 1
                },
                "the holder's slot is untouched"
            );
            assert_eq!(
                p.table.materialized_generation(&second.binding_id, &pr),
                None
            );
        }
        let (holder, slots, connections) = w
            .store
            .transaction(|tx| {
                Ok((
                    tx.binding_holder(&second.binding_id)?,
                    tx.slots_for_binding(&second.binding_id)?,
                    tx.owned_connections_for_binding(&second.binding_id)?,
                ))
            })
            .unwrap();
        assert!(holder.is_none(), "no holder registered");
        assert!(slots.is_empty(), "no slot claimed");
        assert!(connections.is_empty(), "no owned connection");
        assert_eq!(p.table.materialized_pairs(&second.binding_id), Vec::new());
    }
}
