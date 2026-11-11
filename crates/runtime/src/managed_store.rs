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
//!   supervisor as the end requires.

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

    /// The bindings of `grant` the store knows (its references and the bindings of
    /// its owned connections), with the slots each holds.
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
            let mut slots = Vec::new();
            for b in &bindings {
                slots.extend(tx.slots_for_binding(b)?);
            }
            Ok((bindings.into_iter().collect(), slots, masters))
        })
    }

    /// One slot of `binding`, by its own store generation (U6-Q4).
    async fn clear_one_slot(&self, slot: &StoreSlot, had_master: bool) -> Result<(), AdapterError> {
        let Some(binding) = &slot.binding else {
            return Ok(());
        };
        let generation = match &slot.state {
            SlotState::Held {
                binding: holder,
                generation,
            } if holder == binding => *generation,
            SlotState::Clearing { generation } => *generation,
            _ => return Ok(()),
        };
        let env = slot.environment.clone();
        let at = Timestamp::now();
        let store = Arc::clone(&self.sources.store);
        let (pair, b) = (slot.pair.clone(), binding.clone());
        store
            .transaction(|tx| match tx.slot(&env, &pair)? {
                SlotState::Held { .. } => {
                    tx.release_slot(&env, &pair, &b, generation, at).map(|_| ())
                }
                _ => Ok(()),
            })
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))?;
        self.effects.clear_slot(binding, &slot.pair, generation)?;
        store
            .transaction(|tx| {
                tx.slot_files_removed(&env, &pair, generation, at)
                    .map(|_| ())
            })
            .map_err(|_| AdapterError::Unavailable("store".to_owned()))?;
        if !had_master
            && let Some(c) = &self.connections
            && c.clear_slot_path(&slot.pair.destination).await.is_err()
        {
            return Err(AdapterError::Unavailable("slot_path".to_owned()));
        }
        Ok(())
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
                // A grant that has not ended is left alone.
                None => continue,
            }
            let Ok((bindings, slots, masters)) = self.bindings_and_slots(g) else {
                failed = true;
                continue;
            };
            for s in &slots {
                let had_master = masters.iter().any(|p| {
                    heimdall_localenv::projection::content::checked_mux_path(
                        self.effects.runtime_dir(),
                        &s.pair.destination,
                    )
                    .is_ok_and(|m| m.to_string_lossy() == p.as_str())
                });
                if self.clear_one_slot(s, had_master).await.is_err() {
                    failed = true;
                }
            }
            for b in &bindings {
                match files::binding_directories_of(self.effects.runtime_dir(), b) {
                    Ok(dirs) => {
                        for (_, generation) in dirs {
                            if self.effects.clear(b, generation).is_err() {
                                failed = true;
                            }
                        }
                    }
                    Err(_) => failed = true,
                }
            }
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
