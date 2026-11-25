//! ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.1, §6.2, §6.4; D2): the keyset reads behind `inspect`'s
//! `page` form and the restore epoch a page token is bound to.
//!
//! **Keyset order.** Every read here is ordered by the record's immutable ID (SQLite's
//! `BINARY` collation, which is byte order, the order of Rust's `str`), strictly after the
//! previous page's last ID, and reads at most `take` rows: the caller asks for its page's
//! `limit + 1`, so it learns whether more remain without reading them. A record inserted or
//! deleted between two pages never moves another one across the position, so a stable record
//! is never repeated or skipped.
//!
//! Reads only: nothing here writes, and none of them reads the clock.

use heimdall_contract::ids::{EnrollmentId, EnvironmentId};
use heimdall_domain::catalog::{DestinationRecord, IdentityRecord};
use heimdall_domain::decision::{DecisionRecord, DecisionState};
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};
use heimdall_domain::operation::OperationRecord;
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::resource::{ManagedResource, OwnerRef, ResourceKind};

use crate::{
    META_RESTORE_EPOCH, Result, StoreError, Txn, codec, operation_states, parse_restore_epoch,
    sql_in_list,
};

/// A page's row count as SQLite's `LIMIT`.
fn limit(take: usize) -> Result<i64> {
    codec::int(u64::try_from(take).unwrap_or(u64::MAX))
}

impl Txn<'_> {
    /// ⟨rev7; ADR-0014 H9, §3.6⟩ The store's current restore epoch, read where a page is
    /// served (a page token minted under another epoch is refused). A missing or malformed
    /// value is damage ([`StoreError::Corrupt`]), never epoch 0, as at every open.
    pub fn restore_epoch(&mut self) -> Result<u64> {
        self.meta(META_RESTORE_EPOCH)?
            .as_deref()
            .and_then(parse_restore_epoch)
            .ok_or_else(|| {
                StoreError::Corrupt("the restore epoch is missing or malformed".to_owned())
            })
    }

    /// ⟨rev7⟩ At most `take` catalog destinations whose ID sorts after `after` (every one
    /// when `None`), ordered by ID.
    pub fn destinations_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<DestinationRecord>> {
        self.docs(
            "SELECT record_json FROM destinations WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7⟩ At most `take` current profile definitions whose ID sorts after `after`,
    /// ordered by ID. Removed definitions are not listed, as in [`Txn::profiles`].
    pub fn profiles_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<ProfileDefinition>> {
        self.docs(
            "SELECT record_json FROM profiles WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7; m07-plan U3, ruled 2026-11-25 (U3-1b's Q2)⟩ At most `take` destinations, by ID,
    /// whose approved routes include a jump through `via`: a stored route list with a `jump`
    /// route naming `via`, or (with no stored list, the one-element case) a managed definition
    /// whose `jump` is `via`. Exactly the destinations
    /// `heimdall_domain::catalog::RouteCatalogView::used_as_jump_by` would find over the whole
    /// catalog, read by key instead of enumerating it.
    pub fn destinations_jumping_through(
        &mut self,
        via: &heimdall_contract::ids::DestinationId,
        take: usize,
    ) -> Result<Vec<heimdall_contract::ids::DestinationId>> {
        let mut stmt = self.tx.prepare(
            "SELECT id FROM destinations
              WHERE json_extract(record_json, '$.definition.kind') = 'managed'
                AND json_extract(record_json, '$.definition.jump') = ?1
                AND id NOT IN (SELECT destination FROM destination_routes)
             UNION
             SELECT destination FROM destination_routes
              WHERE json_extract(route_json, '$.route.kind') = 'jump'
                AND json_extract(route_json, '$.route.via') = ?1
             ORDER BY 1 LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![via.as_str(), limit(take)?], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for id in rows {
            out.push(
                heimdall_contract::ids::DestinationId::parse(&id?).map_err(|_| {
                    StoreError::Corrupt("a stored route names no destination".into())
                })?,
            );
        }
        Ok(out)
    }

    /// ⟨rev7; S2, ruled 2026-11-25⟩ At most `take` operations `inspect operations` lists (every
    /// state but a settled one: the open operations and `outcome_unknown`, as
    /// [`Txn::open_operations`] and [`Txn::unresolved_operations`] together) whose ID sorts after
    /// `after`, ordered by ID.
    pub fn listed_operations_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<OperationRecord>> {
        let sql = format!(
            "SELECT record_json FROM operations WHERE state IN ({}) AND (?1 IS NULL OR id > ?1)
             ORDER BY id LIMIT ?2",
            sql_in_list(&operation_states(|s| !s.is_settled()))?
        );
        self.docs(&sql, rusqlite::params![after, limit(take)?])
    }

    /// ⟨rev7; S2⟩ At most `take` pending decision records (as [`Txn::pending_decisions`]) whose
    /// ID sorts after `after`, ordered by ID.
    pub fn pending_decisions_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<DecisionRecord>> {
        self.docs(
            "SELECT record_json FROM decisions WHERE state = ?1 AND (?2 IS NULL OR id > ?2)
             ORDER BY id LIMIT ?3",
            rusqlite::params![
                codec::enum_str(&DecisionState::Pending)?,
                after,
                limit(take)?
            ],
        )
    }

    /// ⟨rev7; S2⟩ At most `take` live owned connections (`up` or `closing`: the rows `inspect
    /// connections` lists) whose ID sorts after `after`, ordered by ID.
    pub fn live_owned_connections_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<OwnedConnection>> {
        self.docs(
            "SELECT record_json FROM owned_connections WHERE state IN (?1, ?2)
               AND (?3 IS NULL OR id > ?3)
             ORDER BY id LIMIT ?4",
            rusqlite::params![
                codec::enum_str(&OwnedConnectionState::Up)?,
                codec::enum_str(&OwnedConnectionState::Closing)?,
                after,
                limit(take)?
            ],
        )
    }

    /// ⟨rev7; S2⟩ At most `take` of `environment`'s projection resources (as
    /// [`Txn::projection_resources`]) whose ID sorts after `after`, ordered by ID.
    pub fn projection_resources_after(
        &mut self,
        environment: &EnvironmentId,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<ManagedResource>> {
        let owner = codec::doc(&OwnerRef::Projection {
            environment: environment.clone(),
        })?;
        self.docs(
            "SELECT record_json FROM resources WHERE kind = ?1 AND owner_json = ?2
               AND (?3 IS NULL OR id > ?3)
             ORDER BY id LIMIT ?4",
            rusqlite::params![
                codec::enum_str(&ResourceKind::ConfigProjection)?,
                owner,
                after,
                limit(take)?
            ],
        )
    }

    /// ⟨rev7; S2⟩ At most `take` enrollment records, every state, whose ID sorts after `after`,
    /// ordered by ID: the IDs by keyset, each record then read by [`Txn::enrollment`] (its
    /// row checked against its document there).
    pub fn enrollments_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<heimdall_domain::enrollment::EnrollmentRecord>> {
        let ids: Vec<String> = {
            let mut stmt = self.tx.prepare(
                "SELECT id FROM enrollments WHERE ?1 IS NULL OR id > ?1 ORDER BY id LIMIT ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![after, limit(take)?], |r| {
                r.get::<_, String>(0)
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let id = EnrollmentId::parse(&id)
                .map_err(|_| StoreError::Corrupt("an enrollment ID is malformed".into()))?;
            if let Some(r) = self.enrollment(&id)? {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// ⟨rev7; S2⟩ At most `take` managed environments `controller` manages (the rows
    /// `inspect environments` lists for the owner, as [`Txn::managed_environments`] filtered by
    /// controller) whose ID sorts after `after`, ordered by ID, every state.
    pub fn managed_environments_after(
        &mut self,
        controller: &EnvironmentId,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<heimdall_domain::environment::ManagedEnvironment>> {
        self.docs(
            "SELECT record_json FROM managed_environments
              WHERE controller = ?1 AND (?2 IS NULL OR environment_id > ?2)
             ORDER BY environment_id LIMIT ?3",
            rusqlite::params![controller.as_str(), after, limit(take)?],
        )
    }

    /// ⟨rev7; S2⟩ At most `take` WSL distribution records with a projection namespace that
    /// sorts after `after`, ordered by namespace (then GUID), whose Mode B is not enabled and
    /// whose Mode A is enabled or still owes its cleanup: the distributions `inspect
    /// environments` lists by namespace (`heimdall_app`'s `environments_view`, which applies
    /// the same test to what it reads).
    pub fn mode_a_distributions_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<heimdall_domain::environment::WslDistributionRecord>> {
        self.docs(
            "SELECT record_json FROM wsl_distributions
              WHERE json_extract(record_json, '$.namespace') IS NOT NULL
                AND json_extract(record_json, '$.mode_b') IS NULL
                AND (json_extract(record_json, '$.mode_a') = 1
                     OR json_extract(record_json, '$.cleanup_pending') = 1)
                AND (?1 IS NULL OR json_extract(record_json, '$.namespace') > ?1)
             ORDER BY json_extract(record_json, '$.namespace'), guid LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7; S2⟩ The WSL distribution records whose projection namespace is `namespace` (a
    /// `select` of an `inspect environments` item by its ID), by GUID.
    pub fn distributions_with_namespace(
        &mut self,
        namespace: &str,
    ) -> Result<Vec<heimdall_domain::environment::WslDistributionRecord>> {
        self.docs(
            "SELECT record_json FROM wsl_distributions
              WHERE json_extract(record_json, '$.namespace') = ?1 ORDER BY guid",
            [namespace],
        )
    }

    /// ⟨rev7; S2⟩ At most `take` standing policies (as [`Txn::policies`]) whose ID sorts after
    /// `after`, ordered by ID.
    pub fn policies_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<heimdall_domain::policy::StandingPolicy>> {
        self.docs(
            "SELECT record_json FROM policies WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7⟩ At most `take` catalog identities whose ID sorts after `after`, ordered by ID.
    pub fn identities_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<IdentityRecord>> {
        self.docs(
            "SELECT record_json FROM identities WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }
}

/// Test support (the `test-support` feature, which only dev-dependencies enable): the tables
/// [`Txn::damage_document_for_test`] damages.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTable {
    /// `destinations`.
    Destinations,
    /// `profiles`.
    Profiles,
    /// `identities`.
    Identities,
    /// `operations`.
    Operations,
    /// `decisions`.
    Decisions,
    /// `owned_connections`.
    OwnedConnections,
    /// `resources`.
    Resources,
    /// `enrollments`.
    Enrollments,
    /// `managed_environments` (by `environment_id`).
    ManagedEnvironments,
    /// `policies`.
    Policies,
}

#[cfg(any(test, feature = "test-support"))]
impl Txn<'_> {
    /// Test support (debug builds only; ⟨rev7; S2⟩ the bounded page-read tests): replace the
    /// stored document of row `id` of `table` with one that does not decode, so any read that
    /// materializes that row fails [`StoreError::Corrupt`] while a read that stops before it
    /// succeeds. Returns the rows changed. Never used by production code; a build without the
    /// `test-support` feature (every product build) does not have it.
    #[doc(hidden)]
    pub fn damage_document_for_test(&mut self, table: PageTable, id: &str) -> Result<usize> {
        let (name, key) = match table {
            PageTable::Destinations => ("destinations", "id"),
            PageTable::Profiles => ("profiles", "id"),
            PageTable::Identities => ("identities", "id"),
            PageTable::Operations => ("operations", "id"),
            PageTable::Decisions => ("decisions", "id"),
            PageTable::OwnedConnections => ("owned_connections", "id"),
            PageTable::Resources => ("resources", "id"),
            PageTable::Enrollments => ("enrollments", "id"),
            PageTable::ManagedEnvironments => ("managed_environments", "environment_id"),
            PageTable::Policies => ("policies", "id"),
        };
        Ok(self.tx.execute(
            &format!("UPDATE {name} SET record_json = '{{\"damaged\":true}}' WHERE {key} = ?1"),
            [id],
        )?)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use crate::{NoFaults, Store};

    #[test]
    fn restore_epoch_reads_the_migrated_value_and_refuses_damage() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        assert_eq!(store.transaction(|tx| tx.restore_epoch()).unwrap(), 0);
        store
            .transaction(|tx| tx.set_meta(crate::META_RESTORE_EPOCH, "007"))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.restore_epoch()),
            Err(crate::StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn page_token_key_is_generated_once_and_damage_is_refused() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let first = store
            .transaction(|tx| tx.page_token_key(|| [7; 32]))
            .unwrap();
        assert_eq!(first.expose(), &[7; 32]);
        let again = store
            .transaction(|tx| tx.page_token_key(|| unreachable!("generated once")))
            .unwrap();
        assert_eq!(again, first);
        assert_eq!(format!("{first:?}"), "PageTokenKey(..)");
        store
            .transaction(|tx| tx.set_meta(crate::META_PAGE_TOKEN_KEY, "0707"))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.page_token_key(|| [9; 32])),
            Err(crate::StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn keyset_reads_are_bounded_and_strictly_after() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let all = store
            .transaction(|tx| tx.destinations_after(None, 10))
            .unwrap();
        assert!(all.is_empty());
        let profiles = store
            .transaction(|tx| tx.profiles_after(Some("a"), 0))
            .unwrap();
        assert!(profiles.is_empty());
        let identities = store
            .transaction(|tx| tx.identities_after(None, 1))
            .unwrap();
        assert!(identities.is_empty());
    }
}
