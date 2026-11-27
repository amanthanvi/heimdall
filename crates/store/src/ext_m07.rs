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

use heimdall_contract::OperationState;

use crate::{Result, StoreError, Txn, codec, operation_states, sql_in_list};

/// A page's row count as SQLite's `LIMIT`.
fn limit(take: usize) -> Result<i64> {
    codec::int(u64::try_from(take).unwrap_or(u64::MAX))
}

impl Txn<'_> {
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

/// ⟨rev7; ADR-0013 §5.5, §6.4; D4, PC1⟩ A snapshot section read whole or not at all: its rows
/// are counted, and their stored documents' lengths summed, in SQL over `LIMIT cap + 1` before
/// any row is materialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionRead<T> {
    /// Every row, at most the cap; `bytes` is the sum of their stored documents' lengths.
    Whole {
        /// The rows, in the section's order.
        rows: Vec<T>,
        /// Their stored documents' total length in bytes.
        bytes: u64,
    },
    /// More rows than the cap. None was materialized.
    OverCount,
    /// The rows' documents sum to more than the budget. None was materialized.
    OverBytes,
}

/// ⟨rev7; PC1⟩ Which operations [`Txn::snapshot_operations`] reads.
#[derive(Debug, Clone, Copy)]
pub enum SnapshotOperations<'a> {
    /// The `operations` section: the open operations, then the unresolved
    /// (`outcome_unknown`) ones, each in creation order, of these environments.
    Listed(&'a [EnvironmentId]),
    /// The `operation` section: the one operation `filter.operation_id` names, in any state.
    One(&'a heimdall_contract::ids::OperationId),
}

/// What a bounded read of a snapshot section selects (the `WHERE` clause and its parameters).
struct SectionQuery {
    /// `FROM <table> WHERE ...` (no `ORDER BY` or `LIMIT`).
    from_where: String,
    /// `ORDER BY ...`.
    order: String,
    params: Vec<rusqlite::types::Value>,
}

impl Txn<'_> {
    /// ⟨rev7; PC1⟩ The operations a snapshot holds, whole or not at all
    /// ([`SnapshotOperations`]). `callers` restricts them to operations created by one of those
    /// exact callers (`None`: every caller's, for the local owner's global access). At most
    /// `cap` rows whose documents sum to at most `budget` bytes, else
    /// [`SectionRead::OverCount`] / [`SectionRead::OverBytes`] with nothing materialized.
    pub fn snapshot_operations(
        &mut self,
        which: SnapshotOperations<'_>,
        callers: Option<&[heimdall_domain::principal::CallerContext]>,
        cap: usize,
        budget: u64,
    ) -> Result<SectionRead<OperationRecord>> {
        fn placeholders(values: Vec<String>, params: &mut Vec<rusqlite::types::Value>) -> String {
            let mut out = Vec::with_capacity(values.len());
            for v in values {
                params.push(rusqlite::types::Value::Text(v));
                out.push(format!("?{}", params.len()));
            }
            out.join(",")
        }
        let unresolved = sql_in_list(&operation_states(OperationState::is_unresolved))?;
        let mut params = Vec::new();
        let mut from_where = match which {
            SnapshotOperations::Listed(environments) => {
                let listed = sql_in_list(&operation_states(|s| !s.is_settled()))?;
                let envs = placeholders(
                    environments.iter().map(|e| e.as_str().to_owned()).collect(),
                    &mut params,
                );
                format!("FROM operations WHERE state IN ({listed}) AND environment IN ({envs})")
            }
            SnapshotOperations::One(id) => {
                let id = placeholders(vec![id.as_str().to_owned()], &mut params);
                format!("FROM operations WHERE id = {id}")
            }
        };
        if let Some(callers) = callers {
            let mut docs = Vec::with_capacity(callers.len());
            for c in callers {
                docs.push(codec::doc(c)?);
            }
            let callers = placeholders(docs, &mut params);
            from_where.push_str(&format!(" AND caller_json IN ({callers})"));
        }
        self.section(
            SectionQuery {
                from_where,
                order: format!(
                    "ORDER BY CASE WHEN state IN ({unresolved}) THEN 1 ELSE 0 END, created_at, id"
                ),
                params,
            },
            cap,
            budget,
        )
    }

    /// ⟨rev7; PC1⟩ The pending decisions a snapshot holds (as [`Txn::pending_decisions`], oldest
    /// first), whole or not at all: at most `cap` rows whose documents sum to at most `budget`
    /// bytes, else [`SectionRead::OverCount`] / [`SectionRead::OverBytes`] with nothing
    /// materialized.
    pub fn snapshot_pending_decisions(
        &mut self,
        cap: usize,
        budget: u64,
    ) -> Result<SectionRead<DecisionRecord>> {
        self.section(
            SectionQuery {
                from_where: "FROM decisions WHERE state = ?1".to_owned(),
                order: "ORDER BY created_at, id".to_owned(),
                params: vec![rusqlite::types::Value::Text(codec::enum_str(
                    &DecisionState::Pending,
                )?)],
            },
            cap,
            budget,
        )
    }

    /// One bounded section read: count and sum over `LIMIT cap + 1` first, then materialize.
    fn section<T: serde::de::DeserializeOwned>(
        &mut self,
        q: SectionQuery,
        cap: usize,
        budget: u64,
    ) -> Result<SectionRead<T>> {
        let take = limit(cap.saturating_add(1))?;
        let n = q.params.len();
        let bounded = format!(
            "SELECT record_json {} {} LIMIT ?{}",
            q.from_where,
            q.order,
            n + 1
        );
        let mut params = q.params;
        params.push(rusqlite::types::Value::Integer(take));
        // Lengths in bytes: `length()` of TEXT counts characters.
        let (count, bytes): (i64, i64) = self.tx.query_row(
            &format!(
                "SELECT count(*), coalesce(sum(length(CAST(record_json AS BLOB))), 0)
                 FROM ({bounded})"
            ),
            rusqlite::params_from_iter(params.iter()),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (count, bytes) = (codec::uint(count)?, codec::uint(bytes)?);
        if count > u64::try_from(cap).unwrap_or(u64::MAX) {
            return Ok(SectionRead::OverCount);
        }
        if bytes > budget {
            return Ok(SectionRead::OverBytes);
        }
        let rows = self.docs(&bounded, rusqlite::params_from_iter(params.iter()))?;
        Ok(SectionRead::Whole { rows, bytes })
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
        assert_eq!(store.transaction(|tx| tx.restore_epoch()).unwrap().0, 0);
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

    /// An operation of `uid` in environment 7, `state`, created at second `n`.
    fn snapshot_op(
        n: u8,
        uid: u32,
        state: heimdall_contract::OperationState,
    ) -> (
        heimdall_domain::operation::OperationRecord,
        heimdall_domain::idempotency::IdempotencyRecord,
    ) {
        use heimdall_contract::canonical::RequestHash;
        use heimdall_contract::ids::{EnvironmentId, OperationId, RequestId};
        use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
        use heimdall_domain::operation::{
            EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
        };
        let key = IdempotencyKey {
            caller: caller(uid, heimdall_domain::principal::ClientRole::Owner),
            kind: OperationKind::Ensure,
            request_id: RequestId::parse(&format!("req-{n}")).unwrap(),
        };
        let at: heimdall_contract::Timestamp = format!("2026-10-01T00:00:{n:02}Z").parse().unwrap();
        let op = OperationRecord {
            id: OperationId::from_random_bytes([n; 16]),
            kind: OperationKind::Ensure,
            environment: EnvironmentId::from_random_bytes([7; 16]),
            key: key.clone(),
            request_hash: RequestHash([n; 32]),
            effect_class: EffectClass::Local,
            state,
            code: None,
            effect_status: heimdall_contract::envelope::EffectStatus::None,
            result: None,
            created_at: at,
            updated_at: at,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: op.request_hash,
            operation_id: op.id.clone(),
            created_at: at,
            expires_at: None,
        };
        (op, idem)
    }

    fn caller(
        uid: u32,
        role: heimdall_domain::principal::ClientRole,
    ) -> heimdall_domain::principal::CallerContext {
        heimdall_domain::principal::CallerContext {
            principal: heimdall_domain::principal::PrincipalRef::UnixUser { uid },
            role,
            remote_client: None,
        }
    }

    /// ⟨rev7; PC1⟩ A snapshot section is counted and summed in SQL over `LIMIT cap + 1` before
    /// any row is materialized: over the count or the budget, nothing is decoded (a damaged
    /// row in the section does not fail the read); within both, every row, open ones first,
    /// filtered by environment, caller and ID.
    #[test]
    fn snapshot_sections_are_bounded_before_any_row_is_materialized() {
        use heimdall_contract::OperationState as S;
        use heimdall_contract::ids::{EnvironmentId, OperationId};
        use heimdall_domain::principal::ClientRole;

        use super::{SectionRead, SnapshotOperations};
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let env = [EnvironmentId::from_random_bytes([7; 16])];
        store
            .transaction(|tx| {
                for (n, uid, state) in [
                    (1, 501, S::OutcomeUnknown),
                    (2, 501, S::Running),
                    (3, 502, S::AwaitingApproval),
                    (4, 501, S::Succeeded),
                ] {
                    let (op, idem) = snapshot_op(n, uid, state);
                    tx.insert_operation(&op, &idem)?;
                }
                Ok(())
            })
            .unwrap();
        let read = |callers: Option<Vec<heimdall_domain::principal::CallerContext>>,
                    only: Option<OperationId>,
                    cap: usize,
                    budget: u64| {
            let which = match &only {
                Some(id) => SnapshotOperations::One(id),
                None => SnapshotOperations::Listed(&env),
            };
            store
                .transaction(|tx| tx.snapshot_operations(which, callers.as_deref(), cap, budget))
                .unwrap()
        };
        let ids = |r: SectionRead<heimdall_domain::operation::OperationRecord>| match r {
            SectionRead::Whole { rows, bytes } => {
                assert!(bytes > 0 || rows.is_empty());
                rows.iter()
                    .map(|o| {
                        (1..=4u8)
                            .find(|n| o.id == OperationId::from_random_bytes([*n; 16]))
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            }
            other => panic!("{other:?}"),
        };
        // Open first (creation order), then unresolved; the settled one is not listed.
        assert_eq!(ids(read(None, None, 3, u64::MAX)), vec![2, 3, 1]);
        // One caller's, in either role; another environment's, none.
        let mine = vec![
            caller(501, ClientRole::Owner),
            caller(501, ClientRole::LimitedConsumer),
        ];
        assert_eq!(ids(read(Some(mine), None, 3, u64::MAX)), vec![2, 1]);
        let other = store
            .transaction(|tx| {
                tx.snapshot_operations(
                    SnapshotOperations::Listed(&[EnvironmentId::from_random_bytes([8; 16])]),
                    None,
                    3,
                    u64::MAX,
                )
            })
            .unwrap();
        assert_eq!(ids(other), Vec::<u8>::new());
        let three = OperationId::from_random_bytes([3; 16]);
        assert_eq!(ids(read(None, Some(three.clone()), 1, u64::MAX)), vec![3]);
        // The named operation in any state, settled included; another caller's, none.
        let four = OperationId::from_random_bytes([4; 16]);
        assert_eq!(ids(read(None, Some(four.clone()), 1, u64::MAX)), vec![4]);
        let theirs = vec![caller(502, ClientRole::Owner)];
        assert_eq!(
            ids(read(Some(theirs), Some(four), 1, u64::MAX)),
            Vec::<u8>::new()
        );
        // Over the count, and over the budget: refused, with a damaged row not decoded.
        store
            .transaction(|tx| {
                tx.damage_document_for_test(super::PageTable::Operations, three.as_str())
            })
            .unwrap();
        assert_eq!(read(None, None, 2, u64::MAX), SectionRead::OverCount);
        assert_eq!(read(None, None, 3, 10), SectionRead::OverBytes);
        assert_eq!(read(None, Some(three), 1, 10), SectionRead::OverBytes);
        // Within both, the damaged row is materialized, and refused.
        assert!(
            store
                .transaction(|tx| {
                    tx.snapshot_operations(SnapshotOperations::Listed(&env), None, 3, u64::MAX)
                })
                .is_err()
        );
        // Decisions: none pending is whole and empty; over the count, refused.
        assert_eq!(
            store
                .transaction(|tx| tx.snapshot_pending_decisions(0, 0))
                .unwrap(),
            SectionRead::Whole {
                rows: Vec::new(),
                bytes: 0
            }
        );
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
