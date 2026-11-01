//! Versioned, transactional schema migrations (spec §13.3 "Migration must be
//! transactional and backed up").
//!
//! Each step runs inside one `BEGIN IMMEDIATE` transaction that also sets
//! `PRAGMA user_version`, so a step is either fully applied with its version or not
//! at all. A database whose `user_version` exceeds what this build knows is refused
//! with [`crate::StoreError::NewerSchema`]; a database that has schema objects but
//! no version is refused as [`crate::StoreError::Corrupt`]. Neither case is ever
//! treated as an empty installation (spec §13.3, §15.2).

use rusqlite::{Connection, TransactionBehavior};

use crate::codec::classify;
use crate::{FaultHook, FaultPoint, Result, StoreError, fire};

/// Schema version this build writes and the highest it reads.
pub const SCHEMA_VERSION: u32 = 2;

/// A migration step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Target schema version after this step.
    pub version: u32,
    /// Human name.
    pub name: &'static str,
    /// SQL executed inside one transaction.
    pub sql: &'static str,
}

/// All steps in order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../migrations/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "design_fix",
        sql: include_str!("../migrations/0002_design_fix.sql"),
    },
];

/// Apply pending migrations to `conn`. Before the first pending step on a file-backed
/// database the caller must have written a backup copy. Refuses to run when the
/// on-disk version exceeds [`SCHEMA_VERSION`].
pub fn apply(conn: &mut rusqlite::Connection, faults: &dyn crate::FaultHook) -> crate::Result<u32> {
    apply_steps(conn, faults, MIGRATIONS)
}

/// Highest version a step list produces.
pub(crate) fn target_version(steps: &[Migration]) -> u32 {
    steps.last().map_or(0, |m| m.version)
}

/// `PRAGMA user_version`.
pub(crate) fn user_version(conn: &Connection) -> Result<u32> {
    let v: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(classify)?;
    u32::try_from(v).map_err(|_| StoreError::Corrupt("schema version is out of range".into()))
}

/// Number of schema objects (tables, indexes, triggers, views), excluding SQLite's
/// own `sqlite_*` objects.
pub(crate) fn schema_object_count(conn: &Connection) -> Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        [],
        |r| r.get(0),
    )
    .map_err(classify)
}

/// Refuse a newer schema and an unversioned non-empty schema.
pub(crate) fn check_version(conn: &Connection, steps: &[Migration]) -> Result<u32> {
    let current = user_version(conn)?;
    let supported = target_version(steps);
    if current > supported {
        return Err(StoreError::NewerSchema {
            found: current,
            supported,
        });
    }
    if current == 0 && schema_object_count(conn)? > 0 {
        return Err(StoreError::Corrupt(
            "schema objects present without a schema version".into(),
        ));
    }
    Ok(current)
}

/// Apply `steps` (contiguous from 1) with fault points around each step.
pub(crate) fn apply_steps(
    conn: &mut Connection,
    faults: &dyn FaultHook,
    steps: &[Migration],
) -> Result<u32> {
    let current = check_version(conn, steps)?;
    for step in steps.iter().filter(|m| m.version > current) {
        fire(faults, FaultPoint::BeforeMigration)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(classify)?;
        // Re-read inside the write lock: another opener may have migrated meanwhile.
        let in_tx = user_version(&tx)?;
        if in_tx >= step.version {
            continue;
        }
        if in_tx + 1 != step.version {
            return Err(StoreError::Corrupt(
                "schema version skipped a migration step".into(),
            ));
        }
        tx.execute_batch(step.sql).map_err(classify)?;
        tx.pragma_update(None, "user_version", step.version)
            .map_err(classify)?;
        tx.commit().map_err(classify)?;
        tracing::info!(
            version = step.version,
            name = step.name,
            "state store migrated"
        );
        fire(faults, FaultPoint::AfterMigration)?;
    }
    user_version(conn)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::NoFaults;

    #[test]
    fn migrations_are_contiguous_from_one() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1);
            assert!(!m.sql.trim().is_empty());
        }
        assert_eq!(MIGRATIONS.last().map(|m| m.version), Some(SCHEMA_VERSION));
    }

    #[test]
    fn apply_is_idempotent_and_sets_user_version() {
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply(&mut c, &NoFaults).unwrap(), SCHEMA_VERSION);
        assert_eq!(apply(&mut c, &NoFaults).unwrap(), SCHEMA_VERSION);
        assert_eq!(user_version(&c).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn failing_step_rolls_back_whole_step_and_version() {
        const STEPS: &[Migration] = &[
            Migration {
                version: 1,
                name: "ok",
                sql: "CREATE TABLE a (x INTEGER) STRICT;",
            },
            Migration {
                version: 2,
                name: "broken",
                sql: "CREATE TABLE b (x INTEGER) STRICT; THIS IS NOT SQL;",
            },
        ];
        let mut c = Connection::open_in_memory().unwrap();
        assert!(apply_steps(&mut c, &NoFaults, STEPS).is_err());
        assert_eq!(user_version(&c).unwrap(), 1);
        let b_exists: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'b'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b_exists, 0, "half-applied step must not survive");
    }

    #[test]
    fn newer_and_unversioned_schemas_are_refused() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
        assert!(matches!(
            apply(&mut c, &NoFaults),
            Err(StoreError::NewerSchema {
                found: 99,
                supported: SCHEMA_VERSION
            })
        ));
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE stray (x INTEGER);").unwrap();
        assert!(matches!(
            apply(&mut c, &NoFaults),
            Err(StoreError::Corrupt(_))
        ));
    }
}
