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
pub const SCHEMA_VERSION: u32 = 10;

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
    Migration {
        version: 3,
        name: "grant_approval",
        sql: include_str!("../migrations/0003_grant_approval.sql"),
    },
    Migration {
        version: 4,
        name: "grant_origin",
        sql: include_str!("../migrations/0004_grant_origin.sql"),
    },
    Migration {
        version: 5,
        name: "existing_access",
        sql: include_str!("../migrations/0005_existing_access.sql"),
    },
    Migration {
        version: 6,
        name: "managed_credentials",
        sql: include_str!("../migrations/0006_managed_credentials.sql"),
    },
    // ⟨M04⟩ Joint wave 0 (ADR-0010 §9 item 9; ADR-0011 §10 item 5: `0007` is M04's).
    Migration {
        version: 7,
        name: "platform_realization",
        sql: include_str!("../migrations/0007_platform_realization.sql"),
    },
    // ⟨M05⟩ Joint wave 0 (ADR-0011 §10 item 5: `0008` is M05's).
    Migration {
        version: 8,
        name: "trusted_work",
        sql: include_str!("../migrations/0008_trusted_work.sql"),
    },
    // ⟨M06⟩ Wave 0 (ADR-0012 §9 item 11; ADR-0006 §18): tables only, no store API yet.
    Migration {
        version: 9,
        name: "remote",
        sql: include_str!("../migrations/0009_remote.sql"),
    },
    // ⟨M06⟩ Wave 2 (ADR-0012 §3.10): the runner-local widening records' side table.
    Migration {
        version: 10,
        name: "remote_widening",
        sql: include_str!("../migrations/0010_remote_widening.sql"),
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

    /// ⟨M06⟩ ADR-0006 §18 (ADR-0012 §9 item 11): `0009_remote` applies on a database at
    /// the previous version (8) and adds exactly its tables, leaving every earlier table
    /// as it was; a failure inside the step leaves the database at 8 with none of them
    /// (the step runs as one transaction, as [`failing_step_rolls_back_whole_step_and_version`]
    /// proves for any step). Forward-only: no down step exists.
    #[test]
    fn remote_step_applies_on_the_previous_version_and_rolls_back_whole() {
        const REMOTE: [&str; 11] = [
            "destination_routes",
            "remote_authority_generation",
            "remote_clients",
            "remote_effect_acks",
            "remote_effect_outbox",
            "remote_environment_pins",
            "remote_grant_issuers",
            "remote_invitations",
            "remote_policy_revisions",
            "route_consents",
            "transport_keys",
        ];
        let tables = |c: &Connection| -> Vec<String> {
            let mut stmt = c
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'
                     AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
                )
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        let previous = &MIGRATIONS[..8];
        assert_eq!(MIGRATIONS[8].version, 9);
        assert_eq!(MIGRATIONS[8].name, "remote");
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 8);
        let before = tables(&c);
        assert!(REMOTE.iter().all(|t| !before.iter().any(|b| b == t)));
        c.execute_batch("INSERT INTO meta (key, value) VALUES ('m06-w0-probe', 'kept')")
            .unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, &MIGRATIONS[..9]).unwrap(), 9);
        let after = tables(&c);
        let added: Vec<&String> = after.iter().filter(|t| !before.contains(t)).collect();
        assert_eq!(added, REMOTE.iter().collect::<Vec<_>>());
        let kept: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'm06-w0-probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, "kept");
        // The step is one transaction: broken after its first statement, nothing of it
        // survives and the version stays 8.
        let broken = [
            previous.to_vec(),
            vec![Migration {
                version: 9,
                name: "remote_broken",
                sql: concat!(
                    include_str!("../migrations/0009_remote.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 8);
        assert_eq!(tables(&c), before);
    }

    /// ⟨M06⟩ Wave 2 (ADR-0012 §3.10): `0010_remote_widening` applies on a database at
    /// version 9 and adds exactly its table, keeping every row; a failure inside the step
    /// leaves version 9 and no `remote_widening`.
    #[test]
    fn remote_widening_step_applies_on_version_9_and_rolls_back_whole() {
        let tables = |c: &Connection| -> Vec<String> {
            let mut stmt = c
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'
                     AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
                )
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        let previous = &MIGRATIONS[..9];
        assert_eq!(MIGRATIONS[9].version, 10);
        assert_eq!(MIGRATIONS[9].name, "remote_widening");
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 9);
        let before = tables(&c);
        c.execute_batch("INSERT INTO meta (key, value) VALUES ('m06-w2-probe', 'kept')")
            .unwrap();
        assert_eq!(apply(&mut c, &NoFaults).unwrap(), 10);
        let after = tables(&c);
        let added: Vec<&String> = after.iter().filter(|t| !before.contains(t)).collect();
        assert_eq!(added, vec!["remote_widening"]);
        let kept: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'm06-w2-probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, "kept");
        let broken = [
            previous.to_vec(),
            vec![Migration {
                version: 10,
                name: "remote_widening_broken",
                sql: concat!(
                    include_str!("../migrations/0010_remote_widening.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 9);
        assert_eq!(tables(&c), before);
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
