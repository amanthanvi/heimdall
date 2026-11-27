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
pub const SCHEMA_VERSION: u32 = 16;

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
    // ⟨M06⟩ Wave 3 (ADR-0006 §18.7 item 1): paired clients' Iroh endpoint IDs and the
    // invitation's `iroh_admission`.
    Migration {
        version: 11,
        name: "remote_client_endpoints",
        sql: include_str!("../migrations/0011_remote_client_endpoints.sql"),
    },
    // ⟨M06⟩ Wave 4 (ADR-0006 §18.8 item 4): the controller's lift acknowledgements.
    Migration {
        version: 12,
        name: "remote_lift_acks",
        sql: include_str!("../migrations/0012_remote_lift_acks.sql"),
    },
    // ⟨M06⟩ Wave 5 (ADR-0006 §18.9 item 8): the widening record's origin; a local record
    // has no client.
    Migration {
        version: 13,
        name: "local_widening",
        sql: include_str!("../migrations/0013_local_widening.sql"),
    },
    // ⟨rev7⟩ U0 (ADR-0014 H9, §3.6; U0-Q9): the restore epoch's columns, the request fences
    // and the case-insensitive alias index; no writer yet.
    Migration {
        version: 14,
        name: "restore_epoch",
        sql: include_str!("../migrations/0014_restore_epoch.sql"),
    },
    Migration {
        version: 15,
        name: "grant_live",
        sql: include_str!("../migrations/0015_grant_live.sql"),
    },
    // ⟨M08 W4 U2b-3a⟩ (ADR-0014 §3.6 step 4, ADR-0006 §7.4): the terminal records the request
    // ledger's trim and the restore read by the ledger's digest.
    Migration {
        version: 16,
        name: "request_terminals",
        sql: include_str!("../migrations/0016_request_terminals.sql"),
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
///
/// ⟨M08 U2b-1; ADR-0014 §3.6 adoption step 2⟩ A family fenced for adoption
/// ([`crate::layout::ADOPTION_FENCE`]) is [`StoreError::AdoptionFenced`] for this build's own
/// step list: it is never opened as a store again. A shorter step list models a build that
/// predates generations (`Store::open_at_schema_version`), which knows no fence and answers
/// [`StoreError::NewerSchema`], as such a build does.
pub(crate) fn check_version(conn: &Connection, steps: &[Migration]) -> Result<u32> {
    let current = user_version(conn)?;
    let supported = target_version(steps);
    if current == crate::layout::ADOPTION_FENCE && steps.len() == MIGRATIONS.len() {
        return Err(StoreError::AdoptionFenced);
    }
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
        assert_eq!(
            apply_steps(&mut c, &NoFaults, &MIGRATIONS[..10]).unwrap(),
            10
        );
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

    /// ⟨M06⟩ Wave 3 (ADR-0006 §18.7 item 1): `0011_remote_client_endpoints` applies on a
    /// database at version 10, adds exactly its table and the invitation column (existing
    /// invitations admit no Iroh), keeping every row; a failure inside the step leaves
    /// version 10, no table and no column.
    #[test]
    fn remote_client_endpoints_step_applies_on_version_10_and_rolls_back_whole() {
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
        let columns = |c: &Connection| -> Vec<String> {
            let mut stmt = c
                .prepare("SELECT name FROM pragma_table_info('remote_invitations') ORDER BY cid")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        let previous = &MIGRATIONS[..10];
        assert_eq!(MIGRATIONS[10].version, 11);
        assert_eq!(MIGRATIONS[10].name, "remote_client_endpoints");
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 10);
        let before = tables(&c);
        let before_columns = columns(&c);
        c.execute_batch(
            "INSERT INTO remote_invitations (invitation_id, client_id, role, key_fingerprint,
                 generation, created_wall, created_boot_id, created_elapsed_ms, expires_wall,
                 elapsed_bound_ms, state, record_json)
             VALUES ('inv_probe', 'cl_probe', 'owner', 'SHA256:x', 0, 't', 'b', 0, 't', 0,
                 'pending', '{}')",
        )
        .unwrap();
        assert_eq!(
            apply_steps(&mut c, &NoFaults, &MIGRATIONS[..11]).unwrap(),
            11
        );
        let added: Vec<String> = tables(&c)
            .into_iter()
            .filter(|t| !before.contains(t))
            .collect();
        assert_eq!(added, vec!["remote_client_endpoints".to_owned()]);
        let new_columns: Vec<String> = columns(&c)
            .into_iter()
            .filter(|col| !before_columns.contains(col))
            .collect();
        assert_eq!(new_columns, vec!["iroh_admission".to_owned()]);
        let admission: i64 = c
            .query_row(
                "SELECT iroh_admission FROM remote_invitations WHERE invitation_id = 'inv_probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(admission, 0, "an existing invitation admits no Iroh");
        let broken = [
            previous.to_vec(),
            vec![Migration {
                version: 11,
                name: "remote_client_endpoints_broken",
                sql: concat!(
                    include_str!("../migrations/0011_remote_client_endpoints.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 10);
        assert_eq!(tables(&c), before);
        assert_eq!(columns(&c), before_columns);
    }

    /// ⟨M06⟩ Wave 4 (ADR-0006 §18.8 item 4): `0012_remote_lift_acks` applies on a database
    /// at version 11, adds exactly its table, keeping every row; a failure inside the step
    /// leaves version 11 and no table.
    #[test]
    fn remote_lift_acks_step_applies_on_version_11_and_rolls_back_whole() {
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
        let previous = &MIGRATIONS[..11];
        assert_eq!(MIGRATIONS[11].version, 12);
        assert_eq!(MIGRATIONS[11].name, "remote_lift_acks");
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 11);
        let before = tables(&c);
        c.execute_batch("INSERT INTO meta (key, value) VALUES ('m06-w4-probe', 'kept')")
            .unwrap();
        assert_eq!(
            apply_steps(&mut c, &NoFaults, &MIGRATIONS[..12]).unwrap(),
            12
        );
        let added: Vec<String> = tables(&c)
            .into_iter()
            .filter(|t| !before.contains(t))
            .collect();
        assert_eq!(added, vec!["remote_lift_acks".to_owned()]);
        let kept: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'm06-w4-probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, "kept");
        let broken = [
            previous.to_vec(),
            vec![Migration {
                version: 12,
                name: "remote_lift_acks_broken",
                sql: concat!(
                    include_str!("../migrations/0012_remote_lift_acks.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 11);
        assert_eq!(tables(&c), before);
    }

    /// ⟨M06⟩ Wave 5 (ADR-0006 §18.9 item 8): `0013_local_widening` applies on a database at
    /// version 12, adds no table, keeps every `remote_widening` row as a `paired` one, and
    /// its CHECK constraint ties the client and the delta digest to the origin in both
    /// directions; a failure inside the step leaves version 12 and the old table.
    #[test]
    fn local_widening_step_keeps_paired_rows_and_constrains_the_origin() {
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
        let columns = |c: &Connection| -> Vec<String> {
            let mut stmt = c
                .prepare("SELECT name FROM pragma_table_info('remote_widening') ORDER BY cid")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        const SEED: &str = "
            INSERT INTO decisions (id, kind_json, state, generation, created_at, expires_at,
                record_json)
            VALUES ('dec_probe', '{}', 'pending', 0, 't', 't', '{}');
            INSERT INTO remote_widening (decision_id, client_id, request_kind, request_id,
                request_hash, result_json)
            VALUES ('dec_probe', 'cl_probe', 'transport.enable', 'req_probe', 'aa', NULL);";
        let previous = &MIGRATIONS[..12];
        assert_eq!(MIGRATIONS[12].version, 13);
        assert_eq!(MIGRATIONS[12].name, "local_widening");
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 12);
        let before = tables(&c);
        let before_columns = columns(&c);
        c.execute_batch(SEED).unwrap();
        assert_eq!(
            apply_steps(&mut c, &NoFaults, &MIGRATIONS[..13]).unwrap(),
            13
        );
        assert_eq!(tables(&c), before, "the step adds and drops no table");
        let new_columns: Vec<String> = columns(&c)
            .into_iter()
            .filter(|col| !before_columns.contains(col))
            .collect();
        assert_eq!(
            new_columns,
            vec!["origin".to_owned(), "delta_digest".to_owned()]
        );
        let kept: (
            String,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
        ) = c
            .query_row(
                "SELECT origin, client_id, request_kind, request_id, request_hash, delta_digest
                 FROM remote_widening WHERE decision_id = 'dec_probe'",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            kept,
            (
                "paired".to_owned(),
                Some("cl_probe".to_owned()),
                "transport.enable".to_owned(),
                "req_probe".to_owned(),
                "aa".to_owned(),
                None
            )
        );
        // The constraint: (origin, client, digest) -> accepted?
        let cases: [(&str, Option<&str>, Option<&str>, bool); 7] = [
            ("local", None, Some("d1"), true),
            ("paired", Some("cl_other"), None, true),
            ("local", Some("cl_other2"), Some("d2"), false),
            ("local", None, None, false),
            ("paired", None, None, false),
            ("paired", Some("cl_other3"), Some("d3"), false),
            ("owner", None, Some("d4"), false),
        ];
        for (n, (origin, client, digest, accepted)) in cases.into_iter().enumerate() {
            let id = format!("dec_case{n}");
            c.execute(
                "INSERT INTO decisions (id, kind_json, state, generation, created_at,
                     expires_at, record_json) VALUES (?1, '{}', 'pending', 0, 't', 't', '{}')",
                [&id],
            )
            .unwrap();
            let inserted = c.execute(
                "INSERT INTO remote_widening (decision_id, origin, client_id, request_kind,
                     request_id, request_hash, delta_digest)
                 VALUES (?1, ?2, ?3, 'transport.enable', ?1, 'aa', ?4)",
                rusqlite::params![id, origin, client, digest],
            );
            assert_eq!(
                inserted.is_ok(),
                accepted,
                "origin {origin}, client {client:?}, digest {digest:?}"
            );
        }
        let broken = [
            previous.to_vec(),
            vec![Migration {
                version: 13,
                name: "local_widening_broken",
                sql: concat!(
                    include_str!("../migrations/0013_local_widening.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 12);
        c.execute_batch(SEED).unwrap();
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 12);
        assert_eq!(tables(&c), before);
        assert_eq!(columns(&c), before_columns);
        let rows: i64 = c
            .query_row("SELECT count(*) FROM remote_widening", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the old table and its row are intact");
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

    /// ⟨rev7⟩ U0 (ADR-0014 H9; U0-Q9): `0014_restore_epoch` applies on a database at version
    /// 13 holding one seeded row in each of the four tables it alters, and keeps them: the
    /// operation keeps its ID, kind, state, code and record, the idempotency record its key
    /// and operation, the decision its ID, kind, state, generation and record, and the outbox
    /// row every column (review U0-RC06); each reads epoch 0. Every `meta` row is kept and
    /// `restore_epoch` = `0` is the only one added; the step adds exactly the `request_fences`
    /// table and the two indexes. The alias index is not unique, so an existing case-variant
    /// pair survives the step. A failure inside the step leaves version 13 and nothing of it.
    #[test]
    fn restore_epoch_step_keeps_the_seeded_rows_at_epoch_zero_and_rolls_back_whole() {
        let names = |c: &Connection, kind: &str| -> Vec<String> {
            let mut stmt = c
                .prepare(
                    "SELECT name FROM sqlite_schema WHERE type = ?1
                     AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name",
                )
                .unwrap();
            stmt.query_map([kind], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        const SEED: &str = "
            INSERT INTO operations (id, kind, environment, caller_json, request_id,
                request_hash, effect_class, state, code, effect_status, result_json,
                record_json, created_at, updated_at, terminal_at)
            VALUES ('op_probe', 'ensure', 'env_probe', '{}', 'req_probe', 'aa', 'local',
                'succeeded', 'ACCESS_READY', 'applied', NULL, '{}', 't', 't', 't');
            INSERT INTO idempotency (caller_json, kind, request_id, request_hash,
                operation_id, created_at, expires_at)
            VALUES ('{}', 'ensure', 'req_probe', 'aa', 'op_probe', 't', NULL);
            INSERT INTO decisions (id, kind_json, state, generation, created_at, expires_at,
                record_json)
            VALUES ('dec_probe', '{}', 'pending', 0, 't', 't', '{}');
            INSERT INTO destinations (id, alias, revision, record_json)
            VALUES ('d1', 'Alpha', 1, '{}'), ('d2', 'alpha', 1, '{}');";
        // The seeded rows of the four altered tables (the columns named; every column of the
        // outbox but the new one) and every `meta` row, before and after the step.
        let content = |c: &Connection| -> Vec<String> {
            let mut out = Vec::new();
            for (table, cols) in [
                ("operations", "id, kind, state, code, record_json"),
                (
                    "idempotency",
                    "caller_json, kind, request_id, request_hash, operation_id",
                ),
                ("decisions", "id, kind_json, state, generation, record_json"),
                ("remote_effect_outbox", "*"),
                ("meta", "key, value"),
            ] {
                let cols = if cols == "*" {
                    let mut st = c
                        .prepare(&format!(
                            "SELECT group_concat(name, ', ') FROM pragma_table_info('{table}')
                             WHERE name <> 'restore_epoch'"
                        ))
                        .unwrap();
                    st.query_row([], |r| r.get::<_, String>(0)).unwrap()
                } else {
                    cols.to_owned()
                };
                let mut st = c
                    .prepare(&format!("SELECT {cols} FROM {table} ORDER BY 1"))
                    .unwrap();
                let n = st.column_count();
                let rows = st
                    .query_map([], |r| {
                        (0..n)
                            .map(|i| {
                                r.get::<_, rusqlite::types::Value>(i)
                                    .map(|v| format!("{v:?}"))
                            })
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                out.extend(
                    rows.into_iter()
                        .map(|r| format!("{table}: {}", r.join(" | "))),
                );
            }
            out
        };
        let previous = &MIGRATIONS[..13];
        assert_eq!(MIGRATIONS[13].version, 14);
        assert_eq!(MIGRATIONS[13].name, "restore_epoch");
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 13);
        let tables = names(&c, "table");
        let indexes = names(&c, "index");
        c.execute_batch(SEED).unwrap();
        let outbox_cols: Vec<(String, String)> = {
            let mut st = c
                .prepare(
                    "SELECT name, type FROM pragma_table_info('remote_effect_outbox') ORDER BY cid",
                )
                .unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        // One outbox row with every NOT NULL column filled (the table is one of the four).
        let outbox_names: Vec<&str> = outbox_cols.iter().map(|(n, _)| n.as_str()).collect();
        let values: Vec<String> = outbox_cols
            .iter()
            .map(|(n, t)| {
                if t == "INTEGER" {
                    "1".to_owned()
                } else {
                    format!("'{n}-probe'")
                }
            })
            .collect();
        c.execute_batch(&format!(
            "INSERT INTO remote_effect_outbox ({}) VALUES ({});",
            outbox_names.join(", "),
            values.join(", ")
        ))
        .unwrap();
        let before_content = content(&c);
        assert_eq!(
            apply_steps(&mut c, &NoFaults, &MIGRATIONS[..14]).unwrap(),
            14
        );
        let mut after_content = content(&c);
        after_content.retain(|r| r != "meta: Text(\"restore_epoch\") | Text(\"0\")");
        assert_eq!(
            after_content, before_content,
            "the seeded rows and meta kept"
        );
        let added: Vec<String> = names(&c, "table")
            .into_iter()
            .filter(|t| !tables.contains(t))
            .collect();
        assert_eq!(added, ["request_fences"]);
        let added: Vec<String> = names(&c, "index")
            .into_iter()
            .filter(|t| !indexes.contains(t))
            .collect();
        assert_eq!(
            added,
            ["destinations_alias_nocase", "request_fences_expires_at"]
        );
        let epochs: (i64, i64, i64, i64, String) = c
            .query_row(
                "SELECT (SELECT restore_epoch FROM operations WHERE id = 'op_probe'),
                        (SELECT request_epoch FROM idempotency WHERE request_id = 'req_probe'),
                        (SELECT restore_epoch FROM decisions WHERE id = 'dec_probe'),
                        (SELECT restore_epoch FROM remote_effect_outbox),
                        (SELECT value FROM meta WHERE key = 'restore_epoch')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(epochs, (0, 0, 0, 0, "0".to_owned()));
        let pair: i64 = c
            .query_row(
                "SELECT count(*) FROM destinations WHERE alias = 'ALPHA' COLLATE NOCASE",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pair, 2, "a legacy case-variant pair is kept");

        let broken: Vec<Migration> = [
            previous,
            &[Migration {
                version: 14,
                name: "restore_epoch_broken",
                sql: concat!(
                    include_str!("../migrations/0014_restore_epoch.sql"),
                    "\nTHIS IS NOT SQL;"
                ),
            }],
        ]
        .concat();
        let mut c = Connection::open_in_memory().unwrap();
        assert_eq!(apply_steps(&mut c, &NoFaults, previous).unwrap(), 13);
        assert!(apply_steps(&mut c, &NoFaults, &broken).is_err());
        assert_eq!(user_version(&c).unwrap(), 13);
        assert_eq!(names(&c, "table"), tables);
        assert_eq!(names(&c, "index"), indexes);
    }
}
