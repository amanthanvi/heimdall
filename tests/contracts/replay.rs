//! ⟨rev7⟩ The replay corpus (ADR-0013 §1.3; m07-plan U0): rows written by earlier exit builds
//! replay through revision 7's readers.
//!
//! `tests/contracts/golden/replay/<build>/` holds, for each exit build, one SQL text dump per
//! scratch home of a short fixed journey (`tests/contracts/replay_journey.py`) and a
//! `manifest.json` (the store's `user_version` and row counts per table, and every step with
//! its real exit code). `tests/contracts/golden/replay/hand/` holds hand-authored rows for the
//! historical shapes no journey produces, each a JSON document naming its table and columns.
//!
//! `stored_samples_replay_through_revision_7_readers` rebuilds every dump at its version,
//! opens it with `Store::open` (the backup, then every production migration to the current
//! schema), checks that the migration kept every row, and reads every stored operation,
//! idempotency record, decision and event back: through the store's own readers (an
//! idempotency record by its re-encoded key, which fails if the caller encoding ever
//! changes), then each event through revision 7's typed payloads (`EventPayload`). The
//! hand-authored rows are inserted into a migrated copy of the newest store and read the same
//! way.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::event::{Event, EventFilter};
use heimdall_contract::event_payload::EventPayload;
use heimdall_contract::ids::{DecisionId, EnvironmentId, OperationId, RequestId};
use heimdall_domain::idempotency::IdempotencyKey;
use heimdall_store::{NoFaults, Store};

fn corpus() -> PathBuf {
    heimdall_testkit::repo::repo_path("tests/contracts/golden/replay")
}

/// Rebuild a dump at its recorded version in a new file.
fn rebuild(dump: &str, user_version: u32, at: &Path) {
    let c = rusqlite::Connection::open(at).unwrap();
    // The dump creates tables in name order, so a child table's rows can precede its parent
    // table: foreign keys are checked by `Store::open`'s integrity pass, not while rebuilding.
    c.pragma_update(None, "foreign_keys", "OFF").unwrap();
    c.execute_batch(dump).unwrap();
    c.pragma_update(None, "user_version", user_version).unwrap();
}

/// Every row of `table`'s `columns`, as strings (NULL as `None`).
fn rows(c: &rusqlite::Connection, sql: &str) -> Vec<Vec<Option<String>>> {
    let mut stmt = c.prepare(sql).unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |r| {
        (0..n)
            .map(|i| r.get::<_, Option<String>>(i))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn counts(c: &rusqlite::Connection) -> BTreeMap<String, i64> {
    let tables: Vec<String> = rows(
        c,
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .into_iter()
    .map(|r| r[0].clone().unwrap())
    .collect();
    tables
        .into_iter()
        .map(|t| {
            let n: i64 = c
                .query_row(&format!("SELECT count(*) FROM \"{t}\""), [], |r| r.get(0))
                .unwrap();
            (t, n)
        })
        .collect()
}

/// Read every operation, idempotency record, decision and event of the store at `db`
/// (already migrated) through the store's readers and revision 7's decoders. Returns how many
/// of each it read.
fn read_back(db: &Path, label: &str) -> [usize; 4] {
    let raw = rusqlite::Connection::open(db).unwrap();
    let ops = rows(&raw, "SELECT id FROM operations ORDER BY id");
    let keys = rows(
        &raw,
        "SELECT caller_json, kind, request_id, operation_id FROM idempotency ORDER BY rowid",
    );
    let decisions = rows(&raw, "SELECT id FROM decisions ORDER BY id");
    let envs = rows(
        &raw,
        "SELECT DISTINCT environment FROM events ORDER BY environment",
    );
    let stored_events: i64 = raw
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    drop(raw);
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            for r in &ops {
                let id = OperationId::parse(r[0].as_deref().unwrap()).unwrap();
                assert!(tx.operation(&id)?.is_some(), "{label}: operation {id}");
            }
            for r in &keys {
                let key = IdempotencyKey {
                    caller: serde_json::from_str(r[0].as_deref().unwrap()).unwrap(),
                    kind: serde_json::from_value(serde_json::Value::String(r[1].clone().unwrap()))
                        .unwrap(),
                    request_id: RequestId::parse(r[2].as_deref().unwrap()).unwrap(),
                };
                let record = tx
                    .idempotency_record(&key)?
                    .unwrap_or_else(|| panic!("{label}: an idempotency key no longer matches"));
                assert_eq!(record.operation_id.as_str(), r[3].as_deref().unwrap());
            }
            for r in &decisions {
                let id = DecisionId::parse(r[0].as_deref().unwrap()).unwrap();
                assert!(tx.decision(&id)?.is_some(), "{label}: decision {id}");
            }
            let mut events = 0;
            for r in &envs {
                let env = EnvironmentId::parse(r[0].as_deref().unwrap()).unwrap();
                let page = tx.events_after(&env, 0, &EventFilter::default(), 100_000)?;
                for e in &page.events {
                    decode(e, label);
                }
                events += page.events.len();
            }
            assert_eq!(events as i64, stored_events, "{label}: every event is read");
            Ok(())
        })
        .unwrap();
    [
        ops.len(),
        keys.len(),
        decisions.len(),
        stored_events as usize,
    ]
}

fn decode(e: &Event, label: &str) {
    let typed = EventPayload::decode(e).unwrap_or_else(|err| {
        panic!(
            "{label}: a stored {:?} event does not read as revision 7's payload: {err}",
            e.event_type
        )
    });
    assert_eq!(typed.event_type(), e.event_type);
}

#[test]
fn stored_samples_replay_through_revision_7_readers() {
    let root = corpus();
    let mut builds: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("manifest.json").is_file())
        .collect();
    builds.sort();
    assert!(!builds.is_empty(), "no build in the replay corpus");
    let scratch = tempfile::tempdir().unwrap();
    let mut read = [0usize; 4];
    for build in &builds {
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(build.join("manifest.json")).unwrap())
                .unwrap();
        let name = build.file_name().unwrap().to_string_lossy().into_owned();
        for home in manifest["homes"].as_array().unwrap() {
            let h = home["home"].as_str().unwrap();
            let label = format!("{name}/{h}");
            let dump = std::fs::read_to_string(build.join(format!("{h}.sql"))).unwrap();
            let db = scratch.path().join(format!("{name}-{h}.db"));
            let version = u32::try_from(home["user_version"].as_u64().unwrap()).unwrap();
            rebuild(&dump, version, &db);
            let before = counts(&rusqlite::Connection::open(&db).unwrap());
            for (table, n) in home["rows"].as_object().unwrap() {
                assert_eq!(
                    before.get(table).copied(),
                    n.as_i64(),
                    "{label}: the dump rebuilds {table}"
                );
            }
            let got = read_back(&db, &label);
            let after = counts(&rusqlite::Connection::open(&db).unwrap());
            for (table, n) in &before {
                assert_eq!(
                    after.get(table),
                    Some(n),
                    "{label}: the migration kept {table}"
                );
            }
            for (sum, n) in read.iter_mut().zip(got) {
                *sum += n;
            }
        }
    }
    assert!(read.iter().all(|n| *n > 0), "the corpus read {read:?}");
    hand_authored(scratch.path());
}

/// The hand-authored rows: every historical event shape no journey writes, and an
/// idempotency marker (the 24-hour retention floor would purge a journey's own rows), inserted
/// into a store at the current schema and read back through the same readers.
fn hand_authored(scratch: &Path) {
    let hand = corpus().join("hand");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(hand.join("events.json")).unwrap()).unwrap();
    let db = scratch.join("hand.db");
    drop(Store::open(&db, Arc::new(NoFaults)).unwrap());
    let c = rusqlite::Connection::open(&db).unwrap();
    let events = doc["events"].as_array().unwrap();
    for row in events {
        let e: Event = serde_json::from_value(row["event"].clone())
            .unwrap_or_else(|err| panic!("{}: not an Event: {err}", row["shape"]));
        c.execute(
            "INSERT INTO events (event_id, environment, type, operation_id, timestamp, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                e.event_id.as_str(),
                e.environment_id.as_str(),
                row["event"]["type"].as_str().unwrap(),
                e.operation_id.as_ref().map(OperationId::as_str),
                row["event"]["timestamp"].as_str().unwrap(),
                serde_json::to_string(&row["event"]).unwrap(),
            ],
        )
        .unwrap();
    }
    let marker = heimdall_domain::idempotency::KeyHash(
        heimdall_contract::canonical::RequestHash::from_hex(&"ab".repeat(32)).unwrap(),
    );
    c.execute(
        "INSERT INTO idempotency_markers (key_hash, expired_at, marker_until)
         VALUES (?1, '2026-11-01T00:00:00.000000000Z', '2026-12-01T00:00:00.000000000Z')",
        [marker.0.to_hex()],
    )
    .unwrap();
    drop(c);
    let got = read_back(&db, "hand");
    assert_eq!(got[3], events.len(), "every hand-authored event is read");
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            assert!(
                tx.expired_key_marker(&marker)?.is_some(),
                "hand: the marker reads"
            );
            Ok(())
        })
        .unwrap();
}
