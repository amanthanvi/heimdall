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
//! schema), checks that the migration kept every row, and then reads every row of every table
//! of the migrated schema back through its reader (review U0-RC02): the store's own public
//! readers (`read_tables`; an idempotency record by its re-encoded key, which fails if the
//! caller encoding ever changes), each event also through revision 7's typed payloads
//! (`EventPayload`), each controller pin through revision 7's `RemoteEnvironmentPin`, and each
//! `meta` row through the reader of its key (`read_meta`). For every table the rows read must
//! equal the rows stored, so a reader that skips or refuses a row fails, naming the store and
//! the table. A table or `meta` key with no reader an integration test can reach is listed in
//! [`NOT_READ`] or [`META_NOT_READ`] (and the corpus README's "Stored, not read"); a table of
//! the migrated schema in neither set, or a `META_RECOVERY` key class in neither set, fails the
//! test. The hand-authored rows are inserted into a migrated copy of the newest store and read
//! the same way.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::canonical::RequestHash;
use heimdall_contract::controller_record::RemoteEnvironmentPin;
use heimdall_contract::event::{Event, EventFilter};
use heimdall_contract::event_payload::EventPayload;
use heimdall_contract::ids::{
    AccountName, BindingId, ClientId, CredentialInstanceId, DecisionId, DestinationId,
    EnrollmentId, EnvironmentId, ForeignRemovalId, GrantId, IdentityId, InvitationId, IssuanceId,
    OperationId, PolicyId, ProfileId, RequestId, ResourceId, WorkId, WorkspaceId,
};
use heimdall_contract::request::AccessPairRef;
use heimdall_domain::idempotency::{IdempotencyKey, KeyHash};
use heimdall_domain::policy::PolicyRevision;
use heimdall_store::ext_effects::EffectAck;
use heimdall_store::ext_m03::META_RECOVERY;
use heimdall_store::{NoFaults, Store, Txn};

/// Tables of the migrated schema with no reader an integration test can reach: neither a
/// public reader of the store nor a revision 7 typed reader. Listed, with the same reason, in
/// the corpus README's "Stored, not read". ⟨M08 U2b-2⟩ None: `request_fences` has its reader
/// (`Txn::request_fence`).
const NOT_READ: &[(&str, &str)] = &[];

/// `meta` key classes (as `META_RECOVERY` names them: an exact key, or a prefix ending in `:`)
/// with no reader an integration test can reach. Listed in the corpus README too.
const META_NOT_READ: &[(&str, &str)] = &[
    (
        "remote_revocation_claim_seq",
        "no reader: only `next_remote_claim_seq`, which reads it to advance it (a writer)",
    ),
    (
        "cleanup_intent_version",
        "no reader: only `record_cleanup_intent`, which reads it to advance it (a writer)",
    ),
];

/// Per table, the key columns (as text) its reader is called with: one row per stored row,
/// or (`DISTINCT`) one per group for a reader that returns a group. A table whose reader lists
/// every row needs no keys.
const KEYS: &[(&str, &str)] = &[
    ("operations", "SELECT id FROM operations"),
    (
        "idempotency",
        "SELECT caller_json, kind, request_id, operation_id FROM idempotency",
    ),
    ("decisions", "SELECT id FROM decisions"),
    ("events", "SELECT DISTINCT environment FROM events"),
    ("meta", "SELECT key, value FROM meta"),
    ("environments", "SELECT id FROM environments"),
    ("grants", "SELECT id FROM grants"),
    (
        "grant_references",
        "SELECT DISTINCT grant_id FROM grant_references",
    ),
    ("bindings", "SELECT id FROM bindings"),
    ("resources", "SELECT id FROM resources"),
    (
        "idempotency_markers",
        "SELECT key_hash FROM idempotency_markers",
    ),
    // ⟨M08 U2b-2⟩ The replay fence (ADR-0014 §3.6 step 4).
    ("request_fences", "SELECT key_digest FROM request_fences"),
    (
        "profile_snapshots",
        "SELECT profile, CAST(revision AS TEXT) FROM profile_snapshots",
    ),
    ("grant_anchors", "SELECT grant_id FROM grant_anchors"),
    (
        "recovery_intents",
        "SELECT operation_id FROM recovery_intents",
    ),
    (
        "stage_receipts",
        "SELECT DISTINCT operation_id FROM stage_receipts",
    ),
    ("issuance_log", "SELECT id FROM issuance_log"),
    (
        "credential_instances",
        "SELECT id FROM credential_instances",
    ),
    (
        "interaction_declarations",
        "SELECT identity FROM interaction_declarations",
    ),
    (
        "grant_prepared_facts",
        "SELECT grant_id FROM grant_prepared_facts",
    ),
    (
        "projection_consent",
        "SELECT DISTINCT environment FROM projection_consent",
    ),
    (
        "projection_records",
        "SELECT environment FROM projection_records",
    ),
    ("enrollments", "SELECT id FROM enrollments"),
    ("foreign_removals", "SELECT id FROM foreign_removals"),
    (
        "verification_issuance",
        "SELECT id FROM verification_issuance",
    ),
    (
        "pair_preferences",
        "SELECT destination_id, account FROM pair_preferences",
    ),
    (
        "managed_slots",
        "SELECT environment_id, destination_id, account, CAST(generation AS TEXT)
         FROM managed_slots",
    ),
    ("workspaces", "SELECT id FROM workspaces"),
    (
        "policy_history",
        "SELECT policy_id, CAST(revision AS TEXT) FROM policy_history",
    ),
    ("decision_cooldowns", "SELECT key FROM decision_cooldowns"),
    ("work_stops", "SELECT environment, work_id FROM work_stops"),
    (
        "slot_references",
        "SELECT DISTINCT environment_id, destination_id, account FROM slot_references",
    ),
    (
        "remote_invitations",
        "SELECT invitation_id FROM remote_invitations",
    ),
    (
        "remote_effect_acks",
        "SELECT ack_json FROM remote_effect_acks",
    ),
    (
        "remote_authority_generation",
        "SELECT CAST(id AS TEXT), CAST(generation AS TEXT) FROM remote_authority_generation",
    ),
    ("remote_widening", "SELECT decision_id FROM remote_widening"),
    (
        "remote_client_endpoints",
        "SELECT client_id FROM remote_client_endpoints",
    ),
];

type Row = Vec<Option<String>>;

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

/// Every row of a text query, as strings (NULL as `None`).
fn rows(c: &rusqlite::Connection, sql: &str) -> Vec<Row> {
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

/// Column `i` of a key row (a NOT NULL key column).
fn col(r: &[Option<String>], i: usize) -> &str {
    r[i].as_deref().unwrap()
}

/// A reader's result, or a failure naming the store and the table.
fn ok<T>(r: heimdall_store::Result<T>, label: &str, table: &str) -> T {
    r.unwrap_or_else(|e| panic!("{label}: {table}: a stored row does not read: {e}"))
}

/// A stored key as its typed ID, or a failure naming the store and the table.
fn id<T, E: std::fmt::Debug>(r: Result<T, E>, label: &str, table: &str) -> T {
    r.unwrap_or_else(|e| panic!("{label}: {table}: a stored key does not parse: {e:?}"))
}

/// What [`read_back`] read: rows per table (every table it reads, populated or not), and the
/// `meta` rows of a key class in [`META_NOT_READ`].
struct Read {
    rows: BTreeMap<&'static str, usize>,
    meta_not_read: usize,
}

/// Migrate the store at `db` (`Store::open`), then read every row of every table back through
/// its reader. Returns how many rows of each table it read.
fn read_back(db: &Path, label: &str) -> Read {
    drop(Store::open(db, Arc::new(NoFaults)).unwrap());
    let raw = rusqlite::Connection::open(db).unwrap();
    let keys: BTreeMap<&str, Vec<Row>> = KEYS
        .iter()
        .map(|(table, sql)| (*table, rows(&raw, sql)))
        .collect();
    drop(raw);
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| Ok(read_tables(tx, &keys, label)))
        .unwrap()
}

/// Every table's rows through the store's public readers (and revision 7's typed readers where
/// the store returns a document as text).
fn read_tables(tx: &mut Txn<'_>, keys: &BTreeMap<&str, Vec<Row>>, label: &str) -> Read {
    let k = |t: &str| keys.get(t).map_or(&[][..], Vec::as_slice);
    let mut n: BTreeMap<&'static str, usize> = BTreeMap::new();

    // ⟨M01⟩ The journal, idempotency, decisions and the event log.
    let t = "operations";
    let got = k(t).iter().filter(|r| {
        let op = id(OperationId::parse(col(r, 0)), label, t);
        ok(tx.operation(&op), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "idempotency";
    let got = k(t).iter().filter(|r| {
        let key = IdempotencyKey {
            caller: serde_json::from_str(col(r, 0)).unwrap(),
            kind: serde_json::from_value(serde_json::Value::String(col(r, 1).to_owned())).unwrap(),
            request_id: id(RequestId::parse(col(r, 2)), label, t),
        };
        ok(tx.idempotency_record(&key), label, t)
            .is_some_and(|record| record.operation_id.as_str() == col(r, 3))
    });
    n.insert(t, got.count());
    let t = "decisions";
    let got = k(t).iter().filter(|r| {
        let d = id(DecisionId::parse(col(r, 0)), label, t);
        ok(tx.decision(&d), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "events";
    let mut events = 0;
    for r in k(t) {
        let env = id(EnvironmentId::parse(col(r, 0)), label, t);
        let page = ok(
            tx.events_after(&env, 0, &EventFilter::default(), 100_000),
            label,
            t,
        );
        for e in &page.events {
            decode(e, label);
        }
        events += page.events.len();
    }
    n.insert(t, events);
    let (read, not_read) = read_meta(tx, k("meta"), label);
    n.insert("meta", read);

    // ⟨M01/M02⟩ Catalog, grants, bindings and their records.
    n.insert("policies", ok(tx.policies(), label, "policies").len());
    n.insert("profiles", ok(tx.profiles(), label, "profiles").len());
    let t = "profile_snapshots";
    let got = k(t).iter().filter(|r| {
        let p = id(ProfileId::parse(col(r, 0)), label, t);
        let revision: u64 = col(r, 1).parse().unwrap();
        ok(tx.profile_snapshot(&p, revision), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "environments";
    let got = k(t).iter().filter(|r| {
        let env = id(EnvironmentId::parse(col(r, 0)), label, t);
        ok(tx.environment(&env), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "grants";
    let got = k(t).iter().filter(|r| {
        let g = id(GrantId::parse(col(r, 0)), label, t);
        // The grant's other documents: its approval basis and origin (NULL on older rows).
        ok(tx.grant_approval(&g), label, t);
        ok(tx.grant_origin(&g), label, t);
        ok(tx.grant(&g), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "grant_references";
    let got: usize = k(t)
        .iter()
        .map(|r| {
            let g = id(GrantId::parse(col(r, 0)), label, t);
            ok(tx.grant_references(&g), label, t).len()
        })
        .sum();
    n.insert(t, got);
    let t = "bindings";
    let got = k(t).iter().filter(|r| {
        let b = id(BindingId::parse(col(r, 0)), label, t);
        // The binding's context document (migration 0008; NULL on older rows).
        ok(tx.binding_context(&b), label, t);
        ok(tx.binding(&b), label, t).is_some()
    });
    n.insert(t, got.count());
    n.insert("tombstones", ok(tx.tombstones(), label, "tombstones").len());
    let t = "resources";
    let got = k(t).iter().filter(|r| {
        let res = id(ResourceId::parse(col(r, 0)), label, t);
        ok(tx.resource(&res), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "idempotency_markers";
    let got = k(t).iter().filter(|r| {
        let hash = KeyHash(id(RequestHash::from_hex(col(r, 0)), label, t));
        ok(tx.expired_key_marker(&hash), label, t).is_some()
    });
    n.insert(t, got.count());
    // ⟨M08 U2b-2⟩ The replay fence: every stored record by its key's digest.
    let t = "request_fences";
    let got = k(t).iter().filter(|r| {
        let digest = id(RequestHash::from_hex(col(r, 0)), label, t).0;
        ok(tx.request_fence(&digest), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "grant_anchors";
    let got = k(t).iter().filter(|r| {
        let g = id(GrantId::parse(col(r, 0)), label, t);
        ok(tx.grant_anchor(&g), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "recovery_intents";
    let got = k(t).iter().filter(|r| {
        let op = id(OperationId::parse(col(r, 0)), label, t);
        ok(tx.recovery_intent(&op), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "stage_receipts";
    let got: usize = k(t)
        .iter()
        .map(|r| {
            let op = id(OperationId::parse(col(r, 0)), label, t);
            ok(tx.stage_receipts(&op), label, t).len()
        })
        .sum();
    n.insert(t, got);
    let t = "issuance_log";
    let got = k(t).iter().filter(|r| {
        let i = id(IssuanceId::parse(col(r, 0)), label, t);
        ok(tx.issuance_entry(&i), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "credential_instances";
    let got = k(t).iter().filter(|r| {
        let c = id(CredentialInstanceId::parse(col(r, 0)), label, t);
        ok(tx.credential_instance(&c), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "destinations";
    n.insert(t, ok(tx.destinations(), label, t).len());
    let t = "identities";
    n.insert(t, ok(tx.identities(), label, t).len());
    let t = "interaction_declarations";
    let got = k(t).iter().filter(|r| {
        let i = id(IdentityId::parse(col(r, 0)), label, t);
        ok(tx.interaction_declaration(&i), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "binding_holders";
    n.insert(t, ok(tx.binding_holders(), label, t).len());
    let t = "grant_prepared_facts";
    let got = k(t).iter().filter(|r| {
        let g = id(GrantId::parse(col(r, 0)), label, t);
        ok(tx.grant_prepared_facts(&g), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "projection_consent";
    let got: usize = k(t)
        .iter()
        .map(|r| {
            let env = id(EnvironmentId::parse(col(r, 0)), label, t);
            ok(tx.get_projection_consent(&env), label, t).items.len()
        })
        .sum();
    n.insert(t, got);
    let t = "projection_records";
    let got = k(t).iter().filter(|r| {
        let env = id(EnvironmentId::parse(col(r, 0)), label, t);
        ok(tx.projection_record(&env), label, t).is_some()
    });
    n.insert(t, got.count());

    // ⟨M03⟩ Managed credentials.
    let t = "issuers";
    n.insert(t, ok(tx.issuers(), label, t).len());
    let t = "enrollments";
    let got = k(t).iter().filter(|r| {
        let e = id(EnrollmentId::parse(col(r, 0)), label, t);
        ok(tx.enrollment(&e), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "foreign_removals";
    let got = k(t).iter().filter(|r| {
        let f = id(ForeignRemovalId::parse(col(r, 0)), label, t);
        ok(tx.foreign_removal(&f), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "verification_issuance";
    let got = k(t).iter().filter(|r| {
        let i = id(IssuanceId::parse(col(r, 0)), label, t);
        ok(tx.verification_entry(&i), label, t).is_some()
    });
    n.insert(t, got.count());
    let pair = |r: &[Option<String>], at: usize, t: &str| AccessPairRef {
        destination: id(DestinationId::parse(col(r, at)), label, t),
        account: id(AccountName::parse(col(r, at + 1)), label, t),
    };
    let t = "pair_preferences";
    let got = k(t)
        .iter()
        .filter(|r| ok(tx.pair_preference(&pair(r, 0, t)), label, t).is_some());
    n.insert(t, got.count());
    let t = "managed_slots";
    let got = k(t).iter().filter(|r| {
        let env = id(EnvironmentId::parse(col(r, 0)), label, t);
        let generation: u64 = col(r, 3).parse().unwrap();
        // `slot` reads a missing row as free at generation 0: the stored generation tells
        // the row apart.
        ok(tx.slot(&env, &pair(r, 1, t)), label, t).generation() == generation
    });
    n.insert(t, got.count());
    let t = "owned_connections";
    n.insert(t, ok(tx.owned_connections(), label, t).len());

    // ⟨M04/M05⟩ Platform environments and trusted work.
    let t = "managed_environments";
    n.insert(t, ok(tx.managed_environments(), label, t).len());
    let t = "wsl_distributions";
    n.insert(t, ok(tx.wsl_distributions(), label, t).len());
    let t = "workspaces";
    let got = k(t).iter().filter(|r| {
        let w = id(WorkspaceId::parse(col(r, 0)), label, t);
        ok(tx.workspace(&w), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "policy_history";
    let got = k(t).iter().filter(|r| {
        let p = id(PolicyId::parse(col(r, 0)), label, t);
        let revision = PolicyRevision(col(r, 1).parse().unwrap());
        ok(tx.policy_history_entry(&p, revision), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "decision_cooldowns";
    let got = k(t)
        .iter()
        .filter(|r| ok(tx.decision_cooldown(col(r, 0)), label, t).is_some());
    n.insert(t, got.count());
    let t = "work_stops";
    let got = k(t).iter().filter(|r| {
        let env = id(EnvironmentId::parse(col(r, 0)), label, t);
        let work = id(WorkId::parse(col(r, 1)), label, t);
        ok(tx.work_stop(&env, &work), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "slot_references";
    let got: usize = k(t)
        .iter()
        .map(|r| {
            let env = id(EnvironmentId::parse(col(r, 0)), label, t);
            let p = pair(r, 1, t);
            ok(
                tx.slot_references(&env, &p.destination, &p.account),
                label,
                t,
            )
            .len()
        })
        .sum();
    n.insert(t, got);

    // ⟨M06⟩ Remote runners, effects, routes and transport.
    let t = "remote_clients";
    n.insert(t, ok(tx.remote_clients(), label, t).len());
    let t = "remote_invitations";
    let got = k(t).iter().filter(|r| {
        let i = id(InvitationId::parse(col(r, 0)), label, t);
        ok(tx.remote_invitation(&i), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "remote_effect_outbox";
    let outbox = ok(tx.remote_effect_outbox(None, false), label, t);
    n.insert(t, outbox.len());
    // A lift acknowledgement is written only for an outbox effect and dropped with it, so the
    // outbox's keys find every one.
    let t = "remote_lift_acks";
    let got = outbox
        .iter()
        .filter(|e| ok(tx.remote_lift_ack(&e.key), label, t).is_some());
    n.insert(t, got.count());
    // The runner's acknowledgement carries its own key: looked up by it, the row must read
    // back as the same acknowledgement (which fails if the key's columns ever change).
    let t = "remote_effect_acks";
    let got = k(t).iter().filter(|r| {
        let ack: EffectAck = serde_json::from_str(col(r, 0))
            .unwrap_or_else(|e| panic!("{label}: {t}: a stored row does not read: {e}"));
        ok(tx.remote_effect_ack(&ack.key), label, t).as_ref() == Some(&ack)
    });
    n.insert(t, got.count());
    let t = "remote_policy_revisions";
    n.insert(t, ok(tx.remote_policy_revisions(), label, t).len());
    // The store returns a pin's record as text; revision 7's `RemoteEnvironmentPin` reads it.
    let t = "remote_environment_pins";
    let got = ok(tx.remote_environment_pins(), label, t)
        .into_iter()
        .filter(|(env, json)| {
            let pin: RemoteEnvironmentPin = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("{label}: {t}: a stored row does not read: {e}"));
            pin.environment == *env
        });
    n.insert(t, got.count());
    let t = "remote_grant_issuers";
    n.insert(t, ok(tx.remote_grant_issuers(), label, t).len());
    let t = "destination_routes";
    let got = ok(tx.all_destination_routes(), label, t);
    n.insert(t, got.values().map(Vec::len).sum());
    let t = "route_consents";
    n.insert(t, ok(tx.all_route_consents(), label, t).len());
    let t = "remote_authority_generation";
    let got = k(t).iter().filter(|r| {
        col(r, 0) == "1" && ok(tx.remote_authority_generation(), label, t).to_string() == col(r, 1)
    });
    n.insert(t, got.count());
    let t = "transport_keys";
    n.insert(t, ok(tx.transport_keys(), label, t).len());
    let t = "remote_widening";
    let got = k(t).iter().filter(|r| {
        let d = id(DecisionId::parse(col(r, 0)), label, t);
        ok(tx.remote_widening(&d), label, t).is_some()
    });
    n.insert(t, got.count());
    let t = "remote_client_endpoints";
    let got = k(t).iter().filter(|r| {
        let c = id(ClientId::parse(col(r, 0)), label, t);
        ok(tx.remote_client_endpoint(&c), label, t).is_some()
    });
    n.insert(t, got.count());

    Read {
        rows: n,
        meta_not_read: not_read,
    }
}

/// Every `meta` row through the reader of its key class (`META_RECOVERY` lists every key the
/// store writes): `(rows read, rows of a class in META_NOT_READ)`. A key the store does not
/// list, or a listed class with neither a reader here nor a `META_NOT_READ` entry, fails.
fn read_meta(tx: &mut Txn<'_>, rows: &[Row], label: &str) -> (usize, usize) {
    let t = "meta";
    let mut by_class: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for r in rows {
        let key = col(r, 0);
        let class = META_RECOVERY
            .iter()
            .map(|(class, _)| *class)
            .find(|c| {
                if c.ends_with(':') {
                    key.starts_with(c)
                } else {
                    key == *c
                }
            })
            .unwrap_or_else(|| panic!("{label}: meta: the key {key} is not in META_RECOVERY"));
        by_class.entry(class).or_default().push((key, col(r, 1)));
    }
    let (mut read, mut not_read) = (0, 0);
    for (class, _) in META_RECOVERY {
        let stored = by_class.get(class).map_or(&[][..], Vec::as_slice);
        if META_NOT_READ.iter().any(|(c, _)| c == class) {
            not_read += stored.len();
            continue;
        }
        // A prefix class whose reader lists every row of the prefix.
        let listed = match *class {
            "remote_revocation:" => Some(ok(tx.remote_revocations(), label, t).len()),
            "cleanup_intent:" => Some(ok(tx.cleanup_intents(), label, t).len()),
            "runner_issuer_trust:" => Some(ok(tx.remote_issuer_trust(), label, t).len()),
            "remote_delivered_grant:" => Some(ok(tx.delivered_grants(None), label, t).len()),
            _ => None,
        };
        if let Some(listed) = listed {
            read += listed;
            continue;
        }
        for (key, value) in stored {
            let suffix = &key[class.len()..];
            let env = || id(EnvironmentId::parse(suffix), label, t);
            let grant = || id(GrantId::parse(suffix), label, t);
            let hit =
                match *class {
                    "self_environment_id" => {
                        ok(tx.self_environment(), label, t).is_some_and(|e| e.as_str() == *value)
                    }
                    // ⟨M08 U2b-2⟩ The restore epoch's reader (ADR-0014 §3.6 step 1).
                    "restore_epoch" => ok(tx.restore_epoch(), label, t).0.to_string() == *value,
                    "authority_generation" => {
                        ok(tx.authority_generation(), label, t).0.to_string() == *value
                    }
                    "windows_environment_pipe_token" => {
                        ok(tx.windows_pipe_token(), label, t).as_deref() == Some(*value)
                    }
                    "event_tail:" => {
                        let page = tx.events_after(&env(), 0, &EventFilter::default(), 1);
                        ok(page, label, t).tail_seq.to_string() == *value
                    }
                    "lock_disclosure_acknowledged_at" => {
                        ok(tx.lock_disclosure_ack(), label, t).is_some()
                    }
                    "session_lock_acknowledged_epoch" => ok(tx.acknowledged_lock_epoch(), label, t)
                        .is_some_and(|e| e.to_string() == *value),
                    "managed_released_binding_cleanup:" => {
                        let b = id(BindingId::parse(suffix), label, t);
                        ok(tx.released_binding_cleanup_owed(&b), label, t)
                    }
                    "issuer_last_bundle_at" => ok(tx.last_bundle_at(), label, t).is_some(),
                    "issuer_bundle_sha256:" => {
                        ok(tx.bundle_digest_recorded_at(suffix), label, t).is_some()
                    }
                    "m05_decision_basis:" => {
                        let d = id(DecisionId::parse(suffix), label, t);
                        ok(tx.decision_basis(&d), label, t).is_some()
                    }
                    "high_water_mark" => ok(tx.high_water_mark(), label, t).is_some(),
                    "runtime_anchor" => ok(tx.runtime_anchor(), label, t).is_some(),
                    "time_confirmation" => ok(tx.time_confirmation(), label, t).is_some(),
                    "grant_validation:" => ok(tx.grant_validation(&grant()), label, t)
                        .is_some_and(|g| g.0.to_string() == *value),
                    "withdrawal_reported:" => ok(tx.withdrawal_reported(&grant()), label, t),
                    "grant_degraded:" => ok(tx.grant_degradation(&grant()), label, t).is_some(),
                    "m05.default_profile:" => ok(tx.default_profile(&env()), label, t)
                        .is_some_and(|p| p.as_str() == *value),
                    "runner_time_source" => ok(tx.time_source(), label, t).is_some(),
                    "runner_owner_only" => ok(tx.runner_downgrade(), label, t).is_some(),
                    "runner_policy_recheck" => ok(tx.policy_recheck(), label, t).is_some(),
                    // A missing contact reads as the default, so a stored one counts once it
                    // decodes.
                    "remote_contact:" => {
                        ok(tx.remote_contact(&env()), label, t);
                        true
                    }
                    "transport_serve_port" => ok(tx.transport_serve_port(), label, t)
                        .is_some_and(|p| p.to_string() == *value),
                    "transport_serve_port_unbindable" => {
                        ok(tx.transport_serve_bind_failure(), label, t)
                            .is_some_and(|p| p.to_string() == *value)
                    }
                    "transport_rotation" => ok(tx.transport_rotation(), label, t).is_some(),
                    other => panic!(
                        "{label}: meta: the key class {other} has no reader in this test: add its \
                     reader to `read_meta` or list it in META_NOT_READ"
                    ),
                };
            read += usize::from(hit);
        }
        // A class with no stored row still needs its reader here (or a META_NOT_READ entry).
        if stored.is_empty() {
            assert!(
                META_READ.contains(class),
                "{label}: meta: the key class {class} has no reader in this test: add its \
                 reader to `read_meta` and META_READ, or list it in META_NOT_READ"
            );
        }
    }
    (read, not_read)
}

/// The `meta` key classes [`read_meta`] reads.
const META_READ: &[&str] = &[
    "self_environment_id",
    "restore_epoch",
    "authority_generation",
    "windows_environment_pipe_token",
    "event_tail:",
    "lock_disclosure_acknowledged_at",
    "session_lock_acknowledged_epoch",
    "managed_released_binding_cleanup:",
    "issuer_last_bundle_at",
    "issuer_bundle_sha256:",
    "m05_decision_basis:",
    "high_water_mark",
    "runtime_anchor",
    "time_confirmation",
    "grant_validation:",
    "withdrawal_reported:",
    "grant_degraded:",
    "remote_revocation:",
    "cleanup_intent:",
    "m05.default_profile:",
    "runner_time_source",
    "runner_issuer_trust:",
    "runner_owner_only",
    "runner_policy_recheck",
    "remote_contact:",
    "remote_delivered_grant:",
    "transport_serve_port",
    "transport_serve_port_unbindable",
    "transport_rotation",
];

fn decode(e: &Event, label: &str) {
    let typed = EventPayload::decode(e).unwrap_or_else(|err| {
        panic!(
            "{label}: a stored {:?} event does not read as revision 7's payload: {err}",
            e.event_type
        )
    });
    assert_eq!(typed.event_type(), e.event_type);
}

/// Every table of the migrated schema (`stored`, its row counts) is read whole, or listed in
/// [`NOT_READ`]; every table read is in the schema.
fn check_read(label: &str, got: &Read, stored: &BTreeMap<String, i64>) {
    for (table, n) in stored {
        if NOT_READ.iter().any(|(t, _)| t == table) {
            assert!(
                !got.rows.contains_key(table.as_str()),
                "{label}: {table} is read and listed in NOT_READ"
            );
            continue;
        }
        let Some(read) = got.rows.get(table.as_str()) else {
            panic!("{label}: {table} is in the migrated schema but neither read nor in NOT_READ");
        };
        if table == "meta" {
            assert_eq!(
                (read + got.meta_not_read) as i64,
                *n,
                "{label}: meta: {read} rows read and {} of a key in META_NOT_READ, of {n} stored",
                got.meta_not_read
            );
        } else {
            assert_eq!(
                *read as i64, *n,
                "{label}: {table}: {read} of {n} stored rows read back"
            );
        }
    }
    for table in got.rows.keys() {
        assert!(
            stored.contains_key(*table),
            "{label}: {table} is read but not in the migrated schema"
        );
    }
}

/// The rows read per table across the corpus (shown with `--nocapture`).
#[allow(clippy::print_stdout)]
fn report(total: &BTreeMap<&str, usize>) {
    println!("replay corpus: rows read per table across every build and home: {total:?}");
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
    let mut total: BTreeMap<&str, usize> = BTreeMap::new();
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
                // `meta` may gain keys (0014's `restore_epoch`); every other table keeps its rows.
                let kept = after.get(table).copied().unwrap_or(0);
                if table == "meta" {
                    assert!(kept >= *n, "{label}: the migration kept meta");
                } else {
                    assert_eq!(kept, *n, "{label}: the migration kept {table}");
                }
            }
            check_read(&label, &got, &after);
            for (table, n) in &got.rows {
                *total.entry(*table).or_default() += n;
            }
        }
    }
    report(&total);
    for table in ["operations", "idempotency", "decisions", "events"] {
        assert!(
            total[table] > 0,
            "the corpus read no {table} row: {total:?}"
        );
    }
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
    let marker = KeyHash(RequestHash::from_hex(&"ab".repeat(32)).unwrap());
    c.execute(
        "INSERT INTO idempotency_markers (key_hash, expired_at, marker_until)
         VALUES (?1, '2026-11-01T00:00:00.000000000Z', '2026-12-01T00:00:00.000000000Z')",
        [marker.0.to_hex()],
    )
    .unwrap();
    drop(c);
    let got = read_back(&db, "hand");
    check_read(
        "hand",
        &got,
        &counts(&rusqlite::Connection::open(&db).unwrap()),
    );
    assert_eq!(
        got.rows["events"],
        events.len(),
        "every hand-authored event is read"
    );
    assert_eq!(got.rows["idempotency_markers"], 1, "hand: the marker reads");
}
