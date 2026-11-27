-- Heimdall state store, schema version 16 (M08 W4 U2b-3a: the request ledger made bounded and
-- the terminal records of the request-ID kinds the journal does not hold; ADR-0014 §3.6 step 4,
-- ADR-0006 §7.4 and §19.3 H13). Runs inside the migration step's one transaction together with
-- `PRAGMA user_version = 16`; either all of it applies or none of it does.
--
-- One table and two partial indexes. No existing table is rewritten and nothing is backfilled.
--
--   * `request_terminals`: a request key that reached its end, by the request ledger's digest of
--     its full idempotency key (`heimdall_store::fence::ledger_digest`; lowercase hex, as
--     `request_fences.key_digest`). It holds no request content and no identifier in the clear.
--     Its writers:
--       - the purge of a settled journaled operation (`Txn::purge_operations_before`), beside the
--         expired-key marker it writes: `trim_after` is that marker's `marker_until`. The marker's
--         key hash is another digest, so without this row the ledger entry's settlement could not
--         be found once the operation and its idempotency record are purged;
--       - the runtime, when a request-ID request the journal does not hold (M06's
--         `remote_environment.invite`, `runner_local.*`, `route.add`/`prefer`,
--         `transport.enable`/`adopt_roost`, and `release`) has answered with success:
--         `trim_after` is its settlement plus the operations' retention plus the 30-day marker
--         window. A restore counts the row as the key's terminal record
--         (`Txn::terminal_request_digests`), so a completed request of these kinds is replayed,
--         not fenced;
--       - the purge of a settled fence past its marker (`Txn::purge_markers_before`).
--     `trimmable` is set by the retention pass (`Txn::purge_markers_before`), on the time the
--     runtime's time gate accepted, once `trim_after` has passed: the ledger's trim
--     (`heimdall_runtime::request_fence`) may then drop the key's ledger entry, and removes the row
--     once it has. A key whose settlement is unknown has no row and is never trimmed.
CREATE TABLE request_terminals (
    key_digest TEXT PRIMARY KEY NOT NULL,
    settled_at TEXT NOT NULL,
    trim_after TEXT NOT NULL,
    trimmable  INTEGER NOT NULL DEFAULT 0 CHECK (trimmable IN (0, 1))
) STRICT;
CREATE INDEX request_terminals_due ON request_terminals(trim_after) WHERE trimmable = 0;
CREATE INDEX request_terminals_trimmable ON request_terminals(key_digest) WHERE trimmable = 1;
