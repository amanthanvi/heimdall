-- Heimdall state store, schema version 13 (M06 wave 5: local widening decisions; ADR-0006
-- §18.9 item 8; ADR-0012 §3.10 item 4). Runs inside the migration step's one transaction
-- together with `PRAGMA user_version = 13`; either all of it applies or none of it does.
--
-- This step rebuilds one table, `remote_widening`, because SQLite cannot drop a column's
-- NOT NULL. Every existing row is copied unchanged with `origin = 'paired'` and no delta
-- digest; no row is dropped and no other table is touched. Nothing references this table.
--
-- A widening record now states who submitted it:
--   * `origin = 'paired'`: a paired client, named in `client_id` (every record before this
--     step). Its key is still `(client_id, request_kind, request_id)`.
--   * `origin = 'local'`: this installation's local owner, in an attended session. It has
--     no client: `client_id` is NULL, and no client ID can stand for the local owner. It
--     is looked up by `(request_kind, delta_digest)`: the digest of the exact request
--     (without its request ID) and the exact exposure delta, so a retry finds the pending
--     record instead of making a second one.
-- The CHECK constraint ties the two columns to the origin in both directions.
CREATE TABLE remote_widening_v13 (
    decision_id  TEXT PRIMARY KEY NOT NULL REFERENCES decisions(id),
    origin       TEXT NOT NULL DEFAULT 'paired' CHECK (origin IN ('local', 'paired')),
    client_id    TEXT,
    request_kind TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json  TEXT,
    delta_digest TEXT,
    UNIQUE (client_id, request_kind, request_id),
    CHECK (
        (origin = 'paired' AND client_id IS NOT NULL AND delta_digest IS NULL)
        OR (origin = 'local' AND client_id IS NULL AND delta_digest IS NOT NULL)
    )
) STRICT;

INSERT INTO remote_widening_v13 (decision_id, origin, client_id, request_kind, request_id,
    request_hash, result_json, delta_digest)
SELECT decision_id, 'paired', client_id, request_kind, request_id, request_hash, result_json,
    NULL
FROM remote_widening;

DROP TABLE remote_widening;

ALTER TABLE remote_widening_v13 RENAME TO remote_widening;

CREATE INDEX remote_widening_local ON remote_widening (request_kind, delta_digest)
    WHERE origin = 'local';
