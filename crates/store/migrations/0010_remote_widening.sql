-- Heimdall state store, schema version 10 (M06 wave 2: the runner-local widening records;
-- ADR-0012 §3.10; ADR-0006 §3.1 reused). Runs inside the migration step's one transaction
-- together with `PRAGMA user_version = 10`; either all of it applies or none of it does.
--
-- This step adds one table. It rewrites no existing table and backfills nothing.
--
-- A paired client's widening request is an ADR-0006 §3.1 decision record in `decisions`
-- (kind `remote_widening`: the client, the request kind and ID, the exact request), decided
-- only by an attended session local to the runner. This table is the record's side half:
-- the caller-namespaced key `(client, request kind, request ID)` a replay is looked up by
-- (two clients' identical request IDs are different keys, ADR-0012 §3.7), the request's
-- canonical hash (the same key with another request is `REQUEST_CONFLICT`), and the
-- recorded terminal result once the record is decided, so a replay returns it with no new
-- record and no re-execution (T-RA3, ADR-0006 §7.3). `result_json` is a redacted envelope:
-- identifiers, states and codes only.
CREATE TABLE remote_widening (
    decision_id  TEXT PRIMARY KEY NOT NULL REFERENCES decisions(id),
    client_id    TEXT NOT NULL,
    request_kind TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json  TEXT,
    UNIQUE (client_id, request_kind, request_id)
) STRICT;
