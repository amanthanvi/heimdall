-- Heimdall state store, schema version 2 (M01 design-fix round: review F01, F02,
-- F04-F08; ADR-0005 §3.5/§3.6; ADR-0006 §7). Runs inside the migration step's one
-- transaction together with `PRAGMA user_version = 2`; either all of it applies or
-- none of it does. Timestamps use the store's fixed-width UTC form; JSON columns
-- hold redacted serde documents (references only, never secrets).

-- F02: pending keys never expire, so `expires_at` becomes nullable. SQLite cannot
-- drop NOT NULL in place: rebuild the table and copy every row. A v1 row whose
-- operation is not settled (queued, running, awaiting_approval, outcome_unknown)
-- loses its creation-time expiry (pending keys stay live until settlement); a
-- settled row keeps the expiry it had.
CREATE TABLE idempotency_v2 (
    caller_json  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    PRIMARY KEY (caller_json, kind, request_id)
) STRICT;
INSERT INTO idempotency_v2 (caller_json, kind, request_id, request_hash, operation_id,
                            created_at, expires_at)
SELECT i.caller_json, i.kind, i.request_id, i.request_hash, i.operation_id, i.created_at,
       CASE WHEN o.state IN ('succeeded', 'failed', 'cancelled') THEN i.expires_at END
FROM idempotency i JOIN operations o ON o.id = i.operation_id;
DROP TABLE idempotency;
ALTER TABLE idempotency_v2 RENAME TO idempotency;
CREATE INDEX idempotency_expires_at ON idempotency(expires_at);
CREATE INDEX idempotency_operation ON idempotency(operation_id);

-- F02: compact marker left when a settled record is purged; a reused key inside
-- `marker_until` is REQUEST_EXPIRED, never a silent new operation.
CREATE TABLE idempotency_markers (
    key_hash     TEXT PRIMARY KEY NOT NULL,
    expired_at   TEXT NOT NULL,
    marker_until TEXT NOT NULL
) STRICT;
CREATE INDEX idempotency_markers_until ON idempotency_markers(marker_until);

-- F03: server-issued decision records (consume-once, generation-bound). Never
-- purged by operation retention.
CREATE TABLE decisions (
    id          TEXT PRIMARY KEY NOT NULL,
    kind_json   TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    state       TEXT NOT NULL,
    decided_at  TEXT,
    record_json TEXT NOT NULL
) STRICT;
CREATE INDEX decisions_state ON decisions(state, created_at);

-- F04: bindings pin owner, profile revision, scope and mechanism. No v1 code path
-- wrote bindings; any v1 row keeps its columns and gets a state from `released_at`.
ALTER TABLE bindings ADD COLUMN owner_json TEXT;
ALTER TABLE bindings ADD COLUMN profile TEXT;
ALTER TABLE bindings ADD COLUMN profile_revision INTEGER;
ALTER TABLE bindings ADD COLUMN scope_json TEXT;
ALTER TABLE bindings ADD COLUMN mechanism TEXT;
ALTER TABLE bindings ADD COLUMN parent TEXT;
ALTER TABLE bindings ADD COLUMN state TEXT NOT NULL DEFAULT 'active';
UPDATE bindings SET state = 'released' WHERE released_at IS NOT NULL;
CREATE INDEX bindings_grant ON bindings(grant_id);
CREATE INDEX bindings_parent ON bindings(parent);

-- F04: immutable resolved profile snapshots, one per (profile, revision).
CREATE TABLE profile_snapshots (
    profile     TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (profile, revision)
) STRICT;

-- F01: per-grant budget anchors (ADR-0005 §3.6). `budget_end_ns` and `bound` are
-- informational copies; `record_json` is authoritative. Never purged.
CREATE TABLE grant_anchors (
    grant_id      TEXT PRIMARY KEY NOT NULL,
    record_json   TEXT NOT NULL,
    boot_id       TEXT NOT NULL,
    budget_end_ns INTEGER NOT NULL,
    bound         TEXT NOT NULL
) STRICT;

-- F01: the v1 `time_anchor` meta row has no boot ID and cannot be compared with
-- boot-scoped continuous readings. Its wall time was accepted, so it seeds the
-- high-water mark (v1 never wrote one); the row itself is dropped and the runtime
-- anchor starts empty (first start: fail closed until time is safe).
INSERT INTO meta (key, value)
SELECT 'high_water_mark', json_extract(value, '$.wall')
FROM meta
WHERE key = 'time_anchor' AND json_valid(value)
  AND json_type(value, '$.wall') = 'text'
ON CONFLICT(key) DO NOTHING;
DELETE FROM meta WHERE key = 'time_anchor';

-- F05: redacted recovery intent and append-only stage receipts. They go with
-- their operation when retention purges a settled one; an unresolved operation is
-- never purged, so its evidence stays.
CREATE TABLE recovery_intents (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    record_json  TEXT NOT NULL
) STRICT;

CREATE TABLE stage_receipts (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (operation_id, ordinal)
) STRICT;

-- F06: issuance log (reserved -> published | voided) and credential instances.
-- Never purged by operation retention.
CREATE TABLE issuance_log (
    id           TEXT PRIMARY KEY NOT NULL,
    grant_id     TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    state        TEXT NOT NULL,
    valid_before TEXT NOT NULL,
    reserved_at  TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE INDEX issuance_log_grant_state ON issuance_log(grant_id, state);

CREATE TABLE credential_instances (
    id          TEXT PRIMARY KEY NOT NULL,
    grant_id    TEXT NOT NULL,
    state       TEXT NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE INDEX credential_instances_grant ON credential_instances(grant_id);
