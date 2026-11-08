-- Heimdall state store, schema version 6 (M03 managed credentials: m03-plan §5 item 18;
-- ADR-0008 D4 items 3 and 5, D5 §6.2 and §6.5, D8 item 2, D9, D10 item 2). Runs inside
-- the migration step's one transaction together with `PRAGMA user_version = 6`; either
-- all of it applies or none of it does.
--
-- This step adds tables and indexes only. It rewrites no existing table and backfills
-- nothing: an M01 issuance-log entry has no `ca_fingerprint` and decodes with `None`,
-- and the policy, grant-origin and remote-revocation changes ride in their existing JSON
-- records as defaulted fields. Every column holds nonsecret data (public keys,
-- fingerprints, digests, references); JSON columns hold redacted serde documents.
--
-- The meta keys M03 adds (`lock_disclosure_acknowledged_at`, `session_lock_last`,
-- `session_lock_acknowledged_epoch`, `windows_environment_pipe_token`) need no schema.

-- Registered CAs (ADR-0008 D4). `state` follows `heimdall_domain::issuance::ca_transition`
-- (`pending`, `active`, `retiring`, `unloaded`, `deleted`, `retired`).
CREATE TABLE issuers (
    ca_fingerprint       TEXT PRIMARY KEY NOT NULL,
    public_key           TEXT NOT NULL,
    state                TEXT NOT NULL,
    store_kind           TEXT NOT NULL,
    backup_sha256        TEXT NOT NULL,
    backup_created_at    TEXT NOT NULL,
    restored_without_log INTEGER NOT NULL,
    created_at           TEXT NOT NULL,
    retired_at           TEXT,
    record_json          TEXT NOT NULL
) STRICT;

-- This installation's enrollments (ADR-0008 D5 §6.2). The marker is the add's
-- idempotency key and is unique for ever. At most one enrollment per (pair, CA) is
-- live (orchestrator ruling on S1): the partial index covers only the enrollment-path
-- states, listed positively so a new state is outside it only by an explicit decision.
-- Every removal and rollback state, `abandoned` (§17.4 item 5) and every final state is
-- outside it, so a re-enrollment after `abandoned` is admitted and an abandoned line can
-- be removed while the pair's new enrollment is live. `manual_pending` (the system
-- form's forming state) is included (confirmed with the S1 ruling). A `held` row reached
-- by a removal (its `removal_origin` set) is a residual, not a live enrollment, and is
-- outside the index too (S1 follow-up ruling); a `held` row reached on the enrollment
-- path stays inside. `removal_origin_set` mirrors `record_json`'s `removal_origin`: the
-- store writes both from the same record and refuses a read where they disagree, so the
-- index predicate needs no JSON function.
CREATE TABLE enrollments (
    id             TEXT PRIMARY KEY NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL REFERENCES issuers(ca_fingerprint),
    form           TEXT NOT NULL,
    marker         TEXT NOT NULL UNIQUE,
    state          TEXT NOT NULL,
    verified_at    TEXT,
    removal_origin_set INTEGER NOT NULL DEFAULT 0 CHECK (removal_origin_set IN (0, 1)),
    record_json    TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX enrollments_open_pair_ca
    ON enrollments(destination_id, account, ca_fingerprint)
    WHERE state IN ('planned', 'applying', 'outcome_unknown', 'applied_unverified',
                    'manual_pending', 'verifying', 'verified', 'reverifying', 'held')
      AND NOT (state = 'held' AND removal_origin_set = 1);
CREATE INDEX enrollments_pair ON enrollments(destination_id, account);
CREATE INDEX enrollments_ca ON enrollments(ca_fingerprint);
CREATE INDEX enrollments_state ON enrollments(state);

-- Foreign removals (ADR-0008 D4 item 5): run from another device, keyed by the bundle's
-- marker. No foreign key to `issuers`: the CA is not registered here (F07).
CREATE TABLE foreign_removals (
    id            TEXT PRIMARY KEY NOT NULL,
    marker        TEXT NOT NULL,
    local_alias   TEXT NOT NULL,
    account       TEXT NOT NULL,
    ca_public_key TEXT NOT NULL,
    line_sha256   TEXT NOT NULL,
    state         TEXT NOT NULL,
    operation_id  TEXT NOT NULL,
    record_json   TEXT NOT NULL
) STRICT;
CREATE INDEX foreign_removals_marker ON foreign_removals(marker);

-- Verification issuance entries (ADR-0008 D5 §6.5 item 2): no grant, so their own
-- table. `reserved` and `published` entries count toward the per-pair residual until
-- their `valid_before` (D7 item 4).
CREATE TABLE verification_issuance (
    id             TEXT PRIMARY KEY NOT NULL,
    operation_id   TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    purpose        TEXT NOT NULL,
    state          TEXT NOT NULL,
    valid_before   TEXT NOT NULL,
    reserved_at    TEXT NOT NULL,
    record_json    TEXT NOT NULL
) STRICT;
CREATE INDEX verification_issuance_pair_state
    ON verification_issuance(destination_id, account, state);
CREATE INDEX verification_issuance_operation ON verification_issuance(operation_id);

-- A pair's preferred mechanism, the projection rendering it, and the set of CAs with a
-- verified enrollment for the pair (m03-plan §5 item 4b; F05).
CREATE TABLE pair_preferences (
    destination_id        TEXT NOT NULL,
    account               TEXT NOT NULL,
    mechanism             TEXT NOT NULL,
    projection_state      TEXT NOT NULL,
    projection_generation INTEGER,
    issuing_cas_json      TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (destination_id, account)
) STRICT;

-- One slot per (environment, destination, account) (ADR-0008 D10 item 2). `binding_id`
-- is the holder while `held` and the last holder while `clearing`; NULL while `free`.
-- The generation survives every state.
CREATE TABLE managed_slots (
    environment_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    binding_id     TEXT REFERENCES bindings(id),
    generation     INTEGER NOT NULL,
    state          TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, destination_id, account)
) STRICT;
CREATE INDEX managed_slots_binding ON managed_slots(binding_id);

-- Owned connections (ADR-0008 D8 item 2): the process carrying a connection, separate
-- from the binding's holder. PIDs never leave the process on the wire.
CREATE TABLE owned_connections (
    id           TEXT PRIMARY KEY NOT NULL,
    binding_id   TEXT NOT NULL REFERENCES bindings(id),
    grant_id     TEXT NOT NULL REFERENCES grants(id),
    kind         TEXT NOT NULL,
    pid          INTEGER NOT NULL,
    start_token  TEXT NOT NULL,
    image        TEXT NOT NULL,
    control_path TEXT,
    generation   INTEGER NOT NULL,
    state        TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE INDEX owned_connections_grant ON owned_connections(grant_id);
CREATE INDEX owned_connections_binding ON owned_connections(binding_id);
