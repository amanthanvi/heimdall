-- Heimdall state store, schema version 5 (M02 existing access: m02-plan §5 item 18;
-- ADR-0007 §5.7, §7). Runs inside the migration step's one transaction together with
-- `PRAGMA user_version = 5`; either all of it applies or none of it does.
--
-- This step adds tables only. It rewrites neither `stage_receipts` nor
-- `recovery_intents` and backfills nothing: an M01 receipt or intent has no `local`
-- payload and decodes with `local = None` (m02-plan §5 item 17a). Every column holds
-- nonsecret data; JSON columns hold redacted serde documents.

-- The catalog: destinations (the alias is unique; the ID survives a rename, spec
-- §4.2) and identities (the public-key fingerprint is unique).
CREATE TABLE destinations (
    id          TEXT PRIMARY KEY NOT NULL,
    alias       TEXT NOT NULL UNIQUE,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;

CREATE TABLE identities (
    id          TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;

-- One row per identity, never deleted, so a revision is never reused. Every write is
-- a compare-and-swap on the expected revision (ADR-0007 §7). Expiry is computed when
-- the row is read and is never written.
CREATE TABLE interaction_declarations (
    identity    TEXT PRIMARY KEY NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;

-- The process holding a launch binding (`ProcessHolder`, m02-plan §5 item 5).
CREATE TABLE binding_holders (
    binding     TEXT PRIMARY KEY NOT NULL REFERENCES bindings(id),
    holder_json TEXT NOT NULL
) STRICT;

-- What `prepare` observed for a grant: history only, never interaction,
-- availability or eligibility (m02-plan §5 item 17 `PreparedFacts`; M2-R04).
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;

-- Consented behaviour states per affected item (a managed alias or Git's SSH
-- selection) with the decision that recorded them (ADR-0007 §5.2).
CREATE TABLE projection_consent (
    environment TEXT NOT NULL,
    item        TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (environment, item)
) STRICT;

-- The projection record of an environment (`ProjectionRecord`): the last committed
-- generation of each item with its files and managed aliases. Written only with an
-- item's `item.committed` receipt (`Txn::commit_projection_item`). The projection
-- files themselves are `config_projection` rows of the existing `resources` table,
-- owned by `{"kind":"projection","environment":…}`, whose locator is the canonical
-- `ProjectionLocator`.
CREATE TABLE projection_records (
    environment TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL
) STRICT;

-- `open_setup_operations` reads the open or unresolved setup operations of one
-- environment inside every setup admission (`insert_setup_operation`).
CREATE INDEX operations_environment_kind ON operations(environment, kind);
