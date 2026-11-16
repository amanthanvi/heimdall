-- Heimdall state store, schema version 8 (M05 trusted work: ADR-0011 §9 "Store" and §10
-- item 5; m05-plan §4 item 12; joint wave 0 of M04 and M05). Runs inside the migration
-- step's one transaction together with `PRAGMA user_version = 8`; either all of it
-- applies or none of it does.
--
-- This step adds tables and one nullable column only. It rewrites no existing row and
-- backfills nothing: an existing binding has no `context_json` and reads as personal
-- work (`NULL` means personal), and every M01–M04 document is untouched. Every column
-- holds nonsecret data (identifiers, paths, instants, redacted serde documents).

-- Trusted workspaces (ADR-0011 §2.1 option A): the local identity record, in the
-- environment whose path namespace `root` is in. `state` is `active` or `stale`. The
-- table never leaves the local database (ADR-0011 I4).
CREATE TABLE workspaces (
    id          TEXT PRIMARY KEY NOT NULL,
    environment TEXT NOT NULL,
    root        TEXT NOT NULL,
    state       TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;
CREATE INDEX workspaces_environment ON workspaces(environment);

-- Applied policy changes (ADR-0011 §4.4): one row per (policy, revision), the whole
-- record as applied with its cause.
CREATE TABLE policy_history (
    policy_id   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY (policy_id, revision)
) STRICT;

-- A denied decision's cooldown (ADR-0011 §4.3), keyed by the coalescing key's digest.
CREATE TABLE decision_cooldowns (
    key         TEXT PRIMARY KEY NOT NULL,
    policy_id   TEXT NOT NULL,
    until       TEXT NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE INDEX decision_cooldowns_policy ON decision_cooldowns(policy_id);

-- Stopped work IDs (ADR-0011 §7.2 "Stop (work)"): a stopped work ID is never
-- reactivated, so rows are only ever inserted.
CREATE TABLE work_stops (
    environment TEXT NOT NULL,
    work_id     TEXT NOT NULL,
    stopped_at  TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (environment, work_id)
) STRICT;

-- Bindings that reference a shared ordinary-alias slot (ADR-0011 §5.2 as ruled in §10
-- item 6): the slot's materializer is one of these, the rest wait for handover to the
-- one with the latest `deadline`.
CREATE TABLE slot_references (
    environment_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    binding_id     TEXT NOT NULL REFERENCES bindings(id),
    deadline       TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    PRIMARY KEY (environment_id, destination_id, account, binding_id)
) STRICT;
CREATE INDEX slot_references_binding ON slot_references(binding_id);

-- What a binding pins as its context (ADR-0011 §5.1): a workspace or personal work.
-- Absent (NULL) means personal.
ALTER TABLE bindings ADD COLUMN context_json TEXT;
