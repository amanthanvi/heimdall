-- Heimdall state store, schema version 7 (M04 platform realization: ADR-0010 §2–§4 and
-- §9 item 1; ADR-0006 revision 5 §17; joint wave 0 of M04 and M05). Runs inside the
-- migration step's one transaction together with `PRAGMA user_version = 7`; either all of
-- it applies or none of it does.
--
-- This step adds tables only. It rewrites no existing table and backfills nothing: the
-- runtime's own native environment is implicit (the `self_environment_id` meta row) and
-- has no `managed_environments` row; a route's `jump` rides in the destination's JSON
-- record as a defaulted field; a login entry is a `login_entry` row of the existing
-- `resources` table. Every column holds nonsecret data.

-- The runtime's managed-environment set beyond its own native session (ADR-0010 §9 item
-- 1): each WSL Mode B distribution and each container environment. `controller` is the
-- managing runtime's own environment ID (ownership); `state` is `active`,
-- `not_running`, `removed` or `gone` (only the first two are in the set). Removed and
-- gone rows stay as removed identities, so a removed environment is never a target again.
CREATE TABLE managed_environments (
    environment_id TEXT PRIMARY KEY NOT NULL,
    controller     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    state          TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;
CREATE INDEX managed_environments_state ON managed_environments(state);

-- WSL distribution records (ADR-0010 §2 item 1): a Mode A distribution has no environment
-- record, only this one, keyed by its registration GUID; its owned items are `resources`
-- rows.
CREATE TABLE wsl_distributions (
    guid        TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
