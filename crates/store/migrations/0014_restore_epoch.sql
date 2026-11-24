-- Heimdall state store, schema version 14 (revision 7's preparatory part: ADR-0014 H9 and
-- §3.6, the restore epoch and the replay fence; the contract owner's U0-Q9 ruling on
-- case-insensitive aliases; ADR-0006 §19). Runs inside the migration step's one transaction
-- together with `PRAGMA user_version = 14`; either all of it applies or none of it does.
--
-- Columns, one table and two indexes; no writer yet (U2b writes them). Every existing row is
-- kept unchanged and reads as restore epoch 0: everything minted before a first restore
-- belongs to epoch 0.
--
--   * `meta.restore_epoch` (text, like every `meta` value): the current restore epoch, written
--     `0` here. A restore raises it, durably, before its pointer moves (ADR-0014 §3.6 step 1).
--     From schema version 14 on, a store without the row is damaged (`state_corrupt`), never
--     epoch 0: a lost row must not reset the fence (review U0-R06).
--   * `operations.restore_epoch`, `decisions.restore_epoch`, `remote_effect_outbox.
--     restore_epoch`: the epoch an operation ID, a decision reference or an effect ID was
--     minted under (§3.6 step 2). A reference of an older epoch with no carried record is
--     answered as stale, never as not found.
--   * `idempotency.request_epoch`: the epoch the request ID was minted under (§3.6 step 3).
--   * `request_fences`: one row per fenced request, keyed by the request ledger's digest
--     (SHA-256 over the canonically encoded full idempotency key: principal, caller role,
--     `remote_client`, operation kind and request ID; lowercase hex). `answer_json` is the
--     stored answer (`REQUEST_STALE`, reason `restored_before_completion`); the lifetimes are
--     ADR-0006 §7.4's: an unresolved key (`settled_at` NULL) is kept indefinitely, a settled
--     one until `expires_at`, then its marker until `marker_until`.
--   * `destinations_alias_nocase`: the catalog's case-insensitive alias lookup (U0-Q9).
--     Not UNIQUE: an existing case-variant pair stays stored and readable, and `doctor`
--     reports it; a new write into a case-variant of another destination's alias is refused.
--
-- The quarantine state of a management client and the void state of an invitation need no
-- column: `remote_clients.state` and `remote_invitations.state` are free text (`pending`,
-- `active`, `revoked`; `pending`, `consumed`, `expired`, `revoked`), and U2b adds the values
-- `quarantined` and `void`. The backup's environment binding needs none either: a backup is a
-- consistent copy of the store, so it carries `meta.self_environment_id`.
INSERT INTO meta (key, value) VALUES ('restore_epoch', '0');

ALTER TABLE operations ADD COLUMN restore_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE decisions ADD COLUMN restore_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remote_effect_outbox ADD COLUMN restore_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE idempotency ADD COLUMN request_epoch INTEGER NOT NULL DEFAULT 0;

CREATE TABLE request_fences (
    key_digest   TEXT PRIMARY KEY NOT NULL,
    epoch        INTEGER NOT NULL,
    answer_json  TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    settled_at   TEXT,
    expires_at   TEXT,
    marker_until TEXT
) STRICT;
CREATE INDEX request_fences_expires_at ON request_fences(expires_at);

CREATE INDEX destinations_alias_nocase ON destinations(alias COLLATE NOCASE);
