-- Heimdall state store, schema version 17 (M08 W4 U2b-3b: what a restore quarantined, voided,
-- disabled and ended; ADR-0014 §3.6's table, deltas H9 and H10). Runs inside the migration
-- step's one transaction together with `PRAGMA user_version = 17`; either all of it applies or
-- none of it does.
--
-- One table. No existing table is rewritten and nothing is backfilled: a store that was never
-- restored holds no row.
--
--   * `restore_holds`: one row per recovered item a restore put on hold, written in the staged
--     generation before it becomes current (`heimdall_store::restore`). `kind` says what the
--     item is and how its readers answer it:
--       - `client`: a paired management client of this runner (`remote_clients`), quarantined
--         (`CAPABILITY_UNAVAILABLE` / `client_quarantined_after_restore`) until the owner
--         reauthorizes it at this machine, which removes the row;
--       - `invitation`: an invitation (`remote_invitations`), pending or consumed in the
--         backup, void (`invitation_void_after_restore`); never removed;
--       - `exposure`: the Iroh transport's exposure and admission state, disabled
--         (`exposure_disabled_after_restore`); `ref` names what (`transport`); an `enable`
--         is the same local decision as the first time;
--       - `environment`: a paired runner environment of this controller
--         (`remote_environment_pins`), held until a resynchronization reconciles it;
--       - `grant`: a grant the restore ended, with its tombstone
--         (`CREDENTIAL_EXPIRED` / `state_restored_authority_ended`).
--     `ref` is the item's opaque ID; `epoch` is the restore epoch the restore raised to;
--     `created_at` the restore's time. The rows are a reason, never authority: an item is
--     refused by its own record's state (a tombstone, a void invitation, a withdrawn key), and
--     the row only says why.
CREATE TABLE restore_holds (
    kind       TEXT NOT NULL CHECK (kind IN ('client', 'invitation', 'exposure', 'environment', 'grant')),
    ref        TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (kind, ref)
) STRICT;
