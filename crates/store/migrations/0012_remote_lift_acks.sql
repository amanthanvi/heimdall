-- Heimdall state store, schema version 12 (M06 wave 4: the controller's acknowledgements of
-- a lifted pause or cutoff; ADR-0012 §7.4 as amended 2026-11-21 on M06-W3-R02; ADR-0006
-- §18.8 item 4). Runs inside the migration step's one transaction together with
-- `PRAGMA user_version = 12`; either all of it applies or none of it does.
--
-- This step adds one table. It rewrites no existing row and backfills nothing.
--
-- `remote_lift_acks` holds one row per delivered pause or cutoff effect of this controller
-- whose lift the owner confirmed here (`heimdall environment resume-issuance <env>`,
-- attended). The key is the effect's key in `remote_effect_outbox`. A row alone reopens
-- nothing: issuance for the runner resumes only when the runner's authority report also
-- shows the lift. A row is never updated; it goes with the environment's outbox rows when
-- the controller forgets the environment. No existing effect is acknowledged.
CREATE TABLE remote_lift_acks (
    environment       TEXT NOT NULL,
    producer          TEXT NOT NULL,
    effect_id         TEXT NOT NULL,
    target_kind       TEXT NOT NULL,
    target_ref        TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    acknowledged_at   TEXT NOT NULL,
    PRIMARY KEY (producer, effect_id, target_kind, target_ref, target_generation)
) STRICT;
