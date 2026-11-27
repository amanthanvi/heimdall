-- Heimdall state store, schema version 18 (M08 W4 SEC-3b: the runner's authority history is
-- bounded; ADR-0006 §7.4 and ADR-0012 §7.4 as amended 2026-11-27 on the orchestrator's ruling
-- of 2026-11-26, R1 to R5). Runs inside the migration step's one transaction together with
-- `PRAGMA user_version = 18`; either all of it applies or none of it does.
--
-- Columns and indexes only. No row is rewritten and nothing is backfilled: every new column is
-- NULL on an existing row, which the retention pass reads as "not yet" (fail safe).
--
--   * `tombstones.producer`: the paired client whose delivered `grant_revoke` wrote a bare
--     tombstone (one for a grant ID this runner does not hold); the per-producer cap counts
--     it. NULL for every other tombstone, and for one written before this step.
--   * `remote_policy_revisions.lifted_at`: when the runner's retention pass first found the
--     row lifted (its in-force flag cleared by a runner-local attended lift). NULL while it is
--     in force, and until that pass runs.
--   * `remote_policy_revisions.lift_confirmed_at`: when the producing controller's session went
--     on after a complete authority report that showed the row lifted (the runner's evidence
--     that the controller recorded the lift; `heimdall_runtime::runner`). NULL: not confirmed.
--   * `remote_effect_outbox.lift_seen_at` (a controller's table): when a complete authority
--     report first showed this delivered pause or cutoff lifted. Kept once set: the issuer's
--     barrier counts it for a lifted row the runner has since pruned, and a report that shows
--     the effect in force again (a restored runner) still blocks.
ALTER TABLE tombstones ADD COLUMN producer TEXT;
ALTER TABLE remote_policy_revisions ADD COLUMN lifted_at TEXT;
ALTER TABLE remote_policy_revisions ADD COLUMN lift_confirmed_at TEXT;
ALTER TABLE remote_effect_outbox ADD COLUMN lift_seen_at TEXT;
CREATE INDEX tombstones_producer ON tombstones(producer) WHERE producer IS NOT NULL;
CREATE INDEX tombstones_revoked ON tombstones(revoked_at);
CREATE INDEX remote_effect_acks_applied ON remote_effect_acks(applied_at);
