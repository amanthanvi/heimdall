-- Schema 15 (M08 GRANT-LIVE). The state column is written with the grant snapshot
-- on insert and state change. Deriving liveness here also classifies existing rows
-- without rewriting their snapshots. Keep this list aligned with GrantState::is_terminal.
ALTER TABLE grants ADD COLUMN is_live INTEGER GENERATED ALWAYS AS (
    state NOT IN ('revoked', 'expired', 'released', 'denied', 'cancelled', 'failed')
) VIRTUAL NOT NULL;

-- Building the partial index backfills it for every existing live grant. It serves
-- both ordered live scans and deadline ranges, with no entries for terminal grants.
CREATE INDEX grants_live_deadline ON grants(deadline_effective, id) WHERE is_live = 1;
DROP INDEX grants_deadline;
