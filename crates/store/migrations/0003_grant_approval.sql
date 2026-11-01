-- Heimdall state store, schema version 3 (ADR-0006 §13.7 item 3). Runs inside the
-- migration step's one transaction together with `PRAGMA user_version = 3`; either
-- all of it applies or none of it does.

-- The approval basis of an owner-approved grant (approved delta, decision ID, its
-- generation and the applicable policy revision; a serde `ApprovalBasis` document)
-- is persisted with the grant row, so operation retention, which removes a settled
-- operation together with its recovery intent, cannot purge it. Written once
-- (`Txn::set_grant_approval`); NULL for every other grant.
ALTER TABLE grants ADD COLUMN approval_json TEXT;

-- Backfill: a v2 approval basis lives only in the recovery intent of an operation
-- that pins the grant (`resolved.grant`, `resolved.approval`). Every waiter of a
-- shared decision records the same basis; the lowest operation ID is taken so the
-- result is deterministic. A grant whose operations were already purged has no
-- recorded basis and is re-validated against the standing policy alone (fail
-- closed). Malformed documents are skipped, never parsed.
UPDATE grants SET approval_json = (
    SELECT json_extract(r.record_json, '$.resolved.approval')
    FROM recovery_intents r
    WHERE json_valid(r.record_json)
      AND json_type(r.record_json, '$.resolved.approval') = 'object'
      AND json_extract(r.record_json, '$.resolved.grant') = grants.id
    ORDER BY r.operation_id
    LIMIT 1
)
WHERE approval_json IS NULL;
