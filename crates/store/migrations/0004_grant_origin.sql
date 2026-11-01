-- Heimdall state store, schema version 4 (ADR-0006 §13.9 item 2). Runs inside the
-- migration step's one transaction together with `PRAGMA user_version = 4`; either
-- all of it applies or none of it does.

-- Where a grant's authority was resolved (profile and revision, the applicable
-- policy revision, the caller it was resolved for, the credential mechanism, and
-- the covered basis of a waiting request the saved policy came to cover; a serde
-- `GrantOrigin` document) is persisted with the grant row, so re-validation derives
-- its context from the grant itself and never from a consumer binding or an
-- operation record. Written once at grant creation (`Txn::set_grant_origin`; the
-- covered basis is add-only); NULL for a grant that predates this version and has
-- nothing to backfill from (its re-validation is then undetermined: the use is
-- refused and nothing is ended).
ALTER TABLE grants ADD COLUMN origin_json TEXT;

-- Backfill 1: the recovery intent of an operation that pins the grant
-- (`resolved.grant`) holds the profile, revision, policy revision, mechanism and
-- covered basis it was resolved with; the operation row holds the caller. The
-- lowest operation ID is taken so the result is deterministic. Malformed
-- documents and incomplete intents are skipped, never parsed.
UPDATE grants SET origin_json = (
    SELECT json_object(
        'profile', json_extract(r.record_json, '$.resolved.profile'),
        'profile_revision', json_extract(r.record_json, '$.resolved.profile_revision'),
        'policy_revision', json_extract(r.record_json, '$.resolved.policy_revision'),
        'caller', json(o.caller_json),
        'mechanism', json_extract(r.record_json, '$.resolved.adapter.mechanism'),
        'covered', json(json_extract(r.record_json, '$.resolved.covered'))
    )
    FROM recovery_intents r JOIN operations o ON o.id = r.operation_id
    WHERE json_valid(r.record_json)
      AND json_valid(o.caller_json)
      AND json_extract(r.record_json, '$.resolved.grant') = grants.id
      AND json_type(r.record_json, '$.resolved.profile') = 'text'
      AND json_type(r.record_json, '$.resolved.profile_revision') = 'integer'
      AND json_type(r.record_json, '$.resolved.adapter.mechanism') = 'text'
    ORDER BY r.operation_id
    LIMIT 1
)
WHERE origin_json IS NULL;

-- Backfill 2: a binding that realizes the grant (never a delegated child's binding,
-- which names the child) pins its owner, profile, revision and mechanism; the
-- policy revision is the grant's own standing-policy source revision, if any. The
-- earliest binding (creation time, then ID) is taken.
UPDATE grants SET origin_json = (
    SELECT json_object(
        'profile', b.profile,
        'profile_revision', b.profile_revision,
        'policy_revision', CASE
            WHEN json_extract(grants.record_json, '$.source.kind') = 'standing_policy'
            THEN json_extract(grants.record_json, '$.source.revision')
        END,
        'caller', json(b.owner_json),
        'mechanism', b.mechanism
    )
    FROM bindings b
    WHERE b.grant_id = grants.id
      AND b.profile IS NOT NULL
      AND b.profile_revision IS NOT NULL
      AND b.mechanism IS NOT NULL
      AND json_valid(b.owner_json)
      AND json_valid(grants.record_json)
    ORDER BY b.created_at, b.id
    LIMIT 1
)
WHERE origin_json IS NULL;
