-- Heimdall state store, schema version 9 (M06 remote runners, routes and the Iroh
-- transport: ADR-0012 §9 item 11; ADR-0006 revision 6 §18; M06 wave 0). Runs inside the
-- migration step's one transaction together with `PRAGMA user_version = 9`; either all of
-- it applies or none of it does.
--
-- This step adds tables only. It rewrites no existing table and backfills nothing, so
-- every M01-M05 row and document is untouched. Wave 0 adds no store API: no code reads or
-- writes these tables until the M06 units that own them (m06-plan U1-U5) add their
-- accessors. The store is forward-only (no down migrations): a later change is a new step.
--
-- Every column holds nonsecret data: identifiers, fingerprints, public certificate and key
-- text, instants, redacted serde documents. Key material never enters this database: a
-- transport key is a reference to its platform-store item, and K_env lives only in the
-- runner's memory (ADR-0012 §0, §2.4). Runner-local decisions use the existing
-- `decisions` table (ADR-0006 §3.1's record, unchanged).

-- The runner's role table (ADR-0012 §3.7-§3.9, §3.11): one row per paired client.
-- `state` is `pending`, `active` or `revoked`; a revoked row is the client's tombstone, the
-- admission authority (§2.3 item 3), kept with the authority generation that revoked it.
CREATE TABLE remote_clients (
    client_id          TEXT PRIMARY KEY NOT NULL,
    role               TEXT NOT NULL,
    key_fingerprint    TEXT NOT NULL,
    state              TEXT NOT NULL,
    invitation_id      TEXT,
    revoked_generation INTEGER,
    record_json        TEXT NOT NULL,
    updated_at         TEXT NOT NULL
) STRICT;
CREATE INDEX remote_clients_key ON remote_clients(key_fingerprint);

-- Invitations (ADR-0012 §3.9): consumed once by join's compare-and-set. Live only while the
-- checked wall clock is before `expires_wall` and, under the same boot anchor
-- (`created_boot_id`), the continuous clock shows less than `elapsed_bound_ms` since
-- `created_elapsed_ms`; a rollback cannot extend it. `state` is `pending`, `consumed`,
-- `expired` or `revoked`.
CREATE TABLE remote_invitations (
    invitation_id      TEXT PRIMARY KEY NOT NULL,
    client_id          TEXT NOT NULL,
    role               TEXT NOT NULL,
    key_fingerprint    TEXT NOT NULL,
    generation         INTEGER NOT NULL,
    created_wall       TEXT NOT NULL,
    created_boot_id    TEXT NOT NULL,
    created_elapsed_ms INTEGER NOT NULL,
    expires_wall       TEXT NOT NULL,
    elapsed_bound_ms   INTEGER NOT NULL,
    state              TEXT NOT NULL,
    consumed_at        TEXT,
    record_json        TEXT NOT NULL
) STRICT;
CREATE INDEX remote_invitations_client ON remote_invitations(client_id);

-- The controller's typed effect outbox (ADR-0012 §7.2, §7.4): narrowing effects this
-- controller produced for a runner, keyed by (producer, effect ID, typed target, target
-- generation). `state` is `pending` until the runner's acknowledgement (`ack_json`, with
-- its enforcement state) arrives.
CREATE TABLE remote_effect_outbox (
    environment       TEXT NOT NULL,
    producer          TEXT NOT NULL,
    effect_id         TEXT NOT NULL,
    target_kind       TEXT NOT NULL,
    target_ref        TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    target_json       TEXT NOT NULL,
    state             TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    acknowledged_at   TEXT,
    ack_json          TEXT,
    PRIMARY KEY (producer, effect_id, target_kind, target_ref, target_generation)
) STRICT;
CREATE INDEX remote_effect_outbox_pending ON remote_effect_outbox(environment, state);

-- The runner's acknowledgements of delivered effects (ADR-0012 §7.2): written in the same
-- transaction as the durable record the effect names (a grant tombstone or a policy
-- revision), so a redelivery returns the recorded acknowledgement.
CREATE TABLE remote_effect_acks (
    producer          TEXT NOT NULL,
    effect_id         TEXT NOT NULL,
    target_kind       TEXT NOT NULL,
    target_ref        TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    applied_at        TEXT NOT NULL,
    ack_json          TEXT NOT NULL,
    PRIMARY KEY (producer, effect_id, target_kind, target_ref, target_generation)
) STRICT;

-- Policy revisions the runner received (ADR-0012 §7.2): durable pause and cutoff revisions,
-- one row per (scope, revision). `kind` is `pause` or `cutoff`; `scope_key` is the
-- canonical form of the policy or target it applies to.
CREATE TABLE remote_policy_revisions (
    scope_key   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    producer    TEXT NOT NULL,
    effect_id   TEXT NOT NULL,
    received_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (scope_key, revision)
) STRICT;

-- The controller's pins of each remote runner environment (ADR-0012 §3.3, §7.5): its
-- environment ID, the catalog destination and account that reach it, and its host key.
-- A changed host key or environment ID is `held` (`environment_identity_mismatch`).
CREATE TABLE remote_environment_pins (
    environment_id   TEXT PRIMARY KEY NOT NULL,
    destination      TEXT NOT NULL,
    account          TEXT NOT NULL,
    host_fingerprint TEXT NOT NULL,
    record_json      TEXT NOT NULL,
    pinned_at        TEXT NOT NULL
) STRICT;

-- The runner's grant-to-issuer pins (ADR-0012 §4.2): each grant is pinned to the
-- controller (its client) and CA that issued it; a different issuer needs a separately
-- approved grant.
CREATE TABLE remote_grant_issuers (
    grant_id       TEXT PRIMARY KEY NOT NULL,
    issuer_client  TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    pinned_at      TEXT NOT NULL
) STRICT;

-- A destination's approved routes in preference order (ADR-0012 §5.1, §9 item 9), each with
-- its exposure policy (`route_json` holds the route and its exposure).
CREATE TABLE destination_routes (
    route_id    TEXT PRIMARY KEY NOT NULL,
    destination TEXT NOT NULL,
    position    INTEGER NOT NULL,
    route_json  TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX destination_routes_order ON destination_routes(destination, position);

-- Recorded exposure consents (ADR-0012 §2.1, §2.8): each bound to the exact delta and the
-- attended decision that confirmed it; a route lists the consents it relies on.
CREATE TABLE route_consents (
    consent_id  TEXT PRIMARY KEY NOT NULL,
    route_id    TEXT,
    decision_id TEXT NOT NULL,
    delta_json  TEXT NOT NULL,
    recorded_at TEXT NOT NULL
) STRICT;
CREATE INDEX route_consents_route ON route_consents(route_id);

-- The runner's admission authority generation (ADR-0012 §2.3 items 3-5): one row. The
-- serve child admits only under a lease for the current generation; a client tombstone or
-- an enrollment change moves it.
CREATE TABLE remote_authority_generation (
    id         INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    generation INTEGER NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- Transport key references (ADR-0012 §2.4): the platform-store item holding K_iroh
-- (`store_kind`: `keychain`, `dpapi` or `secret_service`; `store_ref`: the item's locator),
-- never the key. `state` is `active` or `destroyed`.
CREATE TABLE transport_keys (
    endpoint_id  TEXT PRIMARY KEY NOT NULL,
    store_kind   TEXT NOT NULL,
    store_ref    TEXT NOT NULL,
    state        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    destroyed_at TEXT
) STRICT;
