-- Heimdall state store, schema version 11 (M06 wave 3: paired clients' Iroh endpoint IDs;
-- ADR-0012 §2.3 item 1, §3.9 item 5 and §3.11 as amended 2026-11-21; ADR-0006 §18.7 item 1).
-- Runs inside the migration step's one transaction together with `PRAGMA user_version = 11`;
-- either all of it applies or none of it does.
--
-- This step adds one table and two columns. It rewrites no existing row and backfills nothing.
--
-- `remote_client_endpoints` is the serve allowlist's durable source: one row per paired
-- client, the endpoint ID (64 lowercase hex, public) that client sent over its own K_mgmt
-- session, in `join` or in its rotation form, or that the bootstrap owner's `remote init`
-- carried. It is written only for a client admitted over Iroh (`remote_clients.
-- iroh_admission`); a replacement moves `remote_authority_generation` in the same
-- transaction; the client's revocation deletes the row in the tombstone's transaction. No
-- two clients share an endpoint ID.
CREATE TABLE remote_client_endpoints (
    client_id   TEXT PRIMARY KEY NOT NULL REFERENCES remote_clients(client_id),
    endpoint_id TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL
) STRICT;

-- Whether the invitation admits its client over Iroh (`Invite.iroh_admission`; part of the
-- invitation's exact request, so the runner-local widening decision confirms it). Every
-- existing invitation admits none.
ALTER TABLE remote_invitations ADD COLUMN iroh_admission INTEGER NOT NULL DEFAULT 0;

-- Whether the client itself is admitted over Iroh (ADR-0006 §18.7 item 8: admission is an
-- attribute of the client as well as of the invitation). `join` copies the invitation's
-- value; the bootstrap owner's is set by `remote init --iroh-endpoint`, confirmed on the
-- runner's terminal. A client's first endpoint is recorded only when this is 1. Every
-- existing client is admitted to none.
ALTER TABLE remote_clients ADD COLUMN iroh_admission INTEGER NOT NULL DEFAULT 0;
