BEGIN TRANSACTION;
CREATE TABLE binding_holders (
    binding     TEXT PRIMARY KEY NOT NULL REFERENCES bindings(id),
    holder_json TEXT NOT NULL
) STRICT;
CREATE TABLE bindings (
    id          TEXT PRIMARY KEY NOT NULL,
    environment TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    work_id     TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    released_at TEXT
, owner_json TEXT, profile TEXT, profile_revision INTEGER, scope_json TEXT, mechanism TEXT, parent TEXT, state TEXT NOT NULL DEFAULT 'active', context_json TEXT) STRICT;
CREATE TABLE credential_instances (
    id          TEXT PRIMARY KEY NOT NULL,
    grant_id    TEXT NOT NULL,
    state       TEXT NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE decision_cooldowns (
    key         TEXT PRIMARY KEY NOT NULL,
    policy_id   TEXT NOT NULL,
    until       TEXT NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE decisions (
    id          TEXT PRIMARY KEY NOT NULL,
    kind_json   TEXT NOT NULL,
    generation  INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    state       TEXT NOT NULL,
    decided_at  TEXT,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE destinations (
    id          TEXT PRIMARY KEY NOT NULL,
    alias       TEXT NOT NULL UNIQUE,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE enrollments (
    id             TEXT PRIMARY KEY NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL REFERENCES issuers(ca_fingerprint),
    form           TEXT NOT NULL,
    marker         TEXT NOT NULL UNIQUE,
    state          TEXT NOT NULL,
    verified_at    TEXT,
    removal_origin_set INTEGER NOT NULL DEFAULT 0 CHECK (removal_origin_set IN (0, 1)),
    record_json    TEXT NOT NULL
) STRICT;
CREATE TABLE environments (
    id          TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
INSERT INTO "environments" VALUES('env_edd10270a988a33d8c6afc6bc4b9d8e1','{"id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","device":"dev_31653864396234636236636661366338","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_5c2673584655931610cd4d48393f6f36','env_edd10270a988a33d8c6afc6bc4b9d8e1','runtime_lifecycle',NULL,'2026-11-24T07:56:08.320215000Z','{"schema_version":"1","event_id":"evt_5c2673584655931610cd4d48393f6f36","type":"runtime_lifecycle","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","timestamp":"2026-11-24T07:56:08.320215Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_13153b3df2a6fcb023832b3d15465a90','env_edd10270a988a33d8c6afc6bc4b9d8e1','operation_state_changed','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.400766000Z','{"schema_version":"1","event_id":"evt_13153b3df2a6fcb023832b3d15465a90","type":"operation_state_changed","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","operation_id":"op_71627c0f970c34f774a8cb88ead81366","resource":{"kind":"operation","id":"op_71627c0f970c34f774a8cb88ead81366"},"timestamp":"2026-11-24T07:56:08.400766Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_9ac15cb2296bf49259cf50b274e49470','env_edd10270a988a33d8c6afc6bc4b9d8e1','operation_state_changed','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.403255000Z','{"schema_version":"1","event_id":"evt_9ac15cb2296bf49259cf50b274e49470","type":"operation_state_changed","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","operation_id":"op_71627c0f970c34f774a8cb88ead81366","resource":{"kind":"operation","id":"op_71627c0f970c34f774a8cb88ead81366"},"timestamp":"2026-11-24T07:56:08.403255Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_453b0bf6557845fb1548fee224507670','env_edd10270a988a33d8c6afc6bc4b9d8e1','grant_state_changed','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.405154000Z','{"schema_version":"1","event_id":"evt_453b0bf6557845fb1548fee224507670","type":"grant_state_changed","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","operation_id":"op_71627c0f970c34f774a8cb88ead81366","resource":{"kind":"grant","id":"grant_0fc8cd8e962a8c1e316cad5b6d221455"},"timestamp":"2026-11-24T07:56:08.405154Z","cursor":"","payload":{"grant_id":"grant_0fc8cd8e962a8c1e316cad5b6d221455","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_9a231321b76fd60e1e2b8201a42afe38','env_edd10270a988a33d8c6afc6bc4b9d8e1','grant_state_changed','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.411628000Z','{"schema_version":"1","event_id":"evt_9a231321b76fd60e1e2b8201a42afe38","type":"grant_state_changed","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","operation_id":"op_71627c0f970c34f774a8cb88ead81366","resource":{"kind":"grant","id":"grant_0fc8cd8e962a8c1e316cad5b6d221455"},"timestamp":"2026-11-24T07:56:08.411628Z","cursor":"","payload":{"grant_id":"grant_0fc8cd8e962a8c1e316cad5b6d221455","state":"cancelled"}}');
INSERT INTO "events" VALUES(6,'evt_c1431366d25878b8d975ee1cb0d4995e','env_edd10270a988a33d8c6afc6bc4b9d8e1','operation_state_changed','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.411794000Z','{"schema_version":"1","event_id":"evt_c1431366d25878b8d975ee1cb0d4995e","type":"operation_state_changed","environment_id":"env_edd10270a988a33d8c6afc6bc4b9d8e1","operation_id":"op_71627c0f970c34f774a8cb88ead81366","resource":{"kind":"operation","id":"op_71627c0f970c34f774a8cb88ead81366"},"timestamp":"2026-11-24T07:56:08.411794Z","cursor":"","payload":{"code":"OPERATION_CANCELLED","effect_status":"partial","kind":"ensure","state":"cancelled"}}');
CREATE TABLE foreign_removals (
    id            TEXT PRIMARY KEY NOT NULL,
    marker        TEXT NOT NULL,
    local_alias   TEXT NOT NULL,
    account       TEXT NOT NULL,
    ca_public_key TEXT NOT NULL,
    line_sha256   TEXT NOT NULL,
    state         TEXT NOT NULL,
    operation_id  TEXT NOT NULL,
    record_json   TEXT NOT NULL
) STRICT;
CREATE TABLE grant_anchors (
    grant_id      TEXT PRIMARY KEY NOT NULL,
    record_json   TEXT NOT NULL,
    boot_id       TEXT NOT NULL,
    budget_end_ns INTEGER NOT NULL,
    bound         TEXT NOT NULL
) STRICT;
INSERT INTO "grant_anchors" VALUES('grant_0fc8cd8e962a8c1e316cad5b6d221455','{"grant":"grant_0fc8cd8e962a8c1e316cad5b6d221455","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081130,"nanos":896405458},"wall":"2026-11-24T07:56:08.405722Z"},"bound":"2026-11-24T09:56:08.402809Z","budget_end":{"secs":1088330,"nanos":893492458}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088330893492458,'2026-11-24T09:56:08.402809000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_0fc8cd8e962a8c1e316cad5b6d221455','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:11.413392Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
CREATE TABLE grants (
    id                 TEXT PRIMARY KEY NOT NULL,
    environment        TEXT NOT NULL,
    parent             TEXT REFERENCES grants(id),
    state              TEXT NOT NULL,
    starts_at          TEXT NOT NULL,
    deadline_effective TEXT NOT NULL,
    deadline_json      TEXT NOT NULL,
    scope_json         TEXT NOT NULL,
    generation         INTEGER NOT NULL,
    record_json        TEXT NOT NULL,
    updated_at         TEXT NOT NULL
, approval_json TEXT, origin_json TEXT) STRICT;
INSERT INTO "grants" VALUES('grant_0fc8cd8e962a8c1e316cad5b6d221455','env_edd10270a988a33d8c6afc6bc4b9d8e1',NULL,'cancelled','2026-11-24T07:56:08.404861000Z','2026-11-24T09:56:08.402809000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:08.402809Z","effective":"2026-11-24T09:56:08.402809Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_0fc8cd8e962a8c1e316cad5b6d221455","environment":"env_edd10270a988a33d8c6afc6bc4b9d8e1","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:08.404861Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:08.402809Z","effective":"2026-11-24T09:56:08.402809Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"cancelled","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:56:08.404861000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"policy_id":"pol"}');
CREATE TABLE "idempotency" (
    caller_json  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    PRIMARY KEY (caller_json, kind, request_id)
) STRICT;
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r-s','1521d1a2c455dbff4d162502bc4832a980181f38c86801868b439d81e0fea2c1','op_71627c0f970c34f774a8cb88ead81366','2026-11-24T07:56:08.400284000Z','2026-12-01T07:56:08.411109000Z');
CREATE TABLE idempotency_markers (
    key_hash     TEXT PRIMARY KEY NOT NULL,
    expired_at   TEXT NOT NULL,
    marker_until TEXT NOT NULL
) STRICT;
CREATE TABLE identities (
    id          TEXT PRIMARY KEY NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE interaction_declarations (
    identity    TEXT PRIMARY KEY NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE issuance_log (
    id           TEXT PRIMARY KEY NOT NULL,
    grant_id     TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    state        TEXT NOT NULL,
    valid_before TEXT NOT NULL,
    reserved_at  TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE TABLE issuers (
    ca_fingerprint       TEXT PRIMARY KEY NOT NULL,
    public_key           TEXT NOT NULL,
    state                TEXT NOT NULL,
    store_kind           TEXT NOT NULL,
    backup_sha256        TEXT NOT NULL,
    backup_created_at    TEXT NOT NULL,
    restored_without_log INTEGER NOT NULL,
    created_at           TEXT NOT NULL,
    retired_at           TEXT,
    record_json          TEXT NOT NULL
) STRICT;
CREATE TABLE managed_environments (
    environment_id TEXT PRIMARY KEY NOT NULL,
    controller     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    state          TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;
CREATE TABLE managed_slots (
    environment_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    binding_id     TEXT REFERENCES bindings(id),
    generation     INTEGER NOT NULL,
    state          TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (environment_id, destination_id, account)
) STRICT;
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:56:08.411109000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081130,"nanos":901793083},"wall":"2026-11-24T07:56:08.411109Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtestde3c379f1d94070ec97da6dc74eae874');
INSERT INTO "meta" VALUES('self_environment_id','env_edd10270a988a33d8c6afc6bc4b9d8e1');
INSERT INTO "meta" VALUES('authority_generation','3');
INSERT INTO "meta" VALUES('cleanup_intent_version','2');
CREATE TABLE operations (
    id            TEXT PRIMARY KEY NOT NULL,
    kind          TEXT NOT NULL,
    environment   TEXT NOT NULL,
    caller_json   TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    effect_class  TEXT NOT NULL,
    state         TEXT NOT NULL,
    code          TEXT,
    effect_status TEXT NOT NULL,
    result_json   TEXT,
    record_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    terminal_at   TEXT
) STRICT;
INSERT INTO "operations" VALUES('op_71627c0f970c34f774a8cb88ead81366','ensure','env_edd10270a988a33d8c6afc6bc4b9d8e1','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r-s','1521d1a2c455dbff4d162502bc4832a980181f38c86801868b439d81e0fea2c1','local_resources','cancelled','OPERATION_CANCELLED','partial','{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}}','{"id":"op_71627c0f970c34f774a8cb88ead81366","kind":"ensure","environment":"env_edd10270a988a33d8c6afc6bc4b9d8e1","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r-s"},"request_hash":"1521d1a2c455dbff4d162502bc4832a980181f38c86801868b439d81e0fea2c1","effect_class":"local_resources","state":"cancelled","code":"OPERATION_CANCELLED","effect_status":"partial","result":{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}},"created_at":"2026-11-24T07:56:08.400284Z","updated_at":"2026-11-24T07:56:08.411109Z","cancellation":{"requested_at":"2026-11-24T07:56:08.411109Z","may_have_external_effect":true},"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:08.400284000Z','2026-11-24T07:56:08.411109000Z','2026-11-24T07:56:08.411109000Z');
CREATE TABLE owned_connections (
    id           TEXT PRIMARY KEY NOT NULL,
    binding_id   TEXT NOT NULL REFERENCES bindings(id),
    grant_id     TEXT NOT NULL REFERENCES grants(id),
    kind         TEXT NOT NULL,
    pid          INTEGER NOT NULL,
    start_token  TEXT NOT NULL,
    image        TEXT NOT NULL,
    control_path TEXT,
    generation   INTEGER NOT NULL,
    state        TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE TABLE pair_preferences (
    destination_id        TEXT NOT NULL,
    account               TEXT NOT NULL,
    mechanism             TEXT NOT NULL,
    projection_state      TEXT NOT NULL,
    projection_generation INTEGER,
    issuing_cas_json      TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (destination_id, account)
) STRICT;
CREATE TABLE policies (
    id            TEXT PRIMARY KEY NOT NULL,
    revision      INTEGER NOT NULL,
    record_json   TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;
INSERT INTO "policies" VALUES('pol',1,'{"id":"pol","revision":1,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_edd10270a988a33d8c6afc6bc4b9d8e1"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_edd10270a988a33d8c6afc6bc4b9d8e1"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
CREATE TABLE policy_history (
    policy_id   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY (policy_id, revision)
) STRICT;
CREATE TABLE profile_snapshots (
    profile     TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (profile, revision)
) STRICT;
INSERT INTO "profile_snapshots" VALUES('dev',1,'{"id":"dev","revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"},{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}}');
INSERT INTO "profile_snapshots" VALUES('ops',1,'{"id":"ops","revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}}');
CREATE TABLE profiles (
    id          TEXT PRIMARY KEY NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
INSERT INTO "profiles" VALUES('dev',1,'{"id":"dev","revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"},{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"label":null}','');
INSERT INTO "profiles" VALUES('ops',1,'{"id":"ops","revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"label":null}','');
CREATE TABLE projection_consent (
    environment TEXT NOT NULL,
    item        TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (environment, item)
) STRICT;
CREATE TABLE projection_records (
    environment TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE recovery_intents (
    operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "recovery_intents" VALUES('op_71627c0f970c34f774a8cb88ead81366','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r-s","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"async"},"work_id":"w-s"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:08.402809Z","effective":"2026-11-24T09:56:08.402809Z"},"policy_revision":1,"generation":3,"grant":"grant_0fc8cd8e962a8c1e316cad5b6d221455","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
CREATE TABLE resources (
    id             TEXT PRIMARY KEY NOT NULL,
    kind           TEXT NOT NULL,
    owner_json     TEXT NOT NULL,
    generation     INTEGER NOT NULL,
    desired        TEXT NOT NULL,
    observed       TEXT NOT NULL,
    locator        TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;
CREATE TABLE slot_references (
    environment_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    binding_id     TEXT NOT NULL REFERENCES bindings(id),
    deadline       TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    PRIMARY KEY (environment_id, destination_id, account, binding_id)
) STRICT;
CREATE TABLE stage_receipts (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (operation_id, ordinal)
) STRICT;
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:08.400284Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:08.402088Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:08.402809Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:08.40416Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:08.405722Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_b703d980f38375e3a20a67ed95d47561"}}');
INSERT INTO "stage_receipts" VALUES('op_71627c0f970c34f774a8cb88ead81366',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:11.413392Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE TABLE verification_issuance (
    id             TEXT PRIMARY KEY NOT NULL,
    operation_id   TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    account        TEXT NOT NULL,
    purpose        TEXT NOT NULL,
    state          TEXT NOT NULL,
    valid_before   TEXT NOT NULL,
    reserved_at    TEXT NOT NULL,
    record_json    TEXT NOT NULL
) STRICT;
CREATE TABLE work_stops (
    environment TEXT NOT NULL,
    work_id     TEXT NOT NULL,
    stopped_at  TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (environment, work_id)
) STRICT;
CREATE TABLE workspaces (
    id          TEXT PRIMARY KEY NOT NULL,
    environment TEXT NOT NULL,
    root        TEXT NOT NULL,
    state       TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;
CREATE TABLE wsl_distributions (
    guid        TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
CREATE INDEX operations_state ON operations(state);
CREATE INDEX operations_terminal_at ON operations(terminal_at);
CREATE INDEX grants_deadline ON grants(deadline_effective, state);
CREATE INDEX grants_parent ON grants(parent);
CREATE INDEX bindings_work ON bindings(environment, work_id);
CREATE INDEX resources_reconcile ON resources(desired, observed);
CREATE INDEX events_env_seq ON events(environment, seq);
CREATE INDEX events_operation ON events(operation_id);
CREATE INDEX idempotency_expires_at ON idempotency(expires_at);
CREATE INDEX idempotency_operation ON idempotency(operation_id);
CREATE INDEX idempotency_markers_until ON idempotency_markers(marker_until);
CREATE INDEX decisions_state ON decisions(state, created_at);
CREATE INDEX bindings_grant ON bindings(grant_id);
CREATE INDEX bindings_parent ON bindings(parent);
CREATE INDEX issuance_log_grant_state ON issuance_log(grant_id, state);
CREATE INDEX credential_instances_grant ON credential_instances(grant_id);
CREATE INDEX operations_environment_kind ON operations(environment, kind);
CREATE UNIQUE INDEX enrollments_open_pair_ca
    ON enrollments(destination_id, account, ca_fingerprint)
    WHERE state IN ('planned', 'applying', 'outcome_unknown', 'applied_unverified',
                    'manual_pending', 'verifying', 'verified', 'reverifying', 'held')
      AND NOT (state = 'held' AND removal_origin_set = 1);
CREATE INDEX enrollments_pair ON enrollments(destination_id, account);
CREATE INDEX enrollments_ca ON enrollments(ca_fingerprint);
CREATE INDEX enrollments_state ON enrollments(state);
CREATE INDEX foreign_removals_marker ON foreign_removals(marker);
CREATE INDEX verification_issuance_pair_state
    ON verification_issuance(destination_id, account, state);
CREATE INDEX verification_issuance_operation ON verification_issuance(operation_id);
CREATE INDEX managed_slots_binding ON managed_slots(binding_id);
CREATE INDEX owned_connections_grant ON owned_connections(grant_id);
CREATE INDEX owned_connections_binding ON owned_connections(binding_id);
CREATE INDEX managed_environments_state ON managed_environments(state);
CREATE INDEX workspaces_environment ON workspaces(environment);
CREATE INDEX decision_cooldowns_policy ON decision_cooldowns(policy_id);
CREATE INDEX slot_references_binding ON slot_references(binding_id);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('events',6);
COMMIT;
