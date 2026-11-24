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
, owner_json TEXT, profile TEXT, profile_revision INTEGER, scope_json TEXT, mechanism TEXT, parent TEXT, state TEXT NOT NULL DEFAULT 'active') STRICT;
INSERT INTO "bindings" VALUES('binding_4febde2a9fc7db1339d76808dcbe38bc','env_fdb8efc1dca86f6a70c525e3c8096704','grant_1039cb880de151ec0684b5aac3de0b6d','w-u','{"id":"binding_4febde2a9fc7db1339d76808dcbe38bc","environment":"env_fdb8efc1dca86f6a70c525e3c8096704","grant":"grant_1039cb880de151ec0684b5aac3de0b6d","work_id":"w-u","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:52:31.776236Z","released_at":null,"state":"active"}','2026-11-24T07:52:31.776236000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active');
CREATE TABLE credential_instances (
    id          TEXT PRIMARY KEY NOT NULL,
    grant_id    TEXT NOT NULL,
    state       TEXT NOT NULL,
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
CREATE TABLE environments (
    id          TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
INSERT INTO "environments" VALUES('env_fdb8efc1dca86f6a70c525e3c8096704','{"id":"env_fdb8efc1dca86f6a70c525e3c8096704","device":"dev_34303736393038633365353235633037","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_ee4344326d4251d9f03d5b5e3718b439','env_fdb8efc1dca86f6a70c525e3c8096704','runtime_lifecycle',NULL,'2026-11-24T07:52:31.693282000Z','{"schema_version":"1","event_id":"evt_ee4344326d4251d9f03d5b5e3718b439","type":"runtime_lifecycle","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","timestamp":"2026-11-24T07:52:31.693282Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_4a440ca693e3237f4bbebfe33f229c6b','env_fdb8efc1dca86f6a70c525e3c8096704','operation_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.734686000Z','{"schema_version":"1","event_id":"evt_4a440ca693e3237f4bbebfe33f229c6b","type":"operation_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"operation","id":"op_876cf9941dd06eaca4cbd5be5b3d4585"},"timestamp":"2026-11-24T07:52:31.734686Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_1a1bda6fd4ec63683e23e9c268bb04e3','env_fdb8efc1dca86f6a70c525e3c8096704','operation_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.737345000Z','{"schema_version":"1","event_id":"evt_1a1bda6fd4ec63683e23e9c268bb04e3","type":"operation_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"operation","id":"op_876cf9941dd06eaca4cbd5be5b3d4585"},"timestamp":"2026-11-24T07:52:31.737345Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_b100a0cf656655f02d61e56e8d4e62fc','env_fdb8efc1dca86f6a70c525e3c8096704','grant_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.740025000Z','{"schema_version":"1","event_id":"evt_b100a0cf656655f02d61e56e8d4e62fc","type":"grant_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"grant","id":"grant_1039cb880de151ec0684b5aac3de0b6d"},"timestamp":"2026-11-24T07:52:31.740025Z","cursor":"","payload":{"grant_id":"grant_1039cb880de151ec0684b5aac3de0b6d","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_33369e63cae398c95df18a0c9e55113c','env_fdb8efc1dca86f6a70c525e3c8096704','operation_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.747799000Z','{"schema_version":"1","event_id":"evt_33369e63cae398c95df18a0c9e55113c","type":"operation_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"operation","id":"op_876cf9941dd06eaca4cbd5be5b3d4585"},"timestamp":"2026-11-24T07:52:31.747799Z","cursor":"","payload":{"code":"OUTCOME_UNKNOWN","effect_status":"unknown","kind":"ensure","state":"outcome_unknown"}}');
INSERT INTO "events" VALUES(6,'evt_47d7b079ec9cb297ca76b916fd57b6cf','env_fdb8efc1dca86f6a70c525e3c8096704','grant_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.776719000Z','{"schema_version":"1","event_id":"evt_47d7b079ec9cb297ca76b916fd57b6cf","type":"grant_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"grant","id":"grant_1039cb880de151ec0684b5aac3de0b6d"},"timestamp":"2026-11-24T07:52:31.776719Z","cursor":"","payload":{"grant_id":"grant_1039cb880de151ec0684b5aac3de0b6d","state":"active"}}');
INSERT INTO "events" VALUES(7,'evt_cd3b4967a514b6cb03b3c5248b3da62b','env_fdb8efc1dca86f6a70c525e3c8096704','operation_state_changed','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.777256000Z','{"schema_version":"1","event_id":"evt_cd3b4967a514b6cb03b3c5248b3da62b","type":"operation_state_changed","environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","operation_id":"op_876cf9941dd06eaca4cbd5be5b3d4585","resource":{"kind":"operation","id":"op_876cf9941dd06eaca4cbd5be5b3d4585"},"timestamp":"2026-11-24T07:52:31.777256Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
CREATE TABLE grant_anchors (
    grant_id      TEXT PRIMARY KEY NOT NULL,
    record_json   TEXT NOT NULL,
    boot_id       TEXT NOT NULL,
    budget_end_ns INTEGER NOT NULL,
    bound         TEXT NOT NULL
) STRICT;
INSERT INTO "grant_anchors" VALUES('grant_1039cb880de151ec0684b5aac3de0b6d','{"grant":"grant_1039cb880de151ec0684b5aac3de0b6d","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080914,"nanos":233744375},"wall":"2026-11-24T07:52:31.740735Z"},"bound":"2026-11-24T09:52:31.736786Z","budget_end":{"secs":1088114,"nanos":229795166}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088114229795166,'2026-11-24T09:52:31.736786000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_1039cb880de151ec0684b5aac3de0b6d','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:52:31.763485Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_4febde2a9fc7db1339d76808dcbe38bc','grant_1039cb880de151ec0684b5aac3de0b6d','2026-11-24T07:52:31.776236000Z');
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
INSERT INTO "grants" VALUES('grant_1039cb880de151ec0684b5aac3de0b6d','env_fdb8efc1dca86f6a70c525e3c8096704',NULL,'active','2026-11-24T07:52:31.739765000Z','2026-11-24T09:52:31.736786000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:31.736786Z","effective":"2026-11-24T09:52:31.736786Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_1039cb880de151ec0684b5aac3de0b6d","environment":"env_fdb8efc1dca86f6a70c525e3c8096704","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:31.739765Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:31.736786Z","effective":"2026-11-24T09:52:31.736786Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"active","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:52:31.739765000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r-u','a385c5f92e734abbada193ee60126754452632f4dbabe97d82a180481baacb62','op_876cf9941dd06eaca4cbd5be5b3d4585','2026-11-24T07:52:31.732782000Z','2026-12-01T07:52:31.776236000Z');
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
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:52:31.776236000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080914,"nanos":269245166},"wall":"2026-11-24T07:52:31.776236Z"}');
INSERT INTO "meta" VALUES('self_environment_id','env_fdb8efc1dca86f6a70c525e3c8096704');
INSERT INTO "meta" VALUES('authority_generation','3');
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
INSERT INTO "operations" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585','ensure','env_fdb8efc1dca86f6a70c525e3c8096704','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r-u','a385c5f92e734abbada193ee60126754452632f4dbabe97d82a180481baacb62','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_4febde2a9fc7db1339d76808dcbe38bc","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","expires_at":"2026-11-24T09:52:31.736786Z","grant_id":"grant_1039cb880de151ec0684b5aac3de0b6d","offline_until":"2026-11-24T08:52:31.509455Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:31.736786Z"}','{"id":"op_876cf9941dd06eaca4cbd5be5b3d4585","kind":"ensure","environment":"env_fdb8efc1dca86f6a70c525e3c8096704","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r-u"},"request_hash":"a385c5f92e734abbada193ee60126754452632f4dbabe97d82a180481baacb62","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_4febde2a9fc7db1339d76808dcbe38bc","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_fdb8efc1dca86f6a70c525e3c8096704","expires_at":"2026-11-24T09:52:31.736786Z","grant_id":"grant_1039cb880de151ec0684b5aac3de0b6d","offline_until":"2026-11-24T08:52:31.509455Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:31.736786Z"},"created_at":"2026-11-24T07:52:31.732782Z","updated_at":"2026-11-24T07:52:31.776236Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:31.732782000Z','2026-11-24T07:52:31.776236000Z','2026-11-24T07:52:31.776236000Z');
CREATE TABLE policies (
    id            TEXT PRIMARY KEY NOT NULL,
    revision      INTEGER NOT NULL,
    record_json   TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;
INSERT INTO "policies" VALUES('pol',1,'{"id":"pol","revision":1,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_fdb8efc1dca86f6a70c525e3c8096704"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_fdb8efc1dca86f6a70c525e3c8096704"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r-u","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w-u"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:31.736786Z","effective":"2026-11-24T09:52:31.736786Z"},"policy_revision":1,"generation":3,"grant":"grant_1039cb880de151ec0684b5aac3de0b6d","binding":"binding_4febde2a9fc7db1339d76808dcbe38bc","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
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
CREATE TABLE stage_receipts (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    ordinal      INTEGER NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (operation_id, ordinal)
) STRICT;
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:31.732782Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:31.735849Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:31.736786Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:52:31.739076Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:31.740735Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_5e9327022444b1f1205b619fe719dee4"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:31.747415Z","effect":{"kind":"uncertain","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_5e9327022444b1f1205b619fe719dee4"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',7,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:31.763485Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',8,'{"stage":"probe","recorded_at":"2026-11-24T07:52:31.770725Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',9,'{"stage":"recheck","recorded_at":"2026-11-24T07:52:31.774935Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_876cf9941dd06eaca4cbd5be5b3d4585',10,'{"stage":"commit","recorded_at":"2026-11-24T07:52:31.776236Z","effect":{"kind":"not_attempted"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
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
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('events',7);
COMMIT;
