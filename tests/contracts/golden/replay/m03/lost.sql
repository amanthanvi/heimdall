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
INSERT INTO "bindings" VALUES('binding_f2de515283ed1b570b4fb29134be0999','env_5a6c84cd01e5c37fe6bffff38c0189bc','grant_5923d7e9445ac4ea1e7dd16b72dacc18','w-u','{"id":"binding_f2de515283ed1b570b4fb29134be0999","environment":"env_5a6c84cd01e5c37fe6bffff38c0189bc","grant":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","work_id":"w-u","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:56:07.485032Z","released_at":null,"state":"active"}','2026-11-24T07:56:07.485032000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active');
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
INSERT INTO "environments" VALUES('env_5a6c84cd01e5c37fe6bffff38c0189bc','{"id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","device":"dev_63623938313063383366666666623665","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_bf652ab27913b49304bbc36df5375bd3','env_5a6c84cd01e5c37fe6bffff38c0189bc','runtime_lifecycle',NULL,'2026-11-24T07:56:07.379071000Z','{"schema_version":"1","event_id":"evt_bf652ab27913b49304bbc36df5375bd3","type":"runtime_lifecycle","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","timestamp":"2026-11-24T07:56:07.379071Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_d09c11bc12eb3f325a6d1ea90547a7a8','env_5a6c84cd01e5c37fe6bffff38c0189bc','operation_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.465303000Z','{"schema_version":"1","event_id":"evt_d09c11bc12eb3f325a6d1ea90547a7a8","type":"operation_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"operation","id":"op_03f8f1dea93ac6df81746f71a3c4207e"},"timestamp":"2026-11-24T07:56:07.465303Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_479b1678a90dc45e8dbe5e8499118884','env_5a6c84cd01e5c37fe6bffff38c0189bc','operation_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.466628000Z','{"schema_version":"1","event_id":"evt_479b1678a90dc45e8dbe5e8499118884","type":"operation_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"operation","id":"op_03f8f1dea93ac6df81746f71a3c4207e"},"timestamp":"2026-11-24T07:56:07.466628Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_c723ca8e7d84768062b1af8138dd0d44','env_5a6c84cd01e5c37fe6bffff38c0189bc','grant_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.467484000Z','{"schema_version":"1","event_id":"evt_c723ca8e7d84768062b1af8138dd0d44","type":"grant_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"grant","id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18"},"timestamp":"2026-11-24T07:56:07.467484Z","cursor":"","payload":{"grant_id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_79dad4232b955c6d049dbce602a48831','env_5a6c84cd01e5c37fe6bffff38c0189bc','operation_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.472848000Z','{"schema_version":"1","event_id":"evt_79dad4232b955c6d049dbce602a48831","type":"operation_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"operation","id":"op_03f8f1dea93ac6df81746f71a3c4207e"},"timestamp":"2026-11-24T07:56:07.472848Z","cursor":"","payload":{"code":"OUTCOME_UNKNOWN","effect_status":"unknown","kind":"ensure","state":"outcome_unknown"}}');
INSERT INTO "events" VALUES(6,'evt_8ce1e88f0d34b80af82737eacf112942','env_5a6c84cd01e5c37fe6bffff38c0189bc','grant_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.485311000Z','{"schema_version":"1","event_id":"evt_8ce1e88f0d34b80af82737eacf112942","type":"grant_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"grant","id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18"},"timestamp":"2026-11-24T07:56:07.485311Z","cursor":"","payload":{"grant_id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","state":"active"}}');
INSERT INTO "events" VALUES(7,'evt_c1f4c733ab62638b2abd2e3280913065','env_5a6c84cd01e5c37fe6bffff38c0189bc','operation_state_changed','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.485649000Z','{"schema_version":"1","event_id":"evt_c1f4c733ab62638b2abd2e3280913065","type":"operation_state_changed","environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","operation_id":"op_03f8f1dea93ac6df81746f71a3c4207e","resource":{"kind":"operation","id":"op_03f8f1dea93ac6df81746f71a3c4207e"},"timestamp":"2026-11-24T07:56:07.485649Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
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
INSERT INTO "grant_anchors" VALUES('grant_5923d7e9445ac4ea1e7dd16b72dacc18','{"grant":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081129,"nanos":958415041},"wall":"2026-11-24T07:56:07.46772Z"},"bound":"2026-11-24T09:56:07.466288Z","budget_end":{"secs":1088329,"nanos":956982125}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088329956982125,'2026-11-24T09:56:07.466288000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_5923d7e9445ac4ea1e7dd16b72dacc18','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:07.483791Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_f2de515283ed1b570b4fb29134be0999','grant_5923d7e9445ac4ea1e7dd16b72dacc18','2026-11-24T07:56:07.485032000Z');
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
INSERT INTO "grants" VALUES('grant_5923d7e9445ac4ea1e7dd16b72dacc18','env_5a6c84cd01e5c37fe6bffff38c0189bc',NULL,'active','2026-11-24T07:56:07.467268000Z','2026-11-24T09:56:07.466288000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.466288Z","effective":"2026-11-24T09:56:07.466288Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","environment":"env_5a6c84cd01e5c37fe6bffff38c0189bc","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:07.467268Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.466288Z","effective":"2026-11-24T09:56:07.466288Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"active","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:56:07.467268000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r-u','82f02a2806bcc3e92b0cbec36687bddcb95c36bbdb339f37f2272883b11edb5f','op_03f8f1dea93ac6df81746f71a3c4207e','2026-11-24T07:56:07.464673000Z','2026-12-01T07:56:07.485032000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:56:07.485032000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081129,"nanos":975726583},"wall":"2026-11-24T07:56:07.485032Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtest6a3bc82b336c8d778d247df2c9fe1e1e');
INSERT INTO "meta" VALUES('self_environment_id','env_5a6c84cd01e5c37fe6bffff38c0189bc');
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
INSERT INTO "operations" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e','ensure','env_5a6c84cd01e5c37fe6bffff38c0189bc','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r-u','82f02a2806bcc3e92b0cbec36687bddcb95c36bbdb339f37f2272883b11edb5f','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_f2de515283ed1b570b4fb29134be0999","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","expires_at":"2026-11-24T09:56:07.466288Z","grant_id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","offline_until":"2026-11-24T08:56:07.247047Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.466288Z"}','{"id":"op_03f8f1dea93ac6df81746f71a3c4207e","kind":"ensure","environment":"env_5a6c84cd01e5c37fe6bffff38c0189bc","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r-u"},"request_hash":"82f02a2806bcc3e92b0cbec36687bddcb95c36bbdb339f37f2272883b11edb5f","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_f2de515283ed1b570b4fb29134be0999","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_5a6c84cd01e5c37fe6bffff38c0189bc","expires_at":"2026-11-24T09:56:07.466288Z","grant_id":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","offline_until":"2026-11-24T08:56:07.247047Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.466288Z"},"created_at":"2026-11-24T07:56:07.464673Z","updated_at":"2026-11-24T07:56:07.485032Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:07.464673000Z','2026-11-24T07:56:07.485032000Z','2026-11-24T07:56:07.485032000Z');
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
INSERT INTO "policies" VALUES('pol',1,'{"id":"pol","revision":1,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_5a6c84cd01e5c37fe6bffff38c0189bc"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_5a6c84cd01e5c37fe6bffff38c0189bc"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r-u","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w-u"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.466288Z","effective":"2026-11-24T09:56:07.466288Z"},"policy_revision":1,"generation":3,"grant":"grant_5923d7e9445ac4ea1e7dd16b72dacc18","binding":"binding_f2de515283ed1b570b4fb29134be0999","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
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
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:07.464673Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:07.465972Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:07.466288Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:07.466993Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.46772Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_ae3ccb6819c1d1f5a3b4bcd8f5c747d8"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.472596Z","effect":{"kind":"uncertain","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_ae3ccb6819c1d1f5a3b4bcd8f5c747d8"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',7,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.483791Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',8,'{"stage":"probe","recorded_at":"2026-11-24T07:56:07.484168Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',9,'{"stage":"recheck","recorded_at":"2026-11-24T07:56:07.484477Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_03f8f1dea93ac6df81746f71a3c4207e',10,'{"stage":"commit","recorded_at":"2026-11-24T07:56:07.485032Z","effect":{"kind":"not_attempted"}}');
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
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('events',7);
COMMIT;
