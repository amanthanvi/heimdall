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
INSERT INTO "environments" VALUES('env_93c572dfc7b65b68d6756998b1c9f0ab','{"id":"env_93c572dfc7b65b68d6756998b1c9f0ab","device":"dev_62613066396331623839393635373664","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_feddc3cfbc2a48711cf53a50dae4003a','env_93c572dfc7b65b68d6756998b1c9f0ab','runtime_lifecycle',NULL,'2026-11-24T07:52:28.383989000Z','{"schema_version":"1","event_id":"evt_feddc3cfbc2a48711cf53a50dae4003a","type":"runtime_lifecycle","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","timestamp":"2026-11-24T07:52:28.383989Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_a4a3e81261173614c00dc4f79efca9fa','env_93c572dfc7b65b68d6756998b1c9f0ab','operation_state_changed','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.407141000Z','{"schema_version":"1","event_id":"evt_a4a3e81261173614c00dc4f79efca9fa","type":"operation_state_changed","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","operation_id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","resource":{"kind":"operation","id":"op_ed0bdbc815cc43beac2c13ea89a50ec2"},"timestamp":"2026-11-24T07:52:28.407141Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_f5ac25c36ebc632ad48118932b072c96','env_93c572dfc7b65b68d6756998b1c9f0ab','operation_state_changed','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.410033000Z','{"schema_version":"1","event_id":"evt_f5ac25c36ebc632ad48118932b072c96","type":"operation_state_changed","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","operation_id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","resource":{"kind":"operation","id":"op_ed0bdbc815cc43beac2c13ea89a50ec2"},"timestamp":"2026-11-24T07:52:28.410033Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_de96042afced6ecbaac3d76a318b43e3','env_93c572dfc7b65b68d6756998b1c9f0ab','grant_state_changed','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.421150000Z','{"schema_version":"1","event_id":"evt_de96042afced6ecbaac3d76a318b43e3","type":"grant_state_changed","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","operation_id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","resource":{"kind":"grant","id":"grant_281a798ff45b426e3aeff4ce940a426f"},"timestamp":"2026-11-24T07:52:28.42115Z","cursor":"","payload":{"grant_id":"grant_281a798ff45b426e3aeff4ce940a426f","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_c19ac3d26f16f17a6636c44df1617e0c','env_93c572dfc7b65b68d6756998b1c9f0ab','grant_state_changed','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.426064000Z','{"schema_version":"1","event_id":"evt_c19ac3d26f16f17a6636c44df1617e0c","type":"grant_state_changed","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","operation_id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","resource":{"kind":"grant","id":"grant_281a798ff45b426e3aeff4ce940a426f"},"timestamp":"2026-11-24T07:52:28.426064Z","cursor":"","payload":{"grant_id":"grant_281a798ff45b426e3aeff4ce940a426f","state":"cancelled"}}');
INSERT INTO "events" VALUES(6,'evt_111bc267933765e326ffa3b10f68190a','env_93c572dfc7b65b68d6756998b1c9f0ab','operation_state_changed','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.426311000Z','{"schema_version":"1","event_id":"evt_111bc267933765e326ffa3b10f68190a","type":"operation_state_changed","environment_id":"env_93c572dfc7b65b68d6756998b1c9f0ab","operation_id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","resource":{"kind":"operation","id":"op_ed0bdbc815cc43beac2c13ea89a50ec2"},"timestamp":"2026-11-24T07:52:28.426311Z","cursor":"","payload":{"code":"OPERATION_CANCELLED","effect_status":"partial","kind":"ensure","state":"cancelled"}}');
CREATE TABLE grant_anchors (
    grant_id      TEXT PRIMARY KEY NOT NULL,
    record_json   TEXT NOT NULL,
    boot_id       TEXT NOT NULL,
    budget_end_ns INTEGER NOT NULL,
    bound         TEXT NOT NULL
) STRICT;
INSERT INTO "grant_anchors" VALUES('grant_281a798ff45b426e3aeff4ce940a426f','{"grant":"grant_281a798ff45b426e3aeff4ce940a426f","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080910,"nanos":917825875},"wall":"2026-11-24T07:52:28.424781Z"},"bound":"2026-11-24T09:52:28.409424Z","budget_end":{"secs":1088110,"nanos":902468875}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088110902468875,'2026-11-24T09:52:28.409424000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_281a798ff45b426e3aeff4ce940a426f','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:52:31.439991Z"}');
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
INSERT INTO "grants" VALUES('grant_281a798ff45b426e3aeff4ce940a426f','env_93c572dfc7b65b68d6756998b1c9f0ab',NULL,'cancelled','2026-11-24T07:52:28.420429000Z','2026-11-24T09:52:28.409424000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:28.409424Z","effective":"2026-11-24T09:52:28.409424Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_281a798ff45b426e3aeff4ce940a426f","environment":"env_93c572dfc7b65b68d6756998b1c9f0ab","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:28.420429Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:28.409424Z","effective":"2026-11-24T09:52:28.409424Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"cancelled","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:52:28.420429000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r-s','d859c4557013766d1b65cfe058d019f19ea26c3fdbbdb97f1299e152ed64910a','op_ed0bdbc815cc43beac2c13ea89a50ec2','2026-11-24T07:52:28.406484000Z','2026-12-01T07:52:28.421607000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:52:28.424781000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080910,"nanos":917825875},"wall":"2026-11-24T07:52:28.424781Z"}');
INSERT INTO "meta" VALUES('self_environment_id','env_93c572dfc7b65b68d6756998b1c9f0ab');
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
INSERT INTO "operations" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2','ensure','env_93c572dfc7b65b68d6756998b1c9f0ab','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r-s','d859c4557013766d1b65cfe058d019f19ea26c3fdbbdb97f1299e152ed64910a','local_resources','cancelled','OPERATION_CANCELLED','partial','{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}}','{"id":"op_ed0bdbc815cc43beac2c13ea89a50ec2","kind":"ensure","environment":"env_93c572dfc7b65b68d6756998b1c9f0ab","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r-s"},"request_hash":"d859c4557013766d1b65cfe058d019f19ea26c3fdbbdb97f1299e152ed64910a","effect_class":"local_resources","state":"cancelled","code":"OPERATION_CANCELLED","effect_status":"partial","result":{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}},"created_at":"2026-11-24T07:52:28.406484Z","updated_at":"2026-11-24T07:52:28.421607Z","cancellation":{"requested_at":"2026-11-24T07:52:28.421607Z","may_have_external_effect":true},"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:28.406484000Z','2026-11-24T07:52:28.421607000Z','2026-11-24T07:52:28.421607000Z');
CREATE TABLE policies (
    id            TEXT PRIMARY KEY NOT NULL,
    revision      INTEGER NOT NULL,
    record_json   TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;
INSERT INTO "policies" VALUES('pol',1,'{"id":"pol","revision":1,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_93c572dfc7b65b68d6756998b1c9f0ab"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_93c572dfc7b65b68d6756998b1c9f0ab"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r-s","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"async"},"work_id":"w-s"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:28.409424Z","effective":"2026-11-24T09:52:28.409424Z"},"policy_revision":1,"generation":3,"grant":"grant_281a798ff45b426e3aeff4ce940a426f","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
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
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:28.406484Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:28.408696Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:28.409424Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:52:28.411097Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:28.424781Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_2a2bcc5e130241b9ad44d61f032ac08d"}}');
INSERT INTO "stage_receipts" VALUES('op_ed0bdbc815cc43beac2c13ea89a50ec2',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:31.439991Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
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
INSERT INTO "sqlite_sequence" VALUES('events',6);
COMMIT;
