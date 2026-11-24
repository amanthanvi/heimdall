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
CREATE TABLE destination_routes (
    route_id    TEXT PRIMARY KEY NOT NULL,
    destination TEXT NOT NULL,
    position    INTEGER NOT NULL,
    route_json  TEXT NOT NULL,
    created_at  TEXT NOT NULL
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
INSERT INTO "environments" VALUES('env_b21093b5c84880a5762165411ccc3fe4','{"id":"env_b21093b5c84880a5762165411ccc3fe4","device":"dev_34656633636363313134353631323637","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_4d0d23a8efeb2e7b5e79db7f0c652e91','env_b21093b5c84880a5762165411ccc3fe4','runtime_lifecycle',NULL,'2026-11-24T11:20:55.126781000Z','{"schema_version":"1","event_id":"evt_4d0d23a8efeb2e7b5e79db7f0c652e91","type":"runtime_lifecycle","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","timestamp":"2026-11-24T11:20:55.126781Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_71b7a54c18fc5a7648c0e6f2c65b00c7','env_b21093b5c84880a5762165411ccc3fe4','operation_state_changed','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.320550000Z','{"schema_version":"1","event_id":"evt_71b7a54c18fc5a7648c0e6f2c65b00c7","type":"operation_state_changed","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","operation_id":"op_eb0edafea7ed140c79c6dcdc39c55257","resource":{"kind":"operation","id":"op_eb0edafea7ed140c79c6dcdc39c55257"},"timestamp":"2026-11-24T11:20:55.32055Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_fa10e35379a590b6484b1c10c9dd9124','env_b21093b5c84880a5762165411ccc3fe4','operation_state_changed','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.332758000Z','{"schema_version":"1","event_id":"evt_fa10e35379a590b6484b1c10c9dd9124","type":"operation_state_changed","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","operation_id":"op_eb0edafea7ed140c79c6dcdc39c55257","resource":{"kind":"operation","id":"op_eb0edafea7ed140c79c6dcdc39c55257"},"timestamp":"2026-11-24T11:20:55.332758Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_ef2ad3bfc7acdcc95aae2a6b370c7f7f','env_b21093b5c84880a5762165411ccc3fe4','grant_state_changed','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.334976000Z','{"schema_version":"1","event_id":"evt_ef2ad3bfc7acdcc95aae2a6b370c7f7f","type":"grant_state_changed","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","operation_id":"op_eb0edafea7ed140c79c6dcdc39c55257","resource":{"kind":"grant","id":"grant_5612e5dac95f2b224c063ec082fc758b"},"timestamp":"2026-11-24T11:20:55.334976Z","cursor":"","payload":{"grant_id":"grant_5612e5dac95f2b224c063ec082fc758b","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_edc4f3c992d21f77ad828290429fb0a8','env_b21093b5c84880a5762165411ccc3fe4','grant_state_changed','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.342657000Z','{"schema_version":"1","event_id":"evt_edc4f3c992d21f77ad828290429fb0a8","type":"grant_state_changed","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","operation_id":"op_eb0edafea7ed140c79c6dcdc39c55257","resource":{"kind":"grant","id":"grant_5612e5dac95f2b224c063ec082fc758b"},"timestamp":"2026-11-24T11:20:55.342657Z","cursor":"","payload":{"grant_id":"grant_5612e5dac95f2b224c063ec082fc758b","state":"cancelled"}}');
INSERT INTO "events" VALUES(6,'evt_1b721b1e617095c330309805e15619e8','env_b21093b5c84880a5762165411ccc3fe4','operation_state_changed','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.342843000Z','{"schema_version":"1","event_id":"evt_1b721b1e617095c330309805e15619e8","type":"operation_state_changed","environment_id":"env_b21093b5c84880a5762165411ccc3fe4","operation_id":"op_eb0edafea7ed140c79c6dcdc39c55257","resource":{"kind":"operation","id":"op_eb0edafea7ed140c79c6dcdc39c55257"},"timestamp":"2026-11-24T11:20:55.342843Z","cursor":"","payload":{"code":"OPERATION_CANCELLED","effect_status":"partial","kind":"ensure","state":"cancelled"}}');
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
INSERT INTO "grant_anchors" VALUES('grant_5612e5dac95f2b224c063ec082fc758b','{"grant":"grant_5612e5dac95f2b224c063ec082fc758b","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1093417,"nanos":693358416},"wall":"2026-11-24T11:20:55.338308Z"},"bound":"2026-11-24T13:20:55.33206Z","budget_end":{"secs":1100617,"nanos":687110416}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1100617687110416,'2026-11-24T13:20:55.332060000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_5612e5dac95f2b224c063ec082fc758b','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T11:20:58.344537Z"}');
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
INSERT INTO "grants" VALUES('grant_5612e5dac95f2b224c063ec082fc758b','env_b21093b5c84880a5762165411ccc3fe4',NULL,'cancelled','2026-11-24T11:20:55.334436000Z','2026-11-24T13:20:55.332060000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:55.33206Z","effective":"2026-11-24T13:20:55.33206Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_5612e5dac95f2b224c063ec082fc758b","environment":"env_b21093b5c84880a5762165411ccc3fe4","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T11:20:55.334436Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:55.33206Z","effective":"2026-11-24T13:20:55.33206Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"cancelled","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T11:20:55.334436000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"policy_id":"pol"}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r-s','72820813bedd786d7afa826ab4171053bbca98f05d4b89b15000e4877f839d54','op_eb0edafea7ed140c79c6dcdc39c55257','2026-11-24T11:20:55.318491000Z','2026-12-01T11:20:55.342053000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T11:20:55.342053000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1093417,"nanos":697103625},"wall":"2026-11-24T11:20:55.342053Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtest9846f719feaf623be8f2ca9c2815bba4');
INSERT INTO "meta" VALUES('self_environment_id','env_b21093b5c84880a5762165411ccc3fe4');
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
INSERT INTO "operations" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257','ensure','env_b21093b5c84880a5762165411ccc3fe4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r-s','72820813bedd786d7afa826ab4171053bbca98f05d4b89b15000e4877f839d54','local_resources','cancelled','OPERATION_CANCELLED','partial','{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}}','{"id":"op_eb0edafea7ed140c79c6dcdc39c55257","kind":"ensure","environment":"env_b21093b5c84880a5762165411ccc3fe4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r-s"},"request_hash":"72820813bedd786d7afa826ab4171053bbca98f05d4b89b15000e4877f839d54","effect_class":"local_resources","state":"cancelled","code":"OPERATION_CANCELLED","effect_status":"partial","result":{"error":{"code":"OPERATION_CANCELLED","effect_status":"partial","message":"the operation was cancelled","next":{"action":"none"},"retryable":false}},"created_at":"2026-11-24T11:20:55.318491Z","updated_at":"2026-11-24T11:20:55.342053Z","cancellation":{"requested_at":"2026-11-24T11:20:55.342053Z","may_have_external_effect":true},"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:55.318491000Z','2026-11-24T11:20:55.342053000Z','2026-11-24T11:20:55.342053000Z');
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
INSERT INTO "policies" VALUES('pol',1,'{"id":"pol","revision":1,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_b21093b5c84880a5762165411ccc3fe4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_b21093b5c84880a5762165411ccc3fe4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r-s","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"async"},"work_id":"w-s"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:55.33206Z","effective":"2026-11-24T13:20:55.33206Z"},"policy_revision":1,"generation":3,"grant":"grant_5612e5dac95f2b224c063ec082fc758b","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
CREATE TABLE remote_authority_generation (
    id         INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    generation INTEGER NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE remote_client_endpoints (
    client_id   TEXT PRIMARY KEY NOT NULL REFERENCES remote_clients(client_id),
    endpoint_id TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL
) STRICT;
CREATE TABLE remote_clients (
    client_id          TEXT PRIMARY KEY NOT NULL,
    role               TEXT NOT NULL,
    key_fingerprint    TEXT NOT NULL,
    state              TEXT NOT NULL,
    invitation_id      TEXT,
    revoked_generation INTEGER,
    record_json        TEXT NOT NULL,
    updated_at         TEXT NOT NULL
, iroh_admission INTEGER NOT NULL DEFAULT 0) STRICT;
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
CREATE TABLE remote_environment_pins (
    environment_id   TEXT PRIMARY KEY NOT NULL,
    destination      TEXT NOT NULL,
    account          TEXT NOT NULL,
    host_fingerprint TEXT NOT NULL,
    record_json      TEXT NOT NULL,
    pinned_at        TEXT NOT NULL
) STRICT;
CREATE TABLE remote_grant_issuers (
    grant_id       TEXT PRIMARY KEY NOT NULL,
    issuer_client  TEXT NOT NULL,
    ca_fingerprint TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    pinned_at      TEXT NOT NULL
) STRICT;
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
, iroh_admission INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE remote_lift_acks (
    environment       TEXT NOT NULL,
    producer          TEXT NOT NULL,
    effect_id         TEXT NOT NULL,
    target_kind       TEXT NOT NULL,
    target_ref        TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    acknowledged_at   TEXT NOT NULL,
    PRIMARY KEY (producer, effect_id, target_kind, target_ref, target_generation)
) STRICT;
CREATE TABLE remote_policy_revisions (
    scope_key   TEXT NOT NULL,
    producer    TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    runner_seq  INTEGER NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    effect_id   TEXT NOT NULL,
    received_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (scope_key, producer, revision)
) STRICT;
CREATE TABLE "remote_widening" (
    decision_id  TEXT PRIMARY KEY NOT NULL REFERENCES decisions(id),
    origin       TEXT NOT NULL DEFAULT 'paired' CHECK (origin IN ('local', 'paired')),
    client_id    TEXT,
    request_kind TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    result_json  TEXT,
    delta_digest TEXT,
    UNIQUE (client_id, request_kind, request_id),
    CHECK (
        (origin = 'paired' AND client_id IS NOT NULL AND delta_digest IS NULL)
        OR (origin = 'local' AND client_id IS NULL AND delta_digest IS NOT NULL)
    )
) STRICT;
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
CREATE TABLE route_consents (
    consent_id  TEXT PRIMARY KEY NOT NULL,
    route_id    TEXT,
    decision_id TEXT NOT NULL,
    delta_json  TEXT NOT NULL,
    recorded_at TEXT NOT NULL
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
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',1,'{"stage":"authenticate","recorded_at":"2026-11-24T11:20:55.318491Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',2,'{"stage":"load_authority","recorded_at":"2026-11-24T11:20:55.331072Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T11:20:55.33206Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',4,'{"stage":"coalesce","recorded_at":"2026-11-24T11:20:55.33353Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',5,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:55.338308Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_f42903ab2c7362cda0100721ac8bb3d3"}}');
INSERT INTO "stage_receipts" VALUES('op_eb0edafea7ed140c79c6dcdc39c55257',6,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:58.344537Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
CREATE TABLE transport_keys (
    endpoint_id  TEXT PRIMARY KEY NOT NULL,
    store_kind   TEXT NOT NULL,
    store_ref    TEXT NOT NULL,
    state        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    destroyed_at TEXT
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
CREATE INDEX remote_clients_key ON remote_clients(key_fingerprint);
CREATE INDEX remote_invitations_client ON remote_invitations(client_id);
CREATE INDEX remote_effect_outbox_pending ON remote_effect_outbox(environment, state);
CREATE UNIQUE INDEX destination_routes_order ON destination_routes(destination, position);
CREATE INDEX route_consents_route ON route_consents(route_id);
CREATE INDEX remote_widening_local ON remote_widening (request_kind, delta_digest)
    WHERE origin = 'local';
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('events',6);
COMMIT;
