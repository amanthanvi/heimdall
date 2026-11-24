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
INSERT INTO "bindings" VALUES('binding_3ea20e4f5fd064195a9ffb97164f6b0e','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_88e76346414ee63e97c834be5e56ce37','w1','{"id":"binding_3ea20e4f5fd064195a9ffb97164f6b0e","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","grant":"grant_88e76346414ee63e97c834be5e56ce37","work_id":"w1","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T11:20:54.763179Z","released_at":"2026-11-24T11:20:54.970399Z","state":"released"}','2026-11-24T11:20:54.763179000Z','2026-11-24T11:20:54.970399000Z','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'released','{"kind":"personal"}');
INSERT INTO "bindings" VALUES('binding_06c3e015416d372b78bf84369279f0bd','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_1ae0a6f65459ec5971081bcd91f9cd01','w4','{"id":"binding_06c3e015416d372b78bf84369279f0bd","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","grant":"grant_1ae0a6f65459ec5971081bcd91f9cd01","work_id":"w4","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T11:20:54.868834Z","released_at":null,"state":"active"}','2026-11-24T11:20:54.868834000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active','{"kind":"personal"}');
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
INSERT INTO "decisions" VALUES('dec_e369c795828a3f099629ecc21f824aa1','{"kind":"approve_authority","operation":"op_bb3360e384ee2d6d94dc72d704bf7a90","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T11:20:54.800630000Z','2026-11-24T11:35:54.800630000Z','pending',NULL,'{"id":"dec_e369c795828a3f099629ecc21f824aa1","kind":{"kind":"approve_authority","operation":"op_bb3360e384ee2d6d94dc72d704bf7a90","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T11:20:54.80063Z","expires_at":"2026-11-24T11:35:54.80063Z","state":"pending","decided_at":null}');
INSERT INTO "decisions" VALUES('dec_dd1ce20d6505d1096a1b2d154ddbe518','{"kind":"approve_authority","operation":"op_590e2b3cc090963408e9b60ee9380763","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T11:20:54.815152000Z','2026-11-24T11:35:54.815152000Z','denied','2026-11-24T11:20:54.829876000Z','{"id":"dec_dd1ce20d6505d1096a1b2d154ddbe518","kind":{"kind":"approve_authority","operation":"op_590e2b3cc090963408e9b60ee9380763","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T11:20:54.815152Z","expires_at":"2026-11-24T11:35:54.815152Z","state":"denied","decided_at":"2026-11-24T11:20:54.829876Z"}');
INSERT INTO "decisions" VALUES('dec_d28ccfaea3d13e96909507b601ec27fd','{"kind":"approve_authority","operation":"op_11dea9b26b30927a9497ebdae78d6e1f","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T11:20:54.843738000Z','2026-11-24T11:35:54.843738000Z','approved','2026-11-24T11:20:54.858689000Z','{"id":"dec_d28ccfaea3d13e96909507b601ec27fd","kind":{"kind":"approve_authority","operation":"op_11dea9b26b30927a9497ebdae78d6e1f","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T11:20:54.843738Z","expires_at":"2026-11-24T11:35:54.843738Z","state":"approved","decided_at":"2026-11-24T11:20:54.858689Z"}');
INSERT INTO "decisions" VALUES('dec_d025cb0a6d8c5547b75b5a7afc7021a0','{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}}',4,'2026-11-24T11:20:54.894307000Z','2026-11-24T11:35:54.894307000Z','approved','2026-11-24T11:20:54.906406000Z','{"id":"dec_d025cb0a6d8c5547b75b5a7afc7021a0","kind":{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}},"generation":4,"created_at":"2026-11-24T11:20:54.894307Z","expires_at":"2026-11-24T11:35:54.894307Z","state":"approved","decided_at":"2026-11-24T11:20:54.906406Z"}');
INSERT INTO "decisions" VALUES('dec_0628ef2f6c3a701362abf3cd605ac793','{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}}',6,'2026-11-24T11:20:54.927607000Z','2026-11-24T11:35:54.927607000Z','pending',NULL,'{"id":"dec_0628ef2f6c3a701362abf3cd605ac793","kind":{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}},"generation":6,"created_at":"2026-11-24T11:20:54.927607Z","expires_at":"2026-11-24T11:35:54.927607Z","state":"pending","decided_at":null}');
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
INSERT INTO "environments" VALUES('env_6ce8f39b5b4e7b872a799e547a1b4d74','{"id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","device":"dev_34376434623161373435653939376132","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_ce29586fd06d7566d8edb7959353339d','env_6ce8f39b5b4e7b872a799e547a1b4d74','runtime_lifecycle',NULL,'2026-11-24T11:20:54.575470000Z','{"schema_version":"1","event_id":"evt_ce29586fd06d7566d8edb7959353339d","type":"runtime_lifecycle","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","timestamp":"2026-11-24T11:20:54.57547Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_305971dade2f9944cc4a82c44d50b809','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.746257000Z','{"schema_version":"1","event_id":"evt_305971dade2f9944cc4a82c44d50b809","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_d4a89dfe5f859cceb5389ee921653044","resource":{"kind":"operation","id":"op_d4a89dfe5f859cceb5389ee921653044"},"timestamp":"2026-11-24T11:20:54.746257Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_ce23df85157140a76f0f4f02c9dc2c2e','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.753216000Z','{"schema_version":"1","event_id":"evt_ce23df85157140a76f0f4f02c9dc2c2e","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_d4a89dfe5f859cceb5389ee921653044","resource":{"kind":"operation","id":"op_d4a89dfe5f859cceb5389ee921653044"},"timestamp":"2026-11-24T11:20:54.753216Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_80f353b4aa3b6b83c481c53ef6b9f1eb','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.755594000Z','{"schema_version":"1","event_id":"evt_80f353b4aa3b6b83c481c53ef6b9f1eb","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_d4a89dfe5f859cceb5389ee921653044","resource":{"kind":"grant","id":"grant_88e76346414ee63e97c834be5e56ce37"},"timestamp":"2026-11-24T11:20:54.755594Z","cursor":"","payload":{"grant_id":"grant_88e76346414ee63e97c834be5e56ce37","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_d5dca2820d26e8e85cee32aaeb2da525','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.763471000Z','{"schema_version":"1","event_id":"evt_d5dca2820d26e8e85cee32aaeb2da525","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_d4a89dfe5f859cceb5389ee921653044","resource":{"kind":"grant","id":"grant_88e76346414ee63e97c834be5e56ce37"},"timestamp":"2026-11-24T11:20:54.763471Z","cursor":"","payload":{"grant_id":"grant_88e76346414ee63e97c834be5e56ce37","state":"active"}}');
INSERT INTO "events" VALUES(6,'evt_aa0260c7996d56ceaf37fc9ae28804b2','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.763943000Z','{"schema_version":"1","event_id":"evt_aa0260c7996d56ceaf37fc9ae28804b2","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_d4a89dfe5f859cceb5389ee921653044","resource":{"kind":"operation","id":"op_d4a89dfe5f859cceb5389ee921653044"},"timestamp":"2026-11-24T11:20:54.763943Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(7,'evt_8a8db5f162954c0b3b868f9547114972','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_bb3360e384ee2d6d94dc72d704bf7a90','2026-11-24T11:20:54.799423000Z','{"schema_version":"1","event_id":"evt_8a8db5f162954c0b3b868f9547114972","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_bb3360e384ee2d6d94dc72d704bf7a90","resource":{"kind":"operation","id":"op_bb3360e384ee2d6d94dc72d704bf7a90"},"timestamp":"2026-11-24T11:20:54.799423Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(8,'evt_ade9f676690ee80f573fc61173358751','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_bb3360e384ee2d6d94dc72d704bf7a90','2026-11-24T11:20:54.801188000Z','{"schema_version":"1","event_id":"evt_ade9f676690ee80f573fc61173358751","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_bb3360e384ee2d6d94dc72d704bf7a90","resource":{"kind":"grant","id":"grant_cb1deeba84c25b217106a7760587d4de"},"timestamp":"2026-11-24T11:20:54.801188Z","cursor":"","payload":{"grant_id":"grant_cb1deeba84c25b217106a7760587d4de","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(9,'evt_dec6130a6f69936750f3f93d604d8475','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision','op_bb3360e384ee2d6d94dc72d704bf7a90','2026-11-24T11:20:54.801380000Z','{"schema_version":"1","event_id":"evt_dec6130a6f69936750f3f93d604d8475","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_bb3360e384ee2d6d94dc72d704bf7a90","resource":{"kind":"decision","id":"dec_e369c795828a3f099629ecc21f824aa1"},"timestamp":"2026-11-24T11:20:54.80138Z","cursor":"","payload":{"decision_id":"dec_e369c795828a3f099629ecc21f824aa1","expires_at":"2026-11-24T11:35:54.80063Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(10,'evt_464cb0195350a88448b1b42f2557cb36','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_bb3360e384ee2d6d94dc72d704bf7a90','2026-11-24T11:20:54.801601000Z','{"schema_version":"1","event_id":"evt_464cb0195350a88448b1b42f2557cb36","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_bb3360e384ee2d6d94dc72d704bf7a90","resource":{"kind":"operation","id":"op_bb3360e384ee2d6d94dc72d704bf7a90"},"timestamp":"2026-11-24T11:20:54.801601Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(11,'evt_6e430e6c64ea3a2e359f2848b5a13fb7','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.814127000Z','{"schema_version":"1","event_id":"evt_6e430e6c64ea3a2e359f2848b5a13fb7","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"operation","id":"op_590e2b3cc090963408e9b60ee9380763"},"timestamp":"2026-11-24T11:20:54.814127Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(12,'evt_a704fbf243a3a014b89629ba6591e84c','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.815658000Z','{"schema_version":"1","event_id":"evt_a704fbf243a3a014b89629ba6591e84c","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"grant","id":"grant_3857b890ed570ade0d6333dced6b5338"},"timestamp":"2026-11-24T11:20:54.815658Z","cursor":"","payload":{"grant_id":"grant_3857b890ed570ade0d6333dced6b5338","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(13,'evt_5a46c26e5996dc5ae488f5ce6837dc98','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.815739000Z','{"schema_version":"1","event_id":"evt_5a46c26e5996dc5ae488f5ce6837dc98","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"decision","id":"dec_dd1ce20d6505d1096a1b2d154ddbe518"},"timestamp":"2026-11-24T11:20:54.815739Z","cursor":"","payload":{"decision_id":"dec_dd1ce20d6505d1096a1b2d154ddbe518","expires_at":"2026-11-24T11:35:54.815152Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(14,'evt_411b6484c4e37b72d6e787f9b942d6b7','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.815908000Z','{"schema_version":"1","event_id":"evt_411b6484c4e37b72d6e787f9b942d6b7","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"operation","id":"op_590e2b3cc090963408e9b60ee9380763"},"timestamp":"2026-11-24T11:20:54.815908Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(15,'evt_5ebb4b6cd9e6959c289d8632b322b53d','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.831057000Z','{"schema_version":"1","event_id":"evt_5ebb4b6cd9e6959c289d8632b322b53d","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"decision","id":"dec_dd1ce20d6505d1096a1b2d154ddbe518"},"timestamp":"2026-11-24T11:20:54.831057Z","cursor":"","payload":{"decision_id":"dec_dd1ce20d6505d1096a1b2d154ddbe518","expires_at":"2026-11-24T11:35:54.815152Z","kind":"approve_authority","state":"denied"}}');
INSERT INTO "events" VALUES(16,'evt_27e11b906ddc6b89a5ae5f06c650637e','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.831289000Z','{"schema_version":"1","event_id":"evt_27e11b906ddc6b89a5ae5f06c650637e","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"grant","id":"grant_3857b890ed570ade0d6333dced6b5338"},"timestamp":"2026-11-24T11:20:54.831289Z","cursor":"","payload":{"grant_id":"grant_3857b890ed570ade0d6333dced6b5338","state":"denied"}}');
INSERT INTO "events" VALUES(17,'evt_baf5f5472f4a81589a524b3a94d4b2d7','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.831447000Z','{"schema_version":"1","event_id":"evt_baf5f5472f4a81589a524b3a94d4b2d7","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_590e2b3cc090963408e9b60ee9380763","resource":{"kind":"operation","id":"op_590e2b3cc090963408e9b60ee9380763"},"timestamp":"2026-11-24T11:20:54.831447Z","cursor":"","payload":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","kind":"ensure","state":"failed"}}');
INSERT INTO "events" VALUES(18,'evt_47543d6a6a2263131180fd34d5e836ab','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.842691000Z','{"schema_version":"1","event_id":"evt_47543d6a6a2263131180fd34d5e836ab","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"operation","id":"op_11dea9b26b30927a9497ebdae78d6e1f"},"timestamp":"2026-11-24T11:20:54.842691Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(19,'evt_22f4f761da4a8098acd0e09b79be29fc','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.844278000Z','{"schema_version":"1","event_id":"evt_22f4f761da4a8098acd0e09b79be29fc","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:54.844278Z","cursor":"","payload":{"grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(20,'evt_fbcec0d86124868ce78fb5e0988f472f','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.844361000Z','{"schema_version":"1","event_id":"evt_fbcec0d86124868ce78fb5e0988f472f","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"decision","id":"dec_d28ccfaea3d13e96909507b601ec27fd"},"timestamp":"2026-11-24T11:20:54.844361Z","cursor":"","payload":{"decision_id":"dec_d28ccfaea3d13e96909507b601ec27fd","expires_at":"2026-11-24T11:35:54.843738Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(21,'evt_7c1d7ff20fcf798b0ab7c2c5156593bc','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.844532000Z','{"schema_version":"1","event_id":"evt_7c1d7ff20fcf798b0ab7c2c5156593bc","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"operation","id":"op_11dea9b26b30927a9497ebdae78d6e1f"},"timestamp":"2026-11-24T11:20:54.844532Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(22,'evt_efe4421ecd957b7f72570e55a6ba0087','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.859206000Z','{"schema_version":"1","event_id":"evt_efe4421ecd957b7f72570e55a6ba0087","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"decision","id":"dec_d28ccfaea3d13e96909507b601ec27fd"},"timestamp":"2026-11-24T11:20:54.859206Z","cursor":"","payload":{"decision_id":"dec_d28ccfaea3d13e96909507b601ec27fd","expires_at":"2026-11-24T11:35:54.843738Z","kind":"approve_authority","state":"approved"}}');
INSERT INTO "events" VALUES(23,'evt_e0ec32d3b9c558a702adc7c48efc11d4','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.859507000Z','{"schema_version":"1","event_id":"evt_e0ec32d3b9c558a702adc7c48efc11d4","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:54.859507Z","cursor":"","payload":{"grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","state":"preparing"}}');
INSERT INTO "events" VALUES(24,'evt_6ab2d01d501e28014a77434e56e9ce1e','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.859787000Z','{"schema_version":"1","event_id":"evt_6ab2d01d501e28014a77434e56e9ce1e","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"operation","id":"op_11dea9b26b30927a9497ebdae78d6e1f"},"timestamp":"2026-11-24T11:20:54.859787Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(25,'evt_9dfc9552241c54858ba02b2ac26018fd','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.869219000Z','{"schema_version":"1","event_id":"evt_9dfc9552241c54858ba02b2ac26018fd","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:54.869219Z","cursor":"","payload":{"grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","state":"active"}}');
INSERT INTO "events" VALUES(26,'evt_ea2153a48c84cc6c04f28d3255aa07ef','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.869993000Z','{"schema_version":"1","event_id":"evt_ea2153a48c84cc6c04f28d3255aa07ef","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f","resource":{"kind":"operation","id":"op_11dea9b26b30927a9497ebdae78d6e1f"},"timestamp":"2026-11-24T11:20:54.869993Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(27,'evt_bf8739653f3a29e66d0332c23fc9e78b','env_6ce8f39b5b4e7b872a799e547a1b4d74','policy_changed',NULL,'2026-11-24T11:20:54.882800000Z','{"schema_version":"1","event_id":"evt_bf8739653f3a29e66d0332c23fc9e78b","type":"policy_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T11:20:54.8828Z","cursor":"","payload":{"cutoff_at":null,"paused":true,"policy_id":"pol","revision":2}}');
INSERT INTO "events" VALUES(28,'evt_244c85d5c85bd9c6ff5e949bc000bb87','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision',NULL,'2026-11-24T11:20:54.894466000Z','{"schema_version":"1","event_id":"evt_244c85d5c85bd9c6ff5e949bc000bb87","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"decision","id":"dec_d025cb0a6d8c5547b75b5a7afc7021a0"},"timestamp":"2026-11-24T11:20:54.894466Z","cursor":"","payload":{"decision_id":"dec_d025cb0a6d8c5547b75b5a7afc7021a0","expires_at":"2026-11-24T11:35:54.894307Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(29,'evt_e7e00bcb3041923cb5e7fec9fce729b5','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision',NULL,'2026-11-24T11:20:54.906628000Z','{"schema_version":"1","event_id":"evt_e7e00bcb3041923cb5e7fec9fce729b5","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"decision","id":"dec_d025cb0a6d8c5547b75b5a7afc7021a0"},"timestamp":"2026-11-24T11:20:54.906628Z","cursor":"","payload":{"decision_id":"dec_d025cb0a6d8c5547b75b5a7afc7021a0","expires_at":"2026-11-24T11:35:54.894307Z","kind":"widen_policy","state":"approved"}}');
INSERT INTO "events" VALUES(30,'evt_a707767067277f277f12570763bc0e0c','env_6ce8f39b5b4e7b872a799e547a1b4d74','policy_changed',NULL,'2026-11-24T11:20:54.906757000Z','{"schema_version":"1","event_id":"evt_a707767067277f277f12570763bc0e0c","type":"policy_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T11:20:54.906757Z","cursor":"","payload":{"cutoff_at":null,"paused":false,"policy_id":"pol","revision":3}}');
INSERT INTO "events" VALUES(31,'evt_7cdd233df4002e73c66864f2cc8ce782','env_6ce8f39b5b4e7b872a799e547a1b4d74','policy_changed',NULL,'2026-11-24T11:20:54.916944000Z','{"schema_version":"1","event_id":"evt_7cdd233df4002e73c66864f2cc8ce782","type":"policy_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T11:20:54.916944Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":4}}');
INSERT INTO "events" VALUES(32,'evt_b32662e9c13a7c26566604c5d898e923','env_6ce8f39b5b4e7b872a799e547a1b4d74','decision',NULL,'2026-11-24T11:20:54.927761000Z','{"schema_version":"1","event_id":"evt_b32662e9c13a7c26566604c5d898e923","type":"decision","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"decision","id":"dec_0628ef2f6c3a701362abf3cd605ac793"},"timestamp":"2026-11-24T11:20:54.927761Z","cursor":"","payload":{"decision_id":"dec_0628ef2f6c3a701362abf3cd605ac793","expires_at":"2026-11-24T11:35:54.927607Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(33,'evt_6ad150a68d89bffd507475c7e496e3b2','env_6ce8f39b5b4e7b872a799e547a1b4d74','policy_changed',NULL,'2026-11-24T11:20:54.938533000Z','{"schema_version":"1","event_id":"evt_6ad150a68d89bffd507475c7e496e3b2","type":"policy_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T11:20:54.938533Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":5}}');
INSERT INTO "events" VALUES(34,'evt_21aa7f0f50f52948cb2ba6b6e0f49ac0','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_de7d8d170efd9105667c11eb598a81fa','2026-11-24T11:20:54.949438000Z','{"schema_version":"1","event_id":"evt_21aa7f0f50f52948cb2ba6b6e0f49ac0","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_de7d8d170efd9105667c11eb598a81fa","resource":{"kind":"operation","id":"op_de7d8d170efd9105667c11eb598a81fa"},"timestamp":"2026-11-24T11:20:54.949438Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"catalog","state":"queued"}}');
INSERT INTO "events" VALUES(35,'evt_a328dcdd56650bdcaa93d34cc12b76a0','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_de7d8d170efd9105667c11eb598a81fa','2026-11-24T11:20:54.950712000Z','{"schema_version":"1","event_id":"evt_a328dcdd56650bdcaa93d34cc12b76a0","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_de7d8d170efd9105667c11eb598a81fa","resource":{"kind":"operation","id":"op_de7d8d170efd9105667c11eb598a81fa"},"timestamp":"2026-11-24T11:20:54.950712Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"catalog","state":"succeeded"}}');
INSERT INTO "events" VALUES(36,'evt_4191f1b15d97717d983e4b929e61a482','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed',NULL,'2026-11-24T11:20:54.970983000Z','{"schema_version":"1","event_id":"evt_4191f1b15d97717d983e4b929e61a482","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","resource":{"kind":"grant","id":"grant_88e76346414ee63e97c834be5e56ce37"},"timestamp":"2026-11-24T11:20:54.970983Z","cursor":"","payload":{"grant_id":"grant_88e76346414ee63e97c834be5e56ce37","state":"released"}}');
INSERT INTO "events" VALUES(37,'evt_e4e9528dbb9fbe6996699f4fce2259c9','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_6f25111298148c64634bd57e7b4248e2','2026-11-24T11:20:54.980769000Z','{"schema_version":"1","event_id":"evt_e4e9528dbb9fbe6996699f4fce2259c9","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_6f25111298148c64634bd57e7b4248e2","resource":{"kind":"operation","id":"op_6f25111298148c64634bd57e7b4248e2"},"timestamp":"2026-11-24T11:20:54.980769Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(38,'evt_098a795f65cc29a888c9ac83695968e6','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_6f25111298148c64634bd57e7b4248e2','2026-11-24T11:20:54.983994000Z','{"schema_version":"1","event_id":"evt_098a795f65cc29a888c9ac83695968e6","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_6f25111298148c64634bd57e7b4248e2","resource":{"kind":"operation","id":"op_6f25111298148c64634bd57e7b4248e2"},"timestamp":"2026-11-24T11:20:54.983994Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(39,'evt_85f86f6327874cf3a2a53e2371f4dd42','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_6f25111298148c64634bd57e7b4248e2','2026-11-24T11:20:54.985261000Z','{"schema_version":"1","event_id":"evt_85f86f6327874cf3a2a53e2371f4dd42","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_6f25111298148c64634bd57e7b4248e2","resource":{"kind":"operation","id":"op_6f25111298148c64634bd57e7b4248e2"},"timestamp":"2026-11-24T11:20:54.985261Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
INSERT INTO "events" VALUES(40,'evt_0f762060958853eee651440dfe2fd5d3','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:54.996258000Z','{"schema_version":"1","event_id":"evt_0f762060958853eee651440dfe2fd5d3","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"operation","id":"op_b749be3f1524bcd0cbfa47ff1f23ad95"},"timestamp":"2026-11-24T11:20:54.996258Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(41,'evt_629cf4f6a0acac760f02756875189994','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:54.998630000Z','{"schema_version":"1","event_id":"evt_629cf4f6a0acac760f02756875189994","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:54.99863Z","cursor":"","payload":{"grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","state":"revoking"}}');
INSERT INTO "events" VALUES(42,'evt_08a60bcaf0a1da95a53227dd61a12f9e','env_6ce8f39b5b4e7b872a799e547a1b4d74','credential_lifecycle','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:54.998923000Z','{"schema_version":"1","event_id":"evt_08a60bcaf0a1da95a53227dd61a12f9e","type":"credential_lifecycle","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:54.998923Z","cursor":"","payload":{"cause":"revoke","event":"revoked_locally","grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"}}');
INSERT INTO "events" VALUES(43,'evt_03975c6326144be079e889694e5ad27a','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:54.999231000Z','{"schema_version":"1","event_id":"evt_03975c6326144be079e889694e5ad27a","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"operation","id":"op_b749be3f1524bcd0cbfa47ff1f23ad95"},"timestamp":"2026-11-24T11:20:54.999231Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(44,'evt_37f0a37fc1ea90a4d5fbfa1a6f4c4ae5','env_6ce8f39b5b4e7b872a799e547a1b4d74','grant_state_changed','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:55.000240000Z','{"schema_version":"1","event_id":"evt_37f0a37fc1ea90a4d5fbfa1a6f4c4ae5","type":"grant_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"grant","id":"grant_1ae0a6f65459ec5971081bcd91f9cd01"},"timestamp":"2026-11-24T11:20:55.00024Z","cursor":"","payload":{"grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","state":"revoked"}}');
INSERT INTO "events" VALUES(45,'evt_30fa25661e88e76eaa975b80325fe4e4','env_6ce8f39b5b4e7b872a799e547a1b4d74','operation_state_changed','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:55.000549000Z','{"schema_version":"1","event_id":"evt_30fa25661e88e76eaa975b80325fe4e4","type":"operation_state_changed","environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","operation_id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","resource":{"kind":"operation","id":"op_b749be3f1524bcd0cbfa47ff1f23ad95"},"timestamp":"2026-11-24T11:20:55.000549Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
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
INSERT INTO "grant_anchors" VALUES('grant_88e76346414ee63e97c834be5e56ce37','{"grant":"grant_88e76346414ee63e97c834be5e56ce37","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1093417,"nanos":111032500},"wall":"2026-11-24T11:20:54.755976Z"},"bound":"2026-11-24T13:20:54.752009Z","budget_end":{"secs":1100617,"nanos":107065500}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1100617107065500,'2026-11-24T13:20:54.752009000Z');
INSERT INTO "grant_anchors" VALUES('grant_1ae0a6f65459ec5971081bcd91f9cd01','{"grant":"grant_1ae0a6f65459ec5971081bcd91f9cd01","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1093417,"nanos":216929625},"wall":"2026-11-24T11:20:54.861874Z"},"bound":"2026-11-24T13:20:54.843738Z","budget_end":{"secs":1100617,"nanos":198793625}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1100617198793625,'2026-11-24T13:20:54.843738000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_88e76346414ee63e97c834be5e56ce37','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T11:20:54.761114Z"}');
INSERT INTO "grant_prepared_facts" VALUES('grant_1ae0a6f65459ec5971081bcd91f9cd01','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T11:20:54.866814Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_06c3e015416d372b78bf84369279f0bd','grant_1ae0a6f65459ec5971081bcd91f9cd01','2026-11-24T11:20:54.868834000Z');
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
INSERT INTO "grants" VALUES('grant_88e76346414ee63e97c834be5e56ce37','env_6ce8f39b5b4e7b872a799e547a1b4d74',NULL,'released','2026-11-24T11:20:54.754702000Z','2026-11-24T13:20:54.752009000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.752009Z","effective":"2026-11-24T13:20:54.752009Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_88e76346414ee63e97c834be5e56ce37","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T11:20:54.754702Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.752009Z","effective":"2026-11-24T13:20:54.752009Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"released","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T11:20:54.754702000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"policy_id":"pol"}');
INSERT INTO "grants" VALUES('grant_cb1deeba84c25b217106a7760587d4de','env_6ce8f39b5b4e7b872a799e547a1b4d74',NULL,'awaiting_approval','2026-11-24T11:20:54.800630000Z','2026-11-24T13:20:54.800630000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.80063Z","effective":"2026-11-24T13:20:54.80063Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_cb1deeba84c25b217106a7760587d4de","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T11:20:54.80063Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.80063Z","effective":"2026-11-24T13:20:54.80063Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_bb3360e384ee2d6d94dc72d704bf7a90"},"generation":3,"state":"awaiting_approval","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T11:20:54.800630000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_3857b890ed570ade0d6333dced6b5338','env_6ce8f39b5b4e7b872a799e547a1b4d74',NULL,'denied','2026-11-24T11:20:54.815152000Z','2026-11-24T13:20:54.815152000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.815152Z","effective":"2026-11-24T13:20:54.815152Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_3857b890ed570ade0d6333dced6b5338","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T11:20:54.815152Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.815152Z","effective":"2026-11-24T13:20:54.815152Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_590e2b3cc090963408e9b60ee9380763"},"generation":3,"state":"denied","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T11:20:54.815152000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_1ae0a6f65459ec5971081bcd91f9cd01','env_6ce8f39b5b4e7b872a799e547a1b4d74',NULL,'revoked','2026-11-24T11:20:54.843738000Z','2026-11-24T13:20:54.843738000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.843738Z","effective":"2026-11-24T13:20:54.843738Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T11:20:54.843738Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.843738Z","effective":"2026-11-24T13:20:54.843738Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_11dea9b26b30927a9497ebdae78d6e1f"},"generation":3,"state":"revoked","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T11:20:54.843738000Z','{"decision":"dec_d28ccfaea3d13e96909507b601ec27fd","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}','{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r1','0caf3c29109a40dc3b19effb077e167a9044a5b17e1e64ff2c1a80f2bf9efb87','op_d4a89dfe5f859cceb5389ee921653044','2026-11-24T11:20:54.745089000Z','2026-12-01T11:20:54.763179000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r2','317943a207c0bd9b1ef41fda8828e339a75b5d95f5f04ae772bb5ae99f20e6a6','op_bb3360e384ee2d6d94dc72d704bf7a90','2026-11-24T11:20:54.798868000Z',NULL);
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r3','72d3c585b88d8a8015cdef1ba6bd65ed594d6f20079e1a087580d004f970a3e4','op_590e2b3cc090963408e9b60ee9380763','2026-11-24T11:20:54.813706000Z','2026-12-01T11:20:54.829876000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r4','1555cb387ac2645c3ae4c05f31c12bc70405dd61220552b46e6bbd22682bd568','op_11dea9b26b30927a9497ebdae78d6e1f','2026-11-24T11:20:54.842216000Z','2026-12-01T11:20:54.868834000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','catalog','d1','28568f90e9759f121ca2a3ed2b816ecb1c78732c9679f69143c351c1940c6ba9','op_de7d8d170efd9105667c11eb598a81fa','2026-11-24T11:20:54.948953000Z','2026-12-01T11:20:54.949861000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','rv1','2bc5a16d3103671d34a73cce0ba0e314761844cf8f9f9576802c5b7f2ecb9887','op_6f25111298148c64634bd57e7b4248e2','2026-11-24T11:20:54.980181000Z','2026-12-01T11:20:54.981472000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','s1','785a386fa280281be07e44d12f810f1de7500a31398418822ceb143937bab5c1','op_b749be3f1524bcd0cbfa47ff1f23ad95','2026-11-24T11:20:54.995698000Z','2026-12-01T11:20:54.997815000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T11:20:54.999548000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1093417,"nanos":354602041},"wall":"2026-11-24T11:20:54.999548Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtest654a546be7a72985a357d26c8c78f25a');
INSERT INTO "meta" VALUES('self_environment_id','env_6ce8f39b5b4e7b872a799e547a1b4d74');
INSERT INTO "meta" VALUES('authority_generation','10');
INSERT INTO "meta" VALUES('m05.default_profile:env_6ce8f39b5b4e7b872a799e547a1b4d74','dev');
INSERT INTO "meta" VALUES('remote_revocation_claim_seq','2');
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
INSERT INTO "operations" VALUES('op_d4a89dfe5f859cceb5389ee921653044','ensure','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r1','0caf3c29109a40dc3b19effb077e167a9044a5b17e1e64ff2c1a80f2bf9efb87','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_3ea20e4f5fd064195a9ffb97164f6b0e","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","expires_at":"2026-11-24T13:20:54.752009Z","grant_id":"grant_88e76346414ee63e97c834be5e56ce37","offline_until":"2026-11-24T12:20:54.514883Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T13:20:54.752009Z"}','{"id":"op_d4a89dfe5f859cceb5389ee921653044","kind":"ensure","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r1"},"request_hash":"0caf3c29109a40dc3b19effb077e167a9044a5b17e1e64ff2c1a80f2bf9efb87","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_3ea20e4f5fd064195a9ffb97164f6b0e","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","expires_at":"2026-11-24T13:20:54.752009Z","grant_id":"grant_88e76346414ee63e97c834be5e56ce37","offline_until":"2026-11-24T12:20:54.514883Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T13:20:54.752009Z"},"created_at":"2026-11-24T11:20:54.745089Z","updated_at":"2026-11-24T11:20:54.763179Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.745089000Z','2026-11-24T11:20:54.763179000Z','2026-11-24T11:20:54.763179000Z');
INSERT INTO "operations" VALUES('op_bb3360e384ee2d6d94dc72d704bf7a90','ensure','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r2','317943a207c0bd9b1ef41fda8828e339a75b5d95f5f04ae772bb5ae99f20e6a6','local_resources','awaiting_approval',NULL,'none',NULL,'{"id":"op_bb3360e384ee2d6d94dc72d704bf7a90","kind":"ensure","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r2"},"request_hash":"317943a207c0bd9b1ef41fda8828e339a75b5d95f5f04ae772bb5ae99f20e6a6","effect_class":"local_resources","state":"awaiting_approval","code":null,"effect_status":"none","result":null,"created_at":"2026-11-24T11:20:54.798868Z","updated_at":"2026-11-24T11:20:54.80063Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.798868000Z','2026-11-24T11:20:54.800630000Z',NULL);
INSERT INTO "operations" VALUES('op_590e2b3cc090963408e9b60ee9380763','ensure','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r3','72d3c585b88d8a8015cdef1ba6bd65ed594d6f20079e1a087580d004f970a3e4','local_resources','failed','CAPABILITY_UNAVAILABLE','none','{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}}','{"id":"op_590e2b3cc090963408e9b60ee9380763","kind":"ensure","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r3"},"request_hash":"72d3c585b88d8a8015cdef1ba6bd65ed594d6f20079e1a087580d004f970a3e4","effect_class":"local_resources","state":"failed","code":"CAPABILITY_UNAVAILABLE","effect_status":"none","result":{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}},"created_at":"2026-11-24T11:20:54.813706Z","updated_at":"2026-11-24T11:20:54.829876Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.813706000Z','2026-11-24T11:20:54.829876000Z','2026-11-24T11:20:54.829876000Z');
INSERT INTO "operations" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f','ensure','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r4','1555cb387ac2645c3ae4c05f31c12bc70405dd61220552b46e6bbd22682bd568','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_06c3e015416d372b78bf84369279f0bd","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","expires_at":"2026-11-24T13:20:54.843738Z","grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","offline_until":"2026-11-24T12:20:54.514883Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T13:20:54.843738Z"}','{"id":"op_11dea9b26b30927a9497ebdae78d6e1f","kind":"ensure","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r4"},"request_hash":"1555cb387ac2645c3ae4c05f31c12bc70405dd61220552b46e6bbd22682bd568","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_06c3e015416d372b78bf84369279f0bd","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","expires_at":"2026-11-24T13:20:54.843738Z","grant_id":"grant_1ae0a6f65459ec5971081bcd91f9cd01","offline_until":"2026-11-24T12:20:54.514883Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T13:20:54.843738Z"},"created_at":"2026-11-24T11:20:54.842216Z","updated_at":"2026-11-24T11:20:54.868834Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.842216000Z','2026-11-24T11:20:54.868834000Z','2026-11-24T11:20:54.868834000Z');
INSERT INTO "operations" VALUES('op_de7d8d170efd9105667c11eb598a81fa','catalog','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','d1','28568f90e9759f121ca2a3ed2b816ecb1c78732c9679f69143c351c1940c6ba9','local','succeeded','OK','applied','{"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","profile_id":"dev"}','{"id":"op_de7d8d170efd9105667c11eb598a81fa","kind":"catalog","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"catalog","request_id":"d1"},"request_hash":"28568f90e9759f121ca2a3ed2b816ecb1c78732c9679f69143c351c1940c6ba9","effect_class":"local","state":"succeeded","code":"OK","effect_status":"applied","result":{"environment_id":"env_6ce8f39b5b4e7b872a799e547a1b4d74","profile_id":"dev"},"created_at":"2026-11-24T11:20:54.948953Z","updated_at":"2026-11-24T11:20:54.949861Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.948953000Z','2026-11-24T11:20:54.949861000Z','2026-11-24T11:20:54.949861000Z');
INSERT INTO "operations" VALUES('op_6f25111298148c64634bd57e7b4248e2','revoke','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','rv1','2bc5a16d3103671d34a73cce0ba0e314761844cf8f9f9576802c5b7f2ecb9887','local_resources','succeeded','OK','applied','{"committed_at":"2026-11-24T11:20:54.98221Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T11:20:54.980181Z"}','{"id":"op_6f25111298148c64634bd57e7b4248e2","kind":"revoke","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"rv1"},"request_hash":"2bc5a16d3103671d34a73cce0ba0e314761844cf8f9f9576802c5b7f2ecb9887","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"committed_at":"2026-11-24T11:20:54.98221Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T11:20:54.980181Z"},"created_at":"2026-11-24T11:20:54.980181Z","updated_at":"2026-11-24T11:20:54.981472Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.980181000Z','2026-11-24T11:20:54.981472000Z','2026-11-24T11:20:54.981472000Z');
INSERT INTO "operations" VALUES('op_b749be3f1524bcd0cbfa47ff1f23ad95','revoke','env_6ce8f39b5b4e7b872a799e547a1b4d74','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','s1','785a386fa280281be07e44d12f810f1de7500a31398418822ceb143937bab5c1','local_resources','succeeded','OK','applied','{"committed_at":"2026-11-24T11:20:54.998227Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T11:20:54.995698Z"}','{"id":"op_b749be3f1524bcd0cbfa47ff1f23ad95","kind":"revoke","environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"s1"},"request_hash":"785a386fa280281be07e44d12f810f1de7500a31398418822ceb143937bab5c1","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"committed_at":"2026-11-24T11:20:54.998227Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T11:20:54.995698Z"},"created_at":"2026-11-24T11:20:54.995698Z","updated_at":"2026-11-24T11:20:54.997815Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T11:20:54.995698000Z','2026-11-24T11:20:54.997815000Z','2026-11-24T11:20:54.997815000Z');
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
INSERT INTO "policies" VALUES('pol',5,'{"id":"pol","revision":5,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T11:20:54.938415Z"},"lock_behavior":"revoke_on_lock"}','2026-11-24T11:20:54.938415000Z');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
CREATE TABLE policy_history (
    policy_id   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY (policy_id, revision)
) STRICT;
INSERT INTO "policy_history" VALUES('pol',2,'{"policy":"pol","revision":2,"record":{"id":"pol","revision":2,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"paused","since":"2026-11-24T11:20:54.882674Z"},"cutoff_at":null,"source":{"kind":"owner_decision","decided_at":"2026-11-24T11:20:54.882674Z"}},"cause":{"kind":"narrowing"},"at":"2026-11-24T11:20:54.882674Z"}','2026-11-24T11:20:54.882674000Z');
INSERT INTO "policy_history" VALUES('pol',3,'{"policy":"pol","revision":3,"record":{"id":"pol","revision":3,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"owner_decision","decided_at":"2026-11-24T11:20:54.906406Z"}},"cause":{"kind":"decision","decision":"dec_d025cb0a6d8c5547b75b5a7afc7021a0"},"at":"2026-11-24T11:20:54.906406Z"}','2026-11-24T11:20:54.906406000Z');
INSERT INTO "policy_history" VALUES('pol',4,'{"policy":"pol","revision":4,"record":{"id":"pol","revision":4,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T11:20:54.916838Z"}},"cause":{"kind":"narrowing"},"at":"2026-11-24T11:20:54.916838Z"}','2026-11-24T11:20:54.916838000Z');
INSERT INTO "policy_history" VALUES('pol',5,'{"policy":"pol","revision":5,"record":{"id":"pol","revision":5,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6ce8f39b5b4e7b872a799e547a1b4d74"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T11:20:54.938415Z"},"lock_behavior":"revoke_on_lock"},"cause":{"kind":"narrowing"},"at":"2026-11-24T11:20:54.938415Z"}','2026-11-24T11:20:54.938415000Z');
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
INSERT INTO "recovery_intents" VALUES('op_d4a89dfe5f859cceb5389ee921653044','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r1","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w1"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.752009Z","effective":"2026-11-24T13:20:54.752009Z"},"policy_revision":1,"generation":3,"grant":"grant_88e76346414ee63e97c834be5e56ce37","binding":"binding_3ea20e4f5fd064195a9ffb97164f6b0e","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_bb3360e384ee2d6d94dc72d704bf7a90','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r2","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w2"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.80063Z","effective":"2026-11-24T13:20:54.80063Z"},"policy_revision":1,"generation":3,"grant":"grant_cb1deeba84c25b217106a7760587d4de","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_590e2b3cc090963408e9b60ee9380763','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r3","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w3"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.815152Z","effective":"2026-11-24T13:20:54.815152Z"},"policy_revision":1,"generation":3,"grant":"grant_3857b890ed570ade0d6333dced6b5338","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r4","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w4"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T11:20:54.843738Z","effective":"2026-11-24T13:20:54.843738Z"},"policy_revision":1,"generation":3,"grant":"grant_1ae0a6f65459ec5971081bcd91f9cd01","binding":"binding_06c3e015416d372b78bf84369279f0bd","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"approval":{"decision":"dec_d28ccfaea3d13e96909507b601ec27fd","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}}}');
INSERT INTO "recovery_intents" VALUES('op_de7d8d170efd9105667c11eb598a81fa','{"request":{"action":"set_default_profile","profile":"dev","request_id":"d1"},"resolved":null,"local":{"kind":"catalog","action":{"action":"set_default_profile","profile":"dev"}}}');
INSERT INTO "recovery_intents" VALUES('op_6f25111298148c64634bd57e7b4248e2','{"request":{"grant_id":"grant_88e76346414ee63e97c834be5e56ce37","op":"revoke","request_id":"rv1"},"resolved":null}');
INSERT INTO "recovery_intents" VALUES('op_b749be3f1524bcd0cbfa47ff1f23ad95','{"request":{"op":"revoke","request_id":"s1","target":{"environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","kind":"work","work_id":"w4"}},"resolved":null}');
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
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',1,'{"stage":"authenticate","recorded_at":"2026-11-24T11:20:54.745089Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',2,'{"stage":"load_authority","recorded_at":"2026-11-24T11:20:54.750777Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T11:20:54.752009Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',4,'{"stage":"coalesce","recorded_at":"2026-11-24T11:20:54.754196Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',5,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:54.755976Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_7b2eab2b9421bb21da4b4ff2abddee32"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',6,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:54.761114Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',7,'{"stage":"probe","recorded_at":"2026-11-24T11:20:54.762088Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',8,'{"stage":"recheck","recorded_at":"2026-11-24T11:20:54.76248Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d4a89dfe5f859cceb5389ee921653044',9,'{"stage":"commit","recorded_at":"2026-11-24T11:20:54.763179Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_bb3360e384ee2d6d94dc72d704bf7a90',1,'{"stage":"authenticate","recorded_at":"2026-11-24T11:20:54.798868Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_bb3360e384ee2d6d94dc72d704bf7a90',2,'{"stage":"load_authority","recorded_at":"2026-11-24T11:20:54.800196Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_bb3360e384ee2d6d94dc72d704bf7a90',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T11:20:54.80063Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_590e2b3cc090963408e9b60ee9380763',1,'{"stage":"authenticate","recorded_at":"2026-11-24T11:20:54.813706Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_590e2b3cc090963408e9b60ee9380763',2,'{"stage":"load_authority","recorded_at":"2026-11-24T11:20:54.814759Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_590e2b3cc090963408e9b60ee9380763',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T11:20:54.815152Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',1,'{"stage":"authenticate","recorded_at":"2026-11-24T11:20:54.842216Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',2,'{"stage":"load_authority","recorded_at":"2026-11-24T11:20:54.84337Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T11:20:54.843738Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',4,'{"stage":"coalesce","recorded_at":"2026-11-24T11:20:54.86098Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',5,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:54.861874Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_f905b03312890d46454c441efb1378ea"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',6,'{"stage":"reconcile","recorded_at":"2026-11-24T11:20:54.866814Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',7,'{"stage":"probe","recorded_at":"2026-11-24T11:20:54.867584Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',8,'{"stage":"recheck","recorded_at":"2026-11-24T11:20:54.867983Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_11dea9b26b30927a9497ebdae78d6e1f',9,'{"stage":"commit","recorded_at":"2026-11-24T11:20:54.868834Z","effect":{"kind":"not_attempted"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "tombstones" VALUES('grant_88e76346414ee63e97c834be5e56ce37',8,'2026-11-24T11:20:54.982210000Z','{"grant":"grant_88e76346414ee63e97c834be5e56ce37","cascade":[],"generation":8,"revoked_at":"2026-11-24T11:20:54.98221Z","remote_pending":[],"cause":"revoke"}');
INSERT INTO "tombstones" VALUES('grant_1ae0a6f65459ec5971081bcd91f9cd01',10,'2026-11-24T11:20:54.998227000Z','{"grant":"grant_1ae0a6f65459ec5971081bcd91f9cd01","cascade":[],"generation":10,"revoked_at":"2026-11-24T11:20:54.998227Z","remote_pending":[],"cause":"revoke"}');
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
INSERT INTO "work_stops" VALUES('env_6ce8f39b5b4e7b872a799e547a1b4d74','w4','2026-11-24T11:20:54.998227000Z','{"environment":"env_6ce8f39b5b4e7b872a799e547a1b4d74","work_id":"w4","stopped_at":"2026-11-24T11:20:54.998227Z"}');
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
INSERT INTO "sqlite_sequence" VALUES('events',45);
COMMIT;
