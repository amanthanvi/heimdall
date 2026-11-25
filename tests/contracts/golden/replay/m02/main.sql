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
INSERT INTO "bindings" VALUES('binding_06d304dc252f382cbb4993e2430a4f30','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_2cc084c69b274cc26d225ddfaa05311f','w1','{"id":"binding_06d304dc252f382cbb4993e2430a4f30","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","grant":"grant_2cc084c69b274cc26d225ddfaa05311f","work_id":"w1","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:52:27.870141Z","released_at":"2026-11-24T07:52:28.067938Z","state":"released"}','2026-11-24T07:52:27.870141000Z','2026-11-24T07:52:28.067938000Z','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'released');
INSERT INTO "bindings" VALUES('binding_fc87571abc5eafd662ec812ba96be2bb','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_48e570ad06ab89b11cede9be7494b820','w4','{"id":"binding_fc87571abc5eafd662ec812ba96be2bb","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","grant":"grant_48e570ad06ab89b11cede9be7494b820","work_id":"w4","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:52:27.979302Z","released_at":null,"state":"active"}','2026-11-24T07:52:27.979302000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active');
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
INSERT INTO "decisions" VALUES('dec_881732340ffe118ea2e052acd4d57c99','{"kind":"approve_authority","operation":"op_048bdbed6d42bbcf83ceb33a117c6916","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:52:27.905287000Z','2026-11-24T08:07:27.905287000Z','pending',NULL,'{"id":"dec_881732340ffe118ea2e052acd4d57c99","kind":{"kind":"approve_authority","operation":"op_048bdbed6d42bbcf83ceb33a117c6916","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:52:27.905287Z","expires_at":"2026-11-24T08:07:27.905287Z","state":"pending","decided_at":null}');
INSERT INTO "decisions" VALUES('dec_d3adbc17d12f65dfd6f5706f20fb1cdd','{"kind":"approve_authority","operation":"op_d3831fe7ef6169eec4fee6f7627ad6c2","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:52:27.921460000Z','2026-11-24T08:07:27.921460000Z','denied','2026-11-24T07:52:27.934766000Z','{"id":"dec_d3adbc17d12f65dfd6f5706f20fb1cdd","kind":{"kind":"approve_authority","operation":"op_d3831fe7ef6169eec4fee6f7627ad6c2","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:52:27.92146Z","expires_at":"2026-11-24T08:07:27.92146Z","state":"denied","decided_at":"2026-11-24T07:52:27.934766Z"}');
INSERT INTO "decisions" VALUES('dec_d528e20569249de2a404a104dcce8b4e','{"kind":"approve_authority","operation":"op_62e0d63dc95976d559fdbff7cec57a1d","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:52:27.948694000Z','2026-11-24T08:07:27.948694000Z','approved','2026-11-24T07:52:27.965418000Z','{"id":"dec_d528e20569249de2a404a104dcce8b4e","kind":{"kind":"approve_authority","operation":"op_62e0d63dc95976d559fdbff7cec57a1d","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:52:27.948694Z","expires_at":"2026-11-24T08:07:27.948694Z","state":"approved","decided_at":"2026-11-24T07:52:27.965418Z"}');
INSERT INTO "decisions" VALUES('dec_f35e4594ba76cfc524259187997fc5fa','{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}}',4,'2026-11-24T07:52:28.010942000Z','2026-11-24T08:07:28.010942000Z','approved','2026-11-24T07:52:28.028550000Z','{"id":"dec_f35e4594ba76cfc524259187997fc5fa","kind":{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}},"generation":4,"created_at":"2026-11-24T07:52:28.010942Z","expires_at":"2026-11-24T08:07:28.010942Z","state":"approved","decided_at":"2026-11-24T07:52:28.02855Z"}');
INSERT INTO "decisions" VALUES('dec_f7247c00c1df4078fc1108b90a940060','{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}}',6,'2026-11-24T07:52:28.048478000Z','2026-11-24T08:07:28.048478000Z','pending',NULL,'{"id":"dec_f7247c00c1df4078fc1108b90a940060","kind":{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}},"generation":6,"created_at":"2026-11-24T07:52:28.048478Z","expires_at":"2026-11-24T08:07:28.048478Z","state":"pending","decided_at":null}');
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
INSERT INTO "environments" VALUES('env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","device":"dev_34633261656565653338626661363938","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_093163e39692d04e0e14c860b26792d6','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','runtime_lifecycle',NULL,'2026-11-24T07:52:27.676669000Z','{"schema_version":"1","event_id":"evt_093163e39692d04e0e14c860b26792d6","type":"runtime_lifecycle","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","timestamp":"2026-11-24T07:52:27.676669Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_96fa667b8ef14873f9a3cce145eab90d','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.849780000Z','{"schema_version":"1","event_id":"evt_96fa667b8ef14873f9a3cce145eab90d","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_23211995df7815ed4ae46f621368be9f","resource":{"kind":"operation","id":"op_23211995df7815ed4ae46f621368be9f"},"timestamp":"2026-11-24T07:52:27.84978Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_748ed49fbf790b3c598b74953aff96a1','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.856749000Z','{"schema_version":"1","event_id":"evt_748ed49fbf790b3c598b74953aff96a1","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_23211995df7815ed4ae46f621368be9f","resource":{"kind":"operation","id":"op_23211995df7815ed4ae46f621368be9f"},"timestamp":"2026-11-24T07:52:27.856749Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_d1cfefc907785016faee8f38500987f4','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.858956000Z','{"schema_version":"1","event_id":"evt_d1cfefc907785016faee8f38500987f4","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_23211995df7815ed4ae46f621368be9f","resource":{"kind":"grant","id":"grant_2cc084c69b274cc26d225ddfaa05311f"},"timestamp":"2026-11-24T07:52:27.858956Z","cursor":"","payload":{"grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_88a6b742e782b9ccd5968734ad16c82d','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.870605000Z','{"schema_version":"1","event_id":"evt_88a6b742e782b9ccd5968734ad16c82d","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_23211995df7815ed4ae46f621368be9f","resource":{"kind":"grant","id":"grant_2cc084c69b274cc26d225ddfaa05311f"},"timestamp":"2026-11-24T07:52:27.870605Z","cursor":"","payload":{"grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","state":"active"}}');
INSERT INTO "events" VALUES(6,'evt_df3539fab57d973de14052b0c3f9d613','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.871111000Z','{"schema_version":"1","event_id":"evt_df3539fab57d973de14052b0c3f9d613","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_23211995df7815ed4ae46f621368be9f","resource":{"kind":"operation","id":"op_23211995df7815ed4ae46f621368be9f"},"timestamp":"2026-11-24T07:52:27.871111Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(7,'evt_5272f9846dc2b48d0acff56c4bab8477','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_048bdbed6d42bbcf83ceb33a117c6916','2026-11-24T07:52:27.902738000Z','{"schema_version":"1","event_id":"evt_5272f9846dc2b48d0acff56c4bab8477","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_048bdbed6d42bbcf83ceb33a117c6916","resource":{"kind":"operation","id":"op_048bdbed6d42bbcf83ceb33a117c6916"},"timestamp":"2026-11-24T07:52:27.902738Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(8,'evt_6223895d6bf65422f7b28936a63804a6','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_048bdbed6d42bbcf83ceb33a117c6916','2026-11-24T07:52:27.905831000Z','{"schema_version":"1","event_id":"evt_6223895d6bf65422f7b28936a63804a6","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_048bdbed6d42bbcf83ceb33a117c6916","resource":{"kind":"grant","id":"grant_42fd23130fbeb8b96eb666b798a00770"},"timestamp":"2026-11-24T07:52:27.905831Z","cursor":"","payload":{"grant_id":"grant_42fd23130fbeb8b96eb666b798a00770","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(9,'evt_bbec05977497e460ef3643a34db39a7c','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision','op_048bdbed6d42bbcf83ceb33a117c6916','2026-11-24T07:52:27.905919000Z','{"schema_version":"1","event_id":"evt_bbec05977497e460ef3643a34db39a7c","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_048bdbed6d42bbcf83ceb33a117c6916","resource":{"kind":"decision","id":"dec_881732340ffe118ea2e052acd4d57c99"},"timestamp":"2026-11-24T07:52:27.905919Z","cursor":"","payload":{"decision_id":"dec_881732340ffe118ea2e052acd4d57c99","expires_at":"2026-11-24T08:07:27.905287Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(10,'evt_c993fe94d53eab3c3d9c39c846157a11','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_048bdbed6d42bbcf83ceb33a117c6916','2026-11-24T07:52:27.906162000Z','{"schema_version":"1","event_id":"evt_c993fe94d53eab3c3d9c39c846157a11","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_048bdbed6d42bbcf83ceb33a117c6916","resource":{"kind":"operation","id":"op_048bdbed6d42bbcf83ceb33a117c6916"},"timestamp":"2026-11-24T07:52:27.906162Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(11,'evt_df64461dd4b9c0bf2cbe1d5f5249a3e8','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.918406000Z','{"schema_version":"1","event_id":"evt_df64461dd4b9c0bf2cbe1d5f5249a3e8","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"operation","id":"op_d3831fe7ef6169eec4fee6f7627ad6c2"},"timestamp":"2026-11-24T07:52:27.918406Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(12,'evt_04f1b03f4ed413e033bdc14949ef1205','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.922104000Z','{"schema_version":"1","event_id":"evt_04f1b03f4ed413e033bdc14949ef1205","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"grant","id":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd"},"timestamp":"2026-11-24T07:52:27.922104Z","cursor":"","payload":{"grant_id":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(13,'evt_d0f784de26c2f75610efcded1f7cf740','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.922166000Z','{"schema_version":"1","event_id":"evt_d0f784de26c2f75610efcded1f7cf740","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"decision","id":"dec_d3adbc17d12f65dfd6f5706f20fb1cdd"},"timestamp":"2026-11-24T07:52:27.922166Z","cursor":"","payload":{"decision_id":"dec_d3adbc17d12f65dfd6f5706f20fb1cdd","expires_at":"2026-11-24T08:07:27.92146Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(14,'evt_5a0921f5c117ef9d57b88c3569f2cb16','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.922421000Z','{"schema_version":"1","event_id":"evt_5a0921f5c117ef9d57b88c3569f2cb16","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"operation","id":"op_d3831fe7ef6169eec4fee6f7627ad6c2"},"timestamp":"2026-11-24T07:52:27.922421Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(15,'evt_a0d419545efa3dcca4d2a6a692e83d5f','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.935516000Z','{"schema_version":"1","event_id":"evt_a0d419545efa3dcca4d2a6a692e83d5f","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"decision","id":"dec_d3adbc17d12f65dfd6f5706f20fb1cdd"},"timestamp":"2026-11-24T07:52:27.935516Z","cursor":"","payload":{"decision_id":"dec_d3adbc17d12f65dfd6f5706f20fb1cdd","expires_at":"2026-11-24T08:07:27.92146Z","kind":"approve_authority","state":"denied"}}');
INSERT INTO "events" VALUES(16,'evt_b377a58b3038ccff425d4a35711a48ba','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.935814000Z','{"schema_version":"1","event_id":"evt_b377a58b3038ccff425d4a35711a48ba","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"grant","id":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd"},"timestamp":"2026-11-24T07:52:27.935814Z","cursor":"","payload":{"grant_id":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd","state":"denied"}}');
INSERT INTO "events" VALUES(17,'evt_b36e0a14855bb1d34a3f8024fb22e2b4','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.936092000Z','{"schema_version":"1","event_id":"evt_b36e0a14855bb1d34a3f8024fb22e2b4","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","resource":{"kind":"operation","id":"op_d3831fe7ef6169eec4fee6f7627ad6c2"},"timestamp":"2026-11-24T07:52:27.936092Z","cursor":"","payload":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","kind":"ensure","state":"failed"}}');
INSERT INTO "events" VALUES(18,'evt_949c7308cd75524ff71ebb375439f3b4','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.946412000Z','{"schema_version":"1","event_id":"evt_949c7308cd75524ff71ebb375439f3b4","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"operation","id":"op_62e0d63dc95976d559fdbff7cec57a1d"},"timestamp":"2026-11-24T07:52:27.946412Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(19,'evt_179d36a0c024572937612b11c4873579','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.949411000Z','{"schema_version":"1","event_id":"evt_179d36a0c024572937612b11c4873579","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"grant","id":"grant_48e570ad06ab89b11cede9be7494b820"},"timestamp":"2026-11-24T07:52:27.949411Z","cursor":"","payload":{"grant_id":"grant_48e570ad06ab89b11cede9be7494b820","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(20,'evt_c57879cf8a36fa4251cd17ce2e2b9a39','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.949472000Z','{"schema_version":"1","event_id":"evt_c57879cf8a36fa4251cd17ce2e2b9a39","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"decision","id":"dec_d528e20569249de2a404a104dcce8b4e"},"timestamp":"2026-11-24T07:52:27.949472Z","cursor":"","payload":{"decision_id":"dec_d528e20569249de2a404a104dcce8b4e","expires_at":"2026-11-24T08:07:27.948694Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(21,'evt_6633ed0ec45662d5545bdaf1fb7773e7','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.949706000Z','{"schema_version":"1","event_id":"evt_6633ed0ec45662d5545bdaf1fb7773e7","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"operation","id":"op_62e0d63dc95976d559fdbff7cec57a1d"},"timestamp":"2026-11-24T07:52:27.949706Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(22,'evt_cb078f08543d1b21201756a59f05e63b','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.966039000Z','{"schema_version":"1","event_id":"evt_cb078f08543d1b21201756a59f05e63b","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"decision","id":"dec_d528e20569249de2a404a104dcce8b4e"},"timestamp":"2026-11-24T07:52:27.966039Z","cursor":"","payload":{"decision_id":"dec_d528e20569249de2a404a104dcce8b4e","expires_at":"2026-11-24T08:07:27.948694Z","kind":"approve_authority","state":"approved"}}');
INSERT INTO "events" VALUES(23,'evt_06fc6436cb0230d9230e017174b6b854','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.966326000Z','{"schema_version":"1","event_id":"evt_06fc6436cb0230d9230e017174b6b854","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"grant","id":"grant_48e570ad06ab89b11cede9be7494b820"},"timestamp":"2026-11-24T07:52:27.966326Z","cursor":"","payload":{"grant_id":"grant_48e570ad06ab89b11cede9be7494b820","state":"preparing"}}');
INSERT INTO "events" VALUES(24,'evt_c5550dba8a8da7552be993a8e09f6994','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.966630000Z','{"schema_version":"1","event_id":"evt_c5550dba8a8da7552be993a8e09f6994","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"operation","id":"op_62e0d63dc95976d559fdbff7cec57a1d"},"timestamp":"2026-11-24T07:52:27.96663Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(25,'evt_e83f73c3047ceb42c31b12854fd0a802','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.979907000Z','{"schema_version":"1","event_id":"evt_e83f73c3047ceb42c31b12854fd0a802","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"grant","id":"grant_48e570ad06ab89b11cede9be7494b820"},"timestamp":"2026-11-24T07:52:27.979907Z","cursor":"","payload":{"grant_id":"grant_48e570ad06ab89b11cede9be7494b820","state":"active"}}');
INSERT INTO "events" VALUES(26,'evt_c73e0473896a089b2e987d24621486eb','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.981071000Z','{"schema_version":"1","event_id":"evt_c73e0473896a089b2e987d24621486eb","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d","resource":{"kind":"operation","id":"op_62e0d63dc95976d559fdbff7cec57a1d"},"timestamp":"2026-11-24T07:52:27.981071Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(27,'evt_304b82e74f8820a35ed67c387e9cebe5','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','policy_changed',NULL,'2026-11-24T07:52:27.992617000Z','{"schema_version":"1","event_id":"evt_304b82e74f8820a35ed67c387e9cebe5","type":"policy_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:52:27.992617Z","cursor":"","payload":{"cutoff_at":null,"paused":true,"policy_id":"pol","revision":2}}');
INSERT INTO "events" VALUES(28,'evt_3e6607fcad89209c942ceb857ba67c0b','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision',NULL,'2026-11-24T07:52:28.011277000Z','{"schema_version":"1","event_id":"evt_3e6607fcad89209c942ceb857ba67c0b","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"decision","id":"dec_f35e4594ba76cfc524259187997fc5fa"},"timestamp":"2026-11-24T07:52:28.011277Z","cursor":"","payload":{"decision_id":"dec_f35e4594ba76cfc524259187997fc5fa","expires_at":"2026-11-24T08:07:28.010942Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(29,'evt_0d95fe134dd5c6e92359ee66a24af6d0','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision',NULL,'2026-11-24T07:52:28.028887000Z','{"schema_version":"1","event_id":"evt_0d95fe134dd5c6e92359ee66a24af6d0","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"decision","id":"dec_f35e4594ba76cfc524259187997fc5fa"},"timestamp":"2026-11-24T07:52:28.028887Z","cursor":"","payload":{"decision_id":"dec_f35e4594ba76cfc524259187997fc5fa","expires_at":"2026-11-24T08:07:28.010942Z","kind":"widen_policy","state":"approved"}}');
INSERT INTO "events" VALUES(30,'evt_a0c898b11d0d3401a3fcc2abf4e28b92','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','policy_changed',NULL,'2026-11-24T07:52:28.029830000Z','{"schema_version":"1","event_id":"evt_a0c898b11d0d3401a3fcc2abf4e28b92","type":"policy_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:52:28.02983Z","cursor":"","payload":{"cutoff_at":null,"paused":false,"policy_id":"pol","revision":3}}');
INSERT INTO "events" VALUES(31,'evt_535bd27c800d79aea6819699aa153348','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','policy_changed',NULL,'2026-11-24T07:52:28.038955000Z','{"schema_version":"1","event_id":"evt_535bd27c800d79aea6819699aa153348","type":"policy_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:52:28.038955Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":4}}');
INSERT INTO "events" VALUES(32,'evt_5f7a39299cbd626cacae900778d852f5','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','decision',NULL,'2026-11-24T07:52:28.048775000Z','{"schema_version":"1","event_id":"evt_5f7a39299cbd626cacae900778d852f5","type":"decision","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"decision","id":"dec_f7247c00c1df4078fc1108b90a940060"},"timestamp":"2026-11-24T07:52:28.048775Z","cursor":"","payload":{"decision_id":"dec_f7247c00c1df4078fc1108b90a940060","expires_at":"2026-11-24T08:07:28.048478Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(33,'evt_25fdc286a0abc5d6d08298e4be5c50fe','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','grant_state_changed',NULL,'2026-11-24T07:52:28.068652000Z','{"schema_version":"1","event_id":"evt_25fdc286a0abc5d6d08298e4be5c50fe","type":"grant_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","resource":{"kind":"grant","id":"grant_2cc084c69b274cc26d225ddfaa05311f"},"timestamp":"2026-11-24T07:52:28.068652Z","cursor":"","payload":{"grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","state":"released"}}');
INSERT INTO "events" VALUES(34,'evt_f5a83d85816ffe9db30114fb6f68dfc2','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_8c639f859d584262593ca7b15b7576ca','2026-11-24T07:52:28.079183000Z','{"schema_version":"1","event_id":"evt_f5a83d85816ffe9db30114fb6f68dfc2","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_8c639f859d584262593ca7b15b7576ca","resource":{"kind":"operation","id":"op_8c639f859d584262593ca7b15b7576ca"},"timestamp":"2026-11-24T07:52:28.079183Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(35,'evt_0dd01068637409b32350e8e5d2ac72e8','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_8c639f859d584262593ca7b15b7576ca','2026-11-24T07:52:28.082124000Z','{"schema_version":"1","event_id":"evt_0dd01068637409b32350e8e5d2ac72e8","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_8c639f859d584262593ca7b15b7576ca","resource":{"kind":"operation","id":"op_8c639f859d584262593ca7b15b7576ca"},"timestamp":"2026-11-24T07:52:28.082124Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(36,'evt_0a9943bdc3ece68e08fcb998d692983a','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','operation_state_changed','op_8c639f859d584262593ca7b15b7576ca','2026-11-24T07:52:28.083192000Z','{"schema_version":"1","event_id":"evt_0a9943bdc3ece68e08fcb998d692983a","type":"operation_state_changed","environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","operation_id":"op_8c639f859d584262593ca7b15b7576ca","resource":{"kind":"operation","id":"op_8c639f859d584262593ca7b15b7576ca"},"timestamp":"2026-11-24T07:52:28.083192Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
CREATE TABLE grant_anchors (
    grant_id      TEXT PRIMARY KEY NOT NULL,
    record_json   TEXT NOT NULL,
    boot_id       TEXT NOT NULL,
    budget_end_ns INTEGER NOT NULL,
    bound         TEXT NOT NULL
) STRICT;
INSERT INTO "grant_anchors" VALUES('grant_2cc084c69b274cc26d225ddfaa05311f','{"grant":"grant_2cc084c69b274cc26d225ddfaa05311f","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080910,"nanos":352736416},"wall":"2026-11-24T07:52:27.859684Z"},"bound":"2026-11-24T09:52:27.85532Z","budget_end":{"secs":1088110,"nanos":348371500}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088110348371500,'2026-11-24T09:52:27.855320000Z');
INSERT INTO "grant_anchors" VALUES('grant_48e570ad06ab89b11cede9be7494b820','{"grant":"grant_48e570ad06ab89b11cede9be7494b820","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080910,"nanos":461612291},"wall":"2026-11-24T07:52:27.968562Z"},"bound":"2026-11-24T09:52:27.948694Z","budget_end":{"secs":1088110,"nanos":441743666}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088110441743666,'2026-11-24T09:52:27.948694000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_2cc084c69b274cc26d225ddfaa05311f','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:52:27.865502Z"}');
INSERT INTO "grant_prepared_facts" VALUES('grant_48e570ad06ab89b11cede9be7494b820','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:52:27.974699Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_fc87571abc5eafd662ec812ba96be2bb','grant_48e570ad06ab89b11cede9be7494b820','2026-11-24T07:52:27.979302000Z');
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
INSERT INTO "grants" VALUES('grant_2cc084c69b274cc26d225ddfaa05311f','env_6c23ed0bb0c4d8f4896afb83eeeea2c4',NULL,'released','2026-11-24T07:52:27.858668000Z','2026-11-24T09:52:27.855320000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.85532Z","effective":"2026-11-24T09:52:27.85532Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_2cc084c69b274cc26d225ddfaa05311f","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:27.858668Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.85532Z","effective":"2026-11-24T09:52:27.85532Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"released","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:52:27.858668000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
INSERT INTO "grants" VALUES('grant_42fd23130fbeb8b96eb666b798a00770','env_6c23ed0bb0c4d8f4896afb83eeeea2c4',NULL,'awaiting_approval','2026-11-24T07:52:27.905287000Z','2026-11-24T09:52:27.905287000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.905287Z","effective":"2026-11-24T09:52:27.905287Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_42fd23130fbeb8b96eb666b798a00770","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:27.905287Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.905287Z","effective":"2026-11-24T09:52:27.905287Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_048bdbed6d42bbcf83ceb33a117c6916"},"generation":3,"state":"awaiting_approval","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:52:27.905287000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_c3ccd383f32b77b6d9a13fb9ab131bcd','env_6c23ed0bb0c4d8f4896afb83eeeea2c4',NULL,'denied','2026-11-24T07:52:27.921460000Z','2026-11-24T09:52:27.921460000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.92146Z","effective":"2026-11-24T09:52:27.92146Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:27.92146Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.92146Z","effective":"2026-11-24T09:52:27.92146Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_d3831fe7ef6169eec4fee6f7627ad6c2"},"generation":3,"state":"denied","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:52:27.921460000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_48e570ad06ab89b11cede9be7494b820','env_6c23ed0bb0c4d8f4896afb83eeeea2c4',NULL,'active','2026-11-24T07:52:27.948694000Z','2026-11-24T09:52:27.948694000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.948694Z","effective":"2026-11-24T09:52:27.948694Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_48e570ad06ab89b11cede9be7494b820","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:52:27.948694Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.948694Z","effective":"2026-11-24T09:52:27.948694Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_62e0d63dc95976d559fdbff7cec57a1d"},"generation":3,"state":"active","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:52:27.948694000Z','{"decision":"dec_d528e20569249de2a404a104dcce8b4e","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}','{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r1','bc2c24798261ff120e6d8b0b2dead27c82706665dc3953877adfc3d15e8e6fc1','op_23211995df7815ed4ae46f621368be9f','2026-11-24T07:52:27.847944000Z','2026-12-01T07:52:27.870141000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r2','b654edf240336adb031bc59bbc01b0919a7f447fa62fbbfdeb21abdf96a175e5','op_048bdbed6d42bbcf83ceb33a117c6916','2026-11-24T07:52:27.902044000Z',NULL);
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r3','ce6c54900bcf5a0aacc8b9d09ae22c2fe21fc98fd875a5567b8888df0276e609','op_d3831fe7ef6169eec4fee6f7627ad6c2','2026-11-24T07:52:27.917667000Z','2026-12-01T07:52:27.934766000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r4','f765673c698f6280eb9363938297949b653ec8d80b34e619f680ca3cf335d1fe','op_62e0d63dc95976d559fdbff7cec57a1d','2026-11-24T07:52:27.945720000Z','2026-12-01T07:52:27.979302000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','rv1','b6b26bec08b0f399797e4949739b692c2613c5fada33fb012b04697ab637b4cf','op_8c639f859d584262593ca7b15b7576ca','2026-11-24T07:52:28.078340000Z','2026-12-01T07:52:28.080981000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:52:28.102759000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1080910,"nanos":595808958},"wall":"2026-11-24T07:52:28.102759Z"}');
INSERT INTO "meta" VALUES('self_environment_id','env_6c23ed0bb0c4d8f4896afb83eeeea2c4');
INSERT INTO "meta" VALUES('authority_generation','7');
INSERT INTO "meta" VALUES('remote_revocation_claim_seq','1');
INSERT INTO "meta" VALUES('grant_validation:grant_48e570ad06ab89b11cede9be7494b820','7');
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
INSERT INTO "operations" VALUES('op_23211995df7815ed4ae46f621368be9f','ensure','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r1','bc2c24798261ff120e6d8b0b2dead27c82706665dc3953877adfc3d15e8e6fc1','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_06d304dc252f382cbb4993e2430a4f30","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","expires_at":"2026-11-24T09:52:27.85532Z","grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","offline_until":"2026-11-24T08:52:27.41705Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:27.85532Z"}','{"id":"op_23211995df7815ed4ae46f621368be9f","kind":"ensure","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r1"},"request_hash":"bc2c24798261ff120e6d8b0b2dead27c82706665dc3953877adfc3d15e8e6fc1","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_06d304dc252f382cbb4993e2430a4f30","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","expires_at":"2026-11-24T09:52:27.85532Z","grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","offline_until":"2026-11-24T08:52:27.41705Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:27.85532Z"},"created_at":"2026-11-24T07:52:27.847944Z","updated_at":"2026-11-24T07:52:27.870141Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:27.847944000Z','2026-11-24T07:52:27.870141000Z','2026-11-24T07:52:27.870141000Z');
INSERT INTO "operations" VALUES('op_048bdbed6d42bbcf83ceb33a117c6916','ensure','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r2','b654edf240336adb031bc59bbc01b0919a7f447fa62fbbfdeb21abdf96a175e5','local_resources','awaiting_approval',NULL,'none',NULL,'{"id":"op_048bdbed6d42bbcf83ceb33a117c6916","kind":"ensure","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r2"},"request_hash":"b654edf240336adb031bc59bbc01b0919a7f447fa62fbbfdeb21abdf96a175e5","effect_class":"local_resources","state":"awaiting_approval","code":null,"effect_status":"none","result":null,"created_at":"2026-11-24T07:52:27.902044Z","updated_at":"2026-11-24T07:52:27.905287Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:27.902044000Z','2026-11-24T07:52:27.905287000Z',NULL);
INSERT INTO "operations" VALUES('op_d3831fe7ef6169eec4fee6f7627ad6c2','ensure','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r3','ce6c54900bcf5a0aacc8b9d09ae22c2fe21fc98fd875a5567b8888df0276e609','local_resources','failed','CAPABILITY_UNAVAILABLE','none','{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}}','{"id":"op_d3831fe7ef6169eec4fee6f7627ad6c2","kind":"ensure","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r3"},"request_hash":"ce6c54900bcf5a0aacc8b9d09ae22c2fe21fc98fd875a5567b8888df0276e609","effect_class":"local_resources","state":"failed","code":"CAPABILITY_UNAVAILABLE","effect_status":"none","result":{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}},"created_at":"2026-11-24T07:52:27.917667Z","updated_at":"2026-11-24T07:52:27.934766Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:27.917667000Z','2026-11-24T07:52:27.934766000Z','2026-11-24T07:52:27.934766000Z');
INSERT INTO "operations" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d','ensure','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r4','f765673c698f6280eb9363938297949b653ec8d80b34e619f680ca3cf335d1fe','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_fc87571abc5eafd662ec812ba96be2bb","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","expires_at":"2026-11-24T09:52:27.948694Z","grant_id":"grant_48e570ad06ab89b11cede9be7494b820","offline_until":"2026-11-24T08:52:27.41705Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:27.948694Z"}','{"id":"op_62e0d63dc95976d559fdbff7cec57a1d","kind":"ensure","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r4"},"request_hash":"f765673c698f6280eb9363938297949b653ec8d80b34e619f680ca3cf335d1fe","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_fc87571abc5eafd662ec812ba96be2bb","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","expires_at":"2026-11-24T09:52:27.948694Z","grant_id":"grant_48e570ad06ab89b11cede9be7494b820","offline_until":"2026-11-24T08:52:27.41705Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:52:27.948694Z"},"created_at":"2026-11-24T07:52:27.94572Z","updated_at":"2026-11-24T07:52:27.979302Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:27.945720000Z','2026-11-24T07:52:27.979302000Z','2026-11-24T07:52:27.979302000Z');
INSERT INTO "operations" VALUES('op_8c639f859d584262593ca7b15b7576ca','revoke','env_6c23ed0bb0c4d8f4896afb83eeeea2c4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','rv1','b6b26bec08b0f399797e4949739b692c2613c5fada33fb012b04697ab637b4cf','local_resources','succeeded','OK','applied','{"local_applied":true,"remote_pending":[]}','{"id":"op_8c639f859d584262593ca7b15b7576ca","kind":"revoke","environment":"env_6c23ed0bb0c4d8f4896afb83eeeea2c4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"rv1"},"request_hash":"b6b26bec08b0f399797e4949739b692c2613c5fada33fb012b04697ab637b4cf","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"local_applied":true,"remote_pending":[]},"created_at":"2026-11-24T07:52:28.07834Z","updated_at":"2026-11-24T07:52:28.080981Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:52:28.078340000Z','2026-11-24T07:52:28.080981000Z','2026-11-24T07:52:28.080981000Z');
CREATE TABLE policies (
    id            TEXT PRIMARY KEY NOT NULL,
    revision      INTEGER NOT NULL,
    record_json   TEXT NOT NULL,
    updated_at    TEXT NOT NULL
) STRICT;
INSERT INTO "policies" VALUES('pol',4,'{"id":"pol","revision":4,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6c23ed0bb0c4d8f4896afb83eeeea2c4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T07:52:28.038613Z"}}','2026-11-24T07:52:28.038613000Z');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_6c23ed0bb0c4d8f4896afb83eeeea2c4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_23211995df7815ed4ae46f621368be9f','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r1","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w1"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.85532Z","effective":"2026-11-24T09:52:27.85532Z"},"policy_revision":1,"generation":3,"grant":"grant_2cc084c69b274cc26d225ddfaa05311f","binding":"binding_06d304dc252f382cbb4993e2430a4f30","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_048bdbed6d42bbcf83ceb33a117c6916','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r2","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w2"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.905287Z","effective":"2026-11-24T09:52:27.905287Z"},"policy_revision":1,"generation":3,"grant":"grant_42fd23130fbeb8b96eb666b798a00770","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_d3831fe7ef6169eec4fee6f7627ad6c2','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r3","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w3"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.92146Z","effective":"2026-11-24T09:52:27.92146Z"},"policy_revision":1,"generation":3,"grant":"grant_c3ccd383f32b77b6d9a13fb9ab131bcd","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r4","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w4"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:52:27.948694Z","effective":"2026-11-24T09:52:27.948694Z"},"policy_revision":1,"generation":3,"grant":"grant_48e570ad06ab89b11cede9be7494b820","binding":"binding_fc87571abc5eafd662ec812ba96be2bb","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"approval":{"decision":"dec_d528e20569249de2a404a104dcce8b4e","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}}}');
INSERT INTO "recovery_intents" VALUES('op_8c639f859d584262593ca7b15b7576ca','{"request":{"grant_id":"grant_2cc084c69b274cc26d225ddfaa05311f","op":"revoke","request_id":"rv1"},"resolved":null}');
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
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:27.847944Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:27.853638Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:27.85532Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:52:27.857688Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:27.859684Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_5cd8fea461428f8af33eab32e933f5f4"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:27.865502Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',7,'{"stage":"probe","recorded_at":"2026-11-24T07:52:27.866783Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:52:27.867475Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_23211995df7815ed4ae46f621368be9f',9,'{"stage":"commit","recorded_at":"2026-11-24T07:52:27.870141Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_048bdbed6d42bbcf83ceb33a117c6916',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:27.902044Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_048bdbed6d42bbcf83ceb33a117c6916',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:27.904523Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_048bdbed6d42bbcf83ceb33a117c6916',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:27.905287Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d3831fe7ef6169eec4fee6f7627ad6c2',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:27.917667Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d3831fe7ef6169eec4fee6f7627ad6c2',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:27.92043Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_d3831fe7ef6169eec4fee6f7627ad6c2',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:27.92146Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:52:27.94572Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:52:27.948001Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:52:27.948694Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:52:27.9679Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:27.968562Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_fa9d1d4ef64cc852c20fabef24ecf396"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:52:27.974699Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',7,'{"stage":"probe","recorded_at":"2026-11-24T07:52:27.976669Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:52:27.977608Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_62e0d63dc95976d559fdbff7cec57a1d',9,'{"stage":"commit","recorded_at":"2026-11-24T07:52:27.979302Z","effect":{"kind":"not_attempted"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "tombstones" VALUES('grant_2cc084c69b274cc26d225ddfaa05311f',7,'2026-11-24T07:52:28.080981000Z','{"grant":"grant_2cc084c69b274cc26d225ddfaa05311f","cascade":[],"generation":7,"revoked_at":"2026-11-24T07:52:28.080981Z","remote_pending":[],"cause":"revoke"}');
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
INSERT INTO "sqlite_sequence" VALUES('events',36);
COMMIT;
