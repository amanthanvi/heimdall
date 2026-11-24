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
INSERT INTO "bindings" VALUES('binding_548219d74c51f900132f57ad278c2896','env_4228c787fe79f5282a9a007d27a25cc4','grant_17ec6f73dd454da6d4812cf949584635','w1','{"id":"binding_548219d74c51f900132f57ad278c2896","environment":"env_4228c787fe79f5282a9a007d27a25cc4","grant":"grant_17ec6f73dd454da6d4812cf949584635","work_id":"w1","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:56:07.875667Z","released_at":"2026-11-24T07:56:08.06055Z","state":"released"}','2026-11-24T07:56:07.875667000Z','2026-11-24T07:56:08.060550000Z','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'released','{"kind":"personal"}');
INSERT INTO "bindings" VALUES('binding_a56715c42c08e8b3d353612441a5b6a1','env_4228c787fe79f5282a9a007d27a25cc4','grant_506ffeb57417453c89d4e832875f6a3f','w4','{"id":"binding_a56715c42c08e8b3d353612441a5b6a1","environment":"env_4228c787fe79f5282a9a007d27a25cc4","grant":"grant_506ffeb57417453c89d4e832875f6a3f","work_id":"w4","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:56:07.968053Z","released_at":null,"state":"active"}','2026-11-24T07:56:07.968053000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active','{"kind":"personal"}');
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
INSERT INTO "decisions" VALUES('dec_b15c2f627d5552ece1e05949be61cda6','{"kind":"approve_authority","operation":"op_5df1415aeee0c26f0602e026060782ae","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:07.909468000Z','2026-11-24T08:11:07.909468000Z','pending',NULL,'{"id":"dec_b15c2f627d5552ece1e05949be61cda6","kind":{"kind":"approve_authority","operation":"op_5df1415aeee0c26f0602e026060782ae","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:07.909468Z","expires_at":"2026-11-24T08:11:07.909468Z","state":"pending","decided_at":null}');
INSERT INTO "decisions" VALUES('dec_8b726bd1090d199a5e8ba25d55c58061','{"kind":"approve_authority","operation":"op_a5e5a28cad80d22ddce5f5d74dec4a34","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:07.921742000Z','2026-11-24T08:11:07.921742000Z','denied','2026-11-24T07:56:07.934609000Z','{"id":"dec_8b726bd1090d199a5e8ba25d55c58061","kind":{"kind":"approve_authority","operation":"op_a5e5a28cad80d22ddce5f5d74dec4a34","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:07.921742Z","expires_at":"2026-11-24T08:11:07.921742Z","state":"denied","decided_at":"2026-11-24T07:56:07.934609Z"}');
INSERT INTO "decisions" VALUES('dec_dc06ef58c42f2352236b9b318d73b4f9','{"kind":"approve_authority","operation":"op_0f2fbf6dfa09840068aaed4989ca343c","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:07.948264000Z','2026-11-24T08:11:07.948264000Z','approved','2026-11-24T07:56:07.960104000Z','{"id":"dec_dc06ef58c42f2352236b9b318d73b4f9","kind":{"kind":"approve_authority","operation":"op_0f2fbf6dfa09840068aaed4989ca343c","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:07.948264Z","expires_at":"2026-11-24T08:11:07.948264Z","state":"approved","decided_at":"2026-11-24T07:56:07.960104Z"}');
INSERT INTO "decisions" VALUES('dec_76d730184ea9b864b9af876873202ddb','{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}}',4,'2026-11-24T07:56:07.989380000Z','2026-11-24T08:11:07.989380000Z','approved','2026-11-24T07:56:07.999398000Z','{"id":"dec_76d730184ea9b864b9af876873202ddb","kind":{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}},"generation":4,"created_at":"2026-11-24T07:56:07.98938Z","expires_at":"2026-11-24T08:11:07.98938Z","state":"approved","decided_at":"2026-11-24T07:56:07.999398Z"}');
INSERT INTO "decisions" VALUES('dec_c550249faecae8ed80ea24a7c8528012','{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}}',6,'2026-11-24T07:56:08.018741000Z','2026-11-24T08:11:08.018741000Z','pending',NULL,'{"id":"dec_c550249faecae8ed80ea24a7c8528012","kind":{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}},"generation":6,"created_at":"2026-11-24T07:56:08.018741Z","expires_at":"2026-11-24T08:11:08.018741Z","state":"pending","decided_at":null}');
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
INSERT INTO "environments" VALUES('env_4228c787fe79f5282a9a007d27a25cc4','{"id":"env_4228c787fe79f5282a9a007d27a25cc4","device":"dev_34636335326137326437303061396132","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_e8080ea05abccb9ce78d1350df1b1d02','env_4228c787fe79f5282a9a007d27a25cc4','runtime_lifecycle',NULL,'2026-11-24T07:56:07.798684000Z','{"schema_version":"1","event_id":"evt_e8080ea05abccb9ce78d1350df1b1d02","type":"runtime_lifecycle","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","timestamp":"2026-11-24T07:56:07.798684Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_1f1991093f2970d804e042d0a58d23f4','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.860921000Z','{"schema_version":"1","event_id":"evt_1f1991093f2970d804e042d0a58d23f4","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_cd4e86a1ad1137704de0455d856b63be","resource":{"kind":"operation","id":"op_cd4e86a1ad1137704de0455d856b63be"},"timestamp":"2026-11-24T07:56:07.860921Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_c8065b22cd248e308448ad2cabe1047c','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.866548000Z','{"schema_version":"1","event_id":"evt_c8065b22cd248e308448ad2cabe1047c","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_cd4e86a1ad1137704de0455d856b63be","resource":{"kind":"operation","id":"op_cd4e86a1ad1137704de0455d856b63be"},"timestamp":"2026-11-24T07:56:07.866548Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_590d8961240988a109a8cc55dc200990','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.867883000Z','{"schema_version":"1","event_id":"evt_590d8961240988a109a8cc55dc200990","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_cd4e86a1ad1137704de0455d856b63be","resource":{"kind":"grant","id":"grant_17ec6f73dd454da6d4812cf949584635"},"timestamp":"2026-11-24T07:56:07.867883Z","cursor":"","payload":{"grant_id":"grant_17ec6f73dd454da6d4812cf949584635","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_727ead7e4f74cf32a7f584eca3655457','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.876085000Z','{"schema_version":"1","event_id":"evt_727ead7e4f74cf32a7f584eca3655457","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_cd4e86a1ad1137704de0455d856b63be","resource":{"kind":"grant","id":"grant_17ec6f73dd454da6d4812cf949584635"},"timestamp":"2026-11-24T07:56:07.876085Z","cursor":"","payload":{"grant_id":"grant_17ec6f73dd454da6d4812cf949584635","state":"active"}}');
INSERT INTO "events" VALUES(6,'evt_88b0528b6a1ca38c90dd5bb1db5e6351','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.876670000Z','{"schema_version":"1","event_id":"evt_88b0528b6a1ca38c90dd5bb1db5e6351","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_cd4e86a1ad1137704de0455d856b63be","resource":{"kind":"operation","id":"op_cd4e86a1ad1137704de0455d856b63be"},"timestamp":"2026-11-24T07:56:07.87667Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(7,'evt_25312a53105385daedc78569793d33ef','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_5df1415aeee0c26f0602e026060782ae','2026-11-24T07:56:07.908677000Z','{"schema_version":"1","event_id":"evt_25312a53105385daedc78569793d33ef","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_5df1415aeee0c26f0602e026060782ae","resource":{"kind":"operation","id":"op_5df1415aeee0c26f0602e026060782ae"},"timestamp":"2026-11-24T07:56:07.908677Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(8,'evt_ea1e33c24777ffff7175d281521d6bb2','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_5df1415aeee0c26f0602e026060782ae','2026-11-24T07:56:07.909845000Z','{"schema_version":"1","event_id":"evt_ea1e33c24777ffff7175d281521d6bb2","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_5df1415aeee0c26f0602e026060782ae","resource":{"kind":"grant","id":"grant_06f8a0361b8a90521c728a2be5e31b4d"},"timestamp":"2026-11-24T07:56:07.909845Z","cursor":"","payload":{"grant_id":"grant_06f8a0361b8a90521c728a2be5e31b4d","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(9,'evt_212139b21c94ea2b96fb43bddffb8348','env_4228c787fe79f5282a9a007d27a25cc4','decision','op_5df1415aeee0c26f0602e026060782ae','2026-11-24T07:56:07.909923000Z','{"schema_version":"1","event_id":"evt_212139b21c94ea2b96fb43bddffb8348","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_5df1415aeee0c26f0602e026060782ae","resource":{"kind":"decision","id":"dec_b15c2f627d5552ece1e05949be61cda6"},"timestamp":"2026-11-24T07:56:07.909923Z","cursor":"","payload":{"decision_id":"dec_b15c2f627d5552ece1e05949be61cda6","expires_at":"2026-11-24T08:11:07.909468Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(10,'evt_5a807b915f167f0851fa61014b31a465','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_5df1415aeee0c26f0602e026060782ae','2026-11-24T07:56:07.910080000Z','{"schema_version":"1","event_id":"evt_5a807b915f167f0851fa61014b31a465","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_5df1415aeee0c26f0602e026060782ae","resource":{"kind":"operation","id":"op_5df1415aeee0c26f0602e026060782ae"},"timestamp":"2026-11-24T07:56:07.91008Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(11,'evt_f1ee1f2414ebe7b45b7e1f3cfef66f36','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.920875000Z','{"schema_version":"1","event_id":"evt_f1ee1f2414ebe7b45b7e1f3cfef66f36","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"operation","id":"op_a5e5a28cad80d22ddce5f5d74dec4a34"},"timestamp":"2026-11-24T07:56:07.920875Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(12,'evt_3470c726f3259ff6247f4a7ceb384d4e','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.922203000Z','{"schema_version":"1","event_id":"evt_3470c726f3259ff6247f4a7ceb384d4e","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"grant","id":"grant_11c99014b79d0748fe405024b2271a9a"},"timestamp":"2026-11-24T07:56:07.922203Z","cursor":"","payload":{"grant_id":"grant_11c99014b79d0748fe405024b2271a9a","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(13,'evt_07faf372071b1d5685bbf2e9b2715384','env_4228c787fe79f5282a9a007d27a25cc4','decision','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.922274000Z','{"schema_version":"1","event_id":"evt_07faf372071b1d5685bbf2e9b2715384","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"decision","id":"dec_8b726bd1090d199a5e8ba25d55c58061"},"timestamp":"2026-11-24T07:56:07.922274Z","cursor":"","payload":{"decision_id":"dec_8b726bd1090d199a5e8ba25d55c58061","expires_at":"2026-11-24T08:11:07.921742Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(14,'evt_c842011ddb680ddc1602d63b39d3ba34','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.922423000Z','{"schema_version":"1","event_id":"evt_c842011ddb680ddc1602d63b39d3ba34","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"operation","id":"op_a5e5a28cad80d22ddce5f5d74dec4a34"},"timestamp":"2026-11-24T07:56:07.922423Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(15,'evt_96fb9d0d0b19ce623c464aadf3a625fa','env_4228c787fe79f5282a9a007d27a25cc4','decision','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.935533000Z','{"schema_version":"1","event_id":"evt_96fb9d0d0b19ce623c464aadf3a625fa","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"decision","id":"dec_8b726bd1090d199a5e8ba25d55c58061"},"timestamp":"2026-11-24T07:56:07.935533Z","cursor":"","payload":{"decision_id":"dec_8b726bd1090d199a5e8ba25d55c58061","expires_at":"2026-11-24T08:11:07.921742Z","kind":"approve_authority","state":"denied"}}');
INSERT INTO "events" VALUES(16,'evt_c993de4d0098bbd34c7303ace3c505b4','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.935755000Z','{"schema_version":"1","event_id":"evt_c993de4d0098bbd34c7303ace3c505b4","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"grant","id":"grant_11c99014b79d0748fe405024b2271a9a"},"timestamp":"2026-11-24T07:56:07.935755Z","cursor":"","payload":{"grant_id":"grant_11c99014b79d0748fe405024b2271a9a","state":"denied"}}');
INSERT INTO "events" VALUES(17,'evt_6ff49325c5e675d53b76e333f2c96c7c','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.935900000Z','{"schema_version":"1","event_id":"evt_6ff49325c5e675d53b76e333f2c96c7c","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","resource":{"kind":"operation","id":"op_a5e5a28cad80d22ddce5f5d74dec4a34"},"timestamp":"2026-11-24T07:56:07.9359Z","cursor":"","payload":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","kind":"ensure","state":"failed"}}');
INSERT INTO "events" VALUES(18,'evt_55e9e9c246b3ee629d255c7c2acf16f3','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.946878000Z','{"schema_version":"1","event_id":"evt_55e9e9c246b3ee629d255c7c2acf16f3","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"operation","id":"op_0f2fbf6dfa09840068aaed4989ca343c"},"timestamp":"2026-11-24T07:56:07.946878Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(19,'evt_6950b695678405a3626a9d9ecfb71213','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.948740000Z','{"schema_version":"1","event_id":"evt_6950b695678405a3626a9d9ecfb71213","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:07.94874Z","cursor":"","payload":{"grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(20,'evt_1b7e5dda12d8742b1ef93ad1f52ae719','env_4228c787fe79f5282a9a007d27a25cc4','decision','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.948813000Z','{"schema_version":"1","event_id":"evt_1b7e5dda12d8742b1ef93ad1f52ae719","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"decision","id":"dec_dc06ef58c42f2352236b9b318d73b4f9"},"timestamp":"2026-11-24T07:56:07.948813Z","cursor":"","payload":{"decision_id":"dec_dc06ef58c42f2352236b9b318d73b4f9","expires_at":"2026-11-24T08:11:07.948264Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(21,'evt_fc55b23e5b367e243439710179c6289c','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.948962000Z','{"schema_version":"1","event_id":"evt_fc55b23e5b367e243439710179c6289c","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"operation","id":"op_0f2fbf6dfa09840068aaed4989ca343c"},"timestamp":"2026-11-24T07:56:07.948962Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(22,'evt_6f76b09a1dca7432a3009bff2533d6b0','env_4228c787fe79f5282a9a007d27a25cc4','decision','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.960454000Z','{"schema_version":"1","event_id":"evt_6f76b09a1dca7432a3009bff2533d6b0","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"decision","id":"dec_dc06ef58c42f2352236b9b318d73b4f9"},"timestamp":"2026-11-24T07:56:07.960454Z","cursor":"","payload":{"decision_id":"dec_dc06ef58c42f2352236b9b318d73b4f9","expires_at":"2026-11-24T08:11:07.948264Z","kind":"approve_authority","state":"approved"}}');
INSERT INTO "events" VALUES(23,'evt_950a3cd3cc4aa4aeb0eef1232836a7dc','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.960629000Z','{"schema_version":"1","event_id":"evt_950a3cd3cc4aa4aeb0eef1232836a7dc","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:07.960629Z","cursor":"","payload":{"grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","state":"preparing"}}');
INSERT INTO "events" VALUES(24,'evt_02fbe8516ff468d718c8162258b41370','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.960839000Z','{"schema_version":"1","event_id":"evt_02fbe8516ff468d718c8162258b41370","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"operation","id":"op_0f2fbf6dfa09840068aaed4989ca343c"},"timestamp":"2026-11-24T07:56:07.960839Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(25,'evt_512321bab727a0c007f6f9342ae953b9','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.968371000Z','{"schema_version":"1","event_id":"evt_512321bab727a0c007f6f9342ae953b9","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:07.968371Z","cursor":"","payload":{"grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","state":"active"}}');
INSERT INTO "events" VALUES(26,'evt_ddab8d10143d583745a8dade725faddb','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.968778000Z','{"schema_version":"1","event_id":"evt_ddab8d10143d583745a8dade725faddb","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c","resource":{"kind":"operation","id":"op_0f2fbf6dfa09840068aaed4989ca343c"},"timestamp":"2026-11-24T07:56:07.968778Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(27,'evt_1e3b5365cddc23893c21cd1726d77ffd','env_4228c787fe79f5282a9a007d27a25cc4','policy_changed',NULL,'2026-11-24T07:56:07.979856000Z','{"schema_version":"1","event_id":"evt_1e3b5365cddc23893c21cd1726d77ffd","type":"policy_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:07.979856Z","cursor":"","payload":{"cutoff_at":null,"paused":true,"policy_id":"pol","revision":2}}');
INSERT INTO "events" VALUES(28,'evt_e71837b9c7eb64269f966d660ace19c7','env_4228c787fe79f5282a9a007d27a25cc4','decision',NULL,'2026-11-24T07:56:07.989542000Z','{"schema_version":"1","event_id":"evt_e71837b9c7eb64269f966d660ace19c7","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"decision","id":"dec_76d730184ea9b864b9af876873202ddb"},"timestamp":"2026-11-24T07:56:07.989542Z","cursor":"","payload":{"decision_id":"dec_76d730184ea9b864b9af876873202ddb","expires_at":"2026-11-24T08:11:07.98938Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(29,'evt_da92064ed5ffc57bfa6368d58211055d','env_4228c787fe79f5282a9a007d27a25cc4','decision',NULL,'2026-11-24T07:56:07.999489000Z','{"schema_version":"1","event_id":"evt_da92064ed5ffc57bfa6368d58211055d","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"decision","id":"dec_76d730184ea9b864b9af876873202ddb"},"timestamp":"2026-11-24T07:56:07.999489Z","cursor":"","payload":{"decision_id":"dec_76d730184ea9b864b9af876873202ddb","expires_at":"2026-11-24T08:11:07.98938Z","kind":"widen_policy","state":"approved"}}');
INSERT INTO "events" VALUES(30,'evt_e7025f20e20c53107c8b311c26c6bf4d','env_4228c787fe79f5282a9a007d27a25cc4','policy_changed',NULL,'2026-11-24T07:56:07.999608000Z','{"schema_version":"1","event_id":"evt_e7025f20e20c53107c8b311c26c6bf4d","type":"policy_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:07.999608Z","cursor":"","payload":{"cutoff_at":null,"paused":false,"policy_id":"pol","revision":3}}');
INSERT INTO "events" VALUES(31,'evt_afac28f91099d22ac75322d15f31e067','env_4228c787fe79f5282a9a007d27a25cc4','policy_changed',NULL,'2026-11-24T07:56:08.009427000Z','{"schema_version":"1","event_id":"evt_afac28f91099d22ac75322d15f31e067","type":"policy_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:08.009427Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":4}}');
INSERT INTO "events" VALUES(32,'evt_9e1d0e6fab242f497cf2a0a93f879fd0','env_4228c787fe79f5282a9a007d27a25cc4','decision',NULL,'2026-11-24T07:56:08.018886000Z','{"schema_version":"1","event_id":"evt_9e1d0e6fab242f497cf2a0a93f879fd0","type":"decision","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"decision","id":"dec_c550249faecae8ed80ea24a7c8528012"},"timestamp":"2026-11-24T07:56:08.018886Z","cursor":"","payload":{"decision_id":"dec_c550249faecae8ed80ea24a7c8528012","expires_at":"2026-11-24T08:11:08.018741Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(33,'evt_d82759fad7c719b6e526ff8b1e5d2668','env_4228c787fe79f5282a9a007d27a25cc4','policy_changed',NULL,'2026-11-24T07:56:08.028843000Z','{"schema_version":"1","event_id":"evt_d82759fad7c719b6e526ff8b1e5d2668","type":"policy_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:08.028843Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":5}}');
INSERT INTO "events" VALUES(34,'evt_ef5d47f64d05e260f0f36ca0efcc399b','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0c84168c3a77feaa91b0f5cd269afc7b','2026-11-24T07:56:08.039510000Z','{"schema_version":"1","event_id":"evt_ef5d47f64d05e260f0f36ca0efcc399b","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0c84168c3a77feaa91b0f5cd269afc7b","resource":{"kind":"operation","id":"op_0c84168c3a77feaa91b0f5cd269afc7b"},"timestamp":"2026-11-24T07:56:08.03951Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"catalog","state":"queued"}}');
INSERT INTO "events" VALUES(35,'evt_422e3ec80b40681afe0be998095859fa','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_0c84168c3a77feaa91b0f5cd269afc7b','2026-11-24T07:56:08.040531000Z','{"schema_version":"1","event_id":"evt_422e3ec80b40681afe0be998095859fa","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_0c84168c3a77feaa91b0f5cd269afc7b","resource":{"kind":"operation","id":"op_0c84168c3a77feaa91b0f5cd269afc7b"},"timestamp":"2026-11-24T07:56:08.040531Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"catalog","state":"succeeded"}}');
INSERT INTO "events" VALUES(36,'evt_1a7192f15a99bf221e8d88359cdf8fe6','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed',NULL,'2026-11-24T07:56:08.061033000Z','{"schema_version":"1","event_id":"evt_1a7192f15a99bf221e8d88359cdf8fe6","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","resource":{"kind":"grant","id":"grant_17ec6f73dd454da6d4812cf949584635"},"timestamp":"2026-11-24T07:56:08.061033Z","cursor":"","payload":{"grant_id":"grant_17ec6f73dd454da6d4812cf949584635","state":"released"}}');
INSERT INTO "events" VALUES(37,'evt_446ce91fb16220a8a4880770088b3986','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_680f2bbf52a281420139ce66dc2c8e5f','2026-11-24T07:56:08.071291000Z','{"schema_version":"1","event_id":"evt_446ce91fb16220a8a4880770088b3986","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_680f2bbf52a281420139ce66dc2c8e5f","resource":{"kind":"operation","id":"op_680f2bbf52a281420139ce66dc2c8e5f"},"timestamp":"2026-11-24T07:56:08.071291Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(38,'evt_0a76b06d346da463e9a8a0918ca6b9fe','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_680f2bbf52a281420139ce66dc2c8e5f','2026-11-24T07:56:08.072886000Z','{"schema_version":"1","event_id":"evt_0a76b06d346da463e9a8a0918ca6b9fe","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_680f2bbf52a281420139ce66dc2c8e5f","resource":{"kind":"operation","id":"op_680f2bbf52a281420139ce66dc2c8e5f"},"timestamp":"2026-11-24T07:56:08.072886Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(39,'evt_9594df6f6b715dd1cecbae9230b720f9','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_680f2bbf52a281420139ce66dc2c8e5f','2026-11-24T07:56:08.073577000Z','{"schema_version":"1","event_id":"evt_9594df6f6b715dd1cecbae9230b720f9","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_680f2bbf52a281420139ce66dc2c8e5f","resource":{"kind":"operation","id":"op_680f2bbf52a281420139ce66dc2c8e5f"},"timestamp":"2026-11-24T07:56:08.073577Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
INSERT INTO "events" VALUES(40,'evt_f9e9ca0e6aa4025c86a8613925e7176d','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.083652000Z','{"schema_version":"1","event_id":"evt_f9e9ca0e6aa4025c86a8613925e7176d","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"operation","id":"op_efc1618801eb06f1c5a9bdafee138114"},"timestamp":"2026-11-24T07:56:08.083652Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(41,'evt_0cdea0cb1084e76cb0817f85336a9c04','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.085109000Z','{"schema_version":"1","event_id":"evt_0cdea0cb1084e76cb0817f85336a9c04","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:08.085109Z","cursor":"","payload":{"grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","state":"revoking"}}');
INSERT INTO "events" VALUES(42,'evt_ec020c83c0f4e923214dd5cb40b708cb','env_4228c787fe79f5282a9a007d27a25cc4','credential_lifecycle','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.085150000Z','{"schema_version":"1","event_id":"evt_ec020c83c0f4e923214dd5cb40b708cb","type":"credential_lifecycle","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:08.08515Z","cursor":"","payload":{"cause":"revoke","event":"revoked_locally","grant_id":"grant_506ffeb57417453c89d4e832875f6a3f"}}');
INSERT INTO "events" VALUES(43,'evt_5d2e3bd2441473e84f264802d0fffe73','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.085402000Z','{"schema_version":"1","event_id":"evt_5d2e3bd2441473e84f264802d0fffe73","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"operation","id":"op_efc1618801eb06f1c5a9bdafee138114"},"timestamp":"2026-11-24T07:56:08.085402Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(44,'evt_4f919b7c9570170c84d150a39cd923e5','env_4228c787fe79f5282a9a007d27a25cc4','grant_state_changed','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.086551000Z','{"schema_version":"1","event_id":"evt_4f919b7c9570170c84d150a39cd923e5","type":"grant_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"grant","id":"grant_506ffeb57417453c89d4e832875f6a3f"},"timestamp":"2026-11-24T07:56:08.086551Z","cursor":"","payload":{"grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","state":"revoked"}}');
INSERT INTO "events" VALUES(45,'evt_289e6db26963a358ff250c3e9fda2f8b','env_4228c787fe79f5282a9a007d27a25cc4','operation_state_changed','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.086714000Z','{"schema_version":"1","event_id":"evt_289e6db26963a358ff250c3e9fda2f8b","type":"operation_state_changed","environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","operation_id":"op_efc1618801eb06f1c5a9bdafee138114","resource":{"kind":"operation","id":"op_efc1618801eb06f1c5a9bdafee138114"},"timestamp":"2026-11-24T07:56:08.086714Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
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
INSERT INTO "grant_anchors" VALUES('grant_17ec6f73dd454da6d4812cf949584635','{"grant":"grant_17ec6f73dd454da6d4812cf949584635","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081130,"nanos":358812250},"wall":"2026-11-24T07:56:07.868122Z"},"bound":"2026-11-24T09:56:07.865685Z","budget_end":{"secs":1088330,"nanos":356374875}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088330356374875,'2026-11-24T09:56:07.865685000Z');
INSERT INTO "grant_anchors" VALUES('grant_506ffeb57417453c89d4e832875f6a3f','{"grant":"grant_506ffeb57417453c89d4e832875f6a3f","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081130,"nanos":452724916},"wall":"2026-11-24T07:56:07.962036Z"},"bound":"2026-11-24T09:56:07.948264Z","budget_end":{"secs":1088330,"nanos":438952875}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088330438952875,'2026-11-24T09:56:07.948264000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_17ec6f73dd454da6d4812cf949584635','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:07.873971Z"}');
INSERT INTO "grant_prepared_facts" VALUES('grant_506ffeb57417453c89d4e832875f6a3f','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:07.966508Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_a56715c42c08e8b3d353612441a5b6a1','grant_506ffeb57417453c89d4e832875f6a3f','2026-11-24T07:56:07.968053000Z');
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
INSERT INTO "grants" VALUES('grant_17ec6f73dd454da6d4812cf949584635','env_4228c787fe79f5282a9a007d27a25cc4',NULL,'released','2026-11-24T07:56:07.867418000Z','2026-11-24T09:56:07.865685000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.865685Z","effective":"2026-11-24T09:56:07.865685Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_17ec6f73dd454da6d4812cf949584635","environment":"env_4228c787fe79f5282a9a007d27a25cc4","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:07.867418Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.865685Z","effective":"2026-11-24T09:56:07.865685Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"released","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:56:07.867418000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"policy_id":"pol"}');
INSERT INTO "grants" VALUES('grant_06f8a0361b8a90521c728a2be5e31b4d','env_4228c787fe79f5282a9a007d27a25cc4',NULL,'awaiting_approval','2026-11-24T07:56:07.909468000Z','2026-11-24T09:56:07.909468000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.909468Z","effective":"2026-11-24T09:56:07.909468Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_06f8a0361b8a90521c728a2be5e31b4d","environment":"env_4228c787fe79f5282a9a007d27a25cc4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:07.909468Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.909468Z","effective":"2026-11-24T09:56:07.909468Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_5df1415aeee0c26f0602e026060782ae"},"generation":3,"state":"awaiting_approval","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:56:07.909468000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_11c99014b79d0748fe405024b2271a9a','env_4228c787fe79f5282a9a007d27a25cc4',NULL,'denied','2026-11-24T07:56:07.921742000Z','2026-11-24T09:56:07.921742000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.921742Z","effective":"2026-11-24T09:56:07.921742Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_11c99014b79d0748fe405024b2271a9a","environment":"env_4228c787fe79f5282a9a007d27a25cc4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:07.921742Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.921742Z","effective":"2026-11-24T09:56:07.921742Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_a5e5a28cad80d22ddce5f5d74dec4a34"},"generation":3,"state":"denied","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:56:07.921742000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_506ffeb57417453c89d4e832875f6a3f','env_4228c787fe79f5282a9a007d27a25cc4',NULL,'revoked','2026-11-24T07:56:07.948264000Z','2026-11-24T09:56:07.948264000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.948264Z","effective":"2026-11-24T09:56:07.948264Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_506ffeb57417453c89d4e832875f6a3f","environment":"env_4228c787fe79f5282a9a007d27a25cc4","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:07.948264Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.948264Z","effective":"2026-11-24T09:56:07.948264Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_0f2fbf6dfa09840068aaed4989ca343c"},"generation":3,"state":"revoked","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:56:07.948264000Z','{"decision":"dec_dc06ef58c42f2352236b9b318d73b4f9","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}','{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r1','c2aa55480c5544860c02044f8405c6d06796189d258dafd4f06fe238cd1cb996','op_cd4e86a1ad1137704de0455d856b63be','2026-11-24T07:56:07.860033000Z','2026-12-01T07:56:07.875667000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r2','56e48df93c3914a97fc301c88f4e3cc9edd424acdee34faccc93a948ffe92beb','op_5df1415aeee0c26f0602e026060782ae','2026-11-24T07:56:07.908309000Z',NULL);
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r3','4e7c64e6444c3506805257ac447627e7f60c00846f96cdb4d9ca201b8a5f293a','op_a5e5a28cad80d22ddce5f5d74dec4a34','2026-11-24T07:56:07.920494000Z','2026-12-01T07:56:07.934609000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r4','5ee354dffa33288622b694dd21779cdf38a729c56fa3c666479909b126b93c92','op_0f2fbf6dfa09840068aaed4989ca343c','2026-11-24T07:56:07.946280000Z','2026-12-01T07:56:07.968053000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','catalog','d1','5b1a8fc3d8c86d75717b55bada6b818283b198ab56b991dc0054fdbb80b6d81c','op_0c84168c3a77feaa91b0f5cd269afc7b','2026-11-24T07:56:08.039093000Z','2026-12-01T07:56:08.039892000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','rv1','17515c18985e5cb3edd0f7c5da251a60a444adb91d71b34037abbf5b65eff25b','op_680f2bbf52a281420139ce66dc2c8e5f','2026-11-24T07:56:08.070607000Z','2026-12-01T07:56:08.071775000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','s1','7d8989921aca5a834c2a41f5431146cc6b824394d4360d05192480826acf19b3','op_efc1618801eb06f1c5a9bdafee138114','2026-11-24T07:56:08.083272000Z','2026-12-01T07:56:08.084421000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:56:08.084800000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081130,"nanos":575487708},"wall":"2026-11-24T07:56:08.0848Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtestd8fc533e81a571712cf047ce65109c5c');
INSERT INTO "meta" VALUES('self_environment_id','env_4228c787fe79f5282a9a007d27a25cc4');
INSERT INTO "meta" VALUES('authority_generation','10');
INSERT INTO "meta" VALUES('m05.default_profile:env_4228c787fe79f5282a9a007d27a25cc4','dev');
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
INSERT INTO "operations" VALUES('op_cd4e86a1ad1137704de0455d856b63be','ensure','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r1','c2aa55480c5544860c02044f8405c6d06796189d258dafd4f06fe238cd1cb996','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_548219d74c51f900132f57ad278c2896","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","expires_at":"2026-11-24T09:56:07.865685Z","grant_id":"grant_17ec6f73dd454da6d4812cf949584635","offline_until":"2026-11-24T08:56:07.638704Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.865685Z"}','{"id":"op_cd4e86a1ad1137704de0455d856b63be","kind":"ensure","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r1"},"request_hash":"c2aa55480c5544860c02044f8405c6d06796189d258dafd4f06fe238cd1cb996","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_548219d74c51f900132f57ad278c2896","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","expires_at":"2026-11-24T09:56:07.865685Z","grant_id":"grant_17ec6f73dd454da6d4812cf949584635","offline_until":"2026-11-24T08:56:07.638704Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.865685Z"},"created_at":"2026-11-24T07:56:07.860033Z","updated_at":"2026-11-24T07:56:07.875667Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:07.860033000Z','2026-11-24T07:56:07.875667000Z','2026-11-24T07:56:07.875667000Z');
INSERT INTO "operations" VALUES('op_5df1415aeee0c26f0602e026060782ae','ensure','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r2','56e48df93c3914a97fc301c88f4e3cc9edd424acdee34faccc93a948ffe92beb','local_resources','awaiting_approval',NULL,'none',NULL,'{"id":"op_5df1415aeee0c26f0602e026060782ae","kind":"ensure","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r2"},"request_hash":"56e48df93c3914a97fc301c88f4e3cc9edd424acdee34faccc93a948ffe92beb","effect_class":"local_resources","state":"awaiting_approval","code":null,"effect_status":"none","result":null,"created_at":"2026-11-24T07:56:07.908309Z","updated_at":"2026-11-24T07:56:07.909468Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:07.908309000Z','2026-11-24T07:56:07.909468000Z',NULL);
INSERT INTO "operations" VALUES('op_a5e5a28cad80d22ddce5f5d74dec4a34','ensure','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r3','4e7c64e6444c3506805257ac447627e7f60c00846f96cdb4d9ca201b8a5f293a','local_resources','failed','CAPABILITY_UNAVAILABLE','none','{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}}','{"id":"op_a5e5a28cad80d22ddce5f5d74dec4a34","kind":"ensure","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r3"},"request_hash":"4e7c64e6444c3506805257ac447627e7f60c00846f96cdb4d9ca201b8a5f293a","effect_class":"local_resources","state":"failed","code":"CAPABILITY_UNAVAILABLE","effect_status":"none","result":{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}},"created_at":"2026-11-24T07:56:07.920494Z","updated_at":"2026-11-24T07:56:07.934609Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:07.920494000Z','2026-11-24T07:56:07.934609000Z','2026-11-24T07:56:07.934609000Z');
INSERT INTO "operations" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c','ensure','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r4','5ee354dffa33288622b694dd21779cdf38a729c56fa3c666479909b126b93c92','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_a56715c42c08e8b3d353612441a5b6a1","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","expires_at":"2026-11-24T09:56:07.948264Z","grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","offline_until":"2026-11-24T08:56:07.638704Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.948264Z"}','{"id":"op_0f2fbf6dfa09840068aaed4989ca343c","kind":"ensure","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r4"},"request_hash":"5ee354dffa33288622b694dd21779cdf38a729c56fa3c666479909b126b93c92","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_a56715c42c08e8b3d353612441a5b6a1","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","expires_at":"2026-11-24T09:56:07.948264Z","grant_id":"grant_506ffeb57417453c89d4e832875f6a3f","offline_until":"2026-11-24T08:56:07.638704Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:07.948264Z"},"created_at":"2026-11-24T07:56:07.94628Z","updated_at":"2026-11-24T07:56:07.968053Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:07.946280000Z','2026-11-24T07:56:07.968053000Z','2026-11-24T07:56:07.968053000Z');
INSERT INTO "operations" VALUES('op_0c84168c3a77feaa91b0f5cd269afc7b','catalog','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','d1','5b1a8fc3d8c86d75717b55bada6b818283b198ab56b991dc0054fdbb80b6d81c','local','succeeded','OK','applied','{"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","profile_id":"dev"}','{"id":"op_0c84168c3a77feaa91b0f5cd269afc7b","kind":"catalog","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"catalog","request_id":"d1"},"request_hash":"5b1a8fc3d8c86d75717b55bada6b818283b198ab56b991dc0054fdbb80b6d81c","effect_class":"local","state":"succeeded","code":"OK","effect_status":"applied","result":{"environment_id":"env_4228c787fe79f5282a9a007d27a25cc4","profile_id":"dev"},"created_at":"2026-11-24T07:56:08.039093Z","updated_at":"2026-11-24T07:56:08.039892Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:08.039093000Z','2026-11-24T07:56:08.039892000Z','2026-11-24T07:56:08.039892000Z');
INSERT INTO "operations" VALUES('op_680f2bbf52a281420139ce66dc2c8e5f','revoke','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','rv1','17515c18985e5cb3edd0f7c5da251a60a444adb91d71b34037abbf5b65eff25b','local_resources','succeeded','OK','applied','{"committed_at":"2026-11-24T07:56:08.072135Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:08.070607Z"}','{"id":"op_680f2bbf52a281420139ce66dc2c8e5f","kind":"revoke","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"rv1"},"request_hash":"17515c18985e5cb3edd0f7c5da251a60a444adb91d71b34037abbf5b65eff25b","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"committed_at":"2026-11-24T07:56:08.072135Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:08.070607Z"},"created_at":"2026-11-24T07:56:08.070607Z","updated_at":"2026-11-24T07:56:08.071775Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:08.070607000Z','2026-11-24T07:56:08.071775000Z','2026-11-24T07:56:08.071775000Z');
INSERT INTO "operations" VALUES('op_efc1618801eb06f1c5a9bdafee138114','revoke','env_4228c787fe79f5282a9a007d27a25cc4','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','s1','7d8989921aca5a834c2a41f5431146cc6b824394d4360d05192480826acf19b3','local_resources','succeeded','OK','applied','{"committed_at":"2026-11-24T07:56:08.0848Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:08.083272Z"}','{"id":"op_efc1618801eb06f1c5a9bdafee138114","kind":"revoke","environment":"env_4228c787fe79f5282a9a007d27a25cc4","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"s1"},"request_hash":"7d8989921aca5a834c2a41f5431146cc6b824394d4360d05192480826acf19b3","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"committed_at":"2026-11-24T07:56:08.0848Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:08.083272Z"},"created_at":"2026-11-24T07:56:08.083272Z","updated_at":"2026-11-24T07:56:08.084421Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:08.083272000Z','2026-11-24T07:56:08.084421000Z','2026-11-24T07:56:08.084421000Z');
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
INSERT INTO "policies" VALUES('pol',5,'{"id":"pol","revision":5,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:08.028735Z"},"lock_behavior":"revoke_on_lock"}','2026-11-24T07:56:08.028735000Z');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
CREATE TABLE policy_history (
    policy_id   TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY (policy_id, revision)
) STRICT;
INSERT INTO "policy_history" VALUES('pol',2,'{"policy":"pol","revision":2,"record":{"id":"pol","revision":2,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"paused","since":"2026-11-24T07:56:07.979759Z"},"cutoff_at":null,"source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:07.979759Z"}},"cause":{"kind":"narrowing"},"at":"2026-11-24T07:56:07.979759Z"}','2026-11-24T07:56:07.979759000Z');
INSERT INTO "policy_history" VALUES('pol',3,'{"policy":"pol","revision":3,"record":{"id":"pol","revision":3,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:07.999398Z"}},"cause":{"kind":"decision","decision":"dec_76d730184ea9b864b9af876873202ddb"},"at":"2026-11-24T07:56:07.999398Z"}','2026-11-24T07:56:07.999398000Z');
INSERT INTO "policy_history" VALUES('pol',4,'{"policy":"pol","revision":4,"record":{"id":"pol","revision":4,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:08.009331Z"}},"cause":{"kind":"narrowing"},"at":"2026-11-24T07:56:08.009331Z"}','2026-11-24T07:56:08.009331000Z');
INSERT INTO "policy_history" VALUES('pol',5,'{"policy":"pol","revision":5,"record":{"id":"pol","revision":5,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_4228c787fe79f5282a9a007d27a25cc4"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:08.028735Z"},"lock_behavior":"revoke_on_lock"},"cause":{"kind":"narrowing"},"at":"2026-11-24T07:56:08.028735Z"}','2026-11-24T07:56:08.028735000Z');
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
INSERT INTO "recovery_intents" VALUES('op_cd4e86a1ad1137704de0455d856b63be','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r1","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w1"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.865685Z","effective":"2026-11-24T09:56:07.865685Z"},"policy_revision":1,"generation":3,"grant":"grant_17ec6f73dd454da6d4812cf949584635","binding":"binding_548219d74c51f900132f57ad278c2896","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_5df1415aeee0c26f0602e026060782ae','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r2","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w2"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.909468Z","effective":"2026-11-24T09:56:07.909468Z"},"policy_revision":1,"generation":3,"grant":"grant_06f8a0361b8a90521c728a2be5e31b4d","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_a5e5a28cad80d22ddce5f5d74dec4a34','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r3","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w3"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.921742Z","effective":"2026-11-24T09:56:07.921742Z"},"policy_revision":1,"generation":3,"grant":"grant_11c99014b79d0748fe405024b2271a9a","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r4","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w4"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:07.948264Z","effective":"2026-11-24T09:56:07.948264Z"},"policy_revision":1,"generation":3,"grant":"grant_506ffeb57417453c89d4e832875f6a3f","binding":"binding_a56715c42c08e8b3d353612441a5b6a1","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"approval":{"decision":"dec_dc06ef58c42f2352236b9b318d73b4f9","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}}}');
INSERT INTO "recovery_intents" VALUES('op_0c84168c3a77feaa91b0f5cd269afc7b','{"request":{"action":"set_default_profile","profile":"dev","request_id":"d1"},"resolved":null,"local":{"kind":"catalog","action":{"action":"set_default_profile","profile":"dev"}}}');
INSERT INTO "recovery_intents" VALUES('op_680f2bbf52a281420139ce66dc2c8e5f','{"request":{"grant_id":"grant_17ec6f73dd454da6d4812cf949584635","op":"revoke","request_id":"rv1"},"resolved":null}');
INSERT INTO "recovery_intents" VALUES('op_efc1618801eb06f1c5a9bdafee138114','{"request":{"op":"revoke","request_id":"s1","target":{"environment":"env_4228c787fe79f5282a9a007d27a25cc4","kind":"work","work_id":"w4"}},"resolved":null}');
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
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:07.860033Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:07.86492Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:07.865685Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:07.867064Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.868122Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_27f6fcf353f21760e18a6c61dcb8f201"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.873971Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',7,'{"stage":"probe","recorded_at":"2026-11-24T07:56:07.874812Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:56:07.875095Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_cd4e86a1ad1137704de0455d856b63be',9,'{"stage":"commit","recorded_at":"2026-11-24T07:56:07.875667Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5df1415aeee0c26f0602e026060782ae',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:07.908309Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5df1415aeee0c26f0602e026060782ae',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:07.909184Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5df1415aeee0c26f0602e026060782ae',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:07.909468Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_a5e5a28cad80d22ddce5f5d74dec4a34',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:07.920494Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_a5e5a28cad80d22ddce5f5d74dec4a34',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:07.921439Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_a5e5a28cad80d22ddce5f5d74dec4a34',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:07.921742Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:07.94628Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:07.947876Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:07.948264Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:07.961538Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.962036Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_96cedf62c32fda79e395f6a90d37e848"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:07.966508Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',7,'{"stage":"probe","recorded_at":"2026-11-24T07:56:07.967045Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:56:07.967411Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_0f2fbf6dfa09840068aaed4989ca343c',9,'{"stage":"commit","recorded_at":"2026-11-24T07:56:07.968053Z","effect":{"kind":"not_attempted"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "tombstones" VALUES('grant_17ec6f73dd454da6d4812cf949584635',8,'2026-11-24T07:56:08.072135000Z','{"grant":"grant_17ec6f73dd454da6d4812cf949584635","cascade":[],"generation":8,"revoked_at":"2026-11-24T07:56:08.072135Z","remote_pending":[],"cause":"revoke"}');
INSERT INTO "tombstones" VALUES('grant_506ffeb57417453c89d4e832875f6a3f',10,'2026-11-24T07:56:08.084800000Z','{"grant":"grant_506ffeb57417453c89d4e832875f6a3f","cascade":[],"generation":10,"revoked_at":"2026-11-24T07:56:08.0848Z","remote_pending":[],"cause":"revoke"}');
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
INSERT INTO "work_stops" VALUES('env_4228c787fe79f5282a9a007d27a25cc4','w4','2026-11-24T07:56:08.084800000Z','{"environment":"env_4228c787fe79f5282a9a007d27a25cc4","work_id":"w4","stopped_at":"2026-11-24T07:56:08.0848Z"}');
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
INSERT INTO "sqlite_sequence" VALUES('events',45);
COMMIT;
