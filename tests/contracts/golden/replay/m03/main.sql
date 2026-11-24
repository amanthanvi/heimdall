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
INSERT INTO "bindings" VALUES('binding_77af27ebf074466dbb8dc1d2a5f417d2','env_db186ff6a697f997104df2c4e0f82212','grant_931c075f52679325fa4116ab9a82c269','w1','{"id":"binding_77af27ebf074466dbb8dc1d2a5f417d2","environment":"env_db186ff6a697f997104df2c4e0f82212","grant":"grant_931c075f52679325fa4116ab9a82c269","work_id":"w1","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:56:03.652337Z","released_at":"2026-11-24T07:56:03.818925Z","state":"released"}','2026-11-24T07:56:03.652337000Z','2026-11-24T07:56:03.818925000Z','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'released');
INSERT INTO "bindings" VALUES('binding_9992b274658bfabb332c125ef2359673','env_db186ff6a697f997104df2c4e0f82212','grant_7fa03d1f48a3645f905922cede9a9656','w4','{"id":"binding_9992b274658bfabb332c125ef2359673","environment":"env_db186ff6a697f997104df2c4e0f82212","grant":"grant_7fa03d1f48a3645f905922cede9a9656","work_id":"w4","owner":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"mechanism":"fake_agent","parent":null,"created_at":"2026-11-24T07:56:03.740333Z","released_at":null,"state":"active"}','2026-11-24T07:56:03.740333000Z',NULL,'{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','dev',1,'{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}','fake_agent',NULL,'active');
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
INSERT INTO "decisions" VALUES('dec_3378926b1a02a9f705ae9e3320dfe203','{"kind":"approve_authority","operation":"op_c5085a22474fca5496f31326b54c18b0","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:03.682815000Z','2026-11-24T08:11:03.682815000Z','pending',NULL,'{"id":"dec_3378926b1a02a9f705ae9e3320dfe203","kind":{"kind":"approve_authority","operation":"op_c5085a22474fca5496f31326b54c18b0","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:03.682815Z","expires_at":"2026-11-24T08:11:03.682815Z","state":"pending","decided_at":null}');
INSERT INTO "decisions" VALUES('dec_7773981755ae4bafa98d6dd784d9a00b','{"kind":"approve_authority","operation":"op_3e0f0a19b458892f791f2fd74c85a959","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:03.694269000Z','2026-11-24T08:11:03.694269000Z','denied','2026-11-24T07:56:03.706042000Z','{"id":"dec_7773981755ae4bafa98d6dd784d9a00b","kind":{"kind":"approve_authority","operation":"op_3e0f0a19b458892f791f2fd74c85a959","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:03.694269Z","expires_at":"2026-11-24T08:11:03.694269Z","state":"denied","decided_at":"2026-11-24T07:56:03.706042Z"}');
INSERT INTO "decisions" VALUES('dec_2cd2bc0b222ea1e526ec7a58c2bff527','{"kind":"approve_authority","operation":"op_2683acdb92ea8b00755b2d1549103c36","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}}',3,'2026-11-24T07:56:03.717501000Z','2026-11-24T08:11:03.717501000Z','approved','2026-11-24T07:56:03.732681000Z','{"id":"dec_2cd2bc0b222ea1e526ec7a58c2bff527","kind":{"kind":"approve_authority","operation":"op_2683acdb92ea8b00755b2d1549103c36","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false}},"generation":3,"created_at":"2026-11-24T07:56:03.717501Z","expires_at":"2026-11-24T08:11:03.717501Z","state":"approved","decided_at":"2026-11-24T07:56:03.732681Z"}');
INSERT INTO "decisions" VALUES('dec_53c8b3af8038d172bdc9f747b0616159','{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}}',4,'2026-11-24T07:56:03.761129000Z','2026-11-24T08:11:03.761129000Z','approved','2026-11-24T07:56:03.771861000Z','{"id":"dec_53c8b3af8038d172bdc9f747b0616159","kind":{"kind":"widen_policy","action":{"action":"resume","policy_id":"pol"}},"generation":4,"created_at":"2026-11-24T07:56:03.761129Z","expires_at":"2026-11-24T08:11:03.761129Z","state":"approved","decided_at":"2026-11-24T07:56:03.771861Z"}');
INSERT INTO "decisions" VALUES('dec_252cc665147db07aabab785601178841','{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}}',6,'2026-11-24T07:56:03.790834000Z','2026-11-24T08:11:03.790834000Z','pending',NULL,'{"id":"dec_252cc665147db07aabab785601178841","kind":{"kind":"widen_policy","action":{"action":"clear_cutoff","policy_id":"pol"}},"generation":6,"created_at":"2026-11-24T07:56:03.790834Z","expires_at":"2026-11-24T08:11:03.790834Z","state":"pending","decided_at":null}');
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
INSERT INTO "environments" VALUES('env_db186ff6a697f997104df2c4e0f82212','{"id":"env_db186ff6a697f997104df2c4e0f82212","device":"dev_32313232386630653463326664343031","kind":"native_session","label":null,"permissions":{"automatic_activation":true,"managed_signing":true,"issuer_access":true}}','');
CREATE TABLE events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    environment  TEXT NOT NULL,
    type         TEXT NOT NULL,
    operation_id TEXT,
    timestamp    TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "events" VALUES(1,'evt_9f7665f6dbe360d6c7c94a14d559c923','env_db186ff6a697f997104df2c4e0f82212','runtime_lifecycle',NULL,'2026-11-24T07:56:03.583167000Z','{"schema_version":"1","event_id":"evt_9f7665f6dbe360d6c7c94a14d559c923","type":"runtime_lifecycle","environment_id":"env_db186ff6a697f997104df2c4e0f82212","timestamp":"2026-11-24T07:56:03.583167Z","cursor":"","payload":{"open_operations":0,"phase":"started","unresolved_operations":0}}');
INSERT INTO "events" VALUES(2,'evt_d93231ac5005811aa53dbbb58256aca3','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.639079000Z','{"schema_version":"1","event_id":"evt_d93231ac5005811aa53dbbb58256aca3","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_5a7489aca75b17983caeee13d880ee96","resource":{"kind":"operation","id":"op_5a7489aca75b17983caeee13d880ee96"},"timestamp":"2026-11-24T07:56:03.639079Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(3,'evt_c8d73bdd5df15c0bc5338a51f67ecaba','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.644174000Z','{"schema_version":"1","event_id":"evt_c8d73bdd5df15c0bc5338a51f67ecaba","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_5a7489aca75b17983caeee13d880ee96","resource":{"kind":"operation","id":"op_5a7489aca75b17983caeee13d880ee96"},"timestamp":"2026-11-24T07:56:03.644174Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(4,'evt_e81563a008a7d162a17c476918cb480f','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.645546000Z','{"schema_version":"1","event_id":"evt_e81563a008a7d162a17c476918cb480f","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_5a7489aca75b17983caeee13d880ee96","resource":{"kind":"grant","id":"grant_931c075f52679325fa4116ab9a82c269"},"timestamp":"2026-11-24T07:56:03.645546Z","cursor":"","payload":{"grant_id":"grant_931c075f52679325fa4116ab9a82c269","state":"preparing"}}');
INSERT INTO "events" VALUES(5,'evt_6c1ae147622e355db031598c450da82a','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.652734000Z','{"schema_version":"1","event_id":"evt_6c1ae147622e355db031598c450da82a","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_5a7489aca75b17983caeee13d880ee96","resource":{"kind":"grant","id":"grant_931c075f52679325fa4116ab9a82c269"},"timestamp":"2026-11-24T07:56:03.652734Z","cursor":"","payload":{"grant_id":"grant_931c075f52679325fa4116ab9a82c269","state":"active"}}');
INSERT INTO "events" VALUES(6,'evt_991bfcacda1245721383096de4573e33','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.653069000Z','{"schema_version":"1","event_id":"evt_991bfcacda1245721383096de4573e33","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_5a7489aca75b17983caeee13d880ee96","resource":{"kind":"operation","id":"op_5a7489aca75b17983caeee13d880ee96"},"timestamp":"2026-11-24T07:56:03.653069Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(7,'evt_107ccaf6582be72903374747b4862445','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_c5085a22474fca5496f31326b54c18b0','2026-11-24T07:56:03.682016000Z','{"schema_version":"1","event_id":"evt_107ccaf6582be72903374747b4862445","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_c5085a22474fca5496f31326b54c18b0","resource":{"kind":"operation","id":"op_c5085a22474fca5496f31326b54c18b0"},"timestamp":"2026-11-24T07:56:03.682016Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(8,'evt_dce6c6387378054bc7efb541eec1929a','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_c5085a22474fca5496f31326b54c18b0','2026-11-24T07:56:03.683231000Z','{"schema_version":"1","event_id":"evt_dce6c6387378054bc7efb541eec1929a","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_c5085a22474fca5496f31326b54c18b0","resource":{"kind":"grant","id":"grant_5bd322e2796028b63eca7f55439981f8"},"timestamp":"2026-11-24T07:56:03.683231Z","cursor":"","payload":{"grant_id":"grant_5bd322e2796028b63eca7f55439981f8","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(9,'evt_bef2c5ce1718646c1998b8683e52c37c','env_db186ff6a697f997104df2c4e0f82212','decision','op_c5085a22474fca5496f31326b54c18b0','2026-11-24T07:56:03.683283000Z','{"schema_version":"1","event_id":"evt_bef2c5ce1718646c1998b8683e52c37c","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_c5085a22474fca5496f31326b54c18b0","resource":{"kind":"decision","id":"dec_3378926b1a02a9f705ae9e3320dfe203"},"timestamp":"2026-11-24T07:56:03.683283Z","cursor":"","payload":{"decision_id":"dec_3378926b1a02a9f705ae9e3320dfe203","expires_at":"2026-11-24T08:11:03.682815Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(10,'evt_1721c58a874ef903924b0712b897c6dd','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_c5085a22474fca5496f31326b54c18b0','2026-11-24T07:56:03.683439000Z','{"schema_version":"1","event_id":"evt_1721c58a874ef903924b0712b897c6dd","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_c5085a22474fca5496f31326b54c18b0","resource":{"kind":"operation","id":"op_c5085a22474fca5496f31326b54c18b0"},"timestamp":"2026-11-24T07:56:03.683439Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(11,'evt_3b642b7d7322d7cae052e845345bb0fd','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.693554000Z','{"schema_version":"1","event_id":"evt_3b642b7d7322d7cae052e845345bb0fd","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"operation","id":"op_3e0f0a19b458892f791f2fd74c85a959"},"timestamp":"2026-11-24T07:56:03.693554Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(12,'evt_4e6ab6a82864ece0d8dbaaaaff77f1a1','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.694726000Z','{"schema_version":"1","event_id":"evt_4e6ab6a82864ece0d8dbaaaaff77f1a1","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"grant","id":"grant_135d80c6b18fad14288302fa456c0a3f"},"timestamp":"2026-11-24T07:56:03.694726Z","cursor":"","payload":{"grant_id":"grant_135d80c6b18fad14288302fa456c0a3f","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(13,'evt_a0da6171bf425eb6208bb79886c3d6a7','env_db186ff6a697f997104df2c4e0f82212','decision','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.694759000Z','{"schema_version":"1","event_id":"evt_a0da6171bf425eb6208bb79886c3d6a7","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"decision","id":"dec_7773981755ae4bafa98d6dd784d9a00b"},"timestamp":"2026-11-24T07:56:03.694759Z","cursor":"","payload":{"decision_id":"dec_7773981755ae4bafa98d6dd784d9a00b","expires_at":"2026-11-24T08:11:03.694269Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(14,'evt_b05708a0af2bae8174158d1844ffb5a4','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.694896000Z','{"schema_version":"1","event_id":"evt_b05708a0af2bae8174158d1844ffb5a4","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"operation","id":"op_3e0f0a19b458892f791f2fd74c85a959"},"timestamp":"2026-11-24T07:56:03.694896Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(15,'evt_a7892def86e3a9f3e9d83492c6185951','env_db186ff6a697f997104df2c4e0f82212','decision','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.706416000Z','{"schema_version":"1","event_id":"evt_a7892def86e3a9f3e9d83492c6185951","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"decision","id":"dec_7773981755ae4bafa98d6dd784d9a00b"},"timestamp":"2026-11-24T07:56:03.706416Z","cursor":"","payload":{"decision_id":"dec_7773981755ae4bafa98d6dd784d9a00b","expires_at":"2026-11-24T08:11:03.694269Z","kind":"approve_authority","state":"denied"}}');
INSERT INTO "events" VALUES(16,'evt_3067b41ceafe1cbd0eea5dac1f9b73e8','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.706602000Z','{"schema_version":"1","event_id":"evt_3067b41ceafe1cbd0eea5dac1f9b73e8","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"grant","id":"grant_135d80c6b18fad14288302fa456c0a3f"},"timestamp":"2026-11-24T07:56:03.706602Z","cursor":"","payload":{"grant_id":"grant_135d80c6b18fad14288302fa456c0a3f","state":"denied"}}');
INSERT INTO "events" VALUES(17,'evt_20f9773d7d3f2993d8a0474e326388fa','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.706731000Z','{"schema_version":"1","event_id":"evt_20f9773d7d3f2993d8a0474e326388fa","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959","resource":{"kind":"operation","id":"op_3e0f0a19b458892f791f2fd74c85a959"},"timestamp":"2026-11-24T07:56:03.706731Z","cursor":"","payload":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","kind":"ensure","state":"failed"}}');
INSERT INTO "events" VALUES(18,'evt_f230c8924939c2b208e13e189ffa8015','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.716601000Z','{"schema_version":"1","event_id":"evt_f230c8924939c2b208e13e189ffa8015","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"operation","id":"op_2683acdb92ea8b00755b2d1549103c36"},"timestamp":"2026-11-24T07:56:03.716601Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"queued"}}');
INSERT INTO "events" VALUES(19,'evt_1203342cc149055792b8d40686e7bc82','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.718001000Z','{"schema_version":"1","event_id":"evt_1203342cc149055792b8d40686e7bc82","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"grant","id":"grant_7fa03d1f48a3645f905922cede9a9656"},"timestamp":"2026-11-24T07:56:03.718001Z","cursor":"","payload":{"grant_id":"grant_7fa03d1f48a3645f905922cede9a9656","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(20,'evt_102ffc13610717c82477fe075784284e','env_db186ff6a697f997104df2c4e0f82212','decision','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.718043000Z','{"schema_version":"1","event_id":"evt_102ffc13610717c82477fe075784284e","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"decision","id":"dec_2cd2bc0b222ea1e526ec7a58c2bff527"},"timestamp":"2026-11-24T07:56:03.718043Z","cursor":"","payload":{"decision_id":"dec_2cd2bc0b222ea1e526ec7a58c2bff527","expires_at":"2026-11-24T08:11:03.717501Z","kind":"approve_authority","state":"pending"}}');
INSERT INTO "events" VALUES(21,'evt_8c41f6ebcf9015b81d9e1f11e92d4477','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.718207000Z','{"schema_version":"1","event_id":"evt_8c41f6ebcf9015b81d9e1f11e92d4477","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"operation","id":"op_2683acdb92ea8b00755b2d1549103c36"},"timestamp":"2026-11-24T07:56:03.718207Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"awaiting_approval"}}');
INSERT INTO "events" VALUES(22,'evt_7f800b0406fa510019d3f1062aad49f7','env_db186ff6a697f997104df2c4e0f82212','decision','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.733068000Z','{"schema_version":"1","event_id":"evt_7f800b0406fa510019d3f1062aad49f7","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"decision","id":"dec_2cd2bc0b222ea1e526ec7a58c2bff527"},"timestamp":"2026-11-24T07:56:03.733068Z","cursor":"","payload":{"decision_id":"dec_2cd2bc0b222ea1e526ec7a58c2bff527","expires_at":"2026-11-24T08:11:03.717501Z","kind":"approve_authority","state":"approved"}}');
INSERT INTO "events" VALUES(23,'evt_bf51c1b18a81a3671824740f5e1157f0','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.733267000Z','{"schema_version":"1","event_id":"evt_bf51c1b18a81a3671824740f5e1157f0","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"grant","id":"grant_7fa03d1f48a3645f905922cede9a9656"},"timestamp":"2026-11-24T07:56:03.733267Z","cursor":"","payload":{"grant_id":"grant_7fa03d1f48a3645f905922cede9a9656","state":"preparing"}}');
INSERT INTO "events" VALUES(24,'evt_38c9b08d4c283cde49c357203ca87ce9','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.733487000Z','{"schema_version":"1","event_id":"evt_38c9b08d4c283cde49c357203ca87ce9","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"operation","id":"op_2683acdb92ea8b00755b2d1549103c36"},"timestamp":"2026-11-24T07:56:03.733487Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"ensure","state":"running"}}');
INSERT INTO "events" VALUES(25,'evt_23a82797301f5c60d2416629676e0e36','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.740656000Z','{"schema_version":"1","event_id":"evt_23a82797301f5c60d2416629676e0e36","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"grant","id":"grant_7fa03d1f48a3645f905922cede9a9656"},"timestamp":"2026-11-24T07:56:03.740656Z","cursor":"","payload":{"grant_id":"grant_7fa03d1f48a3645f905922cede9a9656","state":"active"}}');
INSERT INTO "events" VALUES(26,'evt_02587e4cc0bf0ea3b2089ace19018f33','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.741007000Z','{"schema_version":"1","event_id":"evt_02587e4cc0bf0ea3b2089ace19018f33","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_2683acdb92ea8b00755b2d1549103c36","resource":{"kind":"operation","id":"op_2683acdb92ea8b00755b2d1549103c36"},"timestamp":"2026-11-24T07:56:03.741007Z","cursor":"","payload":{"code":"ACCESS_READY","effect_status":"applied","kind":"ensure","state":"succeeded"}}');
INSERT INTO "events" VALUES(27,'evt_986babe45686e76ab740c573284faf5d','env_db186ff6a697f997104df2c4e0f82212','policy_changed',NULL,'2026-11-24T07:56:03.751758000Z','{"schema_version":"1","event_id":"evt_986babe45686e76ab740c573284faf5d","type":"policy_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:03.751758Z","cursor":"","payload":{"cutoff_at":null,"paused":true,"policy_id":"pol","revision":2}}');
INSERT INTO "events" VALUES(28,'evt_e7403c436c2dcade1065247f1fef286f','env_db186ff6a697f997104df2c4e0f82212','decision',NULL,'2026-11-24T07:56:03.761292000Z','{"schema_version":"1","event_id":"evt_e7403c436c2dcade1065247f1fef286f","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"decision","id":"dec_53c8b3af8038d172bdc9f747b0616159"},"timestamp":"2026-11-24T07:56:03.761292Z","cursor":"","payload":{"decision_id":"dec_53c8b3af8038d172bdc9f747b0616159","expires_at":"2026-11-24T08:11:03.761129Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(29,'evt_a4d81681729735520bfa346cd190754b','env_db186ff6a697f997104df2c4e0f82212','decision',NULL,'2026-11-24T07:56:03.771966000Z','{"schema_version":"1","event_id":"evt_a4d81681729735520bfa346cd190754b","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"decision","id":"dec_53c8b3af8038d172bdc9f747b0616159"},"timestamp":"2026-11-24T07:56:03.771966Z","cursor":"","payload":{"decision_id":"dec_53c8b3af8038d172bdc9f747b0616159","expires_at":"2026-11-24T08:11:03.761129Z","kind":"widen_policy","state":"approved"}}');
INSERT INTO "events" VALUES(30,'evt_34a5e7f0d73e78277da47e289d22b6c2','env_db186ff6a697f997104df2c4e0f82212','policy_changed',NULL,'2026-11-24T07:56:03.772090000Z','{"schema_version":"1","event_id":"evt_34a5e7f0d73e78277da47e289d22b6c2","type":"policy_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:03.77209Z","cursor":"","payload":{"cutoff_at":null,"paused":false,"policy_id":"pol","revision":3}}');
INSERT INTO "events" VALUES(31,'evt_4e078f92d223e83796a27ee28833e817','env_db186ff6a697f997104df2c4e0f82212','policy_changed',NULL,'2026-11-24T07:56:03.781628000Z','{"schema_version":"1","event_id":"evt_4e078f92d223e83796a27ee28833e817","type":"policy_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:03.781628Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":4}}');
INSERT INTO "events" VALUES(32,'evt_e9fabe45562c1bb54d04ba03bbe0e3d8','env_db186ff6a697f997104df2c4e0f82212','decision',NULL,'2026-11-24T07:56:03.790974000Z','{"schema_version":"1","event_id":"evt_e9fabe45562c1bb54d04ba03bbe0e3d8","type":"decision","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"decision","id":"dec_252cc665147db07aabab785601178841"},"timestamp":"2026-11-24T07:56:03.790974Z","cursor":"","payload":{"decision_id":"dec_252cc665147db07aabab785601178841","expires_at":"2026-11-24T08:11:03.790834Z","kind":"widen_policy","state":"pending"}}');
INSERT INTO "events" VALUES(33,'evt_4bafb0aa88029b92152ca6d40021316b','env_db186ff6a697f997104df2c4e0f82212','policy_changed',NULL,'2026-11-24T07:56:03.800854000Z','{"schema_version":"1","event_id":"evt_4bafb0aa88029b92152ca6d40021316b","type":"policy_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"policy","id":"pol"},"timestamp":"2026-11-24T07:56:03.800854Z","cursor":"","payload":{"cutoff_at":"2099-01-01T00:00:00Z","paused":false,"policy_id":"pol","revision":5}}');
INSERT INTO "events" VALUES(34,'evt_f6c13287b3c998bcf58b55cffc869b4f','env_db186ff6a697f997104df2c4e0f82212','grant_state_changed',NULL,'2026-11-24T07:56:03.819312000Z','{"schema_version":"1","event_id":"evt_f6c13287b3c998bcf58b55cffc869b4f","type":"grant_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","resource":{"kind":"grant","id":"grant_931c075f52679325fa4116ab9a82c269"},"timestamp":"2026-11-24T07:56:03.819312Z","cursor":"","payload":{"grant_id":"grant_931c075f52679325fa4116ab9a82c269","state":"released"}}');
INSERT INTO "events" VALUES(35,'evt_1e8b8ea4a82f7347cc0c4b3689792269','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_14ba14cce4c62f295a3079664d41146c','2026-11-24T07:56:03.829415000Z','{"schema_version":"1","event_id":"evt_1e8b8ea4a82f7347cc0c4b3689792269","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_14ba14cce4c62f295a3079664d41146c","resource":{"kind":"operation","id":"op_14ba14cce4c62f295a3079664d41146c"},"timestamp":"2026-11-24T07:56:03.829415Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"queued"}}');
INSERT INTO "events" VALUES(36,'evt_af86d4d579a7fad52bab6bf40e67d5b5','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_14ba14cce4c62f295a3079664d41146c','2026-11-24T07:56:03.833491000Z','{"schema_version":"1","event_id":"evt_af86d4d579a7fad52bab6bf40e67d5b5","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_14ba14cce4c62f295a3079664d41146c","resource":{"kind":"operation","id":"op_14ba14cce4c62f295a3079664d41146c"},"timestamp":"2026-11-24T07:56:03.833491Z","cursor":"","payload":{"code":null,"effect_status":"none","kind":"revoke","state":"running"}}');
INSERT INTO "events" VALUES(37,'evt_092334c41af4cadd4c6a195f083ec665','env_db186ff6a697f997104df2c4e0f82212','operation_state_changed','op_14ba14cce4c62f295a3079664d41146c','2026-11-24T07:56:03.834528000Z','{"schema_version":"1","event_id":"evt_092334c41af4cadd4c6a195f083ec665","type":"operation_state_changed","environment_id":"env_db186ff6a697f997104df2c4e0f82212","operation_id":"op_14ba14cce4c62f295a3079664d41146c","resource":{"kind":"operation","id":"op_14ba14cce4c62f295a3079664d41146c"},"timestamp":"2026-11-24T07:56:03.834528Z","cursor":"","payload":{"code":"OK","effect_status":"applied","kind":"revoke","state":"succeeded"}}');
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
INSERT INTO "grant_anchors" VALUES('grant_931c075f52679325fa4116ab9a82c269','{"grant":"grant_931c075f52679325fa4116ab9a82c269","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081126,"nanos":136517583},"wall":"2026-11-24T07:56:03.645782Z"},"bound":"2026-11-24T09:56:03.643592Z","budget_end":{"secs":1088326,"nanos":134327125}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088326134327125,'2026-11-24T09:56:03.643592000Z');
INSERT INTO "grant_anchors" VALUES('grant_7fa03d1f48a3645f905922cede9a9656','{"grant":"grant_7fa03d1f48a3645f905922cede9a9656","anchor":{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081126,"nanos":225256416},"wall":"2026-11-24T07:56:03.734522Z"},"bound":"2026-11-24T09:56:03.717501Z","budget_end":{"secs":1088326,"nanos":208234500}}','27F253EF-D6C0-44F1-881A-4A8134AEF903',1088326208234500,'2026-11-24T09:56:03.717501000Z');
CREATE TABLE grant_prepared_facts (
    grant_id    TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
    record_json TEXT NOT NULL
) STRICT;
INSERT INTO "grant_prepared_facts" VALUES('grant_931c075f52679325fa4116ab9a82c269','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:03.65088Z"}');
INSERT INTO "grant_prepared_facts" VALUES('grant_7fa03d1f48a3645f905922cede9a9656','{"provider":null,"executables":[],"overrides":[],"environment":[],"pairs":[],"recorded_at":"2026-11-24T07:56:03.738703Z"}');
CREATE TABLE grant_references (
    binding     TEXT NOT NULL,
    grant_id    TEXT NOT NULL REFERENCES grants(id),
    acquired_at TEXT NOT NULL,
    PRIMARY KEY (binding, grant_id)
) STRICT;
INSERT INTO "grant_references" VALUES('binding_9992b274658bfabb332c125ef2359673','grant_7fa03d1f48a3645f905922cede9a9656','2026-11-24T07:56:03.740333000Z');
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
INSERT INTO "grants" VALUES('grant_931c075f52679325fa4116ab9a82c269','env_db186ff6a697f997104df2c4e0f82212',NULL,'released','2026-11-24T07:56:03.645051000Z','2026-11-24T09:56:03.643592000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.643592Z","effective":"2026-11-24T09:56:03.643592Z"}','{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_931c075f52679325fa4116ab9a82c269","environment":"env_db186ff6a697f997104df2c4e0f82212","scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:03.645051Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.643592Z","effective":"2026-11-24T09:56:03.643592Z"},"parent":null,"source":{"kind":"standing_policy","revision":1},"generation":3,"state":"released","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:56:03.645051000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
INSERT INTO "grants" VALUES('grant_5bd322e2796028b63eca7f55439981f8','env_db186ff6a697f997104df2c4e0f82212',NULL,'awaiting_approval','2026-11-24T07:56:03.682815000Z','2026-11-24T09:56:03.682815000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.682815Z","effective":"2026-11-24T09:56:03.682815Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_5bd322e2796028b63eca7f55439981f8","environment":"env_db186ff6a697f997104df2c4e0f82212","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:03.682815Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.682815Z","effective":"2026-11-24T09:56:03.682815Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_c5085a22474fca5496f31326b54c18b0"},"generation":3,"state":"awaiting_approval","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:56:03.682815000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_135d80c6b18fad14288302fa456c0a3f','env_db186ff6a697f997104df2c4e0f82212',NULL,'denied','2026-11-24T07:56:03.694269000Z','2026-11-24T09:56:03.694269000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.694269Z","effective":"2026-11-24T09:56:03.694269Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_135d80c6b18fad14288302fa456c0a3f","environment":"env_db186ff6a697f997104df2c4e0f82212","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:03.694269Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.694269Z","effective":"2026-11-24T09:56:03.694269Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_3e0f0a19b458892f791f2fd74c85a959"},"generation":3,"state":"denied","enforcement":{"report":{"destination_scope":"unknown","new_authentication_expiry":"unknown","workload_isolation":"unknown","existing_connections":"unknown","revocation":"unknown"},"evidence":[]}}','2026-11-24T07:56:03.694269000Z',NULL,'{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent"}');
INSERT INTO "grants" VALUES('grant_7fa03d1f48a3645f905922cede9a9656','env_db186ff6a697f997104df2c4e0f82212',NULL,'active','2026-11-24T07:56:03.717501000Z','2026-11-24T09:56:03.717501000Z','{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.717501Z","effective":"2026-11-24T09:56:03.717501Z"}','{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]}',3,'{"id":"grant_7fa03d1f48a3645f905922cede9a9656","environment":"env_db186ff6a697f997104df2c4e0f82212","scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"starts_at":"2026-11-24T07:56:03.717501Z","deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.717501Z","effective":"2026-11-24T09:56:03.717501Z"},"parent":null,"source":{"kind":"owner_decision","operation_id":"op_2683acdb92ea8b00755b2d1549103c36"},"generation":3,"state":"active","enforcement":{"report":{"destination_scope":"client_routing","new_authentication_expiry":"signer_only","workload_isolation":"shared_os_user","existing_connections":"graceful_dedicated_connections","revocation":"local_applied"},"evidence":[]}}','2026-11-24T07:56:03.717501000Z','{"decision":"dec_2cd2bc0b222ea1e526ec7a58c2bff527","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}','{"profile":"dev","profile_revision":1,"policy_revision":1,"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"mechanism":"fake_agent","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}');
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
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r1','7ebb83bcb6abc58877d4b726e4bea4775a64109c3e739c8344b165de00c482be','op_5a7489aca75b17983caeee13d880ee96','2026-11-24T07:56:03.638308000Z','2026-12-01T07:56:03.652337000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r2','2b440267e23132de00e6b31d271cf9c4b13e19214b62a8a025275d30c4ff8f09','op_c5085a22474fca5496f31326b54c18b0','2026-11-24T07:56:03.681655000Z',NULL);
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r3','4207458fd61e765a02ff8fcba706fca8cdadd42cef68aa84e04e8ad838f7fc16','op_3e0f0a19b458892f791f2fd74c85a959','2026-11-24T07:56:03.693234000Z','2026-12-01T07:56:03.706042000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','ensure','r4','9bf4bf07efcef3a41703560cfa6e8721eb3e8219df2a13ded219fd45c9581c5e','op_2683acdb92ea8b00755b2d1549103c36','2026-11-24T07:56:03.716216000Z','2026-12-01T07:56:03.740333000Z');
INSERT INTO "idempotency" VALUES('{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','revoke','rv1','4593ce9ec4d19fd080f917bdb46bdbfefccc20b0ba038cce3d053b282c24077b','op_14ba14cce4c62f295a3079664d41146c','2026-11-24T07:56:03.828690000Z','2026-12-01T07:56:03.830139000Z');
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
INSERT INTO "meta" VALUES('high_water_mark','2026-11-24T07:56:03.832930000Z');
INSERT INTO "meta" VALUES('runtime_anchor','{"boot_id":"27F253EF-D6C0-44F1-881A-4A8134AEF903","continuous":{"secs":1081126,"nanos":323664166},"wall":"2026-11-24T07:56:03.83293Z"}');
INSERT INTO "meta" VALUES('windows_environment_pipe_token','hmtest015d5e24abc8126f8173335fc9a750e2');
INSERT INTO "meta" VALUES('self_environment_id','env_db186ff6a697f997104df2c4e0f82212');
INSERT INTO "meta" VALUES('authority_generation','8');
INSERT INTO "meta" VALUES('remote_revocation_claim_seq','1');
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
INSERT INTO "operations" VALUES('op_5a7489aca75b17983caeee13d880ee96','ensure','env_db186ff6a697f997104df2c4e0f82212','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r1','7ebb83bcb6abc58877d4b726e4bea4775a64109c3e739c8344b165de00c482be','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_77af27ebf074466dbb8dc1d2a5f417d2","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_db186ff6a697f997104df2c4e0f82212","expires_at":"2026-11-24T09:56:03.643592Z","grant_id":"grant_931c075f52679325fa4116ab9a82c269","offline_until":"2026-11-24T08:56:03.419775Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:03.643592Z"}','{"id":"op_5a7489aca75b17983caeee13d880ee96","kind":"ensure","environment":"env_db186ff6a697f997104df2c4e0f82212","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r1"},"request_hash":"7ebb83bcb6abc58877d4b726e4bea4775a64109c3e739c8344b165de00c482be","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_77af27ebf074466dbb8dc1d2a5f417d2","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_db186ff6a697f997104df2c4e0f82212","expires_at":"2026-11-24T09:56:03.643592Z","grant_id":"grant_931c075f52679325fa4116ab9a82c269","offline_until":"2026-11-24T08:56:03.419775Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:03.643592Z"},"created_at":"2026-11-24T07:56:03.638308Z","updated_at":"2026-11-24T07:56:03.652337Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:03.638308000Z','2026-11-24T07:56:03.652337000Z','2026-11-24T07:56:03.652337000Z');
INSERT INTO "operations" VALUES('op_c5085a22474fca5496f31326b54c18b0','ensure','env_db186ff6a697f997104df2c4e0f82212','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r2','2b440267e23132de00e6b31d271cf9c4b13e19214b62a8a025275d30c4ff8f09','local_resources','awaiting_approval',NULL,'none',NULL,'{"id":"op_c5085a22474fca5496f31326b54c18b0","kind":"ensure","environment":"env_db186ff6a697f997104df2c4e0f82212","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r2"},"request_hash":"2b440267e23132de00e6b31d271cf9c4b13e19214b62a8a025275d30c4ff8f09","effect_class":"local_resources","state":"awaiting_approval","code":null,"effect_status":"none","result":null,"created_at":"2026-11-24T07:56:03.681655Z","updated_at":"2026-11-24T07:56:03.682815Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:03.681655000Z','2026-11-24T07:56:03.682815000Z',NULL);
INSERT INTO "operations" VALUES('op_3e0f0a19b458892f791f2fd74c85a959','ensure','env_db186ff6a697f997104df2c4e0f82212','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r3','4207458fd61e765a02ff8fcba706fca8cdadd42cef68aa84e04e8ad838f7fc16','local_resources','failed','CAPABILITY_UNAVAILABLE','none','{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}}','{"id":"op_3e0f0a19b458892f791f2fd74c85a959","kind":"ensure","environment":"env_db186ff6a697f997104df2c4e0f82212","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r3"},"request_hash":"4207458fd61e765a02ff8fcba706fca8cdadd42cef68aa84e04e8ad838f7fc16","effect_class":"local_resources","state":"failed","code":"CAPABILITY_UNAVAILABLE","effect_status":"none","result":{"error":{"code":"CAPABILITY_UNAVAILABLE","effect_status":"none","message":"the owner denied the requested additional authority","next":{"action":"narrow_request"},"retryable":false}},"created_at":"2026-11-24T07:56:03.693234Z","updated_at":"2026-11-24T07:56:03.706042Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:03.693234000Z','2026-11-24T07:56:03.706042000Z','2026-11-24T07:56:03.706042000Z');
INSERT INTO "operations" VALUES('op_2683acdb92ea8b00755b2d1549103c36','ensure','env_db186ff6a697f997104df2c4e0f82212','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','r4','9bf4bf07efcef3a41703560cfa6e8721eb3e8219df2a13ded219fd45c9581c5e','local_resources','succeeded','ACCESS_READY','applied','{"binding_id":"binding_9992b274658bfabb332c125ef2359673","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_db186ff6a697f997104df2c4e0f82212","expires_at":"2026-11-24T09:56:03.717501Z","grant_id":"grant_7fa03d1f48a3645f905922cede9a9656","offline_until":"2026-11-24T08:56:03.419775Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:03.717501Z"}','{"id":"op_2683acdb92ea8b00755b2d1549103c36","kind":"ensure","environment":"env_db186ff6a697f997104df2c4e0f82212","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"ensure","request_id":"r4"},"request_hash":"9bf4bf07efcef3a41703560cfa6e8721eb3e8219df2a13ded219fd45c9581c5e","effect_class":"local_resources","state":"succeeded","code":"ACCESS_READY","effect_status":"applied","result":{"binding_id":"binding_9992b274658bfabb332c125ef2359673","consumer":{},"credential_availability":"unknown","credential_mechanism":"fake_agent","enforcement":{"destination_scope":"client_routing","existing_connections":"graceful_dedicated_connections","new_authentication_expiry":"signer_only","revocation":"local_applied","workload_isolation":"shared_os_user"},"environment_id":"env_db186ff6a697f997104df2c4e0f82212","expires_at":"2026-11-24T09:56:03.717501Z","grant_id":"grant_7fa03d1f48a3645f905922cede9a9656","offline_until":"2026-11-24T08:56:03.419775Z","profile_revision":1,"refresh_dependency":"none","usable_until":"2026-11-24T09:56:03.717501Z"},"created_at":"2026-11-24T07:56:03.716216Z","updated_at":"2026-11-24T07:56:03.740333Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:03.716216000Z','2026-11-24T07:56:03.740333000Z','2026-11-24T07:56:03.740333000Z');
INSERT INTO "operations" VALUES('op_14ba14cce4c62f295a3079664d41146c','revoke','env_db186ff6a697f997104df2c4e0f82212','{"principal":{"kind":"unix_user","uid":501},"role":"owner"}','rv1','4593ce9ec4d19fd080f917bdb46bdbfefccc20b0ba038cce3d053b282c24077b','local_resources','succeeded','OK','applied','{"committed_at":"2026-11-24T07:56:03.83293Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:03.82869Z"}','{"id":"op_14ba14cce4c62f295a3079664d41146c","kind":"revoke","environment":"env_db186ff6a697f997104df2c4e0f82212","key":{"caller":{"principal":{"kind":"unix_user","uid":501},"role":"owner"},"kind":"revoke","request_id":"rv1"},"request_hash":"4593ce9ec4d19fd080f917bdb46bdbfefccc20b0ba038cce3d053b282c24077b","effect_class":"local_resources","state":"succeeded","code":"OK","effect_status":"applied","result":{"committed_at":"2026-11-24T07:56:03.83293Z","local_applied":true,"remote_pending":[],"requested_at":"2026-11-24T07:56:03.82869Z"},"created_at":"2026-11-24T07:56:03.82869Z","updated_at":"2026-11-24T07:56:03.830139Z","cancellation":null,"recovery":{"last_stage":null,"attempts":0,"recovers":null}}','2026-11-24T07:56:03.828690000Z','2026-11-24T07:56:03.830139000Z','2026-11-24T07:56:03.830139000Z');
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
INSERT INTO "policies" VALUES('pol',5,'{"id":"pol","revision":5,"profile":"dev","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"},{"destination":"h2","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_db186ff6a697f997104df2c4e0f82212"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":"2099-01-01T00:00:00Z","source":{"kind":"owner_decision","decided_at":"2026-11-24T07:56:03.800748Z"},"lock_behavior":"revoke_on_lock"}','2026-11-24T07:56:03.800748000Z');
INSERT INTO "policies" VALUES('pol-ops',1,'{"id":"pol-ops","revision":1,"profile":"ops","workspace":null,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"environments":["env_db186ff6a697f997104df2c4e0f82212"],"max_window":{"secs":7200,"nanos":0},"pause":{"state":"active"},"cutoff_at":null,"source":{"kind":"setup_default"}}','');
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
INSERT INTO "recovery_intents" VALUES('op_5a7489aca75b17983caeee13d880ee96','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r1","required_capabilities":{},"scope":[{"account":"deploy","destination":"h1"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w1"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h1","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.643592Z","effective":"2026-11-24T09:56:03.643592Z"},"policy_revision":1,"generation":3,"grant":"grant_931c075f52679325fa4116ab9a82c269","binding":"binding_77af27ebf074466dbb8dc1d2a5f417d2","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_c5085a22474fca5496f31326b54c18b0','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r2","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w2"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.682815Z","effective":"2026-11-24T09:56:03.682815Z"},"policy_revision":1,"generation":3,"grant":"grant_5bd322e2796028b63eca7f55439981f8","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_3e0f0a19b458892f791f2fd74c85a959','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r3","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w3"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.694269Z","effective":"2026-11-24T09:56:03.694269Z"},"policy_revision":1,"generation":3,"grant":"grant_135d80c6b18fad14288302fa456c0a3f","binding":null,"adapter":{"mechanism":"fake_agent","instance":"cli-fixture"}}}');
INSERT INTO "recovery_intents" VALUES('op_2683acdb92ea8b00755b2d1549103c36','{"request":{"interaction":"non_interactive","op":"ensure","profile":"dev","request_id":"r4","required_capabilities":{},"scope":[{"account":"deploy","destination":"h3"}],"wait":{"mode":"sync","timeout_ms":30000},"work_id":"w4"},"resolved":{"profile":"dev","profile_revision":1,"scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":["ssh-authentication"]},"deadline":{"intent":{"kind":"duration","value":"7200s"},"resolved_at":"2026-11-24T07:56:03.717501Z","effective":"2026-11-24T09:56:03.717501Z"},"policy_revision":1,"generation":3,"grant":"grant_7fa03d1f48a3645f905922cede9a9656","binding":"binding_9992b274658bfabb332c125ef2359673","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"approval":{"decision":"dec_2cd2bc0b222ea1e526ec7a58c2bff527","delta":{"added_scope":{"pairs":[{"destination":"h3","account":"deploy"}],"capabilities":[]},"extra_window":null,"environment_not_covered":false},"generation":3,"policy_revision":1}}}');
INSERT INTO "recovery_intents" VALUES('op_14ba14cce4c62f295a3079664d41146c','{"request":{"grant_id":"grant_931c075f52679325fa4116ab9a82c269","op":"revoke","request_id":"rv1"},"resolved":null}');
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
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:03.638308Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:03.64287Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:03.643592Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:03.644641Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:03.645782Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_476426fb1e284dc2c3f2bdc9ec50061c"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:03.65088Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',7,'{"stage":"probe","recorded_at":"2026-11-24T07:56:03.651516Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:56:03.651792Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_5a7489aca75b17983caeee13d880ee96',9,'{"stage":"commit","recorded_at":"2026-11-24T07:56:03.652337Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_c5085a22474fca5496f31326b54c18b0',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:03.681655Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_c5085a22474fca5496f31326b54c18b0',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:03.682535Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_c5085a22474fca5496f31326b54c18b0',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:03.682815Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_3e0f0a19b458892f791f2fd74c85a959',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:03.693234Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_3e0f0a19b458892f791f2fd74c85a959',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:03.694036Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_3e0f0a19b458892f791f2fd74c85a959',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:03.694269Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',1,'{"stage":"authenticate","recorded_at":"2026-11-24T07:56:03.716216Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',2,'{"stage":"load_authority","recorded_at":"2026-11-24T07:56:03.717187Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',3,'{"stage":"resolve_mechanism","recorded_at":"2026-11-24T07:56:03.717501Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',4,'{"stage":"coalesce","recorded_at":"2026-11-24T07:56:03.7342Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',5,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:03.734522Z","effect":{"kind":"attempted","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"effect_token":"eff_243adc62c2d6f2e281f103850793b4c8"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',6,'{"stage":"reconcile","recorded_at":"2026-11-24T07:56:03.738703Z","effect":{"kind":"confirmed","adapter":{"mechanism":"fake_agent","instance":"cli-fixture"},"credential_ref":"replay_fixture_credential_ref"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',7,'{"stage":"probe","recorded_at":"2026-11-24T07:56:03.739337Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',8,'{"stage":"recheck","recorded_at":"2026-11-24T07:56:03.73965Z","effect":{"kind":"not_attempted"}}');
INSERT INTO "stage_receipts" VALUES('op_2683acdb92ea8b00755b2d1549103c36',9,'{"stage":"commit","recorded_at":"2026-11-24T07:56:03.740333Z","effect":{"kind":"not_attempted"}}');
CREATE TABLE tombstones (
    grant_id     TEXT PRIMARY KEY NOT NULL,
    generation   INTEGER NOT NULL,
    revoked_at   TEXT NOT NULL,
    record_json  TEXT NOT NULL
) STRICT;
INSERT INTO "tombstones" VALUES('grant_931c075f52679325fa4116ab9a82c269',8,'2026-11-24T07:56:03.832930000Z','{"grant":"grant_931c075f52679325fa4116ab9a82c269","cascade":[],"generation":8,"revoked_at":"2026-11-24T07:56:03.83293Z","remote_pending":[],"cause":"revoke"}');
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
INSERT INTO "sqlite_sequence" VALUES('events',37);
COMMIT;
