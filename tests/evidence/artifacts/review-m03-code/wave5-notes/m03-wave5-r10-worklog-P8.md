# P8 worklog, round 10 (W5-D01; ADR-0008 §17.32 item 1)

Goal: the purge's final read under `service.lock` is compared in full with the confirmed
inventory, but for this uninstall's own changes; anything else refuses `uninstall_inventory_changed`.

Decisions
- One type: `RecoverySnapshot` (uninstall_cmd.rs), built by `Inventory::read` in the same read-only
  txn for the confirmation read, the fence re-read and the final locked read.
- Store (additive reads, ext_m03.rs): `TABLE_RECOVERY` classifies every schema table
  (Rows / Part / Discarded+why), `RECOVERY_IGNORED_COLUMNS`, `RecoveryRow`, `Txn::schema_tables`,
  `Txn::recovery_rows(table)` (SELECT * of a Rows table, so new columns join automatically).
- Own changes admitted: only the CAs whose retirement this uninstall ran (Retired or Stopped):
  state along retiring/unloaded/deleted/retired, retired_at, displaced locators may only shrink.
- Fence re-check (`same_as`) also compares the full snapshot (projection resources excepted).

Progress: implemented; 6 new unit tests; 3 semantic reverts all exit 101; suites green (see api §P8).
- Follow-up (§17.32 item 6): `OPERATION_RECOVERY` in uninstall_cmd.rs classifies every
  OperationKind (enrollment.* included; others excluded with reasons); the snapshot filters its open
  operations through it. Test `operation_kinds_are_classified_for_the_snapshot`. Mutations:
  enrollment.remove excluded -> 101; catalog unclassified -> 101; restored, shasum OK (6e84ca2d...).
  Unit 26/26 (umask 002) 0; host clippy 0; clippy-windows -p heimdall running.
- Audit A2-A5 (round 10 follow-up):
  - A2: `decisions` is Part: pending decisions of kinds DECISION_RECOVERY includes (register_issuer),
    whole; `decision_kind_name` exhaustive match + source-scan test.
  - A3: `retire_offered` observes the CA via `issuer.status` before/after each run; OwnRetirement
    recorded only when both readable and different; final check accepts exactly before→after.
  - A4: META_RECOVERY (store) + `recovery_meta`; DB-level insert/modify/delete cases per Rows/Part
    table; decision-kind and meta-key enumeration tests (scan domain/store sources).
  - A5: OperationSnapshot = whole record + sha256 of stage receipts + outstanding token.
  - Reverts A2,A2(enum),A3a,A3b,A4,A5 all 101; K1 (decision kind), K2 (meta key) unclassified 101;
    restored, shasum OK. Full runs in /tmp/p8-runs.log.
- §17.32 item 7: `remote_revocation:` included (META_RECOVERY None); Inventory.remote_revocations
  listed (JSON `pending_remote_revocations`, human) in reports and the purge prompt; retry route
  missing -> escalated (questions "## P8 (round 10 ...)"), fail-closed switch
  REMOTE_REVOCATION_RETRY_ROUTE=false refuses a purge with pending ones before confirmation.
  cleanup_intent: paths (`<run>/b/<tag>/…`, `<state>/managed/<dst>/…`) were NOT removed by any
  uninstall step -> fixed: `sweep_managed` in `purge_state` (links refused). Reverts R1-R4 all 101.
- Q-I-R10-1 built: contract variant + schemas + golden + sample; dispatch arm; app handler; ADR-0006
  §16.6 row; uninstall retry before stop, OwnChanges.retries allowance; switch/refusal removed.
  Tests: model `uninstall_fence_retry_is_one_ordinary_round`, dispatch
  `uninstall_fence_retry_is_holder_only`, unit `uninstall_lists_and_confirms_pending_remote_revocations`,
  `uninstall_purge_admits_exactly_its_own_retry`, window test kept.
