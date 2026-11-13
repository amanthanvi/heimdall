# Worklog R2 (runtime, app, adapters), M03 wave 5 round 2

Items: 15, 18, 19, 21 (+ ack fix), 22, 23 (ADR-0008 §17.25). Owner files per `.m03-wave5-r2-api.md` R1.

## Decisions
- 18: `prepare::outcome` fills `PrepareOutcome.managed` from the `ManagedReport` it computes, so
  `prepare_from` and `reissue_from` both carry it. `ensure_data` copies the six fields only when the
  binding's mechanism is `managed_certificate` and `Facts.managed` is `Some` (restart: `conservative`
  -> `None` -> absent).
- 19: new app trait `operations::ConnectionWording` (not in `app::ports`), wired by the runtime with
  `Operations::set_connection_wording`; the runtime's impl is the managed adapter's
  `connection_policy_report(alias, policy)` (observations -> selection class -> `connection_wording`).
  The pair policy = the strictest over every current standing policy covering the pair in this
  environment (service.rs `pair_masters_enabled`'s merge). Present only for a `managed_certificate`
  preference with >= 1 covering policy and a wired wording source; computed outside the store txn.
- 15: `reason` set iff `peek()` is `Uncertain(Unsynchronized{..})` (no same-boot reference).
- 21: ack recorded in `enrollment_m03::decision_apply` (wrapper) for an approved `EnrollAccount`
  (and `EnrollSystemForm`) whose summary disclosures contain `LockContinuityOnce`; the store keeps the
  first time.
- 22: `policy_view` adds `lock_behavior`, `connection` for the two M03 actions only (policy's own values).

## Progress
- 15 DONE: `operations.rs` `time_warning_reason`; test `tests/model/operations.rs`
  `w5_time_uncertain_warning_reason_only_without_a_time_reference_for_this_boot` pass.
- 18 DONE: `prepare.rs` `result_facts` + `managed: Some(..)`; `operations.rs` `ensure_data`.
  Tests: e2e_enroll_m03 `managed_ensure_result_carries_d8_connection_policy_graceful_and_strict`
  (unix+windows), app lib `operations::tests::ensure_data_carries_managed_facts_only_from_this_process_outcome`.
- 19 DONE: `lock_connection_m03.rs` `ConnectionWording`, `pair_connection_policy`,
  `set_connection_wording`, `add_connection_policies`; `operations.rs` `destinations_view`;
  `narrowing.rs` field; adapters `connection_policy_report`, `alias_selection`; `service.rs`
  `AdapterWording`. Test integration_runtime_m03 `wave5_r2::inspect_destinations_preference_connection_policy_uses_runtime_wording`.
- 21 DONE: `add_capabilities_lock`; ack in `enrollment_m03::decision_apply`. Tests:
  integration_runtime_m03 `wave5_r2::inspect_capabilities_reports_lock_behavior_disclosure_and_acknowledgement`;
  e2e_enroll_m03 `enroll_account_approval_records_lock_disclosure_acknowledgement_once` (unix).
- 22 DONE: `policy_view(p, changed, action)`. Test model_operations
  `w5_m03_policy_results_carry_lock_behavior_and_connection_m01_unchanged`.
- 23 DONE: service.rs (conditional on signal != None; Q-R2-3).
- Revert proofs (all exit 101 reverted, restored shasum == pre-revert):
  ack enrollment_m03.rs a718eb48…; prepare.rs managed fill 386cba42…; ensure_data filter
  operations.rs dea99936…; items 15+22 operations.rs dea99936…; items 19+21 service.rs 5e27c42c… +
  operations.rs dea99936…. (Later edits to operations.rs/prepare.rs: fmt + clone_on_copy only.)
- `existing_access_prepare_contract_unchanged` (model_operations_m03) was failing on C's seam line;
  amended allow-list (R2-R3).
- Checks: clippy host app/adapters/runtime all-targets 0; clippy heimdall --test e2e_enroll_m03 0;
  clippy-windows.sh 0; crate_graph OK; linux-xcheck blocked by IS2's `test_product.rs:162`
  dead code (E2-R3), retry pending.
- Tests: app+adapters+runtime all targets pass except none (after R2-R3 fix: rerun pending);
  e2e_enroll_m03 69 pass; e2e_managed_m03 16; e2e_consumer_m03 7 (M02 golden); cli_m01 24; cli_m02 42;
  tui_m03 5; cli_m03 2 failures (U2 uninstall usage list, IS2 issuer retire), not mine.
- Final (after the destinations_view refactor, fmt, clone_on_copy): proofs redone for ensure_data
  filter and destinations wording (both exit 101; operations.rs restored 48af897b…). All
  app/adapters/runtime targets pass (exit 0); e2e_enroll_m03 69, e2e_managed_m03 16, e2e_consumer_m03 7,
  e2e_tui_m03 5 (exit 0); clippy host 0, e2e clippy 0, clippy-windows.sh 0; linux-xcheck still exit
  101 on IS2's `crates/issuer/src/store/test_product.rs:162` (not mine). /tmp scratch removed.
  Shared `./target` is 51G (all workers; not pruned by me).
- DONE; final report sent.
