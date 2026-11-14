# M03 wave 5 r10 — worklog G8 (W5-D02, W5-D03; ADR-0008 §17.32 items 2-3)

### G8
Base faf10bba. Design:
- D03: `Operations::write_admitted(Option<FenceAdmission>, f)`; `write` = `write_admitted(None)`. The
  admission moves into the spawn_blocking closure and drops after `store.transaction` returns.
  General class (route admissions: dispatcher, enrollment/issuer routes, decide, passes): admissions record
  their tokio task id; every `write` from a task holding an admission takes a counted extension into its
  closure, so cancelling the route future never drops the count while its write is queued/running.
  Debug-only write pause inside the blocking closure (`debug_pause_next_reservation_write`).
- D02: publish_issuance takes a reservation admission (non-refusing) into its write; the re-reserve
  branch refuses `uninstall_in_progress` with no void/reserve when not admitted (fence held).
Progress:
- Landed + compiles: fence module (task-tracked admissions, `write_extension`, `fence_admit_publication`,
  `debug_pause_next_reservation_write`); operations.rs `write_admitted`, reserve_issuance_with + publish_issuance;
  verification_m03.rs reserve_verification.
- Tests: model `recheck2_publication_must_not_rereserve_under_held_fence`,
  `recheck2_cancelled_reservation_keeps_admission_until_store_write_finishes`,
  `cancelled_verification_reservation_keeps_admission_until_store_write_finishes` exit 0; app
  `cancelled_admitted_work_keeps_admission_until_its_store_write_finishes` exit 0.
- Reverts: R1 (no `!may_reserve` arm) publication test 101 (:2367), restored c0ea06ab = before, rerun 0.
  R2 (admission held on the async frame, no extension) both model cancel tests 101 (:2404, :2433) + app
  test 101 (:779); restored c0ea06ab, rerun 0. R3 (extension only off) app test 101, model 0 (explicit move
  alone covers reservations); restored c0ea06ab, rerun 0.
- Runs (umask 002): app --lib 0 (66); runtime --lib 0 (61); model_operations_m03 0 (42, rerun after rustfmt 0);
  integration_runtime_m03 0 (53); e2e_enroll_m03 0 (94); e2e_managed_m03 0 (16); e2e_cli_m03 0 (64, 3 ign.);
  host clippy app+runtime --all-targets 0, heimdall --test e2e_enroll_m03 0; clippy-windows 0; linux-xcheck 0;
  rustfmt --check 0. DONE.
## Audit A1/A7 (round 10, second pass)
- A1: `fence_admit_pipeline()` (extension inside admitted work, else Work admit) held for all of
  `managed::driver::run_stages` (driver.rs: unowned file, run_stages only); debug-only sign pause
  `debug_pause_next_sign`; `publish_issuance` refused `uninstall_in_progress` (nothing written) when no
  publication admission (fence held by another connection). D02's `!may_reserve` arm folded into it.
- Tests: model `reva_probe_pre_fence_reservation_publishes_under_held_fence`,
  `reservation_joined_during_acquisition_cannot_publish_after`; e2e `fence::acquisition_waits_for_in_flight_activation`,
  `fence::activation_refused_while_fence_is_being_acquired` — all 0.
- Reverts: RA (no pipeline admission) both e2e 101 (:591 waited, :623 ensure Ok); restored a8de1742, rerun 0.
  RB (publish allowed without admission) 3 model tests 101 (:2469, :2505, :2371 = D02 too); restored 3661e335, rerun 0.
- A7: timegate anchor write left as is (see api section).
- Runs (umask 002), all 0: app --lib (66); model_operations_m03 (44); e2e_managed_m03 (16); e2e_enroll_m03 (98);
  e2e_consumer_m03 (7); host clippy app+runtime --all-targets and heimdall --test e2e_enroll_m03; clippy-windows
  (Windows target kept); linux-xcheck -p app -p runtime -p issuer; rustfmt --check. DONE.
