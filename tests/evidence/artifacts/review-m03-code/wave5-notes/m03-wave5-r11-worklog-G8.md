# M03 wave 5 r11 — worklog G8 (item 1: holder lease; W5-E03, W5-E05)

### G8
Base 06990cc8. Design:
- `FenceLease` {fence, connection, generation}; every live lease (incl. clones) counts `holder_work`.
  Holder = {connection, generation, releasing}. Acquire → generation+1. Lease valid iff holder matches and not
  releasing. Release: if holder_work==0 lift now, else `releasing` (leases invalid, fence still refuses new
  work) and lift when the last lease drops; the release request waits bounded (RELEASE_WAIT) and reports
  `SERVICE_UNAVAILABLE uninstall_in_progress` if the bound is hit. Connection drop = sync release (deferred lift).
- Task-local carries the lease (`with_fence_lease`); `spawn_with_lease` transfers a counted clone to a spawned
  task explicitly; plain `tokio::spawn` never gains it.
- Checks: admission sites (fence_admit, pipeline, write_extension) exempt only with a valid lease, refuse with a
  stale one; write closure re-checks a carried lease before the transaction; retry handler checks per round.
Progress:
- Landed + compiles; tests 4 new pass. Reverts (each restored by shasum, rerun 0):
  RV1 verify leader plain spawn → e2e recheck3_fence_holder 101 (:756); RV4 spawn_with_lease drops lease →
  holder_spawned 101 (:1245); RV2 release ignores holder work → recheck3_released 101 (:15710); RV3 no
  per-round + commit lease check → recheck3_released 101 (:15717, second round ran); RV5 validity ignores
  generation → earlier_generation 101 (:1276).
- Q-G8-R11-1 posted (release bound behaviour).
- Runs (umask 002), all exit 0: heimdall-app --lib (68); heimdall-runtime --lib (62); model_operations_m03 (44);
  model_operations (190); integration_runtime_m03 (53); e2e_enroll_m03 (99); e2e_managed_m03 (16);
  e2e_cli_m03 (67, 3 ignored). First host clippy 101: my `LeaseLost` after the tests module (fixed, moved
  before `issuance_time`) + K4's in-flight service.rs needless_borrow (retried after K4's fix). Final: host
  clippy app+runtime --all-targets 0, heimdall --test e2e_enroll_m03 0; clippy-windows 0 (target kept);
  linux-xcheck -p app -p runtime 0; rustfmt --check 0; app fence tests rerun after the move 0. DONE.
## §17.33 item 9 (Q-G8-R11-1 accepted)
- Reason + golden + ADR-0006 row; fence `refusal()` (stuck past RELEASE_WAIT); dispatcher data next_command/next_step;
  RESIDUALS entry (FailClosedOnly). `service run --detach` = ServiceCommand::Run{detach} (cli.rs:1046) →
  a new Operations (fence in memory only); the regression starts a new Operations over the same store: no fence.
- claims_table.py first exit 1: its test detector needs a bare `#[tokio::test]`; switched to `tokio::time::pause()` in the body; then 0. Revert (refusal_of always uninstall_in_progress + release bound → in_progress): app test 101 (rerun after the switch too), dispatch
  test 101 (:981); restored 26638d88 = before; reruns 0.
