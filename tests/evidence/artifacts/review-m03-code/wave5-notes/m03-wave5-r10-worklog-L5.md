# M03 wave 5 round 10 — worker L5 (ADR-0008 §17.32 item 4; W5-D04)

Base `faf10bba`. No commits. Request to G8 posted (fence.rs append-only; verify.rs only).

## Decision
- Single-flight: reuse `Operations.inner.flights` (`SingleFlight<OperationId, DriveResult>`, the `lead`
  pattern) around `verify_operation`; body moved to `verify_once`. Enrollment ops are never driven by
  `lead` (operations.rs `drive`: `EnrollmentApply|Verify|Remove => owner_reconcile_unresolved`), so no
  self-follow deadlock. No store claim: one runtime per DB (instance lock); a durable claim would need its
  own stale-claim recovery after a crash, which the verdict-less resume (§17.31 item 9) already covers.

## Converge (checked)
- Verification routes, all via `verify_operation`: step-result follow-through (steps.rs ~1037),
  `Next::Verify` (~584), reconcile (~1189), verify request (admit.rs ~623), target-change decision
  (enrollment_m03.rs ~670), `reverify_due` resume (passes.rs ~174) / pass admission (idempotent request).
  System absence check (`removal_verifying`) goes through the same function.
- Client steps (removal remove step, the late_write check's inspect, every inspect/append): issued under the
  in-txn `journal.outstanding` CAS (`issue`, steps.rs ~880): a second caller gets STEP_OUTSTANDING, never
  a second effect. No change.
- Removal finalization without a step (`removal_without_step`, AlreadyRemoved/Damaged): two concurrent
  steps both applied it; the second failed STATE_UNAVAILABLE (reproduced). Fixed: in-write state re-check.

## Evidence (exit codes; umask 002)
- Probe before fix: exit 101, `left: 4 right: 2` certificates (= W5-D04). Removal converge before fix:
  exit 101, `Err((StateUnavailable, None))` vs `Ok(done/removed)`.
- R1 flight bypassed: 3 verification tests FAILED exit 101; restored 3a9d2746… = before.
- R2 removal guard removed: removal test FAILED exit 101; restored ed25e67b… = before. Rerun 0.
- Repeated the 4 tests 3 more times: 0 each.

## Runs (umask 002 for tests)
- e2e_enroll_m03 full 0 (94); e2e_cli_m03 full 0 (64, 3 ignored child entries); model_operations_m03 0 (42);
  heimdall-app --lib 0 (66)
- host clippy `-p heimdall-app -p heimdall --all-targets`: 101, only P8's in-flight `uninstall_cmd.rs`
  (:224, :288 type_complexity; :1923 too_many_arguments). clippy-windows.sh (workspace): 101, same three.
- Narrowed: host clippy `-p heimdall-app --all-targets` 0, `-p heimdall --test e2e_enroll_m03` 0; Windows
  (the script's own zig shim, same flags) `-p heimdall-app --all-targets` 0, `-p heimdall --test e2e_enroll_m03` 0.
- linux-xcheck -p heimdall-app 0; rustfmt --check 0. target/x86_64-pc-windows-gnu kept.

## Audit A8 (cancelled leader / pending result write) — done
- Fix 1 (preferred variant): `verify_operation`'s leader runs in a spawned task that owns the flight and a
  counted fence `write_extension()` until the verification and its result write finish; a cancelled caller
  never releases the flight, so a follower only follows (no second reservation or signature).
- Fix 2: `record_verification`'s write is a CAS on the start (`Started { state, outcomes }`: record state,
  operation open, VERIFY_OUTCOME count unchanged); otherwise discarded (nothing written, Ok).
- Debug hooks (enrollment_m03.rs / verify.rs, debug builds only): `debug_pause_next_verification_result_write`
  (hands the write off, then waits, as a blocking-pool write survives cancellation), `debug_verify_operation`,
  `debug_verify_without_flight`.
- Tests (fence.rs, appended): `cancelled_verification_leader_with_a_pending_result_write_is_never_repeated`,
  `verification_result_write_records_only_the_run_it_started_from`.
- R1 (leader inline again): FAILED exit 101 `left: 4 right: 2` (second pair signed); restored 994cdc55… = before.
- R2 (CAS off): FAILED exit 101 (stale write: StateUnavailable instead of discarded); restored 994cdc55…; rerun 0.
- e2e_enroll_m03 0 (98); model_operations_m03 0 (44); heimdall-app --lib 0 (66).
- host clippy (-p heimdall-app -p heimdall --all-targets) 0; clippy-windows.sh 0 (Windows target kept); linux-xcheck -p heimdall-app 0; rustfmt --check 0.
