# M03 wave 5 r8 — worklog G8 (W5-C02, fence at reservations)

### G8
Goal: ADR-0008 §17.31 item 2 / §17.28 item 1. Fence checked under the admission guard held across the
reservation write (grant + verification); supervisor passes + app routes through the same boundary;
StepResult follow-through deferred under fence; regressions (3 recheck probes, deferred verification
runs after lift, deterministic acquire-vs-reservation interleaving).

Design (decided):
- Replace the tokio RwLock admission with a counter state (holder, admitted, acquiring) + Notify in
  `uninstall_fence_m03.rs`. Guard `FenceAdmission` ('static, holds Arc). Two admits:
  `uninstall_fence_admit()` (new work: request/pass/deferral boundary; refused while held by another
  connection OR an acquisition is in progress) and `fence_admit_reservation()` (refused only while held;
  joins while acquiring, so acquire waits for it). Nested admissions never block (no fair-lock deadlock).
  Holder scope (`as_fence_holder`) exempt.
- acquire: sets `acquiring`, waits (<=20 s) for admitted==0, then holds; a dropped acquire clears acquiring.
- Deferral: `enroll_step_result` records the result; if verify_after and `uninstall_fence_admit()` fails,
  the follow-through is skipped. Remembered as the existing state (record `applied_unverified`, apply
  op running, no outstanding step) — no migration. Picked up by `enroll step` (Next::Verify) or
  `enroll reconcile` (AppliedUnverified arm; lapsed approval -> `enroll verify`), the CLI's normal drive.
- Requests posted: L5 (enrollment_request one line; reverify_pass mine; verify.rs defensive), K4 (issuer_request one line).

Progress:
- Landed (compiles): fence core rewrite (uninstall_fence_m03.rs: counter+Notify, `uninstall_fence_admit`,
  `fence_admit_reservation`, `enrollment_fence_admission`, `issuer_fence_admission`, `fenced` (moved from
  dispatch), debug-only `debug_pause_next_reservation`); reserve_issuance_with + reserve_verification
  (verification_m03.rs: reservation fn only, unowned file) hold the admission across the write; decide
  approve admission (operations.rs); managed_reissue_pass admission; dispatcher uses the one boundary;
  supervisor wraps reverify_pass; steps.rs enroll_step_result deferral.
- Tests: app fence unit tests (4) exit 0; model_operations_m03 fence_acquisition_* (2) exit 0.
- e2e tests written in tests/e2e/enroll_m03/fence.rs; waiting on L5 for the `mod fence;` line and the
  enrollment_request admission line; K4 for issuer_request.
- Revert R1 (reservation admission dropped after check = old fence_check): model fence_acquisition_* exit 101
  (both, at the "acquisition must wait" asserts :2276/:2311); restored shasum f0cac3cf… = before; rerun exit 0.
- Q-G8-1 posted (L5, K4 finished without applying requests (a)-(c)); waiting on integrator.
- Runs (umask 002): heimdall-app --lib 0 (65); heimdall-runtime --lib 0 (61); integration_runtime_m03 0 (53);
  model_operations_m03 0 (39); e2e_enroll_m03 full 0 (83; fence.rs not yet compiled in); e2e_cli_m03 full 0
  (64, 3 ignored); host clippy app+runtime --all-targets -D warnings 0; clippy-windows.sh 0;
  linux-xcheck -p heimdall-app -p heimdall-runtime 0; rustfmt --check (G8 files) 0.
- STOPPED waiting on Q-G8-1 (no answer after ~25 min). Owed when (a)-(c) land: compile + run
  e2e_enroll_m03 fence::*; revert runs for the step-result deferral (remove the admit match in
  enroll_step_result) and for (a) (direct admission probe).
