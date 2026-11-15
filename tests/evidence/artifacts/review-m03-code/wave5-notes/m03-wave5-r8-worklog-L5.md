# M03 wave 5 round 8 — worker L5 (ADR-0008 §17.31 items 3, 4; W5-C03, W5-C04)

Base `0cd94961`. No commits. Parallel: P8, G8, K4. Request to G8 posted (steps.rs regions).

## Item 3 (W5-C03) — done
- Probes written first (tests/e2e/enroll_m03.rs, `#[cfg(unix)]`, helper `manually_recovered_removal`):
  `recheck_manual_recovered_withdrawn_removal_clears_residual`, `recheck_manual_recovered_last_removal_drops_issuing_ca`.
  Pre-fix: exit 101 (residual `Some(LateWrite{e5…})` kept; last CA kept) = the re-check's finding.
- Fix: `steps.rs::finish_removal` shared by `removal_confirmed` and the manual-recovery arm for line absent
  with purpose removal/rollback (its own `ManualRecoveryLineAbsent` event and settlement kept).
- Revert (manual arm back to `move_ctx`): both FAILED exit 101; restored shasum c2060f6a… = before; rerun 0.

## Item 4 (W5-C04) — no purpose check (Q-L5-13: not persisted where the store txn can read it)
- W5-C04's three mismatches are covered by round-7 tests (stored `RegistryChanged` = kind `other`, events with
  `host_key_changed` / `lock_holder_unresolved`, every purpose incl. append):
  target change → `transition_refuses_target_change_hold_that_differs_from_the_stored_record`;
  line present/append → `…_manual_recovery_line_present_hold_…`; line absent/append → `…_line_absent_hold_…`.
- Revert (hold arm → true): all 4 payload tests FAILED exit 101; restored 3b5195a2… = before; rerun 0.

## Runs (umask 002)
- heimdall-store 0 (21); integration_store_m03 0 (36); model_managed_domain 0 (21, golden unchanged);
  e2e_enroll_m03 full 0 (83)
- host clippy, full set (store app domain testkit heimdall, all targets): 101 twice, only from others' in-flight
  files (G8 `uninstall_fence_m03.rs:567` missing `uninstall_fence_admission`; P8 `uninstall_cmd.rs:1706` unused
  `NOT_STOPPED`). Narrowed host clippy -D warnings: store+domain+testkit --all-targets 0; heimdall-app --lib 0;
  heimdall --test e2e_enroll_m03 0. clippy-windows.sh 0; linux-xcheck -p store app domain 0; rustfmt --check 0.
- e2e_enroll_m03 full rerun on the current tree 0 (83).
