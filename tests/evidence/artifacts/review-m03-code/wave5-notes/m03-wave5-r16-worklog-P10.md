# P10 worklog, round 16 (W5-J01; ADR-0008 §17.39 per the orchestrator's ruling)
Base 20aa899c. No commits. No devbox. Foreground runs only.

## Plan
- Item 1 (recover_unit marker branch, Unix+Windows): pre-check kept (binding, ops.check, binding; originals' identity), hook `recover-checked`, then restore (no-replace rename; Windows by the held handle), then verify at the live name (binding, ops.check, binding), only then unlink originals/marker/record/dir. Verify failure: nothing unlinked, unit kept, state.db reported as unverified (new `Recovered::unverified`, uninstall_cmd message).
- Item 2 (Unit::delete, both): binding re-read through a fresh descriptor after the unlink hook, before the first original unlink; mismatch -> keep (no restore), marker stays (recovery then keeps all).
- Item 3 (Windows): hold the copy (GENERIC_READ, share READ|DELETE, no WRITE) from the copy check through the last original unlink / through restore+verification; restore through the held handle: new safe wrapper `heimdall_ipc::windows::rename_held_no_replace` (ReOpenFile DELETE + SetFileInformationByHandle(FileRenameInfo, ReplaceIfExists=false)).
- Item 4: RESIDUALS `purge_recovery_copy_overwritten_between_check_and_unlink`, adr "ADR-0008 §17.39" (round 15 wrote "§17.38" before the ADR had it; the tests only require a non-empty adr string).
- Item 5: regressions + revert proofs.

## Progress
- Implemented items 1-4 (purge_sweep.rs Unix+Windows, uninstall_cmd.rs report, ipc windows.rs `rename_held_no_replace`, claims.rs residual). Build exit 0.
- New tests: purge_sweep::tests::w5_j01_restored_copy_failing_verification_keeps_every_original, w5_j01_windows_held_copy_denies_a_second_writer (cfg windows); uninstall_cmd::tests::w5_j01_recovery_copy_overwritten_after_recheck_keeps_originals, w5_j01_copy_overwritten_after_check_keeps_originals. fmt 0; `cargo test --bin heimdall w5_j01` exit 0 (3 passed here).
- Revert proofs (purge_sweep.rs restored from /tmp/p10-rev copy, sha256 700db166...eb1d3 matched each time):
  - R1 Unix item-2 re-check disabled (`&& false`): w5_j01_copy_overwritten_after_check_keeps_originals 101; rerun 0.
  - R2 Unix live verification disabled: w5_j01_restored_copy_failing_verification_keeps_every_original + w5_j01_recovery_copy_overwritten_after_recheck_keeps_originals 101 (both failed); rerun 0.
  - R3 Unix restore-first order reverted (originals unlinked before the restore): both recovery tests 101; rerun 0.
- Runs: fmt --check 0; bin purge_sweep:: 0 (30); bin uninstall_cmd:: 0 (69); runtime integration_runtime 0 (60, 2 ign); store 0 (22); domain 0 (104+21+2); contract 0 (43+90); claims_table.py 0; e2e_cli_m03 0 (69, 3 ign); e2e_cli_m02 uninstall 0 (8).
- clippy host 0; clippy-windows first 101 (originals_kept dead on Windows) -> gated #[cfg(unix)] with comment -> 0; linux-xcheck heimdall/runtime/store 0 (15m55s); fmt --check 0 after; w5_j01 rerun 0. Cargo.lock diff empty. Scratch /tmp/p10-* removed.
- target: debug 153G (shared, not pruned), x86_64-pc-windows-gnu 3.5G, x86_64-unknown-linux-gnu 33G (kept as instructed; flag).
- Questions Q-P10-R16-1/2 filed. DONE file written.
