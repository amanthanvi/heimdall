merge

Reviewed `20aa899c..965b509e` (HEAD `965b509eead0aa0f04d4309620b06fa7ff4326ae`, detached) against ADR-0008 §17.39 and §17.33 items 6 and 10. Review only. Probe edits and both reverts were undone. `git diff --stat` was empty before this report was added. No new must-fix.

## What ran

Checkout `./target` only. No `CARGO_TARGET_DIR`, `--target-dir`, or `cargo clean`.

| Command | Exit | Result |
| --- | --- | --- |
| `cargo test -p heimdall --bin heimdall -- purge_sweep:: uninstall_cmd::tests::final_review_ uninstall_cmd::tests::r13_review_ uninstall_cmd::tests::refused_purge_ uninstall_cmd::tests::w5_i01 uninstall_cmd::tests::w5_j01 uninstall_cmd::tests::f2_ -- --test-threads=8` | 0 | 50 passed, 0 failed, 204 filtered out |
| same filter plus `uninstall_cmd::tests::probe_k_`, on HEAD plus the temporary hooks below | 0 | 59 passed, 0 failed, 204 filtered out (50 regressions + 9 probes) |
| `cargo test -p heimdall-store -- --test-threads=8` | 0 | lib 22 passed, 0 failed; doc-tests 0 |
| re-check removed, then `w5_j01_copy_overwritten_after_check_keeps_originals` | 101 | 0 passed, 1 failed |
| live-name verification removed, then `w5_j01_restored_copy_failing_verification_keeps_every_original` | 101 | 0 passed, 1 failed |
| same verification revert, then `w5_j01_recovery_copy_overwritten_after_recheck_keeps_originals` | 101 | 0 passed, 1 failed |
| those three regressions again after `git checkout` of the two sources | 0 | 3 passed, 0 failed |

The 50 include every `w5_i01_*` and `w5_j01_*` regression that runs on Unix, `f2_shm_without_wal_reads_by_copy`, `final_review_validating_read_writes_no_family_file`, and the crash recoveries `final_review_original_unlink_failure_or_crash_recovers_complete`, `final_review_crash_at_each_copy_step_keeps_a_complete_database`, `final_review_crash_before_the_copy_is_deleted_keeps_a_complete_database`, `final_review_crash_between_database_and_wal_moves_keeps_every_commit`, and `final_review_crash_while_vacuum_writes_recovers`. `w5_j01_windows_held_copy_denies_a_second_writer` is `#[cfg(windows)]` and did not run.

The nine probes, each `ok` in the 59, were `probe_k_altered_copy_before_recovery_keeps_originals`, `probe_k_empty_replacement_database_keeps_wal`, `probe_k_nonempty_unrecorded_wal_keeps_both`, `probe_k_copy_removed_before_recheck_keeps_originals`, `probe_k_overwrite_after_recheck_deletes_family`, `probe_k_overwrite_between_restore_and_verify_keeps_originals`, `probe_k_overwrite_after_verify_before_unlink`, `probe_k_crash_after_restore_before_verify_converges`, and `probe_k_unlink_failure_after_verify_converges`. They used three test-only `step_hook` calls (`rechecked`, `restored`, `recover-verified`) that no production test registers. Those edits were removed before the 50-test run above.

## Revert table

Each revert was applied alone on a clean tree, the named regression was run, then `git checkout` restored the file. After both, `git diff --stat` printed nothing, and the three regressions passed (exit 0).

| Round-16 fix reverted | Regression | Cargo exit |
| --- | --- | --- |
| Unix normal path: the re-check immediately before the first original unlink removed (`copy_binding` mismatch no longer returns) | `w5_j01_copy_overwritten_after_check_keeps_originals` | 101. Panicked: `the purge deleted the originals behind an overwritten copy` |
| Unix recovery: the live-name verification removed (`if in_unit && !bound_at(...)` no longer returns) | `w5_j01_restored_copy_failing_verification_keeps_every_original` | 101. `unverified` was empty and `left` was empty; `restored` held `state.db` |
| same verification revert | `w5_j01_recovery_copy_overwritten_after_recheck_keeps_originals` | 101. Panicked: `recovery deleted the originals behind an overwritten copy` |

The restore-first order was not reverted by itself. Removing the live-name verification is enough to make both item-2 regressions fail: the overwritten copy is still renamed to `state.db` first, and without the check the originals are then unlinked.

## Answers

### 1. Recovery on the marker branch

A file that is planted, altered, or overwritten and then left in place through the checks does not make recovery unlink an original unless a verified database stands at `state.db`. The previous hole is closed. One race remains, and §17.39 item 2 plus the residual already put it out of scope.

On the marker branch, Unix `recover_unit` ([purge_sweep.rs:1915](crates/heimdall/src/purge_sweep.rs:1915)) parses the marker, checks the copy (or the file already at the live name) with `bound_at` (binding, `ops.check`, binding again), checks every original still present, then:

- if the copy is still in the unit, renames it to `state.db` with `renameat` `NOREPLACE` ([purge_sweep.rs:1963](crates/heimdall/src/purge_sweep.rs:1963));
- reads the live name again with `bound_at` ([purge_sweep.rs:1982](crates/heimdall/src/purge_sweep.rs:1982));
- only then unlinks originals ([purge_sweep.rs:1989](crates/heimdall/src/purge_sweep.rs:1989)).

A failed live check returns the unit untouched and reports the live path as unverified. Windows does the same through the held handle ([purge_sweep.rs:3022](crates/heimdall/src/purge_sweep.rs:3022) through [purge_sweep.rs:3037](crates/heimdall/src/purge_sweep.rs:3037)), and was not executed.

Probes and regressions, all exit 0:

- `w5_i01_planted_marker_without_copy_keeps_database`, `w5_i01_planted_marker_with_garbage_copy_keeps_database`, `w5_i01_marker_binding_mismatch_keeps_the_database`, `w5_i01_original_not_the_recorded_inode_keeps_the_unit`, `w5_i01_failed_copy_check_unlinks_nothing`.
- `probe_k_altered_copy_before_recovery_keeps_originals`: a real marker and a checked copy, then the copy overwritten in place with `not-a-database` before recovery starts. Recovery returned an error, the original database and `-wal` were unchanged, and `state.db` was absent.
- `probe_k_empty_replacement_database_keeps_wal`: the recorded `state.db` in the unit replaced by a new empty file. Recovery returned an error, the empty file was still there, the `-wal` bytes were unchanged, and nothing was restored.
- `probe_k_nonempty_unrecorded_wal_keeps_both`: the `-wal` line removed from the unit record, the file left non-empty, the marker left coherent. Recovery returned an error and both files were byte for byte unchanged. The empty-companion exception still excludes the database name and still requires size 0.
- `w5_j01_recovery_copy_overwritten_after_recheck_keeps_originals` and `probe_k_overwrite_between_restore_and_verify_keeps_originals`: the copy (or the just-restored live file) overwritten after the checks and before verification. The garbage file is what stands at `state.db`, verification fails, and every original stays in the unit. A second recovery in the named regression also refuses.

`probe_k_overwrite_after_verify_before_unlink` (exit 0) is the remaining case. The live file had already passed `bound_at`. The hook then wrote `not-a-database` over `state.db`, and the unlink loop ran. Recovery returned success, the unit directory was gone, and `Inventory::read` of the live file did not match the confirmed inventory. That is one overwrite of the live database after verification returned and before `unlinkat`. §17.39 item 2 calls a later overwrite of the live `state.db` the same as corrupting any live database (spec P03). The residual's last sentence records the same limit. It is not a new must-fix, and it is not `purge_recovery_copy_and_marker_forged_together`: the bytes are not a valid database.

### 2. The normal path's re-check

It refuses, and unlinks nothing of the family, when the copy no longer matches. The only remaining normal-path window is the instant the residual describes, and that description matches what ran.

Unix `Unit::delete` reads the copy again by name, through a fresh descriptor, immediately before the first existing original is unlinked ([purge_sweep.rs:1308](crates/heimdall/src/purge_sweep.rs:1308)). A mismatch returns `keep`: nothing of the family is unlinked, nothing is restored, and the unit and its marker stay. Windows does the same read by path while the copy is held ([purge_sweep.rs:2747](crates/heimdall/src/purge_sweep.rs:2747)). The Windows half was not executed.

- `w5_j01_copy_overwritten_after_check_keeps_originals` (exit 0): the overwrite runs from the unlink hook, which is after the marker is written and before this re-check. The purge refuses, the unit stays, `state.db` is not created, and a following recovery also refuses.
- `probe_k_copy_removed_before_recheck_keeps_originals` (exit 0): the copy unlinked in that same hook. `copy_binding` fails, the purge refuses, and the originals stay.

`probe_k_overwrite_after_recheck_deletes_family` (exit 0) places the overwrite after that comparison has returned a match and before `unlinkat`. The purge returned success, the unit directory was gone, and no `state.db` remained: the success path also unlinks the copy, the marker, and the record. That is the residual instant. Nothing else on the normal path sits between the marker and that re-check without the re-check seeing it. The re-check is the last read of the copy; the next operation on a match is the unlink.

The residual text matches this. A mismatch keeps the family. The instant after a matching re-check still deletes the family the owner confirmed with a typed `yes`. Recovery is not on that path: a copy overwritten before the restore fails verification and the originals stay (question 1). The entry's last sentence, a later overwrite of the live `state.db`, is the post-verification instant also in question 1. On Windows the hold is taken before the check and dropped only after the original-unlink loop ([purge_sweep.rs:2720](crates/heimdall/src/purge_sweep.rs:2720), [purge_sweep.rs:2766](crates/heimdall/src/purge_sweep.rs:2766)), which is the "through the last original's deletion" claim. Recovery drops its hold after verification and before its own unlinks ([purge_sweep.rs:3039](crates/heimdall/src/purge_sweep.rs:3039)), which is the "through recovery's restore and verification" claim, not through those unlinks.

### 3. Crash and failure convergence

With the marker and the new order, the crash and failure points that were probed still leave a complete database. That includes a crash between the restore and the verification, and a failed unlink of an original after verification.

`probe_k_crash_after_restore_before_verify_converges` (exit 0) panics at the new `restored` hook: `restore_copy` has renamed the copy to `state.db` and fsynced the state directory, and `bound_at` on the live name has not run. After the panic the original database and `-wal` were still in the unit, byte for byte, and `Inventory::read` of the live file matched the confirmed inventory. A second recovery cleared the quarantine and the live inventory still matched.

`probe_k_unlink_failure_after_verify_converges` (exit 0) makes the unit directory mode `0555` after verification returns, so the first `unlinkat` fails. Recovery returned an error, the originals were unchanged, and the live inventory already matched. Restoring the mode and recovering again cleared the quarantine with the same inventory. The marker is removed only after the original loop ([purge_sweep.rs:1989](crates/heimdall/src/purge_sweep.rs:1989)), so a failed unlink leaves the marker, the live file, and the remaining originals for the next recovery. The next call takes the branch where the copy is no longer in the unit, checks the live file with `bound_at`, and finishes the unlinks.

The five `final_review_crash_*` / `final_review_original_unlink_*` tests passed on the clean tree (exit 0). Those cover a failure or a crash at each original unlink on the normal path, including the first unlink after the marker is durable, and the copy steps before any original is unlinked. A normal-path unlink failure calls `fail`, which restores the copy; the following recovery then completes on that database. There is still no hook inside `write_marker`. A marker that does not parse makes `read_marker` return `None`, and recovery returns the whole unit ([purge_sweep.rs:1922](crates/heimdall/src/purge_sweep.rs:1922)).

### 4. Windows, from the code

The hold and `rename_held_no_replace` match §17.39 item 4 as far as the source shows. None of it was executed.

`hold_copy` ([purge_sweep.rs:2249](crates/heimdall/src/purge_sweep.rs:2249)) opens the copy read-only, `FILE_FLAG_OPEN_REPARSE_POINT`, share mode `FILE_SHARE_READ | FILE_SHARE_DELETE` (`SHARE_NO_WRITE`, [purge_sweep.rs:2216](crates/heimdall/src/purge_sweep.rs:2216)), and refuses a reparse point or a directory. A second open that requests write access conflicts with that share mode, which is the sharing violation (`ERROR_SHARING_VIOLATION`, 32) the Windows tests assert. A read does not: the hold shares read, and `copy_binding` / the read-only store open only need read. On the normal path the handle is acquired before the binding check and dropped only after the last original unlink. In recovery it is acquired before the check, the restore renames that handle, `bound_at` reads the live name while the handle is still open, and the handle is dropped before the original unlinks. While the handle is open, another program can rename or delete the file (delete is shared, so the restore's own rename can open it) and cannot open it for writing. A rename or deletion removes the copy rather than changing its bytes. That is the fail-closed half of item 4.

`rename_held_no_replace` ([windows.rs:773](crates/ipc/src/windows.rs:773)) renames the file the handle refers to, not whatever name is now at the old path:

- `ReOpenFile` asks for `DELETE | SYNCHRONIZE` and shares read and delete, which is compatible with the hold (the hold shares delete and has read access). A failure returns `last_os_error` before any handle is owned.
- The new handle is wrapped in `OwnedHandle` and dropped on both the error path and the success path, so it is closed exactly once. The caller's `held` is not closed.
- The `FILE_RENAME_INFO` buffer is zeroed, so `ReplaceIfExists` is false and `RootDirectory` is null. An existing destination makes `SetFileInformationByHandle` fail; `restore_copy` then returns without a restored path, and recovery leaves the unit in place ([purge_sweep.rs:3031](crates/heimdall/src/purge_sweep.rs:3031)).
- `FileNameLength` is the byte length of the UTF-16 path and does not include the terminator. The allocation keeps a trailing zero `u16`. The name is copied at `offset_of(FILE_RENAME_INFO, FileName)`.
- A drive path gets the `\\?\` prefix. A path that already starts with `\\` is not rewritten, so a UNC path is not given `\\?\UNC\`. Item 4 accepts that: the rename fails and the unit is kept.

`restore_copy` checks the held handle's file id against the marker before the rename ([purge_sweep.rs:2626](crates/heimdall/src/purge_sweep.rs:2626)), then calls `rename_held_no_replace`. A file placed at the copy's old name is not the file renamed.

### 5. Reverts

Recorded in the table above. Both fixes fail their named regressions (exit 101) and pass again on the restored tree (exit 0). `git diff --stat` was empty after the second restore.

### 6. Anything else in the diff

Nothing else meets the must-fix bar. The new residual text in [claims.rs:209](crates/domain/src/claims.rs:209) matches the behavior probed above. The refusal string for an unverified live file ([uninstall_cmd.rs:2115](crates/heimdall/src/uninstall_cmd.rs:2115)) only names the file; it does not delete it. One comment on the Unix re-check says "§17.39 item 2" where the ADR numbers that re-check as item 3. That does not change the check.

## Findings

No new finding. The two ways a single same-user change still ends with originals deleted and no complete database at `state.db` are the ones §17.39 already records: the normal-path instant `purge_recovery_copy_overwritten_between_check_and_unlink` (probe `probe_k_overwrite_after_recheck_deletes_family`, exit 0), and a later overwrite of the live `state.db` after recovery's verification has returned (`probe_k_overwrite_after_verify_before_unlink`, exit 0). The coherent-forgery residual is unchanged and was not re-opened.

## What I could not check

- Native Windows. The hold, the sharing violation, and `rename_held_no_replace` were read and not run. `w5_j01_windows_held_copy_denies_a_second_writer` did not execute.
- An overwrite of the live file on the recovery path that finds the copy already restored (the `!in_unit` branch). That branch checks the live file once, then stats the originals, and does not read it again before the unlinks ([purge_sweep.rs:1932](crates/heimdall/src/purge_sweep.rs:1932) and the `if in_unit && !bound_at` guard at [purge_sweep.rs:1982](crates/heimdall/src/purge_sweep.rs:1982)). The executed post-verify probe is the branch that just restored. The crash probe shows the already-restored branch converges when the live file is left alone.
- A crash inside `write_marker`, and whether the directory fsync survives power loss.
- Filling an empty unrecorded companion after the size check and before the unlink. The size-0 and database-name checks were probed only for a file that was already empty or already non-empty at the start of recovery.
