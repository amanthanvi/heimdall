fix first: W5-I01

Review of `8710717a..40a8d1d4256569fa512052ace87276a1b8f800fe` (detached `HEAD` `40a8d1d4256569fa512052ace87276a1b8f800fe`, branch `m03/wave5` round 14). Review only. No commit, push, or PR. Temporary probe and revert edits were removed; `git diff --stat` is empty and `git status --short` shows only this untracked file.

## Verdict

`recover_unit`'s deleting-marker branch unlinks the owner's recorded database family before it has a proven recovery copy. A same-user program that plants `heimdall-purge-deleting` makes the next `heimdall uninstall` destroy the only complete database, or replace it with whatever regular file sits at the copy's name. ADR-0008 §17.33 item 10 makes that must-fix: it is destructive deletion of the owner's data.

Ordinary crash steps the code itself leaves still keep a complete database. Those regressions passed on the unmodified tree.

## What I ran

Checkout: `git checkout --detach 40a8d1d4256569fa512052ace87276a1b8f800fe`, then `git rev-parse HEAD` printed that commit. Builds used this checkout's `./target`. Toolchain is the pinned 1.99.1. Host is macOS. No `CARGO_TARGET_DIR`, `--target-dir`, or `cargo clean`.

| Command | Exit | Result |
| --- | --- | --- |
| `cargo test -p heimdall --bin heimdall -- purge_sweep:: uninstall_cmd::tests::final_review_ uninstall_cmd::tests::r13_review_ uninstall_cmd::tests::refused_purge_ -- --test-threads=8` | 0 | 41 passed, 0 failed, 204 filtered out |
| `cargo test -p heimdall --bin heimdall -- probe_w5_planted_deleting_marker_without_copy_keeps_database -- --test-threads=1` | 101 | 0 passed, 1 failed |
| `cargo test -p heimdall --bin heimdall -- probe_w5_planted_deleting_marker_with_garbage_copy_keeps_database -- --test-threads=1` | 101 | 0 passed, 1 failed |
| `cargo test -p heimdall --bin heimdall -- probe_w5_recorded_unit_without_marker_recovers -- --test-threads=1` | 0 | 1 passed, 0 failed |
| `cargo test -p heimdall --bin heimdall -- probe_w5_vacuum_into_leaves_original_family_bytes -- --test-threads=1` | 0 | 1 passed, 0 failed |
| `cargo test -p heimdall-store -- probe_w5_no_write_vacuum_leaves_owner_bytes -- --test-threads=8` | 0 | 1 passed, 0 failed, 22 filtered out |
| Revert 1, then `cargo test -p heimdall --bin heimdall -- final_review_validating_read_writes_no_family_file -- --test-threads=1` | 101 | 0 passed, 1 failed |
| Revert 2, then `cargo test -p heimdall --bin heimdall -- final_review_crash_while_vacuum_writes_recovers -- --test-threads=1` | 101 | 0 passed, 1 failed |
| Revert 3, then `cargo test -p heimdall --bin heimdall -- final_review_original_unlink_failure_or_crash_recovers_complete -- --test-threads=1` | 101 | 0 passed, 1 failed |
| Revert 4, then `cargo test -p heimdall --bin heimdall -- final_review_recovery_copy_holds_every_record_by_itself -- --test-threads=1` | 101 | 0 passed, 1 failed |

The 41 passing tests include the §17.36 and §17.37 regressions named below, plus the purge-sweep quarantine tests (`final_review_restore_does_not_attach_old_wal_to_new_owner_database`, `final_review_crash_at_each_copy_step_keeps_a_complete_database`, `final_review_crash_before_the_copy_is_deleted_keeps_a_complete_database`, `final_review_crash_between_database_and_wal_moves_keeps_every_commit`, `r13_review_checkpoint_probe_never_replays_unvalidated_journal`, `r13_review_restore_race_preserves_replacement_record`, `refused_purge_keeps_the_original_until_uninstall_confirms`, and the E1, E2, and E3 tests).

Probe tests were added under `uninstall_cmd::tests` and `heimdall_store::tests`, run, then removed with `git checkout`. They are not in the tree.

## Question 4: revert table

Each revert was applied on the round-14 tree, the named regression was run, and the file was restored. After the last restore, `git diff --stat` printed nothing.

| Fix | Revert | Regression | Exit |
| --- | --- | --- | --- |
| E3, §17.37 item 3. `Store::open_read_only_no_write` URI `mode=ro&readonly_shm=1` (`crates/store/src/lib.rs`) | Query changed to `mode=ro` | `final_review_validating_read_writes_no_family_file` | 101. Empty `-shm` grew from 0 bytes to 32768 and the byte compare failed. |
| E2, §17.37 item 2. Unix `recover_unit` unlinks `UNIT_COPY_PART_FILES` (`crates/heimdall/src/purge_sweep.rs`) | That unlink loop removed | `final_review_crash_while_vacuum_writes_recovers` | 101. Recovery returned `uninstall_quarantine_present` and left the unit, including `.part` and `.part-journal`, with `state.db` still inside it. |
| E1, §17.37 item 1. `Unit::delete` writes `heimdall-purge-deleting` before the first original unlink | `write_marker` skipped (`if false`) | `final_review_original_unlink_failure_or_crash_recovers_complete` | 101. Injected failure on `state.db-shm` left a unit holding the record and `state.db` only; recovery did not finish (`uninstall_quarantine_present`). |
| §17.36 item 1. Recovery copy is `VACUUM INTO` from the read-only connection (`Store::vacuum_into`) | Body replaced with `std::fs::copy` of the main database file, so the `-wal` is omitted | `final_review_recovery_copy_holds_every_record_by_itself` | 101. Panic: `the recovery copy does not hold every confirmed record by itself`. |

## Findings

### W5-I01

- Class: must fix before merge.
- Where: Unix `Anchors::recover_unit`, the `DELETING` branch, [purge_sweep.rs:1779](crates/heimdall/src/purge_sweep.rs#L1779). The same order is in the Windows `recover_unit` at [purge_sweep.rs:2623](crates/heimdall/src/purge_sweep.rs#L2623) (read, not executed). `heimdall uninstall` calls `recover_quarantine` before any prompt at [uninstall_cmd.rs:2004](crates/heimdall/src/uninstall_cmd.rs#L2004). The comment at [uninstall_cmd.rs:2032](crates/heimdall/src/uninstall_cmd.rs#L2032) says a restore deletes nothing.
- The marker is an empty `O_EXCL` file (`write_marker`, [purge_sweep.rs:1301](crates/heimdall/src/purge_sweep.rs#L1301)). It does not record the copy's inode, size, or a check that the copy opens. `Unit::delete` writes it only after `u.copy` is set ([purge_sweep.rs:1255](crates/heimdall/src/purge_sweep.rs#L1255)), so the process's own crash order is "marker implies a non-empty fsynced copy was renamed into place." Recovery does not require that. On the marker it unlinks every present family name first, and only then looks for a regular file named `heimdall-recovery-copy.db`. The record's device and inode are not checked on this branch. If the copy is missing, the unit's record and directory are removed and recovery returns no leftovers. If the copy is any regular file and `state.db` is absent, `restore_copy` renames that file onto `state.db` in one step and the originals are already gone.

Failure scenario. The family is already in an owner-only `.hm-purge-<32 hex>-database` unit with a parseable `heimdall-purge-unit` (the state after quarantine and before `VACUUM INTO` finishes, or after a crash in that window). A same-user program creates `heimdall-purge-deleting` in that directory. The owner then runs `heimdall uninstall`, which is the documented next step when start-up refuses with `uninstall_quarantine_present`. Recovery deletes `state.db`, `-wal`, and `-shm` and removes the unit. Nothing complete remains: not the original, not a restored database, and not a recovery copy. A second plant, the same marker plus a regular file named `heimdall-recovery-copy.db` whose contents are the 14 bytes `not-a-database`, ends with those 14 bytes at `state.db` and the original family gone.

This is the owner's recorded files, not an entry the attacker placed at a family name. `RESIDUALS` entry `purge_entry_placed_in_quarantine_is_deleted` says owner data at an inspected path is never deleted. That sentence is false for this branch. The finding is the marker branch, not a restatement of that residual. F1, F2, and `purge_restore_copy_log_placed_between_check_and_rename` are unchanged and are not re-reported.

The code's own steps do not write the marker until the copy exists. The baseline crash tests (E1, copy-written, restore, delete-copy, crash between the database move and the `-wal` move) passed and still left a readable database. Item 10 applies anyway: the deletion is of the owner's data, and the trigger is a same-user program.

Probes (temporary tests, removed after the run). Both built a real store with `state_dir()` (one committed issuer), moved `state.db` and whichever of `-wal` and `-shm` existed into `.hm-purge-0123456789abcdef0123456789abcdef-database` mode `0700`, wrote `heimdall-purge-unit` as `name\tdev\tino` from `rustix::fs::stat`, wrote the marker, and called `recover_quarantine`. No `-journal`.

- `probe_w5_planted_deleting_marker_without_copy_keeps_database`. No copy file. Exit 101. Panic text: `planted marker with no copy lost the database: recover_ok=true live=false unit_db=false copy=false unit_dir=false`.
- `probe_w5_planted_deleting_marker_with_garbage_copy_keeps_database`. Copy file was `not-a-database`. Exit 101. Panic text: `garbage copy under a planted marker lost the database: recover_ok=true live=true unit_db=false unit_dir=false live_bytes=Some(14)`.
- Control, same harness, no marker and no copy: `probe_w5_recorded_unit_without_marker_recovers`. Exit 0. Recovery restored a live database that `Inventory::same_as` matched to the pre-purge inventory. The harness is accepted by `open_unit` and the non-marker path.

`recover_ok=true` means `rec.left` was empty, so `uninstall` does not stop at `uninstall_quarantine_present`. With no database left, `uninstall_after_recovery` returns at the `!db.exists()` branch ([uninstall_cmd.rs:2330](crates/heimdall/src/uninstall_cmd.rs#L2330)) without the purge prompt. With the 14-byte file in place, a later `--purge-state` hits `Inventory::read` failure and returns `unreadable` before `confirm_purge`. The records are already gone either way.

## Answers

1. Yes, one path loses committed records and leaves no complete database. The two W5-I01 probes did that (exits 101). A crash or injected unlink on the code's own steps did not: the 41-test baseline passed, including every crash step the suite names. `probe_w5_vacuum_into_leaves_original_family_bytes` (exit 0) crashed at `copy-written` for an absent, empty, and stale `-shm`. The quarantined `state.db` and `-wal` bytes were unchanged. An absent `-shm` was still absent or empty. The `.part` file, opened alone, still showed the WAL-only foreign removal.

2. No path found that writes, replays, or attaches a log to the owner's original family, or that attaches an old WAL to a different database. `probe_w5_no_write_vacuum_leaves_owner_bytes` (exit 0) opened with `open_read_only_no_write`, ran `VACUUM INTO` into a pre-created empty file, and the `state.db`, `-wal`, and `-shm` bytes were unchanged. The copy, opened alone, still had the committed token. A hot rollback journal at that URI open returned an error and left the database and journal bytes unchanged. The purge still refuses a `-journal` before the open (`r13_review_checkpoint_probe_never_replays_unvalidated_journal` passed). `final_review_restore_does_not_attach_old_wal_to_new_owner_database` passed. Revert 1 shows the `readonly_shm=1` flag is what stops the empty `-shm` from being rewritten.

3. A restore of the recovery copy is one `rename_between` of `heimdall-recovery-copy.db` onto `state.db` after a check that the four family names are absent ([purge_sweep.rs:1220](crates/heimdall/src/purge_sweep.rs#L1220)). The check and the rename are two steps. A log placed between them is the already-recorded residual `purge_restore_copy_log_placed_between_check_and_rename`; it was not re-probed. Crash recovery converges for the intermediate states the code leaves: part files are unlinked by exact name, a copy without a marker is restored and then confirmed against the original family, and a marker written by `Unit::delete` is followed by finishing the original unlinks and restoring that copy (E1, E2, and the copy-step crash tests passed). It does not converge safely from a marker with no proven copy. That state is W5-I01. A `-journal` in the unit, or a non-empty unit with no parseable record, returns before the deleting branch and leaves the unit (`all_left`).

4. All four reverted fixes failed their regressions. See the table. Exits were 101, 101, 101, and 101. The tree was restored after each one.

5. Nothing else in the wave met the must-fix bar on the evidence gathered here. `confirm_purge` still requires a typed yes on a terminal, and `--non-interactive` does not replace it (read at `confirm_purge`, not a new probe). F1, F2, and the check-then-rename residual stand as already recorded. Older notes `W5-S01` through `W5-S04` in `tests/evidence/artifacts/review-m03-code/wave5-security.md` are from an earlier head and were not re-probed.

## What I could not check

- Windows `recover_unit` was read and matches the Unix order. It was not executed. Directory fsync of the unit record and of the marker is Unix-only in this code; the Windows record syncs the file and not the directory. Not probed.
- A crash inside `VACUUM INTO`, as opposed to the suite's plant of `.part-journal` after `VACUUM` returns (`copy-written`). The byte probe covers the family after a successful `VACUUM` and before the `.part` rename.
- A `-journal` created after `read_db`'s pre-open check and before `VACUUM INTO`. There is no hook between those lines. The journal-at-open probe covers `open_read_only_no_write` only.
- `cargo test -p heimdall-runtime`, `cargo test -p heimdall --test e2e_cli_m03`, the rest of `uninstall_cmd` beyond the 41-test filter, and `tools/validation/check.sh`.
- Native Windows, and any path that needs a non-loopback listener, the owner's keys, or `~/.ssh`.
