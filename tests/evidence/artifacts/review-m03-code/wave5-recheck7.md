fix first: W5-J01

Reviewed `40a8d1d4..20aa899c` (HEAD `20aa899c71775d9a74ac4e215c85bff30a05f98c`, detached) against ADR-0008 §17.38 and §17.33 items 6 and 10. Review only. Probes and reverts were undone; `git diff --stat` was empty before this report was added.

## What ran

Checkout `./target` only. No `CARGO_TARGET_DIR`, `--target-dir`, or `cargo clean`.

| Command | Exit | Result |
| --- | --- | --- |
| `cargo test -p heimdall --bin heimdall -- probe_j_ probe_f2_ -- --test-threads=8` | 101 | 4 passed, 2 failed, 251 filtered out |
| same two overwrite probes, rerun for the on-disk listing | 101 | 0 passed, 2 failed |
| `cargo test -p heimdall --bin heimdall -- purge_sweep:: uninstall_cmd::tests::final_review_ uninstall_cmd::tests::r13_review_ uninstall_cmd::tests::refused_purge_ uninstall_cmd::tests::w5_i01 uninstall_cmd::tests::f2_ -- --test-threads=8` | 0 | 47 passed, 0 failed, 210 filtered out |
| `cargo test -p heimdall-issuer --lib -- --test-threads=8` | 0 | 25 passed, 0 failed |
| `cargo test -p heimdall-store -- --test-threads=8` | 0 | lib 22 passed, 0 failed; doc-tests 0 |

The two failures are W5-J01. The other four probes in that batch passed: `probe_j_one_altered_copy_keeps_originals`, `probe_j_nonempty_unrecorded_companion_keeps_originals`, `probe_j_empty_companion_does_not_drop_database`, `probe_f2_validating_reads_create_no_family_file`. The issuer run includes `probe_j_image_unread_signals_only_this_child` and both named image regressions.

The 47 heimdall tests include every `w5_i01_*` regression, `f2_shm_without_wal_reads_by_copy`, `final_review_validating_read_writes_no_family_file`, and the crash recoveries `final_review_original_unlink_failure_or_crash_recovers_complete`, `final_review_crash_at_each_copy_step_keeps_a_complete_database`, `final_review_crash_before_the_copy_is_deleted_keeps_a_complete_database`, `final_review_crash_between_database_and_wal_moves_keeps_every_commit`, and `final_review_crash_while_vacuum_writes_recovers`.

## Revert table

Each revert was applied alone, the named regression was run, then the edit was restored. After all three, `git diff --stat` printed nothing.

| Round-15 fix reverted | Regression | Cargo exit |
| --- | --- | --- |
| Unix `recover_unit`: the two `copy_binding(...) != bound` checks removed; `ops.check` kept | `w5_i01_marker_binding_mismatch_keeps_the_database` | 101. Failed: `a mismatched binding: recovery went ahead on the mark` |
| F2: in-place open whenever `-shm` exists, the `-wal` condition removed | `f2_shm_without_wal_reads_by_copy` | 101. Failed: `state.db-wal was written`, `left: None`, `right: Some((0, []))` (an absent `-wal` became an empty file) |
| `signal_exact`: image gate restored to the pre-round-15 form (a reader must see `Some` now and `Some` at spawn) | `exact_child_signalled_when_its_image_was_never_readable` | 101. Failed: `signal_exact(...)` returned false |

## Answers

### 1. Deleting marker and recovery

A planted or altered file that is visible at the checks does not unlink an original. These passed (exit 0 in the 47): `w5_i01_planted_marker_without_copy_keeps_database`, `w5_i01_planted_marker_with_garbage_copy_keeps_database`, `w5_i01_marker_binding_mismatch_keeps_the_database`, `w5_i01_original_not_the_recorded_inode_keeps_the_unit`, `w5_i01_failed_copy_check_unlinks_nothing`. `probe_j_one_altered_copy_keeps_originals` passed in the probe batch: a crash leaves a real marker and a checked copy, then only the copy is replaced with `not-a-database`, and recovery keeps a complete database.

The hole is after those checks return. See W5-J01. One overwrite of the copy, after the marker is written on the normal path or after recovery's second binding check, unlinks the original family while no complete checked copy remains. That replacement is not a valid database bound by the marker, so it is outside `purge_recovery_copy_and_marker_forged_together`.

The empty-companion exception did not drop owner data on the paths probed. `probe_j_empty_companion_does_not_drop_database` replaced the recorded `state.db` with an empty file and planted a coherent marker; recovery returned an error, the empty database file was still there, and the `-wal` bytes were unchanged. `probe_j_nonempty_unrecorded_companion_keeps_originals` dropped the `-wal` line from the record and planted a coherent marker; recovery left both the database and the non-empty `-wal` byte for byte. The exception requires an unrecorded regular file, excludes the database name (`n != names[0]` on Unix, `k != 0` on Windows), and requires size 0 (`purge_sweep.rs` 1921–1925 and 2891–2895). An empty file has no bytes to lose. Both of those probes also write the marker, so they are two changes; they show the exception refusing, which is the safe direction.

Crash points that leave the checked copy intact still converge to a complete database. The five `final_review_crash_*` / `final_review_original_unlink_*` tests above passed. A crash at the first original unlink (marker already durable, originals intact, copy intact) is the setup `final_review_original_unlink_failure_or_crash_recovers_complete` recovers. There is no crash hook inside `write_marker`. A marker that does not parse makes `read_marker` return `None`, and recovery returns the whole unit (`purge_sweep.rs` 1902–1903). That partial-marker case was not crash-injected.

### 2. F2

No probed validating read wrote, created, or extended a family file. `final_review_validating_read_writes_no_family_file` and `f2_shm_without_wal_reads_by_copy` passed. `probe_f2_validating_reads_create_no_family_file` passed and covered: neither companion; `-wal` present and `-shm` absent; both companions empty; the purge's own final read stopped at `copy-written`, with `state.db`, `-wal`, and `-shm` byte-identical to the bytes from before the purge. `read_family_no_write` (`uninstall_cmd.rs` 2223–2226) uses `open_read_only_no_write` only when both companions exist. The other callers of that open are `copy_reads` on the rollback-journal recovery copy, the purge final read after `hold` has already created any missing companion inside the quarantine unit, and recovery's `ops.open` after the same `hold`. The revert above shows the old `-shm`-only condition still creates an empty `-wal`.

### 3. Issuer child identity

When `identity.image` is `None`, `signal_exact` (`client.rs` 375–392) signals this client's unreaped `Child` only if `try_wait` has not already reaped an exit, `child.id()` is still that pid, and the start token read now is `Some` and equal to the token stored at spawn. The image reader is not consulted. `start_kill` uses this handle. `probe_j_image_unread_signals_only_this_child` passed inside the issuer lib run (exit 0): the matching unreaped child was signalled; a sibling with another pid was not; a second call on the already-reaped handle returned false and the sibling was still running; a mismatched pid returned false; a spawn token of `None` returned false; a token reader that returns `None` returned false. An unreaped `Child` holds the pid, so the pid cannot be reused before `start_kill`. A token read at signal time that differs from the spawn token does not match. The rule refuses, and so does not end the child, when the token is missing or no longer the same, when the handle is already reaped, or when an image that was read at spawn no longer matches (`exact_child_refused_when_a_read_identity_no_longer_matches` passed). Those refusals are fail-closed. They were not observed to signal some other process.

### 5. Anything else in the diff

No other must-fix. The copy check's place inside `Unit::delete`, after the validated trees are deleted, is the accepted §17.38 item 6. The coherent-forgery residual is the one §17.38 item 2 records.

## Finding

### W5-J01

- Class: must-fix (§17.33 item 10, §17.38 item 2). Lasting loss of the owner's database. One altered file. The altered file is not a valid database matching the marker, so this is outside `purge_recovery_copy_and_marker_forged_together`.
- Where: Unix `Unit::delete` writes the marker and then unlinks with no further binding check, [purge_sweep.rs:1287](crates/heimdall/src/purge_sweep.rs:1287) through [purge_sweep.rs:1324](crates/heimdall/src/purge_sweep.rs:1324). Unix `recover_unit` finishes its second binding check at [purge_sweep.rs:1911](crates/heimdall/src/purge_sweep.rs:1911) and unlinks at [purge_sweep.rs:1929](crates/heimdall/src/purge_sweep.rs:1929), then `restore_copy` renames whatever regular file is now at the copy's name ([purge_sweep.rs:1936](crates/heimdall/src/purge_sweep.rs:1936)). Windows has the same sequence at [purge_sweep.rs:2646](crates/heimdall/src/purge_sweep.rs:2646) through [purge_sweep.rs:2664](crates/heimdall/src/purge_sweep.rs:2664) and [purge_sweep.rs:2880](crates/heimdall/src/purge_sweep.rs:2880) through [purge_sweep.rs:2916](crates/heimdall/src/purge_sweep.rs:2916). Windows was not executed.
- Scenario: A confirmed purge (a final removal, inventory clear) reaches original deletion. The copy's identity, `integrity_check`, schema check, and recovery snapshot have passed, and the marker binds that copy. A same-user writer then overwrites `heimdall-recovery-copy.db` in place with the 14 bytes `not-a-database`. The descriptor used to hash the copy is already closed. Nothing re-reads the size or the SHA-256.
  - Normal path: the purge unlinks the original family, the marker, the copy, and the record, and removes the unit. The probe's state directory contained only `service.lock`. No database remained.
  - Recovery path: the purge is crashed at the first original unlink, so the marker is durable and the originals are intact. Recovery passes both binding checks on the real copy, then the same overwrite happens, then recovery unlinks the originals and renames the garbage file to `state.db`. The probe's state directory contained `service.lock` and `state.db`, and the unit was gone. `state.db` did not read as the confirmed inventory.
- Probe: `probe_j_copy_overwritten_after_check_keeps_originals` and `probe_j_recovery_copy_overwritten_after_recheck_keeps_originals`, both in the batch `cargo test -p heimdall --bin heimdall -- probe_j_ probe_f2_`. Cargo exit 101. The diagnostic rerun of those two tests also exited 101 and printed `state=["service.lock"] unit=[]` and `state=["service.lock", "state.db"] unit=[]`. The overwrite ran from the existing unlink hook (after `write_marker`, before `unlinkat`) and from a test-only `step_hook("recover-unlink")` inserted after recovery's second binding check. Both hooks were removed with the rest of the probe edits.

## What I could not check

- Native Windows. The Windows functions cite the same order and were read, not run.
- Linux after `PR_SET_DUMPABLE 0`. Whether `/proc/<pid>/stat` stays readable, so the production start token can be re-read, was not run. The issuer probe uses a verifier that returns a fixed token. A token that reads as `None` refuses the signal (fail-closed, probed).
- A crash mid-`write_marker`, and whether the directory fsync makes the marker durable across power loss. No hook exists inside `write_marker`.
- Filling an empty unrecorded companion after the size check and before the unlink. Not probed. The size-0 and database-name checks were probed as described above.
