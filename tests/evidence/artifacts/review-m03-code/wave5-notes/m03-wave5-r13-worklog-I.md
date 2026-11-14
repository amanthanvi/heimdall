# M03 wave 5 round 13 — integrator worklog

Base `ccd22853`. Binding ADR-0008 §17.35 items 1-4; re-check5 W5-G01..G04. Narrow round. No commits. Keep the Windows target warm.
- [x] P8 (items 1-4) resumed. Note: uninstall_fence_release_stuck_until_holder_work_ends is absent from claims.rs though ADR-0006 / round-11 notes name it (dropped after round 11; likely the round-12 RESIDUALS rewrite).
- [x] (audit)
- [x] archive + report.
- P8 done: G01 unit dir <state>/.hm-purge-<tag>-database (mkdirat 0700, fd-relative, no-replace;
  restore only when all 4 names free, db first; else whole unit kept + reported; Windows
  create_dir_owner_only wrapper); G02 heimdall_store::Checkpointer (read-write, never creates) in the
  unit dir, census-confirmed, wal_checkpoint(TRUNCATE), WAL empty or CHECKPOINT_REFUSED; delete order
  trees, companions, db, dir; report renamed_back/left_in_quarantine exactly. G03 residual added +
  every_adr_named_residual_is_listed (P8: entry was never present; G8 reported adding it in round 11 —
  lost to concurrent claims.rs edits). G04 apply_retries. Regressions:
  final_review_restore_does_not_attach_old_wal_to_new_owner_database, final_review_companion_failure_preserves_database,
  final_review_checkpoint_puts_every_record_in_the_database_file, delete_refuses_a_non_empty_wal,
  every_adr_named_residual_is_listed, final_review_failed_retry_retains_pending_display_record; 6
  reverts 101 -> 0. To confirm: Checkpointer (store API), ipc::windows::create_dir_owner_only.
- [x] Audit of items 1-2 done (D1-D5, all fixed).
- Checkpointer + create_dir_owner_only ANSWERED (§17.35 item 6); doc comment check pending (after audit, before validation).
- Audit of items 1-2 (fresh, read-only; tree restored): D1 medium FIX-BEFORE-MERGE (probe 101,
  crash simulated): family moves file by file, db first; a crash between the db move and the -wal move
  -> next start (service.rs:522 Store::open) creates an empty state.db and SQLite deletes the leftover
  -wal (commits lost); restore direction likewise. Suggested: start-up refuses + reports when a
  .hm-purge-*-database dir or a leftover family file is present. D2 low (covered by D1): crash ->
  silent fresh install with the unit hidden. D3 low (P03): census after the checkpoint -> do a read,
  census, then checkpoint (cheap). D4 low: misreport when dir removal fails after db deletion. D5 low
  (Windows): created empty -wal/-shm may be moved back and listed. -> asked orchestrator about D1's design.
- D1/D2 ANSWERED (§17.35 item 7: start-up refuses, uninstall_quarantine_present); D3-D5 ANSWERED (item 8: fix). Checkpointer doc comment: 'must never be used to open the live database' added by the integrator. P8 resumed.
- P8 D1-D5 fixed: start-up check after the instance lock, before Store::open (only production
  creator: Service::start_with); uninstall_quarantine_present (contract, golden, ADR-0006 row); unit
  record file heimdall-purge-unit (names + inodes, synced) governs restore membership; uninstall's
  recover_quarantine runs first under the lock, restores without a prompt (deletes nothing), reports
  recovered_from_quarantine. D3 Checkpointer::probe -> census -> truncate + SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE
  (found: close-time checkpoint of an unconfirmed log). D4 report only what exists. D5 Windows keeps
  created-file identities. Regressions integration_runtime start_up_refuses_over_an_interrupted_purge_and_keeps_the_log,
  final_review_crash_between_database_and_wal_moves_keeps_every_commit, final_review_crash_during_restore_keeps_every_commit,
  final_review_wal_swapped_before_checkpoint_is_refused_before_any_write, final_review_partial_report_states_only_what_is_on_disk;
  6 reverts 101 -> 0. Accepted: tests/integration/runtime.rs addition, Checkpointer::probe.
- [x] Final validation: check.sh every step 0 (3088 passed, 0 failed, 192 ignored), linux-xcheck 0, umask 002 all 0 (cli_m03 69p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 238p). Notes archived as m03-wave5-r13-*.md.
