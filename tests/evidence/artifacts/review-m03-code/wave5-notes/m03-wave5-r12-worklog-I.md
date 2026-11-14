# M03 wave 5 round 12 — integrator worklog

Base `2903b0e6`. Binding ADR-0008 §17.34; re-check4 W5-F01..F04. No commits. Keep the Windows target warm.
- [x] P8 (items 1-2), K4 (item 3) resumed in parallel.
- [x] (audit)
- [x] archive + report.
- K4 done (item 3): RESIDUALS issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child (FailClosedOnly); probe e2e_cli_m03 issuer::recheck4_cancelling_stop_must_not_signal_unverified_child (2 s bound, cancel at 2.5 s). Windows clippy pending P8's files.
- P8 done: item 1 quarantine (.hm-purge-<tag>-<name> via renameat / Windows pinned rename; identity
  recheck; absent targets still absent; final read + snapshot + bundle on the quarantined db (Unix:
  path resolved from the held handle via F_GETPATH / /proc/self/fd, then require exactly one new fd of
  this process naming the quarantined inode); unlink only quarantine names; mismatch -> rename back;
  failed restore -> left_in_quarantine reported). Residual uninstall_state_swapped_and_restored_during_final_read
  removed; Windows residual rewritten. Item 2 check_chain(.., PrivateGroup) via
  heimdall_runtime::platform::user_private_group (allowed module). New ipc::windows::file_id.
  Regressions recheck4_transient_state_swap_must_keep_unconfirmed_recovery,
  recheck4_leaf_replacement_must_keep_unconfirmed_owner_data, swap_between_quarantine_and_unlink_spares_new_data,
  quarantine_failed_restore_is_left_and_reported, recheck4_default_unix_home_with_private_group_must_pass,
  shared_group_home_still_refuses; reverts 101 -> 0. Cargo.lock unchanged.
- [x] Independent audit of item 1 done (C0-C4, all fixed).
- Wrappers ANSWERED (§17.34 item 5). Audit's Unix-db-read finding must end in an argument or a fix (post-open identity recheck vs held handle).
- Item-1 audit (fresh, read-only; tree restored): C0 HIGH must-fix (probe 101): post-check counts only
  the db inode; -wal/-shm opened by path are unchecked (swap-and-back hides a committed record; planted
  -wal at the quarantine name applied; decoy main file swapped back after openat). C1 must-fix (probe
  101): delete() failing part-way strands state.db at its quarantine name, unreported. C2 must-fix
  (Windows, reading): remove_tree re-lists by path -> junction swap deletes outside roots; residual
  text false. C3 low: renames replace existing names (use NOREPLACE / no MOVEFILE_REPLACE_EXISTING).
  C4 docs. -> P8 resumed with all five.
- P8 C0-C4 fixed: db + -wal + -shm held at quarantine names (fstat vs inspected; absent created
  O_CREAT|O_EXCL); Quarantine::read_db census before open / after read before drop (each held inode
  exactly +1 — deviation: not process-wide exclusivity, because parallel threads); regular_file_descriptors
  wrapper (runtime/platform.rs); Windows pins all three. C1 trees first, db last, rename-back + report
  (QUARANTINE_PARTIAL). C2 Windows remove_tree pinned + file-ID checks. C3 renameat_with(NOREPLACE)/
  RENAME_EXCL, ipc::windows::move_no_replace. C4 RESIDUALS purge_entry_placed_in_quarantine_is_deleted.
  Regressions final_read_wal_swapped_during_open_keeps_committed_record, final_read_refuses_a_planted_wal,
  quarantine_refuses_a_decoy_database_before_its_read, partial_delete_renames_the_database_back,
  restore_never_replaces_an_entry_at_the_original_name, an_entry_placed_inside_a_quarantined_directory_is_deleted;
  reverts 101 -> 0. New wrappers to confirm: move_no_replace, regular_file_descriptors.
- [x] Final validation: run 1 check.sh every step 0 (3074 passed, 0 failed, 192 ignored), linux-xcheck 0, umask 002 all 0 (cli_m03 69p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 227p); census comment added (comment-only), run 2 check.sh every step 0 (3074/0/192), linux-xcheck 0. Notes archived as m03-wave5-r12-*.md.
- Census + wrappers ANSWERED (§17.34 item 6).
