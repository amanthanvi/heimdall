# M03 wave 5 round 11 — integrator worklog

Base `06990cc8`. Binding ADR-0008 §17.33 (1-6); re-check3 W5-E01..E06. No commits. Keep target/x86_64-pc-windows-gnu warm.
- [x] G8 (item 1), K4 (item 2), P8 (items 3-5) resumed in parallel.
- [x] Independent audit done (B1-B6; B1, B3, B4 fixed; B2, B5, B6 RESIDUALS).
- [x] archive + report.
- P8 done: E01 RemoteRetry.record (complete post-retry record or null) + byte-exact allowance
  (recheck3_retry_allowance_rejects_new_remote_obligation); E04 new crates/heimdall/src/purge_sweep.rs
  (Unix O_NOFOLLOW|O_DIRECTORY, fstat owner/mode, statat NOFOLLOW + dev/ino recheck, unlinkat; 2-pass;
  Windows OPEN_REPARSE_POINT|BACKUP_SEMANTICS no share-delete, refuse reparse points, residual named
  WINDOWS_RESIDUAL) (recheck3_purge_never_follows_runtime_root_replacement, recheck3_purge_does_not_follow_nested_links);
  E06 sweep removes <run>/mux (recheck3_purge_removes_cleanup_mux_path + coverage incl. managed_mux_path);
  converge: db/wal/shm/journal/backups via anchored walk (uninstall_purge_never_follows_state_root_replacement,
  uninstall_purge_refuses_a_shared_runtime_root). Reverts 101 -> 0. Q-P8-R11-1: claims table has no
  residual format (recommend additive RESIDUALS in crates/domain/src/claims.rs read by claims_table.py).
  Item-6 candidate: lock/final read/bundle check open <state> by path (hostile same-user swap).
- P8 rulings ANSWERED (-> §17.33 items 7-8): RESIDUALS list in domain claims.rs + validator + claims_table.py; <state>-by-path recorded as residual with a refusal test. P8 resumed for it.
- G8 done (item 1): FenceLease (connection + generation) replaces FENCE_HOLDER; with_fence_lease,
  uninstall_fence_lease, uninstall_fence_release_waiting; release waits (bounded 20 s, then
  SERVICE_UNAVAILABLE/uninstall_in_progress, fence stays "releasing"); spawn_with_lease for both
  ensure leads, local_lead, verification leader; write_admitted re-checks the lease before the txn;
  retry route per-round lease check. Regressions recheck3_fence_holder_can_finish_own_verification,
  recheck3_released_holder_must_not_continue_retry_under_new_fence (2 reverts),
  holder_spawned_task_keeps_the_lease, earlier_generation_lease_is_refused; 5 reverts 101 -> 0.
  Q-G8-R11-1: release bound hit -> fence stays releasing (fail closed; recommend recording as residual).
- P8 RESIDUALS done: crates/domain/src/claims.rs RESIDUALS (2 entries:
  windows_purge_entry_replaced_between_check_and_delete, uninstall_state_dir_opened_by_path_before_anchored_delete);
  claims_table.py validates (no claim fields, no ID collision, probe test exists) + Rust residuals_are_never_claims,
  the_windows_residual_is_listed; reverts exit 1/101 -> 0.
- Q-G8-R11-1 ANSWERED (-> §17.33 item 9); no `service restart` command exists -> build with
  `heimdall service stop` next step, flagged for confirmation. G8 resumed.
- Next-step wording: read-only commands don't auto-start (15 allow_start=false paths) -> G8 told to name 'heimdall service stop' then 'heimdall service run --detach' exactly, and assert it.
- K4 done (item 2): load keeps the gate permit, sign keeps ClientConfig.request_hold (from
  Operations::issuer_request_hold -> UninstallFence::write_extension) until the reply; on a lost reply:
  crashed, re-verify PID+start token+image, signal, close stdin, await exit <= 5 s, then release; an
  unconfirmed exit keeps the admissions held (acquisition times out with uninstall_in_progress).
  Crash/stop/restart cleanup now signals only a re-verified child. issuer_client_config public.
  Regressions (unix) recheck3_real_issuer_late_sign_cannot_cross_fence, recheck3_real_issuer_cancelled_load_cannot_cross_fence,
  recheck3_real_issuer_unconfirmed_stop_keeps_the_admission_held; reverts 101 -> 0. Changed 3
  integration_issuer_child tests. -> audit: request_hold vs G8's lease (write_extension under a lease).
- G8 item-9 done: uninstall_fence_release_stuck (SERVICE_UNAVAILABLE) past RELEASE_WAIT 20 s; next_command
  `heimdall service stop`, next_step "...then start it again (`heimdall service run --detach`)";
  RESIDUALS entry uninstall_fence_release_stuck_until_holder_work_ends; regressions
  uninstall_fence_m03::tests::fence_release_stuck_past_its_bound_refuses_with_the_restart,
  dispatch::tests::fence_release_stuck_refusal_names_the_restart; revert 101 -> 0. claims_table.py
  test detector does not recognise #[tokio::test(...)] with args (noted).
- [x] (audit started)
- Audit (fresh, read-only; tree restored): B1 must-fix (probe 101): retry allowance re-reads the record
  in a separate txn -> unfenced runtime writes in between are admitted. B2 residual (probe 101):
  request_hold None for the verification leader and holder-lease work. B3 (probe 101): sweep roots'
  parent opened following links; <state> swap for a real dir not refused -> other dir's data deleted;
  contradicts RESIDUALS text. B4 residual: link between passes -> partial deletion (db kept). B5
  residual: holder approvals spawn other connections' work with the holder's lease. B6: sweep uses
  CLI's <run>, not the recorded locators (leftover files only).
- P8 resumed for B1. B3/B4 categorisation -> asked orchestrator.
- B3/B4 ruled FIX (§17.33 item 10); B2/B5/B6 recorded as RESIDUALS (item 11) + report names swept <run>. P8 gets B3/B4/B6-report + RESIDUALS entries after B1.
- P8 done: B1 (reply record = the round's own commit; regressions retry_allowance_is_the_rounds_own_commit_not_a_reread,
  retry_allowance_admits_no_recreated_record_and_nothing_on_failure); B3/B4 purge_sweep::Anchors
  (one no-follow walk from the topmost owned dir; ancestors not writable by others — relaxed from
  owner-only since ~/.local is 0755; lock via the handle; dev/ino checks around the read and bundle
  check; check, recheck, delete) with uninstall_purge_refuses_a_replaced_common_parent,
  uninstall_purge_refuses_a_swapped_owner_only_state, uninstall_purge_link_between_passes_deletes_nothing,
  a_linked_ancestor_refuses_the_anchoring; RESIDUALS now 5 (Windows window;
  uninstall_state_swapped_and_restored_during_final_read; B2 with residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission;
  B5 code citation; B6 + report purge_roots, uninstall_report_names_the_swept_roots); validator accepts
  #[tokio::test(...)] and code citations. Reverts 101 -> 0.
- [x] Final validation: run 1 check.sh overall 1 (test 101: testkit guard caught CARGO_MANIFEST_DIR in domain claims.rs residuals test -> integrator switched to repo_root); run 2 check.sh every step 0 (3059 passed, 0 failed, 192 ignored), linux-xcheck 0; umask 002 all 0 (cli_m03 68p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 213p). Notes archived as m03-wave5-r11-*.md.
- Ancestor rule ANSWERED (-> §17.33 item 12). Stopped the running validation (tree changes). P8 resumed.
- Q-P8-R11-2 ANSWERED (§17.33 item 13: windows-sys security features, lock diff edge-only); Linux test chain ANSWERED (item 14: HEIMDALL_TEST_PURGE_TRUSTED_TOP). P8 resumed with testcfg + release-gate + Cargo.toml grant.
- P8 items 13-14 done: Windows owner check via new safe wrapper file_owner_sid(&File) in
  crates/ipc/src/windows.rs (an overview §9 unsafe-listed module; reuses GetSecurityInfo) — no
  heimdall Cargo.toml change, Cargo.lock diff empty; windows_owner_passes (user/S-1-5-18/S-1-5-32-544)
  + test windows_owner_classification; RESIDUALS Windows entry carried to U13. HEIMDALL_TEST_PURGE_TRUSTED_TOP
  via testcfg::purge_trusted_top (release refuses exit 2; release-gate probe, 27 probes); cfg(test)
  temp trust removed; e2e fixtures set it; full chain from / proven by
  purge_sweep::tests::secure_path_full_chain_from_root_without_the_hook (macOS). Reverts 101/1 -> 0.
  Integrator accepts the ipc/windows.rs touch (listed unsafe module).
- [x] Final validation: run 1 check.sh overall 1 (test 101: testkit guard caught CARGO_MANIFEST_DIR in domain claims.rs residuals test -> integrator switched to repo_root); run 2 check.sh every step 0 (3059 passed, 0 failed, 192 ignored), linux-xcheck 0; umask 002 all 0 (cli_m03 68p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 213p). Notes archived as m03-wave5-r11-*.md.
