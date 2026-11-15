# P8 worklog, round 11 (ADR-0008 §17.33 items 3-5)
Goal: exact retry allowance (E01), anchored sweep (E04), mux paths (E06); converge on every purge delete.
Decisions:
- Reply payload: each RemoteRetry carries `record: Option<PendingRemoteRevocation>` (post-retry, as
  stored); final check: stored meta value == serde_json::to_string(record) byte for byte (the
  store's codec::doc), absent when None; Failed/no record => no allowance.
- Unix sweep: anchored rustix walk (openat O_NOFOLLOW|O_DIRECTORY, fstat owner/mode, unlinkat),
  validation pass then delete pass; db files + backups through the state root handle too.
- Windows: roots opened FILE_FLAG_OPEN_REPARSE_POINT|BACKUP_SEMANTICS without FILE_SHARE_DELETE
  (root cannot be renamed/replaced while held); reparse attr refused per entry; residual named.
- Claims table (crates/domain/src/claims.rs CLAIMS) has no residual format: escalated.
Progress:
- Item 3: app `RemoteRetry.record` (stored record re-read after each round); CLI exact byte check.
- Items 4-5: `crates/heimdall/src/purge_sweep.rs` (validation pass + delete pass; Unix anchored
  rustix walk; Windows pinned no-share-delete handles + reparse refusal; WINDOWS_RESIDUAL named);
  db files, backups, managed, b, mux all through it. Tests: recheck3_* (3), state-root converge,
  shared-root refusal, coverage test + mux path.
- Reverts: E01, E04 (path-based, 3 tests), E06 (2 tests) all 101; restored, shasum OK.
- Runs (umask 002): unit 42, e2e_cli_m03 66/3 ignored, m02 uninstall 8, store 21, contract 43+90,
  model retry 1, schema regen (2 doc lines) + check 0; host clippy --no-deps heimdall+store 0;
  windows clippy --no-deps heimdall+store 0; xcheck heimdall+store 0. Workspace clippy/windows and
  heimdall-app xcheck blocked by G8/K4 in-flight lints (operations.rs:12796, service.rs:2385,
  issuer client.rs:320).
- §17.33 items 7-8 (Q-P8-R11-1 accepted): `RESIDUALS` in crates/domain/src/claims.rs (Residual,
  Probe, ResidualReason) with two entries (windows sweep window; <state> opened by path); Rust test
  `residuals_are_never_claims`; claims_table.py parses/validates residuals (+4 self-tests);
  Windows test `purge_sweep::tests::windows_purge_refuses_a_junction_and_names_its_residual`
  (cfg(windows), blocked: native Windows). Validator reverts: verified/claim-collision/test-exists
  each exit 1; restored, shasum OK.
- Audit B1 (fix): retry_remote_revocation's Unchanged answers the record as its claim txn stores it
  (operations.rs, G8 informed); handler uses the round's own record (no re-read); Err -> no
  allowance (CLI ignores failed retries in the allowance). Tests: model
  retry_allowance_is_the_rounds_own_commit_not_a_reread (add-obligation/recreate/fail via store
  hook); unit retry_allowance_admits_no_recreated_record_and_nothing_on_failure. Reverts 101/101.
- Audit B3/B4 (fix): purge_sweep::Anchors (trusted chain from the topmost user-owned ancestor,
  O_NOFOLLOW each level, roots owner-only, ancestors not group/other-writable; lock via openat;
  verify dev/ino around final read + bundle check; check, between, check+verify, delete with links
  unlinked). Windows: pin every ancestor (no share-delete, reparse refused). Tests: common-parent,
  swapped owner-only state, link-between-passes, linked ancestor. Reverts all 101.
- B2/B5/B6 RESIDUALS + B2 probe test (issuer.rs, appended) + purge_roots report (B6) + detector fix.
- §17.33 item 12 (secure path): open_chain walks from `/` (O_NOFOLLOW; root-owned links followed and
  their target checked); pure `check_chain` (ancestors uid me|root, no g/o write, sticky refused,
  no non-root link; root me + owner-only) + `check_windows_chain` (reparse). Tests: macOS/Linux/
  Windows default layouts, refusals, synthetic trees. Revert (0o022->0o002) 101/101. Windows owner
  check escalated Q-P8-R11-2; Linux /tmp harness note. cfg(test) trusts only temp_dir's own chain.
- §17.33 item 13: owner SID check via a new safe wrapper `heimdall_ipc::windows::file_owner_sid`
  (SE_FILE_OBJECT; ipc windows.rs is a §9 unsafe module, no new unsafe module, no Cargo.lock change);
  pure `windows_owner_passes` (me | S-1-5-18 | S-1-5-32-544) + test. Windows residual note -> U13.
- §17.33 item 14: HEIMDALL_TEST_PURGE_TRUSTED_TOP (testcfg::purge_trusted_top, release refusal, release-
  gate probe); Anchors::open(.., top); cfg(test) temp-dir trust removed; e2e fixtures set it; full
  chain from / proven by `secure_path_full_chain_from_root_without_the_hook` (macOS). Reverts: strict
  ancestor / top owner-only / below-top group-writable 101; release-gate with refusal removed exit 1.
