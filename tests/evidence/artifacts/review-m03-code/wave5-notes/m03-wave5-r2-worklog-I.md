# M03 wave 5 round 2 — integrator worklog (resume from here)

Base `dd08b282` (branch `m03/wave5`; round 1 committed). Binding: ADR-0008 §17.25 items 1–23.
Round-1 notes: `tests/evidence/artifacts/review-m03-code/wave5-notes/`. No commits.

## Plan
1. Worker C (alone, first): every contract / port addition §17.25 authorizes, compiled with
   defaults/None, ADR-0006 change rows, goldens/schemas. -> seams in `.m03-wave5-r2-api.md`.
2. Parallel: E2 (item 3, 4-CLI, 5, 120 s timeout), IS2 (7, 8, 9, 10), U2 (8-uninstall, 9-inline,
   11, 12, 13), R2 (15, 18, 19, 21, 22, 23 runtime/app/adapters), T2 (TUI: 4, 10, 15, 19/20, 21).
3. Then A2 (16 + managed halves of access tests, needs R2 + IS2) and cleanup.
4. check.sh, linux-xcheck --workspace, umask 002 U12 targets, archive `m03-wave5-r2-*.md`, report.

## State
- [x] C done: seams items 4/8/15/18 typed; 19/21/22 untyped keys documented; ADR-0006 §16.5 rows;
  schemas+goldens; C-Q1..Q5 (readings in api R1). Build/contract/e2e_cli_m03/clippy host+win 0.
- [ ] E2, IS2, U2, R2, T2 started (parallel); A2 after.

## Windows finding (orchestrator, native run of dd08b282)
- `access::m03_help_and_discovery_goldens` failed on Windows: usage said `heimdall.exe`. No M01/M02
  help goldens exist (no precedent), so fixed at the root: `#[command(bin_name = "heimdall")]` on
  `Cli` in cli.rs. Test now collects every mismatch (count + first differing line) and rejects
  `heimdall.exe`. macOS: goldens unchanged, test passes.
- [ ] Revert proof (binary copied as `heimdall.exe`, HEIMDALL_E2E_BIN) — first attempt void: the
  build was broken by workers' in-flight edits (exit 101 at compile). Redo after workers finish.

## Worker results
- E2 done: items 3 (app steps.rs inserts pause points, debug-only; service.rs pass-through),
  4 (hold_view; enroll status uses runtime hold), 5 (slot_free_command moved to domain::managed,
  re-exported), 1-residual notice, prompt ask_within + timeout tests. Revert proofs 9x 101->0.
  New unix tests: e2e_cli_m03 enroll::enroll_step_pauses_at_the_runtime_inserted_pause_point,
  enroll::enroll_status_shows_slot_free_late_write_and_held_next_step (changed).
  Flag: linux-xcheck 101 on IS2's store/test_product.rs:162 dead code (E2-R3).
- T2 done: items 4,10,15,19/20,21,17; switch module deleted; read-only CLI-decided kinds (incl.
  remove_enrollment; Q-T2-1 Deny, Q-T2-2 confirm). 52 unit + e2e_tui_m03 5 + e2e_tui_m02 17 pass.
  Unit stand-in: managed_readiness_detail_exact_deadline_strings. Unix pty tests (Windows list):
  e2e_tui_m03 pty::{enrollment_states_rendered,time_confirmation_chore_shown_after_reboot,
  tui_search_never_contacts_issuer_or_remote,tui_restores_terminal_after_enroll_decision}.
- Orchestrator rulings Q-T2-1 (allow Deny on read-only views, typed confirm; Approve CLI-only) and
  Q-T2-2 (remove_enrollment read-only, confirmed) recorded ANSWERED in the r2 questions file
  (-> ADR-0008 §17.26, orchestrator writes it). T2 resumed to implement Deny.
- T2 Deny follow-up done: Deny-only on read-only kinds (typed yes), Approve never; unit + e2e
  (tui_restores_terminal_after_enroll_decision now denies the enroll decision). Revert 101->0.
  52 unit, e2e_tui_m03 5 pass under umask 002; clippy host+win 0 (bin+tests, --no-deps).
- U2 done: items 8 (digest+content), 9 (inline retire_to_retired on a terminal), 11 (both switches
  removed; UninstallArgs: --keep-remote no longer requires --purge-state; --bundle requires both),
  12 (TimeGate::assess_read_only_in Unsynchronized + live CA), 13 (3 findings). 10 e2e pass.
  Unix-only: uninstall_doctor::{doctor_reports_client_trace_family_unrecorded, doctor_reports_managed_dir_unsafe}.
  Q-U2-1 (trace finding only with a CA), Q-U2-2 (bundle lists CAs). TODO integrator:
  * `m03_cli_commands_answer_without_a_runtime...` line `uninstall --keep-remote-enrollments` now exit 0 -> fix table.
  * stale comment in uninstall_refuses_purge_with_live_enrollments (BUNDLE_WRITE_RECORD_REQUIRED).
  * m03-plan §5 item 24 uninstall synopsis.
  * CHECK: heimdall-localenv integration_doctor 4 failures (a21_* x3, home_resolution_matches_ssh_g)
    reported independent of U2's doctor.rs — round-1 check.sh had them passing; find cause.
  -> integration_doctor re-run by integrator: 24 passed, 0 failed (likely the hm-fixture-hook
     binary not built in U2's run, as round-1 U noted). Recheck in the final check.sh.
- R2 done: items 15, 18 (adapter fill + Facts + ensure_data), 19 (ConnectionWording port-free setter
  wired in service.rs), 21 (capabilities lock; ack also on EnrollAccount/EnrollSystemForm), 22, 23.
  Tests: model_operations w5_* x2; integration_runtime_m03 wave5_r2::* x2; e2e_enroll_m03
  managed_ensure_result_carries_d8_connection_policy_graceful_and_strict (unix+windows),
  enroll_account_approval_records_lock_disclosure_acknowledgement_once (unix); app lib
  ensure_data_carries_managed_facts_only_from_this_process_outcome. Q-R2-1..3; R2-R3 touched
  tests/model/operations_m03.rs `existing_access_prepare_contract_unchanged` allow-list (review it).
- Integrator: removed `uninstall --keep-remote-enrollments` from the usage-error table in
  cli_m03.rs, fixed the stale BUNDLE_WRITE_RECORD_REQUIRED comments, updated m03-plan §5 item 24
  uninstall synopsis. Waiting on IS2.
- IS2 done: 7b selector `HEIMDALL_TEST_SECRET_STORE=product-file:<abs>` (store/test_product.rs;
  macOS file keychain, Windows DPAPI dir, Linux refused), 7d debug-only exact-locator deletion,
  8 BundleWritten (CLI after fsync; handler records digest + last_bundle_at, never lowered),
  9 retire_to_retired, 10 public disclosure_text, + Ctrl-C at ceremony prompts (ISIG off; rustix
  already a dep). Switches S3_TEST_STORE_DELETION, RECORD_LAST_BUNDLE_AT_ON_REPLY removed.
  macOS-only tests in e2e_cli_m03 issuer:: (5 new). Q-IS2-1..5. Flake once (issuer_store_locked).
  TODO: IS2-R4 integration_issuer_store 2 tests (issuer_store.rs:1315-1324, 1491-1495) + stale
  headers testkit_m03.rs:14-15, issuer_m03.rs:1100; IS2-R1 enroll render -> shared disclosure_text.
- [ ] A2 next (item 16, render 19/22, managed halves, IS2-R1, IS2-R4), then bin_name revert proof,
  full validation.
- A2 done: items 16 (switch removed), 19/22 render, IS2-R1, IS2-R4; found A2-Q1 PRODUCTION DEFECT:
  real issuer refuses every managed activation (`ceiling_exceeded`): driver valid_after =
  floor(now)-60 < starts_at-60 within the grant's first second. Integrator fix:
  `app::managed::driver::validity_start` (ceil(starts_at) vs now, minus 60 s) + unit test.
  Revert proof: unit 101->0; e2e managed halves (access_ensure_strict…, revoke_output…) 101->0.
  A2 resumed to remove REAL_ISSUER_SIGNS_MANAGED_ACTIVATIONS from access.rs.
- Integrator: m03_cmd REFUSED_LINES: `uninstall --keep-remote-enrollments` replaced by
  `... --keep-remote-enrollments --bundle f` (still refused: --bundle needs --purge-state).
- A2 switch removal done (managed halves unconditional; unix helpers managed_strict_half,
  managed_revoke_half). bin_name revert proof (binary copied as heimdall.exe): with 0; reverted
  101 (all 24 goldens listed); restored 0, shasum OK. Summary now counts goldens, not lines.
- [x] Final: check.sh every step 0 (tests 2896 passed / 0 failed / 191 ignored); linux-xcheck
  --workspace 0; umask 002: e2e_cli_m03 42p/2i, e2e_tui_m03 5p/1i, e2e_tui_m02 17p/1i,
  e2e_enroll_m03 69p, e2e_issuer_ceremony 4p/2i, bin 160p. Notes archived as m03-wave5-r2-*.md.
