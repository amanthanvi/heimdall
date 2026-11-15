# M03 wave 5 round 3 — integrator worklog (resume from here)

Base `a4a41d9e`. Binding ADR-0008 §17.27 (1–10) + §17.26. Reviews: review-m03-code/wave5.md,
wave5-security.md. No commits. devbox Linux at baf2c88f: 21/21 binaries pass; Windows pending.

## Plan
Workers U3 (items 1, 2, uninstall item 3), K3 (5, 6, 7, 8, 10, issuer 4 + issuer 3), D3 (3, enroll 4, 9),
in parallel; then integrate, check.sh, linux-xcheck --workspace, `cargo test --release -p
heimdall-issuer --lib` + the release integration test, umask 002 U12 targets, archive r3 notes, report
with W5-R01..R06 / W5-S01..S06 status each.

## State
- [x] U3, K3, D3 started (background, parallel). Waiting.
- D3 done: W5-S02 fixed (enroll::json_enroll_on_a_terminal_shows_disclosure_prose_before_the_prompt,
  enroll::json_decision_approve_of_an_enrollment_shows_its_disclosures_before_the_prompt,
  enroll_cmd::tests::generic_decision_completion_shows_disclosures_and_needs_the_lock_text; 101->0;
  enroll::json_remove_on_a_terminal_... guard only, no revert). W5-R05/S03 enrollment half fixed
  (enroll::enroll_consent_shows_the_runtimes_lock_text_with_saved_limits,
  enroll_cmd::tests::enrollment_approval_refused_without_the_runtimes_lock_text; 101->0).
  W5-R06 fixed (output::tests::destination_list_renders_the_runtimes_items_shape; 101->0).
  Helper m03_cmd::{lock_disclosure_text, fetch_lock_disclosure_text, lock_text_unavailable};
  sanitizer output::sanitize_for_terminal. Unix pty: 4 new enroll:: tests.
  Pending: clippy-windows 101 on K3's issuer_ceremony.rs:494 dead code.
- K3 done: W5-R03 (issuer::issuer_ceremonies_refuse_redirected_stdin_with_a_terminal_attached),
  W5-R04/S04 (e2e_issuer_ceremony ceremony_registration_prompt_times_out_and_sends_nothing,
  ceremony_written_prompt_times_out_clears_and_stores_nothing), W5-S05 (ceremony_ctrl_c_at_written_cancels_at_once,
  ceremony_eof_at_written_cancels_at_once, issuer::issuer_init_ctrl_c_or_eof_at_written_sends_nothing_more,
  ceremony::tests::written_retries_only_a_wrong_answer), W5-S06 (issuer::issuer_init_backup_path_controls_never_reach_the_terminal),
  W5-R05/S03 issuer half (issuer::issuer_init_shows_the_{continuing,revoke_on_lock}_lock_text_with_saved_limits,
  register_decision_needs_the_runtime_lock_text), item 10 (retire.rs per-profile; release lib 17 pass;
  new tests/integration/issuer_release_gate.rs). All 101->0. K3-Q1 (Windows Ctrl-C kills, U13).
  Known flake: product-store tests `issuer_store_locked` 1 of 6 runs (also seen round 2).
- Integrator: [[test]] integration_issuer_release_gate added to crates/issuer/Cargo.toml; debug 3p,
  release 3p; revert (TEST_STORE_DELETION=true) release 101 (2 failed) -> restored 0, shasum OK.
- Orchestrator added: root-cause the `issuer_store_locked` flake (product race vs fixture; reproduce
  before/after, or explicit isolation + >=20 consecutive runs). K3 resumed with it.
- U3 done: W5-R01 (uninstall_doctor::uninstall_purge_refuses_abandoned_foreign_system_form_removal + unit),
  W5-R02 (uninstall_doctor::uninstall_purge_refuses_withdrawn_late_write + unit), W5-S01
  (uninstall_doctor::uninstall_purge_race_with_concurrent_enrollment_keeps_state [unix], app
  uninstall_fence_refuses_new_work_and_is_lifted, ..._acquire_waits..., runtime dispatch fence tests,
  uninstall_cmd::tests::uninstall_revalidates_under_the_fence), item 3 uninstall
  (uninstall_doctor::uninstall_json_shows_the_preview_on_the_terminal [unix]). All 101->0.
  Contract: RecoveryBundle.foreign_removals (BundleForeignRemoval), Request::UninstallFence
  {Acquire,Release} (service-control/1), reasons uninstall_in_progress (SERVICE_UNAVAILABLE),
  uninstall_inventory_changed (CAPABILITY_UNAVAILABLE, exit 4); ADR-0006 §16.6. Q-U3-1..4.
- Waiting: K3 flake investigation.
- Q-U3-2 RULED (-> §17.28 item 1): scope widened (Step, abandon, reconcile, retire/register/unlock,
  approvals refused for non-holders; reads, denials, pre-fence StepResult allowed; holder exempt);
  unresolved dispatched step blocks purge. Marked ANSWERED; U3 resumed to build it.
- U3 fence ruling built: gate in runtime dispatch (`dispatch::fenced`), holder scope
  `app::operations::as_fence_holder`; app keeps reservation + background-pass checks. New reason
  `uninstall_remote_step_unresolved` (CAPABILITY_UNAVAILABLE) + golden + ADR-0006 §16.6 row 4.
  Tests: e2e uninstall_fence_scope_end_to_end, uninstall_purge_refuses_unresolved_remote_step (unix),
  dispatch::tests::uninstall_fence_refuses_remote_and_ca_work_from_other_connections, app
  uninstall_fence_checks_work_no_request_carries, unresolved_remote_steps_lists_dispatched_and_uncertain_steps.
  6 reverts 101->0. U3 saw 3 heimdall processes from hm-i-* tmp dirs (not U3's; check after K3).
- K3 flake ROOT CAUSE: not a keychain lock. Our `put` builds the item ACL with
  SecTrustedApplicationCreateFromPath(NULL) = code at the path on disk; concurrent cargo builds
  replaced target/debug/heimdall (ad-hoc signed, identity = hash) mid-ceremony -> read-back `get`
  errSecAuthFailed (-25293) -> InteractionNotAllowed -> `issuer_store_locked`, orphan item.
  Fix: product `crates/issuer/src/sys.rs` checks running code == path identity before write
  (StoreError::ExecutableChanged -> SERVICE_UNAVAILABLE exit 5, K3-Q2); fixture: private binary copy
  per rig. Regression issuer::issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony:
  before fix 5/5 fail; revert 3/3 101; restored 3/3 pass. 20/20 consecutive issuer:: runs
  (--test-threads=4); swap loop 10/10 pass (5 under umask 002), private-copy reverted 5/5 fail.
  K3-Q3: ad-hoc signing breaks key access across updates -> recommend Developer ID release obligation.
- Process check after K3: no heimdall/fixture/sshd processes left.
- [ ] Final validation.
- Final validation run 1: check.sh overall 1 — fmt 1 (drift in several workers' files; fixed by
  cargo fmt), test 101 (testkit guard: CARGO_MANIFEST_DIR in runtime dispatch.rs tests 756/832 ->
  repo_path), release-gate 1 (product-file `issuer init` probe exit 3: K3's interactive check ran
  before the test-config release refusal; integrator moved `test_config` to the top of
  `issuer_cmd::session::ceremony` -> release-gate 25/25 PASS). linux-xcheck 0; release lib 17p,
  release gate 3p; umask 002 all 0 (cli_m03 58p/3i, tui_m03 5p, tui_m02 17p, enroll 69p,
  ceremony 8p/2i, bin 168p). issuer:: 16p after the reorder.
- [x] check.sh run 2: every step 0 (2938 passed, 0 failed, 192 ignored); linux-xcheck 0; umask 002 e2e_cli_m03 58p/3i, e2e_issuer_ceremony 8p/2i. Notes archived as m03-wave5-r3-*.md.
