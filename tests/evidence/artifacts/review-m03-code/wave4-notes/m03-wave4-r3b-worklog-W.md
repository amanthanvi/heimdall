# M03 wave 4, round 3b — worker W (W4-N01, Windows port) worklog

## Goal / constraints
- Port `e2e_enroll_m03` flows to Windows (in-box ssh.exe, WSL harness sshd, pipe-form binding endpoint);
  Windows pipe-form binding-endpoint signing test; follower/re-issue pipe forms after X-M item 6.
- No Windows execution here: proof is `bash tools/validation/clippy-windows.sh` + reading. Never claim a
  Windows test passed. Unix behaviour/counts unchanged.
- Owner files: tests/e2e/enroll_m03.rs, new Windows test files, testkit {sshd,home,win,registry}.rs
  (additive), run-windows-local.ps1 / remote-lib.sh (additive, recorded).

## Findings (reading)
- **Registry on the WSL file system.** The harness authorized-keys file is a Windows path (`/mnt/c/...`
  from WSL, drvfs). Default drvfs mounts (no `metadata`) show every directory `drwxrwxrwx`, so the
  enrollment scripts' directory check (`hm_check_dir`: `?????w????|????????w?` -> `dir_writable_by_others`)
  would refuse it as a registry. So the default harness sshd now reads a second `AuthorizedKeysFile` in a
  new 0700 directory of the WSL scratch (`<wsl scratch>/registry/authorized_keys`, 0600), exported as
  `HM_FIXTURE_SSHD_REGISTRY` (Windows path, `wslpath -w`) and `HM_FIXTURE_SSHD_REGISTRY_REMOTE` (WSL path).
- **Client config.** `SshStepRunner` runs `step.client` with only the step's pins; on Unix the test client is
  a `/bin/sh` wrapper adding `-F <scratch config>` and the fixture env. Windows has no such wrapper; the port
  adds `-F` + env in the test's `StepContainment` (`ScratchClientJob`, the kill-on-close job a Windows step
  needs anyway) by rebuilding the `Command` (same program, `-F cfg`, the step's args unchanged, env, piped
  stdio). `TestHost::effective_config` adds `-F` on Windows.
- **Existing-access endpoint.** The fixture agent's pipe: catalog `\\.\pipe\…` (NamedPipe), rendered
  `//./pipe/…` in the plan; `TestHost::endpoint_valid` compares the rendered form only on Windows (probing a
  pipe opens an instance = an agent contact).
- **BLOCKER for 15 Windows tests: the Win32 client has no recorded trace row.** `heimdall_enroll::trace`
  (`RECORDED`: portable 10.5p1 and 9.6p1 only; "The Windows clients are not recorded until their native
  runs") makes every verification through `ssh.exe` inconclusive by design. Every Windows test needing a
  conclusive verification calls `World::require_recorded_client()` and **fails** with
  `client_trace_family_unrecorded …` until the row is recorded (no-op on Unix). To record it, the new
  `windows_client_trace_row_observation` prints the `m03 observation: client_trace_row family=win32 …` lines
  (as `integration_enroll_verify`'s `observe_unrecorded_trace`, which is Unix-only). The row belongs to
  `crates/enroll/src/trace.rs` (not mine; recorded from observed output only).
- **Harness lease.** One harness sshd, leased per thread (600 s bound): a test with two sequential worlds
  now drops the first (`drop(w)`, 4 places; Unix: the first world's sshd stops slightly earlier, assertions
  unchanged); `run-windows-local.ps1` runs `e2e_enroll_m03` with `--test-threads=1`.
- **Decision join needs one instant.** `AuthorityDelta.extra_window` is computed from `now`; with the
  real-time `TestClock` two requests never joined. `TestClock::hold/release` (unused on Unix) stops the clock
  for the two requests, as the live test's virtual clock does. `WorldOptions::default_window` (default 1 h,
  unchanged) lets the follower test ask for 3 h (policy 2 h).

## Changes (files)
- `tests/e2e/enroll_m03.rs`: `mod fx` and 45 tests + helpers `cfg(any(unix, windows))`; 21 tests stay
  `cfg(unix)` with a `// Unix only: <reason>` line; Windows forms of write_mode/owner_only_dir (DACL via
  `heimdall_testkit::win::set_owner_only`), `port_path`, `agent_ref`, `agent_locator`, `serve_pipe`
  (TestSession over `heimdall_ipc::windows::Listener`), `managed_layout`/`endpoint_owner`
  (`EndpointLayout::windows("hmt<tag>")`, SID owner), `ScratchClientJob`, `run_step(home, step)`,
  `World.registry_remote` (spec/seed/foreign registry paths), `World::restart_managed`,
  `require_recorded_client`, `WorldOptions::{default_window, observe_trace}`, `TestClock::{hold, release}`;
  `Holder`/`plant_lock` `cfg(unix)`; `#[path = "enroll_m03/windows.rs"] mod windows` (`cfg(windows)`).
- `tests/e2e/enroll_m03/windows.rs` (new, Windows only; part of the existing `[[test]] e2e_enroll_m03`, no
  `[[test]]` change): `windows_binding_endpoint_pipe_lists_and_signs_through_the_agent_protocol`,
  `windows_decision_joined_follower_names_the_pipe_its_materialization_created`,
  `windows_reissue_restores_the_binding_pipe_and_signs_with_the_new_key`,
  `windows_client_trace_row_observation`.
- `crates/testkit/src/sshd.rs` (additive): harness enrollment registry (`harness_registry`,
  `registry_remote_path`, emptied on drop) + unit test `harness_registry_needs_both_paths_on_the_default_server`.
- `tests/native/m02/remote-lib.sh` (additive): `hm2_sshd_config … [REGISTRY]` (second AuthorizedKeysFile),
  `hm2_sshd_start … [MAXAUTHTRIES [REGISTRY]]` (registry dir 0700 created exclusively, file 0600), sanitize
  unsets the two new variables.
- `tests/native/m02/run-windows-local.ps1` (additive): the default sshd gets the registry and reports
  `registry=`/`registryremote=`; `Get-FixtureEnvironment` exports `HM_FIXTURE_SSHD_REGISTRY` and
  `HM_FIXTURE_SSHD_REGISTRY_REMOTE` (both or neither; remote absolute); a `fixture-sshd-registry` fact and
  command line; `--test-threads=1` for `e2e_enroll_m03`; self-tests U03 and X03 (X01 updated for the new
  start line).

## Verification (this Mac, real exit codes)
- Baseline (testkit additive edits only, test file unchanged): `cargo test -p heimdall --test e2e_enroll_m03`
  → 66 passed, exit 0.
- After: same command → 66 passed, 0 failed, exit 0 (count and names unchanged; the Windows module is
  `cfg(windows)`).
- Windows module logic on Unix (temporary `cfg(any(unix, windows))`, reverted): `… e2e_enroll_m03 windows::`
  → 4 passed (socket form); the follower test first failed (`deadline exceeds the maximum window`, then `one
  decision record, joined`) → fixed by `default_window` and `TestClock::hold`; then 4 passed, exit 0.
- Missing fixture fails, never passes (Mac, harness mode simulated): `HM_FIXTURE_SSHD_PORT=1 …
  step_result_with_wrong_token_refused_nothing_recorded` → exit 101 `fixture sshd unavailable:
  HM_FIXTURE_SSHD_HOST is not set`; full harness vars but no registry → exit 101 `an account-form registry the
  server's account can name (… HM_FIXTURE_SSHD_REGISTRY and HM_FIXTURE_SSHD_REGISTRY_REMOTE)`.
- `cargo test -p heimdall-testkit --features fixtures,managed,app --lib sshd::` → 6 passed.
  Revert-proof of the new unit test (remote-path check removed): exit 101 (FAILED); restored: exit 0.
- `pwsh … run-windows-local.ps1 -SelfTest` → 30 passed, exit 0 (first run: X01 failed on the old start line,
  updated). Revert-proof of U03 (absolute check removed): exit 1, `FAIL U03`; restored: exit 0.
- `shellcheck tests/native/m02/remote-lib.sh` → exit 0. `bash tests/native/m02/selftest.sh` → 243 passed,
  0 failed, exit 0.
- `cargo clippy --workspace --all-targets -- -D warnings` → exit 0 (first run exit 101: unused
  `World.trace_dump` on Unix; fixed).
- `bash tools/validation/clippy-windows.sh` → exit 0 (full workspace, x86_64-pc-windows-gnu). Probe: a
  deliberate type error in `enroll_m03/windows.rs` failed the Windows check (exit 101), so the module is
  checked; probe removed.
- `bash tools/validation/linux-xcheck.sh -p heimdall` → exit 0. `… -p heimdall-testkit` → exit 0.
- Final, after every change: `cargo test -p heimdall --test e2e_enroll_m03` → 66 passed, 0 failed, exit 0.
- `rustfmt --edition 2024 --check tests/e2e/enroll_m03.rs tests/e2e/enroll_m03/windows.rs crates/testkit/src/sshd.rs` → exit 0.

## Not verifiable here
- Every Windows test: no Windows host. Native run needed (below). Risks to watch: (1) the Win32 trace row
  (15 tests fail by design until recorded); (2) Win32 `ssh -G` output vs the pins (`check_effective`), as in
  production; (3) WSL clock vs Windows clock for the four `past_not_after` tests (remote not-after + 64 s);
  (4) 9P writes to the WSL registry keep its 0600 mode (existing file truncated, never recreated).

## Per-test Windows table (`e2e_enroll_m03`, 66 tests + 4 Windows-only)

| Test | Windows | Reason / note |
|---|---|---|
| `enroll_preview_apply_verify_setup_apply_ensure_ssh` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `a10_narrow_certificate_refused_on_other_host_account_form` | gated `cfg(unix)` | needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread. |
| `a10_narrow_certificate_refused_on_other_host_system_form` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`); and needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread. |
| `enroll_requires_attended_decision` | runs |  |
| `step_result_with_wrong_token_refused_nothing_recorded` | runs |  |
| `second_step_refused_while_one_outstanding` | runs |  |
| `step_refused_when_route_changed_after_approval` | runs |  |
| `enroll_same_key_replays_different_params_conflict` | runs |  |
| `enroll_second_for_same_pair_and_ca_already_enrolled` | runs |  |
| `enroll_password_only_account_refused_existing_access_kind_unsupported` | runs |  |
| `enroll_noninteractive_provider_interaction_refused_before_write` | runs |  |
| `cli_killed_during_append_step_leaves_outcome_unknown` | runs |  |
| `step_result_timeout_marks_mutation_uncertain_and_read_retryable` | runs |  |
| `enroll_restart_leaves_operation_unresolved_and_reported` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `verification_session_dropped_on_every_exit_path` | runs |  |
| `enroll_system_form_manual_apply_verify_and_manual_removal_with_absence_check` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `enroll_reconcile_applied` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `enroll_reconcile_unreachable` | gated `cfg(unix)` | it stops the server; the harness sshd is shared by the run and is not this test's to stop (`LoopbackSshd::stop` leaves a harness server running). |
| `abandon_from_outcome_unknown_remove_unknown_and_rollback_pending` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `rotation_and_removal_with_every_managed_binding_released_and_issuer_unavailable` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `enrollment_result_next_discloses_slot_free` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `supervisor_reverifies_before_freshness_lapses` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `client_change_triggers_prompt_reverification` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `held_evidence_hold_reverifies_on_owner_request` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `target_change_pins_come_from_proposed_target` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `foreign_removal_from_second_installation_with_different_catalog` | runs |  |
| `foreign_removal_approved_planned_to_removing` | runs |  |
| `foreign_removal_denied_withdrawn_nothing_remote` | runs |  |
| `foreign_removal_refuses_redacted_bundle_and_line_hash_mismatch` | runs |  |
| `foreign_removal_refuses_bundle_host_mismatch` | runs |  |
| `foreign_removal_lost_reply_reconciled_by_marker` | runs |  |
| `foreign_removal_system_form_manual_route_never_reported_removed` | runs |  |
| `foreign_system_form_abandon_keeps_pending_until_line_removed` | runs |  |
| `foreign_system_form_cancel_after_ca_not_held_never_planned_or_withdrawn` | runs |  |
| `manual_removal_cancel_returns_to_origin_state_and_evidence` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `system_form_never_reported_removed_without_absence_check` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `system_form_cancel_from_manual_pending_keeps_entry_until_absence_verified` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `enroll_reconcile_not_applied_within_validity` | runs |  |
| `reconcile_redispatch_requires_attended_session` | runs |  |
| `enroll_reconcile_approval_lapsed` | runs |  |
| `uncertain_append_left_for_withdrawn_keeps_late_write_residual` | runs |  |
| `ca_retirement_refused_until_every_enrollment_final_or_abandoned` | runs |  |
| `reenroll_after_abandoned_uses_new_marker_old_residual_listed` | runs |  |
| `foreign_removal_held_recovery_by_new_decision_or_abandon` | runs |  |
| `journal_never_stores_foreign_registry_bytes` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `verification_authority_apply_initial_needs_its_own_approval_and_stage` | runs |  |
| `verification_authority_target_change_needs_its_own_decision_and_stage` | runs |  |
| `verification_authority_system_absence_own_stage` | runs |  |
| `fence_unproven_never_unlocks_and_counts_attempt` | gated `cfg(unix)` | the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's. |
| `fence_audit_keeps_signals_sent_on_unproven` | gated `cfg(unix)` | the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's. |
| `reconcile_terminates_stale_holder_then_redispatches` | gated `cfg(unix)` | the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's. |
| `reconcile_after_manual_recovery_classifies_without_redispatch` | gated `cfg(unix)` | the fence's holder is a local Unix process (`Holder`: `/bin/sleep`, its process group, its `ps`/`/proc` start identity) recorded in a symlink lock beside the registry; the harness server's host is WSL, not this process's. |
| `enroll_remove_lists_affected_grants_and_degrades_them` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `target_change_pass_replaces_approved_target_atomically` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `target_change_failure_or_inconclusive_keeps_approved_target_and_held` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `held_host_key_change_needs_target_reapproval_with_key_diff` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`). |
| `held_removal_with_freshly_evaluated_target` | runs |  |
| `initial_verification_retry_under_open_apply_via_reconcile` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `initial_verification_failure_after_approval_lapsed_holds` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `e5_rotation_keeps_projection_and_adds_issuing_ca` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `rotation_two_accounts_one_unreachable` | gated `cfg(unix)` | needs a second sshd (`add_destination`); the Windows harness serves one account-form server, leased once per thread; and it stops the second server. |
| `evidence_invalidated_on_host_key_or_client_change` | gated `cfg(unix)` | the system form: the harness sshd cannot honour `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` (`SshdUnavailable`) (`held_host_key_world_record_with` trusts the CA and writes the principals file). |
| `foreign_removal_held_reuse_needs_the_exact_descriptor` | runs |  |
| `journal_never_stores_marker_bearing_foreign_lines` | runs |  |
| `ensure_scope_minimum_refused_before_any_pass` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `inconclusive_reverification_after_client_change_keeps_scope_unknown` | runs | needs the Win32 trace row (fails on `require_recorded_client` until recorded) |
| `windows::windows_binding_endpoint_pipe_lists_and_signs_through_the_agent_protocol` | runs | Windows only; needs the trace row |
| `windows::windows_decision_joined_follower_names_the_pipe_its_materialization_created` | runs | Windows only; needs the trace row |
| `windows::windows_reissue_restores_the_binding_pipe_and_signs_with_the_new_key` | runs | Windows only; needs the trace row |
| `windows::windows_client_trace_row_observation` | runs | Windows only; observation (no verification evidence) |
