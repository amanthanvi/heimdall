<!-- Saved by the orchestrator on 2026-11-08 from the audit unit's report (Claude Opus 5.5, read-only, worktree at 96611c6f). Rulings on §5: ADR-0007 §12.47. -->
# M02 exit audit: declared Windows and WSL coverage at `ce21a76f`

Read-only audit. No tracked file was changed, nothing was built or run, and nothing was
committed.

**Worktree.** `HEAD` is 86ac4ebe. `origin/main` is 4917cea5, which differs only in
`progress.md` (the "M02 is not exited" note). Every source cited below is identical at
both commits.

**Citations.**
* `W:<n>` is line *n* of `tests/evidence/artifacts/m02/exit-ce21a76f/windows/tests.txt`.
* `L:<n>` is line *n* of `tests/evidence/artifacts/m02/exit-ce21a76f/wsl-distro/tests.txt`.
* Source locations are `file:line`.

**How the "excluded" counts were computed.** I loaded `m02-evidence.py`'s own functions
(`applicable`, `platform_only_lookup`, `parse_log`) against the committed
`case-index.json`, `required-inventory.json` and the exit logs. The scratch scripts are in
`/tmp/hm-audit-w6`, outside the repository, and are removed at the end.

## 0. Summary

1. **The miss is systematic, not five isolated gaps.**
   * **314 distinct required tests** do not exist on Windows. **295** of them are excluded
     only by scan-derived `platform_only` entries, with no rationale in `case-index.json`.
     Counted per case section, that is 328 Windows section-test pairs.
   * These tests are dropped before a row is built, so each record's Windows row shows
     `"not_run_on_this_platform": 0`.
   * Example: `tests/evidence/m02-a22-configuration-precedence.json` reports Windows
     `verified`, `passed: 243`, although 214 of A22's 455 indexed Cargo tests do not exist
     on Windows.
2. **Whole files are `#![cfg(unix)]`**, and have been since they were written:
   * `tests/integration/projection.rs:21`, 107 tests;
   * `tests/integration/projection_git.rs:17`, 42 tests;
   * `tests/integration/projection_recovery_rows.rs:46`, 1 test;
   * `tests/model/setup.rs:15`, 51 tests;
   * `tests/e2e/setup_dispatch.rs:11`, 9 tests.

   These gates were added in 3e51f49b, 88ac9850 and 482c9e70 (waves 2, 2c and 3a). Each
   file ran **0 tests** on Windows (W:1723, W:1734, W:1745, W:3059, W:472); on Linux they
   ran 106, 42, 1, 51 and 9.
3. **Whole modules are `#[cfg(unix)]`:**
   * `e2e_run_m02::a11` (`tests/e2e/run_m02.rs:2278`);
   * `e2e_cli_m02::ssh` (`tests/e2e/cli_m02.rs:2895`);
   * 20 of the 24 `integration_doctor` tests.

   Every `LoopbackSshd::start` caller is Unix-only:
   * `doctor.rs:918`;
   * `testkit_fixtures.rs:518` and `:1191`;
   * `cli_m02.rs` `mod ssh`;
   * `run_m02.rs` `mod a11`.

   So **no Windows test connects any client to a server**. ADR-0007 §12.43 item 5 already
   says so.
4. **Six planned tests do not exist anywhere:**
   * `a22_windows_reparse_point_user_config_is_manual_mode`;
   * `rendered_file_loads_on_target_client` (ADR-0007 §4 says it settles the LF `[I]` for
     Win32-OpenSSH);
   * `git_spaced_client_path_is_quoted_and_runs`;
   * `fresh_writer_creates_absent_global_git_config`;
   * `a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode`, which includes the
     Windows junction variant;
   * `a22_quarantine_removed_when_empty_and_kept_with_foreign_entries`.

   I checked every backticked test-like name in m02-plan §1 against the `fn` names in
   `tests/` and `crates/`; these six are the Windows-relevant ones absent.
5. **Product gaps (Windows behaviour missing in product code):**
   * `sys::account_name` is `cfg(unix)` (`crates/localenv/src/sys/mod.rs:112`).
     `doctor.rs:266-273` returns `None` on Windows. ADR-0007 §12.28 item 4 ("U11 closes it
     natively") is open.
   * The Windows 9.5p2 encodings observation from this very run is not in
     `ENCODING_OBSERVATIONS` (`crates/localenv/src/clients.rs:160`, macOS 10.3p1 only).
     The observation was `corpus_bom_loads="true" corpus_crlf_loads="true"` with B
     effective. So on Windows a CRLF or BOM user config is manual mode
     (`unsupported_encoding`). This fails closed, but it is a functional loss.
6. **A testkit defect blocks naive ungating.** `LoopbackSshd::from_harness`
   (`crates/testkit/src/sshd.rs:123-153`) has four problems:
   * it ignores `max_auth_tries` and `log_level_verbose`, while the WSL sshd is fixed at
     `MaxAuthTries 6` (`tests/native/m02/remote-lib.sh:163`);
   * it **overwrites the one shared** `HM_FIXTURE_SSHD_AUTHORIZED_KEYS` on every start,
     which races under cargo's parallel test threads;
   * every test reads one shared sshd log;
   * there is no sshd user (`HM_FIXTURE_SSHD_USER`).
7. **WSL rows are covered**, with one small gap: the WSL ext4 birth time that U4 names is
   not recorded.

| Case | Windows row in the record | What actually ran natively |
|---|---|---|
| A01 | verified, 3 | 3 pure `model_sshconf_eval` tests. No setup transaction, no client |
| A11 | verified, 14 | adapter-level pipe states. No fresh-eligibility or fallback-clearance case |
| A21 | verified, 6 | agent, network and timeout levels. No `cmd /c` canary, no job containment, no authorization gating |
| A22 | verified, 243 | parser, evaluator, corpus, `ReplaceFileW` primitives. No transaction, no Git transaction, no setup driver |
| A27 | verified, 59 | covered for every declared Windows row (3 smaller Unix-only gaps) |
| A35 | verified, 19 | fixture and observation level only. No `ssh.exe`, `scp.exe`, `sftp.exe` or Git to a server |
| R-RT-05 | verified, 4 | no projection crash or restart test |
| ADR-0006 §13.20 item 3 | verified, 17 | covered |
| R-SE-04 | verified, 5 | render and known_hosts units only. No host-key substitution, no host-verification level |
| T06 | verified, 1 | JSON uninstall covered; incomplete-rollback half uncovered |

## 1. Per-claim verdicts

Verdicts:
* **covered**: ran and passed;
* **ruled out**: an ADR ruling, the plan's own text or an owner-input row removes it;
* **gap, missing test**: planned, but no test exists;
* **gap, Unix-only**: a test exists, but it is `cfg(unix)` with no Windows counterpart and no ruling;
* **gap, other**: described in the row.

### A01

| # | Claim (source) | Test(s), exists? | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A01-1 | Windows "✔ scratch `-F`, fixture pipe agent" (§4 table) | `e2e_cli_m02::ssh::a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_f`, `…::a01_unaffected_aliases_effective_config_identical_before_after`, `…::a01_no_remote_change`, `…::a01_no_key_export`, `…::a01_personal_profile_without_repository` (yes) | `#[cfg(unix)] mod ssh` (cli_m02.rs:2895) | not on Windows; e2e_cli_m02 ran 12, all `json::`, `jsonschema_lite::` or `u9_usage_*` (W:396-430) | **gap, Unix-only** |
| A01-2 | same row, U4 part (§3 A01: "U4 `a22_apply_then_rollback_*`, `private_key_files_never_opened`") | `integration_projection::a22_apply_then_rollback_restores_user_bytes_exactly`, `::private_key_files_never_opened`, `integration_projection_replace::private_key_files_never_opened` (yes) | file `#![cfg(unix)]` (projection.rs:21); `#[cfg(unix)]` (projection_replace.rs:1982) | `### integration_projection` → `running 0 tests` (W:1723) | **gap, Unix-only** |
| A01-3 | same row, U5 part (§3: "U5 `catalog_*`, `e2e_catalog_then_ensure_bind_*`") | `model_setup::catalog_alias_rename_keeps_destination_id`, `e2e_setup_dispatch::e2e_catalog_then_ensure_bind_carry_pairs_and_selection` (yes) | file `#![cfg(unix)]` (setup.rs:15, setup_dispatch.rs:11) | `running 0 tests` (W:3059, W:472) | **gap, Unix-only** |
| A01-4 | same row, U2 part | `model_sshconf_eval::{unaffected_names_keep_their_behaviour, managed_values_are_determined_whatever_follows, identity_selection_reports_fingerprint_and_backing}` | none | `test identity_selection_reports_fingerprint_and_backing ... ok` (W:3151) and the other two | **covered** (pure model only) |
| A01-5 | Windows ordinary ssh without `-F` (§4 blocked) | none | — | blocked row in record | **ruled out**: owner input B2 (m02-plan §7) |
| A01-6 | WSL "✔ ordinary ssh, no `-F`" (§4) | `wsl_ordinary_ssh` steps a01_* (7) | scenario | `test a01_setup_apply_writes_the_users_real_ssh_config ... ok` (L:20) to `test a01_provider_agent_accepted_key_is_the_adopted_one ... ok` (L:27) | **covered** |

### A11

| # | Claim (source) | Test(s), exists? | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A11-1 | Windows "✔ fixture pipe states" (§4) | `integration_adapters::a11_*` (U6) | none (except below) | `test a11_fake_onepassword_states ... ok` (W:1602), `a11_declared_none_reported_declared_and_lapses ... ok` (W:1600), `a11_noninteractive_ensure_never_contacts_provider ... ok` (W:1596) | **covered** |
| A11-2 | Windows "fresh-eligibility … cases with the fixture pipe agent" (§4; U8 M2-R04) | `e2e_run_m02::a11::a11_declaration_withdrawn_after_bind_refused_before_launch`, `…redeclaration_after_bind_changes_revision_and_refuses_launch`, `…declaration_expiring_between_bind_and_launch_refused`, `…lapse_recorded_by_failed_listing_between_ensure_and_bind_refuses_launch`, `…withdrawal_and_redeclaration_after_a_restart_between_ensure_and_bind_refuse`, `…replayed_bind_result_still_gets_prelaunch_check`, plus `a11_declared_none_allows_noninteractive_launch_and_result_says_declared`, `a11_noninteractive_run_refuses_interactive_identity_before_launch`, `a11_multi_pair_binding_refused_when_any_pair_needs_interaction`; `e2e_setup_dispatch::declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher` (yes) | `#[cfg(unix)] mod a11` (run_m02.rs:2278); setup_dispatch.rs:11 | e2e_run_m02 ran 12, none `a11::` (W:433-445). The pure `*domain_eligibility_rule_table` ran | **gap, Unix-only** |
| A11-3 | Windows "fallback-clearance cases with the fixture pipe agent" (§4; M2-R05) | `a11::a11_fallback_cleared_when_alternative_adopted_and_declared_launches`, `a11::a11_file_backed_fallback_is_never_cleared`, `a11::a11_identityfile_added_after_ensure_is_seen_by_prelaunch_check`; `integration_doctor::a21_noninteractive_authentication_refused_for_unknown_or_interactive_identity` (yes) | `mod a11` unix; doctor.rs:1070 `#[cfg(unix)]` | not on Windows; `integration_doctor` `running 4 tests` (W:1634) | **gap, Unix-only** |
| A11-4 | "no unapproved fallback" for exclusive selection (§3: `a35_wrong_key_exclusive_selection_fails_without_fallback`) | `e2e_cli_m02::ssh::a35_wrong_key_exclusive_selection_fails_without_fallback` (yes) | `mod ssh` unix | not on Windows | **gap, Unix-only** (fixed with A35) |
| A11-5 | Windows system agent, incl. confirm-constrained (§4 blocked) | `a11_locked_native_agent_lists_nothing` (adapters.rs:465), `f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed` (testkit_fixtures.rs:828), `a11::a11_confirm_constrained_native_key_refused_before_agent_contact`, `a11::a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact` | `#[cfg(unix)]`: these drive a disposable OpenSSH `ssh-agent` | blocked row in record | **ruled out**: B4 is the Windows equivalent. Needs a `platform_only_rationale` entry (§3 below) |
| A11-6 | interactive approval stays first-class (U8 `a11_interactive_connect_succeeds_after_provider_approval`, a pty case) | yes | `mod a11` unix, pty | not on Windows | **gap, other**: no ruling covers this e2e_run_m02 pty case (§12.32 item 4 is about cli_m02). Needs a decision (D3) |
| A11-7 | 1Password live (B1), hardware touch (B6) | — | — | blocked rows | **ruled out** (owner inputs) |

### A21

| # | Claim (source) | Test(s), exists? | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A21-1 | "all three (Windows canary through `cmd.exe`, F13)" (§3); U3: canaries "through `sh -c` on Unix and `cmd /c` on Windows" | `a21_default_doctor_runs_no_exec_no_agent_no_network_no_mutation` (yes) | doctor.rs:359 `#[cfg(unix)]` | not on Windows (W:1634: 4 tests) | **gap, Unix-only** |
| A21-2 | U3: "on Windows, the hook's child is killed with the job, `containment: job_object`" | `a21_evaluate_authorized_runs_hooks_and_claims_no_exclusion`, `a21_hanging_match_exec_killed_with_group_at_timeout` (yes) | :741, :778 `#[cfg(unix)]` | not on Windows | **gap, Unix-only**. Product path: `local_query.rs:207-257` `JobObject` |
| A21-3 | Authorization gating (M2-R06, M2-S04; U3) | `a21_evaluate_declined_without_allow_config_commands`, `a21_inert_config_still_requires_allow_config_commands`, `a21_match_exec_inserted_after_static_pass_never_runs_unauthorized`, `a21_new_glob_member_after_static_pass_is_reported_and_never_listed`, `a21_change_then_revert_is_undetected_and_inventory_never_complete`, `a21_unreadable_include_declines_even_with_authorization` | `#[cfg(unix)]` :417-686 | not on Windows | **gap, Unix-only** |
| A21-4 | Host-verification and authentication levels (U3) | `a21_host_verification_offers_nothing_to_sign`, `a21_host_verification_requires_authorization_with_or_without_constructs`, `a21_authentication_level_single_identity_fixture_signs_exactly_once` | `#[cfg(unix)]` :985-1045 (needs `LoopbackSshd`) | not on Windows | **gap, Unix-only** |
| A21-5 | Agent and network levels, agent timeout, identity remedy (U3) | `a21_agent_level_sends_only_request_identities`, `a21_network_level_reads_banner_only`, `a21_agent_that_never_replies_times_out`, `doctor_reports_identity_selection_not_exclusive_with_remedy` | none | W:1635-1638 `... ok` | **covered** |
| A21-6 | `home_resolution_matches_ssh_g` "on each platform (F19)" (U3) | yes | :1483 `#[cfg(unix)]` | not on Windows. Only the unit `sys::tests::account_home_is_absolute_and_never_read_from_home_variable ... ok` (W:1088) ran, with no `ssh -G` comparison | **gap, Unix-only** |
| A21-7 | ADR-0007 §12.28 item 4: Windows `sys::account_name` matching Win32-OpenSSH `pw_name`; "U11 closes it natively" | `doctor_reads_localuser_from_the_account_database` (yes, Unix) | doctor.rs:1145 `#[cfg(unix)]`; product `sys/mod.rs:112` `#[cfg(unix)]` | not on Windows | **gap, other (product gap)**: the function does not exist on Windows |
| A21-8 | `a21_local_queries_listed_and_off_with_no_local_exec` (U3) | yes | :1424 `#[cfg(unix)]` | not on Windows | **gap, Unix-only** |
| A21-9 | `a21_fifo_include_does_not_block` (U3: "a Unix `mkfifo` fixture") | yes | :1385 `#[cfg(unix)]` | not on Windows | **ruled out** by the plan's own text. Needs a rationale entry |
| A21-10 | Displays "as written" and `/` on Windows (ADR-0007 §12.26 item 7, §12.30 item 10, §12.43 item 1); home mismatch (§12.17 item 9) | `doctor_shows_a_file_outside_the_home_as_written`, `doctor_lists_config_files_and_include_failures_as_written`, `home_mismatch_makes_a_home_relative_include_not_fully_readable` | :1232, :1307, :1561 `#[cfg(unix)]` | not on Windows | **gap, Unix-only** |
| A21-11 | CLI `a21_cli_*` pty cases | `e2e_cli_m02::unix::a21_cli_*` (3) | `mod unix` | JSON twin `json::a21_cli_doctor_json_validates_against_schema ... ok` (W:406) | **ruled out**: ADR-0007 §12.32 item 4, with rationale in `case-index.json` |
| A21-12 | U10 `search_never_probes`, `config_commands_authorization_requires_typed_yes` | `e2e_tui_m02::pty::*` (yes) | pty, `cfg(unix)` | e2e not on Windows. Model twins `tui::model::tests::search_is_immediate_and_produces_no_effect ... ok` (W:1417), `tui::model::tests::config_commands_authorization_requires_typed_yes ... ok` (W:1448) | **gap, other**: no ruling or rationale covers `e2e_tui_m02` (decision D2) |

### A22

| # | Claim (source) | Test(s), exists? | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A22-1 | Windows "✔ in-box 9.5p2" (§4), corpus "on every target client … Windows in-box 9.5p2" (U3) | `integration_sshconf_vs_ssh_g::*` (15) | none | `test bom_and_crlf_acceptance ... ok` (W:1970), `test corpus_identity_list_matches_ssh_g ... ok` (W:1975); observations `client=windows:9.5p2` (W:1980-2000) | **covered**. Note: the observation `corpus_bom_loads="true" corpus_crlf_loads="true"` was never folded into `ENCODING_OBSERVATIONS` (product data gap, see §2 G-P2) |
| A22-2 | "DACL and displaced-identity retention (race-free only)" (§4) | `windows_replace_preserves_dacl`, `windows_replace_retains_displaced_identity_without_race` | `#[cfg(windows)]` (projection_replace.rs:2121, :2160) | W:1774, W:1765 `... ok` | **covered** |
| A22-3 | `rendered_file_loads_on_target_client`: "Windows native. `ssh -G -F` reads the rendered user file and P" (U4); ADR-0007 §4: "the Windows run of `integration_projection::rendered_file_loads_on_target_client` settles it" (LF `[I]`) | **absent** | — | — (the corpus observation `lf_b_effective="true"` covers the user file only, not a rendered P) | **gap, missing test** |
| A22-4 | "junction reparse row" (§4, ⟨r2⟩); U4 `a22_windows_reparse_point_user_config_is_manual_mode` "a junction for the `.ssh` directory (no elevation needed)" | **absent** | — | — | **gap, missing test** (the doc pass's finding, confirmed) |
| A22-5 | "quarantine via `MoveFileExW` and handle deletion" (§4, ⟨r3⟩) | Primitives: `remove_verified_identity_and_content_mismatch_outcomes`, `settle_outcomes_missing_foreign_occupied_modified`, `edit_after_restore_check_is_kept_in_quarantine_never_deleted` (projection_replace, no gate); `sys::quarantine::windows_tests::*` (4, `cfg(all(test, windows))`). Transaction: `a22_foreign_entry_in_quarantine_slot_is_put_back_never_deleted`, `a22_cleanup_crash_after_quarantine_move_completes_on_retry` (projection.rs). Planned: `a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode` (junction on Windows), `a22_quarantine_removed_when_empty_and_kept_with_foreign_entries` | primitives none/windows; transaction file `cfg(unix)`; planned **absent** | primitives ran (W:1754-1818); `test sys::quarantine::windows_tests::live_quarantine_pins_coexist_and_prevent_removal ... ok` (W:1092), and W:1093, W:1098, W:1101, but `heimdall_localenv-unit` is not in A22's index, so they are uncounted; transaction tests `running 0 tests` (W:1723) | **covered** for the primitives; **gap, Unix-only** for the transaction; **gap, missing test** ×2 |
| A22-6 | "symlink cases `platform_only` Unix" (§4); Windows file-symlink row (B10) | `a22_symlinked_user_config_is_manual_mode` etc. | `cfg(unix)` | deferred row in record | **ruled out**: §4 text, and ADR-0007 §12.45 for the file-symlink row (M04). Developer Mode is on (host.txt `developer-mode=on`), so §12.45's deferral is now cheap to undo (decision D7) |
| A22-7 | "the Git name transitions natively on Windows (`ReplaceFileW` with the `.hm-displaced` backup, the lock held by K)" (§3 ⟨r5⟩, §4); U4: "runs … on Windows natively … with `ReplaceFileW`" | `git_name_transitions_crash_at_every_point_reconciles` (projection_git.rs:1440), `git_lock_occupied_by_holder_until_settlement` (:1602) | file `#![cfg(unix)]` (:17) | `### integration_projection_git` → `running 0 tests` (W:1734) | **gap, Unix-only** (the doc pass's finding, confirmed) |
| A22-8 | Git item applicability where it really applies (Windows bundled MSYS; ADR-0007 §5.6) | `git_item_not_offered_without_bundled_msys_default` (:717) and the whole Git transaction | file `cfg(unix)`. On Unix the transaction runs only through the test override `git_item_any_default` (projection_git.rs:10-13, :484) | not on Windows. The only platform where the item is offered for real never ran it (Windows observed `git_bundles_msys_ssh="true"`, W:1683) | **gap, Unix-only** |
| A22-9 | `git_spaced_client_path_is_quoted_and_runs` "(Windows native: `[clients] ssh` at a spaced scratch copy … `git ls-remote` reaches the fixture sshd)" (U4) | **absent** | — | — | **gap, missing test** |
| A22-10 | `fresh_writer_creates_absent_ssh_config` "(Windows: owner-only DACL)" and `fresh_writer_creates_absent_global_git_config` (U4, M2-T02) | first: yes; second: **absent** | projection.rs `cfg(unix)` | not on Windows | **gap, Unix-only** / **gap, missing test** (the second is absent on every platform) |
| A22-11 | U4 transaction suite on "all three" (§3 A22): commit points, races, settlement, crash recovery, held operations, generated properties, recovery-table vectors | `integration_projection::*` (107), `integration_projection_recovery_rows::recovery_table_rows_each_have_a_test_vector` | file `cfg(unix)` | `running 0 tests` (W:1723, W:1745); Linux ran 106 and 1 | **gap, Unix-only**. By a body-marker heuristic, 70 of 107 use no symlink, mode, hardlink, uid, fifo or signal API |
| A22-12 | U5 decision, consent and restart tests (§3); `simultaneous_setup_admissions_admit_exactly_one` | `model_setup::*` (51), `e2e_setup_dispatch::simultaneous_setup_admissions_admit_exactly_one` | file `cfg(unix)` | `running 0 tests` (W:3059, W:472) | **gap, Unix-only** (50 of 51 show no Unix marker) |
| A22-13 | Git observation fixtures "each in a scratch home on every target Git" (U3, M2-R08) | 16 tests; `git_unreadable_include_makes_item_not_applicable` | 16 none; 1 `#[cfg(unix)]` (git_observe.rs:679, mode 000) | `running 16 tests` (W:1653); observations `git version 2.55.0.windows.3` (W:1674-1686) | 16 **covered**; 1 **gap, Unix-only** (needs a deny-read ACE variant) |
| A22-14 | Exchange and birth-time support per filesystem (§3 ⟨r4⟩) | `exchange_supported_on_target_fs`, `file_identity_birth_recorded_on_target_fs` | none | W:1762, W:1778; `observation: exchange_supported_on_target_fs os=windows supported=true`, `… birth_recorded=false` (W:1786, W:1789) | **covered** |
| A22-15 | Store, recovery model and wire forms | `integration_store m02::*` (13), `model_projection_recovery` (9), `heimdall_domain-unit` `file_identity_wire_forms_with_birth` | none | `test projection::tests::file_identity_wire_forms_with_birth ... ok` (W:727) | **covered** |
| A22-16 | CLI `a22_cli_*` | `e2e_cli_m02::unix::a22_cli_setup_conflict_then_repair`, `…held_operation_status_retry_and_keep` | `mod unix` (pty) | not on Windows | **ruled out** (§12.32 item 4) |
| A22-17 | WSL "✔ ext4 exchange" (§4) | `wsl_ordinary_ssh::a22_rename_exchange_supported_on_the_home_fs` | scenario (Python ctypes `renameat2`, scenario-ordinary-ssh.sh:297-320) | `test a22_rename_exchange_supported_on_the_home_fs ... ok` (L:29); host.txt `rename-exchange=supported (renameat2 RENAME_EXCHANGE)`, `home-fs=ext4` | **covered** |
| A22-18 | WSL ext4 birth time (U4 `file_identity_birth_recorded_on_target_fs`: "APFS, devbox ext4, **WSL ext4** and the container overlay") | no scenario step | — | host.txt has no birth fact | **gap, other**: the WSL scenario does not record it |

### A27

| # | Claim (source) | Test(s) | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A27-1 | "✔ pseudoconsole" (§4); Ctrl-C and resize (U8) | `windows_launch` `ctrlc.event`, `ctrlc.keystroke`, `ctrlc.break`, `resize` | scenario | `test ctrlc.event ... ok` (W:3477), `ctrlc.keystroke` (W:3479), `ctrlc.break` (W:3481), `resize` (W:3483) | **covered** |
| A27-2 | "batch rules" (§4) | `a27_windows_cmd_and_bat_targets_get_escaped_args`, `a27_windows_batch_path_with_percent_bang_caret_refused_127`, `a27_windows_current_directory_never_searched` | `#[cfg(windows)]` | W:444, W:436, W:434 `... ok` | **covered** |
| A27-3 | "`spawned` record" (§4 ⟨r2⟩) | `a27_windows_spawned_record_is_positive_launch_proof` | `#[cfg(windows)]` | W:438 | **covered** |
| A27-4 | "launcher-kill holder row" (§4) | `windows_holder_is_launcher_and_forced_launcher_kill_is_reported` | `#[cfg(windows)]` | W:442 | **covered** |
| A27-5 | Streams, status, no contamination ("all three", §3) | `a27_no_stdout_contamination_in_run_and_connect`, `a27_argv_canary_absent_…`, `a27_child_exit_codes_0_to_255_preserved`, `a27_windows_full_32bit_exit_code_preserved`, `a27_missing_executable_exits_127_with_prelaunch_record`, `run_retry_…` | none / windows | W:439, W:440, W:445, W:437, W:435, W:441 | **covered** |
| A27-6 | `a27_shell_metacharacters_in_argv_reach_child_verbatim`, `a27_cwd_and_env_preserved_plus_only_documented_additions` (U8, "all three") | yes | run_m02.rs:837, :877 `#[cfg(unix)]` | not on Windows | **gap, Unix-only**. Non-batch `.exe` argv quoting and env/cwd are untested natively. `env.rs`'s Windows arm has unit tests only (`windows_bundled_msys_default_injects_the_verified_client_through_git_config_count`, env.rs:564) |
| A27-7 | `a27_meta_file_existing_or_fd_invalid_is_usage_error_before_ensure` (U8) | yes | :745 `#[cfg(unix)]` | not on Windows | **gap, Unix-only** for the `--meta-file` half (`create_owner_only_exclusive` has a Windows arm, sys/mod.rs:306); the `--meta-fd` half is Unix-only by design (sys/mod.rs:274, ADR-0007 §12.15 item 8 E1) |
| A27-8 | `a27_binary_stdin_stdout_roundtrip_through_ssh`, `a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`, `a27_git_clone_and_push_over_ssh_with_binary_blob` (U8) | yes | `mod a11` unix (`SshWorld`) | not on Windows | **gap, Unix-only** (fixed with A35) |
| A27-9 | Unix process-model tests: `a27_signal_death_preserved` (U8: "(Unix)"), `a27_not_executable_exits_126`, `a27_child_exit_127_vs_exec_failure_…`, `a27_kill_between_launching_and_exec_…`, `a27_exec_failure_with_failed_meta_write_…`, `a27_meta_unavailable_aborts_launch_no_child`, `a27_sigpipe_…`, `terminal::*`, `heimdall_launch-unit::{unix,handoff,resolve::unix_*,meta fd}::*` | yes | `cfg(unix)` | not on Windows (Windows counterparts in rows 1-5) | **ruled out** by the plan's text and ADR-0007 §8's Windows sequence (§12.43 item 4: "launching, spawned, exited"), but **no `platform_only_rationale` exists for any of them**. Needs entries (§3) |
| A27-10 | Interactive console Ctrl-C and resize (B5) | — | — | blocked row | **ruled out** (owner input) |

### A35

| # | Claim (source) | Test(s), exists? | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| A35-1 | Windows "✔ fixture pipe agent × in-box ssh" (§4) | `e2e_cli_m02::ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound`; fixture-level `integration_testkit_fixtures::fake_agent_round_trip_with_real_ssh_login` | `mod ssh` unix; testkit_fixtures.rs:1240 `#[cfg(unix)]` | no Windows test starts `ssh.exe` against a server. §12.43 item 5: "No Windows test uses the harness sshd today; every `LoopbackSshd::start` caller is `cfg(unix)`." | **gap, Unix-only** (the doc pass's finding, confirmed) |
| A35-2 | "× Git (System32 via the Q7 include …)" (§4) | Git item applied on Windows (projection_git.rs), `a11::a27_git_clone_and_push_over_ssh_with_binary_blob` | `cfg(unix)` | not on Windows | **gap, Unix-only** |
| A35-3 | "× Git … via run-time injection" (§4; U8 "runs on every target Git") | `git_run_resolution_in_child_cwd_reports_local_override_and_injects_nothing`, `git_run_injection_yields_to_dash_c_and_env`, `git_run_never_records_child_arguments_or_config_values`, `git_run_malformed_caller_git_config_count_injects_nothing` | run_m02.rs:2048-2244 `#[cfg(unix)]` | not on Windows. The Windows-only injection branch (`crates/launch/src/env.rs:4-6`) has never run with Git for Windows | **gap, Unix-only** |
| A35-4 | "… and bundled MSYS as a recorded limitation" (§4) | `integration_git_observe::git_run_selection_in_cwd_reports_local_override` | none | `... ok` (W:1661); `observation … git_bundles_msys_ssh="true"` (W:1683) | **covered** (as a recorded observation) |
| A35-5 | "× scp, sftp" (§4) | `ssh::a35_matrix…` (scp and sftp legs), `a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths` | `cfg(unix)` | no `scp.exe` or `sftp.exe` run | **gap, Unix-only** |
| A35-6 | "× {ordinary alias, run-bound} × {wrong key, inherited fallback (agent, file), too many keys, IdentityAgent overriding SSH_AUTH_SOCK}" (§4 "the same") | `ssh::a35_wrong_key_…`, `ssh::a35_inherited_identity_fallback_agent_backed_…`, `…_file_backed_…`, `ssh::a35_too_many_keys_succeeds_for_managed_alias_only`, `ssh::a35_identity_agent_overriding_ssh_auth_sock_…`, `ssh::a35_mutation_broken_identity_agent_is_detected`; `integration_testkit_fixtures::many_keys_exhaust_max_auth_tries_without_identities_only` | `cfg(unix)` (testkit_fixtures.rs:1333) | not on Windows | **gap, Unix-only** |
| A35-7 | Fixture and adapter level (U6, U7) | `a35_identity_selected_by_public_key_with_identities_only`, `adapters_never_send_*`, `client_command_never_adds_selection_options`, git_observe (16) | none | W:1603, W:1601, W:2289, W:1653 | **covered** (fixture level only; this is the 19 the record counts) |
| A35-8 | WSL "✔ ordinary path" (§4) | `wsl_ordinary_ssh::a01_ordinary_{ssh_alias,git,scp,sftp}_without_f` | scenario | L:21-24 `... ok` | **covered** |
| A35-9 | 1Password (B1), Windows system agent (B4), Linux arm64 (B9) | — | — | blocked rows | **ruled out** (owner inputs) |

### R-RT-05, ADR-0006 §13.20 item 3, R-SE-04, T06

| # | Claim (§3 row; Native runs "all three") | Test(s) | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| RT-1 | R-RT-05 run and journal | `run_retry_with_same_request_id_never_relaunches_automatically`, `contracts m02::journaled_operation_kinds_match_their_request_kind`, `u0b_restart_dispatches_every_operation_kind` | none | W:441, W:253, W:2569, W:2669 | **covered** |
| RT-2 | R-RT-05 projection and setup restart | `integration_projection::{a22_update_crash_after_p_exchange_reconciles, a22_update_crash_between_post_validation_and_commit_reconciles, a22_update_crash_after_commit_before_settlement_settles_never_restores, held_step_moves_nothing_and_reobserves_at_restart, generated::recovery_generated_observations_preserve_every_entry}`, `integration_projection_recovery_rows::recovery_table_rows_each_have_a_test_vector`, `model_setup::{restart_reconciles_attempted_apply_never_reapplies, …_after_a_process_abort}` | file `cfg(unix)` | `running 0 tests` (W:1723, W:1745, W:3059) | **gap, Unix-only** |
| BND-1 | ADR-0006 §13.20 item 3 | `model_operations u0b_adapter_bound::*` and the preserve list (16), `adapters_stop_all_work_when_dropped` | none | W:2654 `u0b_adapter_bound::u0b_every_adapter_call_is_bounded ... ok`, W:1604 `adapters_stop_all_work_when_dropped ... ok`; 17 of 17 | **covered** |
| SE-1 | R-SE-04: render refuses host-verification directives | `heimdall_sshconf-unit render::*` | none | W:1223, W:1224 | **covered** |
| SE-2 | R-SE-04: known_hosts | `heimdall_localenv-unit known_hosts::*` | none | W:1065, W:1096, W:1102 | **covered** |
| SE-3 | R-SE-04: `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` (U9, `LoopbackSshd`) | yes | `mod ssh` unix | not on Windows | **gap, Unix-only** (the doc pass's finding, confirmed) |
| SE-4 | R-SE-04: U3 `known_host_mismatch` finding; host-verification level | asserted in `a21_host_verification_offers_nothing_to_sign` (doctor.rs:1005); `a21_host_verification_requires_authorization_…` | `#[cfg(unix)]` | not on Windows | **gap, Unix-only** |
| T06-1 | `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items` | `e2e_cli_m02::json::…` | none | `test json::uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items ... ok` (W:407) | **covered** |
| T06-2 | `uninstall_with_incomplete_rollback_keeps_artifacts_and_purge_refuses` (Q6, kept quarantine entry) | `e2e_cli_m02::unix::…` | `mod unix`, pty, `from_mode(0o700)` quarantine | not on Windows | **ruled out** for the typed confirmation (§12.32 item 4); the Windows half (kept quarantine under a DACL, purge refused with exit 6) has no test: **gap, other** (decision D4) |
| T06-3 | WSL "the WSL distribution with a real home" | `wsl_ordinary_ssh::t06_*` | scenario | L:32, L:33; host.txt sha256 before = after uninstall | **covered** |

### Exit claims

| # | Claim | Test(s) | cfg | Native at ce21a76f | Verdict |
|---|---|---|---|---|---|
| X-1 | "A participant can connect without a mandatory work wrapper", WSL (only declared row) | `wsl_ordinary_ssh` (5) | scenario | L:20-24 | **covered**; human part B7 **ruled out** (owner input) |
| X-2 | "No remote authentication change, key export, or provider-policy bypass", Windows | `e2e_cli_m02::ssh::a01_no_remote_change`, `…::a01_no_key_export` | `mod ssh` unix | not on Windows | **gap, Unix-only** |
| X-3 | same, adapter level | `adapters_never_send_*`, `a35_identity_selected_…`, `identity_selection_reports_fingerprint_and_backing` | none | W:1601, W:1603, W:3151 | **covered** |
| X-4 | "Does not claim managed unattended access until M03", Windows | `a11_unattended_minimum_is_capability_unavailable_for_both_mechanisms`, `u0b_unattended_minimum_*` | none | W:1592, W:2558 | **covered** |
| X-5 | Aggregate "M02 exit cases" | all the above | | | inherits every gap above |

Also checked and not a gap:
* the WSL binary is the exit build: `heimdall … sha256: 09d04d50…` in both `wsl-distro/build.txt` and `linux/build.txt:220`;
* `test-pipes-before=0` and `test-pipes-after=0` (Windows host.txt);
* the DACL tests use `icacls` in-test (projection_replace.rs:2124-2131).

## 2. Gap details

Product path: whether Heimdall has Windows code that the test would exercise. "Test gap"
means the product path exists and only native evidence is missing.

### G-T1 (prerequisite): fixture sshd for Windows tests

Blocks A01-1, A11-4, A21-4, A27-8, A35-*, SE-3, SE-4, X-2 and A22-9.

**Product:** n/a.

**Testkit defect.** `LoopbackSshd::from_harness` (sshd.rs:123-153) has these problems:
1. **Sshd account.** It has no account name. The WSL sshd authenticates only the WSL
   account, and the runner records `fixture-sshd-account=differs from the Windows user`
   (Windows host.txt). Every Windows client must therefore log in as that account.
   * Add `HM_FIXTURE_SSHD_USER`, exported by `run-windows-local.ps1` from the `wsluser`
     value it already reads (line 581).
   * Have the fixture write `User <name>` into the scratch user config. `ScratchHome`'s
     `isolation_args` must stay `-F`, `UserKnownHostsFile`, `GlobalKnownHostsFile` and
     `BatchMode` only (U7), so the name cannot go there.
   * Add the WSL account name to the runner's redaction and leak scan. It is personal
     data, like `<winuser>`.
2. **Ignored settings.** It ignores `SshdConfig.max_auth_tries` and `log_level_verbose`.
   The harness sshd is fixed at `MaxAuthTries 6`, but
   `a35_too_many_keys_succeeds_for_managed_alias_only` and `ManyKeys` need
   `MaxAuthTries 3`. `from_harness` must either refuse a config it cannot honour
   (`SshdUnavailable`, which then shows as a missing test) or use a second harness sshd
   (for example `HM_FIXTURE_SSHD_STRICT_{PORT,HOST_KEY}`) started with `MaxAuthTries 3`.
3. **Shared authorized-keys file.** It `fs::write`s one shared
   `HM_FIXTURE_SSHD_AUTHORIZED_KEYS` on every start. Under cargo's parallel test threads,
   test B's keys replace test A's mid-login. It needs a process-wide lock held for the
   fixture's lifetime, or the binaries' harness-sshd tests run with `--test-threads=1`.
   The lock is better, because it lives in code.
4. **Shared log.** All tests read one shared `HM_FIXTURE_SSHD_LOG`. `accepted_log()` must
   read from the offset at which the fixture started.

**What the runner already does.** `run-windows-local.ps1:578-652` starts the sshd in WSL
scratch, checks the banner from Windows and exports `HM_FIXTURE_SSHD_{HOST,PORT,HOST_KEY,
AUTHORIZED_KEYS,LOG}`. `StrictModes no` (remote-lib.sh:150) makes the `/mnt/c`
authorized-keys file acceptable.

**Not needed.** No second machine (WSL is on the PC, on loopback) and no owner input. No
elevation and no Developer Mode.

**Size: M.**

### G-1: A35 Windows transport matrix, A01 scratch `-F`, R-SE-04 substitution, no-remote-change claim

Covers A01-1, A11-4, A35-1/5/6, SE-3 and X-2.

**Product:** a test gap.
* P renders the pipe `IdentityAgent` form (`RenderPath::pipe`).
* The corpus agreed with 9.5p2 on `//./pipe/` forms (W:1975).
* The FakeAgent serves `\\.\pipe\heimdall-hmtest-*` (testkit agent.rs:121-136).
* Whether `ssh.exe` 9.5p2 authenticates through that pipe is unproven natively.

**Native test.**
* Ungate `e2e_cli_m02::ssh` (`cfg(any(unix, windows))`).
* Replace its pty `apply` with the `--json` apply path that
  `json::setup_preview_apply_and_status_json_on_every_platform` already exercises on
  Windows (W:405).
* Use the in-box `ssh.exe`, `scp.exe` and `sftp.exe`, which the tests already resolve
  (`ssh-V-tests=OpenSSH_for_Windows_9.5p2`).
* Use a FakeAgent pipe as agent A and a second FakeAgent pipe as the decoy at
  `SSH_AUTH_SOCK`.
* The accepted fingerprint comes from the WSL sshd's VERBOSE log.
* Host-key substitution needs no second server: the test rewrites the scratch known_hosts
  (cli_m02.rs:3412-3418).
* `a35_inherited_identity_fallback_file_backed_…` needs a private key file. On Windows
  `ssh.exe` requires an owner-only DACL for it, so the fixture needs a DACL helper.
* Also ungate `integration_testkit_fixtures::fake_agent_round_trip_with_real_ssh_login`
  and `many_keys_exhaust_max_auth_tries_without_identities_only` (needs G-T1 item 2).

**Inputs:** none. B2 is only for the *without `-F`* row, which stays blocked.

**Size: L.**

### G-2: A35 Git legs and Git under `run`

Covers A35-2, A35-3, A27-8 Git and A22-9.

**Product:** a test gap.
* `crates/launch/src/env.rs:4-6` has the Windows-only `GIT_CONFIG_COUNT` injection,
  unit-tested with `Platform::Windows` (env.rs:564), but never with Git for Windows.
* The B_git include for the System32 client is ADR-0007 §5.6.

**Native test.**
* `git_run_*` (4) and `a27_git_clone_and_push_over_ssh_with_binary_blob`, with Git for
  Windows 2.55 (already on the PC), a scratch `HOME` and `GIT_CONFIG_NOSYSTEM`. The
  runner's environment hygiene already strips `GIT_*`
  (run-windows-local.ps1:413).
* Use the remote repository in WSL scratch, reached as `<alias>:<path>`.
* `a27_git_clone…` uses `DisposableSshAgent` on Unix; on Windows it uses a FakeAgent pipe.
* New test `git_spaced_client_path_is_quoted_and_runs`: copy the verified client to a
  spaced scratch path and set `[clients] ssh` to it; `git ls-remote` reaches the WSL sshd.

**Size: M**, plus an S for the new test.

### G-3: A22 projection transaction on Windows

Covers A01-2, A22-3/4/5/10/11 and RT-2.

**Product:** a test gap. The Windows arms exist:
* `projection/replace.rs` (`ReplaceFileW` and the `.hm-displaced` names, lines 104-110,
  183, 231-245);
* `projection/apply.rs:318-520`;
* `sys/quarantine.rs:103-1056` (`MoveFileExW`, handle deletion, pins);
* `DirHandle::open_with`'s Windows arm, which opens with
  `FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS` (replace.rs:150-197).

ADR-0007 §12.45 says so: "`integration_projection` has no tests on Windows."

**Native test.**
* Replace `#![cfg(unix)]` (projection.rs:21) with per-test gates.
* About 70 tests use no Unix-only API (heuristic); they should run unchanged.
* About 37 use modes, symlinks, hardlinks or a SIGABRT child. They need either a Windows
  variant (owner-only DACL instead of 0600/0700; `std::process::abort` in the child gives
  a non-zero exit on Windows) or a rationale entry. Symlink cases are `platform_only` Unix
  per §4.
* New tests:
  * `a22_windows_reparse_point_user_config_is_manual_mode`: `mklink /J` or
    `CreateDirectoryW` plus a reparse point; a junction needs no elevation and no
    Developer Mode.
  * `a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode`: the Windows variant is a
    junction at `.hm-quarantine`.
  * `a22_quarantine_removed_when_empty_and_kept_with_foreign_entries`.
  * `rendered_file_loads_on_target_client`: `ssh.exe -G -F` reads the rendered user file
    and P. No server is needed.

**Developer Mode:** allows the deferred file-symlink row, through
`SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE`, if the orchestrator un-defers it (D7).

**Size: L.**

### G-4: A22 Git transaction on Windows

Covers A22-7, A22-8 and A22-10's Git half.

**Product:** a test gap. `projection/git.rs` has no `cfg`; it goes through the replace
primitives, so on Windows K and the `.hm-displaced` backup run through `ReplaceFileW`.

**Native test.**
* Remove `#![cfg(unix)]` (projection_git.rs:17).
* On Windows, leave `git_item_any_default` false: Git for Windows really bundles MSYS
  (W:1683), so the item is offered for real.
* Crash points are in-process, as on Unix.
* `git_lock_occupied_by_holder_until_settlement` runs `git config --global` against the
  held lock.
* Remove `#![cfg(unix)]` from `projection_recovery_rows.rs:46` and fill `NOT_REPRESENTABLE`
  honestly for Windows, where both aside names exist.
* New test: `fresh_writer_creates_absent_global_git_config`.
* `git_unreadable_include_makes_item_not_applicable`: a deny-read ACE variant.

**Inputs:** none.

**Size: L.**

### G-5: U5 setup drivers on Windows

Covers A01-3, A11-2 (dispatcher), A22-12 and RT-2 (model_setup).

**Product:** a test gap (runtime service and pipe IPC exist on Windows; `integration_runtime`
ran 52 on Windows per §12.43 item 6).

**Native test:**
* remove the file gates (setup.rs:15, setup_dispatch.rs:11);
* use a Windows owner principal (`PrincipalRef::WindowsUser { sid }`,
  domain/principal.rs:18) where the tests build `UnixUser`;
* write a DACL variant of `apply_through_operations_snapshots_the_original_user_file`;
* for `restart_reconciles_attempted_apply_never_reapplies_after_a_process_abort`, use
  Windows child abort.

**Size: M.**

### G-6: A21 doctor on Windows

Covers A21-1/2/3/4/6/8/10 and SE-4.

**Product:** a test gap, except for account_name (G-P1).
* The passive doctor is platform-neutral.
* Probes run under `JobObject` (`local_query.rs:207-257`).
* The hook has a Windows `escape` (`CREATE_BREAKAWAY_FROM_JOB`, U7).

**Native test:**
* `cmd /c` canaries (F13) through `hm-fixture-hook.exe` (already built and shipped,
  `HM_FIXTURE_HOOK`, run-windows-local.ps1:567) instead of `/bin/sh`;
* `containment: job_object` asserted, with the escaped child killed by its exact PID;
* host-verification and authentication levels against the WSL sshd (G-T1);
* `home_resolution_matches_ssh_g` against `ssh.exe -G`;
* displays checked for `/` (§12.43 item 1);
* `a21_fifo_include_does_not_block` stays Unix (rationale).

**Size: M–L.**

### G-7: A11 fresh eligibility and fallback, `connect`, A27 argv/env on Windows

Covers A11-2/3, A27-6/7/8 and `connect_*`.

**Product:** a test gap. The pre-launch check is platform-neutral (`launch/eligibility.rs`),
and the FakeAgent pipe and the control pipe exist.

**Native test:**
* ungate `mod a11` (run_m02.rs:2278);
* use `PrincipalRef::WindowsUser` instead of the uid (run_m02.rs:2360-2370);
* `a11_file_backed_fallback_is_never_cleared` needs a private key file with an owner-only
  DACL;
* keep the B4-bound confirm-constrained tests Unix-only with a rationale;
* write a Windows `a27_shell_metacharacters_in_argv_reach_child_verbatim`, with argv
  through `CommandLineToArgvW` for an `.exe` child (`argvdump.exe` already exists for the
  pseudoconsole drivers);
* write a Windows `a27_cwd_and_env_preserved_plus_only_documented_additions`;
* cover the `--meta-file` half of `a27_meta_file_existing_or_fd_invalid_…`.

**Size: L.**

### G-P1: `sys::account_name` on Windows (product gap; A21-7, ADR-0007 §12.28 item 4)

**Product:** missing.
* `sys::account_name` is `#[cfg(unix)]` (sys/mod.rs:112).
* `doctor::local_user` returns `None` on non-Unix (doctor.rs:270-273).
* So `Match localuser`, `Match user`, `%u` and `%r` are always undetermined on Windows
  (ADR-0007 §13: "The account is unknown on Windows until the native lookup lands").

**Native test.** First establish Win32-OpenSSH's `pw_name` form natively: case, and any
domain prefix. For example, use `User %u` in a scratch `-F` and read `ssh -G`'s `user`
line. That form is `[I]`; I did not observe it. Then implement it in the Windows `sys`
module (token user, `LookupAccountSidW`). The Windows variant of
`doctor_reads_localuser_from_the_account_database` compares the two.

**Size: M.**

### G-P2: Windows encodings row (product data; A22-1)

**Product data:**
* This run observed on 9.5p2: `corpus_bom_loads="true" corpus_crlf_loads="true"
  bom_b_effective="true" crlf_b_effective="true"` (record observation for
  `bom_and_crlf_acceptance`).
* `ENCODING_OBSERVATIONS` (clients.rs:160) has only macOS 10.3p1.
* Similarly, `OBSERVED_CLIENTS` (sshconf client.rs:110-150) has no 9.5p2; the corpus prints
  `recorded_for_this_client="none"`.

Both fail closed. The first makes every CRLF or BOM user config on Windows manual mode.

**Fix:** add rows citing the exit-ce21a76f artifact; this is a product decision (D5).

**Size: S.**

### G-W1: WSL ext4 birth time (A22-18)

**Native test:** one scenario step that `statx`es a file in the disposable home and records
`btime`, with the same Python `ctypes` approach as the exchange probe
(scenario-ordinary-ssh.sh:297-320).

**Size: S.**

### Decisions only (no test until ruled)

* A11-6 (D3);
* A21-12 (D2);
* T06-2 (D4).

## 3. Proposed `case-index.json` change (not applied)

### How the generator hides a gap today (`tests/native/m02/m02-evidence.py`)

1. `build_inventory` gives a scanned platform's absences as inventory `platform_only`
   (`scan_platform_only`, lines 262-286).
2. `applicable` (line 420) drops any test whose `platform_only` excludes the platform.
3. `required` (line 432) returns only applicable tests, so `row_for` never sees the dropped
   ones: they are neither `absent` nor `incomplete`.
4. The only guard is in `rows_for` (line 752): a declared platform with **zero** applicable
   tests becomes `in_progress`, `no_applicable_test`. One surviving portable test makes the
   row `verified`.
5. A planned test that was never written is invisible. `--generate-inventory` refuses an
   index pattern that resolves to nothing (line 243), so nobody indexes one.

### Smallest correct mechanism: two rules, both needed

* **(R1) Rationale guard.** On a declared `cargo` platform, a required test that only the
  *scan-derived* `platform_only` excludes has no reason on record. It keeps the row
  `in_progress` and is listed in `excluded_without_rationale`. A test is justified only by
  a `case-index.json` `platform_only` entry that has a `platform_only_rationale` (ADR-0006
  §13.13 item 5 already requires a rationale for those). This catches silent `cfg` gates
  without re-enumerating tests.
  * Simulated read-only on the committed inventory, it flags 329 section-test pairs at
    ce21a76f: 328 on Windows (295 distinct tests) and 1 on Linux. That covers all of §1's
    Unix-only gaps, and nothing on macOS.
  * The Linux hit is `integration_projection::a22_crlf_bom_no_trailing_newline_preserved`
    (`#[cfg(target_os = "macos")]`), which needs a rationale.
  * Removing the inaccurate `e2e_cli_m02::ssh::` entry raises the total to 350 pairs
    (308 distinct Windows tests).
* **(R2) Declared tests per platform.** A per-section `platform_required` map,
  `{platform: {target: [exact name]}}`, lists the tests the plan names for that platform.
  * Each must be `ok` in that platform's log. Otherwise the row is `in_progress` with
    `declared_not_run`.
  * These are exact names, deliberately **not** resolved by `--generate-inventory`, so a
    test that does not exist yet is allowed and reads as not run. This is the only way a
    never-written test can block a row.
  * `check_inventory` validates only the shape: the platform is in `declared_platforms`,
    and no name is a pattern.

Also, every row should carry `excluded_on_this_platform` (count and names). A reader of the
record then sees what `"not_run_on_this_platform": 0` currently hides.

**Generator sketch.** In `rows_for`, after `row_for`, and also on the `no_applicable_test`
path:

```python
sec = index[kind][sid]
want = (sec.get("platform_required") or {}).get(pname, {})
missing = [f"{t}::{n}" for t, ns in want.items() for n in ns if logs.get(t, {}).get(n) != "ok"]
cand = [(t, n) for t, ns in inv[kind][sid]["tests"].items() for n in ns]
excl = [(t, n) for t, n in cand if not applicable(index, inv, t, n, pname)
        and t not in index.get("scenario_targets", {})
        and f"{t}::{n}" not in index.get("child_entries", {})]
def justified(t, n):
    p = platform_only_lookup(index, {"platform_only": {}}, t, n)   # index entries only
    key = next((k for k in index.get("platform_only", {}) if covers(k, t, n)), None)
    return p is not None and pname not in p and key in index.get("platform_only_rationale", {})
unjust = [f"{t}::{n}" for t, n in excl if not justified(t, n)]
row["excluded_on_this_platform"] = len(excl)
if missing: row["declared_not_run"] = missing
if unjust: row["excluded_without_rationale"] = unjust
if (missing or unjust) and row["status"] == "verified": row["status"] = "in_progress"
```

Here `covers` is the same prefix rule `platform_only_lookup` already applies. Add tests in
`tests/native/m02/test_m02_evidence.py`:
* a scan-only exclusion keeps a row `in_progress`;
* a rationale-backed exclusion does not;
* a `platform_required` name absent from the log, or not existing, keeps it `in_progress`;
* `excluded_on_this_platform` is counted.

### Fragment (to merge into `tests/native/m02/case-index.json`)

One change is not expressible as a merge: **delete** the key `"e2e_cli_m02::ssh::"` from
`platform_only` and `platform_only_rationale`. Its rationale ("the Windows client rows are
the native harness's and the B2/B4 owner-input rows") is contradicted by ADR-0007 §12.43
item 5, and the scratch `-F` row is neither B2 nor B4. The top-level switch
`"platform_only_requires_rationale": true` that turns on R1 is in the fragment.

The `platform_only` additions below are those the plan or an ADR already justifies. The
orchestrator ratifies the wording.

```json
{
  "platform_only_requires_rationale": true,
  "platform_only": {
    "e2e_run_m02::terminal::": ["macos", "linux"],
    "e2e_run_m02::a27_signal_death_preserved": ["macos", "linux"],
    "e2e_run_m02::a27_not_executable_exits_126": ["macos", "linux"],
    "e2e_run_m02::a27_child_exit_127_vs_exec_failure_distinguished_by_prelaunch_record": ["macos", "linux"],
    "e2e_run_m02::a27_kill_between_launching_and_exec_is_indeterminate_never_launched": ["macos", "linux"],
    "e2e_run_m02::a27_exec_failure_with_failed_meta_write_is_indeterminate": ["macos", "linux"],
    "e2e_run_m02::a27_meta_unavailable_aborts_launch_no_child": ["macos", "linux"],
    "e2e_run_m02::a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded": ["macos", "linux"],
    "heimdall_launch-unit::unix::": ["macos", "linux"],
    "heimdall_launch-unit::handoff::": ["macos", "linux"],
    "heimdall_launch-unit::resolve::tests::unix_": ["macos", "linux"],
    "heimdall_launch-unit::meta::tests::fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal": ["macos", "linux"],
    "heimdall_launch-unit::meta::tests::stdio_descriptors_and_negative_numbers_are_never_adopted": ["macos", "linux"],
    "heimdall_launch-unit::meta::tests::a_closed_reader_is_never_masked_by_a_concurrent_spawn": ["macos", "linux"],
    "integration_doctor::a21_fifo_include_does_not_block": ["macos", "linux"],
    "integration_adapters::a11_locked_native_agent_lists_nothing": ["macos", "linux"],
    "integration_testkit_fixtures::f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed": ["macos", "linux"],
    "e2e_run_m02::a11::a11_confirm_constrained_native_key_refused_before_agent_contact": ["macos", "linux"],
    "e2e_run_m02::a11::a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact": ["macos", "linux"],
    "integration_projection::a22_symlinked_user_config_is_manual_mode": ["macos", "linux"],
    "integration_projection::a22_race_symlink_substitution_at_boundary_is_held": ["macos", "linux"],
    "integration_projection_replace::race_symlink_substitution_at_boundary_is_held": ["macos", "linux"],
    "integration_projection::a22_crlf_bom_no_trailing_newline_preserved": ["macos"]
  },
  "platform_only_rationale": {
    "e2e_run_m02::terminal::": "rustix pty cases (m02-plan U8: 'Unix pty through rustix; Windows pseudoconsole'); the Windows rows are windows_launch ctrlc.* and resize (ADR-0007 §12.44 item 2).",
    "e2e_run_m02::a27_signal_death_preserved": "m02-plan U8 names it '(Unix)': Windows has no signal death.",
    "e2e_run_m02::a27_not_executable_exits_126": "POSIX 126 (no execute permission); Windows has no execute bit. Proposed; ratify.",
    "e2e_run_m02::a27_child_exit_127_vs_exec_failure_distinguished_by_prelaunch_record": "Unix exec-in-place states; the Windows sequence is launching, spawned, exited (ADR-0007 §8, §12.43 item 4), proven by a27_windows_spawned_record_is_positive_launch_proof.",
    "e2e_run_m02::a27_kill_between_launching_and_exec_is_indeterminate_never_launched": "as above: the pre-exec pause exists only on the Unix exec path.",
    "e2e_run_m02::a27_exec_failure_with_failed_meta_write_is_indeterminate": "as above.",
    "e2e_run_m02::a27_meta_unavailable_aborts_launch_no_child": "run --meta-fd is Unix only (sys::adopt_inherited_fd; ADR-0007 §12.15 item 8 E1).",
    "e2e_run_m02::a27_sigpipe_ignored_by_caller_is_reset_limitation_recorded": "SIGPIPE is POSIX; a recorded limitation, not fidelity (m02-plan U8).",
    "heimdall_launch-unit::unix::": "the Unix exec path; Windows has heimdall_launch-unit::windows::tests (platform_extra).",
    "heimdall_launch-unit::handoff::": "POSIX process groups and job-control signals. Proposed; ratify.",
    "heimdall_launch-unit::resolve::tests::unix_": "Unix PATH rules; Windows has a27_windows_current_directory_never_searched.",
    "heimdall_launch-unit::meta::tests::fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal": "run --meta-fd is Unix only (ADR-0007 §12.15 item 8 E1).",
    "heimdall_launch-unit::meta::tests::stdio_descriptors_and_negative_numbers_are_never_adopted": "as above.",
    "heimdall_launch-unit::meta::tests::a_closed_reader_is_never_masked_by_a_concurrent_spawn": "as above.",
    "integration_doctor::a21_fifo_include_does_not_block": "m02-plan U3: 'a Unix mkfifo fixture'.",
    "integration_adapters::a11_locked_native_agent_lists_nothing": "drives a disposable OpenSSH ssh-agent (ssh-add -x); the Windows native agent is the system service, blocked on B4 (m02-plan §7).",
    "integration_testkit_fixtures::f23_confirm_constraint_installed_prompts_per_signature_and_is_not_listed": "as above (B4, incl. the confirm-constrained row).",
    "e2e_run_m02::a11::a11_confirm_constrained_native_key_refused_before_agent_contact": "as above (B4).",
    "e2e_run_m02::a11::a11_inherited_confirm_constrained_fallback_refused_noninteractive_before_agent_contact": "as above (B4).",
    "integration_projection::a22_symlinked_user_config_is_manual_mode": "m02-plan §4: symlink cases platform_only Unix; the Windows file-symlink row is ADR-0007 §12.45 (M04).",
    "integration_projection::a22_race_symlink_substitution_at_boundary_is_held": "as above.",
    "integration_projection_replace::race_symlink_substitution_at_boundary_is_held": "as above.",
    "integration_projection::a22_crlf_bom_no_trailing_newline_preserved": "cfg(target_os = \"macos\"): ENCODING_OBSERVATIONS records CRLF acceptance only for macOS 10.3p1 (clients.rs:160). Revisit with G-P2."
  },
  "groups": {
    "A01": {
      "platform_required": {
        "windows": {
          "e2e_cli_m02": [
            "ssh::a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_f",
            "ssh::a01_unaffected_aliases_effective_config_identical_before_after",
            "ssh::a01_no_remote_change",
            "ssh::a01_no_key_export",
            "ssh::a01_personal_profile_without_repository"
          ],
          "integration_projection": ["a22_apply_then_rollback_restores_user_bytes_exactly", "private_key_files_never_opened"],
          "model_setup": ["catalog_alias_rename_keeps_destination_id"],
          "e2e_setup_dispatch": ["e2e_catalog_then_ensure_bind_carry_pairs_and_selection"]
        }
      }
    },
    "A11": {
      "platform_required": {
        "windows": {
          "e2e_run_m02": [
            "a11::a11_declared_none_allows_noninteractive_launch_and_result_says_declared",
            "a11::a11_noninteractive_run_refuses_interactive_identity_before_launch",
            "a11::a11_multi_pair_binding_refused_when_any_pair_needs_interaction",
            "a11::a11_declaration_withdrawn_after_bind_refused_before_launch",
            "a11::a11_redeclaration_after_bind_changes_revision_and_refuses_launch",
            "a11::a11_declaration_expiring_between_bind_and_launch_refused",
            "a11::a11_lapse_recorded_by_failed_listing_between_ensure_and_bind_refuses_launch",
            "a11::a11_withdrawal_and_redeclaration_after_a_restart_between_ensure_and_bind_refuse",
            "a11::a11_replayed_bind_result_still_gets_prelaunch_check",
            "a11::a11_identityfile_added_after_ensure_is_seen_by_prelaunch_check",
            "a11::a11_fallback_cleared_when_alternative_adopted_and_declared_launches",
            "a11::a11_file_backed_fallback_is_never_cleared"
          ],
          "e2e_setup_dispatch": ["declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher"],
          "integration_doctor": ["a21_noninteractive_authentication_refused_for_unknown_or_interactive_identity"],
          "e2e_cli_m02": ["ssh::a35_wrong_key_exclusive_selection_fails_without_fallback"]
        }
      }
    },
    "A21": {
      "platform_required": {
        "windows": {
          "integration_doctor": [
            "a21_default_doctor_runs_no_exec_no_agent_no_network_no_mutation",
            "a21_evaluate_declined_without_allow_config_commands",
            "a21_inert_config_still_requires_allow_config_commands",
            "a21_match_exec_inserted_after_static_pass_never_runs_unauthorized",
            "a21_new_glob_member_after_static_pass_is_reported_and_never_listed",
            "a21_change_then_revert_is_undetected_and_inventory_never_complete",
            "a21_unreadable_include_declines_even_with_authorization",
            "a21_evaluate_authorized_runs_hooks_and_claims_no_exclusion",
            "a21_hanging_match_exec_killed_with_group_at_timeout",
            "a21_host_verification_offers_nothing_to_sign",
            "a21_host_verification_requires_authorization_with_or_without_constructs",
            "a21_authentication_level_single_identity_fixture_signs_exactly_once",
            "a21_local_queries_listed_and_off_with_no_local_exec",
            "home_resolution_matches_ssh_g",
            "doctor_reads_localuser_from_the_account_database",
            "doctor_shows_a_file_outside_the_home_as_written",
            "doctor_lists_config_files_and_include_failures_as_written",
            "home_mismatch_makes_a_home_relative_include_not_fully_readable"
          ]
        }
      }
    },
    "A22": {
      "platform_required": {
        "windows": {
          "integration_projection": [
            "a22_windows_reparse_point_user_config_is_manual_mode",
            "a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode",
            "a22_quarantine_removed_when_empty_and_kept_with_foreign_entries",
            "rendered_file_loads_on_target_client",
            "fresh_writer_creates_absent_ssh_config",
            "fresh_writer_executes_intent_without_preview",
            "a22_foreign_entry_in_quarantine_slot_is_put_back_never_deleted",
            "a22_cleanup_crash_after_quarantine_move_completes_on_retry",
            "a22_first_adoption_commit_point_crash_as_a_process_abort_reconciles"
          ],
          "integration_projection_git": [
            "git_name_transitions_crash_at_every_point_reconciles",
            "git_lock_occupied_by_holder_until_settlement",
            "git_item_not_offered_without_bundled_msys_default",
            "git_spaced_client_path_is_quoted_and_runs",
            "fresh_writer_creates_absent_global_git_config"
          ],
          "integration_projection_recovery_rows": ["recovery_table_rows_each_have_a_test_vector"],
          "integration_projection_replace": ["windows_replace_preserves_dacl", "windows_replace_retains_displaced_identity_without_race"],
          "integration_git_observe": ["git_unreadable_include_makes_item_not_applicable"],
          "e2e_setup_dispatch": ["simultaneous_setup_admissions_admit_exactly_one"]
        },
        "wsl-distro": {
          "wsl_ordinary_ssh": ["a22_rename_exchange_supported_on_the_home_fs", "a22_birth_time_recorded_on_the_home_fs"]
        }
      }
    },
    "A27": {
      "platform_required": {
        "windows": {
          "e2e_run_m02": [
            "a27_windows_cmd_and_bat_targets_get_escaped_args",
            "a27_windows_batch_path_with_percent_bang_caret_refused_127",
            "a27_windows_current_directory_never_searched",
            "a27_windows_spawned_record_is_positive_launch_proof",
            "windows_holder_is_launcher_and_forced_launcher_kill_is_reported",
            "a27_shell_metacharacters_in_argv_reach_child_verbatim",
            "a27_cwd_and_env_preserved_plus_only_documented_additions",
            "a27_meta_file_existing_or_fd_invalid_is_usage_error_before_ensure"
          ],
          "windows_launch": ["ctrlc.event", "ctrlc.keystroke", "resize"]
        }
      }
    },
    "A35": {
      "platform_required": {
        "windows": {
          "e2e_cli_m02": [
            "ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound",
            "ssh::a35_wrong_key_exclusive_selection_fails_without_fallback",
            "ssh::a35_inherited_identity_fallback_agent_backed_reported_not_exclusive",
            "ssh::a35_inherited_identity_fallback_file_backed_reported_not_exclusive",
            "ssh::a35_too_many_keys_succeeds_for_managed_alias_only",
            "ssh::a35_identity_agent_overriding_ssh_auth_sock_is_reported_and_managed_alias_unaffected",
            "ssh::a35_mutation_broken_identity_agent_is_detected"
          ],
          "e2e_run_m02": [
            "a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths",
            "a11::a27_git_clone_and_push_over_ssh_with_binary_blob",
            "a11::a27_binary_stdin_stdout_roundtrip_through_ssh",
            "git_run_resolution_in_child_cwd_reports_local_override_and_injects_nothing",
            "git_run_injection_yields_to_dash_c_and_env",
            "git_run_never_records_child_arguments_or_config_values",
            "git_run_malformed_caller_git_config_count_injects_nothing"
          ],
          "integration_testkit_fixtures": ["many_keys_exhaust_max_auth_tries_without_identities_only"]
        },
        "wsl-distro": {
          "wsl_ordinary_ssh": ["a01_ordinary_ssh_alias_without_f", "a01_ordinary_git_without_f", "a01_ordinary_scp_without_f", "a01_ordinary_sftp_without_f"]
        }
      }
    },
    "R-RT-05": {
      "platform_required": {
        "windows": {
          "integration_projection": [
            "a22_update_crash_after_p_exchange_reconciles",
            "a22_update_crash_between_post_validation_and_commit_reconciles",
            "a22_update_crash_after_commit_before_settlement_settles_never_restores",
            "held_step_moves_nothing_and_reobserves_at_restart",
            "generated::recovery_generated_observations_preserve_every_entry"
          ],
          "integration_projection_recovery_rows": ["recovery_table_rows_each_have_a_test_vector"],
          "model_setup": ["restart_reconciles_attempted_apply_never_reapplies", "restart_reconciles_attempted_apply_never_reapplies_after_a_process_abort"]
        }
      }
    },
    "R-SE-04": {
      "platform_required": {
        "windows": {
          "e2e_cli_m02": ["ssh::host_key_substitution_fails_closed_and_nothing_written_to_known_hosts"],
          "integration_doctor": ["a21_host_verification_offers_nothing_to_sign", "a21_host_verification_requires_authorization_with_or_without_constructs"]
        }
      }
    }
  },
  "exit_claims": {
    "No remote authentication change, key export, or provider-policy bypass was needed": {
      "platform_required": {
        "windows": { "e2e_cli_m02": ["ssh::a01_no_remote_change", "ssh::a01_no_key_export"] }
      }
    }
  },
  "scenario_targets": {
    "wsl_ordinary_ssh": {
      "steps": {
        "a22_birth_time_recorded_on_the_home_fs": "statx(STATX_BTIME) on a file in the disposable home records whether ext4 fills a birth time (m02-plan U4 file_identity_birth_recorded_on_target_fs, WSL ext4)"
      }
    }
  }
}
```

**Not in the fragment, by design:**
* The other ~180 Unix-only tests in `integration_projection`, `integration_projection_git`
  and `model_setup` are handled by R1. When their units ungate them, each test that stays
  Unix-only must gain a rationale entry, or its row stays `in_progress`.
* The new scenario step requires a matching `scenario-ordinary-ssh.sh` step (WU-6).

**After merging:** `refresh-inventory.sh` and `--check-inventory` are needed. With the
fragment applied to ce21a76f, every Windows row except ADR-0006-13.20-3, the
no-unattended claim and T06 reads `in_progress`. A22's WSL row reads `in_progress` until
the birth-time step exists.

## 4. Native-Windows work units

There are seven units. Ownership is disjoint, and every unit runs in its own scratch clone
on the PC, at Medium integrity, with nothing elevated. WU-6 runs on the build host.
* WU-0 lands first.
* WU-2a, WU-2b and WU-3 need no sshd and can start at once, in parallel with WU-0.
* WU-1, WU-4 and WU-5 start after WU-0.
* Units do not commit (AGENTS.md); the orchestrator integrates.

| Unit | Owns (exclusive) | Tests to make run and pass natively | Needs | Size |
|---|---|---|---|---|
| **WU-0** fixture plumbing | `crates/testkit/src/sshd.rs`, a new `crates/testkit/src/win.rs` (DACL helpers: owner-only check, deny-read ACE; current-user `PrincipalRef::WindowsUser`) plus its one `pub mod` line in `crates/testkit/src/lib.rs`, `crates/testkit/src/home.rs` (`User` line from `HM_FIXTURE_SSHD_USER`), `tests/integration/testkit_fixtures.rs`, `tests/native/m02/run-windows-local.ps1`, `tests/native/m02/remote-lib.sh` | G-T1 items 1-4; `integration_testkit_fixtures::fake_agent_round_trip_with_real_ssh_login`, `many_keys_exhaust_max_auth_tries_without_identities_only`; runner self-test cases for the user export, the redaction and the strict sshd | — | M |
| **WU-1** CLI transport | `tests/e2e/cli_m02.rs` (`ssh` module and its helpers) | `ssh::a01_*` (5), `ssh::a35_*` (7), `ssh::host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` | WU-0 | L |
| **WU-2a** projection | `tests/integration/projection.rs` | the ~70 portable tests, DACL variants of the mode-based ones, process-abort on Windows; new `a22_windows_reparse_point_user_config_is_manual_mode`, `a22_quarantine_symlink_wrong_owner_or_mode_is_manual_mode`, `a22_quarantine_removed_when_empty_and_kept_with_foreign_entries`, `rendered_file_loads_on_target_client`; a rationale list for what stays Unix-only (handed to WU-6) | WU-0's `win.rs` (DACL), or a file-local helper until it lands | L |
| **WU-2b** Git projection | `tests/integration/projection_git.rs`, `tests/integration/projection_recovery_rows.rs`, `tests/integration/git_observe.rs` | `git_name_transitions_crash_at_every_point_reconciles`, `git_lock_occupied_by_holder_until_settlement`, `git_item_not_offered_without_bundled_msys_default` (real MSYS), the other portable Git tests, `recovery_table_rows_each_have_a_test_vector`, new `fresh_writer_creates_absent_global_git_config`, new `git_spaced_client_path_is_quoted_and_runs` (the `ls-remote` leg after WU-0), `git_unreadable_include_makes_item_not_applicable` (ACE) | WU-0 for one test | L |
| **WU-3** setup drivers | `tests/model/setup.rs`, `tests/e2e/setup_dispatch.rs` | all 51 and 9: `catalog_*`, `restart_reconciles_*`, decision, consent and held-repair tests; `simultaneous_setup_admissions_admit_exactly_one`, `declaration_changes_between_ensure_and_bind_are_seen_through_the_dispatcher`, `e2e_catalog_then_ensure_bind_carry_pairs_and_selection` | — | M |
| **WU-4** doctor and account | `tests/integration/doctor.rs`, `crates/localenv/src/sys/mod.rs` (`account_name`, Windows module), `crates/localenv/src/doctor.rs` (the `local_user` arm only) | the 18 A21 `platform_required` tests above; G-P1 with its first-step observation of Win32-OpenSSH `%u` | WU-0 | M–L |
| **WU-5** run and connect | `tests/e2e/run_m02.rs` | the `a11::` fresh-eligibility and fallback tests (12), `connect_*`, `a11::a27_binary_stdin_stdout_roundtrip_through_ssh`, `a11::a27_scp_and_sftp_…`, `a11::a27_git_clone_and_push_…` (FakeAgent pipe), `git_run_*` (4), `a27_shell_metacharacters_in_argv_reach_child_verbatim`, `a27_cwd_and_env_preserved_plus_only_documented_additions`, the meta-file half of `a27_meta_file_existing_or_fd_invalid_…` | WU-0 | L |
| **WU-6** evidence guard (build host) | `tests/native/m02/{m02-evidence.py,test_m02_evidence.py,case-index.json,required-inventory.json,scenario-ordinary-ssh.sh}` | R1, R2 and `excluded_on_this_platform` with their regressions; the §3 fragment; the WSL birth-time step; the rationale entries the units hand over; regenerate the inventory at the next exit build | — | M |
| *(WU-7, only if D5 is accepted)* product data | `crates/localenv/src/clients.rs`, `crates/sshconf/src/client.rs` | Windows 9.5p2 rows citing exit-ce21a76f; the existing `bom_and_crlf_acceptance` and corpus tests re-run natively | D5 | S |

**Every Windows unit's verification:**
* `cargo test -p <crate> --test <target>` natively (msvc, `line-tables-only` per
  §12.43 item 2), with the harness environment of `run-windows-local.ps1`;
* the owned binary's full output, with real exit codes;
* `check.sh` on the build host for the integrated tree.

Then the exit build is re-run on all four platforms.

## 5. Decisions for the orchestrator

These are authority or contract questions that the audit does not decide.

* **D1.** Remove the `e2e_cli_m02::ssh::` `platform_only` entry. Its rationale contradicts
  §12.43 item 5. (Recommended.)
* **D2.** On Windows, the `e2e_tui_m02` pty cases (`search_never_probes`,
  `config_commands_authorization_requires_typed_yes`) could be:
  * covered by a ruling that extends §12.32 item 4, since their model twins ran (W:1417,
    W:1448); or
  * given a pseudoconsole driver.
* **D3.** The same choice for `a11_interactive_connect_succeeds_after_provider_approval`
  (pty).
* **D4.** T06's Windows half: the kept quarantine under a DACL and the purge refused
  with exit 6. Either split it into a `json::` test, or rule it.
* **D5.** Add Windows 9.5p2 to `ENCODING_OBSERVATIONS` and `OBSERVED_CLIENTS` from this
  run's observations (G-P2), or keep failing closed and say so in the matrix.
* **D6.** Whether any gapped Windows row is deferred to M04 with a decision, as §12.45
  did, instead of fixed in M02. The audit's view: A35 transport, R-SE-04, A21's `cmd /c`
  canary and job containment, the projection transaction, the Git name transitions and
  §12.28 item 4 are the core of the declared Windows claims.
* **D7.** Developer Mode is on, so the §12.45 file-symlink row is now an S-sized addition
  to WU-2a. Undo the deferral, or keep it?

## 6. Limits of this audit

* **Nothing was executed:** no build, no test, no Windows or WSL access. Every "ran" is a
  log line quoted from the committed artifacts. Every "not on Windows" is the line's
  absence, together with the target's `running N tests` header.
* **The `cfg` gates of the named tests were read directly** at the cited lines. The
  "about 70 of 107 portable" split comes from a body-marker heuristic over test bodies
  (symlink, mode, hardlink, uid, fifo and signal APIs). It does not prove portability:
  shared helpers may hide Unix calls.
* **Windows applicability comes from the committed inventory.** Its Windows scan came from
  the cross-built `windows-gnu` binaries at 1e69263d. The native run was `msvc` at
  ce21a76f. Per `exit-ce21a76f/runs.json`, the `*.rs` sources digest is unchanged between
  the two. The cross-check holds: every target with 0 Windows tests in the log is
  file-gated.
* **Assertions were not reviewed.** For a "covered" row, I did not check that the passing
  test asserts what the plan says, only that it ran and passed.
* **macOS and Linux rows were not audited.**
* **Win32-OpenSSH's `pw_name` form** (G-P1) and the ACL behaviour of `ssh.exe` for the
  file-backed fallback key are stated as needing native observation, not as observed.
* **This is a single self-review.** No independent reviewer checked it.
