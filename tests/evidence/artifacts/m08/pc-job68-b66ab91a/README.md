# PC job 68: SEC-2 on native Windows, at `b66ab91a` (2026-11-26)

**How it ran:**
- **Job file:** `PC-M08-SEC2.md`, root `hm-m08-sec2pc`.
- **Machine settings:** BelowNormal priority, scratch toolchain homes, `CARGO_BUILD_JOBS=4`, not
  elevated. The outputs here are redacted.
- **Network:** no network share or mapped drive was created or used. The UNC rows assert that
  no filesystem call is made.

| Row | TEMP | Result |
|---|---|---|
| `fs::tests::windows_passive_unc_paths_are_refused_before_filesystem_access` (S4-03) | default | 1 passed |
| `fs::tests::windows_remote_path_classifier_checks_only_drive_letters` (S4-03) | default | 1 passed |
| `include::tests::remote_include_patterns_do_not_call_the_filesystem` (S4-03) | default | 1 passed |
| `remote_git_worktree_pointers_are_not_canonicalized` (S4-03) | default | 1 passed |
| `clients::tests::windows_inbox_ssh_selection_ignores_redirected_system_root` (S4-05) | default | 1 passed |
| `spawn::tests::windows_inbox_programs_ignore_redirected_system_root` (S4-05) | default | 1 passed |
| `state_store::tests::served_state_files_require_owner_only_before_open` (S4-04) | owner-only (`D:PAI`, one owner ACE) | 1 passed |
| `state_store::tests::windows_widened_state_db_dacl_is_refused_before_sqlite_open` (S4-04) | owner-only | 1 passed: a `state.db` with a widened DACL is refused before SQLite opens it |

**Exit codes and TEMP leftovers:**
- Every row exited 0.
- Default TEMP: no new directory, `.tmp*` or `hm-*` entry. Only the host's own short-lived
  GUID-named `.tmp` files appeared, as in job 67.
- Owner-only TEMP: 0 entries before, 0 after.

**The machine:**
- Credential Manager: 173 entries before and after, none of them Heimdall's.
- DWM: 292 MB before, 299 MB after.
- Another interactive application was running, and the job's process tree was idled.
- No firewall prompt appeared.
