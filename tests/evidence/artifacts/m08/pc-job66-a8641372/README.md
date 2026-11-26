# PC job 66: the W3 review fixes on native Windows, at `a8641372` (2026-11-25)

Job file: the M08 lead's `PC-M08-W3fix.md`, under the root `hm-m08-w3fixpc`. It ran with the
default `TEMP`, at BelowNormal priority, with scratch toolchain homes and
`CARGO_BUILD_JOBS=4`, not elevated, and took 12.7 minutes. The outputs here are redacted.

| Step | Target | Result |
|---|---|---|
| 1 (W3-R01) | `paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker` | exit 0, 1 passed, on NTFS |
| 2 (W3-R03) | `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation` | exit 0, 1 passed (8 cases). **H15's first native run under a fault** (`MoveFileExW` with `REPLACE_EXISTING` and `WRITE_THROUGH`) |
| 3 | The 12 rig targets changed for the `TempDir` leak (`s3-tmp-counts.txt`) | 10 exit 0, with `.tmp*` after equal to before (607). Two exited 101 on a missing prerequisite (below). `integration_managed_adapter` still leaks (below) |

**Step 3 in detail:**
- **Exit 0 and no leak:**
  - `integration_request_epoch` (10 tests); PC job 65's leak is fixed on Windows;
  - `integration_remote_runtime_m06` (14), `e2e_setup_dispatch` (9), `managed_store::tests` (4);
  - `model_setup` (52), `model_timegate` (27), `e2e_managed_m03` (18);
  - `integration_issuer_child` (25), `integration_issuer_remote_m06` (10).
- **Not run in job 66, for lack of a harness prerequisite (`blocked` here, and not a regression):**
  - `e2e_deadline_m03`: its nine `windows::*` tests stop at `deadline_m03.rs:212`, because the
    harness fixture sshd (`HM_FIXTURE_SSHD_*`) is missing. They are covered by the next full m02
    Windows harness run, at the W4 candidate at the latest.
  - `e2e_tui_m02`: its two `console::*` tests stop at `tui_m02.rs:2001`, because
    `hm-fixture-hook` was not built. Job 66b reruns them with the hook built and a `.tmp*` count.
- **Residual: `integration_managed_adapter` leaks on Windows.** It exited 0 with 52 tests
  passing, but the `.tmp*` count went from 607 to 622. The 15 new directories each hold
  `state` and `store` and were created during the run. Moving `World.dir` last did not stop
  it, so something else still holds those files when the directory drops. Under the ruling of
  2026-11-25 this is test-only, does not block (ADR-0009 §2.1) and is W4's first item. The PC
  agent removed the 15 directories by exact path.

The PC agent's first try at step 3 failed in its own launcher, a PowerShell variable-name
collision, before any cargo command ran. It reran step 3 only.

Credential Manager: 173 before and 173 after, with no Heimdall entries. DWM: 281 to 293 MB. Drive
C: 259.8 to 238.1 GB free. No firewall prompt, no leftover processes, and
`%LOCALAPPDATA%\Heimdall` is absent.
