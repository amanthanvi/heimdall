# PC job 63 (and 63b): U2b-1 on Windows at `a9b038a7` (2026-11-25)

The job file is `PC-M08-U2b1.md`, run verbatim. The orchestrator added two rules: no
`--ignored` (so the WSL rows stay unrun), and DWM and Credential Manager counts before and after.
The outputs are under `logs/`, redacted by the orchestrator.

| Step | Result at `a9b038a7` | Verified on Windows? |
|---|---|---|
| 1. `adversarial_store_generations` | 6 passed, 0 failed: the switch set, the pointer, adoption, the write-ahead-log copy and the guard. ⟨Corrected 2026-11-25, review W3-R03⟩ These cases run over `RealFs` and `FaultFs<RealFs>` (`std::fs::rename`, then a flush), not over the production `PlatformFs`, so the switch set did not exercise H15's `MoveFileExW` write-through rename | yes |
| 1. `heimdall-stategen` (unit and fault set) | 30 passed, 0 failed | yes |
| 2. `e2e_store_generations` | 2 passed, 0 failed, including **`windows_generation_directory_not_owner_only_is_refused`** on its first run | yes |
| 2. `uninstall_cmd::tests` | **Failed under the inherited TEMP ACL** (63 passed, 4 failed: `state_dir_unsafe`). The tests' `state_dir()` helper made the state directory with `create_dir`, which inherits TEMP's ACL, and this PC's TEMP grants a local group read access; the runtime's refusal was correct. **Job 63b,** with TEMP in an owner-only, protected directory: **67 passed, 0 failed** | **not yet.** The helper fix (`Paths::ensure` on Windows) is verified only by the targeted rerun with the default TEMP at the fix commit, in U1b's PC job |
| 3. `integration_runtime -- windows_fresh_state_dir_is_created_protected_and_passes_the_start_check` | 1 passed | yes |
| 3. `e2e_platform_m04` | 10 passed, 0 failed, 19 ignored (the WSL rows) | yes |
| 3. The M06 Windows targets | 3 passed, 0 failed; 5 passed, 0 failed, 2 ignored | yes |

**H15 (corrected 2026-11-25, review W3-R03):** H15 exercised on the normal path in job 63;
under a fault by
`state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`
(`heimdall-runtime`'s unit tests), in the fix-diff PC run (pending). The normal path here
is step 2: `e2e_store_generations`'s Windows test, and `uninstall_cmd::tests` in job 63b,
open the store through `heimdall_runtime::state_store::open_locked`, so they publish through
`PlatformFs`.

**The owner's state:** Credential Manager held 173 items before and after, none of them
Heimdall's. DWM was at 184 MB both times. The PC root was removed.
