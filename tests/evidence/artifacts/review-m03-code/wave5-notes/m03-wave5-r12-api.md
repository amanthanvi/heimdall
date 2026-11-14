# M03 wave 5, round 12 — ownership (integrator)

Base `2903b0e6`. Binding ADR-0008 §17.34; re-check `review-m03-code/wave5-recheck4.md`.

| Worker | Item | Owner files |
|---|---|---|
| **P8** | 1 (W5-F01, F02): quarantine-then-validate; 2 (W5-F03): user-private-group homes | `crates/heimdall/src/{purge_sweep.rs,uninstall_cmd.rs}`, the group lookup in an overview §9 `unsafe`-allowed module (name it), `crates/domain/src/claims.rs` (`RESIDUALS`), tests |
| **K4** | 3 (W5-F04): the `kill_on_drop` residual | `crates/domain/src/claims.rs` (`RESIDUALS`, append one entry; coordinate with P8 under Requests), `crates/issuer/src/client.rs` tests, `tests/integration/issuer_child.rs` |

## Requests
- **P8 → K4 (`crates/domain/src/claims.rs` `RESIDUALS`):** P8 removed the entry
  `uninstall_state_swapped_and_restored_during_final_read` and rewrote the description of
  `windows_purge_entry_replaced_between_check_and_delete`; append yours after the last entry.
- **P8 → integrator:** two additive safe wrappers in §9 modules: `heimdall_ipc::windows::file_id`
  (`crates/ipc/src/windows.rs`, `GetFileInformationByHandle`) and
  `heimdall_runtime::platform::user_private_group` (`crates/runtime/src/platform.rs`,
  `getpwuid_r`/`getgrgid_r`). No new crate; Cargo.lock unchanged. Audit C0/C3 added two more:
  `heimdall_runtime::platform::regular_file_descriptors` (`fstat` on descriptor numbers) and
  `heimdall_ipc::windows::move_no_replace` (`MoveFileExW`, flags 0).
- **P8 → K4 (`RESIDUALS`):** P8 inserted `purge_entry_placed_in_quarantine_is_deleted` right after
  the Windows purge entry (not at the end); your entry is untouched.
- **K4 → P8 (`crates/domain/src/claims.rs`):** K4 appended one `Residual` at the end of `RESIDUALS`
  (`issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child`); nothing else in the file was touched.
## Worker sections
### P8
Round 12: `purge_sweep.rs` quarantine flow (`Anchors::quarantine`, `Quarantine::{open_db, validate,
delete, restore}`), `uninstall_cmd.rs` purge_locked reads the quarantined db and reports
`left_in_quarantine`; `check_chain(.., PrivateGroup)` with the UPG lookup in runtime::platform.
### K4
- Landed (W5-F04): `RESIDUALS` entry `issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child`
  (FailClosedOnly, §17.34 item 3) with its probe `issuer::recheck4_cancelling_stop_must_not_signal_unverified_child`
  (`-p heimdall --test e2e_cli_m03`, `tests/e2e/cli_m03/issuer.rs`). No code change.
