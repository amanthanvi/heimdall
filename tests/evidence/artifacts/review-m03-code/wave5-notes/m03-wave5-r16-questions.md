# M03 wave 5, round 16 — questions for the orchestrator

## Integrator (I)
- Note (no ruling needed): on Windows, item 2's re-check is unreachable by a writer while the copy is held, so its only regression runs on Unix; and `rename_held_no_replace` does not add `\\?\UNC\` to a UNC full path; if the rename then fails, it fails closed (the restore fails and the unit is kept). Not run natively.
## P10
- Q-P10-R16-1 (for §17.39's text): a new safe wrapper `heimdall_ipc::windows::rename_held_no_replace` (ReOpenFile DELETE + SetFileInformationByHandle(FileRenameInfo, ReplaceIfExists=false)) sits in `crates/ipc/src/windows.rs`, an overview §9 module. Recommendation: accept it in §17.39 as §17.34 item 5 did for `file_id`; overview §9 not edited.
- Q-P10-R16-2: the residual `purge_recovery_copy_overwritten_between_check_and_unlink` uses platform `any` (the overwrite window is Unix; on Windows the hold shares delete, so a rename/deletion of the copy, not an alteration, is still possible on both). Recommendation: keep `any`; the description says which part is Unix.
