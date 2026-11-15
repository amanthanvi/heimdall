# P8 worklog, round 12 (ADR-0008 §17.34 items 1-2)
Goal: quarantine-then-validate deletion (W5-F01, F02); user-private-group homes (W5-F03).
Decisions:
- purge_sweep: Anchors::quarantine (inspect manifests of every target -> between -> renameat to
  .hm-purge-<32hex>-<name> -> re-manifest + absent targets still absent -> db fd held) -> Quarantine::{open_db, validate,
  delete, restore}. Restore failures reported (Stuck). One random tag per quarantine, so
  -wal/-shm sit beside the quarantined db and SQLite reads the db's own log.
- Final read (changed: the immutable /dev/fd read refused a live non-empty WAL, M02 purge e2e
  failed): Unix opens <anchored dir's current path (F_GETPATH / /proc/self/fd link)>/<qname>,
  confirmed by this process's descriptor count of the quarantined inode before/after (+1).
  One store for read + bundle digest. Windows: quarantine path, file + chain pinned.
  Read-created -wal/-shm (quarantine names, never moved entries) unlinked on delete and restore.
- Windows file ID via new safe wrapper `heimdall_ipc::windows::file_id` (§9 module ipc/windows.rs).
- UPG: `heimdall_runtime::platform::user_private_group` (getpwuid_r/getgrgid_r, §9 module
  runtime/src/platform.rs); pure `check_chain(.., PrivateGroup)`; refusal names dir + chmod g-w.
- RESIDUALS: removed uninstall_state_swapped_and_restored_during_final_read; rewrote the Windows one.
Verified: reverts F01 (read by inspected path, no count), F02 (identity name; leaf + swap-between),
restore-unreported, F03 (no UPG match) each exit 101, restored shasum OK, rerun 0.
Clippy-windows initially failed (UnlinkHook alias unused on Windows) -> cfg(unix); rerun host+win clippy 0.
Runs: SWEEP 19 ok, UNIT 47 ok, E2E03 69/3 ignored, M02 uninstall 8 ok, DOMAIN ok, CLAIMS 0, XCHECK 0, Cargo.lock diff empty.
## Audit C0-C4 (same round)
- C0: Quarantine holds db/-wal/-shm (moved: fstat == manifest id; absent: O_CREAT|O_EXCL created);
  -journal at qname must be the moved one. `Quarantine::read_db(open, read)`: census via new
  `heimdall_runtime::platform::regular_file_descriptors` (fstat on fd numbers, no open/close so no
  POSIX lock release) before open and after read, before drop(store): each held inode +1, qnames
  still name held inodes; validate() re-checks held. Census is per held inode, not "only these
  three new fds": a process-wide exclusivity check is perturbed by other threads (parallel tests).
  Windows: three pinned (no share-delete) through read + validate.
- C1: delete order trees -> db, -wal, -shm, -journal; on failure rename back rest (+ failed single
  file), report remaining qnames; PurgeEnd::Purged(Err(QuarantineError)) -> QUARANTINE_PARTIAL with
  left_in_quarantine.
- C2: Windows remove_tree keeps each dir pinned while listing/emptying, file-ID check vs manifest.
- C3: renameat_with NOREPLACE (both directions); Windows `heimdall_ipc::windows::move_no_replace`.
- C4: module docs; new RESIDUALS `purge_entry_placed_in_quarantine_is_deleted` (any) after the
  Windows entry; Windows entry rewritten.
Verified: reverts (census db-only; hold db-only; no fstat compare; no rename-back; replacing
rename) each exit 101, restored shasum OK, rerun 0.
