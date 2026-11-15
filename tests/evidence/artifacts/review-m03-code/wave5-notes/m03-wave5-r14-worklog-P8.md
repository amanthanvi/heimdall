# P8 worklog, round 14 (ADR-0008 §17.36 item 1; W5-H01, H02; Linux test defects)
Base b5f0a715 / 092a4671. Only these items.
Decisions:
- No read-write open of the original family. `-journal` refused at inspection (nothing moved,
  InvalidData -> JOURNAL_REFUSED), in hold(), and re-checked just before the read-only open.
- Read-only final read + census; then `copy` (Store::vacuum_into: SQLITE_OPEN_READONLY main,
  query_only lifted for the one statement; checked by scratch test + store test) into an
  O_EXCL `heimdall-recovery-copy.db.part`, identity/size checked, fsynced, renamed no-replace to
  `heimdall-recovery-copy.db`, dir fsynced. Checkpointer removed (+ ADR-0006 row).
- Restore = the copy alone, one no-replace rename (names free first); original family kept ->
  PurgeEnd::Kept(inner, kept) -> report `kept_in_quarantine`. Before a copy exists, the family stays
  whole in quarantine (Stuck).
- Delete: refuse without a copy; trees; companions, original db, copy, record, dir; failure ->
  restore copy or keep it (reported with its exact path).
- recover_quarantine/Anchors::recover(ops): remove .part; move recorded members left at their names
  into the unit; remove purge-made -shm/empty logs; no copy -> make one (hold + RO census +
  VACUUM INTO); restore copy; confirm = restored opens RO and `same_as` the original family read
  RO; then delete originals. Start-up refuses any `.hm-purge-*` (unchanged).
- SQLite: read-only pager with a hot journal -> SQLITE_READONLY_ROLLBACK (rescode docs; pager.c
  pagerSharedLock); shown by heimdall-store test with a real hot journal (RW control replays).
- Item 2: `GroupOracle` injected into open_chain; tests run against shared and private hosts.
Verified reverts (101 / restored / rerun ok): H01 replacing rename; H02 RW open + no recheck;
crash copy-written (no copy in recovery); crash before copy deleted (copy not restored);
delete without copy; planted journal (no inspection check); group oracle ignored.
## Audit E1-E3 (Gemini)
- E1: Unit::delete writes+fsyncs `heimdall-purge-deleting` before the first original unlink
  (Unix + Windows); recovery with the mark finishes deleting originals, restores the copy if no
  db is live, never runs confirm. Regression: fail and crash at -wal, -shm, state.db unlinks.
- E2: recovery removes `.part`, `.part-journal`, `.part-wal`, `.part-shm` (exact names).
- E3: `Store::open_read_only_no_write` (URI `mode=ro&readonly_shm=1`; scratch-probed with SQLite
  3.54.1, same as the bundled one: empty/stale -shm -> heap WAL index, WAL commit read, bytes
  unchanged; absent -shm -> CANTOPEN). Uninstall's family reads (Inventory::read, digest, counts,
  final read, recovery open) use it in place when -shm exists, else read a copy in an owner-only
  temp scratch dir. hold() still creates an empty -shm (purge-owned, removed) so the in-place
  final read can open read-only. Other callers (doctor, m03, issuer) keep open_read_only.
- RESIDUALS `purge_restore_copy_log_placed_between_check_and_rename` (hostile same-user).
Verified reverts (101 / restored / rerun ok): E1 no mark; E2 only .part; E3 plain RO open.
