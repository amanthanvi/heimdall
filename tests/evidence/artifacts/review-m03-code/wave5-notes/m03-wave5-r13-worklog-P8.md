# P8 worklog, round 13 (ADR-0008 §17.35 items 1-4; W5-G01..G04)
Goal: db family one recovery unit in a quarantine dir (G01); checkpoint TRUNCATE before deletion,
companions -> main -> dir, companion failure keeps complete db (G02); RESIDUALS stuck-release entry
+ ADR residual-ID test (G03); failed/pending retry keeps display record (G04).
Base: ccd22853. Only these four items.
Decisions:
- G01: family moved into `<state>/.hm-purge-<tag>-database` (mkdirat 0700 + openat, checked
  owner-only/this user; Windows `heimdall_ipc::windows::create_dir_owner_only`, pinned). Names kept.
  validate: dir identity, members' manifests, dir holds only members + purge-created files.
  Unit restore: created files removed (identity-checked; else keep), none of the 4 original names
  occupied (an unmoved inspected member at its name is part of the unit), db first, companion
  failure moves the db back in; else whole unit kept, dir + members reported.
- G02: `heimdall_store::Checkpointer` (READ_WRITE, never create): read-write because the validating
  store is SQLITE_OPEN_READ_ONLY + query_only, which cannot write the main file. Opened in the
  quarantine dir through `read_db`'s census; then `wal_empty` (absent or 0 bytes, held fd 0 bytes).
  delete(): refuses if WAL not empty (restore all); trees; companions -> db -> dir; failure ->
  unit restore rule; QuarantineError.restored + report `renamed_back` / `left_in_quarantine`.
- G03: RESIDUALS `uninstall_fence_release_stuck_until_holder_work_ends` (was absent before r13;
  round 12 did not drop it, it was never added); ADR recognition rule in claims.rs tests.
- G04: apply_retries keeps unless outcome == completed && !pending.
Verified reverts (exit 101, restored shasum OK, rerun 0): G01 independent restore; G02 db-first
order; G02 no checkpoint; G02 no empty-log check; G03 renamed residual id; G04 old None => false.
## Audit D1-D5 (§17.35 items 7-8)
- D1/D2: `heimdall_runtime::service::quarantine_leftovers` checked in `Service::start_with` after
  the lock, before `Store::open` (the only production path that creates state.db; doctor, m03,
  issuer CLI paths use open_read_only, which never creates) -> `uninstall_quarantine_present`
  (contract reason, golden, ADR-0006 row). Unit gets a synced record (`heimdall-purge-unit`:
  name, dev, ino per family file) before the first move; `rejoin` uses it (members must be the
  recorded inodes; an original name may hold only its own recorded member; purge-created -shm /
  empty log removed). `Anchors::recover` (units rejoined, trees renamed back, orphans reported);
  `uninstall()` runs `recover_quarantine` first under the lock: RESTORE, no prompt (deletes
  nothing); report `recovered_from_quarantine`; what cannot be restored -> refusal with paths.
- D3: read_db(open, read, then): Checkpointer.probe -> census -> truncate; Checkpointer also sets
  SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE (close-time checkpoint wrote an unconfirmed log otherwise).
- D4: `quarantine_report` lists only existing paths, each described as on disk; neutral message.
- D5 (Windows): created identities kept in Unit.created after pins drop; rejoin never restores
  them. Native test: `purge_sweep::tests::no_purge_created_file_is_restored_or_listed_as_renamed_back`.
