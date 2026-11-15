# M03 wave 5 round 14 — integrator worklog

Base `092a4671`. Binding ADR-0008 §17.36; re-check6 W5-H01, H02; devbox native run at b5f0a715: 3 Linux-only test defects (user-private-group host). No commits. Keep the Windows target warm.
- [x] P8 (item 1 + the 3 Linux test defects) done.
- [x] Gemini audit (2 passes) done: E1-E3 fixed; F1, F2 low, reported.
- [x] Validation: run 1 check.sh overall 1 (fmt only: P8 files unformatted; every other step 0), linux-xcheck 0, umask 002 all 0 (cli_m03 69p/3i, tui_m03 5p/1i, tui_m02 17p/1i, enroll 99p, ceremony 8p/2i, managed 16p, bin 245p); cargo fmt; run 2 check.sh every step 0 (3096/0/192), linux-xcheck 0. Archived.
- §17.36 item 2: audit must be a different model family (not Codex/OpenAI, not Claude). orchestrator_capabilities offers antigravity (gemini-4-hydrogen-xhigh/high, gemini-4-argon-*) and grok (grok-4.7). Plan: antigravity gemini-4-hydrogen-xhigh via delegate_task (role review, shared checkout, read-only brief).
- Windows native failure (testcfg::tests::purge_trusted_top_is_refused_in_a_release_build, '/abs' not absolute on Windows): integrator fixed the test with a platform-absolute ABS (C:bs on Windows), asserting is_absolute; product refusal unchanged. Passes on macOS; the old literal's failure can't be shown off Windows (Path::is_absolute('/abs') is true on Unix) -> named for the next native Windows run (heimdall-unit testcfg::tests::purge_trusted_top_is_refused_in_a_release_build).
- P8 finished (report lost; run set /tmp/p8-r14.log all 0, ALLDONE per orchestrator). Decisions in
  .m03-wave5-r14-worklog-P8.md. Q-P8-R14-1/2 ANSWERED. Integrator reviewing the diff now.
- Integrator diff review (item 1): matches §17.36 — store vacuum_into only on a read-only store
  (SQLITE_OPEN_READONLY main; query_only lifted for the one statement); Checkpointer removed + ADR-0006
  row; hold() refuses a -journal and re-checks it in the unit before the RO open; restore_copy = all four
  family names free, then ONE renameat_with(NOREPLACE) of the copy to state.db, fsync; Unit::delete order
  companions, original db, copy, record, dir; any failure before the copy is gone restores the copy.
  Observation for the audit: restore_copy is check-then-rename; a -wal planted at <state>/state.db-wal in
  between would attach to the copy (needs a same-user actor; nothing legitimate writes there under the lock).
- Testcfg Windows fix also in this diff (crates/heimdall/src/testcfg.rs, integrator).
- Audit started on Gemini (antigravity gemini-4-hydrogen-xhigh), read-only, shared checkout: [Correctness review: uninstall purge database handling (round 14)]. Validation runs in parallel (auditor doesn't edit).
- Gemini audit (read-only, no files modified): E1 HIGH (ordinary crash/error): Unit::delete removes
  -wal/-shm first; a failure deleting the original state.db leaves it without its WAL, and
  recover_unit's confirm (restored_is_original) compares the restored copy (with the WAL's commits)
  against that incomplete original -> false -> unit left forever, start-up and uninstall blocked. E2
  MEDIUM: a crash mid-VACUUM INTO leaves heimdall-recovery-copy.db.part-journal; recover_unit removes
  only .part and refuses any other entry -> wedge. E3 MEDIUM: Store::open_read_only (plain path,
  SQLITE_OPEN_READ_ONLY) opens -wal/-shm read-write and writes/extends -shm via WAL-index recovery when
  -shm is absent, empty (incl. the one hold() creates) or stale -> contradicts "SQLite never writes to the
  original family" (db and -wal bytes unchanged). restore_copy -wal window judged hostile-same-user only;
  VACUUM INTO on RO main and RO hot-journal behaviour confirmed from the bundled SQLite 3.54.1 source.
- Stopped the in-flight validation (P8 will edit); no survivors. P8 resumed for E1-E3.
- P8 E1-E3 done (run set /tmp/p8-r14b.log all 0). Integrator review:
  * E3: read_family_no_write (uninstall_cmd.rs:2215) reads in place with mode=ro&readonly_shm=1 when
    -shm exists; otherwise copies db + -wal to an owner-only temp scratch dir, reads the copy (SQLite
    rebuilds the index from the copied -wal, so a WAL-only commit is seen), removes the scratch. The
    regression final_review_validating_read_writes_no_family_file asserts "the WAL-only commit is not
    seen" for each -shm case and whole-byte equality of every family file.
  * hold()'s empty -shm: held with created=true; Unit::delete unlinks all family names; a refusal keeps
    the unit (with the created -shm) in quarantine by design, and recover_unit removes unrecorded -shm /
    empty logs (purge_sweep.rs ~1823-1831); restore_copy never moves it (copy alone). OK.
  * Material enough (marker file, part-file cleanup, new open mode, scratch read) -> scoped Gemini re-check.
- Gemini scoped re-check of E1-E3 (read-only, no cargo): E1, E2, E3 CLOSED on every path (incl. crash
  during/after the marker). F1 low: a purge-created empty -shm stays inside a kept unit after a Unix
  refusal (and on Windows if marker creation fails) until the next recovery removes it (unrecorded
  -shm). F2 low: read_family_no_write checks only -shm; -shm present without -wal -> no_write open
  CANTOPEN -> a refusal instead of the scratch fallback. Both fail closed, no lasting effect -> reported
  for the orchestrator (recommend: F2 small fix next round, F1 record); not changed now, so the running
  validation stays valid.
