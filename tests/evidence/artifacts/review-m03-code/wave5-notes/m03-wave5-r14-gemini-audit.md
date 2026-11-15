# M03 wave 5, round 14 — independent audit of item 1 (Gemini)

Model family per ADR-0008 §17.36 item 2: Google Gemini (`gemini-4-hydrogen-xhigh`, via the T3 `antigravity`
provider), neither Codex nor Claude. Read-only; no files modified. Two passes. The integrator transcribed
these summaries from the delegate's two reports; the full reports are in the T3 delegated threads.

## Pass 1 — correctness review of the purge's database handling (§17.36 item 1)
- **E1 (high; ordinary crash or I/O error):** `Unit::delete` removed `-wal`/`-shm` before the original
  `state.db`. A failure or crash at that unlink left the original without its WAL, and recovery's
  confirmation (`restored_is_original`) then compared the restored copy against the incomplete original,
  failed, and left the unit for ever (start-up and uninstall blocked).
- **E2 (medium; crash):** a crash during `VACUUM INTO` left `heimdall-recovery-copy.db.part-journal`, which
  `recover_unit` did not recognise, so recovery stopped.
- **E3 (medium; ordinary state):** `Store::open_read_only` (plain path, `SQLITE_OPEN_READ_ONLY`) still let
  SQLite write the original's `-shm` (WAL-index recovery) when it was absent, empty or stale. Database and
  `-wal` bytes were unchanged.
- Judged hostile-same-user only: a `-wal` placed at `state.db-wal` between `restore_copy`'s check and its
  rename.
- Confirmed from the bundled SQLite 3.54.1 source: `VACUUM INTO` on a read-only main opens only a read
  transaction on main; a read-only pager facing a hot journal returns `SQLITE_READONLY_ROLLBACK`.
- Checked and correct: the `-journal` refusals, read-only validation with its census, the copy's creation,
  fsync and no-replace rename, the deletion order, the start-up guard, Windows parity apart from E1–E3.
  Ran `purge_sweep::` (28 passed) and `uninstall_cmd::` (59 passed).

## Pass 2 — scoped re-check of the E1–E3 fixes (reading only; no cargo)
- **E1, E2, E3: closed on every path**, including a crash during or after writing the `heimdall-purge-deleting`
  marker and between the original unlinks; recovery removes all four `.part` files by exact name;
  `open_read_only_no_write` (`mode=ro&readonly_shm=1`) writes no family file, and the scratch-copy read
  (database and `-wal` copied under the held lock) sees WAL-only commits.
- **F1 (low; ordinary refusal or error):** after a Unix refusal (or on Windows if the marker cannot be
  created), the purge-created empty `-shm` stays inside the kept quarantine unit until the next recovery
  removes it. Fails closed; no lasting effect.
- **F2 (low; crash):** `read_family_no_write` checks only for `-shm`; a `-shm` present without a `-wal` makes
  the no-write open fail (`SQLITE_CANTOPEN`), so the read refuses instead of using the scratch copy. Fails
  closed; no lasting effect.
