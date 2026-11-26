# M08 W3 scoped re-check, of `git diff 064f812b a8641372` (2026-11-25)

**Independence (stated limit):** the re-checker was a fresh Claude Opus 5.5, the same model family as the implementers. An attempt by a different model family (GPT-6.2 Sol) stopped at once on a usage limit and wrote nothing. This report is the verdict of record. Its logs are in `w3-recheck-logs/`.

**How its items are handled:**
- W3-RC01: the fix report, with the revert proof and both class audits, is archived beside this one as `w3-fix-report.md`.
- W3-RC02: recorded in `docs/user/limitations.md`, under the pre-release-build residual (ruling of 2026-11-25; commit `6c5ee122`, made after the state this re-check read).
- W3-RC03: corrected in `docs/security/unsafe-inventory.md`.

---

# Scoped re-check: Heimdall M08 wave 3's review fixes, at `a8641372` (2026-11-25)

**Range:** `git diff 064f812b a8641372`. That is one commit: 20 files, +705/−81. Every changed file belongs to one of
the six items below. Nothing outside them changed.
**Re-checker:** a fresh Claude Opus 5.5 session. This is the same model family as the implementer and the W3 reviewer.
The release's security review from outside this family stays open (w3.md, "Independence").
**Classification:** ADR-0009 §2.1. A finding blocks only if it has a lasting effect on remote trust, recovery records or
the owner's data, or bypasses consent, **and** its trigger is one Heimdall must withstand.
**Order of work:** I read the code and records first. Only then did I read the implementer's scratch report
(`/tmp/hm-w3/W3-fix-DONE.md`), to check its revert proof and its audit lists.

## Verdict

**All six items are resolved as ruled. No new defect blocks the merge.**
- W3-R01's fix holds. I checked it two ways. Its regression test passes at `a8641372`. I also repeated the revert proof
  myself: it fails with exit 101 at the assertion the implementer reported.
- There are three non-blocking items, W3-RC01 to W3-RC03.
- The fix diff's native runs (`PC-M08-W3fix.md`, `devbox-w3fix.md`) are still pending. Until they run, the Windows halves
  of the W3-R01 test, the W3-R03 test and the rig fixes stay `implemented_unverified`.

| Item | Status | How I checked it |
|---|---|---|
| W3-R01 (blocking): the bridge's downgrade write against the adoption fence | **Resolved**. Its records are W3-RC01; an unrecorded residual is W3-RC02 | Ran the test and a revert proof; read the code |
| W3-R03: a `PlatformFs` switch-fault case, and the job 63 wording | **Resolved as ruled**. The Windows run is pending | Ran on macOS; read the code |
| W3-R04: the interrupted purge layout removal is recorded | **Resolved** | Read only |
| W3-R05: an interrupted install, then a pre-release flat store, is recorded | **Resolved** | Read only |
| W3-R06: the unsafe inventory's text | **Resolved**, with one nit (W3-RC03) | Ran the check; read the doc |
| PC job 65's `TempDir` rig leak, and the audit of its class | **Resolved** by reading. The Windows `.tmp*` counts are pending | Read; my own scan of the rigs |

| New | Severity | Summary |
|---|---|---|
| W3-RC01 | Not blocking (records) | The blocking fix's revert proof and both class audits exist only in the implementer's scratch report, not in the repository |
| W3-RC02 | Not blocking (a residual of W3-R01; needs a ruling) | A pre-release build's bridge can still lose the downgrade during this build's adoption. Nothing records it |
| W3-RC03 | Nit (documentation) | The inventory's `win.rs` row says 5 unit tests, not 6, and the status line names the wrong commit for the correction |

---

## W3-R01: resolved

The ruling, item by item:

1. **The re-read and the write are in one `BEGIN IMMEDIATE` transaction, and the comment states the mode.** Met.
   - `crates/store/src/ext_runner.rs:523-536`. Inside `store.transaction`, `at_this_builds_schema(&tx.tx)?` (`:525`)
     runs before the runner check and the upsert (`:535`).
   - `crates/store/src/lib.rs:618-640`. `Store::transaction` fires `BeforeTransaction` (`:619`). It then begins
     `TransactionBehavior::Immediate` for a writable store (`:625-629`). The bridge builds its store with
     `read_only: false` (`ext_runner.rs:514-518`).
   - The mode is stated at `ext_runner.rs:519-522` and in the function's doc (`:432-446`). The check before the
     transaction (`:504`) is kept, as an early refusal only.
   - I modelled the SQLite behaviour with `python3 -I` and the system SQLite 3.54.1 (`logs/r5-sqlite-model.txt`). This
     shows SQLite's semantics, not Heimdall's code:
     - **A:** a fence committed between the check and `BEGIN IMMEDIATE` is seen inside (`re-read inside 2000000000`).
     - **B:** while the bridge holds the lock, the fence's `BEGIN IMMEDIATE` is refused as busy. Once the bridge
       commits, the fence commits, and the copy made after it holds the bridge's row (`1`).
     The production fence waits up to 5 s for the lock (`layout.rs:570-577`, `open_flat`), so the doc's "a fence that
     starts later waits for this commit" holds.
2. **A fenced or non-current version takes the existing fail-closed marker path.** Met.
   - `at_this_builds_schema` (`ext_runner.rs:542-551`) calls `migrations::check_version` (`migrations.rs:153-175`). A
     fenced family gives `AdoptionFenced`, a newer schema `NewerSchema`, and an older one or an empty file `OlderSchema`.
   - The error leaves the transaction as it is: `codec::reclassify` maps only SQLite errors (`codec.rs:91-96`). It
     passes through `record_owner_only_in_home` (`crates/runtime/src/paired.rs:468-479`) to `refuse_session`
     (`crates/heimdall/src/m06_cmd.rs:5043-5050`). `refuse_session` queues the marker on any error. That path is
     unchanged, and it is the only fallback.
3. **The test.** Met. The link to the marker is shown by composition.
   - The test is `paired.rs:3352`, in the new module `adoption_window_tests` (`:3272`). That module is `#[cfg(test)]`,
     so it runs on every platform.
   - Its hook fires at `BeforeTransaction`, between the bridge's check and its `BEGIN`. There it runs the runtime's own
     start-up open, `state_store::open_locked` over `PlatformFs`: intent, fence, copy, switch and completion.
   - It asserts `Err(AdoptionFenced)` (`:3397`).
   - It asserts that the flat family's database, `-wal` and `-journal` are byte-identical to what the adoption left
     (`:3408`). A reader held open (`:3365`) stops the bridge's close from checkpointing.
   - It applies the marker with `drain_pending`. The served generation then holds `session_pty` at epoch 1, the marker
     is gone, and the runner is `OwnerOnly`, after a restart too. So the owner-only state follows from the marker, as
     ruled.
   - **Composition note (no finding):** the test queues the marker itself (`:3416`), in place of `refuse_session`.
     Two things carry the link from `AdoptionFenced` to the marker: `refuse_session`'s `is_err()` (read), and
     `a_downgrade_the_bridge_cannot_write_is_queued_and_the_next_admission_records_it` (`m06_cmd.rs:5679`, with a busy
     error). Both hold. The implementer disclosed this (DONE, open question 1).
4. **The revert proof.** It exists, and I reproduced it.
   - The implementer's output is pasted in `/tmp/hm-w3/W3-fix-DONE.md`.
   - My run used an untracked `git archive a8641372` copy with only `ext_runner.rs:525` replaced by a comment. The test
     failed with exit 101:
     `panicked at crates/runtime/src/paired.rs:3397:9: the bridge's write was not refused: Ok(RunnerDowngrade { cause: "session_pty", epoch: 1, … })`
     (`logs/r3-revert-proof.txt`).
   - With the fix, in this worktree, it passes with exit 0 (`logs/r1-runtime-a8641372.txt`).
   - I removed the copy afterwards.
5. **The audit of every other writer that skips the instance lock.** The implementer did it (DONE, "The audit of the
   class"). My own check by grep agrees: the bridge is the only writer of the state database without the lock.
   - **Read-write opens in production code, all under the lock:**
     - `layout::open_locked`: the runtime's start (`service.rs:753`) and the M06 direct writers after
       `InstanceLock::try_acquire` (`m06_cmd.rs:1927-1938`, `:3395-3398`, `:4598-4601`);
     - uninstall and the purge;
     - uninstall's `carry_downgrade_forward` (`uninstall_cmd.rs:2482-2489`; the caller holds the lock, `:2440-2441`);
     - the fence, copy and probe connections inside `open_locked` (`layout.rs`).
   - **The bridge** (`ext_runner.rs:495-499`) is the one opener without the lock.
   - **Every other opener is read-only** (`open_read_only` or `open_read_only_no_write`): `doctor`, the CLI's reads, the
     issuer child and uninstall's reads.
   - **Writes outside the store:** the marker writes the log directory, not the store. `locate` and `db_path` use
     `inspect()`, which writes nothing.
   - The audit is not archived in the repository: see W3-RC01.

Observations that need no action:
- **Deferred transactions.** `ext_runner.rs:521-522` explains why a deferred transaction was not used. In WAL mode, a
  deferred read and then upsert across the fence's commit does not land. It fails with `SQLITE_BUSY_SNAPSHOT` (model
  case C: `write refused: database is locked; row in the fenced family: 0`). `IMMEDIATE` is still the better choice,
  because it gives the typed `AdoptionFenced`. Only the wording is affected.
- **The new seam.** `bridge_record_runner_downgrade_with_faults` (`:477`) is `pub` and `#[doc(hidden)]`, like the store's
  existing test seams. Production passes `NoFaults` (`:453-463`).
- **The W4 half.** The pointer re-check against a restore's or a reset's switch was ruled to U2b-3b (w3.md:6). It is
  outside this scope.

## W3-R03: resolved as ruled; the Windows run is pending

- **The new case:** `crates/runtime/src/state_store.rs:226`, through `open_locked_with` (`:115`).
  - It runs 8 cases: {install, adoption} × {`Before`, `After`} × {`Error`, `Dead`}.
  - Each case uses `FaultFs::new(PlatformFs, Fault { point: PointerRename, nth: 0, .. })`, then restarts through
    `open_locked`.
- **How the fault works** (`FaultFs::step`, `crates/stategen/src/fs.rs:347-365`):
  - `After` makes the inner call and then faults;
  - `Before` does not make the call;
  - `Dead` fails every later call, so no cleanup runs.
- **What that exercises on Windows:**
  - The `After` cases run `PlatformFs::rename_over`, which calls `platform::rename_replacing`, which is
    `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (`platform.rs:1257-1262`; `state_store.rs:8-10`).
  - Every restart also calls it on the normal path. The completed intent's rename replaces an existing file.
- **What it asserts:**
  - the fault is reported;
  - the pointer names a generation only when the rename was made;
  - the restart serves only that generation (`Served`), or runs the first publication again (`Installed` or
    `Adopted`);
  - one generation is left, `CURRENT.tmp` is gone, and the intent is complete;
  - the record's operation is right, and an adoption keeps the store's environment.
- **Ran on macOS:** it passes (`logs/r1-runtime-a8641372.txt`). That path is `rename(2)`, so H15 is not exercised
  there. The Windows run is `PC-M08-W3fix.md` step 2, which is pending, and the records say so.
- **The test's stated limit:** the stop is in-process, not a kill or a power cut. Durability across power loss is not
  established.
- **Records corrected:**
  - the job 63 README's step-1 row (`README.md:9`) and its H15 paragraph (`:17-23`);
  - the units doc (`docs/architecture/m08-w3-units.md:236-240`);
  - `open_locked_with`'s doc (`state_store.rs:110-111`). It now has a caller.
- **The paragraph's normal-path claim checks out:** `tests/e2e/store_generations_cli.rs:205` and `:255`, and the
  `uninstall_cmd` tests, open the store through `heimdall_runtime::state_store::open_locked`.
- **No overstatement left:** I grepped `docs/`, `progress.md` and `tests/evidence/` for H15, `MoveFileExW` and
  write-through. No other text claims that H15 ran under a fault.

## W3-R04: resolved (read only)

- The new bullet is `docs/user/limitations.md:44-53`.
- Its list of what to remove by hand matches `LAYOUT_ENTRIES` (`crates/heimdall/src/purge_sweep.rs:117-129`): `CURRENT`,
  `STAGING-INTENT`, `REQUEST-LEDGER`, `generations`, `state.db` with its `-wal`, `-shm` and `-journal`, and the three
  `.tmp` files.
- Its quoted refusal is `uninstall_cmd.rs:2551` and `:2621`.
- **Its claims hold for the whole window.** `inspect()` → `read_record` (`crates/stategen/src/generations.rs:758-781`)
  answers `generation_missing`, `record_missing` or `file_missing` whenever the pointer's generation has lost its
  directory, record or database. Two things follow:
  - `CURRENT` goes last, so a start anywhere in the window is `state_corrupt`.
  - `db_path` fails, so a second `--purge-state` refuses.
- The flat family's logs are removed before `state.db`, so the window never trips the quarantine refusal instead.
- The units doc (`:242-245`) names `purge_layout_removal_interrupted_leaves_state_corrupt` and the U2b-3a recovery. No
  code was added, as ruled.

## W3-R05: resolved (read only)

- The new sentences are `limitations.md:38-43`, under the existing pre-release bullet, as ruled.
- **They match the code:**
  - The start discards the staged leftover and keeps the `Install` intent (`generations.rs:316-334`).
  - `first_publication` probes the flat store and adopts it (`layout.rs:253-268`).
  - `StateDir::adopt` refuses an `Install` intent with `WrongState` (`generations.rs:427-430`).
- **The manual way out holds.** Once `STAGING-INTENT` is removed, there is no pointer and no intent, and the leftover is
  already gone. So `has_generation()` is false, the start is `Empty`, and the flat store is adopted. "Nothing is lost:
  the next start adopts that store" holds.

## W3-R06: resolved, with one nit (W3-RC03)

- I ran the check (`logs/r4-unsafe-inventory.txt`).
  - `python3 -I tools/validation/unsafe_inventory.py --check`: `unsafe-inventory: PASS (19 entries)`, exit 0.
  - `--list`: `total unsafe constructs: 380 in 19 files`.
- Every row's count matches the scan, and the groups add up: 327 production, 36 testkit and 17 test binaries.
- The `platform.rs` row names `MoveFileExW(… REPLACE_EXISTING | WRITE_THROUGH)` and `rename_replacing`
  (`platform.rs:1257`). Its unit-test count is right (6).
- `tools/validation/check.sh:112-114` runs `--check`, as the corrected text says.

## PC job 65's rig leak and the audit of its class: resolved by reading; Windows pending

- **Job 65's own finding, in `tests/integration/request_epoch.rs`:**
  - `Runner::stop` (`:1092-1120`) does this in order:
    1. cancels the stop token;
    2. awaits every session, whose handles `connect` now keeps (`:1237-1240`);
    3. waits, bounded, for `running_operations()`;
    4. drops the runner;
    5. waits, bounded, until the store's last `Arc` is gone.
  - Both Runner tests call it (`:1404`, `:1515`).
  - `Rig`'s `TempDir` is its last field (`:173-178`).
  - `Drop` still cancels when a test fails before the stop.
- **The same class, fixed elsewhere:**
  - `remote_runtime_m06.rs` gains `Rig::stop` (`:232`).
  - `setup_dispatch.rs` gains `Served::stop` (`:258`). I counted every test: each service it starts is stopped.
  - Ten rigs have their `TempDir` field moved last.
  - The reorders cannot change construction. Where a field's drop needed the directory, as with `deadline_m03`'s sshd
    and agent, the directory now outlives it.
- **The audit:**
  - The implementer's list is in DONE.
  - My own heuristic scan looked for a struct with a `TempDir` or `ScratchHome` field declared before a field that holds
    the store, across `tests/` and `crates/`. It found 12. Every one is in the implementer's named-safe list, and each
    checks out:
    - **Unix-only:** `wsl_helper_channel.rs` (`#![cfg(unix)]`), `connections.rs` (`mod unix`), `managed_store.rs`
      (`live_tests`), `tui_m02.rs` (`mod pty`), and `runtime_m03.rs` (`issuer_crash`, `setup_switch`).
    - **The rig's `Drop` cancels and joins the runtime first:** `cli_m02.rs:747`, `cli_m03/enroll.rs:1163`,
      `cli_m03/issuer.rs:563`, `run_m02.rs:3511` and `tui_m03.rs:747`.
    - **In memory:** `projection_recovery_rows.rs:686`.
- **Limit, disclosed by the implementer:** field order is not an await. If a field-order rig's `Operations` still runs a
  task when the rig drops, it could still leak on Windows. The PC job's before-and-after `.tmp*` counts (step 3) are the
  proof. I did not run these integration targets, because they start a real `Service`.

---

## New findings

### W3-RC01 (not blocking: records). The blocking fix's revert proof and both class audits exist only in scratch

- **What:** three pieces of evidence are only in `/tmp/hm-w3/W3-fix-DONE.md`:
  - W3-R01's revert proof;
  - the audit of the writers that skip the lock;
  - the `TempDir` rig audit.
- **Why it matters:**
  - ADR-0009 §2.3 requires a revert proof for a fix that blocks a merge.
  - AGENTS.md's evidence discipline and ADR-0009 §2.5 keep evidence and reviews in the repository.
  - The fix diff records none of the three: a grep of it finds no "revert" or "audit".
- **Scenario:** `/tmp` is cleared after the merge. At the M09 release audit, the W3 record no longer shows that W3-R01's
  ruled conditions (a revert proof, an audited class) were met.
- **Why it does not block:** it has no effect on remote trust, recovery records or the owner's data. The candidate's
  planned evidence commit can carry it (units doc: "plus the documentation and evidence commits").
- **Fix:** archive these with the W3 records:
  - the implementer's revert-proof output, and this re-check's (`logs/r3-revert-proof.txt`, exit 101; and
    `logs/r1-runtime-a8641372.txt`, exit 0);
  - the two audit lists;
  - this report.

### W3-RC02 (not blocking: a residual of W3-R01, unrecorded; for the lead's ruling). A pre-release build's bridge can still lose the downgrade write

- **What:** the fix closes the window only for this build's bridge.
  - Every build without the fix checks the schema before its transaction. That includes every pre-release build, and
    this wave's own builds before `a8641372`: at `064f812b`, the check is `ext_runner.rs:461` and the transaction
    begins at `:482`.
  - Such a bridge loses its write in the same way, if it is the binary the forced command runs while this build's first
    start adopts the home.
  - The forced command names an absolute binary path (`crates/remote/src/line.rs:5`, `:145-148`). An earlier binary at
    another path therefore keeps answering sessions until the management line is rewritten.
- **Failing scenario:**
  1. A runner home was made by a pre-generation build at path P. The management line names P.
  2. The owner installs this release at another path and starts its runtime, which adopts the home.
  3. During the fence and copy, a session under a paired client's key arrives with a pty.
  4. P's bridge checks the schema before the fence. Its `BEGIN IMMEDIATE` transaction comes after the copy, and its
     write lands in the fenced residue.
  5. The write succeeds, so no marker is written.
  6. The served generation lacks the row, and the runner keeps serving limited clients. This is W3-R01's outcome.
- **Evidence:** reading (the removed lines, and `line.rs`). The SQLite interleaving is the one the W3 review's model
  showed. The implementer raised this as DONE's open question 4. Nothing records it: I grepped `limitations.md` and the
  units doc.
- **Why it does not block:**
  - The defective code is in a pre-release binary the candidate cannot change.
  - The precondition is outside the supported set that the pre-release limitation already scopes out (ADR-0014 §3.2
    item 8): a pre-release binary still answering as the forced command after this release adopts the home.
  - §2.1 (a) does hold, so it needs recording or mitigation.
- **Options:**
  1. Extend the pre-release bullet: point the management line at this release's binary, or stop it from accepting
     sessions, before the first start.
  2. A candidate-side mitigation, for example in U2b-4's residue work: after the switch, compare the fenced residue's
     `runner_owner_only` row and epoch with the served generation's, and carry a newer one forward, set-only, as
     `carry_runner_downgrade` does.

### W3-RC03 (nit: documentation). Two leftovers in the corrected inventory text

- **The `win.rs` row's test count** (`docs/security/unsafe-inventory.md:48`) still says "5 unit tests (native Windows)".
  The file has 6. M07 W9e (`d3d7afde`) added `a_pipes_server_and_a_processes_creation_time`
  (`crates/testkit/src/win.rs:560-561`). That is the same change the corrected reason column now names. The
  `platform.rs` row was corrected from 5 to 6.
- **The status line** (`:5-6`) says the text "were corrected at `064f812b`". The correction is in `a8641372`. `064f812b`
  is the commit whose scan the counts are, and that scan is identical at `a8641372` (380 in 19 files). Suggested
  wording: "corrected in the W3 review fixes, to the scan at `064f812b`".
- **Why it does not block:** it is informational text. The check compares only the set of modules.

---

## What I ran, and what I read

**Ran:**
- **Setup:** at `a8641372`, on macOS arm64, through `/tmp/hm-tools/heavy-gate.sh` with `CARGO_BUILD_JOBS=4`.
  - `TMPDIR`, `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME` and the three fixture-store variables were set to scratch, and
    `SSH_AUTH_SOCK` was unset.
  - Only unit tests ran, with no `heimdall` binary and no key store.
- **Results:**
  1. `cargo test --locked -p heimdall-runtime --lib -- paired::adoption_window_tests state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`:
     exit 0, 2 passed, 0 failed.
  2. `cargo test --locked -p heimdall-store --lib ext_runner`: exit 0, 6 passed, 0 failed. These are the bridge's own
     tests, including the busy and set-only cases.
  3. The revert proof, as in W3-R01 item 4: exit 101, 1 failed at `paired.rs:3397`.
  4. `unsafe_inventory.py --check` and `--list`: PASS (19 entries); 380 constructs.
  5. The SQLite model (`python3 -I`). It shows SQLite's semantics, not Heimdall's code.
- **Afterwards:** this worktree's `git status --porcelain` was empty before and after, and the scratch `TMPDIR` held 0
  entries afterwards.
- **Logs:** redacted outputs are in `/tmp/hm-w3/w3-recheck/logs/`.

**By reading only:**
- the Windows behaviour of the W3-R03 case;
- the accuracy of W3-R04's and W3-R05's text;
- every rig change and the rig audit;
- the audit of the writers that skip the lock;
- W3-RC02.

**Not run:**
- any Windows or devbox run (both are pending);
- the changed integration and e2e rigs, which start a real `Service`;
- `check.sh`, which the brief excludes.

## Limits

- **Same model family:** see the top of this report.
- **Windows:** every Windows conclusion above rests on the pending PC job:
  - H15 under a fault;
  - the W3-R01 test over `PlatformFs` on NTFS;
  - the rigs' `.tmp*` counts.

## Cleanup

Removed by exact path, and confirmed gone:
- the revert-proof source copy, with its build;
- my scratch, script and output directories under `/tmp`;
- the `target/` directory my runs created in this worktree, which had none before.

No process was left running. No tracked file was edited, and nothing was committed or pushed.
