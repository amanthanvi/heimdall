# M08 W3 review fixes: the implementer's report (archived for W3-RC01)

This is the fix worker's report for `a8641372`. It holds W3-R01's revert proof, the audit of lock-exempt writers, and the audit of test rigs that delete a `TempDir` before the store.

---

# DONE: M08 W3 review fixes (Heimdall); uncommitted in this worktree, base `064f812b`

Nothing is committed or pushed. Every result below was observed in this worktree on macOS
(arm64), unless it is marked otherwise. Nothing ran on Windows or the devbox.

## Files changed, each with its reason

| File | Why |
|---|---|
| `crates/store/src/ext_runner.rs` | **W3-R01.** `bridge_record_with` reads `user_version` again inside its `BEGIN IMMEDIATE` transaction (`at_this_builds_schema(&tx.tx)?`), before the runner check and the upsert. The check before the transaction stays, as an early refusal only. New test seam `bridge_record_runner_downgrade_with_faults` (`#[doc(hidden)]`, test support only, the existing `FaultHook` mechanism). The docs give the reason and the transaction mode |
| `crates/runtime/src/paired.rs` | **W3-R01** regression test (new module `adoption_window_tests`, all platforms); `record_owner_only_in_home`'s doc names the re-read |
| `crates/runtime/src/state_store.rs` | **W3-R03** switch-fault case over `PlatformFs` through `open_locked_with` (new `tests` module); `open_locked_with`'s doc names that caller |
| `tests/evidence/artifacts/m08/pc-job63-a9b038a7/README.md` | **W3-R03**: the switch set ran over `RealFs`; the H15 statement |
| `docs/architecture/m08-w3-units.md` | **W3-R03** statement under the job-63 bullet; a pointer to the R04 and R05 residuals |
| `docs/user/limitations.md` | **W3-R04**: a new bullet. **W3-R05**: sentences added to the existing pre-release-build bullet |
| `docs/security/unsafe-inventory.md` | **W3-R06.** The `platform.rs` row names `MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)`; its count is 58 and its unit tests 6. testkit `win.rs` goes from 13 to 21, with its M07 W9e pipe-server calls. Totals are 380 (327 / 36 / 17), at `064f812b`. "Not wired into `check.sh`" now names the `unsafe-inventory` step |
| `tests/integration/request_epoch.rs` | **The Runner rig's `TempDir` leak** (PC job 65). Adds async `Runner::stop`; `connect` keeps each session's `JoinHandle`; `Rig`'s `TempDir` is its last field. Both Runner tests call `stop` |
| `tests/integration/remote_runtime_m06.rs` | Rig audit: the same class (detached `conn.serve` tasks, no stop at all). Adds `Rig::stop`; its two file-store tests call it, at their restart and at their end |
| `tests/e2e/setup_dispatch.rs` | Rig audit: the same class. Each `Session` detached a `serve` task over the service's store in a `ScratchHome`, and the file is Windows-native. A `Served` wrapper now owns those tasks and their stop token, and every test ends with `service.stop().await` |
| 10 rigs with field order (list in "The rig audit") | Rig audit: the `TempDir` or `ScratchHome` field was declared before the store or `Operations` it holds, so it dropped first. Moved last, with U1b's note (the PC job 64 fix in `issuer_reservation_replay.rs`) |

Out of scope and unchanged:
- `crates/heimdall/src/m06_cmd.rs` (`refuse_session`).
- `tools/validation/unsafe_inventory.py`: the script holds no data, and `--check` reads the doc's set.

No file outside the write scope was changed.

## W3-R01

**Transaction mode:** `BEGIN IMMEDIATE`.
- `Store::transaction` uses `TransactionBehavior::Immediate` for a writable store (`crates/store/src/lib.rs`, `transaction`).
- The bridge builds its store with `read_only: false`.
- No helper was added and no other path changed. The code comment says so: "`Store::transaction` on a writable store is `BEGIN IMMEDIATE` ... A deferred transaction would read first and take the write lock only at the upsert".

**What it refuses:** `at_this_builds_schema` accepts exactly `SCHEMA_VERSION`.
- The adoption fence gives `AdoptionFenced`.
- A newer schema gives `NewerSchema`; an older one (an empty file included) gives `OlderSchema`.

**The fail-closed path, unchanged and the only fallback:** `crates/heimdall/src/m06_cmd.rs`, `refuse_session` (about line 5043).
- `if paired::record_owner_only_in_home(home, cause, at).is_err()` then `paired::note_unrecorded_downgrade(&log_dir, cause, at)`.
- The session is refused either way.

**What the design says, and the code that does it:** the served generation carries the downgrade once the marker is applied.
- `RunnerPolicy::drain_pending` (`paired.rs`) writes the row into the served store under the instance lock, then removes the marker. It runs at start (`PairedRunner::new`) and at each limited-role admission or decision (`RunnerPolicy::unverifiable`, and before a join's transaction).
- `marker_dir_of_db` maps `<state>/generations/<name>/state.db` back to the home's log directory.
- Until the marker is applied, `RunnerPolicy::marker_pending` alone keeps the runner owner-only.

**The test:** `paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker`.
- Run it with `cargo test -p heimdall-runtime --lib paired::adoption_window_tests`.
- **The home:** a runner home in the flat layout (`init_runner`). The bridge resolves the flat family (`state_db_of_home`).
- **The seam:** the bridge's store hook fires at `FaultPoint::BeforeTransaction`, after its open and schema check. It runs the runtime's own start-up open, `crate::state_store::open_locked` over `PlatformFs`: intent, fence, copy, publication, completion.
- **Asserted:**
  - the adoption ran, and the pointer names the adopted generation;
  - the bridge returns `Err(AdoptionFenced)`;
  - the fenced flat family is byte-identical to what the adoption left: `state.db` and `-wal`, but not the `-shm` index. A read-only reader stays open throughout, so closing the bridge's connection checkpoints nothing;
  - the marker is queued: `unrecorded_downgrade` reads `session_pty`;
  - the served generation has no row; the policy over it has `marker_pending`; `drain_pending` writes `session_pty` at epoch 1 in the served generation and removes the marker; the runner is `OwnerOnly`, and a restarted policy over that store is too.
- **With the fix:** `test result: ok. 1 passed` here, and in `check.sh`'s test step.

**Revert proof** (only the `at_this_builds_schema(&tx.tx)?;` line commented out, then restored; `cmp` showed the file byte-identical to the fix afterwards). Observed output:

```
test paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker ... FAILED
---- paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker stdout ----
thread '...' panicked at crates/runtime/src/paired.rs:3397:9:
the bridge's write was not refused: Ok(RunnerDowngrade { cause: "session_pty", epoch: 1, recorded_at: 2026-11-25T09:00:00Z, last_event_at: 2026-11-25T09:00:00Z })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 149 filtered out; finished in 0.16s
error: test failed, to rerun pass `-p heimdall-runtime --lib`
exit 101
```

The byte assertion has teeth too. In an earlier experiment (the re-read reverted, and the refusal assertion skipped), the byte comparison failed: "the bridge wrote into the fenced flat family". The test file was restored after it.

**The audit of the class** (by reading, every store writer in production code):
- **The bridge's downgrade write** (`ext_runner::bridge_record_runner_downgrade`, through `paired::record_owner_only_in_home`, from `refuse_session`). This is ADR-0012's one exception. It read `user_version` outside its write transaction. **Fixed.**
  - **Its layout read is also outside the transaction** (`state_db_of_home`, then `layout::locate`).
  - For the adoption, the fence re-read covers it: a flat family resolved before the switch is fenced, so the write is refused and queued.
  - It is not covered for a restore's or a reset's switch: an old generation is never fenced. The ruling sends that pointer re-check to W4 (U2b-3b), and no build switches between two generations yet.
- **The bridge's marker** (`paired::note_unrecorded_downgrade`) is safe.
  - It writes `<home>/log/runner-downgrade-unrecorded.log`, which is not the store, and it reads no `user_version` or layout.
  - Its place does not depend on the layout, and the runtime finds it from whichever generation it serves.
- **A pre-release build's own bridge** has the same flaw (check, then transaction) and cannot be fixed here.
  - Its write is lost only if that older binary is the forced command while this build's first start adopts the home. That happens on pre-release homes only (ADR-0014 §3.2 item 8). See open question 4.
- **Every other writer holds the instance lock**, which also excludes the adoption, since only a lock holder adopts:
  - the runtime's start (`Service::start_with`: `InstanceLock::try_acquire`, then `state_store::open_locked`);
  - the CLI's direct writers (`m06_cmd` `try_writer` / `open_locked_store` and the `InstanceLock::try_acquire` paths at about 3395 and 4598; `remote init`);
  - uninstall's purge (`purge_locked`, `carry_downgrade_forward`);
  - the marker drain (`drain_pending`);
  - the request ledger (`RequestFence` in the running runtime).
- **The layout's own reads are safe:**
  - `fence` and each migration step read `user_version` inside their own IMMEDIATE transactions;
  - `probe_flat`, `copy_fenced` and `generation_version` read under the lock, and the bridge (the one lock-less writer) never changes `user_version` and now refuses a fenced family.
- **Lock-less readers** are read-only connections and cannot write: `doctor`, the CLI's `open_read_only` sites, the issuer child (`child.rs`), and uninstall's no-write reads.
- **Test seams** (`#[doc(hidden)]`): `raise_restore_epoch_for_test`, `fence_ledger_for_test`, `open_at_schema_version`, `open_ahead_of_this_build`, and the new `bridge_record_runner_downgrade_with_faults`.

## W3-R03

**The new test:** `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`.
- Target: `heimdall-runtime`'s unit tests.
- Run it with `cargo test -p heimdall-runtime --lib state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`.

**What it runs:** 8 cases, {install, adoption of a flat store} × {`Before`, `After`} × {`Error`, `Dead`}.
- `FaultFs<PlatformFs>` faults at `Point::PointerRename`, through `open_locked_with`. The state directory comes from `Paths::ensure`, so on Windows it is protected.
- The restart is `open_locked` over `PlatformFs`.
- It serves only the pointer's generation: the faulted attempt's when the rename was made (`Began::Served`), and otherwise the first publication run again.
- Afterwards one generation is left, no `CURRENT.tmp`, the intent is complete, the record's operation is right, and an adoption keeps the flat store's environment.
- On Windows, the `After` cases make the `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` rename and then fault, and the restart's intent rename replaces an existing file through the same call.

**Observed:** passing on macOS only (`rename(2)`), and in `check.sh`'s test step. `clippy-windows` compiled it for `x86_64-pc-windows-gnu`. It has not run on Windows.

**Wording corrected to:** "H15 exercised on the normal path in job 63; under a fault by `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation` ..., in the fix-diff PC run (pending)."
- That text is in the PC job 63 README (its step-1 row, plus an H15 paragraph) and in the units doc's §2b job-63 bullet.
- `docs/user/limitations.md` had no text claiming H15 ran under faults (grep for H15, `MoveFileExW` and write-through found none), so nothing was corrected there.

## W3-R04, W3-R05, W3-R06

- **W3-R04:** a new bullet in `docs/user/limitations.md`.
  - What it says: an interrupted layout removal leaves `state_corrupt`; a second `uninstall --purge-state` is refused ("the state store's pointer is damaged"); recovery is by hand (the layout entries named) until `heimdall state reset` can recover it.
  - The units doc names it as `purge_layout_removal_interrupted_leaves_state_corrupt`.
- **W3-R05:** added under the existing pre-release-build bullet. Start-up refuses (`WrongState`) until `STAGING-INTENT` is removed by hand; the next start then adopts that store. No code was added for either.
- **`docs_commands_check.py` on limitations.md:** 1 file, 0 unknown.
- **W3-R06:** `unsafe_inventory.py --check` gives `PASS (19 entries)`. `--list` gives `total unsafe constructs: 380 in 19 files`, unchanged by this diff.

## The rig audit

**Changed** (the lead's before-and-after `.tmp*` counts on Windows apply to these). "Async stop" means the rig keeps the session tasks it spawns, then stops and awaits them, waits (bounded) for `Operations::running_operations`, and waits (bounded) until the store's last `Arc` is gone. "Field order" means the `TempDir` field was moved last.

| Rig | Fix | Target |
|---|---|---|
| `tests/integration/request_epoch.rs` `Runner` and `Rig` | async stop; `TempDir` last | `heimdall-runtime --test integration_request_epoch` (both Runner tests) |
| `tests/integration/remote_runtime_m06.rs` `Rig` | async stop; called by `paired_widening_is_confirmed_runner_locally_and_replays_its_result` and `decision_backed_replay_after_a_store_restart_answers_each_record_state` | `heimdall-runtime --test integration_remote_runtime_m06` |
| `tests/e2e/setup_dispatch.rs` `Served` / `Session` | async stop for all 9 tests | `heimdall-runtime --test e2e_setup_dispatch` |
| `crates/runtime/src/managed_store.rs` `tests::World` | field order | `heimdall-runtime --lib managed_store::tests` |
| `tests/e2e/managed_m03.rs` `World` | field order | `heimdall --test e2e_managed_m03` |
| `tests/integration/issuer_child.rs` `World` | field order | `heimdall-issuer --test integration_issuer_child` |
| `tests/integration/issuer_remote_m06.rs` `World` | field order | `heimdall-issuer --test integration_issuer_remote_m06` |
| `tests/integration/managed_adapter.rs` `World` | field order | `heimdall-adapters --test integration_managed_adapter` |
| `tests/integration/transport_supervise_m06.rs` `World` | field order | `heimdall-runtime --features iroh --test integration_transport_supervise_m06` |
| `tests/model/setup.rs` `World` | field order | `heimdall-runtime --test model_setup` |
| `tests/model/timegate.rs` `Model` | `file` moved last (`gate` holds the store) | `heimdall-runtime --test model_timegate` |
| `tests/e2e/deadline_m03.rs` `windows::World` (Windows-only) | field order | `heimdall --test e2e_deadline_m03` (needs `HM_FIXTURE_SSHD_*`) |
| `tests/e2e/tui_m02.rs` `console::World` (Windows-only) | field order; its `Drop` joined the thread but dropped `home` before `ops` | `heimdall --test e2e_tui_m02` |

**Named safe, by reading:**
- **Stopped and awaited by the rig or the test:**
  - `request_epoch.rs` `Running`: `stop` awaits the service's `run()`. Job 65 found leftovers only from the two Runner tests.
  - `integration/runtime.rs` `u8b`: `tmp` is declared first; a service is either `run()` and then cancelled and awaited, or dropped without running, and the M04 Windows fix keeps no task holding the store past its drop.
  - `runtime_m03.rs` `round2::Home`: `run_once` cancels and awaits.
  - `cli_m07.rs`, `harness_m07.rs` (`stop` awaits) and `m07_powershell_hook.rs`: they cancel and await the service task.
  - `remote_runtime_m06.rs`'s Service test: awaits `running`.
- **Unix-only** (Unix deletes a directory whose files are open):
  - `runtime_m03.rs`: `wave4::Rig`, `issuer_crash::Rig` and `setup_switch::Rig`;
  - `managed_store.rs` `live_tests::Live`;
  - `connections.rs` `unix::World`;
  - `wsl_helper_channel.rs`;
  - `tui_m02.rs` `pty::World`;
  - the unix module of `paired.rs`;
  - `exit_m06`;
  - `wrapper_m07.rs`.
- **In-memory stores:** `remote_runtime_m06.rs`'s other tests, and `projection_recovery_rows.rs` `World`.
- **The rig's `Drop` stops the runtime before its directory field drops** (cancel and join, or `service stop` with an exact-identity guard):
  - `cli_m02` `World`;
  - `cli_m03`: `access::Rt`, `issuer::Rig` and `enroll::World`;
  - `cli_m05` `Rt`;
  - `run_m02`: `Rig` and `World`;
  - `tui_m03` and `tui_m07` `World`;
  - `windows_m04` (its `StopRuntime` guard is declared after its scratch directory);
  - `exit_m03` `World`;
  - `setup_cmd` `InProcessRuntime`;
  - `uninstall_cmd`'s tests (their threads are joined).
- **Already fixed:** `issuer_reservation_replay.rs` `World` (U1b; PC jobs 64 and 65).

## Gates and runs

**`tools/validation/check.sh`**, through heavy-gate, detached. Its step lines, in order:

```
== fmt: exit 0
== clippy: exit 0
== clippy-windows: exit 0
== crate-graph: exit 0
== unsafe-inventory: exit 0
== iroh-check: exit 0
== audit: exit 3
== claims-table: exit 0
== test: exit 0
== test-discovery: exit 0
== schema: exit 0
== release-gate: exit 0
== native-harness-selftest: exit 0
== evidence-selftest: exit 0
== evidence-records: exit 0
== replay-driver-selftest: exit 0
== skill-lint: exit 0
== wrapper-tests: exit 0
== harness-h1-tests: exit 0
== harness-h2-tests: exit 0
== adapter-page: exit 0
== overall: exit 1
```

- **Test step totals:** 170 `test result:` lines, all `ok`. 4274 passed, 0 failed, 203 ignored.
- **`overall: exit 1` comes only from `audit: exit 3`:** "missing prerequisite: cargo-audit 0.22.1 (cargo install --locked cargo-audit@0.22.1 --root target/tools)". This worktree has no `target/tools/bin/cargo-audit`, and there is none on `PATH`. I did not install it from the network. `Cargo.lock` and `Cargo.toml` are unchanged from `064f812b` (empty `git diff --stat`), so the audit's result is the base's. The audit's own self-tests passed.

**Focused runs, outside the gate:**
- `integration_transport_supervise_m06` with `--features iroh` (through heavy-gate): 13 passed, 0 failed. `check.sh` does not build this target.
- Also: `integration_request_epoch` 10/10; `integration_remote_runtime_m06` 15/15; `e2e_setup_dispatch` 9/9; `heimdall-runtime --lib managed_store` 66; `model_setup` 52; `model_timegate` 27; `integration_issuer_child` 37; `integration_issuer_remote_m06` 10; `integration_managed_adapter` 54; the store's `ext_runner` tests 6.

## Modelled rather than run; open questions

1. **R01's caller.** The test makes the caller's fallback itself, as `refuse_session` makes it. `refuse_session` is outside the write scope and has no seam; its "any error queues the marker" rule has its own test (`m06_cmd`'s `a_downgrade_the_bridge_cannot_write_is_queued_and_the_next_admission_records_it`). The start's drain is `RunnerPolicy::with_store` plus `drain_pending`, which is what `PairedRunner::new` runs; no full runtime start was used.
2. **R01's interleaving.** The whole adoption runs in the window, so the bridge's transaction comes after the switch, not between the copy and the switch as in the review's model. Both put the transaction after the fence and the copy, which is what loses the row. The fixed bridge refuses in both orders, because the check sits under the write lock.
3. **Windows: nothing ran natively.** For the fix-diff PC run, I suggest the R03 test (H15 under a fault), the R01 test (it runs the adoption through `PlatformFs` on Windows), and the changed rigs above with their `.tmp*` counts.
4. **Pre-release bridges.** The residual for a pre-release build's own bridge is not recorded anywhere yet. Should it join the pre-release-build bullet in limitations? That is the lead's call.
5. **Field order is not an await.** The 10 field-order rigs await no detached work. In those holding `Operations`, an operation's lead task that outlives a test body could still hold the store. U1b's reorder held on Windows in job 65; the counts will show whether any of these needs an async stop like `Runner`'s.
6. **Child-process and thread runtimes** were audited by reading only.

## Cleanup and size

- **`target/`:** 36G in total (`debug` 33G, `x86_64-pc-windows-gnu` 1.8G, `release` 676M). It is kept for the lead's commit and gate; delete it when the worktree is done.
- **Removed by exact path:** `/tmp/hm-w3fix-scripts`, `/tmp/hm-w3fix-check` and `/tmp/hm-w3fix-warm.log`. The step lines above are copied from `/tmp/hm-w3fix-check/check.log`.
- **No processes left running.**
- **Not touched:** `prototypes/`, any key store or `~/.ssh`. No `heimdall` was run by hand.
