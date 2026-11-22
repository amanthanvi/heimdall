<!-- M07 wave 2.1 narrow re-check of M07-W2-R01 and R02 (Gemini), at 8e5bb1d6, 2026-11-22. Archived verbatim by the M07 integrator. -->

CLOSED

Scope: scoped re-check of `b4368d0b..8e5bb1d6` (M07 wave 2.1, macOS arm64).

## 1. Findings

- **M07-W2-R01:** Fixed. `event_loop` (`crates/heimdall/src/tui/mod.rs:397-404`) settles with the worker (`SETTLE_BOUND = 25 ms`, `worker.rs:178-185`) and compares `stale_geometry` plus `drawn_resizes != Some(worker.resize_generation()) || !settled` before dispatching any key batch, invalidating `app.frame()` via `app.begin_frame()` and forcing a full clear repaint (`Terminal::resize`, `mod.rs:350-358`). Every key path enters via `Input::Keys` with no path skipping `settle` (`Decision`/`Authorization`/`Repair` modal frame guards remain scheduled for U7 per `w2.md`; `Connect`/`StartRuntime` remain unguarded by prior ruling). Revert proof (`mod.rs:397-404` back to `stale_geometry` only): `0` -> `101` (all 4 tests bypassed on attempt 1) -> `0` (4/4 passed, 20/20 each; multi-step `A->B->C->A` refused 5/5 across all 4; plain no-resize confirm worked).
- **M07-W2-R02:** Fixed. `skill_lint.py` (`tools/validation/skill_lint.py:174-177`) limits operand truncation strictly to `inspect <subject>` (14-item `INSPECT_SUBJECTS`, excluding `issuer`/`export`) and `schema show <name>`. In-memory comparison on the 3 invented-command negatives gave `[0, 0, 0]` findings at `b4368d0b` vs `[1, 1, 1]` at `8e5bb1d6` (self-check passes).

## 2. Residual judgment

- **Theoretical signal-latency window, not a practical bypass.** On Unix, `TIOCSWINSZ` marks `SIGWINCH` pending synchronously before user input is written; returning from `poll`/`SIGCONT` delivers pending signals to user space, and `worker.settle` executes 3 `tokio::task::yield_now()` (`context::defer`) turns, driving `SignalDriver::process()` and `forward_signals` (`resizes.fetch_add(1)`) before `ack` returns. Batched keys that open a confirmation/sight start at frame `0` (`Seen::default()`/`Sight::of`), so they fail closed independent of `settle`. When size still differs (`120x40 -> 40x5`), `stale_geometry` (`tcgetwinsize`) catches it directly without waiting for `SIGWINCH`. Probes observed 0 bypasses across 80/80 `SIGSTOP` roundtrips, 20/20 `A->B->C->A` roundtrips, 30/30 live rapid roundtrips (`live_refused=30, bypassed=0`), and 15/15 `SIGSTOP`+`R` (active doctor blocking-pool thread) attempts (`sigstop_busy_bypassed=0`).

## 3. New findings & harness checks

- **New findings:** None.
- **Harness changes (`tui_m02.rs`, `tui_m03.rs`, `tui_m07.rs`):** Setting `O_NONBLOCK` on the PTY master with `poll`+`read` drain and bounded `write` prevents teardown hangs when macOS flushes PTY output after `poll` without losing captured bytes (`tui.wait` completes before `Pty::drop`). `typed_at_a_drawn_frame` (`tui_m07.rs:1905-1934`) runs only in the post-loop positive control (after 20/20 unretried refusal attempts) and retypes only on fresh refusal bytes; `no_cursor_position_query_emitted` (`tui_m02.rs:1091-1106`) retries `2c` while asserting `exited with status 0` and no `ESC[6n`. Neither weakens an assertion or can mask a bypass.

## 4. Checks run (macOS arm64, `8e5bb1d6` clean unless noted)

- `git diff --check b4368d0b 8e5bb1d6` + added-line hygiene scan (913 lines): `0` (0 hits).
- `cargo build --locked --offline -p heimdall --bin heimdall`: `0`.
- `python3 -I -B tools/validation/skill_lint.py --heimdall target/debug/heimdall`: `0` (`0 finding(s)`), plus 9 edge probes (`0`) and `b4368d0b` vs `8e5bb1d6` negative check (`0`).
- `cargo test --locked --offline -p heimdall --bin heimdall -- tui::`: `0` (`93 passed, 0 failed`).
- `cargo test --locked --offline -p heimdall --test e2e_tui_m07 -- --test-threads=1 --nocapture`: `0` (`12 passed, 0 failed, 1 ignored`; A20 P95: Tab `3.8 ms`, PageDown `3.9 ms`, search `3.8 ms`, Settings `3.9 ms`, Activity `5.2 ms`; idle `0 B/12 s`; roundtrip 4/4 `20/20`).
- `cargo test --locked --offline -p heimdall --test e2e_tui_m02 -- --test-threads=1`: `0` (`17 passed, 0 failed, 1 ignored`).
- `cargo test --locked --offline -p heimdall --test e2e_tui_m03 -- --test-threads=1`: `0` (`5 passed, 0 failed, 1 ignored`).
- Temporary `e2e_tui_m07` probes (`review_probe_`, reverted): `0` (`2 passed`: 4x5 `A->B->C->A` + plain stop `0`; live 30/30 + `R`-busy 15/15 `0` bypass).
- W2-R01 revert proof (`tui/mod.rs:397-404` -> `roundtrip_resize_before_redraw_triggers_nothing`): `0` -> `101` (0 passed, 4 failed on attempt 1) -> `0` (4 passed, restored).
- **Not run (host = macOS arm64):** Windows console resize/input path (`cfg(windows)`).
