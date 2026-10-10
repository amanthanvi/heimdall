# T3-rust-opus1 (written by the orchestrator from the implementer's structured report; the Write tool refused out/REPORT.md)

Status: verified

The TUI now underlines the filter match, has a `?` help overlay, and keeps the selected destination across filter edits (part C, replacing K9). Both harness runs end 136/139 (exit 1) on darwin-arm64 and on linux-arm64. The three failures are exactly the ones TASK.md says a correct implementation fails: tui.filter_edit_resets_selection, tui.no_color and tui.large_100_filter_latency. 0 errors and 0 skipped on both platforms.

The runtime refused my write of out/REPORT.md, so the report content is below. out/diff.patch and out/artifacts.json are written.

**Changes** (only in prototypes/rust):
- **All behaviour is in `ListModel`** (src/list_model.rs); src/tui.rs only renders it.
- **C. Selection across filter edits.** After an append, Backspace or Esc clear, the destination selected before the edit stays selected if it is still shown. Otherwise the first shown row is selected, including when nothing was shown before. Enter keeps the selection as before.
- **Scrolling.** The model now owns the scroll offset; the renderer reports the list height each frame (`set_viewport`). The window is always full when there are enough rows and always contains the selection. After a filter edit the selected row keeps its screen row where possible. I set ratatui's offset explicitly because ratatui does not refill the window from a stale offset.
- **A. Match highlight.**
  - `find_ci` uses the filter's own rule (lowercase plus substring) and maps the match back onto the original characters.
  - Only the first match in the alias is underlined, plus the first match in the host when the row shows it (50 columns or more).
  - The prefix, separators, account, `@`, `:` and port are never underlined, and an empty filter underlines nothing.
  - The underline is an attribute (SGR 4/24), not a colour, so it also shows under NO_COLOR, which still emits no colour codes.
- **B. Help overlay.**
  - `?` opens it only outside filter mode; in filter mode `?` is filter text.
  - While it is open, only `?` and Esc (close) and Ctrl-C (exit 130) act. Esc there does not clear the filter.
  - It covers the whole screen with the nine lines, one per row. After it closes, the screen is identical to before it opened.
  - Opening, resizing and closing it at 20x5 does not crash.
- **REPORT.md:** new §17 in the prototype's REPORT.md describes the change.

**Tests:**
- **Unit:** the K9 test is replaced by two part C tests, one using a destination 90 rows down in the 100-destination fixture. New unit tests cover the help overlay, match mapping (ASCII, CJK, first occurrence, the Turkish dotted İ whose lowercase is longer, Greek sigma), row underline segments, and the model using the current filter.
- **pty suite (tests/pty_tui.py):** its terminal model now tracks underline. The K9 case is replaced by `c-filter-edit-keeps-selection`. New cases: `c-far-selection-stays-visible`, `a-underline-filter-match` and `b-help-overlay`. All four new cases fail against the starting-commit binary built in scratch.

**Results (real exit codes):**

| Step | Exit | Result |
|---|---|---|
| fmt, clippy (host and windows-gnu) | 0 | clean |
| host `cargo test` | 0 | 54 + 4 + 28 passed |
| `build.sh` | 0 | all 4 targets built, as before |
| darwin pty suite | 0 | 30 cases; the only failure is the existing Darwin known limitation `run-terminal-sigint-not-doubled` |
| Linux arm64 native unit tests | 0 | 54 + 4 + 28 passed |
| Linux arm64 pty suite | 0 | 30/30 |
| harness darwin | 1 | 136/139 |
| harness linux-arm64 | 1 | 136/139 |

- **tui.no_color:** only its "> on lab-server" step fails, because nas stays selected under part C. Its no-colour assertion passes on both platforms.
- **K17 latency:** the harness's own latency check uses the old K9 predicate, so I measured it separately with scratch/k17_partc.py. An update counted only when the status showed the new count, the list showed a full window of consecutive matches in profile order, and `> ` was on the destination part C selects. Each run was 5 sessions of 6 edits:
  - darwin: p95 4.1 ms starting from host-000, 3.8 ms starting from host-070 (30/30 edits each).
  - linux-arm64, in the harness image: p95 4.3 ms and 4.1 ms (30/30 each).

**Artifacts** (sha256):
- darwin-arm64: `/tmp/x2ws-674ddca9/heimdall/prototypes/rust/dist/darwin-arm64/heimdall-proto`, `9c6606190083ae44fdcbb7213da8125031eab71402ee7311183f74d6ac8f2ddc`
- linux-arm64: `/tmp/x2ws-674ddca9/heimdall/prototypes/rust/dist/linux-arm64/heimdall-proto`, `11b9be2032c21fb4d5cd6743ba4e93aa7aae12972647a69d24596c9223b735d1`

Harness records, consoles and the K17 JSON files are in `/tmp/x2ws-674ddca9/scratch/`.

**Known gaps:**
- Windows is compile-checked only; running it needs a native Windows host.
- No independent review was run, because this agent had no delegation tool.
- The full-screen unframed help page and keeping the selected row's screen position are my design choices; TASK.md allows both.

## Commands run
- `git init && git add -A && git commit (starting point 58559a9)` exit 0: 61 files committed
- `cargo fmt --check` exit 0: clean
- `cargo clippy --locked --all-targets -- -D warnings` exit 0: no warnings
- `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` exit 0: no warnings
- `HEIMDALL_G02_FIXTURES=... cargo test --locked -- --test-threads=4 (macOS arm64)` exit 0: lib 54 passed, bin 4 passed, cli 28 passed
- `/bin/sh prototypes/rust/build.sh` exit 0: darwin-arm64, linux-x64, linux-arm64, windows-x64 all built
- `python3 tests/pty_tui.py dist/darwin-arm64/heimdall-proto --panic-binary target/panic/debug/heimdall-proto` exit 0: 30 cases; only failure is pre-existing Darwin known limitation run-terminal-sigint-not-doubled
- `HP_PTY_ONLY=<c-filter|c-far|a-under|b-help> python3 tests/pty_tui.py <starting-commit binary built in scratch>` exit 1: red proof: all 4 new cases fail on the original binary
- `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/rust/dist/darwin-arm64/heimdall-proto --candidate rust --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` exit 1: 139 total: 136 pass, 3 fail (tui.filter_edit_resets_selection, tui.no_color, tui.large_100_filter_latency), 0 error, 0 skipped; status=verified
- `sh tests/g02/linux/run.sh --artifact-dir prototypes/rust/dist/linux-arm64 --candidate rust --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` exit 1: 139 total: 136 pass, the same 3 expected fails, 0 error, 0 skipped; platform linux-arm64
- `tests/g02/.venv/bin/python -I -B scratch/k17_partc.py <repo> dist/darwin-arm64/heimdall-proto scratch/k17-partc-darwin.json` exit 0: part C K17 predicate: run A 30/30 edits, p95 4.1 ms; run B (start host-070) 30/30, p95 3.8 ms
- `docker run (harness image heimdall-g02-harness:d0c8e448a3a7, --network none, uid 10001, cap-drop ALL) python3 -B /k17_partc.py /repo dist/linux-arm64/heimdall-proto` exit 0: linux-arm64: run A 30/30, p95 4.3 ms; run B 30/30, p95 4.1 ms
- `cargo-zigbuild test --no-run --target aarch64-unknown-linux-musl && sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64` exit 0: lib 54, bin 4, cli 28 passed (1 ignored by design)
- `sh tools/linux_pty.sh arm64 prototypes/rust/dist/linux-arm64/heimdall-proto <linux panic binary>` exit 0: linux 30/30 pty cases passed

## Limitations
- Windows was compile-checked only (clippy for windows-gnu, and build.sh built windows-x64). It was not run: that needs a native Windows host.
- No independent or adversarial review was run, because this agent has no delegation tool. All verification here is my own.
- The help overlay is a full-screen unframed page, chosen so no help row also contains list text. After a filter edit the selected row keeps its screen row where possible. Both are design choices within TASK.md.
- The harness runs created __pycache__ directories under tests/g02 and tests/fixtures/fake-agent. I deleted them afterwards; nothing tracked under tests/ changed.
- prototypes/rust/target/tools/bin/cargo-zigbuild was already in the workspace and is part of the starting commit. diff.patch excludes target/ and dist/.

## Escalations
- The runtime refused to let me write /tmp/x2ws-674ddca9/out/REPORT.md ('Subagents should return findings as text'). I did not work around the block, so out/REPORT.md is missing and its content is in the summary below for the orchestrator to write. diff.patch and artifacts.json are written.
