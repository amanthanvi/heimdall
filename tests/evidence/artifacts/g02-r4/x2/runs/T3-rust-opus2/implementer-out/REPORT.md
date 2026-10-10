# T3-rust-opus2: TUI match underline, help overlay, selection kept across filter edits (Rust + Ratatui)

Workspace: `/tmp/x2ws-c5670791/heimdall` (git-initialised; starting commit `57bb247`). Only
`prototypes/rust/` changed: `src/list_model.rs`, `src/tui.rs`, `tests/pty_tui.py`, `REPORT.md` (new §17).
`docs/`, `schemas/`, `tests/g02/` and the fixtures are untouched. The diff is in `diff.patch`. Build
outputs (`dist/`, `target/`) are excluded.

## What changed and why

### A. Match underline
- `list_model::match_range(hay, needle_lower)` returns the byte range of the first case-insensitive
  occurrence of the filter text.
  - It searches `hay.to_lowercase()`, the same rule the filter uses.
  - It maps the hit back to whole characters of the original string using per-character lowercase
    lengths. `str::to_lowercase` works character by character; its only context rule, final sigma,
    swaps two code points with the same UTF-8 length. So the mapping stays exact even where
    lowercasing changes a string's length (unit test: `İ`, final sigma).
- `ListModel::row_match(d)` gives the alias range and the host range. Both are `None` while the
  filter is empty, for example after `Esc`. The lowercased needle is stored with each re-filter.
- `tui::row_line` builds each row from spans: `alias`, `"  account@"`, `host`, `":port"`. Only the
  match spans carry `Modifier::UNDERLINED`. The host span exists only at 50 columns or more.
  - The `> ` symbol, the separators, the account, `@`, `:`, the port and any later occurrence are
    never underlined.
  - The selected row's highlight (cyan and bold, colour mode only) adds BOLD and does not remove
    underline.
  - Under `NO_COLOR`, crossterm still writes no colour SGR, but the underline attribute (`ESC[4m`)
    is still drawn.

### B. Help overlay
- The model has a `help` state.
  - Outside filter mode, `?` opens it. In filter mode, `?` is filter text.
  - While it is open, `?` or `Esc` closes it. `Esc` does not clear the filter.
  - While it is open, Ctrl-C cancels (exit 130). Every other key is ignored. The test-only panic
    hook is ignored too.
- `tui::render_help` replaces the whole screen with the nine lines of `HELP_LINES`, one per row
  with a one-space indent. No list text shares a row with them.
- Small sizes clip the overlay. Resizing was tested at 20x5, 1x1, 2x2, 20x1 and 0x0.
- When the overlay closes, the list, filter, filter mode and selection are unchanged, because the
  key handling never touches them while help is open.

### C. Selection kept across filter edits (replaces K9)
- `refilter` remembers which destination was selected before the edit.
  - If that destination is still shown, it stays selected. It is found by binary search, because
    the shown indices are in ascending profile order.
  - Otherwise, including when no row was shown before the edit, the first shown row is selected.
  - `Enter` does not re-filter, so it keeps the selection, as before.
- The model now owns the list window (`ListModel::scroll(height)`).
  - The window keeps its previous position, clamped so it is always full when enough rows match.
  - It moves only as far as needed to keep the selection visible.
  - A kept selection stays on the same screen row where that is possible.
- The window is set explicitly because Ratatui's `List` offset logic does not fill a window that a
  shrinking list leaves short. The acceptance predicate for K17 needs "a full window of consecutive
  matching rows".

## Tests and results (real exit codes)

| Command | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 | |
| `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | |
| `HEIMDALL_G02_FIXTURES=… cargo test --locked -- --test-threads=4` (macOS arm64) | 0 | lib 57, bin 13, cli 28 passed |
| `sh build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64 and windows-x64 all built |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate rust …` | 1 | 136 pass, 3 fail, 0 error, 0 skipped of 139; status `verified`, verdict `fail` |
| `sh tests/g02/linux/run.sh --artifact-dir prototypes/rust/dist/linux-arm64 --candidate rust …` | 1 | 136 pass, 3 fail, 0 error, 0 skipped of 139; status `verified`, verdict `fail` |
| `python3 tests/pty_tui.py dist/darwin-arm64/heimdall-proto --panic-binary target/panic/debug/heimdall-proto` | 0 | 31 cases, passed; 1 pre-existing known limitation (`run-terminal-sigint-not-doubled`, Darwin) |
| `sh tools/linux_pty.sh arm64 …/dist/linux-arm64/heimdall-proto …/panic/…/heimdall-proto` | 0 | 31 cases, all passed |
| `sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64` (cross-built test binaries in a Linux arm64 container) | 0 | lib 57, bin 13, cli 28 passed (1 ignored, as before) |

### Harness failures

The harness fails exactly the three checks that TASK.md names as expected, on both platforms:
- `tui.filter_edit_resets_selection`: it asserts K9.
- `tui.no_color`: only the marker step fails. After `/nas` and `Esc`, `nas` stays selected, as
  part C requires. The "no color SGR in the whole session output" assertion passes on both
  platforms.
- `tui.large_100_filter_latency`: only the "backspace to ''" rows predicate fails, 5 of 30 edits.
  - The screen showed a full window of 23 consecutive matches (host-063 … host-085) with `> ` on
    host-070-lab, which part C keeps.
  - The harness expected the window to start at host-000.
  - The K17 p95 assertion over the edits it could count passes: 2.8 ms on darwin and 3.0 ms on
    Linux, with a maximum of 3.1 ms and 3.7 ms.

The harness's final canary check passed (`canary.no_canary_anywhere`), and it exited 1, not 3.

### New and updated prototype tests
- Unit tests in `src/list_model.rs`:
  - part C: append, Backspace and the Esc clear keep the selection; the first-row fallback; an
    empty result before the edit; host-077 far down the 100-row list
  - scrolling and full windows
  - help key handling
  - `?` in filter mode
  - match ranges, including `İ` and final sigma
  - `row_match`
- `src/tui.rs` render tests, with Ratatui `TestBackend`:
  - the exact underlined cells for `LaB`, `e` (first occurrence only, host-only rows), `東京`, 40
    columns, a host-only match below 50 columns, `NO_COLOR`, after `Enter` and after `Esc`
  - the help rows and their order, ignored keys, the screen being identical after close, tiny sizes
  - full consecutive windows with host-077-db marked after each edit
- `tests/pty_tui.py`:
  - The VT model now tracks the underline attribute per cell.
  - The K9 case is replaced by `t3c-filter-edit-keeps-selection`.
  - New cases:
    - `t3c-large-100-far-selection`
    - `t3c-k17-latency-part-c`: 5 sessions of 6 edits, using the acceptance-style predicate
      (status count, a full consecutive window, and `> ` on the destination part C selects). p95
      was 6.4 ms on darwin and 6.3 ms on Linux, with this driver's 5 ms polling granularity
      included.
    - `t3a-match-underline`: colour and `NO_COLOR`.
    - `t3b-help-overlay`.

## Known gaps and limits
- No independent review was done. This is self-review only; delegation was not used in this run.
- The help overlay replaces the whole screen, including the status line, rather than drawing a
  framed box over the list. TASK.md allows this ("may be framed or indented"). It was chosen so that
  no list text shares a row with a help line.
- The black-box acceptance tests were not available. Underline was checked with the prototype's own
  VT model and Ratatui `TestBackend`, not with pyte. In pyte, a wide CJK character's continuation
  cell carries the same attribute, which is outside the prototype's control.
- Windows (`windows-x64`) was only built and passed clippy. As before, it was not run natively.
- `prototypes/rust/selftest.sh` was not run end to end. It depends on round-1, 2 and 3b red-proof
  binaries and on evidence paths outside this reduced workspace. Its constituent steps listed above
  were run individually.
