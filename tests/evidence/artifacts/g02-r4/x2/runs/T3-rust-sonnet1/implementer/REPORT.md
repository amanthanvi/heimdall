# T3-rust-sonnet1 report

## Changes (prototypes/rust only)
- src/list_model.rs
  - Part C: refilter() remembers the destination selected before the edit and keeps it if still shown, else selects the first shown row (also when no row was shown). Replaces K9.
  - Part A: find_ci() (first case-insensitive occurrence, byte range in the original string, per-char lowercase mapping) and ListModel::match_ranges() (alias range; host range only when width >= 50).
  - Part B: help flag; '?' opens help outside filter mode; while open only '?' and Esc close it, Ctrl-C cancels, all else ignored. HELP_LINES holds the nine lines.
- src/tui.rs
  - Rows are built from spans; only the matched alias/host ranges carry Modifier::UNDERLINED (no colour, so NO_COLOR is unaffected).
  - Help overlay clears the whole screen and draws the nine lines, indented two spaces, from row 0.
  - The list scroll offset persists in ListState and is clamped so a shrinking list still shows a full window and the selected row stays visible.
- tests: unit tests (K9 test replaced by part C tests; find_ci, match_ranges, help keys, far selection in large-100); tests/pty_tui.py gains underline tracking in its Screen model, K9 case replaced by x2c cases, plus x2a (highlight, NO_COLOR) and x2b (help, tiny terminal) cases.

## Results (real exit codes)
- cargo test --offline: exit 0 (53 lib, 4, 28 cli tests passed).
- build.sh: exit 0, all four targets built. "notices generation failed" in dist/logs/notices.log (tools/gen_notices.py, cargo metadata --locked --offline); I did not touch that code and did not investigate further.
- Darwin harness (conformance.py): 139 checks, 136 pass, 3 fail, runner exit 1. The 3 failures are exactly the expected ones: tui.filter_edit_resets_selection, tui.no_color (last step), tui.large_100_filter_latency (list-start predicate). K17 p95 latency 4.1 ms.
- Linux harness (linux/run.sh, linux-arm64 container): 139 checks, 136 pass, 3 fail, same three. K17 p95 3.2 ms.
- tests/pty_tui.py on the darwin release artifact: exit 0; 31 cases, all pass except run-terminal-sigint-not-doubled, a documented known limitation in the existing suite.

## Known gaps
- Hidden black-box tests were not seen; behaviour of the help overlay frame (none, unframed) and scroll position after edits are my choices within the spec.
- Wide (CJK) underline checked only with the prototype's own VT model and the harness, not pyte per-cell.
- The first darwin build step took about 15 minutes of wall time (cause not investigated).
- Windows target compiles but its new code is not run natively.
