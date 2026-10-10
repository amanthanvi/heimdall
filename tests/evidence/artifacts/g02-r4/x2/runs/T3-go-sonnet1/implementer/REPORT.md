# T3-go-sonnet1 report

Changed files: prototypes/go/internal/tui/tui.go, prototypes/go/internal/tui/tui_test.go (only).

## Changes
- A. Highlight: markMatch/indexFold underline (SGR 4 on, SGR 24 off) the first case-insensitive match of the
  filter in the alias and, at width >= 50, in the host. Matching is per rune with unicode.ToLower, the same rule
  strings.ToLower applies in profile.Filter, so rune offsets stay stable (and control-char sanitizing is rune for
  rune). Underline is emitted with NO_COLOR too; SGR 24 (not 0) closes it so the selected row keeps its colour. A
  trailing SGR 24 is appended after truncation in case the cut dropped the closing sequence. Empty filter: no match.
- B. Help overlay: `?` outside filter mode sets Model.help; Render replaces the list area with the nine help
  lines (2-space indent, clipped by height/width) and keeps the status line. While open, only `?` and `Esc` act
  (close; Esc does not clear the filter); every other key is ignored, Ctrl-C and the signal messages still work.
  List, filter, filter state and selection are untouched by the overlay.
- C. refilter() remembers the destination selected before the edit and re-selects it if still shown (shown is
  ascending, sort.SearchInts), else row 0 (also when nothing was shown). Render's stateless window keeps the
  selected row visible. Enter handling is unchanged.
- Tests: K9 test replaced by TestSelectionKeptAcrossFilterEdits and TestSelectionFarDownAndNoRowsBefore;
  added TestHighlight (mixed case, host-only, narrow, CJK, Enter, Esc, NO_COLOR, colour) and TestHelpOverlay.

## Results (real exit codes)
- go vet ./... and go test -count=1 ./... (prototypes/go): all packages ok, exit 0.
- prototypes/go/build.sh: exit 0; darwin-arm64, linux-x64, linux-arm64, windows-x64 all built.
- Darwin harness: conformance.py ... -> total 139, pass 136, fail 3, error 0, exit 1. The three failures are exactly
  the expected ones: tui.filter_edit_resets_selection, tui.no_color (first-row expectation after Esc),
  tui.large_100_filter_latency (predicate expects the list to start at the first match). K17 latencies in that
  check: all 30 edits updated the screen, max about 20 ms, so the 100 ms budget holds.
- Linux harness (tests/g02/linux/run.sh, linux-arm64 artifact): total 139, pass 136, fail 3, exit 1; the same three.
- Own pty+pyte check (scratch/e2e3.py, darwin artifact): underlined cells are exactly the first alias match and
  first host match; host-only match underlines only the host; 40 columns underlines only the alias; none after
  Esc clear; with NO_COLOR underline present and no colour SGR; the nine help lines in order; keys ignored in help;
  Esc closes with filter kept; Ctrl-C exit 130; `?` in filter mode is filter text; 20x5 help clipped without crash.

## Known gaps / notes
- Bubble Tea emits `CSI > 4 ; 2 m` (modifyOtherKeys) at start and exit. Stock pyte misreads this as SGR 4, so
  with an unfiltered pyte every cell painted before the first SGR reset looks underlined, regardless of this
  implementation. My own check strips `CSI > ... m` before feeding pyte. The harness's own emulator is stock pyte
  plus SU/SD, so an acceptance emulator must do the same filtering.
- The scroll window is stateless (existing design): when the selection is past the visible rows it sits on the
  last row. A kept selection is therefore always visible, but the window can jump after a filter edit.
- Esc outside filter mode with a kept filter still does nothing (unchanged behaviour).
- Windows build compiles; not run.
