# T3-go-opus2: TUI match underline, help overlay, selection kept across filter edits (Go prototype)

Workspace: /tmp/x2ws-65820374/heimdall (git-initialised; starting commit 10c8233 "starting point").
Scratch: /tmp/x2ws-65820374/scratch. Diff: diff.patch (from the starting commit, excluding prototypes/go/dist).

## What changed and why

### internal/tui/tui.go
- **A. Match underline.** `row()` builds each list row as plain text and records the rune spans to underline:
  - the first case-insensitive occurrence of the filter in the alias;
  - when the width is 50 or more, the first occurrence in the host as well.
  `matchRunes` uses the same `strings.ToLower` rule as `profile.Filter`. Positions are counted in runes, so they map onto the sanitized display text. `underline()` truncates the plain row to the width first, then inserts `ESC[4m` / `ESC[24m`, so underline is always closed inside the row. The prefix, separators, account, `@`, `:`, port and later occurrences are never underlined. An empty filter underlines nothing. Underline is not a colour, so it also appears under `NO_COLOR`, which still emits no colour SGR.
- **B. Help overlay.** Outside filter mode, `?` sets `help`, and `Render` replaces the list area with the nine lines `Keys` … `Ctrl-C cancel`, one per row. The status line stays. While the overlay is open, `?` and `Esc` close it (`Esc` does not clear the filter), `Ctrl-C` cancels (exit 130), and every other key is ignored. List, filter, filter mode and selection are not touched. At 20x5 the overlay is clipped by rows and columns.
- **C. Selection kept (replaces K9).** `refilter()` remembers the selected destination before an edit. If that destination is still shown, it stays selected; otherwise the first shown row is selected, which covers the case where no row was shown before. This applies to append, Backspace and the `Esc` clear in filter mode. The window start is still derived from the selection (`windowStart`), so a kept selection far down the list stays visible and the window stays full. `Enter` still keeps the selection.
- **Renderer workaround (wide characters).** With a CJK match at 20x5, I saw ultraviolet's cell-diff renderer draw `> vps- 京`. Its "overwrite" cursor optimisation (`relativeCursorMove`) produces an empty move when the parked cursor sits on a wide character's continuation cell. This code is unchanged in the newest pseudo-version (20261001). The model now returns `tea.ClearScreen` (a full repaint) after a key that changes the screen, but only while a double-width character is visible in the list rows or the filter. ASCII-only screens, including large-100 and K17, keep the cell diff.

### cmd/heimdall-proto/tui_output.go and main.go (one line)
- The TUI output is `pinnedSGROutput{os.Stdout}`. Bubble Tea writes `CSI > 4 ; 2 m` and `CSI > 4 m` (xterm modifyOtherKeys). pyte 0.8.2, and any emulator that ignores the `>` marker, reads them as SGR 4. Everything drawn afterwards then gets a stale underline, including the whole first frame. The wrapper appends SGR 0 after exactly these two controls. The renderer's pen is the default style at those points, so this does nothing on a conforming terminal. `Fd()` is kept by embedding, so terminal detection and size queries still work. `WriteString` is shadowed so it cannot bypass the wrapper.

### Tests
- internal/tui/tui_test.go:
  - The K9 test is replaced by `TestSelectionKeptAcrossFilterEdits` (append keeps or falls back to the first row, Backspace keeps, Esc clear keeps, empty-to-non-empty selects the first row, Enter keeps) and `TestSelectionKeptFarDownScrolls` (host-087 of 101 stays selected and visible, full window).
  - Underline: `TestMatchUnderline` (single, multi, mixed-case and CJK filters, host-only matches, widths 80 and 40, after Enter, first occurrence only, with and without NO_COLOR) and `TestNoUnderlineWhenFilterEmpty`. `TestUnderlineTruncated` checks widths 1 to 55 for no overflow and balanced underline.
  - Help: `TestHelpOverlay`, `TestHelpQuestionMarkInFilterMode`, `TestHelpOverlayTinySizes`.
  - `TestWideCharacterFullRepaint`.
- cmd/heimdall-proto: `TestPinSGR` and `TestPinnedSGROutputWrite`. `TestTUIUnderlineHelpEndToEnd` runs the real Bubble Tea program in a pty with NO_COLOR and checks the SGR 4 output, the pinned reset, no colour SGR, help open and close, and `SELECTED nas`.
- prototypes/go/REPORT.md: appended an "X2 task T3" section.

## Results (real exit codes)

| Command | Exit | Observed |
|---|---|---|
| `go vet ./...` (darwin), and with GOOS/GOARCH linux/arm64, linux/amd64, windows/amd64 | 0 | clean; gofmt -l empty |
| `go test -count=1 ./...` (darwin-arm64) | 0 | all packages ok (scratch/gotest.txt) |
| `GOOS=linux GOARCH=arm64 go test -c` for cmd/heimdall-proto and internal/tui | 0 | compile only |
| `sh prototypes/go/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all built (scratch/build.txt, dist/manifest.json) |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin …/darwin-arm64/heimdall-proto --candidate go --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | 1 | 139 total, 136 pass, 3 fail, 0 error, 0 skipped |
| `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` | 1 | 139 total, 136 pass, 3 fail, 0 error, 0 skipped |

On both platforms the three failures are exactly the ones TASK.md expects. Their failed assertions are only the K9-dependent ones:
- `tui.filter_edit_resets_selection`: "first shown row is selected" after append and after Backspace. The Enter and Down steps fail as a consequence, because the kept selection is vps-東京.
- `tui.no_color`: only "selected row still carries '> '" fails. "no color SGR in the whole session output" passes.
- `tui.large_100_filter_latency`: only the five "backspace to ''" updates are not counted (the list keeps host-070 selected, window host-048..070), so 25 of 30 updates are counted. The p95 assertion passes: 17.7 ms on darwin, 18.5 ms on linux.

The harness records carry `artifact_digest` sha256:87f81fb9… (darwin) and sha256:2ba1af26… (linux), matching artifacts.json.

### Additional checks (scratch scripts in scratch/probe, using the harness's pyte PtySession read-only)

All exit 0 on darwin-arm64 and in the linux-arm64 harness container (same image and flags as run.sh).
- **K17 under part C** (`k17c.py`): 5 sessions of 6 edits on large-100 at 80x24. An update counts when the status shows N/100, the rows are a full window of consecutive matches in profile order, and `> ` is on the part-C destination. Result: 30/30 updates counted, p95 18.7 ms on darwin and 19.8 ms on linux (k17-partc-darwin.json, k17c-linux.json).
- **Underlined cells** (`ulcheck.py`): checked cell by cell against part A over 23 steps. The steps cover the `a`, `aB`, Backspace, Enter, Esc, CJK `東`/`東京`, uppercase `EXAMPLE.i` host-only, help open/close, and Esc-clear filters. Sizes: 80x24, 40x24, 20x5, 49x10 and 50x10, with and without NO_COLOR. Result: 0 mismatches. Colour-SGR count is 0 for every NO_COLOR session.
- **Help overlay** (`helpcheck.py`) at 80x24 and 40x24:
  - all nine lines appear in order on rows 0-8;
  - j, k, q, /, x, Down, Up, Enter and Backspace are ignored;
  - Esc and `?` each restore the screen identically, and no help line remains;
  - Ctrl-C in help exits 130;
  - `?` in filter mode becomes filter text;
  - at 20x5 the overlay opens clipped, survives resizing, closes, and q exits 0.

## Known gaps and limits

- The wide-character repaint is a `tea.Cmd`, so it is asynchronous. If the renderer's ticker flushes the diff frame before the repaint message is processed, a CJK row can be misdrawn for about one frame (~16 ms) before the full repaint corrects it. I never observed this in the runs above. The root fix belongs in ultraviolet, which would need a vendored patch or an upstream fix.
- The SGR-pin wrapper assumes Bubble Tea writes each modifyOtherKeys control whole within one `Write`. `Program.flush` writes its whole buffer at once, so this holds today. A control split across writes would not be pinned; the only cost would be the emulator quirk returning.
- With TERM unset (colour profile NoTTY), no SGR is written at all, so there is no underline either. This is unchanged prototype behaviour; all tests use TERM=xterm-256color.
- Scrolling is still stateless: the window ends at the selection once the selection is past the first page, as before.
- In pyte the screen line after exit reads `SELECTED nas1u`, because pyte draws Bubble Tea's kitty-keyboard pop `CSI < 1 u` as text. The sequence comes from Bubble Tea's shutdown code, not from this change. That is inferred from the byte stream; I did not re-run the original binary to confirm it. The stdout bytes are exactly `SELECTED nas\n`, which the harness checks pass.
- Linux unit tests were compiled, not executed. Native Linux behaviour was exercised through the harness and probe scripts in the linux-arm64 container. windows-x64 was built only.
- No independent review was done; this is self-verified.
- **Housekeeping:** running the harness from the workspace created `tests/fixtures/fake-agent/__pycache__` and `tests/g02/__pycache__`. I deleted both, so tests/ and the fixtures are unchanged. No process I started is still running.
