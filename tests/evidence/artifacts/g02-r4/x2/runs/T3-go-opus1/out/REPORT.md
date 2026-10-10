# T3-go-opus1 (written by the orchestrator from the implementer's structured report; the Write tool refused out/REPORT.md)

Status: verified

All three TASK.md changes are implemented in the Go prototype TUI. On both darwin-arm64 and linux-arm64 the G02 harness 2.4.2 gives 136/139, and the only failures are the three checks TASK.md names as encoding K9. Unit tests pass on both platforms (exit 0).

One deliverable is missing: the Write tool refused /tmp/x2ws-3a7f9982/out/REPORT.md for this subagent. I did not get around that with shell writes, so its content is below. /tmp/x2ws-3a7f9982/out/diff.patch (git diff --cached 8a355bf, dist/ excluded; 9 files, +656/-46) and /tmp/x2ws-3a7f9982/out/artifacts.json were written.

=== REPORT ===

## Changes

- **A, match highlight** (prototypes/go/internal/tui/tui.go: matchSpan, highlight).
  - The first case-insensitive occurrence of the filter in the alias is wrapped in SGR 4 ... SGR 24. At 50 columns or wider, the first occurrence in the host is too.
  - Matching uses the filter's own rule (strings.ToLower, rune for rune), so rune positions line up with the Sanitize'd text.
  - Nothing else is underlined: not the '> ' prefix, separators, account, '@', ':', port, later occurrences, or the status line. An empty filter underlines nothing.
  - ansi.Truncate keeps the SGR pair when a match is clipped.
  - Underline still shows under NO_COLOR, because the ASCII colour profile keeps attributes.
- **B, help overlay** (help state, helpLines, renderHelp).
  - '?' outside filter mode opens it. In filter mode '?' is filter text.
  - The overlay replaces the list rows with the nine lines; the status line stays.
  - '?' or Esc closes it; Esc does not clear the filter. Ctrl-C cancels with exit 130. All other keys are ignored.
  - List, filter, filter mode and selection are unchanged after it closes. It clips at small sizes without crashing.
- **C, selection kept** (refilter).
  - After a filter edit, the previously selected destination stays selected if it is still shown; otherwise the first shown row is selected.
  - The existing scroll rule keeps the selected row visible with a full window.
- **Output guard** (new cmd/heimdall-proto/tui_output.go, sgrSafeOutput, wired in runTUI, which now takes an out *os.File).
  - Bubble Tea v2.0.10 always writes CSI >4;2m at start and CSI >4m at exit and cannot be told not to. pyte ignores the '>' and applies SGR 4.
  - I observed the result before the fix: the whole first frame was underlined, and stale cells stayed underlined after '/a'.
  - The guard sends CSI m after each XTMODKEYS sequence. On terminals that understand XTMODKEYS this changes nothing.
  - The wrapper keeps Fd() and does not embed *os.File, so WriteString and ReadFrom cannot bypass it.
- **Tests.**
  - TestK9SelectionAfterFilterEdit is replaced by TestSelectionKeptAcrossFilterEdits.
  - New: TestSelectionKeptFarDown, TestMatchHighlight, TestMatchHighlightTruncated, TestMatchSpan, TestHelpOverlay, TestHelpOverlayTinyAndResize, TestResetAfterXTMODKEYS, TestSGRSafeOutputWrite, and the pty test TestTUIUnderlineInPTY.
  - The cell-level tests parse frames with ultraviolet, the cell model Bubble Tea draws from.
  - k16_test.go and tui_k10_test.go call sites are updated. A short T3 section is appended to prototypes/go/REPORT.md.
  - go.mod and go.sum are unchanged.

## Results (real exit codes)

- gofmt is empty. go vet exits 0 for darwin, linux and windows.
- go test -count=1 ./... exits 0 on darwin-arm64, and 0 on linux-arm64 (native golang:1.27.1-bookworm container, network none, GOPROXY=off).
- Red checks: putting back K9's reset makes 3 tui tests fail; bypassing the guard makes the pty test fail. Sources were restored and tests pass again.
- build.sh exits 0 and builds all 4 targets. An independent rebuild of linux-arm64 gives the same sha256.
  - darwin-arm64: prototypes/go/dist/darwin-arm64/heimdall-proto, sha256 9ad3ce9cda53be94acb294977a14b3b6f3ddec37d7eb3fadc69a273371875b79.
  - linux-arm64: prototypes/go/dist/linux-arm64/heimdall-proto, sha256 9c24614158ee31949e81506ac1078025a60cb1f05100cfe39d8d7ebb989e16ee.
- Harness, darwin (scratch/harness-darwin.json): exit 1, 136 pass, 3 fail, 0 error.
- Harness, linux-arm64 (scratch/harness-linux.json): exit 1, 136 pass, 3 fail, 0 error.
- The 3 failures on both platforms:
  - tui.filter_edit_resets_selection: '> ' stays on vps-東京, which is still shown.
  - tui.no_color: only the '> on lab-server' step fails, because nas stays selected. The no-colour-SGR assertion passes.
  - tui.large_100_filter_latency: the backspace-to-'' window ends at the kept host-070 instead of starting at host-000. Of the 25 updates its predicate accepted, p95 was 20.5 ms (darwin) and 18.9 ms (linux).
- K17 under the part C predicate (my own probe, scratch/probe/k17c.py): 30/30 edits. darwin p95 22.8 ms, max 24.1 ms. linux-arm64 p95 23.2 ms, max 24.0 ms.
- Black-box pty+pyte probe (scratch/probe/probe.py, identical output on darwin and linux):
  - Underlined cells are correct for single, mixed-case, host-only and CJK matches, after Enter, at 40 columns, and after Esc.
  - The help shows the 9 lines in order and ignores other keys. Esc closes it and keeps the filter. '?' in filter mode is filter text. 20x5 clips without a crash.
  - Ctrl-C with the help open exits 130.
  - With NO_COLOR the SGR parameters seen were only '' and '4'.
  - On large-100, after 90 Downs, the selection stays on host-090 through filter edits, and Enter prints SELECTED host-090-lab with exit 0.

## Known gaps

See limitations: no independent review; no underline when TERM is unset or dumb; the guard only works within a single Write call; scrolling is still stateless; Windows was not run.

## Commands run
- `git init && git add -A && git commit -m 'starting point' (workspace)` exit 0: starting commit 8a355bf
- `gofmt -l . ; go vet ./... (darwin/arm64, GOOS=linux, GOOS=windows)` exit 0: gofmt empty; vet exit 0 on all three
- `GOFLAGS=-mod=readonly go test -count=1 ./... (darwin-arm64)` exit 0: all packages ok; log scratch/go-test-darwin.txt
- `docker run golang:1.27.1-bookworm --network none (ro workspace, ro modcache, GOPROXY=off) go test -count=1 ./... (linux-arm64)` exit 0: all packages ok; log scratch/go-test-linux-arm64.txt
- `red check: K9 reset restored in refilter -> go test ./internal/tui/` exit 1: TestSelectionKeptAcrossFilterEdits, TestSelectionKeptFarDown, TestMatchHighlight fail; source restored, tests pass again
- `red check: sgrSafeOutput bypassed -> go test -run TestTUIUnderlineInPTY ./cmd/heimdall-proto/` exit 1: fails; source restored, cmd package ok (exit 0)
- `sh prototypes/go/build.sh` exit 0: built darwin-arm64, linux-x64, linux-arm64, windows-x64; independent linux-arm64 rebuild sha256 identical
- `tests/g02/.venv/bin/python tests/g02/conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate go --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` exit 1: 136/139 pass; fail = tui.filter_edit_resets_selection, tui.no_color (only the '> on lab-server' step; no-colour-SGR assertion passes), tui.large_100_filter_latency (backspace-to-'' window predicate) -- exactly the three K9-encoding checks named in TASK.md
- `sh tests/g02/linux/run.sh --artifact-dir dist/linux-arm64 --candidate go --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` exit 1: 136/139 pass; same three expected failures; all others pass
- `scratch/probe/k17c.py (K17 with part-C predicate, 5 sessions x 6 edits, 80x24) darwin and linux-arm64 harness container` exit 0: darwin 30/30 edits p95 22.8 ms max 24.1; linux 30/30 p95 23.2 ms max 24.0
- `scratch/probe/probe.py (pty+pyte black-box: underline cells, help overlay, ? in filter mode, NO_COLOR, 20x5, far-down selection) darwin and linux-arm64` exit 0: identical output on both; correct underline cells; help 9 lines in order; Ctrl-C in help 130; SELECTED host-090-lab exit 0; NO_COLOR SGR params only '' and '4'
- `git apply -R --check ../out/diff.patch; grep HEIMDALL_CANARY_ in out/ and scratch logs` exit 0: patch consistent; no canary found

## Limitations
- No independent review was done; all review was self-review.
- Underline is dropped when TERM is unset or dumb: colorprofile returns NoTTY, which removes every attribute. The selection colour was already dropped there. The acceptance setup, TERM=xterm-256color, is unaffected.
- The XTMODKEYS guard only matches a sequence inside a single Write call. Bubble Tea writes each flush in one Write today.
- Scrolling is stateless as before: once the selection is past the first window, it is pinned to the bottom row. Unchanged and not requested.
- There is no help hint in the status line. It was not requested, and adding one would change the harness's status parsing.
- Windows was only compile-checked (vet with GOOS=windows), not run.
- The K17 measurement under the part C predicate comes from my own probe, not from the hidden acceptance test.
- The darwin harness run created tests/fixtures/fake-agent/__pycache__/. I removed it; no fixture content was edited.

## Escalations
- The task asked for /tmp/x2ws-3a7f9982/out/REPORT.md, but the Write tool refused it for this subagent ('Subagents should return findings as text, not write report files'). I did not go around that block with shell writes, so out/REPORT.md does not exist. Its full content is in this summary. diff.patch and artifacts.json were written.
- Possible pyte problem in the acceptance emulator: Bubble Tea v2.0.10 always sends XTMODKEYS (CSI > 4;2 m at start, CSI > 4 m at exit). pyte 0.8.2 ignores the '>' and treats these as SGR 4, so a Go TUI looks fully underlined in pyte until cells are redrawn. I worked around it in the prototype by sending SGR reset right after each XTMODKEYS (sgrSafeOutput). The harness owners may want to know that stock pyte mis-parses CSI > ... m.
