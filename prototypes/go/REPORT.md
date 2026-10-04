<!-- Written by the M00 orchestrator from the go prototype agent's returned report (the subagent runtime refused direct REPORT.md writes). Content is the agent's text, unedited, except: statements made stale by the §9 alignment (M00-T05-go-align, 2026-10-03) are marked inline with "[§9 update]", and the section "§9 alignment (2026-10-03)" is appended at the end. Round 2 (M00-T05-go-round2-fix) marks its corrections inline with "[Round 2 update]" and appends the section "Round 2 (2026-10-03)". -->

# G02 Go + Bubble Tea prototype — report (M00-T05-go)

This is disposable gate evidence, not production code. Contract: docs/g02/slice-contract.md. Every result below was observed from commands run 2026-10-02/03 UTC. Raw outputs are in tests/evidence/artifacts/g02-go/selftest/. Base commit: 18bb8dfa841c488247421952c43e50d12980a4f2 (prototype files are uncommitted). The shared harness tests/g02/conformance.py did not exist during the work and was NOT run. [§9 update: during the alignment it was run read-only as information only, not as the verdict: 111/111 on darwin-arm64; see the §9 section.]

## 1. Versions (observed)
- Go: go1.27.1 darwin/arm64. Latest releases listed on go.dev: go1.27.1 and go1.26.8.
- Bubble Tea: charm.land/bubbletea/v2 v2.0.10, released 2026-09-24. Its go.mod declares the charm.land path; the github.com/charmbracelet/bubbletea/v2 path resolves to the same commit. No v3 exists; the v1 line ends at v1.3.10.
- TOML: BurntSushi/toml v1.6.0.
- Named pipes: Microsoft/go-winio v0.6.2 (MIT).
- Terminal helpers: charmbracelet/x/ansi v0.11.8 and x/term v0.2.2.
- x/sys: v0.46.0 (chosen by MVS; latest is v0.48.0).
- Lockfile: go.mod + go.sum; `go mod verify` reports all modules verified.
- Audit tools: go-licenses v2.0.1, govulncheck v1.8.0. govulncheck found no vulnerabilities for darwin, linux or windows.
- Docker 29.8.0 with alpine:3.22 and python:3.13-alpine.
- User-level additions: Go module downloads into ~/go/pkg/mod, tools installed in /tmp/hp-go-ev/bin, a Python venv at /tmp/hp-go-ev/venv (jsonschema 4.25.1), and the Docker image pulls above.

## 2. Structure (domain code shared by CLI and TUI)
- cmd/heimdall-proto: CLI wiring only.
- internal/result: JSON envelope and exit-code mapping.
- internal/profile: Load/Parse/validate, plus a pure Filter function.
- internal/agent: a pure bounded frame parser (frame.go), the probe (probe.go), and dial_unix.go / dial_windows.go.
- internal/run: run.go, run_unix.go, run_windows.go.
- internal/tui: the Bubble Tea model, which uses profile.Load and profile.Filter.

Total: 2,218 lines including tests. [§9 update: 2,780 lines after the alignment.]

## 3. Contract coverage
- §1: every emitted JSON document validates against the schema (21/21).
- §2 profile show: all 9 fixtures, the oversize file and the missing file give the expected code and exit. The canary never appears in any output. Spaced and Unicode paths work. A file of exactly 1 MiB is accepted; 1 MiB+1 is rejected before parsing.
- §3 agent list, Unix: implemented and tested. All crafted bad frames are rejected: oversize length, length 0xFFFFFFFF, huge or above-limit nkeys, nkeys larger than the frame, a string past the frame end, trailing bytes, truncated header or body, wrong message type, failure, failure plus trailing bytes, and a bad key type inside the blob. The request sent is exactly 00 00 00 01 0b. SIGINT cancel latency was 2.1 ms; a 300 ms timeout returned in 0.305 s.
- §3 Windows named pipe: compile-checked only, never run.
- §4 run, Unix:
  - argv passes through byte-for-byte: spaces, quotes, $, ;, *, newlines, non-ASCII, empty strings, backslashes, invalid UTF-8.
  - stdin/stdout bytes pass through unchanged (NUL, invalid UTF-8, ESC).
  - Exit codes pass through; death by signal gives 128+N with `signal` set in the meta file.
  - Launch failure gives exit 127 and CHILD_LAUNCH_FAILED.
  - SIGINT, SIGHUP, SIGWINCH and SIGTERM are each forwarded exactly once.
  - The child is reaped (no zombie).
  - Ctrl-C in a pty reaches the child once. A signal to heimdall's process group reaches the child once. Background job then `fg`: each signal reaches the child once.
- §4 Windows: compile-checked only.
- §5 TUI (tested in a pty):
  - Enters the alternate screen and hides the cursor.
  - On select, q, Ctrl-C and SIGTERM it exits 0, 0, 130 and 143. Each time it leaves the alternate screen, shows the cursor, and leaves termios byte-identical to before. [§9 update: SIGHUP and terminal hangup now exit 129 (K10).]
  - SELECTED is printed after leaving the alternate screen.
  - Filtering works with 東京, Backspace, Esc (clears) and Enter (keeps), and on the 100-destination fixture.
  - Resizes to 20x5, 49x10 and 120x40 redraw within 100 ms.
  - With NO_COLOR set there are zero color SGR sequences. Without a TTY it exits 2.
  - Restore after a panic relies on Bubble Tea's recover handler; not verified. [§9 update: now tested in-process in a pty: exit 1, alternate screen left, cursor shown, termios identical (K10).]
- §6 version: tui_framework_version is read from the embedded build info (v2.0.10).
- §7 build: all four targets build.

## 4. Build (`sh build.sh` run from /, exit 0; CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags "-s -w")

[§9 update: the table below is the attempt-1 build. Those artifacts were replaced; current sizes and digests are in the §9 section and dist/manifest.json.]

| Target | Bytes | sha256 | Run without toolchain? |
|---|---|---|---|
| darwin-arm64 | 5,190,642 | dd1d270c… | yes, via env -i; links only libSystem and libresolv |
| linux-x64 | 5,406,880 | ed97bf84… | yes; static ELF, alpine under Docker emulation |
| linux-arm64 | 5,111,968 | 7279c8af… | yes; static ELF, alpine in the Docker VM |
| windows-x64 | 5,073,920 | c16f99d2… | BLOCKED, never executed |

- Two builds in a row gave identical sha256 for all four artifacts. That is a local repeat-build check, not a reproducible-build claim.
- The darwin binary is unsigned (ad-hoc signature only) and not notarized.
- Startup on an M5 Max: `version --json` median 2.85 ms, max RSS 7.2 MB; `profile show large-100` median 3.34 ms, max RSS 8.0 MB. [Round 2 update: these are attempt-1 numbers. For the round-2 artifact: 2.96 ms / 7.1 MiB and 3.51 ms / 7.7 MiB (median of 50, see the Round 2 section). tests/evidence/g02-measurements.json is the measurement record of record.]

## 5. Tests (exit codes)
- `go test ./...` on darwin-arm64: 0.
- Cross-compiled tests in alpine linux/arm64 and linux/amd64: 0 for every package.
- `go vet` on all four targets: 0.
- Windows `go test -c` (compile only): 0.
- Black-box selftest: 35/35 on darwin and 35/35 in each Linux container. [§9 update: the selftest now has 59 checks; 59/59 on darwin and in each Linux container.]
- Schema check: 21/21. [§9 update: 23/23.]
- One mistake in my own test (a wrong frame length) was correctly rejected by the prototype; I fixed the test, not the prototype.

## 6. Time, difficulty, workarounds
About 25 minutes from module init to green tests on all runnable platforms. The hard part was `run` signal semantics; the TUI was easy.
- [§9 update: the three-mode scheme below was replaced for K6; mode (b) dropped an explicit SIGINT sent to heimdall while its job was in the foreground. See the §9 section for the current model.] Go's os/signal gives no siginfo, so heimdall cannot tell a terminal-generated SIGINT from an explicit kill. The workaround picks one of three modes at launch:
  - (a) heimdall owns the terminal foreground: the child gets its own process group and becomes the foreground group (Setpgid + Foreground + Ctty). Anything heimdall receives is then explicit and is forwarded.
  - (b) a terminal exists but heimdall is a background job: the child stays in heimdall's group. SIGINT, SIGQUIT and SIGWINCH are not forwarded while that group holds the terminal foreground.
  - (c) no terminal: the child gets its own group and every signal is forwarded.
- Because of this, the code waits with wait4(WUNTRACED) directly and propagates job-control stops itself.
- Bubble Tea maps SIGTERM to the same quit message as `q`. Fix: WithoutSignalHandler plus a custom handler.
- Bubble Tea reads TEA_TRACE and TEA_DEBUG from the environment and writes files when they are set, which breaks the no-file-writes rule. Fix: unset both before starting.
- Bubble Tea drops color when TERM is unset; NO_COLOR is honored.
- macOS pty quirk in the selftest: the slave fd is revoked when the session leader exits, so termios is read through the master.

## 7. Known defects
- Windows was not executed.
- .bat/.cmd targets: cmd.exe re-parses the command line, so Go's CommandLineToArgvW quoting does not protect them (Go's docs say so). Not mitigated.
- Windows Ctrl-C: the console delivers it to the child directly; heimdall swallows its own copy and does not forward it. No CTRL_BREAK or close-event handling.
- macOS: a small race could forward a signal to a reused PID right after the child is reaped.
- A terminal hangup can deliver SIGHUP to the child twice.
- The Ctrl-Z path is not verified.
- SIGKILL to heimdall leaves the child running.
- No peer-credential check on the Unix socket, and no check of the Windows pipe server's identity.
- ErrDot gives exit 127. [§9 update: allowed (K7).]
- Control characters in profile values are JSON-escaped in `profile show`. [§9 update: fixed; now exit 2 SCHEMA_INVALID (K2).]
- Output without --json is plain text. [§9 update: allowed and not judged (K12).]
- No NOTICE file is shipped.
- No independent review.

## 8. Native/unsafe components
- CGO_ENABLED=0. Linux binaries are fully static; macOS links libSystem as every Go binary does.
- No `unsafe` in prototype code. Dependencies (x/sys, go-winio, charmbracelet/x/windows, termios) use syscalls and unsafe internally; not audited.
- No runtime downloads and no network access at runtime.

## 9. Windows notes (compile-checked only)
- Agent probe: winio.DialPipeContext. Paths must start with \\.\pipe\. Uses a deadline and closes the connection on cancel. x/sys/windows would be a dependency-free alternative.
- Ctrl-C arrives as os.Interrupt.
- Command lines are built by os/exec makeCmdLine/appendEscapeArg.
- No ConPTY: the child inherits the console, so resize is native. Bubble Tea v2 reads console input through charmbracelet/x/windows and ultraviolet.
- run_test.go is Unix-only.

## 10. Maintenance signals
- Bubble Tea v2.0.10 (2026-09-24); repo active.
- Bubble Tea pins an untagged pseudo-version of charmbracelet/ultraviolet. Ultraviolet has no release tags at all; the latest pseudo-version is from 2026-10-01. This is a stability and supply-chain signal.
- x/ansi v0.11.8 (2026-08-11); colorprofile v0.4.3 (2026-03-09).
- toml v1.6.0 (2025-12-18).
- go-winio v0.6.2 is an old tag (2024-04-09), but the repo was pushed 2026-09-30.
- cancelreader v0.2.2 dates from 2022.
- Bubble Tea pins xo/terminfo at a 2022 pseudo-version, while v1.2.0 exists (2026-09-13).

## 11. Iroh for Go
- Rust iroh is at 1.3.0 (crates.io).
- There is no official Go binding. iroh-ffi v1.1.0 covers Python, Swift, Kotlin and JS.
- The community binding git.coopcloud.tech/decentral1se/iroh-go (v0.0.0-20260830120307-d6233351aba3, no tags) calls itself "Highly Experimental". It needs CGO_ENABLED=1 and a Rust staticlib, targets iroh 1.0.3, and supports linux-musl x86_64/aarch64 only.
- Assessment: Go would need a supervised Rust helper built against iroh 1.3.0, which adds a second toolchain and a second artifact. This is an observation, not a decision.

## 12. Licensing
- Linked dependencies are all MIT or BSD-3-Clause (see LICENSES.md, generated with go-licenses v2.0.1). Attribution notices are required in binary distributions and are not shipped yet.
- The prototype itself has no license.
- iroh is Apache-2.0 OR MIT.

## 13. Escalations
See the escalations list.

## §9 alignment (2026-10-03)

Task M00-T05-go-align: bring the prototype in line with docs/g02/slice-contract.md §9 (K1-K12) with the smallest changes. Every result below was observed on 2026-10-03 UTC. Raw outputs are in tests/evidence/artifacts/g02-go/selftest/k-align-20261003/. The evidence record tests/evidence/g02-go-selftest.json keeps attempt 1 and adds attempt 2. Base commit is unchanged (18bb8df; prototype files uncommitted). go.mod and go.sum are unchanged.

### K1-K12

| Ruling | Result | Change | Proof (native) |
|---|---|---|---|
| K1 control characters in agent output | already conformed | none (`SafeText` already maps invalid UTF-8 and every C0, TAB, DEL and C1 code point to U+FFFD) | `TestK1ControlCharactersInIdentity` (every code point 0x00-0x1F, 0x7F-0x9F in key_type and comment); selftest `agent.k1_controls_replaced` |
| K2 control characters in profile values | **changed** | internal/profile/profile.go: `name`, `id`, `alias`, `host`, `account` and each label are rejected with SCHEMA_INVALID when they contain a C0 (including TAB), DEL or C1 code point. `key_path` names the key; the message is fixed text and never contains the value. `[meta]` is untouched. | `TestK2ControlCharactersInValues` (9 control forms x 6 keys, canary never echoed, meta tolerated); selftest `profile.k2_*` (6 cases + `profile.k2_meta_tolerated`); schema_check `profile:k2-control-value`. Before the change: 6/6 selftest cases gave exit 0 PROFILE_OK with the canary on stdout. |
| K3 agent EOF | **changed** | internal/agent/frame.go: EOF before any response byte returns `ErrNoResponse`, which probe.go classifies as AGENT_UNAVAILABLE. EOF after 1+ bytes stays AGENT_PROTOCOL_ERROR. | `TestK3EOFClassification`; selftest `agent.k3_eof_zero_bytes`, `agent.k3_eof_after_one_byte`, `agent.k3_eof_mid_body`; schema_check `agent:k3-eof-zero-bytes`. Before: zero-byte EOF gave AGENT_PROTOCOL_ERROR. |
| K4 failure frame shape | already conformed | none | `TestK4FailureFrameShape` (end to end), `TestParseRejects` "failure+trailing"; selftest `agent.k4_failure_with_payload`, `agent.k4_failure_len1` |
| K5 meta `state` | already conformed | none | `TestK5MetaState` (exit 0, exit 4, death by SIGTERM -> `succeeded`; launch failure -> `failed`); selftest `run.k5_meta_state` |
| K6 signal mechanism | **changed** | internal/run/run_unix.go (rewritten signal model, below) | selftest `run.k6_foreground_explicit_sigint_once`, `run.k6_bg_fg_explicit_and_terminal_once_each`, plus the existing `run.tty_ctrl_c_once`, `run.group_sigint_once`, `run.shared_tty_bg_then_fg_once_each`, `TestForwardSignalsAndReap`. Red check: the same sources with the attempt-1 run_unix.go fail `run.k6_bg_fg_explicit_and_terminal_once_each` (exit 12, want 13): the explicit SIGINT sent while the background job was in the foreground was dropped. |
| K7 PATH lookup | statement | none. A match through an empty or `.` PATH entry (Go `exec.ErrDot`) is refused with exit 127 and CHILD_LAUNCH_FAILED. Not tested, as K7 allows. | - |
| K8 invalid UTF-8 argv | already conformed | none | `TestInvalidUTF8ArgBytes`, `TestArgvPassthroughAndExitCode`; selftest `run.k8_invalid_utf8_argv_bytes` (bytes `ff fe 80 ... c3 28 ... ed a0 80` reach the child unchanged) |
| K9 selection after a filter edit | already conformed | none (`refilter` already resets the selection on append, Backspace and Esc; Enter only leaves filter mode) | `TestK9SelectionAfterFilterEdit`; selftest `tui.k9_append_resets`, `tui.k9_backspace_resets`, `tui.k9_esc_resets`, `tui.k9_enter_keeps` |
| K10 TUI exit codes | **changed** | cmd/heimdall-proto/main.go: TUI running moved into `runTUI`. It handles SIGHUP (exit 129) and maps a recovered panic to exit 1. A small input wrapper (`hangupInput`) turns EOF/EIO on the terminal into a hangup (129). internal/tui/tui.go: `HangupMsg` and the `HungUp` outcome. SIGTERM -> 143 was already in place. | `TestK10PanicRestoresAndExits1`, `TestK10SIGHUPRestoresAndExits129`, `TestK10TerminalHangupNoSignalExits129` (real pty, darwin and Linux); selftest `tui.k10_sighup_restores_129`, `tui.k10_hangup_master_close_129`, `tui.sigterm_restores`. Before: SIGHUP killed the process by signal (exit -1 in the selftest) with the terminal not restored. Red check: without the wrapper, a hangup with no SIGHUP left the picker running on macOS. |
| K11 native code and sidecars | already conformed | none. One static executable per target (CGO_ENABLED=0), no sidecars, no extraction. The manifest has no `sidecars` array because there are none. | selftest `k11.no_writes_no_sidecars` (version, profile show, agent list, run, tui with an isolated HOME/TMPDIR/cwd and TEA_TRACE/TEA_DEBUG set: nothing written; no extra files beside the executable); schema_check accepts the optional `sidecars` array |
| K12 output without `--json` | statement | none. Plain text, not judged. Exit codes come from the same mapping as with `--json`. | - |

### K6: current signal model (internal/run/run_unix.go)
- The child always runs in its own process group. If heimdall's group holds the terminal foreground at launch, the child's group becomes the foreground group (`Setpgid` + `Foreground` + `Ctty`).
- The kernel sends a terminal-generated signal only to the foreground group. It therefore reaches either the child or heimdall, never both. Every signal heimdall receives (SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH) is forwarded exactly once. There is no longer any case where a signal is skipped, so an explicit `kill -INT <heimdall pid>` reaches the child once in every state.
- Terminal ownership: a watcher checks every 50 ms whether heimdall's group holds the foreground (for example after the shell's `fg`, which need not send any signal). If it does, the watcher hands the foreground to the child's group. Until that handoff, a terminal Ctrl-C goes to heimdall and is forwarded once.
- Job control: when the child stops, heimdall mirrors the stop onto its own group (never with SIGSTOP), so the shell sees the job stop. On resume it hands the terminal back only if its group is in the foreground, which avoids taking the terminal after `bg`. A SIGTTIN/SIGTTOU stop in the brief window before the handoff is resolved by handing over the terminal and continuing the child.
- On exit, heimdall restores the foreground to its own group only if the child's group holds it.
- Known gaps: Ctrl-Z/`bg`/`fg` after a stop has no automated test. A process whose controlling terminal is not on stdio does not hand the terminal to the child (unchanged). Terminal hangup can still deliver SIGHUP to the child twice (kernel + shell). The PID-reuse race and the SIGKILL orphan noted in §7 remain. Since the child is never in heimdall's group, a `killpg` of heimdall's group now reaches the child only by forwarding, which is the K6 intent.

### K10 notes
- The panic path cannot be triggered in the shipped binary, which has no test hook. It is tested in-process with a test-only model wrapper that panics, running against a real pty. Bubble Tea prints "Caught panic" and a stack trace to stderr; nothing goes to stdout.
- On macOS, Bubble Tea's input reader treats EOF as a silent stop. That is why `hangupInput` exists. On Linux the tty read fails with EIO, which is also mapped to 129.
- A test-harness pitfall, recorded so it is not repeated: calling `(*os.File).Fd()` on the pty master makes it blocking, and `Close()` then waits for the pending `Read`, so the pty never hangs up. The test helper uses `SyscallConn` instead.

### Tests and build (2026-10-03, exit codes as observed)
- `go test -count=1 -v ./...` on darwin-arm64: exit 0 (5 packages).
- Linux test binaries (`go test -c`) in alpine:3.22 containers: exit 0 for all 5 packages on linux/arm64, and on linux/amd64 under emulation.
- `go vet` on darwin/arm64, linux/amd64, linux/arm64 and windows/amd64: exit 0. Windows `go test -c`: exit 0. `gofmt -l`: empty. `go mod verify`: ok. `go mod tidy -diff`: exit 0.
- `sh build.sh` run from /: exit 0, 4/4 targets. A second run produced identical sha256 values. No sidecars.

| Target | Bytes | sha256 |
|---|---|---|
| darwin-arm64 | 5,207,474 | 8a3a4fcc136bfe4df7b098f180bb97a9c100c4bc034a9a7ad945a805b9c7f64c |
| linux-x64 | 5,423,264 | 0a16dac34821acadfc95a00917cbc23ad38589e16ee2a88543a931bbb66965a5 |
| linux-arm64 | 5,111,968 | 9a072063d311a356ded98fded373c5534191e7a6c4f8d0e2ddce52cfe2a09614 |
| windows-x64 | 5,084,160 | cf6a7386697015452954ffd84d70b3356373317ffd493f80178f2dc701db5a09 (built, never executed) |

- Black-box selftest (tests/evidence/artifacts/g02-go/selftest/selftest.py, now 59 checks):
  - darwin-arm64: 59/59, exit 0; repeated three more times, 59/59 each.
  - python:3.13-alpine linux/arm64: 59/59.
  - python:3.13-alpine linux/amd64 (emulated): 59/59.
  - The first linux/amd64 run of the new K11 check failed: `$HOME/.cache/rosetta` appeared. A control program (`/bin/true`) creates the same directory under Rosetta, so the check now subtracts what a control program writes. See linux-x64-emulation-k11-control.txt.
- schema_check.py: 23/23 documents valid, manifest shape PASS, exit 0.
- `env -i PATH=/usr/bin:/bin dist/darwin-arm64/heimdall-proto version --json`: exit 0, no Go on PATH.
- For information only (not the verdict, since the harness was changing concurrently): the shared harness run read-only against dist/darwin-arm64 reported 111/111, exit 0.

### Remaining limits
- Windows: nothing executed.
- linux-x64 ran only under emulation.
- The tests were written by the prototype agents; there was no independent review.
- prototypes/go/bin/heimdall-proto is a stale development build whose exact source is unknown. Its K6 behavior differs from the attempt-1 source. It is not a deliverable.
- The selftest leaves empty `hpa*` socket directories in /tmp.
- [Round 2 update: resolved by ruling K3a and fixed in round 2.] Escalation (not decided here): K3 does not say how to classify a connection *reset* after one or more response bytes but before a complete frame. After one or more bytes, the prototype returns AGENT_UNAVAILABLE for a reset (a non-EOF read error) and AGENT_PROTOCOL_ERROR for EOF. The EOF case is tested; the reset case is not.

## Round 2 (2026-10-03)

Task M00-T05-go-round2-fix fixes the defects from the round-1 adversarial review (tests/evidence/artifacts/m00-wf3/review-go.json) and applies rulings §9.1 K6a and K13-K16 with the smallest changes that do the job.

- Every result below was observed on 2026-10-03 UTC, on darwin-arm64 (native) and on linux-arm64 (native arm64 kernel 7.0.14-linuxkit in the Docker Desktop VM, digest-pinned images, `--network none`).
- Raw outputs are in tests/evidence/artifacts/g02-go/selftest/round2-20261003/. The record tests/evidence/g02-go-selftest.json keeps attempts 1-2 and adds attempt 3.
- Base: HEAD b44c312; the prototype files are uncommitted.
- "Red" means a run against the round-1 sources (snapshot taken at round-2 start, with the round-2 test files copied in) or against the round-1 artifacts. Every fix below has a native test that is red before the change and green after it.

### Defect and ruling table

| Review defect / ruling | Outcome | Where / proof |
|---|---|---|
| **major** K3a: a reset after ≥1 response byte gave AGENT_UNAVAILABLE (Linux) | **fixed** | `internal/agent/frame.go` treats ECONNRESET like EOF in the same position (`reset_unix.go`; `reset_windows.go` maps WSAECONNRESET/broken-pipe errors, compile-only). Tests: `TestK3aResetClassificationReadFrame`, plus `TestK3aResetEndToEnd`, which uses a real AF_UNIX peer that closes with the request unread and fails on Linux unless the kernel really delivered ECONNRESET. Linux arm64 before: 3 subtests fail; after: pass (k3a-linux-arm64-red-green.txt). Reviewer agent_probe on Linux: before 31/34 (3 K3a mismatches), after 34/34. |
| **major** profile parser: quadratic memory and CPU (BurntSushi/toml) | **fixed** with a guard (K15) | `internal/profile/guard.go` runs a linear, allocation-free structural pre-scan before `toml.Decode` and rejects with SCHEMA_INVALID when a key path is deeper than 32 levels, there are more than 65,536 key components and containers, or the full key paths of all keys add up to more than 2 MiB. Proof: `TestK15ParserResourceBound` (real process, watchdog), `TestGuardSyntax`, `TestGuardAcceptsValidCorpus` (all 289 parser-valid toml-test documents accepted), FuzzGuard 30 s. k15_probe.py over 32 shapes: before 25/32 on darwin and on Linux (killed above 1 GiB); after 32/32 on both. The worst accepted case was 75.8 MiB (darwin) and 77.1 MiB (Linux); the slowest took 0.083 s. |
| **major** `run` takes the terminal from its own pipeline (K6a) | **fixed** | `internal/run/run_unix.go` uses a new mode model (below); process-group membership comes from `group_darwin.go` (sysctl kern.proc.pgrp) and `group_linux.go` (/proc). Proof: selftest `run.k6a_pipeline_*` (5 cases) and `run.k6a_async_job_of_script`, each with a control run without heimdall. Round-1 artifact: darwin bash 3/6 fail, Linux ash 5/6 fail, Linux bash 5/6 fail. After: 6/6 on all three. The reviewer's pipeline probe: before, 2/4 (darwin) and 4/4 (Linux ash) heimdall cases never got the line; after, 4/4 on both. |
| **major** TUI runs `tmux info` from PATH when TMUX is set (K16) | **fixed** | `cmd/heimdall-proto/main.go` `colorProfileNoExec` calls `colorprofile.Detect` with TMUX removed and passes `tea.WithColorProfile`, so Bubble Tea never calls Detect itself. colorprofile is now a direct dependency, same v0.4.3. Apart from `run`'s own `os/exec`, the only process-spawning code in the linked dependency graph is colorprofile's tmux call, Bubble Tea's `ExecProcess` and the x/sys `unix.Exec` wrapper; the last two are unused. Proof: `TestK16TUINoHelperProcesses` puts fake tmux/tput/infocmp/stty/screen on PATH and sets TMUX, TERM=tmux-256color and TERM_PROGRAM=tmux; red: `tmux info` ran. The reviewer's tui_env_probe: before, tmux was executed and a 5 s hang delayed the first frame; after, it is never executed. |
| K6a inherited-ignored SIGINT / SIGHUP | **fixed** | `run_unix.go` does not `Notify` a signal for which `signal.Ignored` is true, so it is not forwarded and the child inherits SIG_IGN. Proof: selftest `run.k6a_inherited_ignore_int_hup`. Round 1: exit 129 and the child had SIGHUP at default. After: exit 5 (child unaffected), with SIGINT and SIGHUP both ignored. |
| K6a inherited-ignored **SIGQUIT** (also SIGTERM, SIGWINCH) | **stack limitation** | The Go runtime installs its own handler for these signals whatever the inherited disposition (`runtime/signal_unix.go` `sigInstallGoHandler` respects SIG_IGN only for SIGHUP and SIGINT). `clearSignalHandlers` then resets them to SIG_DFL in the exec'd child, and `os/signal.Ignored` reports false for them, so the original disposition cannot be read. Observed on darwin and Linux: the selftest OBSERVE line shows child `SIGQUIT=dfl`; in the informational shared-harness `run.k6a_inherited_ignore` [async-job], the child had SIGQUIT SIG_DFL and heimdall exited 131. Not routed around: guessing SIGQUIT from SIGINT is a heuristic, and `//go:linkname` to `runtime.fwdSig` is a private-API hack. A production option is a cgo constructor that reads the dispositions with `sigaction` before the runtime starts and restores SIG_IGN with `signal.Ignore`, at the cost of cgo and a dynamic libc. |
| K6a: controlling terminal not on stdio (round-1 known gap) | **fixed** | `controllingTTY` falls back to `/dev/tty` (O_RDONLY, O_NOCTTY, O_NONBLOCK). Because macOS answers TIOCGPGRP on pipes too, a descriptor counts as a terminal only if it is a tty and TIOCGPGRP succeeds. Proof: selftest `run.k6a_ctty_not_on_stdio_child_reads_tty`. Round 1: the child was stopped by SIGTTIN forever. After: it reads the line, exit 0. |
| K6 regression found during round 2 | **fixed** | The first round-2 build also treated a piped *stderr* as a pipeline, so an explicit SIGINT under the harness's pty shim (stderr piped) was not forwarded. Only stdin and stdout count now. New selftest `run.k6_foreground_explicit_sigint_once_stderr_piped` (red: red-round2-build1-stderr-piped-darwin-arm64.txt). |
| K14 non-regular `--file` | **fixed** | `internal/profile/profile.go` `Load` stats the path before opening, opens with O_NONBLOCK (`open_unix.go`), then checks fstat and SameFile. Proof: `TestK14NonRegularFiles` (FIFO, symlink to a FIFO, socket, directory, /dev/null). Red: the FIFO blocked for more than 2 s and /dev/null gave SCHEMA_INVALID. The TUI uses the same `Load`. |
| minor GODEBUG=execerrdot=0 re-enables `.` PATH matches | **fixed** | `internal/run/run.go` refuses a bare name that resolves to a relative path, whatever GODEBUG says. Proof: `TestDotPathRefusalNotEnvironmentControlled`, with PATH `.`, `:/usr/bin` and `/usr/bin::/bin` under three GODEBUG values; red: it ran. |
| minor FIFO `--meta-file` blocks forever | **fixed** | `cmd/heimdall-proto/meta_unix.go` opens with O_NONBLOCK: with no reader, the child's status is kept and stderr reports the lost side channel; with a reader, the JSON is delivered. Proof: `TestRunMetaFIFO`; red: blocked for more than 3 s. |
| minor DYLD_INSERT_LIBRARIES injects into the darwin artifact | **fixed** (local signing only) | `build.sh` runs `codesign --force --options runtime --sign -`, an ad-hoc signature with hardened runtime. Before: `INJECTED_DYLIB_LOADED`; after: not loaded (dyld-insert-darwin-arm64-*.txt). Not notarized; there is no Developer ID. The Linux artifacts are static, so LD_PRELOAD does not apply. |
| minor documentation inaccuracies | **fixed** | LICENSES.md now says termios is linked on darwin and linux only (checked with `go version -m`, go-version-m.txt) and that colorprofile is direct. The `Filter` comment now says it is used by the TUI. REPORT §4 startup numbers and the K3a escalation are marked "[Round 2 update]". |
| minor tests not relocatable | **fixed** | `internal/testfix` resolves the fixtures from `HEIMDALL_G02_FIXTURES`, else from the nearest ancestor `tests/fixtures/g02/profiles`. A relocated copy passes with the variable set. Without it the test fails with that instruction rather than being skipped. The fixtures are not duplicated into the module, since two of them carry canary values. |
| minor SIGKILL of heimdall (or killpg SIGKILL) leaves the child | **not fixed** | The contract requires only that no orphan remains after a normal exit. In exclusive and no-tty modes the child is in its own group by design. In shared mode, killpg now reaches both. macOS has no parent-death signal. Linux `Pdeathsig` fires on the exit of the forking *thread*, which is unreliable under the Go scheduler. |
| minor child with fd 1 closed gets a working fd 1 | **stack limitation** | The Go runtime opens /dev/null for closed fds 0-2 at startup (`runtime/fds_unix.go`, documented in `runtime/extern.go`), before any user code runs. Re-observed: run_probe `closed_stdout_inherited` rc=0 against the control's rc=1. |
| minor unwritable `--meta-file` is detected only after the child ran | **not fixed (escalated)** | The contract has no code or exit status for "refuse to launch because the side channel is unwritable". Creating the file before launch changes the "write after the child ends" timing. This is an authority-semantics choice. |
| minor bidi and zero-width code points pass through | **not fixed (escalated)** | K1 and K2 define the replacement set exactly (C0, DEL, C1, invalid UTF-8). Replacing more would diverge from the contract. Display-spoofing policy is a product decision. |
| minor PID-reuse window after reap on macOS; SIGTERM before handlers are installed kills heimdall (run_probe `sigterm_race_60`, no child started, no orphan) | **not fixed** | The first is unchanged and small: the signal goroutine checks `reaped` under a mutex, but there is a window between `wait4` returning and the flag being set. Closing it needs `waitid(WNOWAIT)`, which x/sys does not provide on darwin. The second is inherent to any program: before `signal.Notify` the default action applies, and no child exists yet. |
| minor harness coverage gap (Darwin cannot exercise K3a) | addressed for this candidate | Settled by K13. K3a now has Linux-native evidence. The harness itself is owned by another agent. |
| minor GOTRACEBACK, GOMEMLIMIT, GOMAXPROCS honored | **not fixed** | They are runtime tuning knobs, not security decisions. `debug.SetTraceback` cannot lower the level below the environment's. Listed for the language comparison. |

### Signal and terminal mechanism now used (internal/run/run_unix.go)

Go's `os/signal` gives no siginfo, so heimdall cannot tell a signal the kernel sent to its whole process group (terminal Ctrl-C, killpg) from one sent to its PID alone. The mode is chosen once, before the launch, from observable state:

- **modeNoTTY.** There is no controlling terminal: none on stdio, and `/dev/tty` cannot be opened.
  - The child runs in its own process group.
  - Every signal heimdall receives is forwarded once.
- **modeExclusive.** A controlling terminal exists, heimdall is the only member of its process group, and neither stdin nor stdout is a pipe or socket.
  - The child runs in its own group.
  - That group gets the terminal foreground when heimdall's group holds it: at start (`SysProcAttr.Foreground`), and after the shell's `fg` (50 ms poll, which re-checks group membership before each handoff).
  - Terminal signals reach only the child's group. Every signal heimdall receives is explicit or group-directed at heimdall's group, so it is forwarded once.
  - Child stops are mirrored onto heimdall's group, which contains only heimdall.
  - Taking the foreground from heimdall's group takes it from no other process (K6a).
- **modeShared.** A terminal exists, and heimdall shares its group (pipeline peers, or the script that started it as a `&` job without job control) or stdin/stdout is a pipe or socket.
  - The child stays in heimdall's group, as exec would leave it. heimdall never calls tcsetpgrp and never stops its group.
  - SIGINT, SIGQUIT, SIGWINCH and SIGHUP are forwarded only while heimdall's group is *not* the terminal's foreground group, and never once the terminal can no longer be queried (hangup). In the foreground, the terminal has already delivered them to the child.
  - SIGTERM is always forwarded.
- **In all modes,** inherited-ignored SIGINT and SIGHUP are neither handled nor forwarded.

Remaining gaps:

1. In modeShared, an explicit SIGINT, SIGQUIT, SIGWINCH or SIGHUP sent to heimdall's PID while its group holds the terminal foreground is not forwarded. A killpg of a shared group delivers SIGTERM or SIGHUP twice. Both follow from having no siginfo.
2. The SIGQUIT, SIGTERM and SIGWINCH inherited-ignore limitation above.
3. The mode heuristic can miss a process that joins heimdall's group after the start check without a pipe on stdin/stdout. Stop mirroring does not re-check membership.
4. Unchanged from before:
   - Ctrl-Z/bg/fg after a stop is not automated.
   - A terminal hangup can deliver SIGHUP twice in exclusive mode (kernel plus shell).
   - The PID-reuse window remains.
   - SIGKILL of heimdall leaves the child in modeExclusive and modeNoTTY.
5. Windows: unchanged and compile-only.

### K15 guard notes

The guard follows TOML 1.1 syntax as far as structure needs:
- strings of all four kinds, with escapes and up to two extra quotes inside multi-line delimiters;
- comments, CRLF and a BOM;
- table headers;
- dotted and quoted keys;
- arrays and inline tables, including newlines and trailing commas inside them.

It never echoes input text, and any syntax it cannot follow is "malformed TOML near line N", which the parser would also reject.

The bounds come from measurements: before the guard, per-key memory grew with key-path depth and length. For example:
- 1 MiB of 8-component dotted keys needed 259 MiB;
- 60,000 keys under a header of thirty 10 KB components needed more than 2 GB.

A shape the probe did not model could cost more per unit; that is recorded as a limitation. A valid profile larger than these bounds (for example about 14,000 destinations in 1 MiB) is rejected with SCHEMA_INVALID, which K15 allows. The 10,000-destination at-limit case is accepted.

### Build (`cd / && sh build.sh`, twice, exit 0, identical manifests)

| Target | Bytes | sha256 |
|---|---|---|
| darwin-arm64 | 5,212,000 | 20e8c5c13d597d242bc00bc1dc27774918e4288b12e9c1e85f0a1264e8b5b2e1 (ad-hoc, hardened runtime) |
| linux-x64 | 5,451,936 | ee6d2dc568cb1f04fca5417f5dada74e259627f49b0e55b7837b37ec380dea6d (built; not executed in round 2) |
| linux-arm64 | 5,177,504 | f7d383185190bbaf385082e7c6455f3d714823d3951cd545d385f7d712a10f61 |
| windows-x64 | 5,099,008 | 31b958aca1502915b43df0b46b59df3775506ad9e4c655a069bfe74d1b6eb7a8 (built, never executed) |

Startup on the M5 Max, median of 50 runs: `version --json` 2.96 ms with max RSS 7.1 MiB; `profile show large-100` 3.51 ms with 7.7 MiB.

### Tests (exit codes as observed)

- darwin-arm64:
  - `go test -count=1 -v ./...`: exit 0.
  - go vet on 4 targets, gofmt, `go mod verify`, `go mod tidy -diff`, and Windows `go test -c`: exit 0.
  - FuzzGuard 30 s: exit 0.
  - selftest (68 checks): 68/68 in two runs.
  - schema_check: exit 0.
  - `env -i` run without Go on PATH: exit 0.
- linux-arm64:
  - Test binaries in alpine@sha256:5291449c…: exit 0 for all 5 packages. The corpus test is skipped there because it needs the go command.
  - selftest 68/68 in python:3.13-alpine (busybox ash, @sha256:2dd78ad5…) and in python:3.13-slim-bookworm (bash, @sha256:5024f48b…).
- Red references:
  - Round-1 sources on darwin: 6 new tests fail; on Linux, the new tests fail too.
  - Round-1 artifact with the round-2 selftest: darwin 63/68, Linux 61/68.
- Informational only, not the verdict (the harness is changing concurrently): the shared harness on darwin-arm64 gave 123/124. Only `run.k6a_inherited_ignore` fails, on its SIGQUIT clause, which is the stack limitation above.

### Escalations

1. **Unwritable `--meta-file`.** Choose between refusing to launch and reporting after the child ends (and pick a code), or keep the current behavior: run the child, keep its exit status, and print one stderr line.
2. **Bidi and zero-width code points in agent comments and profile values.** K1/K2 cover only controls; whether to replace or flag these is a product decision.
3. **Inherited-ignored SIGQUIT.** For the G02 comparison, decide whether this is a gating failure of K6a for Go or an accepted stack limitation. Fixing it requires cgo: a pre-runtime constructor plus a dynamic libc.
