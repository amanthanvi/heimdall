<!-- Written by the M00 orchestrator from the rust prototype agent's returned report (the subagent runtime refused direct REPORT.md writes). Content is the agent's text, unedited. -->

# REPORT.md content — G02 prototype: Rust + Ratatui (M00-T05-rust)

**Evidence:** `tests/evidence/g02-rust-selftest.json`, plus `tests/evidence/artifacts/g02-rust/selftest/` (`summary.json` with the real exit code of every step, one log per step). Re-run everything with `prototypes/rust/selftest.sh`.

## 1. Layout and the shared-operations gate
- **Library** (`src/lib.rs`, `#![forbid(unsafe_code)]`): `envelope` (§1), `profile` (§2), `agent` (§3), `runner` (§4), `list_model` (§5 state machine with no terminal), `text`.
- **Binary**: `main.rs`/`cli.rs` (hand-written argument parsing, paths kept as OsString) and `tui.rs` (Ratatui/crossterm rendering of `list_model`).
- CLI and TUI share `profile::load_file`, and all TUI behaviour lives in `ListModel`, which has its own unit tests.

## 2. Versions (from command output)
- **Toolchain:** attempt 1 used rustc 1.98.1 (48a229cea 2026-09-01, LLVM 22.1.8) and cargo 1.98.1. By the attempt-2 rebuild, rustup stable had moved to rustc 1.99.0 (b940084d7 2026-09-28, LLVM 23.1.1) and cargo 1.99.0; there is no `rust-toolchain.toml` pin (see §12). Also rustup 1.29.1, zig 0.16.0 (already installed), cargo-zigbuild 0.23.4 (installed into gitignored `target/tools`).
- **Host:** macOS 27.0 arm64; Docker Desktop 29.8.0.
- **Exact pins:** ratatui 0.30.2 (crossterm feature: ratatui-core 0.1.2, ratatui-crossterm 0.1.2, crossterm 0.29.0), toml 1.1.6+spec-1.1.0, serde_json 1.0.151, sha2 0.11.0, base64 0.23.1.
- **Unix only:** signal-hook 0.4.4, rustix 1.1.5, nix 0.31.3. **Windows only:** ctrlc 3.5.2.
- 91 crate versions in the lock across all four targets.

## 3. Builds (`build.sh` → `dist/manifest.json`, all four built)

Sizes below are from attempt 1. The attempt-2 rebuild (§12) built all four targets again with new sizes and digests; `dist/manifest.json` holds the current ones.

| Target | Size | Notes |
|---|---|---|
| darwin-arm64 | 739,264 B | links only libSystem and libiconv |
| linux-x64 | 901,280 B | static musl, zig |
| linux-arm64 | 838,328 B | static musl, zig |
| windows-x64 | 834,048 B | windows-gnu via zig; imports UCRT `api-ms-win-crt-*`, so needs Windows 10+ |

- Cold release builds took 11–16 s per target.
- **Run without a toolchain:**
  - linux-arm64 ran in a clean `debian:bookworm-slim` with no cargo, rustc, go, node, bun or python3 on PATH.
  - linux-x64 ran in `debian:trixie`, but only under emulation.
  - darwin ran with `env -i PATH=/usr/bin:/bin` on the build machine itself.
  - windows-x64 is **blocked** (needs a Windows 10/11 x64 host).
- **Speed and memory (macOS):** `version --json` median 2.6 ms; `profile show` on the 100-destination profile median 3.0 ms; about 2.1 MiB peak memory.

## 4. Contract coverage
- **§1–§2, §6:** implemented; tested on macOS and Linux against every fixture, the oversize file, and the canary.
- **§3 Unix:** implemented and tested with crafted frames and fake agents in temp dirs: oversize length, nkeys over 1024, string overrun, trailing bytes, truncation, wrong type, refusal, timeout, and SIGINT cancel in under 500 ms. Only type 11 is ever sent. Since attempt 2, EOF before any response byte is `AGENT_UNAVAILABLE` (K3; attempt 1 reported `AGENT_PROTOCOL_ERROR`).
- **§4 Unix:** implemented and tested: byte-exact argv including invalid UTF-8, binary stdio, exit code and 128+N, meta file, 127 on launch failure, forwarding of INT/TERM/HUP/QUIT/WINCH, terminal Ctrl-C delivered to the child exactly once, Ctrl-Z job control, no zombie.
- **§5 Unix:** implemented and tested in a pty on macOS and Linux arm64 (15/15 cases in attempt 1; 18/18 in attempt 2, which adds the K6, K9 and K10 cases). Since attempt 2, every filter edit resets the selection to the first shown row (K9); attempt 1 kept the previously selected destination. Covered: `> ` marker, alias-only rows under 50 columns, status line, keys, Unicode filter, NO_COLOR, redraw after resize in about 6 ms including 20×5, 100 rows, and terminal restore after select/quit/Ctrl-C/SIGTERM/panic/hangup.
- **§7:** done.
- **Windows (§3–§5):** compile-checked only.
- **Shared harness, run read-only (attempt 1; for attempt 2 see §12):**
  - All 70 non-TUI checks pass.
  - Of the 22 TUI checks, 13 pass.
  - 7 hit an `IndexError` inside pyte in the harness.
  - 2 hang until the timeout because of a harness deadlock.
  - Both harness problems are escalated as harness-side.

## 5. What was hard, how long, and the workarounds (about 1 h 40 min total; first green tests after about 25 min)
1. **Double SIGINT (about 25 min).** The first design filtered signals by sender PID via signal-hook's extended-siginfo, which compiles C. On macOS 27, a Ctrl-C typed at the terminal reports the PID of whatever wrote to the pty master, so it looks like `kill(2)`. I replaced it with shell-style job control: the child gets its own process group and the terminal (`tcsetpgrp`), SIGTTOU is blocked via nix's safe `pthread_sigmask` when taking the terminal back, and Ctrl-Z stops and resumes both processes. The C component is gone.
2. **crossterm 0.29 hangs on terminal hangup (about 15 min).** The TUI spins at 100% CPU forever, because `event::poll` loops on EOF/EIO. A watchdog thread now polls stdin for POLLHUP and checks pending signals, then restores the terminal and exits with 129. There is a regression test.
3. **Ratatui `Terminal::clear()` sends a cursor-position query (`ESC[6n`)** and waits 2 s on terminals that never answer. I clear the alternate screen with crossterm `Clear(All)` instead.
4. **macOS test-infrastructure quirks (about 20 min, not product bugs):** a process exiting with unread pty output blocks until it is read; the slave fd is revoked once the session leader exits; Docker could not mount the repo at its `/Users` path, so it is mounted at `/repo` with a symlink.
5. **Cross-compiling with zig and cargo-zigbuild** worked first time (about 5 min).

## 6. Known defects
- Background-job mode: a signal sent to the whole process group reaches the child twice.
- Possible double SIGHUP when the terminal hangs up while the child is in the foreground. This is inferred, not tested.
- heimdall-proto stops itself with SIGSTOP, so shells print "Stopped (signal)". Cosmetic.
- The watchdog exits from a helper thread; on hangup the terminal restore is best effort.
- `build.sh` needs python3 on the build host to write the manifest.
- The darwin binary has only an ad-hoc signature (not Developer-ID signed or notarized).
- The windows-x64 digest is not reproducible between identical builds.

## 7. Windows notes (compile-checked only; native run blocked)
- **Named pipe:** `std::fs::OpenOptions` on `\\.\pipe\name` with a synchronous handle. Timeout and cancel come from a worker thread plus process exit. A busy pipe is reported as `AGENT_UNAVAILABLE` with no retry.
- **Console Ctrl-C:** `ctrlc` (`SetConsoleCtrlHandler`). In `agent list` it sets the cancel flag. In `run` the parent ignores it so the child, on the same console, handles it. In the TUI, raw mode delivers Ctrl-C as a key.
- **CreateProcess quoting:** std's `CommandLineToArgvW`-compatible quoting; it refuses unsafe `.bat`/`.cmd` arguments (the CVE-2024-24576 fix). There is no custom quoting code.
- **Exit codes:** passed through as 32-bit values, so NTSTATUS codes can appear negative; `signal` is always null. There is no job object.
- **Resize / ConPTY:** crossterm's `WINDOW_BUFFER_SIZE_EVENT`. ConPTY is not involved.
- **Dependencies:** `winapi` 0.3.9 (last release 2020) via crossterm, which ships prebuilt `.a` import libraries.

## 8. Native code, unsafe code, downloads
- My code contains no `unsafe` (`forbid(unsafe_code)` in both crates). Dependencies use unsafe internally and were not audited.
- No C is compiled after the extended-siginfo removal.
- The binaries download nothing at runtime.
- Build-time downloads: crates from crates.io, the `x86_64-unknown-linux-musl` rustup target, cargo-zigbuild, and the arm64 `debian:bookworm-slim` image.

## 9. Maintenance signals (crates.io, 2026-10-03)

| Crate | Latest release |
|---|---|
| ratatui | 0.30.2, 2026-06-19 |
| crossterm | 0.29.0, 2025-04-05 (about 18 months old; has the hangup bug) |
| toml | 2026-09-10 |
| serde_json | 2026-07-20 |
| sha2 | 2026-03-25 |
| base64 | 2026-08-04 |
| signal-hook | 0.4.4, 2026-04-04 |
| rustix | 2026-09-16 |
| nix | 2026-05-11 |
| ctrlc | 2026-02-10 |
| windows-sys | 2025-10-06 |
| winapi | 0.3.9, 2020-06-26 |

crossterm still pulls signal-hook 0.3.18, so the graph carries two signal-hook versions.

## 10. Iroh path
- **Embedded library, native to Rust:** `iroh` 1.3.0 (released 2026-09-28, MIT OR Apache-2.0, needs Rust 1.91 or later).
- A scratch resolve pulled 363 crates, including tokio 1.53.1, rustls 0.23.45, noq 1.3.0, and ring 0.17.14 (C and assembly; cross-compiling it is untested).
- It would add BSD-3-Clause, ISC, `Apache-2.0 AND ISC`, and CDLA-Permissive-2.0 licenses.
- Iroh is async, so this synchronous design would need a tokio runtime thread or an optional supervised helper.
- crates.io has no `iroh-ffi` crate.

## 11. Licensing
`LICENSES.md` was generated by `tools/gen_licenses.py` from `cargo tree` (cargo 1.98.1), using each crate's declared license field. Everything is permissive. Besides MIT/Apache:
- ryu: Apache-2.0 OR BSL-1.0
- foldhash: Zlib
- memchr: Unlicense OR MIT
- unicode-ident: Unicode-3.0 (build-time only)

The prototype's own `license = "UNLICENSED"` is a placeholder (spec §15.3 leaves the project license open).

## 12. §9 alignment (2026-10-03)

Task M00-T05-rust-align: bring the prototype into line with contract §9 (K1–K12) with the smallest changes, and prove each ruling with a native test. Evidence: `tests/evidence/g02-rust-selftest.json` (attempt 2; attempt 1 is kept under `attempts`) and `tests/evidence/artifacts/g02-rust/selftest/attempt-2-k-align/`. The attempt-1 artifacts at the top of `selftest/` are untouched.

### K1–K12

| Ruling | Result | Proof (native test) |
|---|---|---|
| K1 controls in agent output | Already conformed: `char::is_control` covers C0 (incl. TAB), DEL and C1, and invalid UTF-8 is decoded lossily first. | `agent::tests::k1_all_control_classes_replaced_in_comment_and_key_type`; `tests/cli.rs` `k1_agent_strings_have_no_control_code_points` (decoded JSON contains no control code point) |
| K2 controls in profile values | Already conformed: `check_text` rejects every string value outside `[meta]`; the message names only the key path. | `profile::tests::k2_control_chars_in_values_rejected_outside_meta` (TAB both literal and escaped, NUL, DEL, ESC, U+0080/0085/009F in name, id, alias, host, account and labels; value never echoed; `[meta]` tolerated) |
| K3 agent EOF | **Changed.** `src/agent.rs` `read_frame`: EOF before any response byte → `AGENT_UNAVAILABLE`. EOF after ≥1 byte stays `AGENT_PROTOCOL_ERROR`. | `tests/cli.rs` `k3_k4_eof_and_failure_frame_shape` (zero bytes / 1 byte / length only / partial body); `agent::tests::truncated_rejected` updated. Red proof: the attempt-1 binary fails this test with `AGENT_PROTOCOL_ERROR` on zero-byte EOF (exit 101). |
| K4 failure frame shape | Already conformed: type 5 with any payload → `AGENT_PROTOCOL_ERROR`. | `agent::tests::k4_failure_with_payload_is_protocol_error`; `k3_k4_eof_and_failure_frame_shape` (len 1 → REFUSED; +1 and +4 bytes → PROTOCOL_ERROR) |
| K5 meta `state` | Already conformed. | `tests/cli.rs` `k5_meta_state` (exit 0, exit 42 and SIGKILL → `succeeded`; launch failure → `failed`); `runner::tests::meta_shapes` now asserts `state` |
| K6 signal mechanism | Already conformed, now tested. The mechanism is unchanged: as a foreground job, the child gets its own process group and the terminal; with no terminal, its own group; as a background job, it shares heimdall-proto's group. Every signal heimdall-proto receives is forwarded once with `kill(child_pid)`. | `tests/cli.rs` `k6_explicit_signal_to_pid_reaches_child_exactly_once` (no controlling terminal: macOS cargo test and Linux containers; INT and TERM; a counting child reports `count=1`, exit 3). pty `k6-explicit-kill-reaches-child-once-fg-and-bg` (foreground-job and background-job states, INT and TERM; the state is checked through child/parent pgids and `tcgetpgrp`). |
| K7 PATH lookup | Statement: not refused. std `Command` follows execvp semantics, so empty and `.` PATH entries resolve to the cwd (observed, `k7-path-lookup-observation.log`). K7 allows this, and it is not tested. | — |
| K8 invalid UTF-8 argv | Already conformed. | `tests/cli.rs` `run_argv_bytes_passthrough` (element `0x80 0xff 'x'`, via `printf %s\0`) |
| K9 selection after filter edit | **Changed.** `src/list_model.rs` `refilter`: every filter change (append, Backspace, Esc clear) sets the selection to row 0. Leaving filter mode with Enter does not refilter, so it keeps the selection. | `list_model::tests::k9_filter_edit_resets_selection_enter_keeps_it`; pty `k9-filter-edit-resets-selection`. Red proof: the attempt-1 binary fails the pty case (selection stayed on `vps-東京` after `/e`). |
| K10 TUI other exits | Already conformed, now tested end to end. | pty `k10-sighup-129-sigterm-143-no-stdout` (`kill -HUP` → 129, `kill -TERM` → 143, both restored with no bytes on the terminal after the final cursor-show; terminal hangup → 129). `tui-panic-restores` → exit 1, with stderr now split off: the panic text is on stderr only, and nothing reaches stdout after restore. |
| K11 sidecars | Statement: each target is one self-contained executable (darwin links only libSystem/libiconv; Linux is static musl; Windows imports only system/UCRT DLLs). There are no sidecars, so the manifest has no `sidecars` entries. Nothing is extracted at runtime. The only runtime write is `--meta-file`. | — |
| K12 output without `--json` | Statement: human text is emitted without `--json`. Exit codes come from the same code path as with `--json`. Not judged. | — |

### Test-driver changes (prototypes/rust/tests/pty_tui.py)
- The session-leader wrapper accepts `HP_PTY_BG=1`, which starts the target as a background job (its own non-foreground group). It also accepts `HP_PTY_STDERR=<file>`, which separates stderr so that stdout-only output can be judged.
- The wrapper tolerates an unreadable termios after hangup, so the hangup exit code can now be recorded.
- `selftest.sh` accepts `HP_SELFTEST_OUT` (per-attempt artifact directory) and `HP_SELFTEST_SKIP_HARNESS=1`. Summary log paths are now relative to that directory.

### Attempt-2 results (all real exit codes; `summary.json`)
- 20/20 self-test steps exited 0: fmt, clippy `-D warnings`, host tests (lib 43, bin 4, cli 18), Windows `cargo check`, `build.sh`, darwin dist CLI tests 18/18 with `env -i`, darwin pty 18/18, Linux arm64 native tests 43+18+4, Linux x64 (emulated) 43+18+4, Linux arm64 pty 18/18.
- Builds (`dist/manifest.json`):

| Target | Size | sha256 |
|---|---|---|
| darwin-arm64 | 755,840 B | 4f852143… |
| linux-x64 | 902,776 B | 10e6bf89… |
| linux-arm64 | 838,696 B | 9bbd19c3… |
| windows-x64 | 839,168 B | 6a177ad4… |

  The size change comes partly from the code change and partly from toolchain drift (rustc 1.98.1 → 1.99.0).
- Shared harness, informational only: a read-only darwin run with the record under `/tmp`. It exited 124 at the 900 s timeout: 73 PASS, 3 ERR (`IndexError` inside the harness's pyte on `tui.filter_basic`, `filter_unicode` and `filter_case_insensitive`), then it hung on `tui.filter_matches_host`. These are the same harness-side symptoms as attempt 1. At the time of the run, the harness check list had no K-specific check names. It is being changed concurrently, so it was not used as the verdict.

### Known gaps still open (unchanged by §9)
- Background-job mode: a signal sent to the whole process group reaches the child twice. K6 governs only explicit signals to heimdall-proto's PID, which arrive exactly once in all three tested states.
- Not tested: an explicit signal sent while heimdall-proto is itself stopped after Ctrl-Z (it stays pending until SIGCONT, then is forwarded).
- K3 does not rule on a connection reset after ≥1 byte. The prototype reports it as `AGENT_UNAVAILABLE`, as before.
- No `rust-toolchain.toml` pin, so rebuilds follow rustup stable.
- Windows remains compile-checked only: native runs are blocked until a Windows 10/11 x64 host is available.

## 13. Round 2 (2026-10-03)

Task M00-T05-rust-round2-fix: fix the defects of the round-1 adversarial review
(`tests/evidence/artifacts/m00-wf3/review-rust.json`) and conform to the round-2 rulings
(contract §9.1: K6a, K10 confirmation, K13–K16). Evidence: `tests/evidence/g02-rust-selftest.json`
(attempt 3; attempts 1–2 kept) and `tests/evidence/artifacts/g02-rust/selftest/attempt-3-round2/`
(`summary.json`: 34 steps, real exit codes, `all_expectations_met: true`; final run started
2026-10-03T21:45:45Z). An informational read-only run of the shared harness at its in-flux
state (darwin, exit 0, 123/123 pass, including the new `agent.reset_*`, `run.k6a_*`,
`*.non_regular_file`, `*.parser_resource_bound`, `tui.hangup_exit_129` and
`common.no_helper_processes` checks) is kept in
`selftest/attempt-3-round2-harness-informational/`; it is not a verdict, and no Linux harness
run (K13) was done by this task. Re-run with
`prototypes/rust/selftest.sh`. The shared harness (`tests/g02/`) was being changed concurrently and
is not used as this report's verdict.

"Red" means the round-1 artifact (digests checked against the round-1 manifest:
darwin `4f852143…`, linux-arm64 `9bbd19c3…`) fails the new test; it is recorded in the
`red-round1-*` steps (expected non-zero, observed 101/1).

### Review defect / ruling → outcome

| Review defect or ruling | Outcome | Where (code; proving test) |
|---|---|---|
| **K3a** (major): reset after ≥1 byte reported as `AGENT_UNAVAILABLE` on Linux | **Fixed.** A reset/abort/broken pipe after at least one response byte is now `AGENT_PROTOCOL_ERROR`; before any byte it stays `AGENT_UNAVAILABLE`. | `src/agent.rs` `read_full`; unit `agent::tests::k3a_reset_classified_like_eof` (mock reader: bytes then `ConnectionReset`/`ConnectionAborted`/`BrokenPipe`); `tests/cli.rs` `k3a_reset_before_and_after_partial_frame` (own crafted agent that never reads the request, writes 0/1/3/7 bytes and closes). On Linux the test first proves the probe really resets: a plain client receives the 3 bytes, then `ConnectionReset`. Passes on Linux arm64 (native kernel, digest-pinned `debian:bookworm-slim`) and linux-x64 (emulated); on darwin the reset arrives as EOF (K13). Red on Linux arm64. |
| **K6a** inherited `SIG_IGN` reset in the child; ignored signals forwarded (major) | **Fixed** for INT, TERM, HUP, QUIT, WINCH. Before installing any handler, `run` queries each disposition; an inherited `SIG_IGN` gets no handler, so `execve` keeps it ignored in the child and it is never forwarded. | `src/sigdisp.rs` `inherited_ignored`, `src/runner.rs`; `tests/cli.rs` `k6a_inherited_ignored_dispositions_reach_child` (`trap '' HUP INT QUIT TERM; exec heimdall-proto run -- sh -c 'kill -HUP $$ …; echo survived'`), `k6a_inherited_ignored_signals_are_not_forwarded` (HUP/INT/QUIT to the heimdall-proto PID are dropped, TERM still forwarded once). Red on darwin and Linux arm64 (round 1: exit 129, child killed). |
| K6a for **SIGPIPE** | **Stack limitation.** Rust std sets SIGPIPE to `SIG_IGN` before `main` (so the inherited disposition is unknowable) and resets it to `SIG_DFL` in every spawned child; the opt-out (`-Zon-broken-pipe=inherit`) is nightly-only (`rustc 1.99.0 -C help` has no such option). Workarounds (`#![no_main]` entry, `pre_exec` re-ignore) bypass the std runtime and were not applied (K8 spirit). | `tests/cli.rs` `k6a_limitation_sigpipe_ignore_not_preserved_by_rust_std` asserts the limitation is present (child killed by SIGPIPE, exit 141, although the caller ignored it). |
| **K6a** terminal takeover by an `&` job of a script; pipeline peers (major) | **Fixed** by switching to exec semantics: no `setpgid`, no `tcsetpgrp`, no self-stop. The child shares heimdall-proto's process group. | `src/runner.rs`; pty `k6a-amp-job-of-script-keeps-terminal` (foreground group unchanged, the script's own `read` gets its input), `k6a-pipeline-peer-reads-terminal` (`heimdall-proto run -- sleep 1 \| (read x </dev/tty …)` reads normally). Red on darwin and Linux arm64. |
| killpg(SIGKILL) orphaned the child without a tty (minor) | **Fixed** (same change: the child is in heimdall-proto's group). | `tests/cli.rs` `k6a_group_sigkill_leaves_no_orphan`. Red on darwin and Linux. |
| K6 explicit signal exactly once, every state | **Kept**, re-verified in the new topology. | `tests/cli.rs` `k6_explicit_signal_to_pid_reaches_child_exactly_once` (no tty), `run_forwards_signals_and_waits`; pty `k6-explicit-kill-reaches-child-once-fg-and-bg` (state asserted: child pgid = heimdall-proto pgid; foreground vs background via `tcgetpgrp`); pty `run-ctrl-z-job-control` (Ctrl-Z stops the whole job, SIGCONT to the group resumes it). |
| §4 terminal Ctrl-C not doubled | **Linux: fixed. Darwin: OS limitation.** Linux marks terminal-generated signals with `si_code = SI_KERNEL`; they are not forwarded (the child, in the foreground group, already got them). Darwin reports identical `siginfo` for a tty signal and for `kill(2)` (C probe on macOS 27: `si_code=0`, `si_pid` = the pty-master writer, in both cases), so heimdall-proto forwards and the child sees Ctrl-C, Ctrl-\ and resize twice. | pty `run-terminal-sigint-not-doubled`: Linux arm64 count=1 (pass); darwin count=2, recorded as `known_limitation`. A mutation check (forwarding disabled for kernel signals) confirmed the SIGHUP rule below is required on Linux. |
| Hangup when heimdall-proto is the session leader | **Covered.** A kernel SIGHUP from a hangup goes to the session leader only; it is forwarded when heimdall-proto is the session leader. | pty `run-session-leader-hangup-reaches-child-once` (Linux and darwin: count=1, exit 3); mutation build without the rule: Linux count=0. |
| Early SIGINT kills `agent list` without CANCELLED (minor) | **Partly addressed; remainder not fixable in user space.** `main` now blocks INT/TERM/HUP/QUIT/WINCH as its first statement and each command restores the mask after installing its handling, so nothing after `main` starts can be lost. The window between `execve` and `main` (dyld/loader and runtime start-up, ~1 ms) remains for any program. | `src/main.rs`, `src/sigdisp.rs`; probe `tools/early_sigint_probe.py` (30 runs per delay; CANCELLED counts in the final recorded run): darwin 1 ms after spawn 20/30 (round 1: 17/30), Linux arm64 0.25 ms 10/30 (round 1: 0/30) and 0.5 ms 26/30 (round 1: 9/30); at 0 ms every run of both versions is killed, from 2 ms on every run is cancelled. Run-to-run noise is large (an earlier recorded run gave darwin 1 ms 18/30 vs 0/30, an ad hoc one 21/30 vs 20/30), so the measurable gain is on Linux only and small. Escalated: the review's question whether "SIGINT while waiting" covers start-up. |
| FIFO `--meta-file` blocks forever (minor) | **Fixed (the hang).** The meta file is opened `O_NONBLOCK` (a FIFO without reader fails at once with ENXIO; stderr diagnostic; exit stays the child's) and switched back to blocking for writing, so a FIFO/pipe with a reader still receives the JSON. **Not changed:** the other points (unwritable path reported only after the child ran; symlinks followed; truncate-then-write): validating or creating the file before launch is a behavior/contract choice (escalated), and an atomic rename would break FIFO and `/dev/fd/N` targets. | `src/main.rs` `write_meta`; `tests/cli.rs` `meta_file_fifo_never_blocks`. Red on darwin and Linux. |
| Windows named pipe without `SECURITY_SQOS_PRESENT` (minor) | **Fixed, compile-checked only.** `security_qos_flags(SECURITY_IDENTIFICATION)` (std then also sets `SECURITY_SQOS_PRESENT`). **Not fixed:** pipe-server identity check and `WaitNamedPipe` retry need `windows-sys` FFI and a Windows host to test. | `src/agent.rs` `conn::connect` (Windows); `clippy --target x86_64-pc-windows-gnu -D warnings` exit 0. Native run **blocked: needs a Windows 10/11 x64 host**. |
| Notice inventory incomplete; dist ships no notices (minor) | **Fixed.** `LICENSES.md` now has three parts: crates.io crates, the Rust standard library and its vendored crates (from the `rust-src` component: std/core/alloc/panic_*/unwind, compiler_builtins `MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)`, std_detect, cfg-if, hashbrown 0.17.1, rustc-demangle 0.1.28, addr2line 0.27.1, gimli 0.34.0, object 0.39.1, memchr 2.8.3, miniz_oxide 0.9.1, adler2 2.0.1, libc 0.2.189, windows-link), and native runtime pieces (musl, LLVM libunwind, GCC crtbegin/crtend `GPL-3.0-or-later WITH GCC-exception-3.1` on Linux, mingw-w64 runtime `ZPL-2.1` with marked PD/BSD/LGPL parts). `dist/THIRD-PARTY-NOTICES.txt` (302,235 B; listed in the manifest as `notices`, not a K11 sidecar) carries every license text, deduplicated. | `tools/inventory.py`, `tools/gen_licenses.py`, `tools/gen_notices.py`, `build.sh`. Limits: which mingw/musl objects zig substitutes was not traced object by object; the musl text is zig's copy. |
| Artifacts embed the builder home path (minor) | **Fixed.** `--remap-path-prefix` for the cargo registry, the toolchain's rust-src (installing rust-src makes rustc embed its real path), this checkout and the target dir; `build.sh` fails a target whose artifact still contains `$HOME`. | `build.sh`; step `artifact-inspect`: 0 home-path strings in all four (round 1: 62–65). |
| Darwin digest depends on the build path; Windows digest on the PE timestamp (minor) | **Fixed.** darwin links with `-oso_prefix,<target dir>/` (the LC_UUID was path-dependent); windows links with `/Brepro`. | step `repro-other-checkout`: a full rebuild from a different checkout path gives identical sha256 for all four targets and the notices file. |
| darwin without hardened runtime, `DYLD_*` honored (minor) | **Fixed (ad-hoc).** `codesign --sign - --options runtime`; `DYLD_PRINT_LIBRARIES=1` prints nothing. **Not fixed:** Developer ID signing and notarization need an Apple Developer ID (owner authority). | `build.sh`; step `darwin-hardened-runtime`. |
| No toolchain pin (minor) | **Partly.** `build.sh` refuses any rustc other than 1.99.0. No `rust-toolchain.toml`: it would make rustup download a separately named toolchain and all targets. | `build.sh` `PINNED_RUSTC`. |
| `build.sh` needs python3 (round-1 note) | **Not changed**: build-host tool only (manifest and notices); the artifacts do not need it. | — |
| **K14** `--file` FIFO/socket/device/dir blocks (minor) | **Fixed.** Opened with `O_NONBLOCK`, then `fstat`: anything but a regular file is `USAGE_ERROR`. | `src/profile.rs` `read_bounded`; `tests/cli.rs` `k14_non_regular_profile_files` (FIFO without writer, directory, `/dev/null`, socket; each < 2 s); pty `k14-tui-fifo-usage-error` (exit 2 in 0.05–0.08 s, no alternate screen). Red: round 1 hangs on the FIFO. |
| Duplicate id/alias check O(n²) (minor) | **Fixed** (hash sets). Behavior covered by the existing `profile::tests::duplicate_alias_and_id`; no timing test. | `src/profile.rs`. |
| **K15** parser resource bound | **Already conformed; now tested.** 12 adversarial 1 MiB inputs inside `[meta]` (deep arrays/inline tables open and closed, 500k-deep dotted keys and table headers, wide arrays of ints/empty arrays/empty tables/strings, 95k `[[meta.a]]`, nested arrays): each `PROFILE_OK` or `SCHEMA_INVALID`; worst peak RSS 140 MiB (darwin, `wide-array`) / 116 MiB (Linux arm64), worst time 77 ms. Measured per child with `wait4(2)`. | `tests/cli.rs` `k15_parser_resource_bound`; steps `darwin-k15-measure`, `linux-arm64-k15-measure`. |
| **K16** helper programs (tput/tmux/infocmp) | **Fixed.** Round 1 reached crossterm 0.29 `terminal::size()`, which runs `tput cols` / `tput lines` from PATH when the size ioctl fails; reproduced on Linux arm64 (TUI without controlling tty, output terminal hung up, then SIGWINCH/keypress: `tput cols`, `tput lines` executed). The TUI no longer calls crossterm's event source or size functions on Unix: input is decoded by `src/keys.rs`, the size comes from `tcgetwinsize(stdout)` with no fallback, and the cursor-position query is refused (`NoProbeBackend`). The string `tput` is no longer present in the Linux artifacts. | `src/keys.rs` (unit tests), `src/tui.rs`; pty `k16-no-helper-programs-in-tui` (TMUX/TERM=tmux-256color/TERM_PROGRAM set, fake tput/tmux/infocmp/stty/tset/resize/toe/clear first on PATH, keys, resizes, quit, hangup: none executed) and `k16-no-tput-when-output-terminal-hangs-up` (exit 129, nothing executed). Red on Linux arm64 (`tput cols`, `tput lines`) and darwin (exit 1). |
| **K10 confirmation** (hangup seen as EOF/EIO only) | **Conforms.** The event loop treats POLLHUP, read EOF and EIO on stdin, and EIO on stdout during a draw, as a hangup: restore, exit 129, on the main thread (round 1 exited from a watchdog thread). | pty `k10-sighup-129-sigterm-143-no-stdout` (hangup variant), `tui-terminal-hangup`, `k16-no-tput-when-output-terminal-hangs-up`. |
| Test portability (minor) | **Fixed.** Fixtures come from `$HEIMDALL_G02_FIXTURES` when set (repository layout otherwise, with a clear failure message). | step `relocated-tests`: a copy of the crate outside the repository passes 49+4+26. The Linux container runs no longer need the path symlink. |
| Agent socket peer not verified (review note, not required) | Not changed: not in the contract. | — |

Two regressions found and fixed while doing the above, each covered by an existing test:
ratatui's `Terminal` drop reports a failed cursor-show with `eprintln!`, which panics when
stderr is the hung-up terminal (exit 1 instead of 129 on macOS; `NoProbeBackend::show_cursor`
now ignores the error, `restore()` shows the cursor), and Darwin sets the kernel-managed
`PENDIN` flag when raw mode is left with `TCSANOW`; round 1 cleared it by accident through its
watchdog's `poll`, now `restore()` polls stdin once.

### Signal and terminal mechanism now used

- **`run` (Unix):** exec semantics. The child is spawned without `setpgid`/`tcsetpgrp` and stays in
  heimdall-proto's process group and session; heimdall-proto never stops itself or anything else.
  Signals inherited as ignored keep `SIG_IGN` and are not caught. INT, TERM, HUP, QUIT and WINCH
  otherwise are caught with their `siginfo` (signal-hook `WithRawSiginfo`, no C) and sent to the
  child's PID, except on Linux when `si_code > 0` (kernel-generated: the terminal already signalled
  the whole foreground group), unless it is a hangup SIGHUP and heimdall-proto is the session
  leader. The child is reaped only after forwarding is disarmed (`waitid(WNOWAIT)`).
- **Startup:** `main` blocks those five signals first; each command restores the mask after its
  own handling is installed.
- **TUI (Unix):** crossterm only writes escape sequences and toggles raw mode. Input bytes are
  decoded by `heimdall_proto::keys`; resize comes from a SIGWINCH flag and `tcgetwinsize(stdout)`;
  no terminal queries are sent. Windows keeps crossterm's console event reader (no `tput` path
  there); compile-checked only.
- **Unsafe:** one `#[allow(unsafe_code)]` function (`sigdisp::inherited_ignored`, query-only
  `sigaction(sig, NULL, &old)`); the crate is `#![deny(unsafe_code)]`, `main.rs` `forbid`. The
  K15 test uses `wait4(2)` (test code only).

### Remaining gaps

- **Darwin:** terminal-generated INT/QUIT/WINCH (and a SIGHUP the kernel sends to the foreground
  group) reach the child twice, because heimdall-proto cannot tell them from `kill(2)`. The
  alternative (round 1's job control: child in its own foreground group) violates K6a whenever
  another process shares heimdall-proto's group. **Escalated:** on Darwin §4 "terminal SIGINT not
  delivered twice", K6 "explicit signal exactly once in every state" and K6a cannot all be met by
  a launcher that stays in its caller's job; this applies to any stack.
- **All platforms:** a signal sent to the whole process group by another process (`killpg`, e.g. a
  supervisor) reaches the child directly and is also forwarded (`si_code` is SI_USER): twice. The
  contract only rules on terminal-generated and PID-directed signals.
- **SIGPIPE** inherited as ignored is not preserved (Rust std; stack limitation above).
- The child's blocked-signal mask is reset to empty by std's spawn (exec would keep it); not ruled.
- The `execve`→`main` start-up window for an early SIGINT remains (any stack).
- Windows: everything compile-checked only (**blocked: needs a Windows 10/11 x64 host**); WSL
  **blocked: needs a Windows host with WSL2**. No job object; pipe-server identity unchecked.
- darwin is ad-hoc signed (hardened runtime), not Developer-ID signed or notarized.

### Round-2 results (attempt 3; all real exit codes)

- Host (macOS 27.0 arm64, rustc 1.99.0): fmt, clippy `-D warnings` (host and
  `x86_64-pc-windows-gnu`) exit 0; `cargo test` lib 49, bin 4, cli 26 passed.
- darwin dist: CLI tests 26/26 under `env -i PATH=/usr/bin:/bin`; pty 24 cases: 23 pass, 1
  `known_limitation` (`run-terminal-sigint-not-doubled`, count=2).
- Linux arm64 (Docker Desktop VM, native arm64 kernel; `debian:bookworm-slim@sha256:0c8bbb8e…`
  and `python:3.13-slim-bookworm@sha256:5024f48b…`, `--network none`, `--pull never`): lib 49,
  bin 4, cli 26 passed; pty 24/24 including `run-terminal-sigint-not-doubled` (count=1).
  linux-x64 (emulated, alpine 3.22 amd64 image ID `c83674e1…`): 49+4+26 passed.
- Red proofs (expected non-zero): round-1 darwin cli 5 of 26 failed (exit 101: K14, both K6a
  dispositions tests, group-SIGKILL orphan, FIFO meta; K3a passes there because Darwin gives EOF),
  round-1 Linux arm64 cli 6 of 26 failed including K3a (exit 101), round-1 pty 6 of 23 failed on
  each platform (exit 1: Ctrl-Z/K6 state assertions of the new topology, both K6a terminal cases,
  K14 TUI FIFO, K16 hangup case; on Linux the K16 failure is the executed `tput cols`/`tput lines`).
- Builds (`dist/manifest.json`, rustc 1.99.0; identical from a second checkout path):

| Target | Size | sha256 |
|---|---|---|
| darwin-arm64 | 717,904 B | d9838f89… |
| linux-x64 | 869,648 B | 28c8dee0… |
| linux-arm64 | 806,528 B | 77d10192… |
| windows-x64 | 841,728 B | 07b1cbc4… |

  Against round 1: darwin −37,936 B, linux-x64 −33,128 B, linux-arm64 −32,168 B, windows-x64
  +2,560 B (Windows still links crossterm's event reader). The Unix drop is inferred, not measured
  per symbol, to come mostly from crossterm's event source no longer being linked.
- Downloads this round: the `rust-src` component for the stable 1.99.0 toolchain (rustup,
  2026-10-03T21:24Z), used for the standard-library inventory. No other downloads; all container
  images were already local and are pinned by digest or image ID.
