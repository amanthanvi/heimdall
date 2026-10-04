<!-- Written by the M00 orchestrator from the ts prototype agent's returned report (the subagent runtime refused direct REPORT.md writes). Content is the agent's text, unedited. -->

# G02 TypeScript + OpenTUI prototype report (M00-T05-ts)

This is disposable gate evidence for the G02 comparison, not production code. The binding contract is `docs/g02/slice-contract.md`. Everything below separates what I observed (commands I ran, with real exit codes) from inference.

Blocked verification:
- Native Windows runs: no Windows host.
- Clean-machine runs on real macOS and Linux hosts: Linux was only run in Docker containers on this Mac, and macOS only on the development host.

Raw evidence is in `tests/evidence/artifacts/g02-ts/selftest/`. The record is `tests/evidence/g02-ts-selftest.json`.

> **Update 2026-10-03 (§9 alignment).** The prototype was changed to follow contract §9 rulings K1–K12. See the new section "§9 alignment (2026-10-03)" at the end. Statements below that the changes made stale are corrected in place and marked *[§9 update]*. Unmarked measurements and observations are from the first build (2026-10-03T00:29Z).

## 1. Outcome by contract section

Host: macOS 27.0 (26A428), arm64.

| § | Item | Result | Notes |
|---|---|---|---|
| §1 | JSON envelope, exit codes, usage errors, spaced/Unicode paths, no secret leakage | Implemented; own tests pass | *[§9 update]* Control characters in strings are now replaced with U+FFFD (K1); before, they were JSON-escaped. |
| §1 | No writes outside named paths | *[§9 update]* Implemented; own tests pass | The first build failed here on the `tui` path (Bun extracted the embedded OpenTUI library to `$TMPDIR/.bun-<uid>-<hash>.<ext>` and left it). The library now ships as a sidecar file and nothing is written to TMPDIR (K11). |
| §2 | `profile show` | Implemented; own tests pass for every fixture plus generated cases | Parser is `smol-toml@1.9.0` with `integersAsBigInt`. |
| §3 | `agent list` | Implemented; own tests pass | Tested against crafted frames, a fake Unix-socket endpoint, and a disposable `/usr/bin/ssh-agent`. The Windows named-pipe path compiles but was never executed. |
| §4 | `run` | Implemented; own tests pass | Stack limitation (K8): argv bytes that are not valid UTF-8 reach the child as U+FFFD. *[§9 update]* Unix children now run in their own process group (K6). Windows quoting is compile-checked only. |
| §5 | `tui` | Implemented; own PTY tests pass | NO_COLOR needed a framework workaround. Exceptions needed extra handling in the adapter. |
| §6 | `version` | Implemented | `runtime` is `bun 1.4.2 (744846f84)`; `tui_framework` is `@opentui/core` `0.5.14`. |
| §7 | `build.sh`, manifest, 4 targets | All 4 built (exit 0) | Runs with no Bun or Node on PATH (macOS and Linux containers). *[§9 update]* `dist/<target>/` now holds the executable plus the OpenTUI library sidecar, listed under `sidecars` in `manifest.json`; no native code is extracted at runtime. `BUN_BE_BUN=1` still turns it into a general runtime. |

Informational run of the shared harness (still being written; run read-only). *[§9 update]* This was the first build. After the alignment, an informational run of the harness at that time scored 95/95; see the new section.
- Score: 91/93.
- `common.no_stray_writes` failed. This is the real TMPDIR failure described above.
- `tui.no_color` failed only on the expectation that the first row is selected after Esc clears a filter. The color assertion itself passed. The contract doesn't specify the selection, so I escalated instead of changing behavior.

## 2. Toolchain and dependency versions

From command output:
- Bun: `bun --version` gives `1.4.2`; `--revision` gives `1.4.2+744846f84`. The 1.4.2 source tree is written in Rust.
- TypeScript: `tsc` 5.9.3, used for typechecking only.
- Node: v24.18.0 is installed but not used. OpenTUI 0.5.14 declares `engines bun>=1.3.0, node>=26.4.0`, and Node also needs `--experimental-ffi`.
- Docker: 29.8.0 (client and server).
- Runtime dependencies, pinned exactly in `package.json` and `bun.lock`:
  - `@opentui/core@0.5.14` (MIT)
  - `smol-toml@1.9.0` (BSD-3-Clause)
- Dev dependencies:
  - `typescript@5.9.3`
  - `@types/bun@1.4.2`
  - `ajv@8.20.0`

## 3. Design

- `src/domain/` is pure (no I/O):
  - `result.ts`: the result envelope
  - `profile.ts`: profile parsing and validation
  - `agent.ts`: bounded agent frame codec
  - `run.ts`: meta result and Windows quoting
  - `listview.ts`: TUI state machine and layout
- `src/platform/` holds the I/O adapters:
  - `files.ts`: bounded file read
  - `agent-client.ts`: `node:net` client
  - `run.ts`: `Bun.spawn` plus signal forwarding
  - `tty.ts`: two libc calls through `bun:ffi`
  - `stdio.ts`
- `src/tui/` holds the OpenTUI adapter (`tui.ts`) and the NO_COLOR filter (`nocolor.ts`).
- `src/cli.ts` handles argument parsing and exit codes only.

The TUI uses the same `parseProfile` as the CLI. All selection, filter, and layout logic lives in `listview.ts`, which is tested without a terminal. The TUI module is lazy-imported, so non-TUI commands never load the native library.

Behaviors the contract leaves open, which I chose and escalated (*[§9 update]* all now settled by §9; the first item changed, K9):
- After a filter change, keep the previous selection if it is still visible; otherwise select row 0. *[§9 update]* Now every filter change selects row 0; `Enter` keeps the selection (K9).
- `tui` exits 143 on SIGTERM and 129 on SIGHUP.
- The `run` meta result `CHILD_EXITED` uses state `succeeded` even when the child exits non-zero. `CHILD_LAUNCH_FAILED` uses `failed`.
- `agent list`: if the peer closes after 0 bytes, the result is AGENT_UNAVAILABLE; after at least 1 byte, AGENT_PROTOCOL_ERROR.
- `profile show` and `version` emit JSON even without `--json`.

TOML parser choice:
- `Bun.TOML.parse` was rejected. It returns `1.0` as `1`, so it cannot reject a non-integer revision. It also rejects integers above 2^53.
- `smol-toml` with BigInt integers can tell the two apart. Its `TomlError.message` includes source excerpts (values), so the prototype emits only line and column. A canary test confirms no value is echoed.

## 4. Hard parts, workarounds, and stack findings

Elapsed time: about 40 minutes from the first command (23:56Z) to the final test run (00:29Z), plus report writing.

### 4.1 Distribution and native code

**Build-time downloads.**
- `bun build --compile --target=bun-<t>` folds `process.platform` per target, so each artifact embeds only its own libopentui.
- Cross-target builds download the target Bun runtime from `registry.npmjs.org` (`@oven/bun-<target>`) into `~/.bun/install/cache`.
- Bun's source shows no integrity check beyond TLS, and the download honors proxy settings and `NODE_TLS_REJECT_UNAUTHORIZED`.

**Native code extracted to TMPDIR at runtime.**
- `dlopen` needs a real file, so Bun writes `$TMPDIR/.bun-<uid>-<wyhash>.<ext>` (mode 0600) and leaves it there.
- Bun reuses an existing file at that name if it is a regular file, has the same uid, and has the same size. It does not check the content. On Windows the ownership check is unconditionally true.
- Probe 2 confirmed this: a zero-filled file of the same size was loaded (TUI exit 1) and left unchanged.
- Consequence: any same-user process that can write to TMPDIR can inject code into the binary.
- A verified mitigation exists: ship libopentui as a sidecar file and set `OTUI_ASSET_ROOT`. No extraction happens then (probe 4).
- That variable is also honored when inherited from the environment, so a real build would have to pin it.
- I did not adopt the sidecar layout in `build.sh` because it changes the §7 artifact shape. *[§9 update]* K11 permits it, and it is now adopted, with the variable pinned by the program; see the new section.
- A `.bun-501-33eea43aef98a673.dylib` from before this task was in my real TMPDIR, and my default-TMPDIR test runs reused it. Its SHA-256 equals the packaged library, so the results stand.

**`BUN_BE_BUN=1`.**
- With this variable set, the artifact acts as the full Bun CLI: `-e` executed arbitrary code (probe 5).
- I found no build flag to disable it.

**`.env` and `bunfig.toml` autoload.**
- A default compiled executable loads `.env` and `bunfig.toml` from the working directory.
- `build.sh` passes `--no-compile-autoload-dotenv --no-compile-autoload-bunfig`. Probe 6 shows the difference.

**Other packaging facts.**
- The glibc-linked Linux artifacts fail on musl (Alpine exit 255).
- The macOS artifact has only an ad-hoc linker signature, and `spctl` rejects it.
- Builds with the same output filename are byte-identical on this host. The output filename is embedded, so changing it changes the digest.

### 4.2 NO_COLOR

- OpenTUI 0.5.14 ignores NO_COLOR and always emits truecolor or 256-color SGR (observed `ESC[38;2;255;255;255m`).
- Using a `transparent` foreground made the text invisible.
- Workaround: with NO_COLOR set, pass a proxied stdout. That switches OpenTUI to its JS "feed" output path, and a streaming filter removes color parameters from SGR sequences. The filter is unit-tested, including sequences split across writes.
- Trap: OpenTUI patches `process.stdout.write`. Writing back through it looped forever on the same 246-byte chunk, so the filter writes to fd 1 directly.
- The selected row always carries `> `, so selection never depends on color.

### 4.3 Exceptions swallowed by the framework

- OpenTUI's KeyHandler catches exceptions from listeners, prints the stack trace with source excerpts over the screen, and keeps running.
- It also installs process-wide `uncaughtException` handlers that only log.
- The adapter wraps its handlers and routes exceptions to an exit that restores the terminal (exit 1).
- Verified with a test-only hook (`HEIMDALL_PROTO_FAULT=tui-throw` plus `!`).

### 4.4 Other OpenTUI terminal behavior

- At startup it sends many capability queries: OSC 10/11, DA1, XTGETTCAP, DECRQM, `CSI 6n` three times, kitty queries, OSC 66/99/1337.
- On exit it clears the window title (empty `OSC 0`) and resets the cursor color and style.
- The default 100 ms resize debounce would hit the contract limit, so the prototype sets `debounceDelay: 1`. Observed re-layout: 7 to 17 ms.

### 4.5 Signals in `run`

*[§9 update]* This subsection describes the first build. The mechanism was replaced to satisfy K6 (child in its own process group, launched through `bun:ffi` `posix_spawnp`); see the new section. The last bullet's gap is closed.

- Bun delivers INT, TERM, HUP, QUIT, and WINCH to `process.on` handlers.
- SIGINT and SIGQUIT are not forwarded while heimdall-proto is the terminal's foreground process group (`tcgetpgrp`/`getpgrp` via `bun:ffi`), because the terminal already delivered them to the child.
- The PTY test uses a Python child. A negative control with the check disabled counted 2 SIGINTs; the real build counted 1.
- Limitation: a `kill -INT` aimed at heimdall-proto while it is the foreground group is not forwarded, because Bun exposes no siginfo.

## 5. Known defects (observed)

1. §1: the TUI writes the native library to TMPDIR, leaves it, and trusts a planted file of the same size. *[§9 update]* Fixed (K11 sidecar).
2. §4: invalid-UTF-8 argv is altered (`61 ff 62` arrives as `61 ef bf bd 62`). Valid UTF-8 passes, and environment values with invalid UTF-8 pass unchanged. *[§9 update]* Still observed; recorded as a stack limitation under K8.
3. `BUN_BE_BUN` turns the artifact into a general runtime.
4. OpenTUI clears the window title on exit.
5. Width is approximated by code point count. Wide CJK glyphs can overflow by one cell; this is cosmetic.
6. Artifacts are large (73 to 99 MB) and include unused OpenTUI image, audio, and tree-sitter assets. *[§9 update]* Now 67 to 91 MB plus a 5.6 to 6.4 MB library sidecar.

## 6. Build results

*[§9 update]* This table is the first build. The current build (2026-10-03T18:21Z) is in the new section.

Final build: 2026-10-03T00:29Z, `build.sh` exit 0.

| Target | Bytes | SHA-256 | Executed |
|---|---|---|---|
| darwin-arm64 | 72,745,074 | d94754c7646b96fbbb52652a70cffe8eca77a157d51016b27fe34cfda479a6b1 | macOS host, full suite 128/128 |
| linux-x64 | 98,813,408 | 185920eb820599720ea85f900daf65c9c8b66a8444f1624d15f64c45affc129d | debian:trixie amd64 container, emulated, smoke test |
| linux-arm64 | 97,962,280 | 3c067c8769a15c4221d182770673913998f65c11f637335f384135bec00bb446 | debian:trixie arm64 container, smoke test |
| windows-x64 | 97,369,600 | 5dbe0f5e446e68de3dfd923e23159f628801032ad49327bc917810a2006662ee | Not executed (blocked: needs Windows) |

Measurements on darwin-arm64:

| Measurement | Result |
|---|---|
| `version` | median 19.6 ms |
| `profile show`, 100 destinations | median 21.0 ms |
| Max RSS, version / profile | 25.7 / 29.7 MB |
| TUI first frame | median 59.9 ms |
| TUI RSS | about 60 MB |
| Filter over 100 destinations | 7–8 ms |
| Resize re-layout | 7–17 ms |
| Agent SIGINT to exit 130 | 1.4–2.0 ms |

## 7. Tests (6 files, 128 tests)

*[§9 update]* Now 7 files, 153 tests; the additions are listed in the new section. `test/dist.test.ts` needs `build.sh` to have run first.

- **`profile.test.ts`:**
  - every fixture, positive and negative
  - key paths, plus canary and value-leak checks
  - schema-version warning
  - 1 MiB boundary (exact size and +1)
  - missing file and directory
  - 16 generated domain cases
- **`agent.test.ts`:**
  - Frame bounds: oversize length, huge nkeys and 1025, string overruns, trailing bytes, truncation, wrong type, failure, exactly MAX_FRAME, and an invalid UTF-8 comment.
  - Fake socket: fragmented replies, refused, fail-fast on an oversize header, timeout, missing socket, SIGINT cancel under 500 ms, request bytes exactly `00 00 00 01 0b`.
  - Disposable `/usr/bin/ssh-agent`: fingerprint matches `ssh-keygen -l -E sha256`.
- **`run.test.ts`:**
  - 16 tricky argv values and PATH lookup
  - binary stdin and stderr passthrough
  - exit code and meta file in a Unicode path
  - signal deaths 15, 9, 11
  - launch failures, usage errors, cwd and env inheritance
  - forwarding of INT, TERM, HUP, QUIT, WINCH without a TTY (heimdall-proto keeps waiting, no orphan)
  - PTY Ctrl-C delivered exactly once
  - untrapped SIGINT gives 130
- **`units.test.ts`:**
  - Windows quoting vectors, round-trip, and Microsoft's documented examples
  - list view-model
  - NO_COLOR filter
- **`tui.test.ts`** (real PTY, with a `stty -g` wrapper so termios is checked on every exit path):
  - select, quit, Ctrl-C 130
  - SIGTERM 143, SIGINT 130, SIGHUP 129
  - injected exception gives 1
  - filtering: Unicode, Backspace, host match, Esc
  - 100-destination latency
  - resize to 20×5 in under 100 ms
  - NO_COLOR with a positive control
  - non-TTY gives 2
  - Screen assertions use a small VT model because OpenTUI redraws only changed cells.
- **`cli.test.ts`:**
  - `version`
  - 10 usage-error shapes (plain vs `--json`)
  - no ANSI in stderr

## 8. Windows notes (compile-checked only, not executed)

Native verification is blocked: it needs a Windows x64 host.

- **Named pipe:** `node:net` with a `\\.\pipe\…` path. Bun 1.4.2's `Listener.rs` routes such paths to its Windows named-pipe client (from reading the source, not running it).
- **Console Ctrl-C:** `run` registers no-op SIGINT and SIGBREAK handlers and doesn't forward; the console delivers CTRL_C_EVENT to the child directly. `agent list` treats SIGINT or SIGBREAK as cancel (exit 130).
- **CreateProcess quoting:**
  - Resolve argv[0] with `Bun.which`, and refuse `.bat`/`.cmd` targets (cmd.exe re-parses the line: BatBadBut).
  - Quote `argv[1..]` with `quoteWindowsArg`, unit-tested against a CommandLineToArgvW reference.
  - Spawn with `windowsVerbatimArguments` and `argv0` set to the quoted program token. Bun's source shows `argv0` becomes the command-line token and `cmd[0]` is the file.
- **ConPTY / console resize:** relies on OpenTUI's `opentui.dll` and Bun's stdout resize events. Not verified.
- **Extraction:** the embedded DLL would be extracted to `%TEMP%`, and the ownership check is unconditional on Windows. *[§9 update]* The DLL is now a sidecar (`dist/windows-x64/@opentui/core-win32-x64/opentui.dll`), loaded from the executable's directory. This was not executed: it needs Windows.

## 9. Native, unsafe, and downloaded components

- **libopentui (Zig):** loaded through `bun:ffi` and bundles Ghostty, lcms2, libwebp, stb, and Wuffs code.
- **libc via `bun:ffi`:** `tcgetpgrp` and `getpgrp` only. *[§9 update]* Now also `posix_spawnp` and its attribute and file-action calls, `sigfillset`, `sigemptyset`, `waitpid`, `tcsetpgrp`, `signal`, and `_NSGetEnviron` (macOS) or `dlsym` (Linux) to read `environ` (`src/platform/posix-spawn.ts`). Arguments are integers and caller-owned buffers, plus a NUL-terminated argv pointer array.
- **Embedded runtime:** Bun 1.4.2, including JavaScriptCore and BoringSSL.
- **Build-time downloads:**
  - npm packages, protected by lockfile integrity hashes
  - cross-target Bun runtimes, TLS only
  - `license-checker-rseidelsohn@5.0.1` via `bunx`
  - Docker images `debian:trixie` (arm64 and amd64) and `alpine:3.22`
- **Runtime downloads:** none observed. The TUI does write native code to TMPDIR. *[§9 update]* It no longer does (K11).

## 10. Maintenance signals (observed 2026-10-03)

| Package / repo | Pinned (published) | Latest (published) / activity |
|---|---|---|
| @opentui/core | 0.5.14 (2026-09-30) | 0.5.14; three releases 2026-09-22..30 |
| anomalyco/opentui | | 13,456 stars, 154 open issues, pushed 2026-10-02 |
| bun | 1.4.2 (2026-09-05) | 1.4.2; repo has 9,639 open issues |
| smol-toml | 1.9.0 (2026-09-22) | 1.9.0 |
| @number0/iroh | 1.1.0 (2026-07-16) | 1.1.0 |
| marked | 17.0.1 | 18.0.14 |
| string-width | 7.2.0 | 8.3.0 |
| web-tree-sitter | 0.25.10 | 0.27.0 |
| typescript | 5.9.3 | 7.0.2 |

OpenTUI is pre-1.0 and fast-moving. Its README calls the native ABI and platform packages internal surfaces.

## 11. Iroh integration path (recorded, not implemented)

**Embedded library is possible.**
- Package: `@number0/iroh@1.1.0`, napi-rs bindings from `iroh-ffi` (MIT OR Apache-2.0).
- There is no darwin-x64 package.
- The Rust crate `iroh` is at 1.3.0, so the JS binding may lag the crate.
- Scratch probe:
  - It loads in Bun 1.4.2 and `SecretKey.generate()` works.
  - It survives `bun build --compile`, and the binary runs with no Bun on PATH.
  - Its `.node` addon (13 MB) is extracted to TMPDIR exactly like libopentui.
  - No endpoint was bound and no network was used.

**A supervised Rust helper is the alternative.** It avoids napi and runtime extraction, at the cost of a second artifact and an IPC contract.

## 12. Licensing

See `LICENSES.md`. No copyleft license appears in the npm tree. Every artifact statically links Bun's LGPL-2 JavaScriptCore/WebCore and LGPL-2.1 tinycc, which carries relinking and notice obligations. The libwebp patent grant ships inside libopentui. No notice file is shipped in `dist/` yet.

## 13. Reproduce

- Build: `sh prototypes/ts/build.sh`
- Install: `cd prototypes/ts && bun install --frozen-lockfile --os='*' --cpu='*'`
- Test against source: `bun test --timeout 20000`
- Test against the binary: `HEIMDALL_PROTO_BIN=$PWD/dist/darwin-arm64/heimdall-proto bun test --timeout 20000`
- *[§9 update]* §9 probes, from the repo root: `OLD_BIN=<pre-alignment build> sh tests/evidence/artifacts/g02-ts/selftest/k-align/probes.sh`. The Linux container smoke script is `k-align/ctest-k.sh`.
- Security probes, from the repo root: `sh tests/evidence/artifacts/g02-ts/selftest/security-probes.sh`

## §9 alignment (2026-10-03)

Task M00-T05-ts-align, from 2026-10-03T18:11Z to about 18:30Z, on the same macOS 27.0 arm64 host. The goal was to bring the prototype into line with contract §9 (K1–K12) using the smallest changes. Every changed behavior has a native test. Raw evidence is in `tests/evidence/artifacts/g02-ts/selftest/k-align/`.

### K1–K12

| Ruling | Result | What and where | Proof |
|---|---|---|---|
| K1: control characters in agent strings | **Changed** | `src/domain/result.ts` `sanitize` now replaces C0 (including TAB), DEL and C1 with U+FFFD instead of writing `\u001b`-style text. `src/domain/agent.ts` decodes `comment` and `key_type` leniently: invalid UTF-8 becomes U+FFFD, then the controls are replaced. A `key_type` that is not valid UTF-8 used to be `AGENT_PROTOCOL_ERROR`; now it is U+FFFD. | `agent.test.ts`: "K1: C0 … in comment", "K1: key_type with invalid UTF-8", "K1: decoded JSON strings contain no C0/DEL/C1 code points" (fake endpoint, end to end). The end-to-end test fails against the pre-alignment binary. |
| K2: control characters in profile values | **Changed** | `src/domain/profile.ts` rejects any C0, DEL or C1 in `name`, `id`, `alias`, `host`, `account` and `labels[j]` with `SCHEMA_INVALID`. `key_path` names the key and the message never contains the value. `[meta]` is not inspected. | `profile.test.ts`: six "K2:" domain cases (ESC, literal TAB, NUL, DEL, U+0085, U+009B in a label, each with a canary), "K2: via CLI" (exit 2, no canary; U+00A0 still accepted), "K2: control characters inside [meta] are still tolerated". The CLI test fails against the pre-alignment binary. |
| K3: agent EOF | Already conformed | `src/platform/agent-client.ts` (unchanged) | New `agent.test.ts` tests: "K3: peer closes …" and "K3: peer resets …" before any byte give `AGENT_UNAVAILABLE`; "K3: 1 byte then close / reset" gives `AGENT_PROTOCOL_ERROR`. They pass on the pre-alignment binary too. |
| K4: failure frame shape | Already conformed | `src/domain/agent.ts` (unchanged) | Existing domain test "failure with payload → protocol_error". New end-to-end test "K4: type-5 frame with a payload → AGENT_PROTOCOL_ERROR". |
| K5: meta `state` | Already conformed | `src/domain/run.ts` (unchanged) | `run.test.ts` now also asserts `state`: `succeeded` for exit 42 and for signal deaths 15, 9 and 11; `failed` for launch failures. |
| K6: signal mechanism | **Changed** | See "K6 mechanism" below. New `src/platform/posix-spawn.ts`; `src/platform/run.ts` rewritten for Unix; `src/platform/tty.ts` removed. | `run.test.ts`: "K6: PTY: terminal ^C/^\/resize once each AND explicit kill INT/QUIT/WINCH/TERM/HUP to proto once each; fg group restored", "K6: child runs in its own process group (no TTY)", "K6 side effect: PTY Ctrl-Z …". The existing tests still pass: no-TTY forwarding of all five signals exactly once, PTY Ctrl-C once, and untrapped SIGINT giving 130. `k-align/probes.sh` K6 probe: an explicit `kill -INT` while heimdall-proto is the PTY foreground group reaches the child once (new) versus 0 times (pre-alignment). Linux containers (`k-align/linux-container-smoke.log`): no-TTY explicit INT and QUIT once each; under script(1), terminal ^C once plus an explicit `kill -INT` once (INT=2), and the shell's group is foreground again afterwards. |
| K7: PATH lookup | Statement only | | The Unix lookup is now `Bun.which`, which follows execvp rules (executable regular file). I did not check how it treats empty or `.` PATH entries. K7 allows either result, and it is not tested. |
| K8: invalid-UTF-8 argv | **Stack limitation** | No code change. | Bun decodes argv into JS strings before user code runs, so `61 ff 62` reaches the child as `61 ef bf bd 62`. Observed on macOS (`k-align/probes.sh`) and in both Linux containers (`k-align/linux-container-smoke.log`). The informational harness run recorded `observed ["efbfbdefbfbd2d78"]` against `expected ["fffe2d78"]`. Environment values pass byte-for-byte (`61 ff 62`). No native helper or workaround was added. See escalation E2 for an untried `bun:ffi` route. |
| K9: selection after a filter edit | **Changed** | `src/domain/listview.ts` `refilter`: every filter change (append, Backspace, Esc clear) sets the selection and scroll offset to row 0. `Enter` leaves filter mode and keeps the selection. | `units.test.ts` "K9: append, Backspace and Esc each reset selection …; Enter keeps it" (also covers scroll reset over 100 rows). `tui.test.ts` "filter: …" now asserts under a real PTY that `> lab-server` is selected after Esc, where `nas` was selected before. That PTY test fails against the pre-alignment binary. |
| K10: TUI exit codes | Already conformed | No code change. | `tui.test.ts`: SIGTERM gives 143, SIGHUP gives 129, an injected exception gives 1; each now also asserts no `SELECTED` output. New test "K10: terminal hangup (PTY master closed) → exit 129" (5 of 5 probe runs gave 129 before the test was added). |
| K11: native code and sidecars | **Changed** | `build.sh` builds with `--external '@opentui/core-*'` (no native library embedded) and copies the target's library to `dist/<target>/@opentui/core-<platform>/<lib>`. `scripts/manifest.ts` adds `sidecars` (`path`, `bytes`, `sha256`). `src/cli.ts` `pinNativeAssets()`, in the compiled executable, sets `OTUI_ASSET_ROOT` to `dirname(realpath(process.execPath))` and deletes `OPENTUI_LIBC` before OpenTUI is imported. Inherited values are overwritten. A missing sidecar makes OpenTUI throw, so the TUI exits 1 with no fallback. | New `test/dist.test.ts` (5 tests, against the artifact): nothing written to a fresh empty TMPDIR, HOME or cwd. An inherited `OTUI_ASSET_ROOT` pointing at a same-size zero-filled library, a relative `OTUI_ASSET_ROOT`, and `OPENTUI_LIBC=musl` are all ignored. Invoked through a symlink, the library is found from the real path and a planted file beside the link is ignored. A missing sidecar gives exit 1 with nothing extracted. `k-align/probes.sh`: `profile show`, `version`, `run` and `tui` leave a fresh TMPDIR empty. Linux containers: fresh TMPDIR empty, no `.bun-*` in `/tmp`, hostile env ignored, missing sidecar gives exit 1. Four of the five tests fail against the pre-alignment binary. |
| K12: output without `--json` | Statement only | | `profile show` and `version` still print JSON without `--json`; K12 leaves that unjudged. Exit codes do not depend on `--json` (`cli.test.ts`). |

### K6 mechanism and known gaps

- Bun.spawn cannot set a process group. Its only option is `detached`, which calls setsid and drops the controlling terminal. Bun also exposes no siginfo, so a terminal SIGINT and an explicit `kill -INT` look the same to heimdall-proto. Job control was therefore implemented through `bun:ffi` (`src/platform/posix-spawn.ts`). That file is about 170 lines of unsafe FFI and is the largest change in this alignment.
- **Launch.** The child is launched with `posix_spawnp` and these flags:
  - `POSIX_SPAWN_SETPGROUP` (pgroup 0): the child gets its own group.
  - `SETSIGDEF` with the full set: Bun ignores SIGPIPE, and the child must not inherit that. Observed: `kill -PIPE $$` in the child now gives 141.
  - `SETSIGMASK` with an empty set.
  - On macOS, `POSIX_SPAWN_CLOEXEC_DEFAULT` plus inheriting fds 0–2: no fd leaks, and `/dev/fd` lists the same entries as a direct run.
- **Environment.** The child gets the C `environ`, so non-UTF-8 environment bytes still pass. It is read with `_NSGetEnviron` on macOS and `dlsym(RTLD_DEFAULT, "environ")` on Linux.
- **Launch failure.** argv[0] is resolved first with `Bun.which`. In the emulated linux-x64 container, `posix_spawnp` returned success for a missing command and the child exited 127, which the meta file reported as `CHILD_EXITED`. The cause was not traced. Native macOS and linux-arm64 reported the error correctly.
- **Terminal hand-off.**
  - If heimdall-proto is the foreground group of the first terminal among fds 0–2, it hands that terminal to the child's group with `tcsetpgrp`.
  - When the child ends, heimdall-proto takes the terminal back with `tcsetpgrp`, ignoring SIGTTOU only for that call.
  - Terminal-generated INT, QUIT and WINCH then reach only the child. Every signal that heimdall-proto itself receives is forwarded once with `kill(pid)`.
- **Waiting.** The child is reaped by polling `waitpid(WNOHANG|WUNTRACED)` every 5 ms. Exit codes and signals were correct on macOS and in both Linux containers, which suggests Bun does not reap it first.
- **Ctrl-Z** (added because the hand-off would otherwise leave the terminal owned by a stopped child):
  - A SIGTSTP or SIGSTOP stop of the child makes heimdall-proto take the terminal back and stop itself.
  - On SIGCONT it hands the terminal back and continues the child's group.
  - A SIGTTIN or SIGTTOU stop from before the hand-off is resumed automatically.
- **Gaps** (none of them tested):
  - A signal that arrives before `posix_spawnp` returns is not forwarded.
  - A SIGTTIN/SIGTTOU stop from a child that deliberately backgrounds itself would be resumed.
  - If heimdall-proto is killed with SIGKILL while the child holds the terminal, the child keeps it.
  - A child that is itself a job-control shell was not tried.
  - Windows is unchanged: no forwarding, and the console delivers Ctrl-C to the child. It was not executed.
- **Side fix.** The first build forwarded SIGWINCH even when the terminal had already sent it, so a resize reached the child twice. The K6 PTY test caught this on the pre-alignment binary.

### K11 layout and what remains

- **Layout.** `dist/<target>/heimdall-proto[.exe]` plus `dist/<target>/@opentui/core-<platform>/<libopentui.dylib|libopentui.so|opentui.dll>`. The sub-path is OpenTUI's own asset key (`OTUI_ASSET_ROOT/<pkg>/<file>`). Placing the file flat beside the executable would need a patched OpenTUI (escalation E1).
- **Sizes.** Executables are now 67.1 MB (darwin-arm64), 86.2 MB (linux-x64), 86.2 MB (linux-arm64) and 91.0 MB (windows-x64).
  - Each linux executable shrank by about the size of the glibc library plus the musl library. My inference is that the first build embedded both; LICENSES.md is corrected.
- **No content check at load.** The program does not verify the sidecar's content before `dlopen`. K11 requires verification only for code reused from a shared temporary location, and the sidecar is shipped inside the artifact directory.
- **`BUN_BE_BUN=1` still works.** With it set, the artifact is still a general Bun runtime: `-e` evaluated code with exit 0 (`k-align/probes.sh`). No build flag was found to disable it. This is a stack limitation.
- **`.env` autoload** stays disabled (probe).

### Build (2026-10-03T18:21:18Z, `build.sh` exit 0; a rebuild at 18:24:56Z was byte-identical)

| Target | Executable bytes | Executable SHA-256 | Sidecar bytes | Sidecar SHA-256 | Executed |
|---|---|---|---|---|---|
| darwin-arm64 | 67,147,506 | cbc197f6cb006919b9d0bfb5e9c77b01250ccd1d75188b3b8f8795d11df0bc9d | 5,560,064 | 708d89ccc32a1528df745788d361a6d22fc0748da017b83990ae70dba223caa6 | macOS host, full suite 153/153 |
| linux-x64 | 86,205,920 | 8feca43bacfb87f34a37eb9df4c859865e772094a0d55bcb74cd78229e22b570 | 6,314,816 | be65f2428361c08fc717a20b67a81990e2864aa2067874d625aa590dee71fcce | debian:trixie amd64 container, emulated, K smoke |
| linux-arm64 | 86,165,800 | 31ee3c33a97af1b26a1cc5b2cb53b18522a8b6ff066f7b20c61446f8e1bca8e2 | 5,907,256 | a9b0e0a95dd3d5c8515a4c94bff42d2e061c7f9ad1860f88ff86a509c916554e | debian:trixie arm64 container, K smoke |
| windows-x64 | 90,981,888 | 79e5827342be78e9670f545966cb5aae5389f29908e41dc24d4b0017bf40a883 | 6,391,688 | 701435b577754aab978f1dc896e0defaf9dffc9abb952ad2f7d3b823755cf827 | Not executed (blocked: needs Windows x64) |

### Test runs (real exit codes)

| Run | Exit | Result |
|---|---|---|
| `tsc --noEmit` | 0 | |
| `bun test --timeout 30000`, source | 0 | 153 pass, 0 fail, 7 files |
| `HEIMDALL_PROTO_BIN=dist/darwin-arm64/heimdall-proto bun test --timeout 30000` | 0 | 153 pass, 0 fail |
| `test/run.test.ts`, 3 repeats after the Ctrl-Z test was added | 0, 0, 0 | 15 pass each |
| Negative control: the suite against a binary built from the pre-alignment sources, before the Ctrl-Z test existed | 1 | 143 pass, 9 fail |
| Linux container K smoke (`ctest-k.sh`), arm64 and amd64 | 0, 0 (`DOCKER_EXIT`) | |
| Shared harness, read-only, informational, in flux (`conformance.py` sha256 `75b23fbe…`) | 0 | 95/95 |

The 9 negative-control failures were:
- K1: end-to-end strings
- K2: CLI test
- K6: two tests (the PTY test failed on the doubled WINCH)
- K9: PTY test
- K11: four tests

The harness's 95/95 includes `run.argv_invalid_utf8`, but that harness version treats the byte check as non-gating. The check itself recorded the mismatch, which conflicts with K8 (escalation E3).

The Linux images: `debian:trixie` was re-pulled for each platform (registry download; containers ran with `--network none`).

### Escalations

1. **E1, K11 "its own directory".** The sidecar is in a subdirectory of the executable's directory (`@opentui/core-<platform>/`), located from the real path. I read "its own directory" as covering this. A flat layout would need a patched OpenTUI. The orchestrator should confirm.
2. **E2, K8 route.** Raw argv bytes are reachable through `bun:ffi` (`_NSGetArgv` on macOS, `/proc/self/cmdline` on Linux). They could be passed to the `posix_spawnp` call already used for K6. I did not do this, because K8 says not to route around a stack limitation. It needs a ruling on whether `bun:ffi` counts as "the stack" for K8.
3. **E3, harness.** The harness version run here marks `run.argv_invalid_utf8` non-gating, which contradicts K8. This is for the harness owner. The TS candidate fails that check (observed bytes `efbfbdefbfbd2d78`).
4. **E4, scope.** The Ctrl-Z propagation is beyond the letter of §9. I added it only because the K6 hand-off would otherwise regress Ctrl-Z, leaving the terminal stuck with a stopped child. It is about 10 lines and has its own test.

## Conformance fixes (2026-10-03, M00-T05-ts-fix)

The shared harness (`conformance.py` sha256 `f2ccd7e7…`) failed two checks on the attempt-2 binary. Evidence is in `tests/evidence/artifacts/g02-ts/selftest/conformance-fix/`.

| Failure | Root cause | Fix |
|---|---|---|
| `tui.hangup_exit_129`, bare variant (K10): the pty master is closed and the session leader does not forward SIGHUP. The process was still running after 5 s. | `tui.ts` exited 129 only on SIGHUP. In a bare hangup the job gets no SIGHUP, only EOF/EIO on the tty. A probe under `pty_shim.py --no-hup-forward` showed that Bun then emits stdin `end` and `close`. Nothing listened for those events, and OpenTUI ignores them, so the TUI kept running. The existing hangup test missed this because there the program is the session leader, so the kernel sends it SIGHUP. | `tui.ts` now treats stdin `end`, `close` or `error` like SIGHUP: restore, then exit 129. In raw mode, Ctrl-D arrives as a byte, so EOF on the tty means the terminal is gone. New test `K10: bare terminal hangup` (`test/tui.test.ts` with `test/bare_hangup.py`, which reuses `tests/g02/pty_shim.py` read-only). It fails on a pre-fix build (rc null) and passes after the fix. |
| `run.argv_invalid_utf8` (K8, gating) | Bun decodes argv to U+FFFD before user code runs. `bun -e` shows `process.argv` and `Bun.argv` both as `61 ef bf bd 62` for the input `61 ff 62`. | No fix. This is a stack limitation under K8 (known defect 2, escalation E2). |

Results after the fix (real exit codes):
- `tsc --noEmit`: exit 0.
- `build.sh` (20:01:53Z): exit 0, 4/4 targets. The darwin-arm64 executable has sha256 `dd7a771d…`; the sidecars are unchanged.
- `bun test`: exit 0, 154/154, both from source and against the darwin-arm64 artifact.
- Harness, `--only tui.hangup_exit_129`: passed 3 times out of 3. Before the fix it failed.
- Full harness, read-only to `/tmp`: exit 1, 112/113. The one failure is `run.argv_invalid_utf8`.

Limits:
- The fix was verified on macOS only.
- Linux EOF/EIO behavior was not re-run in containers.
- The Windows console-close path is blocked: no Windows x64 host.

### Conformance fixes, second pass (2026-10-03T20:08Z, M00-T05-ts-fix re-dispatch)

Only one shared-harness failure was left: `run.argv_invalid_utf8`. Evidence is in `tests/evidence/artifacts/g02-ts/selftest/conformance-fix-2/`.

| Failure | Root cause | Fix |
|---|---|---|
| `run.argv_invalid_utf8` (K8, gating). The harness check is gating (`conformance.py` sha256 `f2ccd7e7…`), so E3 is stale. Elements 0–6 arrive with each invalid byte replaced by U+FFFD; for example `fffe2d78` arrives as `efbfbdefbfbd2d78`. Element 7, valid UTF-8, matches. | Reproduced with `argv-k8-probe.py`, exit 0: `bun -e` sees `61efbfbd62` for the input `61 ff 62` in both `process.argv` and `Bun.argv`. Bun decodes argv to JS strings before user code runs. `bun-types` exposes only `string[]` argv APIs, with no raw-bytes form. | No source change. This is a stack limitation under K8. The only route to the raw bytes is `bun:ffi` to `_NSGetArgv` or `/proc/self/cmdline`, which K8 counts as routing around. That route stays a production option only (E2). |

Results (real exit codes):
- `build.sh`: exit 0, 4/4 targets. The darwin-arm64 artifact is unchanged (`dd7a771d…`).
- `tsc --noEmit`: exit 0.
- `bun test`: exit 0, 154/154, both from source and against the artifact (absolute `HEIMDALL_PROTO_BIN`).
- Full harness, read-only to `/tmp`: exit 1, 112/113. The only failure is `run.argv_invalid_utf8`.

A first artifact test run used a relative `HEIMDALL_PROTO_BIN`. That run exited 1, with 4 ENOENT failures in tests that change cwd. This was an operator error, and the log is kept.
