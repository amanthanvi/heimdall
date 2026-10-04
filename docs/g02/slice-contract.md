# G02 common slice contract (frozen for M00)

**Status:** frozen by the orchestrator for the G02 comparison. Changes require an
orchestrator decision; prototype agents escalate instead of diverging.
**Scope:** plan.md §3 G02 slice only. This is *not* the Heimdall CLI design, the
policy engine, or a public contract. Names and codes here are prototype-local
and are not a G08 freeze.

All three candidates (Go + Bubble Tea, Rust + Ratatui, TypeScript + OpenTUI)
implement the identical behavior below as one executable named
`heimdall-proto` (`heimdall-proto.exe` on Windows). The shared harness in
`tests/g02/` tests every candidate the same way; conformance is judged only by
that harness and by recorded native runs.

## 1. Common rules

- Machine output is exactly one JSON document on **stdout**, followed by `\n`,
  validating against `schemas/g02/result.schema.json`. Human diagnostics go to
  **stderr** only. No ANSI escapes in JSON strings.
- Every JSON result has `schema_version` (`"1"`), `state`, `code`, `data`,
  `warnings` (array of strings), `next` (object or `null`).
- `state` ∈ `succeeded | failed | cancelled`.
- Exit codes (prototype-local, modeled on spec §11.6):

| Exit | Meaning | Codes |
|---|---|---|
| 0 | success | `PROFILE_OK`, `AGENT_OK`, `VERSION_OK` |
| 2 | usage or schema error | `USAGE_ERROR`, `SCHEMA_INVALID`, `INPUT_TOO_LARGE` |
| 5 | unavailable/failed dependency | `AGENT_UNAVAILABLE`, `AGENT_PROTOCOL_ERROR`, `AGENT_REFUSED` |
| 130 | cancelled by SIGINT / Ctrl-C | `CANCELLED` |
| 1 | unexpected internal failure | `INTERNAL` |

  `run` is the exception: see §4.
- Usage errors (unknown subcommand/flag, missing argument) print a JSON
  `USAGE_ERROR` result on stdout **only when `--json` was given**; otherwise
  stderr text only. Exit 2 either way.
- File paths with spaces and non-ASCII characters (UTF-8) must work everywhere a
  path is accepted.
- No secret value read from input may appear in stdout, stderr, or files the
  program writes (see the canary fixture in §2).
- No network access, no shell invocation, no writes outside paths named on the
  command line.

## 2. `heimdall-proto profile show --file <path> --json`

Parses a TOML profile (format: `tests/fixtures/g02/profiles/README.md`) and
emits:

```json
{"schema_version":"1","state":"succeeded","code":"PROFILE_OK",
 "data":{"profile":{"name":"homelab","revision":3,
   "destinations":[{"id":"dst_lab_server","alias":"lab-server",
     "host":"lab.example.internal","port":22,"account":"aman",
     "labels":["homelab","fixed-auth"]}]}},
 "warnings":[],"next":null}
```

- Destination order is preserved from the file. `port` defaults to 22 when
  omitted; `labels` defaults to `[]`.
- Top-level keys allowed: `schema_version`, `name`, `revision`, `meta`,
  `destinations`. Destination keys allowed: `id`, `alias`, `host`, `port`,
  `account`, `labels`. Any other key anywhere except inside `[meta]` →
  exit 2 `SCHEMA_INVALID`. `[meta]` content is tolerated and not echoed.
- `schema_version` must be the integer `1`; anything else → `SCHEMA_INVALID`
  with a warning naming the unsupported version (not the value of other keys).
- Required: `schema_version`, `name`, `revision` (integer ≥ 1), each
  destination's `id`, `alias`, `host`, `account`. `port` in 1..65535. Duplicate
  `id` or `alias` → `SCHEMA_INVALID`.
- Malformed TOML → exit 2 `SCHEMA_INVALID`.
- File larger than 1 MiB (1,048,576 bytes) → exit 2 `INPUT_TOO_LARGE` without
  parsing it. Missing/unreadable file → exit 2 `USAGE_ERROR`.
- Error results set `data` to `{"error":{"key_path":"<dotted path or null>",
  "message":"<text>"}}`. The message may name the offending **key path**; it
  must never include the offending **value** (the canary fixture places a
  `HEIMDALL_CANARY_` string in a forbidden key).

## 3. `heimdall-proto agent list --socket <path> [--timeout-ms N] --json`

Explicit local probe of an SSH-agent-protocol endpoint
(draft-miller-ssh-agent). Unix: `<path>` is a Unix-domain socket. Windows:
`<path>` is a named pipe (`\\.\pipe\...`); the Windows path must be implemented
and must compile, though it is only verifiable on real Windows (blocked here).

- Send one `SSH_AGENTC_REQUEST_IDENTITIES` (type 11) frame: `uint32 length=1`,
  `byte 11`.
- Accept `SSH_AGENT_IDENTITIES_ANSWER` (type 12): `uint32 nkeys`, then per key
  `string key_blob`, `string comment`. For each key emit
  `{"key_type": <first SSH string inside key_blob>,
    "fingerprint": "SHA256:" + base64-no-padding(sha256(key_blob)),
    "comment": <comment as UTF-8, invalid bytes replaced with U+FFFD>}`.
  Do not emit the raw blob.
- Success: exit 0, `AGENT_OK`, `data: {"identities":[...]}`.
- Bounds (fail closed, never allocate from an untrusted length first):
  response frame length > 262,144 bytes, `nkeys` > 1,024, any string length
  exceeding the remaining frame, trailing bytes after the last key, truncated
  frame, or an unexpected message type → exit 5 `AGENT_PROTOCOL_ERROR`.
- `SSH_AGENT_FAILURE` (type 5) → exit 5 `AGENT_REFUSED`.
- Connect failure, or no complete response within `--timeout-ms`
  (default 5000) → exit 5 `AGENT_UNAVAILABLE`.
- SIGINT (or console Ctrl-C on Windows) while waiting → close the connection,
  print `{"state":"cancelled","code":"CANCELLED",...}`, exit 130 within
  500 ms of the signal.
- Never send any message other than type 11. Never sign.

## 4. `heimdall-proto run [--meta-file <path>] -- <argv...>`

- Launch `argv[0]` (PATH lookup) with `argv[1..]` **without a shell**. Arguments
  containing spaces, quotes, `$`, `;`, `*`, newlines, or non-ASCII pass through
  byte-for-byte. On Windows, construct the command line with correct
  `CommandLineToArgvW`-compatible quoting (compile-checked; native test blocked).
- Child inherits stdin, stdout, stderr, the working directory, and the
  environment. `heimdall-proto` writes **nothing** to stdout in `run`; binary
  data (including NUL and invalid UTF-8) passes through unmodified in both
  directions.
- Exit status: the child's exit code. If the child dies by signal N, exit
  128+N (Unix). This is the documented ambiguity spec §10.4 mentions; the
  side channel resolves it.
- `--meta-file <path>`: after the child ends (or launch fails), write one JSON
  result to that file: `code` `CHILD_EXITED` or `CHILD_LAUNCH_FAILED`,
  `data: {"launched": bool, "exit_code": int|null, "signal": int|null}`.
- Launch failure (not found / not executable): exit 127, stderr message,
  meta `CHILD_LAUNCH_FAILED`, `launched:false`.
- Signals: SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH received by
  `heimdall-proto` are forwarded to the child; `heimdall-proto` waits for the
  child and does not exit first. Terminal-generated SIGINT (same process group)
  must not be delivered twice in a way that changes child behavior.
- No zombie or orphaned child after `heimdall-proto` exits normally.
- Missing `--` or empty argv → exit 2 `USAGE_ERROR` (stderr).

## 5. `heimdall-proto tui --file <path>`

Interactive list of the profile's destinations. Requires a TTY on stdin and
stdout; otherwise exit 2 `USAGE_ERROR` (stderr).

- Uses the alternate screen; hides the cursor while active.
- Each row shows `alias  account@host:port`. When terminal width < 50 columns,
  rows show only `alias`. A status line shows `<shown>/<total>` and the active
  filter text.
- The selected row is prefixed with `> ` (unselected rows with two spaces) —
  selection is never color-only. Honor `NO_COLOR` (no color SGR sequences at all
  when `NO_COLOR` is set and non-empty).
- Keys: `Up`/`Down` and `k`/`j` move; `/` enters filter mode; in filter mode,
  printable characters (including non-ASCII) append, `Backspace` deletes,
  `Enter` or `Esc` leaves filter mode (`Esc` also clears the filter). Filter is
  case-insensitive substring match over alias and host. `Enter` (not in filter
  mode) selects; `q` quits without selection; `Ctrl-C` cancels.
- Resize (SIGWINCH / console resize) re-lays out within 100 ms and never
  crashes, including at 20×5.
- On exit by any path (select, quit, Ctrl-C, SIGTERM, panic/exception): leave the
  alternate screen, show the cursor, restore the original termios settings.
  Then: select → print `SELECTED <alias>\n` to stdout, exit 0; quit → exit 0, no
  stdout; Ctrl-C → exit 130.
- No network, agent contact, or file writes. Search performs no I/O.
- Must handle the 100-destination fixture with immediate filtering.

## 6. `heimdall-proto version --json`

`code` `VERSION_OK`, `data: {"name":"heimdall-proto","version":"0.0.0-g02",
"candidate":"go|rust|ts","runtime":"<language/runtime version>",
"tui_framework":"<name>","tui_framework_version":"<pinned version>"}`.

## 7. Distributable build

`prototypes/<candidate>/build.sh` (POSIX sh, run from anywhere) produces
`prototypes/<candidate>/dist/<target>/heimdall-proto[.exe]` for as many of
`darwin-arm64`, `linux-x64`, `linux-arm64`, `windows-x64` as the toolchain can
produce, plus `prototypes/<candidate>/dist/manifest.json`:

```json
{"candidate":"go","targets":[{"target":"darwin-arm64","path":"darwin-arm64/heimdall-proto",
 "bytes":123,"sha256":"…","built":true,"error":null}]}
```

A target that fails to build is recorded with `built:false` and the actual
error. The artifact must run on a machine **without** the candidate's
development toolchain or a separately installed runtime (no Go/Rust/Node/Bun on
PATH). If a candidate cannot meet this, record it — do not hide it.

## 8. Not in scope

Policy engine, persistence, real SSH connections, signing, service/daemon
behavior, Iroh. Each prototype records (not implements) how Iroh would be
integrated in that language (embedded library vs. supervised helper) with
pinned version evidence.

## 9. Clarifications (orchestrator decisions, 2026-10-03)

The prototype builds and the harness surfaced gaps in this contract. These
rulings settle them for the G02 comparison only. They do not decide the
production CLI or any public contract. Each ruling is binding on all three
candidates and on the harness. The ID is cited in fixes and in the ADR.

- **K1. Control characters in agent output** (§1, §3). In `comment` and
  `key_type`, invalid UTF-8 becomes U+FFFD, and so does every C0 control
  (U+0000–U+001F, including TAB), DEL (U+007F) and C1 control (U+0080–U+009F)
  code point. The decoded JSON string values contain none of these code
  points. JSON-escaping them (`\u001b`) does not satisfy §1.
- **K2. Control characters in profile values** (§1, §2). A string value
  outside `[meta]` that contains a C0, DEL or C1 control code point fails with
  exit 2 `SCHEMA_INVALID`. `key_path` names the key, and the message never
  contains the value. Content inside `[meta]` is still tolerated and not
  echoed.
- **K3. Agent EOF** (§3). If the peer closes or resets the connection before
  sending any response byte, the result is `AGENT_UNAVAILABLE`. EOF after at
  least one byte but before a complete frame is `AGENT_PROTOCOL_ERROR`.
- **K3a. Agent connection reset** (§3, added 2026-10-03). A connection reset
  (`ECONNRESET` or equivalent) is classified like EOF in the same position.
  Before any response byte it is `AGENT_UNAVAILABLE`. After at least one byte
  but before a complete frame it is `AGENT_PROTOCOL_ERROR`.
- **K4. Failure frame shape** (§3). An `SSH_AGENT_FAILURE` frame must have
  length exactly 1. A type-5 frame that carries any payload is
  `AGENT_PROTOCOL_ERROR`.
- **K5. Meta `state`** (§4). `CHILD_EXITED` uses `state: "succeeded"` whatever
  the child's exit status: the launch-and-wait operation succeeded, and the
  child status is in `data`. `CHILD_LAUNCH_FAILED` uses `state: "failed"`.
- **K6. Signal mechanism** (§4). Any mechanism that meets the observable rules
  is acceptable, including running the child as its own foreground process
  group (job control). An explicitly sent signal to `heimdall-proto` (for
  example `kill -INT <pid>`) must still reach the child exactly once in every
  state. REPORT.md documents the mechanism and its known gaps. The harness
  judges only observable behavior.
- **K7. PATH lookup** (§4). The program may refuse a match found through an
  empty or `.` PATH entry and report it as launch failure (exit 127). That is
  stricter than execvp and is allowed. It is not tested.
- **K8. Invalid UTF-8 argv** (§4). This is in scope on Unix. "Byte-for-byte"
  includes argv elements that are not valid UTF-8. The harness check for it
  gates the result. A stack that cannot pass it records a stack limitation and
  does not route around it. Reaching raw argv through FFI to private libc
  entry points (for example `_NSGetArgv` or `/proc/self/cmdline` parsing
  through `bun:ffi`) counts as routing around. Record such a path as a
  production option, not as conformance.
- **K9. Selection after a filter edit** (§5). Each filter change (an appended
  character, Backspace, or the `Esc` clear) resets the selection to the first
  shown row. Leaving filter mode with `Enter` keeps the selection.
- **K10. TUI exit codes for other paths** (§5). On SIGTERM, restore the
  terminal and exit 143 with no stdout. On SIGHUP or terminal hangup, restore
  what is possible and exit 129. On an internal panic or exception, restore
  the terminal and exit 1. None of these paths writes to stdout.
- **K11. Native code and sidecars** (§1, §7). `dist/<target>/` may be a
  directory holding `heimdall-proto[.exe]` plus sidecar files. Single-file
  output is not required. Sidecars are listed in `manifest.json` under an
  optional per-target `sidecars` array (`path`, `bytes`, `sha256`). At runtime
  the executable loads sidecars only from its own directory, resolved from the
  executable's real location, and ignores inherited environment overrides of
  that location. "Its own directory" includes subdirectories of
  `dist/<target>/` (for example `@opentui/core-<platform>/`). At runtime the program writes nothing outside the paths named
  on its command line. Extracting executable code to a shared temporary
  location breaks §1 if the code is reused there without verifying its content
  or is left behind.
- **K12. Output without `--json`** (§2, §3, §6). Without `--json`, the output
  of `profile show`, `agent list` and `version` is unspecified and is not
  judged. Exit codes are the same as with `--json`.

### 9.1 Round-2 rulings (2026-10-03, after the round-1 adversarial reviews)

- **K6a. Job and signal transparency** (§4). `run` must not take
  terminal-foreground ownership away from any other process. It must not stop
  another member of its own job, for example a pipeline peer that reads the
  tty, or the script that started it as an `&` job of a non-job-control shell.
  A signal whose disposition `heimdall-proto` inherited as ignored (`nohup`,
  `trap '' HUP`, the SIGINT/SIGQUIT ignore of a non-interactive `&` job) stays
  ignored in the child and is not forwarded. This is exec semantics.
- **K10 confirmation.** "Terminal hangup" includes a hangup that the TUI sees
  only as EOF or EIO on the tty, with no SIGHUP. The harness check
  `tui.hangup_exit_129` (both variants) is correct.
- **K13. Platforms for the G02 verdict.** A candidate passes the common slice
  only if the full harness passes on darwin-arm64 **and** on linux-arm64. The
  Linux run uses the `linux-arm64` artifact in a digest-pinned container on
  the Docker Desktop arm64 VM: a native arm64 kernel, not emulation. Darwin
  delivers an AF_UNIX reset as EOF, so K3a is judged on Linux.
- **K14. Non-regular input files** (§2, §5). If `--file` names something that
  is not a regular file (a FIFO, socket, device or directory), the result is
  exit 2 `USAGE_ERROR` within 2 s, and the program never blocks waiting on it.
- **K15. Parser resource bound** (§2, §5). Parsing any input up to the 1 MiB
  bound, including deeply nested inline tables or arrays inside `[meta]`, must
  finish within 2 s and below 256 MiB peak RSS. The input is either accepted
  or rejected with `SCHEMA_INVALID`.
- **K16. No helper processes** (§1). Apart from the `run` child,
  `heimdall-proto` never executes another program. That includes terminal
  capability or multiplexer probes such as `tmux`, `tput` or `infocmp`. This
  holds whatever `TMUX`, `TERM`, `TERM_PROGRAM` or similar variables say.

TypeScript was frozen after round 1. It failed K8, a gating stack limitation,
and the review found environment-driven code loading in the Bun runtime that
the application cannot disable. Following plan §3 G02 "do not keep polishing
losing prototypes", the round-2 rulings were not applied to it. Its round-2
harness results are recorded for completeness only.

### 9.2 Signal-semantics priority (2026-10-03, after the round-2 fixes)

- **K6b. Precedence when the signal rules conflict** (§4, K6, K6a). Darwin
  gives a terminal-generated signal the same `siginfo` as `kill(2)`. Go's
  `os/signal` exposes no `siginfo` at all. So a launcher that shares its
  caller's process group cannot always tell a terminal signal from an explicit
  one. When the rules cannot all be met, they apply in this order:
  1. K6a: never take the terminal from, or stop, another process, and keep
     inherited ignores for SIGHUP and SIGINT.
  2. K6: a signal sent explicitly to the `heimdall-proto` PID reaches the
     child exactly once.
  3. §4: a terminal-generated SIGINT is not delivered twice.

  A candidate may give the child its own foreground group only when it can
  show it is alone in its process group and K6a still holds. Duplicate
  delivery of a terminal-generated signal where the platform or stack cannot
  tell its origin is allowed, as long as it is documented in REPORT.md. The
  harness treats it as non-gating, as its open question Q3 already does. A
  group-directed signal from another process (`killpg`) may reach the child
  twice. That is recorded, not gated.
- **K6c. Gated inherited-ignore scope.** K6a's inherited-ignore requirement
  gates SIGHUP (`nohup`) and SIGINT (the non-interactive `&` job). Where a
  stack resets other inherited ignored dispositions (SIGQUIT, SIGTERM,
  SIGWINCH, SIGPIPE) or the blocked-signal mask in the child, record it as a
  stack limitation with the production remedy (for example a cgo constructor).
  It is non-gating for G02 and goes into ADR-0002 as an input.
- **Still unspecified and not gated:** refusing to launch when `--meta-file`
  is unwritable, whether to follow symlinks on that path, and whether to write
  it atomically. The same goes for bidi and zero-width code points in
  displayed strings. Both are product-design inputs for M01 and do not affect
  the G02 comparison.

### 9.3 Round-3 rulings (2026-10-04): harness coverage only, no prototype changes

- **K6d. Shared mode** (§4, K6, K6b). K6's "exactly once in every state"
  covers a `heimdall-proto` that shares its process group with the terminal's
  foreground job: a pipeline member, or a child of a foreground
  non-job-control script, Makefile recipe or `sh -c`. A SIGINT, SIGTERM,
  SIGHUP, SIGQUIT or SIGWINCH sent explicitly to the `heimdall-proto` PID
  reaches the child at least once. Duplicate delivery is allowed under K6b
  where the origin cannot be told apart. Silent loss is a failure.
- **K6e. Job control** (§4). Under an interactive job-control shell, Ctrl-Z
  stops the `run` job, and `fg` resumes it with the child receiving terminal
  input again. `bg` followed by `fg` also works. The child is never left
  stopped while the shell believes the job is running, and the job is never
  re-stopped right after `fg`.
- **K17. Filter latency** (§5 "immediate filtering"). On the 100-destination
  fixture, the p95 keystroke-to-screen-update latency in filter mode is at
  most 100 ms. That is the spec §15.1 key budget. It is measured by the harness
  in its pty emulator, using the same method as the existing latency
  observation.
- **K18. Value non-echo scope** (§1, §2). Every offending input value counts as
  potentially secret. It must not appear on stdout **or** stderr. Key names
  may appear. This settles harness question Q9.
- **K10 exit form.** "Exit 143/129" means the process exit status. A
  re-raised signal that yields wait status "killed by signal" also
  conforms. This settles Q8.
- **Start-up window.** A signal that arrives before the program's own code
  runs (between exec and the language runtime's `main`) is outside the
  contract. It is documented as residual, not gated.
- **Not gated, recorded for ADR-0002:**
  - TUI exits by an unhandled signal such as SIGQUIT or SIGUSR1 without
    restoring the terminal.
  - Signals beyond the five forwarded ones, and SIGKILL, orphan the child.
  - Unbounded reads of terminfo or similar environment-selected files.
  - A child started with fd 1 closed gets a working fd 1.

### 9.4 Round-3c rulings (2026-10-04, after the round-3b reviews)

These rulings apply rules that already existed (K6e, K12) to cases the harness
did not check. Every candidate is re-run under harness 2.4.0, and any
candidate that fails gets one fix round.

- **K6e child-initiated stop.** K6e's clause "the child is never left stopped
  while the shell believes the job is running" also covers a child that stops
  itself, for example `kill(getpid(), SIGTSTP)`, which is how OpenSSH's `~^Z`
  escape works. Under an interactive job-control shell, the shell must report
  the job stopped, just as it does when the child is run directly. `fg` must
  then resume the child, and the child must read terminal input again.
  - Gated: SIGTSTP under bash, on darwin-arm64 and linux-arm64.
  - Recorded, not gated: SIGSTOP, and zsh.
- **K12 closed stdout.** "Exit codes are the same as with `--json`" also holds
  when stdout is a pipe whose reader has already closed. Which exit status
  results is not specified, but it must be the same with and without
  `--json`. Here "exit status" includes death by signal.
- **Not gated, recorded for ADR-0002 and M01:**
  - An explicit SIGTSTP or SIGSTOP sent to the launcher's PID stops only the
    launcher. The shell takes back the terminal while the child keeps
    running.
  - Duplicate keys in the environment block are not passed through exactly
    (the Go runtime drops the later duplicates).
  - The Windows executable search order differs from plain PATH lookup (Rust
    std searches the application directory and System32 first). This is from
    code review only.
