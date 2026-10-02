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
