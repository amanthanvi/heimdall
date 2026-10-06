# G02 round 4, X1: native linux-x64 and windows-x64 runs of the frozen Go and Rust artifacts

**Task:** `M00-T05-x1-g02-native`, run on 2026-10-06 (UTC).

**Artifacts:** Go `38b6b72` and Rust `d8f0cbe`, taken from `prototypes/<c>/dist/`.

- Every SHA-256 was verified against `dist/manifest.json` on the Mac.
- It was verified again on the host with `sha256sum`, and on Windows by the script's `integrity` row.
- Nothing was rebuilt, and `prototypes/` was not edited.

**Host:** the owner's Windows 11 Pro 26300 x64 PC.

- **linux-x64:** WSL2 Ubuntu 24.04.5, kernel `6.18.40.1-microsoft-standard-WSL2`, run as the non-root WSL user.
- **windows-x64:** run as the non-elevated Windows user, through WSL interop.

**Redaction:** user, host, profile paths and SIDs are replaced as follows.

| Placeholder | Stands for |
|---|---|
| `<wsluser>`, `<wslhome>`, `<wslscratch>` | the WSL user, home and scratch directory |
| `<winuser>`, `<winhome>`, `<winhost>` | the Windows user, profile and machine name |
| `<scratch>` | the Windows scratch directory |
| `S-1-5-21-<redacted>` | SIDs |

No canary value appears anywhere. On Windows this is the gating row `harness.canary_scan`, which counts hits before redaction; it found 0.

The **status** column uses the gate-probe convention: it describes the evidence. The **verdict** column is the result of the criterion.

| Item | go | rust |
|---|---|---|
| 1. linux-x64, full harness 2.4.2 (`tests/evidence/g02-<c>-conformance-linux-x64.json`) | verified / **pass**, 139/139 | verified / **pass**, 139/139 |
| 1b. linux-x64 with no toolchain on PATH (`env -i`) | every command ran; `run -- true` returns 127 with an empty PATH and 0 with `PATH=/usr/bin:/bin` (expected PATH semantics; corrected per x1-review) | same |
| 2. windows-x64 script (`tests/evidence/g02-<c>-x1-windows.json`) | verified / **pass**, 63/63 gating rows | verified / **fail**, 60/63 gating rows (3 failures, below) |
| 3. X4 spike on Windows (`x4-windows-run/`) | pipe checks 5/5 pass; DPAPI, CNG and TPM blocked | pipe checks 5/5 pass; DPAPI, CNG and TPM blocked |

## 1. linux-x64 (WSL2, native x86_64, no container)

**Command:** `linux-x64/run-linux.sh`. It runs the harness from a git archive of `772a6b1`, using a venv in the WSL scratch directory created with `pip install --require-hashes -r tests/g02/requirements.txt` (pyte 0.8.2, wcwidth 0.9.1). The two candidates ran one after the other.

| | go | rust |
|---|---|---|
| Harness exit / record | 0 / `verified`, `pass`, 139 pass 0 fail 0 error 0 skipped | 0 / `verified`, `pass`, 139 pass 0 fail 0 error 0 skipped |
| Duration (harness) | 184.2 s | 184.2 s |
| `file` / `ldd` | ELF x86-64, statically linked, stripped / "not a dynamic executable" | same |
| Shells | bash 5.2.21 (gating K6e); **zsh not installed**, so the zsh K6e observations were not run (non-gating) | same |
| K3a (connection reset) | ECONNRESET before the reply and after one byte (same as linux-arm64) | same |
| First TUI frame (observation) | 40.2 ms | 20.2 ms |
| K17 filter p95 (observation; bound 100 ms) | 17.7 ms | 2.7 ms |
| Agent SIGINT exit latency (observation) | 1.0–1.3 ms | 5.8–6.4 ms |

**Comparison with the darwin-arm64 and linux-arm64 records** (`linux-x64/compare-platforms.txt`, `compare-structural.txt`):

- Every one of the 139 checks has the same outcome on all three platforms, for both candidates.
- The only structural differences between linux-x64 and linux-arm64 are:
  1. **zsh rows not run.** The `zsh-*` entries in `k6e_job_control` and `k6e_child_self_stop` were not run on this host (`not_run: /bin/zsh not executable`).
  2. **Harness OS probe.** The harness's own probe, `harness_os_probe_back_to_back_signal_merge`, saw 1 duplicate in 10 trials on this kernel; linux-arm64 saw 0. This probe measures the OS, not heimdall-proto.
- Everything else differs only in timings.

**No toolchain** (`linux-x64/notoolchain.txt`): each artifact ran under `env -i` with:

- PATH=/usr/bin:/bin;
- PATH set to an empty directory.

The commands were `version --json`, `profile show` (homelab, spaced fixture, forbidden-key: exit 2, no canary-prefix hit), `run -- /bin/sh -c 'exit 7'` (exit 7), and `agent list` on a missing socket (exit 5).

| Command | Empty PATH directory | PATH=/usr/bin:/bin |
|---|---|---|
| `run -- true` | 127 for both candidates (Go: "command not found"; Rust: "cannot launch command: NotFound") | 0 for both |

Caveat: on this host, `/usr/bin` holds `go`, `gcc` and `node`. So `PATH=/usr/bin:/bin` does not hide a toolchain, and the empty-PATH run is the toolchain-free one.

## 2. windows-x64 (native Windows 11)

**Script:** `tests/native/windows-g02/Invoke-G02WindowsX1.ps1` (new). Its helpers sit in the same directory:

- `G02X1Native.cs` (P/Invoke: pseudoconsole, VT screen model, console control events);
- `Send-ConsoleCtrl.ps1`;
- `StallPipe.ps1`;
- `expected-homelab.json`;
- `argvdump/` (a Go child process that uses the standard library only; it was cross-compiled on the Mac, see `windows/argvdump-build.txt`).

The script also reuses `tests/native/windows/InstrumentedAgent.ps1` (same as HEAD) and `G03Common.psm1`, both unchanged by this task.

**`G03Common.psm1` provenance.** Another task was editing `G03Common.psm1` while this one ran, so the copy that ran is the working-tree version (sha256 `e0bf3cc4…`), not HEAD (`57d295c1…`). That copy is kept in `windows/used-g03-module/`.

- The differences are in `Get-G03Sha256Hex`, `Protect-G03Text`, and a new `Set-G03FileSystemDacl`.
- No row depends on them: this script calls `Get-G03Sha256Hex` only with non-empty input, and `Protect-G03Text` only on an agent start failure, which never occurred.

**Runs** (all in `windows/`, each with a console log, `results.json` and redacted per-row artifacts under `rows/`):

| Run | Shell | Exit | Rows |
|---|---|---|---|
| `final-ps51-a` | Windows PowerShell 5.1.26100.9549 | 1 | 167 |
| `final-ps7-a` | PowerShell 7.6.6 | 1 | 167 |
| `final-ps51-b` | Windows PowerShell 5.1.26100.9549 | 1 | 167 |

The verdicts are identical across the three runs for every row. Exit 1 means at least one gating row did not pass; every such row is a Rust row.

**Setup:**

- PATH was reduced to `%SystemRoot%\System32;%SystemRoot%\System32\WindowsPowerShell\v1.0\`. `%SystemRoot%` itself was left out because `py.exe` lives there. `env.no_toolchain_on_path` passed.
- `SSH_AUTH_SOCK` was set to a pipe name that does not exist.
- No window was created:
  - console and TUI rows run on a pseudoconsole (`CreatePseudoConsole`);
  - all other rows run with no console.
- Only processes this script started were stopped, using handles held since start.
- After the runs, no process from the scratch directory was left running.

**Harness controls** (host rows, all pass in all three runs):

| Row | What it shows |
|---|---|
| `harness.screen_model_unit` | The VT screen model is correct (cursor addressing, pending wrap, wide characters, erase, alternate buffer). It is needed because conhost repaints only the cells that changed. |
| `harness.ctrlc_control_direct` | The Ctrl-C sender reaches a plain child exactly once. |
| `run.argv_control_direct` (per candidate) | The script's own command-line quoting delivers every value exactly. |
| `harness.canary_scan` | No canary value appeared in any captured output. |

### Main findings

| Item | go | rust |
|---|---|---|
| `version --json` | pass (go1.27.1 windows/amd64, bubbletea v2.0.10) | pass (rustc 1.99.0, ratatui 0.30.2) |
| `profile show`, homelab under `dir with space ü 東京 🐉\prøfile homelab.toml` | pass, exact data | pass, exact data |
| invalid fixtures: exit 2 `SCHEMA_INVALID`, key path, no canary or offending value (6 fixtures) | pass | pass |
| missing file, directory, `NUL` device, >1 MiB | pass (exit 2, `USAGE_ERROR`/`INPUT_TOO_LARGE`, < 2 s) | pass |
| **named pipe as `profile show --file`** (K14 FIFO analog) | pass: exit 2 `USAGE_ERROR` in 56 ms | **FAIL: no exit within 10 s; the script killed it**. The stall pipe logged 1 connection, so it opened the pipe; reading from it is an inference. |
| **named pipe as `tui --file`** (K14 FIFO analog) | pass: exit 2 in 28 ms | **FAIL: no exit within 10 s; the script killed it** (the stall pipe logged 1 connection) |
| `agent list` on the fixture agent (ASCII pipe name, and the `heimdall g03 ü-…` pipe name) | pass: 2 identities equal to the fixture keys; the agent saw only type-11 requests | pass, same |
| client identity as seen by the agent (`ImpersonateNamedPipeClient` + `OpenThreadToken`), non-gating | **Anonymous: error 1347** when the server impersonates the client. *Corrected by the independent review (x1-review)*: Win32-OpenSSH's ssh-agent identifies clients by process token (`GetNamedPipeClientProcessId` + `OpenProcessToken`), not by impersonation, and the reviewer's server-side probe identified the Go client that way. The finding that stands is narrower: only servers that rely on `ImpersonateNamedPipeClient` cannot identify the Go client (go-winio `DialPipeContext` default, inference). | Identification: same user SID |
| missing pipe | exit 5 `AGENT_UNAVAILABLE` (31 ms) | exit 5 `AGENT_UNAVAILABLE` (19 ms) |
| **regular file given as `--socket`** (X1 task criterion: not modified) | pass: exit 5 `AGENT_UNAVAILABLE` (stderr "connect failed"), file unchanged. The Go source requires a `\\.\pipe\` prefix before dialing; that is why it refuses, per the code, not observed directly. | **FAIL: the first 5 bytes of the file became `00 00 00 01 0b` (the request frame) and its mtime changed**; exit 5 `AGENT_PROTOCOL_ERROR`. The Rust source opens `--socket` read/write with `OpenOptions` and writes the frame; that is the cause, per the code. |
| pipe that never answers, `--timeout-ms 1000` | exit 5 after 1023–1055 ms | exit 5 after 1022–1026 ms |
| `run` argv: 17 `quoting-cases.json` values plus 8 Windows edge cases, compared code unit by code unit | pass | pass |
| `run` argv with a lone UTF-16 surrogate (non-gating) | pass (passed through) | pass |
| `run` exit codes 0–255 | pass | pass |
| `run` exit codes 256, 1000, 65536, −1, 0xC000013A (non-gating) | pass: same uint32; meta `exit_code` 3221225786 | pass: same uint32; meta `exit_code` −1073741510 (i32) |
| launch failure: not found / `.txt` | not found: 127, stderr message, meta `CHILD_LAUNCH_FAILED`, `state:failed`, `launched:false`, `exit_code:null`; `.txt`: 127 | same |
| binary stdout (NUL, CR/LF, 0x1A, ESC, invalid UTF-8) / 70,000-byte stdin | pass | pass |
| environment and working directory (`cwd é x1`) inherited | pass | pass |
| `.cmd` target with argument `a&echo INJECTED_X1` (non-gating) | **path with a space: the second command ran** (cmd split the path; the script itself did not run). Path without a space: no injection. cmd's AutoRun ran in both cases: stderr had a "not recognized" line from the owner's AutoRun entry, which is configured on this host. That is inference from the stderr line counts; the content is not stored. | no injection in either case; no AutoRun output (stderr empty) |
| resolution: name only on PATH | PATH copy runs | PATH copy runs |
| resolution: same name in heimdall-proto's directory and on PATH | PATH copy | **application-directory copy** |
| resolution: same name in the current directory and on PATH | refused, 127: "resolved to the current directory via PATH" (Go ErrDot) | PATH copy |
| resolution: name only in the current directory | 127 (refused) | 127 (not found) |
| resolution: `hmx1cmd` with only `hmx1cmd.cmd` on PATH (PATHEXT) | runs it through cmd.exe | 127 (std appends `.exe` only) |
| resolution: `hostname` with an earlier PATH entry holding `hostname.exe` | the earlier PATH copy | **System32's `hostname.exe`** (std searches System32 before PATH) |
| `run` + console Ctrl-C: `GenerateConsoleCtrlEvent` and typed ^C | pass: the child saw 1 interrupt, the launcher was alive 600 ms later and exited 42 when the child did | pass, same |
| `run` + CTRL_BREAK (non-gating) | pass, same | pass, same |
| `agent list` + console Ctrl-C while waiting | pass: 130, `CANCELLED`, 1–2 ms after the event | pass: 130, `CANCELLED`, 2–18 ms |
| TUI on an 80x24 pseudoconsole: rows, `> ` marker, n/total, j/k/Down, filter `東京` (1/3, K9), Esc, NAS, Enter keeps the filter, select → `SELECTED nas` | pass (first frame 44 ms) | pass (first frame 32 ms) |
| TUI quit / ^C key / ^C in filter mode (terminal restored) | pass | pass |
| TUI resize 40x12 (alias only) → 20x5 → 80x24 | pass (narrow layout 11–27 ms) | pass (14–29 ms) |
| TUI `NO_COLOR` / large-100 (100/100, 0/100) / no TTY → exit 2 | pass | pass |
| TUI + CTRL_C_EVENT from another process (non-gating; tests/g02 gates only the key) | exit **1**, terminal restored | exit **0xC000013A** (killed by the default handler); **alternate screen left active** |

### All rows (run `final-ps51-a`; the other two runs give the same verdicts)

| Row | gating | go | rust |
|---|---|---|---|
| `integrity.sha256_matches_manifest` | yes | pass | pass |
| `version.json` | yes | pass | pass |
| `version.plain_exit` | yes | pass | pass |
| `profile.homelab_unicode_space_path` | yes | pass | pass |
| `profile.homelab_fixture` | yes | pass | pass |
| `profile.homelab_spaced_fixture` | yes | pass | pass |
| `profile.large_100` | yes | pass | pass |
| `profile.plain_exit` | yes | pass | pass |
| `profile.invalid-forbidden-key` | yes | pass | pass |
| `profile.invalid_plain_exit` | yes | pass | pass |
| `profile.invalid-unknown-dest-key` | yes | pass | pass |
| `profile.invalid-malformed` | yes | pass | pass |
| `profile.invalid-schema-version` | yes | pass | pass |
| `profile.invalid-duplicate-alias` | yes | pass | pass |
| `profile.invalid-port` | yes | pass | pass |
| `profile.missing_file` | yes | pass | pass |
| `profile.directory` | yes | pass | pass |
| `profile.nul_device` | yes | pass | pass |
| `profile.named_pipe_as_file` | yes | pass | fail |
| `profile.oversize` | yes | pass | pass |
| `usage.unknown_subcommand_json` | yes | pass | pass |
| `usage.unknown_subcommand_plain` | yes | pass | pass |
| `usage.unknown_flag_json` | yes | pass | pass |
| `usage.profile_missing_file_arg` | yes | pass | pass |
| `usage.agent_missing_socket_arg` | yes | pass | pass |
| `agent.list_fixture_agent` | yes | pass | pass |
| `agent.client_identifiable_by_server` | no | fail | pass |
| `agent.list_unicode_space_pipe` | yes | pass | pass |
| `agent.missing_pipe` | yes | pass | pass |
| `agent.regular_file_not_modified` | yes | pass | fail |
| `agent.regular_file_result` | no | pass | pass |
| `agent.timeout_no_reply` | yes | pass | pass |
| `run.argv_control_direct` | yes | pass | pass |
| `run.argv_quoting_cases` | yes | pass | pass |
| `run.argv_lone_surrogate` | no | pass | pass |
| `run.exit_code.0` | yes | pass | pass |
| `run.exit_code.1` | yes | pass | pass |
| `run.exit_code.2` | yes | pass | pass |
| `run.exit_code.7` | yes | pass | pass |
| `run.exit_code.42` | yes | pass | pass |
| `run.exit_code.127` | yes | pass | pass |
| `run.exit_code.128` | yes | pass | pass |
| `run.exit_code.255` | yes | pass | pass |
| `run.exit_code.256` | no | pass | pass |
| `run.exit_code.1000` | no | pass | pass |
| `run.exit_code.65536` | no | pass | pass |
| `run.exit_code.-1` | no | pass | pass |
| `run.exit_code.-1073741510` | no | pass | pass |
| `run.launch_failure_not_found` | yes | pass | pass |
| `run.launch_failure_not_executable` | yes | pass | pass |
| `run.usage_missing_separator` | yes | pass | pass |
| `run.usage_empty_argv` | yes | pass | pass |
| `run.stdout_binary_passthrough` | yes | pass | pass |
| `run.stdin_binary_passthrough` | yes | pass | pass |
| `run.env_inherited` | yes | pass | pass |
| `run.cwd_inherited` | yes | pass | pass |
| `run.cmd_metachar_argument` | no | fail | pass |
| `run.cmd_metachar_argument_nospace_path` | no | pass | pass |
| `resolution.path_only` | yes | pass | pass |
| `resolution.app_dir_vs_path` | no | info | info |
| `resolution.cwd_vs_path` | no | info | info |
| `resolution.cwd_only` | no | info | info |
| `resolution.pathext_cmd` | no | info | info |
| `resolution.system32_vs_earlier_path` | no | info | info |
| `ctrlc.run_event` | yes | pass | pass |
| `ctrlc.run_keystroke` | yes | pass | pass |
| `ctrlc.run_break_event` | no | pass | pass |
| `ctrlc.agent_list_event` | yes | pass | pass |
| `ctrlc.agent_list_keystroke` | yes | pass | pass |
| `tui.no_tty_usage_error` | yes | pass | pass |
| `tui.navigate_filter_select` | yes | pass | pass |
| `tui.named_pipe_as_file` | yes | pass | fail |
| `tui.nul_device_as_file` | yes | pass | pass |
| `tui.quit` | yes | pass | pass |
| `tui.ctrl_c_key` | yes | pass | pass |
| `tui.ctrl_c_key_in_filter_mode` | yes | pass | pass |
| `tui.ctrl_c_event` | no | fail | fail |
| `tui.resize` | yes | pass | pass |
| `tui.resize_latency` | no | pass | pass |
| `tui.no_color` | yes | pass | pass |
| `tui.large_100` | yes | pass | pass |

Host rows: `env.facts` info, and the following all pass: `env.no_toolchain_on_path`, `harness.screen_model_unit`, `harness.ctrlc_control_direct`, `harness.canary_scan`.

## 3. X4 Windows spike

See `x4-windows-run/RESULTS.md`. The spike ships no binaries. I rebuilt both with its `build.sh` into scratch, and the SHA-256s are byte-identical to the spike's recorded values.

The spike's runner always creates and deletes keys in the user's key store and TPM, and uses DPAPI. I therefore ran only its named-pipe checks, through `run-x4-pipe-subset.ps1`, a mechanical derivative of the spike runner.

| Checks | Go | Rust |
|---|---|---|
| Named pipe: accept same user at Identification level, refuse foreign SID, refuse Anonymous, impersonation control, first-instance exclusivity | pass | pass |
| DPAPI, CNG, TPM | blocked: needs owner authorization (or a disposable account or host) | blocked: same |
| Other-user DACL, remote client | blocked: needs a second account or machine | blocked: same |

## Decisions and escalations (not decided here)

1. **K14 scope on Windows.** Does K14 ("a FIFO, socket, device or directory") cover a Windows named pipe given as `--file`? I gated it as the FIFO analog, and Rust blocks on it in both `profile show` and `tui`. This is a contract-authority question.
2. **Regular file as `--socket`.** The "must not be modified" criterion came from the X1 task. Contract §1 forbids writes only outside paths named on the command line, so Rust's overwrite is not a literal §1 violation. It is still a user-data loss path.
3. **X4 DPAPI, CNG and TPM on the owner's PC.** These need an owner decision: either use the owner's key store, DPAPI master key and TPM, or provide a disposable Windows account or host.
4. **Records that ran everywhere except one platform.** The owner question is still open; it does not apply to these records.

## Limitations

- **One host, one Windows build, non-elevated.**
  - There was no second Windows account, so other-user DACL checks are blocked.
  - There was no SMB peer.
  - The owner's real Win32-OpenSSH agent was never contacted, so interop with it is unknown.
  - Only Windows 11 x64 was tested, not ARM64.
- **Consoles.** Only pseudoconsoles were tested: not a classic conhost window, Windows Terminal, or legacy console. CTRL_CLOSE, LOGOFF and SHUTDOWN events were not tested.
- **Untested paths and protections.**
  - long paths (> MAX_PATH);
  - UNC working directories;
  - other code pages;
  - SmartScreen and Mark-of-the-Web (the files came through WSL and carry no Zone.Identifier);
  - Defender.
- **The Windows script is new in this task.** Its controls pass, but it has not had an independent review. Several harness bugs were found and fixed while it was developed (the run history is in the task log, not here). Only the three final runs are evidence.
- **linux-x64 is not a K13 verdict platform.** It ran natively, not in the pinned container. The other WSL workloads on the host were not controlled.

## Reproduce

| Part | How |
|---|---|
| linux-x64 | Copy `git archive 772a6b1 tests/g02 tests/fixtures/g02 tests/fixtures/fake-agent schemas/g02 tests/evidence/record.schema.json` and the two `dist/linux-x64` artifacts into a scratch directory with layout `repo/`, `art/<c>/`. Create the venv. Run `linux-x64/run-linux.sh`, then `linux-x64/notoolchain.sh`. Input hashes: `linux-x64/inputs.sha256`. |
| windows-x64 | Stage the layout described in the script header (hashes: `windows/staged-root.sha256`). From WSL run `windows/winrun.sh ps51|ps7 <out>`, or run `powershell.exe -ExecutionPolicy Bypass -File Invoke-G02WindowsX1.ps1 -Root <dir> -OutDir <dir>`. |

## Cleanup

The WSL scratch `~/hm-m00/M00-T05-x1-g02-native` and the Windows scratch `%LOCALAPPDATA%\hm-m00\M00-T05-x1-g02-native` were removed after the evidence was copied back.

- Both parent `hm-m00` directories hold another entry, so they were kept.
- No process from the scratch directory was running.
- The Mac scratch under `/tmp` was removed at the end of the task.


## Corrections from the independent review (2026-10-06, `../x1-review/`)

- The client-identity row is corrected as shown above. It is not an input against Go for G03 or ADR-0002,
  except for servers that use pipe impersonation.
- `pipe_connects` counts are racy, because they are read before the stall pipe appends its marker. Go
  does open a pipe given as `--file` (os.Stat), but it never blocks, so no verdict changes.
- The `harness.canary_scan` criterion covers only text passed through `Protect-X1` (rows and saved
  artifacts), not every captured stream.
- Windows result checks do not validate against `schemas/g02/result.schema.json`, and K18 is checked only
  for the invalid-port case. Both gaps apply equally to both candidates.
- Rust's `fail` rests on rows the orchestrator ruled on in `docs/g02/slice-contract.md` §9.6.

## §9.6 baseline (2026-10-06, task `M00-T05-x1b-script`)

The script now gates `docs/g02/slice-contract.md` §9.6, identically for both candidates, and applies the
cheap review fixes. It was re-run on the same host against the same frozen windows-x64 artifacts
(SHA-256 checked against `dist/manifest.json`; nothing rebuilt). Runs, staging hashes and the wrapper are in
`windows-96/`; the commands and exit codes are in `windows-96/commands.txt`. The previous records are kept
in `prev-records/`.

| Run | Shell | Exit | Rows |
|---|---|---|---|
| `s96-ps51-a` | Windows PowerShell 5.1.26100.9549 | 1 | 183 |
| `s96-ps7-a` | PowerShell 7.6.6 | 1 | 183 |
| `s96-ps51-b` | Windows PowerShell 5.1.26100.9549 | 1 | 183 |

Verdicts are identical across the three runs for all 183 rows. Host rows (`env.no_toolchain_on_path`,
`harness.screen_model_unit`, `harness.ctrlc_control_direct`, `harness.canary_scan`) pass in all three.

| | go | rust |
|---|---|---|
| Gating rows | **67/71**, verdict **fail** | **68/71**, verdict **fail** |
| Failing gating rows | `run.batch_target.cmd_space_path`, `run.batch_target.bat_space_path`, `run.batch_target.cmd_nospace_path`, `run.batch_target.bat_nospace_path` | `profile.named_pipe_as_file`, `tui.named_pipe_as_file`, `agent.regular_file_not_modified` |
| Previous record (pre-§9.6 script) | 63/63, pass | 60/63, fail (same three rows) |

### What changed in the script

| §9.6 / review item | Rows |
|---|---|
| K14: a named pipe or any non-regular path as `--file` → exit 2 within 2 s (`profile show` with `USAGE_ERROR`; `tui` with the alternate screen not left active, as in tests/g02) | `profile.named_pipe_as_file`, `profile.directory`, `profile.nul_device`, `tui.named_pipe_as_file`, `tui.nul_device_as_file`, new `tui.directory_as_file` |
| `agent list --socket` on a regular file, a directory, a non-existent path: refused without modification (file hash and mtime; directory mtime plus every entry's name, mtime, size, hash; non-existent path not created and its parent unchanged), exit 5 `AGENT_UNAVAILABLE` or exit 2 `USAGE_ERROR` | `agent.regular_file_not_modified` (now also requires the refusal result), new `agent.directory_as_socket_refused`, new `agent.nonexistent_path_as_socket_refused` |
| `.bat`/`.cmd` targets: no argument byte run as a command, path with and without a space; refusal (127 + stderr, child never ran) or exact delivery both pass | new `run.batch_control` (harness control) and `run.batch_target.{cmd,bat}_{space,nospace}_path`, 16 arguments each: plain, a space, `&` (two forms), `|`, `>`, `<`, `<`+`&`, `^`, `^^&`, `%VAR%` (two forms), `"` (four forms) |
| Review: schema validation | every parsed JSON result and every `--meta-file` document must validate against `schemas/g02/result.schema.json` (PowerShell port of `tests/g02/minischema.py`, fails closed on unknown keywords) |
| Review: K18 for all invalid fixtures | each fixture's offending value, read from the fixture at run time, must be absent from stdout and stderr of the `--json` and the plain run (schema_version fixture: other-key value gated in the JSON result, recorded on stderr, as tests/g02 Q11) |
| Review: canary scan | `Invoke-X1` now scans every captured stream; the criterion lists exactly what is and is not scanned |
| Review: racy `pipe_connects` | `StallPipe.ps1` takes a stop file; the count is read after the helper has exited (`pipe_connects_final: true` in every run) |

Unchanged rows keep their ids and criteria. The X1 `.cmd` rows `run.cmd_metachar_argument(_nospace_path)`
stay non-gating.

### How the batch rows decide

- **Child.** The batch file forwards `%*` to `argvdump.exe` next to it.
- **Exact delivery.** The forwarded argument decodes to the original UTF-16 code units under
  CommandLineToArgvW **or** under the UCRT (msvcrt 2008+) rules. cmd.exe has no single unescaping rule for
  embedded quotes, so both standard decodings are accepted. This is an interpretation of "the child received
  the exact bytes"; it applies to both candidates.
- **Injection.** Every injected command is `break>hmx1injN.txt`. Any file appearing in the per-run working
  directory, or next to the batch file, counts as an injection.
- **Exit code.** Recorded, not gated: §9.6 does not ask for it, and `run.exit_code.*` gate exit codes.
- **Control.** `run.batch_control` passes for both candidates in all runs. It shows that `cmd.exe /d /c`
  delivers a quoted argument and a literal `%HMX1BATVAR%` exactly through the forwarding batch, and that an
  unquoted `&break>file` is detected.

### Findings

| Item | go | rust |
|---|---|---|
| Named pipe as `profile show --file` / `tui --file` | pass: exit 2 in 21–25 ms over the three runs; opened the pipe once (final count) | **FAIL**: no exit within 10 s, killed; opened the pipe once (final count) |
| Directory as `tui --file` (new) | pass, exit 2 in 23–27 ms | pass, exit 2 in 21–24 ms |
| Regular file as `--socket` | pass: exit 5 `AGENT_UNAVAILABLE`, file unchanged | **FAIL**: first 5 bytes became `00 00 00 01 0b`, mtime changed; exit 5 `AGENT_PROTOCOL_ERROR` (also not an allowed refusal code) |
| Directory / non-existent path as `--socket` (new) | pass: exit 5 `AGENT_UNAVAILABLE`, nothing modified or created | pass: same |
| `.bat`/`.cmd`, path without a space | **FAIL**: 6/16 exact; 8 inject (`&`, `|`, `>`, `<`+`&`, `^^&`, both `%VAR%` forms, `a" & …`); `a<file` and `a^b` arrive changed | pass: 16/16 exact |
| `.bat`/`.cmd`, path with a space | **FAIL**: 1/16 exact (`plain`); 8 inject; 5 never start the batch file (cmd.exe splits the path; exit 1, not a 127 refusal); 2 arrive changed | pass: 16/16 exact |
| Exit code of batch runs (recorded) | 1 in every case. `cmd.exe /c` without `/d` also exits 1 on this host (AutoRun configured, 94 stderr bytes), so this is attributed to AutoRun: CreateProcess starts `.bat`/`.cmd` without `/d` | 0 in every case (Rust starts cmd.exe with `/d`) |
| `a" & break>…` | injects (both path forms) | exact under UCRT only: Rust doubles the quote (`"a"" & …"`), and CommandLineToArgvW splits it at the space |
| JSON results vs `result.schema.json` | all valid | all valid. The only `schema_valid: false` is `profile.named_pipe_as_file`, which produced no output before it was killed |
| K18, all six invalid fixtures | no offending value on stdout or stderr | same |

The Go batch mechanism (CreateProcess on a `.bat`/`.cmd` runs `cmd.exe /c` over Go's
CommandLineToArgvW-style quoting) is an inference from the outcomes and the Go source. It was not
instrumented.

### Limitations of this baseline

- **No independent review yet.** The §9.6 script changes have not been independently reviewed.
- **Two development runs** (`dev1`, `dev2`, not kept) came before the evidence runs. They exposed two harness
  defects, both fixed before the evidence runs:
  - a subdirectory's mtime read through its parent's enumeration changes by itself on NTFS. The script now
    reads it per path, against a baseline that is stable for 200 ms;
  - the batch rows required exit 0 for an exact delivery. That requirement was dropped (see above).
- **Batch coverage.** Batch arguments with `!`, newlines, NUL or non-ASCII were not tested. Delayed
  expansion was not inspected. Bare-name PATHEXT resolution remains the info row `resolution.pathext_cmd`.
- **K14 pipe server.** The named-pipe server accepts and never answers. A server that sends a valid profile
  and closes was not tested.
- **PowerShell 7 dates.** PowerShell 7's ConvertFrom-Json turns ISO-8601 strings into DateTime, and the
  schema port treats DateTime as a string. No G02 result field holds such a string.
- **Earlier limitations still apply:** one host, pseudoconsoles only, no second account, no SMB peer, no
  real Win32-OpenSSH agent.

**Cleanup.** Both task scratch directories were removed. No heimdall-proto or argvdump process, and no
process with the task scratch in its command line, was left running. The parent `hm-m00` directories were
left as found.
