# G03 native Windows probe harness

Executable probes for plan.md §3 G03 (spec §8.4, §10.3, §10.4, §13.2; acceptance A14 and Windows inputs
to A12/A13). Design, sources, question matrix, and pass/fail criteria:
`docs/research/g03-windows-wsl.md`. This is harness code in PowerShell; it does not depend on the
(unselected) production language.

**Nothing here has run on Windows yet.** On non-Windows hosts the orchestrator records every probe as
`blocked`. Parse checks, PSScriptAnalyzer, and a protocol self-test ran on macOS (research doc §7).

## Files

| File | Role |
|---|---|
| `Invoke-G03WindowsProbes.ps1` | Orchestrator: probes `env`, `sshauthsock`, `identityagent`, `git`, `otheruser`, `stalepipe`, `processio`, `quoting`, `service`, `onepassword`, `agentconstraints`, `wslotheruser`, `keyperms`; `-ServeAgentForWsl` mode for the WSL harness (serves the instrumented agent plus a decoy pipe). |
| `G03Common.psm1` | Shared helpers: exact Windows argv quoting, native capture with explicit environment, owned-process tracking, evidence records, canary scan. |
| `InstrumentedAgent.ps1` | Fixture SSH agent on `\\.\pipe\<name>` with in-memory ECDSA P-256 keys. The pipe is created with `CreateNamedPipeW` (P/Invoke) so every N2 property is explicit: protected SDDL DACL (owner-only; owner + Authenticated Users connect-only `0x12019b`; or, as a test control, AU with `FILE_CREATE_PIPE_INSTANCE`), `PIPE_REJECT_REMOTE_CLIENTS`, `-MaxInstances`, and `FILE_FLAG_FIRST_PIPE_INSTANCE` unless `-NoFirstInstanceFlag`. JSONL log of every connection (client PID, image, path, SID) and request. Refuses all mutations. |
| `PipeStdioRelay.ps1` | stdio ↔ named-pipe relay used by the WSL Mode B probe (stand-in for npiperelay). |
| `Test-G03HarnessSelf.ps1` | Self-test of the agent protocol/signatures against local OpenSSH tools (any OS with pwsh 7). Not G03 evidence. |
| `fixtures/quoting-cases.json` | Argument and path fixtures shared with the WSL harness (spaces, Unicode, quotes, backslashes, cmd/POSIX metacharacters, empty, leading dash). |

## Safety model (defaults)

- Uses only disposable keys: probe keys are generated in memory inside `InstrumentedAgent.ps1` and never
  written; `agentconstraints` (gated) generates one disposable file key in scratch and deletes it.
- Never contacts the owner's agent: every child gets an explicit `SSH_AUTH_SOCK` (a fixture pipe or a
  sentinel pipe that does not exist). On Windows an **unset** `SSH_AUTH_SOCK` means
  `\\.\pipe\openssh-ssh-agent` (Win32-OpenSSH `wmain_common.c`), so "unset" is never used. Residual:
  the dead-pipe `ssh-add -l` rows (P-W02 sentinel, P-W06 after-kill) would reach that pipe only if the
  client fell back to it, which the pinned v10.0.0.0 source does not do; when the pipe is present their
  stdout is not saved (exit code and line count only). "No fallback" is judged only when something
  listens on the default name: a server that is already there, or a fixture decoy served there on a
  declared disposable host while the name is free (service stopped, no 1Password); otherwise the record
  says fallback was not judged.
- Never runs an ssh client that could read the owner's SSH configuration or keys in default mode:
  every `ssh.exe` child gets `-F <fixture config>` (which also suppresses
  `%PROGRAMDATA%\ssh\ssh_config`), `IdentityFile=none`, fixture `UserKnownHostsFile`,
  `GlobalKnownHostsFile=none`, `StrictHostKeyChecking=yes`. `HOME` points into scratch, but that only
  protects MSYS/Git-bundled tools: Win32-OpenSSH resolves its home from the user profile, not `HOME`.
  Git therefore always runs with an explicit `core.sshCommand`/`GIT_SSH_COMMAND` that carries `-F` and
  the fixture options; Git's own default ssh is only *resolved* passively (which binary, bundled vs
  external), never executed, unless `-IAmOnADisposableHost` is given, `%USERPROFILE%\.ssh` is absent or
  **empty** (any entry blocks the row; only the entry count is recorded) and
  `%PROGRAMDATA%\ssh\ssh_config` does not exist (existence only). Git also runs with
  `GIT_CONFIG_NOSYSTEM=1` and an empty `GIT_CONFIG_GLOBAL`.
- Reads one piece of owner state: P-W01 asks Git in which scopes `core.sshCommand` is set
  (`git config --show-scope --name-only --get-regexp`), so Git reads the owner's Git configuration, but
  only scope names (`system`/`global`/…) are recorded, never a value or an origin path.
- Other-user probes (`otheruser`, `stalepipe` pre-squat, `wslotheruser`) stage their script as a file in
  a fresh per-run `%PUBLIC%\heimdall-g03-<run>` directory (a pre-existing path is refused) whose protected
  DACL names exactly this account (full control) and the other test account (modify); the script file
  grants the other account read/execute only; the DACL and emptiness are verified before use and the
  directory is removed at the end. The command line is a short `-File` invocation (length recorded and
  checked against the 1024-character `CreateProcessWithLogonW` limit). The staged preamble resets
  `TEMP`/`TMP`, `PSModulePath` and `SSH_AUTH_SOCK`, because `Start-Process -Credential` hands the child
  the caller's environment block (PowerShell `Process.cs`, G03-S22).
- The `keyperms` probe creates one disposable passphrase-less key file in scratch, changes only that
  file's ACL, never loads it into an agent, and deletes it.
- Never changes services, Git/SSH global configuration, or the system agent store unless a gate is set.
- Stops only processes it started, through the Process object it got at start (which holds the process
  handle), and only after re-checking that the PID's start time still matches; a process whose start time
  cannot be read or compared is reported `identity-unverified-not-stopped`. Other-user processes are
  waited for through a done-marker file and are killed only through a handle held since start; a
  non-admin caller may hold no handle (PowerShell source, G03-S22), and then no kill is attempted and the
  record says so.
- Fixture agents re-arm their single pipe instance with `DisconnectNamedPipe` after each client, so a
  fixture's name never has zero instances while it runs (no recreate race with another process).
- Runs non-elevated (the `service` probe records elevation; an elevated run cannot demonstrate R-DI-02).
- No network listeners. The only network client traffic goes to the disposable fixture you name.

Gates (all default off):

| Switch | Allows | Also requires |
|---|---|---|
| `-AllowProviderContact` | contacting `\\.\pipe\openssh-ssh-agent` (system agent or 1Password) | `-OwnerAuthorizationNote "<reference to the owner's explicit authorization>"`; use a disposable 1Password account/key |
| `-AllowSystemAgentMutation` | adding/removing a disposable key in the per-user Windows agent store; starting/stopping the agent service in `onepassword` | `-IAmOnADisposableHost` and `-OwnerAuthorizationNote` |
| `-IAmOnADisposableHost` (alone) | the `git` probe's live `default_no_override` row (Git's default ssh, no `-F`); a fixture decoy on `\\.\pipe\openssh-ssh-agent` in `sshauthsock`/`stalepipe` to detect client fallback | for the Git row: `%USERPROFILE%\.ssh` absent or empty and no `%PROGRAMDATA%\ssh\ssh_config` (existence/count checks only; otherwise the row is skipped and recorded as not run). For the decoy: the name is free, the `ssh-agent` service is not running and no 1Password process exists |

## Preconditions

Native Windows 11 x86-64 (VM acceptable) with the in-box OpenSSH client; Windows PowerShell 5.1 and/or
PowerShell 7.4+; for the probes that need them: a disposable SSH fixture reachable from Windows (for
example `tests/fixtures/ssh` from M00-T03) plus its `known_hosts`; a way to authorize the run's ephemeral
probe key on that fixture (`-AuthorizeKeyScript <script.ps1>` called as
`& $script -PublicKeyPath <pub>`, or `-PauseForKeyInstall`); a disposable Git repository URL on the
fixture; a second, disposable, non-administrator local account (`-OtherUserCredential`) with the
Secondary Logon service available; Git for Windows; WSL with a disposable distribution for
`wslotheruser`; 1Password with a disposable account for `onepassword`.

## Running

```powershell
# Local-only probes (no fixture server needed):
pwsh -NoProfile -File tests\native\windows\Invoke-G03WindowsProbes.ps1 -Probes env,sshauthsock,stalepipe,service

# Everything that default mode allows:
pwsh -NoProfile -File tests\native\windows\Invoke-G03WindowsProbes.ps1 `
  -SshHost 127.0.0.1 -SshPort <port> -SshUser enroll -KnownHostsFile C:\fixture\known_hosts `
  -AuthorizeKeyScript C:\fixture\authorize.ps1 -GitRemoteUrl ssh://enroll@127.0.0.1:<port>/srv/git/probe.git `
  -OtherUserCredential (Get-Credential heimdall-probe-other) -WslDistro g03-target

# Same probes under Windows PowerShell 5.1 (records the 5.1 behaviour separately):
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\native\windows\Invoke-G03WindowsProbes.ps1 ...

# Serve an instrumented agent for tests/native/wsl (keep running while the WSL probes execute):
pwsh -NoProfile -File tests\native\windows\Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl -ServeSeconds 3600
```

Output goes to `tests/evidence/artifacts/g03/runs/<run-id>/` (`records/`, `artifacts/<case>/` redacted
transcripts, `summary.json`). Promote a record by copying it over the matching
`tests/evidence/g03-*.json` (replacing the `blocked` placeholder) in the integrating commit, together with
its artifacts.

Status convention (gate probes, `tests/evidence/README.md`, orchestrator decision 2026-10-03): `status`
describes the evidence and `observed_result.verdict` the criterion. Any criterion unobservable, any
failed control, an environment problem or a harness error → `in_progress` with `verdict:
"inconclusive"`; otherwise any criterion false → `verified` with `verdict: "fail"`; all true →
`verified` with `verdict: "pass"`; missing precondition → `blocked` with `blocked_on`.
`failed_criteria`/`unobserved_criteria` list the keys. Harness self-test records carry no requirement IDs.

## Manual steps the scripts cannot automate

- Ctrl-C to `ssh.exe` in an interactive console and the resulting exit code; console resize to a remote PTY.
- Whether a 1Password approval prompt appeared, and which application it named (`onepassword`, and the
  WSL relay probe).
- Host lock windows are driven from the WSL harness (`--lock-window-minutes`).

## Known limits

Every Windows-only code path is unexecuted: `CreateNamedPipeW` with an SDDL DACL, wrapping the handle in
`NamedPipeServerStream`, client PID/SID capture, the other-user Win32 helper (`CreateFileW`,
`CreateNamedPipeW`, `ConnectNamedPipe`), `Start-Process -Credential` with the file-staged script (whether
Windows PowerShell 5.1 behaves like the pinned PowerShell 7 source, and whether the other account can read
the script and write its result under the staging DACL), the default-name decoy, `DisconnectNamedPipe`
re-arming (exercised only on the .NET Unix-socket path), `sc.exe` parsing, `Get-Acl`/`Set-Acl` on the
disposable key and the staging directory, Git/MSYS behavior. The embedded C# compiled with the PowerShell 7 (Roslyn) compiler
on macOS; compilation by Windows PowerShell 5.1's C# 5 compiler is unverified. Expect harness fixes on
first real run; a harness error is recorded as an `inconclusive` `G03-win-<probe>-harness-error` record
that names no requirement, never as a platform observation.
