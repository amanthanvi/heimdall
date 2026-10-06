# G03 — Native Windows and WSL mechanics: sources, decision matrix, candidate designs, probe plan

**Task:** M00-T04-G03, revised by M00-T04-G03-fix after independent adversarial review (§8) and by
M00-T04-G03-fix2 after the independent re-review (§9) ·
**Gate:** plan.md §3 G03 · **Prepared:** 2026-10-03 (UTC) on the macOS development host · **Requirements:** R-EN-01, R-EN-02, R-EN-03, R-SS-03, R-RT-03, R-DI-02, R-QU-02
(plus R-SS-04, R-RT-01, R-RT-04, R-RT-07, R-SE-03, R-CR-01, R-CR-07, R-CR-08, R-AU-05 where a probe
touches them) · **Acceptance inputs:** A12 (WSL Mode A), A13 (WSL Mode B), A14 (native Windows).

## 0. Status in one table

No Windows host, WSL distribution, or Windows-hosted provider is available to this environment. **Every
native G03 probe is `blocked`.** Nothing below claims Windows or WSL behavior was observed. What exists:
pinned primary sources, a labeled question matrix, candidate designs with an honest security analysis,
executable probe harnesses, and harness self-tests that ran on macOS (they test the harness, not the
platform).

| Probe group | Records | Status | Blocked on (short) |
|---|---|---|---|
| Native Windows endpoint, ACL, Git, quoting, service, 1Password, key-file permissions (P-W01..P-W12) | `tests/evidence/g03-win-*.json` (12) | blocked | native Windows 11 x86-64 host (+ fixture / second account / disposable 1Password as listed per record) |
| WSL Mode A (P-A01..P-A06) + inventory | `tests/evidence/g03-wsl-env-inventory.json`, `g03-wsl-a-*.json` (7) | blocked | WSL2 distribution on a native Windows 11 x86-64 host with interop |
| WSL Mode B (P-B01..P-B11) | `tests/evidence/g03-wsl-b-*.json` (11) | blocked | WSL2 distributions (two for multi-distro/restart/idle) on native Windows; second Windows account for P-B11 |
| Harness self-tests (not G03 evidence) | `tests/evidence/artifacts/g03/harness-selftest/**/records/*.json` | see §7 | — |

Label legend used in every table: **[D]** documented by the vendor/official documentation cited;
**[S]** read from pinned source code at a tag (describes that build's code, not observed behavior; the
Windows in-box build may differ from any GitHub tag); **[C]** community report in an issue tracker, not
vendor-confirmed; **[I]** inference by this author from the cited items; **[U]** unknown;
**[O]** observed by a command actually run here (harness self-tests only).

## 1. Pinned primary sources

Full URLs, commits, and the sha256 of every snapshot actually fetched are in
`tests/evidence/artifacts/g03/sources/source-pins.json`; short verbatim excerpts with file:line are in
`tests/evidence/artifacts/g03/sources/excerpts.txt`. Snapshots were fetched 2026-10-03 between 00:20Z and
00:48Z. Mutable pages (1Password, wikis) are pinned by retrieval time and content hash only.

| ID | Source | Pin | Claims it supports here |
|---|---|---|---|
| G03-S01 | Win32-OpenSSH releases — <https://github.com/PowerShell/Win32-OpenSSH/releases> | release list retrieved 2026-10-03; latest `10.0.0.0p2-Preview` (2025-10-27), preceded by `v9.8.3.0p2-Preview`, `v9.5.0.0p1-Beta`, `v8.1.0.0p1-Beta` … | GitHub releases are labeled "preview-release (non-production ready)"; 10.0 notes mention RedirectionGuard for ssh-agent, CVE fixes in 9.8.2 (incl. CVE-2025-27731 in ssh-agent). |
| G03-S02 | PowerShell/openssh-portable source — <https://github.com/PowerShell/openssh-portable> | tag `v10.0.0.0`, commit `b8c08ef9da9450a94a9c5ef717d96a7bd83f3332`, tarball sha256 `45f316a5…dae0d` | Default agent pipe; agent socket = `CreateFileW` on the given path; IdentityAgent handling; config tokenizer; agent pipe DACL; per-user key store; constraint handling; `Match exec` via `system()`; no Unix-domain server sockets; installer service DACL; private-key file ACL check (`authfile.c` `sshkey_perm_ok` → `w32-sshfileperm.c` `check_secure_file_permission`). |
| G03-S03 | same repository, older tags | `v9.5.0.0` `59aba65c…`; `v8.1.0.0` `ee11c8e1…` | Default pipe identical in both; v8.1 parses IdentityAgent with `strdelim` (no backslash escapes); v9.5 with `argv_next` (escapes). |
| G03-S04 | OpenSSH 8.7 release notes — <https://www.openssh.com/txt/release-8.7> | sha256 `db6db851…4eb76` | "stricter configuration file parser … more shell-like rules for quotes, space and escape characters". |
| G03-S05 | Win32-OpenSSH issue #1949 — <https://github.com/PowerShell/Win32-OpenSSH/issues/1949> | open; updated 2024-10-10 | [C] `IdentityAgent \\.\pipe\…` stopped working 8.6→8.9 (`unable to connect to pipe …, error: 3`); `//./pipe/…` works; setting `SSH_AUTH_SOCK` works. |
| G03-S06 | Win32-OpenSSH issue #1987 — <https://github.com/PowerShell/Win32-OpenSSH/issues/1987> | open; updated 2022-10-14 | [C] users report Git for Windows' bundled OpenSSH does not use the named pipe. |
| G03-S07 | Win32-OpenSSH wiki — `Various-Considerations`, `About-Win32-OpenSSH-and-Design-Details` | wiki commit `b73e3c3d…` (2025-10-27) | ssh-agent "ignores '-c' and '-t' options of ssh-add. It persistently and permanently stores the user's private key"; agent is a LocalSystem service on a static IPC port (historical design page). |
| G03-S08 | Microsoft Learn OpenSSH docs (source repo MicrosoftDocs/windowsserverdocs) | commit `f4adef53…` | In-box OpenSSH is a Feature on Demand from Windows 10 1809 / Server 2019; in-box FOD recommended, GitHub fork releases "might differ"; ssh-agent "disabled" by default, enabling startup type at an elevated prompt; client config at `%userprofile%\.ssh\config` and `%programdata%\ssh\ssh_config`. (Spec S13.) |
| G03-S09 | Win32 docs: Named Pipe Security and Access Rights (MicrosoftDocs/win32) | commit `e103fa4e…` | A pipe created with a NULL security descriptor grants full control to LocalSystem, administrators, creator owner, and **read access to Everyone and anonymous**. |
| G03-S10 | Win32 API docs: CreateNamedPipe, ImpersonateNamedPipeClient (MicrosoftDocs/sdk-api; one id for both documents at this pin, as with S02/S15; citations name the document) | commit `c12073e4…` | `FILE_FLAG_FIRST_PIPE_INSTANCE` makes creation of a second instance fail with `ERROR_ACCESS_DENIED`; creating an instance needs `FILE_CREATE_PIPE_INSTANCE`; all instances must use the same type, access, instance count and time-out, else `ERROR_ACCESS_DENIED`; `PIPE_REJECT_REMOTE_CLIENTS` rejects remote clients. |
| G03-S11 | .NET docs: File path formats on Windows (dotnet/docs) | commit `641989c3…` | Device paths are identified as "two separators and a question mark or period"; forward slashes are canonicalized to backslashes. |
| G03-S12 | 1Password developer docs — <https://www.1password.dev/ssh/…> (wsl, get-started, agent/advanced, agent/security, agent/authorization, agent/config, agent/compatibility) | retrieved 2026-10-03, per-page sha256 in pins | WSL integration = run Windows `ssh.exe` from WSL; config lives in Windows `%USERPROFILE%/.ssh/config`; per-session WSL authorization; Windows agent requires disabling the OpenSSH Authentication Agent service and takes over `\\.\pipe\openssh-ssh-agent`; "Microsoft OpenSSH listens to a fixed pipe … it will authenticate for all hosts"; Git for Windows needs `core.sshCommand` → `C:/Windows/System32/OpenSSH/ssh.exe`; authorization per application incl. subprocesses / per terminal session / per request; "Approve for all applications … only restricted by file permissions on the agent socket or named pipe"; WSL tip: `npiperelay` + `socat` workaround. (Spec S06, S07, S12.) |
| G03-S13 | Git for Windows source and docs | tag `v2.56.0.windows.1`, commit `53e90d5e…` | `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH` > `ssh` (connect.c `get_ssh_command`). |
| G03-S14 | Git for Windows installer — `installer/install.iss` (git-for-windows/build-extra) | commit `43a5d8a0…` | Installer choices "Use bundled OpenSSH" and "Use external OpenSSH" (uses ssh.exe on PATH; bundled binaries removed). |
| G03-S15 | Microsoft Learn WSL docs (MicrosoftDocs/WSL) | commit `a1473a69…` | Windows tools run from WSL with parameters "passed … unmodified"; env crosses only via `WSLENV` (`/p /l /u /w`; `/w` = "only be included when running Win32 from WSL", filesystems.md:188); `networkingMode` values `none`, `nat`, `bridged`, `mirrored`, `consomme` ("called `virtioproxy` in the past", wsl-config.md:247); `[interop] enabled`, `appendWindowsPath`; `wsl --terminate`, `--shutdown`, `--user`; `\\wsl$` access uses the distribution's default user; `instanceIdleTimeout` 15000 ms, `vmIdleTimeout` 60000 ms; WSL1-era AF_UNIX interop (Build 17093); `wslpath`. |
| G03-S16 | microsoft/WSL technical documentation | commit `a4b297c3…` | **"WSL … is not a security sandbox"; "a distribution is not a security boundary from the Windows host or from other distributions running for the same user"; `[interop] enabled=false` is not a containment boundary**; WSL2 distributions run in separate mount, PID and UTS namespaces; `/mnt/wsl` is shared between all distributions; NAT `localhost` relays bound TCP ports to Windows; interop servers under `/run/WSL`. |
| G03-S17 | microsoft/WSL issue #5961 — <https://github.com/microsoft/WSL/issues/5961> | open, label `feature`, updated 2024-09-29 | [C] Windows/WSL AF_UNIX interop does not work in WSL2. |
| G03-S18 | jstarks/npiperelay | commit `4997d3bf…` (v0.1.0, 2020; MIT) — metadata only, not downloaded | Existing stdio↔named-pipe relay pattern (reference only). |
| G03-S21 | dotnet/runtime `NamedPipeServerStream.Windows.cs`, `NamedPipeServerStream.cs`, `NamedPipeServerStream.Unix.cs` | commit `6f1d9331…` (main, retrieved 2026-10-03 by the fix tasks), sha256 `bca7a69c…` (Windows file; others in pins); snapshots not committed (as for every source here) | .NET adds `FILE_FLAG_FIRST_PIPE_INSTANCE` whenever max instances is 1; the pipe mode carries only the transmission mode, so .NET cannot set `PIPE_REJECT_REMOTE_CLIENTS`; default time-out 0. `Disconnect()` is allowed from the Connected and Broken states and calls `DisconnectNamedPipe` on the same handle (Unix: keeps the listening socket); a new wait is allowed from Disconnected. .NET Framework (Windows PowerShell 5.1) not checked. |
| G03-S22 | PowerShell `Process.cs` (Start-Process) | PowerShell/PowerShell commit `caeff5e8…` (master, retrieved 2026-10-03 by fix2), sha256 `9f49e22b…` | With `-Credential`, `StartWithCreateProcess` calls `CreateProcessWithLogonW` with the whole command line and an explicit environment block taken from the **caller's** environment; afterwards it notes that a non-admin caller may be unable to get the process handle of the other user's process. Windows PowerShell 5.1's source is not public; same behavior there is [I]. |
| G03-S23 | Win32 API docs: CreateProcessWithLogonW (MicrosoftDocs/sdk-api) | commit `c12073e4…` (same pin as S10), sha256 `bd612ef2…` | `lpCommandLine`: "The maximum length of this string is 1024 characters."; a non-NULL `lpEnvironment` replaces the environment built from the target user's profile. |
| G03-S19/S20 | WSL releases; Git for Windows releases | WSL `3.0.1` (2026-09-29); Git `v2.56.0.windows.1` (2026-09-28) | Current versions to pin in the probe preconditions (not tested). |
| spec S01/S02/S30 | OpenSSH manuals | Win32 tree copies of `ssh_config.5`, `ssh.1`, `ssh-agent.1` at G03-S02 | `IdentityAgent` semantics (`none`, `SSH_AUTH_SOCK`, `$VAR`, tokens); `-F` makes ssh ignore the system-wide config; agent socket "accessible only to the current user, but is easily abused by root or another instance of the same user". |

## 2. Endpoint-selection and platform question matrix

"Resolves with" names the probe (§4) that turns the row into an observation.

### 2.1 Native Windows

| # | Question | Current answer | Label | Sources | Resolves with |
|---|---|---|---|---|---|
| Q01 | Which `ssh.exe` does a user get? | In-box FOD client at `%WINDIR%\System32\OpenSSH\` (Win10 1809+/Server 2019+; installed-but-disabled on Server 2025 per table); GitHub MSI/zip releases are separate and "might differ"; Git for Windows ships its own MSYS2 `ssh.exe` unless "Use external OpenSSH" was chosen; bare `ssh` resolves by PATH order. | [D] + [S] | S08, S14 | P-W01 records every candidate's path, banner, file version, sha256, PATH order. |
| Q02 | Which in-box OpenSSH version ships in each Windows build? | Not stated in the Microsoft pages fetched. | [U] | S08 | P-W01 (`ssh -V`, file version). G01 then sets floors. |
| Q03 | Endpoint when `SSH_AUTH_SOCK` is unset | `\\.\pipe\openssh-ssh-agent`: the client tools (`ssh`, `ssh-add`, `ssh-keygen`, `scp`, `sftp` link `wmain_common.c` per their `.vcxproj`) set `SSH_AUTH_SOCK` to that pipe if it is unset (identical in v8.1, v9.5, v10.0). **Consequence: unsetting `SSH_AUTH_SOCK` does not disable the agent on Windows; `IdentityAgent none` does.** 1Password's "fixed pipe" statement is consistent with this default. | [S], [D] | S02, S03, S12 | P-W02 (non-existent sentinel must fail with exit 2, not fall back). |
| Q04 | Does `ssh.exe`/`ssh-add.exe` honor `SSH_AUTH_SOCK` = an arbitrary named pipe? | Source: `ssh_get_authentication_socket` reads the variable; the AF_UNIX connect is emulated as `CreateFileW(path, …)` with `SECURITY_SQOS_PRESENT` + `SECURITY_IDENTIFICATION` with a 1 s retry on `ERROR_PIPE_BUSY`. So any pipe path `CreateFileW` can open should work. Community report agrees. | [S], [C] | S02, S05 | P-W02. |
| Q05 | Does `IdentityAgent <named pipe>` work in `ssh_config` or `-o`? | Source: `IdentityAgent` is tilde/percent/env-expanded and then copied into `SSH_AUTH_SOCK`, i.e. the same path as Q04. 1Password documents Windows as lacking this flexibility ("fixed pipe"), which contradicts the source; the vendor statement may reflect older builds or what they support. | [S] vs [D] conflict; [C] supports source | S02, S12, S05 | P-W03 (10 forms × config/-o × each client). |
| Q06 | How must the pipe path be written? | v8.1 (`strdelim`, no escapes): `\\.\pipe\x` is literal [S]. ≥ 8.7 parser (S04) and v9.5/v10 source: `argv_split` turns `\\` into `\` and keeps unrecognized escapes, so `\\.\pipe\x` becomes `\.\pipe\x` [S]; that is a drive-relative path (S11), consistent with the reported `error: 3` (path not found) [I]. `//./pipe/x` is a device path after separator canonicalization [D S11 + I]; reported working [C]. `\\\\.\\pipe\\x` should yield `\\.\pipe\x` on ≥ 8.7 [I]. `%` and `${…}` are expanded in IdentityAgent, so pipe names containing `%`/`$` need escaping [S]. | [S] [I] [C] | S02–S05, S11 | P-W03 records each form per build. |
| Q07 | Precedence among `-o`, `-F` file, user/system config, env | First obtained value wins; command-line `-o` is applied before files; `-F` replaces the user config **and** makes ssh ignore the system-wide config (upstream manual). Windows paths: `%userprofile%\.ssh\config`, `%programdata%\ssh\ssh_config`. | [D] | spec S01/S02, S08 | P-W03 (`ssh -G` line per case). |
| Q08 | Can `ssh.exe` use a real Windows AF_UNIX socket file as agent? | AF_UNIX client sockets are emulated by named pipes (`socket(AF_UNIX)` → `fileio_afunix_socket`, connect → `CreateFileW`), and "Unix domain server sockets are not supported". A Windows AF_UNIX socket file is therefore unlikely to be usable as `IdentityAgent`. | [S] → [I] | S02 | Not needed for the chosen designs; add a W03 form only if a design depends on it. |
| Q09 | Who can connect to the Windows OpenSSH agent pipe, and whose keys do they reach? | Pipe DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)` with `PIPE_REJECT_REMOTE_CLIENTS`: any authenticated local user can connect. The agent identifies the client by PID → token, impersonates it, and opens the client's own `HKCU` key store with DPAPI under the client's context, so a different user reaches their own (normally empty) store. | [S]; isolation outcome [I] | S02 | P-W05 gated sub-probe (`-AllowProviderContact`). |
| Q10 | Does the Windows agent support lifetime/confirm/destination constraints? | Wiki: `-c`/`-t` ignored, keys persist permanently. v10.0 source: `parse_key_constraints` rejects every constraint except `sk-provider@openssh.com`, so constrained adds would fail rather than be ignored; no destination constraints. Wiki and source disagree on "ignored" vs "fails". Either way the system agent offers no deadline or destination enforcement. | [D-wiki] vs [S] | S02, S07 | P-W11 (gated: disposable host, disposable key). |
| Q11 | Who can start or reconfigure the agent service? | Microsoft: disabled by default; enabling requires an elevated prompt. GitHub installer sets the service DACL so Authenticated Users get start (`RP`), interactive/service users get query/interrogate rights, and only Administrators get stop/change-config/DAC rights. In-box FOD service DACL not documented in the fetched pages. | [D], [S], [U] | S08, S02 | P-W09 reads `sc.exe sdshow ssh-agent` (no change made). |
| Q12 | Git for Windows: which ssh, which agent transport? | Installer offers bundled vs external OpenSSH [S]. 1Password documents `core.sshCommand=C:/Windows/System32/OpenSSH/ssh.exe` for Git for Windows to reach the pipe [D]. Bundled MSYS2 ssh uses MSYS/Cygwin socket emulation, not Windows named pipes [C S06]; so with the bundled client the Windows agent pipe is unreachable [I]. | [S] [D] [C] [I] | S12, S14, S06 | P-W02 (MSYS ssh-add with a pipe path), P-W04 (default vs override, client path in agent log). |
| Q13 | Git precedence for the SSH command | `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH` > `ssh`; `GIT_SSH_COMMAND`/`core.sshCommand` go through the shell. | [S] [D] | S13 | P-W04. |
| Q14 | How does 1Password's pipe coexist with the OpenSSH agent service? | 1Password asks the user to disable the OpenSSH Authentication Agent service and then "take[s] over and listen[s] on the system-wide pipe" [D]. No alternate 1Password pipe name is documented [U]. 1Password pipe DACL undocumented [U]. What happens if both run (two servers creating instances of the same name) is undocumented [U]; the OpenSSH agent creates instances without `FILE_FLAG_FIRST_PIPE_INSTANCE` [S], so a shared name is possible if the DACL permits it [I]. | [D] [S] [U] [I] | S12, S02 | P-W10 (gated: disposable 1Password account; mutation sub-probe only on disposable host). |
| Q15 | 1Password authorization semantics relevant to Heimdall | Per key per application (incl. subprocesses), optionally per terminal tab, or per request; approvals until lock/quit or 4/12/24 h; locked app prompts to unlock; "Approve for all applications" = everything running as the OS user, limited only by socket/pipe permissions. | [D] | S12 | P-W10 (operator records prompts), P-B04 attribution. |
| Q16 | Can a scoped per-binding endpoint coexist with the installed global provider? | If Q04/Q05 hold, yes for **selection**: Heimdall creates its own pipe(s) and points bindings at them, leaving the global pipe untouched [I]. Scope is only as real as the signer behind the Heimdall pipe: if it forwards to the global provider, any same-user process can bypass it by using the global pipe directly (filtered convenience) [I]. | [I] | — | P-W02/P-W03 (selection), P-W05 (other user). |
| Q17 | Pipe namespace hazards | Without an explicit DACL a pipe grants Everyone read [D S09] → always set a DACL. `FILE_FLAG_FIRST_PIPE_INSTANCE` lets the creator detect a pre-existing name [D S10]. Another principal can add an instance to an existing pipe only with `FILE_CREATE_PIPE_INSTANCE` (= `FILE_APPEND_DATA`, included in `FILE_GENERIC_WRITE`) [D S09, S10]; the Win32-OpenSSH agent grants AU `0x12019b`, which withholds it [S]. Instance creation also fails with the same `ERROR_ACCESS_DENIED` for the first-instance flag or mismatched type/access/count/time-out [D S10], so a denial is attributable to the DACL only against a same-parameter control. .NET's `NamedPipeServerStream` cannot set `PIPE_REJECT_REMOTE_CLIENTS` [S S21]. Pipe names are enumerable by other users [I]. Win32-OpenSSH clients do not authenticate the pipe server; they only cap impersonation at SecurityIdentification [S] → a squatter can receive agent requests but not impersonate the client [I]. | [D] [S] [I] | S09, S10, S02, S21 | P-W05, P-W06. |
| Q18 | Stale endpoints on Windows | A named pipe exists while a server handle is open; killing the server should remove it (no filesystem residue, unlike Unix sockets). | [I] | — | P-W06. |
| Q19 | `Match exec`/`ProxyCommand` on Windows | Executed with `system()` (cmd.exe semantics). Relevant to passive doctor (R-SS-02) and to quoting. | [S] | S02 | P-W08 indirectly; G08/M02 doctor tests. |
| Q20 | Multiplexing on Windows | No Unix-domain server sockets → `ControlMaster` unavailable in Win32-OpenSSH. | [S] → [I] | S02 | G09 (not a G03 probe). |
| Q20a | Windows private-key file permissions (spec §8.4, S13) | On load, `sshkey_perm_ok` calls `check_secure_file_permission(path, NULL, read_ok=0)`: the file owner must be the user, Administrators, SYSTEM or TrustedInstaller, and **any** allow ACE for another trustee (even read) rejects the key with "UNPROTECTED PRIVATE KEY FILE … will be ignored" [S]. Administrators and SYSTEM access is accepted by design, so file ACLs are no boundary against administrators and elevation is not a key-use approval [I]. Shipped-build behavior [U]. | [S] [I] [U] | S02 | P-W12. |

### 2.2 WSL

| # | Question | Current answer | Label | Sources | Resolves with |
|---|---|---|---|---|---|
| Q21 | Mode A mechanism | WSL launches Windows executables via a `binfmt_misc` interpreter and interop servers under `/run/WSL`; parameters are passed unmodified; Linux env reaches the Windows process only through `WSLENV`; interop can be disabled per distribution (`/etc/wsl.conf`) or for all users (registry `DistributionFlags`). | [D] | S15, S16 | P-A01. |
| Q22 | Is Mode A what 1Password supports? | Yes: run `ssh.exe` from WSL, `git config core.sshCommand ssh.exe`, configuration in the Windows profile, per-WSL-session authorization, interop required. | [D] | S12 | P-A01, P-A04 (with 1Password only under the gated W10 conditions). |
| Q23 | Under which Windows token does `ssh.exe` run when launched from WSL? | The interop server forwards creation to the associated Windows process (`wsl.exe`/`wslhost.exe`) [D S16], so the child should carry that session's token, including elevation if WSL was started elevated [I]. Microsoft also states elevated and non-elevated launches do not create separate guest security boundaries [D S16]. | [D] [I] | S16 | P-A06. |
| Q24 | How is a Linux argv converted to the Windows command line for `ssh.exe`? | Not documented beyond "unmodified". Behavior for spaces, embedded quotes, backslashes, Unicode, and cmd/PowerShell metacharacters is unknown. | [U] | S15 | P-A03 (argv fidelity cases), P-W08 (native comparison). |
| Q25 | Which paths can `ssh.exe` read from WSL? | Needs Windows paths; `wslpath` converts. Whether `ssh.exe` accepts config/known_hosts/certificate files on `\\wsl.localhost\…` (9P) is unknown; Windows ssh checks private-key file ACLs [D S08, S S02], untested for 9P files. | [D] [U] | S08, S15 | P-A03, P-A05. |
| Q26 | Can a WSL2 Linux socket talk to a Windows AF_UNIX socket directly? | Documented for WSL1 (Build 17093); reported not working in WSL2 (open issue). Mode B on WSL2 therefore needs a relay (stdio over interop, `npiperelay` pattern) or another channel. | [D] (WSL1), [C] (WSL2) | S15, S17, S12 | P-B04 exercises the stdio relay. |
| Q27 | What isolation exists between distributions? | Separate mount/PID/UTS namespaces; `/mnt/wsl` shared [D S16]. Network namespace is not in that list → shared network namespace likely, so abstract-namespace sockets and loopback TCP are reachable across distributions [I]. Microsoft: not a security boundary between distributions of the same user [D]. | [D] [I] | S16 | P-B08. |
| Q28 | Can Windows processes reach a Mode B endpoint? | Any process of the same Windows user can run `wsl --distribution X --user root` [D S15], i.e. become root in the distribution and use any socket [I]. `\\wsl$` access uses the default user [D]. Loopback TCP reachability from Windows depends on the networking mode (`[wsl2] networkingMode` = `none`, `nat` (default; unknown values → NAT, which since WSL 2.3.25 falls back to Consomme if NAT fails), `bridged` (deprecated), `mirrored`, `consomme`) [D S15]: NAT relays bound guest TCP ports to Windows via `wslrelay`; mirrored forwards `bind()` calls to Windows; Consomme tracks bound guest ports and forwards them, optionally via `wslrelay` [D S16]. Other Windows users can connect to Windows loopback ports [I]. | [D] [I] | S15, S16 | P-A00/P-B08 record the mode; P-B08, P-B11. |
| Q29 | Can another Windows user reach this user's distributions? | Distributions are registered per Windows user [I]; not stated in fetched docs. | [U]/[I] | — | P-B11 (Windows orchestrator `wslotheruser`). |
| Q30 | Does a background endpoint keep a distribution alive? | `instanceIdleTimeout` default 15000 ms, `vmIdleTimeout` 60000 ms [D]; what counts as idle is not documented [U]. | [D] [U] | S15 | P-B10. |
| Q31 | Is `$XDG_RUNTIME_DIR` available? | Depends on systemd being enabled (`[boot] systemd=true`, WSL 2 only) and the distribution [D S15 for systemd]; not guaranteed [I]. The harness falls back to a private scratch directory and records which one it used. | [D] [I] | S15 | P-A00 inventory, P-B01. |

## 3. Candidate designs and honest security properties

Common facts: OpenSSH documents that an agent socket is usable by root or another process of the same
user (spec S30); Microsoft documents that WSL is not a boundary from the same Windows user (S16).
Nothing below claims protection against same-user code. "Real scope" means a limit that holds against a
caller who can reach the endpoint; "filtered convenience" means a limit that a same-principal caller can
bypass through another reachable path.

### 3.1 Native Windows

**N1 — Global pipe (status quo).** `ssh.exe` → `\\.\pipe\openssh-ssh-agent`, served by the OpenSSH agent
service or by 1Password. *Who can connect:* any local authenticated user can open the OpenSSH agent pipe,
but reaches only their own key store (Q09 [S]); 1Password pipe DACL [U]. *Scope:* none per job; 1Password
authorizes per application/session [D]. *Heimdall use:* acceptable as the ordinary default for existing
access (R-UX-01); **claiming a per-job endpoint here is prohibited** (spec §8.4).

**N2 — Heimdall per-binding named pipes (candidate default for scoped work).** The non-elevated per-user
runtime creates `\\.\pipe\heimdall-<random>` with an explicit owner-only DACL (optionally SYSTEM),
`PIPE_REJECT_REMOTE_CLIENTS`, and `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance (fails if the
name exists); further instances for concurrent clients rely on the DACL withholding
`FILE_CREATE_PIPE_INSTANCE` from everyone but the owner (P-W05, P-W06). This needs direct
`CreateNamedPipe` calls: .NET's stream cannot set `PIPE_REJECT_REMOTE_CLIENTS` [S S21]; the probe fixture
`InstrumentedAgent.ps1` now does exactly this. Bindings select it
with a generated `IdentityAgent //./pipe/heimdall-<id>` (form pending P-W03) or a per-process
`SSH_AUTH_SOCK` (`heimdall run`); Git via `core.sshCommand`/`GIT_SSH_COMMAND` pointing at System32
`ssh.exe` (pending P-W04).
- *Who can connect:* processes holding the owner's token; administrators/SYSTEM are not defended
  against; other standard users are denied by the DACL (to verify, P-W05).
- *Is the channel authenticated?* By OS access check only; the server can additionally read the client
  SID via `ImpersonateNamedPipeClient` (identification level) and require it to equal the owner. PID and
  image path are metadata, never authorization (spec §4.2, §13.2).
- *Scope:* real for the endpoint when Heimdall holds the credential and enforces the binding's key and
  deadline policy itself (G04). When the signer behind it is the global provider, the scope is filtered
  convenience, because the same principal can use N1 directly.
- *Lifecycle:* the pipe disappears with the server [I, P-W06]; the supervisor recreates it under the
  same name only after verifying it is free; pre-squatting is detected by `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance and
  mitigated by unpredictable names created before advertisement; other users can still see names [I],
  so names carry no labels. Logoff ends the per-user runtime [I]; host lock does not affect the pipe, and
  signing availability depends on the credential (G04).

**N3 — Heimdall serves `\\.\pipe\openssh-ssh-agent`.** A global takeover that conflicts with 1Password and
the system service and changes every client's endpoint silently. **Rejected** unless the owner explicitly
adopts it as a visible, reversible setup step (spec §5.2, §8.4 "no silent global takeover").

**N4 — Packaged alternative client.** If P-W03 shows the in-box client cannot select a per-binding pipe,
spec §8.4 allows installing/configuring a selected helper or executable visibly while preserving the
system client. This is a fallback, decided only after P-W03 (E-4).

### 3.2 WSL Mode A — Windows SSH authority

**A1 — WSL consumers invoke Windows `ssh.exe`.** Via `core.sshCommand=ssh.exe`, a Heimdall-generated shim,
or aliases (1Password's documented pattern, S12). `ssh.exe` reaches N1 or an N2 pipe chosen with an
explicit `-o IdentityAgent=//./pipe/…` or a config `IdentityAgent $VAR` + `WSLENV=VAR/w` (P-A01).
- *Who can connect:* every process of the same Windows user, including all of that user's distributions
  and Windows processes (interop) [D S16 + I]; other Windows users are denied by the N2 DACL (P-W05) and,
  presumably, cannot enter this user's distributions (P-B11).
- *Authentication/attribution:* the Windows endpoint sees `ssh.exe` running as the Windows user; no
  Linux identity crosses the boundary [I]. 1Password attributes approvals to the requesting application
  [D]; how it names WSL-launched `ssh.exe` is recorded manually in P-W10.
- *Scope:* identical to N1/N2; the distribution adds nothing.
- *Lifecycle:* no Linux endpoint to go stale; distribution restart is irrelevant; depends on the Windows
  runtime/provider; host lock follows the provider (G04).
- *Risks to test:* argv conversion (Q24), path forms (Q25), stdin EOF / exit status / interrupt
  propagation through interop, Linux tools that ignore `core.sshCommand`, per-invocation latency.

### 3.3 WSL Mode B — Linux-native scoped endpoint

**B1 — `socat` + `npiperelay` to the global pipe (community pattern, S12 tip, S18).** Linux socket →
per-connection relay → `\\.\pipe\openssh-ssh-agent`. No filtering; protected only by the Linux socket mode;
every request is attributed to the relay; third-party binary. **Rejected as a default**: it exposes the
broad personal agent (spec §8.4, §8.5).

**B2 — Heimdall supervised scoped bridge (candidate).** Per binding, a Linux endpoint in a private
directory (`$XDG_RUNTIME_DIR/heimdall/<binding>/agent.sock` when available; directory 0700, socket 0600)
whose helper checks the peer UID (`SO_PEERCRED`), filters the protocol (list only allowed identities,
sign only allowed keys, refuse add/remove/lock/unlock/smartcard and all extensions except
`session-bind@openssh.com`, bound message size, idle time, concurrency, and the binding deadline), and
forwards over a supervised stdio channel created by WSL interop to the Heimdall Windows runtime (N2), which
signs with a Heimdall-held credential or forwards to the selected upstream. The probe proxy
`tests/native/wsl/agent_proxy.py` implements exactly these mechanics so they can be measured.
- *Who can connect:* (a) same-UID Linux processes in that distribution and root — by design;
  (b) other Linux UIDs — blocked by file mode and by the peer-UID check (P-B01), **but** with interop
  enabled any Linux user can run `wsl.exe -u <owner>` and become the owner [I from D S15/S16; P-B01
  measures]; (c) other distributions of the same Windows user — not via the private path (separate mount
  namespace [D]) but trivially via `wsl.exe -d <target>` [D]; must not use `/mnt/wsl`, abstract sockets or
  TCP (P-B08); (d) Windows processes of the same user — via `wsl.exe --user root` [D]; (e) other Windows
  users — expected no (P-B11, P-W05).
- *Is the bridge authenticated?* Linux side: kernel peer credentials. Linux↔Windows hop: a parent/child
  pipe created by interop with no listener, so a third party cannot connect to that hop [I; P-B04 checks
  the relay is per-connection and exits]. Windows side: the N2 DACL plus client SID check, which
  identifies the Windows user, not the Linux program.
- *Scope:* the filter is real enforcement **for requests through this endpoint**. Because the same
  Windows principal can reach the upstream directly (Mode A or N1), the scope is **filtered convenience**
  unless the credential is Heimdall-held and the Windows runtime enforces the binding's policy — and even
  then any same-user process can ask the runtime for that binding (R-SE-03 label: "same-user
  convenience"). Destination limits come only from server-side principals (G04/G09), never from the
  socket filter (spec §8.5).
- *Attribution:* a per-application provider (1Password) sees the relay/runtime process, not the Linux
  caller; Heimdall must disclose this approval-boundary change during setup (spec §14.4) (P-B04, E-5).
- *Lifecycle:* distribution terminate kills the helper (P-B09); the Windows relay must exit on EOF
  (P-B04); sockets on tmpfs vanish, sockets elsewhere go stale and must be detected (connect →
  ECONNREFUSED) and replaced only when owned by this UID and not live (P-B05); deletion of the socket path
  must be detected (P-B03); stale cleanup must never remove a replacement generation (P-B05, R-RT-04);
  the binding stops at its deadline and teardown removes only its own endpoint (P-B06);
  idle shutdown may stop the distribution, so state belongs to the Windows runtime and the Linux helper is
  ephemeral (P-B10); host lock does not affect the Linux helper, and signing follows the provider/G04
  credential (P-B07).

**B3 — Heimdall signer inside the distribution.** No bridge; the managed credential lives in the distro.
Same-Windows-user processes can read distro files (`\\wsl$` default user [D]) and become root [D], so
custody is weaker than a Windows-side store [I]. Not a default; revisit only if G04 selects a Linux-held
recipe.

**B4 — Loopback TCP bridge.** **Rejected:** unauthenticated loopback TCP is excluded (spec §8.4, §13.2);
NAT `localhost` relays WSL listeners to Windows loopback [D S16]; distributions likely share the network
namespace [I]. P-B08 records the exposure as evidence for this rejection.

**B5 — Windows AF_UNIX interop.** WSL1 only (Q26); not available for WSL2.

## 4. Probe plan

Harnesses: `tests/native/windows/Invoke-G03WindowsProbes.ps1` (PowerShell 5.1/7.x),
`tests/native/wsl/run_g03_wsl_probes.sh` (in-distribution), `tests/native/wsl/run_g03_wsl_lifecycle.sh`
(controller → target distribution). They use disposable keys (in-memory ECDSA keys inside
`InstrumentedAgent.ps1`; per-run ed25519 keys in a 0700 scratch directory on Linux) and instrumented
endpoints whose logs show which endpoint a client selected. Defaults never contact the owner's agent;
gated sub-probes need explicit switches plus an owner-authorization reference. Records follow
`tests/evidence/record.schema.json`.

**Common preconditions** (exact versions are recorded by the harness; G01 chooses floors):
native Windows 11 x86-64 host or VM (current GA build and the oldest build G01 wants to support), in-box
OpenSSH client; optionally the Win32-OpenSSH `10.0.0.0p2-Preview` MSI as a second client; Git for
Windows `v2.56.0.windows.1` installed once with "Use bundled OpenSSH" and once with "Use external
OpenSSH"; Windows PowerShell 5.1 and PowerShell 7.4+; WSL `3.0.1` with two disposable WSL2
distributions (suggested: Ubuntu 24.04, Debian 13) with `python3` and OpenSSH client; a disposable SSH
fixture reachable from Windows (e.g. `tests/fixtures/ssh` M00-T03 containers) and its `known_hosts`; a
second disposable non-admin Windows account; for P-W10 only, 1Password for Windows signed in to a
disposable account with a disposable SSH key.

**Status convention for executed probes** (orchestrator decision 2026-10-03, `tests/evidence/README.md`;
resolves E-1): `status` describes the evidence, `observed_result.verdict` the criterion. Any criterion
unobservable, any failed control, an environment problem or a harness error → `in_progress`, verdict
`inconclusive`; otherwise any criterion false → `verified`, verdict `fail`; all true → `verified`,
verdict `pass`; precondition missing → `blocked`. Records list `failed_criteria` and
`unobserved_criteria`. Harness self-test records name no requirement IDs. Controls: a criterion whose
control did not hold is set to null (inconclusive), never left to pass.

### 4.1 Native Windows (feeds A14 unless noted)

| ID / case | Purpose | Preconditions beyond common | Steps (harness) | Pass criteria (all must hold) | Fail means | Feeds |
|---|---|---|---|---|---|---|
| P-W01 `G03-win-env-inventory` | Passive inventory | — | ssh candidates (path, banner, file version, sha256), PATH order, scopes in which git `core.sshCommand` is set (`--show-scope --name-only`: scope names only, no value or path; Git still reads the owner's config to answer), `GIT_SSH*` presence, agent service state/DACL, pipe **names** (no pipe opened), provider process presence | inventory collected; System32 ssh present | in-box client absent → install FOD is a G01 prerequisite | R-EN-01, R-SS-03, R-QU-02 |
| P-W02 `G03-win-sshauthsock-selection` | Q03/Q04: env-based selection, no fallback | — | instrumented agents T and Unicode-named U; `ssh-add -l` with `SSH_AUTH_SOCK` = backslash, forward-slash, space/Unicode pipe, non-existent sentinel; repeated for every `ssh-add.exe` found. Sentinel row: if `\\.\pipe\openssh-ssh-agent` is present it is not contacted unless the client falls back, and that row's stdout is not saved; if absent, on a declared disposable host (service stopped, no 1Password) a fixture decoy serves the default name for that one run | System32 backslash form lists T's key (exit 0); sentinel gives exit 2; no fallback (judged only when something listens on the default name: an existing server → exit 2 discriminates; the decoy → no connection; otherwise not a criterion and the record says so) | `SSH_AUTH_SOCK` cannot target a Heimdall pipe → `heimdall run` binding redesign | R-EN-01, R-SS-03, R-RT-03 |
| P-W03 `G03-win-identityagent-forms` | Q05/Q06/Q07: config/`-o` selection forms | fixture server | per client × {config, `-o`} × 10 forms plus a control (target in `SSH_AUTH_SOCK`, no IdentityAgent); decoy agent D in `SSH_AUTH_SOCK`, target T in IdentityAgent; selection from agent logs; `ssh -G` value | control reaches public-key auth (else all other criteria inconclusive); some form selects T exclusively on System32 ssh; `none` contacts neither; literal `SSH_AUTH_SOCK` contacts only D | no form selects T → per-binding pipe via config impossible on that build → N4 or `run`-only binding (E-4) | R-EN-01, R-SS-03, R-RT-03 |
| P-W04 `G03-win-git-ssh-selection` | Q12/Q13 | Git for Windows; fixture repo URL | passive default-ssh resolution (bundled `ssh.exe` present in the Git installation? PATH order; nothing executed); `git ls-remote` with `-c core.sshCommand=<System32 ssh -F …>`, `GIT_SSH_COMMAND` vs `core.sshCommand`, `core.sshCommand` vs `GIT_SSH` sentinel; `GIT_TRACE`; owner Git config excluded. Live `default_no_override` (Git's default ssh, no `-F`) **only** with `-IAmOnADisposableHost`, `%USERPROFILE%\.ssh` absent or empty (entry count only) and no `%PROGRAMDATA%\ssh\ssh_config` (existence only): Win32-OpenSSH ignores `HOME`, so that row could otherwise read owner config/keys and follow an owner `IdentityAgent`; it passes no BatchMode/known_hosts and may stop at host-key verification (observation only) | System32 via core.sshCommand reaches T (control; if not, precedence rows are inconclusive); `GIT_SSH_COMMAND` wins; `core.sshCommand` beats `GIT_SSH` | precedence differs → Git binding design changes | R-EN-01, R-SS-03, R-EN-02 (A12) |
| P-W05 `G03-win-pipe-acl-other-user` | "inspect from another OS user" | second disposable account (`-OtherUserCredential`) | three owner fixtures with identical parameters (4 instances, duplex, byte, `PIPE_REJECT_REMOTE_CLIENTS`, time-out 0), differing only in DACL: owner-only; AU connect-only `0x12019b` (Win32-OpenSSH agent mask); AU `0x12019f` (adds `FILE_CREATE_PIPE_INSTANCE`, control). Fixture agents re-arm their one instance with `DisconnectNamedPipe` (no recreate window). Other-user staging: script file in a per-run `%PUBLIC%` directory with a protected two-account DACL, short `-File` command line (≤ 1024 for `CreateProcessWithLogonW` [D S23]), preamble resets the inherited caller environment [S S22], done-marker completion. As other user, via raw Win32 calls with the same parameters: enumerate names; `CreateFileW` (SECURITY_IDENTIFICATION) + REQUEST_IDENTITIES; `CreateNamedPipeW` (no first-instance flag); `ssh-add -l`; gated: other user vs default pipe | controls: AU connect answered (type 12) and instance created on the `0x12019f` fixture (else dependent criteria inconclusive); owner-only connect fails with Win32 error 5, `ssh-add` exit 2, instance creation fails with Win32 error 5, owner agent saw no request. Observation: instance creation against the connect-only DACL | DACL ineffective → N2 unacceptable until fixed | R-EN-01, R-RT-03, R-SS-03 |
| P-W06 `G03-win-stale-squat-pipe` | Q17/Q18 | (cross-user part: second account) | 4-instance fixtures with identical parameters: same-name duplicate with first-instance flag, and a no-flag control; kill server, enumerate, `ssh-add` (dead-pipe fallback judged as in P-W02); other user (staged as in P-W05) pre-creates the name (Everyone full control, same parameters); owner starts with the flag, then a no-flag control; owner client against squatted name | duplicate refused while the no-flag control joins the name (else inconclusive); pipe vanishes with server; client exit 2; no fallback to the default pipe (only when judged, as in P-W02); owner start fails on the pre-squatted name while the no-flag control joins it (else inconclusive) | silent sharing or no detection → N2 must change creation/advertisement | R-EN-01, R-RT-03, R-RT-04, R-SS-03 |
| P-W07 `G03-win-process-io` | spec §10.4 process contract | fixture + authorized ephemeral key | `exit 42`; stdout/stderr separation; UTF-8 bytes; 1 MiB binary round trip via Process API and cmd redirection; PowerShell native pipeline (observation); latency; manual Ctrl-C/resize listed | exit 42 preserved; stderr not on stdout; UTF-8 exact; both binary paths exact | byte or status corruption → `run`/transport design blocked on Windows | R-EN-01, R-SS-04, R-QU-02 |
| P-W08 `G03-win-path-quoting` | paths/quoting fixtures | fixture + authorized key | `known_hosts` under spaced/Unicode and `%`/`$` directories in 4 notations; 17 remote-argument cases through Process API, `cmd.exe`, PowerShell | spaced/Unicode `-F` works; forward-slash quoted known_hosts works; Process-API argv exact for all cases | generator must change notation; shell channels recorded as observations | R-EN-01, R-EN-02, R-SS-04, R-QU-02 |
| P-W09 `G03-win-service-elevation` | R-DI-02 no repeated elevation | run non-elevated | read service state and DACL (rights parsed as exact two-letter codes); record token elevation; create an owner-only fixture pipe (N2 stand-in) and list it with System32 `ssh-add` | run non-elevated; service state read; routine scoped pipe created and used non-elevated (inconclusive if the run was elevated) | needs elevation for routine scoped work → N2 redesign | R-EN-01, R-DI-02 |
| P-W10 `G03-win-1password-coexistence` | Q14/Q15 | disposable 1Password account; `-AllowProviderContact` (+ `-AllowSystemAgentMutation` on disposable host) | identify default-pipe server process and its DACL; `ssh-add -l`; operator records prompts; gated: start OpenSSH service while 1Password holds the pipe and sample which server answers | server identified; (gated) at most one server answers | two servers share the name → nondeterministic endpoint; Heimdall must detect and refuse | R-EN-01, R-CR-01, R-SS-03 |
| P-W11 `G03-win-agent-constraints` | Q10 | disposable host; agent service running; mutation flag | `ssh-add -t`, `-c`, `-h`, unconstrained with a disposable key; delete; compare list before/after | unconstrained add works; no residue | (observation) informs R-CR-08 and that the system agent cannot enforce deadlines | R-EN-01, R-CR-08, R-SS-03 |
| P-W12 `G03-win-key-file-permissions` | Q20a, spec §8.4 key-permission requirement (S13) | run non-elevated; (ssh sub-case: fixture) | disposable passphrase-less key from System32 `ssh-keygen` in scratch (never loaded into an agent, deleted after); `ssh-keygen -y -f` as generated, with an AU read ACE, after removing it, with an Administrators read ACE; optional `ssh.exe -o IdentityFile=<key> -o IdentityAgent=none` with the AU ACE; file SDDL and token elevation recorded | control: generated key accepted (else all inconclusive); other-principal read ACE rejected with the bad-permissions message; restored owner-only ACL accepted. Observation: Administrators ACE accepted | client does not enforce → Heimdall must check key-file ACLs itself before generating `IdentityFile` projections on Windows | R-EN-01, R-SS-03, R-DI-02 |

### 4.2 WSL Mode A (feeds A12)

| ID / case | Purpose | Preconditions beyond common | Steps | Pass criteria | Fail means | Feeds |
|---|---|---|---|---|---|---|
| P-A00 `G03-wsl-env-inventory` | Inventory | inside WSL | interop state, `wsl.conf` interop lines, Windows PATH append, `/run/WSL`, `/mnt/wsl`, namespace ids, `wsl.exe --version`/`-l -v`, **networking mode** (`wslinfo --networking-mode` when present [U]; only otherwise the `[wsl2] networkingMode` key of the owner's `.wslconfig`; only a known mode word is recorded [D S15]), ssh.exe, git | collected | — | R-EN-02, R-EN-03, R-QU-02 |
| P-A01 `G03-wsl-a-executable-selection` | Q21: ssh.exe selection of the Windows fixture pipe | Windows `-ServeAgentForWsl` manifest (target + decoy pipe); fixture | before any ssh.exe run, `cmd.exe` must echo the decoy value back through `WSLENV=SSH_AUTH_SOCK/w` (`/w` [D S15]), else all Mode A probes are `blocked`; every ssh.exe run gets the decoy pipe as Windows-side `SSH_AUTH_SOCK` (`WSLENV=SSH_AUTH_SOCK/w`); `-o IdentityAgent=//./pipe/<name>`; config `IdentityAgent $HEIMDALL_G03_IA` with `WSLENV=…:HEIMDALL_G03_IA/w`; Linux env visibility to `cmd.exe` with/without a WSLENV entry (no ssh); observation: ssh with the variable unset, run only while `\\.\pipe\openssh-ssh-agent` does not exist | `-o` selects the target and not the decoy; WSLENV form selects the target and not the decoy (both inconclusive if the `-o` run never reached user authentication); variable not visible without WSLENV (control: visible with it) | selection impossible from WSL → Mode A binding redesign | R-EN-02, R-SS-03 |
| P-A02 `G03-wsl-a-process-io` | interop I/O fidelity | + manifest key authorized on fixture | exit 42, stream separation, UTF-8, 1 MiB round trip, stdin EOF, `timeout -s INT`, orphan `ssh.exe` count, latency | all exact; no orphan `ssh.exe` after interrupt | interop breaks the process contract → `run` wrapper needed in Mode A | R-EN-02, R-SS-04 |
| P-A03 `G03-wsl-a-path-quoting` | Q24/Q25 | as P-A02 | `-F` on Linux path, `\\wsl.localhost` UNC, Windows spaced/Unicode path; embedded-quote `-o`; 17 argv cases (`argv_fidelity.py`) | Windows spaced/Unicode config works; all argv cases exact | quoting broken → generator must avoid affected forms or Mode A needs a shim | R-EN-02, R-SS-04 |
| P-A04 `G03-wsl-a-git` | Git interoperability | as P-A02; fixture repo URL (`--git-push` optional) | `core.sshCommand` with ssh.exe; `GIT_SSH_COMMAND` precedence; clone into Linux and `/mnt/c` spaced/Unicode paths; optional push | all succeed and the Windows agent saw ssh.exe | Git interop gap → documented limitation or shim | R-EN-02, R-SS-03 |
| P-A05 `G03-wsl-a-cert-change` | "change public-certificate files" | fixture CA key + CA-trusting host (M00-T03 `ca-host1`) | sign manifest key with permitted principal → accepted; overwrite cert with wrong principal → rejected; restore → accepted | as stated | cached or ignored cert → Heimdall must restart consumers on rotation | R-EN-02, R-CR-07 |
| P-A06 `G03-wsl-a-elevation` | no recurring UAC | interop | elevation and integrity level of an interop child; operator attests no UAC prompt | child not elevated; no UAC observed | elevated interop children → Mode A launch guidance/limit | R-EN-02, R-DI-02 |

### 4.3 WSL Mode B (feeds A13)

| ID / case | Purpose | Preconditions beyond common | Steps | Pass criteria | Fail means | Feeds |
|---|---|---|---|---|---|---|
| P-B01 `G03-wsl-b-endpoint-perms` | who can connect (Linux side) | (other-UID part: second Linux account with non-interactive sudo) | private dir/socket modes; same-user list; other UID connect; peer-UID check with a deliberately open test socket; other UID → `wsl.exe -u owner` | dir 0700, socket 0600, only allowed key listed, other UID blocked by FS and by peer check | Linux-side boundary absent → B2 redesign; `wsl.exe -u` result is recorded as the documented non-boundary | R-EN-03, R-RT-03, R-SE-03 |
| P-B02 `G03-wsl-b-unauthorized-key` | "try an unauthorized key" | — | filtered list; crafted sign for unallowed key; signature with allowed key verifies; add/remove-all/lock/foreign extension refused; oversize frame closes; upstream unchanged | all | filter bypass → B2 redesign | R-EN-03, R-SE-03, R-RT-03 |
| P-B03 `G03-wsl-b-socket-deletion` | "remove its socket" | — | delete path with and without `--recreate` | recreated with new inode and serving; without recreate exits with distinct code; client exit 2 | silent dead endpoint | R-EN-03, R-RT-01, R-RT-04 |
| P-B04 `G03-wsl-b-relay-attribution` | Linux→Windows hop, attribution | manifest | proxy upstream = `powershell.exe PipeStdioRelay.ps1` per connection; list, sign+verify, filtered key; Windows log client image; latency; relay processes counted (command-line match inside PowerShell, count only) while a client holds a connection and after all clients disconnect, **with the proxy still running**; again after proxy stop (observation) | allowed key works; filtered key refused **by the proxy** (type-5 reply, proxy denial logged, no SIGN_REQUEST for key 2 at the Windows agent); attribution recorded as relay; control sees ≥ 1 relay while a connection is held (else inconclusive); 0 relays after disconnect | relay leaks or bypasses filter → supervised single channel | R-EN-03, R-SE-03, R-CR-01 |
| P-B05 `G03-wsl-b-stale-socket` | stale pipe/socket recovery, ownership | — | refuse live replacement; SIGKILL leaves stale socket; client exit 2; refuse stale without flag; replace with flag; old generation must not unlink a replacement | all | cleanup can delete another generation → R-RT-04 violation | R-EN-03, R-RT-04 |
| P-B06 `G03-wsl-b-teardown-deadline` | "stop its binding", deadline | — | serve before deadline; refuse after; stop removes only own socket; upstream unaffected | all | expiry not enforced at endpoint | R-EN-03, R-RT-04, R-AU-05 |
| P-B07 `G03-wsl-b-host-lock` | host lock | operator present; `--lock-window-minutes` | list every 20 s while operator locks/unlocks; LogonUI heuristic | lock observed; helper survived; post-unlock request ok | helper dies on lock → supervisor design | R-EN-03, R-QU-02 |
| P-B08 `G03-wsl-b-multi-distro-exposure` | multiple distributions | target distro | networking mode recorded (Q28); in target: private-path proxy + inert banner listeners (abstract, `/mnt/wsl`, loopback TCP); from controller and Windows: reachability; controller via `wsl.exe -d target` | private path not visible from controller; exposure matrix measured (loopback rows read per recorded mode) | private path visible → placement redesign; the other rows are evidence for rejecting B4 and for the R-SE-03 label | R-EN-03, R-SE-03, R-RT-03 |
| P-B09 `G03-wsl-b-distro-restart` | "restart one distribution" | target distro; `--allow-terminate-target` | proxies on `/tmp` and `$HOME`; terminate; restart; inspect processes/sockets; client on stale path | processes gone; stale endpoint fails cleanly | — | R-EN-03, R-RT-01, R-RT-04, R-RT-07 |
| P-B10 `G03-wsl-b-idle-timeout` | Q30 | target distro; terminate permission | detached endpoint, no session; poll running state | timeline recorded (observation) | — | R-EN-03, R-RT-01 |
| P-B11 `G03-wsl-b-other-windows-user` | other OS user vs distribution | second Windows account; `-WslDistro` | staged as in P-W05; as other user: `wsl --version` (control), `wsl -l`, `wsl -d`, `\\wsl.localhost\<distro>` | owner baseline visible; control: other user's `wsl --version` exits 0 (else list/launch inconclusive); other user cannot list; launch fails with a recognized distribution-not-found message (other failures inconclusive; pattern not from a pinned source [U]); cannot browse | cross-user exposure → Mode B unacceptable | R-EN-03, R-SE-03, R-QU-02 |

## 5. Failure actions (plan §3 G03)

Plan: "redesign the endpoint or process boundary. Do not mark Windows supported from a successful
cross-compile or defer Mode B into a vague future feature while calling V1 complete." Concretely:

| Trigger | Required action |
|---|---|
| P-W03: no IdentityAgent form selects a Heimdall pipe on the in-box client of a supported build | Per-binding scoping via generated config is infeasible on that build: limit scoped work to `heimdall run` with per-process `SSH_AUTH_SOCK` (if P-W02 passes) or adopt N4 (visible packaged client, system client preserved) after E-4. Never route scoped bindings through N1 and call them scoped. |
| P-W02 fails (env not honored or silent fallback) | `run`-based binding redesign; treat Windows ssh as unscoped-only until resolved. |
| P-W05/P-W06 fail | Fix DACL/creation strategy; N2 may not ship until both pass. |
| P-W09 shows routine elevation | Re-split setup vs routine operations (R-DI-02); no repeated UAC. |
| P-W12 client does not reject a key readable by another principal | Heimdall checks Windows key-file ACLs itself before projecting any `IdentityFile`; document that Administrators/SYSTEM access is accepted by the client and is not a key-use approval. |
| P-W10 shows shared default-pipe servers | Heimdall must detect and report the conflict; never start the system agent service while another server owns the name. |
| P-A01..P-A04 fail | Mode A needs a Heimdall shim (argv/path translation, `WSLENV` handling) or documented limitations per consumer; A12 stays open. |
| P-B01/P-B02/P-B05/P-B06 fail | B2 redesign before any Mode B claim; the prototype proxy's failure location tells which enforcement point is missing. |
| P-B04 relay leaks or misattributes without disclosure | Move to a single supervised Windows-side channel and add setup disclosure (spec §14.4). |
| P-B08 private path reachable from another distribution, or P-B11 cross-user exposure | Placement redesign; Mode B must not ship. |
| Any probe impossible on available hardware | Record `blocked` with the platform; Windows/WSL support stays `not-tested` in `docs/compatibility/matrix.md`; the stable V1 claim remains blocked (plan §6.5, risk register). |

## 6. Decisions outstanding and escalations

| ID | Decision / escalation | Owner | Fail criterion / trigger |
|---|---|---|---|
| E-1 | **Resolved 2026-10-03** by the orchestrator's gate-probe convention (`tests/evidence/README.md`): executed probe with a false criterion → `verified` + `verdict: fail`; invalid/incomplete → `in_progress` + `inconclusive`. Both harnesses now implement it (§4). | Orchestrator (M00) | — |
| E-2 | **A13 "no unintended distribution exposure" vs Microsoft's documented non-boundary (S16).** Proposed interpretation: Heimdall guarantees *default non-exposure* (private placement, no shared mounts, no abstract/TCP endpoints) and labels cross-distribution and same-Windows-user access as convenience, not isolation. This is an authority-semantics reading of spec §8.4/A13 that this task did not decide. | Owner (spec) | If the owner requires isolation between distributions of one Windows user, Mode B needs a mechanism outside WSL's model (separate Windows accounts/VMs), i.e. a spec change. |
| E-3 | **Which upstreams Mode B must support at V1.** With 1Password or the system agent upstream, B2 is filtered convenience; "real" per-binding scope needs a Heimdall-held credential (G04). | Owner + G04 | If V1 requires real scope through Mode B for third-party providers, no evidence-backed design exists today. |
| E-4 | **Packaged alternative Windows client (N4).** Allowed by spec §8.4 if visible and non-destructive; distribution/support cost is an owner decision. | Owner, after P-W03 | Triggered only if P-W03 shows the in-box client cannot select a Heimdall pipe on a supported build. |
| E-5 | **Provider attribution through relays.** 1Password authorizes per application; through B2/N2 the approval names the relay or runtime (spec §14.4 disclosure). Accept, and how to disclose? | Owner | If unacceptable, Mode B with 1Password upstream is unsupported; Mode A remains the 1Password path. |
| D-G03-01 | Windows build and in-box OpenSSH floors | G01 | Floors chosen without P-W01..P-W03 evidence on that build. |
| D-G03-02 | Real-hardware runner for these harnesses (disposable Windows 11 VM vs CI). Hosted CI Windows images are Windows Server, not Windows 11, and lack a second interactive account/WSL distribution set-up by default [I]. | Orchestrator/owner | No runner → all G03 rows stay blocked; stable Windows/WSL V1 blocked. |
| D-G03-03 | Mode B placement when `$XDG_RUNTIME_DIR` is absent (no systemd) | M04 design, after P-A00/P-B09 | Placement leaves stale endpoints that the supervisor cannot attribute. |
| D-G03-04 | Pipe-name scheme and server-side client-SID check for N2 | G08 (local IPC) | P-W05/P-W06 failure. |
| D-G03-05 | Whether Mode A ships a Heimdall `ssh.exe` shim for WSL (argv/path translation) | M04, after P-A01..P-A04 | P-A03 argv failures. |

### 6.1 Decisions recorded 2026-10-06

- **E-2 (owner):** "not exposed by default" is accepted. Heimdall guarantees
  default non-exposure and labels access across distributions, and by the
  same Windows user, as convenience, not isolation.
- **E-3 (owner answer, partly re-asked):**
  - The owner named the AI coding agents Mode B must serve: Claude Code,
    Codex, Pi, Cursor and OpenCode. These are downstream **clients**, and the
    Mode B probes (P-B*) must cover how they start `ssh`.
  - The **upstream** question is still open. The orchestrator's proposed
    default: Heimdall-held managed credentials (G04) as the path with real
    scope, and the system agent / 1Password as filtered convenience upstreams,
    disclosed as such. Waiting for owner confirmation.
- **E-4 (orchestrator, delegated by the owner, "keep it simple"):** V1 does
  not package an alternative Windows SSH client.
  - If P-W03 shows the in-box client cannot select a Heimdall pipe, the
    fallback is env/`run`-based binding plus a documented limitation.
  - Revisit only if no wrapper path works.
- **E-5 (orchestrator, delegated):** accepted, with disclosure.
  - Heimdall's own approval prompt names the destination and grant.
  - Setup text and the approval detail state that the 1Password prompt names
    the relay or runtime process, not Heimdall or the end client (spec §14.4).

## 7. What was checked in this environment (observations about the harness only)

All commands ran on macOS 27.0 arm64 (pwsh 7.6.6 / .NET 10.0.12, OpenSSH_10.3p1, Python 3.14.7,
ShellCheck 0.11.0, PSScriptAnalyzer 1.24.0 from `/tmp/g03-psmodules`, jsonschema 4.25.1 in `/tmp/g03-venv`;
all outside the repository), plus one run in the digest-pinned container
`debian@sha256:0c8bbb8e…` (bookworm-slim, arm64 Docker Desktop VM, `--network none`, read-only repository
mount; image already present locally and already pinned elsewhere in the repository). Exit codes are real.
The M00-T04-G03-fix2 run (2026-10-03 21:25:05Z to 21:25:45Z) is in `static-checks/fix-m00-t04-g03-fix2/`
with the scripts that produced it under `scripts/`; the fix run's transcripts remain in
`static-checks/fix-m00-t04-g03-fix/` and the original task's in `static-checks/*.txt` (both describe
earlier harness states).

| Check | Command | Exit | Observed (transcript) |
|---|---|---|---|
| PowerShell parse | `[Parser]::ParseFile` over all `.ps1/.psm1` | 0 | 0 parse errors in 5 files [O] (`pwsh-parse.txt`) |
| Embedded scripts and C# | parse the four here-string scripts sent to the other user; compile `G03OU`, `G03PipeInfo`, `G03PipeCreate` with `Add-Type` (no native call) | 0 | 0 parse errors; all three types compile under PowerShell 7's compiler [O]. Windows PowerShell 5.1's C# 5 compiler not exercised (`pwsh-embedded-scripts-and-csharp.txt`) |
| Unit checks (pure/mocked functions extracted by AST) | `scripts/unit-checks.ps1` | 0 | 42 checks, 0 failures [O] (`pwsh-unit-checks.txt`): verdict convention and service SDDL (re-run); **D1** the three staged other-user scripts (P-W05, P-W06 squat, P-B11) parse with 0 errors after the staging preamble/`try`/`finally` wrap; new command lines 193/188/197 characters vs the previous `-EncodedCommand` lines 16871/14327/3751 (limit 1024); a path with `"` is refused; a staged script executed by pwsh with a body that throws still writes the done marker, and `TEMP`/`TMP` were reset to the staged directory while an inherited `SSH_AUTH_SOCK` and `PSModulePath` were replaced; **D6** `Wait-OtherUser`: done marker → `done_marker`, no handle + no marker → `timeout` with no PID-only kill, a held handle of a process the check itself started → `killed_via_held_handle`; **D2** `Invoke-DeadSockClient` (platform calls mocked): default pipe present → judged by exit code with stdout not saved; absent and not disposable → not judged; decoy with 0/1 connections → no fallback / fallback; decoy start failure → not judged |
| WSL helper unit checks | `scripts/wsl-unit-checks.sh` on macOS bash 3.2 and in the Debian container (bash 5.2.15, aarch64) | 0 / 0 | **D4** mode-word allowlist; `.wslconfig` parsed only inside `[wsl2]`, unknown values and paths never recorded, not read when `wslinfo` exists; **D7** real `g03_wslenv_check` refuses without `cmd.exe` and, in the container with a stub `cmd.exe` under `/mnt/c`, returns ok only when the value comes back; **D8** `g03_init` exports `PYTHONDONTWRITEBYTECODE=1`; **D6** the extracted `t_keep.sh`/`t_keepstop.sh`: (container only, needs `/proc`) the pidfile PID equals the started PID after `exec sleep`, a wrong start token or a non-`sleep` process is not stopped, an exact match is stopped, then `already-exited` [O] (`wsl-unit-checks-macos.txt`: 22 checks pass, the `/mnt/c` and `/proc` groups skipped; `wsl-unit-checks-linux-container.txt`: 32 checks pass, none skipped) |
| Git scope-only output | `git config --show-scope --name-only --get-regexp '^core\.sshcommand$'` against a temporary global config holding a path-like value (owner config not read: `HOME`, `GIT_CONFIG_GLOBAL` redirected) | 0 | prints `global\tcore.sshcommand` (no value) when set, exit 1 and no output when unset, git 2.54.0 [O] (`git-scope-only-output.txt`); Git for Windows not exercised |
| PSScriptAnalyzer incl. `PSUseCompatibleSyntax` (5.1, 7.4) | `Invoke-ScriptAnalyzer -Recurse -Severity Error,Warning` | 0 | 0 errors, 0 compatibility findings, 56 style warnings (same categories as before) [O] (`psscriptanalyzer.txt`) |
| ShellCheck | `shellcheck -x -s bash *.sh` (harness) and the fix2 check scripts | 0 | clean [O] (`shellcheck.txt`) |
| bash / Python syntax | `bash -n` (4 scripts); `py_compile` (cache under `/tmp`) | 0 / 0 | ok [O] |
| `evidence.py` convention | 4 synthetic criteria sets | 0 | matches the convention [O] |
| PowerShell harness self-test | `Test-G03HarnessSelf.ps1` | 0 | all 17 checks true, including the new `server_instance_rearmed_by_disconnect` (6 connections, 6 `rearm`/`disconnect` events, no recreate) on the .NET Unix-socket path; record `verified`/`pass`, `requirement_ids: []` [O]. Not G03 evidence; `DisconnectNamedPipe` on Windows not exercised |
| WSL-harness mechanics self-test | `selftest_unix.sh` | 0 | 4 records `verified`/`pass`, endpoint-perms `in_progress`/`inconclusive` (no second account), all `requirement_ids: []` [O]; the stale-socket SIGKILL is recorded as `signalled-KILL` and the console no longer carries bash's job notice (0 `Killed` lines). Not G03 evidence |
| Windows orchestrator on a non-Windows host | `Invoke-G03WindowsProbes.ps1 -OutDir …` | 0 | 13 probes `blocked` with the platform reason [O]; only the non-Windows branch ran |
| Placeholder refresh + schema/convention validation | `refresh-hashes.py` (hashes + exact `recorded_at`); jsonschema over 49 records plus convention checks and a sha256 re-check of every harness file named in the 30 placeholders | 0 / 0 | 30 refreshed at 21:25:45Z; 49 valid, 0 invalid, 30 hash-checked, 0 mismatches [O] |
| Leftovers, canary, caches | `pgrep` counts; container count; canary grep (incl. `tests/native`); `__pycache__` under `tests/native/windows` and `tests/native/wsl` | 0 | 0 harness processes, 0 check containers left; no canary strings; 0 caches in the owned harness paths [O] (`tests/native/g04/.venv` belongs to another task and was not touched) |

**Not verified anywhere:** every Windows-only code path (`CreateNamedPipeW` + SDDL, the other-user Win32
helper, client PID/SID capture, `Start-Process -Credential` with the file-staged script and its
`%PUBLIC%` DACL, `DisconnectNamedPipe` re-arming on a real pipe, the default-name decoy,
`Get-Acl`/`Set-Acl`, service/1Password probes), Windows PowerShell 5.1 runtime behavior and its C#
compiler, WSL interop paths (incl. the WSLENV check and keepalive through `wsl.exe`), the lifecycle script,
and every security claim in §3. Independent adversarial reviews were performed (§8, §9); the fix2 changes
in §9 have not been independently re-reviewed.

## 8. Independent review resolution (M00-T04-G03-fix)

Review: `tests/evidence/artifacts/m00-wf1/review-g03.json` (console output under
`tests/evidence/artifacts/review-g03/`). Each finding was checked against the harness and pinned sources
before changing anything. "Fixed" means the harness/doc changed and the checks in §7 pass on macOS; no
fix has run on Windows or WSL, so every G03 record stays `blocked`.

| # | Finding (review severity) | Verified? | Resolution |
|---|---|---|---|
| R1 | Git `default_no_override` runs Git's default ssh without `-F`; with "Use external OpenSSH" that is System32 `ssh.exe`, which ignores `HOME` and can read `%USERPROFILE%\.ssh` and follow an owner `IdentityAgent` (major) | Yes: the case passed no `core.sshCommand`/`GIT_SSH*`, and the harness's own comment says Win32-OpenSSH resolves home from the profile | Fixed. Default mode never executes Git's default ssh: P-W04 records `default_ssh_resolution` passively (bundled `ssh.exe` present in the Git installation, PATH order). The live row runs only with `-IAmOnADisposableHost` **and** no `config`/`id_*` in `%USERPROFILE%\.ssh` (names checked, contents never read). README and script header now state the narrower, accurate claim |
| R2 | P-W05 `owner_only_create_instance_denied` passes with any exception; .NET single-instance pipes add `FILE_FLAG_FIRST_PIPE_INSTANCE`, so it passes with a permissive DACL (major) | Yes, and stronger than reported: CreateNamedPipe returns the **same** `ERROR_ACCESS_DENIED` for the first-instance flag and for mismatched type/access/count/time-out [D S10], so requiring `UnauthorizedAccessException` (the review's suggested fix) would still not discriminate. Also found: PowerShell wraps .NET exceptions (`MethodInvocationException`), so the old `connect -match 'Unauthorized'` check could never pass | Fixed by redesign: three 4-instance fixtures with identical parameters differing only in DACL; the other user uses raw `CreateNamedPipeW`/`CreateFileW` with the same parameters and records Win32 error codes; denial criteria require error 5; the `instance_allowed` control (AU granted `FILE_CREATE_PIPE_INSTANCE`) must succeed and the AU connect control must answer, else the dependent criteria are inconclusive. The connect-only (`0x12019b`) result is recorded as an observation |
| R2b | (same root cause, found while fixing R2) P-W06 duplicate/pre-squat refusals were equally non-discriminating | Yes | Fixed: identical 4-instance parameters plus a no-first-instance-flag control that must join the name; refusal criteria are inconclusive without it |
| R3 | P-B11 lacks a positive control that the other user can run `wsl.exe` (minor) | Yes | Fixed: `wsl.exe --version` control; launch denial counts only with a recognized distribution-not-found message (pattern not from a pinned source [U]); other failures inconclusive |
| R4 | P-B04 filtered-key check cannot tell proxy filtering from the Windows fixture's own refusal (minor) | Yes: serve mode allows only key 1 | Fixed: also requires a proxy `denied_key_not_allowed` log entry and zero Windows SIGN_REQUESTs for key 2's fingerprint |
| R5 | P-B04 relay exit counted only after the proxy stopped (minor) | Yes | Fixed: relays counted by command-line match (inside PowerShell, count only) while the proxy still runs; a held-connection control must see ≥ 1 relay; after-stop count kept as an observation |
| R6 | P-A01 env-form and no-WSLENV cases have no decoy; a fallback to the global pipe would be unseen (minor) | Yes | Fixed: serve mode adds a decoy pipe; every WSL `ssh.exe` run gets it (or a non-existent sentinel) as Windows-side `SSH_AUTH_SOCK` through `WSLENV`; selection criteria fail if the decoy is contacted; env visibility is measured with `cmd.exe` (no ssh); the unset-variable ssh row runs only while `\\.\pipe\openssh-ssh-agent` does not exist |
| R7 | P-W09 never exercises a supported command; the "no elevation" observation is unconditional (minor) | Yes | Fixed: creates an owner-only fixture pipe and lists it with System32 `ssh-add`; new criterion `routine_scoped_pipe_used_non_elevated`; the observation text depends on the result |
| R8 | InstrumentedAgent "remote clients rejected by the OS default" is unsourced and wrong; .NET does not set `PIPE_REJECT_REMOTE_CLIENTS` (minor) | Yes (G03-S21) | Fixed: the fixture now creates its pipe with `CreateNamedPipeW` + SDDL, `PIPE_REJECT_REMOTE_CLIENTS`, explicit max instances and first-instance flag; comment cites S10/S21 |
| R9 | Harness self-test records are `verified` with product requirement IDs (minor) | Yes | Fixed: self-test records carry `requirement_ids: []` (both harnesses); harness-error records name none |
| R10 | Lifecycle target stop kills listener PIDs without start-time checks (minor) | Yes; also found `kill -KILL` in P-B05 and "unknown start time ⇒ kill" in both harnesses | Fixed: start tokens recorded for every target process and required to match; no token ⇒ not signalled; P-B05 SIGKILL goes through `g03_signal_pid`; `g03_stop_pid` and `Stop-G03Owned` refuse unverifiable identities and re-verify before escalating |
| R11 | P-B08/P-A00 do not record the WSL networking mode (minor) | Yes | Fixed: `.wslconfig` `networkingMode` value (only that key) and `wslinfo --networking-mode` when present; Q28 and P-B08 discuss NAT, mirrored and Consomme [D S15, S16] |
| R12 | No probe for the Windows key-file permission requirement (spec §8.4, S13) (minor) | Yes | Fixed: new P-W12 `G03-win-key-file-permissions` (Q20a), placeholder record `blocked` |
| R13 | P-W09 rights parsed by substring across code boundaries (observation) | Yes (unit check shows `SWLOCR` matched `OC`) | Fixed: exact two-letter codes; hex masks make the summary null |
| R14 | Gate-probe status convention | — | Adopted in both harnesses and §4 (E-1 resolved) |

Disputed findings: none. One refinement to a suggested fix is recorded in R2 (an exception type alone
cannot discriminate).

## 9. Independent re-review resolution (M00-T04-G03-fix2)

Re-review: `tests/evidence/artifacts/m00-wf3/review-g03-recheck.json` (confirmed the §8 fixes; eight new
minor defects, one refuted claim). Each item was verified before changing anything; results of the checks
are in §7. Nothing ran on Windows or WSL, so every G03 record stays `blocked`.

| # | Finding | Verified? | Resolution |
|---|---|---|---|
| D1 (+ refuted claim) | Other-user staging passes the whole script as `-EncodedCommand` through `Start-Process -Credential`; `CreateProcessWithLogonW` limits `lpCommandLine` to 1024 characters | **Yes, and confirmed at source level** for PowerShell 7: `StartWithCreateProcess` calls `CreateProcessWithLogonW` with the full command line [S S22]; the limit is documented [D S23]; measured old lengths 16871 (P-W05), 14327 (P-W06 squat), 3751 (P-B11). Windows PowerShell 5.1 is [I]. **Also found in the same source:** (a) the child gets the **caller's** environment block (TEMP/TMP/PSModulePath/SSH_AUTH_SOCK of the harness account), so Windows PowerShell's `Add-Type` (which compiles through `TEMP`) would likely have failed for the other account [I]; (b) a non-admin caller may hold no handle to the other user's process, so the old `WaitForExit`/`Kill` could throw [S S22] | Fixed: the script is written to a fresh per-run `%PUBLIC%\heimdall-g03-<run>` directory (pre-existing path refused) with a protected DACL naming exactly this account (full control) and the other test account (modify), verified (trustees, protection, emptiness) before use; the script file grants the other account read/execute only; command line `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<script>"` with a length check (≤ 1024) recorded per run; the staged preamble resets TEMP/TMP to a directory the other account creates, PSModulePath to the Windows PowerShell defaults and clears SSH_AUTH_SOCK; the body runs in `try`/`finally` that writes a done marker; `Wait-OtherUser` uses the marker and kills only through a handle held since start (else records `not_attempted`). **Remaining assumptions (unexecuted):** 5.1's `Start-Process` behaves like the pinned PS 7 source; the other account can traverse `%PUBLIC%`, read the script and write its result under that DACL; `Set-Acl` on `%PUBLIC%` works non-elevated |
| D2 | Fixture agent recreates its pipe (first-instance flag) after each client: a race with the other user's `TryCreateInstance`; P-W06 `client_fails_cleanly_no_fallback` is exit 2 only | Yes, and the race is broader than reported: between dispose and recreate the name has **zero** instances, so the other user's `TryCreateInstance` would create a fresh pipe and record success on the owner-only fixture (a false `fail` of `owner_only_create_instance_denied`), not only make the agent exit 4. Exit 2 alone is indeed non-discriminating when nothing listens on the default name (a fallback would also give 2); the same weakness was in P-W02's sentinel criterion | Fixed: the agent keeps its one instance and re-arms it with `NamedPipeServerStream.Disconnect()` (`DisconnectNamedPipe`), allowed from Connected/Broken with a new wait from Disconnected [S S21]; recreate only as a logged fallback. New `Invoke-DeadSockClient` for P-W02 sentinel and P-W06 after-kill: fallback is judged only when something listens on `\\.\pipe\openssh-ssh-agent` (an existing server → exit 2 discriminates, stdout not saved; or a fixture decoy served there on a declared disposable host while the name is free, service stopped, no 1Password → must see no connection); otherwise `client_fails_cleanly` (exit 2) is the only criterion and the record says fallback was not judged |
| D3 | Default-mode P-W01 reads owner global Git config and records `core.sshCommand` values with origins | Yes | Fixed: `git -C <scratch> config --show-scope --name-only --get-regexp '^core\.sshcommand$'`: only scope names are recorded (Git still reads the config to answer; disclosed in README/header); output format checked with a temporary config [O] |
| D4 | Default-mode WSL probes read owner `.wslconfig` | Yes (only the `networkingMode` value was emitted, but undisclosed) | Fixed: `wslinfo --networking-mode` first (no Windows file read); `.wslconfig` only as fallback, only the `[wsl2]` key, only a known mode word recorded (`none`/`nat`/`bridged`/`mirrored`/`consomme`/`virtioproxy` [D S15]); disclosed in the WSL header and README |
| D5 | Live `default_no_override` row checks only `config`/`id_*` names; no `%PROGRAMDATA%\ssh\ssh_config` check; no BatchMode | Yes | Fixed: runs only if `%USERPROFILE%\.ssh` is absent or empty (entry count only) and `%PROGRAMDATA%\ssh\ssh_config` does not exist; no BatchMode by design (the row measures Git's defaults), disclosed as "may stop at host-key verification; observation only"; README table updated |
| D6 | `keepalive()` stops only the subshell; `Wait-OtherUser` ignores kill failure; agent stdout/stderr never drained | Yes | Fixed: keepalive `exec`s `wsl.exe` (so the owned PID is the interop process) and its target-side `sleep` records PID + start token; `stop_keepalive` stops it inside the target only on PID + token + `comm` match (container-tested), then the controller PID through the owned check, also on exit. `Wait-OtherUser` records `kill` outcome (D1). `Start-G03InstrumentedAgent` drains both streams asynchronously for the agent's life |
| D7 | WSLENV `/w` semantics unsourced; if reversed, ssh.exe would see an unset SSH_AUTH_SOCK | **Partly disputed:** the semantics are in the already-pinned G03-S15 (`filesystems.md:188`, hash matches the pin: "/w - … only be included when running Win32 from WSL"); the doc listed the flags but did not quote that line. The runtime risk is real | Fixed: excerpt and citation added; `win_setup` now requires `cmd.exe` to echo the decoy/sentinel value back through the same WSLENV entry before any `ssh.exe` run, otherwise every Mode A probe is `blocked` with that reason |
| D8 | S21 snapshot under `/tmp`; id G03-S10 used for two documents; selftest recreates `__pycache__` | Snapshot: yes, though no snapshot in the pins file is committed (stated method); the entry now names a scratch-relative file and says to re-fetch at the pin. **Id reuse disputed as a defect:** one id per pinned collection is the file's convention (S02, S03, S08, S12, S15, S16 all cover several documents); made explicit in the pins notes and the §1 row; citations name the document. `__pycache__`: yes | Fixed: pins notes and §1; `g03_init` exports `PYTHONDONTWRITEBYTECODE=1`; 0 caches after the self-test [O]. New pins: S21 (two more files), S22 (PowerShell `Process.cs`), S23 (`CreateProcessWithLogonW` docs) |

Also fixed while re-running (not in the review): the stale-socket probe's intended SIGKILL made bash print
its job notice, which echoes the fixture proxy's command line, into the self-test console; the kill, wait
and reap now run in one stderr-redirected block (0 `Killed` lines in the console) [O].

Not changed: the reviewer's observation that a definite `false` can sit under an `inconclusive` verdict
follows the orchestrator's convention (`tests/evidence/README.md`) and is left as ruled.
