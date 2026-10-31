# WSL harness: fixes from the first real run

Task M00-T04-G03-native-wsl, 2026-10-06. Host: the owner's Windows 11 Pro PC (build 26300.9550, x86-64),
WSL 3.0.1.0, distribution `Ubuntu` (Ubuntu 24.04.5 LTS, WSL2, systemd, networking mode `nat`,
`[interop] appendWindowsPath=false`). The harness ran inside a `wsl.exe -d Ubuntu --exec` session;
Windows processes ran as the non-admin-token Windows user. These are harness defects found on the
first execution in WSL. No pass criterion was removed or relaxed. The definitive run (r2) and the
supplementary run (r3-msi10) used the final files below. Debug run r1 used the files before fix 4.

| # | File | Reason (observed) | Before | After |
|---|---|---|---|---|
| 1 | `g03_common.sh` (`g03_init`), `run_g03_wsl_probes.sh` (`probe_env`) | On this distribution `[interop] appendWindowsPath=false`, and an sshd or `wsl.exe --exec` session has no Windows PATH entries either. The harness calls `cmd.exe`, `powershell.exe`, `wsl.exe`, `whoami.exe` and `tasklist.exe` by bare name, so every interop step would have failed | Windows tools had to be on the session PATH | `g03_init` keeps the session PATH (`G03_SESSION_PATH`). If interop is present and `cmd.exe` is not on PATH, it appends only `/mnt/c/Windows/System32` and `/mnt/c/Windows/System32/WindowsPowerShell/v1.0`. OpenSSH is not added, so `ssh.exe` still resolves exactly as before. This is recorded as `environment.harness_appended_windows_system32_to_PATH`. `windows_path_appended` in P-A00 is now measured on the session PATH, not on the extended one |
| 2 | `g03_common.sh` (`g03_b_epdir`, `g03_cleanup`) | Mode B endpoint directories are created under `XDG_RUNTIME_DIR` (`/run/user/<uid>`, present with systemd) and were never removed. Cleanup only removed the scratch directory | `hg03-xxxxxx` directories left in `/run/user/<uid>` | Each endpoint directory created outside the scratch is listed in a scratch file. The list is a file because `g03_b_epdir` runs in a command substitution. `g03_cleanup` removes only listed paths that match `*/hg03-??????`. After r1, r2 and r3, `/run/user/<uid>/hg03-*` count was 0 |
| 3 | `g03_common.sh` (`g03_win_init`), `evidence.py` (`redactions`, `_redact_paths`, `redact`, `redact-tree`) | Evidence convention for this task requires kind-specific tokens. The redactor knew user and host names only as `<redacted>`, and replaced home paths only in `redact-tree` | user/host → `<redacted>`; `~` → `<home>` (tree only) | Inside WSL: WSL user → `<wsluser>`, Windows user → `<winuser>`, Windows computer name (`%COMPUTERNAME%`, exported as `HEIMDALL_G03_WIN_HOST` by `g03_win_init`) and hostname → `<winhost>`, `C:\Users\<name>` / `C:/Users/<name>` / JSON-escaped / `/mnt/c/Users/<name>` → `<winhome>`, `$HOME` → `<wslhome>`. Paths are replaced before names, in records and trees. Outside WSL the old tokens remain (`<redacted>`, `<home>`). SID redaction unchanged |
| 4 | `run_g03_wsl_probes.sh` (`probe_a_elevation`), `evidence.py` (`redact`) | r1 saved the full `whoami.exe /groups /fo csv` output. It contains a `MicrosoftAccount\<e-mail address>` group and the local group list, which name–based redaction did not catch | full group list saved as an artifact | Only the `Mandatory Label` row is kept. The full list goes to a scratch file that is deleted on exit, and whoami's exit code is preserved. `redact` also replaces e-mail addresses with `<email>` (defense in depth). In the r1 debug copy the artifact was cut down to the same single row before it was committed |

Not harness changes (run-time choices of this task):

- The run wrapper set `TMPDIR` to the WSL task scratch. It also set `TEMP`/`TMP` to the Windows task
  scratch with `WSLENV=TEMP/p:TMP/p`, so `GetTempPath()` for the harness's Windows scratch and for the
  relay's PowerShell processes was inside `%LOCALAPPDATA%\hm-m00\<task>\`. Every `ssh.exe` run still
  got the harness's own `WSLENV=SSH_AUTH_SOCK/w` (not inherited).
- Fixture (`tests/evidence/artifacts/g03/native-wsl/fixture/`): two loopback non-root sshd instances.
  The certificate host trusted a per-run disposable user CA generated in scratch, not the M00-T03 CA.
  The first certificate-host port, 59849, lay in a Windows TCP excluded port range (59758–59857), so
  WSL NAT localhost forwarding could not relay it, and r1's certificate rows failed with "Connection
  refused". The fixture moved to port 40127, and the full probe set was re-run as r2.
- The Windows fixture agent was `Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl`, unchanged from
  M00-T04-G03-native-windows, run under PowerShell 7.6.6. No Windows harness change was needed.
- Public keys under `windows-serve/` (in-memory disposable probe keys) and `fixture/` (disposable host
  key, deleted user CA) are public fixture keys. The private halves never left scratch and were
  deleted.

Harness files that produced the promoted records (`environment.harness_sha256_*` in every
`tests/evidence/g03-wsl-*.json` from the probe run): `evidence.py`
`91945da532d1ff1ee6a8b8c8c5322139878e43285ab64316a441cf38fada4cdc`, `g03_common.sh`
`cd0ef101357b485bc1d611302b4499cff73478f328699d42d7a8038ac5cf764a`, `run_g03_wsl_probes.sh`
`b6ed680dbe6934d29fdf84973febf2b79c0eafdc516dc844f8f01059292bf7d8`; `agent_proxy.py`, `agent_client.py`,
`agent_proto.py`, `argv_fidelity.py`, `exposure_listener.py` and `run_g03_wsl_lifecycle.sh` unchanged.

## 2026-10-31: first native lifecycle run (P-B08, P-B09, P-B10)

`run_g03_wsl_lifecycle.sh` ran on the owner's Windows 11 PC against a disposable second WSL
distribution (authorized by ADR-0004 §3). One fix from that run: the multi-distribution probe
recorded the target's state file by a path inside the Windows scratch directory that cleanup
deletes; it now copies the file into the run's artifacts first (no step or criterion changed).
Evidence: `tests/evidence/artifacts/g03/native-wsl-b-disposable/`.
