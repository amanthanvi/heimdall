# Native Windows harness: fixes from the first real run

Task M00-T04-G03-native-windows, 2026-10-06. Host: Windows 11 Pro build 26300 (x86-64), non-elevated,
PowerShell 7.6.6 (.NET 10) for the promoted probe run; Windows PowerShell 5.1.26100 for a second
self-test and a supplementary full probe run. These are
harness defects found on the first execution on Windows. No pass criterion was removed or relaxed.
Every affected probe was re-run after its fix. The record of each run carries the harness SHA-256 values.

| # | File | Reason (observed) | Before | After |
|---|---|---|---|---|
| 1 | `G03Common.psm1` (`Protect-G03Text`) | Evidence convention for this task names the redacted kind | user, computer and domain names all became `<redacted>`; profile paths kept their structure only through the user-name token | `%USERPROFILE%` (raw, forward-slash and JSON-escaped forms) → `<winhome>`, user name → `<winuser>`, computer name → `<winhost>`, domain → `<windomain>`. Non-Windows branch unchanged (`<redacted>`). SID redaction unchanged. |
| 2 | `G03Common.psm1` (new `Set-G03FileSystemDacl`), `Invoke-G03WindowsProbes.ps1` (`Set-KeyAce`) | P-W12 aborted with a harness error: `Set-Acl` threw `PrivilegeNotHeldException` (SeSecurityPrivilege) on the ssh-keygen key, under PowerShell 7.6 and 5.1. The key's DACL is protected (`D:P`) and the user's ACE lacks explicit WRITE_DAC; the same `Get-Acl`/`Set-Acl` pair worked on an ordinary file | `Get-Acl` → modify → `Set-Acl` | `FileSecurity(path, Access)` (DACL section only) → modify → `SetAccessControl` (FileInfo method on 5.1, `FileSystemAclExtensions` on 7). Only the DACL is written. The other `Set-Acl` calls (other-user staging directory and script) build fresh security objects and were not executed on this host (no second account), so they are unchanged and still unverified. |
| 3 | `G03Common.psm1` (`Get-G03Sha256Hex`) | P-W12 aborted again: a failing `ssh-keygen -y` writes nothing to stdout, and the mandatory `[byte[]]` parameter rejected the empty array while saving the binary transcript | parameter binding error → harness-error record | `[AllowEmptyCollection()]`; the empty stdout hashes to the SHA-256 of zero bytes |
| 4 | `Invoke-G03WindowsProbes.ps1` (`Invoke-ProbeKeyPerms`, ssh sub-case) | The ssh.exe identity-load observation could not observe what it claimed: ssh offers the public half (from `<key>.pub`) first and opens the private key, where the ACL check runs, only after the server accepts it. The fixture rejected the unauthorized key (`Failed publickey` in the fixture log), so the run ended with `Permission denied (publickey)` and `bad_permissions_reported: false` without reaching the check | one run with the Authenticated Users ACE against an unauthorized key | the disposable key's public half is authorized on the fixture through the existing `-AuthorizeKeyScript` interface; an owner-only control run must authenticate (exit 0) before the open-ACL run counts (`private_key_load_reached`); if the control fails a limitation says so. Still an observation, not a criterion, as designed |
| 5 | `Invoke-G03WindowsProbes.ps1` (new `Get-ExeTag`; P-W02, P-W03 labels) | Transcript labels and the `agent_contact_<tag>` key used the parent directory's leaf, which is `OpenSSH` for both `C:\WINDOWS\System32\OpenSSH` and `C:\Program Files\OpenSSH` (GitHub MSI present on this host). The second build overwrote the first build's transcripts and agent-contact entry | tag = `Split-Path -Leaf (Split-Path -Parent $exe)` | tag = the directory path without the drive, separators/spaces/parentheses → `-` (e.g. `WINDOWS-System32-OpenSSH`, `Program-Files-OpenSSH`, `Program-Files-Git-usr-bin`). Criteria select rows by full executable path and were not affected |
| 6 | `Invoke-G03WindowsProbes.ps1` (`Invoke-ProbeKeyPerms`) | The `administrators_read` step did not change the DACL: Administrators already held FullControl on the generated key, so the added Read ACE merged into it | `administrators_read_ace_accepted` reported without context | new observation `administrators_step_changed_dacl`; when false, a limitation states the observation is vacuous on that host. Not a criterion before or after |

Not harness changes (run-time choices of this task, recorded in the evidence records):

- The run used a scratch-only launcher that sets `TEMP`/`TMP` for the PowerShell process, so the harness
  scratch (`GetTempPath()`) lived under `%LOCALAPPDATA%\hm-m00\<task>\tmp`.
- The disposable SSH fixture was a non-root `sshd` (OpenSSH 9.6p1, Ubuntu 24.04 in WSL2) bound to
  `127.0.0.1` with its own host key, `AuthorizedKeysFile` in the Windows scratch (keys added with the
  `restrict` option), and a scratch bare Git repository. Windows reached it through WSL NAT localhost
  forwarding.

Harness files that produced the promoted records (`environment.harness_sha256` in every
`tests/evidence/g03-win-*.json`): `Invoke-G03WindowsProbes.ps1`
`a7504574525fe02814da5d4c78575bc921be96a58e95bd7d8bc6c2bbafe5dd89`, `G03Common.psm1`
`e0bf3cc40c4e41e182684de15b9f8e75209817d863a1ea1e407380553c4c6581`, `InstrumentedAgent.ps1` and
`PipeStdioRelay.ps1` unchanged. Runs before a fix that show the defect:
`tests/evidence/artifacts/g03/native-win/debug-runs/`.
