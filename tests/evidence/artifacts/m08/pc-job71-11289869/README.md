# PC job 71: the payload install self-test, at `11289869`, from two parent shells (2026-11-27)

**The cause of job 70's failure is found. It is an installer robustness defect.** The outputs
here are redacted.

| Parent shell | Result |
|---|---|
| Windows PowerShell 5.1.26100.10068 (Desktop) | `payload exit=0`, `PASS install.ps1 (fresh install and reinstall)` |
| PowerShell 7 (`pwsh`) | exit 1. The installer's stderr, which the test now captures: `<stage>\install.ps1 : The term 'Get-FileHash' is not recognized as the name of a cmdlet … CommandNotFoundException` |

**The cause, verified on the PC:**
- `pwsh` adds its `PowerShell\7\Modules` directory to `PSModulePath`.
- That value passes through `cmd` and `python` into `powershell.exe` 5.1.
- 5.1 then cannot autoload the module that provides `Get-FileHash`.
- Job 70 was launched from `pwsh`, and job 69 from 5.1. That explains both results.

**Why it matters:** a user who runs `powershell -File install.ps1` from a PowerShell 7 terminal gets
a failed install. That is common, because Windows Terminal opens `pwsh` by default.

**The fix is a W4 unit:** the installer stops depending on the inherited `PSModulePath`. The PC
rerun from both parent shells is job 72.
