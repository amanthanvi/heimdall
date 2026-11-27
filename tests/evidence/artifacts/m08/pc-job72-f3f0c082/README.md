# PC job 72: the payload install self-test from both parent shells, at `f3f0c082` (2026-11-27)

**The installer defect that jobs 70 and 71 found is closed.** The outputs here are redacted.

**Environment:**
- Windows PowerShell 5.1.26100.10068 (Desktop);
- `pwsh` 7.6.10 (Core);
- Python 3.13.15, 64-bit.

| Parent shell | Exit | Result |
|---|---|---|
| Windows PowerShell 5.1 | 0 | `PASS install.ps1 [clean PSModulePath] (fresh install and reinstall)`; `PASS install.ps1 [pwsh-like PSModulePath] (fresh install and reinstall)` |
| PowerShell 7 (`pwsh`), the case that failed in jobs 70 and 71 | 0 | the same two PASS lines |

**The fix** (`792410b5`): on the Desktop edition, `install.ps1` sets `PSModulePath` to `$PSHOME\Modules`
for its own run and imports the bundled modules. In a `finally` block it restores the inherited
value.

Credential Manager: 173 entries before and 173 after, none of them Heimdall's.
