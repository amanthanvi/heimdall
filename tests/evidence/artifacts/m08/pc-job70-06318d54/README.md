# PC job 70: the payload install self-test alone, under Windows PowerShell 5.1.26100, at `06318d54` (2026-11-26)

**Result: it still fails, now in a different way.** This record is the input for the next fix.
The outputs here are redacted.

    FAIL install.ps1 fresh install installer exit: expected 0, got 1
    FAIL install.ps1 fresh install home tree: unexpected path 'AppData'
    FAIL install.ps1 fresh install home tree: unexpected path 'AppData/Roaming'
    FAIL install.ps1 fresh install prefix tree: missing path 'heimdall.exe'
    FAIL install.ps1 fresh install prefix tree: missing path 'linux-x86_64'
    FAIL install.ps1 fresh install prefix tree: missing path 'linux-x86_64/heimdall'

In job 69 the installer exited 0. Here it exits 1 and installs nothing. The test did not capture
the installer's output. The next unit captures it, sanitized, and looks for the cause: the test's
new environment, or an incompatibility in the installer.

Credential Manager: 172 entries before and 172 after, none of them Heimdall's. It held 173 earlier
the same day; the one-entry drop came from outside this job.
