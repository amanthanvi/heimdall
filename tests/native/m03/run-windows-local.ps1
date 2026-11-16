#Requires -Version 7.2
<#
.SYNOPSIS
M03-U13 (m03-plan §4.1, §4.3): the Windows 11 x64 row, run on the PC by an agent. The M02
local-mode runner (tests/native/m02/run-windows-local.ps1, documented there: the clone at the exit
commit, the toolchain in scratch, the native msvc build, every test binary with its timeout, the
WSL fixture sshds with the enrollment registry, redaction, canary masking, one bundle) generalized
for M03 rather than copied: it runs with -Milestone m03 (the run directory hm-m03-local-<random> and
the read-only `w32tm /query /status` fact). The Windows interactive cases run as ordinary test
binaries on a pseudoconsole (heimdall_testkit::console; ADR-0008 §17.26 item 8).

Import on the build host:
  python3 -I tests/native/m02/import-windows-bundle.py --bundle <report> --label exit-<commit> \
      --commit <commit> --artifacts-root tests/evidence/artifacts/m03 --config <artifacts root>/runs.json
.EXAMPLE
pwsh -NoProfile -File tests/native/m03/run-windows-local.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m03
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$ScratchRoot,
    [string]$RepoUrl = 'https://github.com/amanthanvi/heimdall',
    [int]$TimeoutSeconds = 1800,
    [string]$WslDistro = '',
    [string]$ArgvDump = '',
    [string]$Label = 'windows-11-x86_64 (native msvc, local mode)',
    [switch]$SelfTest,
    [string]$Out = ''
)
$runner = Join-Path $PSScriptRoot '..\m02\run-windows-local.ps1'
& $runner @PSBoundParameters -Milestone m03
exit $LASTEXITCODE
