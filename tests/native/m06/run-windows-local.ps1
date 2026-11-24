#Requires -Version 7.2
<#
.SYNOPSIS
M06-U7 (m06-plan §1 U7, §3): the Windows 11 x64 row ("a controller"), run on the PC by an agent.
The M02 local-mode runner (tests/native/m02/run-windows-local.ps1, documented there: the clone at
the exit commit, the toolchain in scratch, the native msvc build, every test binary with its
timeout, the WSL fixture sshds with the enrollment registry, redaction, canary masking, one
bundle) generalized for M06 as M05's wrapper is: it runs with -Milestone m06 (the run directory
hm-m06-local-<random>) and -Feature iroh, so the test targets with required-features = ["iroh"]
(for example integration_transport_supervise_m06 and e2e_exit_m06_iroh) are built natively and
run with the rest, against that build's own heimdall.exe. -FeatureUnit heimdall-transport-iroh also builds
that crate's own unit tests with the feature (they exist almost only under it) and runs them as
heimdall_transport_iroh-unit in place of the default-feature build's. A package whose iroh build fails is
recorded per target as blocked with cargo's exit code and first error (host.txt
`feature-blocked-<target>`, skipped.txt), never as passed or skipped, and the run exits 6 when
nothing else failed.

The Windows controller journey (ADR-0012 §2.6; m06-plan §3 "Windows controller rows": a Windows
controller driving a fixture Linux runner in one scratch directory of the existing WSL distribution, -WslDistro, through the product CLI)
is this directory's run-windows-controller.ps1, a scenario of its own (platform windows-controller
in runs.json; it needs the debug heimdall.exe and the e2e_windows_controller_m06 test executable of
the same commit, and their Linux builds).

Nothing here binds a non-loopback address; the rows of m06-plan §7 that need the owner at the
console (W4, a firewall prompt) are not this runner's.

Import on the build host:
  python3 -I tests/native/m02/import-windows-bundle.py --bundle <report> --label exit-<commit> \
      --commit <commit> --artifacts-root tests/evidence/artifacts/m06 --config <artifacts root>/runs.json
.EXAMPLE
pwsh -NoProfile -File tests/native/m06/run-windows-local.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m06
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
& $runner @PSBoundParameters -Milestone m06 -Feature iroh -FeatureUnit heimdall-transport-iroh
exit $LASTEXITCODE
