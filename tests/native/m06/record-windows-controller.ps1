#Requires -Version 7.2
<#
.SYNOPSIS
M06 exit (RESEARCH §0 items 1 and 5): run the Windows controller journey
(tests/native/m06/run-windows-controller.ps1, unchanged) and record, beside its own output, the
journey process's real exit code and the identity of what it ran.

.DESCRIPTION
Runs ON the PC, not elevated, from a checkout of the exit commit, with exactly the journey's
inputs. It starts the journey as a child process (`pwsh -NoProfile -NonInteractive -File
run-windows-controller.ps1 ...` with the same arguments), passes its output through, and then
writes into -Out:
  commands.txt  one line, `exit <code>: <command>`, the code being the child's real exit status
                ($LASTEXITCODE), so the evidence generator reads the run's own code and never a
                value typed into the run configuration (m06-evidence.py refuses an exit_codes map
                on this platform). The command text names no path, account or distribution;
  build.txt     `commit=<40 hex>` (git rev-parse HEAD of the checkout this script is in) and
                `<name> sha256: <hex>` for the four input binaries and the journey script.
-Out must be absent or empty, so a recorded code never sits beside another run's tests.txt. The
journey writes tests.txt and host.txt (and ssh-stderr.txt) there itself; a blocked journey (exit
3) writes neither, and commands.txt then records the 3.

Bring -Out back to the build host and import it there with
  python3 -I tests/native/m06/import-windows-controller.py --from <copy> --artifacts-dir $A --commit <40hex> --config $A/runs.json
which scans it (canaries, SIDs, home paths, non-loopback addresses) before anything is written.

Exit: the journey's exit code; 2 when -Out is not empty or a required argument is missing (the
journey is then not started and nothing is written).

.PARAMETER SelfTest
The helpers on synthetic data; nothing is started. Runs anywhere.

.EXAMPLE
pwsh -NoProfile -File tests\native\m06\record-windows-controller.ps1 -ScratchRoot C:\hm `
    -HeimdallExe C:\hm\b\heimdall.exe -DriverExe C:\hm\b\e2e_windows_controller_m06.exe `
    -LinuxHeimdall C:\hm\l\heimdall -LinuxDriver C:\hm\l\e2e_windows_controller_m06 `
    -WslDistro <the existing distribution> -Out C:\hm\out
#>
[CmdletBinding()]
param(
    [string]$ScratchRoot,
    [string]$HeimdallExe,
    [string]$DriverExe,
    [string]$LinuxHeimdall,
    [string]$LinuxDriver,
    [string]$WslDistro,
    [string]$Out,
    [switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The command text of commands.txt; import-windows-controller.py COMMAND is the same string.
$Command = 'pwsh -NoProfile -File tests/native/m06/run-windows-controller.ps1 (the Windows controller journey, through record-windows-controller.ps1)'
$Journey = Join-Path $PSScriptRoot 'run-windows-controller.ps1'

function Format-CommandsLine([int]$Code) { return "exit ${Code}: $Command`n" }

function Get-Sha256([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# build.txt: the commit and one sha256 line per input that exists (a missing input is the
# journey's exit 3; the importer refuses a build.txt without all five lines).
function Format-BuildText([string]$Commit, [System.Collections.Specialized.OrderedDictionary]$Inputs) {
    $s = [System.Text.StringBuilder]::new()
    if ($Commit -cmatch '^[0-9a-f]{40}$') { [void]$s.Append("commit=$Commit`n") } else { [void]$s.Append("commit=unknown`n") }
    foreach ($name in $Inputs.Keys) {
        $h = Get-Sha256 ([string]$Inputs[$name])
        if ($h) { [void]$s.Append("$name sha256: $h`n") } else { [void]$s.Append("$name absent`n") }
    }
    return $s.ToString()
}

function Test-OutEmpty([string]$Dir) {
    if (-not (Test-Path -LiteralPath $Dir)) { return $true }
    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return $false }
    return @(Get-ChildItem -LiteralPath $Dir -Force).Count -eq 0
}

if ($SelfTest) {
    $pass = 0; $fail = 0
    function Check([string]$Name, [bool]$Ok) {
        if ($Ok) { Write-Output "ok   $Name"; $script:pass++ } else { Write-Output "FAIL $Name"; $script:fail++ }
    }
    $line = Format-CommandsLine 1
    Check 'R01 commands.txt is one generator line with the real code and a path-free command' (
        $line -ceq "exit 1: $Command`n" -and $line -cmatch '^exit -?\d+: .+\n$' -and -not ($line -match '[A-Za-z]:\\|/Users/|/home/'))
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hm-rwc-" + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tmp)
    try {
        $f = Join-Path $tmp 'a'
        [System.IO.File]::WriteAllText($f, 'abc')
        Check 'R02 sha256 of a file is lowercase hex' ((Get-Sha256 $f) -ceq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        $in = [ordered]@{ 'heimdall.exe' = $f; 'run-windows-controller.ps1' = (Join-Path $tmp 'absent') }
        $b = Format-BuildText ('0' * 40) $in
        Check 'R03 build.txt has the commit, a sha256 per input and no path' (
            $b -ceq "commit=$('0' * 40)`nheimdall.exe sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`nrun-windows-controller.ps1 absent`n" -and -not $b.Contains($tmp))
        Check 'R04 a malformed commit is recorded as unknown' ((Format-BuildText 'HEAD' ([ordered]@{})) -ceq "commit=unknown`n")
        Check 'R05 -Out must be absent or empty' ((Test-OutEmpty (Join-Path $tmp 'none')) -and -not (Test-OutEmpty $tmp) -and -not (Test-OutEmpty $f))
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    Write-Output "record-windows-controller selftest: $pass passed, $fail failed"
    exit $(if ($fail -eq 0) { 0 } else { 1 })
}

if (-not $Out) { Write-Output 'refused: -Out is required'; exit 2 }
if (-not (Test-OutEmpty $Out)) { Write-Output 'refused: -Out exists and is not empty (a recorded code never sits beside another run)'; exit 2 }
$commit = ''
try { $commit = (& git -C $PSScriptRoot rev-parse HEAD 2>$null | Select-Object -First 1) } catch { $commit = '' }
$inputs = [ordered]@{
    'heimdall.exe'                                = $HeimdallExe
    'e2e_windows_controller_m06.exe'              = $DriverExe
    'heimdall (linux x86_64)'                     = $LinuxHeimdall
    'e2e_windows_controller_m06 (linux x86_64)'   = $LinuxDriver
    'run-windows-controller.ps1'                  = $Journey
}
$commitText = "$commit".Trim()
$build = Format-BuildText $commitText $inputs
$journeyArgs = @('-NoProfile', '-NonInteractive', '-File', $Journey, '-Out', $Out)
foreach ($p in @('ScratchRoot', 'HeimdallExe', 'DriverExe', 'LinuxHeimdall', 'LinuxDriver', 'WslDistro')) {
    $v = Get-Variable -Name $p -ValueOnly
    if ($v) { $journeyArgs += @("-$p", $v) }
}
& pwsh @journeyArgs
$code = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
[void](New-Item -ItemType Directory -Path $Out -Force)
[System.IO.File]::WriteAllText((Join-Path $Out 'commands.txt'), (Format-CommandsLine $code))
[System.IO.File]::WriteAllText((Join-Path $Out 'build.txt'), $build)
Write-Output "### recorded exit=$code"
exit $code
