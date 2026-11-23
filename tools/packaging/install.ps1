# Install or update Heimdall for the current Windows user (m08-plan U2a; ADR-0014 section 4.3).
#
# STATUS: written from install.sh and NOT YET RUN on Windows. Its self-test
# (tests\native\m08\lifecycle\install-selftest.ps1, with a fake executable) runs on the PC in
# a later job; until that run is recorded, nothing here is evidence.
#
# Usage, from inside the unpacked archive (PowerShell 5.1 or 7):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1               install or update
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Rollback     put the previous one back
#   ... -Prefix <dir>                                                    default: %LOCALAPPDATA%\Programs\Heimdall
# Exit code: 0 done; 1 refused or failed; 2 usage.
#
# BEFORE YOU RUN THIS: check the archive against SHA256SUMS from the Heimdall repository
# (docs\operations\install.md). This script cannot do that for you. It does check that the
# unpacked files match the archive's own MANIFEST.sha256.
#
# It needs no administrator rights, edits no PATH, profile or %USERPROFILE%\.ssh, starts
# nothing and contacts nothing.
#
# The Windows rules differ from install.sh in one way. A running executable cannot be
# overwritten or deleted, but it CAN be renamed. So:
#   1. the new executable and the Linux WSL helper are copied to temporary names and checked;
#   2. the current executable is RENAMED aside to heimdall.previous.exe (not copied), and the
#      current helper directory to linux-x86_64.previous;
#   3. the staged files are renamed into place.
# Between steps 2 and 3 the install path has no heimdall.exe for an instant. The script
# closes that gap on failure: if step 3 fails, it renames the previous files back, so a
# failed update leaves the old pair in place. A process killed exactly between the two
# renames leaves heimdall.previous.exe complete and heimdall.exe absent; running the script
# again finishes the update, and it says which state it found. (NTFS has no rename that
# replaces a file whose image is mapped, which is why install.sh's single atomic rename is
# not available here.)
# The executable and its helper are replaced as a pair and never left at different versions
# without the script saying so.
[CmdletBinding()]
param(
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA "Programs\Heimdall"),
    [switch]$Rollback
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
function Say([string]$m) { Write-Host "install: $m" }
function Die([string]$m) { Write-Host "install: $m"; exit 1 }
function Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }
function StepDone([int]$n) { if ($env:HM_INSTALL_TEST_STOP_AFTER -eq "$n") { Say "stopped after step $n (test)"; exit 1 } }

$cur = Join-Path $Prefix "heimdall.exe"
$prev = Join-Path $Prefix "heimdall.previous.exe"
$new = Join-Path $Prefix ".heimdall.new.exe"
$helperDirName = "linux-x86_64"
$curHelper = Join-Path $Prefix $helperDirName
$prevHelper = Join-Path $Prefix "$helperDirName.previous"
$newHelper = Join-Path $Prefix ".$helperDirName.new"

function Running {
    # The self-test has no real executable to ask, so it states the answer (as it states
    # where to stop with HM_INSTALL_TEST_STOP_AFTER).
    if ($env:HM_INSTALL_TEST_RUNNING -eq "1") { return $true }
    if ($env:HM_INSTALL_TEST_RUNNING -eq "0") { return $false }
    if (-not (Test-Path -LiteralPath $cur)) { return $false }
    try { $out = & $cur --json --non-interactive service status 2>$null } catch { return $false }
    return ($out -match '"running":true')
}

if ($Rollback) {
    if (-not (Test-Path -LiteralPath $prev)) { Die "there is no previous executable at $prev" }
    if (Running) { Die "a Heimdall runtime is running; stop it first: heimdall service stop" }
    $swap = Join-Path $Prefix ".heimdall.swap.exe"
    $swapHelper = Join-Path $Prefix ".$helperDirName.swap"
    foreach ($p in $swap, $swapHelper) { if (Test-Path -LiteralPath $p) { Remove-Item -Recurse -Force -LiteralPath $p } }
    if (Test-Path -LiteralPath $cur) { Rename-Item -LiteralPath $cur -NewName (Split-Path $swap -Leaf) }
    if (Test-Path -LiteralPath $curHelper) { Rename-Item -LiteralPath $curHelper -NewName (Split-Path $swapHelper -Leaf) }
    try {
        Rename-Item -LiteralPath $prev -NewName (Split-Path $cur -Leaf)
        if (Test-Path -LiteralPath $prevHelper) { Rename-Item -LiteralPath $prevHelper -NewName $helperDirName }
    } catch {
        if ((Test-Path -LiteralPath $swap) -and -not (Test-Path -LiteralPath $cur)) { Rename-Item -LiteralPath $swap -NewName (Split-Path $cur -Leaf) }
        if ((Test-Path -LiteralPath $swapHelper) -and -not (Test-Path -LiteralPath $curHelper)) { Rename-Item -LiteralPath $swapHelper -NewName $helperDirName }
        Die "the rollback failed and was undone: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $swap) { Rename-Item -LiteralPath $swap -NewName (Split-Path $prev -Leaf) }
    if (Test-Path -LiteralPath $swapHelper) { Rename-Item -LiteralPath $swapHelper -NewName "$helperDirName.previous" }
    Say "the previous executable is back at $cur; the one it replaced is now $prev"
    Say "if it reports that the state is newer than it understands, see docs\operations\recovery.md"
    exit 0
}

# 0. The unpacked tree must match its own manifest.
$manifest = Join-Path $here "MANIFEST.sha256"
if (-not (Test-Path -LiteralPath $manifest)) { Die "MANIFEST.sha256 is missing: this is not a complete archive" }
$srcExe = Join-Path $here "heimdall.exe"
if (-not (Test-Path -LiteralPath $srcExe)) { Die "the archive holds no heimdall.exe" }
$wantExe = $null
foreach ($line in Get-Content -LiteralPath $manifest) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { Die "MANIFEST.sha256 has a malformed line" }
    $want = $Matches[1]; $name = $Matches[2]
    $file = Join-Path $here ($name -replace '/', '\')
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Die "the archive is incomplete: $name is missing" }
    if ((Sha $file) -ne $want) { Die "the archive is damaged: $name does not match MANIFEST.sha256" }
    if ($name -eq "heimdall.exe") { $wantExe = $want }
}
if (-not $wantExe) { Die "MANIFEST.sha256 does not list the executable" }
$srcHelper = Join-Path $here $helperDirName

New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
# Recover from an earlier interruption before deciding anything.
foreach ($p in $new, $newHelper) { if (Test-Path -LiteralPath $p) { Remove-Item -Recurse -Force -LiteralPath $p; Say "removed a leftover staged file from an interrupted run" } }
if (-not (Test-Path -LiteralPath $cur) -and (Test-Path -LiteralPath $prev)) {
    Say "an earlier run stopped between its two renames: $prev is complete, $cur is absent; continuing"
}
if ((Test-Path -LiteralPath $cur) -and ((Sha $cur) -eq $wantExe)) { Say "this version is already installed at $cur"; exit 0 }
if (Running) {
    Say "a Heimdall runtime is running. Stop it first: heimdall service stop"
    Say "stopping interrupts new connections until it starts again; open sessions keep running"
    Die "(docs\operations\update-and-rollback.md lists what else). Nothing was changed."
}

# 1. Stage the new executable and the helper beside the old ones.
Copy-Item -LiteralPath $srcExe -Destination $new
if (Test-Path -LiteralPath $srcHelper) { Copy-Item -Recurse -LiteralPath $srcHelper -Destination $newHelper }
StepDone 1
# 2. Check the staged executable.
if ((Sha $new) -ne $wantExe) { Remove-Item -Force -LiteralPath $new; Die "the staged copy does not match the manifest; nothing was changed" }
StepDone 2
# 3. Rename the current pair aside. A running image can be renamed, not overwritten.
$hadCur = Test-Path -LiteralPath $cur
$hadHelper = Test-Path -LiteralPath $curHelper
try {
    if ($hadCur) {
        if (Test-Path -LiteralPath $prev) { Remove-Item -Force -LiteralPath $prev }
        Rename-Item -LiteralPath $cur -NewName (Split-Path $prev -Leaf)
    }
    if ($hadHelper) {
        if (Test-Path -LiteralPath $prevHelper) { Remove-Item -Recurse -Force -LiteralPath $prevHelper }
        Rename-Item -LiteralPath $curHelper -NewName "$helperDirName.previous"
    }
} catch {
    # Undo a half-done step 3 so the old pair is whole again.
    if ($hadCur -and -not (Test-Path -LiteralPath $cur) -and (Test-Path -LiteralPath $prev)) { Rename-Item -LiteralPath $prev -NewName (Split-Path $cur -Leaf) }
    Die "could not move the current executable aside (is a heimdall process still running from it?): $($_.Exception.Message). Nothing was changed."
}
StepDone 3
# 4. Put the new pair in place; on failure, put the old pair back.
try {
    Rename-Item -LiteralPath $new -NewName (Split-Path $cur -Leaf)
    if (Test-Path -LiteralPath $newHelper) { Rename-Item -LiteralPath $newHelper -NewName $helperDirName }
} catch {
    if (-not (Test-Path -LiteralPath $cur) -and (Test-Path -LiteralPath $prev)) { Rename-Item -LiteralPath $prev -NewName (Split-Path $cur -Leaf) }
    if (-not (Test-Path -LiteralPath $curHelper) -and (Test-Path -LiteralPath $prevHelper)) { Rename-Item -LiteralPath $prevHelper -NewName $helperDirName }
    Die "could not put the new executable in place; the previous one was put back: $($_.Exception.Message)"
}
StepDone 4

Say "installed $cur"
if (Test-Path -LiteralPath $prev) { Say "the previous executable is kept as $prev (.\install.ps1 -Rollback puts it back)" }
if (-not (($env:PATH -split ';') -contains $Prefix)) {
    Say "to run it as 'heimdall', add this directory to your PATH yourself: $Prefix"
}
Say "next: heimdall setup    (it shows every change to your SSH configuration and asks first)"
