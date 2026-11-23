# Install or update Heimdall for the current Windows user (m08-plan U2a; ADR-0014 section 4.3).
#
# STATUS: NOT YET RUN ON WINDOWS. Its self-test (tests\native\m08\lifecycle\
# install-selftest.ps1, with fake executables) has been rehearsed under PowerShell 7 on
# macOS only, which exercises the logic and not Windows file semantics. Until a Windows run
# is recorded, nothing here is evidence.
#
# Usage, from inside the unpacked archive (Windows PowerShell 5.1 or PowerShell 7):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1                install or update
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Rollback      put the previous pair back
#   ... -Prefix <dir>          default: %LOCALAPPDATA%\Programs\Heimdall
#   ... -AssumeStopped         you have checked that no Heimdall runtime is running, and the
#                              installed executable cannot say so itself (it is broken)
# Exit code: 0 done; 1 refused or failed; 2 usage.
#
# BEFORE YOU RUN THIS: check the archive against SHA256SUMS from the Heimdall repository
# (docs\operations\install.md). This script cannot do that for you. It does check that the
# unpacked files match the archive's own MANIFEST.sha256.
#
# It needs no administrator rights, edits no PATH, profile or %USERPROFILE%\.ssh, starts
# nothing and contacts nothing.
#
# WHAT IT WILL AND WILL NOT TOUCH. It writes eight names in the prefix: heimdall.exe,
# heimdall.previous.exe, .heimdall.new.exe, .heimdall.swap.exe, and the WSL helper
# directories linux-x86_64, linux-x86_64.previous, .linux-x86_64.new, .linux-x86_64.swap.
# Before any write, each must be absent or exactly what the script expects: a regular file
# for the four executables, a real directory for the four helper directories. A directory
# where a file belongs, a file where a directory belongs, or a junction, symbolic link or
# other reparse point at any of them is REFUSED, and nothing is changed (review
# M08-W01-R01). It never deletes recursively: from a helper directory it removes only the
# files the archive's manifest names, then the directory if that left it empty; anything
# else found inside stops the script with the directory left as it is.
#
# THE PAIR. heimdall.exe and the helper in linux-x86_64 are one unit (review M08-W01-R02).
# They are replaced together, a failure part-way puts BOTH halves back, and a rerun checks
# both digests against the manifest before it says "already installed", repairing whichever
# half does not match.
#
# WINDOWS ORDER. A running executable cannot be overwritten or deleted, but it can be
# renamed, so the current pair is RENAMED aside and the staged pair renamed into place.
# Between those renames the install path holds no heimdall.exe for an instant. A failure
# there is undone. A process killed exactly there leaves the complete previous pair under
# its .previous names; running the script again finishes the update. (install.sh's single
# atomic rename is not available for a mapped image on NTFS.)
[CmdletBinding()]
param(
    [string]$Prefix = "",
    [switch]$Rollback,
    [switch]$AssumeStopped
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
function Say([string]$m) { Write-Host "install: $m" }
function Die([string]$m) { Write-Host "install: $m"; exit 1 }
function Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }

if (-not $Prefix) {
    if (-not $env:LOCALAPPDATA) { Write-Host "install: -Prefix is required (LOCALAPPDATA is not set)"; exit 2 }
    $Prefix = Join-Path (Join-Path $env:LOCALAPPDATA "Programs") "Heimdall"
}
$helperName = "linux-x86_64"
$cur = Join-Path $Prefix "heimdall.exe"
$prev = Join-Path $Prefix "heimdall.previous.exe"
$new = Join-Path $Prefix ".heimdall.new.exe"
$swap = Join-Path $Prefix ".heimdall.swap.exe"
$curH = Join-Path $Prefix $helperName
$prevH = Join-Path $Prefix "$helperName.previous"
$newH = Join-Path $Prefix ".$helperName.new"
$swapH = Join-Path $Prefix ".$helperName.swap"

# 'absent', 'file', 'dir' or 'link' (any reparse point: junction, symbolic link, mount point;
# a dangling link too). Nothing is followed.
# A path that cannot be inspected (access denied, an invalid name, any error other than
# "not there") is never treated as free: the script stops.
function Kind([string]$p) {
    try { $a = [System.IO.FileInfo]::new($p).Attributes }
    catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { return 'absent' }
    catch { Die "cannot inspect $p ($($_.Exception.GetType().Name)). Nothing was changed by this step; resolve that and run this again." }
    if ([int]$a -eq -1) { return 'absent' }
    if ($a -band [System.IO.FileAttributes]::ReparsePoint) { return 'link' }
    if ($a -band [System.IO.FileAttributes]::Directory) { return 'dir' }
    return 'file'
}
# W01-R01-BEGIN (the revert proof replaces this function's body; see install-revert-proofs.ps1)
function Assert-Names {
    $pk = Kind $Prefix
    if ($pk -ne 'absent' -and $pk -ne 'dir') { Die "$Prefix is a $pk, not a directory. Nothing was changed." }
    foreach ($p in $cur, $prev, $new, $swap) {
        $k = Kind $p
        if ($k -ne 'absent' -and $k -ne 'file') { Die "$p is a $k where this script keeps a file. It was left untouched; remove or move it yourself and run this again. Nothing was changed." }
    }
    foreach ($p in $curH, $prevH, $newH, $swapH) {
        $k = Kind $p
        if ($k -ne 'absent' -and $k -ne 'dir') { Die "$p is a $k where this script keeps a directory. It was left untouched; remove or move it yourself and run this again. Nothing was changed." }
    }
}
# W01-R01-END

# A manifest name is a relative path with '/' separators and nothing else: no empty, '.' or
# '..' segment, no backslash, no colon (so no drive and no stream), no leading '/', no
# control character. Anything else is refused when the manifest is read, before any write,
# so a name can never be joined into a path outside the archive or the prefix.
function Test-ManifestName([string]$name) {
    if (-not $name -or $name.StartsWith('/') -or $name.IndexOfAny([char[]]@('\', ':')) -ge 0) { return $false }
    foreach ($c in $name.ToCharArray()) { if ([int]$c -lt 32 -or [int]$c -eq 127) { return $false } }
    foreach ($seg in $name.Split('/')) { if ($seg -eq '' -or $seg -eq '.' -or $seg -eq '..') { return $false } }
    return $true
}
# The path of `rel` under `dir`, walking one component at a time: every intermediate
# component must be a real directory. Returns $null when one is absent; stops the script
# when one is a link (junction, symbolic link, any reparse point) or a file, so nothing is
# ever read, checked or deleted THROUGH a link.
function Resolve-Under([string]$dir, [string]$rel) {
    $parts = $rel.Split('/'); $at = $dir
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $at = Join-Path $at $parts[$i]
        $k = Kind $at
        if ($k -eq 'absent') { return $null }
        if ($k -ne 'dir') { Die "$at is a $k inside a directory this script manages. It was left untouched; remove or move it yourself and run this again." }
    }
    return (Join-Path $at $parts[$parts.Length - 1])
}
# The files the archive's manifest names inside the helper directory (relative, with '/').
$script:helperFiles = @()
# Remove a helper directory this script owns: only the files the manifest names, then the
# directory if that left it empty. Never recursive. Anything else inside stops the script.
function Remove-OwnedHelper([string]$dir) {
    if ((Kind $dir) -eq 'absent') { return }
    foreach ($rel in $script:helperFiles) {
        $f = Resolve-Under $dir $rel
        if ($f -and (Kind $f) -eq 'file') { [System.IO.File]::Delete($f) }
    }
    # Empty subdirectories the manifest's files lived in, deepest first, non-recursively.
    $subs = $script:helperFiles | ForEach-Object { $parts = $_.Split('/'); for ($i = $parts.Length - 1; $i -ge 1; $i--) { ($parts[0..($i - 1)] -join '/') } } | Sort-Object -Unique -Descending
    foreach ($s in $subs) {
        $d = $dir
        foreach ($part in $s.Split('/')) { $d = Join-Path $d $part }
        if ((Kind $d) -eq 'dir' -and -not [System.IO.Directory]::EnumerateFileSystemEntries($d).GetEnumerator().MoveNext()) { [System.IO.Directory]::Delete($d, $false) }
    }
    if ([System.IO.Directory]::EnumerateFileSystemEntries($dir).GetEnumerator().MoveNext()) {
        Die "$dir holds something this script did not put there. It was left as it is; remove or move it yourself and run this again."
    }
    [System.IO.Directory]::Delete($dir, $false)
}

# Renames are recorded so a failure can put every one of them back, newest first. Two test
# switches: HM_INSTALL_TEST_FAIL_AT=<tag> makes that rename fail (an injected I/O error);
# HM_INSTALL_TEST_STOP_AFTER=<tag> exits right after it, as a killed process would.
$script:done = New-Object System.Collections.ArrayList
function Move-Recorded([string]$from, [string]$to, [string]$tag) {
    if ($env:HM_INSTALL_TEST_FAIL_AT -eq $tag) { throw "injected failure at $tag" }
    if ((Kind $from) -eq 'dir') { [System.IO.Directory]::Move($from, $to) } else { [System.IO.File]::Move($from, $to) }
    [void]$script:done.Add(@($from, $to))
    if ($env:HM_INSTALL_TEST_STOP_AFTER -eq $tag) { Say "stopped after $tag (test)"; exit 1 }
}
function Undo-Recorded {
    for ($i = $script:done.Count - 1; $i -ge 0; $i--) {
        $from = $script:done[$i][0]; $to = $script:done[$i][1]
        if ((Kind $to) -ne 'absent' -and (Kind $from) -eq 'absent') {
            if ((Kind $to) -eq 'dir') { [System.IO.Directory]::Move($to, $from) } else { [System.IO.File]::Move($to, $from) }
        }
    }
    $script:done.Clear()
}

# Is a runtime of the installed executable running? Three answers, and only 'none' lets an
# update proceed (the rule of install.sh):
#   none     the executable itself says "no runtime is running";
#   running  a runtime answered;
#   unknown  anything else: no output, an error, an advertisement it does not trust.
# And whatever it says, a live process started from the installed path refuses the update:
# the executable says "no runtime is running" for an unreachable endpoint too.
function Runtime-State {
    switch ($env:HM_INSTALL_TEST_STATUS) {   # the self-test has no real executable to ask
        "@none" { return 'none' } "@running" { return 'running' } "@empty" { $out = "" } "@error" { return 'unknown' }
        default {
            if ((Kind $cur) -eq 'absent') { return 'none' }
            try { $out = (& $cur --json --non-interactive service status 2>$null | Out-String) } catch { return 'unknown' }
        }
    }
    if ($out -match '"running":true') { return 'running' }
    if ($out -match '"message":"no runtime is running"') { return 'none' }
    return 'unknown'
}
function Live-FromCur {
    if ($env:HM_INSTALL_TEST_LIVE) { return @([int]$env:HM_INSTALL_TEST_LIVE) }
    $ids = @()
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        try { if ($p.Path -and ($p.Path -ieq $cur) -and $p.Id -ne $PID) { $ids += $p.Id } } catch { }
    }
    return $ids
}
function Require-Stopped {
    $live = @(Live-FromCur)
    if ($live.Count -gt 0) {
        Say "a process started from $cur is running (pid $($live -join ' ')). Stop it first: heimdall service stop"
        Die "(-AssumeStopped does not override this: the process is there). Nothing was changed."
    }
    if ($AssumeStopped) { Say "-AssumeStopped: not asking the installed executable whether a runtime is running"; return }
    switch (Runtime-State) {
        'none' { return }
        'running' {
            Say "a Heimdall runtime is running. Stop it first: heimdall service stop"
            Say "stopping interrupts new connections until it starts again; open sessions keep running"
            Die "(docs\operations\update-and-rollback.md lists what else). Nothing was changed."
        }
        default {
            Say "cannot tell whether a Heimdall runtime is running: the installed executable did not answer"
            Say "'no runtime is running'. Run: heimdall service status  and  heimdall service stop"
            Die "If no heimdall process is running (check Task Manager), run this again with -AssumeStopped. Nothing was changed."
        }
    }
}

# An interrupted rollback is recognized by its spare names and settled as a unit, in the
# direction the executable shows: if the install path has no heimdall.exe, the rollback had
# not put the previous one in place, and both halves are put back as they were; otherwise it
# had, and both halves are finished.
function Settle-InterruptedRollback {
    $se = (Kind $swap) -ne 'absent'; $sh = (Kind $swapH) -ne 'absent'
    if (-not $se -and -not $sh) { return }
    if ($se -and (Kind $cur) -eq 'absent') {
        [System.IO.File]::Move($swap, $cur)
        if ($sh -and (Kind $curH) -eq 'absent') { [System.IO.Directory]::Move($swapH, $curH) }
        elseif ($sh) { Die "an interrupted rollback left $swapH beside $curH; move one of them yourself and run this again." }
        Say "undid an interrupted rollback: the pair it was replacing is back in place"
        return
    }
    # The executable half was replaced (or finished): finish both halves.
    if ($sh) {
        if ((Kind $curH) -eq 'absent' -and (Kind $prevH) -ne 'absent') { [System.IO.Directory]::Move($prevH, $curH) }
        if ((Kind $prevH) -ne 'absent') { Die "an interrupted rollback left $swapH, $curH and $prevH; move one of them yourself and run this again." }
        [System.IO.Directory]::Move($swapH, $prevH)
    }
    if ($se) {
        if ((Kind $prev) -ne 'absent') { Die "an interrupted rollback left $swap, $cur and $prev; move one of them yourself and run this again." }
        [System.IO.File]::Move($swap, $prev)
    }
    Say "finished an interrupted rollback: the pair it replaced is kept under the .previous names"
}

Assert-Names
if ((Kind $Prefix) -eq 'absent') { [void][System.IO.Directory]::CreateDirectory($Prefix) }

if ($Rollback) {
    Settle-InterruptedRollback
    if ((Kind $prev) -ne 'file') { Die "there is no previous executable at $prev" }
    Require-Stopped
    try {
        if ((Kind $cur) -ne 'absent') { Move-Recorded $cur $swap "ra1" }
        if ((Kind $curH) -ne 'absent') { Move-Recorded $curH $swapH "ra2" }
        Move-Recorded $prev $cur "rb1"
        if ((Kind $prevH) -ne 'absent') { Move-Recorded $prevH $curH "rb2" }
        if ((Kind $swap) -ne 'absent') { Move-Recorded $swap $prev "rc1" }
        if ((Kind $swapH) -ne 'absent') { Move-Recorded $swapH $prevH "rc2" }
    } catch {
        $why = $_.Exception.Message
        Undo-Recorded
        Die "the rollback failed and every step of it was undone, executable and helper together: $why"
    }
    Say "the previous pair is back at $cur; the pair it replaced is now under the .previous names"
    Say "if it reports that the state is newer than it understands, see docs\operations\recovery.md"
    exit 0
}

# 0. The unpacked tree must match its own manifest (every line).
$manifest = Join-Path $here "MANIFEST.sha256"
if ((Kind $manifest) -ne 'file') { Die "MANIFEST.sha256 is missing: this is not a complete archive" }
$srcExe = Join-Path $here "heimdall.exe"
if ((Kind $srcExe) -ne 'file') { Die "the archive holds no heimdall.exe" }
$wantExe = $null
$wantHelper = @{}
foreach ($line in [System.IO.File]::ReadAllLines($manifest)) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { Die "MANIFEST.sha256 has a malformed line" }
    $want = $Matches[1]; $name = $Matches[2]
    if (-not (Test-ManifestName $name)) { Die "MANIFEST.sha256 names a path this script will not use (it must be a plain relative path). Nothing was changed." }
    $file = $here
    foreach ($part in $name.Split('/')) { $file = Join-Path $file $part }
    if ((Kind $file) -ne 'file') { Die "the archive is incomplete: $name is missing" }
    if ((Sha $file) -ne $want) { Die "the archive is damaged: $name does not match MANIFEST.sha256" }
    if ($name -eq "heimdall.exe") { $wantExe = $want }
    if ($name.StartsWith("$helperName/")) { $wantHelper[$name.Substring($helperName.Length + 1)] = $want }
}
if (-not $wantExe) { Die "MANIFEST.sha256 does not list the executable" }
$script:helperFiles = @($wantHelper.Keys | Sort-Object)

Settle-InterruptedRollback
# Leftovers of an interrupted install: a staged file is removed as a file; a staged helper
# directory only through Remove-OwnedHelper.
if ((Kind $new) -eq 'file') { [System.IO.File]::Delete($new); Say "removed a leftover staged file from an interrupted run" }
Remove-OwnedHelper $newH

function Exe-Ok { return ((Kind $cur) -eq 'file') -and ((Sha $cur) -eq $wantExe) }
function Helper-Ok {
    if ($wantHelper.Count -eq 0) { return ((Kind $curH) -eq 'absent') }
    if ((Kind $curH) -ne 'dir') { return $false }
    foreach ($rel in $wantHelper.Keys) {
        $f = Resolve-Under $curH $rel
        if (-not $f -or (Kind $f) -ne 'file' -or (Sha $f) -ne $wantHelper[$rel]) { return $false }
    }
    return $true
}
# W01-R02-BEGIN (the revert proof replaces the pair check with the executable alone)
$exeOk = Exe-Ok
$helperOk = Helper-Ok
# W01-R02-END
if ($exeOk -and $helperOk) { Say "this version is already installed at $cur"; exit 0 }
if ($exeOk -and -not $helperOk) { Say "the executable is this version but its helper is missing or different: repairing the pair" }
if (-not $exeOk -and $helperOk -and (Kind $cur) -ne 'absent') { Say "the helper is this version but the executable is not: repairing the pair" }
Require-Stopped

try {
    # 1. Stage whichever half is not already this version, beside the old one.
    if (-not $exeOk) { [System.IO.File]::Copy($srcExe, $new) }
    if (-not $helperOk -and $wantHelper.Count -gt 0) {
        [void][System.IO.Directory]::CreateDirectory($newH)
        foreach ($rel in $wantHelper.Keys) {
            $src = Join-Path $here $helperName; $dst = $newH
            foreach ($part in $rel.Split('/')) { $src = Join-Path $src $part; $dst = Join-Path $dst $part }
            [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $dst))
            [System.IO.File]::Copy($src, $dst)
        }
    }
    if ($env:HM_INSTALL_TEST_STOP_AFTER -eq "1") { Say "stopped after 1 (test)"; exit 1 }
    # 2. Check the staged copies.
    if (-not $exeOk -and (Sha $new) -ne $wantExe) { throw "the staged executable does not match the manifest" }
    if ($env:HM_INSTALL_TEST_STOP_AFTER -eq "2") { Say "stopped after 2 (test)"; exit 1 }
    # 3. Rename the current halves aside (a running image can be renamed, not overwritten).
    #    The older .previous copies are discarded first: they are about to be replaced.
    if (-not $exeOk -and (Kind $cur) -ne 'absent') {
        if ((Kind $prev) -eq 'file') { [System.IO.File]::Delete($prev) }
        Move-Recorded $cur $prev "3a"
    }
    if (-not $helperOk -and (Kind $curH) -ne 'absent') {
        Remove-OwnedHelper $prevH
        Move-Recorded $curH $prevH "3b"
    }
    # 4. Put the staged halves in place.
    if (-not $exeOk) { Move-Recorded $new $cur "4a" }
    if (-not $helperOk -and $wantHelper.Count -gt 0) { Move-Recorded $newH $curH "4b" }
} catch {
    $why = $_.Exception.Message
    Undo-Recorded
    if ((Kind $new) -eq 'file') { [System.IO.File]::Delete($new) }
    Remove-OwnedHelper $newH
    Die "the update failed and was undone, executable and helper together (an older .previous copy, if there was one, had already been discarded): $why"
}

Say "installed $cur"
if ((Kind $prev) -eq 'file') { Say "the previous pair is kept under the .previous names (install.ps1 -Rollback puts it back)" }
if (-not (($env:PATH -split [System.IO.Path]::PathSeparator) -contains $Prefix)) {
    Say "to run it as 'heimdall', add this directory to your PATH yourself: $Prefix"
}
Say "next: heimdall setup    (it shows every change to your SSH configuration and asks first)"
