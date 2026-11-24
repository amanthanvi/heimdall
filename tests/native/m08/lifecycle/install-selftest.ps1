# Self-test of tools\packaging\install.ps1 with fake archives (m08-plan U2a). The Windows
# counterpart of install-selftest.sh.
#
# STATUS: run on the Windows PC under Windows PowerShell 5.1 and PowerShell 7 (jobs 31, 32
# and 43; 60 checks at job 43). A run under PowerShell 7 on macOS rehearses the logic only
# and is not evidence for Windows.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\native\m08\lifecycle\install-selftest.ps1
#   $env:HM_INSTALL_UNDER_TEST = <file>   test that copy of install.ps1 (for a revert proof)
# Exit code: 0 when every case passes; 1 otherwise.
#
# No Heimdall executable is used or run. The "executables" are files with fixed bytes, never
# started: HM_INSTALL_TEST_STATUS tells install.ps1 what a runtime query would have answered.
# Everything lives in one new directory under the temporary directory, removed at the end by
# its exact path.
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot (Join-Path ".." (Join-Path ".." (Join-Path ".." ".."))))).Path
$sut = if ($env:HM_INSTALL_UNDER_TEST) { $env:HM_INSTALL_UNDER_TEST } else { Join-Path (Join-Path (Join-Path $repo "tools") "packaging") "install.ps1" }
$T = Join-Path ([System.IO.Path]::GetTempPath()) ("hm-install-selftest-" + [System.Guid]::NewGuid().ToString("N"))
[void][System.IO.Directory]::CreateDirectory($T)
$script:failed = 0
$script:n = 0
# The same PowerShell that runs this file runs install.ps1 (Windows PowerShell 5.1 or PowerShell 7).
$script:ps = (Get-Process -Id $PID).Path
$script:last = ""
function Check([string]$name, [bool]$ok) {
    $script:n++
    if ($ok) { Write-Host "ok   $name" } else {
        Write-Host "FAIL $name"; $script:failed = 1
        # The installer's last output (fake file names and fixed strings only), to diagnose.
        ($script:last -split "`n") | Where-Object { $_.Trim() } | Select-Object -Last 6 | ForEach-Object { Write-Host "       | $($_.Trim())" }
    }
}
function Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }
function Text([string]$p) { if ([System.IO.File]::Exists($p)) { [System.IO.File]::ReadAllText($p) } else { "" } }
function P([string]$base, [string[]]$parts) { foreach ($x in $parts) { $base = Join-Path $base $x }; $base }
function Exe([string]$prefix) { Text (P $prefix @("heimdall.exe")) }
function PrevExe([string]$prefix) { Text (P $prefix @("heimdall.previous.exe")) }
function Helper([string]$prefix) { Text (P $prefix @("linux-x86_64", "heimdall")) }
function PrevHelper([string]$prefix) { Text (P $prefix @("linux-x86_64.previous", "heimdall")) }
function Pair([string]$prefix) { "$(Exe $prefix)|$(Helper $prefix)" }
function PrevPair([string]$prefix) { "$(PrevExe $prefix)|$(PrevHelper $prefix)" }
function V([string]$v) { "fake heimdall $v|fake helper $v" }

function Archive([string]$name, [string]$version, [bool]$deep = $false, [string]$helperVersion = "") {
    if (-not $helperVersion) { $helperVersion = $version }
    $d = Join-Path $T $name
    [void][System.IO.Directory]::CreateDirectory((Join-Path $d "linux-x86_64"))
    $names = @("README", "heimdall.exe", "install.ps1", "linux-x86_64/heimdall")
    if ($deep) {   # a helper with a file in a subdirectory
        [void][System.IO.Directory]::CreateDirectory((P $d @("linux-x86_64", "sub")))
        [System.IO.File]::WriteAllText((P $d @("linux-x86_64", "sub", "tool")), "fake tool $version")
        $names += "linux-x86_64/sub/tool"
    }
    [System.IO.File]::WriteAllText((Join-Path $d "heimdall.exe"), "fake heimdall $version")
    [System.IO.File]::WriteAllText((P $d @("linux-x86_64", "heimdall")), "fake helper $helperVersion")
    [System.IO.File]::WriteAllText((Join-Path $d "README"), "notes for $version")
    Copy-Item -LiteralPath $sut -Destination (Join-Path $d "install.ps1")
    $lines = foreach ($f in $names) { "{0}  {1}" -f (Sha (P $d $f.Split('/'))), $f }
    [System.IO.File]::WriteAllText((Join-Path $d "MANIFEST.sha256"), (($lines -join "`n") + "`n"))
    return $d
}
# Every file under a prefix with its digest, sorted: "nothing changed" is this, unchanged.
function Snapshot([string]$prefix) {
    (Get-ChildItem -LiteralPath $prefix -Recurse -Force -File | ForEach-Object { "$($_.FullName.Substring($prefix.Length))=$(Sha $_.FullName)" } | Sort-Object) -join ";"
}
function Install([string]$archive, [string]$prefix, [string[]]$more = @(), [hashtable]$envs = @{}) {
    # Set the case's variables for this one run, then put back whatever was there before.
    $saved = @{}
    foreach ($k in $envs.Keys) { $saved[$k] = [System.Environment]::GetEnvironmentVariable($k); Set-Item -Path "Env:$k" -Value $envs[$k] }
    try { $out = & $script:ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $archive "install.ps1") -Prefix $prefix @more 2>&1 | Out-String; $code = $LASTEXITCODE }
    finally { foreach ($k in $envs.Keys) { if ($null -eq $saved[$k]) { Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue } else { Set-Item -Path "Env:$k" -Value $saved[$k] } } }
    $script:last = $out
    return @{ Code = $code; Out = $out }
}
function Link([string]$at, [string]$target) {
    # A junction on Windows (no privilege needed); a symbolic link elsewhere.
    if ($IsWindows -or $env:OS -eq "Windows_NT") { [void](New-Item -ItemType Junction -Path $at -Target $target) }
    else { [void](New-Item -ItemType SymbolicLink -Path $at -Target $target) }
}

try {
    $a1 = Archive "a1" "1.0.0"; $a2 = Archive "a2" "2.0.0"; $a3 = Archive "a3" "3.0.0"
    $env:HM_INSTALL_TEST_STATUS = "@none"
    $P = Join-Path $T "prefix"

    $r = Install $a1 $P
    Check "a fresh install puts the executable and the helper in place" (($r.Code -eq 0) -and ((Pair $P) -eq (V "1.0.0")) -and ((PrevExe $P) -eq ""))
    Check "it names the directory to add to PATH and edits nothing" ($r.Out -match "add this directory to your PATH yourself")
    $r = Install $a1 $P
    Check "installing the same version again changes nothing" (($r.Out -match "already installed") -and ((PrevExe $P) -eq ""))
    $r = Install $a2 $P
    Check "an update keeps the previous executable and helper, as a pair" (((Pair $P) -eq (V "2.0.0")) -and ((PrevPair $P) -eq (V "1.0.0")))
    $r = Install $a2 $P @("-Rollback")
    Check "a rollback swaps both pairs" (($r.Code -eq 0) -and ((Pair $P) -eq (V "1.0.0")) -and ((PrevPair $P) -eq (V "2.0.0")))

    # A damaged and an incomplete tree are refused; nothing changes.
    $damaged = Join-Path $T "damaged"; Copy-Item -Recurse -LiteralPath $a2 -Destination $damaged; [System.IO.File]::AppendAllText((Join-Path $damaged "heimdall.exe"), "tampered")
    $before = Pair $P
    $r = Install $damaged $P
    Check "a damaged tree is refused (exit 1) and nothing changes" (($r.Code -eq 1) -and ($r.Out -match "does not match MANIFEST") -and ((Pair $P) -eq $before))
    $short = Join-Path $T "short"; Copy-Item -Recurse -LiteralPath $a2 -Destination $short; [System.IO.File]::Delete((Join-Path $short "README"))
    $r = Install $short $P
    Check "an incomplete tree is refused" (($r.Code -eq 1) -and ($r.Out -match "incomplete"))

    # --- M08-W01-R03: the three-state runtime guard.
    $Q = Join-Path $T "prefix-run"; [void](Install $a1 $Q)
    $r = Install $a2 $Q @() @{ HM_INSTALL_TEST_STATUS = "@running" }
    Check "an update is refused while a runtime runs, and says how to stop it" (($r.Code -eq 1) -and ($r.Out -match "heimdall service stop") -and ((Pair $Q) -eq (V "1.0.0")) -and -not (Test-Path -LiteralPath (Join-Path $Q ".heimdall.new.exe")))
    $r = Install $a2 $Q @() @{ HM_INSTALL_TEST_STATUS = "@empty" }
    Check "W01-R03: no output from the installed executable refuses the update (unknown is not none)" (($r.Code -eq 1) -and ($r.Out -match "cannot tell whether") -and ((Pair $Q) -eq (V "1.0.0")))
    $r = Install $a2 $Q @() @{ HM_INSTALL_TEST_STATUS = "@error" }
    Check "W01-R03: an error from the installed executable refuses the update" (($r.Code -eq 1) -and ($r.Out -match "cannot tell whether") -and ((Pair $Q) -eq (V "1.0.0")))
    $r = Install $a2 $Q @() @{ HM_INSTALL_TEST_STATUS = "@none"; HM_INSTALL_TEST_LIVE = "4242" }
    Check "R04: a live process from the installed path refuses the update although status says none" (($r.Code -eq 1) -and ($r.Out -match "a process started from") -and ((Pair $Q) -eq (V "1.0.0")))
    $r = Install $a2 $Q @("-AssumeStopped") @{ HM_INSTALL_TEST_LIVE = "4242" }
    Check "R04: -AssumeStopped does not override a live process" (($r.Code -eq 1) -and ($r.Out -match "does not override"))
    $r = Install $a2 $Q @("-AssumeStopped") @{ HM_INSTALL_TEST_STATUS = "@error" }
    Check "W01-R03: -AssumeStopped is the stated way past a broken executable" (($r.Code -eq 0) -and ((Pair $Q) -eq (V "2.0.0")))

    # --- M08-W01-R01: an unexpected object at a staging or install name is refused, and
    # what is inside it survives. Never a recursive delete.
    $D = Join-Path $T "prefix-dir"; [void](Install $a1 $D)
    $victim = Join-Path $D ".heimdall.new.exe"; [void][System.IO.Directory]::CreateDirectory($victim); [System.IO.File]::WriteAllText((Join-Path $victim "keep.txt"), "mine")
    $r = Install $a2 $D
    Check "W01-R01: a directory at .heimdall.new.exe is refused and keep.txt survives" (($r.Code -eq 1) -and ((Text (Join-Path $victim "keep.txt")) -eq "mine") -and ((Pair $D) -eq (V "1.0.0")) -and ($r.Out -match "left untouched"))
    $D2 = Join-Path $T "prefix-dir2"; [void](Install $a1 $D2); [void](Install $a2 $D2)
    $victim2 = Join-Path $D2 ".heimdall.swap.exe"; [void][System.IO.Directory]::CreateDirectory($victim2); [System.IO.File]::WriteAllText((Join-Path $victim2 "keep.txt"), "mine")
    $r = Install $a2 $D2 @("-Rollback")
    Check "W01-R01: a directory at .heimdall.swap.exe is refused on rollback and keep.txt survives" (($r.Code -eq 1) -and ((Text (Join-Path $victim2 "keep.txt")) -eq "mine") -and ((Pair $D2) -eq (V "2.0.0")) -and ((PrevPair $D2) -eq (V "1.0.0")))
    $D3 = Join-Path $T "prefix-link"; [void](Install $a1 $D3)
    $outside = Join-Path $T "outside"; [void][System.IO.Directory]::CreateDirectory($outside); [System.IO.File]::WriteAllText((Join-Path $outside "keep.txt"), "mine")
    Link (Join-Path $D3 ".linux-x86_64.new") $outside
    $r = Install $a2 $D3
    Check "W01-R01: a junction (or link) at a staging name is refused and its target survives" (($r.Code -eq 1) -and ((Text (Join-Path $outside "keep.txt")) -eq "mine") -and ((Pair $D3) -eq (V "1.0.0")))
    $D4 = Join-Path $T "prefix-link2"; [void](Install $a1 $D4)
    Link (Join-Path $D4 ".heimdall.new.exe") $outside
    $r = Install $a2 $D4
    Check "W01-R01: a junction (or link) at the executable staging name is refused and its target survives" (($r.Code -eq 1) -and ((Text (Join-Path $outside "keep.txt")) -eq "mine") -and ((Pair $D4) -eq (V "1.0.0")))
    $D5 = Join-Path $T "prefix-foreign"; [void](Install $a1 $D5)
    $stg = Join-Path $D5 ".linux-x86_64.new"; [void][System.IO.Directory]::CreateDirectory($stg); [System.IO.File]::WriteAllText((Join-Path $stg "heimdall"), "stale staged helper"); [System.IO.File]::WriteAllText((Join-Path $stg "notes.txt"), "mine")
    $r = Install $a2 $D5
    Check "W01-R01: a staged helper directory holding a foreign file is not deleted" (($r.Code -eq 1) -and ((Text (Join-Path $stg "notes.txt")) -eq "mine") -and ($r.Out -match "did not put there") -and ((Pair $D5) -eq (V "1.0.0")))
    $D6 = Join-Path $T "prefix-leftover"; [void](Install $a1 $D6)
    $stg6 = Join-Path $D6 ".linux-x86_64.new"; [void][System.IO.Directory]::CreateDirectory($stg6); [System.IO.File]::WriteAllText((Join-Path $stg6 "heimdall"), "stale staged helper")
    [System.IO.File]::WriteAllText((Join-Path $D6 ".heimdall.new.exe"), "stale staged exe")
    $r = Install $a2 $D6
    Check "a leftover staged pair holding only the script's own files is cleared and the update completes" (($r.Code -eq 0) -and ((Pair $D6) -eq (V "2.0.0")) -and ((PrevPair $D6) -eq (V "1.0.0")))

    # --- W0.3: a manifest name that is not a plain relative path is refused before any write.
    $outsideFile = Join-Path $T "outside.txt"; [System.IO.File]::WriteAllText($outsideFile, "mine")
    foreach ($badname in "linux-x86_64/../../outside.txt", "../outside.txt", "/outside.txt", "linux-x86_64//x", "linux-x86_64/./heimdall", "a\b", "c:x") {
        $mn = Join-Path $T "mn"; Copy-Item -Recurse -LiteralPath $a2 -Destination $mn
        [System.IO.File]::AppendAllText((Join-Path $mn "MANIFEST.sha256"), ("{0}  {1}`n" -f (Sha $outsideFile), $badname))
        $MP = Join-Path $T "prefix-mn"
        $r = Install $mn $MP
        Check "W0.3: a manifest naming '$badname' is refused, nothing written" (($r.Code -eq 1) -and ($r.Out -match "will not use") -and -not (Test-Path -LiteralPath (Join-Path $MP "heimdall.exe")) -and ((Text $outsideFile) -eq "mine"))
        Remove-Item -Recurse -Force -LiteralPath $mn
    }
    # --- W0.3: nothing is deleted THROUGH a link inside a staged helper directory.
    $a4 = Archive "a4" "4.0.0" $true
    $DL = Join-Path $T "prefix-deeplink"; [void](Install $a1 $DL)
    $far = Join-Path $T "far"; [void][System.IO.Directory]::CreateDirectory($far); [System.IO.File]::WriteAllText((Join-Path $far "tool"), "mine")
    $stgl = Join-Path $DL ".linux-x86_64.new"; [void][System.IO.Directory]::CreateDirectory($stgl)
    Link (Join-Path $stgl "sub") $far
    $r = Install $a4 $DL
    Check "W0.3: a junction (or link) at a subdirectory inside a staged helper is refused; the file behind it survives" (($r.Code -eq 1) -and ((Text (Join-Path $far "tool")) -eq "mine") -and ((Pair $DL) -eq (V "1.0.0")) -and ($r.Out -match "inside a directory this script manages"))
    $DL2 = Join-Path $T "prefix-deeplink2"; [void](Install $a4 $DL2)
    Check "W0.3: (an archive whose helper has a subdirectory installs)" ((Text (P $DL2 @("linux-x86_64", "sub", "tool"))) -eq "fake tool 4.0.0")
    $r = Install $a1 $DL2
    Check "W0.3: and updating away from it keeps the pair, subdirectory included, under .previous" (($r.Code -eq 0) -and ((Pair $DL2) -eq (V "1.0.0")) -and ((Text (P $DL2 @("linux-x86_64.previous", "sub", "tool"))) -eq "fake tool 4.0.0"))

    # --- M08-W01-R02: the executable and the helper are one unit.
    # A failure injected between the two renames of step 4 puts BOTH halves back.
    $U = Join-Path $T "prefix-unit"; [void](Install $a1 $U)
    $r = Install $a2 $U @() @{ HM_INSTALL_TEST_FAIL_AT = "4b" }
    Check "W01-R02: a failure between the two renames of an install undoes both halves" (($r.Code -eq 1) -and ((Pair $U) -eq (V "1.0.0")) -and ($r.Out -match "undone") -and -not (Test-Path -LiteralPath (Join-Path $U ".heimdall.new.exe")) -and -not (Test-Path -LiteralPath (Join-Path $U ".linux-x86_64.new")))
    $r = Install $a2 $U
    Check "W01-R02: and the next run completes the update as a pair" (($r.Code -eq 0) -and ((Pair $U) -eq (V "2.0.0")) -and ((PrevPair $U) -eq (V "1.0.0")))
    # A process killed between those two renames leaves a mixed pair; the rerun must not say
    # "already installed": it repairs the helper.
    $K = Join-Path $T "prefix-killed"; [void](Install $a1 $K)
    [void](Install $a2 $K @() @{ HM_INSTALL_TEST_STOP_AFTER = "4a" })
    Check "W01-R02: (the killed state is the mixed one: new executable, no current helper)" (((Exe $K) -eq "fake heimdall 2.0.0") -and ((Helper $K) -eq ""))
    $r = Install $a2 $K
    Check "W01-R02: a rerun after a kill between the renames repairs the pair, not 'already installed'" (($r.Code -eq 0) -and ((Pair $K) -eq (V "2.0.0")) -and ((PrevPair $K) -eq (V "1.0.0")) -and ($r.Out -notmatch "already installed"))
    # A helper that differs under a matching executable is repaired too.
    $M = Join-Path $T "prefix-mixed"; [void](Install $a2 $M)
    [System.IO.File]::WriteAllText((P $M @("linux-x86_64", "heimdall")), "fake helper 1.0.0")
    $r = Install $a2 $M
    Check "W01-R02: a matching executable with a different helper is repaired" (($r.Code -eq 0) -and ((Pair $M) -eq (V "2.0.0")) -and ($r.Out -match "repairing the helper in place"))
    # Rollback: a failure between its renames undoes both halves.
    $RB = Join-Path $T "prefix-rb"; [void](Install $a1 $RB); [void](Install $a2 $RB)
    $r = Install $a2 $RB @("-Rollback") @{ HM_INSTALL_TEST_FAIL_AT = "rb2" }
    Check "W01-R02: a failure between the two renames of a rollback undoes both halves" (($r.Code -eq 1) -and ((Pair $RB) -eq (V "2.0.0")) -and ((PrevPair $RB) -eq (V "1.0.0")) -and -not (Test-Path -LiteralPath (Join-Path $RB ".heimdall.swap.exe")) -and -not (Test-Path -LiteralPath (Join-Path $RB ".linux-x86_64.swap")))
    # Rollback killed at each point, then any rerun: a complete, matching pair, nothing lost.
    foreach ($tag in "ra1", "ra2", "rb1", "rb2", "rc1") {
        $X = Join-Path $T "prefix-rbk-$tag"; [void](Install $a1 $X); [void](Install $a2 $X)
        [void](Install $a2 $X @("-Rollback") @{ HM_INSTALL_TEST_STOP_AFTER = $tag })
        $r = Install $a2 $X @("-Rollback")
        $pairs = @((Pair $X), (PrevPair $X)) | Sort-Object
        Check "W01-R02: a rollback killed after $tag, then rerun: both versions survive as complete pairs" (($r.Code -eq 0) -and (($pairs -join ";") -eq ((@((V "1.0.0"), (V "2.0.0")) | Sort-Object) -join ";")) -and -not (Test-Path -LiteralPath (Join-Path $X ".heimdall.swap.exe")) -and -not (Test-Path -LiteralPath (Join-Path $X ".linux-x86_64.swap")))
    }

    # --- M08-W1-F1 (PC job 40): .previous always holds exactly the one pair that was in place.
    # An archive whose executable is new and whose helper bytes equal the installed helper's
    # (an "executable-only" update), and the same one version further on.
    $a2x = Archive "a2x" "2.0.0" $false "1.0.0"; $a3x = Archive "a3x" "3.0.0" $false "2.0.0"
    $E1 = Join-Path $T "prefix-f1-exeonly"; [void](Install $a1 $E1)
    $r = Install $a2x $E1
    Check "W1-F1: an executable-only update keeps the whole old pair under .previous" (($r.Code -eq 0) -and ((Pair $E1) -eq "fake heimdall 2.0.0|fake helper 1.0.0") -and ((PrevPair $E1) -eq (V "1.0.0")))
    $r = Install $a2x $E1 @("-Rollback")
    $exeBack = (Sha (P $E1 @("heimdall.exe"))) -eq (Sha (P $a1 @("heimdall.exe")))
    $hlpBack = (Sha (P $E1 @("linux-x86_64", "heimdall"))) -eq (Sha (P $a1 @("linux-x86_64", "heimdall")))
    Check "W1-F1: an executable-only update then a rollback restores the complete old pair (both digests)" (($r.Code -eq 0) -and $exeBack -and $hlpBack -and ((PrevPair $E1) -eq "fake heimdall 2.0.0|fake helper 1.0.0"))
    $E2 = Join-Path $T "prefix-f1-repair"; [void](Install $a1 $E2); [void](Install $a2 $E2)
    $prevBefore = "$(Sha (P $E2 @("heimdall.previous.exe")))|$(Sha (P $E2 @("linux-x86_64.previous", "heimdall")))"
    [System.IO.File]::WriteAllText((P $E2 @("linux-x86_64", "heimdall")), "damaged helper")
    $r = Install $a2 $E2
    $prevAfter = "$(Sha (P $E2 @("heimdall.previous.exe")))|$(Sha (P $E2 @("linux-x86_64.previous", "heimdall")))"
    Check "W1-F1: a helper-only repair fixes the helper in place and leaves .previous byte-identical" (($r.Code -eq 0) -and ((Pair $E2) -eq (V "2.0.0")) -and ($prevAfter -eq $prevBefore) -and ($r.Out -match "not touched"))
    $E3 = Join-Path $T "prefix-f1-chain"; [void](Install $a1 $E3); [void](Install $a2 $E3)
    $r = Install $a3x $E3
    Check "W1-F1: after an earlier full update, an executable-only update leaves .previous a matched pair" (($r.Code -eq 0) -and ((Pair $E3) -eq "fake heimdall 3.0.0|fake helper 2.0.0") -and ((PrevPair $E3) -eq (V "2.0.0")))
    $E4 = Join-Path $T "prefix-f1-incomplete"; [void](Install $a1 $E4); [void](Install $a2 $E4)
    [System.IO.File]::Delete((P $E4 @("linux-x86_64.previous", "heimdall")))
    $snap = Snapshot $E4
    $r = Install $a2 $E4 @("-Rollback")
    Check "W1-F1: a rollback with an incomplete .previous pair refuses, names what is missing, and changes nothing" (($r.Code -eq 1) -and ($r.Out -match "previous pair is incomplete") -and ($r.Out -match "install the older archive again") -and ((Snapshot $E4) -eq $snap))
    $E5 = Join-Path $T "prefix-f1-nohelperdir"; [void](Install $a1 $E5); [void](Install $a2 $E5)
    [System.IO.Directory]::Delete((P $E5 @("linux-x86_64.previous")), $true)
    $snap = Snapshot $E5
    $r = Install $a2 $E5 @("-Rollback")
    Check "W1-F1: a rollback with no .previous helper directory refuses and changes nothing" (($r.Code -eq 1) -and ((Snapshot $E5) -eq $snap))
    $E6 = Join-Path $T "prefix-f1-foreignprev"; [void](Install $a1 $E6); [void](Install $a2 $E6)
    [System.IO.File]::WriteAllText((P $E6 @("linux-x86_64.previous", "notes.txt")), "mine")
    $snap = Snapshot $E6
    $r = Install $a3x $E6
    Check "W1-F1: an update whose older .previous helper holds a foreign file refuses before any write" (($r.Code -eq 1) -and ($r.Out -match "did not put there") -and ((Snapshot $E6) -eq $snap))

    # --- W2 (review M08-W1-R04): a lost executable beside an older .previous executable
    # that has no helper is not an interrupted update: the current helper is never paired
    # with the older executable.
    $L4 = Join-Path $T "prefix-r04"; [void](Install $a2 $L4)
    [System.IO.File]::WriteAllText((Join-Path $L4 "heimdall.previous.exe"), "fake heimdall 1.0.0-nohelper")
    [System.IO.File]::Delete((Join-Path $L4 "heimdall.exe"))
    $r = Install $a2 $L4
    $noMix = ($r.Out -notmatch "finished an interrupted update") -and ((PrevHelper $L4) -eq "")
    Check "W2-R04: a lost executable beside an older .previous one is not finished as an interrupted update" (($r.Code -eq 0) -and $noMix -and ((Pair $L4) -eq (V "2.0.0")) -and ((PrevExe $L4) -eq "fake heimdall 1.0.0-nohelper"))
    Check "W2 (PC job 47): with an executable alone under .previous, the install says so and does not promise a rollback" (($r.Out -notmatch "previous pair is kept") -and ($r.Out -match "without its WSL helper; install.ps1 -Rollback will refuse it"))
    $r = Install $a2 $L4 @("-Rollback")
    Check "W2-R04: and a rollback then refuses instead of installing the older executable with the newer helper" (($r.Code -eq 1) -and ((Pair $L4) -eq (V "2.0.0")) -and ($r.Out -match "run that archive's install.ps1 again"))

    $LP = Join-Path $T "prefix-prevmsg"; [void](Install $a1 $LP)
    $r = Install $a2 $LP
    Check "W2 (PC job 47): with a complete pair under .previous, the install says -Rollback puts it back" (($r.Out -match "previous pair is kept under the .previous names") -and ($r.Out -notmatch "will refuse it"))

    # --- W2.1 (review M08-W2-R01): the same state, then a run stopped after staging. Its leftover
    # .heimdall.new.exe must not be read as an update interrupted between its renames.
    $L4b = Join-Path $T "prefix-w2r01"; [void](Install $a2 $L4b)
    [System.IO.File]::WriteAllText((Join-Path $L4b "heimdall.previous.exe"), "fake heimdall 1.0.0-nohelper")
    [System.IO.File]::Delete((Join-Path $L4b "heimdall.exe"))
    [void](Install $a2 $L4b @() @{ HM_INSTALL_TEST_STOP_AFTER = "1" })
    Check "W2.1-R01: (a run stopped after staging leaves .heimdall.new.exe)" (Test-Path -LiteralPath (Join-Path $L4b ".heimdall.new.exe"))
    $r = Install $a2 $L4b
    Check "W2.1-R01: a rerun after a stop at staging is not finished as an interrupted update" (($r.Code -eq 0) -and ($r.Out -notmatch "finished an interrupted update") -and ((PrevHelper $L4b) -eq "") -and ((Pair $L4b) -eq (V "2.0.0")))
    $r = Install $a2 $L4b @("-Rollback")
    Check "W2.1-R01: and the rollback that follows refuses, pairing nothing" (($r.Code -eq 1) -and ((Pair $L4b) -eq (V "2.0.0")) -and -not (Test-Path -LiteralPath (Join-Path $L4b ".heimdall.updating")))
    $L4c = Join-Path $T "prefix-w2r01-marker"; [void](Install $a1 $L4c)
    [void](Install $a2 $L4c @() @{ HM_INSTALL_TEST_STOP_AFTER = "3a" })
    Check "W2.1-R01: an update stopped after rename 3a leaves its marker" (Test-Path -LiteralPath (Join-Path $L4c ".heimdall.updating"))
    $r = Install $a2 $L4c
    Check "W2.1-R01: and the rerun finishes it and removes the marker" (($r.Code -eq 0) -and ($r.Out -match "finished an interrupted update") -and ((Pair $L4c) -eq (V "2.0.0")) -and ((PrevPair $L4c) -eq (V "1.0.0")) -and -not (Test-Path -LiteralPath (Join-Path $L4c ".heimdall.updating")))
    $D7 = Join-Path $T "prefix-markdir"; [void](Install $a1 $D7)
    [void][System.IO.Directory]::CreateDirectory((Join-Path $D7 ".heimdall.updating"))
    $r = Install $a2 $D7
    Check "W2.1-R01: a directory at the marker's name is refused and nothing changes" (($r.Code -eq 1) -and ($r.Out -match "left untouched") -and ((Pair $D7) -eq (V "1.0.0")))

    # --- W2 (review M08-W1-R05): a repair whose last rename fails says what it left.
    $L5 = Join-Path $T "prefix-r05"; [void](Install $a2 $L5)
    [System.IO.File]::WriteAllText((P $L5 @("linux-x86_64", "heimdall")), "damaged helper")
    $r = Install $a2 $L5 @() @{ HM_INSTALL_TEST_FAIL_AT = "4b" }
    Check "W2-R05: a repair that fails at its last rename says the helper may be missing, not that both halves were put back" (($r.Code -eq 1) -and ($r.Out -match "the helper repair failed") -and ($r.Out -notmatch "executable and helper together") -and ((Exe $L5) -eq "fake heimdall 2.0.0"))
    $r = Install $a2 $L5
    Check "W2-R05: and running the script again repairs the helper" (($r.Code -eq 0) -and ((Pair $L5) -eq (V "2.0.0")))

    # --- W2 (review M08-W1-R07): a staged helper that does not match the manifest is never
    # put in place.
    $L7 = Join-Path $T "prefix-r07"; [void](Install $a1 $L7)
    $r = Install $a2 $L7 @() @{ HM_INSTALL_TEST_TAMPER_STAGED = "1" }
    Check "W2-R07: a staged helper file that does not match the manifest stops the update before any rename" (($r.Code -eq 1) -and ($r.Out -match "staged helper file heimdall does not match") -and ((Pair $L7) -eq (V "1.0.0")) -and ((PrevExe $L7) -eq "") -and -not (Test-Path -LiteralPath (Join-Path $L7 ".heimdall.new.exe")) -and -not (Test-Path -LiteralPath (Join-Path $L7 ".linux-x86_64.new")))

    # --- W2 (review M08-W1-R06): the live-process check compares resolved full paths. The
    # process paths are handed in; the comparison is what is tested.
    $L6 = Join-Path $T "prefix-r06"; [void](Install $a1 $L6)
    $canon = Join-Path (Resolve-Path -LiteralPath $L6).ProviderPath "heimdall.exe"
    # A link to the scratch directory, so the prefix passes through it (a prefix that is
    # itself a link is refused before anything else, as before).
    $LT = Join-Path $T "via-link"; [void][System.IO.Directory]::CreateDirectory($LT); Link (Join-Path $LT "up") $T
    Push-Location $T
    try { $r = Install $a2 "prefix-r06" @("-AssumeStopped") @{ HM_INSTALL_TEST_PROCESS_PATHS = "4242=$canon" } } finally { Pop-Location }
    Check "W2-R06: a relative -Prefix still finds a process started from the installed executable" (($r.Code -eq 1) -and ($r.Out -match "a process started from") -and ((Pair $L6) -eq (V "1.0.0")))
    $r = Install $a2 (P $LT @("up", "prefix-r06")) @("-AssumeStopped") @{ HM_INSTALL_TEST_PROCESS_PATHS = "4242=$canon" }
    Check "W2-R06: a -Prefix that passes through a link (a junction on Windows) still finds it" (($r.Code -eq 1) -and ($r.Out -match "a process started from") -and ((Pair $L6) -eq (V "1.0.0")))
    $viaLink = P $LT @("up", "prefix-r06", "heimdall.exe")
    $r = Install $a2 $L6 @("-AssumeStopped") @{ HM_INSTALL_TEST_PROCESS_PATHS = "4242=$viaLink" }
    Check "W2-R06: a process started through a link to the install directory is found" (($r.Code -eq 1) -and ($r.Out -match "a process started from") -and ((Pair $L6) -eq (V "1.0.0")))
    $other = Join-Path (Join-Path $T "elsewhere") "heimdall.exe"
    $r = Install $a2 $L6 @("-AssumeStopped") @{ HM_INSTALL_TEST_PROCESS_PATHS = "4242=$other" }
    Check "W2-R06: a heimdall.exe elsewhere does not block the update" (($r.Code -eq 0) -and ((Pair $L6) -eq (V "2.0.0")))

    # Interrupted install after each step, then a rerun finishes it as a pair.
    foreach ($tag in "1", "2", "3a", "3b", "4a", "4b") {
        # ($IP, not $R: PowerShell variable names are case-insensitive, and $r is the result.)
        $IP = Join-Path $T "prefix-int$tag"; [void](Install $a1 $IP)
        [void](Install $a2 $IP @() @{ HM_INSTALL_TEST_STOP_AFTER = $tag })
        # Nothing of version 1 is lost at any point: its executable and its helper are each
        # still present, under the current or the .previous name.
        $exe1 = ((Exe $IP) -eq "fake heimdall 1.0.0") -or ((PrevExe $IP) -eq "fake heimdall 1.0.0")
        $hlp1 = ((Helper $IP) -eq "fake helper 1.0.0") -or ((PrevHelper $IP) -eq "fake helper 1.0.0")
        Check "interrupted after ${tag}: version 1's executable and helper both survive" ($exe1 -and $hlp1)
        $r = Install $a2 $IP
        Check "interrupted after ${tag}: rerunning finishes the update, executable and helper together" (($r.Code -eq 0) -and ((Pair $IP) -eq (V "2.0.0")) -and ((PrevPair $IP) -eq (V "1.0.0")) -and -not (Test-Path -LiteralPath (Join-Path $IP ".heimdall.new.exe")))
    }

    # The Windows rule itself: an executable that is open (as a running image would be)
    # can be renamed aside but not overwritten, and the update still succeeds.
    $W = Join-Path $T "prefix-open"; [void](Install $a1 $W)
    $held = [System.IO.File]::Open((Join-Path $W "heimdall.exe"), [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
    try { $r = Install $a2 $W } finally { $held.Close() }
    Check "an update succeeds while the old executable is held open, by renaming it aside" (($r.Code -eq 0) -and ((Pair $W) -eq (V "2.0.0")) -and ((PrevPair $W) -eq (V "1.0.0")))
} finally {
    Remove-Item Env:\HM_INSTALL_TEST_STATUS -ErrorAction SilentlyContinue
    # The exact directory this script created. Links inside it are removed as links first,
    # so nothing outside it can be reached.
    Get-ChildItem -LiteralPath $T -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object { $_.Delete() }
    Remove-Item -Recurse -Force -LiteralPath $T -ErrorAction SilentlyContinue
}
Write-Host ("install-selftest: " + $(if ($script:failed -eq 0) { "PASS" } else { "FAIL" }) + " ($script:n checks)")
exit $script:failed
