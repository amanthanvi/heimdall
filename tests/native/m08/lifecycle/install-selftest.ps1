# Self-test of tools\packaging\install.ps1 with fake archives (m08-plan U2a). The Windows
# counterpart of install-selftest.sh.
#
# STATUS: written on the Mac and NOT YET RUN. It runs on the Windows PC in a later job.
#
# Usage: powershell -ExecutionPolicy Bypass -File tests\native\m08\lifecycle\install-selftest.ps1
# Exit code: 0 when every case passes; 1 otherwise.
#
# No Heimdall executable is used or run. The "executables" are two different files with
# fixed bytes (never started: HM_INSTALL_TEST_RUNNING tells install.ps1 whether a runtime
# is running, so it does not ask one). The "helper" is a directory with one file. Everything
# lives in one new directory under %TEMP%, removed at the end by its exact path.
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$T = Join-Path ([System.IO.Path]::GetTempPath()) ("hm-install-selftest-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $T | Out-Null
$script:bad = 0
# The same PowerShell that runs this file runs install.ps1 (Windows PowerShell 5.1 or PowerShell 7).
$script:ps = (Get-Process -Id $PID).Path
function Check([string]$name, [bool]$ok) { if ($ok) { Write-Host "ok   $name" } else { Write-Host "FAIL $name"; $script:bad = 1 } }
function Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }
function Text([string]$p) { if (Test-Path -LiteralPath $p) { [System.IO.File]::ReadAllText($p) } else { "" } }

function Archive([string]$name, [string]$version) {
    $d = Join-Path $T $name
    New-Item -ItemType Directory -Path (Join-Path $d "linux-x86_64") -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $d "heimdall.exe"), "fake heimdall $version")
    [System.IO.File]::WriteAllText((Join-Path $d "linux-x86_64\heimdall"), "fake helper $version")
    [System.IO.File]::WriteAllText((Join-Path $d "README"), "notes for $version")
    Copy-Item (Join-Path $repo "tools\packaging\install.ps1") (Join-Path $d "install.ps1")
    $lines = foreach ($f in "README", "heimdall.exe", "install.ps1", "linux-x86_64/heimdall") {
        "{0}  {1}" -f (Sha (Join-Path $d ($f -replace '/', '\'))), $f
    }
    [System.IO.File]::WriteAllText((Join-Path $d "MANIFEST.sha256"), (($lines -join "`n") + "`n"))
    return $d
}
function Install([string]$archive, [string]$prefix, [string[]]$more = @()) {
    $out = & $script:ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $archive "install.ps1") -Prefix $prefix @more 2>&1 | Out-String
    return @{ Code = $LASTEXITCODE; Out = $out }
}

try {
    $a1 = Archive "a1" "1.0.0"; $a2 = Archive "a2" "2.0.0"
    $env:HM_INSTALL_TEST_RUNNING = "0"
    $P = Join-Path $T "prefix"

    $r = Install $a1 $P
    Check "a fresh install puts the executable and the helper in place" (($r.Code -eq 0) -and ((Text "$P\heimdall.exe") -eq "fake heimdall 1.0.0") -and ((Text "$P\linux-x86_64\heimdall") -eq "fake helper 1.0.0") -and -not (Test-Path "$P\heimdall.previous.exe"))
    Check "it names the directory to add to PATH and edits nothing" ($r.Out -match "add this directory to your PATH yourself")
    $r = Install $a1 $P
    Check "installing the same version again changes nothing" (($r.Out -match "already installed") -and -not (Test-Path "$P\heimdall.previous.exe"))
    $r = Install $a2 $P
    Check "an update keeps the previous executable and helper, as a pair" (((Text "$P\heimdall.exe") -eq "fake heimdall 2.0.0") -and ((Text "$P\heimdall.previous.exe") -eq "fake heimdall 1.0.0") -and ((Text "$P\linux-x86_64\heimdall") -eq "fake helper 2.0.0") -and ((Text "$P\linux-x86_64.previous\heimdall") -eq "fake helper 1.0.0"))
    $r = Install $a2 $P @("-Rollback")
    Check "a rollback swaps both pairs" (($r.Code -eq 0) -and ((Text "$P\heimdall.exe") -eq "fake heimdall 1.0.0") -and ((Text "$P\heimdall.previous.exe") -eq "fake heimdall 2.0.0") -and ((Text "$P\linux-x86_64\heimdall") -eq "fake helper 1.0.0") -and ((Text "$P\linux-x86_64.previous\heimdall") -eq "fake helper 2.0.0"))

    # A damaged and an incomplete tree are refused; nothing changes.
    $bad = Join-Path $T "bad"; Copy-Item -Recurse $a2 $bad; Add-Content -LiteralPath (Join-Path $bad "heimdall.exe") -Value "tampered"
    $before = Sha "$P\heimdall.exe"
    $r = Install $bad $P
    Check "a damaged tree is refused (exit 1) and nothing changes" (($r.Code -eq 1) -and ($r.Out -match "does not match MANIFEST") -and ((Sha "$P\heimdall.exe") -eq $before))
    $short = Join-Path $T "short"; Copy-Item -Recurse $a2 $short; Remove-Item (Join-Path $short "README")
    $r = Install $short $P
    Check "an incomplete tree is refused" (($r.Code -eq 1) -and ($r.Out -match "incomplete"))

    # A running runtime refuses the update; nothing changes and nothing is staged.
    $Q = Join-Path $T "prefix-run"
    Install $a1 $Q | Out-Null
    $env:HM_INSTALL_TEST_RUNNING = "1"
    $r = Install $a2 $Q
    $env:HM_INSTALL_TEST_RUNNING = "0"
    Check "an update is refused while a runtime runs, and says how to stop it" (($r.Code -eq 1) -and ($r.Out -match "heimdall service stop") -and ((Text "$Q\heimdall.exe") -eq "fake heimdall 1.0.0") -and -not (Test-Path "$Q\.heimdall.new.exe"))

    # Interrupted after each step. Windows cannot replace a mapped image in one rename, so
    # after step 3 the install path has no heimdall.exe and the complete old one is at
    # heimdall.previous.exe: the test states exactly that, and that a rerun finishes.
    foreach ($n in 1, 2, 3, 4) {
        $R = Join-Path $T "prefix-int$n"
        Install $a1 $R | Out-Null
        $env:HM_INSTALL_TEST_STOP_AFTER = "$n"
        Install $a2 $R | Out-Null
        Remove-Item Env:\HM_INSTALL_TEST_STOP_AFTER
        if ($n -le 2) {
            Check "interrupted after step ${n}: the install path holds the complete old executable" ((Text "$R\heimdall.exe") -eq "fake heimdall 1.0.0")
        } elseif ($n -eq 3) {
            Check "interrupted after step 3: the old executable is complete at heimdall.previous.exe (the install path is empty until the rerun)" ((-not (Test-Path "$R\heimdall.exe")) -and ((Text "$R\heimdall.previous.exe") -eq "fake heimdall 1.0.0"))
        } else {
            Check "interrupted after step 4: the install path holds the complete new executable" ((Text "$R\heimdall.exe") -eq "fake heimdall 2.0.0")
        }
        $r = Install $a2 $R
        Check "interrupted after step ${n}: rerunning finishes the update, executable and helper together" (((Text "$R\heimdall.exe") -eq "fake heimdall 2.0.0") -and ((Text "$R\heimdall.previous.exe") -eq "fake heimdall 1.0.0") -and ((Text "$R\linux-x86_64\heimdall") -eq "fake helper 2.0.0") -and -not (Test-Path "$R\.heimdall.new.exe"))
    }

    # The Windows rule itself: an executable that is open (as a running image would be)
    # can be renamed aside but not overwritten, and the update still succeeds.
    $W = Join-Path $T "prefix-open"
    Install $a1 $W | Out-Null
    $held = [System.IO.File]::Open("$W\heimdall.exe", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
    try { $r = Install $a2 $W } finally { $held.Close() }
    Check "an update succeeds while the old executable is held open, by renaming it aside" (($r.Code -eq 0) -and ((Text "$W\heimdall.exe") -eq "fake heimdall 2.0.0") -and ((Text "$W\heimdall.previous.exe") -eq "fake heimdall 1.0.0"))
} finally {
    Remove-Item Env:\HM_INSTALL_TEST_RUNNING -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -LiteralPath $T -ErrorAction SilentlyContinue
}
Write-Host ("install-selftest: " + $(if ($script:bad -eq 0) { "PASS" } else { "FAIL" }))
exit $script:bad
