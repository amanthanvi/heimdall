# Revert proofs for install.ps1's merge-relevant fixes (review M08-W01-R01 and R02; PC job 40's
# finding M08-W1-F1; the W1 review's R04 and R07).
#
# STATUS: rehearsed under PowerShell 7 on macOS only; the evidence is its run on the PC.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\native\m08\lifecycle\install-revert-proofs.ps1
# Exit code: 0 when the self-test PASSES on the real install.ps1 and, for each fix, FAILS in
# exactly the expected cases once that one fix is taken out of a scratch copy; 1 otherwise.
#
# It never changes the repository: each reverted copy is written to a new temporary
# directory (removed at the end by its exact path) and handed to install-selftest.ps1
# through HM_INSTALL_UNDER_TEST. The fixes are found by their marker comments in install.ps1.
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot (Join-Path ".." (Join-Path ".." (Join-Path ".." ".."))))).Path
$real = Join-Path (Join-Path (Join-Path $repo "tools") "packaging") "install.ps1"
$selftest = Join-Path $PSScriptRoot "install-selftest.ps1"
$ps = (Get-Process -Id $PID).Path
$T = Join-Path ([System.IO.Path]::GetTempPath()) ("hm-install-revert-" + [System.Guid]::NewGuid().ToString("N"))
[void][System.IO.Directory]::CreateDirectory($T)
$failed = 0
function Run([string]$sut) {
    $old = $env:HM_INSTALL_UNDER_TEST
    if ($sut) { $env:HM_INSTALL_UNDER_TEST = $sut } else { Remove-Item Env:\HM_INSTALL_UNDER_TEST -ErrorAction SilentlyContinue }
    try { $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $selftest 2>&1 | Out-String; $code = $LASTEXITCODE }
    finally { if ($old) { $env:HM_INSTALL_UNDER_TEST = $old } else { Remove-Item Env:\HM_INSTALL_UNDER_TEST -ErrorAction SilentlyContinue } }
    return @{ Code = $code; Fails = @(($out -split "`n") | Where-Object { $_ -match '^FAIL ' } | ForEach-Object { $_.Trim() }) }
}
function Between([string]$text, [string]$begin, [string]$end, [string]$replacement) {
    $i = $text.IndexOf($begin); $j = $text.IndexOf($end)
    if ($i -lt 0 -or $j -lt $i) { throw "marker $begin not found in install.ps1" }
    $lineStart = $text.LastIndexOf("`n", $i) + 1
    $lineEnd = $text.IndexOf("`n", $j)
    return $text.Substring(0, $lineStart) + $replacement + $text.Substring($lineEnd)
}
try {
    $base = Run ""
    Write-Host "with every fix in place: exit $($base.Code), $($base.Fails.Count) failing"
    if ($base.Code -ne 0) { $failed = 1 }

    $text = [System.IO.File]::ReadAllText($real)
    # R01 reverted: no type check before the writes, and the candidate's cleanup (a
    # recursive delete of whatever sits at a staging name) put back in its place.
    $r01 = Between $text "# W01-R01-BEGIN" "# W01-R01-END" @'
function Assert-Names {
    foreach ($p in $new, $newH, $swap, $swapH) { if (Test-Path -LiteralPath $p) { Remove-Item -Recurse -Force -LiteralPath $p } }
}
'@
    $f1 = Join-Path $T "install-r01-reverted.ps1"; [System.IO.File]::WriteAllText($f1, $r01)
    $a = Run $f1
    Write-Host "W01-R01 reverted: exit $($a.Code); failing cases:"; $a.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($a.Fails | Where-Object { $_ -match 'W01-R01: a directory at \.heimdall\.new\.exe is refused and keep\.txt survives' })
    if ($a.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W01-R01: the directory case did not fail without the fix"; $failed = 1 }

    # R02 reverted: "already installed" decided by the executable alone.
    $r02 = Between $text "# W01-R02-BEGIN" "# W01-R02-END" @'
$exeOk = Exe-Ok
$helperOk = $exeOk
'@
    $f2 = Join-Path $T "install-r02-reverted.ps1"; [System.IO.File]::WriteAllText($f2, $r02)
    $b = Run $f2
    Write-Host "W01-R02 reverted: exit $($b.Code); failing cases:"; $b.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($b.Fails | Where-Object { $_ -match "W01-R02: a rerun after a kill between the renames repairs the pair" })
    if ($b.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W01-R02: the mixed-pair case did not fail without the fix"; $failed = 1 }

    # W1-F1 reverted (PC job 40): the half-pair rule, in which an update moves and stages only
    # the half that differs. With it, an executable-only update keeps no helper under
    # .previous, and the rollback that follows is refused (or, without the rollback check,
    # leaves the install without its helper).
    $f1r = Between $text "# W1-F1-BEGIN" "# W1-F1-END" @'
$update = -not $exeOk
$stageExe = $update
$stageHelper = (-not $helperOk) -and $wantHelper.Count -gt 0
$replaceHelper = -not $helperOk
'@
    $f3 = Join-Path $T "install-f1-reverted.ps1"; [System.IO.File]::WriteAllText($f3, $f1r)
    $c = Run $f3
    Write-Host "W1-F1 reverted: exit $($c.Code); failing cases:"; $c.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($c.Fails | Where-Object { $_ -match "W1-F1: an executable-only update then a rollback restores the complete old pair" })
    if ($c.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W1-F1: the executable-only rollback case did not fail without the fix"; $failed = 1 }

    # W1-F1's rollback check reverted: a rollback no longer insists on a complete pair.
    $f1b = Between $text "# W1-F1-ROLLBACK-BEGIN" "# W1-F1-ROLLBACK-END" ""
    $f4 = Join-Path $T "install-f1-rollback-reverted.ps1"; [System.IO.File]::WriteAllText($f4, $f1b)
    $d = Run $f4
    Write-Host "W1-F1 rollback check reverted: exit $($d.Code); failing cases:"; $d.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($d.Fails | Where-Object { $_ -match "W1-F1: a rollback with an incomplete .previous pair refuses" })
    if ($d.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W1-F1's rollback check: the incomplete-pair case did not fail without it"; $failed = 1 }

    # W2-R04 reverted to W2's rule: the interrupted update decided from a leftover staged
    # executable instead of the marker (review M08-W2-R01).
    $r04 = Between $text "# W2-R04-BEGIN" "# W2-R04-END" @'
$interruptedUpdate = ((Kind $cur) -eq 'absent') -and ((Kind $new) -eq 'file') -and ((Kind $prev) -eq 'file') -and ((Kind $curH) -eq 'dir') -and ((Kind $prevH) -eq 'absent')
'@
    $f5 = Join-Path $T "install-r04-reverted.ps1"; [System.IO.File]::WriteAllText($f5, $r04)
    $e = Run $f5
    Write-Host "W2-R04 reverted: exit $($e.Code); failing cases:"; $e.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($e.Fails | Where-Object { $_ -match "W2.1-R01: a rerun after a stop at staging is not finished" })
    if ($e.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W2-R04/W2.1-R01: the stop-at-staging case did not fail without the marker"; $failed = 1 }

    # W2-R07 reverted: the staged helper is not re-checked.
    $r07 = Between $text "# W2-R07-BEGIN" "# W2-R07-END" ""
    $f6 = Join-Path $T "install-r07-reverted.ps1"; [System.IO.File]::WriteAllText($f6, $r07)
    $g = Run $f6
    Write-Host "W2-R07 reverted: exit $($g.Code); failing cases:"; $g.Fails | ForEach-Object { Write-Host "   $_" }
    $want = @($g.Fails | Where-Object { $_ -match "W2-R07: a staged helper file that does not match" })
    if ($g.Code -eq 0 -or $want.Count -ne 1) { Write-Host "REVERT PROOF FAILED for W2-R07: the tampered-helper case did not fail without the fix"; $failed = 1 }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $T -ErrorAction SilentlyContinue
}
Write-Host ("install-revert-proofs: " + $(if ($failed -eq 0) { "PASS" } else { "FAIL" }))
exit $failed
