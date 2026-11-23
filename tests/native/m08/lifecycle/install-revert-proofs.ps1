# Revert proofs for install.ps1's two merge-relevant fixes (review M08-W01-R01 and R02).
#
# STATUS: rehearsed under PowerShell 7 on macOS only; the evidence is its run on the PC.
#
# Usage: powershell -ExecutionPolicy Bypass -File tests\native\m08\lifecycle\install-revert-proofs.ps1
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
} finally {
    Remove-Item -Recurse -Force -LiteralPath $T -ErrorAction SilentlyContinue
}
Write-Host ("install-revert-proofs: " + $(if ($failed -eq 0) { "PASS" } else { "FAIL" }))
exit $failed
