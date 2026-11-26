# Self-test of build-release.ps1's feature request handling (review M08-W2-F2; PC job 57 step 5c).
#
# The original defect was Windows PowerShell 5.1's parsing of unquoted
# `-Features default,iroh` as an array. PowerShell 7 can also exercise the feature-only path.
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\packaging\build-release-features-selftest.ps1
# Exit code: 0 when every case passes; 1 otherwise.
#
# Each case starts a child shell (Windows PowerShell 5.1, and PowerShell 7 when present) with a
# -Command line written as a user types it, so the child parses the arguments itself. Every run
# uses -CheckFeaturesOnly: build-release.ps1 runs its feature checks (the join, -AllFeatures,
# the character check, `provenance.py check-features`) and exits. Nothing is built, and the
# Linux helper is never read.
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$script = Join-Path $repo "tools\packaging\build-release.ps1"
$shells = @("pwsh")
if ($env:OS -eq "Windows_NT") {
    $shells = @("powershell.exe")
    if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) { $shells += "pwsh.exe" }
}
$fails = 0; $n = 0
$refusedIroh = "release artifacts are built without the iroh feature"
$cases = @(
    # (arguments as typed, expected exit, a line the output must hold)
    @("-Features default,iroh", 2, $refusedIroh),
    @("-Features 'default,iroh'", 2, $refusedIroh),
    @("-Features iroh", 2, $refusedIroh),
    @("-Features heimdall-runtime/iroh", 2, $refusedIroh),
    @("-Features default, iroh", 2, $refusedIroh),
    @("-Features 'iroh iroh'", 2, "-Features may hold only"),
    @("-AllFeatures", 2, "-AllFeatures is refused"),
    @("", 0, "no iroh feature requested and no iroh crate in the selected graph"),
    @("-Features default", 2, "the release graph holds test-only crates")
)
foreach ($sh in $shells) {
    foreach ($c in $cases) {
        $n++
        $line = "& '$script' -CheckFeaturesOnly $($c[0]); exit `$LASTEXITCODE"
        $out = & $sh -NoProfile -ExecutionPolicy Bypass -Command $line 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ok = ($code -eq $c[1]) -and $out.Contains($c[2])
        $label = if ($c[0]) { $c[0] } else { "(no features)" }
        if ($ok) { Write-Host "ok   $sh $label -> exit $code" }
        else { Write-Host "FAIL $sh $label -> exit $code, wanted $($c[1]) and '$($c[2])'"; $fails++ }
    }
}
if ($fails -eq 0) { Write-Host "build-release-features-selftest: PASS ($n checks)"; exit 0 }
Write-Host "build-release-features-selftest: FAIL ($fails of $n)"; exit 1
