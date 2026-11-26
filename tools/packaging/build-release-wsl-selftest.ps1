# Test the Windows packager's WSL helper preflight with synthetic Linux archives.
# Windows PowerShell 5.1: powershell -NoProfile -ExecutionPolicy Bypass -File tools\packaging\build-release-wsl-selftest.ps1
# PowerShell 7: pwsh -NoProfile -File tools/packaging/build-release-wsl-selftest.ps1
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$packager = Join-Path $PSScriptRoot "build-release.ps1"
$provenance = Join-Path $PSScriptRoot "provenance.py"
$fixtures = Join-Path ([System.IO.Path]::GetTempPath()) ("hm-wsl-helper-selftest-" + [Guid]::NewGuid().ToString("N"))
$shell = (Get-Process -Id $PID).Path
$fails = 0
$cases = @(
    @("good", 0, "verified Linux x86-64 WSL helper"),
    @("commit", 1, "WSL helper commit differs"),
    @("target", 1, "target is not x86_64-unknown-linux-gnu"),
    @("features", 1, "WSL helper feature set differs"),
    @("digest", 1, "an executable digest differs from the file"),
    @("index", 1, "archive's digest differs from the external index"),
    @("machine", 1, "ELF machine does not match the target")
)
try {
    New-Item -ItemType Directory -Path $fixtures | Out-Null
    $commit = (git -C $repo rev-parse HEAD).Trim()
    & python -I (Join-Path $PSScriptRoot "wsl_helper_fixtures.py") $fixtures $commit
    if ($LASTEXITCODE -ne 0) { throw "creating archive fixtures failed" }
    foreach ($case in $cases) {
        $dir = Join-Path $fixtures $case[0]
        $archive = Join-Path $dir "linux.tar.gz"
        $index = Join-Path $dir "SHA256SUMS"
        $out = & $shell -NoProfile -ExecutionPolicy Bypass -File $packager -LinuxArchive $archive -LinuxIndex $index -CheckWSLHelperOnly | Out-String
        $code = $LASTEXITCODE
        if ($code -eq $case[1] -and $out.Contains($case[2])) {
            Write-Host "ok   $($case[0]) -> exit $code"
        } else {
            Write-Host "FAIL $($case[0]) -> exit $code, expected $($case[1]) and '$($case[2])'"
            $fails++
        }
    }
    $good = Join-Path $fixtures "good"
    $archive = Join-Path $good "linux.tar.gz"
    $index = Join-Path $good "SHA256SUMS"
    $helper = Join-Path $fixtures "staged-helper"
    $receipt = Join-Path $fixtures "receipt.json"
    & python -I $provenance check-wsl-helper --archive $archive --index $index --commit $commit --out $helper --receipt $receipt | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $saved = Get-Content -Raw -LiteralPath $receipt | ConvertFrom-Json
        $checked = ($saved.commit -eq $commit -and $saved.target -eq "x86_64-unknown-linux-gnu" -and
            $saved.features -eq "--no-default-features" -and $saved.sha256 -eq (Get-FileHash -LiteralPath $helper).Hash.ToLower() -and
            $saved.archive_sha256 -eq (Get-FileHash -LiteralPath $archive).Hash.ToLower())
    } else { $checked = $false }
    if ($checked) { Write-Host "ok   staged helper and receipt" }
    else { Write-Host "FAIL staged helper and receipt"; $fails++ }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $fixtures
}
$count = $cases.Count + 1
if ($fails -eq 0) { Write-Host "build-release-wsl-selftest: PASS ($count checks)"; exit 0 }
Write-Host "build-release-wsl-selftest: FAIL ($fails of $count)"
exit 1
