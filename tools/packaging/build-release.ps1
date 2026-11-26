# Build the Heimdall Windows release archive on the PC (m08-plan U3a; ADR-0014 sections 4.2
# and 4.4). The counterpart of build-release.sh for x86_64-pc-windows-msvc.
#
# STATUS: run successfully on the PC under Windows PowerShell 5.1 (jobs 40 and 43, at
# 5348551b and 3c8265c5), after two first-run fixes: job 34 stopped at provenance (a byte
# order mark in cargo's messages; fixed by the raw-byte capture below and a strict reader)
# and job 36 at verification (combase.dll). Jobs 40 and 43 differed only in the link time
# and the PDB GUID; the link is now deterministic (/Brepro), and whether two builds are
# identical is shown by a two-clone PC run (tools/packaging/README.md).
#
# Usage (PowerShell 5.1 or 7, from the repository root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\packaging\build-release.ps1 `
#       -LinuxArchive <Linux x86-64 tar.gz> -LinuxIndex <its SHA256SUMS> `
#       [-Features <list>] [-AllowDirty] [-Offline] [-Candidate]
#   (-Features takes a comma list, quoted or not: an unquoted `default,iroh` arrives as an
#   array and is joined. -CheckFeaturesOnly runs only the feature checks, then exits.)
# Exit code: 0 when the archive was built and passed verify_artifact.py; 1 when the build,
# the inventory or the verification failed; 2 on a usage or setup error.
#
# Differences from build-release.sh:
#   * the C runtime is linked statically (-C target-feature=+crt-static), so the archive
#     needs no Visual C++ redistributable;
#   * the Linux x86_64 executable is placed where heimdall.exe looks for its WSL helper
#     (a subdirectory beside it; crates/wsl/src/spawn.rs `helper_windows_path`). The packager
#     verifies the indexed Linux archive, commit, target, features and executable digest;
#   * the archive is a .zip.
# Nothing is executed from the built artifact, nothing is uploaded, and nothing outside
# .\target is written except one temporary file removed on exit.
[CmdletBinding()]
param(
    [string]$LinuxArchive,
    [string]$LinuxIndex,
    [string[]]$Features = @(),
    [switch]$AllowDirty,
    [switch]$Offline,
    [switch]$AllFeatures,
    [switch]$CheckFeaturesOnly,
    [switch]$CheckWSLHelperOnly,
    [switch]$Candidate
)
$ErrorActionPreference = "Stop"
$target = "x86_64-pc-windows-msvc"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$here = "tools\packaging"
$provenance = Join-Path $PSScriptRoot "provenance.py"
$env:PYTHONDONTWRITEBYTECODE = "1"

function Fail([int]$code, [string]$msg) { Write-Host "build-release: $msg"; exit $code }

# The feature request, checked before anything else (review M08-W2-F2). Windows PowerShell
# passes an unquoted `-Features default,iroh` as an array; it used to fail binding to a string
# with a PowerShell error, before this script's own refusal. The elements are joined with
# commas into the one list cargo takes, and every check below reads that list.
$featureList = (@($Features) | Where-Object { $_ }) -join ','
if ($AllFeatures) { Fail 2 "-AllFeatures is refused: release artifacts are built without the iroh feature (the Iroh transport is a source-build preview)" }
# The feature list is passed to cargo on one command line (below), so it may hold only the
# characters a feature list uses.
if ($featureList -and ($featureList -notmatch '^[A-Za-z0-9_,/-]+$')) { Fail 2 "-Features may hold only letters, digits, '_', '-', '/' and ','" }
if ($CheckFeaturesOnly) {
    $onlyArgs = @("check-features", "--target", $target)
    if ($featureList) { $onlyArgs += @("--features", $featureList) }
    if ($Offline) { $onlyArgs += "--offline" }
    & python -I $provenance @onlyArgs
    if ($LASTEXITCODE -ne 0) { Fail 2 "refused before the build; nothing was built" }
    exit 0
}

if (-not $LinuxArchive -or -not $LinuxIndex) { Fail 2 "-LinuxArchive and -LinuxIndex are required" }
if ($Candidate -and $AllowDirty) { Fail 2 "-Candidate requires a clean checkout" }
foreach ($tool in "git", "python") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { Fail 2 "$tool not found" }
}
$commit = (git rev-parse HEAD).Trim()
$candidateArgs = @()
if ($Candidate) { $candidateArgs += "--candidate" }
$helperArgs = @("check-wsl-helper", "--archive", $LinuxArchive, "--index", $LinuxIndex, "--commit", $commit)
if ($featureList) { $helperArgs += @("--features", $featureList) }
$helperArgs += $candidateArgs
if ($CheckWSLHelperOnly) {
    & python -I $provenance @helperArgs
    exit $LASTEXITCODE
}

foreach ($tool in "cargo", "rustc", "rustup") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { Fail 2 "$tool not found" }
}
if (-not ((rustup target list --installed) -contains $target)) { Fail 2 "the rust target is not installed: rustup target add $target" }
$sbomTool = Join-Path $repo "target\tools\bin\cargo-cyclonedx.exe"
$sbomToolVersion = "0.5.10"
if (-not (Test-Path $sbomTool) -or ((& $sbomTool cyclonedx --version).Split(" ")[-1] -ne $sbomToolVersion)) {
    Fail 2 "the pinned SBOM tool is missing: cargo install --locked --version =$sbomToolVersion --root target\tools cargo-cyclonedx"
}

$userHome = $env:USERPROFILE
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $userHome ".cargo" }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $userHome ".rustup" }
foreach ($p in $userHome, $cargoHome, $rustupHome, $repo) {
    if ($p -match "\s") { Fail 2 "a build path contains whitespace; the C path remap cannot express it" }
}

$clean = "yes"
if (git status --porcelain) {
    if (-not $AllowDirty) { Fail 2 "the tree is not clean (commit first, or -AllowDirty for a rehearsal)" }
    $clean = "no"
}
$env:TZ = "UTC"
$commitTime = (git show -s --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd HEAD).Trim()
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"$' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $version) { Fail 2 "no workspace version" }
# Release artifacts ship without the Iroh transport (ruling E2, option c): a source-build preview.
# The feature list is judged by `provenance.py check-features` before the build, the one
# authoritative check (review M08-W2-RC06), and what was compiled by `build-record` after it.

# rustc applies the last matching --remap-path-prefix, so the general one comes first.
$sep = [char]0x1f
$flags = @(
    "-Ctarget-feature=+crt-static",
    # Deterministic link (W2-6): without it the MSVC linker writes the link time into the PE
    # header and debug directory and a random PDB GUID, the only differences between PC
    # jobs 40 and 43.
    "-Clink-arg=/Brepro",
    "--remap-path-prefix=$userHome=/builder",
    "--remap-path-prefix=$rustupHome=/rustup",
    "--remap-path-prefix=$cargoHome=/cargo",
    "--remap-path-prefix=$repo=/heimdall"
)
$env:CARGO_ENCODED_RUSTFLAGS = $flags -join $sep
$flagsText = "-Ctarget-feature=+crt-static -Clink-arg=/Brepro --remap-path-prefix=<home>=/builder --remap-path-prefix=<rustup-home>=/rustup --remap-path-prefix=<cargo-home>=/cargo --remap-path-prefix=<checkout>=/heimdall"
# cl.exe: /d1trimfile strips a prefix from __FILE__; the static CRT for the bundled C code.
$env:CFLAGS_x86_64_pc_windows_msvc = "/MT /d1trimfile:$userHome\ /d1trimfile:$repo\"
if (-not $env:CARGO_BUILD_JOBS) { $env:CARGO_BUILD_JOBS = "4" }
$env:SOURCE_DATE_EPOCH = (git show -s --format=%ct HEAD).Trim()

$out = Join-Path $repo "target\release-artifacts"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$name = "heimdall-$version-$target"
$stage = Join-Path $out $name
if ($stage.StartsWith((Join-Path $repo "target\release-artifacts\heimdall-")) -and (Test-Path $stage)) { Remove-Item -Recurse -Force -LiteralPath $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
# The helper sits where the product looks for it: <exe dir>\<HELPER_DIR>\<HELPER_FILE>.
function SpawnConst([string]$n) {
    $m = Select-String -Path crates\wsl\src\spawn.rs -Pattern ('pub const ' + $n + ': &str = "(.*)";') | Select-Object -First 1
    if (-not $m) { Fail 2 "$n was not found in crates\wsl\src\spawn.rs" }
    $m.Matches[0].Groups[1].Value
}
$helperDir = Join-Path $stage (SpawnConst "HELPER_DIR")
New-Item -ItemType Directory -Force -Path $helperDir | Out-Null
$receipt = Join-Path $stage ".wsl-helper.json"
& python -I $provenance @helperArgs --out (Join-Path $helperDir (SpawnConst "HELPER_FILE")) --receipt $receipt
if ($LASTEXITCODE -ne 0) { Fail 2 "Linux WSL helper provenance check failed; nothing was built" }

$messages = Join-Path $out ".build-messages-$target.json"
# --no-default-features: the default feature `test-config` is the debug-build edge to the test
# kit (M08 U3c); a release artifact never has it.
$cargoArgs = @("build", "--release", "--locked", "--no-default-features", "-p", "heimdall", "--target", $target, "--message-format=json-render-diagnostics")
if ($Offline) { $cargoArgs += "--offline" }
if ($featureList) { $cargoArgs += @("--features", $featureList) }
$checkArgs = @("check-features", "--target", $target)
if ($featureList) { $checkArgs += @("--features", $featureList) }
if ($Offline) { $checkArgs += "--offline" }
& python -I $provenance @checkArgs
if ($LASTEXITCODE -ne 0) { Fail 2 "refused before the build; nothing was built" }
$started = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "== build-release: $target at $($commit.Substring(0,12)) (tree clean: $clean)"
# cargo's JSON goes to the file byte for byte (PC job 34). Piping `& cargo` through PowerShell
# would decode its stdout through the console code page and re-encode it, and Windows
# PowerShell 5.1's `Out-File -Encoding utf8` adds a byte order mark. `cmd /c ... >` would
# keep the bytes but needs the command line re-quoted for cmd. So the process is started
# directly, only its stdout is redirected, and the raw stream is copied to the file: no
# decoding, no BOM, no shell. The rendered diagnostics stay on the console (stderr).
$cargoExe = (Get-Command cargo -CommandType Application | Select-Object -First 1).Source
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $cargoExe
$psi.Arguments = $cargoArgs -join " "   # every argument is a fixed token or a checked feature list
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$sink = [System.IO.File]::Create($messages)
try { $proc.StandardOutput.BaseStream.CopyTo($sink) } finally { $sink.Dispose() }
$proc.WaitForExit()
if ($proc.ExitCode -ne 0) { Fail 1 "cargo build failed (exit $($proc.ExitCode))" }
$finished = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Exactly the executable this build produced, by the path cargo reported (review M08-W2-RC02).
$stageArgs = @("stage-exe", "--target", $target, "--build-messages", $messages, "--expect", (Join-Path $repo "target\$target\release\heimdall.exe"), "--out", (Join-Path $stage "heimdall.exe"))
if ($Offline) { $stageArgs += "--offline" }
& python -I $provenance @stageArgs
if ($LASTEXITCODE -ne 0) { Fail 1 "the executable to pack is not the one this build produced; nothing packed" }
$missing = @()
foreach ($f in "LICENSE", "SECURITY.md") { if (Test-Path $f) { Copy-Item $f (Join-Path $stage $f) } else { $missing += $f } }
if (Test-Path "$here\install.ps1") { Copy-Item "$here\install.ps1" (Join-Path $stage "install.ps1") } else { $missing += "install.ps1" }

function Py { & python -I $provenance @args; if ($LASTEXITCODE -ne 0) { exit 1 } }
$feat = @(); if ($featureList) { $feat = @("--features", $featureList) }
$off = @(); if ($Offline) { $off = @("--offline") }
Py stage-payload --stage $stage
Py sbom --target $target @feat @off --commit $commit --time $commitTime --tool $sbomTool --build-messages $messages --out (Join-Path $stage "heimdall-$target.cdx.json")
Py notices --target $target @feat @off --out (Join-Path $stage "THIRD-PARTY-NOTICES.txt")
Py build-record --target $target @feat @off --build-messages $messages --commit $commit --time $commitTime --clean $clean --flags $flagsText --signature "none (unsigned)" --helper-receipt $receipt --stage $stage --out (Join-Path $stage "BUILD-RECORD.json")
Py manifest --stage $stage
Remove-Item -Force -LiteralPath $messages

$forbid = [System.IO.Path]::GetTempFileName()
try {
    # The builder's paths and user name; the name is allowed only inside the exact macOS
    # login-entry label prefix (see build-release.sh).
    # A user name shorter than 4 characters would match ordinary text everywhere, so it is
    # not forbidden as a bare string; that is said, never done silently (as build-release.sh).
    $forbidden = @($userHome, $repo, $cargoHome, $rustupHome)
    if ($env:USERNAME -and $env:USERNAME.Length -ge 4) { $forbidden += $env:USERNAME } else { Write-Host "== note: the builder's user name is shorter than 4 characters and is not forbidden as a bare string" }
    $forbidden | Sort-Object -Unique | Set-Content -Encoding utf8 -LiteralPath $forbid
    $label = (Select-String -Path crates\runtime\src\autostart\render.rs -Pattern 'pub const LAUNCH_AGENT_LABEL_PREFIX: &str = "(.*)";' | Select-Object -First 1).Matches[0].Groups[1].Value
    if (-not $label) { Fail 2 "the login-entry label was not found" }
    & python -I "$here\verify_artifact.py" $stage --target $target --forbid-file $forbid --allow-exact $label @candidateArgs
    if ($LASTEXITCODE -ne 0) { Fail 1 "the staged tree failed verification; no archive written" }
    $archive = Join-Path $out "$name.zip"
    if (Test-Path $archive) { Remove-Item -Force -LiteralPath $archive }
    Py pack --stage $stage --time $commitTime --out $archive
    & python -I "$here\verify_artifact.py" $archive --target $target --forbid-file $forbid --allow-exact $label @candidateArgs
    if ($LASTEXITCODE -ne 0) { Remove-Item -Force -LiteralPath $archive; Fail 1 "the archive failed verification and was removed" }
    Copy-Item (Join-Path $stage "heimdall-$target.cdx.json") (Join-Path $out "$name.cdx.json")
    # The external copy adds the build's wall-clock start and finish (W2-6).
    Py external-record --record (Join-Path $stage "BUILD-RECORD.json") --started $started --finished $finished --out (Join-Path $out "$name.build-record.json")
    Py index --dir $out
    & python -I "$here\verify_artifact.py" $archive --target $target --forbid-file $forbid --allow-exact $label --index (Join-Path $out "SHA256SUMS") @candidateArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 1 "the archive does not match the external index" }
} finally {
    Remove-Item -Force -LiteralPath $forbid -ErrorAction SilentlyContinue
}
Write-Host "== archive: target\release-artifacts\$name.zip"
Write-Host "== sha256:  $((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLower())"
Write-Host "== index:   target\release-artifacts\SHA256SUMS (external; commit it, never pack it)"
if ($missing.Count -gt 0) { Write-Host "== not yet in the tree, so not packaged: $($missing -join ' ')" }
