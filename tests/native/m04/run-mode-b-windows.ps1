#Requires -Version 7.2
<#
.SYNOPSIS
M04 WSL Mode B native rows (ADR-0010 §3, §9 item 10 Q3, §11; m04-plan U4, A13 and A12) on the
Windows PC, in two disposable WSL distributions this script creates and removes itself.

.DESCRIPTION
Runs ON the PC (pwsh 7.2 or later), not elevated. Its steps:
  1. Check the inputs before anything is created: the commit (40 hex), the scratch root (an
     existing directory, not a reparse point), the Linux x86-64 `heimdall` cross-built on the
     build host (-PrebuiltHeimdall / HM_PREBUILT_HEIMDALL) and its sha256 (-PrebuiltSha256 /
     HM_PREBUILT_SHA256: a missing input is exit 3, a malformed digest exit 2, a mismatch exit 1),
     and the pinned Ubuntu image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1: the
     M02 pin, tests/native/m02/run-wsl-distro.sh). Installing packages inside the distributions
     needs -AllowApt / HM_WSL_ALLOW_APT=1 (only inside the distributions this run created).
  2. Create the run directory <ScratchRoot>\hm-m04-modeb-<random> exclusively and give it the
     protected stock profile list (the user, SYSTEM, Administrators; ADR-0010 §11), recording
     its SDDL with the SIDs redacted; TEMP and TMP point inside it.
  3. Record the registered distributions (`wsl --list --verbose`; only this run's are recorded by
     name, the others as a count and a digest). Choose the names hm-m04-<8 hex>-1 and -2 and
     refuse when either is registered already.
  4. Clone the repository at exactly the commit, install the pinned toolchain into the run
     directory (RUSTUP_HOME and CARGO_HOME there, --no-modify-path), and build the test targets.
  5. Import both distributions from the pinned image into the run directory, as WSL 2. In each,
     as root: `[boot] systemd=false` (then a terminate), tests/native/m02/target-root.sh
     `prepare` (the tools, git and python3; one non-root user, hmtest), and `[user] default`
     set to that user (then a terminate).
  6. Start the harness sshd in the second distribution as hmtest (tests/native/m02/remote-lib.sh
     hm2_sshd_start, as the M02/M03 Windows runner does in its WSL scratch): its authorized-keys
     file and log in the run directory, its enrollment registry owner-only in hmtest's home,
     reachable from Windows and from the first distribution on 127.0.0.1. The tests get the
     HM_FIXTURE_SSHD_* variables.
  7. Run, from the clone, in this order, each with its real exit code and its `test result:` line:
       a. the A13 set: e2e_platform_m04 windows::native::mode_b::a13_ (ignored tests, one thread),
          except the unregister row;
       b. the A12 set: e2e_platform_m04 windows::native::a12_;
       c. the helper-session test: heimdall-wsl windows_helper_session_over_wsl_exe_in_a_disposable_distribution;
       d. LAST and ALONE, with HM_WSL_TEST_ALLOW_UNREGISTER=1: a13_unregistered_distribution_releases_bindings,
          which unregisters the second distribution itself.
  8. Always (finally): stop the harness sshd by its recorded PID, start time and configuration
     (hm2_stop_recorded) when its distribution still exists; terminate and unregister ONLY the
     distributions this run created, by exact name (each re-checked against the pattern, the
     before-list and the current list; the unregister row may have removed -2 already; never
     `wsl --shutdown`); check that the registered set equals the one before; remove the clone,
     the toolchain, the build and the distributions' directories.
  9. Keep, as the run goes, the plain results (results.txt: each command's `### <name> exit=N`,
     its tests' outcomes and its `test result:` lines, then the run's exit; names and counts only)
     and print them, so the verdict survives a failed bundle. Then write one redacted bundle (no
     environment dump): tests.txt, commands.txt, host.txt,
     build.txt, skipped.txt, distributions.txt, canary-scan.txt, as bundle.json and its
     gzip+base64 rendering bundle.b64, printed between markers.

The redaction, canary masking, leak scan and bundle functions are tests/native/m02/run-windows-local.ps1's
own (loaded from its definitions, never run as a script), so the two runners redact alike.

.PARAMETER DryRun
Check the inputs that can be checked here, print the plan (names, steps, commands) and exit:
nothing is created, no distribution, network, toolchain or build step runs. Runs anywhere.

.PARAMETER SelfTest
The pure helpers on synthetic data (no host, no network, no WSL), and `bash -n` of every script
this runner sends into a distribution when bash is available. Runs anywhere; exit 0 when every
check passed.

.EXAMPLE
pwsh -NoProfile -File tests\native\m04\run-mode-b-windows.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m04 `
    -PrebuiltHeimdall C:\hm\heimdall -PrebuiltSha256 <64-hex> -Rootfs C:\hm\ubuntu-24.04.5-wsl-amd64.wsl -AllowApt
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$ScratchRoot,
    [string]$RepoUrl = 'https://github.com/amanthanvi/heimdall',
    [string]$PrebuiltHeimdall = $env:HM_PREBUILT_HEIMDALL,
    [string]$PrebuiltSha256 = $env:HM_PREBUILT_SHA256,
    [string]$Rootfs = $env:HM_WSL_ROOTFS,
    [switch]$Download = ($env:HM_WSL_DOWNLOAD -eq '1'),
    [switch]$AllowApt = ($env:HM_WSL_ALLOW_APT -eq '1'),
    [int]$TimeoutSeconds = 5400,
    [string]$Label = 'windows-11-x86_64 (native msvc, M04 Mode B, two disposable distributions)',
    [switch]$DryRun,
    [switch]$SelfTest,
    [string]$Out = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$BundleFormat = 'heimdall-m04-mode-b-windows-bundle/1'
$BeginMarker = '-----BEGIN HEIMDALL M04 MODE B WINDOWS BUNDLE-----'
$EndMarker = '-----END HEIMDALL M04 MODE B WINDOWS BUNDLE-----'
$BundleFiles = @('tests.txt', 'commands.txt', 'host.txt', 'build.txt', 'skipped.txt', 'distributions.txt', 'canary-scan.txt')
# The M02 pin (tests/native/m02/run-wsl-distro.sh): the only image this runner imports.
$RootfsUrl = 'https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl'
$RootfsSha256 = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
$User = 'hmtest'

# ---------------------------------------------------------------------------------------------
# The M02 runner's pure helpers, loaded from their definitions (its main body never runs).
# ---------------------------------------------------------------------------------------------

$m02Runner = Join-Path $PSScriptRoot '..\m02\run-windows-local.ps1'
$m02Helpers = @('New-RandomHex', 'Get-Sha256Hex', 'New-RedactionRule', 'Get-RedactionForms', 'Invoke-Redaction',
    'Get-CanaryCount', 'Hide-Canary', 'Get-LeakCount', 'Format-TargetOutput', 'Format-CommandLine', 'New-Bundle',
    'Protect-BundleFiles', 'Get-ProtectedMetadata', 'Get-ToolEnvironmentOverrides', 'Get-CrlfFileCount',
    'Get-SshdAtEnd', 'Get-SshdStartScript', 'Get-SshdStopScript', 'Test-PlainAccount', 'Get-FixtureEnvironment',
    'Get-RunRedactionRules', 'Test-SshdAtEndOk', 'Get-StockProfileGrantArguments')
$parseErrors = $null
$m02Ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $m02Runner).Path, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'tests/native/m02/run-windows-local.ps1 does not parse' }
foreach ($f in $m02Ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    if ($m02Helpers -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
foreach ($n in $m02Helpers) {
    if (-not (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue)) { throw "the M02 helper $n is missing" }
}

# ---------------------------------------------------------------------------------------------
# This runner's pure helpers (exercised by -SelfTest)
# ---------------------------------------------------------------------------------------------

# The two distribution names of a run: hm-m04-<8 hex>-1 and -2.
function Get-DistributionNames([string]$Hex) {
    return @("hm-m04-$Hex-1", "hm-m04-$Hex-2")
}

# Whether Name is a distribution name this runner makes.
function Test-OwnDistributionName([string]$Name) {
    return ($Name -cmatch '^hm-m04-[0-9a-f]{8}-[12]\z')
}

# The names in `wsl --list --quiet` output (UTF-8 or UTF-16 noise removed, blank lines dropped).
function ConvertFrom-WslList([string]$Text) {
    return @(($Text -replace "`0", '' -replace "`r", '') -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Which of Created may be unregistered now: this run's pattern, absent from the list taken
# before the run, and registered now. Nothing else is ever unregistered.
function Select-RemovableDistributions([string[]]$Created, [string[]]$Before, [string[]]$Now) {
    return @($Created | Where-Object {
            (Test-OwnDistributionName $_) -and -not ($Before -contains $_) -and ($Now -contains $_)
        })
}

# ⟨M04 fix re-check, M04-FX-RC03⟩ Which install directories of the run's attempted imports are
# kept after cleanup: one whose name is still registered, or every one when the listing after
# cleanup could not be read ($Now is $null). A directory is removed only once its distribution
# is known to be unregistered.
function Select-KeptInstallDirectories([string[]]$Attempted, $Now) {
    if ($null -eq $Now) { return @($Attempted) }
    return @($Attempted | Where-Object { $Now -contains $_ })
}

# Whether two registered sets are equal (order and case of the listing aside).
function Test-SameSet([string[]]$A, [string[]]$B) {
    $x = @($A | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    $y = @($B | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    return (($x -join "`n") -ceq ($y -join "`n"))
}

# The distribution facts kept: this run's lines of `wsl --list --verbose` by name, the others
# only as a count and a digest (their names may be the owner's own).
function Get-DistributionFacts([string]$Verbose, [string[]]$Own) {
    $mine = [System.Collections.Generic.List[string]]::new()
    $others = [System.Collections.Generic.List[string]]::new()
    foreach ($l in ($Verbose -replace "`0", '' -replace "`r", '' -split "`n")) {
        $t = $l.Trim().TrimStart('*').Trim()
        if (-not $t -or $t -match '^NAME\s+STATE') { continue }
        $name = ($t -split '\s+')[0]
        if ($Own -contains $name) { $mine.Add(($t -replace '\s+', ' ')) } else { $others.Add($t.ToLowerInvariant()) }
    }
    $digest = (Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes((($others | Sort-Object) -join "`n")))).Substring(0, 12)
    return [pscustomobject]@{ Own = @($mine); OtherCount = $others.Count; OtherDigest = $digest }
}

# The `test result:` lines of libtest output (one per test binary run).
function Get-TestResultLines([string]$Output) {
    return @(($Output -replace "`r", '') -split "`n" | Where-Object { $_ -match '^test result: ' })
}

# ⟨Windows run at 37cb179b⟩ One command's plain result lines: `### <name> exit=N`, each
# `test <name> ... <outcome>` line and each `test result:` line of its output. Names, outcomes
# and counts only (no path, no user, no host), so they are printed as the run goes and kept in
# results.txt before bundling: the run's verdict survives a failed bundle.
function Format-ResultLines([string]$Name, [int]$Code, [string]$Output) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("### $Name exit=$Code")
    foreach ($l in (($Output -replace "`r", '') -split "`n")) {
        if ($l -match '^test (\S+) \.\.\. (ok|FAILED|ignored)\b') { $lines.Add("test $($Matches[1]) ... $($Matches[2])") }
        elseif ($l -match '^test result: ') { $lines.Add($l.Trim()) }
    }
    return ($lines -join "`n") + "`n"
}

# The test commands, in order (step 7). Each: a name, the cargo arguments, and whether it needs
# HM_WSL_TEST_ALLOW_UNREGISTER=1 (only the last).
function Get-TestPlan {
    $unregister = 'a13_unregistered_distribution_releases_bindings'
    return @(
        [pscustomobject]@{ Name = 'a13-mode-b'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', 'windows::native::mode_b::a13_', '--skip', $unregister, '--show-output') },
        [pscustomobject]@{ Name = 'a12-mode-a'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', 'windows::native::a12_', '--show-output') },
        [pscustomobject]@{ Name = 'wsl-helper-session'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall-wsl', '--lib', '--',
                '--ignored', 'windows_helper_session_over_wsl_exe_in_a_disposable_distribution', '--show-output') },
        [pscustomobject]@{ Name = 'a13-unregister'; Unregister = $true; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--exact', "windows::native::mode_b::$unregister", '--show-output') }
    )
}

# The scripts sent into a distribution (bash, on stdin). Each runs as `bash -s -- <args>`.
function Get-DistroScripts {
    return [ordered]@{
        # As root: target-root.sh PHASE from the Windows copy of the files directory.
        # $1 the files directory (Windows path), $2 the distribution's name, then the phase's own
        # arguments; for `prepare` the files directory is appended as the phase expects.
        'root-phase' = @'
set -u
files=$(wslpath -u "$1") || exit 2
name=$2
phase=$3
shift 3
case "$phase" in
    prepare) exec /bin/bash "$files/target-root.sh" "$name" prepare "$@" "$files" </dev/null ;;
    *) exec /bin/bash "$files/target-root.sh" "$name" "$phase" "$@" </dev/null ;;
esac
'@
        # As root: `[user] default=$2` in /etc/wsl.conf, refusing outside the named distribution.
        'default-user' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
id -u "$2" >/dev/null 2>&1 || { echo "no such user" >&2; exit 1; }
python3 -I - /etc/wsl.conf "$2" <<'PY' || exit 1
import configparser, sys
path, user = sys.argv[1], sys.argv[2]
c = configparser.ConfigParser()
c.optionxform = str
c.read(path)
if not c.has_section("user"):
    c.add_section("user")
c.set("user", "default", user)
with open(path, "w") as f:
    c.write(f)
PY
echo "wsl-conf-user-default=set"
'@
        # As the non-root user: the harness sshd's directory in its home (owner-only), and the
        # facts the redaction needs (never printed into the bundle as such).
        'sshd-dir' = @'
set -u
d="$HOME/$1"
mkdir -m 700 -- "$d" || exit 1
echo "created=$d"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
'@
        # As the non-root user: remove exactly the harness sshd's directory.
        'sshd-dir-remove' = @'
set -u
case "$1" in "$HOME"/hm-m04-fx-*) rm -rf -- "$1" && test ! -e "$1" ;; *) exit 2 ;; esac
'@
    }
}

# ---------------------------------------------------------------------------------------------
# -SelfTest
# ---------------------------------------------------------------------------------------------

function Invoke-SelfTest {
    $script:stPass = 0
    $script:stFail = 0
    function Check([string]$Name, [bool]$Ok) {
        if ($Ok) { Write-Host "ok   $Name"; $script:stPass++ } else { Write-Host "FAIL $Name"; $script:stFail++ }
    }
    $names = Get-DistributionNames '0a1b2c3d'
    Check 'N01 two names, hm-m04-<8 hex>-1 and -2' ($names[0] -ceq 'hm-m04-0a1b2c3d-1' -and $names[1] -ceq 'hm-m04-0a1b2c3d-2')
    Check 'N02 only this runner''s pattern is its own' ((Test-OwnDistributionName 'hm-m04-0a1b2c3d-2') -and -not (Test-OwnDistributionName 'hm-m04-0A1B2C3D-1') -and
        -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d-3') -and -not (Test-OwnDistributionName 'Ubuntu') -and -not (Test-OwnDistributionName 'hm-m03-0a1b2c3d') -and
        -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d-1 ') -and -not (Test-OwnDistributionName "hm-m04-0a1b2c3d-1`n"))
    $parsed = @(ConvertFrom-WslList "Ubuntu`r`n`r`nhm-m04-0a1b2c3d-1`r`nDeb`0ian`n")
    Check 'N03 the quiet list parses (CR, NUL and blank lines removed)' (($parsed -join ',') -ceq 'Ubuntu,hm-m04-0a1b2c3d-1,Debian')
    $before = @('Ubuntu', 'hm-m04-0a1b2c3d-2')
    $now = @('Ubuntu', 'hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2', 'hm-m04-ffffffff-1')
    $rm = @(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2', 'Ubuntu', 'hm-m04-99999999-1') $before $now)
    Check 'C01 cleanup removes only a created name of the pattern, absent before, registered now' (($rm -join ',') -ceq 'hm-m04-0a1b2c3d-1')
    Check 'C02 a created name already gone (the unregister row removed it) is not unregistered again' (@(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1') @() @('Ubuntu')).Count -eq 0)
    Check 'C04 an import recorded only as attempted (its listing failed, or Ctrl-C landed before it was recorded) is still unregistered when it is registered' (
        (@(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1') @('Ubuntu') @('Ubuntu', 'hm-m04-0a1b2c3d-1')) -join ',') -ceq 'hm-m04-0a1b2c3d-1')
    Check 'C05 an install directory is kept while its distribution is registered, and all are kept when the listing is unreadable' (
        ((Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2') @('Ubuntu', 'hm-m04-0a1b2c3d-2')) -join ',') -ceq 'hm-m04-0a1b2c3d-2' -and
        ((Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2') $null) -join ',') -ceq 'hm-m04-0a1b2c3d-1,hm-m04-0a1b2c3d-2' -and
        @(Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1') @('Ubuntu')).Count -eq 0)
    Check 'C03 the registered set compares as a set' ((Test-SameSet @('Ubuntu', 'Debian') @('debian', 'Ubuntu')) -and -not (Test-SameSet @('Ubuntu') @('Ubuntu', 'hm-m04-0a1b2c3d-1')))
    $verbose = "  NAME                 STATE           VERSION`r`n* OwnersBox            Running         2`r`n  hm-m04-0a1b2c3d-1    Stopped         2`r`n  Personal-Name        Stopped         2`r`n"
    $facts = Get-DistributionFacts $verbose @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2')
    Check 'D01 only this run''s distributions are recorded by name; the others as a count and digest' (
        ($facts.Own -join '|') -ceq 'hm-m04-0a1b2c3d-1 Stopped 2' -and $facts.OtherCount -eq 2 -and $facts.OtherDigest.Length -eq 12)
    $facts2 = Get-DistributionFacts ($verbose -replace 'Running', 'Stopped') @('hm-m04-0a1b2c3d-1')
    Check 'D02 the digest of the others follows their state, never their names in the bundle' ($facts2.OtherDigest -ne $facts.OtherDigest)
    $libtestOut = "running 2 tests`r`ntest a ... ok`r`ntest result: ok. 2 passed; 0 failed; 0 ignored`r`n`r`ntest result: ok. 0 passed; 0 failed`r`n"
    $lines = @(Get-TestResultLines $libtestOut)
    Check 'T01 the test result lines' ($lines.Count -eq 2 -and $lines[0] -ceq 'test result: ok. 2 passed; 0 failed; 0 ignored')
    $plan = Get-TestPlan
    Check 'P01 four commands: A13, A12, the helper session, then the unregister row' ((($plan | ForEach-Object Name) -join ',') -ceq 'a13-mode-b,a12-mode-a,wsl-helper-session,a13-unregister')
    Check 'P02 only the last carries HM_WSL_TEST_ALLOW_UNREGISTER, and it runs that one test exactly' (
        (@($plan | Where-Object Unregister).Count -eq 1) -and $plan[3].Unregister -and ($plan[3].Args -contains '--exact') -and
        ($plan[3].Args -contains 'windows::native::mode_b::a13_unregistered_distribution_releases_bindings'))
    Check 'P03 the A13 set skips the unregister row and runs on one thread' (($plan[0].Args -contains '--skip') -and
        ($plan[0].Args -contains 'a13_unregistered_distribution_releases_bindings') -and ($plan[0].Args -contains '--test-threads=1'))
    Check 'P04 every command runs only ignored tests (the native rows), --locked' (@($plan | Where-Object { ($_.Args -contains '--ignored') -and ($_.Args -contains '--locked') }).Count -eq 4)
    $rules = Get-RunRedactionRules @{ wslhost = 'PCNAME' } 'C:\S\hm-m04-modeb-00' 'C:\Users\fixtureuser' 'fixtureuser' 'PCNAME' 'pcname.example'
    $p = Protect-BundleFiles @{ 'host.txt' = "home C:\Users\fixtureuser\x on PCNAME run C:\S\hm-m04-modeb-00\src`n" } $rules
    Check 'R01 the M02 redaction applies (home, user, host, run directory)' ($p.Files['host.txt'] -ceq "home <winhome>\x on <winhost> run <run>\src`n" -and $p.Leaks -eq 0)
    Check 'A01 the run root gets the stock list from the M02 runner''s helper' (
        ((Get-StockProfileGrantArguments 'S\run' 'S-1-5-21-1-2-3-1001') -join ' ') -ceq 'S\run /inheritance:r /grant:r *S-1-5-21-1-2-3-1001:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F')
    # ⟨Windows run at 37cb179b⟩ The file table as the run builds it: every bundle file, through
    # the same protection; `.Files` stays a table that a variable holds and indexes.
    $realistic = @{}
    foreach ($f in $BundleFiles) { $realistic[$f] = "### x`nhome C:\Users\fixtureuser\y`n" }
    $prot = Protect-BundleFiles $realistic $rules
    $table = $prot.Files
    $table['canary-scan.txt'] = 'n'
    Check 'B02 Protect-BundleFiles returns one object whose .Files is a table every bundle file can be indexed in' (
        $prot -isnot [array] -and $table -is [System.Collections.IDictionary] -and @($table.Keys).Count -eq $BundleFiles.Count -and
        $table['canary-scan.txt'] -ceq 'n' -and $table['commands.txt'].Contains('<winhome>'))
    $rl = Format-ResultLines 'a13-mode-b' 101 "running 2 tests`r`ntest windows::native::mode_b::a13_x ... ok`r`ntest windows::native::mode_b::a13_y ... FAILED`r`n  at C:\Users\fixtureuser\z`r`ntest result: FAILED. 1 passed; 1 failed; 0 ignored`r`n"
    Check 'B03 the plain result lines: the command and its exit, each test''s outcome, the result line, and nothing else' (
        $rl -ceq "### a13-mode-b exit=101`ntest windows::native::mode_b::a13_x ... ok`ntest windows::native::mode_b::a13_y ... FAILED`ntest result: FAILED. 1 passed; 1 failed; 0 ignored`n")
    $b = New-Bundle @{ 'tests.txt' = 'x'; 'distributions.txt' = 'y' } @{ commit = ('0' * 40); exit = 0 }
    Check 'B01 the bundle carries this runner''s format and markers' ($b.Json.Contains($BundleFormat) -and $b.Text.StartsWith($BeginMarker) -and $b.Text.TrimEnd().EndsWith($EndMarker))
    # ⟨Windows run at 39f48be8⟩ No assignment in this script to a parameter's name: PowerShell
    # names are case-insensitive, so `$out = <hashtable>` turned into the [string] `-Out`.
    $selfAst = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)
    $paramNames = @($selfAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() })
    $clashes = @($selfAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
            Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                ($paramNames -contains $_.Left.VariablePath.UserPath.ToLowerInvariant()) })
    Check 'S02 nothing assigns to a parameter''s name (case-insensitive)' ($clashes.Count -eq 0)
    # bash -n of every script sent into a distribution (and the M02 sshd start and stop scripts).
    $bash = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $bash) {
        $scripts = Get-DistroScripts
        $scripts['sshd-start (M02)'] = Get-SshdStartScript
        $scripts['sshd-stop (M02)'] = Get-SshdStopScript
        foreach ($k in $scripts.Keys) {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tmp, ($scripts[$k] -replace "`r`n", "`n"))
                & $bash.Source -n $tmp 2>$null
                Check "S01 bash -n: $k" ($LASTEXITCODE -eq 0)
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    } else {
        Write-Host 'skip S01 bash -n (no bash on PATH)'
    }
    Write-Host "selftest: $script:stPass passed, $script:stFail failed"
    if ($script:stFail -ne 0) { exit 1 }
    exit 0
}

if ($SelfTest) { Invoke-SelfTest }

# ---------------------------------------------------------------------------------------------
# Inputs (step 1): nothing is created before these pass.
# ---------------------------------------------------------------------------------------------

function Stop-Run([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("run-mode-b-windows: $Message")
    exit $Code
}

if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Run 2 '-Commit must be the 40-hex commit' }
if ($TimeoutSeconds -lt 600) { Stop-Run 2 '-TimeoutSeconds must be at least 600' }
if ([string]::IsNullOrWhiteSpace($PrebuiltHeimdall)) { Stop-Run 3 'blocked: set -PrebuiltHeimdall (HM_PREBUILT_HEIMDALL) to the Linux heimdall cross-built on the build host' }
if ([string]::IsNullOrWhiteSpace($PrebuiltSha256)) { Stop-Run 3 'blocked: set -PrebuiltSha256 (HM_PREBUILT_SHA256) to the digest the build host recorded' }
$wantSha = $PrebuiltSha256.Trim().ToLowerInvariant()
if ($wantSha -notmatch '^[0-9a-f]{64}$') { Stop-Run 2 'bad -PrebuiltSha256 (64 hex digits)' }
if (-not $Rootfs -and -not $Download) { Stop-Run 3 'blocked: the pinned image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1)' }

if ($DryRun) {
    $hex = New-RandomHex 4
    $plan = Get-TestPlan
    Write-Output 'dry run: nothing is created, no distribution, network, toolchain or build step runs'
    Write-Output "commit=$Commit"
    Write-Output "run-directory=<ScratchRoot>\hm-m04-modeb-<random>"
    Write-Output "distributions=$((Get-DistributionNames $hex) -join ' ') (refused when either is registered)"
    Write-Output "image=$(if ($Rootfs) { 'HM_WSL_ROOTFS' } else { "download $RootfsUrl" }) sha256 $RootfsSha256"
    Write-Output "apt-inside-the-distributions=$(if ($AllowApt) { 'allowed' } else { 'not allowed (missing tools stop the run, exit 3)' })"
    Write-Output "prebuilt-heimdall=$(if (Test-Path -LiteralPath $PrebuiltHeimdall -PathType Leaf) { 'present' } else { 'not found here' })"
    Write-Output "user=$User (non-root, in both distributions)"
    Write-Output 'harness-sshd=in -2 as the user (hm2_sshd_start), HM_FIXTURE_SSHD_* exported'
    foreach ($s in $plan) {
        $extra = if ($s.Unregister) { ' [HM_WSL_TEST_ALLOW_UNREGISTER=1; last, alone]' } else { '' }
        Write-Output "test $($s.Name): cargo $($s.Args -join ' ')$extra"
    }
    Write-Output 'cleanup=hm2_stop_recorded for the sshd; terminate + unregister only this run''s distributions by exact name; registered set compared; run directories removed'
    exit 0
}

if (-not $IsWindows) { Stop-Run 2 'run-mode-b-windows.ps1 runs on the Windows PC itself (use -DryRun or -SelfTest elsewhere)' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Run 2 'refusing to run elevated: this runner never needs administrator rights'
}
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) { Stop-Run 2 '-ScratchRoot is required' }
# Created when missing (with its missing parents); an existing one is checked as it is.
if (-not (Test-Path -LiteralPath $ScratchRoot)) { [void][System.IO.Directory]::CreateDirectory($ScratchRoot) }
$rootItem = Get-Item -LiteralPath $ScratchRoot -Force -ErrorAction SilentlyContinue
if ($null -eq $rootItem -or -not $rootItem.PSIsContainer) { Stop-Run 2 '-ScratchRoot must be an existing directory' }
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Run 2 '-ScratchRoot is a reparse point: refused' }
$helperItem = Get-Item -LiteralPath $PrebuiltHeimdall -Force -ErrorAction SilentlyContinue
if ($null -eq $helperItem -or $helperItem.PSIsContainer) { Stop-Run 3 'blocked: -PrebuiltHeimdall is not a regular file' }
$haveSha = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($helperItem.FullName))
if ($haveSha -ne $wantSha) { Stop-Run 1 "prebuilt heimdall sha256 mismatch: file $haveSha, expected $wantSha; nothing created" }
if ($Rootfs) {
    $rootfsItem = Get-Item -LiteralPath $Rootfs -Force -ErrorAction SilentlyContinue
    if ($null -eq $rootfsItem -or $rootfsItem.PSIsContainer) { Stop-Run 3 'blocked: -Rootfs is not a file' }
    if ((Get-Sha256Hex ([System.IO.File]::ReadAllBytes($rootfsItem.FullName))) -ne $RootfsSha256) { Stop-Run 3 'the image is not the pinned one (sha256 mismatch); nothing created' }
}

# ---------------------------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------------------------

$sys32 = Join-Path $env:SystemRoot 'System32'
$wslExe = Join-Path $sys32 'wsl.exe'
$run = Join-Path $rootItem.FullName ('hm-m04-modeb-' + (New-RandomHex 6))
if (Test-Path -LiteralPath $run) { Stop-Run 2 'the run directory exists already' }
[void][System.IO.Directory]::CreateDirectory($run)
# The stock profile list on this run's root before anything is created inside it (ADR-0010 §11;
# the M02 runner's Get-StockProfileGrantArguments); recorded below, its SIDs redacted.
$stockOut = (& (Join-Path $env:SystemRoot 'System32\icacls.exe') @(Get-StockProfileGrantArguments $run ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 2>&1 | Out-String)
$stockRc = $LASTEXITCODE
$src = Join-Path $run 'src'
$tools = Join-Path $run 'toolchain'
$wtmp = Join-Path $run 'tmp'
$files = Join-Path $run 'files'
$distroRoot = Join-Path $run 'distros'
$sshdDir = Join-Path $run 'sshd'
$bundleDir = Join-Path $run 'bundle'
$githome = Join-Path $run 'githome'
foreach ($d in @($tools, $wtmp, $files, $distroRoot, $sshdDir, $bundleDir, $githome)) { [void][System.IO.Directory]::CreateDirectory($d) }
$resultsFile = Join-Path $bundleDir 'results.txt'
$emptyGitConfig = Join-Path $githome 'empty.gitconfig'
[System.IO.File]::WriteAllText($emptyGitConfig, '')

$started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$commands = [System.Text.StringBuilder]::new()
$hostFacts = [System.Text.StringBuilder]::new()
$tests = [System.Text.StringBuilder]::new()
$build = [System.Text.StringBuilder]::new()
$skipped = [System.Text.StringBuilder]::new()
$distFacts = [System.Text.StringBuilder]::new()
$overall = 0
$created = [System.Collections.Generic.List[string]]::new()
# ⟨M04-FX-RC03⟩ Every name an import was started for, recorded before the import runs.
$attempted = [System.Collections.Generic.List[string]]::new()
$before = @()
$names = @()
$sshdProc = $null
$sshdErr = $null
$sshdWslDir = ''
$wv = @{}
$remoteLib = ''
$scripts = Get-DistroScripts

function Add-Command([int]$Rc, [string]$What) { [void]$commands.Append((Format-CommandLine $Rc $What)) }
function Add-Fact([string]$Key, [string]$Value) { [void]$hostFacts.Append("$Key=$(($Value -replace "`r", '') -split "`n" | Select-Object -First 1)`n") }

# An environment for a child: the inherited one without agent, askpass, Git, Heimdall, fixture,
# WSL test, repository and toolchain variables, plus Set.
function New-ChildEnvironment([hashtable]$Set) {
    $envs = @{}
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$e.Key
        if ($k -match '^(GIT_|HEIMDALL_|HM_|SSH_AUTH_SOCK$|SSH_AGENT_PID$|SSH_ASKPASS|RUSTUP_|CARGO|WSLENV$)') { continue }
        $envs[$k] = [string]$e.Value
    }
    foreach ($k in $Set.Keys) { $envs[$k] = [string]$Set[$k] }
    return $envs
}

# Run a program (no shell) with an environment and a timeout; on a timeout the process tree this
# call started is killed through its own handle.
function Invoke-Bounded([string]$File, [string[]]$Arguments, [hashtable]$Environment, [string]$Cwd, [int]$Seconds, [string]$StdIn = $null) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($File)
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Cwd
    if ($null -ne $Environment) {
        $psi.Environment.Clear()
        foreach ($k in $Environment.Keys) { $psi.Environment[$k] = $Environment[$k] }
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if ($null -ne $StdIn) { $p.StandardInput.Write(($StdIn -replace "`r`n", "`n")) }
    $p.StandardInput.Close()
    $timedOut = -not $p.WaitForExit($Seconds * 1000)
    if ($timedOut) { $p.Kill($true); $p.WaitForExit() }
    $p.WaitForExit()
    $code = if ($timedOut) { 124 } else { $p.ExitCode }
    $text = $o.Result + $e.Result
    if ($timedOut) { $text += "`n(timed out after $Seconds s; the process tree this run started was stopped)`n" }
    $p.Dispose()
    return [pscustomobject]@{ Code = $code; Output = $text; TimedOut = $timedOut }
}

$wslEnv = New-ChildEnvironment @{ WSL_UTF8 = '1' }
# wsl.exe itself (list, import, terminate, unregister): never `--shutdown`.
function Invoke-WslExe([string[]]$Arguments, [int]$Seconds = 600) {
    return Invoke-Bounded $wslExe $Arguments $wslEnv $run $Seconds
}
# A script inside one of this run's distributions, as Account, on stdin.
function Invoke-InDistro([string]$Name, [string]$Account, [string]$Script, [string[]]$ScriptArgs, [int]$Seconds = 1800) {
    if (-not ($names -contains $Name)) { throw 'refusing a distribution this run did not create' }
    return Invoke-Bounded $wslExe (@('-d', $Name, '-u', $Account, '--exec', '/bin/bash', '-s', '--') + $ScriptArgs) $wslEnv $run $Seconds $Script
}
function Get-Registered { return ConvertFrom-WslList (Invoke-WslExe @('--list', '--quiet') 120).Output }
# ⟨M04-FX-RC03⟩ The registered names, or $null when the listing failed.
function Get-RegisteredOrNull {
    $r = Invoke-WslExe @('--list', '--quiet') 120
    if ($r.Code -ne 0) { return $null }
    return , @(ConvertFrom-WslList $r.Output)
}
function Add-DistributionFacts([string]$When) {
    $v = Invoke-WslExe @('--list', '--verbose') 120
    $f = Get-DistributionFacts $v.Output $names
    [void]$distFacts.Append("$When`: exit $($v.Code); this run's: $(if ($f.Own.Count) { $f.Own -join '; ' } else { 'none' }); others: $($f.OtherCount) (digest $($f.OtherDigest))`n")
}

$gitEnv = New-ChildEnvironment @{ GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $emptyGitConfig; GIT_TERMINAL_PROMPT = '0'; HOME = $githome }
$git = (Get-Command 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($null -eq $git) { Stop-Run 2 'git.exe is not on PATH' }
$git = $git.Source

try {
    Add-Command $stockRc 'icacls: the run root gets the protected stock profile list (the user, SYSTEM, Administrators; inherited by what is created inside)'
    if ($stockRc -ne 0) { [void]$build.Append($stockOut); throw 'the run root''s list could not be set' }
    Add-Fact 'run-root-sddl' ((Get-Acl -LiteralPath $run).Sddl)
    Add-Fact 'os' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ver') $null $run 30).Output.Trim())
    $groups = (Invoke-Bounded (Join-Path $sys32 'whoami.exe') @('/groups') $null $run 30).Output
    Add-Fact 'integrity' ([regex]::Match($groups, '(Medium|High|System) Mandatory Level').Value)
    Add-Fact 'wsl-version' (((Invoke-WslExe @('--version') 60).Output -replace "`0", '' -split "`n" | Select-Object -First 1).Trim())
    Add-Fact 'prebuilt-heimdall-sha256' "$haveSha (equals HM_PREBUILT_SHA256)"
    Add-Command 0 "prebuilt heimdall sha256 equals HM_PREBUILT_SHA256 ($haveSha)"

    # 3. The registered set, and this run's names.
    $before = @(Get-Registered)
    $names = Get-DistributionNames (New-RandomHex 4)
    Add-DistributionFacts 'before'
    if (@($names | Where-Object { $before -contains $_ }).Count -ne 0) { throw 'a distribution with this run''s name is registered already; nothing imported' }
    Add-Command 0 'wsl --list: neither of this run''s names is registered'

    # 4. The clone at exactly the commit, the pinned toolchain in scratch, the build.
    $r = Invoke-Bounded $git @('-c', 'credential.helper=', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', 'clone', '--quiet', '--no-checkout', $RepoUrl, $src) $gitEnv $run 1800
    Add-Command $r.Code 'git clone of the repository into the run directory'
    [void]$build.Append($r.Output)
    if ($r.Code -ne 0) { throw 'clone failed' }
    foreach ($kv in @(@('core.autocrlf', 'false'), @('core.longpaths', 'true'))) {
        $r = Invoke-Bounded $git @('-C', $src, 'config', '--local', $kv[0], $kv[1]) $gitEnv $run 60
        if ($r.Code -ne 0) { throw "git config $($kv[0]) failed" }
    }
    $r = Invoke-Bounded $git @('-C', $src, 'checkout', '--quiet', '--detach', $Commit) $gitEnv $run 600
    Add-Command $r.Code 'git checkout --detach <commit>'
    if ($r.Code -ne 0) { throw 'checkout failed' }
    $head = (Invoke-Bounded $git @('-C', $src, 'rev-parse', 'HEAD') $gitEnv $run 60).Output.Trim()
    Add-Command $(if ($head -eq $Commit) { 0 } else { 1 }) 'the clone is at exactly the commit'
    if ($head -ne $Commit) { throw 'the clone is not at the commit' }
    $crlf = Get-CrlfFileCount @('Cargo.lock', 'rust-toolchain.toml', 'tests\native\m02\remote-lib.sh', 'tests\native\m02\target-root.sh' | ForEach-Object { Join-Path $src $_ })
    Add-Command $(if ($crlf -eq 0) { 0 } else { 1 }) 'the checked-out tree has LF line endings'
    if ($crlf -ne 0) { throw 'the checkout has CRLF line endings' }
    Add-Fact 'build-commit' $Commit

    $toml = Get-Content -LiteralPath (Join-Path $src 'rust-toolchain.toml') -Raw
    $channel = [regex]::Match($toml, '(?m)^\s*channel\s*=\s*"([^"]+)"').Groups[1].Value
    if (-not $channel) { throw 'rust-toolchain.toml names no channel' }
    $rustupHome = Join-Path $tools 'rustup'
    $cargoHome = Join-Path $tools 'cargo'
    $init = Join-Path $tools 'rustup-init.exe'
    $base = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
    Invoke-WebRequest -Uri $base -OutFile $init
    Invoke-WebRequest -Uri "$base.sha256" -OutFile "$init.sha256"
    $want = ((Get-Content -LiteralPath "$init.sha256" -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $have = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($init))
    Add-Command $(if ($want -eq $have) { 0 } else { 1 }) 'rustup-init.exe downloaded over HTTPS and its sha256 matches the published one'
    if ($want -ne $have) { throw 'rustup-init sha256 mismatch' }
    $toolEnv = New-ChildEnvironment (Get-ToolEnvironmentOverrides $rustupHome $cargoHome $emptyGitConfig $wtmp)
    $toolEnv['PATH'] = (Join-Path $cargoHome 'bin') + ';' + $toolEnv['PATH']
    $r = Invoke-Bounded $init @('-y', '--no-modify-path', '--profile', 'minimal', '--default-host', 'x86_64-pc-windows-msvc', '--default-toolchain', $channel) $toolEnv $run 1800
    Add-Command $r.Code "rustup-init into the run directory (RUSTUP_HOME and CARGO_HOME there, --no-modify-path, toolchain $channel)"
    [void]$build.Append($r.Output)
    if ($r.Code -ne 0) { throw 'toolchain install failed' }
    $cargo = Join-Path $cargoHome 'bin\cargo.exe'
    Add-Fact 'toolchain' ((Invoke-Bounded (Join-Path $cargoHome 'bin\rustc.exe') @('-V') $toolEnv $src 1800).Output.Trim() + "; target x86_64-pc-windows-msvc")
    foreach ($b in @(
            @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--no-run'),
            @('test', '--locked', '-p', 'heimdall-wsl', '--lib', '--no-run'),
            @('build', '--locked', '-p', 'heimdall-testkit', '--bins'))) {
        $r = Invoke-Bounded $cargo $b $toolEnv $src 7200
        Add-Command $r.Code "cargo $($b -join ' ')"
        [void]$build.Append($r.Output)
        if ($r.Code -ne 0) { throw 'the build failed' }
    }
    $hook = Join-Path $src 'target\debug\hm-fixture-hook.exe'
    if (-not (Test-Path -LiteralPath $hook)) { throw 'hm-fixture-hook.exe was not built' }

    # The files the distributions read: the helper, and the M02 root script.
    Copy-Item -LiteralPath $helperItem.FullName -Destination (Join-Path $files 'heimdall')
    if ((Get-Sha256Hex ([System.IO.File]::ReadAllBytes((Join-Path $files 'heimdall')))) -ne $wantSha) { throw 'the copied helper changed' }
    Copy-Item -LiteralPath (Join-Path $src 'tests\native\m02\target-root.sh') -Destination (Join-Path $files 'target-root.sh')
    $remoteLib = (Get-Content -LiteralPath (Join-Path $src 'tests\native\m02\remote-lib.sh') -Raw) -replace "`r`n", "`n"

    # The pinned image.
    $image = if ($Rootfs) { $rootfsItem.FullName } else { Join-Path $run 'ubuntu-24.04.5-wsl-amd64.wsl' }
    if (-not $Rootfs) {
        Invoke-WebRequest -Uri $RootfsUrl -OutFile $image
        Add-Command 0 'the pinned image downloaded over HTTPS'
    }
    $imgSha = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($image))
    Add-Command $(if ($imgSha -eq $RootfsSha256) { 0 } else { 1 }) 'the image is the pinned one (sha256)'
    if ($imgSha -ne $RootfsSha256) { throw 'the image is not the pinned one; nothing imported' }

    # 5. Both distributions.
    $apt = if ($AllowApt) { '1' } else { '0' }
    foreach ($n in $names) {
        $dir = Join-Path $distroRoot $n
        [void][System.IO.Directory]::CreateDirectory($dir)
        # ⟨M04-FX-RC03⟩ Attempted before the import runs, so the outer cleanup considers this
        # name whatever happens next (a failed listing, Ctrl-C); reconciled in this finally.
        $attempted.Add($n)
        $r = $null
        try {
            $r = Invoke-WslExe @('--import', $n, $dir, $image, '--version', '2') 1800
        } finally {
            # Recorded as this run's as soon as it is registered, whatever the exit code said.
            $listed = Get-RegisteredOrNull
            if ($null -ne $listed -and ($listed -contains $n) -and -not ($created -contains $n)) { $created.Add($n) }
        }
        Add-Command $r.Code "wsl --import $n (into the run directory, WSL 2)"
        if ($r.Code -ne 0 -or -not ($created -contains $n)) { throw "the import of $n failed" }
        $r = Invoke-InDistro $n 'root' $scripts['root-phase'] @($files, $n, 'no-systemd') 600
        Add-Command $r.Code "$n`: target-root.sh no-systemd"
        if ($r.Code -ne 0) { throw 'no-systemd failed' }
        [void](Invoke-WslExe @('--terminate', $n) 120)
        $r = Invoke-InDistro $n 'root' $scripts['root-phase'] @($files, $n, 'prepare', $User, $apt) 3600
        [void]$build.Append("### $n prepare`n$($r.Output)`n")
        Add-Command $r.Code "$n`: target-root.sh prepare (tools, git, python3; the non-root user)"
        if ($r.Code -eq 3) { $overall = 3; throw "$n lacks tools (-AllowApt / HM_WSL_ALLOW_APT=1 installs them inside it)" }
        if ($r.Code -ne 0) { throw 'prepare failed' }
        $r = Invoke-InDistro $n 'root' $scripts['default-user'] @($n, $User) 300
        Add-Command $r.Code "$n`: [user] default set to the non-root user"
        if ($r.Code -ne 0) { throw 'the default user could not be set' }
        [void](Invoke-WslExe @('--terminate', $n) 120)
    }
    Add-DistributionFacts 'after-import'

    # 6. The harness sshd in -2, as the user.
    $fxName = 'hm-m04-fx-' + (New-RandomHex 4)
    $r = Invoke-InDistro $names[1] $User $scripts['sshd-dir'] @($fxName) 300
    foreach ($l in ($r.Output -split "`n")) { if ($l -match '^([a-z-]+)=(.*)$') { $wv[$Matches[1]] = $Matches[2].Trim() } }
    Add-Command $r.Code 'the harness sshd directory in the user''s home (owner-only)'
    if ($r.Code -ne 0 -or -not $wv['created']) { throw 'the sshd directory was not created' }
    $sshdWslDir = $wv['created']
    $ak = Join-Path $sshdDir 'authorized_keys'
    $slog = Join-Path $sshdDir 'sshd.log'
    $akStrict = Join-Path $sshdDir 'authorized_keys_strict'
    $slogStrict = Join-Path $sshdDir 'sshd_strict.log'
    foreach ($f in @($ak, $akStrict)) { [System.IO.File]::WriteAllText($f, '') }
    $psi = [System.Diagnostics.ProcessStartInfo]::new($wslExe)
    foreach ($a in @('-d', $names[1], '-u', $User, '--exec', '/bin/bash', '-s', '--', $sshdWslDir, $ak, $slog, $akStrict, $slogStrict)) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment.Clear()
    foreach ($k in $wslEnv.Keys) { $psi.Environment[$k] = $wslEnv[$k] }
    $sshdProc = [System.Diagnostics.Process]::Start($psi)
    $sshdErr = $sshdProc.StandardError.ReadToEndAsync()
    $sshdProc.StandardInput.Write((($remoteLib + "`n" + (Get-SshdStartScript)) -replace "`r`n", "`n"))
    $sshdProc.StandardInput.Close()
    $fx = @{}
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $pending = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not ($fx.ContainsKey('ready') -or $fx.ContainsKey('why'))) {
        if ($null -eq $pending) { $pending = $sshdProc.StandardOutput.ReadLineAsync() }
        if (-not $pending.Wait(5000)) { continue }
        $line = $pending.Result
        $pending = $null
        if ($null -eq $line) { break }
        if ($line -match '^([a-z]+)=(.*)$') { $fx[$Matches[1]] = $Matches[2].Trim() }
    }
    $bannerOk = {
        param($Port)
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.ReceiveTimeout = 5000
            $c.Connect('127.0.0.1', [int]$Port)
            $buf = [byte[]]::new(8)
            $n = $c.GetStream().Read($buf, 0, 8)
            $c.Close()
            return [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).StartsWith('SSH-2.0-')
        } catch { return $false }
    }
    if (-not $fx.ContainsKey('ready') -or -not (& $bannerOk $fx['port'])) {
        Add-Fact 'fixture-sshd' "unavailable: $(if ($fx.ContainsKey('why')) { $fx['why'] } else { 'not reachable from Windows' })"
        Add-Command 1 'harness sshd in the second distribution reachable from Windows on 127.0.0.1'
        throw 'the harness sshd is unavailable'
    }
    Add-Command 0 'harness sshd in the second distribution reachable from Windows on 127.0.0.1'
    $strictOk = $fx.ContainsKey('strictport') -and (& $bannerOk $fx['strictport'])
    $fixtureEnv = Get-FixtureEnvironment $fx $true $strictOk $ak $slog $akStrict $slogStrict $User
    Add-Fact 'fixture-sshd' 'listening on 127.0.0.1 in the second disposable distribution (non-root, per-run host key)'
    Add-Fact 'fixture-sshd-registry' $(if ($fixtureEnv.ContainsKey('HM_FIXTURE_SSHD_REGISTRY')) { 'exported (owner-only, in the user''s home)' } else { 'not reported' })

    # 7. The tests, in order; the unregister row last and alone.
    $testBase = @{
        HM_FIXTURE_HOOK = $hook; HM_REPO_ROOT = $src
        HM_WSL_TEST_DISTRO = $names[0]; HM_WSL_TEST_ACCOUNT = $User
        HM_WSL_TEST_DISTRO2 = $names[1]; HM_WSL_TEST_ACCOUNT2 = $User
        HM_WSL_TEST_HELPER = (Join-Path $files 'heimdall')
    }
    foreach ($k in $fixtureEnv.Keys) { $testBase[$k] = $fixtureEnv[$k] }
    foreach ($s in (Get-TestPlan)) {
        $set = @{}
        foreach ($k in (Get-ToolEnvironmentOverrides $rustupHome $cargoHome $emptyGitConfig $wtmp).GetEnumerator()) { $set[$k.Key] = $k.Value }
        foreach ($k in $testBase.Keys) { $set[$k] = $testBase[$k] }
        if ($s.Unregister) { $set['HM_WSL_TEST_ALLOW_UNREGISTER'] = '1' }
        $testEnv = New-ChildEnvironment $set
        # The in-box OpenSSH first, then the toolchain.
        $testEnv['PATH'] = (Join-Path $sys32 'OpenSSH') + ';' + (Join-Path $cargoHome 'bin') + ';' + $testEnv['PATH']
        $r = Invoke-Bounded $cargo $s.Args $testEnv $src $TimeoutSeconds
        [void]$tests.Append((Format-TargetOutput $s.Name $r.Output $r.Code))
        $results = @(Get-TestResultLines $r.Output)
        Add-Command $r.Code "cargo $($s.Args -join ' ')$(if ($s.Unregister) { ' (HM_WSL_TEST_ALLOW_UNREGISTER=1)' }) -> $(if ($results.Count) { $results -join ' | ' } else { 'no test result line' })"
        # As it goes: printed, and kept in results.txt (names, outcomes and counts only).
        $plain = Format-ResultLines $s.Name $r.Code $r.Output
        Write-Output $plain
        [System.IO.File]::AppendAllText($resultsFile, $plain, [System.Text.UTF8Encoding]::new($false))
        if ($r.Code -ne 0) { $overall = 1 }
    }
} catch {
    # The failing line and the script's stack (redacted with the bundle; printed with it).
    Add-Command 1 "the run stopped: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    [void]$build.Append("### the run stopped`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)`n")
    if ($overall -eq 0) { $overall = 1 }
} finally {
  try {
    # 8. Cleanup: each step reports its own failure and never stops the others or the bundle.
    try {
        if ($sshdWslDir) {
            $now = @(Get-Registered)
            if ($now -contains $names[1]) {
                $r = Invoke-InDistro $names[1] $User ($remoteLib + "`n" + (Get-SshdStopScript) + "`n") @($sshdWslDir) 120
                $atEnd = Get-SshdAtEnd $r.Output
                Add-Fact 'fixture-sshd-at-end' $atEnd
                $ok = Test-SshdAtEndOk $atEnd
                Add-Command $(if ($ok) { 0 } else { 1 }) 'the recorded harness sshd is stopped (or already gone) at the end of the run'
                if (-not $ok -and $overall -eq 0) { $overall = 1 }
                $r = Invoke-InDistro $names[1] $User $scripts['sshd-dir-remove'] @($sshdWslDir) 120
                Add-Command $r.Code 'remove exactly the harness sshd directory'
            } else {
                Add-Fact 'fixture-sshd-at-end' 'gone with its distribution (the unregister row removed it)'
                Add-Command 0 'the harness sshd ended with its distribution'
            }
        }
        if ($null -ne $sshdProc) {
            if (-not $sshdProc.WaitForExit(30000)) { $sshdProc.Kill($true); $sshdProc.WaitForExit() }
            if ($null -ne $sshdErr) { [void]$sshdErr.Wait(5000) }
            $sshdProc.Dispose()
        }
    } catch { Add-Command 1 "stopping the harness sshd: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    try {
        if ($attempted.Count -gt 0) {
            $now = @(Get-Registered)
            foreach ($n in @(Select-RemovableDistributions $attempted.ToArray() $before $now)) {
                [void](Invoke-WslExe @('--terminate', $n) 120)
                $r = Invoke-WslExe @('--unregister', $n) 600
                Add-Command $r.Code "wsl --unregister $n (this run's, by exact name)"
                if ($r.Code -ne 0 -and $overall -eq 0) { $overall = 1 }
            }
            foreach ($n in $created) {
                if (-not ($now -contains $n)) { Add-Command 0 "$n was already unregistered (the unregister row)" }
            }
            # ⟨M04-FX-RC03⟩ Keep the install directory of any distribution not known to be gone.
            $kept = @(Select-KeptInstallDirectories $attempted.ToArray() (Get-RegisteredOrNull))
            foreach ($n in $kept) {
                Add-Command 1 "$n may still be registered: its install directory under the run directory is kept (unregister it by this exact name, then remove the directory)"
                if ($overall -eq 0) { $overall = 1 }
            }
        }
        if ($names.Count -gt 0) {
            Add-DistributionFacts 'after'
            $after = @(Get-Registered)
            $same = Test-SameSet $before $after
            [void]$distFacts.Append("registered-set-equal-to-before=$(if ($same) { 'yes' } else { 'no' })`n")
            Add-Command $(if ($same) { 0 } else { 1 }) 'the registered distributions equal the set before the run (only this run''s were added and removed)'
            if (-not $same -and $overall -eq 0) { $overall = 1 }
        }
    } catch { Add-Command 1 "unregistering this run's distributions: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    foreach ($d in @($src, $tools, $wtmp, $files, $sshdDir, $githome, (Join-Path $run 'ubuntu-24.04.5-wsl-amd64.wsl'))) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    # The distributions' install directories: each removed only when its distribution is known
    # to be unregistered (⟨M04-FX-RC03⟩); the directory root goes when nothing is kept.
    if (-not (Test-Path variable:kept)) { $kept = @(Select-KeptInstallDirectories $attempted.ToArray() (Get-RegisteredOrNull)) }
    foreach ($n in $attempted) {
        if ($kept -contains $n) { continue }
        $d = Join-Path $distroRoot $n
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($kept.Count -eq 0 -and (Test-Path -LiteralPath $distroRoot)) { Remove-Item -LiteralPath $distroRoot -Recurse -Force -ErrorAction SilentlyContinue }
    $gone = -not ((Test-Path -LiteralPath $src) -or (Test-Path -LiteralPath $tools) -or ($kept.Count -eq 0 -and (Test-Path -LiteralPath $distroRoot)))
    Add-Command $(if ($gone) { 0 } else { 1 }) 'remove the clone, the toolchain, the build and the distributions'' directories, then check they are absent'
    if (-not $gone -and $overall -eq 0) { $overall = 1 }

    # 9. Redact, mask, scan, bundle (no environment dump: only the facts above).
    $rules = Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName())
    $raw = @{ 'tests.txt' = $tests.ToString(); 'commands.txt' = $commands.ToString(); 'host.txt' = $hostFacts.ToString()
        'build.txt' = $build.ToString(); 'skipped.txt' = $skipped.ToString(); 'distributions.txt' = $distFacts.ToString(); 'canary-scan.txt' = '' }
    # The run's verdict first, in the plain results (it survives a failed bundle).
    [System.IO.File]::AppendAllText($resultsFile, "### run exit=$overall`n", [System.Text.UTF8Encoding]::new($false))
    Write-Output "### run exit=$overall (results: <run>\bundle\results.txt)"
    $p = Protect-BundleFiles $raw $rules
    if ($p -is [array] -or $p.Files -isnot [System.Collections.IDictionary]) { throw 'Protect-BundleFiles returned no file table' }
    $m = Get-ProtectedMetadata $Label $rules
    $canaryTotal = $p.Canaries + $m.Canaries
    $leakTotal = $p.Leaks + $m.Leaks
    # ⟨Windows run at 39f48be8⟩ Not `$out`: PowerShell names are case-insensitive, so `$out`
    # was the [string] parameter `-Out`, the file table became a string, and indexing it failed.
    $bundleOut = $p.Files
    $bundleOut['canary-scan.txt'] = "canary-prefix occurrences in saved output and metadata: $canaryTotal (values masked before the bundle was written)`n"
    $bundleOut['commands.txt'] += Format-CommandLine $(if ($canaryTotal -eq 0) { 0 } else { 1 }) "canary-prefix scan over saved output and metadata (count = $canaryTotal)"
    $bundleOut['commands.txt'] += Format-CommandLine $(if ($leakTotal -eq 0) { 0 } else { 1 }) "leak scan: saved files and metadata still naming a host, a user or a home ($leakTotal)"
    if (($canaryTotal -ne 0 -or $leakTotal -ne 0) -and $overall -eq 0) { $overall = 1 }
    $meta = [ordered]@{ commit = $Commit; label = $m.Label; started_at = $started; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); exit = $overall }
    $b = New-Bundle $bundleOut $meta
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.json'), $b.Json, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.b64'), $b.Text, [System.Text.UTF8Encoding]::new($false))
    Write-Output "bundle: <run>\bundle\bundle.json and bundle.b64 ($($b.Text.Length) characters)"
    Write-Output $bundleOut['commands.txt']
    Write-Output $b.Text
  } catch {
    # The cleanup or the bundle itself failed: say where, redacted as the bundle would be.
    $diag = "the cleanup or the bundle failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)"
    try {
        $diag = Invoke-Redaction $diag (Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName()))
    } catch { $diag = 'the cleanup or the bundle failed (the diagnostic could not be redacted, so it is not printed)' }
    [Console]::Error.WriteLine("run-mode-b-windows: $(Hide-Canary $diag)")
    if ($overall -eq 0) { $overall = 1 }
  }
}
exit $overall
