#Requires -Version 7.2
<#
.SYNOPSIS
M05-U10 (m05-plan §3, ruling I-19): the bash and zsh shell-hook journeys inside ONE disposable WSL
distribution on the Windows PC, which this script imports, uses and unregisters itself.

.DESCRIPTION
Runs ON the PC (pwsh 7.2 or later), not elevated, from a checkout of the commit (the three files it
sends into the distribution come from that checkout: tests/native/m05/wsl-hook-journeys.sh,
tests/native/m02/remote-lib.sh and tests/native/m02/target-root.sh). Only a committed harness may
manage the PC's own `hm-m0*` distributions: this one is M04's Mode B runner
(tests/native/m04/run-mode-b-windows.ps1) pared down to "import one distribution and run one
script in it". It reuses M04's and M02's functions by loading their definitions, never by copying
them (tests/native/m02/run-windows-local.ps1 and the Mode B runner are parsed, their main bodies
never run), so the redaction, canary scan, bundle writer, `wsl.exe` wrapper, listing parser and
removal selection are the ones those runners use.

Steps:
  1. Check the inputs before anything is created: the commit (40 hex, a label only), the BINDIR
     tarball (-Bundle) against -BundleSha256 (missing exit 3, malformed digest exit 2, mismatch
     exit 1), the pinned Ubuntu image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1:
     the M02 pin, tests/native/m02/run-wsl-distro.sh), the three repository files (LF line
     endings), the scratch root and -Out.
  2. Create the run directory <ScratchRoot>\hm-m05-wsl-<12 hex> exclusively (the protected stock
     profile list, as M04). Record the registered distributions (the census must succeed: a failed
     listing stops the run before anything is imported, exit 1) and choose the one name
     hm-m05-<8 hex>; refuse when it is registered already.
  3. Record a pending-import marker (the `attempted` list and <run>\pending-import.txt), then
     `wsl --import` it from the pinned image as WSL 2, into the run directory.
  4. As root, in that distribution only: `[boot] systemd=false` (tests/native/m02/target-root.sh
     no-systemd) and a terminate; with -AllowApt ONLY, `apt-get install -y --no-install-recommends
     zsh openssh-server openssh-client git util-linux` (services blocked first, as M02 does; without
     -AllowApt a missing tool stops the run, exit 3); then target-root.sh `prepare` for the
     non-root user hmtest.
  5. As hmtest: copy the tarball and the scripts in, check the tarball's sha256 again inside the
     distribution, list then extract it (members `BINDIR/...` and `BINDIR.sha256` only), verify every
     file of BINDIR against BINDIR.sha256 and that nothing else is there, then run
     `bash wsl-hook-journeys.sh <scratch, at most 64 bytes> <BINDIR>` bounded. WSL sets
     WSL_DISTRO_NAME; the script refuses a name that is not hm-m05-<8 hex>.
  6. Always (finally): terminate and unregister ONLY this run's distribution, by exact name (re-checked
     against the pattern, the before-list and the current list; never `wsl --shutdown`, never
     another distribution); check that the registered set equals the one before; remove the run
     directory this script created.
     A registration is this run's only when its name is this run's AND the install directory WSL
     recorded for it (the BasePath of HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}
     whose DistributionName is the name, compared as a normalized full path) is this run's directory:
     checked right after the import (a partial import included), before every phase that runs in it,
     and before the terminate and the unregister. The same name under another directory is never
     used, terminated or unregistered (a commands.txt line, exit 1; this run's directory is kept).
  7. One redacted bundle of the M02/M04 style (`heimdall-m05-wsl-hook-bundle/1`): tests.txt
     (the script's stdout), commands.txt (each step's exit), host.txt (image digest, distribution
     facts, versions), build.txt, skipped.txt, canary-scan.txt. It is written to -Out and printed
     between markers, and the plain result lines (names and counts only) are printed as the run goes, so
     the verdict survives a failed bundle.

BINDIR tarball (built on the build host): `BINDIR/` (heimdall, hm-fixture-hook, e2e_cli_m05,
e2e_hook_m05, adversarial_prompt_injection_cli, repo/) and `BINDIR.sha256`, whose lines are
`sha256sum` output for every regular file under BINDIR, with paths relative to the tarball root
(`<hex>  BINDIR/heimdall`). No symbolic link, no other member.

Exit: 0 every journey passed and everything was cleaned up; 1 a journey, a digest, a clean-up step or
the scan failed; 2 a usage or environment error; 3 blocked (a missing input, or a missing tool without
-AllowApt).

Import on the build host:
  python3 -I tests/native/m02/import-windows-bundle.py --bundle <-Out file> --label exit-<commit> \
      --commit <commit> --artifacts-root tests/evidence/artifacts/m05 --platform-dir wsl-distro \
      --format heimdall-m05-wsl-hook-bundle/1 --config <artifacts root>/runs.json

.PARAMETER SelfTest
The pure helpers on synthetic data (no host, no network, no WSL), `bash -n` of every script this runner
sends into the distribution when bash is available, and, with -Out, the synthetic bundle written to that
file for the importer's test. Runs anywhere; exit 0 when every check passed.

.EXAMPLE
pwsh -NoProfile -File tests\native\m05\run-wsl-hook-windows.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m05 `
    -Bundle C:\hm\m05-bindir.tar.gz -BundleSha256 <64-hex> -Rootfs C:\hm\ubuntu-24.04.5-wsl-amd64.wsl -AllowApt `
    -Out C:\hm\m05-wsl-hook-bundle.txt
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$ScratchRoot,
    [string]$Bundle,
    [string]$BundleSha256,
    [string]$Rootfs = $env:HM_WSL_ROOTFS,
    [switch]$Download = ($env:HM_WSL_DOWNLOAD -eq '1'),
    [switch]$AllowApt = ($env:HM_WSL_ALLOW_APT -eq '1'),
    [int]$TimeoutSeconds = 5400,
    [string]$Label = 'windows-11-x86_64 (WSL 2, M05 hook journeys, one disposable distribution)',
    [switch]$SelfTest,
    [string]$Out = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$BundleFormat = 'heimdall-m05-wsl-hook-bundle/1'
$BeginMarker = '-----BEGIN HEIMDALL M05 WSL HOOK BUNDLE-----'
$EndMarker = '-----END HEIMDALL M05 WSL HOOK BUNDLE-----'
# The six result files tests/native/m02/import-windows-bundle.py reads (no other name).
$BundleFiles = @('tests.txt', 'commands.txt', 'host.txt', 'build.txt', 'skipped.txt', 'canary-scan.txt')
# The M02 pin (tests/native/m02/run-wsl-distro.sh): the only image this runner imports.
$RootfsUrl = 'https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl'
$RootfsSha256 = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
$User = 'hmtest'
# The journeys script's own target header and its eight steps (the case index's scenario steps);
# the self-test compares this list with the names in wsl-hook-journeys.sh.
$JourneyTarget = 'wsl_hook_m05'
$ExpectedSteps = @(
    'm05_wsl_bash_and_zsh_present',
    'm05_wsl_hook_never_evaluates_repository_text',
    'm05_wsl_hook_creates_no_decision_when_uncovered',
    'm05_wsl_hook_warms_the_default_so_the_first_ordinary_ssh_logs_in',
    'm05_wsl_hook_warm_up_creates_no_decision_when_the_default_does_not_cover',
    'm05_wsl_hook_without_a_runtime_prints_nothing_and_starts_none',
    'm05_wsl_a29_hook_ignores_a_hostile_environment',
    'm05_wsl_no_leftover_processes'
)

# ---------------------------------------------------------------------------------------------
# The M02 and M04 runners' functions, loaded from their definitions (their main bodies never run).
# M04's `wsl.exe` wrappers read script-scope variables of the same names as here ($wslExe,
# $wslEnv, $run, $names, $commands, $stepClock, $hostFacts, $distFacts): this script defines them.
# ---------------------------------------------------------------------------------------------

$m02Runner = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'm02') 'run-windows-local.ps1'
$m04Runner = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'm04') 'run-mode-b-windows.ps1'
$m02Helpers = @('New-RandomHex', 'Get-Sha256Hex', 'New-RedactionRule', 'Get-RedactionForms', 'Invoke-Redaction',
    'Get-CanaryCount', 'Hide-Canary', 'Get-LeakCount', 'Format-TargetOutput', 'Format-CommandLine', 'New-Bundle',
    'Protect-BundleFiles', 'Get-ProtectedMetadata', 'Get-CrlfFileCount', 'Get-RunRedactionRules',
    'Get-StockProfileGrantArguments')
# Not loaded from M04: Get-DistributionNames and Test-OwnDistributionName (they hard-code `hm-m04`).
# M04's Select-RemovableDistributions calls Test-OwnDistributionName by name, so this script's own
# (the M05 pattern, below) is the one it applies.
$m04Helpers = @('ConvertFrom-WslList', 'Select-RemovableDistributions', 'Select-KeptInstallDirectories', 'Test-SameSet',
    'Get-DistributionFacts', 'Get-TestResultLines', 'Format-ResultLines', 'Get-DistroScripts', 'Add-Command', 'Add-Fact',
    'New-ChildEnvironment', 'Invoke-Bounded', 'Invoke-WslExe', 'Invoke-InDistro', 'Get-Registered',
    'Get-RegisteredOrNull', 'Add-DistributionFacts')
$loadParseErrors = $null
foreach ($loadSet in @(@($m02Runner, $m02Helpers), @($m04Runner, $m04Helpers))) {
    $loadAst = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $loadSet[0]).Path, [ref]$null, [ref]$loadParseErrors)
    if ($loadParseErrors.Count -gt 0) { throw "$($loadSet[0]) does not parse" }
    foreach ($f in $loadAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($loadSet[1] -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
    }
    foreach ($n in $loadSet[1]) {
        if (-not (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue)) { throw "the helper $n is missing in $($loadSet[0])" }
    }
}

# ---------------------------------------------------------------------------------------------
# This runner's pure helpers (exercised by -SelfTest)
# ---------------------------------------------------------------------------------------------

# The one distribution of a run: hm-m05-<8 hex>.
function Get-DistributionName([string]$Hex) {
    return "hm-m05-$Hex"
}

# Whether Name is a distribution name this runner makes (`hm-m04-...` and every other name: no).
function Test-OwnDistributionName([string]$Name) {
    return ($Name -cmatch '^hm-m05-[0-9a-f]{8}\z')
}

# An input file against its expected digest: Code 0 (matches), 1 (mismatch), 2 (a malformed digest),
# 3 (blocked: no digest given, or the path is not a regular file).
function Test-InputDigest([string]$Path, [string]$Want, [string]$What) {
    if ([string]::IsNullOrWhiteSpace($Want)) { return [pscustomobject]@{ Code = 3; Message = "blocked: no sha256 given for $What"; Sha256 = '' } }
    $w = $Want.Trim().ToLowerInvariant()
    if ($w -notmatch '^[0-9a-f]{64}$') { return [pscustomobject]@{ Code = 2; Message = "bad sha256 for $What (64 hex digits)"; Sha256 = '' } }
    if ([string]::IsNullOrWhiteSpace($Path)) { return [pscustomobject]@{ Code = 3; Message = "blocked: no file given for $What"; Sha256 = '' } }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer) { return [pscustomobject]@{ Code = 3; Message = "blocked: $What is not a regular file"; Sha256 = '' } }
    $have = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($have -ne $w) { return [pscustomobject]@{ Code = 1; Message = "$What sha256 mismatch: file $have, expected $w; nothing created"; Sha256 = $have } }
    return [pscustomobject]@{ Code = 0; Message = "$What sha256 equals the expected digest ($have)"; Sha256 = $have }
}

# The journeys' scratch directory inside the distribution (the script creates it, at most 64
# bytes for the runtime's Unix socket paths) and the bound itself.
function Get-DistroScratch([string]$Hex) {
    return "/tmp/hm05-$Hex"
}
function Test-ScratchLength([string]$Path) {
    return ($Path.StartsWith('/') -and [System.Text.Encoding]::UTF8.GetByteCount($Path) -le 64)
}

# Whether Dir is a run directory this script makes, directly under Root: the only kind it removes.
function Test-OwnRunDirectory([string]$Root, [string]$Dir) {
    if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($Dir)) { return $false }
    $parent = [System.IO.Path]::GetFullPath((Split-Path -Parent $Dir)).TrimEnd('\', '/')
    return (($parent -ceq [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')) -and ((Split-Path -Leaf $Dir) -cmatch '^hm-m05-wsl-[0-9a-f]{12}\z'))
}

# ---- Ownership of a registration (review finding M05-W4F-RC-R04) ----------------------------------
# Two disposable runs can draw the same name. A registration is this run's only when its name is this
# run's (hm-m05-<8 hex>, absent from the census taken before the run) AND the install directory WSL
# recorded for it (the BasePath of the current user's Lxss key) is this run's directory. The check is
# made after the import (also a failed or timed-out one), before anything runs in the distribution,
# and before the cleanup terminates or unregisters it.

# A directory as a comparable string: the `\\?\` (and `\\.\`, `\??\`) prefix removed, `\\?\UNC\` read
# as `\\`, `/` read as `\`, repeated and trailing separators dropped, lower-cased (Windows paths are
# case-insensitive). $null for a blank, relative, `.`/`..`-bearing or otherwise unusable path. Pure
# string work, so it runs (and is self-tested) off Windows.
function ConvertTo-ComparablePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains("`0")) { return $null }
    $p = $Path.Trim().Replace('/', '\')
    if ($p -match '^\\\\[?.]\\UNC\\(.+)$') { $p = '\\' + $Matches[1] }
    elseif ($p -match '^\\\\[?.]\\(.+)$') { $p = $Matches[1] }
    elseif ($p -match '^\\\?\?\\(.+)$') { $p = $Matches[1] }
    $unc = $p.StartsWith('\\')
    $parts = @($p -split '\\' | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0 -or @($parts | Where-Object { $_ -ceq '.' -or $_ -ceq '..' }).Count -gt 0) { return $null }
    if ($unc) {
        if ($parts.Count -lt 2) { return $null }
    } elseif ($parts[0] -notmatch '^[A-Za-z]:$') { return $null }
    return (($(if ($unc) { '\\' } else { '' }) + ($parts -join '\')).ToLowerInvariant())
}

# The `{DistributionName, BasePath}` rows WSL keeps for the current user:
# HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}. Throws when the key cannot be read.
# (Windows only; the self-test feeds synthetic rows through the Source parameters below instead.)
function Read-LxssRows {
    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Lxss')
    if ($null -eq $root) { throw 'the Lxss registry key is not readable' }
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($sub in $root.GetSubKeyNames()) {
            $k = $root.OpenSubKey($sub)
            if ($null -eq $k) { continue }
            try {
                $rows.Add([pscustomobject]@{ DistributionName = [string]$k.GetValue('DistributionName', ''); BasePath = [string]$k.GetValue('BasePath', '') })
            } finally { $k.Dispose() }
        }
    } finally { $root.Dispose() }
    return , $rows.ToArray()
}

# The comparable install directory WSL recorded for Name, or $null when it cannot be read: the rows
# cannot be read, no row or more than one row carries the name, or the BasePath is unusable.
function Get-DistributionInstallDirectory([string]$Name, [scriptblock]$Source = { Read-LxssRows }) {
    try {
        $rows = @(& $Source)
        $match = @($rows | Where-Object { $null -ne $_ -and ([string]$_.DistributionName) -ieq $Name })
        if ($match.Count -ne 1) { return $null }
        return (ConvertTo-ComparablePath ([string]$match[0].BasePath))
    } catch { return $null }
}

# Whether the registration called Name is this run's: its name is this runner's pattern and absent
# from the census taken before the run ($Before, $null when that census failed: never owned), and
# the install directory WSL recorded for it is this run's directory (Dir).
function Test-OwnRegistration([string]$Name, [string]$Dir, $Before, [scriptblock]$Source = { Read-LxssRows }) {
    if ($null -eq $Before) { return $false }
    if (-not (Test-OwnDistributionName $Name)) { return $false }
    if (@($Before) -contains $Name) { return $false }
    $want = ConvertTo-ComparablePath $Dir
    if ($null -eq $want) { return $false }
    $have = Get-DistributionInstallDirectory $Name $Source
    return ($null -ne $have -and $have -ceq $want)
}

# Throws unless the registration called Name is this run's (see Test-OwnRegistration).
function Assert-OwnRegistration([string]$Name, [string]$Dir, $Before) {
    if (-not (Test-OwnRegistration $Name $Dir $Before)) {
        throw "refusing: $Name is not registered under this run's install directory (not used, not removed)"
    }
}

# A script inside this run's distribution: only after the registration is shown to be this run's.
function Invoke-OwnedInDistro([string]$Name, [string]$Dir, $Before, [string]$Account, [string]$Script, [string[]]$ScriptArgs, [int]$Seconds = 1800) {
    Assert-OwnRegistration $Name $Dir $Before
    return Invoke-InDistro $Name $Account $Script $ScriptArgs $Seconds
}

# The census before the run: the registered names, from a listing that succeeded. A failed listing
# ($null from Get-RegisteredOrNull) is never an empty set: it stops the run before anything is imported.
function Get-CensusOrThrow([scriptblock]$List = { Get-RegisteredOrNull }) {
    $names0 = & $List
    if ($null -eq $names0) { throw 'the registered distributions could not be listed (wsl --list --quiet failed); nothing imported' }
    return , @($names0)
}

# The journeys script's stdout reduced to its own part: from its `### wsl_hook_m05` header to its last
# `### wsl_hook_m05 exit=<n>` line (wsl.exe noise before and after is dropped). When either is missing
# (a refused start, a timeout) the part is the header and a synthesized exit line, never a zero.
function Format-JourneyTests([string]$Output, [int]$Code, [string]$Target) {
    $lines = @(($Output -replace "`r", '') -split "`n")
    $start = -1
    $end = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($start -lt 0 -and $lines[$i] -ceq "### $Target") { $start = $i }
        if ($lines[$i] -cmatch "^### $([regex]::Escape($Target)) exit=-?\d+\z") { $end = $i }
    }
    if ($start -ge 0 -and $end -gt $start) { return (($lines[$start..$end]) -join "`n") + "`n" }
    $synth = if ($Code -eq 0) { 1 } else { $Code }
    return "### $Target`n### $Target exit=$synth`n"
}

# The verdict on the journeys' run: it passes only when the process exited 0, the script's own exit
# line says 0, and every expected step printed `... ok` (none FAILED, none missing).
function Get-JourneyVerdict([string]$Output, [int]$Code, [string]$Target, [string[]]$Expected) {
    $text = Format-JourneyTests $Output $Code $Target
    $results = @{}
    $exitLine = $null
    foreach ($l in ($text -split "`n")) {
        if ($l -cmatch '^test (m05_wsl_[a-z0-9_]+) \.\.\. (ok|FAILED)\z') { $results[$Matches[1]] = $Matches[2] }
        elseif ($l -cmatch "^### $([regex]::Escape($Target)) exit=(-?\d+)\z") { $exitLine = [int]$Matches[1] }
    }
    $ok = @($Expected | Where-Object { $results[$_] -ceq 'ok' })
    $failed = @($results.Keys | Where-Object { $results[$_] -ceq 'FAILED' })
    $missing = @($Expected | Where-Object { -not $results.ContainsKey($_) })
    $why = [System.Collections.Generic.List[string]]::new()
    if ($Code -ne 0) { $why.Add("the script exited $Code") }
    if ($null -eq $exitLine -or $exitLine -ne 0) { $why.Add("its exit line says $exitLine") }
    if ($failed.Count -gt 0) { $why.Add("failed: $($failed -join ', ')") }
    if ($missing.Count -gt 0) { $why.Add("not run: $($missing -join ', ')") }
    return [pscustomobject]@{ Pass = ($why.Count -eq 0); Ok = $ok.Count; Failed = $failed.Count; Missing = $missing.Count; Reason = ($why -join '; ') }
}

# Add-DistributionFacts' lines as host.txt facts: `before: exit 0; ...` becomes `distributions-before=...`;
# a `key=value` line is kept.
function Format-DistributionFactLines([string]$Text) {
    $o = [System.Collections.Generic.List[string]]::new()
    foreach ($l in ($Text -replace "`r", '' -split "`n")) {
        if ($l -match '^[A-Za-z0-9_.-]+=') { $o.Add($l) }
        elseif ($l -match '^([a-z-]+): (.*)$') { $o.Add("distributions-$($Matches[1])=$($Matches[2])") }
    }
    if ($o.Count -eq 0) { return '' }
    return ($o -join "`n") + "`n"
}

# Redact, mask and scan every bundle file and the label, then frame the bundle: the files go through
# the M02 runner's Protect-BundleFiles, a finding turns a passing run into exit 1.
function New-ProtectedBundle([hashtable]$Raw, $Rules, [string]$BundleLabel, [string]$CommitHex, [string]$Started, [int]$Exit) {
    $p = Protect-BundleFiles $Raw $Rules
    if ($p -is [array] -or $p.Files -isnot [System.Collections.IDictionary]) { throw 'Protect-BundleFiles returned no file table' }
    $m = Get-ProtectedMetadata $BundleLabel $Rules
    $canaryTotal = $p.Canaries + $m.Canaries
    $leakTotal = $p.Leaks + $m.Leaks
    # Not a variable named like a parameter (PowerShell names are case-insensitive).
    $table = $p.Files
    $table['canary-scan.txt'] = "canary-prefix occurrences in saved output and metadata: $canaryTotal (values masked before the bundle was written)`n"
    $table['commands.txt'] += Format-CommandLine $(if ($canaryTotal -eq 0) { 0 } else { 1 }) "canary-prefix scan over saved output and metadata (count = $canaryTotal)"
    $table['commands.txt'] += Format-CommandLine $(if ($leakTotal -eq 0) { 0 } else { 1 }) "leak scan: saved files and metadata still naming a host, a user or a home ($leakTotal)"
    $final = $Exit
    if (($canaryTotal -ne 0 -or $leakTotal -ne 0) -and $final -eq 0) { $final = 1 }
    $meta = [ordered]@{ commit = $CommitHex; label = $m.Label; started_at = $Started; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); exit = $final }
    return [pscustomobject]@{ Bundle = (New-Bundle $table $meta); Files = $table; Canaries = $canaryTotal; Leaks = $leakTotal; Exit = $final }
}

# The bundle document inside a bundle text: markers, payload digest, gunzip, JSON, every file's
# digest (the importer's checks, on this side; the self-test's round trip).
function ConvertFrom-BundleText([string]$Text) {
    $lines = @(($Text -replace "`r", '') -split "`n" | Where-Object { $_ })
    if ($lines[0] -cne $BeginMarker -or $lines[-1] -cne $EndMarker) { throw 'the bundle is not framed by this runner''s markers' }
    if (-not $lines[1].StartsWith('sha256-gzip: ')) { throw 'the payload sha256 line is missing' }
    $packed = [Convert]::FromBase64String(($lines[2..($lines.Count - 2)] -join ''))
    if ((Get-Sha256Hex $packed) -ne $lines[1].Substring('sha256-gzip: '.Length)) { throw 'the payload sha256 does not match' }
    $ms = [System.IO.MemoryStream]::new($packed)
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = [System.IO.StreamReader]::new($gz, [System.Text.UTF8Encoding]::new($false))
    $json = $sr.ReadToEnd()
    $sr.Dispose()
    $doc = $json | ConvertFrom-Json -AsHashtable
    foreach ($k in $doc['files'].Keys) {
        if ((Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($doc['files'][$k]))) -ne $doc['sha256'][$k]) { throw "$k sha256 does not match" }
    }
    return $doc
}

# The scripts this runner sends into the distribution (bash, on stdin; each runs as `bash -s -- <args>`),
# beside M04's root-phase script (Get-DistroScripts), which runs target-root.sh.
function Get-HookScripts {
    return [ordered]@{
        # As root: the packages the journeys need. $1 the distribution's name, $2 allow-apt (1|0).
        # Allowed: apt-get install with every service blocked first (policy-rc.d exit 101, ssh.service
        # and ssh.socket masked), as target-root.sh prepare does for M02's tools. Not allowed: only
        # the check, and a missing tool is exit 3.
        'packages' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "refusing: needs root inside the disposable distribution" >&2; exit 2; }
allow=$2
have() { command -v "$1" >/dev/null 2>&1 || [ -x "/usr/sbin/$1" ]; }
missing_tools() {
    local m="" t
    for t in zsh sshd ssh ssh-keygen git script; do have "$t" || m="$m $t"; done
    echo "$m"
}
echo "missing-before=$(missing_tools)"
if [ "$allow" != 1 ]; then
    m=$(missing_tools)
    if [ -n "$m" ]; then
        echo "blocked=the pinned image lacks:$m (-AllowApt installs them inside this distribution)"
        exit 3
    fi
    echo "apt=not allowed (nothing to install)"
    exit 0
fi
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d || exit 1
chmod 755 /usr/sbin/policy-rc.d
mkdir -p /etc/systemd/system
ln -sf /dev/null /etc/systemd/system/ssh.service
ln -sf /dev/null /etc/systemd/system/ssh.socket
log=/root/hm-m05-apt.log
rc=0
DEBIAN_FRONTEND=noninteractive apt-get -q update >"$log" 2>&1 &&
    DEBIAN_FRONTEND=noninteractive apt-get -q -y install --no-install-recommends zsh openssh-server openssh-client git util-linux >>"$log" 2>&1 || rc=$?
echo "apt-install-exit=$rc"
[ "$rc" = 0 ] || tail -n 20 "$log"
rm -f -- "$log"
m=$(missing_tools)
echo "missing-after=${m:- none}"
[ "$rc" = 0 ] && [ -z "$m" ]
'@
        # As the non-root user: the facts the redaction needs (never kept in the bundle as such).
        'user-facts' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" != 0 ] || { echo "refusing: run as the non-root user" >&2; exit 2; }
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
'@
        # As the non-root user: copy the inputs from the Windows files directory ($2) into a new
        # directory of the home, check the tarball's sha256 ($3) inside the distribution, list then
        # extract it, and verify BINDIR against BINDIR.sha256. $1 the distribution's name.
        'stage' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" != 0 ] || { echo "refusing: run as the non-root user" >&2; exit 2; }
files=$(wslpath -u "$2") || exit 2
want=$3
in="$HOME/hm05-in"
mkdir -m 700 -- "$in" || { echo "the stage directory exists" >&2; exit 2; }
cp -- "$files/bindir.tar" "$files/wsl-hook-journeys.sh" "$files/remote-lib.sh" "$in/" || { echo "stage-copy=failed"; exit 1; }
have=$(sha256sum -- "$in/bindir.tar" | cut -d' ' -f1)
if [ "$have" != "$want" ]; then echo "bundle-digest-in-distribution=mismatch"; exit 1; fi
echo "bundle-digest-in-distribution=match"
tar -tf "$in/bindir.tar" >"$in/members.txt" 2>/dev/null || { echo "tar-list=failed"; exit 1; }
bad=0
n=0
while IFS= read -r m; do
    n=$((n + 1))
    case "$m" in
        BINDIR | BINDIR/ | BINDIR.sha256 | BINDIR/*) ;;
        *) bad=$((bad + 1)) ;;
    esac
    case "/$m/" in */../*) bad=$((bad + 1)) ;; esac
done <"$in/members.txt"
echo "tar-members=$n"
[ "$n" -gt 0 ] && [ "$bad" = 0 ] || { echo "tar-members-outside-bindir=$bad"; exit 1; }
x="$in/x"
mkdir -m 700 -- "$x" || exit 1
tar -xf "$in/bindir.tar" -C "$x" --no-same-owner 2>/dev/null || { echo "tar-extract=failed"; exit 1; }
[ -d "$x/BINDIR" ] && [ -f "$x/BINDIR.sha256" ] || { echo "bindir=missing"; exit 1; }
odd=$(find "$x" ! -type f ! -type d | wc -l | tr -d ' ')
[ "$odd" = 0 ] || { echo "bindir-special-files=$odd"; exit 1; }
(cd "$x" && sha256sum --check --strict --quiet BINDIR.sha256 >/dev/null 2>&1) || { echo "bindir-sha256=mismatch"; exit 1; }
listed=$(sed -e 's/^[0-9a-f]\{64\}  //' -e 's/^[0-9a-f]\{64\} \*//' "$x/BINDIR.sha256" | LC_ALL=C sort)
present=$(cd "$x" && find BINDIR -type f | LC_ALL=C sort)
[ -n "$present" ] && [ "$listed" = "$present" ] || { echo "bindir-sha256=not exactly the files present"; exit 1; }
echo "bindir-sha256=verified"
echo "bindir-files=$(printf '%s\n' "$present" | wc -l | tr -d ' ')"
if [ -f "$x/BINDIR/heimdall" ]; then echo "heimdall-sha256=$(sha256sum -- "$x/BINDIR/heimdall" | cut -d' ' -f1)"; else echo "heimdall-sha256=absent"; fi
'@
        # As the non-root user: the journeys. $1 the distribution's name, $2 the scratch directory.
        'journeys' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" != 0 ] || { echo "refusing: run as the non-root user" >&2; exit 2; }
in="$HOME/hm05-in"
cd "$in" || exit 2
exec /bin/bash ./wsl-hook-journeys.sh "$2" "$in/x/BINDIR" </dev/null
'@
        # As the non-root user: package and kernel versions (facts only).
        'versions' = @'
set -u
# shellcheck disable=SC1091  # the distribution's own file
echo "os=$(. /etc/os-release && echo "$PRETTY_NAME")"
echo "kernel=$(uname -r)"
for p in bash zsh openssh-server openssh-client git util-linux; do
    echo "pkg-$p=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || echo absent)"
done
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
    $own = 'hm-m05-0a1b2c3d'
    Check 'N01 the one name is hm-m05-<8 hex>' ((Get-DistributionName '0a1b2c3d') -ceq $own)
    Check 'N02 only hm-m05-<8 hex> is this runner''s own: hm-m04 names and every other name are refused' ((Test-OwnDistributionName $own) -and
        -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d') -and -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d-1') -and
        -not (Test-OwnDistributionName 'hm-m05-0a1b2c3d-1') -and -not (Test-OwnDistributionName 'hm-m05-0A1B2C3D') -and
        -not (Test-OwnDistributionName 'hm-m05-0a1b2c3') -and -not (Test-OwnDistributionName 'hm-m05-0a1b2c3d4') -and
        -not (Test-OwnDistributionName 'Ubuntu') -and -not (Test-OwnDistributionName 'hm-m03-0a1b2c3d') -and
        -not (Test-OwnDistributionName "$own ") -and -not (Test-OwnDistributionName "$own`n") -and -not (Test-OwnDistributionName ''))
    $parsed = @(ConvertFrom-WslList "Ubuntu`r`n`r`n$own`r`nDeb`0ian`n")
    Check 'N03 the quiet list parses through M04''s parser (CR, NUL and blank lines removed)' (($parsed -join ',') -ceq "Ubuntu,$own,Debian")
    $before = @('Ubuntu', 'hm-m04-0a1b2c3d-1')
    $now = @('Ubuntu', 'hm-m04-0a1b2c3d-1', $own, 'hm-m05-ffffffff')
    $rm = @(Select-RemovableDistributions @($own, 'Ubuntu', 'hm-m04-0a1b2c3d-1', 'hm-m05-99999999') $before $now)
    Check 'C01 removal selects only a created hm-m05 name, absent before, registered now (an hm-m04 name and the unregistered are never removed)' (($rm -join ',') -ceq $own)
    Check 'C02 a name that was registered before the run is never removed' (@(Select-RemovableDistributions @($own) @('Ubuntu', $own) @('Ubuntu', $own)).Count -eq 0)
    Check 'C03 an import recorded only as attempted (its listing failed) is still removed when it is registered' (
        (@(Select-RemovableDistributions @($own) @('Ubuntu') @('Ubuntu', $own)) -join ',') -ceq $own -and @(Select-RemovableDistributions @($own) @('Ubuntu') @('Ubuntu')).Count -eq 0)
    Check 'C04 the install directory is kept while its distribution is registered, and when the listing is unreadable' (
        ((Select-KeptInstallDirectories @($own) @('Ubuntu', $own)) -join ',') -ceq $own -and ((Select-KeptInstallDirectories @($own) $null) -join ',') -ceq $own -and
        @(Select-KeptInstallDirectories @($own) @('Ubuntu')).Count -eq 0)
    Check 'C05 the registered set compares as a set' ((Test-SameSet @('Ubuntu', 'Debian') @('debian', 'Ubuntu')) -and -not (Test-SameSet @('Ubuntu') @('Ubuntu', $own)))
    $verbose = "  NAME                 STATE           VERSION`r`n* OwnersBox            Running         2`r`n  $own    Stopped         2`r`n"
    $facts = Get-DistributionFacts $verbose @($own)
    Check 'D01 only this run''s distribution is recorded by name; the others as a count and digest' (($facts.Own -join '|') -ceq "$own Stopped 2" -and $facts.OtherCount -eq 1 -and $facts.OtherDigest.Length -eq 12)
    $dl = Format-DistributionFactLines "before: exit 0; this run's: none; others: 1 (digest abc)`nregistered-set-equal-to-before=yes`nnoise`n"
    Check 'D02 distribution facts become host.txt key=value lines' ($dl -ceq "distributions-before=exit 0; this run's: none; others: 1 (digest abc)`nregistered-set-equal-to-before=yes`n")

    # The input digest checks (nothing is created before they pass).
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('hm-m05-st-' + (New-RandomHex 4))
    [void][System.IO.Directory]::CreateDirectory($tmpDir)
    try {
        $f = Join-Path $tmpDir 'input.bin'
        [System.IO.File]::WriteAllBytes($f, [byte[]](1, 2, 3, 4))
        $sha = Get-Sha256Hex ([byte[]](1, 2, 3, 4))
        $okR = Test-InputDigest $f $sha 'the tarball'
        $upR = Test-InputDigest $f $sha.ToUpperInvariant() 'the tarball'
        Check 'I01 an input whose sha256 matches passes (case of the digest aside)' ($okR.Code -eq 0 -and $upR.Code -eq 0 -and $okR.Sha256 -ceq $sha)
        $misR = Test-InputDigest $f ('0' * 64) 'the tarball'
        Check 'I02 a mismatch is exit 1 and names both digests' ($misR.Code -eq 1 -and $misR.Message.Contains($sha) -and $misR.Message.Contains('0' * 64))
        Check 'I03 a missing file, a directory and a blank path are exit 3' ((Test-InputDigest (Join-Path $tmpDir 'absent') $sha 'x').Code -eq 3 -and
            (Test-InputDigest $tmpDir $sha 'x').Code -eq 3 -and (Test-InputDigest '' $sha 'x').Code -eq 3)
        Check 'I04 a malformed digest is exit 2 and none given is exit 3' ((Test-InputDigest $f 'abc' 'x').Code -eq 2 -and (Test-InputDigest $f ('g' * 64) 'x').Code -eq 2 -and
            (Test-InputDigest $f '' 'x').Code -eq 3 -and (Test-InputDigest $f $null 'x').Code -eq 3)
        Check 'I05 the pinned image digest is the M02 pin' ($RootfsSha256 -ceq 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e' -and $RootfsUrl.EndsWith('ubuntu-24.04.5-wsl-amd64.wsl'))
        # The repository files this runner sends in, in the checkout it runs from (LF endings).
        $sent = @((Join-Path $PSScriptRoot 'wsl-hook-journeys.sh'), (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'm02') 'remote-lib.sh'), (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'm02') 'target-root.sh'))
        Check 'I06 the three repository files it sends in exist and have LF line endings' (@($sent | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -eq 0 -and (Get-CrlfFileCount $sent) -eq 0)
    } finally { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }

    $scr = Get-DistroScratch '0a1b2c3d'
    Check 'L01 the scratch path is absolute and at most 64 bytes' ((Test-ScratchLength $scr) -and (Test-ScratchLength ('/' + ('a' * 63))) -and -not (Test-ScratchLength ('/' + ('a' * 64))) -and
        -not (Test-ScratchLength 'relative/dir') -and -not (Test-ScratchLength ('/' + ('é' * 32))) -and (Test-ScratchLength ('/' + ('é' * 31))))
    $root = Join-Path ([System.IO.Path]::GetTempPath()) 'hm-m05-root'
    Check 'L02 only a hm-m05-wsl-<12 hex> directory directly under the scratch root is this runner''s to remove' (
        (Test-OwnRunDirectory $root (Join-Path $root 'hm-m05-wsl-0a1b2c3d4e5f')) -and -not (Test-OwnRunDirectory $root $root) -and
        -not (Test-OwnRunDirectory $root (Join-Path $root 'hm-m05-wsl-0a1b2c3d4e5')) -and -not (Test-OwnRunDirectory $root (Join-Path $root 'hm-m04-modeb-0a1b2c3d4e5f')) -and
        -not (Test-OwnRunDirectory $root (Join-Path (Join-Path $root 'x') 'hm-m05-wsl-0a1b2c3d4e5f')) -and -not (Test-OwnRunDirectory $root (Join-Path (Join-Path $root '..') 'hm-m05-wsl-0a1b2c3d4e5f')))

    # The journeys' verdict.
    $good = "### wsl_hook_m05`n" + (($ExpectedSteps | ForEach-Object { "test $_ ... ok" }) -join "`n") + "`nfact leftover-processes=0`n### wsl_hook_m05 exit=0`n"
    $vGood = Get-JourneyVerdict ("wsl noise`r`n" + ($good -replace "`n", "`r`n") + "trailing noise`r`n") 0 $JourneyTarget $ExpectedSteps
    Check 'V01 all eight steps ok, exit 0 on both sides: pass (wsl.exe noise and CRLF aside)' ($vGood.Pass -and $vGood.Ok -eq 8 -and $vGood.Failed -eq 0 -and $vGood.Missing -eq 0 -and $ExpectedSteps.Count -eq 8)
    $oneFailed = $good -replace "test $($ExpectedSteps[3]) \.\.\. ok", "test $($ExpectedSteps[3]) ... FAILED" -replace 'exit=0', 'exit=1'
    $vF = Get-JourneyVerdict $oneFailed 1 $JourneyTarget $ExpectedSteps
    $vFmask = Get-JourneyVerdict ($oneFailed -replace 'exit=1', 'exit=0') 0 $JourneyTarget $ExpectedSteps
    Check 'V02 a FAILED step fails the run, even when its exit codes were forged to 0' (-not $vF.Pass -and $vF.Failed -eq 1 -and -not $vFmask.Pass -and $vFmask.Reason.Contains($ExpectedSteps[3]))
    $vMiss = Get-JourneyVerdict ($good -replace "test $($ExpectedSteps[7]) \.\.\. ok`n", '') 0 $JourneyTarget $ExpectedSteps
    Check 'V03 a step that never printed fails the run' (-not $vMiss.Pass -and $vMiss.Missing -eq 1)
    Check 'V04 a nonzero process exit, a refused start and a timeout fail the run' (-not (Get-JourneyVerdict $good 124 $JourneyTarget $ExpectedSteps).Pass -and
        -not (Get-JourneyVerdict "refused: not inside a disposable hm-m05-<8 hex> distribution`n" 2 $JourneyTarget $ExpectedSteps).Pass -and -not (Get-JourneyVerdict '' 0 $JourneyTarget $ExpectedSteps).Pass)
    $fmt = Format-JourneyTests "noise`n$good`nnoise`n" 0 $JourneyTarget
    Check 'V05 the saved tests.txt is the script''s part only; a refused start gets a header and a nonzero exit line' (
        $fmt.StartsWith("### wsl_hook_m05`n") -and $fmt.EndsWith("### wsl_hook_m05 exit=0`n") -and -not $fmt.Contains('noise') -and
        (Format-JourneyTests 'refused' 0 $JourneyTarget) -ceq "### wsl_hook_m05`n### wsl_hook_m05 exit=1`n" -and (Format-JourneyTests '' 2 $JourneyTarget) -ceq "### wsl_hook_m05`n### wsl_hook_m05 exit=2`n")
    $journeysPath = Join-Path $PSScriptRoot 'wsl-hook-journeys.sh'
    $inScript = if (Test-Path -LiteralPath $journeysPath) {
        @([regex]::Matches([System.IO.File]::ReadAllText($journeysPath), '(?m)^(?:run_test|step) (m05_wsl_[a-z0-9_]+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    } else { @() }
    Check 'V06 the expected steps are exactly the steps wsl-hook-journeys.sh prints' ((($inScript -join ',') -ceq (($ExpectedSteps | Sort-Object -Unique) -join ',')) -and $inScript.Count -eq 8)
    $rl = Format-ResultLines $JourneyTarget 0 $good
    Check 'V07 the plain result lines: the target and its exit, each step''s outcome, nothing else' (
        $rl -ceq ("### wsl_hook_m05 exit=0`n" + (($ExpectedSteps | ForEach-Object { "test $_ ... ok" }) -join "`n") + "`n"))

    # Redaction, the canary scan and the bundle round trip, through the M02 runner's helpers.
    $rules = Get-RunRedactionRules @{ wsluser = 'wslfixtureuser'; wslhome = '/home/wslfixtureuser'; wslhost = 'WSLBOX' } 'C:\S\hm-m05-wsl-00' 'C:\Users\fixtureuser' 'fixtureuser' 'PCNAME' 'pcname.example'
    $raw = @{
        'tests.txt' = "### wsl_hook_m05`ntest a ... ok`nhome C:\Users\fixtureuser\x /home/wslfixtureuser/y on PCNAME WSLBOX 203.0.113.9 HEIMDALL_CANARY_abc123`n### wsl_hook_m05 exit=0`n"
        'commands.txt' = "exit 0: step`n"; 'host.txt' = "image-sha256=$RootfsSha256`n"; 'build.txt' = "run C:\S\hm-m05-wsl-00\files`n"; 'skipped.txt' = ''; 'canary-scan.txt' = ''
    }
    $pb = New-ProtectedBundle $raw $rules 'label on PCNAME' ('0' * 40) '2026-01-01T00:00:00Z' 0
    $doc = ConvertFrom-BundleText $pb.Bundle.Text
    $allText = ($doc['files'].Values -join "`n") + $doc['label']
    Check 'R01 the M02 redaction applies (windows home, wsl home, hosts, run directory, non-loopback address) and the canary is masked and counted' (
        $doc['files']['tests.txt'].Contains('home <winhome>\x <wslhome>/y on <winhost> <wslhost> <addr> <canary>') -and $doc['files']['build.txt'].Contains('run <run>\files') -and
        $pb.Canaries -eq 1 -and $allText -notmatch 'HEIMDALL_CANARY_|fixtureuser|PCNAME|WSLBOX|203\.0\.113\.9' -and $doc['label'] -ceq 'label on <winhost>')
    Check 'R02 a canary finding turns a passing run into exit 1 and is in canary-scan.txt and commands.txt' (
        $pb.Exit -eq 1 -and $doc['exit'] -eq 1 -and $doc['files']['canary-scan.txt'].Contains(': 1 ') -and $doc['files']['commands.txt'].Contains('exit 1: canary-prefix scan'))
    $clean = New-ProtectedBundle @{ 'tests.txt' = "### wsl_hook_m05`ntest $($ExpectedSteps[0]) ... ok`n### wsl_hook_m05 exit=0`n"; 'commands.txt' = "exit 0: x`n"; 'host.txt' = "k=v`n"; 'build.txt' = ''; 'skipped.txt' = ''; 'canary-scan.txt' = '' } $rules 'plain' ('1' * 40) '2026-01-01T00:00:00Z' 0
    $cdoc = ConvertFrom-BundleText $clean.Bundle.Text
    Check 'B01 the bundle round trip: this runner''s format and markers, exactly the six result files, every digest, the commit, the exit' (
        $cdoc['format'] -ceq $BundleFormat -and $clean.Bundle.Text.StartsWith($BeginMarker) -and $clean.Bundle.Text.TrimEnd().EndsWith($EndMarker) -and
        (($cdoc['files'].Keys | Sort-Object) -join ',') -ceq (($BundleFiles | Sort-Object) -join ',') -and $cdoc['commit'] -ceq ('1' * 40) -and $cdoc['exit'] -eq 0 -and $clean.Exit -eq 0 -and $clean.Canaries -eq 0 -and $clean.Leaks -eq 0)
    $table = $clean.Files
    Check 'B02 the file table is one object every bundle file can be indexed in' ($clean -isnot [array] -and $table -is [System.Collections.IDictionary] -and @($table.Keys).Count -eq $BundleFiles.Count)
    if ($Out) {
        [System.IO.File]::WriteAllText($Out, $clean.Bundle.Text, [System.Text.UTF8Encoding]::new($false))
        Write-Host "wrote the synthetic bundle to the -Out file"
    }

    # The reuse itself: M04's loaded functions run against this script's own variables.
    $psExe = Join-Path $PSHOME 'pwsh'
    if (-not (Test-Path -LiteralPath $psExe)) { $psExe = Join-Path $PSHOME 'pwsh.exe' }
    $r1 = Invoke-Bounded $psExe @('-NoProfile', '-NonInteractive', '-Command', 'Write-Output hello; exit 3') $null $PSScriptRoot 60
    $r2 = Invoke-Bounded $psExe @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60') $null $PSScriptRoot 2
    Check 'E01 M04''s Invoke-Bounded: the exit code and output, and a timeout stopped through its own handle (124)' ($r1.Code -eq 3 -and $r1.Output.Contains('hello') -and $r2.TimedOut -and $r2.Code -eq 124)
    $script:names = @($own)
    $refused = $false
    try { [void](Invoke-InDistro 'Ubuntu' 'root' 'true' @() 5) } catch { $refused = $_.Exception.Message -like '*did not create*' }
    Check 'E02 M04''s Invoke-InDistro refuses a distribution this run did not create' $refused
    $scripts = Get-DistroScripts
    Check 'E03 M04''s root-phase script (target-root.sh) is available, and runs as `bash -s`' ($scripts.Contains('root-phase') -and $scripts['root-phase'].Contains('target-root.sh'))
    $selfText = [System.IO.File]::ReadAllText($PSCommandPath)
    Check 'E04 the import is recorded as attempted, with a marker file, before `wsl --import` runs; the unregister is by exact name after a terminate' (
        $selfText.IndexOf('$attempted.Add($distroName)') -gt 0 -and $selfText.IndexOf('$attempted.Add($distroName)') -lt $selfText.IndexOf("'--import', `$distroName") -and
        $selfText.IndexOf('WriteAllText($markerFile') -lt $selfText.IndexOf("'--import', `$distroName") -and $selfText.Contains("Invoke-WslExe @('--terminate', `$n)") -and $selfText.Contains("Invoke-WslExe @('--unregister', `$n)"))
    $selfAst = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)
    # The arguments the run passes to wsl.exe (this self-test's own strings aside).
    $stFn = $selfAst.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq 'Invoke-SelfTest' }, $false)
    $wslArgs = @($selfAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                ($a.Extent.EndOffset -le $stFn.Extent.StartOffset -or $a.Extent.StartOffset -ge $stFn.Extent.EndOffset) }, $true))
    $shutdown = @($wslArgs | Where-Object { $_.Value -ceq '--shutdown' })
    $unreg = @($wslArgs | Where-Object { $_.Value -ceq '--unregister' })
    Check 'E05 no `wsl --shutdown` argument anywhere, and `--unregister` appears once (the cleanup)' ($shutdown.Count -eq 0 -and $unreg.Count -eq 1)
    $hook = Get-HookScripts
    Check 'E06 the packages script installs zsh, openssh-server, openssh-client, git and util-linux behind allow-apt, services blocked first' (
        $hook['packages'].Contains('apt-get -q -y install --no-install-recommends zsh openssh-server openssh-client git util-linux') -and
        $hook['packages'].IndexOf('policy-rc.d') -lt $hook['packages'].IndexOf('apt-get -q -y install') -and $hook['packages'].Contains('[ "$allow" != 1 ]') -and $hook['packages'].Contains('exit 3'))
    Check 'E07 every script sent in refuses outside the named distribution' (@(@('packages', 'user-facts', 'stage', 'journeys') | Where-Object { -not $hook[$_].Contains('WSL_DISTRO_NAME:-}" = "$1"') }).Count -eq 0)

    # Ownership of a registration (M05-W4F-RC-R04): synthetic {DistributionName, BasePath} rows, no WSL.
    $ownDir = 'C:\Users\fixtureuser\hm\hm-m05-wsl-0a1b2c3d4e5f\distros\hm-m05-0a1b2c3d'
    $otherDir = 'C:\Users\fixtureuser\hm\hm-m05-wsl-ffffffffffff\distros\hm-m05-0a1b2c3d'
    $mkRows = {
        param([string]$P)
        $rows0 = @([pscustomobject]@{ DistributionName = 'Ubuntu'; BasePath = 'C:\Users\fixtureuser\AppData\Local\wsl\ubuntu' },
            [pscustomobject]@{ DistributionName = $own; BasePath = $P })
        return { $rows0 }.GetNewClosure()
    }
    $srcOwn = & $mkRows "\\?\$ownDir"
    $srcOther = & $mkRows $otherDir
    Check 'P01 path normalization: the \\?\ and \\.\ and \??\ prefixes, case, trailing and repeated separators, forward slashes' (
        (ConvertTo-ComparablePath "\\?\$ownDir") -ceq $ownDir.ToLowerInvariant() -and (ConvertTo-ComparablePath $ownDir.ToUpperInvariant()) -ceq $ownDir.ToLowerInvariant() -and
        (ConvertTo-ComparablePath "$ownDir\") -ceq $ownDir.ToLowerInvariant() -and (ConvertTo-ComparablePath ($ownDir + '\\')) -ceq $ownDir.ToLowerInvariant() -and
        (ConvertTo-ComparablePath ($ownDir.Replace('\', '/'))) -ceq $ownDir.ToLowerInvariant() -and (ConvertTo-ComparablePath "\\.\$ownDir") -ceq $ownDir.ToLowerInvariant() -and
        (ConvertTo-ComparablePath "\??\$ownDir") -ceq $ownDir.ToLowerInvariant() -and (ConvertTo-ComparablePath 'C:\a\\b') -ceq 'c:\a\b' -and
        (ConvertTo-ComparablePath '\\?\UNC\Srv\Share\X\') -ceq '\\srv\share\x' -and (ConvertTo-ComparablePath '\\Srv\Share\X') -ceq '\\srv\share\x')
    Check 'P02 path normalization refuses blank, relative, dot-segment and rootless paths (a $null, never a guess)' (
        $null -eq (ConvertTo-ComparablePath '') -and $null -eq (ConvertTo-ComparablePath $null) -and $null -eq (ConvertTo-ComparablePath '   ') -and
        $null -eq (ConvertTo-ComparablePath 'relative\dir') -and $null -eq (ConvertTo-ComparablePath 'C:\a\..\b') -and $null -eq (ConvertTo-ComparablePath 'C:\a\.\b') -and
        $null -eq (ConvertTo-ComparablePath '\\?\') -and $null -eq (ConvertTo-ComparablePath '\\srv') -and $null -eq (ConvertTo-ComparablePath "C:\a`0b") -and
        $null -eq (ConvertTo-ComparablePath '\temp\x'))
    Check 'O01 the name is this run''s and its install directory is this run''s (with or without the \\?\ prefix, any case): owned' (
        (Test-OwnRegistration $own $ownDir @('Ubuntu') $srcOwn) -and (Test-OwnRegistration $own $ownDir.ToUpperInvariant() @() $srcOwn) -and
        (Test-OwnRegistration $own "$ownDir\" @('Ubuntu') (& $mkRows $ownDir.ToUpperInvariant())))
    Check 'O02 the right name under another run''s directory is NOT owned: never used, never terminated, never unregistered' (
        -not (Test-OwnRegistration $own $ownDir @('Ubuntu') $srcOther) -and -not (Test-OwnRegistration $own $otherDir @('Ubuntu') $srcOwn))
    Check 'O03 a name already in the census before the run is NOT owned, even under this run''s directory' (
        -not (Test-OwnRegistration $own $ownDir @('Ubuntu', $own) $srcOwn) -and -not (Test-OwnRegistration $own $ownDir @($own) $srcOwn))
    $srcThrows = { throw 'registry unreadable' }
    Check 'O04 an unreadable directory is NOT owned: unreadable rows, no row, a blank or relative BasePath, the name twice, a failed census, a name not of this runner''s form' (
        -not (Test-OwnRegistration $own $ownDir @('Ubuntu') $srcThrows) -and -not (Test-OwnRegistration $own $ownDir @('Ubuntu') { @() }) -and
        -not (Test-OwnRegistration $own $ownDir @('Ubuntu') (& $mkRows '')) -and -not (Test-OwnRegistration $own $ownDir @('Ubuntu') (& $mkRows 'relative\dir')) -and
        -not (Test-OwnRegistration $own $ownDir @('Ubuntu') { @([pscustomobject]@{ DistributionName = 'hm-m05-0a1b2c3d'; BasePath = 'C:\x' }, [pscustomobject]@{ DistributionName = 'HM-M05-0A1B2C3D'; BasePath = 'C:\x' }) }) -and
        -not (Test-OwnRegistration $own $ownDir $null $srcOwn) -and -not (Test-OwnRegistration $own '' @('Ubuntu') $srcOwn) -and
        -not (Test-OwnRegistration 'Ubuntu' 'C:\Users\fixtureuser\AppData\Local\wsl\ubuntu' @() $srcOwn) -and -not (Test-OwnRegistration 'hm-m04-0a1b2c3d-1' 'C:\x' @() { @([pscustomobject]@{ DistributionName = 'hm-m04-0a1b2c3d-1'; BasePath = 'C:\x' }) }))
    Check 'O05 the install directory is looked up by name only (a row for another name, with this run''s directory, does not count)' (
        $null -eq (Get-DistributionInstallDirectory $own { @([pscustomobject]@{ DistributionName = 'Ubuntu'; BasePath = $ownDir }) }) -and
        (Get-DistributionInstallDirectory $own $srcOwn) -ceq $ownDir.ToLowerInvariant())
    $ownThrew = $false
    try { Assert-OwnRegistration $own $ownDir @('Ubuntu') } catch { $ownThrew = $_.Exception.Message -like '*not registered under this run''s install directory*' }
    $ownedRefused = $false
    try { [void](Invoke-OwnedInDistro $own $ownDir @('Ubuntu') 'root' 'true' @() 5) } catch { $ownedRefused = $_.Exception.Message -like '*not registered under this run''s install directory*' }
    Check 'O06 Assert-OwnRegistration and Invoke-OwnedInDistro refuse before anything runs when the registration is not shown to be this run''s (no Lxss key for it here)' ($ownThrew -and $ownedRefused)
    $lxss = (Get-Command Read-LxssRows -CommandType Function).ScriptBlock.ToString()
    Check 'O07 the registry read is the current user''s Lxss key: HKCU Software\Microsoft\Windows\CurrentVersion\Lxss, DistributionName and BasePath' (
        $lxss.Contains('CurrentUser.OpenSubKey(''Software\Microsoft\Windows\CurrentVersion\Lxss'')') -and $lxss.Contains("GetValue('DistributionName'") -and $lxss.Contains("GetValue('BasePath'"))
    $censusMsg = ''
    try { [void](Get-CensusOrThrow { $null }) } catch { $censusMsg = $_.Exception.Message }
    $censusOk = Get-CensusOrThrow { , @('Ubuntu', 'Debian') }
    $censusEmpty = Get-CensusOrThrow { , @() }
    # The function boundary the run uses: wsl.exe's list through M04's Get-RegisteredOrNull. A failing
    # `wsl --list --quiet` (exit 1) is a failed census, not an empty set; a succeeding one is the set.
    $viaWsl = & {
        function Invoke-WslExe([string[]]$Arguments, [int]$Seconds = 600) { return [pscustomobject]@{ Code = 1; Output = ''; TimedOut = $false } }
        $failMsg = ''
        try { [void](Get-CensusOrThrow) } catch { $failMsg = $_.Exception.Message }
        $failNull = $null -eq (Get-RegisteredOrNull)
        function Invoke-WslExe([string[]]$Arguments, [int]$Seconds = 600) { return [pscustomobject]@{ Code = 0; Output = "Ubuntu`r`n"; TimedOut = $false } }
        $okNames = Get-CensusOrThrow
        [pscustomobject]@{ FailMsg = $failMsg; FailNull = $failNull; Names = $okNames }
    }
    Check 'K01 a failed census (a $null listing, or wsl.exe''s list exiting nonzero) throws before an import; an empty successful listing is a valid empty set' (
        $censusMsg.Contains('could not be listed') -and $viaWsl.FailMsg.Contains('could not be listed') -and $viaWsl.FailNull -and
        ($viaWsl.Names -join ',') -ceq 'Ubuntu' -and ($censusOk -join ',') -ceq 'Ubuntu,Debian' -and $censusEmpty.Count -eq 0 -and $censusEmpty -is [array])
    $mainText = $selfText.Remove($stFn.Extent.StartOffset, $stFn.Extent.EndOffset - $stFn.Extent.StartOffset)
    $iCensus = $mainText.IndexOf('$before = Get-CensusOrThrow')
    $iNames = $mainText.IndexOf('$names = @($distroName)')
    $iImport = $mainText.IndexOf("'--import', `$distroName")
    $iMarker = $mainText.IndexOf('WriteAllText($markerFile')
    Check 'K02 in the run, the successful census comes first: before the name is chosen, the marker is written and `wsl --import` runs; no listing without a failure check feeds $before' (
        $iCensus -gt 0 -and $iCensus -lt $iNames -and $iNames -gt 0 -and $iNames -lt $iMarker -and $iMarker -lt $iImport -and -not $mainText.Contains('$before = @(Get-Registered)'))
    $iUnreg = $mainText.IndexOf("Invoke-WslExe @('--unregister', `$n)")
    $iTermN = $mainText.IndexOf("Invoke-WslExe @('--terminate', `$n)")
    $iGate = $mainText.IndexOf('if (-not (Test-OwnRegistration $n $dir $before))')
    $mainAfterImport = $mainText.Substring($iImport)
    $rawDistro = [regex]::Matches($mainAfterImport, 'Invoke-InDistro \$distroName').Count
    $termDistro = [regex]::Matches($mainAfterImport, "Invoke-WslExe @\('--terminate', \`$distroName\)").Count
    $assertedTerm = [regex]::Matches($mainAfterImport, "Assert-OwnRegistration \`$distroName \`$dir \`$before\s+\[void\]\(Invoke-WslExe @\('--terminate', \`$distroName\)").Count
    Check 'K03 the ownership check gates every use: right after the import (the created list), every phase in the distribution, the mid-run terminates, and the cleanup''s terminate and unregister' (
        $mainText.Contains('if (Test-OwnRegistration $distroName $dir $before)') -and $mainText.IndexOf('$created.Add($distroName)') -gt $iImport -and
        $rawDistro -eq 0 -and $mainAfterImport.Contains('Invoke-OwnedInDistro $distroName $dir $before') -and
        $termDistro -eq 2 -and $assertedTerm -eq 2 -and
        $iGate -gt 0 -and $iGate -lt $iTermN -and $iTermN -lt $iUnreg)
    $paramNames = @($selfAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() })
    $clashes = @($selfAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
            Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and ($paramNames -contains $_.Left.VariablePath.UserPath.ToLowerInvariant()) })
    Check 'S02 nothing assigns to a parameter''s name (case-insensitive)' ($clashes.Count -eq 0)
    $bash = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $bash) {
        $all = [ordered]@{}
        foreach ($k in $hook.Keys) { $all["m05 $k"] = $hook[$k] }
        $all['m04 root-phase'] = $scripts['root-phase']
        foreach ($k in $all.Keys) {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tmp, ($all[$k] -replace "`r`n", "`n"))
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
# Inputs: nothing is created before these pass.
# ---------------------------------------------------------------------------------------------

function Stop-Run([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("run-wsl-hook-windows: $Message")
    exit $Code
}

if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Run 2 '-Commit must be the 40-hex commit' }
if ($TimeoutSeconds -lt 600) { Stop-Run 2 '-TimeoutSeconds must be at least 600' }
$bundleCheck = Test-InputDigest $Bundle $BundleSha256 'the BINDIR tarball (-Bundle, -BundleSha256)'
if ($bundleCheck.Code -ne 0) { Stop-Run $bundleCheck.Code $bundleCheck.Message }
if (-not $Rootfs -and -not $Download) { Stop-Run 3 'blocked: the pinned image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1)' }
if ($Rootfs) {
    $imageCheck = Test-InputDigest $Rootfs $RootfsSha256 'the image (-Rootfs; not the pinned one when it differs)'
    if ($imageCheck.Code -ne 0) { Stop-Run $imageCheck.Code $imageCheck.Message }
}
$m02Dir = Join-Path (Join-Path $PSScriptRoot '..') 'm02'
$sentFiles = [ordered]@{
    'wsl-hook-journeys.sh' = (Join-Path $PSScriptRoot 'wsl-hook-journeys.sh')
    'remote-lib.sh'        = (Join-Path $m02Dir 'remote-lib.sh')
    'target-root.sh'       = (Join-Path $m02Dir 'target-root.sh')
}
foreach ($k in $sentFiles.Keys) {
    if (-not (Test-Path -LiteralPath $sentFiles[$k] -PathType Leaf)) { Stop-Run 3 "blocked: $k is missing in this checkout" }
}
if ((Get-CrlfFileCount @($sentFiles.Values)) -ne 0) { Stop-Run 2 'a script sent into the distribution has CRLF line endings (check this checkout out with LF)' }

if (-not $IsWindows) { Stop-Run 2 'run-wsl-hook-windows.ps1 runs on the Windows PC itself (use -SelfTest elsewhere)' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Run 2 'refusing to run elevated: this runner never needs administrator rights'
}
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) { Stop-Run 2 '-ScratchRoot is required' }
$rootItem = Get-Item -LiteralPath $ScratchRoot -Force -ErrorAction SilentlyContinue
if ($null -eq $rootItem -or -not $rootItem.PSIsContainer) { Stop-Run 2 '-ScratchRoot must be an existing directory' }
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Run 2 '-ScratchRoot is a reparse point: refused' }
$OutFile = ''
if ($Out) {
    $OutFile = [System.IO.Path]::GetFullPath($Out)
    if (Test-Path -LiteralPath $OutFile) { Stop-Run 2 '-Out exists already: it is never overwritten' }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $OutFile) -PathType Container)) { Stop-Run 2 '-Out''s directory does not exist' }
}

# ---------------------------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------------------------

$sys32 = Join-Path $env:SystemRoot 'System32'
$wslExe = Join-Path $sys32 'wsl.exe'
$run = Join-Path $rootItem.FullName ('hm-m05-wsl-' + (New-RandomHex 6))
if (Test-Path -LiteralPath $run) { Stop-Run 2 'the run directory exists already' }
[void](New-Item -ItemType Directory -Path $run -ErrorAction Stop)
if (-not (Test-OwnRunDirectory $rootItem.FullName $run)) { Stop-Run 2 'the run directory is not of this runner''s form' }
$stockOut = (& (Join-Path $env:SystemRoot 'System32\icacls.exe') @(Get-StockProfileGrantArguments $run ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 2>&1 | Out-String)
$stockRc = $LASTEXITCODE
$files = Join-Path $run 'files'
$distroRoot = Join-Path $run 'distros'
$bundleDir = Join-Path $run 'bundle'
foreach ($d in @($files, $distroRoot, $bundleDir)) { [void][System.IO.Directory]::CreateDirectory($d) }
$resultsFile = Join-Path $bundleDir 'results.txt'
$markerFile = Join-Path $run 'pending-import.txt'

$started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$commands = [System.Text.StringBuilder]::new()
$hostFacts = [System.Text.StringBuilder]::new()
$build = [System.Text.StringBuilder]::new()
$distFacts = [System.Text.StringBuilder]::new()
$testsText = ''
$overall = 0
$created = [System.Collections.Generic.List[string]]::new()
$attempted = [System.Collections.Generic.List[string]]::new()
$before = @()
$dir = ''
$names = @()
$wv = @{}
$bundleSaved = $false
$image = ''
$stepClock = [System.Diagnostics.Stopwatch]::StartNew()
$wslEnv = New-ChildEnvironment @{ WSL_UTF8 = '1' }
$m04Scripts = Get-DistroScripts
$hookScripts = Get-HookScripts

try {
    Add-Command $stockRc 'icacls: the run root gets the protected stock profile list (the user, SYSTEM, Administrators; inherited by what is created inside)'
    if ($stockRc -ne 0) { [void]$build.Append($stockOut); throw 'the run root''s list could not be set' }
    Add-Fact 'os' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ver') $null $run 30).Output.Trim())
    $groups = (Invoke-Bounded (Join-Path $sys32 'whoami.exe') @('/groups') $null $run 30).Output
    Add-Fact 'integrity' ([regex]::Match($groups, '(Medium|High|System) Mandatory Level').Value)
    Add-Fact 'wsl-version' (((Invoke-WslExe @('--version') 60).Output -replace "`0", '' -split "`n" | Select-Object -First 1).Trim())
    Add-Fact 'build-commit' "$Commit (a label: the scripts are this checkout's)"
    Add-Fact 'bindir-tarball-sha256' "$($bundleCheck.Sha256) (equals -BundleSha256)"
    Add-Command 0 $bundleCheck.Message
    foreach ($k in $sentFiles.Keys) { Add-Fact "sent-$k-sha256" ((Get-FileHash -LiteralPath $sentFiles[$k] -Algorithm SHA256).Hash.ToLowerInvariant()) }
    Add-Fact 'runner-sha256' ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant())

    # The registered set, and this run's one name.
    # The census must have succeeded: a failed listing stops the run here, before anything is imported.
    $before = Get-CensusOrThrow
    Add-Command 0 "wsl --list --quiet: the census before the run ($($before.Count) registered)"
    $distroName = Get-DistributionName (New-RandomHex 4)
    $names = @($distroName)
    Add-DistributionFacts 'before'
    if (-not (Test-OwnDistributionName $distroName) -or ($before -contains $distroName)) { throw 'a distribution with this run''s name is registered already; nothing imported' }
    Add-Command 0 'wsl --list: this run''s name is not registered'

    # The files the distribution reads: copied, and each copy checked against its source.
    Copy-Item -LiteralPath $Bundle -Destination (Join-Path $files 'bindir.tar')
    foreach ($k in $sentFiles.Keys) { Copy-Item -LiteralPath $sentFiles[$k] -Destination (Join-Path $files $k) }
    # target-root.sh prepare installs FILES/heimdall as the user's ~/heimdall; the build under test
    # is BINDIR/heimdall, so this one is a placeholder that refuses to run.
    [System.IO.File]::WriteAllText((Join-Path $files 'heimdall'), "#!/bin/sh`necho 'placeholder: the build under test is BINDIR/heimdall' >&2`nexit 1`n", [System.Text.UTF8Encoding]::new($false))
    $copyOk = ((Get-FileHash -LiteralPath (Join-Path $files 'bindir.tar') -Algorithm SHA256).Hash.ToLowerInvariant() -eq $bundleCheck.Sha256)
    foreach ($k in $sentFiles.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $files $k) -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $sentFiles[$k] -Algorithm SHA256).Hash) { $copyOk = $false }
    }
    Add-Command $(if ($copyOk) { 0 } else { 1 }) 'the tarball and the scripts are copied into the run directory, each equal to its source'
    if (-not $copyOk) { throw 'a copied input changed' }

    # The pinned image.
    $image = if ($Rootfs) { (Get-Item -LiteralPath $Rootfs).FullName } else { Join-Path $run 'ubuntu-24.04.5-wsl-amd64.wsl' }
    if (-not $Rootfs) {
        Invoke-WebRequest -Uri $RootfsUrl -OutFile $image
        Add-Command 0 'the pinned image downloaded over HTTPS'
    }
    $imgSha = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
    Add-Fact 'image-sha256' "$imgSha ($(if ($imgSha -eq $RootfsSha256) { 'the M02 pin' } else { 'NOT the pin' }))"
    Add-Command $(if ($imgSha -eq $RootfsSha256) { 0 } else { 1 }) 'the image is the pinned one (sha256)'
    if ($imgSha -ne $RootfsSha256) { throw 'the image is not the pinned one; nothing imported' }

    # The pending-import marker, then the import (the install directory is the run directory's).
    $dir = Join-Path $distroRoot $distroName
    [void][System.IO.Directory]::CreateDirectory($dir)
    [System.IO.File]::WriteAllText($markerFile, "$distroName`n", [System.Text.UTF8Encoding]::new($false))
    $attempted.Add($distroName)
    $r = $null
    $foreign = $false
    try {
        $r = Invoke-WslExe @('--import', $distroName, $dir, $image, '--version', '2') 1800
    } finally {
        # Recorded as this run's as soon as it is registered under this run's install directory,
        # whatever the exit code said (a partial import included). The same name registered
        # anywhere else is another run's: never recorded, never used, never removed.
        if (Test-OwnRegistration $distroName $dir $before) {
            if (-not ($created -contains $distroName)) { $created.Add($distroName) }
        } else {
            $listed = Get-RegisteredOrNull
            if ($null -ne $listed -and ($listed -contains $distroName)) { $foreign = $true }
        }
    }
    Add-Command $r.Code "wsl --import $distroName (into the run directory, WSL 2)"
    if ($foreign) {
        Add-Command 1 "$distroName is registered, but not under this run's install directory: another run's, so it is not used and not removed"
        throw "$distroName is registered under another install directory; nothing was run in it"
    }
    if ($r.Code -ne 0 -or -not ($created -contains $distroName)) { throw "the import of $distroName failed" }
    Add-DistributionFacts 'after-import'

    # As root, in this distribution only.
    $r = Invoke-OwnedInDistro $distroName $dir $before 'root' $m04Scripts['root-phase'] @($files, $distroName, 'no-systemd') 600
    Add-Command $r.Code "$distroName`: target-root.sh no-systemd"
    if ($r.Code -ne 0) { throw 'no-systemd failed' }
    Assert-OwnRegistration $distroName $dir $before
    [void](Invoke-WslExe @('--terminate', $distroName) 120)
    $aptFlag = if ($AllowApt) { '1' } else { '0' }
    $r = Invoke-OwnedInDistro $distroName $dir $before 'root' $hookScripts['packages'] @($distroName, $aptFlag) 3600
    [void]$build.Append("### $distroName packages`n$($r.Output)`n")
    Add-Command $r.Code "$distroName`: packages (zsh, openssh-server, openssh-client, git, util-linux; apt $(if ($AllowApt) { 'allowed' } else { 'not allowed: check only' }))"
    if ($r.Code -eq 3) { $overall = 3; throw "$distroName lacks tools (-AllowApt installs them inside it)" }
    if ($r.Code -ne 0) { throw 'the packages step failed' }
    $r = Invoke-OwnedInDistro $distroName $dir $before 'root' $m04Scripts['root-phase'] @($files, $distroName, 'prepare', $User, $aptFlag) 3600
    [void]$build.Append("### $distroName prepare`n$($r.Output)`n")
    Add-Command $r.Code "$distroName`: target-root.sh prepare (tools, git, python3; the non-root user)"
    if ($r.Code -eq 3) { $overall = 3; throw "$distroName lacks tools (-AllowApt installs them inside it)" }
    if ($r.Code -ne 0) { throw 'prepare failed' }
    Assert-OwnRegistration $distroName $dir $before
    [void](Invoke-WslExe @('--terminate', $distroName) 120)

    # As the non-root user: facts for the redaction, versions, the inputs, the journeys.
    $r = Invoke-OwnedInDistro $distroName $dir $before $User $hookScripts['user-facts'] @($distroName) 120
    foreach ($l in ($r.Output -split "`n")) { if ($l -match '^([a-z]+)=(.*)$') { $wv[$Matches[1]] = $Matches[2].Trim() } }
    Add-Command $r.Code 'the non-root user''s facts (kept only as redaction rules)'
    if ($r.Code -ne 0 -or -not $wv['wsluser']) { throw 'the non-root user is not usable' }
    $r = Invoke-OwnedInDistro $distroName $dir $before $User $hookScripts['versions'] @() 120
    foreach ($l in ($r.Output -replace "`r", '' -split "`n")) { if ($l -match '^([a-z0-9-]+)=(.*)$') { Add-Fact "wsl-$($Matches[1])" $Matches[2] } }
    Add-Command $r.Code 'versions inside the distribution'
    $r = Invoke-OwnedInDistro $distroName $dir $before $User $hookScripts['stage'] @($distroName, $files, $bundleCheck.Sha256) 600
    [void]$build.Append("### $distroName stage`n$($r.Output)`n")
    foreach ($l in ($r.Output -replace "`r", '' -split "`n")) { if ($l -match '^(bindir-files|bindir-sha256|heimdall-sha256|tar-members|bundle-digest-in-distribution)=(.*)$') { Add-Fact "stage-$($Matches[1])" $Matches[2] } }
    Add-Command $r.Code 'the tarball is checked inside the distribution, extracted, and BINDIR is verified against BINDIR.sha256'
    if ($r.Code -ne 0) { throw 'the inputs could not be staged' }

    $scratch = Get-DistroScratch (New-RandomHex 4)
    if (-not (Test-ScratchLength $scratch)) { throw 'the scratch path is too long' }
    $r = Invoke-OwnedInDistro $distroName $dir $before $User $hookScripts['journeys'] @($distroName, $scratch) $TimeoutSeconds
    $testsText = Format-JourneyTests $r.Output $r.Code $JourneyTarget
    $verdict = Get-JourneyVerdict $r.Output $r.Code $JourneyTarget $ExpectedSteps
    if (-not $verdict.Pass) { [void]$build.Append("### journeys output (tail)`n$((($r.Output -replace "`r", '') -split "`n" | Select-Object -Last 60) -join "`n")`n") }
    Add-Command $r.Code "bash wsl-hook-journeys.sh <scratch> <BINDIR> as the non-root user -> $($verdict.Ok) of $($ExpectedSteps.Count) steps ok$(if (-not $verdict.Pass) { "; $($verdict.Reason)" })"
    # As it goes: printed, and kept in results.txt (names and outcomes only).
    $plain = Format-ResultLines $JourneyTarget $r.Code $r.Output
    Write-Output $plain
    [System.IO.File]::AppendAllText($resultsFile, $plain, [System.Text.UTF8Encoding]::new($false))
    if (-not $verdict.Pass) { $overall = 1 }
} catch {
    # The failing line and the script's stack (redacted with the bundle; printed with it).
    Add-Command 1 "the run stopped: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    [void]$build.Append("### the run stopped`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)`n")
    if ($overall -eq 0) { $overall = 1 }
} finally {
  try {
    # Cleanup: each step reports its own failure and never stops the others or the bundle.
    $kept = $null
    try {
        if ($attempted.Count -gt 0) {
            $now = @(Get-Registered)
            foreach ($n in @(Select-RemovableDistributions $attempted.ToArray() $before $now)) {
                # Never terminate or unregister a registration whose install directory is not this
                # run's, even with the right name (its directory and marker are kept, below).
                if (-not (Test-OwnRegistration $n $dir $before)) {
                    Add-Command 1 "$n is registered, but its install directory is not this run's (or could not be read): not terminated, not unregistered; this run's install directory and pending-import.txt are kept"
                    if ($overall -eq 0) { $overall = 1 }
                    continue
                }
                [void](Invoke-WslExe @('--terminate', $n) 120)
                $r = Invoke-WslExe @('--unregister', $n) 600
                Add-Command $r.Code "wsl --unregister $n (this run's, by exact name)"
                if ($r.Code -ne 0 -and $overall -eq 0) { $overall = 1 }
            }
            # Keep the install directory (and the marker) of any distribution not known to be gone.
            $kept = @(Select-KeptInstallDirectories $attempted.ToArray() (Get-RegisteredOrNull))
            foreach ($n in $kept) {
                Add-Command 1 "$n may still be registered: its install directory and pending-import.txt under the run directory are kept (unregister it by this exact name, then remove the directory)"
                if ($overall -eq 0) { $overall = 1 }
            }
        }
        if ($names.Count -gt 0) {
            Add-DistributionFacts 'after'
            $after = @(Get-Registered)
            $same = Test-SameSet $before $after
            [void]$distFacts.Append("registered-set-equal-to-before=$(if ($same) { 'yes' } else { 'no' })`n")
            Add-Command $(if ($same) { 0 } else { 1 }) 'the registered distributions equal the set before the run (only this run''s was added and removed)'
            if (-not $same -and $overall -eq 0) { $overall = 1 }
        }
    } catch { Add-Command 1 "unregistering this run's distribution: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    if ($null -eq $kept) { $kept = @(Select-KeptInstallDirectories $attempted.ToArray() $null) }

    # Redact, mask, scan, bundle (no environment dump: only the facts above).
    $rules = Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName())
    [void]$hostFacts.Append((Format-DistributionFactLines $distFacts.ToString()))
    $raw = @{ 'tests.txt' = $(if ($testsText) { $testsText } else { "### $JourneyTarget`n### $JourneyTarget exit=1`n" }); 'commands.txt' = $commands.ToString(); 'host.txt' = $hostFacts.ToString()
        'build.txt' = $build.ToString(); 'skipped.txt' = ''; 'canary-scan.txt' = '' }
    # The run's verdict first, in the plain results (it survives a failed bundle).
    [System.IO.File]::AppendAllText($resultsFile, "### run exit=$overall`n", [System.Text.UTF8Encoding]::new($false))
    Write-Output "### run exit=$overall (results: <run>\bundle\results.txt)"
    $pb = New-ProtectedBundle $raw $rules $Label $Commit $started $overall
    $overall = $pb.Exit
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.json'), $pb.Bundle.Json, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.b64'), $pb.Bundle.Text, [System.Text.UTF8Encoding]::new($false))
    if ($OutFile) {
        $fs = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
        try { $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($pb.Bundle.Text); $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
        $bundleSaved = $true
    }
    Write-Output "bundle: $(if ($bundleSaved) { 'the -Out file' } else { '<run>\bundle\bundle.json and bundle.b64' }) ($($pb.Bundle.Text.Length) characters)"
    Write-Output $pb.Files['commands.txt']
    Write-Output $pb.Bundle.Text

    # The run directory this script created: removed whole once nothing is kept and the bundle is in
    # -Out; otherwise only the bundle directory (the plain results and the bundle) stays.
    if (Test-OwnRunDirectory $rootItem.FullName $run) {
        if ($kept.Count -eq 0) {
            foreach ($d in @($files, $distroRoot, $image, $markerFile)) {
                if ($d -and (Test-Path -LiteralPath $d) -and $d.StartsWith($run + [System.IO.Path]::DirectorySeparatorChar)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
            }
            if ($bundleSaved) { Remove-Item -LiteralPath $run -Recurse -Force -ErrorAction SilentlyContinue }
        } else {
            foreach ($d in @($files)) { if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue } }
        }
    }
  } catch {
    # The cleanup or the bundle itself failed: say where, redacted as the bundle would be.
    $diag = "the cleanup or the bundle failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)"
    try {
        $diag = Invoke-Redaction $diag (Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName()))
    } catch { $diag = 'the cleanup or the bundle failed (the diagnostic could not be redacted, so it is not printed)' }
    [Console]::Error.WriteLine("run-wsl-hook-windows: $(Hide-Canary $diag)")
    if ($overall -eq 0) { $overall = 1 }
  }
}
exit $overall
