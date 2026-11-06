#Requires -Version 7.2
<#
.SYNOPSIS
M02 Windows local-mode runner (ADR-0007 §12.32 items 15-17): run the M02 evidence suite natively
on the Windows 11 x64 PC, launched there by an agent, and hand back one redacted results bundle.

.DESCRIPTION
Runs ON the PC (there is no remote route into WSL; §12.32 item 15). Its steps:
  1. Clone the public repository at the exit commit into a fresh scratch directory
     <ScratchRoot>\hm-m02-local-<random> (created exclusively; a reparse point is refused).
  2. Install the pinned toolchain (rust-toolchain.toml of that commit) into the scratch
     directory: RUSTUP_HOME and CARGO_HOME point there, rustup-init runs with --no-modify-path,
     so the owner's rustup, PATH and registry are never touched.
  3. Build every workspace test binary natively for x86_64-pc-windows-msvc (`cargo test
     --workspace --locked --no-run`), and heimdall.exe and hm-fixture-hook.exe.
  4. Start the fixture sshd in WSL scratch on 127.0.0.1 through wsl.exe (non-root, per-run
     host key; tests/native/m02/remote-lib.sh), its authorized-keys file and log in the Windows
     scratch, and check that Windows reaches it (WSL's localhost forwarding; SSH banner).
  5. Run every test binary (the e2e suites included) with --show-output, a per-binary timeout
     and its real exit code; the inherited agent, Git, Heimdall and fixture variables are
     removed, the in-box OpenSSH is first on PATH, HEIMDALL_E2E_BIN, HM_FIXTURE_HOOK,
     HM_FIXTURE_SSHD_* and HM_REPO_ROOT (the clone) are set, TEMP/TMP are in scratch.
  6. Record `ssh -V` (Windows in-box, Windows PATH-first, WSL), `git --version` (Windows, WSL;
     scratch HOME, GIT_CONFIG_NOSYSTEM=1), the toolchain and the OS.
  7. Redact <winuser>, <winhost> (whole words), <winhome>, the WSL user, host and home, SIDs and
     non-loopback IPv4 addresses; mask any canary value and count it; scan for leaks.
  8. Write one results bundle: the per-test files m02-evidence.py reads (tests.txt with
     "### <target>" and "### <target> exit=N", commands.txt with "exit N: <command>", host.txt
     with key=value facts, build.txt, skipped.txt, canary-scan.txt), as bundle.json, and its
     gzip+base64 rendering bundle.b64 (printed between BEGIN/END markers for transfer).
  9. Remove the build, the toolchain and the WSL scratch, and check they are gone; only the
     bundle is kept until it has been imported (import-windows-bundle.py on the build host).

Nothing is elevated (an elevated session is refused), and no service, firewall rule, registry
value, ssh-agent, ~/.ssh or WSL configuration is touched; there is no `wsl --shutdown`. Only
processes this script started are stopped, through their own handles (the WSL sshd by its
recorded PID, start time and configuration path). The pseudoconsole drivers
(tests/native/windows-launch) need argvdump.exe (Go); they run only when -ArgvDump names one.

.PARAMETER Commit
The exit commit (40 hexadecimal digits). The clone is checked out detached at exactly it.

.PARAMETER ScratchRoot
An existing directory (not a reparse point) under which the run directory is created.

.PARAMETER SelfTest
Run no network, toolchain, build or WSL step: exercise the redaction, masking, results and
bundle functions on synthetic data, write a synthetic bundle under -Out, print one line per
check and exit 0 only when every check passed (tests/native/m02/selftest.sh runs this).

.EXAMPLE
pwsh -NoProfile -File run-windows-local.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m02
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$ScratchRoot,
    [string]$RepoUrl = 'https://github.com/amanthanvi/heimdall',
    [int]$TimeoutSeconds = 1800,
    [string]$WslDistro = '',
    [string]$ArgvDump = '',
    [string]$Label = 'windows-11-x86_64 (native msvc, local mode)',
    [switch]$SelfTest,
    [string]$Out = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$BundleFormat = 'heimdall-m02-windows-local-bundle/1'
$BeginMarker = '-----BEGIN HEIMDALL M02 WINDOWS BUNDLE-----'
$EndMarker = '-----END HEIMDALL M02 WINDOWS BUNDLE-----'
$BundleFiles = @('tests.txt', 'commands.txt', 'host.txt', 'build.txt', 'skipped.txt', 'canary-scan.txt')

# ---------------------------------------------------------------------------------------------
# Pure helpers (exercised by -SelfTest)
# ---------------------------------------------------------------------------------------------

function New-RandomHex([int]$Bytes) {
    $b = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return ([System.BitConverter]::ToString($b) -replace '-', '').ToLowerInvariant()
}

function Get-Sha256Hex([byte[]]$Data) {
    return ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($Data)) -replace '-', '').ToLowerInvariant()
}

# A redaction rule: every form of Value is replaced by Label, case-insensitively, longest first;
# a Word rule (host names) only as a whole word.
function New-RedactionRule([string]$Value, [string]$Label, [switch]$Word) {
    [pscustomobject]@{ Value = $Value; Label = $Label; Word = [bool]$Word }
}

function Get-RedactionForms($Rules) {
    $forms = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rules) {
        if ([string]::IsNullOrEmpty($r.Value) -or $r.Value.Length -lt 2) { continue }
        $vs = [System.Collections.Generic.HashSet[string]]::new()
        [void]$vs.Add($r.Value)
        [void]$vs.Add($r.Value.Replace('\', '\\'))
        [void]$vs.Add($r.Value.Replace('\', '/'))
        if ($r.Value.Length -gt 2 -and $r.Value[1] -eq ':' -and [char]::IsLetter($r.Value[0])) {
            [void]$vs.Add('/mnt/' + [char]::ToLowerInvariant($r.Value[0]) + $r.Value.Substring(2).Replace('\', '/'))
        }
        foreach ($v in $vs) { $forms.Add([pscustomobject]@{ Form = $v; Label = $r.Label; Word = $r.Word }) }
    }
    return @($forms | Sort-Object -Property @{ Expression = { $_.Form.Length }; Descending = $true })
}

function Invoke-Redaction([string]$Text, $Rules) {
    foreach ($f in (Get-RedactionForms $Rules)) {
        $p = [regex]::Escape($f.Form)
        if ($f.Word) { $p = '(?<![A-Za-z0-9_])' + $p + '(?![A-Za-z0-9_])' }
        $label = $f.Label
        $Text = [regex]::Replace($Text, $p, { param($m) $label }, 'IgnoreCase')
    }
    # User and domain SIDs (local and Entra accounts), and non-loopback IPv4 addresses.
    $Text = [regex]::Replace($Text, 'S-1-(5-21|12-1)(-\d+){1,6}', 'S-1-<redacted>')
    $Text = [regex]::Replace($Text, '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', {
            param($m)
            if ($m.Value.StartsWith('127.') -or $m.Value -eq '0.0.0.0') { $m.Value } else { '<addr>' }
        })
    return $Text
}

# Canary values are masked before anything leaves the PC; the count is the finding.
function Get-CanaryCount([string]$Text) { return ([regex]::Matches($Text, 'HEIMDALL_CANARY_')).Count }
function Hide-Canary([string]$Text) { return [regex]::Replace($Text, 'HEIMDALL_CANARY_[A-Za-z0-9_]*', '<canary>') }

# The number of (file, value) pairs where a value is still present (whole word for a Word rule).
function Get-LeakCount([hashtable]$Files, $Rules) {
    $n = 0
    foreach ($r in $Rules) {
        if ([string]::IsNullOrEmpty($r.Value) -or $r.Value.Length -lt 2) { continue }
        $p = [regex]::Escape($r.Value)
        if ($r.Word) { $p = '(?<![A-Za-z0-9_])' + $p + '(?![A-Za-z0-9_])' }
        foreach ($k in $Files.Keys) { if ([regex]::IsMatch($Files[$k], $p, 'IgnoreCase')) { $n++ } }
    }
    return $n
}

# The libtest output of one target in the harness format m02-evidence.py reads.
function Format-TargetOutput([string]$Target, [string]$Output, [int]$ExitCode) {
    $o = $Output -replace "`r`n", "`n"
    if ($o.Length -gt 0 -and -not $o.EndsWith("`n")) { $o += "`n" }
    return "### $Target`n$o### $Target exit=$ExitCode`n"
}

function Format-CommandLine([int]$ExitCode, [string]$What) { return "exit ${ExitCode}: $What`n" }

# bundle.json (UTF-8, LF) and its gzip+base64 rendering, wrapped at 76 columns between markers
# with the payload's sha256.
function New-Bundle([hashtable]$Files, [hashtable]$Meta) {
    $sha = [ordered]@{}
    $ordered = [ordered]@{}
    foreach ($k in ($Files.Keys | Sort-Object)) {
        $ordered[$k] = $Files[$k]
        $sha[$k] = Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($Files[$k]))
    }
    $doc = [ordered]@{ format = $BundleFormat }
    foreach ($k in ($Meta.Keys | Sort-Object)) { $doc[$k] = $Meta[$k] }
    $doc['files'] = $ordered
    $doc['sha256'] = $sha
    $json = ($doc | ConvertTo-Json -Depth 6 -Compress) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $ms = [System.IO.MemoryStream]::new()
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Dispose()
    $packed = $ms.ToArray()
    $b64 = [Convert]::ToBase64String($packed)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($BeginMarker)
    $lines.Add("sha256-gzip: $(Get-Sha256Hex $packed)")
    for ($i = 0; $i -lt $b64.Length; $i += 76) { $lines.Add($b64.Substring($i, [Math]::Min(76, $b64.Length - $i))) }
    $lines.Add($EndMarker)
    return [pscustomobject]@{ Json = $json; Text = (($lines -join "`n") + "`n") }
}

# Redact, mask and leak-scan every bundle file; returns the cleaned files and the counts.
function Protect-BundleFiles([hashtable]$Raw, $Rules) {
    $clean = @{}
    $canaries = 0
    foreach ($k in $Raw.Keys) {
        $t = Invoke-Redaction ([string]$Raw[$k]) $Rules
        $canaries += Get-CanaryCount $t
        $clean[$k] = Hide-Canary $t
    }
    $leaks = Get-LeakCount $clean $Rules
    return [pscustomobject]@{ Files = $clean; Canaries = $canaries; Leaks = $leaks }
}

# ---------------------------------------------------------------------------------------------
# ADR-0007 §12.38 item 2 (L02): the bundle's metadata is protected like the file bodies
# (redacted, canaries counted and masked, leaks counted), so nothing reaches bundle.json
# unprotected and every finding counts toward the run's result.
function Get-ProtectedMetadata([string]$Label, $Rules) {
    $p = Protect-BundleFiles @{ label = $Label } $Rules
    return [pscustomobject]@{ Label = $p.Files['label']; Canaries = $p.Canaries; Leaks = $p.Leaks }
}

# The overrides of the toolchain environment (rustup-init and the Cargo builds). ADR-0007
# §12.35 item 3 (N05): the toolchain homes and every temporary directory are in this run's
# scratch (TEMP/TMP for Windows tools, TMPDIR for MSYS-style ones), and Git reads no user or
# system configuration. ADR-0007 §12.43 item 2: the native MSVC test build keeps line tables
# only (CARGO_PROFILE_DEV_DEBUG / CARGO_PROFILE_TEST_DEBUG); with full debug info the program
# database of the largest test binary (heimdall-runtime `model_operations`) exceeds the MSVC
# linker's limit (LNK1140). The cross builds on the build host keep full debug info, which
# platform-tests.py reads test symbols from.
function Get-ToolEnvironmentOverrides([string]$RustupHome, [string]$CargoHome, [string]$GitConfig, [string]$Tmp) {
    return @{ RUSTUP_HOME = $RustupHome; CARGO_HOME = $CargoHome; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $GitConfig; TEMP = $Tmp; TMP = $Tmp; TMPDIR = $Tmp
        CARGO_PROFILE_DEV_DEBUG = 'line-tables-only'; CARGO_PROFILE_TEST_DEBUG = 'line-tables-only' }
}

# How many of the given files contain a carriage return (0 when every one is LF-only; a file
# that cannot be read counts as one).
function Get-CrlfFileCount([string[]]$Paths) {
    $n = 0
    foreach ($p in $Paths) {
        try { if ([System.Array]::IndexOf([System.IO.File]::ReadAllBytes($p), [byte]13) -ge 0) { $n++ } } catch { $n++ }
    }
    return $n
}

# What the end-of-run stop step (`echo "stop=$(hm2_stop_recorded ...)"` in WSL) answered: the
# word after `stop=` on the first such line (`none`, `stopped`, `gone`, `mismatch` or
# `still-running`), or `no answer` when WSL gave no such line.
function Get-SshdAtEnd([string]$Output) {
    $line = ($Output -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'stop=*' } | Select-Object -First 1
    if ($null -eq $line) { return 'no answer' }
    $word = ($line -replace '^stop=', '').Trim()
    if ($word) { return $word } else { return 'no answer' }
}

# Whether that answer proves no fixture sshd of this run is left running: only `stopped` (it
# was signalled and is gone) and `gone` (it had already exited). `mismatch` (the recorded
# process was not recognised, so it was not signalled), `still-running`, `none` (no usable
# record) and `no answer` all leave it unaccounted for.
function Test-SshdAtEndOk([string]$AtEnd) {
    return ($AtEnd -eq 'stopped' -or $AtEnd -eq 'gone')
}

# -SelfTest: the helpers on synthetic data (no host, no network, no toolchain)
# ---------------------------------------------------------------------------------------------

function Invoke-SelfTest([string]$OutDir) {
    $script:stPass = 0
    $script:stFail = 0
    function Check([string]$Name, [bool]$Ok) {
        if ($Ok) { Write-Host "ok   $Name"; $script:stPass++ } else { Write-Host "FAIL $Name"; $script:stFail++ }
    }
    $rules = @(
        (New-RedactionRule 'C:\Users\fixtureuser' '<winhome>'),
        (New-RedactionRule '/home/wslfixture' '<wslhome>'),
        (New-RedactionRule 'fixtureuser' '<winuser>'),
        (New-RedactionRule 'wslfixture' '<wsluser>'),
        (New-RedactionRule 'FIXTUREHOST' '<winhost>' -Word),
        (New-RedactionRule 'mac' '<wslhost>' -Word)
    )
    $text = "home C:\Users\fixtureuser\x and C:\\Users\\fixtureuser and c:/users/FIXTUREUSER/y and /mnt/c/Users/fixtureuser/z`n" +
        "wsl /home/wslfixture/a user wslfixture host FIXTUREHOST fqdn fixturehost.example`n" +
        "short host mac on macOS, mac-1, xmac`n" +
        "sid S-1-5-21-1111111111-2222222222-3333333333-1001 entra S-1-12-1-111-222-333-444 system S-1-5-18`n" +
        "addr 203.0.113.9 loop 127.0.0.1 any 0.0.0.0 version 1.2.3.4.5`n" +
        "canary " + ("HEIMDALL_" + "CANARY_") + "selftest_value_1 end`n"
    $r = Invoke-Redaction $text $rules
    Check 'R01 the Windows home in its backslash, doubled, slash and /mnt forms, any case' (-not ($r -match '(?i)fixtureuser') -and ([regex]::Matches($r, '<winhome>')).Count -ge 4)
    Check 'R02 the WSL home and user' ($r.Contains('<wslhome>/a') -and $r.Contains('user <wsluser>'))
    Check 'R03 host names as whole words only (inside another word they stay)' ($r.Contains('host <winhost> fqdn <winhost>.example') -and $r.Contains('<wslhost> on macOS, <wslhost>-1, xmac'))
    Check 'R04 user and Entra SIDs masked, a well-known SID kept' ($r.Contains('sid S-1-<redacted>') -and $r.Contains('entra S-1-<redacted>') -and $r.Contains('S-1-5-18') -and -not $r.Contains('3333333333'))
    Check 'R05 non-loopback IPv4 masked, loopback and any kept, version numbers untouched' ($r.Contains('addr <addr>') -and $r.Contains('127.0.0.1') -and $r.Contains('0.0.0.0') -and $r.Contains('1.2.3.4.5'))
    $p = Protect-BundleFiles @{ 'tests.txt' = $text } $rules
    Check 'R06 a canary is counted and its value masked' ($p.Canaries -eq 1 -and $p.Files['tests.txt'].Contains('canary <canary> end') -and -not $p.Files['tests.txt'].Contains('HEIMDALL_CANARY_'))
    Check 'R07 nothing redacted is left (leak scan 0)' ($p.Leaks -eq 0)
    Check 'R08 the leak scan finds a value that is still there' ((Get-LeakCount @{ a = 'x fixtureuser y'; b = 'macOS' } $rules) -eq 1)
    $t = (Format-TargetOutput 'model_setup' "running 2 tests`r`ntest a ... ok`r`ntest b ... FAILED`r`n" 101)
    Check 'T01 target output in the harness format, CRLF normalized' ($t -eq "### model_setup`nrunning 2 tests`ntest a ... ok`ntest b ... FAILED`n### model_setup exit=101`n")
    Check 'T02 a command line with its real exit code' ((Format-CommandLine 3 'step') -eq "exit 3: step`n")
    $files = @{}
    foreach ($f in $BundleFiles) { $files[$f] = '' }
    $files['tests.txt'] = $p.Files['tests.txt'] + $t +
        (Format-TargetOutput 'e2e_cli_m02' "running 1 test`ntest json::u ... ok`n`nsuccesses:`n`n---- json::u stdout ----`nobservation selftest=1`n" 0)
    $files['commands.txt'] = (Format-CommandLine 0 'clone at the exit commit') + (Format-CommandLine 101 'every test binary')
    $files['host.txt'] = "os=Microsoft Windows [Version 10.0.26100.1000] on FIXTUREHOST`nssh-V-inbox=OpenSSH_for_Windows_0.0p0 (exit 0)`ngit-version-windows=git version 0.0.0.windows.1`n"
    $files['canary-scan.txt'] = "canary-prefix occurrences in saved output: $($p.Canaries)`n"
    # Every file goes through the same protection as in a real run.
    $files = (Protect-BundleFiles $files $rules).Files
    Check 'R09 every result file is protected (the host name in host.txt too)' ($files['host.txt'].Contains('on <winhost>'))
    $te = Get-ToolEnvironmentOverrides 'S\rustup' 'S\cargo' 'S\empty.gitconfig' 'S\tmp'
    $canaryLabel = 'run ' + ('HEIMDALL_' + 'CANARY_') + 'labelvalue1 for fixtureuser'
    $pm = Get-ProtectedMetadata $canaryLabel $rules
    $pb = New-Bundle @{ 'tests.txt' = ''; 'commands.txt' = ''; 'host.txt' = ''; 'build.txt' = ''; 'skipped.txt' = ''; 'canary-scan.txt' = '' } ([ordered]@{ commit = ('0' * 40); label = $pm.Label; exit = 0 })
    Check 'E02 a canary or a user name in the label is masked, counted, and absent from the serialized bundle (ADR-0007 §12.38 L02)' ($pm.Canaries -eq 1 -and -not $pm.Label.Contains('HEIMDALL_' + 'CANARY_') -and -not ($pm.Label -match '(?i)fixtureuser') -and -not $pb.Json.Contains('HEIMDALL_' + 'CANARY_') -and -not $pb.Json.Contains('labelvalue1'))
    Check 'E01 the toolchain environment keeps TEMP, TMP and TMPDIR in the run scratch (ADR-0007 §12.35 N05)' ($te['TEMP'] -eq 'S\tmp' -and $te['TMP'] -eq 'S\tmp' -and $te['TMPDIR'] -eq 'S\tmp' -and $te['RUSTUP_HOME'] -eq 'S\rustup' -and $te['CARGO_HOME'] -eq 'S\cargo')
    Check 'E03 the native test build keeps line tables only (ADR-0007 §12.43 item 2, LNK1140)' ($te['CARGO_PROFILE_DEV_DEBUG'] -eq 'line-tables-only' -and $te['CARGO_PROFILE_TEST_DEBUG'] -eq 'line-tables-only')
    $lfDir = Join-Path ([System.IO.Path]::GetTempPath()) ('hm-selftest-eol-' + (New-RandomHex 4))
    New-Item -ItemType Directory -Path $lfDir | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $lfDir 'lf.txt'), [byte[]](97, 10, 98, 10))
    [System.IO.File]::WriteAllBytes((Join-Path $lfDir 'crlf.txt'), [byte[]](97, 13, 10))
    Check 'G01 the line-ending sample counts files holding a CR (LF-only 0, CRLF 1, unreadable 1)' ((Get-CrlfFileCount @((Join-Path $lfDir 'lf.txt'))) -eq 0 -and (Get-CrlfFileCount @((Join-Path $lfDir 'lf.txt'), (Join-Path $lfDir 'crlf.txt'))) -eq 1 -and (Get-CrlfFileCount @((Join-Path $lfDir 'absent.txt'))) -eq 1)
    Remove-Item -LiteralPath $lfDir -Recurse -Force
    $stopOut = "created=x`r`nstop=stopped`r`n"
    Check 'S01 the end-of-run sshd stop answer is read from its stop= line (CRLF too), and only stopped or gone count as stopped' ((Get-SshdAtEnd $stopOut) -eq 'stopped' -and (Test-SshdAtEndOk 'stopped') -and (Test-SshdAtEndOk (Get-SshdAtEnd "stop=gone`n")))
    Check 'S02 mismatch, still-running, none and a missing answer are failures of the run, never a stopped sshd' ((Get-SshdAtEnd "noise`n") -eq 'no answer' -and (Get-SshdAtEnd 'stop=') -eq 'no answer' -and -not (Test-SshdAtEndOk (Get-SshdAtEnd "stop=mismatch`n")) -and -not (Test-SshdAtEndOk 'still-running') -and -not (Test-SshdAtEndOk 'none') -and -not (Test-SshdAtEndOk (Get-SshdAtEnd '')))
    $meta = [ordered]@{ commit = ('0' * 40); label = 'windows-selftest'; started_at = '2026-11-06T00:00:00Z'; finished_at = '2026-11-06T00:00:01Z'; exit = 101 }
    $b = New-Bundle $files $meta
    Check 'B01 the bundle is framed by its markers with the payload sha256' ($b.Text.StartsWith($BeginMarker + "`nsha256-gzip: ") -and $b.Text.TrimEnd().EndsWith($EndMarker))
    $body = (($b.Text -split "`n") | Where-Object { $_ -and $_ -ne $BeginMarker -and $_ -ne $EndMarker -and -not $_.StartsWith('sha256-gzip:') }) -join ''
    $packed = [Convert]::FromBase64String($body)
    $in = [System.IO.Compression.GZipStream]::new([System.IO.MemoryStream]::new($packed), [System.IO.Compression.CompressionMode]::Decompress)
    $rd = [System.IO.StreamReader]::new($in, [System.Text.Encoding]::UTF8)
    $round = $rd.ReadToEnd() | ConvertFrom-Json -AsHashtable
    $rd.Dispose()
    Check 'B02 the gzip+base64 rendering decodes to the same files and sha256s' ($round['format'] -eq $BundleFormat -and $round['files']['tests.txt'] -eq $files['tests.txt'] -and $round['sha256']['tests.txt'] -eq (Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($files['tests.txt']))))
    Check 'B03 the bundle names exactly the result files' ((@($round['files'].Keys | Sort-Object) -join ',') -eq (@($BundleFiles | Sort-Object) -join ','))
    if ($OutDir) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'bundle.b64'), $b.Text, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $OutDir 'bundle.json'), $b.Json, [System.Text.UTF8Encoding]::new($false))
    }
    Write-Host "run-windows-local selftest: $($script:stPass) passed, $($script:stFail) failed"
}

if ($SelfTest) {
    Invoke-SelfTest $Out
    if ($script:stFail -eq 0 -and $script:stPass -gt 0) { exit 0 } else { exit 1 }
}

# ---------------------------------------------------------------------------------------------
# The real run
# ---------------------------------------------------------------------------------------------

# A usage error or a refusal before anything ran: exit 2 with one line on stderr.
function Stop-Usage([string]$Message) {
    [Console]::Error.WriteLine("run-windows-local: $Message")
    exit 2
}

if (-not $IsWindows) { Stop-Usage 'run-windows-local.ps1 runs on the Windows PC itself (use -SelfTest elsewhere)' }
if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Usage '-Commit must be the 40-hex exit commit' }
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) { Stop-Usage '-ScratchRoot is required' }
if ($TimeoutSeconds -lt 60) { Stop-Usage '-TimeoutSeconds must be at least 60' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Usage 'refusing to run elevated: this runner never needs administrator rights'
}
$rootItem = Get-Item -LiteralPath $ScratchRoot -Force -ErrorAction SilentlyContinue
if ($null -eq $rootItem -or -not $rootItem.PSIsContainer) { Stop-Usage '-ScratchRoot must be an existing directory' }
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Usage '-ScratchRoot is a reparse point (symbolic link or junction): refused' }

$run = Join-Path $rootItem.FullName ("hm-m02-local-" + (New-RandomHex 8))
# Exclusive: a directory that exists already (another run's) is never reused.
if (Test-Path -LiteralPath $run) { Stop-Usage 'the run directory exists already' }
[void][System.IO.Directory]::CreateDirectory($run)
$src = Join-Path $run 'src'
$tools = Join-Path $run 'toolchain'
$wtmp = Join-Path $run 'tmp'
$bundleDir = Join-Path $run 'bundle'
$sshdDir = Join-Path $run 'sshd'
foreach ($d in @($tools, $wtmp, $bundleDir, $sshdDir, (Join-Path $run 'githome'))) { [void][System.IO.Directory]::CreateDirectory($d) }
$emptyGitConfig = Join-Path $run 'githome\empty.gitconfig'
[System.IO.File]::WriteAllText($emptyGitConfig, '')

$sys32 = Join-Path $env:SystemRoot 'System32'
$wsl = Join-Path $sys32 'wsl.exe'
$inboxSsh = Join-Path $sys32 'OpenSSH\ssh.exe'
$started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$commands = [System.Text.StringBuilder]::new()
$hostFacts = [System.Text.StringBuilder]::new()
$tests = [System.Text.StringBuilder]::new()
$build = [System.Text.StringBuilder]::new()
$skipped = [System.Text.StringBuilder]::new()
$overall = 0
$wslDir = ''
$sshdProc = $null
$sshdErr = $null
$wv = @{}
$remoteLib = ''

function Add-Command([int]$Rc, [string]$What) { [void]$commands.Append((Format-CommandLine $Rc $What)) }
function Add-Fact([string]$Key, [string]$Value) { [void]$hostFacts.Append("$Key=$(($Value -replace "`r", '') -split "`n" | Select-Object -First 1)`n") }

# An environment for a child: the inherited one without agent, askpass, Git, Heimdall, fixture
# and repository variables, plus Set.
function New-ChildEnvironment([hashtable]$Set) {
    $envs = @{}
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$e.Key
        if ($k -match '^(GIT_|HEIMDALL_|HM_FIXTURE_|HM_REPO_ROOT$|SSH_AUTH_SOCK$|SSH_AGENT_PID$|SSH_ASKPASS|RUSTUP_|CARGO)') { continue }
        $envs[$k] = [string]$e.Value
    }
    foreach ($k in $Set.Keys) { $envs[$k] = [string]$Set[$k] }
    return $envs
}

# Run a program (no shell) with an environment and a timeout; returns exit code and output.
# On a timeout the process tree this call started is killed through its own handle.
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

function Invoke-Wsl([string]$Script, [string[]]$ScriptArgs, [int]$Seconds = 300) {
    $a = @()
    if ($WslDistro) { $a += @('-d', $WslDistro) }
    $a += @('-e', 'bash', '-s', '--') + $ScriptArgs
    return Invoke-Bounded $wsl $a $null $run $Seconds $Script
}

$gitEnv = New-ChildEnvironment @{ GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $emptyGitConfig; GIT_TERMINAL_PROMPT = '0'; HOME = (Join-Path $run 'githome') }
$git = (Get-Command 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($null -eq $git) { Stop-Usage 'git.exe is not on PATH' }
$git = $git.Source

try {
    # Facts before anything runs.
    Add-Fact 'os' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ver') $null $run 30).Output.Trim())
    $groups = (Invoke-Bounded (Join-Path $sys32 'whoami.exe') @('/groups') $null $run 30).Output
    Add-Fact 'integrity' ([regex]::Match($groups, '(Medium|High|System) Mandatory Level').Value)
    Add-Fact 'mode' 'local (run on the PC by an agent; no remote route into WSL, ADR-0007 §12.32 item 15)'
    Add-Fact 'build-target' 'x86_64-pc-windows-msvc (native build and run)'
    $dev = (Invoke-Bounded (Join-Path $sys32 'reg.exe') @('query', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock', '/v', 'AllowDevelopmentWithoutDevLicense') $null $run 30).Output
    Add-Fact 'developer-mode' ($(if ($dev -match '0x1') { 'on' } elseif ($dev -match '0x0') { 'off' } else { 'unknown' }) + ' (read only)')
    Add-Fact 'localappdata-heimdall-before' $(if (Test-Path (Join-Path $env:LOCALAPPDATA 'heimdall')) { 'present' } else { 'absent' })
    $ownerDigest = {
        $h = [System.Security.Cryptography.IncrementalHash]::CreateHash('SHA256')
        $n = 0
        foreach ($root in @((Join-Path $env:USERPROFILE '.ssh'), (Join-Path $env:USERPROFILE '.gitconfig'))) {
            foreach ($i in @(Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue)) {
                if ($null -eq $i) { continue }
                $n++
                $len = if ($i.PSIsContainer) { 0 } else { $i.Length }
                $h.AppendData([System.Text.Encoding]::UTF8.GetBytes("$($i.FullName)|$($i.Attributes)|$len|$($i.LastWriteTimeUtc.Ticks)`n"))
            }
        }
        if ($n -eq 0) { 'absent' } else { "${n}:" + (([System.BitConverter]::ToString($h.GetHashAndReset()) -replace '-', '').ToLowerInvariant().Substring(0, 24)) }
    }
    $ownerBefore = & $ownerDigest
    Add-Fact 'owner-ssh-git-before' $ownerBefore
    Add-Fact 'ssh-V-inbox' ((Invoke-Bounded $inboxSsh @('-V') $null $run 30).Output.Trim())
    Add-Fact 'ssh-V-path-first' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ssh -V') $null $run 30).Output.Trim() + ' (candidate, not selected)')
    Add-Fact 'git-version-windows' ((Invoke-Bounded $git @('--version') $gitEnv $run 30).Output.Trim())

    # 1. The clone, at exactly the commit.
    # Git for Windows' system configuration may set core.autocrlf=true, which would check the
    # tree out with CRLF (schema exports, corpus inertness and TUI snapshots then fail), and
    # evidence paths exceed MAX_PATH: both are set for the clone and the checkout, and then
    # kept in the clone's own configuration (never the user's or the system's).
    $r = Invoke-Bounded $git @('-c', 'credential.helper=', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', 'clone', '--quiet', '--no-checkout', $RepoUrl, $src) $gitEnv $run 1800
    Add-Command $r.Code 'git clone of the public repository into the run directory'
    [void]$build.Append($r.Output)
    if ($r.Code -ne 0) { throw 'clone failed' }
    foreach ($kv in @(@('core.autocrlf', 'false'), @('core.longpaths', 'true'))) {
        $r = Invoke-Bounded $git @('-C', $src, 'config', '--local', $kv[0], $kv[1]) $gitEnv $run 60
        Add-Command $r.Code "git config --local $($kv[0]) $($kv[1]) (the clone's own configuration)"
        if ($r.Code -ne 0) { throw "git config $($kv[0]) failed" }
    }
    $r = Invoke-Bounded $git @('-C', $src, 'checkout', '--quiet', '--detach', $Commit) $gitEnv $run 600
    Add-Command $r.Code 'git checkout --detach <exit commit>'
    if ($r.Code -ne 0) { throw 'checkout failed' }
    $crlf = Get-CrlfFileCount @('Cargo.lock', 'rust-toolchain.toml', 'tests\native\m02\remote-lib.sh', 'crates\testkit\Cargo.toml' | ForEach-Object { Join-Path $src $_ })
    Add-Fact 'git-autocrlf-clone' ((Invoke-Bounded $git @('-C', $src, 'config', '--get', 'core.autocrlf') $gitEnv $run 30).Output.Trim())
    Add-Fact 'clone-line-endings' $(if ($crlf -eq 0) { 'LF (sampled files have no CR)' } else { "CRLF in $crlf sampled files" })
    Add-Command $(if ($crlf -eq 0) { 0 } else { 1 }) 'the checked-out tree has LF line endings (core.autocrlf=false)'
    if ($crlf -ne 0) { throw 'the checkout has CRLF line endings' }
    $head = (Invoke-Bounded $git @('-C', $src, 'rev-parse', 'HEAD') $gitEnv $run 60).Output.Trim()
    Add-Command $(if ($head -eq $Commit) { 0 } else { 1 }) 'the clone is at exactly the exit commit'
    if ($head -ne $Commit) { throw 'the clone is not at the commit' }
    Add-Fact 'build-commit' $Commit

    # 2. The pinned toolchain, in scratch only.
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
    # The first proxy call in the clone installs the toolchain file's components (a download).
    Add-Fact 'toolchain' ((Invoke-Bounded (Join-Path $cargoHome 'bin\rustc.exe') @('-V') $toolEnv $src 1800).Output.Trim() + "; target x86_64-pc-windows-msvc; channel $channel")
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        Add-Fact 'toolchain-msvc' ((Invoke-Bounded $vswhere @('-latest', '-products', '*', '-property', 'catalog_productDisplayVersion') $null $run 60).Output.Trim() + ' (Visual Studio Build Tools, read only)')
    }

    # 3. The build.
    Add-Fact 'build-debuginfo' 'line-tables-only (CARGO_PROFILE_DEV_DEBUG/CARGO_PROFILE_TEST_DEBUG; full debug info exceeds the MSVC PDB limit, LNK1140)'
    $r = Invoke-Bounded $cargo @('test', '--workspace', '--locked', '--no-run', '--message-format=json-render-diagnostics') $toolEnv $src 7200
    Add-Command $r.Code 'cargo test --workspace --locked --no-run (native x86_64-pc-windows-msvc)'
    $bins = [System.Collections.Generic.List[object]]::new()
    $cli = ''
    $hook = ''
    foreach ($line in ($r.Output -split "`n")) {
        if (-not $line.StartsWith('{')) { [void]$build.Append("$line`n"); continue }
        $m = $null
        try { $m = $line | ConvertFrom-Json } catch { continue }
        if ($m.reason -ne 'compiler-artifact' -or -not $m.executable) { continue }
        if ($m.profile.test) {
            $name = if ($m.target.kind -contains 'test') { $m.target.name } else { $m.target.name + '-unit' }
            $bins.Add([pscustomobject]@{ Name = $name; Exe = $m.executable; Cwd = (Split-Path -Parent $m.manifest_path) })
        } elseif ($m.target.name -eq 'heimdall' -and $m.target.kind -contains 'bin') { $cli = $m.executable }
        elseif ($m.target.name -eq 'hm-fixture-hook' -and $m.target.kind -contains 'bin') { $hook = $m.executable }
    }
    if ($r.Code -ne 0 -or $bins.Count -eq 0 -or -not $cli -or -not $hook) { throw 'the build failed or produced no test binaries' }
    $bins = @($bins | Sort-Object -Property Name -Unique)
    foreach ($b in $bins) { [void]$build.Append("$($b.Name).exe sha256: $(Get-Sha256Hex ([System.IO.File]::ReadAllBytes($b.Exe)))`n") }
    [void]$build.Append("heimdall.exe (CLI for the e2e suites, HEIMDALL_E2E_BIN) sha256: $(Get-Sha256Hex ([System.IO.File]::ReadAllBytes($cli)))`n")
    [void]$build.Append("hm-fixture-hook.exe (HM_FIXTURE_HOOK) sha256: $(Get-Sha256Hex ([System.IO.File]::ReadAllBytes($hook)))`n")

    # The run plan: case-index.json build_host_paths (a test that truly needs the build host).
    $index = Get-Content -LiteralPath (Join-Path $src 'tests\native\m02\case-index.json') -Raw | ConvertFrom-Json -AsHashtable
    $skips = @{}
    foreach ($k in $index['build_host_paths'].Keys) {
        $t, $n = $k -split '::', 2
        if ($n) { if (-not $skips.ContainsKey($t)) { $skips[$t] = @() }; $skips[$t] += $n }
        else { $skips[$t] = @('*') }
    }

    # 4. The fixture sshd in WSL scratch, reachable from Windows on 127.0.0.1.
    $remoteLib = (Get-Content -LiteralPath (Join-Path $src 'tests\native\m02\remote-lib.sh') -Raw) -replace "`r`n", "`n"
    $wname = 'hm-m02-local-' + (New-RandomHex 6)
    $r = Invoke-Wsl ($remoteLib + "`n" + 'set -u; mkdir -m 700 -- "$HOME/$1" && echo "created=$HOME/$1"; echo "wsluser=$(id -un)"; echo "wslhome=$HOME"; echo "wslhost=$(hostname)"; hm2_versions "$HOME/$1" | sed "s/^/wsl-/"' + "`n") @($wname) 120
    Add-Command $r.Code 'wsl.exe: create the WSL scratch directory exclusively'
    $wv = @{}
    foreach ($l in ($r.Output -split "`n")) { if ($l -match '^([a-zA-Z-]+)=(.*)$') { $wv[$Matches[1]] = $Matches[2].Trim() } }
    if ($r.Code -ne 0 -or -not $wv['created']) { throw 'the WSL scratch directory was not created' }
    $wslDir = $wv['created']
    Add-Fact 'ssh-V-wsl' $wv['wsl-ssh-V']
    Add-Fact 'sshd-V-wsl' $wv['wsl-sshd-V']
    Add-Fact 'git-version-wsl' $wv['wsl-git-version']
    $ak = Join-Path $sshdDir 'authorized_keys'
    $slog = Join-Path $sshdDir 'sshd.log'
    [System.IO.File]::WriteAllText($ak, '')
    $start = $remoteLib + "`n" + @'
set -u
d=$1
ak=$(wslpath -u "$2")
lg=$(wslpath -u "$3")
hm2_sanitize_env >/dev/null
if hm2_sshd_start "$d/sshd" "$ak" "$lg"; then
    echo "port=$HM2_SSHD_PORT"
    echo "hostkey=$HM2_SSHD_HOSTKEY"
    echo "ready=1"
    wait "$HM2_SSHD_PID"
else
    echo "why=$HM2_SSHD_WHY"
fi
'@
    $psi = [System.Diagnostics.ProcessStartInfo]::new($wsl)
    if ($WslDistro) { $psi.ArgumentList.Add('-d'); $psi.ArgumentList.Add($WslDistro) }
    foreach ($a in @('-e', 'bash', '-s', '--', $wslDir, $ak, $slog)) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $sshdProc = [System.Diagnostics.Process]::Start($psi)
    # stderr is drained so a chatty sshd never blocks on a full pipe.
    $sshdErr = $sshdProc.StandardError.ReadToEndAsync()
    $sshdProc.StandardInput.Write(($start -replace "`r`n", "`n"))
    $sshdProc.StandardInput.Close()
    $fx = @{}
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $pending = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not ($fx.ContainsKey('ready') -or $fx.ContainsKey('why'))) {
        # One outstanding read at a time: a read that is still pending is waited on again.
        if ($null -eq $pending) { $pending = $sshdProc.StandardOutput.ReadLineAsync() }
        if (-not $pending.Wait(5000)) { continue }
        $line = $pending.Result
        $pending = $null
        if ($null -eq $line) { break }
        if ($line -match '^([a-z]+)=(.*)$') { $fx[$Matches[1]] = $Matches[2].Trim() }
    }
    $fixtureEnv = @{}
    if ($fx.ContainsKey('ready')) {
        $banner = 'unreachable'
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.ReceiveTimeout = 5000
            $c.Connect('127.0.0.1', [int]$fx['port'])
            $buf = [byte[]]::new(8)
            $n = $c.GetStream().Read($buf, 0, 8)
            $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $c.Close()
        } catch { $banner = 'unreachable' }
        if ($banner.StartsWith('SSH-2.0-')) {
            Add-Fact 'fixture-sshd' 'listening on 127.0.0.1 in WSL scratch (non-root, per-run host key)'
            Add-Fact 'fixture-sshd-from-windows' 'reachable (WSL localhost forwarding, SSH banner read)'
            Add-Command 0 'fixture sshd in WSL scratch reachable from Windows on 127.0.0.1'
            Add-Fact 'fixture-sshd-account' $(if ($wv['wsluser'] -ieq $env:USERNAME) { 'same name as the Windows user' } else { 'differs from the Windows user (a non-root sshd authenticates only its own account)' })
            $fixtureEnv = @{ HM_FIXTURE_SSHD_HOST = '127.0.0.1'; HM_FIXTURE_SSHD_PORT = $fx['port']; HM_FIXTURE_SSHD_HOST_KEY = $fx['hostkey']; HM_FIXTURE_SSHD_AUTHORIZED_KEYS = $ak; HM_FIXTURE_SSHD_LOG = $slog }
        } else {
            Add-Fact 'fixture-sshd-harness' 'failed: not reachable from Windows; the tests run without HM_FIXTURE_SSHD_*'
            Add-Command 1 'fixture sshd in WSL scratch reachable from Windows on 127.0.0.1'
        }
    } else {
        Add-Fact 'fixture-sshd' "unavailable: $($fx['why'])"
        Add-Command 1 'fixture sshd in WSL scratch reachable from Windows on 127.0.0.1'
    }

    # 5. Every test binary, natively, with a timeout and its real exit code.
    $testEnv = New-ChildEnvironment (@{
            HEIMDALL_E2E_BIN = $cli; HM_FIXTURE_HOOK = $hook; HM_REPO_ROOT = $src; TEMP = $wtmp; TMP = $wtmp
        } + $fixtureEnv)
    # The in-box OpenSSH first (the E6 baseline), as the remote harness does.
    $testEnv['PATH'] = (Join-Path $sys32 'OpenSSH') + ';' + $testEnv['PATH']
    Add-Fact 'ssh-V-tests' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ssh -V') $testEnv $run 30).Output.Trim() + ' (what the tests resolve)')
    $pipes = { @([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -like '*\heimdall-hmtest-*' }).Count }
    Add-Fact 'test-pipes-before' (& $pipes)
    $arc = 0
    foreach ($b in $bins) {
        $sk = $skips[$b.Name]
        if ($sk -and $sk -contains '*') { [void]$skipped.Append("$($b.Name): not run on windows (build_host_paths)`n"); continue }
        $a = @()
        if ($sk) { $a += '--exact'; foreach ($n in $sk) { $a += @('--skip', $n) } }
        $a += '--show-output'
        $r = Invoke-Bounded $b.Exe $a $testEnv $b.Cwd $TimeoutSeconds
        [void]$tests.Append((Format-TargetOutput $b.Name $r.Output $r.Code))
        if ($r.Code -ne 0) { $arc = $r.Code }
    }
    if ($ArgvDump) {
        $drv = Join-Path $src 'tests\native\windows-launch\Invoke-WindowsLaunch.ps1'
        $rep = Join-Path $wtmp 'windows-launch-report.json'
        # Windows PowerShell, as the remote harness runs the drivers; the execution policy is
        # bypassed for that one process only.
        $winps = Join-Path $sys32 'WindowsPowerShell\v1.0\powershell.exe'
        $r = Invoke-Bounded $winps @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $drv, '-Heimdall', $cli, '-ArgvDump', $ArgvDump, '-Out', $rep) $testEnv $run 600
        $rows = ''
        if (Test-Path $rep) {
            foreach ($row in @((Get-Content -LiteralPath $rep -Raw | ConvertFrom-Json).rows)) {
                $rows += "test $($row.id) ... $(if ($row.verdict -eq 'pass') { 'ok' } else { 'FAILED' })`n  observed: $($row.observed | ConvertTo-Json -Compress -Depth 4)`n"
            }
        } else { $rows = "windows_launch: no report (exit $($r.Code))`n" }
        [void]$tests.Append((Format-TargetOutput 'windows_launch' $rows $r.Code))
        if ($r.Code -ne 0) { $arc = $r.Code }
    } else {
        [void]$skipped.Append("windows_launch: not run (the pseudoconsole drivers need argvdump.exe, built with Go; pass -ArgvDump)`n")
    }
    Add-Command $arc 'every test binary natively, each under its timeout (overall exit = last failing binary''s exit, 0 if all passed)'
    if ($arc -ne 0) { $overall = 1 }
    Add-Fact 'test-pipes-after' (& $pipes)
    Add-Fact 'localappdata-heimdall-after' $(if (Test-Path (Join-Path $env:LOCALAPPDATA 'heimdall')) { 'present' } else { 'absent' })
    $ownerAfter = & $ownerDigest
    Add-Fact 'owner-ssh-git-after' $ownerAfter
    Add-Command $(if ($ownerBefore -eq $ownerAfter) { 0 } else { 1 }) '%USERPROFILE%\.ssh and .gitconfig metadata unchanged by the run'
    if ($ownerBefore -ne $ownerAfter) { $overall = 1 }
} catch {
    Add-Command 1 "the run stopped: $($_.Exception.Message)"
    $overall = 1
} finally {
    # Stop the sshd this run started: by its recorded PID, start time and configuration path
    # (hm2_stop_recorded), then the wsl.exe process through its own handle.
    # Each cleanup step reports its own failure and never stops the others or the bundle.
    try {
        if ($wslDir) {
            $r = Invoke-Wsl ($remoteLib + "`n" + 'echo "stop=$(hm2_stop_recorded "$1/sshd")"' + "`n") @($wslDir) 120
            $atEnd = Get-SshdAtEnd $r.Output
            Add-Fact 'fixture-sshd-at-end' $atEnd
            # Only `stopped` (signalled and gone) or `gone` (already exited) leaves no sshd
            # behind; `mismatch`, `still-running`, `none` or no answer at all means one may
            # still be running in WSL, and that is a failure of the run, not just a fact.
            $ended = Test-SshdAtEndOk $atEnd
            Add-Command $(if ($ended) { 0 } else { 1 }) 'wsl.exe: the recorded fixture sshd is stopped (or already gone) at the end of the run'
            if (-not $ended) { $overall = 1 }
        }
        if ($null -ne $sshdProc) {
            if (-not $sshdProc.WaitForExit(30000)) { $sshdProc.Kill($true); $sshdProc.WaitForExit() }
            if ($null -ne $sshdErr) { [void]$sshdErr.Wait(5000) }
            $sshdProc.Dispose()
        }
    } catch { Add-Command 1 "stopping the fixture sshd: $($_.Exception.Message)"; $overall = 1 }
    # 9. Remove the build, the toolchain and the WSL scratch; keep the bundle.
    try {
        if ($wslDir) {
            $r = Invoke-Wsl 'set -u; case "$1" in "$HOME"/hm-m02-local-*) rm -rf -- "$1" && test ! -e "$1" ;; *) exit 2 ;; esac' @($wslDir) 300
            Add-Command $r.Code 'wsl.exe: remove exactly the WSL scratch directory, then check it is absent'
            if ($r.Code -ne 0) { $overall = 1 }
        }
    } catch { Add-Command 1 "removing the WSL scratch directory: $($_.Exception.Message)"; $overall = 1 }
    foreach ($d in @($src, $tools, $wtmp, $sshdDir, (Join-Path $run 'githome'))) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $gone = -not ((Test-Path -LiteralPath $src) -or (Test-Path -LiteralPath $tools) -or (Test-Path -LiteralPath $wtmp))
    Add-Command $(if ($gone) { 0 } else { 1 }) 'remove the clone, the build and the toolchain from the run directory, then check they are absent'
    if (-not $gone) { $overall = 1 }

    # 7 and 8. Redact, mask, scan, bundle.
    $rules = @(
        (New-RedactionRule $env:USERPROFILE '<winhome>'),
        (New-RedactionRule $(if ($wv) { $wv['wslhome'] } else { '' }) '<wslhome>'),
        (New-RedactionRule $env:USERNAME '<winuser>'),
        (New-RedactionRule $(if ($wv) { $wv['wsluser'] } else { '' }) '<wsluser>'),
        (New-RedactionRule $env:COMPUTERNAME '<winhost>' -Word),
        (New-RedactionRule ([System.Net.Dns]::GetHostName()) '<winhost>' -Word),
        (New-RedactionRule $(if ($wv) { $wv['wslhost'] } else { '' }) '<wslhost>' -Word),
        (New-RedactionRule $run '<run>')
    )
    $raw = @{ 'tests.txt' = $tests.ToString(); 'commands.txt' = $commands.ToString(); 'host.txt' = $hostFacts.ToString();
        'build.txt' = $build.ToString(); 'skipped.txt' = $skipped.ToString(); 'canary-scan.txt' = '' }
    $p = Protect-BundleFiles $raw $rules
    $m = Get-ProtectedMetadata $Label $rules
    $canaryTotal = $p.Canaries + $m.Canaries
    $leakTotal = $p.Leaks + $m.Leaks
    $files = $p.Files
    $files['canary-scan.txt'] = "canary-prefix occurrences in saved output and metadata: $canaryTotal (values masked before the bundle was written)`n"
    $files['commands.txt'] += Format-CommandLine $(if ($canaryTotal -eq 0) { 0 } else { 1 }) "canary-prefix scan over saved output and metadata (count = $canaryTotal)"
    $files['commands.txt'] += Format-CommandLine $(if ($leakTotal -eq 0) { 0 } else { 1 }) "leak scan: saved files and metadata still naming a host, a user or a home ($leakTotal)"
    if ($canaryTotal -ne 0 -or $leakTotal -ne 0) { $overall = 1 }
    $meta = [ordered]@{ commit = $Commit; label = $m.Label; started_at = $started; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); exit = $overall }
    $b = New-Bundle $files $meta
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.json'), $b.Json, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.b64'), $b.Text, [System.Text.UTF8Encoding]::new($false))
    Write-Output "bundle: <run>\bundle\bundle.b64 ($($b.Text.Length) characters); import it with tests/native/m02/import-windows-bundle.py"
    Write-Output $b.Text
}
exit $overall
