<#
.SYNOPSIS
  G02 round-4 X1: native Windows checks of the frozen G02 prototype artifacts (harness code, not product code).

.DESCRIPTION
  Runs heimdall-proto.exe of each candidate (default go, rust) against docs/g02/slice-contract.md on a native
  Windows host and writes one row per check to <OutDir>\results.json (plus redacted per-row artifacts under
  <OutDir>\rows\). Sections:

    env         host facts, elevation (must be false), development toolchains on the (reduced) PATH (must be none)
    selftest    harness controls: VT screen-model unit cases; console Ctrl-C delivery to argvdump without heimdall-proto
    integrity   sha256 of each exe against the candidate's dist manifest.json
    version     version --json (section 6), plain version exit (K12)
    profile     profile show: homelab under a path with spaces, Unicode and a non-BMP character; plain fixture;
                large-100; every invalid fixture (exit 2, codes, canary non-echo, K18 value non-echo); missing
                file, directory, NUL device, a named pipe as --file (K14 analogs), >1 MiB (INPUT_TOO_LARGE)
    usage       usage errors with and without --json (section 1)
    agent       agent list --socket on the fixture agent tests/native/windows/InstrumentedAgent.ps1 (ASCII and
                space+Unicode pipe names), missing pipe, a regular file as --socket (must not be modified),
                a pipe that never answers (--timeout-ms)
    run         argv fidelity for tests/native/windows/fixtures/quoting-cases.json (byte compare of the child's
                CommandLineToArgvW split, with a direct-launch control), a lone UTF-16 surrogate (recorded),
                exit codes incl. values above 255 and NTSTATUS-like codes, 127 launch failures, usage errors,
                --meta-file, binary stdout/stdin pass-through, environment and working-directory inheritance,
                a .cmd target with a cmd metacharacter argument (recorded)
    resolution  which executable `run -- <name>` starts: application directory vs PATH vs current directory,
                PATHEXT (.cmd) and a System32 name shadowed earlier on PATH
    ctrlc       console Ctrl-C: the process runs on a new pseudoconsole (no window); the event is raised by a
                separate process (Send-ConsoleCtrl.ps1: AttachConsole + GenerateConsoleCtrlEvent) and, as a
                second form, typed as ^C into the console input. run (child sees it once, launcher waits and
                exits with the child's code), agent list while waiting (exit 130, CANCELLED, <= 500 ms),
                Ctrl-Break (recorded)
    tui         tui on a pseudoconsole (CreatePseudoConsole via P/Invoke): no-TTY usage error, navigation,
                filter (incl. non-ASCII input), Esc clear, select, quit, ^C key and console Ctrl-C event,
                resize to 40x12 and 20x5, NO_COLOR, large-100

  Expected layout under -Root (built by the operator, nothing is downloaded or built here):
    bin\<candidate>\heimdall-proto.exe      frozen artifacts       manifests\<candidate>-manifest.json
    fixtures\profiles\...                   tests/fixtures/g02/profiles
    fixtures\quoting-cases.json             tests/native/windows/fixtures/quoting-cases.json
    g03\G03Common.psm1, g03\InstrumentedAgent.ps1   (tests/native/windows)
    helpers\argvdump.exe                    tests/native/windows-g02/argvdump (cross-compiled)
    this directory's G02X1Native.cs, Send-ConsoleCtrl.ps1, StallPipe.ps1, expected-homelab.json next to this script

  Safety: non-elevated only (aborts when elevated); fixture agent and stall pipe use a protected current-user-only
  DACL and reject remote clients; SSH_AUTH_SOCK is set to a pipe name that does not exist (never unset, never the
  system agent pipe); no windows are created (pseudoconsoles, CreateNoWindow); only processes started here are
  stopped, through handles held since start; all files stay under -Root and -OutDir. Output is redacted (user
  and host names, profile paths, SIDs, canary values) before it is written.

  Compatible with Windows PowerShell 5.1 and PowerShell 7.x. Exit: 0 when every gating row passed, 1 otherwise,
  2 on a setup error.
#>
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string[]]$Candidates = @('go', 'rust'),
    [string[]]$Sections = @('env', 'selftest', 'integrity', 'version', 'profile', 'usage', 'agent', 'run', 'resolution', 'ctrlc', 'tui'),
    [string]$OnlyRows = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# -File passes "a,b" as one string: accept comma lists.
$Candidates = @($Candidates | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Sections = @($Sections | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Here = $PSScriptRoot
$CanaryPrefix = 'HEIMDALL_' + 'CANARY_'

if (-not ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)) { Write-Error 'Windows only'; exit 2 }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'refusing to run elevated'; exit 2 }

New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir 'rows') | Out-Null
$Scratch = Join-Path $Root 'scratch'
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $Here 'G02X1Native.cs')))
Import-Module (Join-Path $Root 'g03\G03Common.psm1') -Force

$MySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$Rows = New-Object System.Collections.ArrayList
$Owned = New-Object System.Collections.ArrayList
$RunTag = New-G03RandomHex 4
$Canary = $CanaryPrefix + 'X1_' + (New-G03RandomHex 10)
$SentinelPipe = '\\.\pipe\hm-x1-none-' + $RunTag
$G03Ctx = [pscustomobject]@{ Scratch = (Join-Path $Scratch 'g03'); Owned = $Owned; Canary = $Canary; SentinelPipe = $SentinelPipe }
New-Item -ItemType Directory -Force -Path $G03Ctx.Scratch | Out-Null
$ArgvDump = Join-Path $Root 'helpers\argvdump.exe'
$HostExe = (Get-Process -Id $PID).Path

# ------------------------------------------------------------------ redaction and rows
$RedactPairs = New-Object System.Collections.ArrayList
function Add-Redaction { param([string]$Value, [string]$Label)
    if ($Value -and $Value.Length -ge 3) {
        [void]$RedactPairs.Add(@($Value, $Label))
        [void]$RedactPairs.Add(@(($Value -replace '\\', '\\'), ($Label -replace '\\', '\\')))   # JSON-escaped form
        [void]$RedactPairs.Add(@(($Value -replace '\\', '/'), ($Label -replace '\\', '/')))
    } }
Add-Redaction $Root '<scratch>'
Add-Redaction $env:LOCALAPPDATA '<winhome>\AppData\Local'
Add-Redaction $env:USERPROFILE '<winhome>'
$script:CanaryHits = 0   # canary-prefix occurrences seen in anything about to be written (before redaction)
function Protect-X1 { param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $null }
    if ($Text.Contains($CanaryPrefix)) { $script:CanaryHits++ }
    $t = $Text
    foreach ($p in $RedactPairs) { $t = $t.Replace($p[0], $p[1]); $t = [regex]::Replace($t, [regex]::Escape($p[0]), $p[1].Replace('$', '$$'), 'IgnoreCase') }
    foreach ($v in @($env:USERNAME, $env:COMPUTERNAME, $env:USERDOMAIN)) {
        if ($v -and $v.Length -ge 3) {
            $lbl = '<winuser>'; if ($v -eq $env:COMPUTERNAME -or $v -eq $env:USERDOMAIN) { $lbl = '<winhost>' }
            $t = [regex]::Replace($t, '(?<![A-Za-z0-9])' + [regex]::Escape($v) + '(?![A-Za-z0-9])', $lbl, 'IgnoreCase')
        } }
    $t = [regex]::Replace($t, 'S-1-5-21-\d+-\d+-\d+', 'S-1-5-21-<redacted>')
    $t = [regex]::Replace($t, [regex]::Escape($CanaryPrefix) + '[A-Za-z0-9_]*', '[REDACTED_CANARY]')
    return $t }

function Test-PSCO { param($O) return ($null -ne $O) -and ($O.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') }
function ConvertTo-X1Safe { param($Obj)
    # Redacts every string in a row before it is stored.
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [string]) { return (Protect-X1 $Obj) }
    if ($Obj -is [System.Collections.IDictionary]) { $o = [ordered]@{}; foreach ($k in $Obj.Keys) { $o[[string]$k] = ConvertTo-X1Safe $Obj[$k] }; return $o }
    if ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) { $a = @(); foreach ($x in $Obj) { $a += , (ConvertTo-X1Safe $x) }; return , $a }
    if (Test-PSCO $Obj) { $o = [ordered]@{}; foreach ($pp in $Obj.PSObject.Properties) { $o[$pp.Name] = ConvertTo-X1Safe $pp.Value }; return $o }
    return $Obj }

function Test-Selected { param([string]$Id) return (-not $OnlyRows) -or ($Id -match $OnlyRows) }

# verdict: pass | fail | inconclusive | blocked | info. gating rows decide the exit code.
function Add-Row { param([string]$Cand, [string]$Id, [string]$Verdict, [bool]$Gating, [string]$Criterion, $Observed, [string]$Note = '')
    $row = [ordered]@{ candidate = $Cand; id = $Id; verdict = $Verdict; gating = $Gating; criterion = $Criterion
        observed = (ConvertTo-X1Safe $Observed); note = (Protect-X1 $Note); at = [DateTime]::UtcNow.ToString('o') }
    [void]$Rows.Add($row)
    $flag = $Verdict.ToUpper(); if (-not $Gating) { $flag += '(non-gating)' }
    [Console]::Out.WriteLine(('{0,-22} {1,-5} {2}' -f $flag, $Cand, $Id))
}
function Get-Verdict { param([bool]$Ok) if ($Ok) { return 'pass' } return 'fail' }

function Save-RowArtifact { param([string]$Cand, [string]$Id, [string]$Name, [AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return }
    $f = Join-Path (Join-Path $OutDir 'rows') (($Cand + '.' + $Id + '.' + $Name) -replace '[^A-Za-z0-9._-]', '_')
    [System.IO.File]::WriteAllText($f, (Protect-X1 $Text), $Utf8) }

function Get-Hex { param([byte[]]$B, [int]$Max = 4096)
    if ($null -eq $B) { return '' }
    $n = [Math]::Min($B.Length, $Max); $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $n; $i++) { [void]$sb.Append($B[$i].ToString('x2')) }
    return $sb.ToString() }
function ConvertTo-U32 { param([long]$Code) return [uint32]($Code -band 0xFFFFFFFFL) }
function Test-CanaryText { param([AllowNull()][string]$Text) if ($null -eq $Text) { return $false } return $Text.Contains($CanaryPrefix) }

# ------------------------------------------------------------------ process helpers
# Pipes for stdin/stdout/stderr, CreateNoWindow (no console) unless -WithConsole (inherits this process's console).
function Invoke-X1 { param([string]$Exe, [string[]]$ArgList = @(), [string]$RawArgs, [hashtable]$Env = @{}, [byte[]]$Stdin,
        [int]$TimeoutMs = 20000, [string]$Cwd, [switch]$WithConsole)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    if ($PSBoundParameters.ContainsKey('RawArgs')) { $psi.Arguments = $RawArgs } else { $psi.Arguments = Join-G03WinArgs $ArgList }
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = -not $WithConsole
    if ($Cwd) { $psi.WorkingDirectory = $Cwd } else { $psi.WorkingDirectory = $Scratch }
    foreach ($k in $Env.Keys) { if ($null -eq $Env[$k]) { [void]$psi.EnvironmentVariables.Remove($k) } else { $psi.EnvironmentVariables[$k] = [string]$Env[$k] } }
    $p = New-Object System.Diagnostics.Process; $p.StartInfo = $psi
    $sw = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $o = New-Object System.IO.MemoryStream; $e = New-Object System.IO.MemoryStream
    $to = $p.StandardOutput.BaseStream.CopyToAsync($o); $te = $p.StandardError.BaseStream.CopyToAsync($e)
    try { if ($Stdin) { $p.StandardInput.BaseStream.Write($Stdin, 0, $Stdin.Length); $p.StandardInput.BaseStream.Flush() }; $p.StandardInput.Close() } catch { }
    $timedOut = -not $p.WaitForExit($TimeoutMs)
    $ms = $sw.ElapsedMilliseconds
    if ($timedOut) { try { $p.Kill() } catch { }; [void]$p.WaitForExit(5000) }
    try { [void]$to.Wait(5000); [void]$te.Wait(5000) } catch { }
    $code = $null; if (-not $timedOut) { $code = ConvertTo-U32 $p.ExitCode }
    $r = [pscustomobject]@{ Exit = $code; TimedOut = $timedOut; Ms = $ms; Out = $o.ToArray(); Err = $e.ToArray()
        OutText = $Utf8.GetString($o.ToArray()); ErrText = $Utf8.GetString($e.ToArray()); CmdLine = $psi.Arguments }
    $p.Dispose()
    return $r }

function Get-JsonDoc { param($R)
    # One JSON document followed by exactly one "\n" and nothing else (section 1).
    $res = [ordered]@{ one_line_lf = $false; parsed = $false; doc = $null; error = $null }
    $b = $R.Out
    if ($b.Length -gt 0 -and $b[$b.Length - 1] -eq 10) {
        $body = $Utf8.GetString($b, 0, $b.Length - 1)
        $res.one_line_lf = -not ($body.Contains("`n"))
        try { $res.doc = $body | ConvertFrom-Json; $res.parsed = $true } catch { $res.error = $_.Exception.Message }
    } else { $res.error = 'stdout does not end with a single LF' }
    return [pscustomobject]$res }

function Get-P { param($Obj, [string]$Path)
    $cur = $Obj
    foreach ($seg in $Path.Split('.')) { if ($null -eq $cur) { return $null }; $pp = $cur.PSObject.Properties[$seg]; if ($null -eq $pp) { return $null }; $cur = $pp.Value }
    return $cur }

function Test-JsonEqual { param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if (Test-PSCO $A) {
        if (-not (Test-PSCO $B)) { return $false }
        $ka = @($A.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object); $kb = @($B.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
        if (($ka -join "`0") -cne ($kb -join "`0")) { return $false }
        foreach ($k in $ka) { if (-not (Test-JsonEqual $A.$k $B.$k)) { return $false } }
        return $true }
    if ($A -is [array]) {
        if (-not ($B -is [array])) { return $false }
        if ($A.Count -ne $B.Count) { return $false }
        for ($i = 0; $i -lt $A.Count; $i++) { if (-not (Test-JsonEqual $A[$i] $B[$i])) { return $false } }
        return $true }
    if ($A -is [string]) { return ($B -is [string]) -and ($A -ceq $B) }
    if ($A -is [bool]) { return ($B -is [bool]) -and ($A -eq $B) }
    return (-not ($B -is [string])) -and (-not ($B -is [bool])) -and ([decimal]$A -eq [decimal]$B) }

function Start-Owned { param([string]$Exe, [string[]]$ArgList)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe; $psi.Arguments = Join-G03WinArgs $ArgList
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $ot = $p.StandardOutput.ReadToEndAsync(); $et = $p.StandardError.ReadToEndAsync()
    $st = $null; try { $st = $p.StartTime.ToUniversalTime().ToString('o') } catch { }
    $o = [pscustomobject]@{ Kind = 'helper'; Pid = $p.Id; StartTime = $st; Process = $p; StdoutTask = $ot; StderrTask = $et }
    [void]$Owned.Add($o)
    return $o }

function Start-StallPipe { param([string]$Name)
    $dir = Join-Path $Scratch ('stall-' + (New-G03RandomHex 3)); New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $marker = Join-Path $dir 'connects.txt'; $ready = Join-Path $dir 'ready.txt'
    $o = Start-Owned $HostExe @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Here 'StallPipe.ps1'),
        '-PipeName', $Name, '-MarkerFile', $marker, '-ReadyFile', $ready, '-RunSeconds', '600')
    $dl = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $ready) -and -not $o.Process.HasExited -and [DateTime]::UtcNow -lt $dl) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path -LiteralPath $ready)) { throw "stall pipe did not start: $(Protect-X1 ([string]$o.StderrTask.Result))" }
    return [pscustomobject]@{ Name = $Name; Path = "\\.\pipe\$Name"; Marker = $marker; Owned = $o } }
function Get-StallConnects { param($S) if (Test-Path -LiteralPath $S.Marker) { return @([System.IO.File]::ReadAllLines($S.Marker)).Count } return 0 }

function Send-Ctrl { param([int]$TargetPid, [int]$Event = 0)
    $r = Invoke-X1 -Exe $HostExe -ArgList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Here 'Send-ConsoleCtrl.ps1'),
        '-TargetPid', [string]$TargetPid, '-Event', [string]$Event) -TimeoutMs 60000
    $line = $r.OutText.Trim()
    $ticks = $null
    if ($line -match '^ok (\d+)$') { $ticks = [long]$Matches[1] }
    return [pscustomobject]@{ Exit = $r.Exit; Line = $line; Ticks = $ticks; Err = $r.ErrText } }

$VtRe = New-Object System.Text.RegularExpressions.Regex ('\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMNOc]')
function ConvertFrom-Vt { param([byte[]]$B) return $VtRe.Replace($Utf8.GetString($B), '') }
function Wait-Pty { param($Pty, [int]$From, [scriptblock]$Pred, [int]$Ms = 5000)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $Ms) {
        $txt = ConvertFrom-Vt ($Pty.Snapshot($From))
        if (& $Pred $txt) { return [pscustomobject]@{ Ok = $true; Ms = $sw.ElapsedMilliseconds; Text = $txt } }
        if ($Pty.HasExited) { Start-Sleep -Milliseconds 100; $txt = ConvertFrom-Vt ($Pty.Snapshot($From)); return [pscustomobject]@{ Ok = [bool](& $Pred $txt); Ms = $sw.ElapsedMilliseconds; Text = $txt } }
        Start-Sleep -Milliseconds 5
    }
    return [pscustomobject]@{ Ok = $false; Ms = $sw.ElapsedMilliseconds; Text = (ConvertFrom-Vt ($Pty.Snapshot($From))) } }
function Get-ArgLine { param([string[]]$A) return (Join-G03WinArgs $A) }

# ------------------------------------------------------------------ environment (reduced PATH, sentinel agent)
$OrigPathEntries = @($env:PATH -split ';' | Where-Object { $_ }).Count
# %SystemRoot% itself is left out: the Python launcher (py.exe) is installed there on some hosts.
$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"
$removedVars = @()
foreach ($v in @('GOROOT', 'GOPATH', 'GOBIN', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTC', 'NODE_PATH', 'BUN_INSTALL', 'PYTHONHOME', 'PYTHONPATH')) {
    if (Test-Path ("env:" + $v)) { $removedVars += $v; Remove-Item ("env:" + $v) } }
$env:SSH_AUTH_SOCK = $SentinelPipe
$env:HEIMDALL_X1_CANARY_ENV = $Canary
$env:NO_COLOR = $null; Remove-Item env:NO_COLOR -ErrorAction SilentlyContinue

$Exe = @{}
foreach ($c in $Candidates) { $Exe[$c] = Join-Path $Root "bin\$c\heimdall-proto.exe" }

try {
# ================================================================== env
if ($Sections -contains 'env') {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'   # read-only query
    $tools = @()
    foreach ($t in @('go', 'gofmt', 'cargo', 'rustc', 'rustup', 'gcc', 'clang', 'cl', 'link', 'zig', 'node', 'bun', 'deno', 'python', 'python3', 'py', 'git')) {
        $cmd = Get-Command $t -CommandType Application -ErrorAction SilentlyContinue
        if ($cmd) { $tools += ($t + ' -> ' + @($cmd)[0].Source) } }
    Add-Row 'host' 'env.facts' 'info' $false 'record host facts' ([ordered]@{
        os = [Environment]::OSVersion.VersionString; product = $cv.ProductName; display_version = $cv.DisplayVersion; build = $cv.CurrentBuild; ubr = $cv.UBR
        arch = $env:PROCESSOR_ARCHITECTURE; powershell = $PSVersionTable.PSVersion.ToString(); edition = $PSVersionTable.PSEdition
        caption = (Get-CimInstance Win32_OperatingSystem).Caption
        clr = [Environment]::Version.ToString(); elevated = $false; py_launcher_in_systemroot = (Test-Path -LiteralPath "$env:SystemRoot\py.exe")
        original_path_entries = $OrigPathEntries; path_now = $env:PATH; removed_env = $removedVars; ssh_auth_sock = 'sentinel pipe that does not exist'
        console_host = 'checks run under pseudoconsoles or with no console; no windows created' })
    Add-Row 'host' 'env.no_toolchain_on_path' (Get-Verdict ($tools.Count -eq 0)) $true 'no Go/Rust/C/Node/Bun/Deno/Python/zig/git resolvable on the PATH the artifacts run with (contract section 7)' ([ordered]@{ found = $tools })
}

# ================================================================== integrity
if ($Sections -contains 'integrity') {
    foreach ($c in $Candidates) {
        $man = Get-Content -LiteralPath (Join-Path $Root "manifests\$c-manifest.json") -Raw | ConvertFrom-Json
        $t = @($man.targets | Where-Object { $_.target -eq 'windows-x64' })[0]
        $h = Get-G03FileSha256 $Exe[$c]
        $len = (Get-Item -LiteralPath $Exe[$c]).Length
        $sig = Get-AuthenticodeSignature -LiteralPath $Exe[$c]
        $zone = $null; try { $zone = Get-Content -LiteralPath $Exe[$c] -Stream Zone.Identifier -ErrorAction Stop } catch { }
        Add-Row $c 'integrity.sha256_matches_manifest' (Get-Verdict ($h -eq $t.sha256 -and $len -eq $t.bytes)) $true 'sha256 and size equal dist/manifest.json windows-x64' ([ordered]@{
            sha256 = $h; manifest_sha256 = $t.sha256; bytes = $len; authenticode = [string]$sig.Status; mark_of_the_web = [bool]$zone })
    }
}

# ================================================================== harness self-test (no heimdall-proto involved)
if ($Sections -contains 'selftest') {
    $E = [char]27
    $cases = @(
        @('cup_and_text', "$E[?1049h$E[2J$E[H> abc$E[2;3Hxyz", 10, 4, "> abc`n  xyz`n`n`n", $true),
        @('pending_wrap_survives_sgr', (('a' * 10) + "$E[1mb$E[m"), 10, 3, (('a' * 10) + "`nb`n`n"), $false),
        @('wide_chars_two_cells', ([string][char]0x6771 + [char]0x4EAC + 'x' + "$E[1;6Hy"), 10, 2, (([string][char]0x6771 + [char]0x4EAC + 'xy') + "`n`n"), $false),
        @('wide_char_at_last_column_wraps', ('abcdefghi' + [char]0x6771), 10, 2, (('abcdefghi') + "`n" + [char]0x6771 + "`n"), $false),
        @('erase_and_ech', "abcdef$E[1;3H$E[2Xz$E[K", 10, 2, "abz`n`n", $false),
        @('alt_screen_leave_restores_main', "main$E[?1049hALT$E[?1049l", 10, 2, "main`n`n", $false))
    $allOk = $true; $obs = [ordered]@{}
    foreach ($tc in $cases) {
        $scr = New-Object X1Screen($tc[2], $tc[3]); $scr.Feed($Utf8.GetBytes($tc[1]))
        $got = $scr.Text(); $ok = ($got -ceq $tc[4]) -and ($scr.AltActive -eq $tc[5])
        $obs[$tc[0]] = $ok; if (-not $ok) { $allOk = $false; $obs[$tc[0] + '_got'] = $got } }
    Add-Row 'host' 'harness.screen_model_unit' (Get-Verdict $allOk) $true 'harness self-test: the VT screen model renders CUP/text, pending wrap across SGR, wide characters, ECH/EL and the alternate buffer as a terminal would' $obs
    $cf = Join-Path $Scratch 'ctrlc-control.json'
    foreach ($f in @($cf, ($cf + '.ready'))) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f } }
    $env:ARGVDUMP_CTRLC = $cf; $env:ARGVDUMP_EXIT = '42'
    try { $pty = [X1Pty]::Start((Get-ArgLine @($ArgvDump)), $Scratch, 100, 30, $null, $null) } finally { Remove-Item env:ARGVDUMP_CTRLC; Remove-Item env:ARGVDUMP_EXIT }
    $dl = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath ($cf + '.ready')) -and [DateTime]::UtcNow -lt $dl) { Start-Sleep -Milliseconds 20 }
    $snd = Send-Ctrl -TargetPid $pty.Pid -Event 0
    $ex = $pty.WaitExit(10000); if (-not $ex) { [void]$pty.Kill() }
    $cr = $null; if (Test-Path -LiteralPath $cf) { $cr = [System.IO.File]::ReadAllText($cf, $Utf8) | ConvertFrom-Json }
    $code = $null; if ($ex) { $code = $pty.ExitCode }
    $pty.Dispose()
    Add-Row 'host' 'harness.ctrlc_control_direct' (Get-Verdict ($snd.Line.StartsWith('ok') -and $cr -and $cr.interrupts -eq 1 -and $code -eq 42)) $true 'harness control: the sender (AttachConsole + GenerateConsoleCtrlEvent) reaches argvdump on a pseudoconsole exactly once, without heimdall-proto' ([ordered]@{ sender = $snd.Line; interrupts = $(if ($cr) { $cr.interrupts } else { $null }); exit = $code })
}

$ExpectedHomelab = ([System.IO.File]::ReadAllText((Join-Path $Here 'expected-homelab.json'), $Utf8)) | ConvertFrom-Json
$FixDir = Join-Path $Root 'fixtures\profiles'
# path with spaces, Unicode (Latin-1 and CJK) and a non-BMP character (UTF-16 surrogate pair)
$uniDirName = 'dir with space ' + [char]0x00FC + ' ' + [char]0x6771 + [char]0x4EAC + ' ' + [char]::ConvertFromUtf32(0x1F409)
$uniDir = Join-Path $Scratch ('fixtures x1\' + $uniDirName)
New-Item -ItemType Directory -Force -Path $uniDir | Out-Null
$uniFile = Join-Path $uniDir ('pr' + [char]0x00F8 + 'file homelab.toml')
[System.IO.File]::WriteAllBytes($uniFile, [System.IO.File]::ReadAllBytes((Join-Path $FixDir 'homelab.toml')))

function Test-ResultDoc { param($R, [int]$ExpExit, [string]$ExpCode, [string]$ExpState)
    $j = Get-JsonDoc $R
    $o = [ordered]@{ exit = $R.Exit; ms = $R.Ms; stdout_one_json_lf = $j.one_line_lf; parsed = $j.parsed; code = $null; state = $null; schema_version = $null
        warnings_is_array = $false; has_next = $false; stderr_bytes = $R.Err.Length; parse_error = $j.error }
    $ok = ($R.Exit -eq $ExpExit) -and $j.one_line_lf -and $j.parsed
    if ($j.parsed) {
        $o.code = Get-P $j.doc 'code'; $o.state = Get-P $j.doc 'state'; $o.schema_version = Get-P $j.doc 'schema_version'
        $o.warnings_is_array = ($null -ne $j.doc.PSObject.Properties['warnings'])
        $o.has_next = $j.doc.PSObject.Properties['next'] -ne $null
        $ok = $ok -and ($o.code -ceq $ExpCode) -and ($o.state -ceq $ExpState) -and ($o.schema_version -ceq '1') -and $o.has_next
    }
    return [pscustomobject]@{ Ok = $ok; Obs = $o; Doc = $j.doc } }

foreach ($c in $Candidates) {
    $X = $Exe[$c]
    # ================================================================== version
    if ($Sections -contains 'version') {
        $r = Invoke-X1 $X @('version', '--json')
        $t = Test-ResultDoc $r 0 'VERSION_OK' 'succeeded'
        $d = $t.Doc
        $ok = $t.Ok -and ((Get-P $d 'data.name') -ceq 'heimdall-proto') -and ((Get-P $d 'data.version') -ceq '0.0.0-g02') -and ((Get-P $d 'data.candidate') -ceq $c) -and
            [bool](Get-P $d 'data.runtime') -and [bool](Get-P $d 'data.tui_framework') -and [bool](Get-P $d 'data.tui_framework_version') -and ($r.Err.Length -eq 0)
        $t.Obs['data'] = (Get-P $d 'data')
        Save-RowArtifact $c 'version.json' 'stdout.txt' $r.OutText
        Add-Row $c 'version.json' (Get-Verdict $ok) $true 'section 6: exit 0, one JSON doc + LF, VERSION_OK, data fields, candidate matches, empty stderr' $t.Obs
        $r2 = Invoke-X1 $X @('version')
        Add-Row $c 'version.plain_exit' (Get-Verdict ($r2.Exit -eq 0)) $true 'K12: plain version exits 0' ([ordered]@{ exit = $r2.Exit; stdout_bytes = $r2.Out.Length })
    }

    # ================================================================== profile
    if ($Sections -contains 'profile') {
        foreach ($case in @(@('profile.homelab_unicode_space_path', $uniFile), @('profile.homelab_fixture', (Join-Path $FixDir 'homelab.toml')),
                            @('profile.homelab_spaced_fixture', (Join-Path $FixDir ('spaced dir ' + [char]0x00FC + '\pr' + [char]0x00F8 + 'file homelab.toml'))))) {
            $r = Invoke-X1 $X @('profile', 'show', '--file', $case[1], '--json')
            $t = Test-ResultDoc $r 0 'PROFILE_OK' 'succeeded'
            $eq = $t.Ok -and (Test-JsonEqual (Get-P $t.Doc 'data') $ExpectedHomelab)
            $t.Obs['data_equals_expected'] = $eq
            $t.Obs['path_utf16_units'] = $case[1].Length
            Save-RowArtifact $c $case[0] 'stdout.txt' $r.OutText
            Save-RowArtifact $c $case[0] 'stderr.txt' $r.ErrText
            Add-Row $c $case[0] (Get-Verdict $eq) $true 'section 2: exit 0 PROFILE_OK and data equal to the homelab fixture (order, default port, Unicode alias); path may contain spaces and non-ASCII' $t.Obs
        }
        $r = Invoke-X1 $X @('profile', 'show', '--file', (Join-Path $FixDir 'large-100.toml'), '--json')
        $t = Test-ResultDoc $r 0 'PROFILE_OK' 'succeeded'
        $dd = Get-P $t.Doc 'data.profile.destinations'; $n = 0; if ($null -ne $dd) { $n = @($dd).Count }
        $t.Obs['destinations'] = $n
        Add-Row $c 'profile.large_100' (Get-Verdict ($t.Ok -and $n -eq 100)) $true 'large-100.toml: PROFILE_OK with 100 destinations' $t.Obs
        $r = Invoke-X1 $X @('profile', 'show', '--file', (Join-Path $FixDir 'homelab.toml'))
        Add-Row $c 'profile.plain_exit' (Get-Verdict ($r.Exit -eq 0)) $true 'K12: plain profile show exits 0' ([ordered]@{ exit = $r.Exit })

        $invalid = @(
            @('invalid-forbidden-key.toml', 'private_key'), @('invalid-unknown-dest-key.toml', 'identity_file'), @('invalid-malformed.toml', $null),
            @('invalid-schema-version.toml', 'schema_version'), @('invalid-duplicate-alias.toml', $null), @('invalid-port.toml', 'port'))
        foreach ($inv in $invalid) {
            $id = 'profile.' + ($inv[0] -replace '\.toml$', '')
            $r = Invoke-X1 $X @('profile', 'show', '--file', (Join-Path $FixDir $inv[0]), '--json')
            $t = Test-ResultDoc $r 2 'SCHEMA_INVALID' 'failed'
            $kp = Get-P $t.Doc 'data.error.key_path'; $msg = Get-P $t.Doc 'data.error.message'
            $canaryHit = (Test-CanaryText $r.OutText) -or (Test-CanaryText $r.ErrText)
            $valueEcho = $false
            if ($inv[0] -eq 'invalid-port.toml') { $valueEcho = $r.OutText.Contains('70000') -or $r.ErrText.Contains('70000') }
            $t.Obs['key_path'] = $kp; $t.Obs['message_present'] = [bool]$msg; $t.Obs['canary_prefix_in_stdout_or_stderr'] = $canaryHit; $t.Obs['offending_value_echoed'] = $valueEcho
            $ok = $t.Ok -and $t.Doc.PSObject.Properties['data'] -ne $null -and ($null -ne (Get-P $t.Doc 'data.error')) -and [bool]$msg -and -not $canaryHit -and -not $valueEcho
            if ($inv[1]) { $ok = $ok -and ([string]$kp).Contains($inv[1]) }
            Save-RowArtifact $c $id 'stdout.txt' $r.OutText
            Save-RowArtifact $c $id 'stderr.txt' $r.ErrText
            Add-Row $c $id (Get-Verdict $ok) $true ('section 2/K18: exit 2 SCHEMA_INVALID, data.error{key_path,message}' + $(if ($inv[1]) { ", key_path names '$($inv[1])'" } else { '' }) + ', no canary or offending value on stdout/stderr') $t.Obs
            $rp = Invoke-X1 $X @('profile', 'show', '--file', (Join-Path $FixDir $inv[0]))
            if ($inv[0] -eq 'invalid-forbidden-key.toml') {
                Add-Row $c 'profile.invalid_plain_exit' (Get-Verdict ($rp.Exit -eq 2 -and -not (Test-CanaryText $rp.OutText) -and -not (Test-CanaryText $rp.ErrText))) $true 'K12/K18: plain run exits 2, no canary' ([ordered]@{ exit = $rp.Exit })
            }
        }
        $missing = Join-Path $Scratch ('no such file ' + $RunTag + '.toml')
        $r = Invoke-X1 $X @('profile', 'show', '--file', $missing, '--json')
        $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'
        Add-Row $c 'profile.missing_file' (Get-Verdict $t.Ok) $true 'section 2: missing file -> exit 2 USAGE_ERROR' $t.Obs
        $r = Invoke-X1 $X @('profile', 'show', '--file', $uniDir, '--json') -TimeoutMs 10000
        $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'; $t.Obs['timed_out'] = $r.TimedOut
        Add-Row $c 'profile.directory' (Get-Verdict ($t.Ok -and $r.Ms -lt 2000)) $true 'K14: a directory -> exit 2 USAGE_ERROR within 2 s' $t.Obs
        $r = Invoke-X1 $X @('profile', 'show', '--file', 'NUL', '--json') -TimeoutMs 10000
        $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'; $t.Obs['timed_out'] = $r.TimedOut
        Add-Row $c 'profile.nul_device' (Get-Verdict ($t.Ok -and $r.Ms -lt 2000)) $true 'K14 analog: the NUL device -> exit 2 USAGE_ERROR within 2 s' $t.Obs
        $sp = Start-StallPipe ('hm-x1-file-' + $c + '-' + $RunTag)
        $r = Invoke-X1 $X @('profile', 'show', '--file', $sp.Path, '--json') -TimeoutMs 10000
        $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'; $t.Obs['timed_out'] = $r.TimedOut; $t.Obs['pipe_connects'] = Get-StallConnects $sp
        Add-Row $c 'profile.named_pipe_as_file' (Get-Verdict ($t.Ok -and $r.Ms -lt 2000)) $true 'K14 analog: a named pipe (never answers) as --file -> exit 2 USAGE_ERROR within 2 s, never blocking' $t.Obs
        [void](Stop-G03Owned -Owned $sp.Owned)
        $big = Join-Path $Scratch 'oversize x1.toml'
        if (-not (Test-Path -LiteralPath $big)) {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.Append("schema_version = 1`nname = `"big`"`nrevision = 1`n")
            while ($sb.Length -le 1048576) { [void]$sb.Append('# ' + ('x' * 77) + "`n") }
            [System.IO.File]::WriteAllText($big, $sb.ToString(), $Utf8) }
        $r = Invoke-X1 $X @('profile', 'show', '--file', $big, '--json')
        $t = Test-ResultDoc $r 2 'INPUT_TOO_LARGE' 'failed'; $t.Obs['file_bytes'] = (Get-Item -LiteralPath $big).Length
        Add-Row $c 'profile.oversize' (Get-Verdict $t.Ok) $true 'section 2: > 1 MiB -> exit 2 INPUT_TOO_LARGE' $t.Obs
    }

    # ================================================================== usage
    if ($Sections -contains 'usage') {
        $r = Invoke-X1 $X @('frobnicate', '--json'); $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'
        Add-Row $c 'usage.unknown_subcommand_json' (Get-Verdict $t.Ok) $true 'section 1: exit 2 and a USAGE_ERROR JSON result with --json' $t.Obs
        $r = Invoke-X1 $X @('frobnicate')
        Add-Row $c 'usage.unknown_subcommand_plain' (Get-Verdict ($r.Exit -eq 2 -and $r.Out.Length -eq 0 -and $r.Err.Length -gt 0)) $true 'section 1: exit 2, stdout empty, stderr text' ([ordered]@{ exit = $r.Exit; stdout_bytes = $r.Out.Length; stderr_bytes = $r.Err.Length })
        $r = Invoke-X1 $X @('version', '--no-such-flag', '--json'); $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'
        Add-Row $c 'usage.unknown_flag_json' (Get-Verdict $t.Ok) $true 'section 1: unknown flag with --json' $t.Obs
        $r = Invoke-X1 $X @('profile', 'show', '--json'); $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'
        Add-Row $c 'usage.profile_missing_file_arg' (Get-Verdict $t.Ok) $true 'section 1: missing --file' $t.Obs
        $r = Invoke-X1 $X @('agent', 'list', '--json'); $t = Test-ResultDoc $r 2 'USAGE_ERROR' 'failed'
        Add-Row $c 'usage.agent_missing_socket_arg' (Get-Verdict $t.Ok) $true 'section 1: missing --socket' $t.Obs
    }

    # ================================================================== agent
    if ($Sections -contains 'agent') {
        $names = @(@('agent.list_fixture_agent', ('hm-x1-agent-' + $c + '-' + $RunTag)),
                   @('agent.list_unicode_space_pipe', ('heimdall g03 ' + [char]0x00FC + '-x1-' + $c + '-' + $RunTag)))
        foreach ($nm in $names) {
            $ag = Start-G03InstrumentedAgent -Ctx $G03Ctx -Name ($c + '-' + $nm[0].Split('_')[-1]) -PipeName $nm[1] -KeyCount 2 -RunSeconds 300
            $r = Invoke-X1 $X @('agent', 'list', '--socket', $ag.PipePath, '--json')
            $t = Test-ResultDoc $r 0 'AGENT_OK' 'succeeded'
            $idsRaw = Get-P $t.Doc 'data.identities'; $ids = @(); if ($null -ne $idsRaw) { $ids = @($idsRaw) }
            $exp = @($ag.Ready.keys)
            $match = ($ids.Count -eq $exp.Count)
            for ($i = 0; $match -and $i -lt $exp.Count; $i++) {
                $match = ($ids[$i].fingerprint -ceq $exp[$i].fingerprint) -and ($ids[$i].comment -ceq $exp[$i].comment) -and ($ids[$i].key_type -ceq 'ecdsa-sha2-nistp256')
                if ($match) { $props = @($ids[$i].PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object); $match = (($props -join ',') -eq 'comment,fingerprint,key_type') } }
            Start-Sleep -Milliseconds 300
            $rp = Invoke-X1 $X @('agent', 'list', '--socket', $ag.PipePath)
            Start-Sleep -Milliseconds 500
            [void](Stop-G03InstrumentedAgent -Agent $ag)
            $log = @(Read-G03AgentLog -Path $ag.LogPath)
            $reqTypes = @($log | Where-Object { $_.event -eq 'request' } | ForEach-Object { [int]$_.msg_type })
            $connects = @($log | Where-Object { $_.event -eq 'connect' })
            $sidSeen = @($connects | ForEach-Object { $s = [string](Get-G03Prop $_ 'client_sid'); if ($s -eq $MySid) { 'same_user' } elseif ($s) { $s } else { 'not_recorded' } })
            $t.Obs['identities'] = $ids.Count; $t.Obs['identities_match_fixture'] = $match
            $t.Obs['agent_request_types'] = $reqTypes; $t.Obs['agent_connections'] = $connects.Count; $t.Obs['client_identity_seen_by_agent'] = $sidSeen
            $t.Obs['plain_exit'] = $rp.Exit
            $ok = $t.Ok -and $match -and (@($reqTypes | Where-Object { $_ -ne 11 }).Count -eq 0) -and $reqTypes.Count -eq 2 -and $rp.Exit -eq 0
            Save-RowArtifact $c $nm[0] 'stdout.txt' $r.OutText
            Save-RowArtifact $c $nm[0] 'agent-log.jsonl' ([System.IO.File]::ReadAllText($ag.LogPath))
            Add-Row $c $nm[0] (Get-Verdict $ok) $true 'section 3: exit 0 AGENT_OK; identities (key_type, SHA256 fingerprint, comment; no blob) equal the fixture agent keys in order; only type-11 requests reach the agent (one per run); plain run exits 0 (K12)' $t.Obs
            if ($nm[0] -eq 'agent.list_fixture_agent') {
                $idOk = ($sidSeen.Count -gt 0) -and (@($sidSeen | Where-Object { $_ -ne 'same_user' }).Count -eq 0)
                Add-Row $c 'agent.client_identifiable_by_server' (Get-Verdict $idOk) $false 'recorded (not in the contract; interop input for G03): the fixture agent can identify the client (ImpersonateNamedPipeClient + OpenThreadToken yields the same user SID). error 1347 (ERROR_CANT_OPEN_ANONYMOUS) means the client connected at SecurityAnonymous, so a server that checks its client (as Win32-OpenSSH ssh-agent does) cannot' ([ordered]@{ seen = $sidSeen })
            }
        }
        $mp = '\\.\pipe\hm-x1-missing-' + $c + '-' + $RunTag
        $r = Invoke-X1 $X @('agent', 'list', '--socket', $mp, '--timeout-ms', '3000', '--json') -TimeoutMs 15000
        $t = Test-ResultDoc $r 5 'AGENT_UNAVAILABLE' 'failed'
        Add-Row $c 'agent.missing_pipe' (Get-Verdict $t.Ok) $true 'section 3: connect failure -> exit 5 AGENT_UNAVAILABLE' $t.Obs

        $reg = Join-Path $Scratch ('regular file as socket ' + $c + '.bin')
        $content = New-Object byte[] 4096
        for ($i = 0; $i -lt $content.Length; $i++) { $content[$i] = [byte](($i * 7 + 3) % 256) }
        [System.IO.File]::WriteAllBytes($reg, $content)
        $before = Get-G03FileSha256 $reg; $mtBefore = (Get-Item -LiteralPath $reg).LastWriteTimeUtc.Ticks
        $r = Invoke-X1 $X @('agent', 'list', '--socket', $reg, '--timeout-ms', '2000', '--json') -TimeoutMs 15000
        $after = Get-G03FileSha256 $reg; $mtAfter = (Get-Item -LiteralPath $reg).LastWriteTimeUtc.Ticks; $lenAfter = (Get-Item -LiteralPath $reg).Length
        $now = [System.IO.File]::ReadAllBytes($reg)
        $firstDiff = -1; for ($i = 0; $i -lt [Math]::Min($now.Length, $content.Length); $i++) { if ($now[$i] -ne $content[$i]) { $firstDiff = $i; break } }
        $j = Get-JsonDoc $r
        $obs = [ordered]@{ exit = $r.Exit; code = (Get-P $j.doc 'code'); ms = $r.Ms; unchanged = ($before -eq $after); length_after = $lenAfter; mtime_changed = ($mtBefore -ne $mtAfter)
            first_changed_offset = $firstDiff; first_16_bytes_after_hex = (Get-Hex $now 16); first_16_bytes_before_hex = (Get-Hex $content 16); stderr = $r.ErrText }
        Add-Row $c 'agent.regular_file_not_modified' (Get-Verdict ($before -eq $after -and $mtBefore -eq $mtAfter)) $true 'X1 task criterion: a regular file given as --socket is not modified (section 3: on Windows <path> is a named pipe; section 1 forbids writes outside paths named on the command line, and this path is named, so the contract does not literally forbid it; the criterion protects user data from a mistyped --socket)' $obs
        Add-Row $c 'agent.regular_file_result' (Get-Verdict ($r.Exit -eq 5)) $false 'recorded: a regular file as --socket gives exit 5 (AGENT_UNAVAILABLE or AGENT_PROTOCOL_ERROR)' ([ordered]@{ exit = $r.Exit; code = (Get-P $j.doc 'code') })

        $sp = Start-StallPipe ('hm-x1-stall-' + $c + '-' + $RunTag)
        $r = Invoke-X1 $X @('agent', 'list', '--socket', $sp.Path, '--timeout-ms', '1000', '--json') -TimeoutMs 15000
        $t = Test-ResultDoc $r 5 'AGENT_UNAVAILABLE' 'failed'; $t.Obs['pipe_connects'] = Get-StallConnects $sp
        Add-Row $c 'agent.timeout_no_reply' (Get-Verdict ($t.Ok -and $r.Ms -ge 900 -and $r.Ms -lt 3000)) $true 'section 3: no response within --timeout-ms 1000 -> exit 5 AGENT_UNAVAILABLE after ~1 s (900..3000 ms incl. start-up)' $t.Obs
        [void](Stop-G03Owned -Owned $sp.Owned)
    }

    # ================================================================== run
    if ($Sections -contains 'run') {
        $qc = Get-Content -LiteralPath (Join-Path $Root 'fixtures\quoting-cases.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $vals = @($qc.remote_argument_cases | ForEach-Object { [string]$_.value })
        $extra = @('\\server\share\', 'C:\path with space\', 'a"b"c', '"', '\', ' ', "nl`nline", 'x=1;y=$z')
        $allVals = $vals + $extra
        function Get-U16 { param([string]$S) $sb = New-Object System.Text.StringBuilder; foreach ($ch in $S.ToCharArray()) { [void]$sb.Append(([int]$ch).ToString('x4')) }; return $sb.ToString() }
        function Invoke-Dump { param([string]$Exe0, [string[]]$Pre, [string[]]$Vals, [hashtable]$Env = @{}, [string]$Cwd)
            $out = Join-Path $Scratch ('argv-' + (New-G03RandomHex 4) + '.json')
            $e = @{ 'ARGVDUMP_OUT' = $out }; foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
            $raw = Get-ArgLine ($Pre + $Vals)
            $r = Invoke-X1 -Exe $Exe0 -RawArgs $raw -Env $e -Cwd $Cwd
            $rep = $null; if (Test-Path -LiteralPath $out) { $rep = [System.IO.File]::ReadAllText($out, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $out }
            return [pscustomobject]@{ R = $r; Rep = $rep } }
        function Compare-Argv { param($Rep, [string[]]$Vals, [int]$Skip)
            if ($null -eq $Rep -or $null -eq $Rep.PSObject.Properties['argv_u16']) { return [ordered]@{ ok = $false; reason = 'no report' } }
            $got = @($Rep.argv_u16); $mism = @()
            if ($got.Count - $Skip -ne $Vals.Count) { return [ordered]@{ ok = $false; reason = ('argc ' + ($got.Count - $Skip) + ' expected ' + $Vals.Count) } }
            for ($i = 0; $i -lt $Vals.Count; $i++) { if ($got[$i + $Skip] -ne (Get-U16 $Vals[$i])) { $mism += $i } }
            return [ordered]@{ ok = ($mism.Count -eq 0); mismatched_indexes = $mism } }
        # control: argvdump launched directly with the same quoting proves the outer command line is right
        $ctl = Invoke-Dump $ArgvDump @() $allVals
        $ctlCmp = Compare-Argv $ctl.Rep $allVals 1
        Add-Row $c 'run.argv_control_direct' (Get-Verdict $ctlCmp.ok) $true 'harness control: argvdump launched directly with the same command-line quoting receives every value exactly (UTF-16 code units)' $ctlCmp
        $res = Invoke-Dump $X @('run', '--', $ArgvDump) $allVals
        $cmp = Compare-Argv $res.Rep $allVals 1
        $cmp['heimdall_exit'] = $res.R.Exit; $cmp['stdout_bytes'] = $res.R.Out.Length; $cmp['values'] = $allVals.Count
        if ($res.Rep) { $cmp['child_cmdline_utf16_hex'] = $res.Rep.cmdline_u16 }
        Add-Row $c 'run.argv_quoting_cases' (Get-Verdict ($cmp.ok -and $ctlCmp.ok -and $res.R.Exit -eq 0 -and $res.R.Out.Length -eq 0)) $true ('section 4: every quoting-cases.json value (17) plus ' + $extra.Count + ' Windows quoting edge cases reaches the child unchanged (CommandLineToArgvW split compared code unit by code unit); exit 0; nothing on stdout') $cmp
        foreach ($v in $allVals) {
            $one = Invoke-Dump $X @('run', '--', $ArgvDump) @($v)
            $oc = Compare-Argv $one.Rep @($v) 1
            if (-not $oc.ok) { Add-Row $c ('run.argv_single.' + (Get-U16 $v).Substring(0, [Math]::Min(16, (Get-U16 $v).Length))) 'fail' $true 'single-value run' ([ordered]@{ value_u16 = (Get-U16 $v); cmp = $oc }) } }
        $sur = 'lone' + [char]0xD800 + 'surrogate'
        $ctl2 = Invoke-Dump $ArgvDump @() @($sur); $c2 = Compare-Argv $ctl2.Rep @($sur) 1
        $res2 = Invoke-Dump $X @('run', '--', $ArgvDump) @($sur); $r2 = Compare-Argv $res2.Rep @($sur) 1
        $r2['control_ok'] = $c2.ok; $r2['heimdall_exit'] = $res2.R.Exit
        if ($res2.Rep) { $r2['child_argv1_u16'] = @($res2.Rep.argv_u16)[1] }
        Add-Row $c 'run.argv_lone_surrogate' (Get-Verdict ($r2.ok -and $c2.ok)) $false 'recorded (Windows analog of K8, not gated by the contract): an argument holding an unpaired UTF-16 surrogate (U+D800) reaches the child unchanged' $r2

        foreach ($code in @(0, 1, 2, 7, 42, 127, 128, 255, 256, 1000, 65536, -1, -1073741510)) {
            $meta = Join-Path $Scratch ('meta exit ' + $code + ' ' + [char]0x00FC + '.json')
            $r = Invoke-X1 $X @('run', '--meta-file', $meta, '--', $ArgvDump) -Env @{ 'ARGVDUMP_EXIT' = [string]$code }
            $m = $null; if (Test-Path -LiteralPath $meta) { $m = [System.IO.File]::ReadAllText($meta, $Utf8) | ConvertFrom-Json }
            $want = ConvertTo-U32 $code
            $mobs = $null; if ($m) { $mobs = [ordered]@{ code = $m.code; state = $m.state; launched = (Get-P $m 'data.launched'); exit_code = (Get-P $m 'data.exit_code'); signal = (Get-P $m 'data.signal') } }
            $metaOk = $m -and $m.code -ceq 'CHILD_EXITED' -and $m.state -ceq 'succeeded' -and (Get-P $m 'data.launched') -eq $true -and $null -ne (Get-P $m 'data.exit_code') -and ((ConvertTo-U32 ([long](Get-P $m 'data.exit_code'))) -eq $want) -and $null -eq (Get-P $m 'data.signal')
            $gate = ($code -ge 0 -and $code -le 255)
            Add-Row $c ('run.exit_code.' + $code) (Get-Verdict ($r.Exit -eq $want -and $metaOk -and $r.Out.Length -eq 0)) $gate ('section 4/K5: heimdall-proto exits with the child''s code (' + $want + ' as uint32); --meta-file CHILD_EXITED, state succeeded, launched true, exit_code equal (as uint32), signal null' + $(if (-not $gate) { '; codes outside 0..255 are recorded (the contract does not name them)' } else { '' })) ([ordered]@{ child_code_u32 = $want; heimdall_exit_u32 = $r.Exit; meta = $mobs })
            if (Test-Path -LiteralPath $meta) { Remove-Item -LiteralPath $meta } }

        $meta = Join-Path $Scratch 'meta launch failure.json'
        $nf = 'hm-x1-no-such-program-' + $RunTag
        $r = Invoke-X1 $X @('run', '--meta-file', $meta, '--', $nf)
        $m = $null; if (Test-Path -LiteralPath $meta) { $m = [System.IO.File]::ReadAllText($meta, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $meta }
        $ok = $r.Exit -eq 127 -and $r.Out.Length -eq 0 -and $r.Err.Length -gt 0 -and $m -and $m.code -ceq 'CHILD_LAUNCH_FAILED' -and $m.state -ceq 'failed' -and (Get-P $m 'data.launched') -eq $false -and $null -eq (Get-P $m 'data.exit_code')
        Add-Row $c 'run.launch_failure_not_found' (Get-Verdict $ok) $true 'section 4/K5: not found -> exit 127, stderr message, stdout empty, meta CHILD_LAUNCH_FAILED state failed launched false exit_code null' ([ordered]@{ exit = $r.Exit; stderr = $r.ErrText; meta = $m })
        $txt = Join-Path $Scratch 'not an executable.txt'; [System.IO.File]::WriteAllText($txt, "plain text`n")
        $r = Invoke-X1 $X @('run', '--', $txt)
        Add-Row $c 'run.launch_failure_not_executable' (Get-Verdict ($r.Exit -eq 127 -and $r.Out.Length -eq 0)) $true 'section 4: a .txt file as argv[0] -> exit 127' ([ordered]@{ exit = $r.Exit; stderr = $r.ErrText })
        $r = Invoke-X1 $X @('run')
        Add-Row $c 'run.usage_missing_separator' (Get-Verdict ($r.Exit -eq 2 -and $r.Out.Length -eq 0)) $true 'section 4: missing -- -> exit 2, stdout empty' ([ordered]@{ exit = $r.Exit; stderr = $r.ErrText })
        $r = Invoke-X1 $X @('run', '--')
        Add-Row $c 'run.usage_empty_argv' (Get-Verdict ($r.Exit -eq 2 -and $r.Out.Length -eq 0)) $true 'section 4: empty argv -> exit 2, stdout empty' ([ordered]@{ exit = $r.Exit; stderr = $r.ErrText })

        $bytes = [byte[]](0x00, 0xff, 0xfe, 0x0d, 0x0a, 0x1a, 0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xc3, 0x28, 0x0a, 0x0d, 0x80, 0x00, 0x41)
        $r = Invoke-X1 $X @('run', '--', $ArgvDump) -Env @{ 'ARGVDUMP_STDOUT_HEX' = (Get-Hex $bytes) }
        Add-Row $c 'run.stdout_binary_passthrough' (Get-Verdict ((Get-Hex $r.Out) -eq (Get-Hex $bytes) -and $r.Exit -eq 0)) $true 'section 4: child stdout bytes (NUL, CR/LF, 0x1A, ESC, invalid UTF-8) arrive unmodified' ([ordered]@{ expected_hex = (Get-Hex $bytes); got_hex = (Get-Hex $r.Out); exit = $r.Exit })
        $inFile = Join-Path $Scratch 'stdin-copy.bin'
        $big = New-Object byte[] 70000; for ($i = 0; $i -lt $big.Length; $i++) { $big[$i] = [byte](($i * 31 + 11) % 256) }
        $r = Invoke-X1 $X @('run', '--', $ArgvDump) -Env @{ 'ARGVDUMP_STDIN_OUT' = $inFile } -Stdin $big
        $got = $null; if (Test-Path -LiteralPath $inFile) { $got = [System.IO.File]::ReadAllBytes($inFile); Remove-Item -LiteralPath $inFile }
        $same = $got -and $got.Length -eq $big.Length -and ((Get-G03Sha256Hex $got) -eq (Get-G03Sha256Hex $big))
        Add-Row $c 'run.stdin_binary_passthrough' (Get-Verdict ($same -and $r.Exit -eq 0)) $true 'section 4: 70,000 stdin bytes (every byte value incl. NUL and 0x1A) reach the child unmodified' ([ordered]@{ sent = $big.Length; received = $(if ($got) { $got.Length } else { $null }); same = $same; exit = $r.Exit })
        $cwd = Join-Path $Scratch ('cwd ' + [char]0x00E9 + ' x1'); New-Item -ItemType Directory -Force -Path $cwd | Out-Null
        $res = Invoke-Dump $X @('run', '--', $ArgvDump) @() -Env @{ 'ARGVDUMP_TAG' = ('env-tag-' + $RunTag) } -Cwd $cwd
        $tagOk = $res.Rep -and $res.Rep.tag -ceq ('env-tag-' + $RunTag)
        Add-Row $c 'run.env_inherited' (Get-Verdict $tagOk) $true 'section 4: the child inherits the environment (a variable set for heimdall-proto is seen by the child)' ([ordered]@{ seen = [bool]$tagOk })
        $cwdSeen = $null; if ($res.Rep) { $cwdSeen = [string]$res.Rep.cwd }
        Add-Row $c 'run.cwd_inherited' (Get-Verdict ($cwdSeen -eq $cwd -and $res.R.Exit -eq 0)) $true 'section 4: the child inherits the working directory (a directory name with a space and U+00E9)' ([ordered]@{ child_cwd = $cwdSeen; expected = $cwd })

        # cmd.exe AutoRun (HKCU/HKLM "Command Processor") runs for `cmd /c` without /d; presence only, never the value.
        $autorun = $false
        foreach ($k in @('HKCU:\Software\Microsoft\Command Processor', 'HKLM:\Software\Microsoft\Command Processor')) {
            try { $v = Get-ItemProperty -LiteralPath $k -Name AutoRun -ErrorAction Stop; if ($v.AutoRun) { $autorun = $true } } catch { } }
        foreach ($variant in @(@('run.cmd_metachar_argument', 'echoargs x1.cmd'), @('run.cmd_metachar_argument_nospace_path', 'echoargsx1.cmd'))) {
            $cmdf = Join-Path $Scratch $variant[1]
            [System.IO.File]::WriteAllText($cmdf, "@echo off`r`necho ARGS:%*`r`n", (New-Object System.Text.ASCIIEncoding))
            $r = Invoke-X1 $X @('run', '--', $cmdf, 'a&echo INJECTED_X1') -TimeoutMs 15000
            $lines = @($r.OutText -split "`r?`n" | Where-Object { $_ -ne '' })
            $injected = @($lines | Where-Object { $_.Trim() -eq 'INJECTED_X1' }).Count -gt 0
            $errLines = @($r.ErrText -split "`r?`n" | Where-Object { $_ -ne '' })
            # stderr is not stored verbatim: with AutoRun configured it would echo the owner's AutoRun command.
            Add-Row $c $variant[0] (Get-Verdict (-not $injected)) $false ('recorded (BatBadBut class; section 4 forbids shell invocation but a .cmd target implies cmd.exe): argument "a&echo INJECTED_X1" to ' + $(if ($variant[1].Contains(' ')) { 'a .cmd whose path has a space' } else { 'a .cmd whose path has no space' }) + ' must not run a second command') ([ordered]@{
                exit = $r.Exit; injected = $injected; cmd_script_ran = (@($lines | Where-Object { $_.StartsWith('ARGS:') }).Count -gt 0); script_saw_args = @($lines | Where-Object { $_.StartsWith('ARGS:') })
                stderr_lines = $errLines.Count; stderr_says_not_recognized = (@($errLines | Where-Object { $_ -match 'is not recognized' }).Count); cmd_autorun_configured = $autorun })
        }
    }

    # ================================================================== resolution
    if ($Sections -contains 'resolution') {
        $base = Join-Path $Scratch ('res-' + $c); if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
        $app = Join-Path $base 'app'; $appClean = Join-Path $base 'app-clean'; $pathDir = Join-Path $base 'pathdir'; $cwdDir = Join-Path $base 'cwd'; $emptyCwd = Join-Path $base 'empty-cwd'
        New-Item -ItemType Directory -Force -Path $app, $appClean, $pathDir, $cwdDir, $emptyCwd | Out-Null
        Copy-Item -LiteralPath $X -Destination (Join-Path $app 'heimdall-proto.exe'); Copy-Item -LiteralPath $X -Destination (Join-Path $appClean 'heimdall-proto.exe')
        foreach ($d in @($app, $pathDir, $cwdDir)) { Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $d 'hmx1probe.exe') }
        Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $pathDir 'hostname.exe')
        [System.IO.File]::WriteAllText((Join-Path $pathDir 'hmx1cmd.cmd'), "@echo off`r`necho CMD_RAN`r`n", (New-Object System.Text.ASCIIEncoding))
        $labels = @{ $app = 'app_dir'; $pathDir = 'path_dir'; $cwdDir = 'cwd_dir'; $appClean = 'app_clean' }
        function Invoke-Res { param([string]$HeimdallDir, [string]$Name, [string]$Cwd, [string]$PathPrefix)
            $out = Join-Path $base ('rep-' + (New-G03RandomHex 3) + '.json')
            $savedPath = $env:PATH
            if ($PathPrefix) { $env:PATH = $PathPrefix + ';' + $savedPath } else { $env:PATH = $savedPath + ';' + $pathDir }
            try { $r = Invoke-X1 -Exe (Join-Path $HeimdallDir 'heimdall-proto.exe') -ArgList @('run', '--', $Name) -Env @{ 'ARGVDUMP_OUT' = $out } -Cwd $Cwd } finally { $env:PATH = $savedPath }
            $who = 'none (no argvdump copy ran)'
            if (Test-Path -LiteralPath $out) { $rep = [System.IO.File]::ReadAllText($out, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $out
                $dir = Split-Path -Parent ([string]$rep.exe); $who = 'unknown'; foreach ($k in $labels.Keys) { if ($dir -ieq $k) { $who = $labels[$k] } } }
            return [ordered]@{ ran = $who; exit = $r.Exit; stdout_bytes = $r.Out.Length; stderr = $r.ErrText } }
        $s1 = Invoke-Res $appClean 'hmx1probe' $emptyCwd $null
        Add-Row $c 'resolution.path_only' (Get-Verdict ($s1.ran -eq 'path_dir' -and $s1.exit -eq 0)) $true 'section 4 PATH lookup: name (no extension) only on PATH -> the PATH copy runs' $s1
        $s2 = Invoke-Res $app 'hmx1probe' $emptyCwd $null
        Add-Row $c 'resolution.app_dir_vs_path' 'info' $false 'recorded (section 9.4 noted the Windows search order from code review only): same name in heimdall-proto''s own directory and on PATH; which runs' $s2
        $s3 = Invoke-Res $appClean 'hmx1probe' $cwdDir $null
        Add-Row $c 'resolution.cwd_vs_path' 'info' $false 'recorded: same name in the current directory and on PATH (different files); which runs (CreateProcess would take the current directory)' $s3
        $savedPath = $env:PATH
        $out = Join-Path $base 'rep-cwdonly.json'
        try { $r = Invoke-X1 -Exe (Join-Path $appClean 'heimdall-proto.exe') -ArgList @('run', '--', 'hmx1probe') -Env @{ 'ARGVDUMP_OUT' = $out } -Cwd $cwdDir } finally { $env:PATH = $savedPath }
        $ranCwd = Test-Path -LiteralPath $out; if ($ranCwd) { Remove-Item -LiteralPath $out }
        Add-Row $c 'resolution.cwd_only' 'info' $false 'recorded: name only in the current directory (not on PATH); whether it runs (Go: ErrDot policy; K7 allows refusing)' ([ordered]@{ cwd_copy_ran = $ranCwd; exit = $r.Exit; stderr = $r.ErrText })
        $s5 = Invoke-Res $appClean 'hmx1cmd' $emptyCwd $null
        Add-Row $c 'resolution.pathext_cmd' 'info' $false 'recorded: `run -- hmx1cmd` where only hmx1cmd.cmd exists on PATH (PATHEXT resolution, implies cmd.exe; stderr not stored, AutoRun output possible)' ([ordered]@{ exit = $s5.exit; cmd_ran = ($s5.stdout_bytes -gt 0); stderr_lines = @($s5.stderr -split "`r?`n" | Where-Object { $_ -ne '' }).Count })
        $s6 = Invoke-Res $appClean 'hostname' $emptyCwd $pathDir
        Add-Row $c 'resolution.system32_vs_earlier_path' 'info' $false 'recorded: `run -- hostname` with a PATH directory holding hostname.exe placed BEFORE System32; which runs (stdout of the system hostname.exe is not stored)' ([ordered]@{ ran = $(if ($s6.ran -eq 'path_dir') { 'path_dir (earlier PATH entry)' } else { 'not the PATH copy (System32 or other)' }); exit = $s6.exit })
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }

    # ================================================================== ctrlc
    if ($Sections -contains 'ctrlc') {
        foreach ($form in @('event', 'keystroke', 'break_event')) {
            $cf = Join-Path $Scratch ('ctrlc-' + $c + '-' + $form + '.json')
            foreach ($f in @($cf, ($cf + '.ready'))) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f } }
            $env:ARGVDUMP_CTRLC = $cf; $env:ARGVDUMP_EXIT = '42'
            $pty = $null
            try {
                $pty = [X1Pty]::Start((Get-ArgLine @($X, 'run', '--', $ArgvDump)), $Scratch, 100, 30, $null, $null)
            } finally { Remove-Item env:ARGVDUMP_CTRLC; Remove-Item env:ARGVDUMP_EXIT }
            $dl = [DateTime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath ($cf + '.ready')) -and [DateTime]::UtcNow -lt $dl -and -not $pty.HasExited) { Start-Sleep -Milliseconds 20 }
            $ready = Test-Path -LiteralPath ($cf + '.ready')
            $send = $null; $sentTicks = $null
            if ($ready) {
                Start-Sleep -Milliseconds 300
                if ($form -eq 'keystroke') { $sentTicks = [DateTime]::UtcNow.Ticks; $pty.Write([byte[]](0x03)); $send = [pscustomobject]@{ Exit = 0; Line = 'typed ^C into the pseudoconsole input' } }
                else { $send = Send-Ctrl -TargetPid $pty.Pid -Event $(if ($form -eq 'break_event') { 1 } else { 0 }); $sentTicks = $send.Ticks }
            }
            $aliveAfter = $null
            if ($sentTicks) { $waitMs = 600 - [int](([DateTime]::UtcNow.Ticks - $sentTicks) / 10000); if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }; $aliveAfter = -not $pty.HasExited }
            $exited = $pty.WaitExit(15000)
            if (-not $exited) { [void]$pty.Kill() }
            $code = $null; if ($exited) { $code = $pty.ExitCode }
            $childRes = $null; if (Test-Path -LiteralPath $cf) { $childRes = [System.IO.File]::ReadAllText($cf, $Utf8) | ConvertFrom-Json }
            $exitAfterMs = $null; if ($exited -and $sentTicks -and $pty.ExitTicksUtc -gt 0) { $exitAfterMs = [int](($pty.ExitTicksUtc - $sentTicks) / 10000) }
            $obs = [ordered]@{ child_ready = $ready; sender = $(if ($send) { $send.Line } else { $null }); heimdall_alive_600ms_after = $aliveAfter
                child_interrupts = $(if ($childRes) { $childRes.interrupts } else { $null }); heimdall_exit = $code; heimdall_exit_ms_after_event = $exitAfterMs; killed_by_harness = (-not $exited) }
            Save-RowArtifact $c ('ctrlc.run_' + $form) 'pty.txt' (ConvertFrom-Vt ($pty.Snapshot(0)))
            $pty.Dispose()
            $ok = $ready -and $aliveAfter -and $childRes -and $childRes.interrupts -eq 1 -and $code -eq 42
            if ($form -eq 'break_event') {
                Add-Row $c 'ctrlc.run_break_event' (Get-Verdict $ok) $false 'recorded: CTRL_BREAK_EVENT on the console of `run`: child sees it once, heimdall-proto still running 600 ms later and exits with the child''s 42' $obs
            } else {
                Add-Row $c ('ctrlc.run_' + $form) (Get-Verdict $ok) $true ('section 4 (Windows: console Ctrl-C, ' + $(if ($form -eq 'event') { 'GenerateConsoleCtrlEvent from another process attached to the console' } else { '^C typed into the console input' }) + '): the child receives exactly one interrupt, heimdall-proto does not exit first (alive 600 ms later while the child waits 1.5 s) and exits with the child''s code 42') $obs
            }
        }
        foreach ($form in @('event', 'keystroke')) {
            $sp = Start-StallPipe ('hm-x1-cc-' + $c + '-' + $form + '-' + $RunTag)
            $so = Join-Path $Scratch ('agent-cc-' + $c + '-' + $form + '.out'); $se = $so + '.err'
            $pty = [X1Pty]::Start((Get-ArgLine @($X, 'agent', 'list', '--socket', $sp.Path, '--timeout-ms', '30000', '--json')), $Scratch, 250, 30, $(if ($form -eq 'event') { $so } else { $null }), $(if ($form -eq 'event') { $se } else { $null }))
            $dl = [DateTime]::UtcNow.AddSeconds(15)
            while ((Get-StallConnects $sp) -lt 1 -and [DateTime]::UtcNow -lt $dl -and -not $pty.HasExited) { Start-Sleep -Milliseconds 20 }
            $connected = (Get-StallConnects $sp) -ge 1
            Start-Sleep -Milliseconds 300
            $sentTicks = $null; $sendLine = $null
            if ($connected) {
                if ($form -eq 'keystroke') { $sentTicks = [DateTime]::UtcNow.Ticks; $pty.Write([byte[]](0x03)); $sendLine = 'typed ^C' }
                else { $s = Send-Ctrl -TargetPid $pty.Pid -Event 0; $sentTicks = $s.Ticks; $sendLine = $s.Line } }
            $exited = $pty.WaitExit(10000); if (-not $exited) { [void]$pty.Kill() }
            $code = $null; if ($exited) { $code = $pty.ExitCode }
            $ms = $null; if ($exited -and $sentTicks -and $pty.ExitTicksUtc -gt 0) { $ms = [int](($pty.ExitTicksUtc - $sentTicks) / 10000) }
            Start-Sleep -Milliseconds 200
            $outText = $null
            if ($form -eq 'event') { if (Test-Path -LiteralPath $so) { $outText = [System.IO.File]::ReadAllText($so, $Utf8) } }
            else { $outText = ConvertFrom-Vt ($pty.Snapshot(0)) }
            $pty.Dispose()
            [void](Stop-G03Owned -Owned $sp.Owned)
            $state = $null; $cc = $null
            if ($outText) { $m = [regex]::Match($outText, '\{.*\}'); if ($m.Success) { try { $d = $m.Value | ConvertFrom-Json; $state = $d.state; $cc = $d.code } catch { } } }
            $obs = [ordered]@{ connected = $connected; sender = $sendLine; exit = $code; exit_ms_after_event = $ms; json_state = $state; json_code = $cc; killed_by_harness = (-not $exited)
                stdout_source = $(if ($form -eq 'event') { 'file (STARTF_USESTDHANDLES)' } else { 'pseudoconsole output, VT stripped' }) }
            Save-RowArtifact $c ('ctrlc.agent_list_' + $form) 'stdout.txt' $outText
            Add-Row $c ('ctrlc.agent_list_' + $form) (Get-Verdict ($connected -and $code -eq 130 -and $null -ne $ms -and $ms -le 500 -and $state -ceq 'cancelled' -and $cc -ceq 'CANCELLED')) $true ('section 3: console Ctrl-C (' + $form + ') while waiting for the agent -> exit 130, {"state":"cancelled","code":"CANCELLED"} on stdout, within 500 ms') $obs
        }
    }

    # ================================================================== tui
    if ($Sections -contains 'tui') {
        $hl = Join-Path $FixDir 'homelab.toml'
        $r = Invoke-X1 $X @('tui', '--file', $hl) -TimeoutMs 10000
        Add-Row $c 'tui.no_tty_usage_error' (Get-Verdict ($r.Exit -eq 2 -and $r.Out.Length -eq 0)) $true 'section 5: stdin/stdout are pipes (no console) -> exit 2, stdout empty' ([ordered]@{ exit = $r.Exit; stderr = $r.ErrText; timed_out = $r.TimedOut })
        function Start-Tui { param([string]$File, [int16]$Cols = 80, [int16]$Rows = 24, [hashtable]$Env = @{})
            foreach ($k in $Env.Keys) { Set-Item -Path ("env:" + $k) -Value $Env[$k] }
            try { $p = [X1Pty]::Start((Get-ArgLine @($X, 'tui', '--file', $File)), $Scratch, $Cols, $Rows, $null, $null) }
            finally { foreach ($k in $Env.Keys) { Remove-Item -Path ("env:" + $k) -ErrorAction SilentlyContinue } }
            return $p }
        # Wait until the screen model (what a terminal would show) satisfies $Pred.
        function Wait-Screen { param($P, [scriptblock]$Pred, [int]$Ms = 5000)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                $txt = $P.ScreenText()
                if (& $Pred $txt) { return [pscustomobject]@{ Ok = $true; Ms = $sw.ElapsedMilliseconds; Text = $txt } }
                if ($sw.ElapsedMilliseconds -ge $Ms -or $P.HasExited) {
                    Start-Sleep -Milliseconds 50; $txt = $P.ScreenText()
                    return [pscustomobject]@{ Ok = [bool](& $Pred $txt); Ms = $sw.ElapsedMilliseconds; Text = $txt } }
                Start-Sleep -Milliseconds 3 } }
        function Send-Keys { param($P, $Bytes) $P.Write([byte[]]$Bytes) }
        function Close-Tui { param($P, [string]$Id)
            $ex = $P.WaitExit(5000); if (-not $ex) { [void]$P.Kill(); [void]$P.WaitExit(3000) }
            Start-Sleep -Milliseconds 300
            $txt = $P.ScreenText()
            $raw = $P.Snapshot(0)
            $res = [pscustomobject]@{ Exited = $ex; Exit = $(if ($ex) { $P.ExitCode } else { $null }); Screen = $txt
                Restored = (-not $P.Screen.AltActive) -and $P.Screen.CursorVisible; AltEnter = $P.Screen.AltEnterCount; AltLeave = $P.Screen.AltLeaveCount
                Selected = [regex]::Matches($txt, '(?m)^SELECTED (.*)$') | ForEach-Object { $_.Groups[1].Value } }
            Save-RowArtifact $c $Id 'pty-raw-escaped.txt' (($Utf8.GetString($raw)) -replace [char]27, '\e')
            Save-RowArtifact $c $Id 'final-screen.txt' $txt
            $P.Dispose()
            return $res }
        $K = @{ j = [byte[]](0x6a); k = [byte[]](0x6b); q = [byte[]](0x71); slash = [byte[]](0x2f); enter = [byte[]](0x0d); esc = [byte[]](0x1b); down = [byte[]](0x1b, 0x5b, 0x42); ctrlc = [byte[]](0x03) }
        # 1 navigation + filter + select
        $p = Start-Tui $hl
        $w0 = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server  aman@lab\.example\.internal:22' -and $t -match '(?m)^  nas  admin@nas\.example\.internal:22' -and $t -match '(?m)^3/3' } 8000
        $st = [ordered]@{ first_frame = $w0.Ok; first_frame_ms = $w0.Ms; alt_screen_entered = $p.Screen.AltActive }
        Send-Keys $p $K.j; $w = Wait-Screen $p { param($t) $t -match '(?m)^> nas' -and $t -match '(?m)^  lab-server' } 3000; $st['j_moves_to_nas'] = $w.Ok
        Send-Keys $p $K.k; $w = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server' } 3000; $st['k_moves_back'] = $w.Ok
        Send-Keys $p $K.down; $w = Wait-Screen $p { param($t) $t -match '(?m)^> nas' } 3000; $st['down_arrow_moves'] = $w.Ok
        Send-Keys $p $K.slash; Start-Sleep -Milliseconds 100
        Send-Keys $p ($Utf8.GetBytes([string][char]0x6771 + [char]0x4EAC))
        $w = Wait-Screen $p { param($t) $t -match '(?m)^1/3' -and $t -match ('(?m)^> vps-' + [char]0x6771 + [char]0x4EAC) -and -not ($t -match 'lab-server') } 3000; $st['unicode_filter_1_of_3'] = $w.Ok; $st['unicode_filter_ms'] = $w.Ms
        Send-Keys $p $K.esc; $w = Wait-Screen $p { param($t) $t -match '(?m)^3/3' -and $t -match '(?m)^> lab-server' } 3000; $st['esc_clears_filter_selection_first'] = $w.Ok
        Send-Keys $p $K.slash; Start-Sleep -Milliseconds 100; Send-Keys $p ([byte[]][char[]]'NAS')
        $w = Wait-Screen $p { param($t) $t -match '(?m)^1/3' -and $t -match '(?m)^> nas' } 3000; $st['filter_case_insensitive_1_of_3'] = $w.Ok
        Send-Keys $p $K.enter; Start-Sleep -Milliseconds 200; $t1 = $p.ScreenText(); $st['enter_keeps_filter'] = ($t1 -match '(?m)^1/3') -and ($t1 -match '(?m)^> nas')
        Send-Keys $p $K.enter
        $res = Close-Tui $p 'tui.select'
        $st['exit'] = $res.Exit; $st['selected'] = @($res.Selected); $st['terminal_restored'] = $res.Restored; $st['alt_enter_leave'] = @($res.AltEnter, $res.AltLeave)
        $ok = $w0.Ok -and $st.j_moves_to_nas -and $st.k_moves_back -and $st.down_arrow_moves -and $st.unicode_filter_1_of_3 -and $st.esc_clears_filter_selection_first -and $st.filter_case_insensitive_1_of_3 -and $st.enter_keeps_filter -and $res.Exit -eq 0 -and (@($res.Selected) -join '|') -ceq 'nas' -and $res.Restored
        Add-Row $c 'tui.navigate_filter_select' (Get-Verdict $ok) $true 'section 5 on an 80x24 pseudoconsole (screen model): rows "alias  account@host:port", "> " marks the selection, n/total status; j/k/Down move; / with non-ASCII input filters to 1/3 with the selection on the first shown row (K9); Esc clears (3/3); case-insensitive filter NAS -> 1/3; Enter keeps the filter; Enter selects -> "SELECTED nas", exit 0, alternate screen left and cursor shown' $st
        # K14 analog for tui --file: a named pipe that never answers and the NUL device, on a pseudoconsole
        foreach ($nr in @(@('tui.named_pipe_as_file', 'pipe'), @('tui.nul_device_as_file', 'NUL'))) {
            $sp = $null; $target = 'NUL'
            if ($nr[1] -eq 'pipe') { $sp = Start-StallPipe ('hm-x1-tuifile-' + $c + '-' + $RunTag); $target = $sp.Path }
            $p = Start-Tui $target
            $ex = $p.WaitExit(10000); if (-not $ex) { [void]$p.Kill(); [void]$p.WaitExit(3000) }
            $ms = $null; if ($ex -and $p.ExitTicksUtc -gt 0) { $ms = [int](($p.ExitTicksUtc - $p.StartedUtc.Ticks) / 10000) }
            $code = $null; if ($ex) { $code = $p.ExitCode }
            Start-Sleep -Milliseconds 200; [void]$p.ScreenText(); $restored = (-not $p.Screen.AltActive)
            $p.Dispose()
            $conn = $null; if ($sp) { $conn = Get-StallConnects $sp; [void](Stop-G03Owned -Owned $sp.Owned) }
            Add-Row $c $nr[0] (Get-Verdict ($ex -and $code -eq 2 -and $null -ne $ms -and $ms -lt 2000 -and $restored)) $true ('K14 analog (tests/g02 tui.non_regular_file): tui --file ' + $(if ($nr[1] -eq 'pipe') { 'naming a named pipe that never answers' } else { 'NUL' }) + ' on a pseudoconsole -> exit 2 within 2 s, never blocking, alternate screen not left active') ([ordered]@{ exit = $code; ms_from_start = $ms; killed_by_harness = (-not $ex); pipe_connects = $conn; alt_screen_active_after = (-not $restored) })
        }
        # 2 quit
        $p = Start-Tui $hl; $w0 = Wait-Screen $p { param($t) $t -match '(?m)^3/3' } 8000
        Send-Keys $p $K.q; $res = Close-Tui $p 'tui.quit'
        Add-Row $c 'tui.quit' (Get-Verdict ($w0.Ok -and $res.Exit -eq 0 -and @($res.Selected).Count -eq 0 -and $res.Restored)) $true 'section 5: q -> exit 0, no SELECTED, terminal restored' ([ordered]@{ started = $w0.Ok; exit = $res.Exit; restored = $res.Restored })
        # 3 ^C key (raw-mode console input), plus in filter mode
        foreach ($v in @(@('tui.ctrl_c_key', $false), @('tui.ctrl_c_key_in_filter_mode', $true))) {
            $p = Start-Tui $hl; $w0 = Wait-Screen $p { param($t) $t -match '(?m)^3/3' } 8000
            if ($v[1]) { Send-Keys $p $K.slash; Send-Keys $p ([byte[]][char[]]'la'); [void](Wait-Screen $p { param($t) $t -match '(?m)^1/3' } 3000) }
            Send-Keys $p $K.ctrlc; $res = Close-Tui $p $v[0]
            Add-Row $c $v[0] (Get-Verdict ($w0.Ok -and $res.Exit -eq 130 -and @($res.Selected).Count -eq 0 -and $res.Restored)) $true ('section 5: ^C typed into the console' + $(if ($v[1]) { ' while typing a filter' } else { '' }) + ' -> exit 130, no SELECTED, terminal restored') ([ordered]@{ started = $w0.Ok; exit = $res.Exit; restored = $res.Restored })
        }
        # 4 console Ctrl-C event raised by another process (Windows analog of an explicit SIGINT; the Unix harness gates the key only)
        $p = Start-Tui $hl; $w0 = Wait-Screen $p { param($t) $t -match '(?m)^3/3' } 8000
        $s = Send-Ctrl -TargetPid $p.Pid -Event 0
        $res = Close-Tui $p 'tui.ctrl_c_event'
        Add-Row $c 'tui.ctrl_c_event' (Get-Verdict ($w0.Ok -and $res.Exit -eq 130 -and $res.Restored)) $false 'recorded (Windows analog of an explicit SIGINT; tests/g02 gates the Ctrl-C key only): CTRL_C_EVENT raised on the TUI console by another process -> exit 130 with the terminal restored' ([ordered]@{ started = $w0.Ok; sender = $s.Line; exit = $res.Exit; restored = $res.Restored; alt_screen_still_active = (-not $res.Restored); killed_by_harness = (-not $res.Exited) })
        # 5 resize
        $p = Start-Tui $hl; $w0 = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server  aman@lab\.example\.internal:22' } 8000
        $sw = [Diagnostics.Stopwatch]::StartNew(); $hr = $p.Resize(40, 12)
        $w = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server\s*$' -and $t -match '(?m)^  nas\s*$' -and -not ($t -match '@') } 3000
        $hr2 = $p.Resize(20, 5); Start-Sleep -Milliseconds 1000
        $tiny = $p.ScreenText(); $alive = -not $p.HasExited
        $hr3 = $p.Resize(80, 24)
        $w3 = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server  aman@lab\.example\.internal:22' } 3000
        Send-Keys $p $K.q; $res = Close-Tui $p 'tui.resize'
        Save-RowArtifact $c 'tui.resize' 'screen-20x5.txt' $tiny
        $obs = [ordered]@{ wide_frame = $w0.Ok; resize_hresults = @($hr, $hr2, $hr3); narrow_alias_only = $w.Ok; narrow_ms = $w.Ms; alive_after_20x5 = $alive; wide_again = $w3.Ok; exit = $res.Exit; restored = $res.Restored }
        Add-Row $c 'tui.resize' (Get-Verdict ($w0.Ok -and $w.Ok -and $alive -and $w3.Ok -and $res.Exit -eq 0 -and $res.Restored)) $true 'section 5: console resize to 40x12 re-lays out (alias only), 20x5 does not crash, back to 80x24 shows account@host:port; q exits 0, terminal restored' $obs
        Add-Row $c 'tui.resize_latency' (Get-Verdict ($w.Ok -and $w.Ms -le 100)) $false 'recorded: narrow layout on the screen model within 100 ms of ResizePseudoConsole (includes conhost re-rendering and 3 ms polling)' ([ordered]@{ ms = $w.Ms })
        # 6 NO_COLOR
        $p = Start-Tui $hl -Env @{ 'NO_COLOR' = '1' }; $w0 = Wait-Screen $p { param($t) $t -match '(?m)^> lab-server' } 8000
        Send-Keys $p $K.j; [void](Wait-Screen $p { param($t) $t -match '(?m)^> nas' } 3000)
        Send-Keys $p $K.q; $rawS = $Utf8.GetString($p.Snapshot(0)); $res = Close-Tui $p 'tui.no_color'
        $sgr = @([regex]::Matches($rawS, [char]27 + '\[([0-9;:]*)m') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match '(^|;)(3[0-7]|38|4[0-7]|48|9[0-7]|10[0-7])([;:]|$)' })
        Add-Row $c 'tui.no_color' (Get-Verdict ($w0.Ok -and $sgr.Count -eq 0 -and $res.Exit -eq 0)) $true 'section 5: NO_COLOR=1 -> no color SGR in the pseudoconsole output (conhost re-encodes what the application drew); selection still marked by "> "' ([ordered]@{ started = $w0.Ok; color_sgr_found = @($sgr | Select-Object -First 10); exit = $res.Exit })
        # 7 large-100
        $p = Start-Tui (Join-Path $FixDir 'large-100.toml'); $w0 = Wait-Screen $p { param($t) $t -match '(?m)^100/100' } 8000
        Send-Keys $p $K.slash; Send-Keys $p ([byte[]][char[]]'zzz-no-match')
        $w = Wait-Screen $p { param($t) $t -match '(?m)^0/100' } 3000
        Send-Keys $p $K.esc; [void](Wait-Screen $p { param($t) $t -match '(?m)^100/100' } 3000); Send-Keys $p $K.q; $res = Close-Tui $p 'tui.large_100'
        Add-Row $c 'tui.large_100' (Get-Verdict ($w0.Ok -and $w.Ok -and $res.Exit -eq 0)) $true 'section 5: 100-destination fixture shows 100/100; a filter matching nothing shows 0/100; q exits 0' ([ordered]@{ started = $w0.Ok; first_frame_ms = $w0.Ms; filter_0_of_100 = $w.Ok; filter_ms = $w.Ms; exit = $res.Exit })
    }
}
} catch {
    Add-Row 'host' 'harness.error' 'inconclusive' $true 'the script itself must not fail' ([ordered]@{ error = ($_.Exception.Message); at = ($_.InvocationInfo.PositionMessage) })
} finally {
    foreach ($o in @($Owned)) { [void](Stop-G03Owned -Owned $o) }
}

# ------------------------------------------------------------------ write results
# Canary rule: count before redaction (Protect-X1), so a leak is reported even though nothing written contains it.
Add-Row 'host' 'harness.canary_scan' (Get-Verdict ($script:CanaryHits -eq 0)) $true 'canary rule: no HEIMDALL_CANARY_ value (fixture canary or the per-run environment canary given to every child) appeared in any captured output or row before redaction' ([ordered]@{ hits_before_redaction = $script:CanaryHits })
$summary = [ordered]@{}
foreach ($c in @($Candidates + 'host')) {
    $rs = @($Rows | Where-Object { $_.candidate -eq $c })
    $summary[$c] = [ordered]@{ rows = $rs.Count; gating = @($rs | Where-Object { $_.gating }).Count
        gating_pass = @($rs | Where-Object { $_.gating -and $_.verdict -eq 'pass' }).Count
        gating_not_pass = @($rs | Where-Object { $_.gating -and $_.verdict -ne 'pass' } | ForEach-Object { $_.id }) }
}
$doc = [ordered]@{ script = 'tests/native/windows-g02/Invoke-G02WindowsX1.ps1'; powershell = $PSVersionTable.PSVersion.ToString(); finished_at = [DateTime]::UtcNow.ToString('o')
    summary = $summary; rows = @($Rows) }
$json = $doc | ConvertTo-Json -Depth 12
$json = Protect-X1 $json
[System.IO.File]::WriteAllText((Join-Path $OutDir 'results.json'), $json + "`n", $Utf8)
# canary self-check over everything written
$leak = @(Get-ChildItem -LiteralPath $OutDir -Recurse -File | Where-Object { ([System.IO.File]::ReadAllText($_.FullName)).Contains([string]$Canary) -or ([System.IO.File]::ReadAllText($_.FullName)).Contains([string]$G03Ctx.Canary) })
if ($leak.Count -gt 0) { [Console]::Out.WriteLine('CANARY LEAK in ' + $leak.Count + ' files'); exit 3 }
$bad = @($Rows | Where-Object { $_.gating -and $_.verdict -ne 'pass' }).Count
[Console]::Out.WriteLine(('rows={0} gating_not_pass={1}' -f $Rows.Count, $bad))
if ($bad -gt 0) { exit 1 } else { exit 0 }
