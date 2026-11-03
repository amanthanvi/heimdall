<#
.SYNOPSIS
  M02-U8 native Windows drivers for `heimdall run` on a pseudoconsole: console Ctrl-C reaches the child once, and
  a pseudoconsole resize reaches the child (m02-plan U8 `a27_ctrl_c_reaches_child_once`, `a27_resize_reaches_child`;
  ADR-0007 §8 "Windows run spawns the child and waits").
.DESCRIPTION
  Test harness, not product code. Reuses the G02 round-4 approach (tests/native/windows-g02): `G02X1Native.cs`
  (X1Pty: CreatePseudoConsole with the process attached, no window; ResizePseudoConsole) and
  `Send-ConsoleCtrl.ps1` (a separate process: AttachConsole + GenerateConsoleCtrlEvent).

  Every heimdall process runs with a scratch HEIMDALL_HOME and the debug build's env-gated test configuration
  (HEIMDALL_TEST_ADAPTER=prepare, HEIMDALL_TEST_TIME_SYNC=synchronized), so `run --profile ops` needs no owner
  decision and contacts no agent. The runtime it starts on demand is stopped with `heimdall service stop` on that
  scratch home. Nothing reads the owner's SSH, Git or agent material; the scratch directory is created here and
  removed (exactly that directory) at the end.

  Cases (each a row in the JSON report):
    ctrlc.event      CTRL_C_EVENT raised on the pseudoconsole by another process: argvdump (the child) counts
                     exactly one interrupt; heimdall is still running 600 ms later (its console control guard
                     consumed the event) and exits with the child's code 42.
    ctrlc.keystroke  ^C typed into the pseudoconsole input: the same.
    ctrlc.break      CTRL_BREAK_EVENT (recorded, not gating): the same.
    resize           ResizePseudoConsole from 100x30 to 132x40 while the child (powershell) polls its console
                     window size: the child sees the new size and exits 0, and heimdall exits 0.

  Not covered (blocked inputs, m02-plan §7 B5 / P-W07): an interactive conhost window or Windows Terminal, where an
  operator presses Ctrl-C or resizes the window.
.PARAMETER Heimdall
  The debug-build heimdall.exe under test (x86_64-pc-windows-gnu).
.PARAMETER ArgvDump
  argvdump.exe built from tests/native/windows-g02/argvdump (`GOOS=windows GOARCH=amd64 go build`).
.PARAMETER Out
  Report path (JSON). Default: windows-launch-report.json in the current directory (outside the scratch, which is
  removed).
.OUTPUTS
  Exit 0 when every gating row passes, 1 otherwise, 2 for a harness error.
#>
param(
    [Parameter(Mandatory = $true)][string]$Heimdall,
    [Parameter(Mandatory = $true)][string]$ArgvDump,
    [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Here = $PSScriptRoot
$G02 = Join-Path (Split-Path -Parent $Here) 'windows-g02'
$Utf8 = New-Object System.Text.UTF8Encoding($false)
foreach ($p in @($Heimdall, $ArgvDump, (Join-Path $G02 'G02X1Native.cs'), (Join-Path $G02 'Send-ConsoleCtrl.ps1'))) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { [Console]::Error.WriteLine("missing input: $p"); exit 2 }
}
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $G02 'G02X1Native.cs')))

function New-RandomHex { param([int]$Bytes = 6)
    $b = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '') }

# Scratch: created here, removed exactly at the end.
$Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('hm-u8-launch-' + (New-RandomHex))
New-Item -ItemType Directory -Path $Scratch | Out-Null
$HomeDir = Join-Path $Scratch 'h'
$UserHome = Join-Path $Scratch 'u'
New-Item -ItemType Directory -Path $UserHome | Out-Null
[System.IO.File]::WriteAllText((Join-Path $UserHome '.gitconfig'), '', $Utf8)
if (-not $Out) { $Out = Join-Path (Get-Location).Path 'windows-launch-report.json' }

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row { param([string]$Id, [bool]$Ok, [bool]$Gating, [string]$Claim, $Obs)
    $rows.Add([ordered]@{ id = $Id; verdict = $(if ($Ok) { 'pass' } else { 'fail' }); gating = $Gating; claim = $Claim; observed = $Obs }) }

# Quote one argument for CreateProcessW's command line (MSVC rules; the argument never contains a NUL).
function ConvertTo-ArgLine { param([string[]]$Items)
    $parts = foreach ($a in $Items) {
        if ($a -ne '' -and $a -notmatch '[\s"]') { $a; continue }
        $sb = New-Object System.Text.StringBuilder; [void]$sb.Append('"'); $bs = 0
        foreach ($ch in $a.ToCharArray()) {
            if ($ch -eq [char]'\') { $bs++; continue }
            if ($ch -eq [char]'"') { [void]$sb.Append(('\' * ($bs * 2 + 1))); [void]$sb.Append('"'); $bs = 0; continue }
            [void]$sb.Append(('\' * $bs)); $bs = 0; [void]$sb.Append($ch) }
        [void]$sb.Append(('\' * ($bs * 2))); [void]$sb.Append('"'); $sb.ToString() }
    return ($parts -join ' ') }

# The test configuration every heimdall process (and so its on-demand runtime) gets.
$TestEnv = [ordered]@{
    HEIMDALL_HOME = $HomeDir; HEIMDALL_TEST_ADAPTER = 'prepare'; HEIMDALL_TEST_TIME_SYNC = 'synchronized'
    HOME = $UserHome; USERPROFILE = $UserHome; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = (Join-Path $UserHome '.gitconfig')
}
function Invoke-WithEnv { param([hashtable]$Extra, [scriptblock]$Body)
    $saved = @{}
    $all = [ordered]@{}; foreach ($k in $TestEnv.Keys) { $all[$k] = $TestEnv[$k] }; foreach ($k in $Extra.Keys) { $all[$k] = $Extra[$k] }
    foreach ($k in $all.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, [string]$all[$k]) }
    try { & $Body } finally { foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) } } }

function Send-Ctrl { param([int]$TargetPid, [int]$Event)
    $ticks = [DateTime]::UtcNow.Ticks
    $line = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $G02 'Send-ConsoleCtrl.ps1') -TargetPid $TargetPid -Event $Event
    return [pscustomobject]@{ Line = [string]$line; Ticks = $ticks } }

$exitCode = 0
try {
    # ------------------------------------------------------------------ Ctrl-C reaches the child once
    foreach ($form in @('event', 'keystroke', 'break')) {
        $cf = Join-Path $Scratch ('ctrlc-' + $form + '.json')
        $pty = $null
        Invoke-WithEnv @{ ARGVDUMP_CTRLC = $cf; ARGVDUMP_EXIT = '42' } {
            $script:pty = [X1Pty]::Start((ConvertTo-ArgLine @($Heimdall, 'run', '--profile', 'ops', '--', $ArgvDump)), $Scratch, 100, 30, $null, $null)
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath ($cf + '.ready')) -and [DateTime]::UtcNow -lt $deadline -and -not $pty.HasExited) { Start-Sleep -Milliseconds 20 }
        $ready = Test-Path -LiteralPath ($cf + '.ready')
        $sent = $null; $sentTicks = $null
        if ($ready) {
            Start-Sleep -Milliseconds 300
            if ($form -eq 'keystroke') { $sentTicks = [DateTime]::UtcNow.Ticks; $pty.Write([byte[]](0x03)); $sent = 'typed ^C into the pseudoconsole input' }
            else { $s = Send-Ctrl -TargetPid $pty.Pid -Event $(if ($form -eq 'break') { 1 } else { 0 }); $sent = $s.Line; $sentTicks = $s.Ticks }
        }
        $aliveAfter = $null
        if ($sentTicks) { $waitMs = 600 - [int](([DateTime]::UtcNow.Ticks - $sentTicks) / 10000); if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }; $aliveAfter = -not $pty.HasExited }
        $exited = $pty.WaitExit(20000)
        if (-not $exited) { [void]$pty.Kill() }
        $code = $null; if ($exited) { $code = $pty.ExitCode }
        $child = $null; if (Test-Path -LiteralPath $cf) { $child = [System.IO.File]::ReadAllText($cf, $Utf8) | ConvertFrom-Json }
        $pty.Dispose()
        $interrupts = $(if ($child) { $child.interrupts } else { $null })
        $ok = $ready -and $aliveAfter -and $interrupts -eq 1 -and $code -eq 42
        Add-Row ('ctrlc.' + $form) $ok ($form -ne 'break') ('a27_ctrl_c_reaches_child_once (' + $form + '): the child counts exactly one interrupt, heimdall is alive 600 ms later and exits with the child''s 42') ([ordered]@{
            child_ready = $ready; sender = $sent; heimdall_alive_600ms_after = $aliveAfter; child_interrupts = $interrupts; heimdall_exit = $code; killed_by_harness = (-not $exited) })
    }

    # ------------------------------------------------------------------ resize reaches the child
    $rf = Join-Path $Scratch 'resize.txt'
    $childScript = "`$o='$rf'; [IO.File]::WriteAllText(`$o + '.ready', 'r'); `$w0=[Console]::WindowWidth; `$h0=[Console]::WindowHeight; " +
        "`$d=[DateTime]::UtcNow.AddSeconds(20); while ([DateTime]::UtcNow -lt `$d) { `$w=[Console]::WindowWidth; `$h=[Console]::WindowHeight; " +
        "if (`$w -ne `$w0 -or `$h -ne `$h0) { [IO.File]::WriteAllText(`$o, ('' + `$w0 + 'x' + `$h0 + ' ' + `$w + 'x' + `$h)); exit 0 }; Start-Sleep -Milliseconds 20 }; exit 9"
    $pty = $null
    Invoke-WithEnv @{} {
        $script:pty = [X1Pty]::Start((ConvertTo-ArgLine @($Heimdall, 'run', '--profile', 'ops', '--', 'powershell.exe', '-NoProfile', '-NonInteractive', '-Command', $childScript)), $Scratch, 100, 30, $null, $null)
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath ($rf + '.ready')) -and [DateTime]::UtcNow -lt $deadline -and -not $pty.HasExited) { Start-Sleep -Milliseconds 20 }
    $ready = Test-Path -LiteralPath ($rf + '.ready')
    $hr = $null; if ($ready) { Start-Sleep -Milliseconds 200; $hr = $pty.Resize(132, 40) }
    $exited = $pty.WaitExit(20000)
    if (-not $exited) { [void]$pty.Kill() }
    $code = $null; if ($exited) { $code = $pty.ExitCode }
    $seen = $null; if (Test-Path -LiteralPath $rf) { $seen = [System.IO.File]::ReadAllText($rf, $Utf8).Trim() }
    $pty.Dispose()
    $ok = $ready -and $hr -eq 0 -and $seen -eq '100x30 132x40' -and $code -eq 0
    Add-Row 'resize' $ok $true 'a27_resize_reaches_child: ResizePseudoConsole 100x30 -> 132x40 reaches the child through heimdall run, which exits with the child''s 0' ([ordered]@{
        child_ready = $ready; resize_hr = $hr; child_saw = $seen; heimdall_exit = $code; killed_by_harness = (-not $exited) })
} catch {
    [Console]::Error.WriteLine('harness error: ' + $_.Exception.Message)
    $exitCode = 2
} finally {
    # Stop the runtime this harness started (its own scratch home; the runtime validates its own advertisement).
    try { Invoke-WithEnv @{} { & $Heimdall service stop | Out-Null } } catch { }
}

$report = [ordered]@{ suite = 'm02-u8-windows-launch'; heimdall = $Heimdall; rows = $rows }
$json = $report | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($Out, $json, $Utf8)
[Console]::Out.WriteLine($json)
if ($exitCode -eq 0) {
    foreach ($r in $rows) { if ($r.gating -and $r.verdict -ne 'pass') { $exitCode = 1 } }
}
Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
exit $exitCode
