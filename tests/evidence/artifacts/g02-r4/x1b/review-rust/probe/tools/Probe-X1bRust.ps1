<#
  Review probes beyond Invoke-G02WindowsX1.ps1 (M00-T05-x1b-review-rust; harness code, not product code).
  Windows PowerShell 5.1. Non-elevated. All files under -Base; pipes are named hm-M00-T05-x1b-review-rust-*;
  only processes started here are stopped, through their own Process objects.
  Output: <Base>\out\probe\results.jsonl (one JSON object per case, redacted).
#>
param([Parameter(Mandatory = $true)][string]$Base, [string]$Only = '')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'elevated; refusing'; exit 2 }
$TID = 'M00-T05-x1b-review-rust'
$Root = Join-Path $Base 'root'
$Exe = Join-Path $Root 'bin\rust\heimdall-proto.exe'
$Fix = Join-Path $Root 'fixtures\profiles'
$ArgvDump = Join-Path $Root 'helpers\argvdump.exe'
$PB = Join-Path $Base 'pb'
if (Test-Path -LiteralPath $PB) {
    foreach ($n in @('dot.bat.', 'spc.bat ')) { $q = '\\?\' + (Join-Path (Join-Path $PB 'batnospace') $n); if ([IO.File]::Exists($q)) { [IO.File]::Delete($q) } }
    Remove-Item -LiteralPath $PB -Recurse -Force }
New-Item -ItemType Directory -Path $PB | Out-Null
$Out = Join-Path $Base 'out\probe'; New-Item -ItemType Directory -Force -Path $Out | Out-Null
$RepDir = Join-Path $Base 'reps'; New-Item -ItemType Directory -Force -Path $RepDir | Out-Null
$ResFile = Join-Path $Out 'results.jsonl'; [IO.File]::WriteAllText($ResFile, '')
$Utf8 = New-Object Text.UTF8Encoding($false)
$CanaryPrefix = 'HEIMDALL_' + 'CANARY_'
$NoAgent = '\\.\pipe\hm-' + $TID + '-none'
$Started = New-Object System.Collections.ArrayList

function Redact([string]$s) {
    if ($null -eq $s) { return $s }
    foreach ($pair in @(@($Base, '<scratch>'), @($env:LOCALAPPDATA, '<winhome>\AppData\Local'), @($env:USERPROFILE, '<winhome>'), @($env:USERNAME, '<winuser>'), @($env:COMPUTERNAME, '<winhost>'))) {
        if ($pair[0]) { $s = $s.Replace($pair[0], $pair[1]) } }
    $i = $s.IndexOf($CanaryPrefix); if ($i -ge 0) { $s = $s.Substring(0, $i) + $CanaryPrefix + '<redacted>' }
    return $s }
function Quote-Arg([string]$a) {
    if ($a.Length -gt 0 -and $a -notmatch '[\s"]') { return $a }
    $sb = New-Object Text.StringBuilder; [void]$sb.Append('"'); $bs = 0
    foreach ($ch in $a.ToCharArray()) {
        if ($ch -eq [char]'\') { $bs++; continue }
        if ($ch -eq [char]'"') { [void]$sb.Append('\' * (2 * $bs + 1)); [void]$sb.Append('"'); $bs = 0; continue }
        if ($bs) { [void]$sb.Append('\' * $bs); $bs = 0 }
        [void]$sb.Append($ch) }
    [void]$sb.Append('\' * (2 * $bs)); [void]$sb.Append('"'); return $sb.ToString() }
function Invoke-P { param([string[]]$Argv, [hashtable]$Env = @{}, [string]$Cwd = $PB, [int]$TimeoutMs = 10000, [string]$Program = $Exe)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Program
    $psi.Arguments = (($Argv | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Cwd
    $psi.EnvironmentVariables['SSH_AUTH_SOCK'] = $NoAgent
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = $Env[$k] }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $mo = New-Object IO.MemoryStream; $me = New-Object IO.MemoryStream
    $t1 = $p.StandardOutput.BaseStream.CopyToAsync($mo); $t2 = $p.StandardError.BaseStream.CopyToAsync($me)
    $exited = $p.WaitForExit($TimeoutMs)
    $el = $sw.ElapsedMilliseconds
    if (-not $exited) { try { $p.Kill() } catch { }; [void]$p.WaitForExit(5000) }
    try { [void][Threading.Tasks.Task]::WaitAll(@($t1, $t2), 3000) } catch { }
    $code = $null; if ($exited) { $code = $p.ExitCode }
    $so = $Utf8.GetString($mo.ToArray()); $se = $Utf8.GetString($me.ToArray())
    $j = $null; try { if ($so.Trim()) { $j = $so | ConvertFrom-Json } } catch { }
    $p.Dispose()
    return [pscustomobject]@{ Exit = $code; TimedOut = (-not $exited); Ms = $el; Out = $so; Err = $se; Json = $j } }
function Add-Res { param([string]$Case, [string]$Verdict, [hashtable]$Obs)
    $o = [ordered]@{ case = $Case; verdict = $Verdict }
    foreach ($k in ($Obs.Keys | Sort-Object)) { $v = $Obs[$k]; if ($v -is [string]) { $v = Redact $v }; $o[$k] = $v }
    $line = ($o | ConvertTo-Json -Compress -Depth 6)
    [IO.File]::AppendAllText($ResFile, $line + "`n", $Utf8)
    Write-Host ('{0,-6} {1}' -f $Verdict, $Case) }
function Want([string]$c) { return (-not $Only) -or ($Only.Split(',') -contains $c.Split('.')[0]) }
function Start-Helper { param([string]$Script, [string[]]$A)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + (Quote-Arg $Script) + ' ' + (($A | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi); [void]$Started.Add($p); return $p }
function Wait-File([string]$f, [int]$ms = 20000) { $sw = [Diagnostics.Stopwatch]::StartNew(); while (-not (Test-Path -LiteralPath $f) -and $sw.ElapsedMilliseconds -lt $ms) { Start-Sleep -Milliseconds 50 }; return (Test-Path -LiteralPath $f) }
function Stop-Helper($p, [string]$stop) {
    if ($stop) { [IO.File]::WriteAllText($stop, 'stop') }
    if (-not $p.WaitForExit(8000)) { try { $p.Kill() } catch { }; [void]$p.WaitForExit(3000) } }
function FileState([string]$f) {
    $i = Get-Item -LiteralPath $f -Force
    $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    return ('{0}|{1}|{2}|{3}' -f $h, $i.Length, $i.LastWriteTimeUtc.Ticks, [int]$i.Attributes) }

# ------------------------------------------------------------------ profile --file (K14, section 9.6)
$homelab = Join-Path $Fix 'homelab.toml'
$d1 = Join-Path $PB 'pdir'; New-Item -ItemType Directory -Path $d1 | Out-Null
$hcopy = Join-Path $PB 'homelab copy.toml'; Copy-Item -LiteralPath $homelab -Destination $hcopy
$ads = $hcopy + ':hmads'; Set-Content -LiteralPath $hcopy -Stream hmads -Value ([IO.File]::ReadAllText($homelab)) -Encoding Ascii
$junc = Join-Path $PB 'pjunc'
$jr = & cmd.exe /d /c mklink /J "$junc" "$d1" 2>&1; $juncOk = Test-Path -LiteralPath $junc
function Profile-Case { param([string]$Case, [string]$Path, [string]$Expect, [string]$Cwd = $PB)
    $r = Invoke-P -Argv @('profile', 'show', '--json', '--file', $Path) -Cwd $Cwd -TimeoutMs 6000
    $code = $null; if ($r.Json) { $code = $r.Json.code }
    $ok = $false
    if ($Expect -eq 'usage') { $ok = (-not $r.TimedOut) -and $r.Exit -eq 2 -and $code -eq 'USAGE_ERROR' -and $r.Ms -lt 2000 }
    elseif ($Expect -eq 'ok') { $ok = $r.Exit -eq 0 -and $code -eq 'PROFILE_OK' }
    $msg = $null; if ($r.Json -and $r.Json.data -and $r.Json.data.PSObject.Properties['error']) { $msg = $r.Json.data.error.message }
    $v = 'FAIL'; if ($ok) { $v = 'PASS' } elseif ($Expect -eq 'record') { $v = 'INFO' }
    Add-Res $Case $v @{ path = $Path; expect = $Expect; exit = $r.Exit; code = $code; ms = $r.Ms; timed_out = $r.TimedOut; message = $msg; canary = ($r.Out + $r.Err).Contains($CanaryPrefix) } }
if (Want 'profile') {
    Profile-Case 'profile.dir' $d1 'usage'
    Profile-Case 'profile.dir_trailing_backslash' ($d1 + '\') 'usage'
    Profile-Case 'profile.dir_verbatim' ('\\?\' + $d1) 'usage'
    Profile-Case 'profile.nul_upper' 'NUL' 'usage'
    Profile-Case 'profile.nul_lower' 'nul' 'usage'
    Profile-Case 'profile.nul_in_dir' (Join-Path $PB 'NUL') 'usage'
    Profile-Case 'profile.nul_dotted_ext' 'NUL.txt' 'usage'
    Profile-Case 'profile.nul_dos_device' '\\.\NUL' 'usage'
    Profile-Case 'profile.nul_verbatim' '\\?\NUL' 'usage'
    Profile-Case 'profile.con' 'CON' 'usage'
    Profile-Case 'profile.conin' 'CONIN$' 'usage'
    Profile-Case 'profile.conout' 'CONOUT$' 'usage'
    Profile-Case 'profile.con_dos_device' '\\.\CON' 'usage'
    Profile-Case 'profile.empty_path' '' 'usage'
    Profile-Case 'profile.pipe_root' '\\.\pipe\' 'usage'
    Profile-Case 'profile.missing_pipe' ('\\.\pipe\hm-' + $TID + '-absent') 'usage'
    if ($juncOk) { Profile-Case 'profile.junction_to_dir' $junc 'usage' } else { Add-Res 'profile.junction_to_dir' 'BLOCKED' @{ mklink = ($jr | Out-String) } }
    # regressions: disk files in other spellings still load
    Profile-Case 'profile.regular_verbatim' ('\\?\' + $hcopy) 'ok'
    Profile-Case 'profile.regular_ads' $ads 'ok'
    Profile-Case 'profile.regular_data_stream' ($hcopy + '::$DATA') 'ok'
    Profile-Case 'profile.regular_relative' '.\homelab copy.toml' 'ok'
    # a file held open without read sharing / with a byte-range lock by another handle (this process)
    $lk = Join-Path $PB 'locked.toml'; Copy-Item -LiteralPath $homelab -Destination $lk
    $fs = New-Object IO.FileStream($lk, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    Profile-Case 'profile.share_none_locked' $lk 'usage'
    $fs.Dispose()
    $fs = New-Object IO.FileStream($lk, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $fs.Lock(0, $fs.Length)
    Profile-Case 'profile.byte_range_locked' $lk 'record'
    $fs.Unlock(0, $fs.Length); $fs.Dispose()
    # pipes served by another process of the same user
    $sp = Join-Path $Root 'tools\StallPipe.ps1'
    $pn = 'hm-' + $TID + '-stall'
    $mk = Join-Path $PB 'stall.marker'; $rd = Join-Path $PB 'stall.ready'; $st = Join-Path $PB 'stall.stop'
    $h = Start-Helper $sp @('-PipeName', $pn, '-MarkerFile', $mk, '-ReadyFile', $rd, '-StopFile', $st, '-RunSeconds', '90')
    if (Wait-File $rd) {
        Profile-Case 'profile.pipe_never_writes' ('\\.\pipe\' + $pn) 'usage'
        Profile-Case 'profile.pipe_never_writes_verbatim' ('\\?\pipe\' + $pn) 'usage'
        Profile-Case 'profile.pipe_never_writes_lowercase_prefix' ('\\.\PIPE\' + $pn) 'usage'
        Stop-Helper $h $st
        $conn = @(); if (Test-Path -LiteralPath $mk) { $conn = @([IO.File]::ReadAllLines($mk) | ForEach-Object { ($_ -split ' ')[0] }) }
        Add-Res 'profile.pipe_server_saw_connections' 'INFO' @{ note = 'recorded: opening a pipe path as --file connects to the server before the type check (a connection, no bytes)'; connections = $conn.Count; kinds = $conn }
    } else { Add-Res 'profile.pipe_never_writes' 'BLOCKED' @{ note = 'stall pipe helper did not become ready' }; Stop-Helper $h $st }
    # outbound-only pipe (client can only read): open for read succeeds
    $pn2 = 'hm-' + $TID + '-outb'; $mk2 = Join-Path $PB 'outb.marker'; $rd2 = Join-Path $PB 'outb.ready'; $st2 = Join-Path $PB 'outb.stop'
    $h2 = Start-Helper (Join-Path $Base 'probe\ProbePipe.ps1') @('-PipeName', $pn2, '-Mode', 'outbound', '-MarkerFile', $mk2, '-ReadyFile', $rd2, '-StopFile', $st2)
    if (Wait-File $rd2) { Profile-Case 'profile.pipe_outbound_only' ('\\.\pipe\' + $pn2) 'usage'
        # instance now held by the helper: a second open sees ERROR_PIPE_BUSY
        Start-Sleep -Milliseconds 300
        Profile-Case 'profile.pipe_busy' ('\\.\pipe\' + $pn2) 'usage' } else { Add-Res 'profile.pipe_outbound_only' 'BLOCKED' @{} }
    Stop-Helper $h2 $st2
}

# ------------------------------------------------------------------ agent list --socket on non-endpoints (section 9.6)
function Socket-Case { param([string]$Case, [string]$Path, [string]$Watch, [string]$MustNotExist)
    $before = $null; if ($Watch) { $before = FileState $Watch }
    $r = Invoke-P -Argv @('agent', 'list', '--socket', $Path, '--timeout-ms', '2000', '--json') -TimeoutMs 8000
    $code = $null; if ($r.Json) { $code = $r.Json.code }
    $after = $null; if ($Watch) { $after = FileState $Watch }
    $created = $false; if ($MustNotExist) { $created = Test-Path -LiteralPath $MustNotExist }
    $resOk = (($r.Exit -eq 5 -and $code -eq 'AGENT_UNAVAILABLE') -or ($r.Exit -eq 2 -and $code -eq 'USAGE_ERROR'))
    $ok = $resOk -and ($before -eq $after) -and (-not $created) -and (-not $r.TimedOut)
    $v = 'FAIL'; if ($ok) { $v = 'PASS' }
    Add-Res $Case $v @{ path = $Path; exit = $r.Exit; code = $code; ms = $r.Ms; unchanged = ($before -eq $after); created = $created; stderr = $r.Err.Trim() } }
if (Want 'socket') {
    $sd = Join-Path $PB 'sock'; New-Item -ItemType Directory -Path $sd | Out-Null
    $f1 = Join-Path $sd 'regular é.bin'; [IO.File]::WriteAllBytes($f1, [byte[]](1..200 | ForEach-Object { [byte]($_ % 256) }))
    $f0 = Join-Path $sd 'empty.bin'; [IO.File]::WriteAllBytes($f0, [byte[]]@())
    $fro = Join-Path $sd 'readonly.bin'; [IO.File]::WriteAllBytes($fro, [byte[]](1, 2, 3)); (Get-Item -LiteralPath $fro).Attributes = 'ReadOnly'
    $fh = Join-Path $sd 'hidden.bin'; [IO.File]::WriteAllBytes($fh, [byte[]](9, 9, 9)); (Get-Item -LiteralPath $fh -Force).Attributes = 'Hidden'
    Set-Content -LiteralPath $f1 -Stream hmads -Value 'ads content' -Encoding Ascii
    Start-Sleep -Milliseconds 100
    Socket-Case 'socket.regular' $f1 $f1
    Socket-Case 'socket.empty_regular' $f0 $f0
    Socket-Case 'socket.readonly' $fro $fro
    Socket-Case 'socket.hidden' $fh $fh
    Socket-Case 'socket.regular_verbatim' ('\\?\' + $f1) $f1
    Socket-Case 'socket.regular_relative_cwd' ('sock\regular é.bin') $f1
    Socket-Case 'socket.regular_data_stream' ($f1 + '::$DATA') $f1
    $adsBefore = (Get-Content -LiteralPath $f1 -Stream hmads -Raw)
    Socket-Case 'socket.existing_ads' ($f1 + ':hmads') $f1
    $adsAfter = (Get-Content -LiteralPath $f1 -Stream hmads -Raw)
    Add-Res 'socket.existing_ads_content' $(if ($adsBefore -eq $adsAfter) { 'PASS' } else { 'FAIL' }) @{ unchanged = ($adsBefore -eq $adsAfter) }
    $streamsBefore = @(Get-Item -LiteralPath $f1 -Stream * | ForEach-Object { $_.Stream }).Count
    Socket-Case 'socket.new_ads_not_created' ($f1 + ':hmnew') $f1
    $streamsAfter = @(Get-Item -LiteralPath $f1 -Stream * | ForEach-Object { $_.Stream }).Count
    Add-Res 'socket.new_ads_stream_count' $(if ($streamsBefore -eq $streamsAfter) { 'PASS' } else { 'FAIL' }) @{ before = $streamsBefore; after = $streamsAfter }
    Socket-Case 'socket.missing_path' (Join-Path $sd 'absent.sock') $null (Join-Path $sd 'absent.sock')
    Socket-Case 'socket.dir' $sd
    Socket-Case 'socket.dir_trailing_backslash' ($sd + '\')
    if ($juncOk) { Socket-Case 'socket.junction' $junc }
    Socket-Case 'socket.nul' 'NUL'
    Socket-Case 'socket.conout' 'CONOUT$'
    Socket-Case 'socket.conin' 'CONIN$'
    Socket-Case 'socket.pipe_root' '\\.\pipe\'
    Socket-Case 'socket.empty' ''
    $fs = New-Object IO.FileStream($f1, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    Socket-Case 'socket.regular_shared_read_only' $f1
    $fs.Dispose()
    Add-Res 'socket.regular_final_state' 'INFO' @{ state_after_all = (FileState $f1).Split('|')[0].Substring(0, 16) }
}

# ------------------------------------------------------------------ agent list on pipes owned by another process
function Agent-Pipe { param([string]$Case, [string]$Mode, [string]$Prefix = '\\.\pipe\', [string]$WantCode, [int]$WantExit, [int]$TimeoutMs = 3000)
    $pn = 'hm-' + $TID + '-' + $Mode + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
    $mk = Join-Path $PB ($pn + '.marker'); $rd = Join-Path $PB ($pn + '.ready'); $st = Join-Path $PB ($pn + '.stop')
    $h = Start-Helper (Join-Path $Base 'probe\ProbePipe.ps1') @('-PipeName', $pn, '-Mode', $Mode, '-MarkerFile', $mk, '-ReadyFile', $rd, '-StopFile', $st)
    if (-not (Wait-File $rd)) { Add-Res $Case 'BLOCKED' @{ note = 'helper not ready' }; Stop-Helper $h $st; return }
    $r = Invoke-P -Argv @('agent', 'list', '--socket', ($Prefix + $pn), '--timeout-ms', [string]$TimeoutMs, '--json') -TimeoutMs ($TimeoutMs + 5000)
    Start-Sleep -Milliseconds 300
    Stop-Helper $h $st
    $code = $null; if ($r.Json) { $code = $r.Json.code }
    $log = @(); if (Test-Path -LiteralPath $mk) { $log = @([IO.File]::ReadAllLines($mk)) }
    $ids = $null; if ($r.Json -and $code -eq 'AGENT_OK') { $ids = @($r.Json.data.identities | ForEach-Object { $_.key_type + ' ' + $_.comment }) }
    $ok = ($r.Exit -eq $WantExit -and $code -eq $WantCode)
    if ($WantCode -eq 'AGENT_OK' -or $WantCode -eq 'AGENT_REFUSED') { $ok = $ok -and ($log.Count -eq 1) -and ($log[0] -like 'connect 1 000000010b extra_bytes=0*') }
    Add-Res $Case $(if ($ok) { 'PASS' } else { 'FAIL' }) @{ mode = $Mode; prefix = $Prefix; exit = $r.Exit; code = $code; ms = $r.Ms; server_log = $log; identities = $ids } }
if (Want 'agentpipe') {
    Agent-Pipe 'agentpipe.answer_other_process' 'answer' '\\.\pipe\' 'AGENT_OK' 0
    Agent-Pipe 'agentpipe.answer_message_mode' 'answermsg' '\\.\pipe\' 'AGENT_OK' 0
    Agent-Pipe 'agentpipe.answer_verbatim_prefix' 'answer' '\\?\pipe\' 'AGENT_OK' 0
    Agent-Pipe 'agentpipe.refuse' 'refuse' '\\.\pipe\' 'AGENT_REFUSED' 5
    Agent-Pipe 'agentpipe.close_immediately' 'close' '\\.\pipe\' 'AGENT_UNAVAILABLE' 5
    Agent-Pipe 'agentpipe.outbound_only' 'outbound' '\\.\pipe\' 'AGENT_UNAVAILABLE' 5
    # accepts and never writes, served by another process: timeout
    $sp = Join-Path $Root 'tools\StallPipe.ps1'; $pn = 'hm-' + $TID + '-stall2'
    $mk = Join-Path $PB 'stall2.marker'; $rd = Join-Path $PB 'stall2.ready'; $st = Join-Path $PB 'stall2.stop'
    $h = Start-Helper $sp @('-PipeName', $pn, '-MarkerFile', $mk, '-ReadyFile', $rd, '-StopFile', $st, '-RunSeconds', '60')
    if (Wait-File $rd) {
        $r = Invoke-P -Argv @('agent', 'list', '--socket', ('\\.\pipe\' + $pn), '--timeout-ms', '1000', '--json') -TimeoutMs 8000
        $code = $null; if ($r.Json) { $code = $r.Json.code }
        Add-Res 'agentpipe.never_writes_timeout' $(if ($r.Exit -eq 5 -and $code -eq 'AGENT_UNAVAILABLE' -and $r.Ms -ge 900 -and $r.Ms -lt 3000) { 'PASS' } else { 'FAIL' }) @{ exit = $r.Exit; code = $code; ms = $r.Ms } }
    Stop-Helper $h $st
}

# ------------------------------------------------------------------ run: batch targets beyond the X1 rows
if (Want 'batch') {
    $bd = Join-Path $PB 'batnospace'; New-Item -ItemType Directory -Path $bd | Out-Null
    Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $bd 'argvdump.exe')
    $body = "@echo off`r`n`"%~dp0argvdump.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    $asc = New-Object Text.ASCIIEncoding
    foreach ($n in @('fwd.bat', 'fwd.cmd')) { [IO.File]::WriteAllText((Join-Path $bd $n), $body, $asc) }
    # files whose names Win32 normally strips (trailing dot / space), created through \\?\
    [IO.File]::WriteAllText(('\\?\' + (Join-Path $bd 'dot.bat.')), $body, $asc)
    [IO.File]::WriteAllText(('\\?\' + (Join-Path $bd 'spc.bat ')), $body, $asc)
    # a directory whose name holds a %VAR% reference
    $pd = Join-Path $PB 'pct%HMRDIRVAR%x'; New-Item -ItemType Directory -Path $pd | Out-Null
    Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $pd 'argvdump.exe'); [IO.File]::WriteAllText((Join-Path $pd 'fwd.bat'), $body, $asc)
    $od = Join-Path $PB 'os%OS%x'; New-Item -ItemType Directory -Path $od | Out-Null
    Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $od 'argvdump.exe'); [IO.File]::WriteAllText((Join-Path $od 'fwd.bat'), $body, $asc)
    # decoy cmd.exe (argvdump copy) in the working directory and first on PATH
    $decoyDir = Join-Path $PB 'decoypath'; New-Item -ItemType Directory -Path $decoyDir | Out-Null
    Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $decoyDir 'cmd.exe')
    $script:inj = 0
    function Bat-Case { param([string]$Case, [string]$Prog, [string[]]$A, [hashtable]$Env = @{}, [switch]$DecoyCwd, [string]$PathOverride, [string[]]$Watch = @())
        $cwd = Join-Path $PB ('cwd-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $cwd | Out-Null
        if ($DecoyCwd) { Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $cwd 'cmd.exe') }
        $rep = Join-Path $RepDir ('rep-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
        $e = @{ 'ARGVDUMP_OUT' = $rep; 'HMRVAR' = 'b&break>hmrinjvar.txt' }
        foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
        if ($PathOverride) { $e['PATH'] = $PathOverride }
        $watchDirs = @($cwd) + $Watch
        $before = @{}; foreach ($w in $watchDirs) { $before[$w] = @(Get-ChildItem -LiteralPath $w -Force | ForEach-Object { $_.Name }) }
        $r = Invoke-P -Argv (@('run', '--', $Prog) + $A) -Env $e -Cwd $cwd -TimeoutMs 15000
        Start-Sleep -Milliseconds 100
        $stray = @(); foreach ($w in $watchDirs) { $stray += @(Get-ChildItem -LiteralPath $w -Force | Where-Object { $before[$w] -notcontains $_.Name } | ForEach-Object { $_.Name }) }
        $j = $null; if (Test-Path -LiteralPath $rep) { $j = [IO.File]::ReadAllText($rep, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $rep }
        $argvGot = $null; $exe0 = $null; $exact = $false; $cl = $null
        if ($j) {
            $aw = @(); if ($j.PSObject.Properties['argv_u16']) { $aw = @($j.argv_u16) }
            $want = @($A | ForEach-Object { (($_.ToCharArray() | ForEach-Object { ([int]$_).ToString('x4') }) -join '') })
            $argvGot = @($aw | Select-Object -Skip 1)
            $exact = ($argvGot.Count -eq $want.Count); if ($exact) { for ($i = 0; $i -lt $want.Count; $i++) { if ($argvGot[$i] -ne $want[$i]) { $exact = $false } } }
            $h = [string]$j.cmdline_u16; $sb = New-Object Text.StringBuilder; for ($i = 0; $i + 4 -le $h.Length; $i += 4) { [void]$sb.Append([char][Convert]::ToUInt16($h.Substring($i, 4), 16)) }; $cl = $sb.ToString()
        }
        # the forwarding batch starts argvdump with "<dir>\argvdump.exe" ...; a decoy cmd.exe (an argvdump copy) would
        # instead report the command line the launcher built for cmd.exe itself
        $decoyRan = ($j -and $cl -and ($cl -match '^(?i)\s*"?[^" ]*cmd(\.exe)?"?\s'))
        Remove-Item -LiteralPath $cwd -Recurse -Force -ErrorAction SilentlyContinue
        $outcome = 'other'
        if ($stray.Count -gt 0) { $outcome = 'INJECTED' }
        elseif ($decoyRan) { $outcome = 'DECOY_CMD_RAN' }
        elseif ($r.Exit -eq 127 -and -not $j) { $outcome = 'refused_or_not_found' }
        elseif ($j -and $exact) { $outcome = 'received_exactly' }
        elseif ($j) { $outcome = 'argument_changed' }
        elseif ($r.TimedOut) { $outcome = 'timed_out' }
        $v = 'PASS'; if ($outcome -eq 'INJECTED' -or $outcome -eq 'DECOY_CMD_RAN' -or $outcome -eq 'timed_out' -or $outcome -eq 'other') { $v = 'FAIL' } elseif ($outcome -eq 'argument_changed') { $v = 'INFO' }
        $o = @{ prog = $Prog; args = $A; outcome = $outcome; exit = $r.Exit; files_created = $stray; child_cmdline = $cl; stderr = $r.Err.Trim() }
        Add-Res $Case $v $o }
    $full = Join-Path $bd 'fwd.bat'
    $payloads = @(@('amp', 'a&break>hmrinj1.txt'), @('quote_amp', 'a"&break>hmrinj2.txt'), @('bs_quote_amp', 'a\"&break>hmrinj3.txt'))
    foreach ($pl in $payloads) {
        Bat-Case ('batch.upper_ext.' + $pl[0]) (Join-Path $bd 'FWD.BAT') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.trailing_dot_normalized.' + $pl[0]) ($full + '.') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.trailing_space_normalized.' + $pl[0]) ($full + ' ') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.trailing_dots_spaces.' + $pl[0]) ($full + '. . .') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.data_stream_suffix.' + $pl[0]) ($full + '::$DATA') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.verbatim.' + $pl[0]) ('\\?\' + $full) @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.verbatim_data_stream.' + $pl[0]) ('\\?\' + $full + '::$DATA') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.verbatim_literal_trailing_dot_file.' + $pl[0]) ('\\?\' + (Join-Path $bd 'dot.bat.')) @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.verbatim_literal_trailing_space_file.' + $pl[0]) ('\\?\' + (Join-Path $bd 'spc.bat ')) @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.cmd_trailing_dot.' + $pl[0]) ((Join-Path $bd 'fwd.cmd') + '.') @($pl[1]) -Watch @($bd)
        Bat-Case ('batch.path_lookup_bare_name.' + $pl[0]) 'fwd.bat' @($pl[1]) -PathOverride ($bd + ';' + "$env:SystemRoot\System32") -Watch @($bd)
        Bat-Case ('batch.pathext_name.' + $pl[0]) 'fwd' @($pl[1]) -PathOverride ($bd + ';' + "$env:SystemRoot\System32") -Env @{ PATHEXT = '.BAT;.CMD;.EXE' } -Watch @($bd)
    }
    # argument shapes against the plain full path
    $shapes = @(
        @('newline', "a`nb"), @('cr', "a`rb"), @('empty', ''), @('trailing_backslash', 'a\'), @('tab', "a`tb"),
        @('bang_var', '!HMRVAR!'), @('percent_alone', '%'), @('double_percent_var', '%%HMRVAR%%'), @('unterminated_percent', '%HMRVAR'),
        @('substring_var', '%HMRVAR:~0%'), @('replace_var', '%HMRVAR:b=c%'), @('cd_var', '%cd%'), @('hidden_eq_var', '%=C:%'),
        @('dp0', '%~dp0'), @('paren', '(a)&break>hmrinj4.txt'), @('caret_amp', '^&break>hmrinj5.txt'),
        @('quote_only', '"'), @('two_quotes', '""'), @('quoted_var', '"%HMRVAR%"'), @('unicode', 'é ü 😀'),
        @('semicolon_comma_eq', 'a;b,c=d'), @('at_sign', '@break>hmrinj6.txt'))
    foreach ($s in $shapes) { Bat-Case ('batch.arg.' + $s[0]) $full @($s[1]) -Watch @($bd) }
    Bat-Case 'batch.arg.span_two_args' $full @('x%HMRVAR', 'y%') -Watch @($bd)
    Bat-Case 'batch.arg.many_mixed' $full @('a b', '&', '|', '"', '%HMRVAR%', '\', '') -Watch @($bd)
    # environment-controlled names the %%cd:~,%% hack relies on
    Bat-Case 'batch.env.cd_overridden' $full @('%HMRVAR%') -Env @{ 'CD' = 'q&break>hmrinjcd.txt&' } -Watch @($bd)
    Bat-Case 'batch.env.var_named_like_hack' $full @('%') -Env @{ 'cd:~,' = 'q&break>hmrinjhack.txt&' } -Watch @($bd)
    # %VAR% inside the script path (argv[0])
    Bat-Case 'batch.scriptpath.percent_var_env_controlled' (Join-Path $pd 'fwd.bat') @('plain') -Env @{ 'HMRDIRVAR' = '" & break>hmrinjdir.txt & "' } -Watch @($pd, $PB)
    Bat-Case 'batch.scriptpath.percent_var_undefined' (Join-Path $pd 'fwd.bat') @('plain') -Watch @($pd)
    Bat-Case 'batch.scriptpath.percent_existing_var' (Join-Path $od 'fwd.bat') @('plain') -Watch @($od)
    # which cmd.exe interprets the batch: decoys in the working directory and first on PATH
    Bat-Case 'batch.cmd_resolution.decoy_cwd' $full @('plain') -DecoyCwd -Watch @($bd)
    Bat-Case 'batch.cmd_resolution.decoy_path' $full @('plain') -PathOverride ($decoyDir + ';' + "$env:SystemRoot\System32") -Watch @($bd)
    Bat-Case 'batch.cmd_resolution.comspec_decoy' $full @('plain') -Env @{ 'ComSpec' = (Join-Path $decoyDir 'cmd.exe') } -Watch @($bd)
}


if (Want 'batch2') {
    # a batch file in a directory whose name holds %OS%: does cmd.exe run a DIFFERENT batch file at the expanded path?
    $asc = New-Object Text.ASCIIEncoding
    $body = "@echo off`r`n`"%~dp0argvdump.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    $od = Join-Path $PB 'os%OS%y'; New-Item -ItemType Directory -Path $od | Out-Null
    Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $od 'argvdump.exe'); [IO.File]::WriteAllText((Join-Path $od 'fwd.bat'), $body, $asc)
    $other = Join-Path $PB ('os' + $env:OS + 'y'); New-Item -ItemType Directory -Path $other | Out-Null
    [IO.File]::WriteAllText((Join-Path $other 'fwd.bat'), "@echo off`r`nbreak>hmr_other_batch_ran.txt`r`n", $asc)
    $cwd = Join-Path $PB 'cwd-b2'; New-Item -ItemType Directory -Path $cwd | Out-Null
    $rep = Join-Path $RepDir 'rep-b2.json'
    $r = Invoke-P -Argv @('run', '--', (Join-Path $od 'fwd.bat'), 'plain') -Env @{ ARGVDUMP_OUT = $rep } -Cwd $cwd -TimeoutMs 15000
    $ran = Test-Path -LiteralPath (Join-Path $cwd 'hmr_other_batch_ran.txt')
    $intended = Test-Path -LiteralPath $rep
    Add-Res 'batch2.scriptpath_existing_var_runs_other_file' $(if ($ran) { 'FAIL' } elseif ($intended) { 'PASS' } else { 'INFO' }) @{ prog = (Join-Path $od 'fwd.bat'); exit = $r.Exit; other_batch_ran = $ran; intended_batch_ran = $intended; stderr = $r.Err.Trim() }
    # control: the same intended file started directly by cmd.exe /d /c with the path quoted and ^% escaped is not the
    # point here; instead record what a direct CreateProcess of the batch (no heimdall-proto) does
    $rep2 = Join-Path $RepDir 'rep-b2-direct.json'
    $cwd2 = Join-Path $PB 'cwd-b2c'; New-Item -ItemType Directory -Path $cwd2 | Out-Null
    $r2 = Invoke-P -Program (Join-Path $od 'fwd.bat') -Argv @('plain') -Env @{ ARGVDUMP_OUT = $rep2 } -Cwd $cwd2 -TimeoutMs 15000
    Add-Res 'batch2.control_direct_createprocess' 'INFO' @{ note = 'no heimdall-proto: .NET Process.Start (CreateProcessW) of the same .bat path'; exit = $r2.Exit; other_batch_ran = (Test-Path -LiteralPath (Join-Path $cwd2 'hmr_other_batch_ran.txt')); intended_batch_ran = (Test-Path -LiteralPath $rep2); stderr = $r2.Err.Trim() }
}

# ------------------------------------------------------------------ cleanup of helpers started here
foreach ($p in $Started) { try { if (-not $p.HasExited) { $p.Kill(); [void]$p.WaitForExit(3000) } } catch { } }
$alive = @($Started | Where-Object { -not $_.HasExited }).Count
Add-Res 'host.helpers_stopped' $(if ($alive -eq 0) { 'PASS' } else { 'FAIL' }) @{ started = $Started.Count; alive = $alive }
$scan = [IO.File]::ReadAllText($ResFile).Contains($CanaryPrefix)
Write-Host "canary_in_results=$scan"
exit 0
