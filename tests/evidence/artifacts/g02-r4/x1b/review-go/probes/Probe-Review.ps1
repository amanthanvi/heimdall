<#
  Adversarial review probes for the go Windows fix round (task M00-T05-x1b-review-go). PowerShell 7.
  Runs bin\go\heimdall-proto.exe under -Root; writes probes.jsonl (paths replaced by <scratch>).
#>
param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$X = Join-Path $Root 'bin\go\heimdall-proto.exe'
$ArgvDump = Join-Path $Root 'helpers\argvdump.exe'
$Tools = Join-Path $Root 'tools'
Import-Module (Join-Path $Root 'g03\G03Common.psm1') -Force
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $Tools 'G02X1Native.cs')))
Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class RvShort {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetShortPathNameW(string l, StringBuilder s, uint n);
  public static string Get(string p) { var sb = new StringBuilder(1024); uint r = GetShortPathNameW(p, sb, 1024); return r == 0 ? null : sb.ToString(); }
}
'@
$P = Join-Path $Root 'probe'
New-Item -ItemType Directory -Force -Path $P | Out-Null
$Cwd = Join-Path $P 'cwd'; New-Item -ItemType Directory -Force -Path $Cwd | Out-Null
$results = New-Object System.Collections.ArrayList
$Tag = 'hmrvgo' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
function Red { param([AllowNull()][string]$S) if ($null -eq $S) { return $null }; return $S.Replace($Root, '<scratch>').Replace($env:USERPROFILE, '<winhome>').Replace($env:USERNAME, '<winuser>').Replace($env:COMPUTERNAME, '<winhost>') }
function Add-R { param([string]$Group, [string]$Id, [hashtable]$Obs, [string]$Verdict, [string]$Criterion)
    $o = [ordered]@{ group = $Group; id = $Id; verdict = $Verdict; criterion = $Criterion }
    foreach ($k in ($Obs.Keys | Sort-Object)) { $v = $Obs[$k]; if ($v -is [string]) { $v = Red $v }; $o[$k] = $v }
    [void]$results.Add([pscustomobject]$o)
    Write-Host ("{0,-8} {1,-48} {2}" -f $Verdict, $Id, (([pscustomobject]$o | ConvertTo-Json -Compress -Depth 4))) }
function Invoke-Hp { param([string]$Exe, [string[]]$A, [int]$TimeoutMs = 10000, [string]$Dir = $Cwd, [hashtable]$Env = @{})
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe)
    foreach ($a in $A) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true; $psi.WorkingDirectory = $Dir
    foreach ($k in $Env.Keys) { $psi.Environment[$k] = [string]$Env[$k] }
    $p = [System.Diagnostics.Process]::new(); $p.StartInfo = $psi
    $sw = [Diagnostics.Stopwatch]::StartNew(); [void]$p.Start()
    $to = $p.StandardOutput.ReadToEndAsync(); $te = $p.StandardError.ReadToEndAsync(); $p.StandardInput.Close()
    $timedOut = -not $p.WaitForExit($TimeoutMs); $ms = $sw.ElapsedMilliseconds
    if ($timedOut) { try { $p.Kill() } catch { }; [void]$p.WaitForExit(5000) }
    [void]$to.Wait(5000); [void]$te.Wait(5000)
    $code = $null; if (-not $timedOut) { $code = $p.ExitCode }
    $r = [pscustomobject]@{ exit = $code; timed_out = $timedOut; ms = $ms; stdout = $to.Result; stderr = $te.Result }
    $p.Dispose(); return $r }
function Get-Code { param($R) try { return ($R.stdout | ConvertFrom-Json).code } catch { return $null } }

# ---------------------------------------------------------------- helper pipe servers (separate processes, ours)
$Pwsh = (Get-Process -Id $PID).Path
$owned = New-Object System.Collections.ArrayList
$srvN = 0
function Start-Srv { param([string]$Mode)
    $script:srvN++; $name = "$Tag-$Mode-$($script:srvN)"; $mk = Join-Path $P "$Mode-$($script:srvN).marker"; $rd = Join-Path $P "$Mode-$($script:srvN).ready"; $st = Join-Path $P "$Mode-$($script:srvN).stop"
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Pwsh)
    foreach ($a in @('-NoProfile', '-NonInteractive', '-File', (Join-Path $Tools 'PipeSrv.ps1'), '-Name', $name, '-Mode', $Mode, '-Marker', $mk, '-ReadyFile', $rd, '-StopFile', $st, '-RunSeconds', '90')) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi); [void]$owned.Add($proc)
    $sw = [Diagnostics.Stopwatch]::StartNew(); while (-not (Test-Path -LiteralPath $rd) -and $sw.ElapsedMilliseconds -lt 20000) { Start-Sleep -Milliseconds 100 }
    return [pscustomobject]@{ Path = "\\.\pipe\$name"; Name = $name; Marker = $mk; Stop = $st; Proc = $proc; Ready = (Test-Path -LiteralPath $rd) } }
function Stop-Srv { param($S) [System.IO.File]::WriteAllText($S.Stop, 'stop'); if (-not $S.Proc.WaitForExit(8000)) { try { $S.Proc.Kill() } catch { } }
    if (Test-Path -LiteralPath $S.Marker) { return @([System.IO.File]::ReadAllLines($S.Marker)) } return @() }

# ---------------------------------------------------------------- fixtures
$hl = Join-Path $Root 'fixtures\profiles\homelab.toml'
$ph = Join-Path $P 'homelab.toml'; Copy-Item -LiteralPath $hl -Destination $ph
$dirA = Join-Path $P 'a dir ü'; New-Item -ItemType Directory -Force -Path $dirA | Out-Null
[System.IO.File]::WriteAllBytes("${ph}:alt", [System.IO.File]::ReadAllBytes($hl))
$junction = Join-Path $P 'junc'; New-Item -ItemType Junction -Path $junction -Target $dirA | Out-Null

# ================================================================ A. --file paths that are not regular files
$silent = Start-Srv 'silent'
$fileCases = [ordered]@{
    'directory' = @($dirA, 2); 'directory_extended' = @("\\?\$dirA", 2); 'junction_to_dir' = @($junction, 2)
    'NUL' = @('NUL', 2); 'dev_NUL' = @('\\.\NUL', 2); 'globalroot_null' = @('\\?\GLOBALROOT\Device\Null', 2); 'dir_NUL' = @((Join-Path $dirA 'NUL'), 2)
    'CON' = @('CON', 2); 'CONIN$' = @('CONIN$', 2); 'CONOUT$' = @('CONOUT$', 2); 'COM1' = @('COM1', 2); 'LPT1' = @('LPT1', 2)
    'pipe_root' = @('\\.\pipe\', 2); 'volume_C' = @('\\.\C:', 2); 'mailslot_missing' = @("\\.\mailslot\$Tag", 2)
    'pipe_silent' = @($silent.Path, 2); 'pipe_silent_qmark' = @(("\\?\pipe\" + $silent.Name), 2)
    'regular_extended' = @("\\?\$ph", 0); 'regular_trailing_dot' = @("$ph.", 0); 'regular_data_stream' = @("${ph}::`$DATA", 0); 'regular_named_stream' = @("${ph}:alt", 0)
}
foreach ($k in $fileCases.Keys) {
    $f = $fileCases[$k][0]; $want = $fileCases[$k][1]
    $r = Invoke-Hp $X @('profile', 'show', '--file', $f, '--json') 6000
    $code = Get-Code $r
    $ok = ($r.exit -eq $want) -and ($r.ms -lt 2000)
    Add-R 'file' "profile.$k" @{ exit = $r.exit; ms = $r.ms; code = $code; timed_out = $r.timed_out; stderr = $r.stderr.Trim() } (@('fail', 'pass')[[int]$ok]) "profile show --file -> exit $want within 2 s"
}
# tui on a pseudoconsole
foreach ($k in @('directory', 'NUL', 'globalroot_null', 'CON', 'CONIN$', 'CONOUT$', 'pipe_root', 'volume_C', 'pipe_silent', 'pipe_silent_qmark', 'junction_to_dir')) {
    $f = $fileCases[$k][0]
    $pty = [X1Pty]::Start((Join-G03WinArgs @($X, 'tui', '--file', $f)), $Cwd, 80, 24, $null, $null)
    $ex = $pty.WaitExit(6000); if (-not $ex) { [void]$pty.Kill(); [void]$pty.WaitExit(3000) }
    $ms = $null; if ($ex -and $pty.ExitTicksUtc -gt 0) { $ms = [int](($pty.ExitTicksUtc - $pty.StartedUtc.Ticks) / 10000) }
    $code = $null; if ($ex) { $code = $pty.ExitCode }
    Start-Sleep -Milliseconds 200; [void]$pty.ScreenText(); $alt = $pty.Screen.AltActive
    $pty.Dispose()
    $ok = $ex -and $code -eq 2 -and $null -ne $ms -and $ms -lt 2000 -and -not $alt
    Add-R 'file' "tui.$k" @{ exit = $code; ms = $ms; killed_by_probe = (-not $ex); alt_screen_active_after = $alt } (@('fail', 'pass')[[int]$ok]) 'tui --file on an 80x24 pseudoconsole -> exit 2 within 2 s, alternate screen not active'
}
$silentLog = Stop-Srv $silent
Add-R 'file' 'file.silent_pipe_server_log' @{ lines = ($silentLog -join ' | ') } 'info' 'what the never-writing pipe server saw from the --file probes'

# ================================================================ B. agent list --socket
$victim = Join-Path $P 'victim.txt'; [System.IO.File]::WriteAllText($victim, "victim content $Tag`n")
$vdir = Join-Path $P 'vdir'; New-Item -ItemType Directory -Force -Path $vdir | Out-Null
function Snap { param([string]$F) $i = Get-Item -LiteralPath $F; return ('{0}|{1}|{2}' -f (Get-FileHash -LiteralPath $F -Algorithm SHA256).Hash, $i.Length, $i.LastWriteTimeUtc.Ticks) }
$drvRel = $victim.Substring(0, 2) + $victim.Substring(2)  # C:\...
$sockFile = [ordered]@{
    'pipe_dotdot_to_file' = "\\.\pipe\..\$victim"; 'pipe_dotdot2_to_file' = "\\.\pipe\..\..\$victim"; 'pipe_slash_dotdot_to_file' = "\\.\pipe/../$victim"
    'PIPE_upper_dotdot_to_file' = "\\.\PIPE\..\$victim"; 'qmark_to_file' = "\\?\$victim"; 'dev_to_file' = "\\.\$victim"; 'forward_slash_dev_to_file' = ('//./pipe/../' + $victim.Replace('\', '/'))
    'pipe_dotdot_to_dir' = "\\.\pipe\..\$vdir"; 'pipe_trailing_dot_to_file' = "\\.\pipe\..\$victim."; 'pipe_dotdot_to_stream' = "\\.\pipe\..\${victim}::`$DATA"
}
foreach ($k in $sockFile.Keys) {
    $s = $sockFile[$k]
    $before = Snap $victim
    $r = Invoke-Hp $X @('agent', 'list', '--socket', $s, '--timeout-ms', '1500', '--json') 8000
    $after = Snap $victim
    $code = Get-Code $r
    $ok = ($before -eq $after) -and ($r.exit -eq 5 -or $r.exit -eq 2)
    Add-R 'socket' "agent.$k" @{ exit = $r.exit; ms = $r.ms; code = $code; victim_unchanged = ($before -eq $after); stderr = $r.stderr.Trim() } (@('fail', 'pass')[[int]$ok]) 'section 9.6: --socket naming a non-endpoint (via device-path normalization) -> exit 5 or 2, file not modified'
}
# pipes owned by another process of the same user
foreach ($mode in @('silent', 'garbage', 'close', 'busy')) {
    $srv = Start-Srv $mode
    $holder = $null
    if ($mode -eq 'busy') { $holder = [System.IO.Pipes.NamedPipeClientStream]::new('.', $srv.Name, [System.IO.Pipes.PipeDirection]::InOut); $holder.Connect(5000) }
    $r = Invoke-Hp $X @('agent', 'list', '--socket', $srv.Path, '--timeout-ms', '1500', '--json') 10000
    if ($holder) { $holder.Dispose() }
    $log = Stop-Srv $srv
    $code = Get-Code $r
    $ok = ($r.exit -eq 5) -and ($r.ms -lt 4000) -and -not $r.timed_out
    Add-R 'socket' "agent.foreign_pipe_$mode" @{ exit = $r.exit; ms = $r.ms; code = $code; server_ready = $srv.Ready; server_log = ($log -join ' | '); stderr = $r.stderr.Trim() } (@('fail', 'pass')[[int]$ok]) 'pipe owned by another process of the same user that is not an agent -> exit 5 within timeout (1500 ms) + slack'
}

# ================================================================ C. run: batch-file targets
$B = Join-Path $P 'b'; New-Item -ItemType Directory -Force -Path $B | Out-Null
$n = 0
function New-Batch { param([string]$Path) $script:n++; $m = Join-Path $P ("RAN-" + $script:n); [System.IO.File]::WriteAllText($Path, "@echo off`r`nbreak>`"$m`"`r`nexit /b 0`r`n"); return $m }
function Test-Run { param([string]$Id, [string]$Target, [string]$Marker, [hashtable]$Env = @{}, [string]$Dir = $Cwd, [string]$Note = '')
    $inj = "hpinj-$Id.txt"
    $r = Invoke-Hp $X @('run', '--', $Target, "a&break>$inj", 'plain') 10000 $Dir $Env
    $ran = $false; if ($Marker) { $ran = Test-Path -LiteralPath $Marker }
    $injd = (Test-Path -LiteralPath (Join-Path $Dir $inj)) -or (Test-Path -LiteralPath (Join-Path $B $inj))
    $ok = (-not $ran) -and (-not $injd) -and -not $r.timed_out
    Add-R 'run' "run.$Id" @{ target = $Target; exit = $r.exit; ms = $r.ms; cmd_ran_marker = $ran; injected_file = $injd; stderr = $r.stderr.Trim(); note = $Note } (@('fail', 'pass')[[int]$ok]) 'section 9.6: no argument byte run as a command (no marker, no injected file)' }

$xbat = Join-Path $B 'x.bat'; $mX = New-Batch $xbat
Test-Run 'control_plain_bat' $xbat $mX
# alternate data streams
$m = New-Batch "${xbat}:s.exe"; Test-Run 'ads_bat_stream_named_exe' "${xbat}:s.exe" $m
$ytxt = Join-Path $B 'y.txt'; [System.IO.File]::WriteAllText($ytxt, 'plain'); $m = New-Batch "${ytxt}:s.bat"; Test-Run 'ads_txt_stream_named_bat' "${ytxt}:s.bat" $m
Test-Run 'ads_bat_colon_data' "${xbat}:`$DATA" $mX
# batch content under non-batch names
$m = New-Batch (Join-Path $B 'z.exe'); Test-Run 'batch_content_named_exe' (Join-Path $B 'z.exe') $m
$m = New-Batch (Join-Path $B 'w.com'); Test-Run 'batch_content_named_com' (Join-Path $B 'w.com') $m
$m = New-Batch (Join-Path $B 'noext'); Test-Run 'batch_content_no_ext' (Join-Path $B 'noext') $m
# hard link and symlink with non-batch names
$hl2 = Join-Path $B 'hl.exe'; try { New-Item -ItemType HardLink -Path $hl2 -Target $xbat | Out-Null; Test-Run 'hardlink_exe_to_bat' $hl2 $mX } catch { Add-R 'run' 'run.hardlink_exe_to_bat' @{ error = $_.Exception.Message } 'blocked' 'hard link creation' }
$sl = Join-Path $B 'sl.exe'; try { New-Item -ItemType SymbolicLink -Path $sl -Target $xbat -ErrorAction Stop | Out-Null; Test-Run 'symlink_exe_to_bat' $sl $mX } catch { Add-R 'run' 'run.symlink_exe_to_bat' @{ error = ($_.Exception.Message -split "`n")[0] } 'blocked' 'symbolic link creation needs SeCreateSymbolicLinkPrivilege or Developer Mode (not changed)' }
# 8.3 short names
$lb = Join-Path $B 'longname.batch'; $m = New-Batch $lb; $sn = [RvShort]::Get($lb)
if ($sn -and $sn -ne $lb) { Test-Run 'shortname_of_dot_batch' $sn $m -Note ('short leaf ' + (Split-Path -Leaf $sn)) } else { Add-R 'run' 'run.shortname_of_dot_batch' @{ short = $sn } 'blocked' 'no 8.3 name on this volume' }
$vb = Join-Path $B 'verylongname.cmd'; $m = New-Batch $vb; $sn = [RvShort]::Get($vb)
if ($sn -and $sn -ne $vb) { Test-Run 'shortname_of_cmd' $sn $m -Note ('short leaf ' + (Split-Path -Leaf $sn)) } else { Add-R 'run' 'run.shortname_of_cmd' @{ short = $sn } 'blocked' 'no 8.3 name on this volume' }
# path spellings
Test-Run 'extended_prefix' "\\?\$xbat" $mX
Test-Run 'device_prefix' "\\.\$xbat" $mX
Test-Run 'forward_slashes' ($xbat.Replace('\', '/')) $mX
Test-Run 'relative_dot' '.\b\x.bat' $mX @{} $P
Test-Run 'dotdot_component' (Join-Path $B '..\b\x.bat') $mX
Test-Run 'trailing_dot_space_mix' "$xbat . . ." $mX
$lit = "\\?\" + (Join-Path $B 'lit.bat.'); $m2 = Join-Path $P 'RAN-lit'; [System.IO.File]::WriteAllText($lit, "@echo off`r`nbreak>`"$m2`"`r`n"); Test-Run 'literal_trailing_dot_file_extended' $lit $m2
# PATH / PATHEXT resolution
$pd = Join-Path $P 'path dir'; New-Item -ItemType Directory -Force -Path $pd | Out-Null; $m = New-Batch (Join-Path $pd 'hmrvb.cmd')
Test-Run 'pathext_bare' 'hmrvb' $m @{ PATH = $pd; PATHEXT = '.BAT;.CMD' }
Test-Run 'pathext_bare_lower' 'hmrvb' $m @{ PATH = $pd; PATHEXT = '.bat;.cmd' }
Test-Run 'path_name_with_ext' 'hmrvb.cmd' $m @{ PATH = $pd }
Test-Run 'path_name_trailing_dot' 'hmrvb.cmd.' $m @{ PATH = $pd }
Test-Run 'path_name_upper' 'HMRVB.CMD' $m @{ PATH = $pd }
Test-Run 'pathext_default_env' 'hmrvb' $m @{ PATH = $pd; PATHEXT = '' } -Note 'empty PATHEXT: Go falls back to .com;.exe;.bat;.cmd'
$m = New-Batch (Join-Path $pd 'hmrvc.bat'); Test-Run 'pathext_custom_ext_list' 'hmrvc' $m @{ PATH = $pd; PATHEXT = '.EXE;.BAT ' } -Note 'PATHEXT entry with a trailing space'
# cwd resolution (ErrDot): batch in cwd, bare name
$m = New-Batch (Join-Path $Cwd 'hmrvd.cmd'); Test-Run 'cwd_bare_errdot' 'hmrvd' $m @{ PATH = $pd } -Note 'batch only in the working directory; Go checks the cwd implicitly (ErrDot)'

# over-refusal (info): a PE file named .cmd
$pe = Join-Path $B 'pe.cmd'; Copy-Item -LiteralPath $ArgvDump -Destination $pe
$r = Invoke-Hp $X @('run', '--', $pe, 'x') 10000
Add-R 'run' 'run.pe_named_cmd' @{ exit = $r.exit; stderr = $r.stderr.Trim() } 'info' 'a real PE image named .cmd (CreateProcess would map it as an image): refusal is over-refusal, allowed by section 9.6'
# controls: ordinary exe still launches with exact argv; .exe in a directory named x.bat
$cd = Join-Path $B 'dir.bat'; New-Item -ItemType Directory -Force -Path $cd | Out-Null; $ce = Join-Path $cd 'argv dump.exe'; Copy-Item -LiteralPath $ArgvDump -Destination $ce
foreach ($t in @($ArgvDump, $ce)) {
    $argv = @('a&break>hpinj-ctl.txt', 'a"b c', '%PATH%', 'x^y', '', 'back\slash\', 'ü €')
    $ao = Join-Path $P ('argv-' + [Guid]::NewGuid().ToString('N') + '.json')
    $r = Invoke-Hp $X (@('run', '--', $t) + $argv) 10000 $Cwd @{ ARGVDUMP_OUT = $ao; ARGVDUMP_EXIT = '7' }
    $got = @(); if (Test-Path -LiteralPath $ao) { $j = Get-Content -Raw -LiteralPath $ao | ConvertFrom-Json
        foreach ($h in @($j.argv_u16)) { $sb = [System.Text.StringBuilder]::new(); for ($i = 0; $i -lt $h.Length; $i += 4) { [void]$sb.Append([char][Convert]::ToUInt16($h.Substring($i, 4), 16)) }; $got += $sb.ToString() } }
    $same = ($got.Count -eq ($argv.Count + 1)) -and ((@($got | Select-Object -Skip 1) -join "`0") -ceq ($argv -join "`0"))
    $ok = ($r.exit -eq 7) -and $same -and -not (Test-Path -LiteralPath (Join-Path $Cwd 'hpinj-ctl.txt'))
    Add-R 'run' ('run.control_exe_' + (Split-Path -Leaf $t).Replace(' ', '_')) @{ exit = $r.exit; argv_exact = $same; argc = $got.Count } (@('fail', 'pass')[[int]$ok]) 'ordinary exe launches (exit 7 passed through) and receives argv[1..] exactly'
}

foreach ($o in $owned) { if (-not $o.HasExited) { try { $o.Kill() } catch { } } }
$results | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } | Set-Content -LiteralPath $Out -Encoding utf8
$bad = @($results | Where-Object { $_.verdict -eq 'fail' }).Count
Write-Host "probes=$($results.Count) fail=$bad"
exit ([int]($bad -gt 0))
