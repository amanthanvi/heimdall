<#
  X1 review probes (M00-T05-x1-g02-native-review). Harness code for an independent review, not product code.
  Runs against the same staged layout as Invoke-G02WindowsX1.ps1 (-Root) and writes <OutDir>\review-probes.json.
  Sections:
    identity   a review-owned pipe server (current-user-only protected DACL, PIPE_REJECT_REMOTE_CLIENTS, first instance,
               1 instance) answers `agent list` with a 0-key identities answer and records, from the SERVER side:
               (a) GetNamedPipeClientProcessId == the heimdall-proto PID, (b) the Win32-OpenSSH ssh-agent method
               (OpenProcess + OpenProcessToken + DuplicateToken + TokenUser, as in contrib/win32/win32compat/ssh-agent/
               agent.c get_con_client_info) yields the current user, (c) ImpersonateNamedPipeClient + OpenThreadToken +
               TokenImpersonationLevel. Also for `profile show --file <that pipe>` (server never writes).
    argv       extra argv edge cases through `run` (argv0 path with space + non-ASCII, a 16,000-char argument,
               300 arguments, quote/backslash runs), each with a direct-launch control.
    ctrlc      two ^C keystrokes 200 ms apart into `run` (child counts 2, launcher waits, exits 42); ^C to `run -- timeout.exe`
               compared with timeout.exe run directly (exit code parity).
    resolution relative .\name, explicit .exe, upper-case name.
  Safety: non-elevated only; no windows; only processes started here are stopped (own handles); output redacted.
#>
param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$OutDir,
      [string[]]$Candidates = @('go', 'rust'), [string[]]$Sections = @('identity', 'argv', 'ctrlc', 'resolution'))
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Candidates = @($Candidates | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Sections = @($Sections | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'refusing to run elevated'; exit 2 }
$Utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Scratch = Join-Path $Root 'review-scratch'; New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $Root 'tools\G02X1Native.cs')))
Import-Module (Join-Path $Root 'g03\G03Common.psm1') -Force
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class RvPipe {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int n; public IntPtr sd; public int inh; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateNamedPipeW(string name, uint open, uint mode, uint max, uint outb, uint inb, uint to, ref SA sa);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint rev, out IntPtr sd, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetNamedPipeClientProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateToken(IntPtr tok, int level, out IntPtr dup);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr th, uint access, bool asSelf, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  public static IntPtr Create(string name, string sddl, out int err) {
    IntPtr sd; uint size; err = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { err = Marshal.GetLastWin32Error(); return new IntPtr(-1); }
    try {
      SA sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.sd = sd;
      // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE; BYTE | WAIT | REJECT_REMOTE; 1 instance
      IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, 0x3u | 0x40000000u | 0x80000u, 0x8u, 1, 65536, 65536, 0, ref sa);
      if (h == new IntPtr(-1)) err = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
  static string TokenUserSid(IntPtr tok) {
    int len; GetTokenInformation(tok, 1, IntPtr.Zero, 0, out len);
    IntPtr b = Marshal.AllocHGlobal(len);
    try { if (!GetTokenInformation(tok, 1, b, len, out len)) return "error:tokenuser:" + Marshal.GetLastWin32Error();
          return new SecurityIdentifier(Marshal.ReadIntPtr(b)).Value; } finally { Marshal.FreeHGlobal(b); }
  }
  // Win32-OpenSSH ssh-agent method (agent.c get_con_client_info): client process token, not the pipe impersonation token.
  public static string ProcessMethod(IntPtr h, string mySid, int expectPid) {
    uint pid; if (!GetNamedPipeClientProcessId(h, out pid)) return "error:clientpid:" + Marshal.GetLastWin32Error();
    string pidm = (pid == (uint)expectPid) ? "pid_is_heimdall" : "pid_other";
    IntPtr p = OpenProcess(0x0400 | 0x0040, false, pid); if (p == IntPtr.Zero) return pidm + ";error:openprocess:" + Marshal.GetLastWin32Error();
    IntPtr t = IntPtr.Zero, d = IntPtr.Zero;
    try {
      if (!OpenProcessToken(p, 0x0008 | 0x0002, out t)) return pidm + ";error:openprocesstoken:" + Marshal.GetLastWin32Error();
      if (!DuplicateToken(t, 2, out d)) return pidm + ";error:duplicatetoken:" + Marshal.GetLastWin32Error();
      string s = TokenUserSid(t);
      return pidm + ";" + (s == mySid ? "same_user" : (s.StartsWith("error") ? s : "other_user"));
    } finally { if (d != IntPtr.Zero) CloseHandle(d); if (t != IntPtr.Zero) CloseHandle(t); CloseHandle(p); }
  }
  // ImpersonateNamedPipeClient + OpenThreadToken + TokenImpersonationLevel (9) + TokenUser, then RevertToSelf.
  public static string ImpersonationMethod(IntPtr h, string mySid) {
    if (!ImpersonateNamedPipeClient(h)) return "error:impersonate:" + Marshal.GetLastWin32Error();
    IntPtr tok = IntPtr.Zero;
    try {
      if (!OpenThreadToken(GetCurrentThread(), 0x0008, true, out tok)) return "error:openthreadtoken:" + Marshal.GetLastWin32Error();
      int len; IntPtr b = Marshal.AllocHGlobal(4);
      string lvl;
      try { if (!GetTokenInformation(tok, 9, b, 4, out len)) lvl = "error:level:" + Marshal.GetLastWin32Error();
            else { int v = Marshal.ReadInt32(b); lvl = v == 0 ? "Anonymous" : v == 1 ? "Identification" : v == 2 ? "Impersonation" : v == 3 ? "Delegation" : ("level" + v); } }
      finally { Marshal.FreeHGlobal(b); }
      string s = TokenUserSid(tok);
      return lvl + ";" + (s == mySid ? "same_user" : (s.StartsWith("error") ? s : "other_user"));
    } finally { RevertToSelf(); if (tok != IntPtr.Zero) CloseHandle(tok); }
  }
}
'@
$MySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ArgvDump = Join-Path $Root 'helpers\argvdump.exe'
$HostExe = (Get-Process -Id $PID).Path
$Results = [ordered]@{ script = 'tests/evidence/artifacts/g02-r4/x1-review/Invoke-X1ReviewProbes.ps1'; powershell = $PSVersionTable.PSVersion.ToString(); started_at = [DateTime]::UtcNow.ToString('o'); rows = New-Object System.Collections.ArrayList }
function Protect-Rv { param([AllowNull()][string]$T)
    if ($null -eq $T) { return $null }
    foreach ($p in @(@($Root, '<scratch>'), @($env:LOCALAPPDATA, '<winhome>\AppData\Local'), @($env:USERPROFILE, '<winhome>'))) {
        $T = [regex]::Replace($T, [regex]::Escape($p[0]), $p[1].Replace('$', '$$'), 'IgnoreCase') }
    foreach ($v in @($env:USERNAME, $env:COMPUTERNAME)) { if ($v) { $T = [regex]::Replace($T, [regex]::Escape($v), '<redacted>', 'IgnoreCase') } }
    $T = [regex]::Replace($T, 'S-1-5-21-\d+-\d+-\d+(-\d+)?', 'S-1-5-21-<redacted>')
    return [regex]::Replace($T, 'HEIMDALL_CANARY_[A-Za-z0-9_]*', '[REDACTED_CANARY]') }
function Add-Rv { param([string]$Cand, [string]$Id, $Obs)
    $o = [ordered]@{ candidate = $Cand; id = $Id; observed = $Obs }
    [void]$Results.rows.Add($o); [Console]::Out.WriteLine(('{0,-5} {1}' -f $Cand, $Id)) }

$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"
$env:SSH_AUTH_SOCK = '\\.\pipe\hm-x1rev-none-' + (New-G03RandomHex 4)
$Exe = @{}; foreach ($c in $Candidates) { $Exe[$c] = Join-Path $Root "bin\$c\heimdall-proto.exe" }
$Owned = New-Object System.Collections.ArrayList

function Start-Proc { param([string]$File, [string]$ArgLine, [string]$Cwd = $Scratch, [hashtable]$Env = @{})
    $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $File; $psi.Arguments = $ArgLine
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Cwd
    foreach ($k in $Env.Keys) { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    $p = [System.Diagnostics.Process]::Start($psi); $p.StandardInput.Close()
    $o = [pscustomobject]@{ P = $p; Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync(); Sw = [Diagnostics.Stopwatch]::StartNew() }
    [void]$Owned.Add($o); return $o }
function Stop-Proc { param($o, [int]$Ms)
    $ex = $o.P.WaitForExit($Ms); $ms = $o.Sw.ElapsedMilliseconds
    if (-not $ex) { try { $o.P.Kill() } catch { }; [void]$o.P.WaitForExit(5000) }
    $code = $null; if ($ex) { $code = [uint32]([long]$o.P.ExitCode -band 0xFFFFFFFFL) }
    $out = ''; $err = ''; try { if ($o.Out.Wait(3000)) { $out = $o.Out.Result }; if ($o.Err.Wait(3000)) { $err = $o.Err.Result } } catch { }
    return [pscustomobject]@{ Exited = $ex; Exit = $code; Ms = $ms; Out = $out; Err = $err } }

try {
# ============================================================ identity (server-side view of the client)
if ($Sections -contains 'identity') {
    foreach ($c in $Candidates) {
        foreach ($mode in @('agent_list', 'profile_file')) {
            $name = 'hm-x1rev-id-' + $c + '-' + $mode + '-' + (New-G03RandomHex 4)
            $err = 0; $raw = [RvPipe]::Create($name, "D:P(A;;GA;;;$MySid)", [ref]$err)
            if ($raw -eq [IntPtr](-1)) { throw "CreateNamedPipeW failed $err" }
            $safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle($raw, $true)
            $srv = New-Object System.IO.Pipes.NamedPipeServerStream([System.IO.Pipes.PipeDirection]::InOut, $true, $false, $safe)
            $wait = $srv.WaitForConnectionAsync()
            if ($mode -eq 'agent_list') { $pr = Start-Proc $Exe[$c] (Join-G03WinArgs @('agent', 'list', '--socket', "\\.\pipe\$name", '--timeout-ms', '5000', '--json')) }
            else { $pr = Start-Proc $Exe[$c] (Join-G03WinArgs @('profile', 'show', '--file', "\\.\pipe\$name", '--json')) }
            $connected = $wait.Wait(5000)
            $obs = [ordered]@{ mode = $mode; connected = $connected }
            if ($connected) {
                $h = $safe.DangerousGetHandle()
                $obs['openssh_process_token_method_before_read'] = [RvPipe]::ProcessMethod($h, $MySid, $pr.P.Id)
                $obs['impersonation_before_read'] = [RvPipe]::ImpersonationMethod($h, $MySid)
                $buf = New-Object byte[] 64; $got = 0
                try { $rt = $srv.ReadAsync($buf, 0, 64); if ($rt.Wait(3000)) { $got = $rt.Result } else { $got = -1 } } catch { $obs['read_error'] = $_.Exception.GetBaseException().GetType().Name }
                $obs['bytes_read_within_3s'] = $got
                if ($got -gt 0) { $obs['request_hex'] = (($buf[0..($got - 1)] | ForEach-Object { $_.ToString('x2') }) -join '') }
                if ($got -gt 0) {
                    $obs['impersonation_after_read'] = [RvPipe]::ImpersonationMethod($h, $MySid)
                    $obs['openssh_process_token_method_after_read'] = [RvPipe]::ProcessMethod($h, $MySid, $pr.P.Id)
                    if ($mode -eq 'agent_list') { try { $srv.Write([byte[]](0, 0, 0, 5, 12, 0, 0, 0, 0), 0, 9); $srv.Flush() } catch { $obs['write_error'] = $_.Exception.GetType().Name } }
                }
            }
            $r = Stop-Proc $pr 4000
            $obs['heimdall_exited'] = $r.Exited; $obs['heimdall_exit'] = $r.Exit; $obs['ms'] = $r.Ms; $obs['stdout'] = Protect-Rv $r.Out; $obs['stderr'] = Protect-Rv $r.Err
            try { $srv.Dispose() } catch { }
            Add-Rv $c ('identity.' + $mode) $obs
        }
    }
}

# ============================================================ argv edge cases
function Get-U16 { param([string]$S) $sb = New-Object System.Text.StringBuilder; foreach ($ch in $S.ToCharArray()) { [void]$sb.Append(([int]$ch).ToString('x4')) }; return $sb.ToString() }
function Invoke-Argv { param([string]$Exe0, [string[]]$Pre, [string[]]$Vals, [string]$Cwd = $Scratch)
    $out = Join-Path $Scratch ('argv-' + (New-G03RandomHex 4) + '.json')
    $pr = Start-Proc $Exe0 (Join-G03WinArgs ($Pre + $Vals)) $Cwd @{ 'ARGVDUMP_OUT' = $out }
    $r = Stop-Proc $pr 20000
    $rep = $null; if (Test-Path -LiteralPath $out) { $rep = [System.IO.File]::ReadAllText($out, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $out }
    return [pscustomobject]@{ R = $r; Rep = $rep } }
function Test-Argv { param($Rep, [string[]]$Vals)
    if ($null -eq $Rep -or $null -eq $Rep.PSObject.Properties['argv_u16']) { return 'no report' }
    $got = @($Rep.argv_u16)
    if ($got.Count - 1 -ne $Vals.Count) { return ('argc ' + ($got.Count - 1) + ' expected ' + $Vals.Count) }
    $bad = @(); for ($i = 0; $i -lt $Vals.Count; $i++) { if ($got[$i + 1] -ne (Get-U16 $Vals[$i])) { $bad += $i } }
    if ($bad.Count) { return ('mismatch at ' + ($bad -join ',')) } return 'exact' }
if ($Sections -contains 'argv') {
    $long = ('L' * 7999) + ' ' + ('M' * 7999) + '\'
    $many = @(1..300 | ForEach-Object { 'arg ' + $_ + ' "q"' })
    $sets = [ordered]@{
        'quote_backslash_runs' = @('\\\"', 'a\\\\"b c', '\"\"', '"" ""', 'end\\\\', ' lead space', 'trail space ', "`t", ('nonbmp ' + [char]::ConvertFromUtf32(0x1F409) + ' ' + [char]::ConvertFromUtf32(0x20000)), '=', '/c', '--', '-')
        'long_16000_chars' = @($long)
        'many_300_args' = $many }
    foreach ($c in $Candidates) {
        foreach ($k in $sets.Keys) {
            $vals = [string[]]$sets[$k]
            $ctl = Invoke-Argv $ArgvDump @() $vals
            $res = Invoke-Argv $Exe[$c] @('run', '--', $ArgvDump) $vals
            Add-Rv $c ('argv.' + $k) ([ordered]@{ values = $vals.Count; control_direct = (Test-Argv $ctl.Rep $vals); via_run = (Test-Argv $res.Rep $vals); heimdall_exit = $res.R.Exit; stdout_bytes = $res.R.Out.Length; stderr = (Protect-Rv $res.R.Err) })
        }
        # argv[0]: child executable in a directory with a space and non-ASCII, file name with a space
        $d = Join-Path $Scratch ('argv0 dir ' + [char]0x00FC + ' ' + [char]0x6771); New-Item -ItemType Directory -Force -Path $d | Out-Null
        $child = Join-Path $d 'argv dump.exe'; Copy-Item -LiteralPath $ArgvDump -Destination $child -Force
        $res = Invoke-Argv $Exe[$c] @('run', '--', $child) @('x y')
        $a0 = $null; $exeSame = $null
        if ($res.Rep) { $a0 = (@($res.Rep.argv_u16)[0] -eq (Get-U16 $child)); $exeSame = ([string]$res.Rep.exe -ieq $child) }
        Add-Rv $c 'argv.argv0_space_nonascii_path' ([ordered]@{ ran = [bool]$res.Rep; argv0_equals_given_path = $a0; exe_is_that_file = $exeSame; argv1 = $(if ($res.Rep) { Test-Argv $res.Rep @('x y') } else { $null }); heimdall_exit = $res.R.Exit; stderr = (Protect-Rv $res.R.Err) })
    }
}

# ============================================================ ctrlc extras
if ($Sections -contains 'ctrlc') {
    foreach ($c in $Candidates) {
        $cf = Join-Path $Scratch ('rv-ctrlc2-' + $c + '.json'); foreach ($f in @($cf, ($cf + '.ready'))) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f } }
        $env:ARGVDUMP_CTRLC = $cf; $env:ARGVDUMP_EXIT = '42'
        try { $pty = [X1Pty]::Start((Join-G03WinArgs @($Exe[$c], 'run', '--', $ArgvDump)), $Scratch, 100, 30, $null, $null) } finally { Remove-Item env:ARGVDUMP_CTRLC; Remove-Item env:ARGVDUMP_EXIT }
        $dl = [DateTime]::UtcNow.AddSeconds(15); while (-not (Test-Path -LiteralPath ($cf + '.ready')) -and [DateTime]::UtcNow -lt $dl -and -not $pty.HasExited) { Start-Sleep -Milliseconds 20 }
        $ready = Test-Path -LiteralPath ($cf + '.ready')
        if ($ready) { Start-Sleep -Milliseconds 300; $pty.Write([byte[]](3)); Start-Sleep -Milliseconds 200; $alive1 = -not $pty.HasExited; $pty.Write([byte[]](3)); Start-Sleep -Milliseconds 300; $alive2 = -not $pty.HasExited } else { $alive1 = $null; $alive2 = $null }
        $ex = $pty.WaitExit(15000); if (-not $ex) { [void]$pty.Kill() }
        $code = $null; if ($ex) { $code = $pty.ExitCode }
        $cr = $null; if (Test-Path -LiteralPath $cf) { $cr = [System.IO.File]::ReadAllText($cf, $Utf8) | ConvertFrom-Json }
        $pty.Dispose()
        Add-Rv $c 'ctrlc.run_two_keystrokes' ([ordered]@{ child_ready = $ready; heimdall_alive_after_first = $alive1; heimdall_alive_after_second = $alive2; child_interrupts = $(if ($cr) { $cr.interrupts } else { $null }); heimdall_exit = $code; killed_by_review = (-not $ex) })
    }
    # timeout.exe (default console handler: killed by CTRL_C) direct vs through run
    $to = Join-Path $env:SystemRoot 'System32\timeout.exe'
    $variants = New-Object System.Collections.ArrayList; [void]$variants.Add(@('direct', @($to, '/t', '20', '/nobreak'))); foreach ($c in $Candidates) { [void]$variants.Add(@($c, @($Exe[$c], 'run', '--', $to, '/t', '20', '/nobreak'))) }
    foreach ($v in $variants) {
        $pty = [X1Pty]::Start((Join-G03WinArgs ([string[]]$v[1])), $Scratch, 100, 30, $null, $null)
        Start-Sleep -Milliseconds 1500
        $alive = -not $pty.HasExited
        $t0 = [DateTime]::UtcNow.Ticks; $pty.Write([byte[]](3))
        $ex = $pty.WaitExit(10000); if (-not $ex) { [void]$pty.Kill() }
        $code = $null; if ($ex) { $code = $pty.ExitCode }
        $ms = $null; if ($ex -and $pty.ExitTicksUtc -gt 0) { $ms = [int](($pty.ExitTicksUtc - $t0) / 10000) }
        $pty.Dispose()
        Add-Rv $v[0] 'ctrlc.timeout_exe_keystroke' ([ordered]@{ alive_before = $alive; exit = $code; exit_hex = $(if ($null -ne $code) { '0x' + ([uint32]$code).ToString('X8') } else { $null }); exit_ms_after_keystroke = $ms; killed_by_review = (-not $ex) })
    }
}

# ============================================================ resolution extras
if ($Sections -contains 'resolution') {
    foreach ($c in $Candidates) {
        $base = Join-Path $Scratch ('rv-res-' + $c); if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
        $app = Join-Path $base 'app'; $pathDir = Join-Path $base 'pathdir'; $cwdDir = Join-Path $base 'cwd'
        New-Item -ItemType Directory -Force -Path $app, $pathDir, $cwdDir | Out-Null
        Copy-Item -LiteralPath $Exe[$c] -Destination (Join-Path $app 'heimdall-proto.exe')
        foreach ($d in @($pathDir, $cwdDir)) { Copy-Item -LiteralPath $ArgvDump -Destination (Join-Path $d 'hmx1probe.exe') }
        $labels = @{ $pathDir = 'path_dir'; $cwdDir = 'cwd_dir' }
        foreach ($nm in @('.\hmx1probe', 'hmx1probe.exe', 'HMX1PROBE', '.\hmx1probe.exe')) {
            $out = Join-Path $base ('rep-' + (New-G03RandomHex 3) + '.json'); $saved = $env:PATH; $env:PATH = $saved + ';' + $pathDir
            try { $pr = Start-Proc (Join-Path $app 'heimdall-proto.exe') (Join-G03WinArgs @('run', '--', $nm)) $cwdDir @{ 'ARGVDUMP_OUT' = $out }; $r = Stop-Proc $pr 15000 } finally { $env:PATH = $saved }
            $who = 'none'
            if (Test-Path -LiteralPath $out) { $rep = [System.IO.File]::ReadAllText($out, $Utf8) | ConvertFrom-Json; Remove-Item -LiteralPath $out
                $dir = Split-Path -Parent ([string]$rep.exe); $who = 'unknown'; foreach ($k in $labels.Keys) { if ($dir -ieq $k) { $who = $labels[$k] } } }
            Add-Rv $c ('resolution.' + ($nm -replace '[^A-Za-z0-9.]', '_')) ([ordered]@{ name = $nm; ran = $who; exit = $r.Exit; stderr = (Protect-Rv $r.Err) })
        }
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }
}
} catch {
    Add-Rv 'host' 'review.error' ([ordered]@{ error = (Protect-Rv $_.Exception.Message); at = (Protect-Rv $_.InvocationInfo.PositionMessage) })
} finally {
    foreach ($o in @($Owned)) { try { if (-not $o.P.HasExited) { $o.P.Kill(); [void]$o.P.WaitForExit(3000) } } catch { } }
}
$Results['finished_at'] = [DateTime]::UtcNow.ToString('o')
$json = Protect-Rv ($Results | ConvertTo-Json -Depth 10)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'review-probes.json'), $json + "`n", $Utf8)
[Console]::Out.WriteLine('done rows=' + $Results.rows.Count)
exit 0
