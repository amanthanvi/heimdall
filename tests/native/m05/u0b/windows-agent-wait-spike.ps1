<#
.SYNOPSIS
  U0b spike (Windows): how long does the in-box ssh.exe / Git wait for an SSH agent's
  answer to REQUEST_IDENTITIES (type 11)?  Measurement only; no admin, no modules.

.DESCRIPTION
  * Serves a FAKE agent on a private named pipe \\.\pipe\hm-spike-<random hex>.
    It answers REQUEST_IDENTITIES with ZERO identities after a delay D, and
    SSH_AGENT_FAILURE (5) to everything else. It never touches the real
    ssh-agent service, openssh-ssh-agent, HKCU\Environment or %PROGRAMDATA%\ssh.
  * For each D it runs  C:\Windows\System32\OpenSSH\ssh.exe -vvv ...  and (if git is on PATH)
    git ls-remote over that same ssh command, from a canary-named scratch Git repository.
  * With zero identities the login fails BY DESIGN. What is measured: did ssh read the
    identities answer after D (from the -vvv log) and how long did the run take.
  * Only <Target>:<Port> (an sshd you control) is contacted. Your ~/.ssh keys are not used:
    an explicit nonexistent IdentityFile stops ssh probing the default key files.
  * Results: one JSON + one summary file in -OutDir. The scratch directory is removed.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows-agent-wait-spike.ps1 -Target 192.168.1.20 -Port 22 -User me
#>
param(
  [Parameter(Mandatory = $true)][string]$Target,
  [Parameter(Mandatory = $true)][int]$Port,
  [Parameter(Mandatory = $true)][string]$User,
  [double[]]$Delays = @(0, 0.5, 1, 2, 5, 10, 30),
  [string]$OutDir = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
$SshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'

Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.IO; using System.IO.Pipes;
using System.Text; using System.Threading;
public class HmMsg { public int Conn, Seq, Type, Len; public string Ext; public bool HasCanary, HasCwd;
                     public double T; public double AnsweredT; public bool WriteFailed; }
public class HmAgent {
  string name, canary, cwd; volatile bool stop; public double DelaySec;
  public List<HmMsg> Log = new List<HmMsg>(); object gate = new object(); int conns;
  DateTime t0 = DateTime.UtcNow;
  public HmAgent(string n, string c, string w) { name = n; canary = c; cwd = w; }
  public void Start() { Thread t = new Thread(Accept); t.IsBackground = true; t.Start(); }
  public void Stop() { stop = true; try { var c = new NamedPipeClientStream(".", name); c.Connect(1000); c.Dispose(); } catch { } }
  public void Clear() { lock (gate) { Log = new List<HmMsg>(); } }
  public HmMsg[] Snapshot() { lock (gate) { return Log.ToArray(); } }
  double Now() { return Math.Round((DateTime.UtcNow - t0).TotalSeconds, 3); }
  void Accept() {
    while (!stop) {
      var s = new NamedPipeServerStream(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                                        PipeTransmissionMode.Byte, PipeOptions.None);
      try { s.WaitForConnection(); } catch { s.Dispose(); if (stop) return; continue; }
      if (stop) { s.Dispose(); return; }
      int id; lock (gate) { id = ++conns; }
      Thread t = new Thread(delegate() { Serve(s, id); }); t.IsBackground = true; t.Start();
    }
  }
  static byte[] ReadN(Stream s, int n) {
    byte[] b = new byte[n]; int got = 0;
    while (got < n) { int r = s.Read(b, got, n - got); if (r <= 0) return null; got += r; }
    return b;
  }
  static bool Has(byte[] hay, string needle) {
    byte[] nd = Encoding.UTF8.GetBytes(needle);
    for (int i = 0; i + nd.Length <= hay.Length; i++) {
      int j = 0; while (j < nd.Length && hay[i + j] == nd[j]) j++;
      if (j == nd.Length) return true;
    }
    return false;
  }
  void Serve(NamedPipeServerStream s, int id) {
    int seq = 0;
    try {
      using (s) {
        while (true) {
          byte[] h = ReadN(s, 4); if (h == null) break;
          int n = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
          if (n < 0 || n > 1048576) break;
          byte[] b = n > 0 ? ReadN(s, n) : new byte[0]; if (n > 0 && b == null) break;
          byte[] all = new byte[4 + n]; Array.Copy(h, all, 4); Array.Copy(b, 0, all, 4, n);
          var m = new HmMsg(); m.Conn = id; m.Seq = ++seq; m.Len = n; m.Type = n > 0 ? b[0] : -1; m.T = Now();
          if (m.Type == 27 && n >= 5) {
            int l = (b[1] << 24) | (b[2] << 16) | (b[3] << 8) | b[4];
            if (l >= 0 && 5 + l <= n) m.Ext = Encoding.ASCII.GetString(b, 5, l);
          }
          m.HasCanary = Has(all, canary); m.HasCwd = Has(all, cwd);
          lock (gate) { Log.Add(m); }
          byte[] resp;
          if (m.Type == 11) {   // identities answer: zero keys, after the delay
            Thread.Sleep((int)(DelaySec * 1000));
            resp = new byte[] { 0, 0, 0, 5, 12, 0, 0, 0, 0 };
          } else resp = new byte[] { 0, 0, 0, 1, 5 };   // SSH_AGENT_FAILURE
          try { s.Write(resp, 0, resp.Length); s.Flush(); m.AnsweredT = Now(); }
          catch (IOException) { m.WriteFailed = true; break; }
        }
      }
    } catch (Exception) { }
  }
}
'@

function Quote([string]$s) { '"' + ($s -replace '"', '\"') + '"' }
function ShQuote([string]$s) { "'" + ($s -replace "'", "'\''") + "'" }

function Invoke-Native([string]$Exe, [string]$ArgLine, [string]$Cwd, [int]$TimeoutSec) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe; $psi.Arguments = $ArgLine; $psi.WorkingDirectory = $Cwd
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  foreach ($v in 'GIT_SSH_COMMAND', 'GIT_SSH', 'SSH_AUTH_SOCK') { [void]$psi.EnvironmentVariables.Remove($v) }
  $psi.EnvironmentVariables['MSYS_NO_PATHCONV'] = '1'; $psi.EnvironmentVariables['GIT_TERMINAL_PROMPT'] = '0'
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
  if ($timedOut) { $p.Kill(); $p.WaitForExit() }
  $sw.Stop()
  [pscustomobject]@{ Exit = $p.ExitCode; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 3)
                     Out = $o.Result; Err = $e.Result; TimedOut = $timedOut }
}

$hex = -join ((1..8) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('hm-spike-' + $hex)
$canary = 'HM-SPIKE-CWD-' + $hex
$cwd = Join-Path $scratch $canary
$pipe = 'hm-spike-' + $hex
$pipePath = '\\.\pipe\' + $pipe
$knownHosts = Join-Path $scratch 'known_hosts'
$noKey = Join-Path $scratch 'no-such-identity'
New-Item -ItemType Directory -Path $cwd -Force | Out-Null
$git = Get-Command git.exe -ErrorAction SilentlyContinue
if ($git) { [void](Invoke-Native $git.Source 'init -q' $cwd 60) }

$agent = New-Object HmAgent($pipe, $canary, $cwd)
$agent.Start()
$runs = @()
try {
  $ver = @{}
  $ver.ssh_V = (Invoke-Native $SshExe '-V' $cwd 30).Err.Trim()
  $ver.git_version = if ($git) { (Invoke-Native $git.Source '--version' $cwd 30).Out.Trim() } else { 'git not on PATH' }
  $ver.os = [System.Environment]::OSVersion.VersionString
  $ver.powershell = $PSVersionTable.PSVersion.ToString()

  $opts = @('-vvv', '-F', 'NUL', '-o', "IdentityAgent=$pipePath", '-o', 'BatchMode=yes',
            '-o', 'PreferredAuthentications=publickey', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', "UserKnownHostsFile=$knownHosts", '-o', 'GlobalKnownHostsFile=NUL',
            '-o', "IdentityFile=$noKey")
  $sshArgs = (($opts | ForEach-Object { Quote $_ }) -join ' ') + " -p $Port " + (Quote "$User@$Target") + ' exit'
  $shCmd = (ShQuote 'C:/Windows/System32/OpenSSH/ssh.exe') + ' ' + (($opts | ForEach-Object { ShQuote $_ }) -join ' ')
  $gitArgs = '-c ' + (Quote "core.sshCommand=$shCmd") + ' ls-remote ' + (Quote "ssh://$User@${Target}:$Port/nonexistent.git")

  foreach ($d in $Delays) {
    foreach ($client in 'ssh', 'git') {
      if ($client -eq 'git' -and -not $git) { continue }
      $agent.DelaySec = $d; $agent.Clear()
      if ($client -eq 'ssh') { $r = Invoke-Native $SshExe $sshArgs $cwd ([int]$d + 150) }
      else                   { $r = Invoke-Native $git.Source $gitArgs $cwd ([int]$d + 150) }
      Start-Sleep -Milliseconds 300
      $msgs = @($agent.Snapshot())
      $log = $r.Err -split "`r?`n"
      $got = [bool]($log -match 'agent returned \d+ keys|agent contains no identities')
      $bad = [bool]($log -match 'ssh_fetch_identitylist|agent communication|communication with agent|error fetching identities')
      $answer = if ($got) { 'yes' } elseif ($bad) { 'no' } else { 'unknown' }
      $runs += [ordered]@{
        client = $client; delay_s = $d; exit_code = $r.Exit; elapsed_s = $r.Seconds; timed_out = $r.TimedOut
        answer_received = $answer
        agent_answer_written = [bool]($msgs | Where-Object { $_.Type -eq 11 -and -not $_.WriteFailed -and $_.AnsweredT -gt 0 })
        any_canary_or_cwd_in_agent_messages = [bool]($msgs | Where-Object { $_.HasCanary -or $_.HasCwd })
        messages = @($msgs | ForEach-Object { [ordered]@{ conn = $_.Conn; seq = $_.Seq; type = $_.Type; ext = $_.Ext; len = $_.Len
                                                      has_canary = $_.HasCanary; has_cwd = $_.HasCwd; t = $_.T } })
        agent_log_lines = @($log | Where-Object { $_ -match 'agent|identit|session-bind|Permission denied|Connection (closed|reset)' } | Select-Object -First 40)
        stderr_tail = @($log | Where-Object { $_ -and $_ -notmatch '^debug' } | Select-Object -Last 6)
      }
      Write-Host ('{0,-3} D={1,-4} exit={2,-3} elapsed={3,7}s answer_received={4}' -f $client, $d, $r.Exit, $r.Seconds, $answer)
    }
  }
  $res = [ordered]@{ versions = $ver; target = "${Target}:$Port"; canary_in_cwd = $canary; runs = $runs
    note = 'fake agent returns zero identities, so every login fails by design; see answer_received and elapsed_s' }
  [System.IO.File]::WriteAllText((Join-Path $OutDir 'windows-agent-wait-spike-results.json'),
    ($res | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding $false))
  $lines = @("ssh: $($ver.ssh_V)", "git: $($ver.git_version)", "os: $($ver.os)", '')
  $lines += $runs | ForEach-Object { '{0,-3} D={1,-4} exit={2,-3} elapsed={3,7}s answer_received={4} canary/cwd_in_agent_msgs={5}' -f $_.client, $_.delay_s, $_.exit_code, $_.elapsed_s, $_.answer_received, $_.any_canary_or_cwd_in_agent_messages }
  [System.IO.File]::WriteAllLines((Join-Path $OutDir 'windows-agent-wait-spike-summary.txt'), $lines)
  Write-Host "Results in $OutDir (windows-agent-wait-spike-results.json, windows-agent-wait-spike-summary.txt)"
}
finally {
  $agent.Stop()
  Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
