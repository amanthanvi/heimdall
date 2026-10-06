<#
.SYNOPSIS
  Named-pipe endpoint that accepts connections and never answers (G02 X1 harness helper, not product code).
.DESCRIPTION
  \\.\pipe\<PipeName>, created with CreateNamedPipeW: protected DACL granting only the current user
  (D:P(A;;GA;;;<user SID>)), PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_FIRST_PIPE_INSTANCE, up to 8 instances.
  Each accepted client is held open without a reply until it disconnects or RunSeconds elapse; a line
  "connect <n> <utc ticks>" is appended to MarkerFile per connection (nothing is read from clients).
  A client that connected and closed before the accept was issued (ERROR_NO_DATA) is counted as
  "connect-closed-before-accept <n> <utc ticks>".
  StopFile (optional): when that file appears the helper stops accepting, waits up to 1 s for an accept that
  has already completed in the kernel to surface, records it, and exits 0. A reader that creates StopFile
  after its client process has exited and then waits for this process to exit gets a final count with no race.
  Used for: agent list timeout, Ctrl-C while waiting, and a pipe given as profile/tui --file (K14, section 9.6).
#>
param([Parameter(Mandatory = $true)][string]$PipeName, [Parameter(Mandatory = $true)][string]$MarkerFile,
      [int]$RunSeconds = 120, [string]$ReadyFile, [string]$StopFile)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class X1Stall {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int n; public IntPtr sd; public int inh; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateNamedPipeW(string name, uint open, uint mode, uint max, uint outb, uint inb, uint to, ref SA sa);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint rev, out IntPtr sd, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static IntPtr Create(string name, string sddl, bool first, out int err) {
    IntPtr sd; uint size; err = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { err = Marshal.GetLastWin32Error(); return new IntPtr(-1); }
    try {
      SA sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.sd = sd;
      // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED [| FILE_FLAG_FIRST_PIPE_INSTANCE]; BYTE|WAIT|REJECT_REMOTE
      IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, 0x3u | 0x40000000u | (first ? 0x80000u : 0u), 0x8u, 8, 65536, 65536, 0, ref sa);
      if (h == new IntPtr(-1)) err = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
}
'@
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "D:P(A;;GA;;;$me)"
$deadline = [DateTime]::UtcNow.AddSeconds($RunSeconds)
$held = New-Object System.Collections.ArrayList
$n = 0
$first = $true
function New-Instance {
    $err = 0
    $raw = [X1Stall]::Create($PipeName, $sddl, $script:first, [ref]$err)
    if ($raw -eq [IntPtr](-1)) { throw "CreateNamedPipeW failed win32=$err" }
    $script:first = $false
    $safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle($raw, $true)
    return New-Object System.IO.Pipes.NamedPipeServerStream([System.IO.Pipes.PipeDirection]::InOut, $true, $false, $safe)
}
# A faulted accept (ERROR_NO_DATA: the client connected and closed before ConnectNamedPipe) is a completed one.
function Test-Accepted { param($W, [int]$Ms) try { return $W.Wait($Ms) } catch { return $true } }
$srv = New-Instance
if ($ReadyFile) { [System.IO.File]::WriteAllText($ReadyFile, "listening $PID`n") }
while ([DateTime]::UtcNow -lt $deadline) {
    $w = $srv.WaitForConnectionAsync()
    $done = $false; $stop = $false
    while (-not $done -and [DateTime]::UtcNow -lt $deadline) {
        $done = Test-Accepted $w 200
        if (-not $done -and $StopFile -and (Test-Path -LiteralPath $StopFile)) { $stop = $true; $done = Test-Accepted $w 1000; break }
    }
    if (-not $done) { break }
    $n++
    $kind = 'connect'; if ($w.IsFaulted) { $kind = 'connect-closed-before-accept' }
    [System.IO.File]::AppendAllText($MarkerFile, ("{0} {1} {2}`n" -f $kind, $n, [DateTime]::UtcNow.Ticks))
    [void]$held.Add($srv)          # held open, never answered
    if ($stop -or ($StopFile -and (Test-Path -LiteralPath $StopFile))) { break }
    $srv = New-Instance
}
foreach ($s in $held) { try { $s.Dispose() } catch { } }
try { $srv.Dispose() } catch { }
exit 0
