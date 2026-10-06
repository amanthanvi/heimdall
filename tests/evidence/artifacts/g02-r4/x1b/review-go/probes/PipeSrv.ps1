<#
  Review probe helper (task M00-T05-x1b-review-go; not product code). Named pipe \\.\pipe\<Name>,
  protected DACL for the current user only, PIPE_REJECT_REMOTE_CLIENTS.
  Mode garbage: accept, read what arrives (<=4096 bytes, 2 s), write a non-agent reply, hold 3 s, close.
  Mode close:   accept, close immediately (no read, no write).
  Mode busy:    one instance only; accept the first client and hold it (later clients see ERROR_PIPE_BUSY).
  Mode silent:  accept, read the request, never write; hold until RunSeconds.
  Writes "<event> <bytesRead>" lines to Marker. Exits after RunSeconds or after StopFile appears.
#>
param([string]$Name, [string]$Mode, [string]$Marker, [string]$ReadyFile, [string]$StopFile, [int]$RunSeconds = 60)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RvPipe {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int n; public IntPtr sd; public int inh; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateNamedPipeW(string name, uint open, uint mode, uint max, uint outb, uint inb, uint to, ref SA sa);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint rev, out IntPtr sd, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static IntPtr Create(string name, string sddl, uint max, bool first, out int err) {
    IntPtr sd; uint size; err = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { err = Marshal.GetLastWin32Error(); return new IntPtr(-1); }
    try {
      SA sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.sd = sd;
      IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, 0x3u | 0x40000000u | (first ? 0x80000u : 0u), 0x8u, max, 65536, 65536, 0, ref sa);
      if (h == new IntPtr(-1)) err = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
}
'@
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "D:P(A;;GA;;;$me)"
$max = 8; if ($Mode -eq 'busy') { $max = 1 }
$first = $true
function New-Inst { $err = 0; $raw = [RvPipe]::Create($Name, $sddl, $max, $script:first, [ref]$err)
    if ($raw -eq [IntPtr](-1)) { throw "CreateNamedPipeW failed win32=$err" }
    $script:first = $false
    $safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle($raw, $true)
    return New-Object System.IO.Pipes.NamedPipeServerStream([System.IO.Pipes.PipeDirection]::InOut, $true, $false, $safe) }
function Log { param([string]$L) [System.IO.File]::AppendAllText($Marker, "$L`n") }
$deadline = [DateTime]::UtcNow.AddSeconds($RunSeconds)
$held = New-Object System.Collections.ArrayList
$srv = New-Inst
[System.IO.File]::WriteAllText($ReadyFile, "listening $PID`n")
while ([DateTime]::UtcNow -lt $deadline) {
    if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { break }
    $w = $srv.WaitForConnectionAsync()
    $ok = $false
    while (-not $ok -and [DateTime]::UtcNow -lt $deadline) { try { $ok = $w.Wait(200) } catch { $ok = $true }; if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { break } }
    if (-not $ok) { break }
    if ($Mode -eq 'close') { Log 'accept-close 0'; $srv.Dispose(); $srv = New-Inst; continue }
    if ($Mode -eq 'busy') { Log 'accept-hold 0'; [void]$held.Add($srv); while ([DateTime]::UtcNow -lt $deadline -and -not ($StopFile -and (Test-Path -LiteralPath $StopFile))) { Start-Sleep -Milliseconds 200 }; break }
    $buf = New-Object byte[] 4096; $n = 0
    try { $t = $srv.ReadAsync($buf, 0, 4096); if ($t.Wait(2000)) { $n = $t.Result } } catch { }
    Log ("accept-read " + $n + " " + [BitConverter]::ToString($buf, 0, [Math]::Min($n, 16)))
    if ($Mode -eq 'garbage') {
        $g = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.0 200 OK`r`n`r`nnot an agent")
        try { $srv.Write($g, 0, $g.Length); $srv.Flush() } catch { Log ('write-error ' + $_.Exception.HResult) }
        Start-Sleep -Milliseconds 3000; $srv.Dispose(); $srv = New-Inst; continue }
    [void]$held.Add($srv); $srv = New-Inst
}
foreach ($s in $held) { try { $s.Dispose() } catch { } }
try { $srv.Dispose() } catch { }
exit 0
