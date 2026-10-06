<#
  Review probe helper (M00-T05-x1b-review-rust; harness code, not product code).
  One named-pipe server in its own process: \\.\pipe\<PipeName>, protected current-user-only DACL,
  PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_FIRST_PIPE_INSTANCE, one instance. Modes:
    answer      read the 5-byte request, reply SSH_AGENT_IDENTITIES_ANSWER with one fixture key blob
    answermsg   same, pipe type/read mode MESSAGE
    refuse      read the request, reply SSH_AGENT_FAILURE
    close       accept, then disconnect at once
    outbound    PIPE_ACCESS_OUTBOUND server (client may only read); accept and hold
  Every accepted client appends "connect <n>" and the hex of the first bytes read to MarkerFile.
  Exits after RunSeconds or when StopFile appears.
#>
param([Parameter(Mandatory = $true)][string]$PipeName, [Parameter(Mandatory = $true)][string]$Mode,
      [Parameter(Mandatory = $true)][string]$MarkerFile, [string]$ReadyFile, [string]$StopFile, [int]$RunSeconds = 120)
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
  public static IntPtr Create(string name, string sddl, uint access, uint mode, out int err) {
    IntPtr sd; uint size; err = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { err = Marshal.GetLastWin32Error(); return new IntPtr(-1); }
    try {
      SA sa = new SA(); sa.n = Marshal.SizeOf(typeof(SA)); sa.sd = sd;
      IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, access | 0x40000000u | 0x80000u, mode | 0x8u, 1, 65536, 65536, 0, ref sa);
      if (h == new IntPtr(-1)) err = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
}
'@
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "D:P(A;;GA;;;$me)"
$access = 0x3; $pmode = 0x0; $dir = [System.IO.Pipes.PipeDirection]::InOut
if ($Mode -eq 'outbound') { $access = 0x2; $dir = [System.IO.Pipes.PipeDirection]::Out }
if ($Mode -eq 'answermsg') { $pmode = 0x4 -bor 0x2 }
function New-Inst {
    $err = 0
    $raw = [RvPipe]::Create($PipeName, $sddl, [uint32]$access, [uint32]$pmode, [ref]$err)
    if ($raw -eq [IntPtr](-1)) { throw "CreateNamedPipeW failed win32=$err" }
    $safe = New-Object Microsoft.Win32.SafeHandles.SafePipeHandle($raw, $true)
    return New-Object System.IO.Pipes.NamedPipeServerStream($dir, $true, $false, $safe)
}
function SStr([byte[]]$b) { $l = [BitConverter]::GetBytes([uint32]$b.Length); [Array]::Reverse($l); return [byte[]]($l + $b) }
$blob = [byte[]]((SStr ([Text.Encoding]::ASCII.GetBytes('ssh-ed25519'))) + (SStr ([byte[]](,7 * 32))))
$body = [byte[]](@(12) + [byte[]](0, 0, 0, 1) + (SStr $blob) + (SStr ([Text.Encoding]::ASCII.GetBytes('review fixture'))))
$l = [BitConverter]::GetBytes([uint32]$body.Length); [Array]::Reverse($l)
$answer = [byte[]]($l + $body)
$fail = [byte[]](0, 0, 0, 1, 5)
$deadline = [DateTime]::UtcNow.AddSeconds($RunSeconds)
$n = 0
$srv = New-Inst
if ($ReadyFile) { [IO.File]::WriteAllText($ReadyFile, "listening $PID`n") }
$held = New-Object System.Collections.ArrayList
while ([DateTime]::UtcNow -lt $deadline) {
    $w = $srv.WaitForConnectionAsync(); $done = $false
    while (-not $done -and [DateTime]::UtcNow -lt $deadline) {
        try { $done = $w.Wait(200) } catch { $done = $true }
        if (-not $done -and $StopFile -and (Test-Path -LiteralPath $StopFile)) { break }
    }
    if (-not $done) { break }
    $n++
    $hex = ''
    try {
        if ($Mode -eq 'answer' -or $Mode -eq 'answermsg' -or $Mode -eq 'refuse') {
            $buf = New-Object byte[] 5; $got = 0
            while ($got -lt 5) { $r = $srv.Read($buf, $got, 5 - $got); if ($r -le 0) { break }; $got += $r }
            $hex = (($buf[0..($got - 1)] | ForEach-Object { $_.ToString('x2') }) -join '')
            if ($Mode -eq 'refuse') { $srv.Write($fail, 0, $fail.Length) } else { $srv.Write($answer, 0, $answer.Length) }
            $srv.Flush()
            $rest = New-Object byte[] 64; $extra = 0
            try { while ($true) { $r = $srv.Read($rest, 0, 64); if ($r -le 0) { break }; $extra += $r } } catch { }
            $hex += " extra_bytes=$extra"
        }
    } catch { $hex += ' error=' + $_.Exception.GetType().Name }
    [IO.File]::AppendAllText($MarkerFile, ("connect {0} {1}`n" -f $n, $hex))
    if ($Mode -eq 'outbound') { [void]$held.Add($srv); break }
    try { $srv.Dispose() } catch { }
    if ($StopFile -and (Test-Path -LiteralPath $StopFile)) { break }
    $srv = New-Inst
}
if ($Mode -eq 'outbound') {
    while ([DateTime]::UtcNow -lt $deadline -and -not ($StopFile -and (Test-Path -LiteralPath $StopFile))) { Start-Sleep -Milliseconds 200 }
}
foreach ($s in $held) { try { $s.Dispose() } catch { } }
try { $srv.Dispose() } catch { }
exit 0
