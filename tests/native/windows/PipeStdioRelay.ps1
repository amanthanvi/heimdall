<#
.SYNOPSIS
  Relay stdin/stdout to a local named pipe (G03 harness fixture).

.DESCRIPTION
  Candidate transport for the WSL Mode B probe: a Linux-side endpoint spawns
  this script through WSL interop (powershell.exe ... -File PipeStdioRelay.ps1)
  once per agent connection and speaks the SSH agent protocol over stdio; the
  script forwards bytes to \\.\pipe\<PipeName> unchanged. It is a stand-in for
  tools such as npiperelay so the probe needs no third-party download.

  Security note (recorded by the probes, not mitigated here): the pipe server
  sees THIS process (powershell.exe running as the Windows user) as its
  client, not the Linux program that originated the request. A provider that
  authorizes per requesting application therefore attributes every bridged
  request to the relay.

  Exit codes: 0 relay finished; 2 could not connect; 3 relay error.
#>
param(
    [Parameter(Mandatory = $true)][string]$PipeName,
    [int]$ConnectTimeoutMs = 5000
)
$ErrorActionPreference = 'Stop'
$client = $null
try {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous, [System.Security.Principal.TokenImpersonationLevel]::Identification)
    try { $client.Connect($ConnectTimeoutMs) } catch { [Console]::Error.WriteLine('relay: connect failed: ' + $_.Exception.GetType().Name); exit 2 }
    $stdin = [Console]::OpenStandardInput()
    $stdout = [Console]::OpenStandardOutput()
    $up = $stdin.CopyToAsync($client)
    $down = $client.CopyToAsync($stdout)
    [void][System.Threading.Tasks.Task]::WaitAny(@($up, $down))
    try { $stdout.Flush() } catch { }
    exit 0
} catch {
    [Console]::Error.WriteLine('relay: error: ' + $_.Exception.GetType().Name)
    exit 3
} finally {
    if ($client) { $client.Dispose() }
}
