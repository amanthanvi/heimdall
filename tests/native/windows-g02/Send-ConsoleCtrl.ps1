<#
.SYNOPSIS
  Raise a console control event on the console of one process (G02 X1 harness helper, not product code).
.DESCRIPTION
  Runs as its own process (a process can be attached to one console only): FreeConsole, AttachConsole(TargetPid),
  ignore the event here (SetConsoleCtrlHandler(NULL, TRUE)), GenerateConsoleCtrlEvent(Event, 0) which reaches
  every process attached to that console, FreeConsole. Prints "ok <utc ticks>" or "error <step> <win32 error>".
  Event: 0 = CTRL_C_EVENT, 1 = CTRL_BREAK_EVENT. Windows PowerShell 5.1 and PowerShell 7.
#>
param([Parameter(Mandatory = $true)][int]$TargetPid, [ValidateSet(0, 1)][int]$Event = 0)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'G02X1Native.cs')))
$r = [X1Ctrl]::Send([uint32]$TargetPid, [uint32]$Event)
[Console]::Out.WriteLine($r)
if ($r.StartsWith('ok ')) { exit 0 } else { exit 2 }
