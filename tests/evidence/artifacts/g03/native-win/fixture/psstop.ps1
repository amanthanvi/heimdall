# Stops exactly one process after re-verifying PID + start time + marker in its command line.
param([Parameter(Mandatory=$true)][int]$TargetPid, [Parameter(Mandatory=$true)][string]$Start, [string]$Marker = 'hm-m00')
$p = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid"
if (-not $p) { 'not-found'; exit 1 }
if ($p.CreationDate.ToUniversalTime().ToString('o') -ne $Start) { 'start-mismatch'; exit 2 }
if (-not $p.CommandLine.Contains($Marker)) { 'marker-mismatch'; exit 3 }
Stop-Process -Id $TargetPid -Force; 'stopped'
