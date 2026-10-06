# Lists processes whose command line contains the scratch marker. Prints only PID, PPID, image name, start time (no command lines).
param([string]$Marker = 'hm-m00')
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Marker) -and $_.ProcessId -ne $PID } |
  ForEach-Object { '{0} {1} {2} {3}' -f $_.ProcessId, $_.ParentProcessId, $_.Name, $_.CreationDate.ToUniversalTime().ToString('o') }
