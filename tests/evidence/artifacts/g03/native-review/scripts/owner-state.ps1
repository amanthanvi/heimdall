# Review M00-T04-G03-native-review: read-only owner-state check. Prints no user,
# host or path values. Never opens \\.\pipe\openssh-ssh-agent (name enumeration only).
$m = 'hm-' + 'm00'
$o = [ordered]@{}
$d = Join-Path $env:LOCALAPPDATA $m
$o.win_scratch_root_exists = Test-Path -LiteralPath $d
$o.win_scratch_root_entries = @(if ($o.win_scratch_root_exists) { Get-ChildItem -LiteralPath $d -Force | ForEach-Object { $_.Name } })
$o.win_procs_with_marker = @(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($m) -and $_.ProcessId -ne $PID } | ForEach-Object { '{0} {1} {2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name })
$s = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
$o.ssh_agent_service = if ($s) { '{0}/{1}' -f $s.Status, $s.StartType } else { 'absent' }
$o.ssh_agent_processes = @(Get-CimInstance Win32_Process -Filter "Name = 'ssh-agent.exe'" | ForEach-Object { 'pid={0} start_utc={1}' -f $_.ProcessId, $_.CreationDate.ToUniversalTime().ToString('o') })
$pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [System.IO.Path]::GetFileName($_) })
$o.pipe_count = $pipes.Count
$o.default_agent_pipe_name_present = ($pipes -contains 'openssh-ssh-agent')
$o.heimdall_pipe_names = @($pipes | Where-Object { $_ -like 'heimdall*' })
$o.public_heimdall_g03_dirs = @(Get-ChildItem -LiteralPath $env:PUBLIC -Filter 'heimdall-g03*' -Force -ErrorAction SilentlyContinue).Count
$o.session_SSH_AUTH_SOCK_set = [bool]$env:SSH_AUTH_SOCK
$o.token_elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$o | ConvertTo-Json -Depth 4
