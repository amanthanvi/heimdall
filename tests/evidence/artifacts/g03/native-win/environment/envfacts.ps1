# Passive environment facts (versions, paths, service state). No agent contact, no config contents.
$o = [ordered]@{}
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$o.windows = [ordered]@{ ProductName_registry = $cv.ProductName; DisplayVersion = $cv.DisplayVersion; CurrentBuild = $cv.CurrentBuild; UBR = $cv.UBR; EditionID = $cv.EditionID; arch = $env:PROCESSOR_ARCHITECTURE }
$bins = @()
foreach ($d in @((Join-Path $env:WINDIR 'System32\OpenSSH'), (Join-Path $env:ProgramFiles 'OpenSSH'), (Join-Path $env:ProgramFiles 'Git\usr\bin'))) {
  foreach ($n in @('ssh.exe', 'ssh-add.exe', 'ssh-agent.exe', 'sshd.exe', 'ssh-keygen.exe')) {
    $p = Join-Path $d $n
    if (Test-Path -LiteralPath $p) { $bins += [ordered]@{ path = $p; file_version = (Get-Item -LiteralPath $p).VersionInfo.FileVersion; product_version = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion } }
  }
}
$o.openssh_binaries = $bins
$o.services = @(foreach ($s in @('ssh-agent', 'sshd')) { $x = Get-Service -Name $s -ErrorAction SilentlyContinue; if ($x) { [ordered]@{ name = $s; status = $x.Status.ToString(); start_type = $x.StartType.ToString() } } else { [ordered]@{ name = $s; present = $false } } })
$o.sshd_service_binary = $null
$qc = & sc.exe qc sshd 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) { $o.sshd_service_binary = (($qc -split "`r?`n" | Where-Object { $_ -match 'BINARY_PATH_NAME' }) -replace '^\s*BINARY_PATH_NAME\s*:\s*', '') }
$o.programdata_ssh_config_exists = Test-Path -LiteralPath (Join-Path $env:ProgramData 'ssh\ssh_config')
$o.pwsh7 = $null
$pw = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
if (Test-Path $pw) { $o.pwsh7 = [ordered]@{ path = $pw; file_version = (Get-Item $pw).VersionInfo.ProductVersion } }
$o.windows_powershell = [ordered]@{ path = (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'); file_version = (Get-Item (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')).VersionInfo.ProductVersion }
$env:WSL_UTF8 = '1'
$o.wsl_version = @((& wsl.exe --version 2>&1 | Out-String) -replace "`0", '' -split "`r?`n" | Where-Object { $_.Trim() })
$o | ConvertTo-Json -Depth 6
