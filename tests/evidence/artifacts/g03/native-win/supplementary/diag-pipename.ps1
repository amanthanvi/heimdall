# Supplementary diagnostic for M00-T04-G03-native-windows (scratch script, not part of the harness).
# Discriminates which pipe-name property makes SSH_AUTH_SOCK selection fail for Win32-OpenSSH ssh-add.
param([string]$OutFile)
$scr = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $scr 'repo\tests\native\windows\G03Common.psm1') -Force
$ctx = New-G03RunContext -RepoRoot (Join-Path $scr 'repo') -OutDir (Join-Path $scr 'runs\diag-pipename')
$names = [ordered]@{
  ascii_control = 'heimdall-g03-ascii-' + (New-G03RandomHex 3)
  space_only    = 'heimdall g03 space ' + (New-G03RandomHex 3)
  nonascii_only = 'heimdall-g03-' + [char]0x00FC + '-' + (New-G03RandomHex 3)
  space_nonascii = 'heimdall g03 ' + [char]0x00FC + ' ' + (New-G03RandomHex 3)
}
$clients = @((Join-Path $env:WINDIR 'System32\OpenSSH\ssh-add.exe'), (Join-Path $env:ProgramFiles 'OpenSSH\ssh-add.exe'))
$rows = @()
foreach ($k in $names.Keys) {
  $a = Start-G03InstrumentedAgent -Ctx $ctx -Name ('d' + $k.Length) -PipeName $names[$k] -RunSeconds 120
  $fp = [string]$a.Ready.keys[0].fingerprint
  foreach ($c in $clients) {
    foreach ($form in @('backslash', 'forward_slash')) {
      $sock = if ($form -eq 'backslash') { '\\.\pipe\' + $names[$k] } else { '//./pipe/' + $names[$k] }
      $res = Invoke-G03Native -Ctx $ctx -FilePath $c -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = $sock } -TimeoutSec 30
      $rows += [ordered]@{ name_kind = $k; client = $c; form = $form; exit_code = $res.ExitCode; lists_key = (Get-G03StdoutText $res).Contains($fp)
        stderr_first_line = (($res.StderrText -split "`r?`n") | Select-Object -First 1) }
    }
  }
  Start-Sleep -Milliseconds 300
  $rows += [ordered]@{ name_kind = $k; agent_contact = (Get-G03AgentContact $a) }
  [void](Stop-G03InstrumentedAgent $a)
}
$out = [ordered]@{ started_at = $ctx.StartedAt; powershell = $PSVersionTable.PSVersion.ToString(); rows = $rows; stops = (Stop-G03AllOwned -Ctx $ctx) }
Write-G03Utf8File -Path $OutFile -Text (Protect-G03Text -Ctx $ctx -Text (($out | ConvertTo-Json -Depth 8) + "`n"))
Remove-G03Scratch -Ctx $ctx
