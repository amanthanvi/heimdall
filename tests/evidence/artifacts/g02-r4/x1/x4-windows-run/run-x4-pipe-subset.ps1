<#
.SYNOPSIS
  X1 pipe-only subset of tests/evidence/artifacts/g02-r4/x4/windows/run-x4-windows.ps1 (task M00-T05-x1-g02-native).

.DESCRIPTION
  Derived mechanically from run-x4-windows.ps1 (sha256 recorded in RESULTS.md next to this file): the DPAPI, CNG
  (software KSP) and Platform Crypto Provider (TPM) blocks are replaced by `blocked` checks; everything else, in
  particular the named-pipe checks (a) to (f) and the reporting, is the original text. Reason: the original runner
  unconditionally creates and deletes persisted keys in the user's key store and on the TPM and uses the user's
  DPAPI master key; X1 runs on the owner's personal PC with a scratch-only authorization, so those parts need an
  explicit owner decision (escalated). The spike itself is not modified.

  Binaries: x4-go.exe / x4-rust.exe rebuilt with the spike's build.sh; their SHA-256 equal the ones recorded in the
  spike's RESULTS.md (reproducible build), so they are the spike's binaries.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [string]$OutDir = "",
  [ValidateSet('go', 'rust', 'both')][string]$Lang = 'both',
  [System.Management.Automation.PSCredential]$OtherUserCredential,
  [string]$OtherUserBinDir = ""
)
$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = ".\x4-windows-out-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$script:Checks = New-Object System.Collections.ArrayList
$script:Started = New-Object System.Collections.ArrayList

function Add-Check($lang, $id, $expect, $result, $observed) {
  [void]$script:Checks.Add([pscustomobject]@{ lang = $lang; id = $id; expect = $expect; result = $result; observed = $observed })
  Write-Host ("[{0}] {1}/{2}: {3}" -f $result.ToUpper(), $lang, $id, ($observed | ConvertTo-Json -Compress -Depth 4))
}

function Start-X4([string]$exe, [string[]]$argv, [string]$tag) {
  $o = Join-Path $OutDir "$tag.out.txt"; $e = Join-Path $OutDir "$tag.err.txt"
  $p = Start-Process -FilePath $exe -ArgumentList $argv -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
  $null = $p.Handle  # keep the handle so ExitCode is readable after exit
  [void]$script:Started.Add($p)
  [pscustomobject]@{ Proc = $p; Out = $o; Err = $e }
}

function Wait-X4($h, [int]$sec) {
  if (-not $h.Proc.WaitForExit($sec * 1000)) {
    Stop-Process -Id $h.Proc.Id -Force -ErrorAction SilentlyContinue  # exact PID we started
    return -999
  }
  return $h.Proc.ExitCode
}

function Read-Lines($file) {
  if (-not (Test-Path $file)) { return @() }
  @(Get-Content -LiteralPath $file | Where-Object { $_.Trim().StartsWith('{') } | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
}

function Invoke-X4([string]$exe, [string[]]$argv, [string]$tag, [int]$sec = 30) {
  $h = Start-X4 $exe $argv $tag
  $code = Wait-X4 $h $sec
  [pscustomobject]@{ Exit = $code; Json = @(Read-Lines $h.Out); Err = (Get-Content -LiteralPath $h.Err -ErrorAction SilentlyContinue | Select-Object -First 3) -join ' | ' }
}

function Wait-Listening($h, [int]$sec = 10) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    if (@(Read-Lines $h.Out | Where-Object { $_.event -eq 'listening' }).Count -gt 0) { return $true }
    if ($h.Proc.HasExited) { return $false }
    Start-Sleep -Milliseconds 100
  }
  return $false
}

function Test-Lang([string]$lang) {
  $exe = Join-Path $BinDir "x4-$lang.exe"
  if (-not (Test-Path $exe)) { Add-Check $lang 'binary' 'exe present' 'blocked' @{ missing = "x4-$lang.exe" }; return }
  $sfx = [guid]::NewGuid().ToString('N').Substring(0, 8)
  $key = "heimdall-x4-$lang-$sfx"
  $pipe = "heimdall-x4-$lang-$sfx"

  # ---- DPAPI / CNG / TPM: NOT RUN in X1 (subset runner; see header)
  Add-Check $lang 'dpapi.roundtrip' 'not run' 'blocked' @{ missing = 'owner authorization to use the owner''s DPAPI user master key on the personal PC (credential store; X1 scope is scratch-only), or a disposable Windows account/host' }
  foreach ($cid in @('cng.probe', 'cng.create', 'cng.create.duplicate_fails', 'cng.sign.new_process', 'cng.delete')) {
    Add-Check $lang $cid 'not run' 'blocked' @{ missing = 'owner authorization to create/delete a persisted key in the owner''s user key store (Software KSP, outside the scratch directories; keychain boundary), or a disposable Windows account/host' } }
  Add-Check $lang 'cng.platform_tpm' 'not run' 'blocked' @{ missing = 'owner authorization to create/delete a TPM-backed key (Platform Crypto Provider) on the owner''s TPM, or a disposable host' }

  # ---- Named pipe
  # (a) positive: identification-level client accepted
  $srv = Start-X4 $exe @('pipe-server', '--name', "$pipe-a", '--count', '1', '--timeout', '20') "$lang-pipe-a-server"
  if (-not (Wait-Listening $srv)) { Add-Check $lang 'pipe.server_start' 'server prints listening' 'fail' @{ stderr = (Get-Content $srv.Err -ErrorAction SilentlyContinue | Select-Object -First 3) -join ' | ' }; return }
  $cl = Invoke-X4 $exe @('pipe-client', '--name', "$pipe-a", '--level', 'identification') "$lang-pipe-a-client" 15
  $se = Wait-X4 $srv 15
  $conn = Read-Lines $srv.Out | Where-Object { $_.event -eq 'conn' } | Select-Object -First 1
  $cj = $cl.Json | Select-Object -Last 1
  Add-Check $lang 'pipe.accept_same_user' 'client exit 0 echo:hello; server decision accept, impersonation_level 1 (Identification), pid cross-check true' $(if ($cl.Exit -eq 0 -and $cj.ok -eq $true -and $conn.decision -eq 'accept' -and $conn.impersonation_level -eq 1 -and $conn.pid_sid_matches_expected -eq $true) { 'pass' } else { 'fail' }) @{ client_exit = $cl.Exit; server_exit = $se; client = $cj; server = $conn }

  # (b) refusal: server expects a SID that is not ours (BUILTIN\Users, constant and harmless)
  $srv = Start-X4 $exe @('pipe-server', '--name', "$pipe-b", '--count', '1', '--timeout', '20', '--expect-sid', 'S-1-5-32-545') "$lang-pipe-b-server"
  [void](Wait-Listening $srv)
  $cl = Invoke-X4 $exe @('pipe-client', '--name', "$pipe-b", '--level', 'identification') "$lang-pipe-b-client" 15
  $se = Wait-X4 $srv 15
  $conn = Read-Lines $srv.Out | Where-Object { $_.event -eq 'conn' } | Select-Object -First 1
  $cj = $cl.Json | Select-Object -Last 1
  Add-Check $lang 'pipe.refuse_foreign_sid' 'client exit 1 verdict denied; server decision refuse' $(if ($cl.Exit -eq 1 -and $cj.verdict -eq 'denied' -and $conn.decision -eq 'refuse') { 'pass' } else { 'fail' }) @{ client_exit = $cl.Exit; server_exit = $se; client = $cj; server = $conn }

  # (c) anonymous-level client: must be refused (token has no usable user SID); fail closed
  $srv = Start-X4 $exe @('pipe-server', '--name', "$pipe-c", '--count', '1', '--timeout', '20') "$lang-pipe-c-server"
  [void](Wait-Listening $srv)
  $cl = Invoke-X4 $exe @('pipe-client', '--name', "$pipe-c", '--level', 'anonymous') "$lang-pipe-c-client" 15
  $se = Wait-X4 $srv 15
  $conn = Read-Lines $srv.Out | Where-Object { $_.event -eq 'conn' } | Select-Object -First 1
  $cj = $cl.Json | Select-Object -Last 1
  Add-Check $lang 'pipe.refuse_anonymous_level' 'client exit 1; server decision refuse (impersonation error or anonymous SID)' $(if ($cl.Exit -eq 1 -and $conn.decision -eq 'refuse') { 'pass' } else { 'fail' }) @{ client_exit = $cl.Exit; server_exit = $se; client = $cj; server = $conn }

  # (d) control: impersonation-level client accepted, server sees level 2
  $srv = Start-X4 $exe @('pipe-server', '--name', "$pipe-d", '--count', '1', '--timeout', '20') "$lang-pipe-d-server"
  [void](Wait-Listening $srv)
  $cl = Invoke-X4 $exe @('pipe-client', '--name', "$pipe-d", '--level', 'impersonation') "$lang-pipe-d-client" 15
  $se = Wait-X4 $srv 15
  $conn = Read-Lines $srv.Out | Where-Object { $_.event -eq 'conn' } | Select-Object -First 1
  Add-Check $lang 'pipe.control_impersonation_level' 'info: accepted, level 2 (Impersonation) observed' $(if ($cl.Exit -eq 0 -and $conn.impersonation_level -eq 2) { 'pass' } else { 'info' }) @{ client_exit = $cl.Exit; server_exit = $se; server = $conn }

  # (e) first-instance exclusivity: a second server on the same name must fail to start
  $s1 = Start-X4 $exe @('pipe-server', '--name', "$pipe-e", '--count', '1', '--timeout', '20') "$lang-pipe-e-server1"
  if (Wait-Listening $s1) {
    $s2 = Invoke-X4 $exe @('pipe-server', '--name', "$pipe-e", '--count', '1', '--timeout', '5') "$lang-pipe-e-server2" 10
    Add-Check $lang 'pipe.first_instance_exclusive' 'second server on same name exits non-zero without listening' $(if ($s2.Exit -ne 0 -and @($s2.Json | Where-Object { $_.event -eq 'listening' }).Count -eq 0) { 'pass' } else { 'fail' }) @{ second_server_exit = $s2.Exit; json = ($s2.Json | Select-Object -Last 1) }
    [void](Invoke-X4 $exe @('pipe-client', '--name', "$pipe-e", '--level', 'identification') "$lang-pipe-e-drain" 15)  # let server 1 finish
    [void](Wait-X4 $s1 15)
  }
  else { Add-Check $lang 'pipe.first_instance_exclusive' 'server 1 listens' 'fail' @{ note = 'server 1 did not start' } }

  # (f) cross-user DACL (optional)
  if ($OtherUserCredential -and $OtherUserBinDir) {
    $oexe = Join-Path $OtherUserBinDir "x4-$lang.exe"
    $srv = Start-X4 $exe @('pipe-server', '--name', "$pipe-f", '--count', '1', '--timeout', '15') "$lang-pipe-f-server"
    [void](Wait-Listening $srv)
    $op = Start-Process -FilePath $oexe -ArgumentList @('pipe-client', '--name', "$pipe-f") -Credential $OtherUserCredential -Wait -PassThru -WindowStyle Hidden
    $null = $op.Handle
    $conn = Read-Lines $srv.Out | Where-Object { $_.event -eq 'conn' }
    Add-Check $lang 'pipe.dacl_refuses_other_user' 'other user client exit 1 (open fails, expected ERROR_ACCESS_DENIED); server saw no connection' $(if ($op.ExitCode -eq 1 -and @($conn).Count -eq 0) { 'pass' } else { 'fail' }) @{ other_user_client_exit = $op.ExitCode; server_conn_events = @($conn).Count }
    [void](Invoke-X4 $exe @('pipe-client', '--name', "$pipe-f") "$lang-pipe-f-drain" 15)  # let the server finish
    [void](Wait-X4 $srv 15)
  }
  else {
    Add-Check $lang 'pipe.dacl_refuses_other_user' 'other-user client denied by DACL' 'blocked' @{ missing = 'second local non-admin account (-OtherUserCredential / -OtherUserBinDir)' }
  }
  Add-Check $lang 'pipe.reject_remote_clients' 'remote (SMB) client rejected' 'blocked' @{ missing = 'second Windows machine on the network; flag presence only checked by code review' }
}

try {
  $os = Get-CimInstance Win32_OperatingSystem
  $tpm = try { $t = Get-Tpm; @{ present = $t.TpmPresent; ready = $t.TpmReady } } catch { @{ present = 'unknown' } }
  $hostInfo = @{
    os = $os.Caption; build = $os.BuildNumber; arch = $env:PROCESSOR_ARCHITECTURE
    ps = $PSVersionTable.PSVersion.ToString(); tpm = $tpm
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ssh_auth_sock_set = [bool]$env:SSH_AUTH_SOCK
  }
  $bins = @{}
  Get-ChildItem -Path $BinDir -Filter 'x4-*.exe' | ForEach-Object { $bins[$_.Name] = @{ size = $_.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower() } }
  $langs = if ($Lang -eq 'both') { @('go', 'rust') } else { @($Lang) }
  foreach ($l in $langs) { Test-Lang $l }
}
finally {
  foreach ($p in $script:Started) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

$summary = [pscustomobject]@{
  generated_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  host = $hostInfo; binaries = $bins; checks = $script:Checks
  counts = @{
    pass    = @($script:Checks | Where-Object result -eq 'pass').Count
    fail    = @($script:Checks | Where-Object result -eq 'fail').Count
    blocked = @($script:Checks | Where-Object result -eq 'blocked').Count
    info    = @($script:Checks | Where-Object result -eq 'info').Count
  }
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir 'results.json')
Write-Host ("pass={0} fail={1} blocked={2} info={3}" -f $summary.counts.pass, $summary.counts.fail, $summary.counts.blocked, $summary.counts.info)
if ($summary.counts.fail -gt 0) { exit 1 } else { exit 0 }
