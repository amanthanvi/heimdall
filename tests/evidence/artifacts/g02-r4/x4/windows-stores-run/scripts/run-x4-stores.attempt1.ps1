<#
.SYNOPSIS
  M00-T04-x4-stores: native Windows runner for the X4 secure-store checks (DPAPI, CNG Software KSP,
  CNG Platform Crypto Provider / TPM), Go and Rust. Mechanical derivative of
  tests/evidence/artifacts/g02-r4/x4/windows/run-x4-windows.ps1: the named-pipe block is removed; the
  DPAPI and CNG blocks are kept and extended; inventory and timing are added.

.DESCRIPTION
  Authorized by ADR-0004 section 3 (uniquely named test keys created and deleted by exact name in the
  same run; DPAPI protect/unprotect of test data only; inventory before and after must match).
  Per language (x4-rust.exe = adapted Rust spike, x4-go.exe = unmodified Go spike):
    DPAPI : in-process round trip, wrong-entropy and tamper rejection (both); Rust also protects in one
            process and unprotects in a second process, timed.
    CNG   : for provider software (Microsoft Software Key Storage Provider) and platform (Microsoft
            Platform Crypto Provider, TPM): create / duplicate create / sign (new process) / delete as
            separate processes. Rust also: export policy and impl type readback, private-export attempts,
            timed signing, public key + signature written to files, verify-pub (BCrypt, public key only,
            another new process).
  Inventory: x4-rust.exe `cng --op inventory` (count + SHA-256 of the sorted name list, names with this
  run's prefix) and certutil -user -silent -csp <provider> -key (count of lines with this run's prefix; the
  raw certutil output stays in memory, never written) before, after each create and delete, and after.
  A final sweep deletes, by exact name, any key with this run's prefix still present.
  Only exact PIDs started by this script are ever stopped. No network, no admin, no elevation.

  Output never contains SID bodies, user names or absolute paths. Exit code: 0 if no check failed, 1 otherwise.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [string]$OutDir = "",
  [ValidateSet('go', 'rust', 'both')][string]$Lang = 'both',
  [int]$Iterations = 20,
  [string]$RunId = ""
)
$ErrorActionPreference = 'Stop'
if (-not $OutDir) { $OutDir = ".\x4-stores-out-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
if (-not $RunId) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 8) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$WorkDir = Join-Path $OutDir 'work'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Prefix = "heimdall-m00-t04-x4-$RunId-"
$Msg = "heimdall-m00-t04-x4-$RunId-sign-marker"
$script:Checks = New-Object System.Collections.ArrayList
$script:Started = New-Object System.Collections.ArrayList
$script:Inventory = [ordered]@{}
$script:Commands = New-Object System.Collections.ArrayList

function Add-Check($lang, $id, $expect, $result, $observed) {
  [void]$script:Checks.Add([pscustomobject]@{ lang = $lang; id = $id; expect = $expect; result = $result; observed = $observed })
  Write-Host ("[{0}] {1}/{2}: {3}" -f $result.ToUpper(), $lang, $id, ($observed | ConvertTo-Json -Compress -Depth 4))
}

function Start-X4([string]$exe, [string[]]$argv, [string]$tag) {
  $o = Join-Path $OutDir "$tag.out.txt"; $e = Join-Path $OutDir "$tag.err.txt"
  $p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $WorkDir -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
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
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $h = Start-X4 $exe $argv $tag
  $code = Wait-X4 $h $sec
  $sw.Stop()
  [void]$script:Commands.Add([pscustomobject]@{ tag = $tag; exe = (Split-Path -Leaf $exe); argv = ($argv -join ' '); exit = $code; wall_ms = $sw.ElapsedMilliseconds })
  [pscustomobject]@{ Exit = $code; Json = @(Read-Lines $h.Out); Err = (Get-Content -LiteralPath $h.Err -ErrorAction SilentlyContinue | Select-Object -First 3) -join ' | '; WallMs = $sw.ElapsedMilliseconds }
}

function Get-KspName([string]$p) { if ($p -eq 'platform') { 'Microsoft Platform Crypto Provider' } else { 'Microsoft Software Key Storage Provider' } }

# Independent cross-check: certutil's own key listing. Raw output (other keys' names) is never written.
function Get-CertutilPrefixCount([string]$p) {
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $out = & certutil.exe -user -silent -csp (Get-KspName $p) -key 2>&1
    $code = $LASTEXITCODE
  }
  finally { $ErrorActionPreference = $old }
  $n = @($out | Where-Object { "$_" -like "*$Prefix*" }).Count
  [void]$script:Commands.Add([pscustomobject]@{ tag = "certutil-$p"; exe = 'certutil.exe'; argv = "-user -silent -csp `"$(Get-KspName $p)`" -key (output counted for the run prefix, not kept)"; exit = $code; wall_ms = $null })
  [pscustomobject]@{ exit = $code; prefix_lines = $n }
}

function Get-Inventory([string]$phase) {
  $rexe = Join-Path $BinDir 'x4-rust.exe'
  $res = [ordered]@{}
  foreach ($p in @('software', 'platform')) {
    $r = Invoke-X4 $rexe @('cng', '--op', 'inventory', '--provider', $p, '--prefix', $Prefix) "inv-$phase-$p"
    $j = $r.Json | Select-Object -Last 1
    $cu = Get-CertutilPrefixCount $p
    $res[$p] = [pscustomobject]@{
      exit = $r.Exit; ok = $j.ok; count = $j.count; names_sha256 = $j.names_sha256; prefix_count = $j.prefix_count
      prefix_names = $j.prefix_names; heimdall_prefixed_count = $j.heimdall_prefixed_count; status_hex = $j.status_hex
      certutil_exit = $cu.exit; certutil_prefix_lines = $cu.prefix_lines
    }
  }
  $script:Inventory[$phase] = $res
  $res
}

function Test-KeyStore([string]$lang, [string]$exe, [string]$prov) {
  $tag = if ($prov -eq 'platform') { 'tpm' } else { 'sw' }
  $sec = if ($prov -eq 'platform') { 120 } else { 30 }
  $key = "$Prefix$lang-$tag"
  $pubf = "pub-$lang-$tag.bin"; $sigf = "sig-$lang-$tag.bin"
  $isRust = ($lang -eq 'rust')
  $created = $false
  try {
    $a = @('cng', '--op', 'create', '--provider', $prov, '--name', $key); if ($isRust) { $a += @('--pub-out', $pubf) }
    $c = Invoke-X4 $exe $a "$lang-cng-$tag-create" $sec
    $cj = $c.Json | Select-Object -Last 1
    $created = ($c.Exit -eq 0 -and $cj.created -eq $true)
    Add-Check $lang "cng.$tag.create" 'exit 0; created; ECCPUBLICBLOB magic ECS1 / 32-byte coords' $(if ($created -and $cj.pub_magic_ok -eq $true) { 'pass' } else { 'fail' }) @{ exit = $c.Exit; wall_ms = $c.WallMs; json = $cj; stderr = $c.Err }
    if (-not $created) { return }
    if ($isRust) {
      $ne = ($cj.export_policy -eq 0 -and $cj.private_export_eccprivateblob_succeeded -eq $false -and $cj.private_export_pkcs8_succeeded -eq $false)
      Add-Check $lang "cng.$tag.non_exportable" 'export_policy 0 read back; ECCPRIVATEBLOB and PKCS8 private exports both refused' $(if ($ne) { 'pass' } else { 'fail' }) @{ export_policy_set_status = $cj.export_policy_set_status; export_policy = $cj.export_policy; export_policy_status = $cj.export_policy_status; impl_type = $cj.impl_type; impl_hardware = $cj.impl_hardware; eccprivateblob_status = $cj.private_export_eccprivateblob_status; pkcs8_status = $cj.private_export_pkcs8_status }
    }
    $inv = Get-Inventory "after-$lang-$tag-create"
    $seen = $inv[$prov]
    Add-Check $lang "cng.$tag.visible_in_inventory" "spike enumeration lists exactly this key under the run prefix; certutil lists it too" $(if ($seen.prefix_names -eq $key -and $seen.certutil_prefix_lines -ge 1) { 'pass' } else { 'fail' }) @{ prefix_names = $seen.prefix_names; certutil_exit = $seen.certutil_exit; certutil_prefix_lines = $seen.certutil_prefix_lines }

    $d = Invoke-X4 $exe @('cng', '--op', 'create', '--provider', $prov, '--name', $key) "$lang-cng-$tag-create-dup" $sec
    $dj = $d.Json | Select-Object -Last 1
    Add-Check $lang "cng.$tag.create.duplicate_fails" 'exit 1 with NTE_EXISTS 0x8009000F (no silent overwrite)' $(if ($d.Exit -eq 1 -and $dj.status_hex -eq '0x8009000F') { 'pass' } else { 'fail' }) @{ exit = $d.Exit; json = $dj }

    $a = @('cng', '--op', 'sign', '--provider', $prov, '--name', $key); if ($isRust) { $a += @('--iterations', "$Iterations", '--msg', $Msg, '--sig-out', $sigf) }
    $s = Invoke-X4 $exe $a "$lang-cng-$tag-sign" $sec
    $sj = $s.Json | Select-Object -Last 1
    $sok = ($s.Exit -eq 0 -and $sj.verify_ok_and_tamper_rejected -eq $true -and $sj.sig_len -eq 64)
    if ($isRust) { $sok = ($sok -and $sj.timed_sig_verifies_with_handle -eq $true -and $sj.sig_written -eq $true -and $sj.sign_n -eq $Iterations) }
    Add-Check $lang "cng.$tag.sign.new_process" 'exit 0; key reopened in a new process; sig_len 64; verify ok; tampered signature rejected (rust: timed signatures verify, one written)' $(if ($sok) { 'pass' } else { 'fail' }) @{ exit = $s.Exit; wall_ms = $s.WallMs; json = $sj }

    if ($isRust) {
      $v = Invoke-X4 $exe @('cng', '--op', 'verify-pub', '--pub-in', $pubf, '--sig-in', $sigf, '--msg', $Msg) "$lang-cng-$tag-verify-pub" $sec
      $vj = $v.Json | Select-Object -Last 1
      Add-Check $lang "cng.$tag.verify_exported_pub" 'exit 0; BCrypt import of the exported ECCPUBLICBLOB verifies the signature; tampered signature and wrong digest rejected' $(if ($v.Exit -eq 0 -and $vj.pub_verify_ok -eq $true -and $vj.pub_tampered_rejected -eq $true -and $vj.pub_wrong_digest_rejected -eq $true) { 'pass' } else { 'fail' }) @{ exit = $v.Exit; json = $vj }
    }
  }
  finally {
    if ($created) {
      $x = Invoke-X4 $exe @('cng', '--op', 'delete', '--provider', $prov, '--name', $key) "$lang-cng-$tag-delete" $sec
      $xj = $x.Json | Select-Object -Last 1
      Add-Check $lang "cng.$tag.delete" 'exit 0; deleted; reopen yields NTE_BAD_KEYSET 0x80090016' $(if ($x.Exit -eq 0 -and $xj.deleted -eq $true -and $xj.open_after_delete_is_bad_keyset -eq $true) { 'pass' } else { 'fail' }) @{ exit = $x.Exit; json = $xj }
      $inv = Get-Inventory "after-$lang-$tag-delete"
      $gone = $inv[$prov]
      Add-Check $lang "cng.$tag.absent_after_delete" 'spike enumeration and certutil list no key with the run prefix' $(if ($gone.prefix_count -eq 0 -and $gone.certutil_prefix_lines -eq 0) { 'pass' } else { 'fail' }) @{ prefix_count = $gone.prefix_count; certutil_prefix_lines = $gone.certutil_prefix_lines }
    }
  }
}

function Test-Lang([string]$lang) {
  $exe = Join-Path $BinDir "x4-$lang.exe"
  if (-not (Test-Path $exe)) { Add-Check $lang 'binary' 'exe present' 'blocked' @{ missing = "x4-$lang.exe" }; return }

  # ---- DPAPI
  $r = Invoke-X4 $exe @('dpapi') "$lang-dpapi"
  $j = $r.Json | Select-Object -Last 1
  Add-Check $lang 'dpapi.roundtrip' 'exit 0; roundtrip_ok, wrong_entropy_rejected, tamper_rejected all true' $(if ($r.Exit -eq 0 -and $j.ok -eq $true) { 'pass' } else { 'fail' }) @{ exit = $r.Exit; wall_ms = $r.WallMs; json = $j; stderr = $r.Err }
  if ($lang -eq 'rust') {
    $ct = "dpapi-ct-$lang.bin"
    $p1 = Invoke-X4 $exe @('dpapi', '--op', 'protect', '--out', $ct, '--iterations', "$Iterations") "$lang-dpapi-protect"
    $p1j = $p1.Json | Select-Object -Last 1
    Add-Check $lang 'dpapi.protect.process1' 'exit 0; ciphertext written; timed' $(if ($p1.Exit -eq 0 -and $p1j.ok -eq $true) { 'pass' } else { 'fail' }) @{ exit = $p1.Exit; json = $p1j }
    $p2 = Invoke-X4 $exe @('dpapi', '--op', 'unprotect', '--in', $ct, '--iterations', "$Iterations") "$lang-dpapi-unprotect"
    $p2j = $p2.Json | Select-Object -Last 1
    Add-Check $lang 'dpapi.unprotect.new_process' 'exit 0; ciphertext from process 1 unprotects in process 2; wrong entropy and tamper rejected; timed' $(if ($p2.Exit -eq 0 -and $p2j.ok -eq $true -and $p2j.roundtrip_ok_new_process -eq $true) { 'pass' } else { 'fail' }) @{ exit = $p2.Exit; json = $p2j }
  }

  # ---- CNG
  $r = Invoke-X4 $exe @('cng', '--op', 'probe') "$lang-cng-probe"
  Add-Check $lang 'cng.probe' 'info only: which KSPs open' 'info' @{ exit = $r.Exit; json = ($r.Json | Select-Object -Last 1) }
  Test-KeyStore $lang $exe 'software'
  Test-KeyStore $lang $exe 'platform'
}

$started = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
try {
  $os = Get-CimInstance Win32_OperatingSystem
  $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
  $hostInfo = [ordered]@{
    os = $os.Caption; build = $os.BuildNumber; ubr = $cv.UBR; display_version = $cv.DisplayVersion; arch = $env:PROCESSOR_ARCHITECTURE
    ps = $PSVersionTable.PSVersion.ToString()
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ssh_auth_sock_set = [bool]$env:SSH_AUTH_SOCK
  }
  $bins = [ordered]@{}
  Get-ChildItem -Path $BinDir -Filter 'x4-*.exe' | ForEach-Object { $bins[$_.Name] = @{ size = $_.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower() } }
  $before = Get-Inventory 'before'
  $langs = if ($Lang -eq 'both') { @('rust', 'go') } else { @($Lang) }
  foreach ($l in $langs) { Test-Lang $l }
}
finally {
  foreach ($p in $script:Started) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
  # Final sweep: delete by exact name any key with this run's prefix that is still present.
  $after = Get-Inventory 'after'
  $swept = 0
  foreach ($p in @('software', 'platform')) {
    if ($after[$p].prefix_names) {
      foreach ($n in ($after[$p].prefix_names -split ';')) {
        if ($n.StartsWith($Prefix)) {
          $x = Invoke-X4 (Join-Path $BinDir 'x4-rust.exe') @('cng', '--op', 'delete', '--provider', $p, '--name', $n) "sweep-$p-$swept" 120
          Add-Check 'runner' "sweep.$p" 'leftover test key deleted by exact name' $(if ($x.Exit -eq 0) { 'pass' } else { 'fail' }) @{ name = $n; exit = $x.Exit }
          $swept++
        }
      }
    }
  }
  if ($swept -gt 0) { $after = Get-Inventory 'after-sweep' }
}

$unchanged = $true
$cmp = [ordered]@{}
foreach ($p in @('software', 'platform')) {
  $b = $before[$p]; $a = $after[$p]
  $same = ($b.exit -eq 0 -and $a.exit -eq 0 -and $b.count -eq $a.count -and $b.names_sha256 -eq $a.names_sha256 -and $a.prefix_count -eq 0 -and $b.prefix_count -eq 0 -and $a.certutil_prefix_lines -eq 0)
  $cmp[$p] = @{ before_count = $b.count; after_count = $a.count; before_sha256 = $b.names_sha256; after_sha256 = $a.names_sha256; before_prefix = $b.prefix_count; after_prefix = $a.prefix_count; certutil_before = $b.certutil_prefix_lines; certutil_after = $a.certutil_prefix_lines; equal = $same }
  if (-not $same) { $unchanged = $false }
}
Add-Check 'runner' 'inventory.unchanged' 'per provider: count and SHA-256 of the sorted key-name list equal before and after; no key with the run prefix before or after (spike and certutil)' $(if ($unchanged) { 'pass' } else { 'fail' }) $cmp

$summary = [pscustomobject]@{
  started_utc = $started
  generated_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  run_id = $RunId; key_prefix = $Prefix; sign_message = $Msg; iterations = $Iterations
  host = $hostInfo; binaries = $bins; checks = $script:Checks; inventory = $script:Inventory; commands = $script:Commands
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
