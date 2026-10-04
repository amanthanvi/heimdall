<#
.SYNOPSIS
  Self-test of the G03 Windows harness tooling that runs on any OS with
  PowerShell 7 and an OpenSSH client (ssh-add, ssh-keygen).

.DESCRIPTION
  Exercises InstrumentedAgent.ps1's protocol and ECDSA signature encoding
  against the real OpenSSH tools:
    1. ssh-add -l lists exactly the allowed probe keys;
    2. ssh-keygen -Y sign -U (agent signing) succeeds for an allowed key and
       ssh-keygen -Y verify accepts the signature;
    3. signing with a filtered key fails and the agent logs the denial;
    4. mutation requests (ssh-add -D) are refused;
    5. the agent re-arms its single server instance with Disconnect() after
       every client (no dispose/recreate window on the name).
  It establishes NOTHING about Windows named pipes, DACLs, Win32-OpenSSH, or
  WSL: on non-Windows hosts .NET maps the "pipe" to a Unix-domain socket.

  Writes a self-test transcript and an evidence record (case
  G03-harness-selftest-<os>) to -OutDir. Uses only disposable in-memory keys.
#>
param(
    [string]$OutDir,
    [string]$SshAdd = '/usr/bin/ssh-add',
    [string]$SshKeygen = '/usr/bin/ssh-keygen'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'G03Common.psm1') -Force
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $SshAdd = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-add.exe'
    $SshKeygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
}
$osTag = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
if (-not $OutDir) { $OutDir = Join-Path $repo "tests/evidence/artifacts/g03/harness-selftest/powershell-$osTag" }
$ctx = New-G03RunContext -RepoRoot $repo -OutDir $OutDir -RunId ('selftest-' + (New-G03RandomHex 3))
$case = "G03-harness-selftest-powershell-$osTag"
$checks = [ordered]@{}
$transcripts = @()
$agent = $null
$sockDir = $null
try {
    $pipeName = "hg03-" + (New-G03RandomHex 4)
    if (-not (Test-G03OnWindows)) {
        # Short absolute socket path (sun_path limit); scratch dir under /tmp.
        $sockDir = Join-Path '/tmp' ("hg03-" + (New-G03RandomHex 4))
        New-Item -ItemType Directory -Force -Path $sockDir | Out-Null
        & chmod 700 $sockDir
        $pipeName = Join-Path $sockDir 'agent.sock'
    }
    $agent = Start-G03InstrumentedAgent -Ctx $ctx -Name 'selftest' -PipeName $pipeName -KeyCount 2 -AllowedKeyIndexes 1 -RunSeconds 120
    $checks['agent_ready'] = ($agent.Ready.status -eq 'listening')
    $env1 = @{ SSH_AUTH_SOCK = $agent.PipePath }

    $r = Invoke-G03Native -Ctx $ctx -FilePath $SshAdd -ArgList @('-l') -Env $env1 -TimeoutSec 30
    $transcripts += Save-G03Transcript -Ctx $ctx -CaseId $case -Label 'ssh-add-l' -Result $r
    $out = Get-G03StdoutText $r
    $fp1 = ($agent.Ready.keys | Where-Object { $_.index -eq 1 }).fingerprint
    $fp2 = ($agent.Ready.keys | Where-Object { $_.index -eq 2 }).fingerprint
    $checks['list_exit_0'] = ($r.ExitCode -eq 0)
    $checks['list_contains_allowed_key'] = $out.Contains($fp1)
    $checks['list_excludes_filtered_key'] = -not $out.Contains($fp2)

    $data = Join-Path $ctx.Scratch 'message.txt'
    Write-G03Utf8File -Path $data -Text "heimdall g03 self-test $(New-G03RandomHex 8)`n"
    $pub1 = Join-Path $agent.Dir 'probe-key-1.pub'
    $pub2 = Join-Path $agent.Dir 'probe-key-2.pub'
    $r = Invoke-G03Native -Ctx $ctx -FilePath $SshKeygen -ArgList @('-Y', 'sign', '-U', '-f', $pub1, '-n', 'heimdall-g03', $data) -Env $env1 -TimeoutSec 30
    $transcripts += Save-G03Transcript -Ctx $ctx -CaseId $case -Label 'ssh-keygen-sign-allowed' -Result $r
    $checks['sign_allowed_exit_0'] = ($r.ExitCode -eq 0)
    $sigFile = "$data.sig"
    $allowedSigners = Join-Path $ctx.Scratch 'allowed_signers'
    $pubLine = ([System.IO.File]::ReadAllText($pub1)).Trim()
    Write-G03Utf8File -Path $allowedSigners -Text ("probe@heimdall " + ($pubLine -split ' ')[0] + ' ' + ($pubLine -split ' ')[1] + "`n")
    $verifyArgs = @('-Y', 'verify', '-f', $allowedSigners, '-I', 'probe@heimdall', '-n', 'heimdall-g03', '-s', $sigFile)
    $r = Invoke-G03Native -Ctx $ctx -FilePath $SshKeygen -ArgList $verifyArgs -StdinBytes ([System.IO.File]::ReadAllBytes($data)) -TimeoutSec 30
    $transcripts += Save-G03Transcript -Ctx $ctx -CaseId $case -Label 'ssh-keygen-verify' -Result $r
    $checks['verify_exit_0'] = ($r.ExitCode -eq 0)
    $checks['verify_good_signature'] = ((Get-G03StdoutText $r) + $r.StderrText) -match 'Good "heimdall-g03" signature'

    Remove-Item -LiteralPath $sigFile -ErrorAction SilentlyContinue
    $r = Invoke-G03Native -Ctx $ctx -FilePath $SshKeygen -ArgList @('-Y', 'sign', '-U', '-f', $pub2, '-n', 'heimdall-g03', $data) -Env $env1 -TimeoutSec 30
    $transcripts += Save-G03Transcript -Ctx $ctx -CaseId $case -Label 'ssh-keygen-sign-filtered' -Result $r
    $checks['sign_filtered_nonzero_exit'] = ($r.ExitCode -ne 0)

    # Crafted SIGN_REQUEST for the filtered key (ssh-keygen refuses client-side
    # because the key is not listed) and for an unknown key blob.
    $raw = Invoke-G03AgentRaw -PipeName $pipeName -Payload (New-G03SignRequest -KeyBlob (Get-G03PubKeyBlob $pub2))
    $checks['crafted_sign_filtered_key_failure_reply'] = ($raw.Connected -and $raw.ReplyType -eq 5)
    $unknown = [byte[]](Get-G03PubKeyBlob $pub1); $unknown[$unknown.Length - 1] = $unknown[$unknown.Length - 1] -bxor 0xFF
    $raw = Invoke-G03AgentRaw -PipeName $pipeName -Payload (New-G03SignRequest -KeyBlob $unknown)
    $checks['crafted_sign_unknown_key_failure_reply'] = ($raw.Connected -and $raw.ReplyType -eq 5)

    $r = Invoke-G03Native -Ctx $ctx -FilePath $SshAdd -ArgList @('-D') -Env $env1 -TimeoutSec 30
    $transcripts += Save-G03Transcript -Ctx $ctx -CaseId $case -Label 'ssh-add-D' -Result $r
    $checks['remove_all_refused_nonzero_exit'] = ($r.ExitCode -ne 0)

    Start-Sleep -Milliseconds 500
    $contact = Get-G03AgentContact -Agent $agent
    $log = Read-G03AgentLog -Path $agent.LogPath
    $checks['log_has_signed'] = ($contact.signed -ge 1)
    $checks['log_has_denied_filtered'] = [bool](@($log | Where-Object { (Get-G03Prop $_ 'result') -eq 'denied_filtered_key' }).Count)
    $checks['log_has_denied_unknown'] = [bool](@($log | Where-Object { (Get-G03Prop $_ 'result') -eq 'denied_unknown_key' }).Count)
    $checks['log_has_denied_remove_all'] = [bool](@($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'request' -and (Get-G03Prop $_ 'msg_type') -eq 19 }).Count)
    # The single server instance is re-armed with Disconnect() after every client
    # (no dispose/recreate window on the name); every completed client must show it.
    $disc = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'disconnect' }).Count
    $rearmDisc = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'rearm' -and (Get-G03Prop $_ 'method') -eq 'disconnect' }).Count
    $rearmOther = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'rearm' -and (Get-G03Prop $_ 'method') -ne 'disconnect' }).Count
    $checks['server_instance_rearmed_by_disconnect'] = ($disc -ge 5 -and $rearmDisc -eq $disc -and $rearmOther -eq 0)
    Copy-Item -LiteralPath $agent.LogPath -Destination (Join-Path (Get-G03CaseArtifactDir -Ctx $ctx -CaseId $case) 'agent-log.jsonl')
} catch {
    $checks['exception'] = $_.Exception.Message
} finally {
    $stops = Stop-G03AllOwned -Ctx $ctx
    if ($sockDir -and (Test-Path -LiteralPath $sockDir)) { Remove-Item -LiteralPath $sockDir -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-G03Scratch -Ctx $ctx
}
$leaks = Test-G03CanaryLeak -Ctx $ctx
$checks['no_canary_leak'] = ($leaks.Count -eq 0)
# Status convention (tests/evidence/README.md): an exception means the run is
# incomplete (in_progress / inconclusive); otherwise the run is verified and the
# verdict says whether every check held.
$incomplete = $checks.Contains('exception')
$allPass = $true
foreach ($k in $checks.Keys) { if ($checks[$k] -ne $true) { $allPass = $false } }
$verdict = if ($incomplete) { 'inconclusive' } elseif ($allPass) { 'pass' } else { 'fail' }
$sshV = Get-G03SshVersion -Ctx $ctx -Exe ($SshAdd -replace 'ssh-add', 'ssh')
$envObj = [ordered]@{ os = (Get-G03WindowsBuild); powershell = $PSVersionTable.PSVersion.ToString(); edition = $PSVersionTable.PSEdition
    dotnet = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription; openssh = $sshV
    harness = [ordered]@{ InstrumentedAgent = (Get-G03FileSha256 (Join-Path $PSScriptRoot 'InstrumentedAgent.ps1')); G03Common = (Get-G03FileSha256 (Join-Path $PSScriptRoot 'G03Common.psm1')) } }
$status = if ($incomplete) { 'in_progress' } else { 'verified' }
# Harness self-test records name no product requirement (tests/evidence/README.md).
$file = Write-G03Record -Ctx $ctx -CaseId $case -Status $status -RequirementIds @() -Environment $envObj `
    -Commands @('pwsh -NoProfile -File tests/native/windows/Test-G03HarnessSelf.ps1') `
    -Observed ([ordered]@{ verdict = $verdict; checks = $checks; agent_stop = $stops }) `
    -EvidencePaths $transcripts `
    -Limitations @('Harness self-test only: NOT G03 evidence. Establishes the instrumented agent protocol/ECDSA encoding against the local OpenSSH tools; says nothing about Windows named pipes, DACLs, Win32-OpenSSH endpoint selection, or WSL.',
        'On non-Windows hosts .NET maps the named pipe to a Unix-domain socket; Windows-only code paths (CreateNamedPipeW with SDDL DACL, PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_FIRST_PIPE_INSTANCE, max instances, client PID/SID) are not exercised.',
        'Names no product requirement: a harness self-test is not requirement evidence (tests/evidence/README.md).',
        'Windows PowerShell 5.1 compatibility is not exercised by this run.')
Write-Output ("self-test verdict: $verdict record: $file")
$checks.GetEnumerator() | ForEach-Object { Write-Output ("  {0} = {1}" -f $_.Key, $_.Value) }
if ($allPass) { exit 0 } else { exit 1 }
