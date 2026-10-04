<#
.SYNOPSIS
  G03 native Windows probe harness (plan.md sec. 3 G03; spec sec. 8.4, sec. 10.3, sec. 10.4, sec. 13.2; A14, A12 inputs).

.DESCRIPTION
  Runs on a REAL Windows x86-64 host (a disposable VM or CI runner is
  preferred). Each probe writes one evidence record (tests/evidence/
  record.schema.json) plus redacted transcripts under -OutDir. On a
  non-Windows host every probe is recorded as "blocked".

  Default mode never contacts the owner's real agent, never changes services,
  never edits global Git or SSH configuration, and never runs an ssh client
  that could read the owner's %USERPROFILE%\.ssh: every ssh.exe/ssh-add.exe
  child receives an explicit SSH_AUTH_SOCK (fixture pipe or a sentinel pipe
  that does not exist) and every ssh.exe child receives `-F <fixture config>`
  with IdentityFile=none, a fixture UserKnownHostsFile and
  GlobalKnownHostsFile=none. HOME is redirected to scratch, but that protects
  only MSYS/Git-bundled tools: Win32-OpenSSH resolves its home from the user
  profile, not HOME. Git's own default ssh (no core.sshCommand/GIT_SSH*) is
  therefore never executed in default mode; the git probe only resolves which
  binary it would be (passive) unless -IAmOnADisposableHost is given.

  Gated sub-probes need explicit switches:
    -AllowProviderContact      contact \\.\pipe\openssh-ssh-agent (system agent or
                               1Password) - requires -OwnerAuthorizationNote.
    -AllowSystemAgentMutation  add/remove a disposable key in the Windows OpenSSH
                               agent store and start/stop its service - requires
                               -IAmOnADisposableHost and -OwnerAuthorizationNote.
    -IAmOnADisposableHost      (alone) also enables the git probe's live
                               default_no_override case, which runs Git's default
                               ssh without -F; it is skipped unless
                               %USERPROFILE%\.ssh is absent or empty and
                               %PROGRAMDATA%\ssh\ssh_config does not exist
                               (existence/counts only, contents never read).
                               It also lets the sshauthsock/stalepipe probes serve
                               a fixture decoy on \\.\pipe\openssh-ssh-agent while
                               that name is free (service stopped, no 1Password),
                               to detect a client fallback.

  Owner state that default mode does read: P-W01 asks git in which scopes
  core.sshCommand is set (git reads the owner's Git config; only scope names are
  recorded, never a value or path). Default mode writes outside scratch only in
  the other-user probes: a per-run %PUBLIC%\heimdall-g03-<run> directory whose
  protected DACL names only this account and the other test account (removed at
  the end). Residual: the dead-pipe ssh-add rows (P-W02 sentinel, P-W06) would
  reach \\.\pipe\openssh-ssh-agent only if the client fell back to it, which the
  pinned v10.0.0.0 source does not do [S]; their stdout is then not saved.

  Probe ids for -Probes: env, sshauthsock, identityagent, git, otheruser,
  stalepipe, processio, quoting, service, onepassword, agentconstraints,
  wslotheruser, keyperms.

.EXAMPLE
  # Passive inventory + local-only probes (no SSH server needed):
  pwsh -File Invoke-G03WindowsProbes.ps1 -Probes env,sshauthsock,stalepipe,service

.EXAMPLE
  # Full default-mode run against a disposable SSH fixture (e.g. M00-T03 containers):
  pwsh -File Invoke-G03WindowsProbes.ps1 -SshHost 127.0.0.1 -SshPort 49222 -SshUser enroll `
       -KnownHostsFile C:\fixtures\known_hosts -AuthorizeKeyScript C:\fixtures\authorize.ps1 `
       -GitRemoteUrl ssh://enroll@127.0.0.1:49222/srv/git/probe.git `
       -OtherUserCredential (Get-Credential heimdall-probe-other)

.EXAMPLE
  # Serve an instrumented agent for the WSL harness (keep the window open):
  pwsh -File Invoke-G03WindowsProbes.ps1 -ServeAgentForWsl -ServeSeconds 3600
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string[]]$Probes = @('all'),
    [string]$SshHost,
    [int]$SshPort = 22,
    [string]$SshUser,
    [string]$KnownHostsFile,
    [string]$AuthorizeKeyScript,         # invoked as: & $AuthorizeKeyScript -PublicKeyPath <pub>
    [switch]$PauseForKeyInstall,         # interactive alternative to -AuthorizeKeyScript
    [string]$GitRemoteUrl,
    [System.Management.Automation.PSCredential]$OtherUserCredential,
    [switch]$AllowProviderContact,
    [switch]$AllowSystemAgentMutation,
    [switch]$IAmOnADisposableHost,
    [string]$OwnerAuthorizationNote,
    [switch]$ServeAgentForWsl,
    [int]$ServeSeconds = 1800,
    [string]$WslDistro                   # disposable WSL distribution for the other-Windows-user probe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'G03Common.psm1') -Force
$repo = (Resolve-Path (Join-Path $PSScriptRoot (Join-Path '..' (Join-Path '..' '..')))).Path
$ctx = New-G03RunContext -RepoRoot $repo -OutDir $OutDir
$OnWin = Test-G03OnWindows

if ($AllowProviderContact -and -not $OwnerAuthorizationNote) { throw '-AllowProviderContact requires -OwnerAuthorizationNote (reference to the owner''s explicit authorization).' }
if ($AllowSystemAgentMutation -and (-not $IAmOnADisposableHost -or -not $OwnerAuthorizationNote)) { throw '-AllowSystemAgentMutation requires -IAmOnADisposableHost and -OwnerAuthorizationNote.' }

$SysSsh = $null; $SysSshAdd = $null; $SysKeygen = $null
if ($OnWin) {
    $SysSsh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    $SysSshAdd = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-add.exe'
    $SysKeygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
}
$Fixture = $null
if ($SshHost -and $SshUser -and $KnownHostsFile -and (Test-Path -LiteralPath $KnownHostsFile)) {
    $kh = Join-Path $ctx.Scratch 'known_hosts'
    Copy-Item -LiteralPath $KnownHostsFile -Destination $kh
    $Fixture = [pscustomobject]@{ Host = $SshHost; Port = $SshPort; User = $SshUser; KnownHosts = $kh }
}
$QuotingCases = (Get-Content -LiteralPath (Join-Path $PSScriptRoot (Join-Path 'fixtures' 'quoting-cases.json')) -Raw -Encoding UTF8 | ConvertFrom-Json)

$HarnessFiles = [ordered]@{}
foreach ($f in @('Invoke-G03WindowsProbes.ps1', 'G03Common.psm1', 'InstrumentedAgent.ps1', 'PipeStdioRelay.ps1')) { $HarnessFiles[$f] = Get-G03FileSha256 (Join-Path $PSScriptRoot $f) }

$nativeArgMode = 'n/a (Windows PowerShell 5.1 legacy)'
if (Get-Variable -Name PSNativeCommandArgumentPassing -ErrorAction SilentlyContinue) { $nativeArgMode = [string]$PSNativeCommandArgumentPassing }
$BaseEnv = [ordered]@{
    run_id     = $ctx.RunId
    os         = (Get-G03WindowsBuild)
    powershell = [ordered]@{ version = $PSVersionTable.PSVersion.ToString(); edition = $PSVersionTable.PSEdition; native_argument_passing = $nativeArgMode }
    dotnet     = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
    elevated   = (Test-G03Elevated)
    harness_sha256 = $HarnessFiles
    fixture_server = $(if ($Fixture) { "provided (port $($Fixture.Port))" } else { 'not provided' })
    gates = [ordered]@{ allow_provider_contact = [bool]$AllowProviderContact; allow_system_agent_mutation = [bool]$AllowSystemAgentMutation
        disposable_host_declared = [bool]$IAmOnADisposableHost; owner_authorization_note = $(if ($OwnerAuthorizationNote) { 'provided' } else { $null }) }
}
$ProviderVersions = @()
if ($OnWin) {
    foreach ($exe in (Get-G03SshCandidates)) {
        $v = Get-G03SshVersion -Ctx $ctx -Exe $exe
        if ($v) { $ProviderVersions += [ordered]@{ name = "ssh client $exe"; version = $v.version_banner; file_version = $v.file_version; sha256 = $v.sha256 } }
    }
    $gitCmd = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($gitCmd) { $gv = Invoke-G03Native -Ctx $ctx -FilePath $gitCmd.Source -ArgList @('--version') -TimeoutSec 20; $ProviderVersions += [ordered]@{ name = "git $($gitCmd.Source)"; version = (Get-G03StdoutText $gv).Trim() } }
    $op = Get-Process -Name '1Password' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($op) { $opv = $null; try { $opv = $op.FileVersion } catch { }; $ProviderVersions += [ordered]@{ name = '1Password (running process)'; version = $opv } }
}

$NotWindowsBlock = 'native Windows 11 (or Windows 10 22H2) x86-64 host with the in-box OpenSSH client (Win32-OpenSSH; exact build recorded at run time); this run was not on Windows'
$NoFixtureBlock = 'disposable SSH fixture server reachable from the Windows host (-SshHost/-SshUser/-KnownHostsFile), e.g. tests/fixtures/ssh (M00-T03) containers'
$NoAuthBlock = 'a way to authorize the run''s ephemeral probe key on the disposable fixture account (-AuthorizeKeyScript or -PauseForKeyInstall)'

function New-Result {
    param([string]$CaseId, [string[]]$Reqs)
    return [ordered]@{ CaseId = $CaseId; Reqs = $Reqs; Status = 'in_progress'; Observed = [ordered]@{}; Limitations = New-Object System.Collections.ArrayList
        BlockedOn = $null; Evidence = New-Object System.Collections.ArrayList; Commands = New-Object System.Collections.ArrayList }
}
function Set-Blocked { param($R, [string]$On) $R.Status = 'blocked'; $R.BlockedOn = $On; $R.Observed = $null; return $R }
function Set-Verdict {
    # Gate-probe status convention (tests/evidence/README.md, orchestrator
    # decision 2026-10-03): status describes the evidence, verdict the criterion.
    #   any criterion null (unobservable, missing/failed control, environment
    #   problem)                      -> in_progress, verdict inconclusive
    #   otherwise any criterion false -> verified,    verdict fail
    #   all criteria true             -> verified,    verdict pass
    # Criteria that were observed false are listed in failed_criteria in every case.
    param($R, [hashtable]$Criteria)
    $R.Observed['criteria'] = $Criteria
    $fail = @($Criteria.Keys | Where-Object { $Criteria[$_] -eq $false } | Sort-Object)
    $unknown = @($Criteria.Keys | Where-Object { $null -eq $Criteria[$_] } | Sort-Object)
    $R.Observed['failed_criteria'] = $fail
    $R.Observed['unobserved_criteria'] = $unknown
    if ($Criteria.Count -eq 0 -or $unknown.Count -gt 0) { $R.Observed['verdict'] = 'inconclusive'; $R.Status = 'in_progress' }
    elseif ($fail.Count -gt 0) { $R.Observed['verdict'] = 'fail'; $R.Status = 'verified' }
    else { $R.Observed['verdict'] = 'pass'; $R.Status = 'verified' }
    return $R
}
function Add-Run {
    param($R, [string]$Label, $Res, [switch]$Binary)
    [void]$R.Evidence.Add((Save-G03Transcript -Ctx $ctx -CaseId $R.CaseId -Label $Label -Result $Res -BinaryStdout:$Binary))
    [void]$R.Commands.Add(("{0} {1} (exit {2})" -f $Res.FilePath, $Res.Arguments, $Res.ExitCode))
}
function New-FixtureConfig {
    param([string]$Alias = 'probe-target', [string]$ExtraLines = '')
    $dir = Join-Path $ctx.Scratch ('cfg ' + (New-G03RandomHex 3))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $cfg = Join-Path $dir 'ssh config'
    $text = @("Host $Alias", "    HostName $($Fixture.Host)", "    Port $($Fixture.Port)", "    User $($Fixture.User)", $ExtraLines) -join "`n"
    Write-G03Utf8File -Path $cfg -Text ($text + "`n")
    return $cfg
}
function Get-SshArgs {
    param([string]$Config, [string[]]$Extra = @(), [string]$Alias = 'probe-target', [string[]]$Remote = @('true'), [string[]]$Without = @())
    return @('-F', $Config) + (Get-G03BaseSshOptions -KnownHostsFile $Fixture.KnownHosts -Without $Without) + $Extra + @($Alias) + $Remote
}
function Get-SshAddPaths {
    $list = @($SysSshAdd)
    foreach ($c in (Get-G03SshCandidates)) {
        $a = Join-Path (Split-Path -Parent $c) 'ssh-add.exe'
        if ((Test-Path -LiteralPath $a) -and ($list -notcontains $a)) { $list += $a }
    }
    return $list
}

function Invoke-DeadSockClient {
    # Runs `<ssh-add> -l` with SSH_AUTH_SOCK = a pipe with no server and judges whether
    # the client fell back to \\.\pipe\openssh-ssh-agent (an unset SSH_AUTH_SOCK means
    # that pipe in Win32-OpenSSH). Exit 2 alone cannot show "no fallback" when nothing
    # listens on the default name, because a fallback would then also exit 2. So:
    #  * default pipe present (another server owns it): exit 2 discriminates (a fallback
    #    would reach that server and list, exit 0/1). The server is reached only if the
    #    client falls back; stdout is then NOT saved (it could list the owner's keys),
    #    only the exit code and the stdout line count are kept.
    #  * default pipe absent, declared disposable host (-IAmOnADisposableHost), ssh-agent
    #    service not running, no 1Password process: a fixture decoy agent serves the
    #    default name (first-instance flag) for this one run and must see no connection.
    #  * otherwise fallback is not judged (fallback_judged = false, reason recorded).
    param($R, [string]$Label, [string]$Exe, [string]$SockPath)
    $o = [ordered]@{ ssh_add = $Exe; default_pipe_present = $null; decoy = 'none'; decoy_connections = $null; exit_code = $null
        stdout_line_count = $null; fallback_judged = $false; no_fallback = $null; reason = $null }
    $present = ((Get-G03PipeNames) -contains 'openssh-ssh-agent')
    $o.default_pipe_present = $present
    $decoy = $null
    if (-not $present) {
        $svc = Get-G03AgentServiceState
        $svcRunning = ($null -ne $svc -and $svc['present'] -and $svc['status'] -eq 'Running')
        $op = (Get-G03ProcessPresence -Names @('1Password'))['1Password']
        if (-not $IAmOnADisposableHost) { $o.reason = 'nothing listens on the default pipe name and serving a decoy there needs -IAmOnADisposableHost' }
        elseif ($svcRunning -or $op) { $o.reason = 'decoy not started: ssh-agent service running or 1Password process present' }
        else {
            $decoy = Start-G03InstrumentedAgent -Ctx $ctx -Name 'defaultdecoy' -PipeName 'openssh-ssh-agent' -RunSeconds 60 -ExpectStartFailure
            if ($null -eq $decoy.Ready -or [string]$decoy.Ready.status -ne 'listening') {
                [void](Stop-G03InstrumentedAgent $decoy); $decoy = $null
                $o.reason = 'decoy on the default name did not start (name taken meanwhile)'
            } else { $o.decoy = 'fixture agent on the default pipe name (declared disposable host)' }
        }
    }
    $res = Invoke-G03Native -Ctx $ctx -FilePath $Exe -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = $SockPath } -TimeoutSec 30
    $o.exit_code = $res.ExitCode
    $o.stdout_line_count = @((Get-G03StdoutText $res) -split "`r?`n" | Where-Object { $_.Trim() }).Count
    if ($present) {
        [void]$R.Commands.Add(("{0} -l (exit {1}; stdout not saved: default pipe present)" -f $Exe, $res.ExitCode))
        $o.fallback_judged = $true; $o.no_fallback = ($res.ExitCode -eq 2)
    } else {
        Add-Run $R $Label $res
        if ($decoy) {
            Start-Sleep -Milliseconds 300
            $dc = Get-G03AgentContact $decoy
            [void](Stop-G03InstrumentedAgent $decoy)
            $o.decoy_connections = $dc.connections
            $o.fallback_judged = $true; $o.no_fallback = ($dc.connections -eq 0 -and $res.ExitCode -eq 2)
        }
    }
    return $o
}

# ------------------------------------------------------------------ W01 env
function Invoke-ProbeEnv {
    $r = New-Result 'G03-win-env-inventory' @('R-EN-01', 'R-SS-03', 'R-QU-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $cands = @()
    foreach ($exe in (Get-G03SshCandidates)) { $cands += (Get-G03SshVersion -Ctx $ctx -Exe $exe) }
    $git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $gitCfg = $null
    if ($git) {
        # Presence and scope only (M00-T04-G03-fix2, review D3): git reads the owner's
        # Git configuration to answer, but `--name-only` prints variable names, never
        # values, and `--show-scope` prints system/global/local/command instead of file
        # paths. No value or origin path is recorded. Runs in scratch so no repository
        # (local) config is involved.
        $gc = Invoke-G03Native -Ctx $ctx -FilePath $git.Source -ArgList @('-C', $ctx.Scratch, 'config', '--show-scope', '--name-only', '--get-regexp', '^core\.sshcommand$') -TimeoutSec 20
        Add-Run $r 'git-config-core-sshCommand-scopes' $gc
        $scopes = @((Get-G03StdoutText $gc) -split "`r?`n" | Where-Object { $_ -match '^\s*(\S+)\s+core\.sshcommand\s*$' } | ForEach-Object { $Matches[1] })
        $gitCfg = [ordered]@{ exit = $gc.ExitCode; set_in_scopes = $scopes; note = 'exit 1 = not set in any scope; values and origin paths are not read into the record' }
    }
    $pipes = Get-G03PipeNames
    $r.Observed = [ordered]@{
        ssh_candidates = $cands
        path_order = (Get-G03PathOrder)
        git_core_sshCommand = $gitCfg
        git_env_present = [ordered]@{ GIT_SSH = [bool]$env:GIT_SSH; GIT_SSH_COMMAND = [bool]$env:GIT_SSH_COMMAND; GIT_SSH_VARIANT = [bool]$env:GIT_SSH_VARIANT }
        session_SSH_AUTH_SOCK = [ordered]@{ present = [bool]$env:SSH_AUTH_SOCK; is_named_pipe_path = ([string]$env:SSH_AUTH_SOCK -match '^(\\\\|//)\.(\\|/)pipe') }
        agent_service = (Get-G03AgentServiceState)
        default_agent_pipe_present = ($pipes -contains 'openssh-ssh-agent')
        agent_like_pipe_names = @($pipes | Where-Object { $_ -match '(?i)ssh|agent|1password|pageant|gpg|heimdall' })
        processes_present = (Get-G03ProcessPresence -Names @('1Password', 'ssh-agent', 'pageant', 'gpg-agent'))
        note = 'Passive: pipe names were enumerated (no pipe was opened); no agent was contacted.'
    }
    return (Set-Verdict $r @{ inventory_collected = $true; system32_ssh_present = (Test-Path -LiteralPath $SysSsh) })
}

# ------------------------------------------------------------------ W02 SSH_AUTH_SOCK
function Invoke-ProbeSshAuthSock {
    $r = New-Result 'G03-win-sshauthsock-selection' @('R-EN-01', 'R-SS-03', 'R-RT-03')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $rows = @(); $sentinelRows = @()
    $uniName = ([string]$QuotingCases.pipe_name_cases[0].name_prefix) + ' ' + (New-G03RandomHex 4)
    foreach ($exe in (Get-SshAddPaths)) {
        $t = Start-G03InstrumentedAgent -Ctx $ctx -Name 'target' -RunSeconds 180
        $u = Start-G03InstrumentedAgent -Ctx $ctx -Name 'unicode' -PipeName $uniName -RunSeconds 180
        $forms = [ordered]@{
            backslash            = "\\.\pipe\$($t.PipeName)"
            forward_slash        = "//./pipe/$($t.PipeName)"
            space_unicode_pipe   = "\\.\pipe\$uniName"
        }
        $tag = Split-Path -Leaf (Split-Path -Parent $exe)
        foreach ($k in $forms.Keys) {
            $res = Invoke-G03Native -Ctx $ctx -FilePath $exe -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = $forms[$k] } -TimeoutSec 30
            Add-Run $r "ssh-add-l-$k-$tag" $res
            $out = Get-G03StdoutText $res
            $rows += [ordered]@{ ssh_add = $exe; form = $k; exit_code = $res.ExitCode
                lists_target_key = $out.Contains([string]$t.Ready.keys[0].fingerprint); lists_unicode_agent_key = $out.Contains([string]$u.Ready.keys[0].fingerprint)
                stderr_first_line = (($res.StderrText -split "`r?`n") | Select-Object -First 1) }
        }
        Start-Sleep -Milliseconds 300
        $r.Observed["agent_contact_$tag"] = [ordered]@{ target = (Get-G03AgentContact $t); unicode = (Get-G03AgentContact $u) }
        [void](Stop-G03InstrumentedAgent $t); [void](Stop-G03InstrumentedAgent $u)
        $sentinelRows += (Invoke-DeadSockClient -R $r -Label "ssh-add-l-nonexistent_sentinel-$tag" -Exe $exe -SockPath $ctx.SentinelPipe)
    }
    $r.Observed['cases'] = $rows
    $r.Observed['nonexistent_sentinel'] = $sentinelRows
    $sys = @($rows | Where-Object { $_.ssh_add -eq $SysSshAdd })
    $sysSentinel = @($sentinelRows | Where-Object { $_.ssh_add -eq $SysSshAdd }) | Select-Object -First 1
    $crit = @{
        system32_backslash_selects_fixture = [bool](@($sys | Where-Object { $_.form -eq 'backslash' -and $_.exit_code -eq 0 -and $_.lists_target_key }).Count)
        system32_nonexistent_fails_cleanly = ($null -ne $sysSentinel -and $sysSentinel.exit_code -eq 2)
    }
    if ($null -ne $sysSentinel -and $sysSentinel.fallback_judged) { $crit['system32_nonexistent_does_not_fall_back'] = [bool]$sysSentinel.no_fallback }
    else { [void]$r.Limitations.Add('Fallback to \\.\pipe\openssh-ssh-agent was not judged on this run: nothing listened on that name and no decoy was permitted (see nonexistent_sentinel.reason). Exit 2 alone cannot distinguish "no fallback" from "fell back to a name with no server".') }
    [void]$r.Limitations.Add('ssh-add exit 2 = could not connect to an agent; exit 1 = agent reachable but no identities (a fallback to another agent would show 0 or 1). When the default pipe was present its server was reached only if the client fell back, and that run''s stdout was not saved.')
    [void]$r.Limitations.Add('Forward-slash and space/Unicode pipe-name forms and non-System32 ssh-add builds are recorded as observations, not pass criteria.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W03 IdentityAgent
function Invoke-SelectionCase {
    param([string]$SshExe, [string]$Channel, [string]$FormId, [string]$Template)
    $pn = $null
    if ($FormId -eq 'fs_quoted_space_unicode') { $pn = 'heimdall g03 ' + [char]0x00FC + ' ' + (New-G03RandomHex 4) }
    $t = Start-G03InstrumentedAgent -Ctx $ctx -Name 'target' -PipeName $pn -RunSeconds 120
    $d = Start-G03InstrumentedAgent -Ctx $ctx -Name 'decoy' -RunSeconds 120
    $value = $Template.Replace('{T}', $t.PipeName)
    $extraLine = ''; $extraArgs = @()
    $envs = @{ SSH_AUTH_SOCK = $d.PipePath; HEIMDALL_G03_IA = $t.PipePath }
    if ($FormId -eq 'control_env_only') {
        # Control: no IdentityAgent at all, target in SSH_AUTH_SOCK. Proves the run reaches
        # public-key authentication; if it does not, selection results are inconclusive.
        $envs['SSH_AUTH_SOCK'] = $t.PipePath
    } elseif ($Channel -eq 'config') { $extraLine = "    IdentityAgent $value" } else { $extraArgs = @('-o', "IdentityAgent=$value") }
    $cfg = New-FixtureConfig -ExtraLines $extraLine
    $g = Invoke-G03Native -Ctx $ctx -FilePath $SshExe -ArgList (@('-G', '-F', $cfg) + $extraArgs + @('probe-target')) -Env $envs -TimeoutSec 20
    $gLine = ((Get-G03StdoutText $g) -split "`r?`n" | Where-Object { $_ -like 'identityagent *' } | Select-Object -First 1)
    $res = Invoke-G03Native -Ctx $ctx -FilePath $SshExe -ArgList (Get-SshArgs -Config $cfg -Extra (@('-v') + $extraArgs)) -Env $envs -TimeoutSec 45
    Start-Sleep -Milliseconds 400
    $tc = Get-G03AgentContact $t; $dc = Get-G03AgentContact $d
    [void](Stop-G03InstrumentedAgent $t); [void](Stop-G03InstrumentedAgent $d)
    return [ordered]@{ ssh = $SshExe; channel = $Channel; form = $FormId; value_template = $Template; ssh_G_identityagent = $gLine
        exit_code = $res.ExitCode; contacted_target = ($tc.request_identities -gt 0); contacted_decoy = ($dc.request_identities -gt 0)
        target_client_paths = $tc.client_paths; transcript = $res }
}

function Invoke-ProbeIdentityAgent {
    $r = New-Result 'G03-win-identityagent-forms' @('R-EN-01', 'R-SS-03', 'R-RT-03')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    if (-not $Fixture) { return (Set-Blocked $r $NoFixtureBlock) }
    $forms = [ordered]@{
        control_env_only        = ''
        backslash               = '\\.\pipe\{T}'
        backslash_quoted        = '"\\.\pipe\{T}"'
        backslash_doubled       = '\\\\.\\pipe\\{T}'
        forward_slash           = '//./pipe/{T}'
        forward_slash_quoted    = '"//./pipe/{T}"'
        env_legacy              = '$HEIMDALL_G03_IA'
        env_braced              = '${HEIMDALL_G03_IA}'
        literal_SSH_AUTH_SOCK   = 'SSH_AUTH_SOCK'
        none                    = 'none'
        fs_quoted_space_unicode = '"//./pipe/{T}"'
    }
    $rows = @()
    foreach ($exe in (Get-G03SshCandidates)) {
        $tag = Split-Path -Leaf (Split-Path -Parent $exe)
        foreach ($channel in @('config', 'cli')) {
            foreach ($k in $forms.Keys) {
                $row = Invoke-SelectionCase -SshExe $exe -Channel $channel -FormId $k -Template $forms[$k]
                Add-Run $r "ssh-$channel-$k-$tag" $row.transcript
                $row.Remove('transcript')
                $rows += $row
            }
        }
    }
    $r.Observed['cases'] = $rows
    $sys = @($rows | Where-Object { $_.ssh -eq $SysSsh })
    $exclusive = @($sys | Where-Object { $_.contacted_target -and -not $_.contacted_decoy })
    $exclusive = @($exclusive | Where-Object { $_.form -ne 'control_env_only' })
    $r.Observed['system32_exclusive_forms'] = @($exclusive | ForEach-Object { "$($_.channel):$($_.form)" })
    $controlOk = (@($sys | Where-Object { $_.form -eq 'control_env_only' -and $_.contacted_target }).Count -ge 1)
    $crit = @{
        control_reaches_publickey_auth = $controlOk
        some_form_selects_fixture_pipe_exclusively = [bool]$exclusive.Count
        none_disables_agent = (@($sys | Where-Object { $_.form -eq 'none' -and -not $_.contacted_target -and -not $_.contacted_decoy }).Count -eq 2)
        literal_SSH_AUTH_SOCK_uses_environment = (@($sys | Where-Object { $_.form -eq 'literal_SSH_AUTH_SOCK' -and $_.contacted_decoy -and -not $_.contacted_target }).Count -eq 2)
    }
    if (-not $controlOk) { foreach ($k in @($crit.Keys)) { if ($k -ne 'control_reaches_publickey_auth') { $crit[$k] = $null } } }
    [void]$r.Limitations.Add('Selection is judged from instrumented-agent logs (REQUEST_IDENTITIES); authentication success is not required and the server may reject the key.')
    [void]$r.Limitations.Add('Results apply only to the ssh.exe builds in provider_versions; the config parser changed in upstream OpenSSH 8.7, so version floors must be re-run per shipped build.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W04 Git
function ConvertTo-ShWord { param([string]$S) return '"' + ($S -replace '(["\\$`])', '\$1') + '"' }

function Get-GitSshCommand {
    param([string]$Exe, [string]$Config, [string]$Extra = '')
    $parts = @((ConvertTo-ShWord ($Exe -replace '\\', '/')), '-F', (ConvertTo-ShWord ($Config -replace '\\', '/')))
    foreach ($o in (Get-G03BaseSshOptions -KnownHostsFile $Fixture.KnownHosts)) { if ($o -eq '-o') { $parts += '-o' } else { $parts += (ConvertTo-ShWord $o) } }
    if ($Extra) { $parts += $Extra }
    return ($parts -join ' ')
}

function Invoke-ProbeGit {
    $r = New-Result 'G03-win-git-ssh-selection' @('R-EN-01', 'R-SS-03', 'R-EN-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $git) { return (Set-Blocked $r 'Git for Windows installed on the Windows probe host') }
    if (-not $Fixture -or -not $GitRemoteUrl) { return (Set-Blocked $r ($NoFixtureBlock + ' and -GitRemoteUrl')) }
    $gitHome = Join-Path $ctx.Scratch 'git home'
    New-Item -ItemType Directory -Force -Path $gitHome | Out-Null
    $emptyCfg = Join-Path $gitHome 'empty.gitconfig'
    Write-G03Utf8File -Path $emptyCfg -Text ''
    $cfg = New-FixtureConfig
    $marker = Join-Path $ctx.Scratch 'git-ssh-marker.txt'
    $sentinel = Join-Path $ctx.Scratch 'git-ssh-sentinel.cmd'
    Write-G03Utf8File -Path $sentinel -Text ("@echo invoked> `"$marker`"`r`n@exit /b 1`r`n")
    # Passive default-ssh resolution (no ssh is executed). Git for Windows'
    # installer offers "Use bundled OpenSSH" vs "Use external OpenSSH" (the
    # latter removes the bundled binaries, install.iss [G03-S14]); Git's
    # default "ssh" is then found on PATH [I]. Which binary Git would run is
    # inferred from these facts; it is not executed here.
    $gitRoot = $null
    try { $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source) } catch { }
    $bundled = @()
    foreach ($rel in @('usr\bin\ssh.exe', 'bin\ssh.exe', 'mingw64\bin\ssh.exe')) {
        if ($gitRoot) { $cand = Join-Path $gitRoot $rel; if (Test-Path -LiteralPath $cand) { $bundled += $cand } }
    }
    $pathSsh = @(Get-Command ssh -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    $r.Observed['default_ssh_resolution'] = [ordered]@{
        git_executable = $git.Source; git_root = $gitRoot; bundled_ssh_present = $bundled
        installer_choice_inferred = $(if ($bundled.Count -gt 0) { 'bundled OpenSSH (MSYS ssh.exe present in the Git installation) [I]' } else { 'external OpenSSH (no bundled ssh.exe found) [I]' })
        path_ssh_order = $pathSsh
        note = 'Passive: no ssh was executed for this observation. Git prepends its own directories to PATH when started through its launcher [I], so a bundled ssh.exe takes precedence when present.'
    }
    $cases = @(
        @{ id = 'core_sshCommand_system32'; env = @{}; cfgArgs = @('-c', ('core.sshCommand=' + (Get-GitSshCommand -Exe $SysSsh -Config $cfg))); expect = 'target via SSH_AUTH_SOCK' },
        @{ id = 'GIT_SSH_COMMAND_beats_core_sshCommand'; env = @{ GIT_SSH_COMMAND = (Get-GitSshCommand -Exe $SysSsh -Config $cfg -Extra '-o IdentityAgent=//./pipe/{T}') }
            cfgArgs = @('-c', ('core.sshCommand=' + (Get-GitSshCommand -Exe $SysSsh -Config $cfg -Extra '-o IdentityAgent=//./pipe/{D}'))); expect = 'target' },
        @{ id = 'core_sshCommand_beats_GIT_SSH'; env = @{ GIT_SSH = $sentinel }; cfgArgs = @('-c', ('core.sshCommand=' + (Get-GitSshCommand -Exe $SysSsh -Config $cfg))); expect = 'target and no sentinel marker' }
    )
    # Live default case: Git's default ssh gets no -F/IdentityFile=none, and
    # Win32-OpenSSH ignores HOME, so it could read %USERPROFILE%\.ssh (config,
    # known_hosts, id_*) and follow an owner IdentityAgent to the real agent.
    # It runs only on a declared disposable host where the client has no SSH state
    # to read: %USERPROFILE%\.ssh absent or EMPTY (any entry - config, keys of any
    # name, known_hosts - blocks the row) and no %PROGRAMDATA%\ssh\ssh_config (a
    # system IdentityAgent there would override the fixture SSH_AUTH_SOCK). Existence
    # and entry counts only; no name or content is read into the record. Git's bundled
    # MSYS ssh resolves ~ from HOME (scratch here); its /etc/ssh/ssh_config inside the
    # Git installation is not inspected [I].
    $liveDefault = 'not run: default mode never executes Git''s default ssh (needs -IAmOnADisposableHost)'
    if ($IAmOnADisposableHost) {
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        $entries = 0
        if (Test-Path -LiteralPath $sshDir) { $entries = @(Get-ChildItem -LiteralPath $sshDir -Force -ErrorAction SilentlyContinue).Count }
        $sysCfg = Test-Path -LiteralPath (Join-Path $env:ProgramData 'ssh\ssh_config')
        if ($entries -gt 0) { $liveDefault = "not run: %USERPROFILE%\.ssh is not empty on the declared disposable host ($entries entries; names not recorded)" }
        elseif ($sysCfg) { $liveDefault = 'not run: %PROGRAMDATA%\ssh\ssh_config exists on the declared disposable host (contents not read)' }
        else {
            $cases = @(@{ id = 'default_no_override'; env = @{}; cfgArgs = @(); expect = 'records which ssh Git runs by default (disposable host)' }) + $cases
            $liveDefault = 'run (disposable host declared; %USERPROFILE%\.ssh absent or empty; no %PROGRAMDATA%\ssh\ssh_config). No BatchMode/known_hosts are passed (that is the point of the row), so ssh may stop at host-key verification before any agent contact; observation only'
        }
    }
    $r.Observed['default_no_override_live'] = $liveDefault
    $rows = @()
    foreach ($c in $cases) {
        if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker }
        $t = Start-G03InstrumentedAgent -Ctx $ctx -Name 'target' -RunSeconds 120
        $d = Start-G03InstrumentedAgent -Ctx $ctx -Name 'decoy' -RunSeconds 120
        $envs = @{ SSH_AUTH_SOCK = $t.PipePath; HOME = $gitHome; GIT_TRACE = '1'; GIT_TERMINAL_PROMPT = '0'; GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $emptyCfg }
        foreach ($k in $c.env.Keys) { $envs[$k] = ([string]$c.env[$k]).Replace('{T}', $t.PipeName).Replace('{D}', $d.PipeName) }
        $cfgArgs = @($c.cfgArgs | ForEach-Object { ([string]$_).Replace('{T}', $t.PipeName).Replace('{D}', $d.PipeName) })
        $res = Invoke-G03Native -Ctx $ctx -FilePath $git.Source -ArgList ($cfgArgs + @('ls-remote', $GitRemoteUrl)) -Env $envs -TimeoutSec 60
        Add-Run $r ('git-' + $c.id) $res
        Start-Sleep -Milliseconds 400
        $tc = Get-G03AgentContact $t; $dc = Get-G03AgentContact $d
        [void](Stop-G03InstrumentedAgent $t); [void](Stop-G03InstrumentedAgent $d)
        $rows += [ordered]@{ case = $c.id; expectation = $c.expect; exit_code = $res.ExitCode; contacted_target = ($tc.request_identities -gt 0)
            contacted_decoy = ($dc.request_identities -gt 0); target_client_paths = $tc.client_paths
            git_trace_run_command = @(($res.StderrText -split "`r?`n") | Where-Object { $_ -match 'run_command' } | Select-Object -First 2)
            git_ssh_sentinel_invoked = (Test-Path -LiteralPath $marker) }
    }
    $r.Observed['cases'] = $rows
    $by = @{}; foreach ($row in $rows) { $by[$row.case] = $row }
    $crit = @{
        core_sshCommand_system32_reaches_fixture_pipe = [bool]$by['core_sshCommand_system32'].contacted_target
        GIT_SSH_COMMAND_precedence = ($by['GIT_SSH_COMMAND_beats_core_sshCommand'].contacted_target -and -not $by['GIT_SSH_COMMAND_beats_core_sshCommand'].contacted_decoy)
        core_sshCommand_precedence_over_GIT_SSH = ($by['core_sshCommand_beats_GIT_SSH'].contacted_target -and -not $by['core_sshCommand_beats_GIT_SSH'].git_ssh_sentinel_invoked)
    }
    if (-not $crit['core_sshCommand_system32_reaches_fixture_pipe']) {
        # The System32 case is the control; without it precedence cannot be judged.
        $crit['GIT_SSH_COMMAND_precedence'] = $null; $crit['core_sshCommand_precedence_over_GIT_SSH'] = $null
    }
    [void]$r.Limitations.Add('Which ssh Git runs by default is inferred passively (default_ssh_resolution); the live default_no_override row exists only on a declared disposable host and is an observation, not a pass criterion.')
    [void]$r.Limitations.Add('GIT_CONFIG_GLOBAL/GIT_CONFIG_NOSYSTEM and HOME were redirected to scratch so the owner''s Git and MSYS ~/.ssh configuration were not read; installer-written system config is therefore excluded from these cases.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ other-user helper
# Staging (M00-T04-G03-fix2). Start-Process -Credential calls CreateProcessWithLogonW
# with the whole command line (PowerShell Process.cs StartWithCreateProcess
# [G03-S22]), and lpCommandLine is limited to 1024 characters (CreateProcessWithLogonW
# docs, quoted by the G03 recheck review). The script therefore travels as a FILE in a
# per-run shared directory and the command line is only
#   "<powershell.exe>" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<script>"
# (length checked, <= 1024, recorded). The directory is created fresh (a pre-existing
# path is refused) with a protected DACL naming exactly two trustees: this account
# (FullControl) and the other test account (Modify, to write its result file); the
# script file itself gets a protected DACL with the other account limited to
# ReadAndExecute. The DACL and emptiness are verified before any script is written.
# Same source [G03-S22]: the child receives the CALLER's environment block (so its
# TEMP/TMP/PSModulePath point into this account's profile) and, for a non-admin
# caller, the returned Process object may hold no handle. The staged preamble resets
# TEMP/TMP to a directory the other account creates in the shared directory, resets
# PSModulePath to the Windows PowerShell defaults and clears SSH_AUTH_SOCK; completion
# is detected from a done-marker file, not from the process handle.
$script:OtherUserShared = $null
function Get-OtherUserSid {
    $n = [string]$OtherUserCredential.UserName
    if ($n.StartsWith('.\')) { $n = $env:COMPUTERNAME + '\' + $n.Substring(2) }
    elseif ($n -notmatch '[\\@]') { $n = $env:COMPUTERNAME + '\' + $n }
    return (New-Object System.Security.Principal.NTAccount($n)).Translate([System.Security.Principal.SecurityIdentifier])
}
function Initialize-OtherUserShared {
    if ($script:OtherUserShared) { return $script:OtherUserShared }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $other = Get-OtherUserSid
    if ($other.Value -eq $me.Value) { throw '-OtherUserCredential names the account running the harness; a second account is required.' }
    $dir = Join-Path $env:PUBLIC ('heimdall-g03-' + $ctx.RunId)
    if (Test-Path -LiteralPath $dir) { throw "shared staging directory already exists; refusing to reuse a path this run did not create" }
    New-Item -ItemType Directory -Path $dir | Out-Null
    $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, [System.Security.AccessControl.FileSystemRights]::FullControl, $inh, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($other, [System.Security.AccessControl.FileSystemRights]::Modify, $inh, $none, $allow)))
    Set-Acl -LiteralPath $dir -AclObject $acl
    $chk = Get-Acl -LiteralPath $dir
    $sids = @($chk.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    $want = @(@($me.Value, $other.Value) | Sort-Object -Unique)
    if (-not $chk.AreAccessRulesProtected -or ($sids -join ',') -ne ($want -join ',')) { throw 'shared staging directory DACL verification failed (expected exactly the two test accounts, protected)' }
    if (@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 0) { throw 'shared staging directory was not empty after its DACL was set' }
    $script:OtherUserShared = [pscustomobject]@{ Dir = $dir; Me = $me; Other = $other
        Info = [ordered]@{ dacl_protected = $true; trustees = 'this account (FullControl), other test account (Modify)'; verified_before_use = $true } }
    return $script:OtherUserShared
}
function New-OtherUserScriptText {
    # Pure: the staged script = preamble (paths, environment reset) + try { probe } finally { done marker }.
    param([string]$ScriptText, [string]$OutFile, [string]$DoneFile, [string]$TmpDir)
    $q = { param([string]$s) return "'" + $s.Replace("'", "''") + "'" }
    $pre = @('$ErrorActionPreference = ''Continue''',
        ('$OutFile = ' + (& $q $OutFile)), ('$DoneFile = ' + (& $q $DoneFile)), ('$G03Tmp = ' + (& $q $TmpDir)),
        '$env:PSModulePath = [IO.Path]::Combine([string]$env:ProgramFiles, ''WindowsPowerShell\Modules'') + '';'' + [IO.Path]::Combine([string]$env:WINDIR, ''system32\WindowsPowerShell\v1.0\Modules'')',
        '[void][IO.Directory]::CreateDirectory($G03Tmp)', '$env:TEMP = $G03Tmp', '$env:TMP = $G03Tmp', '$env:SSH_AUTH_SOCK = $null',
        'try {') -join "`r`n"
    return ($pre + "`r`n" + $ScriptText + "`r`n} finally { [IO.File]::WriteAllText(`$DoneFile, 'done') }`r`n")
}
function Get-OtherUserArgLine {
    # Pure: short -File command line; returns the argument string and the full command-line length.
    param([string]$Exe, [string]$ScriptPath)
    if ($ScriptPath.Contains('"')) { throw 'staged script path contains a double quote' }
    $argLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
    return [pscustomobject]@{ ArgLine = $argLine; Length = ('"' + $Exe + '" ' + $argLine).Length }
}
function Start-AsOtherUser {
    param([string]$ScriptText, [string]$Label)
    $sh = Initialize-OtherUserShared
    $tag = $Label + '-' + (New-G03RandomHex 3)
    $outFile = Join-Path $sh.Dir ($tag + '.json')
    $doneFile = Join-Path $sh.Dir ($tag + '.done')
    $tmpDir = Join-Path $sh.Dir ($tag + '-tmp')
    $scriptPath = Join-Path $sh.Dir ($tag + '.ps1')
    $full = New-OtherUserScriptText -ScriptText $ScriptText -OutFile $outFile -DoneFile $doneFile -TmpDir $tmpDir
    # Create empty, lock the file DACL (other account: read/execute only), then write.
    [IO.File]::WriteAllText($scriptPath, '')
    $fa = New-Object System.Security.AccessControl.FileSecurity
    $fa.SetAccessRuleProtection($true, $false)
    $fa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sh.Me, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)))
    $fa.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sh.Other, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.AccessControlType]::Allow)))
    Set-Acl -LiteralPath $scriptPath -AclObject $fa
    [IO.File]::WriteAllText($scriptPath, $full, (New-Object System.Text.UTF8Encoding($true)))   # BOM: Windows PowerShell 5.1 reads BOM-less files as ANSI
    $exe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $cl = Get-OtherUserArgLine -Exe $exe -ScriptPath $scriptPath
    $argLine = $cl.ArgLine; $cmdLen = $cl.Length
    if ($cmdLen -gt 1024) { throw "other-user command line would be $cmdLen characters (CreateProcessWithLogonW limit 1024)" }
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -Credential $OtherUserCredential -WorkingDirectory $sh.Dir -WindowStyle Hidden -PassThru
    # Hold the process handle if this account may open it; without a held handle the
    # harness never calls HasExited/Kill/ExitCode (those would re-open by PID only).
    $held = $false
    try { $null = $p.Handle; $held = $true } catch { $held = $false }
    return [pscustomobject]@{ Process = $p; HandleHeld = $held; OutFile = $outFile; DoneFile = $doneFile; CommandLineLength = $cmdLen }
}
function Test-OtherUserExited {
    # $true/$false through the held handle; $null when no handle is held.
    param($Handle)
    if (-not $Handle.HandleHeld) { return $null }
    try { return [bool]$Handle.Process.HasExited } catch { return $null }
}
function Test-OtherUserRunning {
    # For polling loops: running unless the done marker exists or the held handle says exited.
    param($Handle)
    if (Test-Path -LiteralPath $Handle.DoneFile) { return $false }
    return ((Test-OtherUserExited $Handle) -ne $true)
}
function Wait-OtherUser {
    param($Handle, [int]$TimeoutSec = 60)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $how = 'timeout'
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Handle.DoneFile) { $how = 'done_marker'; break }
        if ((Test-OtherUserExited $Handle) -eq $true) { $how = 'process_exit_without_done_marker'; break }
        Start-Sleep -Milliseconds 250
    }
    if ($how -eq 'done_marker') {
        $d2 = [DateTime]::UtcNow.AddSeconds(5)
        while ((Test-OtherUserExited $Handle) -eq $false -and [DateTime]::UtcNow -lt $d2) { Start-Sleep -Milliseconds 200 }
    }
    $exited = Test-OtherUserExited $Handle
    $kill = 'not_needed'
    if ($exited -eq $false) {
        # Kill only through the handle held since start (identity bound to that handle).
        try { $Handle.Process.Kill(); $kill = 'killed_via_held_handle' } catch { $kill = 'kill_failed: ' + $_.Exception.GetType().Name }
    } elseif ($null -eq $exited -and $how -ne 'done_marker') {
        $kill = 'not_attempted: no process handle held (PID-only identity is not verifiable)'
    }
    $exit = $null
    if ((Test-OtherUserExited $Handle) -eq $true) { try { $exit = $Handle.Process.ExitCode } catch { $exit = $null } }
    $data = $null
    if (Test-Path -LiteralPath $Handle.OutFile) { try { $data = Get-Content -LiteralPath $Handle.OutFile -Raw | ConvertFrom-Json } catch { $data = $null } }
    return [pscustomobject]@{ ExitCode = $exit; TimedOut = ($how -eq 'timeout'); Completion = $how; HandleHeld = $Handle.HandleHeld
        Exited = $exited; Kill = $kill; CommandLineLength = $Handle.CommandLineLength; Data = $data }
}
$OtherUserStagingNote = 'Other-user staging: the script runs from a file in a per-run %PUBLIC% directory (protected DACL: this account + the other test account only) via Start-Process -Credential with a short -File command line (length recorded, <= 1024 for CreateProcessWithLogonW); preamble resets TEMP/TMP, PSModulePath and SSH_AUTH_SOCK inherited from the caller''s environment; completion from a done marker. Unexecuted on Windows: whether PowerShell 5.1''s Start-Process behaves like the pinned PowerShell 7 source [I], and whether the other account can read the script and write its result under that DACL.'
function Get-OtherUserProcessInfo {
    param($O)
    return [ordered]@{ exit_code = $O.ExitCode; timed_out = $O.TimedOut; completion = $O.Completion; handle_held = $O.HandleHeld
        kill = $O.Kill; command_line_length = $O.CommandLineLength; staging = $(if ($script:OtherUserShared) { $script:OtherUserShared.Info } else { $null }) }
}

# Win32 helper shared by the other-user and squat scripts (Windows PowerShell
# 5.1 / .NET Framework). Raw CreateNamedPipeW/CreateFileW calls report the
# exact Win32 error, so a DACL denial (ERROR_ACCESS_DENIED = 5) is not confused
# with a busy pipe (ERROR_PIPE_BUSY = 231) or a PowerShell-wrapped .NET
# exception (MethodInvocationException). Pipe parameters mirror
# InstrumentedAgent.ps1 exactly (duplex, overlapped, byte type,
# PIPE_REJECT_REMOTE_CLIENTS, 64 KiB buffers, default time-out 0), so the only
# difference between an instance attempt and its control is the existing
# pipe's DACL. CreateNamedPipe docs [G03-S10]: mismatched type, access,
# instance count or time-out, and FILE_FLAG_FIRST_PIPE_INSTANCE, ALSO give
# ERROR_ACCESS_DENIED, which is why every denial criterion has a control.
$OtherUserWin32 = @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class G03OU {
  [StructLayout(LayoutKind.Sequential)] struct SA { public int nLength; public IntPtr sd; public int inherit; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateNamedPipeW")] static extern IntPtr CreateNamedPipeSa(string n, uint o, uint m, uint max, uint ob, uint ib, uint t, ref SA sa);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateNamedPipeW")] static extern IntPtr CreateNamedPipeNoSa(string n, uint o, uint m, uint max, uint ob, uint ib, uint t, IntPtr sa);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s, uint r, out IntPtr sd, out uint size);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string n, uint a, uint sh, IntPtr sa, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h, byte[] b, uint n, out uint w, IntPtr o);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr h, byte[] b, uint n, out uint r, IntPtr o);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ConnectNamedPipe(IntPtr h, IntPtr o);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CancelIoEx(IntPtr h, IntPtr o);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  static readonly IntPtr INVALID = new IntPtr(-1);
  const uint OPEN = 0x3, OVERLAPPED = 0x40000000, FIRST = 0x00080000, MODE = 0x8;
  // Try to create one more server instance of an existing pipe (no FIRST flag).
  // Returns 0 if created (the instance is closed at once), otherwise the Win32 error.
  public static int TryCreateInstance(string name, uint maxInstances) {
    IntPtr h = CreateNamedPipeNoSa("\\\\.\\pipe\\" + name, OPEN | OVERLAPPED, MODE, maxInstances, 65536, 65536, 0, IntPtr.Zero);
    if (h == INVALID) return Marshal.GetLastWin32Error();
    CloseHandle(h); return 0;
  }
  // Create a (squatting) first instance with an explicit SDDL; synchronous handle.
  public static IntPtr CreateServer(string name, string sddl, uint maxInstances, out int error) {
    IntPtr sd; uint size; error = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { error = Marshal.GetLastWin32Error(); return INVALID; }
    try {
      SA sa = new SA(); sa.nLength = Marshal.SizeOf(typeof(SA)); sa.sd = sd; sa.inherit = 0;
      IntPtr h = CreateNamedPipeSa("\\\\.\\pipe\\" + name, OPEN | FIRST, MODE, maxInstances, 65536, 65536, 0, ref sa);
      if (h == INVALID) error = Marshal.GetLastWin32Error();
      return h;
    } finally { LocalFree(sd); }
  }
  // Wait up to ms for a client on a synchronous server handle.
  public static bool WaitClient(IntPtr h, int ms) {
    bool ok = false;
    Thread t = new Thread(() => { ok = ConnectNamedPipe(h, IntPtr.Zero) || Marshal.GetLastWin32Error() == 535; });
    t.IsBackground = true; t.Start();
    if (!t.Join(ms)) { CancelIoEx(h, IntPtr.Zero); t.Join(2000); return false; }
    return ok;
  }
  // Open like Win32-OpenSSH fileio_connect (CreateFileW with SECURITY_SQOS_PRESENT |
  // SECURITY_IDENTIFICATION), send REQUEST_IDENTITIES, return the reply type
  // (-1 open failed, -2 write failed, -3 short reply, -4 reply timed out).
  // error = Win32 error of the open (0 = opened).
  public static int Probe(string name, out int error) {
    error = 0; IntPtr h = INVALID;
    for (int i = 0; i < 10; i++) {
      h = CreateFileW("\\\\.\\pipe\\" + name, 0xC0000000, 0, IntPtr.Zero, 3, 0x00110000, IntPtr.Zero);
      if (h != INVALID) { error = 0; break; }
      error = Marshal.GetLastWin32Error();
      if (error != 231) return -1;
      Thread.Sleep(300);
    }
    if (h == INVALID) return -1;
    try {
      uint n; byte[] req = new byte[] { 0, 0, 0, 1, 11 };
      if (!WriteFile(h, req, 5, out n, IntPtr.Zero)) return -2;
      byte[] hdr = new byte[5]; int got = 0;
      Thread t = new Thread(() => {
        while (got < 5) {
          byte[] tmp = new byte[5 - got]; uint r;
          if (!ReadFile(h, tmp, (uint)tmp.Length, out r, IntPtr.Zero) || r == 0) break;
          Array.Copy(tmp, 0, hdr, got, (int)r); got += (int)r;
        }
      });
      t.IsBackground = true; t.Start();
      if (!t.Join(5000)) { CancelIoEx(h, IntPtr.Zero); t.Join(2000); return -4; }
      return got >= 5 ? hdr[4] : -3;
    } finally { CloseHandle(h); }
  }
}
"@
'@

$OtherUserProbeScript = @'
$res = [ordered]@{}
$names = @(); try { $names = @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_.Substring(9) }) } catch { }
foreach ($n in @($PipeTargets.Keys)) {
  $pn = $PipeTargets[$n]
  $row = [ordered]@{ pipe_visible_in_enumeration = ($names -contains $pn) }
  $err = 0
  try { $row['reply_type'] = [G03OU]::Probe($pn, [ref]$err); $row['connect_win32_error'] = $err } catch { $row['connect_exception'] = $_.Exception.GetType().Name }
  try { $row['create_instance_win32_error'] = [G03OU]::TryCreateInstance($pn, [uint32]$MaxInstances) } catch { $row['create_instance_exception'] = $_.Exception.GetType().Name }
  $env:SSH_AUTH_SOCK = '\\.\pipe\' + $pn
  $null = & $SshAdd -l 2>&1 | Out-String
  $row['ssh_add_exit'] = $LASTEXITCODE
  $res[$n] = $row
}
if ($ProbeDefaultPipe) {
  $env:SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent'
  $out = & $SshAdd -l 2>&1 | Out-String
  $res['default_pipe'] = [ordered]@{ ssh_add_exit = $LASTEXITCODE; listed_key_count = @($out -split "`r?`n" | Where-Object { $_ -match '^\d+ SHA256:' }).Count }
}
($res | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $OutFile -Encoding UTF8
'@

# ------------------------------------------------------------------ W05 other user
function Invoke-ProbeOtherUser {
    $r = New-Result 'G03-win-pipe-acl-other-user' @('R-EN-01', 'R-RT-03', 'R-SS-03')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    if (-not $OtherUserCredential) { return (Set-Blocked $r 'a second, disposable, non-administrator local Windows account on the probe host (-OtherUserCredential) with the Secondary Logon service available') }
    # All three fixtures allow several instances and use identical pipe parameters;
    # only the DACL differs. The instance_allowed control (AU granted
    # FILE_CREATE_PIPE_INSTANCE) proves that the other user's attempt succeeds when
    # the DACL permits it, so a denial on owner_only is attributable to the DACL and
    # not to FILE_FLAG_FIRST_PIPE_INSTANCE, the instance limit, or a parameter mismatch.
    $maxInst = 4
    $owner = Start-G03InstrumentedAgent -Ctx $ctx -Name 'owneronly' -Access OwnerOnly -MaxInstances $maxInst -RunSeconds 300
    $au = Start-G03InstrumentedAgent -Ctx $ctx -Name 'authusers' -Access AuthenticatedUsers -MaxInstances $maxInst -RunSeconds 300
    $ia = Start-G03InstrumentedAgent -Ctx $ctx -Name 'installowed' -Access AuthenticatedUsersCreateInstance -MaxInstances $maxInst -RunSeconds 300
    $probeDefault = '$false'; if ($AllowProviderContact) { $probeDefault = '$true' }
    $script = $OtherUserWin32 + "`n" + '$SshAdd = ''' + $SysSshAdd + "'`n" + '$ProbeDefaultPipe = ' + $probeDefault + "`n" + '$MaxInstances = ' + $maxInst + "`n" +
        '$PipeTargets = [ordered]@{ owner_only = ''' + $owner.PipeName + '''; authenticated_users = ''' + $au.PipeName + '''; instance_allowed = ''' + $ia.PipeName + ''' }' + "`n" + $OtherUserProbeScript
    $o = Wait-OtherUser -Handle (Start-AsOtherUser -ScriptText $script -Label 'other-user')
    Start-Sleep -Milliseconds 500
    $oc = Get-G03AgentContact $owner; $ac = Get-G03AgentContact $au; $ic = Get-G03AgentContact $ia
    [void](Stop-G03InstrumentedAgent $owner); [void](Stop-G03InstrumentedAgent $au); [void](Stop-G03InstrumentedAgent $ia)
    $r.Observed['fixtures'] = [ordered]@{ owner_only = $owner.Ready; authenticated_users = $au.Ready; instance_allowed = $ia.Ready }
    $r.Observed['other_user_process'] = Get-OtherUserProcessInfo $o
    $r.Observed['other_user_results'] = $o.Data
    $r.Observed['owner_only_agent_contact'] = $oc
    $r.Observed['authenticated_users_agent_contact'] = $ac
    $r.Observed['instance_allowed_agent_contact'] = $ic
    if ($null -eq $o.Data) {
        # Environment problem (logon, Secondary Logon, script failure), not a DACL observation.
        [void]$r.Limitations.Add('Other-user process produced no result file; see exit code.')
        return (Set-Verdict $r @{ other_user_process_ran = $null })
    }
    $d = $o.Data
    $connectControl = ((Get-G03Prop (Get-G03Prop $d 'authenticated_users') 'reply_type') -eq 12)
    $instanceControl = ((Get-G03Prop (Get-G03Prop $d 'instance_allowed') 'create_instance_win32_error') -eq 0)
    $crit = @{
        authenticated_users_control_reachable = $connectControl
        instance_allowed_control_created      = $instanceControl
        owner_only_connect_denied             = ((Get-G03Prop (Get-G03Prop $d 'owner_only') 'connect_win32_error') -eq 5)
        owner_only_ssh_add_fails              = ((Get-G03Prop (Get-G03Prop $d 'owner_only') 'ssh_add_exit') -eq 2)
        owner_only_create_instance_denied     = ((Get-G03Prop (Get-G03Prop $d 'owner_only') 'create_instance_win32_error') -eq 5)
        owner_only_agent_saw_no_request       = ($oc.request_identities -eq 0)
    }
    if (-not $connectControl) { $crit['authenticated_users_control_reachable'] = $null; $crit['owner_only_connect_denied'] = $null; $crit['owner_only_ssh_add_fails'] = $null }
    if (-not $instanceControl) { $crit['instance_allowed_control_created'] = $null; $crit['owner_only_create_instance_denied'] = $null }
    $r.Observed['connect_only_dacl_create_instance_win32_error'] = (Get-G03Prop (Get-G03Prop $d 'authenticated_users') 'create_instance_win32_error')
    $r.Observed['pipe_names_visible_to_other_user'] = [ordered]@{ owner_only = (Get-G03Prop (Get-G03Prop $d 'owner_only') 'pipe_visible_in_enumeration'); authenticated_users = (Get-G03Prop (Get-G03Prop $d 'authenticated_users') 'pipe_visible_in_enumeration') }
    if ($AllowProviderContact) { $r.Observed['default_pipe_as_other_user'] = (Get-G03Prop $d 'default_pipe') }
    else { [void]$r.Limitations.Add('Gated sub-probe not run: other user against \\.\pipe\openssh-ssh-agent (needs -AllowProviderContact).') }
    [void]$r.Limitations.Add($OtherUserStagingNote)
    [void]$r.Limitations.Add('Fixture agents re-arm their single server instance with DisconnectNamedPipe after each client, so the name never has zero instances during the other user''s connect/create sequence (no recreate race).')
    [void]$r.Limitations.Add('Denial criteria require Win32 error 5 (ERROR_ACCESS_DENIED) exactly. A failed control (AU connect answered with reply type 12; instance creation on the instance_allowed fixture) makes the dependent criteria inconclusive instead of letting them pass.')
    [void]$r.Limitations.Add('connect_only_dacl_create_instance_win32_error (AU granted 0x12019b, the Win32-OpenSSH agent mask) is an observation of whether a connect-only DACL also withholds FILE_CREATE_PIPE_INSTANCE.')
    [void]$r.Limitations.Add('Pipe names may be visible to other users through enumeration even when the DACL denies access; names must not carry sensitive labels.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W06 stale/squat
$SquatScript = @'
$res = [ordered]@{}
$err = 0
$h = [G03OU]::CreateServer($SquatName, 'D:P(A;;GA;;;WD)', [uint32]$MaxInstances, [ref]$err)
if ($h -eq [IntPtr](-1)) { $res['squat_created'] = $false; $res['create_win32_error'] = $err }
else {
  $res['squat_created'] = $true
  $res['client_connected'] = [G03OU]::WaitClient($h, 60000)
  [void][G03OU]::CloseHandle($h)
}
($res | ConvertTo-Json) | Set-Content -LiteralPath $OutFile -Encoding UTF8
'@

function Get-AgentStartStatus { param($A) if ($A.Ready) { return [string]$A.Ready.status } return 'no-ready-file' }

function Invoke-ProbeStalePipe {
    $r = New-Result 'G03-win-stale-squat-pipe' @('R-EN-01', 'R-RT-03', 'R-RT-04', 'R-SS-03')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    # Every fixture here uses 4 instances and identical parameters, so a refused
    # creation can only come from FILE_FLAG_FIRST_PIPE_INSTANCE (same user, DACL
    # permits). The no-flag control shows the name would otherwise be shared.
    $maxInst = 4
    $t = Start-G03InstrumentedAgent -Ctx $ctx -Name 'stale' -MaxInstances $maxInst -RunSeconds 300
    $dup = Start-G03InstrumentedAgent -Ctx $ctx -Name 'dup' -PipeName $t.PipeName -MaxInstances $maxInst -RunSeconds 30 -ExpectStartFailure
    $dupStatus = Get-AgentStartStatus $dup
    [void](Stop-G03InstrumentedAgent $dup)
    $dupCtl = Start-G03InstrumentedAgent -Ctx $ctx -Name 'dupnoflag' -PipeName $t.PipeName -MaxInstances $maxInst -NoFirstInstanceFlag -RunSeconds 30 -ExpectStartFailure
    $dupCtlStatus = Get-AgentStartStatus $dupCtl
    [void](Stop-G03InstrumentedAgent $dupCtl)
    Start-Sleep -Milliseconds 300
    $before = (Get-G03PipeNames) -contains $t.PipeName
    $stop = Stop-G03InstrumentedAgent $t
    Start-Sleep -Milliseconds 500
    $after = (Get-G03PipeNames) -contains $t.PipeName
    $dead = Invoke-DeadSockClient -R $r -Label 'ssh-add-after-server-killed' -Exe $SysSshAdd -SockPath $t.PipePath
    $r.Observed['same_user_duplicate_server_start'] = $dupStatus
    $r.Observed['same_user_duplicate_without_first_instance_flag'] = $dupCtlStatus
    $r.Observed['pipe_listed_before_kill'] = $before
    $r.Observed['server_stop'] = $stop
    $r.Observed['pipe_listed_after_kill'] = $after
    $r.Observed['ssh_add_after_kill'] = $dead
    $crit = @{
        duplicate_server_refused = ($dupStatus -eq 'create_failed')
        pipe_disappears_with_server = ($before -and -not $after)
        client_fails_cleanly = ($dead.exit_code -eq 2)
    }
    if ($dead.fallback_judged) { $crit['client_does_not_fall_back'] = [bool]$dead.no_fallback }
    else { [void]$r.Limitations.Add('Fallback to the default pipe after the server died was not judged on this run (see ssh_add_after_kill.reason); client_fails_cleanly is exit 2 only.') }
    if ($dupCtlStatus -ne 'listening') { $crit['duplicate_server_refused'] = $null }
    if ($stop -ne 'stopped') { foreach ($k in @('pipe_disappears_with_server', 'client_fails_cleanly', 'client_does_not_fall_back')) { if ($crit.ContainsKey($k)) { $crit[$k] = $null } } }
    if ($OtherUserCredential) {
        $squatName = 'heimdall-g03-squat-' + (New-G03RandomHex 4)
        $h = Start-AsOtherUser -ScriptText ($OtherUserWin32 + "`n" + '$SquatName = ''' + $squatName + "'`n" + '$MaxInstances = ' + $maxInst + "`n" + $SquatScript) -Label 'squat'
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not ((Get-G03PipeNames) -contains $squatName) -and (Test-OtherUserRunning $h) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
        $squatSeen = (Get-G03PipeNames) -contains $squatName
        $mine = Start-G03InstrumentedAgent -Ctx $ctx -Name 'victim' -PipeName $squatName -MaxInstances $maxInst -RunSeconds 30 -ExpectStartFailure
        $mineStatus = Get-AgentStartStatus $mine
        [void](Stop-G03InstrumentedAgent $mine)
        $mineCtl = Start-G03InstrumentedAgent -Ctx $ctx -Name 'victimnoflag' -PipeName $squatName -MaxInstances $maxInst -NoFirstInstanceFlag -RunSeconds 30 -ExpectStartFailure
        $mineCtlStatus = Get-AgentStartStatus $mineCtl
        [void](Stop-G03InstrumentedAgent $mineCtl)
        $cl = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = "\\.\pipe\$squatName" } -TimeoutSec 30
        Add-Run $r 'ssh-add-against-squatted-name' $cl
        $sq = Wait-OtherUser -Handle $h -TimeoutSec 90
        $r.Observed['presquat'] = [ordered]@{ squat_name_seen_before_owner_start = $squatSeen; owner_server_start = $mineStatus
            owner_server_start_without_first_instance_flag = $mineCtlStatus; squatter = $sq.Data; squatter_process = (Get-OtherUserProcessInfo $sq); owner_client_exit_against_squatter = $cl.ExitCode }
        $r.Observed['shared_name_possible_without_first_instance_flag'] = ($mineCtlStatus -eq 'listening')
        $crit['owner_detects_presquatted_name'] = ($mineStatus -eq 'create_failed')
        if (-not $squatSeen -or $mineCtlStatus -ne 'listening') { $crit['owner_detects_presquatted_name'] = $null }
        [void]$r.Limitations.Add($OtherUserStagingNote)
        [void]$r.Limitations.Add('presquat.squatter.client_connected=true means an ordinary ssh client connects to whichever process owns the name; Win32-OpenSSH does not authenticate the pipe server (fileio_connect only limits the server to SECURITY_IDENTIFICATION).')
        [void]$r.Limitations.Add('The squatter grants Everyone full control and uses the owner''s pipe parameters, so the no-flag control is expected to join the squatted name; if it does not, the detection criterion is inconclusive.')
    } else {
        [void]$r.Limitations.Add('Cross-user pre-squat sub-probe not run: needs -OtherUserCredential.')
    }
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ auth agent (probes needing a successful login)
$script:AuthAgent = $null
$script:AuthAgentReason = $null
function Initialize-AuthAgent {
    if ($script:AuthAgent) { return $script:AuthAgent }
    if ($script:AuthAgentReason) { return $null }
    if (-not $Fixture) { $script:AuthAgentReason = $NoFixtureBlock; return $null }
    if (-not $AuthorizeKeyScript -and -not $PauseForKeyInstall) { $script:AuthAgentReason = $NoAuthBlock; return $null }
    $a = Start-G03InstrumentedAgent -Ctx $ctx -Name 'auth' -RunSeconds 7200
    $pub = Join-Path $a.Dir 'probe-key-1.pub'
    if ($AuthorizeKeyScript) { & $AuthorizeKeyScript -PublicKeyPath $pub }
    else { Write-Host 'Authorize this ephemeral probe key on the disposable fixture account, then press Enter:'; Write-Host ([IO.File]::ReadAllText($pub)); [void](Read-Host) }
    $cfg = New-FixtureConfig
    $chk = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $cfg -Remote @('true')) -Env @{ SSH_AUTH_SOCK = $a.PipePath } -TimeoutSec 45
    if ($chk.ExitCode -ne 0) { $script:AuthAgentReason = "probe key authorization check failed (ssh exit $($chk.ExitCode)); fixture did not accept the ephemeral key"; [void](Stop-G03InstrumentedAgent $a); return $null }
    $script:AuthAgent = [pscustomobject]@{ Agent = $a; Config = $cfg }
    return $script:AuthAgent
}

# ------------------------------------------------------------------ W07 process I/O
function Invoke-ProbeProcessIo {
    $r = New-Result 'G03-win-process-io' @('R-EN-01', 'R-SS-04', 'R-QU-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $auth = Initialize-AuthAgent
    if (-not $auth) { return (Set-Blocked $r $script:AuthAgentReason) }
    $envs = @{ SSH_AUTH_SOCK = $auth.Agent.PipePath }
    $e42 = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $auth.Config -Remote @('exit 42')) -Env $envs -TimeoutSec 60; Add-Run $r 'exit-42' $e42
    $sep = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $auth.Config -Remote @('printf out; printf err >&2')) -Env $envs -TimeoutSec 60; Add-Run $r 'stream-separation' $sep
    $uni = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $auth.Config -Remote @("printf '\303\274\342\230\203\n'")) -Env $envs -TimeoutSec 60; Add-Run $r 'utf8-output' $uni -Binary
    $payload = New-Object byte[] (1024 * 1024); (New-Object Random 3).NextBytes($payload)
    $want = Get-G03Sha256Hex $payload
    $cat = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $auth.Config -Remote @('cat')) -Env $envs -StdinBytes $payload -TimeoutSec 120; Add-Run $r 'binary-roundtrip-process-api' $cat -Binary
    $inFile = Join-Path $ctx.Scratch 'payload in.bin'; $outFile = Join-Path $ctx.Scratch 'payload out.bin'
    [IO.File]::WriteAllBytes($inFile, $payload)
    $sshLine = (ConvertTo-G03WinArg $SysSsh) + ' ' + (Join-G03WinArgs (Get-SshArgs -Config $auth.Config -Remote @('cat')))
    $cmdRes = Invoke-G03Native -Ctx $ctx -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -RawArguments ('/d /s /c "' + $sshLine + ' < "' + $inFile + '" > "' + $outFile + '""') -Env $envs -TimeoutSec 120
    Add-Run $r 'binary-roundtrip-cmd-redirection' $cmdRes
    $cmdHash = $null; if (Test-Path -LiteralPath $outFile) { $cmdHash = Get-G03FileSha256 $outFile }
    $psOut = Join-Path $ctx.Scratch 'payload ps out.bin'
    $quotedArgs = ((Get-SshArgs -Config $auth.Config -Remote @('cat')) | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' '
    $psScript = "`$env:SSH_AUTH_SOCK = '$($auth.Agent.PipePath)'; & cmd.exe /d /c type `"$inFile`" | & '$SysSsh' $quotedArgs > `"$psOut`""
    $psRes = Invoke-G03Native -Ctx $ctx -FilePath (Get-G03HostExe) -ArgList @('-NoProfile', '-NonInteractive', '-Command', $psScript) -Env $envs -TimeoutSec 180
    Add-Run $r 'binary-roundtrip-powershell-pipeline' $psRes
    $psHash = $null; if (Test-Path -LiteralPath $psOut) { $psHash = Get-G03FileSha256 $psOut }
    $lat = @()
    for ($i = 0; $i -lt 3; $i++) { $sw = [Diagnostics.Stopwatch]::StartNew(); [void](Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $auth.Config) -Env $envs -TimeoutSec 60); $lat += $sw.ElapsedMilliseconds }
    $uniHex = (($uni.StdoutBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    $r.Observed['exit_42'] = $e42.ExitCode
    $r.Observed['stdout_of_stream_separation'] = (Get-G03StdoutText $sep)
    $r.Observed['utf8_bytes_hex'] = $uniHex
    $r.Observed['payload_sha256'] = $want
    $r.Observed['process_api_sha256'] = (Get-G03Sha256Hex $cat.StdoutBytes)
    $r.Observed['cmd_redirection_sha256'] = $cmdHash
    $r.Observed['powershell_pipeline_sha256'] = $psHash
    $r.Observed['powershell_pipeline_byte_exact'] = ($psHash -eq $want)
    $r.Observed['ssh_true_wall_ms'] = $lat
    $r.Observed['manual_steps_not_run'] = @('Ctrl-C delivered to ssh.exe in an interactive console and the resulting exit code', 'console resize propagation to a remote PTY')
    $crit = @{
        remote_exit_status_preserved = ($e42.ExitCode -eq 42)
        stderr_not_on_stdout = ((Get-G03StdoutText $sep) -eq 'out')
        utf8_output_bytes_exact = ($uniHex -eq 'c3bce298830a')
        binary_roundtrip_process_api = ((Get-G03Sha256Hex $cat.StdoutBytes) -eq $want)
        binary_roundtrip_cmd_redirection = ($cmdHash -eq $want)
    }
    [void]$r.Limitations.Add('PowerShell pipeline byte-exactness is an observation that depends on the PowerShell version, not a pass criterion.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W08 paths and quoting
function ConvertTo-PosixQuoted { param([string]$S) return "'" + $S.Replace("'", "'\''") + "'" }

function Invoke-ProbeQuoting {
    $r = New-Result 'G03-win-path-quoting' @('R-EN-01', 'R-EN-02', 'R-SS-04', 'R-QU-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $auth = Initialize-AuthAgent
    if (-not $auth) { return (Set-Blocked $r $script:AuthAgentReason) }
    $envs = @{ SSH_AUTH_SOCK = $auth.Agent.PipePath }
    $khRows = @()
    foreach ($pc in $QuotingCases.path_cases) {
        $dir = Join-Path $ctx.Scratch (Split-Path -Parent (([string]$pc.relative) -replace '/', '\'))
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $p = Join-Path $dir 'known_hosts'
        Copy-Item -LiteralPath $Fixture.KnownHosts -Destination $p -Force
        $notations = [ordered]@{
            forward_slash_quoted      = ('"' + ($p -replace '\\', '/') + '"')
            backslash_quoted          = ('"' + $p + '"')
            backslash_doubled_quoted  = ('"' + ($p -replace '\\', '\\') + '"')
            percent_escaped_fs_quoted = ('"' + (($p -replace '\\', '/') -replace '%', '%%') + '"')
        }
        foreach ($k in $notations.Keys) {
            $cfg = New-FixtureConfig -ExtraLines ('    UserKnownHostsFile ' + $notations[$k])
            $res = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList (Get-SshArgs -Config $cfg -Without @('UserKnownHostsFile')) -Env $envs -TimeoutSec 45
            Add-Run $r "known-hosts-$($pc.id)-$k" $res
            $khRows += [ordered]@{ path_case = $pc.id; notation = $k; exit_code = $res.ExitCode; host_key_verified = ($res.ExitCode -eq 0) }
        }
    }
    $r.Observed['known_hosts_notations'] = $khRows
    $argRows = @()
    foreach ($qc in $QuotingCases.remote_argument_cases) {
        $value = [string]$qc.value
        $expected = "[$value]`n"
        $sshArgs = Get-SshArgs -Config $auth.Config -Remote @("printf '[%s]\n' " + (ConvertTo-PosixQuoted $value))
        $p1 = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList $sshArgs -Env $envs -TimeoutSec 45
        $p2 = Invoke-G03Native -Ctx $ctx -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -RawArguments ('/d /s /c "' + (ConvertTo-G03WinArg $SysSsh) + ' ' + (Join-G03WinArgs $sshArgs) + '"') -Env $envs -TimeoutSec 45
        $psScript = "`$env:SSH_AUTH_SOCK = '$($auth.Agent.PipePath)'; & '$SysSsh' " + (($sshArgs | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' ')
        $p3 = Invoke-G03Native -Ctx $ctx -FilePath (Get-G03HostExe) -ArgList @('-NoProfile', '-NonInteractive', '-Command', $psScript) -Env $envs -TimeoutSec 60
        Add-Run $r "argv-$($qc.id)-process" $p1; Add-Run $r "argv-$($qc.id)-cmd" $p2; Add-Run $r "argv-$($qc.id)-powershell" $p3
        $argRows += [ordered]@{ case = $qc.id
            process_api_exact = ((Get-G03StdoutText $p1) -eq $expected); process_exit = $p1.ExitCode
            cmd_exact = ((Get-G03StdoutText $p2) -eq $expected); cmd_exit = $p2.ExitCode
            powershell_exact = (((Get-G03StdoutText $p3) -replace "`r`n", "`n") -eq $expected); powershell_exit = $p3.ExitCode }
    }
    $r.Observed['remote_argument_fidelity'] = $argRows
    $allOk = (@($argRows | Where-Object { $_.process_exit -ne 0 }).Count -eq 0)
    $crit = @{
        spaced_unicode_config_path_works = $allOk   # every invocation used -F under a spaced/Unicode scratch directory
        forward_slash_quoted_known_hosts_works = [bool](@($khRows | Where-Object { $_.path_case -eq 'space-unicode-dir' -and $_.notation -eq 'forward_slash_quoted' -and $_.host_key_verified }).Count)
        process_api_argv_exact_all_cases = (@($argRows | Where-Object { -not $_.process_api_exact }).Count -eq 0)
    }
    [void]$r.Limitations.Add('cmd.exe and PowerShell channel results are observations of those shells; Heimdall must launch with an argv contract, not through a shell (spec sec. 10.4).')
    [void]$r.Limitations.Add('Remote argument fidelity uses POSIX single quoting for the remote shell; SSH''s single joined remote command string is protocol semantics, not a Windows property.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W09 service/elevation
function ConvertFrom-ServiceSddlRights {
    # Map trustee -> list of two-letter service access-right codes from allow ACEs.
    # Rights are split into exact two-letter codes (no substring matching across
    # code boundaries); a hex mask is kept verbatim and makes the summary null.
    param([string]$Sddl)
    $rights = [ordered]@{}
    foreach ($m in [regex]::Matches($Sddl, '\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^;)]+)\)')) {
        $trustee = $m.Groups[2].Value; $mask = $m.Groups[1].Value
        if (-not $rights.Contains($trustee)) { $rights[$trustee] = @() }
        if ($mask -match '^0x') { $rights[$trustee] += $mask }
        elseif ($mask.Length % 2 -eq 0) { for ($i = 0; $i -lt $mask.Length; $i += 2) { $rights[$trustee] += $mask.Substring($i, 2) } }
        else { $rights[$trustee] += ('unparsed:' + $mask) }
    }
    return $rights
}

function Test-AnyTrusteeRight {
    param($Rights, [string[]]$Trustees, [string[]]$Codes)
    foreach ($t in $Trustees) {
        if (-not $Rights.Contains($t)) { continue }
        foreach ($c in @($Rights[$t])) { if ($Codes -contains $c) { return $true } }
    }
    return $false
}

function Invoke-ProbeService {
    $r = New-Result 'G03-win-service-elevation' @('R-EN-01', 'R-DI-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    $svc = Get-G03AgentServiceState
    $elev = Test-G03Elevated
    $r.Observed['agent_service'] = $svc
    $r.Observed['current_token_elevated'] = $elev
    $rights = [ordered]@{}
    if ($svc -and $svc.Contains('service_sddl') -and $svc['service_sddl']) { $rights = ConvertFrom-ServiceSddlRights ([string]$svc['service_sddl']) }
    $r.Observed['service_dacl_rights_by_trustee'] = $rights
    $nonAdmin = @('AU', 'IU', 'BU', 'WD')
    # Service access-right codes: RP = start, WP = stop, DC = change config, WD = write DAC, WO = write owner.
    $canStart = $null; $canStop = $null; $canConfig = $null
    $hex = @($nonAdmin | Where-Object { $rights.Contains($_) -and @($rights[$_] | Where-Object { $_ -like '0x*' -or $_ -like 'unparsed:*' }).Count })
    if ($rights.Count -gt 0 -and $hex.Count -eq 0) {
        $canStart = Test-AnyTrusteeRight -Rights $rights -Trustees $nonAdmin -Codes @('RP')
        $canStop = Test-AnyTrusteeRight -Rights $rights -Trustees $nonAdmin -Codes @('WP')
        $canConfig = Test-AnyTrusteeRight -Rights $rights -Trustees $nonAdmin -Codes @('DC', 'WD', 'WO')
    }
    $r.Observed['non_admin_can_start_service_per_dacl'] = $canStart
    $r.Observed['non_admin_can_stop_service_per_dacl'] = $canStop
    $r.Observed['non_admin_can_reconfigure_service_per_dacl'] = $canConfig
    # Routine-operation stand-in (N2 shape): create a scoped, owner-only fixture pipe and
    # use it with the supported in-box client, all from this (non-elevated) token.
    $fx = Start-G03InstrumentedAgent -Ctx $ctx -Name 'routine' -RunSeconds 120
    $use = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = $fx.PipePath } -TimeoutSec 30
    Add-Run $r 'ssh-add-l-routine-fixture-pipe' $use
    Start-Sleep -Milliseconds 300
    $fxc = Get-G03AgentContact $fx
    [void](Stop-G03InstrumentedAgent $fx)
    $listed = (Get-G03StdoutText $use).Contains([string]$fx.Ready.keys[0].fingerprint)
    $routineOk = ($use.ExitCode -eq 0 -and $listed -and $fxc.request_identities -ge 1)
    $r.Observed['routine_fixture_pipe'] = [ordered]@{ created = ($fx.Ready.status -eq 'listening'); ssh_add_exit = $use.ExitCode; key_listed = $listed; agent_contact = $fxc }
    $r.Observed['fixture_pipes_needed_elevation'] = $(if ($elev -eq $false -and $routineOk) { 'no: a scoped owner-only pipe was created and used by System32 ssh-add from a non-elevated token in this run' }
        elseif ($elev -eq $false) { 'unknown: the routine fixture pipe could not be created or used (see routine_fixture_pipe)' } else { 'unknown: run was elevated' })
    [void]$r.Limitations.Add('Rights are read from the service DACL (sc.exe sdshow), not exercised: no service was started, stopped, or reconfigured in default mode.')
    [void]$r.Limitations.Add('The routine-operation criterion uses the instrumented fixture agent as a stand-in for the N2 per-binding pipe; it shows the platform permits the shape non-elevated, not that a Heimdall runtime does.')
    $crit = @{ run_non_elevated = ($elev -eq $false); service_state_read = ($null -ne $svc); routine_scoped_pipe_used_non_elevated = $routineOk }
    if ($elev -ne $false) { $crit['routine_scoped_pipe_used_non_elevated'] = $null }
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W10 1Password
function Invoke-ProbeOnePassword {
    $r = New-Result 'G03-win-1password-coexistence' @('R-EN-01', 'R-CR-01', 'R-SS-03')
    if (-not $OnWin) { return (Set-Blocked $r ($NotWindowsBlock + '; plus 1Password for Windows with a disposable account/vault and disposable SSH key')) }
    if (-not $AllowProviderContact) {
        return (Set-Blocked $r '1Password for Windows signed in to a DISPOSABLE account with a disposable SSH key, plus owner authorization (-AllowProviderContact -OwnerAuthorizationNote); default mode does not contact \\.\pipe\openssh-ssh-agent')
    }
    $pipes = Get-G03PipeNames
    $r.Observed['passive'] = [ordered]@{ onepassword_running = [bool](Get-Process -Name '1Password' -ErrorAction SilentlyContinue)
        default_pipe_present = ($pipes -contains 'openssh-ssh-agent'); agent_service = (Get-G03AgentServiceState) }
    if (-not ('G03PipeSrv' -as [type])) {
        Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class G03PipeSrv { [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId); }'
    }
    $srv = [ordered]@{}
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'openssh-ssh-agent', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        $c.Connect(3000)
        $spid = [uint32]0; [void][G03PipeSrv]::GetNamedPipeServerProcessId($c.SafePipeHandle.DangerousGetHandle(), [ref]$spid)
        $srv['server_pid'] = $spid
        try { $srv['server_image'] = (Get-Process -Id $spid -ErrorAction Stop).ProcessName } catch { $srv['server_image'] = 'not visible (other session or SYSTEM service)' }
        try {
            $acl = $null
            if ($c | Get-Member -Name GetAccessControl) { $acl = $c.GetAccessControl() } else { $acl = [System.IO.Pipes.PipesAclExtensions]::GetAccessControl($c) }
            $srv['pipe_sddl'] = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]'Access, Owner')
        } catch { $srv['pipe_sddl_error'] = $_.Exception.GetType().Name }
    } catch { $srv['connect_error'] = $_.Exception.GetType().Name } finally { $c.Dispose() }
    $r.Observed['default_pipe_server'] = $srv
    $l = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-l') -Env @{ SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent' } -TimeoutSec 120
    Add-Run $r 'ssh-add-l-default-pipe' $l
    $r.Observed['ssh_add_default_pipe'] = [ordered]@{ exit_code = $l.ExitCode; key_count = @((Get-G03StdoutText $l) -split "`r?`n" | Where-Object { $_ -match '^\d+ SHA256:' }).Count }
    $r.Observed['manual_observation_required'] = 'Operator records whether a 1Password approval prompt appeared and which application it named; repeat with the WSL relay probe (G03-wsl-b-relay-attribution).'
    $crit = @{ default_pipe_server_identified = $srv.Contains('server_image') }
    if ($AllowSystemAgentMutation) {
        $svcBefore = Get-G03AgentServiceState
        $start = Invoke-G03Native -Ctx $ctx -FilePath (Join-Path $env:WINDIR 'System32\sc.exe') -ArgList @('start', 'ssh-agent') -TimeoutSec 30
        Add-Run $r 'sc-start-ssh-agent-while-1password-holds-pipe' $start
        Start-Sleep -Seconds 2
        $svcAfter = Get-G03AgentServiceState
        $owners = @()
        for ($i = 0; $i -lt 6; $i++) {
            $c2 = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'openssh-ssh-agent', [System.IO.Pipes.PipeDirection]::InOut)
            try { $c2.Connect(2000); $sp = [uint32]0; [void][G03PipeSrv]::GetNamedPipeServerProcessId($c2.SafePipeHandle.DangerousGetHandle(), [ref]$sp); try { $owners += (Get-Process -Id $sp).ProcessName } catch { $owners += "pid:$sp" } }
            catch { $owners += $_.Exception.GetType().Name } finally { $c2.Dispose() }
        }
        $stop = Invoke-G03Native -Ctx $ctx -FilePath (Join-Path $env:WINDIR 'System32\sc.exe') -ArgList @('stop', 'ssh-agent') -TimeoutSec 30
        Add-Run $r 'sc-stop-ssh-agent-restore' $stop
        $r.Observed['coexistence_mutation'] = [ordered]@{ service_before = $svcBefore['status']; sc_start_exit = $start.ExitCode; service_after = $svcAfter['status']; default_pipe_servers_sampled = $owners; sc_stop_exit = $stop.ExitCode }
        $crit['single_server_for_default_pipe'] = (@($owners | Select-Object -Unique).Count -le 1)
    } else { [void]$r.Limitations.Add('Coexistence sub-probe (start the OpenSSH agent service while 1Password holds the pipe) not run: needs -AllowSystemAgentMutation on a disposable host.') }
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ W11 Windows agent constraints
function Invoke-ProbeAgentConstraints {
    $r = New-Result 'G03-win-agent-constraints' @('R-EN-01', 'R-CR-08', 'R-SS-03')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    if (-not $AllowSystemAgentMutation) { return (Set-Blocked $r 'disposable Windows host with the OpenSSH Authentication Agent service running and owner authorization (-AllowSystemAgentMutation -IAmOnADisposableHost -OwnerAuthorizationNote); the probe adds and removes a disposable key in the per-user agent registry store') }
    $svc = Get-G03AgentServiceState
    if (-not $svc['present'] -or $svc['status'] -ne 'Running') { return (Set-Blocked $r 'OpenSSH Authentication Agent service running on the disposable probe host') }
    $kdir = Join-Path $ctx.Scratch 'disposable key'; New-Item -ItemType Directory -Force -Path $kdir | Out-Null
    $key = Join-Path $kdir 'id_g03'
    $kg = Invoke-G03Native -Ctx $ctx -FilePath $SysKeygen -ArgList @('-q', '-t', 'ed25519', '-N', '', '-C', 'heimdall-g03-disposable', '-f', $key) -TimeoutSec 30
    Add-Run $r 'keygen' $kg
    $pipeEnv = @{ SSH_AUTH_SOCK = '\\.\pipe\openssh-ssh-agent' }
    $before = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-l') -Env $pipeEnv -TimeoutSec 30
    $cases = [ordered]@{ lifetime = @('-t', '60', $key); confirm = @('-c', $key); destination = @('-h', 'probe-host.invalid', $key); unconstrained = @($key) }
    $rows = [ordered]@{}
    foreach ($k in $cases.Keys) {
        $res = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList $cases[$k] -Env $pipeEnv -TimeoutSec 30
        Add-Run $r "ssh-add-$k" $res
        $rows[$k] = [ordered]@{ exit_code = $res.ExitCode; stderr = $res.StderrText.Trim() }
        if ($k -ne 'unconstrained' -and $res.ExitCode -eq 0) { [void](Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-d', "$key.pub") -Env $pipeEnv -TimeoutSec 30) }
    }
    $del = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-d', "$key.pub") -Env $pipeEnv -TimeoutSec 30
    Add-Run $r 'ssh-add-d-cleanup' $del
    $after = Invoke-G03Native -Ctx $ctx -FilePath $SysSshAdd -ArgList @('-l') -Env $pipeEnv -TimeoutSec 30
    Remove-Item -LiteralPath $kdir -Recurse -Force
    $same = ((Get-G03StdoutText $before) -eq (Get-G03StdoutText $after))
    $r.Observed['constraint_results'] = $rows
    $r.Observed['cleanup_delete_exit'] = $del.ExitCode
    $r.Observed['agent_list_unchanged_after_cleanup'] = $same
    [void]$r.Limitations.Add('Constraint rows are observations: the pinned v10.0.0.0 source rejects every add-time constraint except sk-provider (keyagent-request.c parse_key_constraints), while the project wiki says -t/-c are ignored; this probe records the shipped behavior.')
    return (Set-Verdict $r @{ unconstrained_add_works = ($rows['unconstrained'].exit_code -eq 0); no_residue = $same })
}

# ------------------------------------------------------------------ P-B11 WSL distribution vs another Windows user
$WslOtherUserScript = @'
$res = [ordered]@{}
$env:WSL_UTF8 = '1'
# Positive control: can this user run wsl.exe at all in this (hidden, -Credential) context?
try { $null = (& wsl.exe --version 2>&1 | Out-String); $res['version_exit'] = $LASTEXITCODE } catch { $res['version_error'] = $_.Exception.GetType().Name }
try { $l = (& wsl.exe -l -q 2>&1 | Out-String) -replace "`0", ''; $res['list_exit'] = $LASTEXITCODE
      $res['distro_listed'] = [bool](@($l -split "`r?`n" | ForEach-Object { $_.Trim() }) -contains $Distro) } catch { $res['list_error'] = $_.Exception.GetType().Name }
try { $o = (& wsl.exe -d $Distro -- id -u 2>&1 | Out-String) -replace "`0", ''; $res['launch_exit'] = $LASTEXITCODE
      $res['launch_error_is_distro_not_found'] = [bool]($o -match 'WSL_E_DISTRO_NOT_FOUND|no distribution with the supplied name')
      $res['launch_output_first_line'] = (($o -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 1) } catch { $res['launch_error'] = $_.Exception.GetType().Name }
try { $res['unc_visible'] = Test-Path -LiteralPath ('\\wsl.localhost\' + $Distro + '\') } catch { $res['unc_error'] = $_.Exception.GetType().Name }
($res | ConvertTo-Json) | Set-Content -LiteralPath $OutFile -Encoding UTF8
'@

function Invoke-ProbeWslOtherUser {
    $r = New-Result 'G03-wsl-b-other-windows-user' @('R-EN-03', 'R-SE-03', 'R-QU-02')
    if (-not $OnWin) { return (Set-Blocked $r ($NotWindowsBlock + '; plus WSL2 with a disposable distribution (-WslDistro)')) }
    if (-not $WslDistro) { return (Set-Blocked $r 'a disposable WSL2 distribution registered to the probe user (-WslDistro)') }
    if (-not $OtherUserCredential) { return (Set-Blocked $r 'a second, disposable, non-administrator local Windows account (-OtherUserCredential)') }
    $ownerUnc = Test-Path -LiteralPath ('\\wsl.localhost\' + $WslDistro + '\')
    $script = '$Distro = ''' + $WslDistro.Replace("'", "''") + "'`n" + $WslOtherUserScript
    $o = Wait-OtherUser -Handle (Start-AsOtherUser -ScriptText $script -Label 'wsl-other-user') -TimeoutSec 120
    $r.Observed['owner_unc_visible'] = $ownerUnc
    $r.Observed['other_user'] = [ordered]@{ process = (Get-OtherUserProcessInfo $o); results = $o.Data }
    if ($null -eq $o.Data) { return (Set-Verdict $r @{ other_user_process_ran = $null }) }
    $d = $o.Data
    $control = ((Get-G03Prop $d 'version_exit') -eq 0)
    $launchExit = Get-G03Prop $d 'launch_exit'
    $notFound = [bool](Get-G03Prop $d 'launch_error_is_distro_not_found')
    $launchCrit = $null
    if ($launchExit -eq 0) { $launchCrit = $false } elseif ($null -ne $launchExit -and $notFound) { $launchCrit = $true }
    $crit = @{
        owner_baseline_unc_visible          = [bool]$ownerUnc
        other_user_wsl_exe_runs_control     = $control
        other_user_does_not_see_distro      = ($null -ne (Get-G03Prop $d 'list_exit') -and -not [bool](Get-G03Prop $d 'distro_listed'))
        other_user_cannot_launch_distro     = $launchCrit
        other_user_cannot_browse_distro_unc = (-not [bool](Get-G03Prop $d 'unc_visible'))
    }
    if (-not $control) { $crit['other_user_wsl_exe_runs_control'] = $null; $crit['other_user_does_not_see_distro'] = $null; $crit['other_user_cannot_launch_distro'] = $null }
    if (-not $ownerUnc) { $crit['owner_baseline_unc_visible'] = $null; $crit['other_user_cannot_browse_distro_unc'] = $null }
    [void]$r.Limitations.Add($OtherUserStagingNote)
    [void]$r.Limitations.Add('Covers the cross-Windows-user boundary only; WSL distributions are documented as not being a security boundary from the same Windows user or from that user''s other distributions.')
    [void]$r.Limitations.Add('The owner-side \\wsl.localhost check can start the target distribution.')
    [void]$r.Limitations.Add('other_user_cannot_launch_distro is true only when wsl.exe fails with a recognized distribution-not-found message (pattern WSL_E_DISTRO_NOT_FOUND / "no distribution with the supplied name"; the pattern is not from a pinned source [U]); any other failure is inconclusive. A failed wsl.exe --version control makes the list/launch criteria inconclusive.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ P-W12 key-file permissions (spec sec. 8.4, S13)
function Get-BadPermText { param($Res) return [bool]($Res.StderrText -match 'UNPROTECTED PRIVATE KEY FILE|Bad permissions|are too open') }

function Set-KeyAce {
    param([string]$Path, [string]$Sid, [switch]$Remove)
    $acl = Get-Acl -LiteralPath $Path
    $id = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow)
    if ($Remove) { [void]$acl.RemoveAccessRuleAll($rule) } else { $acl.AddAccessRule($rule) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-ProbeKeyPerms {
    $r = New-Result 'G03-win-key-file-permissions' @('R-EN-01', 'R-SS-03', 'R-DI-02')
    if (-not $OnWin) { return (Set-Blocked $r $NotWindowsBlock) }
    # Disposable file key in scratch (never loaded into any agent, deleted at the end).
    # Win32-OpenSSH checks private-key file ACLs on load: sshkey_perm_ok ->
    # check_secure_file_permission(path, NULL, read_ok=0), which accepts only the
    # current user, Administrators, SYSTEM and TrustedInstaller as owner/ACE
    # trustees (authfile.c, w32-sshfileperm.c at G03-S02) [S].
    $kdir = Join-Path $ctx.Scratch 'key perms'
    New-Item -ItemType Directory -Force -Path $kdir | Out-Null
    $key = Join-Path $kdir 'id_g03_perm'
    $kg = Invoke-G03Native -Ctx $ctx -FilePath $SysKeygen -ArgList @('-q', '-t', 'ed25519', '-N', '', '-C', 'heimdall-g03-perm', '-f', $key) -TimeoutSec 30
    Add-Run $r 'keygen' $kg
    if ($kg.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $key)) {
        Remove-Item -LiteralPath $kdir -Recurse -Force -ErrorAction SilentlyContinue
        return (Set-Verdict $r @{ disposable_key_generated = $null })
    }
    $rows = [ordered]@{}
    $step = {
        param([string]$Label)
        $res = Invoke-G03Native -Ctx $ctx -FilePath $SysKeygen -ArgList @('-y', '-f', $key) -TimeoutSec 30
        Add-Run $r "ssh-keygen-y-$Label" $res -Binary
        $rows[$Label] = [ordered]@{ exit_code = $res.ExitCode; bad_permissions_reported = (Get-BadPermText $res); file_sddl = (Get-Acl -LiteralPath $key).Sddl }
    }
    & $step 'as_generated'
    Set-KeyAce -Path $key -Sid 'S-1-5-11'                 # Authenticated Users: read
    & $step 'authenticated_users_read'
    Set-KeyAce -Path $key -Sid 'S-1-5-11' -Remove
    & $step 'restored'
    Set-KeyAce -Path $key -Sid 'S-1-5-32-544'             # Administrators: read (permitted by the rule [S])
    & $step 'administrators_read'
    Set-KeyAce -Path $key -Sid 'S-1-5-32-544' -Remove
    if ($Fixture) {
        # Client load path (observation): ssh.exe loads the file identity only during
        # public-key authentication; the fixture need not accept the key.
        $cfg = New-FixtureConfig
        Set-KeyAce -Path $key -Sid 'S-1-5-11'
        $sshArgs = Get-SshArgs -Config $cfg -Extra @('-o', ('IdentityFile=' + (ConvertTo-G03SshConfigToken ($key -replace '\\', '/'))), '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none') -Without @('IdentityFile', 'IdentitiesOnly')
        $sres = Invoke-G03Native -Ctx $ctx -FilePath $SysSsh -ArgList $sshArgs -TimeoutSec 45
        Add-Run $r 'ssh-identityfile-open-acl' $sres
        Set-KeyAce -Path $key -Sid 'S-1-5-11' -Remove
        $r.Observed['ssh_client_open_acl'] = [ordered]@{ exit_code = $sres.ExitCode; bad_permissions_reported = (Get-BadPermText $sres) }
    } else { [void]$r.Limitations.Add('ssh.exe identity-load sub-case not run: needs the disposable fixture server (-SshHost/-SshUser/-KnownHostsFile).') }
    Remove-Item -LiteralPath $kdir -Recurse -Force -ErrorAction SilentlyContinue
    $r.Observed['steps'] = $rows
    $r.Observed['disposable_key_deleted'] = -not (Test-Path -LiteralPath $key)
    $r.Observed['current_token_elevated'] = (Test-G03Elevated)
    $control = ($rows['as_generated'].exit_code -eq 0 -and -not $rows['as_generated'].bad_permissions_reported)
    $crit = @{
        generated_key_accepted_control      = $control
        other_principal_read_ace_rejected   = ($rows['authenticated_users_read'].exit_code -ne 0 -and $rows['authenticated_users_read'].bad_permissions_reported)
        restored_owner_only_acl_accepted    = ($rows['restored'].exit_code -eq 0 -and -not $rows['restored'].bad_permissions_reported)
    }
    if (-not $control) { foreach ($k in @($crit.Keys)) { $crit[$k] = $null } }
    $r.Observed['administrators_read_ace_accepted'] = ($rows['administrators_read'].exit_code -eq 0)
    [void]$r.Limitations.Add('Administrators and SYSTEM access is accepted by the client rule by design [S]; file ACLs are not a boundary against administrators, and an elevated token is not a key-use approval (spec sec. 8.4).')
    [void]$r.Limitations.Add('ssh-keygen -y exercises the same sshkey_load_private path as ssh/ssh-add on the pinned source [S]; shipped builds may differ, so the result applies to the ssh-keygen.exe in provider_versions.')
    return (Set-Verdict $r $crit)
}

# ------------------------------------------------------------------ serve mode for WSL
if ($ServeAgentForWsl) {
    if (-not $OnWin) { throw '-ServeAgentForWsl requires Windows.' }
    $name = 'heimdall-g03-wsl-' + (New-G03RandomHex 4)
    $a = Start-G03InstrumentedAgent -Ctx $ctx -Name 'wsl' -PipeName $name -KeyCount 2 -AllowedKeyIndexes 1 -RunSeconds $ServeSeconds
    # Decoy: WSL Mode A runs pass it as the Windows-side SSH_AUTH_SOCK (via WSLENV), so a
    # client that ignores IdentityAgent and falls back to the environment is detected
    # instead of reaching \\.\pipe\openssh-ssh-agent.
    $dname = 'heimdall-g03-wsldecoy-' + (New-G03RandomHex 4)
    $dc = Start-G03InstrumentedAgent -Ctx $ctx -Name 'wsldecoy' -PipeName $dname -RunSeconds $ServeSeconds
    $manifest = [ordered]@{ pipe_name = $name; pipe_path = $a.PipePath; log_path = $a.LogPath; public_key_dir = $a.Dir
        decoy_pipe_name = $dname; decoy_log_path = $dc.LogPath
        relay_script = (Join-Path $PSScriptRoot 'PipeStdioRelay.ps1'); keys = $a.Ready.keys; serve_seconds = $ServeSeconds; started_at = (Get-G03UtcNow) }
    $mf = Join-Path $ctx.OutDir 'wsl-agent-manifest.json'
    Write-G03Utf8File -Path $mf -Text (($manifest | ConvertTo-Json -Depth 6) + "`n")
    Write-Host "Instrumented agent for WSL probes is serving \\.\pipe\$name for $ServeSeconds s (key 1 allowed, key 2 filtered); decoy \\.\pipe\$dname."
    Write-Host "Manifest (Windows path): $mf"
    Write-Host 'In WSL: tests/native/wsl/run_g03_wsl_probes.sh --win-manifest "$(wslpath -u ''<manifest path>'')" ...'
    [void]$a.Process.WaitForExit($ServeSeconds * 1000 + 5000)
    [void](Stop-G03AllOwned -Ctx $ctx)
    Remove-G03Scratch -Ctx $ctx
    exit 0
}

# ------------------------------------------------------------------ main
$all = [ordered]@{ env = 'Invoke-ProbeEnv'; sshauthsock = 'Invoke-ProbeSshAuthSock'; identityagent = 'Invoke-ProbeIdentityAgent'; git = 'Invoke-ProbeGit'
    otheruser = 'Invoke-ProbeOtherUser'; stalepipe = 'Invoke-ProbeStalePipe'; processio = 'Invoke-ProbeProcessIo'; quoting = 'Invoke-ProbeQuoting'
    service = 'Invoke-ProbeService'; onepassword = 'Invoke-ProbeOnePassword'; agentconstraints = 'Invoke-ProbeAgentConstraints'
    wslotheruser = 'Invoke-ProbeWslOtherUser'; keyperms = 'Invoke-ProbeKeyPerms' }
$selected = @($all.Keys)
if (-not ($Probes -contains 'all')) { $selected = @($Probes | ForEach-Object { ([string]$_).ToLower() } | Where-Object { $all.Contains($_) }) }
$written = @()
foreach ($p in $selected) {
    $res = $null
    try { $res = & $all[$p] }
    catch {
        $res = New-Result "G03-win-$p-harness-error" @()
        $res.Observed = [ordered]@{ verdict = 'inconclusive'; harness_error = $_.Exception.Message; at = [string]$_.InvocationInfo.PositionMessage }
        [void]$res.Limitations.Add('Harness error: the probe did not complete; this is not a platform observation and names no requirement.')
    }
    $written += Write-G03Record -Ctx $ctx -CaseId $res.CaseId -Status $res.Status -RequirementIds $res.Reqs -Environment $BaseEnv `
        -ProviderVersions $ProviderVersions -Commands @($res.Commands) -Observed $res.Observed -EvidencePaths @($res.Evidence) `
        -Limitations @($res.Limitations) -BlockedOn $res.BlockedOn
    Write-Host ('{0,-42} {1}' -f $res.CaseId, $res.Status)
}
$stops = Stop-G03AllOwned -Ctx $ctx
Remove-G03Scratch -Ctx $ctx
$leaks = Test-G03CanaryLeak -Ctx $ctx
$summary = [ordered]@{ run_id = $ctx.RunId; finished_at = (Get-G03UtcNow); records = @($written | ForEach-Object { Split-Path -Leaf $_ }); owned_process_cleanup = $stops; canary_leaks = $leaks }
Write-G03Utf8File -Path (Join-Path $ctx.OutDir 'summary.json') -Text (($summary | ConvertTo-Json -Depth 6) + "`n")
if ($OnWin) {
    $shared = Join-Path $env:PUBLIC ('heimdall-g03-' + $ctx.RunId)
    if (Test-Path -LiteralPath $shared) { Remove-Item -LiteralPath $shared -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($leaks.Count -gt 0) { Write-Error ("CANARY LEAK detected in: " + ($leaks -join ', ')); exit 9 }
Write-Host "Records: $($ctx.RecordsDir)"
exit 0
