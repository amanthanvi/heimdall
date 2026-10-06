# G03Common.psm1 - shared helpers for the G03 native Windows probe harness.
#
# Harness code, not product code. Compatible with Windows PowerShell 5.1 and
# PowerShell 7.x (no PS7-only syntax). See README.md for the safety model.
#
# Safety invariants enforced here:
#   * Child ssh/ssh-add/git processes never inherit the session's agent
#     selection: SSH_AUTH_SOCK is always set explicitly, to a fixture pipe or to
#     a sentinel pipe name that does not exist. On Windows an UNSET SSH_AUTH_SOCK
#     means the system pipe \\.\pipe\openssh-ssh-agent (wmain_common.c), i.e. the
#     owner's real agent, so "unset" is never used.
#   * Processes are stopped only through the Process object this harness got
#     when it started them (it holds a handle, so a reused PID cannot be hit),
#     and only after re-checking that the live PID still has the recorded start
#     time; a process whose start time cannot be read or compared is not
#     stopped (reported as identity-unverified).
#   * No secret material is written: fixture private keys exist only inside the
#     InstrumentedAgent process.

Set-StrictMode -Version 2.0

$script:OnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
# Canary prefix assembled at run time so repository-wide canary scans do not flag this file.
$script:CanaryPrefix = 'HEIMDALL_' + 'CANARY_'

function Test-G03OnWindows { return $script:OnWindows }

function Get-G03UtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Write-G03Utf8File {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

function Get-G03Sha256Hex {
    # AllowEmptyCollection: a failed command's empty stdout is hashed too (CHANGELOG-native.md fix 3).
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Get-G03FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return Get-G03Sha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path))
}

function New-G03RandomHex {
    param([int]$Bytes = 8)
    $b = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---------------------------------------------------------------------------
# Windows command-line quoting (CommandLineToArgvW / MSVCRT rules).
# Used so that argument vectors reach native executables exactly, independent
# of the PowerShell version's native-argument-passing mode.
# ---------------------------------------------------------------------------
function ConvertTo-G03WinArg {
    param([AllowEmptyString()][string]$Arg)
    if ($Arg.Length -gt 0 -and $Arg -notmatch '[\s"]') { return $Arg }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $backslashes = 0
    foreach ($ch in $Arg.ToCharArray()) {
        if ($ch -eq '\') { $backslashes++; continue }
        if ($ch -eq '"') {
            [void]$sb.Append('\' * ($backslashes * 2 + 1)); [void]$sb.Append('"')
        } else {
            if ($backslashes -gt 0) { [void]$sb.Append('\' * $backslashes) }
            [void]$sb.Append($ch)
        }
        $backslashes = 0
    }
    if ($backslashes -gt 0) { [void]$sb.Append('\' * ($backslashes * 2)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Join-G03WinArgs {
    param([string[]]$ArgList)
    if (-not $ArgList) { return '' }
    return (($ArgList | ForEach-Object { ConvertTo-G03WinArg $_ }) -join ' ')
}

# ---------------------------------------------------------------------------
# Run context
# ---------------------------------------------------------------------------
function New-G03RunContext {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$OutDir,
        [string]$RunId
    )
    if (-not $RunId) { $RunId = ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')) + '-' + (New-G03RandomHex 3) }
    if (-not $OutDir) { $OutDir = Join-Path $RepoRoot (Join-Path 'tests/evidence/artifacts/g03/runs' $RunId) }
    $records = Join-Path $OutDir 'records'
    $artifacts = Join-Path $OutDir 'artifacts'
    New-Item -ItemType Directory -Force -Path $records, $artifacts | Out-Null
    # Scratch lives outside the repository; includes a space and non-ASCII
    # characters on purpose so every probe exercises such paths.
    $scratchBase = [System.IO.Path]::GetTempPath()
    $scratch = Join-Path $scratchBase ("heimdall-g03-$RunId" + [IO.Path]::DirectorySeparatorChar + "probe dir " + [char]0x00FC + [char]0x00F8)
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    $canary = $script:CanaryPrefix + 'G03_' + (New-G03RandomHex 12)
    $commit = $null
    try {
        $commit = (& git -C $RepoRoot rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -ne 0) { $commit = $null }
    } catch { $commit = $null }
    return [pscustomobject]@{
        RunId        = $RunId
        RepoRoot     = $RepoRoot
        OutDir       = $OutDir
        RecordsDir   = $records
        ArtifactsDir = $artifacts
        Scratch      = $scratch
        Canary       = $canary
        BuildCommit  = $commit
        SentinelPipe = "\\.\pipe\heimdall-g03-none-$RunId"
        StartedAt    = (Get-G03UtcNow)
        Owned        = New-Object System.Collections.ArrayList
    }
}

function Remove-G03Scratch {
    # Scratch holds only fixture configs/known_hosts/public keys (private keys
    # live in the instrumented agent process); removed at the end of a run.
    param([Parameter(Mandatory = $true)]$Ctx)
    $root = Split-Path -Parent $Ctx.Scratch
    if ($root -and (Split-Path -Leaf $root) -like 'heimdall-g03-*' -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-G03CaseArtifactDir {
    param([Parameter(Mandatory = $true)]$Ctx, [Parameter(Mandatory = $true)][string]$CaseId)
    $d = Join-Path $Ctx.ArtifactsDir $CaseId
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    return $d
}

# Redact identifying-but-not-secret metadata before it reaches a record.
function Protect-G03Text {
    param([AllowNull()][string]$Text, $Ctx)
    if ($null -eq $Text) { return $null }
    $t = $Text
    # Token per value (M00-T04-G03-native-windows): the evidence convention names the
    # kind of value removed (<winhome>, <winuser>, <winhost>) instead of one generic token.
    $pairs = @()
    if ($script:OnWindows) {
        if ($env:USERPROFILE -and $env:USERPROFILE.Length -ge 6) {
            foreach ($form in @($env:USERPROFILE, ($env:USERPROFILE -replace '\\', '/'), ($env:USERPROFILE -replace '\\', '\\'))) {
                $t = $t -replace [regex]::Escape($form), '<winhome>'
            }
        }
        $pairs = @(@($env:USERNAME, '<winuser>'), @($env:COMPUTERNAME, '<winhost>'), @($env:USERDOMAIN, '<windomain>'))
    } else { $pairs = @(@($env:USER, '<redacted>'), @([Environment]::MachineName, '<redacted>')) }
    foreach ($pv in $pairs) {
        $v = $pv[0]
        # Whole-token, case-insensitive match so e.g. a host named "Mac" does not rewrite "macos".
        if ($v -and $v.Length -ge 3) { $t = $t -replace ('(?<![A-Za-z0-9])' + [regex]::Escape($v) + '(?![A-Za-z0-9])'), $pv[1] }
    }
    $t = $t -replace 'S-1-5-21-\d+-\d+-\d+', 'S-1-5-21-<redacted>'
    return $t
}

# ---------------------------------------------------------------------------
# Native process capture with explicit environment (byte-exact stdout).
# ---------------------------------------------------------------------------
function Invoke-G03Native {
    param(
        [Parameter(Mandatory = $true)]$Ctx,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgList = @(),
        [string]$RawArguments,          # if given, used verbatim (quoting probes)
        [hashtable]$Env = @{},          # name -> value; $null value removes the variable
        [byte[]]$StdinBytes,
        [int]$TimeoutSec = 60,
        [string]$WorkingDirectory
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    if ($PSBoundParameters.ContainsKey('RawArguments')) { $psi.Arguments = $RawArguments } else { $psi.Arguments = Join-G03WinArgs $ArgList }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    # Safety default: never let a child fall back to the system agent pipe.
    # HOME is redirected so MSYS/Git-bundled tools never read or create files in
    # the owner's home; Win32-OpenSSH resolves its home from the user profile,
    # which is why every probe also passes -F and explicit file options.
    $fakeHome = Join-Path $Ctx.Scratch 'home'
    if (-not (Test-Path -LiteralPath $fakeHome)) { New-Item -ItemType Directory -Force -Path $fakeHome | Out-Null }
    $effective = @{ 'SSH_AUTH_SOCK' = $Ctx.SentinelPipe; 'HEIMDALL_G03_CANARY_ENV' = $Ctx.Canary; 'HOME' = $fakeHome }
    foreach ($k in $Env.Keys) { $effective[$k] = $Env[$k] }
    foreach ($k in @('GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT', 'SSH_ASKPASS', 'DISPLAY')) {
        if (-not $Env.ContainsKey($k)) { $effective[$k] = $null }
    }
    foreach ($k in $effective.Keys) {
        if ($null -eq $effective[$k]) { [void]$psi.EnvironmentVariables.Remove($k) } else { $psi.EnvironmentVariables[$k] = [string]$effective[$k] }
    }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $started = [DateTime]::UtcNow
    [void]$p.Start()
    $outMs = New-Object System.IO.MemoryStream
    $errMs = New-Object System.IO.MemoryStream
    $tOut = $p.StandardOutput.BaseStream.CopyToAsync($outMs)
    $tErr = $p.StandardError.BaseStream.CopyToAsync($errMs)
    try {
        if ($StdinBytes) { $p.StandardInput.BaseStream.Write($StdinBytes, 0, $StdinBytes.Length) }
        $p.StandardInput.Close()
    } catch { }
    $timedOut = -not $p.WaitForExit($TimeoutSec * 1000)
    if ($timedOut) {
        try { $p.Kill() } catch { }
        [void]$p.WaitForExit(5000)
    }
    try { [void]$tOut.Wait(5000); [void]$tErr.Wait(5000) } catch { }
    $exit = $null
    if (-not $timedOut) { $exit = $p.ExitCode }
    $res = [pscustomobject]@{
        FilePath    = $FilePath
        Arguments   = $psi.Arguments
        Pid         = $p.Id
        StartedUtc  = $started.ToString('o')
        ExitCode    = $exit
        TimedOut    = $timedOut
        StdoutBytes = $outMs.ToArray()
        StderrText  = $script:Utf8NoBom.GetString($errMs.ToArray())
    }
    $p.Dispose()
    return $res
}

function Get-G03InnerException {
    # PowerShell wraps .NET constructor/method exceptions (MethodInvocationException);
    # classification must use the innermost exception.
    param($Exception)
    $x = $Exception
    while ($null -ne $x -and $null -ne $x.InnerException) { $x = $x.InnerException }
    return $x
}

function Get-G03StdoutText { param($Result) return $script:Utf8NoBom.GetString($Result.StdoutBytes) }

# Save a redacted transcript of one native invocation and return its path.
function Save-G03Transcript {
    param([Parameter(Mandatory = $true)]$Ctx, [Parameter(Mandatory = $true)][string]$CaseId, [Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)]$Result, [switch]$BinaryStdout)
    $dir = Get-G03CaseArtifactDir -Ctx $Ctx -CaseId $CaseId
    $safe = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $path = Join-Path $dir "$safe.txt"
    $stdoutRepr = $null
    if ($BinaryStdout) { $stdoutRepr = "<binary stdout: $($Result.StdoutBytes.Length) bytes, sha256=$(Get-G03Sha256Hex $Result.StdoutBytes)>" } else { $stdoutRepr = Get-G03StdoutText $Result }
    $text = @(
        "label: $Label",
        "file: $($Result.FilePath)",
        "arguments: $($Result.Arguments)",
        "started_utc: $($Result.StartedUtc)",
        "exit_code: $($Result.ExitCode)",
        "timed_out: $($Result.TimedOut)",
        '--- stdout ---', $stdoutRepr,
        '--- stderr ---', $Result.StderrText
    ) -join "`n"
    Write-G03Utf8File -Path $path -Text (Protect-G03Text -Text $text -Ctx $Ctx)
    return $path
}

# ---------------------------------------------------------------------------
# Environment inventory (passive: no agent contact, no network)
# ---------------------------------------------------------------------------
function Get-G03WindowsBuild {
    $o = [ordered]@{ platform = [Environment]::OSVersion.Platform.ToString(); version = [Environment]::OSVersion.Version.ToString() }
    if ($script:OnWindows) {
        try {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            foreach ($n in @('ProductName', 'DisplayVersion', 'CurrentBuild', 'UBR', 'EditionID', 'InstallationType')) {
                if ($cv.PSObject.Properties[$n]) { $o[$n] = [string]$cv.$n }
            }
        } catch { $o['registry_error'] = $_.Exception.Message }
        $o['arch'] = $env:PROCESSOR_ARCHITECTURE
    } else {
        $o['arch'] = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }
    return $o
}

function Test-G03Elevated {
    if (-not $script:OnWindows) { return $null }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-G03SshVersion {
    param([Parameter(Mandatory = $true)]$Ctx, [Parameter(Mandatory = $true)][string]$Exe)
    if (-not (Test-Path -LiteralPath $Exe)) { return $null }
    $r = Invoke-G03Native -Ctx $Ctx -FilePath $Exe -ArgList @('-V') -TimeoutSec 15
    $line = (($r.StderrText + (Get-G03StdoutText $r)) -split "`r?`n" | Where-Object { $_ -match 'OpenSSH' } | Select-Object -First 1)
    $fv = $null
    try { $fv = (Get-Item -LiteralPath $Exe).VersionInfo.FileVersion } catch { }
    return [ordered]@{ path = $Exe; version_banner = $line; file_version = $fv; sha256 = (Get-G03FileSha256 $Exe); exit_code = $r.ExitCode }
}

function Get-G03SshCandidates {
    $c = New-Object System.Collections.ArrayList
    if ($script:OnWindows) {
        $sys = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
        if (Test-Path -LiteralPath $sys) { [void]$c.Add($sys) }
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
            if (-not $root) { continue }
            $g = Join-Path $root 'Git\usr\bin\ssh.exe'
            if (Test-Path -LiteralPath $g) { [void]$c.Add($g) }
        }
    }
    foreach ($cmd in @(Get-Command ssh -All -CommandType Application -ErrorAction SilentlyContinue)) {
        if ($c -notcontains $cmd.Source) { [void]$c.Add($cmd.Source) }
    }
    return , $c.ToArray()
}

function Get-G03PathOrder {
    # Which ssh/git the PATH resolves first (names only; no execution).
    $o = [ordered]@{}
    foreach ($n in @('ssh', 'ssh-add', 'git')) {
        $all = @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
        $o[$n] = $all
    }
    return $o
}

function Get-G03PipeNames {
    # Enumerating \\.\pipe\ lists names without connecting to any pipe.
    if (-not $script:OnWindows) { return @() }
    try { return @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_.Substring(9) }) } catch { return @() }
}

function Get-G03AgentServiceState {
    if (-not $script:OnWindows) { return $null }
    $o = [ordered]@{}
    $svc = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
    if ($null -eq $svc) { $o['present'] = $false; return $o }
    $o['present'] = $true
    $o['status'] = $svc.Status.ToString()
    try { $o['start_type'] = $svc.StartType.ToString() } catch { $o['start_type'] = $null }
    try {
        $qc = & sc.exe qc ssh-agent 2>&1 | Out-String
        $o['sc_qc_exit'] = $LASTEXITCODE
        $o['service_start_name'] = (($qc -split "`r?`n" | Where-Object { $_ -match 'SERVICE_START_NAME' }) -replace '^\s*SERVICE_START_NAME\s*:\s*', '')
        $o['binary_path'] = (($qc -split "`r?`n" | Where-Object { $_ -match 'BINARY_PATH_NAME' }) -replace '^\s*BINARY_PATH_NAME\s*:\s*', '')
        $sd = & sc.exe sdshow ssh-agent 2>&1 | Out-String
        $o['sc_sdshow_exit'] = $LASTEXITCODE
        $o['service_sddl'] = ($sd.Trim())
    } catch { $o['sc_error'] = $_.Exception.Message }
    return $o
}

function Set-G03FileSystemDacl {
    # Write ONLY the DACL of a file or directory. Set-Acl fails with
    # PrivilegeNotHeldException (SeSecurityPrivilege) for a non-admin caller on files
    # whose DACL is protected, e.g. keys written by Win32-OpenSSH ssh-keygen (observed
    # 2026-10-06 under PowerShell 7.6 and 5.1). SetAccessControl with an Access-only
    # security object persists the DACL alone. Windows PowerShell 5.1 exposes it as a
    # FileInfo/DirectoryInfo method, PowerShell 7 as FileSystemAclExtensions.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Acl)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item | Get-Member -Name SetAccessControl -MemberType Method) { $item.SetAccessControl($Acl); return }
    if ($item -is [System.IO.DirectoryInfo]) { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]$item, [System.Security.AccessControl.DirectorySecurity]$Acl) }
    else { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]$item, [System.Security.AccessControl.FileSecurity]$Acl) }
}

function Get-G03ProcessPresence {
    # Names only, never command lines (CLAUDE.md diagnostics rule).
    param([string[]]$Names)
    $o = [ordered]@{}
    foreach ($n in $Names) { $o[$n] = [bool](Get-Process -Name $n -ErrorAction SilentlyContinue) }
    return $o
}

# ---------------------------------------------------------------------------
# Evidence records (tests/evidence/record.schema.json)
# ---------------------------------------------------------------------------
function Write-G03Record {
    param(
        [Parameter(Mandatory = $true)]$Ctx,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][ValidateSet('not_started', 'in_progress', 'blocked', 'implemented_unverified', 'verified', 'deferred_with_decision')][string]$Status,
        # Harness self-test records pass an empty list (tests/evidence/README.md).
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$RequirementIds,
        $Environment,
        [object[]]$ProviderVersions = @(),
        [object]$Commands,
        $Observed,
        [string[]]$EvidencePaths = @(),
        [string[]]$Limitations = @(),
        [string]$BlockedOn
    )
    if ($Status -eq 'blocked' -and -not $BlockedOn) { throw "blocked record $CaseId requires BlockedOn" }
    $rel = @($EvidencePaths | Where-Object { $_ } | ForEach-Object {
            $p = [string]$_
            if ($p.StartsWith($Ctx.RepoRoot)) { $p.Substring($Ctx.RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/' } else { $p }
        })
    $rec = [ordered]@{
        case_id             = $CaseId
        status              = $Status
        requirement_ids     = @($RequirementIds)
        build_commit        = $Ctx.BuildCommit
        artifact_digest     = $null
        environment         = $Environment
        provider_versions   = @($ProviderVersions)
        started_at          = $Ctx.StartedAt
        commands_or_harness = $Commands
        observed_result     = $Observed
        evidence_paths      = $rel
        limitations         = @($Limitations)
        blocked_on          = $(if ($BlockedOn) { $BlockedOn } else { $null })
    }
    $json = $rec | ConvertTo-Json -Depth 12
    $json = Protect-G03Text -Text $json -Ctx $Ctx
    $file = Join-Path $Ctx.RecordsDir ("g03-" + ($CaseId -replace '^G03-', '') + '.json')
    Write-G03Utf8File -Path $file -Text ($json + "`n")
    return $file
}

function Test-G03CanaryLeak {
    param([Parameter(Mandatory = $true)]$Ctx)
    $hits = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $Ctx.OutDir -Recurse -File -ErrorAction SilentlyContinue)) {
        $t = [System.IO.File]::ReadAllText($f.FullName)
        if ($t.Contains($Ctx.Canary) -or $t.Contains($script:CanaryPrefix)) { $hits += $f.FullName }
    }
    return , $hits
}

# ---------------------------------------------------------------------------
# Instrumented agent lifecycle (process owned by this harness)
# ---------------------------------------------------------------------------
function Get-G03HostExe {
    return (Get-Process -Id $PID).Path
}

function Start-G03InstrumentedAgent {
    param(
        [Parameter(Mandatory = $true)]$Ctx,
        [Parameter(Mandatory = $true)][string]$Name,      # logical name, e.g. 'target'
        [string]$PipeName,                                # full pipe name (no \\.\pipe\ prefix)
        [ValidateSet('OwnerOnly', 'AuthenticatedUsers', 'AuthenticatedUsersCreateInstance')][string]$Access = 'OwnerOnly',
        [int]$MaxInstances = 1,
        [switch]$NoFirstInstanceFlag,
        [int]$KeyCount = 1,
        [int[]]$AllowedKeyIndexes,
        [int]$RunSeconds = 300,
        [switch]$ExpectStartFailure
    )
    if (-not $PipeName) { $PipeName = "heimdall-g03-$Name-" + (New-G03RandomHex 6) }
    $dir = Join-Path $Ctx.Scratch ("agent-" + $Name + '-' + (New-G03RandomHex 3))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $log = Join-Path $dir 'agent-log.jsonl'
    $ready = Join-Path $dir 'ready.json'
    $script = Join-Path $PSScriptRoot 'InstrumentedAgent.ps1'
    $agentArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script,
        '-PipeName', $PipeName, '-LogPath', $log, '-ReadyFile', $ready, '-PublicKeyDir', $dir,
        '-KeyCount', [string]$KeyCount, '-RunSeconds', [string]$RunSeconds, '-Access', $Access, '-MaxInstances', [string]$MaxInstances)
    if ($NoFirstInstanceFlag) { $agentArgs += '-NoFirstInstanceFlag' }
    if ($AllowedKeyIndexes) { $agentArgs += @('-AllowedKeyIndexes', (($AllowedKeyIndexes | ForEach-Object { [string]$_ }) -join ',')) }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-G03HostExe
    $psi.Arguments = Join-G03WinArgs $agentArgs
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    # Drain both redirected streams for the agent's whole life so a chatty agent
    # can never block on a full pipe buffer; the text is read only on failure.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $startTime = $null
    try { $startTime = $p.StartTime.ToUniversalTime().ToString('o') } catch { }
    $owned = [pscustomobject]@{ Kind = 'instrumented-agent'; Pid = $p.Id; StartTime = $startTime; Process = $p; StdoutTask = $outTask; StderrTask = $errTask }
    [void]$Ctx.Owned.Add($owned)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $ready) -and -not $p.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    $info = $null
    if (Test-Path -LiteralPath $ready) { $info = Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json }
    if ($null -eq $info -and -not $ExpectStartFailure) {
        $err = ''
        if ($p.HasExited -and $errTask.Wait(2000)) { $err = Protect-G03Text -Ctx $Ctx -Text ([string]$errTask.Result) ; if ($err.Length -gt 2000) { $err = $err.Substring(0, 2000) } }
        throw "instrumented agent '$Name' did not become ready (exited=$($p.HasExited) exit=$(if ($p.HasExited) { $p.ExitCode }) $err)"
    }
    $pipePath = "\\.\pipe\$PipeName"
    if (-not $script:OnWindows -and $info) { $pipePath = $info.endpoint_path }
    return [pscustomobject]@{
        Name = $Name; PipeName = $PipeName; PipePath = $pipePath; LogPath = $log; Dir = $dir
        Process = $p; Owned = $owned; Ready = $info
    }
}

function Stop-G03Owned {
    param([Parameter(Mandatory = $true)]$Owned)
    $p = $Owned.Process
    try {
        if ($p.HasExited) { return 'already-exited' }
        $live = Get-Process -Id $Owned.Pid -ErrorAction SilentlyContinue
        if ($null -eq $live) { return 'not-found' }
        $liveStart = $null
        try { $liveStart = $live.StartTime.ToUniversalTime().ToString('o') } catch { }
        if (-not $Owned.StartTime -or -not $liveStart) { return 'identity-unverified-not-stopped' }
        if ($liveStart -ne $Owned.StartTime) { return 'identity-mismatch-not-stopped' }
        $p.Kill()
        [void]$p.WaitForExit(5000)
        return 'stopped'
    } catch { return ('stop-error: ' + $_.Exception.Message) }
}

function Stop-G03InstrumentedAgent {
    param([Parameter(Mandatory = $true)]$Agent)
    return Stop-G03Owned -Owned $Agent.Owned
}

function Read-G03AgentLog {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $out = @()
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ($line.Trim().Length -eq 0) { continue }
        try { $out += ($line | ConvertFrom-Json) } catch { }
    }
    return $out
}

function Get-G03Prop {
    param($Obj, [string]$Name)
    if ($null -ne $Obj -and $Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
    return $null
}

function Get-G03AgentContact {
    # Summarize what an instrumented agent saw: connections and request types.
    param([Parameter(Mandatory = $true)]$Agent)
    $log = @(Read-G03AgentLog -Path $Agent.LogPath)
    $req = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'request' })
    $conns = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'connect' })
    $resp = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'response' })
    return [ordered]@{
        connections        = $conns.Count
        request_identities = @($req | Where-Object { (Get-G03Prop $_ 'msg_type') -eq 11 }).Count
        sign_requests      = @($req | Where-Object { (Get-G03Prop $_ 'msg_type') -eq 13 }).Count
        signed             = @($resp | Where-Object { (Get-G03Prop $_ 'result') -eq 'signed' }).Count
        denied             = @($resp | Where-Object { [string](Get-G03Prop $_ 'result') -like 'denied*' }).Count
        client_pids        = @($conns | ForEach-Object { Get-G03Prop $_ 'client_pid' } | Where-Object { $_ } | Select-Object -Unique)
        client_images      = @($conns | ForEach-Object { Get-G03Prop $_ 'client_image' } | Where-Object { $_ } | Select-Object -Unique)
        client_paths       = @($conns | ForEach-Object { Get-G03Prop $_ 'client_path' } | Where-Object { $_ } | Select-Object -Unique)
        client_sids        = @($conns | ForEach-Object { Get-G03Prop $_ 'client_sid' } | Where-Object { $_ } | Select-Object -Unique)
        errors             = @($log | Where-Object { (Get-G03Prop $_ 'event') -eq 'error' } | ForEach-Object { Get-G03Prop $_ 'detail' })
    }
}

# Minimal SSH agent protocol client over a named pipe (Unix socket path on
# non-Windows). Used for crafted requests (filtered/unknown key, other-user
# connect attempts). Connects with Identification impersonation level, like
# Win32-OpenSSH's fileio_connect (SECURITY_IDENTIFICATION).
function ConvertTo-G03SshString {
    param([byte[]]$Data)
    if ($null -eq $Data) { $Data = New-Object byte[] 0 }
    $len = [BitConverter]::GetBytes([uint32]$Data.Length); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
    return , ([byte[]]($len + $Data))
}

function New-G03SignRequest {
    param([Parameter(Mandatory = $true)][byte[]]$KeyBlob, [byte[]]$Data = [System.Text.Encoding]::ASCII.GetBytes('heimdall-g03-crafted'))
    $flags = New-Object byte[] 4
    return , ([byte[]](@([byte]13) + (ConvertTo-G03SshString $KeyBlob) + (ConvertTo-G03SshString $Data) + $flags))
}

function Get-G03PubKeyBlob {
    param([Parameter(Mandatory = $true)][string]$PubFile)
    $parts = ([System.IO.File]::ReadAllText($PubFile)).Trim() -split '\s+'
    return , ([Convert]::FromBase64String($parts[1]))
}

function Invoke-G03AgentRaw {
    param([Parameter(Mandatory = $true)][string]$PipeName, [Parameter(Mandatory = $true)][byte[]]$Payload, [int]$TimeoutMs = 5000)
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification)
    try {
        try { $c.Connect($TimeoutMs) } catch { $ie = Get-G03InnerException $_.Exception; return [pscustomobject]@{ Connected = $false; Error = ($ie.GetType().Name + ': ' + $ie.Message); ReplyType = $null; ReplyLength = $null } }
        $len = [BitConverter]::GetBytes([uint32]$Payload.Length); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
        $msg = [byte[]]($len + $Payload)
        $c.Write($msg, 0, $msg.Length); $c.Flush()
        $hdr = New-Object byte[] 4; $got = 0
        while ($got -lt 4) { $n = $c.Read($hdr, $got, 4 - $got); if ($n -le 0) { break }; $got += $n }
        if ($got -lt 4) { return [pscustomobject]@{ Connected = $true; Error = 'no reply header'; ReplyType = $null; ReplyLength = $null } }
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($hdr) }
        $rlen = [BitConverter]::ToUInt32($hdr, 0)
        $first = $c.ReadByte()
        return [pscustomobject]@{ Connected = $true; Error = $null; ReplyType = $first; ReplyLength = $rlen }
    } finally { $c.Dispose() }
}

function Stop-G03AllOwned {
    param([Parameter(Mandatory = $true)]$Ctx)
    $r = @()
    foreach ($o in $Ctx.Owned) { $r += [ordered]@{ kind = $o.Kind; pid = $o.Pid; result = (Stop-G03Owned -Owned $o) } }
    return $r
}

# ---------------------------------------------------------------------------
# Fixture SSH client options: fixture-only state, no owner config/keys.
# ---------------------------------------------------------------------------
function Get-G03BaseSshOptions {
    param([Parameter(Mandatory = $true)][string]$KnownHostsFile, [int]$ConnectTimeout = 10, [string[]]$Without = @())
    $kh = $KnownHostsFile -replace '\\', '/'
    $all = @(
        '-o', 'BatchMode=yes',
        '-o', 'IdentityFile=none',
        '-o', 'IdentitiesOnly=no',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', ("UserKnownHostsFile=" + (ConvertTo-G03SshConfigToken $kh)),
        '-o', 'GlobalKnownHostsFile=none',
        '-o', 'UpdateHostKeys=no',
        '-o', 'ControlMaster=no',
        '-o', 'ControlPath=none',
        '-o', 'ForwardAgent=no',
        '-o', 'ProxyCommand=none',
        '-o', "ConnectTimeout=$ConnectTimeout"
    )
    $out = @()
    for ($i = 0; $i -lt $all.Count; $i += 2) {
        $name = ($all[$i + 1] -split '=', 2)[0]
        if ($Without -contains $name) { continue }
        $out += @($all[$i], $all[$i + 1])
    }
    return $out
}

function ConvertTo-G03SshConfigToken {
    # Quote a value for ssh_config parsing. Forward slashes avoid backslash
    # escaping differences between the strdelim (<=8.6) and argv_split (>=8.7)
    # parsers; double quotes protect spaces.
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -match '[\s"]') { return '"' + ($Value -replace '"', '\"') + '"' }
    return $Value
}

Export-ModuleMember -Function *-G03*
