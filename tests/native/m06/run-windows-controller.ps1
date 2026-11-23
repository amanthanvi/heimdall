#Requires -Version 7.2
<#
.SYNOPSIS
M06 W5 (ADR-0012 §2.6, the 2026-11-22 paragraph; m06-plan §3 "Windows controller rows"): the
Windows controller journey. A Windows controller (the real heimdall.exe under a scratch Heimdall
home; K_mgmt in its DPAPI store under that home; the K_mgmt session agent on its named pipe; the
in-box OpenSSH client) drives a FIXTURE Linux runner that lives in ONE scratch directory inside
the PC's EXISTING WSL distribution, through the product CLI.

.DESCRIPTION
Runs ON the PC (pwsh 7.2 or later), not elevated. Nothing on the Windows host is installed or
changed; nothing binds a non-loopback address; the owner's SSH configuration, keys and agent are
never read (every ssh the product starts here reads the scratch configuration: the debug build's
HEIMDALL_TEST_SSH_HOME, and SSH_AUTH_SOCK is not in any child's environment).

WSL (the owner's rule for the PC): this script NEVER creates, stops or removes a distribution, and
runs no distribution-management command of wsl.exe at all. It uses the distribution -WslDistro
names, which must be registered already, as that distribution's default (non-root) user, inside
one scratch directory it creates there and removes again. Nothing is installed into the
distribution (no package manager runs), no service is enabled, the distribution's own sshd and
its lifetime settings are never touched, and no file outside the scratch directory is written.
The complete list of the WSL commands it runs (host.txt records the ones a run used, as
wsl-command-NN):
  wsl.exe --list --quiet
      read-only: before anything else and after the cleanup (the registered set must be equal);
  wsl.exe -d <WslDistro> --exec /bin/bash -s -- <action> <scratch directory> [arguments]
      one action of tests/native/m06/windows-controller-runner.sh, sent on stdin after
      tests/native/m02/remote-lib.sh (the actions: tools, prepare, authorize, sshd-serve,
      sshd-stop, trust-ca, seed, runtime-serve, runtime-stop, ensure, identities, onward,
      processes, keepalive-before, keepalive-record, cleanup, verify);
  wsl.exe -d <WslDistro> --exec /bin/sleep infinity
      the keep-alive: one process, held by this script and ended through its own handle.
Every wsl.exe start goes through one check (Test-AllowedWslArguments) that refuses any other form.

Reused from the standard harness (tests/native/m02/run-windows-local.ps1 with remote-lib.sh, the
"WSL scratch and both fixture sshds" every PC job starts in the existing distribution): the
scratch layout (<the distribution user's home>/<prefix>-<hex>, created exclusively, mode 700, one
directory per sshd with its per-run host key, configuration, log and state); how the sshd program
is found (hm2_sshd_bin); how a fixture sshd is started (as a child of a wsl.exe session this
script HOLDS for as long as it serves, reading `port=` and `ready=1` from it: that script's step
4) and stopped (hm2_stop_recorded from another session: only when the recorded PID still has the
recorded start time and configuration path; then the held session ends by itself); how wsl.exe is
started (the inherited environment without agent, Git and Heimdall variables, WSL_UTF8=1); and how
Windows reaches the sshd (127.0.0.1, an SSH banner read). remote-lib.sh's functions are called,
not copied. New here: the journey's own sshd configurations, the port kept across a restart, the
runner runtime (held the same way), the keep-alive and the checks after the cleanup.

Inputs (a missing one is exit 3 before anything is created):
  -HeimdallExe      the heimdall.exe under test (a DEBUG build of the candidate commit: the journey
                    needs its test configuration for the scratch SSH home and the scratch issuer
                    store; K_mgmt is the product DPAPI store, under the scratch home);
  -DriverExe        the natively built test executable of e2e_windows_controller_m06 (the fixture
                    driver: the controller's fixture state, and `environment add` on a pseudoconsole);
  -LinuxHeimdall    the Linux x86-64 debug heimdall of the same commit, cross-built on the build host;
  -LinuxDriver      the Linux build of the same driver (the runner's fixture state); both Linux
                    files at plain Windows paths (letters, digits, `.`, `_`, `-`, `\`), which the
                    distribution reads through its Windows drive mount;
  -WslDistro        the name of the EXISTING distribution (required; the one the standard
                    harness's -WslDistro names). Not registered: exit 3, naming it;
  -ScratchRoot      an existing directory for the run directory (never %LOCALAPPDATA%\Heimdall).

Steps:
  1. `wsl.exe --list --quiet`: -WslDistro must be registered (exit 3 otherwise). Then, inside it,
     the runner script's `tools`: every tool the fixture needs is CHECKED, never installed (sshd,
     ssh, ssh-keygen, ssh-add, python3, ps, wslpath and the usual file tools; a missing one is
     exit 3 naming it), the default user must not be root, its home must be able to hold the
     scratch directory and both Linux files must be readable from there. Nothing is created.
  2. The run directory <ScratchRoot>\hm-m06j-<hex> (created exclusively), with the controller's
     scratch Heimdall home and scratch account home.
  3. The runner fixture: <the distribution user's home>/hm-m06j-<hex>, created exclusively by the
     runner script's `prepare` (the staged Linux binaries after a SHA-256 check, the scratch
     Heimdall and account homes, the per-run host keys; this host's sshd must accept the fixture
     configuration unprivileged, exit 3 otherwise).
  4. The keep-alive for the whole run, the "controller stopped" steps included: one
     `wsl.exe -d <WslDistro> --exec /bin/sleep infinity`, started here and ended through its own
     handle in the cleanup. The distribution's own lifetime settings are neither relied on nor
     changed. Its Linux process is recorded in the scratch directory (the one new `sleep
     infinity` of this account), so the cleanup can show it gone.
  5. A management sshd and a destination sshd (unprivileged, 127.0.0.1 only, free high ports
     chosen at run time, per-run host keys; the distribution's own sshd, on 22 or anywhere, is
     never touched) and later the runner's runtime, each a child of a held wsl.exe session;
     reached from Windows on 127.0.0.1 (WSL's localhost relay; waited for up to 90 s).
  6. The journey, one `m06 observation: <case> <step>: <result>` line per step, with the case and
     step names of the single-host suite (tests/e2e/exit_m06) where the step is the same:
       a24 pair, a24 approve, a07 issued, a07 disconnected, a07 revoke-pending, a07 reconnect,
       a07 barrier, a24 controller-leaves, a24 onward-managed, a24 no-controller-socket.
     A step that fails is FAILED with its reason (codes and states only); the steps after it do
     not run and are written `ignored`, which the evidence generator never reads as passed.
  7. Always (pass or fail): the controller runtime is stopped; the keep-alive is ended through
     its handle; the runner script's `cleanup` stops exactly the processes this run started in
     the distribution (the runtime through its own `service stop`; each sshd, and a keep-alive
     process that outlived its handle, by the PID recorded in the scratch directory, only while
     that PID still has the recorded start time and identity) and removes exactly the scratch
     directory; the held sessions end. Then it is verified and recorded: the scratch directory
     is gone, no process naming it is left in the distribution, and the registered set of
     distributions equals the one before. The run directory on Windows is removed.

Output (in -Out, default the current directory): tests.txt (the `### windows-controller-journey`
section in the form tests/native/m02/m02-evidence.py reads: one `test <step> ... ok|FAILED` line
per step and each step's observation under its `---- <step> stdout ----` header), host.txt
(key=value facts: versions, states and the WSL command forms; no path, account, distribution
name or address) and results on stdout.
Exit 0: every step passed; 1: a step failed or the cleanup left something; 3: blocked (an input,
the distribution or a tool in it is missing: no step ran, and what was created is removed).

.PARAMETER WslDistro
The existing WSL distribution's registered name, exactly as `wsl.exe --list --quiet` prints it.

.PARAMETER Local
The script's rehearsal on the build host (any Unix with OpenSSH and pwsh): the runner fixture is
the same runner script in a scratch directory on this host, the controller is this host's own
debug heimdall with a FIXTURE K_mgmt store (never the account's key store), and there is no
distribution and no wsl.exe. It exercises the step logic, the held sessions, the cleanup checks,
the parsing and the output format; it is never evidence for a Windows row (the observations say
`rehearsal`).

.PARAMETER SelfTest
The pure helpers on synthetic data (no host state, no network, no WSL), the scan of this script
and the runner script for a distribution-management verb, and the runner script's refusals.
Runs anywhere.

.PARAMETER DryRun
Check the inputs (and, on the PC, that -WslDistro is registered: the read-only list), print the
plan and exit; nothing is created and nothing runs in the distribution.

.EXAMPLE
pwsh -NoProfile -File tests\native\m06\run-windows-controller.ps1 -ScratchRoot C:\hm `
    -HeimdallExe C:\hm\b\heimdall.exe -DriverExe C:\hm\b\e2e_windows_controller_m06.exe `
    -LinuxHeimdall C:\hm\l\heimdall -LinuxDriver C:\hm\l\e2e_windows_controller_m06 `
    -WslDistro <the existing distribution> -Out C:\hm\out
#>
[CmdletBinding()]
param(
    [string]$ScratchRoot,
    [string]$HeimdallExe,
    [string]$DriverExe,
    [string]$LinuxHeimdall,
    [string]$LinuxDriver,
    [string]$WslDistro = '',
    [string]$Out = '.',
    [switch]$Local,
    [switch]$SelfTest,
    [switch]$DryRun
)
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$Target = 'windows-controller-journey'
$Alias = 'hm-m06j-runner'
$ScratchPattern = '\Ahm-m06j-[0-9a-f]{8}\z'
# The runner script's actions this script sends into the distribution (and no other).
$RunnerActions = @('tools', 'prepare', 'authorize', 'sshd-serve', 'sshd-stop', 'trust-ca', 'seed', 'runtime-serve', 'runtime-stop',
    'ensure', 'identities', 'onward', 'processes', 'keepalive-before', 'keepalive-record', 'cleanup', 'verify')

# ---------------------------------------------------------------------------------------------
# Pure helpers (the self-test's subjects).
# ---------------------------------------------------------------------------------------------

# The journey's steps, in order: the test name of the log, the case and the step.
function Get-JourneySteps {
    return @(
        @{ Test = 'a24_pair'; Case = 'a24'; Step = 'pair' },
        @{ Test = 'a24_approve'; Case = 'a24'; Step = 'approve' },
        @{ Test = 'a07_issued'; Case = 'a07'; Step = 'issued' },
        @{ Test = 'a07_disconnected'; Case = 'a07'; Step = 'disconnected' },
        @{ Test = 'a07_revoke_pending'; Case = 'a07'; Step = 'revoke-pending' },
        @{ Test = 'a07_reconnect'; Case = 'a07'; Step = 'reconnect' },
        @{ Test = 'a07_barrier'; Case = 'a07'; Step = 'barrier' },
        @{ Test = 'a24_controller_leaves'; Case = 'a24'; Step = 'controller-leaves' },
        @{ Test = 'a24_onward_managed'; Case = 'a24'; Step = 'onward-managed' },
        @{ Test = 'a24_no_controller_socket'; Case = 'a24'; Step = 'no-controller-socket' }
    )
}

function New-RandomHex([int]$Bytes) {
    $b = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return ([System.BitConverter]::ToString($b) -replace '-', '').ToLowerInvariant()
}

# The scratch directory's name, on Windows and inside the distribution.
function Test-ScratchName([string]$Name) { return ($Name -cmatch $ScratchPattern) }

# A distribution name this script accepts on its command line: plain, and never an option.
function Test-DistributionName([string]$Name) { return ($Name -cmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') }

# The runner's scratch directory as the distribution reported it: a plain absolute path whose
# last component is this run's name, below at least one directory (the user's home).
function Test-RunnerRoot([string]$Path, [string]$Name) {
    if (-not (Test-ScratchName $Name)) { return $false }
    if ($Path -cnotmatch '\A(/[A-Za-z0-9_.-]+)+\z' -or $Path -cmatch '/\.\.?(/|\z)') { return $false }
    return ($Path.EndsWith("/$Name", [System.StringComparison]::Ordinal) -and $Path.Length -gt ($Name.Length + 1))
}

# A Windows path the distribution can be handed as one plain argument.
function Test-PlainWindowsPath([string]$Path) { return ($Path -cmatch '\A[A-Za-z]:(\\[A-Za-z0-9_.-]+)+\z') }

# The three forms of wsl.exe arguments this script uses (the header lists them).
function Get-WslListArguments { return @('--list', '--quiet') }
function Get-WslKeepAliveArguments([string]$Distro) { return @('-d', $Distro, '--exec', '/bin/sleep', 'infinity') }
function Get-WslRunnerArguments([string]$Distro, [string]$Action, [string]$Root, [string[]]$Arguments) {
    return @('-d', $Distro, '--exec', '/bin/bash', '-s', '--', $Action, $Root) + @($Arguments)
}

# Whether an argument list is exactly one of those forms, for the distribution -WslDistro named.
# Everything else is refused before wsl.exe starts: another distribution, another user, any
# option of wsl.exe besides `--list --quiet`, `-d` and `--exec`, an action that is not the runner
# script's, or a runner argument that looks like an option or needs quoting.
function Test-AllowedWslArguments([string[]]$Arguments, [string]$Distro) {
    $a = @($Arguments)
    if ($a.Count -eq 2) { return ($a[0] -ceq '--list' -and $a[1] -ceq '--quiet') }
    if ($a.Count -lt 5 -or -not (Test-DistributionName $Distro)) { return $false }
    if ($a[0] -cne '-d' -or $a[1] -cne $Distro -or $a[2] -cne '--exec') { return $false }
    if ($a.Count -eq 5) { return ($a[3] -ceq '/bin/sleep' -and $a[4] -ceq 'infinity') }
    if ($a.Count -lt 8 -or $a[3] -cne '/bin/bash' -or $a[4] -cne '-s' -or $a[5] -cne '--') { return $false }
    if ($RunnerActions -cnotcontains $a[6]) { return $false }
    foreach ($x in $a[7..($a.Count - 1)]) { if (-not $x -or $x.StartsWith('-') -or $x -match '[\s"''`$;&|<>]') { return $false } }
    return $true
}

# The form host.txt records for an argument list (no distribution name, path or key).
function Format-WslCommand([string[]]$Arguments) {
    $a = @($Arguments)
    if ($a.Count -eq 2) { return 'wsl.exe --list --quiet' }
    if ($a.Count -eq 5) { return 'wsl.exe -d <WslDistro> --exec /bin/sleep infinity' }
    return "wsl.exe -d <WslDistro> --exec /bin/bash -s -- $($a[6]) <scratch directory>$(if ($a.Count -gt 8) { ' <arguments>' } else { '' })"
}

# The distribution-management verbs of wsl.exe, which must not appear anywhere in this script or
# in the runner script (spelled in two parts here, so this list is not itself a finding).
function Get-ForbiddenWslVerbs {
    return @('import', 'export', 'unregister', 'shutdown', 'terminate', 'install', 'set-default', 'update', 'uninstall', 'set-version', 'mount', 'unmount', 'manage') |
        ForEach-Object { '--' + $_ }
}
function Find-ForbiddenWslVerbs([string]$Text) { return @(Get-ForbiddenWslVerbs | Where-Object { $Text.Contains($_) }) }

# What the runner script's preflight (`tools`, exit 3) says, as the blocked reason.
function Get-PreflightBlock([hashtable]$Facts) {
    if ($Facts['missing']) { return "the distribution lacks: $(($Facts['missing'] -replace '[^A-Za-z0-9,._/-]', '?')) (checked, never installed by this script)" }
    $why = @{
        root_account = 'the distribution''s default user is root (the fixture runs as a non-root user and creates none)'
        no_home = 'the distribution''s user has no home directory'
        home_is_not_a_plain_path = 'the distribution user''s home is not a plain path'
        home_is_not_writable = 'the distribution user''s home cannot hold the scratch directory'
        scratch_directory_exists = 'the scratch directory name exists in the distribution already (run again)'
        windows_path_not_translated = 'the distribution cannot translate the Windows paths of the Linux binaries (wslpath)'
        linux_binaries_not_readable_from_the_distribution = 'the Linux binaries are not readable from the distribution (its Windows drive mount)'
    }
    $b = [string]$Facts['blocked']
    if ($b -and $why.ContainsKey($b)) { return $why[$b] }
    return 'the preflight inside the distribution refused (no reason given)'
}

# `wsl --list --quiet` output as names (it may arrive with NULs and blank lines).
function ConvertFrom-WslList([string]$Text) {
    return @(($Text -replace "`0", '') -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-SameSet([string[]]$A, [string[]]$B) {
    $x = @($A | Sort-Object -Unique); $y = @($B | Sort-Object -Unique)
    return ($x.Count -eq $y.Count) -and (@(Compare-Object $x $y).Count -eq 0 -or $x.Count -eq 0)
}

# `key=value` lines as a table; a line without `=`, or a repeated key, is ignored (first wins).
function ConvertFrom-Facts([string]$Text) {
    $t = @{}
    foreach ($l in ($Text -split "`r?`n")) {
        $i = $l.IndexOf('=')
        if ($i -gt 0) { $k = $l.Substring(0, $i); if (-not $t.ContainsKey($k)) { $t[$k] = $l.Substring($i + 1).Trim() } }
    }
    return $t
}

# The envelope a `--json` command printed, or $null when its output is not one.
function ConvertFrom-Envelope([string]$Text) {
    try { $v = $Text | ConvertFrom-Json -Depth 64 } catch { return $null }
    if ($null -eq $v -or $v -isnot [pscustomobject] -or $null -eq $v.PSObject.Properties['code']) { return $null }
    return $v
}

# One value of an envelope by path (`data.error.reason`, `remote_pending.0.target.kind`): '' when
# any part is absent. Booleans read `true`/`false`; an array or object reads as compact JSON.
function Get-Field($Value, [string]$Path) {
    $v = $Value
    foreach ($k in ($Path -split '\.')) {
        if ($null -eq $v) { return '' }
        if ($v -is [array] -or $v -is [System.Collections.IList]) {
            $i = 0
            if (-not [int]::TryParse($k, [ref]$i) -or $i -lt 0 -or $i -ge @($v).Count) { return '' }
            $v = @($v)[$i]
        } elseif ($v -is [pscustomobject] -and $null -ne $v.PSObject.Properties[$k]) {
            $v = $v.PSObject.Properties[$k].Value
        } else { return '' }
    }
    if ($null -eq $v) { return '' }
    if ($v -is [bool]) { return $v.ToString().ToLowerInvariant() }
    if ($v -is [string]) { return $v }
    if ($v -is [array] -or $v -is [System.Collections.IList] -or $v -is [pscustomobject]) { return (ConvertTo-Json -InputObject $v -Compress -Depth 64) }
    return [string]$v
}

# The controller's record of one runner in `environment status`, or $null.
function Select-Environment($Envelope, [string]$Environment) {
    if ($null -eq $Envelope) { return $null }
    $data = $Envelope.PSObject.Properties['data']
    if ($null -eq $data -or $null -eq $data.Value -or $null -eq $data.Value.PSObject.Properties['environments']) { return $null }
    foreach ($e in @($data.Value.environments)) { if ((Get-Field $e 'environment') -ceq $Environment) { return $e } }
    return $null
}

# What a failed step may say: codes, reasons and states only (lowercase/uppercase words, digits,
# `_`, `=`, `-`, `,`, spaces). Anything else in a reason is replaced, so no path, account, address
# or key can reach the log through a failure.
function Protect-Reason([string]$Text, [int]$Limit = 300) {
    $one = ($Text -replace "[`r`n]+", ' ')
    if ($one.Length -gt $Limit) { $one = $one.Substring(0, $Limit) }
    return ($one -replace '[^A-Za-z0-9_=,\- ]', '?')
}

# ⟨M06 W5 `w5s`, PC job 38 diagnostics⟩ What a driver or command result says about itself, for a
# failed step's reason: its code, reason and exit, and its message through Protect-Reason (codes and
# words only, never a path, address or quote). $Result is a driver's facts (a hashtable) or a
# command's JSON envelope; a part it does not have reads `none`.
function Format-ResultSummary($Result) {
    if ($Result -is [System.Collections.IDictionary]) {
        $get = { param($k) if ($Result.Contains($k) -and "$($Result[$k])") { [string]$Result[$k] } else { 'none' } }
        $code = & $get 'code'; $why = & $get 'reason'; $exit = & $get 'exit'; $message = & $get 'message'
        $fields = & $get 'error_fields'; $envelope = & $get 'envelope'
    } else {
        $pick = { param($path) $v = Get-Field $Result $path; if ($v) { $v } else { 'none' } }
        $code = & $pick 'code'; $why = & $pick 'data.error.reason'; $exit = 'none'; $message = & $pick 'data.error.message'
        $fields = 'none'; $envelope = if ($null -eq $Result) { 'absent' } else { 'present' }
    }
    return "code=$code reason=$why exit=$exit envelope=$envelope error_fields=$(Protect-Reason $fields) message=$(Protect-Reason $message 600)"
}
# The first assertion of a step on a result: as Assert-Equal, and a failure also says the result's
# code, reason and (protected) message, so a step that fails early is never reported by the one
# asserted field alone.
function Assert-Result([string]$What, [string]$Got, [string]$Want, $Result) {
    if ($Got -cne $Want) { throw "$What=$Got wanted=$Want $(Format-ResultSummary $Result)" }
}

# The log section m02-evidence.py reads. $Results: ordered list of @{ Test; Case; Step; Ok;
# Observation; Reason }. A failed step has no observation; its reason is printed (protected)
# under its header. A step of $Planned (the test names, in order) that did not run is `ignored`:
# the evidence generator then keeps its row in_progress, and never reads it as passed or absent.
function Format-JourneyLog([object[]]$Results, [int]$Code, [string[]]$Planned = @()) {
    $s = [System.Text.StringBuilder]::new()
    $ran = @($Results | ForEach-Object { $_.Test })
    $notRun = @($Planned | Where-Object { $ran -notcontains $_ })
    [void]$s.Append("### $Target`n`nrunning $(@($Results).Count + $notRun.Count) tests`n")
    foreach ($r in $Results) { [void]$s.Append("test $($r.Test) ... $(if ($r.Ok) { 'ok' } else { 'FAILED' })`n") }
    foreach ($n in $notRun) { [void]$s.Append("test $n ... ignored`n") }
    $passed = @($Results | Where-Object { $_.Ok }); $failed = @($Results | Where-Object { -not $_.Ok })
    if ($passed.Count -gt 0) {
        [void]$s.Append("`nsuccesses:`n`n")
        foreach ($r in $passed) { [void]$s.Append("---- $($r.Test) stdout ----`nm06 observation: $($r.Case) $($r.Step): $($r.Observation)`n`n") }
    }
    if ($failed.Count -gt 0) {
        [void]$s.Append("`nfailures:`n`n")
        foreach ($r in $failed) { [void]$s.Append("---- $($r.Test) stdout ----`nfailed: $(Protect-Reason $r.Reason 900)`n`n") }
    }
    [void]$s.Append("test result: $(if ($failed.Count -eq 0) { 'ok' } else { 'FAILED' }). $($passed.Count) passed; $($failed.Count) failed; $($notRun.Count) ignored`n")
    [void]$s.Append("### $Target exit=$Code`n")
    return $s.ToString()
}

# The run's exit code: 0 only when every step of the plan ran and passed and the cleanup was clean.
function Get-RunExit([object[]]$Results, [int]$Planned, [bool]$CleanupOk) {
    if (@($Results | Where-Object { -not $_.Ok }).Count -gt 0) { return 1 }
    if (@($Results).Count -ne $Planned) { return 1 }
    if (-not $CleanupOk) { return 1 }
    return 0
}

# The scratch ssh configuration of the controller's existing access to the runner account.
function Format-SshConfig([string]$Port, [string]$IdentityFile) {
    return "Host $Alias`n    HostName 127.0.0.1`n    Port $Port`n    IdentityFile `"$($IdentityFile -replace '\\', '/')`"`n" +
    "    IdentitiesOnly yes`n    IdentityAgent none`n    CertificateFile none`n"
}

function Test-Sha256([string]$Text) { return ($Text -cmatch '\A[0-9a-f]{64}\z') }

# ---------------------------------------------------------------------------------------------
# -SelfTest
# ---------------------------------------------------------------------------------------------

function Invoke-SelfTest {
    $script:fail = 0; $script:count = 0
    function Check([string]$Name, [bool]$Ok) {
        $script:count++
        if ($Ok) { Write-Output "ok   $Name" } else { $script:fail++; Write-Output "FAIL $Name" }
    }
    $steps = Get-JourneySteps
    Check 'S01 ten steps, unique test names without spaces, cases a24 and a07 only' (
        $steps.Count -eq 10 -and @($steps.Test | Sort-Object -Unique).Count -eq 10 -and
        @($steps | Where-Object { $_.Test -notmatch '\A[a-z0-9_]+\z' }).Count -eq 0 -and
        (@($steps.Case | Sort-Object -Unique) -join ',') -eq 'a07,a24')
    Check 'S02 the pair is first and the controller leaves only after the revoke was reconciled' (
        $steps[0].Step -eq 'pair' -and [array]::IndexOf($steps.Step, 'controller-leaves') -gt [array]::IndexOf($steps.Step, 'barrier'))
    Check 'N01 scratch names are only hm-m06j-<8 hex>; a distribution name is plain and never an option' (
        (Test-ScratchName 'hm-m06j-0123abcd') -and -not (Test-ScratchName 'hm-m06j-0123ABCD') -and
        -not (Test-ScratchName 'hm-m06j-0123abcd-1') -and -not (Test-ScratchName "hm-m06j-0123abcd`n") -and -not (Test-ScratchName '') -and
        (Test-DistributionName 'Ubuntu') -and (Test-DistributionName 'Ubuntu-24.04') -and -not (Test-DistributionName '') -and
        -not (Test-DistributionName '--list') -and -not (Test-DistributionName '-d') -and -not (Test-DistributionName 'a b') -and
        -not (Test-DistributionName "Ubuntu`n") -and -not (Test-DistributionName ('a' * 65)))
    Check 'N02 a new name matches the pattern' (Test-ScratchName ('hm-m06j-' + (New-RandomHex 4)))
    $list = ConvertFrom-WslList "U`0b`0u`0n`0t`0u`0`r`n`r`nDebian`r`n"
    Check 'N03 the wsl list is read with NULs and blank lines' ($list.Count -eq 2 -and $list[0] -eq 'Ubuntu' -and $list[1] -eq 'Debian')
    Check 'N04 the runner scratch directory is <a plain home>/<this run''s name> and nothing else' (
        (Test-RunnerRoot '/home/u/hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and (Test-RunnerRoot '/home/a.b_c-d/hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and
        -not (Test-RunnerRoot '/hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and -not (Test-RunnerRoot '/home/u/hm-m06j-0123abce' 'hm-m06j-0123abcd') -and
        -not (Test-RunnerRoot '/home/u/../hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and -not (Test-RunnerRoot '/home/u v/hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and
        -not (Test-RunnerRoot 'home/u/hm-m06j-0123abcd' 'hm-m06j-0123abcd') -and -not (Test-RunnerRoot '/home/u/hm-m06j-0123abcd/' 'hm-m06j-0123abcd') -and
        -not (Test-RunnerRoot '/home/u/x' 'x') -and -not (Test-RunnerRoot '' 'hm-m06j-0123abcd'))
    Check 'N05 set comparison ignores order and repeats' (
        (Test-SameSet @('a', 'b') @('b', 'a', 'a')) -and -not (Test-SameSet @('a') @('a', 'b')) -and (Test-SameSet @() @()) -and -not (Test-SameSet @() @('a')))
    $f = ConvertFrom-Facts "code=OK`r`nenvironment=env_1`nnoequals`n=x`ncode=LATER`nendpoint=/a=b`n"
    Check 'F01 facts: first value wins, values may hold =, malformed lines are ignored' (
        $f['code'] -eq 'OK' -and $f['environment'] -eq 'env_1' -and $f['endpoint'] -eq '/a=b' -and $f.Count -eq 3)
    $e = ConvertFrom-Envelope '{"code":"OK","operation_id":"op_1","data":{"grant_id":"grant_1","local_applied":false,"remote_pending":[{"target":{"kind":"grant_revoke"}}],"environments":[{"environment":"env_a","issuance":"reconciled","connectivity":{"state":"connected"},"remote_pending":[],"residuals":[{"acknowledged":true}]},{"environment":"env_b"}]}}'
    Check 'E01 envelope fields by path, booleans as words, arrays by index' (
        (Get-Field $e 'code') -eq 'OK' -and (Get-Field $e 'data.grant_id') -eq 'grant_1' -and (Get-Field $e 'data.local_applied') -eq 'false' -and
        (Get-Field $e 'data.remote_pending.0.target.kind') -eq 'grant_revoke')
    Check 'E02 an absent part reads empty, never an error' (
        (Get-Field $e 'data.error.reason') -eq '' -and (Get-Field $e 'data.remote_pending.3.target') -eq '' -and
        (Get-Field $e 'data.remote_pending.x') -eq '' -and (Get-Field $null 'code') -eq '' -and (Get-Field $e 'code.more') -eq '')
    $a = Select-Environment $e 'env_a'
    Check 'E03 the status record of one runner; an empty list reads as []' (
        (Get-Field $a 'issuance') -eq 'reconciled' -and (Get-Field $a 'connectivity.state') -eq 'connected' -and
        (Get-Field $a 'remote_pending') -eq '[]' -and (Get-Field $a 'residuals.0.acknowledged') -eq 'true' -and
        $null -eq (Select-Environment $e 'env_c') -and $null -eq (Select-Environment $null 'env_a'))
    Check 'E04 what is not an envelope is $null' (
        $null -eq (ConvertFrom-Envelope 'ssh: connect to host') -and $null -eq (ConvertFrom-Envelope '') -and
        $null -eq (ConvertFrom-Envelope '{"note":1}') -and $null -eq (ConvertFrom-Envelope '[1]'))
    $p = Protect-Reason "code=STATE_UNAVAILABLE at C:\Users\someone\x /home/u 127.0.0.1 `"q`"`nnext"
    Check 'P01 a failure reason keeps codes and loses paths, addresses and quotes' (
        $p.Contains('code=STATE_UNAVAILABLE') -and -not $p.Contains('\') -and -not $p.Contains('/') -and -not $p.Contains('.') -and
        -not $p.Contains('"') -and -not $p.Contains("`n") -and (Protect-Reason ('x' * 900)).Length -eq 300)
    # ⟨`w5s`, PC job 38 diagnostics⟩ A failing first assertion names the result's code, reason and
    # protected message: never a path, address, quote or secret.
    $driverFacts = @{ prompted = 'false'; code = 'STATE_UNAVAILABLE'; reason = 'mgmt_agent_unavailable'; exit = '3'
        message = 'the controller''s management key agent could not start at C:\Users\someone\x /home/u/.ssh 127.0.0.1 "s3cretT0ken"' }
    $driverFail = try { Assert-Result 'first_pass_prompted' $driverFacts['prompted'] 'true' $driverFacts; '' } catch { $_.Exception.Message }
    $envFail = try { Assert-Result 'code' 'DENIED' 'OK' (ConvertFrom-Envelope '{"code":"DENIED","data":{"error":{"reason":"policy_paused","message":"paused at /var/x"}}}'); '' } catch { $_.Exception.Message }
    $logged = Protect-Reason $driverFail 900
    Check 'P02 a failed first assertion prints the result''s code, reason and protected message, never a path or secret' (
        $driverFail.StartsWith('first_pass_prompted=false wanted=true code=STATE_UNAVAILABLE reason=mgmt_agent_unavailable exit=3 ') -and
        $driverFail.Contains('message=the controller') -and $driverFail.Contains('management key agent could not start') -and
        -not $driverFail.Contains('\') -and -not $driverFail.Contains('/') -and -not $driverFail.Contains('127.0.0.1') -and -not $driverFail.Contains('"') -and
        -not $logged.Contains('/') -and
        $envFail.StartsWith('code=DENIED wanted=OK code=DENIED reason=policy_paused ') -and -not $envFail.Contains('/') -and
        (Format-ResultSummary $null).StartsWith('code=none reason=none') -and
        $null -eq (& { try { Assert-Result 'x' 'a' 'a' $driverFacts } catch { 'threw' } }))
    $ok = @{ Test = 'a24_pair'; Case = 'a24'; Step = 'pair'; Ok = $true; Observation = 'owner_enrolled=true'; Reason = '' }
    $bad = @{ Test = 'a24_approve'; Case = 'a24'; Step = 'approve'; Ok = $false; Observation = ''; Reason = 'code=CAPABILITY_UNAVAILABLE reason=x at /p' }
    $log = Format-JourneyLog @($ok, $bad) 1 @('a24_pair', 'a24_approve', 'a07_issued')
    Check 'L01 the log has the section, one test line per planned step (a step that did not run is ignored), and the exit' (
        $log.StartsWith("### $Target`n") -and $log.Contains("`ntest a24_pair ... ok`n") -and $log.Contains("`ntest a24_approve ... FAILED`n") -and
        $log.Contains("`ntest a07_issued ... ignored`n") -and $log.Contains("running 3 tests") -and
        $log.Contains('test result: FAILED. 1 passed; 1 failed; 1 ignored') -and $log.TrimEnd().EndsWith("### $Target exit=1"))
    Check 'L02 a passed step carries its observation under its header; a failed one none' (
        $log.Contains("---- a24_pair stdout ----`nm06 observation: a24 pair: owner_enrolled=true`n") -and
        -not $log.Contains('m06 observation: a24 approve') -and $log.Contains("---- a24_approve stdout ----`nfailed: code=CAPABILITY_UNAVAILABLE reason=x at ?p`n"))
    $lines = @($log -split "`n")
    Check 'L03 every line is one the evidence parser expects (no CR, no stray test line)' (
        -not $log.Contains("`r") -and @($lines | Where-Object { $_ -match '^test \S+ \.\.\. ' }).Count -eq 3 -and
        @($lines | Where-Object { $_ -match '^\s*m06 observation\b' }).Count -eq 1)
    Check 'X01 exit 0 only when every planned step passed and the cleanup was clean' (
        (Get-RunExit @($ok) 1 $true) -eq 0 -and (Get-RunExit @($ok) 2 $true) -eq 1 -and (Get-RunExit @($ok, $bad) 2 $true) -eq 1 -and
        (Get-RunExit @($ok) 1 $false) -eq 1 -and (Get-RunExit @() 10 $true) -eq 1)
    $cfg = Format-SshConfig '20022' 'C:\s\acct\.ssh\id_fixture'
    Check 'C01 the scratch ssh configuration names only the fixture key, no agent, forward slashes' (
        $cfg.Contains("Host $Alias`n") -and $cfg.Contains('    Port 20022') -and $cfg.Contains('IdentityFile "C:/s/acct/.ssh/id_fixture"') -and
        $cfg.Contains('IdentitiesOnly yes') -and $cfg.Contains('IdentityAgent none') -and -not $cfg.Contains('\'))
    Check 'C02 digests are 64 lowercase hex' ((Test-Sha256 ('a' * 64)) -and -not (Test-Sha256 ('A' * 64)) -and -not (Test-Sha256 ('a' * 63)) -and -not (Test-Sha256 (('a' * 64) + "`n")))
    $dn = 'Ubuntu'; $rt = '/home/u/hm-m06j-0123abcd'
    Check 'W01 the three wsl.exe forms this script builds are allowed, for the named distribution only' (
        (Test-AllowedWslArguments (Get-WslListArguments) $dn) -and (Test-AllowedWslArguments (Get-WslKeepAliveArguments $dn) $dn) -and
        (Test-AllowedWslArguments (Get-WslRunnerArguments $dn 'cleanup' $rt @()) $dn) -and
        (Test-AllowedWslArguments (Get-WslRunnerArguments $dn 'tools' $rt @('C:\hm\l\heimdall', 'C:\hm\l\driver')) $dn) -and
        (Test-AllowedWslArguments (Get-WslRunnerArguments $dn 'authorize' $rt @('ssh-ed25519', 'AAAAC3Nza+/x=')) $dn) -and
        -not (Test-AllowedWslArguments (Get-WslRunnerArguments 'Other' 'cleanup' $rt @()) $dn) -and
        -not (Test-AllowedWslArguments (Get-WslKeepAliveArguments 'Other') $dn) -and
        @($RunnerActions | Where-Object { -not (Test-AllowedWslArguments (Get-WslRunnerArguments $dn $_ $rt @()) $dn) }).Count -eq 0)
    $refused = @(
        @(), @('--list'), @('--list', '--verbose'), @('--list', '--quiet', '--all'), @('-d', $dn), @('-d', $dn, '--exec', '/bin/sleep'),
        @('-d', $dn, '--exec', '/bin/sleep', '60'), @('-d', $dn, '--exec', '/bin/rm', '-rf'), @('-d', $dn, '-u', 'root', '--exec', '/bin/sleep', 'infinity'),
        @('-u', 'root', '-d', $dn, '--exec', '/bin/sleep', 'infinity'), @('-d', $dn, '--', '/bin/bash', '-s', '--', 'cleanup', $rt),
        @('-d', $dn, '--exec', '/bin/bash', '-c', 'true', 'x', 'cleanup', $rt), @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'apt-get', $rt),
        @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'cleanup', $rt, '-x'), @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'cleanup', $rt, 'a b'),
        @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'cleanup', $rt, 'a"b'), @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'cleanup', $rt, ''),
        @('-d', $dn, '--exec', '/bin/bash', '-s', '--', 'cleanup'), @('--exec', '/bin/sleep', 'infinity', '-d', $dn))
    foreach ($v in (Get-ForbiddenWslVerbs)) { $refused += , @($v, $dn); $refused += , @('-d', $dn, $v); $refused += , @($v) ; $refused += , @($v, $dn, 'C:\x', 'C:\y', '--version') }
    Check 'W02 every other form is refused: a management verb, another user, another program, an option or a quoted runner argument' (
        @($refused | Where-Object { Test-AllowedWslArguments $_ $dn }).Count -eq 0 -and $refused.Count -gt 60 -and
        -not (Test-AllowedWslArguments (Get-WslKeepAliveArguments '--list') '--list'))
    Check 'W03 host.txt records the forms without a distribution name, path or key' (
        (Format-WslCommand (Get-WslListArguments)) -eq 'wsl.exe --list --quiet' -and
        (Format-WslCommand (Get-WslKeepAliveArguments $dn)) -eq 'wsl.exe -d <WslDistro> --exec /bin/sleep infinity' -and
        (Format-WslCommand (Get-WslRunnerArguments $dn 'cleanup' $rt @())) -eq 'wsl.exe -d <WslDistro> --exec /bin/bash -s -- cleanup <scratch directory>' -and
        (Format-WslCommand (Get-WslRunnerArguments $dn 'authorize' $rt @('ssh-ed25519', 'AAAA'))) -eq 'wsl.exe -d <WslDistro> --exec /bin/bash -s -- authorize <scratch directory> <arguments>')
    $own = Get-Content -LiteralPath $PSCommandPath -Raw
    $runner = Join-Path $PSScriptRoot 'windows-controller-runner.sh'
    $runnerOwn = Get-Content -LiteralPath $runner -Raw
    $verbs = @(Get-ForbiddenWslVerbs)
    Check 'W04 no distribution-management verb of wsl.exe appears anywhere in this script or the runner script' (
        $verbs.Count -ge 8 -and @($verbs | Where-Object { $_ -notmatch '\A--[a-z-]+\z' }).Count -eq 0 -and
        @(Find-ForbiddenWslVerbs $own).Count -eq 0 -and @(Find-ForbiddenWslVerbs $runnerOwn).Count -eq 0 -and
        (@(Find-ForbiddenWslVerbs ('wsl ' + $verbs[2] + ' x')) -join ',') -eq $verbs[2] -and @(Find-ForbiddenWslVerbs ('x ' + $verbs[0] + '-in-place')).Count -eq 1)
    # Every use of the wsl.exe path: its definition and existence check at the top level, and
    # functions that check their arguments first (Assert-WslArguments).
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)
    $uses = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'wslExe' }, $true))
    $unguarded = 0; $guarded = @{}
    foreach ($u in $uses) {
        $f = $u.Parent
        while ($null -ne $f -and $f -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $f = $f.Parent }
        if ($null -eq $f) {
            $s = $u.Parent
            while ($null -ne $s.Parent -and $s -isnot [System.Management.Automation.Language.StatementAst]) { $s = $s.Parent }
            if (-not $s.Extent.Text.StartsWith('$wslExe = if ($onWindows)') -and $s.Extent.Text -cne 'Test-Path -LiteralPath $wslExe') { $unguarded++ }
        } elseif ($f.Extent.Text.Contains('Assert-WslArguments $')) { $guarded[$f.Name] = $true } else { $unguarded++ }
    }
    Check 'W05 wsl.exe is started only by functions that check their arguments first' (
        $unguarded -eq 0 -and (@($guarded.Keys | Sort-Object) -join ',') -eq 'Invoke-WslExe,Start-Held,Start-KeepAlive' -and
        @([regex]::Matches($own, "'wsl\.exe'")).Count -eq 1)
    $lib = Join-Path $PSScriptRoot '..\m02\remote-lib.sh'
    $libText = if (Test-Path -LiteralPath $lib) { (Get-Content -LiteralPath $lib -Raw) -replace "`r`n", "`n" } else { '' }
    $mirrored = 0
    foreach ($fn in @('hm2_sanitize_env', 'hm2_sshd_bin', 'hm2_port', 'hm2_start_time', 'hm2_stop_recorded')) {
        $rx = "(?ms)^$fn\(\) \{\n.*?^\}\n"
        $a = [regex]::Match($libText, $rx); $b = [regex]::Match(($runnerOwn -replace "`r`n", "`n"), $rx)
        if ($a.Success -and $b.Success -and $a.Value -ceq $b.Value) { $mirrored++ }
    }
    Check 'M01 the runner script''s fallback copies of the standard harness''s helpers are that library''s text exactly' ($mirrored -eq 5)
    Check 'M02 a missing tool, a root default user and an unreadable binary are named as the blocked reason' (
        (Get-PreflightBlock @{ missing = 'sshd,python3' }).Contains('sshd,python3') -and (Get-PreflightBlock @{ missing = 'a b;c' }).Contains('a?b?c') -and
        (Get-PreflightBlock @{ blocked = 'root_account' }).Contains('root') -and (Get-PreflightBlock @{ blocked = 'linux_binaries_not_readable_from_the_distribution' }).Contains('not readable') -and
        (Get-PreflightBlock @{ blocked = 'x' }).Contains('no reason') -and (Get-PreflightBlock @{}).Contains('no reason') -and
        (Test-PlainWindowsPath 'C:\hm\l\heimdall') -and -not (Test-PlainWindowsPath 'C:\hm l\heimdall') -and -not (Test-PlainWindowsPath '\\srv\x\y') -and
        -not (Test-PlainWindowsPath 'C:heimdall') -and -not (Test-PlainWindowsPath '/mnt/c/x'))
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash -and $IsWindows -ne $true) {
        & $bash.Source -n $runner
        Check 'B01 the runner script parses (bash -n)' ($LASTEXITCODE -eq 0)
        $refused = @(
            @('prepare', 'relative/hm-m06j-x'), @('prepare', '/tmp/other'), @('cleanup', '/tmp/hm-m06j-a/../b'), @('cleanup', '/tmp/hm-m06j-a b'),
            @('nonsense', '/tmp/hm-m06j-selftest-absent'))
        $allRefused = $true
        foreach ($r in $refused) { & $bash.Source $runner @r 2>$null | Out-Null; if ($LASTEXITCODE -ne 2) { $allRefused = $false } }
        Check 'B02 the runner script refuses a root that is not an absolute hm-m06j-* path, and an unknown action (exit 2)' $allRefused
        $absent = (& $bash.Source $runner cleanup '/tmp/hm-m06j-selftest-absent' 2>$null) -join ','
        Check 'B03 cleanup of a root that does not exist removes nothing and says removed=yes' ($LASTEXITCODE -eq 0 -and $absent -eq 'removed=yes')
        $tools = @(& $bash.Source $runner tools '/tmp/hm-m06j-selftest-absent' 2>$null)
        $toolsRc = $LASTEXITCODE
        Check 'B04 the preflight changes nothing and says where the scratch directory would be, or names what is missing (exit 3)' (
            ($toolsRc -eq 0 -and @($tools | Where-Object { $_ -match '\Aroot=/.*/hm-m06j-selftest-absent\z' }).Count -eq 1) -or
            ($toolsRc -eq 3 -and @($tools | Where-Object { $_ -match '\A(missing|blocked)=' }).Count -eq 1))
        $gone = (& $bash.Source $runner verify '/tmp/hm-m06j-selftest-absent' 2>$null) -join ','
        Check 'B05 after a cleanup: the scratch directory gone and no process naming it' ($LASTEXITCODE -eq 0 -and $gone -eq 'scratch=gone,processes_left=0')
        $t = '/tmp/hm-m06j-st' + (New-RandomHex 4)
        [void](New-Item -ItemType Directory -Path $t)
        try {
            $kept = Join-Path $t 'hm-m06j-0123abcd'; [void](New-Item -ItemType Directory -Path $kept)
            [System.IO.File]::WriteAllText((Join-Path $kept 'theirs'), 'x'); [System.IO.File]::WriteAllText((Join-Path $t 'f'), 'x')
            $sum = (Get-FileHash -LiteralPath (Join-Path $t 'f') -Algorithm SHA256).Hash.ToLowerInvariant()
            & $bash.Source $runner prepare $kept (Join-Path $t 'f') $sum (Join-Path $t 'f') $sum 2>$null | Out-Null
            Check 'B06 a scratch directory that exists already is not this run''s: exit 4, and it is left as it was' (
                $LASTEXITCODE -eq 4 -and (Test-Path -LiteralPath (Join-Path $kept 'theirs')) -and @(Get-ChildItem -LiteralPath $kept -Force).Count -eq 1)
        } finally { Remove-Item -LiteralPath $t -Recurse -Force }
    } else {
        Write-Output 'skip B01-B06 (no bash on this host: the runner script is checked on the build host)'
    }
    Write-Output "$($script:count - $script:fail) passed, $($script:fail) failed"
}

if ($SelfTest) { Invoke-SelfTest; exit $(if ($script:fail -eq 0) { 0 } else { 1 }) }

# ---------------------------------------------------------------------------------------------
# Inputs. Nothing is created before every check passed.
# ---------------------------------------------------------------------------------------------

function Stop-Blocked([string]$Why) { Write-Output "blocked: $Why"; exit 3 }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$runnerScript = Join-Path $PSScriptRoot 'windows-controller-runner.sh'
$remoteLib = Join-Path $PSScriptRoot '..\m02\remote-lib.sh'
$onWindows = ($IsWindows -eq $true)
if (-not $Local -and -not $onWindows) { Stop-Blocked 'the journey runs on Windows (use -Local for the rehearsal, -SelfTest for the helpers)' }
if ($Local -and $onWindows) { Stop-Blocked '-Local is the build host rehearsal; on Windows run the journey itself' }
if (-not $ScratchRoot -or -not (Test-Path -LiteralPath $ScratchRoot -PathType Container)) { Stop-Blocked '-ScratchRoot is not an existing directory' }
$scratchItem = Get-Item -LiteralPath $ScratchRoot -Force
if ($scratchItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { Stop-Blocked '-ScratchRoot is a reparse point' }
if ($onWindows -and $env:LOCALAPPDATA -and $scratchItem.FullName.StartsWith((Join-Path $env:LOCALAPPDATA 'Heimdall'), [System.StringComparison]::OrdinalIgnoreCase)) {
    Stop-Blocked '-ScratchRoot is inside the product data directory'
}
$inputs = [ordered]@{ HeimdallExe = $HeimdallExe; DriverExe = $DriverExe; LinuxHeimdall = $LinuxHeimdall; LinuxDriver = $LinuxDriver }
foreach ($k in $inputs.Keys) {
    if (-not $inputs[$k] -or -not (Test-Path -LiteralPath $inputs[$k] -PathType Leaf)) { Stop-Blocked "-$k is not a file" }
}
# Absolute from here on: children run in the run directory.
$HeimdallExe = (Resolve-Path -LiteralPath $HeimdallExe).Path; $DriverExe = (Resolve-Path -LiteralPath $DriverExe).Path
$LinuxHeimdall = (Resolve-Path -LiteralPath $LinuxHeimdall).Path; $LinuxDriver = (Resolve-Path -LiteralPath $LinuxDriver).Path
$Out = [System.IO.Path]::GetFullPath($Out, (Get-Location).Path)
if (-not $Local) {
    if (-not $WslDistro) { Stop-Blocked '-WslDistro is required: the name of the EXISTING WSL distribution (this script never creates one)' }
    if (-not (Test-DistributionName $WslDistro)) { Stop-Blocked '-WslDistro is not a plain distribution name' }
    if (-not (Test-Path -LiteralPath $remoteLib -PathType Leaf)) { Stop-Blocked 'tests/native/m02/remote-lib.sh is not in this checkout' }
    if (-not (Test-PlainWindowsPath $LinuxHeimdall) -or -not (Test-PlainWindowsPath $LinuxDriver)) {
        Stop-Blocked '-LinuxHeimdall and -LinuxDriver must be at plain Windows paths (a drive, then letters, digits, . _ - only): the distribution is handed them as plain arguments'
    }
}
$sys32 = if ($onWindows) { Join-Path $env:SystemRoot 'System32' } else { '' }
$wslExe = if ($onWindows) { Join-Path $sys32 'wsl.exe' } else { '' }
$sshDir = if ($onWindows) { Join-Path $sys32 'OpenSSH' } else { '/usr/bin' }
$sshKeygen = Join-Path $sshDir $(if ($onWindows) { 'ssh-keygen.exe' } else { 'ssh-keygen' })
if (-not (Test-Path -LiteralPath $sshKeygen)) { Stop-Blocked 'the in-box OpenSSH client is not installed' }
if ($onWindows -and -not (Test-Path -LiteralPath $wslExe)) { Stop-Blocked 'wsl.exe is not installed' }
$linuxHeimdallSha = (Get-FileHash -LiteralPath $LinuxHeimdall -Algorithm SHA256).Hash.ToLowerInvariant()
$linuxDriverSha = (Get-FileHash -LiteralPath $LinuxDriver -Algorithm SHA256).Hash.ToLowerInvariant()

$hex = New-RandomHex 4
$name = "hm-m06j-$hex"
$steps = Get-JourneySteps
$run = Join-Path $scratchItem.FullName $name
$cHome = Join-Path $run 'home'; $cAcct = Join-Path $run 'acct'; $cSsh = Join-Path $cAcct '.ssh'; $facts = Join-Path $run 'facts'
# Where children start: the scratch root until the run directory exists.
$workDir = $scratchItem.FullName
$wslCommands = [System.Collections.Generic.List[string]]::new()
$held = @{}
$before = @(); $holder = $null; $controller = $null; $runnerRoot = ''; $runnerText = ''; $preflight = @{}

function Start-Redirected([string]$File, [string[]]$Arguments, [hashtable]$Environment) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($File)
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $workDir
    if ($null -ne $Environment) { $psi.Environment.Clear(); foreach ($k in $Environment.Keys) { $psi.Environment[$k] = [string]$Environment[$k] } }
    return [System.Diagnostics.Process]::Start($psi)
}

function Invoke-Bounded([string]$File, [string[]]$Arguments, [hashtable]$Environment, [int]$Seconds, [string]$StdIn = $null) {
    $p = Start-Redirected $File $Arguments $Environment
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    if ($StdIn) { $p.StandardInput.Write(($StdIn -replace "`r`n", "`n")) }
    $p.StandardInput.Close()
    $timedOut = -not $p.WaitForExit($Seconds * 1000)
    if ($timedOut) { $p.Kill($true) }
    $p.WaitForExit()
    $r = [pscustomobject]@{ Code = $(if ($timedOut) { 124 } else { $p.ExitCode }); Out = $o.Result; Err = $e.Result }
    $p.Dispose()
    return $r
}

# The environment of every process this run starts: nothing inherited but what the platform
# needs. No SSH_AUTH_SOCK, no agent, no HEIMDALL_* of the caller.
function New-BaseEnvironment {
    $e = @{}
    if ($onWindows) {
        foreach ($k in @('SystemRoot', 'windir', 'ComSpec', 'PATHEXT', 'LOCALAPPDATA', 'APPDATA', 'USERNAME', 'USERDOMAIN', 'COMPUTERNAME', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'ProgramData', 'SystemDrive')) {
            $v = [System.Environment]::GetEnvironmentVariable($k); if ($v) { $e[$k] = $v }
        }
        $e['PATH'] = "$sshDir;$sys32"
        $e['TEMP'] = $run; $e['TMP'] = $run
        $e['USERPROFILE'] = $cAcct
    } else {
        $e['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
    }
    $e['HOME'] = $cAcct
    return $e
}

# wsl.exe's own environment, as the standard harness starts it (tests/native/m02 and m04:
# New-ChildEnvironment @{ WSL_UTF8 = '1' }): the inherited one without agent, askpass, Git,
# Heimdall, harness and toolchain variables, and without WSLENV, so nothing of this session is
# handed into the distribution.
function New-WslEnvironment {
    $e = @{}
    foreach ($v in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$v.Key
        if ($k -match '^(GIT_|HEIMDALL_|HM_|SSH_AUTH_SOCK$|SSH_AGENT_PID$|SSH_ASKPASS|RUSTUP_|CARGO|WSLENV$)') { continue }
        $e[$k] = [string]$v.Value
    }
    $e['WSL_UTF8'] = '1'
    return $e
}

# The controller's product environment: scratch homes and the debug build's scratch SSH home and
# issuer store. K_mgmt is the product store (DPAPI under the scratch home) on Windows; the
# rehearsal uses the fixture file store, never the account's key store.
function New-ControllerEnvironment {
    $e = New-BaseEnvironment
    $e['HEIMDALL_HOME'] = $cHome
    $e['HEIMDALL_TEST_SSH_HOME'] = $cAcct
    $e['HEIMDALL_TEST_TIME_SYNC'] = 'synchronized'
    $e['HEIMDALL_TEST_SECRET_STORE'] = 'scratch'
    if ($Local) {
        # RULES "KEY STORES": off Windows BOTH fixture stores, for every controller command.
        $e['HEIMDALL_TEST_MGMT_STORE'] = 'fixture-file:' + (Join-Path $run 'k_mgmt.fixture')
        $e['HEIMDALL_TEST_IROH_KEY_STORE'] = (Join-Path $run 'k_iroh.fixture')
    }
    return $e
}

function Invoke-Controller([string[]]$Arguments, [int]$Seconds = 120) {
    $r = Invoke-Bounded $HeimdallExe (@('--json', '--home', $cHome) + $Arguments) (New-ControllerEnvironment) $Seconds
    return [pscustomobject]@{ Code = $r.Code; Envelope = (ConvertFrom-Envelope $r.Out) }
}

function Invoke-Driver([string]$Entry, [hashtable]$Inputs, [int]$Seconds = 600) {
    $out = Join-Path $facts "$Entry-$(New-RandomHex 2).facts"
    $e = New-BaseEnvironment
    foreach ($k in $Inputs.Keys) { $e[$k] = $Inputs[$k] }
    $e['HM_M06J_FACTS_OUT'] = $out
    $r = Invoke-Bounded $DriverExe @('--ignored', '--exact', $Entry) $e $Seconds
    if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $out)) { throw "driver_entry=$Entry exit=$($r.Code)" }
    return ConvertFrom-Facts (Get-Content -LiteralPath $out -Raw)
}

# Every wsl.exe start passes here first: only the three forms of the header, for -WslDistro.
function Assert-WslArguments([string[]]$Arguments) {
    if (-not (Test-AllowedWslArguments $Arguments $WslDistro)) { throw 'wsl_arguments=refused' }
    $form = Format-WslCommand $Arguments
    if (-not $wslCommands.Contains($form)) { $wslCommands.Add($form) }
}
function Invoke-WslExe([string[]]$Arguments, [int]$Seconds = 600, [string]$StdIn = $null) {
    Assert-WslArguments $Arguments
    return Invoke-Bounded $wslExe $Arguments (New-WslEnvironment) $Seconds $StdIn
}
# The registered distributions (read-only), or $null when the listing failed.
function Get-Registered {
    $r = Invoke-WslExe (Get-WslListArguments) 120
    if ($r.Code -ne 0) { return $null }
    return , @(ConvertFrom-WslList $r.Out)
}

# One action of the runner script, on the runner: its exit, facts and error text.
function Invoke-RunnerRaw([string]$Action, [string]$Root, [string[]]$Arguments, [int]$Seconds) {
    if ($Local) {
        $r = Invoke-Bounded '/bin/bash' (@($runnerScript, $Action, $Root) + @($Arguments)) (New-BaseEnvironment) $Seconds
    } else {
        $r = Invoke-WslExe (Get-WslRunnerArguments $WslDistro $Action $Root $Arguments) $Seconds $runnerText
    }
    return [pscustomobject]@{ Code = $r.Code; Facts = (ConvertFrom-Facts $r.Out); Err = [string]$r.Err }
}
# The same in this run's scratch directory: its facts, or a throw with the action and exit.
function Invoke-Runner([string]$Action, [string[]]$Arguments = @(), [int]$Seconds = 300, [switch]$AllowFailure) {
    $r = Invoke-RunnerRaw $Action $runnerRoot $Arguments $Seconds
    if ($r.Code -ne 0 -and -not $AllowFailure) { throw "runner_action=$Action exit=$($r.Code)" }
    return $r.Facts
}

# A runner action that SERVES (`sshd-serve`, `runtime-serve`): the process is started here and
# held for as long as what it started runs, as the standard harness holds its fixture sshds'
# session (tests/native/m02/run-windows-local.ps1, step 4). Its facts are read up to `ready=1`.
function Start-Held([string]$Action, [string[]]$Arguments = @(), [int]$Seconds = 90) {
    if ($Local) {
        $p = Start-Redirected '/bin/bash' (@($runnerScript, $Action, $runnerRoot) + @($Arguments)) (New-BaseEnvironment)
        $in = ''
    } else {
        $a = Get-WslRunnerArguments $WslDistro $Action $runnerRoot $Arguments
        Assert-WslArguments $a
        $p = Start-Redirected $wslExe $a (New-WslEnvironment)
        $in = $runnerText
    }
    # stderr is drained so a chatty child never blocks on a full pipe; nothing of it is kept.
    [void]$p.StandardError.ReadToEndAsync()
    if ($in) { $p.StandardInput.Write(($in -replace "`r`n", "`n")) }
    $p.StandardInput.Close()
    $f = @{}; $pending = $null; $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $until -and -not $f.ContainsKey('ready')) {
        # One outstanding read at a time: a read that is still pending is waited on again.
        if ($null -eq $pending) { $pending = $p.StandardOutput.ReadLineAsync() }
        if (-not $pending.Wait(1000)) { continue }
        $line = $pending.Result; $pending = $null
        if ($null -eq $line) { break }
        $i = $line.IndexOf('=')
        if ($i -gt 0 -and -not $f.ContainsKey($line.Substring(0, $i))) { $f[$line.Substring(0, $i)] = $line.Substring($i + 1).Trim() }
    }
    if (-not $f.ContainsKey('ready')) {
        try { if (-not $p.HasExited) { $p.Kill($true) }; [void]$p.WaitForExit(10000) } catch { }
        $code = if ($p.HasExited) { $p.ExitCode } else { 124 }
        $p.Dispose()
        throw "runner_action=$Action exit=$code"
    }
    return [pscustomobject]@{ Process = $p; Facts = $f }
}
function Start-Serving([string]$Name, [string]$Action, [string[]]$Arguments = @()) {
    if ($held.ContainsKey($Name)) { throw "held_session_$Name=already_started" }
    $h = Start-Held $Action $Arguments
    $held[$Name] = $h.Process
    return $h.Facts
}
# After the runner-side stop the held process ends by itself; otherwise it is ended through its
# own handle. Returns whether it ended by itself.
function Wait-Served([string]$Name, [int]$Seconds = 30) {
    if (-not $held.ContainsKey($Name)) { return $true }
    $p = $held[$Name]; $held.Remove($Name)
    $own = $p.WaitForExit($Seconds * 1000)
    if (-not $own) { try { $p.Kill($true); [void]$p.WaitForExit(10000) } catch { } }
    $p.Dispose()
    return $own
}
function Start-FixtureSshd([string]$Which) { return [string](Start-Serving "sshd-$Which" 'sshd-serve' @($Which))['port'] }
function Stop-FixtureSshd([string]$Which) {
    $s = [string](Invoke-Runner 'sshd-stop' @($Which) 120 -AllowFailure)['stopped']
    if (-not (Wait-Served "sshd-$Which")) { return 'session-ended-by-handle' }
    return $s
}

# The keep-alive: one wsl.exe running `sleep infinity` in the distribution, held here and ended
# only through this handle.
function Start-KeepAlive {
    $a = Get-WslKeepAliveArguments $WslDistro
    Assert-WslArguments $a
    $p = Start-Redirected $wslExe $a (New-WslEnvironment)
    [void]$p.StandardOutput.ReadToEndAsync(); [void]$p.StandardError.ReadToEndAsync()
    $p.StandardInput.Close()
    return $p
}

function Test-SshBanner([int]$Port) {
    $c = [System.Net.Sockets.TcpClient]::new()
    try {
        if (-not $c.ConnectAsync('127.0.0.1', $Port).Wait(3000)) { return $false }
        $c.ReceiveTimeout = 3000
        $buf = [byte[]]::new(8); $n = $c.GetStream().Read($buf, 0, 8)
        return [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).StartsWith('SSH-2.0-')
    } catch { return $false } finally { $c.Dispose() }
}
function Wait-Reachable([int]$Port, [int]$Seconds) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ($true) {
        if (Test-SshBanner $Port) { return $true }
        if ([DateTime]::UtcNow -ge $until) { return $false }
        Start-Sleep -Milliseconds 2000
    }
}

function Start-Controller {
    $p = Start-Redirected $HeimdallExe @('--home', $cHome, 'service', 'run') (New-ControllerEnvironment)
    $p.StandardInput.Close()
    # Its output is drained and dropped (it may hold paths); nothing of it is kept.
    [void]$p.StandardOutput.ReadToEndAsync(); [void]$p.StandardError.ReadToEndAsync()
    $script:controller = $p
    $until = [DateTime]::UtcNow.AddSeconds(60)
    while ([DateTime]::UtcNow -lt $until) {
        if ((Invoke-Controller @('service', 'status') 30).Code -eq 0) { return }
        if ($p.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }
    throw 'controller_runtime=not_started'
}

# Stop the controller runtime this run started: `service stop` on its own scratch home, then its
# own process handle must report the exit. Returns whether it is gone.
function Stop-Controller {
    if ($null -eq $script:controller) { return $true }
    [void](Invoke-Controller @('service', 'stop') 60)
    $gone = $script:controller.WaitForExit(30000)
    if (-not $gone) { $script:controller.Kill($true); $gone = $script:controller.WaitForExit(10000) }
    $script:controller.Dispose(); $script:controller = $null
    return $gone
}

function Get-ChildPids([int]$Parent) {
    if ($onWindows) { return @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$Parent" | ForEach-Object { [int]$_.ProcessId }) }
    $r = Invoke-Bounded '/bin/ps' @('-A', '-o', 'pid=', '-o', 'ppid=') (New-BaseEnvironment) 30
    return @($r.Out -split "`n" | ForEach-Object { $w = @($_.Trim() -split '\s+'); if ($w.Count -eq 2 -and $w[1] -eq [string]$Parent) { [int]$w[0] } })
}
function Test-Alive([int]$ProcessId) { return ($null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) }

function Get-Status([string]$Environment) { return Select-Environment (Invoke-Controller @('environment', 'status') 60).Envelope $Environment }
# Wait until the controller's record of the runner has Path = Want; the last value otherwise.
function Wait-Status([string]$Environment, [string]$Path, [string]$Want, [int]$Seconds = 60) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds); $last = ''
    while ($true) {
        $last = Get-Field (Get-Status $Environment) $Path
        if ($last -ceq $Want) { return }
        if ([DateTime]::UtcNow -ge $until) { throw "status_$($Path -replace '\.', '_')=$last wanted=$Want" }
        Start-Sleep -Milliseconds 300
    }
}

# The controller owner's forwarded request to its settled answer (a pending ACCEPTED is followed
# with `operation wait`, as the single-host suite does).
function Invoke-ForwardedEnsure([string]$Environment, [string]$Work, [string]$Request, [string]$Lifetime) {
    $a = (Invoke-Controller @('access', 'ensure', '--profile', 'runner-profile', '--environment', $Environment, '--work-id', $Work, '--for', $Lifetime, '--request-id', $Request) 120).Envelope
    if ((Get-Field $a 'code') -ceq 'ACCEPTED') {
        $op = Get-Field $a 'operation_id'
        if (-not $op) { throw 'forwarded_ensure=ACCEPTED operation=none' }
        $a = (Invoke-Controller @('operation', 'wait', $op, '--timeout-ms', '60000') 120).Envelope
    }
    return $a
}

function Assert-Equal([string]$What, [string]$Got, [string]$Want) { if ($Got -cne $Want) { throw "$What=$Got wanted=$Want" } }

# ---------------------------------------------------------------------------------------------
# The distribution: registered already, and able to hold the fixture. Nothing is created here.
# ---------------------------------------------------------------------------------------------

if (-not $Local) {
    $before = Get-Registered
    if ($null -eq $before) { Stop-Blocked 'wsl.exe --list --quiet failed: WSL is not available to this account' }
    if (@($before) -cnotcontains $WslDistro) { Stop-Blocked "the WSL distribution '$WslDistro' is not registered (this script uses an existing one and never creates one)" }
}
if ($DryRun) {
    Write-Output "plan: run directory <ScratchRoot>/$name; $(if ($Local) { 'no distribution (rehearsal)' } else { "the existing distribution '$WslDistro' (registered; never created, stopped or removed): one scratch directory <its user's home>/$name, kept alive by one held wsl.exe running sleep" })"
    if (-not $Local) {
        foreach ($c in @((Format-WslCommand (Get-WslListArguments)), (Format-WslCommand (Get-WslRunnerArguments $WslDistro '<action>' '/x' @('x'))), (Format-WslCommand (Get-WslKeepAliveArguments $WslDistro)))) { Write-Output "plan: $c" }
    }
    foreach ($s in $steps) { Write-Output "plan: step $($s.Test) -> m06 observation: $($s.Case) $($s.Step)" }
    exit 0
}
if (-not $Local) {
    # The standard harness's library first, then the runner script: one stdin script per action.
    $runnerText = ((Get-Content -LiteralPath $remoteLib -Raw) + "`n" + (Get-Content -LiteralPath $runnerScript -Raw)) -replace "`r`n", "`n"
    $pf = Invoke-RunnerRaw 'tools' "/tmp/$name" @($LinuxHeimdall, $LinuxDriver) 180
    if ($pf.Code -eq 3) { Stop-Blocked (Get-PreflightBlock $pf.Facts) }
    if ($pf.Code -ne 0) { Stop-Blocked "the preflight inside the distribution did not run (exit $($pf.Code)): is /bin/bash there?" }
    $preflight = $pf.Facts
    if (-not (Test-RunnerRoot ([string]$preflight['root']) $name)) { Stop-Blocked 'the distribution did not name a plain scratch directory under its user''s home' }
    if (-not $preflight['heimdall'] -or -not $preflight['driver']) { Stop-Blocked 'the distribution did not name the Linux binaries' }
}

# ---------------------------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------------------------

[void][System.IO.Directory]::CreateDirectory($scratchItem.FullName)
if (Test-Path -LiteralPath $run) { Stop-Blocked 'the run directory exists' }
[void](New-Item -ItemType Directory -Path $run)
$workDir = $run
foreach ($d in @($cHome, $cAcct, $cSsh, $facts)) { [void](New-Item -ItemType Directory -Path $d) }
if (-not $onWindows) { & chmod 700 $run $cAcct $cSsh }
if ($Local) {
    # The rehearsal's fixture K_iroh store: an existing owner-only directory (RULES "KEY STORES").
    $kIroh = Join-Path $run 'k_iroh.fixture'
    [void](New-Item -ItemType Directory -Path $kIroh)
    if (-not $onWindows) { & chmod 700 $kIroh }
}
$hostFacts = [System.Text.StringBuilder]::new()
function Add-Fact([string]$Key, [string]$Value) { [void]$hostFacts.Append("$Key=$(($Value -replace "`r", '') -split "`n" | Select-Object -First 1)`n") }
$results = [System.Collections.Generic.List[object]]::new()
$cleanupOk = $true; $blockedWhy = ''; $rootMayExist = $false

$journey = @{ Environment = ''; Grant = ''; Endpoint = ''; Endpoint2 = ''; Ca = ''; Runner = @{} }
$mode = if ($Local) { 'rehearsal' } else { 'windows' }

$stepBodies = @{
    'a24_pair' = {
        $r = $journey.Runner
        $seeded = Invoke-Driver 'seed_controller' @{
            HM_M06J_HOME = $cHome; HM_M06J_ACCOUNT = $r['account']; HM_M06J_ALIAS = $Alias; HM_M06J_MGMT_HOST = '127.0.0.1'
            HM_M06J_MGMT_PORT = $r['mgmt_port']; HM_M06J_MGMT_HOST_KEY = $r['mgmt_host_key']
        }
        $journey.Ca = $seeded['ca_fingerprint']
        # The CA line as two plain arguments (its type and its body), then the principal.
        [void](Invoke-Runner 'trust-ca' (@($seeded['ca_public_key'] -split ' ')[0..1] + @($seeded['principal'])))
        $add = @{
            HM_M06J_BIN = $HeimdallExe; HM_M06J_HOME = $cHome; HM_M06J_ACCOUNT_HOME = $cAcct; HM_M06J_ACCOUNT = $r['account']
            HM_M06J_RUNNER_PROGRAM = $r['runner_program']; HM_M06J_RUNNER_HOME = $r['runner_home']; HM_M06J_RUNNER_SHA256 = $r['runner_sha256']
            HM_M06J_PATH = (New-BaseEnvironment)['PATH']
        }
        if ($Local) {
            $add['HM_M06J_MGMT_FIXTURE'] = (Join-Path $run 'k_mgmt.fixture')
            $add['HM_M06J_IROH_FIXTURE'] = (Join-Path $run 'k_iroh.fixture')
        }
        # The bootstrap offers to start the runner's runtime in its attended session (ADR-0012
        # 2.6). The journey DECLINES it, as a stated step: its fixture runner is seeded while no
        # runtime runs, and its runtime needs the fixture's own test configuration.
        $add['HM_M06J_RUNTIME_OFFER'] = 'no'
        # The bootstrap session, confirmed at the runner. The runner's runtime does not run yet
        # (the runner exists only once `remote init` made it): the session says so and offers to
        # start it; the journey declines. The controller then cannot open its management session,
        # records nothing, and its refusal names the next step. Nothing here is silent.
        $first = Invoke-Driver 'environment_add' $add
        Assert-Result 'first_pass_prompted' $first['prompted'] 'true' $first
        Assert-Equal 'first_pass_runtime_offer' $first['runtime_offer'] 'declined'
        Assert-Equal 'first_pass_runtime_stated' $first['runtime_stated'] 'not_started'
        Assert-Equal 'first_pass_code' $first['code'] 'DESTINATION_UNREACHABLE'
        if ($first['message'] -cnotmatch 'nothing was recorded on this controller' -or $first['message'] -cnotmatch 'run `environment add` again') {
            throw 'first_pass_next_step=not_named'
        }
        # The named next step: the runner's runtime is started on the runner (after the fixture's
        # seed), then `environment add` again, which repairs after the same confirmation. The
        # runtime runs now, so the session says so and offers nothing.
        [void](Invoke-Runner 'seed')
        Assert-Equal 'runner_runtime' ([string](Start-Serving 'runtime' 'runtime-serve')['runtime']) 'running'
        $second = Invoke-Driver 'environment_add' $add
        Assert-Result 'pair_prompted' $second['prompted'] 'true' $second
        Assert-Equal 'pair_runtime_offer' $second['runtime_offer'] 'not_offered'
        Assert-Equal 'pair_runtime_stated' $second['runtime_stated'] 'running'
        Assert-Result 'pair_code' $second['code'] 'OK' $second
        if ($second['environment'] -cnotmatch '\Aenv_[0-9a-f]+\z') { throw 'pair_environment=none' }
        $journey.Environment = $second['environment']
        $status = Get-Status $journey.Environment
        if ($null -eq $status) { throw 'controller_record=absent' }
        $store = if ($Local) { 'fixture_file' } else {
            $blobs = @(Get-ChildItem -LiteralPath (Join-Path $cHome 'state\mgmt') -Recurse -File -ErrorAction SilentlyContinue)
            if ($blobs.Count -lt 1) { throw 'k_mgmt_dpapi_blob=absent' }
            'dpapi_under_scratch_home'
        }
        Start-Controller
        return "controller=environment_add_on_terminal runner=remote_init_confirmed_on_terminal owner_enrolled=true issuer_trusted=true " +
        "controller_record=written_by_environment_add runtime_offer=declined_next_step_named first_pass=$($first['code']) " +
        "runner_runtime=started_on_the_runner repair=runtime_stated_running k_mgmt_store=$store " +
        "session_agent=$(if ($Local) { 'unix_socket' } else { 'named_pipe' }) run=$mode"
    }
    'a24_approve' = {
        $a = Invoke-ForwardedEnsure $journey.Environment 'job-w-a07' 'w-fwd-1' '1h'
        Assert-Result 'code' (Get-Field $a 'code') 'OK' $a
        Assert-Equal 'environment' (Get-Field $a 'data.environment_id') $journey.Environment
        Assert-Equal 'mechanism' (Get-Field $a 'data.credential_mechanism') 'managed_certificate'
        Assert-Equal 'refresh_dependency' (Get-Field $a 'data.refresh_dependency') 'controller'
        $journey.Grant = Get-Field $a 'data.grant_id'
        if (-not $journey.Grant) { throw 'grant=none' }
        return 'admitted_by=runner_standing_policy mechanism=managed_certificate issued_by=controller_issuer_child'
    }
    'a07_issued' = {
        $e = Invoke-Runner 'ensure' @('job-w-local-1', 'w-local-1', '30s')
        if (@('OK', 'ACCESS_READY') -cnotcontains $e['code']) { throw "runner_ensure=$($e['code'])" }
        Assert-Equal 'runner_grant_is_the_forwarded_grant' ([string]($e['grant'] -ceq $journey.Grant)).ToLowerInvariant() 'true'
        $journey.Endpoint = $e['endpoint']
        $i = Invoke-Runner 'identities' @($journey.Endpoint)
        Assert-Equal 'identities' $i['identities'] '1'
        Assert-Equal 'certificate_signed_by_controller_ca' ([string]($i['certificate_ca'] -ceq $journey.Ca)).ToLowerInvariant() 'true'
        Assert-Equal 'onward' (Invoke-Runner 'onward' @($journey.Endpoint))['onward'] 'ok'
        Wait-Status $journey.Environment 'connectivity.state' 'connected'
        return 'grant=issued onward_login=ok'
    }
    'a07_disconnected' = {
        Assert-Equal 'mgmt_sshd' (Stop-FixtureSshd 'mgmt') 'stopped'
        if (-not (Stop-Controller)) { throw 'controller_runtime=still_running' }
        Start-Controller
        Wait-Status $journey.Environment 'issuance' 'awaiting_resync'
        if ((Get-Field (Get-Status $journey.Environment) 'connectivity.state') -ceq 'connected') { throw 'connectivity=connected' }
        return 'connectivity=not_connected issuance=awaiting_resync'
    }
    'a07_revoke_pending' = {
        $r = (Invoke-Controller @('access', 'revoke', $journey.Grant) 60).Envelope
        Assert-Result 'code' (Get-Field $r 'code') 'OK' $r
        Assert-Equal 'local_applied' (Get-Field $r 'data.local_applied') 'false'
        Assert-Equal 'remote_pending_names_the_grant' ([string]((Get-Field $r 'data.remote_pending.0') -ceq $journey.Grant)).ToLowerInvariant() 'true'
        $s = Get-Status $journey.Environment
        Assert-Equal 'pending_target' (Get-Field $s 'remote_pending.0.target.kind') 'grant_revoke'
        Assert-Equal 'pending_count' (Get-Field $s 'remote_pending.1.target.kind') ''
        Assert-Equal 'residual_acknowledged' (Get-Field $s 'residuals.0.acknowledged') 'false'
        if (-not (Get-Field $s 'residuals.0.statement')) { throw 'residual_statement=none' }
        # Not applied on the runner yet: it still serves the grant.
        Assert-Equal 'identities_while_pending' (Invoke-Runner 'identities' @($journey.Endpoint))['identities'] '1'
        Assert-Equal 'onward_while_pending' (Invoke-Runner 'onward' @($journey.Endpoint))['onward'] 'ok'
        return 'local_applied=false remote_pending=1 target=grant_revoke residual=stated acknowledged=false'
    }
    'a07_reconnect' = {
        $port = Start-FixtureSshd 'mgmt'
        Assert-Equal 'mgmt_port_kept' $port $journey.Runner['mgmt_port']
        if (-not (Wait-Reachable ([int]$port) 90)) { throw 'mgmt_sshd=unreachable_from_controller' }
        [void](Invoke-ForwardedEnsure $journey.Environment 'job-w-a07-b' 'w-fwd-2' '1h')
        Wait-Status $journey.Environment 'remote_pending' '[]'
        Wait-Status $journey.Environment 'residuals.0.acknowledged' 'true'
        Assert-Equal 'identities' (Invoke-Runner 'identities' @($journey.Endpoint))['identities'] '0'
        Assert-Equal 'onward' (Invoke-Runner 'onward' @($journey.Endpoint))['onward'] 'refused'
        return 'remote_pending=0 residual_acknowledged=true runner_endpoint_identities=0 onward_login=refused'
    }
    'a07_barrier' = {
        Wait-Status $journey.Environment 'issuance' 'reconciled'
        Assert-Equal 'connectivity' (Get-Field (Get-Status $journey.Environment) 'connectivity.state') 'connected'
        return 'while_disconnected=awaiting_resync after_resync=reconciled'
    }
    'a24_controller_leaves' = {
        # A grant for the work that outlives the controller, in use on the runner before it leaves.
        $a = Invoke-ForwardedEnsure $journey.Environment 'job-w-a24' 'w-fwd-3' '1h'
        Assert-Result 'code' (Get-Field $a 'code') 'OK' $a
        $e = Invoke-Runner 'ensure' @('job-w-local-2', 'w-local-2', '30s')
        if (@('OK', 'ACCESS_READY') -cnotcontains $e['code']) { throw "runner_ensure=$($e['code'])" }
        $journey.Endpoint2 = $e['endpoint']
        Assert-Equal 'identities' (Invoke-Runner 'identities' @($journey.Endpoint2))['identities'] '1'
        $pid0 = $script:controller.Id
        $children = @(Get-ChildPids $pid0)
        if ($children.Count -lt 1) { throw 'issuer_child=absent' }
        if (-not (Stop-Controller)) { throw 'controller_runtime=still_running' }
        $until = [DateTime]::UtcNow.AddSeconds(30)
        while (@($children | Where-Object { Test-Alive $_ }).Count -gt 0) {
            if ([DateTime]::UtcNow -ge $until) { throw 'issuer_child=still_running' }
            Start-Sleep -Milliseconds 200
        }
        Assert-Equal 'mgmt_sshd' (Stop-FixtureSshd 'mgmt') 'stopped'
        return 'controller_runtime=stopped issuer_child=stopped management_route=blocked'
    }
    'a24_onward_managed' = {
        $i = Invoke-Runner 'identities' @($journey.Endpoint2)
        Assert-Equal 'identities' $i['identities'] '1'
        Assert-Equal 'certificate_signed_by_controller_ca' ([string]($i['certificate_ca'] -ceq $journey.Ca)).ToLowerInvariant() 'true'
        Assert-Equal 'onward' (Invoke-Runner 'onward' @($journey.Endpoint2))['onward'] 'ok'
        return 'login=ok credential=runner_k_env_certificate signed_by=controller_ca controller=stopped route=blocked'
    }
    'a24_no_controller_socket' = {
        # `identities` refuses an endpoint outside the runner's own home, so this also places it.
        Assert-Equal 'identities' (Invoke-Runner 'identities' @($journey.Endpoint2))['identities'] '1'
        $p = Invoke-Runner 'processes'
        Assert-Equal 'runtime_parent_is_sshd' $p['runtime_parent_is_sshd'] 'false'
        if ($p['runtime_has_ssh_auth_sock'] -ceq 'true') { throw 'runtime_has_ssh_auth_sock=true' }
        return "endpoint=under_runner_home identities=1 identity=runner_k_env_certificate runner_started_with_ssh_auth_sock=$($p['runtime_has_ssh_auth_sock'])"
    }
}

try {
    Add-Fact 'mode' $mode
    Add-Fact 'pwsh' $PSVersionTable.PSVersion.ToString()
    # --- the runner's host -------------------------------------------------------------------
    if ($Local) {
        $runnerRoot = Join-Path $run "hm-m06j-r$hex"
        $stage = @{ Heimdall = $LinuxHeimdall; Driver = $LinuxDriver }
        $t = Invoke-RunnerRaw 'tools' $runnerRoot @() 120
        if ($t.Code -eq 3) { $blockedWhy = Get-PreflightBlock $t.Facts; throw 'runner_tools=blocked' }
        if ($t.Code -ne 0) { throw "runner_action=tools exit=$($t.Code)" }
    } else {
        $runnerRoot = [string]$preflight['root']
        $stage = @{ Heimdall = [string]$preflight['heimdall']; Driver = [string]$preflight['driver'] }
        Add-Fact 'wsl-distribution' 'existing: the one -WslDistro names, registered before the run; never created, stopped or removed by this script'
        Add-Fact 'wsl-account' 'the distribution''s default user (not root); nothing installed, no service enabled'
        Add-Fact 'wsl-scratch' 'one directory under that user''s home, created exclusively and removed by this run'
        Add-Fact 'ssh-V-wsl' ([string]$preflight['ssh'])
        Add-Fact 'sshd-V-wsl' ([string]$preflight['sshd'])
        $v = Invoke-Bounded (Join-Path $sshDir 'ssh.exe') @('-V') (New-BaseEnvironment) 30
        Add-Fact 'ssh-V' (($v.Out + $v.Err).Trim())
    }
    # From here the scratch directory may exist and be this run's: the cleanup removes it. An
    # existing one (exit 4) is not this run's and is never touched.
    $rootMayExist = $true
    $p = Invoke-RunnerRaw 'prepare' $runnerRoot @($stage.Heimdall, $linuxHeimdallSha, $stage.Driver, $linuxDriverSha) 300
    if ($p.Code -eq 4) { $rootMayExist = $false; throw 'runner_scratch=exists_already' }
    if ($p.Code -eq 3) { $blockedWhy = "the fixture cannot be prepared on the runner side: $(Protect-Reason $p.Err.Trim())"; throw 'runner_prepare=blocked' }
    if ($p.Code -ne 0) { throw "runner_action=prepare exit=$($p.Code)" }
    $prepared = $p.Facts
    foreach ($k in @('account', 'runner_program', 'runner_home', 'runner_sha256', 'mgmt_host_key', 'dest_host_key')) { if (-not $prepared[$k]) { throw "runner_fact_$k=none" } }
    $journey.Runner = $prepared
    if (-not $Local) {
        # The keep-alive (step 4 of the description): held until the cleanup. Its Linux process
        # is the one new `sleep infinity` of this account, recorded in the scratch directory.
        [void](Invoke-Runner 'keepalive-before' @() 60)
        $holder = Start-KeepAlive
        $ka = [string](Invoke-Runner 'keepalive-record' @() 60)['keepalive']
        Add-Fact 'distribution-keep-alive' "one held wsl.exe running /bin/sleep infinity in the distribution, ended through its own handle in the cleanup (its Linux process: $ka)"
        if ($holder.HasExited) { throw 'keep_alive=exited' }
    }
    # --- the controller's existing access: a per-run fixture key, in the scratch account home ---
    $key = Join-Path $cSsh 'id_fixture'
    $r = Invoke-Bounded $sshKeygen @('-q', '-t', 'ed25519', '-N', '', '-C', 'hm-m06j-access', '-f', $key) (New-BaseEnvironment) 60
    if ($r.Code -ne 0) { throw 'ssh_keygen=failed' }
    # The key line as two plain arguments (its type and its body): nothing sent needs quoting.
    [void](Invoke-Runner 'authorize' @(@((Get-Content -LiteralPath "$key.pub" -Raw).Trim() -split '\s+')[0..1]))
    $journey.Runner['mgmt_port'] = Start-FixtureSshd 'mgmt'
    $journey.Runner['dest_port'] = Start-FixtureSshd 'dest'
    if ($journey.Runner['mgmt_port'] -cnotmatch '\A[0-9]{4,5}\z') { throw 'mgmt_port=none' }
    [System.IO.File]::WriteAllText((Join-Path $cSsh 'config'), (Format-SshConfig $journey.Runner['mgmt_port'] $key))
    if (-not $onWindows) { & chmod 600 (Join-Path $cSsh 'config') }
    $reachable = Wait-Reachable ([int]$journey.Runner['mgmt_port']) 90
    Add-Fact 'fixture-sshd' 'two, each the child of a held session: unprivileged, 127.0.0.1 only, free high ports chosen at run time, per-run host keys'
    Add-Fact 'fixture-sshd-reachable-on-loopback' ([string]$reachable).ToLowerInvariant()
    if (-not $reachable) { throw 'mgmt_sshd=unreachable_from_controller' }

    # --- the journey --------------------------------------------------------------------------
    foreach ($s in $steps) {
        $entry = @{ Test = $s.Test; Case = $s.Case; Step = $s.Step; Ok = $false; Observation = ''; Reason = '' }
        try {
            $entry.Observation = [string](& $stepBodies[$s.Test])
            $entry.Ok = $true
        } catch {
            $entry.Reason = $_.Exception.Message
        }
        $results.Add($entry)
        if ($entry.Ok) { Write-Output "m06 observation: $($s.Case) $($s.Step): $($entry.Observation)" }
        else { Write-Output "FAILED $($s.Test): $(Protect-Reason $entry.Reason)"; break }
    }
} catch {
    Add-Fact 'setup-failed' (Protect-Reason $_.Exception.Message)
    Write-Output "setup failed: $(Protect-Reason $_.Exception.Message)"
} finally {
    # --- always: stop and remove exactly what this run started --------------------------------
    try { if (-not (Stop-Controller)) { $cleanupOk = $false } } catch { $cleanupOk = $false }
    # The keep-alive first, through its own handle: the runner-side cleanup then waits for its
    # Linux process to be gone (the held sessions below keep the distribution up meanwhile).
    if ($null -ne $holder) {
        try { if (-not $holder.HasExited) { $holder.Kill($true); [void]$holder.WaitForExit(10000) } } catch { $cleanupOk = $false }
        $holder.Dispose(); $holder = $null
    }
    $keepAliveAtEnd = 'none'; $scratchAtEnd = 'not-created'; $leftAtEnd = '0'; $sessions = 'none'
    if ($runnerRoot -and $rootMayExist) {
        # The runner script stops exactly its recorded processes (each PID's start time and
        # identity checked before a signal) and removes exactly its scratch directory.
        try {
            $c = Invoke-Runner 'cleanup' @() 300 -AllowFailure
            if ($c['removed'] -cne 'yes') { $cleanupOk = $false }
            if ($c.ContainsKey('keepalive')) { $keepAliveAtEnd = [string]$c['keepalive'] }
            if (@('none', 'gone', 'stopped') -cnotcontains $keepAliveAtEnd) { $cleanupOk = $false }
        } catch { $cleanupOk = $false }
    }
    # The held sessions end by themselves once what they served is stopped; a handle otherwise.
    foreach ($n in @($held.Keys)) { $sessions = if ((Wait-Served $n 20) -and $sessions -cne 'ended-by-handle') { 'ended-by-themselves' } else { 'ended-by-handle' } }
    if ($runnerRoot -and $rootMayExist) {
        try {
            $v = Invoke-Runner 'verify' @() 120 -AllowFailure
            $scratchAtEnd = [string]$v['scratch']; $leftAtEnd = [string]$v['processes_left']
            if ($scratchAtEnd -cne 'gone' -or $leftAtEnd -cne '0') { $cleanupOk = $false }
        } catch { $cleanupOk = $false }
    }
    Add-Fact 'runner-held-sessions-at-end' $sessions
    Add-Fact 'runner-scratch-at-end' $scratchAtEnd
    Add-Fact 'runner-processes-left' $leftAtEnd
    if (-not $Local) {
        Add-Fact 'keep-alive-linux-process-at-end' $keepAliveAtEnd
        $same = $false
        try { $after = Get-Registered; $same = ($null -ne $after) -and (Test-SameSet @($before) @($after)) } catch { $same = $false }
        Add-Fact 'distributions-after-equal-before' ([string]$same).ToLowerInvariant()
        if (-not $same) { $cleanupOk = $false }
        $i = 0
        foreach ($c in $wslCommands) { $i++; Add-Fact ('wsl-command-{0:d2}' -f $i) $c }
    }
    Add-Fact 'cleanup' $(if ($cleanupOk) { 'clean' } else { 'incomplete' })
    $code = Get-RunExit @($results) $steps.Count $cleanupOk
    $blocked = ($blockedWhy -and $results.Count -eq 0)
    if ($blocked -and $cleanupOk) { $code = 3 }
    if (-not $blocked) {
        [void](New-Item -ItemType Directory -Path $Out -Force)
        [System.IO.File]::WriteAllText((Join-Path $Out 'tests.txt'), (Format-JourneyLog @($results) $code @($steps | ForEach-Object { $_.Test })))
        [System.IO.File]::WriteAllText((Join-Path $Out 'host.txt'), $hostFacts.ToString())
    }
    $workDir = $scratchItem.FullName
    try { Remove-Item -LiteralPath $run -Recurse -Force -ErrorAction Stop } catch { Write-Output 'the run directory could not be removed'; $code = 1 }
    if ($blocked) { Write-Output "blocked: $blockedWhy$(if ($cleanupOk) { '' } else { ' (and the cleanup is incomplete)' })" }
    Write-Output "### $Target exit=$code ($(@($results | Where-Object { $_.Ok }).Count) of $($steps.Count) steps passed; cleanup $(if ($cleanupOk) { 'clean' } else { 'incomplete' }))"
}
exit $code
