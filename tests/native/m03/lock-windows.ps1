#Requires -Version 7.2
<#
.SYNOPSIS
M03-U13: the Windows lock procedure (m03-plan §4.4; ADR-0004 §2 lock rule; ADR-0005 §9.3 P-W1).

.DESCRIPTION
Runs ON the Windows PC, at Medium integrity, launched by an agent in the owner's interactive
session. The agent may lock the PC itself only after the console has been idle for at least 15
minutes; the owner unlocks whenever they return. This harness enforces that and decides nothing
about the product: the A03 checks are the lock driver's (`e2e_exit_m03`'s `lock::` tests,
tests/e2e/exit_m03/lock.rs), started ONCE as one process and driven through handshake files in
its state directory: the driver writes `ready` (or `prepare-failed`, `blocked: …` or
`failed: …`); this harness writes `locked` after verifying the lock (or `abort` with a reason);
the driver writes `locked-done`; this harness waits for the unlock and writes `expect` then
`unlocked`; the driver runs its post-unlock step and its cleanup and ends.

Steps:
  1. The product binary must be a release-profile build (F03): asked for its lock state with a
     test variable set, a release build refuses (exit 2, release_build_refuses_m03_test_gates);
     a build that answers is refused here (exit 2, nothing run).
  2. Idle: GetLastInputInfo (user32, through Add-Type in this process). Below 900 s: exit 3,
     blocked (console_not_idle), nothing prepared or locked.
  3. The product's query `heimdall internal session-lock-state` (WTS source) reads `unlocked`.
  4. Three fixture sshds in WSL scratch on 127.0.0.1 (non-root, per-run host keys, each with its
     own authorized-keys file and log in the Windows scratch and its own owner-only enrollment
     registry in WSL scratch; tests/native/m02/remote-lib.sh hm2_sshd_start), passed to the driver
     as HM_LOCK_SSHD_<1..3>_{PORT,HOST_KEY,AUTHORIZED_KEYS,LOG,REGISTRY,REGISTRY_REMOTE,USER}.
  5. The driver starts with HEIMDALL_E2E_BIN = the release product binary (no HEIMDALL_TEST_*
     variable at all; its Heimdall home is a scratch directory under this run's TEMP) and
     prepares unlocked; the issuer uses the product DPAPI store kind there. The driver writes
     the store kind `issuer status` reports; anything but windows_dpapi ends the run (`abort`,
     exit 1): only a release-profile, product-store row is claim-eligible. A preparation the
     driver reports `blocked:` (for example owner_ssh_in_scope: a release runtime projects into
     the account's own ~/.ssh, so it runs only as a disposable account) is exit 3.
  6. Idle again (else `abort`, blocked), then LockWorkStation (user32). The lock is verified
     through the product's query within 30 s; otherwise `abort`, blocked (lock_not_verified),
     and the driver cleans up.
  7. While locked (sampled every 10 s): the driver's locked steps, including the forced issuer
     restart (DPAPI unprotect under lock) and the re-issue it serves. A locked-phase login outside
     the verified-locked window makes the run blocked (lock_interrupted).
  8. Wait for the unlock (bounded, 12 h), then `expect` (each grant's case from its remaining
     deadline: usable, expired; R terminal) and `unlocked`; the driver's post-unlock step and
     cleanup; the attribution check (F09) over the driver's logins.tsv; the sshds stopped by
     recorded PID, start time and configuration; the owner-profile digest (%USERPROFILE%\.ssh,
     metadata only); redaction; canary masking; the leak count.

Nothing is elevated (an elevated session is refused); no service, registry value, firewall rule,
ssh-agent, %USERPROFILE%\.ssh or WSL configuration is touched; there is no wsl --shutdown. Only
processes this script started are stopped, through their own handles or recorded identity.

Output: -Out holds tests.txt ("### e2e_exit_m03" section), commands.txt (one line per driver
test), host.txt (the facts, lock observations and lock-state samples), build.txt (binary digests),
skipped.txt, canary-scan.txt, and bundle.b64, the gzip+base64 bundle in the M02 Windows local
format (printed between markers; imported with tests/native/m02/import-windows-bundle.py
--platform-dir windows-lock).
Exit: 0 every driver test passed with a verified lock; 3 blocked; 1 a check failed; 2 usage.

.PARAMETER ProductBin
The release-profile heimdall.exe of the exit commit (cargo build --release --locked -p heimdall).

.PARAMETER Driver
The e2e_exit_m03 test executable of the same commit (cargo test -p heimdall --test e2e_exit_m03
--no-run --locked).

.PARAMETER SignalTest
The integration_session_lock test executable of the same commit (cargo test -p heimdall-runtime
--test integration_session_lock --no-run --locked): its `windows_lock_signal_observed` (P-W1,
M-F13) starts unlocked and waits across the lock.

.PARAMETER Out
An empty or absent directory for the results.

.PARAMETER Commit
The exit commit (40 hex), recorded in the bundle.

.PARAMETER SelfTest
Exercise the pure functions (release probe verdict, store-kind rule, idle rule, expectations,
attribution, driver results, redaction, bundle) and the whole run with stub hooks (idle, lock,
sshds) and stub programs (a product binary, a driver speaking the handshake, a signal test),
written as PowerShell scripts in a temporary directory; print one line per check and
`lock-windows-selftest: N passed, M failed`; exit 0 only when all passed. Runs anywhere.
#>
[CmdletBinding()]
param(
    [string]$ProductBin = '',
    [string]$Driver = '',
    [string]$SignalTest = '',
    [string]$Out = '',
    [string]$Commit = '',
    [string]$WslDistro = '',
    [int]$WaitUnlockSeconds = 43200,
    [int]$VerifySeconds = 30,
    [switch]$SelfTest
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$MinIdleSeconds = 900
# The driver's own bounds (tests/e2e/exit_m03/lock.rs): its preparation, its locked steps.
$PrepareSeconds = 1800
$LockedStepsSeconds = 10800
$BundleFormat = 'heimdall-m02-windows-local-bundle/1'
$BeginMarker = '-----BEGIN HEIMDALL M02 WINDOWS BUNDLE-----'
$EndMarker = '-----END HEIMDALL M02 WINDOWS BUNDLE-----'
$EnvDrop = '^(HEIMDALL_|HM_FIXTURE_|HM_LOCK_|SSH_AUTH_SOCK$|GIT_)'

# ---------------------------------------------------------------------------------------------
# Pure functions (exercised by -SelfTest)
# ---------------------------------------------------------------------------------------------

# The release probe's verdict from the exit code of `heimdall internal session-lock-state` run
# with HEIMDALL_TEST_SESSION_LOCK set: a release build refuses every test variable with exit 2.
function Test-ReleaseProbe([int]$ExitCode) { return ($ExitCode -eq 2) }

# Only the product DPAPI store kind makes the Windows row claim-eligible (F03).
function Test-ProductStoreKind([string]$Kind) { return ($Kind.Trim() -ceq 'windows_dpapi') }

function Test-IdleOk([long]$Seconds, [long]$Min) { return ($Seconds -ge 0 -and $Seconds -ge $Min) }

# grants.tsv (role, grant, host, deadline epoch seconds) -> "C=usable R=terminal N=expired".
function Get-Expectations([string]$GrantsText, [long]$Now) {
    $parts = @()
    foreach ($line in ($GrantsText -split "`n")) {
        $f = $line.TrimEnd("`r") -split "`t"
        if ($f.Count -ne 4 -or $f[0] -notmatch '^[A-Z]$' -or $f[3] -notmatch '^[0-9]+$') { continue }
        $v = if ($f[0] -eq 'R') { 'terminal' } elseif (([long]$f[3] - $Now) -gt 60) { 'usable' } else { 'expired' }
        $parts += "$($f[0])=$v"
    }
    return ($parts -join ' ')
}

# The attribution check (F09) over logins.tsv (epoch, phase, host, role, key id, accepted|refused),
# grants.tsv and events.tsv (epoch, event, role), with the verified-locked window (epoch seconds;
# $null when the lock was never sampled as locked). Returns a hashtable of counts and Verdict
# (0 pass, 1 misattributed / late / no data, 3 a locked-phase login outside the window).
function Test-Attribution([string]$GrantsText, [string]$LoginsText, [string]$EventsText, $Window) {
    $grants = @{}
    foreach ($line in ($GrantsText -split "`n")) {
        $f = $line.TrimEnd("`r") -split "`t"
        if ($f.Count -eq 4) { $grants[$f[0]] = @($f[1], $f[2]) }
    }
    $logins = @()
    foreach ($line in ($LoginsText -split "`n")) {
        $f = $line.TrimEnd("`r") -split "`t"
        if ($f.Count -eq 6) { $logins += , $f }
    }
    $revoked = @()
    foreach ($line in ($EventsText -split "`n")) {
        $f = $line.TrimEnd("`r") -split "`t"
        if ($f.Count -eq 3 -and $f[1] -eq 'revoked' -and $f[2] -eq 'R' -and $f[0] -match '^[0-9]+$') { $revoked += [long]$f[0] }
    }
    $bad = 0; $late = 0; $outside = 0; $accepted = 0
    foreach ($l in $logins) {
        if ($l[5] -eq 'accepted') {
            $accepted++
            $m = [regex]::Match($l[4], '^heimdall:[^:]+:([^:]+):[^:]+$')
            $want = $grants[$l[3]]
            if (-not $m.Success -or $null -eq $want -or $m.Groups[1].Value -ne $want[0] -or $l[2] -ne $want[1]) { $bad++ }
            if ($l[3] -eq 'R' -and $revoked.Count -gt 0 -and [long]$l[0] -ge ($revoked | Measure-Object -Minimum).Minimum) { $late++ }
        }
        if ($l[1] -eq 'locked' -and $l[0] -match '^[0-9]+$') {
            if ($null -eq $Window -or [long]$l[0] -lt $Window[0] -or [long]$l[0] -gt $Window[1]) { $outside++ }
        }
    }
    $verdict = 0
    if ($logins.Count -eq 0 -or $grants.Count -eq 0 -or $bad -gt 0 -or $late -gt 0) { $verdict = 1 }
    elseif ($outside -gt 0) { $verdict = 3 }
    return @{ Logins = $logins.Count; Accepted = $accepted; Misattributed = $bad; LateR = $late; Outside = $outside; Verdict = $verdict }
}

# The verified-locked window from samples ("<seconds since T0> <state>" lines): the first locked
# sample to the last consecutive one, widened by the 10 s sampling period; $null when none.
function Get-LockedWindow([string]$SamplesText, [long]$T0) {
    $first = $null; $last = $null
    foreach ($line in ($SamplesText -split "`n")) {
        $f = $line.Trim() -split '\s+'
        if ($f.Count -ne 2 -or $f[0] -notmatch '^-?[0-9]+$') { continue }
        $s = $T0 + [long]$f[0]
        if ($f[1] -eq 'locked') { if ($null -eq $first) { $first = $s }; $last = $s }
        elseif ($null -ne $first) { break }
    }
    if ($null -eq $first) { return $null }
    return @(($first - 10), ($last + 10))
}

# The driver's test names on Windows (the issuer-restart test is Windows-only).
function Get-DriverTests {
    return @('a03_lock_prepare', 'a03_fresh_logins_while_locked_continue', 'a03_new_grant_while_locked_under_standing_policy',
        'a03_issuer_restart_dpapi_unprotect_while_locked', 'a03_lock_revokes_ends_grant_and_fresh_login_fails',
        'a03_vault_stand_in_locked_agent_does_not_matter', 'a03_post_unlock_follows_remaining_deadline', 'a03_lock_cleanup')
}

# One result per driver test from its libtest output: Rc 0 `ok`; 3 `FAILED` with an `aborted:`
# or `blocked:` reason (not run, or not runnable: the run is blocked); 1 any other failure or
# no result at all.
function Get-DriverResults([string]$Output) {
    $text = $Output -replace "`r", ''
    $res = @()
    foreach ($t in Get-DriverTests) {
        $m = [regex]::Matches($text, "(?m)^test lock::$t \.\.\. (\S+)")
        if ($m.Count -eq 0) { $res += , @{ Name = $t; Rc = 1; What = 'no result' }; continue }
        $what = $m[$m.Count - 1].Groups[1].Value
        $rc = if ($what -eq 'ok') { 0 } elseif ($what -eq 'FAILED' -and $text -match "(?m)^${t}: (aborted|blocked): ") { 3 } else { 1 }
        $res += , @{ Name = $t; Rc = $rc; What = $what }
    }
    return $res
}

# A prepare-failed line: 3 (blocked) when it starts `blocked: `, else 1.
function Get-PrepareVerdict([string]$Line) { if ($Line.Trim().StartsWith('blocked: ')) { return 3 } else { return 1 } }

# Whether the commands text records a hard failure (an exit other than 0 and 3).
function Test-HardFailure([string]$CommandsText) {
    foreach ($l in ($CommandsText -split "`n")) { if ($l -match '^exit (-?[0-9]+): ' -and $Matches[1] -ne '0' -and $Matches[1] -ne '3') { return $true } }
    return $false
}

# Metadata digest (names, attributes, sizes, write times; never contents) of the given roots.
function Get-OwnerDigest([string[]]$Roots) {
    $h = [System.Security.Cryptography.IncrementalHash]::CreateHash('SHA256')
    $n = 0
    foreach ($root in $Roots) {
        foreach ($i in @(Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue)) {
            if ($null -eq $i) { continue }
            $n++
            $len = if ($i.PSIsContainer) { 0 } else { $i.Length }
            $h.AppendData([System.Text.Encoding]::UTF8.GetBytes("$($i.FullName)|$($i.Attributes)|$len|$($i.LastWriteTimeUtc.Ticks)`n"))
        }
    }
    if ($n -eq 0) { return 'absent' }
    return "${n}:" + (([System.BitConverter]::ToString($h.GetHashAndReset()) -replace '-', '').ToLowerInvariant().Substring(0, 24))
}

function Invoke-Redaction([string]$Text, [string[]]$Values, [string[]]$Words) {
    $forms = @()
    foreach ($v in $Values) { if ($v -and $v.Length -ge 2) { $forms += , @($v, $false); $forms += , @($v.Replace('\', '/'), $false); $forms += , @($v.Replace('\', '\\'), $false) } }
    foreach ($w in $Words) { if ($w -and $w.Length -ge 2) { $forms += , @($w, $true) } }
    foreach ($f in ($forms | Sort-Object -Property { $_[0].Length } -Descending)) {
        $p = [regex]::Escape($f[0])
        if ($f[1]) { $p = '(?<![A-Za-z0-9_])' + $p + '(?![A-Za-z0-9_])' }
        $Text = [regex]::Replace($Text, $p, '<redacted>', 'IgnoreCase')
    }
    $Text = [regex]::Replace($Text, 'S-1-(5-21|12-1)(-\d+){1,6}', 'S-1-<redacted>')
    $Text = [regex]::Replace($Text, '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', { param($m) if ($m.Value.StartsWith('127.')) { $m.Value } else { '<addr>' } })
    return [regex]::Replace($Text, 'HEIMDALL_CANARY_[A-Za-z0-9_]*', '<canary>')
}

function Get-Sha256Hex([byte[]]$Data) {
    return ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($Data)) -replace '-', '').ToLowerInvariant()
}

# The M02 Windows local bundle (import-windows-bundle.py reads it): bundle.json, gzip, base64.
function New-Bundle([hashtable]$Files, [hashtable]$Meta) {
    $sha = [ordered]@{}; $ordered = [ordered]@{}
    foreach ($k in ($Files.Keys | Sort-Object)) { $ordered[$k] = $Files[$k]; $sha[$k] = Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($Files[$k])) }
    $doc = [ordered]@{ format = $BundleFormat }
    foreach ($k in ($Meta.Keys | Sort-Object)) { $doc[$k] = $Meta[$k] }
    $doc['files'] = $ordered; $doc['sha256'] = $sha
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes((($doc | ConvertTo-Json -Depth 6 -Compress) + "`n"))
    $ms = [System.IO.MemoryStream]::new()
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $gz.Write($bytes, 0, $bytes.Length); $gz.Dispose()
    $packed = $ms.ToArray()
    $b64 = [Convert]::ToBase64String($packed)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($BeginMarker); $lines.Add("sha256-gzip: $(Get-Sha256Hex $packed)")
    for ($i = 0; $i -lt $b64.Length; $i += 76) { $lines.Add($b64.Substring($i, [Math]::Min(76, $b64.Length - $i))) }
    $lines.Add($EndMarker)
    return ($lines -join "`n") + "`n"
}

function Get-Epoch { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

# ---------------------------------------------------------------------------------------------
# Processes. A program is an array: the file, then any fixed leading arguments (the self-test's
# stubs are PowerShell scripts run by this pwsh).
# ---------------------------------------------------------------------------------------------

function New-StartInfo([string[]]$Program, [string[]]$Arguments, [hashtable]$SetEnv, [string]$WorkDir) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Program[0])
    foreach ($a in @($Program | Select-Object -Skip 1) + @($Arguments)) { if ($null -ne $a) { $psi.ArgumentList.Add($a) } }
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $WorkDir
    foreach ($k in @($psi.Environment.Keys)) { if ($k -match $EnvDrop) { [void]$psi.Environment.Remove($k) } }
    if ($null -ne $SetEnv) { foreach ($k in $SetEnv.Keys) { $psi.Environment[$k] = [string]$SetEnv[$k] } }
    return $psi
}

function Invoke-Bounded([string[]]$Program, [string[]]$Arguments, [hashtable]$SetEnv, [string]$WorkDir, [int]$Seconds, [string]$StdIn = $null) {
    $p = [System.Diagnostics.Process]::Start((New-StartInfo $Program $Arguments $SetEnv $WorkDir))
    $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
    if ($null -ne $StdIn) { $p.StandardInput.Write($StdIn) }
    $p.StandardInput.Close()
    $timedOut = -not $p.WaitForExit($Seconds * 1000)
    if ($timedOut) { $p.Kill($true); $p.WaitForExit() }
    $p.WaitForExit()
    $code = if ($timedOut) { 124 } else { $p.ExitCode }
    $text = $o.Result + $e.Result
    $p.Dispose()
    return [pscustomobject]@{ Code = $code; Output = $text }
}

# ---------------------------------------------------------------------------------------------
# The run. $P: Product, Driver, Signal (program arrays), Out, Commit, WaitUnlockSeconds,
# VerifySeconds, TempRoot, SignalLead (seconds between starting the signal test and locking),
# Label. $H: the platform hooks, each a scriptblock: IdleSeconds -> long; Lock -> bool;
# StartSshds (run dir) -> @{ Count; Env; Why; State }; StopSshds (state) -> string;
# Facts -> ordered facts; OwnerRoots -> paths for the digest; Words/Values -> redaction.
# Returns the exit code.
# ---------------------------------------------------------------------------------------------

function Invoke-LockRun([hashtable]$P, [hashtable]$H) {
    $run = Join-Path $P.TempRoot ('hm-m03-lock-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))
    [void][System.IO.Directory]::CreateDirectory($run)
    $state = Join-Path $run 'state'; [void][System.IO.Directory]::CreateDirectory($state)
    $commands = [System.Text.StringBuilder]::new()
    $facts = [System.Text.StringBuilder]::new()
    $tests = [System.Text.StringBuilder]::new()
    $build = [System.Text.StringBuilder]::new()
    $samples = [System.Collections.Generic.List[string]]::new()
    $RS = @{ Exit = 0; Driver = $null; DriverOut = $null; DriverErr = $null; DriverRc = $null; Sshds = $null; Signal = $null; T0 = 0 }
    function Add-Command([int]$Rc, [string]$What) { [void]$commands.Append("exit ${Rc}: $What`n") }
    function Add-Fact([string]$Key, [string]$Value) { [void]$facts.Append("$Key=$(($Value -replace "`r", '') -split "`n" | Select-Object -First 1)`n") }
    function Set-Blocked([string]$Reason) { Add-Fact 'lock-run' "blocked ($Reason)"; $RS.Exit = 3 }
    function Write-Flag([string]$Name, [string]$Text = '') {
        $tmp = Join-Path $state ".$Name.tmp"
        [IO.File]::WriteAllText($tmp, "$Text`n")
        Move-Item -LiteralPath $tmp -Destination (Join-Path $state $Name) -Force
    }
    function Read-State([string]$Name) { $f = Join-Path $state $Name; if (Test-Path -LiteralPath $f) { return (Get-Content -LiteralPath $f -Raw) } else { return '' } }
    function Get-LockState {
        $r = Invoke-Bounded $P.Product @('--json', 'internal', 'session-lock-state') @{} $run 60
        if ($r.Code -ne 0) { return 'query_failed' }
        try { $s = (($r.Output -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json).data.state } catch { return 'query_failed' }
        if ($s -in @('unlocked', 'locked', 'unknown', 'unavailable')) { return $s } else { return 'query_failed' }
    }
    function Wait-LockState([string]$Want, [int]$Seconds) {
        $start = Get-Epoch; $last = ''
        while ($true) {
            $s = Get-LockState
            $now = Get-Epoch
            if ($s -ne $last) { Add-Fact "lock-observation-$($now - $RS.T0)s" $s; $last = $s }
            $samples.Add("$($now - $RS.T0) $s")
            if ($s -eq $Want) { return $true }
            if (($now - $start) -ge $Seconds) { return $false }
            Start-Sleep -Seconds 2
        }
    }
    # Wait for one of the handshake files: its name, '<ended>' when the driver ended first, or
    # '<timeout>'. With -Sample, the lock state is sampled every 10 s meanwhile.
    function Wait-Flag([string[]]$Names, [int]$Seconds, [switch]$Sample) {
        $start = Get-Epoch; $next = 0
        while ($true) {
            foreach ($n in $Names) { if (Test-Path -LiteralPath (Join-Path $state $n)) { return $n } }
            if ($RS.Driver.HasExited) {
                foreach ($n in $Names) { if (Test-Path -LiteralPath (Join-Path $state $n)) { return $n } }
                return '<ended>'
            }
            $now = Get-Epoch
            if (($now - $start) -ge $Seconds) { return '<timeout>' }
            if ($Sample -and $now -ge $next) { $samples.Add("$($now - $RS.T0) $(Get-LockState)"); $next = $now + 10 }
            Start-Sleep -Milliseconds 500
        }
    }
    function Wait-Driver([int]$Seconds) {
        if ($null -eq $RS.Driver) { return $true }
        if (-not $RS.Driver.WaitForExit($Seconds * 1000)) { return $false }
        $RS.Driver.WaitForExit()
        $RS.DriverRc = $RS.Driver.ExitCode
        return $true
    }

    $ownerBefore = ''
    try {
        Add-Fact 'build-commit' $P.Commit
        Add-Fact 'lock-rule' 'ADR-0004 §2: locked by the harness only after >= 900 s console idle; the owner unlocks'
        Add-Fact 'lock-driver-protocol' 'one process (e2e_exit_m03 --ignored --test-threads=16 lock::), handshake files'
        $f = & $H.Facts
        foreach ($k in $f.Keys) { Add-Fact $k $f[$k] }
        [void]$build.Append("heimdall.exe (release profile, the product binary) sha256: $(Get-Sha256Hex ([IO.File]::ReadAllBytes($P.Product[-1])))`n")
        [void]$build.Append("e2e_exit_m03.exe (the lock driver, test build) sha256: $(Get-Sha256Hex ([IO.File]::ReadAllBytes($P.Driver[-1])))`n")
        $ownerBefore = Get-OwnerDigest (& $H.OwnerRoots)
        Add-Fact 'owner-ssh-before' $ownerBefore

        # 1. Release profile (F03).
        $probeFile = Join-Path $run 'probe-lock-state'
        [IO.File]::WriteAllText($probeFile, 'locked')
        $r = Invoke-Bounded $P.Product @('--json', 'internal', 'session-lock-state') @{ HEIMDALL_TEST_SESSION_LOCK = $probeFile } $run 60
        $isRelease = Test-ReleaseProbe $r.Code
        Add-Command $(if ($isRelease) { 0 } else { 2 }) "release-profile probe: the product binary refuses HEIMDALL_TEST_SESSION_LOCK (exit $($r.Code); a release build exits 2)"
        Add-Fact 'build-profile' $(if ($isRelease) { 'release (refuses every HEIMDALL_TEST_* variable)' } else { 'not release: refused' })
        if (-not $isRelease) { $RS.Exit = 2; throw 'not a release-profile product binary' }

        # 2. Idle.
        $idle = & $H.IdleSeconds
        Add-Fact 'idle-seconds-before-prepare' "$idle"
        if (-not (Test-IdleOk $idle $MinIdleSeconds)) { Set-Blocked "console_not_idle: ${idle}s < ${MinIdleSeconds}s; nothing prepared or locked"; Add-Command 3 'idle check'; throw 'blocked' }
        Add-Command 0 "idle check: console idle ${idle}s >= ${MinIdleSeconds}s"

        # 3. Unlocked first.
        $before = Get-LockState
        Add-Fact 'lock-state-before' $before
        if ($before -ne 'unlocked') { Set-Blocked "lock_state_not_unlocked_before: $before"; Add-Command 3 'lock state before the lock'; throw 'blocked' }
        Add-Command 0 'heimdall internal session-lock-state before the lock read unlocked (WTS source)'

        # 4. Three fixture sshds.
        $RS.Sshds = & $H.StartSshds $run
        Add-Command $(if ($RS.Sshds.Count -eq 3) { 0 } else { 1 }) "three fixture sshds in WSL scratch on 127.0.0.1 ($($RS.Sshds.Count) started)"
        if ($RS.Sshds.Count -ne 3) { throw 'the fixture sshds did not start' }

        # 5. The driver: start once, wait for its preparation.
        $denv = @{ HM_LOCK_STATE_DIR = $state; HM_LOCK_PLATFORM = 'windows'; HM_LOCK_HARNESS_PID = "$PID"; HEIMDALL_E2E_BIN = $P.Product[-1]; TEMP = $run; TMP = $run }
        foreach ($k in $RS.Sshds.Env.Keys) { $denv[$k] = $RS.Sshds.Env[$k] }
        $psi = New-StartInfo $P.Driver @('--ignored', '--test-threads=16', '--show-output', 'lock::') $denv $run
        $RS.Driver = [System.Diagnostics.Process]::Start($psi)
        $RS.DriverOut = $RS.Driver.StandardOutput.ReadToEndAsync(); $RS.DriverErr = $RS.Driver.StandardError.ReadToEndAsync()
        $RS.Driver.StandardInput.Close()
        $flag = Wait-Flag @('ready', 'prepare-failed') $PrepareSeconds
        if ($flag -eq 'prepare-failed') {
            $why = ((Read-State 'prepare-failed') -split "`n")[0].Trim()
            if ((Get-PrepareVerdict $why) -eq 3) { Set-Blocked "prepare_blocked: $($why.Substring(9))"; Add-Command 3 "the lock driver's preparation is blocked"; throw 'blocked' }
            Add-Command 1 "the lock driver's preparation failed"; $RS.Exit = 1; throw 'prepare failed'
        }
        if ($flag -ne 'ready') { Add-Command 1 "the lock driver prepared within ${PrepareSeconds}s ($flag)"; $RS.Exit = 1; throw 'prepare failed' }
        Add-Command 0 'the lock driver prepared (ready)'
        $kind = (Read-State 'store-kind.txt').Trim()
        Add-Fact 'store-kind' $kind
        Add-Command $(if (Test-ProductStoreKind $kind) { 0 } else { 1 }) "the issuer's store kind is the product DPAPI store (observed: $kind)"
        if (-not (Test-ProductStoreKind $kind)) { Write-Flag 'abort' "store_kind_not_product: $kind"; $RS.Exit = 1; throw 'not the product store' }

        # 6. Idle again, lock, verify.
        $idle = & $H.IdleSeconds
        Add-Fact 'idle-seconds-before-lock' "$idle"
        if (-not (Test-IdleOk $idle $MinIdleSeconds)) {
            Set-Blocked "console_not_idle: ${idle}s after preparing; not locked"; Write-Flag 'abort' "console_not_idle: ${idle}s after preparing; not locked"
            Add-Command 3 'idle check before the lock'; throw 'blocked'
        }
        Add-Command 0 "idle check before the lock: console idle ${idle}s >= ${MinIdleSeconds}s"
        Add-Fact 'lock-method' 'LockWorkStation (user32), from the interactive session'
        # P-W1 (M-F13): the WTS signal test starts unlocked and waits for a real `locked` reading.
        $spsi = New-StartInfo $P.Signal @('--exact', 'windows_lock_signal_observed', '--ignored', '--test-threads=1', '--show-output') @{ HM_LOCK_WAIT_SECS = '120'; TEMP = $run; TMP = $run } $run
        $RS.Signal = [System.Diagnostics.Process]::Start($spsi)
        $RS.SignalOut = $RS.Signal.StandardOutput.ReadToEndAsync(); $RS.SignalErr = $RS.Signal.StandardError.ReadToEndAsync()
        $RS.Signal.StandardInput.Close()
        Start-Sleep -Seconds $P.SignalLead
        $RS.T0 = Get-Epoch
        $ok = & $H.Lock
        Add-Command $(if ($ok) { 0 } else { 1 }) 'LockWorkStation'
        if (-not (Wait-LockState 'locked' $P.VerifySeconds)) {
            Set-Blocked "lock_not_verified: the product's query did not read locked within $($P.VerifySeconds) s"; Write-Flag 'abort' "lock_not_verified: not locked within $($P.VerifySeconds) s"
            Add-Command 3 "lock verified through the product's query within $($P.VerifySeconds) s"; throw 'blocked'
        }
        Add-Command 0 "lock verified through the product's query within $($P.VerifySeconds) s"
        Write-Flag 'locked' "verified at +$((Get-Epoch) - $RS.T0)s"
        if (-not $RS.Signal.WaitForExit(150000)) { $RS.Signal.Kill($true); $RS.Signal.WaitForExit() }
        $src = $RS.Signal.ExitCode
        [void]$tests.Append("### integration_session_lock`n$(($RS.SignalOut.Result + $RS.SignalErr.Result) -replace "`r`n", "`n")`n### integration_session_lock exit=$src`n")
        Add-Command $src 'integration_session_lock windows_lock_signal_observed across the lock (P-W1)'

        # 7. While locked: the driver's locked steps, the lock state sampled meanwhile.
        $flag = Wait-Flag @('locked-done') $LockedStepsSeconds -Sample
        $lockedEnd = Get-Epoch
        if ($flag -ne 'locked-done') { Add-Command 1 "the lock driver finished its locked steps ($flag)"; Write-Flag 'abort' 'locked_steps_unfinished'; $RS.Exit = 1; throw 'locked steps unfinished' }
        Add-Command 0 "the lock driver finished its locked steps (locked-done, $($lockedEnd - $RS.T0)s after the lock)"

        # 8. Unlock, post-unlock, attribution.
        if (-not (Wait-LockState 'unlocked' $P.WaitUnlockSeconds)) {
            Set-Blocked "unlock_not_observed within $($P.WaitUnlockSeconds)s"; Write-Flag 'abort' "unlock_not_observed within $($P.WaitUnlockSeconds)s"
            Add-Command 3 'unlock observed'; throw 'blocked'
        }
        Add-Command 0 'unlock observed'
        $grants = Read-State 'grants.tsv'
        $expect = Get-Expectations $grants (Get-Epoch)
        Add-Fact 'post-unlock-expectations' $expect
        Write-Flag 'expect' $expect
        Write-Flag 'unlocked'
        if (-not (Wait-Driver $PrepareSeconds)) { Add-Command 1 "the lock driver ended within ${PrepareSeconds}s of the unlock"; $RS.Exit = 1; throw 'driver did not end' }
        $a = Test-Attribution $grants (Read-State 'logins.tsv') (Read-State 'events.tsv') (Get-LockedWindow ($samples -join "`n") $RS.T0)
        Add-Fact 'attribution' "logins=$($a.Logins) accepted=$($a.Accepted) misattributed=$($a.Misattributed) r-accepted-after-revocation=$($a.LateR) locked-logins-outside-window=$($a.Outside)"
        Add-Command $a.Verdict 'attribution by certificate key ID over logins.tsv (disjoint pairs; nothing of R accepted after its revocation; locked logins inside the verified window)'
        if ($a.Verdict -eq 3) { Set-Blocked 'lock_interrupted: a locked-phase login fell outside the verified-locked window' }
        elseif ($a.Verdict -ne 0) { $RS.Exit = 1 }
    } catch {
        if ($RS.Exit -eq 0) { $RS.Exit = 1 }
        Add-Fact 'stopped' ($_.Exception.Message)
    } finally {
        if ($null -ne $RS.Driver) {
            # The driver always cleans up after an `abort` (and after `unlocked`): ask, then wait
            # for it; stopped through its handle only if it outlives every bound, and then its
            # runtime through the product's own stop in its scratch home.
            if (-not $RS.Driver.HasExited -and -not (Test-Path -LiteralPath (Join-Path $state 'abort')) -and -not (Test-Path -LiteralPath (Join-Path $state 'unlocked'))) {
                Write-Flag 'abort' 'harness_ended: the harness stopped before the procedure finished'
            }
            if (Wait-Driver 900) { Add-Command 0 "the lock driver ended by itself (exit $($RS.DriverRc))" }
            else {
                $RS.Driver.Kill($true); $RS.Driver.WaitForExit()
                Add-Command 1 'the lock driver outlived its bounds and was stopped through its handle'
                $hh = (Read-State 'runtime-home.txt').Trim()
                if ($hh) { $r = Invoke-Bounded $P.Product @('--json', 'service', 'stop') @{ HEIMDALL_HOME = $hh } $run 120; Add-Command $(if ($r.Code -in @(0, 5)) { 0 } else { 1 }) 'heimdall service stop in the driver''s scratch Heimdall home (fallback)' }
            }
            $dout = (($RS.DriverOut.Result + $RS.DriverErr.Result) -replace "`r`n", "`n")
            [void]$tests.Append("### e2e_exit_m03`n$dout`n### e2e_exit_m03 exit=$(if ($null -ne $RS.DriverRc) { $RS.DriverRc } else { 'killed' })`n")
            foreach ($t in Get-DriverResults $dout) { Add-Command $t.Rc "driver test lock::$($t.Name): $($t.What)" }
        }
        if ($null -ne $RS.Sshds) { Add-Fact 'fixture-sshds-at-end' (& $H.StopSshds $RS.Sshds.State) }
        if ($null -ne $RS.Signal -and -not $RS.Signal.HasExited) { if (-not $RS.Signal.WaitForExit(150000)) { $RS.Signal.Kill($true) } }
        $ownerAfter = Get-OwnerDigest (& $H.OwnerRoots)
        Add-Fact 'owner-ssh-after' $ownerAfter
        Add-Command $(if ($ownerBefore -eq $ownerAfter) { 0 } else { 1 }) '%USERPROFILE%\.ssh metadata unchanged by the run (digests)'
        foreach ($x in $samples) { [void]$facts.Append("lock-sample=$x`n") }
        # A run that stopped before the driver started still names why (the importer needs one
        # "### <name> exit=N" line); `lock_procedure` is the harness, never a cargo target.
        if ($tests.Length -eq 0) { [void]$tests.Append("### lock_procedure`n(no driver started)`n### lock_procedure exit=$($RS.Exit)`n") }
        $files = @{ 'tests.txt' = $tests.ToString(); 'commands.txt' = $commands.ToString(); 'host.txt' = $facts.ToString(); 'build.txt' = $build.ToString(); 'skipped.txt' = '' }
        $values = @(& $H.Values) + @($run, $P.TempRoot) | Where-Object { $_ }
        $words = @(& $H.Words) | Where-Object { $_ }
        $canary = 0
        foreach ($k in @($files.Keys)) { $canary += ([regex]::Matches($files[$k], 'HEIMDALL_CANARY_')).Count; $files[$k] = Invoke-Redaction $files[$k] $values $words }
        $files['canary-scan.txt'] = "canary-prefix occurrences in saved output: $canary`n"
        if ($canary -ne 0) { $files['commands.txt'] += "exit 1: canary-prefix scan over saved output (count = $canary)`n" }
        # A failed driver test (other than one not run because the run is blocked), digest or
        # canary check fails a run that would otherwise have passed or been blocked.
        if (Test-HardFailure $files['commands.txt']) { if ($RS.Exit -ne 2) { $RS.Exit = 1 } }
        foreach ($k in $files.Keys) { [IO.File]::WriteAllText((Join-Path $P.Out $k), $files[$k]) }
        $bundle = New-Bundle $files @{ commit = $P.Commit; label = $P.Label; started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        [IO.File]::WriteAllText((Join-Path $P.Out 'bundle.b64'), $bundle)
        Remove-Item -LiteralPath $run -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $RS.Exit
}

# ---------------------------------------------------------------------------------------------
# The self-test
# ---------------------------------------------------------------------------------------------

function Invoke-SelfTest {
    $script:pass = 0; $script:fail = 0
    function Check([string]$Name, [bool]$Ok) { if ($Ok) { "ok   $Name"; $script:pass++ } else { "FAIL $Name"; $script:fail++ } }
    Check 'release probe: exit 2 (a release build refuses the test variable) is release' (Test-ReleaseProbe 2)
    Check 'release probe: exit 0 (a debug build answered) is refused' (-not (Test-ReleaseProbe 0))
    Check 'release probe: any other exit is refused' (-not (Test-ReleaseProbe 1))
    Check 'store kind: windows_dpapi qualifies' (Test-ProductStoreKind 'windows_dpapi')
    Check 'store kind: the scratch test store does not' (-not (Test-ProductStoreKind 'scratch_test'))
    Check 'store kind: an empty observation does not' (-not (Test-ProductStoreKind ''))
    Check 'idle: 899 s is below the 15-minute rule' (-not (Test-IdleOk 899 900))
    Check 'idle: 900 s meets it' (Test-IdleOk 900 900)
    Check 'idle: an unreadable reading (-1) never does' (-not (Test-IdleOk -1 900))
    $g = "C`tgc`t1`t2000`nR`tgr`t2`t2000`nN`tgn`t3`t1050`n"
    Check 'expectations follow the remaining deadline' ((Get-Expectations $g 1000) -eq 'C=usable R=terminal N=expired')
    $w = Get-LockedWindow "0 locked`n10 locked`n20 unlocked`n" 1000
    Check 'locked window: first to last consecutive locked sample, widened by 10 s' ($null -ne $w -and $w[0] -eq 990 -and $w[1] -eq 1020)
    Check 'locked window: none when never locked' ($null -eq (Get-LockedWindow "0 unlocked`n" 1000))
    $ok = "1000`tlocked`t1`tC`theimdall:e:gc:1`taccepted`n1001`tlocked`t2`tR`t-`trefused`n1002`tlocked`t3`tN`theimdall:e:gn:1`taccepted`n"
    $ev = "1001`trevoked`tR`n"
    $a = Test-Attribution $g $ok $ev @(990, 1020)
    Check 'attribution: key IDs naming their own grant on its own host pass' ($a.Verdict -eq 0 -and $a.Misattributed -eq 0)
    $a = Test-Attribution $g ($ok + "1003`tlocked`t2`tC`theimdall:e:gc:1`taccepted`n") $ev @(990, 1020)
    Check 'attribution: grant C accepted on host 2 fails' ($a.Verdict -eq 1 -and $a.Misattributed -eq 1)
    $a = Test-Attribution $g ($ok + "1004`tlocked`t2`tR`theimdall:e:gr:1`taccepted`n") $ev @(990, 1020)
    Check 'attribution: a key ID of R accepted after its revocation fails' ($a.Verdict -eq 1 -and $a.LateR -eq 1)
    $a = Test-Attribution $g $ok $ev @(990, 1000)
    Check 'attribution: a locked-phase login after the window is blocked (3)' ($a.Verdict -eq 3)
    Check 'attribution: no logins is a failure' ((Test-Attribution $g '' $ev @(0, 1)).Verdict -eq 1)
    $out = "test lock::a03_lock_prepare ... ok`ntest lock::a03_fresh_logins_while_locked_continue ... FAILED`n`n---- lock::a03_fresh_logins_while_locked_continue stdout ----`na03_fresh_logins_while_locked_continue: aborted: lock_not_verified`ntest lock::a03_lock_cleanup ... ok`n"
    $dr = Get-DriverResults $out
    Check 'driver results: ok is 0, an aborted FAILED is 3 (blocked), a missing test is 1' (
        ($dr | Where-Object { $_.Name -eq 'a03_lock_prepare' }).Rc -eq 0 -and ($dr | Where-Object { $_.Name -eq 'a03_fresh_logins_while_locked_continue' }).Rc -eq 3 -and
        ($dr | Where-Object { $_.Name -eq 'a03_new_grant_while_locked_under_standing_policy' }).Rc -eq 1 -and $dr.Count -eq 8)
    $dr = Get-DriverResults "test lock::a03_lock_prepare ... FAILED`n---- x ----`na03_lock_prepare: assertion failed`n"
    Check 'driver results: a FAILED without an aborted or blocked reason is 1' (($dr | Where-Object { $_.Name -eq 'a03_lock_prepare' }).Rc -eq 1)
    Check 'prepare-failed: blocked: ... is 3, failed: ... is 1' ((Get-PrepareVerdict 'blocked: owner_ssh_in_scope: x') -eq 3 -and (Get-PrepareVerdict 'failed: x') -eq 1)
    Check 'hard failure: exit 3 lines are not, exit 1 lines are' (-not (Test-HardFailure "exit 0: a`nexit 3: b`n") -and (Test-HardFailure "exit 0: a`nexit 1: b`n"))
    $r = Invoke-Redaction 'C:\Users\someone\x someone-PC HEIMDALL_CANARY_abc 10.1.2.3 127.0.0.1' @('C:\Users\someone') @('someone-PC')
    Check 'redaction: profile, host, canary and address masked; loopback kept' ($r -eq '<redacted>\x <redacted> <canary> <addr> 127.0.0.1')
    $b = New-Bundle @{ 'tests.txt' = "x`n"; 'commands.txt' = "exit 0: y`n"; 'host.txt' = ''; 'build.txt' = ''; 'skipped.txt' = ''; 'canary-scan.txt' = '' } @{ commit = ('0' * 40) }
    Check 'bundle: markers and the gzip digest line' ($b.StartsWith($BeginMarker) -and $b.Contains('sha256-gzip: ') -and $b.TrimEnd().EndsWith($EndMarker))

    # The whole run with stub hooks and stub programs (PowerShell scripts run by this pwsh).
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('hm-lockwin-st-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
    [void][System.IO.Directory]::CreateDirectory($root)
    try {
        $pwsh = [Environment]::ProcessPath
        $stubHeimdall = Join-Path $root 'heimdall.ps1'
        [IO.File]::WriteAllText($stubHeimdall, @'
$w = Split-Path -Parent $PSCommandPath
Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value ("heimdall " + ($args -join ' '))
$a = $args -join ' '
if ($a -eq '--json service stop') { exit 0 }
if ($a -ne '--json internal session-lock-state') { exit 2 }
if ($env:HEIMDALL_TEST_SESSION_LOCK) { if ((Get-Content -LiteralPath (Join-Path $w 'profile')) -eq 'release') { exit 2 } }
$s = (Get-Content -LiteralPath (Join-Path $w 'lock-state')).Trim()
'{"state":"OK","code":"OK","data":{"state":"' + $s + '","source":"platform","signal":"windows_wts"}}'
exit 0
'@)
        $stubSignal = Join-Path $root 'signal.ps1'
        [IO.File]::WriteAllText($stubSignal, @'
$w = Split-Path -Parent $PSCommandPath
Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value ("signal-test " + ($args -join ' '))
'test windows_lock_signal_observed ... ok'
exit 0
'@)
        $stubDriver = Join-Path $root 'driver.ps1'
        [IO.File]::WriteAllText($stubDriver, @'
$w = Split-Path -Parent $PSCommandPath
$s = $env:HM_LOCK_STATE_DIR
$scenario = (Get-Content -LiteralPath (Join-Path $w 'scenario')).Trim()
function Log([string]$m) { Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value "driver $m" }
function Flag([string]$n, [string]$t = '') { $tmp = Join-Path $s ".$n.tmp"; [IO.File]::WriteAllText($tmp, "$t`n"); Move-Item -LiteralPath $tmp -Destination (Join-Path $s $n) -Force }
function Await([string[]]$names) { for ($i = 0; $i -lt 600; $i++) { foreach ($n in $names) { if (Test-Path -LiteralPath (Join-Path $s $n)) { return $n } }; Start-Sleep -Milliseconds 200 }; return '' }
function Tsv([string]$f, [string]$line) { Add-Content -LiteralPath (Join-Path $s $f) -Value $line -NoNewline:$false }
$fails = [System.Collections.Generic.List[string]]::new()
function Res([string]$t, [string]$r) { "test lock::$t ... $r" }
function Fail([string]$t, [string]$why) { Res $t 'FAILED'; $fails.Add("$t|$why") }
function Finish {
    Res 'a03_lock_cleanup' 'ok'; Log 'cleanup'; Flag 'done'
    if ($fails.Count -gt 0) { ''; 'failures:'; foreach ($f in $fails) { $t, $why = $f -split '\|', 2; ''; "---- lock::$t stdout ----"; "${t}: $why" }; 'test result: FAILED.'; exit 101 }
    'test result: ok.'; exit 0
}
$locked = @('a03_fresh_logins_while_locked_continue', 'a03_new_grant_while_locked_under_standing_policy', 'a03_issuer_restart_dpapi_unprotect_while_locked', 'a03_lock_revokes_ends_grant_and_fresh_login_fails', 'a03_vault_stand_in_locked_agent_does_not_matter')
Log ("start " + ($args -join ' '))
Log ("env HEIMDALL_TEST=" + @(Get-ChildItem env: | Where-Object { $_.Name -like 'HEIMDALL_TEST_*' }).Count + " sshd1port=" + $env:HM_LOCK_SSHD_1_PORT + " bin=" + [bool]$env:HEIMDALL_E2E_BIN)
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($scenario -eq 'prepare-blocked') {
    Flag 'prepare-failed' 'blocked: owner_ssh_in_scope: stub'; Log 'prepare-failed'
    Fail 'a03_lock_prepare' 'blocked: owner_ssh_in_scope: stub'
    foreach ($t in $locked + @('a03_post_unlock_follows_remaining_deadline')) { Fail $t 'aborted: the preparation is blocked' }
    Finish
}
Tsv 'grants.tsv' "C`tgc`t1`t$($now + 46800)"; Tsv 'grants.tsv' "R`tgr`t2`t$($now + 7200)"
# The baselines a few seconds before (the real driver's precede R's revocation by minutes).
Tsv 'logins.tsv' "$($now - 5)`tprepare`t1`tC`theimdall:env:gc:1`taccepted"; Tsv 'logins.tsv' "$($now - 5)`tprepare`t2`tR`theimdall:env:gr:1`taccepted"
[IO.File]::WriteAllText((Join-Path $s 'events.tsv'), '')
[IO.File]::WriteAllText((Join-Path $s 'store-kind.txt'), $(if ($scenario -eq 'scratch-store') { "scratch_test`n" } else { "windows_dpapi`n" }))
Flag 'ready'; Log 'ready'; Res 'a03_lock_prepare' 'ok'
$f = Await @('abort', 'locked')
if ($f -ne 'locked') { Log ("abort " + (Get-Content -LiteralPath (Join-Path $s 'abort') -Raw).Trim()); foreach ($t in $locked + @('a03_post_unlock_follows_remaining_deadline')) { Fail $t 'aborted: stub' }; Finish }
Log 'locked'
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Tsv 'logins.tsv' "$now`tlocked`t1`tC`theimdall:env:gc:1`taccepted"
Tsv 'grants.tsv' "N`tgn`t3`t$($now - 5)"
Tsv 'logins.tsv' "$now`tlocked`t3`tN`theimdall:env:gn:1`taccepted"
Tsv 'events.tsv' "$now`trevoked`tR"
Tsv 'logins.tsv' "$($now + 1)`tlocked`t2`tR`t-`trefused"
foreach ($t in $locked) { Res $t 'ok' }
Set-Content -LiteralPath (Join-Path $w 'lock-state') -Value 'unlocked'
Flag 'locked-done'
$f = Await @('abort', 'unlocked')
if ($f -ne 'unlocked') { Log 'abort'; Fail 'a03_post_unlock_follows_remaining_deadline' 'aborted: stub'; Finish }
Copy-Item -LiteralPath (Join-Path $s 'expect') -Destination (Join-Path $w 'expect.seen')
Log 'post'; Res 'a03_post_unlock_follows_remaining_deadline' 'ok'
Finish
'@)
        $scenarioRun = {
            param([string]$Name, [string]$Build, [long[]]$Idle, [bool]$Locks, [string]$Scenario)
            $w = Join-Path $root $Name
            [void][System.IO.Directory]::CreateDirectory($w)
            foreach ($f in @($stubHeimdall, $stubDriver, $stubSignal)) { Copy-Item -LiteralPath $f -Destination $w }
            [IO.File]::WriteAllText((Join-Path $w 'profile'), $Build)
            [IO.File]::WriteAllText((Join-Path $w 'scenario'), $Scenario)
            [IO.File]::WriteAllText((Join-Path $w 'lock-state'), 'unlocked')
            [IO.File]::WriteAllText((Join-Path $w 'calls.log'), '')
            $owner = Join-Path $w 'owner-ssh'; [void][System.IO.Directory]::CreateDirectory($owner)
            $o = Join-Path $w 'out'; [void][System.IO.Directory]::CreateDirectory($o)
            $idleQ = @{ N = 0; V = $Idle }
            $hooks = @{
                IdleSeconds = { $v = $idleQ.V[[Math]::Min($idleQ.N, $idleQ.V.Count - 1)]; $idleQ.N++; return $v }.GetNewClosure()
                # The stub signal test needs a moment to start (pwsh); the lock waits up to 5 s
                # for its first line, so a signal test started only after the lock shows.
                Lock = {
                    for ($i = 0; $i -lt 50 -and (Get-Content -LiteralPath (Join-Path $w 'calls.log') -Raw) -notmatch 'signal-test'; $i++) { Start-Sleep -Milliseconds 100 }
                    Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value 'lock'; if ($Locks) { [IO.File]::WriteAllText((Join-Path $w 'lock-state'), 'locked') }; return $true }.GetNewClosure()
                StartSshds = { param($runDir) Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value 'sshds start'; return @{ Count = 3; Env = @{ HM_LOCK_SSHD_1_PORT = '2201'; HM_LOCK_SSHD_2_PORT = '2202'; HM_LOCK_SSHD_3_PORT = '2203' }; State = 'stub' } }.GetNewClosure()
                StopSshds = { param($st) Add-Content -LiteralPath (Join-Path $w 'calls.log') -Value 'sshds stop'; return 'stop1=stub stop2=stub stop3=stub removed=yes' }.GetNewClosure()
                Facts = { return [ordered]@{ os = 'stub' } }
                OwnerRoots = { return @($owner) }.GetNewClosure()
                Values = { return @() }
                Words = { return @() }
            }
            $params = @{
                Product = @($pwsh, '-NoProfile', '-File', (Join-Path $w 'heimdall.ps1')); Driver = @($pwsh, '-NoProfile', '-File', (Join-Path $w 'driver.ps1'))
                Signal = @($pwsh, '-NoProfile', '-File', (Join-Path $w 'signal.ps1')); Out = $o; Commit = ('0' * 40); WaitUnlockSeconds = 60; VerifySeconds = 4
                TempRoot = $w; SignalLead = 0; Label = 'self-test'
            }
            $rc = Invoke-LockRun $params $hooks
            return @{ Rc = $rc; Dir = $w; Out = $o; Calls = ((Get-Content -LiteralPath (Join-Path $w 'calls.log') -Raw) -replace "`r", '') }
        }
        $read = { param($d, $f) $p = Join-Path $d $f; if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw } else { '' } }

        $x = & $scenarioRun 'debug' 'debug' @(1000) $true 'good'
        Check 'windows_lock_run_is_release_profile_on_dpapi_store: a product binary that answers with a test variable (debug) -> exit 2, no sshd, no driver, never locked' (
            $x.Rc -eq 2 -and $x.Calls -notmatch '(?m)^driver' -and $x.Calls -notmatch '(?m)^sshds start' -and $x.Calls -notmatch '(?m)^lock$' -and (& $read $x.Out 'commands.txt') -match '(?m)^exit 2: release-profile probe')
        $x = & $scenarioRun 'scratch' 'release' @(1000) $true 'scratch-store'
        Check 'windows_lock_run_is_release_profile_on_dpapi_store: a store kind other than windows_dpapi -> abort, the driver cleans up, exit 1, never locked' (
            $x.Rc -eq 1 -and $x.Calls -match '(?m)^driver abort store_kind_not_product: scratch_test' -and $x.Calls -match '(?m)^driver cleanup' -and $x.Calls -notmatch '(?m)^lock$')
        $x = & $scenarioRun 'good' 'release' @(1000) $true 'good'
        $cmds = & $read $x.Out 'commands.txt'
        if ($env:HM_SELFTEST_VERBOSE -eq '1') { $x.Calls; $cmds }
        Check 'windows_lock_run_is_release_profile_on_dpapi_store: release binary, DPAPI store, verified lock -> exit 0, one driver start, 8 driver tests ok, no test variable for the driver' (
            $x.Rc -eq 0 -and ([regex]::Matches($x.Calls, '(?m)^driver start')).Count -eq 1 -and $x.Calls -match '(?m)^driver start --ignored --test-threads=16 --show-output lock::' -and
            ([regex]::Matches($cmds, '(?m)^exit 0: driver test lock::')).Count -eq 8 -and $x.Calls -match 'HEIMDALL_TEST=0 sshd1port=2201 bin=True')
        Check 'windows_lock_run_handshake_order: ready < lock < locked < post < cleanup; signal test before the lock; sshds stopped after the driver' (
            $x.Calls.IndexOf('driver ready') -lt $x.Calls.IndexOf("`nlock") -and $x.Calls.IndexOf("`nlock") -lt $x.Calls.IndexOf('driver locked') -and
            $x.Calls.IndexOf('driver locked') -lt $x.Calls.IndexOf('driver post') -and $x.Calls.IndexOf('driver post') -lt $x.Calls.IndexOf('driver cleanup') -and
            $x.Calls.IndexOf('signal-test') -lt $x.Calls.IndexOf("`nlock") -and $x.Calls.IndexOf('driver cleanup') -lt $x.Calls.IndexOf('sshds stop'))
        Check 'windows_lock_run_post_unlock_checks_follow_remaining_deadline: the expect file the driver saw' ((& $read $x.Dir 'expect.seen').Trim() -eq 'C=usable R=terminal N=expired')
        Check 'windows_lock_run_attribution_and_bundle: attribution recorded, owner digest unchanged, bundle written' (
            (& $read $x.Out 'host.txt') -match '(?m)^attribution=logins=5 accepted=4 misattributed=0 r-accepted-after-revocation=0 locked-logins-outside-window=0' -and
            $cmds -match '(?m)^exit 0: %USERPROFILE%\\.ssh metadata unchanged' -and (& $read $x.Out 'bundle.b64').StartsWith($BeginMarker))
        $x = & $scenarioRun 'idle' 'release' @(60) $true 'good'
        Check 'windows_lock_run_refuses_without_idle_15_min: 60 s idle -> exit 3, console_not_idle, no driver, never locked' (
            $x.Rc -eq 3 -and (& $read $x.Out 'host.txt') -match 'console_not_idle' -and $x.Calls -notmatch '(?m)^driver' -and $x.Calls -notmatch '(?m)^lock$')
        $x = & $scenarioRun 'idlelate' 'release' @(1000, 30) $true 'good'
        Check 'windows_lock_run_refuses_without_idle_15_min: idle again before the lock (30 s) -> abort, the driver cleans up, exit 3, never locked' (
            $x.Rc -eq 3 -and $x.Calls -match '(?m)^driver abort console_not_idle' -and $x.Calls -match '(?m)^driver cleanup' -and $x.Calls -notmatch '(?m)^lock$')
        $x = & $scenarioRun 'unverified' 'release' @(1000) $false 'good'
        $cmds = & $read $x.Out 'commands.txt'
        Check 'windows_lock_run_records_unverified_lock_as_blocked: never reads locked -> abort, exit 3, skipped tests recorded 3, cleanup ran' (
            $x.Rc -eq 3 -and $x.Calls -match '(?m)^driver abort lock_not_verified' -and $x.Calls -match '(?m)^driver cleanup' -and $x.Calls -notmatch '(?m)^driver locked' -and
            $cmds -match '(?m)^exit 3: driver test lock::a03_fresh_logins_while_locked_continue: FAILED' -and $cmds -notmatch '(?m)^exit 1: ')
        $x = & $scenarioRun 'prepblocked' 'release' @(1000) $true 'prepare-blocked'
        Check 'windows_lock_run_records_a_blocked_preparation: prepare-failed blocked: owner_ssh_in_scope -> exit 3, never locked' (
            $x.Rc -eq 3 -and (& $read $x.Out 'host.txt') -match 'prepare_blocked: owner_ssh_in_scope' -and $x.Calls -notmatch '(?m)^lock$')
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    "lock-windows-selftest: $($script:pass) passed, $($script:fail) failed"
    if ($script:fail -ne 0) { exit 1 }
    exit 0
}

if ($SelfTest) { Invoke-SelfTest }

# ---------------------------------------------------------------------------------------------
# The real run (Windows)
# ---------------------------------------------------------------------------------------------

function Stop-Usage([string]$Message) { [Console]::Error.WriteLine("lock-windows: $Message"); exit 2 }
if (-not $IsWindows) { Stop-Usage 'lock-windows.ps1 runs on the Windows PC itself (use -SelfTest elsewhere)' }
foreach ($p in @($ProductBin, $Driver, $SignalTest)) { if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { Stop-Usage '-ProductBin, -Driver and -SignalTest must name existing files' } }
if (-not $Out) { Stop-Usage '-Out is required' }
if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Usage '-Commit must be the 40-hex exit commit' }
if ($WaitUnlockSeconds -lt 1 -or $WaitUnlockSeconds -gt 43200) { $WaitUnlockSeconds = 43200 }
if ($VerifySeconds -lt 1 -or $VerifySeconds -gt 30) { $VerifySeconds = 30 }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-Usage 'refusing to run elevated' }
if ((Test-Path -LiteralPath $Out) -and @(Get-ChildItem -LiteralPath $Out -Force).Count -gt 0) { Stop-Usage '-Out must be empty or absent' }
[void][System.IO.Directory]::CreateDirectory($Out)
$Out = (Resolve-Path -LiteralPath $Out).Path

Add-Type -Namespace HmLock -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)] public static extern bool LockWorkStation();
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint GetTickCount();
public static long IdleSeconds() {
    LASTINPUTINFO i = new LASTINPUTINFO(); i.cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(LASTINPUTINFO));
    if (!GetLastInputInfo(ref i)) return -1;
    return (long)unchecked(GetTickCount() - i.dwTime) / 1000;
}
'@

$sys32 = Join-Path $env:SystemRoot 'System32'
$wsl = Join-Path $sys32 'wsl.exe'
$wa = @(); if ($WslDistro) { $wa += @('-d', $WslDistro) }
$remoteLib = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\m02\remote-lib.sh') -Raw
$wslSeen = @{ Dir = ''; User = '' }
$hooks = @{
    IdleSeconds = { return [HmLock.Native]::IdleSeconds() }
    Lock = { return [HmLock.Native]::LockWorkStation() }
    Facts = {
        $f = [ordered]@{}
        $f['os'] = (Invoke-Bounded @((Join-Path $sys32 'cmd.exe')) @('/d', '/c', 'ver') @{} $env:TEMP 30).Output.Trim()
        $f['integrity'] = [regex]::Match((Invoke-Bounded @((Join-Path $sys32 'whoami.exe')) @('/groups') @{} $env:TEMP 30).Output, '(Medium|High|System) Mandatory Level').Value
        $f['w32tm-status'] = ((Invoke-Bounded @((Join-Path $sys32 'w32tm.exe')) @('/query', '/status') @{} $env:TEMP 30).Output -split "`n" | Where-Object { $_ -match '^(Leap|Stratum|Source)' }) -join '; '
        return $f
    }
    OwnerRoots = { return @((Join-Path $env:USERPROFILE '.ssh')) }
    Values = { return @($env:USERPROFILE, $env:TEMP, $wslSeen.Dir) }
    Words = { return @($env:USERNAME, $env:COMPUTERNAME, $wslSeen.User) }
    # Three sshds in WSL scratch (tests/native/m02/remote-lib.sh hm2_sshd_start), each with its
    # authorized-keys file and log in the Windows run directory and its enrollment registry in
    # an owner-only WSL scratch directory.
    StartSshds = {
        param($runDir)
        $sshdWin = Join-Path $runDir 'sshd'; [void][System.IO.Directory]::CreateDirectory($sshdWin)
        $wslDir = ((Invoke-Bounded @($wsl) ($wa + @('-e', 'bash', '-c', 'umask 077; mktemp -d /tmp/hm-m03-lock.XXXXXX')) @{} $runDir 60).Output.Trim() -split "`n")[-1]
        if ($wslDir -notmatch '^/tmp/hm-m03-lock\.[A-Za-z0-9]+$') { return @{ Count = 0; Env = @{}; State = $null } }
        $wslSeen.Dir = $wslDir
        $wslUser = ((Invoke-Bounded @($wsl) ($wa + @('-e', 'id', '-un')) @{} $runDir 60).Output.Trim() -split "`n")[-1]
        $wslSeen.User = $wslUser
        $start = $remoteLib + @'

set -u
d=$1; shift
hm2_sanitize_env >/dev/null
pids=""
i=1
for w in "$@"; do
    ak=$(wslpath -u "$w\\authorized_keys$i"); lg=$(wslpath -u "$w\\sshd$i.log")
    if hm2_sshd_start "$d/sshd$i" "$ak" "$lg" 6 "$d/registry$i/authorized_keys"; then
        pids="$pids $HM2_SSHD_PID"
        echo "port$i=$HM2_SSHD_PORT"; echo "hostkey$i=$HM2_SSHD_HOSTKEY"
        echo "registry$i=$(wslpath -w "$d/registry$i/authorized_keys")"; echo "registryremote$i=$d/registry$i/authorized_keys"
    else
        echo "why$i=$HM2_SSHD_WHY"
    fi
    i=$((i + 1))
done
echo "ready=1"
# shellcheck disable=SC2086
wait $pids
'@
        $psi = [System.Diagnostics.ProcessStartInfo]::new($wsl)
        foreach ($a in ($wa + @('-e', 'bash', '-s', '--', $wslDir, $sshdWin, $sshdWin, $sshdWin))) { $psi.ArgumentList.Add($a) }
        $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Write($start); $proc.StandardInput.Close()
        $fx = @{}
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while ([DateTime]::UtcNow -lt $deadline) {
            $line = $proc.StandardOutput.ReadLine()
            if ($null -eq $line) { break }
            if ($line -match '^([a-z]+[0-9]?)=(.*)$') { $fx[$Matches[1]] = $Matches[2] }
            if ($line -eq 'ready=1') { break }
        }
        $envs = @{}; $n = 0
        foreach ($i in 1..3) {
            if (-not $fx.ContainsKey("port$i")) { continue }
            $n++
            $envs["HM_LOCK_SSHD_${i}_PORT"] = $fx["port$i"]
            $envs["HM_LOCK_SSHD_${i}_HOST_KEY"] = $fx["hostkey$i"]
            $envs["HM_LOCK_SSHD_${i}_AUTHORIZED_KEYS"] = (Join-Path $sshdWin "authorized_keys$i")
            $envs["HM_LOCK_SSHD_${i}_LOG"] = (Join-Path $sshdWin "sshd$i.log")
            $envs["HM_LOCK_SSHD_${i}_REGISTRY"] = $fx["registry$i"]
            $envs["HM_LOCK_SSHD_${i}_REGISTRY_REMOTE"] = $fx["registryremote$i"]
            $envs["HM_LOCK_SSHD_${i}_USER"] = $wslUser
        }
        return @{ Count = $n; Env = $envs; State = @{ Dir = $wslDir; Proc = $proc; Run = $runDir } }
    }
    StopSshds = {
        param($st)
        if ($null -eq $st) { return 'none started' }
        $stop = $remoteLib + "`nfor i in 1 2 3; do echo `"stop`$i=`$(hm2_stop_recorded `"`$1/sshd`$i`")`"; done; rm -rf -- `"`$1`" && echo removed=yes"
        $r = Invoke-Bounded @($wsl) ($wa + @('-e', 'bash', '-s', '--', $st.Dir)) @{} $st.Run 120 $stop
        if (-not $st.Proc.WaitForExit(10000)) { $st.Proc.Kill($true) }
        $st.Proc.Dispose()
        return (($r.Output -split "`n" | Where-Object { $_ -match '^(stop[0-9]|removed)=' }) -join ' ')
    }
}
$params = @{
    Product = @($ProductBin); Driver = @($Driver); Signal = @($SignalTest); Out = $Out; Commit = $Commit
    WaitUnlockSeconds = $WaitUnlockSeconds; VerifySeconds = $VerifySeconds; TempRoot = [System.IO.Path]::GetTempPath()
    SignalLead = 3; Label = 'windows-11-x86_64 lock procedure (release profile, DPAPI store)'
}
$rc = Invoke-LockRun $params $hooks
Write-Output (Get-Content -LiteralPath (Join-Path $Out 'bundle.b64') -Raw)
Write-Output "lock-windows exit=$rc"
exit $rc
