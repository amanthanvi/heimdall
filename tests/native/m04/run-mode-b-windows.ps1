#Requires -Version 7.2
<#
.SYNOPSIS
M04 WSL Mode B native rows (ADR-0010 §3, §9 item 10 Q3, §11; m04-plan U4, A13 and A12) on the
Windows PC, in two disposable WSL distributions this script creates and removes itself.

.DESCRIPTION
Runs ON the PC (pwsh 7.2 or later), not elevated. Its steps:
  1. Check the inputs before anything is created: the commit (40 hex), the scratch root (an
     existing directory, not a reparse point), the Linux x86-64 `heimdall` cross-built on the
     build host (-PrebuiltHeimdall / HM_PREBUILT_HEIMDALL) and its sha256 (-PrebuiltSha256 /
     HM_PREBUILT_SHA256: a missing input is exit 3, a malformed digest exit 2, a mismatch exit 1),
     and the pinned Ubuntu image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1: the
     M02 pin, tests/native/m02/run-wsl-distro.sh). Installing packages inside the distributions
     needs -AllowApt / HM_WSL_ALLOW_APT=1 (only inside the distributions this run created).
  2. Create the run directory <ScratchRoot>\hm-m04-modeb-<random> exclusively and give it the
     protected stock profile list (the user, SYSTEM, Administrators; ADR-0010 §11), recording
     its SDDL with the SIDs redacted; TEMP and TMP point inside it.
  3. Record the registered distributions (`wsl --list --verbose`; only this run's are recorded by
     name, the others as a count and a digest). Choose the names hm-m04-<8 hex>-1 and -2 and
     refuse when either is registered already.
  4. Clone the repository at exactly the commit, install the pinned toolchain into the run
     directory (RUSTUP_HOME and CARGO_HOME there, --no-modify-path), and build the test targets.
  5. Import the first distribution from the pinned image into the run directory, as WSL 2, and
     as root: `[boot] systemd=false` (then a terminate), tests/native/m02/target-root.sh
     `prepare` (the tools, git and python3; one non-root user, hmtest), and `[user] default`
     set to that user (then a terminate). Then export it and import the second from that export
     (its own GUID, the same preparation: one image import, one apt run per run), and remove the
     export.
  6. Start the harness sshd in the second distribution as hmtest (tests/native/m02/remote-lib.sh
     hm2_sshd_start, as the M02/M03 Windows runner does in its WSL scratch): its authorized-keys
     file and log in the run directory, its enrollment registry owner-only in hmtest's home,
     reachable from Windows and from the first distribution on 127.0.0.1. Reachability from
     Windows is retried (a 3 s connect and the SSH banner, every 2 s, for up to 90 s: WSL's
     localhost relay can take a while after a start), each attempt kept in build.txt. When it
     never answers, host.txt records why: whether the recorded sshd is alive, whether anything
     listens on its port inside the distribution, WSL's networking mode as the distribution
     reports it (wslinfo), and the .wslconfig [wsl2] networkingMode and localhostForwarding
     (read only; nothing else of the file). The tests get the HM_FIXTURE_SSHD_* variables.
     Every commands.txt line carries the time since the previous one, and host.txt the
     seconds before the tests.
  7. Run, from the clone, in this order, each with its real exit code and its `test result:` line:
       a. the A13 set: e2e_platform_m04 windows::native::mode_b::a13_ (ignored tests, one thread),
          except the unregister row;
       b. the A12 set: e2e_platform_m04 windows::native::a12_;
       c. the helper-session test: heimdall-wsl windows_helper_session_over_wsl_exe_in_a_disposable_distribution;
       d. LAST and ALONE, with HM_WSL_TEST_ALLOW_UNREGISTER=1: a13_unregistered_distribution_releases_bindings,
          which unregisters the second distribution itself.
  8. Always (finally): stop the harness sshd by its recorded PID, start time and configuration
     (hm2_stop_recorded) when its distribution still exists; terminate and unregister ONLY the
     distributions this run created, by exact name (each re-checked against the pattern, the
     before-list and the current list; the unregister row may have removed -2 already; never
     `wsl --shutdown`); check that the registered set equals the one before; remove the clone,
     the toolchain, the build and the distributions' directories; remove HKCU\Software\HeimdallTest
     only when it has no subkey and no value (never recursively), and record
     heimdalltest-parent=absent|empty-removed|nonempty-kept in host.txt.
  9. Keep, as the run goes, the plain results (results.txt: each command's `### <name> exit=N`,
     its tests' outcomes and its `test result:` lines, then the run's exit; names and counts only)
     and print them, so the verdict survives a failed bundle. Then write one redacted bundle (no
     environment dump): tests.txt, commands.txt, host.txt,
     build.txt, skipped.txt, distributions.txt, canary-scan.txt, as bundle.json and its
     gzip+base64 rendering bundle.b64, printed between markers.

The redaction, canary masking, leak scan and bundle functions are tests/native/m02/run-windows-local.ps1's
own (loaded from its definitions, never run as a script), so the two runners redact alike.

⟨M04 U7⟩ Scenarios (-Scenario). Every scenario creates, uses and removes only its own
hm-m04-<8 hex>-1 (and -2) distributions, by exact name, as above; nothing is installed or changed on
the Windows host, and Docker Desktop is never used.
  mode-b         (default) the steps above, two distributions. -Rows picks a subset of step 7's
                 commands by name (Get-TestPlan; a13-new is the two U7 A13 rows alone).
  systemd-login  one distribution, prepared as above, then `[boot] systemd=true` (inside it only)
                 and a terminate; the Linux heimdall staged in the user's home; the A08/A31 row
                 service_login::wsl_login::linux_login_entry_starts_runtime_at_next_login.
  containers     one distribution, prepared as above; inside it only, as root,
                 tests/native/m04/container-engines.sh installs Podman (rootless, with uidmap) and
                 Docker Engine (rootful, dockerd started by hand, no systemd), records each engine's
                 containers and images before the run, pulls the Alpine base by digest and builds the
                 fixture image; the cross-built Linux e2e_platform_m04 (-PrebuiltLinuxTest) runs
                 container::a15_container_mounted_flow once per engine and
                 container::a31_uninstall_with_a_live_container_binding; then only the containers and
                 images this run recorded are removed and the recorded dockerd stopped. No Windows
                 toolchain or build: the clone serves HM_REPO_ROOT and the scripts.
  lock           two distributions and the harness sshd, as mode-b; then the A03 Mode B lock row
                 (-Driver, -Filter): the driver is started and prepares unlocked; the run is ARMED: it
                 waits, for at most -ArmSeconds, until the console has been idle for at least 900 s
                 (GetLastInputInfo; ADR-0004 §2), and never locks before; then LockWorkStation, the lock
                 verified through the product's own `internal session-lock-state` within 30 s; the
                 driver's locked steps, the lock sampled every 10 s; the owner unlocks; `expect` and
                 `unlocked`. Exit 3 (blocked) when the console never stays idle, the lock is not
                 verified, or a locked-phase sample was not locked.

.PARAMETER DryRun
Check the inputs that can be checked here, print the plan (names, steps, commands) and exit:
nothing is created, no distribution, network, toolchain or build step runs. Runs anywhere.

.PARAMETER SelfTest
The pure helpers on synthetic data (no host, no network, no WSL), and `bash -n` of every script
this runner sends into a distribution when bash is available. Runs anywhere; exit 0 when every
check passed.

.PARAMETER Scenario
mode-b (default), systemd-login, containers or lock (above).

.PARAMETER Rows
mode-b only: the names of the step-7 commands to run (default: all but a13-new), in plan order.

.PARAMETER Driver
lock only: the cargo test target of the lock driver (default e2e_platform_m04).

.PARAMETER Filter
lock only: the driver's exact test path (default
windows::native::mode_b::a03_mode_b_fresh_logins_while_windows_locked).

.PARAMETER ArmSeconds
lock only: how long the armed run waits for 900 s of console idle (default and maximum 43200).

.PARAMETER PrebuiltLinuxTest
containers only: the cross-built Linux e2e_platform_m04 test executable of the same commit
(target/x86_64-unknown-linux-gnu/native-test/deps/e2e_platform_m04-<hash> on the build host), with
-PrebuiltLinuxTestSha256; and -PrebuiltLinuxHook / -PrebuiltLinuxHookSha256, its hm-fixture-hook.

.EXAMPLE
pwsh -NoProfile -File tests\native\m04\run-mode-b-windows.ps1 -Commit <40-hex> -ScratchRoot $env:LOCALAPPDATA\hm-m04 `
    -PrebuiltHeimdall C:\hm\heimdall -PrebuiltSha256 <64-hex> -Rootfs C:\hm\ubuntu-24.04.5-wsl-amd64.wsl -AllowApt
#>
[CmdletBinding()]
param(
    [string]$Commit,
    [string]$ScratchRoot,
    [string]$RepoUrl = 'https://github.com/amanthanvi/heimdall',
    [string]$PrebuiltHeimdall = $env:HM_PREBUILT_HEIMDALL,
    [string]$PrebuiltSha256 = $env:HM_PREBUILT_SHA256,
    [string]$Rootfs = $env:HM_WSL_ROOTFS,
    [switch]$Download = ($env:HM_WSL_DOWNLOAD -eq '1'),
    [switch]$AllowApt = ($env:HM_WSL_ALLOW_APT -eq '1'),
    [int]$TimeoutSeconds = 5400,
    [string]$Label = 'windows-11-x86_64 (native msvc, M04 Mode B, two disposable distributions)',
    [ValidateSet('mode-b', 'systemd-login', 'containers', 'lock')]
    [string]$Scenario = 'mode-b',
    [string[]]$Rows = @(),
    [string]$Driver = 'e2e_platform_m04',
    [string]$Filter = 'windows::native::mode_b::a03_mode_b_fresh_logins_while_windows_locked',
    [int]$ArmSeconds = 43200,
    [string]$PrebuiltLinuxTest = $env:HM_PREBUILT_LINUX_TEST,
    [string]$PrebuiltLinuxTestSha256 = $env:HM_PREBUILT_LINUX_TEST_SHA256,
    [string]$PrebuiltLinuxHook = $env:HM_PREBUILT_LINUX_HOOK,
    [string]$PrebuiltLinuxHookSha256 = $env:HM_PREBUILT_LINUX_HOOK_SHA256,
    [switch]$DryRun,
    [switch]$SelfTest,
    [string]$Out = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$BundleFormat = 'heimdall-m04-mode-b-windows-bundle/1'
$BeginMarker = '-----BEGIN HEIMDALL M04 MODE B WINDOWS BUNDLE-----'
$EndMarker = '-----END HEIMDALL M04 MODE B WINDOWS BUNDLE-----'
$BundleFiles = @('tests.txt', 'commands.txt', 'host.txt', 'build.txt', 'skipped.txt', 'distributions.txt', 'canary-scan.txt')
# The M02 pin (tests/native/m02/run-wsl-distro.sh): the only image this runner imports.
$RootfsUrl = 'https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl'
$RootfsSha256 = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
$User = 'hmtest'
# ⟨M04 U7⟩ The container fixture image's base: alpine:3.21's index digest as Docker Hub served it on
# 2026-11-20 (pulled by digest only), and the local tag the fixture is built as.
$A15Base = 'docker.io/library/alpine@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab'
$A15Image = 'localhost/hm-m04-ssh'
$MinIdleSeconds = 900

# ---------------------------------------------------------------------------------------------
# The M02 runner's pure helpers, loaded from their definitions (its main body never runs).
# ---------------------------------------------------------------------------------------------

$m02Runner = Join-Path $PSScriptRoot '..\m02\run-windows-local.ps1'
$m02Helpers = @('New-RandomHex', 'Get-Sha256Hex', 'New-RedactionRule', 'Get-RedactionForms', 'Invoke-Redaction',
    'Get-CanaryCount', 'Hide-Canary', 'Get-LeakCount', 'Format-TargetOutput', 'Format-CommandLine', 'New-Bundle',
    'Protect-BundleFiles', 'Get-ProtectedMetadata', 'Get-ToolEnvironmentOverrides', 'Get-CrlfFileCount',
    'Get-SshdAtEnd', 'Get-SshdStartScript', 'Get-SshdStopScript', 'Test-PlainAccount', 'Get-FixtureEnvironment',
    'Get-RunRedactionRules', 'Test-SshdAtEndOk', 'Get-StockProfileGrantArguments', 'Get-ScratchParentAction',
    'Remove-EmptyHeimdallTestParent')
$parseErrors = $null
$m02Ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $m02Runner).Path, [ref]$null, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'tests/native/m02/run-windows-local.ps1 does not parse' }
foreach ($f in $m02Ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    if ($m02Helpers -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
foreach ($n in $m02Helpers) {
    if (-not (Get-Command $n -CommandType Function -ErrorAction SilentlyContinue)) { throw "the M02 helper $n is missing" }
}

# ---------------------------------------------------------------------------------------------
# This runner's pure helpers (exercised by -SelfTest)
# ---------------------------------------------------------------------------------------------

# The two distribution names of a run: hm-m04-<8 hex>-1 and -2.
function Get-DistributionNames([string]$Hex) {
    return @("hm-m04-$Hex-1", "hm-m04-$Hex-2")
}

# Whether Name is a distribution name this runner makes.
function Test-OwnDistributionName([string]$Name) {
    return ($Name -cmatch '^hm-m04-[0-9a-f]{8}-[12]\z')
}

# The names in `wsl --list --quiet` output (UTF-8 or UTF-16 noise removed, blank lines dropped).
function ConvertFrom-WslList([string]$Text) {
    return @(($Text -replace "`0", '' -replace "`r", '') -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Which of Created may be unregistered now: this run's pattern, absent from the list taken
# before the run, and registered now. Nothing else is ever unregistered.
function Select-RemovableDistributions([string[]]$Created, [string[]]$Before, [string[]]$Now) {
    return @($Created | Where-Object {
            (Test-OwnDistributionName $_) -and -not ($Before -contains $_) -and ($Now -contains $_)
        })
}

# ⟨M04 fix re-check, M04-FX-RC03⟩ Which install directories of the run's attempted imports are
# kept after cleanup: one whose name is still registered, or every one when the listing after
# cleanup could not be read ($Now is $null). A directory is removed only once its distribution
# is known to be unregistered.
function Select-KeptInstallDirectories([string[]]$Attempted, $Now) {
    if ($null -eq $Now) { return @($Attempted) }
    return @($Attempted | Where-Object { $Now -contains $_ })
}

# Whether two registered sets are equal (order and case of the listing aside).
function Test-SameSet([string[]]$A, [string[]]$B) {
    $x = @($A | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    $y = @($B | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    return (($x -join "`n") -ceq ($y -join "`n"))
}

# The distribution facts kept: this run's lines of `wsl --list --verbose` by name, the others
# only as a count and a digest (their names may be the owner's own).
function Get-DistributionFacts([string]$Verbose, [string[]]$Own) {
    $mine = [System.Collections.Generic.List[string]]::new()
    $others = [System.Collections.Generic.List[string]]::new()
    foreach ($l in ($Verbose -replace "`0", '' -replace "`r", '' -split "`n")) {
        $t = $l.Trim().TrimStart('*').Trim()
        if (-not $t -or $t -match '^NAME\s+STATE') { continue }
        $name = ($t -split '\s+')[0]
        if ($Own -contains $name) { $mine.Add(($t -replace '\s+', ' ')) } else { $others.Add($t.ToLowerInvariant()) }
    }
    $digest = (Get-Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes((($others | Sort-Object) -join "`n")))).Substring(0, 12)
    return [pscustomobject]@{ Own = @($mine); OtherCount = $others.Count; OtherDigest = $digest }
}

# The `test result:` lines of libtest output (one per test binary run).
function Get-TestResultLines([string]$Output) {
    return @(($Output -replace "`r", '') -split "`n" | Where-Object { $_ -match '^test result: ' })
}

# ⟨Windows run at 37cb179b⟩ One command's plain result lines: `### <name> exit=N`, each
# `test <name> ... <outcome>` line and each `test result:` line of its output. Names, outcomes
# and counts only (no path, no user, no host), so they are printed as the run goes and kept in
# results.txt before bundling: the run's verdict survives a failed bundle.
function Format-ResultLines([string]$Name, [int]$Code, [string]$Output) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("### $Name exit=$Code")
    foreach ($l in (($Output -replace "`r", '') -split "`n")) {
        if ($l -match '^test (\S+) \.\.\. (ok|FAILED|ignored)\b') { $lines.Add("test $($Matches[1]) ... $($Matches[2])") }
        elseif ($l -match '^test result: ') { $lines.Add($l.Trim()) }
    }
    return ($lines -join "`n") + "`n"
}

# The test commands, in order (step 7). Each: a name, the cargo arguments, and whether it needs
# HM_WSL_TEST_ALLOW_UNREGISTER=1 (only the last). ⟨M04 U7⟩ a13-new (the deadline and the scp/sftp
# rows alone) runs only when -Rows names it; the a13 set covers them otherwise.
function Get-TestPlan {
    $unregister = 'a13_unregistered_distribution_releases_bindings'
    $mb = 'windows::native::mode_b::'
    return @(
        [pscustomobject]@{ Name = 'a13-mode-b'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', "${mb}a13_", '--skip', $unregister, '--show-output') },
        [pscustomobject]@{ Name = 'a13-new'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', '--exact', "${mb}a13_binding_reaches_its_deadline_and_withdraws", "${mb}a13_binary_scp_sftp_through_bridge", '--show-output') },
        [pscustomobject]@{ Name = 'a12-mode-a'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', 'windows::native::a12_', '--show-output') },
        [pscustomobject]@{ Name = 'a12-flow'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', '--exact', "${mb}a12_git_and_ssh_through_windows_ssh_from_wsl", '--show-output') },
        [pscustomobject]@{ Name = 'wsl-helper-session'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall-wsl', '--lib', '--',
                '--ignored', 'windows_helper_session_over_wsl_exe_in_a_disposable_distribution', '--show-output') },
        [pscustomobject]@{ Name = 'a31-uninstall'; Unregister = $false; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--test-threads=1', '--exact', "${mb}a31_uninstall_with_a_live_mode_b_binding", '--show-output') },
        [pscustomobject]@{ Name = 'a13-unregister'; Unregister = $true; Args = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--',
                '--ignored', '--exact', "${mb}$unregister", '--show-output') }
    )
}

# ⟨M04 U7⟩ The commands a run executes: every one but a13-new when Names is empty; otherwise those
# named, in plan order. $null when a name is not a plan command.
function Select-TestPlan([object[]]$Plan, [string[]]$Names) {
    $wanted = @($Names | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($wanted.Count -eq 0) { return @($Plan | Where-Object { $_.Name -ne 'a13-new' }) }
    foreach ($n in $wanted) { if (-not ($Plan.Name -ccontains $n)) { return $null } }
    return @($Plan | Where-Object { $wanted -ccontains $_.Name })
}

# ⟨M04 U7⟩ How many distributions a scenario creates: two with the harness sshd in -2 (mode-b,
# lock), one otherwise.
function Get-ScenarioDistributionCount([string]$Name) {
    if ($Name -in @('mode-b', 'lock')) { return 2 } else { return 1 }
}

# ⟨M04 U7⟩ A test path the lock driver may be given: letters, digits, `_` and `::` only.
function Test-SafeFilter([string]$Text) {
    return ($Text -cmatch '\A[A-Za-z][A-Za-z0-9_]*(::[A-Za-z0-9_]+)*\z')
}

# ⟨M04 U7⟩ Whether a base image reference is pinned by digest, and a tag is local.
function Test-DigestPinned([string]$Ref) { return ($Ref -cmatch '\A[a-z0-9./_-]+@sha256:[0-9a-f]{64}\z') }
function Test-LocalTag([string]$Tag) { return ($Tag -cmatch '\Alocalhost/[a-z0-9][a-z0-9._-]*\z') }

# ⟨M04 U7; ADR-0004 §2⟩ The armed wait: read the console's idle seconds (Idle) until it reaches
# Min, for at most Seconds of the clock (Now, seconds since the wait began); between readings sleep
# until the earliest moment the rule could be met, at most 30 s. Never Ok below Min, and an
# unreadable reading (-1) never counts.
function Wait-ConsoleIdle([scriptblock]$Idle, [int]$Min, [int]$Seconds, [scriptblock]$Now, [scriptblock]$Sleep) {
    $n = 0
    $last = -1
    while ($true) {
        $n++
        $last = [long](& $Idle)
        if ($last -ge 0 -and $last -ge $Min) { return [pscustomobject]@{ Ok = $true; Samples = $n; Last = $last } }
        if ([double](& $Now) -ge $Seconds) { return [pscustomobject]@{ Ok = $false; Samples = $n; Last = $last } }
        $gap = if ($last -ge 0) { ($Min - $last) * 1000 } else { 30000 }
        & $Sleep ([Math]::Max(1000, [Math]::Min(30000, $gap)))
    }
}

# ⟨M04 U7⟩ The A03 Mode B lock phase over hooks (each a scriptblock; the self-test drives it with
# stubs): HasFlag NAME / WriteFlag NAME TEXT (the driver's handshake files), DriverExited, IdleSeconds,
# Lock (LockWorkStation), LockState (the product's `internal session-lock-state`), Now (seconds),
# Sleep MS. Exit 0 (the locked phase ran under a verified lock and the owner unlocked), 1 (the driver
# failed), 3 (blocked: never idle long enough, the lock not verified, or not locked throughout).
function Invoke-LockPhase([hashtable]$H, [int]$Arm, [int]$VerifySeconds = 30, [int]$LockedDoneSeconds = 1800, [int]$UnlockSeconds = 43200) {
    $facts = [System.Collections.Generic.List[string]]::new()
    $steps = [System.Collections.Generic.List[string]]::new()
    $done = { param($Code, $Why) [pscustomobject]@{ Exit = $Code; Blocked = $Why; Facts = @($facts); Steps = @($steps) } }
    $t0 = [double](& $H.Now)
    while (-not (& $H.HasFlag 'ready')) {
        if ((& $H.HasFlag 'prepare-failed') -or (& $H.DriverExited)) { $steps.Add('the driver did not prepare'); return (& $done 1 '') }
        if ([double](& $H.Now) - $t0 -ge 1800) { & $H.WriteFlag 'abort' 'driver_not_ready'; $steps.Add('the driver was not ready within 1800 s'); return (& $done 1 '') }
        & $H.Sleep 1000
    }
    $steps.Add('the driver prepared, unlocked')
    $armStart = [double](& $H.Now)
    $idle = Wait-ConsoleIdle $H.IdleSeconds $MinIdleSeconds $Arm { [double](& $H.Now) - $armStart } $H.Sleep
    $facts.Add("idle-readings=$($idle.Samples)")
    if (-not $idle.Ok) {
        & $H.WriteFlag 'abort' 'console_not_idle'
        $steps.Add("not locked: the console was idle $($idle.Last) s, below $MinIdleSeconds s, for the whole armed wait ($Arm s)")
        return (& $done 3 "console_not_idle: $($idle.Last) s")
    }
    $facts.Add("idle-seconds-before-lock=$($idle.Last)")
    $before = [string](& $H.LockState)
    if ($before -ne 'unlocked') { & $H.WriteFlag 'abort' "lock_state_$before"; $steps.Add("not locked: the session read $before"); return (& $done 3 "session_not_unlocked: $before") }
    if (-not (& $H.Lock)) { & $H.WriteFlag 'abort' 'lock_failed'; $steps.Add('LockWorkStation failed'); return (& $done 3 'lock_failed') }
    $tl = [double](& $H.Now)
    $verified = $false
    while ([double](& $H.Now) - $tl -lt $VerifySeconds) {
        if ([string](& $H.LockState) -eq 'locked') { $verified = $true; break }
        & $H.Sleep 1000
    }
    if (-not $verified) { & $H.WriteFlag 'abort' 'lock_not_verified'; $steps.Add("the lock was not verified within $VerifySeconds s"); return (& $done 3 'lock_not_verified') }
    $facts.Add("lock-verified-after-seconds=$([int]([double](& $H.Now) - $tl))")
    & $H.WriteFlag 'locked' 'locked'
    $steps.Add('locked (LockWorkStation) and verified; the driver runs its locked steps')
    $interrupted = $false
    $samples = 0
    $tSample = -100.0
    $td = [double](& $H.Now)
    while (-not (& $H.HasFlag 'locked-done')) {
        if (& $H.DriverExited) { $steps.Add('the driver ended during the locked phase'); return (& $done 1 '') }
        $t = [double](& $H.Now)
        if ($t - $td -ge $LockedDoneSeconds) { & $H.WriteFlag 'abort' 'locked_phase_timeout'; $steps.Add('no locked-done'); return (& $done 1 '') }
        if ($t - $tSample -ge 10) { $tSample = $t; $samples++; if ([string](& $H.LockState) -ne 'locked') { $interrupted = $true } }
        & $H.Sleep 1000
    }
    $facts.Add("locked-phase-samples=$samples")
    $tu = [double](& $H.Now)
    while ([string](& $H.LockState) -ne 'unlocked') {
        if ([double](& $H.Now) - $tu -ge $UnlockSeconds) { & $H.WriteFlag 'abort' 'unlock_not_observed'; $steps.Add('the unlock was not observed'); return (& $done 3 'unlock_not_observed') }
        & $H.Sleep 10000
    }
    $facts.Add("unlocked-after-seconds=$([int]([double](& $H.Now) - $tl))")
    & $H.WriteFlag 'expect' ''
    & $H.WriteFlag 'unlocked' 'unlocked'
    $steps.Add('the owner unlocked')
    if ($interrupted) { return (& $done 3 'lock_interrupted: a locked-phase sample was not locked') }
    return (& $done 0 '')
}

# ⟨Windows run at 86cd513b⟩ Wait until Probe answers 'ok', for at most Seconds: one attempt,
# then IntervalMs (Sleep) before the next, while Now (seconds since the wait began) is below
# Seconds. Each attempt is kept as `attempt N: <verdict> (<t> s)`. Probe, Now and Sleep are
# script blocks, so the self-test drives the loop with a scripted probe and clock.
function Wait-SshReachable([scriptblock]$Probe, [int]$Seconds, [int]$IntervalMs, [scriptblock]$Now, [scriptblock]$Sleep) {
    $attempts = [System.Collections.Generic.List[string]]::new()
    $n = 0
    while ($true) {
        $n++
        $verdict = [string](& $Probe)
        $at = [double](& $Now)
        $attempts.Add([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, 'attempt {0}: {1} ({2:0.0} s)', $n, $verdict, $at))
        if ($verdict -eq 'ok') { return [pscustomobject]@{ Ok = $true; Attempts = @($attempts); Count = $n; Seconds = $at } }
        if ($at -ge $Seconds) { return [pscustomobject]@{ Ok = $false; Attempts = @($attempts); Count = $n; Seconds = $at } }
        & $Sleep $IntervalMs
    }
}

# ⟨Windows run at 86cd513b⟩ The networking settings in a .wslconfig's [wsl2] section, read only:
# `networkingMode` and `localhostForwarding`, each its value (a word; anything else is `other`)
# or `unset` (WSL's defaults are NAT and forwarding on). Nothing else of the file is kept.
function Get-WslConfigNetworking([string]$Text) {
    $section = ''
    $found = @{ networkingmode = 'unset'; localhostforwarding = 'unset' }
    foreach ($l in (($Text -replace "`0", '' -replace "`r", '') -split "`n")) {
        $s = $l.Trim()
        if ($s -match '^\[(.+)\]$') { $section = $Matches[1].Trim().ToLowerInvariant(); continue }
        if ($section -ne 'wsl2' -or $s -match '^[#;]') { continue }
        if ($s -match '^([A-Za-z]+)\s*=\s*(.*)$') {
            $k = $Matches[1].ToLowerInvariant()
            if ($found.ContainsKey($k)) {
                $v = ($Matches[2] -replace '\s*[#;].*$', '').Trim()
                $found[$k] = if ($v -cmatch '^[A-Za-z]{1,16}$') { $v } else { 'other' }
            }
        }
    }
    return "networkingMode=$($found['networkingmode']); localhostForwarding=$($found['localhostforwarding'])"
}

# The scripts sent into a distribution (bash, on stdin). Each runs as `bash -s -- <args>`.
function Get-DistroScripts {
    return [ordered]@{
        # As root: target-root.sh PHASE from the Windows copy of the files directory.
        # $1 the files directory (Windows path), $2 the distribution's name, then the phase's own
        # arguments; for `prepare` the files directory is appended as the phase expects.
        'root-phase' = @'
set -u
files=$(wslpath -u "$1") || exit 2
name=$2
phase=$3
shift 3
case "$phase" in
    prepare) exec /bin/bash "$files/target-root.sh" "$name" prepare "$@" "$files" </dev/null ;;
    *) exec /bin/bash "$files/target-root.sh" "$name" "$phase" "$@" </dev/null ;;
esac
'@
        # As root: `[user] default=$2` in /etc/wsl.conf, refusing outside the named distribution.
        'default-user' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
id -u "$2" >/dev/null 2>&1 || { echo "no such user" >&2; exit 1; }
python3 -I - /etc/wsl.conf "$2" <<'PY' || exit 1
import configparser, sys
path, user = sys.argv[1], sys.argv[2]
c = configparser.ConfigParser()
c.optionxform = str
c.read(path)
if not c.has_section("user"):
    c.add_section("user")
c.set("user", "default", user)
with open(path, "w") as f:
    c.write(f)
PY
echo "wsl-conf-user-default=set"
'@
        # As the non-root user: the harness sshd's directory in its home (owner-only), and the
        # facts the redaction needs (never printed into the bundle as such).
        'sshd-dir' = @'
set -u
d="$HOME/$1"
mkdir -m 700 -- "$d" || exit 1
echo "created=$d"
echo "wsluser=$(id -un)"
echo "wslhome=$HOME"
echo "wslhost=$(hostname)"
'@
        # ⟨M04 U7⟩ As root: `[boot] systemd=true` in /etc/wsl.conf (the systemd-login scenario),
        # refusing outside the named distribution.
        'systemd-on' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || { echo "refusing: not inside the disposable distribution" >&2; exit 2; }
[ "$(id -u)" = 0 ] || exit 2
python3 -I - /etc/wsl.conf <<'PY' || exit 1
import configparser, sys
path = sys.argv[1]
c = configparser.ConfigParser()
c.optionxform = str
c.read(path)
if not c.has_section("boot"):
    c.add_section("boot")
c.set("boot", "systemd", "true")
with open(path, "w") as f:
    c.write(f)
PY
echo "wsl-conf-boot-systemd=true"
'@
        # ⟨M04 U7⟩ As root, after the systemd terminate: wait (bounded) for systemd to have booted.
        'systemd-wait' = @'
set -u
[ "${WSL_DISTRO_NAME:-}" = "$1" ] || exit 2
i=0
while [ $i -lt 120 ]; do
    if [ -d /run/systemd/system ]; then
        st=$(systemctl is-system-running 2>/dev/null || true)
        case "$st" in running|degraded) echo "systemd=$st"; exit 0 ;; esac
    fi
    sleep 1; i=$((i+1))
done
echo "systemd=not-booted (${st:-none})"
exit 1
'@
        # ⟨M04 U7⟩ As the non-root user: stage files from the Windows copy ($1) into a new
        # owner-only directory $2 under the home, executable; print where.
        'stage' = @'
set -u
src=$(wslpath -u "$1") || exit 2
d="$HOME/$2"
case "$2" in hm-m04-*) ;; *) exit 2 ;; esac
mkdir -m 700 -- "$d" || exit 1
shift 2
for f in "$@"; do install -m 755 -- "$src/$f" "$d/$f" || exit 1; done
echo "staged=$d"
'@
        # ⟨M04 U7⟩ As root: tests/native/m04/container-engines.sh from the Windows copy of the
        # files directory ($1), with the state directory and its command (the rest).
        'engines' = @'
set -u
files=$(wslpath -u "$1") || exit 2
shift
exec /bin/bash "$files/container-engines.sh" "$@" </dev/null
'@
        # ⟨M04 U7⟩ As the non-root user: one engine's container rows from the staged directory $1:
        # the engine $2, the fixture image $3, the repository root's Windows path $4.
        'a15-run' = @'
set -u
d=$1
repo=$(wslpath -u "$4") || exit 2
case "$2" in podman|docker) ;; *) exit 2 ;; esac
cd "$d" || exit 1
HEIMDALL_E2E_BIN="$d/heimdall" HM_FIXTURE_HOOK="$d/hm-fixture-hook" HM_REPO_ROOT="$repo" \
HEIMDALL_M04_CONTAINER_ENGINE="$2" HEIMDALL_M04_CONTAINER_IMAGE="$3" \
    "$d/e2e_platform_m04" --exact container::a15_container_mounted_flow container::a31_uninstall_with_a_live_container_binding \
    --test-threads=1 --nocapture 2>&1
'@
        # As the non-root user: remove exactly the harness sshd's directory.
        'sshd-dir-remove' = @'
set -u
case "$1" in "$HOME"/hm-m04-fx-*) rm -rf -- "$1" && test ! -e "$1" ;; *) exit 2 ;; esac
'@
        # ⟨Windows run at 86cd513b⟩ As the non-root user, after M02's remote-lib.sh (for
        # hm2_start_time): why the harness sshd was not reachable from Windows. $1 the sshd's
        # directory, $2 its port (empty when it never reported one). Whether the recorded sshd
        # is alive (its PID and start time), whether anything listens on the port inside the
        # distribution (/proc/net/tcp*, which needs no tool), and WSL's networking mode as the
        # distribution reports it. Facts only: no address but the listening one's kind.
        'sshd-diagnosis' = @'
set -u
st="$1/sshd/state"
pid=$(sed -n 's/^pid=//p' "$st" 2>/dev/null)
start=$(sed -n 's/^start=//p' "$st" 2>/dev/null)
case "$pid" in
    '' | *[!0-9]*) echo "sshd-process=no-record" ;;
    *)
        if [ ! -r "/proc/$pid/stat" ]; then echo "sshd-process=gone"
        elif [ "$(hm2_start_time "$pid")" = "$start" ]; then echo "sshd-process=alive"
        else echo "sshd-process=pid-reused"; fi ;;
esac
port=${2:-}
case "$port" in
    '' | *[!0-9]*) echo "sshd-listening=unknown (no port reported)" ;;
    *)
        hex=$(printf ':%04X' "$port")
        l=$(awk -v h="$hex" 'FNR > 1 && $4 == "0A" && substr($2, length($2) - 4) == h { print $2; exit }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)
        case "$l" in
            '') echo "sshd-listening=no" ;;
            0100007F:*) echo "sshd-listening=127.0.0.1" ;;
            00000000:*) echo "sshd-listening=0.0.0.0" ;;
            *) echo "sshd-listening=other" ;;
        esac ;;
esac
if m=$(wslinfo --networking-mode 2>/dev/null) && [ -n "$m" ]; then
    case "$m" in *[!A-Za-z]*) m=other ;; esac
    echo "networking-mode=$m"
else
    echo "networking-mode=unavailable (no wslinfo)"
fi
'@
    }
}

# ---------------------------------------------------------------------------------------------
# -SelfTest
# ---------------------------------------------------------------------------------------------

function Invoke-SelfTest {
    $script:stPass = 0
    $script:stFail = 0
    function Check([string]$Name, [bool]$Ok) {
        if ($Ok) { Write-Host "ok   $Name"; $script:stPass++ } else { Write-Host "FAIL $Name"; $script:stFail++ }
    }
    $names = Get-DistributionNames '0a1b2c3d'
    Check 'N01 two names, hm-m04-<8 hex>-1 and -2' ($names[0] -ceq 'hm-m04-0a1b2c3d-1' -and $names[1] -ceq 'hm-m04-0a1b2c3d-2')
    Check 'N02 only this runner''s pattern is its own' ((Test-OwnDistributionName 'hm-m04-0a1b2c3d-2') -and -not (Test-OwnDistributionName 'hm-m04-0A1B2C3D-1') -and
        -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d-3') -and -not (Test-OwnDistributionName 'Ubuntu') -and -not (Test-OwnDistributionName 'hm-m03-0a1b2c3d') -and
        -not (Test-OwnDistributionName 'hm-m04-0a1b2c3d-1 ') -and -not (Test-OwnDistributionName "hm-m04-0a1b2c3d-1`n"))
    $parsed = @(ConvertFrom-WslList "Ubuntu`r`n`r`nhm-m04-0a1b2c3d-1`r`nDeb`0ian`n")
    Check 'N03 the quiet list parses (CR, NUL and blank lines removed)' (($parsed -join ',') -ceq 'Ubuntu,hm-m04-0a1b2c3d-1,Debian')
    $before = @('Ubuntu', 'hm-m04-0a1b2c3d-2')
    $now = @('Ubuntu', 'hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2', 'hm-m04-ffffffff-1')
    $rm = @(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2', 'Ubuntu', 'hm-m04-99999999-1') $before $now)
    Check 'C01 cleanup removes only a created name of the pattern, absent before, registered now' (($rm -join ',') -ceq 'hm-m04-0a1b2c3d-1')
    Check 'C02 a created name already gone (the unregister row removed it) is not unregistered again' (@(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1') @() @('Ubuntu')).Count -eq 0)
    Check 'C04 an import recorded only as attempted (its listing failed, or Ctrl-C landed before it was recorded) is still unregistered when it is registered' (
        (@(Select-RemovableDistributions @('hm-m04-0a1b2c3d-1') @('Ubuntu') @('Ubuntu', 'hm-m04-0a1b2c3d-1')) -join ',') -ceq 'hm-m04-0a1b2c3d-1')
    Check 'C05 an install directory is kept while its distribution is registered, and all are kept when the listing is unreadable' (
        ((Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2') @('Ubuntu', 'hm-m04-0a1b2c3d-2')) -join ',') -ceq 'hm-m04-0a1b2c3d-2' -and
        ((Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2') $null) -join ',') -ceq 'hm-m04-0a1b2c3d-1,hm-m04-0a1b2c3d-2' -and
        @(Select-KeptInstallDirectories @('hm-m04-0a1b2c3d-1') @('Ubuntu')).Count -eq 0)
    Check 'C03 the registered set compares as a set' ((Test-SameSet @('Ubuntu', 'Debian') @('debian', 'Ubuntu')) -and -not (Test-SameSet @('Ubuntu') @('Ubuntu', 'hm-m04-0a1b2c3d-1')))
    $verbose = "  NAME                 STATE           VERSION`r`n* OwnersBox            Running         2`r`n  hm-m04-0a1b2c3d-1    Stopped         2`r`n  Personal-Name        Stopped         2`r`n"
    $facts = Get-DistributionFacts $verbose @('hm-m04-0a1b2c3d-1', 'hm-m04-0a1b2c3d-2')
    Check 'D01 only this run''s distributions are recorded by name; the others as a count and digest' (
        ($facts.Own -join '|') -ceq 'hm-m04-0a1b2c3d-1 Stopped 2' -and $facts.OtherCount -eq 2 -and $facts.OtherDigest.Length -eq 12)
    $facts2 = Get-DistributionFacts ($verbose -replace 'Running', 'Stopped') @('hm-m04-0a1b2c3d-1')
    Check 'D02 the digest of the others follows their state, never their names in the bundle' ($facts2.OtherDigest -ne $facts.OtherDigest)
    $libtestOut = "running 2 tests`r`ntest a ... ok`r`ntest result: ok. 2 passed; 0 failed; 0 ignored`r`n`r`ntest result: ok. 0 passed; 0 failed`r`n"
    $lines = @(Get-TestResultLines $libtestOut)
    Check 'T01 the test result lines' ($lines.Count -eq 2 -and $lines[0] -ceq 'test result: ok. 2 passed; 0 failed; 0 ignored')
    $plan = Get-TestPlan
    Check 'P01 the plan: A13, the U7 A13 rows alone, A12, the A12 flow, the helper session, the A31 uninstall, then the unregister row' (
        (($plan | ForEach-Object Name) -join ',') -ceq 'a13-mode-b,a13-new,a12-mode-a,a12-flow,wsl-helper-session,a31-uninstall,a13-unregister')
    Check 'P02 only the last carries HM_WSL_TEST_ALLOW_UNREGISTER, and it runs that one test exactly' (
        (@($plan | Where-Object Unregister).Count -eq 1) -and $plan[-1].Unregister -and ($plan[-1].Args -contains '--exact') -and
        ($plan[-1].Args -contains 'windows::native::mode_b::a13_unregistered_distribution_releases_bindings'))
    Check 'P03 the A13 set skips the unregister row and runs on one thread' (($plan[0].Args -contains '--skip') -and
        ($plan[0].Args -contains 'a13_unregistered_distribution_releases_bindings') -and ($plan[0].Args -contains '--test-threads=1'))
    Check 'P04 every command runs only ignored tests (the native rows), --locked' (@($plan | Where-Object { ($_.Args -contains '--ignored') -and ($_.Args -contains '--locked') }).Count -eq $plan.Count)
    $def = @(Select-TestPlan $plan @())
    Check 'P05 the default run is every command but a13-new, the uninstall row before the unregister row' (
        (($def | ForEach-Object Name) -join ',') -ceq 'a13-mode-b,a12-mode-a,a12-flow,wsl-helper-session,a31-uninstall,a13-unregister')
    $sel = @(Select-TestPlan $plan @('a31-uninstall,a13-new', 'a12-flow'))
    Check 'P06 -Rows picks commands by name, in plan order (commas or separate values)' ((($sel | ForEach-Object Name) -join ',') -ceq 'a13-new,a12-flow,a31-uninstall')
    Check 'P07 -Rows naming no plan command is refused ($null), and names are case-sensitive' (
        ($null -eq (Select-TestPlan $plan @('a13-nope'))) -and ($null -eq (Select-TestPlan $plan @('A12-flow'))))
    Check 'P08 a13-new runs exactly the deadline and the scp/sftp rows' (($plan[1].Args -contains '--exact') -and
        ($plan[1].Args -contains 'windows::native::mode_b::a13_binding_reaches_its_deadline_and_withdraws') -and
        ($plan[1].Args -contains 'windows::native::mode_b::a13_binary_scp_sftp_through_bridge'))
    Check 'N04 two distributions for mode-b and lock, one for systemd-login and containers' (
        (Get-ScenarioDistributionCount 'mode-b') -eq 2 -and (Get-ScenarioDistributionCount 'lock') -eq 2 -and
        (Get-ScenarioDistributionCount 'systemd-login') -eq 1 -and (Get-ScenarioDistributionCount 'containers') -eq 1)
    Check 'F01 the lock driver filter is a test path only' ((Test-SafeFilter 'windows::native::mode_b::a03_mode_b_fresh_logins_while_windows_locked') -and
        -not (Test-SafeFilter 'a03 --nocapture') -and -not (Test-SafeFilter 'a03;x') -and -not (Test-SafeFilter '') -and -not (Test-SafeFilter 'a::') -and -not (Test-SafeFilter '::a'))
    Check 'G01 the container base is pinned by digest and the fixture tag is local' ((Test-DigestPinned $A15Base) -and (Test-LocalTag $A15Image) -and
        -not (Test-DigestPinned 'docker.io/library/alpine:3.21') -and -not (Test-DigestPinned "alpine@sha256:$('0' * 63)") -and -not (Test-LocalTag 'docker.io/x'))
    # ⟨M04 U7; ADR-0004 §2⟩ The armed wait and the lock phase, on scripted clocks and hooks.
    $script:fakeNow = 0.0
    $script:idleSeq = @(60)
    $script:idleAt = 0
    $idleHook = { $v = $script:idleSeq[[Math]::Min($script:idleAt, $script:idleSeq.Count - 1)]; $script:idleAt++; $v }
    $nowHook = { $script:fakeNow }
    $sleepHook = { param($Ms) $script:fakeNow += $Ms / 1000 }
    $wi = Wait-ConsoleIdle $idleHook 900 600 $nowHook $sleepHook
    Check 'L01 the armed wait never succeeds below 900 s of idle: a console idle 60 s throughout is given up when the arm ends' (-not $wi.Ok -and $wi.Last -eq 60 -and $script:fakeNow -ge 600)
    $script:fakeNow = 0.0; $script:idleSeq = @(100, 500, 899, 905); $script:idleAt = 0
    $wi = Wait-ConsoleIdle $idleHook 900 43200 $nowHook $sleepHook
    Check 'L02 it succeeds at the first reading of at least 900 s (899 is not enough)' ($wi.Ok -and $wi.Samples -eq 4 -and $wi.Last -eq 905)
    $script:fakeNow = 0.0; $script:idleSeq = @(-1); $script:idleAt = 0
    $wi = Wait-ConsoleIdle $idleHook 900 120 $nowHook $sleepHook
    Check 'L03 an unreadable idle reading (-1) never counts' (-not $wi.Ok)
    # The lock phase: stub hooks over an in-memory flag set and lock state.
    function New-LockStub([long[]]$Idle, [bool]$Locks, [string[]]$States, [bool]$Ready = $true) {
        $st = [pscustomobject]@{ Flags = [System.Collections.Generic.List[string]]::new(); Locked = 0; Now = 0.0; IdleAt = 0; StateAt = 0; Idle = $Idle; States = $States; Locks = $Locks; Ready = $Ready }
        $h = @{
            HasFlag = { param($Name) if ($Name -eq 'ready') { return $st.Ready }; if ($Name -eq 'locked-done') { return ($st.Flags -contains 'locked') -and $st.Now -ge 50 }; return $st.Flags -contains $Name }.GetNewClosure()
            WriteFlag = { param($Name, $Text) $st.Flags.Add($Name) }.GetNewClosure()
            DriverExited = { $false }
            IdleSeconds = { $v = $st.Idle[[Math]::Min($st.IdleAt, $st.Idle.Count - 1)]; $st.IdleAt++; $v }.GetNewClosure()
            Lock = { $st.Locked++; return $st.Locks }.GetNewClosure()
            LockState = { $v = $st.States[[Math]::Min($st.StateAt, $st.States.Count - 1)]; $st.StateAt++; $v }.GetNewClosure()
            Now = { $st.Now }.GetNewClosure()
            Sleep = { param($Ms) $st.Now += $Ms / 1000 }.GetNewClosure()
        }
        return [pscustomobject]@{ H = $h; S = $st }
    }
    $k = New-LockStub @(60) $true @('unlocked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L04 windows_lock_run_refuses_without_idle_15_min (M04): never idle 900 s -> exit 3, console_not_idle, never locked, `abort` written' (
        $lp.Exit -eq 3 -and $lp.Blocked.StartsWith('console_not_idle') -and $k.S.Locked -eq 0 -and ($k.S.Flags -contains 'abort') -and -not ($k.S.Flags -contains 'locked'))
    $k = New-LockStub @(950) $true @('unlocked', 'locked', 'locked', 'locked', 'locked', 'locked', 'locked', 'locked', 'unlocked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L05 idle 900 s or more -> one LockWorkStation, verified, then locked, expect and unlocked in that order, exit 0' (
        $lp.Exit -eq 0 -and $k.S.Locked -eq 1 -and (($k.S.Flags -join ',') -ceq 'locked,expect,unlocked'))
    $k = New-LockStub @(950) $true @('unlocked', 'unlocked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L06 a lock the product''s query never reads as locked within 30 s -> exit 3, lock_not_verified, `abort`, no `locked`' (
        $lp.Exit -eq 3 -and $lp.Blocked -eq 'lock_not_verified' -and ($k.S.Flags -contains 'abort') -and -not ($k.S.Flags -contains 'locked'))
    $k = New-LockStub @(950) $true @('unlocked', 'locked', 'locked', 'unlocked', 'locked', 'locked', 'locked', 'locked', 'unlocked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L07 a locked-phase sample that is not locked -> exit 3, lock_interrupted (never verified)' ($lp.Exit -eq 3 -and $lp.Blocked.StartsWith('lock_interrupted'))
    $k = New-LockStub @(950) $true @('locked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L08 a session not unlocked before the lock -> exit 3 and LockWorkStation is never called' ($lp.Exit -eq 3 -and $k.S.Locked -eq 0)
    $k = New-LockStub @(950) $false @('unlocked')
    $lp = Invoke-LockPhase $k.H 600
    Check 'L09 a failed LockWorkStation -> exit 3, lock_failed, `abort`' ($lp.Exit -eq 3 -and $lp.Blocked -eq 'lock_failed' -and ($k.S.Flags -contains 'abort'))
    $k = New-LockStub @(950) $true @('unlocked') $false
    $k.H['DriverExited'] = { $true }
    $lp = Invoke-LockPhase $k.H 600
    Check 'L10 a driver that ends before `ready` -> exit 1, never locked' ($lp.Exit -eq 1 -and $k.S.Locked -eq 0)
    $rules = Get-RunRedactionRules @{ wslhost = 'PCNAME' } 'C:\S\hm-m04-modeb-00' 'C:\Users\fixtureuser' 'fixtureuser' 'PCNAME' 'pcname.example'
    $p = Protect-BundleFiles @{ 'host.txt' = "home C:\Users\fixtureuser\x on PCNAME run C:\S\hm-m04-modeb-00\src`n" } $rules
    Check 'R01 the M02 redaction applies (home, user, host, run directory)' ($p.Files['host.txt'] -ceq "home <winhome>\x on <winhost> run <run>\src`n" -and $p.Leaks -eq 0)
    Check 'K01 the scratch registry parent is removed only when empty, through the M02 runner''s helpers' (
        (Get-ScratchParentAction $true 0 0) -eq 'remove' -and (Get-ScratchParentAction $true 0 1) -eq 'nonempty-kept' -and
        (Get-ScratchParentAction $false 0 0) -eq 'absent' -and (Get-Command Remove-EmptyHeimdallTestParent -CommandType Function -ErrorAction SilentlyContinue))
    # ⟨Windows run at 86cd513b⟩ The reachability wait, on a scripted probe and clock.
    $script:fakeNow = 0.0
    $script:probeSeq = @('refused', 'timeout', 'ok')
    $script:probeAt = 0
    $wr = Wait-SshReachable { $v = $script:probeSeq[$script:probeAt]; $script:probeAt++; $v } 90 2000 { $script:fakeNow } { param($Ms) $script:fakeNow += $Ms / 1000 }
    Check 'W01 the reachability wait retries until ok, and keeps each attempt' (
        $wr.Ok -and $wr.Count -eq 3 -and (($wr.Attempts -join '|') -ceq 'attempt 1: refused (0.0 s)|attempt 2: timeout (2.0 s)|attempt 3: ok (4.0 s)'))
    $script:fakeNow = 0.0
    $wr = Wait-SshReachable { 'refused' } 90 2000 { $script:fakeNow } { param($Ms) $script:fakeNow += $Ms / 1000 }
    Check 'W02 a sshd never reachable is given up after 90 s, with every attempt kept' (
        -not $wr.Ok -and $wr.Count -eq 46 -and $wr.Attempts[-1] -ceq 'attempt 46: refused (90.0 s)')
    Check 'W03 .wslconfig: only [wsl2] networkingMode and localhostForwarding are read, as words' (
        (Get-WslConfigNetworking "[experimental]`r`nnetworkingMode=nat`r`n[wsl2]`r`nmemory=8GB`r`nnetworkingMode = mirrored # note`r`n;localhostForwarding=false`r`n") -ceq 'networkingMode=mirrored; localhostForwarding=unset' -and
        (Get-WslConfigNetworking '') -ceq 'networkingMode=unset; localhostForwarding=unset' -and
        (Get-WslConfigNetworking "[wsl2]`nlocalhostForwarding=true`nnetworkingMode=C:\x") -ceq 'networkingMode=other; localhostForwarding=true')
    $selfText = [System.IO.File]::ReadAllText($PSCommandPath)
    Check 'E01 one preparation per run: the second distribution comes from the first''s export, which is removed after its import and at cleanup' (
        $selfText.Contains('''--export'', $names[0], $preparedTar') -and $selfText.Contains('Remove-Item -LiteralPath $preparedTar') -and
        $selfText.Contains('(Join-Path $run ''hm-m04-prepared.tar''), (Join-Path $run ''lock-state'')'))
    Check 'A01 the run root gets the stock list from the M02 runner''s helper' (
        ((Get-StockProfileGrantArguments 'S\run' 'S-1-5-21-1-2-3-1001') -join ' ') -ceq 'S\run /inheritance:r /grant:r *S-1-5-21-1-2-3-1001:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F')
    # ⟨Windows run at 37cb179b⟩ The file table as the run builds it: every bundle file, through
    # the same protection; `.Files` stays a table that a variable holds and indexes.
    $realistic = @{}
    foreach ($f in $BundleFiles) { $realistic[$f] = "### x`nhome C:\Users\fixtureuser\y`n" }
    $prot = Protect-BundleFiles $realistic $rules
    $table = $prot.Files
    $table['canary-scan.txt'] = 'n'
    Check 'B02 Protect-BundleFiles returns one object whose .Files is a table every bundle file can be indexed in' (
        $prot -isnot [array] -and $table -is [System.Collections.IDictionary] -and @($table.Keys).Count -eq $BundleFiles.Count -and
        $table['canary-scan.txt'] -ceq 'n' -and $table['commands.txt'].Contains('<winhome>'))
    $rl = Format-ResultLines 'a13-mode-b' 101 "running 2 tests`r`ntest windows::native::mode_b::a13_x ... ok`r`ntest windows::native::mode_b::a13_y ... FAILED`r`n  at C:\Users\fixtureuser\z`r`ntest result: FAILED. 1 passed; 1 failed; 0 ignored`r`n"
    Check 'B03 the plain result lines: the command and its exit, each test''s outcome, the result line, and nothing else' (
        $rl -ceq "### a13-mode-b exit=101`ntest windows::native::mode_b::a13_x ... ok`ntest windows::native::mode_b::a13_y ... FAILED`ntest result: FAILED. 1 passed; 1 failed; 0 ignored`n")
    $b = New-Bundle @{ 'tests.txt' = 'x'; 'distributions.txt' = 'y' } @{ commit = ('0' * 40); exit = 0 }
    Check 'B01 the bundle carries this runner''s format and markers' ($b.Json.Contains($BundleFormat) -and $b.Text.StartsWith($BeginMarker) -and $b.Text.TrimEnd().EndsWith($EndMarker))
    # ⟨Windows run at 39f48be8⟩ No assignment in this script to a parameter's name: PowerShell
    # names are case-insensitive, so `$out = <hashtable>` turned into the [string] `-Out`.
    $selfAst = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)
    $paramNames = @($selfAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() })
    $clashes = @($selfAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
            Where-Object { $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                ($paramNames -contains $_.Left.VariablePath.UserPath.ToLowerInvariant()) })
    Check 'S02 nothing assigns to a parameter''s name (case-insensitive)' ($clashes.Count -eq 0)
    # bash -n of every script sent into a distribution (and the M02 sshd start and stop scripts).
    $bash = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $bash) {
        $scripts = Get-DistroScripts
        $scripts['sshd-start (M02)'] = Get-SshdStartScript
        $scripts['sshd-stop (M02)'] = Get-SshdStopScript
        foreach ($k in $scripts.Keys) {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tmp, ($scripts[$k] -replace "`r`n", "`n"))
                & $bash.Source -n $tmp 2>$null
                Check "S01 bash -n: $k" ($LASTEXITCODE -eq 0)
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    } else {
        Write-Host 'skip S01 bash -n (no bash on PATH)'
    }
    Write-Host "selftest: $script:stPass passed, $script:stFail failed"
    if ($script:stFail -ne 0) { exit 1 }
    exit 0
}

if ($SelfTest) { Invoke-SelfTest }

# ---------------------------------------------------------------------------------------------
# Inputs (step 1): nothing is created before these pass.
# ---------------------------------------------------------------------------------------------

function Stop-Run([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("run-mode-b-windows: $Message")
    exit $Code
}

if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Run 2 '-Commit must be the 40-hex commit' }
if ($TimeoutSeconds -lt 600) { Stop-Run 2 '-TimeoutSeconds must be at least 600' }
if ([string]::IsNullOrWhiteSpace($PrebuiltHeimdall)) { Stop-Run 3 'blocked: set -PrebuiltHeimdall (HM_PREBUILT_HEIMDALL) to the Linux heimdall cross-built on the build host' }
if ([string]::IsNullOrWhiteSpace($PrebuiltSha256)) { Stop-Run 3 'blocked: set -PrebuiltSha256 (HM_PREBUILT_SHA256) to the digest the build host recorded' }
$wantSha = $PrebuiltSha256.Trim().ToLowerInvariant()
if ($wantSha -notmatch '^[0-9a-f]{64}$') { Stop-Run 2 'bad -PrebuiltSha256 (64 hex digits)' }
if (-not $Rootfs -and -not $Download) { Stop-Run 3 'blocked: the pinned image (-Rootfs / HM_WSL_ROOTFS, or -Download / HM_WSL_DOWNLOAD=1)' }
# ⟨M04 U7⟩ The scenario's own inputs.
$selectedPlan = Select-TestPlan (Get-TestPlan) $Rows
if ($null -eq $selectedPlan) { Stop-Run 2 "-Rows names a command that is not in the plan ($(((Get-TestPlan).Name) -join ', '))" }
if ($Scenario -ne 'mode-b' -and @($Rows | Where-Object { $_ }).Count -gt 0) { Stop-Run 2 '-Rows applies to the mode-b scenario only' }
if ($Scenario -eq 'lock') {
    if (-not (Test-SafeFilter $Filter)) { Stop-Run 2 '-Filter must be a test path (letters, digits, _ and ::)' }
    if ($Driver -cnotmatch '\A[a-z0-9_]+\z') { Stop-Run 2 '-Driver must be a cargo test target name' }
    if ($ArmSeconds -lt 0 -or $ArmSeconds -gt 43200) { Stop-Run 2 '-ArmSeconds must be 0 to 43200' }
}
$linuxInputs = @()
if ($Scenario -eq 'containers') {
    foreach ($pair in @(@('-PrebuiltLinuxTest', $PrebuiltLinuxTest, $PrebuiltLinuxTestSha256, 'e2e_platform_m04'), @('-PrebuiltLinuxHook', $PrebuiltLinuxHook, $PrebuiltLinuxHookSha256, 'hm-fixture-hook'))) {
        if ([string]::IsNullOrWhiteSpace($pair[1])) { Stop-Run 3 "blocked: set $($pair[0]) (the cross-built Linux file of the same commit)" }
        if ([string]::IsNullOrWhiteSpace($pair[2])) { Stop-Run 3 "blocked: set $($pair[0])Sha256 to the digest the build host recorded" }
        $want = $pair[2].Trim().ToLowerInvariant()
        if ($want -notmatch '^[0-9a-f]{64}$') { Stop-Run 2 "bad $($pair[0])Sha256 (64 hex digits)" }
        $linuxInputs += , [pscustomobject]@{ Param = $pair[0]; Path = $pair[1]; Sha = $want; As = $pair[3] }
    }
    if (-not (Test-DigestPinned $A15Base) -or -not (Test-LocalTag $A15Image)) { Stop-Run 2 'the fixture image base must be pinned by digest' }
}
$distroCount = Get-ScenarioDistributionCount $Scenario

if ($DryRun) {
    $hex = New-RandomHex 4
    $plan = Get-TestPlan
    Write-Output 'dry run: nothing is created, no distribution, network, toolchain or build step runs'
    Write-Output "scenario=$Scenario ($distroCount distribution$(if ($distroCount -ne 1) { 's' }))"
    Write-Output "commit=$Commit"
    Write-Output "run-directory=<ScratchRoot>\hm-m04-modeb-<random>"
    Write-Output "distributions=$((Get-DistributionNames $hex) -join ' ') (refused when either is registered)"
    Write-Output "image=$(if ($Rootfs) { 'HM_WSL_ROOTFS' } else { "download $RootfsUrl" }) sha256 $RootfsSha256"
    Write-Output "apt-inside-the-distributions=$(if ($AllowApt) { 'allowed' } else { 'not allowed (missing tools stop the run, exit 3)' })"
    Write-Output "prebuilt-heimdall=$(if (Test-Path -LiteralPath $PrebuiltHeimdall -PathType Leaf) { 'present' } else { 'not found here' })"
    Write-Output "user=$User (non-root, in both distributions)"
    Write-Output 'preparation=once: -1 from the image and prepared; -2 imported from -1''s export (removed after the import)'
    Write-Output 'harness-sshd=in -2 as the user (hm2_sshd_start), reachable from Windows within 90 s of attempts (else the diagnosis in host.txt), HM_FIXTURE_SSHD_* exported'
    switch ($Scenario) {
        'mode-b' {
            foreach ($s in $selectedPlan) {
                $extra = if ($s.Unregister) { ' [HM_WSL_TEST_ALLOW_UNREGISTER=1; last, alone]' } else { '' }
                Write-Output "test $($s.Name): cargo $($s.Args -join ' ')$extra"
            }
        }
        'systemd-login' { Write-Output 'boot=systemd=true inside the distribution only, then a terminate; heimdall staged in the user''s home'; Write-Output 'test: cargo test --locked -p heimdall --test e2e_platform_m04 -- --ignored --exact service_login::wsl_login::linux_login_entry_starts_runtime_at_next_login' }
        'containers' {
            Write-Output "engines=podman (rootless, uidmap) and docker.io (rootful, dockerd by hand) inside the distribution only; base $A15Base; fixture $A15Image"
            foreach ($i in $linuxInputs) { Write-Output "$($i.Param)=$(if (Test-Path -LiteralPath $i.Path -PathType Leaf) { 'present' } else { 'not found here' })" }
            Write-Output 'test: e2e_platform_m04 --exact container::a15_container_mounted_flow container::a31_uninstall_with_a_live_container_binding, once per engine, as the user'
            Write-Output 'engine-cleanup=only the containers and images this run recorded; the recorded dockerd stopped'
        }
        'lock' { Write-Output "lock=armed: wait up to $ArmSeconds s for $MinIdleSeconds s of console idle, then LockWorkStation, verified; the owner unlocks"; Write-Output "driver=cargo test --locked -p heimdall --test $Driver -- --ignored --exact $Filter" }
    }
    Write-Output 'cleanup=hm2_stop_recorded for the sshd; terminate + unregister only this run''s distributions by exact name; registered set compared; run directories removed'
    exit 0
}

if (-not $IsWindows) { Stop-Run 2 'run-mode-b-windows.ps1 runs on the Windows PC itself (use -DryRun or -SelfTest elsewhere)' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Run 2 'refusing to run elevated: this runner never needs administrator rights'
}
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) { Stop-Run 2 '-ScratchRoot is required' }
# Created when missing (with its missing parents); an existing one is checked as it is.
if (-not (Test-Path -LiteralPath $ScratchRoot)) { [void][System.IO.Directory]::CreateDirectory($ScratchRoot) }
$rootItem = Get-Item -LiteralPath $ScratchRoot -Force -ErrorAction SilentlyContinue
if ($null -eq $rootItem -or -not $rootItem.PSIsContainer) { Stop-Run 2 '-ScratchRoot must be an existing directory' }
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Run 2 '-ScratchRoot is a reparse point: refused' }
$helperItem = Get-Item -LiteralPath $PrebuiltHeimdall -Force -ErrorAction SilentlyContinue
if ($null -eq $helperItem -or $helperItem.PSIsContainer) { Stop-Run 3 'blocked: -PrebuiltHeimdall is not a regular file' }
$haveSha = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($helperItem.FullName))
if ($haveSha -ne $wantSha) { Stop-Run 1 "prebuilt heimdall sha256 mismatch: file $haveSha, expected $wantSha; nothing created" }
foreach ($i in $linuxInputs) {
    $it = Get-Item -LiteralPath $i.Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $it -or $it.PSIsContainer) { Stop-Run 3 "blocked: $($i.Param) is not a regular file" }
    $got = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($it.FullName))
    if ($got -ne $i.Sha) { Stop-Run 1 "$($i.Param) sha256 mismatch: file $got, expected $($i.Sha); nothing created" }
    $i | Add-Member -NotePropertyName Full -NotePropertyValue $it.FullName
}
if ($Rootfs) {
    $rootfsItem = Get-Item -LiteralPath $Rootfs -Force -ErrorAction SilentlyContinue
    if ($null -eq $rootfsItem -or $rootfsItem.PSIsContainer) { Stop-Run 3 'blocked: -Rootfs is not a file' }
    if ((Get-Sha256Hex ([System.IO.File]::ReadAllBytes($rootfsItem.FullName))) -ne $RootfsSha256) { Stop-Run 3 'the image is not the pinned one (sha256 mismatch); nothing created' }
}

# ---------------------------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------------------------

$sys32 = Join-Path $env:SystemRoot 'System32'
$wslExe = Join-Path $sys32 'wsl.exe'
$runPrefix = if ($Scenario -eq 'mode-b') { 'hm-m04-modeb-' } else { "hm-m04-$Scenario-" }
$run = Join-Path $rootItem.FullName ($runPrefix + (New-RandomHex 6))
$runLabel = if ($PSBoundParameters.ContainsKey('Label')) { $Label } else {
    switch ($Scenario) {
        'mode-b' { $Label }
        'lock' { 'windows-11-x86_64 (native msvc, M04 A03 Mode B lock, two disposable distributions)' }
        'systemd-login' { 'windows-11-x86_64 (native msvc, M04 login entry, one disposable systemd distribution)' }
        'containers' { 'windows-11-x86_64 (M04 containers, one disposable distribution with Podman and Docker Engine)' }
    }
}
if (Test-Path -LiteralPath $run) { Stop-Run 2 'the run directory exists already' }
[void][System.IO.Directory]::CreateDirectory($run)
# The stock profile list on this run's root before anything is created inside it (ADR-0010 §11;
# the M02 runner's Get-StockProfileGrantArguments); recorded below, its SIDs redacted.
$stockOut = (& (Join-Path $env:SystemRoot 'System32\icacls.exe') @(Get-StockProfileGrantArguments $run ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) 2>&1 | Out-String)
$stockRc = $LASTEXITCODE
$src = Join-Path $run 'src'
$tools = Join-Path $run 'toolchain'
$wtmp = Join-Path $run 'tmp'
$files = Join-Path $run 'files'
$distroRoot = Join-Path $run 'distros'
$sshdDir = Join-Path $run 'sshd'
$bundleDir = Join-Path $run 'bundle'
$githome = Join-Path $run 'githome'
foreach ($d in @($tools, $wtmp, $files, $distroRoot, $sshdDir, $bundleDir, $githome)) { [void][System.IO.Directory]::CreateDirectory($d) }
$resultsFile = Join-Path $bundleDir 'results.txt'
$emptyGitConfig = Join-Path $githome 'empty.gitconfig'
[System.IO.File]::WriteAllText($emptyGitConfig, '')

$started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$runClock = [System.Diagnostics.Stopwatch]::StartNew()
$commands = [System.Text.StringBuilder]::new()
$hostFacts = [System.Text.StringBuilder]::new()
$tests = [System.Text.StringBuilder]::new()
$build = [System.Text.StringBuilder]::new()
$skipped = [System.Text.StringBuilder]::new()
$distFacts = [System.Text.StringBuilder]::new()
$overall = 0
$created = [System.Collections.Generic.List[string]]::new()
# ⟨M04-FX-RC03⟩ Every name an import was started for, recorded before the import runs.
$attempted = [System.Collections.Generic.List[string]]::new()
$before = @()
$names = @()
$sshdProc = $null
$sshdErr = $null
$sshdWslDir = ''
$wv = @{}
# ⟨M04 U7⟩ The scenarios' own state (set as each step runs; read by the cleanup).
$fixtureEnv = @{}
$loginHeimdall = ''
$a15Dir = ''
$enginesState = ''
$remoteLib = ''
$scripts = Get-DistroScripts

# ⟨Windows run at 86cd513b⟩ Each command line carries the time since the previous one (the
# step it closes), and is printed as the run goes.
$stepClock = [System.Diagnostics.Stopwatch]::StartNew()
function Add-Command([int]$Rc, [string]$What) {
    $line = Format-CommandLine $Rc ('{0} [{1:0} s]' -f $What, $stepClock.Elapsed.TotalSeconds)
    $stepClock.Restart()
    [void]$commands.Append($line)
    Write-Host $line.TrimEnd()
}
function Add-Fact([string]$Key, [string]$Value) { [void]$hostFacts.Append("$Key=$(($Value -replace "`r", '') -split "`n" | Select-Object -First 1)`n") }

# An environment for a child: the inherited one without agent, askpass, Git, Heimdall, fixture,
# WSL test, repository and toolchain variables, plus Set.
function New-ChildEnvironment([hashtable]$Set) {
    $envs = @{}
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$e.Key
        if ($k -match '^(GIT_|HEIMDALL_|HM_|SSH_AUTH_SOCK$|SSH_AGENT_PID$|SSH_ASKPASS|RUSTUP_|CARGO|WSLENV$)') { continue }
        $envs[$k] = [string]$e.Value
    }
    foreach ($k in $Set.Keys) { $envs[$k] = [string]$Set[$k] }
    return $envs
}

# Run a program (no shell) with an environment and a timeout; on a timeout the process tree this
# call started is killed through its own handle.
function Invoke-Bounded([string]$File, [string[]]$Arguments, [hashtable]$Environment, [string]$Cwd, [int]$Seconds, [string]$StdIn = $null) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($File)
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $Cwd
    if ($null -ne $Environment) {
        $psi.Environment.Clear()
        foreach ($k in $Environment.Keys) { $psi.Environment[$k] = $Environment[$k] }
    }
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if ($null -ne $StdIn) { $p.StandardInput.Write(($StdIn -replace "`r`n", "`n")) }
    $p.StandardInput.Close()
    $timedOut = -not $p.WaitForExit($Seconds * 1000)
    if ($timedOut) { $p.Kill($true); $p.WaitForExit() }
    $p.WaitForExit()
    $code = if ($timedOut) { 124 } else { $p.ExitCode }
    $text = $o.Result + $e.Result
    if ($timedOut) { $text += "`n(timed out after $Seconds s; the process tree this run started was stopped)`n" }
    $p.Dispose()
    return [pscustomobject]@{ Code = $code; Output = $text; TimedOut = $timedOut }
}

$wslEnv = New-ChildEnvironment @{ WSL_UTF8 = '1' }
# wsl.exe itself (list, import, terminate, unregister): never `--shutdown`.
function Invoke-WslExe([string[]]$Arguments, [int]$Seconds = 600) {
    return Invoke-Bounded $wslExe $Arguments $wslEnv $run $Seconds
}
# A script inside one of this run's distributions, as Account, on stdin.
function Invoke-InDistro([string]$Name, [string]$Account, [string]$Script, [string[]]$ScriptArgs, [int]$Seconds = 1800) {
    if (-not ($names -contains $Name)) { throw 'refusing a distribution this run did not create' }
    return Invoke-Bounded $wslExe (@('-d', $Name, '-u', $Account, '--exec', '/bin/bash', '-s', '--') + $ScriptArgs) $wslEnv $run $Seconds $Script
}
function Get-Registered { return ConvertFrom-WslList (Invoke-WslExe @('--list', '--quiet') 120).Output }
# ⟨M04-FX-RC03⟩ The registered names, or $null when the listing failed.
function Get-RegisteredOrNull {
    $r = Invoke-WslExe @('--list', '--quiet') 120
    if ($r.Code -ne 0) { return $null }
    return , @(ConvertFrom-WslList $r.Output)
}
# ⟨Windows run at 86cd513b⟩ One reachability attempt on 127.0.0.1:Port: `ok` (an SSH banner),
# `refused`, `timeout` (no connection or no banner within 3 s), `no-banner` (something else
# answered), or the socket error's name.
function Test-SshBanner([int]$Port) {
    $c = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $c.ConnectAsync('127.0.0.1', $Port)
        if (-not $task.Wait(3000)) { return 'timeout' }
        $c.ReceiveTimeout = 3000
        $buf = [byte[]]::new(8)
        $n = $c.GetStream().Read($buf, 0, 8)
        if ([System.Text.Encoding]::ASCII.GetString($buf, 0, $n).StartsWith('SSH-2.0-')) { return 'ok' }
        return 'no-banner'
    } catch {
        $e = $_.Exception
        while ($null -ne $e -and $e -isnot [System.Net.Sockets.SocketException]) { $e = $e.InnerException }
        if ($null -eq $e) { return 'timeout' }
        switch ($e.SocketErrorCode) {
            'ConnectionRefused' { return 'refused' }
            'TimedOut' { return 'timeout' }
            default { return "error-$($e.SocketErrorCode)" }
        }
    } finally { $c.Dispose() }
}

function Add-DistributionFacts([string]$When) {
    $v = Invoke-WslExe @('--list', '--verbose') 120
    $f = Get-DistributionFacts $v.Output $names
    [void]$distFacts.Append("$When`: exit $($v.Code); this run's: $(if ($f.Own.Count) { $f.Own -join '; ' } else { 'none' }); others: $($f.OtherCount) (digest $($f.OtherDigest))`n")
}

$gitEnv = New-ChildEnvironment @{ GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $emptyGitConfig; GIT_TERMINAL_PROMPT = '0'; HOME = $githome }
$git = (Get-Command 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($null -eq $git) { Stop-Run 2 'git.exe is not on PATH' }
$git = $git.Source

try {
    Add-Command $stockRc 'icacls: the run root gets the protected stock profile list (the user, SYSTEM, Administrators; inherited by what is created inside)'
    if ($stockRc -ne 0) { [void]$build.Append($stockOut); throw 'the run root''s list could not be set' }
    Add-Fact 'run-root-sddl' ((Get-Acl -LiteralPath $run).Sddl)
    Add-Fact 'os' ((Invoke-Bounded (Join-Path $sys32 'cmd.exe') @('/d', '/c', 'ver') $null $run 30).Output.Trim())
    $groups = (Invoke-Bounded (Join-Path $sys32 'whoami.exe') @('/groups') $null $run 30).Output
    Add-Fact 'integrity' ([regex]::Match($groups, '(Medium|High|System) Mandatory Level').Value)
    Add-Fact 'wsl-version' (((Invoke-WslExe @('--version') 60).Output -replace "`0", '' -split "`n" | Select-Object -First 1).Trim())
    Add-Fact 'prebuilt-heimdall-sha256' "$haveSha (equals HM_PREBUILT_SHA256)"
    Add-Command 0 "prebuilt heimdall sha256 equals HM_PREBUILT_SHA256 ($haveSha)"

    # 3. The registered set, and this run's names.
    $before = @(Get-Registered)
    # ⟨M04 U7⟩ One or two, per the scenario (always an array: a one-name run still indexes [0]).
    $names = @(@(Get-DistributionNames (New-RandomHex 4))[0..($distroCount - 1)])
    Add-DistributionFacts 'before'
    if (@($names | Where-Object { $before -contains $_ }).Count -ne 0) { throw 'a distribution with this run''s name is registered already; nothing imported' }
    Add-Command 0 'wsl --list: neither of this run''s names is registered'

    # 4. The clone at exactly the commit, the pinned toolchain in scratch, the build.
    $r = Invoke-Bounded $git @('-c', 'credential.helper=', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', 'clone', '--quiet', '--no-checkout', $RepoUrl, $src) $gitEnv $run 1800
    Add-Command $r.Code 'git clone of the repository into the run directory'
    [void]$build.Append($r.Output)
    if ($r.Code -ne 0) { throw 'clone failed' }
    foreach ($kv in @(@('core.autocrlf', 'false'), @('core.longpaths', 'true'))) {
        $r = Invoke-Bounded $git @('-C', $src, 'config', '--local', $kv[0], $kv[1]) $gitEnv $run 60
        if ($r.Code -ne 0) { throw "git config $($kv[0]) failed" }
    }
    $r = Invoke-Bounded $git @('-C', $src, 'checkout', '--quiet', '--detach', $Commit) $gitEnv $run 600
    Add-Command $r.Code 'git checkout --detach <commit>'
    if ($r.Code -ne 0) { throw 'checkout failed' }
    $head = (Invoke-Bounded $git @('-C', $src, 'rev-parse', 'HEAD') $gitEnv $run 60).Output.Trim()
    Add-Command $(if ($head -eq $Commit) { 0 } else { 1 }) 'the clone is at exactly the commit'
    if ($head -ne $Commit) { throw 'the clone is not at the commit' }
    $crlf = Get-CrlfFileCount @('Cargo.lock', 'rust-toolchain.toml', 'tests\native\m02\remote-lib.sh', 'tests\native\m02\target-root.sh' | ForEach-Object { Join-Path $src $_ })
    Add-Command $(if ($crlf -eq 0) { 0 } else { 1 }) 'the checked-out tree has LF line endings'
    if ($crlf -ne 0) { throw 'the checkout has CRLF line endings' }
    Add-Fact 'build-commit' $Commit

    # ⟨M04 U7⟩ The containers scenario runs only Linux binaries the build host cross-built: no
    # Windows toolchain or build.
    $rustupHome = ''; $cargoHome = ''; $cargo = ''; $hook = ''
    if ($Scenario -ne 'containers') {
        $toml = Get-Content -LiteralPath (Join-Path $src 'rust-toolchain.toml') -Raw
        $channel = [regex]::Match($toml, '(?m)^\s*channel\s*=\s*"([^"]+)"').Groups[1].Value
        if (-not $channel) { throw 'rust-toolchain.toml names no channel' }
        $rustupHome = Join-Path $tools 'rustup'
        $cargoHome = Join-Path $tools 'cargo'
        $init = Join-Path $tools 'rustup-init.exe'
        $base = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
        Invoke-WebRequest -Uri $base -OutFile $init
        Invoke-WebRequest -Uri "$base.sha256" -OutFile "$init.sha256"
        $want = ((Get-Content -LiteralPath "$init.sha256" -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $have = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($init))
        Add-Command $(if ($want -eq $have) { 0 } else { 1 }) 'rustup-init.exe downloaded over HTTPS and its sha256 matches the published one'
        if ($want -ne $have) { throw 'rustup-init sha256 mismatch' }
        $toolEnv = New-ChildEnvironment (Get-ToolEnvironmentOverrides $rustupHome $cargoHome $emptyGitConfig $wtmp)
        $toolEnv['PATH'] = (Join-Path $cargoHome 'bin') + ';' + $toolEnv['PATH']
        $r = Invoke-Bounded $init @('-y', '--no-modify-path', '--profile', 'minimal', '--default-host', 'x86_64-pc-windows-msvc', '--default-toolchain', $channel) $toolEnv $run 1800
        Add-Command $r.Code "rustup-init into the run directory (RUSTUP_HOME and CARGO_HOME there, --no-modify-path, toolchain $channel)"
        [void]$build.Append($r.Output)
        if ($r.Code -ne 0) { throw 'toolchain install failed' }
        $cargo = Join-Path $cargoHome 'bin\cargo.exe'
        Add-Fact 'toolchain' ((Invoke-Bounded (Join-Path $cargoHome 'bin\rustc.exe') @('-V') $toolEnv $src 1800).Output.Trim() + "; target x86_64-pc-windows-msvc")
        $builds = [System.Collections.Generic.List[object]]::new()
        $builds.Add(@('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--no-run'))
        if ($Scenario -eq 'mode-b') { $builds.Add(@('test', '--locked', '-p', 'heimdall-wsl', '--lib', '--no-run')) }
        $builds.Add(@('build', '--locked', '-p', 'heimdall-testkit', '--bins'))
        foreach ($b in $builds) {
            $r = Invoke-Bounded $cargo $b $toolEnv $src 7200
            Add-Command $r.Code "cargo $($b -join ' ')"
            [void]$build.Append($r.Output)
            if ($r.Code -ne 0) { throw 'the build failed' }
        }
        $hook = Join-Path $src 'target\debug\hm-fixture-hook.exe'
        if (-not (Test-Path -LiteralPath $hook)) { throw 'hm-fixture-hook.exe was not built' }
    }

    # The files the distributions read: the helper, and the M02 root script.
    Copy-Item -LiteralPath $helperItem.FullName -Destination (Join-Path $files 'heimdall')
    if ((Get-Sha256Hex ([System.IO.File]::ReadAllBytes((Join-Path $files 'heimdall')))) -ne $wantSha) { throw 'the copied helper changed' }
    Copy-Item -LiteralPath (Join-Path $src 'tests\native\m02\target-root.sh') -Destination (Join-Path $files 'target-root.sh')
    # ⟨M04 U7⟩ The containers scenario's files: the engines script of the clone, the cross-built Linux
    # test and hook, each copy checked against the digest given.
    if ($Scenario -eq 'containers') {
        Copy-Item -LiteralPath (Join-Path $src 'tests\native\m04\container-engines.sh') -Destination (Join-Path $files 'container-engines.sh')
        foreach ($i in $linuxInputs) {
            $dest = Join-Path $files $i.As
            Copy-Item -LiteralPath $i.Full -Destination $dest
            if ((Get-Sha256Hex ([System.IO.File]::ReadAllBytes($dest))) -ne $i.Sha) { throw "the copied $($i.As) changed" }
            Add-Fact "prebuilt-$($i.As)-sha256" "$($i.Sha) (equals $($i.Param)Sha256)"
        }
        Add-Command 0 'the cross-built Linux test and hook match their digests'
    }
    $remoteLib = (Get-Content -LiteralPath (Join-Path $src 'tests\native\m02\remote-lib.sh') -Raw) -replace "`r`n", "`n"

    # The pinned image.
    $image = if ($Rootfs) { $rootfsItem.FullName } else { Join-Path $run 'ubuntu-24.04.5-wsl-amd64.wsl' }
    $preparedTar = Join-Path $run 'hm-m04-prepared.tar'
    if (-not $Rootfs) {
        Invoke-WebRequest -Uri $RootfsUrl -OutFile $image
        Add-Command 0 'the pinned image downloaded over HTTPS'
    }
    $imgSha = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($image))
    Add-Command $(if ($imgSha -eq $RootfsSha256) { 0 } else { 1 }) 'the image is the pinned one (sha256)'
    if ($imgSha -ne $RootfsSha256) { throw 'the image is not the pinned one; nothing imported' }

    # 5. Both distributions. ⟨Windows run at 86cd513b⟩ One preparation per run: the first is
    # imported from the pinned image and prepared; the second is imported from the first's
    # export once it is prepared (its own GUID, the same content), and the export is removed.
    $apt = if ($AllowApt) { '1' } else { '0' }
    foreach ($n in $names) {
        $dir = Join-Path $distroRoot $n
        [void][System.IO.Directory]::CreateDirectory($dir)
        $fromExport = $n -ne $names[0]
        if ($fromExport) {
            $r = Invoke-WslExe @('--export', $names[0], $preparedTar) 1800
            Add-Command $r.Code "wsl --export $($names[0]) (prepared; the second distribution is imported from it)"
            if ($r.Code -ne 0) { throw "the export of $($names[0]) failed" }
        }
        # ⟨M04-FX-RC03⟩ Attempted before the import runs, so the outer cleanup considers this
        # name whatever happens next (a failed listing, Ctrl-C); reconciled in this finally.
        $attempted.Add($n)
        $r = $null
        try {
            $r = Invoke-WslExe @('--import', $n, $dir, $(if ($fromExport) { $preparedTar } else { $image }), '--version', '2') 1800
        } finally {
            # Recorded as this run's as soon as it is registered, whatever the exit code said.
            $listed = Get-RegisteredOrNull
            if ($null -ne $listed -and ($listed -contains $n) -and -not ($created -contains $n)) { $created.Add($n) }
        }
        Add-Command $r.Code "wsl --import $n (into the run directory, WSL 2$(if ($fromExport) { ', from the prepared export' } else { '' }))"
        if ($r.Code -ne 0 -or -not ($created -contains $n)) { throw "the import of $n failed" }
        if ($fromExport) {
            Remove-Item -LiteralPath $preparedTar -Force -ErrorAction SilentlyContinue
            Add-Command $(if (Test-Path -LiteralPath $preparedTar) { 1 } else { 0 }) 'remove the prepared export'
            [void]$build.Append("### $n prepare`n(imported from $($names[0])'s export: the same preparation)`n")
            continue
        }
        $r = Invoke-InDistro $n 'root' $scripts['root-phase'] @($files, $n, 'no-systemd') 600
        Add-Command $r.Code "$n`: target-root.sh no-systemd"
        if ($r.Code -ne 0) { throw 'no-systemd failed' }
        [void](Invoke-WslExe @('--terminate', $n) 120)
        $r = Invoke-InDistro $n 'root' $scripts['root-phase'] @($files, $n, 'prepare', $User, $apt) 3600
        [void]$build.Append("### $n prepare`n$($r.Output)`n")
        Add-Command $r.Code "$n`: target-root.sh prepare (tools, git, python3; the non-root user)"
        if ($r.Code -eq 3) { $overall = 3; throw "$n lacks tools (-AllowApt / HM_WSL_ALLOW_APT=1 installs them inside it)" }
        if ($r.Code -ne 0) { throw 'prepare failed' }
        $r = Invoke-InDistro $n 'root' $scripts['default-user'] @($n, $User) 300
        Add-Command $r.Code "$n`: [user] default set to the non-root user"
        if ($r.Code -ne 0) { throw 'the default user could not be set' }
        [void](Invoke-WslExe @('--terminate', $n) 120)
    }
    Add-DistributionFacts 'after-import'

    # ⟨M04 U7⟩ The single-distribution scenarios' own preparation (inside the distribution only).
    if ($Scenario -eq 'systemd-login') {
        $n = $names[0]
        $r = Invoke-InDistro $n 'root' $scripts['systemd-on'] @($n) 300
        Add-Command $r.Code "$n`: [boot] systemd=true (inside it only)"
        if ($r.Code -ne 0) { throw 'systemd could not be enabled' }
        [void](Invoke-WslExe @('--terminate', $n) 120)
        $r = Invoke-InDistro $n 'root' $scripts['systemd-wait'] @($n) 300
        foreach ($l in ($r.Output -split "`n")) { if ($l -match '^systemd=(.*)$') { Add-Fact 'systemd' $Matches[1].Trim() } }
        Add-Command $r.Code "$n`: systemd booted"
        if ($r.Code -ne 0) { throw 'systemd did not boot' }
        $r = Invoke-InDistro $n $User $scripts['stage'] @($files, 'hm-m04-login', 'heimdall') 300
        foreach ($l in ($r.Output -split "`n")) { if ($l -match '^staged=(.*)$') { $loginHeimdall = $Matches[1].Trim() + '/heimdall' } }
        Add-Command $r.Code 'the Linux heimdall staged in the user''s home'
        if ($r.Code -ne 0 -or -not $loginHeimdall) { throw 'staging failed' }
    }
    if ($Scenario -eq 'containers') {
        $n = $names[0]
        $enginesState = '/root/hm-m04-engines'
        $r = Invoke-InDistro $n 'root' $scripts['engines'] @($files, $enginesState, 'install', $User, $apt) 3600
        [void]$build.Append("### $n container-engines.sh install`n$($r.Output)`n")
        foreach ($l in ($r.Output -split "`n")) { if ($l -match '^(podman-version|docker-version|subid|docker-group)=(.*)$') { Add-Fact $Matches[1] $Matches[2].Trim() } }
        Add-Command $r.Code "$n`: container-engines.sh install (Podman, uidmap, Docker Engine; inside it only)"
        if ($r.Code -eq 3) { $overall = 3; throw "$n lacks the engines (-AllowApt / HM_WSL_ALLOW_APT=1 installs them inside it)" }
        if ($r.Code -ne 0) { throw 'the engines could not be installed' }
        $r = Invoke-InDistro $n 'root' $scripts['engines'] @($files, $enginesState, 'dockerd-start') 300
        [void]$build.Append("### $n dockerd-start`n$($r.Output)`n")
        Add-Command $r.Code "$n`: dockerd started by hand (its PID and start time recorded)"
        if ($r.Code -ne 0) { throw 'dockerd did not start' }
        foreach ($e in @('podman', 'docker')) {
            foreach ($step in @(@('snapshot', $e, $User), @('image', $e, $User, $A15Base, $A15Image))) {
                $r = Invoke-InDistro $n 'root' $scripts['engines'] (@($files, $enginesState) + $step) 1800
                [void]$build.Append("### $n container-engines.sh $($step[0]) $e`n$($r.Output)`n")
                foreach ($l in ($r.Output -split "`n")) { if ($l -match '^(image-[a-z]+)=([0-9a-f]{64})$') { Add-Fact $Matches[1] $Matches[2] } }
                Add-Command $r.Code "$n`: container-engines.sh $($step[0]) $e"
                if ($r.Code -ne 0) { throw "$($step[0]) $e failed" }
            }
        }
        $r = Invoke-InDistro $n $User $scripts['stage'] @($files, 'hm-m04-a15', 'heimdall', 'e2e_platform_m04', 'hm-fixture-hook') 300
        foreach ($l in ($r.Output -split "`n")) { if ($l -match '^staged=(.*)$') { $a15Dir = $Matches[1].Trim() } }
        Add-Command $r.Code 'the Linux heimdall, test and hook staged in the user''s home'
        if ($r.Code -ne 0 -or -not $a15Dir) { throw 'staging failed' }
    }

    # 6. The harness sshd in -2 (the two-distribution scenarios).
    if ($names.Count -eq 2) {
        # 6. The harness sshd in -2, as the user.
        $fxName = 'hm-m04-fx-' + (New-RandomHex 4)
        $r = Invoke-InDistro $names[1] $User $scripts['sshd-dir'] @($fxName) 300
        foreach ($l in ($r.Output -split "`n")) { if ($l -match '^([a-z-]+)=(.*)$') { $wv[$Matches[1]] = $Matches[2].Trim() } }
        Add-Command $r.Code 'the harness sshd directory in the user''s home (owner-only)'
        if ($r.Code -ne 0 -or -not $wv['created']) { throw 'the sshd directory was not created' }
        $sshdWslDir = $wv['created']
        $ak = Join-Path $sshdDir 'authorized_keys'
        $slog = Join-Path $sshdDir 'sshd.log'
        $akStrict = Join-Path $sshdDir 'authorized_keys_strict'
        $slogStrict = Join-Path $sshdDir 'sshd_strict.log'
        foreach ($f in @($ak, $akStrict)) { [System.IO.File]::WriteAllText($f, '') }
        $psi = [System.Diagnostics.ProcessStartInfo]::new($wslExe)
        foreach ($a in @('-d', $names[1], '-u', $User, '--exec', '/bin/bash', '-s', '--', $sshdWslDir, $ak, $slog, $akStrict, $slogStrict)) { $psi.ArgumentList.Add($a) }
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.Environment.Clear()
        foreach ($k in $wslEnv.Keys) { $psi.Environment[$k] = $wslEnv[$k] }
        $sshdProc = [System.Diagnostics.Process]::Start($psi)
        $sshdErr = $sshdProc.StandardError.ReadToEndAsync()
        $sshdProc.StandardInput.Write((($remoteLib + "`n" + (Get-SshdStartScript)) -replace "`r`n", "`n"))
        $sshdProc.StandardInput.Close()
        $fx = @{}
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        $pending = $null
        while ([DateTime]::UtcNow -lt $deadline -and -not ($fx.ContainsKey('ready') -or $fx.ContainsKey('why'))) {
            if ($null -eq $pending) { $pending = $sshdProc.StandardOutput.ReadLineAsync() }
            if (-not $pending.Wait(5000)) { continue }
            $line = $pending.Result
            $pending = $null
            if ($null -eq $line) { break }
            if ($line -match '^([a-z]+)=(.*)$') { $fx[$Matches[1]] = $Matches[2].Trim() }
        }
        # ⟨Windows run at 86cd513b⟩ Reachable from Windows only once WSL's localhost relay forwards
        # the port, which can take a while after a distribution starts: up to 90 s of attempts,
        # each a 3 s connect and the banner, every attempt kept.
        $reach = $null
        if ($fx.ContainsKey('ready')) {
            $port = [int]$fx['port']
            $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
            $reach = Wait-SshReachable { Test-SshBanner $port } 90 2000 { $waitClock.Elapsed.TotalSeconds } { param($Ms) Start-Sleep -Milliseconds $Ms }
            [void]$build.Append("### harness sshd reachability from Windows (127.0.0.1)`n$(($reach.Attempts -join "`n"))`n")
            foreach ($a in $reach.Attempts) { Write-Host "harness sshd $a" }
        }
        if ($null -eq $reach -or -not $reach.Ok) {
            $why = if ($fx.ContainsKey('why')) { $fx['why'] }
            elseif ($null -eq $reach) { 'it reported no ready listener within 60 s' }
            else {
                $last = ($reach.Attempts[-1] -split ': ', 2)[1]
                'not reachable from Windows ({0} attempts in {1} s; last: {2})' -f $reach.Count, [int]$reach.Seconds, $last
            }
            Add-Fact 'fixture-sshd' "unavailable: $why"
            # Why: the recorded sshd, a listener inside the distribution, WSL's networking mode.
            try {
                $d = Invoke-InDistro $names[1] $User ($remoteLib + "`n" + $scripts['sshd-diagnosis'] + "`n") @($sshdWslDir, [string]$fx['port']) 120
                foreach ($l in ($d.Output -replace "`r", '' -split "`n")) {
                    if ($l -match '^(sshd-process|sshd-listening|networking-mode)=(.*)$') { Add-Fact "fixture-sshd-$($Matches[1] -replace '^sshd-', '')" $Matches[2] }
                }
            } catch { Add-Fact 'fixture-sshd-diagnosis' "failed ($($_.Exception.GetType().Name))" }
            $wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
            Add-Fact 'wslconfig-networking' $(if (Test-Path -LiteralPath $wslconfig -PathType Leaf) { Get-WslConfigNetworking (Get-Content -LiteralPath $wslconfig -Raw) } else { 'no .wslconfig (NAT, localhost forwarding on)' })
            Add-Command 1 'harness sshd in the second distribution reachable from Windows on 127.0.0.1'
            throw 'the harness sshd is unavailable'
        }
        Add-Command 0 "harness sshd in the second distribution reachable from Windows on 127.0.0.1 (attempt $($reach.Count), $([int]$reach.Seconds) s)"
        $strictClock = [System.Diagnostics.Stopwatch]::StartNew()
        $strictOk = $fx.ContainsKey('strictport') -and ((Wait-SshReachable { Test-SshBanner ([int]$fx['strictport']) } 30 2000 { $strictClock.Elapsed.TotalSeconds } { param($Ms) Start-Sleep -Milliseconds $Ms }).Ok)
        $fixtureEnv = Get-FixtureEnvironment $fx $true $strictOk $ak $slog $akStrict $slogStrict $User
        Add-Fact 'fixture-sshd' 'listening on 127.0.0.1 in the second disposable distribution (non-root, per-run host key)'
        Add-Fact 'fixture-sshd-registry' $(if ($fixtureEnv.ContainsKey('HM_FIXTURE_SSHD_REGISTRY')) { 'exported (owner-only, in the user''s home)' } else { 'not reported' })

    }

    Add-Fact 'seconds-before-tests' ([string][int]$runClock.Elapsed.TotalSeconds)
    # 7. The tests. ⟨M04 U7⟩ Per scenario; mode-b's in plan order, the unregister row last and alone.
    $testBase = @{
        HM_FIXTURE_HOOK = $hook; HM_REPO_ROOT = $src
        HM_WSL_TEST_DISTRO = $names[0]; HM_WSL_TEST_ACCOUNT = $User
        HM_WSL_TEST_HELPER = (Join-Path $files 'heimdall')
    }
    if ($names.Count -eq 2) { $testBase['HM_WSL_TEST_DISTRO2'] = $names[1]; $testBase['HM_WSL_TEST_ACCOUNT2'] = $User }
    foreach ($k in $fixtureEnv.Keys) { $testBase[$k] = $fixtureEnv[$k] }
    function New-TestEnvironment([hashtable]$Extra) {
        $set = @{}
        foreach ($k in (Get-ToolEnvironmentOverrides $rustupHome $cargoHome $emptyGitConfig $wtmp).GetEnumerator()) { $set[$k.Key] = $k.Value }
        foreach ($k in $testBase.Keys) { $set[$k] = $testBase[$k] }
        foreach ($k in $Extra.Keys) { $set[$k] = $Extra[$k] }
        $envs = New-ChildEnvironment $set
        # The in-box OpenSSH first, then the toolchain.
        $envs['PATH'] = (Join-Path $sys32 'OpenSSH') + ';' + (Join-Path $cargoHome 'bin') + ';' + $envs['PATH']
        return $envs
    }
    # As it goes: printed, and kept in results.txt (names, outcomes and counts only).
    function Add-TestResult([string]$Name, [int]$Code, [string]$Output, [string]$What) {
        [void]$tests.Append((Format-TargetOutput $Name $Output $Code))
        $lines = @(Get-TestResultLines $Output)
        Add-Command $Code "$What -> $(if ($lines.Count) { $lines -join ' | ' } else { 'no test result line' })"
        $plain = Format-ResultLines $Name $Code $Output
        Write-Output $plain
        [System.IO.File]::AppendAllText($resultsFile, $plain, [System.Text.UTF8Encoding]::new($false))
        if ($Code -ne 0 -and $script:overall -eq 0) { $script:overall = 1 }
    }
    switch ($Scenario) {
        'mode-b' {
            foreach ($t in $selectedPlan) {
                $x = @{}
                if ($t.Unregister) { $x['HM_WSL_TEST_ALLOW_UNREGISTER'] = '1' }
                $r = Invoke-Bounded $cargo $t.Args (New-TestEnvironment $x) $src $TimeoutSeconds
                Add-TestResult $t.Name $r.Code $r.Output "cargo $($t.Args -join ' ')$(if ($t.Unregister) { ' (HM_WSL_TEST_ALLOW_UNREGISTER=1)' })"
            }
        }
        'systemd-login' {
            $a = @('test', '--locked', '-p', 'heimdall', '--test', 'e2e_platform_m04', '--', '--ignored', '--exact',
                'service_login::wsl_login::linux_login_entry_starts_runtime_at_next_login', '--show-output')
            $r = Invoke-Bounded $cargo $a (New-TestEnvironment @{ HM_FIXTURE_WSL_DISTRO = $names[0]; HM_WSL_LOGIN_USER = $User; HM_WSL_LOGIN_HEIMDALL = $loginHeimdall }) $src $TimeoutSeconds
            Add-TestResult 'a08-login-entry' $r.Code $r.Output "cargo $($a -join ' ')"
        }
        'containers' {
            foreach ($e in @('podman', 'docker')) {
                $r = Invoke-InDistro $names[0] $User $scripts['a15-run'] @($a15Dir, $e, $A15Image, $src) $TimeoutSeconds
                Add-TestResult "a15-$e" $r.Code $r.Output "e2e_platform_m04 --exact container::a15_container_mounted_flow container::a31_uninstall_with_a_live_container_binding (as the user; $e)"
            }
        }
        'lock' {
            Add-Type -Namespace HmM04Lock -Name Native -MemberDefinition @'
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
            $lockState = Join-Path $run 'lock-state'
            [void][System.IO.Directory]::CreateDirectory($lockState)
            $product = Join-Path $src 'target\debug\heimdall.exe'
            if (-not (Test-Path -LiteralPath $product)) { throw 'the heimdall binary was not built' }
            # The product's own read-only query (writes nothing; a scratch home that is never created).
            $lockEnv = New-ChildEnvironment @{ HEIMDALL_HOME = (Join-Path $run 'lock-home') }
            $a = @('test', '--locked', '-p', 'heimdall', '--test', $Driver, '--', '--ignored', '--exact', $Filter, '--nocapture', '--test-threads=1')
            $denv = New-TestEnvironment @{ HM_LOCK_STATE_DIR = $lockState }
            $psi = [System.Diagnostics.ProcessStartInfo]::new($cargo)
            foreach ($x in $a) { $psi.ArgumentList.Add($x) }
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.WorkingDirectory = $src
            $psi.Environment.Clear()
            foreach ($k in $denv.Keys) { $psi.Environment[$k] = $denv[$k] }
            $drv = [System.Diagnostics.Process]::Start($psi)
            $drv.StandardInput.Close()
            $drvOut = $drv.StandardOutput.ReadToEndAsync()
            $drvErr = $drv.StandardError.ReadToEndAsync()
            Add-Command 0 "the lock driver started: cargo $($a -join ' ')"
            $lockClock = [System.Diagnostics.Stopwatch]::StartNew()
            $hooks = @{
                HasFlag = { param($Name) Test-Path -LiteralPath (Join-Path $lockState $Name) }
                WriteFlag = { param($Name, $Text) $tmp = Join-Path $lockState ".$Name.tmp"; [System.IO.File]::WriteAllText($tmp, "$Text`n"); Move-Item -LiteralPath $tmp -Destination (Join-Path $lockState $Name) -Force }
                DriverExited = { $drv.HasExited }
                IdleSeconds = { [HmM04Lock.Native]::IdleSeconds() }
                Lock = { [HmM04Lock.Native]::LockWorkStation() }
                LockState = {
                    $q = Invoke-Bounded $product @('--json', 'internal', 'session-lock-state') $lockEnv $run 60
                    if ($q.Code -ne 0) { return 'query_failed' }
                    try { $st = (($q.Output -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json).data.state } catch { return 'query_failed' }
                    if ($st -in @('unlocked', 'locked', 'unknown', 'unavailable')) { return [string]$st } else { return 'query_failed' }
                }
                Now = { $lockClock.Elapsed.TotalSeconds }
                Sleep = { param($Ms) Start-Sleep -Milliseconds $Ms }
            }
            Add-Fact 'lock-rule' "ADR-0004 §2: locked by this harness only after >= $MinIdleSeconds s console idle (armed for up to $ArmSeconds s); the owner unlocks"
            $phase = Invoke-LockPhase $hooks $ArmSeconds
            foreach ($f in $phase.Facts) { $kv = $f -split '=', 2; Add-Fact "lock-$($kv[0])" $kv[1] }
            foreach ($st in $phase.Steps) { Add-Command 0 "lock: $st" }
            # The driver ends through its own cleanup (`done`, or its failure after `abort`).
            if (-not $drv.WaitForExit(900000)) {
                Add-Command 1 'the lock driver did not end within 900 s of the lock phase; its process tree was stopped (its runtime may be left; see the leftover check)'
                $drv.Kill($true)
                $drv.WaitForExit()
            }
            $drvText = $drvOut.Result + $drvErr.Result
            Add-TestResult 'a03-mode-b-lock' $drv.ExitCode $drvText "cargo $($a -join ' ') (the lock driver)"
            if ($phase.Exit -eq 3) {
                Add-Fact 'lock-blocked' $phase.Blocked
                [void]$skipped.Append("a03_mode_b_fresh_logins_while_windows_locked: blocked: $($phase.Blocked)`n")
                $overall = 3
            } elseif ($phase.Exit -ne 0 -and $overall -eq 0) { $overall = 1 }
            Add-Command $phase.Exit "the lock phase (exit $($phase.Exit)$(if ($phase.Blocked) { ", $($phase.Blocked)" }))"
            $drv.Dispose()
        }
    }
} catch {
    # The failing line and the script's stack (redacted with the bundle; printed with it).
    Add-Command 1 "the run stopped: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    [void]$build.Append("### the run stopped`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)`n")
    if ($overall -eq 0) { $overall = 1 }
} finally {
  try {
    # 8. Cleanup: each step reports its own failure and never stops the others or the bundle.
    try {
        if ($sshdWslDir) {
            $now = @(Get-Registered)
            if ($now -contains $names[1]) {
                $r = Invoke-InDistro $names[1] $User ($remoteLib + "`n" + (Get-SshdStopScript) + "`n") @($sshdWslDir) 120
                $atEnd = Get-SshdAtEnd $r.Output
                Add-Fact 'fixture-sshd-at-end' $atEnd
                $ok = Test-SshdAtEndOk $atEnd
                Add-Command $(if ($ok) { 0 } else { 1 }) 'the recorded harness sshd is stopped (or already gone) at the end of the run'
                if (-not $ok -and $overall -eq 0) { $overall = 1 }
                $r = Invoke-InDistro $names[1] $User $scripts['sshd-dir-remove'] @($sshdWslDir) 120
                Add-Command $r.Code 'remove exactly the harness sshd directory'
            } else {
                Add-Fact 'fixture-sshd-at-end' 'gone with its distribution (the unregister row removed it)'
                Add-Command 0 'the harness sshd ended with its distribution'
            }
        }
        if ($null -ne $sshdProc) {
            if (-not $sshdProc.WaitForExit(30000)) { $sshdProc.Kill($true); $sshdProc.WaitForExit() }
            if ($null -ne $sshdErr) { [void]$sshdErr.Wait(5000) }
            $sshdProc.Dispose()
        }
    } catch { Add-Command 1 "stopping the harness sshd: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    # ⟨M04 U7⟩ The containers scenario: only the containers and images this run recorded, then the
    # recorded dockerd (the distribution is unregistered next either way).
    try {
        if ($enginesState -and $names.Count -gt 0 -and (@(Get-Registered) -contains $names[0])) {
            foreach ($e in @('podman', 'docker')) {
                $r = Invoke-InDistro $names[0] 'root' $scripts['engines'] @($files, $enginesState, 'cleanup', $e, $User) 600
                [void]$build.Append("### container-engines.sh cleanup $e`n$($r.Output)`n")
                Add-Command $r.Code "container-engines.sh cleanup $e (only the containers and images this run recorded)"
                if ($r.Code -ne 0 -and $overall -eq 0) { $overall = 1 }
            }
            $r = Invoke-InDistro $names[0] 'root' $scripts['engines'] @($files, $enginesState, 'dockerd-stop') 120
            [void]$build.Append("### dockerd-stop`n$($r.Output)`n")
            Add-Command $r.Code 'the recorded dockerd is stopped (or already gone)'
            if ($r.Code -ne 0 -and $overall -eq 0) { $overall = 1 }
        }
    } catch { Add-Command 1 "the engine cleanup: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    try {
        if ($attempted.Count -gt 0) {
            $now = @(Get-Registered)
            foreach ($n in @(Select-RemovableDistributions $attempted.ToArray() $before $now)) {
                [void](Invoke-WslExe @('--terminate', $n) 120)
                $r = Invoke-WslExe @('--unregister', $n) 600
                Add-Command $r.Code "wsl --unregister $n (this run's, by exact name)"
                if ($r.Code -ne 0 -and $overall -eq 0) { $overall = 1 }
            }
            foreach ($n in $created) {
                if (-not ($now -contains $n)) { Add-Command 0 "$n was already unregistered (the unregister row)" }
            }
            # ⟨M04-FX-RC03⟩ Keep the install directory of any distribution not known to be gone.
            $kept = @(Select-KeptInstallDirectories $attempted.ToArray() (Get-RegisteredOrNull))
            foreach ($n in $kept) {
                Add-Command 1 "$n may still be registered: its install directory under the run directory is kept (unregister it by this exact name, then remove the directory)"
                if ($overall -eq 0) { $overall = 1 }
            }
        }
        if ($names.Count -gt 0) {
            Add-DistributionFacts 'after'
            $after = @(Get-Registered)
            $same = Test-SameSet $before $after
            [void]$distFacts.Append("registered-set-equal-to-before=$(if ($same) { 'yes' } else { 'no' })`n")
            Add-Command $(if ($same) { 0 } else { 1 }) 'the registered distributions equal the set before the run (only this run''s were added and removed)'
            if (-not $same -and $overall -eq 0) { $overall = 1 }
        }
    } catch { Add-Command 1 "unregistering this run's distributions: $($_.Exception.Message)"; if ($overall -eq 0) { $overall = 1 } }
    foreach ($d in @($src, $tools, $wtmp, $files, $sshdDir, $githome, (Join-Path $run 'ubuntu-24.04.5-wsl-amd64.wsl'), (Join-Path $run 'hm-m04-prepared.tar'), (Join-Path $run 'lock-state'), (Join-Path $run 'lock-home'))) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    # The distributions' install directories: each removed only when its distribution is known
    # to be unregistered (⟨M04-FX-RC03⟩); the directory root goes when nothing is kept.
    if (-not (Test-Path variable:kept)) { $kept = @(Select-KeptInstallDirectories $attempted.ToArray() (Get-RegisteredOrNull)) }
    foreach ($n in $attempted) {
        if ($kept -contains $n) { continue }
        $d = Join-Path $distroRoot $n
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($kept.Count -eq 0 -and (Test-Path -LiteralPath $distroRoot)) { Remove-Item -LiteralPath $distroRoot -Recurse -Force -ErrorAction SilentlyContinue }
    $gone = -not ((Test-Path -LiteralPath $src) -or (Test-Path -LiteralPath $tools) -or ($kept.Count -eq 0 -and (Test-Path -LiteralPath $distroRoot)))
    Add-Command $(if ($gone) { 0 } else { 1 }) 'remove the clone, the toolchain, the build and the distributions'' directories, then check they are absent'
    if (-not $gone -and $overall -eq 0) { $overall = 1 }
    # ⟨M04 Windows fix round 5⟩ The tests' scratch registry keys' parent (the M02 runner's
    # helper): removed when empty, never recursively, and reported either way.
    try { Add-Fact 'heimdalltest-parent' (Remove-EmptyHeimdallTestParent) }
    catch { Add-Fact 'heimdalltest-parent' "unreadable ($($_.Exception.GetType().Name))" }

    # 9. Redact, mask, scan, bundle (no environment dump: only the facts above).
    $rules = Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName())
    $raw = @{ 'tests.txt' = $tests.ToString(); 'commands.txt' = $commands.ToString(); 'host.txt' = $hostFacts.ToString()
        'build.txt' = $build.ToString(); 'skipped.txt' = $skipped.ToString(); 'distributions.txt' = $distFacts.ToString(); 'canary-scan.txt' = '' }
    # The run's verdict first, in the plain results (it survives a failed bundle).
    [System.IO.File]::AppendAllText($resultsFile, "### run exit=$overall`n", [System.Text.UTF8Encoding]::new($false))
    Write-Output "### run exit=$overall (results: <run>\bundle\results.txt)"
    $p = Protect-BundleFiles $raw $rules
    if ($p -is [array] -or $p.Files -isnot [System.Collections.IDictionary]) { throw 'Protect-BundleFiles returned no file table' }
    $m = Get-ProtectedMetadata $runLabel $rules
    $canaryTotal = $p.Canaries + $m.Canaries
    $leakTotal = $p.Leaks + $m.Leaks
    # ⟨Windows run at 39f48be8⟩ Not `$out`: PowerShell names are case-insensitive, so `$out`
    # was the [string] parameter `-Out`, the file table became a string, and indexing it failed.
    $bundleOut = $p.Files
    $bundleOut['canary-scan.txt'] = "canary-prefix occurrences in saved output and metadata: $canaryTotal (values masked before the bundle was written)`n"
    $bundleOut['commands.txt'] += Format-CommandLine $(if ($canaryTotal -eq 0) { 0 } else { 1 }) "canary-prefix scan over saved output and metadata (count = $canaryTotal)"
    $bundleOut['commands.txt'] += Format-CommandLine $(if ($leakTotal -eq 0) { 0 } else { 1 }) "leak scan: saved files and metadata still naming a host, a user or a home ($leakTotal)"
    if (($canaryTotal -ne 0 -or $leakTotal -ne 0) -and $overall -eq 0) { $overall = 1 }
    $meta = [ordered]@{ commit = $Commit; label = $m.Label; started_at = $started; finished_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); exit = $overall }
    $b = New-Bundle $bundleOut $meta
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.json'), $b.Json, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $bundleDir 'bundle.b64'), $b.Text, [System.Text.UTF8Encoding]::new($false))
    Write-Output "bundle: <run>\bundle\bundle.json and bundle.b64 ($($b.Text.Length) characters)"
    Write-Output $bundleOut['commands.txt']
    Write-Output $b.Text
  } catch {
    # The cleanup or the bundle itself failed: say where, redacted as the bundle would be.
    $diag = "the cleanup or the bundle failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))`n$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)"
    try {
        $diag = Invoke-Redaction $diag (Get-RunRedactionRules $wv $run $env:USERPROFILE $env:USERNAME $env:COMPUTERNAME ([System.Net.Dns]::GetHostName()))
    } catch { $diag = 'the cleanup or the bundle failed (the diagnostic could not be redacted, so it is not printed)' }
    [Console]::Error.WriteLine("run-mode-b-windows: $(Hide-Canary $diag)")
    if ($overall -eq 0) { $overall = 1 }
  }
}
exit $overall
