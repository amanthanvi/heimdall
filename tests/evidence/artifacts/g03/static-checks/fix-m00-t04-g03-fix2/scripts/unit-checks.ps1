# M00-T04-G03-fix2 unit checks of pure/mocked orchestrator functions (run from the repo root).
# Functions are extracted from Invoke-G03WindowsProbes.ps1 by AST; no Windows API is called.
$ErrorActionPreference = 'Stop'
$path = (Resolve-Path 'tests/native/windows/Invoke-G03WindowsProbes.ps1').Path
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
foreach ($fn in @('New-Result', 'Set-Verdict', 'ConvertFrom-ServiceSddlRights', 'Test-AnyTrusteeRight', 'New-OtherUserScriptText',
        'Get-OtherUserArgLine', 'Test-OtherUserExited', 'Test-OtherUserRunning', 'Wait-OtherUser', 'Get-OtherUserProcessInfo', 'Invoke-DeadSockClient')) {
    $def = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true)
    if (-not $def) { throw "function not found: $fn" }
    . ([scriptblock]::Create($def.Extent.Text))
}
$here = @{}
foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Right.Expression -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Right.Expression.StringConstantType -eq 'SingleQuotedHereString' }, $false)) {
    $here[$a.Left.Extent.Text] = $a.Right.Expression.Value
}
$fail = 0
function Check { param($Name, $Got, $Want) $ok = ("$Got" -eq "$Want"); if (-not $ok) { $script:fail++ }; "{0,-66} got={1} want={2} {3}" -f $Name, $Got, $Want, $(if ($ok) { 'ok' } else { 'MISMATCH' }) }

"--- verdict convention and service SDDL (unchanged from fix, re-run)"
$r = Set-Verdict (New-Result 'x' @()) @{ a = $true; b = $true };  Check 'all true -> verified/pass' "$($r.Status)/$($r.Observed.verdict)" 'verified/pass'
$r = Set-Verdict (New-Result 'x' @()) @{ a = $true; b = $false }; Check 'one false -> verified/fail' "$($r.Status)/$($r.Observed.verdict)" 'verified/fail'
$r = Set-Verdict (New-Result 'x' @()) @{ a = $null; b = $false }; Check 'null + false -> in_progress/inconclusive' "$($r.Status)/$($r.Observed.verdict)" 'in_progress/inconclusive'
$rights = ConvertFrom-ServiceSddlRights 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;IU)(A;;RP;;;AU)'
Check 'AU codes' ($rights['AU'] -join ',') 'RP'
Check 'no cross-boundary match (OC)' (Test-AnyTrusteeRight (ConvertFrom-ServiceSddlRights '(A;;SWLOCR;;;AU)') @('AU') @('OC')) 'False'

"--- D1 staging: staged scripts parse; command line short; old -EncodedCommand length"
$exe = 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe'
$dir = 'C:\Users\Public\heimdall-g03-20261003T210743Z-a1b2c3'
$scripts = [ordered]@{
    'other-user' = $here['$OtherUserWin32'] + "`n" + '$SshAdd = ''C:\WINDOWS\System32\OpenSSH\ssh-add.exe''' + "`n" + '$ProbeDefaultPipe = $false' + "`n" + '$MaxInstances = 4' + "`n" +
        '$PipeTargets = [ordered]@{ owner_only = ''heimdall-g03-owneronly-a1b2c3d4e5f6''; authenticated_users = ''heimdall-g03-authusers-a1b2c3d4e5f6''; instance_allowed = ''heimdall-g03-installowed-a1b2c3d4e5f6'' }' + "`n" + $here['$OtherUserProbeScript']
    'squat'      = $here['$OtherUserWin32'] + "`n" + '$SquatName = ''heimdall-g03-squat-a1b2c3d4''' + "`n" + '$MaxInstances = 4' + "`n" + $here['$SquatScript']
    'wsl-other-user' = '$Distro = ''g03-target''' + "`n" + $here['$WslOtherUserScript']
}
foreach ($k in $scripts.Keys) {
    $tag = "$k-a1b2c3"
    $out = "$dir\$tag.json"; $done = "$dir\$tag.done"; $tmp = "$dir\$tag-tmp"; $sp = "$dir\$tag.ps1"
    $staged = New-OtherUserScriptText -ScriptText $scripts[$k] -OutFile $out -DoneFile $done -TmpDir $tmp
    $t2 = $null; $e2 = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($staged, [ref]$t2, [ref]$e2)
    Check "$k staged script parse errors" $e2.Count 0
    $cl = Get-OtherUserArgLine -Exe $exe -ScriptPath $sp
    Check "$k new command line <= 1024 (length $($cl.Length))" ($cl.Length -le 1024) 'True'
    $old = '$ErrorActionPreference = ''Continue''; $OutFile = ''' + $out + "'`n" + $scripts[$k]
    $oldLen = ('"' + $exe + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($old))).Length
    Check "$k old -EncodedCommand line exceeds 1024 (length $oldLen)" ($oldLen -gt 1024) 'True'
}
$threw = $false; try { [void](Get-OtherUserArgLine -Exe $exe -ScriptPath 'C:\x"y.ps1') } catch { $threw = $true }
Check 'arg line refuses a double quote in the path' $threw 'True'

"--- D1 staged preamble/finally executed by pwsh on this host (trivial body that throws)"
$work = Join-Path ([IO.Path]::GetTempPath()) ('g03fix2-stage-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
New-Item -ItemType Directory -Path $work | Out-Null
$body = '$o = [ordered]@{ temp = $env:TEMP; tmp = $env:TMP; sock_present = [bool]$env:SSH_AUTH_SOCK; psmodulepath_has_caller_entry = ([string]$env:PSModulePath).Contains(''caller-entry'') }' + "`n" +
    '($o | ConvertTo-Json) | Set-Content -LiteralPath $OutFile -Encoding UTF8' + "`n" + 'throw ''deliberate terminating error after the result'''
$sOut = Join-Path $work 'r.json'; $sDone = Join-Path $work 'r.done'; $sTmp = Join-Path $work 'r-tmp'; $sPath = Join-Path $work 'r.ps1'
[IO.File]::WriteAllText($sPath, (New-OtherUserScriptText -ScriptText $body -OutFile $sOut -DoneFile $sDone -TmpDir $sTmp), (New-Object System.Text.UTF8Encoding($true)))
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Get-Process -Id $PID).Path
foreach ($a in @('-NoProfile', '-NonInteractive', '-File', $sPath)) { $psi.ArgumentList.Add($a) }
$psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$psi.Environment['SSH_AUTH_SOCK'] = '/nonexistent/caller-agent.sock'; $psi.Environment['TEMP'] = '/nonexistent-caller-temp'
$psi.Environment['PSModulePath'] = '/caller-entry'; $psi.Environment['ProgramFiles'] = '/pf'; $psi.Environment['WINDIR'] = '/win'
$cp = [System.Diagnostics.Process]::Start($psi); $so = $cp.StandardOutput.ReadToEndAsync(); $se = $cp.StandardError.ReadToEndAsync()
[void]$cp.WaitForExit(60000)
Check 'staged child exit code is non-zero (body threw)' ($cp.ExitCode -ne 0) 'True'
Check 'done marker written by finally despite the throw' (Test-Path -LiteralPath $sDone) 'True'
$res = Get-Content -LiteralPath $sOut -Raw | ConvertFrom-Json
Check 'TEMP reset to the staged tmp dir' ($res.temp -eq $sTmp) 'True'
Check 'TMP reset to the staged tmp dir' ($res.tmp -eq $sTmp) 'True'
Check 'staged tmp dir created' (Test-Path -LiteralPath $sTmp) 'True'
Check 'inherited SSH_AUTH_SOCK cleared' $res.sock_present 'False'
Check 'inherited PSModulePath replaced' $res.psmodulepath_has_caller_entry 'False'

"--- D6 Wait-OtherUser completion and kill policy"
$h = [pscustomobject]@{ Process = $null; HandleHeld = $false; OutFile = $sOut; DoneFile = $sDone; CommandLineLength = 150 }
$w = Wait-OtherUser -Handle $h -TimeoutSec 5
Check 'done marker, no handle -> completion' $w.Completion 'done_marker'
Check '  kill not needed' $w.Kill 'not_needed'
Check '  result data read' ([bool]$w.Data) 'True'
$h2 = [pscustomobject]@{ Process = $null; HandleHeld = $false; OutFile = (Join-Path $work 'none.json'); DoneFile = (Join-Path $work 'none.done'); CommandLineLength = 150 }
$w2 = Wait-OtherUser -Handle $h2 -TimeoutSec 1
Check 'no marker, no handle -> timeout' "$($w2.Completion)/$($w2.TimedOut)" 'timeout/True'
Check '  no PID-only kill attempted' ($w2.Kill -like 'not_attempted*') 'True'
Check '  running test without handle/marker -> running' (Test-OtherUserRunning $h2) 'True'
# A process this check starts itself, handle held from start: killed through that handle on timeout.
$sl = Start-Process -FilePath '/bin/sleep' -ArgumentList '30' -PassThru
$null = $sl.Handle
$h3 = [pscustomobject]@{ Process = $sl; HandleHeld = $true; OutFile = (Join-Path $work 'none3.json'); DoneFile = (Join-Path $work 'none3.done'); CommandLineLength = 150 }
$w3 = Wait-OtherUser -Handle $h3 -TimeoutSec 1
[void]$sl.WaitForExit(5000)
Check 'held handle, timeout -> killed via held handle' $w3.Kill 'killed_via_held_handle'
Check '  owned sleep process exited' $sl.HasExited 'True'
$info = Get-OtherUserProcessInfo $w3
Check '  process info records command_line_length' $info['command_line_length'] 150
Remove-Item -LiteralPath $work -Recurse -Force

"--- D2 Invoke-DeadSockClient fallback judgement (mocked platform calls)"
$ctx = [pscustomobject]@{ SentinelPipe = '\\.\pipe\heimdall-g03-none-x' }
$script:mock = @{}
function Get-G03PipeNames { return $script:mock.pipes }
function Invoke-G03Native { param($Ctx, $FilePath, $ArgList, $Env, $TimeoutSec) return [pscustomobject]@{ ExitCode = $script:mock.exit; Out = $script:mock.out; FilePath = $FilePath; Arguments = '-l' } }
function Get-G03StdoutText { param($Result) return $Result.Out }
function Add-Run { param($R, $Label, $Res) [void]$R.Evidence.Add("transcript:$Label") }
function Get-G03AgentServiceState { return [ordered]@{ present = $true; status = $script:mock.svc } }
function Get-G03ProcessPresence { param($Names) return @{ '1Password' = $script:mock.op } }
function Start-G03InstrumentedAgent { param($Ctx, $Name, $PipeName, $RunSeconds, [switch]$ExpectStartFailure) $script:mock.decoyStarted = $PipeName; return [pscustomobject]@{ Ready = [pscustomobject]@{ status = $script:mock.decoyStatus } } }
function Stop-G03InstrumentedAgent { param($A) return 'stopped' }
function Get-G03AgentContact { param($A) return @{ connections = $script:mock.decoyConns } }
function Start-Sleep { }
$IAmOnADisposableHost = $false
$script:mock = @{ pipes = @('openssh-ssh-agent'); exit = 2; out = '' }
$r = New-Result 'x' @(); $o = Invoke-DeadSockClient -R $r -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'present + exit 2 -> judged, no fallback' "$($o.fallback_judged)/$($o.no_fallback)" 'True/True'
Check '  stdout not saved (no transcript)' $r.Evidence.Count 0
Check '  command entry says stdout not saved' ([bool]($r.Commands[0] -like '*stdout not saved*')) 'True'
$script:mock = @{ pipes = @('openssh-ssh-agent'); exit = 0; out = "256 SHA256:x key`n" }
$r = New-Result 'x' @(); $o = Invoke-DeadSockClient -R $r -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'present + exit 0 (fell back) -> no_fallback false' "$($o.fallback_judged)/$($o.no_fallback)/$($o.stdout_line_count)" 'True/False/1'
$script:mock = @{ pipes = @(); exit = 2; out = '' }
$r = New-Result 'x' @(); $o = Invoke-DeadSockClient -R $r -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'absent, not disposable -> not judged' "$($o.fallback_judged)/$($null -eq $o.no_fallback)" 'False/True'
Check '  reason names the gate' ([bool]($o.reason -like '*IAmOnADisposableHost*')) 'True'
$IAmOnADisposableHost = $true
$script:mock = @{ pipes = @(); exit = 2; out = ''; svc = 'Running'; op = $false }
$o = Invoke-DeadSockClient -R (New-Result 'x' @()) -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'absent, disposable, service running -> no decoy, not judged' "$($o.fallback_judged)/$($o.decoy)" 'False/none'
$script:mock = @{ pipes = @(); exit = 2; out = ''; svc = 'Stopped'; op = $false; decoyStatus = 'listening'; decoyConns = 0 }
$o = Invoke-DeadSockClient -R (New-Result 'x' @()) -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'decoy listening, 0 connections -> no fallback' "$($o.fallback_judged)/$($o.no_fallback)" 'True/True'
Check '  decoy served the default name' $script:mock.decoyStarted 'openssh-ssh-agent'
$script:mock = @{ pipes = @(); exit = 2; out = ''; svc = 'Stopped'; op = $false; decoyStatus = 'listening'; decoyConns = 1 }
$o = Invoke-DeadSockClient -R (New-Result 'x' @()) -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'decoy contacted -> fallback detected' "$($o.fallback_judged)/$($o.no_fallback)" 'True/False'
$script:mock = @{ pipes = @(); exit = 2; out = ''; svc = 'Stopped'; op = $false; decoyStatus = 'create_failed'; decoyConns = 0 }
$o = Invoke-DeadSockClient -R (New-Result 'x' @()) -Label 'l' -Exe 'ssh-add.exe' -SockPath 'p'
Check 'decoy failed to start -> not judged' "$($o.fallback_judged)/$($o.decoy)" 'False/none'
"FAILURES=$fail"
if ($fail) { exit 1 }
