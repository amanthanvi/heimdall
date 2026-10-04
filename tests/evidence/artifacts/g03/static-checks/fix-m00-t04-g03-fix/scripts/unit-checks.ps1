$ErrorActionPreference = 'Stop'
$path = (Resolve-Path 'tests/native/windows/Invoke-G03WindowsProbes.ps1').Path
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
foreach ($fn in @('New-Result', 'Set-Verdict', 'ConvertFrom-ServiceSddlRights', 'Test-AnyTrusteeRight')) {
  $def = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $fn }, $true)
  . ([scriptblock]::Create($def.Extent.Text))
}
$fail = 0
function Check { param($Name, $Got, $Want) $ok = ("$Got" -eq "$Want"); if (-not $ok) { $script:fail++ }; "{0,-58} got={1} want={2} {3}" -f $Name, $Got, $Want, $(if ($ok) { 'ok' } else { 'MISMATCH' }) }
$r = Set-Verdict (New-Result 'x' @()) @{ a = $true; b = $true };            Check 'all true -> verified/pass' "$($r.Status)/$($r.Observed.verdict)" 'verified/pass'
$r = Set-Verdict (New-Result 'x' @()) @{ a = $true; b = $false };           Check 'one false -> verified/fail' "$($r.Status)/$($r.Observed.verdict)" 'verified/fail'
Check '  failed_criteria lists b' ($r.Observed.failed_criteria -join ',') 'b'
$r = Set-Verdict (New-Result 'x' @()) @{ a = $null; b = $false };           Check 'null + false -> in_progress/inconclusive' "$($r.Status)/$($r.Observed.verdict)" 'in_progress/inconclusive'
Check '  failed_criteria still lists b' ($r.Observed.failed_criteria -join ',') 'b'
$r = Set-Verdict (New-Result 'x' @()) @{};                                 Check 'no criteria -> in_progress/inconclusive' "$($r.Status)/$($r.Observed.verdict)" 'in_progress/inconclusive'
# Service DACL parsing on the pinned installer SDDL (install-sshd.ps1:165, G03-S02)
$sd = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)'
$rights = ConvertFrom-ServiceSddlRights $sd
Check 'AU codes' ($rights['AU'] -join ',') 'RP'
Check 'IU codes' ($rights['IU'] -join ',') 'CC,LC,SW,LO,CR,RC'
$na = @('AU', 'IU', 'BU', 'WD')
Check 'non-admin can start (RP)' (Test-AnyTrusteeRight $rights $na @('RP')) 'True'
Check 'non-admin can stop (WP)' (Test-AnyTrusteeRight $rights $na @('WP')) 'False'
Check 'non-admin can reconfigure (DC/WD/WO)' (Test-AnyTrusteeRight $rights $na @('DC', 'WD', 'WO')) 'False'
# Boundary case the old substring match got wrong: codes "LO"+"CR" contain no "OC" right.
$r2 = ConvertFrom-ServiceSddlRights '(A;;SWLOCR;;;AU)'
Check 'no cross-boundary match (OC not granted)' (Test-AnyTrusteeRight $r2 @('AU') @('OC')) 'False'
Check 'substring would have matched' ([bool]('SWLOCR' -match 'OC')) 'True'
"FAILURES=$fail"
if ($fail) { exit 1 }
