$ErrorActionPreference = 'Stop'
$path = (Resolve-Path 'tests/native/windows/Invoke-G03WindowsProbes.ps1').Path
$t = $null; $e = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
$assigns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Right.Expression -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Right.Expression.StringConstantType -eq 'SingleQuotedHereString' }, $false)
$fail = 0
foreach ($a in $assigns) {
  $name = $a.Left.Extent.Text; $val = $a.Right.Expression.Value
  $t2 = $null; $e2 = $null
  [void][System.Management.Automation.Language.Parser]::ParseInput($val, [ref]$t2, [ref]$e2)
  "{0}: embedded script parse errors={1}" -f $name, $e2.Count
  foreach ($x in $e2) { "  line {0}: {1}" -f $x.Extent.StartLineNumber, $x.Message; $fail++ }
  if ($name -eq '$OtherUserWin32') {
    # Extract the C# between @" and "@ and compile it (no native call is made).
    $cs = ($val -split '@"', 2)[1]; $cs = ($cs -split '"@', 2)[0]
    Add-Type -TypeDefinition $cs
    "  G03OU compiled: " + [bool]('G03OU' -as [type])
  }
}
# InstrumentedAgent C# (Windows-only block): compile on this host without calling it.
$ia = Get-Content -Raw 'tests/native/windows/InstrumentedAgent.ps1'
$cs = ($ia -split "Add-Type -TypeDefinition @'", 2)[1]; $cs = ($cs -split "`n'@", 2)[0]
Add-Type -TypeDefinition $cs
"G03PipeInfo compiled: " + [bool]('G03PipeInfo' -as [type]) + "; G03PipeCreate compiled: " + [bool]('G03PipeCreate' -as [type])
if ($fail) { exit 1 }
