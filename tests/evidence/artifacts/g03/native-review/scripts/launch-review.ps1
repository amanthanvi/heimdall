# Review launcher: pins TEMP/TMP to the review scratch, then runs the Windows harness
# with an explicit, fixed parameter set (no gates, no fixture).
param([Parameter(Mandatory = $true)][string]$Probes, [Parameter(Mandatory = $true)][string]$OutName)
$scr = Split-Path -Parent $PSCommandPath
$tmp = Join-Path $scr 'tmp'
[void][IO.Directory]::CreateDirectory($tmp)
$env:TEMP = $tmp; $env:TMP = $tmp
if (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue) { $PSStyle.OutputRendering = 'PlainText' }
& (Join-Path $scr 'repo\tests\native\windows\Invoke-G03WindowsProbes.ps1') -Probes ($Probes -split ',') -OutDir (Join-Path $scr $OutName)
exit $LASTEXITCODE
