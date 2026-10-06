# Scratch launcher (not part of the repo): pins TEMP/TMP to the task scratch for
# this process and its children only, then runs the target script in-process.
param([Parameter(Mandatory=$true)][string]$Target, [Parameter(ValueFromRemainingArguments=$true)]$Rest)
$scr = Split-Path -Parent $PSCommandPath
$tmp = Join-Path $scr 'tmp'
[void][IO.Directory]::CreateDirectory($tmp)
$env:TEMP = $tmp; $env:TMP = $tmp
$h = @{}; $pos = @(); $i = 0
if ($null -eq $Rest) { $Rest = @() }
$Rest = @($Rest)
while ($i -lt $Rest.Count) {
  $a = [string]$Rest[$i]
  if ($a.StartsWith('-')) {
    $n = $a.Substring(1)
    if ($i + 1 -lt $Rest.Count -and -not ([string]$Rest[$i+1]).StartsWith('-')) { $v = [string]$Rest[$i+1]; if ($v -like '*,*' -and $n -eq 'Probes') { $v = $v -split ',' }; $h[$n] = $v; $i += 2 }
    else { $h[$n] = $true; $i += 1 }
  } else { $pos += $a; $i += 1 }
}
if (-not [IO.Path]::IsPathRooted($Target)) { $Target = Join-Path $scr $Target }
if (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue) { $PSStyle.OutputRendering = 'PlainText' }
& $Target @h
exit $LASTEXITCODE
