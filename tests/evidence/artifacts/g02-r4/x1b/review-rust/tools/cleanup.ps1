param([string]$Base)
$n = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and (($_.CommandLine -and $_.CommandLine.Contains('M00-T05-x1b-review-rust')) -or ($_.ExecutablePath -and $_.ExecutablePath.Contains('M00-T05-x1b-review-rust'))) }).Count
Write-Host "procs_with_task_scratch=$n"
$bd = Join-Path $Base 'pb\batnospace'
foreach ($x in @('dot.bat.', 'spc.bat ')) { $q = '\\?\' + (Join-Path $bd $x); if ([IO.File]::Exists($q)) { [IO.File]::Delete($q) } }
$junc = Join-Path $Base 'pb\pjunc'; if (Test-Path -LiteralPath $junc) { [IO.Directory]::Delete($junc) }
Remove-Item -LiteralPath $Base -Recurse -Force
Write-Host ("removed=" + (-not (Test-Path -LiteralPath $Base)))
