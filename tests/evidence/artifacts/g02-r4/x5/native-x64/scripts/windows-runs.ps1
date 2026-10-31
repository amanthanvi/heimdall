# M00-T05-r5-x5 native Windows subset. Creates NO iroh endpoint:
#  W1 load check: x5-iroh.exe (ring-min, default, none) with no arguments -> usage, exit 64.
#     main() builds a tokio runtime and returns before any endpoint is created.
#  W3 x5-gosup.exe + two no-iroh baseline helpers (bin\none\x5-iroh.exe): helpers never send
#     "ready", so the supervisor times out (15 s), sends shutdown, gets bye, exits 1 by design.
#  W4 supervisor death: TerminateProcess (Process.Kill on the handle we created) of the
#     supervisor during its ready wait; both baseline helpers must exit on stdin EOF.
# Children get an environment holding only SystemRoot. Sockets of each exact PID are listed
# with Get-NetUDPEndpoint/Get-NetTCPConnection -OwningProcess and netstat -ano (PID column).
$ErrorActionPreference = 'Stop'
$D  = Join-Path $env:LOCALAPPDATA 'hm-m00\M00-T05-r5-x5'
$G  = Join-Path $D 'bin\x5-gosup.exe'
$N  = Join-Path $D 'bin\none\x5-iroh.exe'

function Start-Clean([string]$exe, [string]$argline) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $exe; $psi.Arguments = $argline
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $false
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
  $psi.WorkingDirectory = $D
  $psi.EnvironmentVariables.Clear(); $psi.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
  $p = [System.Diagnostics.Process]::Start($psi)
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  return @{ P = $p; Out = $o; Err = $e; T0 = [Diagnostics.Stopwatch]::StartNew() }
}

function Show-Sockets([int]$id) {
  $u = @(Get-NetUDPEndpoint -OwningProcess $id -ErrorAction SilentlyContinue)
  $t = @(Get-NetTCPConnection -OwningProcess $id -ErrorAction SilentlyContinue)
  "    pid $id Get-NetUDPEndpoint=$($u.Count) Get-NetTCPConnection=$($t.Count)"
  foreach ($x in $u) { "      UDP $($x.LocalAddress):$($x.LocalPort)" }
  foreach ($x in $t) { "      TCP $($x.LocalAddress):$($x.LocalPort) $($x.State)" }
  $ns = @(netstat -ano | Where-Object { ($_ -split '\s+' | Where-Object { $_ -ne '' } | Select-Object -Last 1) -eq "$id" })
  "    pid $id netstat -ano rows with this PID=$($ns.Count)"
  foreach ($l in $ns) { "      $($l.Trim())" }
}

function Get-Kids([int]$ppid) {
  @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $ppid" | Select-Object ProcessId, ParentProcessId, Name, CreationDate)
}

$os = Get-CimInstance Win32_OperatingSystem
"## windows caption=$($os.Caption) version=$($os.Version) build=$($os.BuildNumber) arch=$env:PROCESSOR_ARCHITECTURE ps=$($PSVersionTable.PSVersion)"

foreach ($v in 'ring-min', 'default', 'none') {
  $exe = Join-Path $D "bin\$v\x5-iroh.exe"
  foreach ($i in 1..3) {
    $r = Start-Clean $exe ''
    $done = $r.P.WaitForExit(15000); $ms = $r.T0.ElapsedMilliseconds
    if (-not $done) { $r.P.Kill(); "W1 $v run=$i TIMEOUT killed" ; continue }
    $r.P.WaitForExit()
    "W1 load $v run=$i exit=$($r.P.ExitCode) wall_ms=$ms stderr=$($r.Err.Result.Trim())"
  }
}

foreach ($i in 1..3) {
  $r = Start-Clean $G "-helper `"$N`""
  $kids = @(); foreach ($k in 1..50) { $kids = Get-Kids $r.P.Id; if ($kids.Count -ge 2) { break }; Start-Sleep -Milliseconds 100 }
  Start-Sleep -Milliseconds 1500
  $hp = @(); foreach ($k in $kids) { $h = [System.Diagnostics.Process]::GetProcessById([int]$k.ProcessId); $null = $h.Handle; $hp += $h }
  "W3 gosup+none run=$i supervisor_pid=$($r.P.Id) name=$($r.P.ProcessName) children=$(($kids | ForEach-Object { "$($_.ProcessId):$($_.Name):ppid=$($_.ParentProcessId)" }) -join ',')"
  Show-Sockets $r.P.Id
  foreach ($k in $kids) { Show-Sockets ([int]$k.ProcessId) }
  $done = $r.P.WaitForExit(40000); $ms = $r.T0.ElapsedMilliseconds
  if (-not $done) { $r.P.Kill(); "  TIMEOUT: killed supervisor by its handle" }
  $r.P.WaitForExit()
  "W3 gosup+none run=$i exit=$($r.P.ExitCode) wall_ms=$ms stdout=$($r.Out.Result.Trim())"
  $null = $r.Err.Wait(5000)
  "  stderr: $(($r.Err.Result -replace 'pid \d+', 'pid <pid>').Trim() -replace "`r?`n", ' | ')"
  foreach ($h in $hp) { if ($h.WaitForExit(5000)) { "  child $($h.Id) exit=$($h.ExitCode)" } else { "  WARNING child $($h.Id) alive after supervisor exit; killing it by its handle"; $h.Kill() } }
}

foreach ($i in 1..3) {
  $r = Start-Clean $G "-helper `"$N`""
  $kids = @(); foreach ($k in 1..50) { $kids = Get-Kids $r.P.Id; if ($kids.Count -ge 2) { break }; Start-Sleep -Milliseconds 100 }
  Start-Sleep -Milliseconds 1500
  $hp = @(); foreach ($k in $kids) { $h = [System.Diagnostics.Process]::GetProcessById([int]$k.ProcessId); $null = $h.Handle; $hp += $h }
  $sp = Get-Process -Id $r.P.Id
  $idok = (-not $r.P.HasExited) -and ($sp.StartTime -eq $r.P.StartTime) -and ($sp.Path -eq $G) -and ($kids.Count -eq 2) -and
          (@($hp | Where-Object { $_.ProcessName -eq 'x5-iroh' -and -not $_.HasExited }).Count -eq 2) -and
          (@($kids | Where-Object { $_.ParentProcessId -eq $r.P.Id }).Count -eq 2)
  "W4 sup-death run=$i supervisor_pid=$($r.P.Id) helper_pids=$(($hp | ForEach-Object { $_.Id }) -join ',') identity_ok=$idok"
  Show-Sockets $r.P.Id
  foreach ($h in $hp) { Show-Sockets $h.Id }
  if (-not $idok) { "  identity check failed; not killing"; $r.P.WaitForExit(40000) | Out-Null; continue }
  $sw = [Diagnostics.Stopwatch]::StartNew(); $r.P.Kill(); $r.P.WaitForExit()
  "  supervisor TerminateProcess done; supervisor exit=$($r.P.ExitCode)"
  foreach ($h in $hp) {
    $gone = $h.WaitForExit(10000); $ms = $sw.ElapsedMilliseconds
    if ($gone) { "  helper $($h.Id) exited after_ms=$ms exit=$($h.ExitCode)" } else { "  WARNING helper $($h.Id) still alive after 10 s; killing it by its handle"; $h.Kill() }
  }
  $null = $r.Err.Wait(5000)
  "  stderr: $(($r.Err.Result -replace 'pid \d+', 'pid <pid>').Trim() -replace "`r?`n", ' | ')"
}
"## done"
