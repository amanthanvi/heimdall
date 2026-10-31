# Counts only: registry/shortcut/Terminal-fragment traces of ONE distribution name, plus the tarball hash.
param([Parameter(Mandatory=$true)][string]$Name, [string]$Tarball)
$k = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue)
"lxss_subkeys_total=" + $k.Count
"lxss_subkeys_named_target=" + @($k | Where-Object { (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DistributionName -eq $Name }).Count
$sm = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
"start_menu_lnk_named_target=" + @(Get-ChildItem -LiteralPath $sm -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -like ('*' + $Name + '*') }).Count
$fr = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\Fragments'
"wt_fragments_dir_exists=" + (Test-Path -LiteralPath $fr)
"wt_fragment_files_mentioning_target=" + @(Get-ChildItem -LiteralPath $fr -Recurse -File -ErrorAction SilentlyContinue | Where-Object { Select-String -LiteralPath $_.FullName -SimpleMatch -Quiet -Pattern $Name }).Count
if ($Tarball -and (Test-Path -LiteralPath $Tarball)) { "tarball_sha256_windows=" + (Get-FileHash -LiteralPath $Tarball -Algorithm SHA256).Hash.ToLower() } else { "tarball_present=False" }
