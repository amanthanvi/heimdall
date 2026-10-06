# M00-T05-x1b-fix-rust: run cross-compiled Rust test binaries natively (harness code, not product code).
param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$TestExe,
      [Parameter(Mandatory = $true)][string]$ProtoExe, [string]$Label = 'run')
$ErrorActionPreference = 'Stop'
$tmp = Join-Path $Root ('tmp-' + $Label)
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TEMP = $tmp; $env:TMP = $tmp
$env:HEIMDALL_PROTO_BIN = $ProtoExe
$env:HEIMDALL_G02_FIXTURES = (Join-Path $Root 'fixtures\profiles')
$env:SSH_AUTH_SOCK = '\\.\pipe\hm-M00-T05-x1b-fix-rust-none'
& $TestExe --test-threads=1 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
"TEST_EXIT=$code"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
exit $code
