#!/usr/bin/env bash
# Re-runs every static check and self-test available on this macOS host; real exit codes.
set -u
cd <home>/GitRepos/heimdall
unset SSH_AUTH_SOCK SSH_AGENT_PID
export PYTHONDONTWRITEBYTECODE=1
OUT=tests/evidence/artifacts/g03/static-checks/fix-m00-t04-g03-fix
HS=tests/evidence/artifacts/g03/harness-selftest
mkdir -p "$OUT"
red() { sed "s#$HOME#<home>#g"; }
run() { # run NAME -- cmd...
  local name="$1"; shift 2
  { echo "\$ $*"; echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; "$@" 2>&1; rc=$?; echo "exit=$rc"; } | red > "$OUT/$name.txt"
  echo "$name exit=$(tail -1 "$OUT/$name.txt" | sed 's/exit=//')"
}
run pwsh-parse -- pwsh -NoProfile -Command '$n=0; foreach ($f in Get-ChildItem tests/native/windows -Include *.ps1,*.psm1 -Recurse) { $t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e); $n += $e.Count; "{0} errors={1}" -f $f.Name,$e.Count; foreach ($x in $e) { "  {0}: {1}" -f $x.Extent.StartLineNumber,$x.Message } }; "TOTAL=$n"; if ($n) { exit 1 }'
run pwsh-embedded-scripts-and-csharp -- pwsh -NoProfile -File /tmp/g03fix/check-embedded.ps1
run pwsh-unit-verdict-and-sddl -- pwsh -NoProfile -File /tmp/g03fix/unit-checks.ps1
run psscriptanalyzer -- pwsh -NoProfile -Command '$env:PSModulePath = "/tmp/g03-psmodules" + [IO.Path]::PathSeparator + $env:PSModulePath; Import-Module PSScriptAnalyzer; "PSScriptAnalyzer " + (Get-Module PSScriptAnalyzer).Version; $s = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @("5.1","7.4") } } }; $r = Invoke-ScriptAnalyzer -Path tests/native/windows -Recurse -Severity Error,Warning -Settings $s; "errors=" + @($r | Where-Object Severity -eq "Error").Count; "compatibility_findings=" + @($r | Where-Object RuleName -eq "PSUseCompatibleSyntax").Count; $r | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object { "{0} {1}" -f $_.Count,$_.Name }; $r | ForEach-Object { "{0}:{1} {2}" -f $_.ScriptName,$_.Line,$_.RuleName }; if (@($r | Where-Object Severity -eq "Error").Count) { exit 1 }'
run shellcheck -- sh -c 'cd tests/native/wsl && shellcheck --version | sed -n 2p && shellcheck -x -s bash *.sh'
run bash-syntax -- sh -c 'for f in tests/native/wsl/*.sh; do bash -n "$f" || exit 1; echo "ok $f"; done'
run python-compile -- sh -c 'python3 --version; PYTHONPYCACHEPREFIX=/tmp/g03fix/pyc python3 -m py_compile tests/native/wsl/*.py && echo ok'
run evidence-py-convention -- bash /tmp/g03fix/ev-check.sh
# self-tests (outputs replace the previous self-test artifacts)
rm -rf "$HS/powershell-macos" "$HS/windows-orchestrator-on-macos"; mkdir -p "$HS/powershell-macos" "$HS/windows-orchestrator-on-macos"
run selftest-powershell -- pwsh -NoProfile -File tests/native/windows/Test-G03HarnessSelf.ps1
cp "$OUT/selftest-powershell.txt" "$HS/powershell-macos/console.txt"
run selftest-wsl-mechanics -- bash tests/native/wsl/selftest_unix.sh
cp "$OUT/selftest-wsl-mechanics.txt" "$HS/wsl-mechanics-darwin/console.txt"
run orchestrator-non-windows-branch -- pwsh -NoProfile -File tests/native/windows/Invoke-G03WindowsProbes.ps1 -OutDir "$HS/windows-orchestrator-on-macos"
cp "$OUT/orchestrator-non-windows-branch.txt" "$HS/windows-orchestrator-on-macos/console.txt"
python3 /tmp/g03fix/refresh-hashes.py > "$OUT/placeholder-hash-refresh.txt" 2>&1; echo "placeholder-hash-refresh exit=$?"
run schema-and-convention-validation -- /tmp/g03-venv/bin/python /tmp/g03fix/validate.py
run leftover-processes -- sh -c 'echo "agent_proxy.py processes: $(pgrep -f tests/native/wsl/agent_proxy.py | wc -l | tr -d " ")"; echo "InstrumentedAgent.ps1 processes: $(pgrep -f tests/native/windows/InstrumentedAgent.ps1 | wc -l | tr -d " ")"; echo "ssh-agent pids (exact name): $(pgrep -x ssh-agent | tr "\n" " ")"'
run canary-scan -- sh -c 'if grep -rl "HEIMDALL_""CANARY_" tests/evidence/artifacts/g03 tests/evidence/g03-*.json docs/research/g03-windows-wsl.md; then echo "CANARY FOUND"; exit 1; else echo "no canary strings"; fi'
run pycache-check -- sh -c 'find tests/native -name __pycache__ -print; echo "count=$(find tests/native -name __pycache__ | wc -l | tr -d " ")"'
