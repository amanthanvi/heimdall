#!/usr/bin/env bash
# shellcheck disable=SC2016  # single-quoted bodies are run by sh -c / pwsh -Command on purpose
# M00-T04-G03-fix2: re-runs every static check and self-test available on this macOS host
# (plus one digest-pinned Linux container run of the WSL helper unit checks); real exit codes.
set -u
REPO="$(cd "$(dirname "$0")/../../../../../../.." && pwd)"
cd "$REPO" || exit 1
unset SSH_AUTH_SOCK SSH_AGENT_PID
export PYTHONDONTWRITEBYTECODE=1
S=tests/evidence/artifacts/g03/static-checks/fix-m00-t04-g03-fix2
OUT="$S"
HS=tests/evidence/artifacts/g03/harness-selftest
DEBIAN='debian@sha256:0c8bbb8e987a035fe1d9704eb2e571b7e9a836e1caa46345290674b45b69e417'
mkdir -p "$OUT"
red() { sed -e "s#$HOME#<home>#g" -e "s#$(id -un)#<user>#g"; }
run() { # run NAME -- cmd...
  local name="$1"; shift 2
  { echo "\$ $*"; echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; "$@" 2>&1; rc=$?; echo "exit=$rc"; } | red > "$OUT/$name.txt"
  echo "$name exit=$(tail -1 "$OUT/$name.txt" | sed 's/exit=//')"
}
run pwsh-parse -- pwsh -NoProfile -Command '$n=0; foreach ($f in Get-ChildItem tests/native/windows -Include *.ps1,*.psm1 -Recurse) { $t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e); $n += $e.Count; "{0} errors={1}" -f $f.Name,$e.Count; foreach ($x in $e) { "  {0}: {1}" -f $x.Extent.StartLineNumber,$x.Message } }; "TOTAL=$n"; if ($n) { exit 1 }'
run pwsh-embedded-scripts-and-csharp -- pwsh -NoProfile -File "$S/scripts/check-embedded.ps1"
run pwsh-unit-checks -- pwsh -NoProfile -File "$S/scripts/unit-checks.ps1"
run psscriptanalyzer -- pwsh -NoProfile -Command '$env:PSModulePath = "/tmp/g03-psmodules" + [IO.Path]::PathSeparator + $env:PSModulePath; Import-Module PSScriptAnalyzer; "PSScriptAnalyzer " + (Get-Module PSScriptAnalyzer).Version; $s = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @("5.1","7.4") } } }; $r = Invoke-ScriptAnalyzer -Path tests/native/windows -Recurse -Severity Error,Warning -Settings $s; "errors=" + @($r | Where-Object Severity -eq "Error").Count; "compatibility_findings=" + @($r | Where-Object RuleName -eq "PSUseCompatibleSyntax").Count; "total=" + @($r).Count; $r | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object { "{0} {1}" -f $_.Count,$_.Name }; $r | ForEach-Object { "{0}:{1} {2}" -f $_.ScriptName,$_.Line,$_.RuleName }; if (@($r | Where-Object Severity -eq "Error").Count) { exit 1 }'
run shellcheck -- sh -c 'cd tests/native/wsl && shellcheck --version | sed -n 2p && shellcheck -x -s bash *.sh && cd "$0" && shellcheck -s bash tests/evidence/artifacts/g03/static-checks/fix-m00-t04-g03-fix2/scripts/*.sh && echo clean' "$REPO"
run bash-syntax -- sh -c 'for f in tests/native/wsl/*.sh; do bash -n "$f" || exit 1; echo "ok $f"; done'
run python-compile -- sh -c 'python3 --version; PYTHONPYCACHEPREFIX=/tmp/g03fix2/pyc python3 -m py_compile tests/native/wsl/*.py && echo ok'
run evidence-py-convention -- bash "$S/scripts/ev-check.sh"
run wsl-unit-checks-macos -- bash "$S/scripts/wsl-unit-checks.sh" "$REPO"
run wsl-unit-checks-linux-container -- docker run --rm --network none -v "$REPO":/repo:ro "$DEBIAN" bash -c 'uname -sm; bash --version | head -1; bash /repo/tests/evidence/artifacts/g03/static-checks/fix-m00-t04-g03-fix2/scripts/wsl-unit-checks.sh /repo'
run git-scope-only-output -- sh -c 'd=$(mktemp -d /tmp/g03gc-XXXX); printf "[core]\n\tsshCommand = /x/secret-path ssh -i /home/someone/key\n" > "$d/g"; mkdir "$d/s d"; git --version; echo "--- set in a temporary global config:"; HOME="$d" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$d/g" git -C "$d/s d" config --show-scope --name-only --get-regexp "^core\.sshcommand$"; echo "rc=$?"; echo "--- unset:"; HOME="$d" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$d/s d" config --show-scope --name-only --get-regexp "^core\.sshcommand$"; echo "rc=$?"; rm -rf "$d"'
# self-tests (outputs replace the previous self-test artifacts)
rm -rf "$HS/powershell-macos" "$HS/windows-orchestrator-on-macos"; mkdir -p "$HS/powershell-macos" "$HS/windows-orchestrator-on-macos"
run selftest-powershell -- pwsh -NoProfile -File tests/native/windows/Test-G03HarnessSelf.ps1
cp "$OUT/selftest-powershell.txt" "$HS/powershell-macos/console.txt"
run selftest-wsl-mechanics -- bash tests/native/wsl/selftest_unix.sh
cp "$OUT/selftest-wsl-mechanics.txt" "$HS/wsl-mechanics-darwin/console.txt"
run orchestrator-non-windows-branch -- pwsh -NoProfile -File tests/native/windows/Invoke-G03WindowsProbes.ps1 -OutDir "$HS/windows-orchestrator-on-macos"
cp "$OUT/orchestrator-non-windows-branch.txt" "$HS/windows-orchestrator-on-macos/console.txt"
run placeholder-hash-refresh -- python3 "$S/scripts/refresh-hashes.py" "$REPO"
run schema-and-convention-validation -- /tmp/g03-venv/bin/python "$S/scripts/validate.py"
run leftover-processes -- sh -c 'echo "agent_proxy.py processes: $(pgrep -f tests/native/wsl/agent_proxy.py | wc -l | tr -d " ")"; echo "InstrumentedAgent.ps1 processes: $(pgrep -f tests/native/windows/InstrumentedAgent.ps1 | wc -l | tr -d " ")"; echo "containers from this check still running (debian digest): $(docker ps -q --filter ancestor='"$DEBIAN"' | wc -l | tr -d " ")"'
run canary-scan -- sh -c 'if grep -rl "HEIMDALL_""CANARY_" tests/evidence/artifacts/g03 tests/evidence/g03-*.json docs/research/g03-windows-wsl.md tests/native; then echo "CANARY FOUND"; exit 1; else echo "no canary strings"; fi'
run pycache-check -- sh -c 'find tests/native/windows tests/native/wsl -name __pycache__ -print; echo "count (owned harness paths)=$(find tests/native/windows tests/native/wsl -name __pycache__ | wc -l | tr -d " ")"'
