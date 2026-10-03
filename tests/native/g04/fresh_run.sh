#!/bin/bash
# Fresh end-to-end run of the G04 / preliminary G09 experiments:
#   tests/fixtures/ssh/down.sh  -> fixture-down-pre.log   (dispose of any previous fixture material)
#   tests/fixtures/ssh/up.sh    -> fixture-up.log         (new keys, CA, host keys, containers)
#   tests/fixtures/ssh/smoke.sh -> fixture-smoke.log      (fixture control; recorded, not a gate)
#   tests/native/g04/run_all.sh                           (all experiments, real exit codes)
# into tests/evidence/artifacts/g04/experiments/<G04_RUN_STAMP>/. Logs are redacted (repo root and
# $HOME replaced by tokens) and end with "exit=<real exit code>".
# Fixtures are LEFT UP so the logs can be reviewed and single experiments re-run. Afterwards:
#   tests/fixtures/ssh/down.sh  (save its output as <run dir>/fixture-down-post.log)
#   python3 tests/native/g04/make_records.py <G04_RUN_STAMP> --validate
# Exit: 0 when every step exited 0; otherwise the first non-zero step's code (run_all.sh itself
# exits 0; per-experiment codes are in exit-codes.txt). Aborts (exit 4) if up.sh fails.
set -u
unset SSH_AUTH_SOCK SSH_AGENT_PID
D="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$D/../../.." && pwd)"; FX="$REPO/tests/fixtures/ssh"
export G04_RUN_STAMP="${G04_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="$REPO/tests/evidence/artifacts/g04/experiments/$G04_RUN_STAMP"; mkdir -p "$OUT"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
first=0
step() {  # NAME CMD... : run, redact output into fixture-NAME.log, append the real exit code
  local name=$1 tmp rc; shift
  tmp="$(mktemp /tmp/hmg04-fresh.XXXXXX)"
  echo "== $name start $(ts)"
  { echo "== $name start $(ts)"; "$@"; } >"$tmp" 2>&1; rc=$?
  { sed -e "s|$REPO|<repo>|g" -e "s|$HOME|<home>|g" "$tmp"; echo "== $name end $(ts)"; echo "exit=$rc"; } >"$OUT/fixture-$name.log"
  rm -f "$tmp"
  echo "== $name exit=$rc $(ts)"
  [ "$first" = 0 ] && [ "$rc" != 0 ] && first=$rc
  return "$rc"
}
step down-pre "$FX/down.sh"
step up "$FX/up.sh" || { echo "up.sh failed; not running experiments"; exit 4; }
step smoke "$FX/smoke.sh"
echo "== run_all start $(ts) stamp=$G04_RUN_STAMP"
"$D/run_all.sh"; rc=$?
echo "== run_all exit=$rc $(ts)"
[ "$first" = 0 ] && [ "$rc" != 0 ] && first=$rc
cat "$OUT/exit-codes.txt"
exit "$first"
