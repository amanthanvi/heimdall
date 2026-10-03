#!/bin/bash
# Runs the G04 / preliminary G09 OpenSSH mechanism experiments in sequence against RUNNING
# fixtures. Bring them up first with tests/fixtures/ssh/up.sh and down afterwards with
# tests/fixtures/ssh/down.sh (this runner does neither). Outputs go to
# tests/evidence/artifacts/g04/experiments/<G04_RUN_STAMP>/; exit codes in exit-codes.txt.
# Then: python3 tests/native/g04/make_records.py <G04_RUN_STAMP> --validate
# For a complete fresh run (fixture down/up/smoke + this runner) use fresh_run.sh; see README.md.
# Knobs: G04_EXPERIMENTS (space-separated script names), G04_E1_LIFETIME, G04_E2_LEAD,
# G04_E2_GRACE_CHECK, G04_E5_CHILD_LIFE, G04_E7_VALID, G04_E7_PERSIST, G04_RACE_N, G04_RACE_PERSIST, G04_RACE_CLIENT_MAX_MS,
# G04_RACE_STOP_MAX_MS, G04_E7P_VALID, G04_E7P_DELAY1, G04_E7P_DELAY2.
set -u
unset SSH_AUTH_SOCK SSH_AGENT_PID
D="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$D/../../.." && pwd)"
export G04_RUN_STAMP="${G04_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="$REPO/tests/evidence/artifacts/g04/experiments/$G04_RUN_STAMP"; mkdir -p "$OUT"
{ echo "run_stamp=$G04_RUN_STAMP"; echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "build_commit=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
  echo "knobs=E1_LIFETIME=${G04_E1_LIFETIME:-120} E2_LEAD=${G04_E2_LEAD:-90} E2_GRACE_CHECK=${G04_E2_GRACE_CHECK:-1} E5_CHILD_LIFE=${G04_E5_CHILD_LIFE:-60} E7_VALID=${G04_E7_VALID:-90} E7_PERSIST=${G04_E7_PERSIST:-10m} RACE_N=${G04_RACE_N:-50} RACE_PERSIST=${G04_RACE_PERSIST:-3} RACE_CLIENT_MAX_MS=${G04_RACE_CLIENT_MAX_MS:-60} RACE_STOP_MAX_MS=${G04_RACE_STOP_MAX_MS:-40} E7P_VALID=${G04_E7P_VALID:-40} E7P_DELAY1=${G04_E7P_DELAY1:-2} E7P_DELAY2=${G04_E7P_DELAY2:-15}"
} >"$OUT/run.env"
(cd "$D" && shasum -a 256 ./*.sh ./*.py) >"$OUT/script-sha256.txt"
sed -e "s|$REPO|<repo>|g" -e "s|$HOME|<home>|g" "$REPO/tests/fixtures/ssh/runtime/versions.txt" >"$OUT/fixture-versions.txt" 2>/dev/null
: >"$OUT/exit-codes.txt"
for e in ${G04_EXPERIMENTS:-e1_dedicated_agent e2_cert_expiry e3_principal_scope e4_account_ca_principals enroll_marker_key e5_issuer_separation e6_fresh_login_verification e7_mux_after_expiry e7_mux_preconnected e7_mux_stop_race}; do
  echo "== $e start $(date -u +%H:%M:%SZ)"
  "$D/$e.sh" >"$OUT/$e.stdout.txt" 2>&1; rc=$?
  echo "$e $rc" >>"$OUT/exit-codes.txt"
  echo "== $e exit=$rc $(date -u +%H:%M:%SZ)"
done
echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$OUT/run.env"
