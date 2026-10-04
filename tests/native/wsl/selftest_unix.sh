#!/usr/bin/env bash
# Self-test of the G03 WSL harness mechanics on any Unix host with python3 and
# OpenSSH (ssh-agent, ssh-add, ssh-keygen). Runs the Mode B mechanics probes
# (endpoint permissions, unauthorized key, socket deletion, stale socket,
# teardown/deadline) against a disposable fixture ssh-agent, labeling every
# record G03-harness-selftest-unix-*. This is NOT G03 evidence: no WSL, no
# interop, no Windows, no second distribution are involved.
#
# Usage: selftest_unix.sh [--out DIR] [--other-linux-user NAME]
set -u -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
OUT="$REPO/tests/evidence/artifacts/g03/harness-selftest/wsl-mechanics-$(uname -s | tr '[:upper:]' '[:lower:]')"
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --other-linux-user) EXTRA+=(--other-linux-user "$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
unset SSH_AUTH_SOCK SSH_AGENT_PID
rm -rf "$OUT"
TMPDIR=/tmp exec "$HERE/run_g03_wsl_probes.sh" --selftest-non-wsl --out "$OUT" \
  --probes b-perms,b-unauthorized,b-deletion,b-stale,b-teardown "${EXTRA[@]+"${EXTRA[@]}"}"
