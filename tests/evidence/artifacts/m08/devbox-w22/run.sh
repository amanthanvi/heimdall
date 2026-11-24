#!/usr/bin/env bash
# M08 W2.2/W2.3 devbox steps at 2215e8a0. Everything in this scratch dir; HOME is scratch.
set -u
D=$(cd "$(dirname "$0")" && pwd -P)
mkdir -p "$D/src" "$D/home" "$D/tmp"
tar -C "$D/src" -xf "$D/src.tar"
export HOME="$D/home" TMPDIR="$D/tmp"
unset SSH_AUTH_SOCK
cd "$D/src"
step() { name=$1; shift; echo "== $name"; nice -n 10 "$@" >"$D/$name.log" 2>&1; rc=$?; echo "== $name: exit $rc"; tail -2 "$D/$name.log"; }
step stategen-unit "$D/unit"
step stategen-faults "$D/faults"
step install-selftest-sh bash tests/native/m08/lifecycle/install-selftest.sh
step provenance-selftest python3 -I tools/packaging/provenance.py self-test
step agent-delay-selftest python3 -I tools/benchmarks/m08/agent-delay.py self-test
step run-campaign-selftest bash fuzz/run-campaign-selftest.sh
step verify-artifact-selftest python3 -I tools/packaging/verify_artifact.py --self-test
step analyze-selftest python3 -I tools/benchmarks/m08/analyze.py --self-test
step docs-commands-selftest python3 -I tools/validation/docs_commands_check.py --self-test
step docs-commands-check python3 -I tools/validation/docs_commands_check.py
