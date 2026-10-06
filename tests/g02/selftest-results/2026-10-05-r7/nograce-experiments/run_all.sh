#!/bin/sh
# Driver for the run_mirror_nograce experiments (M00-T05-harness-r4-fix).  Usage: run_all.sh REPO_ROOT OUTFILE
# Prints each command, its output and its real exit code.  SSH_AUTH_SOCK is unset; nothing outside temp dirs is written.
set -u
R=$1; OUT=$2; E=$(cd "$(dirname "$0")" && pwd -P)
unset SSH_AUTH_SOCK
REF=$R/tests/g02/reference_impl.py
PY=${PY:-python3}
run() { echo "\$ $*" >> "$OUT"; "$@" >> "$OUT" 2>&1; echo "# exit_code=$?" >> "$OUT"; }
echo "# date -u start: $(date -u +%Y-%m-%dT%H:%M:%SZ); host: $(uname -s) $(uname -m) $(uname -r); python: $($PY -V 2>&1); cpus: $(getconf _NPROCESSORS_ONLN)" >> "$OUT"
run env REF_MUTATE=run_mirror_nograce $PY "$E/pty_cycles.py" "$REF" simple 15
run env REF_MUTATE=run_mirror_nograce $PY "$E/pty_cycles.py" "$REF" grandkids 15 100
run env REF_MUTATE=run_mirror_nograce CREAD=1 $PY "$E/pty_cycles.py" "$REF" simple 15
run env REF_MUTATE=run_mirror_nograce CREAD=1 $PY "$E/pty_cycles.py" "$REF" grandkids 15 100
run env REF_MUTATE=run_mirror_nograce CREAD=1 $PY "$E/burn.py" 18 $PY "$E/pty_cycles.py" "$REF" simple 15
run env REF_MUTATE=run_mirror_nograce CREAD=1 $PY "$E/burn.py" 18 $PY "$E/pty_cycles.py" "$REF" grandkids 15 100
run env CREAD=1 $PY "$E/pty_cycles.py" "$REF" grandkids 15 100
run env CREAD=1 $PY "$E/burn.py" 18 $PY "$E/pty_cycles.py" "$REF" grandkids 15 100
run env REF_MUTATE=run_mirror_nograce $PY "$E/killpg_cycles.py" "$REF" 12
run $PY "$E/killpg_cycles.py" "$REF" 12
L=$(mktemp -d)/ref_logged.py
run $PY "$E/make_logged_copy.py" "$REF" "$L"
run $PY "$E/killpg_cycles.py" "$L" 12
run env CREAD=1 $PY "$E/pty_cycles.py" "$L" grandkids 10 100
echo "# date -u end: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT"
