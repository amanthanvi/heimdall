#!/bin/bash
# usage (through `wsl.exe -d <controller> --cd <scratch> --exec /bin/bash run.sh NAME LABEL [args]`):
# runs the lifecycle harness in the controller (owner's) distribution against the disposable target.
. "$(dirname "$0")/lib.sh"
NAME=$1 LABEL=$2; shift 2
export TMPDIR=$S/tmp TEMP="$W/tmp" TMP="$W/tmp" WSLENV="TEMP/p:TMP/p"
OUT=$S/out/$LABEL
exec bash "$S/repo/tests/native/wsl/run_g03_wsl_lifecycle.sh" --out "$OUT" --target-distro "$NAME" --allow-terminate-target "$@" < /dev/null
