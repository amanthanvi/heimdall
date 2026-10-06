#!/bin/bash
# usage (through wsl.exe -d Ubuntu --exec): wsl-run.sh LABEL PROBES
T=M00-T04-G03-native-review
S=$HOME/hm-m00/$T
W=$(cat $S/winscratch.path)
export TMPDIR=$S/tmp TEMP="$W/tmp" TMP="$W/tmp" WSLENV="TEMP/p:TMP/p"
exec bash $S/repo/tests/native/wsl/run_g03_wsl_probes.sh --out "$S/out/$1" --probes "$2"
