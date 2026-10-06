#!/bin/bash
# usage (through wsl.exe --exec): run.sh LABEL [extra harness args]
T=M00-T04-G03-native-wsl
S=$HOME/hm-m00/$T
W=$(cat $S/winscratch.path)
# Linux temp and Windows temp (GetTempPath for the harness' Windows scratch) inside the task scratch.
export TMPDIR=$S/tmp TEMP="$W/tmp" TMP="$W/tmp" WSLENV="TEMP/p:TMP/p"
F=$S/fixture
PA=$(cat $F/portA); PB=$(cat $F/portB); U=$(id -un)
MF=$(cat $S/manifest.path)
LABEL=$1; shift
OUT=$S/repo/tests/evidence/artifacts/g03/native-wsl/runs/$LABEL
export PATH="/mnt/c/Program Files/OpenSSH:$PATH"
exec bash $S/repo/tests/native/wsl/run_g03_wsl_probes.sh --out "$OUT" --win-manifest "$MF" \
  --ssh-host 127.0.0.1 --ssh-port "$PA" --ssh-user "$U" --known-hosts "$F/known_hosts" \
  --git-url "ssh://$U@127.0.0.1:$PA/~/hm-m00/$T/fixture/probe.git" --git-push \
  --ca-key "$F/user_ca" --cert-principal "$U" --cert-host 127.0.0.1 --cert-port "$PB" --cert-user "$U" "$@"
