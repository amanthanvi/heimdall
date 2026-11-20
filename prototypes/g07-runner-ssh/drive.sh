#!/bin/bash
# Disposable G07 driver, run on the controller (macOS). Reaches the devbox only through the owner's
# ordinary `ssh devbox` transport with agent/X11 forwarding forced off; every fixture key and sshd
# lives in one scratch dir on the devbox (created here, removed by `cleanup`). The fixture CA that
# stands in for the controller's issuer (ADR-0005 §4.2) stays in a Mac scratch dir.
#   drive.sh phase1 | phase2 | collect | cleanup      (state in $S)
set -u
S=/tmp/hm-g07-mac; mkdir -p "$S"; chmod 700 "$S"
T() { ssh -o ForwardAgent=no -o ForwardX11=no -o BatchMode=yes -o ConnectTimeout=15 devbox "$@"; }
here=$(cd "$(dirname "$0")" && pwd)
case "$1" in
phase1)
  R=hm-g07-$(openssl rand -hex 4); echo "$R" > "$S/rdir"
  T "mkdir -m 700 ~/$R" && scp -q -o ForwardAgent=no "$here/probe.sh" "$here/runner.sh" "devbox:$R/" && T "chmod 700 ~/$R/*.sh"
  T "bash ~/$R/probe.sh readout" > "$S/readout.txt" 2>&1; echo "readout rc=$?"
  T "bash ~/$R/probe.sh setup" > "$S/setup.txt" 2>&1; echo "setup rc=$?"
  T "bash ~/$R/probe.sh roles" > "$S/roles.txt" 2>&1; echo "roles rc=$?" ;;
phase2)
  R=$(cat "$S/rdir")
  rm -f "$S/ca" "$S/ca.pub" "$S/kr.pub" "$S/kr-cert.pub"
  ssh-keygen -q -t ed25519 -N '' -C hm-g07-fixture-ca -f "$S/ca"
  echo "cert-authority,principals=\"hm:dest-g07:acct\" $(cat "$S/ca.pub")" | T "bash ~/$R/probe.sh runner-prep" > "$S/kr.pub"
  ssh-keygen -q -s "$S/ca" -I g07-runner-kenv -n hm:dest-g07:acct -V -5m:+150s "$S/kr.pub" && ssh-keygen -L -f "$S/kr-cert.pub" | grep -E 'Valid|Principals' -A1 > "$S/cert-info.txt"
  T "cat > ~/$R/kr-cert.pub" < "$S/kr-cert.pub"
  date +%s > "$S/signed_at"
  T "bash ~/$R/probe.sh runner-start" > "$S/runner-start.txt" 2>&1; echo "runner-start rc=$?"
  date +%s > "$S/controller_left_at" ;;
collect)
  R=$(cat "$S/rdir"); T "bash ~/$R/probe.sh status" > "$S/status.txt" 2>&1; echo "status rc=$?" ;;
cleanup)
  R=$(cat "$S/rdir"); T "bash ~/$R/probe.sh cleanup; ls -d ~/$R 2>/dev/null || echo gone" ; rm -f "$S/ca" "$S/ca.pub" ;;
esac
