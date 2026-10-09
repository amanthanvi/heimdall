#!/bin/bash
# Throwaway check (not in the repository): with a controlling terminal, do ssh-add -s / -K -S
# block on a PIN prompt? Runs only while the CTK store is empty, with a dedicated agent.
set -u
umask 077
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS DISPLAY KEYCHAIN_CERTIFICATES SSH_ASKPASS_REQUIRE
OUT=$1
n=$(/opt/homebrew/bin/timeout 20 /usr/sbin/sc_auth list-ctk-identities </dev/null 2>/dev/null | tr -s ' \t' '\n' | grep -c -E '^[0-9A-Fa-f]{40}$')
echo "CTK identities before: $n"; [ "$n" -eq 0 ] || { echo "store not empty; stop"; exit 3; }
T=$(mktemp -d /tmp/hm-p5-h2.XXXXXXXX); chmod 700 "$T"; mkdir -m 700 "$T/home"
BOGUS=$(od -An -tx1 -N20 /dev/urandom | tr -d ' \n')
out=$(/usr/bin/env HOME="$T/home" KEYCHAIN_CERTIFICATES="$BOGUS" /usr/bin/ssh-agent -U -P /usr/lib/ssh-keychain.dylib -a "$T/a.sock" -s)
AP=$(printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9][0-9]*\);.*/\1/p'); AID=$(ps -o lstart= -o comm= -p "$AP")
echo "agent pid=$AP comm=${AID##* }"
run_pty() {  # LABEL ENVSETTING ARGS... : run ssh-add in a pty with stdin /dev/null, 15 s limit
  local label=$1 envs=$2; shift 2
  local start end rc
  start=$(date +%s)
  /opt/homebrew/bin/timeout 15 /usr/bin/script -q "$T/$label.typescript" /usr/bin/env HOME="$T/home" SSH_AUTH_SOCK="$T/a.sock" \
    KEYCHAIN_CERTIFICATES="$BOGUS" $envs /usr/bin/ssh-add "$@" </dev/null >/dev/null 2>&1
  rc=$?; end=$(date +%s)
  echo "$label: rc=$rc elapsed=$((end - start))s $( [ $rc -eq 124 ] && echo '(killed by 15 s timeout: blocked)')"
  tr -d '\r' < "$T/$label.typescript" | sed 's/^/    tty> /' | head -4
}
run_pty never-sk     "SSH_ASKPASS_REQUIRE=never" -K -S /usr/lib/ssh-keychain.dylib
run_pty never-p11    "SSH_ASKPASS_REQUIRE=never" -s /usr/lib/ssh-keychain.dylib
run_pty force-sk     "SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/usr/bin/true" -K -S /usr/lib/ssh-keychain.dylib
run_pty force-p11    "SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/usr/bin/true" -s /usr/lib/ssh-keychain.dylib
cur=$(ps -o lstart= -o comm= -p "$AP")
if [ "$cur" = "$AID" ]; then kill -TERM "$AP"; sleep 0.5; fi
echo "agent after kill: $(ps -o comm= -p "$AP" 2>/dev/null || echo gone)"
ps -A -o pid=,comm= | awk '$2 ~ /ssh-add$/' | wc -l | sed 's/^ */ssh-add processes left: /'
cp "$T"/*.typescript "$OUT"/ 2>/dev/null
rm -rf "$T"; echo "temp removed: $([ -e "$T" ] && echo no || echo yes)"
