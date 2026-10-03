#!/bin/bash
# G04 research feasibility check F1 (offline, no network, no SSH server).
# Purpose: confirm on the installed OpenSSH that
#   (a) a disposable CA key held ONLY inside a dedicated "issuer" ssh-agent can sign a
#       user certificate via `ssh-keygen -U -s ca.pub` after the CA private file is deleted;
#   (b) a dedicated "worker" agent holding the working key + certificate can produce
#       signatures after the working-key private file is deleted (ssh-add -T);
#   (c) the agent auto-removes an expired certificate (ssh-add default, see ssh-add(1) -N);
#   (d) an `ssh-add -t` lifetime constraint removes a key from the agent.
# Uses only disposable material in a mktemp dir. Never reads or writes ~/.ssh, never uses
# the caller's SSH_AUTH_SOCK, kills only the exact agent PIDs it started.
set -u
SSH_KEYGEN=/usr/bin/ssh-keygen; SSH_AGENT=/usr/bin/ssh-agent; SSH_ADD=/usr/bin/ssh-add
unset SSH_AUTH_SOCK SSH_AGENT_PID
T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-f1.XXXXXXXX") || exit 70
chmod 700 "$T"
ISSUER_PID=""; WORKER_PID=""
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
say() { printf '%s %s\n' "$(ts)" "$*"; }
cleanup() {
  for p in "$ISSUER_PID" "$WORKER_PID"; do
    [ -n "$p" ] || continue
    # kill only if the PID still runs ssh-agent started by this script (socket in $T)
    if [ "$(ps -o comm= -p "$p" 2>/dev/null)" = "$SSH_AGENT" ] || [ "$(ps -o comm= -p "$p" 2>/dev/null)" = "ssh-agent" ]; then
      kill "$p" 2>/dev/null; say "cleanup: sent TERM to agent pid=$p"
    fi
  done
  rm -rf "$T"; say "cleanup: removed temp dir exists_after=$([ -e "$T" ] && echo yes || echo no)"
}
trap cleanup EXIT
start_agent() { # $1 = socket path; prints pid
  local out
  out=$(HOME="$T" "$SSH_AGENT" -U -a "$1" -s) || return 1
  printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p'
}
say "openssh: $(/usr/bin/ssh -V 2>&1)"
"$SSH_KEYGEN" -q -t ed25519 -N '' -C hm-g04-f1-ca -f "$T/ca" || exit 71
"$SSH_KEYGEN" -q -t ed25519 -N '' -C hm-g04-f1-work -f "$T/work" || exit 72
ISSUER_PID=$(start_agent "$T/issuer.sock"); say "issuer agent pid=$ISSUER_PID"
WORKER_PID=$(start_agent "$T/worker.sock"); say "worker agent pid=$WORKER_PID"
SSH_AUTH_SOCK="$T/issuer.sock" "$SSH_ADD" -q "$T/ca"; say "(a) load CA into issuer agent exit=$?"
rm -f "$T/ca"; say "(a) CA private file removed; exists=$([ -e "$T/ca" ] && echo yes || echo no)"
SSH_AUTH_SOCK="$T/issuer.sock" "$SSH_ADD" -l | sed 's/SHA256:[A-Za-z0-9+\/]*/SHA256:<redacted>/'; say "(a) issuer list exit=${PIPESTATUS[0]}"
SSH_AUTH_SOCK="$T/issuer.sock" "$SSH_KEYGEN" -q -U -s "$T/ca.pub" -I hm-g04-f1-cert -n p-host1 -V -1m:+1m "$T/work.pub"
say "(a) sign working-key cert with CA-in-agent exit=$?"
"$SSH_KEYGEN" -L -f "$T/work-cert.pub" | grep -E 'Type:|Key ID:|Valid:|Principals:|p-host1|Critical Options:|Extensions:' | sed 's/^ */  /'
say "(a) cert inspect exit=${PIPESTATUS[0]}"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -q "$T/work"; say "(b) load work key (+cert) into worker agent exit=$?"
rm -f "$T/work"; say "(b) working private file removed; exists=$([ -e "$T/work" ] && echo yes || echo no)"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -l | awk '{print $1, $NF}'; say "(b) worker list exit=${PIPESTATUS[0]}"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -T "$T/work.pub"; say "(b) ssh-add -T sign+verify via worker agent exit=$?"
printf 'nonce-%s\n' "$(date +%s)" > "$T/msg"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_KEYGEN" -Y sign -q -f "$T/work.pub" -n heimdall-g04-f1 "$T/msg"; say "(b) ssh-keygen -Y sign via agent exit=$?"
"$SSH_KEYGEN" -Y check-novalidate -n heimdall-g04-f1 -s "$T/msg.sig" < "$T/msg" >/dev/null 2>&1; say "(b) signature check-novalidate exit=$?"
# (d) lifetime constraint on a second disposable key
"$SSH_KEYGEN" -q -t ed25519 -N '' -C hm-g04-f1-ttl -f "$T/ttl" || exit 73
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -q -t 20 "$T/ttl"; say "(d) add ttl key with -t 20 exit=$?"
rm -f "$T/ttl"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -l | awk '{print $NF}' | sed 's/^/  present: /'
say "waiting 85 s for cert expiry (+1m) and ttl (20 s)"
sleep 85
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -l | awk '{print $NF}' | sed 's/^/  present: /'
say "(c,d) worker list after wait exit=${PIPESTATUS[0]}"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -T "$T/work.pub" >/dev/null 2>&1; say "(c) plain working key still signs after cert removal exit=$?"
SSH_AUTH_SOCK="$T/worker.sock" "$SSH_ADD" -T "$T/ttl.pub" >/dev/null 2>&1; say "(d) ttl key sign after lifetime exit=$?"
say "done"
