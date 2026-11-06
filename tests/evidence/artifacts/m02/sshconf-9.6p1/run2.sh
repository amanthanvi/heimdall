#!/bin/bash
# W5c-sshconf second ssh -G diagnostic: the new corpus-test cases (inert, scratch only).
set -u
umask 077
BASE=${HM_SCRATCH_BASE:-$HOME}
S=$(mktemp -d "$BASE/hm-m02-XXXXXXXXXX") || exit 1
case "$S" in "$BASE"/hm-m02-*) ;; *) echo "unexpected scratch path"; exit 1 ;; esac
cleanup() { rm -rf -- "$S"; if [ -e "$S" ]; then echo "### scratch-removed=no"; else echo "### scratch-removed=yes"; fi; }
trap cleanup EXIT
mkdir -p "$S/home/.ssh"; : > "$S/known_hosts"; : > "$S/empty_known_hosts"
w() { printf '%b' "$2" | sed -e "s|@SCRATCH@|$S|g" > "$S/$1"; }
w inc-tok-x.conf 'Host tok-x\n  Port 2962\n'
w 'inc-%h.conf' 'Host tok-x\n  Port 2965\n'
w tok_include.conf 'Include @SCRATCH@/inc-%h.conf\n'
w tok_user.conf 'Host tok-x\n  User u%h\n'
for k in RefuseConnection VersionAddendum WarnWeakCrypto; do
  case $k in VersionAddendum) val=none ;; *) val=no ;; esac
  lk=$(printf '%s' "$k" | tr 'A-Z' 'a-z')
  w "kw_$k.conf" "Host hm-corpus-nomatch\n    $k $val\n"
  w "kw_${k}_ignored.conf" "IgnoreUnknown $lk\nHost hm-corpus-nomatch\n    $k $val\n"
  w "kw_${k}_ignored_box.conf" "IgnoreUnknown $lk\nHost box\n    $k $val\n    Port 2330\n"
done
w match_command.conf 'Match command hm-corpus-cmd\n    Port 2317\n'
w match_command_neg.conf 'Match !command hm-cmd\n    Port 2318\n'
w match_sessiontype.conf 'Match sessiontype shell\n    Port 2317\n'
w match_version.conf 'Match version OpenSSH_*\n    Port 2317\n'
run() {
  name=$1; file=$2; shift 2
  env -i PATH=/usr/bin:/bin HOME="$S/home" ssh -G -F "$S/$file" \
    -o "UserKnownHostsFile=$S/known_hosts" -o "GlobalKnownHostsFile=$S/empty_known_hosts" \
    -o BatchMode=yes "$@" > "$S/out" 2> "$S/err"
  code=$?
  echo "### case=$name file=$file args=$* env=none exit=$code"
  grep -E '^(port|user|refuseconnection|versionaddendum|warnweakcrypto) ' "$S/out"
  grep -v "^Pseudo-terminal will not be allocated" "$S/err" | sed 's/^/stderr: /'
}
{
  echo "### ssh-V: $(env -i PATH=/usr/bin:/bin ssh -V 2>&1)"
  run include_tokens tok_include.conf tok-x
  run tok_user tok_user.conf tok-x
  for k in RefuseConnection VersionAddendum WarnWeakCrypto; do
    run "kw_$k" "kw_$k.conf" box
    run "kw_${k}_ignored" "kw_${k}_ignored.conf" box
    run "kw_${k}_ignored_box" "kw_${k}_ignored_box.conf" box
  done
  for m in command command_neg sessiontype version; do run "match_$m" "match_$m.conf" box; done
} > "$S/raw.txt" 2>&1
ACCT=$(id -un); SHORT=$(hostname -s 2>/dev/null || hostname); LONG=$(hostname -f 2>/dev/null || hostname)
awk -v S="$S" -v H="$HOME" -v U="$ACCT" -v N="$SHORT" -v F="$LONG" '
function rep(s, a, b,   i, out) { if (a == "") return s; out = ""; while ((i = index(s, a)) > 0) { out = out substr(s, 1, i - 1) b; s = substr(s, i + length(a)) } return out s }
function isw(c) { return c ~ /[A-Za-z0-9_]/ }
function repw(s, a, b,   i, out, pre, post) { if (a == "") return s; out = ""
  while ((i = index(s, a)) > 0) { pre = (i > 1) ? substr(s, i - 1, 1) : ""; post = substr(s, i + length(a), 1)
    if ((pre == "" || !isw(pre)) && (post == "" || !isw(post))) out = out substr(s, 1, i - 1) b; else out = out substr(s, 1, i - 1 + length(a))
    s = substr(s, i + length(a)) } return out s }
{ l = rep($0, S, "<scratch>"); l = rep(l, H, "<home>"); l = repw(l, F, "<host>"); l = repw(l, N, "<host>"); l = repw(l, U, "<local>"); print l }' "$S/raw.txt" > "$S/redacted.txt"
left=$(grep -c -w -F -e "$ACCT" -e "$SHORT" -e "$LONG" -e "$HOME" "$S/redacted.txt")
cat "$S/redacted.txt"
echo "### leak-check: whole-word account, host and home matches left after redaction: $left"
