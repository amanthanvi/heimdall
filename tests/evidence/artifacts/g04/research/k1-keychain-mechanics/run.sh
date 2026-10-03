#!/bin/bash
# G04 research check K1 (macOS, screen unlocked, no lock exercised).
# Observes the mechanics the lock probe relies on, with disposable material only:
#   - `security -i` accepts create-keychain / add-generic-password on stdin (secrets not in argv)
#     and does not echo them;
#   - whether a new custom keychain joins the user search list or changes the default keychain;
#   - default settings of a new custom keychain, and the effect of set-keychain-settings;
#   - read-back of the item; delete-keychain cleanup;
#   - which IORegistry lock-state keys exist while the screen is unlocked (booleans only).
# Never prints the owner's search list, user name, or any secret; prints digests/counts only.
set -u
S=/usr/bin/security
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
T=$(mktemp -d "${TMPDIR:-/tmp}/heimdall-g04-k1.XXXXXXXX"); chmod 700 "$T"
trap 'rm -rf "$T"' EXIT
KC="$T/heimdall-g04-k1.keychain-db"
dig() { shasum -a 256 | cut -c1-16; }
L0=$($S list-keychains -d user | dig); D0=$($S default-keychain -d user | dig)
echo "$(ts) user search list entries=$($S list-keychains -d user | wc -l | tr -d ' ') (contents not printed)"
PW=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
CAN="k1-not-a-canary-$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
printf 'create-keychain -p %s %s\n' "$PW" "$KC" | $S -i > "$T/i1.out" 2>&1; echo "$(ts) create-keychain via security -i exit=$? output_bytes=$(wc -c < "$T/i1.out" | tr -d ' ') output_contains_password=$(grep -c "$PW" "$T/i1.out")"
echo "$(ts) keychain file exists=$([ -e "$KC" ] && echo yes || echo no)"
echo "$(ts) after create: probe keychain in user search list=$($S list-keychains -d user | grep -c "$T") default keychain unchanged=$([ "$($S default-keychain -d user | dig)" = "$D0" ] && echo yes || echo no)"
echo "$(ts) default settings: $($S show-keychain-info "$KC" 2>&1 | sed -n 's/.*keychain-db" *//p')"
$S set-keychain-settings "$KC"; echo "$(ts) set-keychain-settings (no flags) exit=$?"
echo "$(ts) settings now: $($S show-keychain-info "$KC" 2>&1 | sed -n 's/.*keychain-db" *//p')"
printf 'add-generic-password -a hm-g04-k1 -s hm-g04-k1 -w %s %s\n' "$CAN" "$KC" | $S -i > "$T/i2.out" 2>&1; echo "$(ts) add-generic-password via security -i exit=$? output_contains_value=$(grep -c "$CAN" "$T/i2.out")"
out=$($S find-generic-password -a hm-g04-k1 -s hm-g04-k1 -w "$KC" 2>/dev/null); rc=$?
echo "$(ts) find-generic-password exit=$rc value_matches=$([ "$out" = "$CAN" ] && echo yes || echo no)"
$S delete-keychain "$KC"; echo "$(ts) delete-keychain exit=$?"
echo "$(ts) after delete: file exists=$([ -e "$KC" ] && echo yes || echo no) search list unchanged=$([ "$($S list-keychains -d user | dig)" = "$L0" ] && echo yes || echo no) default unchanged=$([ "$($S default-keychain -d user | dig)" = "$D0" ] && echo yes || echo no)"
x=$(/usr/sbin/ioreg -n Root -d1 -a 2>/dev/null)
echo "$(ts) ioreg (screen unlocked): IOConsoleLocked=$(printf '%s\n' "$x" | grep -A1 '<key>IOConsoleLocked</key>' | grep -o -E 'true|false' | head -1) CGSSessionScreenIsLocked_present=$(printf '%s\n' "$x" | grep -c '<key>CGSSessionScreenIsLocked</key>')"
x=""
echo "$(ts) done"
