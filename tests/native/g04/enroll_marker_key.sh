#!/bin/bash
# Enrollment mechanics (G04/A09, R-CR-05/06, spec 7.5) on the account-enrollable fixture:
# add a disposable marker key alongside existing access, verify a FRESH authentication with ONLY
# the new key (fallback and connection reuse disabled), let a concurrent administrator edit land,
# remove only the marker line, and prove unrelated (and concurrent) bytes are identical.
EXP=enroll-marker-key
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

load_fixture; record_env
SEED_SHA=$(cat "$FX_RT/seed/enroll_authorized_keys.sha256")
reg_admin_cfg
start_agent "$T/agent"; A=$AGENT_SOCK
MARK="heimdall-g04-exp-marker-$RUN_ID"
genkey "$T/km" "$MARK"
KFP=$(fp_of "$T/km.pub"); fact marker_key_fp "$KFP"
AFP=$(fp_of "$FX_KEYS/user_enroll.pub"); fact admin_key_fp "$AFP"
agent_add "$A" "$T/km" -t 900
agent_list "$A"; fact agent_contents "$OUT"
cp "$T/km.pub" "$T/line"
write_cfg "$T/cfg" "$A" "$T/km.pub"
CONC="# concurrent admin edit g04 $RUN_ID"

# verify_only_marker LABEL EXPECTED_RC
verify_only_marker() {
  local label=$1 exp=$2 m rc offered offk acc ok
  m=$(mark enroll)
  xrun "$label" "$SSH" -F "$T/cfg" -v g-enroll 'echo marker-fresh-auth'
  rc=$RC
  offered=$(printf '%s\n' "$OUT" | grep -c 'Offering public key')
  offk=$(printf '%s\n' "$OUT" | grep 'Offering public key' | grep -c -F "$KFP")
  sleep 0.3
  acc=$(count_new enroll "$m" "Accepted publickey for enroll" "$KFP")
  accall=$(count_new enroll "$m" "Accepted publickey")
  log_new enroll "$m" "$label"
  if [ "$exp" = 0 ]; then [ "$rc" = 0 ] && [ "$acc" = 1 ] && [ "$accall" = 1 ] && [ "$offered" = 1 ] && [ "$offk" = 1 ]; ok=$?
  else [ "$rc" = 255 ] && [ "$accall" = 0 ] && [ "$offered" = 1 ] && [ "$offk" = 1 ]; ok=$?; fi
  check "ENR-$label" "rc $exp; exactly one key offered (the marker key); $([ "$exp" = 0 ] && echo 'exactly 1 new Accepted line with the marker fingerprint' || echo 'no Accepted line')" \
    "rc=$rc offered_keys=$offered offered_marker=$offk accepted_marker=$acc accepted_any=$accall" $ok
}

xrun "verification config (ssh -G)" "$SSH" -F "$T/cfg" -G g-enroll
G=$OUT
gi=$(printf '%s\n' "$G" | grep '^identityfile ' | oneline); gio=$(printf '%s\n' "$G" | sed -n 's/^identitiesonly //p')
gcm=$(printf '%s\n' "$G" | sed -n 's/^controlmaster //p'); gcp=$(printf '%s\n' "$G" | sed -n 's/^controlpath //p')
gpa=$(printf '%s\n' "$G" | sed -n 's/^preferredauthentications //p'); gpw=$(printf '%s\n' "$G" | sed -n 's/^passwordauthentication //p')
gkb=$(printf '%s\n' "$G" | sed -n 's/^kbdinteractiveauthentication //p'); gag=$(printf '%s\n' "$G" | sed -n 's/^identityagent //p')
[ "$gi" = "identityfile <tmp>/km.pub" ] && [ "$gio" = yes ] && [ "$gcm" = false ] && [ -z "$gcp" ] && [ "$gpa" = publickey ] && [ "$gpw" = no ] && [ "$gkb" = no ] && [ "$gag" = "<tmp>/agent/agent.sock" ]
ok=$?; check ENR-verification-config "only the marker key; identitiesonly yes; no mux; publickey only; no password/kbd fallback; dedicated agent" \
  "$gi identitiesonly=$gio controlmaster=$gcm controlpath=${gcp:-<absent>} preferred=$gpa password=$gpw kbd=$gkb identityagent=$gag" $ok

reg_fetch "$T/pre" preimage; PRE_SHA=$(sha_of "$T/pre")
[ "$RC" = 0 ] && [ "$PRE_SHA" = "$SEED_SHA" ]
ok=$?; check ENR-preimage-is-seed "registry readable via the existing path; equals the fixture seed" "rc=$RC sha256=$PRE_SHA" $ok
[ "$PRE_SHA" = "$SEED_SHA" ] || die_setup "registry is not the seed; run tests/fixtures/ssh/reset.sh"

verify_only_marker marker-before-enrollment 255

reg_add "$PRE_SHA" "$T/line" "add marker key line (CAS on preimage)"
[ "$RC" = 0 ]; ok=$?; check ENR-add-transaction "rc 0" "rc=$RC out=$OUT" $ok
reg_fetch "$T/after_add" after-add
{ cat "$T/pre"; cat "$T/line"; } | cmp -s - "$T/after_add"
ok=$?; check ENR-added-alongside "after-add bytes == preimage + marker line (existing entries untouched)" "cmp_rc=$ok" $ok

verify_only_marker marker-fresh-auth 0

reg_fetch "$T/admin_ok" "existing path still works"
[ "$RC" = 0 ]; ok=$?; check ENR-existing-access-survives "pre-existing working key still authenticates" "rc=$RC" $ok

# a concurrent administrator edit lands while the marker is enrolled (plain append, like a human)
xrun "concurrent admin append" "$SSH" -F "$T/admin.cfg" g-enroll "printf '%s\n' '$CONC' >> ~/.ssh/authorized_keys"
[ "$RC" = 0 ]; ok=$?; check ENR-concurrent-edit-applied "rc 0" "rc=$RC" $ok

reg_remove "$MARK" "remove marker line only"
[ "$RC" = 0 ]; ok=$?; check ENR-remove-transaction "rc 0; exactly one marker line matched" "rc=$RC out=$OUT" $ok
reg_fetch "$T/after_rm" after-remove
{ cat "$T/pre"; printf '%s\n' "$CONC"; } | cmp -s - "$T/after_rm"; c=$?
grep -c -F "$MARK" "$T/after_rm" >/dev/null; still=$?
[ "$c" = 0 ] && [ "$still" = 1 ]
ok=$?; check ENR-unrelated-bytes-identical "after-remove bytes == preimage + concurrent admin line (every unrelated byte and the concurrent edit preserved; marker gone)" \
  "cmp_rc=$c marker_present=$([ "$still" = 0 ] && echo yes || echo no) pre_lines=$(wc -l <"$T/pre" | tr -d ' ') after_lines=$(wc -l <"$T/after_rm" | tr -d ' ')" $ok

verify_only_marker marker-after-removal 255

# restore the seed: remove the concurrent line (exact, unique) the same way
reg_remove "$CONC" "fixture restore: remove concurrent admin line"
reg_fetch "$T/final" final
om=$(reg_owner_mode)
[ "$(sha_of "$T/final")" = "$SEED_SHA" ] && [ "$om" = "enroll:600 0" ]
ok=$?; check ENR-seed-restored "sha256 == seed; owner:mode enroll:600; no hm-g04 temp files" "sha256=$(sha_of "$T/final") owner_mode_tmpcount=[$om]" $ok
finish
