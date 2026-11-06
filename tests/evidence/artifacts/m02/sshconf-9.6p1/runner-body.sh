tar -xzf "$S/bundle.tgz" -C "$S" || exit 1
rm -f "$S/bundle.tgz"
mkdir -p "$S/home/.ssh" "$S/other/.ssh"
: > "$S/known_hosts"
: > "$S/empty_known_hosts"
# Replace the placeholders (no sed -i: GNU and BSD differ).
find "$S/corpus" "$S/cases" -type f | while read -r f; do
  sed -e "s|@CORPUS_DIR@|$S/corpus|g" -e "s|@SCRATCH@|$S|g" "$f" > "$f.hm-tmp" && mv "$f.hm-tmp" "$f"
done
printf 'Host tok-x\n  Port 2963\n' > "$S/home/inc-d.conf"

KEYS='^(hostname|port|user|identityfile|identitiesonly|identityagent|certificatefile|proxyjump|proxycommand|remotecommand|setenv|revokedhostkeys|localforward|remoteforward|controlpath|sessiontype|userknownhostsfile|knownhostscommand|kbdinteractiveauthentication|hostbasedacceptedalgorithms|pubkeyacceptedalgorithms|tag) '

# run <case-name> <file relative to scratch> <ssh arguments after the isolation options>
# Extra environment for the client comes from $X (one NAME=value word, or empty).
run() {
  name=$1; file=$2; shift 2
  env -i PATH=/usr/bin:/bin HOME="$S/home" $X ssh -G -F "$S/$file" \
    -o "UserKnownHostsFile=$S/known_hosts" -o "GlobalKnownHostsFile=$S/empty_known_hosts" \
    -o BatchMode=yes "$@" > "$S/out" 2> "$S/err"
  code=$?
  echo "### case=$name file=$file args=$* env=${X:-none} exit=$code"
  grep -E "$KEYS" "$S/out" | awk 'length($0) > 160 { $0 = substr($0, 1, 60) "...(" length($0) " chars)" } { print }'
  grep -v "^Pseudo-terminal will not be allocated" "$S/err" | sed 's/^/stderr: /'
}

{
  echo "### ssh-V: $(env -i PATH=/usr/bin:/bin ssh -V 2>&1)"
  X=
  for a in alpha x.corpus.example bad.corpus.example beta gamma1 gamma-excluded delta; do run corpus_basic corpus/basic.conf "$a"; done
  run corpus_basic corpus/basic.conf -l corpus-explicit anything.example
  for a in ident-one ident-spaced ident-percent ident-pipe ident-pipe-quoted ident-agent-none ident-files-none; do run corpus_identity corpus/identity.conf "$a"; done
  for a in nested-after nested-level1 nested-glob nested-deep; do run corpus_nested corpus/nested.conf "$a"; done
  for a in state-alpha state-other; do run corpus_include_state corpus/include-state.conf "$a"; done
  run corpus_unsupported corpus/unsupported.conf unsupported
  run corpus_retired corpus/retired.conf retired
  for a in lex-hash lex-quote lex-equals lex-escape lex-unknown-escape lex-command lex-command-bare lex-command-equals lex-command-escapes; do run corpus_lexer corpus/lexer.conf "$a"; done
  run corpus_bom corpus/bom.conf bom-check
  run corpus_crlf corpus/crlf.conf crlf-check
  X=HM_CORPUS_VAR=hmexpanded
  run s01_env cases/env.conf env-x
  run env_user cases/env_user.conf env-x
  run env_setenv cases/env_setenv.conf env-x
  run env_include cases/env_include.conf env-x
  run env_include_top cases/env_include_top.conf env-x
  X=
  run s01_env_unset cases/env.conf env-x
  run env_user_unset cases/env_user.conf env-x
  run env_setenv_unset cases/env_setenv.conf env-x
  run env_include_unset cases/env_include.conf env-x
  run tok_user cases/tok_user.conf tok-x
  run tok_user_pct cases/tok_user_pct.conf tok-x
  run tok_match_user cases/tok_match_user.conf tok-x
  run tok_setenv cases/tok_setenv.conf tok-x
  run tok_include cases/tok_include.conf tok-x
  run tok_include_d cases/tok_include_d.conf tok-x
  run host_pattern_case_first_pass cases/case.conf MixedCase
  run host_pattern_case_first_pass_lower cases/case.conf mixedcase
  run host_pattern_case_final_pass cases/final_case.conf MixedCase
  run match_final_and_canonical cases/final.conf fin-a
  run hostname_not_set_again_in_final_pass cases/final.conf fin-b
  run parse_only_include_under_false_section cases/parseonly.conf target
  run parse_only_include_is_still_checked cases/parsebad.conf target
  run id_first_and_final cases/id_first_and_final.conf idf
  run id_final_only cases/id_final_only.conf idf
  run id_final_dup cases/id_final_dup.conf idf
  run id_none cases/id_none.conf idn
  run id_none_then cases/id_none_then.conf idn
  run final_only_port cases/final_only_port.conf idf
  run sessiontype_none_shell cases/sessiontype_none.conf box
  run sessiontype_subsystem_shell cases/sessiontype_subsystem.conf box
  run sessiontype_none_dash_s cases/sessiontype_none.conf -s box sftp
  run sessiontype_subsystem_dash_s cases/sessiontype_subsystem.conf -s box sftp
  run sessiontype_negated cases/sessiontype_negated.conf box
  run sessiontype_second cases/sessiontype_second.conf box
  run sessiontype_under_false cases/sessiontype_under_false.conf box
  for m in all canonical final host originalhost user localuser localnetwork tagged command version sessiontype; do
    run "match_$m" "cases/match_$m.conf" box
  done
  run kw_sessiontype_line cases/kw_sessiontype_line.conf box
  run kw_tag cases/kw_tag.conf box
  for f in "$S"/kw/*.conf; do
    k=$(basename "$f" .conf)
    run "kw_$k" "kw/$k.conf" hm-kw-other
  done
} > "$S/raw.txt" 2>&1

# Redact before anything leaves this host: the scratch path, the home, the account
# name and the host name (whole words only), then count what is left.
ACCT=$(id -un)
SHORT=$(hostname -s 2>/dev/null || hostname)
LONG=$(hostname -f 2>/dev/null || hostname)
awk -v S="$S" -v H="$HOME" -v U="$ACCT" -v N="$SHORT" -v F="$LONG" '
function rep(s, a, b,   i, out) {
  if (a == "") return s
  out = ""
  while ((i = index(s, a)) > 0) { out = out substr(s, 1, i - 1) b; s = substr(s, i + length(a)) }
  return out s
}
function isw(c) { return c ~ /[A-Za-z0-9_]/ }
function repw(s, a, b,   i, out, pre, post) {
  if (a == "") return s
  out = ""
  while ((i = index(s, a)) > 0) {
    pre = (i > 1) ? substr(s, i - 1, 1) : ""
    post = substr(s, i + length(a), 1)
    if ((pre == "" || !isw(pre)) && (post == "" || !isw(post))) {
      out = out substr(s, 1, i - 1) b
    } else {
      out = out substr(s, 1, i - 1 + length(a))
    }
    s = substr(s, i + length(a))
  }
  return out s
}
{
  l = rep($0, S, "<scratch>")
  l = rep(l, H, "<home>")
  l = repw(l, F, "<host>")
  l = repw(l, N, "<host>")
  l = repw(l, U, "<local>")
  print l
}' "$S/raw.txt" > "$S/redacted.txt"
left=$(grep -c -w -F -e "$ACCT" -e "$SHORT" -e "$LONG" -e "$HOME" "$S/redacted.txt")
cat "$S/redacted.txt"
echo "### leak-check: whole-word account, host and home matches left after redaction: $left"
