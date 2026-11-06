#!/bin/bash
# Build the inert ssh -G diagnostic bundle (W5c-sshconf). Every configuration is inert:
# no Match exec, no command keyword that runs locally under -G, every path under
# /nonexistent/hm-corpus or the scratch directory. @SCRATCH@ and @CORPUS_DIR@ are
# replaced on the target with the scratch directory's absolute path.
set -eu
REPO=$1
OUT=$2
rm -rf "$OUT"
mkdir -p "$OUT/cases" "$OUT/kw"
cp -R "$REPO/tests/fixtures/sshconf/corpus" "$OUT/corpus"
rm -f "$OUT/corpus/README.md"
C="$OUT/cases"
w() { printf '%b' "$2" > "$C/$1"; }
w env.conf 'Host env-x\n  User u${HM_CORPUS_VAR}\n  SetEnv HMSET=${HM_CORPUS_VAR}\n  RevokedHostKeys /nonexistent/hm-corpus/${HM_CORPUS_VAR}/revoked\n  LocalForward /nonexistent/hm-corpus/${HM_CORPUS_VAR}/l.sock /nonexistent/hm-corpus/${HM_CORPUS_VAR}/r.sock\n  RemoteForward /nonexistent/hm-corpus/${HM_CORPUS_VAR}/rf.sock /nonexistent/hm-corpus/${HM_CORPUS_VAR}/rl.sock\n  CertificateFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/cert\n  ControlPath /nonexistent/hm-corpus/${HM_CORPUS_VAR}/cp\n  IdentityAgent /nonexistent/hm-corpus/${HM_CORPUS_VAR}/agent\n  IdentityFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/id\n  KnownHostsCommand /bin/echo ${HM_CORPUS_VAR}\n  UserKnownHostsFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/kh\n  Include @SCRATCH@/cases/${HM_CORPUS_VAR}.conf\n'
w hmexpanded.conf 'Host env-x\n  Port 2950\n'
w env_user.conf 'Host env-x\n  User u${HM_CORPUS_VAR}\n'
w env_setenv.conf 'Host env-x\n  SetEnv HMSET=${HM_CORPUS_VAR}\n'
w env_include.conf 'Host env-x\n  Include @SCRATCH@/cases/${HM_CORPUS_VAR}.conf\n'
w env_include_top.conf 'Include @SCRATCH@/cases/${HM_CORPUS_VAR}.conf\n'
w tok_user.conf 'Host tok-x\n  User u%h\n'
w tok_user_pct.conf 'Host tok-x\n  User u%%h\n'
w tok_setenv.conf 'Host tok-x\n  SetEnv HMSET=%h\n'
w tok_include.conf 'Include @SCRATCH@/cases/inc-%h.conf\n'
w inc-tok-x.conf 'Host tok-x\n  Port 2962\n'
w tok_include_d.conf 'Include %d/inc-d.conf\n'
w tok_match_user.conf 'Host tok-x\n  User u%h\nMatch user utok-x\n  Port 2964\n'
w case.conf 'Host MixedCase\n  Port 2901\nHost mixedcase\n  Port 2911\n'
w final_case.conf 'Match final\n  Port 2912\nHost mixedcase\n  User final-lower-host\n'
w final.conf 'Host fin-a\n  HostName first.example\nMatch final\n  HostName second.example\n  Port 2902\nMatch canonical\n  User canon-user\nHost fin-b\n  Port 2903\n'
w inc.conf 'Host target\n  Port 2905\n'
w parseonly.conf 'Host nomatch\n  Include @SCRATCH@/cases/inc.conf\nHost target\n  User target-user\n'
w bad.conf 'Host target\n  NoSuchKeywordHm yes\n'
w parsebad.conf 'Host nomatch\n  Include @SCRATCH@/cases/bad.conf\n'
w id_first_and_final.conf 'Host idf\n  IdentityFile /nonexistent/hm-corpus/first\nMatch final\n  IdentityFile /nonexistent/hm-corpus/final\n'
w id_final_only.conf 'Match final\n  IdentityFile /nonexistent/hm-corpus/final_only\n'
w id_final_dup.conf 'Host idf\n  IdentityFile /nonexistent/hm-corpus/same\nMatch final\n  IdentityFile /nonexistent/hm-corpus/same\n'
w id_none.conf 'Host idn\n  IdentityFile none\n'
w id_none_then.conf 'Host idn\n  IdentityFile none\n  IdentityFile /nonexistent/hm-corpus/after_none\n'
w final_only_port.conf 'Match final\n  Port 2913\n'
w sessiontype_none.conf 'SessionType none\nMatch sessiontype shell\n    HostName wrong.example\nMatch sessiontype none\n    Port 2202\n'
w sessiontype_subsystem.conf 'SessionType subsystem\nMatch sessiontype subsystem\n    Port 2203\nMatch sessiontype shell\n    Port 2204\n'
w sessiontype_negated.conf 'Match !sessiontype exec\n    Port 2212\n'
w sessiontype_second.conf 'Match host box sessiontype shell\n    Port 2213\n'
w sessiontype_under_false.conf 'Host nomatch\n    Include @SCRATCH@/cases/sessiontype_inner.conf\n'
w sessiontype_inner.conf 'Match sessiontype shell\n    Port 2214\n'
w match_all.conf 'Match all\n    Port 2301\n'
w match_canonical.conf 'Match canonical\n    Port 2302\n'
w match_final.conf 'Match final\n    Port 2303\n'
w match_host.conf 'Match host box\n    Port 2310\n'
w match_originalhost.conf 'Match originalhost box\n    Port 2311\n'
w match_user.conf 'Match user hm-nobody\n    Port 2312\n'
w match_localuser.conf 'Match localuser hm-nobody\n    Port 2313\n'
w match_localnetwork.conf 'Match localnetwork 192.0.2.0/24\n    Port 2314\n'
w match_tagged.conf 'Match tagged hmtag\n    Port 2315\n'
w match_command.conf 'Match command hmcmd\n    Port 2316\n'
w match_version.conf 'Match version OpenSSH_*\n    Port 2317\n'
w match_sessiontype.conf 'Match sessiontype shell\n    Port 2318\n'
w kw_sessiontype_line.conf 'SessionType none\nHost box\n    Port 2320\n'
w kw_tag.conf 'Tag hmtag\nMatch tagged hmtag\n    Port 2321\n'
# One file per keyword of the pinned table, under a Host that never matches, and one
# per alias and retired spelling: the client's stderr tells whether it knows the name.
while read -r k; do
  [ -n "$k" ] || continue
  printf 'Host hm-kw-nomatch\n    %s hmprobe\n' "$k" > "$OUT/kw/$k.conf"
done < "$OUT/../keywords.txt"
echo "bundle ready: $(find "$OUT" -type f | wc -l | tr -d ' ') files"
