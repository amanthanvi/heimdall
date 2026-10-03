#!/bin/bash
# E7 race (preliminary G09, A23): client connect vs "ssh -O stop" with randomized delays.
# Design: docs/research/g04-managed-credentials.md section 8.1 row E7 ("Race").
# Each iteration: a fresh master (ControlPersist=PERSIST, -N -f); then concurrently, after random
# delays (client 0-60 ms, stop 0-40 ms by default; the stop call itself takes about 10 ms, so the
# wider client range puts a useful share of clients after the stop returned), (1) a client using the master's ControlPath with PubkeyAuthentication=no (so a
# fallback fresh connection can never authenticate: rc 0 means "admitted through the master") and
# (2) ssh -O stop. Host timestamps (ms) are taken immediately before each ssh starts and after it
# exits. Classification of admitted clients (rc 0):
#   started_after_stop_returned  client started after -O stop had already received the master's
#                                reply (MUX_S_OK) and exited -> a violation of "stop refuses
#                                future requests"
#   started_during_stop          overlap; cannot be ordered against MUX_S_OK from the host side
#   started_before_stop          admitted before stop was requested
# Clients that were not admitted (rc != 0) get the same timing suffix with a not_admitted_ prefix,
# so the number of post-stop clients actually exercised is visible.
# The master's own exit after stop is also recorded.
# LIMIT (M00-review-g04): classification is by client PROCESS start time. A client whose control
# connection the master accepted before the listener closed is a pre-accepted connection and can be
# admitted after MUX_S_OK (shown directly by e7_mux_preconnected.py); "started_during_stop"
# admissions are consistent with that. This race cannot show that -O stop stops admissions.
EXP=e7-mux-stop-race
# shellcheck disable=SC1091
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
N=${G04_RACE_N:-50}
PERSIST=${G04_RACE_PERSIST:-3}
CMAX=${G04_RACE_CLIENT_MAX_MS:-60}   # client start delay drawn from 0..CMAX ms
SMAX=${G04_RACE_STOP_MAX_MS:-40}     # -O stop start delay drawn from 0..SMAX ms

load_fixture; record_env
start_agent "$T/agent"; A=$AGENT_SOCK
genkey "$T/kr" "g04-race-k-$RUN_ID"
ID="g04-race-$RUN_ID"; NOW=$(date -u +%s)
sign_file "$FX_CA" "$T/kr.pub" "$ID" p-host1 "$(vhex $((NOW-60))):$(vhex $((NOW+1800)))" "$T/cr.pub"
agent_add "$A" "$T/kr" -t 1800
write_cfg "$T/cfg" "$A" "$T/kr.pub" "CertificateFile \"$T/cr.pub\""
fact iterations "$N"; fact control_persist_s "$PERSIST"; fact delay_ranges_ms "client 0-$CMAX, stop 0-$SMAX (uniform, \$RANDOM)"

m0=$(mark ca1)
printf 'iter\tdelay_client_ms\tdelay_stop_ms\tclient_t0\tclient_t1\tclient_rc\tstop_t0\tstop_t1\tstop_rc\tclass\tclient_err\n' >"$T/race.tsv"
started=0; mpids=""
i=1
while [ $i -le "$N" ]; do
  cp="$T/r$i"
  start_master "$T/cfg" "$cp" "$PERSIST" g-ca1
  if [ -z "$MASTER_PID" ]; then printf '%s\tmaster_failed\n' "$i" >>"$T/race.tsv"; i=$((i+1)); continue; fi
  started=$((started+1)); mpids="$mpids $MASTER_PID"
  dc=$((RANDOM % (CMAX + 1))); ds=$((RANDOM % (SMAX + 1)))
  ( sleep "$(printf '0.%03d' "$dc")"; a=$(hr)
    "$SSH" -F "$T/cfg" -o ControlMaster=no -o ControlPath="$cp" -o PubkeyAuthentication=no g-ca1 true </dev/null >/dev/null 2>"$T/rc$i.err"; r=$?
    b=$(hr); printf '%s %s %s\n' "$a" "$b" "$r" >"$T/rc$i" ) &
  pc=$!
  ( sleep "$(printf '0.%03d' "$ds")"; a=$(hr)
    "$SSH" -F "$T/cfg" -S "$cp" -O stop g-ca1 </dev/null >/dev/null 2>"$T/rs$i.err"; r=$?
    b=$(hr); printf '%s %s %s\n' "$a" "$b" "$r" >"$T/rs$i" ) &
  ps_=$!
  wait "$pc" "$ps_" 2>/dev/null
  read -r c0 c1 crc <"$T/rc$i"; read -r s0 s1 src <"$T/rs$i"
  cls=$("$PERL" -e 'my($c0,$crc,$s0,$s1)=@ARGV; my $w=($c0>$s1)?"started_after_stop_returned":(($c0>=$s0)?"started_during_stop":"started_before_stop");
    if($crc!=0){print "not_admitted_$w"} elsif($w eq "started_after_stop_returned"){print "ADMITTED_$w"} else {print "admitted_$w"}' -- "$c0" "$crc" "$s0" "$s1")
  err=$(red <"$T/rc$i.err" | oneline | cut -c1-160)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$dc" "$ds" "$c0" "$c1" "$crc" "$s0" "$s1" "$src" "$cls" "$err" >>"$T/race.tsv"
  i=$((i+1))
done
red <"$T/race.tsv" >"$OUT_DIR/$EXP.race.tsv"
{ echo "    race table:"; red <"$T/race.tsv" | sed 's/^/    /'; } >>"$LOG"

cnt() { awk -F'\t' -v c="$1" 'NR>1 && $10==c {n++} END{print n+0}' "$T/race.tsv"; }
viol=$(cnt ADMITTED_started_after_stop_returned); dur=$(cnt admitted_started_during_stop)
bef=$(cnt admitted_started_before_stop)
nada=$(cnt not_admitted_started_after_stop_returned); nadd=$(cnt not_admitted_started_during_stop); nadb=$(cnt not_admitted_started_before_stop)
nad=$((nada + nadd + nadb))
stopbad=$(awk -F'\t' 'NR>1 && $9!="" && $9!=0 {n++} END{print n+0}' "$T/race.tsv")
nadden=$(awk -F'\t' 'NR>1 && $10 ~ /^not_admitted/ && $11 ~ /Permission denied/ {n++} END{print n+0}' "$T/race.tsv")
nadother=$(awk -F'\t' 'NR>1 && $10 ~ /^not_admitted/ && $11 !~ /Permission denied/ {print $11}' "$T/race.tsv" | sort | uniq -c | oneline)
fact race_counts "masters_started=$started admitted_after_stop_returned=$viol admitted_started_during_stop=$dur admitted_started_before_stop=$bef not_admitted=$nad (started_after_stop_returned=$nada started_during_stop=$nadd started_before_stop=$nadb; fresh-connection publickey denial=$nadden; other=[${nadother:-none}]) stop_rc_nonzero=$stopbad"

# masters after stop (ControlPersist=$PERSIST s): did they exit on their own?
sleep $((PERSIST + 5))
alive=0; ex=0
j=0; while [ $j -lt ${#MS_PID[@]} ]; do
  if alive_ssh "${MS_PID[$j]}" "${MS_IDENT[$j]}"; then alive=$((alive+1)); else ex=$((ex+1)); fi
  j=$((j+1))
done
fact masters_after_stop "exited_on_their_own=$ex still_running_after_${PERSIST}+5s=$alive (any still running are terminated by exact PID in cleanup)"
sleep 0.3
macc=$(count_new ca1 "$m0" "Accepted publickey" "ID $ID "); mall=$(count_new ca1 "$m0" "Accepted publickey")
fact server_accepted "with_race_id=$macc any=$mall (expected: one per master; clients cannot authenticate)"

[ "$started" = "$N" ] && [ "$stopbad" = 0 ] && [ "$macc" = "$started" ] && [ "$mall" = "$started" ]; ok=$?
check E7R-harness "all masters started; every -O stop rc 0; server Accepted lines == masters (no client authenticated itself)" "masters=$started/$N stop_rc_nonzero=$stopbad accepted_with_id=$macc accepted_any=$mall" $ok
[ $((viol + nada)) -ge 5 ]; ok=$?
check E7R-post-stop-clients-exercised "at least 5 clients started after the -O stop call returned (otherwise the race says nothing about post-stop admission)" "clients_started_after_stop_returned=$((viol + nada)) of $started" $ok
[ "$viol" = 0 ]; ok=$?
obs E7R-no-admission-after-stop-returned "no client that started after -O stop returned (MUX_S_OK received) was admitted through the master" "violations=$viol of $((viol + nada)) clients that started after stop returned (not admitted: $nada); started during stop: admitted=$dur not_admitted=$nadd; started before stop: admitted=$bef not_admitted=$nadb; masters=$started" $ok
finish
