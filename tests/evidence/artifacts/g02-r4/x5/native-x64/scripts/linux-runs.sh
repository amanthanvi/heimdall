#!/bin/sh
# Native linux-x64 runs of the X5 probe. Usage: linux-runs.sh <variant-dir-name> <out-dir>
# Runs: 3x selftest (timed), 3x selftest --hold-ms 2500 with exact-PID socket inspection,
#       3x x5-gosup (timed), 3x x5-gosup -hold-ms 3000 with inspection of its 3 exact PIDs,
#       3x supervisor-death (SIGKILL of the supervisor's exact PID, poll both helper PIDs).
# Children run with env -i PATH=/usr/bin:/bin. Prints one result line per run.
set -u
D=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
V=$1; O=$2; mkdir -p "$O"
H=$D/bin/$V/x5-iroh; G=$D/bin/x5-gosup
SC=$D/scripts; export PATH=$SC:/usr/bin:/bin
now_ms() { date +%s%3N; }
exe_of() { basename "$(readlink /proc/$1/exe 2>/dev/null)"; }
ppid_of() { awk '/^PPid:/{print $2}' /proc/$1/status 2>/dev/null; }
echo "## variant=$V host_uname=$(uname -sm) kernel=$(uname -r) shell_pid=$$"

for i in 1 2 3; do
  t0=$(now_ms); env -i PATH=/usr/bin:/bin "$H" selftest > "$O/st-$i.out" 2> "$O/st-$i.err"; rc=$?; t1=$(now_ms)
  echo "selftest run=$i exit=$rc wall_ms=$((t1-t0)) stdout=$(cat "$O/st-$i.out")"
done

for i in 1 2 3; do
  t0=$(now_ms)
  env -i PATH=/usr/bin:/bin "$H" selftest --hold-ms 2500 > "$O/sth-$i.out" 2> "$O/sth-$i.err" &
  P=$!; sleep 1.2
  echo "selftest-hold run=$i launched_pid=$P identity_ok=$([ "$(exe_of $P)" = x5-iroh ] && [ "$(ppid_of $P)" = $$ ] && echo yes || echo NO)"
  inspect-pid.sh "$P" | sed 's/^/  /'
  wait "$P"; rc=$?; t1=$(now_ms)
  echo "selftest-hold run=$i exit=$rc wall_ms=$((t1-t0)) stdout=$(cat "$O/sth-$i.out")"
done

for i in 1 2 3; do
  t0=$(now_ms); env -i PATH=/usr/bin:/bin "$G" -helper "$H" > "$O/g-$i.out" 2> "$O/g-$i.err"; rc=$?; t1=$(now_ms)
  echo "gosup run=$i exit=$rc wall_ms=$((t1-t0)) stdout=$(cat "$O/g-$i.out")"
done

for i in 1 2 3; do
  t0=$(now_ms)
  env -i PATH=/usr/bin:/bin "$G" -helper "$H" -hold-ms 3000 > "$O/gh-$i.out" 2> "$O/gh-$i.err" &
  P=$!; sleep 1.5
  PIDS=$(sed -n 's/.*pid \([0-9]*\), helper A pid \([0-9]*\), helper B pid \([0-9]*\).*/\1 \2 \3/p' "$O/gh-$i.err")
  echo "gosup-hold run=$i launched_pid=$P reported=[$PIDS]"
  set -- $PIDS
  ok=no; [ "${1:-}" = "$P" ] && [ "$(exe_of $P)" = x5-gosup ] && [ "$(ppid_of $P)" = $$ ] && \
    [ "$(exe_of ${2:-0})" = x5-iroh ] && [ "$(ppid_of ${2:-0})" = $P ] && \
    [ "$(exe_of ${3:-0})" = x5-iroh ] && [ "$(ppid_of ${3:-0})" = $P ] && ok=yes
  echo "  identity_ok=$ok"
  for p in $PIDS; do inspect-pid.sh "$p" | sed 's/^/  /'; done
  wait "$P"; rc=$?; t1=$(now_ms)
  echo "gosup-hold run=$i exit=$rc wall_ms=$((t1-t0)) stdout=$(cat "$O/gh-$i.out")"
done

for i in 1 2 3; do
  env -i PATH=/usr/bin:/bin "$G" -helper "$H" -hold-ms 8000 > "$O/k-$i.out" 2> "$O/k-$i.err" &
  P=$!; sleep 2
  PIDS=$(sed -n 's/.*pid \([0-9]*\), helper A pid \([0-9]*\), helper B pid \([0-9]*\).*/\1 \2 \3/p' "$O/k-$i.err")
  set -- $PIDS; A=${2:-0}; B=${3:-0}
  ok=no; [ "${1:-}" = "$P" ] && [ "$(exe_of $P)" = x5-gosup ] && [ "$(ppid_of $P)" = $$ ] && \
    [ "$(exe_of $A)" = x5-iroh ] && [ "$(ppid_of $A)" = $P ] && \
    [ "$(exe_of $B)" = x5-iroh ] && [ "$(ppid_of $B)" = $P ] && ok=yes
  echo "sup-death run=$i supervisor_pid=$P helper_pids=$A,$B identity_ok=$ok"
  if [ $ok != yes ]; then echo "  identity check failed; not killing"; wait "$P"; continue; fi
  tk=$(now_ms); kill -KILL "$P"; wait "$P" 2>/dev/null; wrc=$?
  echo "  supervisor_wait_status=$wrc"
  ga=-; gb=-
  while [ $(( $(now_ms) - tk )) -lt 10000 ]; do
    if [ "$ga" = - ] && { [ ! -d /proc/$A ] || [ "$(exe_of $A)" != x5-iroh ]; }; then ga=$(( $(now_ms) - tk )); fi
    if [ "$gb" = - ] && { [ ! -d /proc/$B ] || [ "$(exe_of $B)" != x5-iroh ]; }; then gb=$(( $(now_ms) - tk )); fi
    [ "$ga" != - ] && [ "$gb" != - ] && break
    sleep 0.05
  done
  echo "  helper_A_gone_after_ms=$ga helper_B_gone_after_ms=$gb (- = still alive after 10 s)"
  for h in $A $B; do [ -d /proc/$h ] && [ "$(exe_of $h)" = x5-iroh ] && echo "  WARNING helper $h still alive"; done
  echo "  stderr (helpers share the supervisor's stderr file):"; sed -E 's/pid [0-9]+/pid <pid>/g; s/^/    /' "$O/k-$i.err"
done
