#!/bin/sh
# Supervisor-death check: start x5-gosup holding for 8 s, SIGKILL exactly that PID after the
# exchange, then report whether its two helper PIDs (read from its stderr) exited on stdin EOF.
set -u
G=$1; H=$2; O=$3
env -i PATH=/usr/bin:/bin "$G" -helper "$H" -hold-ms 8000 > "$O.out" 2> "$O.err" &
P=$!
sleep 2.5
PIDS=$(sed -n 's/.*pid \([0-9]*\), helper A pid \([0-9]*\), helper B pid \([0-9]*\).*/\2 \3/p' "$O.err")
echo "supervisor_pid=$P helper_pids=$PIDS"
for p in $PIDS; do printf 'before: pid %s alive=%s\n' "$p" "$(kill -0 "$p" 2>/dev/null && echo yes || echo no)"; done
kill -KILL "$P"; wait "$P" 2>/dev/null; echo "supervisor_wait_status=$?"
sleep 1.5
for p in $PIDS; do printf 'after 1.5s: pid %s alive=%s\n' "$p" "$(kill -0 "$p" 2>/dev/null && echo yes || echo no)"; done
