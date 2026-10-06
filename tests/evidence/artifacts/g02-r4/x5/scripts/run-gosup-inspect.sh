#!/bin/sh
# Run x5-gosup (Go supervisor) with two x5-iroh helpers, inspect the exact PIDs it reports
# with lsof while it holds, then wait for its real exit code.
# Usage: run-gosup-inspect.sh <gosup> <helper> <out-prefix>
# Prints only PID/PPID/command-name and socket fields (no command lines, no env).
set -u
G=$1; H=$2; O=$3
env -i PATH=/usr/bin:/bin "$G" -helper "$H" -hold-ms 4000 > "$O.out" 2> "$O.err" &
P=$!
sleep 2.5
PIDS=$(sed -n 's/.*pid \([0-9]*\), helper A pid \([0-9]*\), helper B pid \([0-9]*\).*/\1 \2 \3/p' "$O.err")
{
  echo "launched_pid=$P reported_pids=$PIDS"
  for p in $PIDS; do
    echo "== pid $p: $(ps -o pid=,ppid=,comm= -p "$p" | awk '{n=split($3,a,"/"); print "pid="$1" ppid="$2" exe="a[n]}')"
    echo "-- internet sockets (lsof -i):"
    lsof -nP -a -p "$p" -i | awk 'NR>1{print "  "$5,$8,$9,$10}'
    echo "-- non-regular fds by TYPE:"
    lsof -nP -p "$p" | awk 'NR>1 && $5!="REG" && $5!="DIR" && $5!="CHR" {print "  "$5}' | sort | uniq -c
  done
} > "$O.lsof" 2>&1
wait "$P"; rc=$?
echo "gosup_exit=$rc" >> "$O.lsof"
sed -i.bak -E 's/pid [0-9]+/pid <pid>/g' "$O.err" && rm -f "$O.err.bak"
cat "$O.lsof"; cat "$O.out"
exit $rc
