#!/bin/bash
# Review3 misc process/signal probes without a terminal (darwin and Linux).
# usage: misc_probe.sh <heimdall-proto> <workdir>
HP=$1; W=$2; rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1
unset SSH_AUTH_SOCK
set -m  # background jobs get their own group and no inherited SIGINT/SIGQUIT ignore
pid_of_hp() { # wait for the pid file written by the child: "<child pid> <parent pid>"
  for _ in $(seq 1 100); do [ -s "$1" ] && break; sleep 0.02; done; cat "$1" 2>/dev/null
}
cat > counter.sh <<'EOF'
#!/bin/sh
# counts the five forwarded signals, writes "$$ $PPID" to $1, runs ~2 s, prints counts, exits 3
for s in INT TERM HUP QUIT WINCH; do eval "c_$s=0"; trap "c_$s=\$((c_$s+1))" $s; done
echo "$$ $PPID" > "$1"
i=0; while [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done
echo "INT=$c_INT TERM=$c_TERM HUP=$c_HUP QUIT=$c_QUIT WINCH=$c_WINCH"
exit 3
EOF
chmod +x counter.sh

echo "== 1 nohup: SIGHUP to heimdall-proto pid must not reach/kill the child (K6a inherited ignore)"
nohup "$HP" run -- ./counter.sh p1 > o1 2>e1 &
w=$!; set -- $(pid_of_hp p1); kill -HUP "$2"; wait $w; echo "exit=$? out=$(cat o1)"

echo "== 2 sh -c wrapper, explicit signals to the heimdall-proto pid (shared group, no tty)"
for s in INT TERM HUP QUIT WINCH; do
  rm -f p2; sh -c "\"$HP\" run -- ./counter.sh p2 > o2; echo wrapper_rc=\$? >> o2" &
  w=$!; set -- $(pid_of_hp p2); kill -$s "$2"; wait $w; echo "$s: $(tr '\n' ' ' < o2)"
done

echo "== 3 killpg of the shared group (K6b: duplicate allowed, recorded)"
rm -f p3; "$HP" run -- ./counter.sh p3 > o3 & w=$!
set -- $(pid_of_hp p3); pg=$(ps -o pgid= -p "$2" | tr -d ' '); kill -INT -- -"$pg"; wait $w; echo "rc=$? $(cat o3)"

echo "== 4 pipeline: heimdall-proto | cat and cat | heimdall-proto, explicit TERM to the pid"
rm -f p4; "$HP" run -- ./counter.sh p4 | cat > o4 & w=$!; set -- $(pid_of_hp p4); kill -TERM "$2"; wait $w; echo "first: $(cat o4)"
rm -f p5; echo | "$HP" run -- ./counter.sh p5 > o5 & w=$!; set -- $(pid_of_hp p5); kill -TERM "$2"; wait $w; echo "last: $(cat o5)"

echo "== 5 make recipe (if make exists): explicit INT to the pid"
if command -v make >/dev/null 2>&1 && make --version >/dev/null 2>&1; then
  printf 'all:\n\t"%s" run -- ./counter.sh p6 > o6\n' "$HP" > Makefile
  rm -f p6; make -s > mk.out 2>&1 & w=$!; set -- $(pid_of_hp p6); kill -INT "$2"; wait $w; echo "make_rc=$? $(cat o6)"
else echo "make: not available"; fi

echo "== 6 signal not in the five (USR1) / SIGKILL to the pid: orphan? (out of contract, recorded)"
for s in USR1 KILL; do
  rm -f p7; "$HP" run -- ./counter.sh p7 > o7 & w=$!; set -- $(pid_of_hp p7); kill -$s "$2"; wait $w 2>/dev/null; rc=$?
  sleep 0.1; if kill -0 "$1" 2>/dev/null; then alive=yes; else alive=no; fi; echo "$s: hp_rc=$rc child_alive_after_hp_exit=$alive"; kill -TERM "$1" 2>/dev/null
done

echo "== 7 explicit signal burst: 5x INT back to back to the pid"
rm -f p8; "$HP" run -- ./counter.sh p8 > o8 & w=$!; set -- $(pid_of_hp p8); for i in 1 2 3 4 5; do kill -INT "$2"; sleep 0.05; done; wait $w; echo "rc=$? $(cat o8)"

echo "== 8 heimdall-proto stopped (SIGSTOP) then explicit TERM then SIGCONT"
rm -f p9; "$HP" run -- ./counter.sh p9 > o9 & w=$!; set -- $(pid_of_hp p9); kill -STOP "$2"; kill -TERM "$2"; sleep 0.2; kill -CONT "$2"; wait $w; echo "rc=$? $(cat o9)"

echo "== 9 meta file in a read-only dir and a FIFO meta path"
mkdir ro; chmod 555 ro; "$HP" run --meta-file ro/m.json -- true 2>e9; echo "ro rc=$? stderr=$(cat e9)"; chmod 755 ro
mkfifo ff; ( timeout 5 "$HP" run --meta-file ff -- true 2>e10; echo "fifo rc=$?" ) ; echo "fifo stderr=$(cat e10)"

echo "== 10 environment: RUST_MIN_STACK huge -> run launches nothing (no orphan)"
RUST_MIN_STACK=999999999999999 "$HP" run --meta-file m11 -- sh -c 'echo CHILD_RAN > ran11' 2>e11; echo "rc=$? ran=$( [ -e ran11 ] && echo yes || echo no) meta=$(cat m11 2>/dev/null) stderr=$(head -c 160 e11)"
RUST_MIN_STACK=999999999999999 "$HP" agent list --socket ./nosock --json > o12 2>e12; echo "agent rc=$? out=$(head -c 160 o12)"
