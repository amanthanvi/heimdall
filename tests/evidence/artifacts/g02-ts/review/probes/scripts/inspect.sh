B=/tmp/hm-review-root/prototypes/ts/dist/darwin-arm64/heimdall-proto
for V in "ws://127.0.0.1:47391/hmreview" ; do
  env -i PATH=/usr/bin:/bin HOME=/tmp/hm-review-probes/envid BUN_INSPECT="$V" $B run -- /bin/sleep 2 >/tmp/hm-review-probes/envid/inspect.out 2>&1 &
  P=$!
  sleep 1
  echo "BUN_INSPECT=$V listeners_by_pid: $(/usr/sbin/lsof -nP -a -p $P -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $9}' | tr '\n' ' ')"
  wait $P; echo "proto rc=$?"; echo "output: $(head -c 300 /tmp/hm-review-probes/envid/inspect.out | tr '\n' ' ')"
done
echo "== BUN_INSPECT_CONNECT_TO / BUN_JSC_ strings in artifact:"; for s in BUN_INSPECT BUN_INSPECT_CONNECT_TO BUN_OPTIONS BUN_BE_BUN BUN_JSC_ NODE_OPTIONS; do printf '%s=%s ' $s $(grep -c "$s" $B); done; echo
