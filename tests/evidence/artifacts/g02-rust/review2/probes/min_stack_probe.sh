#!/bin/sh
# Reviewer-2 probe: RUST_MIN_STACK (read by Rust std at thread spawn) set to an absurd value.
# Usage: min_stack_probe.sh BIN
B=$1
M=$(mktemp -d /tmp/hp-rv2-ms.XXXX)
RUST_MIN_STACK=999999999999999 "$B" run --meta-file "$M/meta.json" -- /bin/sh -c "sleep 1; echo child-finished-ppid=\$PPID > $M/marker" 2>"$M/err"
echo "run_exit=$?"
echo "meta_exists=$(test -f "$M/meta.json" && echo yes || echo no)"
echo "marker_right_after_hp_exit=$(test -f "$M/marker" && echo yes || echo no)"
sleep 1.5
echo "marker_later=$(cat "$M/marker" 2>/dev/null)"
echo "stderr_first_line=$(sed -n 2p "$M/err" | cut -c1-60)"
RUST_MIN_STACK=999999999999999 "$B" agent list --socket "$M/nosock" --json >"$M/out" 2>/dev/null
echo "agent_exit=$? stdout=$(cat "$M/out")"
rm -rf "$M"
