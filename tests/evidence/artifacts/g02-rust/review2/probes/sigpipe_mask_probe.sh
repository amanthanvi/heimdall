#!/bin/sh
# Reviewer-2 probe: is an inherited SIGPIPE ignore preserved in the run child? (non-python child,
# because CPython ignores SIGPIPE itself at start-up and so cannot observe this)
# Usage: sigpipe_mask_probe.sh BIN
B=$1
M=$(mktemp -d /tmp/hp-rv2-sp.XXXX)
# Baseline: exec semantics (no heimdall-proto) for comparison
sh -c "trap '' PIPE; exec yes" 2>"$M/base.err" | head -n 1 >/dev/null
echo "baseline_exec_yes_stderr=$(head -c 80 "$M/base.err")"
sh -c "trap '' PIPE; exec \"$B\" run --meta-file \"$M/m1.json\" -- yes" 2>"$M/e1" | head -n 1 >/dev/null
echo "ignored_PIPE_via_hp_meta=$(cat "$M/m1.json")"
echo "ignored_PIPE_via_hp_child_stderr=$(head -c 80 "$M/e1")"
"$B" run --meta-file "$M/m2.json" -- yes | head -n 1 >/dev/null
echo "default_PIPE_via_hp_meta=$(cat "$M/m2.json")"
if [ -r /proc/self/status ]; then
  sh -c "trap '' PIPE USR1; exec \"$B\" run -- grep -E '^Sig(Ign|Blk)' /proc/self/status" | tr '\n' ' '; echo
  sh -c "trap '' PIPE USR1; exec grep -E '^Sig(Ign|Blk)' /proc/self/status" | tr '\n' ' '; echo " (baseline exec)"
fi
rm -rf "$M"
