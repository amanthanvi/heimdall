#!/bin/sh
# parity-r3c: run every probe against both candidates on one platform.
#   run_all.sh OUTDIR GO_BIN RUST_BIN
# darwin: run on the host.  linux: run inside the harness image (see run_linux.sh).
# Exit codes of each probe are written to OUTDIR/exit-codes.txt; this script itself never aborts early.
set -u
P=$(cd "$(dirname "$0")" && pwd -P)
OUT=$1; GO=$2; RS=$3
mkdir -p "$OUT"
unset SSH_AUTH_SOCK
PY=${PY:-python3}
EC="$OUT/exit-codes.txt"
: > "$EC"
rec() { echo "$1 exit=$2" >> "$EC"; }

# probe 1a: rust reviewer's extstop.py, unchanged, once per candidate
for c in go rust; do
    b=$GO; [ $c = rust ] && b=$RS
    $PY "$P/extstop.py" "$b" "$OUT/extstop-orig-$c.json" > "$OUT/extstop-orig-$c.console.txt" 2>&1; rec "extstop.py $c" $?
done
# probe 1a+: extended (reaping/completion)
$PY "$P/extstop_plus.py" "$OUT/extstop-plus.json" go="$GO" rust="$RS" > "$OUT/extstop-plus.console.txt" 2>&1; rec "extstop_plus.py" $?
# probe 1a+ again, in a non-orphaned process group (SIGTSTP is otherwise discarded by the kernel)
$PY "$P/nonorphan.py" $PY "$P/extstop_plus.py" "$OUT/extstop-plus-nonorphan.json" go="$GO" rust="$RS" > "$OUT/extstop-plus-nonorphan.console.txt" 2>&1; rec "nonorphan extstop_plus.py" $?
# probe 1b: interactive foreground job
mkdir -p "$OUT/pty"
for sh in bash zsh; do
    $PY "$P/extstop_pty.py" $sh "$OUT/pty" go="$GO" rust="$RS" > "$OUT/pty/$sh-extstop-pty.console.txt" 2>&1; rec "extstop_pty.py $sh" $?
done
# probes 2 + 3: rust reviewer's probe.py, unchanged, scenarios explicit and nested_shell
for c in go rust; do
    b=$GO; [ $c = rust ] && b=$RS
    for sh in bash zsh; do
        mkdir -p "$OUT/probe-$c"
        $PY "$P/probe.py" "$b" $sh "$OUT/probe-$c" explicit,nested_shell > "$OUT/probe-$c/$sh-console.txt" 2>&1; rec "probe.py $c $sh" $?
    done
done
# probe 4: go reviewer's selfstop_detail.py, unchanged, SIGSTOP, exclusive (candidates) / control
mkdir -p "$OUT/detail"
for sh in bash zsh; do
    for trig in read ext; do
        $PY "$P/selfstop_detail.py" "$GO" $sh SIGSTOP control $trig > "$OUT/detail/control-$sh-$trig.json" 2>&1; rec "selfstop_detail control $sh $trig" $?
        for c in go rust; do
            b=$GO; [ $c = rust ] && b=$RS
            $PY "$P/selfstop_detail.py" "$b" $sh SIGSTOP exclusive $trig > "$OUT/detail/$c-$sh-$trig.json" 2>&1; rec "selfstop_detail $c $sh $trig" $?
        done
    done
done
echo done
# dedicated probes 2 and 3
sh "$P/run_extra.sh" "$OUT" "$GO" "$RS"
echo done-extra
