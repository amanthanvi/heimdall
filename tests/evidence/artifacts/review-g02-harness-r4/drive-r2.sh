#!/bin/sh
# reviewer driver M00-T05-review-harness-r4 (resumed). $1 = darwin|linux
set -u
cd <repo>
PLAT=$1
R=tests/evidence/artifacts/review-g02-harness-r4/records-r2/$PLAT
mkdir -p "$R" /tmp/rv4r2/arts/$PLAT /tmp/rv4r2/log/$PLAT
IDS='run.k6e_child_self_stop,k12.closed_stdout_exit_parity'
SUM=$R/summary.tsv
: > "$SUM"
one() { # name bin-or-ref only
    name=$1; bin=$2; only=$3
    t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    log=/tmp/rv4r2/log/$PLAT/$name.log
    if [ "$PLAT" = darwin ]; then
        if [ "$bin" = REF ]; then
            python3 tests/g02/conformance.py --bin tests/g02/reference_impl.py --candidate go --selftest --only "$only" \
                --out "$R/$name.json" --artifacts-dir /tmp/rv4r2/arts/darwin/$name > "$log" 2>&1
        else
            python3 tests/g02/conformance.py --bin "$bin/heimdall-proto" --candidate go --only "$only" \
                --out "$R/$name.json" --artifacts-dir /tmp/rv4r2/arts/darwin/$name > "$log" 2>&1
        fi
        rc=$?
    else
        if [ "$bin" = REF ]; then
            tests/g02/linux/run.sh --reference --only "$only" --out "$R/$name.json" --artifacts-out /tmp/rv4r2/arts/linux/$name > "$log" 2>&1
        else
            tests/g02/linux/run.sh --artifact-dir "$bin" --candidate go --only "$only" --out "$R/$name.json" --artifacts-out /tmp/rv4r2/arts/linux/$name > "$log" 2>&1
        fi
        rc=$?
    fi
    t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$rc" "$t0" "$t1" "$only" >> "$SUM"
}
for i in 1 2 3; do one reference-$i REF "$IDS"; done
for m in $(ls /tmp/rv4r2/mut); do one "$m" /tmp/rv4r2/mut/$m "$IDS"; done
one rv_nograce@jc /tmp/rv4r2/mut/rv_nograce run.k6e_job_control
one rv_mirror_killpg@k6a /tmp/rv4r2/mut/rv_mirror_killpg 'run.k6a_pipeline_peer_not_stopped,run.k6a_background_script_tty,run.k6a_inherited_ignore'
one reference@k6a REF 'run.k6a_pipeline_peer_not_stopped,run.k6a_background_script_tty,run.k6a_inherited_ignore,run.k6e_job_control'
echo DONE >> "$SUM"
