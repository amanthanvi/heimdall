#!/usr/bin/env bash
# Start a soak run of a release archive in a container (m08-plan U5a; ADR-0014 section 6).
#
# Usage: bash tools/benchmarks/m08/run-soak.sh --stage <staged archive dir> --seconds <n>
#            [--tick <s>] [--seed <n>] [--id <name>] [--lanes SL|S|L] [--block]
#        bash tools/benchmarks/m08/run-soak.sh --grant-history-growth
#        bash tools/benchmarks/m08/run-soak.sh --authority-history-growth
#   --stage    a directory holding the Linux `heimdall` for this machine's container
#              architecture (target/release-artifacts/heimdall-<version>-<target>/)
#   --block    wait for the run, print the analysis, remove the container. Use it for a
#              rehearsal. Without it the run is detached and supervises itself (the 72-hour
#              run only; ADR-0014 section 6.6): read target/m08-soak/<id>/{S,L}/status.json.
# Exit code: with --block, 0 when both lanes ended DONE and the analysis found no failure;
# 1 otherwise; 2 on a usage or setup error. Without --block, 0 once the container started.
#
# The container: no network, 2 CPUs, 2 GiB memory, 512 processes. The repository and the
# archive are mounted read-only; the only writable mount is the run's output directory.
# It is capped at 2 CPUs, so it takes no heavy-gate slot; run one capped container at a time.
# Never run the archive's executable on the host: only this container starts it.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
if [ "$#" -eq 1 ] && [ "$1" = --grant-history-growth ]; then
    cd "$repo"
    unset CARGO_TARGET_DIR
    exec env CARGO_BUILD_JOBS=4 cargo test --locked -p heimdall-store --lib \
        grant_live_tests::grant_history_growth -- --exact --ignored --nocapture
fi
# M08 W4 SEC-3b: the runner's authority history (tombstones, delivered pauses and cutoffs,
# their acknowledgements, widening records) and its report, across retention cycles.
if [ "$#" -eq 1 ] && [ "$1" = --authority-history-growth ]; then
    cd "$repo"
    unset CARGO_TARGET_DIR
    exec env CARGO_BUILD_JOBS=4 cargo test --locked -p heimdall-runtime \
        --test integration_runner_history_m08 authority_history_growth -- --exact --ignored \
        --nocapture
fi
image=hm-m08-soak:1
stage=""; seconds=""; tick=60; seed=1; id=""; block=no; lanes=SL
while [ $# -gt 0 ]; do
    case "$1" in
        --stage) stage=$2; shift 2 ;;
        --seconds) seconds=$2; shift 2 ;;
        --tick) tick=$2; shift 2 ;;
        --seed) seed=$2; shift 2 ;;
        --id) id=$2; shift 2 ;;
        --lanes) lanes=$2; shift 2 ;;
        --block) block=yes; shift ;;
        *) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
case "$seconds:$tick:$seed" in *[!0-9:]*|:*|*::*) echo "run-soak: --seconds, --tick and --seed are numbers" >&2; exit 2 ;; esac
[ -n "$stage" ] && [ -f "$stage/heimdall" ] || { echo "run-soak: --stage must hold a heimdall executable" >&2; exit 2; }
stage=$(cd "$stage" && pwd -P)
id=${id:-$(date -u +%Y%m%dT%H%M%SZ)}
case "$lanes" in SL|S|L) ;; *) echo "run-soak: --lanes is SL, S or L" >&2; exit 2 ;; esac
case "$id" in *[!A-Za-z0-9_-]*) echo "run-soak: --id is letters, digits, - and _" >&2; exit 2 ;; esac
name="hm-m08-soak-$id"
out="$repo/target/m08-soak/$id"
[ ! -e "$out" ] || { echo "run-soak: $out exists" >&2; exit 2; }
mkdir -p "$out"
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$repo/tools/benchmarks/m08" >/dev/null
printf '{"host_started_at":"%s","container":"%s","image":"%s","limits":"network none, 2 CPUs, 2 GiB, 512 pids","host_os":"%s %s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$image" "$(uname -s)" "$(uname -m)" >"$out/host.json"
docker run -d --init --name "$name" --network none --cpus 2 --memory 2g --pids-limit 512 \
    -v "$repo":/src:ro -v "$stage":/a:ro -v "$out":/out \
    "$image" bash /src/tools/benchmarks/m08/entry.sh "$seconds" "$seed" "$tick" "$lanes" >/dev/null
echo "run-soak: started $name; output in target/m08-soak/$id"
# The Mac is shared: the host's load is sampled every 30 s beside the soak, detached, for as long
# as the container runs (ruled 2026-11-23).
( while docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; do
      printf '{"at":"%s","load":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$( (sysctl -n vm.loadavg 2>/dev/null || cat /proc/loadavg) | tr -d '{}')" >>"$out/host-load.ndjson"
      sleep 30
  done ) </dev/null >/dev/null 2>&1 &
[ "$block" = yes ] || exit 0
code=$(docker wait "$name")
printf '{"host_stopped_at":"%s","container_exit":%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$code" >"$out/host-end.json"
docker rm "$name" >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 -I "$repo/tools/benchmarks/m08/analyze.py" "$out" --lanes "$lanes" || code=1
[ "$code" = 0 ]
