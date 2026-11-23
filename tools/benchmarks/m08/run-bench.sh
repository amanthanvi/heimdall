#!/usr/bin/env bash
# Run the A34 benchmarks on a release archive in the M08 container (m08-plan W2-3; ADR-0014
# section 6.1). Blocks until the run ends, then removes the container.
#
# Usage: bash tools/benchmarks/m08/run-bench.sh --stage <staged archive dir> [--id <name>]
#            [--destinations N] [--samples N] [--settle S] [--idle-window S] [--idle-windows N]
#   defaults: 100 destinations, 200 samples (the floor), 600 s settle, 3 windows of 300 s.
# Exit code: 0 when the run ended with bench.json written; 1 otherwise; 2 on a usage error.
#
# The container: no network, 2 CPUs, 2 GiB, 512 processes; the repository and the archive
# read-only; the only writable mount is the run's output directory. It is capped at 2 CPUs,
# so it takes no heavy-gate slot, and it is the one capped container at a time (fuzz or soak
# or this). The host's load is sampled every 30 s beside it, because the Mac is shared.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)
image=hm-m08-soak:1
stage=""; id=""; dests=100; samples=200; settle=600; window=300; windows=3
while [ $# -gt 0 ]; do
    case "$1" in
        --stage) stage=$2; shift 2 ;;
        --id) id=$2; shift 2 ;;
        --destinations) dests=$2; shift 2 ;;
        --samples) samples=$2; shift 2 ;;
        --settle) settle=$2; shift 2 ;;
        --idle-window) window=$2; shift 2 ;;
        --idle-windows) windows=$2; shift 2 ;;
        *) sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
case "$dests:$samples:$settle:$window:$windows" in *[!0-9:]*|:*|*::*) echo "run-bench: numbers only" >&2; exit 2 ;; esac
[ -n "$stage" ] && [ -f "$stage/heimdall" ] || { echo "run-bench: --stage must hold a heimdall executable" >&2; exit 2; }
stage=$(cd "$stage" && pwd -P)
id=${id:-$(date -u +%Y%m%dT%H%M%SZ)}
case "$id" in *[!A-Za-z0-9_-]*) echo "run-bench: --id is letters, digits, - and _" >&2; exit 2 ;; esac
name="hm-m08-bench-$id"
out="$repo/target/m08-bench/$id"
[ ! -e "$out" ] || { echo "run-bench: $out exists" >&2; exit 2; }
mkdir -p "$out"
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$repo/tools/benchmarks/m08" >/dev/null
# The host, for the record: model, CPU, memory, OS build and power source. No host name and
# no account name.
model=$( (sysctl -n hw.model 2>/dev/null || cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null) | head -1)
cpu=$( (sysctl -n machdep.cpu.brand_string 2>/dev/null || awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo) | head -1)
mem=$( (sysctl -n hw.memsize 2>/dev/null || awk '/MemTotal/{print $2*1024}' /proc/meminfo) | head -1)
os=$( (sw_vers -productVersion 2>/dev/null && sw_vers -buildVersion 2>/dev/null) | tr '\n' ' ')
power=$( (pmset -g batt 2>/dev/null | head -1 | sed "s/.*'\(.*\)'.*/\1/") || echo unknown)
harness=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$repo" status --porcelain -- tools/benchmarks 2>/dev/null)" ] || harness="$harness (tools/benchmarks modified)"
python3 -I -c 'import json,sys; print(json.dumps({"harness_commit":sys.argv[9],"host_started_at":sys.argv[1],"container":sys.argv[2],"image":sys.argv[3],"limits":"network none, 2 CPUs, 2 GiB, 512 pids","host_model":sys.argv[4],"host_cpu":sys.argv[5],"host_memory_bytes":sys.argv[6],"host_os":sys.argv[7].strip(),"host_power":sys.argv[8],"host_shared":"the Mac runs other workloads; host load is sampled in host-load.ndjson"}))' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$image" "$model" "$cpu" "$mem" "$os" "$power" "$harness" >"$out/host.json"
docker run -d --init --name "$name" --network none --cpus 2 --memory 2g --pids-limit 512 ${BENCH_CAPTURE:+-e BENCH_CAPTURE=1} \
    -v "$repo":/src:ro -v "$stage":/a:ro -v "$out":/out \
    "$image" bash /src/tools/benchmarks/m08/bench-entry.sh "$dests" "$samples" "$settle" "$window" "$windows" >/dev/null
echo "run-bench: started $name; output in target/m08-bench/$id"
( while docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; do
      printf '{"at":"%s","load":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$( (sysctl -n vm.loadavg 2>/dev/null || cat /proc/loadavg) | tr -d '{}')" >>"$out/host-load.ndjson"
      sleep 30
  done ) &
sampler=$!
code=$(docker wait "$name")
wait "$sampler" 2>/dev/null || true
printf '{"host_stopped_at":"%s","container_exit":%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$code" >"$out/host-end.json"
docker rm "$name" >/dev/null
[ "$code" = 0 ] && [ -f "$out/bench/bench.json" ]
