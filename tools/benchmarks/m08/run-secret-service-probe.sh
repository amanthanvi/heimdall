#!/usr/bin/env bash
# Run the secret-service probe, step (i) (m08-w3-plan W3-6), on a staged Linux release archive, in
# its own container image (Dockerfile.secret-service; the soak image is unchanged). Blocks until
# the run ends, then removes the container. Output: target/m08-probe/<id>/ (never committed as
# is; the record copies facts.ndjson, image.json and packages.txt).
#
# Usage: bash tools/benchmarks/m08/run-secret-service-probe.sh --stage <staged Linux archive dir> [--id NAME] [--mode fresh|prereq|slow] [--delay-ms N]
# The container: no network, 2 CPUs, 2 GiB, 512 processes, an init process; the repository and the
# archive read-only. It is a capped container: run it only when the capped slot is free.
set -u
repo=$(cd "$(dirname "$0")/../../.." && pwd -P)
image=hm-m08-secret-service:1
stage=""; id=""; mode=fresh; delay=500
while [ $# -gt 0 ]; do
    case "$1" in
        --stage) stage=$2; shift 2 ;;
        --id) id=$2; shift 2 ;;
        --mode) mode=$2; shift 2 ;;
        --delay-ms) delay=$2; shift 2 ;;
        *) echo "usage: run-secret-service-probe.sh --stage DIR [--id NAME]" >&2; exit 2 ;;
    esac
done
[ -n "$stage" ] && [ -f "$stage/heimdall" ] || { echo "run-secret-service-probe: --stage must hold a heimdall executable" >&2; exit 2; }
stage=$(cd "$stage" && pwd -P)
id=${id:-$(date -u +%Y%m%dT%H%M%SZ)}
case "$delay" in ""|*[!0-9]*) echo "run-secret-service-probe: --delay-ms is a number" >&2; exit 2 ;; esac
case "$mode" in fresh|prereq|slow) ;; *) echo "run-secret-service-probe: --mode is fresh, prereq or slow" >&2; exit 2 ;; esac
case "$id" in *[!A-Za-z0-9_-]*) echo "run-secret-service-probe: --id is letters, digits, - and _" >&2; exit 2 ;; esac
out="$repo/target/m08-probe/$id"; name="hm-m08-ssprobe-$id"
[ ! -e "$out" ] || { echo "run-secret-service-probe: $out exists" >&2; exit 2; }
mkdir -p "$out"
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" -f "$repo/tools/benchmarks/m08/Dockerfile.secret-service" "$repo/tools/benchmarks/m08" >/dev/null || exit 1
docker image inspect "$image" --format '{"image_id":"{{.Id}}","created":"{{.Created}}","arch":"{{.Architecture}}"}' >"$out/image.json"
docker run --rm --network none "$image" dpkg-query -W -f '${Package} ${Version}\n' >"$out/packages.txt"
docker run --init --name "$name" --network none --cpus 2 --memory 2g --pids-limit 512 \
    -v "$repo":/src:ro -v "$stage":/a:ro -v "$out":/out -e mode="$mode" "$image" bash -c '
        set -u
        install -m 0755 /a/heimdall /usr/local/bin/heimdall-under-test
        chown soaks /out
        printf "{\"binary_sha256\":\"%s\",\"kernel\":\"%s\",\"arch\":\"%s\"}\n" "$(sha256sum /a/heimdall | cut -d" " -f1)" "$(uname -r)" "$(uname -m)" >/out/run.json
        runuser -u soaks -- env SLOW_BUS_DELAY_MS='"$delay"' dbus-run-session -- bash /src/tools/benchmarks/m08/secret-service-probe.sh /usr/local/bin/heimdall-under-test /out '"$mode"' >/out/probe.log 2>&1
        echo "{\"exit\":$?}" >/out/end.json' >/dev/null 2>&1
code=$(docker inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null || echo 1)
docker rm "$name" >/dev/null 2>&1
echo "run-secret-service-probe: exit $code; output in target/m08-probe/$id"
exit "$code"
