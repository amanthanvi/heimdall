#!/bin/sh
# Run one X2 hidden test task inside the G02 Linux runner image (linux/arm64, the image
# tests/g02/linux/run.sh builds: same tag derivation, same RUN_FLAGS, --network none).
#
#   HM_REPO=<repo> sh docker-run.sh --task T1|T2|T3|T4 --artifact-dir DIR --out-dir DIR [--bin PATH] -- --lang go|rust|control [run.py args]
#
#   --artifact-dir DIR  host directory holding the linux-arm64 heimdall-proto (mounted read-only at /artifact)
#   --out-dir DIR       host directory for <task>-linux.json and the console log (mounted read-write at /out)
#   --bin PATH          path INSIDE the container (default /artifact/heimdall-proto); e.g.
#                       /hidden/positive-controls/pc_t2.py for a positive control
# Mounts: this directory read-only at /hidden, DIR read-only at /artifact, OUT read-write at /out.
# The repository is not mounted.  Exit status: run.py's (0 pass, 1 fail/error, 2 usage), or 2 for a
# setup error here.  Never builds, pushes or touches resources labelled heimdall.fixture.
set -eu
HID=$(cd "$(dirname "$0")" && pwd -P)
die() { echo "docker-run.sh: $*" >&2; exit 2; }
[ -n "${HM_REPO:-}" ] || die "set HM_REPO to the heimdall repository root (for the image tag)"
TASK=""; ART=""; OUT=""; BIN=/artifact/heimdall-proto
while [ $# -gt 0 ]; do
    case "$1" in
        --task) TASK=$2; shift 2 ;;
        --artifact-dir) ART=$2; shift 2 ;;
        --out-dir) OUT=$2; shift 2 ;;
        --bin) BIN=$2; shift 2 ;;
        --) shift; break ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$TASK" ] && [ -n "$ART" ] && [ -n "$OUT" ] || die "--task, --artifact-dir and --out-dir are required"
[ -d "$ART" ] || die "--artifact-dir is not a directory"
mkdir -p "$OUT"
ART=$(cd "$ART" && pwd -P); OUT=$(cd "$OUT" && pwd -P)
L="$HM_REPO/tests/g02/linux"
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
TAG=$(cat "$L/Dockerfile" "$L/Dockerfile.dockerignore" "$HM_REPO/tests/g02/requirements.txt" | $SUM | cut -c1-12)
IMAGE="heimdall-g02-harness:$TAG"
PIN=$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["linux_image"]["tag"])' "$HID/BASE.json") \
    || die "cannot read the pinned image tag from BASE.json"
[ "$TAG" = "$PIN" ] || die "image tag $TAG differs from the pinned $PIN (HM_REPO/tests/g02/linux changed)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE missing: build it with sh $L/run.sh --build"
[ "$(docker image inspect -f '{{.Architecture}}' "$IMAGE")" = arm64 ] || die "image is not arm64"
[ "$(docker version -f '{{.Server.Arch}}')" = arm64 ] || die "docker server is not arm64 (no emulation)"
# shellcheck disable=SC2086
exec docker run --rm --platform linux/arm64 --network none --user 10001:10001 --cap-drop ALL \
    --security-opt no-new-privileges --memory 2g --pids-limit 4096 -e PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$HID,dst=/hidden,readonly" \
    --mount "type=bind,src=$ART,dst=/artifact,readonly" \
    --mount "type=bind,src=$OUT,dst=/out" \
    "$IMAGE" python3 -I -B /hidden/run.py --task "$TASK" --bin "$BIN" --platform linux --out "/out/$TASK-linux.json" "$@"
