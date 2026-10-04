#!/bin/sh
# G02 Linux runner (contract section 9.1 K13): runs the shared harness inside a digest-pinned linux/arm64
# container on the Docker Desktop arm64 VM (native arm64 kernel, not emulation), with --network none,
# a non-root user, the repository and the artifact directory mounted read-only and only the output
# directory writable.  Produces the same evidence record format as a host run, with
# environment.platform = linux-arm64 and the image digests recorded in environment.container.
#
#   run.sh --artifact-dir DIR --candidate go|rust|ts --out RECORD.json [--artifacts-out DIR] [--only IDS] [--case-id ID]
#       Full catalogue (or --only) against DIR/heimdall-proto (DIR is mounted whole, so sidecars resolve
#       from the executable's own directory, K11).  Default case id G02-<candidate>-conformance-linux-arm64.
#   run.sh --reference --out RECORD.json [--candidate go] [--artifacts-out DIR] [--only IDS] [--case-id ID]
#       Harness self-test record against tests/g02/reference_impl.py (--selftest: no requirement ids).
#       REF_MUTATE and HM_G02_HARNESS_MUTATE from the caller's environment are passed through.
#   run.sh --selftest OUT_DIR [-- selftest.py args...]
#       tests/g02/selftest.py inside the container; writes OUT_DIR/SELFTEST-linux.md, OUT_DIR/selftest-linux.json
#       and the per-run records under OUT_DIR/work.
#   run.sh --build
#       Build (if needed) and print the image reference.
#
# Exit status: the harness's own (0 pass, 1 check failed/errored, 2 usage, 3 canary self-check), or 2 for
# a runner usage/setup error.  Never pushes, publishes or touches resources labelled heimdall.fixture.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd -P)
G02=$(dirname "$HERE")
REPO=$(cd "$G02/../.." && pwd -P)

die() { echo "run.sh: $*" >&2; exit 2; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi
}

command -v docker >/dev/null 2>&1 || die "docker not found"
command -v python3 >/dev/null 2>&1 || die "python3 (host) not found; it builds the environment JSON"

TAG=$(cat "$HERE/Dockerfile" "$HERE/Dockerfile.dockerignore" "$G02/requirements.txt" | sha256_of | cut -c1-12)
IMAGE="heimdall-g02-harness:$TAG"
BASE_REF=$(sed -n 's/^FROM \([^ ]*\).*$/\1/p' "$HERE/Dockerfile" | head -n 1)

build_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "run.sh: building $IMAGE (base $BASE_REF)" >&2
        docker build --platform linux/arm64 --label "org.heimdall.purpose=g02-harness-runner" \
            -f "$HERE/Dockerfile" -t "$IMAGE" "$G02" >&2
    fi
    arch=$(docker image inspect -f '{{.Architecture}}' "$IMAGE")
    [ "$arch" = "arm64" ] || die "image architecture is $arch, K13 needs arm64"
    srv=$(docker version -f '{{.Server.Arch}}')
    [ "$srv" = "arm64" ] || die "docker server architecture is $srv: K13 needs a native arm64 VM, not emulation"
}

MODE=""
ART=""
CAND=""
OUT=""
ARTS_OUT=""
ONLY=""
CASE_ID=""
SELFTEST_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --artifact-dir) ART=$2; MODE=${MODE:-artifact}; shift 2 ;;
        --reference) MODE=reference; shift ;;
        --candidate) CAND=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --artifacts-out) ARTS_OUT=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;;
        --case-id) CASE_ID=$2; shift 2 ;;
        --selftest) MODE=selftest; SELFTEST_DIR=$2; shift 2
                    [ "${1:-}" = "--" ] && shift
                    break ;;
        --build) MODE=build; shift ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done
[ -n "$MODE" ] || die "one of --artifact-dir, --reference, --selftest, --build is required"

build_image
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")
if [ "$MODE" = build ]; then
    echo "$IMAGE $IMAGE_ID"
    exit 0
fi

DOCKER_SERVER=$(docker version -f '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')
PKGS=$(docker run --rm --platform linux/arm64 --network none "$IMAGE" \
       dpkg-query -W -f '${Package}=${Version} ' openssh-client locales zsh)
COMMIT=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)
if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null | head -n 1)" ]; then COMMIT="$COMMIT+dirty"; fi

RUN_FLAGS="--rm --platform linux/arm64 --network none --user 10001:10001 --cap-drop ALL
 --security-opt no-new-privileges --memory 2g --pids-limit 4096 -e PYTHONDONTWRITEBYTECODE=1"

if [ "$MODE" = selftest ]; then
    mkdir -p "$SELFTEST_DIR"
    SD=$(cd "$SELFTEST_DIR" && pwd -P)
    # shellcheck disable=SC2086
    exec docker run $RUN_FLAGS \
        --mount "type=bind,src=$REPO,dst=/repo,readonly" --mount "type=bind,src=$SD,dst=/out" \
        -e "HM_G02_IMAGE=$IMAGE" -e "HM_G02_IMAGE_ID=$IMAGE_ID" -e "HM_G02_BASE=$BASE_REF" \
        -e "HM_G02_DOCKER=$DOCKER_SERVER" -e "HM_G02_PKGS=$PKGS" -e "HM_G02_COMMIT=$COMMIT" \
        "$IMAGE" python3 /repo/tests/g02/selftest.py --out /out/SELFTEST-linux.md --json-out /out/selftest-linux.json \
        --workdir /out/work "$@"
fi

[ -n "$OUT" ] || die "--out is required"
if [ "$MODE" = reference ]; then
    CAND=${CAND:-go}
    BIN=/repo/tests/g02/reference_impl.py
    CASE_ID=${CASE_ID:-G02-harness-selftest-$CAND-linux-arm64}
else
    [ -n "$CAND" ] || die "--candidate is required"
    [ -d "$ART" ] || die "--artifact-dir must be a directory holding heimdall-proto"
    ART=$(cd "$ART" && pwd -P)
    [ -x "$ART/heimdall-proto" ] || die "$ART/heimdall-proto is not an executable file"
    BIN=/artifact/heimdall-proto
    CASE_ID=${CASE_ID:-G02-$CAND-conformance-linux-arm64}
fi
mkdir -p "$(dirname "$OUT")"
OUTDIR=$(cd "$(dirname "$OUT")" && pwd -P)
OUTNAME=$(basename "$OUT")
if [ -n "$ARTS_OUT" ]; then
    mkdir -p "$ARTS_OUT"
    ARTS_HOST=$(cd "$ARTS_OUT" && pwd -P)
else
    ARTS_HOST="$OUTDIR/artifacts/$CASE_ID"
    mkdir -p "$ARTS_HOST"
fi

ENV_JSON=$(python3 - "$IMAGE" "$IMAGE_ID" "$BASE_REF" "$DOCKER_SERVER" "$PKGS" "$MODE" "${ART:-}" "$REPO" <<'PYEOF'
import json, os, sys
image, image_id, base, server, pkgs, mode, art, repo = sys.argv[1:9]
rel = (os.path.relpath(art, repo) if art and art.startswith(repo + os.sep) else art) or None
print(json.dumps({"container": {
    "runner": "tests/g02/linux/run.sh", "image_ref": image, "image_id": image_id, "base_image": base,
    "image_packages": pkgs.split(), "docker_server": server, "network": "none", "user": "10001:10001",
    "capabilities": "all dropped, no-new-privileges", "memory_limit": "2g",
    "mounts": {"repository": "/repo (read-only)", "artifact_dir": "/artifact (read-only)" if art else None,
               "output": "/out (read-write)"}},
    "artifact_dir": rel, "subject": "reference_impl.py" if mode == "reference" else "artifact"}))
PYEOF
)

set -- --bin "$BIN" --candidate "$CAND" --out "/out/$OUTNAME" --artifacts-dir /arts --case-id "$CASE_ID" \
    --build-commit "$COMMIT" --environment-extra "$ENV_JSON" \
    --path-map "/out=$OUTDIR" --path-map "/arts=$ARTS_HOST" --path-map "/repo=$REPO"
[ -n "$ONLY" ] && set -- "$@" --only "$ONLY"
rc=0
if [ "$MODE" = reference ]; then
    set -- "$@" --selftest --pass-env REF_MUTATE,REF_CANDIDATE
    # shellcheck disable=SC2086
    docker run $RUN_FLAGS \
        -e "REF_MUTATE=${REF_MUTATE:-}" -e "REF_CANDIDATE=${REF_CANDIDATE:-$CAND}" \
        -e "HM_G02_HARNESS_MUTATE=${HM_G02_HARNESS_MUTATE:-}" \
        --mount "type=bind,src=$REPO,dst=/repo,readonly" \
        --mount "type=bind,src=$OUTDIR,dst=/out" --mount "type=bind,src=$ARTS_HOST,dst=/arts" \
        "$IMAGE" python3 /repo/tests/g02/conformance.py "$@" || rc=$?
else
    set -- "$@" --path-map "/artifact=$ART"
    # shellcheck disable=SC2086
    docker run $RUN_FLAGS \
        --mount "type=bind,src=$REPO,dst=/repo,readonly" --mount "type=bind,src=$ART,dst=/artifact,readonly" \
        --mount "type=bind,src=$OUTDIR,dst=/out" --mount "type=bind,src=$ARTS_HOST,dst=/arts" \
        "$IMAGE" python3 /repo/tests/g02/conformance.py "$@" || rc=$?
fi
exit "$rc"
