#!/bin/sh
# parity-r3c: run run_all.sh inside the G02 harness image (tests/g02/linux/run.sh, same tag
# derivation and the same RUN_FLAGS), linux/arm64, --network none, uid 10001, cap-drop ALL.
#   run_linux.sh REPO SCRATCH
# SCRATCH holds probes/ and bin/{go,rust}/linux-arm64/heimdall-proto (sha256-verified copies of
# the dist artifacts) and is mounted read-write at /w; the repository is not mounted.
set -u
REPO=$1; S=$2
H="$REPO/tests/g02/linux"
TAG=$(cat "$H/Dockerfile" "$H/Dockerfile.dockerignore" "$REPO/tests/g02/requirements.txt" | shasum -a 256 | cut -c1-12)
IMAGE="heimdall-g02-harness:$TAG"
docker image inspect -f '{{.Id}} {{.Architecture}}' "$IMAGE" > "$S/out/linux-image.txt" || exit 2
docker version -f '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}' >> "$S/out/linux-image.txt"
echo "$IMAGE" >> "$S/out/linux-image.txt"
RUN_FLAGS="--rm --platform linux/arm64 --network none --user 10001:10001 --cap-drop ALL
 --security-opt no-new-privileges --memory 2g --pids-limit 4096 -e PYTHONDONTWRITEBYTECODE=1"
# shellcheck disable=SC2086
docker run $RUN_FLAGS --mount "type=bind,src=$S,dst=/w" "$IMAGE" \
    sh -c 'uname -srm; bash --version | head -1; zsh --version; python3 --version; sh /w/probes/run_all.sh /w/out/linux /w/bin/go/linux-arm64/heimdall-proto /w/bin/rust/linux-arm64/heimdall-proto' \
    > "$S/out/linux-run_all.console.txt" 2>&1
echo "docker run_all exit=$?" > "$S/out/linux-run_all.exit.txt"
