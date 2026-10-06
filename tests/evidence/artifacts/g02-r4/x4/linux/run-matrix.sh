#!/bin/bash
# Host-side driver. Usage: run-matrix.sh <spikes-dir>. Writes run-A/B/C-*.txt next to itself.
# Spike dir holds: go-spike rust-gnu rust-musl rust-keyring-gnu rust-keyring-musl (linux/arm64).
set -u
here=$(cd "$(dirname "$0")" && pwd); S=$1; IMG=hm-x4-run:bookworm-arm64
BINS="go-spike rust-gnu rust-musl rust-keyring-gnu rust-keyring-musl"
common=(--rm --network none --platform linux/arm64 --cap-drop ALL --security-opt no-new-privileges -v "$S":/spikes:ro)
docker build -q -f "$here/Dockerfile.run" -t $IMG "$here" >/dev/null
{ echo "# run A: Docker default seccomp profile; --network none --cap-drop ALL --security-opt no-new-privileges"; date -u +%FT%TZ; docker run "${common[@]}" $IMG $BINS; echo "docker_exit=$?"; } > "$here/run-A-default-seccomp.txt" 2>&1
{ echo "# run B: seccomp=unconfined (keyctl family reachable); otherwise identical to run A"; date -u +%FT%TZ; docker run "${common[@]}" --security-opt seccomp=unconfined $IMG $BINS; echo "docker_exit=$?"; } > "$here/run-B-seccomp-unconfined.txt" 2>&1
{ echo "# run C: D-Bus session bus up but no provider started; gnome-keyring is bus-activated with no initialised keyring (negative case), seccomp=unconfined"; date -u +%FT%TZ; docker run "${common[@]}" --security-opt seccomp=unconfined -e X4_NO_SS=1 $IMG $BINS; echo "docker_exit=$?"; } > "$here/run-C-no-provider.txt" 2>&1
{ echo "# run D: no D-Bus session bus at all (negative case), seccomp=unconfined"; date -u +%FT%TZ; docker run "${common[@]}" --security-opt seccomp=unconfined -e X4_NO_BUS=1 $IMG $BINS; echo "docker_exit=$?"; } > "$here/run-D-no-bus.txt" 2>&1
