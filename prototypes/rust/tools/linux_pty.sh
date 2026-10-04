#!/bin/sh
# Run tests/pty_tui.py against a Linux binary in a digest-pinned python image (round 2).
# Usage: tools/linux_pty.sh <arch> <binary path inside repo> [panic-binary path inside repo]
# --pull never (image must be present), --network none, repo mounted read-only.
# HP_PTY_ONLY (round 3b): case-name filter passed through to pty_tui.py.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd -P)
arch=$1; bin=$2; pbin=${3:-}
IMG="${HP_LINUX_PTY_IMAGE:-python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed}"
set -- python3 /repo/prototypes/rust/tests/pty_tui.py "/repo/$bin"
[ -n "$pbin" ] && set -- "$@" --panic-binary "/repo/$pbin"
exec docker run --rm --pull never --platform "linux/$arch" --network none \
  -e PYTHONDONTWRITEBYTECODE=1 ${HP_PTY_ONLY:+-e "HP_PTY_ONLY=$HP_PTY_ONLY"} -v "$REPO:/repo:ro" "$IMG" "$@"
