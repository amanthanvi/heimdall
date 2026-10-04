#!/bin/sh
# Run the cross-built native test executables and the dist binary in a Linux container
# (round 2). Usage: tools/linux_tests.sh <arch: arm64|amd64> <rust triple> <dist target> [binary-override]
#   binary-override: path (inside the repo) of the heimdall-proto binary under test,
#   e.g. a round-1 binary for a red proof; default dist/<dist target>/heimdall-proto.
# HP_TEST_ONLY: substring filter on test executable paths; HP_TEST_ARGS: arguments for
# them (default --test-threads=4). Images are pinned by digest and must already be present locally (--pull never).
# Fixtures come from HEIMDALL_G02_FIXTURES, so no path symlink is needed. --network none.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
REPO=$(CDPATH= cd -- "$HERE/../.." && pwd -P)
arch=$1; triple=$2; dt=$3
bin=${4:-prototypes/rust/dist/$dt/heimdall-proto}
IMG="${HP_LINUX_TEST_IMAGE:-debian:bookworm-slim@sha256:0c8bbb8e987a035fe1d9704eb2e571b7e9a836e1caa46345290674b45b69e417}"
list="$HERE/target/tests-$triple.txt"
bins=$(sed "s#^$REPO#/repo#" "$list" | grep -F -- "${HP_TEST_ONLY:-/}" | tr '\n' ' ')
ARGS=${HP_TEST_ARGS:---test-threads=4}
exec docker run --rm --pull never --platform "linux/$arch" --network none \
  -v "$REPO:/repo:ro" \
  -e HEIMDALL_G02_FIXTURES=/repo/tests/fixtures/g02/profiles \
  -e "HEIMDALL_PROTO_BIN=/repo/$bin" \
  "$IMG" sh -c 'uname -m; rc=0; for b in '"$bins"'; do echo "## $b"; "$b" '"$ARGS"' || rc=$?; done; exit $rc'
