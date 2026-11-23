#!/usr/bin/env bash
# Run the lifecycle journey of journey.sh for release archives, inside the M08 container
# (m08-plan U2a). The only way this script starts a release build is in that container.
#
# Usage: bash tests/native/m08/lifecycle/run-journey.sh --dir <release-artifacts dir>
#            --old <archive name> --new <archive name> [--kill-before-update]
#   --dir holds the archives and the external SHA256SUMS (target/release-artifacts).
# Exit code: the journey's (0 no step failed; 1 a step failed; 2 refused or setup error).
# The container: no network, 2 CPUs, 2 GiB; the repository and the archives read-only; one
# capped container at a time on this machine. Output is printed; nothing is kept.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
image=hm-m08-soak:1
dir=""; old=""; new=""; extra=()
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) dir=$2; shift 2 ;;
        --old) old=$2; shift 2 ;;
        --new) new=$2; shift 2 ;;
        --kill-before-update) extra+=(--kill-before-update); shift ;;
        *) sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
[ -n "$dir" ] && [ -f "$dir/SHA256SUMS" ] && [ -f "$dir/$old" ] && [ -f "$dir/$new" ] ||
    { echo "run-journey: --dir must hold SHA256SUMS and both archives" >&2; exit 2; }
dir=$(cd "$dir" && pwd -P)
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$repo/tools/benchmarks/m08" >/dev/null
exec docker run --rm --init --network none --cpus 2 --memory 2g --pids-limit 512 \
    -v "$repo":/src:ro -v "$dir":/a:ro "$image" \
    runuser -u soaks -- bash /src/tests/native/m08/lifecycle/journey.sh --build release \
    --index /a/SHA256SUMS --old "/a/$old" --new "/a/$new" ${extra[@]+"${extra[@]}"}
