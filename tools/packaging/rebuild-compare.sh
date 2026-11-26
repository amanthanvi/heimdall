#!/usr/bin/env bash
# Usage: bash tools/packaging/rebuild-compare.sh TARGET [--commit REF] [--features LIST] [--offline] [--candidate]
# Builds the same commit through build-release.sh in two clean checkouts, each with its own ./target.
# Writes target/rebuild-compare/TARGET-COMMIT.json. Exit 0 on equality, 1 on difference,
# or 2 if the comparison could not complete. No release executable is run.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repo"
usage() { sed -n '2,5p' tools/packaging/rebuild-compare.sh | sed 's/^# //' >&2; exit 2; }
target=${1:-}
case "$target" in
    aarch64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-unknown-linux-gnu) shift ;;
    *) usage ;;
esac
ref=HEAD
features=""
args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --commit) [ "$#" -ge 2 ] || usage; ref=$2; shift 2 ;;
        --features) [ "$#" -ge 2 ] || usage; features=$2; shift 2 ;;
        --offline|--candidate) args+=("$1"); shift ;;
        *) usage ;;
    esac
done
[ -z "$features" ] || args+=(--features "$features")
commit=$(git rev-parse --verify --end-of-options "$ref^{commit}") || exit 2
version=$(git show "$commit:Cargo.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | sed -n '1p')
[ -n "$version" ] || { echo "rebuild-compare: no workspace version" >&2; exit 2; }
archive="target/release-artifacts/heimdall-$version-$target.tar.gz"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
record="target/rebuild-compare/$target-$commit.json"
mkdir -p target/rebuild-compare
tool="$repo/target/tools/bin/cargo-cyclonedx"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/hm-rebuild.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 2' HUP INT TERM
first="$scratch/one"
second="$scratch/another/two"

build() {
    local checkout=$1
    git clone --quiet --shared --no-checkout -- "$repo" "$checkout" &&
        git -C "$checkout" -c advice.detachedHead=false checkout --quiet --detach "$commit" &&
        mkdir -p "$checkout/target/tools/bin" &&
        cp -- "$tool" "$checkout/target/tools/bin/cargo-cyclonedx" &&
        (cd "$checkout" && bash tools/packaging/build-release.sh "$target" ${args[@]+"${args[@]}"})
}

first_exit=0
second_exit=0
build "$first" || first_exit=$?
build "$second" || second_exit=$?
python3 -I tools/packaging/rebuild_compare.py "$first/$archive" "$second/$archive" \
    "$target" "$commit" "$started" "$record" "$first_exit" "$second_exit"
