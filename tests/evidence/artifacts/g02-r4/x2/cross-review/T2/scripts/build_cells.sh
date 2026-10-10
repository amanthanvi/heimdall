#!/bin/sh
# M00-T05-r4-x2-xrev-T2: rebuild the two baselines and the six T2 cells (darwin-arm64).
#
# usage: build_cells.sh REPO SCRATCH LANG CELL...
#   REPO     repository root (holds the base commits and the cell patches)
#   SCRATCH  scratch root (one work tree per language under SCRATCH/work/<lang>)
#   LANG     go | rust
#   CELL     "base" or a T2 cell name (T2-go-opus1 ...)
#
# One scratch copy per language: the sources are reset from `git archive <base>` before
# each cell, the cell's implementer diff.patch is applied with `git apply`, and the
# prototype's own build.sh builds it (every target it builds; Rust with the repository's
# pinned cargo-zigbuild copied into target/tools/bin). Rust keeps target/ between cells
# (incremental), dist/ is removed by build.sh itself. The darwin-arm64 binary is copied to
# SCRATCH/bin/<cell>/heimdall-proto (base-<lang> for the baseline) and its sha256 printed. Offline: GOPROXY=off,
# GOFLAGS=-mod=readonly (build.sh), CARGO_NET_OFFLINE=true.
set -u
REPO=$1; SCRATCH=$2; LANG_=$3; shift 3
case $LANG_ in go) BASE=84c7665 ;; rust) BASE=001a791 ;; *) echo "lang?" >&2; exit 2 ;; esac
RUNS="$REPO/tests/evidence/artifacts/g02-r4/x2/runs"
W="$SCRATCH/work/$LANG_"
mkdir -p "$W" "$SCRATCH/bin" "$SCRATCH/logs"
export GOPROXY=off CARGO_NET_OFFLINE=true

patch_of() {
  for p in "$RUNS/$1/implementer-out/diff.patch" "$RUNS/$1/out/diff.patch"; do
    [ -f "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

for CELL in "$@"; do
  T="$W/prototypes/$LANG_"
  # reset sources: keep only target/ (Rust incremental cache); everything else from git
  if [ -d "$T" ]; then
    find "$T" -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +
  fi
  (cd "$REPO" && git archive "$BASE" "prototypes/$LANG_") | tar -x -C "$W" || { echo "archive failed" >&2; exit 1; }
  digest=$(cd "$T" && find . -path ./target -prune -o -type f -print | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-64)
  echo "[$CELL] base tree digest (excl. target) $digest"
  if [ "$CELL" != base ]; then
    P=$(patch_of "$CELL") || { echo "[$CELL] no diff.patch" >&2; exit 1; }
    (cd "$W" && git apply --whitespace=nowarn "$P"); rc=$?
    echo "[$CELL] git apply $(echo "$P" | sed "s|$REPO/||") rc=$rc"
    [ "$rc" -eq 0 ] || exit 1
  fi
  if [ "$LANG_" = rust ]; then
    mkdir -p "$T/target/tools/bin"
    [ -x "$T/target/tools/bin/cargo-zigbuild" ] || cp "$REPO/prototypes/rust/target/tools/bin/cargo-zigbuild" "$T/target/tools/bin/"
  fi
  start=$(date +%s)
  (cd "$T" && sh ./build.sh) >"$SCRATCH/logs/build-$CELL.log" 2>&1; rc=$?
  end=$(date +%s)
  echo "[$CELL] build.sh rc=$rc in $((end - start))s"
  python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print("  manifest:", {t["target"]: t["built"] for t in m["targets"]})' "$T/dist/manifest.json"
  B="$T/dist/darwin-arm64/heimdall-proto"
  NAME=$CELL; [ "$CELL" = base ] && NAME="base-$LANG_"
  if [ -f "$B" ]; then
    mkdir -p "$SCRATCH/bin/$NAME"
    cp "$B" "$SCRATCH/bin/$NAME/heimdall-proto"
    echo "[$CELL] darwin-arm64 sha256 $(shasum -a 256 "$B" | cut -c1-64)"
  else
    echo "[$CELL] NO darwin-arm64 binary"
  fi
done
