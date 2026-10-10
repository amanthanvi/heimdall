#!/bin/sh
# M00-T05-r4-x2-t1cal: rebuild the X2 T1 cells from the pinned base trees plus each cell's
# implementer diff, with the prototype's own build.sh, and copy the darwin-arm64 and
# linux-arm64 binaries out. One scratch copy per language (one Rust target dir).
# Usage: sh build_cells.sh <scratch-root> <repo-root> <cell>...
# <scratch-root>/<lang> must be a git repo whose only commit is the base tree
# (git archive of the pinned base commit). Writes <scratch-root>/bins/<cell>/{darwin,linux}-arm64/
# and <scratch-root>/logs/build-<cell>.log; prints one provenance line per cell.
set -u
S=$1; R=$2; shift 2
RUNS="$R/tests/evidence/artifacts/g02-r4/x2/runs"
for cell in "$@"; do
  case $cell in
    T1-go-*) lang=go ;;
    T1-rust-*) lang=rust ;;
    *) echo "unknown cell $cell" >&2; continue ;;
  esac
  patch=$(find "$RUNS/$cell" -name diff.patch | head -1)
  cd "$S/$lang" || exit 1
  git reset -q --hard && git clean -fdq
  find "prototypes/$lang" -name __pycache__ -prune -not -path '*/target/*' -exec rm -rf {} + 2>/dev/null
  if git apply --check "$patch" 2>"$S/logs/apply-$cell.err"; then
    git apply "$patch"; applied=yes
  else
    applied=no
  fi
  ( cd "prototypes/$lang" && sh build.sh >"$S/logs/build-$cell.log" 2>&1 ); brc=$?
  mkdir -p "$S/bins/$cell/darwin-arm64" "$S/bins/$cell/linux-arm64"
  cp "prototypes/$lang/dist/darwin-arm64/heimdall-proto" "$S/bins/$cell/darwin-arm64/" 2>/dev/null
  cp "prototypes/$lang/dist/linux-arm64/heimdall-proto" "$S/bins/$cell/linux-arm64/" 2>/dev/null
  d=$(shasum -a 256 "$S/bins/$cell/darwin-arm64/heimdall-proto" 2>/dev/null | cut -d' ' -f1)
  l=$(shasum -a 256 "$S/bins/$cell/linux-arm64/heimdall-proto" 2>/dev/null | cut -d' ' -f1)
  git diff --stat HEAD | tail -1 >"$S/logs/diffstat-$cell.txt"
  git add -A -N . && git diff HEAD >"$S/logs/applied-$cell.diff"
  echo "$cell applied=$applied build_exit=$brc darwin=$d linux=$l"
done
