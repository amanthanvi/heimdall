#!/bin/sh
# M00-T05-r4-x2-xrev-T3: rebuild the X2 T3 baselines and cells from the pinned base trees plus each
# cell's implementer diff (git apply), with the prototype's own build.sh, and copy the darwin-arm64
# binary out. One scratch copy per language; reset between cells (target/ and dist/ are excluded
# from git, so the Rust target dir is reused).
# Usage: sh build_cells.sh <scratch-root> <repo-root> <cell|base-go|base-rust>...
# <scratch-root>/<lang> must be a git repo whose only commit is the base tree (git archive of the
# pinned base commit). Writes <scratch-root>/bins/<cell>/heimdall-proto and
# <scratch-root>/logs/{build,apply}-<cell>.*; prints one provenance line per cell.
set -u
S=$1; R=$2; shift 2
RUNS="$R/tests/evidence/artifacts/g02-r4/x2/runs"
for cell in "$@"; do
  case $cell in
    T3-go-*|base-go) lang=go ;;
    T3-rust-*|base-rust) lang=rust ;;
    *) echo "unknown cell $cell" >&2; continue ;;
  esac
  cd "$S/$lang" || exit 1
  git reset -q --hard && git clean -fdq
  find "prototypes/$lang" -name __pycache__ -prune -not -path '*/target/*' -exec rm -rf {} + 2>/dev/null
  applied=base; patch=-
  case $cell in
    T3-*)
      patch=$(find "$RUNS/$cell" -name diff.patch | head -1)
      if git apply --check "$patch" 2>"$S/logs/apply-$cell.err"; then
        git apply "$patch"; applied=yes
      else
        applied=no
      fi ;;
  esac
  if [ "$lang" = rust ]; then
    mkdir -p prototypes/rust/target/tools/bin
    [ -x prototypes/rust/target/tools/bin/cargo-zigbuild ] || cp "$R/prototypes/rust/target/tools/bin/cargo-zigbuild" prototypes/rust/target/tools/bin/
  fi
  t0=$(date +%s)
  ( cd "prototypes/$lang" && sh build.sh >"$S/logs/build-$cell.log" 2>&1 ); brc=$?
  t1=$(date +%s)
  mkdir -p "$S/bins/$cell"
  cp "prototypes/$lang/dist/darwin-arm64/heimdall-proto" "$S/bins/$cell/" 2>/dev/null
  cp "prototypes/$lang/dist/manifest.json" "$S/logs/manifest-$cell.json" 2>/dev/null
  d=$(shasum -a 256 "$S/bins/$cell/heimdall-proto" 2>/dev/null | cut -d' ' -f1)
  git add -A -N . && git diff HEAD -- . ':!prototypes/*/target' ':!prototypes/*/dist' >"$S/logs/applied-$cell.diff"
  git reset -q
  echo "$cell lang=$lang patch=${patch#$R/} applied=$applied build_exit=$brc secs=$((t1-t0)) darwin-arm64=$d"
done
