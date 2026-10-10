#!/bin/sh
# M00-T05-r4-x2-xrev-T3-verify: rebuild the X2 T3 baselines and cells for the real-terminal check.
# Base trees are `git archive` copies of the pinned base commits (Go 84c7665, Rust 001a791), each
# committed once into a scratch git repo so that `git apply` and `git reset --hard` work. Each
# cell's implementer diff.patch is applied and the tree is built with the prototype's own build.sh.
# For Rust, the repository's target/tools/bin/cargo-zigbuild is copied into the scratch target dir.
# Usage: sh build_verify.sh <scratch-root> <repo-root> <build>...
#   <build>: base-go | base-rust | T3-go-opus1 | T3-go-opus2 | T3-go-sonnet1 | T3-rust-opus1 | ...
# Writes <scratch>/bins/<build>/heimdall-proto, <scratch>/logs/*, and prints one provenance line.
set -u
S=$1; R=$2; shift 2
RUNS="$R/tests/evidence/artifacts/g02-r4/x2/runs"
mkdir -p "$S/logs" "$S/bins"

ensure_base() {   # ensure_base <lang> <commit>
  lang=$1; c=$2; d="$S/$lang"
  if [ ! -d "$d/.git" ]; then
    mkdir -p "$d"
    (cd "$R" && git archive "$c" "prototypes/$lang") | tar -x -C "$d" || return 1
    (cd "$d" && git init -q && git add -A \
      && git -c user.name=verify -c user.email=verify@localhost commit -q -m "base $c prototypes/$lang") || return 1
    # tree digest, BASE.json method: sha256 over "sha256  path" lines of every file, sorted by path
    (cd "$d" && find "prototypes/$lang" -type f | LC_ALL=C sort | while read -r f; do
        printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done | shasum -a 256 | cut -d' ' -f1) \
      > "$S/logs/tree-digest-$lang.txt"
  fi
}

for b in "$@"; do
  case $b in
    base-go|T3-go-*) lang=go; commit=84c7665 ;;
    base-rust|T3-rust-*) lang=rust; commit=001a791 ;;
    *) echo "unknown build $b" >&2; continue ;;
  esac
  ensure_base "$lang" "$commit" || { echo "$b: base tree setup failed" >&2; continue; }
  cd "$S/$lang" || exit 1
  git reset -q --hard && git clean -fdq
  find "prototypes/$lang" -name __pycache__ -prune -not -path '*/target/*' -exec rm -rf {} + 2>/dev/null
  applied=base; patch=-; psha=-
  case $b in
    T3-*)
      patch=$(find "$RUNS/$b" -name diff.patch | head -1)
      psha=$(shasum -a 256 "$patch" | cut -d' ' -f1)
      if git apply --check "$patch" 2>"$S/logs/apply-$b.err"; then
        git apply "$patch" && applied=yes || applied=failed
      else
        applied=no
      fi ;;
  esac
  if [ "$lang" = rust ]; then
    mkdir -p prototypes/rust/target/tools/bin
    [ -x prototypes/rust/target/tools/bin/cargo-zigbuild ] || cp "$R/prototypes/rust/target/tools/bin/cargo-zigbuild" prototypes/rust/target/tools/bin/
  fi
  t0=$(date +%s)
  ( cd "prototypes/$lang" && sh build.sh >"$S/logs/build-$b.log" 2>&1 ); brc=$?
  t1=$(date +%s)
  mkdir -p "$S/bins/$b"
  cp "prototypes/$lang/dist/darwin-arm64/heimdall-proto" "$S/bins/$b/" 2>/dev/null
  cp "prototypes/$lang/dist/manifest.json" "$S/logs/manifest-$b.json" 2>/dev/null
  d=$(shasum -a 256 "$S/bins/$b/heimdall-proto" 2>/dev/null | cut -d' ' -f1)
  sz=$(wc -c <"$S/bins/$b/heimdall-proto" 2>/dev/null | tr -d ' ')
  git reset -q
  if [ "$lang" = go ]; then tc=$(go version | awk '{print $3}'); else tc=$(rustc --version | awk '{print "rustc", $2}'); fi
  echo "$b lang=$lang patch=${patch#$R/} patch_sha256=$psha applied=$applied build_exit=$brc secs=$((t1-t0)) toolchain=$tc darwin-arm64_bytes=$sz darwin-arm64_sha256=$d"
done
