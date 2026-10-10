#!/bin/sh
# Source equivalence: base + implementer diff.patch (git apply) vs base + evaluator change.patch (patch -p1).
# Usage: sh srccheck.sh <scratch-root> <repo-root> <cell>...   prints one line per cell.
set -u
S=$1; R=$2; shift 2
RUNS="$R/tests/evidence/artifacts/g02-r4/x2/runs"
for cell in "$@"; do
  case $cell in T3-go-*) lang=go; base=84c7665 ;; T3-rust-*) lang=rust; base=001a791 ;; esac
  W="$S/srccheck/$cell"; rm -rf "$W"; mkdir -p "$W/a" "$W/b"
  (cd "$R" && git archive $base prototypes/$lang) | tar -x -C "$W/a"
  (cd "$R" && git archive $base prototypes/$lang) | tar -x -C "$W/b"
  impl=$(find "$RUNS/$cell" -name diff.patch | head -1)
  chg=$(find "$RUNS/$cell" -name change.patch | head -1)
  (cd "$W/a" && git apply "$impl"); arc=$?
  # change.patch names files <x>/base/prototypes/<lang>/F and <x>/frozen/<lang>/F; rewrite to prototypes/<lang>/F
  sed -E "s#^(---|\+\+\+) [^[:space:]]*/(base/prototypes|frozen)/$lang/#\1 prototypes/$lang/#; s#^(---|\+\+\+) (base/prototypes|frozen)/$lang/#\1 prototypes/$lang/#" "$chg" > "$W/change.norm.patch"
  (cd "$W/b" && patch -s -p0 -E < "$W/change.norm.patch" >"$W/patch.out" 2>&1); prc=$?
  diff -r "$W/a" "$W/b" > "$W/diff-r.txt" 2>&1; drc=$?
  echo "$cell git_apply_impl=$arc patch_change=$prc diff_r_exit=$drc diff_lines=$(wc -l < "$W/diff-r.txt" | tr -d ' ')"
done
