#!/bin/sh
# Build the six T4 cell source trees: seeded tree + the implementer's diff.patch (git apply -p3),
# and cross-check against the evaluator's change.patch (headers rewritten, patch -p1) with diff -r.
# Usage: prepare-trees.sh <scratch-root> <repo-root>
# <scratch-root>/src/seeded-{go,rust} must already exist (copies of seeded-trees/{go,rust}).
set -u
S=$1
R=$2
RUNS="$R/tests/evidence/artifacts/g02-r4/x2/runs"
rc_all=0
for cell in T4-go-opus1 T4-go-opus2 T4-go-sonnet1 T4-rust-opus1 T4-rust-opus2 T4-rust-sonnet1; do
  lang=$(echo "$cell" | cut -d- -f2)
  d="$RUNS/$cell"
  if [ -f "$d/implementer-out/diff.patch" ]; then ip="$d/implementer-out/diff.patch"; else ip="$d/implementer/diff.patch"; fi
  if [ -f "$d/eval/change.patch" ]; then cp_="$d/eval/change.patch"; else cp_="$d/change.patch"; fi
  rm -rf "$S/src/$cell" "$S/src/$cell.evalcheck"
  cp -R "$S/src/seeded-$lang" "$S/src/$cell"
  cp -R "$S/src/seeded-$lang" "$S/src/$cell.evalcheck"
  (cd "$S/src/$cell" && git apply -p3 --whitespace=nowarn "$ip"); a=$?
  # evaluator patch: '--- <x>/base/prototypes/<lang>/F <ts>' and '+++ <x>/frozen/<lang>/F <ts>'
  sed -E -e "s#^--- .*base/prototypes/$lang/([^	]*).*#--- a/\1#" \
         -e "s#^\+\+\+ .*frozen/$lang/([^	]*).*#+++ b/\1#" \
         -e "s#^diff .*#diff#" "$cp_" > "$S/logs/$cell.change.rewritten.patch"
  (cd "$S/src/$cell.evalcheck" && patch -s -p1 < "$S/logs/$cell.change.rewritten.patch"); b=$?
  diff -r "$S/src/$cell" "$S/src/$cell.evalcheck" > "$S/logs/$cell.evalcheck.diff"; c=$?
  digest=$(cd "$S/src/$cell" && find . -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | awk '{print $1}')
  printf '%s\tgit_apply_rc=%s\tchange_patch_rc=%s\tdiff_r_rc=%s\ttree_digest=%s\n' "$cell" "$a" "$b" "$c" "$digest"
  [ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ] || rc_all=1
  rm -rf "$S/src/$cell.evalcheck"
done
exit $rc_all
