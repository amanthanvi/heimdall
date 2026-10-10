#!/bin/sh
# Run each subject tree's own unit tests (Go: go test -count=1 ./...; Rust: cargo test --locked --no-fail-fast)
# in the per-language scratch copy, sequentially, and record exit code and failing test names.
# Usage: unit-tests.sh <scratch-root> <repo-root> <subject> [<subject> ...]
# Subjects are directories under <scratch-root>/src (cells and their .seed/.nocheck mutants).
set -u
S=$1
R=$2
shift 2
OUT="$S/logs/unit-results.tsv"
[ -f "$OUT" ] || printf 'subject\trc\tseconds\tfailed_tests\n' > "$OUT"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly CARGO_NET_OFFLINE=true
export HEIMDALL_G02_FIXTURES="$R/tests/fixtures/g02/profiles"
unset SSH_AUTH_SOCK
for subj in "$@"; do
  case $subj in *-go*) lang=go ;; *) lang=rust ;; esac
  W="$S/work/$lang"
  rsync -a --delete --exclude /target/ --exclude /dist/ "$S/src/$subj/" "$W/"
  find "$W" -path "$W/target" -prune -o -type f -exec touch {} +
  if [ "$lang" = go ]; then
    T="$S/tmp-tests/$subj"
    rm -rf "$T"; mkdir -p "$T"
  else
    # Rust's cli tests bind AF_UNIX sockets under TMPDIR: the scratch path exceeds SUN_LEN
    # (observed: "path must be shorter than SUN_LEN"), so use a short directory of our own.
    T=$(mktemp -d /tmp/hmx4u-XXXXXX) || exit 1
  fi
  log="$S/logs/unit-$subj.log"
  start=$(date +%s)
  if [ "$lang" = go ]; then
    (cd "$W" && TMPDIR="$T" go test -count=1 ./...) > "$log" 2>&1
    rc=$?
    failed=$(grep -E '^\s*--- FAIL: ' "$log" | sed -E 's/^\s*--- FAIL: ([^ ]+).*/\1/' | sort -u | tr '\n' ' ')
  else
    (cd "$W" && TMPDIR="$T" cargo test --locked --no-fail-fast) > "$log" 2>&1
    rc=$?
    failed=$(grep -E '^test .* \.\.\. FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | sort -u | tr '\n' ' ')
    if grep -q -E '^error\[E[0-9]+\]|^error: could not compile' "$log"; then failed="COMPILE_ERROR $failed"; fi
  fi
  end=$(date +%s)
  printf '%s\t%s\t%s\t%s\n' "$subj" "$rc" "$((end - start))" "${failed:-none}" >> "$OUT"
  rm -rf "$T"
  echo "done $subj rc=$rc" >&2
done
