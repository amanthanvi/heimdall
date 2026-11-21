#!/usr/bin/env bash
# E8 vs E9 (and an E9 rebuild as a control): build the lock run's binaries in ONE scratch worktree path,
# keep copies in /tmp/hm-w6/lockid/bins/<tag>/ for a section-level comparison.
set -u
repo=<repo>
out=/tmp/hm-w6/lockid
mkdir -p "$out/bins"
base=$(mktemp -d /tmp/hm-lockid-XXXXXX)
wt="$base/wt"
echo "worktree=$wt" >"$out/run2.txt"
git -C "$repo" worktree add -q --detach "$wt" 7b75c4c12e925bf4049f67d10ce58ff3b63559e7 || exit 2
build() {
  local tag=$1
  ( cd "$wt" && cargo build -p heimdall --bin heimdall --locked >"$out/$tag-build-bin.log" 2>&1 &&
    cargo test -p heimdall --test e2e_exit_m03 -p heimdall-runtime --test integration_session_lock \
      --no-run --locked --message-format=json-render-diagnostics >"$out/$tag-build.json" 2>"$out/$tag-build.log" )
  local rc=$?
  echo "$tag build exit=$rc commit=$(git -C "$wt" rev-parse HEAD)" >>"$out/run2.txt"
  [ "$rc" = 0 ] || return "$rc"
  local driver signal
  driver=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "e2e_exit_m03" and .executable != null) | .executable' "$out/$tag-build.json" | tail -1)
  signal=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "integration_session_lock" and .executable != null) | .executable' "$out/$tag-build.json" | tail -1)
  mkdir -p "$out/bins/$tag"
  cp "$wt/target/debug/heimdall" "$out/bins/$tag/heimdall"
  cp "$driver" "$out/bins/$tag/e2e_exit_m03"
  cp "$signal" "$out/bins/$tag/integration_session_lock"
}
build e8
git -C "$wt" checkout -q --detach 2b79aac1b6bea72f886cef2331c9e3b5d0a123e8 && build e9
# Control: the same E9 tree rebuilt after its sources are touched (new object timestamps).
touch "$wt/crates/app/src/lib.rs" "$wt/tests/e2e/exit_m03.rs" "$wt/tests/integration/session_lock.rs" 2>/dev/null
build e9b
git -C "$repo" worktree remove --force "$wt" && rmdir "$base" && echo "removed $base" >>"$out/run2.txt"
git -C "$repo" worktree prune
echo DONE >>"$out/run2.txt"
