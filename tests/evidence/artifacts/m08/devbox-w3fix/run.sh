#!/usr/bin/env bash
# M08 W3 fix-diff devbox steps at a8641372. Everything in this scratch dir; HOME and TMPDIR are scratch.
set -u
D=$(cd "$(dirname "$0")" && pwd -P)
mkdir -p "$D/home" "$D/tmp"
export HOME="$D/home" TMPDIR="$D/tmp"
unset SSH_AUTH_SOCK
cd "$D"
step() { name=$1; shift; echo "== $name"; nice -n 10 "$@" >"$D/$name.log" 2>&1; rc=$?; echo "== $name: exit $rc"; grep -E "^test |^test result|panicked|FAILED" "$D/$name.log" | sed "s#$D#<scratch>#g"; }
step r01-adoption-window "$D/runtime_lib" paired::adoption_window_tests
step r03-platform-fs "$D/runtime_lib" --exact state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation
