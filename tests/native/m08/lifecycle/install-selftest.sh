#!/usr/bin/env bash
# Self-test of tools/packaging/install.sh with fake archives (m08-plan U2a:
# `install_refuses_a_tree_that_differs_from_its_manifest`,
# `install_interrupted_at_each_step_leaves_a_complete_pair`, update, rollback, a running
# runtime). No real Heimdall executable is used or run: the "executable" is a tiny script
# that prints its version and answers `service status`, so this is safe on any host.
#
# Usage: bash tests/native/m08/lifecycle/install-selftest.sh
# Exit code: 0 when every case passes; 1 otherwise. Everything lives in one mktemp
# directory, removed on exit (the exact path, never a glob).
set -u
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
T=$(mktemp -d "${TMPDIR:-/tmp}/hm-install-selftest.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
bad=0
ok() { echo "ok   $1"; }
no() { echo "FAIL $1"; bad=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

archive() { # archive NAME VERSION [RUNNING]: a fake unpacked archive at $T/NAME
    local d=$T/$1
    mkdir -p "$d"
    printf '#!/bin/sh\n# fake heimdall %s\ncase "$*" in *"service status"*) echo %s ;; *) echo "heimdall %s" ;; esac\n' \
        "$2" "'{\"running\":${3:-false}}'" "$2" >"$d/heimdall"
    chmod 0755 "$d/heimdall"
    echo "notes for $2" >"$d/README"
    cp "$repo/tools/packaging/install.sh" "$d/install.sh"
    (cd "$d" && for f in README heimdall install.sh; do printf '%s  %s\n' "$(sha "$f")" "$f"; done >MANIFEST.sha256)
}
archive a1 1.0.0
archive a2 2.0.0
archive a2run 2.0.0
archive a1run 1.0.0 true
P=$T/prefix

sh "$T/a1/install.sh" --prefix "$P" >"$T/o1" 2>&1
check "a fresh install puts the executable in place" '[ "$("$P/heimdall")" = "heimdall 1.0.0" ] && [ ! -e "$P/heimdall.previous" ]'
check "it prints the PATH line and does not edit a profile" 'grep -q "add this line to your shell profile yourself" "$T/o1"'
sh "$T/a1/install.sh" --prefix "$P" >"$T/o1b" 2>&1
check "installing the same version again changes nothing" 'grep -q "already installed" "$T/o1b" && [ ! -e "$P/heimdall.previous" ]'
sh "$T/a2/install.sh" --prefix "$P" >/dev/null 2>&1
check "an update keeps the previous executable" '[ "$("$P/heimdall")" = "heimdall 2.0.0" ] && [ "$("$P/heimdall.previous")" = "heimdall 1.0.0" ]'
sh "$T/a2/install.sh" --prefix "$P" --rollback >/dev/null 2>&1
check "a rollback swaps the two" '[ "$("$P/heimdall")" = "heimdall 1.0.0" ] && [ "$("$P/heimdall.previous")" = "heimdall 2.0.0" ]'

# A tree that differs from its manifest is refused and nothing changes.
cp -R "$T/a2" "$T/bad"; echo tampered >>"$T/bad/heimdall"
before=$(sha "$P/heimdall")
sh "$T/bad/install.sh" --prefix "$P" >"$T/ob" 2>&1; rc=$?
check "a damaged tree is refused (exit 1) and nothing changes" '[ "$rc" = 1 ] && grep -q "does not match MANIFEST" "$T/ob" && [ "$(sha "$P/heimdall")" = "$before" ]'
cp -R "$T/a2" "$T/short"; rm "$T/short/README"
sh "$T/short/install.sh" --prefix "$P" >"$T/os" 2>&1; rc=$?
check "an incomplete tree is refused" '[ "$rc" = 1 ] && grep -q "incomplete" "$T/os"'

# A running runtime refuses the update; nothing changes.
Q=$T/prefix-run
sh "$T/a1run/install.sh" --prefix "$Q" >/dev/null 2>&1
sh "$T/a2run/install.sh" --prefix "$Q" >"$T/or" 2>&1; rc=$?
check "an update is refused while a runtime runs, and says how to stop it" '[ "$rc" = 1 ] && grep -q "heimdall service stop" "$T/or" && [ "$("$Q/heimdall" x)" = "heimdall 1.0.0" ] && [ ! -e "$Q/.heimdall.new" ]'

# Interrupted after each step: the install path itself always holds a complete executable
# (the old one through step 3, the new one after step 4), and rerunning finishes the update.
for n in 1 2 3 4; do
    R=$T/prefix-int$n
    sh "$T/a1/install.sh" --prefix "$R" >/dev/null 2>&1
    HM_INSTALL_TEST_STOP_AFTER=$n sh "$T/a2/install.sh" --prefix "$R" >/dev/null 2>&1
    want="heimdall 1.0.0"; [ "$n" = 4 ] && want="heimdall 2.0.0"
    check "interrupted after step $n: the install path holds the complete $want" '[ -x "$R/heimdall" ] && [ "$("$R/heimdall")" = "$want" ]'
    sh "$T/a2/install.sh" --prefix "$R" >"$T/oi$n" 2>&1
    check "interrupted after step $n: rerunning finishes the update" '[ "$("$R/heimdall")" = "heimdall 2.0.0" ] && [ "$("$R/heimdall.previous")" = "heimdall 1.0.0" ] && [ ! -e "$R/.heimdall.new" ]'
done
# The previous copy is a second name or a copy, never the moved original: changing one
# does not empty the other, and a rollback leaves the install path populated throughout.
check "after an update both names hold complete, different executables" '[ "$("$P/heimdall")" != "$("$P/heimdall.previous")" ]'
sh "$T/a2/install.sh" --prefix "$P" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$P" --rollback >/dev/null 2>&1
check "update then rollback: the install path holds the older executable, the newer is kept" '[ "$("$P/heimdall")" = "heimdall 1.0.0" ] && [ "$("$P/heimdall.previous")" = "heimdall 2.0.0" ] && [ ! -e "$P/.heimdall.swap" ] && [ ! -e "$P/.heimdall.new" ]'
echo "install-selftest: $([ $bad = 0 ] && echo PASS || echo FAIL)"
exit $bad
