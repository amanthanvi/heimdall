#!/usr/bin/env bash
# Self-test of tools/packaging/install.sh with fake archives (m08-plan U2a:
# `install_refuses_a_tree_that_differs_from_its_manifest`,
# `install_interrupted_at_each_step_leaves_a_complete_pair`, update, rollback, a running
# runtime). No real Heimdall executable is used or run: the "executable" is a tiny script
# that prints its version and answers `service status`, so this is safe on any host.
#
# Usage: bash tests/native/m08/lifecycle/install-selftest.sh
#   HM_INSTALL_UNDER_TEST=<file>  test that copy of install.sh instead (for a revert proof)
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

# The script under test. HM_INSTALL_UNDER_TEST lets a revert proof point this self-test at a
# copy of install.sh with one fix taken out.
SUT=${HM_INSTALL_UNDER_TEST:-$repo/tools/packaging/install.sh}
NONE='{"schema_version":"1","state":"failed","code":"SERVICE_UNAVAILABLE","data":{"error":{"code":"SERVICE_UNAVAILABLE","effect_status":"none","message":"no runtime is running","retryable":true}}}'
RUNNING='{"schema_version":"1","state":"succeeded","code":"OK","data":{"running":true,"pid":4242}}'
UNREACHABLE='{"schema_version":"1","state":"failed","code":"SERVICE_UNAVAILABLE","data":{"error":{"code":"SERVICE_UNAVAILABLE","message":"the runtime did not answer"}}}'
archive() { # archive NAME VERSION [none|running|unreachable|silent]: a fake unpacked archive at $T/NAME
    local d=$T/$1 answer
    case "${3:-none}" in none) answer=$NONE ;; running) answer=$RUNNING ;; unreachable) answer=$UNREACHABLE ;; silent) answer="" ;; esac
    mkdir -p "$d"
    printf '#!/bin/sh\n# fake heimdall %s\ncase "$*" in *"service status"*) echo %s ;; *) echo "heimdall %s" ;; esac\n' \
        "$2" "'$answer'" "$2" >"$d/heimdall"
    chmod 0755 "$d/heimdall"
    echo "notes for $2" >"$d/README"
    cp "$SUT" "$d/install.sh"
    (cd "$d" && for f in README heimdall install.sh; do printf '%s  %s\n' "$(sha "$f")" "$f"; done >MANIFEST.sha256)
}
archive a1 1.0.0
archive a2 2.0.0
archive a2run 2.0.0
archive a1run 1.0.0 running
archive a3 3.0.0
archive a1unreach 1.0.0 unreachable
archive a1silent 1.0.0 silent
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

# --- Review M08-W0-R01: the current executable could not be kept (the hard link is refused
# and the copy fails, as on a full disk). The update must stop BEFORE the replace.
SH=$T/shims; mkdir -p "$SH"
printf '#!/bin/sh\nexit 1\n' >"$SH/ln"
printf '#!/bin/sh\n# fails for a destination ending in .tmp, as a full disk would\nfor a in "$@"; do last=$a; done\ncase "$last" in *.tmp) echo "cp: simulated ENOSPC" >&2; exit 1 ;; esac\nexec /bin/cp "$@"\n' >"$SH/cp"
chmod 0755 "$SH/ln" "$SH/cp"
K=$T/prefix-keep
sh "$T/a1/install.sh" --prefix "$K" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$K" >/dev/null 2>&1
PATH="$SH:$PATH" sh "$T/a3/install.sh" --prefix "$K" >"$T/ok" 2>&1; rc=$?
echo "     R01 case observed: exit $rc, cur=$("$K/heimdall"), prev=$("$K/heimdall.previous")"
check "R01: a failed backup stops the update before the replace (exit 1, cur 2.0.0, prev 1.0.0, nothing staged)" \
    '[ "$rc" = 1 ] && [ "$("$K/heimdall")" = "heimdall 2.0.0" ] && [ "$("$K/heimdall.previous")" = "heimdall 1.0.0" ] && grep -q "could not keep" "$T/ok" && ! grep -q "is kept as" "$T/ok" && [ ! -e "$K/.heimdall.new" ] && [ ! -e "$K/heimdall.previous.tmp" ]'

# --- R02: staging names that are not ordinary files.
L=$T/prefix-link
sh "$T/a1/install.sh" --prefix "$L" >/dev/null 2>&1
ln -s "$T/victim" "$L/.heimdall.new"
sh "$T/a2/install.sh" --prefix "$L" >"$T/ol" 2>&1; rc=$?
check "R02: a dangling symlink at the staging name is removed, never written through" \
    '[ "$rc" = 0 ] && [ ! -e "$T/victim" ] && [ ! -L "$L/heimdall" ] && [ -f "$L/heimdall" ] && [ "$("$L/heimdall")" = "heimdall 2.0.0" ]'
L2=$T/prefix-link2
sh "$T/a1/install.sh" --prefix "$L2" >/dev/null 2>&1
echo untouched >"$T/victim2"; ln -s "$T/victim2" "$L2/heimdall.previous.tmp"; ln -s "$T/victim2" "$L2/.heimdall.swap"
sh "$T/a2/install.sh" --prefix "$L2" >/dev/null 2>&1
check "R02: symlinks at the other staging names leave their target untouched" '[ "$(cat "$T/victim2")" = untouched ] && [ ! -L "$L2/heimdall.previous" ]'
L3=$T/prefix-link3
mkdir -p "$L3"; echo real >"$T/elsewhere"; ln -s "$T/elsewhere" "$L3/heimdall"
sh "$T/a2/install.sh" --prefix "$L3" >"$T/ol3" 2>&1; rc=$?
check "R02: a symbolic link at the install path is refused and left alone" '[ "$rc" = 1 ] && grep -q "symbolic link" "$T/ol3" && [ "$(cat "$T/elsewhere")" = real ]'
L4=$T/prefix-dir
sh "$T/a1/install.sh" --prefix "$L4" >/dev/null 2>&1
mkdir "$L4/heimdall.previous"
sh "$T/a2/install.sh" --prefix "$L4" >"$T/ol4" 2>&1; rc=$?
check "R10: a directory at heimdall.previous is refused, and nothing is claimed kept" '[ "$rc" = 1 ] && grep -q "is a directory" "$T/ol4" && [ "$("$L4/heimdall")" = "heimdall 1.0.0" ]'

# --- R03: a manifest whose last line has no newline still has that line checked.
cp -R "$T/a2" "$T/nonl"
printf '%s  %s\n%s  %s' "$(sha "$T/nonl/heimdall")" heimdall "$(sha "$T/nonl/README")" README >"$T/nonl/MANIFEST.sha256"
echo tampered >>"$T/nonl/README"
sh "$T/nonl/install.sh" --prefix "$T/prefix-nonl" >"$T/on" 2>&1; rc=$?
check "R03: a tampered file named on an unterminated last manifest line is refused" '[ "$rc" = 1 ] && grep -q "README does not match" "$T/on" && [ ! -e "$T/prefix-nonl/heimdall" ]'

# --- R04: the runtime guard fails closed when it cannot tell.
U=$T/prefix-unreach
sh "$T/a1unreach/install.sh" --prefix "$U" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$U" >"$T/ou" 2>&1; rc=$?
check "R04: an advertised runtime that does not answer refuses the update, with a next action" '[ "$rc" = 1 ] && grep -q "cannot tell whether a Heimdall runtime is running" "$T/ou" && grep -q "heimdall service stop" "$T/ou" && [ "$("$U/heimdall")" = "heimdall 1.0.0" ] && [ ! -e "$U/.heimdall.new" ]'
V=$T/prefix-silent
sh "$T/a1silent/install.sh" --prefix "$V" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$V" >"$T/ov" 2>&1; rc=$?
check "R04: an installed executable that says nothing refuses the update too" '[ "$rc" = 1 ] && [ "$("$V/heimdall")" = "heimdall 1.0.0" ]'
sh "$T/a2/install.sh" --prefix "$V" --assume-stopped >"$T/ov2" 2>&1; rc=$?
check "R04: --assume-stopped is the stated way past a broken executable" '[ "$rc" = 0 ] && [ "$("$V/heimdall")" = "heimdall 2.0.0" ] && grep -q "assume-stopped" "$T/ov2"'
check "R04: the plain not-running answer (also given for a stale advertisement after a crash) lets the update proceed" '[ "$("$P/heimdall")" = "heimdall 1.0.0" ] && sh "$T/a2/install.sh" --prefix "$P" >/dev/null 2>&1 && [ "$("$P/heimdall")" = "heimdall 2.0.0" ]'

# --- R09: a rollback interrupted between its rename and its last step loses nothing.
B=$T/prefix-rb
sh "$T/a1/install.sh" --prefix "$B" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$B" >/dev/null 2>&1
HM_INSTALL_TEST_STOP_AFTER=r2 sh "$T/a2/install.sh" --prefix "$B" --rollback >/dev/null 2>&1
check "an interrupted rollback: the install path holds the older executable" '[ "$("$B/heimdall")" = "heimdall 1.0.0" ]'
sh "$T/a1/install.sh" --prefix "$B" >"$T/orb" 2>&1
check "an interrupted rollback: the next run keeps the newer executable as the previous one" '[ "$("$B/heimdall.previous")" = "heimdall 2.0.0" ] && [ ! -e "$B/.heimdall.swap" ] && grep -q "finished an interrupted rollback" "$T/orb"'

# --- Re-check M08-W01-R04: a rollback interrupted BEFORE its replace loses nothing either.
B1=$T/prefix-rb1
sh "$T/a1/install.sh" --prefix "$B1" >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$B1" >/dev/null 2>&1
HM_INSTALL_TEST_STOP_AFTER=r1 sh "$T/a2/install.sh" --prefix "$B1" --rollback >/dev/null 2>&1
sh "$T/a2/install.sh" --prefix "$B1" >"$T/orb1" 2>&1
check "a rollback interrupted before its replace: the rerun keeps v2 current and v1 as the previous one" '[ "$("$B1/heimdall")" = "heimdall 2.0.0" ] && [ "$("$B1/heimdall.previous")" = "heimdall 1.0.0" ] && [ ! -e "$B1/.heimdall.swap" ] && [ ! -e "$B1/.heimdall.new" ] && grep -q "had not replaced anything yet" "$T/orb1"'

# --- Re-check on R04: "no runtime is running" is not believed while a process started from
# the installed executable is alive (the product says that for an unreachable endpoint too).
A=$T/prefix-alive
sh "$T/a1/install.sh" --prefix "$A" >/dev/null 2>&1
printf '#!/bin/sh\n# fake heimdall 1.0.0 that also stays alive\ncase "$*" in *"service status"*) echo %s ;; *stay*) sleep 30 ;; *) echo "heimdall 1.0.0" ;; esac\n' "'$NONE'" >"$A/heimdall"
"$A/heimdall" stay &
alive=$!
sleep 1
sh "$T/a2/install.sh" --prefix "$A" >"$T/oa" 2>&1; rc=$?
check "a live process from the installed path refuses the update although status says none" '[ "$rc" = 1 ] && grep -q "a process started from" "$T/oa" && [ ! -e "$A/.heimdall.new" ] && [ ! -e "$A/heimdall.previous" ]'
sh "$T/a2/install.sh" --prefix "$A" --assume-stopped >"$T/oa2" 2>&1; rc=$?
check "--assume-stopped does not override a live process" '[ "$rc" = 1 ] && grep -q "does not override" "$T/oa2"'
kill "$alive" 2>/dev/null; wait "$alive" 2>/dev/null
sh "$T/a2/install.sh" --prefix "$A" >/dev/null 2>&1; rc=$?
check "once that process has ended, the update proceeds" '[ "$rc" = 0 ] && [ "$("$A/heimdall")" = "heimdall 2.0.0" ]'

# --- W0.3: a manifest name that is not a plain relative path is refused before any write.
echo outside >"$T/outside.txt"
for badname in "../outside.txt" "/etc/hosts" "sub//x" "./README" 'a\\b' "c:x"; do
    cp -R "$T/a2" "$T/mn"; printf '%s  %s\n' "$(sha "$T/outside.txt")" "$badname" >>"$T/mn/MANIFEST.sha256"
    sh "$T/mn/install.sh" --prefix "$T/prefix-mn" >"$T/omn" 2>&1; rc=$?
    check "a manifest naming '$badname' is refused, nothing written" '[ "$rc" = 1 ] && grep -q "will not use" "$T/omn" && [ ! -e "$T/prefix-mn/heimdall" ] && [ "$(cat "$T/outside.txt")" = outside ]'
    rm -rf "$T/mn"
done

# --- R10: a prefix that looks like an option.
(cd "$T" && mkdir dash && cd dash && sh "$T/a1/install.sh" --prefix -x >"$T/od" 2>&1); rc=$?
check "R10: a prefix beginning with a dash is a directory, not an option" '[ "$rc" = 0 ] && [ "$("$T/dash/-x/heimdall")" = "heimdall 1.0.0" ]'

echo "install-selftest: $([ $bad = 0 ] && echo PASS || echo FAIL)"
exit $bad
