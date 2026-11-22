#!/bin/sh
# Install or update Heimdall for the current user (m08-plan U2a; ADR-0014 section 4.3).
#
# Usage, from inside the unpacked archive:
#   ./install.sh                 install, or update an existing install
#   ./install.sh --rollback      put the previous executable back
#   ./install.sh --prefix DIR    install into DIR (default: $HOME/.local/bin)
# Exit code: 0 done; 1 refused or failed (nothing half-done is left without a message
# saying what is in place); 2 usage.
#
# BEFORE YOU RUN THIS: check the archive against SHA256SUMS from the Heimdall repository
# (docs/operations/install.md). This script cannot do that for you: a replaced archive
# would carry a replaced script. What it does check is that the unpacked files match the
# archive's own MANIFEST.sha256, which catches a damaged or partial extraction.
#
# What it does: copies the executable to a fixed per-user location and prints the line you
# may add to your PATH. It needs no administrator rights. It does not edit your PATH, your
# shell profile or ~/.ssh, starts nothing, and contacts nothing. `heimdall setup` is a
# separate step that shows every change and asks.
#
# Updating: the runtime must be stopped first (`heimdall service stop`); this script
# refuses while one is running and tells you so. The current executable is kept as
# `heimdall.previous`. The replacement is staged: the new file is copied beside the old one
# and checked, the old one is linked (or copied) to `heimdall.previous`, and one rename puts
# the new one in place. The install path therefore holds a complete executable at every
# moment, the old one or the new one, and running the script again finishes an interrupted
# update.
set -eu

here=$(cd "$(dirname "$0")" && pwd -P)
prefix="${HOME}/.local/bin"
mode=install
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || { echo "install: --prefix needs a directory" >&2; exit 2; }; prefix=$2; shift 2 ;;
        --rollback) mode=rollback; shift ;;
        *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
say() { printf 'install: %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
# The interruption test stops the script after a numbered step (HM_INSTALL_TEST_STOP_AFTER).
step_done() { if [ "${HM_INSTALL_TEST_STOP_AFTER:-}" = "$1" ]; then say "stopped after step $1 (test)"; exit 1; fi; }

cur="$prefix/heimdall"
prev="$prefix/heimdall.previous"
new="$prefix/.heimdall.new"

running() {
    # Is a runtime of the installed executable running? `service status` never starts one.
    [ -x "$cur" ] || return 1
    "$cur" --json --non-interactive service status 2>/dev/null | grep -q '"running":true'
}

if [ "$mode" = rollback ]; then
    [ -f "$prev" ] || die "there is no previous executable at $prev"
    if running; then die "a Heimdall runtime is running; stop it first: heimdall service stop"; fi
    # Stage a copy of the previous executable, keep the current one under a spare name by
    # hard link (or copy), then replace in one rename: the install path is never empty.
    tmp="$prefix/.heimdall.swap"
    rm -f -- "$new" "$tmp"
    cp -p -- "$prev" "$new"
    if [ -f "$cur" ]; then ln -f -- "$cur" "$tmp" 2>/dev/null || cp -p -- "$cur" "$tmp"; fi
    mv -f -- "$new" "$cur"
    if [ -f "$tmp" ]; then mv -f -- "$tmp" "$prev"; else rm -f -- "$prev"; fi
    say "the previous executable is back at $cur; the one it replaced is now $prev"
    say "if it reports that the state is newer than it understands, see docs/operations/recovery.md"
    exit 0
fi

# 0. The unpacked tree must match its own manifest.
[ -f "$here/MANIFEST.sha256" ] || die "MANIFEST.sha256 is missing: this is not a complete archive"
[ -f "$here/heimdall" ] || die "the archive holds no heimdall executable"
while IFS= read -r line; do
    want=${line%%  *}; name=${line#*  }
    [ -f "$here/$name" ] || die "the archive is incomplete: $name is missing"
    [ "$(sha "$here/$name")" = "$want" ] || die "the archive is damaged: $name does not match MANIFEST.sha256"
done <"$here/MANIFEST.sha256"
want_exe=$(grep '  heimdall$' "$here/MANIFEST.sha256" | cut -d' ' -f1)
[ -n "$want_exe" ] || die "MANIFEST.sha256 does not list the executable"

mkdir -p "$prefix"
# Recover from an earlier interruption before deciding anything.
if [ -f "$new" ]; then rm -f -- "$new"; say "removed a leftover staged file from an interrupted run"; fi
rm -f -- "$prev.tmp"
if [ -f "$cur" ] && [ "$(sha "$cur")" = "$want_exe" ]; then
    say "this version is already installed at $cur"
    exit 0
fi
if running; then
    die "a Heimdall runtime is running. Stop it first: heimdall service stop
install: stopping interrupts new connections until it starts again; open sessions keep running
install: (docs/operations/update-and-rollback.md lists what else). Nothing was changed."
fi

# 1. Stage the new executable beside the old one.
cp -- "$here/heimdall" "$new"
chmod 0755 "$new"
sync 2>/dev/null || true
step_done 1
# 2. Check the staged copy.
[ "$(sha "$new")" = "$want_exe" ] || { rm -f -- "$new"; die "the staged copy does not match the manifest; nothing was changed"; }
step_done 2
# 3. Keep a copy of the current executable as the previous one, WITHOUT moving it: a hard
#    link (the same file under a second name), or a copy when the link is refused. The
#    install path keeps its complete executable throughout.
if [ -f "$cur" ]; then
    rm -f -- "$prev.tmp"
    if ! ln -f -- "$cur" "$prev" 2>/dev/null; then
        cp -p -- "$cur" "$prev.tmp" && mv -f -- "$prev.tmp" "$prev"
    fi
fi
step_done 3
# 4. Replace in one rename. rename(2) replaces the target atomically, so the install path
#    always holds a complete executable: the old one before this line, the new one after.
mv -f -- "$new" "$cur"
sync 2>/dev/null || true
step_done 4

say "installed $cur"
[ ! -f "$prev" ] || say "the previous executable is kept as $prev (./install.sh --rollback puts it back)"
case ":${PATH}:" in
    *":$prefix:"*) ;;
    *) say "to run it as 'heimdall', add this line to your shell profile yourself:"
       say "    export PATH=\"$prefix:\$PATH\"" ;;
esac
say "next: heimdall setup    (it shows every change to your SSH configuration and asks first)"
