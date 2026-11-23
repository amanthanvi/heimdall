#!/bin/sh
# Install or update Heimdall for the current user (m08-plan U2a; ADR-0014 section 4.3).
#
# Usage, from inside the unpacked archive:
#   ./install.sh                 install, or update an existing install
#   ./install.sh --rollback      put the previous executable back
#   ./install.sh --prefix DIR    install into DIR (default: $HOME/.local/bin)
#   ./install.sh --assume-stopped   you have checked that no Heimdall runtime is running, and
#                                the installed executable cannot say so itself (it is broken)
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
# refuses while one is running, and also when it cannot tell (the installed executable does
# not answer plainly that none is running), and tells you what to do. The current executable is kept as
# `heimdall.previous`. The replacement is staged: the new file is copied beside the old one
# and checked, the old one is linked (or copied) to `heimdall.previous`, and one rename puts
# the new one in place. The install path therefore holds a complete executable at every
# moment, the old one or the new one, and running the script again finishes an interrupted
# update.
set -eu

here=$(cd "$(dirname "$0")" && pwd -P)
prefix="${HOME}/.local/bin"
mode=install
assume_stopped=no
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || { echo "install: --prefix needs a directory" >&2; exit 2; }; prefix=$2; shift 2 ;;
        --rollback) mode=rollback; shift ;;
        --assume-stopped) assume_stopped=yes; shift ;;
        *) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
# A relative prefix is anchored with ./ so that one beginning with a dash is never read as
# an option by test, mkdir, cp, ln or mv.
case "$prefix" in /*) ;; *) prefix="./$prefix" ;; esac
say() { printf 'install: %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
# The interruption test stops the script after a numbered step (HM_INSTALL_TEST_STOP_AFTER).
step_done() { if [ "${HM_INSTALL_TEST_STOP_AFTER:-}" = "$1" ]; then say "stopped after step $1 (test)"; exit 1; fi; }

cur="$prefix/heimdall"
prev="$prefix/heimdall.previous"
new="$prefix/.heimdall.new"
swap="$prefix/.heimdall.swap"

# Is a runtime of the installed executable running? `service status` never starts one.
# Three answers, and only one of them lets an update proceed:
#   none     the executable itself says "no runtime is running". It says that when there is
#            no advertisement, and also for a crashed runtime's stale one, because it checks
#            the advertised process against its start time before believing it;
#   running  a runtime answered;
#   unknown  anything else: an advertisement it does not trust, a live runtime that does
#            not answer (starting, wedged), no output at all, or an executable that will not
#            run. The update is refused (fail closed), with what to do next.
# (The "none" answer is recognized by the executable's own message, because its envelope has
# no reason code for it yet. If that text ever changes, this guard refuses: the safe side.)
runtime_state() {
    [ -e "$cur" ] || { echo none; return 0; }
    out=$("$cur" --json --non-interactive service status 2>/dev/null) || true
    case "$out" in
        *'"running":true'*) echo running ;;
        *'"message":"no runtime is running"'*) echo none ;;
        *) echo unknown ;;
    esac
}
# Processes of this user that were started from the installed executable's exact path.
# `service status` can say "no runtime is running" while a live runtime's endpoint is merely
# not connectable (review M08-W01 on R04), so its word is not taken alone: a live process
# from this path refuses the update whatever the executable says. It reads the process
# list; it signals nothing. (The first two words of each command line are compared, so a
# script run through an interpreter is seen too. A runtime started from some OTHER path is
# not seen here; that case needs the product to report "advertised but unreachable".)
# A process started from the installed executable. Compared as files, not strings (review
# M08-W1-R06): `[ a -ef b ]` is true when both names reach the same device and inode, so a
# relative --prefix, a prefix through a symbolic link, or a process started through a link
# to the installed file all match. Each of the first two words of a process's command line
# (the executable, or the interpreter and its script) that is an absolute path is checked.
# Not covered, and said: a process started through a relative path or by name from PATH
# shows no absolute path, and is caught only by the runtime query that follows.
live_from_cur() {
    ps -u "$(id -u)" -o pid= -o args= 2>/dev/null | while read -r pid w1 w2 rest; do
        [ "$pid" != "$$" ] || continue
        for w in "$w1" "$w2"; do
            case "$w" in /*) if [ "$w" -ef "$cur" ]; then echo "$pid"; break; fi ;; esac
        done
    done
}
require_stopped() {
    live=$(live_from_cur | tr '\n' ' ')
    [ -z "$live" ] || die "a process started from $cur is running (pid ${live% }). Stop it first: heimdall service stop
install: (--assume-stopped does not override this: the process is there). Nothing was changed."
    [ "$assume_stopped" = no ] || { say "--assume-stopped: not asking the installed executable whether a runtime is running"; return 0; }
    case "$(runtime_state)" in
        none) ;;
        running) die "a Heimdall runtime is running. Stop it first: heimdall service stop
install: stopping interrupts new connections until it starts again; open sessions keep running
install: (docs/operations/update-and-rollback.md lists what else). Nothing was changed." ;;
        *) die "cannot tell whether a Heimdall runtime is running: the installed executable did not answer
install: 'no runtime is running'. Run: heimdall service status  and  heimdall service stop
install: If no heimdall process is running (check your process list), run this again with
install: --assume-stopped. Nothing was changed." ;;
    esac
}

# The names this script writes must be ordinary files or absent. A symbolic link there
# would be written through or installed as the executable; a directory would swallow the
# file. Links at the staging names are removed (the link, never its target); anything else
# unexpected is refused before any write.
[ ! -e "$prefix" ] || [ -d "$prefix" ] || die "$prefix exists and is not a directory"
mkdir -p -- "$prefix"
for p in "$new" "$swap" "$prev.tmp"; do
    if [ -L "$p" ]; then
        rm -f -- "$p"; say "removed a symbolic link found at a staging name ($(basename "$p"))"
    elif [ -d "$p" ]; then
        die "$p is a directory; remove it and run this again. Nothing was changed."
    fi
done
for p in "$cur" "$prev"; do
    if [ -L "$p" ]; then
        die "$p is a symbolic link. This script replaces files, not links; remove the link and run this again. Nothing was changed."
    elif [ -d "$p" ]; then
        die "$p is a directory; remove it and run this again. Nothing was changed."
    fi
done
# An interrupted rollback leaves the executable it had replaced under the spare name, and
# nothing else holds it: finish that rollback's last step before anything is removed.
# Which of the rollback's renames had happened is read from the files, not assumed
# (review M08-W01-R04): the spare copy is a second name for the executable the rollback
# was replacing. If the install path still holds that same executable, the replace had not
# happened yet: the previous executable is still in place under its own name, and the spare
# copy is just removed. Otherwise the replace happened, and the spare copy becomes the
# previous executable.
if [ -f "$swap" ]; then
    if [ -f "$cur" ] && [ "$(sha "$cur")" = "$(sha "$swap")" ]; then
        rm -f -- "$swap"
        say "undid an interrupted rollback that had not replaced anything yet: $cur and $prev are as they were"
    else
        mv -f -- "$swap" "$prev"
        say "finished an interrupted rollback: the executable it replaced is kept as $prev"
    fi
fi
if [ -f "$new" ]; then rm -f -- "$new"; say "removed a leftover staged file from an interrupted run"; fi
rm -f -- "$prev.tmp"

# keep_as SRC DST: make DST a second name for SRC (a hard link), or a copy when the link
# is refused. It either succeeds completely or fails: a partial copy is never left at DST.
keep_as() {
    if ln -f -- "$1" "$2" 2>/dev/null; then return 0; fi
    rm -f -- "$2.tmp"
    if cp -p -- "$1" "$2.tmp" && mv -f -- "$2.tmp" "$2"; then return 0; fi
    rm -f -- "$2.tmp"
    return 1
}

if [ "$mode" = rollback ]; then
    [ -f "$prev" ] || die "there is no previous executable at $prev"
    require_stopped
    # Stage a copy of the previous executable, keep the current one under a spare name,
    # then replace in one rename: the install path is never empty.
    cp -p -- "$prev" "$new" || { rm -f -- "$new"; die "could not stage the previous executable; nothing was changed"; }
    if [ -f "$cur" ]; then
        keep_as "$cur" "$swap" || { rm -f -- "$new"; die "could not keep the current executable; nothing was changed"; }
    fi
    step_done r1
    mv -f -- "$new" "$cur"
    step_done r2
    if [ -f "$swap" ]; then mv -f -- "$swap" "$prev"; else rm -f -- "$prev"; fi
    say "the previous executable is back at $cur; the one it replaced is now $prev"
    say "if it reports that the state is newer than it understands, see docs/operations/recovery.md"
    exit 0
fi

# 0. The unpacked tree must match its own manifest (every line, a last one without a
#    newline included).
[ -f "$here/MANIFEST.sha256" ] || die "MANIFEST.sha256 is missing: this is not a complete archive"
[ -f "$here/heimdall" ] || die "the archive holds no heimdall executable"
want_exe=""
while IFS= read -r line || [ -n "$line" ]; do
    want=${line%%  *}; name=${line#*  }
    [ "$want" != "$line" ] && [ ${#want} = 64 ] || die "MANIFEST.sha256 has a malformed line"
    # A manifest name is a plain relative path: no empty, . or .. segment, no backslash, no
    # colon, no leading slash, no control character. Refused before anything is written, so
    # a name is never joined into a path outside the archive.
    case "/$name/" in
        *//*|*/./*|*/../*|*\\*|*:*) die "MANIFEST.sha256 names a path this script will not use (it must be a plain relative path). Nothing was changed." ;;
    esac
    case "$name" in *[[:cntrl:]]*|"") die "MANIFEST.sha256 names a path this script will not use (it must be a plain relative path). Nothing was changed." ;; esac
    [ -f "$here/$name" ] || die "the archive is incomplete: $name is missing"
    [ "$(sha "$here/$name")" = "$want" ] || die "the archive is damaged: $name does not match MANIFEST.sha256"
    [ "$name" != heimdall ] || want_exe=$want
done <"$here/MANIFEST.sha256"
[ -n "$want_exe" ] || die "MANIFEST.sha256 does not list the executable"

if [ -f "$cur" ] && [ "$(sha "$cur")" = "$want_exe" ]; then
    say "this version is already installed at $cur"
    exit 0
fi
require_stopped

# 1. Stage the new executable beside the old one.
cp -- "$here/heimdall" "$new" || { rm -f -- "$new"; die "could not stage the new executable; nothing was changed"; }
chmod 0755 "$new"
sync 2>/dev/null || true
step_done 1
# 2. Check the staged copy.
[ "$(sha "$new")" = "$want_exe" ] || { rm -f -- "$new"; die "the staged copy does not match the manifest; nothing was changed"; }
step_done 2
# 3. Keep the current executable as the previous one, WITHOUT moving it: a hard link (the
#    same file under a second name), or a copy when the link is refused. If neither works,
#    STOP HERE: replacing the executable without having kept it would leave nothing to
#    roll back to, while saying otherwise. The install path keeps its complete executable.
if [ -f "$cur" ]; then
    keep_as "$cur" "$prev" || {
        rm -f -- "$new"
        die "could not keep the current executable as $prev (is the disk full?). The update was not made: $cur is unchanged."
    }
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
