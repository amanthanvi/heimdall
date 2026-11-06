#!/bin/sh
# usage: runbin2.sh <scratch> <run-subdir> <umask-or-default> <binary-name> [libtest args...]
# Scratch HOME and TMPDIR; no Git variable inherited; output redacted inside this script.
S=$1; D=$2; U=$3; BIN=$4; shift 4
mkdir -p "$S/$D/tmp" "$S/$D/h"; chmod 700 "$S/$D/tmp" "$S/$D/h"
[ "$U" = default ] || umask "$U"
echo "umask=$(umask)"
env -i PATH=/usr/bin:/bin HOME="$S/$D/h" TMPDIR="$S/$D/tmp" "$S/$BIN" "$@" 2>&1
echo "exit=$?"
