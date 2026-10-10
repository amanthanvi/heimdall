#!/bin/sh
# Free the disk space one evaluated X2 cell holds (fix round 2, 2026-10-06; the host disk is nearly full).
#
#   HM_REPO=<repo> sh cleanup-cell.sh --lang go|rust --ws WS --eval EVAL [--dry-run]
#
# Run it as the last evaluator step, after the hidden tests, scoring, the full harness, the unit tests
# and the evidence scan.  It first copies what the reviewer needs into EVAL/out/:
#   EVAL/out/dist-frozen/      the evaluator's build of the frozen copy (all targets, from EVAL/frozen/<lang>/dist)
#   EVAL/out/dist-workspace/   the implementer's own last build (from WS/prototypes/<lang>/dist), if any
#   EVAL/out/SHA256SUMS        sha256 of every file copied above
# and then deletes only heavy build intermediates:
#   rust: WS/prototypes/rust/target and EVAL/frozen/rust/target, except target/tools (the delivered
#         cargo-zigbuild, a few MB, so the workspace can still be rebuilt);
#   go:   Go build caches and module caches an implementer or evaluator placed inside WS or EVAL
#         (a directory holding the Go build cache README and trim.txt, or a module cache's cache/download).
# Source trees, change.patch, records, transcripts and EVAL/out are never touched.  WS must look like an
# X2 workspace (TASK.md and prototypes/<lang>), and WS and EVAL must lie outside the repository and the
# hidden material; the copies must succeed before anything is deleted.  --dry-run only prints.
# Output: sizes before and after, relative paths only.  Exit status: 0 done; 2 usage or refusal.
set -u
HID=$(cd "$(dirname "$0")" && pwd -P)
die() { echo "cleanup-cell.sh: $*" >&2; exit 2; }
LANG_=""; WS=""; EV=""; DRY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --lang) LANG_=${2:-}; shift 2 ;;
        --ws) WS=${2:-}; shift 2 ;;
        --eval) EV=${2:-}; shift 2 ;;
        --dry-run) DRY=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
case "$LANG_" in go|rust) ;; *) die "--lang must be go or rust" ;; esac
: "${HM_REPO:?set HM_REPO to the heimdall repository root}"
REPO=$(cd "$HM_REPO" && pwd -P) || die "HM_REPO is not a directory"
WS=$(cd "$WS" 2>/dev/null && pwd -P) || die "--ws is not a directory"
EV=$(cd "$EV" 2>/dev/null && pwd -P) || die "--eval is not a directory"
HPAR=$(cd "$HID/.." && pwd -P)
for d in "$WS" "$EV"; do
    case "$d/" in "$REPO"/*|"$HID"/*) die "refusing a directory inside the repository or the hidden directory" ;; esac
    [ "$d" = "$HPAR" ] && die "refusing the hidden material's parent"
    [ "$d" = / ] || [ "$d" = "$HOME" ] && die "refusing / or the home directory"
done
[ -f "$WS/TASK.md" ] && [ -d "$WS/prototypes/$LANG_" ] || die "--ws is not an X2 workspace for $LANG_"
case "$EV/" in "$WS"/*) die "--eval must lie outside --ws" ;; esac
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
size() { [ -e "$1" ] && du -sk "$1" 2>/dev/null | cut -f1 || echo 0; }
run() { if [ "$DRY" = 1 ]; then echo "dry-run: $*" | sed "s#$WS#<ws>#g; s#$EV#<eval>#g"; else "$@"; fi; }

echo "before: ws $(size "$WS") KiB, eval $(size "$EV") KiB"
mkdir -p "$EV/out" || die "cannot create EVAL/out"
if [ -d "$EV/frozen/$LANG_/dist" ]; then
    run rm -rf "$EV/out/dist-frozen"
    run cp -R "$EV/frozen/$LANG_/dist" "$EV/out/dist-frozen" || die "copy of the frozen build failed; nothing deleted"
fi
if [ -d "$WS/prototypes/$LANG_/dist" ]; then
    run rm -rf "$EV/out/dist-workspace"
    run cp -R "$WS/prototypes/$LANG_/dist" "$EV/out/dist-workspace" || die "copy of the workspace build failed; nothing deleted"
fi
if [ "$DRY" = 0 ]; then
    (cd "$EV/out" && find dist-frozen dist-workspace -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do $SUM "$f"; done) \
        > "$EV/out/SHA256SUMS" || die "cannot write SHA256SUMS; nothing deleted"
fi

if [ "$LANG_" = rust ]; then
    for t in "$WS/prototypes/rust/target" "$EV/frozen/rust/target"; do
        [ -d "$t" ] || continue
        for e in "$t"/* "$t"/.[!.]*; do
            [ -e "$e" ] || continue
            [ "$(basename "$e")" = tools ] && continue
            run rm -rf "$e"
        done
    done
fi
# Go build and module caches placed inside WS or EVAL (any language; a Rust cell may run go too).
for root in "$WS" "$EV"; do
    find "$root" -type f -name trim.txt 2>/dev/null | while IFS= read -r f; do
        d=$(dirname "$f")
        grep -qs "Go build" "$d/README" || continue
        [ "$d" != "$root" ] || continue
        case "$d/" in "$EV/out"/*) continue ;; esac
        run rm -rf "$d"
    done
    find "$root" -type d -path '*/cache/download' 2>/dev/null | while IFS= read -r d; do
        m=$(dirname "$(dirname "$d")")
        [ "$m" != "$root" ] || continue
        case "$m/" in "$root"/*) ;; *) continue ;; esac
        case "$m/" in "$EV/out"/*|"$WS/prototypes/$LANG_/"|"$EV/frozen/$LANG_/") continue ;; esac
        # never a source directory
        [ -e "$m/go.mod" ] || [ -e "$m/Cargo.toml" ] || [ -e "$m/TASK.md" ] || [ -e "$m/build.sh" ] && continue
        [ -d "$m/cache/download" ] || continue
        run chmod -R u+w "$m"
        run rm -rf "$m"
    done
done
echo "after: ws $(size "$WS") KiB, eval $(size "$EV") KiB (out: $(size "$EV/out") KiB)"
