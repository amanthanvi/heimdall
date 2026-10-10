#!/bin/sh
# Evaluator entry point for the X2 hidden tests (one task, one platform, one binary).
#
#   sh hidden.sh --task T1|T2|T3|T4 --platform darwin|linux --lang go|rust --bin PATH
#                [--expect-sha256 HEX] [--out-dir DIR] [-- run.py args, e.g. --only 'T1.s*']
#
# --lang (fix round 2) is recorded in the result ("lang") and checked by score.py.
#
# Run it from the heimdall repository root (HM_REPO defaults to the current directory; it is used
# for the Linux image tag and, on darwin, for pyte in tests/g02/.venv).  HM_REPO's tracked tests/g02
# must equal BASE.json support_commit (harness 2.4.2), and docker-run.sh checks the image tag.
#
# --bin is the heimdall-proto built for --platform: <dist>/darwin-arm64/heimdall-proto for darwin,
# <dist>/linux-arm64/heimdall-proto for linux.  The binary is first copied into a private directory
# (mode 0555), its sha256 is taken, and run.py refuses to start unless the copy has that digest and
# marks the run invalid (exit 2) if it changes.  So a rebuild of the source tree during the run
# cannot change what is tested.  With --expect-sha256 the copy must also match HEX.
#
# Output: DIR/<task>-<platform>.json (per-assertion record, paths scrubbed) and
# DIR/<task>-<platform>.console.txt.  DIR defaults to ${TMPDIR:-/tmp}/hm-r4-x2-eval/<task>-<platform>-<sha12>.
# Exit status: run.py's (0 pass, 1 fail/error, 2 usage/setup/invalid); 2 for a setup error here.
# Never signals a process it did not start; SSH_AUTH_SOCK is removed; no network.
set -u
HID=$(cd "$(dirname "$0")" && pwd -P)
die() { echo "hidden.sh: $*" >&2; exit 2; }
TASK=""; PLAT=""; BIN=""; EXP=""; OUT=""; LNG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --task) TASK=${2:-}; shift 2 ;;
        --platform) PLAT=${2:-}; shift 2 ;;
        --bin) BIN=${2:-}; shift 2 ;;
        --lang) LNG=${2:-}; shift 2 ;;
        --expect-sha256) EXP=${2:-}; shift 2 ;;
        --out-dir) OUT=${2:-}; shift 2 ;;
        --) shift; break ;;
        *) die "unknown argument: $1" ;;
    esac
done
case "$TASK" in T1|T2|T3|T4) ;; *) die "--task must be T1, T2, T3 or T4" ;; esac
case "$PLAT" in darwin|linux) ;; *) die "--platform must be darwin or linux" ;; esac
case "$LNG" in go|rust) ;; *) die "--lang must be go or rust" ;; esac
[ -n "$BIN" ] && [ -f "$BIN" ] || die "--bin must name the heimdall-proto file for $PLAT"
HM_REPO=${HM_REPO:-$(pwd -P)}
[ -f "$HM_REPO/tests/g02/linux/Dockerfile" ] || die "run from the heimdall repository root (or set HM_REPO)"
export HM_REPO
# The Linux image tag and the darwin pyte venv come from HM_REPO/tests/g02: it must be the pinned harness.
SUPPORT=$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["support_commit"])' "$HID/BASE.json") \
    || die "cannot read BASE.json"
git -C "$HM_REPO" diff --quiet "$SUPPORT" -- tests/g02 2>/dev/null \
    || die "HM_REPO/tests/g02 differs from the pinned support commit $SUPPORT (or HM_REPO is not the repository)"
unset SSH_AUTH_SOCK
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi

PRIV=$(mktemp -d "${TMPDIR:-/tmp}/hm-r4-x2-bin.XXXXXX") || die "mktemp failed"
chmod 0755 "$PRIV"   # the linux container user (10001) must be able to read the mount
trap 'chmod -R u+w "$PRIV" 2>/dev/null; rm -rf "$PRIV"' EXIT
cp "$BIN" "$PRIV/heimdall-proto" || die "cannot copy --bin"
chmod 0555 "$PRIV/heimdall-proto"
SHA=$($SUM "$PRIV/heimdall-proto" | cut -c1-64)
if [ -n "$EXP" ] && [ "$SHA" != "$EXP" ]; then
    die "binary sha256 $(echo "$SHA" | cut -c1-16)... does not match --expect-sha256 $(echo "$EXP" | cut -c1-16)..."
fi
SHA12=$(echo "$SHA" | cut -c1-12)
OUT=${OUT:-${TMPDIR:-/tmp}/hm-r4-x2-eval/$TASK-$PLAT-$SHA12}
mkdir -p "$OUT" || die "cannot create --out-dir"
OUT=$(cd "$OUT" && pwd -P)
CON="$OUT/$TASK-$PLAT.console.txt"
echo "hidden.sh: task=$TASK platform=$PLAT lang=$LNG sha256=$SHA started=$(date -u +%FT%TZ)" > "$CON"
if [ "$PLAT" = darwin ]; then
    [ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "darwin runs need a darwin-arm64 host"
    HM_G02_VENV=${HM_G02_VENV:-$HM_REPO/tests/g02/.venv} python3 -I -B "$HID/run.py" --task "$TASK" \
        --bin "$PRIV/heimdall-proto" --platform darwin --lang "$LNG" --expect-sha256 "$SHA" \
        --out "$OUT/$TASK-darwin.json" "$@" >> "$CON" 2>&1
    rc=$?
else
    D="$OUT/.docker-out"
    sh "$HID/docker-run.sh" --task "$TASK" --artifact-dir "$PRIV" --out-dir "$D" -- --lang "$LNG" --expect-sha256 "$SHA" "$@" >> "$CON" 2>&1
    rc=$?
    [ -f "$D/$TASK-linux.json" ] && mv "$D/$TASK-linux.json" "$OUT/$TASK-linux.json"
    rmdir "$D" 2>/dev/null
fi
echo "hidden.sh: exit=$rc finished=$(date -u +%FT%TZ)" >> "$CON"
tail -n 2 "$CON"
echo "hidden.sh: results in $OUT"
exit $rc
