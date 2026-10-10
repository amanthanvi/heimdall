#!/bin/sh
# RED/GREEN verification matrix for the X2 hidden tests (pack author, reviewer, evaluator).
#
#   HM_REPO=<repo> [TASKS="T1 T2 T3 T4"] sh verify-matrix.sh OUT_DIR [darwin|linux|both]
#
# Subjects are the digest-pinned binaries listed in BASE.json (fix round 2026-10-06), never the
# repository's prototypes/*/dist, which another task may rebuild at any time:
#   base-go, base-rust      the X2 base (post-X1b: Go 84c7665, Rust 001a791)
#   seeded-go, seeded-rust  the T4 seeded builds of <hidden>/seeded-trees/{go,rust}
#   pc                      positive-controls/pc_t{1,2,3}.py
# Per platform: T1 T2 T3 on base-* (expected RED) and pc (expected GREEN); T4 on seeded-* (RED) and
# base-* (GREEN).  Every binary run goes through hidden.sh, which copies the binary to a private
# directory and makes run.py refuse it unless its sha256 equals the BASE.json digest.
# Output: OUT_DIR/<platform>/<task>-<subject>.json and .console.txt; OUT_DIR/exit-codes.tsv has the
# real exit status of every run; OUT_DIR/inputs.txt records the harness pin, the Linux image id and a
# digest of the pack's test code.  Exit 2 if HM_REPO/tests/g02 differs from BASE.json support_commit.
# Darwin runs need pyte (HM_G02_VENV, default <repo>/tests/g02/.venv).  Every pack Python runs with
# -I -B (fix round 2: no __pycache__, which would embed the home path).  OUT_DIR belongs in
# <hidden>/../r4-scratch or the evaluator's scratch, never in the repository.
set -u
HID=$(cd "$(dirname "$0")" && pwd -P)
OUT=$1; WHICH=${2:-both}
: "${HM_REPO:?set HM_REPO}"
export HM_REPO
mkdir -p "$OUT/darwin" "$OUT/linux"
OUT=$(cd "$OUT" && pwd -P)
unset SSH_AUTH_SOCK
TSV="$OUT/exit-codes.tsv"
[ -f "$TSV" ] || printf 'platform\ttask\tsubject\texpected\texit\tsha256_12\tstarted_utc\n' > "$TSV"
TASKS=${TASKS:-"T1 T2 T3 T4"}
SUPPORT=$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["support_commit"])' "$HID/BASE.json")
if ! git -C "$HM_REPO" diff --quiet "$SUPPORT" -- tests/g02 2>/dev/null; then
    echo "verify-matrix.sh: HM_REPO/tests/g02 differs from the pinned support commit $SUPPORT" >&2; exit 2
fi
{ echo "support_commit=$SUPPORT tests/g02=unchanged"
  echo "linux_image=$(docker image inspect -f '{{.Id}}' "heimdall-g02-harness:$(python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["linux_image"]["tag"])' "$HID/BASE.json")" 2>/dev/null | cut -c1-19)"
  echo "pack_sha256=$(cd "$HID" && find run.py hidden.sh docker-run.sh common t1 t2 t3 t4 positive-controls -type f -not -name '*.pyc' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-16)"
} > "$OUT/inputs.txt"
want() { case " $TASKS " in *" $1 "*) return 0 ;; esac; return 1; }
pin() { # subject platform -> sha256 from BASE.json
    python3 -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["binaries"][sys.argv[2]][sys.argv[3]]["sha256"])' \
        "$HID/BASE.json" "$1" "$2"
}

one() { # platform task subject expected
    want "$2" || return 0
    st=$(date -u +%FT%TZ)
    sha=$(pin "$3" "$1")
    d="$OUT/$1/.$2-$3.d"
    sh "$HID/hidden.sh" --task "$2" --platform "$1" --lang "${3#*-}" --bin "$HID/bin/$3/$1-arm64/heimdall-proto" \
        --expect-sha256 "$sha" --out-dir "$d" > /dev/null 2>&1
    rc=$?
    [ -f "$d/$2-$1.json" ] && mv "$d/$2-$1.json" "$OUT/$1/$2-$3.json"
    [ -f "$d/$2-$1.console.txt" ] && mv "$d/$2-$1.console.txt" "$OUT/$1/$2-$3.console.txt"
    rmdir "$d" 2>/dev/null
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$rc" "$(echo "$sha" | cut -c1-12)" "$st" >> "$TSV"
    echo "$1 $2 $3 expected=$4 exit=$rc $(grep '^SUMMARY' "$OUT/$1/$2-$3.console.txt" 2>/dev/null | cut -c1-120)"
}

pc() { # platform task
    want "$2" || return 0
    st=$(date -u +%FT%TZ)
    n=$(echo "$2" | cut -c2)
    if [ "$1" = darwin ]; then
        HM_G02_VENV="${HM_G02_VENV:-$HM_REPO/tests/g02/.venv}" python3 -I -B "$HID/run.py" --task "$2" \
            --bin "$HID/positive-controls/pc_t$n.py" --platform darwin --lang control --out "$OUT/darwin/$2-pc.json" \
            > "$OUT/darwin/$2-pc.console.txt" 2>&1
        rc=$?
    else
        d="$OUT/linux/.$2-pc.d"
        # The artifact mount is required by docker-run.sh but unused: the subject is the control script.
        sh "$HID/docker-run.sh" --task "$2" --artifact-dir "$HID/bin/base-go/linux-arm64" --out-dir "$d" \
            --bin "/hidden/positive-controls/pc_t$n.py" -- --lang control > "$OUT/linux/$2-pc.console.txt" 2>&1
        rc=$?
        [ -f "$d/$2-linux.json" ] && mv "$d/$2-linux.json" "$OUT/linux/$2-pc.json"
        rmdir "$d" 2>/dev/null
    fi
    printf '%s\t%s\tpc\tgreen\t%s\t-\t%s\n' "$1" "$2" "$rc" "$st" >> "$TSV"
    echo "$1 $2 pc expected=green exit=$rc $(grep '^SUMMARY' "$OUT/$1/$2-pc.console.txt" 2>/dev/null | cut -c1-120)"
}

for p in darwin linux; do
    [ "$WHICH" = both ] || [ "$WHICH" = "$p" ] || continue
    for t in T2 T3 T1; do
        one $p $t base-go red
        one $p $t base-rust red
        pc $p $t
    done
    for c in go rust; do
        one $p T4 seeded-$c red
        one $p T4 base-$c green
    done
done
date -u +%FT%TZ > "$OUT/finished_utc.txt"
