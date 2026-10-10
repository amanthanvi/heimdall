#!/bin/sh
# Build one isolated implementer workspace for an X2 cell (fix round 2026-10-06; fix round 2 the same day).
#
#   HM_REPO=<repo> sh make-workspace.sh --task T1|T2|T3|T4 --lang go|rust --dest DIR --manifest FILE [--test-build]
#
# Why: implementers must not reach the unseeded prototypes (a `diff -r` against the seeded tree
# shows the T4 seed in one step), the other language's prototype, the evidence tree (reviews,
# per-language results), or this hidden directory.  The workspace mirrors the repository layout so
# that build.sh, the unit tests, tests/g02/conformance.py and tests/g02/linux/run.sh work unchanged
# from the workspace root.  It holds only:
#
#   TASK.md                      the task spec (tests/evidence/artifacts/g02-r4/x2/specs/<task>.md)
#   prototypes/<lang>/           T1-T3: `git archive <base commit>`; T4: the seeded tree.  Both are
#                                checked against the tree digests in BASE.json.
#   docs/g02/slice-contract.md   the binding contract (incl. section 9.6)
#   schemas/g02/                 result schema
#   tests/g02/                   harness 2.4.2 (no selftest-results/, no SELFTEST.md)
#   tests/g02/.venv              a NEW venv (same interpreter as the repository's) holding byte copies
#                                of the pyte and wcwidth packages; the repository venv is not copied
#                                because its scripts and pyvenv.cfg name the repository path
#   tests/fixtures/g02/, tests/fixtures/fake-agent/, tests/evidence/record.schema.json  (harness inputs)
#   prototypes/rust/target/tools/bin/cargo-zigbuild   (Rust only: the cross-build tool build.sh looks for)
#
# Every tracked file comes from the pinned commits in BASE.json, so every cell gets identical inputs.
# There is no .git directory.  DIR must not exist yet and must lie outside the repository, outside
# the hidden material's parent (heimdall-m00: the hidden dir and ../r4-scratch) and outside
# /tmp/hm-r4.  DIR is resolved before anything is created: relative paths are made absolute, `.` and
# `..` components are refused, and the nearest existing ancestor is resolved with `pwd -P` (so a
# symlinked parent cannot smuggle DIR into a refused place); only then is the parent created, and it
# is checked again after creation.  Use a neutral name with a common prefix, e.g.
# /tmp/x2ws-<random>/heimdall, and give that prefix to audit-transcript.py (--workspace-prefix).
# FILE (written outside DIR) records sources and digests for the evaluator; never give it to the
# implementer.  --test-build (pack verification only, never for an implementer) also allows a DIR
# under <hidden>/../r4-scratch/M00-T05-*/ so the pack author can prove the layout without writing
# elsewhere.  The seeded T4 trees are <hidden>/seeded-trees/<lang> (BASE.json seed.<lang>.tree).
# Exit status: 0 built; 2 usage or verification error (DIR is removed again only if this run made it).
set -u
HID=$(cd "$(dirname "$0")" && pwd -P)
die() { echo "make-workspace.sh: $*" >&2; [ -n "${CREATED:-}" ] && rm -rf "$DEST"; exit 2; }
TASK=""; LANG_=""; DEST=""; MAN=""; TEST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --task) TASK=${2:-}; shift 2 ;;
        --lang) LANG_=${2:-}; shift 2 ;;
        --dest) DEST=${2:-}; shift 2 ;;
        --manifest) MAN=${2:-}; shift 2 ;;
        --test-build) TEST=1; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
case "$TASK" in T1|T2|T3|T4) ;; *) die "--task must be T1..T4" ;; esac
case "$LANG_" in go|rust) ;; *) die "--lang must be go or rust" ;; esac
[ -n "$DEST" ] && [ -n "$MAN" ] || die "--dest and --manifest are required"
: "${HM_REPO:?set HM_REPO to the heimdall repository root}"
REPO=$(cd "$HM_REPO" && pwd -P) || die "HM_REPO is not a directory"
SCR=$(cd "$HID/.." && pwd -P)   # heimdall-m00: the hidden dir and r4-scratch
# resolve PATH: absolute, no . or .. components, nearest existing ancestor resolved with pwd -P.
# Creates nothing.  Prints the resolved path, or nothing (status 1) with a reason on stderr.
resolve() {
    r=$1
    case "$r" in /*) ;; *) r="$(pwd -P)/$r" ;; esac
    case "$r/" in */./*|*/../*) echo "make-workspace.sh: $2 must not contain . or .. components" >&2; return 1 ;; esac
    anc=$(dirname "$r"); rest=$(basename "$r")
    while [ ! -d "$anc" ]; do
        if [ -e "$anc" ] || [ -L "$anc" ]; then
            echo "make-workspace.sh: a component of $2 exists but is not a directory" >&2; return 1
        fi
        rest="$(basename "$anc")/$rest"; anc=$(dirname "$anc")
    done
    anc=$(cd "$anc" && pwd -P) || return 1
    echo "${anc%/}/$rest"
}
destcheck() {
case "$1/" in
    "$REPO"/*|"$HID"/*) die "--dest must lie outside the repository and the hidden directory" ;;
    "$SCR"/r4-scratch/M00-T05-*/*)
        [ "$TEST" = 1 ] || die "--dest must lie outside the round-4 scratch (only --test-build may use $SCR/r4-scratch/M00-T05-*/)" ;;
    "$SCR"/*) die "--dest must lie outside the hidden material's parent directory" ;;
    /tmp/hm-r4/*|/private/tmp/hm-r4/*) die "--dest must lie outside /tmp/hm-r4" ;;
esac
}
RDEST=$(resolve "$DEST" --dest) && [ -n "$RDEST" ] || die "cannot resolve --dest"
destcheck "$RDEST"                       # before anything is created
DEST=$RDEST
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || die "--dest already exists"
RMAN=$(resolve "$MAN" --manifest) && [ -n "$RMAN" ] || die "cannot resolve --manifest"
case "$RMAN/" in "$DEST"/*) die "--manifest must lie outside --dest" ;; esac
case "$RMAN/" in "$REPO"/*) die "--manifest must lie outside the repository" ;; esac
MAN=$RMAN
mkdir -p "$(dirname "$DEST")" || die "cannot create the parent of --dest"
[ "$(cd "$(dirname "$DEST")" && pwd -P)/$(basename "$DEST")" = "$DEST" ] || die "the parent of --dest changed while it was created"
destcheck "$DEST"
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
treesum() { (cd "$1" && find . -type f | LC_ALL=C sort | xargs $SUM | $SUM | cut -c1-64); }
field() { python3 -I -B -c 'import json,sys
d=json.load(open(sys.argv[1]))
for k in sys.argv[2:]: d=d[k]
print(d)' "$HID/BASE.json" "$@"; }

BASE_COMMIT=$(field base "$LANG_" commit)
SUPPORT=$(field support_commit)
SPEC="$REPO/tests/evidence/artifacts/g02-r4/x2/specs/$TASK.md"
[ -f "$SPEC" ] || die "spec $TASK.md not found"
git -C "$REPO" cat-file -e "$BASE_COMMIT^{commit}" 2>/dev/null || die "base commit $BASE_COMMIT not in HM_REPO"
git -C "$REPO" cat-file -e "$SUPPORT^{commit}" 2>/dev/null || die "support commit $SUPPORT not in HM_REPO"
RVENV="$REPO/tests/g02/.venv"
[ -f "$RVENV/pyvenv.cfg" ] || die "the repository harness venv (pyte) is missing; see tests/g02/README.md"
PYHOME=$(sed -n 's/^home = //p' "$RVENV/pyvenv.cfg")
PYVER=$(sed -n 's/^version = \([0-9]*\.[0-9]*\).*/\1/p' "$RVENV/pyvenv.cfg")
PYBASE="$PYHOME/python$PYVER"
[ -x "$PYBASE" ] || die "the interpreter of the repository venv is missing"
RSITE="$RVENV/lib/python$PYVER/site-packages"

mkdir "$DEST" || die "cannot create --dest"
CREATED=1
cp "$SPEC" "$DEST/TASK.md" || die "copy spec"
mkdir -p "$DEST/prototypes"
if [ "$TASK" = T4 ]; then
    SEEDED="$HID/$(field seed "$LANG_" tree)"
    [ -d "$SEEDED" ] || die "seeded tree for $LANG_ missing under the hidden directory"
    WANT=$(field seed "$LANG_" tree_digest)
    [ "$(treesum "$SEEDED")" = "$WANT" ] || die "seeded tree digest differs from BASE.json"
    cp -R "$SEEDED" "$DEST/prototypes/$LANG_" || die "copy seeded tree"
    PROTO_SRC="seeded tree (BASE.json seed.$LANG_)"
else
    WANT=$(field base "$LANG_" tree_digest)
    git -C "$REPO" archive "$BASE_COMMIT" "prototypes/$LANG_" | tar -x -C "$DEST" || die "git archive prototype"
    PROTO_SRC="git archive $BASE_COMMIT prototypes/$LANG_"
fi
PROTO_SUM=$(treesum "$DEST/prototypes/$LANG_")
[ "$PROTO_SUM" = "$WANT" ] || die "prototype tree digest differs from BASE.json"
git -C "$REPO" archive "$SUPPORT" docs/g02/slice-contract.md schemas/g02 tests/g02 tests/fixtures/g02 \
    tests/fixtures/fake-agent tests/evidence/record.schema.json | tar -x -C "$DEST" || die "git archive support files"
rm -rf "$DEST/tests/g02/selftest-results" "$DEST/tests/g02/SELFTEST.md"

# Harness venv: a fresh venv plus byte copies of the two pinned packages (no network, no pip).
WVENV="$DEST/tests/g02/.venv"
"$PYBASE" -m venv --without-pip "$WVENV" || die "python -m venv failed"
WSITE="$WVENV/lib/python$PYVER/site-packages"
for pkg in pyte wcwidth; do
    for src in "$RSITE/$pkg" "$RSITE"/$pkg-*.dist-info; do
        [ -d "$src" ] || die "$pkg missing from the repository venv"
        (cd "$(dirname "$src")" && tar -cf - --exclude __pycache__ "$(basename "$src")") | tar -xf - -C "$WSITE" \
            || die "copy $pkg"
    done
done
PYTE_VER=$(cd /tmp && "$WVENV/bin/python" -I -B -c 'import pyte, wcwidth, importlib.metadata as m; print(m.version("pyte"), m.version("wcwidth"))') \
    || die "pyte is not importable from the workspace venv"
[ "$PYTE_VER" = "0.8.2 0.9.1" ] || die "unexpected pyte/wcwidth versions in the workspace venv"
VENV_SUM=$(treesum "$WSITE")

if [ "$LANG_" = rust ]; then
    ZB="$REPO/prototypes/rust/target/tools/bin/cargo-zigbuild"
    [ -x "$ZB" ] || die "cargo-zigbuild not found under the repository's prototypes/rust/target/tools/bin"
    mkdir -p "$DEST/prototypes/rust/target/tools/bin" && cp "$ZB" "$DEST/prototypes/rust/target/tools/bin/" || die "copy cargo-zigbuild"
fi

# Nothing that points back at the repository, the hidden material, the scratch trees or the other
# prototype.  Every file is scanned as bytes (binaries and the venv included); occurrences of the
# workspace's own path are removed first, so a --test-build scratch path is not a false hit.
OTHER=go; [ "$LANG_" = go ] && OTHER=rust
[ ! -e "$DEST/prototypes/$OTHER" ] || die "other prototype present"
[ ! -e "$DEST/.git" ] || die ".git present"
python3 -I -B - "$DEST" "$REPO" "$HID" <<'EOF' || die "workspace content points at the repository, the hidden material or scratch paths"
import os, sys
dest, repo, hid = sys.argv[1:4]
own = [dest.encode()]
if dest.startswith("/private/tmp/"):
    own.append(dest[len("/private"):].encode())
pats = [repo.encode(), hid.encode(), b"r4-hidden", b"heimdall-m00", b"/tmp/hm-r4", b"r4-scratch", b"seeded-trees", b"taskpack",
        b"GitRepos/heimdall", b"g02-r4/x2"]
bad = 0
for root, dirs, files in os.walk(dest):
    for f in files:
        p = os.path.join(root, f)
        if os.path.islink(p):
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        for o in own:
            data = data.replace(o, b"")
        hit = [q.decode() for q in pats if q in data]
        if hit:
            bad += 1
            print("make-workspace.sh: %s mentions %s" % (os.path.relpath(p, dest), ", ".join(
                "<repo>" if h == repo else "<hidden>" if h == hid else h for h in hit)), file=sys.stderr)
sys.exit(1 if bad else 0)
EOF

mkdir -p "$(dirname "$MAN")"
python3 -I -B - "$MAN" <<EOF || die "write manifest"
import json, sys
json.dump({"task": "$TASK", "lang": "$LANG_", "created_utc": "$(date -u +%FT%TZ)",
           "workspace": "$DEST", "test_build": bool($TEST),
           "prototype_source": "$PROTO_SRC", "prototype_tree_digest": "$PROTO_SUM",
           "prototype_tree_digest_pinned": True,
           "support_commit": "$SUPPORT", "spec_sha256": "$($SUM "$SPEC" | cut -c1-64)",
           "venv_python": "$PYVER", "venv_packages": "$PYTE_VER", "venv_site_packages_digest": "$VENV_SUM",
           "tree_digest_method": "find . -type f | LC_ALL=C sort | xargs sha256 | sha256 (prototype dir as delivered, before cargo-zigbuild is added under target/ and before any change)"},
          open(sys.argv[1], "w"), indent=1)
EOF
echo "make-workspace.sh: $TASK $LANG_ workspace ready (prototype tree $(echo "$PROTO_SUM" | cut -c1-16)..., matches BASE.json)"
