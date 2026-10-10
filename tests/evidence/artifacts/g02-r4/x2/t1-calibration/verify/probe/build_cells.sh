#!/bin/sh
# M00-T05-r4-x2-t1cal-verify: independent rebuild of the two baselines and the six
# T1 cells (darwin-arm64 + linux-arm64 copied out), one scratch copy per language.
# POSIX sh. Writes only under $S (scratch root). No network, no git push.
set -u
unset SSH_AUTH_SOCK
S=${S:?scratch root}
REPO=${REPO:?repository}
X2="$REPO/tests/evidence/artifacts/g02-r4/x2"
BIN="$S/bin"
LOG="$S/build-logs"
mkdir -p "$BIN" "$LOG"
: > "$S/builds.tsv"
printf 'build\tlang\tsource\tapply_check\tapply\tbuild_exit\tdarwin_sha256\tlinux_sha256\ttree_digest\n' >> "$S/builds.tsv"

sha() { shasum -a 256 "$1" | awk '{print $1}'; }
# Same method as BASE.json (find -type f | sort | shasum | shasum) but skipping the
# build-output dirs (target/, dist/), which a pristine archive does not contain.
tree_digest() { ( cd "$1" && find . -type f -not -path './target/*' -not -path './dist/*' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | awk '{print $1}' ); }

# prepare <lang> <base-commit>
prepare() {
  lang=$1; base=$2
  src="$S/src/$lang"
  rm -rf "$src"; mkdir -p "$src"
  git -C "$REPO" archive "$base" "prototypes/$lang" | tar -x -C "$src" || return 1
  printf 'prototypes/*/dist/\nprototypes/rust/target/\nprototypes/go/bin/\n' > "$src/.gitignore"
  ( cd "$src" && git init -q && git add -A && \
    git -c user.name=verify -c user.email=verify@localhost commit -q -m "base $base prototypes/$lang" ) || return 1
  if [ "$lang" = rust ]; then
    mkdir -p "$src/prototypes/rust/target/tools/bin"
    cp "$REPO/prototypes/rust/target/tools/bin/cargo-zigbuild" "$src/prototypes/rust/target/tools/bin/" || return 1
  fi
}

# build_one <name> <lang> <source-desc> <patch-or-empty>
build_one() {
  name=$1; lang=$2; sdesc=$3; patch=${4:-}
  src="$S/src/$lang"
  proto="$src/prototypes/$lang"
  ( cd "$src" && git reset -q --hard && git clean -qfd ) || { echo "reset failed: $name" >&2; return 1; }
  ac=n/a; ap=n/a
  if [ -n "$patch" ]; then
    if ( cd "$src" && git apply --check "$patch" ) >"$LOG/$name.apply-check.log" 2>&1; then ac=clean; else ac=FAIL; fi
    if ( cd "$src" && git apply "$patch" ) >"$LOG/$name.apply.log" 2>&1; then ap=ok; else ap=FAIL; fi
  fi
  td=$(tree_digest "$proto")
  sh "$proto/build.sh" >"$LOG/$name.build.log" 2>&1
  rc=$?
  mkdir -p "$BIN/$name/darwin-arm64" "$BIN/$name/linux-arm64"
  d=''; l=''
  if [ -f "$proto/dist/darwin-arm64/heimdall-proto" ]; then
    cp "$proto/dist/darwin-arm64/heimdall-proto" "$BIN/$name/darwin-arm64/"; d=$(sha "$BIN/$name/darwin-arm64/heimdall-proto")
  fi
  if [ -f "$proto/dist/linux-arm64/heimdall-proto" ]; then
    cp "$proto/dist/linux-arm64/heimdall-proto" "$BIN/$name/linux-arm64/"; l=$(sha "$BIN/$name/linux-arm64/heimdall-proto")
  fi
  cp "$proto/dist/manifest.json" "$LOG/$name.manifest.json" 2>/dev/null
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$lang" "$sdesc" "$ac" "$ap" "$rc" "$d" "$l" "$td" >> "$S/builds.tsv"
  echo "== $name: apply_check=$ac apply=$ap build_exit=$rc darwin=$d linux=$l" >&2
}

echo "### go" >&2
prepare go 84c7665 || exit 1
echo "go base tree digest: $(tree_digest "$S/src/go/prototypes/go")" >&2
build_one base-go go "84c7665 prototypes/go" ""
build_one T1-go-opus1 go "84c7665 + runs/T1-go-opus1/out/diff.patch" "$X2/runs/T1-go-opus1/out/diff.patch"
build_one T1-go-opus2 go "84c7665 + runs/T1-go-opus2/out/diff.patch" "$X2/runs/T1-go-opus2/out/diff.patch"
build_one T1-go-sonnet1 go "84c7665 + runs/T1-go-sonnet1/implementer/diff.patch" "$X2/runs/T1-go-sonnet1/implementer/diff.patch"

echo "### rust" >&2
prepare rust 001a791 || exit 1
echo "rust base tree digest: $(tree_digest "$S/src/rust/prototypes/rust")" >&2
build_one base-rust rust "001a791 prototypes/rust" ""
build_one T1-rust-opus1 rust "001a791 + runs/T1-rust-opus1/implementer/diff.patch" "$X2/runs/T1-rust-opus1/implementer/diff.patch"
build_one T1-rust-opus2 rust "001a791 + runs/T1-rust-opus2/implementer/diff.patch" "$X2/runs/T1-rust-opus2/implementer/diff.patch"
build_one T1-rust-sonnet1 rust "001a791 + runs/T1-rust-sonnet1/implementer-out/diff.patch" "$X2/runs/T1-rust-sonnet1/implementer-out/diff.patch"

echo "### done" >&2
cat "$S/builds.tsv" >&2
