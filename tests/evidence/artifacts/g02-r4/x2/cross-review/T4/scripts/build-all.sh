#!/bin/sh
# Build every T4 subject with its own unmodified build.sh, one scratch copy per language,
# reset (rsync --delete, target/ kept) between subjects. Copies darwin-arm64, linux-arm64 and
# windows-x64 binaries to <scratch>/bins/<subject>/ and writes <scratch>/logs/build-results.tsv.
# Usage: build-all.sh <scratch-root> <repo-root> [subject ...]
# Offline: GOPROXY=off, GOTOOLCHAIN=local, CARGO_NET_OFFLINE=true. Rust uses the repository's
# pinned cargo-zigbuild, copied into the scratch copy's target/tools/bin/ (build.sh looks there).
set -u
S=$1
R=$2
shift 2
SUBJECTS=${*:-"base-go seeded-go T4-go-opus1 T4-go-opus2 T4-go-sonnet1 base-rust seeded-rust T4-rust-opus1 T4-rust-opus2 T4-rust-sonnet1"}
OUT="$S/logs/build-results.tsv"
[ -f "$OUT" ] || printf 'subject\tlang\tbuild_sh_rc\tdarwin_arm64_sha256\tlinux_arm64_sha256\twindows_x64_sha256\tmanifest_built\n' > "$OUT"
export GOPROXY=off GOTOOLCHAIN=local CARGO_NET_OFFLINE=true
for subj in $SUBJECTS; do
  case $subj in *go*) lang=go ;; *) lang=rust ;; esac
  W="$S/work/$lang"
  mkdir -p "$W"
  rsync -a --delete --exclude /target/ --exclude /dist/ "$S/src/$subj/" "$W/"
  # cargo fingerprints local sources by mtime: rsync -a keeps the (older) source mtimes, so
  # without this a kept target/ is judged fresh and the previous subject's binary is reused
  # (observed in the first Rust pass: all five darwin binaries were the base binary).
  find "$W" -path "$W/target" -prune -o -type f -exec touch {} +
  if [ "$lang" = rust ]; then
    mkdir -p "$W/target/tools/bin"
    [ -x "$W/target/tools/bin/cargo-zigbuild" ] || cp "$R/prototypes/rust/target/tools/bin/cargo-zigbuild" "$W/target/tools/bin/"
  fi
  log="$S/logs/build-$subj.log"
  (cd "$W" && sh ./build.sh) > "$log" 2>&1
  rc=$?
  B="$S/bins/$subj"
  rm -rf "$B"; mkdir -p "$B"
  for t in darwin-arm64 linux-arm64 windows-x64; do
    for f in "$W/dist/$t/heimdall-proto" "$W/dist/$t/heimdall-proto.exe"; do
      [ -f "$f" ] && mkdir -p "$B/$t" && cp "$f" "$B/$t/"
    done
  done
  [ -f "$W/dist/manifest.json" ] && cp "$W/dist/manifest.json" "$B/manifest.json"
  h() { [ -f "$1" ] && shasum -a 256 "$1" | awk '{print $1}' || echo missing; }
  built=$(python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1])); print(",".join(t["target"]+"="+str(t["built"]).lower() for t in m["targets"]))' "$B/manifest.json" 2>/dev/null || echo none)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$subj" "$lang" "$rc" "$(h "$B/darwin-arm64/heimdall-proto")" \
    "$(h "$B/linux-arm64/heimdall-proto")" "$(h "$B/windows-x64/heimdall-proto.exe")" "$built" >> "$OUT"
  echo "done $subj rc=$rc" >&2
done
