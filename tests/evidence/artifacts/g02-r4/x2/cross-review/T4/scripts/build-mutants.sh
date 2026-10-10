#!/bin/sh
# Plain darwin-arm64 builds of the ".nocheck" mutants (positive controls for the TOCTOU probe).
# Not release artifacts: Go `go build -trimpath`, Rust `cargo build --release --locked`.
# Usage: build-mutants.sh <scratch-root> <subject> [<subject> ...]   (e.g. T4-go-opus1.nocheck)
set -u
S=$1
shift
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly CARGO_NET_OFFLINE=true
for subj in "$@"; do
  case $subj in *-go-*) lang=go ;; *) lang=rust ;; esac
  W="$S/work/$lang"
  rsync -a --delete --exclude /target/ --exclude /dist/ "$S/src/$subj/" "$W/"
  find "$W" -path "$W/target" -prune -o -type f -exec touch {} +
  B="$S/bins/$subj/darwin-arm64"
  mkdir -p "$B"
  log="$S/logs/build-$subj.log"
  if [ "$lang" = go ]; then
    (cd "$W" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$B/heimdall-proto" ./cmd/heimdall-proto) > "$log" 2>&1
    rc=$?
  else
    (cd "$W" && cargo build --release --locked --target aarch64-apple-darwin) > "$log" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && cp "$W/target/aarch64-apple-darwin/release/heimdall-proto" "$B/heimdall-proto"
  fi
  printf '%s\t%s\t%s\n' "$subj" "$rc" "$(shasum -a 256 "$B/heimdall-proto" 2>/dev/null | awk '{print $1}')" >> "$S/logs/build-mutants.tsv"
  echo "done $subj rc=$rc" >&2
done
