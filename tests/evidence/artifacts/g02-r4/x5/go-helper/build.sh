#!/bin/sh
# Build x5-gosup for the four contract targets. CGO disabled, -trimpath, stdlib only.
# Usage: build.sh <out-dir>
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
OUT=${1:?out dir}; mkdir -p "$OUT"
cd "$HERE" || exit 1
for gt in darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do
  os=${gt%/*}; arch=${gt#*/}; exe=x5-gosup; [ "$os" = windows ] && exe=x5-gosup.exe
  mkdir -p "$OUT/$os-$arch"
  s=$(date -u +%s)
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOTOOLCHAIN=local go build -trimpath -ldflags='-s -w -buildid=' -o "$OUT/$os-$arch/$exe" . 
  rc=$?; e=$(date -u +%s)
  bytes=-; sha=-
  [ $rc -eq 0 ] && bytes=$(wc -c < "$OUT/$os-$arch/$exe" | tr -d ' ') && sha=$(shasum -a 256 "$OUT/$os-$arch/$exe" | cut -d' ' -f1)
  printf '%s\t%s\t%s\t%s\t%s\n' "$os-$arch" "$rc" "$((e-s))" "$bytes" "$sha" | tee -a "$OUT/results.tsv"
done
