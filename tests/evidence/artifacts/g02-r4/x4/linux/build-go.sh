#!/bin/bash
# Runs inside golang:1.27.1-bookworm (linux/arm64). /src = copy of ./go, /out = scratch.
set -u
go version
export GOCACHE=/out/gocache GOMODCACHE=/out/gomod GOFLAGS=-mod=readonly
cd /src
echo "=== default env (CGO_ENABLED unset; gcc present: $(command -v gcc >/dev/null && echo yes || echo no)) ==="
go env CGO_ENABLED
( time go build -trimpath -ldflags='-s -w' -o /out/go-default . ) 2>&1 | grep -E 'real|error'; echo "exit=${PIPESTATUS[0]}"
echo "=== CGO_ENABLED=0 ==="
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/go-cgo0 . ; echo "exit=$?"
CGO_ENABLED=0 go build -tags nobackends -trimpath -ldflags='-s -w' -o /out/go-cgo0-baseline . ; echo "exit=$?"
echo "=== default env, baseline ==="
go build -tags nobackends -trimpath -ldflags='-s -w' -o /out/go-default-baseline . ; echo "exit=$?"
echo "=== default env, netgo+osusergo tags ==="
go build -tags netgo,osusergo -trimpath -ldflags='-s -w' -o /out/go-tags . ; echo "exit=$?"
ls -l /out/go-*
for f in go-default go-cgo0 go-tags; do echo "LDD $f: $(ldd /out/$f 2>&1 | head -1 | tr -s ' \t' ' ')"; done
