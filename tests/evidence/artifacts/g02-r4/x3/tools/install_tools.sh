#!/bin/sh
# Pinned, user-level tool installs for X3. Everything under /tmp/hm-r4/tools/x3.
T=/tmp/hm-r4/tools/x3
L=$T/logs
export GOBIN=$T/bin GOMODCACHE=$T/gomodcache GOPATH=$T/gopath GOFLAGS=-mod=mod GOTOOLCHAIN=local
for p in golang.org/x/vuln/cmd/govulncheck@v1.8.0 github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0 github.com/google/go-licenses/v2@v2.0.1 github.com/goreleaser/goreleaser/v2@v2.18.2; do
  n=$(echo "$p" | sed 's#.*/##; s#@.*##')
  go install "$p" >"$L/go-$n.log" 2>&1; echo "go install $p exit=$?" >>"$L/summary.txt"
done
export CARGO_HOME=$T/cargo-home CARGO_TARGET_DIR=$T/cargo-build
for c in cargo-audit@0.22.2 cargo-deny@0.20.2 cargo-cyclonedx@0.5.9 cargo-fuzz@0.13.2 cargo-zigbuild@0.23.4 cargo-about@0.9.2 cargo-auditable@0.7.7 cargo-dist@0.32.0 cargo-geiger@0.13.0; do
  n=${c%@*}; v=${c#*@}
  cargo install --locked --root "$T" "$n" --version "$v" >"$L/cargo-$n.log" 2>&1; echo "cargo install $n $v exit=$?" >>"$L/summary.txt"
done
echo DONE >>"$L/summary.txt"
