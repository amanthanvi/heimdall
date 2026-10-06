#!/bin/sh
export PATH=/tmp/hm-r4/tools/x3/bin:$PATH
date -u; go version; rustc --version; cargo --version; echo "zig $(zig version)"
for c in "govulncheck -version" "cyclonedx-gomod version" "goreleaser --version" "cargo audit --version" "cargo deny --version" "cargo cyclonedx --version" "cargo fuzz --version" "cargo zigbuild --version" "cargo auditable --version" "cargo about --version" "dist --version" "cargo geiger --version" "syft version"; do
  echo "--- $c"; $c 2>&1 | grep -v '^ *$' | grep -iv 'usage\|__\|/ \|\\' | head -5
done
echo "--- go-licenses: installed via go install github.com/google/go-licenses/v2@v2.0.1 (no version subcommand)"
echo "--- syft is the pre-existing Homebrew install (not pinned by this task)"
