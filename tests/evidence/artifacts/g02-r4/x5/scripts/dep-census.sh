#!/bin/sh
# Dependency census per variant x target (cargo tree, --locked, no network).
# all = unique packages in normal+build edges (excluding the root); normal = normal edges only;
# (native C/asm crates are listed by native_crates.py; see results/native-code-crates.txt)
set -u
cd "$(dirname "$0")/../rust-embed" || exit 1
for v in iroh-default iroh-ring-min iroh-awslc-min none; do
  F="--no-default-features"; [ "$v" != none ] && F="$F --features $v"
  for t in aarch64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-gnu; do
    all=$(cargo tree --locked -q $F --target $t -e normal,build --prefix none -f '{p}' | sed 's/ (\*)//; s/ (proc-macro)//; s/ (.*rust-embed)//' | sort -u | grep -v '^x5-iroh' | wc -l | tr -d ' ')
    nor=$(cargo tree --locked -q $F --target $t -e normal --prefix none -f '{p}' | sed 's/ (\*)//; s/ (proc-macro)//' | sort -u | grep -v '^x5-iroh' | wc -l | tr -d ' ')
    printf "%s\t%s\t%s\t%s\n" "$v" "$t" "$all" "$nor"
  done
done
