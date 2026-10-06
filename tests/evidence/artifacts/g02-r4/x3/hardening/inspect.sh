#!/bin/sh
# Runs inside debian:bookworm-slim (linux/arm64). Artifacts mounted read-only at /a.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends checksec binutils file >/dev/null 2>&1
echo "apt rc=$?"
echo "checksec: $(dpkg-query -W -f='${Version}' checksec) binutils: $(dpkg-query -W -f='${Version}' binutils) file: $(dpkg-query -W -f='${Version}' file)"
for f in /a/*; do
  n=$(basename "$f")
  echo "=================== $n"
  file -b "$f"
  checksec --output=json --file="$f" 2>&1
  echo; echo "-- ELF type: $(readelf -h "$f" | awk -F: '/Type:/{gsub(/^ +/,"",$2);print $2}')"
  echo "-- program headers (RELRO/STACK/INTERP/LOAD flags):"; readelf -lW "$f" | grep -E 'GNU_RELRO|GNU_STACK|INTERP|GNU_PROPERTY' 
  echo "-- dynamic BIND_NOW/FLAGS:"; readelf -dW "$f" 2>/dev/null | grep -E 'BIND_NOW|FLAGS|NEEDED' || echo "(no dynamic section)"
  echo "-- notes (AArch64 BTI/PAC property):"; readelf -nW "$f" 2>/dev/null | grep -iE 'AArch64 feature|x86 feature|Properties' || echo "(none)"
  case $(readelf -h "$f" | awk '/Machine:/{print $2}') in
    AArch64) objdump -d --no-show-raw-insn "$f" > /tmp/dis.txt 2>/dev/null
      echo "-- insn counts: paciasp=$(grep -cw paciasp /tmp/dis.txt) autiasp=$(grep -cw autiasp /tmp/dis.txt) bti=$(grep -cE '\sbti(\s|$)' /tmp/dis.txt) total_lines=$(wc -l </tmp/dis.txt)";;
  esac
done
# canary symbol references (only meaningful for unstripped binaries)
for f in /a/*unstripped*; do echo "-- $(basename $f): __stack_chk_fail symbol refs: $(nm "$f" 2>/dev/null | grep -c '__stack_chk_fail') ; bl __stack_chk_fail call sites: $(objdump -d --no-show-raw-insn "$f" 2>/dev/null | grep -c 'bl.*<__stack_chk_fail')"; done
