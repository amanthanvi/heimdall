#!/bin/bash
# X1 linux-x64: each artifact under env -i with (a) PATH=/usr/bin:/bin and (b) an empty PATH directory.
T=$HOME/hm-m00/M00-T05-x1-g02-native
F=$T/repo/tests/fixtures/g02/profiles
E=$T/empty-path; mkdir -p "$E"
echo "toolchain binaries present in /usr/bin:/bin (env -i PATH=/usr/bin:/bin does not hide them):"
for t in go gofmt cargo rustc gcc cc clang node bun deno; do for d in /usr/bin /bin; do [ -x "$d/$t" ] && echo "  $d/$t"; done; done | sort -u
for c in go rust; do
  B=$T/art/$c/heimdall-proto
  echo "=== $c sha256 $(sha256sum "$B" | cut -c1-64)"
  echo "ldd: $(ldd "$B" 2>&1 | head -1)"
  for P in /usr/bin:/bin "$E"; do
    lbl=$P; [ "$P" = "$E" ] && lbl="<empty dir>"
    echo "--- PATH=$lbl"
    out=$(cd "$E" && env -i PATH="$P" "$B" version --json 2>&1); echo "version --json rc=$? $out"
    out=$(cd "$E" && env -i PATH="$P" "$B" profile show --file "$F/homelab.toml" --json 2>&1); echo "profile show homelab rc=$? bytes=${#out} code=$(echo "$out" | grep -o '"code":"[A-Z_]*"')"
    out=$(cd "$E" && env -i PATH="$P" "$B" profile show --file "$F/spaced dir ü/prøfile homelab.toml" --json 2>&1); echo "profile show spaced rc=$? code=$(echo "$out" | grep -o '"code":"[A-Z_]*"')"
    out=$(cd "$E" && env -i PATH="$P" "$B" profile show --file "$F/invalid-forbidden-key.toml" --json 2>&1); rc=$?; echo "profile show forbidden-key rc=$rc code=$(echo "$out" | grep -o '"code":"[A-Z_]*"') canary_prefix_hits=$(echo "$out" | grep -c HEIMDALL_CANARY_)"
    out=$(cd "$E" && env -i PATH="$P" "$B" run -- /bin/sh -c 'exit 7' 2>&1); echo "run -- /bin/sh -c 'exit 7' rc=$? out_bytes=${#out}"
    out=$(cd "$E" && env -i PATH="$P" "$B" run -- true 2>&1); echo "run -- true (PATH lookup) rc=$? stderr=${out:0:120}"
    out=$(cd "$E" && env -i PATH="$P" "$B" agent list --socket "$E/no-such.sock" --json 2>&1); echo "agent list missing socket rc=$? code=$(echo "$out" | grep -o '"code":"[A-Z_]*"')"
  done
done
rmdir "$E"
