#!/bin/bash
# M00-T05-r4-x2-xrev-T3: (1) K2 - a control character in a profile value is rejected before the TUI starts, so
# a sanitised (U+FFFD) value can never reach the highlight (go-sonnet1 reviewer item D12); (2) where the stray
# tools/__pycache__/inventory.*.pyc of rust-opus2 (D17) comes from.
# Usage: bash k2_pyc_check.sh <bins-dir> <repo-root>    (prints to stdout)
set -u
BINS=$1; R=$2
d=$(mktemp -d)
printf 'schema_version = 1\nname = "k2"\nrevision = 1\n\n[[destinations]]\nid = "d1"\nalias = "a\\u0007b"\nhost = "h.example"\naccount = "u"\n' > "$d/ctl.toml"
echo "# K2: alias holds U+0007 (TOML escape). profile show --json: code, key_path, exit status. tui (under script(1)): the SCHEMA_INVALID stderr line"
for b in T3-go-opus1 T3-go-opus2 T3-go-sonnet1 T3-rust-opus1 T3-rust-opus2 T3-rust-sonnet1; do
  out=$("$BINS/$b/heimdall-proto" profile show --file "$d/ctl.toml" --json </dev/null 2>/dev/null); rc=$?
  code=$(printf '%s' "$out" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["code"], d["data"]["error"]["key_path"])')
  err=$(script -q /dev/null "$BINS/$b/heimdall-proto" tui --file "$d/ctl.toml" </dev/null 2>&1 | tr -d '\r' | grep -o 'SCHEMA_INVALID.*' | head -1)
  echo "$b profile_show: $code exit=$rc | tui: $err"
done
rm -rf "$d"
echo "# rust build.sh (001a791): $(git -C "$R" show 001a791:prototypes/rust/build.sh | grep -n 'python3 tools/gen_notices.py' | head -1)"
echo "# tools/gen_notices.py (001a791): $(git -C "$R" show 001a791:prototypes/rust/tools/gen_notices.py | grep -n '^import inventory')"
echo "# git check-ignore: $(git -C "$R" check-ignore -v prototypes/rust/tools/__pycache__/inventory.cpython-314.pyc)"
