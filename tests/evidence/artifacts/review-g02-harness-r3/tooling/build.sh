#!/bin/sh
# build.sh NAME MUTS  -> /tmp/r3rev/m/NAME/heimdall-proto with MUT baked in (comma list, may be empty)
set -eu
name=$1; muts=${2:-}
d=/tmp/r3rev/m/$name
mkdir -p "$d"
python3 - "$muts" /tmp/r3rev/patched/reference_impl.py "$d/heimdall-proto" <<'PY'
import sys
muts, src, dst = sys.argv[1:4]
t = open(src).read()
old = 'MUT = set(x for x in os.environ.get("REF_MUTATE", "").split(",") if x)'
assert t.count(old) == 1
t = t.replace(old, "MUT = set(%r)" % [x for x in muts.split(",") if x])
open(dst, "w").write(t)
PY
cp /tmp/r3rev/patched/reference_tui.py "$d/"
chmod 755 "$d" "$d/heimdall-proto"; chmod 644 "$d/reference_tui.py"
