#!/usr/bin/env python3
"""Read `cargo ... --message-format=json` on stdin; print test executables.
Arg: "all" (every test executable) or a target name (e.g. "cli")."""
import json
import sys

want = sys.argv[1] if len(sys.argv) > 1 else "all"
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact" or not m.get("executable") or not m["profile"].get("test"):
        continue
    if want == "all" or m["target"]["name"] == want:
        print(m["executable"])
