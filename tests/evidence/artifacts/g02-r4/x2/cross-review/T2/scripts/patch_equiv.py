#!/usr/bin/env python3
"""Compare the evaluator's change.patch (diff -ruN base/prototypes/<lang> frozen/<lang>) with the
implementer's diff.patch (git diff a/prototypes/<lang>/...) file by file: same files, and the same
multiset of added and removed lines in each file (diff -u and git diff group change blocks
differently, so the order inside a block can differ). Headers and context lines are ignored.

usage: python3 -I patch_equiv.py CHANGE.patch DIFF.patch
"""
import re
import sys


def parse(path):
    files = {}
    cur = None
    for raw in open(path, encoding="utf-8", errors="surrogateescape").read().splitlines():
        if raw.startswith("diff "):
            m = re.search(r"(?:frozen|b)/(?:prototypes/)?(?:go|rust)/(\S+)\s*$", raw)
            cur = m.group(1) if m else raw
            files.setdefault(cur, [])
            continue
        if cur is None or raw.startswith(("--- ", "+++ ", "@@", "index ", "new file", "deleted file", "\\ No newline")):
            continue
        if raw[:1] in "+-":
            files[cur].append(raw)
    return files


a, b = parse(sys.argv[1]), parse(sys.argv[2])
ok = True
for f in sorted(set(a) | set(b)):
    if sorted(a.get(f, [])) != sorted(b.get(f, [])):
        ok = False
        print("DIFFERS:", f, "change.patch lines=%s diff.patch lines=%s" % (len(a.get(f, [])), len(b.get(f, []))))
print("files:", len(a), len(b), "equivalent" if ok else "NOT equivalent")
sys.exit(0 if ok else 1)
