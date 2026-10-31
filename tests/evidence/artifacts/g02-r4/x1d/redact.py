#!/usr/bin/env python3
"""X1d redaction: copy a tree, replacing host identifiers by placeholders (byte level, so binary captures too).
Derived from ../x1c/redact.py; the identifier list is generic instead of the WSL-specific names.

usage: python3 -I redact.py scan <ids.json> <dir>          count identifier hits per file (no values printed)
       python3 -I redact.py copy <ids.json> <src> <dst>    copy src to dst with replacements, then rescan dst

ids.json (kept outside the repository) is a list of [placeholder, literal value, delimited] entries, applied in
order (paths first, so "<home>" absorbs the user name inside the home path). A delimited entry is replaced only
where it is not inside a longer [A-Za-z0-9] run, case-insensitively; the rescan counts every remaining occurrence,
delimited or not, so an undelimited leftover is reported and can be inspected.
"""
import json
import re
import sys
from pathlib import Path


def load_ids(p):
    return [(k, v.encode(), bool(d)) for k, v, d in json.loads(Path(p).read_text(encoding="utf-8")) if v]


def rx_for(v, delimited):
    if delimited:
        return re.compile(rb"(?<![A-Za-z0-9])" + re.escape(v) + rb"(?![A-Za-z0-9])", re.I)
    return re.compile(re.escape(v))


def scan(ids, root):
    tot = {}
    for f in sorted(Path(root).rglob("*")):
        if not f.is_file():
            continue
        b = f.read_bytes()
        hits = {}
        for k, v, _ in ids:
            n = len(re.findall(re.escape(v), b, re.I))
            if n:
                hits[k] = hits.get(k, 0) + n
                tot[k] = tot.get(k, 0) + n
        if hits:
            print(f"  {f.relative_to(root)}: {hits}")
    print(f"  total raw (case-insensitive, undelimited) hits: {tot or 0}")
    return tot


def copy(ids, src, dst):
    src, dst = Path(src), Path(dst)
    counts = {}
    for f in sorted(src.rglob("*")):
        out = dst / f.relative_to(src)
        if f.is_dir():
            out.mkdir(parents=True, exist_ok=True)
            continue
        b = f.read_bytes()
        for k, v, d in ids:
            b, n = rx_for(v, d).subn(b"<" + k.encode() + b">", b)
            if n:
                counts[k] = counts.get(k, 0) + n
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b)
    print(f"  replacements: {counts or 0}")
    print("  rescan of the copy:")
    return scan(ids, dst)


def main():
    mode, ids = sys.argv[1], load_ids(sys.argv[2])
    if mode == "scan":
        scan(ids, sys.argv[3])
    elif mode == "copy":
        left = copy(ids, sys.argv[3], sys.argv[4])
        sys.exit(1 if left else 0)
    else:
        sys.exit("usage: see module docstring")


if __name__ == "__main__":
    main()
