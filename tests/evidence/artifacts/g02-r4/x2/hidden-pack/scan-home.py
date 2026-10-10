#!/usr/bin/env python3
"""Refuse to let a home path reach the evidence tree (fix round 2026-10-06).

usage: python3 -I -B scan-home.py PATH...

Scans every file under each PATH (bytes decoded as UTF-8 with replacement) for the home directory,
also where a terminal wrap, a JSON escape or a CSI sequence splits it (the same matcher as the run
records' scrub, common/hm.py), and for the bare user name.  Run it on anything before it is copied
to <repo>/tests/evidence.  Prints only relative file names and counts.  Exit status: 0 clean;
1 at least one hit; 2 usage error.
"""
import sys
sys.dont_write_bytecode = True   # importing common/hm.py must not create __pycache__ (home path)
import os  # noqa: E402
from pathlib import Path  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))
import hm  # noqa: E402


def main(argv):
    if not argv:
        print("usage: python3 -I -B scan-home.py PATH...", file=sys.stderr)
        return 2
    home = os.path.expanduser("~").rstrip("/")
    user = os.path.basename(home)
    if len(home) < 2:
        print("scan-home: HOME is not set", file=sys.stderr)
        return 2
    rx = hm._gappy(home)
    hits = files = 0
    for a in argv:
        root = Path(a)
        if not root.exists():
            print("scan-home: missing: %s" % root.name, file=sys.stderr)
            return 2
        for p in sorted([root] if root.is_file() else root.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            files += 1
            text = p.read_bytes().decode("utf-8", "replace")
            n_home = len(rx.findall(text))
            n_user = text.count(user) if len(user) >= 6 else 0
            if n_home or n_user:
                hits += 1
                rel = p.name if root.is_file() else str(p.relative_to(root))
                print("HIT %s: home path %d, user name %d" % (rel, n_home, n_user))
    print("scan-home: %d file(s), %d with a hit" % (files, hits))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
