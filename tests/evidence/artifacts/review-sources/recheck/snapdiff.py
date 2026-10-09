#!/usr/bin/env python3
"""M00-T02-recheck: word-level diff of a committed normalized snapshot vs a fresh one.

Usage: python3 -I snapdiff.py <committed.txt.gz> <fresh.txt.gz> [max_ops]
Prints counts and up to max_ops (default 12) changed segments, each truncated
to 160 chars, so the classification (chrome vs content) can be judged without
dumping whole pages.
"""
import difflib, gzip, sys

a = gzip.open(sys.argv[1], "rb").read().decode("utf-8").split(" ")
b = gzip.open(sys.argv[2], "rb").read().decode("utf-8").split(" ")
mx = int(sys.argv[3]) if len(sys.argv) > 3 else 12
sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
ops = [o for o in sm.get_opcodes() if o[0] != "equal"]
print("words committed=%d fresh=%d changed_ops=%d ratio=%.4f" % (len(a), len(b), len(ops), sm.ratio()))
for tag, i1, i2, j1, j2 in ops[:mx]:
    ctx = " ".join(a[max(0, i1 - 6):i1])
    print("%s @%d ctx=[...%s]" % (tag, i1, ctx[-70:]))
    print("   - " + " ".join(a[i1:i2])[:160])
    print("   + " + " ".join(b[j1:j2])[:160])
