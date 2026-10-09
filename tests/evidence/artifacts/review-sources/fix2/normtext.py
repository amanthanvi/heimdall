#!/usr/bin/env python3
"""M00-T02-fix2 helper: normalize saved bodies with the committed fetcher's
normalizer (docs/sources/tools/fetch_pins.py, NORMALIZER_VERSION 1) and print
the window of normalized text around each search term.

Usage: python3 -I normtext.py <repo_root> <content_type> <body_file> <url> [term ...]
"""
import hashlib
import importlib.util
import os
import sys

root, ct, path, url = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("fetch_pins", os.path.join(root, "docs/sources/tools/fetch_pins.py"))
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
body = open(path, "rb").read()
norm = fp.normalize(body, ct, url)
print("normalized_sha256", hashlib.sha256(norm.encode("utf-8")).hexdigest(), "chars", len(norm))
for term in sys.argv[5:]:
    i = norm.find(term)
    print("--- term %r at %d" % (term, i))
    if i >= 0:
        print(norm[max(0, i - 200): i + 700])
