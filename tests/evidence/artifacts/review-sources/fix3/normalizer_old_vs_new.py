#!/usr/bin/env python3
"""M00-T02-fix3 (n4): does the revised normalizer give the same text as the committed one (3622c56)
for every pinned source as the pages are served now?

Usage (repository root): python3 -I -B normalizer_old_vs_new.py <scratch_dir>
  - The old module is taken from `git show 3622c56:docs/sources/tools/fetch_pins.py` into <scratch_dir>
    and loaded from there (nothing is written into the repository).
  - Each of the 38 sources (S01-S34 and A01-A04) is fetched once, with the revised tool's fetch_url_for()
    and http_get() (GET, https only). The body is normalized by both modules; hashes are compared.
  - Offline part: synthetic documents, old versus new, for the head cases of the selftest.
Exit 0 = no difference on any live source; 1 = a difference or a fetch that failed.
"""
import importlib.util
import json
import os
import subprocess
import sys

scr = sys.argv[1]
os.makedirs(scr, exist_ok=True)
old_path = os.path.join(scr, "fetch_pins_3622c56.py")
with open(old_path, "wb") as f:
    f.write(subprocess.run(["git", "show", "3622c56:docs/sources/tools/fetch_pins.py"], check=True, capture_output=True).stdout)
sys.path.insert(0, "docs/sources/tools")
import fetch_pins as new  # noqa: E402

spec = importlib.util.spec_from_file_location("fetch_pins_old", old_path)
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)

print("python", sys.version.split()[0])
bad = 0
pins = json.load(open("docs/sources/pins.json"))
for s in pins["sources"] + pins["auxiliary_sources"]:
    url = new.fetch_url_for(s)
    r = new.http_get(url)
    if r["status"] != 200:
        print(s["id"], "FETCH", r["status"], r.get("error", ""))
        bad += 1
        continue
    ct = r["headers"].get("content-type", "")
    a, b = old.normalize(r["body"], ct, url), new.normalize(r["body"], ct, url)
    same = a == b
    bad += 0 if same else 1
    print(s["id"], "html" if "html" in ct.lower() else "other", "chars old=%d new=%d" % (len(a), len(b)),
          "SAME" if same else "DIFFERENT")

print("-- synthetic documents (old -> new)")
docs = {
    "closed head": b"<html><head><title>T</title></head><body><p>Hello</p></body></html>",
    "closed head with a stray div": b"<head><title>t</title><div>stray</div></head><body><p>x</p></body>",
    "no head": b"<html><body><p>a</p></body></html>",
    "head without </head>, with <body>": b"<html><head><title>t</title><body><p>Hello world</p></body></html>",
    "head without </head>, no <body>": b"<html><head><title>t</title><link rel=x><p>Para</p>",
}
for name, body in docs.items():
    a, b = old.normalize(body, "text/html", "u"), new.normalize(body, "text/html", "u")
    print("%-36s old=%r new=%r %s" % (name, a, b, "same" if a == b else "changed"))
sys.exit(1 if bad else 0)
