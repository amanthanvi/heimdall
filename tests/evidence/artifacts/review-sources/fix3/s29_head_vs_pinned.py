#!/usr/bin/env python3
"""M00-T02-fix3: S29 (OpenTUI README). What differs between the pinned README and the README on HEAD, and which
quoted excerpt fragments are on each.

Usage (repository root): python3 -I -B s29_head_vs_pinned.py
Two GETs: the URL recorded in pins.json `upstream.url` and the pinned-commit URL the fetcher builds. The pinned body
must have the pinned blob sha1. Prints word-level differences (first 8 regions, 160 characters each) and, for every
quoted fragment, whether it is on HEAD and in the pinned copy.
"""
import difflib
import json
import sys

sys.path.insert(0, "docs/sources/tools")
import fetch_pins as fp  # noqa: E402

s = [x for x in json.load(open("docs/sources/pins.json"))["sources"] if x["id"] == "S29"][0]
head = fp.http_get(s["upstream"]["url"])
pinned = fp.http_get(fp.fetch_url_for(s))
print("HEAD   ", s["upstream"]["url"], head["status"], "blob", fp.git_blob_sha1(head["body"]))
print("pinned ", fp.fetch_url_for(s), pinned["status"], "blob", fp.git_blob_sha1(pinned["body"]),
      "equals the pin" if fp.git_blob_sha1(pinned["body"]) == s["pin"]["blob_sha"] else "DOES NOT EQUAL THE PIN")
h, p = head["body"].decode("utf-8", "replace"), pinned["body"].decode("utf-8", "replace")
for fr in fp.excerpt_fragments(s["excerpt"]):
    print("fragment on HEAD: %-5s in pinned copy: %-5s | %s" % (
        fp.contains_words(fp.loose(h), fr), fp.contains_words(fp.loose(p), fr), fr[:100]))
a, b = p.split(), h.split()
ops = [o for o in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if o[0] != "equal"]
print("words: pinned %d, HEAD %d, changed regions %d" % (len(a), len(b), len(ops)))
for tag, i1, i2, j1, j2 in ops[:8]:
    print(" ", tag, "PINNED:", repr(" ".join(a[i1:i2])[:160]), "HEAD:", repr(" ".join(b[j1:j2])[:160]))
