#!/usr/bin/env python3
"""M00-T02-recheck: rebuild PowerShell/openssh-portable LICENCE at e581929 from the
GitHub blob page (listed in pins.json) and hash it. Usage: python3 -I <this> <page.html> <pins.json>"""
import hashlib, json, sys
h = open(sys.argv[1], encoding="utf-8").read()
k = '"rawLines":'
arr, _ = json.JSONDecoder().raw_decode(h[h.index(k) + len(k):])
b = ("\n".join(arr) + "\n").encode("utf-8")
w = json.load(open(sys.argv[2]))["candidates"]["win32_openssh"]
r = {"lines": len(arr), "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest(),
     "git_blob_sha1": hashlib.sha1(b"blob %d\0" % len(b) + b).hexdigest()}
r["matches_pin"] = r["bytes"] == w["license_file_bytes"] and r["sha256"] == w["license_file_raw_sha256"] and r["git_blob_sha1"] == w["license_file_blob_sha1"]
print(json.dumps(r, indent=1))
sys.exit(0 if r["matches_pin"] else 1)
