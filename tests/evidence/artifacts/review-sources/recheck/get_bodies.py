#!/usr/bin/env python3
"""M00-T02-recheck: GET listed URLs and save raw bodies to a temp dir outside the repo.

Usage: python3 -I get_bodies.py <outdir> <ua-label> <name>=<url> [...]
ua-label: 'pins' (the committed fetcher's UA) or 'curl' ('curl/8.7.1').
Prints one JSON line per URL: name, url, status, final_url, bytes, raw sha256,
selected headers (content-type, last-modified, cf-mitigated, server). GET only.
"""
import hashlib, json, os, sys, urllib.error, urllib.request

UAS = {"pins": "heimdall-source-pins/1 (read-only GET; M00-T02-fix)", "curl": "curl/8.7.1"}
KEEP = ("content-type", "last-modified", "cf-mitigated", "server", "etag")
outdir, ua = sys.argv[1], UAS[sys.argv[2]]
os.makedirs(outdir, exist_ok=True)
for arg in sys.argv[3:]:
    name, url = arg.split("=", 1)
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "identity"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            st, fu, hd, body = r.status, r.geturl(), r.headers, r.read()
    except urllib.error.HTTPError as e:
        st, fu, hd, body = e.code, url, e.headers, e.read()
    with open(os.path.join(outdir, name), "wb") as f:
        f.write(body)
    print(json.dumps({"name": name, "url": url, "ua": sys.argv[2], "status": st, "final_url": fu, "bytes": len(body),
                      "raw_sha256": hashlib.sha256(body).hexdigest(),
                      "headers": {k.lower(): v for k, v in hd.items() if k.lower() in KEEP}}))
