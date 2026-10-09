#!/usr/bin/env python3
"""M00-T02-fix2 helper: HTTP GET each URL, save the raw body under <outdir>/<name>,
print one JSON line per URL (name, url, status, final_url, bytes, sha256,
content-type, last-modified). GET only, no credentials, stdlib only.

Usage: python3 -I get.py <outdir> <name>=<url> [...]
"""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

UA = "heimdall-source-pins/1 (read-only GET; M00-T02-fix2)"


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    rc = 0
    for arg in sys.argv[2:]:
        name, url = arg.split("=", 1)
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                st, fu, hd, body = r.status, r.geturl(), r.headers, r.read()
        except urllib.error.HTTPError as e:
            st, fu, hd, body = e.code, url, e.headers, e.read()
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(body)
        if st != 200:
            rc = 1
        print(json.dumps({"name": name, "url": url, "status": st, "final_url": fu, "bytes": len(body),
                          "sha256": hashlib.sha256(body).hexdigest(),
                          "content_type": hd.get("content-type"), "last_modified": hd.get("last-modified")}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
