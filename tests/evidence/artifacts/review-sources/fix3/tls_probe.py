#!/usr/bin/env python3
"""M00-T02-fix3: diagnose why `fetch` could not reach man.openbsd.org and www.openssh.org under one interpreter.

Usage: <python> -I -B tls_probe.py        (one GET each to three URLs that are listed in pins.json)
Prints the interpreter, its OpenSSL version, and for each URL either the HTTP status or the exception class and
reason. No request bodies, no credentials, https only.
"""
import ssl
import sys
import urllib.request

URLS = [
    "https://man.openbsd.org/ssh_config",                    # S01
    "https://www.openssh.org/agent-restrict.html",           # S03
    "https://www.1password.dev/ssh/agent/security",          # S06 (control)
]
print("python", sys.version.split()[0], "|", ssl.OPENSSL_VERSION)
for u in URLS:
    req = urllib.request.Request(u, headers={"User-Agent": "heimdall-source-pins/1 (read-only GET; M00-T02-fix3 TLS probe)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            print(u, "HTTP", r.status, len(r.read()), "bytes")
    except Exception as e:
        print(u, "FAILED", type(e).__name__, getattr(e, "reason", ""))
