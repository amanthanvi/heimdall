"""Second redaction pass (after tests/native/wsl/evidence.py redact-tree): owner distribution names
in context and non-loopback private IPv4 addresses. usage: python3 -I redact_extra.py DIR NAME[=TOKEN]..."""
import os
import re
import sys

root, pairs = sys.argv[1], [a.split("=", 1) if "=" in a else (a, "<owner-distro>") for a in sys.argv[2:]]
# A distribution name is replaced only as a whole token that is not followed by a version number
# ("Ubuntu 24.04.5 LTS" and "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19" keep their OS names).
pats = [(re.compile(r"(?<![A-Za-z0-9._-])" + re.escape(n) + r"(?![A-Za-z0-9._-])(?!\s+\d)"), t) for n, t in pairs]
ip = re.compile(r"(?<![\d.])(?:10\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[01])|192\.168|169\.254|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}\.\d{1,3}(?![\d.])")
changed = 0
for d, _s, files in os.walk(root):
    for f in files:
        p = os.path.join(d, f)
        try:
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        new = text
        for rx, tok in pats:
            new = rx.sub(tok, new)
        new = ip.sub("<ip>", new)
        if new != text:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(new)
            changed += 1
print("redact_extra changed files: %d" % changed)
