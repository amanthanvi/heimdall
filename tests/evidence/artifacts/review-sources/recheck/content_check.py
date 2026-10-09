#!/usr/bin/env python3
"""M00-T02-recheck: check finding-specific claims against fetched bodies and committed snapshots.

Usage: python3 -I content_check.py <repo_root> <content_dir>
Bodies are untrusted data; this only searches for fixed phrases and hashes.
Phrase search uses a loose form: lowercase, curly quotes -> straight,
markdown emphasis/backticks removed, whitespace collapsed.
"""
import base64, gzip, hashlib, io, json, os, re, sys, tarfile

root, cdir = sys.argv[1], sys.argv[2]
def loose(t):
    # v2 of the matcher: also ignore quote style, link brackets, the space that the
    # normalizer inserts before ':' at tag boundaries, and GitHub's JSON line joins.
    t = t.replace('","', " ")
    t = re.sub(r"[*`_\[\]'\"‘’“”]", "", t)
    t = re.sub(r"\s+([:;,.])", r"\1", t)
    return " ".join(t.lower().split())
def snap(i):
    return gzip.open(os.path.join(root, "docs/sources/snapshots", i + ".txt.gz"), "rb").read().decode("utf-8")
def body(n):
    return open(os.path.join(cdir, n), "rb").read()
res = []
def chk(label, text, phrase, expect=True):
    hit = loose(phrase) in loose(text)
    res.append({"check": label, "phrase": phrase[:90], "found": hit, "expected": expect, "ok": hit == expect})

# S26 / S31 misattribution (snapshots; live .md is 403 from this host)
s26, s31 = snap("S26"), snap("S31")
chk("S26 snapshot lacks v1 quote", s26, "Be very specific about your end goal", False)
chk("S31 snapshot has the quote", s31, "Be very specific about your end goal", True)
chk("S26 snapshot section", s26, "Initiative and follow-through")
chk("S26 snapshot section", s26, "Testing and verification")
chk("S26 snapshot quote", s26, "unclear or conflicting guidance in a skill file may cause the model to pause and block work early")
chk("S26 snapshot quote", s26, "Make the priority of user instructions and skills explicit")
chk("S26 snapshot quote", s26, "complete all the necessary work until the intended outcome is fulfilled")
pins = json.load(open(os.path.join(root, "docs/sources/pins.json")))
by = {s["id"]: s for s in pins["sources"]}
res.append({"check": "pins.json S26 excerpt free of v1 quote", "found": "end goal" in by["S26"]["excerpt"].lower(), "expected": False,
            "ok": "end goal" not in by["S26"]["excerpt"].lower(), "phrase": "end goal"})
# every double-quoted fragment in pins.json S26/S31/S07/S22/S19 excerpts must occur in its pinned copy
def frags(ex):
    return [f for f in re.findall(r'"([^"]{12,})"', ex)]
copies = {"S26": s26, "S31": s31, "S07": snap("S07"), "S22": snap("S22"), "S06": snap("S06")}
copies["S19"] = body("S19").decode("utf-8")
for i, txt in copies.items():
    for f in frags(by[i]["excerpt"]):
        for part in re.split(r"\s*(?:\.\.\.|…)\s*", f):
            if len(part) >= 12:
                chk("pins.json %s excerpt fragment in pinned copy" % i, txt, part)

# E1 / S07
s07 = snap("S07")
chk("S07 timed option", s07, "You can choose from 4, 12, or 24 hours")
chk("S07 approvals remain while locked", s07, "even when 1Password is locked")
chk("S07 unlock still needed", s07, "you'll be prompted to unlock 1Password so the SSH agent can access your private key")
res.append({"check": "pins.json S07 note no longer says spec untrue", "phrase": by["S07"]["note"][:200], "found": None, "expected": None,
            "ok": "not for approvals" not in by["S07"]["note"].lower()})

# S22
s22 = snap("S22")
chk("S22 no Intel build", s22, "arm64 (no Intel build)")
chk("S22 n0 preset default", s22, "Endpoint.bind applies the n0 preset")

# Pigeons S19 behaviours (README at pinned commit)
s19 = body("S19").decode("utf-8")
res.append({"check": "S19 body git blob sha1 == pin", "found": hashlib.sha1(b"blob %d\0" % len(body("S19")) + body("S19")).hexdigest() == by["S19"]["pin"]["blob_sha"], "expected": True, "phrase": "", "ok": None})
res[-1]["ok"] = res[-1]["found"]
for p in ["Nothing is sent unless it is", "sampled once a minute", "the sending endpoint ID is visible to the collector",
          "pigeons service install", "runs as root", "added to ~/.ssh/config", "pigeons_ed25519",
          "anyone holding the endpoint ID can reach your SSH port", "pigeons fly --stdio", "/etc/pigeons/config.toml",
          "ProgramData", "systemd", "launchd"]:
    chk("S19 README", s19, p)
chk("S19 README telemetry asks once (ADR line 84 wording)", s19, "asks once")

# S29 OpenTUI README
s29 = body("S29").decode("utf-8")
for p in ["Bun", "Zig"]:
    chk("S29 README", s29, p)
m = re.findall(r"(?i)(bun[^\n]{0,40}1\.4\.1|zig[^\n]{0,40}0\.16)", s29)
res.append({"check": "S29 README Bun 1.4.1 / Zig 0.16 strings", "phrase": "; ".join(m)[:160], "found": bool(m), "expected": True, "ok": bool(m)})

# S27 Bubble Tea README import path
chk("S27 README import path", body("S27").decode("utf-8"), 'charm.land/bubbletea/v2')

# S17 drift
a, b = body("S17pin"), body("S17main")
blob = lambda x: hashlib.sha1(b"blob %d\0" % len(x) + x).hexdigest()
res.append({"check": "S17 pinned blob", "phrase": blob(a), "found": blob(a) == by["S17"]["pin"]["blob_sha"], "expected": True, "ok": blob(a) == by["S17"]["pin"]["blob_sha"]})
res.append({"check": "S17 main blob today (drift note says 35c8b0a at 2026-10-03)", "phrase": blob(b), "found": blob(b).startswith("35c8b0a"), "expected": None, "ok": None})

# openssh-portable LICENCE page at e581929 (HTML; GitHub embeds the file text)
lic = body("LICENCEpage").decode("utf-8", "replace")
chk("LICENCE page at e581929", lic, "all components are under a BSD licence, or a licence more free than that")
chk("LICENCE page at e581929", lic, "OpenSSH contains no GPL code")
chk("LICENCE page path is LICENCE", lic, "openssh-portable/blob/e581929d3d0cf44e033e47bf3b75a2544918b87e/LICENCE")

# Go proxy v2.0.10 origin
info = json.loads(body("bt_info"))
res.append({"check": "Go proxy v2.0.10 info", "phrase": json.dumps(info)[:200], "found": str(info.get("Origin", {}).get("Hash", "")).startswith("d5bfd5c"), "expected": True,
            "ok": str(info.get("Origin", {}).get("Hash", "")).startswith("d5bfd5c") and info.get("Version") == "v2.0.10"})

# npm tarball: integrity, shasum, engines, exports, license, deps
tgz = body("opentui_tgz")
integ = "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode()
core = pins["candidates"]["opentui"]["npm"]["@opentui/core"]
res.append({"check": "npm @opentui/core 0.5.14 integrity == pin", "phrase": integ[:40], "found": integ == core["integrity"], "expected": True, "ok": integ == core["integrity"]})
res.append({"check": "npm @opentui/core 0.5.14 shasum == pin", "phrase": hashlib.sha1(tgz).hexdigest(), "found": hashlib.sha1(tgz).hexdigest() == core["shasum"], "expected": True, "ok": hashlib.sha1(tgz).hexdigest() == core["shasum"]})
with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tf:
    pj = json.load(tf.extractfile("package/package.json"))
facts = {"version": pj.get("version"), "license": pj.get("license"), "engines": pj.get("engines"),
         "exports_dot": pj.get("exports", {}).get(".") if isinstance(pj.get("exports"), dict) else None,
         "main": pj.get("main"), "optionalDependencies": sorted((pj.get("optionalDependencies") or {}).keys()),
         "dependencies": pj.get("dependencies"), "peerDependencies": pj.get("peerDependencies")}
res.append({"check": "npm tarball package.json facts", "phrase": json.dumps(facts)[:900], "found": None, "expected": None,
            "ok": facts["engines"] == core["engines"] and facts["license"] == "MIT" and facts["version"] == "0.5.14"
                  and sorted(core["optional_platform_packages"]) == facts["optionalDependencies"]})

print(json.dumps(res, indent=1))
bad = [r for r in res if r["ok"] is False]
print("checks=%d ok=%d failed=%d informational=%d" % (len(res), sum(r["ok"] is True for r in res), len(bad), sum(r["ok"] is None for r in res)))
sys.exit(1 if bad else 0)
