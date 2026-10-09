"""Offline exit-code honesty probes for fetch_pins.py (recheck2). Uses the tool's own functions."""
import copy, importlib.util, json, sys
tool, pins_path, run1 = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("fp", tool)
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
pins = json.load(open(pins_path))
prim = fp.primary_pins(pins)
base = {x["id"]: x for x in json.load(open(run1))["results"]}

def run(name, A, B):
    counts, lines = fp.compare_results(A, B, prim)
    rc = fp.compare_exit(counts)
    shown = [ln for cls, ln in lines if cls != fp.IDENTICAL or "primary_same=no" in ln]
    print("[%s] exit=%d counts=%s" % (name, rc, {k: v for k, v in counts.items() if v}))
    for ln in shown:
        print("     ", ln)

# H1: raw-primary man page, raw bytes change, visible text identical (e.g. markup/CSS change)
A = {"S01": base["S01"]}
B = {"S01": dict(base["S01"], raw_body_sha256="0" * 64)}
run("H1 raw-primary S01 raw-only change", A, B)
# H2: same, plus the Last-Modified-style marker moves
B2 = {"S03": dict(base["S03"], raw_body_sha256="0" * 64, markers=dict(base["S03"]["markers"], http_last_modified="Thu, 01 Jan 2027 00:00:00 GMT"))}
run("H2 raw-primary S03 raw+marker change", {"S03": base["S03"]}, B2)
# H3: a cited page is removed (HTTP 404 / 410), persistent
run("H3 S13 page gone (404)", {"S13": base["S13"]}, {"S13": dict(base["S13"], http_status=404, normalized_text_sha256="x")})
# H4: both files are fresh runs (neither is the baseline); S26 differs from its pin in both
run("H4 fresh-vs-fresh, S26/S28 off-pin", {"S26": base["S26"], "S28": base["S28"]}, {"S26": base["S26"], "S28": base["S28"]})
# H5: GitHub source at pinned commit serves different bytes (integrity failure)
run("H5 S16 blob mismatch", {"S16": base["S16"]}, {"S16": dict(base["S16"], raw_body_sha256="1" * 64, git_blob_matches_pin=False)})

# H6: normalizer ignores text inside <template>/<noscript>; a change there is RAW_ONLY
pa = b"<html><head><title>t</title></head><body><p>Keys stay locked.</p><template>Keys never leave the vault.</template></body></html>"
pb = b"<html><head><title>t</title></head><body><p>Keys stay locked.</p><template>Keys may leave the vault.</template></body></html>"
na, nb = fp.normalize(pa, "text/html", "u"), fp.normalize(pb, "text/html", "u")
print("[H6] template-only change: normalized equal =", na == nb, "| raw equal =", pa == pb)
# H7: HTML that omits the optional </head> end tag: every body word is dropped
ph = b"<html><head><title>t</title><body><p>Agent forwarding is disabled by default.</p></body></html>"
print("[H7] no </head>: normalized text =", repr(fp.normalize(ph, "text/html", "u")))

# H8: upstream exit for drift with zero quoted fragments, and with 1 of 1 kept
print("[H8] upstream drift 0/0 fragments -> exit", fp.upstream_exit([{"result": "drifted", "fragments_found": 0, "fragments_total": 0}]))
print("[H8] upstream drift 1/1 fragments -> exit", fp.upstream_exit([{"result": "drifted", "fragments_found": 1, "fragments_total": 1}]))
# H9: upstream file deleted on the branch (404) -> fetch_failed
print("[H9] upstream 404 (file removed on branch) -> exit", fp.upstream_exit([{"result": "fetch_failed"}]))

# H10: excerpt matching has no word boundary
frag, copy_txt = "is not permitted by default", "this is not permitted by defaults"
print("[H10] fragment %r found in %r: %s" % (frag, copy_txt, fp.loose(frag) in fp.loose(copy_txt)))
frag2, copy2 = "keys are not exportable", "the keys are not exportable"
print("[H10b] negation lost upstream? %r in %r: %s" % ("keys are exportable", copy2, fp.loose("keys are exportable") in fp.loose(copy2)))
