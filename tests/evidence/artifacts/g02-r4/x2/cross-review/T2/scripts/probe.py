#!/usr/bin/env python3
"""M00-T05-r4-x2-xrev-T2: the same black-box probes of `heimdall-proto profile lint` on every
build (the two baselines and the six T2 cells). Spec: specs/T2.md; contract: docs/g02/slice-contract.md.

usage: python3 -I -B probe.py --work DIR --out DIR --ref LINT_REF.py --fixtures DIR \
           --bin NAME=PATH [--bin NAME=PATH ...] [--groups P1,P2,...] [--seed N] [--n N]

--work      disposable scratch directory for generated fixtures (created, must be empty)
--out       directory for the redacted result files (results.json, raw/*.json)
--ref       hidden-pack t2/lint_ref.py (a second, independent reference model)
--fixtures  tests/fixtures/g02/profiles (copied into --work, never used in place)

Every probe runs every binary with the same argv, inputs, environment and timeout. The
environment is minimal (PATH, HOME, TMPDIR pointing into --work; no SSH_AUTH_SOCK). Outputs
are redacted before they are written: canary-prefixed values, the scratch path and the home
path are replaced by placeholders.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata

CANARY_PREFIX = "HEIMDALL_" + "CANARY_"
RULE_MSG = {
    "duplicate-endpoint": "destinations share the same host and port",
    "privileged-port": "port below 1024 other than 22",
    "root-account": "account is root",
    "duplicate-label": "label repeated within a destination",
    "label-case-variant": "labels differ only in letter case",
}
ENVELOPE_KEYS = {"schema_version", "state", "code", "data", "warnings", "next"}
FINDING_KEYS = {"rule", "key_paths", "destination_ids", "message"}

A = None          # parsed args
BINS = {}         # name -> path
LANG = {}         # name -> go | rust
REDACT = []       # (needle, placeholder)
RESULTS = {}      # group -> payload


# ---------------------------------------------------------------- helpers

def redact_text(s):
    for needle, ph in REDACT:
        if needle:
            s = s.replace(needle, ph)
    s = re.sub(re.escape(CANARY_PREFIX) + r"[A-Za-z0-9_]*", "<canary>", s)
    return s


def show_bytes(b, limit=1500):
    t = b.decode("utf-8", errors="backslashreplace")
    t = redact_text(t)
    if len(t) > limit:
        return t[:limit] + "...<%d chars total, sha256 %s>" % (len(t), hashlib.sha256(b).hexdigest()[:16])
    return t


def env_for():
    home = os.path.join(A.work, "env-home")
    tmp = os.path.join(A.work, "env-tmp")
    os.makedirs(home, exist_ok=True)
    os.makedirs(tmp, exist_ok=True)
    return {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": tmp, "LC_ALL": "C"}


def run(binp, args, cwd=None, stdin=subprocess.DEVNULL, timeout=10, env=None):
    t0 = time.monotonic()
    p = subprocess.Popen([binp] + list(args), stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         cwd=cwd or A.work, env=env or env_for())
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        rc = None
    return rc, out, err, time.monotonic() - t0


def run_rusage(binp, args, timeout=30):
    """Run with stdout/stderr to files; return rc, wall seconds, max RSS bytes (wait4), out bytes."""
    od = os.path.join(A.work, "rusage")
    os.makedirs(od, exist_ok=True)
    fo, fe = os.path.join(od, "out"), os.path.join(od, "err")
    with open(fo, "wb") as so, open(fe, "wb") as se:
        t0 = time.monotonic()
        p = subprocess.Popen([binp] + list(args), stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                             cwd=A.work, env=env_for())
        deadline = t0 + timeout
        while True:
            pid, status, ru = os.wait4(p.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() > deadline:
                p.kill()
                pid, status, ru = os.wait4(p.pid, 0)
                break
            time.sleep(0.005)
        el = time.monotonic() - t0
        p.returncode = os.waitstatus_to_exitcode(status)
    out = open(fo, "rb").read()
    err = open(fe, "rb").read()
    return p.returncode, el, ru.ru_maxrss, out, err  # darwin: ru_maxrss in bytes


def parse_json(out):
    try:
        return json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def tstr(s):
    return json.dumps(s, ensure_ascii=False)


def profile_toml(dests, name="probe-profile", revision=1, meta_lines=None, explicit_empty=False):
    lines = ["schema_version = 1", "name = %s" % tstr(name), "revision = %d" % revision]
    if explicit_empty and not dests:
        lines.append("destinations = []")
    if meta_lines:
        lines += ["", "[meta]"] + meta_lines
    for d in dests:
        lines += ["", "[[destinations]]", "id = %s" % tstr(d["id"]), "alias = %s" % tstr(d["alias"]),
                  "host = %s" % tstr(d["host"])]
        if d.get("port") is not None:
            lines.append("port = %d" % d["port"])
        lines.append("account = %s" % tstr(d["account"]))
        if d.get("labels") is not None:
            lines.append("labels = [" + ", ".join(tstr(x) for x in d["labels"]) + "]")
    return "\n".join(lines) + "\n"


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


# ---------------------------------------------------------------- reference model (from specs/T2.md)

def ascii_lower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def ref_lint(doc):
    ds = doc.get("destinations", [])
    out = []

    def add(rule, places):
        ids = []
        for i in [p[0] for p in places]:
            if ds[i]["id"] not in ids:
                ids.append(ds[i]["id"])
        out.append({"rule": rule, "key_paths": [p[1] for p in places], "destination_ids": ids,
                    "message": RULE_MSG[rule]})

    groups = {}
    for i, d in enumerate(ds):
        groups.setdefault((ascii_lower(d["host"]), d.get("port", 22)), []).append(i)
    for members in sorted(groups.values(), key=lambda m: m[0]):
        if len(members) > 1:
            add("duplicate-endpoint", [(i, "destinations[%d].host" % i) for i in members])
    for i, d in enumerate(ds):
        p = d.get("port", 22)
        if p < 1024 and p != 22:
            add("privileged-port", [(i, "destinations[%d].port" % i)])
    for i, d in enumerate(ds):
        if d["account"] == "root":
            add("root-account", [(i, "destinations[%d].account" % i)])
    for i, d in enumerate(ds):
        occ = {}
        for j, lab in enumerate(d.get("labels", [])):
            occ.setdefault(lab, []).append(j)
        for js in sorted(occ.values(), key=lambda v: v[0]):
            if len(js) > 1:
                add("duplicate-label", [(i, "destinations[%d].labels[%d]" % (i, j)) for j in js])
    sets = {}
    for i, d in enumerate(ds):
        for j, lab in enumerate(d.get("labels", [])):
            sets.setdefault(ascii_lower(lab), []).append((i, j, lab))
    for occ in sorted(sets.values(), key=lambda v: (v[0][0], v[0][1])):
        if len({x[2] for x in occ}) > 1:
            add("label-case-variant", [(i, "destinations[%d].labels[%d]" % (i, j)) for i, j, _ in occ])
    return out


REF2 = None


def ref2_lint(doc):
    return REF2.lint(doc)["findings"]


# ---------------------------------------------------------------- envelope checks

def check_lint_json(rc, out, err, exp_findings):
    """Return a list of problems (strings) for one --json run on a schema-valid profile."""
    probs = []
    exp_code = "LINT_FINDINGS" if exp_findings else "LINT_CLEAN"
    exp_rc = 3 if exp_findings else 0
    if rc != exp_rc:
        probs.append("exit %r (expected %d)" % (rc, exp_rc))
    if not out.endswith(b"\n") or out.count(b"\n") != 1:
        probs.append("stdout is not exactly one line ending in \\n (%d newlines)" % out.count(b"\n"))
    if b"\x1b" in out:
        probs.append("ESC byte on stdout")
    doc = parse_json(out)
    if not isinstance(doc, dict):
        probs.append("stdout is not one JSON object")
        return probs
    if set(doc) != ENVELOPE_KEYS:
        probs.append("envelope members %s" % sorted(doc))
    if doc.get("schema_version") != "1" or doc.get("state") != "succeeded":
        probs.append("schema_version/state %r/%r" % (doc.get("schema_version"), doc.get("state")))
    if doc.get("code") != exp_code:
        probs.append("code %r (expected %s)" % (doc.get("code"), exp_code))
    if doc.get("warnings") != [] or doc.get("next") is not None:
        probs.append("warnings/next %r/%r" % (doc.get("warnings"), doc.get("next")))
    data = doc.get("data")
    if not isinstance(data, dict) or set(data) != {"findings"}:
        probs.append("data members %r" % (sorted(data) if isinstance(data, dict) else data))
        return probs
    for f in data["findings"]:
        if not isinstance(f, dict) or set(f) != FINDING_KEYS:
            probs.append("finding members %r" % (sorted(f) if isinstance(f, dict) else f))
            break
    if data["findings"] != exp_findings:
        probs.append("findings differ from the reference model")
    return probs


# ---------------------------------------------------------------- P1 differential random profiles

HOSTS = ["h1.ex.invalid", "H1.EX.invalid", "h1.Ex.invalid", "h2.ex.invalid", "\u00fc.ex.invalid",
         "\u00dc.ex.invalid", "\u212a.ex.invalid", "k.ex.invalid", "K.ex.invalid", "\u017f.ex.invalid",
         "s.ex.invalid", "S.ex.invalid", "\u0131.ex.invalid", "i.ex.invalid", "I.ex.invalid",
         "\u0130.ex.invalid", "e\u0301.ex.invalid", "\u00e9.ex.invalid", "\u00c9.EX.invalid"]
PORTS = [None, None, None, 22, 1, 21, 80, 443, 1023, 1024, 2222, 65535]
ACCOUNTS = ["root", "Root", "ROOT", "root ", "roots", "u", "admin", "r\u00f6ot", "r\u043e\u043et"]
LABELS = ["a", "A", "b", "B", "ab", "aB", "Ab", "AB", "", "\u00e9", "\u00c9", "e\u0301", "E\u0301",
          "k", "K", "\u212a", "\u00df", "SS", "ss", "Ss", "x y", "X Y", "\u0130", "i", "I", "\u0131",
          "\u6771\u4eac", "lbl", "LBL", "Lbl", "\u017f", "s", "S", "a\u00e4", "A\u00c4", "A\u00e4"]
ODD_IDS = ['q"uote', "back\\slash", "\u2028line-sep", "<&>", "\u00fcnicode-\U0001F600", "slash/id",
           "sp ace", "\u200bzero-width"]


def random_profile(rng):
    n = rng.choice([0, 1, 2, 2, 3, 3, 4, 4, 5, 6, 8, 12])
    ds = []
    odd = list(ODD_IDS)
    rng.shuffle(odd)
    for k in range(n):
        d = {"id": odd.pop() if (odd and rng.random() < 0.25) else "d%d" % k,
             "alias": "alias-%d" % k, "host": rng.choice(HOSTS), "account": rng.choice(ACCOUNTS)}
        p = rng.choice(PORTS)
        if p is not None:
            d["port"] = p
        r = rng.random()
        if r < 0.15:
            pass  # labels omitted
        elif r < 0.25:
            d["labels"] = []
        else:
            m = rng.choice([1, 2, 3, 3, 4, 5, 6, 8])
            pool = rng.sample(LABELS, rng.choice([2, 3, 4, 6, len(LABELS)]))
            d["labels"] = [rng.choice(pool) for _ in range(m)]
        ds.append(d)
    return ds


def p1():
    rng = random.Random(A.seed)
    cases = []
    d = os.path.join(A.work, "p1")
    for k in range(A.n):
        ds = random_profile(rng)
        txt = profile_toml(ds, name="p1-%d" % k, explicit_empty=(k % 7 == 0))
        path = write(os.path.join(d, "p%04d.toml" % k), txt)
        doc = tomllib.loads(txt)
        exp = ref_lint(doc)
        exp2 = ref2_lint(doc)
        cases.append((k, path, exp, exp2 == exp))
    res = {"profiles": len(cases), "seed": A.seed, "ref_models_agree": all(c[3] for c in cases),
           "profiles_with_findings": sum(1 for c in cases if c[2]),
           "rules_seen": {}, "per_bin": {}}
    for c in cases:
        for f in c[2]:
            res["rules_seen"][f["rule"]] = res["rules_seen"].get(f["rule"], 0) + 1
    for name, b in BINS.items():
        if LANG[name] == "base":
            continue
        fails = []
        plain_mismatch = []
        stderr_nonempty = 0
        for k, path, exp, _ in cases:
            rc, out, err, el = run(b, ["profile", "lint", "--file", path, "--json"])
            probs = check_lint_json(rc, out, err, exp)
            if err:
                stderr_nonempty += 1
            if probs:
                fails.append({"profile": k, "problems": probs, "stdout": show_bytes(out, 600),
                              "stderr": show_bytes(err, 300)})
            if k % 5 == 0:
                rcp, outp, errp, _ = run(b, ["profile", "lint", "--file", path])
                if rcp != rc:
                    plain_mismatch.append({"profile": k, "json_rc": rc, "plain_rc": rcp})
        res["per_bin"][name] = {"failed_profiles": len(fails), "first_failures": fails[:5],
                                "plain_exit_mismatch": plain_mismatch[:5],
                                "plain_runs": len([c for c in cases if c[0] % 5 == 0]),
                                "stderr_nonempty_runs": stderr_nonempty}
    RESULTS["P1_differential"] = res


# ---------------------------------------------------------------- P2 determinism

def p2():
    ds = []
    labs = [["zz", "Yy", "xx", "ZZ"], ["yy", "XX", "zz", "Zz"], ["yY", "xX", "zZ"], ["xx", "xx", "YY", "YY"]]
    for k in range(12):
        ds.append({"id": "det%d" % k, "alias": "al%d" % k, "host": ["H.ex", "h.EX", "g.ex"][k % 3],
                   "port": [22, None, 80, 21][k % 4], "account": ["root", "u"][k % 2], "labels": labs[k % 4]})
    txt = profile_toml(ds, name="det")
    path = write(os.path.join(A.work, "p2", "det.toml"), txt)
    exp = ref_lint(tomllib.loads(txt))
    res = {"runs_per_bin": 40, "findings_expected": len(exp), "per_bin": {}}
    for name, b in BINS.items():
        if LANG[name] == "base":
            continue
        outs = set()
        wrong = 0
        for _ in range(40):
            rc, out, err, _ = run(b, ["profile", "lint", "--file", path, "--json"])
            outs.add(out)
            if check_lint_json(rc, out, err, exp):
                wrong += 1
        res["per_bin"][name] = {"distinct_outputs": len(outs), "runs_not_matching_reference": wrong}
    RESULTS["P2_determinism"] = res


# ---------------------------------------------------------------- P3 hand-made edge profiles

def p3():
    D = lambda i, host="e.ex", port=None, account="u", labels=None, idv=None: {  # noqa: E731
        "id": idv or "e%d" % i, "alias": "ea%d" % i, "host": host, "port": port, "account": account,
        "labels": labels}
    cases = [
        ("exact repeat plus case variant in one destination", [D(0, labels=["a", "A", "a"])]),
        ("two empty labels in one destination", [D(0, labels=["", ""])]),
        ("NFC vs NFD e-acute, not equal", [D(0, labels=["\u00e9", "e\u0301"]), D(1, host="f.ex", labels=["\u00c9"])]),
        ("explicit empty destinations array", []),
        ("three spellings, repeats across destinations", [D(0, labels=["Prod", "x"]), D(1, host="f.ex", labels=["prod"]),
                                                           D(2, host="g.ex", labels=["PROD", "prod", "Prod"])]),
        ("rule 1 groups interleaved, three groups", [D(0, host="A.ex"), D(1, host="b.ex"), D(2, host="c.ex"),
                                                      D(3, host="a.EX", port=22), D(4, host="B.ex"), D(5, host="C.EX"),
                                                      D(6, host="a.ex", port=2222)]),
        ("rule 5 sets interleaved: first occurrence order is (i, j), not destination order of later members",
         [D(0, labels=["b", "a"]), D(1, host="f.ex", labels=["A", "B"]), D(2, host="g.ex", labels=["c"]),
          D(3, host="h.ex", labels=["C", "b"])]),
        ("rule 4 order within a destination: by first occurrence", [D(0, labels=["y", "x", "y", "x", "z", "z"])]),
        ("ports 1, 21, 22, 23, 1023, 1024 and omitted", [D(0, port=1), D(1, host="f.ex", port=21), D(2, host="g.ex", port=22),
                                                         D(3, host="h.ex", port=23), D(4, host="i.ex", port=1023),
                                                         D(5, host="j.ex", port=1024), D(6, host="k.ex")]),
        ("root vs near misses", [D(0, account="root"), D(1, host="f.ex", account="ROOT"),
                                 D(2, host="g.ex", account=" root"), D(3, host="h.ex", account="r\u043e\u043et")]),
        ("ids needing JSON escapes", [D(0, labels=["q", "Q"], idv='i"d\\1'), D(1, host="E.EX", idv="\u2028id2")]),
        ("Kelvin sign and long s in hosts and labels, ASCII pair only",
         [D(0, host="\u212aey.ex", labels=["\u017fx"]), D(1, host="key.ex", labels=["sx", "SX"])]),
    ]
    res = {"cases": [], "per_bin": {n: [] for n in BINS}}
    for k, (label, ds) in enumerate(cases):
        txt = profile_toml(ds, name="edge-%d" % k, explicit_empty=(not ds))
        path = write(os.path.join(A.work, "p3", "edge%02d.toml" % k), txt)
        exp = ref_lint(tomllib.loads(txt))
        res["cases"].append({"case": label, "expected_findings": exp})
        for name, b in BINS.items():
            rc, out, err, _ = run(b, ["profile", "lint", "--file", path, "--json"])
            probs = check_lint_json(rc, out, err, exp)
            res["per_bin"][name].append({"case": label, "ok": not probs, "problems": probs,
                                         "stdout": None if not probs else show_bytes(out, 800)})
    RESULTS["P3_edge_profiles"] = res


# ---------------------------------------------------------------- P4 value non-echo

def p4():
    tok = "nq%s" % os.urandom(4).hex()
    canary = CANARY_PREFIX + "XREVT2_" + os.urandom(6).hex().upper()
    REDACT.append((canary, "<canary>"))
    REDACT.append((canary.lower(), "<canary-lowercased>"))
    vals = {
        "name": "name-" + tok,
        "alias0": "alias0-" + tok, "alias1": "alias1-" + tok, "alias2": "alias2-" + tok,
        "host0": "HostQ-" + tok + ".example.invalid", "host1": "hostq-" + tok + ".EXAMPLE.invalid",
        "host2": canary + ".example.invalid",
        "acct1": "acct-" + tok, "acct2": canary,
        "lab0": "LabelQ-" + tok, "lab1": "labelq-" + tok, "lab2": canary, "lab3": canary.lower(),
        "meta1": "meta-" + tok, "meta2": canary,
    }
    ds = [
        {"id": "nid0", "alias": vals["alias0"], "host": vals["host0"], "port": 21, "account": "root",
         "labels": [vals["lab0"], vals["lab0"], vals["lab2"]]},
        {"id": "nid1", "alias": vals["alias1"], "host": vals["host1"], "port": 21, "account": vals["acct1"],
         "labels": [vals["lab1"], vals["lab3"]]},
        {"id": "nid2", "alias": vals["alias2"], "host": vals["host2"], "port": 2222, "account": vals["acct2"],
         "labels": [vals["lab2"]]},
    ]
    meta = ['note = %s' % tstr(vals["meta1"]), 'secret = %s' % tstr(vals["meta2"]),
            'nested = { deep = [%s, { x = %s }] }' % (tstr(vals["meta1"]), tstr(vals["meta2"]))]
    txt = profile_toml(ds, name=vals["name"], meta_lines=meta)
    path = write(os.path.join(A.work, "p4", "nonecho.toml"), txt)
    clean_ds = [dict(ds[1], port=2201, labels=[vals["lab1"]]), dict(ds[2], labels=[])]
    clean_txt = profile_toml(clean_ds, name=vals["name"], meta_lines=meta)
    cpath = write(os.path.join(A.work, "p4", "nonecho-clean.toml"), clean_txt)
    exp = ref_lint(tomllib.loads(txt))
    needles = sorted({v for v in vals.values()} | {tok, canary.lower(), canary.upper(), CANARY_PREFIX})
    res = {"values_checked": len(needles), "expected_findings": len(exp),
           "note": "every needle is searched case-sensitively; the random token is also searched alone", "per_bin": {}}
    for name, b in BINS.items():
        if LANG[name] == "base":
            continue
        r = {}
        for label, p, args in (("findings --json", path, ["--json"]), ("findings plain", path, []),
                               ("clean --json", cpath, ["--json"]), ("clean plain", cpath, [])):
            rc, out, err, _ = run(b, ["profile", "lint", "--file", p] + args)
            hits = [redact_text(n) for n in needles if n.encode() in out or n.encode() in err]
            row = {"exit": rc, "echoed_values": hits}
            if args:
                row["json_matches_reference"] = not check_lint_json(
                    rc, out, err, exp if p == path else ref_lint(tomllib.loads(clean_txt)))
            else:
                row["ids_in_plain_output"] = any(x.encode() in out for x in ("nid0", "nid1", "nid2"))
            r[label] = row
        res["per_bin"][name] = r
    RESULTS["P4_non_echo"] = res


# ---------------------------------------------------------------- P5 input handling vs profile show

def make_inputs():
    d = os.path.join(A.work, "p5")
    os.makedirs(d, exist_ok=True)
    valid = profile_toml([{"id": "v0", "alias": "va", "host": "v.ex", "account": "root", "labels": ["a", "A"]}],
                         name="valid")
    hdr = 'schema_version = 1\nname = "inv"\nrevision = 1\n'
    dest = '[[destinations]]\nid = "i1"\nalias = "i1a"\nhost = "i1.example.invalid"\naccount = "u"\n'
    marker = "XREVMARK" + os.urandom(6).hex()
    canary = CANARY_PREFIX + "XREVT2P5_" + os.urandom(6).hex().upper()
    REDACT.append((canary, "<canary>"))
    items = []

    def f(label, name, data, mode=None):
        p = write(os.path.join(d, name), data)
        if mode is not None:
            os.chmod(p, mode)
        items.append((label, p, None))
        return p

    vp = f("valid regular file (control)", "valid.toml", valid)
    f("zero-byte file", "empty.toml", b"")
    f("exactly 1 MiB, valid", "exact-1mib.toml", (valid + "#" + "x" * (1048576 - len(valid.encode()) - 2) + "\n").encode())
    f("1 MiB + 1 byte", "over-1mib.toml", (valid + "#" + "x" * (1048576 - len(valid.encode()) - 1) + "\n").encode())
    f("UTF-8 BOM then valid profile", "bom.toml", b"\xef\xbb\xbf" + valid.encode())
    f("CRLF line endings, valid", "crlf.toml", valid.replace("\n", "\r\n").encode())
    f("invalid UTF-8 inside a comment", "badutf8-comment.toml", valid.encode() + b"# \xff\xfe\n")
    f("invalid UTF-8 inside a label", "badutf8-label.toml", (hdr + dest).encode() + b'labels = ["a\xffb"]\n')
    f("NUL byte inside a host string", "nul.toml", (hdr + dest.replace("i1.example", "i1\x00x.example")).encode())
    f("duplicate TOML key", "dupkey.toml", hdr + dest + 'host = "again"\n')
    f("port given as a string", "port-string.toml", hdr + dest + 'port = "22"\n')
    f("port 65536", "port-65536.toml", hdr + dest + "port = 65536\n")
    f("port -1", "port-neg.toml", hdr + dest + "port = -1\n")
    f("labels not an array", "labels-str.toml", hdr + dest + 'labels = "x"\n')
    f("label not a string", "labels-int.toml", hdr + dest + "labels = [1]\n")
    f("label with DEL (K2)", "label-del.toml", hdr + dest + 'labels = ["a\\u007f%s"]\n' % marker)
    f("label with C1 NEL (K2)", "label-c1.toml", hdr + dest + 'labels = ["a\\u0085%s"]\n' % marker)
    f("host with ESC (K2)", "host-esc.toml", hdr + dest.replace('host = "i1.example.invalid"', 'host = "\\u001b[31m%s"' % marker))
    f("canary in a forbidden top-level key", "forbidden-canary.toml", hdr + 'private_key = "%s"\n' % canary)
    f("canary in an unknown destination key", "unknown-dest-canary.toml", hdr + dest + 'identity_file = "%s"\n' % canary)
    f("deeply nested arrays in [meta] (K15)", "deep-arrays.toml", hdr + "[meta]\nx = " + "[" * 20000 + "]" * 20000 + "\n")
    f("deeply nested inline tables in [meta] (K15)", "deep-tables.toml",
      hdr + "[meta]\nx = " + "{a = " * 5000 + "1" + " }" * 5000 + "\n")
    f("destinations as a table", "dest-table.toml", hdr + '[destinations]\nid = "x"\n')
    f("revision 0", "rev0.toml", 'schema_version = 1\nname = "inv"\nrevision = 0\n')
    f("missing name", "noname.toml", 'schema_version = 1\nrevision = 1\n')
    f("duplicate id", "dup-id.toml", hdr + dest + dest.replace('alias = "i1a"', 'alias = "i2a"'))
    f("empty-string host", "empty-host.toml", hdr + dest.replace('host = "i1.example.invalid"', 'host = ""'))
    f("unreadable file (mode 000)", "mode000.toml", valid, mode=0)
    os.makedirs(os.path.join(d, "locked-dir"), exist_ok=True)
    write(os.path.join(d, "locked-dir", "in.toml"), valid)
    os.chmod(os.path.join(d, "locked-dir"), 0)
    items.append(("file inside a mode-000 directory", os.path.join(d, "locked-dir", "in.toml"), None))
    fifo = os.path.join(d, "fifo.toml")
    os.mkfifo(fifo)
    items.append(("FIFO", fifo, None))
    os.symlink(fifo, os.path.join(d, "link-to-fifo.toml"))
    items.append(("symlink to a FIFO", os.path.join(d, "link-to-fifo.toml"), None))
    os.symlink(vp, os.path.join(d, "link-to-valid.toml"))
    items.append(("symlink to a valid regular file", os.path.join(d, "link-to-valid.toml"), None))
    os.symlink(os.path.join(d, "nowhere.toml"), os.path.join(d, "dangling.toml"))
    items.append(("dangling symlink", os.path.join(d, "dangling.toml"), None))
    os.symlink(os.path.join(d, "loop-b.toml"), os.path.join(d, "loop-a.toml"))
    os.symlink(os.path.join(d, "loop-a.toml"), os.path.join(d, "loop-b.toml"))
    items.append(("symlink loop", os.path.join(d, "loop-a.toml"), None))
    items.append(("directory with trailing slash", d + "/", None))
    items.append(("/dev/null (character device)", "/dev/null", None))
    items.append(("/dev/zero (character device)", "/dev/zero", None))
    items.append(("/dev/stdin, stdin a pipe held open", "/dev/stdin", "pipe"))
    items.append(("/dev/stdin, stdin a regular valid file", "/dev/stdin", vp))
    # AF_UNIX paths are limited to 104 bytes on darwin: a short directory of our own in /tmp
    sdir = tempfile.mkdtemp(prefix="xrT2-", dir="/tmp")
    sp = os.path.join(sdir, "sock.toml")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sp)  # bound only, never listening: a socket file, not a listener
    items.append(("Unix socket file (bound, not listening)", sp, None))
    items.append(("empty path", "", None))
    items.append(("path longer than PATH_MAX", os.path.join(d, "x" * 200, "y" * 200, "z" * 200, "w" * 200, "v" * 200, "f.toml"), None))
    # (an existing file with a non-UTF-8 name cannot be created on APFS: EILSEQ)
    items.append(("missing file whose name is not UTF-8", os.path.join(os.fsencode(d), b"missing-\xff.toml"), None))
    return items, (s, sdir), marker


def run_input(b, sub, path, stdin_spec, json_flag=True):
    args = ["profile", sub, "--file", path] + (["--json"] if json_flag else [])
    if stdin_spec == "pipe":
        r, w = os.pipe()
        try:
            res = run(b, args, stdin=r, timeout=10)
        finally:
            os.close(r)
            os.close(w)
        return res
    if stdin_spec:
        with open(stdin_spec, "rb") as fh:
            return run(b, args, stdin=fh, timeout=10)
    return run(b, args, timeout=10)


def kp(doc):
    if not isinstance(doc, dict):
        return "<no json>"
    return ((doc.get("data") or {}).get("error") or {}).get("key_path", "<missing>")


def p5():
    items, (sock, sdir), marker = make_inputs()
    res = {"inputs": [lbl for lbl, _, _ in items], "per_bin": {}}
    try:
        for name, b in BINS.items():
            rows = []
            for label, path, stdin_spec in items:
                rs, os_, es, els = run_input(b, "show", path, stdin_spec)
                if LANG[name] == "base":
                    ds = parse_json(os_)
                    rows.append({"input": label, "show": {"exit": rs, "code": (ds or {}).get("code"),
                                                          "key_path": kp(ds), "secs": round(els, 2)}})
                    continue
                rl, ol, el, ell = run_input(b, "lint", path, stdin_spec)
                rlp, olp, elp, ellp = run_input(b, "lint", path, stdin_spec, json_flag=False)
                ds, dl = parse_json(os_), parse_json(ol)
                row = {"input": label, "show": {"exit": rs, "code": (ds or {}).get("code"), "state": (ds or {}).get("state"),
                                                "key_path": kp(ds), "secs": round(els, 2)},
                       "lint": {"exit": rl, "code": (dl or {}).get("code"), "state": (dl or {}).get("state"),
                                "key_path": kp(dl), "secs": round(ell, 2)},
                       "lint_plain_exit": rlp}
                problems = []
                if rs == 0:
                    if rl not in (0, 3) or (dl or {}).get("code") not in ("LINT_CLEAN", "LINT_FINDINGS"):
                        problems.append("show accepts the input but lint does not succeed")
                else:
                    for k in ("exit", "code", "state", "key_path"):
                        if row["show"][k] != row["lint"][k]:
                            problems.append("%s differs from show" % k)
                if rl is None or ell > 2.0:
                    problems.append("lint did not answer within 2 s")
                if rlp != rl:
                    problems.append("plain exit %r != --json exit %r" % (rlp, rl))
                for blob in (ol, el, olp, elp):
                    if marker.encode() in blob or CANARY_PREFIX.encode() in blob:
                        problems.append("offending value echoed by lint")
                        break
                row["problems"] = problems
                if problems:
                    row["lint_stdout"] = show_bytes(ol, 400)
                    row["show_stdout"] = show_bytes(os_, 400)
                rows.append(row)
            res["per_bin"][name] = rows
    finally:
        sock.close()
        shutil.rmtree(sdir)  # only the directory mkdtemp created above
        d = os.path.join(A.work, "p5")
        os.chmod(os.path.join(d, "locked-dir"), 0o700)
    RESULTS["P5_inputs_vs_show"] = res


# ---------------------------------------------------------------- P6 argv handling vs profile show

def p6():
    d = os.path.join(A.work, "p6")
    vp = write(os.path.join(d, "valid.toml"), profile_toml(
        [{"id": "v0", "alias": "va", "host": "v.ex", "account": "u", "labels": ["x"]}], name="valid"))
    cwd = os.path.join(d, "cwd")
    os.makedirs(cwd, exist_ok=True)
    # a file literally named "--json" in the working directory (findings profile)
    write(os.path.join(cwd, "--json"), profile_toml(
        [{"id": "j0", "alias": "ja", "host": "j.ex", "account": "root"}], name="dashfile"))
    write(os.path.join(cwd, "-"), profile_toml(
        [{"id": "m0", "alias": "ma", "host": "m.ex", "account": "u"}], name="minusfile"))
    templates = [
        [], ["--json"], ["--file"], ["--json", "--file"], ["--file", "--json"],
        ["--file", "{P}", "--json", "--json"], ["--file", "{P}", "--file", "{P}", "--json"],
        ["--file", "{P}", "extra", "--json"], ["--file={P}", "--json"], ["-file", "{P}", "--json"],
        ["--json=true", "--file", "{P}"], ["--file", "{P}", "--json=false"], ["--file", "{P}", "-json"],
        ["--file", "{P}", "--json", "--"], ["--", "--file", "{P}", "--json"], ["-h", "--json"], ["--help"],
        ["--file", "", "--json"], ["--file", "-", "--json"], ["--JSON", "--file", "{P}"],
        ["--file", "{P}", "--bogus"], ["--bogus", "--file", "{P}", "--json"], ["--file", "--file", "--json"],
    ]
    res = {"templates": [" ".join(t).replace("{P}", "P") for t in templates],
           "cwd_note": "cwd holds files named '--json' (a findings profile) and '-' (a clean profile)", "per_bin": {}}
    for name, b in BINS.items():
        rows = []
        for t in templates:
            args = [a.replace("{P}", vp) for a in t]
            rs, os_, es, _ = run(b, ["profile", "show"] + args, cwd=cwd)
            if LANG[name] == "base":
                ds = parse_json(os_)
                rows.append({"argv": " ".join(t).replace("{P}", "P"),
                             "show": {"exit": rs, "json": ds is not None, "code": (ds or {}).get("code")}})
                continue
            rl, ol, el, ell = run(b, ["profile", "lint"] + args, cwd=cwd)
            ds, dl = parse_json(os_), parse_json(ol)
            row = {"argv": " ".join(t).replace("{P}", "P"),
                   "show": {"exit": rs, "json": ds is not None, "code": (ds or {}).get("code")},
                   "lint": {"exit": rl, "json": dl is not None, "code": (dl or {}).get("code"),
                            "stdout_empty": ol == b""}}
            if rs == 0:
                row["match"] = rl in (0, 3)
            else:
                row["match"] = (rs == rl and (ds is not None) == (dl is not None) and
                                (ds or {}).get("code") == (dl or {}).get("code"))
            if not row["match"]:
                row["lint_stdout"] = show_bytes(ol, 300)
                row["lint_stderr"] = show_bytes(el, 300)
            rows.append(row)
        res["per_bin"][name] = rows
    RESULTS["P6_argv_vs_show"] = res


# ---------------------------------------------------------------- P7 resource bound (K15) on 1 MiB inputs

def fill_labels(prefix_txt, label_cycle, close="]\n", limit=1048576, sep=", "):
    parts = [prefix_txt, "labels = ["]
    size = len(prefix_txt.encode()) + len("labels = [") + len(close)
    k = 0
    while True:
        item = (sep if k else "") + tstr(label_cycle[k % len(label_cycle)])
        n = len(item.encode())
        if size + n > limit:
            break
        parts.append(item)
        size += n
        k += 1
    parts.append(close)
    return "".join(parts), k


def fill_dests(make, limit=1048576):
    head = 'schema_version = 1\nname = "big"\nrevision = 1\n'
    parts = [head]
    size = len(head.encode())
    k = 0
    while True:
        blk = make(k)
        n = len(blk.encode())
        if size + n > limit:
            break
        parts.append(blk)
        size += n
        k += 1
    return "".join(parts), k


def p7():
    d = os.path.join(A.work, "p7")
    head1 = ('schema_version = 1\nname = "big"\nrevision = 1\n\n[[destinations]]\nid = "b0"\nalias = "ba"\n'
             'host = "b.ex"\naccount = "u"\n')
    cases = []
    txt, n = fill_labels(head1, ["a"])
    cases.append(("A one destination, %d copies of one label (rule 4)" % n, txt))
    txt, n = fill_labels(head1, ["a", "A"])
    cases.append(("B one destination, %d labels alternating a/A (rules 4 and 5)" % n, txt))
    txt, n = fill_labels(head1, ["a", "A"], sep=",")
    cases.append(("B2 one destination, %d labels alternating a/A, no spaces (most key paths per MiB)" % n, txt))
    txt, n = fill_labels(head1, ["l%06d" % k for k in range(300000)])
    cases.append(("C one destination, %d distinct labels (no finding)" % n, txt))
    txt, n = fill_dests(lambda k: '[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h"\naccount="u"\n' % (k, k))
    cases.append(("D %d destinations, same host and port (rule 1, one group)" % n, txt))
    txt, n = fill_dests(lambda k: '[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h%d"\naccount="u"\nlabels=["x","X"]\n' % (k, k, k))
    cases.append(("E %d destinations, labels x/X each (rule 5, one set over all destinations)" % n, txt))
    txt, n = fill_dests(lambda k: '[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h"\nport=21\naccount="root"\n' % (k, k))
    cases.append(("F %d destinations, same host, port 21, root (rules 1-3)" % n, txt))
    txt, n = fill_dests(lambda k: '[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h%d"\naccount="u"\nlabels=["x","x"]\n' % (k, k, k))
    cases.append(("G %d destinations, label x twice each (rule 4, one finding each)" % n, txt))
    # Go's parser guard (internal/profile/guard.go, MaxStructureUnits = 65536 keys and containers)
    # rejects D-G above as SCHEMA_INVALID; these smaller variants fit under it, so the Go lint
    # code runs on many destinations too.
    head = 'schema_version = 1\nname = "big"\nrevision = 1\n'
    txt = head + "".join('[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h"\naccount="u"\n' % (k, k) for k in range(10000))
    cases.append(("H 10000 destinations, same host and port (rule 1, one group; under the Go guard)", txt))
    txt = head + "".join('[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h%d"\naccount="u"\nlabels=["x","X"]\n' % (k, k, k) for k in range(8000))
    cases.append(("I 8000 destinations, labels x/X each (rule 5 over all; under the Go guard)", txt))
    txt = head + "".join('[[destinations]]\nid="i%d"\nalias="a%d"\nhost="h"\nport=21\naccount="root"\n' % (k, k) for k in range(8000))
    cases.append(("J 8000 destinations, same host, port 21, root (rules 1-3; under the Go guard)", txt))
    res = {"bound": "K15: within 2 s and below 256 MiB peak RSS (contract 9.1)", "cases": [], "per_bin": {}}
    paths = []
    for k, (label, txt) in enumerate(cases):
        p = write(os.path.join(d, "big%d.toml" % k), txt)
        exp = ref_lint(tomllib.loads(txt))
        paths.append((label, p, exp))
        res["cases"].append({"case": label, "bytes": os.path.getsize(p), "findings": len(exp),
                             "key_paths": sum(len(f["key_paths"]) for f in exp)})
    for name, b in BINS.items():
        rows = []
        for label, p, exp in paths:
            row = {"case": label.split(" ")[0]}
            for sub, args in (("show", ["--json"]), ("lint", ["--json"]), ("lint_plain", [])):
                if sub != "show" and LANG[name] == "base":
                    continue
                best = None
                rss_max = 0
                for _ in range(A.reps):
                    rc, el, rss, out, err = run_rusage(b, ["profile", sub.split("_")[0], "--file", p] + args)
                    rss_max = max(rss_max, rss)
                    if best is None or el > best[1]:
                        best = (rc, el, rss, out, err)
                rc, el, rss, out, err = best
                # worst (slowest) wall time and the largest peak RSS over the repetitions
                row[sub] = {"exit": rc, "secs": round(el, 3), "max_rss_mib": round(rss_max / 1048576, 1),
                            "stdout_bytes": len(out)}
                if sub == "lint":
                    row[sub]["matches_reference"] = not check_lint_json(rc, out, err, exp)
                    row[sub]["within_K15"] = el <= 2.0 and rss < 256 * 1048576
            rows.append(row)
        res["per_bin"][name] = rows
    RESULTS["P7_resources"] = res


# ---------------------------------------------------------------- P8 K12 closed stdout parity

def run_closed(b, args):
    r, w = os.pipe()
    os.close(r)
    try:
        p = subprocess.Popen([b] + args, stdin=subprocess.DEVNULL, stdout=w, stderr=subprocess.PIPE,
                             cwd=A.work, env=env_for())
    finally:
        os.close(w)
    try:
        _, err = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return None
    return p.returncode


def p8():
    d = os.path.join(A.work, "p8")
    clean = write(os.path.join(d, "clean.toml"), profile_toml(
        [{"id": "c0", "alias": "ca", "host": "c.ex", "account": "u"}], name="clean"))
    find = write(os.path.join(d, "find.toml"), profile_toml(
        [{"id": "f0", "alias": "fa", "host": "f.ex", "port": 21, "account": "root"}], name="find"))
    big, _ = fill_labels('schema_version = 1\nname = "big"\nrevision = 1\n\n[[destinations]]\nid = "b0"\n'
                         'alias = "ba"\nhost = "b.ex"\naccount = "u"\n', ["a", "A"])
    bigp = write(os.path.join(d, "big.toml"), big)
    bad = write(os.path.join(d, "bad.toml"), 'schema_version = 1\nname = "x"\nrevision = 1\nbogus = 1\n')
    cases = [("clean", ["--file", clean]), ("findings", ["--file", find]), ("findings, ~10 MB output", ["--file", bigp]),
             ("schema error", ["--file", bad]), ("usage error (unknown flag)", ["--file", clean, "--bogus"])]
    res = {"rule": "exit status with a closed stdout is the same with and without --json (contract 9.4)", "per_bin": {}}
    for name, b in BINS.items():
        if LANG[name] == "base":
            continue
        rows = []
        for label, args in cases:
            rj = run_closed(b, ["profile", "lint"] + args + ["--json"])
            rp = run_closed(b, ["profile", "lint"] + args)
            ro, _, _, _ = run(b, ["profile", "lint"] + args + ["--json"])
            rows.append({"case": label, "closed_json": rj, "closed_plain": rp, "open_json": ro, "parity": rj == rp})
        res["per_bin"][name] = rows
    RESULTS["P8_K12_closed_stdout"] = res


# ---------------------------------------------------------------- P9 no writes, P10 stdin not read

def snapshot(dirs):
    snap = {}
    for root in dirs:
        for dp, dn, fn in os.walk(root):
            for x in dn + fn:
                p = os.path.join(dp, x)
                st = os.lstat(p)
                snap[p] = (st.st_size, st.st_mtime_ns, stat.S_IFMT(st.st_mode))
        st = os.lstat(root)
        snap[root] = (st.st_mtime_ns,)
    return snap


def p9_p10():
    res9 = {"watched": ["cwd (empty dir)", "profile dir", "HOME", "TMPDIR"], "per_bin": {}}
    res10 = {"what": "stdin is a pipe whose writer stays open; lint --file <valid> must not read it", "per_bin": {}}
    for name, b in BINS.items():
        if LANG[name] == "base":
            continue
        base = os.path.join(A.work, "p9", name)
        cwd, pd, home, tmp = (os.path.join(base, x) for x in ("cwd", "prof", "home", "tmp"))
        for x in (cwd, pd, home, tmp):
            os.makedirs(x, exist_ok=True)
        p = write(os.path.join(pd, "p.toml"), profile_toml(
            [{"id": "w0", "alias": "wa", "host": "w.ex", "port": 80, "account": "root", "labels": ["a", "A", "a"]}],
            name="nowrite"))
        env = {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": tmp, "LC_ALL": "C"}
        before = snapshot([cwd, pd, home, tmp])
        rcs = []
        for args in (["--json"], []):
            rc, _, _, _ = run(b, ["profile", "lint", "--file", p] + args, cwd=cwd, env=env)
            rcs.append(rc)
        after = snapshot([cwd, pd, home, tmp])
        res9["per_bin"][name] = {"exits": rcs, "changed": sorted(redact_text(k) for k in set(before) ^ set(after)) +
                                 sorted(redact_text(k) for k in before if k in after and before[k] != after[k])}
        r, w = os.pipe()
        try:
            rc, out, err, el = run(b, ["profile", "lint", "--file", p, "--json"], stdin=r, timeout=5)
        finally:
            os.close(r)
            os.close(w)
        res10["per_bin"][name] = {"exit": rc, "secs": round(el, 2)}
    RESULTS["P9_no_writes"] = res9
    RESULTS["P10_stdin_not_read"] = res10


# ---------------------------------------------------------------- P12 existing behaviour vs baseline

def p12():
    fx = os.path.join(A.work, "fixtures")
    if not os.path.isdir(fx):
        shutil.copytree(A.fixtures, fx)
    homelab = os.path.join(fx, "homelab.toml")
    cmds = [
        ["profile", "show", "--file", homelab, "--json"], ["profile", "show", "--file", homelab],
        ["profile", "show", "--file", os.path.join(fx, "large-100.toml"), "--json"],
        ["profile", "show", "--file", os.path.join(fx, "invalid-forbidden-key.toml"), "--json"],
        ["profile", "show", "--file", os.path.join(fx, "invalid-port.toml"), "--json"],
        ["profile", "show", "--file", os.path.join(fx, "invalid-malformed.toml"), "--json"],
        ["profile", "show", "--json"], ["profile", "show", "--file", "--json"],
        ["profile", "--json"], ["profile"], ["profile", "list", "--json"], ["profile", "lint2", "--json"],
        ["agent", "list", "--json"], ["agent", "list", "--socket", os.path.join(A.work, "no-such.sock"),
                                      "--timeout-ms", "200", "--json"],
        ["run"], ["run", "--", "/usr/bin/true"], ["tui", "--file", homelab], ["bogus", "--json"], ["--help"],
        ["version", "--json"], [],
    ]
    res = {"commands": [" ".join(redact_text(x) for x in c) for c in cmds], "per_bin": {}}
    outs = {}
    for name, b in BINS.items():
        outs[name] = []
        for c in cmds:
            rc, out, err, _ = run(b, c, timeout=10)
            outs[name].append((rc, out, err))
    for name in BINS:
        if LANG[name] == "base":
            continue
        base = "base-" + ("go" if "-go-" in name else "rust")
        if base not in outs:
            continue
        diffs = []
        for c, x, y in zip(res["commands"], outs[base], outs[name]):
            if x != y:
                diffs.append({"command": c, "exit": [x[0], y[0]],
                              "stdout_same": x[1] == y[1], "stderr_same": x[2] == y[2],
                              "base_stdout": show_bytes(x[1], 400), "cell_stdout": show_bytes(y[1], 400),
                              "base_stderr": show_bytes(x[2], 400), "cell_stderr": show_bytes(y[2], 400)})
        res["per_bin"][name] = {"baseline": base, "commands_differing": len(diffs), "diffs": diffs}
    RESULTS["P12_existing_behaviour"] = res


# ---------------------------------------------------------------- main

GROUPS = {"P1": p1, "P2": p2, "P3": p3, "P4": p4, "P5": p5, "P6": p6, "P7": p7, "P8": p8, "P9": p9_p10, "P12": p12}


def main():
    global A, REF2
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--bin", action="append", required=True)
    ap.add_argument("--groups", default=",".join(GROUPS))
    ap.add_argument("--seed", type=int, default=20261010)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--reps", type=int, default=3)
    A = ap.parse_args()
    os.makedirs(A.work, exist_ok=True)
    os.makedirs(A.out, exist_ok=True)
    A.work = os.path.realpath(A.work)
    REDACT.append((A.work, "<work>"))
    REDACT.append((os.path.expanduser("~"), "<home>"))
    spec = importlib.util.spec_from_file_location("lint_ref", A.ref)
    REF2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(REF2)
    for x in A.bin:
        n, p = x.split("=", 1)
        BINS[n] = p
        LANG[n] = "base" if n.startswith("base-") else ("go" if "-go-" in n else "rust")
    meta = {"bins": {n: hashlib.sha256(open(p, "rb").read()).hexdigest() for n, p in BINS.items()},
            "groups": A.groups, "seed": A.seed, "n": A.n, "reps": A.reps,
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    for g in A.groups.split(","):
        t0 = time.monotonic()
        GROUPS[g]()
        meta.setdefault("group_secs", {})[g] = round(time.monotonic() - t0, 1)
        print("done", g, meta["group_secs"][g], file=sys.stderr)
    meta["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    text = json.dumps({"meta": meta, "results": RESULTS}, indent=1, ensure_ascii=False)
    text = redact_text(text)
    with open(os.path.join(A.out, "results-%s.json" % A.groups.replace(",", "-")), "w", encoding="utf-8") as f:
        f.write(text + "\n")


if __name__ == "__main__":
    main()
