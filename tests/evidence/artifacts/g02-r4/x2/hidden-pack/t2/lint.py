"""T2 hidden tests: `heimdall-proto profile lint --file <path> --json` (specs/T2.md)."""
import json
import os
import shutil
import time
from pathlib import Path

import hm
from hm import check, parse_one_json, check_envelope, Abort

T = "T2"
FIX = Path(__file__).resolve().parent / "fixtures"
EXP = Path(__file__).resolve().parent / "expected"

# Profile values from the fixtures that must never appear on stdout or stderr (ids may).
NON_ECHO = {
    "all-rules": ["lintcase-qv", "metaval-K2x9", "metahost-K2x9", "metalbl-K2x9", "METALBL-K2X9",
                  "aliaszq", "hostq", "HostQ", "HOSTQ", "höst-q", "acctalpha", "acctdelta", "acctecho",
                  "acctgolf", "accthotel", "acctindia", "lblzeta", "LblZeta", "LBLZETA", "lblomega",
                  "lblOmega", "lbldup", "lblpi", "lblkappa", "LBLKAPPA", "Root"],
    "near-miss": ["nearmiss-qv", "aliasnm", "hostnm", "Root", "roots", "rootnm", "acctnm", "lblnm"],
    "ascii-fold": ["asciifold-qv", "foldqv", "fold-ü-qv", "FOLD-Ü-QV", "elvin-foldqv", "lbl-é-foldqv",
                   "LBL-É-FOLDQV", "lbl-k-foldqv", "Lbl-Ascii-FoldQV", "lbl-ascii-foldqv"],
    "clean": ["lab-server", "lab.example.internal", "aman", "vps-東京", "free-form metadata", "personal"],
}


def fixture(ctx, name, subdir=None):
    d = ctx.new_dir(subdir or "fx")
    p = d / (name + ".toml")
    shutil.copyfile(FIX / (name + ".toml"), p)
    return p


def expected(name):
    return json.loads((EXP / (name + ".json")).read_text(encoding="utf-8"))


def no_echo(t, name, out, err, label):
    for v in NON_ECHO.get(name, []):
        b = v.encode("utf-8")
        t.check("%s: value %r not echoed on stdout/stderr" % (label, v), b not in out and b not in err,
                "absent", "present on %s" % ("stdout" if b in out else "stderr"))


def exact_case(t, ctx, name, exit_code, args_order="file-first", path=None):
    p = path or fixture(ctx, name)
    args = (["profile", "lint", "--file", str(p), "--json"] if args_order == "file-first"
            else ["profile", "lint", "--json", "--file", str(p)])
    rc, out, err, el = ctx.run(args)
    t.eq("exit code", rc, exit_code)
    doc = parse_one_json(t, out)
    exp = expected(name)
    check_envelope(t, doc, exp["state"], exp["code"])
    t.eq("data (exact)", doc.get("data"), exp["data"])
    no_echo(t, name, out, err, "--json")


@check(T, "T2.clean_homelab", "homelab profile: LINT_CLEAN, exit 0, findings []")
def _(t, ctx):
    exact_case(t, ctx, "clean", 0)


@check(T, "T2.clean_empty", "profile without destinations: LINT_CLEAN, exit 0")
def _(t, ctx):
    exact_case(t, ctx, "empty", 0)


@check(T, "T2.clean_near_miss", "every rule's near miss: LINT_CLEAN, exit 0")
def _(t, ctx):
    exact_case(t, ctx, "near-miss", 0)


@check(T, "T2.all_rules_exact", "all five rules: LINT_FINDINGS, exit 3, exact findings in exact order")
def _(t, ctx):
    exact_case(t, ctx, "all-rules", 3)


@check(T, "T2.flag_order", "--json before --file gives the same result")
def _(t, ctx):
    exact_case(t, ctx, "all-rules", 3, args_order="json-first")


@check(T, "T2.ascii_fold_only", "case folding is ASCII-only: Unicode-only case pairs (É/é, Ü/ü, KELVIN SIGN/k) "
                                 "are not findings; one ASCII pair is (fix round 2026-10-06)")
def _(t, ctx):
    exact_case(t, ctx, "ascii-fold", 3)


@check(T, "T2.spaced_unicode_path", "path with spaces and non-ASCII characters")
def _(t, ctx):
    d = ctx.new_dir("spaced dir ü")
    p = d / "prøfile lint ü.toml"
    shutil.copyfile(FIX / "all-rules.toml", p)
    exact_case(t, ctx, "all-rules", 3, path=p)


@check(T, "T2.plain_exit_codes", "without --json: same exit codes (0 clean, 3 findings), values not echoed")
def _(t, ctx):
    for name, code in (("clean", 0), ("near-miss", 0), ("all-rules", 3)):
        p = fixture(ctx, name)
        rc, out, err, _ = ctx.run(["profile", "lint", "--file", str(p)])
        t.eq("%s: exit code without --json" % name, rc, code)
        no_echo(t, name, out, err, "%s plain" % name)


@check(T, "T2.single_rules", "each rule in isolation (one-destination edits of a clean profile)")
def _(t, ctx):
    base = ('schema_version = 1\nname = "single-qv"\nrevision = 1\n\n'
            '[[destinations]]\nid = "s_a"\nalias = "a-singleqv"\nhost = "h1-singleqv.example.invalid"\n'
            'account = "acct-singleqv"\n%s\n'
            '[[destinations]]\nid = "s_b"\nalias = "b-singleqv"\nhost = "%s"\n%saccount = "acct-singleqv"\n')
    cases = [
        # (label, dest-a extra lines, dest-b host, dest-b extra, expected findings)
        ("default port equals explicit 22", "", "H1-SINGLEQV.example.invalid", "port = 22\n",
         [{"rule": "duplicate-endpoint", "key_paths": ["destinations[0].host", "destinations[1].host"],
           "destination_ids": ["s_a", "s_b"], "message": "destinations share the same host and port"}]),
        ("port 21 is privileged", "port = 21\n", "h2-singleqv.example.invalid", "",
         [{"rule": "privileged-port", "key_paths": ["destinations[0].port"], "destination_ids": ["s_a"],
           "message": "port below 1024 other than 22"}]),
        ("port 1 is privileged", "port = 1\n", "h2-singleqv.example.invalid", "",
         [{"rule": "privileged-port", "key_paths": ["destinations[0].port"], "destination_ids": ["s_a"],
           "message": "port below 1024 other than 22"}]),
        ("labels only differ in case within one destination", 'labels = ["Lbl-SingleQV", "lbl-singleqv"]\n',
         "h2-singleqv.example.invalid", "",
         [{"rule": "label-case-variant", "key_paths": ["destinations[0].labels[0]", "destinations[0].labels[1]"],
           "destination_ids": ["s_a"], "message": "labels differ only in letter case"}]),
        ("same label in two destinations is fine", 'labels = ["lbl-sharedqv"]\n', "h2-singleqv.example.invalid",
         'labels = ["lbl-sharedqv"]\n', []),
        ("same host, different port is fine", "port = 2201\n", "h1-singleqv.example.invalid", "port = 2202\n", []),
    ]
    for label, a_extra, b_host, b_extra, findings in cases:
        d = ctx.new_dir("single")
        p = d / "p.toml"
        p.write_text(base % (a_extra, b_host, b_extra), encoding="utf-8")
        rc, out, err, _ = ctx.run(["profile", "lint", "--file", str(p), "--json"])
        t.eq("[%s] exit code" % label, rc, 3 if findings else 0)
        try:
            doc = json.loads(out.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            t.check("[%s] stdout is JSON" % label, False, "JSON", out[:200])
            continue
        t.eq("[%s] code" % label, doc.get("code"), "LINT_FINDINGS" if findings else "LINT_CLEAN")
        t.eq("[%s] data" % label, doc.get("data"), {"findings": findings})


def invalid_profiles(ctx):
    """(label, path) of inputs `profile show` rejects; generated per run.  The forbidden-key marker
    is random per run and is a plain marker, not a HEIMDALL_CANARY_ value."""
    marker = "HMX2LINTSECRET_" + os.urandom(8).hex()
    d = ctx.new_dir("invalid")
    out = []

    def w(name, text):
        p = d / name
        p.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        out.append((name, p))

    hdr = 'schema_version = 1\nname = "inv"\nrevision = 1\n'
    dest = '[[destinations]]\nid = "i1"\nalias = "i1a"\nhost = "i1.example.invalid"\naccount = "u"\n'
    w("forbidden-key.toml", hdr + 'private_key = "%s"\n' % marker)
    w("unknown-dest-key.toml", hdr + dest + 'identity_file = "%s"\n' % marker)
    w("malformed.toml", hdr + 'name2 = "%s\n' % marker)
    w("schema-version-2.toml", 'schema_version = 2\nname = "inv"\nrevision = 1\n')
    w("duplicate-alias.toml", hdr + dest + dest.replace('id = "i1"', 'id = "i2"'))
    w("port-zero.toml", hdr + dest + "port = 0\n")
    w("control-char.toml", hdr + dest.replace('account = "u"', 'account = "u\\u001b[31m%s"' % marker))
    w("oversize.toml", hdr + "# " + "x" * (1024 * 1024) + "\n")
    out.append(("missing", d / "no such file ü.toml"))
    out.append(("directory", ctx.new_dir("a dir")))
    fifo = d / "fifo.toml"
    os.mkfifo(fifo)
    out.append(("fifo", fifo))
    return marker, out


@check(T, "T2.invalid_same_as_show", "a profile `profile show` rejects gives the same code/exit/state/key_path; "
                                      "no value echoed; never blocks")
def _(t, ctx):
    marker, cases = invalid_profiles(ctx)
    mb = marker.encode()
    for label, p in cases:
        rc_s, out_s, err_s, _ = ctx.run(["profile", "show", "--file", str(p), "--json"], timeout=10)
        rc_l, out_l, err_l, el = ctx.run(["profile", "lint", "--file", str(p), "--json"], timeout=10)
        t.check("[%s] lint returns within 2 s" % label, rc_l is not None and el <= 2.0, "<= 2 s",
                "%.2f s rc=%r" % (el, rc_l))
        t.eq("[%s] exit code equals show's" % label, rc_l, rc_s)
        try:
            ds, dl = json.loads(out_s.decode()), json.loads(out_l.decode())
        except (UnicodeDecodeError, ValueError):
            t.check("[%s] both print one JSON document" % label, False, "JSON", out_l[:200])
            continue
        for k in ("state", "code"):
            t.eq("[%s] %s equals show's" % (label, k), dl.get(k), ds.get(k))
        kp = lambda doc: ((doc.get("data") or {}).get("error") or {}).get("key_path", "<missing>")  # noqa: E731
        t.eq("[%s] data.error.key_path equals show's" % label, kp(dl), kp(ds))
        t.check("[%s] marker value not echoed by lint" % label, mb not in out_l and mb not in err_l,
                "absent", "present")


@check(T, "T2.usage_errors", "missing --file / unknown flag: exit 2 USAGE_ERROR (JSON only with --json)")
def _(t, ctx):
    p = fixture(ctx, "clean")
    for label, args, js in (("missing --file, --json", ["profile", "lint", "--json"], True),
                            ("unknown flag, --json", ["profile", "lint", "--file", str(p), "--json", "--bogus"], True),
                            ("missing --file, plain", ["profile", "lint"], False),
                            ("--file without value", ["profile", "lint", "--json", "--file"], True)):
        rc, out, err, _ = ctx.run(args)
        t.eq("[%s] exit code" % label, rc, 2)
        if js:
            try:
                doc = json.loads(out.decode())
                t.eq("[%s] code" % label, doc.get("code"), "USAGE_ERROR")
                t.eq("[%s] state" % label, doc.get("state"), "failed")
            except (UnicodeDecodeError, ValueError):
                t.check("[%s] stdout is one JSON document" % label, False, "JSON", out[:200])
        else:
            t.eq("[%s] stdout empty" % label, out, b"")


@check(T, "T2.no_writes", "lint writes no file next to the profile or in the working directory")
def _(t, ctx):
    p = fixture(ctx, "all-rules", "nowrite")
    cwd = ctx.new_dir("cwd")
    before = sorted(os.listdir(p.parent)), sorted(os.listdir(cwd))
    rc, out, err, _ = ctx.run(["profile", "lint", "--file", str(p), "--json"], cwd=cwd)
    t.eq("exit code", rc, 3)
    t.eq("no new files", (sorted(os.listdir(p.parent)), sorted(os.listdir(cwd))), before)
