#!/usr/bin/env python3
"""Review-3 K15 probe: inputs up to 1 MiB with shapes chosen independently of the
builder's k15 corpus. For each: exit code, result code, wall time and peak RSS of
`heimdall-proto profile show --file F --json`.

usage: k15_shapes.py HEIMDALL_BIN OUT_JSON
"""
import json
import os
import resource
import subprocess
import sys
import tempfile
import time

HP = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]
LIM = 1048576
HEAD = 'schema_version = 1\nname = "x"\nrevision = 1\n[meta]\n'


def fill(prefix, unit, suffix=""):
    n = (LIM - len(prefix) - len(suffix)) // len(unit)
    return prefix + unit * n + suffix


def shapes():
    n = (LIM - len(HEAD) - 10) // 2
    yield "deep_array_nesting", HEAD + "x = " + "[" * n + "]" * n + "\n"
    yield "wide_empty_inline_tables", fill(HEAD + "x = [", "{},", "]\n")
    yield "wide_strings_array", fill(HEAD + "x = [", '"",', "]\n")
    yield "wide_int_array", fill(HEAD + "x = [", "1,", "]\n")
    yield "wide_nested_pairs", fill(HEAD + "x = [", "[[]],", "]\n")
    yield "escape_heavy_string", fill(HEAD + 'x = "', "\\u0041", '"\n')
    yield "multiline_basic_quotes", fill(HEAD + 'x = """', 'a""', '"""\n')
    yield "many_headers", HEAD + "".join("[meta.t%d]\n" % i for i in range(LIM // 14))[: LIM - len(HEAD) - 1]
    yield "array_of_tables", fill(HEAD, "[[meta.a]]\n")
    yield "many_keys_flat", HEAD + "".join("k%d=1\n" % i for i in range(LIM // 9))[: LIM - len(HEAD) - 1]
    yield "huge_float_exponents", fill(HEAD + "x = [", "1e400,", "]\n")
    yield "bigint_overflow", HEAD + "x = 9" + "9" * (LIM - len(HEAD) - 10) + "\n"
    yield "datetimes", fill(HEAD + "x = [", "1979-05-27T07:32:00Z,", "]\n")
    yield "comments_only", fill(HEAD, "#" + "c" * 78 + "\n")
    yield "inline_table_wide_keys", fill(HEAD + "x = {", "a%s=1," % "", "b=1}\n")
    yield "nested_array_inline_mix", HEAD + "x = " + "[{a=" * 20000 + "1" + "}]" * 20000 + "\n"
    yield "crlf_bom", "﻿" + fill(HEAD.replace("\n", "\r\n"), "k=1\r\n")


RSS_WRAP = os.environ.get("RSS_WRAP", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "../../../../../g02/rss_wrap.py"))


def run(path):
    rep = path + ".rss.json"
    t0 = time.monotonic()
    try:
        p = subprocess.run([sys.executable, RSS_WRAP, rep, "--", HP, "profile", "show", "--file", path, "--json"],
                           capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"rc": "timeout"}
    code = None
    try:
        code = json.loads(p.stdout)["code"]
    except Exception:
        pass
    r = json.load(open(rep))
    os.unlink(rep)
    return {"rc": p.returncode, "code": code, "wall_s": r.get("wall_s"),
            "maxrss_mib": round((r.get("maxrss_bytes") or 0) / 2**20, 1)}


def main():
    d = tempfile.mkdtemp(prefix="hp-rv3-k15-")
    res = {}
    for name, text in shapes():
        p = os.path.join(d, name + ".toml")
        b = text.encode()[:LIM]
        open(p, "wb").write(b)
        r = run(p)
        r["bytes"] = len(b)
        res[name] = r
        print(name, json.dumps(r), flush=True)
    json.dump(res, open(OUT, "w"), indent=1)
    for f in os.listdir(d):
        os.unlink(os.path.join(d, f))
    os.rmdir(d)


if __name__ == "__main__":
    main()
