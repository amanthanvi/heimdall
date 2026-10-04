#!/usr/bin/env python3
"""Reviewer-2 K15 probe: adversarial <=1 MiB profiles, wall time and peak RSS via os.wait4.
Usage: k15_probe.py BIN OUT.json"""
import json, os, sys, tempfile, time, resource
BIN, OUT = sys.argv[1], sys.argv[2]
LIM = 1048576
HEAD = 'schema_version = 1\nname = "k15"\nrevision = 1\n'
W = tempfile.mkdtemp(prefix="hp-rv2-k15-")


def fill(prefix, unit_open, unit_close, tail=""):
    n = (LIM - len(prefix) - len(tail)) // (len(unit_open) + len(unit_close))
    return prefix + unit_open * n + unit_close * n + tail


cases = {
    "meta_deep_array_closed": fill(HEAD + "[meta]\na = ", "[", "]", "\n"),
    "meta_deep_array_unclosed": HEAD + "[meta]\na = " + "[" * (LIM - len(HEAD) - 20),
    "meta_deep_inline_table": fill(HEAD + "[meta]\na = ", "{b=", "}", "\n"),
    "toplevel_deep_array": fill(HEAD + "zzz = ", "[", "]", "\n"),
    "dest_deep_inline": fill(HEAD + "[[destinations]]\nid = ", "{a=", "}", "\n"),
    "meta_dotted_key_500k": HEAD + "[meta]\n" + "a." * ((LIM - len(HEAD) - 20) // 2) + "a = 1\n",
    "meta_table_header_deep": HEAD + "[meta." + "a." * ((LIM - len(HEAD) - 20) // 2) + "a]\n",
    "meta_many_tables": HEAD + "".join("[meta.t%d]\n" % i for i in range(70000)),
    "meta_wide_array_ints": HEAD + "[meta]\na = [" + "1," * ((LIM - len(HEAD) - 20) // 2) + "1]\n",
    "meta_wide_inline_tables": HEAD + "[meta]\na = [" + "{}," * ((LIM - len(HEAD) - 20) // 3) + "{}]\n",
    "meta_long_string": HEAD + '[meta]\na = "' + "x" * (LIM - len(HEAD) - 20) + '"\n',
    "meta_deep_mixed": fill(HEAD + "[meta]\na = ", "[{b=", "}]", "\n"),
    "many_destinations_16k": HEAD + "".join('[[destinations]]\nid="d%d"\nalias="a%d"\nhost="h"\naccount="u"\n' % (i, i) for i in range(16000)),
}
res = []
for name, text in cases.items():
    data = text.encode()[:LIM]
    p = os.path.join(W, name + ".toml")
    open(p, "wb").write(data)
    t0 = time.time()
    pid = os.fork()
    if pid == 0:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, 2)
        out = os.open(os.path.join(W, name + ".out"), os.O_WRONLY | os.O_CREAT)
        os.dup2(out, 1)
        os.execv(BIN, [BIN, "profile", "show", "--file", p, "--json"])
    _, st, ru = os.wait4(pid, 0)
    el = time.time() - t0
    rss = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    try:
        code = json.loads(open(os.path.join(W, name + ".out")).read())["code"]
    except Exception as e:
        code = "unparseable"
    r = {"case": name, "bytes": len(data), "exit": os.waitstatus_to_exitcode(st), "code": code,
         "wall_ms": round(el * 1000, 1), "peak_rss_mib": round(rss / 1048576, 1),
         "ok": el < 2 and rss < 256 * 1048576 and code in ("PROFILE_OK", "SCHEMA_INVALID")}
    res.append(r)
    print(json.dumps(r), flush=True)
json.dump({"bin": BIN, "platform": sys.platform, "results": res, "all_ok": all(r["ok"] for r in res)}, open(OUT, "w"), indent=1)
import shutil; shutil.rmtree(W)
