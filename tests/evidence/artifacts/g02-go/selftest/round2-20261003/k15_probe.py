#!/usr/bin/env python3
"""K15 probe: parser time and peak RSS for adversarial TOML shapes up to 1 MiB.

Usage: k15_probe.py <heimdall-proto> <out-json> [limit_s=2] [rss_limit_mib=256]
The inputs are generated first; the measurements run in a fresh, small Python
process, because on Linux a child's ru_maxrss also counts the parent's memory
image at fork/exec time (signal->maxrss inherits the pre-exec mm high-water).
Every run is bounded: the exact child PID is SIGKILLed after WATCH_S seconds or
when sampled RSS exceeds CAP_MIB. Peak RSS is ru_maxrss from wait4 (bytes on
darwin, KiB on Linux) or the sampled peak when killed. Writes only temp files.
"""
import json, os, signal, subprocess, sys, tempfile, time

BIN, OUT = sys.argv[1], sys.argv[2]
LIMIT_S = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
RSS_MIB = float(sys.argv[4]) if len(sys.argv) > 4 else 256.0
WATCH_S, CAP_MIB = 6.0, 1024.0
MAXB = 1 << 20
HEAD = 'schema_version = 1\nname = "x"\nrevision = 1\n'
d = tempfile.mkdtemp(prefix="hp-k15-")


def rss_mib_sampled(pid):
    if os.path.exists("/proc/%d/status" % pid):
        try:
            for line in open("/proc/%d/status" % pid):
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
        except OSError:
            return 0.0
        return 0.0
    try:
        r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        return int(r) / 1024 if r else 0.0
    except Exception:
        return 0.0


def fit(make, lo=1, hi=1 << 22):
    """Largest n with len(make(n)) <= MAXB (binary search)."""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(make(mid).encode()) <= MAXB:
            lo = mid
        else:
            hi = mid - 1
    return lo


SHAPES = {
    "inline_table_nest": lambda n: HEAD + "[meta]\na = " + "{b = " * n + "1" + "}" * n + "\n",
    "array_nest": lambda n: HEAD + "[meta]\na = " + "[" * n + "]" * n + "\n",
    "array_of_inline_nest": lambda n: HEAD + "[meta]\na = " + "[{b = " * n + "1" + "}]" * n + "\n",
    "dotted_key_depth": lambda n: HEAD + "[meta]\n" + ".".join(["a"] * n) + " = 1\n",
    "table_header_depth": lambda n: HEAD + "[" + ".".join(["meta"] + ["a"] * n) + "]\nx = 1\n",
    "dotted_key_in_inline": lambda n: HEAD + "[meta]\nz = {" + ".".join(["a"] * n) + " = 1}\n",
    "many_keys": lambda n: HEAD + "[meta]\n" + "".join("k%d = 1\n" % i for i in range(n)),
    "many_tables": lambda n: HEAD + "".join("[meta.t%d]\n" % i for i in range(n)),
    "array_of_tables": lambda n: HEAD + "[meta]\n" + "[[meta.x]]\n" * n,
    "wide_inline": lambda n: HEAD + "[meta]\na = {" + ", ".join("k%d = 1" % i for i in range(n)) + "}\n",
    "wide_array": lambda n: HEAD + "[meta]\na = [" + "1," * n + "]\n",
    "wide_array_of_inline": lambda n: HEAD + "[meta]\na = [" + "{b = 1}," * n + "]\n",
    "long_string": lambda n: HEAD + "[meta]\na = \"" + "x" * n + "\"\n",
    "long_ml_string": lambda n: HEAD + "[meta]\na = \"\"\"\n" + "x\\\n" * n + "\"\"\"\n",
    "many_destinations": lambda n: HEAD + "".join(
        '[[destinations]]\nid = "d%d"\nalias = "a%d"\nhost = "h"\naccount = "u"\n' % (i, i) for i in range(n)),
    "nest32_repeated": lambda n: HEAD + "[meta]\n" + "".join(
        "k%d = " % i + "{b = " * 32 + "1" + "}" * 32 + "\n" for i in range(n)),
    "nest64_arrays_repeated": lambda n: HEAD + "[meta]\n" + "".join(
        "k%d = " % i + "[" * 64 + "]" * 64 + "\n" for i in range(n)),
    "deep_in_string_not_nesting": lambda n: HEAD + "[meta]\na = \"" + "{[" * n + "\"\n",
}

# Worst cases just inside the Go guard (MaxKeyDepth 32, MaxStructureUnits 65536,
# MaxKeyPathBytes 2 MiB), and a few just outside it (over_*); n is fixed, not
# fitted.
M = HEAD + "[meta]\n"
AT_LIMIT = {
    "at_limit_inline_nest30_x1049": (1049, lambda n: M + "".join(  # 61 units/line, depth 32
        "k%d = " % i + "{b = " * 30 + "1" + "}" * 30 + "\n" for i in range(n))),
    "over_bytes_deep_header_65000_keys": (65000, lambda n: HEAD + "[" + ".".join(["meta"] + ["a"] * 30) + "]\n" + "".join(
        "k%d = 1\n" % i for i in range(n))),
    "over_bytes_dotted31_x2064": (2064, lambda n: M + "".join("k%d" % i + ".a" * 30 + " = 1\n" for i in range(n))),
    "over_bytes_deep_inline_64000_keys": (64000, lambda n: M + "z = " + "{b = " * 29 + "{" + ", ".join(
        "k%d = 1" % i for i in range(n)) + "}" + "}" * 29 + "\n"),
    "at_limit_array_of_inline_32000": (32000, lambda n: M + "a = [" + "{b = 1}," * n + "]\n"),
    "at_limit_destinations_10000": (10000, lambda n: HEAD + "".join(
        '[[destinations]]\nid = "d%d"\nalias = "a%d"\nhost = "h"\naccount = "u"\n' % (i, i) for i in range(n))),
    "at_limit_array_nest30_x2064": (2064, lambda n: M + "".join("k%d = " % i + "[" * 30 + "]" * 30 + "\n" for i in range(n))),
    "at_limit_deep_header_28000_keys": (28000, lambda n: HEAD + "[" + ".".join(["meta"] + ["a"] * 30) + "]\n" + "".join(
        "k%d = 1\n" % i for i in range(n))),
    "at_limit_deep_inline_27000_keys": (27000, lambda n: M + "z = " + "{b = " * 29 + "{" + ", ".join(
        "k%d = 1" % i for i in range(n)) + "}" + "}" * 29 + "\n"),
    "at_limit_dotted31_x1800": (1800, lambda n: M + "".join("k%d" % i + ".a" * 30 + " = 1\n" for i in range(n))),
    "at_limit_long_header_comps_60_keys": (60, lambda n: HEAD + "[" + ".".join(["meta"] + ["a" * 1000] * 30) + "]\n" + "".join(
        "k%d = 1\n" % i for i in range(n))),
    "at_limit_long_key_names_100": (100, lambda n: M + "".join("k%d%s = 1\n" % (i, "x" * 10000) for i in range(n))),
    "at_limit_long_quoted_dotted_keys": (60, lambda n: M + "".join(
        'k%d."%s"."%s" = 1\n' % (i, "q" * 5000, "r" * 5000) for i in range(n))),
    "at_limit_dotted_inline_mix_x1560": (1560, lambda n: M + "".join(
        "k%d = " % i + "{a.a.a = " * 10 + "1" + "}" * 10 + "\n" for i in range(n))),
}

if len(sys.argv) > 5 and sys.argv[5] == "--measure":
    d = sys.argv[6]
    PLAN = json.load(open(os.path.join(d, "plan.json")))
else:
    PLAN = []
    for name, make in list(SHAPES.items()) + [(k, v) for k, v in AT_LIMIT.items()]:
        if isinstance(make, tuple):
            n, make = make
        else:
            n = fit(make)
        text = make(n)
        path = os.path.join(d, name + ".toml")
        with open(path, "w") as f:
            f.write(text)
        PLAN.append([name, n, len(text.encode()), path])
    json.dump(PLAN, open(os.path.join(d, "plan.json"), "w"))
    del text
    rc = subprocess.run([sys.executable, __file__, BIN, OUT, str(LIMIT_S), str(RSS_MIB), "--measure", d]).returncode
    sys.exit(rc)

rows = []
for name, n, nbytes, path in PLAN:
    t0 = time.monotonic()
    p = subprocess.Popen([BIN, "profile", "show", "--file", path, "--json"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "HOME": d, "TMPDIR": d})
    peak, killed = 0.0, None
    import threading
    out = {}

    def drain():
        out["o"], out["e"] = p.stdout.read(), p.stderr.read()
    th = threading.Thread(target=drain); th.start()
    while True:
        wp, st, ru = os.wait4(p.pid, os.WNOHANG)
        if wp:
            break
        peak = max(peak, rss_mib_sampled(p.pid))
        if time.monotonic() - t0 > WATCH_S:
            killed = "time"
        elif peak > CAP_MIB:
            killed = "rss"
        if killed:
            os.kill(p.pid, signal.SIGKILL)  # exact PID this script started
            wp, st, ru = os.wait4(p.pid, 0)
            break
        time.sleep(0.01)
    el = time.monotonic() - t0
    p.returncode = os.waitstatus_to_exitcode(st)
    th.join()
    maxrss_mib = ru.ru_maxrss / (1024 * 1024) if sys.platform == "darwin" else ru.ru_maxrss / 1024
    try:
        code = json.loads(out["o"]).get("code")
    except Exception:
        code = None
    ok = killed is None and el < LIMIT_S and maxrss_mib < RSS_MIB and code in ("PROFILE_OK", "SCHEMA_INVALID")
    row = {"shape": name, "n": n, "file_bytes": nbytes, "elapsed_s": round(el, 3),
           "peak_rss_mib": round(max(maxrss_mib, peak), 1), "killed_by_probe": killed, "exit": p.returncode,
           "code": code, "within_bounds": ok}
    rows.append(row)
    print(("PASS" if ok else "FAIL"), json.dumps(row), flush=True)

allok = all(r["within_bounds"] for r in rows)
json.dump({"bin": BIN, "limits": {"time_s": LIMIT_S, "rss_mib": RSS_MIB, "watch_s": WATCH_S, "cap_mib": CAP_MIB},
           "platform": sys.platform, "rows": rows, "all_within_bounds": allok}, open(OUT, "w"), indent=1)
print("SUMMARY", sum(r["within_bounds"] for r in rows), "/", len(rows), flush=True)
sys.exit(0 if allok else 1)
