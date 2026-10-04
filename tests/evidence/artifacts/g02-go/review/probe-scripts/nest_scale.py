#!/usr/bin/env python3
"""Scaling of `profile show` on nested inline tables / arrays inside [meta].
Each run is bounded: SIGKILL (exact child PID) after T seconds or RSS > CAP KiB.
Usage: nest_scale.py <bin> <out-json>
"""
import json, os, subprocess, sys, tempfile, time, signal

BIN, OUT = sys.argv[1], sys.argv[2]
T, CAP_KIB = 20.0, 2 * 1024 * 1024
d = tempfile.mkdtemp(prefix="hrg-nest-")
rows = []


def rss_kib(pid):
    r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(r) if r else 0


def one(kind, depth):
    if kind == "inline_table":
        body = "a=" + "{b=" * depth + "1" + "}" * depth
    elif kind == "array":
        body = "a=" + "[" * depth + "]" * depth
    else:
        body = "a=" + "[{b=" * depth + "1" + "}]" * depth
    text = "schema_version=1\nname=\"x\"\nrevision=1\n[meta]\n" + body + "\n"
    path = os.path.join(d, f"{kind}-{depth}.toml")
    open(path, "w").write(text)
    t0 = time.monotonic()
    p = subprocess.Popen([BIN, "profile", "show", "--file", path, "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env={"PATH": "/usr/bin:/bin", "HOME": d, "TMPDIR": d})
    peak, killed = 0, None
    while p.poll() is None:
        peak = max(peak, rss_kib(p.pid))
        if time.monotonic() - t0 > T:
            killed = "time"
        elif peak > CAP_KIB:
            killed = "rss"
        if killed:
            os.kill(p.pid, signal.SIGKILL)
            break
        time.sleep(0.02)
    out, err = p.communicate()
    el = time.monotonic() - t0
    try:
        code = json.loads(out).get("code")
    except Exception:
        code = None
    row = {"kind": kind, "depth": depth, "file_bytes": len(text), "elapsed_s": round(el, 3), "peak_rss_kib_sampled": peak,
           "killed_by_reviewer": killed, "exit": p.returncode, "code": code, "stderr_head": err.decode("utf-8", "replace")[:160]}
    rows.append(row)
    print(json.dumps(row), flush=True)
    return row


for kind in ("inline_table", "array", "array_of_inline"):
    for depth in (100, 1000, 2000, 4000, 8000, 16000):
        r = one(kind, depth)
        if r["killed_by_reviewer"]:
            break
json.dump({"bin": BIN, "limits": {"time_s": T, "rss_cap_kib": CAP_KIB}, "rows": rows}, open(OUT, "w"), indent=1)
