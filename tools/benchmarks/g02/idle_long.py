#!/usr/bin/env python3
"""G02 long idle CPU hold (round 2): same TUI/idle method as measure.phase_idle, longer hold.

  tests/g02/.venv/bin/python tools/benchmarks/g02/idle_long.py [--idle-s 300] [--reps 3] [--short-s 2]

Per rep the three candidates are visited round-robin (start member rotated each rep); for each, one
idle hold (idle-s seconds after the first large-100 frame) and one short hold (short-s seconds) are run
under `/usr/bin/time -l`.  Net idle CPU = (idle cpu - mean short cpu) / (idle real - mean short real), the
same arithmetic as measure.summarize_pass; gross = idle cpu / idle real.  /usr/bin/time -l reports CPU
at 10 ms resolution, which is 0.0033% of a 300 s hold, so resolution is not the limit here.
Writes tests/evidence/artifacts/g02-measure/idle-long-raw.json and idle-long-summary.json.
"""
import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import g02bench as B  # noqa: E402
import measure as M  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--idle-s", type=float, default=300.0)
    ap.add_argument("--short-s", type=float, default=2.0)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out-dir", default=str(B.ART))
    a = ap.parse_args()
    os.environ.pop("SSH_AUTH_SOCK", None)
    cx = M.Ctx()
    cx.pyte = B.load_pyte()
    cx.sb = Path(tempfile.mkdtemp(prefix="hmg02i-", dir="/tmp"))
    for sub in ("home", "tmp", "cwd"):
        (cx.sb / sub).mkdir()
    cx.cwd = str(cx.sb / "cwd")
    cx.env = M.make_env(cx.sb)
    cx.aliases = {"homelab": B.alias_list(M.HOMELAB), "large": B.alias_list(M.LARGE)}
    cx.hosts = {"large": B.host_list(M.LARGE)}
    inv_start = B.artifact_inventory()
    meta = {"started_at": B.utc(), "params": vars(a).copy(), "target": M.TARGET, "hardware": B.capture_hardware(),
            "artifact_sha256_start": {c: {f["path"]: f["sha256"] for f in inv_start[c][M.TARGET]["files"]} for c in B.CANDIDATES},
            "load": [B.capture_load("start")], "order": []}
    res = {c: {"idle": [], "control_short": []} for c in B.CANDIDATES}
    try:
        for i in range(a.reps):
            order = M.rotated(B.CANDIDATES, i)
            meta["order"].append(order)
            for c in order:
                for label, secs in (("idle", a.idle_s), ("control_short", a.short_s)):
                    p = M.start_tui(cx, c, M.LARGE, wrapper=[B.TIME_BIN, "-l"])
                    r = p.wait_until(M.first_frame_pred(p, "large", cx.aliases["large"]), 10, p.t0)
                    ok = r is not None
                    t0 = time.perf_counter()
                    p.drain(secs)
                    held = time.perf_counter() - t0
                    rc, forced, err = p.finish()
                    tl = B.time_l_parse(err.decode("utf-8", "replace"))
                    tl.update(ok=ok, held_s=held, exit_code=rc, forced_kill=forced, rep=i + 1, at=B.utc())
                    res[c][label].append(tl)
                    print(i + 1, c, label, {k: tl.get(k) for k in ("ok", "real_s", "user_s", "sys_s", "exit_code", "forced_kill")}, flush=True)
            meta["load"].append(B.capture_load("rep%d-end" % (i + 1)))
    finally:
        meta["load"].append(B.capture_load("end"))
        shutil.rmtree(cx.sb, ignore_errors=True)
    inv_end = B.artifact_inventory()
    meta["artifact_sha256_unchanged"] = all(
        {f["path"]: f["sha256"] for f in inv_end[c][M.TARGET]["files"]} == meta["artifact_sha256_start"][c] for c in B.CANDIDATES)
    meta["finished_at"] = B.utc()

    summ = {}
    for c, d in res.items():
        good = [x for x in d["idle"] if x["ok"] and "user_s" in x]
        short = [x for x in d["control_short"] if x["ok"] and "user_s" in x]
        cpu = lambda x: x["user_s"] + x["sys_s"]
        s = {"idle_runs": len(d["idle"]), "idle_ok": len(good), "short_ok": len(short),
             "idle_cpu_s": [round(cpu(x), 3) for x in good], "idle_real_s": [round(x["real_s"], 3) for x in good],
             "short_cpu_s": [round(cpu(x), 3) for x in short], "short_real_s": [round(x["real_s"], 3) for x in short],
             "idle_max_rss_bytes": [x.get("max_rss_bytes") for x in good]}
        if good and short:
            sc = sum(cpu(x) for x in short) / len(short)
            sr = sum(x["real_s"] for x in short) / len(short)
            gross = [100.0 * cpu(x) / x["real_s"] for x in good]
            net = [100.0 * (cpu(x) - sc) / (x["real_s"] - sr) for x in good]
            s["gross_pct_of_one_core_per_run"] = [round(v, 4) for v in gross]
            s["net_pct_of_one_core_per_run"] = [round(v, 4) for v in net]
            s["gross_pct_mean"] = round(sum(gross) / len(gross), 4)
            s["net_pct_mean"] = round(sum(net) / len(net), 4)
            s["net_pct_max"] = round(max(net), 4)
            s["pooled_net_pct"] = round(100.0 * (sum(cpu(x) for x in good) - sc * len(good)) / (sum(x["real_s"] for x in good) - sr * len(good)), 4)
        summ[c] = s
    B.write_json(Path(a.out_dir) / "idle-long-raw.json", {"meta": meta, "runs": res})
    B.write_json(Path(a.out_dir) / "idle-long-summary.json", {"meta": {k: meta[k] for k in ("started_at", "finished_at", "params", "order", "artifact_sha256_unchanged")}, "summary": summ})
    print("done", flush=True)


if __name__ == "__main__":
    main()
