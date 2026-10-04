#!/usr/bin/env python3
"""G02 host measurements: one methodology for go / rust / ts darwin-arm64 artifacts.

Run with tests/g02/.venv/bin/python (pyte for TUI timing):

  tests/g02/.venv/bin/python tools/benchmarks/g02/measure.py [--passes 2] [--warmup 10] [--n 100]
        [--rss-n 15] [--tui-n 30] [--key-sessions 30] [--idle-s 20] [--cold-n 5] [--smoke]

What is measured (all candidates interleaved round-robin, start candidate rotated each iteration,
plus a no-op control so the launcher floor is visible):
  startup_version      `version --json` wall time (subprocess spawn to exit, stdout captured)
  startup_profile      `profile show --file large-100.toml --json`
  rss                  peak RSS / peak footprint via /usr/bin/time -l (version, profile, TUI workload)
  tui_first_frame      launch -> all first-screen aliases rendered (pyte screen), homelab and large-100
  tui_keystroke        key write -> screen update on large-100 (j moves, filter typing, Esc clear)
  tui_idle_cpu         user+sys CPU of an idle TUI via /usr/bin/time -l (idle-s vs 2 s control)
  cold_first_exec      first execution of a freshly copied artifact directory vs the second execution
Raw samples go to tests/evidence/artifacts/g02-measure/host-raw.json, summaries to host-summary.json.

Environment for every run: PATH=/usr/bin:/bin, HOME/TMPDIR/cwd inside a private /tmp sandbox, no
SSH_AUTH_SOCK.  The artifacts are used as they are in prototypes/*/dist (never rebuilt).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import g02bench as B  # noqa: E402

TARGET = "darwin-arm64"
CONTROL = "control"
LARGE = B.FIX / "large-100.toml"
HOMELAB = B.FIX / "homelab.toml"
CTRL_BIN = "/usr/bin/true"
CTRL_PTY = ["/usr/bin/printf", "3/3 lab-server nas vps-東京\n"]


def bin_of(cand):
    return str(B.artifact_path(cand, TARGET))


def rotated(items, i):
    k = i % len(items)
    return items[k:] + items[:k]


class Ctx:
    pass


def make_env(sb):
    return {"PATH": "/usr/bin:/bin", "HOME": str(sb / "home"), "TMPDIR": str(sb / "tmp"),
            "LANG": "en_US.UTF-8", "TERM": "xterm-256color"}


# ------------------------------------------------------------------ startup
def timed(argv, env, cwd):
    t0 = time.perf_counter_ns()
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env, cwd=cwd)
    dt = (time.perf_counter_ns() - t0) / 1e6
    return dt, p


def check_version(p):
    try:
        d = json.loads(p.stdout)
        return p.returncode == 0 and d["code"] == "VERSION_OK"
    except Exception:
        return False


def check_profile_large(p):
    try:
        d = json.loads(p.stdout)
        return p.returncode == 0 and d["code"] == "PROFILE_OK" and len(d["data"]["profile"]["destinations"]) == 100
    except Exception:
        return False


def phase_startup(cx, name, argv_tail, checker, warmup, n):
    members = B.CANDIDATES + [CONTROL]
    samples = {m: [] for m in members}
    fails = {m: 0 for m in members}
    for i in range(warmup + n):
        for m in rotated(members, i):
            argv = [CTRL_BIN] if m == CONTROL else [bin_of(m)] + argv_tail
            dt, p = timed(argv, cx.env, cx.cwd)
            if i < warmup:
                continue
            ok = True if m == CONTROL else checker(p)
            if ok:
                samples[m].append(dt)
            else:
                fails[m] += 1
    return {"warmup": warmup, "n_requested": n, "samples_ms": samples, "failed_samples": fails}


# ------------------------------------------------------------------ rss
def run_time_l(argv, env, cwd):
    p = subprocess.run([B.TIME_BIN, "-l"] + argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env, cwd=cwd)
    d = B.time_l_parse(p.stderr.decode("utf-8", "replace"))
    d["rc"] = p.returncode
    return d, p


def phase_rss_cli(cx, n):
    out = {}
    for name, tail, checker in (("version", ["version", "--json"], check_version),
                                ("profile_large", ["profile", "show", "--file", str(LARGE), "--json"],
                                 check_profile_large)):
        members = B.CANDIDATES + [CONTROL]
        res = {m: [] for m in members}
        for i in range(n + 2):          # 2 warmups
            for m in rotated(members, i):
                argv = [CTRL_BIN] if m == CONTROL else [bin_of(m)] + tail
                d, p = run_time_l(argv, cx.env, cx.cwd)
                if i < 2:
                    continue
                d["ok"] = True if m == CONTROL else checker(p)
                res[m].append(d)
        out[name] = res
    return out


# ------------------------------------------------------------------ TUI workload
def sel_alias_pred(pty, alias):
    pat = re.compile(r"^[─-╿]?> " + re.escape(alias))
    return lambda: any(pat.match(l) for l in pty.lines())


def filter_count(typed, aliases, hosts):
    t = typed.lower()
    return sum(1 for a, h in zip(aliases, hosts) if t in a.lower() or t in h.lower())


def status_pred(pty, shown, total, text=None, absent=None):
    def pred():
        st = B.status_of(pty.lines())
        if st is None or (st[0], st[1]) != (shown, total):
            return False
        rest = B.STATUS_RE.sub("", st[2], count=1)
        if text is not None and text not in rest:
            return False
        if absent is not None and absent in rest:
            return False
        return True
    return pred


def first_frame_pred(pty, profile_name, aliases):
    if profile_name == "homelab":
        return lambda: all(a in pty.text() for a in aliases) and (B.status_of(pty.lines()) or (0, 0))[:2] == (3, 3)
    first10 = aliases[:10]
    return lambda: all(a in pty.text() for a in first10) and (B.status_of(pty.lines()) or (0, 0))[:2] == (100, 100)


def start_tui(cx, cand, profile, wrapper=None, stderr=subprocess.PIPE):
    argv = (wrapper or []) + [bin_of(cand), "tui", "--file", str(profile)]
    return B.Pty(cx.pyte, argv, cx.env, cx.cwd, 24, 80, stderr=stderr)


def tui_first_frame(cx, cand, profile_name):
    profile = HOMELAB if profile_name == "homelab" else LARGE
    aliases = cx.aliases[profile_name]
    if cand == CONTROL:
        p = B.Pty(cx.pyte, CTRL_PTY, cx.env, cx.cwd, 24, 80)
        r = p.wait_until(lambda: "lab-server" in p.text(), 5, p.t0)
        p.finish(quit_key=b"")
        return {"ok": r is not None, "ms": r["ms_to_update"] if r else None,
                "ms_first_byte": r["ms_to_first_byte"] if r else None, "bytes": r["bytes"] if r else None,
                "popen_ms": (p.t_spawned - p.t0) / 1e6}
    p = start_tui(cx, cand, profile)
    r = p.wait_until(first_frame_pred(p, profile_name, aliases), 10, p.t0)
    alt = b"\x1b[?1049h" in p.raw
    rc, forced, err = (None, None, b"")
    p.drain(0.05)
    rc, forced, err = p.finish()
    return {"ok": r is not None, "ms": r["ms_to_update"] if r else None,
            "ms_first_byte": r["ms_to_first_byte"] if r else None, "bytes": r["bytes"] if r else None,
            "popen_ms": (p.t_spawned - p.t0) / 1e6, "alt_screen_seen": alt, "exit_code": rc,
            "forced_kill": forced, "stderr_bytes": len(err)}


def tui_workload(cx, cand, wrapper=None, idle_s=0.0, moves=20, filt="host-05"):
    """First frame on large-100, `moves` x j, '/', type filt char by char, Esc, optional idle, q."""
    aliases, hosts = cx.aliases["large"], cx.hosts["large"]
    p = start_tui(cx, cand, LARGE, wrapper=wrapper)
    out = {"ok": True, "moves_ms": [], "moves_first_byte_ms": [], "type_ms": [], "type_first_byte_ms": [],
           "esc_ms": None, "failures": []}
    r = p.wait_until(first_frame_pred(p, "large", aliases), 10, p.t0)
    if r is None:
        out["ok"] = False
        out["failures"].append("first_frame")
        rc, forced, err = p.finish()
        out.update(exit_code=rc, forced_kill=forced, stderr_text=err.decode("utf-8", "replace"))
        return out
    out["first_frame_ms"] = r["ms_to_update"]
    p.drain(0.1)
    for i in range(1, moves + 1):
        p.first_byte_ns = None
        t = p.send("j")
        r = p.wait_until(sel_alias_pred(p, aliases[i]), 5, t)
        if r is None:
            out["failures"].append("move_%d" % i)
            out["ok"] = False
            break
        out["moves_ms"].append(r["ms_to_update"])
        out["moves_first_byte_ms"].append(r["ms_to_first_byte"])
        p.drain(0.01)
    if out["ok"]:
        t = p.send("/")
        p.drain(0.05)
        typed = ""
        for ch in filt:
            typed += ch
            t = p.send(ch)
            r = p.wait_until(status_pred(p, filter_count(typed, aliases, hosts), 100, text=typed), 5, t)
            if r is None:
                out["failures"].append("type_%s" % typed)
                out["ok"] = False
                break
            out["type_ms"].append(r["ms_to_update"])
            out["type_first_byte_ms"].append(r["ms_to_first_byte"])
            p.drain(0.01)
    if out["ok"]:
        t = p.send(b"\x1b")
        r = p.wait_until(status_pred(p, 100, 100, absent=filt), 5, t)
        if r is None:
            out["failures"].append("esc")
            out["ok"] = False
        else:
            out["esc_ms"] = r["ms_to_update"]
            p.drain(0.05)
    if idle_s and out["ok"]:
        p.drain(idle_s)
    rc, forced, err = p.finish()
    out.update(exit_code=rc, forced_kill=forced, stderr_text=err.decode("utf-8", "replace"))
    return out


def phase_first_frame(cx, n):
    res = {}
    for prof in ("homelab", "large"):
        members = B.CANDIDATES + [CONTROL]
        samples = {m: [] for m in members}
        for i in range(n + 3):          # 3 warmups
            for m in rotated(members, i):
                r = tui_first_frame(cx, m, prof)
                if i >= 3:
                    samples[m].append(r)
        res[prof] = samples
    return res


def phase_keystroke(cx, sessions):
    samples = {c: [] for c in B.CANDIDATES}
    for i in range(sessions + 2):
        for c in rotated(B.CANDIDATES, i):
            r = tui_workload(cx, c)
            if i >= 2:
                samples[c].append(r)
    return samples


def phase_rss_tui(cx, n):
    res = {c: [] for c in B.CANDIDATES}
    for i in range(n + 1):
        for c in rotated(B.CANDIDATES, i):
            r = tui_workload(cx, c, wrapper=[B.TIME_BIN, "-l"])
            tl = B.time_l_parse(r.get("stderr_text", ""))
            tl["ok"] = r["ok"]
            tl["exit_code"] = r.get("exit_code")
            tl["failures"] = r["failures"]
            if i >= 1:
                res[c].append(tl)
    return res


def phase_idle(cx, idle_s, reps):
    res = {c: {"idle": [], "control_short": []} for c in B.CANDIDATES}
    for i in range(reps):
        for c in rotated(B.CANDIDATES, i):
            for label, secs in (("idle", idle_s), ("control_short", 2.0)):
                p = start_tui(cx, c, LARGE, wrapper=[B.TIME_BIN, "-l"])
                r = p.wait_until(first_frame_pred(p, "large", cx.aliases["large"]), 10, p.t0)
                ok = r is not None
                t_start = time.perf_counter()
                p.drain(secs)
                held = time.perf_counter() - t_start
                rc, forced, err = p.finish()
                tl = B.time_l_parse(err.decode("utf-8", "replace"))
                tl.update(ok=ok, held_s=held, exit_code=rc, forced_kill=forced)
                res[c][label].append(tl)
    return res


# ------------------------------------------------------------------ cold first exec
def phase_cold(cx, n):
    res = {c: [] for c in B.CANDIDATES}
    base = cx.sb / "cold"
    for i in range(n):
        for c in rotated(B.CANDIDATES, i):
            dst = base / ("%s-%d" % (c, i))
            shutil.copytree(B.artifact_dir(c, TARGET), dst)
            exe = str(dst / "heimdall-proto")
            first_dt, p1 = timed([exe, "version", "--json"], cx.env, cx.cwd)
            second_dt, p2 = timed([exe, "version", "--json"], cx.env, cx.cwd)
            third_dt, p3 = timed([exe, "version", "--json"], cx.env, cx.cwd)
            res[c].append({"first_ms": first_dt, "second_ms": second_dt, "third_ms": third_dt,
                           "ok": all(check_version(p) for p in (p1, p2, p3))})
            shutil.rmtree(dst)
    return res


# ------------------------------------------------------------------ summaries
def vals(lst, key):
    return [x[key] for x in lst if x.get("ok", True) and x.get(key) is not None]


def summarize_pass(pr):
    s = {}
    for k in ("startup_version", "startup_profile"):
        s[k] = {m: B.summarize(v) for m, v in pr[k]["samples_ms"].items()}
    for ph in ("version", "profile_large"):
        s["rss_" + ph] = {m: {"max_rss_bytes": B.summarize(vals(v, "max_rss_bytes")),
                              "peak_footprint_bytes": B.summarize(vals(v, "peak_footprint_bytes"))}
                          for m, v in pr["rss"][ph].items()}
    s["rss_tui_workload"] = {c: {"max_rss_bytes": B.summarize(vals(v, "max_rss_bytes")),
                                 "peak_footprint_bytes": B.summarize(vals(v, "peak_footprint_bytes")),
                                 "failed_sessions": sum(1 for x in v if not x["ok"])}
                             for c, v in pr["rss_tui"].items()}
    s["tui_first_frame"] = {prof: {m: {"ms": B.summarize(vals(v, "ms")),
                                       "ms_first_byte": B.summarize(vals(v, "ms_first_byte")),
                                       "popen_ms": B.summarize([x["popen_ms"] for x in v]),
                                       "failed": sum(1 for x in v if not x["ok"])}
                                   for m, v in d.items()} for prof, d in pr["tui_first_frame"].items()}
    ks = {}
    for c, sess in pr["tui_keystroke"].items():
        ok = [x for x in sess if x["ok"]]
        ks[c] = {"sessions": len(sess), "failed_sessions": len(sess) - len(ok),
                 "move_j_ms": B.summarize([v for x in ok for v in x["moves_ms"]]),
                 "move_j_first_byte_ms": B.summarize([v for x in ok for v in x["moves_first_byte_ms"] if v is not None]),
                 "filter_type_ms": B.summarize([v for x in ok for v in x["type_ms"]]),
                 "filter_type_first_byte_ms": B.summarize([v for x in ok for v in x["type_first_byte_ms"] if v is not None]),
                 "esc_clear_ms": B.summarize([x["esc_ms"] for x in ok if x["esc_ms"] is not None]),
                 "all_keys_ms": B.summarize([v for x in ok for v in x["moves_ms"] + x["type_ms"]
                                             + ([x["esc_ms"]] if x["esc_ms"] is not None else [])])}
    s["tui_keystroke_large100"] = ks
    idle = {}
    for c, d in pr["tui_idle"].items():
        cpu = lambda lst: [x["user_s"] + x["sys_s"] for x in lst if "user_s" in x]
        wall = lambda lst: [x["real_s"] for x in lst if "real_s" in x]
        idle[c] = {"idle_cpu_s": B.summarize(cpu(d["idle"]), boot=0), "idle_real_s": B.summarize(wall(d["idle"]), boot=0),
                   "short_cpu_s": B.summarize(cpu(d["control_short"]), boot=0),
                   "short_real_s": B.summarize(wall(d["control_short"]), boot=0)}
        if idle[c]["idle_cpu_s"].get("n") and idle[c]["short_cpu_s"].get("n"):
            dcpu = idle[c]["idle_cpu_s"]["mean"] - idle[c]["short_cpu_s"]["mean"]
            dwall = idle[c]["idle_real_s"]["mean"] - idle[c]["short_real_s"]["mean"]
            idle[c]["extra_idle_cpu_percent_of_one_core_est"] = round(100.0 * dcpu / dwall, 3) if dwall > 0 else None
    s["tui_idle_cpu"] = idle
    s["cold_first_exec"] = {c: {"first_ms": B.summarize([x["first_ms"] for x in v if x["ok"]], boot=0),
                                "second_ms": B.summarize([x["second_ms"] for x in v if x["ok"]], boot=0),
                                "third_ms": B.summarize([x["third_ms"] for x in v if x["ok"]], boot=0)}
                            for c, v in pr["cold_first_exec"].items()}
    return s


def pooled(passes, getter):
    """Concatenate raw per-candidate lists across passes."""
    out = {}
    for pr in passes:
        for k, v in getter(pr).items():
            out.setdefault(k, []).extend(v)
    return out


def summarize_pooled(passes):
    s = {}
    for k in ("startup_version", "startup_profile"):
        s[k] = {m: B.summarize(v) for m, v in pooled(passes, lambda pr: pr[k]["samples_ms"]).items()}
    s["tui_first_frame"] = {}
    for prof in ("homelab", "large"):
        pooled_ff = pooled(passes, lambda pr: pr["tui_first_frame"][prof])
        s["tui_first_frame"][prof] = {m: {"ms": B.summarize(vals(v, "ms")),
                                          "ms_first_byte": B.summarize(vals(v, "ms_first_byte")),
                                          "failed": sum(1 for x in v if not x["ok"])}
                                      for m, v in pooled_ff.items()}
    pk = pooled(passes, lambda pr: pr["tui_keystroke"])
    s["tui_keystroke_large100"] = {}
    for c, sess in pk.items():
        ok = [x for x in sess if x["ok"]]
        keys = [v for x in ok for v in x["moves_ms"] + x["type_ms"] + ([x["esc_ms"]] if x["esc_ms"] is not None else [])]
        s["tui_keystroke_large100"][c] = {
            "sessions": len(sess), "failed_sessions": len(sess) - len(ok),
            "move_j_ms": B.summarize([v for x in ok for v in x["moves_ms"]]),
            "filter_type_ms": B.summarize([v for x in ok for v in x["type_ms"]]),
            "all_keys_ms": B.summarize(keys),
            "all_keys_first_byte_ms": B.summarize([v for x in ok for v in x["moves_first_byte_ms"] + x["type_first_byte_ms"] if v is not None])}
    for ph in ("version", "profile_large"):
        pr_rss = pooled(passes, lambda pr: pr["rss"][ph])
        s["rss_" + ph] = {m: {"max_rss_bytes": B.summarize(vals(v, "max_rss_bytes")),
                              "peak_footprint_bytes": B.summarize(vals(v, "peak_footprint_bytes"))}
                          for m, v in pr_rss.items()}
    pt = pooled(passes, lambda pr: pr["rss_tui"])
    s["rss_tui_workload"] = {c: {"max_rss_bytes": B.summarize(vals(v, "max_rss_bytes")),
                                 "peak_footprint_bytes": B.summarize(vals(v, "peak_footprint_bytes")),
                                 "failed_sessions": sum(1 for x in v if not x["ok"])} for c, v in pt.items()}
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--passes", type=int, default=2)
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--rss-n", type=int, default=15)
    ap.add_argument("--tui-n", type=int, default=30)
    ap.add_argument("--key-sessions", type=int, default=30)
    ap.add_argument("--idle-s", type=float, default=20.0)
    ap.add_argument("--idle-reps", type=int, default=2)
    ap.add_argument("--cold-n", type=int, default=5)
    ap.add_argument("--smoke", action="store_true", help="tiny run, writes to a -smoke suffix")
    ap.add_argument("--out-dir", default=str(B.ART))
    a = ap.parse_args()
    if a.smoke:
        a.passes, a.warmup, a.n, a.rss_n, a.tui_n, a.key_sessions, a.idle_s, a.idle_reps, a.cold_n = 1, 2, 5, 2, 3, 2, 3.0, 1, 1
    out_dir = Path(a.out_dir)
    suffix = "-smoke" if a.smoke else ""

    os.environ.pop("SSH_AUTH_SOCK", None)
    cx = Ctx()
    cx.pyte = B.load_pyte()
    cx.sb = Path(tempfile.mkdtemp(prefix="hmg02m-", dir="/tmp"))
    for sub in ("home", "tmp", "cwd"):
        (cx.sb / sub).mkdir()
    cx.cwd = str(cx.sb / "cwd")
    cx.env = make_env(cx.sb)
    cx.aliases = {"homelab": B.alias_list(HOMELAB), "large": B.alias_list(LARGE)}
    cx.hosts = {"large": B.host_list(LARGE)}

    meta = {"started_at": B.utc(), "python": sys.version.split()[0], "argv": sys.argv[1:],
            "params": {k: v for k, v in vars(a).items()}, "target": TARGET,
            "env_used": {"PATH": cx.env["PATH"], "TERM": cx.env["TERM"], "LANG": cx.env["LANG"],
                         "HOME": "private sandbox", "TMPDIR": "private sandbox", "cwd": "private sandbox"},
            "pty_size": "80x24",
            "hardware": B.capture_hardware()}
    rc, out, _ = B.run_text([sys.executable, "-c", "import pyte,wcwidth;print(pyte.__file__)"])
    meta["pyte"] = "tests/g02/.venv (pinned pyte==0.8.2, wcwidth==0.9.1)"
    inv_start = B.artifact_inventory()
    meta["artifact_inventory_start"] = inv_start
    meta["load"] = [B.capture_load("start")]
    print("inventory done", flush=True)

    passes = []
    try:
        for pi in range(a.passes):
            pr = {"pass": pi + 1, "started_at": B.utc(), "load": [B.capture_load("pass%d-start" % (pi + 1))]}
            t0 = time.time()
            print("pass", pi + 1, "startup_version", flush=True)
            pr["startup_version"] = phase_startup(cx, "version", ["version", "--json"], check_version, a.warmup, a.n)
            print("pass", pi + 1, "startup_profile", flush=True)
            pr["startup_profile"] = phase_startup(
                cx, "profile", ["profile", "show", "--file", str(LARGE), "--json"], check_profile_large, a.warmup, a.n)
            pr["load"].append(B.capture_load("pass%d-after-startup" % (pi + 1)))
            print("pass", pi + 1, "rss_cli", flush=True)
            pr["rss"] = phase_rss_cli(cx, a.rss_n)
            print("pass", pi + 1, "tui_first_frame", flush=True)
            pr["tui_first_frame"] = phase_first_frame(cx, a.tui_n)
            pr["load"].append(B.capture_load("pass%d-after-first-frame" % (pi + 1)))
            print("pass", pi + 1, "tui_keystroke", flush=True)
            pr["tui_keystroke"] = phase_keystroke(cx, a.key_sessions)
            print("pass", pi + 1, "rss_tui", flush=True)
            pr["rss_tui"] = phase_rss_tui(cx, a.rss_n)
            print("pass", pi + 1, "tui_idle", flush=True)
            pr["tui_idle"] = phase_idle(cx, a.idle_s, a.idle_reps)
            print("pass", pi + 1, "cold", flush=True)
            pr["cold_first_exec"] = phase_cold(cx, a.cold_n)
            pr["load"].append(B.capture_load("pass%d-end" % (pi + 1)))
            pr["finished_at"] = B.utc()
            pr["wall_s"] = round(time.time() - t0, 1)
            passes.append(pr)
            pr["summary"] = summarize_pass(pr)
    finally:
        meta["load"].append(B.capture_load("end"))
        meta["sandbox_leftovers_after_run"] = sorted(
            str(p.relative_to(cx.sb)) for p in cx.sb.rglob("*") if p.is_file() or p.is_dir())
        meta["artifact_inventory_end_sha_unchanged"] = None

    inv_end = B.artifact_inventory()
    meta["artifact_inventory_end_sha_unchanged"] = all(
        [(f["path"], f["sha256"]) for f in inv_start[c][t].get("files", [])]
        == [(f["path"], f["sha256"]) for f in inv_end[c][t].get("files", [])]
        for c in B.CANDIDATES for t in B.TARGETS)
    meta["finished_at"] = B.utc()
    raw = {"meta": meta, "passes": passes}
    summary = {"meta": {k: meta[k] for k in ("started_at", "finished_at", "params", "target")},
               "pooled_across_passes": summarize_pooled(passes),
               "per_pass": [{"pass": p["pass"], "wall_s": p["wall_s"], "summary": p["summary"]} for p in passes]}
    B.write_json(out_dir / ("host-raw%s.json" % suffix), raw)
    B.write_json(out_dir / ("host-summary%s.json" % suffix), summary)
    shutil.rmtree(cx.sb, ignore_errors=True)       # sandbox we created
    print("wrote", out_dir / ("host-raw%s.json" % suffix))


if __name__ == "__main__":
    main()
