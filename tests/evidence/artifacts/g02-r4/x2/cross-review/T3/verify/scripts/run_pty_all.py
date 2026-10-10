"""M00-T05-r4-x2-xrev-T3-verify: record every (build, case, TERM) in a plain pty and replay each
recording into xterm.js headless.

Usage: python3 -I run_pty_all.py <scratch-root> [--terms xterm-256color,tmux-256color]
                                [--cases-only R1,R2] [--builds a,b] [--reps 1]
Writes <scratch>/rec/<build>/<case>-<term>[-r<rep>].json (pty bytes) and
       <scratch>/xt/<build>/<case>-<term>[-r<rep>].json (xterm.js screens).
"""
import argparse
import json
import os
import subprocess
import sys

PROF = {"homelab": "homelab.toml", "wide": "wide.toml"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scratch")
    ap.add_argument("--terms", default="xterm-256color,tmux-256color")
    ap.add_argument("--cases-only", default=None)
    ap.add_argument("--builds", default=None)
    ap.add_argument("--reps", type=int, default=1)
    a = ap.parse_args()
    S = os.path.abspath(a.scratch)
    spec = json.load(open(os.path.join(S, "scripts", "cases.json"), encoding="utf-8"))
    cases = spec["cases"]
    if a.cases_only:
        cases = {k: v for k, v in cases.items() if k in a.cases_only.split(",")}
    builds = a.builds.split(",") if a.builds else spec["builds"]
    fails = 0
    for build in builds:
        binpath = os.path.join(S, "bins", build, "heimdall-proto")
        for cid, case in cases.items():
            for term in a.terms.split(","):
                for rep in range(1, a.reps + 1):
                    tag = "%s-%s" % (cid, term) + ("" if a.reps == 1 else "-r%d" % rep)
                    rec = os.path.join(S, "rec", build, tag + ".json")
                    xt = os.path.join(S, "xt", build, tag + ".json")
                    os.makedirs(os.path.dirname(rec), exist_ok=True)
                    os.makedirs(os.path.dirname(xt), exist_ok=True)
                    cmd = [sys.executable, "-I", os.path.join(S, "scripts", "pty_record.py"),
                           "--bin", binpath, "--profile", os.path.join(S, "profiles", PROF[case["profile"]]),
                           "--size", case["size"], "--term", term, "--sandbox-root", os.path.join(S, "sandboxes"),
                           "--out", rec] + list(case["keys"])
                    r = subprocess.run(cmd, capture_output=True, text=True)
                    if r.returncode != 0:
                        fails += 1
                        print("RECORD FAIL %s %s: %s" % (build, tag, (r.stderr or "")[-300:]), flush=True)
                        continue
                    r2 = subprocess.run(["node", os.path.join(S, "scripts", "xterm_replay.js"),
                                         os.path.join(S, "xtermjs"), rec, xt], capture_output=True, text=True)
                    if r2.returncode != 0:
                        fails += 1
                        print("REPLAY FAIL %s %s: %s" % (build, tag, (r2.stderr or "")[-300:]), flush=True)
                        continue
                    print("%s %s %s" % (build, tag, (r2.stdout or "").strip()), flush=True)
    print("done, failures=%d" % fails)


if __name__ == "__main__":
    main()
