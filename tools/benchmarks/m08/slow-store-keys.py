#!/usr/bin/env python3
"""Probe step (ii) (m08-w3-plan W3-6; ruled 2026-11-24): TUI key handling while the runtime's
issuer child reloads its CA key from a slow Secret Service. Run inside the secret-service probe
container by secret-service-probe.sh (mode `slow`), after the runtime was started with its
session bus behind agent-delay.py.

The background loop runs `heimdall issuer unlock` on a pseudo-terminal, one after another: each
asks the runtime's issuer child to load its CA from the store, through the delayed bus. The
keys are timed by bench.py's own `key_to_frame` (the reconstructed screen, the effect absent
before the key). The row measures **issuer secret-store load under a slow Secret Service**, not
each signature: a signature is in-memory work in the child.

Usage: slow-store-keys.py --heimdall HM --out OUT --scratch DIR --delay-ms N [--samples N]
"""
import argparse
import json
import os
import runpy
import subprocess
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--heimdall", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--scratch", required=True)
    p.add_argument("--delay-ms", type=int, required=True)
    p.add_argument("--samples", type=int, default=200)
    a = p.parse_args()
    g = runpy.run_path(os.path.join(here, "bench.py"))
    Bench = g["Bench"]

    class SlowStore(Bench):
        def background(self, stop, lat):
            n = 0
            while not stop.is_set():
                tr = os.path.join(a.scratch, "bg-unlock.txt")
                t = time.perf_counter()
                rc = subprocess.run([sys.executable, "-I", os.path.join(here, "pty-drive.py"), tr, "120", "[y/N]", "yes",
                                     "--", a.heimdall, "--json", "issuer", "unlock"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
                lat.append(((time.perf_counter() - t) * 1000, rc == 0))
                n += 1

    ns = argparse.Namespace(heimdall=a.heimdall, out=a.out, samples=a.samples, destinations=1,
                            slow_profile="(issuer unlock loop)", bg_delay_ms=a.delay_ms)
    b = SlowStore(ns)
    b.key_to_frame("key_to_frame_quiet", loaded=False)
    b.key_to_frame("key_to_frame_slow_store", loaded=True)
    cond = (f"one TUI on a 120x40 pty, view keys 2 and 1 in turn, while `issuer unlock` runs in a loop: each makes the "
            f"runtime's issuer child load its CA from the Secret Service through a bus relay holding each request "
            f"{a.delay_ms} ms. Measures issuer secret-store load under a slow Secret Service, not each signature")
    for k in ("key_to_frame_slow_store", "key_to_first_byte_slow_store"):
        if k in b.result:
            b.result[k]["conditions"] = cond
    bg = b.result.pop("background_ensures", None)
    if bg is not None:
        bg["what"] = "issuer unlock calls in the background (latency includes the CLI's process start)"
        b.result["background_unlocks"] = bg
    with open(os.path.join(a.out, "slow-store.json"), "w", encoding="utf-8") as fh:
        json.dump(b.result, fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
