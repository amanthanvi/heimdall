#!/usr/bin/env python3
"""Judge a soak run's samples against ADR-0014 section 6.2 (m08-plan U5a).

Usage: python3 -I tools/benchmarks/m08/analyze.py <run directory>      (holds S/ and L/)
       python3 -I tools/benchmarks/m08/analyze.py --self-test
Exit code: 0 when no check failed; 1 when one did; 2 on a usage error.

Windows scale with the run's length D, so a rehearsal exercises the same arithmetic as the
72-hour run: "early" is D/12 to D/6 (hours 6 to 12 of 72), "final" is the last D/12 (the
last 6 hours), and the slope is fitted from D/6 to the end. **A result on a run shorter
than 72 hours is a rehearsal of the harness, never an A34 result**, and the report says so.

Checks (the section 6.2 items this harness version can see):
  2  memory, lane S: median(final) <= median(early) * 1.10 + 4 MiB; slope <= 0.1 MiB/h
     (scaled: the allowed total rise over the fitted span is 6 MiB); maximum <= 150 MiB
  3  descriptors and threads, lane S: max(final) <= max(early) + 4 and + 2
  4  files: the account's file count at the end <= the count at D/3 + 8
  5  retries: no two connection attempts during an sshd outage closer than 1 s, and no
     unrequested attempts beyond 12 per outage
  1  duration and gaps: every gap between samples above 3 ticks is listed
  8  no panic line; both lanes ended DONE
Lane L restarts its runtime, so its memory series is checked per process lifetime for the
maximum only.
"""
import json
import os
import statistics
import sys

MIB = 1024.0


def load(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def slope_per_hour(points):
    """Least-squares slope of (seconds, value) in value per hour."""
    n = len(points)
    if n < 3:
        return 0.0
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    den = sum((p[0] - mx) ** 2 for p in points)
    return 0.0 if den == 0 else sum((p[0] - mx) * (p[1] - my) for p in points) / den * 3600


def merge_root(samples, root):
    """Fill a sample's missing `fds` from the root-side sampler: the same pid, nearest time."""
    for s in samples:
        if s.get("pid") and s.get("fds") is None:
            near = [r for r in root if r.get("pid") == s["pid"]]
            if near:
                s["fds"] = min(near, key=lambda r: abs(r["t"] - s["t"]))["fds"]
    return samples


def judge(samples, events, status, lane, tick):
    fails, notes = [], []
    if not samples:
        return ["no samples"], notes
    D = samples[-1]["t"]
    live = [s for s in samples if s.get("pid") and "rss_kib" in s]
    gaps = [(a["t"], round(b["t"] - a["t"], 1)) for a, b in zip(samples, samples[1:]) if b["t"] - a["t"] > 3 * tick]
    for at, g in gaps:
        notes.append(f"gap of {g} s after t={at}")
    if any(s.get("panic_in_log") for s in samples):
        fails.append("a panic line in a Heimdall log")
    if (status or {}).get("state") != "DONE":
        fails.append(f"the lane ended {(status or {}).get('state')}: {(status or {}).get('reason')}")
    if live:
        peak = max(s["rss_kib"] for s in live) / MIB
        notes.append(f"resident memory peak {peak:.1f} MiB over {len(live)} samples")
        if peak > 150:
            fails.append(f"resident memory peak {peak:.1f} MiB above 150 MiB")
    if lane == "S" and live:
        early = [s for s in live if D / 12 <= s["t"] <= D / 6]
        final = [s for s in live if s["t"] >= D - D / 12]
        if early and final:
            me = statistics.median(s["rss_kib"] for s in early) / MIB
            mf = statistics.median(s["rss_kib"] for s in final) / MIB
            notes.append(f"resident memory median early {me:.1f} MiB, final {mf:.1f} MiB")
            if mf > me * 1.10 + 4:
                fails.append(f"memory grew: final median {mf:.1f} MiB > early {me:.1f} * 1.10 + 4")
            span = [(s["t"], s["rss_kib"] / MIB) for s in live if s["t"] >= D / 6]
            sl = slope_per_hour(span)
            hours = max((D - D / 6) / 3600, 1e-9)
            notes.append(f"memory slope {sl:.3f} MiB/h over {hours:.2f} h")
            # 0.1 MiB/h over the 60 fitted hours of a 72-hour run is 6 MiB in total.
            if sl * hours > 6.0:
                fails.append(f"memory slope {sl:.3f} MiB/h rises more than 6 MiB over the fitted span")
            for key, allow in (("fds", 4), ("threads", 2)):
                if any(s.get(key) is None for s in early + final):
                    fails.append(f"{key} were not measured for every sample")
                    continue
                if max(s[key] for s in final) > max(s[key] for s in early) + allow:
                    fails.append(f"{key} grew: final max {max(s[key] for s in final)} > early max {max(s[key] for s in early)} + {allow}")
    third = [s for s in samples if s["t"] >= D / 3]
    if third and samples[-1]["home_files"] > third[0]["home_files"] + 8:
        fails.append(f"file count grew from {third[0]['home_files']} to {samples[-1]['home_files']}")
    for e in events:
        if e.get("event") == "sshd_outage_attempts":
            if e.get("min_gap_s") is not None and e["min_gap_s"] < 1.0 and e.get("unrequested", 0) > 0:
                fails.append(f"connection attempts {e['min_gap_s']} s apart during an sshd outage")
            if e.get("unrequested", 0) > 12:
                fails.append(f"{e['unrequested']} unrequested attempts in one sshd outage")
    return fails, notes


def analyze(run_dir):
    bad = 0
    for lane in ("S", "L"):
        d = os.path.join(run_dir, lane)
        try:
            samples, events = load(os.path.join(d, "samples.ndjson")), load(os.path.join(d, "events.ndjson"))
            if os.path.isfile(os.path.join(d, "root-samples.ndjson")):
                samples = merge_root(samples, load(os.path.join(d, "root-samples.ndjson")))
            with open(os.path.join(d, "status.json"), encoding="utf-8") as fh:
                status = json.load(fh)
        except OSError:
            print(f"lane {lane}: FAIL no output")
            bad += 1
            continue
        fails, notes = judge(samples, events, status, lane, status.get("tick_s", 60))
        hours = (samples[-1]["t"] / 3600) if samples else 0
        kind = "soak" if hours >= 72 else "REHEARSAL (not an A34 result)"
        print(f"lane {lane}: {'FAIL' if fails else 'pass'} | {kind}, {hours:.2f} h, {len(samples)} samples | totals {json.dumps(status.get('totals'))}")
        for n in notes:
            print(f"  note: {n}")
        for f in fails:
            print(f"  FAIL: {f}")
        bad += bool(fails)
    return 1 if bad else 0


def self_test():
    def series(n, rss, fds=20, threads=4, files=50, tick=60):
        return [{"t": i * tick, "tick": i, "pid": 7, "rss_kib": rss(i), "fds": fds if isinstance(fds, int) else fds(i),
                 "threads": threads, "home_files": files if isinstance(files, int) else files(i), "panic_in_log": False}
                for i in range(n)]
    done = {"state": "DONE", "tick_s": 60}
    cases = [
        ("plateau passes", series(720, lambda i: 40000 + (i % 7) * 30), [], done, None),
        ("leak fails", series(720, lambda i: 40000 + i * 40), [], done, "memory"),
        ("descriptor leak fails", series(720, lambda i: 40000, fds=lambda i: 20 + i // 20), [], done, "fds grew"),
        ("file growth fails", series(720, lambda i: 40000, files=lambda i: 50 + i // 10), [], done, "file count grew"),
        ("tight retry loop fails", series(720, lambda i: 40000),
         [{"event": "sshd_outage_attempts", "unrequested": 40, "min_gap_s": 0.01}], done, "apart during an sshd outage"),
        ("a failed lane fails", series(720, lambda i: 40000), [], {"state": "FAILED", "reason": "x", "tick_s": 60}, "ended FAILED"),
        ("over the absolute bound fails", series(720, lambda i: 200 * 1024), [], done, "above 150 MiB"),
    ]
    bad = 0
    for name, samples, events, status, expect in cases:
        fails, _ = judge(samples, events, status, "S", 60)
        ok = (not fails) if expect is None else any(expect in f for f in fails)
        if not ok:
            bad += 1
            print(f"self-test FAILED: {name}: {fails}")
    gap = series(100, lambda i: 40000)
    for s in gap[50:]:
        s["t"] += 900
    _, notes = judge(gap, [], done, "S", 60)
    if not any("gap of" in n for n in notes):
        bad += 1
        print("self-test FAILED: a gap is not reported")
    print(f"analyze self-test: {len(cases) + 1} cases, {bad} failed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 1 or not os.path.isdir(argv[0]):
        print(__doc__)
        return 2
    return analyze(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
