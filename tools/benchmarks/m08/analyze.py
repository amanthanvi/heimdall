#!/usr/bin/env python3
"""Judge benchmark and soak runs against ADR-0014 section 6 (m08-plan U5).

Usage: python3 -I tools/benchmarks/m08/analyze.py <run directory>      (holds S/ and L/)
       python3 -I tools/benchmarks/m08/analyze.py --benchmark <run directory>
           [--prepare-stage <staged archive directory>]
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
  4  files: the account's file count at the end <= the count at D/3 + 8; and, by kind, the
     database, its write-ahead log and other files must have stopped growing by the final
     quarter (its maximum within 5 % and 64 KiB of the third quarter's); logs <= 17 MiB
  5  retries: no two connection attempts during an sshd outage closer than 1 s, and no
     unrequested attempts beyond 12 per outage
  1  duration and gaps: every gap between samples above 3 ticks is listed
  8  no panic line; both lanes ended DONE
Lane L restarts its runtime, so its memory series is checked per process lifetime for the
maximum only.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import statistics
import sys
import tempfile

MIB = 1024.0
REPO = Path(__file__).resolve().parents[3]

LATENCY_BUDGETS = {
    "inspect_warm": {"max_p95_ms": 100, "min_samples": 200},
    "ensure_warm": {"max_p95_ms": 250, "min_samples": 200},
    "tui_first_useful_frame": {"max_p95_ms": 750, "min_samples": 50},
    "key_to_frame": {"max_p95_ms": 100, "min_samples": 200, "slow_provider": True},
}
BENCH_BUDGETS = {
    "destinations": 100, **LATENCY_BUDGETS, "max_errors_per_latency_metric": 0,
    "idle_cpu": {"less_than_percent_of_one_core": 0.5, "min_windows": 3,
                 "min_window_seconds": 300, "min_settle_seconds": 600},
    "idle_memory": {"max_mib": 150},
    "idle_polling": {"max_unrequested_attempts_per_provider": 0, "providers": ["sshd", "agent_proxy"]},
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def prepare_benchmark(out, stage):
    record = read_json(stage / "BUILD-RECORD.json")
    if (record.get("schema") != "heimdall-build-record/1" or record.get("profile") != "release"
            or record.get("target") not in ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
            or not re.fullmatch("[0-9a-f]{40}", str(record.get("commit")))):
        raise ValueError("expected a Linux release build record")
    with (stage / "heimdall").open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    outputs = record.get("outputs", [])
    if not any(item.get("path") == "heimdall" and item.get("sha256") == digest for item in outputs):
        raise ValueError("staged executable digest differs from its build record")
    write_json(out / "build.json", {
        **{key: record[key] for key in ("commit", "target", "features", "tree_clean", "toolchain")},
        "binary_sha256": digest,
    })


def nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def judge_benchmark(metrics):
    destinations = metrics.get("destinations")
    checks = {"destinations": "unmeasured" if destinations is None else
              "pass" if destinations == BENCH_BUDGETS["destinations"] else "fail"}
    for name, budget in LATENCY_BUDGETS.items():
        row = metrics.get(name, {})
        if not row or (budget.get("slow_provider") and row.get("slow_provider") is not True):
            checks[name] = "unmeasured"
            continue
        p50, p95 = row.get("p50_ms"), row.get("p95_ms")
        samples, errors = row.get("samples"), row.get("errors")
        ok = (nonnegative(p50) and nonnegative(p95) and p50 <= p95 <= budget["max_p95_ms"] and type(samples) is int
              and samples >= budget["min_samples"] and type(errors) is int and errors == 0)
        checks[name] = "pass" if ok else "fail"

    idle = metrics.get("idle", {})
    windows = idle.get("windows", [])
    method = BENCH_BUDGETS["idle_cpu"]
    settle = idle.get("settle_s")
    enough = (len(windows) >= method["min_windows"] and nonnegative(settle)
              and settle >= method["min_settle_seconds"]
              and all(nonnegative(w.get("seconds")) and w["seconds"] >= method["min_window_seconds"]
                      for w in windows))
    for name, field, bound, inclusive in (
            ("idle_cpu", "cpu_percent_of_one_core", method["less_than_percent_of_one_core"], False),
            ("idle_memory", "rss_mib", BENCH_BUDGETS["idle_memory"]["max_mib"], True)):
        values = [w.get(field) for w in windows]
        if not enough or not all(nonnegative(v) for v in values):
            checks[name] = "unmeasured"
        else:
            checks[name] = "pass" if all(v < bound or (inclusive and v == bound) for v in values) else "fail"
    polls = idle.get("unrequested_polls", {})
    counts = [polls.get(provider) for provider in BENCH_BUDGETS["idle_polling"]["providers"]]
    if not enough or not all(type(count) is int and count >= 0 for count in counts):
        checks["idle_polling"] = "unmeasured"
    else:
        checks["idle_polling"] = "pass" if not any(counts) else "fail"
    return checks


def benchmark_evidence(out):
    build = read_json(out / "build.json")
    host = read_json(out / "host.json")
    container_end = read_json(out / "host-end.json")
    run_path, bench_path = out / "run.json", out / "bench" / "bench.json"
    run = read_json(run_path) if run_path.is_file() else {}
    metrics = read_json(bench_path) if bench_path.is_file() else {}
    checks = judge_benchmark(metrics)
    checked_binary = run.get("binary_sha256") == build["binary_sha256"]
    passed = checked_binary and container_end["container_exit"] == 0 and all(v == "pass" for v in checks.values())
    limitations = ["Container benchmark only; the native platform rows and soak require separate evidence."]
    if checks["key_to_frame"] == "unmeasured":
        limitations.append("Key latency under real slow provider work was not measured.")
    if checks["idle_polling"] == "unmeasured":
        limitations.append("The fixture sshd and agent proxy did not both report idle polling counts.")
    if not checked_binary:
        limitations.append("The container did not report the recorded executable digest.")
    evidence = {
        "case_id": "A34-benchmark",
        "status": "verified" if passed else "implemented_unverified",
        "requirement_ids": ["R-QU-03"],
        "build_commit": build["commit"],
        "artifact_digest": run.get("binary_sha256"),
        "environment": {"target": build["target"], "host": host,
                        "container": {key: run.get(key) for key in ("arch", "kernel", "cpus_seen", "mem_total_kib")}},
        "provider_versions": [],
        "started_at": metrics.get("started_at") or host["host_started_at"],
        "commands_or_harness": "tools/benchmarks/m08/run-bench.sh and analyze.py --benchmark",
        "observed_result": {
            "result": "pass" if passed else "fail", "container_exit": container_end["container_exit"],
            "budgets": BENCH_BUDGETS, "measurements": metrics, "checks": checks, "build": build,
        },
        "evidence_paths": [path for path in ("host.json", "host-end.json", "build.json",
                                            "run.json", "bench/bench.json", "host-load.ndjson")
                           if (out / path).is_file()],
        "limitations": limitations,
    }
    write_json(out / "evidence.json", evidence)
    return evidence


def benchmark_main(argv):
    parser = argparse.ArgumentParser(description="Prepare or analyze a benchmark evidence record")
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--prepare-stage", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.prepare_stage:
            prepare_benchmark(args.run_dir, args.prepare_stage)
            return 0
        evidence = benchmark_evidence(args.run_dir)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"benchmark analysis: could not read or write evidence ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(f"benchmark analysis: {evidence['observed_result']['result']} (evidence.json)")
    return 0 if evidence["observed_result"]["result"] == "pass" else 1


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
    # Item 4, by kind of file. A ceiling is a size that stops growing: the final quarter's
    # maximum is at most 5 % (and 64 KiB) above the third quarter's maximum.
    kinds = sorted({k for s in samples for k in (s.get("bytes") or {})})
    for k in kinds:
        series = [(s["t"], s["bytes"][k]) for s in samples if s.get("bytes")]
        q3 = [v for t, v in series if D / 2 <= t < 3 * D / 4]
        q4 = [v for t, v in series if t >= 3 * D / 4]
        if not q3 or not q4:
            continue
        first, last, peak = series[0][1], series[-1][1], max(v for _, v in series)
        rate = slope_per_hour(series) / 1024.0
        plateau = max(q4) <= max(q3) * 1.05 + 65536
        notes.append(f"{k}: {first} -> {last} bytes, peak {peak}, slope {rate:.1f} KiB/h, "
                     f"{'ceiling reached' if plateau else 'STILL GROWING in the final quarter'}")
        if k in ("db", "wal", "other") and not plateau:
            fails.append(f"{k} is still growing in the final quarter ({max(q3)} -> {max(q4)} bytes)")
        if k == "log" and peak > 17 * 1024 * 1024:
            fails.append(f"logs peaked at {peak} bytes, above two 8 MiB generations")
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


def analyze(run_dir, lanes="SL"):
    bad = 0
    for lane in lanes:
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


def benchmark_self_test():
    """Exercise the normal evidence writer with recorded inputs and synthetic measurements."""
    schema = read_json(REPO / "tests/evidence/record.schema.json")
    validate = runpy.run_path(str(REPO / "tests/g02/minischema.py"))["validate"]
    metrics = {"destinations": 100, "started_at": "2026-11-26T00:00:00Z"}
    for name, budget in LATENCY_BUDGETS.items():
        metrics[name] = {"p50_ms": budget["max_p95_ms"] / 2, "p95_ms": budget["max_p95_ms"],
                         "samples": budget["min_samples"], "errors": 0}
    metrics["key_to_frame"]["slow_provider"] = True
    metrics["idle"] = {"settle_s": 600, "windows": [
        {"seconds": 300, "cpu_percent_of_one_core": 0.49, "rss_mib": 150} for _ in range(3)
    ], "unrequested_polls": {"sshd": 0, "agent_proxy": 0}}
    stage_record = {"schema": "heimdall-build-record/1", "profile": "release",
                    "target": "aarch64-unknown-linux-gnu", "commit": "a" * 40,
                    "features": "--no-default-features", "tree_clean": True, "toolchain": {}}
    binary = b"synthetic benchmark artifact bytes"
    digest = hashlib.sha256(binary).hexdigest()
    stage_record["outputs"] = [{"path": "heimdall", "sha256": digest}]
    bad = 0
    with tempfile.TemporaryDirectory(prefix="hm-benchmark-evidence-") as tmp:
        out = Path(tmp)
        (out / "bench").mkdir()
        (out / "heimdall").write_bytes(binary)
        write_json(out / "BUILD-RECORD.json", stage_record)
        prepare_benchmark(out, out)
        write_json(out / "host.json", {"host_started_at": metrics["started_at"], "host_os": "fixture"})
        write_json(out / "host-end.json", {"container_exit": 0})
        write_json(out / "run.json", {"binary_sha256": digest, "arch": "aarch64"})
        bench_path = out / "bench/bench.json"
        for name, expected, checks in (
                ("budget equality allowed", "pass", {}),
                ("strict CPU bound and latency miss", "fail", {"idle_cpu": "fail", "ensure_warm": "fail"}),
                ("fast-work and missing polls", "fail", {"key_to_frame": "unmeasured", "idle_polling": "unmeasured"}),
                ("digest mismatch", "fail", {}),
                ("container failure without metrics", "fail", {"inspect_warm": "unmeasured"})):
            write_json(bench_path, metrics)
            if name == "strict CPU bound and latency miss":
                metrics["idle"]["windows"][0]["cpu_percent_of_one_core"] = 0.5
                metrics["ensure_warm"]["p95_ms"] = 250.01
                write_json(bench_path, metrics)
                metrics["idle"]["windows"][0]["cpu_percent_of_one_core"] = 0.49
                metrics["ensure_warm"]["p95_ms"] = 250
            if name == "fast-work and missing polls":
                metrics["key_to_frame"]["slow_provider"] = False
                metrics["idle"].pop("unrequested_polls")
                write_json(bench_path, metrics)
                metrics["key_to_frame"]["slow_provider"] = True
                metrics["idle"]["unrequested_polls"] = {"sshd": 0, "agent_proxy": 0}
            if name == "digest mismatch":
                write_json(out / "run.json", {"binary_sha256": "b" * 64, "arch": "aarch64"})
            if name == "container failure without metrics":
                write_json(out / "run.json", {"binary_sha256": digest, "arch": "aarch64"})
                write_json(out / "host-end.json", {"container_exit": 1})
                bench_path.unlink()
            benchmark_evidence(out)
            record = read_json(out / "evidence.json")
            result = record["observed_result"]
            if (validate(schema, record) or record["build_commit"] != stage_record["commit"]
                    or record["environment"]["target"] != stage_record["target"]
                    or result["budgets"] != BENCH_BUDGETS or result["result"] != expected
                    or any(result["checks"][row] != value for row, value in checks.items())):
                bad += 1
                print(f"self-test FAILED: benchmark {name}")
    return 5, bad


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
    grow = series(720, lambda i: 40000)
    for i, x in enumerate(grow):
        x["bytes"] = {"db": 100000 + i * 2000, "wal": 4000000 if i > 100 else i * 40000, "log": 50000 + i * 100}
    fails, notes = judge(grow, [], done, "S", 60)
    if not any("db is still growing" in f for f in fails) or any("wal is still growing" in f for f in fails):
        bad += 1
        print(f"self-test FAILED: per-kind growth: {fails}")
    gap = series(100, lambda i: 40000)
    for s in gap[50:]:
        s["t"] += 900
    _, notes = judge(gap, [], done, "S", 60)
    if not any("gap of" in n for n in notes):
        bad += 1
        print("self-test FAILED: a gap is not reported")
    bench_cases, bench_bad = benchmark_self_test()
    bad += bench_bad
    print(f"analyze self-test: {len(cases) + 2 + bench_cases} cases, {bad} failed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--benchmark"]:
        return benchmark_main(argv[1:])
    lanes = "SL"
    if len(argv) == 3 and argv[1] == "--lanes" and argv[2] in ("SL", "S", "L"):
        lanes, argv = argv[2], argv[:1]
    if len(argv) != 1 or not os.path.isdir(argv[0]):
        print(__doc__)
        return 2
    return analyze(argv[0], lanes)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
