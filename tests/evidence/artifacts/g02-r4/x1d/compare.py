#!/usr/bin/env python3
"""X1d: compare each host's harness record with the X1c record of the same artifact (and the two hosts with each
other). Reuses the masking and assertion helpers of ../x1c/compare.py (imported, not copied).

usage: python3 -I compare.py <repo-root> <x1d-dir>

<x1d-dir>/<label>/g02-<c>-conformance-linux-x64-x1d-<label>.json are the redacted host records;
X1c's are tests/evidence/g02-<c>-conformance-linux-x64-x1b.json. Output per candidate and host: sources, check
outcome differences, assertion count and failed-assertion differences, paired heimdall-proto captures (exit code,
timeout and leftover state; stdout/stderr digest differences with stderr excerpts), structural (non-timing)
observation differences, limitation lines present in only one record, and timing observations.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

HOSTS = ("ubuntu2404-kvm", "debian13-x64")


def load_x1c_helpers(repo):
    sys.dont_write_bytecode = True   # no __pycache__ next to X1c's script
    spec = importlib.util.spec_from_file_location(
        "x1c_compare", repo / "tests/evidence/artifacts/g02-r4/x1c/compare.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def norm_lim(s):
    s = re.sub(r"\[[0-9., ]+\] on \d+ CPUs", "[<loadavg>] on <n> CPUs", s)
    s = re.sub(r"in \d+ trials \(deliveries per trial \[[0-9, ]+\]\)", "in <n> trials (deliveries per trial [...])", s)
    return s


def harness_lims(rec):
    """The limitation lines the harness wrote: everything before the first line added afterwards by X1c/X1d."""
    lims = rec["limitations"]
    idx = next((i for i, x in enumerate(lims) if x.startswith("Added by X1")), len(lims))
    return lims[:idx]


def main():
    repo, xd = Path(sys.argv[1]), Path(sys.argv[2])
    X = load_x1c_helpers(repo)
    p = X.p
    for c in ("go", "rust"):
        ref = X.load(repo / f"tests/evidence/g02-{c}-conformance-linux-x64-x1b.json")
        recs = {h: X.load(xd / h / f"g02-{c}-conformance-linux-x64-x1d-{h}.json") for h in HOSTS}
        p(f"== {c}")
        p("  sources (status / verdict / summary / harness / artifact digest):")
        for label, r in [("X1c wsl2", ref)] + [(h, recs[h]) for h in HOSTS]:
            sm = r["observed_result"]["summary"]
            p(f"    {label:16s} {r['status']}/{r['observed_result']['verdict']} "
              f"{json.dumps({x: sm[x] for x in ('pass', 'fail', 'error', 'skipped', 'total')})} "
              f"duration_s={sm.get('duration_s')} harness={r['environment'].get('harness_version')} "
              f"python={r['environment'].get('python')} digest={r['artifact_digest'][:19]}")
        pairs = [(h, recs[h], "X1c", ref) for h in HOSTS] + [(HOSTS[1], recs[HOSTS[1]], HOSTS[0], recs[HOSTS[0]])]
        for na, n, ka, k in pairs:
            p(f"  --- {na} vs {ka}")
            on, ok = X.outcomes_full(n), X.outcomes_full(k)
            ids = sorted(set(on) | set(ok))
            diff = [i for i in ids if on.get(i, "<absent>") != ok.get(i, "<absent>")]
            p(f"  check ids (union): {len(ids)}; differing outcome or presence: {len(diff)}")
            for i in diff:
                p(f"    {i}: {na}={on.get(i, '<absent>')} {ka}={ok.get(i, '<absent>')}")
            nchecks = {ch["id"]: ch for ch in n["observed_result"]["checks"]}
            rchecks = {ch["id"]: ch for ch in k["observed_result"]["checks"]}
            cnt_diff, fail_diff = [], []
            for i in sorted(set(nchecks) & set(rchecks)):
                a, b = nchecks[i], rchecks[i]
                if len(a.get("assertions", [])) != len(b.get("assertions", [])):
                    cnt_diff.append((i, len(a.get("assertions", [])), len(b.get("assertions", []))))
                if X.failed_assertions(a) != X.failed_assertions(b):
                    fail_diff.append((i, X.failed_assertions(a), X.failed_assertions(b)))
            p(f"  assertions: checks with a different assertion count: {len(cnt_diff)}; "
              f"with a different set of failed assertions: {len(fail_diff)}")
            for i, x, y in cnt_diff:
                p(f"    count {i}: {na}={x} {ka}={y}")
            for i, x, y in fail_diff:
                p(f"    failed {i}:\n      {na}={X.short(x, 600)}\n      {ka}={X.short(y, 600)}")
            tot = same_exit = same_out = same_err = 0
            exit_diff, out_diff = [], []
            for i in sorted(set(nchecks) & set(rchecks)):
                la, lb = nchecks[i].get("captures", []), rchecks[i].get("captures", [])
                if [x["label"] for x in la] != [x["label"] for x in lb]:
                    exit_diff.append((i, "label list differs", len(la), len(lb)))
                    continue
                for x, y in zip(la, lb):
                    tot += 1
                    kx = (x["exit_code"], x["timed_out"], x["leftover_processes"])
                    ky = (y["exit_code"], y["timed_out"], y["leftover_processes"])
                    same_exit += kx == ky
                    same_out += x["stdout_sha256"] == y["stdout_sha256"]
                    same_err += x["stderr_sha256"] == y["stderr_sha256"]
                    if kx != ky:
                        exit_diff.append((i, x["label"], kx, ky))
                    for s in ("stdout", "stderr"):
                        if x[s + "_sha256"] != y[s + "_sha256"]:
                            out_diff.append((s, i, x["label"], x[s + "_bytes"], y[s + "_bytes"],
                                             x[s + "_excerpt"] if s == "stderr" else None,
                                             y[s + "_excerpt"] if s == "stderr" else None))
            p(f"  captures: {tot} paired; same (exit_code, timed_out, leftover_processes): {same_exit}; "
              f"same stdout sha256: {same_out}; same stderr sha256: {same_err}")
            for d in exit_diff:
                p(f"    exit/timeout/leftover differs: {d}")
            for s, i, lab, bx, by, ex, ey in out_diff:
                p(f"    {s} digest differs: {i} [{lab}] bytes {na}={bx} {ka}={by}"
                  + (f"\n      {na} stderr={X.short(ex)}\n      {ka} stderr={X.short(ey)}" if s == "stderr" else ""))
            nobs, robs = n["observed_result"]["observations"], k["observed_result"]["observations"]
            keys = sorted(set(nobs) | set(robs))
            only = [x for x in keys if (x in nobs) != (x in robs)]
            d = X.struct_diff(nobs, robs)
            p(f"  observations: keys {len(nobs)}/{len(robs)}, only in one: {only}; structural (non-timing) leaf "
              f"differences: {len(d)}, grouped by observation sub-key:")
            groups = {}
            for path, a, b in d:
                g = ".".join(re.split(r"[.\[]", path)[:2])
                groups.setdefault(g, []).append((path, a, b))
            for g, items in groups.items():
                p(f"    {g}: {len(items)} leaf difference(s)")
                for path, a, b in items[:6]:
                    p(f"      {path}\n        {na}={X.short(a)}\n        {ka}={X.short(b)}")
                if len(items) > 6:
                    p(f"      ... {len(items) - 6} more")
            ln = {norm_lim(x) for x in harness_lims(n)}
            lk = {norm_lim(x) for x in harness_lims(k)}
            p(f"  harness limitation lines only in {na}: {len(ln - lk)}; only in {ka}: {len(lk - ln)} "
              "(load averages and probe trial counts masked; lines added after the run by X1c/X1d ignored)")
            for x in sorted(ln - lk):
                p(f"    + {X.short(x, 300)}")
            for x in sorted(lk - ln):
                p(f"    - {X.short(x, 300)}")
        p("  timing observations (wall-clock, not gating except via each check's own bound):")
        p(X.timing_row("X1c wsl2", ref))
        for h in HOSTS:
            p(X.timing_row(h, recs[h]))
        p("")


if __name__ == "__main__":
    main()
