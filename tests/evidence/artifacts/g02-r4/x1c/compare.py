#!/usr/bin/env python3
"""X1c: compare the post-fix linux-x64 harness records with earlier G02 harness results.

usage: python3 -I compare.py <repo-root> <new-go-record.json> <new-rust-record.json>

Reference sources (all inside the repository):
  r3-linux-x64    tests/evidence/g02-<c>-conformance-linux-x64.json   (X1, round-3 artifacts, native WSL2)
  r3-linux-arm64  tests/evidence/g02-<c>-conformance-linux.json       (round 3, pinned container)
  r3-darwin-arm64 tests/evidence/g02-<c>-conformance.json             (round 3)
  x1b-*           tests/evidence/artifacts/g02-r4/x1b/...             (post-fix artifacts; Go: per-check summaries
                                                                       only, Rust: full records)
Output: per-source summary, per-check outcome differences, assertion-level differences against r3-linux-x64,
non-gating failed assertions, structural (non-timing) observation differences, and timing observations.
"""
import json
import re
import statistics
import sys
from pathlib import Path

TIMING_KEY = re.compile(r"(ms|_s|seconds|latency|wall|rss|mib|samples|elapsed|duration|after|pid|_at$|loadavg)", re.I)
VOLATILE_STR = [
    (re.compile(r"/tmp/hmg02-[A-Za-z0-9_]+"), "/tmp/hmg02-*"),
    (re.compile(r"\bpid[ =:]+\d+", re.I), "pid=*"),
]


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def outcomes_full(rec):
    return {c["id"]: c["outcome"] for c in rec["observed_result"]["checks"]}


def norm_str(s):
    for rx, rep in VOLATILE_STR:
        s = rx.sub(rep, s)
    return s


def mask(v, key=""):
    timing = bool(TIMING_KEY.search(key))
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, float):
        return "<num>"
    if isinstance(v, int):
        return "<num>" if timing else v
    if isinstance(v, str):
        return norm_str(v)
    if isinstance(v, list):
        if timing and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v):
            return "<num-list>"
        return [mask(x, key) for x in v]
    if isinstance(v, dict):
        return {k: mask(x, k) for k, x in v.items()}
    return v


def leaves(v, path=""):
    if isinstance(v, dict):
        if not v:
            yield path, {}
        for k, x in v.items():
            yield from leaves(x, f"{path}.{k}" if path else k)
    elif isinstance(v, list) and v and any(isinstance(x, (dict, list)) for x in v):
        for i, x in enumerate(v):
            yield from leaves(x, f"{path}[{i}]")
    else:
        yield path, v


def short(v, n=160):
    s = json.dumps(v, ensure_ascii=False, sort_keys=True)
    return s if len(s) <= n else s[: n - 3] + "..."


def struct_diff(a, b):
    la = dict(leaves(mask(a)))
    lb = dict(leaves(mask(b)))
    out = []
    for k in sorted(set(la) | set(lb)):
        if la.get(k, "<absent>") != lb.get(k, "<absent>"):
            out.append((k, la.get(k, "<absent>"), lb.get(k, "<absent>")))
    return out


def failed_assertions(check):
    res = []
    for a in check.get("assertions", []) + [x for x in check.get("failed_assertions", []) if isinstance(x, dict)]:
        if not a.get("ok", True):
            res.append((bool(a.get("gating")), norm_str(a.get("desc", ""))))
    return sorted(set(res))


def p(*a):
    print(*a)


def timing_row(label, rec):
    o = rec["observed_result"]["observations"]
    l100 = o.get("large100_keystroke_to_update_ms", {}) or {}
    rz = o.get("resize_relayout_ms") or []
    env = rec.get("environment") or {}
    return (f"  {label:16s} duration_s={rec['observed_result']['summary'].get('duration_s')} "
            f"first_frame_ms={o.get('first_frame_latency_ms')} k17_filter_p95_ms={l100.get('filter_p95')} "
            f"sigint_exit_ms={o.get('agent_sigint_exit_latency_ms')} "
            f"resize_ms(median/max)={statistics.median(rz) if rz else None}/{max(rz) if rz else None} "
            f"loadavg_start={env.get('loadavg_start')} loadavg_end={env.get('loadavg_end')}")


def main():
    repo = Path(sys.argv[1])
    new = {"go": load(sys.argv[2]), "rust": load(sys.argv[3])}
    ev = repo / "tests/evidence"
    x1b = ev / "artifacts/g02-r4/x1b"
    for c in ("go", "rust"):
        n = new[c]
        full = {
            "r3-linux-x64": load(ev / f"g02-{c}-conformance-linux-x64.json"),
            "r3-linux-arm64": load(ev / f"g02-{c}-conformance-linux.json"),
            "r3-darwin-arm64": load(ev / f"g02-{c}-conformance.json"),
        }
        summaries = {}
        if c == "go":
            for tag, f in (("x1b-fix", x1b / "go/harness/harness-summary.json"),
                           ("x1b-review", x1b / "review-go/harness/harness-summary.json")):
                for plat, run in load(f)["runs"].items():
                    summaries[f"{tag}-{plat}"] = run
        else:
            for tag, d in (("x1b-fix", x1b / "rust/harness"), ("x1b-review", x1b / "review-rust/harness")):
                for plat in ("darwin-arm64", "linux-arm64"):
                    full[f"{tag}-{plat}"] = load(d / f"g02-rust-conformance-{plat}.json")
        p(f"== {c}")
        p("  sources (status / verdict / summary / harness / artifact digest):")
        rows = [("NEW linux-x64", n["status"], n["observed_result"]["verdict"], n["observed_result"]["summary"],
                 n["environment"].get("harness_version"), n["artifact_digest"])]
        for k, r in full.items():
            rows.append((k, r["status"], r["observed_result"]["verdict"], r["observed_result"]["summary"],
                         r["environment"].get("harness_version"), r["artifact_digest"]))
        for k, r in summaries.items():
            rows.append((k, r["status"], r["verdict"], r["summary"], r.get("harness_version", "2.4.2 (not in summary)"),
                         r["artifact_digest"]))
        for label, st, vd, sm, hv, dg in rows:
            p(f"    {label:24s} {st}/{vd} {json.dumps({x: sm[x] for x in ('pass', 'fail', 'error', 'skipped', 'total')})} "
              f"duration_s={sm.get('duration_s')} harness={hv} digest={dg[:19]}")
        allout = {"NEW": outcomes_full(n)}
        allout.update({k: outcomes_full(r) for k, r in full.items()})
        allout.update({k: dict(r["checks"]) for k, r in summaries.items()})
        ids = sorted(set().union(*[set(v) for v in allout.values()]))
        diff = [i for i in ids if len({allout[s].get(i, "<absent>") for s in allout}) > 1]
        p(f"  check ids (union over {len(allout)} sources): {len(ids)}; checks with differing outcome or presence: {len(diff)}")
        for i in diff:
            p(f"    {i}: " + ", ".join(f"{s}={allout[s].get(i, '<absent>')}" for s in allout))

        # assertion level, against every full record
        nchecks = {ch["id"]: ch for ch in n["observed_result"]["checks"]}
        for k, r in full.items():
            rchecks = {ch["id"]: ch for ch in r["observed_result"]["checks"]}
            cnt_diff, fail_diff = [], []
            for i in sorted(set(nchecks) & set(rchecks)):
                a, b = nchecks[i], rchecks[i]
                if len(a.get("assertions", [])) != len(b.get("assertions", [])):
                    cnt_diff.append((i, len(a.get("assertions", [])), len(b.get("assertions", []))))
                if failed_assertions(a) != failed_assertions(b):
                    fail_diff.append((i, failed_assertions(a), failed_assertions(b)))
            p(f"  assertions NEW vs {k}: checks with a different assertion count: {len(cnt_diff)}; "
              f"with a different set of failed assertions: {len(fail_diff)}")
            for i, x, y in cnt_diff:
                p(f"    count {i}: NEW={x} {k}={y}")
            for i, x, y in fail_diff:
                p(f"    failed {i}:\n      NEW={short(x, 400)}\n      {k}={short(y, 400)}")
        # captures (heimdall-proto invocations recorded by the harness), against the round-3 linux-x64 record:
        # exit code, timed_out, leftover_processes per (check, label, occurrence); stdout/stderr digests counted
        # (they also differ when the output contains a per-run temporary path or timing)
        r3 = {ch["id"]: ch for ch in full["r3-linux-x64"]["observed_result"]["checks"]}
        tot = same_exit = same_out = same_err = 0
        exit_diff, out_diff = [], []
        for i in sorted(set(nchecks) & set(r3)):
            la, lb = nchecks[i].get("captures", []), r3[i].get("captures", [])
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
        p(f"  captures NEW vs r3-linux-x64: {tot} paired; same (exit_code, timed_out, leftover_processes): {same_exit}; "
          f"same stdout sha256: {same_out}; same stderr sha256: {same_err}")
        for d in exit_diff:
            p(f"    exit/timeout/leftover differs: {d}")
        for s, i, lab, bx, by, ex, ey in out_diff:
            p(f"    {s} digest differs: {i} [{lab}] bytes NEW={bx} r3={by}"
              + (f"\n      NEW stderr={short(ex)}\n      r3  stderr={short(ey)}" if s == "stderr" else ""))
        nf = [(i, failed_assertions(ch)) for i, ch in nchecks.items() if failed_assertions(ch)]
        p(f"  NEW: checks with failed (necessarily non-gating, since all checks pass) assertions: {len(nf)}")
        for i, fa in nf:
            p(f"    {i}: {short(fa, 400)}")

        # structural observation differences
        nobs = n["observed_result"]["observations"]
        for k in ["r3-linux-x64", "r3-linux-arm64"] + (["x1b-fix-linux-arm64"] if c == "rust" else []):
            robs = full[k]["observed_result"]["observations"]
            keys = sorted(set(nobs) | set(robs))
            only = [x for x in keys if (x in nobs) != (x in robs)]
            d = struct_diff(nobs, robs)
            p(f"  observations NEW vs {k}: keys {len(nobs)}/{len(robs)}, only in one: {only}; "
              f"structural (non-timing) leaf differences: {len(d)}, grouped by observation sub-key:")
            groups = {}
            for path, a, b in d:
                g = ".".join(re.split(r"[.\[]", path)[:2])
                groups.setdefault(g, []).append((path, a, b))
            for g, items in groups.items():
                top, _, sub = g.partition(".")
                na = (nobs.get(top) or {}).get(sub) if isinstance(nobs.get(top), dict) else None
                ra = (robs.get(top) or {}).get(sub) if isinstance(robs.get(top), dict) else None
                nr = [f"{lab} not_run: {x['not_run']}" for lab, x in (("NEW", na), (k, ra))
                      if isinstance(x, dict) and x.get("not_run")]
                p(f"    {g}: {len(items)} leaf difference(s)" + (f" ({'; '.join(nr)})" if nr else ""))
                if not nr:
                    for path, a, b in items[:8]:
                        p(f"      {path}\n        NEW={short(a)}\n        {k}={short(b)}")
                    if len(items) > 8:
                        p(f"      ... {len(items) - 8} more")
        p("  timing observations (wall-clock, not gating except via each check's own bound):")
        p(timing_row("NEW linux-x64", n))
        for k, r in full.items():
            p(timing_row(k, r))
        p("")


if __name__ == "__main__":
    main()
