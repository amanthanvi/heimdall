"""M00-T05-r4-x2-t1cal: build the behaviour matrix from jcprobe.py outputs.

Usage: python3 -I -B analyze.py <out-dir> <matrix.json> <matrix.md>
<out-dir>/<platform>-<shell>/<label>.json are jcprobe.py results. For every platform/shell,
scenario and build, the per-rep `cmp` dicts are compared with the plain-exec control of the same
platform/shell (all reps) and with the same language's baseline. Cell text: `=` when every rep
equals plain exec on every compared key; otherwise the differing keys with this build's values
(`a or b` when reps differ). `~` marks a build whose reps disagree (flaky); `!` marks a control whose
reps disagree.
"""
import json
import os
import re
import sys

BUILDS = ["plain", "base-go", "base-go-pinned", "T1-go-opus1", "T1-go-opus2", "T1-go-sonnet1",
          "base-rust", "T1-rust-opus1", "T1-rust-opus2", "T1-rust-sonnet1"]
BASE = {"go": "base-go", "rust": "base-rust"}


def lang(b):
    return "go" if "go" in b else ("rust" if "rust" in b else None)


def norm(v):
    return json.dumps(v, sort_keys=True)


def load(outdir):
    data = {}
    for pd in sorted(os.listdir(outdir)):
        p = os.path.join(outdir, pd)
        if not os.path.isdir(p) or pd not in ("darwin-bash", "linux-bash", "darwin-zsh"):
            continue
        for b in BUILDS:
            f = os.path.join(p, b + ".json")
            if not os.path.exists(f):
                continue
            d = json.load(open(f))
            for r in d["runs"]:
                key = (pd, r["scenario"])
                data.setdefault(key, {}).setdefault(b, []).append(r)
    return data


def cmpd(r):
    if "error" in r and "cmp" not in r:
        return {"error": r["error"]}
    return r.get("cmp", {})


def diff_keys(runs, ref_runs):
    """Keys where any rep of `runs` differs from every value the control showed."""
    out = {}
    refvals = {}
    for rr in ref_runs:
        for k, v in cmpd(rr).items():
            refvals.setdefault(k, set()).add(norm(v))
    keys = set(refvals)
    for r in runs:
        keys |= set(cmpd(r))
    for k in sorted(keys):
        vals = [norm(cmpd(r).get(k)) for r in runs]
        if any(v not in refvals.get(k, set()) for v in vals):
            out[k] = vals
    return out


ABBR = {"job_stopped_consistent": "consistent", "child_completed": "completed", "child_state": "child",
        "recovery": "rec", "rc_at_prompt": "$?", "inner_rc_after_recovery": "inner_rc",
        "child_after_kill_cont_jobspec": "child_after_kill-CONT_%1", "prompt_returned": "prompt"}


def short(v):
    v = json.loads(v)
    if isinstance(v, str):
        return v.replace("|", "/")
    return json.dumps(v).replace("|", "/").replace('"', "")


def cell_text(dk, flaky):
    if not dk:
        return "=" + (" ~" if flaky else "")
    parts = []
    for k, vals in dk.items():
        uniq = []
        for v in vals:
            if v not in uniq:
                uniq.append(v)
        parts.append("%s=%s" % (ABBR.get(k, k), " or ".join(short(v) for v in uniq)))
    return "; ".join(parts) + (" ~" if flaky else "")


def main():
    outdir, jout, mout = sys.argv[1:4]
    data = load(outdir)
    matrix = {}
    lines = []
    plats = sorted({k[0] for k in data})
    for pd in plats:
        scen = [k[1] for k in data if k[0] == pd]
        order = sorted(set(scen), key=lambda s: (int(re.match(r"P(\d+)", s).group(1)), s))
        lines.append("\n### %s\n" % pd)
        lines.append("| scenario | " + " | ".join(BUILDS) + " |")
        lines.append("|---" * (len(BUILDS) + 1) + "|")
        for s in order:
            row = data[(pd, s)]
            ref = row.get("plain", [])
            ref_flaky = len({norm(cmpd(r)) for r in ref}) > 1
            cells = []
            for b in BUILDS:
                runs = row.get(b, [])
                if not runs:
                    cells.append("n/a")
                    continue
                flaky = len({norm(cmpd(r)) for r in runs}) > 1
                if b == "plain":
                    sig = cmpd(runs[0])
                    txt = "; ".join("%s=%s" % (ABBR.get(k, k), short(norm(v))) for k, v in sig.items())
                    cells.append(txt + (" !" if ref_flaky else ""))
                    matrix.setdefault(pd, {}).setdefault(s, {})[b] = {
                        "reps": [cmpd(r) for r in runs], "flaky": flaky,
                        "durations_s": [r.get("duration_s") for r in runs],
                        "leftovers": [r.get("cleanup", {}).get("left_after_cleanup") for r in runs]}
                    continue
                dk = diff_keys(runs, ref)
                base = BASE.get(lang(b))
                bdk = diff_keys(row.get(base, []), ref) if base and base in row else None
                same_as_base = (norm([cmpd(r) for r in runs][:1]) == norm([cmpd(r) for r in row.get(base, [])][:1])
                                if base and base in row else None)
                matrix.setdefault(pd, {}).setdefault(s, {})[b] = {
                    "reps": [cmpd(r) for r in runs], "flaky": flaky, "diverges_from_plain": dk,
                    "baseline_diverges": bool(bdk) if bdk is not None else None,
                    "baseline_divergent_keys": sorted(bdk) if bdk else [],
                    "first_rep_equals_baseline_first_rep": same_as_base,
                    "durations_s": [r.get("duration_s") for r in runs],
                    "leftovers": [r.get("cleanup", {}).get("left_after_cleanup") for r in runs],
                    "errors": [r.get("error") for r in runs if r.get("error")]}
                cells.append(cell_text(dk, flaky))
            lines.append("| %s | %s |" % (s, " | ".join(c.replace("\n", " ") for c in cells)))
    json.dump(matrix, open(jout, "w"), indent=1, sort_keys=True)
    open(mout, "w").write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
