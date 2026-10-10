#!/usr/bin/env python3
"""Aggregate probe.py records (raw/*/*.json) into a markdown table and a JSON summary.
Usage: aggregate.py <raw-root> <out.md> <out.json>"""
import glob, json, os, sys, collections

BUILDS = ["exec", "base-go", "base-rust", "T1-go-opus1", "T1-go-opus2", "T1-go-sonnet1",
          "T1-rust-opus1", "T1-rust-opus2", "T1-rust-sonnet1"]


def jobs_word(txt):
    """The job state word from a `jobs -l` output (bash: Stopped/Running/Suspended: N;
    zsh: suspended/running/stopped), or 'none' when no job line is present."""
    if txt is None:
        return "timeout"
    for l in txt.replace("\x1b[?2004h", "").replace("\x1b[?2004l", "").splitlines()[1:]:
        s = l.strip()
        if s.startswith("["):
            low = s.lower()
            for w in ("suspended", "stopped", "running", "done"):
                if w in low:
                    return w
            return "other"
    return "none"


def st(p):
    # First letter of the state only: S/R sleeping or running, T stopped, Z zombie.
    return "-" if p is None else p["state"][:1]


def main():
    root, out_md, out_json = sys.argv[1:4]
    recs = []
    for f in sorted(glob.glob(os.path.join(root, "*", "*.json"))):
        recs.extend(json.load(open(f)))
    # key: (platform, shell, build, signal, mode)
    groups = collections.defaultdict(list)
    for r in recs:
        groups[(r["platform"], r["shell"], r["build"], r["signal"], r["mode"])].append(r)
    summary = []
    rows = []
    for (plat, shell, build, sig, mode), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], BUILDS.index(kv[0][2]) if kv[0][2] in BUILDS else 99, kv[0][3], kv[0][4])):
        worked = [r.get("worked") or ("ERR:" + str(r.get("error"))) for r in rs]
        jobs = [jobs_word(r.get("jobs_after_signal")) for r in rs]
        lstate = [st((r.get("after_jobs") or {}).get("launcher")) for r in rs]
        pstate = [st((r.get("after_jobs") or {}).get("program")) for r in rs]
        rc = []
        for r in rs:
            steps = r.get("steps") or []
            done = [s for s in steps if s.get("shell_done")]
            rc.append(done[0].get("rc") if done else "-")
        left_end = [bool(r.get("leftover_at_end")) for r in rs]
        left_clean = [bool(r.get("leftover_after_cleanup")) for r in rs]
        pg_same = []
        for r in rs:
            a = r.get("after_jobs") or {}
            l, p = a.get("launcher"), a.get("program")
            pg_same.append(None if not (l and p) else l["pgid"] == p["pgid"])
        summary.append({"platform": plat, "shell": shell, "build": build, "signal": sig, "mode": mode,
                        "reps": len(rs), "worked": worked, "jobs_after_signal": jobs,
                        "launcher_state": lstate, "program_state": pstate, "rc_at_recovery": rc,
                        "child_in_launcher_group": pg_same,
                        "leftover_at_end": left_end, "leftover_after_cleanup": left_clean})
        def u(xs):
            xs = [str(x) for x in xs]
            return xs[0] if len(set(xs)) == 1 else "/".join(xs)
        rows.append(f"| {plat} | {shell} | {build} | {sig} | {mode} | {len(rs)} | {u(jobs)} | L={u(lstate)} P={u(pstate)} | {u(worked)} | {u(rc)} | {u(['yes' if x else 'no' for x in left_end])} |")
    hdr = ("| platform | shell | build | signal | mode | reps | `jobs -l` after signal | states after signal | recovery that worked | `$?` | job procs left when prompt returned |\n"
           "|---|---|---|---|---|---|---|---|---|---|---|")
    with open(out_md, "w") as fh:
        fh.write(hdr + "\n" + "\n".join(rows) + "\n")
    with open(out_json, "w") as fh:
        json.dump(summary, fh, indent=1)
    print(f"{len(recs)} records, {len(rows)} cells")


if __name__ == "__main__":
    main()
