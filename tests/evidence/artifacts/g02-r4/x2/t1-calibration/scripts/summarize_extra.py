"""M00-T05-r4-x2-t1cal: tables for the repeated race runs (P10r/P11r), the escalating-recovery runs
(P1x/P2x) and the S3 resume window (P12-S3) from the jcprobe outputs.
Usage: python3 -I -B summarize_extra.py <out-dir> <extra.md> <extra.json>
"""
import json
import os
import sys

BUILDS = ["plain", "base-go", "base-go-pinned", "T1-go-opus1", "T1-go-opus2", "T1-go-sonnet1",
          "base-rust", "T1-rust-opus1", "T1-rust-opus2", "T1-rust-sonnet1"]


def runs(path):
    if not os.path.exists(path):
        return []
    return json.load(open(path))["runs"]


def main():
    out, md, js = sys.argv[1:4]
    lines, data = [], {}
    # race
    lines.append("### Repeated race runs (P10r, P11r; 10 reps per build and platform, bash)\n")
    lines.append("Cell: runs with at least one re-stop right after `fg` / runs; total re-stops; whether a "
                 "second `fg` recovered every re-stop.\n")
    lines.append("| build | darwin P10r | darwin P11r | linux P10r | linux P11r |")
    lines.append("|---|---|---|---|---|")
    for b in BUILDS:
        cells = []
        for plat in ("darwin", "linux"):
            rr = runs(os.path.join(out, "race-%s-bash" % plat, b + ".json"))
            for sc in ("P10r", "P11r"):
                x = [r for r in rr if r["scenario"] == sc]
                if not x:
                    cells.append("n/a")
                    continue
                hit = [r for r in x if r.get("cmp", {}).get("restops")]
                tot = sum(r.get("cmp", {}).get("restops", 0) for r in x)
                rec = all(r.get("cmp", {}).get("restop_recovered_by_second_fg", True) for r in x)
                err = [r for r in x if "error" in r]
                fin = [r for r in x if sc == "P11r" and r.get("cmp", {}).get("finished") is False]
                c = "%d/%d; %d; %s" % (len(hit), len(x), tot, "yes" if rec else "NO")
                if err:
                    c += "; errors %d" % len(err)
                if fin:
                    c += "; unfinished %d" % len(fin)
                cells.append(c)
                data.setdefault("race", {}).setdefault(b, {})["%s-%s" % (plat, sc)] = {
                    "runs": len(x), "runs_with_restop": len(hit), "restops": tot, "all_recovered_by_second_fg": rec,
                    "errors": len(err)}
        lines.append("| %s | %s |" % (b, " | ".join(cells)))
    # recovery
    lines.append("\n### Escalating recovery (P1x: background job, stdio redirected; P2x: stdio on the terminal; "
                 "third-party SIGTSTP of the child; 2 reps, bash)\n")
    lines.append("Cell: `jobs` state after the stop; what gave the prompt back after `fg` "
                 "(`fg` = the job finished; otherwise the first of ^C, ^Z, ^\\ that did; `none` = nothing did).\n")
    lines.append("| build | darwin P1x | darwin P2x | linux P1x | linux P2x |")
    lines.append("|---|---|---|---|---|")
    for b in BUILDS:
        cells = []
        for plat in ("darwin", "linux"):
            rr = runs(os.path.join(out, "recover-%s-bash" % plat, b + ".json"))
            for sc in ("P1x-TSTP", "P2x-TSTP"):
                x = [r for r in rr if r["scenario"] == sc]
                vals = sorted({"%s -> %s" % (r.get("cmp", {}).get("jobs"), r.get("cmp", {}).get("prompt_back_by") or "none")
                               for r in x})
                cells.append(" / ".join(vals) if vals else "n/a")
                data.setdefault("recovery", {}).setdefault(b, {})["%s-%s" % (plat, sc)] = vals
        lines.append("| %s | %s |" % (b, " | ".join(cells)))
    # P9e repeated fg (follow-up)
    lines.append("\n### P9e follow-up: repeated `fg` (P9e0-fg3: suspend, fg; P9e-bg-fg3: suspend, bg, fg; 2 reps)\n")
    lines.append("Cell: after which `fg` the job-control child answered (0 = not after three) and where the typed "
                 "`xq-ping` lines went (child / shell = ran as a command in the outer shell / nowhere = no answer).\n")
    sets = [p for p in ("p9e-darwin-bash", "p9e-darwin-zsh", "p9e-linux-bash") if os.path.isdir(os.path.join(out, p))]
    lines.append("| build | " + " | ".join("%s %s" % (p[4:], sc) for p in sets for sc in ("P9e0-fg3", "P9e-bg-fg3")) + " |")
    lines.append("|---" * (2 * len(sets) + 1) + "|")
    for b in [x for x in BUILDS if x != "base-go-pinned"]:
        cells = []
        for p in sets:
            rr = runs(os.path.join(out, p, b + ".json"))
            for sc in ("P9e0-fg3", "P9e-bg-fg3"):
                x = [r for r in rr if r["scenario"] == sc]
                vals = sorted({"%s; %s" % (r.get("cmp", {}).get("answered_after_fg_number"),
                                           ",".join(r.get("cmp", {}).get("ping_destinations") or [])) for r in x})
                cells.append(" / ".join(vals) if vals else "n/a")
                data.setdefault("p9e_fg3", {}).setdefault(b, {})["%s-%s" % (p, sc)] = vals
        lines.append("| %s | %s |" % (b, " | ".join(cells)))
    # S3 window
    lines.append("\n### S3 resume window (P12-S3)\n")
    lines.append("Milliseconds, sampled every few microseconds for 1 s after the third party's SIGCONT to the "
                 "launcher, during which the launcher was not stopped while the child still was (per rep). "
                 "Plain exec has no launcher; `jobs` 1 s later is in the matrix.\n")
    plats = [p for p in ("darwin-bash", "linux-bash", "darwin-zsh") if os.path.isdir(os.path.join(out, p))]
    lines.append("| build | " + " | ".join(plats) + " |")
    lines.append("|---" * (len(plats) + 1) + "|")
    for b in BUILDS[1:]:
        cells = []
        for p in plats:
            x = [r for r in runs(os.path.join(out, p, b + ".json")) if r["scenario"] == "P12-S3"]
            w = [r.get("launcher_running_child_stopped_ms") for r in x]
            cells.append(", ".join("%s" % v for v in w))
            data.setdefault("s3_window_ms", {}).setdefault(b, {})[p] = w
        lines.append("| %s | %s |" % (b, " | ".join(cells)))
    open(md, "w").write("\n".join(lines) + "\n")
    json.dump(data, open(js, "w"), indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
