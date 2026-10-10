"""M00-T05-r4-x2-xrev-T3-verify: build the per-(build, case) table across the three emulators.

Usage: python3 -I compare.py <scratch-root> <cross-review-T3-dir> <out-dir>
Reads  <scratch>/tmux/runs/<build>/<case>-<variant>-r<rep>.json   (tmux 3.8, private socket)
       <scratch>/xt/<build>/<case>-<TERM>.json                      (xterm.js headless replay of pty bytes)
       <scratch>/pyte/<case>.txt                                    (cross-review repro_bytes.py on these binaries)
       <cross-review>/raw/repro/<case>-*.txt                        (the cross-review's own pyte runs, R1-R6)
Writes <out>/results.json and <out>/table.md.

Verdict per emulator: 'correct' when the list rows occupy rows 0..n-1 exactly as expected, every row between
is blank, and the last row equals the language's expected status line; otherwise 'CORRUPT' with the rows seen.
Only text is compared (not attributes). A verdict is only given for the screen after the last key.
"""
import glob
import json
import os
import re
import sys

BUILDS = ["base-go-pinned", "base-go", "T3-go-opus1", "T3-go-opus2", "T3-go-sonnet1",
          "base-rust", "T3-rust-opus1", "T3-rust-opus2", "T3-rust-sonnet1"]
REPRO_FILES = {"R1": "R1-homelab-20x5-filter-東京.txt", "R2": "R2-wide-80x24-filter-dash.txt",
               "R3": "R3-wide-40x10-filter-屋-backspace.txt", "R4": "R4-homelab-80x24-reenter-filter-mode.txt",
               "R5": "R5-homelab-40x10-filter-東京.txt", "R6": "R6-homelab-80x24-filter-東京.txt"}


def lang_of(b):
    return "go" if "-go" in b else "rust"


def expected(case, build):
    rows = case.get("expected_baseline_rows") if build.startswith("base-") and case.get("expected_baseline_rows") else case["expected_rows"]
    return list(rows), case["status"][lang_of(build)]


def verdict(lines, nrows, exp_rows, exp_status):
    """lines: the full screen, len == nrows (blank rows as '')."""
    lines = [l.rstrip() for l in lines]
    while len(lines) < nrows:
        lines.append("")
    lines = lines[:nrows]
    got_list = lines[:len(exp_rows)]
    between = lines[len(exp_rows):nrows - 1]
    status = lines[nrows - 1]
    ok = got_list == exp_rows and all(l == "" for l in between) and status == exp_status
    shown = [l for l in lines if l]
    return ("correct" if ok else "CORRUPT"), shown


def parse_pyte_text(path):
    """{build: {'ok': bool, 'rows': {y: text}, 'ul': {y: [...]}, 'bytes': str, 'issues': str}} from repro_bytes output."""
    out, cur = {}, None
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        m = re.match(r"^=== (\S+)\s+last key .* oracle ok=(\w+)", line)
        if m:
            cur = m.group(1)
            out[cur] = {"ok": m.group(2) == "True", "rows": {}, "ul": {}, "bytes": None, "issues": None}
            continue
        if cur is None:
            continue
        m = re.match(r"^ +(\d+) \|(.*)\|(?:  ul=(\[.*\]))?$", line)
        if m:
            out[cur]["rows"][int(m.group(1))] = m.group(2)
            if m.group(3):
                out[cur]["ul"][int(m.group(1))] = m.group(3)
            continue
        if line.startswith("  bytes: "):
            out[cur]["bytes"] = line[len("  bytes: "):]
        elif line.startswith("  issues: "):
            out[cur]["issues"] = line[len("  issues: "):]
    return out


def pyte_verdict(rec, nrows, exp_rows, exp_status):
    if rec is None:
        return "n/a", []
    lines = [""] * nrows
    for y, t in rec["rows"].items():
        if y < nrows:
            lines[y] = t
    return verdict(lines, nrows, exp_rows, exp_status)


def main():
    S, XREV, OUT = sys.argv[1:4]
    spec = json.load(open(os.path.join(S, "scripts", "cases.json"), encoding="utf-8"))
    cases = spec["cases"]
    os.makedirs(OUT, exist_ok=True)
    results = {}
    my_pyte = {cid: parse_pyte_text(os.path.join(S, "pyte", cid + ".txt")) for cid in cases}
    xr_pyte = {cid: parse_pyte_text(os.path.join(XREV, "raw", "repro", f)) for cid, f in REPRO_FILES.items()}
    for build in BUILDS:
        results[build] = {}
        for cid, case in cases.items():
            cols, nrows = map(int, case["size"].split("x"))
            exp_rows, exp_status = expected(case, build)
            r = {"expected_rows": exp_rows, "expected_status": exp_status, "tmux": {}, "xtermjs": {}, "pyte": {}}
            # tmux: variant -> list of (rep, verdict, shown, cursor, bytes_last_key)
            for variant in ("default", "xterm"):
                reps = []
                for f in sorted(glob.glob(os.path.join(S, "tmux", "runs", build, "%s-%s-r*.json" % (cid, variant)))):
                    rec = json.load(open(f, encoding="utf-8"))
                    if rec.get("error") or not rec.get("screens"):
                        reps.append({"rep": f, "verdict": "ERROR", "error": rec.get("error")})
                        continue
                    last = rec["screens"][-1]
                    v, shown = verdict(last["lines"], nrows, exp_rows, exp_status)
                    reps.append({"rep": int(re.search(r"-r(\d+)\.json$", f).group(1)), "verdict": v, "shown": shown,
                                 "cursor": last["cursor"], "pane": rec.get("pane_size"), "program_env": rec.get("program_env"),
                                 "last_key_bytes": rec["chunks"][-1]["esc"] if rec.get("chunks") else None,
                                 "sgr_last": last.get("sgr")})
                r["tmux"][variant] = reps
            # xterm.js: TERM -> verdict
            for term in ("xterm-256color", "tmux-256color"):
                f = os.path.join(S, "xt", build, "%s-%s.json" % (cid, term))
                if not os.path.exists(f):
                    r["xtermjs"][term] = {"verdict": "n/a"}
                    continue
                rec = json.load(open(f, encoding="utf-8"))
                last = rec["snapshots"][-1]
                v, shown = verdict(last["lines"], nrows, exp_rows, exp_status)
                recf = os.path.join(S, "rec", build, "%s-%s.json" % (cid, term))
                pr = json.load(open(recf, encoding="utf-8"))
                r["xtermjs"][term] = {"verdict": v, "shown": shown, "cursor": last["cursor"], "underline": last["underline"],
                                      "cells_nonblank": last["cells"], "last_key_bytes": pr["chunks"][-1]["esc"],
                                      "rc": pr["rc"], "xterm_headless": rec["xterm_headless"]}
            # pyte (this task's run of the cross-review script on these binaries)
            rec = my_pyte[cid].get(build)
            v, shown = pyte_verdict(rec, nrows, exp_rows, exp_status)
            r["pyte"]["this_run"] = {"verdict": v, "shown": shown, "oracle_ok": rec["ok"] if rec else None,
                                     "last_key_bytes": rec["bytes"] if rec else None}
            rec = xr_pyte.get(cid, {}).get(build)
            v, shown = pyte_verdict(rec, nrows, exp_rows, exp_status)
            r["pyte"]["cross_review"] = {"verdict": v, "shown": shown, "oracle_ok": rec["ok"] if rec else None,
                                         "last_key_bytes": rec["bytes"] if rec else None}
            results[build][cid] = r
    with open(os.path.join(OUT, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=1)

    # markdown table
    def cell_tmux(reps):
        if not reps:
            return "n/a"
        vs = [x["verdict"] for x in reps]
        if all(v == vs[0] for v in vs):
            return "%s (%d/%d)" % (vs[0], len(vs), len(vs))
        return "MIXED " + "/".join(vs)

    lines = ["| build | case | tmux TERM=tmux-256color | tmux TERM=xterm-256color | xterm.js TERM=xterm-256color | xterm.js TERM=tmux-256color | pyte (this run) | pyte (cross-review) |",
             "|---|---|---|---|---|---|---|---|"]
    for build in BUILDS:
        for cid in cases:
            r = results[build][cid]
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                build, cid, cell_tmux(r["tmux"].get("default", [])), cell_tmux(r["tmux"].get("xterm", [])),
                r["xtermjs"]["xterm-256color"]["verdict"], r["xtermjs"]["tmux-256color"]["verdict"],
                r["pyte"]["this_run"]["verdict"], r["pyte"]["cross_review"]["verdict"]))
    # screens seen where anything is not correct
    detail = ["", "## Screens where a verdict is not `correct` (rows after the last key)", ""]
    for build in BUILDS:
        for cid in cases:
            r = results[build][cid]
            items = []
            for variant in ("default", "xterm"):
                for x in r["tmux"].get(variant, []):
                    if x["verdict"] != "correct":
                        items.append("tmux %s r%s: %s" % (variant, x["rep"], x.get("shown", x.get("error"))))
            for term in ("xterm-256color", "tmux-256color"):
                x = r["xtermjs"][term]
                if x["verdict"] not in ("correct", "n/a"):
                    items.append("xterm.js %s: %s" % (term, x["shown"]))
            for k in ("this_run", "cross_review"):
                x = r["pyte"][k]
                if x["verdict"] not in ("correct", "n/a"):
                    items.append("pyte %s: %s" % (k, x["shown"]))
            if items:
                detail.append("- **%s / %s** (expected %s + status `%s`)" % (build, cid, r["expected_rows"], r["expected_status"]))
                for it in items:
                    detail.append("  - %s" % it)
    with open(os.path.join(OUT, "table.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines + detail) + "\n")
    print("\n".join(lines))
    print("\n".join(detail))


if __name__ == "__main__":
    main()
