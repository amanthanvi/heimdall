#!/usr/bin/env python3
"""parity-r3c: build the RESULTS.md tables from the raw probe outputs.
usage: summarize.py RAWDIR   (RAWDIR/{darwin,linux}/...)  -> markdown on stdout.
Only reads recorded JSON; 'matches control' is computed from the fields named in each table note."""
import json
import os
import re
import sys

RAW = sys.argv[1]
PLATS = [p for p in ("darwin", "linux") if os.path.isdir(os.path.join(RAW, p))]
VIA = ("plain", "go", "rust")
LBL = {"plain": "control", "go": "go", "rust": "rust"}


def load(p):
    with open(p) as f:
        return json.load(f)


def ps(x):
    """'gone(ppid=None)' -> 'gone (reaped)', 'Z(ppid=N)' -> 'Z (unreaped zombie)'."""
    x = re.sub(r"gone\(ppid=None\)", "gone (reaped)", x)
    return re.sub(r"Z\(ppid=\d+\)", "Z (unreaped zombie)", x)


def yn(b):
    return "yes" if b else "no"


out = []
w = out.append

# ---------------- probe 1a
w("### Probe 1a: non-interactive parent, third-party stop then SIGCONT of the child PID\n")
w("`extstop_plus.py` (same procedure as review3c `extstop.py`, plus completion/reaping fields). "
  "\"as launched\" = the probe's process group as the tool/container starts it, which is an orphaned "
  "process group on both platforms (the kernel discards SIGTSTP to members of such a group, see the control). "
  "\"non-orphaned\" = same probe under `nonorphan.py`. Matches control = same launcher result (exit 7 within 6 s) "
  "and the child ran to `exit 7`. The last column is the unchanged `extstop.py` run (as launched).\n")
w("| platform | group | signal | via | states 0.5 s after stop (child/launcher) | launcher result | child completed / reaped | matches control | unchanged extstop.py |")
w("|---|---|---|---|---|---|---|---|---|")
for p in PLATS:
    orig = {}
    for c in ("go", "rust"):
        f = os.path.join(RAW, p, "extstop-orig-%s.json" % c)
        if os.path.exists(f):
            for r in load(f)["runs"]:
                orig[(c if r["via"] == "hp" else "plain:" + c, r["signal"])] = r
    for grp, fn in (("as launched", "extstop-plus.json"), ("non-orphaned", "extstop-plus-nonorphan.json")):
        f = os.path.join(RAW, p, fn)
        if not os.path.exists(f):
            continue
        runs = load(f)["runs"]
        ctl = {r["signal"]: r for r in runs if r["via"] == "plain"}
        for sig in ("SIGSTOP", "SIGTSTP"):
            for v in VIA:
                r = next(x for x in runs if x["via"] == v and x["signal"] == sig)
                res = r["result"]
                if res == "hung":
                    res = "**hung** (child %s, launcher %s); after manual SIGCONT to launcher: %s" % (
                        r["states_when_hung"]["child"], r["states_when_hung"]["launcher"], r["after_manual_cont_of_launcher"])
                elif r.get("result_after_s") is not None:
                    res += " (%.2f s)" % r["result_after_s"]
                fin = r["child_after_launcher_end_3s"][-1]
                comp = "%s / %s" % (yn(r["child_completed"]), "yes" if fin.startswith("gone") else fin)
                c = ctl[sig]
                match = (r["result"] == c["result"] and r["child_completed"] == c["child_completed"])
                o = ""
                if grp == "as launched":
                    key = (v, sig) if v != "plain" else ("plain:go", sig)
                    if key in orig:
                        o = orig[key]["result"]
                        if o == "hung":
                            o = "hung; manual CONT: " + orig[key]["after_manual_cont_of_launcher"]
                st = r["states_after_stop"]
                w("| %s | %s | %s | %s | %s/%s | %s | %s | %s | %s |" % (
                    p, grp, sig, LBL[v], st["child"], st["launcher"] or "-", res, comp,
                    "-" if v == "plain" else yn(match), o))
w("")

# ---------------- probe 1b
w("### Probe 1b: interactive shell, job in the foreground, third-party stop then SIGCONT of the child PID\n")
w("`extstop_pty.py` v2. Child `sh -c 'echo $$ >pf; sleep 1; echo x >pf.done; exit 7'`. After SIGCONT the probe waits 6 s, "
  "then runs `echo RC=$?; jobs`; if the job is still listed stopped it types `fg`. Matches control = same stop notice, child "
  "completed, and the job ended without user action (no stopped job left).\n")
w("| platform | shell | signal | via | after stop: child/launcher, shell notice | 6 s after SIGCONT: child, launcher | child completed | shell shows (`$?`, `jobs`) | user `fg` | matches control |")
w("|---|---|---|---|---|---|---|---|---|---|")
for p in PLATS:
    for sh in ("bash", "zsh"):
        f = os.path.join(RAW, p, "pty", "%s-extstop-pty.json" % sh)
        if not os.path.exists(f):
            continue
        runs = load(f)["runs"]
        for sig in ("SIGSTOP", "SIGTSTP"):
            ctl = next(x for x in runs if x["via"] == "plain" and x["signal"] == sig)
            for v in VIA:
                r = next(x for x in runs if x["via"] == v and x["signal"] == sig)
                if "exception" in r:
                    w("| %s | %s | %s | %s | exception %s | | | | | |" % (p, sh, sig, LBL[v], r["exception"]))
                    continue
                a = r["after_stop"]
                b = r["after_6s"]
                jt = r["jobs_text"].replace("|", "/")
                jt = (jt[:60] + "...") if len(jt) > 60 else jt
                shows = "$?=%s; jobs: %s" % (r["rc_after"], jt or "(none)")
                fg = ("rc %s, child %s, launcher %s" % (r["user_fg"]["rc"], r["user_fg"]["child"].split("(")[0],
                                                       r["user_fg"]["launcher"])) if "user_fg" in r else "-"
                ended = not r["jobs_says_stopped"] and not r["jobs_says_running"]
                cended = not ctl["jobs_says_stopped"] and not ctl["jobs_says_running"]
                match = (a["shell_stop_notice"] == ctl["after_stop"]["shell_stop_notice"]
                         and b["child_completed"] == ctl["after_6s"]["child_completed"] and ended == cended)
                w("| %s | %s | %s | %s | %s/%s, %s | %s, %s | %s | %s | %s | %s |" % (
                    p, sh, sig, LBL[v], a["child"], a["launcher"] or "-",
                    "stop notice" if a["shell_stop_notice"] else "no stop notice", ps(b["child"]), b["launcher"] or "-",
                    yn(b["child_completed"]), shows, fg, "-" if v == "plain" else yn(match)))
w("")

# ---------------- probe 2
w("### Probe 2: child self-stop reported to the shell, then SIGCONT to the launcher PID only\n")
w("`contlauncher.py` (clean form of probe.py `explicit` last step; control: SIGCONT to the job's only process, the child). "
  "\"K6e breach\" = `jobs` says running while the child is T. Matches control = same `jobs` verdict 0.6 s and 2 s after the "
  "SIGCONT and the same child behaviour (resumed or not). The last column is the unchanged probe.py `explicit` run, "
  "whose `jobs` fields are unreliable (harness defect H2) and whose earlier steps contaminate this step for Go (H3).\n")
w("| platform | shell | via | after self-stop: notice, child/launcher | after SIGCONT: child/launcher | child resumed (printed BACK) | `jobs` at 0.6 s / 2 s | K6e breach | launcher CPU 2 s | recovery (CONT child, fg) | matches control | probe.py explicit (unchanged) states |")
w("|---|---|---|---|---|---|---|---|---|---|---|---|")


def verdict(j):
    return "running" if j["running"] else ("stopped" if j["stopped"] else "none")


for p in PLATS:
    for sh in ("bash", "zsh"):
        f = os.path.join(RAW, p, "cont", "%s-contlauncher.json" % sh)
        if not os.path.exists(f):
            continue
        runs = load(f)["runs"]
        ctl = next(x for x in runs if x["via"] == "plain")
        for v in VIA:
            r = next(x for x in runs if x["via"] == v)
            if "exception" in r:
                w("| %s | %s | %s | exception %s |||||||||" % (p, sh, LBL[v], r["exception"]))
                continue
            pr = ""
            if v != "plain":
                pf = os.path.join(RAW, p, "probe-%s" % v, "%s-results.json" % sh)
                if os.path.exists(pf):
                    e = load(pf).get("explicit-hp", {}).get("cont_to_launcher")
                    if e:
                        pr = "child %s, launcher %s" % tuple(e["states"])
            ss, sc = r["states_stopped"], r["states_after_cont"]
            match = (verdict(r["jobs"]) == verdict(ctl["jobs"]) and verdict(r["jobs_after_2s"]) == verdict(ctl["jobs_after_2s"])
                     and r["after_2s"]["child_printed_BACK"] == ctl["after_2s"]["child_printed_BACK"])
            cpu = r["after_2s"]["launcher_cpu"]
            w("| %s | %s | %s | %s, %s/%s | %s/%s | %s | %s / %s | %s | %s | %s | %s | %s |" % (
                p, sh, LBL[v], "notice" if r["stop_notice"] else "NO notice", ss["child"], ss["launcher"] or "-",
                sc["child"], sc["launcher"] or "-", yn(r["after_2s"]["child_printed_BACK"]),
                verdict(r["jobs"]), verdict(r["jobs_after_2s"]),
                "**yes**" if r["shell_believes_running_while_child_stopped"] else "no",
                "-" if v == "plain" else "%s -> %s" % tuple(cpu),
                "ok, rc %s" % r["rc"] if r["child_reads_after_recovery"] else "FAILED (rc %s)" % r["rc"],
                "-" if v == "plain" else yn(match), pr))
w("")

# ---------------- probe 3
w("### Probe 3: nested job-control shell as the child (`run -- bash -i`, `suspend`, outer `fg`)\n")
w("`nested.py` (extended form of probe.py `nested_shell`). \"answer after fg\": `echo ALIVE-$W-42` typed after `fg` is "
  "answered by the nested shell, the outer shell, or nobody. Matches control = stop notice, outer shell survives, nested "
  "shell answers after `fg`. The last column is the unchanged probe.py `nested_shell` run.\n")
w("| platform | outer shell | via | after `suspend`: notice, outer prompt | nested / launcher state | outer shell | after `fg`: nested / launcher, answer | diagnostic: SIGCONT nested PID | matches control | probe.py nested_shell (unchanged) |")
w("|---|---|---|---|---|---|---|---|---|---|")
for p in PLATS:
    for sh in ("bash", "zsh"):
        f = os.path.join(RAW, p, "nested", "%s-nested.json" % sh)
        if not os.path.exists(f):
            continue
        for r in load(f)["runs"]:
            v = r["via"]
            if "exception" in r:
                w("| %s | %s | %s | exception %s |||||||" % (p, sh, LBL[v], r["exception"]))
                continue
            a = r["after_suspend"]
            outer = "alive" if a["outer_alive"] else "**exited (%s)**, pty EOF=%s" % (a["outer_exit"], a["pty_eof"])
            if "after_fg" in r:
                fg = "%s / %s, %s" % (r["after_fg"]["nested"]["state"],
                                      (r["after_fg"]["launcher"] or {}).get("state", "-"), r["after_fg_answer"])
            else:
                fg = "not reached"
            mc = ("%s / %s, %s" % (r["after_manual_cont_of_nested"]["nested"]["state"],
                                   (r["after_manual_cont_of_nested"]["launcher"] or {}).get("state", "-"),
                                   r.get("after_manual_cont_answer", "-"))) if "after_manual_cont_of_nested" in r else "-"
            match = r["stop_notice"] and a["outer_alive"] and r.get("after_fg_answer") == "nested answered"
            pr = ""
            pf = os.path.join(RAW, p, "probe-%s" % ("go" if v == "plain" else v), "%s-results.json" % sh)
            if os.path.exists(pf):
                e = load(pf).get("nested_shell-%s" % ("plain" if v == "plain" else "hp"), {})
                if "exception" in e:
                    pr = "exception %s" % e["exception"]
                elif e:
                    pr = "notice %s, after fg %s, answers %s" % (yn(e.get("stop_notice")), e.get("states_after_fg"),
                                                                yn(e.get("nested_responds_after_fg")))
            w("| %s | %s | %s | %s, %s | %s / %s | %s | %s | %s | %s | %s |" % (
                p, sh, LBL[v], "notice" if r["stop_notice"] else "NO notice", yn(r["outer_prompt"]),
                a["nested"]["state"], (a["launcher"] or {}).get("state", "-"), outer, fg, mc,
                "-" if v == "plain" else yn(match), pr))
w("")

# ---------------- probe 4
w("### Probe 4: child stopped by SIGSTOP in exclusive mode (Go review3c `selfstop_detail.py`, unchanged)\n")
w("Interactive shell, foreground job, child `child3c.py read SIGSTOP`; trigger `read` = the child stops itself "
  "(`~z`), `ext` = this probe sends SIGSTOP to the exact child PID. States sampled every 0.25 s for 3 s (shown: distinct "
  "values). Matches control = shell reports the stop and the child is T (a different stop signal in `$?` is noted). `$?` 145/146 = SIGSTOP/SIGTSTP on darwin, 147/148 on linux. \"not written yet\": the meta file is written when the run ends, after the sampling window.\n")
w("| platform | shell | trigger | via | stop reported | `$?` | child/launcher over 3 s | child log after start | meta file | matches control |")
w("|---|---|---|---|---|---|---|---|---|---|")
for p in PLATS:
    for sh in ("bash", "zsh"):
        for trig in ("read", "ext"):
            for v in VIA:
                f = os.path.join(RAW, p, "detail", "%s-%s-%s.json" % ("control" if v == "plain" else v, sh, trig))
                if not os.path.exists(f):
                    continue
                try:
                    d = json.loads(open(f).read().splitlines()[0])
                except Exception as e:  # noqa
                    w("| %s | %s | %s | %s | unparsable output (%s) ||||||" % (p, sh, trig, LBL[v], e))
                    continue
                seq = []
                for s in d["states"]:
                    x = "%s/%s" % (s["child"], s["hp"] or "-")
                    if not seq or seq[-1] != x:
                        seq.append(x)
                log = [l.split(" ")[0] + (" " + l.split(" ")[1] if l.startswith("SIG ") else "") for l in d["child_log"][1:]]
                m = d["meta"]
                meta = ("%s exit_code=%s signal=%s" % (m["code"], m["data"]["exit_code"], m["data"]["signal"])) if m else "not written yet"
                rc = d["rc_line"].split("=")[1] if d["rc_line"] else None
                ctlf = os.path.join(RAW, p, "detail", "control-%s-%s.json" % (sh, trig))
                crc = json.loads(open(ctlf).read().splitlines()[0])["rc_line"].split("=")[1]
                match = d["stop_reported"] and bool(seq) and seq[0].startswith("T")
                if match and rc != crc:
                    match = "yes (`$?` %s vs control %s)" % (rc, crc)
                w("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                    p, sh, trig, LBL[v], yn(d["stop_reported"]), rc, " -> ".join(seq), ", ".join(log) or "-",
                    "-" if v == "plain" else meta, "-" if v == "plain" else (match if isinstance(match, str) else yn(match))))
w("")
print("\n".join(out))


# ---------------- repeats of probes 2 and 3 (appended section)
def rep_dirs(p):
    ds = [("main", os.path.join(RAW, p))]
    for i in (2, 3):
        d = os.path.join(RAW, "%s-rep%d" % (p, i))
        if os.path.isdir(d):
            ds.append(("rep%d" % i, d))
    return ds


rep = []
r_ = rep.append
r_("### Repeat stability of probes 2 and 3 (main run + repeats)\n")
r_("Each cell lists main / rep2 / rep3. Probe 2: `jobs` verdict 2 s after SIGCONT to the launcher, child resumed (y/n), "
   "recovery ok (y/n). Probe 3: outer shell alive after `suspend` (y/n), answer after `fg` (nested/outer/none/-).\n")
r_("| platform | shell | via | probe 2 | probe 3 |")
r_("|---|---|---|---|---|")
for p in PLATS:
    for sh in ("bash", "zsh"):
        for v in VIA:
            c2, c3 = [], []
            for _, d in rep_dirs(p):
                f2 = os.path.join(d, "cont", "%s-contlauncher.json" % sh)
                f3 = os.path.join(d, "nested", "%s-nested.json" % sh)
                if os.path.exists(f2):
                    r = next(x for x in load(f2)["runs"] if x["via"] == v)
                    c2.append("exc" if "exception" in r else "%s,%s,%s" % (
                        verdict(r["jobs_after_2s"]), "y" if r["after_2s"]["child_printed_BACK"] else "n",
                        "y" if r["child_reads_after_recovery"] else "n"))
                if os.path.exists(f3):
                    r = next(x for x in load(f3)["runs"] if x["via"] == v)
                    ans = {"nested answered": "nested", "outer shell answered": "outer", "no answer": "none"}.get(
                        r.get("after_fg_answer"), "-")
                    c3.append("exc" if "exception" in r else "%s,%s" % ("y" if r["after_suspend"]["outer_alive"] else "n", ans))
            r_("| %s | %s | %s | %s | %s |" % (p, sh, LBL[v], " / ".join(c2), " / ".join(c3)))
print("\n".join(rep))
