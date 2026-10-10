"""M00-T05-r4-x2-xrev-T3: the T3 cross-review probes.  The same probes, key sequences and oracle run on every build.

Usage: tests/g02/.venv/bin/python -I probes.py <bins-dir> <out-dir> <build> [<build>...] [--only P01,P05]
  <bins-dir>/<build>/heimdall-proto for every build except base-go-pinned (repository prototypes/go/dist).
Writes <out-dir>/<build>.json.  Exit 0 when every probe ran (pass or fail), 2 on a usage error.
"""
import hashlib
import json
import os
import re
import signal
import sys
sys.dont_write_bytecode = True   # no __pycache__ next to the evidence scripts
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_lib as L  # noqa: E402

HOME = str(Path.home())


def build_info(bins, name):
    lang = "go" if "-go" in name else "rust"
    if name == "base-go-pinned":
        path = L.REPO / "prototypes" / "go" / "dist" / "darwin-arm64" / "heimdall-proto"
    else:
        path = Path(bins) / name / "heimdall-proto"
    cell = name.startswith("T3-")
    return {"name": name, "path": str(path), "lang": lang, "cell": cell,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def mk(b, profile, rows, cols, env=None):
    return L.Run(b["name"], b["path"], b["lang"], profile, rows=rows, cols=cols, env=env,
                 rule="C" if b["cell"] else "K9", help_ok=b["cell"], underline=b["cell"])


def run_seq(b, pid, variant, profile, rows, cols, seq, env=None, extra=None):
    r = mk(b, profile, rows, cols, env)
    res = {"probe": pid, "variant": variant}
    try:
        r.start()
        for item in seq:
            if r.sim.exit or r.s.poll() is not None:
                break
            if isinstance(item, tuple) and item[0] == "resize":
                r.resize(item[1], item[2])
            elif isinstance(item, tuple) and item[0] == "batch":
                r.batch(item[1])
            elif isinstance(item, tuple) and item[0] == "signal":
                r.signal_exit(item[1], item[2], "signal %s" % signal.Signals(item[1]).name)
            elif isinstance(item, tuple) and item[0] == "hangup":
                r.hangup_exit(item[1], "hangup (pty master closed)")
            elif isinstance(item, tuple) and item[0] == "alive":
                r.alive_after(item[1])
            elif isinstance(item, tuple) and item[0] == "raw-resize":     # ioctl only (pyte cannot be 0x0)
                import fcntl, struct, termios
                fcntl.ioctl(r.s.master, termios.TIOCSWINSZ, struct.pack("HHHH", item[1], item[2], 0, 0))
                r.s.signal(signal.SIGWINCH)
                r.alive_after("ioctl resize %dx%d (screen model not resized)" % (item[2], item[1]))
            else:
                r.key(item)
        if extra:
            extra(r, res)
        if r.s.poll() is None and not r.sim.exit:
            res["still_running_at_end"] = True
    except Exception:  # noqa
        res["probe_error"] = traceback.format_exc()[-1500:]
    finally:
        res["leftover_killed"] = r.close()
    res["steps"] = r.steps
    res["ok"] = all(s.get("ok") for s in r.steps) and "probe_error" not in res
    res["failed_steps"] = sum(1 for s in r.steps if not s.get("ok"))
    return res


# ------------------------------------------------------------------ probe definitions
SEQ_HOMELAB = ["down", "down", "/", "東", "bs", "a", "s", "up", "bs", "bs", "L", "A", "B", "enter", "?", "?",
               "/", "bs", "bs", "bs", "e", "x", "bs", "esc", "up", "up", "/", "京", "enter", "down", "?", "esc",
               "/", "esc", "q"]
SEQ_WIDE = ["/", "東", "京", "bs", "bs", "-", "b", "bs", "bs", "a", "down", "down", "bs", "大", "bs", "esc",
            "down", "down", "down", "/", "e", "x", "enter", "up", "up", "?", "?", "/", "bs", "bs", "esc",
            "j", "j", "k", "q"]
SEQ_LONG = ["/", "x", "y", "z", "bs", "bs", "bs", "t", "e", "s", "t", "s", "-", "x", "esc", "/", "i", "n", "t",
            "e", "r", "n", "a", "l", "esc", "/", "東", "京", "bs", "bs", "京", "東", "bs", "bs", "東", "c", "enter",
            "down", "q"]


def P01(b):
    return [run_seq(b, "P01", "homelab %dx%d" % (c, r), "homelab", r, c, SEQ_HOMELAB)
            for r, c in [(24, 80), (8, 50), (8, 49), (6, 30), (5, 20)]]


def P02(b):
    return [run_seq(b, "P02", "wide %dx%d" % (c, r), "wide", r, c, SEQ_WIDE)
            for r, c in [(24, 80), (10, 60), (10, 50), (10, 40), (8, 30), (6, 21), (5, 20)]]


def P03(b):
    return [run_seq(b, "P03", "long %dx%d" % (c, r), "long", r, c, SEQ_LONG)
            for r, c in [(10, 80), (10, 60), (10, 50), (10, 49), (10, 33), (6, 21), (5, 20)]]


def P04(b):
    if not b["cell"]:
        return [{"probe": "P04", "variant": "help behaviour", "skipped": "baseline has no help overlay", "ok": None}]
    seq = ["down", "/", "a", "enter", "?", "j", "k", "q", "/", "enter", "down", "up", "bs", "x", "!",
           ("resize", 10, 40), ("resize", 5, 20), ("resize", 3, 12), ("resize", 24, 80), "esc",
           "?", "?", "/", "?", "bs", "esc", "?", "ctrl-c"]
    return [run_seq(b, "P04", "help behaviour 80x24", "homelab", 24, 80, seq)]


def P05(b):
    seq = ["?", ("resize", 1, 1), ("resize", 5, 2), ("resize", 2, 5), ("raw-resize", 0, 0), ("resize", 5, 20),
           "esc", ("resize", 24, 80), "/", "東", ("resize", 5, 20), ("resize", 1, 1), ("raw-resize", 0, 0),
           ("resize", 24, 80), "esc", "q"]
    return [run_seq(b, "P05", "tiny sizes and resize, homelab from 20x5", "homelab", 5, 20, seq),
            run_seq(b, "P05", "tiny sizes and resize, wide from 20x5", "wide", 5, 20,
                    ["/", "東", "enter", "?"] + seq[1:])]


def P06(b):
    out = []
    cases = [
        ("help open + SIGTERM", ["?", ("signal", signal.SIGTERM, 143)]),
        ("help open + SIGHUP", ["?", ("signal", signal.SIGHUP, 129)]),
        ("help open + SIGINT (kill)", ["?", ("signal", signal.SIGINT, 130)]),
        ("help open + terminal hangup", ["?", ("hangup", 129)]),
        ("help open + Ctrl-C", ["?", "ctrl-c"]),
        ("filter mode + SIGTERM", ["/", "a", ("signal", signal.SIGTERM, 143)]),
        ("help: q ignored, then ? closes, q quits", ["?", "q", "?", "q"]),
        ("help: Esc closes, Down, Enter selects", ["?", "esc", "down", "enter"]),
        ("wide filter + help + SIGTERM at 20x5", ["/", "東", "enter", "?", ("signal", signal.SIGTERM, 143)]),
    ]
    for name, seq in cases:
        rows, cols = (5, 20) if "20x5" in name else (24, 80)
        out.append(run_seq(b, "P06", name, "homelab", rows, cols, seq))
    return out


def P07(b):
    def colour(r, res):
        hits = r.colour_sgr()
        res["colour_sgr"] = hits
        r.steps.append({"step": "no colour SGR in the session (NO_COLOR=1)", "ok": not hits, "hits": hits})
    return [run_seq(b, "P07", "NO_COLOR homelab %dx%d" % (c, r), "homelab", r, c, SEQ_HOMELAB,
                    env={"NO_COLOR": "1"}, extra=colour) for r, c in [(24, 80), (5, 20)]] + \
           [run_seq(b, "P07", "NO_COLOR wide 40x10", "wide", 10, 40, SEQ_WIDE, env={"NO_COLOR": "1"}, extra=colour)]


TERMS = ["xterm-256color", "xterm", "xterm-color", "screen", "screen-256color", "tmux-256color", "linux",
         "vt100", "vt220", "ansi", "rxvt-unicode-256color", "alacritty", "xterm-kitty", "xterm-ghostty", "dumb", None]


def P08(b):
    out = []
    for t in TERMS:
        out.append(run_seq(b, "P08", "TERM=%s" % (t if t is not None else "(unset)"), "homelab", 24, 80,
                           ["/", "a", "enter", "q"], env={"TERM": t}))
    return out


def P09(b):
    s1 = [("batch", ["down", "down", "/", "e", "x", "bs"]), ("batch", ["enter", "?", "j", "j", "q", "/"]), "?",
          ("batch", ["?", "?", "/", "n", "a", "s", "enter"]), ("batch", ["?", "j", "k", "?"]),
          ("batch", ["/", "v", "p", "bs", "bs", "bs"]), "esc", "q"]
    s2 = [("batch", ["down"] * 20), ("batch", ["up"] * 4 + ["/", "1"]), ("batch", ["bs", "2"]), "esc",
          ("batch", ["down"] * 50), ("batch", ["/", "9", "0", "bs", "bs"]), "enter", ("batch", ["k"] * 3),
          ("batch", ["/", "-", "d", "b"]), "enter", "q"]
    return [run_seq(b, "P09", "rapid batches homelab 80x24", "homelab", 24, 80, s1),
            run_seq(b, "P09", "rapid batches large-100 80x8", "large100", 8, 80, s2)]


def P10(b):
    seq = [("batch", ["down"] * 90), "/", "9", "0", "bs", "bs", "esc", ("batch", ["up"] * 40), "/", "5", "bs",
           "-", "d", "b", "enter", ("resize", 5, 80), ("resize", 24, 80), "j", "k", "q"]
    return [run_seq(b, "P10", "large-100 scroll %dx%d" % (c, r), "large100", r, c, seq)
            for r, c in [(24, 80), (8, 80), (5, 20)]]


def P11(b):
    L.STRIP_MN = True
    seq = ["/", "e", "esc", "/", "ς", "esc", "/", "σ", "esc", "/", "i", "esc", "/", "ｆ", "esc", "/", "Ｆ", "Ｕ",
           "esc", "/", "c", "a", "f", "e", "esc", "q"]
    try:
        return [run_seq(b, "P11", "unicode case/combining %dx%d (combining marks ignored)" % (c, r), "uni", r, c, seq)
                for r, c in [(24, 80), (12, 40)]]
    finally:
        L.STRIP_MN = False


def P15(b):
    """Does the combining accent of 'cafe' + U+0301 survive (a) the first frame, (b) a highlight of 'e' that splits
    the cluster, (c) the Esc clear?  Observation per build (pyte attaches a combining mark to the previous cell)."""
    r = mk(b, "uni", 24, 80)
    res = {"probe": "P15", "variant": "combining accent through highlight split (observation)"}
    obs = {}
    try:
        r.s.settle(1.0)
        row0 = lambda: "".join(r.s.screen.buffer[0][x].data for x in range(2, 10))
        obs["first_frame"] = row0()
        for k in ["/", "e"]:
            r.s.send(k)
            r.s.settle(0.4)
        obs["filter_e"] = row0()
        obs["filter_e_underlined_cols"] = L.underlined_cols(r.s, 0)
        r.s.key("esc")
        r.s.settle(0.4)
        obs["after_esc"] = row0()
        r.steps.append({"step": "observation", "ok": True, "obs": obs})
        r.sim.exit = ("rc", 0)
        r.s.send("q")
        r.finish_exit("q")
    except Exception:  # noqa
        res["probe_error"] = traceback.format_exc()[-1500:]
    finally:
        res["leftover_killed"] = r.close()
    res["observation"] = obs
    res["steps"] = r.steps
    res["ok"] = all(s.get("ok") for s in r.steps) and "probe_error" not in res
    res["failed_steps"] = sum(1 for s in r.steps if not s.get("ok"))
    return [res]


def P12(b):
    """zero-width / bidi profile: process state and raw bytes only (pyte cannot draw these)."""
    r = mk(b, "zw", 24, 80)
    res = {"probe": "P12", "variant": "zero-width and bidi aliases 80x24 (process state, raw bytes)"}
    try:
        r.s.settle(1.0)
        for k in ["/", "e", "esc", "/", "\U0001F469", "esc", "/", "a", "b", "esc", "/", "s", "p", "esc",
                  "down", "down", "?", "?"]:
            if k in L.KEYS:
                r.s.key(L.KEYS[k])
            else:
                r.s.send(k)
            r.sim.key(k)
            r.s.settle(0.25 if k != "esc" else 0.3)
            alive = r.s.poll() is None
            r.steps.append({"step": "key %r" % k, "ok": alive, "alive": alive})
            if not alive:
                break
        # last rendering of each tricky alias in the byte stream (escaped), for the record
        raw = bytes(r.s.raw)
        snaps = {}
        for name, pat in [("dev ZWJ", "dev-".encode()), ("rtl RLO", "rtl-".encode()), ("zw ZWSP", b"zw")]:
            i = raw.rfind(pat)
            snaps[name] = raw[max(i - 12, 0):i + 60].decode("utf-8", "backslashreplace").encode(
                "unicode_escape").decode("ascii") if i >= 0 else None
        res["last_bytes"] = snaps
        res["feed_errors"] = r.s.feed_errors[:3]
        r.key("q")
    except Exception:  # noqa
        res["probe_error"] = traceback.format_exc()[-1500:]
    finally:
        res["leftover_killed"] = r.close()
    res["steps"] = r.steps
    res["ok"] = all(s.get("ok") for s in r.steps) and "probe_error" not in res
    res["failed_steps"] = sum(1 for s in r.steps if not s.get("ok"))
    return [res]


def P13(b):
    if not b["cell"]:
        return [{"probe": "P13", "variant": "help residue after resize", "skipped": "baseline has no help overlay",
                 "ok": None}]
    return [run_seq(b, "P13", "help open, resize 30x6, close; reopen, resize 80x24, Esc", "homelab", 24, 80,
                    ["/", "n", "a", "s", "enter", "?", ("resize", 6, 30), "?", "?", ("resize", 24, 80), "esc",
                     "/", "esc", "q"]),
            run_seq(b, "P13", "wide: CJK filter kept, help, resize 20x5, Esc, resize 40x10", "wide", 6, 21,
                    ["/", "東", "enter", "?", ("resize", 5, 20), "esc", ("resize", 10, 40), "?", ("resize", 6, 21),
                     "?", "down", "q"])]


def P14(b):
    """Selection when the selected row disappears and reappears, empty results, Enter/? with nothing shown."""
    seq = ["down", "/", "v", "p", "s", "bs", "bs", "bs", "up", "z", "bs", "n", "a", "s", "bs", "bs", "bs",
           "z", "z", "enter", "enter", "?", "?", "down", "up", "/", "bs", "bs", "enter", "enter"]
    return [run_seq(b, "P14", "disappear/reappear, empty results %dx%d" % (c, r), "homelab", r, c, seq)
            for r, c in [(24, 80), (5, 20)]]


FUZZ_SIZES = [(24, 80), (10, 60), (10, 50), (10, 49), (8, 40), (6, 30), (6, 21), (5, 20)]


def issue_class(i):
    if i.startswith("status"):
        return "status-line"
    if "underline cols" in i:
        return "underline"
    if "not in the visible window" in i or i.startswith("list shows"):
        return "window"
    if "help" in i or "while help" in i:
        return "help"
    return "list-rows"


def P16(b):
    """Seeded random walk (identical keys for every build; the next key depends only on the seed and on the
    simulator's mode, which is the same for every build except that '?' opens help only in the cells)."""
    import random
    out = []
    for profile in ("wide", "homelab"):
        for seed in (1, 2, 3):
            rng = random.Random("%s-%d" % (profile, seed))
            rows, cols = FUZZ_SIZES[seed % len(FUZZ_SIZES)]
            r = mk(b, profile, rows, cols)
            res = {"probe": "P16", "variant": "random walk %s seed %d (120 keys, start %dx%d)" % (profile, seed, cols, rows)}
            try:
                r.start()
                for n in range(120):
                    if r.s.poll() is not None:
                        break
                    x = rng.random()
                    if x < 0.06:
                        rr, cc = FUZZ_SIZES[rng.randrange(len(FUZZ_SIZES))]
                        r.resize(rr, cc)
                        continue
                    if r.sim.help:
                        pool = ["?", "esc", "j", "k", "down", "up", "/", "x"]
                    elif r.sim.filtering:
                        pool = ["a", "e", "-", "b", "東", "京", "大", "s", "x", "bs", "bs", "bs", "up", "down",
                                "enter", "esc", "?"]
                    else:
                        pool = ["up", "down", "j", "k", "/", "/", "/", "?", "esc"]
                    r.key(rng.choice(pool))
                r.sim.exit = ("rc", 130)
                r.s.send(b"\x03")
                r.finish_exit("ctrl-c at end")
            except Exception:  # noqa
                res["probe_error"] = traceback.format_exc()[-1500:]
            finally:
                res["leftover_killed"] = r.close()
            fails = [s for s in r.steps if not s.get("ok")]
            classes = {}
            for s in fails:
                for c in {issue_class(i) for i in (s.get("issues") or ["exit/restore"])}:
                    classes[c] = classes.get(c, 0) + 1
            res["issue_classes"] = classes
            res["steps_total"] = len(r.steps)
            res["steps"] = [s for s in r.steps if not s.get("ok")][:12]
            res["ok"] = not fails and "probe_error" not in res
            res["failed_steps"] = len(fails)
            out.append(res)
    return out


def P17(b):
    """From a fresh start: '/', one filter character, then Backspace; the oracle after each key."""
    out = []
    for profile in ("wide", "homelab"):
        for rows, cols in [(24, 80), (10, 40), (5, 20)]:
            for ch in ["-", "a", "e", "b", "k", "p", "s", "r", ".", "x", "東", "京", "サ", "大", "屋"]:
                res = run_seq(b, "P17", "%s %dx%d '/%s' then Backspace" % (profile, cols, rows, ch), profile, rows,
                              cols, ["/", ch, "bs", "esc"])
                res["steps"] = [st for st in res["steps"] if not st.get("ok")]
                out.append(res)
    return out


PROBES = {"P01": P01, "P02": P02, "P03": P03, "P04": P04, "P05": P05, "P06": P06, "P07": P07, "P08": P08,
          "P09": P09, "P10": P10, "P11": P11, "P12": P12, "P13": P13, "P14": P14, "P15": P15, "P16": P16, "P17": P17}


def redact(obj):
    s = json.dumps(obj, ensure_ascii=False, indent=1)
    s = s.replace(HOME, "<home>")
    s = re.sub(r"(/private)?/tmp/hm-xrevT3-[A-Za-z0-9_]+", "<sandbox>", s)
    assert ("HEIMDALL_" + "CANARY_") not in s   # canary prefix never in a record
    return s


def main():
    args = sys.argv[1:]
    only = None
    if "--only" in args:
        i = args.index("--only")
        only = args[i + 1].split(",")
        del args[i:i + 2]
    if len(args) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    bins, out = args[0], Path(args[1])
    out.mkdir(parents=True, exist_ok=True)
    os.environ.pop("SSH_AUTH_SOCK", None)
    for name in args[2:]:
        b = build_info(bins, name)
        rec = {"build": name, "lang": b["lang"], "cell": b["cell"], "darwin_arm64_sha256": b["sha256"],
               "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "probes": []}
        for pid, fn in PROBES.items():
            if only and pid not in only:
                continue
            t0 = time.monotonic()
            for res in fn(b):
                res["secs"] = round(time.monotonic() - t0, 1)
                rec["probes"].append(res)
        rec["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        suffix = ("-" + "-".join(only)) if only else ""
        (out / ("%s%s.json" % (name, suffix))).write_text(redact(rec), encoding="utf-8")
        npass = sum(1 for p in rec["probes"] if p.get("ok") is True)
        nfail = sum(1 for p in rec["probes"] if p.get("ok") is False)
        print("%s: %d variants pass, %d fail" % (name, npass, nfail), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
