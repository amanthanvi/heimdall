#!/usr/bin/env python3
"""G02 round-4 X2 hidden acceptance tests (implementers never see this directory).

usage: python3 -I -B run.py --task T1|T2|T3|T4 --bin PATH --platform darwin|linux --lang go|rust|control
                      [--only ID,ID*...] [--out RESULT.json] [--keep] [--list] [--expect-sha256 HEX]

--lang names the implementation language of --bin (control: a positive control script).  It cannot
be observed black-box, so the evaluator states it and it is recorded as "lang"; score.py refuses a
record whose lang differs from its own --lang (fix round 2).

Exit status: 0 every selected check passed; 1 at least one check failed or errored; 2 usage or
setup error (wrong platform, binary missing, pyte missing for T3/T4 tty checks, no checks selected,
--expect-sha256 mismatch, or the binary changed during the run: verdict "invalid").

The binary is judged black-box.  Each check prints one line (PASS/FAIL/ERROR id :: first failed
assertions).  --out writes the full per-assertion record (expected vs observed), with sandbox,
binary and home paths replaced by <sandbox>, <bin>, <home>.
"""
import sys
sys.dont_write_bytecode = True   # no __pycache__ (it would embed the home path) even without -B
import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import signal  # noqa: E402
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "common"))
import hm  # noqa: E402

TASKS = {"T1": "t1.jobctl", "T2": "t2.lint", "T3": "t3.tui", "T4": "t4.symlink"}
NEEDS_PYTE = {"T3", "T4"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--task", required=True, choices=sorted(TASKS))
    ap.add_argument("--bin", required=True, help="path to heimdall-proto under test")
    ap.add_argument("--platform", required=True, choices=["darwin", "linux"])
    ap.add_argument("--lang", required=True, choices=["go", "rust", "control"],
                    help="implementation language of --bin (recorded; score.py checks it)")
    ap.add_argument("--only", default="", help="comma-separated check ids (* wildcard)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep", action="store_true", help="keep the sandbox (debugging)")
    ap.add_argument("--list", action="store_true", help="list check ids and exit")
    ap.add_argument("--expect-sha256", default=None,
                    help="refuse to run (exit 2) unless --bin has this sha256; checked again after the run")
    a = ap.parse_args()

    host = "darwin" if sys.platform == "darwin" else ("linux" if sys.platform.startswith("linux") else sys.platform)
    if a.platform != host:
        print("run.py: --platform %s but this host is %s" % (a.platform, host), file=sys.stderr)
        return 2
    sys.path.insert(0, str(HERE))
    __import__(TASKS[a.task])
    if a.list:
        for cid, title, _ in hm.REGISTRY.get(a.task, []):
            print("%s\t%s" % (cid, title))
        return 0
    b = Path(a.bin)
    if not (b.is_file() and os.access(b, os.X_OK)):
        print("run.py: --bin is not an executable file", file=sys.stderr)
        return 2
    bin_sha = hm.H.sha256_hex(b.read_bytes())
    if a.expect_sha256 and bin_sha != a.expect_sha256.lower():
        print("run.py: --bin sha256 %s... does not match --expect-sha256 %s..." % (bin_sha[:16], a.expect_sha256[:16]),
              file=sys.stderr)
        return 2
    os.environ.pop("SSH_AUTH_SOCK", None)
    hm.H.install_alarm_handler()
    hm.H.normalize_signal_dispositions()
    ctx = hm.Ctx(a.bin, a.platform, keep=a.keep)
    if a.task in NEEDS_PYTE:
        ctx.pyte = hm.load_pyte()
        if ctx.pyte is None:
            print("run.py: pyte not importable (use the harness venv: HM_G02_VENV=<repo>/tests/g02/.venv, "
                  "or run inside the Linux runner image)", file=sys.stderr)
            ctx.cleanup()
            return 2
    only = [x for x in a.only.split(",") if x]

    def on_term(signum, _f):
        hm.H.kill_tracked(2.0)
        ctx.cleanup()
        sys.exit(2)

    signal.signal(signal.SIGTERM, on_term)
    t0 = time.time()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0))
    try:
        results = hm.run_task(a.task, ctx, only=only)
    finally:
        hm.H.kill_tracked(2.0)
        ctx.cleanup()
    if not results:
        print("run.py: no checks selected", file=sys.stderr)
        return 2
    summary = {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "error")}
    summary["total"] = len(results)
    verdict = "pass" if summary["pass"] == summary["total"] else "fail"
    after_sha = hm.H.sha256_hex(b.read_bytes()) if b.is_file() else None
    if after_sha != bin_sha:
        # The binary under test changed or vanished during the run (fix round: another task rebuilt
        # dist/ mid-run).  The results are not evidence for either binary.
        print("run.py: --bin changed during the run (sha256 before %s..., after %s); results discarded"
              % (bin_sha[:16], (after_sha or "missing")[:16]), file=sys.stderr)
        verdict = "invalid"
    print("SUMMARY %s %s platform=%s lang=%s %s" % (a.task, verdict.upper(), a.platform, a.lang, json.dumps(summary)))
    if a.out:
        rec = {"task": a.task, "platform": a.platform, "lang": a.lang, "started_at": started,
               "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "binary_sha256": bin_sha, "binary_sha256_after": after_sha,
               "python": sys.version.split()[0], "verdict": verdict, "summary": summary, "checks": results}
        text = json.dumps(rec, indent=1, ensure_ascii=False) + "\n"
        home = os.environ.get("HOME")
        if hm.contains_path(text, home):
            # Last guard: never write a home path into a record, even one the scrub missed.
            rec["redactions"] = _redact(rec, home)
            text = json.dumps(rec, indent=1, ensure_ascii=False) + "\n"
        if hm.contains_path(text, home):
            print("run.py: record still holds a home path after redaction; not written", file=sys.stderr)
            return 2
        Path(a.out).write_text(text, encoding="utf-8")
    if verdict == "invalid":
        return 2
    return 0 if verdict == "pass" else 1


def _redact(node, home, n=None):
    """Replace every string that still holds a home path with a fixed marker; returns the count."""
    n = n if n is not None else [0]
    items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else []
    for k, v in items:
        if isinstance(v, str):
            if hm.contains_path(v, home):
                node[k] = "<redacted: held a home path>"
                n[0] += 1
        elif isinstance(v, (dict, list)):
            _redact(v, home, n)
    return n[0]


if __name__ == "__main__":
    sys.exit(main())
