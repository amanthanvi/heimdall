#!/usr/bin/env python3
"""M00-T02-fix3: do the new selftest cases fail when the code they guard is broken?

Usage (repository root): python3 -I -B mutation_check.py <scratch_dir>
For each mutation, copy docs/sources/tools/fetch_pins.py and docs/sources/pins.json into <scratch_dir>/<name>/
docs/sources/..., apply one exact string replacement to the copy, run its `selftest`, and report the exit code
and the first FAIL lines. The unmutated copy must pass (exit 0); every mutant must fail (exit 1).
Exit 0 = baseline passes and every mutant is caught; 1 otherwise. Nothing in the repository is modified.
"""
import os
import shutil
import subprocess
import sys

scr = sys.argv[1]
SRC = open("docs/sources/tools/fetch_pins.py", encoding="utf-8").read()

MUTANTS = [
    ("n10 substring match instead of word boundaries",
     '    return bool(f) and (" " + f + " ") in (" " + copy_loose + " ")', '    return f in copy_loose'),
    ("n3 GONE class removed",
     'if sx == 200 and "error" not in x and sy in GONE_STATUSES and "error" not in y:', 'if False:'),
    ("n3 GONE not part of exit 2",
     'if counts.get(CONTENT) or counts.get(MISSING) or counts.get(GONE):', 'if counts.get(CONTENT) or counts.get(MISSING):'),
    ("n2 off-pin ignored by the exit code",
     '    if off_pin:\n        return EXIT_OFF_PIN\n', ''),
    ("n2 off-pin IDENTICAL lines hidden without --all",
     'return [ln for cls, off, ln in lines if show_all or cls != IDENTICAL or off]',
     'return [ln for cls, off, ln in lines if show_all or cls != IDENTICAL]'),
    ("n2 off-pin shown for a GONE source",
     'if i in prim and y is not None and cls not in (FETCH_FAILED, GONE):', 'if i in prim and y is not None and cls != FETCH_FAILED:'),
    ("n4 no second pass for a head without </head>", '        if head_unclosed:', '        if False:'),
    ("n4 implied head end applied to every document (changes closed-head output)",
     '        text, head_unclosed = _html_text(text, False)', '        text, head_unclosed = _html_text(text, True)'),
    ("n4 body does not end the head", 'tag not in HEAD_TAGS:', 'tag not in HEAD_TAGS | {"body"}:'),
    ("n5 drifted with no quoted fragment counts as quotes intact",
     'and (not r.get("fragments_total") or r.get("fragments_found") != r.get("fragments_total")))',
     'and r.get("fragments_found") != r.get("fragments_total"))'),
    ("n3 upstream: a gone file is not exit 2", 'return r.get("result") == "gone" or (', 'return False or ('),
    ("n9 blob mismatch shares the input-error code", 'EXIT_BLOB_MISMATCH = EXIT_CONTENT', 'EXIT_BLOB_MISMATCH = EXIT_INPUT'),
    ("n9 failed fetch is exit 1 again", 'return (EXIT_FETCH_FAILED if bad else 0), bad, blob_bad', 'return (1 if bad else 0), bad, blob_bad'),
    ("n9 failed GitHub fetch counted as blob mismatch",
     'blob_bad = [x["id"] for x in results if ok(x) and x.get("git_blob_matches_pin") is False]',
     'blob_bad = [x["id"] for x in results if x.get("git_blob_matches_pin") is False]'),
    ("n8 body read ignores the deadline", '        if time.monotonic() >= stop_at:\n            raise _DeadlineExceeded()\n', ''),
    ("n8 no hard deadline around the GET", 'done, res = run_with_deadline(lambda: _get_with_retries(url, timeout, retries, stop_at), deadline + DEADLINE_GRACE_S)',
     'done, res = True, _get_with_retries(url, timeout, retries, stop_at)'),
    ("n8 output not line-buffered", '        stream.reconfigure(line_buffering=True)\n        return True', '        return True'),
    ("n13 repo-root upstream URL uses main instead of HEAD",
     '"https://raw.githubusercontent.com/%s/HEAD/%s" % (m.group(1), path), "HEAD"',
     '"https://raw.githubusercontent.com/%s/main/%s" % (m.group(1), path), "main"'),
]


def run(name, src):
    d = os.path.join(scr, "m%02d" % run.n)
    run.n += 1
    os.makedirs(os.path.join(d, "docs", "sources", "tools"), exist_ok=True)
    shutil.copy("docs/sources/pins.json", os.path.join(d, "docs", "sources", "pins.json"))
    tool = os.path.join(d, "docs", "sources", "tools", "fetch_pins.py")
    with open(tool, "w", encoding="utf-8") as f:
        f.write(src)
    p = subprocess.run([sys.executable, "-I", "-B", tool, "selftest"], capture_output=True, text=True, timeout=120)
    return p.returncode, [ln for ln in (p.stdout + p.stderr).splitlines() if ln.startswith("FAIL") or ln.startswith("selftest")]


run.n = 0
not_caught = 0
rc, out = run("unmutated", SRC)
print("unmutated copy: exit=%d %s" % (rc, out[-1:]))
baseline_ok = rc == 0
for name, old, new in MUTANTS:
    assert SRC.count(old) == 1, "mutation target not found exactly once: %s" % name
    rc, out = run(name, SRC.replace(old, new))
    caught = rc == 1 and any(ln.startswith("FAIL") for ln in out)
    not_caught += not caught
    print("%-78s exit=%d %s" % (name, rc, "CAUGHT" if caught else "NOT CAUGHT"))
    for ln in out[:2]:
        print("      ", ln[:150])
print("mutants: %d, not caught: %d, unmutated baseline %s" % (len(MUTANTS), not_caught, "passes" if baseline_ok else "FAILS"))
sys.exit(0 if baseline_ok and not not_caught else 1)
