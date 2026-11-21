#!/usr/bin/env python3
"""M07 design probe P4 (disposable; never imported; docs/architecture/m07-plan.md §8).

Captures the TUI's first settled Overview for a fresh catalog of three imported (observed)
destinations at 120x40 and 40x12, through the debug build's screen dump, redacted
(scratch paths, the account's user name and home). Same boundaries as probe.py.

Usage: screen.py <heimdall binary> <output directory>
"""

import os
import pwd
import sys

OUTDIR = sys.argv[2]
sys.argv = [sys.argv[0], sys.argv[1], os.devnull]
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "probe.py"), encoding="utf-8").read()
SRC = SRC.replace('if __name__ == "__main__":\n    main()\n', "")
NS = {"__name__": "probe_helpers", "__file__": os.path.join(HERE, "probe.py")}
exec(compile(SRC, "probe.py", "exec"), NS)  # noqa: S102 (our own disposable script)

import json  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402

cli, Tui, env = NS["cli"], NS["Tui"], NS["env"]
SCRATCH, BIN, HOME = NS["SCRATCH"], NS["BIN"], NS["HOME"]
ME = pwd.getpwuid(os.getuid())


def redact(text):
    for needle, label in ((SCRATCH, "<scratch>"), (ME.pw_dir, "<home>"), (ME.pw_name, "<user>")):
        text = text.replace(needle, label)
    return text


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    service = subprocess.Popen([BIN, "service", "run"], env=env(), cwd=HOME,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(100):
            if cli("--json", "service", "status")[0] == 0:
                break
            time.sleep(0.1)
        path = os.path.join(SCRATCH, "b3.json")
        NS["bundle"](3, path)
        print("import exit", cli("--json", "import", path, "--yes")[0])
        for rows, cols in ((40, 120), (12, 40)):
            screen_path = os.path.join(SCRATCH, "screen.txt")
            t = Tui(rows, cols, {"HEIMDALL_TEST_TUI_SCREEN": screen_path})
            t.wait_for(b"Static pass: ", 60, screen_path)
            t.read_for(6)
            text = open(screen_path, encoding="utf-8").read()
            print("quit exit", t.quit())
            name = "overview-3-destinations-%dx%d.txt" % (cols, rows)
            with open(os.path.join(OUTDIR, name), "w", encoding="utf-8") as f:
                f.write(redact(text))
    finally:
        print("stop exit", cli("service", "stop")[0])
        try:
            service.wait(15)
        except subprocess.TimeoutExpired:
            os.kill(service.pid, signal.SIGTERM)  # the exact PID this script started
            service.wait(10)
        print("service exit", service.returncode)
        shutil.rmtree(SCRATCH)
        print("scratch removed", not os.path.exists(SCRATCH))


main()
