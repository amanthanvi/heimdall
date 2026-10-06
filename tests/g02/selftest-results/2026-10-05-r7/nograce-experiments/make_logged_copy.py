#!/usr/bin/env python3
"""make_logged_copy.py SRC DST: a copy of reference_impl.py with no grace (STOP_GRACE_S = 0.0) that appends a line to
DST.log between its 'child still stopped' decision and its own stop (the instrumentation artefact)."""
import sys
src = open(sys.argv[1]).read()
a = 'STOP_GRACE_S = 0.0 if "run_mirror_nograce" in MUT else 0.2\n'
b = '                os.kill(0 if "run_mirror_killpg" in MUT else os.getpid(), sig)'
assert src.count(a) == 1 and src.count(b) == 1
src = src.replace(a, "STOP_GRACE_S = 0.0\n").replace(
    b, '                open(%r, "a").write("%%d mirror\\n" %% time.monotonic_ns())\n' % (sys.argv[2] + ".log") + b)
open(sys.argv[2], "w").write(src)
import os
os.chmod(sys.argv[2], 0o755)
