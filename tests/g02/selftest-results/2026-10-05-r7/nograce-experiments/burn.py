#!/usr/bin/env python3
"""burn.py N CMD...: run CMD while N busy-loop processes load the CPUs; the burners are killed afterwards."""
import subprocess, sys
ps = [subprocess.Popen([sys.executable, "-c", "while True: pass"]) for _ in range(int(sys.argv[1]))]
try:
    rc = subprocess.run(sys.argv[2:]).returncode
finally:
    for p in ps:
        p.kill()
        p.wait()
sys.exit(rc)
