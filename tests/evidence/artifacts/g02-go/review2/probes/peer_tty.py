import os, sys, json, signal
d = sys.argv[1]
fd = os.open("/dev/tty", os.O_RDWR)
res = {"pgrp": os.getpgrp(), "fg_before": os.tcgetpgrp(fd)}
open(os.path.join(d, "peer.reading"), "w").write("1")
signal.signal(signal.SIGTTIN, signal.SIG_IGN)
try:
    res["read"] = os.read(fd, 100).decode()
except OSError as e:
    res["err"] = e.errno
sys.stdin.read()
open(os.path.join(d, "peer.result"), "w").write(json.dumps(res))
