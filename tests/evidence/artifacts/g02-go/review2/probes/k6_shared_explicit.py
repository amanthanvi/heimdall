# K6/K6b probe: heimdall-proto in modeShared (shares its process group with the
# foreground script that started it, no job control), group holds the terminal
# foreground; a signal is sent explicitly to the heimdall-proto PID by an outside
# process. K6b rank 2: it must reach the child exactly once.
import json, os, pty, signal, sys, tempfile, time, select, subprocess
P = sys.argv[1]; PY = sys.executable; HERE = os.path.dirname(os.path.abspath(__file__))
results = {}
def run_case(name, sig, layout):
    d = tempfile.mkdtemp(prefix="hm-r2-k6-")
    if layout == "script-fg":
        # non-job-control sh in the pty foreground starts heimdall-proto (same group)
        cmd = ["/bin/sh", "-c", '"$P" run -- "$Y" "$C" "$D" 2.5; echo "RC=$?" > "$D/rc"']
    elif layout == "pipeline-stdout":
        cmd = ["/bin/sh", "-c", '"$P" run -- "$Y" "$C" "$D" 2.5 | cat; echo "RC=$?" > "$D/rc"']
    elif layout == "alone-fg":   # control: modeExclusive
        cmd = [P, "run", "--", PY, os.path.join(HERE, "child_trap.py"), d, "2.5"]
    env = dict(os.environ, P=P, Y=PY, C=os.path.join(HERE, "child_trap.py"), D=d)
    env.pop("SSH_AUTH_SOCK", None)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(cmd[0], cmd, env)
    end = time.time() + 10
    while not os.path.exists(os.path.join(d, "ready")) and time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.01)
        if r:
            try: os.read(fd, 4096)
            except OSError: pass
    ready = open(os.path.join(d, "ready")).read().split()
    child_pid, proto_pid, child_pgrp = int(ready[0]), int(ready[1]), int(ready[2])
    proto_pgrp = os.getpgid(proto_pid)
    fg = os.tcgetpgrp(fd)
    time.sleep(0.1)
    os.kill(proto_pid, sig)   # explicit, to heimdall-proto's PID only
    end = time.time() + 8
    st = None
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.02)
        if r:
            try: os.read(fd, 4096)
            except OSError: pass
        w, s = os.waitpid(pid, os.WNOHANG)
        if w:
            st = s; break
    sigs = open(os.path.join(d, "signals")).read().split() if os.path.exists(os.path.join(d, "signals")) else []
    rc = open(os.path.join(d, "rc")).read().strip() if os.path.exists(os.path.join(d, "rc")) else None
    if layout == "alone-fg" and st is not None:
        rc = "RC=%d" % os.waitstatus_to_exitcode(st)
    results["%s/%s" % (layout, signal.Signals(sig).name)] = {
        "child_signals": sigs, "proto_rc": rc, "proto_pgrp_eq_child_pgrp": proto_pgrp == child_pgrp,
        "terminal_fg_is_proto_group": fg == proto_pgrp, "terminal_fg_is_child_group": fg == child_pgrp,
        "expected_child_signals_K6": [signal.Signals(sig).name]}
    os.close(fd)
for layout in ("alone-fg", "script-fg", "pipeline-stdout"):
    for sig in (signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH, signal.SIGTERM):
        run_case(layout, sig, layout) if False else run_case(None, sig, layout)
print(json.dumps(results, indent=1))
bad = [k for k, v in results.items() if v["child_signals"] != v["expected_child_signals_K6"]]
print("K6_VIOLATIONS", bad)
sys.exit(1 if bad else 0)
