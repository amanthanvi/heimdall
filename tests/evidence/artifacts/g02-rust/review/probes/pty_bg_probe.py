#!/usr/bin/env python3
"""Does `heimdall-proto run -- X &` inside a non-interactive script steal the terminal foreground group?"""
import json, os, pty, select, signal, sys, time

BIN = sys.argv[1]
OUT = sys.argv[2]
results = []


def session(script, feed=None, feed_at=0.6, budget=6.0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve("/bin/sh", ["/bin/sh", "-c", script], {"PATH": "/usr/bin:/bin", "BIN": BIN, "TERM": "dumb"})
    out = b""
    t0 = time.monotonic()
    fed = False
    status = None
    while time.monotonic() - t0 < budget:
        if feed is not None and not fed and time.monotonic() - t0 > feed_at:
            os.write(fd, feed)
            fed = True
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                d = b""
            if d:
                out += d
        wp, st = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if wp:
            if os.WIFSTOPPED(st):
                status = f"STOPPED by signal {os.WSTOPSIG(st)}"
                break
            status = f"exit {os.waitstatus_to_exitcode(st)}"
            # drain
            try:
                while True:
                    r, _, _ = select.select([fd], [], [], 0.1)
                    if not r:
                        break
                    d = os.read(fd, 4096)
                    if not d:
                        break
                    out += d
            except OSError:
                pass
            break
    if status is None or status.startswith("STOPPED"):
        # reviewer cleanup: the exact session we forked (pid == its own pgid/sid)
        if os.getpgid(pid) == pid:
            os.killpg(pid, signal.SIGKILL)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        status = status or "timeout (killed by reviewer)"
    os.close(fd)
    return status, out.decode("utf-8", "replace")


ps = "ps -o pid=,pgid=,tpgid=,stat=,comm= -p $$"
# A: direct background job: terminal fg group stays with the script
for label, job in (("direct", "/bin/sleep 1.5"), ("via_heimdall", '"$BIN" run -- /bin/sleep 1.5')):
    script = f'{job} & sleep 0.4; echo "script pgid=$(ps -o pgid= -p $$) tty_fg=$(ps -o tpgid= -p $$)"; IFS= read -r line; echo "read-ok:$line"; wait; echo done'
    st, out = session(script, feed=b"hello\n", feed_at=0.8)
    rec = {"case": "bg_job_in_noninteractive_script_" + label, "session_status": st, "transcript": out.replace("\r", "")[-400:]}
    rec["read_from_terminal_succeeded"] = "read-ok:hello" in out
    results.append(rec)
    print(json.dumps(rec, ensure_ascii=False))

json.dump(results, open(OUT, "w"), indent=1, ensure_ascii=False)
