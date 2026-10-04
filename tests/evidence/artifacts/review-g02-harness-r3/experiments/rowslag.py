# Direct observation: after typing "7" in filter mode, when does the status show 19/100 and when do the rows
# show only matching destinations?  Prints the elapsed times and a screen excerpt at the status-update moment.
import os, pty, sys, time, select, struct, fcntl, termios, re
import pyte
binp, prof = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execve(binp, [binp, "tui", "--file", prof], {"PATH": os.environ["PATH"], "TERM": "xterm-256color", "LANG": "en_US.UTF-8"})
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
scr = pyte.Screen(80, 24); st = pyte.ByteStream(scr)
def pump(t):
    r, _, _ = select.select([fd], [], [], t)
    if r:
        try: st.feed(os.read(fd, 65536))
        except OSError: pass
def status():
    for l in reversed(scr.display):
        m = re.search(r"(\d+)/(\d+)", l)
        if m: return m.group(0)
def rows_ok():   # every non-status row with content must contain a 7 in alias/host
    rows = [l.strip() for l in scr.display[:-1] if l.strip()]
    return rows and all("7" in l for l in rows), len(rows)
end = time.time() + 5
while time.time() < end and status() != "100/100": pump(0.01)
os.write(fd, b"/"); t = time.time()
while time.time() - t < 0.3: pump(0.01)
t0 = time.monotonic(); os.write(fd, b"7"); ts = tr = None; snap = None
while time.monotonic() - t0 < 1.0:
    pump(0.002)
    if ts is None and status() == "19/100":
        ts = time.monotonic() - t0; snap = (rows_ok(), scr.display[0][:40], scr.display[-1][:30])
    if tr is None and rows_ok()[0] and rows_ok()[1] == 19:
        tr = time.monotonic() - t0
print("status 19/100 after %.1f ms; rows all-matching (19) after %s ms; at status moment rows_ok/first row/status=%r"
      % (ts * 1000, "%.1f" % (tr * 1000) if tr else None, snap))
os.write(fd, b"\x1b"); os.write(fd, b"q")
time.sleep(0.3); os.kill(pid, 15) if False else None
os.waitpid(pid, 0)
