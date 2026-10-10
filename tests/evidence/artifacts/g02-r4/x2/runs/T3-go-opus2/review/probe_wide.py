# Read-only reviewer probe: drive the built TUI in a pty with pyte and dump
# the screen (text + underline) after key sequences where a wide character
# leaves the screen. argv: binary profile cols rows keyseq...
import os, pty, sys, time, select, struct, fcntl, termios, pyte
binary, profile, cols, rows = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
keys = sys.argv[5:]
pid, fd = pty.fork()
if pid == 0:
    env = {"PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "NO_COLOR": "1"}
    os.execve(binary, [binary, "tui", "--file", profile], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
scr = pyte.Screen(cols, rows); st = pyte.ByteStream(scr)
def pump(t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: st.feed(os.read(fd, 65536))
            except OSError: return
def dump(label):
    print("==", label)
    for y in range(rows):
        line = scr.buffer[y]
        txt = "".join(line[x].data for x in range(cols))
        ul = "".join("^" if line[x].underscore else " " for x in range(cols))
        print("|" + txt + "|"); 
        if ul.strip(): print("|" + ul + "|")
pump(1.0); dump("start")
for k in keys:
    os.write(fd, k.encode().decode("unicode_escape").encode("utf-8") if k.startswith("\\") else k.encode())
    pump(0.5); dump("after %r" % k)
os.write(fd, b"\x03"); pump(0.5)
_, status = os.waitpid(pid, 0); print("exit", os.waitstatus_to_exitcode(status))
