# TUI with TERMINFO pointing at a directory holding a crafted (fuzzer-found) terminfo
# entry for TERM: does the panic in xo/terminfo restore and exit 1 (K10)?
import fcntl, struct, termios, os, pty, select, sys, tempfile, time, json, shutil
P = sys.argv[1]; FIX = sys.argv[2]; CRASH = sys.argv[3]
d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "ti", "x")); shutil.copy(CRASH, os.path.join(d, "ti", "x", "xterm-hmcrash"))
# termios before
mfd, sfd = pty.openpty(); fcntl.ioctl(mfd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
before = termios.tcgetattr(mfd)
pid = os.fork()
if pid == 0:
    os.setsid(); fcntl.ioctl(sfd, termios.TIOCSCTTY, 0)
    for i in (0, 1, 2): os.dup2(sfd, i)
    os.execve(P, [P, "tui", "--file", os.path.join(FIX, "homelab.toml")], {"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm-hmcrash", "TERMINFO": os.path.join(d, "ti")})
buf = bytearray(); st = None; t0 = time.monotonic()
while time.monotonic() - t0 < 5:
    r, _, _ = select.select([mfd], [], [], 0.05)
    if r:
        try: buf.extend(os.read(mfd, 65536))
        except OSError: break
    w, s = os.waitpid(pid, os.WNOHANG)
    if w: st = os.waitstatus_to_exitcode(s); break
after = termios.tcgetattr(mfd)
txt = bytes(buf).decode("utf-8", "replace")
print(json.dumps({"exit": st, "termios_identical": before == after, "alt_screen_entered": "\x1b[?1049h" in txt,
                  "panic_text": ("panic:" in txt), "first_line": txt.split("\n")[0][:120],
                  "goroutine_trace": "goroutine " in txt}, indent=1))
