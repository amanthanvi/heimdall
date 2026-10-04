#!/usr/bin/env python3
"""Black-box selftest of the Go G02 prototype binary (not the shared harness).

Usage: python3 selftest.py <path-to-heimdall-proto> <repo-root>
Prints one line per check: PASS/FAIL <name> <detail>. Exit 0 iff all pass.
Uses only temp dirs, a fake in-process agent on a private Unix socket, and a
private pty. No network listeners, no real agent, no ~/.ssh.
"""
import fcntl, json, os, re, select, signal, socket, struct, subprocess, sys, tempfile, termios, threading, time

BIN, REPO = sys.argv[1], sys.argv[2]
FIX = os.path.join(REPO, "tests/fixtures/g02/profiles")
results = []
ENV = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK",)}


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS" if ok else "FAIL"), name, detail, flush=True)


# ---------- byte passthrough and meta ----------
data = b"\x00\xff\xfeline\r\n\x1b[31m\x00end"
p = subprocess.run([BIN, "run", "--", "cat"], input=data, capture_output=True, env=ENV)
check("run.stdin_stdout_bytes", p.returncode == 0 and p.stdout == data, f"exit={p.returncode}")
with tempfile.TemporaryDirectory(prefix="hp go ü ") as d:
    meta = os.path.join(d, "meta ü.json")
    p = subprocess.run([BIN, "run", "--meta-file", meta, "--", "sh", "-c", "printf '\\377\\000' >&2; kill -KILL $$"],
                       capture_output=True, env=ENV)
    m = json.load(open(meta))
    check("run.signal_meta", p.returncode == 137 and p.stdout == b"" and p.stderr == b"\xff\x00"
          and m["code"] == "CHILD_EXITED" and m["data"] == {"launched": True, "exit_code": None, "signal": 9},
          f"exit={p.returncode} meta={m['data']}")


# ---------- non-tty: signal to heimdall's whole process group delivered once ----------
COUNTER = r'''
import signal, sys, time, os
n = [0]
def h(s, f): n[0] += 1
signal.signal(signal.SIGINT, h)
open(sys.argv[1], "w").write("ready")
end = time.time() + 3
while time.time() < end and n[0] == 0: time.sleep(0.01)
time.sleep(0.5)
sys.exit(10 + n[0])
'''
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    p = subprocess.Popen([BIN, "run", "--", sys.executable, "-c", COUNTER, ready], start_new_session=True, env=ENV)
    for _ in range(300):
        if os.path.exists(ready): break
        time.sleep(0.01)
    os.killpg(p.pid, signal.SIGINT)  # like a supervisor signalling the job's group
    rc = p.wait(10)
    check("run.group_sigint_once", rc == 11, f"exit={rc} (10+count)")


# ---------- pty helpers ----------
def spawn_pty(argv, cols=80, rows=24, env=None):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    before = termios.tcgetattr(master)  # macOS revokes the slave when the session leader exits
    p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                         preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0), env=env or ENV)
    return p, master, slave, before


def read_for(master, secs):
    out, end = b"", time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.02)
        if r:
            try:
                b = os.read(master, 65536)
            except OSError:
                break
            if not b: break
            out += b
    return out


def finish(p, master, slave, before, secs=3):
    out = b""
    end = time.time() + secs
    while p.poll() is None and time.time() < end:
        out += read_for(master, 0.05)
    out += read_for(master, 0.2)
    rc = p.poll()
    if rc is None:
        p.kill(); rc = p.wait()
    after = termios.tcgetattr(master)
    os.close(master); os.close(slave)
    return rc, out, after == before


def tui_case(name, keys, expect_rc, expect_sel, profile="homelab.toml", env=None, pre=None, cols=80, rows=24):
    e = dict(ENV); e["TERM"] = "xterm-256color"; e.update(env or {})
    p, m, s, before = spawn_pty([BIN, "tui", "--file", os.path.join(FIX, profile)], cols, rows, e)
    out = read_for(m, 0.6)
    if pre: out += pre(p, m, s)
    for k in keys:
        os.write(m, k); out += read_for(m, 0.08)
    rc, rest, restored = finish(p, m, s, before)
    out += rest
    entered = b"\x1b[?1049h" in out and b"\x1b[?25l" in out
    tail = out[out.rfind(b"\x1b[?1049l"):] if b"\x1b[?1049l" in out else b""
    left = bool(tail) and b"\x1b[?25h" in out[out.rfind(b"\x1b[?1049h"):]
    sel_ok = (expect_sel is None and b"SELECTED" not in out) or (expect_sel is not None and ("SELECTED " + expect_sel).encode() in tail)
    ok = rc == expect_rc and entered and left and restored and sel_ok
    check("tui." + name, ok, f"exit={rc} altscreen_in={entered} restored_screen={left} termios_restored={restored} selection_ok={sel_ok}")
    return out


tui_case("select_down_enter", [b"\x1b[B", b"\r"], 0, "nas")
tui_case("j_k_select", [b"j", b"j", b"k", b"\r"], 0, "nas")
tui_case("filter_unicode", ["/東京".encode(), b"\r", b"\r"], 0, "vps-東京")
tui_case("filter_esc_clears", [b"/", b"nas", b"\x1b", b"\r"], 0, "lab-server")
tui_case("filter_backspace", [b"/", b"nasx", b"\x7f", b"\r", b"\r"], 0, "nas")
tui_case("quit_q", [b"q"], 0, None)
tui_case("ctrl_c", [b"\x03"], 130, None)
tui_case("large_100_filter", [b"/", b"099", b"\r", b"\r"], 0, "host-099-ci", profile="large-100.toml")


def term_pre(p, m, s):
    p.send_signal(signal.SIGTERM)
    return b""
tui_case("sigterm_restores", [], 143, None, pre=term_pre)

out = tui_case("no_color", [b"\x1b[B", b"q"], 0, None, env={"NO_COLOR": "1"})
color_sgr = [x for x in re.findall(rb"\x1b\[([0-9;:]*)m", out) if re.search(rb"(^|;)(3[0-9]|4[0-9]|9[0-7]|10[0-7])(;|$)", x)]
check("tui.no_color_sgr", not color_sgr, f"color_sgr_count={len(color_sgr)}")
out = tui_case("color_default", [b"q"], 0, None, env={"NO_COLOR": ""})
check("tui.color_when_allowed", re.search(rb"\x1b\[[0-9;]*36", out) is not None, "TERM=xterm-256color, NO_COLOR empty")


def resize_pre(p, m, s):
    got = b""
    for cols, rows in [(20, 5), (49, 10), (120, 40), (20, 5)]:
        fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        t0 = time.time()
        chunk = read_for(m, 0.1)
        got += chunk
        check(f"tui.resize_{cols}x{rows}_redraw_within_100ms", bool(chunk) and p.poll() is None, f"bytes={len(chunk)} alive={p.poll() is None}")
    return got
out = tui_case("resize_then_select", [b"\r"], 0, "lab-server", pre=resize_pre)
p = subprocess.run([BIN, "tui", "--file", os.path.join(FIX, "homelab.toml")], capture_output=True, env=ENV)
check("tui.requires_tty", p.returncode == 2 and p.stdout == b"", f"exit={p.returncode}")


# ---------- interactive run: terminal Ctrl-C delivered once ----------
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    p, m, s, before = spawn_pty([BIN, "run", "--", sys.executable, "-c", COUNTER, ready])
    for _ in range(300):
        if os.path.exists(ready): break
        time.sleep(0.01)
    os.write(m, b"\x03")
    rc, out, restored = finish(p, m, s, before, 6)
    check("run.tty_ctrl_c_once", rc == 11, f"exit={rc} (10+count) termios_same={restored}")


# ---------- shared-tty mode: heimdall started as a background job ----------
# A session leader owns the pty; heimdall runs in a separate (background)
# process group. An explicit SIGINT to heimdall is forwarded once; after the
# job is moved to the foreground, a terminal Ctrl-C reaches the child directly
# and must not be forwarded a second time. Expected child count: 2.
COUNT2 = COUNTER.replace("n[0] == 0", "n[0] < 2")
LEADER = r'''
import os, sys, time, signal, termios
bin_, script, ready = sys.argv[1], sys.argv[2], sys.argv[3]
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    os.execv(bin_, [bin_, "run", "--", sys.executable, "-c", script, ready])
os.setpgid(pid, pid)
for _ in range(300):
    if os.path.exists(ready): break
    time.sleep(0.01)
time.sleep(0.1)
os.kill(pid, signal.SIGINT)              # explicit, job in background -> forwarded
time.sleep(0.3)
os.tcsetpgrp(0, pid)                     # "fg"
open(ready + ".fg", "w").write("1")
_, st = os.waitpid(pid, 0)
os.tcsetpgrp(0, os.getpgrp())
sys.exit(os.waitstatus_to_exitcode(st))
'''
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    p, m, s, before = spawn_pty([sys.executable, "-c", LEADER, BIN, COUNT2, ready])
    for _ in range(500):
        if os.path.exists(ready + ".fg"): break
        time.sleep(0.01)
    time.sleep(0.1)
    os.write(m, b"\x03")                 # terminal SIGINT to the (now foreground) job group
    rc, out, _ = finish(p, m, s, before, 8)
    check("run.shared_tty_bg_then_fg_once_each", rc == 12, f"exit={rc} (10+count, want 12)")


# ---------- agent CLI against a fake agent ----------
def ssh_str(b): return struct.pack(">I", len(b)) + b
def frame(b): return struct.pack(">I", len(b)) + b
blob = ssh_str(b"ssh-ed25519") + ssh_str(b"\x01" * 32)
ok_body = bytes([12]) + struct.pack(">I", 1) + ssh_str(blob) + ssh_str(b"fixture \xff")
cases = {
    "ok": (frame(ok_body), 0, "AGENT_OK"),
    "failure": (frame(b"\x05"), 5, "AGENT_REFUSED"),
    "oversize_len": (struct.pack(">I", 262145), 5, "AGENT_PROTOCOL_ERROR"),
    "huge_nkeys": (frame(bytes([12]) + struct.pack(">I", 0xFFFFFFFF)), 5, "AGENT_PROTOCOL_ERROR"),
    "trailing": (frame(ok_body + b"\x00"), 5, "AGENT_PROTOCOL_ERROR"),
    "truncated": (struct.pack(">I", 50) + ok_body[:10], 5, "AGENT_PROTOCOL_ERROR"),
    "wrong_type": (frame(b"\x06"), 5, "AGENT_PROTOCOL_ERROR"),
    "string_over": (frame(bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", 0x7FFFFFFF)), 5, "AGENT_PROTOCOL_ERROR"),
}


def fake_agent(path, reply, hold=0.0):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path); srv.listen(1)
    seen = {}
    def serve():
        c, _ = srv.accept()
        seen["req"] = c.recv(64)
        if reply is not None: c.sendall(reply)
        time.sleep(hold)
        c.close(); srv.close()
    t = threading.Thread(target=serve, daemon=True); t.start()
    return t, seen


for name, (reply, want_rc, want_code) in cases.items():
    d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
    path = os.path.join(d, "agent ü.sock")
    t, seen = fake_agent(path, reply)
    p = subprocess.run([BIN, "agent", "list", "--socket", path, "--json"], capture_output=True, env=ENV, timeout=10)
    t.join(2)
    doc = json.loads(p.stdout)
    extra = ""
    if name == "ok":
        idt = doc["data"]["identities"][0]
        extra = f" key_type={idt['key_type']} comment={idt['comment']!r} fp_ok={bool(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', idt['fingerprint']))}"
    check(f"agent.{name}", p.returncode == want_rc and doc["code"] == want_code and seen.get("req") == b"\x00\x00\x00\x01\x0b",
          f"exit={p.returncode} code={doc['code']}{extra}")

d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
p = subprocess.run([BIN, "agent", "list", "--socket", os.path.join(d, "missing"), "--json"], capture_output=True, env=ENV)
check("agent.connect_failure", p.returncode == 5 and json.loads(p.stdout)["code"] == "AGENT_UNAVAILABLE", f"exit={p.returncode}")

d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
path = os.path.join(d, "a.sock")
t, _ = fake_agent(path, None, hold=3)
t0 = time.time()
p = subprocess.run([BIN, "agent", "list", "--socket", path, "--timeout-ms", "300", "--json"], capture_output=True, env=ENV)
el = time.time() - t0
check("agent.timeout", p.returncode == 5 and json.loads(p.stdout)["code"] == "AGENT_UNAVAILABLE" and el < 1.5, f"exit={p.returncode} elapsed={el:.3f}s")

d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
path = os.path.join(d, "a.sock")
t, _ = fake_agent(path, None, hold=5)
p = subprocess.Popen([BIN, "agent", "list", "--socket", path, "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
time.sleep(0.4)
t0 = time.time()
p.send_signal(signal.SIGINT)
out, _ = p.communicate(5)
el = time.time() - t0
doc = json.loads(out)
check("agent.sigint_cancel", p.returncode == 130 and doc["state"] == "cancelled" and doc["code"] == "CANCELLED" and el < 0.5,
      f"exit={p.returncode} latency={el*1000:.1f}ms")

print(f"SUMMARY {sum(results)}/{len(results)} passed", flush=True)
sys.exit(0 if all(results) else 1)
