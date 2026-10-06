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


# ======================================================================
# §9 clarifications K1-K12 (added 2026-10-03, M00-T05-go-align)
# ======================================================================

# ---------- K1: control characters in agent output become U+FFFD ----------
ctl = "".join(chr(c) for c in list(range(0x20)) + list(range(0x7f, 0xa0))).encode("utf-8")
kt_raw = b"ssh-ed25519\x1b[31m\t" + ctl
blob_k1 = ssh_str(kt_raw) + ssh_str(b"\x01" * 32)
body_k1 = bytes([12]) + struct.pack(">I", 1) + ssh_str(blob_k1) + ssh_str(b"c\xff\x1b]0;x\x07" + ctl)
d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
path = os.path.join(d, "k1.sock")
t, _ = fake_agent(path, frame(body_k1))
p = subprocess.run([BIN, "agent", "list", "--socket", path, "--json"], capture_output=True, env=ENV, timeout=10)
t.join(2)
doc = json.loads(p.stdout)
idt = doc["data"]["identities"][0] if doc.get("code") == "AGENT_OK" else {}
bad = [c for s_ in (idt.get("key_type", ""), idt.get("comment", "")) for c in s_ if ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f]
check("agent.k1_controls_replaced", p.returncode == 0 and idt != {} and not bad and "�" in idt["comment"] and "�" in idt["key_type"]
      and b"\\u001b" not in p.stdout and b"\x1b" not in p.stdout,
      f"exit={p.returncode} control_code_points_left={len(bad)}")

# ---------- K3 / K4: EOF classification and failure frame shape ----------
for name, reply, want_rc, want_code in (
        ("k3_eof_zero_bytes", b"", 5, "AGENT_UNAVAILABLE"),
        ("k3_eof_after_one_byte", b"\x00", 5, "AGENT_PROTOCOL_ERROR"),
        ("k3_eof_mid_body", struct.pack(">I", 5) + b"\x0c\x00", 5, "AGENT_PROTOCOL_ERROR"),
        ("k4_failure_with_payload", frame(b"\x05\x00"), 5, "AGENT_PROTOCOL_ERROR"),
        ("k4_failure_len1", frame(b"\x05"), 5, "AGENT_REFUSED")):
    d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
    path = os.path.join(d, "a.sock")
    t, seen = fake_agent(path, reply)
    p = subprocess.run([BIN, "agent", "list", "--socket", path, "--json"], capture_output=True, env=ENV, timeout=10)
    t.join(2)
    doc = json.loads(p.stdout)
    check("agent." + name, p.returncode == want_rc and doc["code"] == want_code and doc["state"] == "failed",
          f"exit={p.returncode} code={doc['code']}")

# ---------- K2: control characters in profile values ----------
K2_HEAD = 'schema_version = 1\nrevision = 1\n'
K2_DEST = '[[destinations]]\nid = "d1"\nalias = "a1"\nhost = "h1"\naccount = "u1"\n'
k2_cases = [
    ("name_esc", K2_HEAD + 'name = "HEIMDALL_CANARY_k2\\u001b[31m"\n', "name"),
    ("name_raw_tab", K2_HEAD + 'name = "HEIMDALL_CANARY_k2\tx"\n', "name"),
    ("alias_del", K2_HEAD + 'name = "x"\n' + K2_DEST.replace('"a1"', '"HEIMDALL_CANARY_k2\\u007f"'), "destinations[0].alias"),
    ("host_c1", K2_HEAD + 'name = "x"\n' + K2_DEST.replace('"h1"', '"HEIMDALL_CANARY_k2\\u009b"'), "destinations[0].host"),
    ("account_nul", K2_HEAD + 'name = "x"\n' + K2_DEST.replace('"u1"', '"HEIMDALL_CANARY_k2\\u0000"'), "destinations[0].account"),
    ("label_newline", K2_HEAD + 'name = "x"\n' + K2_DEST + 'labels = ["ok", "HEIMDALL_CANARY_k2\\n"]\n', "destinations[0].labels[1]"),
]
with tempfile.TemporaryDirectory(prefix="hp k2 ü ") as d:
    for name, src, kp in k2_cases:
        f = os.path.join(d, name + ".toml")
        open(f, "w", encoding="utf-8").write(src)
        p = subprocess.run([BIN, "profile", "show", "--file", f, "--json"], capture_output=True, env=ENV)
        doc = json.loads(p.stdout)
        leak = b"HEIMDALL_CANARY_" in p.stdout + p.stderr
        got_kp = ((doc.get("data") or {}).get("error") or {}).get("key_path")
        check("profile.k2_" + name, p.returncode == 2 and doc["code"] == "SCHEMA_INVALID"
              and got_kp == kp and not leak,
              f"exit={p.returncode} code={doc['code']} key_path={got_kp} canary_leak={leak}")
    f = os.path.join(d, "meta.toml")
    open(f, "w", encoding="utf-8").write(K2_HEAD + 'name = "x"\n[meta]\nnote = "HEIMDALL_CANARY_k2\\u001b\\t\\u009b"\n')
    p = subprocess.run([BIN, "profile", "show", "--file", f, "--json"], capture_output=True, env=ENV)
    check("profile.k2_meta_tolerated", p.returncode == 0 and json.loads(p.stdout)["code"] == "PROFILE_OK"
          and b"HEIMDALL_CANARY_" not in p.stdout + p.stderr, f"exit={p.returncode}")

# ---------- K5: meta state ----------
with tempfile.TemporaryDirectory(prefix="hp k5 ") as d:
    meta = os.path.join(d, "m.json")
    got = []
    for argv, want_rc, want_code, want_state in (
            (["sh", "-c", "exit 3"], 3, "CHILD_EXITED", "succeeded"),
            (["sh", "-c", "kill -TERM $$"], 143, "CHILD_EXITED", "succeeded"),
            (["heimdall-proto-no-such-cmd-k5"], 127, "CHILD_LAUNCH_FAILED", "failed")):
        p = subprocess.run([BIN, "run", "--meta-file", meta, "--"] + argv, capture_output=True, env=ENV)
        m = json.load(open(meta))
        got.append(p.returncode == want_rc and m["code"] == want_code and m["state"] == want_state and p.stdout == b"")
    check("run.k5_meta_state", all(got), f"cases_ok={got}")

# ---------- K8: invalid UTF-8 argv passes byte-for-byte ----------
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, "raw")
    arg = b"\xff\xfe\x80 inv\xc3(alid \xed\xa0\x80"
    p = subprocess.run([BIN.encode(), b"run", b"--", b"/bin/sh", b"-c", b'printf "%s" "$1" > "$2"', b"sh", arg, out.encode()],
                       capture_output=True, env=ENV)
    raw = open(out, "rb").read()
    check("run.k8_invalid_utf8_argv_bytes", p.returncode == 0 and raw == arg, f"exit={p.returncode} bytes_equal={raw == arg}")

# ---------- K6: explicit signal reaches the child exactly once in every state ----------
COUNT1 = COUNTER
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    p, m, s, before = spawn_pty([BIN, "run", "--", sys.executable, "-c", COUNT1, ready])
    for _ in range(300):
        if os.path.exists(ready): break
        time.sleep(0.01)
    time.sleep(0.1)
    p.send_signal(signal.SIGINT)         # explicit kill -INT <heimdall pid>, heimdall in the foreground
    rc, out, restored = finish(p, m, s, before, 6)
    check("run.k6_foreground_explicit_sigint_once", rc == 11, f"exit={rc} (10+count, want 11) termios_same={restored}")

# Background job: explicit SIGINT (1); `fg` without SIGCONT (as bash does for a
# running job); explicit SIGINT to heimdall while its job is in the foreground
# (2); then a terminal Ctrl-C (3). Each must reach the child exactly once.
COUNT3 = COUNTER.replace("n[0] == 0", "n[0] < 3").replace("time.time() + 3", "time.time() + 6")
LEADER3 = r"""
import os, sys, time, signal
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
os.kill(pid, signal.SIGINT)              # 1: explicit, job in background
time.sleep(0.3)
os.tcsetpgrp(0, pid)                     # "fg" (no SIGCONT)
time.sleep(0.3)
os.kill(pid, signal.SIGINT)              # 2: explicit, job in foreground
time.sleep(0.3)
open(ready + ".fg", "w").write("1")
_, st = os.waitpid(pid, 0)
os.tcsetpgrp(0, os.getpgrp())
sys.exit(os.waitstatus_to_exitcode(st))
"""
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    p, m, s, before = spawn_pty([sys.executable, "-c", LEADER3, BIN, COUNT3, ready])
    for _ in range(800):
        if os.path.exists(ready + ".fg"): break
        time.sleep(0.01)
    time.sleep(0.1)
    os.write(m, b"\x03")                 # 3: terminal SIGINT
    rc, out, _ = finish(p, m, s, before, 10)
    check("run.k6_bg_fg_explicit_and_terminal_once_each", rc == 13, f"exit={rc} (10+count, want 13)")

# ---------- K9: filter edits reset the selection; Enter keeps it ----------
DOWN = b"\x1b[B"
tui_case("k9_append_resets", [DOWN, DOWN, b"/", b"e", b"\r", b"\r"], 0, "lab-server")
tui_case("k9_backspace_resets", [b"/", b"e", DOWN, b"\x7f", b"\r", b"\r"], 0, "lab-server")
tui_case("k9_esc_resets", [b"/", b"e", DOWN, DOWN, b"\x1b", b"\r"], 0, "lab-server")
tui_case("k9_enter_keeps", [b"/", b"e", DOWN, DOWN, b"\r", b"\r"], 0, "vps-東京")

# ---------- K10: SIGHUP / terminal hangup ----------
def hup_pre(p, m, s):
    p.send_signal(signal.SIGHUP)
    return b""
tui_case("k10_sighup_restores_129", [], 129, None, pre=hup_pre)

e = dict(ENV); e["TERM"] = "xterm-256color"
p, m, s, before = spawn_pty([BIN, "tui", "--file", os.path.join(FIX, "homelab.toml")], 80, 24, e)
out = read_for(m, 0.6)
os.close(m)                              # terminal hangup: kernel sends SIGHUP to the session
try:
    rc = p.wait(5)
except subprocess.TimeoutExpired:
    p.kill(); rc = p.wait()
os.close(s)
check("tui.k10_hangup_master_close_129", rc == 129 and b"\x1b[?1049h" in out, f"exit={rc}")

# ---------- K11: no sidecars; no writes outside paths named on the command line ----------
with tempfile.TemporaryDirectory(prefix="hp k11 ") as d:
    home = os.path.join(d, "home"); os.mkdir(home)
    e = dict(ENV); e.update({"HOME": home, "TMPDIR": home, "TEA_TRACE": os.path.join(home, "trace.log"), "TEA_DEBUG": "1",
                             "TERM": "xterm-256color"})
    # Control: an unrelated program under the same environment. Under x86-64
    # emulation (Rosetta in Docker Desktop) every process creates
    # $HOME/.cache/rosetta; such emulator writes are reported, not attributed.
    def tree(root):
        return sorted(os.path.relpath(os.path.join(dp, n), root) for dp, dns, fns in os.walk(root) for n in dns + fns)
    subprocess.run(["true"], env=e, cwd=home)
    control = tree(home)
    control_dirs = [c for c in control if os.path.isdir(os.path.join(home, c)) and not any(o.startswith(c + os.sep) for o in control)]
    rcs = []
    for args in (["version", "--json"], ["profile", "show", "--file", os.path.join(FIX, "homelab.toml"), "--json"],
                 ["agent", "list", "--socket", os.path.join(home, "missing.sock"), "--json"], ["run", "--", "true"]):
        rcs.append(subprocess.run([BIN] + args, capture_output=True, env=e, cwd=home).returncode)
    p, m, s_, before = spawn_pty([BIN, "tui", "--file", os.path.join(FIX, "homelab.toml")], env=e)
    read_for(m, 0.5); os.write(m, b"q")
    rc, _, _ = finish(p, m, s_, before)
    rcs.append(rc)
    left = [x for x in tree(home) if x not in control and not any(x.startswith(c + os.sep) for c in control_dirs)]
    sidecars = sorted(x for x in os.listdir(os.path.dirname(os.path.abspath(BIN))) if not x.startswith("heimdall-proto"))
    check("k11.no_writes_no_sidecars", rcs == [0, 0, 5, 0, 0] and left == [] and sidecars == [],
          f"exits={rcs} files_written={left} sidecars={sidecars} control_program_wrote={control}")

# ---------- round 2 (2026-10-03): K6a job and signal transparency ----------
# An interactive job-control shell runs in a private pty. A pipeline member,
# or the script that started heimdall as a `&` job, reads the tty; it must get
# the line and must not be stopped. Each case has a control without heimdall:
# if the control fails, the environment is wrong and the check fails too.
SHELL = os.environ.get("PROBE_SHELL") or ("/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh")


def shell_session(cmdline, feed_after=0.6, wait=6.0):
    import pty
    home = tempfile.mkdtemp(prefix="hp-k6a-")
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update({"PATH": "/usr/bin:/bin", "HOME": home, "TERM": "xterm", "PS1": "PROMPT$ ", "LANG": "C.UTF-8"})
        argv = ["bash", "--norc", "--noprofile", "-i"] if SHELL.endswith("bash") else [SHELL, "-i"]
        os.execv(SHELL, argv)
    buf = bytearray()

    def pump(t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    b = os.read(fd, 4096)
                except OSError:
                    return
                if not b:
                    return
                buf.extend(b)
    pump(0.8)
    os.write(fd, cmdline.encode() + b"\n")
    pump(feed_after)
    os.write(fd, b"hello\n")
    got, end = False, time.monotonic() + wait
    while time.monotonic() < end and not got:
        pump(0.1)
        got = b"GOT:hello" in buf
    pump(0.3)
    stopped = b"Stopped" in buf or b"stopped" in buf
    for c in (b"exit\n", b"exit\n"):
        try:
            os.write(fd, c)
        except OSError:
            break
        pump(0.3)
    try:
        os.kill(pid, signal.SIGKILL)  # the shell this check started
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(fd)
    return got, stopped


RD = "/bin/sh -c 'sleep 0.3; read x </dev/tty; echo GOT:$x'"
SLOW = "/bin/sh -c 'sleep 1; read x </dev/tty; echo GOT:$x >/dev/tty'"
K6A = [
    ("pipeline_run_first", BIN + " run -- sleep 1.5 | " + RD, "sleep 1.5 | " + RD, 0.6),
    ("pipeline_run_last", RD + " | " + BIN + " run -- cat", RD + " | cat", 0.6),
    ("pipeline_slow_reader_then_run", SLOW + " | " + BIN + " run -- sleep 3", SLOW + " | sleep 3", 1.6),
    ("pipeline_run_then_slow_reader", BIN + " run -- sleep 3 | " + SLOW, "sleep 3 | " + SLOW, 1.6),
    ("pipeline_child_reads_tty", BIN + " run -- " + RD + " | cat", RD + " | cat", 0.6),
    ("async_job_of_script", "/bin/sh -c '" + BIN + " run -- sleep 2 & sleep 0.5; read x </dev/tty; echo GOT:$x; wait'",
     "/bin/sh -c 'sleep 2 & sleep 0.5; read x </dev/tty; echo GOT:$x; wait'", 1.0),
]
for name, cmd, control, feed in K6A:
    cg, cs = shell_session(control, feed)
    g, st = shell_session(cmd, feed)
    check("run.k6a_" + name, cg and not cs and g and not st,
          f"shell={SHELL} control_got={cg} control_stopped={cs} got={g} stopped={st}")

# Inherited ignored dispositions (K6a): heimdall started with SIGINT and SIGHUP
# ignored. The child must inherit them as ignored, and explicit SIGINT/SIGHUP
# to heimdall must not reach (or end) the child. SIGQUIT is recorded only: the
# Go runtime installs its own SIGQUIT handler whatever the inherited
# disposition and the child gets the default (stack limitation, REPORT.md).
DISP = """
import signal, sys, time
n = {"SIG_IGN": "ign", "SIG_DFL": "dfl"}
d = {s: n.get(getattr(signal.getsignal(getattr(signal, s)), "name", "other"), "other") for s in ("SIGINT", "SIGHUP", "SIGQUIT")}
open(sys.argv[1], "w").write(" ".join("%s=%s" % kv for kv in sorted(d.items())))
time.sleep(1.0)
sys.exit(5)
"""
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, "disp")

    def ign():
        for sg in (signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(sg, signal.SIG_IGN)
    p = subprocess.Popen([BIN, "run", "--", sys.executable, "-c", DISP, out], start_new_session=True, env=ENV, preexec_fn=ign)
    for _ in range(300):
        if os.path.exists(out) and open(out).read(): break
        time.sleep(0.01)
    time.sleep(0.1)
    p.send_signal(signal.SIGINT)
    p.send_signal(signal.SIGHUP)
    rc = p.wait(10)
    disp = open(out).read() if os.path.exists(out) else ""
    check("run.k6a_inherited_ignore_int_hup", rc == 5 and "SIGINT=ign" in disp and "SIGHUP=ign" in disp,
          f"exit={rc} (want 5: child unaffected) child_dispositions='{disp}'")
    q = disp.split("SIGQUIT=")[1].split()[0] if "SIGQUIT=" in disp else "?"
    print("OBSERVE run.k6a_inherited_ignore_quit (stack limitation, not counted): child SIGQUIT=" + q
          + " (exec semantics would be ign)", flush=True)

# Exclusive mode must not be lost because stderr alone is a pipe (log capture):
# an explicit SIGINT to heimdall in the foreground still reaches the child once.
with tempfile.TemporaryDirectory() as d:
    ready = os.path.join(d, "ready")
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    p = subprocess.Popen([BIN, "run", "--", sys.executable, "-c", COUNTER, ready], stdin=slave, stdout=slave,
                         stderr=subprocess.PIPE, start_new_session=True,
                         preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0), env=ENV)
    for _ in range(300):
        if os.path.exists(ready): break
        time.sleep(0.01)
    time.sleep(0.1)
    p.send_signal(signal.SIGINT)
    try:
        rc = p.wait(6)
    except subprocess.TimeoutExpired:
        p.kill(); rc = p.wait()
    p.stderr.close(); os.close(master); os.close(slave)
    check("run.k6_foreground_explicit_sigint_once_stderr_piped", rc == 11, f"exit={rc} (10+count, want 11)")


def children_of(ppid):
    """PIDs whose parent is ppid (no command lines are read or printed)."""
    out = []
    if os.path.isdir("/proc/self"):
        for n in os.listdir("/proc"):
            if n.isdigit():
                try:
                    st = open("/proc/%s/stat" % n).read()
                except OSError:
                    continue
                f = st[st.rfind(")") + 1:].split()
                if len(f) > 1 and f[1] == str(ppid):
                    out.append(int(n))
    else:
        for line in subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True).stdout.splitlines():
            f = line.split()
            if len(f) == 2 and f[1] == str(ppid):
                out.append(int(f[0]))
    return out


# Controlling terminal not on stdio: the child reads /dev/tty while
# heimdall's stdin/stdout/stderr are redirected. heimdall must find the
# terminal through /dev/tty and let the child have it (no endless SIGTTIN stop).
with tempfile.TemporaryDirectory() as d:
    m, s_ = os.openpty()
    sname = os.ttyname(s_)
    got = os.path.join(d, "got")

    def ctty():
        fdt = os.open(sname, os.O_RDWR)
        fcntl.ioctl(fdt, termios.TIOCSCTTY, 0)
        os.close(fdt)
    p = subprocess.Popen([BIN, "run", "--", "/bin/sh", "-c", 'read x </dev/tty; echo "GOT:$x" > "$0"', got],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, preexec_fn=ctty, env=ENV)
    # Drain the master: the echoed input must not fill the pty output queue,
    # or the exiting session leader (heimdall) waits for it to drain.
    stop_drain = threading.Event()

    def drain():
        while not stop_drain.is_set():
            r, _, _ = select.select([m], [], [], 0.05)
            if r:
                try:
                    os.read(m, 4096)
                except OSError:
                    return
    th = threading.Thread(target=drain, daemon=True); th.start()
    time.sleep(0.5)
    os.write(m, b"hello\n")
    try:
        rc = p.wait(5)
    except subprocess.TimeoutExpired:
        rc = None
    text = open(got).read().strip() if os.path.exists(got) else ""
    if rc is None:
        # Stuck child (stopped by SIGTTIN): the check failed. Stop exactly what
        # this check started: heimdall (p.pid) and its session's other members.
        for cpid in children_of(p.pid):
            try:
                os.kill(cpid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        p.kill()
        os.close(s_); os.close(m)  # hang up the pty so heimdall's exit can finish
        try:
            rc = p.wait(5)
        except subprocess.TimeoutExpired:
            rc = "stuck"
        stop_drain.set()
    else:
        stop_drain.set(); th.join(1)
        os.close(m); os.close(s_)
    check("run.k6a_ctty_not_on_stdio_child_reads_tty", rc == 0 and text == "GOT:hello", f"exit={rc} child_got='{text}'")


# ---------- round 3b (2026-10-04): K6e job control, K6d shared mode, env-selected terminfo ----------
import shutil
def proc_state(pid):
    """One-letter scheduler state ('T' = stopped) or None; never reads a command line."""
    try:
        if sys.platform.startswith("linux"):
            return open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[0]
        r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(int(pid))], capture_output=True, text=True, timeout=5)
        return r.stdout.strip()[:1] or None
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def rss_kib(pid):
    try:
        if sys.platform.startswith("linux"):
            for line in open("/proc/%d/status" % pid):
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
            return 0
        r = subprocess.run(["/bin/ps", "-o", "rss=", "-p", str(int(pid))], capture_output=True, text=True, timeout=5)
        return int(r.stdout.strip() or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


K6E_CHILD = r"""
import json, os, sys, time
d, n = sys.argv[1], int(sys.argv[2])
def put(name, text):
    p = os.path.join(d, name)
    with open(p + ".part", "w") as f:
        f.write(text)
    os.replace(p + ".part", p)
put("child.json", json.dumps({"pid": os.getpid(), "ppid": os.getppid()}))
got = []
def take():
    got.append(os.read(0, 4096).decode("utf-8", "replace"))
    put("got", json.dumps(got))
beat = 0
for i in range(1, n + 1):
    put("ready-a.%d" % i, "1")
    take()
    put("wait-b.%d" % i, "1")
    while not os.path.exists(os.path.join(d, "go-b.%d" % i)):
        beat += 1
        put("beat", str(beat))
        time.sleep(0.02)
    put("ready-b.%d" % i, "1")
    take()
put("done", "1")
sys.exit(0)
"""
K6E_N = 5


def k6e_session(shell, form):
    """Ctrl-Z/fg and Ctrl-Z/bg/fg, K6E_N times each, with `run` as a job of an interactive shell.
    Returns (ok, detail). Every wait is bounded; the shell started here is killed at the end."""
    import pty
    d = tempfile.mkdtemp(prefix="hp-k6e-")
    open(os.path.join(d, "c.py"), "w").write(K6E_CHILD)
    stopw = b"Stopped" if shell.endswith("bash") else b"suspended"
    argv = [shell, "--norc", "--noprofile", "-i"] if shell.endswith("bash") else [shell, "-f", "-i"]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update({"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm", "PS1": "HMPS1$ ", "LANG": "C.UTF-8",
                           "HISTFILE": os.path.join(d, "hist"), "BASH_SILENCE_DEPRECATION_WARNING": "1",
                           "P": BIN, "Y": sys.executable, "D": d})
        os.execv(shell, argv)
    buf = bytearray()
    prompt = b"HMPS1$ "

    def pump(t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.02)
            if r:
                try:
                    b = os.read(fd, 4096)
                except OSError:
                    return
                if not b:
                    return
                buf.extend(b)

    def until(pred, t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            if pred():
                return True
            pump(0.02)
        return pred()

    def exists(n):
        return os.path.exists(os.path.join(d, n))

    def got():
        try:
            return json.load(open(os.path.join(d, "got")))
        except (OSError, ValueError):
            return []

    def beat():
        try:
            return int(open(os.path.join(d, "beat")).read() or 0)
        except (OSError, ValueError):
            return 0
    child = proto = None
    fail = None
    try:
        if not until(lambda: prompt in buf, 10):
            return False, "no prompt"
        line = '"$P" run -- "$Y" "$D/c.py" "$D" %d' % K6E_N + ('; echo "LIST_RC=$?"' if form == "list" else "")
        os.write(fd, line.encode() + b"\r")
        if not until(lambda: exists("ready-a.1"), 10):
            return False, "child did not start"
        ids = json.load(open(os.path.join(d, "child.json")))
        child, proto = ids["pid"], ids["ppid"]
        n = 0

        def ctrl_z(tag):
            m = len(buf)
            os.write(fd, b"\x1a")
            ok = until(lambda: stopw in buf[m:] and prompt in buf[m:][buf[m:].find(stopw):], 5)
            return ok or "%s: Ctrl-Z did not stop the job" % tag

        def fg(tag):
            m = len(buf)
            os.write(fd, b"fg\r")
            pump(0.5)
            if stopw in buf[m:] or prompt in buf[m:] or proc_state(child) == "T":
                return "%s: re-stopped right after fg (child state %s)" % (tag, proc_state(child))
            return m

        def typed(tag, text, k):
            os.write(fd, text.encode() + b"\r")
            ok = until(lambda: len(got()) >= k, 3) and got()[k - 1] == text + "\n"
            return ok or "%s: child did not read the line (got %r)" % (tag, got()[k - 1:k])

        for i in range(1, K6E_N + 1):
            tag = "iter %d z-fg" % i
            if not until(lambda: exists("ready-a.%d" % i), 5):
                fail = tag + ": child not back in its read"; break
            pump(0.15)
            r = ctrl_z(tag)
            if r is not True:
                fail = r; break
            m = fg(tag)
            if isinstance(m, str):
                fail = m; break
            r = typed(tag, "K6E-A-%d" % i, n + 1)
            if r is not True:
                fail = r; break
            n += 1
            pump(1.0)  # 1.5 s after fg: no late re-stop
            if stopw in buf[m:] or proc_state(child) == "T":
                fail = tag + ": re-stopped within 1.5 s after fg"; break
            tag = "iter %d z-bg-fg" % i
            if not until(lambda: exists("wait-b.%d" % i), 5):
                fail = tag + ": child not in heartbeat"; break
            pump(0.1)
            r = ctrl_z(tag)
            if r is not True:
                fail = r; break
            b0 = beat(); pump(0.4); b1 = beat()
            if b0 != b1:
                fail = "%s: child ran while the job was stopped (%d->%d, child %s, proto %s)" % (
                    tag, b0, b1, proc_state(child), proc_state(proto)); break
            mb = len(buf)
            os.write(fd, b"bg\r")
            until(lambda: prompt in buf[mb:] or (b"continued" in buf[mb:]), 3)
            pump(0.3); b2 = beat(); pump(0.4); b3 = beat()
            if not (b3 > b2) or proc_state(child) == "T" or stopw in buf[mb:]:
                fail = "%s: after bg the child is not running (%d->%d, %s)" % (tag, b2, b3, proc_state(child)); break
            m = fg(tag)
            if isinstance(m, str):
                fail = m; break
            open(os.path.join(d, "go-b.%d" % i), "w").write("1")
            if not until(lambda: exists("ready-b.%d" % i), 3):
                fail = tag + ": child did not leave its heartbeat"; break
            pump(0.05)
            r = typed(tag, "K6E-B-%d" % i, n + 1)
            if r is not True:
                fail = r; break
            n += 1
            pump(1.0)
            if stopw in buf[m:] or proc_state(child) == "T":
                fail = tag + ": re-stopped within 1.5 s after fg"; break
        if fail is None:
            until(lambda: exists("done"), 5)
            until(lambda: buf.rstrip().endswith(prompt.rstrip()), 5)
            m = len(buf)
            jobs = "$(jobs -p | wc -l)" if shell.endswith("bash") else "${#jobstates}"
            os.write(fd, ('echo "K6E_RC=$? K6E_JOBS=%s"\r' % jobs).encode())
            until(lambda: re.search(rb"K6E_RC=(\d+) K6E_JOBS=\s*(\d+)", bytes(buf[m:])) is not None, 5)
            mm = re.search(rb"K6E_RC=(\d+) K6E_JOBS=\s*(\d+)", bytes(buf[m:]))
            if not (exists("done") and mm and mm.groups() == (b"0", b"0")):
                fail = "job did not finish cleanly (done=%s rc/jobs=%s)" % (exists("done"), mm and mm.groups())
        return fail is None, ("lines=%d" % n) if fail is None else fail
    finally:
        # Stop exactly what this check started: the shell, and (if the job was abandoned) its child and heimdall.
        for x in (child, proto):
            if isinstance(x, int) and proc_state(x) is not None and fail is not None:
                try:
                    os.kill(x, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.close(fd)  # before reaping: a macOS session leader exits only once its pty output can drain
        os.waitpid(pid, 0)
        shutil.rmtree(d, ignore_errors=True)


if os.path.exists("/bin/bash"):
    for form in ("simple", "list"):
        ok, det = k6e_session("/bin/bash", form)
        check("run.k6e_job_control_bash_" + form, ok, det)
else:
    check("run.k6e_job_control_bash", False, "BLOCKED: /bin/bash missing in this environment")
if os.path.exists("/bin/zsh"):
    for form in ("simple", "list"):
        ok, det = k6e_session("/bin/zsh", form)
        print("OBSERVE run.k6e_job_control_zsh_%s (non-gating, not counted): %s %s" % (form, "ok" if ok else "FAIL", det),
              flush=True)

# K6d: heimdall-proto shares the foreground group of a bash -i pipeline job; an explicit kill(<pid>, sig)
# must reach the child at least once (duplicates allowed). Child records signals via a wakeup fd.
K6D_CHILD = r"""
import json, os, signal, sys, time
d = sys.argv[1]
r, w = os.pipe(); os.set_blocking(r, False); os.set_blocking(w, False)
signal.set_wakeup_fd(w, warn_on_full_buffer=False)
for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
    signal.signal(s, lambda n, f: None)
open(os.path.join(d, "ready.part"), "w").write(json.dumps({"ppid": os.getppid(), "pgrp": os.getpgrp()}))
os.replace(os.path.join(d, "ready.part"), os.path.join(d, "ready"))
got = []
end = time.time() + 30
while time.time() < end and not os.path.exists(os.path.join(d, "stop")):
    time.sleep(0.01)
    try:
        got += [signal.Signals(b).name for b in os.read(r, 256)]
        open(os.path.join(d, "signals"), "w").write(" ".join(got))
    except BlockingIOError:
        pass
os._exit(7)
"""


def k6d_pipeline(layout, signame, via="kill"):
    """via="kill": kill(<heimdall-proto pid>, sig) from outside the job (gated, K6d).
    via="tty": the terminal generates SIGINT (^C) for the foreground job (observation only: K6b allows a duplicate)."""
    import pty
    d = tempfile.mkdtemp(prefix="hp-k6d-")
    open(os.path.join(d, "c.py"), "w").write(K6D_CHILD)
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update({"PATH": "/usr/bin:/bin", "HOME": d, "TERM": "xterm", "PS1": "HMPS1$ ", "LANG": "C.UTF-8",
                           "HISTFILE": os.path.join(d, "hist"), "BASH_SILENCE_DEPRECATION_WARNING": "1",
                           "P": BIN, "Y": sys.executable, "D": d})
        os.execv("/bin/bash", ["bash", "--norc", "--noprofile", "-i"])
    buf = bytearray()

    def pump(t):
        end = time.monotonic() + t
        while time.monotonic() < end:
            r, _, _ = select.select([fd], [], [], 0.02)
            if r:
                try:
                    b = os.read(fd, 4096)
                except OSError:
                    return
                if not b:
                    return
                buf.extend(b)
    try:
        pump(0.8)
        if layout == "first":
            cmd = '"$P" run -- "$Y" "$D/c.py" "$D" | cat; echo K6D_DONE'
        elif layout == "alone":
            cmd = '"$P" run -- "$Y" "$D/c.py" "$D"; echo K6D_DONE'
        else:
            cmd = 'while [ ! -e "$D/stop" ]; do sleep 0.05; done | "$P" run -- "$Y" "$D/c.py" "$D"; echo "K6D_DONE ${PIPESTATUS[1]}"'
        os.write(fd, cmd.encode() + b"\r")
        end = time.monotonic() + 10
        while time.monotonic() < end and not os.path.exists(os.path.join(d, "ready")):
            pump(0.02)
        info = json.load(open(os.path.join(d, "ready")))
        fg = os.tcgetpgrp(fd)
        shared = fg == info["pgrp"] and os.getpgid(info["ppid"]) == info["pgrp"]
        pump(0.1)
        if via == "tty":
            os.write(fd, b"\x03")
        else:
            os.kill(info["ppid"], getattr(signal, signame))
        end = time.monotonic() + 3
        while time.monotonic() < end and not (os.path.exists(os.path.join(d, "signals")) and
                                              open(os.path.join(d, "signals")).read()):
            pump(0.02)
        pump(0.3)
        open(os.path.join(d, "stop"), "w").write("1")
        end = time.monotonic() + 5
        while time.monotonic() < end and buf.count(b"K6D_DONE") < 2:  # the echoed command line, then the output
            pump(0.05)
        got = open(os.path.join(d, "signals")).read().split() if os.path.exists(os.path.join(d, "signals")) else []
        return shared, got
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.close(fd)  # before reaping (see k6e_session)
        os.waitpid(pid, 0)
        shutil.rmtree(d, ignore_errors=True)


if os.path.exists("/bin/bash"):
    for layout in ("first", "last"):
        res = {}
        for sn in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGWINCH"):
            res[sn] = k6d_pipeline(layout, sn)
        ok = all(sh and len(g) >= 1 and set(g) == {sn} for sn, (sh, g) in res.items())
        check("run.k6d_pipeline_%s_explicit_signals" % layout, ok,
              " ".join("%s:shared=%s,got=%s" % (sn, sh, ",".join(g) or "-") for sn, (sh, g) in res.items()))
    # Terminal-generated ^C, 3 trials per layout: how often the child sees SIGINT (2 = kernel + forward, K6b).
    for layout in ("first", "alone"):
        counts = [len(k6d_pipeline(layout, "SIGINT", via="tty")[1]) for _ in range(3)]
        print("OBSERVE run.terminal_ctrl_c_deliveries_%s (non-gating, not counted): %s heimdall-proto %s; child SIGINT "
              "deliveries per trial %s" % (layout, sys.platform, "shares the foreground job (modeShared)" if layout == "first"
                                           else "alone in its job (modeExclusive)", counts), flush=True)

# Environment-selected terminfo (TERM traversal to /dev/zero, a FIFO named after TERM, a malformed entry):
# the TUI draws, quits on q with exit 0, stays small and never panics. Round 2: unbounded read, hang, exit 2.
TI_CRASH = b"\x1a\x01 \x000\x9d0\xc40\xf5" + b"0" * 33 + b"\x00" + b"0" * 6
with tempfile.TemporaryDirectory() as d:
    ti = os.path.join(d, "ti", "x")
    os.makedirs(ti)
    open(os.path.join(ti, "xterm-hmcrash"), "wb").write(TI_CRASH)
    os.mkfifo(os.path.join(ti, "xterm-hmfifo"))
    base = {"PATH": "/usr/bin:/bin", "HOME": d, "USER": "hp-test"}  # USER: cgo-less os/user.Current needs it without a passwd entry
    cases = {"traversal_dev_zero": {"TERM": "../" * 12 + "dev/zero"},
             "fifo_terminfo": {"TERM": "xterm-hmfifo", "TERMINFO": os.path.join(d, "ti")},
             "malformed_entry": {"TERM": "xterm-hmcrash", "TERMINFO": os.path.join(d, "ti")}}
    for name, extra in cases.items():
        p, m, s_, before = spawn_pty([BIN, "tui", "--file", os.path.join(FIX, "homelab.toml")], env=dict(base, **extra))
        out, peak = b"", 0
        end = time.monotonic() + 3
        while time.monotonic() < end and b"\x1b[?1049h" not in out and peak < 512 * 1024:
            out += read_for(m, 0.05)
            peak = max(peak, rss_kib(p.pid))  # watchdog: the round-2 binary grows without bound here
        drew = b"\x1b[?1049h" in out
        if drew:
            os.write(m, b"q")
            rc, rest, _ = finish(p, m, s_, before)
            out += rest if isinstance(rest, bytes) else b""
        else:
            p.kill()  # exactly the process this check started
            rc, _, _ = finish(p, m, s_, before)
        check("tui.terminfo_" + name, drew and rc == 0 and b"goroutine " not in out and peak < 256 * 1024,
              "drew=%s exit=%s peak_rss_kib=%d" % (drew, rc, peak))

# K12 closed stdout (slice-contract section 9.4, Q17): stdout is a pipe whose reader closed before the start; the
# wait status is the same with and without --json, for success and error results; error results keep exit 2/5.
# heimdall-proto starts with SIGPIPE at its default (subprocess restore_signals). Round 3b: --json errors died of SIGPIPE.
def closed_stdout_status(argv):
    r, w = os.pipe()
    os.close(r)
    try:
        p = subprocess.run([BIN] + argv, stdout=w, stderr=subprocess.DEVNULL, env=ENV, timeout=20)
    finally:
        os.close(w)
    return ("signal %s" % signal.Signals(-p.returncode).name) if p.returncode < 0 else "exit %d" % p.returncode


d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
k12_cases = [("version", ["version"], None, None),
             ("profile-show-homelab", ["profile", "show", "--file", os.path.join(FIX, "homelab.toml")], None, None),
             ("agent-list-ok", ["agent", "list", "--socket"], "ok", None),
             ("profile-missing", ["profile", "show", "--file", os.path.join(d, "missing.toml")], None, "exit 2"),
             ("profile-schema-invalid", ["profile", "show", "--file", os.path.join(FIX, "invalid-forbidden-key.toml")],
              None, "exit 2"),
             ("agent-unavailable", ["agent", "list", "--socket", os.path.join(d, "none.sock")], None, "exit 5"),
             ("usage-unknown-flag", ["version", "--no-such-flag"], None, "exit 2")]
k12_seen, k12_ok = [], True
for label, argv, agent, want in k12_cases:
    st = {}
    for variant in ("plain", "json"):
        a = list(argv)
        if agent:
            sock = os.path.join(d, "%s-%s.sock" % (label, variant))
            t, _ = fake_agent(sock, frame(ok_body))
            a.append(sock)
        st[variant] = closed_stdout_status(a + (["--json"] if variant == "json" else []))
        if agent:
            t.join(2)
    ok = st["plain"] == st["json"] and (want is None or st["plain"] == want)
    k12_ok = k12_ok and ok
    k12_seen.append("%s:%s/%s" % (label, st["plain"], st["json"]))
check("cli.k12_closed_stdout_parity", k12_ok, "plain/json " + " ".join(k12_seen))

print(f"SUMMARY {sum(results)}/{len(results)} passed", flush=True)
sys.exit(0 if all(results) else 1)
