#!/usr/bin/python3
"""E7 phase 5 (preliminary G09, A23, R-AU-05): does `ssh -O stop` stop admissions on mux control
connections that the master ACCEPTED BEFORE the stop?  Design: docs/research/g04-managed-credentials.md
section 8.1 row E7 (phase 5, added after the M00-review-g04 refutation of "-O stop: admissions stopped").
Adopted from the reviewer's independent probe tests/evidence/artifacts/review-g04/probe_preconnected_mux.py
and extended to MUX_C_OPEN_FWD (local and remote), MUX_C_NEW_STDIO_FWD, -O exit and exact-PID termination.

A raw mux protocol v4 client (PROTOCOL.mux, openssh-portable mux.c @87f0cd1) connects to the control
socket and exchanges hellos BEFORE `-O stop`, stays idle, and sends its request after `-O stop` returned
rc 0 (socket removed, -O check fails). Source basis: mux_master_process_stop_listening frees only the
listener channel; request handlers do not consult the listener state.

  Phase A (ca1; certificate valid_before = master start + VALID; ControlPersist=10m; sshd TrustedUserCAKeys)
    controls: master authenticated once; raw client opens a session before the stop; fresh login after
              valid_before refused as expired; -O stop rc 0, socket removed, -O check fails; a NEW client
              after stop with PubkeyAuthentication=no is refused.
    H2e   a control connection accepted before the stop is REFUSED a new session 2 s after stop returned
    H2e2  a second one, idle until 15 s after stop (master has no session meanwhile), is REFUSED
    finding H2d-held: the stopped master stays running while an idle pre-accepted control connection is open
    finding H2d-exit: the stopped master exits once its last control connection and session are gone
  Phase B (bastion; fixture key; AllowTcpForwarding yes, PermitOpen hm-m00t03-target:22)
    controls (each on its own control connection, before the stop): MUX_C_OPEN_FWD local 127.0.0.1:P1 ->
              target:22 returns MUX_S_OK and the target's SSH banner is read through P1; MUX_C_OPEN_FWD
              remote 127.0.0.1:0 returns MUX_S_REMOTE_PORT and the port accepts inside the bastion
              container; MUX_C_NEW_STDIO_FWD to target:22 returns MUX_S_SESSION_OPENED and the banner
    H2f   pre-accepted connection: OPEN_FWD local after stop is REFUSED (no MUX_S_OK, or no banner)
    H2g   pre-accepted connection: OPEN_FWD remote after stop is REFUSED (no remote listener)
    H2h   pre-accepted connection: NEW_STDIO_FWD after stop is REFUSED
    finding H3d: SIGTERM to the exact master PID closes a remaining pre-accepted control connection and the
              local forward listener it created after the stop
  Phase C (bastion, second master)
    finding H3c: `-O exit` closes a control connection accepted before it (a later request fails)
Hypotheses H2e..H2h state the property a deadline control needs ("-O stop refuses every later
admission"); REFUTED means the master admitted the request. They are the verdict criterion.

Safety: SSH_AUTH_SOCK removed; /usr/bin/ssh* by absolute path; -F generated config (IdentitiesOnly,
IdentityAgent = dedicated temp agent or none, StrictHostKeyChecking yes, fixture known_hosts, loopback
fixture ports); forwards bind 127.0.0.1 only; the generated private key is deleted after ssh-add;
processes are signalled only by exact PID after re-checking PID + start time + executable; logs are
redacted and carry only exit codes, counts, fixed markers and SSH banners.
Output: tests/evidence/artifacts/g04/experiments/<G04_RUN_STAMP>/e7-mux-preconnected.{log,results.tsv}
(same CHECK/OBS/FACT/CLEANUP/EXIT rows as lib.sh). Exit: 0 every CHECK held; 1 a CHECK failed; 3 setup
failure or interruption. Knobs: G04_E7P_VALID (40 s), G04_E7P_DELAY1 (2 s), G04_E7P_DELAY2 (15 s).
"""
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

EXP = "e7-mux-preconnected"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FX = os.path.join(REPO, "tests", "fixtures", "ssh", "runtime")
SSH, KEYGEN, AGENT, ADD = "/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/ssh-agent", "/usr/bin/ssh-add"
CPREFIX = "hm-m00t03"
TARGET = CPREFIX + "-target"
STAMP = os.environ.get("G04_RUN_STAMP") or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
OUT_DIR = os.path.join(REPO, "tests", "evidence", "artifacts", "g04", "experiments", STAMP)
VALID = int(os.environ.get("G04_E7P_VALID", "40"))
DELAY1 = float(os.environ.get("G04_E7P_DELAY1", "2"))
DELAY2 = float(os.environ.get("G04_E7P_DELAY2", "15"))
BASE_ENV = {k: v for k, v in os.environ.items()
            if k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
HOME = os.path.expanduser("~")
RUN_ID = "%s-%d" % (time.strftime("%H%M%S", time.gmtime()), os.getpid())

MUX_MSG_HELLO, MUX_C_NEW_SESSION, MUX_C_OPEN_FWD, MUX_C_CLOSE_FWD, MUX_C_NEW_STDIO_FWD = 0x1, 0x10000002, 0x10000006, 0x10000007, 0x10000008
NAMES = {0x80000001: "MUX_S_OK", 0x80000002: "MUX_S_PERMISSION_DENIED", 0x80000003: "MUX_S_FAILURE",
         0x80000004: "MUX_S_EXIT_MESSAGE", 0x80000006: "MUX_S_SESSION_OPENED", 0x80000007: "MUX_S_REMOTE_PORT"}
FWD_LOCAL, FWD_REMOTE = 1, 2

os.makedirs(OUT_DIR, exist_ok=True)
LOGF = open(os.path.join(OUT_DIR, EXP + ".log"), "w")
RESF = open(os.path.join(OUT_DIR, EXP + ".results.tsv"), "w")
os.umask(0o077)
T = tempfile.mkdtemp(prefix="hmg04-e7p.")
os.chmod(T, 0o700)
RT = os.path.realpath(T)
CHECKS = FAILS = 0
AGENTS, MASTERS, CONNS = [], [], []


class SetupFailure(Exception):
    pass


def ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def red(s):
    s = str(s)
    for a, b in (("/private" + RT, "<tmp>"), (RT, "<tmp>"), (T, "<tmp>"), (FX, "<fixture-runtime>"), (REPO, "<repo>"), (HOME, "<home>")):
        s = s.replace(a, b)
    return s


def oneline(s):
    return " ".join(str(s).replace("\t", " ").split())


def log(msg):
    line = "[%s] %s" % (ts(), red(msg))
    print(line, flush=True)
    LOGF.write(line + "\n")
    LOGF.flush()


def row(*fields):
    RESF.write(red("\t".join(fields)) + "\n")
    RESF.flush()


def fact(name, val):
    row("FACT", name, oneline(val))
    log("FACT %s = %s" % (name, val))


def check(name, expected, observed, ok):
    global CHECKS, FAILS
    CHECKS += 1
    st = "PASS" if ok else "FAIL"
    FAILS += 0 if ok else 1
    row("CHECK", name, oneline(expected), oneline(observed), st)
    log("%s %s | expected: %s | observed: %s" % (st, name, expected, observed))
    return ok


def obs(name, hyp, observed, confirmed):
    st = "CONFIRMED" if confirmed else "REFUTED"
    row("OBS", name, oneline(hyp), oneline(observed), st)
    log("%s %s | hypothesis: %s | observed: %s" % (st, name, hyp, observed))


def run(label, argv, env_extra=None, timeout=60):
    e = dict(BASE_ENV, **(env_extra or {}))
    t0 = time.time()
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=e, timeout=timeout)
        rc, out = p.returncode, p.stdout.decode(errors="replace").strip()
    except subprocess.TimeoutExpired:
        rc, out = 124, "TIMEOUT after %d s" % timeout
    t1 = time.time()
    body = "".join("\n    | " + l for l in red(out).splitlines()) if out else ""
    LOGF.write("[%s] $ (%s) %s%s\n    rc=%d t_start=%.3f t_end=%.3f\n" % (ts(), label, red(" ".join(argv)), body, rc, t0, t1))
    LOGF.flush()
    print("[%s] %s -> rc=%d" % (ts(), label, rc), flush=True)
    return rc, red(out), t0, t1


# ------------------------------------------------------------------ process identity (exact PID only)
def ps_field(pid, field):
    p = subprocess.run(["ps", "-o", field + "=", "-p", str(pid)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return " ".join(p.stdout.decode(errors="replace").split())


def is_agent(c):
    return c.endswith("/ssh-agent") or c == "ssh-agent"


def is_ssh(c):
    return c in ("/usr/bin/ssh", "ssh") or c.startswith("ssh: ")


def alive_same(pid, lst, comm_ok):
    return pid is not None and bool(lst) and ps_field(pid, "lstart") == lst and comm_ok(ps_field(pid, "comm"))


def kill_exact(pid, lst, comm_ok):
    if pid is None:
        return "not_started"
    if not ps_field(pid, "lstart"):
        return "already_exited"
    if not alive_same(pid, lst, comm_ok):
        return "identity_mismatch_not_signalled"
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if not alive_same(pid, lst, comm_ok):
            return "terminated"
        time.sleep(0.1)
    return "still_running"


# ------------------------------------------------------------------ fixture access
def srv_lines(role):
    p = subprocess.run(["docker", "logs", "%s-%s" % (CPREFIX, role)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode(errors="replace").splitlines()


def mark(role):
    return len(srv_lines(role))


def count_new(role, m, *pats):
    return sum(1 for l in srv_lines(role)[m:] if all(p in l for p in pats))


def log_new(role, m, label):
    lines = [l for l in srv_lines(role)[m:] if "kex_exchange_identification" not in l]
    LOGF.write("[%s] server log %s-%s (%s), new lines:\n" % (ts(), CPREFIX, role, label) + "".join("    > %s\n" % red(l) for l in lines))
    LOGF.flush()


def clock_offset(role):
    h0 = time.time()
    p = subprocess.run(["docker", "exec", "%s-%s" % (CPREFIX, role), "date", "-u", "+%s.%N"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    h1 = time.time()
    try:
        c = float(p.stdout.decode().strip())
        return "offset_s=%.3f rtt_s=%.3f" % (c - (h0 + h1) / 2, h1 - h0)
    except ValueError:
        return "not measured"


def write_cfg(path, role, port, user, agent, identity, extra=()):
    lines = ["# generated by tests/native/g04/e7_mux_preconnected.py (run %s); disposable" % RUN_ID,
             "Host g-%s" % role, "  HostName 127.0.0.1", "  Port %s" % port, "  User %s" % user, "  HostKeyAlias hm-%s" % role,
             "Host *"] + ["  " + x for x in extra] + [
             '  UserKnownHostsFile "%s"' % os.path.join(FX, "known_hosts"), "  GlobalKnownHostsFile /dev/null",
             "  StrictHostKeyChecking yes", "  CheckHostIP no", "  UpdateHostKeys no", "  VerifyHostKeyDNS no",
             ("  IdentityAgent none" if agent is None else '  IdentityAgent "%s"' % agent),
             '  IdentityFile "%s"' % identity, "  IdentitiesOnly yes", "  ControlMaster no", "  ControlPath none",
             "  PreferredAuthentications publickey", "  PasswordAuthentication no", "  KbdInteractiveAuthentication no",
             "  BatchMode yes", "  ForwardAgent no", "  ForwardX11 no", "  ConnectTimeout 10", "  LogLevel ERROR"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def start_master(cfg, cm, host):
    rc, out, _, _ = run("start master " + os.path.basename(cm), [SSH, "-F", cfg, "-o", "ControlMaster=yes", "-o", "ControlPath=" + cm,
                                                                "-o", "ControlPersist=10m", "-N", "-f", host])
    rc2, out2, _, _ = run("-O check " + os.path.basename(cm), [SSH, "-F", cfg, "-S", cm, "-O", "check", host])
    if rc != 0 or "pid=" not in out2:
        return None, None
    pid = int(out2.split("pid=")[1].split(")")[0])
    lst = ps_field(pid, "lstart")
    if not (lst and is_ssh(ps_field(pid, "comm"))):
        log("master pid %s not identifiable as ssh; not tracked" % pid)
        return None, None
    MASTERS.append((pid, lst))
    log("master started: pid=%s lstart='%s' comm='%s' controlpath=%s" % (pid, lst, ps_field(pid, "comm"), cm))
    return pid, lst


def stop(cfg, cm, host, pid, lst):
    rc, out, _, t1 = run("ssh -O stop " + os.path.basename(cm), [SSH, "-F", cfg, "-S", cm, "-O", "stop", host])
    time.sleep(0.5)
    rcc, outc, _, _ = run("-O check after stop", [SSH, "-F", cfg, "-S", cm, "-O", "check", host])
    sock = "present" if os.path.exists(cm) else "removed"
    alive = alive_same(pid, lst, is_ssh)
    return rc, out, t1, rcc, sock, alive


# ------------------------------------------------------------------ raw mux protocol v4 client
def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("control connection closed by master")
        b += c
    return b


def recv_msg(s):
    (n,) = struct.unpack(">I", recv_exact(s, 4))
    return recv_exact(s, n)


def send_msg(s, payload):
    s.sendall(struct.pack(">I", len(payload)) + payload)


def sstr(b):
    return struct.pack(">I", len(b)) + b


def mux_connect(path, label):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect(path)
    m = recv_msg(s)
    typ, ver = struct.unpack(">II", m[:8])
    if typ != MUX_MSG_HELLO:
        raise SetupFailure("unexpected first mux message 0x%08x" % typ)
    send_msg(s, struct.pack(">II", MUX_MSG_HELLO, ver))
    CONNS.append(s)
    log("raw control connection '%s': hello exchanged (mux protocol %d), idle" % (label, ver))
    return s, ver


def reply_desc(r):
    typ = struct.unpack(">I", r[:4])[0]
    name = NAMES.get(typ, "0x%08x" % typ)
    extra = ""
    if typ in (0x80000002, 0x80000003) and len(r) > 12:
        extra = " reason=" + r[12:].decode(errors="replace")
    if typ == 0x80000007 and len(r) >= 12:
        extra = " port=%d" % struct.unpack(">I", r[8:12])[0]
    return typ, name + extra


def mux_session(s, rid, cmd, outpath):
    """MUX_C_NEW_SESSION on an existing control connection -> (reply, exit value, stdout)."""
    payload = struct.pack(">II", MUX_C_NEW_SESSION, rid) + sstr(b"") + struct.pack(">IIIII", 0, 0, 0, 0, 0xffffffff) + sstr(b"") + sstr(cmd.encode())
    send_msg(s, payload)
    fds = [os.open("/dev/null", os.O_RDONLY), os.open(outpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
           os.open(outpath + ".err", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)]
    try:
        for fd in fds:
            socket.send_fds(s, [b"\0"], [fd])
    finally:
        for fd in fds:
            os.close(fd)
    typ, desc = reply_desc(recv_msg(s))
    if typ != 0x80000006:
        return desc, None, ""
    exitval = None
    while True:
        r = recv_msg(s)
        if struct.unpack(">I", r[:4])[0] == 0x80000004:
            exitval = struct.unpack(">I", r[8:12])[0]
            break
    time.sleep(0.2)
    with open(outpath, "rb") as f:
        out = f.read().decode(errors="replace").strip()
    return desc, exitval, out


def fwd_payload(code, rid, ftype, lhost, lport, chost, cport):
    return struct.pack(">III", code, rid, ftype) + sstr(lhost.encode()) + struct.pack(">I", lport) + sstr(chost.encode()) + struct.pack(">I", cport)


def mux_fwd(s, rid, ftype, lhost, lport, chost, cport, close=False):
    send_msg(s, fwd_payload(MUX_C_CLOSE_FWD if close else MUX_C_OPEN_FWD, rid, ftype, lhost, lport, chost, cport))
    return reply_desc(recv_msg(s))


def mux_stdio_fwd(s, rid, chost, cport):
    """MUX_C_NEW_STDIO_FWD; stdin and stdout are one end of a socketpair -> (reply, banner)."""
    send_msg(s, struct.pack(">II", MUX_C_NEW_STDIO_FWD, rid) + sstr(b"") + sstr(chost.encode()) + struct.pack(">I", cport))
    a, b = socket.socketpair()
    try:
        socket.send_fds(s, [b"\0"], [b.fileno()])
        socket.send_fds(s, [b"\0"], [b.fileno()])
    finally:
        b.close()
    typ, desc = reply_desc(recv_msg(s))
    banner = ""
    if typ == 0x80000006:
        banner = read_banner(a)
    a.close()
    return desc, banner


def read_banner(sock):
    sock.settimeout(10)
    buf = b""
    try:
        while b"\n" not in buf and len(buf) < 256:
            c = sock.recv(256)
            if not c:
                break
            buf += c
    except OSError as ex:
        return "<%s>" % type(ex).__name__
    return buf.split(b"\n")[0].decode(errors="replace").strip()


def banner_via_port(port):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=10)
    except OSError as ex:
        return "<connect failed: %s>" % type(ex).__name__
    try:
        return read_banner(c)
    finally:
        c.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def remote_listener_accepts(port):
    p = subprocess.run(["docker", "exec", CPREFIX + "-bastion", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/%d && echo OPEN" % port],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    return p.returncode == 0 and b"OPEN" in p.stdout


def attempt(fn):
    """Run one mux request on a pre-accepted connection; exceptions mean the master refused/closed."""
    t = time.time()
    try:
        return t, fn(), None
    except Exception as ex:  # closed connection, reset, timeout
        return t, None, "%s: %s" % (type(ex).__name__, ex)


def wait_until(epoch):
    d = epoch - time.time()
    if d > 0:
        log("waiting %.1f s" % d)
        time.sleep(d)


def on_signal(signum, _frame):
    raise KeyboardInterrupt("signal %d" % signum)


for _s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_s, on_signal)

rc_final = 3
log("BEGIN %s run_stamp=%s run_id=%s" % (EXP, STAMP, RUN_ID))
try:
    for need in ("ports.env", "known_hosts", "keys/user_ca", "keys/user_bastion"):
        if not os.path.exists(os.path.join(FX, need)):
            raise SetupFailure("fixture runtime missing %s; run tests/fixtures/ssh/up.sh" % need)
    ports = dict(l.strip().split("=", 1) for l in open(os.path.join(FX, "ports.env")) if "=" in l)
    for r in ("ca1", "bastion", "target"):
        p = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", "%s-%s" % (CPREFIX, r)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if p.stdout.decode().strip() != "true":
            raise SetupFailure("fixture container %s-%s not running" % (CPREFIX, r))
    fact("host_ssh", subprocess.run([SSH, "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().strip())
    fact("container_sshd", subprocess.run(["docker", "exec", CPREFIX + "-ca1", "dpkg-query", "-W", "-f=${Package} ${Version}", "openssh-server"],
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().strip())
    fact("docker_server", subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().strip())
    fact("ssh_auth_sock_in_harness", "unset" if "SSH_AUTH_SOCK" not in os.environ else "set in the parent environment; removed from every child environment")
    fact("clock_ca1", clock_offset("ca1"))
    fact("delays_s", "request 1 at stop+%.0f s, request 2 at stop+%.0f s; certificate validity %d s" % (DELAY1, DELAY2, VALID))

    # dedicated agent + disposable key/certificate (private file deleted after ssh-add)
    ad = os.path.join(T, "agent")
    os.mkdir(ad, 0o700)
    sock = os.path.join(ad, "agent.sock")
    a = subprocess.run([AGENT, "-U", "-a", sock, "-s"], env=dict(BASE_ENV, HOME=ad), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    apid = None
    for part in a.stdout.decode().split(";"):
        part = part.strip()
        if part.startswith("SSH_AGENT_PID="):
            apid = int(part.split("=", 1)[1])
    alst = ps_field(apid, "lstart") if apid else ""
    if not (apid and alst and is_agent(ps_field(apid, "comm")) and os.path.exists(sock)):
        raise SetupFailure("dedicated ssh-agent not verified")
    AGENTS.append((apid, alst, sock))
    log("dedicated ssh-agent started: pid=%s lstart='%s' socket=%s" % (apid, alst, sock))
    key = os.path.join(T, "k")
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "g04-e7p-k-" + RUN_ID, "-f", key], check=True, env=BASE_ENV)
    now = int(time.time())
    vb = now + VALID
    cid = "g04-e7p-" + RUN_ID
    subprocess.run([KEYGEN, "-q", "-s", os.path.join(FX, "keys", "user_ca"), "-I", cid, "-n", "p-host1", "-V", "0x%x:0x%x" % (now - 60, vb), key + ".pub"],
                   check=True, env=BASE_ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fact("cert_valid_before_epoch", vb)
    rc, _, _, _ = run("ssh-add -t 1800 k", [ADD, "-t", "1800", key], {"SSH_AUTH_SOCK": sock})
    os.unlink(key)
    if rc != 0 or os.path.exists(key):
        raise SetupFailure("ssh-add failed or private key file not deleted")
    cfg1 = os.path.join(T, "cfg-ca1")
    write_cfg(cfg1, "ca1", ports["PORT_ca1"], "cert", sock, key + ".pub", ['CertificateFile "%s"' % (key + "-cert.pub")])
    cfgb = os.path.join(T, "cfg-bastion")
    write_cfg(cfgb, "bastion", ports["PORT_bastion"], "jump", None, os.path.join(FX, "keys", "user_bastion"))

    # ================= Phase A: ca1, certificate expiry, MUX_C_NEW_SESSION
    cm = os.path.join(T, "cmA")
    m = mark("ca1")
    mpid, mlst = start_master(cfg1, cm, "g-ca1")
    time.sleep(0.3)
    macc = count_new("ca1", m, "Accepted publickey", "ID %s " % cid)
    check("E7P-A-master-authenticated", "ca1 master started; exactly 1 Accepted line with the short-lived cert ID", "master_pid=%s accepted=%d" % (mpid, macc), bool(mpid) and macc == 1)
    if not mpid:
        raise SetupFailure("phase A master did not start")
    s0, ver = mux_connect(cm, "A-control")
    m1 = mark("ca1")
    d0, ev0, out0 = mux_session(s0, 1, "echo G04-E7P-RAW-BEFORE-STOP", os.path.join(T, "o0"))
    s0.close()
    time.sleep(0.3)
    check("E7P-A-raw-client-session-before-stop", "the raw mux client opens a session through the master before the stop (so a refusal later is meaningful)",
          "reply=%s exit=%s stdout=[%s] new_accepted=%d new_connections=%d mux_protocol=%d" % (d0, ev0, out0, count_new("ca1", m1, "Accepted publickey"), count_new("ca1", m1, "Connection from"), ver),
          d0 == "MUX_S_SESSION_OPENED" and ev0 == 0 and out0 == "G04-E7P-RAW-BEFORE-STOP")
    c1, _ = mux_connect(cm, "A-C1 (request at stop+%.0fs)" % DELAY1)
    c2, _ = mux_connect(cm, "A-C2 (request at stop+%.0fs)" % DELAY2)
    wait_until(vb + 5)
    m2 = mark("ca1")
    rcf, _, _, _ = run("fresh login after valid_before", [SSH, "-F", cfg1, "g-ca1", "true"])
    time.sleep(0.3)
    expl = count_new("ca1", m2, "Certificate invalid: expired")
    log_new("ca1", m2, "fresh login after valid_before")
    check("E7P-A-fresh-login-rejected-after-expiry", "rc 255; sshd logs 'Certificate invalid: expired'", "rc=%d expired_lines=%d" % (rcf, expl), rcf == 255 and expl >= 1)
    src, sout, st1, rcc, sk, alive = stop(cfg1, cm, "g-ca1", mpid, mlst)
    fact("A_stop", "rc=%d out=[%s] check_rc_after=%d control_socket=%s master_running_after_stop=%s master_ps_comm=[%s]" % (src, sout, rcc, sk, alive, red(ps_field(mpid, "comm"))))
    check("E7P-A-stop-effective", "-O stop rc 0; control socket removed; -O check fails", "stop_rc=%d socket=%s check_rc=%d" % (src, sk, rcc), src == 0 and sk == "removed" and rcc != 0)
    rch, _, _, _ = run("new client after stop (old ControlPath, PubkeyAuthentication=no)", [SSH, "-F", cfg1, "-o", "ControlMaster=no", "-o", "ControlPath=" + cm, "-o", "PubkeyAuthentication=no", "g-ca1", "echo NEW-CLIENT-ADMITTED"])
    check("E7P-A-new-client-after-stop-refused", "a client that connects after the stop (and cannot authenticate) is refused, rc 255", "rc=%d" % rch, rch == 255)

    wait_until(st1 + DELAY1)
    m4 = mark("ca1")
    t_req, res, err = attempt(lambda: mux_session(c1, 7, "echo G04-E7P-PRECONNECTED-SESSION-1; id -un", os.path.join(T, "o1")))
    time.sleep(0.5)
    d1, ev1, out1 = res if res else (None, None, "")
    adm1 = d1 == "MUX_S_SESSION_OPENED" and "G04-E7P-PRECONNECTED-SESSION-1" in out1
    obs("H2e-preconnected-session-refused-after-stop",
        "a control connection accepted before -O stop is refused a new session after stop returned (ca1, certificate expired)",
        "request_s_after_stop_returned=%.3f s_after_valid_before=%.1f reply=%s exit=%s stdout=[%s] error=%s new_connections=%d new_accepted=%d"
        % (t_req - st1, t_req - vb, d1, ev1, out1.replace("\n", " | "), err, count_new("ca1", m4, "Connection from"), count_new("ca1", m4, "Accepted publickey")),
        not adm1)
    try:
        c1.close()
    except OSError:
        pass
    last_activity = time.time()
    # master with no session and only the idle pre-accepted connection C2
    samples = []
    while time.time() < st1 + DELAY2 - 0.5:
        samples.append(alive_same(mpid, mlst, is_ssh))
        time.sleep(1)
    held = bool(samples) and all(samples)
    obs("H2d-held-stopped-master-kept-alive-by-idle-control-connection",
        "after -O stop, with no session and no new connection, the master keeps running while an idle pre-accepted control connection is open",
        "master_running_in_all_%d_samples_over_%.0f_s_after_last_session=%s" % (len(samples), time.time() - last_activity, held), held)
    m5 = mark("ca1")
    t_req2, res2, err2 = attempt(lambda: mux_session(c2, 8, "echo G04-E7P-PRECONNECTED-SESSION-2; id -un", os.path.join(T, "o2")))
    time.sleep(0.5)
    d2, ev2, out2 = res2 if res2 else (None, None, "")
    adm2 = d2 == "MUX_S_SESSION_OPENED" and "G04-E7P-PRECONNECTED-SESSION-2" in out2
    obs("H2e2-preconnected-session-refused-late",
        "a control connection accepted before -O stop and idle for %.0f s is refused a new session" % DELAY2,
        "request_s_after_stop_returned=%.3f s_after_valid_before=%.1f reply=%s exit=%s stdout=[%s] error=%s new_connections=%d new_accepted=%d"
        % (t_req2 - st1, t_req2 - vb, d2, ev2, out2.replace("\n", " | "), err2, count_new("ca1", m5, "Connection from"), count_new("ca1", m5, "Accepted publickey")),
        not adm2)
    try:
        c2.close()
    except OSError:
        pass
    i = 0
    while i < 20 and alive_same(mpid, mlst, is_ssh):
        time.sleep(0.25)
        i += 1
    gone = not alive_same(mpid, mlst, is_ssh)
    obs("H2d-exit-stopped-master-exits-when-last-control-connection-closes",
        "the stopped master exits once its last pre-accepted control connection and session are gone (despite ControlPersist=10m)",
        ("exited within %.2f s of the last control connection closing" % ((i + 1) * 0.25)) if gone else "still running 5 s after the last control connection closed", gone)

    # ================= Phase B: bastion, MUX_C_OPEN_FWD (local, remote) and MUX_C_NEW_STDIO_FWD
    cmb = os.path.join(T, "cmB")
    mb = mark("bastion")
    bpid, blst = start_master(cfgb, cmb, "g-bastion")
    time.sleep(0.3)
    bacc = count_new("bastion", mb, "Accepted publickey")
    check("E7P-B-master-authenticated", "bastion master started; exactly 1 Accepted line", "master_pid=%s accepted=%d" % (bpid, bacc), bool(bpid) and bacc == 1)
    if not bpid:
        raise SetupFailure("phase B master did not start")
    k0, _ = mux_connect(cmb, "B-control")
    p1 = free_port()
    dl0 = mux_fwd(k0, 11, FWD_LOCAL, "127.0.0.1", p1, TARGET, 22)[1]
    bn0 = banner_via_port(p1) if dl0 == "MUX_S_OK" else ""
    cl0 = mux_fwd(k0, 12, FWD_LOCAL, "127.0.0.1", p1, TARGET, 22, close=True)[1]
    check("E7P-B-local-fwd-before-stop", "before the stop, MUX_C_OPEN_FWD local 127.0.0.1:P -> target:22 returns MUX_S_OK and the target's SSH banner is read through P",
          "reply=%s banner=[%s] close_fwd_reply=%s" % (dl0, bn0, cl0), dl0 == "MUX_S_OK" and bn0.startswith("SSH-2.0-"))
    dr0 = mux_fwd(k0, 13, FWD_REMOTE, "127.0.0.1", 0, "127.0.0.1", 9)[1]
    rp0 = int(dr0.split("port=")[1]) if "port=" in dr0 else 0
    acc0 = remote_listener_accepts(rp0) if rp0 else False
    cr0 = mux_fwd(k0, 14, FWD_REMOTE, "127.0.0.1", 0, "127.0.0.1", 9, close=True)[1]
    check("E7P-B-remote-fwd-before-stop", "before the stop, MUX_C_OPEN_FWD remote 127.0.0.1:0 returns MUX_S_REMOTE_PORT and that port accepts inside the bastion container",
          "reply=%s remote_listener_accepts=%s close_fwd_reply=%s" % (dr0, acc0, cr0), dr0.startswith("MUX_S_REMOTE_PORT") and acc0)
    k0.close()
    w0, _ = mux_connect(cmb, "B-control-stdio")
    dw0, bw0 = mux_stdio_fwd(w0, 15, TARGET, 22)
    w0.close()
    check("E7P-B-stdio-fwd-before-stop", "before the stop, MUX_C_NEW_STDIO_FWD to target:22 returns MUX_S_SESSION_OPENED and the target's SSH banner",
          "reply=%s banner=[%s]" % (dw0, bw0), dw0 == "MUX_S_SESSION_OPENED" and bw0.startswith("SSH-2.0-"))
    cL, _ = mux_connect(cmb, "B-CL (local forward after stop)")
    cR, _ = mux_connect(cmb, "B-CR (remote forward after stop)")
    cW, _ = mux_connect(cmb, "B-CW (stdio forward after stop)")
    cK, _ = mux_connect(cmb, "B-CK (held until exact-PID termination)")
    time.sleep(1)
    bsrc, bsout, bst1, brcc, bsk, balive = stop(cfgb, cmb, "g-bastion", bpid, blst)
    fact("B_stop", "rc=%d out=[%s] check_rc_after=%d control_socket=%s master_running_after_stop=%s master_ps_comm=[%s]" % (bsrc, bsout, brcc, bsk, balive, red(ps_field(bpid, "comm"))))
    check("E7P-B-stop-effective", "-O stop rc 0; control socket removed; -O check fails", "stop_rc=%d socket=%s check_rc=%d" % (bsrc, bsk, brcc), bsrc == 0 and bsk == "removed" and brcc != 0)
    wait_until(bst1 + DELAY1)
    mb2 = mark("bastion")
    p2 = free_port()
    tL, rL, eL = attempt(lambda: mux_fwd(cL, 21, FWD_LOCAL, "127.0.0.1", p2, TARGET, 22)[1])
    bnL = banner_via_port(p2) if rL == "MUX_S_OK" else ""
    admL = rL == "MUX_S_OK" and bnL.startswith("SSH-2.0-")
    obs("H2f-preconnected-local-fwd-refused-after-stop",
        "a control connection accepted before -O stop is refused MUX_C_OPEN_FWD (local) after stop returned",
        "request_s_after_stop_returned=%.3f reply=%s error=%s banner_through_new_listener=[%s]" % (tL - bst1, rL, eL, bnL), not admL)
    tR, rR, eR = attempt(lambda: mux_fwd(cR, 22, FWD_REMOTE, "127.0.0.1", 0, "127.0.0.1", 10)[1])
    rpR = int(rR.split("port=")[1]) if rR and "port=" in rR else 0
    accR = remote_listener_accepts(rpR) if rpR else False
    obs("H2g-preconnected-remote-fwd-refused-after-stop",
        "a control connection accepted before -O stop is refused MUX_C_OPEN_FWD (remote) after stop returned",
        "request_s_after_stop_returned=%.3f reply=%s error=%s remote_listener_accepts=%s" % (tR - bst1, rR, eR, accR), not (rR and rR.startswith("MUX_S_REMOTE_PORT") and accR))
    tW, rW, eW = attempt(lambda: mux_stdio_fwd(cW, 23, TARGET, 22))
    dW, bW = rW if rW else (None, "")
    obs("H2h-preconnected-stdio-fwd-refused-after-stop",
        "a control connection accepted before -O stop is refused MUX_C_NEW_STDIO_FWD after stop returned",
        "request_s_after_stop_returned=%.3f reply=%s error=%s banner=[%s]" % (tW - bst1, dW, eW, bW), not (dW == "MUX_S_SESSION_OPENED" and bW.startswith("SSH-2.0-")))
    time.sleep(0.3)
    fact("B_after_stop_server_lines", "bastion new_connections=%d new_accepted=%d since the after-stop requests began" % (count_new("bastion", mb2, "Connection from"), count_new("bastion", mb2, "Accepted publickey")))
    log_new("bastion", mb2, "after-stop requests")
    for c in (cL, cR, cW):
        try:
            c.close()
        except OSError:
            pass
    time.sleep(1)
    bal = alive_same(bpid, blst, is_ssh)
    kres = kill_exact(bpid, blst, is_ssh)
    time.sleep(0.5)
    tK, rK, eK = attempt(lambda: mux_session(cK, 31, "echo G04-E7P-AFTER-KILL", os.path.join(T, "oK")))
    bnK = banner_via_port(p2)
    closedK = rK is None and eK is not None
    obs("H3d-exact-pid-termination-closes-preconnected-connection-and-forward",
        "SIGTERM to the exact stopped-master PID closes a remaining pre-accepted control connection and the local forward listener created after the stop",
        "master_running_before_kill=%s kill=%s later_request_reply=%s error=%s local_forward_port_after_kill=[%s]" % (bal, kres, rK[0] if rK else None, eK, bnK),
        closedK and not bnK.startswith("SSH-2.0-"))

    # ================= Phase C: -O exit with a pre-accepted connection
    cmc = os.path.join(T, "cmC")
    cpid, clst = start_master(cfgb, cmc, "g-bastion")
    if not cpid:
        raise SetupFailure("phase C master did not start")
    cX, _ = mux_connect(cmc, "C-CX (request after -O exit)")
    rce, oute, _, et1 = run("ssh -O exit cmC", [SSH, "-F", cfgb, "-S", cmc, "-O", "exit", "g-bastion"])
    time.sleep(1)
    calive = alive_same(cpid, clst, is_ssh)
    tX, rX, eX = attempt(lambda: mux_session(cX, 41, "echo G04-E7P-AFTER-EXIT", os.path.join(T, "oX")))
    admX = rX is not None and rX[0] == "MUX_S_SESSION_OPENED"
    obs("H3c-exit-closes-preconnected-control-connection",
        "-O exit terminates the master, and a control connection accepted before it can no longer obtain a session",
        "exit_rc=%d out=[%s] master_running_1s_after=%s request_s_after_exit_returned=%.3f reply=%s error=%s socket=%s"
        % (rce, oute, calive, tX - et1, rX[0] if rX else None, eX, "present" if os.path.exists(cmc) else "removed"),
        rce == 0 and not calive and not admX)
    rc_final = 0 if FAILS == 0 else 1
except SetupFailure as ex:
    log("SETUP FAILURE: %s" % ex)
    row("SETUP_FAILURE", oneline(ex))
    rc_final = 3
except KeyboardInterrupt as ex:
    log("interrupted (%s)" % ex)
    row("SETUP_FAILURE", "interrupted")
    rc_final = 3
except Exception as ex:  # unexpected harness error: incomplete evidence
    log("HARNESS ERROR: %r" % (ex,))
    row("SETUP_FAILURE", oneline("harness error %r" % (ex,)))
    rc_final = 3
finally:
    for _s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(_s, signal.SIG_IGN)
    for c in CONNS:
        try:
            c.close()
        except OSError:
            pass
    for pid, lst in MASTERS:
        out = kill_exact(pid, lst, is_ssh)
        out = "not_running" if out == "already_exited" else out
        row("CLEANUP", "master pid=%s" % pid, out)
    for pid, lst, sk in AGENTS:
        out = kill_exact(pid, lst, is_agent)
        out += " socket_still_present" if os.path.exists(sk) else " socket_removed"
        row("CLEANUP", "agent pid=%s" % pid, out)
        log("cleanup agent pid=%s: %s" % (pid, out))
    shutil.rmtree(T, ignore_errors=True)
    row("CLEANUP", "tempdir", "still_present" if os.path.exists(T) else "removed")
    row("EXIT", str(rc_final), "checks=%d" % CHECKS, "fails=%d" % FAILS)
    log("END %s exit=%d checks=%d fails=%d" % (EXP, rc_final, CHECKS, FAILS))
    LOGF.close()
    RESF.close()
sys.exit(rc_final)
