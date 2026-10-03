#!/usr/bin/python3
"""review-g04 adversarial probe (independent of tests/native/g04): does `ssh -O stop` stop
admissions on mux control connections that were ACCEPTED BEFORE the stop?

Source basis (openssh-portable mux.c @87f0cd1, re-fetched by this review):
mux_master_process_stop_listening frees only the listener channel; mux_master_process_new_session
does not consult the listener state.

  HP1  A control connection opened (hello exchanged) before `-O stop`, idle until after `-O stop`
       returned rc 0, can still request a new session; the master opens it over the existing
       authenticated connection (no new TCP connection, no new Accepted line), after the
       certificate that authenticated the master has expired.
  HC1  (control, = harness H2b2) a client started after `-O stop` with the old ControlPath and no
       usable credential is not admitted.
  HC2  (control) before the stop, the same raw client can open a session (proves the raw mux
       client works, so a refusal in HP1 would be meaningful).

Safety: SSH_AUTH_SOCK removed; /usr/bin/ssh* by absolute path; -F generated config (IdentitiesOnly,
IdentityAgent = dedicated temp agent, StrictHostKeyChecking yes, fixture known_hosts, loopback
fixture port); private key deleted after ssh-add; processes are signalled only by exact PID after
re-checking PID + start time + executable; only exit codes, counts and fixed markers are logged.
Writes only to its temp dir and OUTDIR. Usage: probe_preconnected_mux.py <repo_root> <outdir>
Exit: 0 probe ran to completion (HP1 may be confirmed or refuted), 3 setup failure.
"""
import json, os, shutil, socket, struct, subprocess, sys, tempfile, time

REPO, OUTDIR = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
FX = os.path.join(REPO, "tests/fixtures/ssh/runtime")
SSH, KEYGEN, AGENT, ADD = "/usr/bin/ssh", "/usr/bin/ssh-keygen", "/usr/bin/ssh-agent", "/usr/bin/ssh-add"
BASE_ENV = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
os.makedirs(OUTDIR, exist_ok=True)
LOGF = open(os.path.join(OUTDIR, "probe_preconnected_mux.log"), "w")
T = tempfile.mkdtemp(prefix="hmrev-g04-")
os.chmod(T, 0o700)
RT = os.path.realpath(T)
HOME = os.path.expanduser("~")
RES = {"probe": "review-g04 pre-connected mux control client vs -O stop", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "steps": [], "hypotheses": {}, "cleanup": {}}

MUX_MSG_HELLO, MUX_C_NEW_SESSION = 0x00000001, 0x10000002
MUX_S_EXIT_MESSAGE, MUX_S_SESSION_OPENED = 0x80000004, 0x80000006
MUX_S_FAILURE, MUX_S_PERMISSION_DENIED = 0x80000003, 0x80000002


def now_s():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def red(s):
    for a, b in ((RT, "<tmp>"), (T, "<tmp>"), (FX, "<fixture-runtime>"), (REPO, "<repo>"), (HOME, "<home>")):
        s = s.replace(a, b)
    return s


def log(msg):
    line = "[%s] %s" % (now_s(), red(msg))
    print(line, flush=True)
    LOGF.write(line + "\n"); LOGF.flush()


def run(label, argv, extra_env=None):
    e = dict(BASE_ENV, **(extra_env or {}))
    t0 = time.time()
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=e)
    out = p.stdout.decode(errors="replace").strip()
    log("$ (%s) %s\n    | %s\n    rc=%d t_start=%.3f t_end=%.3f" % (label, " ".join(argv), out.replace("\n", "\n    | "), p.returncode, t0, time.time()))
    RES["steps"].append({"label": label, "rc": p.returncode, "output": red(out)[:300], "t_start": round(t0, 3), "t_end": round(time.time(), 3)})
    return p.returncode, out


def ps_field(pid, field):
    p = subprocess.run(["ps", "-o", field + "=", "-p", str(pid)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return " ".join(p.stdout.decode().split())


def alive_same(pid, lst, comm_ok):
    return pid is not None and ps_field(pid, "lstart") == lst and comm_ok(ps_field(pid, "comm"))


def is_agent(c):
    return c.endswith("/ssh-agent") or c == "ssh-agent"


def is_ssh(c):
    return c in ("/usr/bin/ssh", "ssh") or c.startswith("ssh: ")


def kill_exact(pid, lst, comm_ok):
    if pid is None:
        return "not_started"
    if not ps_field(pid, "lstart"):
        return "already_exited"
    if not alive_same(pid, lst, comm_ok):
        return "identity_mismatch_not_signalled"
    os.kill(pid, 15)
    for _ in range(50):
        if not alive_same(pid, lst, comm_ok):
            return "terminated"
        time.sleep(0.1)
    return "still_running"


def srv_lines():
    p = subprocess.run(["docker", "logs", "hm-m00t03-ca1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode(errors="replace").splitlines()


def count_new(mark, *pats):
    return sum(1 for l in srv_lines()[mark:] if all(p in l for p in pats))


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


def mux_connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect(path)
    m = recv_msg(s)
    typ, ver = struct.unpack(">II", m[:8])
    assert typ == MUX_MSG_HELLO, "unexpected first message 0x%08x" % typ
    send_msg(s, struct.pack(">II", MUX_MSG_HELLO, ver))
    return s, ver


def mux_session(s, rid, cmd, outpath):
    """Request a new session on an existing control connection; return (reply_type, exit_value, stdout)."""
    payload = struct.pack(">II", MUX_C_NEW_SESSION, rid) + sstr(b"") + struct.pack(">IIIII", 0, 0, 0, 0, 0xffffffff) + sstr(b"") + sstr(cmd.encode())
    send_msg(s, payload)
    fin = os.open("/dev/null", os.O_RDONLY)
    fout = os.open(outpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    ferr = os.open(outpath + ".err", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        for fd in (fin, fout, ferr):
            socket.send_fds(s, [b"\0"], [fd])
    finally:
        for fd in (fin, fout, ferr):
            os.close(fd)
    r = recv_msg(s)
    typ, rrid = struct.unpack(">II", r[:8])
    if typ != MUX_S_SESSION_OPENED:
        msg = r[12:].decode(errors="replace") if len(r) > 12 else ""
        return ("0x%08x" % typ, None, msg)
    exitval = None
    while True:
        r = recv_msg(s)
        t = struct.unpack(">I", r[:4])[0]
        if t == MUX_S_EXIT_MESSAGE:
            exitval = struct.unpack(">I", r[8:12])[0]
            break
    time.sleep(0.2)
    with open(outpath, "rb") as f:
        out = f.read().decode(errors="replace").strip()
    return ("MUX_S_SESSION_OPENED", exitval, out)


agent_pid = agent_lst = master_pid = master_lst = None
pre = None
rc_final = 3
try:
    ports = dict(l.strip().split("=", 1) for l in open(os.path.join(FX, "ports.env")) if "=" in l)
    port = ports["PORT_ca1"]
    sock = os.path.join(T, "agent.sock")
    a = subprocess.run([AGENT, "-U", "-a", sock, "-s"], env=dict(BASE_ENV, HOME=T), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for part in a.stdout.decode().split(";"):
        part = part.strip()
        if part.startswith("SSH_AGENT_PID="):
            agent_pid = int(part.split("=", 1)[1])
    agent_lst = ps_field(agent_pid, "lstart")
    if not (agent_lst and is_agent(ps_field(agent_pid, "comm")) and os.path.exists(sock)):
        raise RuntimeError("dedicated agent not verified")
    log("dedicated agent pid=%s lstart='%s' comm='%s' socket=%s" % (agent_pid, agent_lst, ps_field(agent_pid, "comm"), sock))
    key = os.path.join(T, "k")
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "review-g04-preconn", "-f", key], check=True, env=BASE_ENV)
    now = int(time.time()); vb = now + 40
    cid = "review-g04-preconn-%d" % now
    subprocess.run([KEYGEN, "-q", "-s", os.path.join(FX, "keys/user_ca"), "-I", cid, "-n", "p-host1", "-V", "0x%x:0x%x" % (now - 60, vb), key + ".pub"],
                   check=True, env=BASE_ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    RES["cert_id"] = cid; RES["valid_before_epoch"] = vb
    rc, _ = run("ssh-add key (+cert) -t 600", [ADD, "-t", "600", key], {"SSH_AUTH_SOCK": sock})
    os.unlink(key)
    if rc != 0 or os.path.exists(key):
        raise RuntimeError("ssh-add failed or key not deleted")
    cfg = os.path.join(T, "cfg")
    with open(cfg, "w") as f:
        f.write("Host g-ca1\n  HostName 127.0.0.1\n  Port %s\n  User cert\n  HostKeyAlias hm-ca1\nHost *\n"
                "  UserKnownHostsFile \"%s\"\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  CheckHostIP no\n  UpdateHostKeys no\n"
                "  IdentityAgent \"%s\"\n  IdentityFile \"%s\"\n  CertificateFile \"%s\"\n  IdentitiesOnly yes\n  ControlMaster no\n  ControlPath none\n"
                "  PreferredAuthentications publickey\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  BatchMode yes\n"
                "  ForwardAgent no\n  ForwardX11 no\n  ConnectTimeout 10\n  LogLevel ERROR\n"
                % (port, os.path.join(FX, "known_hosts"), sock, key + ".pub", key + "-cert.pub"))
    os.chmod(cfg, 0o600)
    cm = os.path.join(T, "cm")

    m0 = len(srv_lines())
    rc, _ = run("start master (ControlPersist=10m)", [SSH, "-F", cfg, "-o", "ControlMaster=yes", "-o", "ControlPath=" + cm, "-o", "ControlPersist=10m", "-N", "-f", "g-ca1"])
    rc2, out = run("-O check", [SSH, "-F", cfg, "-S", cm, "-O", "check", "g-ca1"])
    if rc != 0 or "pid=" not in out:
        raise RuntimeError("master did not start")
    master_pid = int(out.split("pid=")[1].split(")")[0])
    master_lst = ps_field(master_pid, "lstart")
    if not (master_lst and is_ssh(ps_field(master_pid, "comm"))):
        raise RuntimeError("master identity not verified")
    time.sleep(0.3)
    macc = count_new(m0, "Accepted publickey", "ID %s " % cid)
    log("master pid=%s lstart='%s' accepted_lines_with_id=%d" % (master_pid, master_lst, macc))

    # HC2: raw client works before the stop (on its own control connection)
    s0, ver = mux_connect(cm)
    m1 = len(srv_lines())
    typ0, ev0, out0 = mux_session(s0, 1, "echo REVIEW-RAW-MUX-BEFORE-STOP", os.path.join(T, "o0"))
    s0.close()
    time.sleep(0.3)
    hc2 = typ0 == "MUX_S_SESSION_OPENED" and ev0 == 0 and out0 == "REVIEW-RAW-MUX-BEFORE-STOP"
    RES["hypotheses"]["HC2-raw-mux-client-works-before-stop"] = {"confirmed": hc2, "observed": "reply=%s exit=%s out=%s new_accepted=%d new_connections=%d mux_version=%d" % (typ0, ev0, out0, count_new(m1, "Accepted publickey"), count_new(m1, "Connection from"), ver)}
    log("HC2 %s" % RES["hypotheses"]["HC2-raw-mux-client-works-before-stop"])

    # pre-connect an idle control client BEFORE the stop
    pre, _ = mux_connect(cm)
    log("pre-connected control client: hello exchanged, idle")

    # wait for certificate expiry
    while time.time() < vb + 5:
        time.sleep(0.5)
    m2 = len(srv_lines())
    rcf, _ = run("fresh login after valid_before (control)", [SSH, "-F", cfg, "g-ca1", "true"])
    time.sleep(0.3)
    exp_lines = count_new(m2, "Certificate invalid: expired")
    RES["fresh_login_after_expiry"] = {"rc": rcf, "expired_lines": exp_lines}

    rcs, outs = run("-O stop", [SSH, "-F", cfg, "-S", cm, "-O", "stop", "g-ca1"])
    stop_t1 = time.time()
    time.sleep(0.5)
    rcc, _ = run("-O check after stop", [SSH, "-F", cfg, "-S", cm, "-O", "check", "g-ca1"])
    RES["stop"] = {"rc": rcs, "check_rc_after": rcc, "socket_after": "present" if os.path.exists(cm) else "removed",
                   "master_running_after": alive_same(master_pid, master_lst, is_ssh), "master_comm_after": ps_field(master_pid, "comm")}
    log("stop: %s" % RES["stop"])

    # HC1: a new client after stop with no usable credential
    m3 = len(srv_lines())
    rch, _ = run("HC1 new client after stop, PubkeyAuthentication=no", [SSH, "-F", cfg, "-o", "ControlMaster=no", "-o", "ControlPath=" + cm, "-o", "PubkeyAuthentication=no", "g-ca1", "echo HC1-ADMITTED"])
    RES["hypotheses"]["HC1-new-client-after-stop-not-admitted"] = {"confirmed": rch == 255, "observed": "rc=%d" % rch}

    # HP1: the pre-connected client requests a session 2 s after stop returned
    delay = float(os.environ.get("HP1_DELAY", "2"))  # seconds between stop returning and the request
    RES["hp1_delay_s"] = delay
    time.sleep(max(0, stop_t1 + delay - time.time()))
    m4 = len(srv_lines())
    req_t = time.time()
    try:
        typ, ev, outp = mux_session(pre, 7, "echo REVIEW-PRECONNECTED-ADMITTED-AFTER-STOP; id -un", os.path.join(T, "o1"))
        err = None
    except Exception as ex:  # master closed the connection or refused
        typ, ev, outp, err = None, None, "", repr(ex)
    time.sleep(0.5)
    new_acc = count_new(m4, "Accepted publickey"); new_con = count_new(m4, "Connection from")
    admitted = typ == "MUX_S_SESSION_OPENED" and "REVIEW-PRECONNECTED-ADMITTED-AFTER-STOP" in outp
    RES["hypotheses"]["HP1-preconnected-client-admitted-after-stop"] = {
        "confirmed": admitted,
        "observed": "request_sent_s_after_stop_returned=%.3f reply=%s exit=%s stdout=[%s] error=%s new_accepted=%d new_connections=%d cert_valid_before_minus_request_s=%.1f"
                    % (req_t - stop_t1, typ, ev, outp.replace("\n", " | "), err, new_acc, new_con, vb - req_t)}
    log("HP1 %s" % RES["hypotheses"]["HP1-preconnected-client-admitted-after-stop"])
    RES["master_running_after_hp1"] = alive_same(master_pid, master_lst, is_ssh)
    try:
        pre.close()
    except Exception:
        pass
    pre = None
    time.sleep(1.0)
    RES["master_running_1s_after_preconnected_client_closed"] = alive_same(master_pid, master_lst, is_ssh)
    rc_final = 0
except Exception as ex:
    log("SETUP/RUN FAILURE: %r" % (ex,))
    RES["failure"] = red(repr(ex))
    rc_final = 3
finally:
    if pre is not None:
        try:
            pre.close()
        except Exception:
            pass
    RES["cleanup"]["master"] = kill_exact(master_pid, master_lst, is_ssh) if master_pid else "not_started"
    RES["cleanup"]["agent"] = kill_exact(agent_pid, agent_lst, is_agent) if agent_pid else "not_started"
    shutil.rmtree(T, ignore_errors=True)
    RES["cleanup"]["tempdir"] = "still_present" if os.path.exists(T) else "removed"
    RES["exit"] = rc_final
    RES["finished_at"] = now_s()
    log("cleanup %s exit=%d" % (RES["cleanup"], rc_final))
    with open(os.path.join(OUTDIR, "probe_preconnected_mux.result.json"), "w") as f:
        json.dump(RES, f, indent=2)
    sys.exit(rc_final)
