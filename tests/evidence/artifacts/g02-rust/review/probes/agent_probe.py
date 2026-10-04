#!/usr/bin/env python3
"""Independent crafted-frame probes for heimdall-proto agent list (reviewer-owned, disposable)."""
import json, os, signal, socket, struct, subprocess, sys, threading, time, tempfile, resource

BIN = sys.argv[1]
OUT = sys.argv[2]
results = []


def s(b):
    return struct.pack(">I", len(b)) + b


def key(kt, extra, comment):
    blob = s(kt) + s(extra)
    return s(blob) + s(comment)


def answer(keys, nkeys=None):
    n = len(keys) if nkeys is None else nkeys
    return bytes([12]) + struct.pack(">I", n) + b"".join(keys)


def frame(body):
    return s(body)


class Server:
    def __init__(self, path, behavior):
        self.path = path
        self.behavior = behavior
        self.received = b""
        self.sent = 0
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        self.conns = 0
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        self.conns += 1
        c.settimeout(10)
        try:
            self.behavior(self, c)
        except Exception as e:  # noqa
            self.err = repr(e)
        # drain anything else the client sends until it closes
        try:
            c.settimeout(2)
            while True:
                d = c.recv(65536)
                if not d:
                    break
                self.received += d
        except Exception:
            pass
        try:
            c.close()
        except Exception:
            pass

    def recv_req(self, c):
        d = b""
        while len(d) < 5:
            x = c.recv(5 - len(d))
            if not x:
                break
            d += x
        self.received += d
        return d

    def send(self, c, b):
        c.sendall(b)
        self.sent += len(b)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            os.unlink(self.path)
        except Exception:
            pass


def run_case(name, behavior, timeout_ms=2000, sig_after=None, expect=None, extra_args=()):
    d = tempfile.mkdtemp(prefix="hr agent ü ")
    path = os.path.join(d, "agent sock ü")
    srv = Server(path, behavior)
    env = {"PATH": "/usr/bin:/bin", "HOME": d, "TMPDIR": d}
    argv = [BIN, "agent", "list", "--socket", path, "--timeout-ms", str(timeout_ms), "--json", *extra_args]
    t0 = time.monotonic()
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    sig_t = None
    if sig_after is not None:
        time.sleep(sig_after)
        sig_t = time.monotonic()
        p.send_signal(signal.SIGINT)
    out, err = p.communicate(timeout=30)
    t1 = time.monotonic()
    srv.t.join(5)
    srv.close()
    try:
        doc = json.loads(out)
        code = doc.get("code")
        nids = len(doc.get("data", {}).get("identities", [])) if code == "AGENT_OK" else None
    except Exception:
        doc, code, nids = None, None, None
    r = {
        "case": name,
        "exit_code": p.returncode,
        "code": code,
        "identities": nids,
        "elapsed_ms": round((t1 - t0) * 1000, 1),
        "signal_to_exit_ms": round((t1 - sig_t) * 1000, 1) if sig_t else None,
        "server_received_hex": srv.received.hex(),
        "server_received_len": len(srv.received),
        "stdout_lines": out.count(b"\n"),
        "stderr_tail": err.decode("utf-8", "replace")[-160:],
        "expect": expect,
    }
    if expect:
        ok = (p.returncode, code) == tuple(expect)
        r["verdict"] = "pass" if ok else "fail"
    results.append(r)
    print(json.dumps({k: r[k] for k in ("case", "exit_code", "code", "elapsed_ms", "signal_to_exit_ms", "server_received_len", "verdict") if k in r}))


def reply(body_bytes):
    def b(srv, c):
        srv.recv_req(c)
        srv.send(c, body_bytes)
    return b


# 1. exact max frame filled with a valid answer of many keys padded via a long comment
def max_frame_valid():
    # body length must be exactly 262144: type(1)+nkeys(4)+key
    kt = b"ssh-ed25519"
    blob = s(kt) + s(b"k" * 32)
    fixed = 1 + 4 + 4 + len(blob) + 4
    comment = b"c" * (262144 - fixed)
    body = answer([s(blob) + s(comment)])
    assert len(body) == 262144
    return frame(body)


run_case("frame_exactly_262144_valid", reply(max_frame_valid()), expect=(0, "AGENT_OK"))
run_case("frame_262145_header_only", reply(struct.pack(">I", 262145)), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("frame_len_0xffffffff_then_hold", reply(struct.pack(">I", 0xFFFFFFFF) + b"\x0c"), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("frame_len_zero", reply(struct.pack(">I", 0)), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("nkeys_1025", reply(frame(answer([], nkeys=1025))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("nkeys_0xffffffff", reply(frame(answer([], nkeys=0xFFFFFFFF))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("nkeys_1024_but_one_present", reply(frame(answer([key(b"ssh-ed25519", b"k", b"c")], nkeys=1024))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("comment_len_overrun_by_1", reply(frame(bytes([12]) + struct.pack(">I", 1) + s(s(b"ssh-ed25519") + s(b"k")) + struct.pack(">I", 2) + b"c")), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("keytype_len_overrun_inside_blob", reply(frame(answer([s(struct.pack(">I", 99) + b"ssh") + s(b"c")]))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("blob_without_keytype_3bytes", reply(frame(answer([s(b"abc") + s(b"c")]))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("empty_keytype_ok", reply(frame(answer([s(s(b"")) + s(b"c")]))), expect=(0, "AGENT_OK"))
run_case("trailing_1_byte", reply(frame(answer([key(b"ssh-ed25519", b"k", b"c")]) + b"\x00")), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("bytes_after_complete_frame_ignored", reply(frame(answer([key(b"ssh-ed25519", b"k", b"c")])) + b"\x00\x00\x00\x01\x05"), expect=(0, "AGENT_OK"))
run_case("type_6_success", reply(frame(b"\x06")), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("type_14_sign_response", reply(frame(b"\x0e" + s(b"sig"))), expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("failure_len1", reply(frame(b"\x05")), expect=(5, "AGENT_REFUSED"))
run_case("failure_with_payload", reply(frame(b"\x05\x00")), expect=(5, "AGENT_PROTOCOL_ERROR"))
def closing(f):
    def b(srv, c):
        f(srv, c)
        c.shutdown(socket.SHUT_RDWR)
        c.close()
    return b


run_case("close_without_reading", closing(lambda srv, c: None), timeout_ms=5000, expect=(5, "AGENT_UNAVAILABLE"))
run_case("close_after_request_no_byte", closing(lambda srv, c: srv.recv_req(c)), timeout_ms=5000, expect=(5, "AGENT_UNAVAILABLE"))
run_case("close_after_3_header_bytes", closing(reply(b"\x00\x00\x00")), timeout_ms=5000, expect=(5, "AGENT_PROTOCOL_ERROR"))
run_case("close_mid_body", closing(reply(frame(answer([key(b"ssh-ed25519", b"k", b"c")]))[:-3])), timeout_ms=5000, expect=(5, "AGENT_PROTOCOL_ERROR"))


def slow_drip(srv, c):
    srv.recv_req(c)
    data = frame(answer([key(b"ssh-ed25519", b"k", b"c")]))
    for b in data:
        try:
            srv.send(c, bytes([b]))
        except OSError:
            return
        time.sleep(0.05)


run_case("slow_drip_exceeds_timeout_500", slow_drip, timeout_ms=500, expect=(5, "AGENT_UNAVAILABLE"))


def fragmented_fast(srv, c):
    srv.recv_req(c)
    data = frame(answer([key(b"ssh-ed25519", b"k" * 40, "ü \x1b[31m‮\u0085".encode() + b"\xff")]))
    for i in range(0, len(data), 3):
        srv.send(c, data[i:i + 3])
        time.sleep(0.002)


run_case("fragmented_3byte_chunks_with_controls_bidi", fragmented_fast, timeout_ms=3000, expect=(0, "AGENT_OK"))


def hold(srv, c):
    srv.recv_req(c)
    time.sleep(3)


run_case("sigint_while_waiting_hold", hold, timeout_ms=5000, sig_after=0.3, expect=(130, "CANCELLED"))
run_case("sigint_at_10ms", hold, timeout_ms=5000, sig_after=0.01, expect=(130, "CANCELLED"))
run_case("sigint_at_0ms", hold, timeout_ms=5000, sig_after=0.0, expect=(130, "CANCELLED"))


def never_accept_case():
    d = tempfile.mkdtemp(prefix="hr noaccept ")
    path = os.path.join(d, "s")
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(path)
    ls.listen(1)
    t0 = time.monotonic()
    p = subprocess.run([BIN, "agent", "list", "--socket", path, "--timeout-ms", "400", "--json"], capture_output=True, env={"PATH": "/usr/bin:/bin"})
    el = (time.monotonic() - t0) * 1000
    code = json.loads(p.stdout).get("code") if p.stdout else None
    r = {"case": "listener_never_accepts_timeout_400", "exit_code": p.returncode, "code": code, "elapsed_ms": round(el, 1), "verdict": "pass" if (p.returncode, code) == (5, "AGENT_UNAVAILABLE") and el < 1400 else "fail"}
    results.append(r)
    print(json.dumps(r))
    ls.close()


never_accept_case()


def path_kinds():
    d = tempfile.mkdtemp(prefix="hr kinds ")
    reg = os.path.join(d, "regular")
    open(reg, "w").close()
    fifo = os.path.join(d, "fifo")
    os.mkfifo(fifo)
    for nm, pth in (("regular_file", reg), ("directory", d), ("fifo", fifo), ("missing", os.path.join(d, "nope")), ("too_long_path", os.path.join(d, "x" * 200))):
        t0 = time.monotonic()
        try:
            p = subprocess.run([BIN, "agent", "list", "--socket", pth, "--timeout-ms", "500", "--json"], capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=10)
            code = json.loads(p.stdout).get("code") if p.stdout else None
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc, code = "timeout", None
        r = {"case": "socket_path_" + nm, "exit_code": rc, "code": code, "elapsed_ms": round((time.monotonic() - t0) * 1000, 1), "verdict": "pass" if (rc, code) == (5, "AGENT_UNAVAILABLE") else "fail"}
        results.append(r)
        print(json.dumps(r))


path_kinds()

# repeated SIGINT race sweep
sweep = []
for i in range(30):
    d = tempfile.mkdtemp(prefix="hr sweep ")
    path = os.path.join(d, "s")
    srv = Server(path, hold)
    p = subprocess.Popen([BIN, "agent", "list", "--socket", path, "--timeout-ms", "5000", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin"})
    time.sleep(0.001 * i)
    ts = time.monotonic()
    p.send_signal(signal.SIGINT)
    out, err = p.communicate(timeout=10)
    dt = (time.monotonic() - ts) * 1000
    try:
        code = json.loads(out).get("code")
    except Exception:
        code = None
    sweep.append({"delay_ms": i, "exit_code": p.returncode, "code": code, "sig_to_exit_ms": round(dt, 1), "sent_by_client": srv.received.hex()})
    srv.close()
bad = [x for x in sweep if not (x["exit_code"] == 130 and x["code"] == "CANCELLED" and x["sig_to_exit_ms"] < 500)]
results.append({"case": "sigint_race_sweep_0_29ms", "n": len(sweep), "bad": bad, "max_sig_to_exit_ms": max(x["sig_to_exit_ms"] for x in sweep), "client_bytes_seen": sorted(set(x["sent_by_client"] for x in sweep)), "verdict": "pass" if not bad else "fail"})
print(json.dumps(results[-1]))

passive_bad = [r for r in results if r.get("server_received_hex") not in (None, "", "000000010b")]
results.append({"case": "passivity_only_type11_ever_sent", "bad": [(r["case"], r["server_received_hex"][:40]) for r in passive_bad], "verdict": "pass" if not passive_bad else "fail"})
print(json.dumps(results[-1]))

json.dump(results, open(OUT, "w"), indent=1, ensure_ascii=False)
fails = [r["case"] for r in results if r.get("verdict") == "fail"]
print("FAILS:", fails)
sys.exit(1 if fails else 0)
