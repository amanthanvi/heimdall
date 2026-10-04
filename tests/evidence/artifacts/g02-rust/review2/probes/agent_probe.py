#!/usr/bin/env python3
"""Reviewer-2 crafted-frame agent probe (independent of tests/fixtures/fake-agent).

Usage: agent_probe.py BIN OUT.json
For each case a disposable Unix socket server in a temp dir (path with space and non-ASCII)
sends crafted bytes; we record exit code, JSON code, and every byte the client sent.
"""
import hashlib, base64, json, os, signal, socket, struct, subprocess, sys, tempfile, threading, time

BIN = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]
TMP = tempfile.mkdtemp(prefix="hp-rv2-agent ü ")
results = []


def s(b):
    return struct.pack(">I", len(b)) + b


def frame(body):
    return struct.pack(">I", len(body)) + body


def key(kt, comment, extra=b"\x07" * 32):
    blob = s(kt) + s(extra)
    return s(blob) + s(comment), blob


def answer(keys, nkeys=None):
    b = bytes([12]) + struct.pack(">I", len(keys) if nkeys is None else nkeys)
    for k in keys:
        b += k
    return b


class Server:
    def __init__(self, name, behaviour):
        self.path = os.path.join(TMP, name + " sock é")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.bind(self.path)
        except OSError:
            self.path = os.path.join(tempfile.mkdtemp(prefix="hpa"), "s")
            self.sock.bind(self.path)
        self.sock.listen(4)
        self.received = b""
        self.behaviour = behaviour
        self.conns = 0
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        self.conns += 1
        try:
            self.behaviour(c, self)
        except Exception as e:  # noqa
            pass
        # drain whatever else the client sends until it closes
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

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def read_req(c, srv):
    data = b""
    c.settimeout(3)
    while len(data) < 5:
        d = c.recv(5 - len(data))
        if not d:
            break
        data += d
    srv.received += data
    return data


def send_after_req(payload, close=True, linger_rst=False, drip=None):
    def b(c, srv):
        read_req(c, srv)
        if drip:
            for ch in payload:
                c.sendall(bytes([ch]))
                time.sleep(drip)
        else:
            c.sendall(payload)
        if linger_rst:
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        if close:
            c.shutdown(socket.SHUT_WR)
    return b


def no_read_then(payload):
    # never reads the request; writes payload; closes with unread data (Linux: ECONNRESET to peer)
    def b(c, srv):
        time.sleep(0.2)
        if payload:
            c.sendall(payload)
        time.sleep(0.05)
        c.close()
    return b


def hang(c, srv):
    read_req(c, srv)
    time.sleep(4)


def run_case(name, behaviour, expect_exit, expect_code, timeout_ms=1500, extra=None, check=None):
    srv = Server(name, behaviour)
    t0 = time.time()
    p = subprocess.run([BIN, "agent", "list", "--socket", srv.path, "--timeout-ms", str(timeout_ms), "--json"],
                       capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    el = round((time.time() - t0) * 1000)
    srv.t.join(timeout=5)
    srv.close()
    try:
        j = json.loads(p.stdout)
        code = j.get("code")
    except Exception:
        j, code = None, None
    ok = (p.returncode == expect_exit and code == expect_code)
    extra_obs = check(j) if (check and j) else None
    if extra_obs is not None and extra_obs is not True:
        ok = False
    r = {"case": name, "exit": p.returncode, "code": code, "expect": [expect_exit, expect_code],
         "ok": ok, "elapsed_ms": el, "client_sent_hex": srv.received.hex(), "client_sent_ok": srv.received in (b"\x00\x00\x00\x01\x0b", b""),
         "stdout_lines": p.stdout.count(b"\n"), "check": extra_obs}
    results.append(r)
    print(json.dumps(r), flush=True)
    return j


k1, blob1 = key(b"ssh-ed25519", b"plain comment")
fp1 = "SHA256:" + base64.b64encode(hashlib.sha256(blob1).digest()).decode().rstrip("=")
run_case("valid_one", send_after_req(frame(answer([k1]))), 0, "AGENT_OK",
         check=lambda j: j["data"]["identities"] == [{"key_type": "ssh-ed25519", "fingerprint": fp1, "comment": "plain comment"}] or j["data"])
run_case("valid_zero", send_after_req(frame(answer([]))), 0, "AGENT_OK")
ctrl = b"a\x00b\tc\x1b[31md\x7fe\xc2\x85f\xc2\x9bg\xff\xfeh\xe2\x80\xaei"
kc, _ = key(b"ssh-\x1bed\xc2\x80", ctrl)
def chk_ctrl(j):
    i = j["data"]["identities"][0]
    bad = [c for c in i["comment"] + i["key_type"] if ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f]
    return True if not bad else "control chars remain: %r" % bad
run_case("k1_controls_replaced", send_after_req(frame(answer([kc]))), 0, "AGENT_OK", check=chk_ctrl)
run_case("len_262145", send_after_req(struct.pack(">I", 262145) + b"\x0c"), 5, "AGENT_PROTOCOL_ERROR")
run_case("len_ffffffff", send_after_req(b"\xff\xff\xff\xff"), 5, "AGENT_PROTOCOL_ERROR")
# exactly 262144 byte frame, valid: one key with a large comment
big_c = 262144 - 1 - 4 - 4 - 4 - (4 + 11 + 4 + 32)
kb, _ = key(b"ssh-ed25519", b"c" * big_c)
body = answer([kb])
run_case("len_262144_valid", send_after_req(frame(body)), 0, "AGENT_OK", timeout_ms=3000,
         check=lambda j: True if len(body) == 262144 else "body len %d" % len(body))
run_case("nkeys_1025", send_after_req(frame(answer([], nkeys=1025))), 5, "AGENT_PROTOCOL_ERROR")
run_case("nkeys_ffffffff", send_after_req(frame(answer([], nkeys=0xFFFFFFFF))), 5, "AGENT_PROTOCOL_ERROR")
k_empty = s(b"") + s(b"c")
run_case("nkeys_1024_ok", send_after_req(frame(answer([key(b"t", b"", b"")[0]] * 1024))), 0, "AGENT_OK",
         check=lambda j: True if len(j["data"]["identities"]) == 1024 else len(j["data"]["identities"]))
run_case("blob_len_overrun", send_after_req(frame(bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", 0xFFFFFF00) + b"x")), 5, "AGENT_PROTOCOL_ERROR")
run_case("empty_blob", send_after_req(frame(answer([k_empty]))), 5, "AGENT_PROTOCOL_ERROR")
inner_over = s(struct.pack(">I", 99) + b"ab") + s(b"c")
run_case("keytype_overrun_in_blob", send_after_req(frame(answer([inner_over]))), 5, "AGENT_PROTOCOL_ERROR")
run_case("trailing_bytes", send_after_req(frame(answer([k1]) + b"\x00")), 5, "AGENT_PROTOCOL_ERROR")
run_case("nkeys_more_than_present", send_after_req(frame(answer([k1], nkeys=2))), 5, "AGENT_PROTOCOL_ERROR")
run_case("failure_len1", send_after_req(frame(b"\x05")), 5, "AGENT_REFUSED")
run_case("failure_with_payload", send_after_req(frame(b"\x05\x00")), 5, "AGENT_PROTOCOL_ERROR")
run_case("success_type6", send_after_req(frame(b"\x06")), 5, "AGENT_PROTOCOL_ERROR")
run_case("type_13_sign_response", send_after_req(frame(b"\x0e" + s(b"sig"))), 5, "AGENT_PROTOCOL_ERROR")
run_case("zero_length_frame", send_after_req(b"\x00\x00\x00\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("eof_no_bytes", send_after_req(b""), 5, "AGENT_UNAVAILABLE")
run_case("eof_after_2_header_bytes", send_after_req(b"\x00\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("eof_after_header", send_after_req(b"\x00\x00\x00\x10"), 5, "AGENT_PROTOCOL_ERROR")
run_case("eof_partial_body", send_after_req(b"\x00\x00\x00\x10\x0c\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("rst_after_req_no_bytes", send_after_req(b"", linger_rst=True), 5, "AGENT_UNAVAILABLE")
run_case("noread_close_0_bytes", no_read_then(b""), 5, "AGENT_UNAVAILABLE")
run_case("noread_close_1_byte", no_read_then(b"\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("noread_close_3_bytes", no_read_then(b"\x00\x00\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("noread_close_full_header_partial", no_read_then(b"\x00\x00\x00\x09\x0c\x00"), 5, "AGENT_PROTOCOL_ERROR")
run_case("noread_full_valid_frame_then_close", no_read_then(frame(answer([k1]))), 0, "AGENT_OK")
run_case("drip_valid_within_timeout", send_after_req(frame(answer([])), drip=0.05), 0, "AGENT_OK", timeout_ms=3000)
run_case("drip_exceeds_timeout", send_after_req(frame(answer([k1])), drip=0.05), 5, "AGENT_UNAVAILABLE", timeout_ms=700)
run_case("hang_timeout", hang, 5, "AGENT_UNAVAILABLE", timeout_ms=500)
run_case("second_frame_after_first_ignored", send_after_req(frame(answer([])) + frame(b"\x05"), close=False), 0, "AGENT_OK")

# non-socket paths
for nm, mk in (("regular_file", lambda p: open(p, "w").write("x")), ("directory", os.mkdir), ("fifo", os.mkfifo), ("missing", lambda p: None)):
    pth = os.path.join(TMP, "np-" + nm)
    mk(pth)
    t0 = time.time()
    p = subprocess.run([BIN, "agent", "list", "--socket", pth, "--timeout-ms", "800", "--json"], capture_output=True, timeout=10)
    try:
        code = json.loads(p.stdout)["code"]
    except Exception:
        code = None
    r = {"case": "path_" + nm, "exit": p.returncode, "code": code, "elapsed_ms": round((time.time() - t0) * 1000),
         "ok": p.returncode == 5 and code == "AGENT_UNAVAILABLE"}
    results.append(r); print(json.dumps(r), flush=True)

# SIGINT while waiting: CANCELLED within 500 ms, connection closed (server sees EOF)
for delay in (0.3,):
    srv = Server("sigint", hang)
    p = subprocess.Popen([BIN, "agent", "list", "--socket", srv.path, "--timeout-ms", "5000", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(delay)
    t0 = time.time()
    p.send_signal(signal.SIGINT)
    o, e = p.communicate(timeout=5)
    el = round((time.time() - t0) * 1000)
    try:
        code = json.loads(o)["code"]
    except Exception:
        code = None
    srv.t.join(timeout=6); srv.close()
    r = {"case": "sigint_while_waiting", "exit": p.returncode, "code": code, "signal_to_exit_ms": el,
         "ok": p.returncode == 130 and code == "CANCELLED" and el < 500, "client_sent_hex": srv.received.hex()}
    results.append(r); print(json.dumps(r), flush=True)

# SIGINT arriving during connect to a socket whose backlog is full (Linux connect blocks)
json.dump({"bin": BIN, "platform": sys.platform, "results": results,
           "all_ok": all(r["ok"] for r in results)}, open(OUT, "w"), indent=1)
print("ALL_OK", all(r["ok"] for r in results))
