#!/usr/bin/env python3
"""Reviewer's crafted-frame agent probe (M00-T05-review-go). Stdlib only.

Usage: agent_probe.py <heimdall-proto binary> <out-json>
Runs each case: start a Unix socket server in a private temp dir, run
`heimdall-proto agent list --socket <path> --timeout-ms T --json`, capture the
real exit code/stdout/stderr, the bytes the client sent, and compare with the
expected contract code.
"""
import json, os, socket, struct, subprocess, sys, tempfile, threading, time, hashlib, base64, signal

BIN, OUT = sys.argv[1], sys.argv[2]


def sstr(b):
    return struct.pack(">I", len(b)) + b


def frame(body):
    return struct.pack(">I", len(body)) + body


def blob(kt=b"ssh-ed25519", key=b"\x00" * 32):
    return sstr(kt) + sstr(key)


def answer(keys):
    body = b"\x0c" + struct.pack(">I", len(keys))
    for kb, c in keys:
        body += sstr(kb) + sstr(c)
    return frame(body)


def linger0(conn):
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


# action(conn, rx) -> None. rx: bytes received list.
def send_then_close(data, reset=False, read_first=True, drip=None):
    def act(conn, rx):
        if read_first:
            conn.settimeout(2)
            try:
                rx.append(conn.recv(64))
            except Exception:
                pass
        if drip:
            for i in range(0, len(data), drip[0]):
                conn.sendall(data[i:i + drip[0]])
                time.sleep(drip[1])
        elif data:
            conn.sendall(data)
        if reset:
            linger0(conn)
        conn.close()
    return act


def reset_unread(nbytes):
    # peek, do not consume the request, send nbytes of header, reset
    def act(conn, rx):
        conn.settimeout(2)
        try:
            rx.append(conn.recv(64, socket.MSG_PEEK))
        except Exception:
            pass
        if nbytes:
            conn.sendall(b"\x00" * nbytes)
            time.sleep(0.2)
        linger0(conn)
        conn.close()
    return act


def reset_unread_bytes(data):
    def act(conn, rx):
        conn.settimeout(2)
        try:
            rx.append(conn.recv(64, socket.MSG_PEEK))
        except Exception:
            pass
        conn.sendall(data)
        time.sleep(0.2)
        linger0(conn)
        conn.close()
    return act


def hold(seconds):
    def act(conn, rx):
        conn.settimeout(2)
        try:
            rx.append(conn.recv(64))
        except Exception:
            pass
        time.sleep(seconds)
        conn.close()
    return act


big_comment = b"A" * 200000
k1 = blob()
CASES = [
    # name, action, expected code, timeout ms, extra
    ("ok_one_key", send_then_close(answer([(k1, b"c")])), "AGENT_OK", 3000),
    ("ok_zero_keys", send_then_close(answer([])), "AGENT_OK", 3000),
    ("frame_len_0", send_then_close(struct.pack(">I", 0)), "AGENT_PROTOCOL_ERROR", 3000),
    ("frame_len_ffffffff", send_then_close(struct.pack(">I", 0xFFFFFFFF) + b"\x0c"), "AGENT_PROTOCOL_ERROR", 3000),
    ("frame_len_262144_exact_valid", send_then_close(frame(b"\x0c" + struct.pack(">I", 1) + sstr(k1) + sstr(b"B" * (262144 - 1 - 4 - 4 - len(k1) - 4)))), "AGENT_OK", 5000),
    ("frame_len_262145", send_then_close(frame(b"\x0c" + struct.pack(">I", 1) + sstr(k1) + sstr(b"B" * (262145 - 1 - 4 - 4 - len(k1) - 4)))), "AGENT_PROTOCOL_ERROR", 5000),
    ("nkeys_1024_min", send_then_close(frame(b"\x0c" + struct.pack(">I", 1024) + (sstr(sstr(b"t")) + sstr(b"")) * 1024)), "AGENT_OK", 5000),
    ("nkeys_1025", send_then_close(frame(b"\x0c" + struct.pack(">I", 1025) + (sstr(sstr(b"t")) + sstr(b"")) * 1025)), "AGENT_PROTOCOL_ERROR", 5000),
    ("nkeys_huge_short_frame", send_then_close(frame(b"\x0c" + struct.pack(">I", 0xFFFFFFFF))), "AGENT_PROTOCOL_ERROR", 3000),
    ("blob_len_overrun", send_then_close(frame(b"\x0c" + struct.pack(">I", 1) + struct.pack(">I", 0x7FFFFFFF) + b"xx")), "AGENT_PROTOCOL_ERROR", 3000),
    ("keytype_len_overrun_blob", send_then_close(answer([(struct.pack(">I", 999) + b"ssh", b"c")])), "AGENT_PROTOCOL_ERROR", 3000),
    ("empty_blob", send_then_close(answer([(b"", b"c")])), "AGENT_PROTOCOL_ERROR", 3000),
    ("trailing_1_byte", send_then_close(frame(answer([(k1, b"c")])[4:] + b"\x00")), "AGENT_PROTOCOL_ERROR", 3000),
    ("nkeys_missing", send_then_close(frame(b"\x0c")), "AGENT_PROTOCOL_ERROR", 3000),
    ("nkeys_3_bytes", send_then_close(frame(b"\x0c\x00\x00\x00")), "AGENT_PROTOCOL_ERROR", 3000),
    ("type_6_success", send_then_close(frame(b"\x06")), "AGENT_PROTOCOL_ERROR", 3000),
    ("type_0", send_then_close(frame(b"\x00")), "AGENT_PROTOCOL_ERROR", 3000),
    ("failure_len1", send_then_close(frame(b"\x05")), "AGENT_REFUSED", 3000),
    ("failure_payload", send_then_close(frame(b"\x05\x00")), "AGENT_PROTOCOL_ERROR", 3000),
    ("truncated_header_2", send_then_close(b"\x00\x00"), "AGENT_PROTOCOL_ERROR", 3000),
    ("truncated_body", send_then_close(struct.pack(">I", 100) + b"\x0c\x00"), "AGENT_PROTOCOL_ERROR", 3000),
    ("close_silent", send_then_close(b""), "AGENT_UNAVAILABLE", 3000),
    ("close_without_reading", send_then_close(b"", read_first=False), "AGENT_UNAVAILABLE", 3000),
    ("hold_no_reply_timeout_400", hold(3), "AGENT_UNAVAILABLE", 400),
    ("drip_1byte_per_50ms_total_ok", send_then_close(answer([(k1, b"c")]), drip=(1, 0.01)), "AGENT_OK", 5000),
    ("drip_slow_past_deadline", send_then_close(answer([(k1, b"c")]), drip=(1, 0.1)), "AGENT_UNAVAILABLE", 1000),
    ("reset_before_any_byte", reset_unread(0), "AGENT_UNAVAILABLE", 3000),
    ("reset_after_1_byte", reset_unread(1), "AGENT_PROTOCOL_ERROR", 3000),
    ("reset_after_4_header_bytes", reset_unread(4), "AGENT_PROTOCOL_ERROR", 3000),
    ("reset_after_3_header_bytes", reset_unread_bytes(b"\x00\x00\x00"), "AGENT_PROTOCOL_ERROR", 3000),
    ("reset_mid_body_len100_sent6", reset_unread_bytes(struct.pack(">I", 100) + b"\x0c\x00"), "AGENT_PROTOCOL_ERROR", 3000),
    ("extra_bytes_after_frame", send_then_close(answer([(k1, b"c")]) + b"\x00\x00\x00\x01\x05"), "AGENT_OK", 3000),
    ("bidi_and_zero_width_in_comment", send_then_close(answer([(k1, "x‮evil​ y".encode())])), "AGENT_OK", 3000),
    ("c1_and_esc_in_keytype", send_then_close(answer([(blob(kt=b"ssh-\x1b[31m\xc2\x9b-ed"), b"\x07\x7f")])), "AGENT_OK", 3000),
]


def run_case(name, action, expect, tmo):
    d = tempfile.mkdtemp(prefix="hrg-agent-")
    path = os.path.join(d, "agent sock ü")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)
    rx = []
    conns = []

    def serve():
        srv.settimeout(10)
        try:
            c, _ = srv.accept()
        except Exception:
            return
        conns.append(1)
        try:
            action(c, rx)
        except Exception as e:  # noqa
            rx.append(("server_err", repr(e)))
        # count extra connections
        srv.settimeout(0.3)
        try:
            c2, _ = srv.accept()
            conns.append(2)
            c2.close()
        except Exception:
            pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    env = {"PATH": "/usr/bin:/bin", "HOME": d, "TMPDIR": d, "LANG": "C.UTF-8"}
    t0 = time.monotonic()
    p = subprocess.run([BIN, "agent", "list", "--socket", path, "--timeout-ms", str(tmo), "--json"],
                       capture_output=True, env=env, timeout=30, stdin=subprocess.DEVNULL)
    el = time.monotonic() - t0
    th.join(5)
    srv.close()
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        os.rmdir(d)
        leftover = []
    except OSError:
        leftover = os.listdir(d)
    try:
        doc = json.loads(p.stdout)
        code = doc.get("code")
    except Exception:
        doc, code = None, None
    sent = [x.hex() if isinstance(x, bytes) else x for x in rx]
    out = {
        "case": name, "expected_code": expect, "observed_code": code, "exit_code": p.returncode,
        "elapsed_s": round(el, 3), "client_sent_hex": sent, "connections": len(conns),
        "stdout_len": len(p.stdout), "stderr": p.stderr.decode("utf-8", "replace")[:300],
        "files_left": leftover,
        "match": code == expect,
    }
    if code == "AGENT_OK" and doc:
        ids = doc["data"]["identities"]
        out["n_identities"] = len(ids)
        if ids:
            s = json.dumps(ids[0], ensure_ascii=True)
            out["first_identity_ascii"] = s[:240]
    return out


results = []
only = os.environ.get("ONLY")
for name, act, exp, tmo in CASES:
    if only and name not in only.split(","):
        continue
    r = run_case(name, act, exp, tmo)
    results.append(r)
    print(("OK  " if r["match"] else "MISMATCH ") + f"{name}: exp={exp} got={r['observed_code']} rc={r['exit_code']} {r['elapsed_s']}s sent={r['client_sent_hex']}", flush=True)

json.dump({"bin": BIN, "uname": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()), "results": results}, open(OUT, "w"), indent=1)
bad = [r for r in results if not r["match"]]
print(f"total={len(results)} mismatches={len(bad)}")
sys.exit(1 if bad else 0)
