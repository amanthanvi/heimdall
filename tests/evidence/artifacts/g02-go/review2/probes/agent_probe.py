# Crafted SSH-agent frames against heimdall-proto agent list (reviewer-built server).
import json, os, signal, socket, struct, subprocess, sys, tempfile, threading, time, hashlib, base64, platform
P = sys.argv[1]
def s(b): return struct.pack(">I", len(b)) + b
def frame(body): return struct.pack(">I", len(body)) + body
def blob(kt=b"ssh-ed25519", extra=b"\x00" * 36): return s(kt) + s(extra)
def answer(keys, trailing=b""):
    body = bytes([12]) + struct.pack(">I", len(keys))
    for b, c in keys: body += s(b) + s(c)
    return frame(body + trailing)
def fp(b): return "SHA256:" + base64.b64encode(hashlib.sha256(b).digest()).decode().rstrip("=")
B = blob()
cases = []
def case(name, actions, want_code, want_exit, extra=None, timeout_ms=1500, sigint_after=None):
    cases.append(dict(name=name, actions=actions, want_code=want_code, want_exit=want_exit, extra=extra or {}, timeout_ms=timeout_ms, sigint_after=sigint_after))
# exact bounds
pad = 262144 - (1 + 4 + 4 + len(B) + 4)
case("frame_len_exactly_262144_ok", [("send", answer([(B, b"c" * pad)]))], "AGENT_OK", 0)
case("frame_len_262145", [("send", answer([(B, b"c" * (pad + 1))]))], "AGENT_PROTOCOL_ERROR", 5)
case("frame_len_0xffffffff_header_only", [("send", b"\xff\xff\xff\xff")], "AGENT_PROTOCOL_ERROR", 5)
case("nkeys_1024_ok", [("send", answer([(B, b"")] * 1024))], "AGENT_OK", 0, {"count": 1024})
case("nkeys_1025", [("send", answer([(B, b"")] * 1025))], "AGENT_PROTOCOL_ERROR", 5)
case("nkeys_huge_small_frame", [("send", frame(bytes([12]) + b"\xff\xff\xff\xff"))], "AGENT_PROTOCOL_ERROR", 5)
case("blob_len_past_end", [("send", frame(bytes([12]) + struct.pack(">I", 1) + struct.pack(">I", 1000) + b"abc"))], "AGENT_PROTOCOL_ERROR", 5)
case("comment_len_past_end", [("send", frame(bytes([12]) + struct.pack(">I", 1) + s(B) + struct.pack(">I", 99)))], "AGENT_PROTOCOL_ERROR", 5)
case("keytype_len_past_blob", [("send", answer([(struct.pack(">I", 50) + b"ssh", b"")]))], "AGENT_PROTOCOL_ERROR", 5)
case("empty_blob", [("send", answer([(b"", b"x")]))], "AGENT_PROTOCOL_ERROR", 5, {"note": "contract: key_type is the first SSH string inside key_blob; an empty blob has none (reviewer expectation, not stated verbatim)"})
case("trailing_after_last_key", [("send", answer([(B, b"c")], trailing=b"\x00"))], "AGENT_PROTOCOL_ERROR", 5)
case("type6_success", [("send", frame(b"\x06"))], "AGENT_PROTOCOL_ERROR", 5)
case("type5_len1_refused", [("send", frame(b"\x05"))], "AGENT_REFUSED", 5)
case("type5_with_payload_K4", [("send", frame(b"\x05\x00"))], "AGENT_PROTOCOL_ERROR", 5)
case("zero_length_frame", [("send", b"\x00\x00\x00\x00")], "AGENT_PROTOCOL_ERROR", 5)
case("eof_before_any_byte_K3", [("close",)], "AGENT_UNAVAILABLE", 5)
case("eof_after_2_header_bytes_K3", [("send", b"\x00\x00"), ("close",)], "AGENT_PROTOCOL_ERROR", 5)
case("eof_mid_body_K3", [("send", answer([(B, b"comment")])[:20]), ("close",)], "AGENT_PROTOCOL_ERROR", 5)
case("reset_before_any_byte_K3a", [("reset",)], "AGENT_UNAVAILABLE", 5)
case("reset_after_1_byte_K3a", [("send", b"\x00"), ("sleep", 0.05), ("reset",)], "AGENT_PROTOCOL_ERROR", 5)
case("reset_mid_body_K3a", [("send", answer([(B, b"comment")])[:20]), ("sleep", 0.05), ("reset",)], "AGENT_PROTOCOL_ERROR", 5)
case("slow_drip_valid_within_timeout", [("drip", answer([(B, b"slow")]), 0.004)], "AGENT_OK", 0, timeout_ms=3000)
case("slow_drip_exceeds_timeout", [("drip", answer([(B, b"x" * 400)]), 0.01)], "AGENT_UNAVAILABLE", 5, timeout_ms=800)
case("silent_until_timeout", [("sleep", 3.0)], "AGENT_UNAVAILABLE", 5, timeout_ms=500)
case("sigint_while_waiting", [("sleep", 3.0)], "CANCELLED", 130, timeout_ms=5000, sigint_after=0.3)
case("sigint_after_partial_header", [("send", b"\x00\x00"), ("sleep", 3.0)], "CANCELLED", 130, timeout_ms=5000, sigint_after=0.3)
ctl = "".join(chr(c) for c in list(range(0, 0x20)) + list(range(0x7f, 0xa0))).encode("utf-8")
case("controls_and_invalid_utf8_K1", [("send", answer([(blob(b"ssh-\x1b[31mrsa\x7f"), ctl + b"\xff\xfe" + "‮evil​".encode()) ]))], "AGENT_OK", 0, {"k1": True})
case("valid_then_extra_bytes_after_frame", [("send", answer([(B, b"ok")]) + b"GARBAGE")], "AGENT_OK", 0, {"note": "bytes after one complete frame are outside the frame; reviewer records behavior"})
case("response_before_request_read", [("send_first", answer([(B, b"early")]))], "AGENT_OK", 0)

def server(path, c, rec, ready):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path); srv.listen(1); ready.set()
    srv.settimeout(10)
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        rec["accepted"] = False; return
    rec["accepted"] = True
    conn.settimeout(2)
    first = [a for a in c["actions"] if a[0] == "send_first"]
    if first:
        conn.sendall(first[0][1])
    req = b""
    try:
        while len(req) < 5:
            d = conn.recv(5 - len(req))
            if not d: break
            req += d
    except socket.timeout:
        pass
    rec["request_hex"] = req.hex()
    for a in c["actions"]:
        try:
            if a[0] == "send": conn.sendall(a[1])
            elif a[0] == "sleep": time.sleep(a[1])
            elif a[0] == "close": conn.shutdown(socket.SHUT_RDWR); conn.close(); break
            elif a[0] == "reset":
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); conn.close(); break
            elif a[0] == "drip":
                for i in range(len(a[1])):
                    conn.sendall(a[1][i:i+1]); time.sleep(a[2])
        except OSError as e:
            rec.setdefault("server_errors", []).append(str(e)); break
    else:
        # anything else sent by the client after the response?
        try:
            conn.settimeout(0.5); more = conn.recv(100); rec["client_sent_after"] = more.hex()
        except (socket.timeout, OSError) as e:
            rec["client_sent_after"] = "none(%s)" % type(e).__name__
        conn.close()
    srv.close()

out = {"platform": platform.system() + "-" + platform.machine(), "cases": {}}
fails = []
for c in cases:
    d = tempfile.mkdtemp(prefix="hm r2 ü-")
    path = os.path.join(d, "a s.sock")
    rec, ready = {}, threading.Event()
    th = threading.Thread(target=server, args=(path, c, rec, ready)); th.start(); ready.wait(5)
    env = {"PATH": "/usr/bin:/bin", "HOME": d, "LANG": "C.UTF-8"}
    t0 = time.monotonic()
    pr = subprocess.Popen([P, "agent", "list", "--socket", path, "--timeout-ms", str(c["timeout_ms"]), "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    t_sig = None
    if c["sigint_after"]:
        time.sleep(c["sigint_after"]); pr.send_signal(signal.SIGINT); t_sig = time.monotonic()
    so, se = pr.communicate(timeout=20)
    t1 = time.monotonic()
    th.join(10)
    try: doc = json.loads(so)
    except Exception: doc = None
    code = doc.get("code") if doc else None
    r = {"exit": pr.returncode, "code": code, "elapsed_s": round(t1 - t0, 3), "server": rec, "stderr": se.decode("utf-8", "replace")[:200]}
    if t_sig: r["sigint_to_exit_ms"] = round((t1 - t_sig) * 1000, 1)
    ok = pr.returncode == c["want_exit"] and code == c["want_code"] and rec.get("request_hex", "") in ("000000010b", "")
    if c["extra"].get("count"): ok = ok and len(doc["data"]["identities"]) == 1024
    if c["extra"].get("k1") and doc:
        ids = doc["data"]["identities"]; s_ = ids[0]["key_type"] + ids[0]["comment"]
        bad = [hex(ord(ch)) for ch in s_ if ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f]
        r["k1_bad_codepoints"] = bad; r["identity"] = ids[0]; ok = ok and not bad
        r["bidi_zero_width_passed_through"] = ("‮" in s_, "​" in s_)
    if code == "AGENT_OK" and doc and not c["extra"].get("k1"):
        r["fingerprint_ok"] = doc["data"]["identities"][0]["fingerprint"] == fp(B)
        ok = ok and r["fingerprint_ok"]
    if t_sig: ok = ok and r["sigint_to_exit_ms"] < 500
    if c["name"] == "slow_drip_exceeds_timeout" or c["name"] == "silent_until_timeout": r["timeout_overrun_ms"] = round((t1 - t0) * 1000 - c["timeout_ms"], 1)
    r["want"] = [c["want_exit"], c["want_code"]]; r["ok"] = ok
    if not ok: fails.append(c["name"])
    out["cases"][c["name"]] = r
out["fails"] = fails
print(json.dumps(out, indent=1, ensure_ascii=True))
sys.exit(1 if fails else 0)
