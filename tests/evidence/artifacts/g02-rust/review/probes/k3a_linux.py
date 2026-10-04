#!/usr/bin/env python3
"""K3a probe on Linux: server peeks the request (leaves it unread), optionally sends N header bytes,
then closes with SO_LINGER 0 so the kernel reports ECONNRESET to the client."""
import json, os, socket, struct, subprocess, sys, tempfile, threading, time

BIN = sys.argv[1]
res = []


def case(name, pre_bytes, consume_request, expect):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "s")
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(path)
    ls.listen(1)

    def srv():
        c, _ = ls.accept()
        if consume_request:
            c.recv(5)
        else:
            c.recv(5, socket.MSG_PEEK)
        if pre_bytes:
            c.sendall(pre_bytes)
            time.sleep(0.2)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        c.close()

    t = threading.Thread(target=srv)
    t.start()
    p = subprocess.run([BIN, "agent", "list", "--socket", path, "--timeout-ms", "3000", "--json"], capture_output=True)
    t.join()
    code = json.loads(p.stdout)["code"] if p.stdout else None
    r = {"case": name, "exit_code": p.returncode, "code": code, "stderr": p.stderr.decode()[-120:], "expect": expect, "verdict": "pass" if code == expect else "fail"}
    res.append(r)
    print(json.dumps(r))


case("reset_before_any_byte_request_unread", b"", False, "AGENT_UNAVAILABLE")
case("reset_after_1_header_byte_request_unread", b"\x00", False, "AGENT_PROTOCOL_ERROR")
case("reset_after_3_header_bytes_request_unread", b"\x00\x00\x00", False, "AGENT_PROTOCOL_ERROR")
case("reset_after_full_header_mid_body_request_unread", b"\x00\x00\x00\x09\x0c", False, "AGENT_PROTOCOL_ERROR")
case("linger0_after_1_byte_request_consumed", b"\x00", True, "AGENT_PROTOCOL_ERROR")
print("FAILS:", [r["case"] for r in res if r["verdict"] == "fail"])
sys.exit(1 if any(r["verdict"] == "fail" for r in res) else 0)
