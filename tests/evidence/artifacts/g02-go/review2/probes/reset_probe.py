# K3a on the real reset path: the server never reads the 5-byte request, so closing
# makes Linux deliver ECONNRESET to the reader. A Python control client verifies
# the delivery before heimdall-proto is judged on the same server behaviour.
import json, os, socket, struct, subprocess, sys, tempfile, threading, time, platform
P = sys.argv[1]
def serve(path, pre, ready, unread=True):
    srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1); ready.set()
    c, _ = srv.accept()
    time.sleep(0.1)          # request is in our receive queue, unread
    if pre: c.sendall(pre); time.sleep(0.05)
    c.close(); srv.close()
out = {"platform": platform.system()}
for name, pre, want in (("before_any_byte", b"", "AGENT_UNAVAILABLE"), ("after_1_byte", b"\x00", "AGENT_PROTOCOL_ERROR"),
                        ("after_4_byte_header", b"\x00\x00\x00\x30", "AGENT_PROTOCOL_ERROR"), ("mid_body", b"\x00\x00\x00\x30\x0c\x00\x00", "AGENT_PROTOCOL_ERROR")):
    d = tempfile.mkdtemp(); path = os.path.join(d, "s")
    # control client
    ev = threading.Event(); th = threading.Thread(target=serve, args=(path, pre, ev)); th.start(); ev.wait()
    cl = socket.socket(socket.AF_UNIX); cl.connect(path); cl.sendall(b"\x00\x00\x00\x01\x0b")
    got = b""; err = None
    try:
        while True:
            x = cl.recv(100)
            if not x: err = "EOF"; break
            got += x
    except OSError as e:
        err = type(e).__name__ + ":" + str(e.errno)
    th.join(); cl.close(); os.unlink(path)
    ev = threading.Event(); th = threading.Thread(target=serve, args=(path, pre, ev)); th.start(); ev.wait()
    pr = subprocess.run([P, "agent", "list", "--socket", path, "--timeout-ms", "3000", "--json"], capture_output=True, env={"PATH": "/usr/bin:/bin"})
    th.join()
    code = json.loads(pr.stdout).get("code") if pr.stdout else None
    out[name] = {"control_reader_saw": err, "control_bytes": len(got), "proto_exit": pr.returncode, "proto_code": code, "want": want, "ok": code == want and pr.returncode == 5}
print(json.dumps(out, indent=1)); sys.exit(0 if all(v["ok"] for k, v in out.items() if isinstance(v, dict)) else 1)
