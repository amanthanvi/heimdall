#!/usr/bin/env python3
"""Reviewer-2: confirm how the kernel delivers a peer close-with-unread-data to a reader
(precondition for the K3a probe cases noread_close_*). Prints what a plain client sees."""
import os, socket, sys, tempfile, threading, time
d = tempfile.mkdtemp()
p = os.path.join(d, "s")
srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)
def serve():
    c, _ = srv.accept(); time.sleep(0.2); c.sendall(b"\x00\x00\x00"); time.sleep(0.05); c.close()
threading.Thread(target=serve, daemon=True).start()
cl = socket.socket(socket.AF_UNIX); cl.connect(p); cl.sendall(b"\x00\x00\x00\x01\x0b")
got = b""
try:
    while True:
        b = cl.recv(10)
        if not b:
            print(sys.platform, "bytes_before_end", got.hex(), "END=EOF"); break
        got += b
except OSError as e:
    print(sys.platform, "bytes_before_end", got.hex(), "END=%s" % type(e).__name__)
