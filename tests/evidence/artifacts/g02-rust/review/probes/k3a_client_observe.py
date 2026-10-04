import os, socket, struct, tempfile, threading, time
for pre in (b"\x00", b"\x00\x00\x00", b"\x00\x00\x00\x09\x0c"):
    d = tempfile.mkdtemp(); path = os.path.join(d, "s")
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); ls.bind(path); ls.listen(1)
    def srv():
        c, _ = ls.accept(); c.recv(5, socket.MSG_PEEK); c.sendall(pre); time.sleep(0.2)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); c.close()
    t = threading.Thread(target=srv); t.start()
    cl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); cl.connect(path); cl.sendall(b"\x00\x00\x00\x01\x0b")
    t.join(); seen = []
    for _ in range(4):
        try:
            b = cl.recv(4)
            seen.append(b.hex() if b else "EOF")
            if not b: break
        except OSError as e:
            seen.append(f"ERR:{e.errno}:{os.strerror(e.errno)}"); break
    print("server_sent", pre.hex(), "client_reads", seen)
