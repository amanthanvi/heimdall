#!/usr/bin/env python3
"""Delaying SSH-agent proxy for the U0b spike (measurement only).

Listens on --listen, forwards every agent frame to the disposable agent at
--upstream, and delays only the answer to SSH_AGENTC_REQUEST_IDENTITIES (11)
by --delay seconds. Logs one JSON line per event to --log. Request bytes are
checked for the needles given via --needle NAME=VALUE (canary, cwd, repo...).
"""
import argparse, json, os, select, socket, struct, sys, threading, time

NAMES = {11: "REQUEST_IDENTITIES", 12: "IDENTITIES_ANSWER", 13: "SIGN_REQUEST",
         14: "SIGN_RESPONSE", 17: "ADD_IDENTITY", 18: "REMOVE_IDENTITY",
         19: "REMOVE_ALL", 5: "FAILURE", 6: "SUCCESS", 25: "ADD_ID_CONSTRAINED",
         22: "LOCK", 23: "UNLOCK", 27: "EXTENSION", 28: "EXT_FAILURE"}
T0 = time.monotonic()
LOCK = threading.Lock()


def log(fh, **kw):
    kw["t"] = round(time.monotonic() - T0, 4)
    with LOCK:
        fh.write(json.dumps(kw) + "\n")
        fh.flush()


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            if buf:
                raise EOFError("partial frame")
            return None
        buf += c
    return buf


def read_frame(s):
    h = recvn(s, 4)
    if h is None:
        return None
    (n,) = struct.unpack(">I", h)
    if n > 1 << 20:
        raise ValueError("oversize frame")
    body = recvn(s, n) if n else b""
    if n and body is None:
        raise EOFError("eof in body")
    return h + body


def ext_name(body):
    if len(body) >= 5:
        (l,) = struct.unpack(">I", body[1:5])
        return body[5:5 + l].decode("ascii", "replace")
    return None


def serve(c, cid, a, fh, needles):
    up = socket.socket(socket.AF_UNIX)
    seq = 0
    try:
        up.connect(a.upstream)
        log(fh, ev="conn_open", conn=cid)
        while True:
            fr = read_frame(c)
            if fr is None:
                break
            body = fr[4:]
            typ = body[0] if body else None
            seq += 1
            rec = dict(ev="req", conn=cid, seq=seq, type=typ,
                       type_name=NAMES.get(typ, "TYPE_%s" % typ),
                       ext=ext_name(body) if typ == 27 else None,
                       len=len(body), frame_bytes=len(fr))
            for name, val in needles.items():
                rec["has_" + name] = val.encode() in fr
            log(fh, **rec)
            up.sendall(fr)
            resp = read_frame(up)
            if resp is None:
                break
            delayed = 0.0
            if typ == 11 and a.delay > 0:
                deadline = time.monotonic() + a.delay
                closed = False
                while True:
                    rem = deadline - time.monotonic()
                    if rem <= 0:
                        break
                    r, _, _ = select.select([c], [], [], rem)
                    if r:
                        if c.recv(1, socket.MSG_PEEK) == b"":
                            closed = True
                            break
                        time.sleep(rem)
                        break
                delayed = round(a.delay - max(0.0, deadline - time.monotonic()), 3)
                if closed:
                    log(fh, ev="client_closed_during_delay", conn=cid, seq=seq,
                        waited_s=delayed)
                    return
            try:
                c.sendall(resp)
                log(fh, ev="resp", conn=cid, seq=seq, type=resp[4] if len(resp) > 4 else None,
                    delayed_s=delayed, delivered=True)
            except OSError as e:
                log(fh, ev="resp", conn=cid, seq=seq, delivered=False, err=str(e))
                return
    except Exception as e:  # measurement tool: log and drop the connection
        log(fh, ev="error", conn=cid, err=repr(e))
    finally:
        log(fh, ev="conn_close", conn=cid)
        c.close()
        up.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--delay", type=float, required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--needle", action="append", default=[], help="NAME=VALUE")
    a = p.parse_args()
    needles = dict(n.split("=", 1) for n in a.needle)
    fh = open(a.log, "a")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(a.listen)
    os.chmod(a.listen, 0o600)
    srv.listen(16)
    log(fh, ev="start", delay=a.delay, pid=os.getpid())
    cid = 0
    while True:
        c, _ = srv.accept()
        cid += 1
        threading.Thread(target=serve, args=(c, cid, a, fh, needles), daemon=True).start()


if __name__ == "__main__":
    main()
