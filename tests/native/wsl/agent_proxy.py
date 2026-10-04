#!/usr/bin/env python3
"""G03 Mode B prototype endpoint: filtering, instrumented SSH agent proxy.

Harness code that makes the WSL Mode B *mechanics* measurable; it is not the
Heimdall bridge and makes no product claim. Stdlib only (Python 3.8+).

Listens on a Unix-domain socket and forwards permitted agent requests to an
upstream, which is either a Unix socket (--upstream-unix, e.g. a fixture
ssh-agent) or a per-connection stdio command (--upstream-cmd, e.g. the Windows
PipeStdioRelay.ps1 launched through WSL interop).

Enforced by this process for every caller that reaches the socket:
  * peer UID must equal --expected-uid (SO_PEERCRED / getpeereid);
  * REQUEST_IDENTITIES answers are filtered to the allowlist;
  * SIGN_REQUEST only for allowlisted keys; everything that mutates the
    upstream (add/remove/lock/unlock/smartcard) is refused;
  * extensions other than session-bind@openssh.com are refused;
  * after --deadline every request is refused;
  * bounded message size, concurrency and client idle time.
Lifecycle: refuses to replace a live endpoint, replaces a stale socket only
with --replace-stale, records a generation file, detects deletion/replacement
of its socket path, and on shutdown unlinks the path only if it is still the
inode this process created (stale cleanup cannot remove a replacement).

Exit codes: 0 normal stop; 3 live endpoint already present; 4 stale socket
present without --replace-stale; 5 unsafe directory or non-socket path;
6 endpoint replaced by another owner; 7 endpoint deleted (no --recreate);
8 deadline reached with --exit-at-deadline; 2 usage.
"""
import argparse
import ctypes
import ctypes.util
import errno
import json
import os
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_proto as ap  # noqa: E402

MUTATING = {ap.ADD_IDENTITY, ap.REMOVE_IDENTITY, ap.REMOVE_ALL_IDENTITIES, ap.LOCK, ap.UNLOCK,
            ap.ADD_ID_CONSTRAINED, 20, 21, 26, 1, 9}


class Log:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, **entry):
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
        entry["proxy_pid"] = os.getpid()
        line = json.dumps(entry, sort_keys=True)
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


def peer_credentials(conn):
    """Return (pid, uid, gid); pid is None where the platform does not report it."""
    if hasattr(socket, "SO_PEERCRED"):
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return pid, uid, gid
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if libc.getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "getpeereid failed")
    return None, uid.value, gid.value


class Upstream:
    def __init__(self, args):
        self.args = args
        self.sock = None
        self.proc = None

    def open(self):
        if self.args.upstream_unix:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.args.upstream_timeout)
            self.sock.connect(self.args.upstream_unix)
        else:
            argv = json.loads(self.args.upstream_cmd)
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, bufsize=0, cwd=self.args.upstream_cwd)

    def request(self, body):
        if self.sock is None and self.proc is None:
            self.open()
        if self.sock is not None:
            self.sock.sendall(ap.frame(body))
            return ap.read_msg(self.sock.recv)
        self.proc.stdin.write(ap.frame(body))
        self.proc.stdin.flush()
        return ap.read_msg(self.proc.stdout.read)

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.proc is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


class Proxy:
    def __init__(self, args):
        self.args = args
        self.log = Log(args.log)
        self.allowed = set(args.allow_fp or [])
        for p in args.allow_pub or []:
            self.allowed.add(ap.fingerprint(ap.pub_blob_from_file(p)))
        self.listen_sock = None
        self.identity = None  # (st_dev, st_ino) of the socket we created
        self.generation = None
        self.stop = threading.Event()
        self.exit_code = 0
        self.slots = threading.BoundedSemaphore(args.max_clients)
        self.conn_seq = 0
        self.seq_lock = threading.Lock()

    # ------------------------------------------------------------ endpoint
    def check_dir(self):
        d = os.path.dirname(os.path.abspath(self.args.listen))
        st = os.lstat(d)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return "listen directory not owned by this uid"
        if not self.args.insecure_mode_for_test and stat.S_IMODE(st.st_mode) & 0o077:
            return "listen directory is group/other accessible (mode %o)" % stat.S_IMODE(st.st_mode)
        return None

    def preflight(self):
        problem = self.check_dir()
        if problem:
            self.log.write(event="refuse_start", reason=problem)
            return 5
        path = self.args.listen
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return 0
        if not stat.S_ISSOCK(st.st_mode):
            self.log.write(event="refuse_start", reason="path exists and is not a socket")
            return 5
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(2)
        try:
            probe.connect(path)
            probe.close()
            self.log.write(event="refuse_start", reason="live endpoint already listening")
            return 3
        except OSError as e:
            probe.close()
            if e.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                self.log.write(event="refuse_start", reason="probe error errno=%s" % e.errno)
                return 5
        if st.st_uid != os.getuid():
            self.log.write(event="refuse_start", reason="stale socket owned by another uid")
            return 5
        if not self.args.replace_stale:
            self.log.write(event="refuse_start", reason="stale socket present (use --replace-stale)")
            return 4
        os.unlink(path)
        self.log.write(event="stale_replaced", path=path)
        return 0

    def bind(self):
        old = os.umask(0o177 if not self.args.insecure_mode_for_test else 0o111)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(self.args.listen)
        finally:
            os.umask(old)
        mode = 0o600 if not self.args.insecure_mode_for_test else 0o666
        os.chmod(self.args.listen, mode)
        s.listen(16)
        s.settimeout(0.5)
        st = os.lstat(self.args.listen)
        self.identity = (st.st_dev, st.st_ino)
        self.generation = secrets.token_hex(6)
        self.listen_sock = s
        if self.args.generation_file:
            tmp = self.args.generation_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"pid": os.getpid(), "generation": self.generation, "inode": st.st_ino,
                           "dev": st.st_dev, "listen": self.args.listen, "created": time.time()}, fh)
            os.replace(tmp, self.args.generation_file)
        self.log.write(event="listening", path=self.args.listen, generation=self.generation,
                       mode="%o" % stat.S_IMODE(st.st_mode), allowed=sorted(self.allowed))

    def still_ours(self):
        try:
            st = os.lstat(self.args.listen)
        except FileNotFoundError:
            return "missing"
        return "ours" if (st.st_dev, st.st_ino) == self.identity else "replaced"

    def watch(self):
        while not self.stop.is_set():
            time.sleep(0.5)
            state = self.still_ours()
            if state == "ours":
                if self.args.deadline and self.args.exit_at_deadline and time.time() >= self.args.deadline:
                    self.log.write(event="deadline_exit")
                    self.exit_code = 8
                    self.stop.set()
                continue
            if state == "missing" and self.args.recreate:
                self.log.write(event="endpoint_missing", action="recreate", old_generation=self.generation)
                try:
                    self.listen_sock.close()
                except OSError:
                    pass
                self.bind()
                continue
            self.log.write(event="endpoint_" + state, action="stop_without_unlink", generation=self.generation)
            self.exit_code = 7 if state == "missing" else 6
            self.identity = None  # never unlink a path we no longer own
            self.stop.set()

    # ------------------------------------------------------------ requests
    def decide(self, body, upstream, cid):
        mtype = body[0]
        entry = {"event": "request", "conn": cid, "msg_type": mtype, "msg_name": ap.NAMES.get(mtype)}
        if self.args.deadline and time.time() >= self.args.deadline:
            entry["result"] = "denied_expired"
            self.log.write(**entry)
            return bytes([ap.FAILURE])
        if mtype == ap.REQUEST_IDENTITIES:
            reply = upstream.request(body)
            try:
                idents = ap.parse_identities(reply)
            except ap.ProtocolError:
                entry["result"] = "upstream_bad_reply"
                self.log.write(**entry)
                return bytes([ap.FAILURE])
            keep = [(b, c) for (b, c) in idents if self.args.allow_all or ap.fingerprint(b) in self.allowed]
            entry["result"] = "identities:%d/%d" % (len(keep), len(idents))
            self.log.write(**entry)
            return ap.build_identities(keep)
        if mtype == ap.SIGN_REQUEST:
            try:
                blob, _ = ap.get_string(body, 1)
            except ap.ProtocolError:
                entry["result"] = "denied_malformed"
                self.log.write(**entry)
                return bytes([ap.FAILURE])
            fp = ap.fingerprint(blob)
            entry["key_fp"] = fp
            if not (self.args.allow_all or fp in self.allowed):
                entry["result"] = "denied_key_not_allowed"
                self.log.write(**entry)
                return bytes([ap.FAILURE])
            reply = upstream.request(body)
            entry["result"] = "forwarded_reply_type:%s" % (reply[0] if reply else None)
            self.log.write(**entry)
            return reply if reply else bytes([ap.FAILURE])
        if mtype == ap.EXTENSION:
            name = ap.extension_name(body)
            entry["extension"] = name
            if name == "session-bind@openssh.com":
                reply = upstream.request(body)
                entry["result"] = "forwarded_extension"
                self.log.write(**entry)
                return reply if reply else bytes([ap.FAILURE])
            entry["result"] = "denied_extension"
            self.log.write(**entry)
            return bytes([ap.FAILURE])
        entry["result"] = "denied_mutation" if mtype in MUTATING else "denied_unsupported"
        self.log.write(**entry)
        return bytes([ap.FAILURE])

    def serve_client(self, conn, cid):
        upstream = Upstream(self.args)
        try:
            conn.settimeout(self.args.client_idle_timeout)
            try:
                pid, uid, gid = peer_credentials(conn)
            except OSError as e:
                self.log.write(event="peer_rejected", conn=cid, reason="no peer credentials errno=%s" % e.errno)
                return
            if uid != self.args.expected_uid:
                self.log.write(event="peer_rejected", conn=cid, peer_uid=uid, peer_pid=pid,
                               reason="uid mismatch (expected %d)" % self.args.expected_uid)
                return
            self.log.write(event="connect", conn=cid, peer_uid=uid, peer_pid=pid)
            while not self.stop.is_set():
                try:
                    body = ap.read_msg(conn.recv)
                except ap.ProtocolError as e:
                    self.log.write(event="error", conn=cid, detail=str(e))
                    return
                except socket.timeout:
                    self.log.write(event="idle_timeout", conn=cid)
                    return
                if body is None:
                    return
                try:
                    reply = self.decide(body, upstream, cid)
                except (OSError, ap.ProtocolError, ValueError) as e:
                    self.log.write(event="upstream_error", conn=cid, detail=type(e).__name__ + ": " + str(e))
                    reply = bytes([ap.FAILURE])
                conn.sendall(ap.frame(reply))
        finally:
            upstream.close()
            try:
                conn.close()
            except OSError:
                pass
            self.log.write(event="disconnect", conn=cid)
            self.slots.release()

    def run(self):
        rc = self.preflight()
        if rc:
            return rc
        self.bind()
        if self.args.ready_file:
            with open(self.args.ready_file, "w", encoding="utf-8") as fh:
                json.dump({"status": "listening", "pid": os.getpid(), "generation": self.generation,
                           "listen": self.args.listen}, fh)
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        threading.Thread(target=self.watch, daemon=True).start()
        while not self.stop.is_set():
            try:
                conn, _ = self.listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    break
                time.sleep(0.1)
                continue
            if not self.slots.acquire(blocking=False):
                self.log.write(event="busy_reject")
                conn.close()
                continue
            with self.seq_lock:
                self.conn_seq += 1
                cid = self.conn_seq
            threading.Thread(target=self.serve_client, args=(conn, cid), daemon=True).start()
        self.shutdown()
        return self.exit_code

    def shutdown(self):
        try:
            self.listen_sock.close()
        except OSError:
            pass
        if self.identity is not None and self.still_ours() == "ours":
            os.unlink(self.args.listen)
            self.log.write(event="unlinked_own_endpoint", generation=self.generation)
        else:
            self.log.write(event="left_path_untouched", generation=self.generation)
        self.log.write(event="exit", exit_code=self.exit_code)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--listen", required=True)
    up = p.add_mutually_exclusive_group(required=True)
    up.add_argument("--upstream-unix")
    up.add_argument("--upstream-cmd", help="JSON argv list, spawned once per client connection")
    p.add_argument("--allow-fp", action="append")
    p.add_argument("--allow-pub", action="append")
    p.add_argument("--allow-all", action="store_true", help="explicitly disable key filtering (test only)")
    p.add_argument("--log", required=True)
    p.add_argument("--ready-file")
    p.add_argument("--generation-file")
    p.add_argument("--expected-uid", type=int, default=os.getuid())
    p.add_argument("--deadline", type=float, default=0.0, help="epoch seconds; refuse all requests afterwards")
    p.add_argument("--exit-at-deadline", action="store_true")
    p.add_argument("--replace-stale", action="store_true")
    p.add_argument("--recreate", action="store_true", help="recreate the socket if its path is deleted")
    p.add_argument("--max-clients", type=int, default=8)
    p.add_argument("--client-idle-timeout", type=float, default=30.0)
    p.add_argument("--upstream-timeout", type=float, default=30.0)
    p.add_argument("--upstream-cwd", help="working directory for --upstream-cmd (e.g. /mnt/c for Windows tools)")
    p.add_argument("--insecure-mode-for-test", action="store_true",
                   help="0666 socket in a non-private dir, to test the peer-UID check in isolation")
    args = p.parse_args()
    if not (args.allow_fp or args.allow_pub or args.allow_all):
        p.error("an allowlist (--allow-fp/--allow-pub) or explicit --allow-all is required")
    sys.exit(Proxy(args).run())


if __name__ == "__main__":
    main()
