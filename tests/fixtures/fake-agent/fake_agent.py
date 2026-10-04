#!/usr/bin/env python3
"""Instrumented fake SSH agent for Heimdall gate experiments (plan.md section 6.2).

Python standard library only.  Serves the SSH agent protocol
(draft-miller-ssh-agent) on a Unix-domain socket and records every connection
and every received message type to a JSON-lines contact log, so a later gate
can prove that a component under test stayed passive or sent exactly the
messages it was allowed to send.

This agent NEVER signs anything, never reads or stores private keys, and
answers every request type other than REQUEST_IDENTITIES (11) with
SSH_AGENT_FAILURE (5) after recording it.

Usage:
  fake_agent.py --socket PATH --mode MODE [--pubkey FILE ...] [--log FILE]
                [--ready-file FILE]

Modes (what the answer to a type-11 request looks like):
  normal              type 12 with one identity per --pubkey file, in order
  empty               type 12, nkeys = 0
  slow                accept and read, never answer, keep the connection open
  oversize            frame header declaring 0x7fffffff bytes, then silence
  huge_nkeys          type 12 with nkeys = 100000 but only one key present
  truncated           frame declares 100 bytes, 10 are sent, connection closed
  trailing_bytes      valid type 12 answer followed by 3 junk bytes inside the frame
  wrong_type          frame of type 6 (SSH_AGENT_SUCCESS)
  failure             frame of type 5 (SSH_AGENT_FAILURE)
  invalid_utf8_comment  one identity whose comment is b"bad-\\xff-comment"
  string_overrun      one identity whose key-blob length exceeds the frame
  comment_overrun     one identity with a valid blob whose comment length exceeds the frame
  nkeys_max           valid answer with exactly 1024 identities (boundary)
  nkeys_over          valid answer with 1025 identities (one over the bound)
  frame_max           valid answer whose frame length is exactly 262144
  frame_over          valid answer whose frame length is exactly 262145
  fragmented          normal answer delivered a few bytes at a time
  control_chars       one identity whose key-blob key type and comment contain ESC, TAB, DEL,
                      other C0 (BEL, SOH), C1 code points (U+0085, U+009B) and one invalid
                      UTF-8 byte (contract K1)
  close_silent        read the request, then close without sending a single byte (K3)
  partial_header      send 1 byte of the 4-byte frame header, then close (K3)
  failure_payload     SSH_AGENT_FAILURE (type 5) frame that carries a 4-byte payload (K4)
  reset_before_reply  peek at the request without consuming it, then close with SO_LINGER 0 and
                      the request still unread, before sending a single byte (K3a)
  reset_after_byte    same, but send 1 byte of the frame header first (K3a)
  zero_length_frame   frame header declaring length 0 (no message type byte), connection kept open
  answer_type_only    type 12 frame of length 1 (no nkeys field), connection kept open
  answer_short        type 12 frame of length 3 (nkeys field cut after 2 bytes), connection kept open
  nkeys_short         type 12 frame declaring nkeys = 3 (within the bound) but holding only one key
  drip                normal type 12 answer sent one byte every 100 ms (a reply that never completes
                      within a short --timeout-ms although bytes keep arriving)
                      Linux reports a close with unread data to the peer as ECONNRESET (after any
                      bytes already queued).  Darwin AF_UNIX stream sockets never report
                      ECONNRESET: the peer sees EOF in the same position (measured 2026-10-03).

Contact log (one JSON object per line):
  {"seq":1,"ts":"...Z","mono_ms":12.3,"event":"listen","socket":"...","mode":"..."}
  {"seq":2,...,"event":"connect","conn":1}
  {"seq":3,...,"event":"message","conn":1,"type":11,"length":1,"bytes":5,
   "responded":"normal","sent_bytes":123}
  {"seq":4,...,"event":"disconnect","conn":1,"reason":"peer_eof",
   "bytes_received":5,"bytes_sent":123,"partial_bytes":0}
  {"seq":5,...,"event":"shutdown"}
disconnect.reason: peer_eof | peer_reset | server_close | server_reset |
server_shutdown | request_oversize.  Only peer_eof/peer_reset mean the peer closed the connection.

SIGTERM/SIGINT: close connections, remove the socket, exit 0.
"""
import argparse
import base64
import datetime
import json
import os
import signal
import socket
import struct
import sys
import threading
import time

MODES = (
    "normal", "empty", "slow", "oversize", "huge_nkeys", "truncated",
    "trailing_bytes", "wrong_type", "failure", "invalid_utf8_comment",
    "string_overrun", "comment_overrun", "nkeys_max", "nkeys_over", "frame_max", "frame_over",
    "fragmented", "control_chars", "close_silent", "partial_header", "failure_payload",
    "reset_before_reply", "reset_after_byte",
    "zero_length_frame", "answer_type_only", "answer_short", "nkeys_short", "drip",
)
DRIP_INTERVAL = 0.1   # seconds between the bytes of the `drip` mode
RESET_MODES = {"reset_before_reply": b"", "reset_after_byte": b"\x00"}
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENT_IDENTITIES_ANSWER = 12
REQUEST_CAP = 1 << 20  # never buffer more than this from a client


class _EndConnection(Exception):
    pass


def ssh_string(b):
    return struct.pack(">I", len(b)) + b


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def load_pubkey(path):
    """Return (key_blob, comment_bytes) from an OpenSSH public key file."""
    with open(path, "rb") as fh:
        line = fh.readline().strip()
    parts = line.split(None, 2)
    if len(parts) < 2:
        raise SystemExit("bad public key file: %s" % path)
    blob = base64.b64decode(parts[1])
    comment = parts[2] if len(parts) > 2 else b""
    return blob, comment


# Contract K1 material.  Every control code point is valid UTF-8 (so the expected U+FFFD count
# is unambiguous: one per code point); the single 0xFF byte is the only invalid UTF-8.
K1_KEY_TYPE = b"ssh-k1\x1b[31m\tx\x7fy\xc2\x9bz\xff"
K1_COMMENT = b"c\x1b]0;t\x07o\tm\x7fm\xc2\x85e\xc2\x9b2Jn\x01t\xff!"


def k1_blob():
    return ssh_string(K1_KEY_TYPE) + ssh_string(bytes(range(32)))


def dummy_key():
    blob = ssh_string(b"ssh-ed25519") + ssh_string(bytes(range(32)))
    return blob, b"dummy"


class Log:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.seq = 0
        self.t0 = time.monotonic()
        self.fh = open(path, "a", encoding="utf-8") if path else None

    def write(self, event, **fields):
        with self.lock:
            self.seq += 1
            now = datetime.datetime.now(datetime.timezone.utc)
            rec = {
                "seq": self.seq,
                "ts": now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (now.microsecond // 1000),
                "mono_ms": round((time.monotonic() - self.t0) * 1000.0, 3),
                "event": event,
            }
            rec.update(fields)
            if self.fh:
                self.fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
                self.fh.flush()


class Agent:
    def __init__(self, args, keys):
        self.args = args
        self.keys = keys
        self.mode = args.mode
        self.log = Log(args.log)
        self.stop = threading.Event()
        self.next_conn = 0

    # ----- answers ---------------------------------------------------------
    @staticmethod
    def identities_payload(keys):
        body = struct.pack(">I", len(keys))
        for blob, comment in keys:
            body += ssh_string(blob) + ssh_string(comment)
        return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + body

    def answer(self):
        """Return (list_of_chunks_to_send, close_after)."""
        m = self.mode
        keys = self.keys
        first = keys[0]
        if m == "normal":
            return [frame(self.identities_payload(keys))], False
        if m == "fragmented":
            data = frame(self.identities_payload(keys))
            return [data[i:i + 3] for i in range(0, len(data), 3)], False
        if m == "empty":
            return [frame(self.identities_payload([]))], False
        if m == "slow":
            return [], False
        if m == "oversize":
            return [struct.pack(">I", 0x7FFFFFFF) + bytes([SSH_AGENT_IDENTITIES_ANSWER])], False
        if m == "huge_nkeys":
            body = bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 100000)
            body += ssh_string(first[0]) + ssh_string(first[1])
            return [frame(body)], False
        if m == "truncated":
            return [struct.pack(">I", 100) + bytes([SSH_AGENT_IDENTITIES_ANSWER]) + b"\x00" * 9], True
        if m == "trailing_bytes":
            return [frame(self.identities_payload(keys) + b"\x01\x02\x03")], False
        if m == "wrong_type":
            return [frame(bytes([SSH_AGENT_SUCCESS]))], False
        if m == "failure":
            return [frame(bytes([SSH_AGENT_FAILURE]))], False
        if m == "invalid_utf8_comment":
            return [frame(self.identities_payload([(first[0], b"bad-\xff-comment")]))], False
        if m == "string_overrun":
            body = bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 1)
            body += struct.pack(">I", len(first[0]) + 1000) + first[0]
            return [frame(body)], False
        if m == "comment_overrun":
            body = bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 1)
            body += ssh_string(first[0]) + struct.pack(">I", 1000) + b"short"
            return [frame(body)], False
        if m == "nkeys_max":
            return [frame(self.identities_payload([first] * 1024))], False
        if m == "nkeys_over":
            return [frame(self.identities_payload([first] * 1025))], False
        if m in ("frame_max", "frame_over"):
            target = 262144 if m == "frame_max" else 262145
            overhead = 1 + 4 + 4 + len(first[0]) + 4  # type, nkeys, blob str, comment len
            payload = self.identities_payload([(first[0], b"x" * (target - overhead))])
            assert len(payload) == target, (len(payload), target)
            return [frame(payload)], False
        if m == "control_chars":
            return [frame(self.identities_payload([(k1_blob(), K1_COMMENT)]))], False
        if m == "close_silent":
            return [], True
        if m == "partial_header":
            return [b"\x00"], True
        if m == "failure_payload":
            return [frame(bytes([SSH_AGENT_FAILURE]) + b"\x00\x00\x00\x00")], False
        if m == "zero_length_frame":
            return [struct.pack(">I", 0)], False
        if m == "answer_type_only":
            return [frame(bytes([SSH_AGENT_IDENTITIES_ANSWER]))], False
        if m == "answer_short":
            return [frame(bytes([SSH_AGENT_IDENTITIES_ANSWER]) + b"\x00\x00")], False
        if m == "nkeys_short":
            body = bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 3)
            body += ssh_string(first[0]) + ssh_string(first[1])
            return [frame(body)], False
        if m == "drip":
            data = frame(self.identities_payload(keys))
            return [data[i:i + 1] for i in range(len(data))], False
        raise SystemExit("unknown mode %r" % m)

    # ----- connection handling --------------------------------------------
    def handle_reset(self, conn, cid):
        """K3a: never consume the request (MSG_PEEK only), optionally send a partial header, then
        close with SO_LINGER {on, 0} while the request is still unread in the receive queue."""
        reason = None
        peeked = b""
        sent = 0
        try:
            while not self.stop.is_set():
                try:
                    peeked = conn.recv(64, socket.MSG_PEEK)
                except socket.timeout:
                    continue
                except OSError:
                    reason = "peer_reset"
                    break
                if not peeked:
                    reason = "peer_eof"
                    break
                if len(peeked) >= 4 and len(peeked) >= 4 + struct.unpack(">I", peeked[:4])[0]:
                    break
                time.sleep(0.005)
            if reason is None and not self.stop.is_set():
                (length,) = struct.unpack(">I", peeked[:4])
                mtype = peeked[4] if length else None
                first = RESET_MODES[self.mode]
                if first:
                    try:
                        conn.sendall(first)
                        sent = len(first)
                    except OSError:
                        pass
                self.log.write("message", conn=cid, type=mtype, length=length, bytes=4 + length,
                               responded=self.mode, sent_bytes=sent, consumed=False)
                time.sleep(0.05)      # let the partial header reach the peer before the reset
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                reason = "server_reset"
        finally:
            if reason is None:
                reason = "server_shutdown"
            n = len(peeked) if reason == "server_reset" else 0
            self.log.write("disconnect", conn=cid, reason=reason, bytes_received=n, bytes_sent=sent,
                           partial_bytes=0, request_left_unread=(reason == "server_reset"))
            try:
                conn.close()
            except OSError:
                pass

    def handle(self, conn, cid):
        if self.mode in RESET_MODES:
            conn.settimeout(0.2)
            return self.handle_reset(conn, cid)
        recv_total = 0
        sent_total = 0
        buf = b""
        reason = None  # None => the loop ended because of server shutdown
        conn.settimeout(0.2)
        try:
            while not self.stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    reason = "peer_reset"
                    break
                if not chunk:
                    reason = "peer_eof"
                    break
                recv_total += len(chunk)
                buf += chunk
                while len(buf) >= 4:
                    (length,) = struct.unpack(">I", buf[:4])
                    if length > REQUEST_CAP:
                        self.log.write("message", conn=cid, type=None, length=length, bytes=len(buf),
                                       responded="none_request_oversize", sent_bytes=0)
                        reason = "request_oversize"
                        raise _EndConnection
                    if len(buf) < 4 + length:
                        break
                    body = buf[4:4 + length]
                    buf = buf[4 + length:]
                    mtype = body[0] if body else None
                    if mtype == 11:
                        chunks, close_after = self.answer()
                        sent = 0
                        for c in chunks:
                            if self.stop.is_set():
                                break
                            try:
                                conn.sendall(c)
                            except OSError:
                                break
                            sent += len(c)
                            if self.mode == "fragmented":
                                time.sleep(0.002)
                            elif self.mode == "drip":
                                time.sleep(DRIP_INTERVAL)
                        sent_total += sent
                        self.log.write("message", conn=cid, type=11, length=length, bytes=4 + length,
                                       responded=self.mode, sent_bytes=sent)
                        if close_after:
                            reason = "server_close"
                            raise _EndConnection
                    else:
                        # Anything but REQUEST_IDENTITIES is refused; never sign.
                        try:
                            conn.sendall(frame(bytes([SSH_AGENT_FAILURE])))
                            sent_total += 5
                        except OSError:
                            pass
                        self.log.write("message", conn=cid, type=mtype, length=length, bytes=4 + length,
                                       responded="failure_unsupported_type", sent_bytes=5)
        except _EndConnection:
            pass
        finally:
            if reason is None:
                reason = "server_shutdown"
            self.log.write("disconnect", conn=cid, reason=reason, bytes_received=recv_total,
                           bytes_sent=sent_total, partial_bytes=len(buf))
            try:
                conn.close()
            except OSError:
                pass

    # ----- lifecycle -------------------------------------------------------
    def serve(self):
        path = self.args.socket
        if len(os.fsencode(path)) >= 104:
            raise SystemExit("socket path too long for AF_UNIX on macOS (%d bytes)" % len(os.fsencode(path)))
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        if os.path.lexists(path):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o077)
        try:
            s.bind(path)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        s.listen(16)
        s.settimeout(0.1)
        self.log.write("listen", socket=path, mode=self.mode, keys=len(self.keys))

        def on_signal(signum, _frame):
            self.stop.set()

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        if self.args.ready_file:
            tmp = self.args.ready_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("READY\n")
            os.replace(tmp, self.args.ready_file)
        threads = []
        try:
            while not self.stop.is_set():
                try:
                    conn, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self.next_conn += 1
                cid = self.next_conn
                self.log.write("connect", conn=cid)
                t = threading.Thread(target=self.handle, args=(conn, cid), daemon=True)
                t.start()
                threads.append(t)
        finally:
            self.stop.set()
            try:
                s.close()
            except OSError:
                pass
            for t in threads:
                t.join(timeout=2.0)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                print("could not remove socket: %s" % exc, file=sys.stderr)
            self.log.write("shutdown")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--socket", required=True)
    ap.add_argument("--mode", required=True, choices=MODES)
    ap.add_argument("--pubkey", action="append", default=[], help="OpenSSH .pub file (repeatable)")
    ap.add_argument("--log", help="JSON-lines contact log (appended)")
    ap.add_argument("--ready-file", help="created once the socket is listening")
    args = ap.parse_args(argv)
    keys = [load_pubkey(p) for p in args.pubkey]
    if args.mode == "normal" and not keys:
        ap.error("normal mode needs at least one --pubkey")
    if not keys:
        keys = [dummy_key()]
    Agent(args, keys).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
