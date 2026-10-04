"""Minimal SSH agent protocol helpers for the G03 harness (stdlib only).

Wire format per draft-ietf-sshm-ssh-agent: uint32 length, byte type, payload.
Harness code, not product code.
"""
import base64
import hashlib
import struct

MAX_MSG = 256 * 1024

FAILURE = 5
SUCCESS = 6
REQUEST_IDENTITIES = 11
IDENTITIES_ANSWER = 12
SIGN_REQUEST = 13
SIGN_RESPONSE = 14
ADD_IDENTITY = 17
REMOVE_IDENTITY = 18
REMOVE_ALL_IDENTITIES = 19
LOCK = 22
UNLOCK = 23
ADD_ID_CONSTRAINED = 25
EXTENSION = 27

NAMES = {
    1: "SSH_AGENTC_REQUEST_RSA_IDENTITIES", 5: "SSH_AGENT_FAILURE", 6: "SSH_AGENT_SUCCESS",
    9: "SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES", 11: "SSH2_AGENTC_REQUEST_IDENTITIES",
    12: "SSH2_AGENT_IDENTITIES_ANSWER", 13: "SSH2_AGENTC_SIGN_REQUEST", 14: "SSH2_AGENT_SIGN_RESPONSE",
    17: "SSH2_AGENTC_ADD_IDENTITY", 18: "SSH2_AGENTC_REMOVE_IDENTITY", 19: "SSH2_AGENTC_REMOVE_ALL_IDENTITIES",
    20: "SSH_AGENTC_ADD_SMARTCARD_KEY", 21: "SSH_AGENTC_REMOVE_SMARTCARD_KEY", 22: "SSH_AGENTC_LOCK",
    23: "SSH_AGENTC_UNLOCK", 25: "SSH2_AGENTC_ADD_ID_CONSTRAINED",
    26: "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED", 27: "SSH_AGENTC_EXTENSION",
    28: "SSH_AGENT_EXTENSION_FAILURE",
}


class ProtocolError(Exception):
    pass


def recv_exact(read, n):
    """read(k) -> bytes; returns exactly n bytes or None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_msg(read, max_len=MAX_MSG):
    hdr = recv_exact(read, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > max_len:
        raise ProtocolError("bad_length:%d" % length)
    body = recv_exact(read, length)
    if body is None:
        raise ProtocolError("truncated_body")
    return body


def frame(body):
    return struct.pack(">I", len(body)) + body


def put_string(b):
    return struct.pack(">I", len(b)) + b


def get_string(buf, off):
    if off + 4 > len(buf):
        raise ProtocolError("truncated_u32")
    (n,) = struct.unpack(">I", buf[off:off + 4])
    if off + 4 + n > len(buf):
        raise ProtocolError("truncated_string")
    return buf[off + 4:off + 4 + n], off + 4 + n


def fingerprint(blob):
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def pub_blob_from_line(line):
    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError("not an OpenSSH public key line")
    return base64.b64decode(parts[1])


def pub_blob_from_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return pub_blob_from_line(fh.read())


def parse_identities(body):
    if not body or body[0] != IDENTITIES_ANSWER:
        raise ProtocolError("not_identities_answer")
    (n,) = struct.unpack(">I", body[1:5])
    off = 5
    out = []
    for _ in range(n):
        blob, off = get_string(body, off)
        comment, off = get_string(body, off)
        out.append((blob, comment))
    return out


def build_identities(idents):
    body = bytes([IDENTITIES_ANSWER]) + struct.pack(">I", len(idents))
    for blob, comment in idents:
        body += put_string(blob) + put_string(comment)
    return body


def sign_request(blob, data=b"heimdall-g03-crafted", flags=0):
    return bytes([SIGN_REQUEST]) + put_string(blob) + put_string(data) + struct.pack(">I", flags)


def extension_name(body):
    try:
        name, _ = get_string(body, 1)
        return name.decode("ascii", "replace")
    except ProtocolError:
        return "<unparseable>"
