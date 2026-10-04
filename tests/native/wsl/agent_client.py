#!/usr/bin/env python3
"""Minimal SSH agent client for G03 probes (stdlib only, harness code).

Prints one JSON object on stdout. Exit 0 when a reply (or the expected close)
was observed, 2 when the endpoint could not be reached, 3 on protocol error.

Endpoints: --socket PATH | --abstract NAME (Linux abstract namespace) |
           --tcp HOST:PORT (only for exposure probes against test listeners).
Commands:  list | sign --pub FILE | raw --type N [--payload-hex HEX] |
           oversize | connect | banner
"""
import argparse
import json
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent_proto as ap  # noqa: E402


def connect(args):
    if args.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target = args.socket
    elif args.abstract:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target = "\0" + args.abstract
    else:
        host, port = args.tcp.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target = (host, int(port))
    s.settimeout(args.timeout)
    s.connect(target)
    return s


def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--socket")
    g.add_argument("--abstract")
    g.add_argument("--tcp")
    p.add_argument("--timeout", type=float, default=10.0)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sp = sub.add_parser("sign")
    sp.add_argument("--pub", required=True)
    rp = sub.add_parser("raw")
    rp.add_argument("--type", type=int, required=True)
    rp.add_argument("--payload-hex", default="")
    sub.add_parser("oversize")
    sub.add_parser("connect")
    sub.add_parser("banner")
    args = p.parse_args()

    out = {"cmd": args.cmd}
    try:
        s = connect(args)
    except OSError as e:
        out.update(connected=False, error=type(e).__name__, errno=e.errno)
        print(json.dumps(out))
        return 2
    out["connected"] = True
    try:
        if args.cmd == "connect":
            pass
        elif args.cmd == "banner":
            out["banner"] = s.recv(64).decode("ascii", "replace")
        elif args.cmd == "oversize":
            s.sendall(struct.pack(">I", ap.MAX_MSG + 1) + b"\x0b")
            try:
                data = s.recv(16)
                out["closed_by_peer"] = (data == b"")
                out["reply_bytes"] = len(data)
            except (ConnectionResetError, socket.timeout) as e:
                out["closed_by_peer"] = isinstance(e, ConnectionResetError)
                out["error"] = type(e).__name__
        else:
            if args.cmd == "list":
                body = bytes([ap.REQUEST_IDENTITIES])
            elif args.cmd == "sign":
                body = ap.sign_request(ap.pub_blob_from_file(args.pub))
            else:
                body = bytes([args.type]) + bytes.fromhex(args.payload_hex)
            s.sendall(ap.frame(body))
            reply = ap.read_msg(s.recv)
            if reply is None:
                out["reply_type"] = None
                out["closed_by_peer"] = True
            else:
                out["reply_type"] = reply[0]
                out["reply_name"] = ap.NAMES.get(reply[0])
                if args.cmd == "list" and reply[0] == ap.IDENTITIES_ANSWER:
                    out["keys"] = [{"fingerprint": ap.fingerprint(b), "comment": c.decode("utf-8", "replace")}
                                   for b, c in ap.parse_identities(reply)]
    except ap.ProtocolError as e:
        out["protocol_error"] = str(e)
        print(json.dumps(out))
        return 3
    except OSError as e:
        out["io_error"] = type(e).__name__
    finally:
        s.close()
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
