#!/usr/bin/env python3
"""Inert banner listener for G03 exposure probes (stdlib only, harness code).

Serves a fixed banner and closes; it never speaks the agent protocol and never
forwards anything. Used to learn which WSL placements (Unix path, abstract
namespace, /mnt/wsl, loopback TCP) are reachable from other distributions or
from Windows. TCP binds 127.0.0.1 only. Exits after --seconds.
"""
import argparse
import json
import os
import socket
import sys
import time

BANNER = b"heimdall-g03-banner\n"


def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--unix")
    g.add_argument("--abstract")
    g.add_argument("--tcp-port", type=int, help="binds 127.0.0.1:<port>; 0 picks a free port")
    p.add_argument("--seconds", type=float, default=120)
    p.add_argument("--ready-file", required=True)
    args = p.parse_args()

    if args.tcp_port is not None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", args.tcp_port))
        where = {"tcp": "127.0.0.1:%d" % s.getsockname()[1]}
    else:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if args.unix:
            old = os.umask(0o177)
            try:
                s.bind(args.unix)
            finally:
                os.umask(old)
            where = {"unix": args.unix}
        else:
            s.bind("\0" + args.abstract)
            where = {"abstract": args.abstract}
    s.listen(8)
    s.settimeout(0.5)
    with open(args.ready_file, "w", encoding="utf-8") as fh:
        json.dump(dict(where, pid=os.getpid()), fh)
    end = time.time() + args.seconds
    served = 0
    while time.time() < end:
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        try:
            c.sendall(BANNER)
            served += 1
        finally:
            c.close()
    s.close()
    if args.unix:
        try:
            os.unlink(args.unix)
        except FileNotFoundError:
            pass
    print(json.dumps(dict(where, served=served)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
