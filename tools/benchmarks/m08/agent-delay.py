#!/usr/bin/env python3
"""A delaying ssh-agent proxy for the benchmark's background work (W2-3; spec section 15.1
"responsive key handling under background operations"). Standard library only.

Usage: agent-delay.py LISTEN_SOCKET UPSTREAM_SOCKET DELAY_MS ALLOWED_DIR
       agent-delay.py self-test

Listens on LISTEN_SOCKET (mode 0600) and relays every connection to the real agent at
UPSTREAM_SOCKET, holding each request DELAY_MS milliseconds before forwarding it. The answer is
the real agent's, unchanged: the provider is slow, not different. Runs as the benchmark's own
unprivileged account, inside the container, until killed.

It refuses to start (exit 2) unless UPSTREAM_SOCKET, every link resolved, is a socket owned by
the calling account inside ALLOWED_DIR (the run's scratch directory), so it never relays to an
agent the run did not create (review M08-W2-R06).
"""
import os
import socket
import stat
import sys
import tempfile
import threading
import time


def relay(client, upstream_path, delay):
    try:
        up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        up.connect(upstream_path)
    except OSError:
        client.close()
        return

    def back():
        try:
            while True:
                data = up.recv(65536)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            client.close()

    threading.Thread(target=back, daemon=True).start()
    try:
        while True:
            data = client.recv(65536)
            if not data:
                break
            time.sleep(delay)
            up.sendall(data)
    except OSError:
        pass
    finally:
        up.close()


def upstream_refusal(upstream, allowed_dir):
    """None when the upstream may be used, else the reason it may not."""
    real = os.path.realpath(upstream)
    root = os.path.realpath(allowed_dir)
    if not real.startswith(root.rstrip(os.sep) + os.sep):
        return "the upstream is not inside the allowed directory"
    try:
        st = os.stat(real)
    except OSError:
        return "the upstream does not exist"
    if not stat.S_ISSOCK(st.st_mode):
        return "the upstream is not a socket"
    if st.st_uid != os.getuid():
        return "the upstream is not owned by this account"
    return None


def self_test():
    bad = []
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        socks = []
        for d in (a, b):
            sk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sk.bind(os.path.join(d, "agent.sock"))
            socks.append(sk)
        with open(os.path.join(a, "plain"), "w") as fh:
            fh.write("x")
        os.symlink(os.path.join(b, "agent.sock"), os.path.join(a, "link.sock"))
        os.makedirs(a + "-sibling", exist_ok=True)
        try:
            cases = [
                ("this run's socket is accepted", os.path.join(a, "agent.sock"), True),
                ("another directory's socket is refused", os.path.join(b, "agent.sock"), False),
                ("a link inside to a socket outside is refused", os.path.join(a, "link.sock"), False),
                ("a path climbing out is refused", os.path.join(a, "..", os.path.basename(b), "agent.sock"), False),
                ("a regular file is refused", os.path.join(a, "plain"), False),
                ("a missing path is refused", os.path.join(a, "none.sock"), False),
                ("a sibling sharing the prefix is refused", os.path.join(a + "-sibling", "agent.sock"), False),
            ]
            for name, path, ok in cases:
                if (upstream_refusal(path, a) is None) != ok:
                    bad.append(name)
        finally:
            os.rmdir(a + "-sibling")
            for sk in socks:
                sk.close()
    for name in bad:
        print(f"FAIL {name}")
    # Not covered here: a socket owned by another account (making one needs a second account).
    print(f"agent-delay self-test: {len(bad)} failed of 7")
    return 1 if bad else 0


def main():
    if sys.argv[1:] == ["self-test"]:
        return self_test()
    if len(sys.argv) != 5:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    listen, upstream, delay, allowed = sys.argv[1], sys.argv[2], int(sys.argv[3]) / 1000, sys.argv[4]
    why = upstream_refusal(upstream, allowed)
    if why:
        print(f"agent-delay: refused: {why}", file=sys.stderr)
        return 2
    if os.path.exists(listen):
        os.unlink(listen)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    srv.bind(listen)
    os.umask(old)
    srv.listen(16)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=relay, args=(c, upstream, delay), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
