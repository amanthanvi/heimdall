#!/usr/bin/env python3
"""A delaying ssh-agent proxy for the benchmark's background work (W2-3; spec section 15.1
"responsive key handling under background operations"). Standard library only.

Usage: agent-delay.py LISTEN_SOCKET UPSTREAM_SOCKET DELAY_MS

Listens on LISTEN_SOCKET (mode 0600) and relays every connection to the real agent at
UPSTREAM_SOCKET, holding each request DELAY_MS milliseconds before forwarding it. The answer is
the real agent's, unchanged: the provider is slow, not different. Runs as the benchmark's own
unprivileged account, inside the container, until killed.
"""
import os
import socket
import sys
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


def main():
    if len(sys.argv) != 4:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    listen, upstream, delay = sys.argv[1], sys.argv[2], int(sys.argv[3]) / 1000
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
