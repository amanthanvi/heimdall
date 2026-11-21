#!/usr/bin/env python3
"""M07 design probe (disposable; never imported; docs/architecture/m07-plan.md §8).

Questions:
  P1  How many bytes does an idle TUI write to the terminal per minute (spec §12.2
      "avoid continual repainting"), at 120x40 and 40x12, with and without NO_COLOR?
  P2  Key-to-output latency of the TUI (spec §15.1 "responsive key handling" P95 <= 100 ms),
      with a small and a large catalog.
  P3  At what catalog size does `inspect destinations` stop fitting one control frame
      (ADR-0006 §2.2: 1 MiB), and what do the CLI and the TUI show then?

Boundaries: scratch HOME and HEIMDALL_HOME under one mktemp directory; environment cleared;
no SSH_AUTH_SOCK; no network (destinations use the reserved .invalid TLD and are never
contacted: nothing here connects); the runtime this script starts is stopped by
`service stop` and then, only if still alive, by its exact PID.

Usage: probe.py <heimdall binary> <output json>
"""

import errno
import fcntl
import json
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

BIN = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]

SCRATCH = tempfile.mkdtemp(prefix="hm-m07-probe-")
HOME = os.path.join(SCRATCH, "home")
HH = os.path.join(SCRATCH, "hh")
SSH_HOME = os.path.join(SCRATCH, "sshhome")
os.makedirs(HOME, mode=0o700)
os.makedirs(HH, mode=0o700)
# The passive static pass resolves ~/.ssh from the account database, never $HOME
# (localenv/src/paths.rs). The debug-only redirect keeps it inside the scratch: an
# empty account home and an empty system directory (`<home>/etc-ssh`).
os.makedirs(os.path.join(SSH_HOME, "etc-ssh"), mode=0o700)

BASE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME": HOME,
    "HEIMDALL_HOME": HH,
    "LANG": "en_US.UTF-8",
    "TERM": "xterm-256color",
    # Debug-build test configuration: the runtime treats the clock as synchronized, so a
    # first start can write without an attended `time confirm` (testcfg.rs SYNC_ENV).
    "HEIMDALL_TEST_TIME_SYNC": "synchronized",
    "HEIMDALL_TEST_SSH_HOME": SSH_HOME,
}


def env(extra=None):
    e = dict(BASE_ENV)
    if extra:
        e.update(extra)
    return e


def cli(*args, extra=None, timeout=120):
    t0 = time.monotonic()
    p = subprocess.run([BIN, *args], env=env(extra), cwd=HOME, capture_output=True,
                       timeout=timeout, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout, p.stderr, time.monotonic() - t0


def bundle(n, path):
    b = {
        "schema": "heimdall-portable/1",
        "created_at": "2026-11-21T00:00:00Z",
        "destinations": [
            {"id": "d%06d" % i, "alias": "host-%06d" % i,
             "hostname": "h%06d.example.invalid" % i, "account": "probe", "port": 22}
            for i in range(n)
        ],
    }
    with open(path, "w") as f:
        json.dump(b, f)


class Tui:
    """`heimdall tui` on a pseudo-terminal of the given size."""

    def __init__(self, rows, cols, extra=None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.proc = subprocess.Popen(
            [BIN, "tui"], env=env(extra), cwd=HOME, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True, close_fds=True,
            preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        self.buf = bytearray()
        self.t0 = time.monotonic()

    def read_for(self, seconds):
        """Read for `seconds`; returns [(t, nbytes)] write bursts."""
        end = time.monotonic() + seconds
        bursts = []
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return bursts
            r, _, _ = select.select([self.master], [], [], left)
            if not r:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError as e:
                if e.errno == errno.EIO:
                    return bursts
                raise
            if not data:
                return bursts
            self.buf.extend(data)
            bursts.append((time.monotonic(), len(data)))

    def wait_for(self, needle, limit, screen_path=None):
        """Seconds from spawn until `needle` is on the screen (the debug screen dump when
        given: the terminal stream interleaves text with cursor moves)."""
        end = time.monotonic() + limit
        while time.monotonic() < end:
            hay = self.buf
            if screen_path:
                try:
                    hay = open(screen_path, "rb").read()
                except OSError:
                    hay = b""
            if needle in hay:
                return time.monotonic() - self.t0
            self.read_for(0.05)
        return None

    def key_latency(self, key, quiet=0.3, limit=2.0):
        """Drain, send `key`, return seconds to the first output byte (None if none)."""
        self.read_for(quiet)
        t = time.monotonic()
        os.write(self.master, key)
        end = t + limit
        while time.monotonic() < end:
            r, _, _ = select.select([self.master], [], [], end - time.monotonic())
            if r:
                data = os.read(self.master, 65536)
                self.buf.extend(data)
                return time.monotonic() - t
        return None

    def quit(self):
        try:
            os.write(self.master, b"q")
        except OSError:
            pass
        # Keep draining while waiting: a TUI blocked writing a frame into a full pty buffer
        # cannot read the `q`.
        end = time.monotonic() + 10
        while self.proc.poll() is None and time.monotonic() < end:
            self.read_for(0.1)
        if self.proc.poll() is None:
            self.proc.kill()  # our own child, exact PID
        code = self.proc.wait(5)
        self.read_for(1.0)  # until EIO: everything the TUI wrote before exiting
        os.close(self.master)
        return code


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = max(0, min(len(xs) - 1, int(round(p / 100.0 * len(xs) + 0.5)) - 1))
    return xs[k]


def ms(x):
    return None if x is None else round(x * 1000, 1)


def main():
    result = {"binary": "target/debug/heimdall (debug build)", "rows": {}}
    service = subprocess.Popen([BIN, "service", "run"], env=env(), cwd=HOME,
                               stdin=subprocess.DEVNULL,
                               stdout=open(os.path.join(SCRATCH, "service.log"), "wb"),
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        for _ in range(100):
            code, out, _, _ = cli("--json", "service", "status")
            if code == 0:
                break
            time.sleep(0.1)
        result["service_status_exit"] = code

        smoke = bool(os.environ.get("PROBE_SMOKE"))

        def tui_row(rows, cols, extra=None, idle=(3 if smoke else 45), keys=(4 if smoke else 40)):
            screen_path = os.path.join(SCRATCH, "screen-%dx%d.txt" % (cols, rows))
            t = Tui(rows, cols, dict(extra or {}, HEIMDALL_TEST_TUI_SCREEN=screen_path))
            first = t.wait_for(b"Over", 20)  # the stream: first bytes of the first frame
            settled = t.wait_for(b"Runtime: connected", 60, screen_path)
            t.read_for(6)  # let the static pass and first poll finish
            try:
                screen = open(screen_path, encoding="utf-8").read()
            except OSError:
                screen = ""
            lines = screen.splitlines()
            finding_rows = [l.strip().lstrip(">").strip() for l in lines
                            if l.strip().lstrip(">").strip().startswith("[")]
            codes = sorted({r.split("]", 1)[1].split(":", 1)[0].split(" (")[0].strip()
                            for r in finding_rows if "]" in r})
            bursts = t.read_for(idle)
            idle_bytes = sum(n for _, n in bursts)
            lat = []
            for i in range(keys):
                lat.append(t.key_latency(b"\t" if i % 2 == 0 else b"\x1b[Z"))
            got = [x for x in lat if x is not None]
            screen_tail = bytes(t.buf[-4000:])
            code = t.quit()
            restored = b"\x1b[?1049l" in bytes(t.buf[-4000:])
            return {
                "size": "%dx%d" % (cols, rows), "no_color": bool(extra),
                "first_frame_ms": ms(first), "runtime_connected_ms": ms(settled),
                "idle_seconds": idle, "idle_bytes": idle_bytes, "idle_write_bursts": len(bursts),
                "idle_bytes_per_minute": round(idle_bytes * 60.0 / idle),
                "key_samples": len(lat), "key_no_output": len(lat) - len(got),
                "key_p50_ms": ms(pct(got, 50)), "key_p95_ms": ms(pct(got, 95)),
                "key_max_ms": ms(max(got) if got else None),
                "quit_exit": code, "left_alternate_screen": restored,
                "shows_frame_limit_error": b"frame limit" in screen_tail,
                "overview_header": lines[1].strip() if len(lines) > 1 else None,
                "overview_finding_rows_visible": len(finding_rows),
                "overview_duplicate_rows_visible": len(finding_rows) - len(set(finding_rows)),
                "overview_codes_visible": codes,
            }

        # ---- P3 and the catalog sizes used by P2 --------------------------------------
        sizes = [5] if os.environ.get("PROBE_SMOKE") else [100, 1000, 3000, 5000, 6000, 7000, 9000]
        p3 = []
        have = 0
        for n in sizes:
            path = os.path.join(SCRATCH, "b%d.json" % n)
            bundle(n, path)
            ic, iout, ierr, it = cli("--json", "import", path, "--yes", timeout=600)
            have = n
            c, out, err, dt = cli("--json", "inspect", "destinations")
            try:
                env_ = json.loads(out.decode().strip().splitlines()[-1])
                code_s = env_.get("code")
                items = len((env_.get("data") or {}).get("items") or [])
                msg = ((env_.get("data") or {}).get("error") or {}).get("message")
            except Exception as e:  # noqa: BLE001
                code_s, items, msg = "unparsed: %s" % e, None, None
            hc, hout, herr, hdt = cli("destination", "list")
            p3.append({
                "catalog_destinations": n, "import_exit": ic, "import_s": round(it, 2),
                "inspect_exit": c, "inspect_code": code_s, "inspect_items": items,
                "inspect_stdout_bytes": len(out), "inspect_ms": ms(dt), "error_message": msg,
                "human_list_exit": hc, "human_list_stdout_lines": hout.count(b"\n"),
                "human_list_stderr_head": herr.decode(errors="replace")[:160],
            })
            if n == sizes[0]:
                result["rows"]["P1_P2_tui_small_catalog"] = [
                    dict(tui_row(40, 120), catalog_destinations=n),
                    dict(tui_row(12, 40), catalog_destinations=n),
                    dict(tui_row(40, 120, {"NO_COLOR": "1"}), catalog_destinations=n),
                ]
            if c != 0:
                break
        result["rows"]["P3_inspect_destinations_vs_frame_limit"] = p3

        # ---- P1/P2 with the large catalog (whatever P3 left) -------------------------
        result["rows"]["P1_P2_tui_large_catalog"] = [
            dict(tui_row(40, 120, idle=(3 if smoke else 20), keys=(4 if smoke else 20)),
                 catalog_destinations=have),
        ]
    finally:
        sc, _, _, _ = cli("service", "stop")
        try:
            service.wait(15)
        except subprocess.TimeoutExpired:
            os.kill(service.pid, signal.SIGTERM)  # the exact PID this script started
            service.wait(10)
        result["service_stop_exit"] = sc
        result["service_exit"] = service.returncode
    with open(OUT, "w") as f:
        json.dump(result, f, indent=1)
    shutil.rmtree(SCRATCH)
    result["scratch_removed"] = not os.path.exists(SCRATCH)
    with open(OUT, "w") as f:
        json.dump(result, f, indent=1)


if __name__ == "__main__":
    main()
