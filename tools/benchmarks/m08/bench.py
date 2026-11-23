#!/usr/bin/env python3
"""The A34 benchmark driver (m08-plan W2-3; ADR-0014 section 6.1; spec section 15.1).

Started by bench-world.sh inside the M08 container, as the unprivileged account, once the
world exists: DESTINATIONS managed destinations, the projection applied, the runtime running
and one owner-approved grant for the profile. Standard library only. It never starts the
runtime and never runs as root.

What it measures, each with at least SAMPLES samples (a floor) and P50/P95:
  inspect_warm       `inspect destinations` on ONE open control session, after 20 warm-up
                     requests: the runtime, the session and the file-system caches are warm.
                     Process start is excluded (spec section 15.1).
  inspect_session    the same request on a NEW control session each time (connect, hello,
                     request): the runtime is warm, the session is cold.
  inspect_first      the first wrapper request after the world was built (one sample; the
                     world's own CLI calls ran before it, so it is not a fresh-start figure).
  ensure_warm        `ensure` of the already-authorized profile on one open session, a new
                     request ID each time, after 20 warm-up requests.
  cli_status, cli_inspect   `heimdall --json status` and `--json inspect destinations` end to
                     end, including process start: printed beside, for information only.
  tui_first_frame    from spawn of `heimdall tui` on a 120x40 pseudo-terminal to the first
                     output that shows the first destination's alias (the first useful frame).
  key_to_frame       in one TUI, from writing a Down key to the end of the frame it causes:
                     the last byte before 20 ms of quiet (the quiet itself is not counted).
                     NO background work runs in this version: ADR-0014 section 6.1 asks for
                     M05 U0b's delaying agent proxy, which is not wired yet. The record says so.
  idle               after SETTLE seconds, IDLE_WINDOWS windows of IDLE_WINDOW seconds: the
                     runtime's CPU time as a share of one core, and its resident set size.
The output is OUT/bench.json. A sample that errors is counted as an error, never dropped
silently.
"""
import argparse
import json
import os
import pty
import runpy
import select
import signal
import struct
import subprocess
import termios
import time
import fcntl

WARMUP = 20
QUIET_S = 0.020


def pct(values, p):
    """Nearest-rank percentile of a non-empty list."""
    v = sorted(values)
    k = max(0, min(len(v) - 1, int(-(-p * len(v) // 100)) - 1))
    return v[k]


def summary(ms, errors, conditions):
    out = {"samples": len(ms), "errors": errors, "conditions": conditions}
    if ms:
        out.update({"p50_ms": round(pct(ms, 50), 2), "p95_ms": round(pct(ms, 95), 2),
                    "min_ms": round(min(ms), 2), "max_ms": round(max(ms), 2)})
    return out


class Bench:
    def __init__(self, a):
        self.a = a
        wrapper = runpy.run_path("/src/examples/reference-wrapper/reference_wrapper.py")
        self.Client = wrapper["Client"]
        self.code_defaults = wrapper["code_defaults"]
        self.result = {"schema": "heimdall-m08-bench/1", "destinations": a.destinations,
                       "sample_floor": a.samples, "started_at": iso()}

    # ---- control-session requests
    def inspect_ok(self, client):
        r = client.request("inspect", subject="destinations")
        items = (r.get("data") or {}).get("items")
        return self.code_defaults(r).success and isinstance(items, list) and len(items) >= self.a.destinations

    def ensure_ok(self, client, n):
        r = client.request("ensure", profile=self.a.profile, work_id=self.a.work_id, request_id=f"bench-w{n}")
        return self.code_defaults(r).success

    def timed(self, fn):
        t = time.perf_counter()
        ok = fn()
        return ok, (time.perf_counter() - t) * 1000

    def session_metric(self, name, fn, conditions):
        ms, errors = [], 0
        with self.Client(self.a.control, self.a.environment) as c:
            for i in range(WARMUP):
                fn(c, -1 - i)
            for i in range(self.a.samples):
                ok, t = self.timed(lambda: fn(c, i))
                if ok:
                    ms.append(t)
                else:
                    errors += 1
        self.result[name] = summary(ms, errors, conditions)

    def first_and_session(self):
        ok, t = self.timed(lambda: self._one_session())
        self.result["inspect_first"] = summary([t] if ok else [], 0 if ok else 1,
                                               "the first wrapper request after the world was built, on a new session (one sample)")
        ms, errors = [], 0
        for _ in range(self.a.samples):
            ok, t = self.timed(self._one_session)
            if ok:
                ms.append(t)
            else:
                errors += 1
        self.result["inspect_session"] = summary(ms, errors, "a new control session per sample (connect, hello, request); the runtime warm")

    def _one_session(self):
        with self.Client(self.a.control, self.a.environment) as c:
            return self.inspect_ok(c)

    # ---- CLI, for information
    def cli(self, name, argv, n=50):
        ms, errors = [], 0
        for _ in range(n):
            t = time.perf_counter()
            p = subprocess.run([self.a.heimdall, "--json", "--non-interactive", *argv],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
            if p.returncode == 0:
                ms.append((time.perf_counter() - t) * 1000)
            else:
                errors += 1
        self.result[name] = summary(ms, errors, "end to end including process start; for information, not the budget")

    # ---- TUI on a pseudo-terminal
    def spawn_tui(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.execv(self.a.heimdall, [self.a.heimdall, "tui"])
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        return pid, fd

    def stop_tui(self, pid, fd):
        try:
            os.write(fd, b"q")
        except OSError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            self.drain(fd, 0.05)
        else:
            # The child is ours (pty.fork); end it by its own PID only.
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)

    @staticmethod
    def drain(fd, wait):
        got = b""
        while True:
            r, _, _ = select.select([fd], [], [], wait)
            if not r:
                return got
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return got
            if not chunk:
                return got
            got += chunk
            wait = 0

    def tui_first_frame(self):
        ms, errors = [], 0
        marker = b"hmb000"
        for _ in range(self.a.samples):
            t = time.perf_counter()
            pid, fd = self.spawn_tui()
            seen, ok = b"", False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                seen += self.drain(fd, 0.5)
                if marker in seen:
                    ok = True
                    break
            if ok:
                ms.append((time.perf_counter() - t) * 1000)
            else:
                errors += 1
            self.stop_tui(pid, fd)
        self.result["tui_first_frame"] = summary(ms, errors, "spawn to the first output showing the first destination's alias; 120x40 pty")

    def key_to_frame(self):
        pid, fd = self.spawn_tui()
        seen = b""
        deadline = time.monotonic() + 10
        while b"hmb000" not in seen and time.monotonic() < deadline:
            seen += self.drain(fd, 0.5)
        self.drain(fd, 0.5)
        first, frame, errors = [], [], 0
        for i in range(WARMUP + self.a.samples):
            key = b"\x1b[B" if (i // 50) % 2 == 0 else b"\x1b[A"
            t = time.perf_counter()
            os.write(fd, key)
            r, _, _ = select.select([fd], [], [], 2)
            if not r:
                errors += 0 if i < WARMUP else 1
                continue
            t_first = time.perf_counter()
            os.read(fd, 65536)
            t_last = t_first
            while True:
                r, _, _ = select.select([fd], [], [], QUIET_S)
                if not r:
                    break
                if not os.read(fd, 65536):
                    break
                t_last = time.perf_counter()
            if i >= WARMUP:
                first.append((t_first - t) * 1000)
                frame.append((t_last - t) * 1000)
        self.stop_tui(pid, fd)
        cond = "one TUI on a 120x40 pty, Down and Up keys; NO background work (the delaying agent proxy is not wired in this version)"
        self.result["key_to_first_byte"] = summary(first, errors, cond)
        self.result["key_to_frame"] = summary(frame, errors, cond + "; the frame ends at the last byte before 20 ms of quiet")

    # ---- idle
    def runtime_pid(self):
        p = subprocess.run([self.a.heimdall, "--json", "--non-interactive", "service", "status"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        try:
            pid = json.loads(p.stdout)["data"]["pid"]
        except (ValueError, KeyError, TypeError):
            return None
        try:
            if os.stat(f"/proc/{pid}").st_uid == os.getuid():
                return pid
        except OSError:
            pass
        return None

    @staticmethod
    def proc(pid):
        with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
            f = fh.read().rsplit(")", 1)[1].split()
        rss = threads = None
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
        return int(f[11]) + int(f[12]), rss, threads

    def idle(self):
        pid = self.runtime_pid()
        if not pid:
            self.result["idle"] = {"error": "the runtime's pid was not found"}
            return
        hz = os.sysconf("SC_CLK_TCK")
        time.sleep(self.a.settle)
        windows = []
        for _ in range(self.a.idle_windows):
            c0, _, _ = self.proc(pid)
            t0 = time.monotonic()
            time.sleep(self.a.idle_window)
            c1, rss, threads = self.proc(pid)
            secs = time.monotonic() - t0
            windows.append({"cpu_percent_of_one_core": round((c1 - c0) / hz / secs * 100, 3),
                            "rss_mib": round(rss / 1024, 1) if rss else None, "threads": threads,
                            "seconds": round(secs, 1)})
        self.result["idle"] = {"settle_s": self.a.settle, "windows": windows,
                               "memory_method": "VmRSS of the runtime process (/proc/<pid>/status)",
                               "cpu_method": "utime+stime ticks of the runtime process over the window"}

    def run(self):
        self.first_and_session()
        self.session_metric("inspect_warm", lambda c, i: self.inspect_ok(c),
                            "one open control session, 20 warm-up requests first; process start excluded")
        self.session_metric("ensure_warm", self.ensure_ok,
                            "one open control session, the profile already authorized, a new request ID each time, 20 warm-up requests first")
        self.cli("cli_status", ["status"])
        self.cli("cli_inspect", ["inspect", "destinations"])
        self.tui_first_frame()
        self.key_to_frame()
        self.idle()
        self.result["finished_at"] = iso()
        with open(os.path.join(self.a.out, "bench.json"), "w", encoding="utf-8") as fh:
            json.dump(self.result, fh, indent=1, sort_keys=True)
            fh.write("\n")


def iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main():
    p = argparse.ArgumentParser()
    for name in ("--heimdall", "--control", "--environment", "--profile", "--work-id", "--out"):
        p.add_argument(name, required=True)
    p.add_argument("--samples", type=int, default=200)
    p.add_argument("--destinations", type=int, default=100)
    p.add_argument("--settle", type=int, default=600)
    p.add_argument("--idle-window", type=int, default=300)
    p.add_argument("--idle-windows", type=int, default=3)
    a = p.parse_args()
    if a.samples < 200:
        p.error("--samples is at least 200 (ADR-0014 section 6.1)")
    if os.getuid() == 0:
        p.error("never as root")
    Bench(a).run()
    with open(os.path.join(a.out, "status.json"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"phase": "bench", "state": "DONE", "at": iso()}) + "\n")


if __name__ == "__main__":
    main()
