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
  ensure_warm        THE spec 15.1 row: `ensure` of the profile a standing personal policy covers
                     (`access allow`, as M07's harness task 2 "covered" sets up), on one open
                     session, a NEW request ID each time, after 20 warm-up requests.
  ensure_replay      (informational) `ensure` of the approved request: the same request ID,
                     answered from its record (idempotent replay), after 20 warm-up requests.
                     A NEW request ID on the same profile and work needs a new owner decision
                     (observed), so a plain ensure is never "already authorized".
  activate_covered   (informational) `heimdall activate --hook --cwd <trusted project>` end to end: the path a
                     trusted project's standing authority covers without a decision. It includes
                     process start; the control protocol has no covered ensure for this caller.
  cli_status, cli_inspect   `heimdall --json status` and `--json inspect destinations` end to
                     end, including process start: printed beside, for information only.
  tui_first_runtime_frame   (informational) from spawn of `heimdall tui` on a 120x40 pty to
                     the first screen showing "listings read" (runtime data has arrived).
  tui_first_useful_frame    THE spec row: from spawn to the first screen showing the catalog
                     counts ("<N> destinations,"), runtime data a user can act on. Both read
                     the reconstructed screen (Screen), not raw bytes: the TUI moves the cursor
                     over unchanged cells, so a raw byte search misses whole words.
  key_to_frame       in one TUI, from writing a view key ("2" Destinations, "1" Overview, in
                     turn) to the end of the frame it causes:
                     the last byte before 20 ms of quiet (the quiet itself is not counted).
                     UNDER BACKGROUND WORK (ruled 2026-11-23): while the keys are measured, a
                     second session keeps ensures in flight for profile `slow`, whose provider
                     is reached through a delaying agent proxy (agent-delay.py, BG_DELAY_MS per
                     request). The record gives the background ensures' own latency, so it shows
                     the work was really slow and really running. key_to_frame_quiet is the
                     same with no background work, for comparison.
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


class Screen:
    """A minimal terminal screen, enough to read what the TUI shows: the TUI redraws only
    changed cells and moves the cursor over unchanged ones (CSI H, CSI C), so its raw bytes never
    hold a whole line. Handles cursor position and forward, erase in line and display, line
    feed, carriage return and printable text; other sequences are ignored."""

    def __init__(self, rows=40, cols=120):
        self.rows, self.cols = rows, cols
        self.cells = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.pending = ""

    def feed(self, data):
        import re
        text = self.pending + data.decode("utf-8", "replace")
        self.pending = ""
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[([0-9;?]*)([A-Za-z@`])", text[i:])
                if not m:
                    if len(text) - i < 16:
                        self.pending = text[i:]
                        return
                    i += 1
                    continue
                args, cmd = m.group(1), m.group(2)
                nums = [int(x) if x.isdigit() else 0 for x in args.replace("?", "").split(";")] if args else []
                if cmd in "Hf":
                    self.r = max(0, (nums[0] if nums and nums[0] else 1) - 1)
                    self.c = max(0, (nums[1] if len(nums) > 1 and nums[1] else 1) - 1)
                elif cmd == "C":
                    self.c += nums[0] if nums and nums[0] else 1
                elif cmd == "K":
                    if self.r < self.rows:
                        for x in range(self.c, self.cols):
                            self.cells[self.r][x] = " "
                elif cmd == "J" and (nums[:1] or [0])[0] == 2:
                    self.cells = [[" "] * self.cols for _ in range(self.rows)]
                i += m.end()
                continue
            if ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r += 1
            elif ch >= " ":
                if self.r < self.rows and self.c < self.cols:
                    self.cells[self.r][self.c] = ch
                self.c += 1
            i += 1

    def text(self):
        return "\n".join("".join(row) for row in self.cells)
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

    def ensure_new(self, client, n):
        r = client.request("ensure", profile=self.a.profile, work_id=self.a.work_id, request_id=f"bench-w{n}")
        return self.code_defaults(r).success

    def ensure_ok(self, client, n):
        r = client.request("ensure", profile=self.a.profile, work_id=self.a.work_id, request_id=self.a.request_id)
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
    def cli(self, name, argv, n=50, cwd=None, conditions="end to end including process start; for information, not the budget"):
        ms, errors = [], 0
        for _ in range(n):
            t = time.perf_counter()
            p = subprocess.run([self.a.heimdall, "--json", "--non-interactive", *argv],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=60, cwd=cwd)
            if p.returncode == 0:
                ms.append((time.perf_counter() - t) * 1000)
            else:
                errors += 1
        self.result[name] = summary(ms, errors, conditions)

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
        import re
        useful = re.compile(r"\d+ destinations,")
        runtime_ms, useful_ms, e_runtime, e_useful = [], [], 0, 0
        for _ in range(self.a.samples):
            t = time.perf_counter()
            pid, fd = self.spawn_tui()
            screen = Screen()
            got_runtime = got_useful = None
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and got_useful is None:
                r, _, _ = select.select([fd], [], [], 0.05)
                if not r:
                    continue
                try:
                    b = os.read(fd, 65536)
                except OSError:
                    break
                if not b:
                    break
                screen.feed(b)
                now = (time.perf_counter() - t) * 1000
                txt = screen.text()
                if got_runtime is None and "listings read" in txt:
                    got_runtime = now
                if useful.search(txt):
                    got_useful = now
            if got_runtime is None:
                e_runtime += 1
            else:
                runtime_ms.append(got_runtime)
            if got_useful is None:
                e_useful += 1
                if e_useful == 1:
                    with open(os.path.join(self.a.out, "tui-first-failure.txt"), "w", encoding="utf-8") as fh:
                        fh.write(screen.text())
            else:
                useful_ms.append(got_useful)
            self.stop_tui(pid, fd)
        self.result["tui_first_runtime_frame"] = summary(runtime_ms, e_runtime, "informational: spawn to the first screen showing 'listings read'; 120x40 pty; the screen reconstructed")
        self.result["tui_first_useful_frame"] = summary(useful_ms, e_useful, "THE spec row: spawn to the first screen showing the catalog counts ('<N> destinations,'); 120x40 pty; the screen reconstructed")

    def background(self, stop, lat):
        """Ensures of the slow profile, one after another, on their own session, until stop."""
        n = 0
        try:
            with self.Client(self.a.control, self.a.environment) as c:
                while not stop.is_set():
                    t = time.perf_counter()
                    r = c.request("ensure", profile=self.a.slow_profile, work_id="bench-bg", request_id=f"bench-bg{n}")
                    lat.append(((time.perf_counter() - t) * 1000, self.code_defaults(r).success))
                    n += 1
        except Exception as e:  # recorded, never hidden
            lat.append((None, repr(e)[:200]))

    def key_to_frame(self, name="key_to_frame", loaded=True):
        import threading
        stop, lat = threading.Event(), []
        bg = threading.Thread(target=self.background, args=(stop, lat), daemon=True) if loaded else None
        pid, fd = self.spawn_tui()
        seen = b""
        deadline = time.monotonic() + 10
        while b"listings read" not in seen and time.monotonic() < deadline:
            seen += self.drain(fd, 0.5)
        self.drain(fd, 0.5)
        if bg:
            bg.start()
            time.sleep(2)  # background ensures are in flight before the first key
        first, frame, errors = [], [], 0
        for i in range(WARMUP + self.a.samples):
            key = b"2" if i % 2 == 0 else b"1"
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
        if bg:
            stop.set()
            bg.join(timeout=30)
        self.stop_tui(pid, fd)
        if loaded:
            cond = (f"one TUI on a 120x40 pty, view keys 2 and 1 in turn; UNDER BACKGROUND WORK: ensures of profile "
                    f"'{self.a.slow_profile}' kept in flight on a second session, its provider behind a {self.a.bg_delay_ms} ms delaying agent proxy")
            ok = [m for m, good in lat if m is not None and good is True]
            self.result["background_ensures"] = {
                "count": len(lat), "succeeded": len(ok),
                "p50_ms": round(pct(ok, 50), 2) if ok else None, "min_ms": round(min(ok), 2) if ok else None,
                "errors": [g for m, g in lat if m is None or g is not True][:5]}
        else:
            cond = "one TUI on a 120x40 pty, view keys 2 and 1 in turn; no background work (for comparison)"
        self.result[name.replace("frame", "first_byte")] = summary(first, errors, cond)
        self.result[name] = summary(frame, errors, cond + "; the frame ends at the last byte before 20 ms of quiet")

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

    def capture(self):
        """Diagnosis only (--capture): one TUI for 12 s, its raw output kept with arrival times,
        and the text seen by 1, 2, 5 and 10 s. Nothing is measured."""
        pid, fd = self.spawn_tui()
        t0 = time.perf_counter()
        chunks = []
        while time.perf_counter() - t0 < 12:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    b = os.read(fd, 65536)
                except OSError:
                    break
                if not b:
                    break
                chunks.append((time.perf_counter() - t0, b))
        self.stop_tui(pid, fd)
        with open(os.path.join(self.a.out, "tui-capture.ndjson"), "w", encoding="utf-8") as fh:
            for t, b in chunks:
                fh.write(json.dumps({"t_s": round(t, 4), "bytes": b.decode("utf-8", "replace")}) + "\n")
        import re
        for sec in (1, 2, 5, 10):
            raw = b"".join(b for t, b in chunks if t <= sec)
            text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b" ", raw)
            with open(os.path.join(self.a.out, f"tui-capture-{sec}s.txt"), "wb") as fh:
                fh.write(text)

    def run(self):
        if self.a.capture:
            self.capture()
            return
        self.first_and_session()
        self.session_metric("inspect_warm", lambda c, i: self.inspect_ok(c),
                            "one open control session, 20 warm-up requests first; process start excluded")
        self.session_metric("ensure_warm", self.ensure_new,
                            "THE spec 15.1 row: one open control session; the profile covered by a standing personal policy (access allow); a new request ID each time; 20 warm-up requests first")
        self.session_metric("ensure_replay", self.ensure_ok,
                            "one open control session; the approved request ID replayed (answered from its record); 20 warm-up requests first")
        self.cli("activate_covered", ["activate", "--hook", "--cwd", self.a.project], n=self.a.samples, cwd=self.a.project,
                 conditions="end to end including process start: the trusted project's hook, covered by its standing authority")
        self.cli("cli_status", ["status"])
        self.cli("cli_inspect", ["inspect", "destinations"])
        self.tui_first_frame()
        self.key_to_frame("key_to_frame_quiet", loaded=False)
        self.key_to_frame("key_to_frame", loaded=True)
        self.idle()
        self.result["finished_at"] = iso()
        with open(os.path.join(self.a.out, "bench.json"), "w", encoding="utf-8") as fh:
            json.dump(self.result, fh, indent=1, sort_keys=True)
            fh.write("\n")


def iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main():
    p = argparse.ArgumentParser()
    for name in ("--heimdall", "--control", "--environment", "--profile", "--work-id", "--request-id", "--project", "--out"):
        p.add_argument(name, required=True)
    p.add_argument("--slow-profile", required=True)
    p.add_argument("--bg-delay-ms", type=int, default=500)
    p.add_argument("--samples", type=int, default=200)
    p.add_argument("--capture", action="store_true")
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
