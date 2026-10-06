"""Shared helpers for the G02 measurement scripts (stdlib + pyte from tests/g02/.venv).

Used by measure.py (host timing), clean_env.py (clean-environment runs) and assemble.py.
Nothing here touches the owner's ~/.ssh, a real SSH agent or any network endpoint.
"""
import fcntl
import gzip
import hashlib
import io
import json
import math
import os
import random
import re
import select
import shutil
import statistics
import struct
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PROTO = REPO / "prototypes"
FIX = REPO / "tests" / "fixtures" / "g02" / "profiles"
FAKE_AGENT = REPO / "tests" / "fixtures" / "fake-agent" / "fake_agent.py"
ART = REPO / "tests" / "evidence" / "artifacts" / "g02-measure"
ALL_CANDIDATES = ["go", "rust", "ts"]
# Round 3: HM_G02_CANDS=go,rust restricts every script that iterates CANDIDATES (same variable clean_env.py uses).
CANDIDATES = [c for c in os.environ.get("HM_G02_CANDS", ",".join(ALL_CANDIDATES)).split(",") if c]
assert CANDIDATES and all(c in ALL_CANDIDATES for c in CANDIDATES), CANDIDATES
TARGETS = ["darwin-arm64", "linux-arm64", "linux-x64", "windows-x64"]
TIME_BIN = "/usr/bin/time"


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_offset():
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def exe_name(target):
    return "heimdall-proto.exe" if target.startswith("windows") else "heimdall-proto"


def artifact_dir(cand, target):
    return PROTO / cand / "dist" / target


def artifact_path(cand, target):
    return artifact_dir(cand, target) / exe_name(target)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(cand):
    return json.loads((PROTO / cand / "dist" / "manifest.json").read_text())


def load_pyte():
    import glob
    for sp in glob.glob(str(REPO / "tests" / "g02" / ".venv" / "lib" / "python*" / "site-packages")):
        if sp not in sys.path:
            sys.path.insert(0, sp)
    import pyte
    return pyte


def run_text(argv, timeout=20):
    """Run a fixed, non-secret inspection command; return (rc, stdout, stderr) text."""
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"})
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- statistics
def percentile(sorted_vals, q):
    """Linear-interpolation percentile (method 7), q in [0,100]."""
    n = len(sorted_vals)
    if n == 0:
        return None
    if n == 1:
        return sorted_vals[0]
    pos = (n - 1) * q / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def summarize(vals, ndigits=3, boot=2000, seed=20261003):
    """p50/p95 with bootstrap 95% CIs, plus min/max/mean/stdev/MAD.  vals: list of floats."""
    vals = [float(v) for v in vals if v is not None]
    n = len(vals)
    if n == 0:
        return {"n": 0}
    s = sorted(vals)
    out = {"n": n, "min": s[0], "p50": percentile(s, 50), "p90": percentile(s, 90),
           "p95": percentile(s, 95), "max": s[-1], "mean": statistics.fmean(s),
           "stdev": statistics.stdev(s) if n > 1 else 0.0}
    med = out["p50"]
    out["mad"] = percentile(sorted(abs(v - med) for v in s), 50)
    if n >= 5 and boot:
        rng = random.Random(seed)
        p50s, p95s = [], []
        for _ in range(boot):
            r = sorted(rng.choice(s) for _ in range(n))
            p50s.append(percentile(r, 50))
            p95s.append(percentile(r, 95))
        p50s.sort()
        p95s.sort()
        out["p50_ci95"] = [percentile(p50s, 2.5), percentile(p50s, 97.5)]
        out["p95_ci95"] = [percentile(p95s, 2.5), percentile(p95s, 97.5)]
    return round_floats(out, ndigits)


def round_floats(o, nd):
    if isinstance(o, float):
        return round(o, nd)
    if isinstance(o, dict):
        return {k: round_floats(v, nd) for k, v in o.items()}
    if isinstance(o, list):
        return [round_floats(v, nd) for v in o]
    return o


# ---------------------------------------------------------------- environment
def capture_hardware():
    hw = {}
    for key in ("hw.model", "hw.memsize", "machdep.cpu.brand_string", "kern.osversion", "hw.ncpu",
                "hw.physicalcpu", "hw.perflevel0.logicalcpu", "hw.perflevel1.logicalcpu", "kern.boottime"):
        rc, out, _ = run_text(["/usr/sbin/sysctl", "-n", key])
        hw[key] = out.strip() if rc == 0 else None
    rc, out, _ = run_text(["/usr/bin/sw_vers"])
    hw["sw_vers"] = dict(l.split(":", 1) for l in out.strip().splitlines() if ":" in l)
    hw["sw_vers"] = {k.strip(): v.strip() for k, v in hw["sw_vers"].items()}
    rc, out, _ = run_text(["/usr/bin/uname", "-srvm"])
    hw["uname"] = out.strip()
    return hw


def capture_load(label):
    """uptime + power/thermal context.  No process listings."""
    d = {"label": label, "at": utc()}
    rc, out, _ = run_text(["/usr/bin/uptime"])
    d["uptime"] = out.strip()
    d["loadavg"] = list(os.getloadavg())
    rc, out, _ = run_text(["/usr/bin/pmset", "-g", "batt"])
    d["pmset_batt_first_line"] = out.splitlines()[0] if out else None
    rc, out, _ = run_text(["/usr/bin/pmset", "-g"])
    d["low_power_mode"] = next((l.split()[-1] for l in out.splitlines() if "lowpowermode" in l.lower()), None)
    rc, out, _ = run_text(["/usr/bin/pmset", "-g", "therm"])
    d["pmset_therm"] = " | ".join(l.strip() for l in out.splitlines() if l.strip())[:300]
    rc, out, _ = run_text(["/usr/bin/top", "-l", "2", "-n", "0", "-s", "1"], timeout=30)
    cpu = [l for l in out.splitlines() if l.startswith("CPU usage")]
    d["top_cpu_usage_sample2"] = cpu[-1] if cpu else None
    return d


def dir_gzip_size(paths_rel, base):
    """Size of a tar.gz (level 9) of the listed files, relative to base; streamed, not stored."""
    class Counter(io.RawIOBase):
        n = 0

        def writable(self):
            return True

        def write(self, b):
            self.n += len(b)
            return len(b)

    c = Counter()
    gz = gzip.GzipFile(fileobj=c, mode="wb", compresslevel=9, mtime=0)
    with tarfile.open(fileobj=gz, mode="w") as tf:
        for rel in paths_rel:
            tf.add(str(Path(base) / rel), arcname=rel, recursive=False)
    gz.close()
    return c.n


def artifact_inventory():
    """Per candidate/target: files (exe + sidecars) with bytes + sha256 (measured now) vs manifest."""
    inv = {}
    for cand in CANDIDATES:
        man = load_manifest(cand)
        by_target = {t["target"]: t for t in man["targets"]}
        inv[cand] = {}
        for tgt in TARGETS:
            m = by_target.get(tgt)
            d = artifact_dir(cand, tgt)
            rec = {"manifest_entry": m, "present": d.is_dir()}
            if not d.is_dir():
                rec["note"] = "artifact directory missing"
                inv[cand][tgt] = rec
                continue
            files = []
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    rel = str(p.relative_to(d))
                    files.append({"path": rel, "bytes": p.stat().st_size, "sha256": sha256_file(p)})
            rec["files"] = files
            rec["total_bytes_on_disk"] = sum(f["bytes"] for f in files)
            exe = next((f for f in files if f["path"] == exe_name(tgt)), None)
            rec["exe_bytes"] = exe["bytes"] if exe else None
            rec["sidecar_bytes"] = sum(f["bytes"] for f in files if exe and f["path"] != exe["path"])
            rec["sidecar_paths"] = [f["path"] for f in files if exe and f["path"] != exe["path"]]
            mm = {}
            if m:
                mm[m["path"].split("/", 1)[1]] = (m["bytes"], m["sha256"])
                for s in m.get("sidecars", []):
                    mm[s["path"].split("/", 1)[1]] = (s["bytes"], s["sha256"])
            rec["manifest_matches_disk"] = bool(m) and all(
                (f["path"] in mm and mm[f["path"]] == (f["bytes"], f["sha256"])) for f in files) \
                and len(mm) == len(files)
            rec["tar_gz9_bytes"] = dir_gzip_size([f["path"] for f in files], d)
            inv[cand][tgt] = rec
    return inv


# ---------------------------------------------------------------- pty session
STATUS_RE = re.compile(r"(?<![\d.])(\d+)/(\d+)(?!\d)")


def status_of(lines):
    for line in reversed(lines):
        m = STATUS_RE.search(line)
        if m:
            return int(m.group(1)), int(m.group(2)), line
    return None


class Pty:
    """Command as a session leader on a fresh pty, screen kept by pyte.  Times are perf_counter_ns."""

    def __init__(self, pyte, argv, env, cwd, rows=24, cols=80, stderr=subprocess.PIPE):
        sys.path.insert(0, str(REPO / "tests" / "g02"))
        from harness_lib import make_screen  # answers DA/DSR queries like the conformance harness
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.screen = make_screen(pyte, cols, rows, self.master)
        self.stream = pyte.ByteStream(self.screen)
        self.raw = bytearray()
        self.closed = False
        self.t0 = time.perf_counter_ns()
        self.proc = subprocess.Popen(
            argv, env=env, cwd=cwd, stdin=self.slave, stdout=self.slave, stderr=stderr,
            start_new_session=True, preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        self.t_spawned = time.perf_counter_ns()
        os.close(self.slave)
        self.slave = None
        self.first_byte_ns = None
        self.err = b""

    def lines(self):
        return [l.rstrip() for l in self.screen.display]

    def text(self):
        return "\n".join(self.lines())

    def read_chunk(self, timeout):
        """Wait up to timeout s for output; feed pyte; return (arrival_ns, nbytes) or None."""
        r, _, _ = select.select([self.master], [], [], max(0.0, timeout))
        if not r:
            return None
        try:
            data = os.read(self.master, 65536)
        except OSError:
            data = b""
        t = time.perf_counter_ns()
        if not data:
            return (t, 0)
        if self.first_byte_ns is None:
            self.first_byte_ns = t
        self.raw += data
        try:
            self.stream.feed(data)
        except Exception:  # an emulator problem must not abort the measurement
            pass
        return (t, len(data))

    def wait_until(self, pred, timeout, t_ref_ns):
        """Return dict {ms_to_update, ms_to_first_byte(after t_ref)} when pred() true else None.

        ms_to_update uses the arrival time of the chunk after which pred became true (so emulator
        parse time is not counted); pred is evaluated after each chunk.
        """
        end = time.perf_counter() + timeout
        first_after = None
        if pred():
            return {"ms_to_update": 0.0, "ms_to_first_byte": None, "bytes": 0}
        nbytes = 0
        while True:
            left = end - time.perf_counter()
            if left <= 0:
                return None
            got = self.read_chunk(left)
            if got is None:
                return None
            t, n = got
            if n == 0:       # EOF
                return None
            nbytes += n
            if first_after is None and t >= t_ref_ns:
                first_after = t
            if pred():
                return {"ms_to_update": (t - t_ref_ns) / 1e6,
                        "ms_to_first_byte": (first_after - t_ref_ns) / 1e6 if first_after else None,
                        "bytes": nbytes}

    def drain(self, secs):
        end = time.perf_counter() + secs
        while True:
            left = end - time.perf_counter()
            if left <= 0:
                return
            got = self.read_chunk(left)
            if got is not None and got[1] == 0:
                return

    def send(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        t = time.perf_counter_ns()
        os.write(self.master, data)
        return t

    def finish(self, quit_key=b"q", wait=3.0):
        """Quit, drain until exit, force-kill our own Popen if it hangs.  Returns (rc, forced, stderr)."""
        forced = False
        rc = self.proc.poll()
        if rc is None:
            try:
                os.write(self.master, quit_key)
            except OSError:
                pass
            end = time.monotonic() + wait
            while self.proc.poll() is None and time.monotonic() < end:
                self.read_chunk(0.02)
            if self.proc.poll() is None:
                forced = True
                self.proc.kill()           # exact Popen object we started
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        self.drain(0.02)
        rc = self.proc.returncode
        try:
            if self.proc.stderr is not None:
                self.err = self.proc.stderr.read()
                self.proc.stderr.close()
        except Exception:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass
        self.closed = True
        return rc, forced, self.err


def time_l_parse(stderr_text):
    """Parse /usr/bin/time -l (macOS) output: bytes for max RSS / peak footprint, seconds for cpu."""
    out = {}
    m = re.search(r"^\s*([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", stderr_text, re.M)
    if m:
        out["real_s"], out["user_s"], out["sys_s"] = (float(m.group(i)) for i in (1, 2, 3))
    m = re.search(r"^\s*(\d+)\s+maximum resident set size", stderr_text, re.M)
    if m:
        out["max_rss_bytes"] = int(m.group(1))
    m = re.search(r"^\s*(\d+)\s+peak memory footprint", stderr_text, re.M)
    if m:
        out["peak_footprint_bytes"] = int(m.group(1))
    return out


def alias_list(path):
    import tomllib
    return [d["alias"] for d in tomllib.loads(Path(path).read_text(encoding="utf-8"))["destinations"]]


def host_list(path):
    import tomllib
    return [d["host"] for d in tomllib.loads(Path(path).read_text(encoding="utf-8"))["destinations"]]


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")
