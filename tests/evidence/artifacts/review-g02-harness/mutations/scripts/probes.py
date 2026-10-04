#!/usr/bin/env python3
"""Reviewer probes: show that each reviewer mutation is an observable contract defect.

Each probe runs the unmutated reference copy and the mutant under the same input, inside a private
sandbox (own HOME/TMPDIR/cwd, no SSH_AUTH_SOCK), and records exit codes and the deciding observation.
Run with the harness venv python (pyte needed for the TUI probes).
"""
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path("<repo>")
sys.path.insert(0, str(REPO / "tests" / "g02"))
import harness_lib as H  # noqa: E402

BIN = "/tmp/hm-review-mut/reference_impl.py"
PY = sys.executable
SB = Path(tempfile.mkdtemp(prefix="hmrv-", dir="/tmp"))
HOME, TMP = SB / "home", SB / "tmp"
HOME.mkdir()
TMP.mkdir()
RESULTS = []


def env(mut=None, extra=None):
    e = {"PATH": os.path.dirname(PY) + ":/usr/bin:/bin", "HOME": str(HOME), "TMPDIR": str(TMP),
         "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TERM": "xterm-256color"}
    if mut:
        e["REV_MUTATE"] = mut
    e.update(extra or {})
    return e


def run(argv, mut=None, timeout=30, extra=None, cwd=None, stdin=subprocess.DEVNULL):
    t0 = time.monotonic()
    p = subprocess.run([BIN] + argv, env=env(mut, extra), cwd=cwd or str(SB), stdin=stdin, capture_output=True,
                       timeout=timeout)
    return p.returncode, p.stdout, p.stderr, round(time.monotonic() - t0, 3)


def record(name, base, mut, deciding, defect):
    RESULTS.append({"mutation": name, "unmutated": base, "mutant": mut, "deciding_observation": deciding,
                    "observable_defect": defect})
    print("%-36s defect=%s  %s" % (name, defect, deciding), flush=True)


# ------------------------------------------------------------------ agent
class Agent:
    """One-shot AF_UNIX server answering the first request with `chunks` (list of (bytes, delay_s))."""

    def __init__(self, chunks, close=False):
        self.path = str(SB / ("a%d.sock" % (len(RESULTS) * 10 + int(time.time() * 1000) % 1000)))
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(self.path)
        self.s.listen(1)
        self.chunks, self.close = chunks, close
        self.t = threading.Thread(target=self.serve, daemon=True)
        self.t.start()

    def serve(self):
        c, _ = self.s.accept()
        c.recv(64)
        try:
            for data, delay in self.chunks:
                time.sleep(delay)
                c.sendall(data)
            if not self.close:
                time.sleep(30)
        except OSError:
            pass
        finally:
            c.close()
            self.s.close()


def ss(b):
    return struct.pack(">I", len(b)) + b


def frame(p):
    return struct.pack(">I", len(p)) + p


BLOB = ss(b"ssh-ed25519") + ss(bytes(range(32)))


def agent_probe(name, chunks, extra=(), timeout=30, close=False):
    out = {}
    for label, m in (("unmutated", None), ("mutant", name)):
        a = Agent(chunks, close=close)
        rc, so, se, dt = run(["agent", "list", "--socket", a.path, "--json"] + list(extra), mut=m, timeout=timeout)
        try:
            code = json.loads(so).get("code")
        except ValueError:
            code = None
        out[label] = {"exit": rc, "code": code, "seconds": dt,
                      "stderr_has_traceback": b"Traceback" in se}
    return out


def agent_probes():
    # zero-length frame
    o = agent_probe("agent_zero_frame_crash", [(struct.pack(">I", 0), 0)])
    record("agent_zero_frame_crash", o["unmutated"], o["mutant"], "length-0 frame", o["mutant"]["exit"] != 5)
    # type-12 frame of length 3
    o = agent_probe("agent_short_answer_crash", [(frame(b"\x0c\x00\x00"), 0)])
    record("agent_short_answer_crash", o["unmutated"], o["mutant"], "type-12 frame of 3 bytes", o["mutant"]["exit"] != 5)
    # nkeys 3, two keys present, frame ends cleanly after the second
    body = b"\x0c" + struct.pack(">I", 3) + (ss(BLOB) + ss(b"k")) * 2
    o = agent_probe("agent_nkeys_short_tolerated", [(frame(body), 0)])
    record("agent_nkeys_short_tolerated", o["unmutated"], o["mutant"], "nkeys=3 with 2 keys in the frame",
           o["mutant"]["code"] == "AGENT_OK")
    # key_blob whose inner key-type string length exceeds the blob
    bad_blob = struct.pack(">I", 500) + b"ssh-ed25519"
    body = b"\x0c" + struct.pack(">I", 1) + ss(bad_blob) + ss(b"c")
    o = agent_probe("agent_keyblob_inner_clamp", [(frame(body), 0)])
    record("agent_keyblob_inner_clamp", o["unmutated"], o["mutant"],
           "key_blob inner string length 500 > blob (contract does not name this case: ambiguity)",
           o["mutant"]["code"] == "AGENT_OK")
    # drip: a complete reply delivered one byte every 0.15 s; --timeout-ms 1000
    reply = frame(b"\x0c" + struct.pack(">I", 1) + ss(BLOB) + ss(b"drip"))
    chunks = [(reply[i:i + 1], 0.15) for i in range(len(reply))]
    o = agent_probe("agent_per_read_timeout", chunks, extra=("--timeout-ms", "1000"), timeout=60)
    record("agent_per_read_timeout", o["unmutated"], o["mutant"],
           "reply of %d bytes dripped at 1 byte/150 ms with --timeout-ms 1000" % len(reply),
           o["mutant"]["code"] != "AGENT_UNAVAILABLE" or o["mutant"]["seconds"] > 3)
    # default timeout: silent agent, no --timeout-ms
    out = {}
    for label, m in (("unmutated", None), ("mutant", "agent_default_timeout_60s")):
        a = Agent([], close=False)
        try:
            rc, so, se, dt = run(["agent", "list", "--socket", a.path, "--json"], mut=m, timeout=12)
            out[label] = {"exit": rc, "seconds": dt, "timed_out_at_12s": False}
        except subprocess.TimeoutExpired:
            out[label] = {"exit": None, "seconds": 12, "timed_out_at_12s": True}
    record("agent_default_timeout_60s", out["unmutated"], out["mutant"], "silent agent, default --timeout-ms",
           out["mutant"]["timed_out_at_12s"])


# ------------------------------------------------------------------ profile
def profile_probes():
    fix = REPO / "tests" / "fixtures" / "g02" / "profiles"
    out = {}
    for label, m in (("unmutated", None), ("mutant", "type_error_echoes_value")):
        rc, so, se, _ = run(["profile", "show", "--file", str(fix / "invalid-port.toml"), "--json"], mut=m)
        out[label] = {"exit": rc, "value_70000_echoed": b"70000" in so + se}
    record("type_error_echoes_value", out["unmutated"], out["mutant"], "invalid-port.toml value 70000 in output",
           out["mutant"]["value_70000_echoed"])
    p = SB / "malformed-secret.toml"
    marker = "REVIEW_SECRET_MARKER_" + os.urandom(4).hex()
    p.write_text('schema_version = 1\nname = "x"\nrevision = 1\npassword = "%s" oops\n' % marker)
    out = {}
    for label, m in (("unmutated", None), ("mutant", "malformed_echo_source_line")):
        rc, so, se, _ = run(["profile", "show", "--file", str(p), "--json"], mut=m)
        out[label] = {"exit": rc, "secret_marker_in_output": marker.encode() in so + se}
    record("malformed_echo_source_line", out["unmutated"], out["mutant"],
           "malformed TOML whose error line holds a secret-like value", out["mutant"]["secret_marker_in_output"])
    out = {}
    for label, m in (("unmutated", None), ("mutant", "schema_version_warning_echoes_name")):
        rc, so, se, _ = run(["profile", "show", "--file", str(fix / "invalid-schema-version.toml"), "--json"], mut=m)
        w = json.loads(so).get("warnings")
        out[label] = {"exit": rc, "warnings": w, "name_value_in_warning": any("homelab" in x for x in w)}
    record("schema_version_warning_echoes_name", out["unmutated"], out["mutant"], "warning text",
           out["mutant"]["name_value_in_warning"])
    # K15 shape not sampled by the harness: 1 MiB of [[destinations]] tables
    p = SB / "k15-many-destinations.toml"
    head = 'schema_version = 1\nname = "x"\nrevision = 1\n'
    parts, n = [head], 0
    size = len(head)
    while True:
        t = '[[destinations]]\nid = "i%d"\nalias = "a%d"\nhost = "h"\naccount = "u"\n' % (n, n)
        if size + len(t) > 1048576:
            break
        parts.append(t)
        size += len(t)
        n += 1
    p.write_text("".join(parts))
    out = {}
    for label, m in (("unmutated", None), ("mutant", "dup_check_quadratic")):
        rep = SB / ("rss-%s.json" % label)
        t0 = time.monotonic()
        r = subprocess.run([PY, str(REPO / "tests/g02/rss_wrap.py"), str(rep), "--", BIN, "profile", "show", "--file",
                            str(p), "--json"], env=env(m), cwd=str(SB), capture_output=True, timeout=120)
        js = json.loads(rep.read_text())
        out[label] = {"exit": r.returncode, "wall_s": js.get("wall_s"),
                      "maxrss_mib": round(js["maxrss_bytes"] / 1048576, 1), "destinations": n,
                      "bytes": p.stat().st_size}
    record("dup_check_quadratic", out["unmutated"], out["mutant"],
           "K15: 1 MiB profile of %d [[destinations]] tables (shape not in the harness's 13)" % n,
           (out["mutant"]["wall_s"] or 0) >= 2.0)
    RESULTS[-1]["note"] = "unmutated reference K15 verdict on this shape: wall %.2f s (bound 2 s)" % out["unmutated"]["wall_s"]
    # hard-coded /tmp
    tgt = Path("/tmp/hm-review-k11-%d.cache" % os.getuid())
    out = {}
    for label, m in (("unmutated", None), ("mutant", "profile_tmp_hardcoded")):
        if tgt.exists():
            tgt.unlink()
        run(["profile", "show", "--file", str(fix / "homelab.toml"), "--json"], mut=m)
        out[label] = {"file_written_in_/tmp": tgt.exists()}
    if tgt.exists():
        tgt.unlink()
    record("profile_tmp_hardcoded", out["unmutated"], out["mutant"], "file created in /tmp (outside TMPDIR)",
           out["mutant"]["file_written_in_/tmp"])


# ------------------------------------------------------------------ run
TRAP = r"""
import os, signal, sys, time
seen = []
signal.signal(signal.SIGINT, lambda s, f: seen.append(s))
open(sys.argv[1], 'w').write('1')
end = time.time() + 5
while time.time() < end and len(seen) < 2:
    time.sleep(0.01)
time.sleep(0.5)
open(sys.argv[2], 'w').write(str(len(seen)))
os._exit(7)
"""


def run_probes():
    out = {}
    for label, m in (("unmutated", None), ("mutant", "run_second_signal_exits")):
        d = Path(tempfile.mkdtemp(dir=SB))
        ready, done = d / "ready", d / "done"
        p = subprocess.Popen([BIN, "run", "--", PY, "-c", TRAP, str(ready), str(done)], env=env(m), cwd=str(SB),
                             stdin=subprocess.DEVNULL, start_new_session=True)
        end = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < end:
            time.sleep(0.01)
        time.sleep(0.05)
        os.kill(p.pid, signal.SIGINT)
        time.sleep(0.2)
        if p.poll() is None:
            os.kill(p.pid, signal.SIGINT)
        rc = p.wait(timeout=15)
        child_done_before_exit = done.exists()
        time.sleep(1.0)
        out[label] = {"proto_exit": rc, "child_finished_before_proto_exit": child_done_before_exit,
                      "child_finished_eventually": done.exists()}
    record("run_second_signal_exits", out["unmutated"], out["mutant"], "two SIGINTs 200 ms apart to the proto pid",
           out["mutant"]["proto_exit"] != 7)
    # child's view of its fds and terminal under a pty
    probe = ("import os, json, sys\nr = {'isatty': [os.isatty(i) for i in (0, 1, 2)], 'sid_eq_parent': os.getsid(0) == os.getsid(os.getppid())}\n"
             "try:\n    os.close(os.open('/dev/tty', os.O_RDWR)); r['dev_tty'] = True\nexcept OSError:\n    r['dev_tty'] = False\n"
             "open(sys.argv[1], 'w').write(json.dumps(r))\n")
    import pyte  # noqa
    for name in ("run_pump_output", "run_child_new_session"):
        out = {}
        for label, m in (("unmutated", None), ("mutant", name)):
            f = SB / ("tty-%s-%s.json" % (name, label))
            s = H.PtySession(pyte, [BIN, "run", "--", PY, "-c", probe, str(f)], env(m), str(SB), 24, 80)
            s.wait_exit(10)
            s.close()
            out[label] = json.loads(f.read_text()) if f.exists() else None
        if name == "run_pump_output":
            defect = out["mutant"] and out["mutant"]["isatty"][1:] != [True, True]
            deciding = "child's isatty(stdout, stderr) under a pty"
        else:
            defect = out["mutant"] and not out["mutant"]["dev_tty"]
            deciding = "child can open /dev/tty (controlling terminal) under a pty (contract: 'inherits' does not name the ctty)"
        record(name, out["unmutated"], out["mutant"], deciding, bool(defect))
    out = {}
    for label, m in (("unmutated", None), ("mutant", "run_meta_tmp_sibling")):
        d = Path(tempfile.mkdtemp(dir=SB))
        run(["run", "--meta-file", str(d / "meta.json"), "--", PY, "-c", "pass"], mut=m)
        out[label] = {"files_in_meta_dir": sorted(x.name for x in d.iterdir())}
    record("run_meta_tmp_sibling", out["unmutated"], out["mutant"], "files next to --meta-file",
           out["mutant"]["files_in_meta_dir"] != ["meta.json"])


# ------------------------------------------------------------------ tui
def tui_probes():
    import pyte
    fix = REPO / "tests" / "fixtures" / "g02" / "profiles"
    out = {}
    for label, m in (("unmutated", None), ("mutant", "tui_narrow_threshold_60")):
        s = H.PtySession(pyte, [BIN, "tui", "--file", str(fix / "homelab.toml")], env(m), str(SB), 24, 55)
        s.wait_for(lambda x: "3/3" in x.text(), 10)
        s.settle(0.3)
        out[label] = {"cols": 55, "shows_account_at_host": "@" in s.text()}
        s.send("q")
        s.wait_exit(3)
        s.close()
    record("tui_narrow_threshold_60", out["unmutated"], out["mutant"], "55-column terminal (contract: host shown at >= 50)",
           not out["mutant"]["shows_account_at_host"])
    out = {}
    for label, m in (("unmutated", None), ("mutant", "tui_status_filter_only_while_typing")):
        s = H.PtySession(pyte, [BIN, "tui", "--file", str(fix / "homelab.toml")], env(m), str(SB), 24, 80)
        s.wait_for(lambda x: "3/3" in x.text(), 10)
        s.send("/")
        s.settle(0.1)
        s.send("nas")
        s.wait_for(lambda x: "1/3" in x.text(), 5)
        s.key("enter")
        s.settle(0.3)
        st = [l for l in s.lines() if "1/3" in l]
        out[label] = {"status_line_after_enter": st[-1].strip() if st else None,
                      "filter_text_shown": bool(st) and "nas" in st[-1]}
        s.key("ctrl-c")
        s.wait_exit(3)
        s.close()
    record("tui_status_filter_only_while_typing", out["unmutated"], out["mutant"],
           "status line after Enter keeps filter 'nas' active", not out["mutant"]["filter_text_shown"])
    out = {}
    for label, m in (("unmutated", None), ("mutant", "tui_slow_filter")):
        s = H.PtySession(pyte, [BIN, "tui", "--file", str(fix / "large-100.toml")], env(m), str(SB), 24, 80)
        s.wait_for(lambda x: "100/100" in x.text(), 10)
        s.send("/")
        s.settle(0.1)
        t0 = time.monotonic()
        s.send("7")
        lat = s.wait_for(lambda x: "19/100" in x.text(), 5, t_start=t0)
        out[label] = {"keystroke_to_update_ms": None if lat is None else round(lat * 1000)}
        s.key("ctrl-c")
        s.wait_exit(3)
        s.close()
    record("tui_slow_filter", out["unmutated"], out["mutant"], "large-100 keystroke-to-update latency",
           (out["mutant"]["keystroke_to_update_ms"] or 0) >= 500)
    # K16 by TERM: tripwire tmux on PATH, TERM=tmux-256color
    trip = SB / "trip"
    trip.mkdir(exist_ok=True)
    log = SB / "trip.log"
    (trip / "tmux").write_text("#!%s\nopen(%r, 'a').write('tmux\\n')\n" % (PY, str(log)))
    os.chmod(trip / "tmux", 0o755)
    out = {}
    for label, m in (("unmutated", None), ("mutant", "tui_tmux_probe_by_term")):
        if log.exists():
            log.unlink()
        e = env(m, {"TERM": "tmux-256color", "PATH": "%s:%s:/usr/bin:/bin" % (trip, os.path.dirname(PY))})
        s = H.PtySession(pyte, [BIN, "tui", "--file", str(fix / "homelab.toml")], e, str(SB), 24, 80)
        s.wait_for(lambda x: "3/3" in x.text(), 10)
        s.send("q")
        s.wait_exit(3)
        s.close()
        out[label] = {"tripwire_tmux_ran": log.exists()}
    record("tui_tmux_probe_by_term", out["unmutated"], out["mutant"], "TERM=tmux-256color with a tmux tripwire on PATH",
           out["mutant"]["tripwire_tmux_ran"])


def main():
    try:
        agent_probes()
        profile_probes()
        run_probes()
        tui_probes()
    finally:
        H.kill_tracked()
        shutil.rmtree(SB, ignore_errors=True)
    Path(sys.argv[1]).write_text(json.dumps(RESULTS, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
