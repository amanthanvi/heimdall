#!/usr/bin/env python3
"""One soak lane's workload, sampler and fault schedule (m08-plan U5a; ADR-0014 section 6).

Started by lane.sh inside the soak container, as the lane's unprivileged account, after
the lane's world exists. Standard library only.

Every tick it: runs `heimdall status` and `heimdall inspect capabilities`; makes one
ordinary `ssh <alias> true` login through the projection (the decoy agent at
SSH_AUTH_SOCK, so only the projected configuration can succeed) and one
`heimdall connect <alias>` with stdin closed, which goes through the runtime's ensure and
launch path; samples the runtime process
(/proc) and the account's files; applies and lifts the faults the seeded schedule says;
appends one line to samples.ndjson; and rewrites status.json (the heartbeat).

Faults, from a schedule generated once from the seed, so a seed replays exactly:
  lane S (steady):    sshd_down, agent_down                  (dependency faults only)
  lane L (lifecycle): the same, plus service_stop and runtime_kill
While the fixture sshd is down, a counting listener takes its port on 127.0.0.1 and records
every connection attempt with its time: attempts beyond this harness's own login probes
are Heimdall's unrequested retries.

It stops itself, with state FAILED and a reason, on: a login that succeeds while the
provider agent is down (Heimdall used a credential it should not hold); resident memory
above 300 MiB; more than 1024 descriptors; a panic line in a Heimdall log; three
consecutive unexpected login failures after recovery; the output directory above its budget.

Version 2 samples the account's files by kind (database, write-ahead log, shared-memory
file, logs, backups, other), because version 1's rehearsal saw the total grow and could not
say which file.

NOT COVERED by this version (m08-plan section 6.2 names them): grants with deadlines,
explicit stops and expiry probes; the managed lane; the runner lane; update and rollback;
the full-volume and damaged-file faults; an idle TUI; canary planting. The record of a run
made with this version must say so.
"""
import argparse
import json
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import time

RSS_STOP_KIB = 300 * 1024
FD_STOP = 1024
OUT_BUDGET = 256 * 1024 * 1024
FAULT_TICKS = 3
CYCLE_TICKS = 20


def iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def schedule(lane, seed, ticks):
    """[(start_tick, end_tick, fault)], deterministic for (lane, seed, ticks)."""
    rng = random.Random(f"{lane}:{seed}")
    faults = ["sshd_down", "agent_down"] + (["service_stop", "runtime_kill"] if lane == "L" else [])
    out, t = [], CYCLE_TICKS // 2
    while t + FAULT_TICKS < ticks:
        order = faults[:]
        rng.shuffle(order)
        for f in order:
            start = t + rng.randrange(0, 3)
            if start + FAULT_TICKS >= ticks:
                break
            dur = FAULT_TICKS if f in ("sshd_down", "agent_down") else 1
            out.append((start, start + dur, f))
            t = start + dur + 3
        t += CYCLE_TICKS // 2
    return out


class Counter(threading.Thread):
    """Accepts and closes connections on the fixture sshd's port while it is down."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.sock.settimeout(0.5)
        self.times, self.stop = [], False

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.times.append(time.monotonic())
            conn.close()

    def close(self):
        self.stop = True
        self.join(2)
        self.sock.close()


class Lane:
    def __init__(self, a):
        self.a = a
        self.env = dict(os.environ, SSH_AUTH_SOCK=os.path.join(a.scratch, "decoy.sock"))
        self.sshd_pid = a.sshd_pid
        self.port = self._port()
        self.counter = None
        self.own_probes_down = 0
        self.samples = open(os.path.join(a.out, "samples.ndjson"), "a", encoding="utf-8")
        self.events = open(os.path.join(a.out, "events.ndjson"), "a", encoding="utf-8")
        self.t0 = time.monotonic()
        self.started = iso()
        self.unexpected_run = 0
        self.totals = {"ticks": 0, "logins_ok": 0, "logins_failed_expected": 0, "logins_failed_unexpected": 0,
                       "connects_ok": 0, "connects_failed": 0, "faults": 0, "unrequested_attempts": 0, "min_attempt_gap_s": None,
                       "recoveries_on_demand": 0, "recoveries_by_explicit_start": 0}

    def _port(self):
        with open(self.a.sshd_config, encoding="utf-8") as fh:
            for line in fh:
                p = line.split()
                if len(p) == 2 and p[0].lower() == "port":
                    return int(p[1])
        raise SystemExit("no Port in the fixture sshd configuration")

    def event(self, kind, **kw):
        self.events.write(json.dumps({"t": round(time.monotonic() - self.t0, 2), "at": iso(), "event": kind, **kw}) + "\n")
        self.events.flush()

    # ---- product calls
    def hm(self, *args, timeout=60):
        t = time.monotonic()
        try:
            p = subprocess.run([self.a.heimdall, "--json", "--non-interactive", *args], capture_output=True,
                               text=True, timeout=timeout, stdin=subprocess.DEVNULL, env=self.env)
            code, out = p.returncode, p.stdout
        except subprocess.TimeoutExpired:
            code, out = -1, ""
        try:
            doc = json.loads(out) if out.strip() else None
        except ValueError:
            doc = None
        return code, doc, round((time.monotonic() - t) * 1000, 1)

    def login(self):
        t = time.monotonic()
        try:
            p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self.a.alias, "true"],
                               capture_output=True, timeout=30, stdin=subprocess.DEVNULL, env=self.env)
            ok = p.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        return ok, round((time.monotonic() - t) * 1000, 1)

    def runtime_pid(self):
        _, doc, _ = self.hm("service", "status")

        def find(v):
            if isinstance(v, dict):
                if isinstance(v.get("pid"), int):
                    return v["pid"]
                for x in v.values():
                    r = find(x)
                    if r:
                        return r
            return None
        pid = find(doc)
        # The runtime may be non-dumpable, which hides /proc/<pid>/exe and fd from its own
        # account. Its identity is then: the pid the runtime itself advertised over its
        # owner-only endpoint, owned by this account, with the executable's name.
        try:
            if pid and os.stat(f"/proc/{pid}").st_uid == os.getuid():
                with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                    if fh.read().strip() == os.path.basename(self.a.heimdall)[:15]:
                        return pid
        except OSError:
            pass
        return None

    # ---- sampling
    def sample(self, pid):
        s = {"pid": pid}
        if pid:
            try:
                with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("VmRSS:"):
                            s["rss_kib"] = int(line.split()[1])
                        elif line.startswith("Threads:"):
                            s["threads"] = int(line.split()[1])
                try:
                    s["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
                except OSError:
                    s["fds"] = None  # non-dumpable: the root-side sampler in entry.sh counts them
                with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                    f = fh.read().rsplit(")", 1)[1].split()
                s["cpu_ticks"] = int(f[11]) + int(f[12])
                s["start_ticks"] = int(f[19])
            except (OSError, ValueError, IndexError):
                s["pid"] = None
        nbytes = nfiles = 0
        panic = False
        sizes = {"db": 0, "wal": 0, "shm": 0, "log": 0, "backups": 0, "other": 0}
        home = os.path.expanduser("~")
        for base, dirs, names in os.walk(home):
            if base == home and "s" in dirs:
                dirs.remove("s")
            for n in names:
                full = os.path.join(base, n)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                nbytes += st.st_size
                nfiles += 1
                # Which file grows (ADR-0014 section 6.2 item 4): the database, its write-ahead
                # log and shared-memory file, the logs, the backups, everything else.
                kind = ("wal" if n.endswith(".db-wal") else "shm" if n.endswith(".db-shm")
                        else "db" if n.endswith(".db") else "log" if n.startswith("heimdall.log")
                        else "backups" if os.sep + "backups" in base else "other")
                sizes[kind] += st.st_size
                if n.startswith("heimdall.log") and st.st_size < 32 * 1024 * 1024:
                    try:
                        with open(full, "rb") as fh:
                            panic = panic or b"panicked at" in fh.read()
                    except OSError:
                        pass
        s["home_bytes"], s["home_files"], s["panic_in_log"] = nbytes, nfiles, panic
        s["bytes"] = sizes
        return s

    # ---- faults
    def sshd_stop(self):
        os.kill(self.sshd_pid, signal.SIGTERM)
        try:
            os.waitpid(self.sshd_pid, 0)
        except ChildProcessError:
            time.sleep(0.5)
        self.counter = Counter(self.port)
        self.counter.start()
        self.own_probes_down = 0

    def sshd_start(self):
        if self.counter:
            self.counter.close()
            times = self.counter.times
            extra = max(0, len(times) - self.own_probes_down)
            self.totals["unrequested_attempts"] += extra
            gaps = [b - a for a, b in zip(times, times[1:])]
            if gaps:
                g = round(min(gaps), 3)
                cur = self.totals["min_attempt_gap_s"]
                self.totals["min_attempt_gap_s"] = g if cur is None else min(cur, g)
            self.event("sshd_outage_attempts", total=len(times), own_probes=self.own_probes_down, unrequested=extra,
                       min_gap_s=round(min(gaps), 3) if gaps else None)
            self.counter = None
        p = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", self.a.sshd_config, "-E", self.a.sshd_log],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.sshd_pid = p.pid
        time.sleep(1)

    def agent_stop(self):
        with open(os.path.join(self.a.scratch, "agent.pid"), encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        # ssh-agent is non-dumpable, so its /proc/<pid>/exe is unreadable: check the name.
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                if fh.read().strip() == "ssh-agent" and os.stat(f"/proc/{pid}").st_uid == os.getuid():
                    os.kill(pid, signal.SIGTERM)
                    for _ in range(50):
                        if not os.path.exists(f"/proc/{pid}/comm"):
                            break
                        try:
                            os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            pass
                        time.sleep(0.1)
        except OSError:
            pass

    def agent_start(self):
        sock = os.path.join(self.a.scratch, "agent.sock")
        try:
            os.unlink(sock)
        except OSError:
            pass
        env = dict(os.environ, HOME=os.path.join(self.a.scratch, "agent-home"))
        p = subprocess.Popen(["ssh-agent", "-D", "-a", sock], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        with open(os.path.join(self.a.scratch, "agent.pid"), "w", encoding="utf-8") as fh:
            fh.write(str(p.pid))
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        subprocess.run(["ssh-add", "-q", os.path.join(self.a.scratch, "k0")], env=dict(os.environ, SSH_AUTH_SOCK=sock),
                       stdin=subprocess.DEVNULL, capture_output=True, check=False)

    def recover_runtime(self):
        """After a stop or a kill: does an ordinary login bring the runtime back by itself?"""
        if self.runtime_pid():
            # An earlier call in the fault's own tick (`heimdall connect`) already started it.
            self.totals["recoveries_on_demand"] += 1
            self.event("runtime_recovered", by="an earlier on-demand start (heimdall connect)")
            return
        ok, _ = self.login()
        subprocess.Popen([self.a.heimdall, "service", "run", "--detach"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env=self.env)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.runtime_pid():
                self.totals["recoveries_by_explicit_start"] += 1
                self.event("runtime_recovered", by="service run --detach", login_first=ok)
                return
            time.sleep(1)
        self.event("runtime_not_recovered")

    # ---- the loop
    def status(self, state, reason=None, last=None):
        doc = {"lane": self.a.lane, "state": state, "reason": reason, "started_at": self.started, "heartbeat_at": iso(),
               "elapsed_s": round(time.monotonic() - self.t0, 1), "planned_s": self.a.seconds, "seed": self.a.seed,
               "tick_s": self.a.tick, "totals": self.totals, "last_sample": last,
               "not_covered": "grants and expiry, stops, managed and runner lanes, update and rollback, "
                              "full-volume and damaged-file faults, idle TUI, canaries"}
        tmp = os.path.join(self.a.out, "status.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        os.replace(tmp, os.path.join(self.a.out, "status.json"))

    def run(self):
        a = self.a
        ticks = max(1, a.seconds // a.tick)
        plan = schedule(a.lane, a.seed, ticks)
        self.event("schedule", faults=[{"start": s, "end": e, "fault": f} for s, e, f in plan])
        active, verdict, reason, grace = {}, "DONE", None, 0
        for tick in range(ticks):
            begin = time.monotonic()
            for s, e, f in plan:
                if s == tick:
                    self.totals["faults"] += 1
                    self.event("fault_begin", fault=f)
                    if f == "sshd_down":
                        self.sshd_stop()
                    elif f == "agent_down":
                        self.agent_stop()
                    elif f == "service_stop":
                        self.hm("service", "stop")
                    elif f == "runtime_kill":
                        pid = self.runtime_pid()
                        if pid:
                            os.kill(pid, signal.SIGKILL)
                    active[f] = e
            for f, e in list(active.items()):
                if e == tick:
                    self.event("fault_end", fault=f)
                    if f == "sshd_down":
                        self.sshd_start()
                    elif f == "agent_down":
                        self.agent_start()
                    else:
                        self.recover_runtime()
                    del active[f]
                    grace = 2
            dependency_down = "sshd_down" in active or "agent_down" in active
            runtime_down = "service_stop" in active or "runtime_kill" in active
            c1, _, ms_status = self.hm("status")
            c2, _, ms_inspect = self.hm("inspect", "capabilities")
            ok, ms_login = self.login()
            c3, _, ms_connect = self.hm("connect", self.a.alias, "--allow-provider-interaction", timeout=45)
            self.totals["connects_ok" if c3 == 0 else "connects_failed"] += 1
            if c3 == 0 and "agent_down" in active:
                verdict, reason = "FAILED", "a connect succeeded while the provider agent was down"
            if "sshd_down" in active:
                self.own_probes_down += 1
            if "sshd_down" in active:
                self.own_probes_down += 1
            if ok:
                self.totals["logins_ok"] += 1
                self.unexpected_run = 0
                if "agent_down" in active:
                    verdict, reason = "FAILED", "a login succeeded while the provider agent was down"
            elif dependency_down or runtime_down or grace > 0:
                self.totals["logins_failed_expected"] += 1
            else:
                self.totals["logins_failed_unexpected"] += 1
                self.unexpected_run += 1
                if self.unexpected_run >= 3:
                    verdict, reason = "FAILED", "three consecutive unexpected login failures"
            grace = max(0, grace - 1)
            s = self.sample(None if runtime_down else self.runtime_pid())
            s.update({"t": round(time.monotonic() - self.t0, 2), "tick": tick, "login_ok": ok, "ms_login": ms_login,
                      "ms_status": ms_status, "ms_inspect": ms_inspect, "ms_connect": ms_connect,
                      "exit_status": c1, "exit_inspect": c2, "exit_connect": c3,
                      "faults": sorted(active)})
            self.samples.write(json.dumps(s) + "\n")
            self.samples.flush()
            self.totals["ticks"] = tick + 1
            if s.get("rss_kib", 0) > RSS_STOP_KIB:
                verdict, reason = "FAILED", "resident memory above 300 MiB"
            if (s.get("fds") or 0) > FD_STOP:
                verdict, reason = "FAILED", "more than 1024 descriptors"
            if s["panic_in_log"]:
                verdict, reason = "FAILED", "a panic line in a Heimdall log"
            if sum(os.path.getsize(os.path.join(a.out, f)) for f in os.listdir(a.out)) > OUT_BUDGET:
                verdict, reason = "FAILED", "the output directory is over its budget"
            if verdict == "FAILED":
                self.status("FAILED", reason, s)
                break
            self.status("RUNNING", None, s)
            time.sleep(max(0.0, a.tick - (time.monotonic() - begin)))
        # Leave nothing running: lift any fault, then stop what this lane started.
        if self.counter:
            self.counter.close()
        self.hm("service", "stop")
        for pid in (self.sshd_pid,):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        self.agent_stop()
        self.status(verdict, reason, None)
        return 0 if verdict == "DONE" else 1


def in_container():
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as fh:
            return any(k in fh.read() for k in ("docker", "containerd", "kubepods", "libpod"))
    except OSError:
        return False


def main():
    # Refuse outside a container (review M08-W0-R08): this starts and kills processes and
    # runs a release build.
    if not in_container():
        sys.stderr.write("refused: this runs only inside the M08 container (no container was detected)\n")
        return 2
    if any(k.startswith("HEIMDALL_TEST_") for k in os.environ):
        sys.stderr.write("refused: a HEIMDALL_TEST_* variable is set in the environment of a release run\n")
        return 2
    p = argparse.ArgumentParser()
    for name in ("lane", "heimdall", "scratch", "alias", "out", "sshd-config", "sshd-log"):
        p.add_argument("--" + name, required=True)
    for name in ("seconds", "seed", "tick", "sshd-pid"):
        p.add_argument("--" + name, required=True, type=int)
    a = p.parse_args()
    if a.lane not in ("S", "L"):
        raise SystemExit("lane is S or L")
    return Lane(a).run()


if __name__ == "__main__":
    sys.exit(main())
