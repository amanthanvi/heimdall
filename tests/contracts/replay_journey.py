#!/usr/bin/env python3
"""Write one exit build's replay-corpus stores (ADR-0013 §1.3; docs/architecture/u0-plan.md §5).

Usage: python3 -I -B tests/contracts/replay_journey.py <milestone> <heimdall binary> <out dir>

Runs one short fixed journey against a debug `heimdall` of an earlier exit build, in scratch
homes only, and writes each home's state store as a SQL text dump with a manifest:
`<out dir>/<home>.sql` and `<out dir>/manifest.json`. The same commands run at every build
(their flags are identical from the M02 exit on); a step a build does not have is skipped
and recorded. Nothing reaches the network, an SSH server, an agent or a key store:

* every process gets an environment built from nothing (no inherited variable): `PATH`, a
  scratch `HOME`, `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME`, the fixture stores
  (`HEIMDALL_TEST_SECRET_STORE=scratch`, `HEIMDALL_TEST_MGMT_STORE=fixture-file:…`,
  `HEIMDALL_TEST_IROH_KEY_STORE=…`) and the fake adapter (`HEIMDALL_TEST_ADAPTER`); a build
  ignores the variables it does not know;
* before anything is spawned, the three homes are checked to resolve inside the run's own
  scratch root;
* the runtime is this script's own child (`service run` in the foreground). It is stopped with
  `service stop`, and if it has not exited it is killed by its own handle: never by name;
* attended steps answer a typed `yes` on a pseudo-terminal this script owns.

Every step's real exit code is recorded. No step expects `INTERNAL_ERROR`: a failed
operation comes from the denied approval, a cancelled one from the cancel step. The fake adapter's synthetic credential reference (a
canary) is replaced by a fixed placeholder; the dump is then refused if it holds a home
directory outside the scratch root, the account's user name, any canary or private-key armor.
"""

import json
import os
import pty
import re
import select
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT_BASE = "/tmp/u0-replay"
TIMEOUT = 60


class Home:
    """One scratch root with HOME, HEIMDALL_HOME and HEIMDALL_TEST_SSH_HOME inside it."""

    def __init__(self, milestone, name, binary, extra):
        self.name = name
        self.binary = binary
        self.root = os.path.join(ROOT_BASE, f"run-{milestone}-{name}")
        if os.path.exists(self.root):
            shutil.rmtree(self.root)
        os.makedirs(self.root, mode=0o700)
        self.root = os.path.realpath(self.root)
        self.home = os.path.join(self.root, "home")
        self.hh = os.path.join(self.root, "hh")
        self.ssh = os.path.join(self.root, "sshhome")
        for d in (self.home, self.ssh, os.path.join(self.ssh, "etc-ssh"), os.path.join(self.root, "iroh")):
            os.makedirs(d, mode=0o700)
        with open(os.path.join(self.root, "lock"), "w", encoding="ascii") as f:
            f.write("unlocked\n")
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": self.home,
            "HEIMDALL_HOME": self.hh,
            "HEIMDALL_TEST_SSH_HOME": self.ssh,
            "HEIMDALL_TEST_SECRET_STORE": "scratch",
            "HEIMDALL_TEST_MGMT_STORE": "fixture-file:" + os.path.join(self.root, "mgmt"),
            "HEIMDALL_TEST_IROH_KEY_STORE": os.path.join(self.root, "iroh"),
            "HEIMDALL_TEST_ADAPTER": "prepare",
            "HEIMDALL_TEST_LEDGER": os.path.join(self.root, "effects.ledger"),
            "HEIMDALL_TEST_TIME_SYNC": "synchronized",
            "HEIMDALL_TEST_SESSION_LOCK": os.path.join(self.root, "lock"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
        self.env.update(extra)
        for key in ("HOME", "HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME"):
            real = os.path.realpath(self.env[key])
            if not real.startswith(self.root + os.sep):
                raise SystemExit(f"{key} is not inside the scratch root; nothing was started")
        self.steps = []
        self.service = None

    def run(self, label, args, attended=False):
        argv = [self.binary] + args
        if attended:
            code, out = self._pty(argv)
        else:
            p = subprocess.run(argv, env=self.env, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=TIMEOUT)
            code, out = p.returncode, p.stdout.decode("utf-8", "replace")
        env = last_json(out)
        self.steps.append({"step": label, "exit": code,
                           "code": env.get("code") if env else None})
        return code, env or {}

    def _pty(self, argv):
        master, slave = pty.openpty()
        p = subprocess.Popen(argv, env=self.env, stdin=slave, stdout=slave, stderr=slave,
                             start_new_session=True)
        os.close(slave)
        seen, answered = b"", False
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                if not chunk and p.poll() is not None:
                    break
                seen += chunk
                if not answered and b"[y/N]: " in seen:
                    os.write(master, b"yes\n")
                    answered = True
            elif p.poll() is not None:
                break
        if p.poll() is None:
            p.kill()
        code = p.wait()
        os.close(master)
        return code, seen.decode("utf-8", "replace")

    def start(self):
        self.service = subprocess.Popen([self.binary, "service", "run"], env=self.env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            p = subprocess.run([self.binary, "--json", "service", "status"], env=self.env,
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT)
            if p.returncode == 0:
                self.steps.append({"step": "service run", "exit": 0, "code": "OK"})
                return
            if self.service.poll() is not None:
                break
            time.sleep(0.2)
        raise SystemExit(f"{self.name}: the runtime did not become ready "
                         f"(exit {self.service.poll()})")

    def stop(self):
        code, _ = self.run("service stop", ["--json", "service", "stop"])
        try:
            self.service.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            # Our own child, by its own handle.
            self.service.kill()
            self.service.wait()
            self.steps.append({"step": "service killed", "exit": None, "code": None})
        return code

    def dump(self, out_dir):
        db = os.path.join(self.hh, "state", "state.db")
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        version = con.execute("PRAGMA user_version").fetchone()[0]
        counts = {}
        for (table,) in con.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                " ORDER BY name"):
            counts[table] = con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
        text = "\n".join(con.iterdump()) + "\n"
        con.close()
        # The fake adapter's credential reference is a synthetic canary that must never be
        # printed or committed; it is stored as an opaque reference, so a fixed placeholder
        # reads the same way.
        # (The prefix is assembled here so this source holds no canary-shaped literal.)
        prefix = "HEIMDALL_" + "CANARY_"
        text = re.sub(prefix + r"cli_fixture_[0-9]+", "replay_fixture_credential_ref", text)
        refuse(text, self.root)
        # Scratch paths become one fixed placeholder, so the dump is the same on every run.
        text = text.replace(self.root, "/scratch")
        with open(os.path.join(out_dir, f"{self.name}.sql"), "w", encoding="utf-8") as f:
            f.write(text)
        return {"home": self.name, "user_version": version, "rows": counts,
                "steps": self.steps}

    def remove(self):
        shutil.rmtree(self.root, ignore_errors=True)


def account_user():
    return os.environ.get("USER") or os.path.basename(os.path.expanduser("~"))


def refuse(text, root, user=None):
    """Exit unless `text` is free of a home directory outside `root`, the account's user name,
    any canary and private-key armor (the self-test is `test_replay_journey.py`)."""
    user = account_user() if user is None else user
    outside = text.replace(root, "<scratch>")
    # A home directory is an absolute path that starts with one; the scratch root's own
    # `home` directory is inside `<scratch>` and so never starts a path.
    if re.search(r"(^|[^A-Za-z0-9_.>-])/(Users|home)/", outside):
        raise SystemExit("the dump holds a home directory; nothing was written")
    for needle in ("HEIMDALL_" + "CANARY_", "PRIVATE " + "KEY"):
        if needle in outside:
            raise SystemExit(f"the dump holds {needle!r}; nothing was written")
    if user and re.search(r"\b" + re.escape(user) + r"\b", outside):
        raise SystemExit("the dump holds the account's user name; nothing was written")


def last_json(text):
    for line in reversed(text.splitlines()):
        i = line.find("{")
        if i < 0:
            continue
        try:
            return json.loads(line[i:])
        except ValueError:
            continue
    return None


def find(doc, key, where):
    """The first value of `key` in an object of `doc` that matches `where`."""
    if isinstance(doc, dict):
        if all(doc.get(k) == v for k, v in where.items()) and key in doc:
            return doc[key]
        for v in doc.values():
            r = find(v, key, where)
            if r is not None:
                return r
    elif isinstance(doc, list):
        for v in doc:
            r = find(v, key, where)
            if r is not None:
                return r
    return None


def ensure(request, work, pair, more=()):
    return ["--json", "access", "ensure", "--profile", "dev", "--work-id", work,
            "--request-id", request, "--pair", pair, *more]


def journey_main(h, milestone):
    h.start()
    code, ready = h.run("ensure (ready)", ensure("r1", "w1", "h1:deploy"))
    binding = (ready.get("data") or {}).get("binding_id")
    h.run("ensure (replay)", ensure("r1", "w1", "h1:deploy"))
    h.run("ensure (conflict)", ensure("r1", "w-other", "h1:deploy"))
    h.run("ensure (pending)", ensure("r2", "w2", "h3:deploy", ["--non-interactive"]))
    _, pending = h.run("ensure (to deny)", ensure("r3", "w3", "h3:deploy", ["--non-interactive"]))
    deny = (pending.get("next") or {}).get("decision_ref")
    if deny:
        h.run("decision deny (attended)", ["--json", "decision", "deny", deny], attended=True)
    _, pending = h.run("ensure (to approve)",
                       ensure("r4", "w4", "h3:deploy", ["--non-interactive"]))
    approve = (pending.get("next") or {}).get("decision_ref")
    if approve:
        h.run("decision approve (attended)", ["--json", "decision", "approve", approve],
              attended=True)
    h.run("access pause", ["--json", "access", "pause", "pol"])
    h.run("access resume (pending)", ["--json", "access", "resume", "pol"])
    h.run("access resume (attended)", ["--json", "access", "resume", "pol"], attended=True)
    h.run("access cutoff", ["--json", "access", "cutoff", "pol", "--at", "2099-01-01T00:00:00Z"])
    h.run("access cutoff --clear (pending)", ["--json", "access", "cutoff", "pol", "--clear"])
    if milestone in ("m03", "m0405", "m06"):
        h.run("access lock-behavior", ["--json", "access", "lock-behavior", "--policy", "pol",
                                      "revoke-on-lock"])
    if milestone in ("m0405", "m06"):
        h.run("access default-profile", ["--json", "access", "default-profile", "dev",
                                        "--request-id", "d1"])
    if binding:
        _, bindings = h.run("inspect bindings", ["--json", "inspect", "bindings"])
        grant = find(bindings, "grant_id", {"binding_id": binding})
        h.run("access release", ["--json", "access", "release", binding])
        if grant:
            h.run("access revoke", ["--json", "access", "revoke", grant, "--request-id", "rv1"])
    if milestone in ("m0405", "m06"):
        h.run("access stop --work", ["--json", "access", "stop", "--work", "w4",
                                    "--request-id", "s1"])
    h.run("operation events", ["--json", "operation", "events"])
    h.stop()


def journey_slow(h):
    h.start()
    _, accepted = h.run("ensure --async", ensure("r-s", "w-s", "h1:deploy", ["--async"]))
    op = accepted.get("operation_id")
    if op:
        h.run("operation cancel", ["--json", "operation", "cancel", op])
    h.stop()


def journey_lost(h):
    h.start()
    h.run("ensure (outcome unknown)", ensure("r-u", "w-u", "h1:deploy"))
    h.run("ensure (same key retry)", ensure("r-u", "w-u", "h1:deploy"))
    h.stop()


def main():
    milestone, binary, out_dir = sys.argv[1], os.path.realpath(sys.argv[2]), sys.argv[3]
    os.makedirs(ROOT_BASE, mode=0o700, exist_ok=True)
    os.makedirs(out_dir, exist_ok=True)
    homes = [
        ("main", {}, lambda h: journey_main(h, milestone)),
        ("slow", {"HEIMDALL_TEST_SLOW_PREPARE_MS": "3000"}, journey_slow),
        ("lost", {"HEIMDALL_TEST_ADAPTER": "lose_reply,prepare"}, journey_lost),
    ]
    manifest = {"milestone": milestone, "homes": []}
    for name, extra, journey in homes:
        h = Home(milestone, name, binary, extra)
        try:
            journey(h)
            manifest["homes"].append(h.dump(out_dir))
        finally:
            if h.service is not None and h.service.poll() is None:
                h.service.kill()
                h.service.wait()
            h.remove()
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    for home in manifest["homes"]:
        for s in home["steps"]:
            print(f"{milestone} {home['home']}: {s['step']}: exit {s['exit']} {s['code']}")


if __name__ == "__main__":
    main()
