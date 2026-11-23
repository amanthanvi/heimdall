#!/usr/bin/env python3
"""M06 W5 `w5g`: the helpers of the cross-host journey (tests/native/m06/run-crosshost.sh and
its runner-side script crosshost-runner.sh). Standard library only; runs with `python3 -I` on
the build host (macOS) and on the runner host (Linux).

  crosshost-tool.py pty [--expect TEXT] [--send TEXT] [--timeout S] [--transcript FILE]
                        [--envelope-out FILE] [--field NAME=PATH]... -- ARGV...
      Run ARGV on a pseudo-terminal with this process's environment (the caller clears it),
      type SEND (default `yes`) and Enter each time EXPECT (default: either of the product's
      typed confirmations, `Type yes to continue` and `Type 'yes' to confirm`) appears, and wait for the exit. The bootstrap's offer to start the runner's runtime (`Type yes to start it`)
      is answered --offer (`no` by default; the cross-host journey passes `yes`, so the
      product's own start is what its pairing evidences). Prints `key=value` facts: prompted (true|false), exit,
      code (the last JSON envelope's), reason, runtime_offer (declined | accepted |
      not_offered), runtime_stated (what the bootstrap session said about the runner's
      runtime: started | not_started | running | not_running | none), message_names_next_step
      (whether a refusal's message names `environment add` again), message (that envelope's
      data.error.message, protected as `protect` does), error_fields (the keys of its
      data.error, comma-separated, or none), and one line per --field
      (a dotted path into that envelope; `none` when absent). The transcript is written only to --transcript
      (the caller's scratch): it may hold paths and is never a saved artifact. --envelope-out
      writes that last envelope (the command's own public answer) as JSON.
  crosshost-tool.py field PATH...            one line per PATH from the JSON on stdin
  crosshost-tool.py envelope-facts NAME=PATH...   `NAME=value` lines from the JSON on stdin
  crosshost-tool.py environment ENV NAME=PATH...  the same, inside the entry of
      `environment status` (data.environments[]) whose `environment` is ENV; `present=false`
      and nothing else when there is none
  crosshost-tool.py protect                  stdin as one protected failure reason (codes and
      states only: `[A-Za-z0-9_=,- ]`, 300 characters)
  crosshost-tool.py log --target T --results TSV --planned FILE --exit N
      The log section m02-evidence.py reads (the form of run-windows-controller.ps1's
      Format-JourneyLog): one `test <step> ... ok|FAILED|ignored` line per planned step, a
      passed step's `m06 observation:` under its `---- <step> stdout ----` header, a failed
      step's protected reason (900 characters). TSV rows: test, case, step, ok|failed, text.
  crosshost-tool.py connections --host ADDR [--own PEER_PORT:LOCAL_PORT] [--listening PORTS]
      `ss -Htn state established` on stdin. Facts: established_from_host (the established TCP
      connections whose peer address is ADDR, an IPv4-mapped form included), own_channel (how
      many of them are the caller's own observation channel, the one with that peer port and
      local port: 0 or 1) and established_from_host_other (the rest). With --listening (this
      host's listening TCP ports, comma-separated; `none` for no port) the same rows BY
      DIRECTION: inbound_from_host (the local port is one this host listens on: the peer
      connected here) and outbound_to_host (any other local port: this host connected out).
      A row whose local port cannot be read counts as outbound (the failing side).
  crosshost-tool.py free-port                a free loopback TCP port
  crosshost-tool.py banner PORT              exit 0 when 127.0.0.1:PORT answers `SSH-2.0-`
  crosshost-tool.py selftest                 the pure helpers on synthetic data
"""

import json
import os
import re
import socket
import sys
import time

# The product's typed confirmations: `environment`/`remote` commands, and `decision approve`.
CONFIRMATION = "Type yes to continue"
DECISION_CONFIRMATION = "Type 'yes' to confirm"
CONFIRMATIONS = (CONFIRMATION, DECISION_CONFIRMATION)
# The bootstrap's offer to start the runner's runtime (`remote init --offer-runtime-start`).
RUNTIME_OFFER = "Type yes to start it"


def runtime_stated(transcript):
    """What the bootstrap session said about the runner's runtime, read across line breaks
    (the form of tests/e2e/windows_controller_m06.rs `runtime_stated`)."""
    flat = " ".join(transcript.split())
    if "runtime is running on this installation (started now)" in flat:
        return "started"
    if "The runner's runtime was not started. Next step:" in flat:
        return "not_started"
    if "The runner's runtime is running on this installation" in flat:
        return "running"
    if "The runner's runtime is NOT running" in flat:
        return "not_running"
    return "none"


def split_endpoint(text):
    """`addr:port` of one `ss` column -> (addr, port); brackets and an IPv4-mapped prefix are
    removed from the address. (None, None) for anything else."""
    addr, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        return None, None
    addr = addr.strip("[]")
    if "%" in addr:
        addr = addr.split("%", 1)[0]
    if addr.lower().startswith("::ffff:") and "." in addr:
        addr = addr[7:]
    return addr, port


def connections_from(table, host, own=None):
    """(all, own, other): the rows of an `ss -Htn state established` table whose peer address
    is `host`; `own` is (peer_port, local_port) of the caller's own channel."""
    host = split_endpoint(host + ":0")[0]
    total = mine = 0
    for line in table.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local_addr, local_port = split_endpoint(cols[-2])
        peer_addr, peer_port = split_endpoint(cols[-1])
        if peer_addr is None or local_addr is None or peer_addr != host:
            continue
        total += 1
        if own is not None and (peer_port, local_port) == own:
            mine += 1
    mine = min(mine, 1)
    return total, mine, total - mine


def connections_by_direction(table, host, listening):
    """(inbound, outbound): the rows of an `ss -Htn state established` table whose peer
    address is `host`, split by whether the row's local port is in `listening` (this host's
    listening TCP ports, as strings). Anything else, an unreadable local port included, is
    outbound: the side the caller fails on."""
    host = split_endpoint(host + ":0")[0]
    inbound = outbound = 0
    for line in table.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local_addr, local_port = split_endpoint(cols[-2])
        peer_addr, _ = split_endpoint(cols[-1])
        if peer_addr is None or peer_addr != host:
            continue
        if local_addr is not None and local_port in listening:
            inbound += 1
        else:
            outbound += 1
    return inbound, outbound


def walk(value, path):
    """One value by dotted path; None when any part is absent."""
    for key in path.split("."):
        if isinstance(value, list):
            if not key.isdigit() or int(key) >= len(value):
                return None
            value = value[int(key)]
        elif isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def text_of(value):
    """A fact's value: words as they are, booleans as words, containers as compact JSON, on
    one line; `none` for an absent value."""
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        out = value
    elif isinstance(value, (list, dict)):
        out = json.dumps(value, separators=(",", ":"), sort_keys=True)
    else:
        out = str(value)
    return out.replace("\r", " ").replace("\n", " ")


def last_envelope(transcript):
    """The last JSON envelope of a terminal transcript: the last line holding an object with
    a `code` (the command's `--json` answer after the session's own lines)."""
    for line in reversed(transcript.splitlines()):
        start = line.find("{")
        if start < 0:
            continue
        try:
            value = json.loads(line[start:].strip())
        except ValueError:
            continue
        if isinstance(value, dict) and "code" in value:
            return value
    return None


def parse_json(text):
    try:
        value = json.loads(text)
    except ValueError:
        return last_envelope(text)
    return value if isinstance(value, dict) else None


def pairs(args):
    out = []
    for a in args:
        name, sep, path = a.partition("=")
        if not sep or not name or not path:
            sys.exit("expected NAME=PATH")
        out.append((name, path))
    return out


def protect(text, limit=300):
    one = re.sub(r"[\r\n]+", " ", text)[:limit]
    return re.sub(r"[^A-Za-z0-9_=,\- ]", "?", one)


def select_environment(envelope, environment):
    for e in walk(envelope, "data.environments") or []:
        if isinstance(e, dict) and e.get("environment") == environment:
            return e
        # `environment status` nests the record's own fields at the entry's top level or
        # under `record`, depending on the revision: both are read.
        if isinstance(e, dict) and walk(e, "record.environment") == environment:
            merged = dict(e.get("record") or {})
            merged.update({k: v for k, v in e.items() if k != "record"})
            return merged
    return None


def format_log(target, results, planned, code):
    ran = [r[0] for r in results]
    not_run = [p for p in planned if p not in ran]
    out = [f"### {target}", "", f"running {len(results) + len(not_run)} tests"]
    out += [f"test {r[0]} ... {'ok' if r[3] == 'ok' else 'FAILED'}" for r in results]
    out += [f"test {n} ... ignored" for n in not_run]
    passed = [r for r in results if r[3] == "ok"]
    failed = [r for r in results if r[3] != "ok"]
    if passed:
        out += ["", "successes:", ""]
        for r in passed:
            out += [f"---- {r[0]} stdout ----", f"m06 observation: {r[1]} {r[2]}: {r[4]}", ""]
    if failed:
        out += ["", "failures:", ""]
        for r in failed:
            out += [f"---- {r[0]} stdout ----", f"failed: {protect(r[4], 900)}", ""]
    out.append(
        f"test result: {'ok' if not failed else 'FAILED'}. {len(passed)} passed; {len(failed)} failed; {len(not_run)} ignored"
    )
    out.append(f"### {target} exit={code}")
    return "\n".join(out) + "\n"


def read_results(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 5:
                rows.append(parts)
    return rows


def run_pty(argv, expect, send, timeout, transcript_path, offer=None):
    """`offer`: a one-element list holding the answer typed at RUNTIME_OFFER; on return it
    holds [answer, offered] (whether the offer appeared). None: the offer is not answered."""
    expects = (expect,) if isinstance(expect, str) else tuple(expect)
    offered = 0
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(argv[0], argv)
        finally:
            os._exit(127)
    try:
        import fcntl
        import struct
        import termios

        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 400, 0, 0))
    except Exception:
        pass
    data = b""
    answered = 0
    deadline = time.monotonic() + timeout
    status = None
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        ready, _, _ = select.select([fd], [], [], min(left, 0.5))
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            data += chunk
            seen = sum(data.count(e.encode()) for e in expects)
            if seen > answered:
                answered = seen
                time.sleep(0.3)
                os.write(fd, send.encode() + b"\r")
            if offer is not None and data.count(RUNTIME_OFFER.encode()) > offered:
                offered = data.count(RUNTIME_OFFER.encode())
                time.sleep(0.3)
                os.write(fd, offer[0].encode() + b"\r")
        else:
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
                # Whatever is still buffered.
                while True:
                    r, _, _ = select.select([fd], [], [], 0.2)
                    if not r:
                        break
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    data += chunk
                break
    if status is None:
        # The terminal reached its end (the child closed it) a moment before the child is
        # reaped: give the exit a short bounded wait before calling it a timeout.
        grace = time.monotonic() + max(0.0, min(5.0, deadline - time.monotonic()))
        done, st = os.waitpid(pid, os.WNOHANG)
        while not done and time.monotonic() < grace:
            time.sleep(0.02)
            done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
        else:
            # Only this helper's own child, by its PID.
            try:
                os.kill(pid, 15)
            except OSError:
                pass
            for _ in range(50):
                done, st = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
                time.sleep(0.1)
            else:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
                os.waitpid(pid, 0)
            status = None
    try:
        os.close(fd)
    except OSError:
        pass
    text = data.decode("utf-8", "replace")
    if transcript_path:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(transcript_path, flags, 0o600), "w", encoding="utf-8") as f:
            f.write(text)
    if status is None:
        code = "timeout"
    elif os.WIFEXITED(status):
        code = str(os.WEXITSTATUS(status))
    else:
        code = "signal"
    if offer is not None:
        offer[1:] = [offered > 0]
    return text, answered > 0, code


def cmd_pty(args):
    expect, send, timeout, transcript, fields, envelope_out = CONFIRMATIONS, "yes", 180.0, None, [], None
    offer = ["no"]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in ("--expect", "--send", "--timeout", "--transcript", "--field", "--envelope-out", "--offer") and i + 1 < len(args):
            v = args[i + 1]
            if a == "--offer":
                if v not in ("yes", "no"):
                    sys.exit("pty: --offer is yes or no")
                offer = [v]
            elif a == "--expect":
                expect = v
            elif a == "--send":
                send = v
            elif a == "--timeout":
                timeout = float(v)
            elif a == "--transcript":
                transcript = v
            elif a == "--envelope-out":
                envelope_out = v
            else:
                fields.append(v)
            i += 2
            continue
        sys.exit("pty: unexpected argument")
    argv = args[i:]
    if not argv:
        sys.exit("pty: no command")
    text, prompted, code = run_pty(argv, expect, send, timeout, transcript, offer)
    envelope = last_envelope(text)
    if envelope_out and envelope is not None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(envelope_out, flags, 0o600), "w", encoding="utf-8") as f:
            json.dump(envelope, f)
    print(f"prompted={'true' if prompted else 'false'}")
    print(f"exit={code}")
    print(f"code={text_of(walk(envelope, 'code'))}")
    print(f"reason={text_of(walk(envelope, 'data.error.reason'))}")
    offered = len(offer) > 1 and offer[1]
    print("runtime_offer=" + ("not_offered" if not offered else "accepted" if offer[0] == "yes" else "declined"))
    print(f"runtime_stated={runtime_stated(text)}")
    message = text_of(walk(envelope, "data.error.message"))
    # A refusal's own words and the fields its error carries, for a failed step's reason
    # (protected: codes and words only, never a path, address or quote).
    # A caller that names its own `message` field gets that one (the first value is read).
    if not any(name == "message" for name, _ in pairs(fields)):
        print(f"message={protect(message)}")
    error = walk(envelope, "data.error")
    print("error_fields=" + (",".join(sorted(error)) if isinstance(error, dict) and error else "none"))
    named = "nothing was recorded on this controller" in message and "run `environment add` again" in message
    print(f"message_names_next_step={'true' if named else 'false'}")
    for name, path in pairs(fields):
        print(f"{name}={text_of(walk(envelope, path))}")
    return 0


def cmd_selftest():
    fails = []

    def check(name, ok):
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            fails.append(name)

    env = {
        "code": "OK",
        "next": {"decision_ref": "dec_1"},
        "data": {
            "grant_id": "g1",
            "local_applied": False,
            "remote_pending": [{"target": {"kind": "grant_revoke"}}],
            "environments": [
                {"environment": "env_a", "issuance": "reconciled", "connectivity": {"state": "connected"}, "remote_pending": []},
                {"record": {"environment": "env_b", "role": "viewer"}, "remote": {"issuance": "awaiting_resync"}},
            ],
        },
    }
    check("T01 fields by path, booleans as words, arrays by index, absent as none", (
        text_of(walk(env, "code")) == "OK" and text_of(walk(env, "data.local_applied")) == "false"
        and text_of(walk(env, "data.remote_pending.0.target.kind")) == "grant_revoke"
        and text_of(walk(env, "data.remote_pending.3")) == "none" and text_of(walk(env, "data.x.y")) == "none"
        and text_of(walk(env, "code.more")) == "none" and text_of(walk(None, "code")) == "none"
        and text_of(walk(env, "next.decision_ref")) == "dec_1"))
    a = select_environment(env, "env_a")
    b = select_environment(env, "env_b")
    check("T02 the status entry of one runner, in both shapes; an empty list reads []", (
        text_of(walk(a, "issuance")) == "reconciled" and text_of(walk(a, "remote_pending")) == "[]"
        and text_of(walk(b, "role")) == "viewer" and text_of(walk(b, "remote.issuance")) == "awaiting_resync"
        and select_environment(env, "env_c") is None and select_environment(None, "env_a") is None))
    t = 'Enroll?\r\nType yes to continue: yes\r\n{"note": 1}\r\n{"code":"OK","data":{"environment":"env_1"}}\r\nConnection closed.\r\n'
    check("T03 the answer is the last envelope of a transcript", (
        last_envelope(t)["data"]["environment"] == "env_1" and last_envelope("no json") is None
        and last_envelope('x {"code":"CAPABILITY_UNAVAILABLE","data":{"error":{"reason":"r"}}}')["data"]["error"]["reason"] == "r"))
    p = protect('code=STATE_UNAVAILABLE at /home/u/x C:\\y 127.0.0.1 "q"\nnext')
    check("T04 a failure reason keeps codes and loses paths, addresses and quotes", (
        "code=STATE_UNAVAILABLE" in p and not any(c in p for c in '/\\."\n') and len(protect("x" * 900)) == 300))
    rows = [["a24_pair", "a24", "pair", "ok", "owner_enrolled=true"], ["a24_approve", "a24", "approve", "failed", "code=X at /p"]]
    log = format_log("crosshost-journey", rows, ["a24_pair", "a24_approve", "a24_bound"], 1)
    check("T05 the log: one test line per planned step, a step that did not run is ignored, the exit", (
        log.startswith("### crosshost-journey\n") and "\ntest a24_pair ... ok\n" in log and "\ntest a24_approve ... FAILED\n" in log
        and "\ntest a24_bound ... ignored\n" in log and "running 3 tests" in log
        and "test result: FAILED. 1 passed; 1 failed; 1 ignored" in log and log.rstrip().endswith("### crosshost-journey exit=1")))
    check("T06 a passed step carries its observation under its header; a failed one its protected reason", (
        "---- a24_pair stdout ----\nm06 observation: a24 pair: owner_enrolled=true\n" in log
        and "m06 observation: a24 approve" not in log and "---- a24_approve stdout ----\nfailed: code=X at ?p\n" in log
        and "\r" not in log and len(re.findall(r"(?m)^test \S+ \.\.\. ", log)) == 3))
    ok_log = format_log("crosshost-journey", rows[:1], ["a24_pair"], 0)
    check("T07 an all-passed log says ok and has no failures section", (
        "test result: ok. 1 passed; 0 failed; 0 ignored" in ok_log and "failures:" not in ok_log))
    long_log = format_log("crosshost-journey", [["a24_pair", "a24", "pair", "failed", "pair_code=X message=" + "w " * 500]], ["a24_pair"], 1)
    long_line = [line for line in long_log.splitlines() if line.startswith("failed: ")][0]
    check("T07b a failed step's reason keeps a refusal's message, up to 900 protected characters", (
        long_line.startswith("failed: pair_code=X message=w w ") and len(long_line) == len("failed: ") + 900))
    # The pseudo-terminal: a child that asks, reads the answer and prints an envelope.
    child = (
        "import sys\n"
        "sys.stdout.write('Confirm.\\nType yes to continue: '); sys.stdout.flush()\n"
        "a = sys.stdin.readline().strip()\n"
        "print('{\"code\":\"%s\",\"data\":{\"said\":\"%s\"}}' % ('OK' if a == 'yes' else 'DENIED', a))\n"
        "sys.exit(0 if a == 'yes' else 3)\n"
    )
    text, prompted, code = run_pty([sys.executable, "-I", "-c", child], CONFIRMATION, "yes", 30.0, None)
    e = last_envelope(text)
    check("T08 a prompt on the pseudo-terminal is answered and the answer is read", (
        prompted and code == "0" and e is not None and e["code"] == "OK" and e["data"]["said"] == "yes"))
    text, prompted, code = run_pty([sys.executable, "-I", "-c", "print('{\"code\":\"OK\"}')"], CONFIRMATION, "yes", 30.0, None)
    check("T09 a command that never asks is reported as not prompted", (not prompted) and code == "0")
    child2 = child.replace("'Confirm.\\nType yes to continue: '", '"Confirm.\\nType \'yes\' to confirm [y/N]: "')
    text, prompted, code = run_pty([sys.executable, "-I", "-c", child2], CONFIRMATIONS, "yes", 30.0, None)
    e = last_envelope(text)
    check("T12 the decision confirmation is answered too", prompted and code == "0" and e is not None and e["code"] == "OK")
    text, prompted, code = run_pty([sys.executable, "-I", "-c", "import time; time.sleep(30)"], CONFIRMATION, "yes", 1.0, None)
    check("T10 a command that outlives the bound is stopped and reported as a timeout", code == "timeout")
    port = free_port()
    check("T11 a free port is a loopback port, and nothing answers an SSH banner there", 1024 < port < 65536 and not banner(port))
    # The bootstrap's offer: a child that asks the confirmation, then makes the offer.
    child3 = (
        "import sys\n"
        "sys.stdout.write('Confirm.\\nType yes to continue: '); sys.stdout.flush()\n"
        "a = sys.stdin.readline().strip()\n"
        "sys.stdout.write(\"The runner's runtime is NOT running on this installation.\\nType yes to start it: \"); sys.stdout.flush()\n"
        "b = sys.stdin.readline().strip()\n"
        "print(\"The runner's runtime is running on this installation (started now).\" if b == 'yes' else \"The runner's runtime was not\\nstarted. Next step: start it\")\n"
        "print('{\"code\":\"OK\",\"data\":{\"said\":\"%s/%s\"}}' % (a, b))\n"
    )
    declined = ["no"]
    text, prompted, code = run_pty([sys.executable, "-I", "-c", child3], CONFIRMATIONS, "yes", 30.0, None, declined)
    e = last_envelope(text)
    check("T13 the runtime offer is declined by default, after the confirmation was answered yes", (
        prompted and code == "0" and e is not None and e["data"]["said"] == "yes/no" and declined == ["no", True]
        and runtime_stated(text) == "not_started"))
    accepted = ["yes"]
    text, prompted, code = run_pty([sys.executable, "-I", "-c", child3], CONFIRMATIONS, "yes", 30.0, None, accepted)
    check("T14 --offer yes accepts it; a command that never offers reads not offered", (
        last_envelope(text)["data"]["said"] == "yes/yes" and accepted == ["yes", True] and runtime_stated(text) == "started"))
    never = ["no"]
    text, prompted, code = run_pty([sys.executable, "-I", "-c", child], CONFIRMATIONS, "yes", 30.0, None, never)
    check("T15 without an offer nothing more is typed", never == ["no", False] and last_envelope(text)["data"]["said"] == "yes"
          and runtime_stated(text) == "none"
          and runtime_stated("The runner's runtime is running on this\r\n installation.") == "running"
          and runtime_stated("The runner's runtime is NOT running on") == "not_running")
    table = (
        "0 0 10.0.0.5:22 100.64.0.9:51000\n"
        "0 0 [::ffff:10.0.0.5]:22 [::ffff:100.64.0.9]:51001\n"
        "0 0 127.0.0.1:40222 127.0.0.1:38000\n"
        "0 0 10.0.0.5:443 100.64.0.7:51000\n"
        "0 0 [fd7a::5]:22 [fd7a::9]:51002\n"
        "garbage\n"
    )
    check("T16 connections from one host are counted by peer address, IPv4-mapped included", (
        connections_from(table, "100.64.0.9") == (2, 0, 2) and connections_from(table, "fd7a::9") == (1, 0, 1)
        and connections_from(table, "100.64.0.1") == (0, 0, 0) and connections_from("", "100.64.0.9") == (0, 0, 0)))
    check("T17 the caller's own observation channel is one exact peer port and local port, never more", (
        connections_from(table, "100.64.0.9", ("51000", "22")) == (2, 1, 1)
        and connections_from(table, "100.64.0.9", ("51000", "443")) == (2, 0, 2)
        and connections_from(table, "100.64.0.9", ("51009", "22")) == (2, 0, 2)
        and split_endpoint("[::ffff:1.2.3.4]:22") == ("1.2.3.4", "22") and split_endpoint("*") == (None, None)))
    listening = {"22", "443"}
    outward = table + "0 0 10.0.0.5:47000 100.64.0.9:22\n0 0 10.0.0.5:47001 100.64.0.9:8443\n"
    check("T18 connections to one host are split by direction: a local listening port is inbound, any other is outbound", (
        connections_by_direction(table, "100.64.0.9", listening) == (2, 0)
        and connections_by_direction(outward, "100.64.0.9", listening) == (2, 2)
        and connections_by_direction(outward, "100.64.0.9", set()) == (0, 4)
        and connections_by_direction(outward, "100.64.0.7", listening) == (1, 0)
        and connections_by_direction("0 0 * 100.64.0.9:22\n", "100.64.0.9", listening) == (0, 1)
        and connections_by_direction("", "100.64.0.9", listening) == (0, 0)))
    print(f"{18 - len(fails)} passed, {len(fails)} failed")
    return 1 if fails else 0


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def banner(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.settimeout(3)
            return s.recv(8).startswith(b"SSH-2.0-")
    except OSError:
        return False


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    cmd, rest = args[0], args[1:]
    if cmd == "pty":
        return cmd_pty(rest)
    if cmd == "field":
        value = parse_json(sys.stdin.read())
        for path in rest:
            print(text_of(walk(value, path)))
        return 0
    if cmd == "envelope-facts":
        value = parse_json(sys.stdin.read())
        for name, path in pairs(rest):
            print(f"{name}={text_of(walk(value, path))}")
        return 0
    if cmd == "environment":
        if not rest:
            sys.exit("environment: ENV")
        entry = select_environment(parse_json(sys.stdin.read()), rest[0])
        print(f"present={'true' if entry is not None else 'false'}")
        if entry is not None:
            for name, path in pairs(rest[1:]):
                print(f"{name}={text_of(walk(entry, path))}")
        return 0
    if cmd == "protect":
        print(protect(sys.stdin.read()))
        return 0
    if cmd == "log":
        opts = dict(zip(rest[0::2], rest[1::2]))
        with open(opts["--planned"], encoding="utf-8") as f:
            planned = [line.strip() for line in f if line.strip()]
        sys.stdout.write(format_log(opts["--target"], read_results(opts["--results"]), planned, int(opts["--exit"])))
        return 0
    if cmd == "connections":
        opts = dict(zip(rest[0::2], rest[1::2]))
        if "--host" not in opts:
            sys.exit("connections: --host ADDR")
        own = None
        if "--own" in opts:
            peer, sep, local = opts["--own"].partition(":")
            if not (sep and peer.isdigit() and local.isdigit()):
                sys.exit("connections: --own PEER_PORT:LOCAL_PORT")
            own = (peer, local)
        table = sys.stdin.read()
        total, mine, other = connections_from(table, opts["--host"], own)
        print(f"established_from_host={total}")
        print(f"own_channel={mine}")
        print(f"established_from_host_other={other}")
        if "--listening" in opts:
            ports = opts["--listening"]
            if ports != "none" and not all(p.isdigit() for p in ports.split(",")):
                sys.exit("connections: --listening PORT[,PORT...] | none")
            listening = set() if ports == "none" else set(ports.split(","))
            inbound, outbound = connections_by_direction(table, opts["--host"], listening)
            print(f"inbound_from_host={inbound}")
            print(f"outbound_to_host={outbound}")
        return 0
    if cmd == "free-port":
        print(free_port())
        return 0
    if cmd == "banner":
        return 0 if banner(int(rest[0])) else 1
    if cmd == "selftest":
        return cmd_selftest()
    sys.exit("unknown command")


if __name__ == "__main__":
    sys.exit(main())
