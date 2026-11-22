"""H1: procedural tasks against Heimdall's public CLI."""

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


class HarnessError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise HarnessError(message)


def object_field(record, key):
    value = record.get(key)
    require(isinstance(value, dict), f"missing or invalid {key} object")
    return value


def text_field(record, key):
    value = record.get(key)
    require(isinstance(value, str) and bool(value), f"missing or invalid {key} string")
    return value


def id_field(record, key, prefix):
    value = text_field(record, key)
    require(len(value) <= 128 and re.fullmatch(prefix + r"_[A-Za-z0-9._:-]+", value),
            f"invalid {key} identifier")
    return value


def records(output):
    require(output.endswith(b"\n"), "CLI record missing its newline")
    result = []
    for line in output.split(b"\n")[:-1]:
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise HarnessError("invalid JSON on CLI stdout") from None
        require(isinstance(record, dict) and record.get("schema_version") == "1",
                "expected a CLI record with schema major 1")
        result.append(record)
    return result


def check_reply(status, envelope, expected_exit, *codes):
    require(status == expected_exit and envelope.get("code") in codes,
            f"expected {' or '.join(codes)} with exit {expected_exit}, got exit {status}")
    return envelope


def scratch_environment(root):
    require(root.is_absolute() and root.is_dir(), "expected an absolute fixture scratch root")
    root = root.resolve(strict=True)
    if os.name == "posix":
        info = root.stat()
        require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
                "expected an owner-only fixture scratch root")
    home = root / "home"
    state = root / "heimdall-home"
    ssh = root / "ssh-home"
    etc = ssh / "etc-ssh"
    for directory in (home, state, ssh, etc):
        require(directory.is_dir() and directory.resolve(strict=True) == directory,
                "missing or redirected fixture home directory")
    require(not any(etc.iterdir()), "expected an empty fixture etc-ssh directory")
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "TERM": "dumb",
        "HOME": str(home),
        "HEIMDALL_HOME": str(state),
        "HEIMDALL_TEST_SSH_HOME": str(ssh),
    }


@dataclass
class Metrics:
    task: str
    success: bool = False
    calls: int = 0
    human_handoffs: int = 0
    invalid_retries: int = 0
    wall_time_ms: float = 0
    discovery_bytes: int = 0
    detail: str = ""


class Journey:
    def __init__(self, command, root):
        require(Path(command[0]).is_absolute(), "expected an absolute Heimdall executable path")
        self.command = command
        self.root = root
        self.binding = None

    def call(self, metrics, *args):
        env = scratch_environment(self.root)
        metrics.calls += 1
        try:
            done = subprocess.run(
                [*self.command, "--json", "--non-interactive", *args],
                env=env, cwd=self.root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=40,
            )
        except subprocess.TimeoutExpired:
            raise HarnessError("CLI subprocess exceeded its time limit") from None
        except OSError:
            raise HarnessError("could not launch the CLI subprocess") from None
        if metrics.task == "discover":
            metrics.discovery_bytes += len(done.stdout)
        return done.returncode, done.stdout

    def reply(self, metrics, *args):
        status, output = self.call(metrics, *args)
        lines = records(output)
        require(len(lines) == 1, "expected exactly one CLI envelope")
        return status, lines[0]

    def discover(self, metrics):
        codes = check_reply(*self.reply(metrics, "schema", "show", "codes"), 0, "OK")
        rows = object_field(codes, "data").get("codes")
        require(isinstance(rows, list) and any(
            isinstance(row, dict) and row.get("code") == "ACCESS_READY"
            and type(row.get("exit_code")) is int and row["exit_code"] == 0 for row in rows
        ), "expected ACCESS_READY in the installed code table")
        caps = check_reply(*self.reply(metrics, "inspect", "capabilities"), 0, "OK")
        data = object_field(caps, "data")
        for field in ("capabilities", "codes", "schemas"):
            require(isinstance(data.get(field), list) and bool(data[field]),
                    f"expected nonempty capability discovery field {field}")

    def ensure(self, metrics, profile, *options):
        return self.reply(metrics, "access", "ensure", *work_args(profile), *options)

    def covered(self, metrics, profile):
        self.binding = None
        ready = check_reply(*self.ensure(metrics, profile), 0, "ACCESS_READY")
        next_action = object_field(ready, "next")
        binding = id_field(next_action, "binding_id", "binding")
        require(ready.get("state") == "succeeded" and next_action.get("action") == "use_binding"
                and object_field(ready, "data").get("binding_id") == binding,
                "expected a successful ensure with a matching binding")
        self.binding = binding

    def wait_ready(self, metrics, operation):
        observed = check_reply(*self.reply(
            metrics, "operation", "wait", operation, "--timeout-ms", "30000"
        ), 0, "OK")
        result = object_field(observed, "data")
        require(observed.get("operation_id") == result.get("operation_id") == operation
                and observed.get("state") == result.get("state") == "succeeded"
                and result.get("code") == "ACCESS_READY",
                "operation wait did not observe the requested operation reach ACCESS_READY")
        return id_field(object_field(result, "result"), "binding_id", "binding")

    def timeout(self, metrics, profile):
        pending = check_reply(*self.ensure(metrics, profile, "--timeout-ms", "1"), 5, "ACCEPTED")
        next_action = object_field(pending, "next")
        operation = id_field(pending, "operation_id", "op")
        require(next_action.get("action") == "observe"
                and next_action.get("operation_id") == operation, "expected an operation to observe")
        self.wait_ready(metrics, operation)

    def follow(self, metrics, operation, cursor=None):
        extra = (f"--cursor={cursor}",) if cursor is not None else ()
        limit = 1 if extra else 0
        status, output = self.call(metrics, "operation", "events", "--operation", operation,
                                   "--follow", "--max-events", str(limit), *extra)
        lines = records(output)
        require(bool(lines), "expected a subscription envelope")
        head = object_field(check_reply(status, lines[0], 0, "OK"), "data")
        head_cursor = text_field(head, "cursor")
        require(type(head.get("subscription")) is int and len(lines) == limit + 1,
                "unexpected subscription head or event count")
        if limit:
            require(head.get("snapshot") is None, "subscription resume replaced the expected backlog")
            event = lines[1]
            require(event.get("operation_id") == operation
                    and text_field(event, "type") != "resync_required",
                    "expected an event for the subscribed operation")
            id_field(event, "event_id", "evt")
            text_field(event, "cursor")
        else:
            snapshot = object_field(object_field(head, "snapshot"), "data")
            pending = object_field(snapshot, "operation")
            require(pending.get("operation_id") == operation and pending.get("state") == "awaiting_approval",
                    "subscription snapshot did not show this operation awaiting approval")
        return head_cursor

    def approval(self, metrics, profile, pair, handoff):
        pending = check_reply(*self.ensure(metrics, profile, "--pair", pair),
                              3, "APPROVAL_REQUIRED", "INTERACTION_REQUIRED")
        action = object_field(pending, "next")
        operation = id_field(pending, "operation_id", "op")
        decision = id_field(action, "decision_ref", "dec")
        require(action.get("operation_id") == operation
                and action.get("action") in ("observe", "interact"), "expected an owner decision")
        # Take the cursor before the fixture driver acts so replay cannot race approval.
        cursor = self.follow(metrics, operation)
        metrics.human_handoffs += 1
        start = time.monotonic()
        try:
            require(handoff(operation, decision), "fixture driver ended the approval handoff")
        finally:
            metrics.wall_time_ms -= (time.monotonic() - start) * 1000
        self.follow(metrics, operation, cursor)
        self.wait_ready(metrics, operation)

    def bind_run(self, metrics, profile, child):
        executable = Path(child[0])
        require(executable.is_absolute() and executable.is_file()
                and executable.resolve().is_relative_to(self.root.resolve()),
                "expected an absolute fixture child executable inside the scratch root")
        status, output = self.call(metrics, "run", *work_args(profile), "--", *child)
        require(status == 0 and output.splitlines() == [b"h1-fixture-child"],
                "fixture child did not return the expected marker and exit 0")

    def release(self, metrics):
        require(self.binding is not None, "release needs a covered binding from this run")
        released = check_reply(*self.reply(metrics, "access", "release", self.binding), 0, "OK")
        data = object_field(released, "data")
        require(data.get("binding_id") == self.binding
                and object_field(data, "outcome").get("outcome") == "released",
                "expected this run's binding to be released")
        self.binding = None

    def capability_refusal(self, metrics, profile):
        refused = check_reply(*self.ensure(metrics, profile, "--require-unattended"),
                              4, "CAPABILITY_UNAVAILABLE")
        error = object_field(object_field(refused, "data"), "error")
        require(error.get("code") == "CAPABILITY_UNAVAILABLE" and error.get("effect_status") == "none",
                "expected CAPABILITY_UNAVAILABLE with effect none")
        metrics.detail = "CAPABILITY_UNAVAILABLE (effect none)"


def work_args(profile):
    return "--profile", profile, "--work-id", uuid.uuid4().hex, "--request-id", uuid.uuid4().hex


def terminal_handoff(operation, decision):
    print(json.dumps({"operation_id": operation, "decision_ref": decision}),
          file=sys.stderr, flush=True)
    return sys.stdin.readline() == "continue\n"


def run_task(task, callback, *args):
    metrics = Metrics(task)
    start = time.monotonic()
    if callback is None:
        metrics.detail = "needs the U5h Rust fixture driver"
    else:
        try:
            callback(metrics, *args)
            metrics.success = True
        except HarnessError as error:
            metrics.detail = str(error)
        except OSError:
            metrics.detail = "fixture filesystem or handoff I/O failed"
    metrics.wall_time_ms = round(metrics.wall_time_ms + (time.monotonic() - start) * 1000, 3)
    record = asdict(metrics)
    record["round_trips"] = metrics.calls
    record["skipped"] = callback is None
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heimdall-bin", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--task", action="append", required=True, choices=(
        "discover", "covered", "approval", "timeout", "bind-run", "release", "capability-refusal",
    ))
    parser.add_argument("--profile")
    parser.add_argument("--approval-pair")
    parser.add_argument("--child", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not args.heimdall_bin.is_absolute():
        parser.error("--heimdall-bin must be absolute")
    if not args.profile and ({"covered", "timeout", "capability-refusal"}.intersection(args.task)
                             or args.approval_pair or args.child):
        parser.error("the selected fixture task needs --profile")
    journey = Journey([str(args.heimdall_bin)], args.scratch_root)
    scripts = {
        "discover": (journey.discover,),
        "covered": (journey.covered, args.profile),
        "approval": ((journey.approval, args.profile, args.approval_pair, terminal_handoff)
                     if args.approval_pair else (None,)),
        "timeout": (journey.timeout, args.profile),
        "bind-run": (journey.bind_run, args.profile, args.child) if args.child else (None,),
        "release": (journey.release,),
        "capability-refusal": (journey.capability_refusal, args.profile),
    }
    tasks = [run_task(task, *scripts[task]) for task in args.task]
    print(json.dumps({"harness": "H1", "tasks": tasks}))
    return int(any(not task["success"] for task in tasks))


if __name__ == "__main__":
    sys.exit(main())
