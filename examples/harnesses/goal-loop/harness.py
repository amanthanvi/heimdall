"""H2: a goal-directed planner over Heimdall's public CLI.

A task is a goal (data). The planner holds one typed state, and the list of bindings
it was given and has not released. The goal names the first call; after that every
step is one row of TRANSITIONS, chosen from the state and the last answer's `code`
and `next.action`. Every answer is checked against the exit class of its process
(EXIT_CLASSES). Nothing here reads an answer's prose.
"""

import argparse
from collections import namedtuple
import json
import os
from pathlib import Path, PureWindowsPath
import queue
import re
import subprocess
import sys
import threading
import time
import uuid


class PlannerError(Exception):
    """The harness could not go on: a bad fixture, an unreadable answer, a wait that ran out."""


def require(condition, problem):
    if not condition:
        raise PlannerError(problem)


# --------------------------------------------------------------------------------------
# The call set: every command, flag and option name H2 uses is in this one table.
# --------------------------------------------------------------------------------------

BASE_FLAGS = ("--json", "--non-interactive")

# A part written "{name}" is replaced by that value; `options` maps a goal field to its flag.
LOCAL_CALL_SET = {
    "discover": {"argv": ("schema", "show", "codes"), "options": {}, "answer": "codes"},
    "ensure": {
        "argv": ("access", "ensure", "--profile", "{profile}", "--work-id", "{work_id}",
                 "--request-id", "{request_id}"),
        "options": {"pairs": "--pair", "timeout_ms": "--timeout-ms",
                    "require_unattended": "--require-unattended"},
        "answer": "envelope",
    },
    "observe": {"argv": ("operation", "wait", "{operation_id}", "--timeout-ms", "{observe_ms}"),
                "options": {}, "answer": "operation"},
    "bind": {
        "argv": ("run", "--profile", "{profile}", "--work-id", "{work_id}",
                 "--request-id", "{request_id}", "--meta-file", "{meta_file}", "--"),
        "options": {}, "answer": "launch",
    },
    "release": {"argv": ("access", "release", "{binding_id}"), "options": {}, "answer": "release"},
}
CALL_SET_SOURCE = "local table (held for U4b: `schema show primitives` is not served yet)"


def load_call_set(command):
    """The planner's call set.

    SEAM, held for U4b (contract revision 7): the call set is to be loaded from the
    installed binary's `schema show primitives`. Today's build does not serve that
    schema, so this returns the one local table above. When it is served, this function
    is the only place that changes: run `command` with `schema show primitives` and
    build the same mapping from its answer.
    """
    del command  # unused until the primitive index is served
    return LOCAL_CALL_SET


# --------------------------------------------------------------------------------------
# Typed state
# --------------------------------------------------------------------------------------

# Five states more than m07-plan §5a lists. Three hold what the next call needs:
# `observing`, an accepted operation that is neither an approval nor a provider wait;
# `reconciling`, the operation of an uncertain outcome, observed until it ends;
# `releasing`, the next binding to release: a stop that holds more than one binding,
# or one that begins where the state itself holds none.
# Two end a goal: `unresolved`, an uncertain outcome whose operation was still
# unfinished at the step limit (it names that operation); and `inconsistent`, an answer
# whose process ended in another exit class than the one documented for its code.
STATES = {
    "start": (),
    "discovered": (),
    "observing": ("operation_id",),
    "reconciling": ("operation_id",),
    "pending_approval": ("decision_ref", "operation_id"),
    "pending_provider": ("provider", "kind"),
    "ready": ("binding_id",),
    "running": ("pid", "binding_id"),
    "releasing": ("binding_id",),
    "stopped": (),
    "failed": ("code",),
    "inconsistent": ("code", "exit_code"),
    "unresolved": ("code", "operation_id"),
}
# A field a state may carry beside its own. `failed` names the operation of an
# uncertain outcome whenever one is known.
OPTIONAL = {"failed": ("operation_id",)}


def _identifier(prefix):
    pattern = re.compile(prefix + r"_[A-Za-z0-9._:-]{1,120}")
    return lambda value: isinstance(value, str) and pattern.fullmatch(value) is not None


def _word(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value) is not None


FIELD_CHECKS = {
    "operation_id": _identifier("op"),
    "decision_ref": _identifier("dec"),
    "binding_id": _identifier("binding"),
    "provider": _word,
    "kind": _word,
    "code": _word,
    "pid": lambda value: type(value) is int and value > 0,
    "exit_code": lambda value: type(value) is int,
}


class State:
    """One state of STATES with its fields (and any of its OPTIONAL ones), each checked."""

    __slots__ = ("name", "fields")

    def __init__(self, name, **fields):
        require(name in STATES and set(STATES[name]) <= set(fields)
                and set(fields) <= set(STATES[name]) | set(OPTIONAL.get(name, ())),
                f"state {name} was given the wrong fields")
        for field, value in fields.items():
            require(FIELD_CHECKS[field](value), f"state {name} was given an invalid {field}")
        self.name = name
        self.fields = dict(fields)

    def __eq__(self, other):
        return isinstance(other, State) and (self.name, self.fields) == (other.name, other.fields)

    def __hash__(self):
        return hash((self.name, tuple(sorted(self.fields.items()))))

    def __repr__(self):
        inside = ", ".join(f"{key}={value!r}" for key, value in sorted(self.fields.items()))
        return f"{self.name}({inside})"

    def record(self):
        return dict(self.fields, state=self.name)


# --------------------------------------------------------------------------------------
# The transition table
# --------------------------------------------------------------------------------------

# One answer, reduced to what a transition may use. `facts` holds the answer's typed
# parts (`next`, `data`, the envelope's `operation_id`, a run record); a row names the
# paths its new state is built from. `state.*` is the current state's own fields, and a
# path written "=VALUE" is that fixed value: neither is a part of the answer.
# `exit` is the exit status of the answer's process (None while that process still runs).
Reading = namedtuple("Reading", "code action effect facts exit", defaults=(None,))
Row = namedtuple("Row", "states code action to takes")

STAY = "(same state)"
# Two answers are the planner's own. Each stands where the code would, and no envelope
# can carry either: they are not words.
# The step limit ran out:
BOUND = "(the step limit)"
# The process ended in another exit class than the one documented for its answer. The
# facts hold that answer's code and the exit status:
MISMATCH = "(the exit class)"
ORIGIN = ("start", "discovered")
REQUESTING = ORIGIN + ("pending_provider",)
SENDING = REQUESTING + ("ready",)  # every state a request is sent from
IN_FLIGHT = ("observing", "pending_approval")
HELD = ("ready", "running")
RELEASABLE = HELD + ("releasing",)  # every state a release is sent from
CALLING = SENDING + IN_FLIGHT + ("reconciling", "running", "releasing")  # every state that calls
DECISION = (("decision_ref", "next.decision_ref"), ("operation_id", "next.operation_id"))
PROVIDER = (("provider", "next.provider_interaction.provider"),
            ("kind", "next.provider_interaction.kind"))
CODE = (("code", "code"),)
STILL_UNKNOWN = (("code", "=OUTCOME_UNKNOWN"), ("operation_id", "state.operation_id"))

TRANSITIONS = (
    # discovery
    Row(("start",), "OK", "none", "discovered", ()),
    # the answer to a request for access
    Row(REQUESTING, "ACCESS_READY", "use_binding", "ready", (("binding_id", "next.binding_id"),)),
    Row(REQUESTING, "ACCEPTED", "observe", "observing", (("operation_id", "next.operation_id"),)),
    Row(ORIGIN, "APPROVAL_REQUIRED", "observe", "pending_approval", DECISION),
    Row(ORIGIN, "INTERACTION_REQUIRED", "interact", "pending_approval", DECISION),
    Row(ORIGIN, "INTERACTION_REQUIRED", "interact", "pending_provider", PROVIDER),
    Row(ORIGIN, "PROVIDER_LOCKED", "interact", "pending_provider", PROVIDER),
    # the provider asked again after its one handoff: stop
    Row(("pending_provider",), "INTERACTION_REQUIRED", "interact", "failed", CODE),
    Row(("pending_provider",), "PROVIDER_LOCKED", "interact", "failed", CODE),
    # refusals: report them, never look for another way in
    Row(REQUESTING, "CAPABILITY_UNAVAILABLE", "narrow_request", "failed", CODE),
    Row(REQUESTING, "POLICY_PAUSED", "owner_decision", "failed", CODE),
    Row(REQUESTING, "POLICY_CUTOFF", "owner_decision", "failed", CODE),
    Row(REQUESTING, "REQUEST_CONFLICT", "new_request_id", "failed", CODE),
    # an uncertain outcome: the request is never sent again. The operation the answer's
    # `next` names is observed until it ends; an answer whose `next` names none is
    # reported as it is, with the envelope's own operation when it carries one
    Row(SENDING, "OUTCOME_UNKNOWN", "reconcile", "reconciling",
        (("operation_id", "next.operation_id"),)),
    Row(SENDING, "OUTCOME_UNKNOWN", "reconcile", "failed", CODE + (("operation_id", "operation_id"),)),
    Row(SENDING, "OUTCOME_UNKNOWN", "reconcile", "failed", CODE),
    # observing the same operation: unfinished, so observe it again
    Row(("observing",), "OK", "observe", STAY, ()),
    Row(("pending_approval",), "OK", "observe", STAY, ()),
    Row(("reconciling",), "OK", "observe", STAY, ()),
    Row(IN_FLIGHT + ("reconciling",), "ACCESS_READY", "none", "ready",
        (("binding_id", "data.result.binding_id"),)),
    Row(IN_FLIGHT + ("reconciling",), "CAPABILITY_UNAVAILABLE", "none", "failed", CODE),
    Row(IN_FLIGHT + ("reconciling",), "OPERATION_CANCELLED", "none", "failed", CODE),
    # the operation's own outcome is unknown: the report names the operation
    Row(IN_FLIGHT + ("reconciling",), "OUTCOME_UNKNOWN", "none", "failed",
        CODE + (("operation_id", "state.operation_id"),)),
    # the step limit ran out with the operation of an uncertain outcome unfinished:
    # the outcome is still unknown, and the report names the operation
    Row(("reconciling",), BOUND, "none", "unresolved", STILL_UNKNOWN),
    # a launch has no envelope: its run record's `type` stands where the code would
    Row(SENDING, "launching", "none", "running",
        (("pid", "record.pid"), ("binding_id", "record.binding_id"))),
    # release: one binding for each call, until the planner holds no other
    Row(RELEASABLE, "OK", "none", "releasing", (("binding_id", "held.binding_id"),)),
    Row(RELEASABLE, "OK", "none", "stopped", ()),
    # the exit class did not fit the answer, whatever the call was: stop and report both
    Row(CALLING, MISMATCH, "none", "inconsistent", CODE + (("exit_code", "exit_code"),)),
)

# The exit class the CLI documents for each answer the table acts on
# (docs/api/local-protocol.md, "Exit classes": 0 success, 1 internal, 2 usage, 3 needs a
# person, 4 not allowed, 5 unavailable for now, 6 conflict, 7 uncertain). A key is a
# code, or a (code, next.action) pair where the class is not the code's own.
EXIT_CLASSES = {
    "OK": 0,
    "ACCESS_READY": 0,
    "APPROVAL_REQUIRED": 3,
    "INTERACTION_REQUIRED": 3,
    "PROVIDER_LOCKED": 3,
    "CAPABILITY_UNAVAILABLE": 4,
    "POLICY_PAUSED": 4,
    "POLICY_CUTOFF": 4,
    "OPERATION_CANCELLED": 4,
    "REQUEST_CONFLICT": 6,
    "OUTCOME_UNKNOWN": 7,
    # Still pending after a bounded wait. H2 never asks asynchronously, so `ACCEPTED` is
    # never the success it is for a caller that does; and an observation that found its
    # operation unfinished answers `OK` with `next.action` `observe`.
    "ACCEPTED": 5,
    ("OK", "observe"): 5,
}

# Actions with which Heimdall says the request itself was wrong or wrongly repeated.
INVALID_REQUEST_ACTIONS = ("fix_request", "new_request_id")

# What a state does next while its goal is unmet: (call, handoff on entering the state).
# REQUEST is the goal's first call again, as a new request.
REQUEST = "(the goal's first call)"
FOLLOW = {
    "observing": ("observe", None),
    "reconciling": ("observe", None),
    "releasing": ("release", None),
    "pending_approval": ("observe", "approval"),
    "pending_provider": (REQUEST, "provider"),
}

# A goal names its first call, where it begins, and the states that satisfy it.
GOALS = {
    "discover": {"first": "discover", "begin": "start", "accept": ("discovered",),
                 "fields": ()},
    "access": {"first": "ensure", "begin": "work", "accept": ("ready",),
               "fields": ("profile", "work_id", "pairs", "timeout_ms", "require_unattended",
                          "expect_refusal")},
    "run": {"first": "bind", "begin": "work", "accept": ("running",),
            "fields": ("profile", "work_id", "argv")},
    "stop": {"first": "release", "begin": "held", "accept": ("stopped",), "fields": ()},
}

MAX_STEPS = 6
OBSERVE_MS = 20000
CALL_SECONDS = 40
LAUNCH_SECONDS = 30
CHILD_END_SECONDS = 10
STDERR_LIMIT = 64 * 1024


def lookup(facts, path):
    value = facts
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def transition(state, reading):
    """Choose the next state: the first row for this state, code and action whose typed
    fields the answer carries. Returns (state, row), or (failed, None) when no row applies."""
    facts = dict(reading.facts, state=state.fields)
    for row in TRANSITIONS:
        if state.name in row.states and (row.code, row.action) == (reading.code, reading.action):
            fields = {field: path[1:] if path.startswith("=") else lookup(facts, path)
                      for field, path in row.takes}
            if all(value is not None for value in fields.values()):
                return (state if row.to == STAY else State(row.to, **fields)), row
    return unmatched(state, reading), None


def unmatched(state, reading):
    """No row applied: `failed` with the answer's code. An uncertain outcome still names
    its operation when one is known: the one being observed, else the one the answer names."""
    if reading.code == "OUTCOME_UNKNOWN":
        for operation in (state.fields.get("operation_id"), lookup(reading.facts, "next.operation_id"),
                          lookup(reading.facts, "operation_id")):
            if FIELD_CHECKS["operation_id"](operation):
                return State("failed", code=reading.code, operation_id=operation)
    return State("failed", code=reading.code)


def check_exit(reading):
    """Check the exit status of an answer's process against the class documented for the
    answer. Returns (reading, None) when they agree, and otherwise the planner's own
    reading of the mismatch with its account. An answer whose process still runs has no
    exit status yet, and a code EXIT_CLASSES lacks has no row in TRANSITIONS either."""
    documented = EXIT_CLASSES.get((reading.code, reading.action), EXIT_CLASSES.get(reading.code))
    if reading.exit is None or documented is None or reading.exit == documented:
        return reading, None
    facts = {"code": reading.code, "exit_code": reading.exit}
    return (Reading(MISMATCH, "none", None, facts, reading.exit),
            f"exit {reading.exit} does not fit {reading.code}: its documented exit class is {documented}")


def known_codes():
    return {row.code for row in TRANSITIONS}


def no_row(state, reading):
    """Why no row applied: a code the table does not know at all is an unknown code."""
    if reading.code not in known_codes():
        return f"unknown code {reading.code}"
    return f"no transition from {state.name} for {reading.code} with next {reading.action}"


# --------------------------------------------------------------------------------------
# Reading answers
# --------------------------------------------------------------------------------------

def one_envelope(output):
    lines = output.split(b"\n")
    require(len(lines) == 2 and not lines[1], "expected exactly one line of JSON from the CLI")
    try:
        envelope = json.loads(lines[0].decode("utf-8"))
    except (UnicodeError, ValueError):
        raise PlannerError("the CLI printed something that is not JSON") from None
    require(isinstance(envelope, dict) and envelope.get("schema_version") == "1",
            "expected an envelope of schema major 1")
    return envelope


def read_envelope(envelope):
    code = envelope.get("code")
    require(_word(code), "the envelope has no usable code")
    following = envelope.get("next")
    require(following is None or isinstance(following, dict), "the envelope's next is not an object")
    action = "none" if following is None else following.get("action")
    require(_word(action), "the envelope's next has no usable action")
    data = envelope.get("data")
    facts = {"code": code, "next": following or {}, "data": data if isinstance(data, dict) else {},
             "operation_id": envelope.get("operation_id")}
    return Reading(code, action, lookup(facts, "data.error.effect_status"), facts)


def read_operation(envelope, operation_id):
    """An observation: once the operation has a code of its own, that is the answer's code."""
    reading = read_envelope(envelope)
    if reading.code != "OK":
        return reading
    view = reading.facts["data"]
    require(view.get("operation_id") == operation_id, "the answer is about another operation")
    code = view.get("code")
    if code is None:
        return reading
    require(_word(code), "the operation has no usable code")
    return reading._replace(code=code, effect=view.get("effect_status"),
                            facts=dict(reading.facts, code=code))


def read_codes(envelope):
    reading = read_envelope(envelope)
    if reading.code != "OK":
        return reading, None
    rows = reading.facts["data"].get("codes")
    require(isinstance(rows, list) and rows, "the code table is empty")
    installed = {}  # each installed code, with the exit class its row gives
    for row in rows:
        require(isinstance(row, dict) and _word(row.get("code")), "a code table row has no code")
        installed[row["code"]] = row.get("exit_code")
    missing = sorted(code for code in known_codes() if code.isupper() and code not in installed)
    require(not missing, "the installed code table lacks " + ", ".join(missing))
    return reading, installed


def read_run_records(text):
    records = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            raise PlannerError("the run record file holds something that is not JSON") from None
        require(isinstance(record, dict) and record.get("schema_version") == "1"
                and isinstance(record.get("type"), str), "expected run records of schema major 1")
        records.append(record)
    return records


# --------------------------------------------------------------------------------------
# The launch environment (m07-plan §0 rule 4), checked before every launch
# --------------------------------------------------------------------------------------

HOMES = ("HOME", "HEIMDALL_HOME", "HEIMDALL_TEST_SSH_HOME")
STORES = {"HEIMDALL_TEST_MGMT_STORE": "fixture-file:", "HEIMDALL_TEST_IROH_KEY_STORE": ""}


def windows_launch_variables(system_root, fixture_home):
    windows = PureWindowsPath(system_root)
    require(windows.is_absolute(), "SystemRoot is not an absolute Windows directory")
    system = windows / "System32"
    variables = {"SystemRoot": system_root,
                 "PATH": ";".join(str(p) for p in (system / "OpenSSH", system, windows))}
    for name in ("USERPROFILE", "ProgramData", "ALLUSERSPROFILE",
                 "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        variables[name] = fixture_home
    return variables


def launch_environment(root, given):
    """The three separate homes and fixture stores inside the scratch root, fixed
    PATH, LANG and TERM, and Windows system and scratch paths.

    The homes are checked by their real paths and passed on as they were given: a
    runtime is found under the spelling of the Heimdall home it was started with."""
    require(root.is_absolute() and root.is_dir(), "the scratch root is not an absolute directory")
    real_root = Path(os.path.realpath(root))
    homes = {}
    for name in HOMES:
        value = given.get(name)
        require(bool(value) and Path(value).is_absolute() and Path(value).is_dir(),
                f"{name} is not set to an existing absolute directory")
        real = Path(os.path.realpath(value))
        require(real != real_root and real_root in real.parents,
                f"{name} is outside the scratch root")
        homes[name] = real
    for name, home in homes.items():
        for other_name, other in homes.items():
            require(name == other_name or (home != other and home not in other.parents),
                    f"{name} and {other_name} are not separate directories")
    env = {"LANG": "C", "TERM": "dumb"}
    env.update((name, given[name]) for name in HOMES)
    for name, prefix in STORES.items():
        value = given.get(name, "")
        path = Path(value[len(prefix):])
        require(value.startswith(prefix) and path.is_absolute(),
                f"{name} is not set to {prefix}<absolute path>")
        try:
            real = path.resolve()
        except (OSError, RuntimeError):
            raise HarnessError(f"{name} could not be resolved") from None
        require(real_root in real.parents and (not real.exists() or real.is_file()),
                f"{name} is not a file path inside the scratch root")
        env[name] = value
    env["HEIMDALL_TEST_SECRET_STORE"] = "scratch"
    if os.name == "nt":
        env.update(windows_launch_variables(given.get("SystemRoot", ""), env["HOME"]))
    else:
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    return env


# --------------------------------------------------------------------------------------
# The child a `run` goal starts (held by its own handle, ended by its own handle)
# --------------------------------------------------------------------------------------

class Child:
    def __init__(self, process):
        self.process = process
        self.lines = queue.Queue()
        self.errors = bytearray()
        self.threads = [threading.Thread(target=self._lines, daemon=True),
                        threading.Thread(target=self._errors, daemon=True)]
        for thread in self.threads:
            thread.start()

    def _lines(self):
        first = True
        for line in self.process.stdout:  # the first line is the signal; the rest is drained
            if first:
                self.lines.put(line)
                first = False
        self.lines.put(None)

    def _errors(self):
        for chunk in iter(lambda: self.process.stderr.read(4096), b""):
            if len(self.errors) < STDERR_LIMIT:
                self.errors.extend(chunk[:STDERR_LIMIT - len(self.errors)])

    def first_line(self, seconds):
        """Whether the child wrote a line before it ended or the wait ran out."""
        try:
            return self.lines.get(timeout=seconds) is not None
        except queue.Empty:
            return False

    def end(self, seconds=None):
        """Close the child's input and wait; a child that stays is stopped by this handle."""
        seconds = CHILD_END_SECONDS if seconds is None else seconds
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for thread in self.threads:
            thread.join(timeout=seconds)
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        return self.process.returncode


# --------------------------------------------------------------------------------------
# The planner
# --------------------------------------------------------------------------------------

def terminal_handoff(report):
    """Tell the person (one JSON line on stderr) and wait for `continue` on stdin."""
    print(json.dumps(report), file=sys.stderr, flush=True)
    return sys.stdin.readline() == "continue\n"


class Planner:
    def __init__(self, command, root, given_environment, handoff=terminal_handoff):
        require(Path(command[0]).is_absolute(), "the Heimdall executable path is not absolute")
        self.command = list(command)
        self.root = root
        self.given = dict(given_environment)
        self.handoff = handoff
        self.calls = load_call_set(self.command)
        self.state = State("start")
        self.installed_codes = None
        self.work = None
        self.child = None
        # Every binding an answer gave this planner that it has not released, oldest first.
        self.held = []

    # ---- calls ----

    def arguments(self, name, values, goal):
        call = self.calls[name]
        argv = []
        for part in call["argv"]:
            argv.append(str(values[part[1:-1]]) if part.startswith("{") else part)
        for field, flag in call["options"].items():
            value = goal.get(field)
            if isinstance(value, list):
                for item in value:
                    argv += [flag, item]
            elif value is True:
                argv.append(flag)
            elif value is not None and value is not False:
                argv += [flag, str(value)]
        return argv

    def invoke(self, name, goal, metrics):
        """Make one call and reduce its answer to a Reading that carries its exit status."""
        env = launch_environment(self.root, self.given)
        values = dict(self.work or {}, observe_ms=OBSERVE_MS, **self.state.fields)
        kind = self.calls[name]["answer"]
        if kind == "launch":
            return self.launch(name, values, goal, env, metrics)
        argv = [*self.command, *BASE_FLAGS, *self.arguments(name, values, goal)]
        metrics["calls"] += 1
        try:
            done = subprocess.run(argv, env=env, cwd=self.root, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=CALL_SECONDS)
        except subprocess.TimeoutExpired:
            raise PlannerError("a CLI call ran past its time limit") from None
        except OSError:
            raise PlannerError("the CLI could not be started") from None
        envelope = one_envelope(done.stdout)
        if kind == "codes":
            metrics["discovery_bytes"] += len(done.stdout)
            reading, installed = read_codes(envelope)
            if installed is not None:
                self.installed_codes = installed
        elif kind == "operation":
            reading = read_operation(envelope, values["operation_id"])
        elif kind == "release":
            reading = self.read_release(envelope, values["binding_id"])
        else:
            reading = read_envelope(envelope)
        return reading._replace(exit=done.returncode)

    def read_release(self, envelope, binding_id):
        """A release: the answer's facts name the binding held next (`held.binding_id`),
        when there is one beside the binding this answer is about."""
        reading = read_envelope(envelope)
        if reading.code != "OK":
            return reading
        require(lookup(reading.facts, "data.binding_id") == binding_id,
                "the answer is about another binding")
        others = [held for held in self.held if held != binding_id]
        still = {"binding_id": others[-1]} if others else {}
        return reading._replace(facts=dict(reading.facts, held=still))

    def hold(self, binding_id):
        """Add a binding this planner was given to the list, once."""
        if binding_id not in self.held:
            self.held.append(binding_id)

    def launch(self, name, values, goal, env, metrics):
        """`run`: start the child and read the launch's run record, or its refusal."""
        require(self.child is None, "a child is already running")
        program = Path(goal["argv"][0])
        require(program.is_absolute() and program.is_file()
                and Path(os.path.realpath(self.root)) in Path(os.path.realpath(program)).parents,
                "the child executable is not a file inside the scratch root")
        # The run records go to a file of the harness's own, named on the command line.
        meta = self.root / f"h2-run-{uuid.uuid4().hex}.ndjson"
        argv = [*self.command, *BASE_FLAGS,
                *self.arguments(name, dict(values, meta_file=meta), goal), *goal["argv"]]
        metrics["calls"] += 1
        try:
            process = subprocess.Popen(argv, env=env, cwd=self.root, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            raise PlannerError("the CLI could not be started") from None
        child = Child(process)
        up = child.first_line(LAUNCH_SECONDS)
        try:
            records = read_run_records(meta.read_text(encoding="utf-8")) if meta.is_file() else []
            types = [record["type"] for record in records]
            for record in records:  # a binding a record names is held, whatever became of the launch
                if FIELD_CHECKS["binding_id"](record.get("binding_id")):
                    self.hold(record["binding_id"])
            if up and types == ["launching"]:
                require(records[0].get("pid") == process.pid, "the run record names another process")
                self.child = child
                return Reading("launching", "none", None, {"record": records[0]})
        except (OSError, UnicodeError):
            raise PlannerError("the run records could not be read") from None
        finally:
            if self.child is None:
                status = child.end(1)
            if meta.is_file():
                meta.unlink()
        # Not launched, or the child ended without a word. A refusal is one envelope on stderr.
        require("launching" not in types or "prelaunch_failed" in types,
                f"the child wrote no line (exit {status})")
        return read_envelope(one_envelope(bytes(child.errors)))._replace(exit=status)

    # ---- goals ----

    def begin(self, goal, spec):
        if spec["begin"] == "held":
            # A stop begins wherever a binding is held. It goes on from a state that holds
            # one. From any other state (a goal that failed, a stop the step limit cut
            # short and whose binding is gone) it begins at the newest binding on the list.
            require(self.held, f"nothing is held to stop in state {self.state.name}")
            if (self.state.name not in RELEASABLE
                    or self.state.fields["binding_id"] not in self.held):
                self.state = State("releasing", binding_id=self.held[-1])
            return
        require(self.child is None, "a child is still running: stop it first")
        if spec["begin"] == "start":
            self.state = State("start")
            return
        prepared = (self.work is not None and self.state.name == "ready"
                    and spec["first"] == "bind"
                    and (self.work["profile"], self.work["work_id"])
                    == (goal["profile"], goal["work_id"]))
        if not prepared:  # a launch for the work just prepared starts from `ready`
            self.state = State("start" if self.installed_codes is None else "discovered")
        # Every changing request gets a request ID of its own: the ID guards one request
        # against being applied twice, and never carries work on from an earlier request.
        self.work = {"profile": goal["profile"], "work_id": goal["work_id"],
                     "request_id": uuid.uuid4().hex}

    def pursue(self, goal, metrics):
        """Work toward one goal. Returns a short account of how it was met."""
        spec = GOALS[goal["goal"]]
        self.begin(goal, spec)
        expected = goal.get("expect_refusal")
        call = spec["first"]
        for _ in range(MAX_STEPS):
            answer = self.invoke(call, goal, metrics)
            before = self.state
            if answer.action in INVALID_REQUEST_ACTIONS:
                metrics["invalid_retries"] += 1
            reading, problem = check_exit(answer)
            try:
                after, row = transition(before, answer)
                # A binding the answer names is held from here on, whatever the exit
                # class of its process: a later stop releases it.
                if after.name in HELD:
                    self.hold(after.fields["binding_id"])
                if reading is not answer:
                    after, row = transition(before, reading)
            except PlannerError as error:  # the code's typed fields are present but invalid
                reading = answer
                after, row, problem = State("failed", code=answer.code), None, str(error)
            metrics["transitions"].append(
                {"from": before.name, "code": reading.code, "action": reading.action,
                 "to": after.name, "by_table": row is not None})
            if row is None and problem is None:
                problem = no_row(before, reading)
            self.state = after
            if call == "release" and after.name in ("releasing", "stopped"):
                # The release was answered, in its documented exit class: no longer held.
                self.held = [held for held in self.held if held != before.fields["binding_id"]]
            if after.name == "stopped" and self.child is not None:
                child, self.child = self.child, None
                status = child.end()
                metrics["child_exit_code"] = status
                require(status == 0, f"the child ended with exit {status}")
            if after.name == "failed":
                require(row is not None, problem)
                require(expected == after.fields["code"],
                        f"failed: {after.fields['code']}")
                require(reading.effect == "none", "the refusal reports an effect")
                return f"{expected} (effect none)"
            require(problem is None, problem)  # `inconsistent`: the exit class did not fit
            if after.name in spec["accept"]:
                require(expected is None, f"expected {expected}, reached {after.name}")
                return after.name
            require(after.name in FOLLOW, f"the goal cannot go on from state {after.name}")
            call, handoff = FOLLOW[after.name]
            if handoff is not None and after.name != before.name:
                metrics["human_handoffs"] += 1
                started = time.monotonic()
                try:
                    answered = self.handoff(dict(after.fields, handoff=handoff))
                finally:
                    metrics["human_ms"] += (time.monotonic() - started) * 1000
                require(answered, "the person did not come back from the handoff")
            if call == REQUEST:
                call = spec["first"]
                self.work["request_id"] = uuid.uuid4().hex
        # The step limit ran out. Where the table has a row for that in this state, the
        # row gives the state the goal ends in. No call is made for it.
        before = self.state
        if any(before.name in row.states and row.code == BOUND for row in TRANSITIONS):
            reading = Reading(BOUND, "none", None, {})
            self.state, row = transition(before, reading)
            metrics["transitions"].append(
                {"from": before.name, "code": BOUND, "action": reading.action,
                 "to": self.state.name, "by_table": row is not None})
            raise PlannerError(f"the goal was not met within the step limit: {self.state!r}")
        raise PlannerError("the goal was not met within the step limit")

    def close(self):
        """Release every binding still held, then end a child that is still held, by its
        own handle. Returns what was released here and what is still held.

        Each round is one stop, bounded like any goal. A round that releases nothing
        ends the attempt, so the whole of it is bounded too."""
        before = list(self.held)
        while self.held:
            count = len(self.held)
            try:
                self.pursue({"goal": "stop"}, new_metrics())
            except (PlannerError, OSError):
                pass
            if len(self.held) >= count:
                break
        if self.child is not None:
            child, self.child = self.child, None
            child.end(1)
        return {"released": [binding for binding in before if binding not in self.held],
                "held": list(self.held)}


# --------------------------------------------------------------------------------------
# Goals and records
# --------------------------------------------------------------------------------------

def _label(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


GOAL_FIELD_CHECKS = {
    "profile": _label,
    "work_id": _label,
    "pairs": lambda value: isinstance(value, list) and bool(value) and all(
        _label(item) and item.count(":") == 1 for item in value),
    "timeout_ms": lambda value: type(value) is int and 0 < value <= 600000,
    "require_unattended": lambda value: value is True,
    "expect_refusal": _word,
    "argv": lambda value: isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item and "\0" not in item for item in value),
}
GOAL_REQUIRED = {"access": ("profile", "work_id"), "run": ("profile", "work_id", "argv")}


def check_goal(goal):
    require(isinstance(goal, dict) and isinstance(goal.get("goal"), str)
            and goal["goal"] in GOALS, "a goal names no known goal")
    name = goal["goal"]
    require(_label(goal.get("task", name)), "a goal's task label is not a plain name")
    for field, value in goal.items():
        if field in ("goal", "task"):
            continue
        require(field in GOALS[name]["fields"], f"goal {name} does not take {field}")
        require(GOAL_FIELD_CHECKS[field](value), f"goal {name} has an invalid {field}")
    for field in GOAL_REQUIRED.get(name, ()):
        require(field in goal, f"goal {name} needs {field}")
    return goal


def new_metrics():
    return {"calls": 0, "human_handoffs": 0, "invalid_retries": 0, "discovery_bytes": 0,
            "human_ms": 0.0, "transitions": []}


def run_goal(planner, goal):
    """Pursue one goal and return its record (the fields H1's records have, and the path taken)."""
    metrics = new_metrics()
    success, started = False, time.monotonic()
    try:
        detail = planner.pursue(check_goal(goal), metrics)
        success = True
    except PlannerError as error:
        detail = str(error)
    except OSError:
        detail = "fixture filesystem or handoff I/O failed"
    wall = (time.monotonic() - started) * 1000 - metrics.pop("human_ms")
    record = dict(metrics, task=goal.get("task", goal.get("goal")) if isinstance(goal, dict) else None,
                  goal=goal.get("goal") if isinstance(goal, dict) else None,
                  success=success, round_trips=metrics["calls"], wall_time_ms=round(max(wall, 0), 3),
                  detail=detail, skipped=False, final_state=planner.state.record(),
                  held=list(planner.held))
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heimdall-bin", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--goal", action="append", required=True, type=json.loads,
                        help='one task goal as JSON, for example {"goal": "access", '
                             '"profile": "<profile>", "work_id": "<work-id>"}; repeat for a sequence')
    args = parser.parse_args(argv)
    if not args.heimdall_bin.is_absolute():
        parser.error("--heimdall-bin must be absolute")
    planner = Planner([str(args.heimdall_bin)], args.scratch_root, os.environ)
    try:
        tasks = [run_goal(planner, goal) for goal in args.goal]
    finally:
        closing = planner.close()  # whatever the goals left held is released here
    print(json.dumps({"harness": "H2", "call_set": CALL_SET_SOURCE, "tasks": tasks,
                      "close": closing}))
    return int(any(not task["success"] for task in tasks) or bool(closing["held"]))


if __name__ == "__main__":
    sys.exit(main())
